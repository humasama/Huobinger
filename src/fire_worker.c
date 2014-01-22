#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <errno.h>
#include <stdint.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

#include "fire_worker.h"
#include "fire_config.h"
#include "fire_common.h"
#include "psio.h"

fire_worker_t workers[MAX_WORKER_NUM];
extern fire_config_t *config;

int fire_worker_init(fire_worker_context_t *context)
{
	/* nids init */
	nids_init(context->core_id);

	/* set schedule affinity */
	unsigned long mask = 1 << context->core_id;
	if (sched_setaffinity(0, sizeof(unsigned long), (cpu_set_t *)&mask) < 0) {
		assert(0);
	}

	/* set schedule policy */
	struct sched_param param;
	param.sched_priority = 99;
	pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);

	return 0;
}

int form_packet(char *data, int len)
{
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct ip6_hdr *ip6h;
	struct udphdr *udph;
	struct tcphdr *tcph;
	uint8_t proto_in_ip = 0;
	uint16_t checksum;
	char tmp[6];

	ethh = (struct ethhdr *)data;

	// FIXME: dest address of the server/client
	memcpy(tmp, ethh->h_dest, 6);
	memcpy(ethh->h_dest, ethh->h_source, 6);
	memcpy(ethh->h_source, tmp, 6);

	/* IP layer */
	switch (ntohs(ethh->h_proto)) {
	case ETH_P_IP:
		iph = (struct iphdr *)(ethh + 1);
		proto_in_ip = iph->protocol;
		udph = (struct udphdr *)((uint32_t *)iph + iph->ihl);
		tcph = (struct tcphdr *)((uint32_t *)iph + iph->ihl);

		/* Do checksum */
		iph->check = 0;
		checksum = ip_fast_csum((unsigned char *)iph, iph->ihl);
		iph->check = ~checksum;
		break;
	default:
		fprint(ERROR, "protocol %04hx  ", ntohs(ethh->h_proto));
		goto done;
	}

	/* Transport layer */
	switch (proto_in_ip) {
	case IPPROTO_TCP:
		tcph->check = 0;
		checksum = my_tcp_check((void *)tcph, len - ((char *)tcph - data),
			iph->saddr, iph->daddr);
		tcph->check = ~checksum;
		break;
	case IPPROTO_UDP:
		udph->check = 0;
		checksum = my_udp_check((void *)udph, ntohs(udph->len),
			iph->saddr, iph->daddr);
		udph->check = ~checksum;
		break;
	default:
		fprint(ERROR, "protocol %d ", proto_in_ip);
		break;
	}
done:
	return 0;
}

int process_packet(char *eth_data, int len)
{
	struct ethhdr *ethh = (struct ethhdr *)eth_data;
	return nids_process((void *)(ethh + 1), len);
}

int fire_worker_start(int queue_id)
{
	int ret, i, prot, send_ret;

	fire_worker_t *cc = &(workers[queue_id]); 
	assert(ps_init_handle(&(cc->handle)) == 0);

	struct ps_queue queue;
	queue.ifindex = config->ifindex;
	queue.qidx = queue_id;

	assert(ps_attach_rx_device(&(cc->handle), &queue) == 0);
	fprint(INFO, "[Worker %d] is attaching if:queue %d:%d ...\n", queue_id, queue.ifindex, queue.qidx);

	struct ps_chunk chunk, send_chunk;
	assert(ps_alloc_chunk(&(cc->handle), &chunk) == 0);
	assert(ps_alloc_chunk(&(cc->handle), &send_chunk) == 0);
	chunk.recv_blocking = 1;

	gettimeofday(&(cc->startime), NULL);

	for (;;) {
		chunk.cnt = config->io_batch_num;

		ret = ps_recv_chunk(&(cc->handle), &chunk);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (!chunk.recv_blocking && errno == EWOULDBLOCK) {
				fprint(ERROR, "!!! [Worker %d] : recv nothing\n", queue_id);
				assert(0);
			}
			assert(0);
		}

		cc->total_packets += ret;

#if defined(NOT_PROCESS)
		for (i = 0; i < ret; i ++) {
			cc->total_bytes += chunk.info[i].len; 
		}
		continue;
#endif

		int j = 0;
		for (i = 0; i < ret; i ++) {
			prot = process_packet(chunk.buf + chunk.info[i].offset, chunk.info[i].len);
			if (prot == -1) {
				fprint(WARN, "Is IP fragment or bad packet, not forwarding\n");
				continue;
			}
			cc->total_bytes += chunk.info[i].len; 

			send_chunk.info[j].len = chunk.info[i].len;
			send_chunk.info[j].offset = j * PS_MAX_PACKET_SIZE;
			memcpy(send_chunk.buf + send_chunk.info[j].offset,
				chunk.buf + chunk.info[i].offset, chunk.info[i].len);

			form_packet(send_chunk.buf + send_chunk.info[j].offset, send_chunk.info[j].len);

			j++;
		}
	
		if (j == 0) {
			fprint(ERROR, "Sending 0 packets\n");
			continue;
		}
		send_chunk.recv_blocking = 1;
		send_chunk.queue.ifindex = config->ifindex; 
		send_chunk.queue.qidx = queue_id;

		// FIXME: cannot send all packets
		fprint(DEBUG, "sending packet, queue_id %d, num %d, index %d\n", queue_id, j, config->ifindex);
		send_chunk.cnt = j;
		send_ret = ps_send_chunk(&(cc->handle), &send_chunk);
		if (send_ret < 0)
			fprint(ERROR, "send packet fail, ret = %d\n", send_ret);
		/*
		while (j > 0) {
			send_chunk.cnt = j;
			send_ret = ps_send_chunk(&(cc->handle), &send_chunk);
			if (send_ret < 0)
				fprint(ERROR, "send packet fail, ret = %d\n", send_ret);
			j -= send_ret;
			//assert(ret >= 0);
		}*/
	}
	return 0;
}

void *fire_worker_main(fire_worker_context_t *context) 
{
	fprint(INFO, "Worker on core %d, receiving queue %d ...\n", context->core_id, context->queue_id);
	fire_worker_init(context);
	fire_worker_start(context->queue_id);

	pthread_exit(NULL);
}
