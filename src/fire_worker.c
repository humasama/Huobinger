#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <errno.h>
#include <stdint.h>
#include <numa.h>

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
#include "hipac.h"


fire_worker_t workers[MAX_WORKER_NUM];
extern fire_config_t *config;

#ifdef HIPAC_TCB
extern struct rlp *l;
#endif

char * buffer[MAX_WORKER_NUM];
int buf_size = 500000000;

/* FIXME: a dirty copy form netinet/tcp.h */
enum {
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING			/* now a valid state */
};

int fire_worker_init(fire_worker_context_t *context)
{
	buffer[context->queue_id] = (char *)malloc(buf_size);

	/* init worker struct */
	fire_worker_t *cc = &(workers[context->queue_id]); 
	cc->total_packets = 0;
	cc->total_bytes = 0;

	/* nids init */
	nids_init(context->core_id);

#if !defined(AFFINITY_NO)
	/* set schedule affinity */
	unsigned long mask = 1 << context->core_id;
	if (sched_setaffinity(0, sizeof(unsigned long), (cpu_set_t *)&mask) < 0) {
		assert(0);
	}

	/* set schedule policy */
	struct sched_param param;
	param.sched_priority = 99;
	pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);
#endif

	if (numa_max_node() == 0)
		return 0;
	
	struct bitmask *bmask;

	bmask = numa_bitmask_alloc(16);
	assert(bmask);
	numa_bitmask_setbit(bmask, context->core_id % 2);
	numa_set_membind(bmask);
	numa_bitmask_free(bmask);

	return 0;
}

char *get_ptr(int id, int length)
{
	static int offset = 0;
	char *ptr = buffer[id] + offset;
	*(int *)ptr = id + length;
	offset = (offset + length) % (buf_size - 1500);
	return ptr;
}

int form_syn_response(char *data, int len)
{
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct udphdr *udph;
	struct tcphdr *tcph;
	uint8_t proto_in_ip = 0;
	uint16_t checksum;
	char tmp[6];
	char *payload_ptr;
	int payload_len;

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

		uint32_t tmp = iph->saddr;
		iph->saddr = iph->daddr;
		iph->daddr = tmp;

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
		payload_ptr = (char *)tcph + tcph->doff * 4;
		payload_len = len - (payload_ptr - data);

		/* TODO: there will be a mapping between sequence
			number of p-c and s-p connection, the sequence difference
			will be stored in the TCB, and code should be added, but not here
		*/ 
		tcph->ack_seq = htonl(ntohl(tcph->seq) + 1);
		tcph->seq = 0;
		uint16_t tmp_port = tcph->source;
		tcph->source = tcph->dest;
		tcph->dest = tmp_port;
		tcph->ack = 1;

		tcph->check = 0;
		checksum = my_tcp_check((void *)tcph, len - ((char *)tcph - data),
			iph->saddr, iph->daddr);
		tcph->check = ~checksum;
		break;
	case IPPROTO_UDP:
		fprint(ERROR, "a udp packet?\n");
		payload_ptr = (char *)udph + 8;
		payload_len = len - (payload_ptr - data);

		udph->check = 0;
		checksum = my_udp_check((void *)udph, ntohs(udph->len),
			iph->saddr, iph->daddr);
		udph->check = ~checksum;
		break;
	default:
		fprint(ERROR, "protocol %d\n", proto_in_ip);
		break;
	}

done:
	return 0;
}

int process_packet(char *eth_data, int len)
{
	struct ethhdr *ethh = (struct ethhdr *)eth_data;
	int ret = nids_process((void *)(ethh + 1), len);
	return ret;
}

void dmesg(char *data)
{
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct tcphdr *tcph;

	ethh = (struct ethhdr *)data;
	iph = (struct iphdr *)(ethh + 1); 
	tcph = (struct tcphdr *)(data + sizeof(struct ethhdr) + 4*iph->ihl);
	printf("ack pkt :syn %u, ack %u, seq %u, ack_seq %u, (sip %u, sport %u, dip %u, dport %u)\n",\
			tcph->syn, tcph->ack,\
			ntohl(tcph->seq), ntohl(tcph->ack_seq),\
			ntohl(iph->saddr), ntohs(tcph->source),\
			ntohl(iph->daddr), ntohs(tcph->dest));
}


int fire_worker_start(int queue_id)
{
	int ret, i, j, k, prot, send_ret;

	fire_worker_t *cc = &(workers[queue_id]); 
	assert(ps_init_handle(&(cc->server_handle)) == 0);
	assert(ps_init_handle(&(cc->client_handle)) == 0);

	struct ps_queue server_queue, client_queue;
	server_queue.ifindex = config->server_ifindex;
	server_queue.qidx = queue_id;
	client_queue.ifindex = config->client_ifindex;
	client_queue.qidx = queue_id;

	assert(ps_attach_rx_device(&(cc->server_handle), &server_queue) == 0);
	assert(ps_attach_rx_device(&(cc->client_handle), &client_queue) == 0);

	struct ps_chunk client_chunk, send_client_chunk, server_chunk, send_server_chunk;
	assert(ps_alloc_chunk(&(cc->client_handle), &client_chunk) == 0);
	assert(ps_alloc_chunk(&(cc->client_handle), &send_client_chunk) == 0);
	assert(ps_alloc_chunk(&(cc->server_handle), &server_chunk) == 0);
	assert(ps_alloc_chunk(&(cc->server_handle), &send_server_chunk) == 0);

	client_chunk.queue.ifindex = config->client_ifindex;
	client_chunk.queue.qidx = queue_id;
	send_client_chunk.queue.ifindex = config->client_ifindex;
	send_client_chunk.queue.qidx = queue_id;
	server_chunk.queue.ifindex = config->server_ifindex;
	server_chunk.queue.qidx = queue_id;
	send_server_chunk.queue.ifindex = config->server_ifindex;
	send_server_chunk.queue.qidx = queue_id;

	int num_pkt_to_client = 0, num_pkt_to_server = 0;
	int pret;

	gettimeofday(&(cc->startime), NULL);

#if defined(HIPAC_TCB)
	int hipac_cnt = 0;
#endif

	for (;;) {
		num_pkt_to_client = 0;
		num_pkt_to_server = 0;
		j = 0;
		k = 0;

		client_chunk.cnt = config->io_batch_num;
		client_chunk.recv_blocking = 0;

		ret = ps_recv_chunk(&(cc->client_handle), &client_chunk);
		if (ret <= 0) {
			/* Receive nothing from server, go to the start of the loop to process client again */
			goto process_server;
		}
		cc->total_packets += ret;

		int action;

		for (i = 0; i < ret; i ++) {
			prot = process_packet(client_chunk.buf + client_chunk.info[i].offset, client_chunk.info[i].len);
			switch (prot) {
				case TCP_SYN_SENT:
					action = HiPAC(client_chunk.buf + client_chunk.info[i].offset, client_chunk.info[i].len, l);
					if(action == FORWARD) {
						// first handshake packet
						// construct the response, and send back to client
						//fprint(INFO, "1) TCP_SYN_SENT\n");
						send_client_chunk.info[j].len = client_chunk.info[i].len;
						send_client_chunk.info[j].offset = j * PS_MAX_PACKET_SIZE;
						memcpy(send_client_chunk.buf + send_client_chunk.info[j].offset,
								client_chunk.buf + client_chunk.info[i].offset, client_chunk.info[i].len);
						form_syn_response(send_client_chunk.buf + send_client_chunk.info[j].offset,
								send_client_chunk.info[j].len);
						pret = process_packet(send_client_chunk.buf 
								+ send_client_chunk.info[j].offset, send_client_chunk.info[j].len);
#if 0
						if(pret != TCP_SYN_RECV){
							printf("pret is %d\n", pret);
							printf("client:\n");
							dmesg(client_chunk.buf + client_chunk.info[i].offset);
							printf("server:\n");
							dmesg(send_client_chunk.buf + send_client_chunk.info[j].offset);
							exit(0);
						}
#endif
						assert(pret == TCP_SYN_RECV);
						//fprint(INFO, "2) TCP_SYN_RECV\n");
						j ++;
					}
					else{ 
					//	hipac_cnt ++;
					//	if(hipac_cnt > 0) printf("hipac filter : %d\n", hipac_cnt);
						delete_tcp(client_chunk.buf + client_chunk.info[i].offset);
					}			
					break;

				case TCP_ESTABLISHED:
					// the 3rd handshake packet
					// do nothing and wait for client's real request
					//fprint(INFO, "3) TCP_ESTABLISHED\n");
					break;

				case -2:
					//fprint(INFO, "two buckets full\n");
					break;

				case -1:
					//fprint(INFO, "Error pkt, don't forward to server.\n");
					break;

				default:
					// normal packet, send to server
					//fprint(INFO, "4) Normal packet, send to server\n");
					send_server_chunk.info[k].len = client_chunk.info[i].len;
					send_server_chunk.info[k].offset = k * PS_MAX_PACKET_SIZE;
					memcpy(send_server_chunk.buf + send_server_chunk.info[k].offset,
							client_chunk.buf + client_chunk.info[i].offset, client_chunk.info[i].len);
					k ++;
					break;
			}

			cc->total_bytes += client_chunk.info[i].len; 

		}
	
		if (j > 0) {
			//fprint(INFO, "sending %d SYN/ACK packet to client, queue_id %d, ifindex %d\n", j, queue_id, config->client_ifindex);
			send_client_chunk.cnt = j;
			send_ret = ps_send_chunk(&(cc->client_handle), &send_client_chunk);
			if (send_ret < 0)
				fprint(ERROR, "send packet fail, ret = %d\n", send_ret);
		}

		if (k > 0) {
			//fprint(INFO, "sending %d packets of established connection to server, queue_id %d, ifindex %d\n", k, queue_id, config->server_ifindex);
			send_server_chunk.cnt = k;
			send_ret = ps_send_chunk(&(cc->server_handle), &send_server_chunk);
			if (send_ret < 0)
				fprint(ERROR, "send packet fail, ret = %d\n", send_ret);
		}
#if 0
		/* FIXME: cannot send all packets
		while (ret > 0) {
			chunk.cnt = ret;
			send_ret = ps_send_chunk(&(cc->handle), &send_chunk);
			if (send_ret < 0)
				fprint(ERROR, "send packet fail, ret = %d\n", send_ret);
			ret -= send_ret;
			//assert(ret >= 0);
		}*/
#endif

process_server:
		/*----------------------------------------------------------------------------------*/
		/* Now process server side packet*/
		server_chunk.cnt = config->io_batch_num;
		//server_chunk.recv_blocking = 0;	//modify at the frist time

		server_chunk.recv_blocking = 0;
		j = 0;

		ret = ps_recv_chunk(&(cc->server_handle), &server_chunk);
		if (ret <= 0) {
			if (errno == EINTR)
				continue;
			/* Receive nothing from server, go to the start of the loop to process client again */
			continue;
		}
		for (i = 0; i < ret; i ++) {
			prot = process_packet(server_chunk.buf + server_chunk.info[i].offset, server_chunk.info[i].len);
			if (prot == 0) {
				send_client_chunk.info[j].len = server_chunk.info[i].len;
				send_client_chunk.info[j].offset = j * PS_MAX_PACKET_SIZE;
				memcpy(send_client_chunk.buf + send_client_chunk.info[j].offset,
					server_chunk.buf + server_chunk.info[i].offset, server_chunk.info[i].len);
				j ++;
			} else {
				fprint(ERROR, "wrong packet from server\n");
			}
		}

		if (j > 0) {
			fprint(DEBUG, "sending packet, queue_id %d, num %d, index %d\n", queue_id, ret, config->client_ifindex);
			send_client_chunk.cnt = j;
			send_ret = ps_send_chunk(&(cc->client_handle), &send_client_chunk);
			if (send_ret < 0)
				fprint(ERROR, "send packet fail, ret = %d\n", send_ret);
		}
	}
	return 0;
}

void *fire_worker_main(fire_worker_context_t *context) 
{
	fprint(INFO, "[Worker %d] on core %d is attaching client if:queue %d:%d, server if:queue %d:%d ...\n", 
		context->queue_id, context->core_id, config->client_ifindex, context->queue_id,
		config->server_ifindex, context->queue_id);
	fire_worker_init(context);
	fire_worker_start(context->queue_id);

	pthread_exit(NULL);
}
