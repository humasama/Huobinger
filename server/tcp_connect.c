#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define __USE_GNU

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>


#include <sys/wait.h>
#include <sys/time.h>
//#include "pkt_buff.h"
//#include <numa.h>

#include "../../include/psio.h"

#define PS_MAX_CPUS 32
//#define DEBUG
#define FW_IO_BATCH_NUM 512	//firewall: config->io_batch_num 512

int num_devices;
struct ps_device devices[PS_MAX_DEVICES];

int num_devices_attached;
int devices_attached[PS_MAX_DEVICES];

struct ps_handle handles[PS_MAX_CPUS];

int my_cpu;  

struct timeval startime;
struct timeval endtime;

int get_num_cpus()
{
	return sysconf(_SC_NPROCESSORS_ONLN);
}


int bind_cpu(int cpu)
{
	cpu_set_t *cmask;
	struct bitmask *bmask;
	size_t ncpu, setsize;
	int ret;

	ncpu = get_num_cpus();

	if (cpu < 0 || cpu >= (int)ncpu) {
		errno = -EINVAL;
		return -1;
	}

	cmask = CPU_ALLOC(ncpu);
	if (cmask == NULL)
		return -1;

	setsize = CPU_ALLOC_SIZE(ncpu);
	CPU_ZERO_S(setsize, cmask);
	CPU_SET_S(cpu, setsize, cmask);

	ret = sched_setaffinity(0, ncpu, cmask);

	CPU_FREE(cmask);

	/* skip NUMA stuff for UMA systems */
	if (numa_max_node() == 0)
		return ret;

	bmask = numa_bitmask_alloc(16);
	assert(bmask);

	numa_bitmask_setbit(bmask, cpu % 2);
	numa_set_membind(bmask);
	numa_bitmask_free(bmask);

	return ret;
}

void print_usage(char *argv0)
{
	fprintf(stderr, "Usage: %s <interface to echo> <...>",
			argv0);

	exit(2);
}

void parse_opt(int argc, char **argv)
{
	int i, j;

	if (argc < 2)
		print_usage(argv[0]);

	for (i = 1; i < argc; i++) {
		int ifindex = -1;

		for (j = 0; j < num_devices; j++) {
			if (strcmp(argv[i], devices[j].name) != 0)
				continue;

			ifindex = devices[j].ifindex;
			break;
		}

		if (ifindex == -1) {
			fprintf(stderr, "Interface %s does not exist!\n", argv[i]);
			exit(4);
		}

		for (j = 0; j < num_devices_attached; j++) {
			if (devices_attached[j] == ifindex)
				goto already_attached;
		}

		devices_attached[num_devices_attached] = ifindex;
		num_devices_attached++;
		printf("ifindex = %d\n", ifindex);

already_attached:
		;
	}

	assert(num_devices_attached > 0);
}
void handle_signal(int signal)
{
	struct ps_handle *handle = &handles[my_cpu];

	uint64_t total_tx_packets = 0;
	uint64_t total_tx_bytes = 0;

	int i;
	int ifindex;

	struct timeval subtime;

	gettimeofday(&endtime, NULL);
	timersub(&endtime, &startime, &subtime);

	usleep(10000 * (my_cpu + 1));

	assert (num_devices_attached == 1);
	for (i = 0; i < num_devices_attached; i++) {
		ifindex = devices_attached[i];
		total_tx_packets += handle->tx_packets[ifindex];
		total_tx_bytes += handle->tx_bytes[ifindex];
	}
	/*
	   printf("----------\n");
	   printf("CPU %d: %ld packets transmitted, elapse time : %lds, Send Speed : %lf Mpps, %5.2f Gbps, Aveage Len. = %ld\n", 
	   my_cpu, total_tx_packets, subtime.tv_sec, 
	   (double)(total_tx_packets) / (double) (subtime.tv_sec*1000000+subtime.tv_usec),
	//(double)(total_tx_bytes*8) / (double) ((subtime.tv_sec*1000000+subtime.tv_usec) * 1000),
	(double)(total_tx_packets * (pktlen+20) * 8) / (double) ((subtime.tv_sec*1000000+subtime.tv_usec) * 1000),
	total_tx_bytes/total_tx_packets);
	 */	
	for (i = 0; i < num_devices_attached; i++) {
		char *dev = devices[devices_attached[i]].name;
		ifindex = devices_attached[i];

		if (handle->tx_packets[ifindex] == 0)
			continue;

		printf("  %s: ", dev);

		printf("TX %ld packets "
				"(%ld chunks, %.2f packets per chunk)\n", 
				handle->tx_packets[ifindex],
				handle->tx_chunks[ifindex],
				handle->tx_packets[ifindex] / 
				(double)handle->tx_chunks[ifindex]);
	}

	exit(0);
}



void build_connect_ack(struct ps_chunk *chunk, int num) //just deal data pkt
{
	char *pktdata;
	struct ethhdr *ethh;
	struct iphdr *iph;
	__be32 tmp_addr;
	struct tcphdr *tcph;
	__be16 tmp_port;
	__u32 tmp_u;

	int i = 0;
	for(; i < num; i++) {
		pktdata = chunk->buf + chunk->info[i].offset;
		ethh = (struct ethhdr *)pktdata;

		iph = (struct iphdr *)(ethh + 1);
		tmp_addr = iph->saddr;
		iph->saddr = iph->daddr;
		iph->daddr = tmp_addr;

		tcph = (struct tcphdr *)(pktdata + sizeof(struct ethhdr) + 4*iph->ihl);
		tmp_port = tcph->source;
		tcph->source = tcph->dest;
		tcph->dest = tmp_port;
		tcph->syn = 0;
		tcph->ack = 1;
		tcph->psh = 1;	

		tmp_u = ntohl(tcph->seq);
		tcph->seq = tcph->ack_seq;
		tcph->ack_seq = htonl(tmp_u + chunk->info[i].len - sizeof(struct ethhdr) - sizeof(struct tcphdr) - 4 * iph->ihl);

#ifdef DEBUG
		printf("connect ack : seq_s is %u, ack_s is %u. ip_tot is %u,"
				"(saddr %u, sport %u, daddr %u, dport %u)\n",
				ntohl(tcph->seq), ntohl(tcph->ack_seq),\
				ntohs(iph->tot_len), ntohl(iph->saddr),\
				ntohs(tcph->source), ntohl(iph->daddr), ntohs(tcph->dest));
#endif
	}

}

void clean_chunk(struct ps_chunk *chunk, int num)
{
	int i = 0;
	for(; i < num; i++) {
		memset(chunk->buf + chunk->info[i].offset, 0, chunk->info[i].len);
		chunk->info[i].offset = 0;
		chunk->info[i].len = 0;
	}
}

void tcp_connect(int my_cpu, int my_queue)
{
	struct ps_handle *handle;
	struct ps_chunk chunk;
	u_char *pktdata;

	int status = 1;
	int ifindex;
	int ret = -1, i;
	int pkt_num;
//	printf("input the pkt num of a chunk:\n");
//	scanf("%d", &pkt_num);

	handle = &handles[my_cpu];
	assert(ps_init_handle(handle) == 0);
	struct ps_queue queue;

	for (i = 0; i < num_devices_attached; i++) {
		if (devices[devices_attached[i]].num_rx_queues <= my_queue)
			continue;

		if (devices[devices_attached[i]].num_tx_queues <= my_queue) {
			printf("WARNING: xge%d has not enough TX queues!\n",
					devices_attached[i]);
			continue;
		}

		queue.ifindex = devices_attached[i];
		queue.qidx = my_queue;

		printf("attaching RX queue xge%d:%d to CPU %d\n", queue.ifindex, queue.qidx, my_cpu);
		assert(ps_attach_rx_device(handle, &queue) == 0);
	}

	assert(ps_alloc_chunk(handle, &chunk) == 0);

	//=========================================
	chunk.recv_blocking = 1;	//blocking, secure recv pkts (upper limit is: chunk.cnt)
	//chunk.cnt = pkt_num;   //max recving pkt num
	//=========================================
	chunk.queue.ifindex = queue.ifindex;
	chunk.queue.qidx = queue.qidx;

	while(1) {
		chunk.cnt = FW_IO_BATCH_NUM;
		while(1) {
			ret = ps_recv_chunk(handle, &chunk);	//actual pkt num
			//assert(ret >= 0);
			if(ret > 0) break;
		}
		
		build_connect_ack(&chunk, ret);
		
		chunk.cnt = ret;	//recv m pkts, snd pkt num should lower than m.--->necessary, i guess
		ps_send_chunk(handle, &chunk);	// return value is not the actual send num
		//clean_chunk(&chunk, ret);	//unnecessary time overhead --420
	}
}

int main(int argc, char **argv)
{
	int num_cpus, my_queue;
	int i=0;

	num_cpus = get_num_cpus();
	assert(num_cpus >= 1);

	num_devices = ps_list_devices(devices);
	if (num_devices == -1) {
		perror("ps_list_devices");
		exit(1);
	}

	parse_opt(argc, argv);

    	num_cpus = 1;
	for (i = 0; i < num_cpus; i ++) {
//		int ret = fork();
//		assert(ret >= 0);
//		if(ret == 0) {
			my_cpu = i;
			my_queue = i;
			bind_cpu(my_cpu);		
			tcp_connect(my_queue, my_queue);
//		}

	}

	signal(SIGINT, SIG_IGN);
/*
	while (1) {
		int ret = wait(NULL);
		if (ret == -1 && errno == ECHILD)
			break;
	}
*/
	return 0;
}
