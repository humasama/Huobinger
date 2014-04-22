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
#include "pkt_buff.h"
//#include <numa.h>
#include <sys/time.h>

#include "../../include/psio.h"

#define PS_MAX_CPUS 32
//#define DEBUG
#define TIMECALCULATE
#define FW_IO_BATCH_NUM 512	//firewall config->io_batch_num : 512


int pktlen = 128;	// meaningless

int num_devices;
struct ps_device devices[PS_MAX_DEVICES];

int num_devices_attached;
int devices_attached[PS_MAX_DEVICES];

struct ps_handle handles[PS_MAX_CPUS];

struct timeval endtime, startime;
int my_cpu;  

#ifdef DEBUG
int seq_cnt = 0;
#endif

static int gen_ip = 1;

#ifdef TIMECALCULATE
struct timeval tpdata, tpsyn;
double sum_time = 0.0;
double timeuse = 0.0;
int connect_times = 0, pkt_num = 0;
int recv_snd_times = 0;	//record the total times of the accumulated interval time
#endif

 
int get_num_cpus()
{
	return sysconf(_SC_NPROCESSORS_ONLN);
}

int bind_cpu(int cpu)
{
   cpu_set_t *cmask;
	struct bitmask *bmask;
	cpu_set_t mask;
	size_t n;
	int ret;

	n = get_num_cpus();

    if (cpu < 0 || cpu >= (int)n) {
		errno = -EINVAL;
		return -1;
	}

	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);

	ret = sched_setaffinity(0, sizeof(cpu_set_t), &mask);

	cmask = CPU_ALLOC(n);
	if (cmask == NULL)
		return -1;

        CPU_ZERO_S(n, cmask);
        CPU_SET_S(cpu, n, cmask);

        ret = sched_setaffinity(0, n, cmask);

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

	printf("----------\n");
	printf("CPU %d: %ld packets transmitted, elapse time : %lds, Send Speed : %lf Mpps, %5.2f Gbps, Aveage Len. = %ld\n", 
			my_cpu, total_tx_packets, subtime.tv_sec, 
			(double)(total_tx_packets) / (double) (subtime.tv_sec*1000000+subtime.tv_usec),
			(double)(total_tx_packets * (pktlen+20) * 8) / (double) ((subtime.tv_sec*1000000+subtime.tv_usec) * 1000),
			total_tx_bytes/total_tx_packets);
	
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

void build_packet(struct ps_chunk *chunk, int index)
{
	char *ip;
	ip = chunk->buf + chunk->info[index].offset + 26;     //modify saddr 
	*(uint32_t *)ip = htonl((ntohl(*(uint32_t *)ip) + gen_ip) % 0xFFFFFFFF);
	ip = chunk->buf + chunk->info[index].offset + 34;;      // modify src port
	*(uint16_t *)ip = htons((ntohs(*(uint16_t *)ip) + gen_ip) % 0xFFFF);
	gen_ip ++;
}


void build_syn_pkt(struct ps_chunk *chunk, int seq)	//1
{
	char *pktdata;
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct tcphdr *tcph;

	int i = 0;
	for(; i < chunk->cnt; i++ ) {
		pktdata = chunk->buf + chunk->info[i].offset;
		ethh = (struct ethhdr *)pktdata;
		iph = (struct iphdr *)(ethh + 1);
		
		iph->tot_len =htons(chunk->info[i].len - sizeof(struct ethhdr));
		build_packet(chunk, i);		

		tcph = (struct tcphdr *)(pktdata + sizeof(struct ethhdr) + 4*iph->ihl);
		tcph->syn = 1;
		tcph->ack = 0;
		tcph->psh = 0;
		tcph->rst = 0;	//4-22
		tcph->seq = htonl(seq);
	}
}

void build_ack_pkt(struct ps_chunk *chunk, int num)	// syn ack and data ack
{
	char *pktdata;
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct tcphdr *tcph;
#ifdef TIMECALCULATE
	char *pkt_t_ptr;
	char *eptr;
	double pkt_t_double, cur_t;	// r time --> w time
#endif
	__be32 tmp;
	__u32 tmp_u;
	__be16 tmp_port;
	int i = 0; 
	
	for(; i < num; i++) {
		pktdata = chunk->buf + chunk->info[i].offset;
		ethh = (struct ethhdr *)pktdata;
		iph = (struct iphdr *)(ethh + 1);

		tmp = iph->saddr;
		iph->saddr = iph->daddr;
		iph->daddr = tmp;

		iph->tot_len =htons(chunk->info[i].len - sizeof(struct ethhdr));
		tcph = (struct tcphdr *)(pktdata + sizeof(struct ethhdr) + 4*iph->ihl);

		tmp_u = ntohl(tcph->seq);
		tcph->seq = tcph->ack_seq;

		if(tcph->syn) {
			tcph->ack_seq = htonl(tmp_u + 1);
			tcph->psh = 0;
		}
		else {
#ifdef TIMECALCULATE
			gettimeofday(&tpdata, NULL);
			cur_t =  (double)tpdata.tv_usec / 1000000 + tpdata.tv_sec;
			pkt_t_ptr = (char *)(tcph + 1);
			//pkt_t_double = strtod(pkt_t_ptr, &eptr);
			pkt_t_double = *((double *)pkt_t_ptr);
			
			sum_time = sum_time + cur_t - pkt_t_double;	//r
			recv_snd_times ++;
			//gcvt(cur_t, 28, pkt_t_ptr);	//w
			*((double *)pkt_t_ptr) = cur_t;
#endif
			tcph->ack_seq = htonl(tmp_u + chunk->info[i].len);
			tcph->psh = 1;
		}

		tcph->syn = 0;
		tcph->rst = 0;	//4-22
		tcph->ack = 1;

		tmp_port = tcph->source;
		tcph->source = tcph->dest;
		tcph->dest = tmp_port;
#ifdef DEBUG
		printf("ack pkt : seq is %u, ack is %u, (sip %u, sport %u, dip %u, dport %u)\n",\
				ntohl(tcph->seq), ntohl(tcph->ack_seq),\
				ntohl(iph->saddr), ntohs(tcph->source),\
				ntohl(iph->daddr), ntohs(tcph->dest));
#endif

	}

#ifdef DEBUG
        seq_cnt = ntohl(tcph->seq);
#endif
}


void build_req_pkt(struct ps_chunk *chunk)	// request pkts after syn
{
	char *buf;
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct tcphdr *tcph;
	int length;
	int i;
	__be32 tmp_addr;
	__be16 tmp_port;
	__u32 tmp_u;

#ifdef TIMECALCULATE
	char *pkt_time;	// w timestamp
	double tmp_t;
#endif

	for(i = 0; i < chunk->cnt; i++) {

		length  = chunk->info[i].len + 30;
		buf = (char *)malloc(sizeof(char) * length);
		memset(buf, 0, length);

		memcpy(buf, chunk->buf + chunk->info[i].offset, chunk->info[i].len);

		ethh = (struct ethhdr *)buf;
		iph = (struct iphdr *)(ethh + 1);
		tcph = (struct tcphdr *)(buf + sizeof(struct ethhdr) + 4*iph->ihl);

                tmp_addr = iph->saddr;
                iph->saddr = iph->daddr;
                iph->daddr = tmp_addr;

                tmp_port = tcph->source;
                tcph->source = tcph->dest;
                tcph->dest = tmp_port;

		iph->tot_len =htons(ntohs(iph->tot_len) + 30);
		
		tmp_u = ntohl(tcph->seq);
		tcph->seq = tcph->ack_seq;  
		tcph->ack_seq = htonl(tmp_u + 1);
		 
		tcph->psh = 1;
		tcph->syn = 0;
		tcph->ack = 1;

#ifdef TIMECALCULATE

		pkt_time = (char *)(tcph + 1);
		gettimeofday(&tpsyn, NULL);
		tmp_t = tpsyn.tv_sec + (double)tpsyn.tv_usec / 1000000;
		//gcvt(tmp_t, 28, pkt_time);	//store interval_start as string, len is 28 + 1(\0),without point.
		*(double *)pkt_time = tmp_t;
#endif

		chunk->info[i].len = length;
		chunk->info[i].offset = i * PS_ALIGN(length, 64);
		memcpy(chunk->buf + chunk->info[i].offset, buf, length);
		
#ifdef DEBUG
		ethh = (struct ethhdr *)buf;
		iph = (struct iphdr *)(ethh + 1);
		tcph = (struct tcphdr *)(buf + sizeof(struct ethhdr) + 4*iph->ihl);
		printf("first request pkt : seq is %u, ack is %u, (sip %u, sport %u, dip %u, dport %u)\n",\
				ntohl(tcph->seq), ntohl(tcph->ack_seq),\
				ntohl(iph->saddr), ntohs(tcph->source),\
				ntohl(iph->daddr), ntohs(tcph->dest));
#endif
		free(buf);
		buf = NULL;
	}

}

void clean_chunk(struct ps_chunk *chunk)
{
	int i = 0;
	for(; i < chunk->cnt; i++) {
		memset(chunk->buf + chunk->info[i].offset, 0, chunk->info[i].len);
		chunk->info[i].len = 0;
		chunk->info[i].offset = 0;
	}
}

int isSyn(struct ps_chunk *chunk, int index)
{
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct tcphdr *tcph;

	ethh = (struct ethhdr*)(chunk->buf + chunk->info[index].offset);
	iph = (struct iphdr *)(ethh + 1);
	tcph = (struct tcphdr *)(chunk->buf + sizeof(struct ethhdr) + 4*iph->ihl);
	if(tcph->syn == 1) return 1;
	return 0;
}

void process_pkt_time()
{
	timeuse = sum_time / (double)recv_snd_times;
	printf("pktnum is %d, sum_time is %lf, loop time is %d, average time is %lf s\n",\
						pkt_num, sum_time, recv_snd_times, timeuse);
}

void tcp_connect(int cpu, struct ps_queue *queue)
{
	struct ps_handle *handle = &handles[cpu];
	struct ps_chunk chunk, syn_chunk;	//chunk: snd & recv , syn_chunk: snd
	file_cache_t *fct;
	unsigned int tmp_pktlen;
	u_char *pktdata;

	int i, ret;
	int ifindex;
	char *ip;

	assert(ps_init_handle(handle) == 0);
	assert(ps_attach_rx_device(handle, queue) == 0);
	assert(ps_alloc_chunk(handle, &chunk) == 0);
	assert(ps_alloc_chunk(handle, &syn_chunk) == 0);
	chunk.recv_blocking = 0;
	syn_chunk.recv_blocking = 0;

	chunk.queue.ifindex = queue->ifindex;
	chunk.queue.qidx = queue->qidx;
	syn_chunk.queue.ifindex = queue->ifindex;
	syn_chunk.queue.qidx = queue->qidx;

	int file_no = 0;
	printf("input the pkt num:\n");
	scanf("%d", &pkt_num);
	printf("input the communication times :\n");
	scanf("%d", &connect_times);

	//===================================================
	//chunk.cnt = FW_IO_BATCH_NUM;	//pkt num's upper limit
	chunk.recv_blocking = 1;	//still secure the correction of pkts loss 
	syn_chunk.recv_blocking = 1;	//meaningless
	//===================================================

	if((fct = preload_pcap_file(file_no)) != NULL) {
		printf("Loading done, file %d\n", file_no);
		if (!check_pcap(fct))
			printf("It is not trace file, core %d\n", my_cpu);
	} 
	else {
		printf("Loading failed, file %d\n", file_no);
	}

	pktdata = prep_next_skb(fct, &tmp_pktlen);
	pktlen = tmp_pktlen;	//the actual pkt length.


#ifdef DEBUG
	printf("pcap pktlen is %d\n", pktlen);
#endif

	assert(FW_IO_BATCH_NUM <= 4096);

	i = 0;
	for(; i < FW_IO_BATCH_NUM; i++) {
		chunk.info[i].offset = i * PS_ALIGN(pktlen, 64);
		chunk.info[i].len = pktlen;   
		memcpy(chunk.buf + chunk.info[i].offset, pktdata, pktlen);
	}

	//build_syn_pkt(&chunk, 0);

	int tmp_num = pkt_num;
	while(tmp_num > 0){
		chunk.cnt = tmp_num > FW_IO_BATCH_NUM ? FW_IO_BATCH_NUM : tmp_num; 
		build_syn_pkt(&chunk, 0);
		ret = ps_send_chunk(handle, &chunk);
		tmp_num = tmp_num - FW_IO_BATCH_NUM;
	}

	int k = 0;

	for(;;) {
		chunk.cnt = FW_IO_BATCH_NUM;
		while(1) {
			ret = ps_recv_chunk(handle, &chunk);
			if(ret > 0) break;
		}

		for(i = 0; i < ret; i++) {	//actual pkt num
			if(isSyn(&chunk, i)) {
				syn_chunk.info[k].offset = k * PS_ALIGN(chunk.info[i].len, 64);
				syn_chunk.info[k].len = chunk.info[i].len;
				memcpy(syn_chunk.buf + syn_chunk.info[k].offset, chunk.buf \ 
						+ chunk.info[i].offset, chunk.info[i].len);
				k++;
			}
		}
		syn_chunk.cnt = k;

		build_ack_pkt(&chunk, ret);

		chunk.cnt = ret;
		ret = ps_send_chunk(handle, &chunk);
		//clean_chunk(&chunk);	//if reset chunk.cnt = ret, this action is useless. ---may time overhead 420

		if(k > 0) {
			build_req_pkt(&syn_chunk);
			ret = ps_send_chunk(handle, &syn_chunk);
			k = 0;
			//clean_chunk(&syn_chunk);
		}

#ifdef TIMECALCULATE
		// recv -> send: one time
		if(recv_snd_times >= connect_times * pkt_num) {
			process_pkt_time();
			return;
		}
#endif

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

	struct ps_queue *queue = (struct ps_queue*)malloc(sizeof(struct ps_queue));
	num_cpus = 1;
	
	for (i = 0; i < num_cpus; i ++) {

		my_cpu = i;
		my_queue = i;
		for (i = 0; i < num_devices_attached; i++) {

			if (devices[devices_attached[i]].num_rx_queues <= my_cpu)
				continue;

			if (devices[devices_attached[i]].num_tx_queues <= my_cpu) {
				printf("WARNING: xge%d has not enough TX queues!\n",
						devices_attached[i]);
				continue;
			}

			queue->ifindex = devices_attached[i];
			queue->qidx = my_queue;
			printf("attaching RX queue xge%d : %d to CPU %d\n", queue->ifindex, queue->qidx, my_cpu);
			break;
		}

		bind_cpu(i);
		signal(SIGINT, handle_signal);

		tcp_connect(my_cpu, queue);
		return 0;
	}

	signal(SIGINT, SIG_IGN);

	while (1) {
		int ret = wait(NULL);
		if (ret == -1 && errno == ECHILD)
			break;
	}

	return 0;
}
