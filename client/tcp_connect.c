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
#include <pthread.h>

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
#include <numa.h>
#include <sys/time.h>

#include "../../include/psio.h"

#define CHUNK_RX_TEST

#define PS_MAX_CPUS 32
//#define DEBUG
#define TIMECALCULATE 1
#define FW_IO_BATCH_NUM 4096	//firewall config->io_batch_num : 512
#define WITHSYNATTACK

int num_devices;
struct ps_device devices[PS_MAX_DEVICES];

int num_devices_attached;
int devices_attached[PS_MAX_DEVICES];

struct ps_handle handles[PS_MAX_CPUS];
struct timeval endtime, startime;

static uint64_t gen_ip = 0x10001;

#ifdef TIMECALCULATE
struct timeval tpdata, tpsyn;
double sum_time = 0.0;
double timeuse = 0.0;
int connect_times = 0, pkt_num =0;
long recv_snd_times = 0;	//record the total times of the accumulated interval time
#endif

struct param{
	struct ps_queue *queue;
	int cpu_id;
};
 
int get_cpu_nums()
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

	n = get_cpu_nums();

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

#if 0
void  bind_cpu_thread(int cpu)
{
	cpu_set_t *cmask;
	struct bitmask *bmask;
	size_t ncpu, setsize;
	int ret;    

	ncpu = get_cpu_nums();

	printf("bind cpu : %d\n",cpu);

	if (cpu < 0 || cpu >= (int)ncpu) {
		errno = -EINVAL;
		pthread_exit(NULL);
	}   

	cmask = CPU_ALLOC(ncpu);
	if (cmask == NULL) {
		pthread_exit(NULL);
	}   
	setsize = CPU_ALLOC_SIZE(ncpu); 
	CPU_ZERO_S(setsize, cmask);
	CPU_SET_S(cpu, setsize, cmask);

	ret = pthread_setaffinity_np(pthread_self(), setsize, cmask) ; //setsize,not ncpu

	CPU_FREE(cmask);

	if(ret!=0) pthread_exit(NULL);

	/* skip NUMA stuff for UMA systems */
	if (numa_max_node() != 0) {                                                                                                

		bmask = numa_bitmask_alloc(16);

		if(bmask==0) pthread_exit(NULL);

		numa_bitmask_setbit(bmask, cpu % 2); 
		numa_set_membind(bmask);
		numa_bitmask_free(bmask);
	}   
}
#endif

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
	struct ps_handle *handle = &handles[0];

	uint64_t total_tx_packets = 0;
	uint64_t total_tx_bytes = 0;

	int i;
	int ifindex;
	struct timeval subtime;

	gettimeofday(&endtime, NULL);
	timersub(&endtime, &startime, &subtime);

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
	   (double)(total_tx_packets * (pktlen+20) * 8) / (double) ((subtime.tv_sec*1000000+subtime.tv_usec) * 1000),
	   total_tx_bytes/total_tx_packets);
	 */

	printf("----------\n");
	printf("bytes: %lu, pkts: %lu\n---------------\n", total_tx_bytes, total_tx_packets);
	printf("CPU 0: %ld packets transmitted, elapse time : %lds, Send Speed : %lf Mpps, %5.2f Gbps, Aveage Len. = %ld\n", 
			total_tx_packets, subtime.tv_sec, 
			(double)(total_tx_packets) / (double) (subtime.tv_sec*1000000+subtime.tv_usec),
			(double)(total_tx_bytes * 8) / (double) ((subtime.tv_sec*1000000+subtime.tv_usec) * 1000),
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
		tcph = (struct tcphdr *)(pktdata + sizeof(struct ethhdr) + 4*iph->ihl);

		iph->tot_len =htons(chunk->info[i].len - sizeof(struct ethhdr));
		
		//build_packet(chunk, i);

		iph->saddr = htonl((uint32_t)(gen_ip >> 16));
		tcph->source = htons((uint16_t)(gen_ip & 0xFFFF));
		gen_ip ++;
		//printf("%u, %u\n", iph->saddr, tcph->source);

		tcph->syn = 1;
		tcph->ack = 0;
		tcph->psh = 0;
		tcph->rst = 0;	//4-22
		tcph->seq = htonl(seq);
	}
}

void dmesg(char *data)
{
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct tcphdr *tcph;

	ethh = (struct ethhdr *)data;
	iph = (struct iphdr *)(ethh + 1); 
	tcph = (struct tcphdr *)(data + sizeof(struct ethhdr) + 4*iph->ihl);
	printf("syn is %u, ack is %u, seq is %u, ack_seq is %u, (sip %u, sport %u, dip %u, dport %u)\n",\
			tcph->syn, tcph->ack,\
			ntohl(tcph->seq), ntohl(tcph->ack_seq),\
			ntohl(iph->saddr), ntohs(tcph->source),\
			ntohl(iph->daddr), ntohs(tcph->dest));
}


int build_ack_pkt(struct ps_chunk *chunk, int chunk_size, int attack_start)	// syn ack and data ack
{
	char *pktdata, *payload_s;
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
	int i, datalen;

	char *copy = (char *)calloc(chunk_size * 128, sizeof(char));
	int copy_cnt = 0, syn_val = 0, offset = 0, filter = 0;

	for(i = 0; i < chunk_size; i++) {
		pktdata = chunk->buf + chunk->info[i].offset;
		ethh = (struct ethhdr *)pktdata;
		iph = (struct iphdr *)(ethh + 1);
		
		assert(PS_ALIGN(chunk->info[i].len, 64) == 128);

		tmp = iph->saddr;
		iph->saddr = iph->daddr;
		iph->daddr = tmp;

		iph->tot_len =htons(chunk->info[i].len - sizeof(struct ethhdr));
		tcph = (struct tcphdr *)(pktdata + sizeof(struct ethhdr) + 4 * iph->ihl);
		payload_s = (char *)tcph + 4 * tcph->doff ;

		tmp_u = ntohl(tcph->seq);
		tcph->seq = tcph->ack_seq;

		syn_val = tcph->syn;

		if(tcph->syn) {
			tcph->ack_seq = htonl(tmp_u + 1);
			//tcph->psh = 0;
			tcph->syn = 0;
		}
		else {
#ifdef TIMECALCULATE
			gettimeofday(&tpdata, NULL);
			cur_t =  (double)tpdata.tv_usec / 1000000 + tpdata.tv_sec;
			pkt_t_ptr = (char *)(tcph + 1);
			pkt_t_double = *((double *)pkt_t_ptr);
			
			printf("#%lf %lf\n", (cur_t - pkt_t_double) * 1000 , cur_t);

			//sum_time = sum_time + cur_t - pkt_t_double; //r
			//recv_snd_times ++;
			*((double *)pkt_t_ptr) = cur_t;	//w
#endif
			
			datalen = chunk->info[i].len - (payload_s - pktdata);
			tcph->ack_seq = htonl(tmp_u + datalen);

			//tcph->psh = 1;
		}

		//tcph->syn = 0;
		//tcph->ack = 1;

		tmp_port = tcph->source;
		tcph->source = tcph->dest;
		tcph->dest = tmp_port;

		//filter syn pkts after syn attack
		if(attack_start && syn_val) filter = 1;

		if(attack_start && !syn_val)
		{
			memcpy(copy + offset, chunk->info[i].offset + pktdata, 128);
			copy_cnt ++;
			offset = copy_cnt * 128;
		}
	}

#if 0
	if(attack_start && filter){
		printf("chunk.cnt is %d, copy pkt num is %d\n", chunk_size, copy_cnt);
	}
#endif

	//copy data pkts back
	if(attack_start && filter){
		for(i =0; i < copy_cnt; i ++){
			memcpy(chunk->buf + chunk->info[i].offset, copy + i * 128, 128);
		}
		chunk->cnt = copy_cnt;

		free(copy);
		return copy_cnt;
	}

#ifdef DEBUG
		printf("ack pkt : seq is %u, ack is %u, (sip %u, sport %u, dip %u, dport %u)\n",\
				ntohl(tcph->seq), ntohl(tcph->ack_seq),\
				ntohl(iph->saddr), ntohs(tcph->source),\
				ntohl(iph->daddr), ntohs(tcph->dest));
#endif

		free(copy);
		return chunk_size;
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

		length  = chunk->info[i].len + 10;
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

		iph->tot_len =htons(ntohs(iph->tot_len) + 10);

		tmp_u = ntohl(tcph->seq);
		tcph->seq = tcph->ack_seq;  
		tcph->ack_seq = htonl(tmp_u + 1);

		tcph->psh = 1;
		tcph->syn = 0;
		//tcph->ack = 1;

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
	printf("pktnum is %d, sum_time is %lf, loop time is %ld, average time is %lf s\n",\
						pkt_num, sum_time, recv_snd_times, timeuse);
}

void loadpkt(u_char **pktdata, int *pktlen)
{
	file_cache_t *fct;
	int file_no = 0;
	unsigned int tmp_pktlen;

	if((fct = preload_pcap_file(file_no)) != NULL) {
		printf("Loading done, file %d\n", file_no);
		if (!check_pcap(fct))
			printf("It is not trace file, core \n");
	} 
	else {
		printf("Loading failed, file %d\n", file_no);
	}

	*pktdata = prep_next_skb(fct, &tmp_pktlen);
	*pktlen = tmp_pktlen;    //the actual pkt length.
}

void tcp_connect(struct param *param_m)
{
	int cpu_id = param_m->cpu_id;
	struct ps_queue *queue = param_m->queue;

	bind_cpu(cpu_id);

	struct ps_handle *handle = &handles[cpu_id];
	
	struct ps_chunk chunk, syn_chunk;	//chunk: snd & recv , syn_chunk: snd
	u_char *pktdata;
	int pktlen;

	loadpkt(&pktdata, &pktlen);

	int i, ret;
	//assert(ps_init_handle(handle) == 0);
	ret = ps_init_handle(handle);
	if(ret != 0){
		printf("init fail\n");
		exit(0);
	}

	int ifindex = devices_attached[0];
	int num_rx_queue = devices[ifindex].num_rx_queues;
	struct ps_queue tmp_queue;
	tmp_queue.ifindex = queue->ifindex;

	for(i = 0; i < num_rx_queue; i ++){		//bind all the rx queues to this handle{}
		tmp_queue.qidx = i;
		assert(ps_attach_rx_device(handle, &tmp_queue) == 0);
	}

	assert(ps_alloc_chunk(handle, &chunk) == 0);
	assert(ps_alloc_chunk(handle, &syn_chunk) == 0);

	chunk.queue.ifindex = queue->ifindex;
	chunk.queue.qidx = tmp_queue.qidx;
	syn_chunk.queue.ifindex = queue->ifindex;
	syn_chunk.queue.qidx = queue->qidx;

#if 0
	printf("input the pkt num:\n");
	scanf("%d", &pkt_num);
	//pkt_num = 2000;
	printf("input the communication times :\n");
	scanf("%d", &connect_times);
	//connect_times = 10000;
#endif
	pkt_num = 512;//2048;

	chunk.recv_blocking = 0;	//still secure the correction of pkts loss 
	syn_chunk.recv_blocking = 0;	//meaningless

	assert(FW_IO_BATCH_NUM <= 4096);

	int sum = pkt_num > FW_IO_BATCH_NUM ? FW_IO_BATCH_NUM : pkt_num;
	for(i = 0; i < sum; i++){
		chunk.info[i].offset = i * PS_ALIGN(pktlen, 64);
		chunk.info[i].len = pktlen;   
		memcpy(chunk.buf + chunk.info[i].offset, pktdata, pktlen);
	}

	int tmp_num = pkt_num;

	gettimeofday(&startime, NULL);

	while(tmp_num > 0){
		chunk.cnt = tmp_num > FW_IO_BATCH_NUM ? FW_IO_BATCH_NUM : tmp_num; 
		build_syn_pkt(&chunk, 0);
		ret = ps_send_chunk(handle, &chunk);
		tmp_num = tmp_num - FW_IO_BATCH_NUM;
	}

	int k = 0;
	int syn_counter = 0, attack_start = 0, threshold = (int)(pkt_num * 0.9);

	for(;;){

		chunk.cnt = FW_IO_BATCH_NUM;
		while(1){
			ret = ps_recv_chunk(handle, &chunk);
			if(ret > 0) break;
		}
		//don't arise first data request --2
		if(!attack_start){
			for(i = 0; i < ret; i++){	//actual pkt num
				if(isSyn(&chunk, i)){
					syn_chunk.info[k].offset = k * PS_ALIGN(chunk.info[i].len, 64);
					syn_chunk.info[k].len = chunk.info[i].len;
					memcpy(syn_chunk.buf + syn_chunk.info[k].offset, chunk.buf + chunk.info[i].offset, chunk.info[i].len);
					k++;
					syn_counter ++;
				}
			}
			syn_chunk.cnt = k;
		}

		//don't reply handshake pkts: filter. return left pkt num.
		ret = build_ack_pkt(&chunk, ret, attack_start);

		chunk.cnt = ret;
		ret = ps_send_chunk(handle, &chunk);
		
		if(k > 0 && !attack_start){		//bug point: if(k > 0), unknown reason ( phase 2: state doesn't match pkt 5-16)
			build_req_pkt(&syn_chunk);
			ret = ps_send_chunk(handle, &syn_chunk);
			k = 0;
		}

		if(syn_counter >= threshold){
			//printf("start attack!\n");
			attack_start = 1;
			syn_counter = 0;	// work done
		}
#ifdef TIMECALCULATE
		// recv -> send: one time
#if 0
		if(recv_snd_times >= threshold * connect_times){
			process_pkt_time();
			return;
		}
#endif

#endif
	}

}


int main(int argc, char **argv)
{

	int num_cpus = get_cpu_nums();
	int thrd_id;
	assert(num_cpus >= 1);

	num_devices = ps_list_devices(devices);
	printf("num_devices is %d\n", num_devices);

	if (num_devices == -1) {
		perror("ps_list_devices");
		exit(1);
	}
	parse_opt(argc, argv);

	struct param *param1 = (struct param *)malloc(sizeof(struct param));
	param1->queue = (struct ps_queue *)malloc(sizeof(struct ps_queue));



	param1->queue->ifindex = devices_attached[0];
	param1->queue->qidx = 0;
	param1->cpu_id = 0;

	signal(SIGINT, handle_signal);

	tcp_connect(param1);

	return 0;
}
