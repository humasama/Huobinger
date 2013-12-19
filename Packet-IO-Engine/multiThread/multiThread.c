#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sys/wait.h>
#include <numa.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include "psio.h"
#define MAX_CPUS 32


struct ps_handle handles[MAX_CPUS];
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void bind_cpu_thread(int cpu);
void attach(struct ps_handle *handle, int cpu);
void dump(struct ps_handle *handle);



int get_cpu_nums()
{
	return sysconf(_SC_NPROCESSORS_ONLN);
}


void *thread_recv(void *argv)	  
{
	struct ps_handle handle;
	int cpu_id = (int)(long int)argv;

	handle = handles[cpu_id];	
	
	bind_cpu_thread(cpu_id);

	attach(&handle,cpu_id);

	dump(&handle);

	pthread_exit(NULL);
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



void dump_packet(char *buf, int len)
{
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct ip6_hdr *ip6h;
	struct udphdr *udph;
	struct tcphdr *tcph;
	uint8_t proto_in_ip = 0;
	char outbuf[64];

	ethh = (struct ethhdr *)buf;
	printf("%02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X ",
			ethh->h_source[0],
			ethh->h_source[1],
			ethh->h_source[2],
			ethh->h_source[3],
			ethh->h_source[4],
			ethh->h_source[5],
			ethh->h_dest[0],
			ethh->h_dest[1],
			ethh->h_dest[2],
			ethh->h_dest[3],
			ethh->h_dest[4],
			ethh->h_dest[5]);

	/* IP layer */
	switch (ntohs(ethh->h_proto)) {
	case ETH_P_IP:
		iph = (struct iphdr *)(ethh + 1);
		proto_in_ip = iph->protocol;
		udph = (struct udphdr *)((uint32_t *)iph + iph->ihl);
		tcph = (struct tcphdr *)((uint32_t *)iph + iph->ihl);
		printf(" ");
		inet_ntop(AF_INET, (void *)&iph->saddr, outbuf, sizeof(outbuf));
		printf("%s", outbuf);
		if (proto_in_ip == IPPROTO_TCP || proto_in_ip == IPPROTO_UDP)
			printf("(%d)", ntohs(udph->source));
		printf(" -> ");
		inet_ntop(AF_INET, (void *)&iph->daddr, outbuf, sizeof(outbuf));
		printf("%s", outbuf);
		if (proto_in_ip == IPPROTO_TCP || proto_in_ip == IPPROTO_UDP)
			printf("(%d)", ntohs(udph->dest));
		printf(" TTL=%d ", iph->ttl);
		if (ip_fast_csum(iph, iph->ihl)) {
			__sum16 org_csum, correct_csum;
			org_csum = iph->check;
			iph->check = 0;
			correct_csum = ip_fast_csum(iph, iph->ihl);
			printf("(bad checksum %04x should be %04x) ",
					ntohs(org_csum), ntohs(correct_csum));
			iph->check = org_csum;
		}
		break;
	case ETH_P_IPV6:
		ip6h = (struct ip6_hdr *)(ethh + 1);
		proto_in_ip = ip6h->ip6_nxt;
		udph = (struct udphdr *)((uint8_t *)ip6h + ip6h->ip6_plen);
		tcph = (struct tcphdr *)((uint8_t *)ip6h + ip6h->ip6_plen);
		printf(" ");
		inet_ntop(AF_INET6, (void *)&ip6h->ip6_src, outbuf, sizeof(outbuf));
		printf("%s", outbuf);
		if (proto_in_ip == IPPROTO_TCP || proto_in_ip == IPPROTO_UDP)
			printf("(%d)", ntohs(udph->source));
		printf(" -> ");
		inet_ntop(AF_INET6, (void *)&ip6h->ip6_dst, outbuf, sizeof(outbuf));
		printf("%s", outbuf);
		if (proto_in_ip == IPPROTO_TCP || proto_in_ip == IPPROTO_UDP)
			printf("(%d)", ntohs(udph->dest));
		printf(" ");
		break;
	default:
		printf("protocol %04hx  ", ntohs(ethh->h_proto));
		goto done;
	}

	/* Transport layer */
	switch (proto_in_ip) {
	case IPPROTO_TCP:
		printf("TCP ");
		if (tcph->syn)
			printf("S ");
		if (tcph->fin)
			printf("F ");
		if (tcph->ack)
			printf("A ");
		if (tcph->rst)
			printf("R ");

		printf("seq %u ", ntohl(tcph->seq));
		if (tcph->ack)
			printf("ack %u ", ntohl(tcph->ack_seq));
		break;
	case IPPROTO_UDP:
		printf("UDP ");
		break;
	default:
		printf("protocol %d ", proto_in_ip);
		goto done;
	}

done:
	printf("len=%d\n", len);
}

int num_devices;
struct ps_device devices[PS_MAX_DEVICES];

int num_devices_attached;
int devices_attached[PS_MAX_DEVICES];

void print_usage(char *argv0)
{
	fprintf(stderr, "Usage: %s <interface to sniff> <...>",
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

already_attached:
		;
	}

	assert(num_devices_attached > 0);
}


//thread runs on core i, binding to NIC queue i
void attach(struct ps_handle *handle, int cpu)
{
	int ret;
	int i, flag=0;

	ret = ps_init_handle(handle);
	if (ret != 0) {
		perror("ps_init_handle");
		pthread_exit(NULL);
	}
	
	for (i = 0; i < num_devices_attached; i++) {
		struct ps_queue queue;

		queue.ifindex = devices_attached[i];
	
		if (devices[devices_attached[i]].num_rx_queues <= cpu)	
			continue;

		if (devices[devices_attached[i]].num_tx_queues <= cpu) {
			printf("WARNING: xge%d has not enough TX queues!\n",devices_attached[i]);
			continue;
		}

		flag=1;		//the threads whose cpu id >= queue num should abort.( pthread_exit )
		queue.qidx=cpu;	
		ret = ps_attach_rx_device(handle, &queue);

		if (ret != 0) {
			perror("ps_attach_rx_device");
			pthread_exit(NULL);
		}
	}
	if(!flag) {
		printf("there are not enough queues,thread exit.\n");
		pthread_exit(NULL);
	}
	//printf("attach cpu is %d, thread is %ld\n", cpu,pthread_self());
}



void dump(struct ps_handle *handle)
{
	int ret;
	struct ps_chunk chunk;

	ret = ps_alloc_chunk(handle, &chunk);
	if (ret != 0) {
		perror("ps_alloc_chunk");
		pthread_exit(NULL);
	}

	//printf("thread id is %ld\n",pthread_self());
		
	chunk.recv_blocking = 1;

	if(num_devices_attached <= 0) {	
		goto done;
	}

	for (;;) {
	
		/* batching, blocking mode. */
		chunk.cnt = 1;
		int ret = ps_recv_chunk(handle, &chunk);

		//printf("ret: %d\n", ret);
		if (ret < 0) {
			printf("===> %d: %s, %s\n", ret,
				strerror(ret),
				strerror(-ret));
	
			if (errno == EINTR)
				continue;

			if (!chunk.recv_blocking && errno == EWOULDBLOCK)
				break;
			pthread_exit(NULL);			
		}

		if (ret > 0) {
			//lock for multi threads using unique hardware
			pthread_mutex_lock(&mutex);
			printf("%s:%d:%ld ", devices[chunk.queue.ifindex].name, chunk.queue.qidx, pthread_self());
			pthread_mutex_unlock(&mutex);	


			pthread_mutex_lock(&mutex);
			dump_packet(chunk.buf + chunk.info[0].offset, chunk.info[0].len);
			pthread_mutex_unlock(&mutex);	
		}
		
	}
done:
	ps_close_handle(handle); 
}


int main(int argc, char **argv)
{
	num_devices = ps_list_devices(devices);
	if (num_devices == -1) {
		perror("ps_list_devices");
		exit(1);
	}
	
	parse_opt(argc, argv);
	
	int i = 0, cpu_num = get_cpu_nums();
	assert(cpu_num >= 1);

	pthread_t thread[cpu_num];

	printf("cpu_num: %d\n", cpu_num);
	for(;i < cpu_num; i++) {
		pthread_create(&thread[i], NULL, thread_recv, (void *)(long int)i);
	}

	while(1) {	
		;
	}

	return 0;
}
