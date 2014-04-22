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
#define DEBUG
#define TIMECACULATE

int pktlen = 128;	// meaningless

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
			//(double)(total_tx_bytes*8) / (double) ((subtime.tv_sec*1000000+subtime.tv_usec) * 1000),
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
        *(uint32_t *)ip = htonl((ntohl(*(uint32_t *)ip) + 2011 * index) % 0xFFFFFFFF);
        ip = chunk->buf + chunk->info[index].offset + 34;;      // modify src port
        *(uint16_t *)ip = htons((ntohs(*(uint16_t *)ip) + 1783 * index) % 0xFFFF);
}

/*
void prepare_syn_pkt(char **pktdata, int *len)
{
        int file_no, tmp_pktlen;
        printf("input the file number :\n");
        scanf("%d", &file_no);

        if ((fct = preload_pcap_file(file_no)) != NULL) {
                 printf("Loading done, file %d\n", file_no);
                 if (!check_pcap(fct))
                        printf("It is not trace file, core %d\n", my_cpu);
        } else {
                printf("Loading failed, file %d\n", file_no);
        }

	char *str = prep_next_skb(fct, &tmp_pktlen);
	*len = tmp_pktlen - 20;	//str[21] - '0'
	(*pktdata) = (char)malloc(sizeof(char) * (*len));
	memcpy((*pktdata), str, 20);
	memcpy((*pktdata) + 20), str + 20, 
}
*/

void build_syn_pkt(struct ps_chunk *chunk, int seq)	//c --> s
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
#ifdef DEBUG
printf("pcap after memcpy: ip tot len is %u\n",ntohs(iph->tot_len));
#endif

		iph->tot_len =htons(chunk->info[i].len - sizeof(struct ethhdr));
		build_packet(chunk, i);		

#ifdef DEBUG
printf("syn first: ip tot len is %u\n",ntohs(iph->tot_len));
#endif

		tcph = (struct tcphdr *)(pktdata + sizeof(struct ethhdr) + 4*iph->ihl);
#ifdef DEBUG
#endif
		tcph->syn = 1;
		tcph->ack = 0;
		tcph->psh = 0;
		tcph->seq = htonl(seq);
	}
}

void build_syn_ack(struct ps_chunk *chunk)
{
	char *pktdata;
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct tcphdr *tcph;
	__be32 tmp;
	__u32 tmp_u;
	__be16 tmp_port;
	int i = 0; 

	for(; i < chunk->cnt; i++) {

	pktdata = chunk->buf + chunk->info[i].offset;
	ethh = (struct ethhdr *)pktdata;
	iph = (struct iphdr *)(ethh + 1);
	tmp = iph->saddr;
	iph->saddr = iph->daddr;
	iph->daddr = tmp;
	iph->tot_len =htons(chunk->info[i].len - sizeof(struct ethhdr)); //not necessary
	tcph = (struct tcphdr *)(pktdata + sizeof(struct ethhdr) + 4*iph->ihl);
	
	tmp_u = ntohl(tcph->seq) ;
	tcph->seq = tcph->ack_seq;
	tcph->ack_seq = htonl(tmp_u + 1);
	tcph->syn = 0;
	tcph->ack = 1;
	tcph->psh = 0;  //no data
#ifdef DEBUG
printf("syn ack: seq_s is %d, ack_seq is %d \n", tmp_u, ntohl(tcph->ack_seq) );
#endif
	tmp_port = tcph->source;
	tcph->source = tcph->dest;
	tcph->dest = tmp_port;
	}
}

/*
int check_ack(struct ps_chunk *chunk, int seq, int ack, int syn_flag)
{
	char *pktdata = chunk->buf + chunk->info[0].offset;
	struct ethhdr *ethh = (struct ethhdr *)pktdata;
	struct iphdr *iph = (struct iphdr *)(ethh + 1);
	struct tcphdr *tcph = (struct tcphdr *)(pktdata + sizeof(struct ethhdr) + 4*iph->ihl);
	
	if(tcph->ack_seq == ack && tcph->ack == 1) {
		if(syn_flag) {
			if(tcph->syn == 1) return 1;
			return 0;
		}
		else {
			if((tcph->seq == seq) && (tcph->syn == 0)) return 1;
			return 0;
		}
	}
	return 0;
							
}
*/

void build_req_pkt(struct ps_chunk *chunk)
{
	char *pktdata;
        struct ethhdr *ethh;
	struct iphdr *iph;
	struct tcphdr *tcph;
	__be32 tmp;
	__be16 tmp_port;
	__u32 tmp_u;

	int i = 0;
	for(; i < chunk->cnt; i++) {
		pktdata = (char*)(chunk->buf + chunk->info[i].offset);
		ethh = (struct ethhdr *)pktdata;
		iph = (struct iphdr *)(ethh + 1);
		tcph = (struct tcphdr *)(pktdata + sizeof(struct ethhdr) + 4*iph->ihl);

		tmp = iph->saddr;
        	iph->saddr = iph->daddr;
        	iph->daddr = tmp;
        
		tmp_port = tcph->source;
        	tcph->source = tcph->dest;
        	tcph->dest = tmp_port;

		tmp_u = ntohl(tcph->seq);
        	tcph->seq = tcph->ack_seq;
		tcph->ack_seq = htonl(tmp_u + chunk->info[i].len - sizeof(struct ethhdr) \
						- sizeof(struct iphdr) - sizeof(struct tcphdr) - 20);	//tcp option 20B
		tcph->ack = 1;
		tcph->syn = 0;
		tcph->psh = 1;
#ifdef DEBUG
printf("request pkt : seq is %u, ack is %u, (sip %u, sport %u, dip %u, dport %u)\n", 
		ntohl(tcph->seq), ntohl(tcph->ack_seq),
			ntohl(iph->saddr), ntohs(tcph->source), 
				ntohl(iph->daddr), ntohs(tcph->dest));
#endif
	}

#ifdef DEBUG
//printf("req pkt: length is %d \n", chunk->info[0].len);
#endif

}

void build_first_req_pkt(struct ps_chunk *chunk)
{
	char *buf;
	struct ethhdr *ethh;
        struct iphdr *iph;
        struct tcphdr *tcph;
	int length;
	int i;
	
	for(i = 0; i < chunk->cnt; i++) {

       		length  = chunk->info[i].len + 10;
        	buf = (char *)malloc(sizeof(char) * length);
       		memset(buf, (int)'A', length);

        	memcpy(buf, chunk->buf + chunk->info[i].offset, chunk->info[i].len);
        
       		ethh = (struct ethhdr *)buf;
        	iph = (struct iphdr *)(ethh + 1);
        	tcph = (struct tcphdr *)(buf + sizeof(struct ethhdr) + 4*iph->ihl);

#ifdef DEBUG
//printf("before memcpy ip tot len is %u\n", ntohs(iph->tot_len));
#endif
		iph->tot_len =htons(ntohs(iph->tot_len) + 10);  
       		tcph->psh = 1;
        	tcph->syn = 0;
	        tcph->ack = 1;

		chunk->info[i].len = length;
                chunk->info[i].offset = i * PS_ALIGN(length, 64);
		memcpy(chunk->buf + chunk->info[i].offset, buf, length);
#ifdef DEBUG
ethh = (struct ethhdr *)buf;
iph = (struct iphdr *)(ethh + 1);
tcph = (struct tcphdr *)(buf + sizeof(struct ethhdr) + 4*iph->ihl);
//printf("first request after memcpy: seq_c is %u, ack_c is %u. ip tot is %u\n",\ 
//				ntohl(tcph->seq), ntohl(tcph->ack_seq), ntohs(iph->tot_len));
printf("first request pkt : seq is %u, ack is %u, (sip %u, sport %u, dip %u, dport %u)\n",
                ntohl(tcph->seq), ntohl(tcph->ack_seq),
                        ntohl(iph->saddr), ntohs(tcph->source),
                                ntohl(iph->daddr), ntohs(tcph->dest));
#endif

	free(buf);
	buf = NULL;
	}

}

void tcp_connect(int cpu, struct ps_queue *queue)
{

#ifdef DEBUG
int connect_times = 0;
int times_count = 0;
#endif

#ifdef TIMECACULATE
struct timeval tpstart, tpend;
float timeuse;
#endif
	struct ps_handle *handle = &handles[cpu];
	struct ps_chunk chunk;
	file_cache_t *fct;
	unsigned int tmp_pktlen;
	u_char *pktdata;

	int i, ret;
	int status = 1;
	int ifindex;
	char *ip;
	int pkt_num;
	
	assert(ps_init_handle(handle) == 0);
	assert(ps_attach_rx_device(handle, queue) == 0);
	assert(ps_alloc_chunk(handle, &chunk) == 0);
	chunk.recv_blocking = 1;

//==================================================
	chunk.queue.ifindex = queue->ifindex;
	chunk.queue.qidx = queue->qidx;
//===================================================

	int file_no = 0;
	//printf("input the file number :\n");
	//scanf("%d", &file_no);

	printf("input the pkt num of one connection:\n");
	scanf("%d", &pkt_num);

        printf("input the communication times :\n");
        scanf("%d", &connect_times);
	
	chunk.cnt = pkt_num;
        assert(pkt_num > 0);

	if ((fct = preload_pcap_file(file_no)) != NULL) {
		 printf("Loading done, file %d\n", file_no);
                 if (!check_pcap(fct))
			printf("It is not trace file, core %d\n", my_cpu);
        } else {
                printf("Loading failed, file %d\n", file_no);
        }

	pktdata = prep_next_skb(fct, &tmp_pktlen);
	pktlen = tmp_pktlen;	//the accurate pkt length.


#ifdef DEBUG
printf("pcap pktlen is %d\n", pktlen);
#endif


	i = 0;
	for(; i < chunk.cnt; i++) {
		//chunk.info[i].offset = i * pktlen;
		chunk.info[i].offset = i * PS_ALIGN(pktlen, 64);
		chunk.info[i].len = pktlen;   
		memcpy(chunk.buf + chunk.info[i].offset, pktdata, pktlen);
		//printf("after memcpy: chunk.offset is %d, chunk.len is %d\n", chunk.info[i].offset, chunk.info[i].len);

	}	

	while(1) {
#ifdef DEBUG
		if(times_count  >= connect_times) exit(0);
#endif
		switch(status) {
			case 1:	/* syn */
				build_syn_pkt(&chunk, 0);
				while(1) {
					ret = ps_send_chunk(handle, &chunk);	//forbid syn pkt fail.
#ifdef DEBUG
#endif
					if (ret > 0) {
						break;
					}
				}
				while(1) {
					ret = ps_recv_chunk(handle, &chunk);
#ifdef DEBUG
#endif
					if (ret > 0) {
						break;
					}
				}

				chunk.cnt = ret;
				build_syn_ack(&chunk);	
				while(1) {	
					ret = ps_send_chunk(handle, &chunk);
#ifdef DEBUG
#endif
					if(ret > 0) {
#ifdef DEBUG
#endif
						//exit(0);	//test syn procedure
						status = 4;
						break;
					}
				}
				break;

			case 2:	/* connect  */

				if(ret > 0) chunk.cnt = ret;
				else chunk.cnt = pkt_num;	//bug panda

				build_req_pkt(&chunk);
				while(1) {
					ret = ps_send_chunk(handle, &chunk);
					if(ret > 0) {
#ifdef DEBUG
#endif 

#ifdef TIMECACULATE 
						gettimeofday(&tpstart, NULL);
#endif
						status = 3;
						break;
					}else printf("case 2: ret<0\n");
				}
#ifdef DEBUG
#endif
				break;	
			case 3:
				if(ret > 0) chunk.cnt = ret;
				else chunk.cnt = pkt_num;     //bug panda
				while(1) {
					ret = ps_recv_chunk(handle, &chunk);
					if (ret > 0) {
#ifdef DEBUG
						times_count ++;
#endif

#ifdef TIMECACULATE 
						gettimeofday(&tpend, NULL);
						timeuse = 1000000 * (tpend.tv_sec - tpstart.tv_sec) + tpend.tv_usec - tpstart.tv_usec;
						printf("time interval is %fs \n", timeuse / 1000000);
						timeuse = 0.0; 
#endif
						status = 2;
						break;
					}else printf("case 3: ret<0\n");
				}
				break;

			case 4:
				if(ret > 0) chunk.cnt = ret;
				else chunk.cnt = pkt_num;
				build_first_req_pkt(&chunk);

				while(1) {
					ret = ps_send_chunk(handle, &chunk);
#ifdef DEBUG
#endif
					if(ret > 0) {
						chunk.cnt = ret;	//bug panda
						while(1) {
							ret = ps_recv_chunk(handle, &chunk);
#ifdef DEBUG
#endif
							if(ret > 0) {
								status = 2;
#ifdef DEBUG
								times_count ++;
#endif 
								break;
							}
						}
					}
					if(status == 2) break;
				}
				//exit(0);	//test first request
				break;
		}

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

		//int ret = fork();
		//assert(ret >= 0);	
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
		
		//if (ret == 0) { 
			bind_cpu(i);
			signal(SIGINT, handle_signal);

			tcp_connect(my_cpu, queue);
			return 0;
		//}
	}

	signal(SIGINT, SIG_IGN);

	while (1) {
		int ret = wait(NULL);
		if (ret == -1 && errno == ECHILD)
			break;
	}

	return 0;
}
