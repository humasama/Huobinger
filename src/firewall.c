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
#include <sys/time.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include "fire_config.h"
#include "fire_common.h"
#include "fire_worker.h"
#include "psio.h"
#include "hipac.h"

#define HIPAC

extern fire_worker_t workers[MAX_WORKER_NUM];
extern pthread_key_t ip_context;
extern pthread_key_t tcp_context;
fire_config_t *config;

#ifdef HIPAC
struct rlp *l;  
#endif

//int affinity_array[12] = {1,3,5,7,9,11,0,2,4,6,8,10};
int affinity_array[12] = {0,2,4,6,8,10,1,3,5,7,9,11};

int get_cpu_nums()
{
	return sysconf(_SC_NPROCESSORS_ONLN);
}

int fire_init_config()
{
	config = (fire_config_t *)calloc(sizeof(fire_config_t), 1);

	memcpy(config->client_interface, "xge1", sizeof("xge1"));
	memcpy(config->server_interface, "xge0", sizeof("xge0"));
	config->io_batch_num = 512;		//512;
	config->client_ifindex = -1;
	config->server_ifindex = -1;
	config->max_stream_num = 2000; // XXX
	//config->worker_num = 8;

	return 0;
}

int fire_init_ioengine()
{
	int i, ifindex = -1;
	int num_devices_attached = 0;
	int devices_attached[PS_MAX_DEVICES];
	struct ps_device devices[PS_MAX_DEVICES];

	int num_devices = ps_list_devices(devices);
	if (num_devices == -1) {
		perror("ps_list_devices");
		exit(1);
	}

	/* client side interface */
	for (i = 0; i < num_devices; i ++) {
		if (strcmp(config->client_interface, devices[i].name) != 0)
			continue;
		ifindex = devices[i].ifindex;
		memcpy(&(config->client_device), &(devices[i]), sizeof(struct ps_device));
		break;
	}
	assert (ifindex != -1);

	for (i = 0; i < num_devices_attached; i ++) {
		assert(devices_attached[i] != ifindex);
	}
	devices_attached[num_devices_attached] = ifindex;
	config->client_ifindex = ifindex;
	num_devices_attached ++;


	/* server side interface */
	for (i = 0; i < num_devices; i ++) {
		if (strcmp(config->server_interface, devices[i].name) != 0)
			continue;
		ifindex = devices[i].ifindex;
		memcpy(&(config->server_device), &(devices[i]), sizeof(struct ps_device));
		break;
	}
	assert (ifindex != -1);

	for (i = 0; i < num_devices_attached; i ++) {
		//assert(devices_attached[i] != ifindex);
	}
	devices_attached[num_devices_attached] = ifindex;
	config->server_ifindex = ifindex;
	//config->client_ifindex = ifindex;
	num_devices_attached ++;

    /* There are the same number of queues and workers */
    config->worker_num = devices[0].num_rx_queues; 

	return 0;
}

int fire_init_pthread_keys()
{
	pthread_key_create(&ip_context, NULL);
	pthread_key_create(&tcp_context, NULL);

	return 0;
}

void stop_signal_handler(int signal)
{
	int i;
	struct timeval subtime;
	uint64_t total_rx_packets = 0, total_rx_bytes = 0;;
	fire_worker_t *cc;
	double speed_handle = 0;
	double speed_actual = 0;

	for (i = 0; i < config->worker_num; i ++) {
		cc = &(workers[i]);

		gettimeofday(&(cc->endtime), NULL);
		timersub(&(cc->endtime), &(cc->startime), &(cc->subtime));
	}

	for (i = 0; i < config->worker_num; i ++) {
		cc = &(workers[i]);
		subtime = cc->subtime;

		total_rx_packets = (cc->client_handle).rx_packets[config->client_ifindex];
		total_rx_bytes = (cc->client_handle).rx_bytes[config->client_ifindex];
		speed_handle += (double)((total_rx_bytes + total_rx_packets * 20) * 8) / (double) ((subtime.tv_sec * 1000000 + subtime.tv_usec) * 1000);

		printf("----------\n");
		printf("In handle: %ld packets received, elapse time : %lds, RX Speed : %lf Mpps, %5.2f Gbps, Aveage Len. = %ld\n", 
				total_rx_packets, subtime.tv_sec, 
				(double)(total_rx_packets) / (double) (subtime.tv_sec * 1000000 + subtime.tv_usec),
				(double)((total_rx_bytes + total_rx_packets * 20) * 8) / (double) ((subtime.tv_sec * 1000000 + subtime.tv_usec) * 1000),
				total_rx_bytes / total_rx_packets);

		total_rx_packets = cc->total_packets;
		total_rx_bytes = cc->total_bytes;
		speed_actual += (double)((total_rx_bytes + total_rx_packets * 20) * 8) / (double) ((subtime.tv_sec * 1000000 + subtime.tv_usec) * 1000),
		printf("Actual: %ld packets received, elapse time : %lds, RX Speed : %lf Mpps, %5.2f Gbps, Aveage Len. = %ld\n", 
				total_rx_packets, subtime.tv_sec, 
				(double)(total_rx_packets) / (double) (subtime.tv_sec * 1000000 + subtime.tv_usec),
				(double)((total_rx_bytes + total_rx_packets * 20) * 8) / (double) ((subtime.tv_sec * 1000000 + subtime.tv_usec) * 1000),
				total_rx_bytes / total_rx_packets);
	}

	printf("----------\n");
	printf("<<< IOEngine handle speed %lf, actual processing speed %lf >>>\n", speed_handle, speed_actual);

	exit(0);
}

int fire_launch_workers()
{
	unsigned int i;
	pthread_t tid;
	pthread_attr_t attr;
	fire_worker_context_t *context;

#if defined(AFFINITY_NIC)
	fprint(INFO, "Affinity on the NIC node\n");
#elif defined(AFFINITY_GPU)
	fprint(INFO, "Affinity on the GPU node\n");
#elif defined(AFFINITY_SCATTER)
	fprint(INFO, "Affinity scatter on two nodes\n");
#elif defined(AFFINITY_STATIC)
	fprint(INFO, "Affinity specified in static array\n");
#elif defined(AFFINITY_NO)
	fprint(INFO, "Not assign affinity manually\n");
#else
	fprint(ERROR, "No affinity scheme selected\n");
	exit(0);
#endif

#ifdef HIPAC
	l = (struct rlp*)malloc(sizeof(struct rlp));
	l->rangeArray = (struct rlp_range *) malloc (sizeof(struct rlp_range) * 2);	//1 ~ 2N+2
	init_rlp_tree(l);
#endif

	for (i = 0; i < config->worker_num; i ++) {
		context = (fire_worker_context_t *)malloc(sizeof(fire_worker_context_t));
		context->queue_id = i;
#if defined(AFFINITY_NIC)
		context->core_id = i * 2 + 1;
#elif defined(AFFINITY_GPU)
		context->core_id = i * 2;
#elif defined(AFFINITY_SCATTER)
		context->core_id = i;
#elif defined(AFFINITY_STATIC)
		context->core_id = affinity_array[i];
#endif

		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		if (pthread_create(&tid, &attr, (void *)fire_worker_main, (void *)context) != 0) {
			fprint(ERROR, "pthread_create error!!\n");
			return -1;
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	fire_init_config();
	fire_init_ioengine();
	fire_init_pthread_keys();
	
	signal(SIGINT, stop_signal_handler);

	fire_launch_workers();

	while(1) sleep(60);	
	return 0;
}
