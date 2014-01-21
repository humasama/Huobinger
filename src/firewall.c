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

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include "fire_config.h"
#include "fire_worker.h"
#include "psio.h"

extern fire_worker_t workers[MAX_WORKER_NUM];
extern pthread_key_t ip_context;
extern pthread_key_t tcp_context;
fire_config_t *config;

int get_cpu_nums()
{
	return sysconf(_SC_NPROCESSORS_ONLN);
}

int fire_init_config()
{
	config = (fire_config_t *)calloc(sizeof(fire_config_t), 1);

	memcpy(config->interface, "xge1", sizeof("xge1"));
	config->io_batch_num = 128;
	config->ifindex = -1;
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

	for (i = 0; i < num_devices; i ++) {
		if (strcmp(config->interface, devices[i].name) != 0)
			continue;
		ifindex = devices[i].ifindex;
		memcpy(&(config->device), &(devices[i]), sizeof(struct ps_device));
		break;
	}
	assert (ifindex != -1);

    /* There are the same number of queues and workers */
    config->worker_num = (config->device).num_rx_queues; 

	for (i = 0; i < num_devices_attached; i ++) {
		assert(devices_attached[i] != ifindex);
	}
	devices_attached[num_devices_attached] = ifindex;
	config->ifindex = ifindex;
	num_devices_attached ++;

	return 0;
}

int fire_init_pthread_keys()
{
	pthread_key_create(&ip_context, NULL);
	pthread_key_create(&tcp_context, NULL);

	return 0;
}

int fire_launch_workers()
{
	unsigned int i;
	pthread_t tid;
	pthread_attr_t attr;
	fire_worker_context_t *context;

	for (i = 0; i < config->worker_num; i ++) {
		context = (fire_worker_context_t *)malloc(sizeof(fire_worker_context_t));
		context->queue_id = i;
		context->core_id = i;

		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		if (pthread_create(&tid, &attr, (void *)fire_worker_main, (void *)context) != 0) {
			printf("pthread_create error!!\n");
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
	
	fire_launch_workers();

	while(1) sleep(60);	
	return 0;
}
