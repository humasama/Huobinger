#ifndef FIRE_CONFIG_H
#define FIRE_CONFIG_H

#include "psio.h"

typedef struct fire_config_s {
	unsigned int worker_num;

	int max_stream_num;
	int io_batch_num;
	int client_ifindex;
	int server_ifindex;
	char client_interface[5];
	char server_interface[5];
	struct ps_device client_device;
	struct ps_device server_device;
} fire_config_t;

#endif
