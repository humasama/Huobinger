#ifndef FIRE_CONFIG_H
#define FIRE_CONFIG_H

#include "psio.h"

typedef struct fire_config_s {
	unsigned int worker_num;

	int max_stream_num;
	int io_batch_num;
	int ifindex;
	char interface[5];
	struct ps_device device;
} fire_config_t;

#endif
