#ifndef FIRE_WORKER_H
#define FIRE_WORKER_H

#include "psio.h"

typedef struct fire_worker_context_s {
	int core_id;
	int queue_id;
	int initialized;
} fire_worker_context_t;

typedef struct fire_worker_s {
	struct ps_handle server_handle;
	struct ps_handle client_handle;
	uint64_t total_packets;
	uint64_t total_bytes;
	struct timeval startime;
	struct timeval endtime;
	struct timeval subtime;
} __attribute__((aligned(64))) fire_worker_t;

void *fire_worker_main(fire_worker_context_t *); 
#endif
