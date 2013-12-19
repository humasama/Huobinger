#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <errno.h>
#include <stdint.h>

#include "fire_worker.h"
#include "fire_config.h"
#include "fire_common.h"
#include "psio.h"

fire_worker_t workers[MAX_WORKER_NUM];
extern fire_config_t *config;

int fire_worker_init(fire_worker_context_t *context)
{
	/* set schedule affinity */
	unsigned long mask = 1 << context->core_id;
	if (sched_setaffinity(0, sizeof(unsigned long), (cpu_set_t *)&mask) < 0) {
		assert(0);
	}

	/* set schedule policy */
	struct sched_param param;
	param.sched_priority = 99;
	pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);

	return 0;
}

int process_packet(char *data, int len)
{
	nids_process(data, len);
	return 0;
}

int fire_worker_start(int queue_id)
{
	int ret, i;

	fire_worker_t *cc = &(workers[queue_id]); 
	assert(ps_init_handle(&(cc->handle)) == 0);

	struct ps_queue queue;
	queue.ifindex = config->ifindex;
	queue.qidx = queue_id;

	assert(ps_attach_rx_device(&(cc->handle), &queue) == 0);
	fprint(INFO, "[Collector %d] is attaching if:queue %d:%d ...\n", queue_id, queue.ifindex, queue.qidx);

	struct ps_chunk chunk;
	assert(ps_alloc_chunk(&(cc->handle), &chunk) == 0);
	chunk.recv_blocking = 1;

	gettimeofday(&(cc->startime), NULL);

	for (;;) {
		chunk.cnt = config->io_batch_num;

		ret = ps_recv_chunk(&(cc->handle), &chunk);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			if (!chunk.recv_blocking && errno == EWOULDBLOCK) {
				fprint(ERROR, "!!! [Collector %d] : recv nothing\n", queue_id);
				assert(0);
			}
			assert(0);
		}

		cc->total_packets += ret;
		cc->total_bytes += ret * 1370;

#if defined(NOT_PROCESS)
		continue;
#endif

		for (i = 0; i < ret; i ++) {
			process_packet(chunk.buf + chunk.info[i].offset, chunk.info[i].len);
		}
	}
	return 0;
}

void *fire_worker_main(fire_worker_context_t *context) 
{
	fprint(INFO, "Worker on core %d, receiving queue %d ...\n", context->core_id, context->queue_id);
	fire_worker_init(context);
	fire_worker_start(context->queue_id);

	pthread_exit(NULL);
}
