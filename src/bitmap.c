#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include "bitmap.h"
#include "fire_config.h"
#include "fire_common.h"

#define BITSPERWORD 64
#define SHIFT 6
#define MASK 0x3F

extern pthread_key_t tcp_context;
extern fire_config_t *config;

#define WORD_FULL 0x0

inline void clr(int i, tcp_context_t *tcp_thread_local_p) { (tcp_thread_local_p->bitmap)[i>>SHIFT] |= ((uint64_t)1 << (i & MASK));}
inline void set(int i, tcp_context_t *tcp_thread_local_p) { (tcp_thread_local_p->bitmap)[i>>SHIFT] &= ~((uint64_t)1 << (i & MASK));}

void bitmap_init(int cache_elem_num)
{
	tcp_context_t *tcp_thread_local_p = pthread_getspecific(tcp_context);

	if (config->max_stream_num <= cache_elem_num) {
		return;
	}
	int bitmap_size = (config->max_stream_num - cache_elem_num) / BITSPERWORD;
	tcp_thread_local_p->bitmap_size = bitmap_size/(config->worker_num - 1);
	tcp_thread_local_p->bitmap = calloc(tcp_thread_local_p->bitmap_size, sizeof(uint64_t));
	if (!tcp_thread_local_p->bitmap) {
		fprint(ERROR, "Error allocating bitmap!\n");
		exit(0);
	}
	memset((void *)tcp_thread_local_p->bitmap, 0xFF, tcp_thread_local_p->bitmap_size * 8);
	tcp_thread_local_p->walker = -1;
}

// If a bit is 0, it represents that this block is in use
// if is 1, the block is free.
idx_type find_free_index()
{
	uint32_t j;
	tcp_context_t *tcp_thread_local_p = pthread_getspecific(tcp_context);

	tcp_thread_local_p->walker ++;
	if (tcp_thread_local_p->walker == tcp_thread_local_p->bitmap_size)
		tcp_thread_local_p->walker = 0;

	int walker = tcp_thread_local_p->walker;

	// this word has no bits free, continue
	if ((tcp_thread_local_p->bitmap)[walker] == WORD_FULL) {
		printf("Run out of bits????? Too many connections?????\n");
		exit(0);
	}
	
	// find a bit is zero
	j = __builtin_ffsll((tcp_thread_local_p->bitmap)[walker]) - 1;
	if (j >= 0)
		return (idx_type)(walker * BITSPERWORD + j);

	printf("ERROR in find_free_index\n");
	exit(0);
}

idx_type bitmap_get_free_index()
{
	idx_type index;
	tcp_context_t *tcp_thread_local_p = pthread_getspecific(tcp_context);
	
	// Find a free index
	index = find_free_index();

	// Mark as used in bitmap
	set(index, tcp_thread_local_p);

	return index;
}

void bitmap_ret_free_index(idx_type index)
{
	tcp_context_t *tcp_thread_local_p = pthread_getspecific(tcp_context);
	// Mark as unused in bitmap
	clr(index, tcp_thread_local_p);
}
