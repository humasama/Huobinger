#ifndef FIRE_COMMON_H
#define FIRE_COMMON_H

#include <stdio.h>
#include <execinfo.h>

#define STAT	0
#define FATAL	1
#define ERROR	2
#define WARN	3
#define INFO	4
#define DEBUG	5
#define PRINT_LEVELS	6

#ifndef FIRE_PRINT_LEVEL
#define FIRE_PRINT_LEVEL	FATAL
#endif

extern char *FIRE_PRINT_MSG[];

#ifdef FIRE_PRINT_BUFFER
#include <sys/time.h>
#include "spinlock.h"

extern char *fprint_buffer;
extern int fprint_lines;
extern int fprint_head;
extern struct spinlock fprint_lock;

#define fprint(lvl, fmt, arg...) \
	do { \
		if (lvl <= FIRE_PRINT_LEVEL) { \
			int len; \
			struct timeval t; \
			gettimeofday(&t, NULL); \
			acquire(&fprint_lock); \
			len = sprintf(fprint_buffer + fprint_head, \
					"[%d %s] %lf " fmt, getpid(), FIRE_PRINT_MSG[lvl], \
					((double)(t.tv_sec) + t.tv_usec / 1000000.0), ##arg); \
			fprint_lines++; \
			fprint_head += len + 1; \
			release(&fprint_lock); \
		} \
	} while (0)
#else
#define fprint(lvl, fmt, arg...) \
		do { \
			if (lvl <= FIRE_PRINT_LEVEL) { \
				printf("[%d %s] " fmt, getpid(), FIRE_PRINT_MSG[lvl], ##arg); \
			} \
		} while (0)
#endif

void fprint_init();
void fprint_fini();

#ifndef gettid
#include <unistd.h>
#include <sys/syscall.h>
static inline pid_t gettid()
{
	return (pid_t)syscall(186);
}
#endif

void panic(char *msg);

#endif
