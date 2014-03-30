#ifndef _NIDS_TCP_H
#define _NIDS_TCP_H
#include <sys/time.h>
#include "parallel.h"

struct skbuff {
	struct skbuff *next;
	struct skbuff *prev;

	void *data;
	u_int len;
	u_int truesize;
	u_int urg_ptr;

	char fin;
	char urg;
	u_int seq;
	u_int ack;
};

int tcp_init(int);
void tcp_exit();
int process_tcp(u_char *, int);
void process_icmp(u_char *);
void tcp_check_timeouts(struct timeval *);

#endif /* _NIDS_TCP_H */
