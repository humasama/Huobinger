#ifndef ORIGIN_TCP_H
#define ORIGIN_TCP_H

#include "parallel.h"

#if defined(ORIGIN_TCP)

struct tcp_stream *find_stream(struct tcphdr *, struct ip *, int *);
void add_new_tcp(struct tcphdr *, struct ip *);
void nids_free_tcp_stream(struct tcp_stream *);
void process_tcp(u_char *, int);
int tcp_init(int);
void tcp_exit();
#endif

#endif
