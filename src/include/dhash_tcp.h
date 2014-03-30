#ifndef DHASH_H
#define DHASH_H

#include "signature.h"
#include "parallel.h"

#if defined(MAJOR_INDEXFREE_TCP)

struct tcp_stream *find_stream(struct tcphdr *, struct ip *, int *);
void add_new_tcp(struct tcphdr *, struct ip *);
void nids_free_tcp_stream(struct tcp_stream *);
int process_tcp(u_char *, int);
int tcp_init(int);
void tcp_exit();
#endif

#endif
