#ifndef POWEROFTWO_H
#define POWEROFTWO_H

#include "signature.h"
#include "parallel.h"

#if defined(POWEROFTWO)

#if defined(HIPAC_TCB)
void delete_tcp(char *data);
#endif

struct tcp_stream *find_stream(struct tcphdr *, struct ip *, int *);
static idx_type add_new_tcp(struct tcphdr *, struct ip *);
void nids_free_tcp_stream(struct tcp_stream *);
int process_tcp(u_char *, int);
int tcp_init(int);
void tcp_exit();
#endif

#endif
