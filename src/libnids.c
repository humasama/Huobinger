#include <config.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <alloca.h>
#include <errno.h>
#include <config.h>
#include <pthread.h>
#if (HAVE_UNISTD_H)
#include <unistd.h>
#endif
#include <stdlib.h>
#include "checksum.h"
#include "ip_fragment.h"
#include "scan.h"
#include "tcp.h"
#include "util.h"
#include "nids.h"

#include "fire_common.h"

#ifdef __linux__
extern int set_all_promisc();
#endif

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))
extern int ip_options_compile(unsigned char *);
extern int raw_init();
static int nids_ip_filter(struct ip *, int);

TEST_SET tcp_test[MAX_CPU_CORES];

pthread_key_t ip_context;
pthread_key_t tcp_context;

ip_context_t ip_context_array[MAX_CPU_CORES];
tcp_context_t tcp_context_array[MAX_CPU_CORES];

char *nids_warnings[] = {
	"Murphy - you never should see this message !",
	"Oversized IP packet",
	"Invalid IP fragment list: fragment over size",
	"Overlapping IP fragments",
	"Invalid IP header",
	"Source routed IP frame",
	"Max number of TCP streams reached",
	"Invalid TCP header",
	"Too much data in TCP receive queue",
	"Invalid TCP flags"
};

struct nids_prm nids_params = {
	1040,			/* n_tcp_streams */
	256,			/* n_hosts */
	NULL,			/* device */
	NULL,			/* filename */
	168,			/* sk_buff_size */
	-1,				/* dev_addon */
	256,			/* scan_num_hosts */
	3000,			/* scan_delay */
	10,				/* scan_num_ports */
	nids_no_mem,		/* no_mem() */
	nids_ip_filter,		/* ip_filter() */
	NULL,			/* pcap_filter */
	1,				/* promisc */
	0,				/* one_loop_less */
	1024,			/* pcap_timeout */
	0,				/* multiproc */
	20000,			/* queue_limit */
	0,				/* tcp_workarounds */
};

static int nids_ip_filter(struct ip *x, int len)
{
	(void)x;
	(void)len;
	return 1;
}

/* wireless frame types, mostly from tcpdump (wam) */
#define FC_TYPE(fc)			 (((fc) >> 2) & 0x3)
#define FC_SUBTYPE(fc)		  (((fc) >> 4) & 0xF)
#define DATA_FRAME_IS_QOS(x)	((x) & 0x08)
#define FC_WEP(fc)			  ((fc) & 0x4000)
#define FC_TO_DS(fc)			((fc) & 0x0100)
#define FC_FROM_DS(fc)		  ((fc) & 0x0200)
#define T_MGMT 0x0		/* management */
#define T_CTRL 0x1		/* control */
#define T_DATA 0x2		/* data */
#define T_RESV 0x3		/* reserved */
#define EXTRACT_LE_16BITS(p) \
	((unsigned short)*((const unsigned char *)(p) + 1) << 8 | \
	(unsigned short)*((const unsigned char *)(p) + 0))
#define EXTRACT_16BITS(p)	((unsigned short)ntohs(*(const unsigned short *)(p)))
#define LLC_FRAME_SIZE 8
#define LLC_OFFSET_TO_TYPE_FIELD 6
#define ETHERTYPE_IP 0x0800

#if HAVE_BSD_UDPHDR
#define UH_ULEN uh_ulen
#define UH_SPORT uh_sport
#define UH_DPORT uh_dport
#else
#define UH_ULEN len
#define UH_SPORT source
#define UH_DPORT dest
#endif

static void process_udp(char *data)
{
#if 0
	struct ip *iph = (struct ip *) data;
	struct udphdr *udph;
	struct tuple4 addr;
	int hlen = iph->ip_hl << 2;
	int len = ntohs(iph->ip_len);
	int ulen;
	if (len - hlen < (int)sizeof(struct udphdr)) {
		fprint(ERROR, "packet worng\n");
		return;
	}
	udph = (struct udphdr *) (data + hlen);
	ulen = ntohs(udph->UH_ULEN);
	if (len - hlen < ulen || ulen < (int)sizeof(struct udphdr)) {
		fprint(ERROR, "packet worng\n");
		return;
	}
	/* According to RFC768 a checksum of 0 is not an error (Sebastien Raveau) */
	if (udph->uh_sum && my_udp_check((void *) udph, ulen, iph->ip_src.s_addr, 
		iph->ip_dst.s_addr)) {
		fprint(DEBUG, "packet worng\n");
		return;
	}
	addr.source = ntohs(udph->UH_SPORT);
	addr.dest = ntohs(udph->UH_DPORT);
	addr.saddr = iph->ip_src.s_addr;
	addr.daddr = iph->ip_dst.s_addr;
#endif
}

int nids_init(int core_id)
{
	ip_context_t *my_ip_context = &(ip_context_array[core_id]);
	my_ip_context->self_cpu_id = core_id;
	pthread_setspecific(ip_context, (void *)my_ip_context);
	__builtin_prefetch(my_ip_context);
	__builtin_prefetch(&ip_context);

	tcp_context_t *my_tcp_context = &(tcp_context_array[core_id]);
	my_tcp_context->self_cpu_id = core_id;
	pthread_setspecific(tcp_context, (void *)my_tcp_context);
	__builtin_prefetch(my_tcp_context);
	__builtin_prefetch(&tcp_context);

	tcp_init(nids_params.n_tcp_streams);
	ip_frag_init(nids_params.n_hosts);
	scan_init();

#if defined(MEM_LL)
	init_mem_table();
	// Init tcp digest hash table element in conflict list
	// Add more init here to support lock-free malloc
	mem_init(SIZE_LIST_ELEM, 2000, sizeof(elem_list_type), thread_id);
#endif

	return 1;
}

void nids_exit()
{
	tcp_exit();
	ip_frag_exit();
	scan_exit();
}

static int gen_ip_proc(struct ip *data, int skblen)
{
	int ret = -1;

	switch (data->ip_p) {
		case IPPROTO_TCP:
			ret = process_tcp((u_char *)data, skblen);
			break;
		case IPPROTO_UDP:
			process_udp((char *)data);
			ret = 1;
			break;
		case IPPROTO_ICMP:
			fprint(ERROR, "icmp packet\n");
			if (nids_params.n_tcp_streams)
				process_icmp((u_char *)data);
			break;
		default:
			fprint(ERROR, "bad protocol packet\n");
			break;
	}

	return ret;
}

static int gen_ip_frag_proc(struct ip * data, int len)
{
	struct ip *iph = (struct ip *) data;
	int need_free = 0;
	int skblen, ret;

	if (len < (int)sizeof(struct ip) || iph->ip_hl < 5 || iph->ip_v != 4 ||
			ip_fast_csum((unsigned char *) iph, iph->ip_hl) != 0 ||
			len < ntohs(iph->ip_len) || ntohs(iph->ip_len) < iph->ip_hl << 2) {
		fprint(DEBUG, "wrong packet\n");
		//return -1;
	}

	//return 0;

	if (iph->ip_hl > 5 && ip_options_compile((unsigned char *)data)) {
		fprint(DEBUG, "wrong packet\n");
		//return -1;
	}
	switch (ip_defrag_stub((struct ip *) data, &iph)) {
		case IPF_ISF:
			return -1;
		case IPF_NOTF:
			need_free = 0;
			iph = (struct ip *) data;
			break;
		case IPF_NEW:
			need_free = 1;
			break;
		default:;
	}
	skblen = ntohs(iph->ip_len) + 16;
	if (!need_free)
		skblen += nids_params.dev_addon;
	skblen = (skblen + 15) & ~15;
	skblen += nids_params.sk_buff_size;


	ret = gen_ip_proc(iph, skblen);
	if (need_free) {
		//FIXME: currently we do not handle fragment
		fprint(ERROR, "still cannot handle ip fragmentation\n");
		exit(0);
		free(iph);
	}

	return ret;
}

int nids_process(void *ip_data, int len)
{
	int ret = gen_ip_frag_proc((struct ip *)ip_data, len);
	return ret;
}
