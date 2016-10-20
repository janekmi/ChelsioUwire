/*
 * Copyright (c) 2010-2015 Chelsio Communications. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef __CXGB4_UDP_H__
#define __CXGB4_UDP_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#include <chelsio/queue.h>
#include <syslog.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <net/if.h>

#define UDP_MAX_SGE 3
#define UDP_FRAG_RQ_DEPTH 256
#define UDP_FRAG_SIZE 4096
#define UDP_CHELSIO_VID 0x1425

/*
 * max wr size for T4 (ocq limit): 256
 * wr overhead: 32 (struct cpl_tx_pkt) + 16 (fw_eth_tx_pkt_wr)
 * wire protocol overhead: 14 (eth) + 20 (ipv4) + 8 (udp)
 * So the max payload inline limit is: 166 bytes
 */
#define UDP_MAX_INLINE_IPV4 166
#define UDP_MAX_INLINE_IPV6 (UDP_MAX_INLINE_IPV4 - 20)

static inline int udp_max_inline(int family)
{
	if (family == AF_INET)
		return UDP_MAX_INLINE_IPV4;
	return UDP_MAX_INLINE_IPV6;
}

#ifndef IBV_QPT_RAW_ETH
#define IBV_QPT_RAW_ETH 8
#endif

#ifndef IBV_SEND_IP_CSUM
#define IBV_SEND_IP_CSUM (1 << 4)
#endif

#ifndef IBV_SEND_IP6_CSUM
#define IBV_SEND_IP6_CSUM (1 << 5)
#endif

struct udp_send_wr {
	uint64_t		wr_id;
	struct ibv_sge		*sg_list;
	unsigned		num_sge;
	int			send_flags;
	struct sockaddr		*peer;
};

enum udp_send_flags {
	UDP_SEND_FENCE		= 1 << 0,
	UDP_SEND_SIGNALED	= 1 << 1,
	UDP_SEND_SOLICITED	= 1 << 2,
	UDP_SEND_INLINE		= 1 << 3,
	UDP_SEND_HDR_ROOM	= 1 << 4
};

static inline int to_ibv_send_flags(int flags)
{
	int ret = 0;

	if (flags & UDP_SEND_FENCE)
		ret |= IBV_SEND_FENCE;
	if (flags & UDP_SEND_SIGNALED)
		ret |= IBV_SEND_SIGNALED;
	if (flags & UDP_SEND_SOLICITED)
		ret |= IBV_SEND_SOLICITED;
	if (flags & UDP_SEND_INLINE)
		ret |= IBV_SEND_INLINE;
	return ret;
}

struct udp_recv_wr {
	uint64_t		wr_id;
	struct ibv_sge		*sg_list;
	unsigned		num_sge;
};

union sockaddrs {
	struct sockaddr sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	struct sockaddr_storage sas;	/* ensures enough storage */
};

struct udp_dev {
	struct ibv_context		*verbs;
	struct ibv_pd			*pd;
	struct ibv_qp			*frag_qp;
	struct ibv_cq			*frag_cq;
	struct rdma_event_channel	*rch;
	struct rdma_cm_id		*id;
	uint8_t				hwaddr[6];
	uint8_t				port_num;
	struct sockaddr_in		sin;
	struct sockaddr_in6		sin6;
	uint8_t				*frag_bufs;
	struct ibv_mr			*frag_mr;
	uint32_t			nfids;
	char 				ifname[IF_NAMESIZE];
	struct udp_qp			**qpid2ptr;
};

struct udp4_headers {
	struct ether_header 	eth;
	struct iphdr		ip;
	struct udphdr		udp;
} __attribute__ ((packed));

struct udp6_headers {
	struct ether_header 	eth;
	struct ip6_hdr		ip;
	struct udphdr		udp;
} __attribute__ ((packed));

struct udp_headers {
	struct udp4_headers v4;
	struct udp6_headers v6;
};

struct udp_qp;

struct udp_hbuf {
	SLIST_ENTRY(udp_hbuf)	list;
	uint64_t		cookie;
	struct udp_headers  	hdrs;
	uint8_t			*hdrp;
	struct udp_qp		*qp;
	struct udp_srq		*srq;
	uint32_t		wc_count;
	int			off;
}  __attribute__((aligned(256)));

struct udp_stats {
	unsigned long long tx_bytes;
	unsigned long long tx_pkts;
	unsigned long long rx_bytes;
	unsigned long long rx_pkts;
};

struct udp_srq {
	struct udp_dev		*dev;
	struct ibv_srq		*raw_srq;
	struct ibv_mr		*hbufs_mr;
	struct udp_hbuf		*hbufs;
	uint32_t		srq_idx;
	uint32_t		depth;
	uint32_t		count;
	pthread_spinlock_t	lock;
	uint32_t		iqid;
	SLIST_HEAD(,udp_qp)	qps;
	uint8_t			packed;
	uint8_t			first_skipped;
};

struct udp_qp {
	struct udp_dev		*dev;
	struct ibv_qp		*raw_qp;
	struct ibv_mr		*hbufs_mr;
	struct udp_hbuf		*sq_hbufs;
	uint32_t		sq_idx;
	uint32_t		send_depth;
	uint32_t		send_count;
	uint32_t		sq_pending_count;
	struct udp_hbuf		*rq_hbufs;
	uint32_t		rq_idx;
	uint32_t		recv_depth;
	uint32_t		recv_count;
	pthread_spinlock_t	lock;
	uint32_t		fid;
	uint16_t		vlan;
	uint16_t		udp_port;
	union sockaddrs		bound_addr;
	union sockaddrs		laddr;
	union sockaddrs		raddr;
	struct udp_stats 	stats;
	uint8_t			v6only;
	uint8_t			packed;
	uint8_t			first_skipped;
	uint32_t		iqid;
	struct udp_srq		*srq;
	SLIST_ENTRY(udp_qp)	srq_list;
};

enum {
	UDP_IPV6ONLY 		= (1 << 0),
	UDP_PACKED_MODE 	= (1 << 1),
};

int udp_dealloc_dev(struct udp_dev *dev);
int udp_alloc_dev(struct sockaddr_in *sin, struct sockaddr_in6 *sin6, struct udp_dev **devp);
int udp_stop_dev(struct udp_dev *dev);
int udp_start_dev(struct udp_dev *dev, struct ibv_cq *frag_cq);
int udp_create_srq(struct udp_dev *dev, int depth, uint32_t flags, struct udp_srq **srqp);
int udp_destroy_srq(struct udp_srq *srq);
int udp_create_qp(struct udp_dev *dev, struct ibv_cq *send_cq,
		  struct ibv_cq *recv_cq, int send_depth, int recv_depth, struct udp_srq *srq,
		  struct sockaddr *laddr, struct sockaddr *raddr,
		  uint16_t vlan, uint8_t pri, uint32_t flags,
		  struct udp_qp **qpp);
int udp_destroy_qp(struct udp_qp *qp);
int udp_post_send(struct udp_qp *qp, struct udp_send_wr *wr);
int udp_post_send_many(struct udp_qp *qp, struct udp_send_wr *wr, int count);
int udp_post_recv(struct udp_qp *qp, struct udp_recv_wr *wr);
int udp_post_srq_recv(struct udp_srq *srq, struct udp_recv_wr *wr);
int udp_poll_cq(struct ibv_cq *cq, struct ibv_wc *wc, struct sockaddr *from, int flags);
int udp_attach_mcast(struct udp_qp *qp, struct sockaddr *sa);
int udp_detach_mcast(struct udp_qp *qp, struct sockaddr *sa);
void udp_profile_report();

extern unsigned dbg_flags;
extern unsigned dbg_dst;
extern FILE *dbg_file;

enum dbg_levels {
	DBG_UM		= (1 << 0),
	DBG_INIT	= (1 << 1),
	DBG_BIND	= (1 << 2),
	DBG_CONNECT	= (1 << 3),
	DBG_SEND	= (1 << 4),
	DBG_SENDTO	= (1 << 5),
	DBG_SENDMSG	= (1 << 6),
	DBG_WRITE	= (1 << 7),
	DBG_RECV	= (1 << 8),
	DBG_RECVFROM	= (1 << 9),
	DBG_RECVMSG	= (1 << 10),
	DBG_READ	= (1 << 11),
	DBG_CLOSE	= (1 << 12),
	DBG_SELECT	= (1 << 13),
	DBG_POLL	= (1 << 14),
	DBG_EPOLL	= (1 << 15),
	DBG_ROUTE	= (1 << 16),
	DBG_DUP		= (1 << 17),
	DBG_OPT		= (1 << 18),
	DBG_SOCKET	= (1 << 19),
};

#define DBG_RD (DBG_RECV | DBG_RECVFROM | DBG_RECVMSG | DBG_READ)
#define DBG_WR (DBG_SEND | DBG_SENDTO | DBG_SENDMSG | DBG_WRITE)
#define DBG_IO (DBG_RD | DBG_WR)


enum {
	DBG_DST_SYSLOG,
	DBG_DST_STDOUT,
	DBG_DST_STDERR,
	DBG_DST_FILE
};

#ifdef DEBUG
#define DBG(l, fmt, args...) \
{ \
	if ((l) & dbg_flags) { \
		switch (dbg_dst) { \
		case DBG_DST_SYSLOG: \
			syslog(LOG_DEBUG, "%08x %s: " fmt, (unsigned)pthread_self(), __func__, ## args); \
			break; \
		default: \
			fprintf(dbg_file, "%08x %s: " fmt, (unsigned)pthread_self(), __func__, ## args); \
			fflush(dbg_file); \
			break; \
		} \
	} \
}

#else
#define DBG(l, fmt, args...)
#endif

#endif
