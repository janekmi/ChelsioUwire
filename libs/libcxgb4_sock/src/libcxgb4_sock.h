/*
 * Copyright (c) 2004 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005-2006 Mellanox Technologies Ltd.  All rights reserved.
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
#ifndef __LIBCXGB4_SOCK_H__
#define __LIBCXGB4_SOCK_H__

#include <sys/poll.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/syslog.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <pthread.h>

#include "chelsio/queue.h"
#include "chelsio/cxgb4_udp.h"

typedef int (
	*ioctl_func_t ) (
	int fd,
	int request,
	void *arg0,
	void *arg1,
	void *arg2,
	void *arg3,
	void *arg4,
	void *arg5,
	void *arg6,
	void *arg7 );

typedef int (
	*fcntl_func_t ) (
	int fd,
	int cmd,
	... );

typedef int (
	*socket_func_t ) (
	int domain,
	int type,
	int protocol );

typedef int (
	*setsockopt_func_t ) (
	int s,
	int level,
	int optname,
	const void *optval,
	socklen_t optlen );

typedef int (
	*getsockopt_func_t ) (
	int s,
	int level,
	int optname,
	void *optval,
	socklen_t *optlen );

typedef int (
	*bind_func_t ) (
	int sockfd,
	const struct sockaddr * my_addr,
	socklen_t addrlen );

typedef int (
	*connect_func_t ) (
	int sockfd,
	const struct sockaddr * serv_addr,
	socklen_t addrlen );

typedef int (
	*close_func_t ) (
	int fd );

typedef int (
	*dup_func_t ) (
	int fd );

typedef int (
	*dup2_func_t ) (
	int oldfd,
	int newfd );

typedef int (
	*dup3_func_t ) (
	int oldfd,
	int newfd,
	int flags );

typedef int (
	*getsockname_func_t ) (
	int fd,
	struct sockaddr * name,
	socklen_t * namelen );

typedef int (
	*getpeername_func_t ) (
	int fd,
	struct sockaddr * name,
	socklen_t * namelen );

typedef int (
	*select_func_t ) (
	int n,
	fd_set * readfds,
	fd_set * writefds,
	fd_set * exceptfds,
	struct timeval * timeout );

typedef int (
	*pselect_func_t ) (
	int n,
	fd_set * readfds,
	fd_set * writefds,
	fd_set * exceptfds,
	const struct timespec * timeout,
	const sigset_t * sigmask);

typedef int (
	*poll_func_t ) (
	struct pollfd *ufds,
	unsigned long int nfds,
	int timeout);

typedef int (
	*epoll_create_func_t ) (
	int size);

typedef int (
	*epoll_create1_func_t ) (
	int flags);

typedef int (
	*epoll_ctl_func_t ) (
	int epfd,
	int op,
	int fd,
	struct epoll_event *event);

typedef int (
	*epoll_wait_func_t ) (
	int epfd,
	struct epoll_event *events,
	int maxevents,
	int timeout);

typedef int (
	*epoll_pwait_func_t ) (
	int epfd,
	struct epoll_event *events,
	int maxevents,
	int timeout,
	const sigset_t *sigmask);

typedef ssize_t (
	*write_func_t ) (
	int fd,
	const void *buf,
	size_t count);

typedef ssize_t (
	*writev_func_t ) (
	int fd,
	const struct iovec *iov,
	int iovcnt);

typedef ssize_t (
	*send_func_t ) (
	int s,
	const void *buf,
	size_t len,
	int flags);

typedef ssize_t (
	*sendto_func_t ) (
	int s,
	const void *buf,
	size_t len,
	int flags,
	const struct sockaddr *to,
	socklen_t tolen);

typedef ssize_t (
	*sendmsg_func_t ) (
	int s,
	const struct msghdr *msg,
	int flags);

typedef ssize_t (
	*read_func_t ) (
	int fd,
	void *buf,
	size_t count);

typedef ssize_t (
	*readv_func_t ) (
	int fd,
	const struct iovec *iov,
	int iovcnt);

typedef ssize_t (
	*recv_func_t ) (
	int s,
	void *buf,
	size_t len,
	int flags);

typedef ssize_t (
	*recvfrom_func_t ) (
	int s,
	const void *buf,
	size_t len,
	int flags,
	struct sockaddr *from,
	socklen_t *fromlen);

typedef ssize_t (
	*recvmsg_func_t ) (
	int s,
	struct msghdr *msg,
	int flags);

struct socket_lib_funcs
{
	socket_func_t socket;
	bind_func_t bind;
	connect_func_t connect;
	write_func_t write;
	writev_func_t writev;
	send_func_t send;
	sendto_func_t sendto;
	sendmsg_func_t sendmsg;
	read_func_t read;
	readv_func_t readv;
	recv_func_t recv;
	recvfrom_func_t recvfrom;
	recvmsg_func_t recvmsg;
	ioctl_func_t ioctl;
	fcntl_func_t fcntl;
	setsockopt_func_t setsockopt;
	getsockopt_func_t getsockopt;
	close_func_t close;
	dup_func_t dup;
	dup2_func_t dup2;
	dup3_func_t dup3;
	getpeername_func_t getpeername;
	getsockname_func_t getsockname;
	select_func_t select;
	pselect_func_t pselect;
	poll_func_t poll;
	epoll_create_func_t epoll_create;
	epoll_create1_func_t epoll_create1;
	epoll_ctl_func_t epoll_ctl;
	epoll_wait_func_t epoll_wait;
	epoll_pwait_func_t epoll_pwait;
};
extern struct socket_lib_funcs socket_funcs;

#define lsocket socket_funcs.socket
#define lbind socket_funcs.bind
#define lclose socket_funcs.close
#define lsend socket_funcs.send
#define lrecv socket_funcs.recv
#define lfcntl socket_funcs.fcntl

enum states {
	IDLE = 0,
	BOUND = 1,
	CONNECTED = 2
};

enum {
	SQ_COAL = 20,
	SQ_DEPTH = SQ_COAL * 4,
	RQ_DEPTH = 1020,
};

struct cs_context;

enum buf_status {
	FREE = 0,
	PENDING,
	POSTED,
};

struct cs_buf {
	SLIST_ENTRY(cs_buf)	list;
	uint8_t			*addr;
	struct cs_context	*c;
	unsigned 		wc_count;
	enum buf_status		status;
	union sockaddrs		peer;
};

struct stats {
	unsigned long long fast_sends;
	unsigned long long slow_sends;
	unsigned long long fast_recvs;
	unsigned long long slow_recvs;
	unsigned long long waits;
};

struct cs_context {
	int sockfd;
	struct chelsio_dev *chelsio_dev;
	struct udp_dev *dev;
	struct ibv_comp_channel *rq_chan;
	struct ibv_comp_channel *sq_chan;
	struct ibv_cq *frag_cq;
	struct udp_qp *qp;
	struct ibv_cq *scq;
	struct ibv_cq *rcq;
	struct cs_buf *rbuf;
	struct cs_buf *prev_rbuf;
	unsigned rbuf_curoff;
	union sockaddrs laddr;
	union sockaddrs raddr;
	enum states state;
#ifdef USE_MUTEX
	pthread_mutex_t lock;
#else
	pthread_spinlock_t lock;
#endif
	uint8_t *bufs;
	struct ibv_mr *bufs_mr;
	struct cs_buf *sq_bufs;;
	struct ibv_sge *sq_sges;
	struct udp_send_wr *sq_wrs;
	unsigned sq_idx;
	unsigned snd_cnt;
	unsigned sq_coal_count;
	struct cs_buf *rq_bufs;;
	in_addr_t rtcache_in;
	uint8_t rtcache_in6[16];
	int rtcache_answer;
	unsigned rmsn;
	unsigned smsn;
	uint8_t mcast_if;
	uint8_t nonblocking;
	uint8_t slowpath;
	uint8_t v6only;
	uint16_t vlan;
	uint8_t pri;
	int spin_count;
	struct stats stats;
	int buf_size;
	int huge_size;
	int max_inline;
	int coalescing;
	unsigned long long coal_count;
	unsigned long long coal_sum;
	unsigned long long coal_transitions;
	unsigned long long sq_full;
};

#define MAX_UDP_HDR_SIZE 64
#define ulp_mss(c) \
	(c->chelsio_dev->mtu - (c->laddr.sa.sa_family == AF_INET ? 30 : 50))

struct chelsio_dev {
	STAILQ_ENTRY(chelsio_dev) list;
	uint8_t hwaddr[IFHWADDRLEN];
	struct sockaddr_in ipv4addr;
	struct sockaddr_in6 ipv6addr;
	char name[IF_NAMESIZE];
	int ifindex;
	int mtu;
};

struct epoller {
	LIST_ENTRY(epoller)	list;
	epoll_data_t 		org_data;
	__uint32_t		events;
	int 			sockfd;
	struct cs_context	*c;
};

struct epoll_context {
	int epfd;
	LIST_HEAD(, epoller)	pollers;
	int count;
};

#define NIPHW(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define NIPHW_FMT "%02x:%02x:%02x:%02x:%02x:%02x"

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#define NIPQUAD_FMT "%u.%u.%u.%u"

#define IFI_RTA(p) ((struct rtattr*)(((char*)(p)) + \
		   NLMSG_ALIGN(sizeof(struct ifinfomsg))))

#define sa_inaddr(sa) ((struct sockaddr_in *)(sa))->sin_addr
#define sa_ipaddr(sa) ((struct sockaddr_in *)(sa))->sin_addr.s_addr
#define sa_port(sa) ((struct sockaddr_in *)(sa))->sin_port
#define sa_any(sa) (((struct sockaddr_in *)(sa))->sin_addr.s_addr == INADDR_ANY)

extern int quiet;
#define VERBOSE(l, fmt, args...) do {if (!quiet) printf("WD_UDP: " fmt, ## args); else DBG(l, fmt, ## args); } while (0)


int route_ours(struct cs_context *c, const struct sockaddr *sa);
void build_t4_dev_list();
struct chelsio_dev *find_chelsio_dev(char *name, struct sockaddr *addrp);
int parse_config_file(const char *filename);

void add_endpoint(char *interface, unsigned short port, unsigned short vlan,
		  unsigned char priority);
int lookup_endpoint(unsigned short port, char *name,
		    unsigned short *pvlan, unsigned char *ppriority);

#define VLAN_ID_NA 0xfff
#define VLAN_PRI_NA 0

#define SA(s) ((struct sockaddr *)(s))

static inline uint8_t *sinx_addrp(struct sockaddr *s)
{
	return (s->sa_family == AF_INET ? 
		(uint8_t *)&((struct sockaddr_in *)s)->sin_addr.s_addr : 
		((struct sockaddr_in6 *)s)->sin6_addr.s6_addr);
}

#endif
