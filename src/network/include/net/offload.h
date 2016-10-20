/*
 * Copyright (C) 2003-2008 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef _NET_OFFLOAD_H
#define _NET_OFFLOAD_H

#include <net/tcp.h>

#if defined(CONFIG_TCP_OFFLOAD_MODULE)
# define SOCK_OFFLOADED (31)		// connected socket is offloaded
# define SOCK_NO_DDP	(30)		// socket should not do DDP
#endif

enum {
	OFFLOAD_LISTEN_START,
	OFFLOAD_LISTEN_STOP
};

struct sock;
struct sk_buff;
struct toedev;
struct notifier_block;
struct pipe_inode_info;

/*
 * Extended 'struct proto' with additional members used by offloaded
 * connections.
 */
struct sk_ofld_proto {
	struct proto proto;    /* keep this first */
	int (*read_sock)(struct sock *sk, read_descriptor_t *desc,
			 sk_read_actor_t recv_actor);
	ssize_t (*splice_read)(struct sock *sk, loff_t *ppos,
			       struct pipe_inode_info *pipe, size_t len,
			       unsigned int flags);
};

/* Per-skb backlog handler.  Run when a socket's backlog is processed. */
struct blog_skb_cb {
	void (*backlog_rcv) (struct sock *sk, struct sk_buff *skb);
	struct toedev *dev;
};

#define BLOG_SKB_CB(skb) ((struct blog_skb_cb *)(skb)->cb)

#ifndef LINUX_2_4
struct offload_req {
	__be32 sip[4];
	__be32 dip[4];
	__be16 sport;
	__be16 dport;
	__u8   ipvers_opentype;
	__u8   tos;
	__be16 vlan;
	__u32  mark;
};

enum { OPEN_TYPE_LISTEN, OPEN_TYPE_ACTIVE, OPEN_TYPE_PASSIVE };

struct offload_settings {
	__u8  offload;
	__s8  ddp;
	__s8  rx_coalesce;
	__s8  cong_algo;
	__s32 rssq;
	__s16 sched_class;
	__s8  tstamp;
	__s8  sack;

};

enum {
	QUEUE_RANDOM = -2,
	QUEUE_CPU = -3,
};

struct ofld_prog_inst {          /* offload policy program "instructions" */
	s32 offset;
	u32 mask;
	u32 value;
	s32 next[2];
};

struct offload_policy {
	struct rcu_head rcu_head;
	int match_all;
	int use_opt;
	const struct offload_settings *settings;
	const u32 *opt_prog_start;
	struct ofld_prog_inst prog[0];
};

struct ofld_policy_file {
	unsigned int vers;
	int output_everything;
	unsigned int nrules;
	unsigned int prog_size;
	unsigned int opt_prog_size;
	unsigned int nsettings;
	const struct ofld_prog_inst prog[0];
};
#endif /* !LINUX_2_4 */

#if defined(CONFIG_TCP_OFFLOAD) || \
    (defined(CONFIG_TCP_OFFLOAD_MODULE) && defined(MODULE))
int register_listen_offload_notifier(struct notifier_block *nb);
int unregister_listen_offload_notifier(struct notifier_block *nb);
int start_listen_offload(struct sock *sk);
int stop_listen_offload(struct sock *sk);
int tcp_connect_offload(struct sock *sk);
void security_inet_conn_estab(struct sock *sk, struct sk_buff *skb);
void walk_listens(void *handle, int (*func)(void *handle, struct sock *sk));
int set_offload_policy(struct toedev *dev, const struct ofld_policy_file *f);
void offload_req_from_sk(struct offload_req *req, struct sock *sk, int otype);
const struct offload_settings *
lookup_ofld_policy(const struct toedev *dev, const struct offload_req *req,
		   int cop_managed_offloading);
ssize_t tcp_sendpage_offload(struct socket *sock, struct page *page,
                                    int offset, size_t size, int flags);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
int tcp_sendmsg_offload(struct kiocb *iocb, struct socket *sock,
			struct msghdr *msg, size_t size);
#else
int tcp_sendmsg_offload(struct socket *sock,
			struct msghdr *msg, size_t size);
#endif
ssize_t tcp_splice_read_offload(struct socket *sock, loff_t *ppos,
                                       struct pipe_inode_info *pipe, size_t len,
                                       unsigned int flags);
#else
static inline int tcp_connect_offload(struct sock *sk)
{
	return 0;
}

static inline int start_listen_offload(struct sock *sk)
{
	return -EPROTONOSUPPORT;
}

static inline int stop_listen_offload(struct sock *sk)
{
	return -EPROTONOSUPPORT;
}
#endif

#if defined(CONFIG_TCP_OFFLOAD_MODULE)
int  check_special_data_ready(const struct sock *sk);
int  install_special_data_ready(struct sock *sk);
void restore_special_data_ready(struct sock *sk);
int  skb_splice_bits_pub(struct sk_buff *skb, unsigned int offset,
			 struct pipe_inode_info *pipe, unsigned int len,
			 unsigned int flags);
#else
static inline int check_special_data_ready(const struct sock *sk) { return 0; }
static inline int install_special_data_ready(struct sock *sk) { return 0; }
static inline void restore_special_data_ready(struct sock *sk) {}
#define skb_splice_bits_pub skb_splice_bits
#endif

#if defined(CONFIG_DEBUG_RODATA) && defined(CONFIG_TCP_OFFLOAD_MODULE)
void offload_socket_ops(struct sock *sk);
void restore_socket_ops(struct sock *sk);
#else
static inline void offload_socket_ops(struct sock *sk) {}
static inline void restore_socket_ops(struct sock *sk) {}
#endif

/*
 * List of sockets in SYN_RCV state.
 * ---------------------------------
 */

/*
 * Definitions for SYN_RCV state socket doubly-linked queue hung off of a
 * listening socket.  These overlap fields in (struct tcp_sock) which we know
 * are free for sockets in this state.  We'd like to get rid of this
 * overloading by putting the fields into the offloaded socket state data but
 * we can have a parent listening socket which is not offloaded and children
 * sockets which are offloaded.  And then there's also the issue of wanting to
 * support more than one kind of offloaded socket ...  So, in the absense of
 * well-defined fields for this purpose, we hijack others ...
 *
 * Also note that we must reset the state of these fields after we're done
 * with them.  Thus, the synq_empty() and reset_synq() functions are Linux-
 * version dependent and are defined in the compatibility header along with
 * the SYN queue next/prev fields ...
 *
 * We use the (stuct tcp_sock):ucopy.prequeue.{head,tail} fields to implement
 * the Offload SYN Queue.  Each listening socket keeps a doubly linked list of
 * its children sockets in SYN_RCV state, i.e., the sockets on its SYN queue.
 */
#define synq_next_tp_field ucopy.prequeue.next
#define synq_prev_tp_field ucopy.prequeue.prev

#define synq_next(sk) (*(struct sock **)&(tcp_sk(sk)->synq_next_tp_field))
#define synq_prev(sk) (*(struct sock **)&(tcp_sk(sk)->synq_prev_tp_field))

static inline int synq_empty(struct sock *sk)
{
	return skb_queue_empty(&tcp_sk(sk)->ucopy.prequeue);
}

static inline void reset_synq(struct sock *sk)
{
	skb_queue_head_init(&tcp_sk(sk)->ucopy.prequeue);
}

static inline void synq_add(struct sock *parent, struct sock *child)
{
	/* Add the child socket onto the front of the list */
	if (synq_empty(parent)) {
		/* this is the first child */
		synq_next(child) = parent;
		synq_prev(parent) = child;
	} else {
		synq_next(child) = synq_next(parent);
		synq_prev(synq_next(parent)) = child;
	}
	synq_next(parent) = child;
	synq_prev(child) = parent;
}

static inline void synq_remove(struct sock *child)
{
	struct sock *next = synq_next(child);
	struct sock *prev = synq_prev(child);

	if (next == prev) {
		/* sole child */
		reset_synq(next);
	} else {
		synq_next(prev) = synq_next(child);
		synq_prev(next) = synq_prev(child);
	}
	reset_synq(child);
}

#endif /* !_NET_OFFLOAD_H */
