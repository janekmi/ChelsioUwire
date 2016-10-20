/*
 * This file contains pieces of the Linux TCP/IP stack needed for modular
 * TOE support.
 *
 * Copyright (C) 2006-2008 Chelsio Communications.  All rights reserved.
 * See the corresponding files in the Linux tree for copyrights of the
 * original Linux code a lot of this file is based on.
 *
 * Additional code written by Dimitris Michailidis (dm@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/*
 * The following tags are used by the out-of-kernel Makefile to identify
 * supported kernel versions if a module_support-<kver> file is not found.
 * Do not remove these tags.
 * $SUPPORTED KERNEL 2.6.32$
 */
#include <net/tcp.h>
#include <linux/random.h>
#include <linux/highmem.h>
#include <linux/pfn.h>
#include <linux/kprobes.h>
#include <linux/notifier.h>
#include <linux/module.h>
#include "toe_compat.h"
#include <linux/toedev.h>
#include <linux/sunrpc/xprt.h>
#include <net/inet_common.h>
#include <net/offload.h>
#include <linux/highmem.h>
#include "toe_iscsi.h"

static struct proto orig_tcp_prot;

static unsigned long (*kallsyms_lookup_name_p)(const char *name);
static __u32 (*secure_tcp_sequence_number_p)(__u32 saddr, __u32 daddr,
					     __u16 sport, __u16 dport);

void (*security_inet_conn_established_p)(struct sock *sk, struct sk_buff *skb);

/* Enable TCP options by default in case we can't locate the actual sysctls. */
static int tcp_options_sysctl = 1;
int *sysctl_tcp_timestamps_p = &tcp_options_sysctl;
int *sysctl_tcp_sack_p = &tcp_options_sysctl;
int *sysctl_tcp_window_scaling_p = &tcp_options_sysctl;
int *sysctl_tcp_ecn_p = &tcp_options_sysctl;

/* The next few definitions track the data_ready callbacks for RPC and iSCSI */
static void (*iscsi_tcp_data_ready_p)(struct sock *sk, int bytes);
static void (*iscsi_sw_tcp_data_ready_p)(struct sock *sk, int bytes);
static sk_read_actor_t iscsi_tcp_recv_p;
static sk_read_actor_t iscsi_sw_tcp_recv_p;
static sk_read_actor_t iscsi_tcp_data_recv_p;
static void (*xs_tcp_data_ready_p)(struct sock *sk, int bytes);
static sk_read_actor_t xs_tcp_data_recv_p;
static void (*lustre_tcp_data_ready_p)(struct sock *sk, int bytes);
static void (*sock_def_readable_p)(struct sock *sk, int bytes);

/*
 * The next definitions provide a replacement for route.h:rt_get_peer(),
 * which is not exported to modules.
 */
static void (*rt_bind_peer_p)(struct rtable *rt, int create);

static inline struct inet_peer *rt_get_peer_offload(struct rtable *rt)
{
	if (rt->peer)
		return rt->peer;

	if (rt_bind_peer_p)
		rt_bind_peer_p(rt, 0);
	return rt->peer;
}

static void find_rpc_iscsi_callbacks(void)
{
	/* All of these may fail since RPC/iSCSI may not be loaded */
	iscsi_tcp_data_ready_p =
		(void *)kallsyms_lookup_name_p("iscsi_tcp_data_ready");
	iscsi_sw_tcp_data_ready_p =
		(void *)kallsyms_lookup_name_p("iscsi_sw_tcp_data_ready");
	iscsi_tcp_recv_p = (void *)kallsyms_lookup_name_p("iscsi_tcp_recv");
	iscsi_sw_tcp_recv_p =
		(void *)kallsyms_lookup_name_p("iscsi_sw_tcp_recv");
	iscsi_tcp_data_recv_p =
		(void *)kallsyms_lookup_name_p("iscsi_tcp_data_recv");
	xs_tcp_data_ready_p =
		(void *)kallsyms_lookup_name_p("xs_tcp_data_ready");
	xs_tcp_data_recv_p = (void *)kallsyms_lookup_name_p("xs_tcp_data_recv");
	sock_def_readable_p = (void *)kallsyms_lookup_name_p("sock_def_readable");
	lustre_tcp_data_ready_p = (void *)kallsyms_lookup_name_p("ksocknal_data_ready");
}

static int module_notify_handler(struct notifier_block *this,
				 unsigned long event, void *data)
{
	switch (event) {
	case MODULE_STATE_GOING:
		if (xs_tcp_data_ready_p || iscsi_tcp_data_ready_p || 
			lustre_tcp_data_ready_p) 
				find_rpc_iscsi_callbacks();
		break;
	case MODULE_STATE_COMING:
		if (!xs_tcp_data_ready_p || !iscsi_tcp_data_ready_p ||
			!lustre_tcp_data_ready_p)	
				find_rpc_iscsi_callbacks();
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block module_notifier = {
	.notifier_call = module_notify_handler
};

void security_inet_conn_estab(struct sock *sk, struct sk_buff *skb)
{
	if (security_inet_conn_established_p)
		security_inet_conn_established_p(sk, skb);
}
EXPORT_SYMBOL(security_inet_conn_estab);

static int (*skb_splice_bits_p)(struct sk_buff *skb, unsigned int offset,
				struct pipe_inode_info *pipe, unsigned int len,
				unsigned int flags);

int skb_splice_bits_pub(struct sk_buff *skb, unsigned int offset,
			struct pipe_inode_info *pipe, unsigned int len,
			unsigned int flags)
{
	return skb_splice_bits_p(skb, offset, pipe, len, flags);
}
EXPORT_SYMBOL(skb_splice_bits_pub);

/*
 * The functions below replace some of the original methods of tcp_prot to
 * support offloading.
 */

static void tcp_v4_hash_offload(struct sock *sk)
{
	orig_tcp_prot.hash(sk);
	if (sk->sk_state == TCP_LISTEN)
		start_listen_offload(sk);
}

static void tcp_unhash_offload(struct sock *sk)
{
	if (sk->sk_state == TCP_LISTEN)
		stop_listen_offload(sk);
	orig_tcp_prot.unhash(sk);
}

static int tcp_v4_connect_offload(struct sock *sk, struct sockaddr *uaddr,
				  int addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
	struct rtable *rt;
	__be32 daddr, nexthop;
	int tmp;
	int err;

	if (addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;

	if (usin->sin_family != AF_INET)
		return -EAFNOSUPPORT;

	nexthop = daddr = usin->sin_addr.s_addr;
	if (inet->opt && inet->opt->srr) {
		if (!daddr)
			return -EINVAL;
		nexthop = inet->opt->faddr;
	}

	tmp = ip_route_connect(&rt, nexthop, inet->inet_saddr,
			       RT_CONN_FLAGS(sk), sk->sk_bound_dev_if,
			       IPPROTO_TCP,
			       inet->inet_sport, usin->sin_port, sk, 1);
	if (tmp < 0) {
		if (tmp == -ENETUNREACH)
			T3_IP_INC_STATS_BH(sock_net(sk), IPSTATS_MIB_OUTNOROUTES);
		return tmp;
	}

	if (rt->rt_flags & (RTCF_MULTICAST | RTCF_BROADCAST)) {
		ip_rt_put(rt);
		return -ENETUNREACH;
	}

	if (!inet->opt || !inet->opt->srr)
		daddr = rt->rt_dst;

	if (!inet->inet_saddr)
		inet->inet_saddr = rt->rt_src;
	inet->inet_rcv_saddr = inet->inet_saddr;

	if (tp->rx_opt.ts_recent_stamp && inet->inet_daddr != daddr) {
		/* Reset inherited state */
		tp->rx_opt.ts_recent	   = 0;
		tp->rx_opt.ts_recent_stamp = 0;
		tp->write_seq		   = 0;
	}

	if (tcp_death_row.sysctl_tw_recycle &&
	    !tp->rx_opt.ts_recent_stamp && rt->rt_dst == daddr) {
		struct inet_peer *peer = rt_get_peer_offload(rt);

		/* VJ's idea. We save last timestamp seen from
		 * the destination in peer table, when entering state TIME-WAIT
		 * and initialize rx_opt.ts_recent from it, when trying new
		 * connection.
		 */

		if (peer &&
		    peer->tcp_ts_stamp + TCP_PAWS_MSL >= get_seconds()) {
			tp->rx_opt.ts_recent_stamp = peer->tcp_ts_stamp;
			tp->rx_opt.ts_recent = peer->tcp_ts;
		}
	}

	inet->inet_dport = usin->sin_port;
	inet->inet_daddr = daddr;

	inet_csk(sk)->icsk_ext_hdr_len = 0;
	if (inet->opt)
		inet_csk(sk)->icsk_ext_hdr_len = inet->opt->optlen;

	tp->rx_opt.mss_clamp = 536;

	/* Socket identity is still unknown (sport may be zero).
	 * However we set state to SYN-SENT and not releasing socket
	 * lock select source port, enter ourselves into the hash tables and
	 * complete initialization after this.
	 */
	tcp_set_state(sk, TCP_SYN_SENT);
	err = inet_hash_connect(&tcp_death_row, sk);
	if (err)
		goto failure;

	err = ip_route_newports(&rt, IPPROTO_TCP, inet->inet_sport,
				inet->inet_dport, sk);
	if (err)
		goto failure;

	/* OK, now commit destination to socket.  */
	sk->sk_gso_type = SKB_GSO_TCPV4;
	sk_setup_caps(sk, &rt->u.dst);

	if (tcp_connect_offload(sk))
		return 0;

	if (!tp->write_seq)
		tp->write_seq = secure_tcp_sequence_number_p(inet->inet_saddr,
							     inet->inet_daddr,
							     inet->inet_sport,
							     usin->sin_port);

	inet->inet_id = tp->write_seq ^ jiffies;

	err = tcp_connect(sk);
	rt = NULL;
	if (err)
		goto failure;

	return 0;

failure:
	/* This unhashes the socket and releases the local port,
	   if necessary */
	tcp_set_state(sk, TCP_CLOSE);
	ip_rt_put(rt);
	sk->sk_route_caps = 0;
	inet->inet_dport = 0;
	return err;
}

ssize_t tcp_sendpage_offload(struct socket *sock, struct page *page,
				    int offset, size_t size, int flags)
{
	struct sock *sk = sock->sk;

	if (sk->sk_prot->sendpage)
		return sk->sk_prot->sendpage(sk, page, offset, size, flags);

	return tcp_sendpage(sock, page, offset, size, flags);
}
EXPORT_SYMBOL(tcp_sendpage_offload);

int tcp_sendmsg_offload(struct kiocb *iocb, struct socket *sock,
			       struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;

	if (sk->sk_prot->sendmsg)
		return sk->sk_prot->sendmsg(iocb, sk, msg, size);

	return tcp_sendmsg(iocb, (void *)sock, msg, size);
}
EXPORT_SYMBOL(tcp_sendmsg_offload);

ssize_t tcp_splice_read_offload(struct socket *sock, loff_t *ppos,
				       struct pipe_inode_info *pipe, size_t len,
				       unsigned int flags)
{
	struct sock *sk = sock->sk;

	if (sock_flag(sk, SOCK_OFFLOADED)) {
		const struct sk_ofld_proto *p = (void *)sk->sk_prot;

		return p->splice_read(sk, ppos, pipe, len, flags);
	}
	return tcp_splice_read(sock, ppos, pipe, len, flags);
}
EXPORT_SYMBOL(tcp_splice_read_offload);

static int offload_enabled;

#ifdef CONFIG_DEBUG_RODATA
static struct proto_ops offload_inet_stream_ops;

void offload_socket_ops(struct sock *sk)
{
	struct socket *sock = sk->sk_socket;

	if (sock && sock->ops == &inet_stream_ops)
		sock->ops = &offload_inet_stream_ops;
}

void restore_socket_ops(struct sock *sk)
{
	struct socket *sock = sk->sk_socket;

	if (sock && sock->ops == &offload_inet_stream_ops)
		sock->ops = &inet_stream_ops;
}
EXPORT_SYMBOL(restore_socket_ops);

static int offload_listen_cb(void *dummy, struct sock *sk)
{
	offload_socket_ops(sk);
	return 0;
}

static int restore_listen_cb(void *dummy, struct sock *sk)
{
	restore_socket_ops(sk);
	return 0;
}
#endif

static int find_kallsyms_lookup_name(void)
{
	int err = 0;

#if defined(KPROBES_KALLSYMS)
	struct kprobe kp;

	memset(&kp, 0, sizeof kp);
	kp.symbol_name = "kallsyms_lookup_name";
	err = register_kprobe(&kp);
	if (!err) {
		kallsyms_lookup_name_p = (void *)kp.addr;
		unregister_kprobe(&kp);
	}
#else
	kallsyms_lookup_name_p = (void *)KALLSYMS_LOOKUP;
#endif
	if (!err)
		err = kallsyms_lookup_name_p == NULL;

	return err;
}

#define FIND_SYMBOL(name, ptr) do { \
	ptr = (void *)kallsyms_lookup_name_p(name); \
	if (!ptr) { \
		printk("toecore failure: could not get " name "\n"); \
		return -ENOENT; \
	} \
} while (0)

#define FIND_SYSCTL(name) do { \
	int *p = (void *)kallsyms_lookup_name_p("sysctl_tcp_" # name); \
	if (p) \
		sysctl_tcp_ ## name ## _p = p; \
} while (0)

int prepare_tcp_for_offload(void)
{
	if (offload_enabled)   /* already done */
		return 0;

	if (!kallsyms_lookup_name_p) {
		int err = find_kallsyms_lookup_name();
		if (err) {
			printk(KERN_ERR "find_kallsyms_lookup_name failed\n");
			return err;
		}
	}

	FIND_SYMBOL("skb_splice_bits", skb_splice_bits_p);
	FIND_SYMBOL("secure_tcp_sequence_number", secure_tcp_sequence_number_p);

#ifdef CONFIG_SECURITY_NETWORK
	FIND_SYMBOL("security_inet_conn_established",
		    security_inet_conn_established_p);
#endif

	/*
	 * rt_bind_peer is not a critical function, it's ok if we are unable
	 * to locate it.
	 */
	rt_bind_peer_p = (void *)kallsyms_lookup_name_p("rt_bind_peer");

	/* sysctls are also best effort */
	FIND_SYSCTL(timestamps);
	FIND_SYSCTL(sack);
	FIND_SYSCTL(window_scaling);
	FIND_SYSCTL(ecn);

	find_rpc_iscsi_callbacks();
	register_module_notifier(&module_notifier);

#ifdef CONFIG_DEBUG_RODATA
	offload_inet_stream_ops = inet_stream_ops;
	offload_inet_stream_ops.sendmsg = tcp_sendmsg_offload;
	offload_inet_stream_ops.sendpage = tcp_sendpage_offload;
	offload_inet_stream_ops.splice_read = tcp_splice_read_offload;
	walk_listens(NULL, offload_listen_cb);
#else
	{
		struct proto_ops *iso = (struct proto_ops *)&inet_stream_ops;
		iso->sendmsg = tcp_sendmsg_offload;
		iso->sendpage = tcp_sendpage_offload;
		iso->splice_read = tcp_splice_read_offload;
	}
#endif

	orig_tcp_prot = tcp_prot;
	tcp_prot.hash = tcp_v4_hash_offload;
	tcp_prot.unhash = tcp_unhash_offload;
	tcp_prot.connect = tcp_v4_connect_offload;

	offload_enabled = 1;
	return 0;
}

void restore_tcp_to_nonoffload(void)
{
	if (offload_enabled) {
		unregister_module_notifier(&module_notifier);
#ifdef CONFIG_DEBUG_RODATA
		walk_listens(NULL, restore_listen_cb);
#else
		{
			struct proto_ops *iso;

			iso = (struct proto_ops *)&inet_stream_ops;
			iso->sendmsg = tcp_sendmsg;
			iso->sendpage = tcp_sendpage;
		}
#endif
		tcp_prot.hash = orig_tcp_prot.hash;
		tcp_prot.unhash = orig_tcp_prot.unhash;
		tcp_prot.connect = orig_tcp_prot.connect;
		offload_enabled = 0;
	}
}

static inline int ofld_read_sock(struct sock *sk, read_descriptor_t *desc,
				 sk_read_actor_t recv_actor)
{
	if (sock_flag(sk, SOCK_OFFLOADED)) {
		const struct sk_ofld_proto *p = (void *)sk->sk_prot;

		return p->read_sock(sk, desc, recv_actor);
	}
	return tcp_read_sock(sk, desc, recv_actor);
}

/* Replacement for RPC's ->data_ready callback */
static void xs_ofld_tcp_data_ready(struct sock *sk, int bytes)
{
	struct rpc_xprt *xprt;
	read_descriptor_t rd_desc;

	read_lock(&sk->sk_callback_lock);
	if (!(xprt = sk->sk_user_data))
		goto out;
	if (xprt->shutdown)
		goto out;

	/* We use rd_desc to pass struct xprt to xs_tcp_data_recv */
	rd_desc.arg.data = xprt;
	rd_desc.count = 65536;
	ofld_read_sock(sk, &rd_desc, xs_tcp_data_recv_p);
out:
	read_unlock(&sk->sk_callback_lock);
}

/* Copy of iscsi_tcp_segment_unmap */
static inline void iscsi_tcp_segment_unmap(struct iscsi_segment *segment)
{
	if (segment->sg_mapped) {
		kunmap_atomic(segment->sg_mapped, KM_SOFTIRQ0);
		segment->sg_mapped = NULL;
		segment->data = NULL;
	}
}

/* Replacement for iSCSI's ->data_ready callback */
static void iscsi_ofld_tcp_data_ready_0(struct sock *sk, int bytes)
{
	struct iscsi_conn *conn = sk->sk_user_data;
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	read_descriptor_t rd_desc;

	read_lock(&sk->sk_callback_lock);

	rd_desc.arg.data = conn;
	rd_desc.count = 1;
	ofld_read_sock(sk, &rd_desc, iscsi_tcp_recv_p);

	read_unlock(&sk->sk_callback_lock);

	iscsi_tcp_segment_unmap(&tcp_conn->in.segment);
}

/* Replacement for iSCSI's ->data_ready callback */
static void iscsi_ofld_tcp_data_ready_2(struct sock *sk, int bytes)
{
	struct iscsi_conn *conn = sk->sk_user_data;
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	read_descriptor_t rd_desc;

	read_lock(&sk->sk_callback_lock);

	rd_desc.arg.data = conn;
	rd_desc.count = 1;
	ofld_read_sock(sk, &rd_desc, iscsi_sw_tcp_recv_p);

	read_unlock(&sk->sk_callback_lock);

	iscsi_tcp_segment_unmap(&tcp_conn->in.segment);
}

/* Replacement for iSCSI's ->data_ready callback, old api */
static void iscsi_ofld_tcp_data_ready_1(struct sock *sk, int bytes)
{
	struct iscsi_conn *conn = sk->sk_user_data;
	read_descriptor_t rd_desc;

	read_lock(&sk->sk_callback_lock);

	rd_desc.arg.data = conn;
	rd_desc.count = 1;
	ofld_read_sock(sk, &rd_desc, iscsi_tcp_data_recv_p);

	read_unlock(&sk->sk_callback_lock);
}

int check_special_data_ready(const struct sock *sk)
{
	if (!sk->sk_user_data)
		return 0;

	if (sk->sk_data_ready == sock_def_readable_p)
		return 0;

	if (sk->sk_data_ready == lustre_tcp_data_ready_p)
		return 0;

	return 1;
}
EXPORT_SYMBOL(check_special_data_ready);

int install_special_data_ready(struct sock *sk)
{
	if (!sk->sk_user_data)
		return 0;

	if (sk->sk_data_ready == xs_tcp_data_ready_p)
		sk->sk_data_ready = xs_ofld_tcp_data_ready;

	else if (sk->sk_data_ready == iscsi_tcp_data_ready_p) {
		if (iscsi_tcp_recv_p)
			sk->sk_data_ready = iscsi_ofld_tcp_data_ready_0;
		else if (iscsi_tcp_data_recv_p)
			sk->sk_data_ready = iscsi_ofld_tcp_data_ready_1;

	} else if (sk->sk_data_ready == iscsi_sw_tcp_data_ready_p) {
		sk->sk_data_ready = iscsi_ofld_tcp_data_ready_2;

	} else
		return 0;
	return 1;
}
EXPORT_SYMBOL(install_special_data_ready);

void restore_special_data_ready(struct sock *sk)
{
	if (sk->sk_data_ready == xs_ofld_tcp_data_ready)
		sk->sk_data_ready = xs_tcp_data_ready_p;

	else if (sk->sk_data_ready == iscsi_ofld_tcp_data_ready_0)
		sk->sk_data_ready = iscsi_tcp_data_ready_p;

	else if (sk->sk_data_ready == iscsi_ofld_tcp_data_ready_1)
		sk->sk_data_ready = iscsi_tcp_data_ready_p;

	else if (sk->sk_data_ready == iscsi_ofld_tcp_data_ready_2)
		sk->sk_data_ready = iscsi_sw_tcp_data_ready_p;
}
EXPORT_SYMBOL(restore_special_data_ready);
