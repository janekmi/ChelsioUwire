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
 * $SUPPORTED KERNEL 3.14$
 */
#include <linux/kconfig.h>
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
#include <drivers/net/bonding/bonding.h>
#ifdef CONFIG_TCPV6_OFFLOAD
#include <net/ipv6.h>
#include <net/transp_v6.h>
#include <net/ip6_route.h>
#include <net/inet6_hashtables.h>
#include <net/inet6_connection_sock.h>
#include <net/ip6_checksum.h>
#endif
#include <net/secure_seq.h>
#include "toe_iscsi.h"

static struct proto orig_tcp_prot;

#ifdef CONFIG_TCPV6_OFFLOAD
static const struct inet_connection_sock_af_ops ipv6_mapped;
static const struct inet_connection_sock_af_ops ipv6_specific;

static struct proto orig_tcpv6_prot;
static struct proto *tcpv6_prot_p;
static struct request_sock_ops *tcp6_request_sock_ops_p;
static __u32 (*cookie_v6_init_sequence_p)(struct sock *sk,
					struct sk_buff *skb, __u16 *mssp);
static struct sock * (*cookie_v6_check_p)(struct sock *sk, struct sk_buff *skb);
static struct dst_entry * (*inet6_csk_route_req_p)(struct sock *sk,
				      struct flowi6 *fl6,
				      const struct request_sock *req);
#ifdef CONFIG_TCP_MD5SIG
static const struct tcp_sock_af_ops tcp_sock_ipv6_specific;
static const struct tcp_sock_af_ops tcp_sock_ipv6_mapped_specific;
#endif
#endif

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

static void find_rpc_iscsi_callbacks(void)
{
	/* All of these may fail since RPC/iSCSI may not be loaded */
	iscsi_tcp_data_ready_p =
		(void *)kallsyms_lookup_name("iscsi_tcp_data_ready");
	iscsi_sw_tcp_data_ready_p =
		(void *)kallsyms_lookup_name("iscsi_sw_tcp_data_ready");
	iscsi_tcp_recv_p = (void *)kallsyms_lookup_name("iscsi_tcp_recv");
	iscsi_sw_tcp_recv_p =
		(void *)kallsyms_lookup_name("iscsi_sw_tcp_recv");
	iscsi_tcp_data_recv_p =
		(void *)kallsyms_lookup_name("iscsi_tcp_data_recv");
	xs_tcp_data_ready_p =
		(void *)kallsyms_lookup_name("xs_tcp_data_ready");
	xs_tcp_data_recv_p = (void *)kallsyms_lookup_name("xs_tcp_data_recv");
	sock_def_readable_p = (void *)kallsyms_lookup_name("sock_def_readable");
	lustre_tcp_data_ready_p = (void *)kallsyms_lookup_name("ksocknal_data_ready");
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

/* Offload version of Linux kernel tcp_v4_connect() */
/* This will initiate an outgoing connection. */
int tcp_v4_connect_offload(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	__be16 orig_sport, orig_dport;
	__be32 daddr, nexthop;
	struct flowi4 *fl4;
	struct rtable *rt;
	int err;
	struct ip_options_rcu *inet_opt;

	if (addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;

	if (usin->sin_family != AF_INET)
		return -EAFNOSUPPORT;

	nexthop = daddr = usin->sin_addr.s_addr;
	inet_opt = rcu_dereference_protected(inet->inet_opt,
					     sock_owned_by_user(sk));
	if (inet_opt && inet_opt->opt.srr) {
		if (!daddr)
			return -EINVAL;
		nexthop = inet_opt->opt.faddr;
	}

	orig_sport = inet->inet_sport;
	orig_dport = usin->sin_port;
	fl4 = &inet->cork.fl.u.ip4;
	rt = ip_route_connect(fl4, nexthop, inet->inet_saddr,
			      RT_CONN_FLAGS(sk), sk->sk_bound_dev_if,
			      IPPROTO_TCP,
			      orig_sport, orig_dport, sk);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		if (err == -ENETUNREACH)
			IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTNOROUTES);
		return err;
	}

	if (rt->rt_flags & (RTCF_MULTICAST | RTCF_BROADCAST)) {
		ip_rt_put(rt);
		return -ENETUNREACH;
	}

	if (!inet_opt || !inet_opt->opt.srr)
		daddr = fl4->daddr;

	if (!inet->inet_saddr)
		inet->inet_saddr = fl4->saddr;
	inet->inet_rcv_saddr = inet->inet_saddr;

	if (tp->rx_opt.ts_recent_stamp && inet->inet_daddr != daddr) {
		/* Reset inherited state */
		tp->rx_opt.ts_recent	   = 0;
		tp->rx_opt.ts_recent_stamp = 0;
		if (likely(!tp->repair))
			tp->write_seq	   = 0;
	}

	if (tcp_death_row.sysctl_tw_recycle &&
	    !tp->rx_opt.ts_recent_stamp && fl4->daddr == daddr)
		tcp_fetch_timewait_stamp(sk, &rt->dst);

	inet->inet_dport = usin->sin_port;
	inet->inet_daddr = daddr;

	inet_csk(sk)->icsk_ext_hdr_len = 0;
	if (inet_opt)
		inet_csk(sk)->icsk_ext_hdr_len = inet_opt->opt.optlen;

	tp->rx_opt.mss_clamp = TCP_MSS_DEFAULT;

	/* Socket identity is still unknown (sport may be zero).
	 * However we set state to SYN-SENT and not releasing socket
	 * lock select source port, enter ourselves into the hash tables and
	 * complete initialization after this.
	 */
	tcp_set_state(sk, TCP_SYN_SENT);
	err = inet_hash_connect(&tcp_death_row, sk);
	if (err)
		goto failure;

	rt = ip_route_newports(fl4, rt, orig_sport, orig_dport,
			       inet->inet_sport, inet->inet_dport, sk);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		rt = NULL;
		goto failure;
	}
	/* OK, now commit destination to socket.  */
	sk->sk_gso_type = SKB_GSO_TCPV4;
	sk_setup_caps(sk, &rt->dst);

	if (tcp_connect_offload(sk))
		return 0;

	if (!tp->write_seq && likely(!tp->repair))
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
	/*
	 * This unhashes the socket and releases the local port,
	 * if necessary.
	 */
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

	return tcp_sendpage(sk, page, offset, size, flags);
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

#ifdef CONFIG_TCPV6_OFFLOAD
static void rt6_bind_peer(struct rt6_info *rt, int create)
{
	struct inet_peer_base *base;
	struct inet_peer *peer;

	base = inetpeer_base_ptr(rt->_rt6i_peer);
	if (!base)
		return;

	peer = inet_getpeer_v6(base, &rt->rt6i_dst.addr, create);
	if (peer) {
		if (!rt6_set_peer(rt, peer))
			inet_putpeer(peer);
	}
}

static struct inet_peer *__rt6_get_peer(struct rt6_info *rt, int create)
{
	if (rt6_has_peer(rt))
		return rt6_peer_ptr(rt);

	rt6_bind_peer(rt, create);
	return (rt6_has_peer(rt) ? rt6_peer_ptr(rt) : NULL);
}

static inline struct inet_peer *rt6_get_peer_offload(struct rt6_info *rt)
{
	return __rt6_get_peer(rt, 0);
}

static void inet6_sk_rx_dst_set(struct sock *sk, const struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	const struct rt6_info *rt = (const struct rt6_info *)dst;

	dst_hold(dst);
	sk->sk_rx_dst = dst;
	inet_sk(sk)->rx_dst_ifindex = skb->skb_iif;
	if (rt->rt6i_node)
		inet6_sk(sk)->rx_dst_cookie = rt->rt6i_node->fn_sernum;
}

static int tcp_v6_send_synack(struct sock *sk, struct dst_entry *dst,
			      struct flowi6 *fl6,
			      struct request_sock *req,
			      u16 queue_mapping)
{
	struct inet_request_sock *ireq = inet_rsk(req);
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct sk_buff *skb;
	int err = -ENOMEM;

	/* First, grab a route. */
	if (!dst && (dst = inet6_csk_route_req_p(sk, fl6, req)) == NULL)
		goto done;

	skb = tcp_make_synack(sk, dst, req, NULL);

	if (skb) {
		__tcp_v6_send_check(skb, &ireq->ir_v6_loc_addr,
				    &ireq->ir_v6_rmt_addr);

		fl6->daddr = ireq->ir_v6_rmt_addr;
		if (np->repflow && (ireq->pktopts != NULL))
			fl6->flowlabel = ip6_flowlabel(ipv6_hdr(ireq->pktopts));

		skb_set_queue_mapping(skb, queue_mapping);
		err = ip6_xmit(sk, skb, fl6, np->opt, np->tclass);
		err = net_xmit_eval(err);
	}

done:
	return err;
}

#ifdef CONFIG_TCP_MD5SIG

static int tcp_v6_md5_hash_pseudoheader(struct tcp_md5sig_pool *hp,
					const struct in6_addr *daddr,
					const struct in6_addr *saddr, int nbytes)
{
	struct tcp6_pseudohdr *bp;
	struct scatterlist sg;

	bp = &hp->md5_blk.ip6;
	/* 1. TCP pseudo-header (RFC2460) */
	bp->saddr = *saddr;
	bp->daddr = *daddr;
	bp->protocol = cpu_to_be32(IPPROTO_TCP);
	bp->len = cpu_to_be32(nbytes);

	sg_init_one(&sg, bp, sizeof(*bp));
	return crypto_hash_update(&hp->md5_desc, &sg, sizeof(*bp));
}

static int tcp_v6_md5_hash_skb(char *md5_hash, struct tcp_md5sig_key *key,
			       const struct sock *sk,
			       const struct request_sock *req,
			       const struct sk_buff *skb)
{
	const struct in6_addr *saddr, *daddr;
	struct tcp_md5sig_pool *hp;
	struct hash_desc *desc;
	const struct tcphdr *th = tcp_hdr(skb);

	if (sk) {
		saddr = &inet6_sk(sk)->saddr;
		daddr = &sk->sk_v6_daddr;
	} else if (req) {
		saddr = &inet_rsk(req)->ir_v6_loc_addr;
		daddr = &inet_rsk(req)->ir_v6_rmt_addr;
	} else {
		const struct ipv6hdr *ip6h = ipv6_hdr(skb);
		saddr = &ip6h->saddr;
		daddr = &ip6h->daddr;
	}

	hp = tcp_get_md5sig_pool();
	if (!hp)
		goto clear_hash_noput;
	desc = &hp->md5_desc;

	if (crypto_hash_init(desc))
		goto clear_hash;

	if (tcp_v6_md5_hash_pseudoheader(hp, daddr, saddr, skb->len))
		goto clear_hash;
	if (tcp_md5_hash_header(hp, th))
		goto clear_hash;
	if (tcp_md5_hash_skb_data(hp, skb, th->doff << 2))
		goto clear_hash;
	if (tcp_md5_hash_key(hp, key))
		goto clear_hash;
	if (crypto_hash_final(desc, md5_hash))
		goto clear_hash;

	tcp_put_md5sig_pool();
	return 0;

clear_hash:
	tcp_put_md5sig_pool();
clear_hash_noput:
	memset(md5_hash, 0, 16);
	return 1;
}

static struct tcp_md5sig_key *tcp_v6_md5_do_lookup(struct sock *sk,
						   const struct in6_addr *addr)
{
	return tcp_md5_do_lookup(sk, (union tcp_md5_addr *)addr, AF_INET6);
}

static struct tcp_md5sig_key *tcp_v6_md5_lookup(struct sock *sk,
						struct sock *addr_sk)
{
	return tcp_v6_md5_do_lookup(sk, &addr_sk->sk_v6_daddr);
}

static struct tcp_md5sig_key *tcp_v6_reqsk_md5_lookup(struct sock *sk,
						      struct request_sock *req)
{
	return tcp_v6_md5_do_lookup(sk, &inet_rsk(req)->ir_v6_rmt_addr);
}

static int tcp_v6_parse_md5_keys (struct sock *sk, char __user *optval,
				  int optlen)
{
	struct tcp_md5sig cmd;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&cmd.tcpm_addr;

	if (optlen < sizeof(cmd))
		return -EINVAL;

	if (copy_from_user(&cmd, optval, sizeof(cmd)))
		return -EFAULT;

	if (sin6->sin6_family != AF_INET6)
		return -EINVAL;

	if (!cmd.tcpm_keylen) {
		if (ipv6_addr_v4mapped(&sin6->sin6_addr))
			return tcp_md5_do_del(sk, (union tcp_md5_addr *)&sin6->sin6_addr.s6_addr32[3],
					      AF_INET);
		return tcp_md5_do_del(sk, (union tcp_md5_addr *)&sin6->sin6_addr,
				      AF_INET6);
	}

	if (cmd.tcpm_keylen > TCP_MD5SIG_MAXKEYLEN)
		return -EINVAL;

	if (ipv6_addr_v4mapped(&sin6->sin6_addr))
		return tcp_md5_do_add(sk, (union tcp_md5_addr *)&sin6->sin6_addr.s6_addr32[3],
				      AF_INET, cmd.tcpm_key, cmd.tcpm_keylen, GFP_KERNEL);

	return tcp_md5_do_add(sk, (union tcp_md5_addr *)&sin6->sin6_addr,
			      AF_INET6, cmd.tcpm_key, cmd.tcpm_keylen, GFP_KERNEL);
}

static int tcp_v6_inbound_md5_hash(struct sock *sk, const struct sk_buff *skb)
{
	const __u8 *hash_location = NULL;
	struct tcp_md5sig_key *hash_expected;
	const struct ipv6hdr *ip6h = ipv6_hdr(skb);
	const struct tcphdr *th = tcp_hdr(skb);
	int genhash;
	u8 newhash[16];

	hash_expected = tcp_v6_md5_do_lookup(sk, &ip6h->saddr);
	hash_location = tcp_parse_md5sig_option(th);

	/* We've parsed the options - do we have a hash? */
	if (!hash_expected && !hash_location)
		return 0;

	if (hash_expected && !hash_location) {
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPMD5NOTFOUND);
		return 1;
	}

	if (!hash_expected && hash_location) {
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPMD5UNEXPECTED);
		return 1;
	}

	/* check the signature */
	genhash = tcp_v6_md5_hash_skb(newhash,
				      hash_expected,
				      NULL, NULL, skb);

	if (genhash || memcmp(hash_location, newhash, 16) != 0) {
		net_info_ratelimited("MD5 Hash %s for [%pI6c]:%u->[%pI6c]:%u\n",
				     genhash ? "failed" : "mismatch",
				     &ip6h->saddr, ntohs(th->source),
				     &ip6h->daddr, ntohs(th->dest));
		return 1;
	}
	return 0;
}

static int tcp_v6_md5_hash_hdr(char *md5_hash, struct tcp_md5sig_key *key,
			       const struct in6_addr *daddr, struct in6_addr *saddr,
			       const struct tcphdr *th)
{
	struct tcp_md5sig_pool *hp;
	struct hash_desc *desc;

	hp = tcp_get_md5sig_pool();
	if (!hp)
		goto clear_hash_noput;
	desc = &hp->md5_desc;

	if (crypto_hash_init(desc))
		goto clear_hash;
	if (tcp_v6_md5_hash_pseudoheader(hp, daddr, saddr, th->doff << 2))
		goto clear_hash;
	if (tcp_md5_hash_header(hp, th))
		goto clear_hash;
	if (tcp_md5_hash_key(hp, key))
		goto clear_hash;
	if (crypto_hash_final(desc, md5_hash))
		goto clear_hash;

	tcp_put_md5sig_pool();
	return 0;

clear_hash:
	tcp_put_md5sig_pool();
clear_hash_noput:
	memset(md5_hash, 0, 16);
	return 1;
}

#endif /* CONFIG_TCP_MD5SIG */

static const struct tcp_sock_af_ops tcp_sock_ipv6_mapped_specific = {

#ifdef CONFIG_TCP_MD5SIG
	.md5_lookup	=	tcp_v4_md5_lookup,
	.calc_md5_hash	=	tcp_v4_md5_hash_skb,
	.md5_parse	=	tcp_v6_parse_md5_keys,
#endif

};

static const struct tcp_sock_af_ops tcp_sock_ipv6_specific = {

#ifdef CONFIG_TCP_MD5SIG
	.md5_lookup	=	tcp_v6_md5_lookup,
	.calc_md5_hash	=	tcp_v6_md5_hash_skb,
	.md5_parse	=	tcp_v6_parse_md5_keys,
#endif

};

static const struct tcp_request_sock_ops tcp_request_sock_ipv6_ops = {

#ifdef CONFIG_TCP_MD5SIG
	.md5_lookup	=	tcp_v6_reqsk_md5_lookup,
	.calc_md5_hash	=	tcp_v6_md5_hash_skb,
#endif

};

static __u32 tcp_v6_init_sequence(const struct sk_buff *skb)
{
	return secure_tcpv6_sequence_number(ipv6_hdr(skb)->daddr.s6_addr32,
					    ipv6_hdr(skb)->saddr.s6_addr32,
					    tcp_hdr(skb)->dest,
					    tcp_hdr(skb)->source);
}

static struct sock *tcp_v6_hnd_req(struct sock *sk, struct sk_buff *skb)
{
	struct request_sock *req, **prev;
	const struct tcphdr *th = tcp_hdr(skb);
	struct sock *nsk;

	/* Find possible connection requests. */
	req = inet6_csk_search_req(sk, &prev, th->source,
				   &ipv6_hdr(skb)->saddr,
				   &ipv6_hdr(skb)->daddr, inet6_iif(skb));
	if (req)
		return tcp_check_req(sk, skb, req, prev, false);

	nsk = __inet6_lookup_established(sock_net(sk), &tcp_hashinfo,
			&ipv6_hdr(skb)->saddr, th->source,
			&ipv6_hdr(skb)->daddr, ntohs(th->dest), inet6_iif(skb));

	if (nsk) {
		if (nsk->sk_state != TCP_TIME_WAIT) {
			bh_lock_sock(nsk);
			return nsk;
		}
		inet_twsk_put(inet_twsk(nsk));
		return NULL;
	}

#ifdef CONFIG_SYN_COOKIES
	if (!th->syn)
		sk = cookie_v6_check_p(sk, skb);
#endif
	return sk;
}

/* FIXME: this is substantially similar to the ipv4 code.
 * Can some kind of merge be done? -- erics
 */
static int tcp_v6_conn_request(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_options_received tmp_opt;
	struct request_sock *req;
	struct inet_request_sock *ireq;
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	__u32 isn = TCP_SKB_CB(skb)->when;
	struct dst_entry *dst = NULL;
	struct flowi6 fl6;
	bool want_cookie = false;

	if (skb->protocol == htons(ETH_P_IP))
		return tcp_v4_conn_request(sk, skb);

	if (!ipv6_unicast_destination(skb))
		goto drop;

	if ((sysctl_tcp_syncookies == 2 ||
	     inet_csk_reqsk_queue_is_full(sk)) && !isn) {
		want_cookie = tcp_syn_flood_action(sk, skb, "TCPv6");
		if (!want_cookie)
			goto drop;
	}

	if (sk_acceptq_is_full(sk) && inet_csk_reqsk_queue_young(sk) > 1) {
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_LISTENOVERFLOWS);
		goto drop;
	}

	req = inet6_reqsk_alloc(tcp6_request_sock_ops_p);
	if (req == NULL)
		goto drop;

#ifdef CONFIG_TCP_MD5SIG
	tcp_rsk(req)->af_specific = &tcp_request_sock_ipv6_ops;
#endif

	tcp_clear_options(&tmp_opt);
	tmp_opt.mss_clamp = IPV6_MIN_MTU - sizeof(struct tcphdr) - sizeof(struct ipv6hdr);
	tmp_opt.user_mss = tp->rx_opt.user_mss;
	tcp_parse_options(skb, &tmp_opt, 0, NULL);

	if (want_cookie && !tmp_opt.saw_tstamp)
		tcp_clear_options(&tmp_opt);

	tmp_opt.tstamp_ok = tmp_opt.saw_tstamp;
	tcp_openreq_init(req, &tmp_opt, skb);

	ireq = inet_rsk(req);
	ireq->ir_v6_rmt_addr = ipv6_hdr(skb)->saddr;
	ireq->ir_v6_loc_addr = ipv6_hdr(skb)->daddr;
	if (!want_cookie || tmp_opt.tstamp_ok)
		TCP_ECN_create_request(req, skb, sock_net(sk));

	ireq->ir_iif = sk->sk_bound_dev_if;

	/* So that link locals have meaning */
	if (!sk->sk_bound_dev_if &&
	    ipv6_addr_type(&ireq->ir_v6_rmt_addr) & IPV6_ADDR_LINKLOCAL)
		ireq->ir_iif = inet6_iif(skb);

	if (!isn) {
		if (ipv6_opt_accepted(sk, skb) ||
		    np->rxopt.bits.rxinfo || np->rxopt.bits.rxoinfo ||
		    np->rxopt.bits.rxhlim || np->rxopt.bits.rxohlim ||
		    np->repflow) {
			atomic_inc(&skb->users);
			ireq->pktopts = skb;
		}

		if (want_cookie) {
			isn = cookie_v6_init_sequence_p(sk, skb, &req->mss);
			req->cookie_ts = tmp_opt.tstamp_ok;
			goto have_isn;
		}

		/* VJ's idea. We save last timestamp seen
		 * from the destination in peer table, when entering
		 * state TIME-WAIT, and check against it before
		 * accepting new connection request.
		 *
		 * If "isn" is not zero, this request hit alive
		 * timewait bucket, so that all the necessary checks
		 * are made in the function processing timewait state.
		 */
		if (tmp_opt.saw_tstamp &&
		    tcp_death_row.sysctl_tw_recycle &&
		    (dst = inet6_csk_route_req_p(sk, &fl6, req)) != NULL) {
			if (!tcp_peer_is_proven(req, dst, true)) {
				NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_PAWSPASSIVEREJECTED);
				goto drop_and_release;
			}
		}
		/* Kill the following clause, if you dislike this way. */
		else if (!sysctl_tcp_syncookies &&
			 (sysctl_max_syn_backlog - inet_csk_reqsk_queue_len(sk) <
			  (sysctl_max_syn_backlog >> 2)) &&
			 !tcp_peer_is_proven(req, dst, false)) {
			/* Without syncookies last quarter of
			 * backlog is filled with destinations,
			 * proven to be alive.
			 * It means that we continue to communicate
			 * to destinations, already remembered
			 * to the moment of synflood.
			 */
			LIMIT_NETDEBUG(KERN_DEBUG "TCP: drop open request from %pI6/%u\n",
				       &ireq->ir_v6_rmt_addr, ntohs(tcp_hdr(skb)->source));
			goto drop_and_release;
		}

		isn = tcp_v6_init_sequence(skb);
	}
have_isn:
	tcp_rsk(req)->snt_isn = isn;

	if (security_inet_conn_request(sk, skb, req))
		goto drop_and_release;

	if (tcp_v6_send_synack(sk, dst, &fl6, req,
			       skb_get_queue_mapping(skb)) ||
	    want_cookie)
		goto drop_and_free;

	tcp_rsk(req)->snt_synack = tcp_time_stamp;
	tcp_rsk(req)->listener = NULL;
	inet6_csk_reqsk_queue_hash_add(sk, req, TCP_TIMEOUT_INIT);
	return 0;

drop_and_release:
	dst_release(dst);
drop_and_free:
	reqsk_free(req);
drop:
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_LISTENDROPS);
	return 0; /* don't send reset */
}

static struct sock *tcp_v6_syn_recv_sock(struct sock *sk, struct sk_buff *skb,
					 struct request_sock *req,
					 struct dst_entry *dst)
{
	struct inet_request_sock *ireq;
	struct ipv6_pinfo *newnp, *np = inet6_sk(sk);
	struct tcp6_sock *newtcp6sk;
	struct inet_sock *newinet;
	struct tcp_sock *newtp;
	struct sock *newsk;
#ifdef CONFIG_TCP_MD5SIG
	struct tcp_md5sig_key *key;
#endif
	struct flowi6 fl6;

	if (skb->protocol == htons(ETH_P_IP)) {
		/*
		 *	v6 mapped
		 */

		newsk = tcp_v4_syn_recv_sock(sk, skb, req, dst);

		if (newsk == NULL)
			return NULL;

		newtcp6sk = (struct tcp6_sock *)newsk;
		inet_sk(newsk)->pinet6 = &newtcp6sk->inet6;

		newinet = inet_sk(newsk);
		newnp = inet6_sk(newsk);
		newtp = tcp_sk(newsk);

		memcpy(newnp, np, sizeof(struct ipv6_pinfo));

		ipv6_addr_set_v4mapped(newinet->inet_daddr, &newsk->sk_v6_daddr);

		ipv6_addr_set_v4mapped(newinet->inet_saddr, &newnp->saddr);

		newsk->sk_v6_rcv_saddr = newnp->saddr;

		inet_csk(newsk)->icsk_af_ops = &ipv6_mapped;
		newsk->sk_backlog_rcv = tcp_v4_do_rcv;
#ifdef CONFIG_TCP_MD5SIG
		newtp->af_specific = &tcp_sock_ipv6_mapped_specific;
#endif

		newnp->ipv6_ac_list = NULL;
		newnp->ipv6_fl_list = NULL;
		newnp->pktoptions  = NULL;
		newnp->opt	   = NULL;
		newnp->mcast_oif   = inet6_iif(skb);
		newnp->mcast_hops  = ipv6_hdr(skb)->hop_limit;
		newnp->rcv_flowinfo = ip6_flowinfo(ipv6_hdr(skb));
		if (np->repflow)
			newnp->flow_label = ip6_flowlabel(ipv6_hdr(skb));

		/*
		 * No need to charge this sock to the relevant IPv6 refcnt debug socks count
		 * here, tcp_create_openreq_child now does this for us, see the comment in
		 * that function for the gory details. -acme
		 */

		/* It is tricky place. Until this moment IPv4 tcp
		   worked with IPv6 icsk.icsk_af_ops.
		   Sync it now.
		 */
		tcp_sync_mss(newsk, inet_csk(newsk)->icsk_pmtu_cookie);

		return newsk;
	}

	ireq = inet_rsk(req);

	if (sk_acceptq_is_full(sk))
		goto out_overflow;

	if (!dst) {
		dst = inet6_csk_route_req_p(sk, &fl6, req);
		if (!dst)
			goto out;
	}

	newsk = tcp_create_openreq_child(sk, req, skb);
	if (newsk == NULL)
		goto out_nonewsk;

	/*
	 * No need to charge this sock to the relevant IPv6 refcnt debug socks
	 * count here, tcp_create_openreq_child now does this for us, see the
	 * comment in that function for the gory details. -acme
	 */

	newsk->sk_gso_type = SKB_GSO_TCPV6;
	__ip6_dst_store(newsk, dst, NULL, NULL);
	inet6_sk_rx_dst_set(newsk, skb);

	newtcp6sk = (struct tcp6_sock *)newsk;
	inet_sk(newsk)->pinet6 = &newtcp6sk->inet6;

	newtp = tcp_sk(newsk);
	newinet = inet_sk(newsk);
	newnp = inet6_sk(newsk);

	memcpy(newnp, np, sizeof(struct ipv6_pinfo));

	newsk->sk_v6_daddr = ireq->ir_v6_rmt_addr;
	newnp->saddr = ireq->ir_v6_loc_addr;
	newsk->sk_v6_rcv_saddr = ireq->ir_v6_loc_addr;
	newsk->sk_bound_dev_if = ireq->ir_iif;

	/* Now IPv6 options...

	   First: no IPv4 options.
	 */
	newinet->inet_opt = NULL;
	newnp->ipv6_ac_list = NULL;
	newnp->ipv6_fl_list = NULL;

	/* Clone RX bits */
	newnp->rxopt.all = np->rxopt.all;

	/* Clone pktoptions received with SYN */
	newnp->pktoptions = NULL;
	if (ireq->pktopts != NULL) {
		newnp->pktoptions = skb_clone(ireq->pktopts,
					      sk_gfp_atomic(sk, GFP_ATOMIC));
		consume_skb(ireq->pktopts);
		ireq->pktopts = NULL;
		if (newnp->pktoptions)
			skb_set_owner_r(newnp->pktoptions, newsk);
	}
	newnp->opt	  = NULL;
	newnp->mcast_oif  = inet6_iif(skb);
	newnp->mcast_hops = ipv6_hdr(skb)->hop_limit;
	newnp->rcv_flowinfo = ip6_flowinfo(ipv6_hdr(skb));
	if (np->repflow)
		newnp->flow_label = ip6_flowlabel(ipv6_hdr(skb));

	/* Clone native IPv6 options from listening socket (if any)

	   Yes, keeping reference count would be much more clever,
	   but we make one more one thing there: reattach optmem
	   to newsk.
	 */
	if (np->opt)
		newnp->opt = ipv6_dup_options(newsk, np->opt);

	inet_csk(newsk)->icsk_ext_hdr_len = 0;
	if (newnp->opt)
		inet_csk(newsk)->icsk_ext_hdr_len = (newnp->opt->opt_nflen +
						     newnp->opt->opt_flen);

	tcp_sync_mss(newsk, dst_mtu(dst));
	newtp->advmss = dst_metric_advmss(dst);
	if (tcp_sk(sk)->rx_opt.user_mss &&
	    tcp_sk(sk)->rx_opt.user_mss < newtp->advmss)
		newtp->advmss = tcp_sk(sk)->rx_opt.user_mss;

	tcp_initialize_rcv_mss(newsk);

	newinet->inet_daddr = newinet->inet_saddr = LOOPBACK4_IPV6;
	newinet->inet_rcv_saddr = LOOPBACK4_IPV6;

#ifdef CONFIG_TCP_MD5SIG
	/* Copy over the MD5 key from the original socket */
	if ((key = tcp_v6_md5_do_lookup(sk, &newsk->sk_v6_daddr)) != NULL) {
		/* We're using one, so create a matching key
		 * on the newsk structure. If we fail to get
		 * memory, then we end up not copying the key
		 * across. Shucks.
		 */
		tcp_md5_do_add(newsk, (union tcp_md5_addr *)&newsk->sk_v6_daddr,
			       AF_INET6, key->key, key->keylen,
			       sk_gfp_atomic(sk, GFP_ATOMIC));
	}
#endif

	if (__inet_inherit_port(sk, newsk) < 0) {
		inet_csk_prepare_forced_close(newsk);
		tcp_done(newsk);
		goto out;
	}
	__inet6_hash(newsk, NULL);

	return newsk;

out_overflow:
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_LISTENOVERFLOWS);
out_nonewsk:
	dst_release(dst);
out:
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_LISTENDROPS);
	return NULL;
}

static const struct inet_connection_sock_af_ops ipv6_mapped = {
	.queue_xmit	   = ip_queue_xmit,
	.send_check	   = tcp_v4_send_check,
	.rebuild_header	   = inet_sk_rebuild_header,
	.sk_rx_dst_set	   = inet_sk_rx_dst_set,
	.conn_request	   = tcp_v6_conn_request,
	.syn_recv_sock	   = tcp_v6_syn_recv_sock,
	.net_header_len	   = sizeof(struct iphdr),
	.setsockopt	   = ipv6_setsockopt,
	.getsockopt	   = ipv6_getsockopt,
	.addr2sockaddr	   = inet6_csk_addr2sockaddr,
	.sockaddr_len	   = sizeof(struct sockaddr_in6),
	.bind_conflict	   = inet6_csk_bind_conflict,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_ipv6_setsockopt,
	.compat_getsockopt = compat_ipv6_getsockopt,
#endif
};

static void tcp_v6_send_response(struct sk_buff *skb, u32 seq, u32 ack, u32 win,
				 u32 tsval, u32 tsecr,
				 struct tcp_md5sig_key *key, int rst, u8 tclass,
				 u32 label)
{
	const struct tcphdr *th = tcp_hdr(skb);
	struct tcphdr *t1;
	struct sk_buff *buff;
	struct flowi6 fl6;
	struct net *net = dev_net(skb_dst(skb)->dev);
	struct sock *ctl_sk = net->ipv6.tcp_sk;
	unsigned int tot_len = sizeof(struct tcphdr);
	struct dst_entry *dst;
	__be32 *topt;

	if (tsecr)
		tot_len += TCPOLEN_TSTAMP_ALIGNED;
#ifdef CONFIG_TCP_MD5SIG
	if (key)
		tot_len += TCPOLEN_MD5SIG_ALIGNED;
#endif

	buff = alloc_skb(MAX_HEADER + sizeof(struct ipv6hdr) + tot_len,
			 GFP_ATOMIC);
	if (buff == NULL)
		return;

	skb_reserve(buff, MAX_HEADER + sizeof(struct ipv6hdr) + tot_len);

	t1 = (struct tcphdr *) skb_push(buff, tot_len);
	skb_reset_transport_header(buff);

	/* Swap the send and the receive. */
	memset(t1, 0, sizeof(*t1));
	t1->dest = th->source;
	t1->source = th->dest;
	t1->doff = tot_len / 4;
	t1->seq = htonl(seq);
	t1->ack_seq = htonl(ack);
	t1->ack = !rst || !th->ack;
	t1->rst = rst;
	t1->window = htons(win);

	topt = (__be32 *)(t1 + 1);

	if (tsecr) {
		*topt++ = htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) |
				(TCPOPT_TIMESTAMP << 8) | TCPOLEN_TIMESTAMP);
		*topt++ = htonl(tsval);
		*topt++ = htonl(tsecr);
	}

#ifdef CONFIG_TCP_MD5SIG
	if (key) {
		*topt++ = htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) |
				(TCPOPT_MD5SIG << 8) | TCPOLEN_MD5SIG);
		tcp_v6_md5_hash_hdr((__u8 *)topt, key,
				    &ipv6_hdr(skb)->saddr,
				    &ipv6_hdr(skb)->daddr, t1);
	}
#endif

	memset(&fl6, 0, sizeof(fl6));
	fl6.daddr = ipv6_hdr(skb)->saddr;
	fl6.saddr = ipv6_hdr(skb)->daddr;
	fl6.flowlabel = label;

	buff->ip_summed = CHECKSUM_PARTIAL;
	buff->csum = 0;

	__tcp_v6_send_check(buff, &fl6.saddr, &fl6.daddr);

	fl6.flowi6_proto = IPPROTO_TCP;
	if (ipv6_addr_type(&fl6.daddr) & IPV6_ADDR_LINKLOCAL)
		fl6.flowi6_oif = inet6_iif(skb);
	fl6.fl6_dport = t1->dest;
	fl6.fl6_sport = t1->source;
	security_skb_classify_flow(skb, flowi6_to_flowi(&fl6));

	/* Pass a socket to ip6_dst_lookup either it is for RST
	 * Underlying function will use this to retrieve the network
	 * namespace
	 */
	dst = ip6_dst_lookup_flow(ctl_sk, &fl6, NULL);
	if (!IS_ERR(dst)) {
		skb_dst_set(buff, dst);
		ip6_xmit(ctl_sk, buff, &fl6, NULL, tclass);
		TCP_INC_STATS_BH(net, TCP_MIB_OUTSEGS);
		if (rst)
			TCP_INC_STATS_BH(net, TCP_MIB_OUTRSTS);
		return;
	}

	kfree_skb(buff);
}

static void tcp_v6_send_reset(struct sock *sk, struct sk_buff *skb)
{
	const struct tcphdr *th = tcp_hdr(skb);
	u32 seq = 0, ack_seq = 0;
	struct tcp_md5sig_key *key = NULL;
#ifdef CONFIG_TCP_MD5SIG
	const __u8 *hash_location = NULL;
	struct ipv6hdr *ipv6h = ipv6_hdr(skb);
	unsigned char newhash[16];
	int genhash;
	struct sock *sk1 = NULL;
#endif

	if (th->rst)
		return;

	if (!ipv6_unicast_destination(skb))
		return;

#ifdef CONFIG_TCP_MD5SIG
	hash_location = tcp_parse_md5sig_option(th);
	if (!sk && hash_location) {
		/*
		 * active side is lost. Try to find listening socket through
		 * source port, and then find md5 key through listening socket.
		 * we are not loose security here:
		 * Incoming packet is checked with md5 hash with finding key,
		 * no RST generated if md5 hash doesn't match.
		 */
		sk1 = inet6_lookup_listener(dev_net(skb_dst(skb)->dev),
					   &tcp_hashinfo, &ipv6h->saddr,
					   th->source, &ipv6h->daddr,
					   ntohs(th->source), inet6_iif(skb));
		if (!sk1)
			return;

		rcu_read_lock();
		key = tcp_v6_md5_do_lookup(sk1, &ipv6h->saddr);
		if (!key)
			goto release_sk1;

		genhash = tcp_v6_md5_hash_skb(newhash, key, NULL, NULL, skb);
		if (genhash || memcmp(hash_location, newhash, 16) != 0)
			goto release_sk1;
	} else {
		key = sk ? tcp_v6_md5_do_lookup(sk, &ipv6h->saddr) : NULL;
	}
#endif

	if (th->ack)
		seq = ntohl(th->ack_seq);
	else
		ack_seq = ntohl(th->seq) + th->syn + th->fin + skb->len -
			  (th->doff << 2);

	tcp_v6_send_response(skb, seq, ack_seq, 0, 0, 0, key, 1, 0, 0);

#ifdef CONFIG_TCP_MD5SIG
release_sk1:
	if (sk1) {
		rcu_read_unlock();
		sock_put(sk1);
	}
#endif
}

/* The socket must have it's spinlock held when we get
 * here.
 *
 * We have a potential double-lock case here, so even when
 * doing backlog processing we use the BH locking scheme.
 * This is because we cannot sleep with the original spinlock
 * held.
 */
static int tcp_v6_do_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct tcp_sock *tp;
	struct sk_buff *opt_skb = NULL;

	/* Imagine: socket is IPv6. IPv4 packet arrives,
	   goes to IPv4 receive handler and backlogged.
	   From backlog it always goes here. Kerboom...
	   Fortunately, tcp_rcv_established and rcv_established
	   handle them correctly, but it is not case with
	   tcp_v6_hnd_req and tcp_v6_send_reset().   --ANK
	 */

	if (skb->protocol == htons(ETH_P_IP))
		return tcp_v4_do_rcv(sk, skb);

#ifdef CONFIG_TCP_MD5SIG
	if (tcp_v6_inbound_md5_hash (sk, skb))
		goto discard;
#endif

	if (sk_filter(sk, skb))
		goto discard;

	/*
	 *	socket locking is here for SMP purposes as backlog rcv
	 *	is currently called with bh processing disabled.
	 */

	/* Do Stevens' IPV6_PKTOPTIONS.

	   Yes, guys, it is the only place in our code, where we
	   may make it not affecting IPv4.
	   The rest of code is protocol independent,
	   and I do not like idea to uglify IPv4.

	   Actually, all the idea behind IPV6_PKTOPTIONS
	   looks not very well thought. For now we latch
	   options, received in the last packet, enqueued
	   by tcp. Feel free to propose better solution.
					       --ANK (980728)
	 */
	if (np->rxopt.all)
		opt_skb = skb_clone(skb, sk_gfp_atomic(sk, GFP_ATOMIC));

	if (sk->sk_state == TCP_ESTABLISHED) { /* Fast path */
		struct dst_entry *dst = sk->sk_rx_dst;

		sock_rps_save_rxhash(sk, skb);
		if (dst) {
			if (inet_sk(sk)->rx_dst_ifindex != skb->skb_iif ||
			    dst->ops->check(dst, np->rx_dst_cookie) == NULL) {
				dst_release(dst);
				sk->sk_rx_dst = NULL;
			}
		}

		tcp_rcv_established(sk, skb, tcp_hdr(skb), skb->len);
		if (opt_skb)
			goto ipv6_pktoptions;
		return 0;
	}

	if (skb->len < tcp_hdrlen(skb) || tcp_checksum_complete(skb))
		goto csum_err;

	if (sk->sk_state == TCP_LISTEN) {
		struct sock *nsk = tcp_v6_hnd_req(sk, skb);
		if (!nsk)
			goto discard;

		/*
		 * Queue it on the new socket if the new socket is active,
		 * otherwise we just shortcircuit this and continue with
		 * the new socket..
		 */
		if (nsk != sk) {
			sock_rps_save_rxhash(nsk, skb);
			if (tcp_child_process(sk, nsk, skb))
				goto reset;
			if (opt_skb)
				__kfree_skb(opt_skb);
			return 0;
		}
	} else
		sock_rps_save_rxhash(sk, skb);

	if (tcp_rcv_state_process(sk, skb, tcp_hdr(skb), skb->len))
		goto reset;
	if (opt_skb)
		goto ipv6_pktoptions;
	return 0;

reset:
	tcp_v6_send_reset(sk, skb);
discard:
	if (opt_skb)
		__kfree_skb(opt_skb);
	kfree_skb(skb);
	return 0;
csum_err:
	TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_CSUMERRORS);
	TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_INERRS);
	goto discard;


ipv6_pktoptions:
	/* Do you ask, what is it?

	   1. skb was enqueued by tcp.
	   2. skb is added to tail of read queue, rather than out of order.
	   3. socket is not in passive state.
	   4. Finally, it really contains options, which user wants to receive.
	 */
	tp = tcp_sk(sk);
	if (TCP_SKB_CB(opt_skb)->end_seq == tp->rcv_nxt &&
	    !((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN))) {
		if (np->rxopt.bits.rxinfo || np->rxopt.bits.rxoinfo)
			np->mcast_oif = inet6_iif(opt_skb);
		if (np->rxopt.bits.rxhlim || np->rxopt.bits.rxohlim)
			np->mcast_hops = ipv6_hdr(opt_skb)->hop_limit;
		if (np->rxopt.bits.rxflow || np->rxopt.bits.rxtclass)
			np->rcv_flowinfo = ip6_flowinfo(ipv6_hdr(opt_skb));
		if (np->repflow)
			np->flow_label = ip6_flowlabel(ipv6_hdr(opt_skb));
		if (ipv6_opt_accepted(sk, opt_skb)) {
			skb_set_owner_r(opt_skb, sk);
			opt_skb = xchg(&np->pktoptions, opt_skb);
		} else {
			__kfree_skb(opt_skb);
			opt_skb = xchg(&np->pktoptions, NULL);
		}
	}

	kfree_skb(opt_skb);
	return 0;
}

static void tcp_v6_hash_offload(struct sock *sk)
{
	orig_tcpv6_prot.hash(sk);
	if (sk->sk_state == TCP_LISTEN)
		start_listen_offload(sk);
}

static void tcp_v6_unhash_offload(struct sock *sk)
{
	if (sk->sk_state == TCP_LISTEN)
		stop_listen_offload(sk);
	orig_tcpv6_prot.unhash(sk);
}

/* Offload version of Linux kernel tcp_v6_connect() */
static int tcp_v6_connect_offload(struct sock *sk, struct sockaddr *uaddr,
				  int addr_len)
{
	struct sockaddr_in6 *usin = (struct sockaddr_in6 *) uaddr;
	struct inet_sock *inet = inet_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct in6_addr *saddr = NULL, *final_p, final;
	struct rt6_info *rt;
	struct flowi6 fl6;
	struct dst_entry *dst;
	int addr_type;
	int err;

	if (addr_len < SIN6_LEN_RFC2133)
		return -EINVAL;

	if (usin->sin6_family != AF_INET6)
		return -EAFNOSUPPORT;

	memset(&fl6, 0, sizeof(fl6));

	if (np->sndflow) {
		fl6.flowlabel = usin->sin6_flowinfo&IPV6_FLOWINFO_MASK;
		IP6_ECN_flow_init(fl6.flowlabel);
		if (fl6.flowlabel&IPV6_FLOWLABEL_MASK) {
			struct ip6_flowlabel *flowlabel;
			flowlabel = fl6_sock_lookup(sk, fl6.flowlabel);
			if (flowlabel == NULL)
				return -EINVAL;
			fl6_sock_release(flowlabel);
		}
	}

	/*
	 *	connect() to INADDR_ANY means loopback (BSD'ism).
	 */

	if (ipv6_addr_any(&usin->sin6_addr))
		usin->sin6_addr.s6_addr[15] = 0x1;

	addr_type = ipv6_addr_type(&usin->sin6_addr);

	if (addr_type & IPV6_ADDR_MULTICAST)
		return -ENETUNREACH;

	if (addr_type&IPV6_ADDR_LINKLOCAL) {
		if (addr_len >= sizeof(struct sockaddr_in6) &&
		    usin->sin6_scope_id) {
			/* If interface is set while binding, indices
			 * must coincide.
			 */
			if (sk->sk_bound_dev_if &&
			    sk->sk_bound_dev_if != usin->sin6_scope_id)
				return -EINVAL;

			sk->sk_bound_dev_if = usin->sin6_scope_id;
		}

		/* Connect to link-local address requires an interface */
		if (!sk->sk_bound_dev_if)
			return -EINVAL;
	}

	if (tp->rx_opt.ts_recent_stamp &&
	    !ipv6_addr_equal(&sk->sk_v6_daddr, &usin->sin6_addr)) {
		tp->rx_opt.ts_recent = 0;
		tp->rx_opt.ts_recent_stamp = 0;
		tp->write_seq = 0;
	}

	sk->sk_v6_daddr = usin->sin6_addr;
	np->flow_label = fl6.flowlabel;

	/*
	 *	TCP over IPv4
	 */

	if (addr_type == IPV6_ADDR_MAPPED) {
		u32 exthdrlen = icsk->icsk_ext_hdr_len;
		struct sockaddr_in sin;

		SOCK_DEBUG(sk, "connect: ipv4 mapped\n");

		if (__ipv6_only_sock(sk))
			return -ENETUNREACH;

		sin.sin_family = AF_INET;
		sin.sin_port = usin->sin6_port;
		sin.sin_addr.s_addr = usin->sin6_addr.s6_addr32[3];

		icsk->icsk_af_ops = &ipv6_mapped;
		sk->sk_backlog_rcv = tcp_v4_do_rcv;
#ifdef CONFIG_TCP_MD5SIG
		tp->af_specific = &tcp_sock_ipv6_mapped_specific;
#endif

		err = tcp_v4_connect(sk, (struct sockaddr *)&sin, sizeof(sin));

		if (err) {
			icsk->icsk_ext_hdr_len = exthdrlen;
			icsk->icsk_af_ops = &ipv6_specific;
			sk->sk_backlog_rcv = tcp_v6_do_rcv;
#ifdef CONFIG_TCP_MD5SIG
			tp->af_specific = &tcp_sock_ipv6_specific;
#endif
			goto failure;
		} else {
			ipv6_addr_set_v4mapped(inet->inet_saddr, &np->saddr);
			ipv6_addr_set_v4mapped(inet->inet_rcv_saddr,
					       &sk->sk_v6_rcv_saddr);
		}

		return err;
	}

	if (!ipv6_addr_any(&sk->sk_v6_rcv_saddr))
		saddr = &sk->sk_v6_rcv_saddr;

	fl6.flowi6_proto = IPPROTO_TCP;
	fl6.daddr = sk->sk_v6_daddr;
	fl6.saddr = saddr ? *saddr : np->saddr;
	fl6.flowi6_oif = sk->sk_bound_dev_if;
	fl6.flowi6_mark = sk->sk_mark;
	fl6.fl6_dport = usin->sin6_port;
	fl6.fl6_sport = inet->inet_sport;

	final_p = fl6_update_dst(&fl6, np->opt, &final);

	security_sk_classify_flow(sk, flowi6_to_flowi(&fl6));

	dst = ip6_dst_lookup_flow(sk, &fl6, final_p);
	if (IS_ERR(dst)) {
		err = PTR_ERR(dst);
		goto failure;
	}

	if (saddr == NULL) {
		saddr = &fl6.saddr;
		sk->sk_v6_rcv_saddr = *saddr;
	}

	/* set the source address */
	np->saddr = *saddr;
	inet->inet_rcv_saddr = LOOPBACK4_IPV6;

	sk->sk_gso_type = SKB_GSO_TCPV6;
	__ip6_dst_store(sk, dst, NULL, NULL);

	rt = (struct rt6_info *) dst;
	if (tcp_death_row.sysctl_tw_recycle &&
	    !tp->rx_opt.ts_recent_stamp &&
	    ipv6_addr_equal(&rt->rt6i_dst.addr, &sk->sk_v6_daddr))
		tcp_fetch_timewait_stamp(sk, dst);

	icsk->icsk_ext_hdr_len = 0;
	if (np->opt)
		icsk->icsk_ext_hdr_len = (np->opt->opt_flen +
					  np->opt->opt_nflen);

	tp->rx_opt.mss_clamp = IPV6_MIN_MTU - sizeof(struct tcphdr) - sizeof(struct ipv6hdr);

	inet->inet_dport = usin->sin6_port;

	tcp_set_state(sk, TCP_SYN_SENT);
	err = inet6_hash_connect(&tcp_death_row, sk);
	if (err)
		goto late_failure;

	if (tcp_connect_offload(sk))
		return 0;

	if (!tp->write_seq && likely(!tp->repair))
		tp->write_seq = secure_tcpv6_sequence_number(np->saddr.s6_addr32,
							     sk->sk_v6_daddr.s6_addr32,
							     inet->inet_sport,
							     inet->inet_dport);

	err = tcp_connect(sk);
	if (err)
		goto late_failure;

	return 0;

late_failure:
	tcp_set_state(sk, TCP_CLOSE);
	__sk_dst_reset(sk);
failure:
	inet->inet_dport = 0;
	sk->sk_route_caps = 0;
	return err;
}

static const struct inet_connection_sock_af_ops ipv6_specific = {
	.queue_xmit	   = inet6_csk_xmit,
	.send_check	   = tcp_v6_send_check,
	.rebuild_header	   = inet6_sk_rebuild_header,
	.sk_rx_dst_set	   = inet6_sk_rx_dst_set,
	.conn_request	   = tcp_v6_conn_request,
	.syn_recv_sock	   = tcp_v6_syn_recv_sock,
	.net_header_len	   = sizeof(struct ipv6hdr),
	.net_frag_header_len = sizeof(struct frag_hdr),
	.setsockopt	   = ipv6_setsockopt,
	.getsockopt	   = ipv6_getsockopt,
	.addr2sockaddr	   = inet6_csk_addr2sockaddr,
	.sockaddr_len	   = sizeof(struct sockaddr_in6),
	.bind_conflict	   = inet6_csk_bind_conflict,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_ipv6_setsockopt,
	.compat_getsockopt = compat_ipv6_getsockopt,
#endif
};

static struct proto_ops *orig_inet6_stream_ops_p;
#endif //CONFIG_TCPV6_OFFLOAD

static int offload_enabled;

#ifdef CONFIG_DEBUG_RODATA
static struct proto_ops offload_inet_stream_ops;
#ifdef CONFIG_TCPV6_OFFLOAD
static struct proto_ops offload_inet6_stream_ops;
#endif

void offload_socket_ops(struct sock *sk)
{
	struct socket *sock = sk->sk_socket;

	if (!sock)
		return;

	if (sock->ops == &inet_stream_ops)
		sock->ops = &offload_inet_stream_ops;

#ifdef CONFIG_TCPV6_OFFLOAD
	else if (sock->ops == orig_inet6_stream_ops_p)
		sock->ops = &offload_inet6_stream_ops;
#endif
}

void restore_socket_ops(struct sock *sk)
{
	struct socket *sock = sk->sk_socket;

	if (!sock)
		return;

	if (sock->ops == &offload_inet_stream_ops)
		sock->ops = &inet_stream_ops;

#ifdef CONFIG_TCPV6_OFFLOAD
	if (sock->ops == &offload_inet6_stream_ops)
		sock->ops = orig_inet6_stream_ops_p;
#endif
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

#define FIND_SYMBOL(name, ptr) do { \
	ptr = (void *)kallsyms_lookup_name(name); \
	if (!ptr) { \
		printk("toecore failure: could not get " name "\n"); \
		return -ENOENT; \
	} \
} while (0)

#define FIND_SYSCTL(name) do { \
	int *p = (void *)kallsyms_lookup_name("sysctl_tcp_" # name); \
	if (p) \
		sysctl_tcp_ ## name ## _p = p; \
} while (0)

int prepare_tcp_for_offload(void)
{
	if (offload_enabled)   /* already done */
		return 0;

	FIND_SYMBOL("skb_splice_bits", skb_splice_bits_p);
	FIND_SYMBOL("secure_tcp_sequence_number", secure_tcp_sequence_number_p);

#ifdef CONFIG_SECURITY_NETWORK
	FIND_SYMBOL("security_inet_conn_established",
		    security_inet_conn_established_p);
#endif

#ifdef CONFIG_TCPV6_OFFLOAD
	FIND_SYMBOL("cookie_v6_init_sequence", cookie_v6_init_sequence_p);
	FIND_SYMBOL("cookie_v6_check", cookie_v6_check_p);
	FIND_SYMBOL("tcp6_request_sock_ops", tcp6_request_sock_ops_p);
	FIND_SYMBOL("inet6_csk_route_req", inet6_csk_route_req_p);
	FIND_SYMBOL("tcpv6_prot", tcpv6_prot_p);
	FIND_SYMBOL("inet6_stream_ops", orig_inet6_stream_ops_p);
#endif

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

#ifdef CONFIG_TCPV6_OFFLOAD
	offload_inet6_stream_ops = *orig_inet6_stream_ops_p;
	offload_inet6_stream_ops.sendmsg = tcp_sendmsg_offload;
	offload_inet6_stream_ops.sendpage = tcp_sendpage_offload;
	offload_inet6_stream_ops.splice_read = tcp_splice_read_offload;
#endif

	walk_listens(NULL, offload_listen_cb);
#else
	{
		struct proto_ops *iso = (struct proto_ops *)&inet_stream_ops;
#ifdef CONFIG_TCPV6_OFFLOAD
		struct proto_ops *iso6 = (struct proto_ops *)orig_inet6_stream_ops_p;
#endif

		iso->sendmsg = tcp_sendmsg_offload;
		iso->sendpage = tcp_sendpage_offload;
		iso->splice_read = tcp_splice_read_offload;

#ifdef CONFIG_TCPV6_OFFLOAD
		iso6->sendmsg = tcp_sendmsg_offload;
		iso6->sendpage = tcp_sendpage_offload;
		iso6->splice_read = tcp_splice_read_offload;
#endif
	}
#endif

	orig_tcp_prot = tcp_prot;
	tcp_prot.hash = tcp_v4_hash_offload;
	tcp_prot.unhash = tcp_unhash_offload;
	tcp_prot.connect = tcp_v4_connect_offload;

#ifdef CONFIG_TCPV6_OFFLOAD
	orig_tcpv6_prot = *tcpv6_prot_p;
	tcpv6_prot_p->hash = tcp_v6_hash_offload;
	tcpv6_prot_p->unhash = tcp_v6_unhash_offload;
	tcpv6_prot_p->connect = tcp_v6_connect_offload;
#endif

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
			struct proto_ops *iso = (struct proto_ops *)&inet_stream_ops;
#ifdef CONFIG_TCPV6_OFFLOAD
			struct proto_ops *iso6 = (struct proto_ops *)orig_inet6_stream_ops_p;
#endif

			iso->sendmsg = inet_sendmsg;
			iso->sendpage = inet_sendpage;
			iso->splice_read = tcp_splice_read;

#ifdef CONFIG_TCPV6_OFFLOAD
			iso6->sendmsg = inet_sendmsg;
			iso6->sendpage = inet_sendpage;
			iso6->splice_read = tcp_splice_read;
#endif
		}
#endif
		tcp_prot.hash = orig_tcp_prot.hash;
		tcp_prot.unhash = orig_tcp_prot.unhash;
		tcp_prot.connect = orig_tcp_prot.connect;

#ifdef CONFIG_TCPV6_OFFLOAD
		tcpv6_prot_p->hash = orig_tcpv6_prot.hash;
		tcpv6_prot_p->unhash = orig_tcpv6_prot.unhash;
		tcpv6_prot_p->connect = orig_tcpv6_prot.connect;
#endif

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

static inline struct rpc_xprt *xprt_from_sock(struct sock *sk)
{
        return (struct rpc_xprt *) sk->sk_user_data;
}

/* Offload version of Linux kernel xs_tcp_data_ready() */
/* Replacement for RPC's ->data_ready callback */
static void xs_ofld_tcp_data_ready(struct sock *sk, int bytes)
{
	struct rpc_xprt *xprt;
	read_descriptor_t rd_desc;

	read_lock_bh(&sk->sk_callback_lock);
	if (!(xprt = xprt_from_sock(sk)))
		goto out;
	/* Any data means we had a useful conversation, so
	 * the we don't need to delay the next reconnect
	 */
	if (xprt->reestablish_timeout)
		xprt->reestablish_timeout = 0;

	/* We use rd_desc to pass struct xprt to xs_tcp_data_recv */
	rd_desc.arg.data = xprt;
	rd_desc.count = 65536;
	ofld_read_sock(sk, &rd_desc, xs_tcp_data_recv_p);
out:
	read_unlock_bh(&sk->sk_callback_lock);
}

static inline void iscsi_tcp_segment_unmap(struct iscsi_segment *segment)
{
	if (segment->sg_mapped) {
		if (segment->atomic_mapped)
			kunmap_atomic(segment->sg_mapped);
		else
			kunmap(sg_page(segment->sg));
		segment->sg_mapped = NULL;
		segment->data = NULL;
	}
}

/*
 * Offload version of Linux kernel iscsi_tcp_data_ready() when
 * iscsi_tcp_recv() is in the kernel.
 */
/* Replacement for iSCSI's ->data_ready callback */
static void iscsi_ofld_tcp_data_ready_0(struct sock *sk, int bytes)
{
	struct iscsi_conn *conn;
	struct iscsi_tcp_conn *tcp_conn;
	read_descriptor_t rd_desc;

	read_lock(&sk->sk_callback_lock);
	conn = sk->sk_user_data;
	if (!conn) {
		read_unlock(&sk->sk_callback_lock);
		return;
	}
	tcp_conn = conn->dd_data;

	/*
	 * Use rd_desc to pass 'conn' to iscsi_tcp_recv.
	 * We set count to 1 because we want the network layer to
	 * hand us all the skbs that are available. iscsi_tcp_recv
	 * handled pdus that cross buffers or pdus that still need data.
	 */
	rd_desc.arg.data = conn;
	rd_desc.count = 1;
	ofld_read_sock(sk, &rd_desc, iscsi_tcp_recv_p);

	// Chelsio toecore: Not worth pulling this in ...
	// iscsi_sw_sk_state_check(sk);

	/* If we had to (atomically) map a highmem page,
	 * unmap it now. */
	iscsi_tcp_segment_unmap(&tcp_conn->in.segment);
	read_unlock(&sk->sk_callback_lock);
}

/*
 * Offload version of Linux kernel iscsi_sw_tcp_data_ready()
 */
/* Replacement for iSCSI's ->data_ready callback */
static void iscsi_ofld_tcp_data_ready_2(struct sock *sk, int bytes)
{
	struct iscsi_conn *conn;
	struct iscsi_tcp_conn *tcp_conn;
	read_descriptor_t rd_desc;

	read_lock(&sk->sk_callback_lock);
	conn = sk->sk_user_data;
	if (!conn) {
		read_unlock(&sk->sk_callback_lock);
		return;
	}
	tcp_conn = conn->dd_data;

	/*
	 * Use rd_desc to pass 'conn' to iscsi_tcp_recv.
	 * We set count to 1 because we want the network layer to
	 * hand us all the skbs that are available. iscsi_tcp_recv
	 * handled pdus that cross buffers or pdus that still need data.
	 */
	rd_desc.arg.data = conn;
	rd_desc.count = 1;
	ofld_read_sock(sk, &rd_desc, iscsi_sw_tcp_recv_p);

	// Chelsio toecore: Not worth pulling this in ...
	// iscsi_sw_sk_state_check(sk);

	/* If we had to (atomically) map a highmem page,
	 * unmap it now. */
	iscsi_tcp_segment_unmap(&tcp_conn->in.segment);
	read_unlock(&sk->sk_callback_lock);
}

/*
 * Offload version of Linux kernel iscsi_tcp_data_recv() when
 * iscsi_tcp_data_recv() is in the kernel.
 */
/* Replacement for iSCSI's ->data_ready callback, old api */
static void iscsi_ofld_tcp_data_ready_1(struct sock *sk, int bytes)
{
	struct iscsi_conn *conn;
	read_descriptor_t rd_desc;

	read_lock(&sk->sk_callback_lock);
	conn = sk->sk_user_data;
	if (!conn) {
		read_unlock(&sk->sk_callback_lock);
		return;
	}

	/*
	 * Use rd_desc to pass 'conn' to iscsi_tcp_recv.
	 * We set count to 1 because we want the network layer to
	 * hand us all the skbs that are available. iscsi_tcp_recv
	 * handled pdus that cross buffers or pdus that still need data.
	 */
	rd_desc.arg.data = conn;
	rd_desc.count = 1;
	ofld_read_sock(sk, &rd_desc, iscsi_tcp_data_recv_p);

	// Chelsio toecore: Not worth pulling this in ...
	// iscsi_sw_sk_state_check(sk);

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

static int toe_bond_xmit_hash_policy_l2(struct net_device *dev,
                                        struct neighbour *neigh, bool is_ipv6,
                                        int count)
{
        return (neigh->ha[5] ^ dev->dev_addr[5]) % count;
}

static int toe_bond_xmit_hash_policy_l23(struct net_device *dev,
                                         struct neighbour *neigh, __u32 saddr,
                                         __u32 daddr, __be32 *s, __be32 *d,
                                         int count, bool is_ipv6)
{
        u32 hash;

        hash = ((neigh->ha[5] ^ dev->dev_addr[5]) ^
                (is_ipv6 ? ETH_P_IPV6 : ETH_P_IP)) % count;

        if (is_ipv6)
                hash ^= (__force __be32)ipv6_addr_hash((const struct in6_addr *)s) ^
                        (__force __be32)ipv6_addr_hash((const struct in6_addr *)d);
        else
                hash ^= (__force u32)daddr ^ (__force u32)saddr;
        hash ^= (hash >> 16);
        hash ^= (hash >> 8);

        return hash % count;
}

static int toe_bond_xmit_hash_policy_l34(struct net_device *dev,
                                         struct neighbour *neigh, __u32 saddr,
                                         __u32 daddr, __u16 sport, __u16 dport,
                                         __be32 *s, __be32 *d, int count,
                                         bool is_ipv6, u16 l4_prot)
{
        u32 hash;

        hash = (__force u32)((sport << 16) | dport);
        if (is_ipv6)
                hash ^= (__force __be32)ipv6_addr_hash((const struct in6_addr *)s) ^
                        (__force __be32)ipv6_addr_hash((const struct in6_addr *)d);
        else
                hash ^= (__force u32)daddr ^ (__force u32)saddr;
        hash ^= (hash >> 16);
        hash ^= (hash >> 8);

        return hash % count;

}

int toe_bond_get_hash(struct toe_hash_params *hash_params, int xmit_policy,
                      int count)
{
        switch (xmit_policy) {
        case BOND_XMIT_POLICY_LAYER23:
                return toe_bond_xmit_hash_policy_l23(hash_params->dev,
                                                     hash_params->neigh,
                                                     hash_params->saddr,
                                                     hash_params->daddr,
                                                     hash_params->s,
                                                     hash_params->d,
                                                     count, hash_params->is_ipv6);
        case BOND_XMIT_POLICY_LAYER34:
                return toe_bond_xmit_hash_policy_l34(hash_params->dev,
                                                     hash_params->neigh,
                                                     hash_params->saddr,
                                                     hash_params->daddr,
                                                     hash_params->sport,
                                                     hash_params->dport,
                                                     hash_params->s,
                                                     hash_params->d,
                                                     count, hash_params->is_ipv6,
                                                     hash_params->l4_prot);
        case BOND_XMIT_POLICY_LAYER2:
        default:
                return toe_bond_xmit_hash_policy_l2(hash_params->dev,
                                                    hash_params->neigh,
                                                    hash_params->is_ipv6,
                                                    count);
        }
}
EXPORT_SYMBOL(toe_bond_get_hash);
