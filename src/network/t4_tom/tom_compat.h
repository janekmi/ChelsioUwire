/*
 * Copyright (C) 2003-2015 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com),
 *	      Divy Le Ray (divy@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __TOM_COMPAT_H
#define __TOM_COMPAT_H

#include <linux/version.h>

/*
 * Pull in either Linux 3.0 or earlier compatibility definitions.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
#include "tom_compat_3_0.h"
#else
#include "tom_compat_2_6.h"
#endif

#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#endif

#if !defined(NEW_SKB_OFFSET)
static inline void skb_reset_transport_header(struct sk_buff *skb)
{
	skb->h.raw = skb->data;
}

#if !defined(T4_TCP_HDR)
static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
	return skb->h.th;
}
#endif
#endif

#if !defined(SEC_INET_CONN_REQUEST)
static inline int security_inet_conn_request(struct sock *sk,
					     struct sk_buff *skb,
					     struct request_sock *req)
{
	return 0;
}
#endif

#if defined(OLD_OFFLOAD_H)
/*
 * Extended 'struct proto' with additional members used by offloaded
 * connections.
 */
struct sk_ofld_proto {
        struct proto proto;    /* keep this first */
        int (*read_sock)(struct sock *sk, read_descriptor_t *desc,
                         sk_read_actor_t recv_actor);
};

#if defined(CONFIG_TCP_OFFLOAD_MODULE)
extern int  install_special_data_ready(struct sock *sk);
extern void restore_special_data_ready(struct sock *sk);
#else
static inline int install_special_data_ready(struct sock *sk) { return 0; }
static inline void restore_special_data_ready(struct sock *sk) {}
#endif

#if defined(CONFIG_DEBUG_RODATA) && defined(CONFIG_TCP_OFFLOAD_MODULE)
extern void offload_socket_ops(struct sock *sk);
extern void restore_socket_ops(struct sock *sk);
#else
static inline void offload_socket_ops(struct sock *sk) {}
static inline void restore_socket_ops(struct sock *sk) {}
#endif

#endif

#if defined(DEACTIVATE_OFFLOAD)
struct toedev;
static inline int deactivate_offload(struct toedev *dev)
{
        return -1;
}
#endif

#if defined(CONFIG_KPROBES) && defined(KPROBES_SYMBOL_NAME)
#define KPROBES_KALLSYMS
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#define TUNABLE_INT_CTL_NAME(name) (TOE_CONF_ ## name)
#define TUNABLE_INT_RANGE_CTL_NAME(name) (TOE_CONF_ ## name)
#define TOM_INSTANCE_DIR_CTL_NAME 1
#define ROOT_DIR_CTL_NAME CTL_TOE
#else
#define TUNABLE_INT_CTL_NAME(name) CTL_UNNUMBERED
#define TUNABLE_INT_RANGE_CTL_NAME(name) CTL_UNNUMBERED
#define TOM_INSTANCE_DIR_CTL_NAME CTL_UNNUMBERED
#define ROOT_DIR_CTL_NAME CTL_UNNUMBERED
#endif

#if defined(PPC64_TLB_BATCH_NR)
static inline void flush_tlb_mm_p(struct mm_struct *mm)
{
}

static inline void flush_tlb_page_p(struct vm_area_struct *vma,
				  unsigned long vmaddr)
{
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#define SET_PROC_NODE_OWNER(_p, _owner) \
	do { (_p)->owner = (_owner); } while (0)
#else
#define SET_PROC_NODE_OWNER(_p, _owner) \
	do { } while (0)
#endif

#if !defined(INET_PREFIX)
#define inet_daddr daddr
#define inet_rcv_saddr rcv_saddr
#define inet_dport dport
#define inet_saddr saddr
#define inet_sport sport
#define inet_num num
#define inet_id id
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)

static inline wait_queue_head_t *sk_sleep(struct sock *sk)
{
	return sk->sk_sleep;
}

static inline bool sk_has_sleepers(struct sock *sk)
{
	smp_mb();
	return sk->sk_sleep && waitqueue_active(sk->sk_sleep);
}

#else

static inline bool sk_has_sleepers(struct sock *sk)
{
	/* wq_has_sleeper() has smp_mb() in it ... */
	return wq_has_sleeper(sk->sk_wq);
}

#endif

static inline void sk_wakeup_sleepers(struct sock *sk, bool interruptable)
{
	if (sk_has_sleepers(sk)) {
		if (interruptable)
			wake_up_interruptible(sk_sleep(sk));
		else
			wake_up_all(sk_sleep(sk));
	}
}

static inline void t4_set_req_port(struct request_sock *oreq,
				   __be16 source, __be16 dest)
{
	inet_rsk(oreq)->ir_rmt_port = source;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	inet_rsk(oreq)->ir_num = dest;
#else
	inet_rsk(oreq)->ir_num = ntohs(dest);
#endif
}

static inline __be16 t4_get_req_lport(struct request_sock *oreq)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	return inet_rsk(oreq)->ir_num;
#else
	return htons(inet_rsk(oreq)->ir_num);
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
typedef int socklen_t;
#else
typedef unsigned int socklen_t;
#endif

#if !defined(INET_PREFIX)
#define inet_daddr daddr
#define inet_rcv_saddr rcv_saddr
#define inet_dport dport
#define inet_saddr saddr
#define inet_sport sport
#define inet_num num
#define inet_id id
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
static inline void __sk_add_backlog(struct sock *sk, struct sk_buff *skb)
{
	sk_add_backlog(sk, skb);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
static inline void t4_tcp_parse_options(const struct sk_buff *skb,
					struct tcp_options_received *opt_rx,
					u8 **hvpp, int estab)
{
	tcp_parse_options(skb, opt_rx, estab);
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static inline void t4_tcp_parse_options(const struct sk_buff *skb,
					struct tcp_options_received *opt_rx,
					u8 **hvpp, int estab)
{
	tcp_parse_options(skb, opt_rx, (const u8 **)hvpp, estab, NULL);
}
#else
static inline void t4_tcp_parse_options(const struct sk_buff *skb,
					struct tcp_options_received *opt_rx,
					u8 **hvpp, int estab)
{
	tcp_parse_options(skb, opt_rx, estab, NULL);
}
#endif

#ifndef NIPQUAD
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#endif

#ifndef NIPQUAD_FMT
#define NIPQUAD_FMT "%u.%u.%u.%u"
#endif

#ifndef VLAN_PRIO_MASK
#define VLAN_PRIO_MASK          0xe000
#endif
#ifndef VLAN_PRIO_SHIFT
#define VLAN_PRIO_SHIFT         13
#endif

static inline struct rtattr *
__rta_reserve(struct sk_buff *skb, int attrtype, int attrlen)
{
	struct rtattr *rta;
	int size = RTA_LENGTH(attrlen);

	rta = (struct rtattr*)skb_put(skb, RTA_ALIGN(size));
	rta->rta_type = attrtype;
	rta->rta_len = size;
	memset(RTA_DATA(rta) + attrlen, 0, RTA_ALIGN(size) - size);
	return rta;
}

#define __RTA_PUT(skb, attrtype, attrlen) \
({     if (unlikely(skb_tailroom(skb) < (int)RTA_SPACE(attrlen))) \
               goto rtattr_failure; \
       __rta_reserve(skb, attrtype, attrlen); })

/*
 * In Linux 3.1 dst->neighbour was removed and we now need to use the function
 * dst_neigh_lookup() which takes a reference on the neighbour.  These
 * compatibility routines encode that dependency.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
static inline struct neighbour *t4_dst_neigh_lookup(const struct dst_entry *dst,
						    const void *daddr)
{
	return dst->neighbour;
}

static inline void t4_dst_neigh_release(struct neighbour *neigh)
{
}
#else
static inline struct neighbour *t4_dst_neigh_lookup(const struct dst_entry *dst,
						    const void *daddr)
{
	return dst_neigh_lookup(dst, daddr);
}

static inline void t4_dst_neigh_release(struct neighbour *neigh)
{
	neigh_release(neigh);
}
#endif

#if defined(CONFIG_T4_ZCOPY_HUGEPAGES) && defined(CONFIG_HUGETLB_PAGE)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
/*
 * Fake out the few Huge Page State elements that we need for kernels prior to
 * 2.6.27 where this was introduced.  Before that, only a single compile-time
 * Huge Page Size was supported.
 */
struct hstate {
	int dummy;
};
struct vm_area_struct;

static inline struct hstate *hstate_vma(struct vm_area_struct *vma)
{
	return NULL;
}

static inline unsigned long huge_page_size(struct hstate *h)
{
	return HPAGE_SIZE;
}
#endif /* Linux < 2.6.27 */
#endif /* CONFIG_T4_ZCOPY_HUGEPAGES && CONFIG_HUGETLB_PAGE */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
#define sk_sendmessage_offset(sk) ((sk)->sk_sndmsg_off)
#define sk_sendmessage_page(sk)  ((sk)->sk_sndmsg_page)
#else
#define sk_sendmessage_offset(sk)  ((sk)->sk_frag.offset)
#define sk_sendmessage_page(sk)  ((sk)->sk_frag.page)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0)
#define ip6_datagram_send_ctl datagram_send_ctl
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
static inline void ip6_flow_hdr(struct ipv6hdr *hdr, unsigned int tclass,
				__be32 flowlabel)
{
	*(__be32 *)hdr = htonl(0x60000000 | (tclass << 20)) | flowlabel;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
static inline struct sk_buff *t4_vlan_insert_tag(struct sk_buff *skb, __be16 vlan_proto,
		u16 vlan_tci)
{
	return vlan_put_tag(skb, vlan_tci);
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static inline struct sk_buff *t4_vlan_insert_tag(struct sk_buff *skb, __be16 vlan_proto,
						 u16 vlan_tci)
{
	return vlan_insert_tag(skb, vlan_tci);
}
#else
static inline struct sk_buff *t4_vlan_insert_tag(struct sk_buff *skb, __be16 vlan_proto,
						 u16 vlan_tci)
{
	return vlan_insert_tag(skb, vlan_proto, vlan_tci);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
#define ip6_dst_lookup_flow_compat(__sk, __fl6, __final_dst, __can_sleep) \
	ip6_dst_lookup_flow(__sk, __fl6, __final_dst, __can_sleep)
#define ip6_sk_dst_lookup_flow_compat(__sk, __fl6, __final_dst, __can_sleep) \
	ip6_sk_dst_lookup_flow(__sk, __fl6, __final_dst, __can_sleep)
#else
#define ip6_dst_lookup_flow_compat(__sk, __fl6, __final_dst, __can_sleep) \
	ip6_dst_lookup_flow(__sk, __fl6, __final_dst)
#define ip6_sk_dst_lookup_flow_compat(__sk, __fl6, __final_dst, __can_sleep) \
	ip6_sk_dst_lookup_flow(__sk, __fl6, __final_dst)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
#define net_random()		prandom_u32()
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
#define FLOWI_FLAG_CAN_SLEEP	0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0)
#define sk_data_ready_compat(__sk, __bytes) \
	(__sk)->sk_data_ready(__sk, __bytes)
#else
#define sk_data_ready_compat(__sk, __bytes) \
	(__sk)->sk_data_ready(__sk)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0)
#define srtt_us srtt
#endif

/*
 * The story of sk_filter_charge()/sk_filter_uncharge() is long and taudry.
 * Older kernels used to make them available and then intermediate kernels hid
 * sk_filter_uncharge() (so we used sk_filter_release() possibly incorrectly).
 * Finally in 3.15 they got hidden completely so now we need to get pointers
 * to them in the kernel namelist ...
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0)

#if !defined(SK_FILTER_UNCHARGE)
#define sk_filter_uncharge sk_filter_release
#endif

#define sk_filter_charge_compat(__sk, __fp) sk_filter_charge(__sk, __fp)
#define sk_filter_uncharge_compat(__sk, __fp) sk_filter_uncharge(__sk, __fp)

#else

extern void (*sk_filter_charge_p)(struct sock *, struct sk_filter *);
extern void (*sk_filter_uncharge_p)(struct sock *, struct sk_filter *);

#define sk_filter_charge_compat(__sk, __fp) sk_filter_charge_p(__sk, __fp)
#define sk_filter_uncharge_compat(__sk, __fp) sk_filter_uncharge_p(__sk, __fp)

#endif

/*
 * A little complicated here.  The Bond Slave AD Information used to be an
 * embedded structure within the (struct slave) and is now a pointer to
 * a separately allocated structure.  So SLAVE_AD_INFO() used to be a
 * reference to that embedded structure and we'd see uses of code like
 *
 *     SLAVE_AD_INFO(slave).port
 *
 * but these now need to be
 *
 *     SLAVE_AD_INFO(slave)->port
 *
 * So we give ourselves a compatibility definition which work more like the
 * new one.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
#define SLAVE_AD_INFO_COMPAT(__slave) \
	(&SLAVE_AD_INFO(__slave))
#else
#define SLAVE_AD_INFO_COMPAT(__slave) \
	SLAVE_AD_INFO(__slave)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
#define ignore_df local_df
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
#define inet6_reqsk_alloc inet_reqsk_alloc
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
#define module_param_unsafe module_param
#endif

extern struct sk_ofld_proto t4_tcp_prot;
extern struct sk_ofld_proto t4_tcp_v6_prot;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,64)
static inline void t4_inet_twsk_purge(struct inet_hashinfo *hashinfo,
			struct inet_timewait_death_row *twdr, int family)
{
	struct inet_timewait_sock *tw;
	struct sock *sk;
	struct hlist_nulls_node *node;
	unsigned int slot;

	for (slot = 0; slot <= hashinfo->ehash_mask; slot++) {
		struct inet_ehash_bucket *head = &hashinfo->ehash[slot];
restart_rcu:
		cond_resched();
		rcu_read_lock();
restart:
		sk_nulls_for_each_rcu(sk, node, &head->chain) {
			if (sk->sk_state != TCP_TIME_WAIT)
				continue;
			if ((sk->sk_family == AF_INET) && (sk->sk_prot != &t4_tcp_prot.proto))
				continue;
#if defined(CONFIG_TCPV6_OFFLOAD)
			if ((sk->sk_family == AF_INET6) && (sk->sk_prot != &t4_tcp_v6_prot.proto))
				continue;
#endif

			tw = inet_twsk(sk);
			if ((tw->tw_family != family) ||
				atomic_read(&twsk_net(tw)->count))
				continue;

			if (unlikely(!atomic_inc_not_zero(&tw->tw_refcnt)))
				continue;

			if (unlikely((tw->tw_family != family) ||
				atomic_read(&twsk_net(tw)->count))) {
				inet_twsk_put(tw);
				goto restart;
			}

			rcu_read_unlock();
			local_bh_disable();
			inet_twsk_deschedule(tw);
			local_bh_enable();
			inet_twsk_put(tw);
			goto restart_rcu;
		}
		/* If the nulls value we got at the end of this lookup is
		 * not the expected one, we must restart lookup.
		 * We probably met an item that was moved to another chain.
		*/
		if (get_nulls_value(node) != slot)
			goto restart;
		rcu_read_unlock();
	}
}
#else
static inline void t4_inet_twsk_purge(struct inet_hashinfo *hashinfo,
                        struct inet_timewait_death_row *twdr, int family) {}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
static inline struct sk_buff *skb_peek_next(struct sk_buff *skb,
		const struct sk_buff_head *list_)
{
	struct sk_buff *next = skb->next;
	if (next == (struct sk_buff *)list_)
		next = NULL;
	return next;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0) && \
	LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
#define bpf_prog_alloc(__size, __gfp) \
	kzalloc(__size, __gfp)
#define bpf_prog_free(__fp) \
	kfree(__fp)
#endif

#endif /* __TOM_COMPAT_H */
