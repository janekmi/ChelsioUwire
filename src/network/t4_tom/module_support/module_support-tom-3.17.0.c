/*
 * This file contains pieces of the Linux TCP/IP stack needed for modular
 * TOE support.
 *
 * Copyright (C) 2006-2009 Chelsio Communications.  All rights reserved.
 * See the corresponding files in the Linux tree for copyrights of the
 * original Linux code a lot of this file is based on.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/* The following tags are used by the out-of-kernel Makefile to identify
 * supported kernel versions if a module_support-<kver> file is not found.
 * Do not remove these tags.
 * $SUPPORTED KERNEL 3.17$
 * $SUPPORTED KERNEL 3.18$
 */

#include <net/tcp.h>
#include <linux/pkt_sched.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include "defs.h"
#include <asm/tlbflush.h>
#include <linux/hash.h>

#if defined(CONFIG_PPC64)
static void (*hpte_need_flush_p)(struct mm_struct *mm, unsigned long addr,
		pte_t *ptep, unsigned long pte, int huge);
static struct page *(*pmd_page_p)(pmd_t pmd);

void hpte_need_flush_offload(struct mm_struct *mm, unsigned long addr,
		pte_t *ptep, unsigned long pte, int huge)
{
	if (hpte_need_flush_p)
		hpte_need_flush_p(mm, addr, ptep, pte, huge);
}

struct page *pmd_page_offload(pmd_t pmd)
{
	struct page *page = NULL;
	if (pmd_page_p)
		page = pmd_page_p(pmd);
	return page;
}
#endif

static void (*tcp_update_metrics_p)(struct sock *sk);

#if defined(CONFIG_SMP) && !defined(PPC64_TLB_BATCH_NR)
#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
static void (*flush_tlb_mm_range_p)(struct mm_struct *mm,
           unsigned long start, unsigned long end, unsigned long vmflag);
static void (*flush_tlb_page_p)(struct vm_area_struct *vma,
				unsigned long va);
#endif
static __u32 (*secure_tcp_sequence_number_p)(__be32 saddr,
			__be32 daddr, __be16 sport, __be16 dport);

void flush_tlb_mm_offload(struct mm_struct *mm);
#endif

#ifdef CONFIG_UDPV6_OFFLOAD
void (*ipv6_local_rxpmtu_p)(struct sock *sk, struct flowi6 *fl6, u32 mtu);
void (*ipv6_local_error_p)(struct sock *sk, int err, struct flowi6 *fl6,
			   u32 info);
void (*ipv6_select_ident_p)(struct frag_hdr *fhdr, struct rt6_info *rt);
void (*ipv6_push_frag_opts_p)(struct sk_buff *skb, struct ipv6_txoptions *opt,
			      u8 *proto);
struct proto *udpv6_prot_p;
#endif /* CONFIG_UDPV6_OFFLOAD */

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
struct proto * tcpv6_prot_p;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0)
struct tcp_congestion_ops *tcp_reno_p;
#endif

void (*sk_filter_charge_p)(struct sock *, struct sk_filter *);
void (*sk_filter_uncharge_p)(struct sock *, struct sk_filter *);

void flush_tlb_page_offload(struct vm_area_struct *vma, unsigned long addr)
{
#if defined(CONFIG_SMP) && !defined(PPC64_TLB_BATCH_NR)
#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
	flush_tlb_page_p(vma, addr);
#endif
#endif
}

int sysctl_tcp_window_scaling = 1;
int sysctl_tcp_adv_win_scale  = 2;

#define ECN_OR_COST(class)	TC_PRIO_##class

const __u8 ip_tos2prio[16] = {
	TC_PRIO_BESTEFFORT,
	ECN_OR_COST(BESTEFFORT),
	TC_PRIO_BESTEFFORT,
	ECN_OR_COST(BESTEFFORT),
	TC_PRIO_BULK,
	ECN_OR_COST(BULK),
	TC_PRIO_BULK,
	ECN_OR_COST(BULK),
	TC_PRIO_INTERACTIVE,
	ECN_OR_COST(INTERACTIVE),
	TC_PRIO_INTERACTIVE,
	ECN_OR_COST(INTERACTIVE),
	TC_PRIO_INTERACTIVE_BULK,
	ECN_OR_COST(INTERACTIVE_BULK),
	TC_PRIO_INTERACTIVE_BULK,
	ECN_OR_COST(INTERACTIVE_BULK)
};

struct tcpm_hash_bucket {
	struct tcp_metrics_block __rcu  *chain;
};

enum tcp_metric_index {
	TCP_METRIC_RTT,
	TCP_METRIC_RTTVAR,
	TCP_METRIC_SSTHRESH,
	TCP_METRIC_CWND,
	TCP_METRIC_REORDERING,

	TCP_METRIC_RTT_US,	/* in usec units */
	TCP_METRIC_RTTVAR_US,	/* in usec units */

	/* Always last.  */
	__TCP_METRIC_MAX,
};

#define TCP_METRIC_MAX	(__TCP_METRIC_MAX - 1)

/* TCP_METRIC_MAX includes 2 extra fields for userspace compatibility
 * Kernel only stores RTT and RTTVAR in usec resolution
 */
#define TCP_METRIC_MAX_KERNEL (TCP_METRIC_MAX - 2)

struct tcp_fastopen_metrics {
	u16	mss;
	u16	syn_loss:10;		/* Recurring Fast Open SYN losses */
	unsigned long	last_syn_loss;	/* Last Fast Open SYN loss */
	struct	tcp_fastopen_cookie	cookie;
};

struct tcp_metrics_block {
	struct tcp_metrics_block __rcu	*tcpm_next;
	struct inetpeer_addr		tcpm_saddr;
	struct inetpeer_addr		tcpm_daddr;
	unsigned long			tcpm_stamp;
	u32				tcpm_ts;
	u32				tcpm_ts_stamp;
	u32				tcpm_lock;
	u32				tcpm_vals[TCP_METRIC_MAX_KERNEL + 1];
	struct tcp_fastopen_metrics	tcpm_fastopen;

	struct rcu_head			rcu_head;
};

static bool addr_same(const struct inetpeer_addr *a,
		      const struct inetpeer_addr *b)
{
	const struct in6_addr *a6, *b6;

	if (a->family != b->family)
		return false;
	if (a->family == AF_INET)
		return a->addr.a4 == b->addr.a4;

	a6 = (const struct in6_addr *) &a->addr.a6[0];
	b6 = (const struct in6_addr *) &b->addr.a6[0];

	return ipv6_addr_equal(a6, b6);
}

#define TCP_METRICS_RECLAIM_DEPTH	5
#define TCP_METRICS_RECLAIM_PTR		(struct tcp_metrics_block *) 0x1UL

static struct tcp_metrics_block *tcp_get_encode(struct tcp_metrics_block *tm, int depth)
{
	if (tm)
		return tm;
	if (depth > TCP_METRICS_RECLAIM_DEPTH)
		return TCP_METRICS_RECLAIM_PTR;
	return NULL;
}

static struct tcp_metrics_block *__tcp_get_metrics(const struct inetpeer_addr *saddr,
						   const struct inetpeer_addr *daddr,
						   struct net *net, unsigned int hash)
{
	struct tcp_metrics_block *tm;
	int depth = 0;

	for (tm = rcu_dereference(net->ipv4.tcp_metrics_hash[hash].chain); tm;
	     tm = rcu_dereference(tm->tcpm_next)) {
		if (addr_same(&tm->tcpm_saddr, saddr) &&
		    addr_same(&tm->tcpm_daddr, daddr))
			break;
		depth++;
	}
	return tcp_get_encode(tm, depth);
}

static DEFINE_SPINLOCK(tcp_metrics_lock);

static void tcpm_suck_dst(struct tcp_metrics_block *tm,
			  const struct dst_entry *dst,
			  bool fastopen_clear)
{
	u32 msval;
	u32 val;

	tm->tcpm_stamp = jiffies;

	val = 0;
	if (dst_metric_locked(dst, RTAX_RTT))
		val |= 1 << TCP_METRIC_RTT;
	if (dst_metric_locked(dst, RTAX_RTTVAR))
		val |= 1 << TCP_METRIC_RTTVAR;
	if (dst_metric_locked(dst, RTAX_SSTHRESH))
		val |= 1 << TCP_METRIC_SSTHRESH;
	if (dst_metric_locked(dst, RTAX_CWND))
		val |= 1 << TCP_METRIC_CWND;
	if (dst_metric_locked(dst, RTAX_REORDERING))
		val |= 1 << TCP_METRIC_REORDERING;
	tm->tcpm_lock = val;

	msval = dst_metric_raw(dst, RTAX_RTT);
	tm->tcpm_vals[TCP_METRIC_RTT] = msval * USEC_PER_MSEC;

	msval = dst_metric_raw(dst, RTAX_RTTVAR);
	tm->tcpm_vals[TCP_METRIC_RTTVAR] = msval * USEC_PER_MSEC;
	tm->tcpm_vals[TCP_METRIC_SSTHRESH] = dst_metric_raw(dst, RTAX_SSTHRESH);
	tm->tcpm_vals[TCP_METRIC_CWND] = dst_metric_raw(dst, RTAX_CWND);
	tm->tcpm_vals[TCP_METRIC_REORDERING] = dst_metric_raw(dst, RTAX_REORDERING);
	tm->tcpm_ts = 0;
	tm->tcpm_ts_stamp = 0;
	if (fastopen_clear) {
		tm->tcpm_fastopen.mss = 0;
		tm->tcpm_fastopen.syn_loss = 0;
		tm->tcpm_fastopen.cookie.len = 0;
	}
}

#define TCP_METRICS_TIMEOUT             (60 * 60 * HZ)

static void tcpm_check_stamp(struct tcp_metrics_block *tm, struct dst_entry *dst)
{
	if (tm && unlikely(time_after(jiffies, tm->tcpm_stamp + TCP_METRICS_TIMEOUT)))
		tcpm_suck_dst(tm, dst, false);
}

static struct tcp_metrics_block *tcpm_new(struct dst_entry *dst,
					  struct inetpeer_addr *saddr,
					  struct inetpeer_addr *daddr,
					  unsigned int hash)
{
	struct tcp_metrics_block *tm;
	struct net *net;
	bool reclaim = false;

	spin_lock_bh(&tcp_metrics_lock);
	net = dev_net(dst->dev);

	/* While waiting for the spin-lock the cache might have been populated
	 * with this entry and so we have to check again.
	 */
	tm = __tcp_get_metrics(saddr, daddr, net, hash);
	if (tm == TCP_METRICS_RECLAIM_PTR) {
		reclaim = true;
		tm = NULL;
	}
	if (tm) {
		tcpm_check_stamp(tm, dst);
		goto out_unlock;
	}

	if (unlikely(reclaim)) {
		struct tcp_metrics_block *oldest;

		oldest = rcu_dereference(net->ipv4.tcp_metrics_hash[hash].chain);
		for (tm = rcu_dereference(oldest->tcpm_next); tm;
		     tm = rcu_dereference(tm->tcpm_next)) {
			if (time_before(tm->tcpm_stamp, oldest->tcpm_stamp))
				oldest = tm;
		}
		tm = oldest;
	} else {
		tm = kmalloc(sizeof(*tm), GFP_ATOMIC);
		if (!tm)
			goto out_unlock;
	}
	tm->tcpm_saddr = *saddr;
	tm->tcpm_daddr = *daddr;

	tcpm_suck_dst(tm, dst, true);

	if (likely(!reclaim)) {
		tm->tcpm_next = net->ipv4.tcp_metrics_hash[hash].chain;
		rcu_assign_pointer(net->ipv4.tcp_metrics_hash[hash].chain, tm);
	}

out_unlock:
	spin_unlock_bh(&tcp_metrics_lock);
	return tm;
}

static struct tcp_metrics_block *tcp_get_metrics(struct sock *sk,
						 struct dst_entry *dst,
						 bool create)
{
	struct tcp_metrics_block *tm;
	struct inetpeer_addr saddr, daddr;
	unsigned int hash;
	struct net *net;

	if (sk->sk_family == AF_INET) {
		saddr.family = AF_INET;
		saddr.addr.a4 = inet_sk(sk)->inet_saddr;
		daddr.family = AF_INET;
		daddr.addr.a4 = inet_sk(sk)->inet_daddr;
		hash = (__force unsigned int) daddr.addr.a4;
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (sk->sk_family == AF_INET6) {
		if (ipv6_addr_v4mapped(&sk->sk_v6_daddr)) {
			saddr.family = AF_INET;
			saddr.addr.a4 = inet_sk(sk)->inet_saddr;
			daddr.family = AF_INET;
			daddr.addr.a4 = inet_sk(sk)->inet_daddr;
			hash = (__force unsigned int) daddr.addr.a4;
		} else {
			saddr.family = AF_INET6;
			*(struct in6_addr *)saddr.addr.a6 = sk->sk_v6_rcv_saddr;
			daddr.family = AF_INET6;
			*(struct in6_addr *)daddr.addr.a6 = sk->sk_v6_daddr;
			hash = ipv6_addr_hash(&sk->sk_v6_daddr);
		}
	}
#endif
	else
		return NULL;

	net = dev_net(dst->dev);
	hash = hash_32(hash, net->ipv4.tcp_metrics_hash_log);

	tm = __tcp_get_metrics(&saddr, &daddr, net, hash);
	if (tm == TCP_METRICS_RECLAIM_PTR)
		tm = NULL;
	if (!tm && create)
		tm = tcpm_new(dst, &saddr, &daddr, hash);
	else
		tcpm_check_stamp(tm, dst);

	return tm;
}

/* VJ's idea. Save last timestamp seen from this destination and hold
 * it at least for normal timewait interval to use for duplicate
 * segment detection in subsequent connections, before they enter
 * synchronized state.
 */
bool tcp_remember_stamp(struct sock *sk)
{
	struct dst_entry *dst = __sk_dst_get(sk);
	bool ret = false;

	if (dst) {
		struct tcp_metrics_block *tm;

		rcu_read_lock();
		tm = tcp_get_metrics(sk, dst, true);
		if (tm) {
			struct tcp_sock *tp = tcp_sk(sk);

			if ((s32)(tm->tcpm_ts - tp->rx_opt.ts_recent) <= 0 ||
			    ((u32)get_seconds() - tm->tcpm_ts_stamp > TCP_PAWS_MSL &&
			     tm->tcpm_ts_stamp <= (u32)tp->rx_opt.ts_recent_stamp)) {
				tm->tcpm_ts_stamp = (u32)tp->rx_opt.ts_recent_stamp;
				tm->tcpm_ts = tp->rx_opt.ts_recent;
			}
			ret = true;
		}
		rcu_read_unlock();
	}
	return ret;
}

/*
 * Move a socket to time-wait or dead fin-wait-2 state.
 */
void tcp_time_wait(struct sock *sk, int state, int timeo)
{
	struct inet_timewait_sock *tw = NULL;
	const struct inet_connection_sock *icsk = inet_csk(sk);
	const struct tcp_sock *tp = tcp_sk(sk);
	bool recycle_ok = false;

	if (tcp_death_row.sysctl_tw_recycle && tp->rx_opt.ts_recent_stamp)
		recycle_ok = tcp_remember_stamp(sk);

	if (tcp_death_row.tw_count < tcp_death_row.sysctl_max_tw_buckets)
		tw = inet_twsk_alloc(sk, state);

	if (tw != NULL) {
		struct tcp_timewait_sock *tcptw = tcp_twsk((struct sock *)tw);
		const int rto = (icsk->icsk_rto << 2) - (icsk->icsk_rto >> 1);
		struct inet_sock *inet = inet_sk(sk);

		tw->tw_transparent	= inet->transparent;
		tw->tw_rcv_wscale	= tp->rx_opt.rcv_wscale;
		tcptw->tw_rcv_nxt	= tp->rcv_nxt;
		tcptw->tw_snd_nxt	= tp->snd_nxt;
		tcptw->tw_rcv_wnd	= tcp_receive_window(tp);
		tcptw->tw_ts_recent	= tp->rx_opt.ts_recent;
		tcptw->tw_ts_recent_stamp = tp->rx_opt.ts_recent_stamp;
		tcptw->tw_ts_offset	= tp->tsoffset;

#if IS_ENABLED(CONFIG_IPV6)
		if (tw->tw_family == PF_INET6) {
			struct ipv6_pinfo *np = inet6_sk(sk);

			tw->tw_v6_daddr = sk->sk_v6_daddr;
			tw->tw_v6_rcv_saddr = sk->sk_v6_rcv_saddr;
			tw->tw_tclass = np->tclass;
			tw->tw_flowlabel = np->flow_label >> 12;
			tw->tw_ipv6only = sk->sk_ipv6only;
		}
#endif

#ifdef CONFIG_TCP_MD5SIG
		/*
		 * The timewait bucket does not have the key DB from the
		 * sock structure. We just make a quick copy of the
		 * md5 key being used (if indeed we are using one)
		 * so the timewait ack generating code has the key.
		 */
		do {
			struct tcp_md5sig_key *key;
			tcptw->tw_md5_key = NULL;
			key = tp->af_specific->md5_lookup(sk, sk);
			if (key != NULL) {
				tcptw->tw_md5_key = kmemdup(key, sizeof(*key), GFP_ATOMIC);
				if (tcptw->tw_md5_key && !tcp_alloc_md5sig_pool())
					BUG();
			}
		} while (0);
#endif

		/* Linkage updates. */
		__inet_twsk_hashdance(tw, sk, &tcp_hashinfo);

		/* Get the TIME_WAIT timeout firing. */
		if (timeo < rto)
			timeo = rto;

		if (recycle_ok) {
			tw->tw_timeout = rto;
		} else {
			tw->tw_timeout = TCP_TIMEWAIT_LEN;
			if (state == TCP_TIME_WAIT)
				timeo = TCP_TIMEWAIT_LEN;
		}

		inet_twsk_schedule(tw, &tcp_death_row, timeo,
				   TCP_TIMEWAIT_LEN);
		inet_twsk_put(tw);
	} else {
		/* Sorry, if we're out of memory, just CLOSE this
		 * socket up.  We've got bigger problems than
		 * non-graceful socket closings.
		 */
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPTIMEWAITOVERFLOW);
	}

	tcp_update_metrics_p(sk);
	tcp_done(sk);
}

#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
#define t4_flush_tlb_mm(mm)        flush_tlb_mm_range_p(mm, 0UL, TLB_FLUSH_ALL, 0UL)
#else
#define t4_flush_tlb_mm(mm)        flush_tlb_mm(mm)
#endif

void flush_tlb_mm_offload(struct mm_struct *mm)
{
#if defined(CONFIG_SMP) && !defined(PPC64_TLB_BATCH_NR)
#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
		t4_flush_tlb_mm(mm);
#endif
#endif
}

__u32 secure_tcp_sequence_number_offload(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
#if defined(CONFIG_SMP) && !defined(PPC64_TLB_BATCH_NR)
	if (secure_tcp_sequence_number_p)
		return secure_tcp_sequence_number_p(saddr, daddr, sport, dport);
#endif
	return 0;
}

int prepare_tom_for_offload(void)
{
#if defined(CONFIG_SMP) && !defined(PPC64_TLB_BATCH_NR)
#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
	flush_tlb_mm_range_p = (void *)kallsyms_lookup_name("flush_tlb_mm_range");
        if (!flush_tlb_mm_range_p) {
                printk(KERN_ERR "Could not locate flush_tlb_mm_range");
                return -1;
        }
#endif
	flush_tlb_page_p = (void *)kallsyms_lookup_name("flush_tlb_page");
        if (!flush_tlb_page_p) {
                printk(KERN_ERR "Could not locate flush_tlb_page");
                return -1;
        }
#endif
	tcp_update_metrics_p = (void *)kallsyms_lookup_name("tcp_update_metrics");
	if (!tcp_update_metrics_p) {
		printk(KERN_ERR "Could not locate tcp_update_metrics");
		return -1;
	}

	secure_tcp_sequence_number_p = (void *)kallsyms_lookup_name("secure_tcp_sequence_number");
	if (!secure_tcp_sequence_number_p) {
		printk(KERN_ERR "Could not locate secure_tcp_sequence_number");
		return -1;
	}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0)
	tcp_reno_p = (void *)kallsyms_lookup_name("tcp_reno");
        if (!tcp_reno_p) {
                printk(KERN_ERR "Could not locate tcp_reno");
                return -1;
        }
#endif

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	tcpv6_prot_p = (void *)kallsyms_lookup_name("tcpv6_prot");
	if (!tcpv6_prot_p) {
		printk(KERN_ERR "Could not locate tcpv6_prot");
		return -1;
	}
#endif

	sk_filter_charge_p = (void *)kallsyms_lookup_name("sk_filter_charge");
	if (!sk_filter_charge_p) {
		printk(KERN_ERR "Could not locate sk_filter_charge");
		return -1;
	}

	sk_filter_uncharge_p = (void *)kallsyms_lookup_name("sk_filter_uncharge");
	if (!sk_filter_uncharge_p) {
		printk(KERN_ERR "Could not locate sk_filter_uncharge");
		return -1;
	}

#if defined(CONFIG_PPC64)
	hpte_need_flush_p = (void *)kallsyms_lookup_name("hpte_need_flush");
        if (!hpte_need_flush_p) {
                printk(KERN_ERR "Could not locate hpte_need_flush");
                return -1;
        }

	pmd_page_p = (void *)kallsyms_lookup_name("pmd_page");
	if (!pmd_page_p) {
		printk(KERN_ERR "Could not locate pmd_page");
		return -1;
	}
#endif

#ifdef CONFIG_UDPV6_OFFLOAD
	udpv6_prot_p = (void *)kallsyms_lookup_name("udpv6_prot");
	if (!udpv6_prot_p) {
		pr_err("Could not locate udpv6_prot");
		return -1;
	}

	ipv6_local_rxpmtu_p = (void *)kallsyms_lookup_name(
						"ipv6_local_rxpmtu");
	if (!ipv6_local_rxpmtu_p) {
		pr_err("Could not locate ipv6_local_rxpmtu");
		return -1;
	}

	ipv6_local_error_p = (void *)kallsyms_lookup_name("ipv6_local_error");
	if (!ipv6_local_error_p) {
		pr_err("Could not locate ipv6_local_error");
		return -1;
	}

	ipv6_select_ident_p = (void *)kallsyms_lookup_name(
						"ipv6_select_ident");
	if (!ipv6_select_ident_p) {
		pr_err("Could not locate ipv6_select_ident");
		return -1;
	}

	ipv6_push_frag_opts_p = (void *)kallsyms_lookup_name(
						"ipv6_push_frag_opts");
	if (!ipv6_push_frag_opts_p) {
		pr_err("Could not locate ipv6_push_frag_opts");
		return -1;
	}
#endif /* CONFIG_UDPV6_OFFLOAD */

	return 0;
}
