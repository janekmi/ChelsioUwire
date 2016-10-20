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
 * $SUPPORTED KERNEL 3.5$
 */

#include <net/tcp.h>
#include <linux/pkt_sched.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include "defs.h"
#include <asm/tlbflush.h>

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
static void (*flush_tlb_mm_p)(struct mm_struct *mm);
static void (*flush_tlb_page_p)(struct vm_area_struct *vma,
				unsigned long va);
static __u32 (*secure_tcp_sequence_number_p)(__be32 saddr,
			__be32 daddr, __be16 sport, __be16 dport);

void flush_tlb_mm_offload(struct mm_struct *mm);
#endif

#ifdef CONFIG_TCPV6_OFFLOAD
struct proto * tcpv6_prot_p;
#endif

void flush_tlb_page_offload(struct vm_area_struct *vma, unsigned long addr)
{
#if defined(CONFIG_SMP) && !defined(PPC64_TLB_BATCH_NR)
	flush_tlb_page_p(vma, addr);
#endif
}

int sysctl_tcp_window_scaling = 1;
int sysctl_tcp_adv_win_scale  = 2;

#define ECN_OR_COST(class)	TC_PRIO_##class

const __u8 ip_tos2prio[16] = {
	TC_PRIO_BESTEFFORT,
	ECN_OR_COST(FILLER),
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

/* VJ's idea. Save last timestamp seen from this destination
 * and hold it at least for normal timewait interval to use for duplicate
 * segment detection in subsequent connections, before they enter synchronized
 * state.
 */

static bool tcp_remember_stamp(struct sock *sk)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_peer *peer;
	bool release_it;

	peer = icsk->icsk_af_ops->get_peer(sk, &release_it);
	if (peer) {
		if ((s32)(peer->tcp_ts - tp->rx_opt.ts_recent) <= 0 ||
		    ((u32)get_seconds() - peer->tcp_ts_stamp > TCP_PAWS_MSL &&
		     peer->tcp_ts_stamp <= (u32)tp->rx_opt.ts_recent_stamp)) {
			peer->tcp_ts_stamp = (u32)tp->rx_opt.ts_recent_stamp;
			peer->tcp_ts = tp->rx_opt.ts_recent;
		}
		if (release_it)
			inet_putpeer(peer);
		return true;
	}

	return false;
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

		tw->tw_transparent	= inet_sk(sk)->transparent;
		tw->tw_rcv_wscale	= tp->rx_opt.rcv_wscale;
		tcptw->tw_rcv_nxt	= tp->rcv_nxt;
		tcptw->tw_snd_nxt	= tp->snd_nxt;
		tcptw->tw_rcv_wnd	= tcp_receive_window(tp);
		tcptw->tw_ts_recent	= tp->rx_opt.ts_recent;
		tcptw->tw_ts_recent_stamp = tp->rx_opt.ts_recent_stamp;

#if IS_ENABLED(CONFIG_IPV6)
		if (tw->tw_family == PF_INET6) {
			struct ipv6_pinfo *np = inet6_sk(sk);
			struct inet6_timewait_sock *tw6;

			tw->tw_ipv6_offset = inet6_tw_offset(sk->sk_prot);
			tw6 = inet6_twsk((struct sock *)tw);
			tw6->tw_v6_daddr = np->daddr;
			tw6->tw_v6_rcv_saddr = np->rcv_saddr;
			tw->tw_tclass = np->tclass;
			tw->tw_ipv6only = np->ipv6only;
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
				if (tcptw->tw_md5_key && tcp_alloc_md5sig_pool(sk) == NULL)
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

void flush_tlb_mm_offload(struct mm_struct *mm)
{
#if defined(CONFIG_SMP) && !defined(PPC64_TLB_BATCH_NR)
	if (flush_tlb_mm_p)
		flush_tlb_mm_p(mm);
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
	flush_tlb_mm_p = (void *)kallsyms_lookup_name("flush_tlb_mm");
        if (!flush_tlb_mm_p) {
                printk(KERN_ERR "Could not locate flush_tlb_mm");
                return -1;
        }

	flush_tlb_page_p = (void *)kallsyms_lookup_name("flush_tlb_page");
        if (!flush_tlb_page_p) {
                printk(KERN_ERR "Could not locate flush_tlb_page");
                return -1;
        }

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
#ifdef CONFIG_TCPV6_OFFLOAD
	tcpv6_prot_p = (void *)kallsyms_lookup_name("tcpv6_prot");
	if (!tcpv6_prot_p) {
		printk(KERN_ERR "Could not locate tcpv6_prot");
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
#endif
	return 0;
}
