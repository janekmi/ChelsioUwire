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

#ifndef __TOM_COMPAT_2_6_H
#define __TOM_COMPAT_2_6_H

#include <linux/version.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
#include <linux/hugetlb.h>

/* 2.6.9 */
#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,9)

#ifndef ATOMIC_ADD_RETURN
#if defined(CONFIG_X86_64)
static __inline__ int atomic_add_return(int i, atomic_t *v)
{
	int __i = i;
	__asm__ __volatile__(
		LOCK "xaddl %0, %1;"
		:"=r"(i)
		:"m"(v->counter), "0"(i));
	return i + __i;
} 

#elif defined(CONFIG_X86)
static __inline__ int atomic_add_return(int i, atomic_t *v)
{
	int __i;
#ifdef CONFIG_M386
	if(unlikely(boot_cpu_data.x86==3))
		goto no_xadd;
#endif
	/* Modern 486+ processor */
	__i = i;
	__asm__ __volatile__(
		LOCK "xaddl %0, %1;"
		:"=r"(i)
		:"m"(v->counter), "0"(i));
	return i + __i;

#ifdef CONFIG_M386
no_xadd: /* Legacy 386 processor */
	local_irq_disable();
	__i = atomic_read(v);
	atomic_set(v, i + __i);
	local_irq_enable();
	return i + __i;
#endif
} 

#elif defined(CONFIG_IA64)
#define atomic_add_return(i,v)						\
({									\
	int __ia64_aar_i = (i);						\
	(__builtin_constant_p(i)					\
	 && (   (__ia64_aar_i ==  1) || (__ia64_aar_i ==   4)		\
	     || (__ia64_aar_i ==  8) || (__ia64_aar_i ==  16)		\
	     || (__ia64_aar_i == -1) || (__ia64_aar_i ==  -4)		\
	     || (__ia64_aar_i == -8) || (__ia64_aar_i == -16)))		\
		? ia64_fetch_and_add(__ia64_aar_i, &(v)->counter)	\
		: ia64_atomic_add(__ia64_aar_i, v);			\
})
#endif
#endif /* ATOMIC_ADD_RETURN */

#define ROUTE_REQ

#define dst_mtu(dst) dst_metric(dst, RTAX_MTU)

#define tcp_sock tcp_opt
#define inet_sock inet_opt
#define request_sock open_request

#define inet_csk(sk) tcp_sk(sk)
#define inet_csk_destroy_sock(sk) tcp_destroy_sock(sk)
#define inet_csk_route_req(lsk, oreq) tcp_v4_route_req(lsk, oreq)

#define inet_connection_sock tcp_opt
#define icsk_bind_hash bind_hash
#define icsk_af_ops af_specific
#define icsk_ack ack
#define icsk_pmtu_cookie pmtu_cookie
#define inet_csk_reqsk_queue_removed tcp_synq_removed
#define inet_csk_delete_keepalive_timer tcp_delete_keepalive_timer
#define inet_csk_reqsk_queue_is_full tcp_synq_is_full
#define inet_csk_reqsk_queue_add tcp_acceptq_queue
#define icsk_retransmit_timer retransmit_timer
#define inet_csk_reqsk_queue_added(sk, timeo) tcp_synq_added(sk)

#define __reqsk_free tcp_openreq_fastfree
#define tcp_rsk
#define inet_rsk

#define t4_inet_inherit_port(p_hashinfo, lsk, newsk) tcp_inherit_port(lsk, newsk)
#define t4_inet_put_port(a, sk) tcp_put_port(sk)

#define ACCEPT_QUEUE(sk) (&(tcp_sk(sk)->accept_queue))

#define MSS_CLAMP(tp) ((tp)->mss_clamp)
#define SND_WSCALE(tp) ((tp)->snd_wscale)
#define RCV_WSCALE(tp) ((tp)->rcv_wscale)
#define USER_MSS(tp) ((tp)->user_mss)
#define TS_RECENT_STAMP(tp) ((tp)->ts_recent_stamp)
#define WSCALE_OK(tp) ((tp)->wscale_ok)
#define TSTAMP_OK(tp) ((tp)->tstamp_ok)
#define SACK_OK(tp) ((tp)->sack_ok)

#ifdef CONFIG_CHELSIO_T4_OFFLOAD_MODULE
extern atomic_t tcp_orphan_count_offload;
extern int ip_route_output_flow_offload(struct rtable **rp,
					struct flowi *flp,
					struct sock *sk, int flags);
#define ip_route_output_flow ip_route_output_flow_offload
extern void flush_tlb_page_offload(struct vm_area_struct *vma, unsigned long addr);
#define INC_ORPHAN_COUNT(sk) (atomic_inc(&tcp_orphan_count_offload))
#else
#define INC_ORPHAN_COUNT(sk) (atomic_inc(&tcp_orphan_count))
#endif

#define SOCK_QUEUE_SHRUNK SOCK_TIMESTAMP

/* Added TCP socket option */
/* XXX Divy. Will we support it when the OS does not ? */

#define __read_mostly
struct request_sock_ops {
	int		family;
	int		obj_size;
};

/* Inet diag stuff. Added for compilation only */
enum {
	INET_DIAG_NONE,
	INET_DIAG_MEMINFO,
	INET_DIAG_INFO,
	INET_DIAG_VEGASINFO,
	INET_DIAG_CONG,
};
#define INET_DIAG_MAX INET_DIAG_CONG

#define rsk_ops class
#define RSK_OPS(rsk) (struct or_calltable *)(rsk)
static inline void t4_init_rsk_ops(struct proto *t4_tcp_prot,
				   struct request_sock_ops *t4_tcp_ops,
				   struct proto *tcp_prot, int family)
{}
static inline void t4_init_rsk6_ops(struct proto *t4_tcp_prot,
                                   struct request_sock_ops *t4_tcp_ops,
                                   struct proto *tcp_prot, int family)
{}

/* TCP congestion stuff. Added for compilation only */
#define TCP_CONGESTION	13	/* Congestion control algorithm */
#define TCP_CA_NAME_MAX	16

struct tcp_congestion_ops {
	void (*get_info)(struct sock *sk, u32 ext, struct sk_buff *skb);

	char 		name[TCP_CA_NAME_MAX];
	struct module 	*owner;
};

static inline void t4_set_ca_ops(struct sock *sk,
				 struct tcp_congestion_ops *t_ops)
{}

static inline struct open_request *reqsk_alloc(struct request_sock_ops *rsk)
{
	struct open_request *oreq = tcp_openreq_alloc();

	if (oreq)
		oreq->class = (struct or_calltable *)rsk;

	return oreq;
}

static inline void t4_set_req_addr(struct open_request *oreq,
				   __u32 local_ip, __u32 peer_ip)
{
	oreq->af.v4_req.loc_addr = local_ip;
	oreq->af.v4_req.rmt_addr = peer_ip;
}

static inline void t4_set_req_opt(struct open_request *oreq,
				  struct ip_options *ip_opt)
{
}

static inline void sk_setup_caps(struct sock *sk, struct dst_entry *dst)
{
	__sk_dst_set(sk, dst);
	tcp_v4_setup_caps(sk, dst);
}

static inline void setup_timer(struct timer_list * timer,
				void (*function)(unsigned long),
				unsigned long data)
{
	timer->function = function;
	timer->data = data;
	init_timer(timer);
}

extern int prepare_tom_for_offload(void);

#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
# define t4_ptep_set_wrprotect(mm, address, ptep) ptep_set_wrprotect(ptep)
#endif

#elif LINUX_VERSION_CODE == KERNEL_VERSION(2,6,12)

#define ROUTE_REQ

#define request_sock open_request

#define inet_csk(sk) tcp_sk(sk)

#define inet_csk(sk) tcp_sk(sk)
#define inet_csk_destroy_sock(sk) tcp_destroy_sock(sk)
#define inet_csk_route_req(lsk, oreq) tcp_v4_route_req(lsk, oreq)

#define inet_connection_sock tcp_sock
#define icsk_bind_hash bind_hash
#define icsk_af_ops af_specific
#define icsk_ack ack
#define icsk_pmtu_cookie pmtu_cookie
#define inet_csk_reqsk_queue_removed tcp_synq_removed
#define inet_csk_delete_keepalive_timer tcp_delete_keepalive_timer
#define inet_csk_reqsk_queue_is_full tcp_synq_is_full
#define inet_csk_reqsk_queue_add tcp_acceptq_queue
#define icsk_retransmit_timer retransmit_timer
#define inet_csk_reqsk_queue_added(sk, timeo) tcp_synq_added(sk)

#define ACCEPT_QUEUE(sk) (&(tcp_sk(sk)->accept_queue))

#define MSS_CLAMP(tp) ((tp)->rx_opt.mss_clamp)
#define SND_WSCALE(tp) ((tp)->rx_opt.snd_wscale)
#define RCV_WSCALE(tp) ((tp)->rx_opt.rcv_wscale)
#define USER_MSS(tp) ((tp)->rx_opt.user_mss)
#define TS_RECENT_STAMP(tp) ((tp)->rx_opt.ts_recent_stamp)
#define WSCALE_OK(tp) ((tp)->rx_opt.wscale_ok)
#define TSTAMP_OK(tp) ((tp)->rx_opt.tstamp_ok)
#define SACK_OK(tp) ((tp)->rx_opt.sack_ok)

#define __reqsk_free tcp_openreq_fastfree
#define tcp_rsk
#define inet_rsk

#define t4_inet_inherit_port(p_hashinfo, lsk, newsk) tcp_inherit_port(lsk, newsk)
#define t4_inet_put_port(a, sk) tcp_put_port(sk)

#define __read_mostly
struct request_sock_ops {
	int		family;
	int		obj_size;
};


#ifdef CONFIG_TCP_OFFLOAD_MODULE
extern atomic_t tcp_orphan_count_offload;
extern int ip_route_output_flow_offload(struct rtable **rp,
					struct flowi *flp,
					struct sock *sk, int flags);
#define ip_route_output_flow ip_route_output_flow_offload
extern void flush_tlb_page_offload(struct vm_area_struct *vma, unsigned long addr);
#define INC_ORPHAN_COUNT(sk) (atomic_inc(&tcp_orphan_count_offload))
#else
#define INC_ORPHAN_COUNT(sk) (atomic_inc(&tcp_orphan_count))
#endif

#define rsk_ops class
#define RSK_OPS(rsk) (struct or_calltable *)(rsk)
static inline void t4_init_rsk_ops(struct proto *t4_tcp_prot,
				   struct request_sock_ops *t4_tcp_ops,
				   struct proto *tcp_prot, int family)
{}
static inline void t4_init_rsk6_ops(struct proto *t4_tcp_prot,
                                   struct request_sock_ops *t4_tcp_ops,
                                   struct proto *tcp_prot, int family)
{}

/* Inet diag stuff. Added for compilation only */
enum {
	INET_DIAG_NONE,
	INET_DIAG_MEMINFO,
	INET_DIAG_INFO,
	INET_DIAG_VEGASINFO,
	INET_DIAG_CONG,
};
#define INET_DIAG_MAX INET_DIAG_CONG

/* TCP congestion stuff. Added for compilation only */
#define TCP_CONGESTION	13	/* Congestion control algorithm */
#define TCP_CA_NAME_MAX	16

struct tcp_congestion_ops {
	void (*get_info)(struct sock *sk, u32 ext, struct sk_buff *skb);

	char 		name[TCP_CA_NAME_MAX];
	struct module 	*owner;
};

static inline void t4_set_ca_ops(struct sock *sk,
				 struct tcp_congestion_ops *t_ops)
{}

static inline struct open_request *reqsk_alloc(struct request_sock_ops *rsk)
{
	struct open_request *oreq = tcp_openreq_alloc();

	if (oreq)
		oreq->class = (struct or_calltable *)rsk;

	return oreq;
}

static inline void t4_set_req_addr(struct open_request *oreq,
				   __u32 local_ip, __u32 peer_ip)
{
	oreq->af.v4_req.loc_addr = local_ip;
	oreq->af.v4_req.rmt_addr = peer_ip;
}

static inline void t4_set_req_opt(struct open_request *oreq,
				  struct ip_options *ip_opt)
{
}

static inline void sk_setup_caps(struct sock *sk, struct dst_entry *dst)
{
	__sk_dst_set(sk, dst);
	tcp_v4_setup_caps(sk, dst);
}

#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
# define t4_ptep_set_wrprotect ptep_set_wrprotect
#endif

extern int prepare_tom_for_offload(void);

/* 2.6.14 and above */
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2,6,13)

#include <linux/inet_diag.h>

#define TCP_CONGESTION_CONTROL

#define ACCEPT_QUEUE(sk) (&inet_csk(sk)->icsk_accept_queue.rskq_accept_head)

#define MSS_CLAMP(tp) ((tp)->rx_opt.mss_clamp)
#define SND_WSCALE(tp) ((tp)->rx_opt.snd_wscale)
#define RCV_WSCALE(tp) ((tp)->rx_opt.rcv_wscale)
#define USER_MSS(tp) ((tp)->rx_opt.user_mss)
#define TS_RECENT_STAMP(tp) ((tp)->rx_opt.ts_recent_stamp)
#define WSCALE_OK(tp) ((tp)->rx_opt.wscale_ok)
#define TSTAMP_OK(tp) ((tp)->rx_opt.tstamp_ok)
#define SACK_OK(tp) ((tp)->rx_opt.sack_ok)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
#define INC_ORPHAN_COUNT(sk) percpu_counter_inc((sk)->sk_prot->orphan_count)
#else
#define INC_ORPHAN_COUNT(sk) atomic_inc((sk)->sk_prot->orphan_count)
#endif

#define route_req inet_csk_route_req

#define RSK_OPS

static inline void t4_init_rsk_ops(struct proto *t4_tcp_prot,
				   struct request_sock_ops *t4_tcp_ops,
				   struct proto *tcp_prot, int family)
{
	memset(t4_tcp_ops, 0, sizeof(*t4_tcp_ops));
	t4_tcp_ops->family = family;
	t4_tcp_ops->obj_size = sizeof(struct tcp_request_sock);
	t4_tcp_ops->slab = tcp_prot->rsk_prot->slab;
	BUG_ON(!t4_tcp_ops->slab);

	t4_tcp_prot->rsk_prot = t4_tcp_ops;
}

static inline void t4_init_rsk6_ops(struct proto *t4_tcp_prot,
                                   struct request_sock_ops *t4_tcp_ops,
                                   struct proto *tcp_prot, int family)
{
        memset(t4_tcp_ops, 0, sizeof(*t4_tcp_ops));
        t4_tcp_ops->family = family;
        t4_tcp_ops->obj_size = sizeof(struct tcp6_request_sock);
        t4_tcp_ops->slab = tcp_prot->rsk_prot->slab;
	if (!t4_tcp_ops->slab)
		printk(KERN_WARNING
		       "t4_tom: IPv6 administratively disabled. "
		       "No IPv6 offload available\n");

        t4_tcp_prot->rsk_prot = t4_tcp_ops;
}

static inline void t4_set_ca_ops(struct sock *sk,
				 struct tcp_congestion_ops *t_ops)
{
	inet_csk(sk)->icsk_ca_ops = t_ops;
}

static inline void t4_set_req_addr(struct request_sock *oreq,
				   __u32 local_ip, __u32 peer_ip)
{
	inet_rsk(oreq)->loc_addr = local_ip;
	inet_rsk(oreq)->rmt_addr = peer_ip;
}

static inline void t4_set_req_opt(struct request_sock *oreq,
				  struct ip_options *ip_opt)
{
	inet_rsk(oreq)->opt = ip_opt;
}

extern int prepare_tom_for_offload(void);
extern __u32 secure_tcp_sequence_number_offload(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport);

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,16)) && defined(CONFIG_COMPAT)
# define TOM_CONFIG_COMPAT
#endif

#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
# define t4_ptep_set_wrprotect ptep_set_wrprotect
extern void flush_tlb_page_offload(struct vm_area_struct *vma, unsigned long addr);
extern void flush_tlb_mm_offload(struct mm_struct *mm);
#endif

#if defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
#if defined(KALLSYMS_LOOKUP_NAME)
#include <linux/kallsyms.h>
#else
static inline unsigned long kallsyms_lookup_name(const char *name)
{
        return 0;
}
#endif /* KALLSYMS_LOOKUP_NAME */
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
#define t4_inet_put_port(hash_info, sk) inet_put_port(sk)

/* Are BHs disabled already? */
static inline void t4_inet_inherit_port(struct inet_hashinfo *hash_info,
					struct sock *lsk, struct sock *newsk)
{
	local_bh_disable();
	__inet_inherit_port(lsk, newsk);
	local_bh_enable();
}
#else
#define t4_inet_put_port inet_put_port
#define t4_inet_inherit_port inet_inherit_port
#endif

#endif /* 2.6.14 and above */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
static inline struct dst_entry *skb_dst(const struct sk_buff *skb)
{
	return skb->dst;
}

static inline void skb_dst_set(struct sk_buff *skb, struct dst_entry *dst)
{
	skb->dst = dst;
}

static inline struct rtable *skb_rtable(const struct sk_buff *skb)
{
	return (struct rtable *)skb_dst(skb);
}
#endif

static inline void skb_gl_set(struct sk_buff *skb, struct ddp_gather_list *gl)
{
	skb_dst_set(skb, (void *)gl);
}

static inline struct ddp_gather_list *skb_gl(const struct sk_buff *skb)
{
	return (struct ddp_gather_list *)skb_dst(skb);
}

#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
/*
 * We hide the Zero-Copy (ZCOPY) Virtual Address in the skb's "dst" field ...
 */
static inline void skb_vaddr_set(struct sk_buff *skb, unsigned long va)
{
	skb_dst_set(skb, (void *)va);
}

static inline unsigned long skb_vaddr(const struct sk_buff *skb)
{
	return (unsigned long)skb_dst(skb);
}
#endif

static inline void tom_eat_ddp_skb(struct sock *sk, struct sk_buff *skb)
{
	skb_dst_set(skb, NULL);
	__skb_unlink(skb, &sk->sk_receive_queue);
	kfree_skb(skb);
}

static inline void tom_eat_skb(struct sock *sk, struct sk_buff *skb)
{
	skb_dst_set(skb, NULL);
        __skb_unlink(skb, &sk->sk_receive_queue);
	__kfree_skb(skb);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
#define DECLARE_TASK_FUNC(task, task_param) \
	static void task(void *task_param)

#define T4_INIT_WORK INIT_WORK

#define WORK2TOMDATA(task_param, task) task_param

#define T4_DECLARE_WORK(task, func, data) \
	DECLARE_WORK(task, func, data)
#else
#define DECLARE_TASK_FUNC(task, task_param) \
        static void task(struct work_struct *task_param)

#define WORK2TOMDATA(task_param, task) \
	container_of(task_param, struct tom_data, task)

#define T4_INIT_WORK(task_handler, task, adapter) \
        INIT_WORK(task_handler, task)

#define T4_DECLARE_WORK(task, func, data) \
	DECLARE_WORK(task, func)
#endif

#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)

/* Older kernels don't have a PUD; if that's the case, simply fold that level.
 */
#ifndef PUD_SIZE
# define pud_t			pgd_t
# define pud_offset(pgd, addr)	(pgd)
# define pud_none(pud)		0
# define pud_bad(pud)		0
# define pud_present(pud)	0
#endif

/* Unfortunately, flush_tlb_range() is not available on all platforms and 
 * configurations and we must fall back to an implementation based on
 * flush_tlb_page(). Good thing that tlb flushing is in the exception path
 * only.
 */ 
#if defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
static inline void _t4_flush_tlb_range(struct vm_area_struct *vma,
                                       unsigned long start, unsigned long end)
{
        for (; start < end; start += PAGE_SIZE)
                flush_tlb_page_offload(vma, start);
}
#else
static inline void _t4_flush_tlb_range(struct vm_area_struct *vma,
				       unsigned long start, unsigned long end)
{
	for (; start < end; start += PAGE_SIZE)
		flush_tlb_page(vma, start);
}
#endif

#if defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE) && (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)) && defined(CONFIG_64BIT)
static inline void _t4_flush_tlb_mm(struct vm_area_struct *vma,
                                       unsigned long start, unsigned long end)
{
	flush_tlb_mm_offload(vma->vm_mm);
}
#else
static inline void _t4_flush_tlb_mm(struct vm_area_struct *vma,
                                       unsigned long start, unsigned long end)
{
	flush_tlb_range(vma, start, end);
}
#endif

#if defined(CONFIG_X86)
# if !defined(CONFIG_SMP)
#  define t4_flush_tlb_range flush_tlb_range
# elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)) && defined(CONFIG_64BIT)
#  define t4_flush_tlb_range _t4_flush_tlb_mm
# else
#  define t4_flush_tlb_range _t4_flush_tlb_range
# endif
#elif defined(CONFIG_PPC)
# define t4_flush_tlb_range _t4_flush_tlb_range
#else
# define t4_flush_tlb_range flush_tlb_range
#endif
#if defined(CONFIG_T4_ZCOPY_HUGEPAGES)
static __inline__ int zcopy_vma(struct vm_area_struct *vma) {
	return !(vma->vm_flags & VM_SHARED);
}
#else
static __inline__ int zcopy_vma(struct vm_area_struct *vma) {
	return !((vma->vm_flags & VM_SHARED) || is_vm_hugetlb_page(vma));
}
#endif

#if defined(CONFIG_T4_ZCOPY_HUGEPAGES) && defined(CONFIG_HUGETLB_PAGE)
#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
static __inline__ pte_t *t4_huge_pte_offset(struct mm_struct *mm, unsigned long addr)
{
        pgd_t *pgd;
        pud_t *pud;
        pmd_t *pmd = NULL;

        pgd = pgd_offset(mm, addr);
        if (pgd_present(*pgd)) {
                pud = pud_offset(pgd, addr);
                if (pud_present(*pud))
                        pmd = pmd_offset(pud, addr);
        }
        return (pte_t *) pmd;
}
#else
#error CONFIG_T4_ZCOPY_HUGEPAGES not supported on non-x86

#endif
#endif
#endif /* ZCOPY_SENDMSG */

#ifndef KZALLOC
static inline void *kzalloc(size_t size, int flags)
{
	void *ret = kmalloc(size, flags);
	if (ret)
		memset(ret, 0, size);
	return ret;
}
#endif

#define TCP_PAGE(sk)   (sk->sk_sndmsg_page)
#define TCP_OFF(sk)    (sk->sk_sndmsg_off)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
static inline void tom_sysctl_set_de(struct ctl_table *tbl)
{
	tbl->de = NULL;
}
#define tom_register_sysctl_table register_sysctl_table
#else
static inline void tom_sysctl_set_de(struct ctl_table *tbl)
{}

static inline struct ctl_table_header *tom_register_sysctl_table(
						   struct ctl_table * table,
						   int insert_at_head)
{
	return register_sysctl_table(table);
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
#define T4_TCP_INC_STATS_BH(net, field)	TCP_INC_STATS_BH(net, field)
#define T4_NET_INC_STATS_BH(net, field) NET_INC_STATS_BH(net, field)
#define T4_TCP_INC_STATS(net, field)	TCP_INC_STATS(net, field)
#define T4_NET_INC_STATS_USER(net, field) NET_INC_STATS_USER(net, field)
#define t4_type_compat void
#define t4_pci_dma_mapping_error(p, a) pci_dma_mapping_error(p, a)
#else
#define T4_NET_INC_STATS_BH(net, field)	NET_INC_STATS_BH(field)
#define T4_TCP_INC_STATS_BH(net, field) TCP_INC_STATS_BH(field)
#define T4_TCP_INC_STATS(net, field)    TCP_INC_STATS(field)	
#define T4_NET_INC_STATS_USER(net, field) NET_INC_STATS_USER(field)
#define t4_type_compat int
#define t4_pci_dma_mapping_error(p, a) pci_dma_mapping_error(a)
#endif

static inline int t4_get_user_pages(unsigned long addr, int nr_pages, int write, struct page **pages)
{
	int err;
	down_read(&current->mm->mmap_sem);
	err = get_user_pages(current, current->mm, addr, nr_pages, write, 0 , pages, NULL);
	up_read(&current->mm->mmap_sem);
	return err;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
#define GET_USER_PAGES(addr, nr_pages, write, pages) \
	 get_user_pages_fast(addr, nr_pages, write, pages)
#else
#define GET_USER_PAGES(addr, nr_pages, write, pages) \
	t4_get_user_pages(addr, nr_pages, write, pages)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
#define __GET_USER_PAGES(tsk, mm, start, nr_pages, foll_flags, pages, vmas, nonblocking) \
         __get_user_pages(tsk, mm, start, nr_pages, foll_flags, pages, vmas, nonblocking)
#else
#define __GET_USER_PAGES(tsk, mm, start, nr_pages, foll_flags, pages, vmas, nonblocking) \
        __get_user_pages(tsk, mm, start, nr_pages, foll_flags, pages, vmas)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38)
#define dst_metric_advmss(dst) dst_metric(dst, RTAX_ADVMSS)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
#define rtable_dst(__rt) (__rt)->u.dst
#else
#define rtable_dst(__rt) (__rt)->dst
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
#define ipcm_cookie_tx_flags(__ipcm)	(__ipcm).shtx.flags
#define sock_tx_timestamp_ipcm(__msg, __sk, __ipcm) \
	sock_tx_timestamp(__msg, __sk, &(__ipcm).shtx)
#else
#define ipcm_cookie_tx_flags(__ipcm)	(__ipcm).tx_flags
#define sock_tx_timestamp_ipcm(__msg, __sk, __ipcm) \
	sock_tx_timestamp(__sk, &(__ipcm).tx_flags)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
#define t4_pte_offset_map_lock pte_offset_map_lock
#endif

#endif /* __TOM_COMPAT_2_6_H */
