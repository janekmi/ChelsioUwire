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

#ifndef __TOM_COMPAT_3_0_H
#define __TOM_COMPAT_3_0_H

#include <linux/version.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
#include <linux/hugetlb.h>
#include <linux/inet_diag.h>
#include "distro_compat.h"

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

#define INC_ORPHAN_COUNT(sk) percpu_counter_inc((sk)->sk_prot->orphan_count)
#define RSK_OPS

static inline struct dst_entry *route_req(struct sock *sk,
					const struct request_sock *req)
{
	struct flowi4 fl4;
	return inet_csk_route_req(sk, &fl4, req);
}

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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0) && !defined(RHEL_RELEASE_7_0)
#define ir_loc_addr		loc_addr
#define ir_rmt_addr		rmt_addr
#define ir_num			loc_port
#define ir_rmt_port		rmt_port

#define ir_iif			iif
#define ir_v6_rmt_addr		rmt_addr
#define ir_v6_loc_addr		loc_addr

typedef struct inet6_request_sock inet6_request_sock_t;

#else

#define inet6_rsk(__oreq)	inet_rsk(__oreq)

typedef struct inet_request_sock inet6_request_sock_t;
#endif

static inline void t4_set_req_addr(struct request_sock *oreq,
				   __u32 local_ip, __u32 peer_ip)
{
	inet_rsk(oreq)->ir_loc_addr = local_ip;
	inet_rsk(oreq)->ir_rmt_addr = peer_ip;
}

static inline void t4_set_req_opt(struct request_sock *oreq,
				  struct ip_options_rcu *ip_opt)
{
	inet_rsk(oreq)->opt = ip_opt;
}

static inline void t4_set_inet_sock_opt(struct inet_sock *sk,
					struct ip_options_rcu *ip_opt)
{
	sk->inet_opt = ip_opt;
}

extern int prepare_tom_for_offload(void);
extern __u32 secure_tcp_sequence_number_offload(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport);
extern void hpte_need_flush_offload(struct mm_struct *mm, unsigned long addr,
                            pte_t *ptep, unsigned long pte, int huge);
extern struct page *pmd_page_offload(pmd_t pmd);

#if defined(CONFIG_COMPAT)
# define TOM_CONFIG_COMPAT
#endif

#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
#if defined(CONFIG_PPC64)
/* Atomic PTE updates */
static inline unsigned long t4_pte_update(struct mm_struct *mm,
                                       unsigned long addr,
                                       pte_t *ptep, unsigned long clr,
                                       unsigned long set,
                                       int huge)
{
#ifdef PTE_ATOMIC_UPDATES
        unsigned long old, tmp;

        __asm__ __volatile__(
        "1:     ldarx   %0,0,%3         # pte_update\n\
        andi.   %1,%0,%6\n\
        bne-    1b \n\
        andc    %1,%0,%4 \n\
        or      %1,%1,%7\n\
        stdcx.  %1,0,%3 \n\
        bne-    1b"
        : "=&r" (old), "=&r" (tmp), "=m" (*ptep)
        : "r" (ptep), "r" (clr), "m" (*ptep), "i" (_PAGE_BUSY), "r" (set)
        : "cc" );
#else
        unsigned long old = pte_val(*ptep);
        *ptep = __pte((old & ~clr) | set);
#endif
        /* huge pages use the old page table lock */
        if (!huge)
                assert_pte_locked(mm, addr);

#ifdef CONFIG_PPC_STD_MMU_64
        if (old & _PAGE_HASHPTE)
                hpte_need_flush_offload(mm, addr, ptep, old, huge);
#endif

        return old;
}

#ifdef CONFIG_PPC_STD_MMU_64
static inline void t4_ptep_set_wrprotect(struct mm_struct *mm, unsigned long addr,
                                      pte_t *ptep)
{

        if ((pte_val(*ptep) & _PAGE_RW) == 0)
                return;

        t4_pte_update(mm, addr, ptep, _PAGE_RW, 0, 0);
}
#else
#define t4_ptep_set_wrprotect ptep_set_wrprotect
#endif

static inline spinlock_t *t4_pte_lockptr(struct mm_struct *mm, pmd_t *pmd)
{
        return ptlock_ptr(pmd_page_offload(*pmd));
}

#define t4_pte_offset_map_lock(mm, pmd, address, ptlp)     \
({                                                      \
        spinlock_t *__ptl = t4_pte_lockptr(mm, pmd);       \
        pte_t *__pte = pte_offset_map(pmd, address);    \
        *(ptlp) = __ptl;                                \
        spin_lock(__ptl);                               \
        __pte;                                          \
})
#else
#define t4_ptep_set_wrprotect ptep_set_wrprotect
#define t4_pte_offset_map_lock pte_offset_map_lock
#endif /* CONFIG_PPC64 */

extern void flush_tlb_page_offload(struct vm_area_struct *vma, unsigned long addr);
extern void flush_tlb_mm_offload(struct mm_struct *mm);
#endif /* CONFIG_T4_ZCOPY_SENDMSG_MODULE */

#define t4_inet_put_port(hash_info, sk) inet_put_port(sk)

/* Are BHs disabled already? */
static inline void t4_inet_inherit_port(struct inet_hashinfo *hash_info,
					struct sock *lsk, struct sock *newsk)
{
	local_bh_disable();
	__inet_inherit_port(lsk, newsk);
	local_bh_enable();
}

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

#define DECLARE_TASK_FUNC(task, task_param) \
        static void task(struct work_struct *task_param)

#define WORK2TOMDATA(task_param, task) \
	container_of(task_param, struct tom_data, task)

#define T4_INIT_WORK(task_handler, task, adapter) \
        INIT_WORK(task_handler, task)

#define T4_DECLARE_WORK(task, func, data) \
	DECLARE_WORK(task, func)

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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
#define TCP_PAGE(sk)   (sk->sk_sndmsg_page)
#define TCP_OFF(sk)    (sk->sk_sndmsg_off)
#else
#define TCP_PAGE(sk)   (sk->sk_frag.page)
#define TCP_OFF(sk)    (sk->sk_frag.offset)
#endif

static inline void tom_sysctl_set_de(struct ctl_table *tbl)
{}

static inline struct ctl_table_header *tom_register_sysctl_table(
						   struct ctl_table * table,
						   int insert_at_head)
{
	return register_sysctl_table(table);
}

#define T4_TCP_INC_STATS_BH(net, field)	TCP_INC_STATS_BH(net, field)
#define T4_NET_INC_STATS_BH(net, field) NET_INC_STATS_BH(net, field)
#define T4_TCP_INC_STATS(net, field)	TCP_INC_STATS(net, field)
#define T4_NET_INC_STATS_USER(net, field) NET_INC_STATS_USER(net, field)
#define t4_type_compat void
#define t4_pci_dma_mapping_error(p, a) pci_dma_mapping_error(p, a)

static inline int t4_get_user_pages(unsigned long addr, int nr_pages, int write, struct page **pages)
{
	int err;
	down_read(&current->mm->mmap_sem);
	err = get_user_pages(current, current->mm, addr, nr_pages, write, 0 , pages, NULL);
	up_read(&current->mm->mmap_sem);
	return err;
}

#define GET_USER_PAGES(addr, nr_pages, write, pages) \
	 get_user_pages_fast(addr, nr_pages, write, pages)

#define __GET_USER_PAGES(tsk, mm, start, nr_pages, foll_flags, pages, vmas, nonblocking) \
	__get_user_pages(tsk, mm, start, nr_pages, foll_flags, pages, vmas, nonblocking)

static inline void t4_reqsk_free(struct request_sock *req)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
	__reqsk_free(req);
#else
        if (req->rsk_listener)
                sock_put(req->rsk_listener);
	kmem_cache_free(req->rsk_ops->slab, req);
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
static inline void tom_skb_set_napi_id(struct sk_buff *skb,
				       unsigned int napi_id)
{
}

static inline unsigned int tom_skb_get_napi_id(struct sk_buff *skb)
{
	return 0;
}

static inline void tom_sk_set_napi_id(struct sock *sk, unsigned int napi_id)
{
}

static inline bool tom_sk_can_busy_loop(struct sock *sk)
{
	return false;
}

static inline void tom_sk_busy_loop(struct sock *sk, int nonblock)
{
}
#else
static inline void tom_skb_set_napi_id(struct sk_buff *skb,
				       unsigned int napi_id)
{
	skb->napi_id = napi_id;
}

static inline unsigned int tom_skb_get_napi_id(struct sk_buff *skb)
{
	return skb->napi_id;
}

static inline void tom_sk_set_napi_id(struct sock *sk, unsigned int napi_id)
{
	sk->sk_napi_id = napi_id;
}

static inline bool tom_sk_can_busy_loop(struct sock *sk)
{
	return sk_can_busy_loop(sk);
}

static inline void tom_sk_busy_loop(struct sock *sk, int nonblock)
{
	sk_busy_loop(sk, nonblock);
}
#endif
#endif /* __TOM_COMPAT_3_0_H */
