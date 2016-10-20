/*
 * lipippm.c: Chelsio common library for T3/T4 iSCSI PagePod Manager
 *
 * Copyright (c) 2014 Chelsio Communications, Inc. All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Written by: Karen Xie (kxie@chelsio.com)
 */

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/debugfs.h>
#ifdef KERNEL_HAS_KCONFIG_H
#include <linux/kconfig.h>
#endif
#ifdef KERNEL_HAS_EXPORT_H
#include <linux/export.h>
#endif
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/pci.h>
#include <linux/scatterlist.h>

#include "cxgbi_ippm.h"

#ifndef pr_warn
#define pr_warn(fmt, args...) \
	printk(KERN_WARNING fmt, ## args)
#endif

#ifdef __VARIABLE_DDP_PAGE_SIZE__
/*
 * ddp_pgidx, simulate different ddp page sizes 
 * 0 - kernel default PAGE_SIZE 
 * 1 ~ 3, the ddp page size index from ULPRX_ISCSI_PSZ.
 * 4, randomly choose the ddp page size
 * NOTE:
 *	reg ULPRX_CTL (0x500 on t3), bit IscsiTagTcb=1 for per-tag ddp page size
 *	reg ULPRX_ISCSI_PSZ (0x518 on t3) contains the 4 ddp page size shifts
 *	T3 GNAT 5465, 5507
 */
unsigned int ddp_pgidx = 0;
#endif /* __VARIABLE_DDP_PAGE_SIZE__ */

unsigned int ppm_dbg = 0;

#define log_ppm_debug(fmt, ...)      \
        do {    \
                if (ppm_dbg) \
                        pr_info("ippm: " fmt, ##__VA_ARGS__); \
        } while (0)

/*
 * Direct Data Placement -
 * Directly place the iSCSI Data-In or Data-Out PDU's payload into pre-posted
 * final destination host-memory buffers based on the Initiator Task Tag (ITT)
 * in Data-In or Target Task Tag (TTT) in Data-Out PDUs.
 * The host memory address is programmed into h/w in the format of pagepod
 * entries.
 * The location of the pagepod entry is encoded into ddp tag which is used as
 * the base for ITT/TTT.
 */

/*
 * Direct-Data Placement page size adjustment
 */
int cxgbi_ppm_find_page_index(struct cxgbi_ppm *ppm, unsigned long pgsz)
{
	struct cxgbi_tag_format *tformat = &ppm->tformat;
	int i;

	for (i = 0; i < DDP_PGIDX_MAX; i++) {
		if (pgsz == 1UL << (DDP_PGSZ_BASE_SHIFT +
					 tformat->pgsz_order[i])) {
			log_ppm_debug("%s: %s ppm, pgsz %lu -> idx %d.\n",
				 __func__, ppm->ndev->name, pgsz, i);
			return i;
		}
	}
	pr_info("ippm: ddp page size %lu not supported.\n", pgsz);
	return DDP_PGIDX_MAX;
}

/*
 * DDP setup & teardown
 */
static inline int ppm_find_unused_entries(unsigned long *bmap,
				unsigned int max_ppods, unsigned int start,
				unsigned int nr, unsigned int align_mask)
{
	unsigned long i;

	i = bitmap_find_next_zero_area(bmap, max_ppods, start, nr, align_mask);

	if (unlikely(i >= max_ppods) && (start > nr))
		i = bitmap_find_next_zero_area(bmap, max_ppods, 0, start - 1,
						 align_mask);
	if (unlikely(i >= max_ppods))
		return -ENOSPC;

        bitmap_set(bmap, i, nr);
	return (int)i;
}

static void ppm_mark_entries(struct cxgbi_ppm *ppm, int i, int count,
				unsigned long caller_data)
{
	struct cxgbi_ppod_data *pdata = ppm->ppod_data + i;

	pdata->caller_data = caller_data;
	pdata->npods = count;

	if (pdata->color == ((1 << PPOD_IDX_SHIFT) - 1))
               	pdata->color = 0;
	else
		pdata->color++;
}

static int ppm_get_cpu_entries(struct cxgbi_ppm *ppm, unsigned int count,
				unsigned long caller_data)
{
 	struct cxgbi_ppm_pool *pool;
	unsigned int cpu;
	int i;

	cpu = get_cpu();
	pool = per_cpu_ptr(ppm->pool, cpu);
	spin_lock_bh(&pool->lock);
       	put_cpu();

	i = ppm_find_unused_entries(pool->bmap, ppm->pool_index_max,
				pool->next, count, 0);
	if (i < 0) {
		pool->next = 0;
		spin_unlock_bh(&pool->lock);
		return -ENOSPC;
	}

	pool->next = i + count;
	if (pool->next >= ppm->pool_index_max)
		pool->next = 0;

	spin_unlock_bh(&pool->lock);

	log_ppm_debug("%s: cpu %u, idx %d + %d (%d), next %u.\n",
		 __func__, cpu, i, count, i + cpu * ppm->pool_index_max,
		pool->next);

	i += cpu * ppm->pool_index_max;
	ppm_mark_entries(ppm, i, count, caller_data);

	return i;
}

static inline int ppm_get_entries(struct cxgbi_ppm *ppm, unsigned int count,
				unsigned long caller_data)
{
	int i;

	spin_lock_bh(&ppm->map_lock);
	i = ppm_find_unused_entries(ppm->ppod_bmap, ppm->bmap_index_max,
				ppm->next, count, 0);
	if (i < 0) {
		ppm->next = 0;
		spin_unlock_bh(&ppm->map_lock);
		log_ppm_debug("ippm: NO suitable entries %u available.\n",
				count);
		return -ENOSPC;
	}

	ppm->next = i + count;
	if (ppm->next >= ppm->bmap_index_max)
		ppm->next = 0;

	spin_unlock_bh(&ppm->map_lock);

	log_ppm_debug("%s: idx %d + %d (%d), next %u, caller_data 0x%lx.\n",
		 	__func__, i, count, i + ppm->pool_rsvd, ppm->next,
			caller_data);

	i += ppm->pool_rsvd;
	ppm_mark_entries(ppm, i, count, caller_data);

	return i;
}

static inline void ppm_unmark_entries(struct cxgbi_ppm *ppm, int i, int count)
{
	log_ppm_debug("%s: idx %d + %d.\n", __func__, i, count);

	if (i < ppm->pool_rsvd) {
		unsigned int cpu;
		struct cxgbi_ppm_pool *pool;

		cpu = i / ppm->pool_index_max;
		i %= ppm->pool_index_max;

		pool = per_cpu_ptr(ppm->pool, cpu);
		spin_lock_bh(&pool->lock);
		bitmap_clear(pool->bmap, i, count);

		if (i < pool->next)
			pool->next = i;
		spin_unlock_bh(&pool->lock);

		log_ppm_debug("%s: cpu %u, idx %d, next %u.\n",
				 __func__, cpu, i, pool->next);
	} else {
		spin_lock_bh(&ppm->map_lock);

		i -= ppm->pool_rsvd;
		bitmap_clear(ppm->ppod_bmap, i, count);

		if (i < ppm->next)
			ppm->next = i;
		spin_unlock_bh(&ppm->map_lock);

		log_ppm_debug("%s: idx %d, next %u.\n", __func__, i, ppm->next);
	}
}

void cxgbi_ppm_ppod_release(struct cxgbi_ppm *ppm, u32 idx)
{
	struct cxgbi_ppod_data *pdata;

	if (idx >= ppm->ppmax) {
		pr_warn("ippm: idx too big %u > %u.\n", idx, ppm->ppmax);
		return;
	}

	pdata = ppm->ppod_data + idx;
	if (!pdata->npods) {
		pr_warn("ippm: idx %u, npods 0.\n", idx);
		return;
	}

	log_ppm_debug("release idx %u, npods %u.\n", idx, pdata->npods);
	ppm_unmark_entries(ppm, idx, pdata->npods);
}


int cxgbi_ppm_ppods_reserve(struct cxgbi_ppm *ppm, unsigned short nr_pages,
			u32 per_tag_pg_idx, u32 *ppod_idx, u32 *ddp_tag,
			unsigned long caller_data)
{
	struct cxgbi_ppod_data *pdata;
	unsigned int npods;
	int idx = -1;
	unsigned int hwidx;
	u32 tag;

	npods = (nr_pages + PPOD_PAGES_MAX - 1) >> PPOD_PAGES_SHIFT;
	if (!npods) {
                pr_warn("%s: pages %u -> npods %u, full.\n",
                        __func__, nr_pages, npods);
		return -EINVAL;
	}

	        /* grab from cpu pool first */
        idx = ppm_get_cpu_entries(ppm, npods, caller_data);
        /* try the general pool */
        if (idx < 0)
                idx = ppm_get_entries(ppm, npods, caller_data);
        if (idx < 0) {
                log_ppm_debug("ippm: pages %u, nospc %u, nxt %u, 0x%lx.\n",
				nr_pages, npods, ppm->next, caller_data);
                return idx;
        }

	pdata = ppm->ppod_data + idx;
	hwidx = ppm->base_idx + idx;

	tag = cxgbi_ppm_make_ddp_tag(hwidx, pdata->color);

	if (per_tag_pg_idx)
		tag |= (per_tag_pg_idx << 30) & 0xC0000000;

	*ppod_idx = idx;
	*ddp_tag = tag;

	log_ppm_debug("ippm: sg %u, tag 0x%x(%u,%u), data 0x%lx.\n",
			nr_pages, tag, idx, npods, caller_data);

	return npods;
}

struct pi_ctrl_bits_table {
	unsigned int extract_ctl;
	unsigned int check_ctl;
	unsigned int report_ctl;
};

static void get_tx_pi_control_bits(struct cxgbi_pdu_pi_info *pi,
			unsigned int *extract_ctl,
			unsigned int *check_ctl,
			unsigned int *report_ctl)
{
	/* pi->guard and pi_interval can have only 0 or 1 as values */
	unsigned int idx = (pi->guard << 1) + pi->interval;

	/* see ulprx doc for detail */
	struct pi_ctrl_bits_table diff_ctrl_table[] = {
					/* Extract  check  report */
	/* guard ip(0), interval 512B(0) */ {1,      1,      2},
	/* guard ip(0), interval 4K(1)   */ {1,      2,      2},
	/* guard crc(1), interval 512B(0)*/ {1,      1,      1},
	/* guard crc(1), interval 4K(1)  */ {1,      2,      1},
					};

	struct pi_ctrl_bits_table dix_ctrl_table[] = {
					/* Extract  check   report */
	/* guard ip(0), interval 512B(0) */ {0,        3,       1},
	/* guard ip(0), interval 4K(1)   */ {0,        3,       3},
	/* guard crc(1), interval 512B(0)*/ {0,        3,       0},
	/* guard crc(1), interval 4K(1)  */ {0,        3,       2},
					};

#if 0
	pr_info("%s: prot_op %u, idx %u, pi->guard 0x%x, pi->interval 0x%x\n",
		__func__, pi->prot_op, idx, pi->guard, pi->interval);
#endif

	if ((pi->prot_op == ISCSI_PI_OP_SCSI_PROT_READ_PASS) ||
	    (pi->prot_op == ISCSI_PI_OP_SCSI_PROT_READ_STRIP)){
		*extract_ctl = diff_ctrl_table[idx].extract_ctl;
		*check_ctl = diff_ctrl_table[idx].check_ctl;
		*report_ctl = diff_ctrl_table[idx].report_ctl;
	} else if (pi->prot_op == ISCSI_PI_OP_SCSI_PROT_READ_INSERT) {
		*extract_ctl = dix_ctrl_table[idx].extract_ctl;
		*check_ctl = dix_ctrl_table[idx].check_ctl;
		*report_ctl = dix_ctrl_table[idx].report_ctl;
	}
}

void cxgbi_ppm_make_ppod_hdr(struct cxgbi_ppm *ppm, u32 tag, unsigned int tid,
			unsigned int offset, unsigned int length,
			struct cxgbi_pdu_pi_info *pi,
			struct cxgbi_pagepod_hdr *hdr)
{
	/*
 	 * gnat #5507 workaround:
 	 * the ddp tag in pagepod should be with bit 31:30 set to 0.
 	 * the ddp Tag on the wire should be with non-zero 31:30 to the peer
 	 */
	tag &= 0x3FFFFFFF;
	
	if (pi && pi->prot_op) {
		unsigned int extract_ctl = 0, check_ctl = 0, report_ctl = 0;

		get_tx_pi_control_bits(pi, &extract_ctl, &check_ctl,
					&report_ctl);

		log_ppm_debug("%s: tag 0x%x, pi ctrl bits in ppod dif_type "
			"0x%x, extract 0x%x, check 0x%x, report 0x%x\n",
			__func__, tag, pi->dif_type, extract_ctl, check_ctl,
			report_ctl);

		hdr->vld_tid = htonl(PPOD_VALID_FLAG | PPOD_TID(tid) |
					PPOD_PI_EXTRACT_CTL(extract_ctl) |
					PPOD_PI_CHECK_CTL(check_ctl) |
					PPOD_PI_REPORT_CTL(report_ctl) |
					PPOD_PI_TYPE(pi->dif_type));
	} else
		hdr->vld_tid = htonl(PPOD_VALID_FLAG | PPOD_TID(tid));


	hdr->rsvd = 0;
	hdr->pgsz_tag_clr = htonl(tag & ppm->tformat.idx_clr_mask);
	hdr->max_offset = htonl(length);
	hdr->page_offset = htonl(offset);

	/* T10DIF_DDP_WORKAROUND only for T5 */
	if (pi && !pi->offset_updated && pi->prot_op ==
					ISCSI_PI_OP_SCSI_PROT_READ_PASS)
		hdr->max_offset = htonl(length + (length >> 3));

	log_ppm_debug("ippm: tag 0x%x, tid 0x%x, xfer %u, off %u.\n",
			tag, tid, length, offset);
}

static inline void ppm_free(struct cxgbi_ppm *ppm)
{
	vfree(ppm);
}

static void ppm_destroy(struct kref *kref)
{
	struct cxgbi_ppm *ppm = container_of(kref,
						struct cxgbi_ppm,
						refcnt);
	pr_info("ippm: kref 0, destroy %s ppm 0x%p.\n", ppm->ndev->name, ppm);

	*ppm->ppm_pp = NULL;

	free_percpu(ppm->pool);
	ppm_free(ppm);
}

int cxgbi_ppm_release(struct cxgbi_ppm *ppm)
{
	if (ppm) {
		int rv;

		//module_put(THIS_MODULE);
//pr_info("%s: ppm 0x%p, ref 0x%x.\n", __func__, ppm, atomic_read(&ppm->refcnt.refcount));
		rv = kref_put(&ppm->refcnt, ppm_destroy);
		return rv;
	}
	return 1;
}

static struct cxgbi_ppm_pool *ppm_alloc_cpu_pool(unsigned int *total,
						unsigned int *pcpu_ppmax)
{
	struct cxgbi_ppm_pool *pools;
	unsigned int ppmax = (*total) / num_possible_cpus();
	unsigned int max = (PCPU_MIN_UNIT_SIZE - sizeof(*pools)) << 3;
	unsigned int bmap;
	unsigned int alloc_sz;
	unsigned int count = 0;
	unsigned int cpu;

	/* make sure per cpu pool fits into PCPU_MIN_UNIT_SIZE */
	if (ppmax > max)
		ppmax = max;

	/* pool size must be multiple of unsigned long */
	bmap = BITS_TO_LONGS(ppmax);
	ppmax = (bmap * sizeof(unsigned long)) << 3;

	alloc_sz = sizeof(*pools) + sizeof(unsigned long) * bmap;
	pools = __alloc_percpu(alloc_sz, __alignof__(struct cxgbi_ppm_pool));

	if (!pools)
		return NULL;

	for_each_possible_cpu(cpu) {
		struct cxgbi_ppm_pool *ppool = per_cpu_ptr(pools, cpu);

		memset(ppool, 0, alloc_sz);
		spin_lock_init(&ppool->lock);
		count += ppmax;
	}

	*total = count;
	*pcpu_ppmax = ppmax;

	return pools;
}

int cxgbi_ppm_init(void **ppm_pp, struct net_device *ndev, struct pci_dev *pdev,
		void *lldev, struct cxgbi_tag_format *tformat,
		unsigned int ppmax, unsigned int llimit, unsigned int start,
		unsigned int reserve_factor)
{
	struct cxgbi_ppm *ppm = (struct cxgbi_ppm *)(*ppm_pp);
	struct cxgbi_ppm_pool *pool = NULL;
	unsigned int ppmax_pool = 0;
	unsigned int pool_index_max = 0;
	unsigned int alloc_sz;
	unsigned int ppod_bmap_size;

	if (ppm) {
		pr_info("ippm: %s, ppm 0x%p,0x%p already initialized, %u/%u.\n",
			ndev->name, ppm_pp, ppm, ppm->ppmax, ppmax);
		kref_get(&ppm->refcnt);
		return 1;
	}

	if (reserve_factor) {
 		ppmax_pool = ppmax / reserve_factor;
		pool = ppm_alloc_cpu_pool(&ppmax_pool, &pool_index_max);

		log_ppm_debug("%s: ppmax %u, cpu total %u, per cpu %u.\n",
			ndev->name, ppmax, ppmax_pool, pool_index_max);
	}
		
	ppod_bmap_size = BITS_TO_LONGS(ppmax - ppmax_pool);
	alloc_sz = sizeof(struct cxgbi_ppm) +
			ppmax * (sizeof(struct cxgbi_ppod_data)) +
			ppod_bmap_size * sizeof(unsigned long);

	ppm = vmalloc(alloc_sz);
	if (!ppm) {
		pr_warn("ippm: %s, ppm ppmax %u,%u OOM.\n",
			ndev->name, ppmax, alloc_sz);
		goto release_ppm_pool;
	}
	memset(ppm, 0, alloc_sz);

	ppm->ppod_bmap = (unsigned long *)(&ppm->ppod_data[ppmax]);

	if ((ppod_bmap_size >> 3) > (ppmax - ppmax_pool)) {
		unsigned int start = ppmax - ppmax_pool;
		unsigned int end = ppod_bmap_size >> 3;;

        	bitmap_set(ppm->ppod_bmap, ppmax, end - start);
		pr_info("%s: %u - %u < %u * 8, mask extra bits %u, %u.\n",
			 __func__, ppmax, ppmax_pool, ppod_bmap_size, start,
			end);
	}

	spin_lock_init(&ppm->map_lock);
	kref_init(&ppm->refcnt);

	memcpy(&ppm->tformat, tformat, sizeof(struct cxgbi_tag_format));

        ppm->ppm_pp = ppm_pp;
        ppm->ndev = ndev;
        ppm->pdev = pdev;
	ppm->lldev = lldev;
	ppm->ppmax = ppmax;
	ppm->next = 0;
	ppm->llimit = llimit;
	ppm->base_idx = start > llimit ?
			(start - llimit + 1) >> PPOD_SIZE_SHIFT : 0;
	ppm->bmap_index_max = ppmax - ppmax_pool;

	ppm->pool = pool;
	ppm->pool_rsvd = ppmax_pool;
	ppm->pool_index_max = pool_index_max;

	/* check one more time */
	if (*ppm_pp) {
		ppm_free(ppm);
		ppm = (struct cxgbi_ppm *)(*ppm_pp);

		pr_info("ippm: %s, ppm 0x%p,0x%p already initialized, %u/%u.\n",
			ndev->name, ppm_pp, *ppm_pp, ppm->ppmax, ppmax);

		kref_get(&ppm->refcnt);
		return 1;
	}
	*ppm_pp = ppm;

	ppm->tformat.pgsz_idx_dflt = cxgbi_ppm_find_page_index(ppm, PAGE_SIZE);

	pr_info("ippm %s: ppm 0x%p, 0x%p, base %u/%u, pg %lu,%u, rsvd %u,%u.\n",
		ndev->name, ppm_pp, ppm, ppm->base_idx, ppm->ppmax, PAGE_SIZE,
		ppm->tformat.pgsz_idx_dflt, ppm->pool_rsvd,
		ppm->pool_index_max);

	return 0;

release_ppm_pool:
	free_percpu(pool);
	return -ENOMEM;
}

unsigned int cxgbi_tagmask_set(unsigned int ppmax)
{
	unsigned int bits = fls(ppmax);

	if (bits > PPOD_IDX_MAX_SIZE)
		bits = PPOD_IDX_MAX_SIZE;

	pr_info("ippm: ppmax %u/0x%x -> bits %u, tagmask 0x%x.\n",
		ppmax, ppmax, bits, 1 << (bits + PPOD_IDX_SHIFT));

	return 1 << (bits + PPOD_IDX_SHIFT);
}
