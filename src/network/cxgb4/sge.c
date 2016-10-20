/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver.
 *
 * Copyright (C) 2005-2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/dma-mapping.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#ifdef CONFIG_NET_RX_BUSY_POLL
#include <net/busy_poll.h>
#endif /* CONFIG_NET_RX_BUSY_POLL */
#include <linux/io.h>
#ifdef CONFIG_PO_FCOE
#include <scsi/fc/fc_fs.h>
#include <scsi/fc/fc_fcoe.h>
#include <scsi/libfc.h>
#include <scsi/libfcoe.h>
#include <t4_tcb.h>
#endif /* CONFIG_PO_FCOE */
#include "common.h"
#include "t4_regs.h"
#include "t4_regs_values.h"
#include "t4_msg.h"
#include "t4fw_interface.h"
#include "t4_ma_failover.h"

extern int attempt_err_recovery;
/*
 * Rx buffer size for "packed" pages Free List buffers (multiple ingress
 * packets packed per page buffer).  We use largish buffers if possible but
 * settle for single pages under memory shortage.
 */
#if PAGE_SHIFT >= 16
# define FL_PG_ORDER 0
#else
# define FL_PG_ORDER (16 - PAGE_SHIFT)
#endif

/* RX_PULL_LEN should be <= RX_COPY_THRES */
#define RX_COPY_THRES    256
#define RX_PULL_LEN      128

/*
 * Main body length for sk_buffs used for Rx Ethernet packets with fragments.
 * Should be >= RX_PULL_LEN but possibly bigger to give pskb_may_pull some room.
 */
#define RX_PKT_SKB_LEN   512

#ifdef CONFIG_PO_FCOE
#define MAX_TX_RECLAIM 1024
#else
/*
 * Max number of Tx descriptors we clean up at a time.  Should be modest as
 * freeing skbs isn't cheap and it happens while holding locks.  We just need
 * to free packets faster than they arrive, we eventually catch up and keep
 * the amortized cost reasonable.  Must be >= 2 * TXQ_STOP_THRES.
 */
#define MAX_TX_RECLAIM 16
#endif /* CONFIG_PO_FCOE */

/*
 * Max number of Rx buffers we replenish at a time.  Again keep this modest,
 * allocating buffers isn't cheap either.
 */
#define MAX_RX_REFILL 16U

/*
 * Period of the Rx queue check timer.  This timer is infrequent as it has
 * something to do only when the system experiences severe memory shortage.
 */
#define RX_QCHECK_PERIOD (HZ / 2)

/*
 * Period of the Tx queue check timer.
 */
#define TX_QCHECK_PERIOD (HZ / 2)

/*
 * Max number of Tx descriptors to be reclaimed by the Tx timer.
 */
#define MAX_TIMER_TX_RECLAIM 100

/*
 * Timer index used when Rx queues encounter severe memory shortage.
 */
#define NOMEM_TMR_IDX (SGE_NTIMERS - 1)

#ifdef CONFIG_PO_FCOE
#define ETHTXQ_STOP_THRES 1024
#else
/*
 * Suspend an Ethernet Tx queue with fewer available descriptors than this.
 * This is the same as calc_tx_descs() for a TSO packet with
 * nr_frags == MAX_SKB_FRAGS.
 */
#define ETHTXQ_STOP_THRES \
	(1 + DIV_ROUND_UP((3 * MAX_SKB_FRAGS) / 2 + (MAX_SKB_FRAGS & 1), 8))
#endif /* CONFIG_PO_FCOE */

/*
 * Suspension threshold for non-Ethernet Tx queues.  We require enough room
 * for a full sized WR.
 */
#define TXQ_STOP_THRES (SGE_MAX_WR_LEN / sizeof(struct tx_desc))

/*
 * Max size of a WR sent through a control Tx queue.
 */
#define MAX_CTRL_WR_LEN SGE_MAX_WR_LEN

/*
 * Currently there are two types of coalesce WR. Type 0 needs 48 bytes per
 * packet (if one sgl is present) and type 1 needs 32 bytes. This means
 * that type 0 can fit a maximum of 10 packets per WR and type 1 can fit
 * 15 packets. We need to keep track of the skb pointers in a coalesce WR
 * to be able to free those skbs when we get completions back from the FW.
 * Allocating the maximum number of pointers in every tx desc is a waste
 * of memory resources so we only store 2 pointers per tx desc which should
 * be enough since a tx desc can only fit 2 packets in the best case
 * scenario where a packet needs 32 bytes.
 */
#define ETH_COALESCE_PKT_NUM 15
#define ETH_COALESCE_PKT_PER_DESC 2
#define MAX_SKB_COALESCE_LEN 4096

struct tx_eth_coal_desc {
	struct sk_buff *skb[ETH_COALESCE_PKT_PER_DESC];
	struct ulptx_sgl *sgl[ETH_COALESCE_PKT_PER_DESC];
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
	/* Reference to the loopbacked vxlan rx_desc page */
	struct page *page[ETH_COALESCE_PKT_PER_DESC];
#endif
	int idx; 
};

struct tx_sw_desc {                /* SW state per Tx descriptor */
	struct sk_buff *skb;
	struct ulptx_sgl *sgl;
	struct tx_eth_coal_desc coalesce;
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
	/* Reference to the loopbacked vxlan rx_desc page */
	struct page *page;
#endif
};

#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
static void vxlan_copy_frags(struct sge_eth_rxq *rxq, const struct pkt_gl *gl,
			     const struct cpl_rx_pkt *pkt, struct sk_buff *skb,
			     unsigned long vxlan_hdr_len, unsigned int offset);
static inline bool is_vxlan_pkt(bool is_ipv4, const struct pkt_gl *si,
				u32 offset, struct net_device *dev);
#endif

struct rx_sw_desc {                /* SW state per Rx descriptor */
	struct page *page;
	dma_addr_t dma_addr;
};

/*
 * Rx buffer sizes for "useskbs" Free List buffers (one ingress packet per skb
 * buffer).  We currently only support two sizes for 1500- and 9000-byte MTUs.
 * We could easily support more but there doesn't seem to be much need for
 * that ...
 */
#define FL_MTU_SMALL 1500
#define FL_MTU_LARGE 9000

static inline unsigned int fl_mtu_bufsize(struct adapter *adapter,
					  unsigned int mtu)
{
	struct sge *s = &adapter->sge;

	return ALIGN(s->pktshift + ETH_HLEN + VLAN_HLEN + mtu, s->fl_align);
}

#define FL_MTU_SMALL_BUFSIZE(adapter) fl_mtu_bufsize(adapter, FL_MTU_SMALL)
#define FL_MTU_LARGE_BUFSIZE(adapter) fl_mtu_bufsize(adapter, FL_MTU_LARGE)

/*
 * Bits 0..3 of rx_sw_desc.dma_addr have special meaning.  The hardware uses
 * these to specify the buffer size as an index into the SGE Free List Buffer
 * Size register array.  We also use bit 4, when the buffer has been unmapped
 * for DMA, but this is of course never sent to the hardware and is only used
 * to prevent double unmappings.  All of the above requires that the Free List
 * Buffers which we allocate have the bottom 5 bits free (0) -- i.e. are
 * 32-byte or or a power of 2 greater in alignment.  Since the SGE's minimal
 * Free List Buffer alignment is 32 bytes, this works out for us ...
 */
enum {
	RX_BUF_FLAGS     = 0x1f,   /* bottom five bits are special */
	RX_BUF_SIZE      = 0x0f,   /* bottom three bits are for buf sizes */
	RX_UNMAPPED_BUF  = 0x10,   /* buffer is not mapped */

	/*
	 * XXX We shouldn't depend on being able to use these indices.
	 * XXX Especially when some other Master PF has initialized the
	 * XXX adapter or we use the Firmware Configuration File.  We
	 * XXX should really search through the Host Buffer Size register
	 * XXX array for the appropriately sized buffer indices.
	 */
	RX_SMALL_PG_BUF  = 0x0,   /* small (PAGE_SIZE) page buffer */
	RX_LARGE_PG_BUF  = 0x1,   /* buffer large (FL_PG_ORDER) page buffer */
};

static int timer_pkt_quota[] = {1, 1, 2, 3, 4, 5};
#define MIN_NAPI_WORK	1

static inline dma_addr_t get_buf_addr(const struct rx_sw_desc *d)
{
	return d->dma_addr & ~(dma_addr_t)RX_BUF_FLAGS;
}

static inline bool is_buf_mapped(const struct rx_sw_desc *d)
{
	return !(d->dma_addr & RX_UNMAPPED_BUF);
}

/**
 *	txq_avail - return the number of available slots in a Tx queue
 *	@q: the Tx queue
 *
 *	Returns the number of descriptors in a Tx queue available to write new
 *	packets.
 */
static inline unsigned int txq_avail(const struct sge_txq *q)
{
	return q->size - 1 - q->in_use;
}

/**
 *	fl_cap - return the capacity of a free-buffer list
 *	@fl: the FL
 *
 *	Returns the capacity of a free-buffer list.  The capacity is less than
 *	the size because one descriptor needs to be left unpopulated, otherwise
 *	HW will think the FL is empty.
 */
static inline unsigned int fl_cap(const struct sge_fl *fl)
{
	return fl->size - 8;   /* 1 descriptor = 8 buffers */
}

/**
 *	fl_starving - return whether a Free List is starving.
 *	@adapter: pointer to the adapter
 *	@fl: the Free List
 *
 *	Tests specified Free List to see whether the number of buffers
 *	available to the hardware has falled below our "starvation"
 *	threshold.
 */
static inline bool fl_starving(const struct adapter *adapter,
			       const struct sge_fl *fl)
{
	const struct sge *s = &adapter->sge;

	return fl->avail - fl->pend_cred <= s->fl_starve_thres;
}

static int map_skb(struct device *dev, const struct sk_buff *skb,
		   dma_addr_t *addr)
{
	const skb_frag_t *fp, *end;
	const struct skb_shared_info *si;

	/* In case of T5 VxLAN, all of the headers go as immediate data.
	 * The caller might have adjusted the lengths accordingly.
	 * Hence need to check if there is any data in the skb->data
	 * before mapping.
	 */
	if (skb_headlen(skb)) {
		*addr = dma_map_single(dev, skb->data, skb_headlen(skb),
				       DMA_TO_DEVICE);
		if (dma_mapping_error(dev, *addr))
			goto out_err;
	}

	si = skb_shinfo(skb);
	end = &si->frags[si->nr_frags];

	for (fp = si->frags; fp < end; fp++) {
		*++addr = skb_frag_dma_map(dev, fp, 0, skb_frag_size(fp),
					   DMA_TO_DEVICE);
		if (dma_mapping_error(dev, *addr))
			goto unwind;
	}
	return 0;

unwind:
	while (fp-- > si->frags)
		dma_unmap_page(dev, *--addr, skb_frag_size(fp), DMA_TO_DEVICE);

	if (skb_headlen(skb))
		dma_unmap_single(dev, addr[-1], skb_headlen(skb), DMA_TO_DEVICE);
out_err:
	return -ENOMEM;
}

#ifdef CONFIG_NEED_DMA_MAP_STATE
static void unmap_skb(struct device *dev, const struct sk_buff *skb,
		      const dma_addr_t *addr)
{
	const skb_frag_t *fp, *end;
	const struct skb_shared_info *si;

	dma_unmap_single(dev, *addr++, skb_headlen(skb), DMA_TO_DEVICE);

	si = skb_shinfo(skb);
	end = &si->frags[si->nr_frags];
	for (fp = si->frags; fp < end; fp++)
		dma_unmap_page(dev, *addr++, skb_frag_size(fp), DMA_TO_DEVICE);
}

/**
 *	deferred_unmap_destructor - unmap a packet when it is freed
 *	@skb: the packet
 *
 *	This is the packet destructor used for Tx packets that need to remain
 *	mapped until they are freed rather than until their Tx descriptors are
 *	freed.
 */
static void deferred_unmap_destructor(struct sk_buff *skb)
{
	unmap_skb(skb->dev->dev.parent, skb, (dma_addr_t *)skb->head);
}
#endif

static void unmap_sgl(struct device *dev, const struct sk_buff *skb,
		      const struct ulptx_sgl *sgl, const struct sge_txq *q)
{
	const struct ulptx_sge_pair *p;
	unsigned int nfrags = skb_shinfo(skb)->nr_frags;

	if (likely(skb_headlen(skb)))
		dma_unmap_single(dev, be64_to_cpu(sgl->addr0), ntohl(sgl->len0),
				 DMA_TO_DEVICE);
	else {
		dma_unmap_page(dev, be64_to_cpu(sgl->addr0), ntohl(sgl->len0),
			       DMA_TO_DEVICE);
		nfrags--;
	}

	/*
	 * the complexity below is because of the possibility of a wrap-around
	 * in the middle of an SGL
	 */
	for (p = sgl->sge; nfrags >= 2; nfrags -= 2) {
		if (likely((u8 *)(p + 1) <= (u8 *)q->stat)) {
unmap:			dma_unmap_page(dev, be64_to_cpu(p->addr[0]),
				       ntohl(p->len[0]), DMA_TO_DEVICE);
			dma_unmap_page(dev, be64_to_cpu(p->addr[1]),
				       ntohl(p->len[1]), DMA_TO_DEVICE);
			p++;
		} else if ((u8 *)p == (u8 *)q->stat) {
			p = (const struct ulptx_sge_pair *)q->desc;
			goto unmap;
		} else if ((u8 *)p + 8 == (u8 *)q->stat) {
			const __be64 *addr = (const __be64 *)q->desc;

			dma_unmap_page(dev, be64_to_cpu(addr[0]),
				       ntohl(p->len[0]), DMA_TO_DEVICE);
			dma_unmap_page(dev, be64_to_cpu(addr[1]),
				       ntohl(p->len[1]), DMA_TO_DEVICE);
			p = (const struct ulptx_sge_pair *)&addr[2];
		} else {
			const __be64 *addr = (const __be64 *)q->desc;

			dma_unmap_page(dev, be64_to_cpu(p->addr[0]),
				       ntohl(p->len[0]), DMA_TO_DEVICE);
			dma_unmap_page(dev, be64_to_cpu(addr[0]),
				       ntohl(p->len[1]), DMA_TO_DEVICE);
			p = (const struct ulptx_sge_pair *)&addr[1];
		}
	}
	if (nfrags) {
		__be64 addr;

		if ((u8 *)p == (u8 *)q->stat)
			p = (const struct ulptx_sge_pair *)q->desc;
		addr = (u8 *)p + 16 <= (u8 *)q->stat ? p->addr[0] :
						       *(const __be64 *)q->desc;
		dma_unmap_page(dev, be64_to_cpu(addr), ntohl(p->len[0]),
			       DMA_TO_DEVICE);
	}
}

/**
 *	 need_skb_unmap - does the platform need unmapping of sk_buffs?
 *
 *	Returns true if the platfrom needs sk_buff unmapping.  The compiler
 *	optimizes away unecessary code if this returns true.
 */
static inline int need_skb_unmap(void)
{
	/*
	 * This structure is used to tell if the platfrom needs buffer
	 * unmapping by checking if DECLARE_PCI_UNMAP_ADDR defines anything.
	 */
	struct dummy {
		DECLARE_PCI_UNMAP_ADDR(addr);
	};

	return sizeof(struct dummy) != 0;
}

/**
 *	free_tx_desc - reclaims Tx descriptors and their buffers
 *	@adapter: the adapter
 *	@q: the Tx queue to reclaim descriptors from
 *	@n: the number of descriptors to reclaim
 *	@unmap: whether the buffers should be unmapped for DMA
 *
 *	Reclaims Tx descriptors from an SGE Tx queue and frees the associated
 *	Tx buffers.  Called with the Tx queue lock held.
 */
static void free_tx_desc(struct adapter *adap, struct sge_txq *q,
			 unsigned int n, bool unmap)
{
	struct tx_sw_desc *d;
	unsigned int cidx = q->cidx;
	struct device *dev = adap->pdev_dev;
	int i;

	const int need_unmap = need_skb_unmap() && unmap;

#ifdef T4_TRACE
	T4_TRACE2(adap->tb[q->cntxt_id & 7],
		  "reclaiming %u Tx descriptors at cidx %u", n, cidx);
#endif
	d = &q->sdesc[cidx];
	while (n--) {
		if (d->skb) {                       /* an SGL is present */
			if (need_unmap)
				unmap_sgl(dev, d->skb, d->sgl, q);
			dev_consume_skb_any(d->skb);
			d->skb = NULL;
		}
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
		if (q->is_vxlan_lb && d->page) {
			/* Release the reference of loopbacked vxlan page */
			put_page(d->page);
			d->page = NULL;
		}
#endif
		if (d->coalesce.idx) {
			for (i = 0; i < d->coalesce.idx; i++) {
				if (need_unmap)
					unmap_sgl(dev, d->coalesce.skb[i],
						  d->coalesce.sgl[i], q);
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
				if (q->is_vxlan_lb && d->coalesce.page[i]) {
					/* This is from vxlan path.
					 * Release the page reference.
					 */
					put_page(d->coalesce.page[i]);
					d->coalesce.page[i] = NULL;
				} else
#endif
					kfree_skb(d->coalesce.skb[i]);
				d->coalesce.skb[i] = NULL;
			}
			d->coalesce.idx = 0;
		}
		++d;
		if (++cidx == q->size) {
			cidx = 0;
			d = q->sdesc;
		}
	}
	q->cidx = cidx;
}

/*
 * Return the number of reclaimable descriptors in a Tx queue.
 */
static inline int reclaimable(const struct sge_txq *q)
{
	int hw_cidx = ntohs(ACCESS_ONCE(q->stat->cidx));
	hw_cidx -= q->cidx;
	return hw_cidx < 0 ? hw_cidx + q->size : hw_cidx;
}

/**
 *	reclaim_completed_tx - reclaims completed Tx descriptors
 *	@adap: the adapter
 *	@q: the Tx queue to reclaim completed descriptors from
 *	@unmap: whether the buffers should be unmapped for DMA
 *
 *	Reclaims Tx descriptors that the SGE has indicated it has processed,
 *	and frees the associated buffers if possible.  Called with the Tx
 *	queue locked.
 */
static inline void reclaim_completed_tx(struct adapter *adap, struct sge_txq *q,
					bool unmap)
{
	int avail = reclaimable(q);

	if (avail) {
		/*
		 * Limit the amount of clean up work we do at a time to keep
		 * the Tx lock hold time O(1).
		 */
		if (avail > MAX_TX_RECLAIM)
			avail = MAX_TX_RECLAIM;

		free_tx_desc(adap, q, avail, unmap);
		q->in_use -= avail;
	}
}

static inline int get_buf_size(struct adapter *adapter,
			       const struct rx_sw_desc *d)
{
	struct sge *s = &adapter->sge;
	unsigned int rx_buf_size_idx = d->dma_addr & RX_BUF_SIZE;
	int buf_size;

	switch (rx_buf_size_idx) {
	case RX_SMALL_PG_BUF:
		buf_size = PAGE_SIZE;
		break;

	case RX_LARGE_PG_BUF:
		buf_size = PAGE_SIZE << s->fl_pg_order;
		break;

	default:
		BUG_ON(1);
		buf_size = 0; /* deal with bogus compiler warnings */
		/*NOTREACHED*/
	}

	return buf_size;
}

/**
 *	free_rx_bufs - free the Rx buffers on an SGE free list
 *	@adap: the adapter
 *	@q: the SGE free list to free buffers from
 *	@n: how many buffers to free
 *
 *	Release the next @n buffers on an SGE free-buffer Rx queue.   The
 *	buffers must be made inaccessible to HW before calling this function.
 */
static void free_rx_bufs(struct adapter *adap, struct sge_fl *q, int n)
{
	while (n--) {
		struct rx_sw_desc *d = &q->sdesc[q->cidx];

		if (is_buf_mapped(d))
			dma_unmap_page(adap->pdev_dev, get_buf_addr(d),
				       get_buf_size(adap, d),
				       PCI_DMA_FROMDEVICE);
		put_page(d->page);
		d->page = NULL;
		if (++q->cidx == q->size)
			q->cidx = 0;
		q->avail--;
	}
}

/**
 *	unmap_rx_buf - unmap the current Rx buffer on an SGE free list
 *	@adap: the adapter
 *	@q: the SGE free list
 *
 *	Unmap the current buffer on an SGE free-buffer Rx queue.   The
 *	buffer must be made inaccessible to HW before calling this function.
 *
 *	This is similar to @free_rx_bufs above but does not free the buffer.
 *	Do note that the FL still loses any further access to the buffer.
 */
static void unmap_rx_buf(struct adapter *adap, struct sge_fl *q)
{
	struct rx_sw_desc *d = &q->sdesc[q->cidx];

	if (is_buf_mapped(d))
		dma_unmap_page(adap->pdev_dev, get_buf_addr(d),
			       get_buf_size(adap, d), PCI_DMA_FROMDEVICE);
	d->page = NULL;
	if (++q->cidx == q->size)
		q->cidx = 0;
	q->avail--;
}

static inline void ring_fl_db(struct adapter *adap, struct sge_fl *q)
{
	if (q->pend_cred >= 8) {
		u32 val = adap->params.arch.sge_fl_db;

		if (is_t4(adap->params.chip))
			val |= V_PIDX(q->pend_cred / 8);
		else
			val |= V_PIDX_T5(q->pend_cred / 8);

		/*
		 * Make sure all memory writes to the Free List queue are
		 * committed before we tell the hardware about them.
		 */
		wmb();
		
		/* If we don't have access to the new User Doorbell (T5+), use
		 * the old doorbell mechanism; otherwise use the new BAR2
		 * mechanism.
		 */
		if (unlikely(q->bar2_addr == NULL)) {
			t4_write_reg(adap, MYPF_REG(A_SGE_PF_KDOORBELL),
				     val | V_QID(q->cntxt_id));
		} else {
			writel(val | V_QID(q->bar2_qid),
			       q->bar2_addr + SGE_UDB_KDOORBELL);

			/* This Write memory Barrier will force the write to
			 * the User Doorbell area to be flushed.
			 */
			wmb();
		}
		q->pend_cred &= 7;
	}
}

static inline void set_rx_sw_desc(struct rx_sw_desc *sd, struct page *pg,
				  dma_addr_t mapping)
{
	sd->page = pg;
	sd->dma_addr = mapping;      /* includes size low bits */
}

/**
 *	refill_fl - refill an SGE Rx buffer ring
 *	@adap: the adapter
 *	@q: the ring to refill
 *	@n: the number of new buffers to allocate
 *	@gfp: the gfp flags for the allocations
 *
 *	(Re)populate an SGE free-buffer queue with up to @n new packet buffers,
 *	allocated with the supplied gfp flags.  The caller must assure that
 *	@n does not exceed the queue's capacity.  If afterwards the queue is
 *	found critically low mark it as starving in the bitmap of starving FLs.
 *
 *	Returns the number of buffers allocated.
 */
static unsigned int refill_fl(struct adapter *adap, struct sge_fl *q, int n,
			      gfp_t gfp)
{
	struct sge *s = &adap->sge;
	struct page *pg;
	dma_addr_t mapping;
	unsigned int cred = q->avail;
	__be64 *d = &q->desc[q->pidx];
	struct rx_sw_desc *sd = &q->sdesc[q->pidx];
	int node;
 
	if (test_bit(q->cntxt_id - adap->sge.egr_start, adap->sge.blocked_fl))
		goto out;

	gfp |= __GFP_NOWARN;         /* failures are expected */
	node = dev_to_node(adap->pdev_dev);

	if (s->fl_pg_order == 0)
		goto alloc_small_pages;

	/*
	 * Prefer large buffers
	 */
	while (n) {
		pg = alloc_pages_node(node, gfp | __GFP_COMP, s->fl_pg_order);
		if (unlikely(!pg)) {
			q->large_alloc_failed++;
			break;       /* fall back to single pages */
		}

		mapping = dma_map_page(adap->pdev_dev, pg, 0,
				       PAGE_SIZE << s->fl_pg_order,
				       PCI_DMA_FROMDEVICE);
		if (unlikely(dma_mapping_error(adap->pdev_dev, mapping))) {
			__free_pages(pg, s->fl_pg_order);
			q->mapping_err++;
			goto out;   /* do not try small pages for this error */
		}
		mapping |= RX_LARGE_PG_BUF;
		*d++ = cpu_to_be64(mapping);

		set_rx_sw_desc(sd, pg, mapping);
		sd++;

		q->avail++;
		if (++q->pidx == q->size) {
			q->pidx = 0;
			sd = q->sdesc;
			d = q->desc;
		}
		n--;
	}

alloc_small_pages:
	while (n--) {
		pg = alloc_pages_node(node, gfp, 0);
		if (unlikely(!pg)) {
			q->alloc_failed++;
			break;
		}

		mapping = dma_map_page(adap->pdev_dev, pg, 0, PAGE_SIZE,
				       PCI_DMA_FROMDEVICE);
		if (unlikely(dma_mapping_error(adap->pdev_dev, mapping))) {
			put_page(pg);
			q->mapping_err++;
			break;
		}
		mapping |= RX_SMALL_PG_BUF;
		*d++ = cpu_to_be64(mapping);

		set_rx_sw_desc(sd, pg, mapping);
		sd++;

		q->avail++;
		if (++q->pidx == q->size) {
			q->pidx = 0;
			sd = q->sdesc;
			d = q->desc;
		}
	}

out:	cred = q->avail - cred;
	q->pend_cred += cred;
	ring_fl_db(adap, q);

	if (unlikely(fl_starving(adap, q))) {
		smp_wmb();
		q->low++;
		set_bit(q->cntxt_id - adap->sge.egr_start,
			adap->sge.starving_fl);
	}

	return cred;
}

static inline void __refill_fl(struct adapter *adap, struct sge_fl *fl)
{
	refill_fl(adap, fl, min(MAX_RX_REFILL, fl_cap(fl) - fl->avail),
		  GFP_ATOMIC);
}

/**
 *	alloc_ring - allocate resources for an SGE descriptor ring
 *	@dev: the PCI device's core device
 *	@nelem: the number of descriptors
 *	@elem_size: the size of each descriptor
 *	@sw_size: the size of the SW state associated with each ring element
 *	@phys: the physical address of the allocated ring
 *	@metadata: address of the array holding the SW state for the ring
 *	@stat_size: extra space in HW ring for status information
 *	@node: preferred node for memory allocations
 *
 *	Allocates resources for an SGE descriptor ring, such as Tx queues,
 *	free buffer lists, or response queues.  Each SGE ring requires
 *	space for its HW descriptors plus, optionally, space for the SW state
 *	associated with each HW entry (the metadata).  The function returns
 *	three values: the virtual address for the HW ring (the return value
 *	of the function), the bus address of the HW ring, and the address
 *	of the SW ring.
 */
static void *alloc_ring(struct device *dev, size_t nelem, size_t elem_size,
			size_t sw_size, dma_addr_t *phys, void *metadata,
			size_t stat_size, int node)
{
	size_t len = nelem * elem_size + stat_size;
	void *s = NULL;
	void *p = dma_alloc_coherent(dev, len, phys, GFP_KERNEL);

	if (!p)
		return NULL;
	if (sw_size) {
		s = kzalloc_node(nelem * sw_size, GFP_KERNEL, node);

		if (!s) {
			dma_free_coherent(dev, len, p, *phys);
			return NULL;
		}
	}
	if (metadata)
		*(void **)metadata = s;
	memset(p, 0, len);
	return p;
}

/**
 *	sgl_len - calculates the size of an SGL of the given capacity
 *	@n: the number of SGL entries
 *
 *	Calculates the number of flits needed for a scatter/gather list that
 *	can hold the given number of entries.
 */
static inline unsigned int sgl_len(unsigned int n)
{
	/* A Direct Scatter Gather List uses 32-bit lengths and 64-bit PCI DMA
	 * addresses.  The DSGL Work Request starts off with a 32-bit DSGL
	 * ULPTX header, then Length0, then Address0, then, for 1 <= i <= N,
	 * repeated sequences of { Length[i], Length[i+1], Address[i],
	 * Address[i+1] } (this ensures that all addresses are on 64-bit
	 * boundaries).  If N is even, then Length[N+1] should be set to 0 and
	 * Address[N+1] is omitted.
	 *
	 * The following calculation incorporates all of the above.  It's
	 * somewhat hard to follow but, briefly: the "+2" accounts for the
	 * first two flits which include the DSGL header, Length0 and
	 * Address0; the "(3*(n-1))/2" covers the main body of list entries (3
	 * flits for every pair of the remaining N) +1 if (n-1) is odd; and
	 * finally the "+((n-1)&1)" adds the one remaining flit needed if
	 * (n-1) is odd ...
	 */
	n--;
	return (3 * n) / 2 + (n & 1) + 2;
}

/**
 *	flits_to_desc - returns the num of Tx descriptors for the given flits
 *	@n: the number of flits
 *
 *	Returns the number of Tx descriptors needed for the supplied number
 *	of flits.
 */
static inline unsigned int flits_to_desc(unsigned int n)
{
	BUG_ON(n > SGE_MAX_WR_LEN / 8);
	return DIV_ROUND_UP(n, 8);
}

/**
 *	is_eth_imm - can an Ethernet packet be sent as immediate data?
 *	@skb: the packet
 *	@chip: chip type
 *
 *	Returns whether an Ethernet packet is small enough to fit as
 *	immediate data. Return value corresponds to the headroom required.
 */
static inline int is_eth_imm(const struct sk_buff *skb, unsigned int chip_ver)
{
	int hdrlen = 0;

#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
	/* vxlan tso is enabled only for T5 and T6.
	 * gre offload is enabled only for T6.
	 * fw_eth_tx_eo_wr is used in T5 for segmenting encapsulated packets.
	 * T6 uses cpl_tx_tnl_lso.
	 */
	if (skb->encapsulation && skb_shinfo(skb)->gso_size) {
		if (chip_ver == CHELSIO_T5)
			hdrlen = sizeof(struct fw_eth_tx_eo_wr);
		else
			hdrlen = sizeof(struct cpl_tx_tnl_lso);
		hdrlen += sizeof(struct cpl_tx_pkt_core);
	} else
#endif
	{
		hdrlen = skb_shinfo(skb)->gso_size ?
			 sizeof(struct cpl_tx_pkt_lso_core) : 0;
		hdrlen += sizeof(struct cpl_tx_pkt);
	}
	if (skb->len <= MAX_IMM_TX_PKT_LEN - hdrlen)
		return hdrlen;

	return 0;
}

/**
 *	calc_tx_flits - calculate the number of flits for a packet Tx WR
 *	@skb: the packet
 *	@chip: chip type
 *
 *	Returns the number of flits needed for a Tx WR for the given Ethernet
 *	packet, including the needed WR and CPL headers.
 */
static inline unsigned int calc_tx_flits(const struct sk_buff *skb,
					 unsigned int chip_ver)
{
	unsigned int flits;
	int hdrlen = is_eth_imm(skb, chip_ver);

	/* If the skb is small enough, we can pump it out as a work request
	 * with only immediate data.  In that case we just have to have the
	 * TX Packet header plus the skb data in the Work Request.
	 */

	if (hdrlen)
		return DIV_ROUND_UP(skb->len + hdrlen, sizeof(__be64));

	/* Otherwise, we're going to have to construct a Scatter gather list
	 * of the skb body and fragments.  We also include the flits necessary
	 * for the TX Packet Work Request and CPL.  We always have a firmware
	 * Write Header (incorporated as part of the cpl_tx_pkt_lso and
	 * cpl_tx_pkt structures), followed by either a TX Packet Write CPL
	 * message or, if we're doing a Large Send Offload, an LSO CPL message
	 * with an embedded TX Packet Write CPL message.
	 */
	flits = sgl_len(skb_shinfo(skb)->nr_frags + 1);
	if (skb_shinfo(skb)->gso_size) {
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
		if (skb->encapsulation) {
			if (chip_ver == CHELSIO_T5)
				hdrlen = sizeof(struct fw_eth_tx_eo_wr);
			else
				hdrlen = sizeof(struct fw_eth_tx_pkt_wr) +
					 sizeof(struct cpl_tx_tnl_lso);
		} else
#endif
			hdrlen = sizeof(struct fw_eth_tx_pkt_wr) +
				 sizeof(struct cpl_tx_pkt_lso_core);
		hdrlen += sizeof(struct cpl_tx_pkt_core);
		flits += (hdrlen / sizeof(__be64));
	} else {
		flits += (sizeof(struct fw_eth_tx_pkt_wr) +
			  sizeof(struct cpl_tx_pkt_core)) / sizeof(__be64);
	}
	return flits;
}

/**
 *	calc_tx_descs - calculate the number of Tx descriptors for a packet
 *	@skb: the packet
 *
 *	Returns the number of Tx descriptors needed for the given Ethernet
 *	packet, including the needed WR and CPL headers.
 */
static inline unsigned int calc_tx_descs(const struct sk_buff *skb,
					 unsigned int chip_ver)
{
	return flits_to_desc(calc_tx_flits(skb, chip_ver));
}

/**
 *	write_sgl - populate a scatter/gather list for a packet
 *	@skb: the packet
 *	@q: the Tx queue we are writing into
 *	@sgl: starting location for writing the SGL
 *	@end: points right after the end of the SGL
 *	@start: start offset into skb main-body data to include in the SGL
 *
 *	Generates a scatter/gather list for the buffers that make up a packet.
 *	The caller must provide adequate space for the SGL that will be written.
 *	The SGL includes all of the packet's page fragments and the data in its
 *	main body except for the first @start bytes.  @sgl must be 16-byte
 *	aligned and within a Tx descriptor with available space.  @end points
 *	write after the end of the SGL but does not account for any potential
 *	wrap around, i.e., @end > @sgl.
 */
static void write_sgl(const struct sk_buff *skb, struct sge_txq *q,
		      struct ulptx_sgl *sgl, u64 *end, unsigned int start,
		      const dma_addr_t *addr)
{
	unsigned int i, len;
	struct ulptx_sge_pair *to;
	const struct skb_shared_info *si = skb_shinfo(skb);
	unsigned int nfrags = si->nr_frags;
	struct ulptx_sge_pair buf[MAX_SKB_FRAGS / 2 + 1];

	len = skb_headlen(skb) - start;
	if (likely(len)) {
		sgl->len0 = htonl(len);
		sgl->addr0 = cpu_to_be64(addr[0] + start);
		nfrags++;
	} else {
		sgl->len0 = htonl(skb_frag_size(&si->frags[0]));
		sgl->addr0 = cpu_to_be64(addr[1]);
	}

	sgl->cmd_nsge = htonl(V_ULPTX_CMD(ULP_TX_SC_DSGL) |
			      V_ULPTX_NSGE(nfrags));
	if (likely(--nfrags == 0))
		return;
	/*
	 * Most of the complexity below deals with the possibility we hit the
	 * end of the queue in the middle of writing the SGL.  For this case
	 * only we create the SGL in a temporary buffer and then copy it.
	 */
	to = (u8 *)end > (u8 *)q->stat ? buf : sgl->sge;

	for (i = (nfrags != si->nr_frags); nfrags >= 2; nfrags -= 2, to++) {
		to->len[0] = cpu_to_be32(skb_frag_size(&si->frags[i]));
		to->len[1] = cpu_to_be32(skb_frag_size(&si->frags[++i]));
		to->addr[0] = cpu_to_be64(addr[i]);
		to->addr[1] = cpu_to_be64(addr[++i]);
	}
	if (nfrags) {
		to->len[0] = cpu_to_be32(skb_frag_size(&si->frags[i]));
		to->len[1] = cpu_to_be32(0);
		to->addr[0] = cpu_to_be64(addr[i + 1]);
	}
	if (unlikely((u8 *)end > (u8 *)q->stat)) {
		unsigned int part0 = (u8 *)q->stat - (u8 *)sgl->sge, part1;

		if (likely(part0))
			memcpy(sgl->sge, buf, part0);
		part1 = (u8 *)end - (u8 *)q->stat;
		memcpy(q->desc, (u8 *)buf + part0, part1);
		end = (void *)q->desc + part1;
	}
	if ((uintptr_t)end & 8)           /* 0-pad to multiple of 16 */
		*end = 0;
}

/* This function copies 64 byte coalesced work request to
 * memory mapped BAR2 space. For coalesced WR SGE fetches
 * data from the FIFO instead of from Host.
 */
static void cxgb_pio_copy(u64 __iomem *dst, u64 *src)
{
	int count = 8;

	while (count) {
		writeq(*src, dst);
		src++;
		dst++;
		count--;
	}
}

/**
 *	ring_tx_db - check and potentially ring a Tx queue's doorbell
 *	@adap: the adapter
 *	@q: the Tx queue
 *	@n: number of new descriptors to give to HW
 *
 *	Ring the doorbel for a Tx queue.
 */
static inline void ring_tx_db(struct adapter *adap, struct sge_txq *q, int n)
{
	/* Make sure that all writes to the TX Descriptors are committed
	 * before we tell the hardware about them.
	 */
	wmb();

	/* If we don't have access to the new User Doorbell (T5+), use the old
	 * doorbell mechanism; otherwise use the new BAR2 mechanism.
	 */
	if (unlikely(q->bar2_addr == NULL)) {
		u32 val = V_PIDX(n);
		unsigned long flags;

		/* For T4 we need to participate in the Doorbell Recovery
		 * mechanism.
		 */
		spin_lock_irqsave(&q->db_lock, flags);
		if (!q->db_disabled)
			t4_write_reg(adap, MYPF_REG(A_SGE_PF_KDOORBELL),
				     V_QID(q->cntxt_id) | val);
		else
			q->db_pidx_inc += n;
		q->db_pidx = q->pidx;
		spin_unlock_irqrestore(&q->db_lock, flags);
	} else {
		u32 val = V_PIDX_T5(n);

		/* T4 and later chips share the same PIDX field offset within
		 * the doorbell, but T5 and later shrank the field in order to
		 * gain a bit for Doorbell Priority.  The field was absurdly
		 * large in the first place (14 bits) so we just use the T5
		 * and later limits and warn if a Queue ID is too large.
		 */
		WARN_ON(val & F_DBPRIO);

		/* If we're only writing a single TX Descriptor and we can use
		 * Inferred QID registers, we can use the Write Combining
		 * Gather Buffer; otherwise we use the simple doorbell.
		 */
		if (n == 1 && adap->tx_db_wc && q->bar2_qid == 0) {
			int index = (q->pidx
				     ? (q->pidx - 1)
				     : (q->size - 1));
			u64 *wr = (u64 *)&q->desc[index];

			cxgb_pio_copy((u64 __iomem *)
				      (q->bar2_addr + SGE_UDB_WCDOORBELL),
				      wr);
		} else {
			writel(val | V_QID(q->bar2_qid),
			       q->bar2_addr + SGE_UDB_KDOORBELL);
		}

		/* This Write Memory Barrier will force the write to the User
		 * Doorbell area to be flushed.  This is needed to prevent
		 * writes on different CPUs for the same queue from hitting
		 * the adapter out of order.  This is required when some Work
		 * Requests take the Write Combine Gather Buffer path (user
		 * doorbell area offset [SGE_UDB_WCDOORBELL..+63]) and some
		 * take the traditional path where we simply increment the
		 * PIDX (User Doorbell area SGE_UDB_KDOORBELL) and have the
		 * hardware DMA read the actual Work Request.
		 */
		wmb();
	}
}

/**
 *	inline_tx_skb - inline a packet's data into Tx descriptors
 *	@skb: the packet
 *	@q: the Tx queue where the packet will be inlined
 *	@pos: starting position in the Tx queue where to inline the packet
 *
 *	Inline a packet's contents directly into Tx descriptors, starting at
 *	the given position within the Tx DMA ring.
 *	Most of the complexity of this operation is dealing with wrap arounds
 *	in the middle of the packet we want to inline.
 */
static void inline_tx_skb(const struct sk_buff *skb, const struct sge_txq *q,
			  void *pos)
{
	u64 *p;
	int left = (void *)q->stat - pos;

	if (likely(skb->len <= left)) {
		if (likely(!skb->data_len))
			skb_copy_from_linear_data(skb, pos, skb->len);
		else
			skb_copy_bits(skb, 0, pos, skb->len);
		pos += skb->len;
	} else {
		skb_copy_bits(skb, 0, pos, left);
		skb_copy_bits(skb, left, q->desc, skb->len - left);
		pos = (void *)q->desc + (skb->len - left);
	}

	/* 0-pad to multiple of 16 */
	p = PTR_ALIGN(pos, 8);
	if ((uintptr_t)p & 8)
		*p = 0;
}

static void *inline_tx_skb_header(const struct sk_buff *skb,
				const struct sge_txq *q,  void *pos, int length)
{
	u64 *p;
	int left = (void *)q->stat - pos;

	if (likely(length <= left)) {
		memcpy(pos, skb->data, length);
		pos += length;
	} else {
		memcpy(pos, skb->data, left);
		memcpy(q->desc, skb->data + left, length - left);
		pos = (void *)q->desc + (length - left);
	}
	/* 0-pad to multiple of 16 */
	p = PTR_ALIGN(pos, 8);
	if ((uintptr_t)p & 8) {
		*p = 0;
		return p + 1;
	}
	return p;
}

/*
 * Figure out what HW csum a packet wants and return the appropriate control
 * bits. @inner_hdr_csum will indicate whether inner header checksum
 * needs to be calculated whenever the packet is an encapsulated packet.
 */
static u64 hwcsum(enum chip_type chip, const struct sk_buff *skb)
{
	int csum_type;
	u16 proto, ver;
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
	bool inner_hdr_csum = false;

	if (skb->encapsulation &&
	   (CHELSIO_CHIP_VERSION(chip) > CHELSIO_T4))
		inner_hdr_csum = true;

	if (inner_hdr_csum) {
		ver = inner_ip_hdr(skb)->version;
		proto = (ver == 4) ? inner_ip_hdr(skb)->protocol :
			 inner_ipv6_hdr(skb)->nexthdr;
	} else
#endif
	{
		ver = ip_hdr(skb)->version;
		proto = (ver == 4) ? ip_hdr(skb)->protocol :
			 ipv6_hdr(skb)->nexthdr;
	}

	if (ver == 4) {
		if (proto == IPPROTO_TCP)
			csum_type = TX_CSUM_TCPIP;
		else if (proto == IPPROTO_UDP)
			csum_type = TX_CSUM_UDPIP;
		else {
nocsum:			/*
			 * unknown protocol, disable HW csum
			 * and hope a bad packet is detected
			 */
			return F_TXPKT_L4CSUM_DIS;
		}
	} else {
		/*
		 * this doesn't work with extension headers
		 */

		if (proto == IPPROTO_TCP)
			csum_type = TX_CSUM_TCPIP6;
		else if (proto == IPPROTO_UDP)
			csum_type = TX_CSUM_UDPIP6;
		else
			goto nocsum;
	}

	if (likely(csum_type >= TX_CSUM_TCPIP)) {
		u64 hdr_len;
		int eth_hdr_len, l4_len;

#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
		if (inner_hdr_csum) {
			/* This allows checksum offload for all encapsulated
			 * packets like GRE etc..
			 */
			l4_len = skb_inner_network_header_len(skb);
			eth_hdr_len = skb_inner_network_offset(skb) - ETH_HLEN;
		} else
#endif
		{
			l4_len = skb_network_header_len(skb);
			eth_hdr_len = skb_network_offset(skb) - ETH_HLEN;
		}

		hdr_len = V_TXPKT_IPHDR_LEN(l4_len);
		if (CHELSIO_CHIP_VERSION(chip) <= CHELSIO_T5)
			hdr_len |= V_TXPKT_ETHHDR_LEN(eth_hdr_len);
		else
			hdr_len |= V_T6_TXPKT_ETHHDR_LEN(eth_hdr_len);
		return V_TXPKT_CSUM_TYPE(csum_type) | hdr_len;
	} else {
		int start = skb_transport_offset(skb);

		return V_TXPKT_CSUM_TYPE(csum_type) |
			V_TXPKT_CSUM_START(start) |
			V_TXPKT_CSUM_LOC(start + skb->csum_offset);
	}
}

static void eth_txq_stop(struct sge_eth_txq *q)
{
	netif_tx_stop_queue(q->txq);
	q->q.stops++;
}

static inline void txq_advance(struct sge_txq *q, unsigned int n)
{
	q->in_use += n;
	q->pidx += n;
	if (q->pidx >= q->size)
		q->pidx -= q->size;
}

#define MAX_COALESCE_LEN 64000

static inline int wraps_around(struct sge_txq *q, int ndesc)
{
	return (q->pidx + ndesc) > q->size ? 1 : 0;
}

/**
 * 	ship_tx_pkt_coalesce_wr - finalizes and ships a coalesce WR
 * 	@ adap: adapter structure
 * 	@txq: tx queue
 *
 * 	writes the different fields of the pkts WR and sends it.
 */
static inline int ship_tx_pkt_coalesce_wr(struct adapter *adap, struct sge_eth_txq *txq)
{
	u32 wr_mid;
	struct sge_txq *q = &txq->q;
	struct fw_eth_tx_pkts_wr *wr;
	unsigned int ndesc;

	/* fill the pkts WR header */
	wr = (void *)&q->desc[q->pidx];
	wr->op_pkd = htonl(V_FW_WR_OP(FW_ETH_TX_PKTS_WR));

	wr_mid = V_FW_WR_LEN16(DIV_ROUND_UP(q->coalesce.flits, 2));
	ndesc = flits_to_desc(q->coalesce.flits);
	
	if (q->coalesce.intr) {
		wr_mid |= F_FW_WR_EQUEQ | F_FW_WR_EQUIQ;
		q->coalesce.intr = false;
	}

	wr->equiq_to_len16 = htonl(wr_mid);
	wr->plen = cpu_to_be16(q->coalesce.len);
	wr->npkt = q->coalesce.idx;
	wr->r3 = 0;
	wr->type = q->coalesce.type;

	/* zero out coalesce structure members */
	q->coalesce.idx = 0;
	q->coalesce.flits = 0;
	q->coalesce.len = 0;

	txq_advance(q, ndesc);
	txq->coal_wr++;
	txq->coal_pkts += wr->npkt;
	ring_tx_db(adap, q, ndesc);

	return 1;
}

int t4_sge_coalesce_handler(struct adapter *adap, struct sge_eth_txq *eq)
{
	struct sge_txq *q = &eq->q;
	int hw_cidx = ntohs(ACCESS_ONCE(q->stat->cidx));
	int in_use = q->pidx - hw_cidx + flits_to_desc(q->coalesce.flits);

	/* in_use is what the hardware hasn't processed yet and not
	 * the tx descriptors not yet freed */
	if (in_use < 0)
		in_use += q->size;

#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
	/* Check if it is a loopback txq for vxlan packets */
	if (q->is_vxlan_lb) {
		if (in_use >= (q->size >> 1))
			q->coalesce.intr = true;

		if (q->coalesce.idx &&
		    (test_and_set_bit(VXLAN_TXQ_RUNNING, &q->flags) == 0)) {
			ship_tx_pkt_coalesce_wr(adap, eq);
			clear_bit(VXLAN_TXQ_RUNNING, &eq->q.flags);
		}
		return 1;
	}
#endif
	/* if the queue is stopped and half the descritors were consumed
	 * by the hw, restart the queue */
	if (netif_tx_queue_stopped(eq->txq) && in_use < (eq->q.size >> 1)) {
		netif_tx_wake_queue(eq->txq);
		eq->q.restarts++;
	} else if (!netif_tx_queue_stopped(eq->txq) && in_use >= (eq->q.size >> 1))
		eq->q.coalesce.intr = true;

	if (eq->q.coalesce.idx && __netif_tx_trylock(eq->txq)){
		if (eq->q.coalesce.idx)
			ship_tx_pkt_coalesce_wr(adap, eq);
		__netif_tx_unlock(eq->txq);
	}
	return 1; 
}

/**
 * 	should_tx_packet_coalesce - decides wether to coalesce an skb or not
 * 	@txq: tx queue where the skb is sent
 *	@skb: skb to be sent. NULL when we are trying to loopback received
 *	      vxlan packet (after updating it) for checksum verification.
 * 	@nflits: return value for number of flits needed
 * 	@adap: adapter structure
 *	@len: data length
 *
 *	This function decides if a packet should be coalesced or not. We start
 *	coalescing if half of the descriptors in a tx queue are used and stop
 *	when the number of used descriptors falls down to one fourth of the txq.
 */

static inline int should_tx_packet_coalesce(struct sge_eth_txq *txq, struct sk_buff *skb,
					    int *nflits, struct adapter *adap,
					    unsigned int len)
{
	struct skb_shared_info *si = NULL;
	struct sge_txq *q = &txq->q;
	unsigned int flits, ndesc;
	unsigned char type = 0, nr_frags;
	int credits, hw_cidx = ntohs(ACCESS_ONCE(q->stat->cidx));
	int in_use = q->pidx - hw_cidx + flits_to_desc(q->coalesce.flits);

	/* Check if it is called from transmit(normal) or receive(vxlan) path */
	if (skb) {
		si = skb_shinfo(skb);
		nr_frags = si->nr_frags;
	} else {
		/* We will be sending 2 fragments (inner packet and
		 * outer vxlan header) for looping back received vxlan packets.
		 */
		nr_frags = 2;
	}
	/* use coal WR type 1 when no frags are present */
	type = (nr_frags == 0) ? 1 : 0;

	if (in_use < 0)
		in_use += q->size;

	if (unlikely(type != q->coalesce.type && q->coalesce.idx))
		ship_tx_pkt_coalesce_wr(adap, txq);

	/* calculate the number of flits required for coalescing this packet
	 * without the 2 flits of the WR header. These are added further down
	 * if we are just starting in new PKTS WR. sgl_len doesn't account for
	 * the possible 16 bytes alignment ULP TX commands so we do it here.
	 */
	flits = (sgl_len(nr_frags + 1) + 1) & ~1U;
	if (type == 0)
		flits += (sizeof(struct ulp_txpkt) +
			  sizeof(struct ulptx_idata)) / sizeof(__be64);
	flits += sizeof(struct cpl_tx_pkt_core) / sizeof(__be64);
	*nflits = flits;

	/* if we're using less than 64 descriptors and the tx_coal module parameter
	 * is not equal to 2 stop coalescing and ship any pending WR */
	if ((adap->tx_coal != 2) && in_use < 64) {
		if (q->coalesce.idx)
			ship_tx_pkt_coalesce_wr(adap, txq);
		q->coalesce.ison = false;

		return 0;
	}

	/* we don't bother coalescing gso packets or skb larger than 4K or
	 * if it is an encapsulated packet, or FCoE frame.
	 */
	if (skb && (si->gso_size || skb->len > MAX_SKB_COALESCE_LEN
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
	    || skb->encapsulation
#endif
#ifdef CONFIG_PO_FCOE
	    || (skb->protocol == htons(ETH_P_FCOE))
#endif
	   )) {
		if (q->coalesce.idx)
			ship_tx_pkt_coalesce_wr(adap, txq);
		return 0;
	}

	/* if coalescing is on, the skb is added to a pkts WR. Otherwise,
	 * if the queue is half full we turn coalescing on but send this
	 * skb through the normal path to request a completion interrupt.
	 * if the queue is not half full we just send the skb through the
	 * normal path. */
	if (q->coalesce.ison) {
		if (q->coalesce.idx) {
			ndesc = DIV_ROUND_UP(q->coalesce.flits + flits, 8);
			credits = txq_avail(q) - ndesc;
			/* If credits are not available for this skb, send the
			 * already coalesced skbs and let the non-coalesce pass
			 * handle stopping the queue.
			 */
			if (unlikely(credits < ETHTXQ_STOP_THRES ||
				     wraps_around(q, ndesc))) {
				ship_tx_pkt_coalesce_wr(adap, txq);
				return 0;
			}
			/* If the max coalesce len or the max WR len is reached
			 * ship the WR and keep coalescing on.
			 */
			if (unlikely((q->coalesce.len + len >
				      MAX_COALESCE_LEN) ||
				     (q->coalesce.flits + flits >
				      q->coalesce.max))) {
				ship_tx_pkt_coalesce_wr(adap, txq);
				goto new;
			}
			return 1;
		} else
			goto new;
			
	} else if ((adap->tx_coal == 2 && in_use > 32) ||
		   in_use > (q->size >> 1)) {
		/* start coalescing and arm completion interrupt */
		q->coalesce.ison = true;
		q->coalesce.intr = true;
		return 0;
	} else
		return 0;

new:
	/* start a new pkts WR, the WR header is not filled below */
	flits += sizeof(struct fw_eth_tx_pkts_wr) /
			sizeof(__be64);
	ndesc = flits_to_desc(q->coalesce.flits + flits);
	credits = txq_avail(q) - ndesc;
	if (unlikely((credits < ETHTXQ_STOP_THRES) || wraps_around(q, ndesc)))
		return 0;
	q->coalesce.flits += 2;
	q->coalesce.type = type;
	q->coalesce.ptr = (unsigned char *) &q->desc[q->pidx] +
			  2 * sizeof(__be64);
	return 1;
}

/* Unwind any state built up by a successful should_tx_packet_coalesce()
 * call. Undo of coalesce.type and coalesce.ptr are not required as it will
 * be assigned to a new value in next should_tx_packet_coalesce() call.
 */
static inline void unwind_should_tx_packet_coalesce(struct sge_eth_txq *txq)
{
	struct sge_txq *q = &txq->q;

	if (!q->coalesce.idx)
		q->coalesce.flits -= 2;
}

/**
 * 	tx_do_packet_coalesce - add an skb to a coalesce WR
 *	@txq: sge_eth_txq used send the skb
 *	@skb: skb to be sent
 *	@flits: flits needed for this skb
 *	@adap: adapter structure
 *	@pi: port_info structure
 *	@addr: mapped address of the skb
 *
 *	Adds an skb to be sent as part of a coalesce WR by filling a
 *	ulp_tx_pkt command, ulp_tx_sc_imm command, cpl message and
 *	ulp_tx_sc_dsgl command.
 */
static inline int tx_do_packet_coalesce(struct sge_eth_txq *txq,
					struct sk_buff *skb,
					int flits, struct adapter *adap,
					const struct port_info *pi,
					dma_addr_t *addr)
{
	u32 ctrl0;
	u64 cntrl, *end;
	struct sge_txq *q = &txq->q;
	struct ulp_txpkt *mc;
	struct ulptx_idata *sc_imm;
	struct cpl_tx_pkt_core *cpl;
	struct tx_sw_desc *sd;
	unsigned int idx = q->coalesce.idx, len = skb->len;

	if (q->coalesce.type == 0) {
		mc = (struct ulp_txpkt *) q->coalesce.ptr;
		mc->cmd_dest = htonl(V_ULPTX_CMD(4) | V_ULP_TXPKT_DEST(0) |
				V_ULP_TXPKT_FID(adap->sge.fw_evtq.cntxt_id) |
				F_ULP_TXPKT_RO);
		mc->len = htonl(DIV_ROUND_UP(flits, 2));

		sc_imm = (struct ulptx_idata *) (mc + 1);
		sc_imm->cmd_more = htonl(V_ULPTX_CMD(ULP_TX_SC_IMM) | F_ULP_TX_SC_MORE);
		sc_imm->len = htonl(sizeof(*cpl));
		end = (u64 *) mc + flits;
		cpl = (struct cpl_tx_pkt_core *) (sc_imm + 1);
	} else {
		end = (u64 *) q->coalesce.ptr + flits;
		cpl = (struct cpl_tx_pkt_core *) q->coalesce.ptr;
	}

	/* update coalesce structure for this txq */
	q->coalesce.flits += flits;
	q->coalesce.ptr += flits * sizeof(__be64);
	q->coalesce.len += skb->len;

	/* fill the cpl message, same as in t4_eth_xmit, this should be kept
	 * similar to t4_eth_xmit
	 */
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		cntrl = hwcsum(adap->params.chip, skb) | F_TXPKT_IPCSUM_DIS;
		txq->tx_cso++;
	} else
		cntrl = F_TXPKT_L4CSUM_DIS | F_TXPKT_IPCSUM_DIS;

	if (skb_vlan_tag_present(skb)) {
		txq->vlan_ins++;
		cntrl |= F_TXPKT_VLAN_VLD | V_TXPKT_VLAN(skb_vlan_tag_get(skb));
	}

	ctrl0 = V_TXPKT_OPCODE(CPL_TX_PKT_XT) | V_TXPKT_INTF(pi->tx_chan) |
		V_TXPKT_PF(adap->pf);
#ifdef CONFIG_CXGB4_DCB
	if (is_t4(adap->params.chip))
		ctrl0 |= V_TXPKT_OVLAN_IDX(txq->dcb_prio);
	else
		ctrl0 |= V_TXPKT_T5_OVLAN_IDX(txq->dcb_prio);
#endif
	cpl->ctrl0 = htonl(ctrl0);
	cpl->pack = htons(0);
	cpl->len = htons(len);
	cpl->ctrl1 = cpu_to_be64(cntrl);

	write_sgl(skb, q, (struct ulptx_sgl *)(cpl + 1), end, 0,
		  addr);
	skb_orphan(skb);

	/* store pointers to the skb and the sgl used in free_tx_desc.
	 * each tx desc can hold two pointers corresponding to the value
	 * of ETH_COALESCE_PKT_PER_DESC */
	sd = &q->sdesc[q->pidx + (idx >> 1)];
	sd->coalesce.skb[idx & 1] = skb;
	sd->coalesce.sgl[idx & 1] = (struct ulptx_sgl *)(cpl + 1);
	sd->coalesce.idx = (idx & 1) + 1;

	/* send the coaelsced work request if max reached */
	if (++q->coalesce.idx == ETH_COALESCE_PKT_NUM)
		ship_tx_pkt_coalesce_wr(adap, txq);

	return NETDEV_TX_OK;
}

#ifdef CONFIG_PO_FCOE

#define CXGB_FCOE_NUM_IMM_PPODS		4

#define CXGB_FCOE_NUM_IMM_PPOD_BYTES	\
	(CXGB_FCOE_NUM_IMM_PPODS * CXGB_FCOE_PPOD_SIZE)

#define WR_LEN_MAX_PPODS	\
	(sizeof(struct ulp_mem_io) + \
	(2 * sizeof(struct ulptx_idata)) + \
	CXGB_FCOE_NUM_IMM_PPOD_BYTES)

#define WR_CRED_MAX_PPODS	(DIV_ROUND_UP(WR_LEN_MAX_PPODS, X_IDXSIZE_UNIT))

#define WR_LEN_SET_TCBS \
	(sizeof(struct fw_pofcoe_ulptx_wr) + \
	 (5 * ALIGN(sizeof(struct cpl_set_tcb_field), 16)))

#define WR_LEN16_SET_TCBS DIV_ROUND_UP(WR_LEN_SET_TCBS, 16)

#define WR_NDESC_SET_TCBS DIV_ROUND_UP(WR_LEN_SET_TCBS, X_IDXSIZE_UNIT)

static inline int
calc_ddp_credits(struct adapter *adap, struct sk_buff *skb,
		 unsigned int nppods)
{
	unsigned int n_full = (nppods / CXGB_FCOE_NUM_IMM_PPODS);
	int credits = n_full * WR_CRED_MAX_PPODS;
	unsigned int last_ppod_len = (nppods % CXGB_FCOE_NUM_IMM_PPODS) *
					CXGB_FCOE_PPOD_SIZE;
	unsigned int last_len;
	unsigned int flits;
	unsigned int chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);

	if (last_ppod_len) {
		last_len = sizeof(struct ulp_mem_io) +
				(2 * sizeof(struct ulptx_idata)) + last_ppod_len;
		credits += DIV_ROUND_UP(last_len, X_IDXSIZE_UNIT);
	}

	credits += WR_NDESC_SET_TCBS;

	flits = calc_tx_flits(skb, chip_ver);
	credits += flits_to_desc(flits);

	return credits;
}

static inline void
cxgb_fcoe_set_tcb_field(struct cpl_set_tcb_field *req, unsigned int tid,
			unsigned int word, u64 mask, u64 val)
{
	struct ulp_txpkt *txpkt = (struct ulp_txpkt *)req;
	struct ulptx_idata *sc = (struct ulptx_idata *)(txpkt + 1);

	txpkt->cmd_dest = htonl(V_ULPTX_CMD(ULP_TX_PKT) | V_ULP_TXPKT_DEST(0));
	txpkt->len = htonl((tid << 8) | DIV_ROUND_UP(sizeof(*req), 16));
	sc->cmd_more = htonl(V_ULPTX_CMD(ULP_TX_SC_IMM));
	sc->len = htonl(sizeof(*req) - sizeof(struct work_request_hdr));
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_SET_TCB_FIELD, tid));
	req->reply_ctrl = htons(V_NO_REPLY(1) | V_REPLY_CHAN(0) |
				V_QUEUENO(0));
	req->word_cookie = htons(V_WORD(word) | V_COOKIE(0));
	req->mask = cpu_to_be64(mask);
	req->val = cpu_to_be64(val);
	sc = (struct ulptx_idata *)(req + 1);
	sc->cmd_more = htonl(V_ULPTX_CMD(ULP_TX_SC_NOOP));
	sc->len = htonl(0);
}

static inline void
cxgb_fcoe_set_tcbs(struct adapter *adap, const struct port_info *pi,
		   struct sge_eth_txq *q,
		   struct cxgb_fcoe_ddp *ddp, u16 iqid)
{
	struct cpl_set_tcb_field *req;
	struct fw_pofcoe_ulptx_wr *wr;
	u8 buf[WR_LEN_SET_TCBS] = {0};
	u8 *end, *wrp = (u8 *)&q->q.desc[q->q.pidx];
	unsigned int len = ALIGN(sizeof(struct cpl_set_tcb_field), 16);

	end = wrp + WR_LEN_SET_TCBS;
	wr = (struct fw_pofcoe_ulptx_wr *)
		((u8 *)end > (u8 *)q->q.stat ? buf : wrp);

	wr->op_pkd = htonl(V_FW_WR_OP(FW_POFCOE_ULPTX_WR));
	wr->equiq_to_len16 = htonl(V_FW_WR_LEN16(WR_LEN16_SET_TCBS));

	req = (struct cpl_set_tcb_field *)(wr + 1);
	cxgb_fcoe_set_tcb_field(req, ddp->tid, W_TCB_RX_DDP_BUF0_TAG,
				V_TCB_RX_DDP_BUF0_TAG(M_TCB_RX_DDP_BUF0_TAG),
				V_TCB_RX_DDP_BUF0_TAG(
					V_PPOD_TAG(ddp->ppod_tag)));

	req = (struct cpl_set_tcb_field *)((u8 *)req + len);
	cxgb_fcoe_set_tcb_field(req, ddp->tid, W_TCB_RX_DDP_BUF0_OFFSET,
				V_TCB_RX_DDP_BUF0_OFFSET(
					M_TCB_RX_DDP_BUF0_OFFSET) |
				V_TCB_RX_DDP_BUF0_LEN(M_TCB_RX_DDP_BUF0_LEN),
				V_TCB_RX_DDP_BUF0_OFFSET(0) |
				V_TCB_RX_DDP_BUF0_LEN(ddp->xfer_len));

	req = (struct cpl_set_tcb_field *)((u8 *)req + len);
	cxgb_fcoe_set_tcb_field(req, ddp->tid, W_TCB_T_STATE,
				V_TCB_T_STATE(M_TCB_T_STATE) |
				V_TCB_RSS_INFO(M_TCB_RSS_INFO),
				V_TCB_T_STATE(0x4) |
				V_TCB_RSS_INFO(iqid));

	req = (struct cpl_set_tcb_field *)((u8 *)req + len);
	cxgb_fcoe_set_tcb_field(req, ddp->tid, W_TCB_T_FLAGS,
				V_TF_NON_OFFLOAD(1), 0);

	req = (struct cpl_set_tcb_field *)((u8 *)req + len);
	cxgb_fcoe_set_tcb_field(req, ddp->tid, W_TCB_RX_DDP_FLAGS,
				V_TF_DDP_BUF_INF(1) |
				V_TF_DDP_INDICATE_OUT(1) |
				V_TF_DDP_BUF0_INDICATE(1) |
				V_TF_DDP_BUF0_VALID(1) |
				V_TF_DDP_OFF(1),
				V_TF_DDP_BUF_INF(1) |
				V_TF_DDP_INDICATE_OUT(1) |
				V_TF_DDP_BUF0_INDICATE(1) |
				V_TF_DDP_BUF0_VALID(1) |
				V_TF_DDP_OFF(0));

	if (unlikely((u8 *)end > (u8 *)q->q.stat)) {
		unsigned int part0 = (u8 *)q->q.stat - (u8 *)wrp, part1;

		if (likely(part0))
			memcpy(wrp, buf, part0);
		part1 = (u8 *)end - (u8 *)q->q.stat;
		memcpy(q->q.desc, (u8 *)buf + part0, part1);
	}

	/* Post this WR */
	txq_advance(&q->q, WR_NDESC_SET_TCBS);
	ring_tx_db(adap, &q->q, WR_NDESC_SET_TCBS);
}

static inline void
cxgb_setup_ppods(struct adapter *adap, const struct port_info *pi,
		 struct sge_eth_txq *q, struct cxgb_fcoe_ddp *ddp)
{
	unsigned int i, j, pidx;
	struct pagepod *p;
	u8 *wrp = (u8 *)&q->q.desc[q->q.pidx];
	struct fw_pofcoe_ulptx_wr *mwr;
	struct ulp_mem_io *wr;
	struct ulptx_idata *sc;
	unsigned int tid = ddp->tid;
	unsigned int color = 0;
	unsigned int nppods = ddp->nppods;
	unsigned int tag = ddp->ppod_tag;
	unsigned int maxoff = ddp->xfer_len;
	unsigned int pg_off = ddp->first_pg_off;
	unsigned int ppod_addr = tag * CXGB_FCOE_PPOD_SIZE +
					adap->vres.ddp.start;
	unsigned int len, podchunk, ndesc;
	u8 buf[WR_LEN_MAX_PPODS] = {0};
	u8 *end, *to;
	__be32 cmd = htonl(V_ULPTX_CMD(ULP_TX_MEM_WRITE));

	if (is_t4(adap->params.chip))
		cmd |= htonl(V_ULP_MEMIO_ORDER(1));
	else
		cmd |= htonl(V_T5_ULP_MEMIO_IMM(1));

	for (i = 0; i < nppods; ppod_addr += podchunk) {
		unsigned int ppodout = 0;

		podchunk = ((nppods - i) >= CXGB_FCOE_NUM_IMM_PPODS) ?
				CXGB_FCOE_NUM_IMM_PPODS : (nppods - i);
		podchunk *= CXGB_FCOE_PPOD_SIZE;

		len = roundup(sizeof(*wr) + (2 * sizeof(*sc)) + podchunk, 16);
		end = wrp + len;
		to = (u8 *)end > (u8 *)q->q.stat ? buf : wrp;

		mwr = (struct fw_pofcoe_ulptx_wr *)to;
		mwr->op_pkd = htonl(V_FW_WR_OP(FW_POFCOE_ULPTX_WR));
		mwr->equiq_to_len16 = htonl(V_FW_WR_LEN16(
						DIV_ROUND_UP(len, 16)));
		wr = (struct ulp_mem_io *)to;
		wr->cmd = cmd;
		wr->dlen = htonl(V_ULP_MEMIO_DATA_LEN(podchunk / 32));
		wr->len16 = htonl((ddp->tid << 8) |
					DIV_ROUND_UP(len - sizeof(wr->wr), 16));
		wr->lock_addr = htonl(V_ULP_MEMIO_ADDR(ppod_addr >> 5));
		sc = (struct ulptx_idata *)(wr + 1);
		sc->cmd_more = htonl(V_ULPTX_CMD(ULP_TX_SC_IMM));
		sc->len = htonl(podchunk);
		p = (struct pagepod *)(sc + 1);

		do {
			pidx = 4 * i;
			if (likely(i < nppods - CXGB_FCOE_NUM_SENTINEL_PPODS)) {
				p->vld_tid_pgsz_tag_color =
					cpu_to_be64(F_PPOD_VALID |
							V_PPOD_TID(tid) |
							V_PPOD_TAG(tag) |
							V_PPOD_COLOR(color));
				p->len_offset = cpu_to_be64(V_PPOD_LEN(maxoff) |
							V_PPOD_OFST(pg_off));
				p->rsvd = 0;
				for (j = 0; j < 5; ++j, ++pidx)
					p->addr[j] = pidx < ddp->npages ?
					    cpu_to_be64(ddp->ppod_gl[pidx]) : 0;
			} else {
				/* mark sentinel page pods invalid */
				p->vld_tid_pgsz_tag_color = 0;
			}
			p++;
			ppodout += CXGB_FCOE_PPOD_SIZE;
			i++;

		} while (ppodout < podchunk);

		sc = (struct ulptx_idata *)p;
		sc->cmd_more = htonl(V_ULPTX_CMD(ULP_TX_SC_NOOP));
		sc->len = htonl(0);

		if (unlikely((u8 *)end > (u8 *)q->q.stat)) {
			unsigned int part0 = (u8 *)q->q.stat - (u8 *)wrp, part1;

			if (likely(part0))
				memcpy(wrp, buf, part0);
			part1 = (u8 *)end - (u8 *)q->q.stat;
			memcpy(q->q.desc, (u8 *)buf + part0, part1);
		}

		/* Post this WR */
		ndesc = DIV_ROUND_UP(len, X_IDXSIZE_UNIT);
		txq_advance(&q->q, ndesc);
		ring_tx_db(adap, &q->q, ndesc);

		wrp = (u8 *)&q->q.desc[q->q.pidx];
	} /* for all pagepod chunks */
}

static inline int
cxgb_fcoe_offload(struct sk_buff *skb, struct net_device *dev,
		  struct adapter *adap, const struct port_info *pi,
		  struct sge_eth_txq *q, u64 *cntrl)
{
	const struct cxgb_fcoe *fcoe = &pi->fcoe;
	struct cxgb_fcoe_ddp *ddp;
	struct ethhdr *eh;
	struct fc_frame_header *fh;
	struct sge_eth_rxq *rxq;
	unsigned int ndesc;
	int qidx, credits;
	u16 xid, vlan_tci = 0;
	u32 fctl;

	if (!(fcoe->flags & CXGB_FCOE_ENABLED))
		return 0;

	if (skb->protocol != htons(ETH_P_FCOE))
		return 0;

	skb_reset_mac_header(skb);
	skb->mac_len = sizeof(struct ethhdr);

	skb_set_network_header(skb, skb->mac_len);
	skb_set_transport_header(skb, skb->mac_len + sizeof(struct fcoe_hdr));

	if (!cxgb_fcoe_sof_eof_supported(adap, skb))
		return -ENOTSUPP;

	/* FC CRC offload */
	*cntrl = V_TXPKT_CSUM_TYPE(TX_CSUM_FCOE) |
		     F_TXPKT_L4CSUM_DIS | F_TXPKT_IPCSUM_DIS |
		     V_TXPKT_CSUM_START(CXGB_FCOE_TXPKT_CSUM_START) |
		     V_TXPKT_CSUM_END(CXGB_FCOE_TXPKT_CSUM_END) |
		     V_TXPKT_CSUM_LOC(CXGB_FCOE_TXPKT_CSUM_END);

	if (skb_vlan_tag_present(skb)) {
		vlan_tci = skb_vlan_tag_get(skb);
		vlan_tci |= ((skb->priority & 0x7) << VLAN_PRIO_SHIFT);
	}

	fh = (struct fc_frame_header *)(skb_transport_header(skb));

	/* Program DDP for XFER_RDY frames only */
	if (fh->fh_r_ctl != FC_RCTL_DD_DATA_DESC)
		return 0;

	fctl = ntoh24(fh->fh_f_ctl);
	if (!(fctl & FC_FC_EX_CTX))
		return 0;

	xid = be16_to_cpu(fh->fh_rx_id);

	if (xid >= CXGB_FCOE_MAX_XCHGS_PORT)
		return 0;

	ddp = (struct cxgb_fcoe_ddp *)&fcoe->ddp[xid];

	/* Upper layer may not have requested for ddp_setup */
	if (!ddp->sgl)
		return 0;

	eh = (struct ethhdr *)skb_mac_header(skb);
	/* Save d_id, smac, dmac, vlan */
	memcpy(ddp->h_source, eh->h_source, ETH_ALEN);
	memcpy(ddp->h_dest, eh->h_dest, ETH_ALEN);
	memcpy(ddp->d_id, fh->fh_d_id, 3);
	ddp->vlan_tci = vlan_tci;

	/*
	 * program ppods on the card. They should already have been
	 * allocated in cxgb_fcoe_ddp_setup
	 */
	/* Calculate number credits required for ddp */
	ndesc = calc_ddp_credits(adap, skb, ddp->nppods);

	credits = txq_avail(&q->q) - ndesc;

	if (unlikely(credits < 0))
		return -EBUSY;

	/* Get an associated iqid */
	qidx = skb_get_queue_mapping(skb);
	rxq = &adap->sge.ethrxq[qidx + pi->first_qset];

	cxgb_fcoe_set_tcbs(adap, pi, q, ddp, rxq->rspq.abs_id);

	cxgb_setup_ppods(adap, pi, q, ddp);

	dev->trans_start = jiffies;

	reclaim_completed_tx(adap, &q->q, true);

	return 0;
}
#endif /* CONFIG_PO_FCOE */

#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
static inline void
t6_fill_tnl_lso(struct sk_buff *skb, struct cpl_tx_tnl_lso *tnl_lso,
		enum cpl_tx_tnl_lso_type tnl_type)
{
	u32 val;
	int in_eth_xtra_len;
	int l3hdr_len = skb_network_header_len(skb);
	int eth_xtra_len = skb_network_offset(skb) - ETH_HLEN;
	const struct skb_shared_info *ssi = skb_shinfo(skb);
	bool v6 = (ip_hdr(skb)->version == 6);

	val = V_CPL_TX_TNL_LSO_OPCODE(CPL_TX_TNL_LSO) |
	      F_CPL_TX_TNL_LSO_FIRST |
	      F_CPL_TX_TNL_LSO_LAST |
	      (v6 ? F_CPL_TX_TNL_LSO_IPV6OUT : 0) |
	      V_CPL_TX_TNL_LSO_ETHHDRLENOUT(eth_xtra_len / 4) |
	      V_CPL_TX_TNL_LSO_IPHDRLENOUT(l3hdr_len / 4) |
	      (v6 ? 0 : F_CPL_TX_TNL_LSO_IPHDRCHKOUT) |
	      F_CPL_TX_TNL_LSO_IPLENSETOUT |
	      (v6 ? 0 : F_CPL_TX_TNL_LSO_IPIDINCOUT);
	tnl_lso->op_to_IpIdSplitOut = htonl(val);

	tnl_lso->IpIdOffsetOut = 0;

	/* Get the tunnel header length */
	val = skb_inner_mac_header(skb) - skb_mac_header(skb);
	in_eth_xtra_len = skb_inner_network_header(skb) -
			  skb_inner_mac_header(skb) - ETH_HLEN;

	switch (tnl_type) {
	case TX_TNL_TYPE_VXLAN:
		tnl_lso->UdpLenSetOut_to_TnlHdrLen =
			htons(F_CPL_TX_TNL_LSO_UDPCHKCLROUT |
			F_CPL_TX_TNL_LSO_UDPLENSETOUT);
		break;
	case TX_TNL_TYPE_NVGRE:
	default:
		tnl_lso->UdpLenSetOut_to_TnlHdrLen = 0;
		break;
	}

	tnl_lso->UdpLenSetOut_to_TnlHdrLen |=
		 htons(V_CPL_TX_TNL_LSO_TNLHDRLEN(val) |
		       V_CPL_TX_TNL_LSO_TNLTYPE(tnl_type));

	tnl_lso->r1 = 0;

	val = V_CPL_TX_TNL_LSO_ETHHDRLEN(in_eth_xtra_len / 4) |
	      V_CPL_TX_TNL_LSO_IPV6(inner_ip_hdr(skb)->version == 6) |
	      V_CPL_TX_TNL_LSO_IPHDRLEN(skb_inner_network_header_len(skb) / 4) |
	      V_CPL_TX_TNL_LSO_TCPHDRLEN(inner_tcp_hdrlen(skb) / 4);
	tnl_lso->Flow_to_TcpHdrLen = htonl(val);

	tnl_lso->IpIdOffset = htons(0);

	tnl_lso->IpIdSplit_to_Mss = htons(V_CPL_TX_TNL_LSO_MSS(ssi->gso_size));
	tnl_lso->TCPSeqOffset = htonl(0);
	tnl_lso->EthLenOffset_Size = htonl(V_CPL_TX_TNL_LSO_SIZE(skb->len));
}

/**
 *	t5_fill_eo_wr - prepares the encapsulated firmware work request
 *	@skb: encapulated skb to be segmented
 *	@eo_wr: work request to be filled
 *	@q: sge_eth_txq used send the skb
 *	@end: pointer to the end of the SGL
 *	@immediate: if the packet is small enough to send as immediate data
 *
 *	Fills the fw_eth_tx_eo_wr work request with the vxlan info
 *	from the skb. Headers will be sent as immediate data right after
 *	the cpl_tx_pkt_core cpl. end pointer will be updated (wrapped around
 *	if needed) as we copy the headers. Returns the pointer to the location
 *	for writing SGL.
 */
static inline u64 *
t5_fill_eo_wr(struct sk_buff *skb, struct fw_eth_tx_eo_wr *eo_wr,
	      struct sge_eth_txq *q, u64 **end, bool immediate)
{
	struct iphdr *iph;
	struct fw_eth_tx_eo_vxlanseg *vxlanseg;
	u64 *pos, *before;
	unsigned int left;
	int tcp_hdr_offset, tcp_hdr_len, len, imm_data_len;
	struct sge_txq *txq = &q->q;
	struct cpl_tx_pkt_core *cpl;

	tcp_hdr_offset = (skb_inner_transport_header(skb) - skb->data);
	tcp_hdr_len = inner_tcp_hdrlen(skb);
	imm_data_len = tcp_hdr_offset + tcp_hdr_len;

	/* T5 won't calculate checksum for outer IP header.
	 * Hence calculating it in the driver.
	 */
	if (vlan_get_protocol(skb) == htons(ETH_P_IP)) {
		iph = ip_hdr(skb);
		iph->tot_len = 0;
		iph->check = 0;
		iph->check = ip_fast_csum((u8 *)iph, iph->ihl);
	}

	len = sizeof(struct cpl_tx_pkt_core) + imm_data_len;
	eo_wr->op_immdlen = htonl(V_FW_WR_OP(FW_ETH_TX_EO_WR) |
				  V_FW_WR_IMMDLEN(len));
	vxlanseg = &eo_wr->u.vxlanseg;
	vxlanseg->type = FW_ETH_TX_EO_TYPE_VXLANSEG;
	vxlanseg->iphdroffout = ETH_HLEN;
	vxlanseg->vxlanhdroff = htons(ETH_HLEN +
				      sizeof(struct udphdr) +
				      skb_network_header_len(skb));
	vxlanseg->iphdroffin = htons(skb_inner_network_offset(skb));
	vxlanseg->tcphdroffin = htons(tcp_hdr_offset);
	vxlanseg->mss =  htons(skb_shinfo(skb)->gso_size);
	vxlanseg->plen = htonl(skb->len - imm_data_len);

	cpl = (void *)(eo_wr + 1);
	before = (u64 *) (cpl + 1);
	pos = before;
	if (!immediate) {
		/* One of the requirement for segmentation is to include
		 * all headers as immediate data.
		 * Copy the headers after the cpl_tx_pkt_core.
		 */
		pos = (void *)inline_tx_skb_header(skb, &q->q, (void *)pos,
						   imm_data_len);
		/* The WR headers  may not fit within one descriptor.
		 * So we need to deal with wrap-around here.
		 */
		if (before > (u64 *)pos) {
			left = (u8 *)*end - (u8 *)txq->stat;
			*end = (void *)txq->desc + left;
		}

		/* If current position is already at the end of the
		 * ofld queue, reset the current to point to
		 * start of the queue and update the end ptr as well.
		 */
		if (pos == (u64 *) txq->stat) {
			left = (u8 *)*end - (u8 *)txq->stat;
			*end = (void *)txq->desc + left;
			pos = (void *)txq->desc;
		}
		q->tso++;
		q->tx_cso += skb_shinfo(skb)->gso_segs;
	}
	return pos;
}
#endif

/**
 *	t4_eth_xmit - add a packet to an Ethernet Tx queue
 *	@skb: the packet
 *	@dev: the egress net device
 *
 *	Add a packet to an SGE Ethernet Tx queue.  Runs with softirqs disabled.
 */
int t4_eth_xmit(struct sk_buff *skb, struct net_device *dev)
{
	u32 wr_mid, ctrl0, op;
	u64 cntrl = F_TXPKT_L4CSUM_DIS | F_TXPKT_IPCSUM_DIS;
	u64 *end, *sgl;
	int qidx, credits;
	unsigned int flits = 0, ndesc, cflits;
	struct adapter *adap;
	struct sge_eth_txq *q;
	const struct port_info *pi;
	struct fw_eth_tx_pkt_wr *wr;
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
	struct fw_eth_tx_eo_wr *eo_wr = NULL;
	int tcp_hdr_offset = 0, tcp_hdr_len = 0, imm_data_len = 0;
	enum cpl_tx_tnl_lso_type tnl_type = TX_TNL_TYPE_OPAQUE;
#endif
	struct cpl_tx_pkt_core *cpl;
	const struct skb_shared_info *ssi = skb_shinfo(skb);
	dma_addr_t addr[MAX_SKB_FRAGS + 1];
	int loopback = 0;
	bool immediate = false;
	int len, max_pkt_len;
	unsigned int chip_ver;
#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
	bool ptp_enabled = is_ptp_enabled(skb, dev);
#else
	bool ptp_enabled = 0;
#endif
#ifdef CONFIG_PO_FCOE
	int err;
#endif /* CONFIG_PO_FCOE */

	/*
	 * The chip min packet length is 10 octets but play safe and reject
	 * anything shorter than an Ethernet header.
	 */
	if (unlikely(skb->len < ETH_HLEN)) {
out_free:	dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	/* Discard the packet if the length is greater than mtu */
	max_pkt_len = ETH_HLEN + dev->mtu;
	if (skb_vlan_tag_present(skb))
		max_pkt_len += VLAN_HLEN;
	if (!skb_shinfo(skb)->gso_size && (unlikely(skb->len > max_pkt_len)))
		goto out_free;

	pi = netdev_priv(dev);
	if (ma_fail_check_rx_pkt((struct port_info *)pi, skb))
		loopback = 1;
	adap = pi->adapter;
	qidx = skb_get_queue_mapping(skb);

	if (ptp_enabled) {
#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
		spin_lock(&adap->ptp_lock);
		if (!(adap->ptp_tx_skb)) {
			skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
			adap->ptp_tx_skb = skb_get(skb);
		} else {
			spin_unlock(&adap->ptp_lock);
			goto out_free;
		}
		q = &adap->sge.ptptxq;
		reclaim_completed_tx(adap, &q->q, true);
#endif
	} else {
		q = &adap->sge.ethtxq[qidx + pi->first_qset];
		reclaim_completed_tx(adap, &q->q, true);
		/* align the end fo coalesce WR to a 512 byte boundary */
		q->q.coalesce.max = (8 - (q->q.pidx & 7)) * 8;
	}

	skb_tx_timestamp(skb);
	/* check if we can do packet coalescing */
	if (adap->tx_coal && should_tx_packet_coalesce(q, skb, &cflits, adap,
						       skb->len) &&
	    !ptp_enabled) {
		if (unlikely(map_skb(adap->pdev_dev, skb, addr) < 0)) {
			q->mapping_err++;
			unwind_should_tx_packet_coalesce(q);
			goto out_free;
		}
		return tx_do_packet_coalesce(q, skb, cflits, adap, pi, addr);
	}

#ifdef CONFIG_PO_FCOE
	err = cxgb_fcoe_offload(skb, dev, adap, pi, q, &cntrl);
	if (unlikely(err == -EBUSY)) {
		eth_txq_stop(q);
		dev_err(adap->pdev_dev,
			"%s: (fcoe) Tx ring %u full while queue awake!\n",
			dev->name, qidx);
		return NETDEV_TX_BUSY;
	} else if (unlikely(err == -ENOTSUPP)) {
			goto out_free;
	}
#endif /* CONFIG_PO_FCOE */

	chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);
	if (is_eth_imm(skb, chip_ver))
		immediate = true;

#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
	/* We advertise GSO for UDP_TUNNEL and GRE packets.
	 * Hence encapsulation and gso_size will be set for
	 * VxLAN and GRE packets alone.
	 */
	if (skb->encapsulation && (chip_ver > CHELSIO_T4))
		switch (chip_ver) {
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,4))
		case CHELSIO_T6:
			tnl_type = cxgb_encap_offload_supported(skb);
			break;
#endif
		default:
			tnl_type = TX_TNL_TYPE_VXLAN;
		}
#endif
	flits = calc_tx_flits(skb, chip_ver);

#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
	if (!immediate && tnl_type && ssi->gso_size &&
	    (chip_ver == CHELSIO_T5)) {
		/* Incase of encapsulation segmentation offload,
		 * header goes as Immediate data. Consider this
		 * length while calculating flits needed.
		 */
		tcp_hdr_offset = (skb_inner_transport_header(skb) - skb->data);
		tcp_hdr_len = inner_tcp_hdrlen(skb);
		imm_data_len = tcp_hdr_offset + tcp_hdr_len;
		/* Aligning it to 16B for SGL start location */
		flits += DIV_ROUND_UP(DIV_ROUND_UP(imm_data_len, 16) * 16, 8);
	}
#endif

	ndesc = flits_to_desc(flits);
	credits = txq_avail(&q->q) - ndesc;

	if (unlikely(credits < 0)) {
		eth_txq_stop(q);
		dev_err(adap->pdev_dev,
			"%s: Tx ring %u full while queue awake!\n",
			dev->name, qidx);
		return NETDEV_TX_BUSY;
	}

#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
	/* All headers will be sent as immediate data for eo_wr.
	 * Hence adjust the skb->data pointer for dma mapping.
	 */
	if (!immediate && tnl_type && ssi->gso_size && (chip_ver == CHELSIO_T5))
		__skb_pull(skb, imm_data_len);
#endif

    	if (!immediate &&
	    unlikely(map_skb(adap->pdev_dev, skb, addr) < 0)) {
		q->mapping_err++;
#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
		if (ptp_enabled)
			spin_unlock(&adap->ptp_lock);
#endif
		goto out_free;
	}

	wr_mid = V_FW_WR_LEN16(DIV_ROUND_UP(flits, 2));
	if (unlikely(credits < ETHTXQ_STOP_THRES)) {
		eth_txq_stop(q);
		wr_mid |= F_FW_WR_EQUEQ | F_FW_WR_EQUIQ;
	}

	/* request tx completion if needed for tx coalescing */
	if (adap->tx_coal && q->q.coalesce.intr) {
		wr_mid |= F_FW_WR_EQUEQ | F_FW_WR_EQUIQ;
		q->q.coalesce.intr = false;
	}

	wr = (void *)&q->q.desc[q->q.pidx];
	wr->equiq_to_len16 = htonl(wr_mid);
	wr->r3 = cpu_to_be64(0);
	end = (u64 *)wr + flits;

	len = immediate ? skb->len : 0;
	len += sizeof(*cpl);
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
	if (tnl_type && ssi->gso_size && (chip_ver == CHELSIO_T5)) {
		eo_wr = (void *)&q->q.desc[q->q.pidx];
		end = (u64 *)eo_wr + flits;
		/* Adjust skb data pointer for t5_fill_eo_wr to
		 * copy headers as immediate data.
		 */
		__skb_push(skb, imm_data_len);
		sgl = t5_fill_eo_wr(skb, eo_wr, q, &end, immediate);
		cntrl = hwcsum(adap->params.chip, skb);
		cpl = (void *)(eo_wr + 1);
		/* Done copying headers. Change the data pointer for dma'ing */
		__skb_pull(skb, imm_data_len);
		len += imm_data_len;
	} else
#endif
	if (ssi->gso_size) {
		struct cpl_tx_pkt_lso_core *lso = (void *)(wr + 1);
		bool v6 = (ssi->gso_type & SKB_GSO_TCPV6) != 0;
		int l3hdr_len = skb_network_header_len(skb);
		int eth_xtra_len = skb_network_offset(skb) - ETH_HLEN;

#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
		struct cpl_tx_tnl_lso *tnl_lso = (void *)(wr + 1);

		if (tnl_type)
			len += sizeof(*tnl_lso);
		else
#endif
			len += sizeof(*lso);

		wr->op_immdlen = htonl(V_FW_WR_OP(FW_ETH_TX_PKT_WR) |
				     V_FW_WR_IMMDLEN(len));
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
		if (tnl_type) {
			struct iphdr *iph = ip_hdr(skb);

			t6_fill_tnl_lso(skb, tnl_lso, tnl_type);

			cpl = (void *)(tnl_lso + 1);
			/* Driver is expected to compute partial checksum that
			 * does not include the IP Total Length.
			 */
			if (iph->version == 4) {
				iph->check = 0;
				iph->tot_len = 0;
				iph->check = (u16)(~ip_fast_csum((u8 *)iph,
								 iph->ihl));
			}

			if (skb->ip_summed == CHECKSUM_PARTIAL)
				cntrl = hwcsum(adap->params.chip, skb);
		} else
#endif
		{
			u32 ctrl = V_LSO_OPCODE(CPL_TX_PKT_LSO) |
				   F_LSO_FIRST_SLICE |
				   F_LSO_LAST_SLICE |
				   V_LSO_IPV6(v6) |
				   V_LSO_ETHHDR_LEN(eth_xtra_len / 4) |
				   V_LSO_IPHDR_LEN(l3hdr_len / 4) |
				   V_LSO_TCPHDR_LEN(tcp_hdr(skb)->doff);
			lso->lso_ctrl = htonl(ctrl);
			lso->ipid_ofst = htons(0);
			lso->mss = htons(ssi->gso_size);
			lso->seqno_offset = htonl(0);
			if (chip_ver == CHELSIO_T4)
				lso->len = htonl(skb->len);
			else
				lso->len = htonl(V_LSO_T5_XFER_SIZE(skb->len));
			cpl = (void *)(lso + 1);

			if (chip_ver <= CHELSIO_T5)
				cntrl =	V_TXPKT_ETHHDR_LEN(eth_xtra_len);
			else
				cntrl = V_T6_TXPKT_ETHHDR_LEN(eth_xtra_len);

			cntrl |= V_TXPKT_CSUM_TYPE(v6 ?
						   TX_CSUM_TCPIP6 :
						   TX_CSUM_TCPIP) |
				 V_TXPKT_IPHDR_LEN(l3hdr_len);
		}
		sgl = (u64 *) (cpl + 1); /* sgl start here */
		if (unlikely((u8 *)sgl >= (u8 *)q->q.stat)) {
			/* If current position is already at the end of the
			 * txq, reset the current to point to start of the queue
			 * and update the end ptr as well.
			 */
			if (sgl == (u64 *) q->q.stat) {
				int left = (u8 *)end - (u8 *)q->q.stat;

				end = (void *)q->q.desc + left;
				sgl = (void *)q->q.desc;
			}
		}

		q->tso++;
		q->tx_cso += ssi->gso_segs;
	} else {
#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
		if (ptp_enabled)
			op = FW_PTP_TX_PKT_WR;
		else
#endif
			op = FW_ETH_TX_PKT_WR;

		wr->op_immdlen = htonl(V_FW_WR_OP(op) |
				       V_FW_WR_IMMDLEN(len));
		cpl = (void *)(wr + 1);
		sgl = (u64 *) (cpl + 1); /* sgl start here */
		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			cntrl = hwcsum(adap->params.chip, skb) |
				F_TXPKT_IPCSUM_DIS;
			q->tx_cso++;
		}
	}

	if (skb_vlan_tag_present(skb)) {
		q->vlan_ins++;
		cntrl |= F_TXPKT_VLAN_VLD | V_TXPKT_VLAN(skb_vlan_tag_get(skb));

#ifdef CONFIG_PO_FCOE
		if (skb->protocol == htons(ETH_P_FCOE))
			cntrl |= V_TXPKT_VLAN(
				 ((skb->priority & 0x7) << VLAN_PRIO_SHIFT));
#endif /* CONFIG_PO_FCOE */

	}

	ctrl0 = V_TXPKT_OPCODE(CPL_TX_PKT_XT) | V_TXPKT_INTF(pi->tx_chan) |
		V_TXPKT_PF(adap->pf);
#ifdef CONFIG_CXGB4_DCB
	if (chip_ver == CHELSIO_T4)
		ctrl0 |= V_TXPKT_OVLAN_IDX(q->dcb_prio);
	else
		ctrl0 |= V_TXPKT_T5_OVLAN_IDX(q->dcb_prio);
#endif
	if (loopback)
		ctrl0 |= V_TXPKT_INTF(pi->tx_chan + 4);
	if (ptp_enabled)
		ctrl0 |= F_TXPKT_TSTAMP;
	cpl->ctrl0 = htonl(ctrl0);
	cpl->pack = htons(0);
	cpl->len = htons(skb->len);
	cpl->ctrl1 = cpu_to_be64(cntrl);

#ifdef T4_TRACE
	T4_TRACE5(adap->tb[q->q.cntxt_id & 7],
		  "eth_xmit: ndesc %u, credits %u, pidx %u, len %u, frags %u",
		  ndesc, credits, q->q.pidx, skb->len, ssi->nr_frags);
#endif

	if (immediate) {
		inline_tx_skb(skb, &q->q, sgl);
		dev_consume_skb_any(skb);
	} else {
		int last_desc;

		write_sgl(skb, &q->q, (void *)sgl, end, 0, addr);
		skb_orphan(skb);

		last_desc = q->q.pidx + ndesc - 1;
		if (last_desc >= q->q.size)
			last_desc -= q->q.size;
		q->q.sdesc[last_desc].skb = skb;
		q->q.sdesc[last_desc].sgl = (struct ulptx_sgl *)sgl;
	}

	txq_advance(&q->q, ndesc);

	dev->trans_start = jiffies;    // XXX removed in newer kernels
	ring_tx_db(adap, &q->q, ndesc);
#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
	if (ptp_enabled)
		spin_unlock(&adap->ptp_lock);
#endif
	return NETDEV_TX_OK;
}

/*
 * Constants ...
 */
enum {
	/*
	 * Egress Queue sizes, producer and consumer indices are all in units
	 * of Egress Context Units bytes.  Note that as far as the hardware is
	 * concerned, the free list is an Egress Queue (the host produces free
	 * buffers which the hardware consumes) and free list entries are
	 * 64-bit PCI DMA addresses.
	 */
	EQ_UNIT = X_IDXSIZE_UNIT,
	FL_PER_EQ_UNIT = EQ_UNIT / sizeof(__be64),
	TXD_PER_EQ_UNIT = EQ_UNIT / sizeof(__be64),

	T4VF_ETHTXQ_MAX_HDR = (sizeof(struct fw_eth_tx_pkt_vm_wr) +
			       sizeof(struct cpl_tx_pkt_lso_core) +
			       sizeof(struct cpl_tx_pkt_core)) / sizeof(__be64),
};

/**
 *	t4vf_is_eth_imm - can an Ethernet packet be sent as immediate data?
 *	@skb: the packet
 *
 *	Returns whether an Ethernet packet is small enough to fit completely as
 *	immediate data.
 */
static inline int t4vf_is_eth_imm(const struct sk_buff *skb)
{
	/*
	 * The VF Driver uses the FW_ETH_TX_PKT_VM_WR firmware Work Request
	 * which does not accommodate immediate data.  We could dike out all
	 * of the support code for immediate data but that would tie our hands
	 * too much if we ever want to enhace the firmware.  It would also
	 * create more differences between the PF and VF Drivers.
	 */
	return false;
}

/**
 *	t4vf_calc_tx_flits - calculate the number of flits for a packet TX WR
 *	@skb: the packet
 *
 *	Returns the number of flits needed for a TX Work Request for the
 *	given Ethernet packet, including the needed WR and CPL headers.
 */
static inline unsigned int t4vf_calc_tx_flits(const struct sk_buff *skb)
{
	unsigned int flits;

	/*
	 * If the skb is small enough, we can pump it out as a work request
	 * with only immediate data.  In that case we just have to have the
	 * TX Packet header plus the skb data in the Work Request.
	 */
	if (t4vf_is_eth_imm(skb))
		return DIV_ROUND_UP(skb->len + sizeof(struct cpl_tx_pkt),
				    sizeof(__be64));

	/*
	 * Otherwise, we're going to have to construct a Scatter gather list
	 * of the skb body and fragments.  We also include the flits necessary
	 * for the TX Packet Work Request and CPL.  We always have a firmware
	 * Write Header (incorporated as part of the cpl_tx_pkt_lso and
	 * cpl_tx_pkt structures), followed by either a TX Packet Write CPL
	 * message or, if we're doing a Large Send Offload, an LSO CPL message
	 * with an embedded TX Packet Write CPL message.
	 */
	flits = sgl_len(skb_shinfo(skb)->nr_frags + 1);
	if (skb_shinfo(skb)->gso_size)
		flits += (sizeof(struct fw_eth_tx_pkt_vm_wr) +
			  sizeof(struct cpl_tx_pkt_lso_core) +
			  sizeof(struct cpl_tx_pkt_core)) / sizeof(__be64);
	else
		flits += (sizeof(struct fw_eth_tx_pkt_vm_wr) +
			  sizeof(struct cpl_tx_pkt_core)) / sizeof(__be64);
	return flits;
}

/**
 *	t4vf_eth_xmit - add a packet to an Ethernet TX queue
 *	@skb: the packet
 *	@dev: the egress net device
 *
 *	Add a packet to an SGE Ethernet TX queue.  Runs with softirqs disabled.
 */
int t4vf_eth_xmit(struct sk_buff *skb, struct net_device *dev)
{
	u32 wr_mid;
	u64 cntrl, *end;
	int qidx, credits, max_pkt_len;
	unsigned int flits, ndesc;
	struct adapter *adapter;
	struct sge_eth_txq *txq;
	const struct port_info *pi;
	struct fw_eth_tx_pkt_vm_wr *wr;
	struct cpl_tx_pkt_core *cpl;
	const struct skb_shared_info *ssi;
	dma_addr_t addr[MAX_SKB_FRAGS + 1];
	const size_t fw_hdr_copy_len = (sizeof(wr->ethmacdst) +
					sizeof(wr->ethmacsrc) +
					sizeof(wr->ethtype) +
					sizeof(wr->vlantci));

	/*
	 * The chip minimum packet length is 10 octets but the firmware
	 * command that we are using requires that we copy the Ethernet header
	 * (including the VLAN tag) into the header so we reject anything
	 * smaller than that ...
	 */
	if (unlikely(skb->len < fw_hdr_copy_len))
		goto out_free;

	/* Discard the packet if the length is greater than mtu */
	max_pkt_len = ETH_HLEN + dev->mtu;
	if (skb_vlan_tag_present(skb))
		max_pkt_len += VLAN_HLEN;
	if (!skb_shinfo(skb)->gso_size && (unlikely(skb->len > max_pkt_len)))
		goto out_free;

	/*
	 * Figure out which TX Queue we're going to use.
	 */
	pi = netdev_priv(dev);
	adapter = pi->adapter;
	qidx = skb_get_queue_mapping(skb);
	BUG_ON(qidx >= pi->nqsets);
	txq = &adapter->sge.ethtxq[pi->first_qset + qidx];

	/*
	 * Take this opportunity to reclaim any TX Descriptors whose DMA
	 * transfers have completed.
	 */
	reclaim_completed_tx(adapter, &txq->q, true);

	/*
	 * Calculate the number of flits and TX Descriptors we're going to
	 * need along with how many TX Descriptors will be left over after
	 * we inject our Work Request.
	 */
	flits = t4vf_calc_tx_flits(skb);
	ndesc = flits_to_desc(flits);
	credits = txq_avail(&txq->q) - ndesc;

	if (unlikely(credits < 0)) {
		/*
		 * Not enough room for this packet's Work Request.  Stop the
		 * TX Queue and return a "busy" condition.  The queue will get
		 * started later on when the firmware informs us that space
		 * has opened up.
		 */
		eth_txq_stop(txq);
		dev_err(adapter->pdev_dev,
			"%s: TX ring %u full while queue awake!\n",
			dev->name, qidx);
		return NETDEV_TX_BUSY;
	}

	if (!t4vf_is_eth_imm(skb) &&
	    unlikely(map_skb(adapter->pdev_dev, skb, addr) < 0)) {
		/*
		 * We need to map the skb into PCI DMA space (because it can't
		 * be in-lined directly into the Work Request) and the mapping
		 * operation failed.  Record the error and drop the packet.
		 */
		txq->mapping_err++;
		goto out_free;
	}

	wr_mid = V_FW_WR_LEN16(DIV_ROUND_UP(flits, 2));
	if (unlikely(credits < ETHTXQ_STOP_THRES)) {
		/*
		 * After we're done injecting the Work Request for this
		 * packet, we'll be below our "stop threshhold" so stop the TX
		 * Queue now and schedule a request for an SGE Egress Queue
		 * Update message.  The queue will get started later on when
		 * the firmware processes this Work Request and sends us an
		 * Egress Queue Status Update message indicating that space
		 * has opened up.
		 */
		eth_txq_stop(txq);
		wr_mid |= F_FW_WR_EQUEQ | F_FW_WR_EQUIQ;
	}

	/*
	 * Start filling in our Work Request.  Note that we do _not_ handle
	 * the WR Header wrapping around the TX Descriptor Ring.  If our
	 * maximum header size ever exceeds one TX Descriptor, we'll need to
	 * do something else here.
	 */
	BUG_ON(DIV_ROUND_UP(T4VF_ETHTXQ_MAX_HDR, TXD_PER_EQ_UNIT) > 1);
	wr = (void *)&txq->q.desc[txq->q.pidx];
	wr->equiq_to_len16 = cpu_to_be32(wr_mid);
	wr->r3[0] = cpu_to_be32(0);
	wr->r3[1] = cpu_to_be32(0);
	skb_copy_from_linear_data(skb, (void *)wr->ethmacdst, fw_hdr_copy_len);
	end = (u64 *)wr + flits;

	/*
	 * If this is a Large Send Offload packet we'll put in an LSO CPL
	 * message with an encapsulated TX Packet CPL message.  Otherwise we
	 * just use a TX Packet CPL message.
	 */
	ssi = skb_shinfo(skb);
	if (ssi->gso_size) {
		struct cpl_tx_pkt_lso_core *lso = (void *)(wr + 1);
		bool v6 = (ssi->gso_type & SKB_GSO_TCPV6) != 0;
		int l3hdr_len = skb_network_header_len(skb);
		int eth_xtra_len = skb_network_offset(skb) - ETH_HLEN;

		wr->op_immdlen =
			cpu_to_be32(V_FW_WR_OP(FW_ETH_TX_PKT_VM_WR) |
				    V_FW_WR_IMMDLEN(sizeof(*lso) +
						    sizeof(*cpl)));
		/*
		 * Fill in the LSO CPL message.
		 */
		lso->lso_ctrl =
			cpu_to_be32(V_LSO_OPCODE(CPL_TX_PKT_LSO) |
				    F_LSO_FIRST_SLICE |
				    F_LSO_LAST_SLICE |
				    V_LSO_IPV6(v6) |
				    V_LSO_ETHHDR_LEN(eth_xtra_len/4) |
				    V_LSO_IPHDR_LEN(l3hdr_len/4) |
				    V_LSO_TCPHDR_LEN(tcp_hdr(skb)->doff));
		lso->ipid_ofst = cpu_to_be16(0);
		lso->mss = cpu_to_be16(ssi->gso_size);
		lso->seqno_offset = cpu_to_be32(0);
		if (is_t4(adapter->params.chip))
			lso->len = cpu_to_be32(skb->len);
		else
			lso->len = cpu_to_be32(V_LSO_T5_XFER_SIZE(skb->len));

		/*
		 * Set up TX Packet CPL pointer, control word and perform
		 * accounting.
		 */
		cpl = (void *)(lso + 1);

		if (CHELSIO_CHIP_VERSION(adapter->params.chip) <= CHELSIO_T5)
			cntrl =	V_TXPKT_ETHHDR_LEN(eth_xtra_len);
		else
			cntrl = V_T6_TXPKT_ETHHDR_LEN(eth_xtra_len);

		cntrl |= V_TXPKT_CSUM_TYPE(v6 ?
					   TX_CSUM_TCPIP6 :
					   TX_CSUM_TCPIP) |
			 V_TXPKT_IPHDR_LEN(l3hdr_len);
		txq->tso++;
		txq->tx_cso += ssi->gso_segs;
	} else {
		int len;

		len = (t4vf_is_eth_imm(skb)
		       ? skb->len + sizeof(*cpl)
		       : sizeof(*cpl));
		wr->op_immdlen =
			cpu_to_be32(V_FW_WR_OP(FW_ETH_TX_PKT_VM_WR) |
				    V_FW_WR_IMMDLEN(len));

		/*
		 * Set up TX Packet CPL pointer, control word and perform
		 * accounting.
		 */
		cpl = (void *)(wr + 1);
		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			cntrl = hwcsum(adapter->params.chip, skb) |
				F_TXPKT_IPCSUM_DIS;
			txq->tx_cso++;
		} else
			cntrl = F_TXPKT_L4CSUM_DIS | F_TXPKT_IPCSUM_DIS;
	}

	/*
	 * If there's a VLAN tag present, add that to the list of things to
	 * do in this Work Request.
	 */
	if (skb_vlan_tag_present(skb)) {
		txq->vlan_ins++;
		cntrl |= F_TXPKT_VLAN_VLD | V_TXPKT_VLAN(skb_vlan_tag_get(skb));
	}

	/*
	 * Fill in the TX Packet CPL message header.
	 */
	cpl->ctrl0 = cpu_to_be32(V_TXPKT_OPCODE(CPL_TX_PKT_XT) |
				 V_TXPKT_INTF(pi->port_id) |
				 V_TXPKT_PF(0));
	cpl->pack = cpu_to_be16(0);
	cpl->len = cpu_to_be16(skb->len);
	cpl->ctrl1 = cpu_to_be64(cntrl);


	/*
	 * Fill in the body of the TX Packet CPL message with either in-lined
	 * data or a Scatter/Gather List.
	 */
	if (t4vf_is_eth_imm(skb)) {
		/*
		 * In-line the packet's data and free the skb since we don't
		 * need it any longer.
		 */
		inline_tx_skb(skb, &txq->q, cpl + 1);
		dev_kfree_skb(skb);
	} else {
		/*
		 * Write the skb's Scatter/Gather list into the TX Packet CPL
		 * message and retain a pointer to the skb so we can free it
		 * later when its DMA completes.  (We store the skb pointer
		 * in the Software Descriptor corresponding to the last TX
		 * Descriptor used by the Work Request.)
		 *
		 * The retained skb will be freed when the corresponding TX
		 * Descriptors are reclaimed after their DMAs complete.
		 * However, this could take quite a while since, in general,
		 * the hardware is set up to be lazy about sending DMA
		 * completion notifications to us and we mostly perform TX
		 * reclaims in the transmit routine.
		 *
		 * This is good for performamce but means that we rely on new
		 * TX packets arriving to run the destructors of completed
		 * packets, which open up space in their sockets' send queues.
		 * Sometimes we do not get such new packets causing TX to
		 * stall.  A single UDP transmitter is a good example of this
		 * situation.  We have a clean up timer that periodically
		 * reclaims completed packets but it doesn't run often enough
		 * (nor do we want it to) to prevent lengthy stalls.  A
		 * solution to this problem is to run the destructor early,
		 * after the packet is queued but before it's DMAd.  A con is
		 * that we lie to socket memory accounting, but the amount of
		 * extra memory is reasonable (limited by the number of TX
		 * descriptors), the packets do actually get freed quickly by
		 * new packets almost always, and for protocols like TCP that
		 * wait for acks to really free up the data the extra memory
		 * is even less.  On the positive side we run the destructors
		 * on the sending CPU rather than on a potentially different
		 * completing CPU, usually a good thing.
		 *
		 * Run the destructor before telling the DMA engine about the
		 * packet to make sure it doesn't complete and get freed
		 * prematurely.
		 */
		struct ulptx_sgl *sgl = (struct ulptx_sgl *)(cpl + 1);
		struct sge_txq *tq = &txq->q;
		int last_desc;

		/*
		 * If the Work Request header was an exact multiple of our TX
		 * Descriptor length, then it's possible that the starting SGL
		 * pointer lines up exactly with the end of our TX Descriptor
		 * ring.  If that's the case, wrap around to the beginning
		 * here ...
		 */
		if (unlikely((void *)sgl == (void *)tq->stat)) {
			sgl = (void *)tq->desc;
			end = (void *)((void *)tq->desc +
				       ((void *)end - (void *)tq->stat));
		}

		write_sgl(skb, tq, sgl, end, 0, addr);
		skb_orphan(skb);

		last_desc = tq->pidx + ndesc - 1;
		if (last_desc >= tq->size)
			last_desc -= tq->size;
		tq->sdesc[last_desc].skb = skb;
		tq->sdesc[last_desc].sgl = sgl;
	}

	/*
	 * Advance our internal TX Queue state, tell the hardware about
	 * the new TX descriptors and return success.
	 */
	txq_advance(&txq->q, ndesc);
	dev->trans_start = jiffies;
	ring_tx_db(adapter, &txq->q, ndesc);
	return NETDEV_TX_OK;

out_free:
	/*
	 * An error of some sort happened.  Free the TX skb and tell the
	 * OS that we've "dealt" with the packet ...
	 */
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

/**
 *	reclaim_completed_tx_imm - reclaim completed control-queue Tx descs
 *	@q: the SGE control Tx queue
 *
 *	This is a variant of reclaim_completed_tx() that is used for Tx queues
 *	that send only immediate data (presently just the control queues) and
 *	thus do not have any sk_buffs to release.
 */
static inline void reclaim_completed_tx_imm(struct sge_txq *q)
{
	int hw_cidx = ntohs(ACCESS_ONCE(q->stat->cidx));
	int reclaim = hw_cidx - q->cidx;

	if (reclaim < 0)
		reclaim += q->size;

	q->in_use -= reclaim;
	q->cidx = hw_cidx;
}

/**
 *	is_imm - check whether a packet can be sent as immediate data
 *	@skb: the packet
 *
 *	Returns true if a packet can be sent as a WR with immediate data.
 */
static inline int is_imm(const struct sk_buff *skb)
{
	return skb->len <= MAX_CTRL_WR_LEN;
}

/**
 *	ctrlq_check_stop - check if a control queue is full and should stop
 *	@q: the queue
 *	@wr: most recent WR written to the queue
 *
 *	Check if a control queue has become full and should be stopped.
 *	We clean up control queue descriptors very lazily, only when we are out.
 *	If the queue is still full after reclaiming any completed descriptors
 *	we suspend it and have the last WR wake it up.
 */
static void ctrlq_check_stop(struct sge_ctrl_txq *q, struct fw_wr_hdr *wr)
{
	reclaim_completed_tx_imm(&q->q);
	if (unlikely(txq_avail(&q->q) < TXQ_STOP_THRES)) {
		wr->lo |= htonl(F_FW_WR_EQUEQ | F_FW_WR_EQUIQ);
		q->q.stops++;
		q->full = 1;
	}
}

/**
 *	ctrl_xmit - send a packet through an SGE control Tx queue
 *	@q: the control queue
 *	@skb: the packet
 *
 *	Send a packet through an SGE control Tx queue.  Packets sent through
 *	a control queue must fit entirely as immediate data.
 */
static int ctrl_xmit(struct sge_ctrl_txq *q, struct sk_buff *skb)
{
	unsigned int ndesc;
	struct fw_wr_hdr *wr;

	if (unlikely(!is_imm(skb))) {
		WARN_ON(1);
		dev_kfree_skb(skb);
		return NET_XMIT_DROP;
	}

	ndesc = DIV_ROUND_UP(skb->len, sizeof(struct tx_desc));
	spin_lock(&q->sendq.lock);

	if (unlikely(q->full)) {
		skb->priority = ndesc;                  /* save for restart */
		__skb_queue_tail(&q->sendq, skb);
		spin_unlock(&q->sendq.lock);
		return NET_XMIT_CN;
	}

	wr = (struct fw_wr_hdr *)&q->q.desc[q->q.pidx];
	inline_tx_skb(skb, &q->q, wr);

	txq_advance(&q->q, ndesc);
	if (unlikely(txq_avail(&q->q) < TXQ_STOP_THRES))
		ctrlq_check_stop(q, wr);

	q->q.txp++;

	ring_tx_db(q->adap, &q->q, ndesc);
	spin_unlock(&q->sendq.lock);

	kfree_skb(skb);
	return NET_XMIT_SUCCESS;
}


/**
 *	restart_ctrlq - restart a suspended control queue
 *	@data: the control queue to restart
 *
 *	Resumes transmission on a suspended Tx control queue.
 */
static void restart_ctrlq(unsigned long data)
{
	struct sk_buff *skb;
	unsigned int written = 0;
	struct sge_ctrl_txq *q = (struct sge_ctrl_txq *)data;

	spin_lock(&q->sendq.lock);
	reclaim_completed_tx_imm(&q->q);
	BUG_ON(txq_avail(&q->q) < TXQ_STOP_THRES);  /* q should be empty */

	while ((skb = __skb_dequeue(&q->sendq)) != NULL) {
		struct fw_wr_hdr *wr;
		unsigned int ndesc = skb->priority;     /* previously saved */

		written += ndesc;
		/*
		 * Write descriptors and free skbs outside the lock to limit
		 * wait times.  q->full is still set so new skbs will be queued.
		 */
		wr = (struct fw_wr_hdr *)&q->q.desc[q->q.pidx];
		txq_advance(&q->q, ndesc);
		spin_unlock(&q->sendq.lock);

		inline_tx_skb(skb, &q->q, wr);
		kfree_skb(skb);

		if (unlikely(txq_avail(&q->q) < TXQ_STOP_THRES)) {
			unsigned long old = q->q.stops;

			ctrlq_check_stop(q, wr);
			if (q->q.stops != old) {          /* suspended anew */
				spin_lock(&q->sendq.lock);
				goto ringdb;
			}
		}
		if (written > 16) {
			ring_tx_db(q->adap, &q->q, written);
			written = 0;
		}
		spin_lock(&q->sendq.lock);
	}
	q->full = 0;
ringdb: if (written)
		ring_tx_db(q->adap, &q->q, written);
	spin_unlock(&q->sendq.lock);
}

/**
 *	t4_mgmt_tx - send a management message
 *	@adap: the adapter
 *	@skb: the packet containing the management message
 *
 *	Send a management message through control queue 0.
 */
int t4_mgmt_tx(struct adapter *adap, struct sk_buff *skb)
{
	int ret;

	local_bh_disable();
	ret = ctrl_xmit(&adap->sge.ctrlq[0], skb);
	local_bh_enable();
	return ret;
}

/**
 *	is_ofld_imm - check whether a packet can be sent as immediate data
 *	@skb: the packet
 *
 *	Returns true if a packet can be sent as an offload WR with immediate
 *	data.
 *	FW_OFLD_TX_DATA_WR limits the payload to 255 bytes due to 8-bit field.
 *	However, FW_ULPTX_WR commands have a 256 byte immediate only
 *	payload limit.
 */
static inline int is_ofld_imm(const struct sk_buff *skb)
{
	struct work_request_hdr *req = (struct work_request_hdr *)skb->data;
	unsigned long opcode = G_FW_WR_OP(ntohl(req->wr_hi));

	if (unlikely(opcode == FW_ULPTX_WR))
		return skb->len <= MAX_IMM_ULPTX_WR_LEN;
	else
		return skb->len <= MAX_IMM_OFLD_TX_DATA_WR_LEN;
}

/**
 *	calc_tx_flits_ofld - calculate # of flits for an offload packet
 *	@skb: the packet
 *
 *	Returns the number of flits needed for the given offload packet.
 *	These packets are already fully constructed and no additional headers
 *	will be added.
 */
static inline unsigned int calc_tx_flits_ofld(const struct sk_buff *skb)
{
	unsigned int flits, cnt;

	if (is_ofld_imm(skb))
		return DIV_ROUND_UP(skb->len, 8);

	flits = DIV_ROUND_UP(skb_transport_offset(skb), 8);   /* headers */
	cnt = skb_shinfo(skb)->nr_frags;
	if (skb_tail_pointer(skb) != skb_transport_header(skb))
		cnt++;
	return flits + sgl_len(cnt);
}

/**
 *	txq_stop_maperr - stop a Tx queue due to I/O MMU exhaustion
 *	@adap: the adapter
 *	@q: the queue to stop
 *
 *	Mark a Tx queue stopped due to I/O MMU exhaustion and resulting
 *	inability to map packets.  A periodic timer attempts to restart
 *	queues so marked.
 */
static void txq_stop_maperr(struct sge_ofld_txq *q)
{
	q->mapping_err++;
	q->q.stops++;
	set_bit(q->q.cntxt_id - q->adap->sge.egr_start,
		q->adap->sge.txq_maperr);
}

/**
 *	ofldtxq_stop - stop an offload Tx queue that has become full
 *	@q: the queue to stop
 *	@skb: the packet causing the queue to become full
 *
 *	Stops an offload Tx queue that has become full and modifies the packet
 *	being written to request a wakeup.
 */
static void ofldtxq_stop(struct sge_ofld_txq *q, struct sk_buff *skb)
{
	struct fw_wr_hdr *wr = (struct fw_wr_hdr *)skb->data;

	wr->lo |= htonl(F_FW_WR_EQUEQ | F_FW_WR_EQUIQ);
	q->q.stops++;
	q->full = 1;
}

static inline int ofld_skb_map_head(struct device *dev,
				const struct sk_buff *skb)
{
	dma_addr_t *addr = (dma_addr_t *)skb->head;

	*addr = dma_map_single(dev, skb->data, skb_headlen(skb), DMA_TO_DEVICE);
	if (dma_mapping_error(dev, *addr))
		return -ENOMEM;
	return 0;
}

/**
 *	service_ofldq - service/restart a suspended offload queue
 *	@q: the offload queue
 *
 *	Services an offload Tx queue by moving packets from its Pending Send
 *	Queue to the Hardware TX ring.  The function starts and ends with the
 *	Send Queue locked, but drops the lock while putting the skb at the
 *	head of the Send Queue onto the Hardware TX Ring.  Dropping the lock
 *	allows more skbs to be added to the Send Queue by other threads.
 *	The packet being processed at the head of the Pending Send Queue is
 *	left on the queue in case we experience DMA Mapping errors, etc.
 *	and need to give up and restart later.
 *
 *	service_ofldq() can be thought of as a task which opportunistically
 *	uses other threads execution contexts.  We use the Offload Queue
 *	boolean "service_ofldq_running" to make sure that only one instance
 *	is ever running at a time ...
 */
static void service_ofldq(struct sge_ofld_txq *q)
{
	u64 *pos, *before, *end;
	int credits;
	struct sk_buff *skb;
	struct sge_txq *txq;
	unsigned int left;
	unsigned int written = 0;
	unsigned int flits, ndesc;

	/*
	 * If another thread is currently in service_ofldq() processing the
	 * Pending Send Queue then there's nothing to do.  Otherwise, flag
	 * that we're doing the work and continue.  Examining/modifying
	 * the Offload Queue boolean "service_ofldq_running" must be done
	 * while holding the Pending Send Queue Lock.
	 */
	if (q->service_ofldq_running)
		return;
	q->service_ofldq_running = 1;

	while ((skb = skb_peek(&q->sendq)) != NULL && !q->full) {
		const int premapped_frags = ofld_skb_get_premapped_frags(skb);
		const int ofld_imm = is_ofld_imm(skb) && !premapped_frags;

		/*
		 * We drop the lock while we're working with the skb at the
		 * head of the Pending Send Queue.  This allows more skbs to
		 * be added to the Pending Send Queue while we're working on
		 * this one.  We don't need to lock to guard the TX Ring
		 * updates because only one thread of execution is ever
		 * allowed into service_ofldq() at a time.
		 */
		spin_unlock(&q->sendq.lock);

		reclaim_completed_tx(q->adap, &q->q, false);

		flits = skb->priority;                /* previously saved */
		ndesc = flits_to_desc(flits);
		credits = txq_avail(&q->q) - ndesc;
		BUG_ON(credits < 0);
		if (unlikely(credits < TXQ_STOP_THRES))
			ofldtxq_stop(q, skb);
#ifdef T4_TRACE
		T4_TRACE5(q->adap->tb[q->q.cntxt_id & 7],
			  "ofld_xmit: ndesc %u, pidx %u, len %u, main %u, "
                          "frags %u", ndesc, q->q.pidx, skb->len,
                          skb->len - skb->data_len, skb_shinfo(skb)->nr_frags);
#endif
		pos = (u64 *)&q->q.desc[q->q.pidx];
		if (ofld_imm)
			inline_tx_skb(skb, &q->q, pos);
		else if (unlikely(premapped_frags)) {
#ifdef T4_TRACE
		T4_TRACE4(q->adap->tb[q->q.cntxt_id & 7],
			  "ofld_xmit: premapped skb 0x%p, len %u,%u, frags %u",
			  skb, skb->len, skb->data_len,
			  skb_shinfo(skb)->nr_frags);
#endif
			if (ofld_skb_map_head(q->adap->pdev_dev, skb)) {
				txq_stop_maperr(q);
				spin_lock(&q->sendq.lock);
				break;
			} else
				goto wr_sgl;
		} else if (map_skb(q->adap->pdev_dev, skb,
				 (dma_addr_t *)skb->head)) {
			txq_stop_maperr(q);
			spin_lock(&q->sendq.lock);
			break;
		} else 
wr_sgl:
		{
			int last_desc, hdr_len = skb_transport_offset(skb);

			/*
			 * The WR headers  may not fit within one descriptor.
			 * So we need to deal with wrap-around here.
			 */

			before = (u64 *) pos;
			end = (u64 *)pos + flits;
			txq = &q->q;
			pos = (void *)inline_tx_skb_header(skb, &q->q,
							(void *)pos, hdr_len);
			if (before > (u64 *)pos) {
				left = (u8 *)end - (u8 *)txq->stat;
				end = (void *)txq->desc + left;
			}

			/* If current position is already at the end of the
			 * ofld queue, reset the current to point to
			 * start of the queue and update the end ptr as well.
			 */
			if (pos == (u64 *) txq->stat) {
				left = (u8 *)end - (u8 *)txq->stat;
				end = (void *)txq->desc + left;
				pos = (void *)txq->desc;
			}

			write_sgl(skb, &q->q, (void *)pos,
				  end, hdr_len,
				  (dma_addr_t *)skb->head);

#ifdef CONFIG_NEED_DMA_MAP_STATE
			skb->dev = q->adap->port[0];
			if (likely(!ofld_skb_get_premapped_frags(skb)) &&
			    need_skb_unmap()) 
				skb->destructor = deferred_unmap_destructor;
#endif

			last_desc = q->q.pidx + ndesc - 1;
			if (last_desc >= q->q.size)
				last_desc -= q->q.size;
			q->q.sdesc[last_desc].skb = skb;
		}

		txq_advance(&q->q, ndesc);
		written += ndesc;
		q->q.txp++;
		if (unlikely(written > 32)) {
			ring_tx_db(q->adap, &q->q, written);
			written = 0;
		}

		/*
		 * Reacquire the Pending Send Queue Lock so we can unlink the
		 * skb we've just successfully transferred to the TX Ring and
		 * loop for the next skb which may be at the head of the
		 * Pending Send Queue.
		 */
		spin_lock(&q->sendq.lock);

		__skb_unlink(skb, &q->sendq);
		if (ofld_imm)
			kfree_skb(skb);
	}
	if (likely(written))
		ring_tx_db(q->adap, &q->q, written);

	/*
	 * Indicate that no thread is processing the Pending Send Queue
	 * currently.
	 */
	q->service_ofldq_running = 0;
}

/**
 *	ofld_xmit - send a packet through an offload queue
 *	@q: the Tx offload queue
 *	@skb: the packet
 *
 *	Send an offload packet through an SGE offload queue.
 */
static int ofld_xmit(struct sge_ofld_txq *q, struct sk_buff *skb)
{
	skb->priority = calc_tx_flits_ofld(skb);       /* save for restart */
	spin_lock(&q->sendq.lock);

	/*
	 * Queue the new skb onto the Offload Queue's Pending Send Queue.  If
	 * that results in this new skb being the only one on the queue, start
	 * servicing it.  If there are other skbs already on the list, then
	 * either the queue is currently being processed or it's been stopped
	 * for some reason and it'll be restarted at a later time.  Restart
	 * paths are triggered by events like experiencing a DMA Mapping Error
	 * or filling the Hardware TX Ring.
	 */
	__skb_queue_tail(&q->sendq, skb);
	if (q->sendq.qlen == 1)
		service_ofldq(q);

	spin_unlock(&q->sendq.lock);
	return NET_XMIT_SUCCESS;
}

/**
 *	restart_ofldq - restart a suspended offload queue
 *	@data: the offload queue to restart
 *
 *	Resumes transmission on a suspended Tx offload queue.
 */
static void restart_ofldq(unsigned long data)
{
	struct sge_ofld_txq *q = (struct sge_ofld_txq *)data;

	spin_lock(&q->sendq.lock);
	q->full = 0;            /* the queue actually is completely empty now */
	service_ofldq(q);
	spin_unlock(&q->sendq.lock);
}

/**
 *	skb_txq - return the Tx queue an offload packet should use
 *	@skb: the packet
 *
 *	Returns the Tx queue an offload packet should use as indicated by bits
 *	1-15 in the packet's queue_mapping.
 */
static inline unsigned int skb_txq(const struct sk_buff *skb)
{
	return skb->queue_mapping >> 1;
}

/**
 *	is_ctrl_pkt - return whether an offload packet is a control packet
 *	@skb: the packet
 *
 *	Returns whether an offload packet should use an OFLD or a CTRL
 *	Tx queue as indicated by bit 0 in the packet's queue_mapping.
 */
static inline unsigned int is_ctrl_pkt(const struct sk_buff *skb)
{
	return skb->queue_mapping & 1;
}

static inline int ofld_send(struct adapter *adap, struct sk_buff *skb)
{
	unsigned int idx = skb_txq(skb);

	if (unlikely(is_ctrl_pkt(skb))) {
		/* Single ctrl queue is a requirement for LE workaround path */
		if (adap->tids.nsftids)
			idx = 0;
		return ctrl_xmit(&adap->sge.ctrlq[idx], skb);
	}
	return ofld_xmit(&adap->sge.ofldtxq[idx], skb);
}

/**
 *	t4_ofld_send - send an offload packet
 *	@adap: the adapter
 *	@skb: the packet
 *
 *	Sends an offload packet.  We use the packet queue_mapping to select the
 *	appropriate Tx queue as follows: bit 0 indicates whether the packet
 *	should be sent as regular or control, bits 1-15 select the queue.
 */
int t4_ofld_send(struct adapter *adap, struct sk_buff *skb)
{
	int ret;

	local_bh_disable();
	ret = ofld_send(adap, skb);
	local_bh_enable();
	return ret;
}

/**
 *	cxgb4_ofld_send - send an offload packet
 *	@dev: the net device
 *	@skb: the packet
 *
 *	Sends an offload packet.  This is an exported version of @t4_ofld_send,
 *	intended for ULDs.
 */
int cxgb4_ofld_send(struct net_device *dev, struct sk_buff *skb)
{
	return t4_ofld_send(netdev2adap(dev), skb);
}
EXPORT_SYMBOL(cxgb4_ofld_send);

/**
 *	copy_frags - copy fragments from gather list into skb_shared_info
 *	@si: destination skb shared info structure
 *	@gl: source internal packet gather list
 *	@offset: packet start offset in first page
 *
 *	Copy an internal packet gather list into a Linux skb_shared_info
 *	structure.
 */
static inline void copy_frags(struct sk_buff *skb,
			      const struct pkt_gl *gl, unsigned int offset)
{
	int i;

	/* usually there's just one frag */
	__skb_fill_page_desc(skb, 0, gl->frags[0].page,
			     gl->frags[0].offset + offset,
			     gl->frags[0].size - offset);
	skb_shinfo(skb)->nr_frags = gl->nfrags;
	for (i = 1; i < gl->nfrags; i++)
		__skb_fill_page_desc(skb, i, gl->frags[i].page,
				     gl->frags[i].offset,
				     gl->frags[i].size);

	/* get a reference to the last page, we don't own it */
	get_page(gl->frags[gl->nfrags - 1].page);
}

/**
 *	cxgb4_pktgl_to_skb - build an sk_buff from a packet gather list
 *	@napi: rspq's napi struct
 *	@gl: the gather list
 *	@skb_len: size of sk_buff main body if it carries fragments
 *	@pull_len: amount of data to move to the sk_buff's main body
 *
 *	Builds an sk_buff from the given packet gather list.  Returns the
 *	sk_buff or %NULL if sk_buff allocation failed.
 */
struct sk_buff *cxgb4_pktgl_to_skb(struct napi_struct *napi,
				   const struct pkt_gl *gl,
				   unsigned int skb_len, unsigned int pull_len)
{
	struct sk_buff *skb;

	/*
	 * Below we rely on RX_COPY_THRES being less than the smallest Rx buffer
	 * size, which is expected since buffers are at least PAGE_SIZEd.
	 * In this case packets up to RX_COPY_THRES have only one fragment.
	 */
	if (gl->tot_len <= RX_COPY_THRES) {
		skb = napi_alloc_skb(napi, gl->tot_len);
		if (unlikely(!skb))
			goto out;
		__skb_put(skb, gl->tot_len);
		skb_copy_to_linear_data(skb, gl->va, gl->tot_len);
	} else {
		skb = napi_alloc_skb(napi, skb_len);
		if (unlikely(!skb))
			goto out;
		__skb_put(skb, pull_len);
		skb_copy_to_linear_data(skb, gl->va, pull_len);

		copy_frags(skb, gl, pull_len);
		skb->len = gl->tot_len;
		skb->data_len = skb->len - pull_len;
		skb->truesize += skb->data_len;
	}
out:	return skb;
}
EXPORT_SYMBOL(cxgb4_pktgl_to_skb);

/**
 *	t4_pktgl_free - free a packet gather list
 *	@gl: the gather list
 *
 *	Releases the buffers of a packet gather list. We do not own the last
 *	page on the list and do not free it.
 */
static void t4_pktgl_free(const struct pkt_gl *gl)
{
	int n;
	const struct page_frag *p;

	for (p = gl->frags, n = gl->nfrags - 1; n--; p++)
		put_page(p->page);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
/**
 * cxgb4_sgetim_to_hwtstamp - convert sge time stamp to hw time stamp
 * @adap: the adapter
 * @hwtstamps: time stamp structure to update
 * @sgetstamp: 60bit iqe timestamp
 *
 * Every ingress queue entry has the 60-bit timestamp, convert that timestamp
 * which is in Core Clock ticks into ktime_t and assign it
 **/
static void cxgb4_sgetim_to_hwtstamp(struct adapter *adap,
				     struct skb_shared_hwtstamps *hwtstamps,
				     u64 sgetstamp)
{
	u64 ns;
	u64 tmp = (sgetstamp * 1000 * 1000 + adap->params.vpd.cclk/2);

	ns = div_u64(tmp, adap->params.vpd.cclk);

	memset(hwtstamps, 0, sizeof(*hwtstamps));
	hwtstamps->hwtstamp = ns_to_ktime(ns);
}
#endif

#ifdef CONFIG_CXGB4_GRO
/**
 *	do_gro - perform Generic Receive Offload ingress packet processing
 *	@rxq: ingress RX Ethernet Queue
 *	@gl: gather list for ingress packet
 *	@pkt: CPL header for last packet fragment
 *
 *	Perform Generic Receive Offload (GRO) ingress packet processing.
 *	We use the standard Linux GRO interfaces for this.
 */
static void do_gro(struct sge_eth_rxq *rxq, const struct pkt_gl *gl,
		   const struct cpl_rx_pkt *pkt,
		   unsigned long tnl_hdr_len)
{
	struct adapter *adapter = rxq->rspq.adap;
	struct sge *s = &adapter->sge;
	struct port_info *pi;
	int ret;
	struct sk_buff *skb;
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
	unsigned int chip_ver = CHELSIO_CHIP_VERSION(adapter->params.chip);
#endif

	skb = napi_get_frags(&rxq->rspq.napi);
	if (unlikely(!skb)) {
		t4_pktgl_free(gl);
		rxq->stats.rx_drops++;
		return;
	}

#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
	if (tnl_hdr_len) {
		if (chip_ver == CHELSIO_T5)
			vxlan_copy_frags(rxq, gl, pkt, skb, tnl_hdr_len,
					 s->pktshift);
		else
			copy_frags(skb, gl, s->pktshift);
		/* Indicate that inner packet checksum is verified */
		skb->csum_level = 1;
	} else
#endif
		copy_frags(skb, gl, s->pktshift);

	skb->len = gl->tot_len - s->pktshift;
	skb->data_len = skb->len;
	skb->truesize += skb->data_len;
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_record_rx_queue(skb, rxq->rspq.idx);
	cxgb4_skb_mark_napi_id(skb, &rxq->rspq.napi);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
	pi = netdev_priv(skb->dev);
	if (pi->rxtstamp)
		cxgb4_sgetim_to_hwtstamp(adapter, skb_hwtstamps(skb),
					 gl->sgetstamp);
#endif

	if (unlikely(pkt->vlan_ex)) {
		__vlan_hwaccel_put_ctag(skb, ntohs(pkt->vlan));
		rxq->stats.vlan_ex++;
	}
	ret = napi_gro_frags(&rxq->rspq.napi);

	if (ret == GRO_HELD)
		rxq->stats.lro_pkts++;
	else if (ret == GRO_MERGED || ret == GRO_MERGED_FREE)
		rxq->stats.lro_merged++;
	rxq->stats.pkts++;
	rxq->stats.rx_cso++;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0)
static unsigned int inet_ehashfn(struct net *net, const __be32 laddr,
				 const __u16 lport, const __be32 faddr,
				 const __be16 fport)
{
	static u32 inet_ehash_secret __read_mostly;

	net_get_random_once(&inet_ehash_secret, sizeof(inet_ehash_secret));

	return __inet_ehashfn(laddr, lport, faddr, fport,
			      inet_ehash_secret + net_hash_mix(net));
}
#endif

int t4_trace_handler(struct sge_rspq *q, const __be64 *rsp,
                     const struct pkt_gl *si)
{
        struct sge_eth_rxq *rxq = container_of(q, struct sge_eth_rxq, rspq);
        struct adapter *adapter = q->adap;
	struct ethhdr *eh = NULL;
        struct vlan_ethhdr *vlan_eh = NULL;
	struct vlan_hdr *vlan2 = NULL;
	struct vlan_hdr *vlan3 = NULL;
	struct iphdr *iph;
        struct tcphdr *tcph;
        u8 *payload = NULL;

        const struct hlist_nulls_node *node;
        unsigned int hash;
        unsigned int slot;
        struct filter_ehash_bucket *head;
	struct filter_entry *f = NULL;
	spinlock_t *lock;

        if (unlikely(*(u8 *)rsp != CPL_T5_TRACE_PKT))
                goto free_si;

        payload = (u8 *)(si->va) + sizeof(struct cpl_t5_trace_pkt);
        eh = (struct ethhdr *)payload;

	/*
	 * T5 HW Filters can match a packet with at-most double-tagged vlans.
	 * So, a switch filter with vlan insertion can have at max tripple-tagged vlans.
	 */
	if ((ntohs(eh->h_proto) == ETH_P_IP) ||
	    (ntohs(eh->h_proto) == ETH_P_IPV6))
		iph = (struct iphdr *)(eh + 1);
	else if (ntohs(eh->h_proto) == ETH_P_8021Q) {
		vlan_eh = (struct vlan_ethhdr *)payload;

		if ((ntohs(vlan_eh->h_vlan_encapsulated_proto) == ETH_P_IP) ||
		    (ntohs(vlan_eh->h_vlan_encapsulated_proto) == ETH_P_IPV6))
			iph = (struct iphdr *)(vlan_eh + 1);
		else if (ntohs(vlan_eh->h_vlan_encapsulated_proto) == ETH_P_8021Q) {
			vlan2 = (struct vlan_hdr *)(vlan_eh + 1);

			if ((ntohs(vlan2->h_vlan_encapsulated_proto) == ETH_P_IP) ||
			    (ntohs(vlan2->h_vlan_encapsulated_proto) == ETH_P_IPV6))
				iph = (struct iphdr *)(vlan2 + 1);
			else if (ntohs(vlan2->h_vlan_encapsulated_proto) == ETH_P_8021Q) {
				vlan3 = (struct vlan_hdr *)(vlan2 + 1);

				if ((ntohs(vlan3->h_vlan_encapsulated_proto) == ETH_P_IP) ||
				    (ntohs(vlan3->h_vlan_encapsulated_proto) == ETH_P_IPV6))
					iph = (struct iphdr *)(vlan3 + 1);
				else
					goto free_si;
			} else
				goto free_si;
		} else
			goto free_si;
	} else
		goto free_si;

	switch(iph->version) {
        case 0x4:
                tcph = (struct tcphdr *)(iph + 1);
                hash = inet_ehashfn(NULL,
                                    iph->daddr, ntohs(tcph->dest), iph->saddr,
                                    ntohs(tcph->source));
                if (iph->protocol == IPPROTO_TCP) {
                        slot = hash & adapter->filter_tcphash.ehash_mask;
                        head = &adapter->filter_tcphash.ehash[slot];
                } else if (iph->protocol == IPPROTO_UDP) {
                        slot = hash & adapter->filter_udphash.ehash_mask;
                        head = &adapter->filter_udphash.ehash[slot];
                } else
			goto free_si;

                break;
        case 0x6:
                {
                        const struct ipv6hdr *ip6h = (const struct ipv6hdr *)iph;
                        tcph = (struct tcphdr *)(ip6h + 1);

                        hash = t4_inet6_ehashfn(NULL,
                                             &ip6h->daddr, ntohs(tcph->dest),
                                             &ip6h->saddr,
                                             ntohs(tcph->source));
                        if (ip6h->nexthdr == IPPROTO_TCP) {
                                slot = hash & adapter->filter_tcphash.ehash_mask;
                                head = &adapter->filter_tcphash.ehash[slot];
                        } else if (ip6h->nexthdr == IPPROTO_UDP) {
                                slot = hash & adapter->filter_udphash.ehash_mask;
                                head = &adapter->filter_udphash.ehash[slot];
                        } else
				goto free_si;
                }

                break;
        default:
                goto free_si;
        };

        rxq->stats.pkts++;
        rcu_read_lock();
begin:
        hlist_nulls_for_each_entry_rcu(f, node, &head->chain, filter_nulls_node) {
                if ((f->filter_hash == hash) &&
                    (f->fs.val.lport == ntohs(tcph->dest)) &&
                    (f->fs.val.fport == ntohs(tcph->source))) {
                        goto out;
                }
        }
        /*
         * if the nulls value we got at the end of this lookup is
         * not the expected one, we must restart lookup.
         * We probably met an item that was moved to another chain.
         */
        if (get_nulls_value(node) != slot)
                goto begin;

out:
        rcu_read_unlock();
        if (f) {
                if (f->fs.val.proto == IPPROTO_UDP)
                        lock = &adapter->filter_udphash.ehash_filter_locks[f->filter_hash &
                                adapter->filter_udphash.ehash_filter_locks_mask];
                else
                        lock = &adapter->filter_tcphash.ehash_filter_locks[f->filter_hash &
                                adapter->filter_tcphash.ehash_filter_locks_mask];
		spin_lock_bh(lock);
		f->pkt_counter++;
		spin_unlock_bh(lock);
	}

        t4_pktgl_free(si);
        return 0;

free_si:
        t4_pktgl_free(si);
        rxq->stats.rx_drops++;
        return 0;
}


/*
 * Process an MPS trace packet.  Give it an unused protocol number so it won't
 * be delivered to anyone and send it to the stack for capture.
 */
static noinline int handle_trace_pkt(struct adapter *adap,
				     struct napi_struct *napi,
				     const struct pkt_gl *gl)
{
	struct sk_buff *skb;

	skb = cxgb4_pktgl_to_skb(napi, gl, RX_PULL_LEN, RX_PULL_LEN);
	if (unlikely(!skb)) {
		t4_pktgl_free(gl);
		return 0;
	}
	if (is_t4(adap->params.chip))
		__skb_pull(skb, sizeof(struct cpl_trace_pkt));
	else
		__skb_pull(skb, sizeof(struct cpl_t5_trace_pkt));

	skb_reset_mac_header(skb);
	skb->protocol = htons(0xffff);
	skb->dev = adap->port[0];
	netif_receive_skb(skb);
	return 0;
}

#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
enum {
	RX_NON_PTP_PKT = 0,
	RX_PTP_PKT_SUC = 1,
	RX_PTP_PKT_ERR = 2
};

/**
 *	t4_systim_to_hwstamp - read hardware time stamp
 *	@adap: the adapter
 *	@skb: the packet
 *
 *	Read Time Stamp from MPS packet and insert in skb which
 *	is forwarded to PTP application
 */
static noinline int t4_systim_to_hwstamp(struct adapter *adapter,
					 struct sk_buff *skb)
{
	struct skb_shared_hwtstamps *hwtstamps;
	struct cpl_rx_mps_pkt *cpl = NULL;
	unsigned char *data;
	int offset;

	cpl = (struct cpl_rx_mps_pkt *)skb->data;

	if (!(G_CPL_RX_MPS_PKT_TYPE(ntohl(cpl->op_to_r1_hi)) &
	      MPS_PKT_TYPE_PTP))
		return RX_PTP_PKT_ERR;

	data = skb->data + sizeof(*cpl);
	skb_pull(skb, 2 * sizeof(u64) + sizeof(struct cpl_rx_mps_pkt));
	offset = ETH_HLEN + IPV4_HLEN(skb->data) + UDP_HLEN;
	if (skb->len < offset + OFF_PTP_SEQUENCE_ID + sizeof(short))
		return RX_PTP_PKT_ERR;

	hwtstamps = skb_hwtstamps(skb);
	memset(hwtstamps, 0, sizeof(*hwtstamps));
	hwtstamps->hwtstamp = ns_to_ktime(be64_to_cpu(*((u64 *)data)));

	return RX_PTP_PKT_SUC;
}

/**
 *	t4_rx_hststamp - Recv PTP Event Message
 *	@adap: the adapter
 *	@rsp: the response queue descriptor holding the RX_PKT message
 *	@skb: the packet
 *
 *	PTP enabled and MPS packet, read HW timestamp
 */
static int t4_rx_hststamp(struct adapter *adapter, const __be64 *rsp,
			  struct sge_eth_rxq *rxq, struct sk_buff *skb)
{
	int ret;

	if (unlikely((*(u8 *)rsp == CPL_RX_MPS_PKT) &&
		     !is_t4(adapter->params.chip))) {
		ret = t4_systim_to_hwstamp(adapter, skb);
		if (ret == RX_PTP_PKT_ERR) {
			kfree_skb(skb);
			rxq->stats.rx_drops++;
		}
		return ret;
	}
	return RX_NON_PTP_PKT;
}

/**
 *	t4_tx_hststamp - Loopback PTP Transmit Event Message
 *	@adap: the adapter
 *	@skb: the packet
 *	@dev: the ingress net device
 *
 *	Read hardware timestamp for the loopback PTP Tx event message
 */
static int t4_tx_hststamp(struct adapter *adapter, struct sk_buff *skb,
			  struct net_device *dev)
{
	struct port_info *pi = netdev_priv(dev);

	if (!is_t4(adapter->params.chip) && adapter->ptp_tx_skb) {
		cxgb4_ptp_read_hwstamp(adapter, pi);
		kfree_skb(skb);
		return 0;
	}
	return 1;
}
#endif

#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,4))

/* Returns tunnel type if hardware supports offloading of the same */
enum cpl_tx_tnl_lso_type cxgb_encap_offload_supported(struct sk_buff *skb)
{
	u8 l4_hdr = 0;
	enum cpl_tx_tnl_lso_type tnl_type = TX_TNL_TYPE_OPAQUE;
	struct port_info *pi = netdev_priv(skb->dev);
	struct adapter *adapter = pi->adapter;

	if (skb->inner_protocol_type != ENCAP_TYPE_ETHER ||
	    skb->inner_protocol != htons(ETH_P_TEB))
		return tnl_type;

	switch (vlan_get_protocol(skb)) {
	case htons(ETH_P_IP):
		l4_hdr = ip_hdr(skb)->protocol;
		break;
	case htons(ETH_P_IPV6):
		l4_hdr = ipv6_hdr(skb)->nexthdr;
		break;
	default:
		return tnl_type;
	}

	switch (l4_hdr) {
	case IPPROTO_UDP:
		if (adapter->vxlan_port == udp_hdr(skb)->dest)
			tnl_type = TX_TNL_TYPE_VXLAN;
		break;
	case IPPROTO_GRE:
		if (!is_t5(adapter->params.chip))
			tnl_type = TX_TNL_TYPE_NVGRE;
		break;
	default:
		return tnl_type;
	}

	return tnl_type;
}
#endif

#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
/* Allocate buffer to store the headers for vxlan packets for gro */
void *refill_vxlan_hdr_buf(struct adapter *adap,
			   struct sge_eth_rxq *rxq, gfp_t gfp)
{
	struct sge *s = &adap->sge;
	int node;
	struct vxlan_buf_for_hdr *hdr_buf = &rxq->hdr_buf;

	gfp |= __GFP_NOWARN;         /* failures are expected */
	node = dev_to_node(adap->pdev_dev);

	/* Is there enough space to hold a header? */
	if ((hdr_buf->offset + MAX_ENCAP_HDR_SIZE) > hdr_buf->size) {
		/* Free the old filled page */
		if (hdr_buf->pg) {
			put_page(hdr_buf->pg);
			memset(hdr_buf, 0, sizeof(rxq->hdr_buf));
		}

		/* Allocate a new page */
		hdr_buf->pg = alloc_pages_node(node, gfp | __GFP_COMP,
					       s->fl_pg_order);
		if (unlikely(!hdr_buf->pg)) {
			hdr_buf->pg = alloc_pages_node(node, gfp, 0);
			if (unlikely(!hdr_buf->pg))
				return hdr_buf->pg;
			hdr_buf->size = PAGE_SIZE;
		} else {
			hdr_buf->size = PAGE_SIZE << s->fl_pg_order;
		}

		hdr_buf->offset = 0;
		/* Get the virtual address for copying headers */
		hdr_buf->va = page_address(hdr_buf->pg);
	}
	return hdr_buf->pg;
}

/**
 *	lb_vxlan_do_packet_coalesce - add an skb to a coalesce WR
 *	@txq: sge_eth_txq used send the skb
 *	@si: the gather list of packet fragments
 *	@flits: flits needed for this skb
 *	@adap: adapter structure
 *	@pi: port_info structure
 *
 *	Adds the received packte to be looped back as part of a coalesce WR
 *	by filling a ulp_tx_pkt command, ulp_tx_sc_imm command, cpl message and
 *	ulp_tx_sc_dsgl command. This is modelled on tx_do_packet_coalesce.
 */
static inline int lb_vxlan_do_packet_coalesce(struct sge_eth_txq *txq,
					      struct sge_rspq *rspq,
					      const __be64 *rsp,
					      const struct pkt_gl *si,
					      int flits, struct adapter *adap,
					      const struct port_info *pi)
{
	u64 cntrl, *end;
	struct sge_txq *q = &txq->q;
	struct ulp_txpkt *mc;
	struct ulptx_idata *sc_imm;
	struct cpl_tx_pkt_core *cpl;
	struct tx_sw_desc *sd;
	unsigned int idx = q->coalesce.idx, len = si->tot_len;
	const struct cpl_rx_pkt *pkt;
	int vxlan_headroom;
	struct ulptx_sgl *sgl;
	struct sge *s;
	struct ulptx_sge_pair *to;
	dma_addr_t addr;
	struct ulptx_sge_pair buf[MAX_SKB_FRAGS / 2 + 1];
	struct sge_eth_rxq *rxq;
	struct rx_sw_desc *rsd;

	s = &adap->sge;
	pkt = (void *)&rsp[1];
	rxq = container_of(rspq, struct sge_eth_rxq, rspq);

	/* Get the dma address of rx_desc where packet is received */
	rsd = &rxq->fl.sdesc[rxq->fl.cidx];
	addr = get_buf_addr(rsd);
	dma_sync_single_for_cpu(adap->pdev_dev,
				addr,
				len, DMA_FROM_DEVICE);
	addr += si->frags[0].offset;
	/* get a reference to the page */
	get_page(si->frags[0].page);

	if (q->coalesce.type == 0) {
		mc = (struct ulp_txpkt *)q->coalesce.ptr;
		mc->cmd_dest = htonl(V_ULPTX_CMD(4) | V_ULP_TXPKT_DEST(0) |
				V_ULP_TXPKT_FID(adap->sge.fw_evtq.cntxt_id) |
				F_ULP_TXPKT_RO);
		mc->len = htonl(DIV_ROUND_UP(flits, 2));

		sc_imm = (struct ulptx_idata *)(mc + 1);
		sc_imm->cmd_more = htonl(V_ULPTX_CMD(ULP_TX_SC_IMM) |
					 F_ULP_TX_SC_MORE);
		sc_imm->len = htonl(sizeof(*cpl));
		end = (u64 *)mc + flits;
		cpl = (struct cpl_tx_pkt_core *)(sc_imm + 1);
	} else {
		end = (u64 *)q->coalesce.ptr + flits;
		cpl = (struct cpl_tx_pkt_core *)q->coalesce.ptr;
	}

	sgl = (struct ulptx_sgl *)(cpl + 1); /* sgl start here */

	/* update coalesce structure for this txq */
	q->coalesce.flits += flits;
	q->coalesce.ptr += flits * sizeof(__be64);
	len -= s->pktshift;
	q->coalesce.len += len;

	/* fill the cpl message, same as in t4_eth_xmit, this should be kept
	 * similar to t4_eth_xmit
	 */
	cntrl = F_TXPKT_L4CSUM_DIS | F_TXPKT_IPCSUM_DIS;

	if (unlikely(pkt->vlan_ex)) {
		txq->vlan_ins++;
		cntrl |= F_TXPKT_VLAN_VLD | V_TXPKT_VLAN(ntohs(pkt->vlan));
	}

	/* loopback the packet */
	cpl->ctrl0 = htonl(V_TXPKT_OPCODE(CPL_TX_PKT_XT) |
			   V_TXPKT_INTF(pi->tx_chan + 4) |
			   V_TXPKT_PF(adap->pf));
	cpl->pack = htons(0);
	cpl->len = htons(len);
	cpl->ctrl1 = cpu_to_be64(cntrl);

	if (pkt->l2info & cpu_to_be32(F_RXF_IP))
		vxlan_headroom = VXLAN_HEADROOM;
	else
		vxlan_headroom = VXLAN6_HEADROOM;

	/* Prepare the sgl list.
	 * First sgl will point to innner packet.
	 */
	sgl->len0 = htonl(len - vxlan_headroom);
	sgl->addr0 = cpu_to_be64(addr + s->pktshift + vxlan_headroom);
	sgl->cmd_nsge = htonl(V_ULPTX_CMD(ULP_TX_SC_DSGL) |
			      V_ULPTX_NSGE(2));
	/* Most of the complexity below deals with the possibility we hit the
	 * end of the queue in the middle of writing the SGL.  For this case
	 * only we create the SGL in a temporary buffer and then copy it.
	 */
	to = (u8 *)end > (u8 *)txq->q.stat ? buf : sgl->sge;
	/* Second sgl will point to vxlan header and is
	 * padded at the end of the packet before loopback
	 */
	to->len[0] = cpu_to_be32(vxlan_headroom);
	to->len[1] = cpu_to_be32(0);
	to->addr[0] = cpu_to_be64(addr + s->pktshift);

	if (unlikely((u8 *)end > (u8 *)txq->q.stat)) {
		unsigned int part0 = (u8 *)txq->q.stat - (u8 *)sgl->sge, part1;

		if (likely(part0))
			memcpy(sgl->sge, buf, part0);
		part1 = (u8 *)end - (u8 *)txq->q.stat;
		memcpy(q->desc, (u8 *)buf + part0, part1);
		end = (void *)q->desc + part1;
	}
	if ((uintptr_t)end & 8)           /* 0-pad to multiple of 16 */
		*end = 0;

	/* store pointers to the page used in free_tx_desc */
	sd = &q->sdesc[q->pidx + (idx >> 1)];
	sd->coalesce.page[idx & 1] = si->frags[0].page;
	sd->coalesce.idx = (idx & 1) + 1;

	/* send the coaelsced work request if max reached */
	if (++q->coalesce.idx == ETH_COALESCE_PKT_NUM)
		ship_tx_pkt_coalesce_wr(adap, txq);

	return NETDEV_TX_OK;
}

/**
 *	t4_loopback_vxlan_packet - update and loopback an ingress vxlan packet
 *	@q: the response queue that received the packet
 *	@rsp: the response queue descriptor holding the RX_PKT message
 *	@si: the gather list of packet fragments
 *
 *	Process an ingress vxlan packet and send it over the loopback port.
 *	For the received vxlan packet, we will see if the checksum is
 *	verified for the outer header. Once it is found good,
 *	we will remove and put the outer header after the inner header and
 *	send it over the special egress queue. THis is modelled on t4_eth_xmit.
 */
int t4_loopback_vxlan_packet(struct sge_rspq *q, const __be64 *rsp,
			     const struct pkt_gl *si)
{
	u32 wr_mid;
	u64 cntrl, *end;
	struct ulptx_sgl *sgl;
	int credits, last_desc, len, vxlan_headroom;
	unsigned int flits, ndesc, cflits;
	struct fw_eth_tx_pkt_wr *wr;
	struct cpl_tx_pkt_core *cpl;
	unsigned int chip_ver;
	struct sge_eth_rxq *rxq;
	struct adapter *adap;
	struct sge *s;
	const struct port_info *pi;
	struct sge_eth_txq *txq;
	const struct cpl_rx_pkt *pkt;
	dma_addr_t addr;
	struct ulptx_sge_pair *to;
	struct ulptx_sge_pair buf[MAX_SKB_FRAGS / 2 + 1];
	struct rx_sw_desc *rsd;

	pkt = (void *)&rsp[1];
	rxq = container_of(q, struct sge_eth_rxq, rspq);
	adap = q->adap;
	s = &adap->sge;
	pi = netdev_priv(q->netdev);

	/* Get the special txq corresponding to this rxq */
	txq = &s->vxlantxq[pi->first_qset + rxq->rspq.idx];

	if (test_and_set_bit(VXLAN_TXQ_RUNNING, &txq->q.flags) != 0)
		return NETDEV_TX_BUSY;

	reclaim_completed_tx(adap, &txq->q, false);

	/* align the end fo coalesce WR to a 512 byte boundary */
	txq->q.coalesce.max = (8 - (txq->q.pidx & 7)) * 8;

	/* check if we can do packet coalescing */
	if (adap->tx_coal &&
	    should_tx_packet_coalesce(txq, NULL, &cflits, adap,
				      si->tot_len - s->pktshift)) {
		lb_vxlan_do_packet_coalesce(txq, q, rsp, si, cflits, adap, pi);
		clear_bit(VXLAN_TXQ_RUNNING, &txq->q.flags);
		return NETDEV_TX_OK;
	}

	cntrl = F_TXPKT_L4CSUM_DIS | F_TXPKT_IPCSUM_DIS;
	chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);

	/* We need 2 sgl elements. One to store the inner packet
	 * and the other to store the outer header as padding.
	 */
	flits = sgl_len(2);
	/* add the flits required for the headers */
	flits += (sizeof(struct fw_eth_tx_pkt_wr) +
		  sizeof(struct cpl_tx_pkt_core)) / sizeof(__be64);

	ndesc = flits_to_desc(flits);
	credits = txq_avail(&txq->q) - ndesc;
	if (unlikely(credits < 0)) {
		txq->q.stops++;
		clear_bit(VXLAN_TXQ_RUNNING, &txq->q.flags);
		return NETDEV_TX_BUSY;
	}

	/* Instead of allocating an skb, copying the fragements and
	 * dma mapping the memory, we will reuse the already obtained
	 * dma address from receive descriptor where this packet was
	 * received. */
	rsd = &rxq->fl.sdesc[rxq->fl.cidx];
	addr = get_buf_addr(rsd);
	dma_sync_single_for_cpu(q->adap->pdev_dev,
				addr,
				si->tot_len, DMA_FROM_DEVICE);

	addr += si->frags[0].offset;
	/* get a reference to the page */
	get_page(si->frags[0].page);

	wr_mid = V_FW_WR_LEN16(DIV_ROUND_UP(flits, 2));
	if (unlikely(credits < ETHTXQ_STOP_THRES))
		wr_mid |= F_FW_WR_EQUEQ | F_FW_WR_EQUIQ;

	/* request tx completion if needed for tx coalescing */
	if (adap->tx_coal && txq->q.coalesce.intr) {
		wr_mid |= F_FW_WR_EQUEQ | F_FW_WR_EQUIQ;
		txq->q.coalesce.intr = false;
	}

	wr = (void *)&txq->q.desc[txq->q.pidx];
	wr->equiq_to_len16 = htonl(wr_mid);
	wr->r3 = cpu_to_be64(0);
	end = (u64 *)wr + flits;

	len = sizeof(*cpl);

	wr->op_immdlen = htonl(V_FW_WR_OP(FW_ETH_TX_PKT_WR) |
			       V_FW_WR_IMMDLEN(len));
	cpl = (void *)(wr + 1);
	sgl = (struct ulptx_sgl *)(cpl + 1); /* sgl start here */

	if (unlikely(pkt->vlan_ex)) {
		txq->vlan_ins++;
		cntrl |= F_TXPKT_VLAN_VLD | V_TXPKT_VLAN(ntohs(pkt->vlan));
	}

	/* loopback the packet */
	cpl->ctrl0 = htonl(V_TXPKT_OPCODE(CPL_TX_PKT_XT) |
			   V_TXPKT_INTF(pi->tx_chan + 4) |
			   V_TXPKT_PF(adap->pf));

	cpl->pack = htons(0);
	cpl->len = htons(si->tot_len - s->pktshift);
	cpl->ctrl1 = cpu_to_be64(cntrl);

	if (pkt->l2info & cpu_to_be32(F_RXF_IP))
		vxlan_headroom = VXLAN_HEADROOM;
	else
		vxlan_headroom = VXLAN6_HEADROOM;
	/* Prepare the sgl list.
	 * First sgl will point to inner packet.
	 */
	sgl->len0 = htonl(si->tot_len - vxlan_headroom - s->pktshift);
	sgl->addr0 = cpu_to_be64(addr + s->pktshift + vxlan_headroom);
	sgl->cmd_nsge = htonl(V_ULPTX_CMD(ULP_TX_SC_DSGL) |
			      V_ULPTX_NSGE(2));
	/* Most of the complexity below deals with the possibility we hit the
	 * end of the queue in the middle of writing the SGL.  For this case
	 * only we create the SGL in a temporary buffer and then copy it.
	 */
	to = (u8 *)end > (u8 *)txq->q.stat ? buf : sgl->sge;
	/* Second sgl will point to vxlan header and is
	 * padded at the end of the packet before loopback
	 */
	to->len[0] = cpu_to_be32(vxlan_headroom);
	to->len[1] = cpu_to_be32(0);
	to->addr[0] = cpu_to_be64(addr + s->pktshift);

	if (unlikely((u8 *)end > (u8 *)txq->q.stat)) {
		unsigned int part0 = (u8 *)txq->q.stat - (u8 *)sgl->sge, part1;

		if (likely(part0))
			memcpy(sgl->sge, buf, part0);
		part1 = (u8 *)end - (u8 *)txq->q.stat;
		memcpy(q->desc, (u8 *)buf + part0, part1);
		end = (void *)q->desc + part1;
	}
	if ((uintptr_t)end & 8)           /* 0-pad to multiple of 16 */
		*end = 0;

	last_desc = txq->q.pidx + ndesc - 1;
	if (last_desc >= txq->q.size)
		last_desc -= txq->q.size;

	/* Store the page info for later to free */
	txq->q.sdesc[last_desc].page = si->frags[0].page;

	txq_advance(&txq->q, ndesc);
	ring_tx_db(adap, &txq->q, ndesc);
	clear_bit(VXLAN_TXQ_RUNNING, &txq->q.flags);

	return NETDEV_TX_OK;
}

/**
 *	t4_vxlan_lb_receive - process the loopbacked vxlan packet
 *	@q: the response queue that received the packet
 *	@rsp: the response queue descriptor holding the RX_PKT message
 *	@si: the gather list of packet fragments
 *
 *	Process an ingress loopbacked vxlan packet.
 *	We will move back the outer header to the front of the packet
 *	and deliver it to the stack. This is modelled on t4_ethrx_handler.
 */
int t4_vxlan_lb_receive(struct sge_rspq *q, const __be64 *rsp,
			struct pkt_gl *si)
{
	struct sk_buff *skb;
	struct port_info *pi;
	const struct cpl_rx_pkt *pkt;
	bool csum_ok;
	struct sge_eth_rxq *rxq = container_of(q, struct sge_eth_rxq, rspq);
	struct adapter *adapter = q->adap;
	struct sge *s = &adapter->sge;
	unsigned long eth_hdr_len, pkt_len, vxlan_hdr_len, cpl_pkt_len, l2info;
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	struct ethhdr *eh;

	pkt = (void *)&rsp[1];
	csum_ok = pkt->csum_calc && !pkt->err_vec &&
		  (q->netdev->features & NETIF_F_RXCSUM);

	l2info = be32_to_cpu(pkt->l2info);
	cpl_pkt_len = be16_to_cpu(pkt->len);
	eth_hdr_len = is_t4(adapter->params.chip) ?
			G_RX_ETHHDR_LEN(l2info) : G_RX_T5_ETHHDR_LEN(l2info);
	if (l2info & F_RXF_IP) {
		/* IPv4 packet */
		iph = (struct iphdr *)((u8 *)si->va + eth_hdr_len +
				       s->pktshift);
		pkt_len = ntohs(iph->tot_len);
	} else if (l2info & F_RXF_IP6) {
		/* IPv6 packet */
		ip6h = (struct ipv6hdr *)((u8 *)si->va + eth_hdr_len +
					  s->pktshift);
		pkt_len = ntohs(ip6h->payload_len) +
				G_RX_IPHDR_LEN(ntohs(pkt->hdr_len));
	} else {
		eh = (struct ethhdr *)((u8 *)si->va + s->pktshift);
		if (ntohs(eh->h_proto) == ETH_P_ARP)
			pkt_len = 28;
		else
			pkt_len = ntohs(eh->h_proto);
	}

	/* Get VxLAN outer header length */
	vxlan_hdr_len = cpl_pkt_len - eth_hdr_len - pkt_len;

	/* It is not looped back VxLAN packet if the padding is less than
	 * expected VxLAN header size.
	 */
	if (vxlan_hdr_len >= VXLAN_HEADROOM) {
		int offset = cpl_pkt_len - vxlan_hdr_len + s->pktshift;

		if (!is_vxlan_pkt((vxlan_hdr_len == VXLAN_HEADROOM), si,
				   offset, q->netdev))
			return -EINVAL;
	} else
		return -EINVAL;

	/* If this is a good TCP packet and we have Generic Receive Offload
	 * enabled, handle the packet in the GRO path.
	 */
	if ((pkt->l2info & cpu_to_be32(F_RXF_TCP)) &&
	    !(cxgb_poll_busy_polling(q)) &&
	    (q->netdev->features & NETIF_F_GRO) &&
	    csum_ok && !pkt->ip_frag && (si->nfrags == 1)) {
		do_gro(rxq, si, pkt, vxlan_hdr_len);
		return 0;
	}

	/* Below code is cxgb4_pktgl_to_skb equivalent.
	 * Here we need to rearrange received data.
	 * vxlan header which is at the end of the data should be copied to
	 * skb->data followed by inner packet which is at the beginning of
	 * gather list to skb frags.
	 */
	if (cpl_pkt_len <= RX_COPY_THRES) {
		skb = dev_alloc_skb(cpl_pkt_len);
		if (unlikely(!skb)) {
			t4_pktgl_free(si);
			rxq->stats.rx_drops++;
			return 0;
		}
		__skb_put(skb, cpl_pkt_len);
		/* Copy outer vxlan header */
		skb_copy_to_linear_data(skb, si->va + cpl_pkt_len -
					vxlan_hdr_len + s->pktshift,
					vxlan_hdr_len);
		/* Copy inner packet */
		skb_copy_to_linear_data_offset(skb, vxlan_hdr_len,
					       si->va + s->pktshift,
					       cpl_pkt_len - vxlan_hdr_len);
	} else {
		/* Should be >= vxlan_hdr_len but possibly bigger to give
		 * pskb_may_pull some room.
		 */
		skb = dev_alloc_skb(RX_PKT_SKB_LEN);
		if (unlikely(!skb)) {
			t4_pktgl_free(si);
			rxq->stats.rx_drops++;
			return 0;
		}
		__skb_put(skb, vxlan_hdr_len);
		/* Copy outer vxlan header to skb->data */
		skb_copy_to_linear_data(skb, si->va + cpl_pkt_len -
					vxlan_hdr_len + s->pktshift,
					vxlan_hdr_len);
		/* Copy inner packet to frags */
		__skb_fill_page_desc(skb, 0, si->frags[0].page,
				     si->frags[0].offset + s->pktshift,
				     cpl_pkt_len - vxlan_hdr_len);
		skb->len = cpl_pkt_len;
		skb->data_len = skb->len - vxlan_hdr_len;
		skb->truesize += skb->data_len;
		skb_shinfo(skb)->nr_frags = 1;
		/* get a reference to the page */
		get_page(si->frags[0].page);
	}

	skb->protocol = eth_type_trans(skb, q->netdev);
	skb_record_rx_queue(skb, q->idx);
	pi = netdev_priv(skb->dev);
	rxq->stats.pkts++;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
	if (pi->rxtstamp)
		cxgb4_sgetim_to_hwtstamp(adapter, skb_hwtstamps(skb),
					 si->sgetstamp);
#endif

	if (csum_ok && (pkt->l2info & htonl(F_RXF_UDP | F_RXF_TCP))) {
		if (!pkt->ip_frag) {
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			rxq->stats.rx_cso++;
		} else if (pkt->l2info & htonl(F_RXF_IP)) {
			__sum16 c = (__force __sum16)pkt->csum;

			skb->csum = csum_unfold(c);
			skb->ip_summed = CHECKSUM_COMPLETE;
			rxq->stats.rx_cso++;
		}
	} else {
		skb_checksum_none_assert(skb);

#ifdef CONFIG_PO_FCOE
#define CPL_RX_PKT_FLAGS (F_RXF_PSH | F_RXF_SYN | F_RXF_UDP | \
			  F_RXF_TCP | F_RXF_IP | F_RXF_IP6 | F_RXF_LRO)

		if (!(pkt->l2info & cpu_to_be32(CPL_RX_PKT_FLAGS))) {
			if ((pkt->l2info & cpu_to_be32(F_RXF_FCOE)) &&
			    (pi->fcoe.flags & CXGB_FCOE_ENABLED)) {
				if (!(pkt->err_vec & cpu_to_be16(F_RXERR_CSUM)))
					skb->ip_summed = CHECKSUM_UNNECESSARY;
			}
		}

#undef CPL_RX_PKT_FLAGS
#endif
	}

	if (unlikely(pkt->vlan_ex)) {
		__vlan_hwaccel_put_ctag(skb, ntohs(pkt->vlan));
		rxq->stats.vlan_ex++;
	}

	cxgb4_skb_mark_napi_id(skb, &q->napi);
	netif_receive_skb(skb);

	return 0;
}

/* Returns true, if the destination udp port is 8472 */
static inline bool is_vxlan_pkt(bool is_ipv4, const struct pkt_gl *si,
				u32 offset, struct net_device *dev)
{
	struct udphdr *udph;
	struct port_info *pi = netdev_priv(dev);

	offset += ETH_HLEN;

	if (is_ipv4) {
		struct iphdr *iph;

		iph = (struct iphdr *)((u8 *)si->va + offset);
		udph = (struct udphdr *)((u8 *)iph + (iph->ihl << 2));
	} else {
		struct ipv6hdr *ip6h;

		ip6h = (struct ipv6hdr *)((u8 *)si->va + offset);
		udph = (struct udphdr *)(ip6h + 1);
	}

	/* Check if destination port is a standard vxlan port */
	return (udph->dest == pi->adapter->vxlan_port);
}

/* Rearranges the looped back vxlan packet and fills it in skb fragments */
static void vxlan_copy_frags(struct sge_eth_rxq *rxq, const struct pkt_gl *gl,
			     const struct cpl_rx_pkt *pkt, struct sk_buff *skb,
			     unsigned long vxlan_hdr_len, unsigned int offset)
{
	struct vxlan_buf_for_hdr *hdr_buf = &rxq->hdr_buf;
	int pkt_hdr_len;
	struct adapter *adapter = rxq->rspq.adap;

	/* Find out header length of inner packet */
	switch (CHELSIO_CHIP_VERSION(adapter->params.chip)) {
	case CHELSIO_T4:
		pkt_hdr_len = G_RX_ETHHDR_LEN(htonl(pkt->l2info));
		break;
	case CHELSIO_T5:
		pkt_hdr_len = G_RX_T5_ETHHDR_LEN(htonl(pkt->l2info));
		break;
	case CHELSIO_T6:
	default:
		pkt_hdr_len = G_RX_T6_ETHHDR_LEN(htonl(pkt->l2info));
	}

	pkt_hdr_len += G_RX_IPHDR_LEN(ntohs(pkt->hdr_len));
	pkt_hdr_len += G_RX_TCPHDR_LEN(ntohs(pkt->hdr_len));

	/* If there is not enough space in the page
	 * to copy the headers, allocate a new page. */
	if (!refill_vxlan_hdr_buf(adapter, rxq, GFP_ATOMIC)) {
		t4_pktgl_free(gl);
		rxq->stats.rx_drops++;
		return;
	}

	/* Copy all the headers to the page and
	 * initialise it to first fragment in the skb.
	 */
	memcpy(hdr_buf->va + hdr_buf->offset,
	       gl->va + gl->tot_len - vxlan_hdr_len,
	       vxlan_hdr_len);
	memcpy(hdr_buf->va + hdr_buf->offset + vxlan_hdr_len,
	       gl->va + offset, pkt_hdr_len);

	__skb_fill_page_desc(skb, 0, hdr_buf->pg,
			     hdr_buf->offset,
			     pkt_hdr_len + vxlan_hdr_len);

	hdr_buf->offset += pkt_hdr_len + vxlan_hdr_len;
	/* get a reference to the page */
	get_page(hdr_buf->pg);

	/* initialise data to second fragment of the skb */
	__skb_fill_page_desc(skb, 1, gl->frags[0].page,
			     gl->frags[0].offset +
			     offset + pkt_hdr_len,
			     gl->tot_len - pkt_hdr_len -
			     vxlan_hdr_len - offset);
	/* get a reference to the page. */
	get_page(gl->frags[0].page);

	skb_shinfo(skb)->nr_frags = 2;
	/* Indicate that inner packet checksum is verified */
	skb->csum_level = 1;
}
#endif

/**
 *	t4_ethrx_handler - process an ingress ethernet packet
 *	@q: the response queue that received the packet
 *	@rsp: the response queue descriptor holding the RX_PKT message
 *	@si: the gather list of packet fragments
 *
 *	Process an ingress ethernet packet and deliver it to the stack.
 *	If it is a vxlan packet, we will do further processing in
 *	t4_loopback_vxlan_packet. Received loopbacked packet is further
 *	processed in t4_vxlan_lb_receive.
 */
int t4_ethrx_handler(struct sge_rspq *q, const __be64 *rsp,
		     const struct pkt_gl *si)
{
	struct sk_buff *skb;
	struct port_info *pi;
	const struct cpl_rx_pkt *pkt;
	bool csum_ok;
	struct sge_eth_rxq *rxq = container_of(q, struct sge_eth_rxq, rspq);
	struct adapter *adapter = q->adap;
	struct sge *s = &adapter->sge;
	unsigned int chip_ver = CHELSIO_CHIP_VERSION(adapter->params.chip);
	int cpl_trace_pkt = (chip_ver == CHELSIO_T4) ? CPL_TRACE_PKT :
					     CPL_T5_TRACE_PKT;
	u16 err_vec, tnl_type = 0, tnl_hdr_len = 0;
#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
	int ret = 0;
#endif

#ifdef CONFIG_PO_FCOE
	if (cxgb_fcoe_rx_handler(q, rsp))
		return 0;
#endif /* CONFIG_PO_FCOE */

	if (unlikely(*(u8 *)rsp == cpl_trace_pkt))
		return handle_trace_pkt(q->adap, &q->napi, si);

	pkt = (void *)&rsp[1];
	/* Compressed error vector is enabled for T6 only */
	if (adapter->params.tp.rx_pkt_encap) {
		/* It is enabled only in T6 config file */
		err_vec = G_T6_COMPR_RXERR_VEC(ntohs(pkt->err_vec));
		tnl_type = G_T6_RX_TNL_TYPE(ntohs(pkt->err_vec));
		tnl_hdr_len = G_T6_RX_TNLHDR_LEN(ntohs(pkt->err_vec));
	} else
		err_vec = ntohs(pkt->err_vec);

	csum_ok = pkt->csum_calc && !err_vec &&
		  (q->netdev->features & NETIF_F_RXCSUM);

#if IS_ENABLED(CONFIG_CXGB4_GRO) && IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
	/* Check if it is a vxlan packet ie udp destination port is 8472.
	 * Throughtput actually decreased with loopaback if GRO is not enabled.
	 * Hence vxlan offload will be enabled only when GRO is enabled.
	 * For T5, loopback of vxlan packets requires the interface to be in
	 * promiscous mode.
	 */
	if ((q->netdev->hw_enc_features & NETIF_F_RXCSUM) &&
	    (q->netdev->flags & IFF_PROMISC) &&
	    (pkt->l2info & cpu_to_be32(F_RXF_UDP)) && (si->nfrags == 1) &&
	    !(cxgb_poll_busy_polling(q)) && (chip_ver == CHELSIO_T5) &&
	    (q->netdev->features & NETIF_F_GRO) && csum_ok && !pkt->ip_frag) {
		/* Is it a vxlan packet? */
		if (is_vxlan_pkt(pkt->l2info & cpu_to_be32(F_RXF_IP), si,
				 s->pktshift, q->netdev)) {
			int ret;

			ret = t4_loopback_vxlan_packet(q, rsp, si);
			if (ret == NETDEV_TX_OK)
				return ret;
			/* Looping back this packet to verify inner packet
			 * checksum failied, probably due to lack of credits.
			 * Send it via regular receive path without updating
			 * csum_level for stack to verify the checksum.
			 */
		}
	}

	/* The packet received on one of the loopback port
	 * is a loopbacked VxLAN packet.
	 */
	if (pkt->iff >= NCHAN) {
		int ret = t4_vxlan_lb_receive(q, rsp, (struct pkt_gl *)si);

		if (!ret)
			return ret;
	}
#endif

#ifdef CONFIG_CXGB4_GRO
	/*
	 * If this is a good TCP packet and we have Generic Receive Offload
	 * enabled, handle the packet in the GRO path.
	 */
	if (((pkt->l2info & (cpu_to_be32(F_RXF_TCP))) ||
	    tnl_hdr_len) &&
	    !(cxgb_poll_busy_polling(q)) &&
	    (q->netdev->features & NETIF_F_GRO) && csum_ok && !pkt->ip_frag) {
		do_gro(rxq, si, pkt, tnl_hdr_len);
		return 0;
	}
#endif
	skb = cxgb4_pktgl_to_skb(&q->napi, si, RX_PKT_SKB_LEN, RX_PULL_LEN);
	if (unlikely(!skb)) {
		t4_pktgl_free(si);
		rxq->stats.rx_drops++;
		return 0;
	}
	pi = netdev_priv(q->netdev);

#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
	/* Handle PTP Event Rx packet */
	if (unlikely(pi->ptp_enable)) {
		ret = t4_rx_hststamp(adapter, rsp, rxq, skb);
		if (ret == RX_PTP_PKT_ERR)
			return 0;
	}
	if (likely(!ret))
#endif
		__skb_pull(skb, s->pktshift); /* remove ethernet hdr padding */

#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
	/* Handle the PTP Event Tx Loopback packet */
	if (unlikely(pi->ptp_enable && !ret &&
		     (pkt->l2info & htonl(F_RXF_UDP)) &&
		     cxgb4_ptp_is_ptp_rx(skb))) {
		if (!t4_tx_hststamp(adapter, skb, q->netdev))
			return 0;
	}
#endif
	skb->protocol = eth_type_trans(skb, q->netdev);
	skb_record_rx_queue(skb, q->idx);
	rxq->stats.pkts++;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
	if (pi->rxtstamp)
		cxgb4_sgetim_to_hwtstamp(adapter, skb_hwtstamps(skb),
					 si->sgetstamp);
#endif

	if (csum_ok && (pkt->l2info & htonl(F_RXF_UDP | F_RXF_TCP))) {
		if (!pkt->ip_frag) {
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			rxq->stats.rx_cso++;
		} else if (pkt->l2info & htonl(F_RXF_IP)) {
			__sum16 c = (__force __sum16)pkt->csum;
			skb->csum = csum_unfold(c);
			skb->ip_summed = CHECKSUM_COMPLETE;
			rxq->stats.rx_cso++;
		}
	} else {
		skb_checksum_none_assert(skb);

#ifdef CONFIG_PO_FCOE
#define CPL_RX_PKT_FLAGS (F_RXF_PSH | F_RXF_SYN | F_RXF_UDP | \
			  F_RXF_TCP | F_RXF_IP | F_RXF_IP6 | F_RXF_LRO)

		if (!(pkt->l2info & cpu_to_be32(CPL_RX_PKT_FLAGS))) {
			if ((pkt->l2info & cpu_to_be32(F_RXF_FCOE)) &&
			    (pi->fcoe.flags & CXGB_FCOE_ENABLED)) {
				if (adapter->params.tp.rx_pkt_encap)
					csum_ok = err_vec &
						  F_T6_COMPR_RXERR_CSUM;
				else
					csum_ok = err_vec & F_RXERR_CSUM;
				if (!csum_ok)
					skb->ip_summed = CHECKSUM_UNNECESSARY;
			}
		}

#undef CPL_RX_PKT_FLAGS
#endif
	}

	if (unlikely(pkt->vlan_ex)) {

		__vlan_hwaccel_put_ctag(skb, ntohs(pkt->vlan));
		rxq->stats.vlan_ex++;
	}

	cxgb4_skb_mark_napi_id(skb, &q->napi);
	netif_receive_skb(skb);

	return 0;
}

/**
 *	restore_rx_bufs - put back a packet's Rx buffers
 *	@si: the packet gather list
 *	@q: the SGE free list
 *	@frags: number of FL buffers to restore
 *
 *	Puts back on an FL the Rx buffers.  The buffers have already been
 *	unmapped and are left unmapped, we mark them so to prevent further
 *	unmapping attempts. 
 *
 *	This function undoes a series of @unmap_rx_buf calls when we find out
 *	that the current packet can't be processed right away afterall and we
 *	need to come back to it later.  This is a very rare event and there's
 *	no effort to make this particularly efficient.
 */
static void restore_rx_bufs(const struct pkt_gl *si,
			    struct sge_fl *q, int frags)
{
	struct rx_sw_desc *d;

	while (frags--) {
		if (q->cidx == 0)
			q->cidx = q->size - 1;
		else
			q->cidx--;
		d = &q->sdesc[q->cidx];

		/*
		 * Note that this is a purely software bit and is never
		 * sent to the hardware.
		 */
		d->page = si->frags[frags].page;
		d->dma_addr |= RX_UNMAPPED_BUF;
		q->avail++;
	}
}

/**
 *	is_new_response - check if a response is newly written
 *	@r: the response descriptor
 *	@q: the response queue
 *
 *	Returns true if a response descriptor contains a yet unprocessed
 *	response.
 */
static inline bool is_new_response(const struct rsp_ctrl *r,
				   const struct sge_rspq *q)
{
	return (r->u.type_gen >> S_RSPD_GEN) == q->gen;
}

/**
 *	rspq_next - advance to the next entry in a response queue
 *	@q: the queue
 *
 *	Updates the state of a response queue to advance it to the next entry.
 */
static inline void rspq_next(struct sge_rspq *q)
{
	q->cur_desc = (void *)q->cur_desc + q->iqe_len;
	if (unlikely(++q->cidx == q->size)) {
		q->cidx = 0;
		q->gen ^= 1;
		q->cur_desc = q->desc;
	}
}

/**
 *	process_responses - process responses from an SGE response queue
 *	@q: the ingress queue to process
 *	@budget: how many responses can be processed in this round
 *
 *	Process responses from an SGE response queue up to the supplied budget.
 *	Responses include received packets as well as control messages from FW
 *	or HW.
 *
 *	Additionally choose the interrupt holdoff time for the next interrupt
 *	on this queue.  If the system is under memory shortage use a fairly
 *	long delay to help recovery.
 */
static int process_responses(struct sge_rspq *q, int budget)
{
	int ret, rsp_type;
	int budget_left = budget;
	const struct rsp_ctrl *rc;
	struct sge_eth_rxq *rxq = container_of(q, struct sge_eth_rxq, rspq);
	struct adapter *adapter = q->adap;
	struct sge *s = &adapter->sge;

	while (likely(budget_left)) {
		rc = (void *)q->cur_desc + (q->iqe_len - sizeof(*rc));
		if (!is_new_response(rc, q)) {
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
			if (q->flush_handler)
				q->flush_handler(q);
#endif
			break;
		}

		dma_rmb();
		rsp_type = G_RSPD_TYPE(rc->u.type_gen);
		if (likely(rsp_type == X_RSPD_TYPE_FLBUF)) {
			struct page_frag *fp;
			struct pkt_gl si;
			const struct rx_sw_desc *rsd;
			u32 len = ntohl(rc->pldbuflen_qid), bufsz, frags;

			if (len & F_RSPD_NEWBUF) {
				if (likely(q->offset > 0)) {
					free_rx_bufs(q->adap, &rxq->fl, 1);
					q->offset = 0;
				}
				len = G_RSPD_LEN(len);
			}
			si.tot_len = len;

			/*
			 * Gather packet fragments.  Note that the use
			 * of q->offset in the loop below works
			 * because either the new Ingress Packet will
			 * be a single chunk in an existing Packed
			 * Buffer, or it will be in multiple chunks
			 * across more than one buffer.  In the latter
			 * case, the hardware will always start with a
			 * new buffer and so the offset for all of the
			 * chunks will be 0 ...
			 */
			for (frags = 0, fp = si.frags; ; frags++, fp++) {
				rsd = &rxq->fl.sdesc[rxq->fl.cidx];
				bufsz = get_buf_size(adapter, rsd);
				fp->page = rsd->page;
				fp->offset = q->offset;
				fp->size = min(bufsz, len);
				len -= fp->size;
				if (!len)
					break;
				unmap_rx_buf(q->adap, &rxq->fl);
			}

			si.sgetstamp = G_SGE_TIMESTAMP(
					be64_to_cpu(rc->u.last_flit));
			/*
			 * Last buffer remains mapped so explicitly
			 * make it coherent for CPU access.
			 */
			dma_sync_single_for_cpu(q->adap->pdev_dev,
						get_buf_addr(rsd),
						fp->size, DMA_FROM_DEVICE);

			si.va = page_address(si.frags[0].page) +
				si.frags[0].offset;
			prefetch(si.va);

			si.nfrags = frags + 1;
			ret = q->handler(q, q->cur_desc, &si);
			if (likely(ret == 0))
				q->offset += ALIGN(fp->size, s->fl_align);
			else
				restore_rx_bufs(&si, &rxq->fl, frags);
		} else if (likely(rsp_type == X_RSPD_TYPE_CPL)) {
			ret = q->handler(q, q->cur_desc, NULL);
		} else {
			ret = q->handler(q, (const __be64 *)rc, CXGB4_MSG_AN);
		}

		if (unlikely(ret)) {
			/* couldn't process descriptor, back off for recovery */
			q->next_intr_params = V_QINTR_TIMER_IDX(NOMEM_TMR_IDX);
			break;
		}

		rspq_next(q);
		budget_left--;
	}

	/*
	 * If this is a Response Queue with an associated Free List and
	 * there's room for another chunk of new Free List buffer pointers,
	 * refill the Free List.
	 */
	if (q->offset >= 0 && rxq->fl.size - rxq->fl.avail >= 16)
		__refill_fl(q->adap, &rxq->fl);
	return budget - budget_left;
}

#ifdef CONFIG_NET_RX_BUSY_POLL
int cxgb_busy_poll(struct napi_struct *napi)
{
	struct sge_rspq *q = container_of(napi, struct sge_rspq, napi);
	unsigned int params, work_done;
	u32 val;

	if (!cxgb_poll_lock_poll(q))
		return LL_FLUSH_BUSY;

	work_done = process_responses(q, 4);
	params = V_QINTR_TIMER_IDX(X_TIMERREG_COUNTER0) | V_QINTR_CNT_EN(1);
	q->next_intr_params = params;
	val = V_CIDXINC(work_done) | V_SEINTARM(params);

	/* If we don't have access to the new User GTS (T5+), use the old
	 * doorbell mechanism; otherwise use the new BAR2 mechanism.
	 */
	if (unlikely(!q->bar2_addr))
		t4_write_reg(q->adap, MYPF_REG(A_SGE_PF_GTS),
			     val | V_INGRESSQID((u32)q->cntxt_id));
	else {
		writel(val | V_INGRESSQID(q->bar2_qid),
		       q->bar2_addr + SGE_UDB_GTS);
		wmb();
	}

	cxgb_poll_unlock_poll(q);
	return work_done;
}
#endif /* CONFIG_NET_RX_BUSY_POLL */

/**
 *	napi_rx_handler - the NAPI handler for Rx processing
 *	@napi: the napi instance
 *	@budget: how many packets we can process in this round
 *
 *	Handler for new data events when using NAPI.  This does not need any
 *	locking or protection from interrupts as data interrupts are off at
 *	this point and other adapter interrupts do not interfere (the latter
 *	in not a concern at all with MSI-X as non-data interrupts then have
 *	a separate handler).
 */
static int napi_rx_handler(struct napi_struct *napi, int budget)
{
	unsigned int params;
	struct sge_rspq *q = container_of(napi, struct sge_rspq, napi);
	int work_done = 0;
	u32 val;

	if (!cxgb_poll_lock_napi(q))
		return budget;

	work_done = process_responses(q, budget);
	if (likely(work_done < budget)) {
		int timer_index;

		napi_complete_done(napi, work_done);
		timer_index = G_QINTR_TIMER_IDX(q->next_intr_params);

		if (q->adaptive_rx) {
			if (work_done > max(timer_pkt_quota[timer_index],
					    MIN_NAPI_WORK))
				timer_index = (timer_index + 1);
			else
				timer_index = timer_index - 1;

			timer_index = clamp(timer_index, 0, SGE_TIMERREGS-1);
			q->next_intr_params = V_QINTR_TIMER_IDX(timer_index) |
								V_QINTR_CNT_EN(0);
			params = q->next_intr_params;
		} else {
			params = q->next_intr_params;
			q->next_intr_params = q->intr_params;
		}
	} else
		params = V_QINTR_TIMER_IDX(X_TIMERREG_UPDATE_CIDX);

	val = V_CIDXINC(work_done) | V_SEINTARM(params);

	/* If we don't have access to the new User GTS (T5+), use the old
	 * doorbell mechanism; otherwise use the new BAR2 mechanism.
	 */
	if (unlikely(q->bar2_addr == NULL)) {
		t4_write_reg(q->adap, MYPF_REG(A_SGE_PF_GTS),
			     val | V_INGRESSQID((u32)q->cntxt_id));
	} else {
		writel(val | V_INGRESSQID(q->bar2_qid),
		       q->bar2_addr + SGE_UDB_GTS);
		wmb();
	}
	cxgb_poll_unlock_napi(q);
	return work_done;
}

/*
 * The MSI-X interrupt handler for an SGE response queue.
 */
irqreturn_t t4_sge_intr_msix(int irq, void *cookie)
{
	struct sge_rspq *q = cookie;

	napi_schedule(&q->napi);
	return IRQ_HANDLED;
}

/*
 * Process the indirect interrupt entries in the interrupt queue and kick off
 * NAPI for each queue that has generated an entry.
 */
static unsigned int process_intrq(struct adapter *adap)
{
	unsigned int credits;
	const struct rsp_ctrl *rc;
	struct sge_rspq *q = &adap->sge.intrq;
	u32 val;

	spin_lock(&adap->sge.intrq_lock);
	for (credits = 0; ; credits++) {
		rc = (void *)q->cur_desc + (q->iqe_len - sizeof(*rc));
		if (!is_new_response(rc, q))
			break;

		dma_rmb();
		if (G_RSPD_TYPE(rc->u.type_gen) == X_RSPD_TYPE_INTR) {
			unsigned int qid = ntohl(rc->pldbuflen_qid);

			qid -= adap->sge.ingr_start;
			napi_schedule(&adap->sge.ingr_map[qid]->napi);
		}

		rspq_next(q);
	}

	val = V_CIDXINC(credits) | V_SEINTARM(q->intr_params);

	/* If we don't have access to the new User GTS (T5+), use the old
	 * doorbell mechanism; otherwise use the new BAR2 mechanism.
	 */
	if (unlikely(q->bar2_addr == NULL)) {
		t4_write_reg(adap, MYPF_REG(A_SGE_PF_GTS),
			     val | V_INGRESSQID(q->cntxt_id));
	} else {
		writel(val | V_INGRESSQID(q->bar2_qid),
		       q->bar2_addr + SGE_UDB_GTS);
		wmb();
	}
	spin_unlock(&adap->sge.intrq_lock);
	return credits;
}

/*
 * The MSI interrupt handler, which handles data events from SGE response queues
 * as well as error and other async events as they all use the same MSI vector.
 */
static irqreturn_t t4_intr_msi(int irq, void *cookie)
{
	struct adapter *adap = cookie;

	if (adap->flags & MASTER_PF)
		t4_slow_intr_handler(adap);
	process_intrq(adap);
	return IRQ_HANDLED;
}

/*
 * Interrupt handler for legacy INTx interrupts for T4-based cards.
 * Handles data events from SGE response queues as well as error and other
 * async events as they all use the same interrupt line.
 */
static irqreturn_t t4_intr_intx(int irq, void *cookie)
{
	struct adapter *adap = cookie;

	t4_write_reg(adap, MYPF_REG(A_PCIE_PF_CLI), 0);
	if (((adap->flags & MASTER_PF) && t4_slow_intr_handler(adap)) |
	    process_intrq(adap))
		return IRQ_HANDLED;
	return IRQ_NONE;             /* probably shared interrupt */
}

/**
 *	t4_intr_handler - select the top-level interrupt handler
 *	@adap: the adapter
 *
 *	Selects the top-level interrupt handler based on the type of interrupts
 *	(MSI-X, MSI, or INTx).
 */
irq_handler_t t4_intr_handler(struct adapter *adap)
{
	if (adap->flags & USING_MSIX)
		return t4_sge_intr_msix;
	if (adap->flags & USING_MSI)
		return t4_intr_msi;
	return t4_intr_intx;
}

#define SGE_IDMA_MARK_DEAD 30

/**
 *	sge_rx_timer_cb - perform periodic maintenance of SGE Rx queues
 *	@data: the adapter
 *
 *	Runs periodically from a timer to perform maintenance of SGE Rx queues.
 *	It performs two tasks:
 *
 *	a) Replenishes Rx queues that have run out due to memory shortage.
 *	Normally new Rx buffers are added as existing ones are consumed but
 *	when out of memory a queue can become empty.  We schedule NAPI to do
 *	the actual refill.
 *
 *	b) Checks that the SGE is not stuck trying to deliver packets.  This
 *	typically indicates a programming error that has caused an Rx queue to
 *	be exhausted.
 */
static void sge_rx_timer_cb(unsigned long data)
{
	unsigned long m;
	unsigned int i;
	struct adapter *adap = (struct adapter *)data;
	struct sge *s = &adap->sge;

	for (i = 0; i < BITS_TO_LONGS(s->egr_sz); i++)
		for (m = s->starving_fl[i]; m; m &= m - 1) {
			struct sge_eth_rxq *rxq;
			unsigned int id = __ffs(m) + i * BITS_PER_LONG;
			struct sge_fl *fl = s->egr_map[id];

			clear_bit(id, s->starving_fl);
			smp_mb__after_atomic();

			/* Since we are accessing fl without a lock there's a
			 * small probability of a false positive where we
			 * schedule napi but the FL is no longer starving.
			 * No biggie.
			 */
			if (fl_starving(adap, fl)) {
				rxq = container_of(fl, struct sge_eth_rxq, fl);
				if (napi_reschedule(&rxq->rspq.napi))
					fl->starving++;
				else
					set_bit(id, s->starving_fl);
			}
		}

	/* The remainder of the SGE RX Timer Callback routine is dedicated to
	 * global Master PF activities like checking for chip ingress stalls,
	 * etc.
	 */
	if (!(adap->flags & MASTER_PF))
		goto done;

	if (!(test_bit(ADAPTER_ERROR, &adap->adap_err_state))) {
		t4_idma_monitor(adap, &s->idma_monitor, HZ, RX_QCHECK_PERIOD);

		/* Mark adapter as dead if stall > 30 seconds, OR if state is
		 * set to 3F, which is nothing but all 1's. This can happen
		 * only when adapter goes for a belly up.
		 */
		for (i=0; i<2; i++) {
			if (attempt_err_recovery &&
			    ((s->idma_monitor.idma_stalled[i] / HZ >
			      SGE_IDMA_MARK_DEAD) ||
			     s->idma_monitor.idma_state[i] == 0x3F)) {
				t4_fatal_err(adap);
				return;
			}
		}
	}

done:
	mod_timer(&s->rx_timer, jiffies + RX_QCHECK_PERIOD);
}

/**
 *	sge_tx_timer_cb - perform periodic maintenance of SGE Tx queues
 *	@data: the adapter
 *
 *	Runs periodically from a timer to perform maintenance of SGE Tx queues.
 *	It performs two tasks:
 *
 *	a) Restarts offload Tx queues stopped due to I/O MMU mapping errors.
 *
 *	b) Reclaims completed Tx packets for the Ethernet queues.  Normally
 *	packets are cleaned up by new Tx packets, this timer cleans up packets
 *	when no new packets are being submitted.  This is essential for pktgen,
 *	at least. Also reclaims completed loopbacked packets for VxLAN queues.
 */
static void sge_tx_timer_cb(unsigned long data)
{
	unsigned long m, period;
	unsigned int i, budget;
	struct adapter *adap = (struct adapter *)data;
	struct sge *s = &adap->sge;

	for (i = 0; i < BITS_TO_LONGS(s->egr_sz); i++)
		for (m = s->txq_maperr[i]; m; m &= m - 1) {
			unsigned long id = __ffs(m) + i * BITS_PER_LONG;
			struct sge_ofld_txq *txq = s->egr_map[id];

			clear_bit(id, s->txq_maperr);
			tasklet_schedule(&txq->qresume_tsk);
		}

#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
	/* Reclaim completed vxlan loopback packets.
	 * For now going through all the queues and not limiting
	 * to any budget (like for normal ethernet queues).
	 */
	if (is_t5(adap->params.chip)) {
		for (i = 0; i < s->ethqsets; i++) {
			struct sge_eth_txq *q = &s->vxlantxq[i];
			/* Is tx already running? */
			if (test_and_set_bit(VXLAN_TXQ_RUNNING,
					     &q->q.flags) == 0) {
				int avail = reclaimable(&q->q);

				if (avail) {
					free_tx_desc(adap, &q->q, avail, false);
					q->q.in_use -= avail;
				}

				/* if coalescing is on, ship the coal WR */
				if (q->q.coalesce.idx) {
					ship_tx_pkt_coalesce_wr(adap, q);
					q->q.coalesce.ison = false;
				}
				clear_bit(VXLAN_TXQ_RUNNING, &q->q.flags);
			}
		}
	}
#endif
#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
	if (!is_t4(adap->params.chip)) {
		struct sge_eth_txq *q = &s->ptptxq;
		int avail;

		spin_lock(&adap->ptp_lock);
		avail = reclaimable(&q->q);

		if (avail) {
			free_tx_desc(adap, &q->q, avail, false);
			q->q.in_use -= avail;
		}
		spin_unlock(&adap->ptp_lock);
	}
#endif

	budget = MAX_TIMER_TX_RECLAIM;
	i = s->ethtxq_rover;
	do {
		struct sge_eth_txq *q = &s->ethtxq[i];

		if (__netif_tx_trylock(q->txq)) {

			if (reclaimable(&q->q)) {
				int avail = reclaimable(&q->q);
				if (avail > budget)
					avail = budget;

				free_tx_desc(adap, &q->q, avail, true);
				q->q.in_use -= avail;

				budget -= avail;
				if (!budget){
					__netif_tx_unlock(q->txq);
					break;
				}
			}

			/* if coalescing is on, ship the coal WR */
			if (q->q.coalesce.idx) {
				ship_tx_pkt_coalesce_wr(adap, q);
				q->q.coalesce.ison = false;
			}
			__netif_tx_unlock(q->txq);
		}

		i++;
		if (i >= s->ethqsets)
			i = 0;
	} while (i != s->ethtxq_rover);
	s->ethtxq_rover = i;
	/* if we coalesce all the time, we need to run the timer more often */
	period = (adap->tx_coal == 2) ? (TX_QCHECK_PERIOD / 20) :
					TX_QCHECK_PERIOD;
	
	/*
	 * If we found too many reclaimable packets schedule a timer in the
	 * near future to continue where we left off.  Otherwise the next timer
	 * will be at its normal interval.
	 */
	mod_timer(&s->tx_timer, jiffies + (budget ? period : 2));
}

/**
 *	bar2_address - return the BAR2 address for an SGE Queue's Registers
 *	@adapter: the adapter
 *	@qid: the SGE Queue ID
 *	@qtype: the SGE Queue Type (Egress or Ingress)
 *	@pbar2_qid: BAR2 Queue ID or 0 for Queue ID inferred SGE Queues
 *
 *	Returns the BAR2 address for the SGE Queue Registers associated with
 *	@qid.  If BAR2 SGE Registers aren't available, returns NULL.  Also
 *	returns the BAR2 Queue ID to be used with writes to the BAR2 SGE
 *	Queue Registers.  If the BAR2 Queue ID is 0, then "Inferred Queue ID"
 *	Registers are supported (e.g. the Write Combining Doorbell Buffer).
 */
static void __iomem *bar2_address(struct adapter *adapter,
				  unsigned int qid,
				  enum t4_bar2_qtype qtype,
				  unsigned int *pbar2_qid)
{
	u64 bar2_qoffset;
	int ret;

	ret = t4_bar2_sge_qregs(adapter, qid, qtype, 0,
				&bar2_qoffset, pbar2_qid);
	if (ret)
		return NULL;

	return adapter->bar2 + bar2_qoffset;
}

/*
 * @intr_idx: MSI/MSI-X vector if >=0, -(absolute qid + 1) if < 0
 * @cong: < 0 -> no congestion feedback, >= 0 -> congestion channel map
 */
int t4_sge_alloc_rxq(struct adapter *adap, struct sge_rspq *iq, bool fwevtq,
		     struct net_device *dev, int intr_idx,
		     struct sge_fl *fl, rspq_handler_t hnd,
		     rspq_flush_handler_t flush_hnd, int cong)
{
	int ret, flsz = 0;
	struct fw_iq_cmd c;
	struct sge *s = &adap->sge;
	struct port_info *pi = netdev_priv(dev);

	/* Size needs to be multiple of 16, including status entry. */
	iq->size = roundup(iq->size, 16);

	iq->desc = alloc_ring(adap->pdev_dev, iq->size, iq->iqe_len, 0,
			      &iq->phys_addr, NULL, 0, dev_to_node(adap->pdev_dev));
	if (!iq->desc)
		return -ENOMEM;

	memset(&c, 0, sizeof(c));
	c.op_to_vfn = htonl(V_FW_CMD_OP(FW_IQ_CMD) | F_FW_CMD_REQUEST |
			    F_FW_CMD_WRITE | F_FW_CMD_EXEC |
			    V_FW_IQ_CMD_PFN(adap->pf) | V_FW_IQ_CMD_VFN(0));
	c.alloc_to_len16 = htonl(F_FW_IQ_CMD_ALLOC | F_FW_IQ_CMD_IQSTART |
				 FW_LEN16(c));
	c.type_to_iqandstindex = htonl(V_FW_IQ_CMD_TYPE(FW_IQ_TYPE_FL_INT_CAP) |
		V_FW_IQ_CMD_IQASYNCH(fwevtq) | V_FW_IQ_CMD_VIID(pi->viid) |
		V_FW_IQ_CMD_IQANDST(intr_idx < 0) |
		V_FW_IQ_CMD_IQANUD(X_UPDATEDELIVERY_INTERRUPT) |
		V_FW_IQ_CMD_IQANDSTINDEX(intr_idx >= 0 ? intr_idx :
							-intr_idx - 1));
	c.iqdroprss_to_iqesize = htons(V_FW_IQ_CMD_IQPCIECH(pi->tx_chan) |
		F_FW_IQ_CMD_IQGTSMODE |
		V_FW_IQ_CMD_IQINTCNTTHRESH(iq->pktcnt_idx) |
		V_FW_IQ_CMD_IQESIZE(ilog2(iq->iqe_len) - 4));
	c.iqsize = htons(iq->size);
	c.iqaddr = cpu_to_be64(iq->phys_addr);
	if (cong >= 0)
		c.iqns_to_fl0congen = htonl(F_FW_IQ_CMD_IQFLINTCONGEN);

	if (fl) {
		unsigned int chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);

		/* Allocate the ring for the hardware free list (with space
		 * for its status page) along with the associated software
		 * descriptor ring.  The free list size needs to be a multiple
		 * of the Egress Queue Unit and at least 2 Egress Units larger
		 * than the SGE's Egress Congrestion Threshold
		 * (fl_starve_thres - 1).
		 */
		if (fl->size < s->fl_starve_thres - 1 + 2 * 8)
			fl->size = s->fl_starve_thres - 1 + 2 * 8;
		fl->size = roundup(fl->size, 8);
		fl->desc = alloc_ring(adap->pdev_dev, fl->size, sizeof(__be64),
				      sizeof(struct rx_sw_desc), &fl->addr,
				      &fl->sdesc, s->stat_len, dev_to_node(adap->pdev_dev));
		if (!fl->desc)
			goto fl_nomem;

		flsz = fl->size / 8 + s->stat_len / sizeof(struct tx_desc);
		c.iqns_to_fl0congen |=
			htonl(V_FW_IQ_CMD_FL0HOSTFCMODE(X_HOSTFCMODE_NONE) |
			      F_FW_IQ_CMD_FL0PACKEN |
			      F_FW_IQ_CMD_FL0FETCHRO |
			      F_FW_IQ_CMD_FL0DATARO |
			      F_FW_IQ_CMD_FL0PADEN);
		if (cong >= 0)
			c.iqns_to_fl0congen |=
				htonl(V_FW_IQ_CMD_FL0CNGCHMAP(cong) |
				      F_FW_IQ_CMD_FL0CONGCIF |
				      F_FW_IQ_CMD_FL0CONGEN);

		/* In T6, for egress queue type FL there is internal overhead
		 * of 16B for header going into FLM module.  Hence the maximum
		 * allowed burst size is 448 bytes.  For T4/T5, the hardware
		 * doesn't coalesce fetch requests if more than 64 bytes of
		 * Free List pointers are provided, so we use a 128-byte Fetch
		 * Burst Minimum there (T6 implements coalescing so we can use
		 * the smaller 64-byte value there).
		 */
		c.fl0dcaen_to_fl0cidxfthresh =
			htons(V_FW_IQ_CMD_FL0FBMIN(chip_ver <= CHELSIO_T5
						   ? X_FETCHBURSTMIN_128B
						   : X_FETCHBURSTMIN_64B) |
			      V_FW_IQ_CMD_FL0FBMAX(chip_ver <= CHELSIO_T5
						   ? X_FETCHBURSTMAX_512B
						   : X_FETCHBURSTMAX_256B) |
			      V_FW_IQ_CMD_FL0CIDXFTHRESH(X_CIDXFLUSHTHRESH_1));
		c.fl0size = htons(flsz);
		c.fl0addr = cpu_to_be64(fl->addr);
	}

	ret = t4_wr_mbox(adap, adap->mbox, &c, sizeof(c), &c);
	if (ret)
		goto err;

	netif_napi_add(dev, &iq->napi, napi_rx_handler, 64);
	cxgb4_napi_hash_add(&iq->napi);
	iq->cur_desc = iq->desc;
	iq->cidx = 0;
	iq->gen = 1;
	iq->next_intr_params = iq->intr_params;
	iq->cntxt_id = ntohs(c.iqid);
	iq->abs_id = ntohs(c.physiqid);
	iq->bar2_addr = bar2_address(adap,
				     iq->cntxt_id,
				     T4_BAR2_QTYPE_INGRESS,
				     &iq->bar2_qid);
	iq->size--;                           /* subtract status entry */
	iq->netdev = dev;   // XXX use napi.dev in newer kernels
	iq->handler = hnd;
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	iq->flush_handler = flush_hnd;
	memset(&iq->lro_mgr, 0, sizeof(struct t4_lro_mgr));
	skb_queue_head_init(&iq->lro_mgr.lroq);
#endif

	/* set offset to -1 to distinguish ingress queues without FL */
	iq->offset = fl ? 0 : -1;

	adap->sge.ingr_map[iq->cntxt_id - adap->sge.ingr_start] = iq;

	if (fl) {
		fl->cntxt_id = ntohs(c.fl0id);
		fl->avail = fl->pend_cred = 0;
		fl->pidx = fl->cidx = 0;
		fl->alloc_failed = fl->large_alloc_failed = fl->starving = 0;
		adap->sge.egr_map[fl->cntxt_id - adap->sge.egr_start] = fl;

		/* Note, we must initialize the BAR2 Free List User Doorbell
		 * information before refilling the Free List!
		 */
		fl->bar2_addr = bar2_address(adap,
					     fl->cntxt_id,
					     T4_BAR2_QTYPE_EGRESS,
					     &fl->bar2_qid);

		refill_fl(adap, fl, fl_cap(fl), GFP_KERNEL);
	}

	/* For T5 and later we attempt to set up the Congestion Manager values
	 * of the new RX Ethernet Queue.  This should really be handled by
	 * firmware because it's more complex than any host driver wants to
	 * get involved with and it's different per chip and this is almost
	 * certainly wrong.  Firmware would be wrong as well, but it would be
	 * a lot easier to fix in one place ...  For now we do something very
	 * simple (and hopefully less wrong).
	 */
	if (!is_t4(adap->params.chip) && cong >= 0) {
		u32 param, val, ch_map = 0;
		int i;
		u16 cng_ch_bits_log = adap->params.arch.cng_ch_bits_log;

		param = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DMAQ) |
			 V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DMAQ_CONM_CTXT) |
			 V_FW_PARAMS_PARAM_YZ(iq->cntxt_id));
		if (cong == 0) {
			val = V_CONMCTXT_CNGTPMODE(X_CONMCTXT_CNGTPMODE_QUEUE);
		} else {
			val = V_CONMCTXT_CNGTPMODE(X_CONMCTXT_CNGTPMODE_CHANNEL);
			for (i = 0; i < 4; i++) {
				if (cong & (1 << i))
					ch_map |= 1 << (i << cng_ch_bits_log);
			}
			val |= V_CONMCTXT_CNGCHMAP(ch_map);
		}
		ret = t4_set_params(adap, adap->mbox, adap->pf, 0, 1,
				    &param, &val);
		if (ret)
			dev_warn(adap->pdev_dev, "Failed to set Congestion"
				 " Manager Context for Ingress Queue %d: %d\n",
				 iq->cntxt_id, -ret);
	}

	return 0;

fl_nomem:
	ret = -ENOMEM;
err:
	if (iq->desc) {
		dma_free_coherent(adap->pdev_dev, iq->size * iq->iqe_len,
				  iq->desc, iq->phys_addr);
		iq->desc = NULL;
	}
	if (fl && fl->desc) {
		kfree(fl->sdesc);
		fl->sdesc = NULL;
		dma_free_coherent(adap->pdev_dev, flsz * sizeof(struct tx_desc),
				  fl->desc, fl->addr);
		fl->desc = NULL;
	}
	return ret;
}

static void init_txq(struct adapter *adap, struct sge_txq *q, unsigned int id)
{
	q->cntxt_id = id;
	q->bar2_addr = bar2_address(adap,
				    q->cntxt_id,
				    T4_BAR2_QTYPE_EGRESS,
				    &q->bar2_qid);
	q->in_use = 0;
	q->cidx = q->pidx = 0;
	q->stops = q->restarts = 0;
	q->coalesce.idx = q->coalesce.flits = 0;
	q->coalesce.ison = q->coalesce.intr = false;
	q->stat = (void *)&q->desc[q->size];
	q->txp = 0;
	spin_lock_init(&q->db_lock);
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
	clear_bit(VXLAN_TXQ_RUNNING, &q->flags);
#endif
	q->is_vxlan_lb = 0;
	adap->sge.egr_map[id - adap->sge.egr_start] = q;
}

int t4_sge_alloc_eth_txq(struct adapter *adap, struct sge_eth_txq *txq,
			 struct net_device *dev, struct netdev_queue *netdevq,
			 unsigned int iqid)
{
	int ret, nentries;
	struct fw_eq_eth_cmd c;
	struct sge *s = &adap->sge;
	struct port_info *pi = netdev_priv(dev);

	/* Add status entries */
	nentries = txq->q.size + s->stat_len / sizeof(struct tx_desc);

	txq->q.desc = alloc_ring(adap->pdev_dev, txq->q.size,
			sizeof(struct tx_desc), sizeof(struct tx_sw_desc),
			&txq->q.phys_addr, &txq->q.sdesc, s->stat_len,
			netdev_queue_numa_node_read(netdevq));
	if (!txq->q.desc)
		return -ENOMEM;

	memset(&c, 0, sizeof(c));
	c.op_to_vfn = htonl(V_FW_CMD_OP(FW_EQ_ETH_CMD) | F_FW_CMD_REQUEST |
			    F_FW_CMD_WRITE | F_FW_CMD_EXEC |
			    V_FW_EQ_ETH_CMD_PFN(adap->pf) |
			    V_FW_EQ_ETH_CMD_VFN(0));
	c.alloc_to_len16 = htonl(F_FW_EQ_ETH_CMD_ALLOC |
				 F_FW_EQ_ETH_CMD_EQSTART | (sizeof(c) / 16));
	c.autoequiqe_to_viid = htonl(F_FW_EQ_ETH_CMD_AUTOEQUEQE |
				     V_FW_EQ_ETH_CMD_VIID(pi->viid));
	c.fetchszm_to_iqid =
		htonl(V_FW_EQ_ETH_CMD_HOSTFCMODE(X_HOSTFCMODE_STATUS_PAGE) |
		      V_FW_EQ_ETH_CMD_PCIECHN(pi->tx_chan) |
		      F_FW_EQ_ETH_CMD_FETCHRO | V_FW_EQ_ETH_CMD_IQID(iqid));
	c.dcaen_to_eqsize =
		htonl(V_FW_EQ_ETH_CMD_FBMIN(X_FETCHBURSTMIN_64B) |
		      V_FW_EQ_ETH_CMD_FBMAX(X_FETCHBURSTMAX_512B) |
		      V_FW_EQ_ETH_CMD_CIDXFTHRESH(X_CIDXFLUSHTHRESH_32) |
		      V_FW_EQ_ETH_CMD_EQSIZE(nentries));
	c.eqaddr = cpu_to_be64(txq->q.phys_addr);

	ret = t4_wr_mbox(adap, adap->mbox, &c, sizeof(c), &c);
	if (ret) {
		kfree(txq->q.sdesc);
		txq->q.sdesc = NULL;
		dma_free_coherent(adap->pdev_dev,
				  nentries * sizeof(struct tx_desc),
				  txq->q.desc, txq->q.phys_addr);
		txq->q.desc = NULL;
		return ret;
	}

	init_txq(adap, &txq->q, G_FW_EQ_ETH_CMD_EQID(ntohl(c.eqid_pkd)));
	txq->txq = netdevq;
	txq->tso = txq->tx_cso = txq->vlan_ins = 0;
	txq->mapping_err = 0;
	return 0;
}

int t4_sge_alloc_ctrl_txq(struct adapter *adap, struct sge_ctrl_txq *txq,
			  struct net_device *dev, unsigned int iqid,
			  unsigned int cmplqid)
{
	int ret, nentries;
	struct fw_eq_ctrl_cmd c;
	struct sge *s = &adap->sge;
	struct port_info *pi = netdev_priv(dev);

	/* Add status entries */
	nentries = txq->q.size + s->stat_len / sizeof(struct tx_desc);

	txq->q.desc = alloc_ring(adap->pdev_dev, nentries,
				 sizeof(struct tx_desc), 0, &txq->q.phys_addr,
				 NULL, 0, dev_to_node(adap->pdev_dev));
	if (!txq->q.desc)
		return -ENOMEM;

	c.op_to_vfn = htonl(V_FW_CMD_OP(FW_EQ_CTRL_CMD) | F_FW_CMD_REQUEST |
			    F_FW_CMD_WRITE | F_FW_CMD_EXEC |
			    V_FW_EQ_CTRL_CMD_PFN(adap->pf) |
			    V_FW_EQ_CTRL_CMD_VFN(0));
	c.alloc_to_len16 = htonl(F_FW_EQ_CTRL_CMD_ALLOC |
				 F_FW_EQ_CTRL_CMD_EQSTART | (sizeof(c) / 16));
	c.cmpliqid_eqid = htonl(V_FW_EQ_CTRL_CMD_CMPLIQID(cmplqid));
	c.physeqid_pkd = htonl(0);
	c.fetchszm_to_iqid =
		htonl(V_FW_EQ_CTRL_CMD_HOSTFCMODE(X_HOSTFCMODE_STATUS_PAGE) |
		      V_FW_EQ_CTRL_CMD_PCIECHN(pi->tx_chan) |
		      F_FW_EQ_CTRL_CMD_FETCHRO | V_FW_EQ_CTRL_CMD_IQID(iqid));
	c.dcaen_to_eqsize =
		htonl(V_FW_EQ_CTRL_CMD_FBMIN(X_FETCHBURSTMIN_64B) |
		      V_FW_EQ_CTRL_CMD_FBMAX(X_FETCHBURSTMAX_512B) |
		      V_FW_EQ_CTRL_CMD_CIDXFTHRESH(X_CIDXFLUSHTHRESH_32) |
		      V_FW_EQ_CTRL_CMD_EQSIZE(nentries));
	c.eqaddr = cpu_to_be64(txq->q.phys_addr);

	ret = t4_wr_mbox(adap, adap->mbox, &c, sizeof(c), &c);
	if (ret) {
		dma_free_coherent(adap->pdev_dev,
				  nentries * sizeof(struct tx_desc),
				  txq->q.desc, txq->q.phys_addr);
		txq->q.desc = NULL;
		return ret;
	}

	init_txq(adap, &txq->q, G_FW_EQ_CTRL_CMD_EQID(ntohl(c.cmpliqid_eqid)));
	txq->adap = adap;
	skb_queue_head_init(&txq->sendq);
	tasklet_init(&txq->qresume_tsk, restart_ctrlq, (unsigned long)txq);
	txq->full = 0;
	return 0;
}

int t4_sge_alloc_ofld_txq(struct adapter *adap, struct sge_ofld_txq *txq,
			  struct net_device *dev, unsigned int iqid)
{
	int ret, nentries;
	struct fw_eq_ofld_cmd c;
	struct sge *s = &adap->sge;
	struct port_info *pi = netdev_priv(dev);

	/* Add status entries */
	nentries = txq->q.size + s->stat_len / sizeof(struct tx_desc);

	txq->q.desc = alloc_ring(adap->pdev_dev, txq->q.size,
			sizeof(struct tx_desc), sizeof(struct tx_sw_desc),
			&txq->q.phys_addr, &txq->q.sdesc, s->stat_len,
			NUMA_NO_NODE);
	if (!txq->q.desc)
		return -ENOMEM;

	memset(&c, 0, sizeof(c));
	c.op_to_vfn = htonl(V_FW_CMD_OP(FW_EQ_OFLD_CMD) | F_FW_CMD_REQUEST |
			    F_FW_CMD_WRITE | F_FW_CMD_EXEC |
			    V_FW_EQ_OFLD_CMD_PFN(adap->pf) |
			    V_FW_EQ_OFLD_CMD_VFN(0));
	c.alloc_to_len16 = htonl(F_FW_EQ_OFLD_CMD_ALLOC |
				 F_FW_EQ_OFLD_CMD_EQSTART | (sizeof(c) / 16));
	c.fetchszm_to_iqid =
		htonl(V_FW_EQ_OFLD_CMD_HOSTFCMODE(X_HOSTFCMODE_STATUS_PAGE) |
		      V_FW_EQ_OFLD_CMD_PCIECHN(pi->tx_chan) |
		      F_FW_EQ_OFLD_CMD_FETCHRO | V_FW_EQ_OFLD_CMD_IQID(iqid));
	c.dcaen_to_eqsize =
		htonl(V_FW_EQ_OFLD_CMD_FBMIN(X_FETCHBURSTMIN_64B) |
		      V_FW_EQ_OFLD_CMD_FBMAX(X_FETCHBURSTMAX_512B) |
		      V_FW_EQ_OFLD_CMD_CIDXFTHRESH(X_CIDXFLUSHTHRESH_32) |
		      V_FW_EQ_OFLD_CMD_EQSIZE(nentries));
	c.eqaddr = cpu_to_be64(txq->q.phys_addr);

	ret = t4_wr_mbox(adap, adap->mbox, &c, sizeof(c), &c);
	if (ret) {
		kfree(txq->q.sdesc);
		txq->q.sdesc = NULL;
		dma_free_coherent(adap->pdev_dev,
				  nentries * sizeof(struct tx_desc),
				  txq->q.desc, txq->q.phys_addr);
		txq->q.desc = NULL;
		return ret;
	}

	init_txq(adap, &txq->q, G_FW_EQ_OFLD_CMD_EQID(ntohl(c.eqid_pkd)));
	txq->adap = adap;
	skb_queue_head_init(&txq->sendq);
	tasklet_init(&txq->qresume_tsk, restart_ofldq, (unsigned long)txq);
	txq->full = 0;
	txq->mapping_err = 0;

	return 0;
}

static void free_txq(struct adapter *adap, struct sge_txq *q)
{
	struct sge *s = &adap->sge;

	dma_free_coherent(adap->pdev_dev,
			  q->size * sizeof(struct tx_desc) + s->stat_len,
			  q->desc, q->phys_addr);
	q->cntxt_id = 0;
	q->sdesc = NULL;
	q->desc = NULL;
}

static void free_rspq_fl(struct adapter *adap, struct sge_rspq *rq,
			 struct sge_fl *fl)
{
	struct sge *s = &adap->sge;
	unsigned int fl_id = fl ? fl->cntxt_id : 0xffff;

	adap->sge.ingr_map[rq->cntxt_id - adap->sge.ingr_start] = NULL;
	if (!(test_bit(ADAPTER_ERROR, &adap->adap_err_state)))
		t4_iq_free(adap, adap->mbox, adap->pf, 0, FW_IQ_TYPE_FL_INT_CAP,
			   rq->cntxt_id, fl_id, 0xffff);
	dma_free_coherent(adap->pdev_dev, (rq->size + 1) * rq->iqe_len,
			  rq->desc, rq->phys_addr);
	cxgb4_napi_hash_del(&rq->napi);
	netif_napi_del(&rq->napi);
	rq->netdev = NULL;
	rq->cntxt_id = rq->abs_id = 0;
	rq->desc = NULL;

	if (fl) {
		free_rx_bufs(adap, fl, fl->avail);
		dma_free_coherent(adap->pdev_dev, fl->size * 8 + s->stat_len,
				  fl->desc, fl->addr);
		kfree(fl->sdesc);
		fl->sdesc = NULL;
		fl->cntxt_id = 0;
		fl->desc = NULL;
	}
}

/**
 *	t4_free_ofld_rxqs - free a block of consecutive Rx queues
 *	@adap: the adapter
 *	@n: number of queues
 *	@q: pointer to first queue
 *
 *	Release the resources of a consecutive block of offload Rx queues.
 */
void t4_free_ofld_rxqs(struct adapter *adap, int n, struct sge_ofld_rxq *q)
{
	for ( ; n; n--, q++)
		if (q->rspq.desc)
			free_rspq_fl(adap, &q->rspq,
				     q->fl.size ? &q->fl : NULL);
}

/**
 *	t4_free_sge_resources - free SGE resources
 *	@adap: the adapter
 *
 *	Frees resources used by the SGE queue sets.
 */
void t4_free_sge_resources(struct adapter *adap)
{
	int i;
	struct sge_eth_rxq *eq = adap->sge.ethrxq;
	struct sge_eth_txq *etq = adap->sge.ethtxq;

	/* clean up Ethernet Tx/Rx queues */
	for (i = 0; i < adap->sge.ethqsets; i++, eq++, etq++) {
		if (eq->rspq.desc)
			free_rspq_fl(adap, &eq->rspq,
				     eq->fl.size ? &eq->fl : NULL);
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
		if (eq->hdr_buf.pg) {
			put_page(eq->hdr_buf.pg);
			memset(&eq->hdr_buf, 0, sizeof(eq->hdr_buf));
		}
#endif
		if (etq->q.desc) {
			if (!(test_bit(ADAPTER_ERROR, &adap->adap_err_state)))
				t4_eth_eq_free(adap, adap->mbox, adap->pf, 0,
					       etq->q.cntxt_id);
			__netif_tx_lock(etq->txq, smp_processor_id());
			free_tx_desc(adap, &etq->q, etq->q.in_use, true);
			__netif_tx_unlock(etq->txq);
			kfree(etq->q.sdesc);
			free_txq(adap, &etq->q);
		}
	}

	/* clean up TOE, RDMA and iSCSI Rx queues */
	t4_free_ofld_rxqs(adap, adap->sge.ofldqsets, adap->sge.ofldrxq);
	t4_free_ofld_rxqs(adap, adap->sge.rdmaqs, adap->sge.rdmarxq);
	t4_free_ofld_rxqs(adap, adap->sge.rdmaciqs, adap->sge.rdmaciq);
	t4_free_ofld_rxqs(adap, adap->sge.niscsiq, adap->sge.iscsirxq);

	/* clean up offload Tx queues */
	for (i = 0; i < ARRAY_SIZE(adap->sge.ofldtxq); i++) {
		struct sge_ofld_txq *q = &adap->sge.ofldtxq[i];

		if (q->q.desc) {
			tasklet_kill(&q->qresume_tsk);
			if (!(test_bit(ADAPTER_ERROR, &adap->adap_err_state)))
				t4_ofld_eq_free(adap, adap->mbox, adap->pf,
						0, q->q.cntxt_id);
			free_tx_desc(adap, &q->q, q->q.in_use, false);
			kfree(q->q.sdesc);
			__skb_queue_purge(&q->sendq);
			free_txq(adap, &q->q);
		}
	}

	/* clean up control Tx queues */
	for (i = 0; i < ARRAY_SIZE(adap->sge.ctrlq); i++) {
		struct sge_ctrl_txq *cq = &adap->sge.ctrlq[i];

		if (cq->q.desc) {
			tasklet_kill(&cq->qresume_tsk);
			if (!(test_bit(ADAPTER_ERROR, &adap->adap_err_state)))
				t4_ctrl_eq_free(adap, adap->mbox, adap->pf, 0,
						cq->q.cntxt_id);
			__skb_queue_purge(&cq->sendq);
			free_txq(adap, &cq->q);
		}
	}

	if (adap->sge.fw_evtq.desc)
		free_rspq_fl(adap, &adap->sge.fw_evtq, NULL);

	if (adap->sge.intrq.desc)
		free_rspq_fl(adap, &adap->sge.intrq, NULL);

	if (is_hashfilter(adap) && is_t5(adap->params.chip)) {
		struct sge_eth_rxq *q = adap->sge.traceq;
		int n = adap->sge.ntraceq;
		for (; n ; n--, q++)
			if (q->rspq.desc)
				free_rspq_fl(adap, &q->rspq,
					     q->fl.size ? &q->fl : NULL);
	}

#ifdef CONFIG_T4_MA_FAILOVER
	if (is_offload(adap)) {
		if (adap->sge.failoverq.rspq.desc)
			free_rspq_fl(adap, &adap->sge.failoverq.rspq,
				     adap->sge.failoverq.fl.size ?
				     &adap->sge.failoverq.fl : NULL);
	}
#endif

#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
	/* clean up the vxlan queues */
	etq = adap->sge.vxlantxq;
	for (i = 0; i < adap->sge.ethqsets; i++, etq++) {
		if (etq->q.desc) {
			t4_eth_eq_free(adap, adap->mbox, adap->pf, 0,
				       etq->q.cntxt_id);
			free_tx_desc(adap, &etq->q, etq->q.in_use, false);
			kfree(etq->q.sdesc);
			free_txq(adap, &etq->q);
		}
	}
#endif

#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
	if (!is_t4(adap->params.chip)) {
		etq = &adap->sge.ptptxq;
		if (etq->q.desc) {
			t4_eth_eq_free(adap, adap->mbox, adap->pf, 0,
				       etq->q.cntxt_id);
			spin_lock(&adap->ptp_lock);
			free_tx_desc(adap, &etq->q, etq->q.in_use, true);
			spin_unlock(&adap->ptp_lock);
			kfree(etq->q.sdesc);
			free_txq(adap, &etq->q);
		}
	}
#endif

	/* clear the reverse egress queue map */
	memset(adap->sge.egr_map, 0,
	       adap->sge.egr_sz * sizeof(*adap->sge.egr_map));
}

void t4_sge_start(struct adapter *adap)
{
	adap->sge.ethtxq_rover = 0;
	mod_timer(&adap->sge.rx_timer, jiffies + RX_QCHECK_PERIOD);
	mod_timer(&adap->sge.tx_timer, jiffies + TX_QCHECK_PERIOD);
}

/**
 *	t4_sge_init_tasklet - Init tasklets associated with the DMA engine.
 *	@adap: the adapter
 */
void t4_sge_init_tasklet(struct adapter *adap)
{
	int i;
	struct sge *s = &adap->sge;

	for (i = 0; i < ARRAY_SIZE(s->ofldtxq); i++) {
		struct sge_ofld_txq *q = &s->ofldtxq[i];

		if (q->q.desc)
			tasklet_init(&q->qresume_tsk, restart_ofldq, (unsigned long)q);
	}
	for (i = 0; i < ARRAY_SIZE(s->ctrlq); i++) {
		struct sge_ctrl_txq *cq = &s->ctrlq[i];

		if (cq->q.desc)
			tasklet_init(&cq->qresume_tsk, restart_ctrlq, (unsigned long)cq);
	}
}

/**
 *	t4_sge_stop - disable SGE operation
 *	@adap: the adapter
 *
 *	Stop tasklets and timers associated with the DMA engine.  Note that
 *	this is effective only if measures have been taken to disable any HW
 *	events that may restart them.
 */
void t4_sge_stop(struct adapter *adap)
{
	int i;
	struct sge *s = &adap->sge;

	if (in_interrupt())  /* actions below require waiting */
		return;

	if (s->rx_timer.function)
		del_timer_sync(&s->rx_timer);
	if (s->tx_timer.function)
		del_timer_sync(&s->tx_timer);

	for (i = 0; i < ARRAY_SIZE(s->ofldtxq); i++) {
		struct sge_ofld_txq *q = &s->ofldtxq[i];

		if (q->q.desc)
			tasklet_kill(&q->qresume_tsk);
	}
	for (i = 0; i < ARRAY_SIZE(s->ctrlq); i++) {
		struct sge_ctrl_txq *cq = &s->ctrlq[i];

		if (cq->q.desc)
			tasklet_kill(&cq->qresume_tsk);
	}
}

/**
 *	t4_sge_init_soft - grab core SGE values needed by SGE code
 *	@adap: the adapter
 *
 *	We need to grab the SGE operating parameters that we need to have
 *	in order to do our job and make sure we can live with them.
 */
static int t4_sge_init_soft(struct adapter *adap)
{
	struct sge *s = &adap->sge;
	u32 fl_small_pg, fl_large_pg;
	u32 timer_value_0_and_1, timer_value_2_and_3, timer_value_4_and_5;
	u32 ingress_rx_threshold;

	/*
	 * Verify that CPL messages are going to the Ingress Queue for
	 * process_responses() and that only packet data is going to the
	 * Free Lists.
	 */
	if ((t4_read_reg(adap, A_SGE_CONTROL) & F_RXPKTCPLMODE) !=
	    V_RXPKTCPLMODE(X_RXPKTCPLMODE_SPLIT)) {
		dev_err(adap->pdev_dev, "bad SGE CPL MODE\n");
		return -EINVAL;
	}

	/*
	 * Validate the Host Buffer Register Array indices that we want to
	 * use ...
	 *
	 * XXX Note that we should really read through the Host Buffer Size
	 * XXX register array and find the indices of the Buffer Sizes which
	 * XXX meet our needs!
	 */
	#define READ_FL_BUF(x) \
		t4_read_reg(adap, A_SGE_FL_BUFFER_SIZE0+(x)*sizeof(u32))

	fl_small_pg = READ_FL_BUF(RX_SMALL_PG_BUF);
	fl_large_pg = READ_FL_BUF(RX_LARGE_PG_BUF);

	/* We only bother using the Large Page logic if the Large Page Buffer
	 * is larger than our Page Size Buffer.
	 */
	if (fl_large_pg <= fl_small_pg)
		fl_large_pg = 0;

	#undef READ_FL_BUF

	/* The Page Size Buffer must be exactly equal to our Page Size and the
	 * Large Page Size Buffer should be 0 (per above) or a power of 2.
	 */
	if (fl_small_pg != PAGE_SIZE ||
	    (fl_large_pg & (fl_large_pg-1)) != 0) {
		dev_err(adap->pdev_dev, "bad SGE FL page buffer sizes [%d, %d]\n",
			fl_small_pg, fl_large_pg);
		return -EINVAL;
	}
	if (fl_large_pg)
		s->fl_pg_order = ilog2(fl_large_pg) - PAGE_SHIFT;

	/*
	 * Retrieve our RX interrupt holdoff timer values and counter
	 * threshold values from the SGE parameters.
	 */
	timer_value_0_and_1 = t4_read_reg(adap, A_SGE_TIMER_VALUE_0_AND_1);
	timer_value_2_and_3 = t4_read_reg(adap, A_SGE_TIMER_VALUE_2_AND_3);
	timer_value_4_and_5 = t4_read_reg(adap, A_SGE_TIMER_VALUE_4_AND_5);
	s->timer_val[0] = core_ticks_to_us(adap,
		G_TIMERVALUE0(timer_value_0_and_1));
	s->timer_val[1] = core_ticks_to_us(adap,
		G_TIMERVALUE1(timer_value_0_and_1));
	s->timer_val[2] = core_ticks_to_us(adap,
		G_TIMERVALUE2(timer_value_2_and_3));
	s->timer_val[3] = core_ticks_to_us(adap,
		G_TIMERVALUE3(timer_value_2_and_3));
	s->timer_val[4] = core_ticks_to_us(adap,
		G_TIMERVALUE4(timer_value_4_and_5));
	s->timer_val[5] = core_ticks_to_us(adap,
		G_TIMERVALUE5(timer_value_4_and_5));

	ingress_rx_threshold = t4_read_reg(adap, A_SGE_INGRESS_RX_THRESHOLD);
	s->counter_val[0] = G_THRESHOLD_0(ingress_rx_threshold);
	s->counter_val[1] = G_THRESHOLD_1(ingress_rx_threshold);
	s->counter_val[2] = G_THRESHOLD_2(ingress_rx_threshold);
	s->counter_val[3] = G_THRESHOLD_3(ingress_rx_threshold);

	return 0;
}

/*
 *	t4_sge_init - initialize SGE
 *	@adap: the adapter
 *
 *	Perform low-level SGE code initialization needed every time after a
 *	chip reset.
 */
int t4_sge_init(struct adapter *adap)
{
	struct sge *s = &adap->sge;
	u32 sge_control, sge_conm_ctrl;
	int ret, egress_threshold;

	/*
	 * Ingress Padding Boundary and Egress Status Page Size are set up by
	 * t4_fixup_host_params().
	 */
	sge_control = t4_read_reg(adap, A_SGE_CONTROL);
	s->pktshift = G_PKTSHIFT(sge_control);
	s->stat_len = (sge_control & F_EGRSTATUSPAGESIZE) ? 128 : 64;

	s->fl_align = t4_fl_pkt_align(adap);
	ret = t4_sge_init_soft(adap);
	if (ret < 0)
		return ret;

	/*
	 * A FL with <= fl_starve_thres buffers is starving and a periodic
	 * timer will attempt to refill it.  This needs to be larger than the
	 * SGE's Egress Congestion Threshold.  If it isn't, then we can get
	 * stuck waiting for new packets while the SGE is waiting for us to
	 * give it more Free List entries.  (Note that the SGE's Egress
	 * Congestion Threshold is in units of 2 Free List pointers.) For T4,
	 * there was only a single field to control this.  For T5 there's the
	 * original field which now only applies to Unpacked Mode Free List
	 * buffers and a new field which only applies to Packed Mode Free List
	 * buffers.
	 */
	sge_conm_ctrl = t4_read_reg(adap, A_SGE_CONM_CTRL);
	switch (CHELSIO_CHIP_VERSION(adap->params.chip)) {
	case CHELSIO_T4:
		egress_threshold = G_EGRTHRESHOLD(sge_conm_ctrl);
		break;
	case CHELSIO_T5:
		egress_threshold = G_EGRTHRESHOLDPACKING(sge_conm_ctrl);
		break;
	case CHELSIO_T6:
	default:
		egress_threshold = G_T6_EGRTHRESHOLDPACKING(sge_conm_ctrl);
	}
	s->fl_starve_thres = 2*egress_threshold + 1;

	t4_idma_monitor_init(adap, &s->idma_monitor);

	/* Set up timers used for recuring callbacks to process RX and TX
	 * administrative tasks.
	 */
	setup_timer(&s->rx_timer, sge_rx_timer_cb, (unsigned long)adap);
	setup_timer(&s->tx_timer, sge_tx_timer_cb, (unsigned long)adap);

	spin_lock_init(&s->intrq_lock);

	return 0;
}
