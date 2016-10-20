/*
 * This file implements the Chelsio CPL5 message processing.
 *
 * Copyright (C) 2006-2015 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <linux/mm.h>
#include <linux/pci.h>
#include <linux/highmem.h>
#include <linux/dma-mapping.h>
#include "l2t.h"
#include "defs.h"
#include "tom.h"
#include "t4_hw.h"
#include "t4_ddp.h"
#include "t4_tcb.h"
#include "trace.h"

/*
 * Return the # of page pods needed to accommodate a # of pages.
 */
static inline unsigned int pages2ppods(unsigned int pages)
{
	return (pages + PPOD_PAGES - 1) / PPOD_PAGES + NUM_SENTINEL_PPODS;
}

static void unmap_ddp_gl(struct pci_dev *pdev,
			 const struct ddp_gather_list *gl,
			 unsigned int npages)
{
	int i;

	if (!npages)
		return;

	pci_unmap_page(pdev, gl->phys_addr[0] + gl->offset,
		       PAGE_SIZE - gl->offset, PCI_DMA_FROMDEVICE);
	for (i = 1; i < npages; ++i)
		pci_unmap_page(pdev, gl->phys_addr[i], PAGE_SIZE,
			       PCI_DMA_FROMDEVICE);
}

static int t4_dma_map_pages(struct pci_dev *pdev, size_t pg_off, size_t len,
			    unsigned int npages, struct ddp_gather_list *p)
{
	int i;
	dma_addr_t page0;

	page0 = pci_map_page(pdev, p->pages[0], pg_off,
				       PAGE_SIZE - pg_off,
				       PCI_DMA_FROMDEVICE);
	if (unlikely(t4_pci_dma_mapping_error(pdev, page0)))
		return -ENOMEM;
	p->phys_addr[0] = page0 - pg_off;
	for (i = 1; i < npages; ++i) {
		p->phys_addr[i] = pci_map_page(pdev, p->pages[i], 0, PAGE_SIZE,
					       PCI_DMA_FROMDEVICE);
		if (unlikely(t4_pci_dma_mapping_error(pdev, p->phys_addr[i]))) {
			unmap_ddp_gl(pdev, p, i);
			return -ENOMEM;
		}
	}
	p->length = len;
	p->offset = pg_off;
	p->nelem = npages;
	return 0;
}

static inline int check_nonmatching_gl(struct ddp_gather_list *gl1, struct ddp_gather_list *gl2,
					size_t pg_off, size_t len, unsigned int npages)
{
	int i;

        if (gl1->offset == pg_off && gl1->nelem >= npages &&
            gl1->length >= len) {
                for (i = 0; i < npages; ++i)
                        if (gl1->pages[i] != gl2->pages[i]) {
                                return i;
                        }
                return -1;
        }
	return 0;
}

/**
 *	t4_pin_pages - pin a user memory range and prepare it for DDP
 *	@addr - the starting address
 *	@len - the length of the range
 *	@newgl - contains the pages and physical addresses of the pinned range
 *	@gl - an existing gather list, may be %NULL
 *
 *	Pins the pages in the user-space memory range [addr, addr + len) and
 *	maps them for DMA.  Returns a gather list with the pinned pages and
 *	their physical addresses.  If @gl is non NULL the pages it describes
 *	are compared against the pages for [addr, addr + len), and if the
 *	existing gather list already covers the range a new list is not
 *	allocated.  Returns 0 on success, or a negative errno.  On success if
 *	a new gather list was allocated it is returned in @newgl.
 */ 
int t4_pin_pages(struct pci_dev *pdev, unsigned long addr, size_t len,
		 struct ddp_gather_list **newgl,
		 struct ddp_state *ds)
{
	int i;
	size_t pg_off;
	struct ddp_gather_list *p;
	int match0, match1;
	unsigned long lock_limit;
	unsigned long locked;
	long err, npages;
	int mm_locked = 1;

	if (!len)
		return -EINVAL;
	if (!access_ok(VERIFY_WRITE, addr, len))
		return -EFAULT;

	pg_off = addr & ~PAGE_MASK;
	npages = (pg_off + len + PAGE_SIZE - 1) >> PAGE_SHIFT;

	p = kmalloc(sizeof(struct ddp_gather_list) +
		    npages * (sizeof(dma_addr_t) + sizeof(struct page *)),
		    GFP_KERNEL);
	if (!p) {
		err = -ENOMEM;
		goto free_gl;
	}

	down_read(&current->mm->mmap_sem);
	lock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;
	locked = npages + current->mm->pinned_vm;
	if ((locked > lock_limit) && !capable(CAP_IPC_LOCK)) {
		up_read(&current->mm->mmap_sem);
		err = -ENOMEM;
		goto free_gl;
	}

	p->type = DDP_TYPE_USER;
	p->pages = (struct page **)&p->phys_addr[npages];
	/*
	 * get_user_pages() will mark the pages dirty so we don't need to do it
	 * later.  See how get_user_pages() uses FOLL_TOUCH | FOLL_WRITE.
	 */
	err = get_user_pages_locked(current, current->mm, addr, npages, 1, 0,
				    p->pages, &mm_locked);
	if (mm_locked)
		up_read(&current->mm->mmap_sem);
	if (err != npages) {
		if (err < 0)
			goto free_gl;
		npages = err;
		err = -EFAULT;
		goto unpin;
	}
	match0 = match1 = 0;
	if (ds->ubuf[0])
		match0 = check_nonmatching_gl(ds->ubuf[0], p, pg_off, len , npages);
	if (ds->ubuf[1])
		match1 = check_nonmatching_gl(ds->ubuf[1], p, pg_off, len , npages);

	if (match0 >=0 && match1 >=0) {
		err = t4_dma_map_pages(pdev, pg_off, len, npages, p);
		if (err < 0)
			goto unpin;
		*newgl = p;
		if (ds->ubuf[0] && ds->ubuf[1])
			;
		else if (ds->ubuf[0])
			ds->cur_ubuf = 1;
		else
			ds->cur_ubuf = 0;
		return 0;
	}
	if (match0 < 0)
		ds->cur_ubuf=0;
	else
		ds->cur_ubuf=1;
unpin:
	for (i = 0; i < npages; ++i)
		put_page(p->pages[i]);
free_gl:
	kfree(p);
	*newgl = NULL;
	return err;
}

/**
 *      t4_map_pages - map a kernel memory range and prepare it for DDP
 *	and assumes caller handles page refcounting.
 *	In all other respects same as t4_pin_pages.
 *      @addr - the starting address
 *      @len - the length of the range
 *      @newgl - contains the pages and physical addresses of the range
 *      @gl - an existing gather list, may be %NULL
 */

int t4_map_pages(struct pci_dev *pdev, unsigned long addr, size_t len,
		 struct ddp_gather_list **newgl,
		 struct ddp_state *ds)
{
	int i, err=0;
	size_t pg_off;
	unsigned int npages;
	struct ddp_gather_list *p;
	int match;

	if (!len)
		return -EINVAL;

	pg_off = addr & ~PAGE_MASK;
	npages = (pg_off + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	p = kmalloc(sizeof(struct ddp_gather_list) +
		    npages * (sizeof(dma_addr_t) + sizeof(struct page *)),
		    GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	p->type = DDP_TYPE_KERNEL;
	p->pages = (struct page **)&p->phys_addr[npages];
	
	for (i=0; i < npages; i++) {
		if ((addr < VMALLOC_START) || (addr >= VMALLOC_END))
			p->pages[i] = virt_to_page((void *)addr);
		else
			p->pages[i] = vmalloc_to_page((void *)addr);
		addr += PAGE_SIZE;
	}

	match = 0;
	if (ds->ubuf[0])
		match = check_nonmatching_gl(ds->ubuf[0], p, pg_off, len , npages);
	if (match >=0) {
		err = t4_dma_map_pages(pdev, pg_off, len, npages, p);
		if (err < 0)
			goto free_gl;
		*newgl = p;
		ds->cur_ubuf = 0;
		return 0;
	}

free_gl:
	kfree(p);
	*newgl = NULL;
	return err;
}

static inline void ddp_gl_free_pages(struct ddp_gather_list *gl)
{
        int i;

        for (i = 0; i < gl->nelem; ++i)
		put_page(gl->pages[i]);
}

void t4_free_ddp_gl(struct sock *sk, unsigned int idx)
{
	struct ddp_gather_list *gl;
	struct ddp_state *p = DDP_STATE(sk);

	gl = p->ubuf[idx]; 
	if (gl->type == DDP_TYPE_USER)
		ddp_gl_free_pages(gl);
	p->ubuf[idx] = NULL;
	kfree(gl);
}

/*
 * Allocate page pods for DDP buffer 1 (the user buffer) and set up the tag in
 * the TCB.  We allocate page pods in multiples of PPOD_CLUSTER_SIZE.  First we
 * try to allocate enough page pods to accommodate the whole buffer, subject to
 * the ddp_maxpages limit.
 * If that fails we try to allocate PPOD_CLUSTER_SIZE page pods
 * before failing entirely.
 */
static int t4_alloc_buf1_ppods(struct sock *sk, struct ddp_state *p,
			    unsigned long addr, unsigned int len)
{
	int tag, npages, nppods;
	struct toedev *tdev = CPL_IO_STATE(sk)->toedev;
	struct tom_data *d = TOM_DATA(tdev);

	npages = ((addr & ~PAGE_MASK) + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	nppods = min(pages2ppods(npages),
			pages2ppods(TOM_TUNABLE(tdev, ddp_maxpages)));
	nppods = ALIGN(nppods, PPOD_CLUSTER_SIZE);
	tag = t4_alloc_ppods(d, nppods);

	if (tag < 0 && nppods > PPOD_CLUSTER_SIZE) {
		nppods = PPOD_CLUSTER_SIZE;
		tag = t4_alloc_ppods(d, nppods);
	}
	if (tag < 0)
		return -ENOMEM;
	p->ubuf_nppods = nppods;
	p->ubuf_tag = tag;
	return nppods;
}

static inline u64 select_ddp_flags(const struct sock *sk, int buf_idx,
					     int nonblock, int rcv_flags)
{
	struct toedev *tdev = CPL_IO_STATE(sk)->toedev;
	unsigned long long flush = !TOM_TUNABLE(tdev, ddp_push_wait);

	if (buf_idx == 1) {
		if (unlikely(rcv_flags & MSG_WAITALL))
			return V_TF_DDP_PSH_NO_INVALIDATE1(1ULL)|
				V_TF_DDP_PUSH_DISABLE_1(1ULL);

		if (nonblock)
			return V_TF_DDP_BUF1_FLUSH(1ULL);

		return V_TF_DDP_PSHF_ENABLE_1(1ULL)|V_TF_DDP_BUF1_FLUSH(flush);
	}

	if (unlikely(rcv_flags & MSG_WAITALL))
		return V_TF_DDP_PUSH_DISABLE_0(1ULL);

	return V_TF_DDP_PSHF_ENABLE_0(1ULL)|V_TF_DDP_BUF0_FLUSH(flush);
}

/**
 * setup_iovec_ppods - setup HW page pods for a user iovec
 * @sk: the associated socket
 * @msg: the msghdr for access to iterator
 *
 * Pins a user iovec and sets up HW page pods for DDP into it.  We allocate
 * page pods for user buffers on the first call per socket.  Afterwards we
 * limit the buffer length to whatever the existing page pods can accommodate.
 * Returns a negative error code or the length of the mapped buffer.
 *
 * The current implementation handles iovecs with only one entry.
 */
static int t4_setup_iovec_ppods(struct sock *sk, struct msghdr *msg)
{
	int err, nppods, tag;
	unsigned int len;
	struct ddp_gather_list *gl;
	struct ddp_state *p = DDP_STATE(sk);
	const struct iovec *iov = msg->msg_iter.iov;
	unsigned long addr = (unsigned long)iov->iov_base +
				msg->msg_iter.iov_offset;

	if (p->ubuf[0] && p->ubuf[1]) {
		p->cur_ubuf ^= 1;
		nppods = p->ubuf[p->cur_ubuf]->nppods;
		tag = p->ubuf[p->cur_ubuf]->tag;
	} else if (!p->ubuf_nppods) {
		err = t4_alloc_buf1_ppods(sk, p, addr,
				iov_iter_single_seg_count(&msg->msg_iter));
		if (err < 0)
			return err;
		nppods = p->ubuf_nppods;
		tag = p->ubuf_tag;
	} else {
		nppods = p->ubuf_nppods;
		tag = p->ubuf_tag;
	}
	BUG_ON(nppods <= NUM_SENTINEL_PPODS);
	len = (nppods - NUM_SENTINEL_PPODS) * PPOD_PAGES * PAGE_SIZE;

	len -= addr & ~PAGE_MASK;
	if (len > M_TCB_RX_DDP_BUF0_LEN)
		len = M_TCB_RX_DDP_BUF0_LEN;
	len = min_t(int, len, iov_iter_single_seg_count(&msg->msg_iter));

	if (!segment_eq(get_fs(), KERNEL_DS))
		err = t4_pin_pages(p->pdev, addr, len, &gl, p);
	else
		err = t4_map_pages(p->pdev, addr, len, &gl, p);
	if (err < 0)
		return err;

	if (gl) {
		if (p->ubuf[0] && p->ubuf[1]) {
			struct ddp_gather_list *cur_gl = p->ubuf[p->cur_ubuf];

			unmap_ddp_gl(p->pdev, cur_gl, cur_gl->nelem);
			t4_free_ddp_gl(sk, p->cur_ubuf);
		}
		p->ubuf[p->cur_ubuf] = gl;
		gl->tag = tag;
		gl->nppods = nppods;
		p->ubuf_nppods = p->ubuf_tag = 0;
		err = t4_setup_ppods(sk, gl, pages2ppods(gl->nelem), gl->tag,
				     len, gl->offset, 0);
		if (err < 0)
			return err;
	}
	return len;
}

int t4_post_ubuf(struct sock *sk, struct msghdr *msg,
		 int nonblock, int rcv_flags)
{
	int len, ret;
	u64 flags;
	struct ddp_state *p = DDP_STATE(sk);

	len = t4_setup_iovec_ppods(sk, msg);
	if (len < 0)
		return len;

	p->buf_state[1].cur_offset = 0;
	p->buf_state[1].flags = DDP_BF_NOCOPY;
	p->buf_state[1].gl = p->ubuf[p->cur_ubuf];

	flags = select_ddp_flags(sk, 1, nonblock, rcv_flags);

	if (p->ddp_tag != p->ubuf[p->cur_ubuf]->tag) {
		t4_set_ddp_tag(sk, 1, p->ubuf[p->cur_ubuf]->tag << 6);
		p->ddp_tag = p->ubuf[p->cur_ubuf]->tag;
	}
	p->cur_buf = 1;

	ret = t4_setup_ddpbufs(sk, 0, 0, len, 0, V_TF_DDP_BUF1_VALID(1ULL) |
			 V_TF_DDP_ACTIVE_BUF(1ULL) | V_TF_DDP_INDICATE_OUT(1ULL) |
			flags,
			 V_TF_DDP_PSHF_ENABLE_1(1ULL) |
			 V_TF_DDP_BUF0_INDICATE(1ULL) | V_TF_DDP_BUF1_INDICATE(1ULL) |
			 V_TF_DDP_PSH_NO_INVALIDATE0(1ULL) | V_TF_DDP_PSH_NO_INVALIDATE1(1ULL) |
			 V_TF_DDP_BUF1_FLUSH(1ULL) | V_TF_DDP_PUSH_DISABLE_1(1ULL) |
			 V_TF_DDP_BUF1_VALID(1ULL) | V_TF_DDP_BUF0_VALID(1ULL) |
			 V_TF_DDP_ACTIVE_BUF(1ULL) | V_TF_DDP_INDICATE_OUT(1ULL));
	return ret;
}

/*
 * 
 */
void t4_cancel_ubuf(struct sock *sk, long *timeo)
{
	struct ddp_state *p = DDP_STATE(sk);
	int rc;
	int ubuf_pending;
	long gettcbtimeo;
	int canceled=0;
	int norcv=0;
	int err;

	DEFINE_WAIT(wait);
	
	if (!p->ddp_setup || !p->pdev)
		return;

	gettcbtimeo = max_t(long, msecs_to_jiffies(1), *timeo);
	p->cancel_ubuf = 1;

       if (t4_ddp_ubuf_pending(sk)) {
                release_sock(sk);
                lock_sock(sk);
        }

	ubuf_pending = t4_ddp_ubuf_pending(sk);

	while (ubuf_pending && !norcv) {
#ifdef T4_TRACE
		T4_TRACE3(TIDTB(sk), 
		  "t4_cancel_ubuf: flags0 0x%x flags1 0x%x get_tcb_count %d",
		  p->buf_state[0].flags & DDP_BF_NOCOPY, 
		  p->buf_state[1].flags & DDP_BF_NOCOPY,
		  p->get_tcb_count);
#endif
		if (!canceled && !p->get_tcb_count) {
			canceled = 1;
			err = t4_cancel_ddpbuf(sk, p->cur_buf);
			BUG_ON(err < 0);
		}

		do {
			prepare_to_wait(sk_sleep(sk), &wait, 
					TASK_INTERRUPTIBLE);
			rc = sk_wait_event(sk, &gettcbtimeo, 
					   !(DDP_STATE(sk)->ddp_setup ? DDP_STATE(sk)->get_tcb_count : 0) &&
					   !(sk->sk_shutdown & RCV_SHUTDOWN));
			p = DDP_STATE(sk);
			
			finish_wait(sk_sleep(sk), &wait);

			if (signal_pending(current))
				break;

			gettcbtimeo = max_t(long, gettcbtimeo << 1, *timeo);
			norcv = (sk->sk_err == ECONNRESET) || (sk->sk_shutdown & RCV_SHUTDOWN);
		} while ((p->ddp_setup ? p->get_tcb_count : 0) && !norcv);

		ubuf_pending = t4_ddp_ubuf_pending(sk);

		if (signal_pending(current))
			break;
	}

	while (t4_ddp_ubuf_pending(sk) && !norcv) {
		if (!canceled && !p->get_tcb_count) {
			canceled=1;
			err = t4_cancel_ddpbuf(sk, p->cur_buf);
			BUG_ON(err < 0);
		}

		do {
			release_sock(sk);
			gettcbtimeo = (net_random() % (HZ / 2)) + 2;
			__set_current_state(TASK_UNINTERRUPTIBLE);
			schedule_timeout(gettcbtimeo);
			lock_sock(sk);
			p = DDP_STATE(sk);
			norcv = (sk->sk_err == ECONNRESET) || (sk->sk_shutdown & RCV_SHUTDOWN);
		} while ((p->ddp_setup ? p->get_tcb_count : 0) && !norcv);
	}

	if (p->ddp_setup)
		p->cancel_ubuf = 0;
		
	return;
}

/*
 * Clean up DDP state that needs to survive until socket close time, such as the
 * DDP buffers.  The buffers are already unmapped at this point as unmapping
 * needs the PCI device and a socket may close long after the device is removed.
 */
void t4_cleanup_ddp(struct sock *sk)
{
	struct ddp_state *p = DDP_STATE(sk);

	if (!p->ddp_setup)
		return;

	p->ddp_setup = 0;
	p->state = 0;

	if (p->ubuf[0])
		t4_free_ddp_gl(sk, 0);
        if (p->ubuf[1])
		t4_free_ddp_gl(sk, 1);
}

/*
 * This is a companion to t4_cleanup_ddp() and releases the HW resources
 * associated with a connection's DDP state, such as the page pods.
 * It's called when HW is done with a connection.   The rest of the state
 * remains available until both HW and the app are done with the connection.
 */
void t4_release_ddp_resources(struct sock *sk)
{
	struct ddp_state *p = DDP_STATE(sk);

	if (p->ddp_setup) {
		struct tom_data *d = TOM_DATA(CPL_IO_STATE(sk)->toedev);
		
		if (p->ubuf[0] && p->ubuf[0]->nppods) {
			t4_free_ppods(d, p->ubuf[0]->tag, p->ubuf[0]->nppods);
			p->ubuf[0]->nppods = 0;
		}
                if (p->ubuf[1] && p->ubuf[1]->nppods) {
                        t4_free_ppods(d, p->ubuf[1]->tag, p->ubuf[1]->nppods);
                        p->ubuf[1]->nppods = 0;
                }
		if (p->ubuf_nppods) {
                        t4_free_ppods(d, p->ubuf_tag, p->ubuf_nppods);
                        p->ubuf_nppods = 0;
		}
		if (p->ubuf[0])
			unmap_ddp_gl(p->pdev, p->ubuf[0], p->ubuf[0]->nelem);
		if (p->ubuf[1])
			unmap_ddp_gl(p->pdev, p->ubuf[1], p->ubuf[1]->nelem);
	}
	p->pdev = NULL;
}

/*
 * Prepare a socket for DDP.  Must be called when the socket is known to be
 * open.
 */
int t4_enter_ddp(struct sock *sk, unsigned int target, unsigned int waitall, int nonblock)
{
	unsigned int dack_mode = 0;
	struct ddp_state *p = DDP_STATE(sk);
	struct toedev *tdev = CPL_IO_STATE(sk)->toedev;
	struct tom_data *d = TOM_DATA(tdev);
	unsigned int indicate_size;

	if (p->state == DDP_ENABLED)
		return 0;

	p->state = DDP_ENABLED;
	p->pdev = d->pdev;
	p->buf_state[0].cur_offset = 0;
	p->buf_state[0].flags = 0;
	p->buf_state[0].gl = NULL;
	p->cur_buf = p->cur_ubuf = p->ubuf_nppods = 0;
	p->ubuf[0] = NULL;
	p->ubuf[1] = NULL;
	p->ubuf_ddp_pending = 0;
	p->indicate = 0;
	p->avg_request_len = 0;
	p->ddp_tag = INVALID_TAG;
	p->post_failed = 0;

	indicate_size = roundup(target, d->lldi->sge_ingpadboundary);
	indicate_size -= sizeof(struct cpl_rx_data);
	indicate_size = max(target, indicate_size);
	p->ind_size = indicate_size;
	t4_set_ddp_buf(sk, 0, 0, indicate_size);
	t4_set_tcb_field_rpl(sk, W_TCB_RX_DDP_FLAGS, V_TF_DDP_OFF(1ULL) |
                                V_TF_DDP_INDICATE_OUT(1ULL) |
                                V_TF_DDP_BUF0_VALID(1ULL) | V_TF_DDP_BUF1_VALID(1ULL) |
                                V_TF_DDP_BUF0_INDICATE(1ULL) | V_TF_DDP_BUF1_INDICATE(1ULL),
                                V_TF_DDP_BUF0_INDICATE(1ULL) | V_TF_DDP_INDICATE_OUT(1ULL) ,
				DDP_COOKIE_ENABLE);

	dack_mode = t4_select_delack(sk);

        if (dack_mode == 1) {
                t4_set_tcb_field(sk, W_TCB_T_FLAGS, V_TF_RCV_COALESCE_ENABLE(1ULL)|
                                                        V_TF_DACK_MSS(1ULL)|
                                                        V_TF_DACK(1ULL),
                                                        V_TF_RCV_COALESCE_ENABLE((unsigned long long)TOM_TUNABLE(tdev,ddp_rcvcoalesce))|
                                                        V_TF_DACK(1ULL));
        } else if (dack_mode == 2) {
                t4_set_tcb_field(sk, W_TCB_T_FLAGS, V_TF_RCV_COALESCE_ENABLE(1ULL)|
                                                        V_TF_DACK_MSS(1ULL)|
                                                        V_TF_DACK(1ULL),
                                                        V_TF_RCV_COALESCE_ENABLE((unsigned long long)TOM_TUNABLE(tdev,ddp_rcvcoalesce))|
                                                        V_TF_DACK_MSS(1ULL));
        } else if (dack_mode == 3) {
                t4_set_tcb_field(sk, W_TCB_T_FLAGS, V_TF_RCV_COALESCE_ENABLE(1ULL)|
                                                        V_TF_DACK_MSS(1ULL)|
                                                        V_TF_DACK(1ULL),
                                                        V_TF_RCV_COALESCE_ENABLE((unsigned long long)TOM_TUNABLE(tdev,ddp_rcvcoalesce))|
                                                        V_TF_DACK_MSS(1ULL)|
                                                        V_TF_DACK(1ULL));
        }

	return 0;
}

/* Pagepod allocator */

/*
 * Allocate n page pods.  Returns -1 on failure or the page pod tag.
 */
int t4_alloc_ppods(struct tom_data *td, unsigned int n)
{
	int tag;

	if (unlikely(!td->ppod_bmap))
		return -1;

	spin_lock_bh(&td->ppod_map_lock);
	tag = cxgb4_alloc_ppods(td->ppod_bmap, td->nppods, td->start_tag, n,
				PPOD_CLUSTER_SIZE-1);
	if (likely(tag >= 0)) {
		unsigned int end_tag = tag + n;

		td->start_tag = end_tag < td->nppods ? end_tag : 0;
	} else {
		td->start_tag = 0;
		tag = cxgb4_alloc_ppods(td->ppod_bmap, td->nppods, 0, n,
					PPOD_CLUSTER_SIZE-1);
	}
	spin_unlock_bh(&td->ppod_map_lock);

	return tag;
}

void t4_free_ppods(struct tom_data *td, unsigned int tag, unsigned int n)
{
	spin_lock_bh(&td->ppod_map_lock);
	cxgb4_free_ppods(td->ppod_bmap, tag, n);
	spin_unlock_bh(&td->ppod_map_lock);
}
