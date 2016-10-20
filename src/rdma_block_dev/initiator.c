/*
 * Copyright (c) 2015 Chelsio Communications, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *	copyright notice, this list of conditions and the following
 *	disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *	copyright notice, this list of conditions and the following
 *	disclaimer in the documentation and/or other materials
 *	provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/inet.h>
#include <linux/blkdev.h>
#include <linux/spinlock.h>
#include <linux/genhd.h>
#include <linux/ctype.h>
#include <linux/module.h>
#include <linux/hdreg.h>
#include <linux/debugfs.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>

#include <rdma/rdma_cm.h>
#include <rdma/ib_verbs.h>

#include "proto.h"
#include "common.h"
#include "rbdi_dev.h"

enum {
	RBDI_MAX_DISKS = 255,
	RBDI_MINOR_CNT = 1,
};

#define PFX "rbdi: "
#define RBDI_NAME "rbdi"

static u_int rbdi_major = 0;
static DEFINE_IDA(rbdi_minors);

static int debug = 0;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "Debug level (0=none, 1=all)");

static int use_immd = 1;
module_param(use_immd, int, 0644);
MODULE_PARM_DESC(use_immd, "Use immediate mode for small IO (default 1)");

static int responder_resources = RBDP_MAX_READ_DEPTH;
module_param(responder_resources, int, 0644);
MODULE_PARM_DESC(responder_resources, "RDMA Read responder resources to support (default 32)");

static int default_sqdepth = 250;
module_param(default_sqdepth, int, 0644);
MODULE_PARM_DESC(default_sqdepth, "SQ Depth (default 250)");

/**
 * Polling mode - poll for completions avoiding interrupts
 *
 * Each connection/target creates a kthread on both initiator and target
 * to poll the cqs.  The kthread will spin draining both cqs for up to
 * @poll_period_ns nanosecs and then arm the cqs and block until a completion
 * event generates an interrupt and awakens the thread.  Each time it
 * unblocks it will repeat the polling period.  The default polling period
 * is 200 usecs.  EG: Setting it to 1000000 (1ms), interrupts are reduced to
 * 1/ms under streaming loads.
 *
 * Module option @poll_period_ns allows tweaking how long the thread will
 * spin/poll.  Use with caution.
 */
static ulong poll_period_ns = 200000;
module_param(poll_period_ns, ulong, 0444);
MODULE_PARM_DESC(poll_period_ns, "Polling period, in nanoseconds, before "
		 "arming the CQs and blocking (default 200000)");

/**
 * cq_weights - integer array used to arbitrate between polling the SCQ and RCQ.
 *
 * Index SCQ_INDEX in @cq_weights is for the SCQ and RCQ_INDEX for RCQ.
 * The value in each is the max number of times that CQ will be polled
 * for a CQE before switching to the other CQ.  So if both entrys have the same
 * value, then the two CQs are treated equally.  The amount in each entry
 * controls how many CQEs will be consumed before processing any pending RBDP
 * requested.
 */
enum {
	SCQ_INDEX = 0,
	RCQ_INDEX,
	CQ_WEIGHT_SIZE,
};
static unsigned cq_weights[CQ_WEIGHT_SIZE];

static unsigned scq_weight = 10;
module_param(scq_weight, uint, 0444);
MODULE_PARM_DESC(scq_weight, "Number of SCQEs to poll before switching to the "
		 "RCQ (default 10)");

static unsigned rcq_weight = 10;
module_param(rcq_weight, uint, 0444);
MODULE_PARM_DESC(rcq_weight, "Number of RCQEs to poll before switching to the "
		 "SCQ (default 10)");

static struct workqueue_struct *workq;

static struct dentry *debugfs_root;

static int rbdi_start_request(struct request *req);

/**
 * struct send_wr_ring - send queue request ring
 */
struct send_wr_ring {
	void *va;
	dma_addr_t dma_addr;
	struct ib_sge sge;
	struct ib_send_wr wr;
};

/**
 * struct recv_wr_ring - recv queue request ring
 */
struct recv_wr_ring {
	void *va;
	struct ib_sge sge;
	struct ib_recv_wr wr;
};

enum target_state {
	INIT,
	RESOLVED,
	CONNECTED,
	ERROR
};

static char *state_str[] = {
	"INIT",
	"RESOLVED",
	"CONNECTED",
	"ERROR",
};

struct target_ctx;

/**
 * struct req_ctx - RBDP request context
 *
 * Holds all the state for each outstanding RDBP request.
 */
struct req_ctx {
	struct target_ctx *t;
	struct request *req;
	struct ib_fast_reg_page_list *frpl;
	struct ib_mr *frmr;
	u8 frmr_key;
	int fr_fbo;
	int fr_page_count;
	int fr_len;
	struct list_head rctx_free_entry;
	struct list_head rctx_inuse_entry;
	int xid;
};

/*
 * Global list of all connected targets
 */
static LIST_HEAD(target_list);
static DEFINE_MUTEX(target_mutex);


/*
 * target statistics viewable via debugfs.
 */
struct target_stats {
	unsigned long long reqs_started;
	unsigned long long reqs_completed;
	unsigned long long immd_writes;
	unsigned long long immd_reads;
	unsigned long long stall_max_reqs;
	unsigned long long stall_sq_full;
	unsigned long long max_outstanding_reqs;
	unsigned long long cq_waits;
	unsigned long long max_rcq_polled;
	unsigned long long max_scq_polled;
};

/**
 * struct poll_thread_ctx - context for each polling thread
 *
 * @poll_thread:	The task_struct of our kthread
 * @poll_targets:	The list of targets currently needing polling
 * @wait:		The wait object used to block for new CQ events
 * @lock:		The spin lock used by the event handlers and poll
 *			thread to synchronize adding new targets to the poll
 *			list.
 * @cpu: 		Currently not used, but eventually will be the
 *			cpu to which this thread is bound.
 */
struct poll_thread_ctx {
	struct task_struct *poll_thread;
	struct list_head poll_targets;
	wait_queue_head_t wait;
	spinlock_t lock;
	int cpu;
};

static unsigned poll_thread_count = 4;
module_param(poll_thread_count, uint, 0444);
MODULE_PARM_DESC(poll_thread_count,
	"Number of poller threads (default = 4, 0 = num_online_cpus())");
static struct poll_thread_ctx *poll_threads;
static unsigned next_poll_ctx;

/**
 * struct target_ctx - target context struct
 *
 * Holds all the state for each connected target device.
 */
struct target_ctx {
	unsigned int size;
	struct request_queue *rq;
	struct gendisk *disk;
	int open_count;
	struct list_head req_list;
	char ipaddr[RBDP_ADDRLEN];
	char device[RBDP_DEVLEN];
	u16 port;
	enum target_state state;
	unsigned long event_state;
	struct rdma_cm_id *cm_id;
	struct ib_pd *pd;
	struct ib_cq *rcq;
	struct ib_cq *scq;
	int sqdepth;
	int rqdepth;
	u64 start_sec;
	u64 sectors;
	u32 sec_size;
	u32 max_io_size;
	u32 max_sges;
	struct send_wr_ring *sring;
	int snext;
	int scnt;
	struct recv_wr_ring *rring;
	int rnext;
	int inuse_req_cnt;
	int req_cnt;
	struct list_head free_req_ctxs;
	struct list_head inuse_req_ctxs;
	struct req_ctx *req_ctx_mem;
	spinlock_t lock;
	struct target_stats stats;
	struct dentry *debugfs_root;
	int xid_start;
	struct list_head target_list_entry;
	wait_queue_head_t wait;
	int ret;
	struct poll_thread_ctx *my_thread_ctx;
	struct list_head poll_thread_entry;
	int cq_index;
};

/**
 * lookup_xid() - lookup the xid and return the associated request context
 * @t:		target context
 * @xid:	xid to lookup
 *
 * Search the active requests @xid and return its request context if found.
 *
 * Return: the associated req_ctx ptr or NULL if not found.
 */
static struct req_ctx *lookup_xid(struct target_ctx *t, int xid)
{
	struct req_ctx *r;

	list_for_each_entry(r, &t->inuse_req_ctxs, rctx_inuse_entry)
		if (r->xid == xid)
			return r;
	return NULL;
}

/**
 * dma_sync_for_cpu() - sync the memory for cpu access
 * @rctx:	request context to sync
 *
 * Sync all the fastreg pages after dma for cpu access
 */
static void dma_sync_for_cpu(struct req_ctx *rctx)
{
	u32 tot_len = rctx->fr_len;
	int i = 0;

	while (tot_len) {
		u32 size = min_t(u32, tot_len, PAGE_SIZE);

		ib_dma_sync_single_for_cpu(rctx->t->cm_id->device,
					   rctx->frpl->page_list[i], size,
					   DMA_BIDIRECTIONAL);
		tot_len -= size;
		i++;
	}
}

/**
 * dma_sync_for_dev() - sync the memory for device access
 * @rctx:	request context to sync
 *
 * Sync all the fastreg pages after cpu has touched them for device/dma access.
 */
static void dma_sync_for_dev(struct req_ctx *rctx)
{
	u32 tot_len = rctx->fr_len;
	int i = 0;

	while (tot_len) {
		u32 size = min_t(u32, tot_len, PAGE_SIZE);

		ib_dma_sync_single_for_device(rctx->t->cm_id->device,
					      rctx->frpl->page_list[i], size,
					      DMA_BIDIRECTIONAL);
		tot_len -= size;
		i++;
	}
}

/**
 * dealloc_req_ctxs() - deallocate all request contexts for this target
 * @t:		target context
 *
 * Deallocate the request context, fastreg page lists, and fastreg mrs.
 */
static void dealloc_req_ctxs(struct target_ctx *t)
{
	int i;
	struct req_ctx *rctx = t->req_ctx_mem;

	for (i = 0; i < RBDP_MAX_REQUESTS; i++) {
		BUG_ON(!list_empty(&rctx->rctx_inuse_entry));
		BUG_ON(list_empty(&rctx->rctx_free_entry));
		list_del_init(&rctx->rctx_free_entry);
		ib_dereg_mr(rctx->frmr);
		ib_free_fast_reg_page_list(rctx->frpl);
		rctx++;
	}
	kfree(t->req_ctx_mem);
}

/**
 * alloc_req_ctxs() - allocate and initializerequest contexts for this target
 * @t:		target context
 *
 * Allocate and initialize the request contexts, fastreg page lists, and
 * fastreg mrs for this target.  Link them on the @t->free_req_ctxs.
 *
 * Return: 0 upon success or negative errno upon failure.
 */
static int alloc_req_ctxs(struct target_ctx *t)
{
	int i;
	struct req_ctx *rctx;
	int ret;

	rctx = kzalloc(RBDP_MAX_REQUESTS * sizeof *rctx, GFP_KERNEL);
	if (!rctx)
		return -ENOMEM;

	t->req_ctx_mem = rctx;
	rctx->t = t;
	for (i = 0; i < RBDP_MAX_REQUESTS; i++) {

		INIT_LIST_HEAD(&rctx->rctx_free_entry);
		INIT_LIST_HEAD(&rctx->rctx_inuse_entry);

		rctx->frpl = ib_alloc_fast_reg_page_list(t->cm_id->device,
						       RBDP_MAX_FR_DEPTH);
		if (IS_ERR(rctx->frpl)) {
			ret = PTR_ERR(rctx->frpl);
			goto err;
		}

		rctx->frmr = ib_alloc_fast_reg_mr(t->pd, RBDP_MAX_FR_DEPTH);
		if (IS_ERR(rctx->frmr)) {
			ret = PTR_ERR(rctx->frmr);
			goto err;
		}
		list_add_tail(&rctx->rctx_free_entry, &t->free_req_ctxs);
		rctx++;
	}
	return 0;
err:
	while (i--) {
		if (!list_empty(&rctx->rctx_free_entry))
			list_del(&rctx->rctx_free_entry);
		if (rctx->frmr)
			ib_dereg_mr(rctx->frmr);
		if (rctx->frpl)
			ib_free_fast_reg_page_list(rctx->frpl);
		rctx--;
	}
	BUG_ON(t->req_ctx_mem != rctx);
	kfree(t->req_ctx_mem);
	t->req_ctx_mem = NULL;
	return ret;
}

/**
 * post_recv() - post the next receive wr to the rq
 * @t:		target context.
 *
 * Post the next available recv wr to the rq and advance @t->rnext.
 *
 * Return: 0 upon success or negative errno upon failure.
 */
static int post_recv(struct target_ctx *t)
{
	struct ib_recv_wr *bad_wr;
	int ret;

	ret = ib_post_recv(t->cm_id->qp, &t->rring[t->rnext].wr, &bad_wr);
	if (!ret) {
		t->rnext++;
		if (t->rnext == t->rqdepth)
			t->rnext = 0;
	} else
		pr_err(PFX "%s ret %d\n", __func__, ret);
	return ret;
}

/**
 * post_send() - post the next send wr to the rq
 * @t:		target context.
 *
 * Post the next available send wr to the sq and advance @t->snext.  Also
 * bump @t->scnt for flow control.
 *
 * Return: 0 upon success or negative errno upon failure.
 */
static int post_send(struct target_ctx *t)
{
	struct ib_send_wr *bad_wr;
	int ret;

	BUG_ON(t->sring[t->snext].wr.opcode == -1);
	BUG_ON(t->snext >= t->sqdepth);
	ret = ib_post_send(t->cm_id->qp, &t->sring[t->snext].wr, &bad_wr);
	if (!ret) {
		t->scnt++;
		BUG_ON(t->scnt > t->sqdepth);
		t->snext++;
		if (t->snext == t->sqdepth)
			t->snext = 0;
	} else
		pr_err(PFX "%s ret %d\n", __func__, ret);
	DBG(PFX "%s sent scnt %d\n", __func__, t->scnt);
	return ret;
}

/**
 * map_buf() - map a buffer for dma
 * @t:		target context
 * @addrp:	the resulting dma address
 * @va:		the virtual address to map
 *
 * Map @va for dma and return the dma address in @addrp.
 *
 * Return: 0 upon success or negative errno upon failure.
 */
static int map_buf(struct target_ctx *t, u64 *addrp, void *va)
{
	int ret;
	*addrp = ib_dma_map_single(t->cm_id->device, va,
				   RBDP_BUFSZ, DMA_BIDIRECTIONAL);
	ret = ib_dma_mapping_error(t->cm_id->device, *addrp);
	if (ret)
		pr_err(PFX "dma_mapping error %d\n", ret);
	return ret;
}

/**
 * unmap_buf() - unmap a dma-mapped buffer
 * @t:		target context
 * @addr:	the dma address to unmap
 */
static void unmap_buf(struct target_ctx *t, u64 addr)
{
	ib_dma_unmap_single(t->cm_id->device, addr, RBDP_BUFSZ,
			    DMA_BIDIRECTIONAL);
}

/**
 * free_rings() - free the send and recv rings
 * @t:		target context
 *
 * Free and unmap the send and recv work request rings for @t.
 */
static void free_rings(struct target_ctx *t)
{
	int i;
	for (i = 0; i < t->sqdepth; i++) {
		if (t->sring[i].va) {
			unmap_buf(t, t->sring[i].sge.addr);
			kfree(t->sring[i].va);
		}
	}
	for (i = 0; i < t->rqdepth; i++) {
		if (t->rring[i].va) {
			unmap_buf(t, t->rring[i].sge.addr);
			kfree(t->rring[i].va);
		}
	}
	kfree(t->sring);
}

/**
 * alloc_rings() - allocate the send and recv rings
 * @t:		target context
 *
 * Allocate, dma-map, and initialize the send and recv wr rings for @t.
 *
 * Return: 0 upon success or negative errno upon failure.
 */
static int alloc_rings(struct target_ctx *t)
{
	int i, j = 0;
	int ret;
	int rings_len = t->sqdepth * sizeof *t->sring +
			t->rqdepth * sizeof *t->rring;

	t->sring = kzalloc(rings_len, GFP_KERNEL);
	if (!t->sring) {
		ret = -ENOMEM;
		goto err;
	}
	t->rring = (void *)(t->sring + t->sqdepth);

	for (i = 0; i < t->sqdepth; i++) {
		t->sring[i].va = kmalloc(RBDP_BUFSZ, GFP_KERNEL);
		if (!t->sring[i].va) {
			ret = -ENOMEM;
			goto err_ring;
		}
		memset(t->sring[i].va, 0xaa, RBDP_BUFSZ);
		ret = map_buf(t, &t->sring[i].dma_addr, t->sring[i].va);
		if (ret)
			goto err_ring;
		t->sring[i].sge.lkey = t->cm_id->device->local_dma_lkey;
		t->sring[i].wr.wr_id = i;
		t->sring[i].wr.sg_list = &t->sring[i].sge;
		t->sring[i].wr.num_sge = 1;
		t->sring[i].wr.opcode = -1;
		t->sring[i].wr.send_flags = IB_SEND_SIGNALED;
	}

	for (; j < t->rqdepth; j++) {
		t->rring[j].va = kmalloc(RBDP_BUFSZ, GFP_KERNEL);
		if (!t->rring[j].va) {
			ret = -ENOMEM;
			goto err_ring;
		}
		memset(t->rring[j].va, 0xbb, RBDP_BUFSZ);
		ret = map_buf(t, &t->rring[j].sge.addr, t->rring[j].va);
		if (ret)
			goto err_ring;
		t->rring[j].sge.lkey = t->cm_id->device->local_dma_lkey;
		t->rring[j].sge.length = RBDP_BUFSZ;
		t->rring[j].wr.wr_id = j;
		t->rring[j].wr.sg_list = &t->rring[j].sge;
		t->rring[j].wr.num_sge = 1;
	}
	return 0;
err_ring:
	while (i--) {
		unmap_buf(t, t->sring[i].sge.addr);
		kfree(t->sring[i].va);
		t->sring[i].va = NULL;
	}
	while (j--) {
		unmap_buf(t, t->rring[j].sge.addr);
		kfree(t->rring[j].va);
		t->rring[j].va = NULL;
	}
	kfree(t->sring);
err:
	return ret;
}

static int post_recvs(struct target_ctx *t)
{
	int ret = 0;
	int i;

	for (i = 0; i < t->rqdepth; i++) {
		ret = post_recv(t);
		if (ret)
			break;
	}
	return ret;
}

static void end_request(struct target_ctx *t, struct request *req, int err)
{
	BUG_ON(t->req_cnt == 0);
	t->req_cnt--;
	__blk_end_request_all(req, err);
}

/**
 * fail_pending_reqs() - complete any pending blk requests in error.
 * @t:		target context
 *
 * When a target's connection dies, we need to complete any outstanding
 * blk requests with -EIO.
 */
static void fail_pending_reqs(struct target_ctx *t)
{
	struct request *req;

	while (!list_empty(&t->req_list)) {
		req = list_first_entry(&t->req_list, struct request,
				       queuelist);
		list_del_init(&req->queuelist);
		DBG(PFX "failing pending req %p\n", req);
		end_request(t, req, -EIO);
	}
}

/**
 * process_pending_reqs() - process any pending requests
 * @t:		target context
 *
 * Process any pending requests if there is room on the SQ and
 * room in the RBDP send window.  This is called when either we
 * process SQ completions freeing up SQ slots, and after processing
 * RQ completions which indicate RGBDP requests have completed and
 * opened up the send window.
 */
static void process_pending_reqs(struct target_ctx *t)
{
	struct request *req;
	int ret;

	while (t->scnt <= (t->sqdepth - 3) &&
	       t->inuse_req_cnt < RBDP_MAX_REQUESTS &&
	       !list_empty(&t->req_list)) {
		req = list_first_entry(&t->req_list, struct request,
				       queuelist);
		list_del_init(&req->queuelist);
		DBG(PFX "starting pending req %p\n", req);
		ret = rbdi_start_request(req);
		if (ret)
			end_request(t, req, ret);
	}
}

/**
 * poll_scq() - poll the send queue and process completions
 * @t:		target context
 * @scnt	current count of SQ slots made available by this
 * 		CQ drain.
 *
 * Poll the SQ.  If the completion is for an inline SEND, then
 * we know this completion also completes the preceeding INV and
 * FASTREG work requests, so bump @scnt by 3.  Otherwise, the
 * SEND is for an immediate request so @scnt is bumped only by 1.
 * @scnt is initialized by the caller and this function only increments
 * @scnt.
 *
 * Return: 0 if cq empty, negative errnor on error, 1 if CQE consumed.
 */
static int poll_scq(struct target_ctx *t, int *scnt)
{
	struct ib_wc wc;
	int ret;

	ret = ib_poll_cq(t->scq, 1, &wc);
	if (ret > 0) {
		if (wc.status && wc.status != IB_WC_WR_FLUSH_ERR)
			pr_err(PFX "send wc status %d\n", wc.status);
		if (t->sring[wc.wr_id].wr.opcode == IB_WR_SEND) {
			(*scnt)++;

			/* INLINE == INV + FR + SEND vs IMMD SEND */
			if (t->sring[wc.wr_id].wr.send_flags & IB_SEND_INLINE) {
				(*scnt) +=2;
			}
		}
		t->sring[wc.wr_id].wr.opcode = -1;

		DBG(PFX "%s t %p t->snext %u t->scnt %u scnt %u wc %p\n",
			__func__, t, t->snext, t->scnt, *scnt, &wc);
	}
	return ret;
}

/**
 * scq_event_handler() - handle send completion event notifications
 * @cq:		cq to process
 * @ctx:	target context associated with this cq
 *
 * This is the upcall handler for send cq event notifications.  If this
 * target isn't on its poll thread's target list, then add it and wake
 * up the poll thread.
 */
static void scq_event_handler(struct ib_cq *cq, void *ctx)
{
	struct target_ctx *t = ctx;

	spin_lock(&t->my_thread_ctx->lock);
	if (list_empty(&t->poll_thread_entry)) {
		DBG(PFX "%s waking up target %p\n", __func__, t);
		list_add_tail(&t->poll_thread_entry,
			      &t->my_thread_ctx->poll_targets);
		wake_up_interruptible(&t->my_thread_ctx->wait);
	}
	/* Since this target entry is added/present in the poll target list,
	 * we set POLL_ACTIVE flage here and poll thread will reset this flag
	 * after draining all CQEs of this target.
	 */
	set_bit(POLL_ACTIVE_BIT, &t->event_state);
	spin_unlock(&t->my_thread_ctx->lock);
	return;
}

#ifdef DEBUG
static void dumpit(const char *str, void *p)
{
	u8 *cp = (u8 *)p;
	pr_info(PFX "%s %02x %02x %02x %02x %02x %02x %02x %02x "
		"%02x %02x %02x %02x %02x %02x %02x %02x : "
		"%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n", str,
		cp[0], cp[1], cp[2], cp[3], cp[4], cp[5], cp[6], cp[7],
		cp[8], cp[9], cp[10], cp[11], cp[12], cp[13], cp[14], cp[15],
		cp[0] < 32 || cp[0] > 127 ? '.' : cp[0],
		cp[1] < 32 || cp[1] > 127 ? '.' : cp[1],
		cp[2] < 32 || cp[2] > 127 ? '.' : cp[2],
		cp[3] < 32 || cp[3] > 127 ? '.' : cp[3],
		cp[4] < 32 || cp[4] > 127 ? '.' : cp[4],
		cp[5] < 32 || cp[5] > 127 ? '.' : cp[5],
		cp[6] < 32 || cp[6] > 127 ? '.' : cp[6],
		cp[7] < 32 || cp[7] > 127 ? '.' : cp[7],
		cp[8] < 32 || cp[8] > 127 ? '.' : cp[8],
		cp[9] < 32 || cp[8] > 127 ? '.' : cp[9],
		cp[10] < 32 || cp[10] > 127 ? '.' : cp[10],
		cp[11] < 32 || cp[11] > 127 ? '.' : cp[11],
		cp[12] < 32 || cp[12] > 127 ? '.' : cp[12],
		cp[13] < 32 || cp[13] > 127 ? '.' : cp[13],
		cp[14] < 32 || cp[14] > 127 ? '.' : cp[14],
		cp[15] < 32 || cp[15] > 127 ? '.' : cp[15]);
}
#endif

/**
 * dump_bvecs() - dump all segments of a blk request
 * @req:	blk request
 *
 * Debug code to dump the bio_vecs of @req.
 */
static void dump_bvecs(struct request *req)
{
	struct req_iterator iter;
	struct bio_vec bv, *bvp;
	int i=0;

	pr_info(PFX"----\n");
	RQ_FOR_EACH_SEGMENT(bv, bvp, req, iter)
		pr_info(PFX "bv[%u] page %p off %d len %d\n",
			i++, bv.bv_page, bv.bv_offset, bv.bv_len);
	pr_info(PFX"----\n");
}


/**
 * unmap_req_pages() - unmap the pages of a fastreg page list
 * @rctx:	request context
 *
 * Unmap all the fastreg pages used for this request.
 */
static void unmap_req_pages(struct req_ctx *rctx)
{
	int remain = rctx->fr_len;
	int i;

	DBG(PFX "%s\n", __func__);

	for (i = 0; i < rctx->fr_page_count; i++) {
		int size;
		size = min_t(int, remain, PAGE_SIZE);

		ib_dma_unmap_page(rctx->t->cm_id->device,
				  rctx->frpl->page_list[i],
				  size, DMA_BIDIRECTIONAL);
		BUG_ON(remain < size);
		remain -= size;
	}
	BUG_ON(remain || i != rctx->fr_page_count);
}

/**
 * add_seg_to_frpl() - add biovec segment to the fastreg page list
 * @rctx:	request context
 * @bvp:	bio_vev segment to add
 * @cur_page:	the current fastreg page to-which the segment will be added
 * @cur_len:    the length of the current fastreg entry
 *
 * Add @bvp to the curent fastreg page list, packing if possible.  If @bvp
 * contains a new page, then map its page for dma, bump to the next fastreg
 * page list entry, and initialize it and update @cur_page/@cur_len.
 * Upon return, @cur_page and @cur_len contain the current page and total
 * length in that page accumulated so far.  Thus this code will pack multiple
 * bio_vec segments if they are all in the same page.
 * EG:
 * biovecs:
 *	page X, offset 1024, len 1024
 *	page X, offset 2048, len 1024
 *	page X, offset 3072, len 1024
 *	page Y, offset 0, len 4096
 * resulting fastreg mr:
 *      page_list[0] X
 *      page_list[1] Y
 *	fr_fbo 1024
 *	fr_len 7168
 *	page_count 2
 *
 * Return: 0 upon success or negative errno upon failure.
 */
static int add_seg_to_frpl(struct req_ctx *rctx, struct bio_vec *bvp,
			   struct page **cur_page, int *cur_len)
{
	dma_addr_t addrp;
	int ret = 0;

	if (*cur_page == bvp->bv_page && *cur_len < PAGE_SIZE) {
		DBG(PFX "%s appending %d to cur page! rctx %p bv %p "
		    "cur_page %p cur_len %u\n", __func__, bvp->bv_len,
		    rctx, bvp, *cur_page, *cur_len);
		if (bvp->bv_offset != *cur_len) {
			pr_warn(PFX "%s non-sequential segment in same page! "
				"cur_page %p cur_len %d bv_off %d\n",
				__func__, *cur_page, *cur_len, bvp->bv_offset);
			ret = 1;
		}
		*cur_len += bvp->bv_len;
		BUG_ON(*cur_len > PAGE_SIZE);
		rctx->fr_len += bvp->bv_len;
		goto out;
	}
	addrp = ib_dma_map_page(rctx->t->cm_id->device, bvp->bv_page,
				bvp->bv_offset, bvp->bv_len,
				DMA_BIDIRECTIONAL);
	ret = ib_dma_mapping_error(rctx->t->cm_id->device, addrp);
	if (ret) {
		pr_err(PFX "dma_mapping error %d\n", ret);
		ret = -ENOMEM;
		goto out;
	}
	if (!*cur_page)
		rctx->fr_fbo = bvp->bv_offset;
	rctx->frpl->page_list[rctx->fr_page_count] = addrp;
	rctx->fr_len += bvp->bv_len;
	rctx->fr_page_count++;
	*cur_page = bvp->bv_page;
	*cur_len = bvp->bv_len;
out:
	return ret;
}

/**
 * map_req_pages() - map all pages from a request into a fastreg mr
 * @rctx:	request context
 *
 * For each segment in the request, map it and add it to the fastreg mr.
 * The bulk of the work is done by calling add_seg_to_frpl().
 *
 * Return: 0 upon success or negative errno upon failure.
 */
static int map_req_pages(struct req_ctx *rctx)
{
	struct request *req = rctx->req;
	struct req_iterator iter;
	struct page *cur_page = NULL;
	int cur_len = 0;
	struct bio_vec bv, *bvp;
	int ret = 0;

	DBG(PFX "%s\n", __func__);
	rctx->fr_len = 0;
	rctx->fr_page_count = 0;

	RQ_FOR_EACH_SEGMENT(bv, bvp, req, iter) {
		if (rctx->fr_len == RBDP_MAX_FR_DEPTH) {
			pr_err(PFX" %s bio depth too large!\n", __func__);
			ret = -E2BIG;
			goto err_unmap;
		}
		ret = add_seg_to_frpl(rctx, &bv, &cur_page, &cur_len);
		if (ret) {
			if (ret < 0)
				goto err_unmap;
			dump_bvecs(req);
			ret = 0;
		}
	}
	DBG(PFX "%s fr_page_count %d fr_len %d fr_fbo %d\n", __func__,
		rctx->fr_page_count, rctx->fr_len, rctx->fr_fbo);
	BUG_ON(rctx->fr_len != blk_rq_bytes(rctx->req));
	goto out;

err_unmap:
	unmap_req_pages(rctx);
out:
	return ret;
}

static void copy_immd_reply_data(struct req_ctx *rctx, struct rbdp_reply *rep)
{
	u32 tot_len = rctx->fr_len;
	struct req_iterator iter;
	struct bio_vec bv, *bvp;
	u8 *dstp, *srcp;

	srcp = (u8 *)(rep + 1);
	RQ_FOR_EACH_SEGMENT(bv, bvp, rctx->req, iter) {
		u32 size = min_t(u32, tot_len, bv.bv_len);

		BUG_ON(size != bv.bv_len);
		dstp = (u8 *)page_address(bv.bv_page) + bv.bv_offset;

		DBG(PFX "%s dstp %p srcp %p size %d\n", __func__,
		    dstp, srcp, size);

		memcpy(dstp, srcp, size);
		srcp += size;
		tot_len -= size;
		if (!tot_len)
			break;
	}
	BUG_ON(tot_len);
}

/**
 * process_reply() - process an RBDP reply from target host
 * @t:		target context
 * @wc:		recv work completion containing the reply
 *
 * Sync the reply data for cpu access, unmap the pages, and complete
 * the blk request indicating success or failure as per the RBDP reply.
 * Since a reply opens the request window, also process any pending requests.
 */
static void process_reply(struct target_ctx *t, struct ib_wc *wc)
{
	int idx = wc->wr_id;
	struct recv_wr_ring *wrr = &t->rring[idx];
	struct rbdp_reply *rep = (struct rbdp_reply *)wrr->va;
	struct req_ctx *rctx = lookup_xid(t, rep->xid);

	if (!rctx) {
		pr_err(PFX "bogus xid!\n");
		return;
	}

	if (ntohl(rep->flags) & RBDP_IMMD) {
		copy_immd_reply_data(rctx, rep);
		t->stats.immd_reads++;
	} else
		dma_sync_for_cpu(rctx);
	unmap_req_pages(rctx);

	DBG(PFX "completing %s rctx %p request %p status %d, "
		"started %llu completed %llu queue is %s rnext %u "
		"snext %u scnt %u\n",
		(ntohl(rep->flags) & RBDP_IMMD) ? "immd" : "",
		rctx, rctx->req,
		ntohl(rep->status), t->stats.reqs_started,
		t->stats.reqs_completed,
		list_empty(&t->req_list) ? "empty" : "not empty", idx,
		t->snext, t->scnt);

	t->stats.reqs_completed++;
	end_request(t, rctx->req, ntohl(rep->status));
	BUG_ON(t->inuse_req_cnt == 0);
	BUG_ON(list_empty(&rctx->rctx_inuse_entry));
	BUG_ON(!list_empty(&rctx->rctx_free_entry));
	list_del_init(&rctx->rctx_inuse_entry);
	list_add_tail(&rctx->rctx_free_entry, &t->free_req_ctxs);
	t->inuse_req_cnt--;
	post_recv(t);
}

/**
 * poll_rcq() - drain the recv cq processing all completions
 * @t:		target context
 *
 * Poll the recv CQ and process one reply.
 *
 * Return: 0 if cq empty, negative errnor on error, 1 if CQE consumed.
 */
static int poll_rcq(struct target_ctx *t)
{
	struct ib_wc wc;
	int ret;

	PENTER(INI_POLL_RCQ);
	ret = ib_poll_cq(t->rcq, 1, &wc);
	PEXIT(INI_POLL_RCQ);

	if (ret > 0) {
		if (!wc.status) {
			spin_lock_irq(&t->lock);
			PENTER(INI_REPLY);
			process_reply(t, &wc);
			PEXIT(INI_REPLY);
			spin_unlock_irq(&t->lock);
		} else if (wc.status != IB_WC_WR_FLUSH_ERR)
			pr_err(PFX "recv wc status 0x%x\n", wc.status);
	}
	return ret;
}

/**
 * drain_cqs() - drain the SQ and RQ CQs with weighted arbitration
 * @t:		Target context
 *
 * Using the cq_weights array to arbitrate how many CQEs are polled from
 * each CQ, drain both CQs until empty.  After each specific CQ drain cycle,
 * update SQ counts and process any pending requests if we actually consumed
 * any CQEs.
 */
static void drain_cqs(struct target_ctx *t)
{
	int scq_empty = 0;
	int rcq_empty = 0;
	int total_scnt = 0;
	int total_rcnt = 0;
	int scnt;
	int rcnt;
	int count;
	int ret;

	do {
		count = 0;
		rcnt = 0;
		scnt = 0;

		/*
		 * Drain the current CQ until empty or we hit the cq weight.
		 */
		while (count++ < cq_weights[t->cq_index]) {
			if (t->cq_index == SCQ_INDEX) {
				ret = poll_scq(t, &scnt);
				if (ret <= 0) {
					scq_empty = 1;
					break;
				}
			} else {
				ret = poll_rcq(t);
				if (ret > 0)
					rcnt++;
				else {
					rcq_empty = 1;
					break;
				}
			}
		}

		/*
		 * If any SQ slots were freed up then update the send ring
		 * count.  If either SQ or RQ CQEs were consumed, then process
		 * any pending requests.
		 */
		if (scnt || rcnt) {
			spin_lock_irq(&t->lock);
			t->scnt -= scnt;
			process_pending_reqs(t);
			spin_unlock_irq(&t->lock);
			total_scnt += scnt;
			total_rcnt += rcnt;
		}

		/*
		 * Toggle which CQ to poll.
		 */
		t->cq_index ^= 1;
	} while (!scq_empty || !rcq_empty);

	if (total_scnt > t->stats.max_scq_polled)
		t->stats.max_scq_polled = total_scnt;
	if (total_rcnt > t->stats.max_rcq_polled)
		t->stats.max_rcq_polled = total_rcnt;
}

/**
 * rcq_event_handler() - handle recv completion event notifications
 * @cq:		cq to process
 * @ctx:	target context associated with this cq
 *
 * This is the upcall handler for recv cq event notifications.  If this
 * target isn't on its poll thread's target list, then add it and wake
 * up the poll thread.
 */
static void rcq_event_handler(struct ib_cq *cq, void *ctx)
{
	struct target_ctx *t = ctx;

	spin_lock(&t->my_thread_ctx->lock);
	if (list_empty(&t->poll_thread_entry)) {
		list_add_tail(&t->poll_thread_entry,
			      &t->my_thread_ctx->poll_targets);
		wake_up_interruptible(&t->my_thread_ctx->wait);
	}
	/* Since this target entry is added/present in the poll target list,
	 * we set POLL_ACTIVE flage here and poll thread will reset this flag
	 * after draining all CQEs of this target.
	 */
	set_bit(POLL_ACTIVE_BIT, &t->event_state);
	spin_unlock(&t->my_thread_ctx->lock);
	return;
}

/**
 * fail_inuse_reqs() - fail any requests that are in flight
 *
 * @t:		target context
 *
 * If the connection to the target dies, then we need to complete any
 * blk requests that will never complete.
 */
static void fail_inuse_reqs(struct target_ctx *t)
{
	struct req_ctx *rctx;

	while (!list_empty(&t->inuse_req_ctxs)) {
		rctx = list_first_entry(&t->inuse_req_ctxs, struct req_ctx,
					rctx_inuse_entry);
		list_del_init(&rctx->rctx_inuse_entry);

		unmap_req_pages(rctx);

		t->stats.reqs_completed++;
		end_request(t, rctx->req, -EIO);

		BUG_ON(t->inuse_req_cnt == 0);
		list_add_tail(&rctx->rctx_free_entry, &t->free_req_ctxs);
		t->inuse_req_cnt--;
	}
}

/**
 * flush_pending_io() - flush all in-progress and pending blk requests
 * @t:		target context
 *
 * On a fatal error, fail all outstanding blk io requests.
 */
static void flush_pending_io(struct target_ctx *t)
{
	spin_lock_irq(&t->lock);
	fail_inuse_reqs(t);
	fail_pending_reqs(t);
	spin_unlock_irq(&t->lock);
}

/**
 * parse_accept_data() - parse connection private data defining the disk geom
 * @t:		target context
 * @event:	cm event with private data
 *
 * This function does 2 key things: 1) validate and unmarshall the connection
 * data that defines the target disk. 2) convert the disk sector size to
 * PAGE_SIZE.  We want PAGE_SIZE sectors so we can efficiently fast register
 * block io requests (they will all be page aligned).
 *
 * Return: 0 upon success or negative errno upon failure.
 */
static int parse_accept_data(struct target_ctx *t, struct rdma_cm_event *event)
{
	struct rbdp_accept_data *rad;
	u64 start_sec, sectors;
	u32 sec_size;
	u32 factor;

	if (!event->param.conn.private_data ||
	    event->param.conn.private_data_len != sizeof *rad) {
		pr_err(PFX "bad private data len %d\n",
			event->param.conn.private_data_len);
		return -EINVAL;
	}
	rad = (struct rbdp_accept_data *)event->param.conn.private_data;

	t->max_io_size = be32_to_cpu(rad->max_io_size);
	t->max_sges = be32_to_cpu(rad->max_sges);
	start_sec = be64_to_cpu(rad->start_sec);
	sectors = be64_to_cpu(rad->sectors);
	sec_size = be32_to_cpu(rad->sec_size);

	DBG(PFX "target sectors %llu start_sec %llu sec_size %u bytes %llu "
		"max_io_size %u max_sges %u\n",
		sectors, start_sec, sec_size, sectors * sec_size,
		t->max_io_size, t->max_sges);

	if (!sectors || !sec_size || !t->max_io_size || !t->max_sges) {
		return -EINVAL;
	}

	/* Transform the geometry to PAGE_SIZE sector sizes */
	factor = PAGE_SIZE / sec_size;
	if (sec_size * factor != PAGE_SIZE) {
		pr_info(PFX "target sector size %u is not a factor of "
			"PAGE_SIZE %lu! Cannot attach target.\n", sec_size,
			PAGE_SIZE);
		return -EINVAL;
	}

	sec_size = PAGE_SIZE;
	start_sec = roundup(start_sec, factor);
	start_sec = div_u64(start_sec, factor);
	sectors = rounddown(sectors, factor);
	sectors = div_u64(sectors, factor);

	DBG(PFX "initiator sectors %llu start_sec %llu sec_size %u "
		"bytes %llu\n",
		sectors, start_sec, sec_size, sectors * sec_size);

	t->sec_size = sec_size;
	t->start_sec = start_sec;
	t->sectors = sectors;
	return 0;
}

/**
 * cm_event_handler() - handle new events from the rdma_cm layer
 *
 * @cm_id:	rdma_cm id posting the event
 * @event:	the event to process
 *
 * Process a connection event and wake up any waiters.
 */
static int cm_event_handler(struct rdma_cm_id *cm_id,
			    struct rdma_cm_event *event)
{
	struct target_ctx *t = cm_id->context;

	/* check if the target is in proper state to handle CM events */
	if (DELETING_TARGET & test_and_set_bit(CM_ACTIVE_BIT,
					       &t->event_state)) {
		/* This target is being detroyed, so reset the flag and exit */
		clear_bit(CM_ACTIVE_BIT, &t->event_state);
		goto error;
	}

	switch (event->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		t->ret = rdma_resolve_route(cm_id, 2000);
		if (t->ret) {
			t->state = ERROR;
			pr_err(PFX "rdma_resolve_route err %d\n", t->ret);
			wake_up_interruptible(&t->wait);
		}
		break;

	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		t->state = RESOLVED;
		wake_up_interruptible(&t->wait);
		break;

	case RDMA_CM_EVENT_ESTABLISHED:
		t->state = CONNECTED;
		t->ret = parse_accept_data(t, event);
		wake_up_interruptible(&t->wait);
		break;
	case RDMA_CM_EVENT_ADDR_ERROR:
	case RDMA_CM_EVENT_ROUTE_ERROR:
	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
	case RDMA_CM_EVENT_REJECTED:
		pr_err(PFX "cm event %d, err %d\n", event->event,
		       event->status);
		t->ret = event->status;
		t->state = ERROR;
		wake_up_interruptible(&t->wait);
		break;

	case RDMA_CM_EVENT_DISCONNECTED:
		DBG(PFX "Target disconnect! %s\n", t->disk->disk_name);
		flush_pending_io(t);
		t->state = ERROR;
		wake_up_interruptible(&t->wait);
		break;

	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		pr_err(PFX "Device removal! %s\n", t->disk->disk_name);
		t->state = ERROR;
		wake_up_interruptible(&t->wait);
		break;

	default:
		pr_err(PFX "oof unexpected event %d! %s\n", event->event,
		       t->disk->disk_name);
		t->state = ERROR;
		wake_up_interruptible(&t->wait);
		break;
	}
	clear_bit(CM_ACTIVE_BIT, &t->event_state);
error:
	return 0;
}

/**
 * send_inv_fr() - build and send invalidate-local-stag + fastreg-mr WRs
 *
 * @rctx:	request context
 *
 * Each reuse of @rctx requires invalidating the previous iteration of the
 * fastreg MR, and registering the new fastreg MR.  So build and post the
 * invalidate, bump the fastreg key, and build/post the fastreg mr.  This
 * function assumes there are 2 SQ entries available; so flow control must
 * be handled by the caller.
 *
 * Return: 0 upon success or negative errno upon failure.
 */
static int send_inv_fr(struct req_ctx *rctx)
{
	struct target_ctx *t = rctx->t;
	struct send_wr_ring *sr = &t->sring[t->snext];
	struct ib_send_wr *wr = &sr->wr;
	int dir = rq_data_dir(rctx->req);
	int ret;

	DBG(PFX "%s\n", __func__);

	BUG_ON(list_empty(&rctx->rctx_inuse_entry));
	BUG_ON(!list_empty(&rctx->rctx_free_entry));

	wr->opcode = IB_WR_LOCAL_INV;
	wr->ex.invalidate_rkey = rctx->frmr->rkey;
	wr->send_flags = 0;
	ret = post_send(t);
	if (ret)
		goto out;

	ib_update_fast_reg_key(rctx->frmr, ++rctx->frmr_key);
	sr = &t->sring[t->snext];
	wr = &sr->wr;
	wr->opcode = IB_WR_FAST_REG_MR;
	wr->send_flags = 0;
	wr->wr.fast_reg.page_shift = PAGE_SHIFT;
	wr->wr.fast_reg.length = rctx->fr_len;
	wr->wr.fast_reg.page_list = rctx->frpl;
	wr->wr.fast_reg.page_list_len = rctx->fr_page_count;
	wr->wr.fast_reg.rkey = rctx->frmr->rkey;
	wr->wr.fast_reg.iova_start = 0;
	wr->wr.fast_reg.access_flags = IB_ACCESS_LOCAL_WRITE;

	/*
	 * If this is a WRITE blk request, then the target will
	 * rdma-read the data, so sync it for dma and set the REMOTE_READ
	 * access rights.  Otherwise, the target will rdma write into our
	 * fastreg MR so set REMOTE_WRITE access rights.
	 */
	if (dir == WRITE) {
		dma_sync_for_dev(rctx);
		wr->wr.fast_reg.access_flags |= IB_ACCESS_REMOTE_READ;
	} else
		wr->wr.fast_reg.access_flags |= IB_ACCESS_REMOTE_WRITE;

	ret = post_send(t);
out:
	return ret;
}

/**
 * send_request() - send the RBDP request message to the target
 * @rctx:	request context
 *
 * Build the RDBP request message and send it to the target.
 *
 * Return: 0 upon success or negative errno upon failure.
 */
static int send_request(struct req_ctx *rctx)
{
	struct rbdp_request *rbdp_req;
	struct target_ctx *t = rctx->t;
	struct send_wr_ring *sr = &t->sring[t->snext];
	struct ib_send_wr *wr = &sr->wr;
	int dir = rq_data_dir(rctx->req);

	rbdp_req = sr->va;

	BUG_ON(list_empty(&rctx->rctx_inuse_entry));
	BUG_ON(!list_empty(&rctx->rctx_free_entry));

	rbdp_req->xid = rctx->xid;
	if (dir == WRITE)
		rbdp_req->cmd = htonl(RBDP_CMD_WRITE);
	else
		rbdp_req->cmd = htonl(RBDP_CMD_READ);
	rbdp_req->flags = 0;
	rbdp_req->start_sector = htonl(blk_rq_pos(rctx->req));
	rbdp_req->num_sge = htonl(1); /* XXX */
	rbdp_req->tot_len = htonl(rctx->fr_len);
	rbdp_req->sgl[0].stag = htonl(rctx->frmr->rkey);
	rbdp_req->sgl[0].len = htonl(rctx->fr_len);
	rbdp_req->sgl[0].to = 0;

	sr->sge.length = sizeof *rbdp_req + sizeof *rbdp_req->sgl;
	sr->sge.addr = (u64)(uintptr_t)sr->va;

	wr->num_sge = 1;
	wr->opcode = IB_WR_SEND;
	wr->send_flags = IB_SEND_SIGNALED | IB_SEND_INLINE;

	DBG(PFX "sending request %p req_ctx %p xid %x cmd %s sec_start %d "
		"stag %x to %llx len %d\n", rctx->req, rctx,
		rbdp_req->xid, dir == WRITE ? "WR" : "RD",
		(int)blk_rq_pos(rctx->req), rctx->frmr->rkey,
		ntohll(rbdp_req->sgl[0].to), rctx->fr_len);

	return post_send(t);
}

/**
 * copy_req_segments() - copy the request segments to linear buffer
 * @dst:	destination address
 * @req:	blk request
 *
 * Copy all segment data from @req into @dst.
 */
static void copy_req_segments(u8 *dst, struct request *req)
{
	struct req_iterator iter;
	struct bio_vec bv, *bvp;

	RQ_FOR_EACH_SEGMENT(bv, bvp, req, iter)  {
		memcpy(dst, page_address(bv.bv_page) + bv.bv_offset, bv.bv_len);
		dst += bv.bv_len;
	}
}

/**
 * send_immd() - send a WRITE request with immediate data
 * @rctx:	request context
 *
 * Send a WRITE request with the payload inline in the SEND message.
 *
 * Return: 0 upon success or negative errno upon failure.
 */
static int send_immd(struct req_ctx *rctx)
{
	struct rbdp_request *rbdp_req;
	struct target_ctx *t = rctx->t;
	struct send_wr_ring *sr = &t->sring[t->snext];
	struct ib_send_wr *wr = &sr->wr;
	int dir = rq_data_dir(rctx->req);

	rbdp_req = sr->va;

	BUG_ON(list_empty(&rctx->rctx_inuse_entry));
	BUG_ON(!list_empty(&rctx->rctx_free_entry));

	rbdp_req->xid = rctx->xid;
	rbdp_req->cmd = htonl(RBDP_CMD_WRITE);
	rbdp_req->flags = htonl(RBDP_IMMD);
	rbdp_req->start_sector = htonl(blk_rq_pos(rctx->req));
	rbdp_req->num_sge = htonl(0); /* XXX */
	rbdp_req->tot_len = htonl(blk_rq_bytes(rctx->req));
	copy_req_segments((u8 *)rbdp_req->sgl, rctx->req);

	sr->sge.length = sizeof *rbdp_req + blk_rq_bytes(rctx->req);
	sr->sge.addr = (u64)(uintptr_t)sr->dma_addr;

	wr->num_sge = 1;
	wr->opcode = IB_WR_SEND;
	wr->send_flags = IB_SEND_SIGNALED;

	DBG(PFX "sending immd request %p req_ctx %p xid %x cmd %s sec_start %d "
		"stag %x to %llx len %d\n", rctx->req, rctx,
		rbdp_req->xid, dir == WRITE ? "WR" : "RD",
		(int)blk_rq_pos(rctx->req), rctx->frmr->rkey,
		ntohll(rbdp_req->sgl[0].to), ntohl(rbdp_req->tot_len));

	t->stats.immd_writes++;
	return post_send(t);
}

/**
 * rbdi_start_request() - begin processing a blk request
 * @req:	blk request
 *
 * This is the starting point of processing a blk request, either
 * from the blk layer downcall, or for processing pending requests.
 * If the connection is up and we're not flow controlled, then start the send.
 * If the total length fits a RBDP immediate request, then send it immediate.
 * Otherwise, map the request buffers, send the invalidate/fastreg, and
 * then send the RBDP request to the target node.
 *
 * Return: 0 upon success or negative errno upon failure.
 */
static int rbdi_start_request(struct request *req)
{
	struct target_ctx *t = req->rq_disk->private_data;
	struct req_ctx *rctx;
	int ret = 0;

	PENTER(INI_REQUEST);
	BUG_ON(t->scnt > t->sqdepth);
	BUG_ON(t->inuse_req_cnt > RBDP_MAX_REQUESTS);

	if (t->state != CONNECTED) {
		ret = -EIO;
		goto out;
	}

	DBG(PFX "%s dir %d start_sec %ld sec_count %d\n", __func__,
		rq_data_dir(req), blk_rq_pos(req), blk_rq_sectors(req));


	if (t->scnt > (t->sqdepth - 3) ||
	    t->inuse_req_cnt == RBDP_MAX_REQUESTS) {
		if (t->scnt > (t->sqdepth - 3)) {
			DBG(PFX "SQ full, deferring req %p.\n", req);
			t->stats.stall_sq_full++;
		} else {
			DBG(PFX "Max reqs, deferring req %p.\n", req);
			t->stats.stall_max_reqs++;
		}
		list_add_tail(&req->queuelist, &t->req_list);
		goto out;
	}
	BUG_ON((t->sqdepth - t->scnt) < 3); /* INV, FR, SEND */

	rctx = list_first_entry(&t->free_req_ctxs, struct req_ctx,
				rctx_free_entry);
	BUG_ON(!rctx);

	rctx->xid = t->xid_start++;

	list_del_init(&rctx->rctx_free_entry);
	list_add_tail(&rctx->rctx_inuse_entry, &t->inuse_req_ctxs);
	t->inuse_req_cnt++;
	rctx->t = t;
	rctx->req = req;

	PEXIT(INI_REQUEST);
	if (use_immd && blk_rq_bytes(req) <= RBDP_MAX_IMMD &&
	    rq_data_dir(rctx->req) == WRITE) {
		ret = send_immd(rctx);
		if (ret)
			goto err_list;
	} else {

		PENTER(INI_MAP);
		ret = map_req_pages(rctx);
		if (ret)
			goto err_list;

		ret = send_inv_fr(rctx);
		if (ret)
			goto err_unmap;;
		PEXIT(INI_MAP);

		PENTER(INI_SEND);
		ret = send_request(rctx);
		PEXIT(INI_SEND);
		if (ret)
			goto err_unmap;
	}
	BUG_ON(list_empty(&rctx->rctx_inuse_entry));
	BUG_ON(!list_empty(&rctx->rctx_free_entry));
	t->stats.reqs_started++;
	goto out;
err_unmap:
	unmap_req_pages(rctx);
err_list:
	list_add(&rctx->rctx_free_entry, &t->free_req_ctxs);
	list_del_init(&rctx->rctx_inuse_entry);
	t->inuse_req_cnt--;
out:
	return ret;
}

static int init_target_ctx(struct target_ctx *t);

/**
 * alloc_target_ctx() - allocate and initialize the target structure
 * @ipaddr_str:		ipaddress string
 * @port:		ip port number
 * @device:		backend target device
 *
 * Allocate memory for the target context and inialize the various cruft.
 *
 * Return: target_ctx ptr upon success or NULL
 */
static struct target_ctx *alloc_target_ctx(char *ipaddr_str, u16 port,
					   char *device)
{
	struct target_ctx *t;

	t = kzalloc(sizeof *t, GFP_USER);
	if (!t)
		return NULL;
	memcpy(t->ipaddr, ipaddr_str, sizeof t->ipaddr);
	memcpy(t->device, device, sizeof t->device);
	t->port = port;
	t->sqdepth = default_sqdepth;
	t->rqdepth = RBDP_MAX_REQUESTS;
	init_waitqueue_head(&t->wait);
	INIT_LIST_HEAD(&t->free_req_ctxs);
	INIT_LIST_HEAD(&t->inuse_req_ctxs);
	INIT_LIST_HEAD(&t->req_list);
	INIT_LIST_HEAD(&t->poll_thread_entry);
	INIT_LIST_HEAD(&t->target_list_entry);
	spin_lock_init(&t->lock);
	return t;
}

static int destroy_target(struct target_ctx *t);

/**
 * rbdi_remove_device() - find and remove the device
 * @device:	string of the local initiator device name to find
 *
 * Find @device in the target list and return a pointer to the target context.
 *
 * Return: 0 upon success or negative errno upon failure.
 */
int rbdi_remove_device(__u8 *device)
{
	char dev[32];
	int found = 0;
	struct target_ctx *t;
	int ret;

	mutex_lock(&target_mutex);
	list_for_each_entry(t, &target_list, target_list_entry) {
		snprintf(dev,sizeof dev, "/dev/%s", t->disk->disk_name);
		if (!strncmp(dev, device, sizeof dev)) {
			found = 1;
			break;
		}
	}
	if (found)
		ret = destroy_target(t);
	mutex_unlock(&target_mutex);
	return found ? ret : -ENODEV;
}

int rbdi_add_target(__u8 *addrstr, __u16 port, __u8 *device)
{
	struct target_ctx *t;
	int ret = 0;

	t = alloc_target_ctx(addrstr, port, device);
	if (!t) {
		ret = -EIO;
		goto out;
	}
	ret = init_target_ctx(t);
out:
	return ret;
}

/**
 * tgt_show() - debugfs read fops for the "devices" file
 *
 * dump the list of currently connected target devices.
 */
static int tgt_show(struct seq_file *seq, void *v)
{
	struct target_ctx *t;

	mutex_lock(&target_mutex);
	list_for_each_entry(t, &target_list, target_list_entry)
		seq_printf(seq, "local /dev/%s %pI4:%u remote %s "
			"%pI4:%u state %s\n",
			t->disk->disk_name,
			&SINP(&t->cm_id->route.addr.src_addr)->sin_addr,
			ntohs(SINP(&t->cm_id->route.addr.src_addr)->sin_port),
			t->device,
			&SINP(&t->cm_id->route.addr.dst_addr)->sin_addr,
			ntohs(SINP(&t->cm_id->route.addr.dst_addr)->sin_port),
			state_str[t->state]);
	mutex_unlock(&target_mutex);
	return 0;
}

size_t rbdi_list_targets(__u64 response_buf, __u32 response_size)
{
	struct target_ctx *t;
	char buf[256];
	int total_cc = 0, cc;
	int just_count = response_size == 0;

	mutex_lock(&target_mutex);
	list_for_each_entry(t, &target_list, target_list_entry) {
		cc = snprintf(buf, sizeof buf,
			"local /dev/%s %pI4:%u remote %s %pI4:%u state %s\n",
			t->disk->disk_name,
			&SINP(&t->cm_id->route.addr.src_addr)->sin_addr,
			ntohs(SINP(&t->cm_id->route.addr.src_addr)->sin_port),
			t->device,
			&SINP(&t->cm_id->route.addr.dst_addr)->sin_addr,
			ntohs(SINP(&t->cm_id->route.addr.dst_addr)->sin_port),
			state_str[t->state]);

		total_cc += cc;

		if (just_count)
			continue;

		if (cc > response_size) {
			total_cc = -ENOMEM;
			break;
		}
		if (copy_to_user((void __user *)(uintptr_t)response_buf,
				 buf, cc)) {
			total_cc = -EFAULT;
			break;
		}
		response_buf += cc;
		response_size -= cc;
	}
	mutex_unlock(&target_mutex);
	return total_cc;
}

static int tgt_open(struct inode *inode, struct file *file)
{
	return single_open(file, tgt_show, inode->i_private);
}

static const struct file_operations tgt_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = tgt_open,
	.release = single_release,
	.read    = seq_read,
	.llseek  = seq_lseek,
};

/**
 * stats_show() - show statistics for this target device
 */
static int stats_show(struct seq_file *seq, void *v)
{
	struct target_ctx *t = seq->private;

	seq_printf(seq, "reqs_started %llu\n", t->stats.reqs_started);
	seq_printf(seq, "reqs_completed %llu\n", t->stats.reqs_completed);
	seq_printf(seq, "immd_writes %llu\n", t->stats.immd_writes);
	seq_printf(seq, "immd_reads %llu\n", t->stats.immd_reads);
	seq_printf(seq, "stall_max_reqs %llu\n", t->stats.stall_max_reqs);
	seq_printf(seq, "stall_sq_full %llu\n", t->stats.stall_sq_full);
	seq_printf(seq, "max_outstanding_reqs %llu\n",
		   t->stats.max_outstanding_reqs);
	seq_printf(seq, "cq_waits %llu\n", t->stats.cq_waits);
	seq_printf(seq, "max_rcq_polled %llu\n", t->stats.max_rcq_polled);
	seq_printf(seq, "max_scq_polled %llu\n", t->stats.max_scq_polled);
	return 0;
}

static int stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, stats_show, inode->i_private);
}

static ssize_t stats_clear(struct file *file, const char __user *buf,
			      size_t count, loff_t *pos)
{
	struct target_ctx *t = ((struct seq_file *)file->private_data)->private;

	memset(&t->stats, 0, sizeof t->stats);
	return count;
}

static const struct file_operations stats_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = stats_open,
	.release = single_release,
	.read	 = seq_read,
	.llseek  = seq_lseek,
	.write   = stats_clear,
};

static void setup_target_debugfs(struct target_ctx *t)
{
	struct dentry *de;

	de = debugfs_create_file("stats", S_IWUSR, t->debugfs_root,
				 (void *)t, &stats_debugfs_fops);
}

/**
 * flush_qp() - move the qp to ERROR to flush any WRs
 * @t:		target context
 *
 * If connection setup fails, then we're stuck with a qp that
 * has posted recv wrs.  So flush them before destroying the
 * target context.
 */
static void flush_qp(struct target_ctx *t)
{
	struct ib_qp_attr attr = {0};

	DBG(PFX "Flushing qp.\n");
	attr.qp_state = IB_QPS_ERR;
	(void)ib_modify_qp(t->cm_id->qp, &attr, IB_QP_STATE);
}

/**
 * connect_to_target() - connect to the target device
 * @t:		target context
 *
 * attempt an rdma connect to the target device.  Successful
 * connection initializes @t device sector count, sector size
 * etc...see cm_event_handler().
 *
 * Return: 0 upon success or negative errno upon failure.
 */
static int connect_to_target(struct target_ctx *t)
{
	int ret;
	struct sockaddr_in sin = { 0 };
	struct rdma_conn_param conn_param = { 0 };
	struct ib_qp_init_attr init_attr = { 0 };
	struct ib_device_attr dev_attr = { 0 };
	struct rbdp_connect_data rcd;

	DBG(PFX "connecting to target %s-%u\n", t->ipaddr, t->port);
	t->xid_start = get_random_int() & 0x7fffffff;

	/* create cm_id */
	t->cm_id = rdma_create_id(cm_event_handler, t, RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(t->cm_id)) {
		ret = PTR_ERR(t->cm_id);
		goto err_out;
	}
	DBG(PFX "cm_id created!\n");

	/* resolve address/route */
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = in_aton(t->ipaddr);
	sin.sin_port = htons(t->port);
	ret = rdma_resolve_addr(t->cm_id, NULL, (struct sockaddr *)&sin,
				2000);
	if (ret)
		goto err_cm_id;

	wait_event_interruptible(t->wait, t->state >= RESOLVED);
	if (t->state != RESOLVED) {
		ret = t->ret;
		goto err_cm_id;
	}
	DBG(PFX "addr/route resolved!\n");

	/*
	 * XXX - don't let the underlying device go away!
	 */
	if (!try_module_get(t->cm_id->device->owner)) {
		pr_err(PFX "try_module_get() failed!\n");
		ret = -ENODEV;
		goto err_cm_id;
	}

	t->pd = ib_alloc_pd(t->cm_id->device);
	if (IS_ERR(t->pd)) {
		ret = PTR_ERR(t->pd);
		pr_err(PFX "ib_alloc_pd failed %d\n", ret);
		t->pd = NULL;
		goto err_module_get;
	}
	DBG(PFX "pd allocated!\n");

	t->scq = IB_CREATE_CQ(t->cm_id->device, scq_event_handler, NULL,
			      t, t->sqdepth, 0);
	if (IS_ERR(t->scq)) {
		ret = PTR_ERR(t->scq);
		pr_err(PFX "ib_create_cq failed %d\n", ret);
		t->scq = NULL;
		goto err_pd;
	}
	t->rcq = IB_CREATE_CQ(t->cm_id->device, rcq_event_handler, NULL,
			      t, t->rqdepth, 1);
	if (IS_ERR(t->rcq)) {
		ret = PTR_ERR(t->rcq);
		pr_err(PFX "ib_create_cq failed %d\n", ret);
		t->rcq = NULL;
		goto err_scq;
	}

	t->my_thread_ctx = &poll_threads[next_poll_ctx++ % poll_thread_count];
	ib_req_notify_cq(t->rcq, IB_CQ_NEXT_COMP);
	ib_req_notify_cq(t->scq, IB_CQ_NEXT_COMP);

	ret = alloc_rings(t);
	if (ret) {
		pr_err(PFX "init_rings failed %d\n", ret);
		goto err_rcq;
	}

	ret = alloc_req_ctxs(t);
	if (ret) {
		pr_err(PFX "alloc_req_ctxs failed %d\n", ret);
		goto err_rings;
	}

	init_attr.cap.max_send_wr = t->sqdepth;
	init_attr.cap.max_recv_wr = t->rqdepth;
	init_attr.cap.max_recv_sge = 1;
	init_attr.cap.max_send_sge = 1;
	init_attr.qp_type = IB_QPT_RC;
	init_attr.send_cq = t->scq;
	init_attr.recv_cq = t->rcq;
	init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	ret = rdma_create_qp(t->cm_id, t->pd, &init_attr);
	if (ret) {
		pr_err(PFX "rdma_create_qp failed %d\n", ret);
		goto err_rctx;
	}

	ret = post_recvs(t);
	if (ret) {
		pr_err(PFX "error posting recvs %d\n", ret);
		goto err_qp;
	}

	/* connect */
	DBG(PFX "connecting!\n");
	conn_param.responder_resources = responder_resources;
	conn_param.initiator_depth = 0;
	conn_param.retry_count = 10;
	rcd.version = ntohl(RBDP_VERSION);
	rcd.max_requests = ntohl(RBDP_MAX_REQUESTS);
	rcd.max_io_size = ntohl(RBDP_MAX_IO_SIZE);
	rcd.max_read_depth = ntohl(responder_resources);
	rcd.max_sges = ntohl(RBDP_MAX_SGES);
	memcpy(rcd.dev, t->device, RBDP_DEVLEN);
	conn_param.private_data = &rcd;
	conn_param.private_data_len = sizeof rcd;

	ret = rdma_connect(t->cm_id, &conn_param);
	if (ret) {
		pr_err(PFX "rdma_connect failed %d\n", ret);
		goto err_qp;
	}

	wait_event_interruptible(t->wait, t->state >= CONNECTED);
	if (t->ret) {
		ret = t->ret;
		pr_err(PFX "connection failed %d!\n", ret);
		flush_qp(t);
		destroy_target(t);
		goto err_out;
	}

	pr_info(PFX "connected %pI4:%u<->%pI4:%u!\n",
		&SINP(&t->cm_id->route.addr.src_addr)->sin_addr,
		ntohs(SINP(&t->cm_id->route.addr.src_addr)->sin_port),
		&SINP(&t->cm_id->route.addr.dst_addr)->sin_addr,
		ntohs(SINP(&t->cm_id->route.addr.dst_addr)->sin_port));
	ib_query_device(t->cm_id->device, &dev_attr);
	DBG(PFX "max_page_list_len %d\n", dev_attr.max_fast_reg_page_list_len);

	return 0;
err_qp:
	rdma_destroy_qp(t->cm_id);
err_rctx:
	dealloc_req_ctxs(t);
err_rings:
	free_rings(t); /* XXX needs to happen after CQs are destroyed */
err_rcq:
	ib_destroy_cq(t->rcq);
err_scq:
	ib_destroy_cq(t->scq);
err_pd:
	ib_dealloc_pd(t->pd);
err_module_get:
	module_put(t->cm_id->device->owner);
err_cm_id:
	rdma_destroy_id(t->cm_id);
err_out:
	return ret;
}

/**
 * destroy_target() - destroy a connected target if not in use
 * @t:		target context
 *
 * if there are no opens on the device, then disconnect and destroy
 * all resources.
 *
 * Return: 0 upon success or negative errno upon failure.
 */
static int destroy_target(struct target_ctx *t)
{
	int opened;
	int index = -1;
	int i = 0;

	spin_lock_irq(&t->lock);
	opened = t->open_count;
	spin_unlock_irq(&t->lock);
	if (opened) {
		pr_info(PFX "%s target %s busy!\n", __func__,
			t->disk->disk_name);
		return -EBUSY;
	}

	pr_info(PFX "destroying target /dev/%s->%s\n", t->disk->disk_name,
		t->device);

	if (t->state == CONNECTED) {
		rdma_disconnect(t->cm_id);
		wait_event_interruptible(t->wait, t->state >= CONNECTED);
		DBG(PFX "disconnected!\n");
	}
	for (i = 0; i < DESTROY_TIMEOUT; i++) {
		/* Wait for poll thread to drain pending CQEs of this target */
		msleep(10);

		set_bit(DELETING_TARGET_BIT, &t->event_state);

		/* Check whether poll thread finished draining all CQEs */
		if (DELETING_TARGET == atomic_long_read((atomic_long_t *)
						     &t->event_state))
			break;
	}
	if (i == DESTROY_TIMEOUT) {
		pr_info(PFX "Could not destroy target objects %s\n", t->device);
		return -EBUSY;
	}

	if (t->cm_id->qp)
		rdma_destroy_qp(t->cm_id);

	if (t->rcq)
		ib_destroy_cq(t->rcq);
	if (t->scq)
		ib_destroy_cq(t->scq);
	if (t->pd)
		ib_dealloc_pd(t->pd);
	dealloc_req_ctxs(t);
	free_rings(t);
	module_put(t->cm_id->device->owner);
	if (t->cm_id)
		rdma_destroy_id(t->cm_id);
	if (t->debugfs_root)
		debugfs_remove_recursive(t->debugfs_root);
	if (t->disk) {
		/* take backup of index number */
		index = t->disk->first_minor;
		del_gendisk(t->disk);
		put_disk(t->disk);
	}
	if (index > -1)
		ida_simple_remove(&rbdi_minors, index);

	if (t->rq)
		blk_cleanup_queue(t->rq);
	if (!list_empty(&t->target_list_entry))
		list_del(&t->target_list_entry);
	kfree(t);
	return 0;
}

/**
 * rbdi_open() - open a rbdi device
 * @bdev:	Block device to open
 * @mode:	open mode
 *
 * Open a RBDI device.  Just bumps the open_count...
 *
 * Return: 0 upon success or negative errno upon failure.
 */
static int rbdi_open(struct block_device *bdev, fmode_t mode)
{
	struct target_ctx *t = bdev->bd_disk->private_data;
	int ret = 0;

	spin_lock_irq(&t->lock);
	if (t->state != CONNECTED)
		ret = -EIO;
	else
		t->open_count++;
	spin_unlock_irq(&t->lock);

	DBG(PFX "Open %s open_count %d ret %d\n", t->disk->disk_name,
	    t->open_count, ret);
	return ret;
}

/**
 * rbdi_close() - close an rbdi device
 * @disk:	rbdi disk to close
 * @mode:	open mode
 *
 * Close the RBDI device.  Just decrements the open count on
 * this target.
 */
static void rbdi_close(struct gendisk *disk, fmode_t mode)
{
	struct target_ctx *t = disk->private_data;

	spin_lock_irq(&t->lock);
	DBG(PFX "Close %s open_count %d!\n", t->disk->disk_name,
	    t->open_count);
	if (t->open_count)
		t->open_count--;
	spin_unlock_irq(&t->lock);
	return;
}

/**
 * rbdi_getgeo() - get an rbdi disk geometry
 * @bdev:	block device
 * @geo:	geometry struct
 *
 * Provide the disks's geometry. We do 64 heads 32 sectors/track.
 *
 * Return: 0 upon success or negative errno upon failure.
 */
static int rbdi_getgeo(struct block_device *bdev, struct hd_geometry *geo)
{
	struct target_ctx *t = bdev->bd_disk->private_data;
	sector_t capacity = t->sectors * t->sec_size / 512;

	geo->heads = 1 << 6;
	geo->sectors = 1 << 5;
	sector_div(capacity, (geo->heads * geo->sectors));
	geo->cylinders = capacity;
	geo->start = t->start_sec;
	return 0;
}

/**
 * rbdi_request() - blk request function
 * @q:		our blk request queue
 *
 * Drain the blk request queue calling rbdi_start_request() for
 * each new request.  Ignore non FS type requests.
 */
static void rbdi_request(struct request_queue *q)
{
	struct request *req;
	int ret;

	while ((req = blk_fetch_request(q)) != NULL) {
		struct target_ctx *t = req->rq_disk->private_data;

		t->req_cnt++;
		if (t->req_cnt > t->stats.max_outstanding_reqs)
			t->stats.max_outstanding_reqs = t->req_cnt;
		if (req->cmd_type != REQ_TYPE_FS) {
			pr_info(PFX "dropping req type %d\n",
				(int)req->cmd_type);
			end_request(t, req, 0);
			continue;
		}
		ret = rbdi_start_request(req);
		if (ret) {
			end_request(t, req, ret);
		}
	}
}

static struct block_device_operations rbdi_fops =
{
	.owner = THIS_MODULE,
	.open = rbdi_open,
	.release = rbdi_close,
	.getgeo = rbdi_getgeo,
};

/**
 * arm_cqs_and_wait() - arm the CQs and block until an event occurs
 * @p:		poll thread context
 * @targets:	list of targets
 *
 * Arm the CQs and then block awaiting a new CQ event.  Also unblock
 * if our kthread has been stopped.
 */
static void arm_cqs_and_wait(struct poll_thread_ctx *p,
			     struct list_head *targets)
{
	struct target_ctx *t, *tmp;

	list_for_each_entry_safe(t, tmp, targets, poll_thread_entry) {
		DBG(PFX "%s arming cqs target %p\n", __func__, t);

		spin_lock_irq(&p->lock);
		list_del_init(&t->poll_thread_entry);

		if (!test_bit(DELETING_TARGET_BIT, &t->event_state)) {
			ib_req_notify_cq(t->rcq, IB_CQ_NEXT_COMP);
			ib_req_notify_cq(t->scq, IB_CQ_NEXT_COMP);
		}
		spin_unlock_irq(&p->lock);

		drain_cqs(t);
		t->stats.cq_waits++;

		spin_lock_irq(&p->lock);
		/* Reset the POLL_ACTIVE flag as we finshed processing all CQEs
		 * of this target
		 */
		if (list_empty(&t->poll_thread_entry))
			clear_bit(POLL_ACTIVE_BIT, &t->event_state);
		spin_unlock_irq(&p->lock);

	}
	wait_event_interruptible(p->wait, !list_empty(&p->poll_targets) ||
					  kthread_should_stop());
}

/**
 * poll_targets() - drain the cqs for all targets in our pool group
 * @p:		poll thread context
 * @targets:	list of targets to poll/drain.
 *
 * With the poll_thread_ctx lock held and IRQs disbaled, drain the CQs
 * for all targets in list @targets.
 */
static void poll_targets(struct poll_thread_ctx *p, struct list_head *targets)
{
	struct target_ctx *t;

	list_for_each_entry(t, targets, poll_thread_entry)
		drain_cqs(t);
}

/**
 * poll_thread_func() - kthread function to poll the cqs
 * @data:	pointer to the poll thread context
 *
 * Run until stopped polling and processing CQEs for all
 * targets that are posted to the poll thread context.  If we
 * iterate for more the @poll_period_ns nanoseconds, then arm the CQS
 * and block until a new CQ event happens.
 *
 * Return: 0 upon success or negative errno upon failure.
 */
static int poll_thread_func(void *data)
{
	struct poll_thread_ctx *p = data;
	struct timespec sleep, now, delta;
	LIST_HEAD(targets);

	DBG(PFX "%s running for cpu %u\n", __func__, p->cpu);

	set_user_nice(current, -20);
	getnstimeofday(&sleep);
	while (!kthread_should_stop()) {

		/* 
		 * If any new targets are posted by the 
		 * event handler functions, splice them
		 * into our poll group.
		 */
		if (!list_empty(&p->poll_targets)) {
			spin_lock_irq(&p->lock);
			list_splice_tail_init(&p->poll_targets, &targets);
			spin_unlock_irq(&p->lock);
		}

		poll_targets(p, &targets);

		getnstimeofday(&now);
		delta = timespec_sub(now, sleep);
		if (timespec_to_ns(&delta) >= poll_period_ns) {
			arm_cqs_and_wait(p, &targets);
			BUG_ON(!list_empty(&targets));
			getnstimeofday(&sleep);
		}
	}
	DBG(PFX "%s cpu %u exiting!\n", __func__, p->cpu);
	return 0;
}

/**
 * init_target_ctx() - initialize the target device with the blk layer
 * @t:		target context
 *
 * Allocate a blk queue and disk for this target and register it with
 * the blk layer as an available blk device.
 *
 * Return: 0 upon success or negative errno upon failure.
 */
static int init_target_ctx(struct target_ctx *t)
{
	u64 segment_size;
	int ret;

	ret = connect_to_target(t);
	if (ret)
		goto err;

	t->rq = blk_init_queue(rbdi_request, &t->lock);
	if (t->rq == NULL) {
		pr_info(PFX "blk_init_queue failure\n");
		ret = -ENOMEM;
		goto err_target;
	}

	t->disk = alloc_disk(RBDI_MINOR_CNT);
	if (!t->disk) {
		pr_info(PFX "alloc_disk failure\n");
		ret = -ENOMEM;
		goto err_blkq;
	}

	/* set io sizes to max IO size per SDP request */
	segment_size = t->max_io_size;
	DBG(PFX "%s segment_size %llu max_hw_sectors %llu\n",
		__func__, segment_size, segment_size >> 9);
		
	blk_queue_physical_block_size(t->rq, t->sec_size);
	blk_queue_logical_block_size(t->rq, t->sec_size);

	/* blk_queue_max_hw_sectors takes 512B sectors! */
	blk_queue_max_hw_sectors(t->rq, segment_size >> 9);
	blk_queue_max_segment_size(t->rq, segment_size);
	blk_queue_io_min(t->rq, t->sec_size);
	blk_queue_io_opt(t->rq, segment_size);
	blk_queue_max_segments(t->rq, RBDP_MAX_FR_DEPTH);
	t->rq->nr_requests = RBDP_MAX_REQUESTS << 2;
	blk_queue_bounce_limit(t->rq, BLK_BOUNCE_ANY);

	queue_flag_set_unlocked(QUEUE_FLAG_NOMERGES, t->rq);
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, t->rq);
	queue_flag_clear_unlocked(QUEUE_FLAG_ADD_RANDOM, t->rq);

	t->disk->major = rbdi_major;
	t->disk->first_minor = -1;

	ret = ida_simple_get(&rbdi_minors, 0, RBDI_MAX_DISKS, GFP_KERNEL);
	if (ret < 0)
		goto err_disk;
	t->disk->first_minor = ret;
	t->disk->fops = &rbdi_fops;
	t->disk->private_data = t;
	t->disk->queue = t->rq;
	t->disk->flags |= GENHD_FL_NO_PART_SCAN |
			  GENHD_FL_EXT_DEVT;
	sprintf(t->disk->disk_name, "%s%u", RBDI_NAME, t->disk->first_minor);

	/* set_capacity takes 512B sectors! */
	set_capacity(t->disk, t->sectors * t->sec_size / 512);
	add_disk(t->disk);

	pr_info(PFX "initialized /dev/%s (%llu sectors; %llu bytes)\n",
		t->disk->disk_name, t->sectors, t->sectors * t->sec_size);

	if (debugfs_root) {
		t->debugfs_root = debugfs_create_dir(t->disk->disk_name,
						     debugfs_root);
		if (t->debugfs_root)
			setup_target_debugfs(t);
	}

	mutex_lock(&target_mutex);
	list_add_tail(&t->target_list_entry, &target_list);
	mutex_unlock(&target_mutex);

	return 0;
err_disk:
	put_disk(t->disk);
	t->disk = NULL;
err_blkq:
	blk_cleanup_queue(t->rq);
	t->rq = NULL;
err_target:
	destroy_target(t);
err:
	return ret;
}

/**
 * create_thread_pool() - create pool of poller threads
 *
 * Create and initialize the poll thread contexts for the
 * thread pool, and then kthread_run() all the threads.
 * The amount of threads is determine by module parameter
 * poll_thread_count.  If it is 0, then use num_online_cpus().
 *
 * Return: 0 upon success, or negative errno on failure.
 */
static int create_thread_pool(void)
{
	int ret = 0;
	int i;

	if (!poll_thread_count)
		poll_thread_count = num_online_cpus();

	DBG(PFX "allocating %d poll threads\n", poll_thread_count);
	poll_threads = kzalloc(poll_thread_count * sizeof *poll_threads,
			       GFP_KERNEL);
	if (!poll_threads) {
		ret = -ENOMEM;
		goto err;
	}

	for (i = 0; i < poll_thread_count; i++) {
		struct poll_thread_ctx *p = &poll_threads[i];

		p->poll_thread = kthread_run(poll_thread_func, p, "rbdi-%d", i);
		if (IS_ERR(p->poll_thread)) {
			ret = PTR_ERR(p->poll_thread);
			pr_info(PFX "Error starting kthreads %d\n", ret);
			goto err_kzalloc;
		}
		p->cpu = i;
		spin_lock_init(&p->lock);
		init_waitqueue_head(&p->wait);
		INIT_LIST_HEAD(&p->poll_targets);
	}
	return 0;
err_kzalloc:
	kfree(poll_threads);
err:
	return ret;
}

/**
 * destroy_thread_pool() - stop and destroy all poller threads
 *
 */
static void destroy_thread_pool(void)
{
	int i;

	DBG(PFX "destroying thread pool\n");
	for (i = 0; i < poll_thread_count; i++)
		if (poll_threads[i].poll_thread)
			kthread_stop(poll_threads[i].poll_thread);
	kfree(poll_threads);
}

/**
 * rbdi_init() - module init function
 *
 * create our debugfs cruft, our workq thead for handling new target adds,
 * and register as a block device.
 *
 * Return: 0 upon success or negative errno upon failure.
 */
static int __init rbdi_init(void)
{
	struct dentry *de;
	int ret = 0;

	cq_weights[SCQ_INDEX] = scq_weight;
	cq_weights[RCQ_INDEX] = rcq_weight;

	debugfs_root = debugfs_create_dir(RBDI_NAME, NULL);
	if (!debugfs_root) {
		pr_warn(PFX "could not create debugfs entry\n");
		ret = -ENOMEM;
		goto err;
	}
	PINIT(debugfs_root);
	de = debugfs_create_file("devices", S_IWUSR, debugfs_root,
				 NULL, &tgt_debugfs_fops);
	if (!de) {
		ret = -ENOMEM;
		goto err;
	}
	workq = create_singlethread_workqueue("rbdi_wq");
	if (!workq) {
		ret = -ENOMEM;
		goto err;
	}

	ret = create_thread_pool();
	if (ret)
		goto err;
	rbdi_major = register_blkdev(0, RBDI_NAME);
	if (rbdi_major <= 0) {
		pr_info(PFX "Unable to get Major Number\n");
		ret = -EBUSY;
		goto err_threadpool;
	}
	ret = rbdi_dev_init();
	if (ret)
		goto err_blkdev;
	return 0;

err_blkdev:
	unregister_blkdev(rbdi_major, RBDI_NAME);
err_threadpool:
	destroy_thread_pool();
err:
	debugfs_remove_recursive(debugfs_root);
	return ret;
}

/**
 * rbdi_cleanup() - module remove function
 *
 * destroy any targets, unregister us as a block deivce, and cleanup
 */
static void __exit rbdi_cleanup(void)
{
	struct target_ctx *t, *tmp;
	int ret = 0;

	mutex_lock(&target_mutex);
	list_for_each_entry_safe(t, tmp, &target_list, target_list_entry)
		ret |= destroy_target(t);
	mutex_unlock(&target_mutex);

	unregister_blkdev(rbdi_major, RBDI_NAME);
	debugfs_remove_recursive(debugfs_root);
	ida_destroy(&rbdi_minors);
	destroy_workqueue(workq);
	destroy_thread_pool();
	rbdi_dev_cleanup();
	DBG(PFX "Unloading\n");
}

module_init(rbdi_init);
module_exit(rbdi_cleanup);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Steve Wise <swise@chelsio.com>");
MODULE_DESCRIPTION("RDMA Block Device Initiator");
MODULE_ALIAS_BLOCKDEV_MAJOR(rbdi_major);
