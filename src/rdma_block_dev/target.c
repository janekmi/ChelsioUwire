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
#include <linux/module.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/inet.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/bio.h>
#include <linux/fs.h>
#include <linux/workqueue.h>
#include <linux/blkdev.h>
#include <linux/genhd.h>
#include <linux/debugfs.h>
#include <linux/hdreg.h>

#include <rdma/rdma_cm.h>
#include <rdma/ib_verbs.h>

#define RBDT_NAME "rbdt"
#define PFX "rbdt: "

#include "proto.h"
#include "common.h"

static int debug = 0;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "Debug level (0=none, 1=all)");

static int use_immd = 1;
module_param(use_immd, int, 0644);
MODULE_PARM_DESC(use_immd, "Use immediate mode for small IO (default 1)");

static int initiator_depth = RBDP_MAX_READ_DEPTH;
module_param(initiator_depth, int, 0644);
MODULE_PARM_DESC(initiator_depth, "Default read initiator depth (default 32)");

struct rdma_cm_id *listen_cm_id;

static char *listen_ipaddr = "0.0.0.0";
module_param(listen_ipaddr, charp, 0644);
MODULE_PARM_DESC(dev, "Default listen ip address (default 0.0.0.0)");

static int listen_port = 65000;
module_param(listen_port, int, 0644);
MODULE_PARM_DESC(listen_port, "Default listen port (default 65000)");

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

static int null_backend = 0;
module_param(null_backend, int, 0644);
MODULE_PARM_DESC(null_backend, "Null backend blk device (default 0)");

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

static LIST_HEAD(target_list);
static DEFINE_MUTEX(target_mutex);

static struct workqueue_struct *cm_workq;

enum target_state {
	INIT,
	CONNECTED,
	ERROR
};

static char *state_str[] = {
	"INIT",
	"CONNECTED",
	"ERROR",
};

struct req_ctx;

/**
 * struct wr_ring - send and recv work request ring struct.
 */
struct wr_ring {
	void *va;
	dma_addr_t dma_addr;
	struct ib_sge sge;
	union {
		struct ib_send_wr swr;
		struct ib_recv_wr rwr;
	} u;
};

struct target_ctx;

/**
 * struct req_ctx - holds all state for an in-progress RBDP request
 */
struct req_ctx {
	struct target_ctx *t;
	u32 xid;
	u32 cmd;
	u32 flags;
	u32 num_sge;
	u32 start_sector;
	u32 tot_len;
	u64 to;
	u32 stag;
	struct bio *bio;
	struct work_struct work;
	int bio_err;
	int bio_complete;
	int read_complete;
	struct page *pages[RBDP_MAX_FR_DEPTH];
	struct ib_fast_reg_page_list *frpl;
	struct ib_mr *frmr;
	int frmr_valid;
	struct list_head rctx_free_entry;
	struct list_head rctx_bio_entry;
	struct list_head rctx_pending_entry;
};

/**
 * struct target_stats - per-target statistics viewable via debugfs
 */
struct target_stats {
	unsigned long long reqs_started;
	unsigned long long reqs_completed;
	unsigned long long immd_writes;
	unsigned long long immd_reads;
	unsigned long long stall_sq_full;
	unsigned long long stall_ordq_full;
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
	char device[RBDP_DEVLEN];
	u16 port;
	enum target_state state;
	unsigned long event_state;
	int ret;
	struct rdma_cm_id *cm_id;
	struct ib_pd *pd;
	struct ib_cq *rcq;
	struct ib_cq *scq;
	int rqdepth;
	int sqdepth;
	struct task_struct *thread;
	struct wr_ring *sring;
	int snext;
	int scnt;
	int read_cnt;
	int initiator_depth;
	struct wr_ring *rring;
	int rnext;
	int rcnt;
	struct ib_mr dma_mr;
	struct block_device *bdev;
	struct list_head free_req_ctxs;
	struct list_head pending_req_ctxs;
	struct list_head pending_read_req_ctxs;
	struct req_ctx *req_ctx_mem;
	spinlock_t lock;
	int outstanding_req_cnt;
	struct target_stats stats;
	struct dentry *debugfs_root;
	struct list_head target_list_entry;
	struct work_struct work;
	struct poll_thread_ctx *my_thread_ctx;
	struct list_head poll_thread_entry;
	wait_queue_head_t wait;
	int cq_index;
	unsigned int bios;
};

static struct dentry *debugfs_root;

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
	seq_printf(seq, "stall_sq_full %llu\n", t->stats.stall_sq_full);
	seq_printf(seq, "stall_ordq_full %llu\n", t->stats.stall_ordq_full);
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

/**
 * stats_clear() - clear the per-target stats via this debugfs file
 *
 * Writing 0 to the stats debugfs file zeros all the stats.
 */
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
	.read 	 = seq_read,
	.llseek  = seq_lseek,
	.write   = stats_clear,
};

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
		seq_printf(seq, "local %s %pI4:%u remote %pI4:%u state %s\n",
			t->device,
			&SINP(&t->cm_id->route.addr.src_addr)->sin_addr,
			ntohs(SINP(&t->cm_id->route.addr.src_addr)->sin_port),
			&SINP(&t->cm_id->route.addr.dst_addr)->sin_addr,
			ntohs(SINP(&t->cm_id->route.addr.dst_addr)->sin_port),
			state_str[t->state]);
	mutex_unlock(&target_mutex);
	return 0;
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
 * setup_debugfs() - setup the target-specific debugfs files
 * @t:		target context
 *
 * Create debugfs files that are target-specific.  Currently
 * only the "stats" file to dump target stats.
 */
static void setup_debugfs(struct target_ctx *t)
{
	struct dentry *de;

	de = debugfs_create_file("stats", S_IWUSR, t->debugfs_root,
				 (void *)t, &stats_debugfs_fops);
}

/**
 * unmap_and_free_fr_pages() - release the pages for a fastreg page list
 * @t:		target context
 * @rctx:	request context contining the fastreg pages to unmap/free
 */
static void unmap_and_free_fr_pages(struct target_ctx *t, struct req_ctx *rctx)
{
	int i;

	for (i = 0; i < RBDP_MAX_FR_DEPTH; i++) {
		if (rctx->pages[i]) {
			ib_dma_unmap_page(t->cm_id->device,
					  rctx->frpl->page_list[i],
					  PAGE_SIZE, DMA_BIDIRECTIONAL);
			__free_page(rctx->pages[i]);
		}
	}
}

/**
 * alloc_and_map_fr_pages() - allocate and map pages for a fastreg page list
 * @t:		target context
 * @rctx:	request context to hold the fastreg page list
 *
 * Setup the fastreg page list for this @rctx.
 *
 * Return: 0 upon success or negative errno upon failure.
 */
static int alloc_and_map_fr_pages(struct target_ctx *t, struct req_ctx *rctx)
{
	int i;
	int ret = 0;
	dma_addr_t dma_addr;

	for (i = 0; i < RBDP_MAX_FR_DEPTH; i++) {
		rctx->pages[i] = alloc_page(GFP_KERNEL);
		if (!rctx->pages[i]) {
			pr_err(PFX "alloc_page failed!\n");
			break;
		}
		dma_addr = ib_dma_map_page(t->cm_id->device,
					   rctx->pages[i], 0, PAGE_SIZE,
					   DMA_BIDIRECTIONAL);
		ret = ib_dma_mapping_error(t->cm_id->device, dma_addr);
		if (ret) {
			__free_page(rctx->pages[i]);
			rctx->pages[i] = 0;
			pr_err(PFX "dma_mapping error %d\n", ret);
			break;
		}
		rctx->frpl->page_list[i] = dma_addr;
	}
	if (ret)
		goto err;
	return 0;
err:
	while (i--) {
		if (rctx->pages[i]) {
			ib_dma_unmap_page(t->cm_id->device,
					  rctx->frpl->page_list[i], PAGE_SIZE,
					  DMA_BIDIRECTIONAL);
			__free_page(rctx->pages[i]);
		}
	}
	return ret;
}

/**
 * dealloc_req_ctxs() - deallocate all request contexts for a target
 * @t: 		target context
 *
 * Free up the frmr, fast_reg page list, and pages assocated with @t.
 */
static void dealloc_req_ctxs(struct target_ctx *t)
{
	int i;
	struct req_ctx *rctx = t->req_ctx_mem;

	for (i = 0; i < RBDP_MAX_REQUESTS; i++) {
		list_del_init(&rctx->rctx_free_entry);
		ib_dereg_mr(rctx->frmr);
		unmap_and_free_fr_pages(t, rctx);
		ib_free_fast_reg_page_list(rctx->frpl);
		bio_put(rctx->bio);
		rctx++;
	}
	kfree(t->req_ctx_mem);
}


/**
 * alloc_req_ctxs() - allocate request contexts for this target context
 * @t:		target context
 *
 * Allocate and initialize all request context resources for @t.
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
	for (i = 0; i < RBDP_MAX_REQUESTS; i++) {
		rctx->t = t;
		INIT_LIST_HEAD(&rctx->rctx_free_entry);
		INIT_LIST_HEAD(&rctx->rctx_bio_entry);
		INIT_LIST_HEAD(&rctx->rctx_pending_entry);
		rctx->bio = bio_kmalloc(GFP_KERNEL, RBDP_MAX_FR_DEPTH);
		if (!rctx->bio) {
			ret = -ENOMEM;
			goto err;
		}

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

		ret = alloc_and_map_fr_pages(t, rctx);
		if (ret)
			goto err;

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
		unmap_and_free_fr_pages(t, rctx);
		bio_put(rctx->bio);
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

	ret = ib_post_recv(t->cm_id->qp, &t->rring[t->rnext].u.rwr, &bad_wr);
	if (!ret) {
		t->rcnt++;
		t->rnext++;
		if (t->rnext == t->rqdepth)
			t->rnext = 0;
	}
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

	ret = ib_post_send(t->cm_id->qp, &t->sring[t->snext].u.swr, &bad_wr);
	if (!ret) {
		t->scnt++;
		t->snext++;
		if (t->snext == t->sqdepth)
			t->snext = 0;
	}
	return ret;
}

/**
 * map_buf() - map a buffer for dma
 * @t:		target context
 * @wrr:	the send or recv work request ring entry
 *
 * Map @wrr->va for dma and store the dma address in @wrr->dma_addr.
 *
 * Return: 0 upon success or negative errno upon failure.
 */
static int map_buf(struct target_ctx *t, struct wr_ring *wrr)
{
	int ret;

	wrr->dma_addr = ib_dma_map_single(t->cm_id->device, wrr->va,
					  RBDP_BUFSZ, DMA_BIDIRECTIONAL);
	ret = ib_dma_mapping_error(t->cm_id->device, wrr->sge.addr);
	if (ret)
		pr_err(PFX "dma_mapping error %d\n", ret);
	return ret;
}

/**
 * unmap_buf() - unmap a dma-mapped buffer
 * @t:		target context
 * @wrr:	the send or recv work request ring entry
 */
static void unmap_buf(struct target_ctx *t, struct wr_ring *wrr)
{
	if (!ib_dma_mapping_error(t->cm_id->device, wrr->sge.addr))
		ib_dma_unmap_single(t->cm_id->device, wrr->sge.addr, RBDP_BUFSZ,
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
			unmap_buf(t, &t->sring[i]);
			kfree(t->sring[i].va);
		}
	}
	for (i = 0; i < t->rqdepth; i++) {
		if (t->rring[i].va) {
			unmap_buf(t, &t->rring[i]);
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

	t->sring = kzalloc((t->sqdepth + t->rqdepth) * sizeof *t->sring,
			   GFP_KERNEL);
	if (!t->sring) {
		ret = -ENOMEM;
		goto err;
	}
	t->rring = t->sring + t->sqdepth;

	for (i = 0; i < t->sqdepth; i++) {
		t->sring[i].va = kmalloc(RBDP_BUFSZ, GFP_KERNEL);
		if (!t->sring[i].va) {
			ret = -ENOMEM;
			goto err_ring;
		}
		ret = map_buf(t, &t->sring[i]);
		if (ret)
			goto err_ring;
		memset(t->sring[i].va, 0xaa, RBDP_BUFSZ);
		t->sring[i].u.swr.sg_list = &t->sring[i].sge;
		t->sring[i].u.swr.num_sge = 1;
	}

	for (; j < t->rqdepth; j++) {
		t->rring[j].va = kmalloc(RBDP_BUFSZ, GFP_KERNEL);
		if (!t->rring[j].va) {
			ret = -ENOMEM;
			goto err_ring;
		}
		memset(t->rring[j].va, 0xbb, RBDP_BUFSZ);
		ret = map_buf(t, &t->rring[j]);
		if (ret)
			goto err_ring;
		t->rring[j].sge.addr = t->rring[j].dma_addr;
		t->rring[j].sge.lkey = t->cm_id->device->local_dma_lkey;
		t->rring[j].sge.length = RBDP_BUFSZ;
		t->rring[j].u.rwr.wr_id = j;
		t->rring[j].u.rwr.sg_list = &t->rring[j].sge;
		t->rring[j].u.rwr.num_sge = 1;
		ret = post_recv(t);
		if (ret)
			goto err;
	}
	return 0;
err_ring:
	while (i--) {
		unmap_buf(t, &t->sring[i]);
		kfree(t->sring[i].va);
		t->sring[i].va = NULL;
	}
	while (j--) {
		unmap_buf(t, &t->rring[j]);
		kfree(t->rring[j].va);
		t->rring[j].va = NULL;
	}
	kfree(t->sring);
err:
	return ret;
}

/**
 * send_reply() - send an RBDP reply to the initiator completing the request
 * @rctx:	request context
 * @status: 	request status (a negative errno)
 *
 * Build an RDBP reply from the next available send ring entry and send
 * the reply.  Post the recv associated with this outstanding request. Update
 * accounting info.
 */
static void send_reply(struct req_ctx *rctx, int status)
{
	struct target_ctx *t = rctx->t;
	struct rbdp_reply *rbdp_rep = t->sring[t->snext].va;
	struct ib_send_wr *wr = &t->sring[t->snext].u.swr;

	PENTER(TGT_REPLY);
	rbdp_rep->xid = rctx->xid;
	rbdp_rep->flags = 0;
	rbdp_rep->status = htonl(status);

	wr->opcode = IB_WR_SEND;
	wr->sg_list[0].addr = (u64)(uintptr_t)rbdp_rep;
	wr->sg_list[0].length = sizeof *rbdp_rep;
	wr->send_flags = IB_SEND_SIGNALED | IB_SEND_INLINE;
	wr->wr_id = 0;
	DBG(PFX "%s xid %x status %d\n", __func__, rctx->xid, status);

	post_recv(t);
	post_send(t);

	BUG_ON(t->outstanding_req_cnt == 0);
	t->outstanding_req_cnt--;
	t->stats.reqs_completed++;
	list_add_tail(&rctx->rctx_free_entry, &t->free_req_ctxs);
	PEXIT(TGT_REPLY);
}

/**
 * copy_bio_to_reply() - copy completed biosegments into the RDBP reply msg
 * @rctx:	request context
 * @rdbp_rep:	RDBP reply message
 *
 * For immediate replies, we copy the bio segments directly into the RDBP
 * reply message vs RDMA writing that data.
 */
static void copy_bio_to_reply(struct req_ctx *rctx, struct rbdp_reply *rbdp_rep)
{
	u8 *srcp, *dstp;
	int tot_len;
	int i;

	srcp = (u8 *)(page_address(rctx->pages[0]));
	dstp = (u8 *)(rbdp_rep + 1);
	tot_len = rctx->tot_len;
	i = 0;

	while (tot_len) {
		u32 size = min_t(u32, tot_len, PAGE_SIZE);

		DBG(PFX "%s i %d dstp %p srcp %p size %d\n", __func__,
		    i, dstp, srcp, size);
		memcpy(dstp, srcp, size);
		tot_len -= size;
		dstp += size;
		srcp += size;
		if (tot_len) {
			i++;
			dstp = page_address(rctx->pages[i]);
		}
	}
}

/**
 * send_immd_read_repl() - send RDBP read reply with immediate data
 * @rctx:	request context
 *
 * For smaller read requests, we provide the read response data directly
 * in the RDBP reply message.  This avoids the latency overhead of RDMA
 * Writing the read response data at the overead of a CPU copy.
 */
static void send_immd_read_repl(struct req_ctx *rctx)
{
	struct target_ctx *t = rctx->t;
	struct rbdp_reply *rbdp_rep = t->sring[t->snext].va;
	struct ib_send_wr *wr = &t->sring[t->snext].u.swr;

	rbdp_rep->xid = rctx->xid;
	rbdp_rep->flags = htonl(RBDP_IMMD);
	rbdp_rep->status = htonl(rctx->bio_err);

	wr->opcode = IB_WR_SEND;
	wr->sg_list[0].lkey = t->cm_id->device->local_dma_lkey;
	wr->sg_list[0].addr = t->sring[t->snext].dma_addr;
	wr->sg_list[0].length = sizeof *rbdp_rep + rctx->tot_len;
	wr->send_flags = IB_SEND_SIGNALED;
	wr->wr_id = 0;

	t->stats.immd_reads++;
	copy_bio_to_reply(rctx, rbdp_rep);
	DBG(PFX "%s xid %x status %d\n", __func__, rctx->xid, rctx->bio_err);

	post_recv(t);
	post_send(t);

	BUG_ON(t->outstanding_req_cnt == 0);
	t->outstanding_req_cnt--;
	t->stats.reqs_completed++;
	list_add_tail(&rctx->rctx_free_entry, &t->free_req_ctxs);
}

/**
 * send_rdma_write() - send an RDMA Write with RBDP read response data
 * @rctx:	request context
 *
 * Build and post the RDMA Write with the next available send ring entry.
 */
static void send_rdma_write(struct req_ctx *rctx)
{
	struct target_ctx *t = rctx->t;
	struct ib_send_wr *wr;

	PENTER(TGT_WRITE);
	BUG_ON(!rctx);

	DBG(PFX "%s rctx %p xid %x\n", __func__, rctx, rctx->xid);

	/* build RDMA WR */
	wr = &t->sring[t->snext].u.swr;
	wr->wr.rdma.rkey = rctx->stag;
	wr->wr.rdma.remote_addr = rctx->to;
	wr->sg_list[0].lkey = rctx->frmr->lkey;
	wr->sg_list[0].addr = 0;
	wr->sg_list[0].length = rctx->tot_len;
	wr->send_flags = IB_SEND_SIGNALED;
	wr->opcode = IB_WR_RDMA_WRITE;
	wr->wr_id = (u64)(uintptr_t)rctx;

	/* Post RDMA WR */
	post_send(t);
	PEXIT(TGT_WRITE);
	return;
}

/**
 * dma_sync_for_cpu() - sync the memory for cpu access
 * @rctx:	request context to sync
 *
 * Sync all the fastreg pages after dma for cpu access
 */
static void dma_sync_for_cpu(struct req_ctx *rctx)
{
	u32 tot_len = rctx->tot_len;
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
	u32 tot_len = rctx->tot_len;
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
 * resume_bio() - resume a bio operation
 * @rctx:	request context
 *
 * This is called to complete or resume a bio operation.  For RBDP READ
 * operations, this sends the RDMA Write after the bio operation fetched
 * the read data.  For RBDP WRITE operations, this sends the RBDP reply
 * since the bio operation has completed writing the data to the blkdev.
 */
static void resume_bio(struct req_ctx *rctx)
{
	if (rctx->cmd == RBDP_CMD_READ) {
		if (rctx->tot_len <= RBDP_MAX_IMMD && use_immd) {
			send_immd_read_repl(rctx);
		} else {
			dma_sync_for_dev(rctx);
			send_rdma_write(rctx);
			send_reply(rctx, 0);
		}
	} else
		send_reply(rctx, rctx->bio_err);
	BUG_ON(rctx->t->bios == 0);
	rctx->t->bios--;
}

/**
 * bio_complete() - handle a bio completion upcall
 * @b:		bio structure
 * @err:	completion status (negative errno
 *
 * This is called by the BIO layer when a submit_bio() operation completes.
 * Save the error status and mark @bio as completed, and attempt to
 * further process this RBDP request.  If we are flow controlled, then add
 * @rctx to the pending list to process later once the SQ is not full.
 */
static void bio_complete(struct bio *b, int err)
{
	struct req_ctx *rctx = b->bi_private;
	unsigned long flags;

	DBG(PFX "%s rctx %p err %d\n", __func__, rctx, err);
	if (err)
		pr_err(PFX "bio error %d\n", err);

	rctx->bio_err = err;
	rctx->bio_complete = 1;

	spin_lock_irqsave(&rctx->t->lock, flags);
	BUG_ON(rctx->t->scnt > rctx->t->sqdepth);
	if (rctx->t->scnt <= (rctx->t->sqdepth - 2))
		resume_bio(rctx);
	else {
		BUG_ON(rctx->t->bios == 0);
		rctx->t->bios--;
		DBG(PFX "%s SQ full, deferring rctx %p.\n", __func__, rctx);
		rctx->t->stats.stall_sq_full++;
		list_add_tail(&rctx->rctx_pending_entry,
			      &rctx->t->pending_req_ctxs);
	}
	spin_unlock_irqrestore(&rctx->t->lock, flags);
}

/**
 * start_bio() - submit a BIO operation to the backend block device
 * @rctx:	request context
 *
 * Initiate block IO to the backend block device.  The fastreg pages
 * associated with this request are added to the bio and submitted to the BIO
 * layer via submit_bio(). Function bio_complete() is called by the BIO layer
 * once the IO completes.  We need to release the lock around the submit_bio()
 * call.  This should be ok since we're not touching target_ctx state.
 */
static void start_bio(struct req_ctx *rctx)
{
	u32 tot_len = rctx->tot_len;
	int ret = 0;
	int i;

	/* set various bio fields */
	bio_reset(rctx->bio);
	rctx->bio->BI_SECTOR = rctx->start_sector;
	rctx->bio->bi_bdev = rctx->t->bdev;
	rctx->bio->bi_end_io = bio_complete;
	rctx->bio->bi_private = rctx;

	/* add pages/offsets/lengths via bio_add_page() */
	i = 0;
	while (tot_len) {
		u32 size = min_t(u32, tot_len, PAGE_SIZE);

		DBG(PFX "%s rctx %p add page %p size %d\n", __func__, rctx,
			rctx->pages[i], size);
		ret = bio_add_page(rctx->bio, rctx->pages[i], size, 0);
		if (ret <= 0) {
			pr_err(PFX "%s bio_add_page error rctx %p "
			       "tot_len %d i %d bio %p\n", __func__, rctx,
			       tot_len, i, rctx->bio);
			goto err;
		}
		tot_len -= size;
		i++;
	}

	DBG(PFX "%s bio %p max_vecs %u bi_vcnt %u bi_sector %u "
		"bi_size %u\n", __func__, rctx->bio, rctx->bio->bi_max_vecs,
		rctx->bio->bi_vcnt, (unsigned)rctx->bio->BI_SECTOR,
		rctx->bio->BI_SIZE);

	rctx->t->bios++;
	spin_unlock_irq(&rctx->t->lock);
	if (unlikely(null_backend))
		bio_complete(rctx->bio, 0);
	else
		submit_bio(rctx->cmd == RBDP_CMD_READ ? READ : WRITE,
			   rctx->bio);
	spin_lock_irq(&rctx->t->lock);
	return;
err:
	rdma_disconnect(rctx->t->cm_id);
	PEXIT(TGT_BACKEND);
	return;
}

/**
 * process_scqe() - process a SQ completion
 * @t: 		target context
 * @wc:		RDMA completion structure
 *
 * Based on @wc->opcode, we either queue the request for backend BIO
 * processing (for an RBDP Write), or send a RBDP reply back to the
 * initiator completing * the RBDP request (for an RBDP READ).
 */
static void process_scqe(struct target_ctx *t, struct ib_wc *wc)
{
	struct req_ctx *rctx = (struct req_ctx *)(uintptr_t)wc->wr_id;

	if (wc->status) {
		pr_err(PFX "send opcode %u completion in error %d\n",
			wc->opcode, wc->status);
		return;
	}

	switch (wc->opcode) {
	case IB_WC_SEND:
		BUG_ON(rctx);
		break;
	case IB_WC_FAST_REG_MR:
		BUG_ON(rctx);
		break;
	case IB_WC_RDMA_READ:
		BUG_ON(!rctx);
		dma_sync_for_cpu(rctx);
		rctx->read_complete = 1;
		BUG_ON(rctx->t->read_cnt == 0);
		rctx->t->read_cnt--;
		start_bio(rctx);
		break;
	case IB_WC_RDMA_WRITE:
		BUG_ON(!rctx);
		break;
	default:
		BUG_ON(1);
	}
}

/**
 * register_frmr() - register the request frmr
 * @rctx:	request context
 *
 * Register the FRMR for @rctx.  This is done only once before using
 * this request structure.  So the FRMR for each request context is left
 * registered for the life of the connection.
 *
 * Return: 0 upon success or negative errno upon failure.
 */
static int register_frmr(struct req_ctx *rctx)
{
	struct target_ctx *t = rctx->t;
	struct ib_send_wr *wr;

	BUG_ON(!rctx);

	DBG(PFX "%s page_list_len %ld page_list[0] %llx", __func__,
	    RBDP_MAX_FR_DEPTH, rctx->frpl->page_list[0]);


	wr = &t->sring[t->snext].u.swr;
	wr->opcode = IB_WR_FAST_REG_MR;
	wr->send_flags = IB_SEND_SIGNALED;
	wr->wr.fast_reg.page_shift = PAGE_SHIFT;
	wr->wr.fast_reg.length = RBDP_MAX_IO_SIZE;
	wr->wr.fast_reg.page_list = rctx->frpl;
	wr->wr.fast_reg.page_list_len = RBDP_MAX_FR_DEPTH;
	wr->wr.fast_reg.rkey = rctx->frmr->rkey;
	wr->wr.fast_reg.iova_start = 0;
	wr->wr.fast_reg.access_flags = IB_ACCESS_REMOTE_READ |
				       IB_ACCESS_REMOTE_WRITE |
				       IB_ACCESS_LOCAL_WRITE;
	wr->wr_id = 0;
	rctx->frmr_valid = 1;

	return post_send(t);
}

/**
 * send_rdma_read() - send an rdma read
 * @rctx: 	request context
 *
 * Send an rdma read into the fastreg mr using the next available
 * work request ring entry.  This moves data for a RBDP write from the
 * initiator memory to the @rctx frmr.  Once the read is complete,
 * a BIO operation is done to push the data to the backend block device.
 * See process_scqe(), start_bio() for the backend logc.
 */
static int send_rdma_read(struct req_ctx *rctx)
{
	struct target_ctx *t = rctx->t;
	struct ib_send_wr *wr;
	int ret;

	BUG_ON(!rctx);

	DBG(PFX "%s rctx %p xid %x\n", __func__, rctx, rctx->xid);

	/* build RDMA WR */
	wr = &t->sring[t->snext].u.swr;
	wr->wr.rdma.rkey = rctx->stag;
	wr->wr.rdma.remote_addr = rctx->to;
	wr->sg_list[0].lkey = rctx->frmr->lkey;
	wr->sg_list[0].addr = 0;
	wr->sg_list[0].length = rctx->tot_len;
	wr->send_flags = IB_SEND_SIGNALED;
	wr->opcode = IB_WR_RDMA_READ;
	wr->wr_id = (u64)(uintptr_t)rctx;

	/* Post RDMA WR */
	ret = post_send(t);
	if (!ret)
		t->read_cnt++;
	return ret;
}

/**
 * start_request() - start processing a RBDP request from the initiator
 * @rctx:	request context
 *
 * Register the frmr for @rctx if it has not been registered, and then
 * begin processing the request.  For small RBDP_WRITE operations with
 * RBDP_IMMD set, the payload is in the request message itself, so process
 * it immediately.  Otherwise issue an RDMA Read to pull the RBDP_WRITE data.
 * If it is an RBDP_READ op, then queue @rctx for backed BIO processing.  See
 * start_bio() for further processing of the RBDP_READ>
 *
 * Return: 0 upon success or negative errno upon failure.
 */
static int start_request(struct req_ctx *rctx)
{
	int ret = 0;

	DBG(PFX "%s xid %x sec_start %d cmd %s tot_len %d "
	    "SGL[0] stag %x to %llx len %d\n", __func__,
	    rctx->xid, rctx->start_sector,
	    rctx->cmd == RBDP_CMD_WRITE ? "WR" : "RD", rctx->tot_len,
	    rctx->stag, rctx->to, rctx->tot_len);

	/* If the frmr isn't registered, do it */
	if (!rctx->frmr_valid) {
		ret = register_frmr(rctx);
		if (ret)
			goto err;
	}

	if (rctx->cmd == RBDP_CMD_WRITE && !rctx->read_complete) {
		if (rctx->t->read_cnt == rctx->t->initiator_depth) {
			DBG(PFX "%s ORDQ full, deferring rctx %p.\n", __func__,
			    rctx);
			rctx->t->stats.stall_ordq_full++;
			list_add_tail(&rctx->rctx_pending_entry,
				      &rctx->t->pending_read_req_ctxs);
			ret = 1;
			goto out;
		}
		ret = send_rdma_read(rctx);
		if (ret)
			goto err;
	} else
		start_bio(rctx);
	goto out;
err:
	send_reply(rctx, ret);
out:
	return ret;
}

/**
 * process_pending_reqs() - process any RBDP requests on the pending list
 * @t: 		target context
 *
 * This is called when the SQ has emptied enough to process pending
 * RBDP requests.  Drain the pending list calling either resume_bio() or
 * start_request() until we're flow controlled or the list is emptied.
 */
static void process_pending_reqs(struct target_ctx *t)
{
	struct req_ctx *rctx;

	while (t->scnt <= (t->sqdepth - 2)) {

		if (t->read_cnt < t->initiator_depth &&
		    !list_empty(&t->pending_read_req_ctxs))
			rctx = list_first_entry(&t->pending_read_req_ctxs,
						struct req_ctx,
						rctx_pending_entry);
		else if (!list_empty(&t->pending_req_ctxs))
			rctx = list_first_entry(&t->pending_req_ctxs,
						struct req_ctx,
						rctx_pending_entry);
		else
			break;

		list_del_init(&rctx->rctx_pending_entry);
		DBG(PFX "starting pending req rctx %p\n", rctx);

		if (rctx->bio_complete)
			resume_bio(rctx);
		else
			start_request(rctx);
	}
}

/**
 * poll_scq() - drain the SCQ processing completions
 * @t:		target_context
 *
 * Poll 1 SCQE and call process_scqe() to process the request further.
 * After draining the SCQ, if we did in fact open up the SQ, then call
 * process_pending_reqs() to pull in more requests.
 *
 * Return: 0 for empty CQ, negative errno on error, or num polled.
 */
static int poll_scq(struct target_ctx *t)
{
	struct ib_wc wc;
	int ret;

	ret = ib_poll_cq(t->scq, 1, &wc);
	if (ret > 0) {
		if (wc.status && wc.status != IB_WC_WR_FLUSH_ERR)
			pr_err("send wc status %d\n", wc.status);
		spin_lock_irq(&t->lock);
		BUG_ON(t->scnt == 0);
		t->scnt--;
		process_scqe(t, &wc);
		spin_unlock_irq(&t->lock);
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

/**
 * validate_req() - do basic sanity testing on a new RBDP request
 * @rctx:	request context
 *
 *
 * Return: 0 upon success or negative errno upon failure.
 */
static int validate_req(struct req_ctx *rctx)
{
	switch (rctx->cmd) {
	case RBDP_CMD_WRITE:
	case RBDP_CMD_READ:
		break;
	default:
		pr_err(PFX "bad request cmd %d\n", rctx->cmd);
		return -EINVAL;
	}

	/* XXX only one SGE for now */
	if (rctx->num_sge > 1) {
		pr_err(PFX "bad sgl depth %d\n", rctx->num_sge);
		return -EINVAL;
	}
	DBG(PFX "%s xidx %x A-OK!\n", __func__, rctx->xid);
	return 0;
}

/**
 * process_immd_write() - start an immediate write.
 * @rctx:	request context
 * @rbdp_req:	RBDP request message
 *
 * Copy the payload from the request buffer into the frpl pages and
 * queue the bio.
 *
 * Return: 0 upon success or negative errno upon failure.
 */
static int process_immd_write(struct req_ctx *rctx,
			      struct rbdp_request *rbdp_req)
{
	u32 tot_len = rctx->tot_len;
	int ret = 0;
	int i = 0;
	u8 *dstp, *srcp;

	if (rctx->cmd != RBDP_CMD_WRITE) {
		ret = -EINVAL;
		goto out;
	}
	dstp = (u8 *)page_address(rctx->pages[0]);
	srcp = (u8 *)rbdp_req->sgl;
	while (tot_len) {
		u32 size = min_t(u32, tot_len, PAGE_SIZE);

		DBG(PFX "%s i %d dstp %p srcp %p size %d\n", __func__,
		    i, dstp, srcp, size);
		memcpy(dstp, srcp, size);
		tot_len -= size;
		dstp += size;
		srcp += size;
		if (tot_len) {
			i++;
			dstp = page_address(rctx->pages[i]);
		}
	}
	rctx->t->stats.immd_writes++;
	start_bio(rctx);
out:
	return ret;
}

/**
 * process_request() - process a new RBDP request
 * @t:		target context
 * @wc:		recv completion describing the request buffer
 *
 * Allocate a new req_ctx structure and initialize it for handling
 * the new RBDP request in the recv completion.
 * If we have SQ space, then begin processing.  Otherwise queue it for
 * deferred processing when the SQ drains.
 */
static void process_request(struct target_ctx *t, struct ib_wc *wc)
{
	int idx = wc->wr_id;
	struct wr_ring *wrr = &t->rring[idx];
	struct rbdp_request *rbdp_req = wrr->va;
	struct req_ctx *rctx;
	int ret;

	PENTER(TGT_REQUEST);
	rctx = list_first_entry(&t->free_req_ctxs, struct req_ctx,
				rctx_free_entry);
	if (!rctx) {
		pr_err(PFX "too many outstanding requests %d\n",
		       t->outstanding_req_cnt);
		rdma_disconnect(t->cm_id);
		PEXIT(TGT_REQUEST);
		return;
	}

	list_del_init(&rctx->rctx_free_entry);
	t->outstanding_req_cnt++;
	if (t->outstanding_req_cnt > t->stats.max_outstanding_reqs)
		t->stats.max_outstanding_reqs = t->outstanding_req_cnt;

	t->stats.reqs_started++;
	rctx->bio_complete = 0;
	rctx->read_complete = 0;

	rctx->xid = rbdp_req->xid;
	rctx->cmd = ntohl(rbdp_req->cmd);
	rctx->flags = ntohl(rbdp_req->flags);
	rctx->num_sge = ntohl(rbdp_req->num_sge);
	rctx->start_sector = ntohl(rbdp_req->start_sector);
	rctx->tot_len = ntohl(rbdp_req->tot_len);
	rctx->to = ntohll(rbdp_req->sgl[0].to);
	rctx->stag = ntohl(rbdp_req->sgl[0].stag);

	ret = validate_req(rctx);
	if (ret)
		goto err;

	if (t->scnt > (t->sqdepth - 2)) {
		DBG(PFX "%s SQ full, deferring rctx %p.\n", __func__, rctx);
		rctx->t->stats.stall_sq_full++;
		list_add_tail(&rctx->rctx_pending_entry,
			      &t->pending_req_ctxs);
		return;
	}
	if (rctx->flags & RBDP_IMMD) {
		ret = process_immd_write(rctx, rbdp_req);
		if (ret)
			goto err;
	} else
		start_request(rctx);
	PEXIT(TGT_REQUEST);
	return;
err:
	pr_err(PFX "request failed ret %d\n", ret);
	PEXIT(TGT_REQUEST);
	send_reply(rctx, ret);
}

/**
 * poll_rcq() - drain the recv cq processing all completions
 * @t:		target context
 *
 * Poll an RCQE and process the request.  This holds the target lock.
 *
 * Return: 0 for empty CQ, negative errno on error, or num polled.
 */
static int poll_rcq(struct target_ctx *t)
{
	struct ib_wc wc;
	int ret;

	PENTER(TGT_POLL_RCQ);
	ret = ib_poll_cq(t->rcq, 1, &wc);
	PEXIT(TGT_POLL_RCQ);
	if (ret > 0) {
		spin_lock_irq(&t->lock);
		BUG_ON(t->rcnt == 0);
		t->rcnt--;
		if (!wc.status)
			process_request(t, &wc);
		else if (wc.status != IB_WC_WR_FLUSH_ERR)
			pr_err(PFX "recv wc status %d\n", wc.status);
		spin_unlock_irq(&t->lock);
	}
	return ret;
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
 * validate_connect_data() - validate the connect request private data
 * @e:		rdma cm event.
 *
 * Sanity check the various RBDP protocol parameters send from the initiator
 * vs those in proto.h to detect protocol version mismatches.
 *
 * Return: a valid rbdp_connect_data pointer if things check out, or NULL.
 */
static struct rbdp_connect_data *validate_connect_data(struct rdma_cm_event *e)
{
	struct rbdp_connect_data *rcd = (void *)e->param.conn.private_data;
	int pdlen = e->param.conn.private_data_len;

	if (!rcd || pdlen != sizeof *rcd) {
		pr_warn(PFX "%s invalid connect data - "
			"received len %d expected %ld\n", __func__,
			pdlen, sizeof *rcd);
		return NULL;
	}
	if (ntohl(rcd->version) != RBDP_VERSION) {
		pr_warn(PFX "%s RBDP version mismatch - "
			"received %d expected %d\n", __func__,
			ntohl(rcd->version), RBDP_VERSION);
		return NULL;
	}
	if (ntohl(rcd->max_requests) != RBDP_MAX_REQUESTS) {
		pr_warn(PFX "%s RBDP max requests - "
			"received %d expected %d\n", __func__,
			ntohl(rcd->max_requests), RBDP_MAX_REQUESTS);
		return NULL;
	}
	if (ntohl(rcd->max_io_size) != RBDP_MAX_IO_SIZE) {
		pr_warn(PFX "%s RBDP max io size - "
			"received %d expected %d\n", __func__,
			ntohl(rcd->max_io_size), RBDP_MAX_IO_SIZE);
		return NULL;
	}
	if (ntohl(rcd->max_read_depth) != initiator_depth) {
		pr_warn(PFX "%s RBDP max read depth - "
			"received %d expected %d\n", __func__,
			ntohl(rcd->max_read_depth), initiator_depth);
		return NULL;
	}
	if (ntohl(rcd->max_sges) != RBDP_MAX_SGES) {
		pr_warn(PFX "%s RBDP max sge depth - "
			"received %d expected %d\n", __func__,
			ntohl(rcd->max_sges), RBDP_MAX_SGES);
		return NULL;
	}
	DBG(PFX "%s connect data A-OK!\n", __func__);
	return rcd;
}

static void init_accept_data(struct target_ctx *t, struct rbdp_accept_data *rad)
{
	u64 sectors;
	u32 sec_size;

	sec_size = bdev_logical_block_size(t->bdev);
	sectors = i_size_read(t->bdev->bd_inode) >> 9;

	rad->start_sec = htonll((u64)get_start_sect(t->bdev));
	rad->sectors = htonll(sectors);
	rad->sec_size = htonl(sec_size);
	if (null_backend)
		rad->max_io_size = htonl(RBDP_MAX_IO_SIZE);
	else
		rad->max_io_size = htonl(queue_max_segment_size(t->bdev->bd_queue));
	rad->max_sges = htonl(queue_max_segments(t->bdev->bd_queue));

	DBG(PFX "start %llu sectors %llu sec_size %u "
		"max_io_size %u max_sges %u\n",
		ntohll(rad->start_sec),
		ntohll(rad->sectors),
		ntohl(rad->sec_size),
		ntohl(rad->max_io_size),
		ntohl(rad->max_sges));
}

/**
 * drain_cqs() - drain the SQ and RQ CQs with weighted arbitration
 * @t:		Target context
 *
 * Using the cq_weights array to arbitrate how many CQEs are polled from
 * each CQ, drain both CQs until empty.  After each specific CQ drain cycle,
 * process any pending requests if we actually consumed any CQEs.
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
				ret = poll_scq(t);
				if (ret > 0)
					scnt++;
				else {
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

		spin_lock_irq(&p->lock);
		list_del_init(&t->poll_thread_entry);
		spin_unlock_irq(&p->lock);

		DBG(PFX "%s arming cqs target %p\n", __func__, t);
		if (!test_bit(DELETING_TARGET_BIT, &t->event_state)) {
			ib_req_notify_cq(t->rcq, IB_CQ_NEXT_COMP);
			ib_req_notify_cq(t->scq, IB_CQ_NEXT_COMP);
		}
		drain_cqs(t);
		t->stats.cq_waits++;

		spin_lock_irq(&p->lock);
		/* Reset the POLL_ACTIVE flag as we finshed processing all CQEs
		 * of this target.
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
 * process_newconn() - process an incoming connection request
 * @cm_id:	rdma cm_id for the new connection
 * @event: 	rdma cm event
 *
 * Validate the private data which contains RBDP connection parameters.  If
 * ok, then allocate and initalize a new target_ctx struct for this new
 * initiator connection.  Open the backend BIO device and return its parameters
 * to the initiator in private data as part of the connect reply.  Allocate all
 * the RDMA widgets needed and rdma_accept() the connection to finalize things.
 *
 * Return: 0 upon success or negative errno upon failure.
 */
static int process_newconn(struct rdma_cm_id *cm_id,
			   struct rdma_cm_event *event)
{
	struct ib_qp_init_attr init_attr = { 0 };
	struct rdma_conn_param conn_param;
	struct target_ctx *t;
	struct rbdp_connect_data *rcd;
	struct rbdp_accept_data rad;
	int ret;

	rcd = validate_connect_data(event);
	if (!rcd) {
		ret = -EINVAL;
		goto err_out;
	}
	t = kzalloc(sizeof *t, GFP_KERNEL);
	if (!t) {
		ret = -ENOMEM;
		goto err_out;
	}
	INIT_LIST_HEAD(&t->free_req_ctxs);
	INIT_LIST_HEAD(&t->pending_req_ctxs);
	INIT_LIST_HEAD(&t->pending_read_req_ctxs);
	INIT_LIST_HEAD(&t->poll_thread_entry);
	init_waitqueue_head(&t->wait);
	spin_lock_init(&t->lock);
	t->cm_id = cm_id;
	t->cm_id->context = t;
	t->rqdepth = RBDP_MAX_REQUESTS;
	t->sqdepth = RBDP_MAX_REQUESTS * 2;
	memcpy(t->device, rcd->dev, RBDP_DEVLEN);

	DBG(PFX "%s opening %s\n", __func__, t->device);
	t->bdev = blkdev_get_by_path(t->device, FMODE_READ | FMODE_WRITE |
					  FMODE_EXCL, t);
	if (IS_ERR(t->bdev)) {
		pr_err(PFX "blkdev_get_by_path(%s) failed ret %ld\n",
			t->device, PTR_ERR(t->bdev));
		ret = PTR_ERR(t->bdev);
		goto err_kzalloc;
	}

	/*
	 * XXX - don't let the underlying device go away!
	 */
	if (!try_module_get(t->cm_id->device->owner)) {
		pr_err(PFX "try_module_get() failed!\n");
		ret = -ENODEV;
		goto err_bdev;
	}

	t->pd = ib_alloc_pd(t->cm_id->device);
	if (IS_ERR(t->pd)) {
		ret = PTR_ERR(t->pd);
		pr_err(PFX "ib_alloc_pd failed %d\n", ret);
		goto err_module_get;
	}
	DBG(PFX "pd allocated!\n");

	t->scq = IB_CREATE_CQ(t->cm_id->device, scq_event_handler, NULL,
			      t, t->sqdepth, 0);
	if (IS_ERR(t->scq)) {
		ret = PTR_ERR(t->scq);
		pr_err(PFX "ib_create_cq failed %d\n", ret);
		goto err_pd;
	}
	t->rcq = IB_CREATE_CQ(t->cm_id->device, rcq_event_handler, NULL,
			      t, t->rqdepth, 1);
	if (IS_ERR(t->rcq)) {
		ret = PTR_ERR(t->rcq);
		pr_err(PFX "ib_create_cq failed %d\n", ret);
		goto err_scq;
	}

	t->my_thread_ctx = &poll_threads[next_poll_ctx++ % poll_thread_count];
	ib_req_notify_cq(t->rcq, IB_CQ_NEXT_COMP);
	ib_req_notify_cq(t->scq, IB_CQ_NEXT_COMP);

	init_attr.cap.max_send_wr = t->sqdepth;
	init_attr.cap.max_recv_wr = t->rqdepth;
	init_attr.cap.max_recv_sge = 4;
	init_attr.cap.max_send_sge = 16;
	init_attr.qp_type = IB_QPT_RC;
	init_attr.send_cq = t->scq;
	init_attr.recv_cq = t->rcq;
	init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	ret = rdma_create_qp(t->cm_id, t->pd, &init_attr);
	if (ret) {
		pr_err(PFX "rdma_create_qp failed %d\n", ret);
		goto err_rcq;
	}

	ret = alloc_rings(t);
	if (ret) {
		pr_err(PFX "alloc_rings failed %d\n", ret);
		goto err_qp;
	}
	ret = alloc_req_ctxs(t);
	if (ret) {
		pr_err(PFX "alloc_req_ctxs failed %d\n", ret);
		goto err_rings;
	}

	/* accept */
	conn_param.responder_resources = 0;
	conn_param.initiator_depth = initiator_depth;
	conn_param.retry_count = 10;

	init_accept_data(t, &rad);
	conn_param.private_data = (u8 *)&rad;
	conn_param.private_data_len = sizeof rad;

	t->initiator_depth = initiator_depth;

	ret = rdma_accept(t->cm_id, &conn_param);
	if (ret) {
		pr_err(PFX "rdma_connect failed %d\n", ret);
		goto err_rctx;
	}


	pr_info(PFX "connected %pI4:%u<->%pI4:%u!\n",
		&SINP(&t->cm_id->route.addr.src_addr)->sin_addr,
		ntohs(SINP(&t->cm_id->route.addr.src_addr)->sin_port),
		&SINP(&t->cm_id->route.addr.dst_addr)->sin_addr,
		ntohs(SINP(&t->cm_id->route.addr.dst_addr)->sin_port));

	if (debugfs_root) {
		t->debugfs_root = debugfs_create_dir(kbasename(t->device),
						     debugfs_root);
		if (t->debugfs_root)
			setup_debugfs(t);
	}

	mutex_lock(&target_mutex);
	list_add_tail(&t->target_list_entry, &target_list);
	mutex_unlock(&target_mutex);

	return 0;
err_rctx:
	dealloc_req_ctxs(t);
err_rings:
	free_rings(t);
err_qp:
	rdma_destroy_qp(t->cm_id);
err_rcq:
	ib_destroy_cq(t->rcq);
err_scq:
	ib_destroy_cq(t->scq);
err_pd:
	ib_dealloc_pd(t->pd);
err_module_get:
	module_put(t->cm_id->device->owner);
err_bdev:
	blkdev_put(t->bdev, FMODE_EXCL);
err_kzalloc:
	kfree(t);
err_out:
	return ret;
}

/**
 * destroy_target() - destroy a target context releasing all resources
 * @t:		target context
 */
static void destroy_target (struct target_ctx *t)
{
	int i = 0;

	pr_info(PFX "destroying target %s\n", t->device);
	rdma_disconnect(t->cm_id);

	for (i = 0; i < DESTROY_TIMEOUT; i++) {
		/* Wait for poll thread to drain pending CQEs of this target */
		msleep(10);

		set_bit(DELETING_TARGET_BIT, &t->event_state);

		/* Check whether poll thread finished draining all CQEs */
		if (DELETING_TARGET == atomic_long_read((atomic_long_t *)
						     &t->event_state))
			break;
		DBG(PFX "waiting for pollers to complete!\n");
	}
	if (i == DESTROY_TIMEOUT) {
		pr_info(PFX "Could not destroy target objects %s\n", t->device);
		return;
	}

	while (t->bios) {
		DBG(PFX "waiting for bios to complete!\n");
		msleep(10);
	}

	rdma_destroy_qp(t->cm_id);
	ib_destroy_cq(t->rcq);
	ib_destroy_cq(t->scq);
	ib_dealloc_pd(t->pd);
	dealloc_req_ctxs(t);
	free_rings(t);
	module_put(t->cm_id->device->owner);
	rdma_destroy_id(t->cm_id);
	blkdev_put(t->bdev, FMODE_EXCL);
	list_del(&t->target_list_entry);
	debugfs_remove_recursive(t->debugfs_root);
	kfree(t);
	return;
}

/**
 * process_disconnect() - work queue handler for disconnect events
 * @work: 	work structure
 *
 * This is the work handler for disconnect events.  If the target context
 * is actually in the global list, then destroy it.
 */
static void process_disconnect(struct work_struct *work)
{
	struct target_ctx *t = container_of(work, struct target_ctx, work);
	struct target_ctx *tcur, *tmp;

	mutex_lock(&target_mutex);
	list_for_each_entry_safe(tcur, tmp, &target_list, target_list_entry)
		if (tcur == t)
			destroy_target(t);
	mutex_unlock(&target_mutex);
}

/**
 * cm_event_handler - handler for connection events
 * @cm_id: 	rdma cm id
 * @evnet:	connection event
 *
 * For new connect requests, call process_newconn().  The only other
 * interesting events are ESTABLISHED when a connection finally gets setup,
 * and disconnect to tear down a target.  Treat device removal as a disconnect.
 *
 * Return: 0 upon success or negative errno upon failure.  NOTE: Non zero
 * returns from process_newconn() cause the RDMACM to destroy the connect
 * request cm_id, which is what we want.
 */
static int cm_event_handler(struct rdma_cm_id *cm_id,
			    struct rdma_cm_event *event)
{
	struct target_ctx *t = cm_id->context;
	int ret = 0;

	/* check if the target is in proper state to handle CM events */
	if (event->event != RDMA_CM_EVENT_CONNECT_REQUEST) {
		if (DELETING_TARGET & test_and_set_bit(CM_ACTIVE_BIT,
						    &t->event_state)) {
			/* This target is being detroyed, so reset the flag
			 * and exit.
			 */
			clear_bit(CM_ACTIVE_BIT, &t->event_state);
			goto error;
		}
	}

	switch (event->event) {

	case RDMA_CM_EVENT_CONNECT_REQUEST:
		ret = process_newconn(cm_id, event);
		break;

	case RDMA_CM_EVENT_ESTABLISHED:
		t->state = CONNECTED;
		break;

	case RDMA_CM_EVENT_DISCONNECTED:
		DBG(PFX "DISCONNECT EVENT...\n");
		t->state = ERROR;
		INIT_WORK(&t->work, process_disconnect);
		queue_work(cm_workq, &t->work);
		break;

	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		pr_err(PFX "cm detected device removal!\n");
		t->state = ERROR;
		INIT_WORK(&t->work, process_disconnect);
		queue_work(cm_workq, &t->work);
		break;

	default:
		pr_err(PFX "oof unexpected event %d!\n", event->event);
		t->state = ERROR;
		INIT_WORK(&t->work, process_disconnect);
		queue_work(cm_workq, &t->work);
		break;
	}

	if (event->event != RDMA_CM_EVENT_CONNECT_REQUEST)
		clear_bit(CM_ACTIVE_BIT, &t->event_state);

error:
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

		p->poll_thread = kthread_run(poll_thread_func, p, "rbdt-%d", i);
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
 *  rbdt_init() - module init function
 *
 * setup the cm workq, debugfs files, and create a listening cm_id to
 * listen for incoming initiator connection requests.
 *
 * Return: 0 upon success or negative errno upon failure.
 */
int __init rbdt_init(void)
{
	struct sockaddr_in sin = { 0 };
	int ret;

	pr_info(PFX "setting up rdma target on %s:%u\n", listen_ipaddr,
		listen_port);

	cq_weights[SCQ_INDEX] = scq_weight;
	cq_weights[RCQ_INDEX] = rcq_weight;

	cm_workq = create_singlethread_workqueue("rbdt_cm_wq");
	if (!cm_workq) {
		ret = -ENOMEM;
		goto err;
	}
	ret = create_thread_pool();
	if (ret)
		goto err_workqueue;

	debugfs_root = debugfs_create_dir(RBDT_NAME, NULL);
	if (debugfs_root) {
		struct dentry *de;

		de = debugfs_create_file("devices", S_IWUSR, debugfs_root,
					 NULL, &tgt_debugfs_fops);
		if (!de) {
			pr_warn(PFX "could not create devices debugfs entry, "
				"continuing\n");
		}
		PINIT(debugfs_root);
	} else
		pr_warn(PFX "could not create debugfs entry, continuing\n");

	/* create cm_id */
	listen_cm_id = rdma_create_id(cm_event_handler, NULL, RDMA_PS_TCP,
				      IB_QPT_RC);
	if (IS_ERR(listen_cm_id)) {
		ret = PTR_ERR(listen_cm_id);
		goto err_debugfs;
	}
	DBG(PFX "cm_id created!\n");

	/* resolve address/route */
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = in_aton(listen_ipaddr);
	sin.sin_port = htons(listen_port);
	ret = rdma_bind_addr(listen_cm_id, (struct sockaddr *) &sin);
	if (ret)
		goto err_cm_id;

	DBG(PFX "listener bound!\n");

	ret = rdma_listen(listen_cm_id, 0);
	if (ret)
		goto err_cm_id;
	DBG(PFX "listener listening!\n");
	return 0;
err_cm_id:
	rdma_destroy_id(listen_cm_id);
err_debugfs:
	debugfs_remove_recursive(debugfs_root);
	destroy_thread_pool();
err_workqueue:
	destroy_workqueue(cm_workq);
err:
	return ret;
}

/**
 * rbdt_remove() - module unload function
 *
 * Destroy the listening cm_id, nuke the targets, and cleanup the debugfs
 * files and the cm workq.
 */
void rbdt_remove(void)
{
	struct target_ctx *t, *tmp;

	mutex_lock(&target_mutex);
	list_for_each_entry_safe(t, tmp, &target_list, target_list_entry)
		destroy_target(t);
	mutex_unlock(&target_mutex);

	rdma_destroy_id(listen_cm_id);
	debugfs_remove_recursive(debugfs_root);
	destroy_thread_pool();
	destroy_workqueue(cm_workq);
	DBG(PFX "Unloading\n");
}

module_init(rbdt_init);
module_exit(rbdt_remove);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Steve Wise <swise@chelsio.com>");
MODULE_DESCRIPTION("RDMA Block Device Target");
