#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include "kernelcom.h"
#include "chardev.h"
#include "debug.h"
#include "mmap.h"
#include "device.h"

extern unsigned long wdtoe_page_size;

int open_global_chardev(void)
{
	int fd;

	fd = open(GLOBAL_DEV_NODE, O_RDWR | O_SYNC);

	if (fd == -1)
		DBG(DBG_CHAR_DEV, "could not open device %s\n",
		    GLOBAL_DEV_NODE);

	return fd;
}

int create_wd_dev(struct wdtoe_device **wd_dev, int global_devfd)
{
	int ret;
	struct wdtoe_create_dev cmd_new_dev;
	struct wdtoe_create_dev_resp resp_new_dev;

	*wd_dev = calloc(1, sizeof(*(*wd_dev)));
	if (!(*wd_dev)) {
		DBG(DBG_CHAR_DEV, "mem allocation for wdtoe_device failed");
		return -1;
	}

	ret = wdtoe_cmd_create_dev(global_devfd, &cmd_new_dev,
				   sizeof(cmd_new_dev),
				   &resp_new_dev,
				   sizeof(resp_new_dev));
	if (ret) {
		DBG(DBG_CHAR_DEV, "Kernel communication error");
		return -1;
	}

	(*wd_dev)->dev_idx = resp_new_dev.dev_idx;

	return 0;
}

int open_wd_dev(struct wdtoe_device *wd_dev)
{
	int ret;
	struct stat s;
	unsigned int stat_i = 0;
	char cdevname[20];

	if (!wd_dev)
		return -1;

	ret = snprintf(cdevname, sizeof(cdevname), DEV_NODE_NAME_FMT,
		       wd_dev->dev_idx);
	if (ret < 0)
		return -1;


	/*
	 * We need to poll the /dev/wdtoeN node before
	 * we try to access it with the open() call.
	 * Not doing so may lead to trying to open a
	 * non existing file. We sure could loop over
	 * the open call and check the errno code
	 * but open() is more likely to be caught and
	 * overridden by someone else than stat().
	 *
	 * We will loop for 2^10 times maximum, as we
	 * do not want the application to be trapped
	 * in an infinite loop if something goes
	 * wrong (e.g. node never created).
	 */
	memset(&s, 0, sizeof(s));

	do {
		stat(cdevname, &s);
		stat_i++;
	} while (*(volatile dev_t *)&s.st_dev == 0 && stat_i != (1 << 10));

	wd_dev->devfd = open(cdevname, O_RDWR | O_SYNC);
	if (wd_dev->devfd == -1) {
		DBG(DBG_CHAR_DEV, "could not open device %s\n", cdevname);
		return -1;
	}

	return 0;
}

static struct t4_iq *create_iq(struct wdtoe_device *wd_dev, u16 size,
			       size_t memsize, u16 qid, void *gts,
			       unsigned int idx)
{
	struct t4_iq *iq = NULL;
	unsigned int map_idx = idx * WDTOE_MMAPNUM_RXQ;

	iq = calloc(1, sizeof(*iq));
	if (!iq) {
		DBG(DBG_RES_ALLOC, "could not allocate memory for IQ "
		    "(qid: %u)\n", qid);
		    return NULL;
	}

	iq->size = size;
	iq->memsize = memsize;
	iq->qid = qid;
	iq->gts = gts;

	iq->queue = wdtoe_mmap(iq->memsize, wd_dev->devfd,
			       (0 + map_idx) * wdtoe_page_size);

	if (iq->queue == MAP_FAILED) {
		DBG(DBG_RES_ALLOC, "IQ mapping failed\n");
		goto free_iq;
	}

	assert(iq->queue);

	iq->iq_shared_params = wdtoe_mmap(wdtoe_page_size, wd_dev->devfd,
					  (3 + map_idx) * wdtoe_page_size);

	if (iq->iq_shared_params == MAP_FAILED) {
		DBG(DBG_RES_ALLOC, "IQ shared params mapping failed\n");
		goto unmap_iq;
	}

	assert(iq->iq_shared_params);

	iq->iq_shared_params->cidx = 0;
	iq->iq_shared_params->cidx_inc = 0;
	iq->iq_shared_params->gen = 1;

	wd_dev->iq_list[idx] = iq;

	return iq;

unmap_iq:
	wdtoe_munmap(iq->queue, iq->memsize);

free_iq:
	free(iq);
	return NULL;
}

void free_iq(struct t4_iq **iq)
{
	wdtoe_munmap((*iq)->iq_shared_params, wdtoe_page_size);
	wdtoe_munmap((*iq)->queue, (*iq)->memsize);
	free(*iq);
	*iq = NULL;
}

static int create_fl_bufs(struct wdtoe_device *wd_dev, struct t4_raw_fl *fl,
			  unsigned int idx, unsigned int *offset)
{
	unsigned int i;
	unsigned int map_idx = idx * WDTOE_MMAPNUM_RXQ;

	fl->sw_queue = calloc(fl->size, sizeof(uint64_t));
	if (!fl->sw_queue) {
		DBG(DBG_RES_ALLOC, "could not allocate memory for FL buffers "
		    "(qid: %u)\n", fl->qid);
		return -1;
	}

	/* XXX NEED ROLLBACK MECHANISM */
	for (i = 0; i < fl->size; i++) {
		fl->sw_queue[i] = (uint64_t)wdtoe_mmap(wdtoe_page_size,
					    wd_dev->devfd,
					    (5 + i + map_idx) * wdtoe_page_size);
		*offset = 5 + i + map_idx;
		if (fl->sw_queue[i] == (uint64_t)MAP_FAILED)
			DBG(DBG_RES_ALLOC, "fl->sw_queue[%d] mapping failed\n",
			    i);
	}

	return 0;
}

static struct t4_raw_fl *create_fl(struct wdtoe_device *wd_dev, u16 size,
				   size_t memsize, u16 qid, unsigned int idx,
				   u16 pidx, u16 pend_cred, u16 avail)
{
	struct t4_raw_fl *fl = NULL;
	unsigned int map_idx = idx * WDTOE_MMAPNUM_RXQ;

	fl = calloc(1, sizeof(*fl));
	if (!fl) {
		DBG(DBG_RES_ALLOC, "could not allocate memory for FL "
		    "(qid: %u)\n", qid);
		return NULL;
	}

	fl->size = size;
	fl->memsize = memsize;
	fl->qid = qid;

	fl->queue = wdtoe_mmap(fl->memsize, wd_dev->devfd,
			       (1 + map_idx) * wdtoe_page_size);

	if (fl->queue == MAP_FAILED) {
		DBG(DBG_RES_ALLOC, "FL mapping failed\n");
		goto free_fl;
	}

	assert(fl->queue);

	fl->db = wdtoe_mmap(wdtoe_page_size, wd_dev->devfd,
			    (2 + map_idx) * wdtoe_page_size);

	if (fl->db == MAP_FAILED) {
		DBG(DBG_RES_ALLOC, "FL db mapping failed\n");
		goto unmap_fl;
	}

	assert(fl->db);

	/*
	 * The FL buffer allocation is done in kernel,
	 * here get pend_cred, pidx and available number of FL buffer.
	 *
	 * Note that we have allocated all the FL buffers, and filled
	 * FL with their address in kernel already, but when ringing
	 * DB from user, we pretend the last 8 FL bufs has not yet
	 * "allocated". This is to keep the same logic as cxgb4 uses,
	 * avoiding running into the situation where pidx == cidx
	 * with all the FL bufs are allocated, which is supposed to
	 * be indicating an empty, unfilled FL.
	 */
	fl->fl_shared_params = wdtoe_mmap(wdtoe_page_size, wd_dev->devfd,
					  (4 + map_idx) * wdtoe_page_size);

	if (fl->fl_shared_params == MAP_FAILED) {
		DBG(DBG_RES_ALLOC, "FL shared params mapping failed\n");
		goto unmap_fl_db;
	}

	assert(fl->fl_shared_params);

	fl->fl_shared_params->cidx = 0;
	fl->fl_shared_params->pidx = pidx - 8;
	fl->fl_shared_params->pend_cred = pend_cred - 8;
	fl->fl_shared_params->in_use = avail - 8;

	/* ringing doorbell from user space */
	t4_ring_fl_db(fl);

	wd_dev->fl_list[idx] = fl;

	return fl;

unmap_fl_db:
	wdtoe_munmap(fl->db, wdtoe_page_size);

unmap_fl:
	wdtoe_munmap(fl->queue, fl->memsize);

free_fl:
	free(fl);
	return NULL;
}

static void free_fl(struct t4_raw_fl **fl)
{
	wdtoe_munmap((*fl)->fl_shared_params, wdtoe_page_size);
	wdtoe_munmap((*fl)->db, wdtoe_page_size);
	wdtoe_munmap((*fl)->queue, (*fl)->memsize);
	free(*fl);
	*fl = NULL;
}

static int create_rxq(struct wdtoe_device *wd_dev,
		      struct wdtoe_copy_rxq_resp rx_rsp,
		      unsigned int idx, unsigned int *offset)
{
	int ret;
	struct t4_raw_fl *fl;
	struct t4_iq *iq;
	void *gts;

	fl = create_fl(wd_dev, rx_rsp.fl_size, rx_rsp.fl_memsize, rx_rsp.fl_id,
		       idx, rx_rsp.fl_pidx, rx_rsp.fl_pend_cred,
		       rx_rsp.fl_avail);
	if (!fl)
		goto err_out;

	/*
	 * Ingress Queue's GTS register has a known offset from the FL db.
	 * We don't need a specific mapping operation from Kernel, which is
	 * nice.
	 */
	gts = fl->db + 4;
	iq = create_iq(wd_dev, rx_rsp.iq_size, rx_rsp.iq_memsize, rx_rsp.iq_id,
		       gts, idx);
	if (!iq)
		goto free_fl;

	ret = create_fl_bufs(wd_dev, fl, idx, offset);
	if (ret == -1)
		goto free_iq;

	return 0;

free_iq:
	free_iq(&iq);

free_fl:
	free_fl(&fl);

err_out:
	return -1;
}

static struct t4_txq *__create_txq(struct wdtoe_device *wd_dev, u16 size,
				   size_t memsize, u16 qid, void *db,
				   unsigned int idx)
{
	struct t4_txq *txq = NULL;

	txq = calloc(1, sizeof(*txq));
	if (!txq) {
		DBG(DBG_RES_ALLOC, "could not allocate memory for TxQ "
		    "(qid: %u)\n", qid);
		return NULL;
	}

	txq->size = size;
	txq->memsize = memsize;
	txq->qid = qid;
	txq->db = db;

	wd_dev->txq_list[idx] = txq;

	return txq;
}

static void free_txq_desc(struct t4_txq **txq)
{
	wdtoe_munmap((*txq)->desc, (*txq)->memsize);
	free(*txq);
	*txq = NULL;
}

static int create_txq(struct wdtoe_device *wd_dev,
		      struct wdtoe_copy_txq_resp tx_rsp,
		      unsigned int idx, unsigned int *offset)
{
	struct t4_txq *txq;

	txq = __create_txq(wd_dev, tx_rsp.txq_size, tx_rsp.txq_memsize,
			   tx_rsp.txq_id, wd_dev->fl_list[idx]->db, idx);
	if (!txq)
		return -1;

	(*offset)++;
	txq->desc = wdtoe_mmap(txq->memsize, wd_dev->devfd,
			       *offset * wdtoe_page_size);

	if (txq->desc == MAP_FAILED) {
		DBG(DBG_RES_ALLOC, "txq desc mapping failed\n");
		goto err_out;
	}

	assert(txq->desc);

	(*offset)++;
	txq->txq_params = wdtoe_mmap(wdtoe_page_size, wd_dev->devfd,
				     *offset * wdtoe_page_size);

	if (txq->txq_params == MAP_FAILED) {
		DBG(DBG_RES_ALLOC, "txq shared params mapping failed\n");
		goto free_desc;
	}

	assert(txq->txq_params);

	txq->txq_params->cidx = 0;
	txq->txq_params->pidx = 0;
	txq->txq_params->flags = tx_rsp.flags;

	/* map the TxQ's user db */
	(*offset)++;
	txq->udb = wdtoe_mmap(wdtoe_page_size, wd_dev->devfd,
				*offset * wdtoe_page_size);

	if (txq->udb == MAP_FAILED) {
		DBG(DBG_RES_ALLOC, "txq user db mapping failed\n");
		goto unmap_params;
	}

	assert(txq->udb);

	/* On T5, calculate the offset for this txq's qid */
	if (wd_dev->hca_type == CHELSIO_T5) {
		txq->udb += (128 * (txq->qid & wd_dev->qid_mask)) / 4;
		txq->udb += 2;
	}

	return 0;

unmap_params:
	wdtoe_munmap((void *)txq->udb, wdtoe_page_size);

free_desc:
	free_txq_desc(&txq);

err_out:
	return -1;
}

static int __create_qp_set(struct wdtoe_device *wd_dev, unsigned int *offset)
{
	int ret;
	unsigned int i;
	struct wdtoe_copy_rxq rx_cmd;
	struct wdtoe_copy_rxq_resp rx_rsp;
	struct wdtoe_copy_txq tx_cmd;
	struct wdtoe_copy_txq_resp tx_rsp;

	for (i = 0; i < wd_dev->nports; i++) {
		rx_cmd.port_num = i;
		/*
		 * XXX This needs to be renamed to something that makes sense.
		 * We are just trying to get per-RxQ information, not to
		 * copy an RxQ.
		 */
		ret = wdtoe_cmd_copy_rxq(wd_dev->devfd, &rx_cmd, sizeof(rx_cmd),
					 &rx_rsp, sizeof(rx_rsp));

		/* XXX NEEDS ROLLBACK MECHANISM */
		if (ret < 0) {
			DBG(DBG_RES_ALLOC, "could not retrieve RxQ info\n");
			return -1;
		}

		ret = create_rxq(wd_dev, rx_rsp, i, offset);
		if (ret == -1)
			return -1;
	}

	/*
	 * XXX Please, please, please, fix this.
	 *
	 * Yeah, well, I know. We have two loops that seem like they could be
	 * merged into a single one. The thing is, if I do that I also need to
	 * rewrite the entire back-end logic that sits in Kernel. It should be
	 * done. It has to be done. It will be done. Just not right now.
	 */
	for (i = 0; i < wd_dev->nports; i++) {
		tx_cmd.port_num = i;
		/*
		 * XXX Same thing as in the above loop.
		 */
		ret = wdtoe_cmd_copy_txq(wd_dev->devfd, &tx_cmd, sizeof(tx_cmd),
					 &tx_rsp, sizeof(tx_rsp));

		/* NEEDS ROLLBACK MECHANISM */
		if (ret < 0) {
			DBG(DBG_RES_ALLOC, "could not retrieve TxQ info\n");
			return -1;
		}

		ret = create_txq(wd_dev, tx_rsp, i, offset);
		if (ret == -1)
			return -1;
	}

	return 0;
}

/*
 * Creates a set of QPs for this instance of the library.
 * A QP is created for each port of the adapter. After calling this function
 * the QPs are accessible through *wd_dev (iq_list, fl_list, txq_list)
 */
int create_qp_set(struct wdtoe_device *wd_dev, int tx_hold_thres,
		  unsigned int *offset)
{
	int ret;
	struct wdtoe_create_rxq cmd_new_rxq;
	struct wdtoe_create_rxq_resp resp_new_rxq;

	/*
	 * XXX wdtoe_cmd_create_rxq() and the corresponding Kernel fns
	 * need to be renamed wdtoe_cmd_create_qp() or something like
	 * that. We are creating a QP, not an RxQ.
	 */
	ret = wdtoe_cmd_create_rxq(wd_dev->devfd, &cmd_new_rxq,
				   sizeof(cmd_new_rxq), &resp_new_rxq,
				   sizeof(resp_new_rxq), tx_hold_thres);

	if (ret) {
		DBG(DBG_CHAR_DEV | DBG_RES_ALLOC, "could not create QP "
		    "through char device with fd %d\n", wd_dev->devfd);
		return -1;
	}

	wd_dev->hca_type = resp_new_rxq.hca_type;

	if (wd_dev->hca_type == CHELSIO_T4) {
		DBG(DBG_RES_ALLOC, "adapter is a Chelsio T4\n");
	} else if (wd_dev->hca_type == CHELSIO_T5) {
		DBG(DBG_RES_ALLOC, "adapter is a Chelsio T5\n");
	} else {
		DBG(DBG_RES_ALLOC, "WARNING: unknown adapter type\n");
	}

	wd_dev->qid_mask = resp_new_rxq.qid_mask;
	wd_dev->nports = resp_new_rxq.nports;
	wd_dev->stack_info_memsize = resp_new_rxq.stack_info_memsize;

	wd_dev->iq_list = calloc(wd_dev->nports, sizeof(struct t4_iq *));
	if (!wd_dev->iq_list)
		goto err_out;

	wd_dev->fl_list = calloc(wd_dev->nports, sizeof(struct t4_raw_fl *));
	if (!wd_dev->fl_list)
		goto free_iq_list;

	wd_dev->txq_list = calloc(wd_dev->nports, sizeof(struct t4_txq *));
	if (!wd_dev->txq_list)
		goto free_fl_list;

	ret = __create_qp_set(wd_dev, offset);
	if (ret == -1)
		goto free_txq_list;

	return 0;

free_txq_list:
	free(wd_dev->txq_list);
	wd_dev->txq_list = NULL;

free_fl_list:
	free(wd_dev->fl_list);
	wd_dev->fl_list = NULL;

free_iq_list:
	free(wd_dev->iq_list);
	wd_dev->iq_list = NULL;

err_out:
	DBG(DBG_RES_ALLOC, "resource allocation for QP failed\n");
	return -1;
}

int map_stack_info(struct wdtoe_device *wd_dev, unsigned int *offset)
{
	(*offset)++;

	wd_dev->stack_info = wdtoe_mmap(wd_dev->stack_info_memsize,
					wd_dev->devfd,
					*offset * wdtoe_page_size);

	if (wd_dev->stack_info == MAP_FAILED) {
		DBG(DBG_RES_ALLOC, "stack info mapping failed\n");
		return -1;
	}

	assert(wd_dev->stack_info);

	return 0;
}

int create_sw_fl_and_sw_txq(struct wdtoe_device *wd_dev)
{
	int ret;
	struct wdtoe_create_mempool cmd;
	struct wdtoe_create_mempool_resp rsp;

	memset(&cmd, 0, sizeof(cmd));
	memset(&rsp, 0, sizeof(rsp));

	/* number of pages you want the kernel to allocate for you */
	cmd.page_num = NWDTOECONN * (NTXBUF + NRXBUF);

	ret = wdtoe_cmd_create_mempool(wd_dev->devfd, &cmd, sizeof(cmd),
				       &rsp, sizeof(rsp));
	if (ret) {
		DBG(DBG_RES_ALLOC, "could not create memory pool through "
		    "char device with devfd %d\n", wd_dev->devfd);
		return -1;
	}

	return 0;
}

int map_sw_txq(struct wdtoe_device *wd_dev, unsigned int *idx)
{
	unsigned int i;

	/* XXX do we need the "+1" here? */
	*idx = wd_dev->nports * WDTOE_MMAPNUM_RXQ +
	       wd_dev->nports * WDTOE_MMAPNUM_TXQ + 1;

	for (i = 0; i < NWDTOECONN * NTXBUF; i++) {
		/* map the page for tx */
		wd_dev->stack_info->buf.sw_txq[i/NTXBUF].
					sw_queue[i%NTXBUF] =
					(uint64_t)wdtoe_mmap(
						wdtoe_page_size,
						wd_dev->devfd,
						(*idx + i) *
						wdtoe_page_size);

		/* XXX NEED ROLLBACK MECHANISM */
		if (!(wd_dev->stack_info->buf.sw_txq[i/NTXBUF].sw_queue[i%NTXBUF]))
			return -1;
	}

	*idx += i;

	return 0;
}

int map_sw_fl(struct wdtoe_device *wd_dev, unsigned int idx)
{
	unsigned int i;

	for (i = 0; i < NWDTOECONN * NRXBUF; i++) {
		/* XXX what if mmap fails? */
		wd_dev->stack_info->buf.sw_fl[i/NRXBUF].
					sw_queue[i%NRXBUF] =
					(uint64_t)wdtoe_mmap(
						wdtoe_page_size,
						wd_dev->devfd,
						(idx + i) *
						wdtoe_page_size);

		/*XXX NEED ROLLBACK MECHANISM */
		if (!(wd_dev->stack_info->buf.sw_fl[i/NRXBUF].sw_queue[i%NRXBUF]))
			return -1;
	}

	return 0;
}

int register_stack(struct wdtoe_device *wd_dev)
{
	int ret;
	struct wdtoe_reg_stack cmd;
	struct wdtoe_reg_stack_resp rsp;

	memset(&cmd, 0, sizeof(cmd));
	memset(&rsp, 0, sizeof(rsp));

	/* register this WD-TOE stack in kernel */
	ret = wdtoe_cmd_register_stack(wd_dev->devfd, &cmd, sizeof(cmd),
				       &rsp, sizeof(rsp));
	if (ret) {
		DBG(DBG_RES_ALLOC, "stack registration failed\n");
		return -1;
	}

	return 0;
}
