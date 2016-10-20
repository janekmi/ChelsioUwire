/*
 *  Copyright (C) 2008-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 * 
 * Description:
 * 
 */

#ifndef __CSIO_SCSI_H__
#define __CSIO_SCSI_H__

#include <csio_defs.h>
#include <csio_wr.h>

/* Exported to OS-specific layer so they can be made tunable */
extern int csio_scsi_eqsize;
extern int csio_scsi_iqlen;
extern int csio_scsi_ioreqs;
extern int csio_ddp_descs;
extern uint32_t csio_max_scan_tmo;
extern uint32_t csio_delta_scan_tmo;

/* Protocol specific defines */
/*
 **************************** NOTE *******************************
 * How do we calculate MAX FCoE SCSI SGEs? Here is the math:
 * Max Egress WR size = 512 bytes
 * One SCSI egress WR has the following fixed no of bytes:
 *      48 (sizeof(struct fw_scsi_write[read]_wr)) - FW WR
 *    + 32 (sizeof(struct csio_fcp_cmnd)) - Immediate FCP_CMD
 *    ------
 *      80
 *    ------
 * That leaves us with 512 - 96 = 432 bytes for data SGE. Using
 * struct ulptx_sgl header for the SGE consumes:
 * 	- 4 bytes for cmnd_sge.
 * 	- 12 bytes for the first SGL.
 * That leaves us with 416 bytes for the remaining SGE pairs. Which is
 * is 416 / 24 (size(struct ulptx_sge_pair)) = 17 SGE pairs,
 * or 34 SGEs. Adding the first SGE fetches us 35 SGEs.
 */
#define CSIO_SCSI_FCOE_MAX_SGE		35
#define CSIO_SCSI_FCOE_ABRT_TMO_MS	60000
#define CSIO_SCSI_FCOE_LUNRST_TMO_MS	60000
#define CSIO_SCSI_FCOE_TGTRST_TMO_MS	60000

/* TODO: Change this later */
#define CSIO_SCSI_ISCSI_MAX_SGE		32
#define CSIO_SCSI_ISCSI_ABRT_TMO_MS	30000
#define CSIO_SCSI_ISCSI_LUNRST_TMO_MS	60000
#define CSIO_SCSI_ISCSI_TGTRST_TMO_MS	60000

#define CSIO_SCSI_TM_POLL_MS		2000	/* should be less than
						 * all TM timeouts.
						 */

#define CSIO_SCSI_IQ_WRSZ		128
#define CSIO_SCSI_IQSIZE		(csio_scsi_iqlen * CSIO_SCSI_IQ_WRSZ)

#define SCSI_ABORT 0
#define SCSI_CLOSE 1

/* The OS-specific command has to be placed in scratch1 */
#define csio_scsi_osreq(req)			((req)->scratch1)

struct csio_scsi_stats {
	uint64_t		n_tot_success;	/* Total number of good I/Os */
	uint32_t		n_rn_nr_error;	/* No. of remote-node-not-
						 * ready errors 
						 */
	uint32_t		n_hw_nr_error;	/* No. of hw-module-not-
						 * ready errors 
						 */
	uint32_t		n_dmamap_error;	/* No. of DMA map erros */
	uint32_t		n_unsupp_sge_error; /* No. of too-many-SGes 
						     * errors.
						     */
	uint32_t		n_no_req_error;	/* No. of Out-of-ioreqs error */
	uint32_t		n_busy_error;	/* No. of CSIO_BUSY errors */
	uint32_t		n_hosterror;	/* No. of FW_HOSTERROR I/O */
	uint32_t		n_rsperror;	/* No. of response errors */
	uint32_t		n_autosense;	/* No. of auto sense replies */
	uint32_t		n_ovflerror;	/* No. of overflow errors */
	uint32_t		n_unflerror;	/* No. of underflow errors */
	uint32_t		n_rdev_nr_error;/* No. of rdev not 
						 * ready errors
						 */
	uint32_t		n_rdev_lost_error;/* No. of rdev lost errors */
	uint32_t		n_rdev_logo_error;/* No. of rdev logo errors */
	uint32_t		n_link_down_error;/* No. of link down errors */
	uint32_t 		n_no_xchg_error; /* No. no exchange error */
	uint32_t		n_unknown_error;/* No. of unhandled errors */
	uint32_t		n_aborted;	/* No. of aborted I/Os */
	uint32_t		n_abrt_timedout; /* No. of abort timedouts */
	uint32_t		n_abrt_fail;	/* No. of abort failures */
	uint32_t		n_abrt_dups;	/* No. of duplicate aborts */
	uint32_t		n_abrt_race_comp; /* No. of aborts that raced
						   * with completions.
						   */
	uint32_t		n_abrt_busy_error;/* No. of abort failures 
						   * due to CSIO_BUSY.
						   */
	uint32_t		n_closed;	/* No. of closed I/Os */
	uint32_t		n_cls_busy_error; /* No. of close failures 
						   * due to CSIO_BUSY.
						   */
	uint32_t		n_active;	/* No. of IOs in active_q */
	uint32_t		n_tm_active;	/* No. of TMs in active_q */
	uint32_t		n_wcbfn;	/* No. of I/Os in worker
						 * cbfn q 
						 */
	uint32_t		n_free_ioreq;	/* No. of freelist entries */
	uint32_t		n_free_ddp;	/* No. of DDP freelist */
	uint32_t		n_ddp_miss;	/* No. of DDP misses */
	uint32_t		n_inval_cplop;	/* No. invalid CPL op's in IQ */
	uint32_t		n_inval_scsiop;	/* No. invalid scsi op's in IQ*/
	
#ifdef __CSIO_SCSI_PERF__
	/* Performance stats */
	uint64_t		start_sec;
	int64_t			rbytes;
	int64_t			wbytes;
	int64_t			reads;
	int64_t			writes;
	uint64_t		saved_delta_secs;
	int64_t			saved_rbytes;
	int64_t			saved_wbytes;
	int64_t			saved_reads;
	int64_t			saved_writes;
#endif /* __CSIO_SCSI_PERF__ */
};

struct csio_scsim {
	struct csio_hw		*hw;		/* Pointer to HW moduel */
	uint8_t			max_sge;	/* Max SGE */
	uint8_t			proto_cmd_len;	/* Proto specific SCSI
						 * cmd length
						 */
	uint16_t		proto_rsp_len;	/* Proto specific SCSI
						 * response length
						 */
	csio_spinlock_t		freelist_lock;	/* Lock for ioreq freelist */ 
	struct csio_list	active_q;	/* Outstanding SCSI I/Os */
	struct csio_list	ioreq_freelist;	/* Free list of ioreq's */
	struct csio_list	ddp_freelist;	/* DDP descriptor freelist */
	struct csio_scsi_stats	stats;		/* This module's statistics */
};

/* State machine defines */
typedef enum {
	CSIO_SCSIE_START_IO = 1,		/* Start a regular SCSI IO */
	CSIO_SCSIE_START_TM,			/* Start a TM IO */
	CSIO_SCSIE_COMPLETED,			/* IO Completed */
	CSIO_SCSIE_RES_FAIL,			/* No resources available */ 
	CSIO_SCSIE_RES_AVAIL,			/* Resources available */
	CSIO_SCSIE_RES_TIMEOUT,			/* Timedout waiting for
						 * for resoures.
						 */
	CSIO_SCSIE_ABORT,			/* Abort IO */
	CSIO_SCSIE_ABORTED,			/* IO Aborted */
	CSIO_SCSIE_TIMEOUT,			/* IO Timed out */
	CSIO_SCSIE_CLOSE,			/* Close exchange */
	CSIO_SCSIE_CLOSED,			/* Exchange closed */
	CSIO_SCSIE_DRVCLEANUP,			/* Driver wants to manually
						 * cleanup this I/O.
						 */
} csio_scsi_ev_t;

typedef enum {
	CSIO_LEV_ALL = 1,
	CSIO_LEV_LNODE,
	CSIO_LEV_RNODE,
	CSIO_LEV_LUN,
} csio_scsi_lev_t;

struct csio_scsi_level_data {
	csio_scsi_lev_t level;
	struct csio_rnode 	*rnode;
	struct csio_lnode 	*lnode;
	uint64_t		oslun;
};

static inline struct csio_ioreq *
csio_get_scsi_ioreq(struct csio_scsim *scm)
{
	struct csio_ioreq *ioreq = NULL;
	
	csio_deq_from_head(&scm->ioreq_freelist, &ioreq);
	if (ioreq)
		CSIO_DEC_STATS(scm, n_free_ioreq);

	return ioreq;
}

static inline void
csio_put_scsi_ioreq(struct csio_scsim *scm, struct csio_ioreq *ioreq)
{
	csio_enq_at_tail(&scm->ioreq_freelist, &ioreq->sm.sm_list);
	CSIO_INC_STATS(scm, n_free_ioreq);
}

static inline void
csio_put_scsi_ioreq_list(struct csio_scsim *scm, struct csio_list *reqlist,
			 int n)
{
	csio_enq_list_at_head(&scm->ioreq_freelist, reqlist);
	scm->stats.n_free_ioreq += n;
}

static inline struct csio_dma_buf *
csio_get_scsi_ddp(struct csio_scsim *scm)
{
	struct csio_dma_buf *ddp = NULL;
	
	csio_deq_from_head(&scm->ddp_freelist, &ddp);
	if (ddp)
		CSIO_DEC_STATS(scm, n_free_ddp);

	return ddp;
}

static inline void
csio_put_scsi_ddp(struct csio_scsim *scm, struct csio_dma_buf *ddp)
{
	csio_enq_at_tail(&scm->ddp_freelist, &ddp->list);
	CSIO_INC_STATS(scm, n_free_ddp);
}

static inline void
csio_put_scsi_ddp_list(struct csio_scsim *scm, struct csio_list *reqlist,
			 int n)
{
	csio_enq_list_at_tail(&scm->ddp_freelist, reqlist);
	scm->stats.n_free_ddp += n;
}

static inline void
csio_scsi_completed(struct csio_ioreq *ioreq, struct csio_list *cbfn_q)
{
	csio_post_event(&ioreq->sm, CSIO_SCSIE_COMPLETED);
	if (csio_elem_dequeued(ioreq))
		csio_enq_at_tail(cbfn_q, &ioreq->sm.sm_list);
}

static inline void
csio_scsi_aborted(struct csio_ioreq *ioreq, struct csio_list *cbfn_q)
{
	csio_post_event(&ioreq->sm, CSIO_SCSIE_ABORTED);
	csio_enq_at_tail(cbfn_q, &ioreq->sm.sm_list);
}

static inline void
csio_scsi_closed(struct csio_ioreq *ioreq, struct csio_list *cbfn_q)
{
	csio_post_event(&ioreq->sm, CSIO_SCSIE_CLOSED);
	csio_enq_at_tail(cbfn_q, &ioreq->sm.sm_list);
}

static inline void
csio_scsi_drvcleanup(struct csio_ioreq *ioreq)
{
	csio_post_event(&ioreq->sm, CSIO_SCSIE_DRVCLEANUP);
}

/*
 * csio_scsi_start_io - Kick starts the IO SM.
 * @req: io request SM.
 *
 * needs to be called with lock held.
 */
static inline csio_retval_t
csio_scsi_start_io(struct csio_ioreq *ioreq)
{
	csio_post_event(&ioreq->sm, CSIO_SCSIE_START_IO);
	return ioreq->drv_status;
}

/*
 * csio_scsi_start_tm - Kicks off the Task management IO SM.
 * @req: io request SM.
 *
 * needs to be called with lock held.
 */
static inline csio_retval_t
csio_scsi_start_tm(struct csio_ioreq *ioreq)
{
	csio_post_event(&ioreq->sm, CSIO_SCSIE_START_TM);
	return ioreq->drv_status;
}

/*
 * csio_scsi_abort - Abort an IO request
 * @req: io request SM.
 *
 * needs to be called with lock held.
 */
static inline csio_retval_t
csio_scsi_abort(struct csio_ioreq *ioreq)
{
	csio_post_event(&ioreq->sm, CSIO_SCSIE_ABORT);
	return ioreq->drv_status;
}

/*
 * csio_scsi_close - Close an IO request
 * @req: io request SM.
 *
 * needs to be called with lock held.
 */
static inline csio_retval_t
csio_scsi_close(struct csio_ioreq *ioreq)
{
	csio_post_event(&ioreq->sm, CSIO_SCSIE_CLOSE);
	return ioreq->drv_status;
}

bool csio_scsi_io_active(struct csio_ioreq *req);
void csio_scsi_gather_active_ios(struct csio_scsim *,
				 struct csio_scsi_level_data *,
				 struct csio_list *);
csio_retval_t csio_scsi_abort_io_q(struct csio_scsim *, struct csio_list *,
				   uint32_t);
void csio_scsi_cleanup_io_q(struct csio_scsim *, struct csio_list *);
csio_retval_t csio_scsim_cleanup_io(struct csio_scsim *, bool abort);
csio_retval_t csio_scsim_cleanup_io_lnode(struct csio_scsim *, 
					  struct csio_lnode *);

struct csio_ioreq *csio_scsi_cmpl_handler(struct csio_hw *, void *, uint32_t,
			       struct csio_fl_dma_buf *, void *, uint8_t **);
csio_retval_t csio_scsi_qconfig(struct csio_hw *);
csio_retval_t csio_scsim_init(struct csio_scsim *, struct csio_hw *);
void csio_scsim_exit(struct csio_scsim *);

/* DPC Worker */
void csio_scsi_worker(void *data);

#endif /* __CSIO_SCSI_H__ */
