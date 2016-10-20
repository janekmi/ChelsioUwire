/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/*
 * Description:
 * 	This is chfcoe_io.h header file, contains IO request related defines.
 */
#ifndef __CHFCOE_IO_H__
#define __CHFCOE_IO_H__
#include "chfcoe_adap.h"
#include "chfcoe_port.h"
#include "chfcoe_rnode.h"
#include "chfcoe_ddp.h"
#ifdef __CSIO_TARGET__
#include "csio_sal_api.h"
#endif
#define SCSI_ABORT 0
#define SCSI_CLOSE 1

#define CHFCOE_CMD_DATA_READ  0
#define CHFCOE_CMD_DATA_WRITE 1
#define CHFCOE_CMD_DATA_NONE  2

#define CHFCOE_TGTQ_POLL_MS               2000

/* IO request State Machine states */
typedef enum {
	CHFCOE_IO_ST_UNINIT = 0,	/* UNINIT state */
	CHFCOE_IO_ST_ACTIVE,		/* ACTIVE state */
	CHFCOE_IO_ST_RRQ,		/* RRQ state */
	CHFCOE_IO_ST_AWAIT_RRQ,		/* AWAIT RRQ state */
	CHFCOE_IO_ST_SAL_ABRT_SENT,     /* ABORT sent to SCST */
	CHFCOE_IO_ST_SAL_ABRT_DONE,     /* ABORT DONE */
	CHFCOE_IO_ST_DATA_XFER,		/* DATA Transfer state, Target mode */
	CHFCOE_IO_ST_SAL_DATA_SENT,	/* DATA Transfer DONE in Target mode */
	CHFCOE_IO_ST_SAL_CMD_SENT,	/* SCSI command sent to SAL state */
	CHFCOE_IO_ST_SAL_TM_SENT,       /* TM request sent to SAL (non-abort)*/
	CHFCOE_IO_ST_DRAIN,		/* DRAIN IO state */
	CHFCOE_IO_ST_RSP_SENT,		/* Response sent state*/
	CHFCOE_IO_ST_SAL_DONE_SENT,
} chfcoe_ioreq_state_t;

typedef enum {
	CHFCOE_IO_EVT_START = 0,	/* IO Start event */
	CHFCOE_IO_EVT_COMPLETE,		/* IO successfully completed event */
	CHFCOE_IO_EVT_ABORT,		/* IO timed-out, aborting(initiator) */
	CHFCOE_IO_EVT_ABORTED,		/* Aborted the IO */
	CHFCOE_IO_EVT_SEND_RRQ,		/* Send RRQ */
	CHFCOE_IO_EVT_XFER_DONE,	/* In Target, for Read Cmd to SAL */
	CHFCOE_IO_EVT_SAL_XMIT_ACC,	/* In Target, for Write Cmd from SAL */
	CHFCOE_IO_EVT_CLOSE,		/* IO closed (in Link Down/LOGO etc) */
} chfcoe_ioreq_evt_t;

typedef struct chfcoe_ioreq {
	struct chfcoe_list	list;		/* Pointer to IO req list */
	uint8_t			txq;
	uint8_t			state;		/* State of IO req */
#ifdef __CSIO_TARGET__
	/* Target Mode Specific */
	csio_sal_req_t		sreq;           /* Corresponding SAL req */
#endif
	uint32_t		req_len;	/* Requested data len */
	uint32_t		xfrd_len;	/* Transferred data len */
	uint32_t		max_xfer_len;	/* Max transfer len */

	uint64_t		lun;		/* LUN for Task mgmt functions*/
	/* End of Target Mode specific */
	void			*scratch1;	/* Scratch area 1. */
	void			*xchg;
	struct chfcoe_ddp 	ddp;
} chfcoe_ioreq_t;

#define chfcoe_ioreq_size	(sizeof(struct chfcoe_ioreq))

#define chfcoe_ioreq_set_state(__req, __state)	((__req)->state = (__state))
#define chfcoe_ioreq_get_state(__req)		((__req)->state)
#define chfcoe_ioreq_is_state(__req, __state)	((__req)->state == (__state))

/* References */
/* The SCSI server private command is in scratch1 */
#define chfcoe_tgt_set_sal_ref(__t, __c) 	((__t)->scratch1 = (__c))
#define chfcoe_tgt_clear_sal_ref(__t) 		((__t)->scratch1 = NULL)
#define chfcoe_tgt_get_sal_ref(__t)		((__t)->scratch1)
#define chfcoe_treq_sal_has_ref(__t)		((__t)->scratch1 != NULL)

#define chfcoe_tgt_set_fw_ref(__t, __f)	((__t)->req_flowid = (__f))
#define chfcoe_tgt_clear_fw_ref(__t)	((__t)->req_flowid = CSIO_INVALID_IDX)
#define chfcoe_tgt_get_fw_ref(__t)	((__t)->req_flowid)
#define chfcoe_treq_fw_has_ref(__t)    ((__t)->req_flowid != CSIO_INVALID_IDX)

#define CHFCOE_BLOCK_IO_SIZE		512

/* chfcoe_ioreq Flags */
#define CHFCOE_TREQF_AUTO_RSP		0x1	/* Is auto-reponse set? */
#define CHFCOE_TREQF_CHAIN		0x2     /* This tgtreq has > 1 WR */

#define chfcoe_treq_set_flag(__t, __f)            ((__t)->flags |= (__f))
#define chfcoe_treq_clear_flag(__t, __f)          ((__t)->flags &= ~(__f))
#define chfcoe_treq_is_flag_set(__t, __f)         ((__t)->flags & (__f))

chfcoe_retval_t chfcoe_tgt_register_session(struct chfcoe_rnode *rn);
void chfcoe_tgt_unregister_session(struct chfcoe_rnode *rn/*, int work*/);
chfcoe_retval_t chfcoe_tgt_register(struct chfcoe_lnode *ln);
void chfcoe_tgt_unregister(struct chfcoe_lnode *ln);
int chfcoe_tgt_cleanup_io_rn(struct chfcoe_rnode *rn);
void chfcoe_sal_sess_unreg_done(void *data);
void chfcoe_tgt_tm_close_rn_reqs(struct chfcoe_rnode *rn,
		uint64_t lun, uint8_t match_lun);
void chfcoe_err_work_fn_data(void *data);
void chfcoe_tgtreq_cleanup(void *data);

void chfcoe_rmmod_rnode_lookup(struct chfcoe_lnode *lnode, int num);
#endif /* __CHFCOE_IO_H__ */
