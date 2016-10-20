/*
 *  Copyright (C) 2008-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: This is the FCoE ELS/CT module's header file.
 *
 */

#ifndef __CSIO_ELS_CT_H__
#define __CSIO_ELS_CT_H__

#include <csio_defs.h>
#include <csio_wr.h>

#define ECM_MIN_TMO             1000    /* Minimum timeout value for req */

enum {
	CSIO_MGMT_EQ_WRSIZE = 512,
	CSIO_MGMT_IQ_WRSIZE = 128,
	CSIO_MGMT_EQLEN = 64,	/* REVISIT */
	CSIO_MGMT_IQLEN = 64,	/* REVISIT */
	CSIO_MGMT_FLLEN = 64
};

#define CSIO_MGMT_EQSIZE	(CSIO_MGMT_EQLEN * CSIO_MGMT_EQ_WRSIZE)
#define CSIO_MGMT_IQSIZE	(CSIO_MGMT_IQLEN * CSIO_MGMT_IQ_WRSIZE)
#define CSIO_MGMT_QSIZE		(CSIO_MGMT_IQSIZE + CSIO_MGMT_EQSIZE)

/* mgmt module stats */
struct csio_mgmtm_stats {
	uint32_t	n_abort_req;		/* Total abort request */
	uint32_t	n_abort_rsp;		/* Total abort response */
	uint32_t	n_close_req;		/* Total close request */
	uint32_t	n_close_rsp;		/* Total close response */
	uint32_t	n_err;			/* Total Errors */
	uint32_t	n_drop;			/* Total request dropped */
	uint32_t	n_active;     		/* Count of active_q */
	uint32_t	n_cbfn;     		/* Count of cbfn_q */
};

/* MGMT module */
struct csio_mgmtm {
	struct	csio_hw		*hw;		/* Pointer to HW moduel */
	int			eq_idx;		/* Egress queue index */
	int			iq_idx;		/* Ingress queue index */
	int			msi_vec;	/* OS assinged MSI vector */
	struct csio_list	active_q;	/* Outstanding ELS/CT */
	struct csio_list	abort_q;	/* TODO:Outstanding abort req */
	struct csio_list	cbfn_q;		/* Completion queue */
	struct csio_list	mgmt_req_freelist; /* Free poll of reqs */	
						/* ELSCT request freelist*/
	csio_timer_t		mgmt_timer;	/* MGMT timer */
	csio_work_t		mgmt_work;	/* Worker thread for ELS/CT */
	struct csio_mgmtm_stats stats;		/* ELS/CT stats */
	csio_kref_t		kref;		/* Reference count */

};

#define csio_mgmt_eq_idx(mgm)		((mgm)->eq_idx)
#define csio_mgmt_iq_idx(mgm)		((mgm)->iq_idx)


enum csio_oss_error
csio_mgmt_req_lookup(struct csio_mgmtm *mgmtm, struct csio_ioreq *io_req); 

csio_retval_t
csio_map_fw_retval(uint8_t fw_ret);

void csio_mgmtm_cleanup(struct csio_mgmtm *);

/* Entry points */
csio_retval_t csio_mgmtm_init(struct csio_mgmtm *mgmtm, struct csio_hw *hw);
void csio_mgmtm_exit(struct csio_mgmtm *);

#endif /* __CSIO_ELS_CT_H__ */
