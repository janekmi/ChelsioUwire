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
 * 	This is chfcoe_xchg.h header file, contains exchange/seq related 
 *	defines.
 *
 * Author:
 * 	Praveen M <praveenm@chelsio.com>
 */
#ifndef __CHFCOE_XCHG_H__
#define __CHFCOE_XCHG_H__

#include "chfcoe_adap.h"
#include "chfcoe_lnode.h"
#include "chfcoe_io.h"

#define CHFCOE_XCHG_ERR_TIMEOUT1	5000
#define CHFCOE_XCHG_ERR_TIMEOUT2	15000

typedef struct chfcoe_xchg_cb {
	uint32_t		sid;		/* Source ID */
	uint32_t		did;		/* Destination ID */
	uint16_t		ox_id;		/* Exchange ID */
	uint16_t		rx_id;		/* Receive Exchange ID */
	uint16_t		seq_id;		/* Exchange Sequence id */
	uint32_t		xferd_len;	/* Transferred Length */
	uint8_t			port;		/* Port Number */
	uint16_t		seq_cnt;	/* Exchange sequence counter */
	uint16_t 		xid;		/* Exchange bit */
	unsigned int            worker_id;
	void		 	*xchg_refcnt;	/* xchg ref count*/
	struct chfcoe_lnode     *ln;		/* lnode pointer */
	struct chfcoe_rnode     *rn;		/* rnode pointer */
	struct chfcoe_ioreq	*tgtreq;
	unsigned int		timeo;		/* timeout */
	unsigned long		state;		/* Exchange Status bits */
	void			*xchg_mutex;	/* mutex */
	chfcoe_dwork_t		*xchg_work;      /* xchg_work */
	void                	(*cbfn)(chfcoe_fc_buffer_t *, void *); /* callback function */
	void 			*cbarg;		/* callback argument */
	void 			*cbarg1;	/* callback argument */

} chfcoe_xchg_cb_t;

#define chfcoe_xchg_cb_size	(sizeof(struct chfcoe_xchg_cb) + os_atomic_size \
				+ os_mutex_size + chfcoe_dwork_size)

#define chfcoe_xchg_ioreq_size	(chfcoe_xchg_cb_size + chfcoe_ioreq_size)
/* Exchange state */
typedef enum {
	CHFCOE_XCHG_ST_ACTIVE = 0,
	CHFCOE_XCHG_ST_FREED,
	CHFCOE_XCHG_ST_ABORTED,
	CHFCOE_XCHG_ST_FIRST_FRAME,
	CHFCOE_XCHG_ST_FCP,
	CHFCOE_XCHG_ST_DDP,
	CHFCOE_XCHG_ST_W_XFER,
	CHFCOE_XCHG_ST_ERR_TIMEOUT1,
}chfcoe_xchg_state_t;

#define CHFCOE_XID_TO_XCHG(rn, xid)	\
	((chfcoe_xchg_cb_t *) rn->xchg_tbl[xid])

static inline void chfcoe_xchg_rst_seq(chfcoe_xchg_cb_t *xchg)	
{	
	xchg->seq_id = 0;
	xchg->seq_cnt = 0;
}

static inline void chfcoe_xchg_next_seq(chfcoe_xchg_cb_t *xchg)
{	
	xchg->seq_id++;
	xchg->seq_cnt = 0;
}

static inline void chfcoe_xchg_mem_init(chfcoe_xchg_cb_t *xchg, uint16_t xid)
{
	chfcoe_memset(xchg, 0, chfcoe_xchg_ioreq_size);
	xchg->xchg_refcnt = CHFCOE_PTR_OFFSET(xchg, (sizeof(struct chfcoe_xchg_cb)));
	xchg->xchg_mutex = CHFCOE_PTR_OFFSET(xchg, (sizeof(struct chfcoe_xchg_cb) + os_atomic_size));
	xchg->xchg_work = CHFCOE_PTR_OFFSET(xchg, (sizeof(struct chfcoe_xchg_cb)
				+ os_atomic_size + os_mutex_size));
	xchg->xchg_work->work = CHFCOE_PTR_OFFSET(xchg, (sizeof(struct chfcoe_xchg_cb)
				+ os_atomic_size + os_mutex_size + sizeof(chfcoe_dwork_t)));
	chfcoe_atomic_set(xchg->xchg_refcnt, 1);
	chfcoe_mutex_init(xchg->xchg_mutex);
	xchg->xid = xid;
	xchg->tgtreq = (chfcoe_ioreq_t *)((unsigned char *)(xchg) + chfcoe_xchg_cb_size);
	chfcoe_set_bit(CHFCOE_XCHG_ST_ACTIVE, &xchg->state);
}


static inline chfcoe_xchg_cb_t *__chfcoe_get_xchg(struct chfcoe_rnode *rn, uint16_t *xid)
{
	chfcoe_xchg_cb_t *xchg = NULL;
	int xchg_xid;

	xchg_xid = chfcoe_find_next_zero_bit(rn->fc_xchg_bm, CHFCOE_MAX_XID, 0);
	if (xchg_xid >= CHFCOE_MAX_XID) {
		return NULL;
	}
	chfcoe_set_bit(xchg_xid, rn->fc_xchg_bm);

	*xid = xchg_xid;
	xchg = CHFCOE_XID_TO_XCHG(rn, (*xid));

	return xchg;
}	


static inline chfcoe_xchg_cb_t *chfcoe_get_xchg(struct chfcoe_rnode *rn)
{
	chfcoe_xchg_cb_t *xchg = NULL;
	uint16_t xid;

	chfcoe_spin_lock(rn->lock);
	xchg = __chfcoe_get_xchg(rn, &xid);
	chfcoe_spin_unlock(rn->lock);

	if (chfcoe_unlikely(!xchg)) {
		chfcoe_err(0, "rnode:0x%x get xchg failed\n", rn->nport_id);
		return NULL;
	}

	chfcoe_xchg_mem_init(xchg, xid);
	
	return xchg;
}

static inline void __chfcoe_free_xchg(chfcoe_xchg_cb_t *xchg)
{
	xchg->ox_id = 0;
	xchg->rx_id = 0;
	xchg->sid = 0;
	xchg->did = 0;
	xchg->state = 0;
	xchg->cbarg = NULL;
	xchg->cbfn = NULL;
	chfcoe_clear_bit(xchg->xid, xchg->rn->fc_xchg_bm);
}

static inline int __chfcoe_put_xchg(chfcoe_xchg_cb_t *xchg)
{
	if (chfcoe_likely(chfcoe_atomic_dec_and_test(xchg->xchg_refcnt))) {
		__chfcoe_free_xchg(xchg);
		return CHFCOE_SUCCESS;
	}
	return CHFCOE_RETRY;
}

static inline int chfcoe_put_xchg(chfcoe_xchg_cb_t *xchg)
{
	struct chfcoe_rnode *rn = xchg->rn;
	int rv;

	chfcoe_spin_lock(rn->lock);
	rv = __chfcoe_put_xchg(xchg);
	chfcoe_spin_unlock(rn->lock);

	return rv;
}

void chfcoe_err_work_fn_control(void *data);

static inline void chfcoe_xchg_init(chfcoe_xchg_cb_t *xchg,
		void (*cbfn)(chfcoe_fc_buffer_t *, void *), void *data,
		struct chfcoe_rnode *rn, uint32_t sid, uint32_t did,
		uint16_t ox_id, uint16_t rx_id, uint8_t control,
		unsigned int worker_id)		
{
	xchg->cbarg = data;

	if (control)
		chfcoe_init_delayed_work(xchg->xchg_work, chfcoe_err_work_fn_control, xchg);
	else {
		chfcoe_init_delayed_work(xchg->xchg_work, chfcoe_err_work_fn_data, xchg->cbarg);
		chfcoe_set_bit(CHFCOE_XCHG_ST_FCP, &xchg->state);
	}
	
	xchg->cbfn = cbfn;
	xchg->rn = rn;
	xchg->ln = rn->lnode;
	xchg->sid = sid;
	xchg->did = did;
	xchg->ox_id = ox_id;
	xchg->rx_id = rx_id;
	xchg->worker_id = worker_id;
	
}

int chfcoe_xchg_build_send(struct chfcoe_lnode *ln, chfcoe_fc_buffer_t *,
		void (*cbfn)(chfcoe_fc_buffer_t *, void *), void *, int timeo);

int chfcoe_xchg_build(struct chfcoe_lnode *ln, chfcoe_fc_buffer_t *, 
		chfcoe_xchg_cb_t *xchg);
int chfcoe_xchg_send(struct chfcoe_lnode *ln, struct chfcoe_rnode *rn,
		chfcoe_fc_buffer_t *, chfcoe_xchg_cb_t *xchg);
void chfcoe_xchg_recv(struct chfcoe_lnode *ln, chfcoe_fc_buffer_t *);
void chfcoe_xchg_timer_sched(chfcoe_xchg_cb_t *xchg);
#endif /* __CHFCOE_XCHG_H__ */
