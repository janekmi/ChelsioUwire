/*
 *  Copyright (C) 2008-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: This file implements the common rnode functions.
 *
 */

#include <csio_hw.h>
#include <csio_lnode.h>
#include <csio_rnode.h>

/**
 * csio_rn_lookup - Finds the rnode with the given flowid
 * @ln - lnode
 * @flowid - flowid.
 *
 * Does the rnode lookup on the given lnode and flowid.If no matching entry
 * found, NULL is returned.
 */
struct csio_rnode *
csio_rn_lookup(struct csio_lnode *ln, uint32_t flowid)
{
	struct csio_rnode *rnhead = (struct csio_rnode *) &ln->rnhead;
	struct csio_list *tmp;
	struct csio_rnode *rn;

	csio_list_for_each(tmp, &rnhead->rnlist) {
		rn = (struct csio_rnode *) tmp;
		if (rn->flowid == flowid)
			return rn;
	}

	return NULL;
}

/**
 * csio_get_rn - Gets rnode with the given flowid
 * @ln - lnode
 * @flowid - flow id.
 *
 * Does the rnode lookup on the given lnode and flowid. If no matching
 * rnode found, then new rnode with given npid is allocated and returned.
 */
struct csio_rnode *
csio_get_rn(struct csio_lnode *ln, uint32_t flowid)
{
	struct csio_hw *hw = csio_lnode_to_hw(ln);
	struct csio_rnode *rn;

	rn = csio_rn_lookup(ln, flowid);
	if (!rn) {

		if (!csio_hw_to_ops(hw)->os_alloc_rnode)
			return NULL;

		rn = csio_hw_to_ops(hw)->os_alloc_rnode(ln);
		if (!rn)
			return NULL;

		rn->flowid = flowid;
	} else {
		/* REVISIT */
		/*
		 * We found an rnode, do we need to call csio_rnf_init
		 * on that rnode here? Guess not..
		 * Calling init will change state and thats not what we want.
		 * Instead the State machine will handle appropriate events.
		 */
	}

	return rn;
}

/**
 * csio_put_rn - Frees the given rnode
 * @ln - lnode
 * @flowid - flow id.
 *
 * Does the rnode lookup on the given lnode and flowid. If no matching
 * rnode found, then new rnode with given npid is allocated and returned.
 */
void
csio_put_rn(struct csio_lnode *ln, struct csio_rnode *rn)
{
	struct csio_hw *hw = csio_lnode_to_hw(ln);
#ifdef __CSIO_DEBUG__
	struct csio_rnode_fcoe *rnf = csio_rnode_to_fcoe(rn);
	if (csio_is_fcoe(hw))
		CSIO_DB_ASSERT(csio_is_rnf_uninit(rnf) != 0);
#endif	

	/* Free rnf */	
	if (csio_hw_to_ops(hw)->os_free_rnode)
		csio_hw_to_ops(hw)->os_free_rnode(rn);

	return;
}

/**
 * csio_get_next_rnode - Gets next rnode.
 * @ln: lnode module
 * @ssni: Given ssni index
 * This routine searches rnode list of an given lnode returns the next rnode
 * from given ssni index.
 * If given ssni is set to CSIO_INVALID_IDX, it will return first rnode.
 */
struct csio_rnode *csio_get_next_rnode(struct csio_lnode *ln, uint32_t ssni)
{
	struct csio_rnode *rnhead = (struct csio_rnode *) &ln->rnhead;
	struct csio_list *cur_rn, *next_rn;
	struct csio_rnode *rn;

	csio_list_for_each_safe(cur_rn, next_rn, &rnhead->rnlist) {
		rn = (struct csio_rnode *) cur_rn;
		if (ssni == CSIO_INVALID_IDX) {
			return rn;
		}

		if (rn->flowid == ssni && next_rn != &rnhead->rnlist) {
			rn = (struct csio_rnode *) next_rn;
			return rn;
		}
	}

	return NULL;
}

/*
 * csio_rnode_init - Initialize rnode.
 * @rn: RNode
 * @ln: Associated lnode
 *
 * Caller is responsible for holding the lock. The lock is required
 * to be held for inserting the rnode in ln->rnhead list.
 */
csio_retval_t
csio_rnode_init(struct csio_rnode *rn, struct csio_lnode *ln)
{
	int rv = -CSIO_INVAL;
	struct csio_hw *hw = ln->hwp;

	csio_rnode_to_lnode(rn) = ln;

#ifdef __CSIO_TARGET__
	rn->ssn_hdl = NULL;
	csio_head_init(&rn->active_q);
	rn->eq_idx = rn->iq_idx = -1;
#endif /* __CSIO_TARGET__ */

	if (csio_is_fcoe(hw)) {
		csio_rnode_to_fcoe(rn)->rn = rn;
		if (csio_rnf_init(csio_rnode_to_fcoe(rn)))
			goto err;
	} else {
#ifdef __CSIO_FOISCSI_ENABLED__
		csio_rnode_to_iscsi(rn)->rn = rn;
		rv = csio_rni_init(csio_rnode_to_iscsi(rn));
		if (rv)
			goto err;
#endif
	}

	/* Add rnode to list of lnodes->rnhead */
	csio_enq_at_tail(&ln->rnhead, rn);

	return CSIO_SUCCESS;
err:
	csio_rnode_to_lnode(rn) = NULL;
	return rv;
	
}

void csio_rnode_exit(struct csio_rnode *rn)
{
	struct csio_lnode *ln = rn->lnp;
	struct csio_hw *hw = ln->hwp;

	csio_deq_elem(rn);

	if (csio_is_fcoe(hw)) {
		csio_rnf_exit(csio_rnode_to_fcoe(rn));
	} else {
#ifdef __CSIO_FOISCSI_ENABLED__
		csio_rni_exit(csio_rnode_to_iscsi(rn));
#endif
	}

#ifdef __CSIO_TARGET__
	rn->ssn_hdl = NULL;
	CSIO_DB_ASSERT(csio_list_empty(&rn->active_q));
	rn->eq_idx = rn->iq_idx = -1;
#endif /* __CSIO_TARGET__ */
	
	return;
}
