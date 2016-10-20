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

#ifndef __CSIO_RNODE_H__
#define __CSIO_RNODE_H__

#include <csio_rnode_fcoe.h>
#include <csio_defs.h>

#ifdef __CSIO_FOISCSI_ENABLED__
#include <csio_rnode_foiscsi.h>
#endif

/* Common rnode stats */
struct csio_rnode_stats {
	uint32_t		n_lun_rst;	/* Number of resets of
						 * of LUNs under this
						 * target
						 */
	uint32_t		n_lun_rst_fail;	/* Number of LUN reset
						 * failures.
						 */
	uint32_t		n_tgt_rst;	/* Number of target resets */
	uint32_t		n_tgt_rst_fail;	/* Number of target reset
						 * failures.
						 */
};

/* Common rnode params */
struct csio_rnode_params {
	uint32_t		resvd1;
};

struct csio_rnode {
	struct csio_list	rnlist;		/* Rnode list - should be the 
						 * first member in this 
						 * structure.
						 */
	struct csio_lnode	*lnp;		/* Pointer to owning Lnode */
	void 			*os_rnp;	/* pointer to OS dependent 
						 * object 
						 */ 
	uint32_t		flowid;		/* Firmware ID */
#ifdef __CSIO_TARGET__
	csio_ssn_handle_t	ssn_hdl;        /* Session handle */
	struct csio_list	active_q;	/* Active I/O queue for this
						 * initiator.
						 */
	int			eq_idx;		/* Associated egress q */
	int			iq_idx;		/* Associated ingress q */
#endif /* __CSIO_TARGET__ */

	/* Transport module */
	union {					/* Transport Rnode module */
		struct csio_rnode_fcoe	rnf;
#ifdef __CSIO_FOISCSI_ENABLED__		
		struct csio_rnode_iscsi	rni;
#endif
	} un;

	struct csio_rnode_stats	stats; 		/* Common rnode stats */
	struct csio_rnode_params params; 	/* Common rnode params */
};

/* Common->OS events */
typedef enum {
	/* FCOE rnode events */
	CSIO_RNF_OSE_OFFLINE = 1,
	CSIO_RNF_OSE_ONLINE,

	/* iSCSI rnode events */

} csio_rn_os_evt_t;

#define csio_rnode_to_os(rn)	((rn)->os_rnp)
#define csio_rnode_to_lnode(rn)	((rn)->lnp)
#define csio_rnode_to_fcoe(rn)	(&(rn)->un.rnf)
#define csio_rnode_to_iscsi(rn)	(&(rn)->un.rni)

struct csio_rnode *csio_rn_lookup(struct csio_lnode *ln, uint32_t flowid);
struct csio_rnode *csio_get_rn(struct csio_lnode *ln, uint32_t flowid);
void csio_put_rn(struct csio_lnode *ln, struct csio_rnode *rn);
struct csio_rnode *csio_get_next_rnode(struct csio_lnode *ln, uint32_t ssni);
csio_retval_t csio_rnode_init(struct csio_rnode *, struct csio_lnode *);
void csio_rnode_exit(struct csio_rnode *);

#endif /* ifndef __CSIO_RNODE_H__ */
