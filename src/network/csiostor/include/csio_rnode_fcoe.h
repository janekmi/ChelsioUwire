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

#ifndef __CSIO_RNODE_FCOE_H__
#define __CSIO_RNODE_FCOE_H__

#include <csio_defs.h>
#include <csio_fcoe_proto.h>

/* State machine evets */
typedef enum {
	CSIO_RNFE_NONE = (uint32_t)0,			/* None */
	CSIO_RNFE_LOGIN,				/* Start discovery */
	CSIO_RNFE_DO_ADISC,
	CSIO_RNFE_ADISC_ACC,				/* ADISC accepted */
	CSIO_RNFE_ADISC_REJ,				/* ADISC rejected */
#if 0
	/* Should be have PLOGI_DONE as one event, or these 2 separate evts? */
	CSIO_RNFE_PLOGI_ACC,				/* PLOGI accepted */
	CSIO_RNFE_PLOGI_REJ,				/* PLOGI rejected */
#endif
	CSIO_RNFE_LOGGED_IN,				/* [N/F]Port login
							 * complete. 
							 */
	CSIO_RNFE_PRLI_DONE,				/* PRLI completed */
	CSIO_RNFE_PLOGI_RECV,				/* Received PLOGI */
	CSIO_RNFE_PRLI_RECV,				/* Received PLOGI */
	CSIO_RNFE_LOGO_RECV,				/* Received LOGO */
	CSIO_RNFE_PRLO_RECV,				/* Received PRLO */
	CSIO_RNFE_DOWN,					/* Rnode is down */
	CSIO_RNFE_CLOSE,				/* Close rnode */
	CSIO_RNFE_NAME_MISSING,				/* Rnode name missing
							 * in name server.
							 */
	CSIO_RNFE_MAX_EVENT,
} csio_rnf_ev_t;

/* FCoE rnode stats */
struct csio_rnode_fcoestats {
	uint32_t	n_err;		/* error */
	uint32_t	n_err_inval;	/* invalid parameter */
	uint32_t	n_err_nomem;	/* error nomem */
	uint32_t	n_evt_unexp;	/* unexpected event */
	uint32_t	n_evt_drop;	/* unexpected event */
	uint32_t  	n_evt_fw[RSCN_DEV_LOST]; 	/* fw events */
	csio_rnf_ev_t   n_evt_sm[CSIO_RNFE_MAX_EVENT]; 	/* State m/c events */
};

/* FcoE  rnode params */
struct csio_rnode_fcoeparams {
	uint32_t	param1;
	uint32_t	param2;
};

/* Defines for rnode role */
#define	CSIO_RNFR_INITIATOR	0x1 
#define	CSIO_RNFR_TARGET	0x2
#define CSIO_RNFR_FABRIC	0x4
#define	CSIO_RNFR_NS		0x8
#define CSIO_RNFR_NPORT		0x10

struct csio_rnode_fcoe {
	struct csio_sm		sm;			/* State machine - 
							 * should be the 
							 * 1st member
							 */
	struct csio_rnode 	*rn;			/* owning rnode */
	struct csio_list	os_cmpl_q;		/* SCSI IOs 
							 * pending to completed
							 * to OS. 
							 */
	void (*disc_done)(struct csio_rnode_fcoe *, int);
							/* Callback from
							 * rnode to lnode
							 * to indicate
							 * completion of
							 * discovery SM.
							 */
	/* FC identifiers for remote node */
	uint32_t		nport_id;
	uint16_t		fcp_flags;		/* FCP Flags */
	uint8_t			cur_evt;		/* Current event */
	uint8_t			prev_evt;		/* Previous event */
	uint32_t		role;			/* Fabric/Target/
							 * Initiator/NS
							 */
	struct fcoe_rdev_entry		*rdev_entry;	/* Rdev entry */
	struct csio_service_parms	rn_sparm;

	struct csio_rnode_fcoestats  	stats;		/* FCoE rnode stats */
	struct csio_rnode_fcoeparams 	tparams; 	/* FCoE rnode params */
};

#define csio_rnf_flowid(rnf)			(rnf->rn->flowid)
#define csio_rnf_wwpn(rnf)			(rnf->rn_sparm.wwpn)
#define csio_rnf_wwnn(rnf)			(rnf->rn_sparm.wwnn)

int csio_is_rnf_ready(struct csio_rnode_fcoe *rnf);
int csio_is_rnf_uninit(struct csio_rnode_fcoe *rnf);

csio_retval_t csio_rnf_remove(struct csio_rnode_fcoe *);
csio_retval_t csio_rnf_close(struct csio_rnode_fcoe *);
void csio_rnf_devloss_handler(struct csio_rnode_fcoe *);
csio_retval_t csio_rnf_init(struct csio_rnode_fcoe *);
void csio_rnf_exit(struct csio_rnode_fcoe *);

void
csio_rnf_fwevt_handler(struct csio_rnode_fcoe *rnf, uint8_t fwevt);
void csio_rnf_stateto_str(struct csio_rnode_fcoe *rnf, int8_t *str); 
struct csio_rnode_fcoe * 
csio_rnf_confirm_rnode(struct csio_lnode_fcoe *lnf, uint32_t rdev_flowid, 
			struct fcoe_rdev_entry *rdevp);
struct csio_rnode_fcoe * 
csio_rnf_lookup_portid(struct csio_lnode_fcoe *lnf, uint32_t portid);
struct csio_rnode_fcoe *
csio_rnf_lookup_wwpn(struct csio_lnode_fcoe *lnf, uint8_t *wwpn);

csio_retval_t
csio_fcoe_get_rnode_info(struct csio_hw *hw, void *buffer, uint32_t buffer_len);
csio_retval_t
csio_fcoe_get_rnode_info_by_fcid(struct csio_hw *hw, 
			void *buffer, uint32_t buffer_len);
const char *csio_rnf_evt_name(csio_rnf_ev_t evt); 
const char *csio_rnf_fwevt_name(uint32_t evt); 

#endif /* ifndef __CSIO_RNODE_FCOE_H__ */
