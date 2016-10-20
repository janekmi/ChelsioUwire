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

#ifndef __CSIO_RNODE_FOISCSI_H__
#define __CSIO_RNODE_FOISCSI_H__

#include <csio_defs.h>
#include <csio_mb_foiscsi.h>
#include <csio_foiscsi_persistent.h>

typedef enum {
	CSIO_RNIE_FREE = 1,

	CSIO_RNIE_INIT,

	CSIO_RNIE_IN_LOGIN,
	CSIO_RNIE_LOGGED_IN,
	CSIO_RNIE_LOGIN_FAILED,

	CSIO_RNIE_IN_LOGOUT,
	CSIO_RNIE_LOGGED_OUT,
	CSIO_RNIE_LOGOUT_FAILED,

	CSIO_RNIE_IN_RECOVERY,
	CSIO_RNIE_RECOVERED,
	CSIO_RNIE_RECOVERY_TIMEDOUT,

	CSIO_RNIE_IN_SCSI,
	CSIO_RNIE_SCSI_BLOCKED,
	CSIO_RNIE_SCSI_UNBLOCKED,
	CSIO_RNIE_SCSI_SCAN_FINISHED,
	
	CSIO_RNIE_IN_CLEANUP,
	CSIO_RNIE_CLEANUP_COMPL,
}csio_rni_evt_t;

#define CSIO_RNI_SCAN_PENDING		0x01


/* This represents an ISCSI target session*/
struct csio_rnode_iscsi {

	struct csio_sm		sm;
	
	struct csio_rnode	*rn;		/* Owning rnode */
	struct csio_rni_os_ops	*os_ops;	/* Os callbacks */

	u8 			cached_evnt;
	u8 			sess_type;
	u8			wr_status;
	u8			io_state;

	u8 			*disc_resp_buf;
	
	u8			flags;
	u8 			disc_comp;
	u16			r1;

	/*
	 * unique handle identifying the sesion.
	 */
	int 			sess_handle;
	int 			sess_id;
	unsigned int 		io_handle;
	unsigned int 		node_id;

	unsigned int  		disc_resp_len;
	unsigned int 		disc_buf_offset;
	
	struct foiscsi_login_info	login_info;
}__attribute__((aligned(sizeof(unsigned long))));


/* When u get a fw evt(RDEV_WR) then allocate an rnode and set all the target
 * information got from that event in the sess member. queue the rnode into
 * ln->rnhead list. This is already done in fcoe..do iscsi specific stuff.
 *
 * See to it that rnodes allocated doesnt exceed MAX supported targets.
 */

struct csio_rni_os_ops {
	void (*os_rni_reg_rnode)(struct csio_rnode_iscsi *);
	void (*os_rni_unreg_rnode)(struct csio_rnode_iscsi *);
};

csio_retval_t csio_rni_init(struct csio_rnode_iscsi *);
void csio_rni_exit(struct csio_rnode_iscsi *);

void
csio_rni_fwevt_handler(struct csio_rnode_iscsi *rni,
					   struct fw_rdev_wr *rdev_wr);

int csio_rnism_in_ready(struct csio_rnode_iscsi *);
int csio_rnism_in_uninit(struct csio_rnode_iscsi *);
int csio_rnism_in_recovery(struct csio_rnode_iscsi *);
int csio_rnism_in_cleanup(struct csio_rnode_iscsi *);
int csio_rnism_in_logout(struct csio_rnode_iscsi *);
int csio_rnism_in_login(struct csio_rnode_iscsi *);

#if 0
void csio_rnis_in_logout(struct csio_rnode_iscsi *, csio_rni_evt_t);
void csio_rnis_in_cleanup(struct csio_rnode_iscsi *, csio_rni_evt_t);
void csio_rnis_ready(struct csio_rnode_iscsi *rni, csio_rni_evt_t);
void csio_rnis_in_login(struct csio_rnode_iscsi *, csio_rni_evt_t);
void csio_rnis_uninit(struct csio_rnode_iscsi *, csio_rni_evt_t);
#endif

#define csio_iscsi_to_rnode(rni) ((rni)->rn)

#endif /* ifndef __CSIO_RNODE_FOISCSI_H__ */
