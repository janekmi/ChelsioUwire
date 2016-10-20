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

#ifndef __CSIO_LNODE_FOISCSI_H__
#define __CSIO_LNODE_FOISCSI_H__

#include <csio_defs.h>
#include <csio_hw.h>
#include <csio_mb_foiscsi.h>
#include <csio_foiscsi_persistent.h>
#include <csio_foiscsi_ioctl.h>

#define INVALID_NODE_ID		0xffffffff
#define	CSIO_FOISCSI_TOT_QSIZE	65536 	/* REVISIT */
#define CSIO_FOISCSI_NUMQ		0	/* REVISIT */
#define CSIO_FOISCSI_NEQ		1 /* #of egress queues for full iscsi ofld */
#define CSIO_FOISCSI_NIQ		0 /* #of ingress queues for full iscsi ofld */

#define	NET_CFG_TMO				10000
#define	TARGET_LOGIN_TMO			10000
#define DFLT_POLL_VAL				-1

#define FOISCSI_CMD_TIMEOUT			(10*HZ)
#define FOISCSI_LOGIN_TIMEOUT			(120*HZ)

#define csio_root_lni(lni)	(csio_lnode_to_iscsi(csio_root_lnode((lni)->ln)))
#define csio_is_root_lni(lni)   (((lni) == csio_root_lni((lni))) ? 1 : 0)
#define csio_is_phys_lni(lni)   (((lni)->ln->pln == NULL) ? 1 : 0)

struct csio_lnode_iscsi {
	struct csio_sm		sm;
	struct csio_lnode	*ln;

	csio_mutex_t		lni_mtx;
#ifdef	__CSIO_DEBUG__
	atomic_t		mtx_cnt;
#endif
	csio_workq_t		workq;

	int			inode_flowid;
	int			inode_id;
	int			logout_all;

	unsigned int 		num_sessions;
	unsigned int		iport_flowid;
	unsigned int		nscans;

	unsigned char		valid;
	struct foiscsi_instance inst;
};

csio_retval_t csio_lni_init(struct csio_lnode_iscsi *);
void csio_lni_exit(struct csio_lnode_iscsi *);
enum csio_oss_error csio_lni_start(struct csio_lnode_iscsi *);

void
csio_close_lni(struct csio_lnode_iscsi *lni);

void
csio_lni_down(struct csio_lnode_iscsi *lni);

void
csio_lni_stop(struct csio_lnode_iscsi *lni);

void csio_iscsi_session_cleanup(struct csio_rnode *rn);
void csio_iscsi_sess_in_recovery(struct csio_hw *, u32);
void csio_iscsi_sess_recovered(struct csio_hw *, u32, u32, u16);
void csio_iscsi_sess_recovery_timeout(struct csio_hw *, u32);

int csio_issue_foiscsi_node_wr(struct csio_hw *,
		struct csio_lnode_iscsi *,
		struct foiscsi_instance *, short , unsigned int, u8);

int csio_issue_foiscsi_ctrl_wr(struct csio_hw *, struct foiscsi_login_info *,
		struct csio_rnode *, u8, unsigned int, unsigned int,
		unsigned int sess_id);

void csio_foiscsi_block_lnode(struct csio_hw *, struct csio_lnode *);
void csio_foiscsi_unblock_lnode(struct csio_hw *, struct csio_lnode *);

u8* csio_fw_iscsi_get_targetdb(struct csio_hw *hw, uint32_t size, uint32_t page_size);
#endif /* ifndef __CSIO_LNODE_FOISCSI_H__ */
