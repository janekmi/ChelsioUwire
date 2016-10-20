/*
 *  Copyright (C) 2008-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: Handlers and support code for foiscsi transport functions.
 *
 */

#include <csio_os_init.h>
#include <csio_version.h>
#include <csio_foiscsi_ioctl.h>
#include <csio_stor_ioctl.h>
#include <csio_foiscsi.h>
#include <csio_os_foiscsi.h>
#include <csio_foiscsi_persistent.h>
#include <csio_lnode_foiscsi.h>
#include <csio_lnode.h>

#include <csio_trans_foiscsi.h>

#define MAC_ADDR_LEN                    6       /* in bytes */
#define IP_ADDR_LEN                     4       /* in bytes */

int
csio_foiscsi_cleanup_rnode_io(struct csio_scsim *scm, struct csio_rnode *rn)
{
#ifdef __CSIO_DEBUG__
	struct csio_hw *hw = scm->hw;
#endif
	struct csio_scsi_level_data sld;
	struct csio_list cmpl_q;
	struct csio_lnode *ln = csio_rnode_to_lnode(rn);

	csio_scsi_dbg(hw, "Gathering all SCSI I/Os on rnode %p\n", rn);

	sld.level = CSIO_LEV_RNODE;
	sld.lnode = ln;
	sld.rnode = rn;
	csio_head_init(&cmpl_q);
	csio_dbg(hw, "call gather active ios\n");
	csio_scsi_gather_active_ios(scm, &sld, &cmpl_q);
	csio_dbg(hw, "cleanup active ios \n");
	csio_scsi_cleanup_io_q(scm, &cmpl_q);

	return 0;

}

void foiscsi_block_session(struct csio_rnode_iscsi *rni)
{
	struct csio_os_rnode *osrn = csio_rnode_to_os(rni->rn);
	
	csio_work_schedule(&osrn->rsess->foiscsi_block);
	csio_dbg(csio_rnode_to_lnode(rni->rn)->hwp,
		"%s: __foiscsi_block scheduled for sess_id [%d]\n",
		__FUNCTION__, rni->sess_id);
}

void foiscsi_unblock_session(struct csio_rnode_iscsi *rni)
{
	struct csio_os_rnode *osrn = csio_rnode_to_os(rni->rn);
	
	csio_work_schedule(&osrn->rsess->foiscsi_unblock);
	csio_dbg(csio_rnode_to_lnode(rni->rn)->hwp,
		"%s: __foiscsi_unblock scheduled for sess_id [%d]\n",
		__FUNCTION__, rni->sess_id);
}


struct csio_lnode *csio_foiscsi_get_lnode(struct csio_hw *hw,
		int id)
{
	struct csio_list *tmp = NULL, *sln_head = &hw->sln_head;
	struct csio_lnode *ln = NULL;
	struct csio_lnode_iscsi *lni = NULL;

	csio_list_for_each(tmp, sln_head)
	{
		ln = (struct csio_lnode *)tmp;
		lni = csio_lnode_to_iscsi(ln);
		if (lni->inode_id == id) {
			return ln;
		}
	}

	return NULL;
}

int csio_iscsi_get_session_state(struct csio_rnode *rn)
{
	return (csio_rnism_in_ready(csio_rnode_to_iscsi(rn)));
}

static void csio_foiscsi_iface_cmd_mb_init(struct fw_chnet_iface_cmd *cmdp,
		uint8_t portid, uint8_t flags, uint8_t subop)
{
	csio_memset(cmdp, 0, sizeof(*cmdp));
	cmdp->op_to_portid = csio_htonl((V_FW_CMD_OP(FW_CHNET_IFACE_CMD) |
				F_FW_CMD_REQUEST |
				F_FW_CMD_WRITE |
				V_FW_CHNET_IFACE_CMD_PORTID(portid)));
	cmdp->retval_len16 = csio_htonl(V_FW_CMD_LEN16(sizeof(*cmdp) >> 4));
	cmdp->subop = subop;
	cmdp->r2[0] = flags;
	return;
}

csio_retval_t
csio_foiscsi_do_link_cmd(struct csio_hw *hw, uint8_t portid, uint8_t flags,
		enum fw_chnet_iface_cmd_subop link_op, unsigned long handle)
{
	struct adapter *adap = &hw->adap;
	struct fw_chnet_iface_cmd c;
	struct csio_foiscsi_iface *iface;
	struct csio_ctrl_foiscsi *foiscsi_cdev;
	int ret;
	
	csio_dbg(hw, "Bringing %s FOiSCSI LINK for port [%u], flags [0x%x] loopback [%s]\n",
		(link_op == FW_CHNET_IFACE_CMD_SUBOP_LINK_UP ? "up" : "down"),
		portid, flags, (flags & 0x1) ? "enabled" : "disabled");

	csio_foiscsi_iface_cmd_mb_init(&c, portid, flags, link_op);

	ret = t4_wr_mbox(adap, adap->mbox, &c, sizeof(c), NULL);
	if (ret) {
		csio_err(hw, "FW_FOISCSI_LINK_CMD failed for port [%u] with "
			"ret [%0x]\n", portid, ret);
		goto out;
	}

	if (link_op == FW_CHNET_IFACE_CMD_SUBOP_LINK_DOWN) {
		
		foiscsi_cdev = get_foiscsi_cdev(hw);
		
		if (!foiscsi_cdev) {
			csio_err(hw, "chnet inst not found\n");
			goto out;
		}

		iface = &foiscsi_cdev->ifaces[portid];
		csio_dbg(hw, "%s: iface->if_id [%0x], iface->if_state [%0x]\n",
				__FUNCTION__, iface->if_id, iface->if_state);

		iface->if_state = FOISCSI_IFACE_STATE_LINK_DOWN;
		hw->t4port[portid].link_status = 0;
	}

out:
	return ret;
}

csio_retval_t
csio_ln_logout(struct csio_hw *hw, void *arg1,
	struct foiscsi_logout_info *linfo, unsigned long handle)
{
	struct csio_list *rnhead = NULL, *tmp = NULL, *next = NULL;
	struct csio_rnode_iscsi *rni = NULL;
	struct csio_rnode *rn = NULL;
	struct csio_lnode *ln = NULL;
	struct csio_lnode_iscsi *lni = NULL;
	struct csio_os_lnode *osln = NULL;
	int rc = 0, found = 0;

	ln = csio_foiscsi_get_lnode(hw, linfo->inode_id);

	if (!ln) {
		rc = FOISCSI_ERR_INVALID_INDEX;
		goto out;
	}
	
	osln = csio_lnode_to_os(ln);
	lni = csio_lnode_to_iscsi(ln);
	lni->logout_all = 0;
	
	if (linfo->sess_id < 0) {
		/* Let caller call it multiple
		 * times to logout from all the targets till
		 * we return error or FOISCSI_ERR_ZERO_OBJ_FOUND */
		lni->logout_all = 1;
	}

	if (!csio_list_empty(&ln->rnhead)) {
		rnhead = &ln->rnhead;
		csio_list_for_each_safe(tmp, next, rnhead) {
			rn = (struct csio_rnode *)tmp;
			rni = csio_rnode_to_iscsi(rn);
			if ((csio_rnism_in_ready(rni) ||
				csio_rnism_in_recovery(rni)) &&
				(lni->logout_all || linfo->sess_id == rni->sess_id)) {
				csio_dbg(hw, "%s: Logging out from session-id [%d].\n",
						__FUNCTION__, rni->sess_id);
				csio_mutex_lock(&lni->lni_mtx);
#ifdef __CSIO_DEBUG__
				atomic_inc(&lni->mtx_cnt);
#endif
				rc = csio_iscsi_send_logout(hw, rn);
				/* Let caller call this
				 * function multiple times and we will
				 * logout from the first target in the list. */
				found = 1;
			}
		}
	}
	
	if (!lni->logout_all && !found)
		rc = FOISCSI_ERR_INVALID_INDEX;
	else if (lni->logout_all && !found)
		rc = FOISCSI_ERR_ZERO_OBJ_FOUND;

out:
	return rc;
}

static int csio_foiscsi_session_exists(struct csio_lnode_iscsi *lni,
				       struct foiscsi_login_info *linfo)
{
	struct csio_lnode *ln = lni->ln;
	struct csio_list *tmp = NULL, *rnhead = &ln->rnhead, *next = NULL;
	struct csio_rnode *rn = NULL;
	struct csio_rnode_iscsi *rni;

	if (csio_list_empty(&ln->rnhead)) {
		csio_dbg(ln->hwp, "%s: ln->rnhead empty.\n", __FUNCTION__);
		return 0;
	}

	csio_list_for_each_safe(tmp, next, rnhead) {
		rn = (struct csio_rnode *)tmp;
		rni = csio_rnode_to_iscsi(rn);

		/*csio_dbg(ln->hwp, "%s: linfo [%p] tgt_name len [%d], "
				"rni [%p] tgt_name len [%d]\n",
				__FUNCTION__, linfo, (int)strlen(linfo->tgt_name),
				rni, (int)strlen(rni->login_info.tgt_name));*/

		if ((strlen(linfo->tgt_name) ==
			strlen(rni->login_info.tgt_name)) &&
		    (!(strcmp(linfo->tgt_name, rni->login_info.tgt_name)) &&
		    (linfo->ip_type == rni->login_info.ip_type) &&
		    (linfo->tgt_port == rni->login_info.tgt_port))) {

			if ((linfo->ip_type ==  TYPE_IPV4) &&
			    (linfo->tgt_ip.ip4 == rni->login_info.tgt_ip.ip4) &&
			    (linfo->src_ip.ip4 == rni->login_info.src_ip.ip4))
				return 1;
			else if ((linfo->ip_type == TYPE_IPV6) &&
				 (!memcmp(linfo->tgt_ip.ip6,
					rni->login_info.tgt_ip.ip6, 16)) &&
				 (!memcmp(linfo->src_ip.ip6,
					rni->login_info.src_ip.ip6, 16)))
				return 1;
		}
	}
	return 0;
}

void
csio_put_rni(struct csio_rnode_iscsi *rni)
{
	struct csio_rnode *rn = rni->rn;
	struct csio_lnode *ln = csio_rnode_to_lnode(rn);
	struct csio_hw *hw = csio_lnode_to_hw(ln);
	struct csio_ctrl_foiscsi *foiscsi_cdev = NULL;
	struct csio_foiscsi_sess_table *sess_table = NULL;
	unsigned long flags;

	CSIO_DB_ASSERT(!!csio_rnism_in_uninit(rni));

	if (!(foiscsi_cdev = get_foiscsi_cdev(hw))) {
		csio_err(hw, "foiscsi inst not found\n");
		goto out;
	}

	sess_table = &foiscsi_cdev->sess_table;

	csio_dbg(hw, "%s: deallocating sid [%d].\n",
			__FUNCTION__, rni->sess_id);

	csio_spin_lock_irqsave(hw, &hw->lock, flags);
	
	rni->sess_id -= sess_table->start;
	clear_bit(rni->sess_id, sess_table->bitmap);
	rni->sess_id = 0;
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

	/* Free rni */	
	if (csio_hw_to_ops(hw)->os_free_rnode)
		csio_hw_to_ops(hw)->os_free_rnode(rn);
out:
	return;
}

/**
 * csio_get_rni - Gets a free iSCSI rnode with the given flowid
 * @ln - lnode
 */
struct csio_rnode_iscsi *
csio_get_rni(struct csio_lnode *ln)
{
	struct csio_hw *hw = csio_lnode_to_hw(ln);
	struct csio_rnode *rn = NULL ;
	struct csio_rnode_iscsi *rni = NULL;
	struct csio_ctrl_foiscsi *foiscsi_cdev = NULL;
	struct csio_foiscsi_sess_table *sess_table = NULL;
	unsigned long flags;
	unsigned int sid;

 	if (!(foiscsi_cdev = get_foiscsi_cdev(hw))) {
		csio_err(hw, "foiscsi inst not found\n");
		goto out;
	}

	sess_table = &foiscsi_cdev->sess_table;

	csio_spin_lock_irqsave(hw, &hw->lock, flags);

	sid = find_next_zero_bit(sess_table->bitmap,
			sess_table->max, sess_table->last);
	
	if (sid >= sess_table->max)
		sid = find_first_zero_bit(sess_table->bitmap, sess_table->max);

	if (sid < sess_table->max) {
		sess_table->last = sid + 1;
		if (sess_table->last >= sess_table->max)
			sess_table->last = 0;
		set_bit(sid, sess_table->bitmap);
		sid += sess_table->start;
	} else
		sid = -1;

	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

	csio_dbg(hw, "%s: allocated sid [%u]\n", __FUNCTION__, sid);

	if (sid == -1)
		goto out;

	rn = csio_rn_lookup(ln, sid);
	csio_dbg(hw, "%s: rn lookup [%p]\n", __FUNCTION__, rn);
	CSIO_DB_ASSERT(!rn);
	if (!rn) {
		if (!csio_hw_to_ops(hw)->os_alloc_rnode)
			goto out;

		rn = csio_hw_to_ops(hw)->os_alloc_rnode(ln);
		if (!rn)
			goto out;

		rn->flowid = sid;
		rni = csio_rnode_to_iscsi(rn);
		
		rni->sess_id = sid;
		csio_post_event(&rni->sm, CSIO_RNIE_INIT);

	} else {
		csio_err(hw, "Trying to login to existing session [%d].\n",
				sid);
		rn = NULL;
		goto out;
	}

	csio_dbg(hw, "%s: rn [%p],rni [%p], sid [%u], sess_id [%u].\n "
			, __FUNCTION__, rn, csio_rnode_to_iscsi(rn),
			sid, csio_rnode_to_iscsi(rn)->sess_id);
out:
	return rni;
}

csio_retval_t
csio_ln_login(struct csio_hw *hw, void *arg1,
		struct foiscsi_login_info *linfo,
		bool do_disc, unsigned long handle)
{
	struct csio_lnode_iscsi *lni = NULL;
	struct csio_lnode *ln = NULL;
	struct csio_rnode_iscsi *rni = NULL;
	struct csio_os_lnode *osln = NULL;
	int rc = CSIO_SUCCESS;
	int ini_passlen = 0, tgt_passlen = 0;
	unsigned char sess_type;

	if (linfo->inode_id > (FW_FOISCSI_INIT_NODE_MAX)) {
		csio_err(hw, "Initiator node id %d is greater than"
				"Max Initiator instances supported %d\n",
				linfo->inode_id, FW_FOISCSI_INIT_NODE_MAX);
		rc = -CSIO_INVAL;
		goto out;
	}

	ln = csio_foiscsi_get_lnode(hw, linfo->inode_id);

	if (!ln) {
		csio_dbg(hw, "inode not found\n");
		rc = FOISCSI_ERR_INVALID_INDEX;
		goto out;
	}

	lni = csio_lnode_to_iscsi(ln);
	csio_mutex_lock(&lni->lni_mtx);
#ifdef __CSIO_DEBUG__
	atomic_inc(&lni->mtx_cnt);
#endif

	osln = csio_lnode_to_os(ln);	

	if (!lni->valid) {
		csio_err(hw, "Invalid Initiator instance index %d\n",
			       linfo->inode_id);
		rc = -CSIO_INVAL;
		goto lni_mutex_unlock;
	}

	sess_type = G_FW_FOISCSI_CTRL_WR_SESS_TYPE(linfo->sess_attr.sess_type_to_erl);
	
	if (sess_type == FW_FOISCSI_SESSION_TYPE_NORMAL) {
		if (csio_foiscsi_session_exists(lni, linfo)) {

			if (linfo->ip_type == TYPE_IPV4) {
				char ip[20];
			
				sprintf(ip,"%u.%u.%u.%u",
					(linfo->tgt_ip.ip4>>24)&0xFF,
					(linfo->tgt_ip.ip4>>16)&0xFF,
					(linfo->tgt_ip.ip4>>8)&0xFF,
					linfo->tgt_ip.ip4&0xFF);

				csio_err(hw,
					"Session already exists for Target \"%s\", NetworkPortal \"%s:%d\"\n",
					linfo->tgt_name, ip,
					linfo->tgt_port);
			} else if (linfo->ip_type == TYPE_IPV6) {
				char ip[128];
				sprintf(ip, "%pI6", linfo->tgt_ip.ip6);

				csio_err(hw,
					"Session already exists for Target \"%s\", NetworkPortal \"[%s]:%d\"\n",
					linfo->tgt_name, ip,
					linfo->tgt_port);
			}

			linfo->status = FOISCSI_ERR_SESSION_EXISTS;
			rc = FOISCSI_ERR_SESSION_EXISTS;
			goto lni_mutex_unlock;
		}
	}

	if (G_FW_FOISCSI_CTRL_WR_AUTH_METHOD(linfo->conn_attr.hdigest_to_ddp_pgsz) &&
		G_FW_FOISCSI_CTRL_WR_AUTH_POLICY(linfo->conn_attr.hdigest_to_ddp_pgsz)) {
		tgt_passlen = strlen(linfo->tgt_sec);
		ini_passlen = strlen(lni->inst.chap_sec);
		if (tgt_passlen == ini_passlen) {
			if (!strncmp(lni->inst.chap_sec, linfo->tgt_sec, tgt_passlen)) {
				csio_err(hw, "Both peers cannot have same "
						"chap secret\n");
				rc = -CSIO_INVAL;
				goto lni_mutex_unlock;
			}
		}
	}

	rni = csio_get_rni(ln);
	if (!rni) {
		rc = -CSIO_NOMEM;
		goto lni_mutex_unlock;
	}

	rni->sess_type = sess_type;
	
	if (linfo->ip_type == TYPE_IPV4) {
		csio_dbg(hw,
			"login: src ip %u.%u.%u.%u, target ip %u.%u.%u.%u, port %u, target %s\n",
			(linfo->src_ip.ip4 >> 24) & 0xFF,
			(linfo->src_ip.ip4 >> 16) & 0xFF,
			(linfo->src_ip.ip4 >> 8) & 0xFF,
			(linfo->src_ip.ip4 & 0xFF),
			(linfo->tgt_ip.ip4 >> 24) & 0xFF,
			(linfo->tgt_ip.ip4 >> 16) & 0xFF,
			(linfo->tgt_ip.ip4 >> 8) & 0xFF,
			(linfo->tgt_ip.ip4 & 0xFF),
			linfo->tgt_port, linfo->tgt_name);
	} else if (linfo->ip_type == TYPE_IPV6) {
		csio_dbg(hw,
			"login: src ip %pI6, target ip %pI6, port %u, target %s\n",
			linfo->src_ip.ip6, linfo->tgt_ip.ip6,
			linfo->tgt_port, linfo->tgt_name);
	}
		
	linfo->sess_idx = rni->sess_id;
	
	csio_memcpy(&rni->login_info, linfo, sizeof(*linfo));
	
	if (G_FW_FOISCSI_CTRL_WR_SESS_TYPE(
				linfo->sess_attr.sess_type_to_erl)
			== FW_FOISCSI_SESSION_TYPE_DISCOVERY) {
		rni->disc_resp_buf = ((u8 *)linfo + sizeof(
					struct foiscsi_login_info));
		rni->disc_buf_offset = 0;
		rni->disc_resp_len = 0;
	}

	csio_post_event(&rni->sm, CSIO_RNIE_IN_LOGIN);

out:
	csio_dbg(hw, "iSCSI login status [%d]\n", rc);
	return rc;

lni_mutex_unlock:
#ifdef __CSIO_DEBUG__
	atomic_dec(&lni->mtx_cnt);
	BUG_ON(atomic_read(&lni->mtx_cnt) < 0);
#endif
	csio_mutex_unlock(&lni->lni_mtx);
	goto out;
}

csio_retval_t
csio_foiscsi_show_instance_handler(struct csio_hw *hw,
		struct foiscsi_instance *ini_inst)
{
	struct csio_list *tmp = NULL, *sln_head = &hw->sln_head;
	struct csio_lnode *ln = NULL;
	struct csio_lnode_iscsi *lni = NULL;

	int i = 0, j=0;

	csio_dbg(hw, "instance id = %d\n", ini_inst->id);
	if (ini_inst->id > 0 && ini_inst->id <= FW_FOISCSI_INIT_NODE_MAX) {
		i = ini_inst->id;
		ln = csio_foiscsi_get_lnode(hw, ini_inst->id);
		lni = csio_lnode_to_iscsi(ln);
		csio_dbg(hw, "lnode inode id = %d\n", lni->inode_id);
		
		if (!ln)
			return FOISCSI_ERR_INVALID_INDEX;

		if (lni->valid) {
			memcpy((ini_inst + j)->name, lni->inst.name,
					strlen(lni->inst.name));
			memcpy((ini_inst + j)->alias, lni->inst.alias,
					strlen(lni->inst.alias));
			memcpy((ini_inst + j)->chap_id, lni->inst.chap_id,
					strlen(lni->inst.chap_id));
			memcpy((ini_inst + j)->chap_sec, lni->inst.chap_sec,
					strlen(lni->inst.chap_sec));
			
			(ini_inst + j)->id = lni->inode_id;
			j++;
		}

		return CSIO_SUCCESS;

	} else if (ini_inst->id < 0) {
		csio_list_for_each(tmp, sln_head) {
			ln = (struct csio_lnode *)tmp;
			lni = csio_lnode_to_iscsi(ln);

			if (lni->valid) {
				memcpy((ini_inst + j)->name, lni->inst.name,
						strlen(lni->inst.name));
				memcpy((ini_inst + j)->alias, lni->inst.alias,
						strlen(lni->inst.alias));
				memcpy((ini_inst + j)->chap_id, lni->inst.chap_id,
						strlen(lni->inst.chap_id));
				memcpy((ini_inst + j)->chap_sec, lni->inst.chap_sec,
						strlen(lni->inst.chap_sec));

				(ini_inst + j)->id = lni->inode_id;
				j++;
			}
		}

		return CSIO_SUCCESS;

	} else {
		return FOISCSI_ERR_INVALID_INDEX;
	}
	
	return CSIO_SUCCESS;
}

csio_retval_t
csio_foiscsi_clear_instance_handler(struct csio_hw *hw,
		struct foiscsi_instance *ini_inst, unsigned long thandle)
{
	struct csio_lnode *ln = NULL;
	struct csio_lnode_iscsi *lni = NULL;
	/* struct csio_os_hw *oshw = csio_hw_to_os(hw); */
	short inode_db_idx = -1;
    int flowid = 0;

	if (ini_inst->id <= 0)
		return FOISCSI_ERR_INVALID_INDEX;

	ln = csio_foiscsi_get_lnode(hw, ini_inst->id);

	if (!ln) {
		csio_dbg(hw, "clear: inode not found\n");
		return FOISCSI_ERR_INVALID_INDEX;
	}

	lni = csio_lnode_to_iscsi(ln);

	if (!lni->valid) {
		csio_err(hw, "Not a valid index %d\n", ini_inst->id);
		return FOISCSI_ERR_INVALID_INDEX;
	}

	if (!csio_list_empty(&ln->rnhead)) {
		csio_err(hw, "Active sessions exist on Initiator\n");
		return FOISCSI_ERR_INST_BUSY;
	}

	flowid = lni->iport_flowid;

	inode_db_idx = ini_inst->id;
	/* send node_wr */
	csio_issue_foiscsi_node_wr(hw, lni, ini_inst,
			inode_db_idx, flowid,
			FW_FOISCSI_WR_SUBOP_DEL);

	return CSIO_SUCCESS;
}

csio_retval_t
csio_foiscsi_assign_instance_handler(struct csio_hw *hw, unsigned int if_id,
		struct foiscsi_instance *ini_inst, unsigned long handle)
{
	struct csio_list *tmp = NULL, *sln_head = &hw->sln_head;
	struct csio_lnode *ln = NULL;
	struct csio_lnode_iscsi *lni = NULL;
	/* struct csio_os_hw *oshw = csio_hw_to_os(hw); */
	short inode_db_idx = -1;
	int flowid = if_id;
	u8 subop = 0;

	csio_list_for_each(tmp, sln_head)
	{
		ln = (struct csio_lnode *)tmp;
		lni = csio_lnode_to_iscsi(ln);
		if (strlen(lni->inst.name) !=
				strlen(ini_inst->name))
			continue;
		if (!strcmp(lni->inst.name, ini_inst->name) && lni->valid) {
			inode_db_idx = lni->inode_id;
			break;
		}
	}

	if (inode_db_idx >= 0)
		if (inode_db_idx != ini_inst->id) {
			csio_err(hw, "Node already exists at idx %d\n",
					inode_db_idx);

			return FOISCSI_ERR_INST_EEXISTS;
		}

	ln = csio_foiscsi_get_lnode(hw, ini_inst->id);

	if (!ln) {
		csio_dbg(hw, "node id %d doesnot exist\n", ini_inst->id);
		return FOISCSI_ERR_INVALID_INDEX;
	}

	lni = csio_lnode_to_iscsi(ln);

	if (lni->valid) {
		if (!csio_list_empty(&ln->rnhead)) {
			csio_err(hw,
				 "Cannot modify instance info. Active sessions exist for Node\n");
			return FOISCSI_ERR_INST_BUSY;
		}
		subop = FW_FOISCSI_WR_SUBOP_MOD;
	} else {
		subop = FW_FOISCSI_WR_SUBOP_ADD;
	}
	inode_db_idx = ini_inst->id;

	/* copy all needed fields of ini_inst now itself
	 * because we will not have the ini_inst when we come back in LLD. */
	lni->inode_id = ini_inst->id;
	strcpy(lni->inst.name, ini_inst->name);
	strcpy(lni->inst.alias, ini_inst->alias);
	strcpy(lni->inst.chap_id, ini_inst->chap_id);
	strcpy(lni->inst.chap_sec, ini_inst->chap_sec);

	lni->iport_flowid = flowid;
	/* send node_wr */
	csio_issue_foiscsi_node_wr(hw, lni, ini_inst,
			inode_db_idx, flowid, subop);

	return CSIO_SUCCESS;
}

csio_retval_t
csio_foiscsi_set_chap_secret_handler(struct csio_hw *hw,
		struct foiscsi_instance *ini_inst)
{
	struct csio_lnode *ln = NULL;
	struct csio_lnode_iscsi *lni = NULL;

	ln = csio_foiscsi_get_lnode(hw, ini_inst->id);

	if (!ln) {
		csio_dbg(hw, "node id %d doesnot exist\n", ini_inst->id);
		return FOISCSI_ERR_INVALID_INDEX;
	}

	lni = csio_lnode_to_iscsi(ln);
	if (lni->valid) {
		csio_dbg(hw, "Add: name = %s alias = %s at idx = %d\n",
			lni->inst.name, lni->inst.alias, lni->inode_id);
		csio_issue_foiscsi_chap_wr(hw, lni, NULL,
			lni->inode_id, lni->inode_flowid,
			FW_FOISCSI_NODE_TYPE_INITIATOR);
	}
	return CSIO_SUCCESS;

}

csio_retval_t
csio_foiscsi_get_count_handler(struct csio_hw *hw,
		struct foiscsi_count *cnt)
{
	struct csio_list *tmp = NULL, *sln_head = &hw->sln_head;
	struct csio_lnode *ln = NULL;
	struct csio_lnode_iscsi *lni = NULL;
	struct csio_list *rnhead = NULL, *next = NULL;

	cnt->count = 0;

	switch (cnt->type) {
	case FOISCSI_INSTANCE_COUNT: {
		if (cnt->inode_idx > 0 &&
				cnt->inode_idx <= FW_FOISCSI_INIT_NODE_MAX) {
			ln = csio_foiscsi_get_lnode(hw, (cnt->inode_idx));
			lni = csio_lnode_to_iscsi(ln);
			if (lni->valid)
				cnt->count = 1;
			break;
		}

		csio_list_for_each(tmp, sln_head) {
			ln = (struct csio_lnode *)tmp;
			lni = csio_lnode_to_iscsi(ln);
			if (lni->valid)
				cnt->count++;
		}

		csio_dbg(hw, "Number of instances %d\n", cnt->count);
		break;
	}
	case FOISCSI_SESSION_COUNT:
		ln = csio_foiscsi_get_lnode(hw, cnt->inode_idx);

		if (!ln) {
			csio_dbg(hw, "inode not found\n");
			return FOISCSI_ERR_INVALID_INDEX;
		}

		lni = csio_lnode_to_iscsi(ln);

		if (!lni->valid)
			return FOISCSI_ERR_INVALID_INDEX;

		rnhead = &ln->rnhead;
		csio_list_for_each_safe(tmp, next, rnhead)
			cnt->count++;

		/* Do not use lni->num_sessions to count because it indicates
		 * only established sessions */
		/* cnt->count = lni->num_sessions; */
		csio_dbg(hw, "Number of sessions %d\n", cnt->count);

		break;
	
	default:
		break;
	}

	return 0;
}

csio_retval_t
csio_foiscsi_get_sess_info_handler (struct csio_hw *hw,
		struct foiscsi_sess_info *sess_info)
{
	struct csio_lnode *ln = NULL;
	struct csio_lnode_iscsi *lni = NULL;
	struct csio_rnode *rn = NULL;
	struct csio_rnode_iscsi *rni = NULL;
	struct csio_list *tmp = NULL, *next = NULL, *rnhead = NULL;
	int rc = 0, all = 0, found = 0;

	if (sess_info->sess_idx <= 0)
		all = 1;

	ln = csio_foiscsi_get_lnode(hw, sess_info->inode_idx);

	if (!ln) {
		csio_dbg(hw, "inode not found\n");
		return FOISCSI_ERR_INVALID_INDEX;
	}

	lni = csio_lnode_to_iscsi(ln);

	rnhead = &ln->rnhead;	

	csio_list_for_each_safe(tmp, next, rnhead) {
		rn = (struct csio_rnode *)tmp;
		rni = csio_rnode_to_iscsi(rn);

		if (!all) {
			if (sess_info->sess_idx != rni->sess_id)
				continue;
			else
				found = 1;
		}

		sess_info->inode_idx = rni->node_id;
		
		memcpy(sess_info->targ_name, rni->login_info.tgt_name,
				strlen(rni->login_info.tgt_name));
		if (strlen(rni->login_info.tgt_alias))
			memcpy(sess_info->targ_alias, rni->login_info.tgt_alias,
					strlen(rni->login_info.tgt_alias));

		//if (rni->iface)
		sess_info->ip_type = rni->login_info.ip_type;
		if (rni->login_info.ip_type == TYPE_IPV4) {
			sess_info->init_ip.ip4 = rni->login_info.src_ip.ip4;
			sess_info->targ_ip.ip4 = rni->login_info.tgt_ip.ip4;
		} else if (rni->login_info.ip_type == TYPE_IPV6) {
			memcpy(sess_info->init_ip.ip6,
				rni->login_info.src_ip.ip6, 16);
			memcpy(sess_info->targ_ip.ip6,
				rni->login_info.tgt_ip.ip6, 16);
		}
		sess_info->targ_port = rni->login_info.tgt_port;
		sess_info->sess_idx = rni->sess_id;
		if (csio_rnism_in_ready(rni))
			sess_info->state = 1;
		sess_info->port = ln->portid;

		if (!all)
			break;

		sess_info++;
	}

	if (!all && !found)
		rc = FOISCSI_ERR_INVALID_INDEX;

	return rc;
}

csio_retval_t
csio_foiscsi_do_mtu_req(struct csio_hw *hw, uint8_t opc,
			unsigned int if_id, uint16_t mtu, unsigned long handle)
{
	enum csio_oss_error rc = CSIO_SUCCESS;
	struct csio_wr_pair wrp;
	uint32_t size;
	struct fw_chnet_ifconf_wr ifconf_wr;
	unsigned long flags;
	
	csio_spin_lock_irqsave(hw, &hw->lock, flags);

	size = CSIO_ALIGN(sizeof(struct fw_chnet_ifconf_wr), 16);

	rc = csio_wr_get(hw, hw->mgmtm.eq_idx, size, &wrp);
	if (csio_unlikely(rc != CSIO_SUCCESS))
		goto out;

	memset(&ifconf_wr, 0, sizeof(struct fw_chnet_ifconf_wr));
	ifconf_wr.op_compl = csio_cpu_to_be32(V_FW_WR_OP(FW_CHNET_IFCONF_WR));
	ifconf_wr.flowid_len16 = csio_cpu_to_be32(
			V_FW_WR_FLOWID(if_id) |
			V_FW_WR_LEN16(CSIO_ROUNDUP(size, 16)));
		
	ifconf_wr.cookie = (uint64_t)handle;
	
	ifconf_wr.subop = ((opc == CSIO_FOISCSI_IFCONF_MTU_SET_IOCTL) ?
				FW_CHNET_IFCONF_WR_SUBOP_MTU_SET :
				FW_CHNET_IFCONF_WR_SUBOP_MTU_GET);

	ifconf_wr.param.mtu = csio_cpu_to_be16(mtu);
	
	csio_wr_copy_to_wrp(&ifconf_wr, &wrp, 0, sizeof(struct fw_chnet_ifconf_wr));
	csio_wr_issue(hw, hw->mgmtm.eq_idx, CSIO_FALSE);

out:
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

#ifdef __CSIO_DEBUG__
	if (rc)
		csio_dbg(hw, "%s: Out of credits, cannot allocate wr\n", __FUNCTION__);
	else
		csio_dump_wr_buffer((uint8_t *)&ifconf_wr, sizeof(struct fw_chnet_ifconf_wr));
#endif
	return rc;
}

csio_retval_t
csio_foiscsi_ifconf_ip_set(struct csio_hw *hw, int8_t opc, unsigned int if_id,
		struct csio_foiscsi_ifconf_ioctl *req, unsigned long handle)
{
	enum csio_oss_error rc = CSIO_SUCCESS;

	struct csio_wr_pair wrp;
	uint32_t size;
	struct fw_chnet_ifconf_wr ifconf_wr;
	unsigned long flags;
	
	csio_spin_lock_irqsave(hw, &hw->lock, flags);
	
	size = CSIO_ALIGN(sizeof(struct fw_chnet_ifconf_wr), 16);
	
	rc = csio_wr_get(hw, hw->mgmtm.eq_idx, size, &wrp);
	if (csio_unlikely(rc != CSIO_SUCCESS))
		goto out;

	memset(&ifconf_wr, 0, sizeof(struct fw_chnet_ifconf_wr));
	
	ifconf_wr.op_compl = csio_cpu_to_be32(V_FW_WR_OP(FW_CHNET_IFCONF_WR));
	ifconf_wr.flowid_len16 = csio_cpu_to_be32(
			V_FW_WR_FLOWID(if_id) |
			V_FW_WR_LEN16(CSIO_ROUNDUP(size, 16)));
		
	ifconf_wr.cookie = (uint64_t)handle;
	if (req->type == TYPE_IPV4) {
		ifconf_wr.subop = FW_CHNET_IFCONF_WR_SUBOP_IPV4_SET;

		ifconf_wr.param.in_attr.ipv4.addr =
				csio_cpu_to_be32(req->v4.ipv4_addr);
		ifconf_wr.param.in_attr.ipv4.mask =
				csio_cpu_to_be32(req->v4.ipv4_mask);
		ifconf_wr.param.in_attr.ipv4.router =
				csio_cpu_to_be32(req->v4.ipv4_gw);
	} else { /* IPv6 */
		ifconf_wr.subop = FW_CHNET_IFCONF_WR_SUBOP_IPV6_SET;

		ifconf_wr.param.in_attr.ipv6.prefix_len = req->v6.prefix_len;
		ifconf_wr.param.in_attr.ipv6.addr_hi =
					*(__be64 *)(req->v6.ipv6_addr);
		ifconf_wr.param.in_attr.ipv6.addr_lo =
					*(__be64 *)(req->v6.ipv6_addr + 8);
		ifconf_wr.param.in_attr.ipv6.router_hi =
					*(__be64 *)(req->v6.ipv6_gw);
		ifconf_wr.param.in_attr.ipv6.router_lo =
					*(__be64 *)(req->v6.ipv6_gw + 8);
	}

	if ((req->vlanid & 0x0fff) >= 2 && (req->vlanid & 0x0fff) < 4095 )
		ifconf_wr.param.vlanid = csio_cpu_to_be16(req->vlanid);

	csio_wr_copy_to_wrp(&ifconf_wr, &wrp, 0, sizeof(struct fw_chnet_ifconf_wr));
	csio_wr_issue(hw, hw->mgmtm.eq_idx, CSIO_FALSE);
out:
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

#ifdef __CSIO_DEBUG__
	if (rc)
		csio_dbg(hw, "%s: Out of credits, cannot allocate wr\n", __FUNCTION__);
	else
		csio_dump_wr_buffer((uint8_t *)&ifconf_wr, sizeof(struct fw_chnet_ifconf_wr));
#endif

	return rc;
}

csio_retval_t
csio_foiscsi_ifconf_dhcp_set(struct csio_hw *hw, unsigned int if_id,
		struct csio_foiscsi_ifconf_ioctl *req, unsigned long handle)
{
	enum csio_oss_error rc = CSIO_SUCCESS;

	struct csio_wr_pair wrp;
	uint32_t size;
	struct fw_chnet_ifconf_wr ifconf_wr;
	unsigned long flags;
	
	csio_spin_lock_irqsave(hw, &hw->lock, flags);
	
	size = CSIO_ALIGN(sizeof(struct fw_chnet_ifconf_wr), 16);

	rc = csio_wr_get(hw, hw->mgmtm.eq_idx, size, &wrp);
	if (csio_unlikely(rc != CSIO_SUCCESS))
		goto out;

	memset(&ifconf_wr, 0, sizeof(struct fw_chnet_ifconf_wr));
	
	ifconf_wr.op_compl = csio_cpu_to_be32(V_FW_WR_OP(FW_CHNET_IFCONF_WR));
	ifconf_wr.flowid_len16 = csio_cpu_to_be32(
			V_FW_WR_FLOWID(if_id) |
			V_FW_WR_LEN16(CSIO_ROUNDUP(size, 16)));
		
	ifconf_wr.cookie = (uint64_t)handle;
	if (req->type == TYPE_DHCP)
		ifconf_wr.subop = FW_CHNET_IFCONF_WR_SUBOP_DHCP_SET;
	else
		ifconf_wr.subop = FW_CHNET_IFCONF_WR_SUBOP_DHCPV6_SET;

	if (req->vlanid >= 2 && req->vlanid < 4095)
		ifconf_wr.param.vlanid = csio_cpu_to_be16(req->vlanid);

	csio_wr_copy_to_wrp(&ifconf_wr, &wrp, 0, sizeof(struct fw_chnet_ifconf_wr));
	csio_wr_issue(hw, hw->mgmtm.eq_idx, CSIO_FALSE);
out:
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

#ifdef __CSIO_DEBUG__
	if (rc)
		csio_dbg(hw, "%s: Out of credits, cannot allocate wr\n", __FUNCTION__);
	else
		csio_dump_wr_buffer((uint8_t *)&ifconf_wr, sizeof(struct fw_chnet_ifconf_wr));
#endif
	return rc;
}

csio_retval_t
csio_foiscsi_do_vlan_req(struct csio_hw *hw, uint8_t opc,
		unsigned int if_id, uint16_t vlanid, unsigned long handle)
{

	enum csio_oss_error rc = CSIO_SUCCESS;

	struct csio_wr_pair wrp;
	uint32_t size;
	struct fw_chnet_ifconf_wr ifconf_wr;
	unsigned long flags;
	
	csio_spin_lock_irqsave(hw, &hw->lock, flags);
	
	size = CSIO_ALIGN(sizeof(struct fw_chnet_ifconf_wr), 16);

	rc = csio_wr_get(hw, hw->mgmtm.eq_idx, size, &wrp);
	if (csio_unlikely(rc != CSIO_SUCCESS))
		goto out;

	memset(&ifconf_wr, 0, sizeof(struct fw_chnet_ifconf_wr));
	
	ifconf_wr.op_compl = csio_cpu_to_be32(
				V_FW_WR_OP(FW_CHNET_IFCONF_WR));
	ifconf_wr.flowid_len16 = csio_cpu_to_be32(
					V_FW_WR_FLOWID(if_id) |
					V_FW_WR_LEN16(CSIO_ROUNDUP(size, 16)));

	ifconf_wr.cookie = (uint64_t)handle;
		
	if (opc == CSIO_FOISCSI_IFCONF_VLAN_SET_IOCTL) {
		ifconf_wr.subop = FW_CHNET_IFCONF_WR_SUBOP_VLAN_SET;
		ifconf_wr.param.vlanid = csio_cpu_to_be16(vlanid);
	}
	
	csio_dbg(hw, "Assigning vlan-id [%u] vlan-prio [%d] for if_id [%0x]\n",
		vlanid & 0x0fff, (vlanid >> 13) & 0xf, if_id);

	csio_wr_copy_to_wrp(&ifconf_wr, &wrp, 0, sizeof(struct fw_chnet_ifconf_wr));
	csio_wr_issue(hw, hw->mgmtm.eq_idx, CSIO_FALSE);
out:
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

#ifdef __CSIO_DEBUG__
	if (rc)
		csio_dbg(hw, "%s: Out of credits, cannot allocate wr\n", __FUNCTION__);
	else
		csio_dump_wr_buffer((uint8_t *)&ifconf_wr, sizeof(struct fw_chnet_ifconf_wr));
#endif
	
	return rc;
}

void csio_foiscsi_ctrl_add(struct csio_hw *hw,
		struct csio_rnode *rn, struct fw_foiscsi_ctrl_wr *ctrl_wr,
		u8 status)
{
	struct csio_rnode_iscsi *rni = csio_rnode_to_iscsi(rn);
	int node_id = 0, ctrl_id = 0, io_id = 0;
	unsigned int cflow_id;
	int state = 0, len = 0, rc = CSIO_SUCCESS;
	unsigned long flags = 0;
	struct foiscsi_login_info *linfo;
	
	csio_spin_lock_irqsave(hw, &hw->lock, flags);


	node_id = csio_be32_to_cpu(ctrl_wr->node_id);
	cflow_id = csio_be32_to_cpu(ctrl_wr->ctrl_id);
	ctrl_id = csio_be32_to_cpu(ctrl_wr->ctrl_id);
	io_id = csio_be32_to_cpu(ctrl_wr->io_id);
	state = ctrl_wr->ctrl_state;
	rni->wr_status = ctrl_wr->status;

	rn->flowid = io_id;
	rni->sess_handle = ctrl_id;
	rni->node_id = node_id;
	rni->io_handle = io_id;
	
	if (status) {
		switch (status) {
		case FW_EPROTO:
			csio_err(hw, "Protocol Error!!\n");
			rc = FOISCSI_ERR_PARAM;
			break;

		case FW_ENOMEM:
			csio_err(hw, "Out of Memory!!\n");
			rc = FOISCSI_ERR_ENORES;
			break;
			
		case FW_EBUSY:
			csio_err(hw, "Busy..Try later!!\n");
			rc = FOISCSI_ERR_ENORES;
			break;
			
		case FW_EINVAL:
			csio_err(hw, "Invalid request!!\n");
			rc = FOISCSI_ERR_INVALID_REQUEST;
			break;

		case FW_ENETUNREACH:
			csio_err(hw, "Network not reachable\n");
			rc = FOISCSI_ERR_LOGIN_TIMEDOUT;
			break;

		default:
			csio_err(hw, "Unkown error code [%d]\n", status);
			rc = FOISCSI_ERR_NOT_IMPLEMENTED;
			break;
		}
	}

	rni->login_info.status = rc;
	
	switch(state) {
	case FW_FOISCSI_CTRL_STATE_FREE:
		csio_spin_unlock_irqrestore(hw, &hw->lock, flags);
		if (!status && (rni->sess_type ==
					FW_FOISCSI_SESSION_TYPE_NORMAL)) {
			if (csio_issue_foiscsi_chap_wr(hw, NULL, rni,
					0, rni->sess_handle,
					FW_FOISCSI_NODE_TYPE_TARGET)) {
				rc = -CSIO_INVAL;
			}
		}

		if (!rc)
			break;

		csio_err(hw, "Login to %s failed [status = %d]\n",
				rni->login_info.tgt_name, status);
		csio_post_event(&rni->sm, CSIO_RNIE_LOGIN_FAILED);
		break;

	case FW_FOISCSI_CTRL_STATE_ONLINE:
		
		if (rni->sess_type == FW_FOISCSI_SESSION_TYPE_DISCOVERY) {
			len = csio_be32_to_cpu(ctrl_wr->flowid_len16);
			memcpy(rni->disc_resp_buf + rni->disc_buf_offset,
					((u8 *)ctrl_wr + sizeof(__be64)*4), len);
			rni->disc_buf_offset += len;
			rni->disc_resp_len += len;
			
			if (!(csio_be32_to_cpu(ctrl_wr->op_compl) & F_FW_WR_COMPL)) {
				csio_spin_unlock_irqrestore(hw, &hw->lock, flags);
				break;
			}
			
			linfo = (struct foiscsi_login_info *)
				((u8 *)rni->disc_resp_buf -
				 sizeof(struct foiscsi_login_info));
			linfo->buf_len = rni->disc_resp_len;
			csio_dbg(hw, "linfo->sess_idx %d rni->sess_id %d\n",
					linfo->sess_idx, rni->sess_id);
		}

		csio_spin_unlock_irqrestore(hw, &hw->lock, flags);
		
		csio_dbg(hw, "%s: Session id [0x%x] sess_handle [0x%x], io_handle [0x%x] %s\n",
				__FUNCTION__, rni->sess_id, rni->sess_handle, rni->io_handle,
				csio_rnism_in_recovery(rni) ? "recovered" : "online");
		
		csio_post_event(&rni->sm, CSIO_RNIE_LOGGED_IN);
		break;
	
	case FW_FOISCSI_CTRL_STATE_FAILED:
		csio_spin_unlock_irqrestore(hw, &hw->lock, flags);
		csio_dbg(hw, "%s: Session:[%d]: %s timedout/failed\n",
			       	__FUNCTION__, rni->sess_id,
				csio_rnism_in_login(rni) ? "Login" : "Recovery");
		if (csio_rnism_in_login(rni))
			csio_post_event(&rni->sm, CSIO_RNIE_LOGIN_FAILED);
		else if (csio_rnism_in_recovery(rni))
			csio_post_event(&rni->sm, CSIO_RNIE_RECOVERY_TIMEDOUT);
		break;
	
	case FW_FOISCSI_CTRL_STATE_IN_RECOVERY:
		csio_spin_unlock_irqrestore(hw, &hw->lock, flags);
		csio_dbg(hw, "%s: Session:[%d]: in Recovery mode\n",
				__FUNCTION__, rni->sess_id);
		rni->io_state = ctrl_wr->io_state;
		if (!status)
			csio_post_event(&rni->sm, CSIO_RNIE_IN_RECOVERY);

		break;
	}
	return;
}

