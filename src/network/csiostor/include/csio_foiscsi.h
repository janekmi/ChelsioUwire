/*
 * Copyright (C) 2003-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef	CSIO_FOISCSI_H
#define	CSIO_FOISCSI_H

#include <csio_defs.h>
#include <csio_foiscsi_ioctl.h>
#include <csio_rnode_foiscsi.h>


#ifdef __CSIO_DEBUG__
static inline void
csio_dump_buffer(uint8_t *buf, uint32_t buf_len)
{
	uint32_t ii;

	for (ii = 0; ii < buf_len ; ii++) {
		if (!(ii & 0xF))
			csio_printk("\n0x%p:", (buf + ii));
		if (!(ii & 0x7))
			csio_printk(" 0x%02x", buf[ii]);
		else
			csio_printk("%02x", buf[ii]);
	}
	csio_printk("\n");
}

static inline void
csio_dump_wr_buffer(uint8_t *buf, uint32_t buf_len)
{
	csio_printk("################ SCSI (EQ) WR len: %d ###############\n",
			buf_len);

	csio_dump_buffer(buf, buf_len);
}


static inline void
csio_dump_wr(struct csio_hw *hw, struct csio_wr_pair *wrp)
{
	csio_printk("################ SCSI (EQ) WR len: %d ###############\n",
				wrp->size1 + wrp->size2);

	csio_dump_buffer((uint8_t *)wrp->addr1, wrp->size1);
	csio_dump_buffer((uint8_t *)wrp->addr2, wrp->size2);
}
#endif

#if 0
static inline void
csio_iscsi_post_wr(struct csio_hw *hw, struct csio_rnode_iscsi *rni)
{
#ifdef __CSIO_DEBUG__
	csio_dump_wr(hw, &rni->wrp);
#endif
	csio_wr_issue(hw, hw->mgmtm.eq_idx, CSIO_FALSE);
}
#endif

enum csio_foiscsi_iface_addr {
	CSIO_FOISCSI_IFACE_ADDR_INVALID = -1,
	CSIO_FOISCSI_IFACE_ADDR_FREE	= 0,
	CSIO_FOISCSI_IFACE_ADDR_IN_USE	= 1,
};

int
csio_foiscsi_cleanup_rnode_io(struct csio_scsim *scm, struct csio_rnode *rn);
struct csio_lnode *csio_foiscsi_get_lnode(struct csio_hw *, int);
int csio_init_foiscsi_hw(struct csio_hw *);
void csio_foiscsi_ctrl_del(struct csio_rnode *rn, u8 status);

void csio_foiscsi_ctrl_add(struct csio_hw *hw,
		struct csio_rnode *rn, struct fw_foiscsi_ctrl_wr *ctrl_wr,
		u8 status);
void csio_foiscsi_queue_work(struct csio_hw *hw, struct csio_rnode *rn, u8 block);

int csio_foiscsi_session_chkready(struct csio_rnode *rn);
void csio_rni_reg_rnode(struct csio_rnode *rn);
void csio_rni_unreg_rnode(struct csio_rnode *rn);
int csio_foiscsi_get_session_state(struct csio_rnode *rn);

void foiscsi_unblock_session(struct csio_rnode_iscsi *);
void foiscsi_block_session(struct csio_rnode_iscsi *);

csio_retval_t
csio_foiscsi_ifconf_ip_set(struct csio_hw *hw, int8_t opc, unsigned int if_id,
		struct csio_foiscsi_ifconf_ioctl *req, unsigned long handle);
csio_retval_t
csio_foiscsi_ifconf_dhcp_set(struct csio_hw *hw, unsigned int if_id,
		struct csio_foiscsi_ifconf_ioctl *req, unsigned long handle);
csio_retval_t
csio_foiscsi_do_vlan_req(struct csio_hw *hw, uint8_t opc,
			unsigned int if_id,	uint16_t vlanid, unsigned long handle);
csio_retval_t
csio_foiscsi_do_mtu_req(struct csio_hw *hw, uint8_t opc,
			unsigned int if_id,	uint16_t mtu, unsigned long handle);
csio_retval_t
csio_foiscsi_assign_instance_handler(struct csio_hw *hw, unsigned int if_id,
				struct foiscsi_instance *ini_inst, unsigned long handle);
csio_retval_t
csio_foiscsi_set_chap_secret_handler(struct csio_hw *hw,
		struct foiscsi_instance *ini_inst);
csio_retval_t
csio_foiscsi_clear_instance_handler(struct csio_hw *hw, 
				struct foiscsi_instance *ini_inst, unsigned long handle);
csio_retval_t
csio_foiscsi_get_count_handler(struct csio_hw *hw, 
								struct foiscsi_count *cnt);
csio_retval_t
csio_foiscsi_get_sess_info_handler (struct csio_hw *hw, 
					struct foiscsi_sess_info *sess_info);
csio_retval_t
csio_foiscsi_show_instance_handler(struct csio_hw *hw, 
		struct foiscsi_instance *ini_inst);

csio_retval_t
csio_ln_login(struct csio_hw *hw, void *arg1, struct foiscsi_login_info *linfo,
 			bool do_disc, unsigned long handle);

csio_retval_t
csio_ln_logout(struct csio_hw *hw, void *arg1, 
	struct foiscsi_logout_info *linfo, unsigned long handle);

csio_retval_t
csio_foiscsi_do_link_cmd(struct csio_hw *hw, uint8_t portid, uint8_t flags, 
		enum fw_chnet_iface_cmd_subop link_op, unsigned long handle);

int csio_iscsi_get_session_state(struct csio_rnode *rn);

int csio_issue_foiscsi_chap_wr(struct csio_hw *,
		struct csio_lnode_iscsi *,
		struct csio_rnode_iscsi *,
		short , unsigned int, u8);

void csio_put_rni(struct csio_rnode_iscsi *);
struct csio_rnode_iscsi *csio_get_rni(struct csio_lnode *);

#endif	/* CSIO_FOISCSI_H */
