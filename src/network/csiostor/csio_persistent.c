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

#include <csio_defs.h>
#include <csio_trans_foiscsi.h>
#include <csio_stor_ioctl.h>
#include <csio_foiscsi.h>
#include <csio_foiscsi_persistent.h>
#include <csio_lnode.h>

static csio_mutex_t plock;

int csio_foiscsi_persistent_init(void)
{
	return csio_mutex_init(&plock);
}

u8* csio_fw_iscsi_get_targetdb(struct csio_hw *hw, uint32_t size, uint32_t page_size)
{
	int ret, ofst = 0;
	u8  *iscsi_sector  = NULL;
	u32 words = size/4;
	u32 page_words = page_size/4;

	iscsi_sector = (u8 *)foiscsi_alloc
				(sizeof(struct iscsi_persistent_target_db));
	if (!iscsi_sector) {
		csio_err(hw, "Failed to alloc mem for iscsi persistent \
				target database\n");
		return NULL;
	}

	csio_mutex_lock(&plock);
	while (words) {
		ret = csio_hw_read_flash(hw, FOISCSI_DB_START+ofst,
			page_words, (u32 *)(iscsi_sector+ofst), 1);

		if (ret) {
			csio_err(hw,"Failed to read flash at offset %d\n",ofst);
			foiscsi_free((void *)iscsi_sector);
			iscsi_sector = NULL;
			goto out;
		}
		words -= page_words;
		ofst += page_size;
	}

out:
	csio_mutex_unlock(&plock);
	return iscsi_sector;
}

static void csio_fw_iscsi_put_targetdb(struct csio_hw *hw, void *target_db)
{
	foiscsi_free((void *)target_db);
}

static csio_retval_t
csio_fw_iscsi_update_targetdb(struct csio_hw *hw, u8 *target_db)
{
	enum csio_oss_error ret = CSIO_SUCCESS;
	u32 size = 0, len = 0, ofst = 0;

	csio_mutex_lock(&plock);
	ret = csio_hw_flash_erase_sectors(hw,
		SF_FOISCSI_SECTOR_NO, SF_FOISCSI_SECTOR_NO);

	if (CSIO_SUCCESS != ret) {
		csio_err(hw, "Failed to Erase iscsi sector\n");
		goto out;
	}

	size = sizeof(struct iscsi_persistent_target_db);
	while (size) {
		len = size > SF_PAGE_SIZE ? SF_PAGE_SIZE : size;
		
		ret = csio_hw_write_flash(hw,
			FOISCSI_DB_START+ofst, len, target_db+ofst);
		
		if (CSIO_SUCCESS != ret) {
			csio_err(hw, "Failed to update target_db: ofst = %d\n",
									ofst);
			goto out;
		}

		size -= len;
		ofst += len;
	}

out:
	csio_mutex_unlock(&plock);
	return ret;
}

int csio_persistent_check(struct csio_hw *hw, struct iscsi_persistent_target_db *target_db)
{
	if(target_db == NULL) {
		csio_err(hw, "Failed to read the iscsi database\n");
		return -CSIO_INVAL;
	}

	if (target_db->signature != FOISCSI_PERSISTENT_SIGNATURE) {
		memset(target_db, 0, sizeof(struct iscsi_persistent_target_db));
		target_db->signature = FOISCSI_PERSISTENT_SIGNATURE;
	} else if (target_db->num_valid_targets == MAX_ISCSI_PERSISTENT_TARGETS) {
		return ISCSI_STATUS_FAILURE;
	}

	return CSIO_SUCCESS;
}

int csio_add_persistent_iface(struct csio_hw *hw, struct csio_foiscsi_iface *iface, struct iscsi_persistent_target_db *targetdb)
{
	struct iscsi_persistent_target_db *target_db = NULL;
	enum csio_oss_error ret = CSIO_SUCCESS;
	uint16_t vlanid = iface->vlan_info.vlan_id & 0x0fff;
	int atype_ipv6 = ((iface->address_state & CSIO_IPV6_STATIC) | (iface->address_state & CSIO_IPV6_DHCP));

	if(targetdb == NULL) {
		target_db = (struct iscsi_persistent_target_db *)
					csio_fw_iscsi_get_targetdb(hw, SF_SEC_SIZE, SF_PAGE_SIZE);
		ret = csio_persistent_check(hw, target_db);

		if(ret == -CSIO_INVAL) {
			return ret;
		/* ISCSI_STATUS_FAILURE only indicates max targets is hit, not an issue when storing ifaces */
		} else if(ret && ret != (int)ISCSI_STATUS_FAILURE)
			goto out;

	} else target_db = targetdb;

	target_db->initiator.net[iface->tport->portid].if_id =
							iface->tport->portid;

	if (vlanid == 4095) {
		if (!atype_ipv6) {
			target_db->initiator.net[iface->tport->portid].sip.ipaddr.ipv4_address
									= iface->ipv4.addr;
			target_db->initiator.net[iface->tport->portid].sip.netmask.ipv4_address
									= iface->ipv4.mask;
		} else {
			memcpy(target_db->initiator.net[iface->tport->portid].sip.ipaddr.ipv6_address, iface->ipv6.addr, sizeof(iface->ipv6.addr));
			memcpy(target_db->initiator.net[iface->tport->portid].sip.netmask.ipv6_address, &iface->ipv6.prefix_len, sizeof(uint8_t));
		}

	} else if (vlanid >= 2 && vlanid < 4095) {
		if (!atype_ipv6) {
			target_db->initiator.net[iface->tport->portid].sip.ipaddr.ipv4_address
									= iface->vlan_info.ipv4.addr;
			target_db->initiator.net[iface->tport->portid].sip.netmask.ipv4_address
									= iface->vlan_info.ipv4.mask;
		} else {
			memcpy(target_db->initiator.net[iface->tport->portid].sip.ipaddr.ipv6_address, iface->vlan_info.ipv6.addr, sizeof(iface->ipv6.addr));
			memcpy(target_db->initiator.net[iface->tport->portid].sip.netmask.ipv6_address, &iface->vlan_info.ipv6.prefix_len, sizeof(uint8_t));
		}
	}

	target_db->initiator.net[iface->tport->portid].valid =
							VALID_REC;

	target_db->initiator.net[iface->tport->portid].sip.vlan = iface->vlan_info.vlan_id;

	if (atype_ipv6)
		target_db->initiator.net[iface->tport->portid].flag = 1;

	if (iface->gw)
		target_db->initiator.net[iface->tport->portid].sip.gateway.ipv4_address
							= iface->gw;
	else if (iface->gw6 && atype_ipv6)
		memcpy(target_db->initiator.net[iface->tport->portid].sip.gateway.ipv6_address, iface->gw6, sizeof(iface->gw6));

	if (iface->mtu)
		target_db->initiator.net[iface->tport->portid].sip.mtu
							= iface->mtu;

	if (iface->address_state == CSIO_IPV4_DHCP || iface->address_state == CSIO_IPV6_DHCP)
		target_db->initiator.net[iface->tport->portid].dhcp_en = 1;
	else
		target_db->initiator.net[iface->tport->portid].dhcp_en = 0;

	/* if this function opened target_db, update it otherwise let someone else worry about it */
	if(!targetdb)
		csio_fw_iscsi_update_targetdb(hw, (u8 *)target_db);
out:
	if(!targetdb)	
		csio_fw_iscsi_put_targetdb(hw, target_db);

	return ret;
}		

int csio_add_persistent_instance(struct csio_hw *hw,  struct csio_lnode_iscsi *lni, int inode_id, struct iscsi_persistent_target_db *targetdb)
{
	struct iscsi_persistent_target_db *target_db = NULL;
	enum csio_oss_error ret = CSIO_SUCCESS;

	if(targetdb == NULL) {
		target_db = (struct iscsi_persistent_target_db *)
					csio_fw_iscsi_get_targetdb(hw, SF_SEC_SIZE, SF_PAGE_SIZE);
		ret = csio_persistent_check(hw, target_db);

		if(ret == -CSIO_INVAL) {
			return ret;
		/* ISCSI_STATUS_FAILURE only indicates max targets is hit, not an issue when storing instances */
		} else if(ret && ret != (int)ISCSI_STATUS_FAILURE)
			goto out;

	} else target_db = targetdb;

	target_db->initiator.node[inode_id - 1].id = inode_id;

	if(lni->inst.name)
		csio_strcpy(target_db->initiator.node[inode_id - 1].name,
								lni->inst.name);
	else {
		csio_err(hw, "empty initiator name\n");
		goto out;
	}

	if(lni->inst.alias)
		csio_strcpy(target_db->initiator.node[inode_id - 1].alias,
								lni->inst.alias);
	else
		memset(target_db->initiator.node[inode_id - 1].alias, 0 , FW_FOISCSI_ALIAS_MAX_LEN);

	if(lni->inst.chap_id)
		csio_strcpy(target_db->initiator.node[inode_id - 1 ].chap_id,
								lni->inst.chap_id);
	else
		memset(target_db->initiator.node[inode_id - 1 ].chap_id, 0, FW_FOISCSI_NAME_MAX_LEN);

	if(lni->inst.chap_sec)
		csio_strcpy(target_db->initiator.node[inode_id - 1 ].chap_sec,
								lni->inst.chap_sec);
	else
		memset(target_db->initiator.node[inode_id - 1 ].chap_sec, 0, FW_FOISCSI_CHAP_SEC_MAX_LEN +1);

	target_db->initiator.node[inode_id - 1].valid = VALID_REC;

	/* if this function opened target_db, update it otherwise let someone else worry about it */
	if(!targetdb)
		csio_fw_iscsi_update_targetdb(hw, (u8 *)target_db);

out:
	if(!targetdb)
		csio_fw_iscsi_put_targetdb(hw, target_db);

	return ret;
}

int csio_add_persistent_target_info(struct csio_hw *hw, struct foiscsi_login_info *login, struct iscsi_persistent_target_db *targetdb)
{
	struct iscsi_persistent_target_db *target_db = NULL;
	enum csio_oss_error ret = CSIO_SUCCESS;
	uint8_t i = 0, flag = 0, num_target = 0;
	int8_t replace = -1;

	if(targetdb == NULL) {
		target_db = (struct iscsi_persistent_target_db *)
					csio_fw_iscsi_get_targetdb(hw, SF_SEC_SIZE, SF_PAGE_SIZE);
		ret = csio_persistent_check(hw, target_db);

		if(ret) {
			if(ret == -CSIO_INVAL)
				return ret;
			if(ret == (int)ISCSI_STATUS_FAILURE) {
				csio_err(hw, "Error! Exceeding Max targets supported\n");
				login->status = ret;
			}
			goto out;
		}

	} else target_db = targetdb;

	for(i = 0; i < target_db->num_persistent_targets; i++) {
		if (target_db->target[i].valid == VALID_REC) {
			if(target_db->target[i].node_id == login->inode_id)
				if(target_db->target[i].portal.tcpport == login->tgt_port) {
					if(login->ip_type == TYPE_IPV4) {
						if(target_db->target[i].portal.taddr.ipv4_address != login->tgt_ip.ip4)
							continue;
					} else { /* ipv6 */
						if(strcmp(target_db->target[i].portal.taddr.ipv6_address, login->tgt_ip.ip6))
							continue;
					}

					if(!strcmp(target_db->target[i].targname, login->tgt_name)) {
						/* Already exists, don't store again */
						csio_dbg(hw, "Target %s already stored in persistent db\n",login->tgt_name);
							return ret;
					}
				}
		} else if(replace < 0) {
			replace = i;
		}
	}


	if (replace >= 0) {
		num_target = target_db->num_persistent_targets;
		target_db->num_persistent_targets = replace;
		flag = 1;
	}

	target_db->target[target_db->num_persistent_targets].node_id
							= login->inode_id;

	target_db->target[target_db->num_persistent_targets].valid = VALID_REC;

	if(login->ip_type == TYPE_IPV4) {
		target_db->target[target_db->num_persistent_targets].saddr = login->src_ip.ip4;
		target_db->target[target_db->num_persistent_targets].portal.taddr.ipv4_address
                                                                = login->tgt_ip.ip4;	
	} else {
		memcpy(target_db->target[target_db->num_persistent_targets].saddr6, login->src_ip.ip6, sizeof(login->src_ip.ip6));
		memcpy(target_db->target[target_db->num_persistent_targets].portal.taddr.ipv6_address, login->tgt_ip.ip6, sizeof(login->tgt_ip.ip6));
		target_db->target[target_db->num_persistent_targets].flag = 1;	
	}

	if (login->tgt_name) {
		csio_strcpy(
		target_db->target[target_db->num_persistent_targets].targname,
							login->tgt_name);
	} else {
		csio_err(hw, "empty target name\n");
		goto out;
	}

	target_db->target[target_db->num_persistent_targets].portal.tcpport
							= login->tgt_port;
	target_db->target[target_db->num_persistent_targets].attr.sess_type_to_erl
					= login->sess_attr.sess_type_to_erl;
	target_db->target[target_db->num_persistent_targets].attr.max_conn
					= login->sess_attr.max_conn;
	target_db->target[target_db->num_persistent_targets].attr.max_r2t
					= login->sess_attr.max_r2t;
	target_db->target[target_db->num_persistent_targets].attr.time2wait
					= login->sess_attr.time2wait;
	target_db->target[target_db->num_persistent_targets].attr.time2retain
					= login->sess_attr.time2retain;
	target_db->target[target_db->num_persistent_targets].attr.max_burst
					= login->sess_attr.max_burst;
	target_db->target[target_db->num_persistent_targets].attr.first_burst
					= login->sess_attr.first_burst;
	target_db->target[target_db->num_persistent_targets].attr.hdigest_to_ddp_pgsz
					= login->conn_attr.hdigest_to_ddp_pgsz;
	if(login->tgt_id)
		csio_strcpy(
			target_db->target[target_db->num_persistent_targets].tgt_id,
								login->tgt_id);
	if(login->tgt_sec)
		csio_strcpy(target_db->target[target_db->num_persistent_targets].tgt_sec,
								login->tgt_sec);

	target_db->target[target_db->num_persistent_targets].attr.max_rcv_dsl
						= login->conn_attr.max_rcv_dsl;
	target_db->target[target_db->num_persistent_targets].attr.ping_tmo
						= login->conn_attr.ping_tmo;
	target_db->target[target_db->num_persistent_targets].attr.login_retry_count
						= login->login_retry_cnt;

	if (flag)
		target_db->num_persistent_targets = num_target;
	else
		target_db->num_persistent_targets++;
	
	target_db->num_valid_targets++;

	/* if this function opened target_db, update it otherwise let someone else worry about it */
	if(!targetdb)
		csio_fw_iscsi_update_targetdb(hw, (u8 *)target_db);
out:
	if(!targetdb)
		csio_fw_iscsi_put_targetdb(hw, target_db);

	return ret;
}

int csio_add_persistent_target(struct csio_hw *hw,
				struct foiscsi_login_info *login,
				struct csio_lnode_iscsi *lni,
				struct csio_foiscsi_iface *iface)
{
	struct iscsi_persistent_target_db *target_db = NULL;
	enum csio_oss_error ret = CSIO_SUCCESS;

	target_db = (struct iscsi_persistent_target_db *)
				csio_fw_iscsi_get_targetdb(hw, SF_SEC_SIZE, SF_PAGE_SIZE);

	ret = csio_persistent_check(hw, target_db);

	if(ret == -CSIO_INVAL) {
		csio_err(hw, "Failed to read the iscsi database\n");
		login->status = ISCSI_STATUS_FAILURE;
		return ret;

	}
	
	if(ret == (int)ISCSI_STATUS_FAILURE) {
		csio_err(hw, "Error! Exceeding Max targets supported\n");
		login->status = ret;
		goto out;
	}

	ret = csio_add_persistent_iface(hw, iface, target_db);
	if(ret)
		goto out;

	ret = csio_add_persistent_instance(hw, lni, login->inode_id, target_db);
	if(ret)
		goto out;

	ret = csio_add_persistent_target_info(hw, login, target_db);
	if(ret)
		goto out;

	csio_fw_iscsi_update_targetdb(hw, (u8 *)target_db);

out:
	csio_fw_iscsi_put_targetdb(hw, target_db);

	return ret;
}

int csio_foiscsi_persistent_login(struct csio_foiscsi_devinst *foiscsi_inst)
{
	struct csio_ctrl_foiscsi *foiscsi_cdev = &foiscsi_inst->foiscsi_cdev;
	struct csio_hw *hw = foiscsi_inst->hw;
	struct csio_foiscsi_iface *iface;
	struct iscsi_persistent_target_db *target_db = NULL;
	struct csio_foiscsi_iface_ioctl *iface_req = NULL;
	struct csio_foiscsi_ifconf_ioctl *ifconf_req = NULL;
	struct foiscsi_instance *ini_inst = NULL;
	struct foiscsi_login_info *linfo = NULL;
	struct csio_lnode *ln = NULL;
	struct csio_lnode_iscsi *lni = NULL;
	uint32_t j=0, rc = 0, i = 0;
	uint32_t target_idx = 0;
	uint32_t link_tmo = 10000;
	uint32_t  config_saddr[4]={0};
	uint32_t config_saddr6[4][4];
	uint32_t found = 0, retry_count;
	uint16_t vlanid;

	memset(config_saddr6, 0, 16);

	target_db = (struct iscsi_persistent_target_db *)
					csio_fw_iscsi_get_targetdb(hw, 4, 4);
	if (target_db == NULL) {
		csio_err(hw, "Failed to read persistent target database\n");
		rc = -ENOMEM;
		return rc;
	}

	if (target_db->signature != FOISCSI_PERSISTENT_SIGNATURE) {
		csio_dbg(hw, "Invalid signature in flash, will not read persistent target database\n");
		goto out;	
	}

	iface_req = &foiscsi_inst->bootlogin.request.iface_req;
	ifconf_req = &foiscsi_inst->bootlogin.request.ifconf_req;
	ini_inst = &foiscsi_inst->bootlogin.ini_inst;
	linfo = &foiscsi_inst->bootlogin.linfo;

	csio_memset(linfo, 0, sizeof(struct foiscsi_login_info));

	csio_memset(iface_req, 0, sizeof(struct csio_foiscsi_iface_ioctl));
	if(target_db->num_persistent_targets) {
		for (i = 0; i < hw->num_t4ports; i++) {
			iface = &foiscsi_cdev->ifaces[hw->t4port[i].portid];
			if (iface->if_state != FOISCSI_IFACE_STATE_LINK_UP) {
				iface_req->op = CSIO_FOISCSI_IFACE_LINK_UP_IOCTL;
				iface_req->ifid = i;
				csio_foiscsi_transport_ioctl_handler(hw,
						CSIO_FOISCSI_IFACE_LINK_UP_IOCTL,
						0, iface_req, sizeof(struct csio_foiscsi_iface_ioctl));
				if (iface_req->retval != CSIO_SUCCESS) {
					csio_err(hw,"Failed to bring up link for port %d\n", i);
					return iface_req->retval;
				}

			}	
		}
	}
		
	csio_mdelay(link_tmo);
	csio_fw_iscsi_put_targetdb(hw, target_db);

	target_db = (struct iscsi_persistent_target_db *)
					csio_fw_iscsi_get_targetdb(hw, SF_SEC_SIZE, SF_PAGE_SIZE);
	if (target_db == NULL) {
		csio_err(hw, "Failed to read persistent target database\n");
		rc = -ENOMEM;
		return rc;
	}

	
	for (i = 0; i < hw->num_t4ports; i++) {
		iface = &foiscsi_cdev->ifaces[hw->t4port[i].portid];

		vlanid = target_db->initiator.net[i].sip.vlan & 0x0fff;
		if(vlanid >=2 && vlanid < 4095) {
			if(!(target_db->initiator.net[i].flag) && !(iface->vlan_info.ipv4.refcnt))
				rc = csio_foiscsi_do_vlan_req(iface->hw,
					CSIO_FOISCSI_IFCONF_VLAN_SET_IOCTL, iface->if_id,
					target_db->initiator.net[i].sip.vlan, iface->tport->portid);
			else if(target_db->initiator.net[i].flag && !(iface->vlan_info.ipv6.refcnt))
				rc = csio_foiscsi_do_vlan_req(iface->hw,
					CSIO_FOISCSI_IFCONF_VLAN_SET_IOCTL, iface->if_id,
					target_db->initiator.net[i].sip.vlan, iface->tport->portid);
			else
				continue;

			if (rc != CSIO_SUCCESS) {
				csio_err(hw,"Failed to bring up vlan\n");
				return rc;
			}
		}
	}

	for (j=0; j<FW_FOISCSI_INIT_NODE_MAX; j++) {
		if (target_db->initiator.node[j].valid == VALID_REC) {
			/* Make sure we don't overwrite any iBFT info */
			ln = csio_foiscsi_get_lnode(hw, target_db->initiator.node[j].id);
			if(ln) {
				lni = csio_lnode_to_iscsi(ln);
				if(lni)
					if (lni->valid && lni->num_sessions)
						continue;
			}

			csio_memset(ini_inst, 0, sizeof(struct foiscsi_instance));
			csio_strcpy(ini_inst->name,target_db->initiator.node[j].name);
			csio_strcpy(ini_inst->alias,target_db->initiator.node[j].alias);
			ini_inst->id = target_db->initiator.node[j].id;
			csio_strcpy(ini_inst->chap_id,
			target_db->initiator.node[j].chap_id);
			csio_strcpy(ini_inst->chap_sec,
			target_db->initiator.node[j].chap_sec);
			csio_foiscsi_transport_ioctl_handler(hw,
				CSIO_FOISCSI_ASSIGN_INSTANCE_IOCTL,
				0, ini_inst, sizeof(struct foiscsi_instance));
		}
	}
	csio_memset(ifconf_req, 0, sizeof(struct csio_foiscsi_ifconf_ioctl));
	for (j=0; j<MAX_T4_PORTS; j++) {
		if ((target_db->initiator.net[j].valid == VALID_REC) &&
			(foiscsi_cdev->ifaces[j].if_state == FOISCSI_IFACE_STATE_LINK_UP) ) {
			/* Make sure we don't overwrite any iBFT info */
			if (((foiscsi_cdev->ifaces[j].vlan_info.vlan_id & 0x0fff) >=2) &&
				((foiscsi_cdev->ifaces[j].vlan_info.vlan_id & 0x0fff) < 4095)) {
				if (target_db->initiator.net[i].flag) {
					if(foiscsi_cdev->ifaces[j].vlan_info.ipv6.refcnt)
						continue;
				} else if(foiscsi_cdev->ifaces[j].vlan_info.ipv4.refcnt)
					continue;
			} else {
				if (target_db->initiator.net[i].flag) {
					if(foiscsi_cdev->ifaces[j].ipv6.refcnt)
						continue;
				} else  if(foiscsi_cdev->ifaces[j].ipv4.refcnt)
					continue;
			}

			ifconf_req->ifid = target_db->initiator.net[j].if_id;
			ifconf_req->vlanid = target_db->initiator.net[j].sip.vlan;
			ifconf_req->subop = OP_ASSIGN;

			if(target_db->initiator.net[j].flag)
				ifconf_req->type = TYPE_IPV6;
			else
				ifconf_req->type = TYPE_IPV4;

			if(target_db->initiator.net[j].dhcp_en) {
				if (target_db->initiator.net[j].flag)
					i = CSIO_FOISCSI_IFCONF_IPV4_DHCP_SET_IOCTL;
				else
					i = CSIO_FOISCSI_IFCONF_IPV6_DHCP_SET_IOCTL;

				rc = csio_foiscsi_transport_ioctl_handler(hw,
					i, 0, ifconf_req, sizeof(struct
					csio_foiscsi_ifconf_ioctl));
			} else {
				if (!target_db->initiator.net[j].flag) {
					ifconf_req->v4.ipv4_addr =
					target_db->initiator.net[j].sip.ipaddr.ipv4_address;
					ifconf_req->v4.ipv4_mask =
					target_db->initiator.net[j].sip.netmask.ipv4_address;
					ifconf_req->v4.ipv4_gw =
					target_db->initiator.net[j].sip.gateway.ipv4_address;
					i = CSIO_FOISCSI_IFCONF_IPV4_SET_IOCTL;
				} else {
					memcpy(ifconf_req->v6.ipv6_addr, target_db->initiator.net[j].sip.ipaddr.ipv6_address, 16);
					memcpy(&ifconf_req->v6.prefix_len, target_db->initiator.net[j].sip.netmask.ipv6_address, sizeof(uint8_t));
					memcpy(ifconf_req->v6.ipv6_gw, target_db->initiator.net[j].sip.gateway.ipv6_address, 16);
					i = CSIO_FOISCSI_IFCONF_IPV6_SET_IOCTL;
				}

				ifconf_req->mtu =  target_db->initiator.net[j].sip.mtu;

				rc = csio_foiscsi_transport_ioctl_handler(hw,
					i , 0, ifconf_req, sizeof(struct
					csio_foiscsi_ifconf_ioctl));
				if (ifconf_req->retval == CSIO_SUCCESS) {
					 if (target_db->initiator.net[j].flag)
						memcpy(config_saddr6[j], ifconf_req->v6.ipv6_addr, 16);
					else
						config_saddr[j] = ifconf_req->v4.ipv4_addr;
				}
				if(ifconf_req->mtu != 1500) {
					rc = csio_foiscsi_transport_ioctl_handler(hw,
						CSIO_FOISCSI_IFCONF_MTU_SET_IOCTL,
						0, ifconf_req, sizeof(struct
						csio_foiscsi_ifconf_ioctl));
				}
			}
		}
	}

	for (j=0; j< target_db->num_persistent_targets; j++) {
		target_idx = j;
		if (target_db->target[target_idx].valid == VALID_REC) {
			if (!target_db->target[target_idx].flag)
				linfo->src_ip.ip4 =  target_db->target[target_idx].saddr;
			else
				memcpy(linfo->src_ip.ip6, target_db->target[target_idx].saddr6, 16);

			found = 0;
			for(i=0; i<MAX_T4_PORTS; i++) {
				if (target_db->target[target_idx].flag) {
					if(memcmp(linfo->src_ip.ip6, config_saddr6[i], 16)) {
						found = 1;
						break;
					}
				} else if (linfo->src_ip.ip4 == config_saddr[i]) {
						found = 1;
						break;
					
				}
			}
			
			if(!found) {
				continue;
			}

			linfo->inode_id = target_db->target[target_idx].node_id;
			linfo->sess_attr.sess_type_to_erl =
			target_db->target[target_idx].attr.sess_type_to_erl;
			linfo->conn_attr.hdigest_to_ddp_pgsz =
			target_db->target[target_idx].attr.hdigest_to_ddp_pgsz;
			csio_strcpy(linfo->tgt_id,
			target_db->target[target_idx].tgt_id);
			csio_strcpy(linfo->tgt_sec,
			target_db->target[target_idx].tgt_sec);
			linfo->sess_attr.max_conn =
			target_db->target[target_idx].attr.max_conn;
			linfo->sess_attr.max_r2t =
			target_db->target[target_idx].attr.max_r2t;
			linfo->sess_attr.time2wait =
			target_db->target[target_idx].attr.time2wait;
			linfo->sess_attr.time2retain =
			target_db->target[target_idx].attr.time2retain;
			linfo->sess_attr.max_burst =
			target_db->target[target_idx].attr.max_burst;
			linfo->sess_attr.first_burst =
			target_db->target[target_idx].attr.first_burst;
			linfo->conn_attr.max_rcv_dsl =
			target_db->target[target_idx].attr.max_rcv_dsl;
			linfo->conn_attr.ping_tmo =
			target_db->target[target_idx].attr.ping_tmo;
			linfo->op = OP_LOGIN;
			if (target_db->target[target_idx].flag) {	
				linfo->ip_type = TYPE_IPV6;
				memcpy(linfo->tgt_ip.ip6, target_db->target[target_idx].portal.taddr.ipv6_address, 16);
			} else {
				linfo->ip_type = TYPE_IPV4;
				linfo->tgt_ip.ip4 =
				target_db->target[target_idx].portal.taddr.ipv4_address;
			}
			linfo->tgt_port =
			target_db->target[target_idx].portal.tcpport;
			csio_strcpy(linfo->tgt_name,
			target_db->target[target_idx].targname);
			linfo->login_retry_cnt =
			target_db->target[target_idx].attr.login_retry_count;

			retry_count = 0;
			while(csio_foiscsi_transport_ioctl_handler(hw,
				CSIO_FOISCSI_LOGIN_TO_TARGET,
				0, linfo, sizeof(struct foiscsi_login_info)) && retry_count <= linfo->login_retry_cnt) {
				if(linfo->status == FOISCSI_ERR_LOGIN_TIMEDOUT)
					retry_count++;
				else
					break;
			}

		}
	}

out:
	csio_fw_iscsi_put_targetdb(hw, target_db);
	return rc;
}

int csio_foiscsi_persistent_show_handler(struct csio_hw *hw,
			     struct iscsi_persistent_target_db *target_db_buff)
{
	struct iscsi_persistent_target_db *target_db;
	target_db = (struct iscsi_persistent_target_db *)
				csio_fw_iscsi_get_targetdb(hw, SF_SEC_SIZE, SF_PAGE_SIZE);
	
	if(target_db == NULL) {
		csio_err(hw, "Failed to get the persistent target database\n");
		return -ENOMEM;
	}
	
	if (target_db->signature != FOISCSI_PERSISTENT_SIGNATURE) {
		csio_err(hw, "No valid record found\n");
		goto out;
	}

	memcpy(target_db_buff, target_db,
			sizeof(struct iscsi_persistent_target_db));

out:
	csio_fw_iscsi_put_targetdb(hw, target_db);

	return CSIO_SUCCESS;
}

int csio_foiscsi_persistent_clear_handler(struct csio_hw *hw, uint8_t idx)
{
	struct iscsi_persistent_target_db *target_db = NULL;
	enum csio_oss_error ret = CSIO_SUCCESS;

	target_db = (struct iscsi_persistent_target_db *)
		csio_fw_iscsi_get_targetdb(hw, SF_SEC_SIZE, SF_PAGE_SIZE);

	if(target_db == NULL) {
		csio_err(hw, "Failed to get the persistent target database\n");
		return -ENOMEM;
	}

	if (idx == (uint8_t)-1) {
		memset(target_db, 0, sizeof(struct iscsi_persistent_target_db));
		csio_fw_iscsi_update_targetdb(hw, (u8 *)target_db);
		goto out;
	}

	if (target_db->target[idx].valid != VALID_REC) {
		csio_err(hw, "No valid target record found for index %d\n",idx);
		ret = CSIO_INVAL;
		goto out;
	}

	target_db->target[idx].valid = INVALID_REC;
	target_db->num_valid_targets--;
	csio_fw_iscsi_update_targetdb(hw, (u8 *)target_db);

out:
	csio_fw_iscsi_put_targetdb(hw, target_db);

	return ret;
}

