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
#include <linux/acpi.h>
#include <linux/efi.h>
#include <linux/iscsi_ibft.h>
#include <csio_defs.h>
#include <csio_trans_foiscsi.h>
#include <csio_stor_ioctl.h>
#include <csio_foiscsi.h>
#include <csio_ibft.h>

static void
fill_target_info(struct csio_hw *hw, void *ibft_loc,
		 struct foiscsi_login_info *linfo,
		 struct foiscsi_instance *ini_inst,
		 struct acpi_ibft_target *target)
{
	csio_strncpy((char *)linfo->tgt_name,
	(char *)(ibft_loc+target->target_name_offset), target->target_name_length);

	if (target->target_ip_address[0] == 0 && target->target_ip_address[1] == 0 &&
		target->target_ip_address[2] == 0 && target->target_ip_address[3] == 0 &&
		target->target_ip_address[4] == 0 && target->target_ip_address[5] == 0 &&
		target->target_ip_address[6] == 0 && target->target_ip_address[7] == 0 &&
		target->target_ip_address[8] == 0 && target->target_ip_address[9] == 0 &&
		target->target_ip_address[10] == 0xff &&
		target->target_ip_address[11] == 0xff) {

		linfo->ip_type = TYPE_IPV4;
		linfo->tgt_ip.ip4  = ntohl((target->target_ip_address[15] << 24) |
					(target->target_ip_address[14] << 16) |
					(target->target_ip_address[13] << 8) |
					(target->target_ip_address[12]));
	} else {
		linfo->ip_type = TYPE_IPV6;
		memcpy(linfo->tgt_ip.ip6, target->target_ip_address, 16);
	}

	linfo->tgt_port = target->target_ip_socket;

	if (IBFT_TARGET_CHAP_NONE == target->chap_type) {
		linfo->conn_attr.hdigest_to_ddp_pgsz |=
				V_FW_FOISCSI_CTRL_WR_AUTH_METHOD
				(FW_FOISCSI_AUTH_METHOD_NONE);

	} else if (IBFT_TARGET_CHAP_ONEWAY == target->chap_type) {
		linfo->conn_attr.hdigest_to_ddp_pgsz |=
			V_FW_FOISCSI_CTRL_WR_AUTH_METHOD
			(FW_FOISCSI_AUTH_METHOD_CHAP);

		linfo->conn_attr.hdigest_to_ddp_pgsz |=
			V_FW_FOISCSI_CTRL_WR_AUTH_POLICY
			(FW_FOISCSI_AUTH_POLICY_ONEWAY);
	
		csio_strncpy(ini_inst->chap_id,
			(const char *)(ibft_loc + target->chap_name_offset),
			target->chap_name_length);

		csio_strncpy(ini_inst->chap_sec,
			(char *)(ibft_loc + target->chap_secret_offset),
			target->chap_secret_length);

	} else if (IBFT_TARGET_CHAP_MUTUAL == target->chap_type) {
		linfo->conn_attr.hdigest_to_ddp_pgsz |=
			V_FW_FOISCSI_CTRL_WR_AUTH_METHOD(
			FW_FOISCSI_AUTH_METHOD_CHAP);

		linfo->conn_attr.hdigest_to_ddp_pgsz |=
			V_FW_FOISCSI_CTRL_WR_AUTH_POLICY
			(FW_FOISCSI_AUTH_POLICY_MUTUAL);
		
		csio_strncpy(ini_inst->chap_id,
			(const char *)(ibft_loc + target->chap_name_offset),
			target->chap_name_length);

		csio_strncpy(ini_inst->chap_sec,
			(char *)(ibft_loc + target->chap_secret_offset),
			target->chap_secret_length);

		csio_strncpy(linfo->tgt_id,
			(char *)(ibft_loc + target->reverse_chap_name_offset),
			target->reverse_chap_name_length);
	
		csio_strncpy(linfo->tgt_sec,
			(char *)(ibft_loc + target->reverse_chap_secret_offset),
			target->reverse_chap_secret_length);

	} else
		csio_err(hw,"invalid CHAP method\n");
		
}

static int
csio_foiscsi_get_ibft_data(struct csio_foiscsi_devinst *foiscsi_inst,
			   void *ibft_loc, struct foiscsi_login_info *linfo)
{
	struct csio_ctrl_foiscsi *foiscsi_cdev = &foiscsi_inst->foiscsi_cdev;
	struct csio_hw *hw = foiscsi_inst->hw;
	struct acpi_table_ibft *tbl = ibft_loc;
	struct acpi_ibft_nic *nic = NULL;
	struct acpi_ibft_control *control = NULL;
	struct acpi_ibft_initiator *initiator = NULL;
	struct acpi_ibft_nic *nic0 = NULL, *nic1 = NULL;
	struct acpi_ibft_target *target0 = NULL, *target1 = NULL;
	uint8_t interface_mac[6];
	uint8_t interface_ip[16];
	uint8_t interface_gateway[16];
	int subnet_mask_prefix;
	uint16_t vlan_id;
	struct foiscsi_instance *ini_inst;
	struct csio_foiscsi_iface_ioctl *iface_req;
	struct csio_foiscsi_ifconf_ioctl *ifconf_req;
	struct csio_foiscsi_iface *iface;
	uint32_t link_tmo = 10000, delay = 5;
	int i, j, subop;
	uint16_t ip_type;

        ini_inst = &foiscsi_inst->bootlogin.ini_inst;
        iface_req = &foiscsi_inst->bootlogin.request.iface_req;
        ifconf_req = &foiscsi_inst->bootlogin.request.ifconf_req;
	csio_memset(ini_inst, 0, sizeof(struct foiscsi_instance));

	csio_memset(iface_req, 0, sizeof(struct csio_foiscsi_iface_ioctl));
	for (i = 0; i < hw->num_t4ports; i++) {
		iface = &foiscsi_cdev->ifaces[hw->t4port[i].portid];
		iface_req->op = CSIO_FOISCSI_IFACE_LINK_UP_IOCTL;
		iface_req->ifid = i;
		csio_foiscsi_transport_ioctl_handler(hw,
			CSIO_FOISCSI_IFACE_LINK_UP_IOCTL,
			0, iface_req, sizeof(struct csio_foiscsi_iface_ioctl));
		if (iface_req->retval != CSIO_SUCCESS) {
			csio_err(hw,"Failed to bring up link for port %d\n", i);
			return -ENOLINK;
		}
	}

	control = (struct acpi_ibft_control *)((char *)tbl +
						 sizeof(struct acpi_table_ibft));

	if (control->initiator_offset) {
		initiator = (struct acpi_ibft_initiator *)((char *)ibft_loc +
						control->initiator_offset);
	}

	if (control->nic0_offset) {
		nic0 = (struct acpi_ibft_nic *)((char *)ibft_loc +
							control->nic0_offset);
	}

	if (nic0 != NULL)
		nic = nic0;

	if (control->nic1_offset) {
		nic1 = (struct acpi_ibft_nic *)((char *)ibft_loc +
							control->nic1_offset);
	}

	if (nic1 != NULL)
		nic = nic1;

	/* We can't check pci id, so settle for a PF check instead */
	if ((nic->pci_address & 0xff) != PF_ISCSI) {
		csio_dbg(hw, "Invalid PF written in iBFT info, driver needs %0x, got %0x\n",
			 PF_ISCSI, nic->pci_address & 0xff);
		return -EINVAL;
	}

	csio_memcpy(interface_mac, nic->mac_address, 6);
	csio_memcpy(interface_ip, nic->ip_address, 16);
	subnet_mask_prefix = (0xFFFFFFFFUL << (32 - nic->subnet_mask_prefix));

	csio_memcpy(interface_gateway, nic->gateway, 16);
	vlan_id = nic->vlan;

	csio_memset(ifconf_req, 0, sizeof(struct csio_foiscsi_ifconf_ioctl));
	if (!nic->ip_address[0] && !nic->ip_address[1] && !nic->ip_address[2] &&
		!nic->ip_address[3] && !nic->ip_address[4] && !nic->ip_address[5] &&
		!nic->ip_address[6] && !nic->ip_address[7] && !nic->ip_address[8] &&
		!nic->ip_address[9] && nic->ip_address[10] == 0xFF &&
		nic->ip_address[11] == 0xFF) {
		csio_dbg(hw,"\nSetting IP address of the Chelsio NIC "
			"to %u.%u.%u.%u \n",
			nic->ip_address[12], nic->ip_address[13],
			nic->ip_address[14], nic->ip_address[15]);
		ip_type = TYPE_IPV4;
		ifconf_req->v4.ipv4_addr = ntohl((interface_ip[15] << 24) |
					 (interface_ip[14] << 16) |
					 (interface_ip[13] << 8)  |
					 (interface_ip[12]));

		ifconf_req->v4.ipv4_gw = ntohl((interface_gateway[15] << 24) |
					(interface_gateway[14] << 16) |
					(interface_gateway[13] << 8) |
					(interface_gateway[12]));

		ifconf_req->v4.ipv4_mask = subnet_mask_prefix;

		subop = CSIO_FOISCSI_IFCONF_IPV4_SET_IOCTL;
	} else {
		csio_dbg(hw,"\nSetting IP address of the Chelsio NIC "
				"to %d.%d.%d.%d.%d.%d.%d.%d\n",
			ntohs(nic->ip_address[0]), ntohs(nic->ip_address[1]),
			ntohs(nic->ip_address[2]), ntohs(nic->ip_address[3]),
			ntohs(nic->ip_address[4]), ntohs(nic->ip_address[5]),
			ntohs(nic->ip_address[6]), ntohs(nic->ip_address[7]));

		ip_type = TYPE_IPV6;

		memcpy(ifconf_req->v6.ipv6_addr, interface_ip, 16);
		memcpy(ifconf_req->v6.ipv6_gw, interface_gateway, 16);
		ifconf_req->v6.prefix_len = subnet_mask_prefix;

		subop = CSIO_FOISCSI_IFCONF_IPV6_SET_IOCTL;
	}

	ifconf_req->ifid = -1;

retry_find_iface:
	for (j = 0; j < hw->num_t4ports; j++) {
		iface = &foiscsi_cdev->ifaces[hw->t4port[j].portid];

		if((iface->tport->mac[5]>>3) == (interface_mac[5]>>3))
			ifconf_req->ifid = j;
	}

	for (i = 0; i < link_tmo; i+=delay) {
		iface = &foiscsi_cdev->ifaces[(((int8_t)ifconf_req->ifid < 0) ? 0 : ifconf_req->ifid)];

		if (iface->if_state == (int)FOISCSI_IFACE_STATE_LINK_UP)
			break;

		csio_msleep(delay);
	}

	/* Ignore link_tmo and allow 1 retry, we might have been waiting on the
 	 * wrong iface in the first place */

	if ((int8_t)ifconf_req->ifid == -1) {
		csio_dbg(hw, "Could not find ibft iface in the first try, retrying one last time\n");
		ifconf_req->ifid--;
		goto retry_find_iface;
	}
	
	if (i == link_tmo) {
		csio_err(hw, "Link up timed out on port %d\n", (int8_t)ifconf_req->ifid);
		return -ENOLINK;	
	}

	if ((int8_t)ifconf_req->ifid < 0) {
		csio_err(hw, "Could not find valid interface [%d] to use for iBFT\n", ifconf_req->ifid);
		return -EINVAL;
	}

	ifconf_req->type = ip_type;
	ifconf_req->subop = OP_ASSIGN;

	if ((vlan_id & 0x0fff) >=2 && (vlan_id & 0x0fff) < 4095) {
		ifconf_req->vlanid = vlan_id;
		csio_foiscsi_transport_ioctl_handler(hw,
			CSIO_FOISCSI_IFCONF_VLAN_SET_IOCTL,
			0, ifconf_req, sizeof(struct csio_foiscsi_ifconf_ioctl));
		if (ifconf_req->retval != CSIO_SUCCESS) {
			csio_err(hw,"Failed to bring up vlan\n");
			return -ENODEV;
		}
	} else {
		ifconf_req->vlanid = 4095;
	}
	
	csio_foiscsi_transport_ioctl_handler(hw,
		subop,
		0, ifconf_req, sizeof(struct csio_foiscsi_ifconf_ioctl));

	if (control->target0_offset) {
		target0 = (struct acpi_ibft_target *)((char *)ibft_loc +
		control->target0_offset);
	}

	if (control->target1_offset) {
		target1 = (struct acpi_ibft_target *)((char *)ibft_loc +
		control->target1_offset);
	}

	if (target0 && (target0->header.flags & IBFT_BLOCK_FLAG_FW_BOOT_SEL)) {
		fill_target_info(hw, ibft_loc, linfo, ini_inst, target0);
       	} else if (target1 &&
			(target1->header.flags & IBFT_BLOCK_FLAG_FW_BOOT_SEL)) {
		fill_target_info(hw, ibft_loc, linfo, ini_inst, target1);
	}

	csio_strncpy(ini_inst->name,
		(char *)ibft_loc+initiator->name_offset,
		initiator->name_length);


	csio_strcpy(ini_inst->alias, "iscsi_ibft1");
	ini_inst->id = 1;
	csio_foiscsi_transport_ioctl_handler(hw,
					CSIO_FOISCSI_ASSIGN_INSTANCE_IOCTL,
					0, ini_inst,
					sizeof(struct foiscsi_instance));
	linfo->ip_type = ip_type;
	if (ip_type == TYPE_IPV4)
		linfo->src_ip.ip4 = ifconf_req->v4.ipv4_addr;
	else
		memcpy(linfo->src_ip.ip6, ifconf_req->v6.ipv6_addr, 16);
	linfo->sess_attr.max_conn = 1;
	linfo->sess_attr.max_r2t = 1;
	linfo->sess_attr.time2wait = 20;
	linfo->sess_attr.time2retain = 20;
	linfo->sess_attr.max_burst = 16776192;
	linfo->sess_attr.first_burst = 262144;
	linfo->sess_attr.sess_type_to_erl |=
		V_FW_FOISCSI_CTRL_WR_SESS_TYPE(FW_FOISCSI_SESSION_TYPE_NORMAL) | V_FW_FOISCSI_CTRL_WR_PDU_INORDER(1) \
		| V_FW_FOISCSI_CTRL_WR_SEQ_INORDER(1) | V_FW_FOISCSI_CTRL_WR_ERL(0) \
		| V_FW_FOISCSI_CTRL_WR_IMMD_DATA_EN(1) | V_FW_FOISCSI_CTRL_WR_INIT_R2T_EN(1);
	linfo->op = OP_LOGIN;
	linfo->inode_id = 1;
	linfo->conn_attr.max_rcv_dsl = 8192;
	linfo->conn_attr.ping_tmo = 10;

	return 0;
}

void csio_foiscsi_ibft_login(struct csio_foiscsi_devinst *foiscsi_inst)
{
	struct csio_hw *hw = foiscsi_inst->hw;
	struct acpi_table_ibft *csio_ibft_addr = NULL;
	uint8_t	*ptr, csum = 0;
	struct foiscsi_login_info *linfo;
#ifndef CONFIG_ISCSI_IBFT_FIND
	unsigned long pos;
	unsigned int len = 0;
	void *virt;
#ifdef CONFIG_ACPI
	struct acpi_table_header *table=NULL;
#endif
#endif /* !defined(CONFIG_ISCSI_IBFT_FIND) */
#ifdef CONFIG_ACPI
	union acpi_name_union cbft_sig;
#else
	strcut csio_name cbft_sig;
#endif /* defined(CONFIG_ACPI) */
	memcpy(cbft_sig.ascii, "iBFT", IBFT_SIGN_LEN);

	linfo = &foiscsi_inst->bootlogin.linfo;
	
	/* Use kernel provided ibft_addr first */
#ifdef CONFIG_ISCSI_IBFT_FIND
	if (ibft_addr) {
		csio_dbg(hw, "iBFT available through kernel interface\n");
		csio_ibft_addr = (struct acpi_table_ibft *)ibft_addr;
	}
#else
	if (csio_efi_enabled) {
		if (acpi_disabled) {
			csio_dbg(hw, "ACPI disabled in UEFI mode, cannot read boot information\n");
			return;
		}

#ifdef CONFIG_ACPI
		if (!(acpi_get_table(cbft_sig.ascii, 0, &table))) {
			csio_ibft_addr = (struct acpi_table_ibft *)table;
			csio_dbg(hw,
				"CBFT header could be read through ACPI tables, following UEFI boot spec\n");
		} else {
			/* iBFT 1.03 section 1.4.3.1 mandates that UEFI machines will
      			 * only use ACPI for this */
			csio_dbg(hw,
				 "CBFT header could not be read through ACPI tables, UEFI cannot use legacy ibft area\n");
			return;
		}
#endif
	} else
		csio_dbg(hw, "System is not booted through UEFI, trying legacy boot\n");
	
	if (!csio_ibft_addr) {
		for (pos = IBFT_START; pos < IBFT_END; pos += 16) {
			/* The table can't be inside the VGA BIOS reserved space,
			 * so skip that area */

			if (pos == VGA_MEM)
				pos += VGA_SIZE;

			virt = isa_bus_to_virt(pos);

			if (csio_memcmp(virt, cbft_sig.ascii, IBFT_SIGN_LEN) == 0) {
				unsigned long *addr =
					(unsigned long *)isa_bus_to_virt(pos + 4);
				len = *addr;
				/* if the length of the table extends past 1M,
				 * the table cannot be valid. */
				if (pos + len <= (IBFT_END-1)) {
					csio_ibft_addr = (struct acpi_table_ibft *)virt;
					break;
				} else {
					csio_err(hw,"IBFT length extends past %x\n",
									IBFT_END);
					return;
				}
			}
		}
	}
#endif /* defined(CONFIG_ISCSI_IBFT_FIND) */

	if (csio_ibft_addr) {
		if (csio_ibft_addr->header.revision != IBFT_REVISION) {
			csio_err(hw,"Only IBFT revision %d \
					supported(Found IBFT revision %d)\n",
					IBFT_REVISION, csio_ibft_addr->header.revision);
			return;
		}

		for (ptr = (uint8_t *)csio_ibft_addr; ptr < (uint8_t *)csio_ibft_addr
						+ csio_ibft_addr->header.length; ptr++)
			csum += *ptr;

		if (csum) {
			csio_err(hw,"iBFT has incorrect checksum (0x%x)!\n",
								csum);
			return;
		}

		/* Make sure we aren't reading BIFT */
		if (csio_memcmp(csio_ibft_addr, cbft_sig.ascii, IBFT_SIGN_LEN)) {
			csio_err(hw,"iBFT signature mismatch, expected [%.4s], got [%.4s]\n",
				 cbft_sig.ascii, (char *)csio_ibft_addr);
			return;

		}
	} else {
		csio_dbg(hw,"iBFT table not found\n");
		return;
	}

	if (csio_memcmp(csio_ibft_addr->header.oem_id, "CHLSIO", 6))
		csio_warn(hw, "Expecting iBFT OEM Id of 'CHLSIO, found '%s' instead\n", csio_ibft_addr->header.oem_id);

	csio_memset(linfo, 0, sizeof(struct foiscsi_login_info));
	if (csio_foiscsi_get_ibft_data(foiscsi_inst, csio_ibft_addr, linfo))
		return;
	csio_foiscsi_transport_ioctl_handler(hw, CSIO_FOISCSI_LOGIN_TO_TARGET,
				0, linfo, sizeof(struct foiscsi_login_info));
}
