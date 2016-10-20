/*
 *  Copyright (C) 2008-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: foiscsi transport functions. The possible transport could be
 * chelsio properietary interface (ioctl based),  open-iscsi or any other.
 *
 */

#include <csio_ctrl_foiscsi.h>

static csio_retval_t
csio_foiscsi_iface_start(struct csio_foiscsi_iface *iface)
{
	csio_retval_t rc = CSIO_SUCCESS;

	/* let's not bring up the link by default for now */

	/* portid value is the handle */
	/*rc = csio_foiscsi_do_link_cmd(iface->hw, iface->tport->portid,
		FW_CHNET_IFACE_CMD_SUBOP_LINK_UP, iface->tport->portid);*/

	return rc;
}

enum csio_oss_error
csio_foiscsi_iface_init(struct csio_hw *hw, int ifid,
				struct csio_foiscsi_iface *iface)
{
	csio_retval_t rc = CSIO_SUCCESS;

	iface->hw = hw;
	iface->mtu = 1500;
	iface->vlan_info.vlan_id = 0xfff;
	iface->tport = &hw->t4port[ifid];
	csio_mutex_init(&iface->mlock);

	rc = csio_foiscsi_iface_start(iface);
	
	return rc;
}

