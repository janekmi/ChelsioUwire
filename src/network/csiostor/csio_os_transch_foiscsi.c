/*
 *  Copyright (C) 2008-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: Chelsio cxgbtool based transport.
 */
/*
linux_chelsio
linux_oiscsi
windows_chelsio
others
*/

#include <csio_defs.h>
#include <csio_trans_foiscsi.h>
#include <csio_stor_ioctl.h>
#include <csio_foiscsi.h>

struct op_handle {
	uint32_t status;
	//struct completion completion;  reaplce this with cmplobj.cmpl
	csio_cmpl_t	cmplobj;
};

static csio_retval_t csio_foiscsi_linux_event_handler(struct csio_hw *hw,
		uint32_t op, uint32_t status,
		struct foiscsi_transport_handle *h);

static csio_retval_t csio_foiscsi_linux_ioctl_handler(struct csio_hw *hw,
		uint32_t op, unsigned long arg,
		void *buffer,
		uint32_t buffer_len);

static int csio_foiscsi_transport_linux_ch_init(struct csio_hw *);

static struct foiscsi_transport transport = {
	.name		= "linux_ch",
	.type		= LINUX_CHELSIO,
	.event_handler	= csio_foiscsi_linux_event_handler,
	.ioctl_handler	= csio_foiscsi_linux_ioctl_handler,
	.init_handler	= csio_foiscsi_transport_linux_ch_init
};

static int csio_foiscsi_transport_count = 1;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
static inline void reinit_completion(struct completion *x)
{
	INIT_COMPLETION(*x);
}
#endif

char *csio_os_foiscsi_transport_get_name(struct foiscsi_transport *transp)
{
	return transp->name;
}

int csio_os_foiscsi_transport_count(void)
{
	return csio_foiscsi_transport_count;
}

struct foiscsi_transport *csio_os_foiscsi_transport_get(unsigned int idx)
{
	return &transport;
}

static int csio_foiscsi_transport_linux_ch_init(struct csio_hw *hw)
{
	/* register the transport type and event callback with the LLD */
	return csio_foiscsi_register_transport(hw, &transport);
}

/* called from interrupt context. DO NOT SLEEP IN IT */
static csio_retval_t csio_foiscsi_linux_event_handler(struct csio_hw *hw,
		uint32_t op, uint32_t status,
		struct foiscsi_transport_handle *h)
{
	
	csio_dbg(hw, "%s: op %d, status %d\n", __FUNCTION__, op, status);
	/* if waiting for any event then unblock it */
	
	if (h) {
		((struct op_handle *)(h->handle))->status = status;
		complete(&((struct op_handle *)(h->handle))->cmplobj.cmpl);
	}
	return CSIO_SUCCESS;
}
static csio_retval_t logout_from_all_target(struct csio_hw *hw,
		struct foiscsi_logout_info *linfo,
		struct foiscsi_transport_handle *h)
{
	int rc, id ;
#if 0
	int ret;
#endif

	id = linfo->inode_id;
	memcpy(&h->iparam, linfo, sizeof(*linfo));
	for(;;) {
		/* logout from all session. Call logout till fn returns
		 * error or no more session. */

		rc = csio_ln_logout_handler(hw, NULL, linfo, h);
		/* Either error or no more session to logout */
		if (rc != CSIO_SUCCESS)
			break;
		/* wait for event callback */
		csio_dbg(hw, "%s: waiting for command completion..\n",
				__FUNCTION__);
#if 1
		wait_for_completion(&((struct op_handle *)
					h->handle)->cmplobj.cmpl);
#else
		/*ret = wait_for_completion_timeout(&((struct op_handle *)h->handle)->\
				cmplobj.cmpl, FOISCSI_LOGIN_TIMEOUT); */
		ret = wait_for_completion_interruptible(&((struct op_handle *)
					h->handle)->cmplobj.cmpl);

		/* if ((ret == 0) || (ret < 0)) { */
		if (ret < 0) {
			csio_err(hw, "Timeout/Error waiting for the "
					"LLD logout resp ret = %d\n", ret);
			rc  = -EFAULT;
			csio_clean_op_handle(hw, LOGOUT_FROM_TARGET, id, h);
			goto out;
		}
#endif
		csio_dbg(hw, "%s: Unblocking command status %d\n", __FUNCTION__,
				((struct op_handle *)h->handle)->status);
		reinit_completion((&((struct op_handle *)h->handle)->cmplobj.cmpl));
		/* Clean the handle inside LLD */
		csio_clean_op_handle(hw, LOGOUT_FROM_TARGET, id, h);
	}
#if 0
out:
#endif
	if (rc == FOISCSI_ERR_ZERO_OBJ_FOUND)
		rc = CSIO_SUCCESS;

	return rc;
}

static void
csio_clear_address_state(struct csio_hw *hw, struct csio_foiscsi_ifconf_ioctl *req, unsigned int iface_op)
{
	struct csio_ctrl_foiscsi *foiscsi_cdev = get_foiscsi_cdev(hw);
	struct csio_foiscsi_iface *iface;
	int vlan = 0;

	if(!foiscsi_cdev)
		return;

	iface = &foiscsi_cdev->ifaces[hw->t4port[req->ifid].portid];

	if (((iface->vlan_info.vlan_id & 0x0fff) >=2) &&
	    ((iface->vlan_info.vlan_id & 0x0fff) < 4095))
		vlan = VLAN_SHIFT;
	
	/* Shift bit for vlan operations */
	if (iface_op == IFCONF_IPV4_SET)
		iface->address_state &= ~(CSIO_IPV4_MASK << vlan);
	else if (iface_op == IFCONF_IPV6_SET)
		iface->address_state &= ~(CSIO_IPV6_MASK << vlan);
}

static csio_retval_t csio_foiscsi_linux_ioctl_handler(struct csio_hw *hw,
		uint32_t op, unsigned long arg,
		void *buffer,
		uint32_t buffer_len)
{
	enum csio_oss_error rc = CSIO_SUCCESS;
	int timeout = 0;
	unsigned int int_op = 0, id = 0xffff; /* invalid value */
	void __user *payload = NULL;
	struct op_handle handle;
	struct foiscsi_transport_handle *h;
	
	csio_dbg(hw, "%s: recv op [0x%x]\n", __FUNCTION__, op);

	init_completion(&handle.cmplobj.cmpl);
	h = foiscsi_alloc(sizeof(struct foiscsi_transport_handle));
	if (!h)
		return -ENOMEM;		
	h->transport = &transport;
	h->handle = &handle;

	/* LLD already takes care of keeping only
	 * one active operation at a time. */
	switch (op) {
	case CSIO_FOISCSI_IFACE_LINK_UP_IOCTL: {
		struct csio_foiscsi_iface_ioctl *req = buffer;
		int_op = IFACE_CMD_SUBOP_LINK_UP;
		id = req->ifid;
		memcpy(&h->iparam, req, sizeof(*req));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_foiscsi_link_up_cmd_handler(hw, req);
		break;
	}
	case CSIO_FOISCSI_IFACE_LINK_DOWN_IOCTL: {
		struct csio_foiscsi_iface_ioctl *req = buffer;
		int_op = IFACE_CMD_SUBOP_LINK_DOWN;
		id = req->ifid;
		memcpy(&h->iparam, req, sizeof(*req));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc  = csio_foiscsi_link_down_cmd_handler(hw, req);
		break;
	}

	case CSIO_FOISCSI_IFCONF_VLAN_SET_IOCTL: {
		struct csio_foiscsi_ifconf_ioctl *req = buffer;
		int_op = IFCONF_IPV4_VLAN_SET;
		id = req->ifid;
		memcpy(&h->iparam, req, sizeof(*req));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_foiscsi_vlan_cmd_handler(hw, op, req, h);
		timeout = FOISCSI_CMD_TIMEOUT;
		break;
	}

	case CSIO_FOISCSI_IFCONF_MTU_SET_IOCTL: {
		struct csio_foiscsi_ifconf_ioctl *req = buffer;
		int_op = IFCONF_MTU_SET;
		id = req->ifid;
		memcpy(&h->iparam, req, sizeof(*req));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_foiscsi_mtu_cmd_handler(hw, op, req, h);
		//rc = csio_foiscsi_do_mtu_req(hw, op, req, h);
		timeout = FOISCSI_CMD_TIMEOUT;
		break;
	}
	case CSIO_FOISCSI_IFCONF_MTU_GET_IOCTL: {
		struct csio_foiscsi_ifconf_ioctl *req = buffer;
		int_op = IFCONF_MTU_GET;
		id = req->ifid;
		memcpy(&h->iparam, req, sizeof(*req));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_foiscsi_mtu_cmd_handler(hw, op, req, NULL);
		break;
	}
	case CSIO_FOISCSI_IFACE_GET_IOCTL: {
		struct csio_foiscsi_ifconf_ioctl *req = buffer;
		rc = csio_foiscsi_iface_get(hw, req);
		break;
	}
	case CSIO_FOISCSI_IFCONF_IPV4_SET_IOCTL: {
		struct csio_foiscsi_ifconf_ioctl *req = buffer;
		int_op = IFCONF_IPV4_SET;
		id = req->ifid;
		memcpy(&h->iparam, req, sizeof(*req));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_foiscsi_ifconf_ipv4_set_cmd_handler(hw, op, req, h);
		timeout = FOISCSI_CMD_TIMEOUT;
		break;
	}
	case CSIO_FOISCSI_IFCONF_IPV4_GET_IOCTL: {
		struct csio_foiscsi_ifconf_ioctl *req = buffer;
		rc = csio_foiscsi_ifconf_ip_get(hw, req);
		break;
	}
	case CSIO_FOISCSI_IFCONF_IPV6_SET_IOCTL: {
		struct csio_foiscsi_ifconf_ioctl *req = buffer;
		int_op = IFCONF_IPV6_SET;
		id = req->ifid;
		memcpy(&h->iparam, req, sizeof(*req));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_foiscsi_ifconf_ipv6_set_cmd_handler(hw, op, req, h);
		timeout = FOISCSI_CMD_TIMEOUT;
		break;
	}
	case CSIO_FOISCSI_IFCONF_IPV6_GET_IOCTL: {
		struct csio_foiscsi_ifconf_ioctl *req = buffer;
		rc = csio_foiscsi_ifconf_ip_get(hw, req);
		break;
	}
	case CSIO_FOISCSI_IFCONF_IPV4_DHCP_SET_IOCTL: {
		struct csio_foiscsi_ifconf_ioctl *req = buffer;
		int_op = IPV4_DHCP_SET;
		id = req->ifid;
		memcpy(&h->iparam, req, sizeof(*req));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc  = csio_foiscsi_ifconf_dhcp_set_cmd_handler(hw, req, h);
		timeout = 200*HZ;
		break;
	}
	case CSIO_FOISCSI_IFCONF_IPV6_DHCP_SET_IOCTL: {
		struct csio_foiscsi_ifconf_ioctl *req = buffer;
		int_op = IPV6_DHCP_SET;
		id = req->ifid;
		memcpy(&h->iparam, req, sizeof(*req));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc  = csio_foiscsi_ifconf_dhcp_set_cmd_handler(hw, req, h);
		timeout = 200*HZ;
		break;
	}
	case CSIO_FOISCSI_ASSIGN_INSTANCE_IOCTL: {
		struct foiscsi_instance *ini_inst =
			(struct foiscsi_instance *)buffer;
		int_op = ASSIGN_INSTANCE;
		id = ini_inst->id;
		memcpy(&h->iparam, ini_inst, sizeof(*ini_inst));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_foiscsi_ioctl_assign_instance_handler(hw, ini_inst, h);
		timeout = FOISCSI_CMD_TIMEOUT;
		break;
	}
	case CSIO_FOISCSI_CLEAR_INSTANCE_IOCTL: {
		struct foiscsi_instance *ini_inst =
			(struct foiscsi_instance *)buffer;
		int_op = CLEAR_INSTANCE;
		id = ini_inst->id;
		memcpy(&h->iparam, ini_inst, sizeof(*ini_inst));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_foiscsi_ioctl_clear_instance_handler(hw, ini_inst, h);
		timeout = FOISCSI_CMD_TIMEOUT;
		break;
	}
	case CSIO_FOISCSI_SHOW_INSTANCE_IOCTL: {
		struct foiscsi_instance *ini_inst =
			(struct foiscsi_instance *)buffer;
		rc = csio_foiscsi_ioctl_show_instance_handler(hw, ini_inst);
		break;
	}
	case CSIO_FOISCSI_GET_COUNT_IOCTL: {
		struct foiscsi_count *cnt = (struct foiscsi_count *)buffer;
		rc  = csio_foiscsi_ioctl_get_count_handler(hw, cnt);
		break;
	}
	case CSIO_FOISCSI_SESSION_INFO_IOCTL: {
		struct foiscsi_sess_info *sess_info =
			(struct foiscsi_sess_info *)buffer;
		rc = csio_foiscsi_ioctl_get_sess_info_handler(hw, sess_info);
		break;
	}
	case CSIO_FOISCSI_LOGIN_TO_TARGET: {
		struct foiscsi_login_info *linfo =
			(struct foiscsi_login_info *)buffer;
		int_op = ISCSI_LOGIN_TO_TARGET;
		id = linfo->inode_id;
		memcpy(&h->iparam, linfo, sizeof(*linfo));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_ln_login_handler(hw, NULL, linfo, 0, h);
		timeout = FOISCSI_LOGIN_TIMEOUT;
		break;
	}
	case CSIO_FOISCSI_LOGOUT_FROM_TARGET: {
		struct foiscsi_logout_info *linfo =
			(struct foiscsi_logout_info *) buffer;
		int_op = LOGOUT_FROM_TARGET;
		id = linfo->inode_id;
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		if (linfo->sess_id < 0) {
			rc = logout_from_all_target(hw, linfo, h);
		} else  {
			memcpy(&h->iparam, linfo, sizeof(*linfo));
			rc = csio_ln_logout_handler(hw, NULL, linfo, h);
			timeout = FOISCSI_CMD_TIMEOUT;
		}
		break;
	}
	case CSIO_FOISCSI_DISC_TARGS: {
		struct foiscsi_login_info *linfo =
			(struct foiscsi_login_info *)buffer;
		int_op = ISCSI_DISC_TARGS;
		id = linfo->inode_id;
		memcpy(&h->iparam, linfo, sizeof(*linfo));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc  = csio_ln_login_handler(hw, NULL, linfo, 1, h);
		timeout = FOISCSI_LOGIN_TIMEOUT;
		break;
	}
#ifdef CSIO_FOISCSI_PERSISTENT_ENABLE
	case CSIO_FOISCSI_PERSISTENT_GET_IOCTL: {
		struct iscsi_persistent_target_db *target_db =
			( struct iscsi_persistent_target_db * )buffer;
		rc = csio_foiscsi_ioctl_persistent_show_handler(hw, target_db);
		break;
	}
	case CSIO_FOISCSI_PERSISTENT_CLEAR_IOCTL: {
		struct iscsi_persistent_target_db *target_db =
			( struct iscsi_persistent_target_db * )buffer;
		rc = csio_foiscsi_ioctl_persistent_clear_handler(hw,
				target_db->num_persistent_targets);
		break;
	}
#endif
	default:
		rc = CSIO_INVAL;
	}

	if ((rc == CSIO_SUCCESS) && timeout) {
		/* int ret; */
		/* Wait for response for a timeout value */
		csio_dbg(hw, "%s: waiting for command completion..\n",
				__FUNCTION__);
#if 1
		wait_for_completion(&((struct op_handle *)h->handle)->cmplobj.cmpl);
#else
		ret = wait_for_completion_interruptible(&((struct op_handle *)
					h->handle)->cmplobj.cmpl);
		/*ret = wait_for_completion_timeout(&((struct op_handle *)h->handle)->\
							cmplobj.cmpl, timeout);
		if ((ret == 0) || (ret < 0)) { */
		if (ret < 0) {
			csio_err(hw, "Error in waiting for the "
					"LLD resp, ret %d\n", ret);
			rc  = -EFAULT;
			goto out;
		}
#endif
		csio_dbg(hw, "%s: Unblocking command status %d\n",
		 __FUNCTION__, ((struct op_handle *)h->handle)->status);
		
		if (!((struct op_handle *)h->handle)->status) {
			if (int_op == ASSIGN_INSTANCE) {
				/* pass chap secret */
				struct foiscsi_instance *ini_inst =
					(struct foiscsi_instance *)buffer;
				csio_foiscsi_set_chap_secret(hw, ini_inst);
			} else {
				/* Set address state as well */
				switch (int_op) {
				case IPV4_DHCP_SET:
				case IPV6_DHCP_SET:
					memcpy(buffer, &h->iparam, sizeof(
					       struct csio_foiscsi_ifconf_ioctl));
					break;
				case IFCONF_IPV4_SET:
				case IFCONF_IPV6_SET: {
					struct csio_foiscsi_ifconf_ioctl *req = buffer;
					if (req->subop == OP_CLEAR)
						csio_clear_address_state(hw, req, int_op);
				}
				default:
					break;
				}
			}
		} else {
			
			if ((int_op == ISCSI_LOGIN_TO_TARGET ||
			     int_op == ISCSI_DISC_TARGS) &&
			     buffer) {
				struct foiscsi_login_info *linfo = (struct foiscsi_login_info *)buffer;

				linfo->status = ((struct op_handle *)h->handle)->status;
				csio_dbg(hw, "%s: linfo->status [0x%x]\n", __FUNCTION__, linfo->status);
				rc = -EAGAIN;
			} else if (int_op == IFCONF_IPV4_SET ||
				   int_op == IFCONF_IPV6_SET) {
				if ((((struct op_handle *)h->handle)->status ==
						FW_EADDRINUSE) ||
				    (((struct op_handle *)h->handle)->status ==
						FW_EADDRNOTAVAIL))
					rc = -EINVAL;
			}
		}
	}

	/* ibft calls don't have a userspace buffer */
	if(arg) {
		/* copy_to_user */
		if ((payload) && (copy_to_user(payload, buffer, buffer_len)))
			rc = -EFAULT;
	}
	
	if (timeout)
		csio_clean_op_handle(hw, int_op, id, h);
	if (h)
		foiscsi_free(h);
	return rc;
}

