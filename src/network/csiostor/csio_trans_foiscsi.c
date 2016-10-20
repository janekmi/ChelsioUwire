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
#include <csio_defs.h>
#include <csio_hw.h>
#include <csio_trans_foiscsi.h>
#include <csio_ctrl_foiscsi.h>
#include <csio_foiscsi.h>
#include <csio_os_trans_foiscsi.h>
#include <csio_stor_ioctl.h>
#include <csio_ibft.h>
#include <csio_foiscsi_persistent.h>
#include <csio_lnode.h>

//static struct csio_ctrl_foiscsi foiscsi_cdev;
/* Maintains the per adapter instance of foiscsi common transport */

static struct csio_list foiscsi_inst_head;
static struct csio_list foiscsi_transport_list;

/*static struct foiscsi_transport *transport_list[MAX_TRANSPORT_SUPPORTED];*/
/*static unsigned int num_transport;*/
static unsigned int transport_init_done;

struct csio_foiscsi_devinst* get_foiscsi_inst(struct csio_hw *hw)
{
	struct csio_foiscsi_devinst *inst = NULL;
	struct csio_list *tmp = NULL;

	if (csio_list_empty(&foiscsi_inst_head))
		return NULL;

	csio_list_for_each(tmp, &foiscsi_inst_head) {
		inst = (struct csio_foiscsi_devinst *) tmp;
		if (inst->hw == hw)	
			return inst;
	}
	return NULL;
}

#ifdef CSIO_FOISCSI_PERSISTENT_ENABLE
static int bootlogin_threadfunc(void *data)
{
	struct csio_foiscsi_devinst *foiscsi_inst =
		(struct csio_foiscsi_devinst*)data;

	if (!foiscsi_inst)
		return -EINVAL;

	if (csio_foiscsi_persistent_init() == CSIO_SUCCESS) {
		csio_foiscsi_ibft_login(foiscsi_inst);
		csio_foiscsi_persistent_login(foiscsi_inst);
	}
	return 0;
}

static void csio_bootlogin_start(uintptr_t data)
{
	struct csio_foiscsi_devinst *foiscsi_inst =
			(struct csio_foiscsi_devinst *) data;
	struct csio_hw *hw = foiscsi_inst->hw;

	if (csio_is_hw_ready(hw))
		csio_wake_up(foiscsi_inst->bootlogin.bootlogin_ts);
	else if (foiscsi_inst->bootlogin.attempt++ < 3)
		csio_timer_start(&foiscsi_inst->bootlogin.bootlogin_timer,
			3000);
}
#endif

static int
csio_foiscsi_sess_table_alloc(struct csio_foiscsi_sess_table *sess_table,
			      unsigned int start, unsigned num)
{
	sess_table->start = start;
	sess_table->last = 0;
	sess_table->max = num;

	csio_head_init(&sess_table->rni_list);
	csio_spin_lock_init(&sess_table->tlock);

	sess_table->bitmap = foiscsi_alloc(BITS_TO_LONGS(num) * sizeof(long));
	if (!sess_table->bitmap)
		return -ENOMEM;

	bitmap_zero(sess_table->bitmap, num);

	return 0;
}

void csio_foiscsi_sess_table_free(struct csio_foiscsi_sess_table *sess_table)
{
	foiscsi_free(sess_table);
}

/* Do not sleep in this function. Caller is protecting it with hw spin lock */
int csio_foiscsi_transport_init(struct csio_hw *hw)
{
	struct csio_foiscsi_iface *iface;
	struct csio_foiscsi_devinst *foiscsi_inst;
	struct csio_ctrl_foiscsi *foiscsi_cdev;
	struct foiscsi_transport *transport = NULL;
	unsigned int i;
	int rv = 0;
#ifdef CSIO_FOISCSI_PERSISTENT_ENABLE
	char thread_name[20] ;
#endif

	/* if this is the first call into transport layer,
	 * get done with transport initilization */
	if (!transport_init_done) {
		csio_head_init(&foiscsi_transport_list);
		csio_head_init(&foiscsi_inst_head);
		
		for (i = 0; i < csio_os_foiscsi_transport_count(); i++) {
			
			transport = csio_os_foiscsi_transport_get(i);

			if (transport && transport->init_handler) {
				csio_elem_init((struct csio_list *)transport);
				rv = transport->init_handler(hw);
				if (rv == -1) {
					csio_err(hw,
				"transport %s failed to initialize\n",
				csio_os_foiscsi_transport_get_name(transport));
					rv = -ENODEV;
					goto out;
				}
				csio_enq_at_tail(&foiscsi_transport_list,
						transport);
			}
			
		}
		transport_init_done = 1;
	}

	foiscsi_inst = foiscsi_alloc(sizeof(struct csio_foiscsi_devinst));
	if (!foiscsi_inst) {
		rv = -ENODEV;
		csio_err(hw, "foiscsi_hw allocation failed\n");
		goto out;
	}
	
	foiscsi_inst->hw = hw;
	foiscsi_cdev = &foiscsi_inst->foiscsi_cdev;
	
	/* add the foisci_inst in foiscsi_inst_head */
	csio_enq_at_tail(&foiscsi_inst_head, foiscsi_inst);

	/* initialize other fields of foiscsi_cdev */
	foiscsi_cdev->max_init_instances = FW_FOISCSI_INIT_NODE_MAX;
	for (i = 0; i < FW_FOISCSI_INIT_NODE_MAX; i++) {
		csio_mutex_init(&foiscsi_cdev->instance[i].inode_lock);
	}

	/* Enable ipv6 */
	if (!is_t4(hw->adap.params.chip))
		csio_enable_foiscsi_ipv6(hw);
	
	for (i = 0; i < hw->num_t4ports; i++) {
		iface = &foiscsi_cdev->ifaces[hw->t4port[i].portid];
		iface->if_id = FOISCSI_IFACE_INVALID_IFID;
		csio_spin_lock_init(&iface->hlock);
		if (csio_foiscsi_iface_init(hw, i, iface) != CSIO_SUCCESS) {
			rv = -ENODEV;
			goto free_foiscsi_inst;
		}
	}

	rv = csio_foiscsi_sess_table_alloc(&foiscsi_cdev->sess_table,
				1, CSIO_ISCSI_NUM_RNODES);
	if (rv) {
		csio_err(hw, "FOiSCSI hw allocations failed. rv [%d].\n", rv);
		goto free_foiscsi_inst;
	}

#ifdef CSIO_FOISCSI_PERSISTENT_ENABLE
	sprintf(thread_name, "boot_thread%d", hw->dev_num );
	foiscsi_inst->bootlogin.bootlogin_ts = csio_kthread_create(
				bootlogin_threadfunc, (void *)foiscsi_inst,
				thread_name);
	/* wake up thread only when hw initialization is done */
	csio_timer_init(&foiscsi_inst->bootlogin.bootlogin_timer,
					csio_bootlogin_start, foiscsi_inst);
	csio_timer_start(&foiscsi_inst->bootlogin.bootlogin_timer, 3000);
#endif
	return rv;

free_foiscsi_inst:
	csio_deq_elem((struct csio_list *)foiscsi_inst);
	foiscsi_free(foiscsi_inst);
out:
	return rv;
}

int csio_foiscsi_transport_uninit(struct csio_hw *hw)
{
	struct csio_foiscsi_devinst *dev;
	struct csio_list *elem;
	
	/*
	 * bail out if we are not even initialized.
	 * */
	if (!transport_init_done)
		goto out;

	dev = get_foiscsi_inst(hw);
	if (!dev) {
		csio_err(hw, "foiscsi inst not found\n");
		goto out;
	}
#ifdef CSIO_FOISCSI_PERSISTENT_ENABLE
	csio_timer_stop(&dev->bootlogin.bootlogin_timer);
#endif
	CSIO_DB_ASSERT(
		csio_list_empty(&dev->foiscsi_cdev.sess_table.rni_list));
	foiscsi_free(dev->foiscsi_cdev.sess_table.bitmap);

	elem = (struct csio_list *)dev;
	csio_deq_elem(elem);
	foiscsi_free(elem);
out:
	return 0;
}

/* No protection for trasport_list because register fn is called in serial
 * order as of now. */
int csio_foiscsi_register_transport(struct csio_hw *hw,
		struct foiscsi_transport *transport)
{
	/*unsigned int i;*/

	if (!transport)
		return -1;

	csio_dbg(hw, "%s: transport type %d\n", __FUNCTION__, transport->type);

	/* Only chelsio transport(in all platform) can have the registered ioctl
	 * handler. */
	if (!is_chelsio_transport(transport->type) && transport->ioctl_handler)
		return -1;
#if 0
	for (i = 0; i < MAX_TRANSPORT_SUPPORTED; i++) {
		if (!transport_list[i]) {
			transport_list[i] = transport;
			num_transport++;
			break;
		}
	}
	if (i == MAX_TRANSPORT_SUPPORTED)
		return -1;
#endif
	return 0;
}

/* NOT USED AS OF NOW */
int csio_foiscsi_unregister_transport(struct csio_hw *hw,
		struct foiscsi_transport *transport)
{
#if 0
	unsigned int i;

	for (i = 0; i < MAX_TRANSPORT_SUPPORTED; i++) {
		if (transport_list[i] == transport) {
			transport_list[i] = NULL;
			num_transport--;
			break;
		}
	}
#endif
	return 0;
}

static struct csio_foiscsi_iface *
csio_foiscsi_iface_addr_get(struct csio_hw *hw,
		struct csio_ctrl_foiscsi *foiscsi_cdev,
		struct foiscsi_login_info *linfo)
{
	struct csio_foiscsi_iface *iface = NULL;
	int i = 0, got = 0;
	
	
	for (i = 0; i < hw->num_t4ports; i++) {
		iface = &foiscsi_cdev->ifaces[i];
		csio_spin_lock_irq(hw, &iface->hlock);
		if (!iface->op_pending) {
			if (linfo->ip_type == TYPE_IPV4) {
				if (iface->ipv4.addr == linfo->src_ip.ip4) {
					iface->ipv4.refcnt++;
#if 0
					csio_dbg(hw,
					 "got interface %d ip %u.%u.%u.%u\n", i,
					 (iface->ipv4.addr >> 24) & 0xff,
					 (iface->ipv4.addr >> 16) & 0xff,
					 (iface->ipv4.addr >> 8) & 0xff,
					 iface->ipv4.addr & 0xff);
					csio_dbg(hw,
					  "%s: iface->ipv4.refcnt [%d]\n",
					  __FUNCTION__, iface->ipv4.refcnt);
#endif
					got = 1;
				} else if (iface->vlan_info.ipv4.addr ==
							   linfo->src_ip.ip4) {
					iface->vlan_info.ipv4.refcnt++;
#if 0
					csio_dbg(hw,
					  "got interface %d, vlanid %d, ip "
					  "%u.%u.%u.%u\n", i,
					  iface->vlan_info.vlan_id,
					  (iface->vlan_info.ipv4.addr >> 24) &
									  0xff,
					  (iface->vlan_info.ipv4.addr >> 16) &
									  0xff,
					  (iface->vlan_info.ipv4.addr >> 8) &
									  0xff,
					  iface->vlan_info.ipv4.addr & 0xff);
					csio_dbg(hw,
					  "%s: iface->vlan_info.ipv4.refcnt "
					  "[%d]\n", __FUNCTION__,
					  iface->vlan_info.ipv4.refcnt);
#endif
					got = 1;
				}
			} else { /* IPv6 */
				if (!csio_memcmp((void*) iface->ipv6.addr,
					(void *) linfo->src_ip.ip6, 16)) {
					iface->ipv6.refcnt++;
					got = 1;
					csio_dbg(hw,
					 "got interface %d ip %pI6\n", i,
					 iface->ipv6.addr);
					csio_dbg(hw,
					  "%s: iface->ipv6.refcnt [%d]\n",
					  __FUNCTION__, iface->ipv6.refcnt);

				} else if (!csio_memcmp((void *)iface->\
						vlan_info.ipv6.addr,
						linfo->src_ip.ip6, 16)) {
					iface->vlan_info.ipv6.refcnt++;
					got = 1;

					csio_dbg(hw,
					 "got interface %d vlanid %d ip %pI6\n",
					 i, iface->vlan_info.vlan_id,
					 iface->vlan_info.ipv6.addr);
					csio_dbg(hw, "%s: "
					  "iface->vlan_info.ipv6.refcnt [%d]\n",
					  __FUNCTION__,
					  iface->vlan_info.ipv6.refcnt);
				}
			}
		}
		csio_spin_unlock_irq(hw, &iface->hlock);
		if (got)
			break;
	}
	if (got)
		return iface;
	else
		return NULL;
}

/* iface locked by the caller */
static int csio_foiscsi_iface_addr_put(struct csio_hw *hw,
			struct csio_foiscsi_iface *iface, unsigned int ip_type,
			unsigned int ip, uint8_t *ip6)
{
	int done = 0;

	if (ip_type == TYPE_IPV4) {
		CSIO_DB_ASSERT(ip);
		if (iface->ipv4.addr == ip) {
			CSIO_DB_ASSERT(iface->ipv4.refcnt > 0);
			iface->ipv4.refcnt--;
			done = 1;
			csio_dbg(hw, "%s: iface->ipv4.refcnt [%d]\n",
				__FUNCTION__, iface->ipv4.refcnt);
		} else if (iface->vlan_info.ipv4.addr == ip) {
			CSIO_DB_ASSERT(iface->vlan_info.ipv4.refcnt > 0);
			iface->vlan_info.ipv4.refcnt--;
			done = 1;
			csio_dbg(hw, "%s: iface->vlan_info.ipv4.refcnt [%d]\n",
				__FUNCTION__, iface->vlan_info.ipv4.refcnt);
		}
	} else { /* IPV6 */
		CSIO_DB_ASSERT(ip6);
		if (!memcmp(iface->ipv6.addr, ip6, 16)) {
			CSIO_DB_ASSERT(iface->ipv6.refcnt > 0);
			iface->ipv6.refcnt--;
			done = 1;
			csio_dbg(hw, "%s: iface->ipv6.refcnt [%d]\n",
				__FUNCTION__, iface->ipv6.refcnt);
			
		} else if (!memcmp(iface->vlan_info.ipv6.addr, ip6, 16)) {
			CSIO_DB_ASSERT(iface->vlan_info.ipv6.refcnt > 0);
			iface->vlan_info.ipv6.refcnt--;
			done = 1;
			csio_dbg(hw, "%s: iface->vlan_info.ipv6.refcnt [%d]\n",
				__FUNCTION__, iface->vlan_info.ipv6.refcnt);
		}
	}
	return done;
}

csio_retval_t
csio_foiscsi_link_up_cmd_handler(struct csio_hw *hw,
		struct csio_foiscsi_iface_ioctl *req)
{
	int rc = CSIO_SUCCESS;
	struct csio_foiscsi_iface *iface;
	struct csio_ctrl_foiscsi *foiscsi_cdev;

	if (req->ifid >= hw->num_t4ports) {
		csio_err(hw, "invalid ifid %d\n", req->ifid);
		req->retval = FOISCSI_ERR_INVALID_REQUEST;
		return EINVAL;
	}
	foiscsi_cdev = get_foiscsi_cdev(hw);
	if (!foiscsi_cdev) {
		csio_err(hw, "foiscsi inst not found\n");
		req->retval = FOISCSI_ERR_INST_NOT_FOUND;
		return EINVAL;
	}

	iface = &foiscsi_cdev->ifaces[req->ifid];
	csio_mutex_lock(&iface->mlock);

	if (iface->op_pending) {
		req->retval = FOISCSI_ERR_IFACE_BUSY;
		rc = EBUSY;
		goto ulock_out;
	}
	/* iface->op_pending = 1; */

	rc = csio_foiscsi_do_link_cmd(hw, iface->tport->portid, req->flags,
			FW_CHNET_IFACE_CMD_SUBOP_LINK_UP, iface->tport->portid);
	req->retval = rc;
	if (rc != CSIO_SUCCESS)
		iface->op_pending = 0;

ulock_out:
	csio_mutex_unlock(&iface->mlock);
	return rc;
}

csio_retval_t
csio_foiscsi_link_down_cmd_handler(struct csio_hw *hw,
		struct csio_foiscsi_iface_ioctl *req)
{
	int rc = CSIO_SUCCESS;
	struct csio_foiscsi_iface *iface;
	struct csio_ctrl_foiscsi *foiscsi_cdev;

	if (req->ifid >= hw->num_t4ports) {
		csio_err(hw, "invalid ifid %d\n", req->ifid);
		req->retval = FOISCSI_ERR_IFACE_INVALID_PORT;
		return EINVAL;
	}

	foiscsi_cdev = get_foiscsi_cdev(hw);
	if (!foiscsi_cdev) {
		csio_err(hw, "foiscsi inst not found\n");
		req->retval = FOISCSI_ERR_INST_NOT_FOUND;
		return EINVAL;
	}

	iface = &foiscsi_cdev->ifaces[req->ifid];
	csio_mutex_lock(&iface->mlock);

	if (iface->op_pending) {
		req->retval = FOISCSI_ERR_IFACE_BUSY;
		rc = EBUSY;
		goto ulock_out;
	}
	/* iface->op_pending = 1; */

	rc = csio_foiscsi_do_link_cmd(hw, iface->tport->portid, req->flags,
			FW_CHNET_IFACE_CMD_SUBOP_LINK_DOWN,
			iface->tport->portid);
	req->retval = rc;
	if (rc != CSIO_SUCCESS)
		iface->op_pending = 0;

ulock_out:
	csio_mutex_unlock(&iface->mlock);
	return rc;
}

csio_retval_t
csio_foiscsi_vlan_cmd_handler(struct csio_hw *hw, uint32_t op,
		struct csio_foiscsi_ifconf_ioctl *req, void *handle)
{
	enum csio_oss_error rc = CSIO_SUCCESS;
	struct csio_foiscsi_iface *iface;
	struct csio_ctrl_foiscsi *foiscsi_cdev;

	if (req->ifid >= hw->num_t4ports) {
		csio_err(hw, "invalid ifid %d\n", req->ifid);
		req->retval = FOISCSI_ERR_INVALID_PARAM;
		return CSIO_INVAL;
	}

	if (!(foiscsi_cdev = get_foiscsi_cdev(hw))) {
		csio_err(hw, "foiscsi inst not found\n");
		req->retval = FOISCSI_ERR_INVALID_PARAM;
		return CSIO_INVAL;
	}

	iface = &foiscsi_cdev->ifaces[req->ifid];
	csio_mutex_lock(&iface->mlock);

	if (iface->if_state != FOISCSI_IFACE_STATE_LINK_UP) {
		csio_dbg(hw, "%s: link [%0x] is not up\n",
				__FUNCTION__, req->ifid);
		req->retval = FOISCSI_ERR_IFACE_ENOLINK;
		rc = CSIO_INVAL;
		goto ulock_out;
	}

	if ((iface->vlan_info.ipv4.addr) ||
	    (iface->vlan_info.ipv6.addr[0] ||
	     iface->vlan_info.ipv6.addr[1] ||
	     iface->vlan_info.ipv6.addr[2] ||
	     iface->vlan_info.ipv6.addr[3])) {
		req->retval = FOISCSI_ERR_IFACE_BUSY;
		rc = CSIO_BUSY;
		csio_dbg(hw, "%s: addr in use. Cannot change vlan\n",
				__FUNCTION__);
		goto ulock_out;
	}
	if (iface->op_pending) {
		req->retval = FOISCSI_ERR_IFACE_BUSY;
		rc = EBUSY;
		goto ulock_out;
	}
	iface->op_pending = 1;
	iface->transport_handle = handle;
	iface->vlan_info.vlan_id = req->vlanid;

	csio_dbg(hw, "iface->if_id [%0x], iface->if_state [%0x]\n",
			iface->if_id, iface->if_state);

	rc = csio_foiscsi_do_vlan_req(hw, op, iface->if_id, req->vlanid,
			iface->tport->portid);
	
	req->retval = rc;
	if (rc != CSIO_SUCCESS) {
		iface->op_pending = 0;
		iface->transport_handle = NULL;
	}
ulock_out:
	csio_mutex_unlock(&iface->mlock);
	return rc;
}

csio_retval_t
csio_foiscsi_mtu_cmd_handler(struct csio_hw *hw, uint32_t op,
		struct csio_foiscsi_ifconf_ioctl *req, void *handle)
{
	enum csio_oss_error rc = CSIO_SUCCESS;
	struct csio_foiscsi_iface *iface;
	struct csio_ctrl_foiscsi *foiscsi_cdev;

	if (req->ifid >= hw->num_t4ports) {
		csio_err(hw, "invalid ifid %d\n", req->ifid);
		req->retval = FOISCSI_ERR_INVALID_PARAM;
		return CSIO_INVAL;
	}

	if (!(foiscsi_cdev = get_foiscsi_cdev(hw))) {
		csio_err(hw, "foiscsi inst not found\n");
		req->retval = FOISCSI_ERR_INVALID_PARAM;
		return CSIO_INVAL;
	}

	iface = &foiscsi_cdev->ifaces[hw->t4port[req->ifid].portid];
	csio_dbg(hw, "%s: iface->if_id [%0x], iface->if_state [%0x] "
			"iface->ipv4.refcnt [%u], iface->ipv6.refcnt [%u] \n", __FUNCTION__,
			iface->if_id, iface->if_state, iface->ipv4.refcnt, iface->ipv6.refcnt);

	csio_mutex_lock(&iface->mlock);

	if (iface->if_state != FOISCSI_IFACE_STATE_LINK_UP) {
		/* Link is not up */
		csio_dbg(hw, "%s: link [%0x] is not up\n",
				__FUNCTION__, req->ifid);
		req->retval = FOISCSI_ERR_IFACE_ENOLINK;
		rc = CSIO_INVAL;
		goto ulock_out;
	}

	if (iface->ipv4.refcnt > 0 || iface->ipv6.refcnt > 0) {
		req->retval = FOISCSI_ERR_IFACE_BUSY;
		rc = CSIO_BUSY;
		goto ulock_out;
	}
	if (iface->op_pending) {
		req->retval = FOISCSI_ERR_IFACE_BUSY;
		rc = CSIO_BUSY;
		goto ulock_out;
	}
	if (op == CSIO_FOISCSI_IFCONF_MTU_GET_IOCTL) {
		req->mtu = iface->mtu;
		goto ulock_out;
	}
	iface->op_pending = 1;
	iface->transport_handle = handle;
	iface->old_mtu = iface->mtu;
	iface->mtu = req->mtu;

	csio_dbg(hw, "iface->if_id [%0x], iface->if_state [%0x]\n",
			iface->if_id, iface->if_state);

	rc = csio_foiscsi_do_mtu_req(hw, op, iface->if_id, req->mtu,
			iface->tport->portid);
	req->retval = rc;
	if (rc != CSIO_SUCCESS) {
		iface->op_pending = 0;
		iface->transport_handle = NULL;
	}
ulock_out:
	csio_mutex_unlock(&iface->mlock);
	return rc;
}

csio_retval_t
csio_foiscsi_iface_get(struct csio_hw *hw,
		struct csio_foiscsi_ifconf_ioctl *req)
{
	int rc = CSIO_SUCCESS;
	struct csio_foiscsi_iface *iface;
	struct csio_ctrl_foiscsi *foiscsi_cdev;

	csio_dbg(hw, "%s: req->ifid [%u]\n", __FUNCTION__, req->ifid);

	if (req->ifid >= hw->num_t4ports) {
		csio_err(hw, "invalid ifid %d\n", req->ifid);
		return EINVAL;
	}

	if (!(foiscsi_cdev = get_foiscsi_cdev(hw))) {
		csio_err(hw, "foiscsi inst not found\n");
		return EINVAL;
	}

	iface = &foiscsi_cdev->ifaces[req->ifid];

	csio_mutex_lock(&iface->mlock);
	csio_dbg(hw, "%s: iface->if_id [%0x], vlanid [%u], "
			"iface->if_state [%0x], iface->ipv4.refcnt [%u] "
			"iface->ipv6.refcnt [%u] "
			"iface->mtu [%u]\n",
			__FUNCTION__, iface->if_id, iface->vlan_info.vlan_id,
			iface->if_state, iface->ipv4.refcnt,
			iface->ipv6.refcnt, iface->mtu);

	req->vlanid = iface->vlan_info.vlan_id;
	req->mtu = iface->mtu;
	req->address_state = iface->address_state;

	csio_mutex_unlock(&iface->mlock);

	return rc;
}

csio_retval_t
csio_foiscsi_ifconf_ipv4_set_cmd_handler(struct csio_hw *hw, uint32_t op,
		struct csio_foiscsi_ifconf_ioctl *req, void *handle)
{
	enum csio_oss_error rc = CSIO_SUCCESS;
	struct csio_foiscsi_iface *iface;
	struct csio_ctrl_foiscsi *foiscsi_cdev;
	uint16_t vlanid;

	if (req->ifid >= hw->num_t4ports) {
		csio_err(hw, "invalid ifid %d\n", req->ifid);
		req->retval = FOISCSI_ERR_INVALID_PARAM;
		return CSIO_INVAL;
	}

	if (!(foiscsi_cdev = get_foiscsi_cdev(hw))) {
		csio_err(hw, "foiscsi inst not found\n");
		req->retval = FOISCSI_ERR_INVALID_PARAM;
		return CSIO_INVAL;
	}

	vlanid = req->vlanid & 0x0fff;
	iface = &foiscsi_cdev->ifaces[hw->t4port[req->ifid].portid];
	csio_dbg(hw, "%s: iface->if_id [%0x], vlan-id [%d], vlan-prio [%d], "
			"iface->if_state [%0x], iface->ipv4.refcnt [%u]\n",
			__FUNCTION__, iface->if_id, vlanid,
			(req->vlanid >> 13) & 0xf, iface->if_state,
			iface->ipv4.refcnt);

	csio_mutex_lock(&iface->mlock);

	if (iface->if_state != FOISCSI_IFACE_STATE_LINK_UP) {
		csio_dbg(hw, "%s: link [%0x] is not up\n",
				__FUNCTION__, req->ifid);
		req->retval = FOISCSI_ERR_IFACE_ENOLINK;
		rc = CSIO_INVAL;
		goto ulock_out;
	}

	if (vlanid == 4095) {
		if (iface->ipv4.refcnt > 0) {
			req->retval = FOISCSI_ERR_IFACE_BUSY;
			rc = CSIO_BUSY;
			goto ulock_out;
		}
	} else if (vlanid >= 2 && vlanid < 4095) {
		if (iface->vlan_info.ipv4.refcnt > 0 ) {
			req->retval = FOISCSI_ERR_IFACE_BUSY;
			rc = CSIO_BUSY;
			goto ulock_out;
		}
	}
	if (iface->op_pending) {
		req->retval = FOISCSI_ERR_IFACE_BUSY;
		rc = CSIO_BUSY;
		goto ulock_out;
	}
	iface->op_pending = 1;
	iface->transport_handle = handle;

	if (vlanid >= 2 && vlanid < 4095) {
		iface->vlan_info.ipv4.addr = req->v4.ipv4_addr;
		iface->vlan_info.ipv4.mask = req->v4.ipv4_mask;
		iface->vlan_info.vlan_id = req->vlanid;
		iface->gw = req->v4.ipv4_gw;
	} else {
		iface->ipv4.addr = req->v4.ipv4_addr;
		iface->ipv4.mask = req->v4.ipv4_mask;
		iface->gw = req->v4.ipv4_gw;
	}

	rc = csio_foiscsi_ifconf_ip_set(hw, op, iface->if_id, req,
			iface->tport->portid);
	req->retval = rc;
	if (rc != CSIO_SUCCESS) {
		iface->op_pending = 0;
		iface->transport_handle = NULL;
	}
ulock_out:
	csio_mutex_unlock(&iface->mlock);
	return rc;

}

csio_retval_t
csio_foiscsi_ifconf_ipv6_set_cmd_handler(struct csio_hw *hw, uint32_t op,
		struct csio_foiscsi_ifconf_ioctl *req, void *handle)
{
	enum csio_oss_error rc = CSIO_SUCCESS;
	struct csio_foiscsi_iface *iface;
	struct csio_ctrl_foiscsi *foiscsi_cdev;
	uint16_t vlanid;

	if (req->ifid >= hw->num_t4ports) {
		csio_err(hw, "invalid ifid %d\n", req->ifid);
		req->retval = FOISCSI_ERR_INVALID_PARAM;
		return CSIO_INVAL;
	}

	if (!(foiscsi_cdev = get_foiscsi_cdev(hw))) {
		csio_err(hw, "foiscsi inst not found\n");
		req->retval = FOISCSI_ERR_INVALID_PARAM;
		return CSIO_INVAL;
	}

	vlanid = req->vlanid & 0x0fff;
	iface = &foiscsi_cdev->ifaces[hw->t4port[req->ifid].portid];
	csio_dbg(hw, "%s: iface->if_id [%0x], vlan-id [%d], vlan-prio [%d], "
			"iface->if_state [%0x], iface->ipv6.refcnt [%u]\n",
			__FUNCTION__, iface->if_id, vlanid,
			(req->vlanid >> 13) & 0xf, iface->if_state,
			iface->ipv6.refcnt);

	csio_mutex_lock(&iface->mlock);

	if (iface->if_state != 1) {
		csio_dbg(hw, "%s: link [%0x] is not up\n",
				__FUNCTION__, req->ifid);
		req->retval = FOISCSI_ERR_IFACE_ENOLINK;
		rc = CSIO_INVAL;
		goto ulock_out;
	}

	if (vlanid == 4095) {
		if (iface->ipv6.refcnt > 0) {
			req->retval = FOISCSI_ERR_IFACE_BUSY;
			rc = CSIO_BUSY;
			goto ulock_out;
		}
	} else if (vlanid >= 2 && vlanid < 4095) {
		if (iface->vlan_info.ipv6.refcnt > 0 ) {
			req->retval = FOISCSI_ERR_IFACE_BUSY;
			rc = CSIO_BUSY;
			goto ulock_out;
		}
	}
	if (iface->op_pending) {
		req->retval = FOISCSI_ERR_IFACE_BUSY;
		rc = CSIO_BUSY;
		goto ulock_out;
	}
	iface->op_pending = 1;
	iface->transport_handle = handle;

	if (vlanid >= 2 && vlanid < 4095) {
		csio_memcpy(iface->vlan_info.ipv6.addr, req->v6.ipv6_addr, 16);
		csio_memcpy(iface->gw6, req->v6.ipv6_gw, 16);
		iface->vlan_info.ipv6.prefix_len = req->v6.prefix_len;

		iface->vlan_info.vlan_id = req->vlanid;
	} else {
		csio_memcpy(iface->ipv6.addr, req->v6.ipv6_addr, 16);
		csio_memcpy(iface->gw6, req->v6.ipv6_gw, 16);
		iface->ipv6.prefix_len = req->v6.prefix_len;
	}

	rc = csio_foiscsi_ifconf_ip_set(hw, op, iface->if_id, req,
			iface->tport->portid);
	req->retval = rc;
	if (rc != CSIO_SUCCESS) {
		iface->op_pending = 0;
		iface->transport_handle = NULL;
	}
ulock_out:
	csio_mutex_unlock(&iface->mlock);
	return rc;

}

csio_retval_t
csio_foiscsi_ifconf_ip_get(struct csio_hw *hw,
		struct csio_foiscsi_ifconf_ioctl *req)
{
	csio_retval_t rc = CSIO_SUCCESS;
	struct csio_foiscsi_iface *iface = NULL;
	struct csio_foiscsi_iface_ipv4 *ifipv4 = NULL;
	struct csio_foiscsi_iface_ipv6 *ifipv6 = NULL;
	struct csio_ctrl_foiscsi *foiscsi_cdev;
	unsigned int vlan = 0;

	if (req->ifid >= hw->num_t4ports) {
		csio_err(hw, "invalid ifid %d\n", req->ifid);
		rc = EINVAL;
		goto out;
	}

	if (!(foiscsi_cdev = get_foiscsi_cdev(hw))) {
		csio_err(hw, "foiscsi inst not found\n");
		return EINVAL;
	}

	iface = &foiscsi_cdev->ifaces[req->ifid];

	csio_dbg(hw, "%s: waiting on mutex\n", __FUNCTION__);

	csio_mutex_lock(&iface->mlock);
	csio_dbg(hw, "%s: iface->if_id [%0x], vlanid [%d], "
			"iface->if_state [%0x], iface->ipv4.refcnt [%u]\n",
			__FUNCTION__, iface->if_id, req->vlanid,
			iface->if_state, iface->ipv4.refcnt);

	if (((req->vlanid & 0x0fff) >= 2) && ((req->vlanid & 0x0fff) < 4095))
		vlan = 1;

	if (req->type == TYPE_IPV4) {
		if (vlan)
			ifipv4 = &iface->vlan_info.ipv4;
		else
			ifipv4 = &iface->ipv4;

		req->v4.ipv4_addr = ifipv4->addr;
		req->v4.ipv4_mask = ifipv4->mask;
		req->v4.ipv4_gw = iface->gw;
	} else { /* IPv6 */
		if(req->subop == OP_LLOCAL) {
			if (vlan)
				ifipv6 = &iface->link_local.ipv6_vlan;
			else
				ifipv6 = &iface->link_local.ipv6;
		} else {
			if (vlan)
				ifipv6 = &iface->vlan_info.ipv6;
			else
				ifipv6 = &iface->ipv6;
		}
		csio_memcpy(req->v6.ipv6_addr, ifipv6->addr, 16);
		csio_memcpy(req->v6.ipv6_gw, iface->gw6, 16);
		req->v6.prefix_len = ifipv6->prefix_len;
	}
	req->type = iface->address_state;

	csio_mutex_unlock(&iface->mlock);
out:
	return rc;
}

csio_retval_t
csio_foiscsi_ifconf_dhcp_set_cmd_handler(struct csio_hw *hw,
		struct csio_foiscsi_ifconf_ioctl *req, void *handle)
{
	enum csio_oss_error rc = CSIO_SUCCESS;
	struct csio_foiscsi_iface *iface = NULL;
	struct csio_ctrl_foiscsi *foiscsi_cdev;

	if (req->ifid >= hw->num_t4ports) {
		csio_err(hw, "invalid ifid %d\n", req->ifid);
		req->retval = FOISCSI_ERR_INVALID_PARAM;
		return EINVAL;
	}

	if (!(foiscsi_cdev = get_foiscsi_cdev(hw))) {
		csio_err(hw, "foiscsi inst not found\n");
		req->retval = FOISCSI_ERR_INVALID_PARAM;
		return EINVAL;
	}

	iface = &foiscsi_cdev->ifaces[req->ifid];
	csio_mutex_lock(&iface->mlock);

	if (iface->if_state != FOISCSI_IFACE_STATE_LINK_UP) {
		csio_dbg(hw, "%s: link [%0x] is not up\n",
				__FUNCTION__, req->ifid);
		req->retval = FOISCSI_ERR_IFACE_ENOLINK;
		rc = CSIO_INVAL;
		goto unlock_out;
	}

	csio_dbg(hw, "%s: iface [%p], vlanid [%d], iface->if_id [%0x], "
			"iface->if_state [%0x]\n",
			__FUNCTION__, iface, req->vlanid,
			iface->if_id, iface->if_state);

	if (req->vlanid == 4095) {
		if (iface->ipv4.refcnt > 0) {
			req->retval = FOISCSI_ERR_IFACE_BUSY;
			rc = CSIO_BUSY;
			goto unlock_out;
		}
	} else if (req->vlanid >= 2 && req->vlanid < 4095) {
		if (iface->vlan_info.ipv4.refcnt > 0 ) {
			req->retval = FOISCSI_ERR_IFACE_BUSY;
			rc = CSIO_BUSY;
			goto unlock_out;
		}
	}
	if (iface->op_pending) {
		req->retval = FOISCSI_ERR_IFACE_BUSY;
		rc = CSIO_BUSY;
		goto unlock_out;
	}
	iface->op_pending = 1;
	iface->transport_handle = handle;

	rc = csio_foiscsi_ifconf_dhcp_set(hw, iface->if_id, req,
			iface->tport->portid);

	req->retval = rc;
	if (rc != CSIO_SUCCESS) {
		iface->op_pending = 0;
		iface->transport_handle = NULL;
	}
unlock_out:
	csio_mutex_unlock(&iface->mlock);
	return rc;
}

csio_retval_t
csio_foiscsi_ioctl_assign_instance_handler(struct csio_hw *hw,
		struct foiscsi_instance *ini_inst, void *handle)
{
	enum csio_oss_error rc = CSIO_SUCCESS;
	unsigned int inst_idx, i, flowid = 0;
	struct csio_foiscsi_iface *iface = NULL;
	struct csio_ctrl_instance *inst;
	struct csio_ctrl_foiscsi *foiscsi_cdev;

	if ((ini_inst->id <= 0) || (ini_inst->id > FW_FOISCSI_INIT_NODE_MAX)) {
		csio_err(hw, "invalid initiator instance %d\n", ini_inst->id);
		ini_inst->retval = FOISCSI_ERR_INVALID_INDEX;
		rc = -1;
		goto out;
	}

	if (!(foiscsi_cdev = get_foiscsi_cdev(hw))) {
		csio_err(hw, "foiscsi inst not found\n");
		ini_inst->retval = FOISCSI_ERR_INST_NOT_FOUND;
		rc = -1;
		goto out;
	}

	inst_idx = ini_inst->id - 1;

	for (i = 0; i < hw->num_t4ports; i++) {
		iface = &foiscsi_cdev->ifaces[i];
		flowid = iface->if_id;
		if (flowid) {
			csio_dbg(hw, "Got flowid [0x%x] at iface idx %d\n",
					flowid, i);
			break;
		}
	}
	if (!flowid) {
		csio_dbg(hw, "iface not provisioned\n");
		ini_inst->retval = FOISCSI_ERR_IFACE_NOT_PROVISIONED;
		rc = -1;
		goto out;
	}

	inst = &foiscsi_cdev->instance[inst_idx];
	csio_mutex_lock(&inst->inode_lock);

	if (inst->op_pending) {
		ini_inst->retval = FOISCSI_ERR_INST_BUSY;
		rc = -1;
		goto ulock_out;
	}
	inst->op_pending = 1;
	inst->transport_handle = handle;

	rc = csio_foiscsi_assign_instance_handler(hw, iface->if_id,
			ini_inst, inst_idx+1);
	ini_inst->retval = rc;
	if (rc != CSIO_SUCCESS) {
		inst->op_pending = 0;
		inst->transport_handle = NULL;
	}
ulock_out:
	csio_mutex_unlock(&inst->inode_lock);
out:
	return rc;
}

csio_retval_t
csio_foiscsi_ioctl_clear_instance_handler(struct csio_hw *hw,
		struct foiscsi_instance *ini_inst, void *handle)
{
	unsigned int inst_idx;
	enum csio_oss_error rc = CSIO_SUCCESS;
	struct csio_ctrl_instance *inst;
	struct csio_ctrl_foiscsi *foiscsi_cdev;

	if ((ini_inst->id <= 0) || (ini_inst->id > FW_FOISCSI_INIT_NODE_MAX)) {
		ini_inst->retval = FOISCSI_ERR_INVALID_INDEX;
		return CSIO_INVAL;
	}

	inst_idx = ini_inst->id - 1;

	if (!(foiscsi_cdev = get_foiscsi_cdev(hw))) {
		csio_err(hw, "foiscsi inst not found\n");
		ini_inst->retval = FOISCSI_ERR_INST_NOT_FOUND;
		return CSIO_INVAL;
	}

	inst = &foiscsi_cdev->instance[inst_idx];
	csio_mutex_lock(&inst->inode_lock);

	if (inst->op_pending) {
		ini_inst->retval = FOISCSI_ERR_INST_BUSY;
		rc = CSIO_BUSY;
		goto ulock_out;
	}
	inst->op_pending = 1;
	inst->transport_handle = handle;

	rc = csio_foiscsi_clear_instance_handler(hw, ini_inst, inst_idx+1);
	ini_inst->retval = rc;
	if (rc != CSIO_SUCCESS) {
		inst->op_pending = 0;
		inst->transport_handle = NULL;
	}
ulock_out:
	csio_mutex_unlock(&inst->inode_lock);
	return rc;
}

csio_retval_t
csio_foiscsi_set_chap_secret(struct csio_hw *hw,
		struct foiscsi_instance *ini_inst)
{
	unsigned int inst_idx;
	csio_retval_t rc = CSIO_SUCCESS;
	struct csio_ctrl_instance *inst;
	struct csio_ctrl_foiscsi *foiscsi_cdev;

	if ((ini_inst->id <= 0) || (ini_inst->id > FW_FOISCSI_INIT_NODE_MAX)) {
		ini_inst->retval = FOISCSI_ERR_INVALID_INDEX;
		return CSIO_INVAL;
	}

	inst_idx = ini_inst->id - 1;

	if (!(foiscsi_cdev = get_foiscsi_cdev(hw))) {
		csio_err(hw, "foiscsi inst not found\n");
		ini_inst->retval = FOISCSI_ERR_INST_NOT_FOUND;
		return CSIO_INVAL;
	}

	inst = &foiscsi_cdev->instance[inst_idx];
	csio_mutex_lock(&inst->inode_lock);
	rc = csio_foiscsi_set_chap_secret_handler(hw, ini_inst);
	csio_mutex_unlock(&inst->inode_lock);
	return rc;
}


csio_retval_t
csio_foiscsi_ioctl_show_instance_handler(struct csio_hw *hw,
	struct foiscsi_instance *ini_inst)
{
	return csio_foiscsi_show_instance_handler(hw, ini_inst);
}

csio_retval_t
csio_foiscsi_ioctl_get_count_handler(struct csio_hw *hw,
		struct foiscsi_count *cnt)
{
	return csio_foiscsi_get_count_handler(hw, cnt);
}

csio_retval_t
csio_foiscsi_ioctl_get_sess_info_handler (struct csio_hw *hw,
		struct foiscsi_sess_info *sess_info)
{
	return csio_foiscsi_get_sess_info_handler(hw, sess_info);
}

#ifdef CSIO_FOISCSI_PERSISTENT_ENABLE
csio_retval_t
csio_foiscsi_ioctl_persistent_show_handler(struct csio_hw *hw,
				struct iscsi_persistent_target_db *target_db)
{
	return csio_foiscsi_persistent_show_handler(hw, target_db);
}

csio_retval_t
csio_foiscsi_ioctl_persistent_clear_handler(struct csio_hw *hw, uint8_t idx)
{
	return csio_foiscsi_persistent_clear_handler(hw, idx);
}
#endif

csio_retval_t
csio_ln_login_handler(struct csio_hw *hw, void *arg1,
			struct foiscsi_login_info *linfo,
			bool do_disc, void *handle)
{
	enum csio_oss_error rc = CSIO_SUCCESS;
	unsigned int inst_idx = linfo->inode_id - 1;
	struct csio_ctrl_instance *inst;
	struct csio_foiscsi_iface *iface;
	struct csio_ctrl_foiscsi *foiscsi_cdev;
#ifdef CSIO_FOISCSI_PERSISTENT_ENABLE
	struct csio_lnode_iscsi *lni = NULL;
	struct csio_lnode *ln = NULL;
#endif

	if (inst_idx >= FW_FOISCSI_INIT_NODE_MAX) {
		csio_err(hw, "invalid initiator instance id %d\n", inst_idx);
		return CSIO_INVAL;
	}

	if (!(foiscsi_cdev = get_foiscsi_cdev(hw))) {
		csio_err(hw, "foiscsi inst not found\n");
		return CSIO_INVAL;
	}

	inst = &foiscsi_cdev->instance[inst_idx];

	if (inst->op_pending) {
		return CSIO_BUSY;
	}
	
	csio_mutex_lock(&inst->inode_lock);

	iface = csio_foiscsi_iface_addr_get(hw, foiscsi_cdev, linfo);
	if (!iface) {
		csio_err(hw, "Interface not provisioned\n");
		rc = FOISCSI_ERR_IFACE_NOT_PROVISIONED;
		goto ulock_out;
	}
	if (iface->if_state != FOISCSI_IFACE_STATE_LINK_UP) {
		csio_dbg(hw, "%s: link is not up\n", __FUNCTION__);
		rc = FOISCSI_ERR_IFACE_ENOLINK;
		goto ulock_out;
	}
	inst->op_pending = 1;
	inst->transport_handle = handle;
	inst->portid = iface->tport->portid;

	rc = csio_ln_login(hw, arg1, linfo, do_disc, inst_idx+1);
	if (rc != CSIO_SUCCESS) {
		csio_spin_lock_irq(hw, &iface->hlock);
		csio_foiscsi_iface_addr_put(hw, iface, linfo->ip_type,
			linfo->src_ip.ip4, linfo->src_ip.ip6);
		csio_spin_unlock_irq(hw, &iface->hlock);
		inst->op_pending = 0;
		inst->transport_handle = NULL;
		goto ulock_out;
	}

#ifdef CSIO_FOISCSI_PERSISTENT_ENABLE	
	if (linfo->persistent) {
		ln = csio_foiscsi_get_lnode(hw, linfo->inode_id);
		if (!ln) {
			csio_dbg(hw, "inode not found\n");
			rc = FOISCSI_ERR_INVALID_INDEX;
			goto ulock_out;
		}
		
		lni = csio_lnode_to_iscsi(ln);
		
		rc = csio_add_persistent_target(hw, linfo, lni, iface);
		if(rc != CSIO_SUCCESS) {
			csio_err(hw, "failed to add to persistent db\n");
			goto ulock_out;
		}
	}
#endif
ulock_out:
	csio_mutex_unlock(&inst->inode_lock);
	return rc;
}

csio_retval_t
csio_ln_logout_handler(struct csio_hw *hw, void *arg1,
    struct foiscsi_logout_info *linfo, void *handle)
{
	enum csio_oss_error rc = CSIO_SUCCESS;
	unsigned int inst_idx = linfo->inode_id - 1;
	struct csio_ctrl_instance *inst;
	struct csio_ctrl_foiscsi *foiscsi_cdev;
	
	if (inst_idx >= FW_FOISCSI_INIT_NODE_MAX) {
		csio_err(hw, "invalid initiator instance id %d\n", inst_idx);
		return CSIO_INVAL;
	}

	if (!(foiscsi_cdev = get_foiscsi_cdev(hw))) {
		csio_err(hw, "foiscsi inst not found\n");
		return CSIO_INVAL;
	}

	inst = &foiscsi_cdev->instance[inst_idx];
	csio_mutex_lock(&inst->inode_lock);

	if (inst->op_pending) {
		rc = CSIO_BUSY;
		goto ulock_out;
	}
	inst->op_pending = 1;
	inst->transport_handle = handle;

	rc = csio_ln_logout(hw, arg1, linfo, inst_idx+1);
	if (rc != CSIO_SUCCESS) {
		inst->op_pending = 0;
		inst->transport_handle = NULL;
	}
ulock_out:
	csio_mutex_unlock(&inst->inode_lock);
	return rc;
}

/* Response handlers */
static csio_retval_t
handle_link_op_resp(struct csio_hw *hw, uint32_t opcode, uint32_t status,
			unsigned long handle, void *data)
{
	struct csio_foiscsi_iface *iface = NULL;
	struct foiscsi_iface_info *iface_info = data;
	/* struct foiscsi_transport_handle *h = NULL; */
	struct csio_ctrl_foiscsi *foiscsi_cdev;
	csio_retval_t rc = CSIO_SUCCESS;

	if (handle >= hw->num_t4ports) {
		csio_err(hw, "invalid handle %lu\n", handle);
		rc = CSIO_INVAL;
		goto out;
	}

	if (!(foiscsi_cdev = get_foiscsi_cdev(hw))) {
		csio_err(hw, "foiscsi inst not found\n");
		return CSIO_INVAL;
	}

	iface = &foiscsi_cdev->ifaces[hw->t4port[handle].portid];

	csio_dbg(hw, "%s: if_state [%0x]\n",
			__FUNCTION__, iface_info->if_state);
	iface->if_state = iface_info->if_state;
	if (iface->if_state == FOISCSI_IFACE_STATE_ENABLED) {
		iface->if_id = iface_info->if_id;
		csio_memcpy(iface->tport->mac, iface_info->mac, 6);
		csio_dbg(hw, "handle_link_op_resp: "
		"MAC[%u]:[%x:%x:%x:%x:%x:%x]\n", hw->t4port[handle].portid,
	    iface->tport->mac[0], iface->tport->mac[1],
	    iface->tport->mac[2], iface->tport->mac[3],
	    iface->tport->mac[4], iface->tport->mac[5]);
	}
out:
	return rc;
}

static csio_retval_t
handle_ifconf_op_resp(struct csio_hw *hw, uint32_t opcode, uint32_t status,
		unsigned long handle, void *data)
{
	csio_retval_t rc = CSIO_SUCCESS;
	struct csio_foiscsi_iface *iface = NULL;
	struct csio_foiscsi_ifconf_ioctl *req;
	struct csio_foiscsi_iface_ipv4 *ipv4_addr;
	struct csio_foiscsi_iface_ipv6 *ipv6_addr;
	struct foiscsi_transport_handle *h = NULL;
	struct csio_ctrl_foiscsi *foiscsi_cdev;
	uint8_t	vlan_shift = 0;

	if (handle >= hw->num_t4ports) {
		csio_err(hw, "invalid handle %lu\n", handle);
		rc = CSIO_INVAL;
		goto out;
	}

	if (!(foiscsi_cdev = get_foiscsi_cdev(hw))) {
		csio_err(hw, "foiscsi inst not found\n");
		return CSIO_INVAL;
	}

	iface = &foiscsi_cdev->ifaces[hw->t4port[handle].portid];
	if (!iface->transport_handle || !iface->op_pending) {
		if (!iface->transport_handle && opcode != IFCONF_LINKLOCAL_ADDR_SET &&
			opcode != IFCONF_RA_BASED_ADDR_SET)
			goto out;
	}
	if (status != CSIO_SUCCESS)
		csio_dbg(hw, "%s: status %d, operation failed\n",
				__FUNCTION__, status);

	switch (opcode) {
	case IFCONF_IPV4_VLAN_SET:
		if (status != CSIO_SUCCESS)
			iface->vlan_info.vlan_id = 0;
		else
			csio_dbg(hw, "ifid[%u] : vlan %u provisioned\n",
					iface->tport->portid,
					iface->vlan_info.vlan_id);
		break;

	case IFCONF_MTU_SET:
		if (status != CSIO_SUCCESS) {
			iface->mtu = iface->old_mtu;
			iface->old_mtu = 0;
		} else {
			csio_dbg(hw, "ifid[%d] : mtu changed to %u\n",
					iface->tport->portid, iface->mtu);
		}
		break;

	case IFCONF_IPV4_SET:
		if (((iface->vlan_info.vlan_id & 0x0fff) >=2) &&
			((iface->vlan_info.vlan_id & 0x0fff) < 4095)) {
			ipv4_addr =  &iface->vlan_info.ipv4;
			vlan_shift = VLAN_SHIFT;
		} else {
			ipv4_addr = &iface->ipv4;
		}

		if (status != CSIO_SUCCESS) {
			ipv4_addr->addr = 0;
			ipv4_addr->mask = 0;
			iface->gw = 0;
			iface->vlan_info.vlan_id = 0;
		} else {
			iface->address_state &= ~(CSIO_IPV4_MASK << vlan_shift);
			iface->address_state |= (CSIO_IPV4_STATIC << vlan_shift);
		}

		csio_dbg(hw, "ifid[%d] : ip %u.%u.%u.%u provisioned\n",
				iface->tport->portid,
				(ipv4_addr->addr >> 24) & 0xff,
				(ipv4_addr->addr >> 16) & 0xff,
				(ipv4_addr->addr >> 8) & 0xff,
				ipv4_addr->addr & 0xff);
		break;

	case IPV4_DHCP_SET:
		if (status == CSIO_SUCCESS && data) {
			struct csio_foiscsi_ifconf_ioctl *ifconf_info = data;
			if ((ifconf_info->vlanid >= 2) &&
			    (ifconf_info->vlanid < 4095)) {
				ipv4_addr = &iface->vlan_info.ipv4;
				vlan_shift = VLAN_SHIFT;
			} else {
				ipv4_addr = &iface->ipv4;
			}

			ipv4_addr->addr = ifconf_info->v4.ipv4_addr;
			ipv4_addr->mask = ifconf_info->v4.ipv4_mask ;
			iface->gw = ifconf_info->v4.ipv4_gw;
			iface->mtu = ifconf_info->mtu;
			csio_dbg(hw, "ifid[%d] : ip %u.%u.%u.%u "
					"provisioned by dhcp\n",
					iface->tport->portid,
					(ipv4_addr->addr >> 24) & 0xff,
					(ipv4_addr->addr >> 16) & 0xff,
					(ipv4_addr->addr >> 8) & 0xff,
					ipv4_addr->addr & 0xff);
			if (iface->transport_handle) {
				req = &((struct foiscsi_transport_handle *)
						(iface->transport_handle))->\
					iparam.u.ifconf_req;
				req->v4.ipv4_addr = ipv4_addr->addr;
				req->v4.ipv4_mask = ipv4_addr->mask;
				csio_dbg(hw, "%s: req->ipv4_addr [0x%x],"
						" req->ipv4_mask [0x%x]\n",
						__FUNCTION__, req->v4.ipv4_addr,
						req->v4.ipv4_mask);
			}
			iface->address_state &= ~(CSIO_IPV4_MASK << vlan_shift);
			iface->address_state |= (CSIO_IPV4_DHCP << vlan_shift);
		}
		break;

	case IFCONF_IPV6_SET:
		if (((iface->vlan_info.vlan_id & 0x0fff) >=2) &&
			((iface->vlan_info.vlan_id & 0x0fff) < 4095)) {
			ipv6_addr =  &iface->vlan_info.ipv6;
			vlan_shift = VLAN_SHIFT;
		} else {
			ipv6_addr = &iface->ipv6;
		}

		if (status != CSIO_SUCCESS) {
			memset(ipv6_addr->addr, 0, 16);
			memset(iface->gw6, 0, 16);
			ipv6_addr->prefix_len = 0;
			iface->vlan_info.vlan_id = 0;
		} else {
			iface->address_state &= ~(CSIO_IPV6_MASK << vlan_shift);
			iface->address_state |= (CSIO_IPV6_STATIC << vlan_shift);
		}

		csio_dbg(hw, "ifid[%d] : ip %pI6 provisioned\n",
			iface->tport->portid, ipv6_addr->addr);
		break;

	case IPV6_DHCP_SET:
		if (status == CSIO_SUCCESS && data) {
			struct csio_foiscsi_ifconf_ioctl *ifconf_info = data;
			if ((ifconf_info->vlanid >= 2) &&
			    (ifconf_info->vlanid < 4095)) {
				ipv6_addr = &iface->vlan_info.ipv6;
				vlan_shift = VLAN_SHIFT;
			} else {
				ipv6_addr = &iface->ipv6;
			}

			csio_memcpy(ipv6_addr->addr,
				ifconf_info->v6.ipv6_addr, 16);
			csio_memcpy(iface->gw6, ifconf_info->v6.ipv6_gw, 16);;
			ipv6_addr->prefix_len = ifconf_info->v6.prefix_len ;
			iface->mtu = ifconf_info->mtu;
			csio_dbg(hw, "ifid[%d] : ip %pI6 "
					"provisioned by dhcp\n",
					iface->tport->portid,
					ipv6_addr->addr);
			if (iface->transport_handle) {
				req = &((struct foiscsi_transport_handle *)
						(iface->transport_handle))->\
					iparam.u.ifconf_req;
				csio_memcpy(req->v6.ipv6_addr,
					ipv6_addr->addr, 16);
				req->v6.prefix_len = ipv6_addr->prefix_len;
				csio_dbg(hw, "%s: req->ipv6_addr [%pI6],"
						" req->prefix_len [%u]\n",
						__FUNCTION__, req->v6.ipv6_addr,
						req->v6.prefix_len);
			}
			iface->address_state &= ~(CSIO_IPV6_MASK << vlan_shift);
			iface->address_state |= (CSIO_IPV6_DHCP << vlan_shift);
		}
		break;

	case IFCONF_LINKLOCAL_ADDR_SET:
		if (status == CSIO_SUCCESS && data) {
			struct csio_foiscsi_ifconf_ioctl *ifconf_info = data;
			if ((ifconf_info->vlanid >= 2) &&
			    (ifconf_info->vlanid < 4095)) {
				ipv6_addr = &iface->link_local.ipv6_vlan;
				vlan_shift = VLAN_SHIFT;
			} else {
				ipv6_addr = &iface->link_local.ipv6;
			}

			csio_memcpy(ipv6_addr->addr,
				ifconf_info->v6.ipv6_addr, 16);
			ipv6_addr->prefix_len = ifconf_info->v6.prefix_len;
			csio_dbg(hw, "ifid[%d] : ip %pI6 "
					"provisioned as link-local address\n",
					iface->tport->portid,
					ipv6_addr->addr);
			iface->address_state |= CSIO_IPV6_LLOCAL;
		}
		break;

	case IFCONF_RA_BASED_ADDR_SET:
		if (status == CSIO_SUCCESS && data) {
			struct csio_foiscsi_ifconf_ioctl *ifconf_info = data;
			if ((ifconf_info->vlanid >= 2) &&
			    (ifconf_info->vlanid < 4095)) {
				ipv6_addr = &iface->vlan_info.ipv6;
				vlan_shift = VLAN_SHIFT;
			} else {
				ipv6_addr = &iface->ipv6;
			}

			csio_memcpy(ipv6_addr->addr,
				ifconf_info->v6.ipv6_addr, 16);
			csio_memcpy(iface->gw6, ifconf_info->v6.ipv6_gw, 16);;
			ipv6_addr->prefix_len = ifconf_info->v6.prefix_len ;
			iface->mtu = ifconf_info->mtu;
			csio_dbg(hw, "ifid[%d] : ip %pI6 "
					"provisioned by router advertisement\n",
					iface->tport->portid,
					ipv6_addr->addr);
			iface->address_state &= ~(CSIO_IPV6_MASK << vlan_shift);
			iface->address_state |= (CSIO_IPV6_RTADV << vlan_shift);
		}
		break;

	case IFCONF_ADDR_EXPIRED:
		/* Not supported */
		break;
	}

	h = iface->transport_handle;
	if (h && h->transport && h->transport->event_handler) {
		h->transport->event_handler(hw, opcode, status, h);
	}
out:
	return rc;
}

static csio_retval_t
handle_instance_op_resp(struct csio_hw *hw, uint32_t opcode, uint32_t status,
			unsigned long handle, void *data)
{
	csio_retval_t rc = CSIO_SUCCESS;
	struct csio_ctrl_instance *instance;
	struct foiscsi_transport_handle *h = NULL;
	struct csio_ctrl_foiscsi *foiscsi_cdev;
	unsigned int inst_idx = handle - 1;

	if (inst_idx > FW_FOISCSI_INIT_NODE_MAX) {
		rc = CSIO_INVAL;
		csio_err(hw, "invalid initiator instance id %u\n", inst_idx);
		goto out;
	}
	
	if (!(foiscsi_cdev = get_foiscsi_cdev(hw))) {
		csio_err(hw, "foiscsi inst not found\n");
		return CSIO_INVAL;
	}

	instance = &foiscsi_cdev->instance[inst_idx];

	if (instance->op_pending) {
		h = instance->transport_handle;
		if (h && h->transport && h->transport->event_handler)
			h->transport->event_handler(hw, opcode, status, h);
	}
out:
	return rc;
}

static csio_retval_t
handle_login_op_resp(struct csio_hw *hw, uint32_t opcode, uint32_t status,
		unsigned long handle, void *data)
{
	csio_retval_t rc = CSIO_SUCCESS;
	unsigned int inst_idx = handle - 1;
	struct csio_ctrl_instance *inst;
	struct csio_foiscsi_iface *iface;
	struct foiscsi_transport_handle *h = NULL;
	struct csio_ctrl_foiscsi *foiscsi_cdev;
	struct foiscsi_login_info *ipinfo = data;

	csio_dbg(hw, "%s: inst_idx %d\n", __FUNCTION__, inst_idx);
	if (inst_idx > FW_FOISCSI_INIT_NODE_MAX) {
		csio_err(hw, "invalid initiator instance id %u\n", inst_idx);
		rc = CSIO_INVAL;
		goto out;
	}
	if (!data) {
		csio_err(hw, "missing ip info in instance %u\n", inst_idx);
		rc = CSIO_INVAL;
		goto out;
	}
	
	if (!(foiscsi_cdev = get_foiscsi_cdev(hw))) {
		csio_err(hw, "foiscsi inst not found\n");
		return CSIO_INVAL;
	}

	inst = &foiscsi_cdev->instance[inst_idx];
	if (!inst->op_pending)
		goto out;

	iface = &foiscsi_cdev->ifaces[inst->portid];
	if ((status != CSIO_SUCCESS) ||
	    (opcode == ISCSI_DISC_TARGS)) {
		csio_spin_lock_irq(hw, &iface->hlock);
		csio_foiscsi_iface_addr_put(hw, iface, ipinfo->ip_type,
			ipinfo->src_ip.ip4, ipinfo->src_ip.ip6);
		csio_spin_unlock_irq(hw, &iface->hlock);
	}

	if (inst->op_pending) {
		h = inst->transport_handle;
		if (h && h->transport && h->transport->event_handler)
			h->transport->event_handler(hw, opcode, status, h);
	}
out:
	return rc;
}

static csio_retval_t
handle_logout_op_resp(struct csio_hw *hw, uint32_t opcode, uint32_t status,
			unsigned long handle, void *data)
{
	unsigned int i;
	csio_retval_t rc = CSIO_SUCCESS;
	unsigned int inst_idx = handle - 1;
	struct csio_foiscsi_iface *iface = NULL;
	struct csio_ctrl_instance *inst = NULL;
	struct foiscsi_transport_handle *h;
	struct csio_ctrl_foiscsi *foiscsi_cdev;
	struct foiscsi_login_info *ipinfo;

	csio_dbg(hw, "%s: inst_idx %d\n", __FUNCTION__, inst_idx);

	if (inst_idx > FW_FOISCSI_INIT_NODE_MAX) {
		csio_err(hw, "invalid initiator instance %u\n", inst_idx);
		rc = CSIO_INVAL;
		goto out;
	}
	if (!data) {
		csio_err(hw, "missing ip info in instance %u\n", inst_idx);
		rc = CSIO_INVAL;
		goto out;
	}
	ipinfo = data;

	if (!(foiscsi_cdev = get_foiscsi_cdev(hw))) {
		csio_err(hw, "foiscsi inst not found\n");
		rc = CSIO_INVAL;
		goto out;
	}

	inst = &foiscsi_cdev->instance[inst_idx];
	if (!inst->op_pending)
		goto out;

	for (i = 0; i < hw->num_t4ports; i++) {
		iface = &foiscsi_cdev->ifaces[i];
		csio_spin_lock_irq(he, &iface->hlock);
		if (csio_foiscsi_iface_addr_put(hw, iface, ipinfo->ip_type,
				ipinfo->src_ip.ip4, ipinfo->src_ip.ip6)) {
			csio_spin_unlock_irq(hw, &iface->hlock);
			break;
		}
		csio_spin_unlock_irq(hw, &iface->hlock);
	}

	if (inst->op_pending) {
		h = inst->transport_handle;
		//inst->transport_handle = NULL;
		//inst->op_pending = 0;
		if (h && h->transport && h->transport->event_handler)
			h->transport->event_handler(hw, opcode, status, h);
	}
out:
	return rc;
}

csio_retval_t csio_foiscsi_transport_ioctl_handler(struct csio_hw *hw,
		uint32_t opcode, unsigned long arg,
		void *buffer, uint32_t buffer_len)
{
	csio_retval_t rc = CSIO_INVAL;
	/*unsigned int i;*/
	struct csio_list *tmp = NULL;
	struct foiscsi_transport *transport = NULL;

	/* Check for all registered transport, if ioctl handler is registered
 	 * then call it and break; */

	if (csio_list_empty(&foiscsi_inst_head))
		goto out;

	csio_list_for_each(tmp, &foiscsi_transport_list) {
		transport = (struct foiscsi_transport *) tmp;
		if (transport && transport->ioctl_handler) {
			/* Only platform's chelsio transport can
			 * have the registered
		 	 * ioctl. So we are safe. */
			rc = transport->ioctl_handler(hw, opcode, arg,
							buffer, buffer_len);
			break;
		}
	}

out:
	csio_dbg(hw, "%s: opcode [%d], rc [%d].\n", __FUNCTION__, opcode, rc);

	return rc;
}

/* This function should be called by LLD from the WR response handlers. This
 * function will call the appropriate transport */
csio_retval_t csio_foiscsi_transport_event_handler(struct csio_hw *hw,
		uint32_t opcode, uint32_t status,
		unsigned long handle, void *data)
{
	csio_retval_t rc =  CSIO_SUCCESS;
	/* struct foiscsi_transport_handle *h = NULL; */

	csio_dbg(hw, "%s: opcode %d, handle %lu\n",
			__FUNCTION__, opcode, handle);


	/* if opcode is iface specific then the handle is the portid value
	 * or if opcode is instance/login/discovery/logout related then
	 * handle is the instance id */

	/* if the internal transport handle is null that means no transport is
	 * waiting for this event. This may be for us only. This will happen
	 * mostly in iface start case. TODO */

	switch(opcode) {
	case IFACE_CMD_SUBOP_LINK_UP:
	case IFACE_CMD_SUBOP_LINK_DOWN:
		rc = handle_link_op_resp(hw, opcode, status, handle, data);
		break;
	case IFCONF_IPV4_VLAN_SET:
	case IFCONF_MTU_SET:
	case IFCONF_MTU_GET:
	case IFCONF_IPV4_SET:
	case IPV4_DHCP_SET:
	case IPV6_DHCP_SET:
	case IFCONF_IPV6_SET:
	case IFCONF_LINKLOCAL_ADDR_SET:
	case IFCONF_RA_BASED_ADDR_SET:
		rc = handle_ifconf_op_resp(hw, opcode, status, handle, data);
		break;
	case ASSIGN_INSTANCE:
	case CLEAR_INSTANCE:
		rc = handle_instance_op_resp(hw, opcode, status, handle, data);
		break;
	case ISCSI_LOGIN_TO_TARGET:
	case ISCSI_DISC_TARGS:
		rc = handle_login_op_resp(hw, opcode, status, handle, data);
		break;
	case LOGOUT_FROM_TARGET:
		rc = handle_logout_op_resp(hw, opcode, status, handle, data);
		break;
	default:
		csio_dbg(hw, "unknown event %d in transport from LLD\n",opcode);
	}
	return CSIO_SUCCESS;
}

static inline unsigned int foiscsi_instance_op(unsigned int op)
{
	unsigned int rc = 0;
	if (op == ASSIGN_INSTANCE ||  op == CLEAR_INSTANCE ||
		op == ISCSI_LOGIN_TO_TARGET || op == ISCSI_DISC_TARGS ||
		op == LOGOUT_FROM_TARGET)
		rc = 1;

	return rc;
}

static inline unsigned int foiscsi_iface_op(unsigned int op)
{
	unsigned int rc = 0;

	if (op == IFACE_CMD_SUBOP_LINK_UP || op == IFACE_CMD_SUBOP_LINK_DOWN ||
		op == IFCONF_IPV4_VLAN_SET || op == IFCONF_MTU_SET ||
		op == IFCONF_MTU_GET || op == IFCONF_IPV4_SET ||
		op == IPV4_DHCP_SET ||
		op == IPV6_DHCP_SET || op == IFCONF_IPV6_SET)
		rc = 1;
	return rc;
}


csio_retval_t
csio_clean_op_handle(struct csio_hw *hw, uint32_t op, uint32_t id,
			void *thandle)
{
	struct csio_ctrl_instance *inst;
	struct csio_foiscsi_iface *iface;
	struct csio_ctrl_foiscsi *foiscsi_cdev;

	if (!(foiscsi_cdev = get_foiscsi_cdev(hw))) {
		csio_err(hw, "foiscsi inst not found\n");
		return CSIO_INVAL;
	}

	if(foiscsi_instance_op(op)) {
		/* the thandle is present in the foiscsi_cdev->instance array */
		if (id > 0  && id <= FW_FOISCSI_INIT_NODE_MAX) {
			inst = &foiscsi_cdev->instance[id - 1];
			csio_mutex_lock(&inst->inode_lock);
			if ((inst->transport_handle == thandle) &&
			 	 inst->op_pending) {
				inst->transport_handle = NULL;
				inst->op_pending = 0;
			}
			csio_mutex_unlock(&inst->inode_lock);
		}
	} else if (foiscsi_iface_op(op)) {
		/* the thandle is present in the foiscsi_cdev->ifaces array */

		if (id >= hw->num_t4ports)
			goto out;
		
		iface = &foiscsi_cdev->ifaces[id];
		csio_mutex_lock(&iface->mlock);
		if ((iface->transport_handle == thandle) &&
				(iface->op_pending)) {
			iface->transport_handle = NULL;
			iface->op_pending = 0;
		}
		csio_mutex_unlock(&iface->mlock);
	}
out:
	return CSIO_SUCCESS;
}

