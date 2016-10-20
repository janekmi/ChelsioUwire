/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/*
 * Description:
 * 	This chfcoe_os_init.c file does initialization of the driver.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/if_vlan.h>
#include <scsi/scsi.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_transport_fc.h>
#include <linux/kthread.h>
#include <linux/cpu.h>
#include <net/dcbnl.h>
#include <net/dcbevent.h>

#include "chfcoe_os_init.h"
#include <t4fw_interface.h>
#include <csio_stor_ioctl.h>
#include <csio_t4_ioctl.h>
#include <chfcoe_adap.h>
#include <chfcoe_port.h>
#include <chfcoe_lnode.h>
#include <common.h>
#include <cxgb4_ofld.h>
#include <t4_msg.h>
#include <csio_sal_api.h>

#if !defined(__LITTLE_ENDIAN)
#error "Byte order not supported"
#endif

static struct chfcoe_list adap_head;
static unsigned int chfcoe_cdev_major;
static struct class *chfcoe_class;
DECLARE_BITMAP(chfcoe_cdev_minors, CHFCOE_MAX_CMINORS);

extern int csio_ddp_thres;

static int chfcoe_fip_mode = 0;
CHFCOE_MODULE_PARAM(fip_mode, 0, 0, 2," FIP mode."
                 " Default - 0(FCF), 1(VN2VN)", int);

int chfcoe_vlanid = 0;
CHFCOE_MODULE_PARAM(vlanid, 0, 0, 4094," FCoE Static VLAN"
                 " Default - 0(no vlan), > 0 (vlanid)", int);
static int chfcoe_ddp_thres = -1;

unsigned int chfcoe_node_num = 0;
unsigned int chfcoe_node_id[2] = {0, 0};
module_param_array(chfcoe_node_id, uint, &chfcoe_node_num, S_IRUGO);
MODULE_PARM_DESC(chfcoe_node_id, "Bind chfcoe workers to specified nodes, max 2 nodes");

unsigned int chfcoe_worker_num[2] = {0, 0};
module_param_array(chfcoe_worker_num, uint, NULL, S_IRUGO);
MODULE_PARM_DESC(chfcoe_worker_num, "Number of chfcoe worker threads per node");

/*
 * Although we attach to the FC transport, the template is referred to
 * as chfcoe_fcoe_transport, because this is an FCoE driver.
 */

extern struct fc_function_template chfcoe_fc_transport_funcs;
extern struct fc_function_template chfcoe_fc_transport_vport_funcs;

extern struct sk_buff *t4_pktgl_to_skb(const struct pkt_gl *gl,
		unsigned int skb_len,
		unsigned int pull_len);
static int chfcoe_cdev_init(struct chfcoe_os_adap_info *);
static chfcoe_retval_t
chfcoe_tx_frame(chfcoe_fc_buffer_t *p, void *pi_osdev, uint8_t chan);

#define RX_PULL_LEN 128

void *chfcoe_get_pdev(struct chfcoe_adap_info *adap)
{
	return (void *)(((struct chfcoe_os_adap_info *)adap->os_dev)->pdev);
}

int chfcoe_get_chip_type(struct chfcoe_adap_info *adap)
{
	return ((struct chfcoe_os_adap_info *)adap->os_dev)->adapter_type;
}

/*
 * chfcoe_module_params_check - checks for module params value.
 *
 * This function checks if any module params value is set during boot or
 * module load.
 */
static int chfcoe_module_params_check(void)
{
	unsigned int i = 0;

	chfcoe_fip_mode_check(chfcoe_fip_mode);
	chfcoe_vlanid_check(chfcoe_vlanid);
	csio_ddp_thres = chfcoe_ddp_thres;

	if (chfcoe_node_num > 2) {
		chfcoe_err(0, "more than 2 nodes specified:%u\n", chfcoe_node_num);
		return CHFCOE_INVAL;
	}	

	if (chfcoe_node_num) {
		for (i = 0; i < chfcoe_node_num; i++) {
			if (!node_online(chfcoe_node_id[i])) {
				chfcoe_err(0, "chfcoe_node_id, node %u is not online\n", i);
				return CHFCOE_INVAL;
			}
		}
	} else { 

		chfcoe_node_num = 1;
		chfcoe_node_id[0] = numa_node_id();
	}

	for (i = 0; i < chfcoe_node_num; i++) {
		if ((chfcoe_worker_num[i] <= 0) || (chfcoe_worker_num[i] > nr_cpus_node(chfcoe_node_id[i])))
			chfcoe_worker_num[i] = nr_cpus_node(chfcoe_node_id[i]);
		chfcoe_info(err, "chfcoe worker count set to %u for node %u\n", chfcoe_worker_num[i], chfcoe_node_id[i]);
	}

	return CHFCOE_SUCCESS;
} /* chfcoe_module_params_check */


void chfcoe_link_up(struct chfcoe_port_info *pi)
{
	int ret;

	pi->link_state = CHFCOE_PORT_ONLINE;
	pi->dcb_prio = os_dcb_get_prio(pi->os_dev);
	chfcoe_info(pi, "Port:%d updating dcbx prio:%d\n", pi->port_num,
			pi->dcb_prio);
	CHFCOE_INC_STATS(pi, n_link_up);

	ret = chfcoe_start_fip(pi);
	if (ret)
		chfcoe_err(adap, "failed to start fip,"
				" port num: %d dev:%s\n",
				pi->port_num,
				os_netdev_name(pi->os_dev));
}

void chfcoe_link_down(struct chfcoe_port_info *pi)
{
	pi->link_state = CHFCOE_PORT_OFFLINE;
	if (chfcoe_stop_fip(pi)) {
		chfcoe_err(adap, "failed to stop fip,"
				" port num: %d\n", pi->port_num);
	}

	return;
}

void chfcoe_dcb_update(struct chfcoe_adap_info *adap, void *netdev)
{
	struct chfcoe_port_info *pi;
	int i, found = 0;

	pi = adap->pi;
	for (i=0; i<adap->nports; i++) {
		pi = CHFCOE_PTR_OFFSET(adap->pi, (i * chfcoe_port_info_size));
		if (netdev == pi->os_dev) {
			found = 1;
			break;
		}
	}

	if (!found || !pi || !os_netif_running(pi->os_dev))
		return;

	pi->dcb_prio = os_dcb_get_prio(netdev);
	chfcoe_info(pi, "%s:updating dcbx prio:%d\n", os_netdev_name(netdev),
			pi->dcb_prio);
}

void chfcoe_os_netdev_event(struct chfcoe_adap_info *adap, void *ndev, 
		void *pdev, int event, uint8_t port)
{
	int ret, link_down = 0, old_mfs;
	struct chfcoe_port_info *pi = CHFCOE_PTR_OFFSET(adap->pi, 
			port * chfcoe_port_info_size);

	chfcoe_dbg(edev, "%s netdev event received 0x%lx.\n",
			os_netdev_name(ndev), event);

	if (event >= OS_NETDEV_EVENT_MAX)
		return;

	switch (event) {
	case OS_NETDEV_REGISTER:
		break;

	case OS_NETDEV_UNREGISTER:
		link_down = 1;
		break;

	case OS_NETDEV_UP:
		break;

	case OS_NETDEV_CHANGE:
		if (!os_netif_carrier_ok(ndev)) {
			chfcoe_info(adap, "dev:%s port:%d DOWN\n", 
					os_netdev_name(ndev), pi->port_num);
			link_down = 1;
		} else {
			chfcoe_info(adap, "dev:%s port:%d UP\n",
					os_netdev_name(ndev), pi->port_num);
		}
		break;

	case OS_NETDEV_DOWN:
	case OS_NETDEV_GOING_DOWN:
		link_down = 1;
		break;

	case OS_NETDEV_CHANGEMTU:
		old_mfs = pi->root_ln->max_pldlen;
		ret = chfc_set_maxfs(pi->root_ln);
		if (!ret && pi->root_ln->max_pldlen < old_mfs && 
				os_netif_carrier_ok(ndev)) {
			chfcoe_link_down(pi);
			chfcoe_msleep(10000);
			chfcoe_link_up(pi);
		}

		break;

	case OS_NETDEV_FEAT_CHANGE:
		break;

	default:
		chfcoe_dbg(adap, "Unknown event %ld dev:%s\n", event,
				os_netdev_name(ndev));
		link_down = 1;
		break;
	}

	if (!link_down && os_netif_carrier_ok(ndev) &&
			((pi->link_state == CHFCOE_PORT_INIT) ||
			 (pi->link_state == CHFCOE_PORT_OFFLINE) )) {
		chfcoe_link_up(pi);
	} else if (link_down && (pi->link_state == CHFCOE_PORT_ONLINE)) {
		CHFCOE_INC_STATS(pi, n_link_down);
		chfcoe_link_down(pi);
	}
}

static int chfcoe_netdev_event(struct notifier_block *this, unsigned long event,
		void *p)
{
	struct chfcoe_os_adap_info *os_adap;
	struct chfcoe_adap_info *adap;
	struct chfcoe_list *entry;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	struct net_device *ndev = p;
#else
	struct netdev_notifier_info *info = p;
	struct net_device *ndev = info->dev;
#endif
	struct net_device *pi_osdev = NULL;
	struct device *dev = ndev->dev.parent;
	struct pci_dev *pdev = dev ? to_pci_dev(dev) : NULL;
	int i, found = 0;
	uint8_t port_num = 0;


	chfcoe_list_for_each(entry, &adap_head) {
		os_adap = (struct chfcoe_os_adap_info *)entry;
		adap = os_adap->adap;
		for (i = 0; i<adap->nports; i++) {
			pi_osdev = chfcoe_port_get_osdev(adap, i);
			if (ndev == pi_osdev) {
				port_num = i;
				found = 1;
				break;
			}
		}
		if (found)
			break;
	}

	if (!found || !pi_osdev || !netif_running(pi_osdev))
		return NOTIFY_DONE;

	chfcoe_os_netdev_event(adap, ndev, pdev, event, port_num);

	return NOTIFY_DONE;
}

static int chfcoe_dcb_event(struct notifier_block *this, unsigned long event,
		void *p)
{
	struct dcb_app_type *dcb_entry = p;
	struct chfcoe_os_adap_info *os_adap;
	struct chfcoe_adap_info *adap;
	struct chfcoe_list *entry;
	struct net_device *ndev;
	struct net_device *pi_osdev = NULL;
	int i, found = 0;
	uint8_t port_num = 0;


	if (dcb_entry->app.selector != DCB_APP_IDTYPE_ETHTYPE)
		return NOTIFY_OK;

	ndev = dev_get_by_index(&init_net, dcb_entry->ifindex);
	if (!ndev)
		return NOTIFY_OK;
	dev_put(ndev);
	chfcoe_list_for_each(entry, &adap_head) {
		os_adap = (struct chfcoe_os_adap_info *)entry;
		adap = os_adap->adap;
		for (i = 0; i<adap->nports; i++) {
			pi_osdev = chfcoe_port_get_osdev(adap, i);
			if (ndev == pi_osdev) {
				port_num = i;
				found = 1;
				break;
			}
		}
		if (found)
			break;
	}

	if (!found || !pi_osdev || !netif_running(pi_osdev))
		return NOTIFY_DONE;

	chfcoe_dcb_update(adap, ndev);
	return NOTIFY_DONE;
}

static struct notifier_block chfcoe_notifier = {
	.notifier_call = chfcoe_netdev_event,
};

static struct notifier_block chfcoe_dcb_notifier = {
	.notifier_call = chfcoe_dcb_event,
};

static chfcoe_retval_t
chfcoe_set_mac_addr(void *pi_osdev, u8 *mac, u16 *idx, bool clear)
{
	struct net_device *netdev = (struct net_device *) pi_osdev;
	if (cxgb4_fcoe_set_mac(netdev, mac, idx, clear) != 0)
		return CHFCOE_INVAL;
	return CHFCOE_SUCCESS;
}

static chfcoe_retval_t
chfcoe_enable_dev(void *pi_osdev, bool enable)
{
	struct net_device *netdev = (struct net_device *) pi_osdev;
	if (cxgb4_fcoe_enable(netdev, enable) != 0)
		return CHFCOE_INVAL;
	return CHFCOE_SUCCESS;
}

static chfcoe_retval_t chfcoe_tx_frame(chfcoe_fc_buffer_t *p, 
		void *pi_osdev, uint8_t chan)
{
	struct sk_buff *skb = p;

	set_wr_txq(skb, CPL_PRIORITY_DATA, chan);
	skb->dev = pi_osdev;
	skb->protocol = chfcoe_htons(ETH_P_FIP);	
	cxgb4_fcoe_send(skb->dev, skb); 
	return CHFCOE_SUCCESS;
}

struct chfcoe_lld_ops lldi_ops = {
	.set_mac_addr = chfcoe_set_mac_addr,
	.fcoe_enable = chfcoe_enable_dev,
	.send_frame = chfcoe_tx_frame,
};

/*
 * chfcoe_uld_add - attach chfcoe as ULD to cxgb4
 * @infop: the lower-level driver information pointer.
 */
static void *
chfcoe_uld_add(const struct cxgb4_lld_info *infop)
{
	struct cxgb4_lld_info *lldi = NULL;
	struct chfcoe_os_adap_info *os_adap;
	struct chfcoe_adap_info *adap;
	struct chfcoe_port_lld_info pi_lldi;
	int i = 0, err = -ENOMEM;

	os_adap = kzalloc(chfcoe_os_adap_info_size, GFP_KERNEL);
	if (!os_adap) {
		chfcoe_err(adap, "uld add: failed to alloc fcoe adap object "
			"dev:%s\n", pci_name(infop->pdev));
		return ERR_PTR(-ENOMEM);
	}	

	lldi = kzalloc(sizeof(struct cxgb4_lld_info), GFP_KERNEL);
	if (!lldi) {
		chfcoe_err(adap, "failed to alloc fcoe lldi object dev:%s\n",
			pci_name(infop->pdev));
		goto err1;
	}	

	*lldi = *infop;
	os_adap->adap = CHFCOE_PTR_OFFSET(os_adap, sizeof(struct chfcoe_os_adap_info));
	chfcoe_elem_init(&os_adap->lentry);
	os_adap->lldi = lldi;
	os_adap->pdev = lldi->pdev;
	os_adap->id = lldi->pdev->devfn;
	os_adap->max_wr_credits = (lldi->wr_cred -
			DIV_ROUND_UP(sizeof(struct cpl_abort_req), 16));
	adap = os_adap->adap;
	adap->lock = CHFCOE_PTR_OFFSET(adap, sizeof(struct chfcoe_adap_info));
	adap->mtus = lldi->mtus;
	adap->fw_evtq_cntxt_id = lldi->fw_evtq_cntxt_id;
	adap->tids = lldi->tids;
	adap->nports = lldi->nports;
	adap->txq_ids = lldi->txq_ids;
	adap->rxq_ids = lldi->rxq_ids;
	adap->ntxq = lldi->ntxq;
	adap->nrxq = lldi->nrxq;
	adap->pf = lldi->pf;
	os_adap->adapter_type = lldi->adapter_type;
	adap->queue_frame = chfcoe_queue_fcb,
	adap->devid = (lldi->pdev->bus->number < 8) | lldi->pdev->devfn;
	adap->os_dev = os_adap;
#ifdef __CHFCOE_TRACE_SUPPORT__
	adap->trace_buffer = os_adap->trace_buffer;
#endif
#ifdef __CHFCOE_DEBUGFS__
        chfcoe_osdfs_adap_init(os_adap);
#endif
	adap->fip_mode = chfcoe_fip_mode;
	adap->lld_ops = &lldi_ops;
	strncpy(adap->drv_version, CHFCOE_DRV_VERSION, 32);
	chfcoe_info(adap, "Found ports:%d dev:%s\n", adap->nports, 
			pci_name(os_adap->pdev));

	adap->pi = chfcoe_port_alloc(lldi->nports);
	if (!adap->pi) {
		chfcoe_err(adap, "failed to alloc fcoe pi object dev:%s\n",
			pci_name(infop->pdev));
		goto err2;
	}	

	/* Assign the net_device structure (from lldi)
	 * to os_dev (OS specific) ptr in chfcoe_port_info
	 */
	
	for (i = 0; i < lldi->nports; i++) {
		memset(&pi_lldi, 0, sizeof(struct chfcoe_port_lld_info));
		pi_lldi.os_dev = (void *)lldi->ports[i];
		pi_lldi.vi_id = lldi->vr->fcoe_viid[i];
		pi_lldi.fcoe_nqsets = lldi->vr->fcoe_nqsets[i];
		memcpy(&(pi_lldi.phy_mac), &(lldi->vr->fcoe_mac[i]), 6);

		if (chfcoe_port_init(adap, &pi_lldi, i) != CHFCOE_SUCCESS)
			goto err3;
		chfcoe_info(adap, "Found fcoe device %s\n", 
				os_netdev_name(pi_lldi.os_dev));
	}

	adap->ntids = lldi->tids->ntids;
	err = chfcoe_adap_ddp_init(adap);
	if (err) {
		chfcoe_err(adap, "failed to initialize ddp for dev:%s\n",
			pci_name(infop->pdev));
		adap->ddp_thres = -1;
		goto err3;
	}

	if (lldi->vr->fcoe.size) {
		adap->ddp_llimit = lldi->vr->fcoe.start;
		adap->ddp_ulimit = lldi->vr->fcoe.start +
			lldi->vr->fcoe.size - 1;

		adap->nppods = lldi->vr->fcoe.size / sizeof(struct pagepod);
		adap->toe_nppods = lldi->vr->toe_nppods;
		adap->ppod_map = chfcoe_mem_alloc(adap->nppods);
		if (!adap->ppod_map) {
			chfcoe_err(adap, "failed to alloc ppod map for "
				" dev:%s\n", pci_name(infop->pdev));
			goto err4;
		}

		chfcoe_info(adap, "%s: ddp: llim:%d ulim:%d size:%d nppods:%d "
			       "toe_nppods 0x%x\n", pci_name(infop->pdev), 
			       adap->ddp_llimit, 
			       adap->ddp_ulimit, lldi->vr->fcoe.size, 
			       adap->nppods, adap->toe_nppods);
	}
	else 
		chfcoe_info(adap, "DDP feature disabled on fcoe device %s\n", 
				pci_name(infop->pdev));

	adap->ddp_thres = chfcoe_ddp_thres;

	/* Initialize Adapter's spin lock */
	chfcoe_spin_lock_init(adap->lock);

	if ((err = chfcoe_init(adap)))
		goto err5;

	if (chfcoe_cdev_init(os_adap))
		goto err6;

	chfcoe_enq_at_tail(&adap_head, &os_adap->lentry);
	return os_adap;

err6:
	chfcoe_exit(adap);
err5:

err4:
	chfcoe_ddp_disable(adap);
err3:
	for (i -= 1 ; i >= 0; i--) {
		chfcoe_port_exit(adap, i);
	}

	kfree(adap->pi);
err2:
	kfree(lldi);
#ifdef __CHFCOE_DEBUGFS__
	chfcoe_osdfs_adap_exit(os_adap);
#endif
err1:
	kfree(os_adap);
	return ERR_PTR(err);
}


static inline struct sk_buff *
chfcoe_pktgl_to_skb_usepages(const struct pkt_gl *gl)
{
	struct sk_buff *skb;
	struct skb_shared_info *ssi;

	if (gl->nfrags > 1)
		return NULL;

	skb = dev_alloc_skb(0);
	if (unlikely(!skb))
		return NULL;

	ssi = skb_shinfo(skb);
	skb_frag_set_page(skb, 0, gl->frags[0].page);
	ssi->frags[0].page_offset = gl->frags[0].offset;
	ssi->frags[0].size = gl->frags[0].size;
	ssi->nr_frags = gl->nfrags;

	skb->len = gl->tot_len;
	skb->data_len = skb->len;
	skb->truesize += skb->data_len;

	/* Get a reference for the last page, we don't own it */
	get_page(gl->frags[0].page);

	return skb;
}

/*
 * chfcoe_uld_rx_handler - process an ingress offload packet
 * @handle: the response queue that received the packet
 * @rsp: the response queue descriptor holding the offload message
 * @gl: the gather list of packet fragments
 *
 * Process an ingress offload packet and deliver it to the offload modules.
 */

#define CHFCOE_CPL_RX_ERROR_CSUM	(1 << 13)

int chfcoe_uld_rx_handler(void *handle, const __be64 *rsp, 
		const struct pkt_gl *gl)
{
	struct chfcoe_os_adap_info *os_adap = handle;
	struct chfcoe_adap_info *adap = (os_adap->adap);
	chfcoe_fc_buffer_t *fcb;
	struct sk_buff *skb = NULL;
	int ret = 0;
	struct cpl_rx_pkt *pkt;
	uint32_t l2info;
	uint8_t port;
	uint16_t vlan_tci;
	unsigned int sge_pktshift = 0;

	switch (*((uint8_t *)rsp)) {
	case CPL_RX_PKT:
		pkt = (void *) &rsp[1];
		skb = chfcoe_pktgl_to_skb_usepages(gl);
		if (unlikely(!skb))
			goto no_skb;

//		__skb_pull(skb, os_adap->lldi->sge_pktshift);
		fcb = (chfcoe_fc_buffer_t *)skb;
		l2info = chfcoe_ntohl(pkt->l2info);
		
		port = pkt->iff;
		vlan_tci = chfcoe_ntohs(pkt->vlan) & VLAN_VID_MASK;
		
		skb->ip_summed = !(chfcoe_ntohs(pkt->err_vec) &
				CHFCOE_CPL_RX_ERROR_CSUM);
		/* Queueing the skb even if there is checksum error.
		 * Upper layers can handle it.
		 */
		if (unlikely(!skb->ip_summed)) {
			chfcoe_err(adap, "CPL RX PKT recv with csum err for "
				"dev:%s\n", pci_name(os_adap->pdev));
			kfree_skb(skb);
			break;
		}

		sge_pktshift = os_adap->lldi->sge_pktshift;
		chfcoe_queue_fcb(adap, fcb, ((unsigned char *)gl->va) + sge_pktshift,
				gl->tot_len - sge_pktshift, port, vlan_tci, l2info);
		break;

	default:
		if (gl)
			chfcoe_err(adap, "gl not null\n");
		ret = chfcoe_cpl_rx_handler(adap, rsp);
		break;
	}

	return ret;

no_skb:
	chfcoe_err(adap, "SKB alloc failed for dev:%s\n", 
			pci_name(os_adap->pdev));
	return -ENOMEM;
}

/*
 * chfcoe_uld_state_change - processes if any state change
 * @handle: the response queue that received the packet
 * @new_state: change the current state to new state
 *
 */
static int
chfcoe_uld_state_change(void *handle, enum cxgb4_state new_state)
{
	struct chfcoe_os_adap_info *os_adap = handle;
	struct chfcoe_adap_info *adap = (os_adap->adap);

	switch (new_state) {
		case CXGB4_STATE_UP:
			chfcoe_info(adap, "Chelsio pci device %s is UP\n", 
					pci_name(os_adap->pdev));
			adap->rxq_ids = os_adap->lldi->rxq_ids;
			break;
		case CXGB4_STATE_DOWN:
			chfcoe_info(adap, "Chelsio pci device %s is DOWN\n",
				pci_name(os_adap->pdev));
			break;
		case CXGB4_STATE_DETACH:
			chfcoe_info(adap, "Chelsio pci device %s is DETACH\n",
				pci_name(os_adap->pdev));
//			chfcoe_exit(adap);
			break;
		default:
			chfcoe_err(adap, "Unknown State %d from LLD(cxgb4)\n",
					new_state);
	}
	return 0;
} /* chfcoe_uld_state_change */

/* 
 * ULD - Upper Level Driver Initialization
 * Needed for Registering Upper Level Driver with cxgb4 driver.
 */
static struct cxgb4_uld_info chfcoe_uld_info = {
	.name = "chfcoe_uld",
	.add = chfcoe_uld_add,
	.rx_handler = chfcoe_uld_rx_handler,
	.ma_failover_handler = NULL,
	.state_change = chfcoe_uld_state_change,
	.control = NULL,
};

/* 
 * chfcoe_fip_buffer_alloc - Alloc the frame buffer for fip frames
 */


/*
 * chfcoe_cdev_open - Open entry point for character device
 * @inode - inode structure
 * @filep - file pointer
 */
static int
chfcoe_cdev_open(struct inode *inode, struct file *filep)
{
	struct chfcoe_os_adap_info *os_adap;
	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	/* Populate os_adap * pointer for use by ioctl */
	os_adap = container_of(inode->i_cdev, struct chfcoe_os_adap_info, cdev);
	filep->private_data = os_adap;
	chfcoe_dbg(inode, "cdev open %d\n", os_adap->adap->pf);

	return 0;
} /* chfcoe_cdev_open */

/*
 * chfcoe_cdev_release - Release entry point.
 *
 * Called when all shared references to this open object have closed
 * their file descriptors (Eg: between parent/child processes)
 */
static int
chfcoe_cdev_release(struct inode *inode, struct file *filep)
{
	filep->private_data = NULL;
	chfcoe_dbg(inode, "cdev release\n");
	return 0;
} /* chfcoe_cdev_release */

/*
 * chfcoe_os_ioctl_handler - OS related IOCTL command handler
 * @os_adap - OS specific Adapter information
 * @opcode - IOCTL command opcode
 * @arg - Arguments to the command
 * @kbuf - kernel buffer
 * @len - length of the buffer
 */
static int
chfcoe_os_ioctl_handler(struct chfcoe_os_adap_info *os_adap, uint32_t opcode,
		unsigned long arg, void *kbuf, uint32_t len)
{
#ifdef __CHFCOE_TRACE_SUPPORT__
	int mlen;
	struct chfcoe_adap_info *adap = (os_adap->adap);
	struct chfcoe_oss_trace_msg trace_msg;
	void __user *payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
#endif

	switch (opcode) {
#ifdef __CHFCOE_TRACE_SUPPORT__
		case CSIO_OS_GET_HOST_TRACE_BUF:
			mlen = sizeof(struct chfcoe_oss_trace_msg);
			while (len >= mlen) {
				if (!(chfcoe_oss_trace_readmsg(
								adap->trace_buffer, &trace_msg, 1))) {
					/* No more messages */
					break;
				}
				if (copy_to_user(payload, (void *)&trace_msg,
							mlen))
					return -EFAULT;

				payload += mlen;
				len -= mlen;
			}
			break;
#endif

		default:
			return -EOPNOTSUPP;
	}
	return 0;
} /* chfcoe_os_ioctl_handler */

static int chfcoe_adap_show(struct chfcoe_adap_info *adap,
                void *buffer, uint32_t buffer_len)
{
	struct chfcoe_os_adap_info *os_adap = adap->os_dev;
	struct cxgb4_lld_info *lldi = os_adap->lldi;
	csio_hw_info_t *hw_info = buffer;

	if (buffer_len < sizeof(csio_hw_info_t))
		return -CHFCOE_NOMEM;

	strcpy(hw_info->name, "POFCoE Target driver");
	strncpy(hw_info->pci_name, pci_name(lldi->pdev), 32);
	memcpy(hw_info->drv_version, adap->drv_version, 32);

	hw_info->pci_id.s.vendor_id = lldi->pdev->vendor;
	hw_info->pci_id.s.device_id = lldi->pdev->device;

	hw_info->fwrev          = lldi->fw_vers;
	hw_info->chip_rev       = CHELSIO_CHIP_RELEASE(lldi->adapter_type);

	hw_info->pfn            = lldi->pf;
	hw_info->num_t4ports    = lldi->nports;

	hw_info->partial_offload    = 1;
	hw_info->initiator      = 0;
	hw_info->target         = 1;


	return CHFCOE_SUCCESS;
}

/*
 * chfcoe_adap_ioctl_handler - Partial Offload FCoE IOCTL handler
 * @adap - Adapter information structure
 * @opcode - IOCTL opcode
 */
chfcoe_retval_t chfcoe_os_adap_ioctl_handler(struct chfcoe_adap_info *adap, 
		uint32_t opcode, void *buffer, uint32_t buffer_len)
{
	chfcoe_retval_t rv = CHFCOE_SUCCESS;

	switch (opcode) {
	case CSIO_HW_SHOW:
		rv = chfcoe_adap_show(adap, buffer, buffer_len);
		break;
	default:
		rv = chfcoe_adap_ioctl_handler(adap, opcode, buffer, 
				buffer_len);
		break;
	}

	return rv;
} /* chfcoe_adap_ioctl_handler */

/*
 * chfcoe_cdev_ioctl - Driver ioctl entry point.
 * @file - file pointer
 * @cmd - command (OS related or FCoE related)
 * @arg - arguments to the ioctl command from user space
 */
static long
chfcoe_cdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret, len;
	struct chfcoe_os_adap_info *os_adap;
	struct chfcoe_adap_info *adap;
	void *kbuf = NULL;
	int dir = _IOC_NONE;
	ioctl_hdr_t hdr;

	os_adap = (struct chfcoe_os_adap_info *)file->private_data;
	if (!os_adap) {
		/* There is no Adap struct available to use chfcoe_err macro */
		printk("chfcoe: Unable to find Chfcoe Adapter instance\n");
		return -ENOTTY;
	}

	adap = (os_adap->adap);

	if (copy_from_user((void *)&hdr, (void __user *)arg,
				sizeof(ioctl_hdr_t)))
		return -EFAULT;

	len = hdr.len;
	dir = hdr.dir;

	if (len < 0) {
		chfcoe_err(adap, "Invalid ioctl len:%x dev:%s\n", cmd, 
				pci_name(os_adap->pdev));
		return -EINVAL;
	}
	if (dir != _IOC_NONE) {
		if (len == 0) {
			chfcoe_err(adap, "Invalid ioctl len/dir %x dev:%s\n",
					cmd,  pci_name(os_adap->pdev));
			return -EINVAL;
		}

		kbuf = kzalloc(len, GFP_KERNEL);
		if (!kbuf)
			return -ENOMEM;

		if ((dir & _IOC_WRITE) &&
				(copy_from_user(kbuf,
						(void __user *)(arg + sizeof(ioctl_hdr_t)),
						len))) {
			kfree(kbuf);
			return -EFAULT;
		}
	}

	ret = 0;
	chfcoe_dbg(adap, "ioctl: recv cmd %x dev:%s\n", cmd, 
			pci_name(os_adap->pdev));
	switch (cmd & CSIO_STOR_IOCTL_MASK) {
		case CSIO_STOR_HW:
			ret = chfcoe_os_adap_ioctl_handler(adap,
					CSIO_STOR_GET_OPCODE(cmd), kbuf, len);
			if (ret != CHFCOE_SUCCESS)
				goto out;
			break;

		case CSIO_OS:
			ret = chfcoe_os_ioctl_handler(os_adap,
					CSIO_STOR_GET_OPCODE(cmd), arg, kbuf, len);
			goto out;

		case CSIO_STOR_FCOE:
			ret = chfcoe_fcoe_ioctl_handler(adap,
					CSIO_STOR_GET_OPCODE(cmd), kbuf, len);
			if (ret != CHFCOE_SUCCESS) 
				goto out;
			break;

		default:
			chfcoe_err(adap, "Invalid IOCTL cmd:%x dev:%s\n", cmd, 
					pci_name(os_adap->pdev));
			ret = -EOPNOTSUPP;
			goto out;
	}

	if ((dir & _IOC_READ) &&
			(copy_to_user((void __user *)(arg + sizeof(ioctl_hdr_t)),
				      kbuf, len)))
		ret = -EFAULT;

out:
	if (dir != _IOC_NONE)
		kfree(kbuf);

	return ret;
} /* chfcoe_cdev_ioctl */

/*
 * cdev file operations structure definitions.
 */
static struct file_operations chfcoe_cdev_fops = {
	.owner		= THIS_MODULE,
	.open		= chfcoe_cdev_open,
	.release	= chfcoe_cdev_release,
	.unlocked_ioctl = chfcoe_cdev_ioctl,
};

/*
 * chfcoe_cdev_init - Initialize the character device.
 * @os_adap: The OS specific adapter information.
 *
 * Get a an unused minor number, initialize the character device
 * for this os_adap instance and create the device file for it.
 */
static int
chfcoe_cdev_init(struct chfcoe_os_adap_info *os_adap)
{
	int minor, rv = 0;
	struct device *dev;

	minor = find_first_zero_bit(chfcoe_cdev_minors,
			sizeof(chfcoe_cdev_minors));
	__chfcoe_set_bit(minor, chfcoe_cdev_minors);
	cdev_init(&os_adap->cdev, &chfcoe_cdev_fops);
	os_adap->cdev.owner = THIS_MODULE;

	rv = cdev_add(&os_adap->cdev, MKDEV(chfcoe_cdev_major, minor), 1);
	if (rv) {
		__chfcoe_clear_bit(minor, chfcoe_cdev_minors);
	} else {
		dev = device_create(chfcoe_class, NULL,
				MKDEV(chfcoe_cdev_major, minor),
				NULL, "chfcoe%u", minor);
		if (IS_ERR(dev)) {
			rv = PTR_ERR(dev);
			chfcoe_err(os_adap, "failed to create devfile:%d"
				"dev:%s\n", rv, pci_name(os_adap->pdev));
			__chfcoe_clear_bit(minor, chfcoe_cdev_minors);
			cdev_del(&os_adap->cdev);
			return rv;
		}
	}

	return rv;
} /* chfcoe_cdev_init */

/*
 * chfcoe_cdev_exit - Cleanup the character device
 * @os_adap: The OS specifice Adapter information.
 */
static void
chfcoe_cdev_exit(struct chfcoe_os_adap_info *os_adap)
{
	__chfcoe_clear_bit(MINOR(os_adap->cdev.dev), chfcoe_cdev_minors);
	device_destroy(chfcoe_class, MKDEV(chfcoe_cdev_major,
				MINOR(os_adap->cdev.dev)));
	cdev_del(&os_adap->cdev);
} /* chfcoe_cdev_exit */

static void chfcoe_cleanup_os_adap(void)
{
	struct chfcoe_os_adap_info *os_adap;
	struct chfcoe_adap_info *adap;
	struct chfcoe_list *entry;

	while (!chfcoe_list_empty(&adap_head)) {
		chfcoe_deq_from_tail(&adap_head, &entry);
		if (entry == NULL)
			continue;
		os_adap = (struct chfcoe_os_adap_info *)entry;
		adap = os_adap->adap;
		chfcoe_port_close(adap);
		chfcoe_cdev_exit(os_adap);
		if (os_adap->lldi)
			kfree(os_adap->lldi);
#ifdef __CHFCOE_DEBUGFS__
		chfcoe_osdfs_adap_exit(os_adap);
#endif
		kfree(os_adap);
	}
}

/*
 * chfcoe_os_init - Initialization of chfcoe driver
 *
 * This is the first function called in the driver load path.
 * It also initializes other modules as well.
 */
static int __init chfcoe_os_init(void)
{
	int err = 0;
	dev_t dev;

	printk("chfcoe: Loading %s v%s\n", CHFCOE_DRV_DESC,
			CHFCOE_DRV_VERSION);

	if (chfcoe_module_params_check() != CHFCOE_SUCCESS) {
		err = -EINVAL;
		goto err0;
	}	       

	if (chfcoe_module_init() != CHFCOE_SUCCESS) {
		err = -ENOMEM;
		goto err0;
	}	       

	err = alloc_chrdev_region(&dev, 0, CHFCOE_MAX_CMINORS, CHFCOE_CDEVFILE);
	if (err) {
		printk("chfcoe: failed to allocated device minor numbers.\n");
		goto err1;
	}

	chfcoe_cdev_major = MAJOR(dev);
	chfcoe_class = class_create(THIS_MODULE, CHFCOE_CDEVFILE);
	if (IS_ERR(chfcoe_class)) {
		err = PTR_ERR(chfcoe_class);
		printk("chfcoe: failed to create %s class: %d\n",
				CHFCOE_CDEVFILE, err);
		goto err2;
	}
#ifdef __CHFCOE_DEBUGFS__
	chfcoe_osdfs_init();
#endif	
	chfcoe_head_init(&adap_head);

#ifdef __CSIO_TARGET__	
	if ((err = csio_scst_sal_init()))
		goto err3;

	if (chfcoe_tgt_init())
		goto err4;
#endif	
	cxgb4_register_uld(CXGB4_ULD_FCOE, &chfcoe_uld_info);

	register_netdevice_notifier(&chfcoe_notifier);
	register_dcbevent_notifier(&chfcoe_dcb_notifier);

	return 0;

#ifdef __CSIO_TARGET__
err4:
	csio_scst_sal_exit();
err3:
#ifdef __CHFCOE_DEBUGFS__	
	chfcoe_osdfs_exit();
#endif
	class_destroy(chfcoe_class);
#endif
err2:
	unregister_chrdev_region(dev, CHFCOE_MAX_CMINORS);
err1:
	chfcoe_module_exit();
err0:
	return err;
} /* chfcoe_os_init */

/*
 * chfcoe_os_exit - Uninitializing the chfcoe driver.
 * This function gets called during unload path.
 */
static void __exit chfcoe_os_exit(void)
{

	unregister_netdevice_notifier(&chfcoe_notifier);
	unregister_dcbevent_notifier(&chfcoe_dcb_notifier);
	chfcoe_flush_skb_queue();

	chfcoe_cleanup_os_adap();

#ifdef __CHFCOE_DEBUGFS__        
	chfcoe_osdfs_exit();
#endif

#ifdef __CSIO_TARGET__	
	chfcoe_tgt_exit();
	csio_scst_sal_exit();
#endif
	cxgb4_unregister_uld(CXGB4_ULD_FCOE);
	class_destroy(chfcoe_class);
	unregister_chrdev_region(MKDEV(chfcoe_cdev_major, 0), 
			CHFCOE_MAX_CMINORS);
	
	chfcoe_module_exit();
	printk("Unloaded %s v%s\n", CHFCOE_DRV_DESC, CHFCOE_DRV_VERSION);

	return;
} /* chfcoe_os_exit */

module_init(chfcoe_os_init);
module_exit(chfcoe_os_exit);
MODULE_AUTHOR(CHFCOE_DRV_AUTHOR);
MODULE_DESCRIPTION(CHFCOE_DRV_DESC);
MODULE_LICENSE(CHFCOE_DRV_LICENSE);
MODULE_VERSION(CHFCOE_DRV_VERSION);
