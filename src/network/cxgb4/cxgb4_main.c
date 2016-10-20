/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver for Linux.
 *
 * Copyright (C) 2003-2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/bitmap.h>
#include <linux/crc32.h>
#include <linux/debugfs.h>
#include <linux/etherdevice.h>
#include <linux/firmware.h>
#include <linux/if_vlan.h>
#include <linux/log2.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/pci.h>
#include <linux/aer.h>
#include <linux/rtnetlink.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/sockios.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <net/neighbour.h>
#include <net/netevent.h>
#include <net/addrconf.h>
#include <asm/uaccess.h>
#include <linux/dma-mapping.h>
#include <linux/mii.h>
#include <linux/proc_fs.h>
#include <linux/sort.h>
#include <linux/notifier.h>
#include <linux/string_helpers.h>
#include <net/inet6_hashtables.h>

#include "common.h"
#include "cxgbtool.h"
#include "cxgb4_cxgbtool.h"
#include "cxgb4_filter.h"
#include "t4_regs.h"
#include "t4_regs_values.h"
#include "t4_msg.h"
#include "t4_tcb.h"
#include "t4fw_interface.h"
#include "t4_ma_failover.h"
#include "t4_linux_fs.h"

#include "t4_bypass.h"
#include "bypass_sysfs.h"

#include "cxgb4_dcb.h"
#include "smt.h"
#include "srq.h"
#include "cxgb4_debugfs.h"
#include "clip_tbl.h"
#include "l2t.h"
#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
#include "cxgb4_ptp.h"
#endif

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
#include "cxgb4_ofld.h"
#include "ocqp.h"
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

#if defined(BOND_SUPPORT)
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
#include <drivers/net/bonding/bonding.h>
#include <drivers/net/bonding/bond_3ad.h>
#else
#include <net/bonding.h>
#include <net/bond_3ad.h>
#endif
#endif

char cxgb4_driver_name[] = KBUILD_MODNAME;

#ifdef DRV_VERSION
#undef DRV_VERSION
#endif
#define DRV_VERSION "2.12.0.3"
const char cxgb4_driver_version[] = DRV_VERSION;

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
#define DRV_DESC "Chelsio T4/T5/T6 Offload Network Driver"
#else
#define DRV_DESC "Chelsio T4/T5/T6 Non-Offload Network Driver"
#endif

#ifdef CONFIG_PCI_IOV
enum {
	VF_MONITOR_PERIOD = 4 * HZ,
};
#endif

#define PORT_MASK ((1 << MAX_NPORTS) - 1)

#define DFLT_MSG_ENABLE (NETIF_MSG_DRV | NETIF_MSG_PROBE | NETIF_MSG_LINK | \
			 NETIF_MSG_TIMER | NETIF_MSG_IFDOWN | NETIF_MSG_IFUP |\
			 NETIF_MSG_RX_ERR | NETIF_MSG_TX_ERR)

/* Macros needed to support the PCI Device ID Table ...
 */
#define CH_PCI_DEVICE_ID_TABLE_DEFINE_BEGIN \
	static const struct pci_device_id cxgb4_pci_tbl[] = {
#define CH_PCI_DEVICE_ID_FUNCTION 0x4

#ifdef CHELSIO_T4_DIAGS
/* Include PCI Device IDs for both PF4 and PF0-3 so our PCI probe() routine is
 * called for both.  Normally we'll manage the adapter via PF4 but for some
 * diagnostic purposes we need the use PF0.
 */
#define CH_PCI_DEVICE_ID_FUNCTION2 0x0
#endif

#define CH_PCI_ID_TABLE_ENTRY(devid) \
		{PCI_VDEVICE(CHELSIO, (devid)), 0}

#define CH_PCI_DEVICE_ID_TABLE_DEFINE_END \
		{ 0, } \
	}

#ifdef CONFIG_CHELSIO_BYPASS
#define CH_PCI_DEVICE_ID_BYPASS_SUPPORTED 1
#endif

/*
 * ... and the PCI ID Table itself ...
 */
#include "t4_pci_id_tbl.h"

#define FW4_FNAME "cxgb4/t4fw.bin"
#define FW5_FNAME "cxgb4/t5fw.bin"
#define FW6_FNAME "cxgb4/t6fw.bin"
#define FW4_CFNAME "cxgb4/t4-config.txt"
#define FW5_CFNAME "cxgb4/t5-config.txt"
#define FW6_CFNAME "cxgb4/t6-config.txt"
#define FW4_FPGA_CFNAME "cxgb4/t4-config_fpga.txt"
#define FW5_FPGA_CFNAME "cxgb4/t5-config_fpga.txt"
#define FW6_FPGA_CFNAME "cxgb4/t6-config_fpga.txt"
#define PHY_AQ1202_FIRMWARE "cxgb4/aq1202_fw.cld"
#define PHY_BCM84834_FIRMWARE "cxgb4/bcm8483.bin"
#define PHY_AQ1202_DEVICEID 0x4409
#define PHY_BCM84834_DEVICEID 0x4486

MODULE_DESCRIPTION(DRV_DESC);
MODULE_AUTHOR("Chelsio Communications");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, cxgb4_pci_tbl);
MODULE_FIRMWARE(FW4_FNAME);
MODULE_FIRMWARE(FW5_FNAME);
MODULE_FIRMWARE(FW6_FNAME);
MODULE_FIRMWARE(FW4_CFNAME);
MODULE_FIRMWARE(FW5_CFNAME);
MODULE_FIRMWARE(FW6_CFNAME);

#ifdef CHELSIO_T4_DIAGS
/*
 * The master PF is normally PF4 but can be changed to PF0 via the attach_pf0
 * module parameter.  Note that PF0 does have extra privileges and can access
 * all the other PFs' VPDs and the entire EEPROM which the other PFs cannot.
 * This functionality is vital for diagnostics which needs access to the entire
 * EEPROM.
 */
static bool attach_pf0;

module_param(attach_pf0, bool, 0644);
MODULE_PARM_DESC(attach_pf0, "Attach to Master Physical Function 0");

/*
 * Allow firmware to initialize the external memory so that diagnostics can
 * run BIST. Normally, the memory is initialized only when it is needed, but
 * this parameter allows the memory to be initialized from the driver by
 * sending a FW command to do so.
 */
static bool extmem_init = 0;
module_param(extmem_init, bool, 0644);
MODULE_PARM_DESC(extmem_init, "Initialize external memory");
#endif

/*
 * Default message set for the interfaces.  This can be changed after the
 * driver is loaded via "ethtool -s ethX msglvl N".
 */
static int dflt_msg_enable = DFLT_MSG_ENABLE;

module_param(dflt_msg_enable, int, 0644);
MODULE_PARM_DESC(dflt_msg_enable, "Chelsio T4/T5/T6 default message enable bitmap");

/*
 * The driver uses the best interrupt scheme available on a platform in the
 * order MSI-X, MSI, legacy INTx interrupts.  This parameter determines which
 * of these schemes the driver may consider as follows:
 *
 * msi = 2: choose from among all three options
 * msi = 1: only consider MSI and INTx interrupts
 * msi = 0: force INTx interrupts
 */
static int msi = 2;

module_param(msi, int, 0644);
MODULE_PARM_DESC(msi, "whether to use INTx (0), MSI (1) or MSI-X (2)");

/*
 * TX Packet coalescing.  Set to 0, disables all TX Coalescing.  Set to 1,
 * we perform TX Coalescing when it looks like a TX Queue is "getting full."
 * Set to 2, we perform TX Coalescing most of the time with a consequent
 * impact to TX Latency ...
 */
static int tx_coal = 1;

module_param(tx_coal, int, 0644);
MODULE_PARM_DESC(tx_coal, "use tx WR coalescing, if set to 2, coalescing "
		 " will be used most of the time improving packets per "
		 " second troughput but affecting latency");

/*
 * TX Doorbell Write Combining support.  Set to 0, disables this
 * functionality.  Set to 1 (default), it enables it on chip and system
 * architectures which support this and Write-Combined memory mappings.
 */
#ifdef ARCH_HAS_IOREMAP_WC
static int tx_db_wc = 1;
#else
static int tx_db_wc = 0;
#endif
module_param(tx_db_wc, int, 0644);
MODULE_PARM_DESC(tx_db_wc, "use tx WR combining");

/*
 * Use Ethernet TX Packet Virtual Machine Work Request instead of normal TX
 * Packet Work Request to send packets out on Ethernet (NIC) TX Queues.  The
 * normal FW_ETH_TX_PKT_WR doesn't go through a loopback lookup in the
 * hardware and so always simply goes out on the wire and is never replicated
 * for loopback to the host on Virtual Interfaces on the same port.  The
 * FW_ETH_TX_PKT_VM_WR does do this lookup but haas somewhat lower
 * performance.
 */
static int tx_vm = 0;
module_param(tx_vm, int, 0644);
MODULE_PARM_DESC(tx_vm, "Use Ethernet TX Workrequests which can be delivered "
		 "to Virtual Interfaces on the same port.");

/*
 * Normally we tell the chip to deliver Ingress Packets into our DMA buffers
 * offset by 2 bytes in order to have the IP headers line up on 4-byte
 * boundaries.  This is a requirement for many architectures which will throw
 * a machine check fault if an attempt is made to access one of the 4-byte IP
 * header fields on a non-4-byte boundary.  And it's a major performance issue
 * even on some architectures which allow it like some implementations of the
 * x86 ISA.  However, some architectures don't mind this and for some very
 * edge-case performance sensitive applications (like forwarding large volumes
 * of small packets), setting this DMA offset to 0 will decrease the number of
 * PCI-E Bus transfers enough to measurably affect performance.
 */
static int rx_dma_offset = 2;

module_param(rx_dma_offset, int, 0644);
MODULE_PARM_DESC(rx_dma_offset, "Offset of RX packets into DMA buffers -- "
		 " legal values 2 (default) and 0");

#ifdef CONFIG_PCI_IOV
/* Configure the number of PCI-E Virtual Function which are to be instantiated
 * on SR-IOV Capable Physical Functions.
 */
static unsigned int num_vf[NUM_OF_PF_WITH_SRIOV];

module_param_array(num_vf, uint, NULL, 0644);
MODULE_PARM_DESC(num_vf, "number of VFs for each of PFs 0-3");
#endif

/*
 * Firmware auto-install by driver during attach (0, 1, 2 = prohibited, allowed,
 * encouraged respectively).
 */
static int t4_fw_install = 1;
module_param(t4_fw_install, int, 0644);
MODULE_PARM_DESC(t4_fw_install, "whether to have FW auto-installed by driver "
		 "during attach (0, 1, 2 = prohibited, allowed, encouraged "
		 "respectively).");

/*
 * If fw_attach is 0 the driver will not connect to FW.  This is intended only
 * for FW debugging.  fw_attach must be 1 for normal operation.
 */
int fw_attach = 1;

module_param(fw_attach, int, 0644);
MODULE_PARM_DESC(fw_attach, "whether to connect to FW");

/*
 * SGE Doorbell FIFO Overflow recovery ...
 */
int dbfifo_int_thresh = 5; /* 5 == 320 entry threshold */
module_param(dbfifo_int_thresh, int, 0644);
MODULE_PARM_DESC(dbfifo_int_thresh, "doorbell fifo interrupt threshold");

/*
 * usecs to sleep while draining the dbfifo
 */
static int dbfifo_drain_delay = 1000;
module_param(dbfifo_drain_delay, int, 0644);
MODULE_PARM_DESC(dbfifo_drain_delay, 
		 "usecs to sleep while draining the dbfifo");

int allow_nonroot_filters = 0;
module_param(allow_nonroot_filters, int, 0644);
MODULE_PARM_DESC(allow_nonroot_filters,
		 "Allow nonroot access to filters (default = 0)");

int attempt_err_recovery = 0;
module_param(attempt_err_recovery, int, 0644);
MODULE_PARM_DESC(attempt_err_recovery,
		 "Attempt to reset and recover from fatal hw errors (default = 0)");

/* TX Queue select used to determine what algorithm to use for selecting TX
 * queue. Select between the kernel provided function (select_queue=0) or user
 * cxgb_select_queue function (select_queue=1)
 *
 * Default: select_queue=0
 */
static int select_queue = 0;
module_param(select_queue, int, 0644);
MODULE_PARM_DESC(select_queue,
		 "Select between kernel provided method of selecting or driver method of selecting TX queue. Default is kernel method.");

int max_eth_qsets = 32;
module_param(max_eth_qsets, int, 0644);
MODULE_PARM_DESC(max_eth_qsets, "Maximum number of queue sets that will be "
		 "allocated per adapter, for Nic traffic. Valid values - "
		 "32..64, Default value is 32.");
 
#ifndef CONFIG_CHELSIO_BYPASS
/*
 * Host Deadman Watchdog Timer.  If this is enabled, then the Host Driver will
 * set up a firmware watchdog timer to cause the firmware to shut down the
 * adapter if mode is set to zero and turnoff pause if mode is non zero,
 * if the Host Driver stops resetting the watchdog timer.  One use of
 * this is to prevent a dead host from causing its attached switch from going
 * down.  This can happen with some switches when the dead host stops
 * processing ingress packets which will eventually result in an endless
 * stream of Pause Frames being sent.  A Good Switch would simply disable that
 * port but there are Less Good Switches out there that crash.
 *
 * This feature isn't available for Bypass adapters because they already use
 * the adapter watchdog support for their special needs.
 */
#define DEADMAN_WATCHDOG_MIN 1000
#define DEADMAN_SHUTDOWN_MAX 60000
static int deadman_watchdog[2] = {0,0};
module_param_array(deadman_watchdog, int, NULL, 0644);
MODULE_PARM_DESC(deadman_watchdog,
		 "Array of elements representing pair of {n,m} "
		 "where n is timer (min=1000ms, max=60000ms, 0=watchdog off) default 0;"
		 " m is the mode(Optional), valid values (0=shutdown, 1=pauseoff) default 0");
#endif /* CONFIG_CHELSIO_BYPASS */

static unsigned int mq_with_1G;
module_param(mq_with_1G, uint, 0644);
MODULE_PARM_DESC(mq_with_1G,
		 "Support core no of queues per port, even for 1G port");

static int user_filter_perc = 33;
module_param(user_filter_perc, int, 0444);
MODULE_PARM_DESC(user_filter_perc,
	         "Percentage of total Filter region space to be allotted for"
		 " user-filters. Valid values - 0..100. Default is 33");

/*
 * Enable use of DDR Filters.
 */
static unsigned int use_ddr_filters;
module_param(use_ddr_filters, uint, 0444);
MODULE_PARM_DESC(use_ddr_filters,
		 "Use DDR Filters to support more no. of User-Filters");

/*
 * Offload RX queue intr cnt threshold.
 */
static unsigned int offload_rx_intr_cnt = 1;
module_param(offload_rx_intr_cnt, uint, 0444);
MODULE_PARM_DESC(offload_rx_intr_cnt,
		"Offload RX queue intr cnt threshold (default=1)");

static struct dentry *cxgb4_debugfs_root;

static LIST_HEAD(adapter_list);
DEFINE_MUTEX(uld_mutex);
struct cxgb4_uld_info cxgb4_ulds[CXGB4_ULD_MAX];
const char *uld_str[] = { "RDMA", "iSCSI", "TOE" };

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
static unsigned int registered_notifier_block;
enum {
	CXGB4_NETDEV_REGISTERED		= 1 << 0,
	CXGB4_INET6ADDR_REGISTERED	= 1 << 1,
	CXGB4_NETEVENT_REGISTERED	= 1 << 2
};
#endif

/**
 *	link_report - show link status and link speed/duplex
 *	@dev: the port whose settings are to be reported
 *
 *	Shows the link status, speed, and duplex of a port.
 */
static void link_report(struct net_device *dev)
{
	if (!netif_carrier_ok(dev))
		printk(KERN_INFO "%s: link down\n", dev->name);
	else {
		static const char *fc[] = { "no", "Rx", "Tx", "Tx/Rx" };

		const char *s;
		const struct port_info *p = netdev_priv(dev);

		switch (p->link_cfg.speed) {
		case 10000:
			s = "10Gbps";
			break;
		case 1000:
			s = "1000Mbps";
			break;
		case 100:
			s = "100Mbps";
			break;
		case 40000:
			s = "40Gbps";
			break;

		default:
			printk(KERN_INFO "%s: unsupported speed: %d\n",
			       dev->name, p->link_cfg.speed);
			return;
		}

		printk(KERN_INFO "%s: link up, %s, full-duplex, %s PAUSE\n",
		       dev->name, s, fc[p->link_cfg.fc]);
	}
}

#ifdef CONFIG_CXGB4_DCB
extern char *dcb_ver_array[];

/* Set up/tear down Data Center Bridging Priority mapping for a net device. */
static void dcb_tx_queue_prio_enable(struct net_device *dev, int enable)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adap = pi->adapter;
	struct sge_eth_txq *txq = &adap->sge.ethtxq[pi->first_qset];
	int i;

	/* We use a simple mapping of Port TX Queue Index to DCB
	 * Priority when we're enabling DCB.
	 */
	for (i = 0; i < pi->nqsets; i++, txq++) {
		u32 name, value;
		int err;

		name = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DMAQ) |
			V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DMAQ_EQ_DCBPRIO_ETH) |
			V_FW_PARAMS_PARAM_YZ(txq->q.cntxt_id));
		value = enable ? i : 0xffffffff;

		/* Since we can be called while atomic (from "interrupt
		 * level") we need to issue the Set Parameters Commannd
		 * without sleeping (timeout < 0).
		 */
		err = t4_set_params_timeout(adap, adap->mbox, adap->pf, 0, 1,
					    &name, &value,
					    -FW_CMD_MAX_TIMEOUT);

		if (err)
			CH_ERR(adap,
				"Can't %s DCB Priority on port %d, TX Queue %d: err=%d\n",
				enable ? "set" : "unset", pi->port_id, i, -err);
		else
			txq->dcb_prio = value;
	}
}
#endif /* CONFIG_CXGB4_DCB */

/**
 *	t4_os_link_changed - handle link status changes
 *	@adapter: the adapter associated with the link change
 *	@port_id: the port index whose link status has changed
 *	@link_stat: the new status of the link
 *
 *	This is the OS-dependent handler for link status changes.  The OS
 *	neutral handler takes care of most of the processing for these events,
 *	then calls this handler for any OS-specific processing.
 */
void t4_os_link_changed(struct adapter *adapter, int port_id, int link_stat)
{
	struct net_device *dev = adapter->port[port_id];

	/* Skip changes from disabled ports. */
	if (netif_running(dev) && link_stat != netif_carrier_ok(dev)) {
		if (link_stat)
			netif_carrier_on(dev);
		else {
#ifdef CONFIG_CXGB4_DCB
			cxgb4_dcb_state_init(dev);
			dcb_tx_queue_prio_enable(dev, false);
#endif /* CONFIG_CXGB4_DCB */
			netif_carrier_off(dev);
		}

		link_report(dev);
	}
}

/**
 *	t4_os_portmod_changed - handle port module changes
 *	@adap: the adapter associated with the module change
 *	@port_id: the port index whose module status has changed
 *
 *	This is the OS-dependent handler for port module changes.  It is
 *	invoked when a port module is removed or inserted for any OS-specific
 *	processing.
 */
void t4_os_portmod_changed(const struct adapter *adap, int port_id)
{
	static const char *mod_str[] = {
		NULL, "LR", "SR", "ER", "passive DA", "active DA", "LRM"
	};

	const struct net_device *dev = adap->port[port_id];
	const struct port_info *pi = netdev_priv(dev);

	if (pi->mod_type == FW_PORT_MOD_TYPE_NONE)
		printk(KERN_INFO "%s: port module unplugged\n", dev->name);
	else if (pi->mod_type < ARRAY_SIZE(mod_str))
		printk(KERN_INFO "%s: %s port module inserted\n", dev->name,
		       mod_str[pi->mod_type]);
	else if (pi->mod_type == FW_PORT_MOD_TYPE_NOTSUPPORTED)
		printk(KERN_INFO "%s: unsupported optical port module "
		 	"inserted\n", dev->name);
	else if (pi->mod_type == FW_PORT_MOD_TYPE_UNKNOWN)
		printk(KERN_INFO "%s: unknown port module inserted, forcing "
		       "TWINAX\n", dev->name);
	else if (pi->mod_type == FW_PORT_MOD_TYPE_ERROR)
		printk(KERN_INFO "%s: transceiver module error\n", dev->name);
	else
		printk(KERN_INFO "%s: unknown module type %d inserted\n",
		       dev->name, pi->mod_type);
}

static inline int cxgb4_set_addr_hash(struct port_info *pi)
{
	struct adapter *adap = pi->adapter;
	u64 vec = 0;
	bool ucast = false;
	struct hash_mac_addr *entry;

	/* Calculate the hash vector for the updated list and program it */
	list_for_each_entry(entry, &adap->mac_hlist, list) {
		ucast |= is_unicast_ether_addr(entry->addr);
		vec |= (1ULL << hash_mac_addr(entry->addr));
	}
	return t4_set_addr_hash(adap, adap->mbox, pi->viid, ucast,
				vec, false);
}

static int cxgb4_mac_sync(struct net_device *netdev, const u8 *mac_addr)
{
	struct port_info *pi = netdev_priv(netdev);
	struct adapter *adap = pi->adapter;
	int ret;
	u64 mhash = 0;
	u64 uhash = 0;
	bool free = false;
	bool ucast = is_unicast_ether_addr(mac_addr);
	const u8 *maclist[1] = {mac_addr};
	struct hash_mac_addr *new_entry;

	ret = t4_alloc_mac_filt(adap, adap->mbox, pi->viid, free, 1, maclist,
				NULL, ucast ? &uhash : &mhash, false);
	if (ret < 0)
		goto out;
	/* if hash != 0, then add the addr to hash addr list
	 * so on the end we will calculate the hash for the
	 * list and program it
	 */
	if (uhash || mhash) {
		new_entry = kzalloc(sizeof(*new_entry), GFP_ATOMIC);
		if (!new_entry)
			return -ENOMEM;
		ether_addr_copy(new_entry->addr, mac_addr);
		list_add_tail(&new_entry->list, &adap->mac_hlist);
		ret = cxgb4_set_addr_hash(pi);
	}
out:
	return ret < 0 ? ret : 0;
}

static int cxgb4_mac_unsync(struct net_device *netdev, const u8 *mac_addr)
{
	struct port_info *pi = netdev_priv(netdev);
	struct adapter *adap = pi->adapter;
	int ret;
	const u8 *maclist[1] = {mac_addr};
	struct hash_mac_addr *entry, *tmp;

	/* If the MAC address to be removed is in the hash addr
	 * list, delete it from the list and update hash vector
	 */
	list_for_each_entry_safe(entry, tmp, &adap->mac_hlist, list) {
		if (ether_addr_equal(entry->addr, mac_addr)) {
			list_del(&entry->list);
			kfree(entry);
			return cxgb4_set_addr_hash(pi);
		}
	}

	ret = t4_free_mac_filt(adap, adap->mbox, pi->viid, 1, maclist, false);
	return ret < 0 ? -EINVAL : 0;
}

/*
 * Set Rx properties of a port, such as promiscruity, address filters, and MTU.
 * If @mtu is -1 it is left unchanged.
 */
static int set_rxmode(struct net_device *dev, int mtu, bool sleep_ok)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;

	if (!(dev->flags & IFF_PROMISC)) {
		__dev_uc_sync(dev, cxgb4_mac_sync, cxgb4_mac_unsync);
		if (!(dev->flags & IFF_ALLMULTI))
			__dev_mc_sync(dev, cxgb4_mac_sync, cxgb4_mac_unsync);
	}

	return t4_set_rxmode(adapter, adapter->mbox, pi->viid, mtu,
			     (dev->flags & IFF_PROMISC) ? 1 : 0,
			     (dev->flags & IFF_ALLMULTI) ? 1 : 0, 1, -1,
			     sleep_ok);
}

static void cxgb_set_rxmode(struct net_device *dev)
{
	/* unfortunately we can't return errors to the stack */
	set_rxmode(dev, -1, false);
}

/**
 *	link_start - enable a port
 *	@dev: the port to enable
 *
 *	Performs the MAC and PHY actions needed to enable a port.
 */
static int link_start(struct net_device *dev)
{
	int ret;
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;

	/*
	 * We do not set address filters and promiscuity here, the stack does
	 * that step explicitly.
	 */
	ret = t4_set_rxmode(adapter, adapter->mbox, pi->viid, dev->mtu, -1, -1,
			    -1, !!(dev->features & NETIF_F_HW_VLAN_CTAG_RX),
			    true);
	if (ret == 0) {
		ret = t4_change_mac(adapter, adapter->mbox, pi->viid,
				    pi->xact_addr_filt, dev->dev_addr, true,
				    true);
		if (ret >= 0) {
			pi->xact_addr_filt = ret;
			ret = 0;
		}
	}
	if (ret == 0)
		ret = t4_link_l1cfg(adapter, adapter->mbox, pi->tx_chan,
				    &pi->link_cfg);
	if (ret == 0) {
		/*
		 * Enabling a Virtual Interface can result in an interrupt
		 * during the processing of the VI Enable command and, in some
		 * paths, result in an attempt to issue another command in the
		 * interrupt context.  Thus, we disable interrupts during the
		 * course of the VI Enable command ...
		 */

		local_bh_disable();
		ret = t4_enable_vi_params(adapter, adapter->mbox, pi->viid,
					  true, true, CXGB4_DCB_ENABLED);
		local_bh_enable();
	}

	return ret;
}

int cxgb4_dcb_enabled(const struct net_device *dev)
{
#ifdef CONFIG_CXGB4_DCB
	struct port_info *pi = netdev_priv(dev);

	if (!pi->dcb.enabled)
		return 0;

	return ((pi->dcb.state == CXGB4_DCB_STATE_FW_ALLSYNCED) ||
		(pi->dcb.state == CXGB4_DCB_STATE_HOST));
#else
	return 0;
#endif
}
EXPORT_SYMBOL(cxgb4_dcb_enabled);

#ifdef CONFIG_CXGB4_DCB
/* Handle a Data Center Bridging update message from the firmware. */
static void dcb_rpl(struct adapter *adap, const struct fw_port_cmd *pcmd)
{
	int port = G_FW_PORT_CMD_PORTID(ntohl(pcmd->op_to_portid));
	struct net_device *dev = adap->port[port];
	int old_dcb_enabled = cxgb4_dcb_enabled(dev);
	int new_dcb_enabled;

	cxgb4_dcb_handle_fw_update(adap, pcmd);
	new_dcb_enabled = cxgb4_dcb_enabled(dev);

	/* If the DCB has become enabled or disabled on the port then we're
	 * going to need to set up/tear down DCB Priority parameters for the
	 * TX Queues associated with the port.
	 */
	if (new_dcb_enabled != old_dcb_enabled)
		dcb_tx_queue_prio_enable(dev, new_dcb_enabled);
}
#endif /* CONFIG_CXGB4_DCB */

/* Response queue handler for the FW event queue.
 */
static int fwevtq_handler(struct sge_rspq *q, const __be64 *rsp,
			  const struct pkt_gl *gl)
{
	u8 opcode = ((const struct rss_header *)rsp)->opcode;

	rsp++;                                          /* skip RSS header */

	/* FW can send EGR_UPDATEs encapsulated in a CPL_FW4_MSG.
	 */
	if (unlikely(opcode == CPL_FW4_MSG &&
	   ((const struct cpl_fw4_msg *)rsp)->type == FW_TYPE_RSSCPL)) {
		rsp++;
		opcode = ((const struct rss_header *)rsp)->opcode;
		rsp++;
		if (opcode != CPL_SGE_EGR_UPDATE) {
			CH_ERR(q->adap,
				"unexpected FW4/CPL %#x on FW event queue\n",
				opcode);
			goto out;
		}
	}

	if (likely(opcode == CPL_SGE_EGR_UPDATE)) {
		const struct cpl_sge_egr_update *p = (void *)rsp;
		unsigned int qid = G_EGR_QID(ntohl(p->opcode_qid));
		struct sge_txq *txq;

		txq = q->adap->sge.egr_map[qid - q->adap->sge.egr_start];
		if ((u8 *)txq < (u8 *)q->adap->sge.ofldtxq) {
			struct sge_eth_txq *eq;

			eq = container_of(txq, struct sge_eth_txq, q);
			t4_sge_coalesce_handler(q->adap, eq);
		} else {
			struct sge_ofld_txq *oq;

			txq->restarts++;
			oq = container_of(txq, struct sge_ofld_txq, q);
			tasklet_schedule(&oq->qresume_tsk);
		}
	} else if (opcode == CPL_FW6_MSG || opcode == CPL_FW4_MSG) {
		const struct cpl_fw6_msg *msg = (void *)rsp;

#ifdef CONFIG_CXGB4_DCB
		/*
		 * This might be a PORT command with a DCB update ... this
		 * simplifies the following conditionals ...  We can get away
		 * with pre-dereferencing op_to_portid and action_to_len16
		 * because they're both in the first 16 bytes and all messages
		 * will be at least that long.
		 */
		const struct fw_port_cmd *pcmd = (const void *)msg->data;
		unsigned int cmd = G_FW_CMD_OP(ntohl(pcmd->op_to_portid));
		unsigned int action =
			G_FW_PORT_CMD_ACTION(ntohl(pcmd->action_to_len16));

		/*
		 * If this is a DCB update from the firmware, process it.
		 * Otherwise throw the message at the general firmware reply
		 * handler.  We also catch the DCB Disabled/not Disabled from
		 * the general Port Information message to drive the DCB state
		 * machine.  (And yes, we could skip the #ifdef here since
		 * cxgb4_handle_fw_dcb_update() is defined to be a no-op.  But
		 * doing it this way will cause any Data Center Bridging
		 * messages we receive from the firmware to be sent to the
		 * general firmware reply handler which will then issue a
		 * warning about the unexpected messages.  Which may help
		 * someone realize that they need to turn DCB support on in
		 * the driver ...)
		 */
		if (cmd == FW_PORT_CMD &&
		    action == FW_PORT_ACTION_GET_PORT_INFO) {
			int port = G_FW_PORT_CMD_PORTID(
					be32_to_cpu(pcmd->op_to_portid));
			struct net_device *dev = q->adap->port[port];
			int state_input = ((pcmd->u.info.dcbxdis_pkd &
					    F_FW_PORT_CMD_DCBXDIS)
					   ? CXGB4_DCB_INPUT_FW_DISABLED
					   : CXGB4_DCB_INPUT_FW_ENABLED);

			cxgb4_dcb_state_fsm(dev, state_input);
		}

		if (cmd == FW_PORT_CMD &&
		    action == FW_PORT_ACTION_L2_DCB_CFG)
			dcb_rpl(q->adap, pcmd);
		else
#endif
			t4_handle_fw_rpl(q->adap, msg->data);
	} else if (opcode == CPL_SET_TCB_RPL) {
		const struct cpl_set_tcb_rpl *p = (void *)rsp;

		filter_rpl(q->adap, p);
	} else if (opcode == CPL_ACT_OPEN_RPL) {
		const struct cpl_act_open_rpl *p = (void *)rsp;

		hash_filter_rpl(q->adap, p);
	} else if (opcode == CPL_ABORT_RPL_RSS) {
		const struct cpl_abort_rpl_rss *p = (void *)rsp;

		hash_del_filter_rpl(q->adap, p);
	} else if (opcode == CPL_SMT_WRITE_RPL) {
		const struct cpl_smt_write_rpl *p = (void *)rsp;

		do_smt_write_rpl(q->adap, p);
        } else if (opcode == CPL_L2T_WRITE_RPL) {
		const struct cpl_l2t_write_rpl *p = (void *)rsp;

		do_l2t_write_rpl(q->adap, p);
	} else if (opcode == CPL_SRQ_TABLE_RPL) {
		const struct cpl_srq_table_rpl *p = (void *)rsp;

		do_srq_table_rpl(q->adap, p);
	} else {
		CH_ERR(q->adap,
			"unexpected CPL %#x on FW event queue\n", opcode);
	}
out:
	return 0;
}

#ifdef CONFIG_T4_MA_FAILOVER
static int uldma_failover_handler(struct sge_rspq *q, const __be64 *rsp,
               const struct pkt_gl *gl)
{
       if (cxgb4_ulds[q->uld].ma_failover_handler(q->adap->uld_handle[q->uld], rsp, gl)) {
               return -1;
       }
       return 0;
}
#endif /* CONFIG_T4_MA_FAILOVER */

#ifdef CONFIG_CHELSIO_T4_OFFLOAD

/* Flush the aggregated lro sessions */
static void uldrx_flush_handler(struct sge_rspq *q)
{
	if (cxgb4_ulds[q->uld].lro_flush)
		cxgb4_ulds[q->uld].lro_flush(&q->lro_mgr);
}

/**
 *	uldrx_handler - response queue handler for ULD queues
 *	@q: the response queue that received the packet
 *	@rsp: the response queue descriptor holding the offload message
 *	@gl: the gather list of packet fragments
 *
 *	Deliver an ingress offload packet to a ULD.  All processing is done by
 *	the ULD, we just maintain statistics.
 */
static int uldrx_handler(struct sge_rspq *q, const __be64 *rsp,
			 const struct pkt_gl *gl)
{
	struct sge_ofld_rxq *rxq = container_of(q, struct sge_ofld_rxq, rspq);
	int ret;

	/* FW can send CPLs encapsulated in a CPL_FW4_MSG.
	 */
	if (((const struct rss_header *)rsp)->opcode == CPL_FW4_MSG &&
	    ((const struct cpl_fw4_msg *)(rsp + 1))->type == FW_TYPE_RSSCPL)
		rsp += 2;

	if (q->flush_handler)
		ret = cxgb4_ulds[q->uld].lro_rx_handler(q->adap->uld_handle[q->uld],
							rsp, gl, &q->lro_mgr,
							&q->napi);
	else
		ret = cxgb4_ulds[q->uld].rx_handler(q->adap->uld_handle[q->uld],
					      rsp, gl);

	if (ret) {
		rxq->stats.nomem++;
		return -1;
	}
	if (gl == NULL)
		rxq->stats.imm++;
	else if (gl == CXGB4_MSG_AN)
		rxq->stats.an++;
	else
		rxq->stats.pkts++;
	return 0;
}
#endif

static void cxgb_disable_msi(struct adapter *adapter)
{
	if (adapter->flags & USING_MSIX) {
		pci_disable_msix(adapter->pdev);
		adapter->flags &= ~USING_MSIX;
	} else if (adapter->flags & USING_MSI) {
		pci_disable_msi(adapter->pdev);
		adapter->flags &= ~USING_MSI;
	}
}

/*
 * Interrupt handler for non-data events used with MSI-X.
 */
static irqreturn_t t4_nondata_intr(int irq, void *cookie)
{
	struct adapter *adap = cookie;

	u32 v = t4_read_reg(adap, MYPF_REG(A_PL_PF_INT_CAUSE));
	if (v & F_PFSW) {
		adap->swintr = 1;
		t4_write_reg(adap, MYPF_REG(A_PL_PF_INT_CAUSE), v);
	}
	if (adap->flags & MASTER_PF)
		t4_slow_intr_handler(adap);
	return IRQ_HANDLED;
}

/*
 * Name the MSI-X interrupts.
 */
static void name_msix_vecs(struct adapter *adap)
{
	int i, j, msi_idx = 2, n = sizeof(adap->msix_info[0].desc);

	/* non-data interrupts */
	snprintf(adap->msix_info[0].desc, n, "%s", adap->name);

	/* FW events */
	snprintf(adap->msix_info[1].desc, n, "%s-FWeventq", adap->name);

	/* Ethernet queues */
	for_each_port(adap, j) {
		struct net_device *d = adap->port[j];
		const struct port_info *pi = netdev_priv(d);

		for (i = 0; i < pi->nqsets; i++, msi_idx++)
			snprintf(adap->msix_info[msi_idx].desc, n,
				 "%s (queue %d)", d->name, i);
	}

	if (is_hashfilter(adap) && is_t5(adap->params.chip)) {
		for_each_tracerxq(&adap->sge, i) {
		       snprintf(adap->msix_info[msi_idx++].desc, n,
				"%s-traceq%d", adap->name, i);
		}
	}

	/* offload queues */
	for_each_ofldrxq(&adap->sge, i)
		snprintf(adap->msix_info[msi_idx++].desc, n, "%s-ofld%d",
			 adap->name, i);

	for_each_rdmarxq(&adap->sge, i)
		snprintf(adap->msix_info[msi_idx++].desc, n, "%s-rdma%d",
			 adap->name, i);

	for_each_rdmaciq(&adap->sge, i)
		snprintf(adap->msix_info[msi_idx++].desc, n, "%s-rdma-ciq%d",
			 adap->name, i);

	for_each_iscsirxq(&adap->sge, i)
		snprintf(adap->msix_info[msi_idx++].desc, n, "%s-iSCSI%d",
			 adap->name, i);

#ifdef CONFIG_T4_MA_FAILOVER
	if (is_offload(adap)) {
		/* MA-Failover queue */
		snprintf(adap->msix_info[msi_idx].desc, n, "%s-ma-failoverq", adap->name);
	}
#endif /* CONFIG_T4_MA_FAILOVER */

}

static int request_msix_queue_irqs(struct adapter *adap)
{
	struct sge *s = &adap->sge;
	int err, ethqidx;
	int msi_index = 2;
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	int ofldqidx = 0, rdmaqidx = 0, rdmaciqqidx = 0, iscsiqidx = 0;
#endif
	int traceqidx = 0;

	err = request_irq(adap->msix_info[1].vec, t4_sge_intr_msix, 0,
			  adap->msix_info[1].desc, &s->fw_evtq);
	if (err)
		return err;

	for_each_ethrxq(s, ethqidx) {
		err = request_irq(adap->msix_info[msi_index].vec,
				  t4_sge_intr_msix, 0,
				  adap->msix_info[msi_index].desc,
				  &s->ethrxq[ethqidx].rspq);
		if (err)
			goto unwind;
		msi_index++;
	}

	if (is_hashfilter(adap) && is_t5(adap->params.chip)) {
		for_each_tracerxq(s, traceqidx) {
			err = request_irq(adap->msix_info[msi_index].vec,
					  t4_sge_intr_msix, 0,
					  adap->msix_info[msi_index].desc,
					  &s->traceq[traceqidx].rspq);
			if (err) {
				printk("%s: got error for traceq[%d].rspq, err = %d\n",
					__func__, traceqidx, err);
				goto unwind;
			}
			msi_index++;
		}
	}

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	for_each_ofldrxq(s, ofldqidx) {
		err = request_irq(adap->msix_info[msi_index].vec,
				  t4_sge_intr_msix, 0,
				  adap->msix_info[msi_index].desc,
				  &s->ofldrxq[ofldqidx].rspq);
		if (err)
			goto unwind;
		msi_index++;
	}
	for_each_rdmarxq(s, rdmaqidx) {
		err = request_irq(adap->msix_info[msi_index].vec,
				  t4_sge_intr_msix, 0,
				  adap->msix_info[msi_index].desc,
				  &s->rdmarxq[rdmaqidx].rspq);
		if (err)
			goto unwind;
		msi_index++;
	}
	for_each_rdmaciq(s, rdmaciqqidx) {
		err = request_irq(adap->msix_info[msi_index].vec,
				  t4_sge_intr_msix, 0,
				  adap->msix_info[msi_index].desc,
				  &s->rdmaciq[rdmaciqqidx].rspq);
		if (err)
			goto unwind;
		msi_index++;
	}
	for_each_iscsirxq(s, iscsiqidx) {
		err = request_irq(adap->msix_info[msi_index].vec,
				  t4_sge_intr_msix, 0,
				  adap->msix_info[msi_index].desc,
				  &s->iscsirxq[iscsiqidx].rspq);
		if (err)
			goto unwind;
		msi_index++;
	}
#ifdef CONFIG_T4_MA_FAILOVER
	if (is_offload(adap)) {
		err = request_irq(adap->msix_info[msi_index].vec, t4_sge_intr_msix, 0,
				  adap->msix_info[msi_index].desc,
				  &s->failoverq.rspq);
		if (err)
			goto unwind;
	}
#endif /* CONFIG_T4_MA_FAILOVER */
#endif

	return 0;

unwind:
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	while (--iscsiqidx >= 0)
		free_irq(adap->msix_info[--msi_index].vec,
			 &s->iscsirxq[iscsiqidx].rspq);
	while (--rdmaciqqidx >= 0)
		free_irq(adap->msix_info[--msi_index].vec,
			 &s->rdmaciq[rdmaciqqidx].rspq);
	while (--rdmaqidx >= 0)
		free_irq(adap->msix_info[--msi_index].vec,
			 &s->rdmarxq[rdmaqidx].rspq);
	while (--ofldqidx >= 0)
		free_irq(adap->msix_info[--msi_index].vec,
			 &s->ofldrxq[ofldqidx].rspq);
#endif
	while (--traceqidx >= 0)
		free_irq(adap->msix_info[--msi_index].vec,
			 &s->traceq[traceqidx].rspq);
	while (--ethqidx >= 0)
		free_irq(adap->msix_info[--msi_index].vec,
			 &s->ethrxq[ethqidx].rspq);
	free_irq(adap->msix_info[1].vec, &s->fw_evtq);
	return err;
}

static void free_msix_queue_irqs(struct adapter *adap)
{
	int i, msi_index = 2;
	struct sge *s = &adap->sge;

	free_irq(adap->msix_info[1].vec, &s->fw_evtq);
	for_each_ethrxq(s, i)
		free_irq(adap->msix_info[msi_index++].vec, &s->ethrxq[i].rspq);
	if (is_hashfilter(adap) && is_t5(adap->params.chip))
		for_each_tracerxq(s, i)
			free_irq(adap->msix_info[msi_index++].vec, &s->traceq[i].rspq);
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	for_each_ofldrxq(s, i)
		free_irq(adap->msix_info[msi_index++].vec, &s->ofldrxq[i].rspq);
	for_each_rdmarxq(s, i)
		free_irq(adap->msix_info[msi_index++].vec, &s->rdmarxq[i].rspq);
	for_each_rdmaciq(s, i)
		free_irq(adap->msix_info[msi_index++].vec, &s->rdmaciq[i].rspq);
	for_each_iscsirxq(s, i)
		free_irq(adap->msix_info[msi_index++].vec,
			 &s->iscsirxq[i].rspq);
#ifdef CONFIG_T4_MA_FAILOVER
	if (is_offload(adap))
		free_irq(adap->msix_info[msi_index].vec, &s->failoverq.rspq);
#endif /* CONFIG_T4_MA_FAILOVER */
#endif
}

/**
 *	cxgb4_write_rss - write the RSS table for a given port
 *	@pi: the port
 *	@queues: array of queue indices for RSS
 *
 *	Sets up the portion of the HW RSS table for the port's VI to distribute
 *	packets to the Rx queues in @queues.
 *	Should never be called before setting up sge eth rx queues
 */
int cxgb4_write_rss(const struct port_info *pi, const u16 *queues)
{
	u16 *rss;
	int i, err;
	struct adapter *adapter = pi->adapter;
	const struct sge_eth_rxq *rxq;

	rxq = &adapter->sge.ethrxq[pi->first_qset];
	rss = kmalloc(pi->rss_size * sizeof(u16), GFP_KERNEL);
	if (!rss)
		return -ENOMEM;

	/* map the queue indices to queue ids */
	for (i = 0; i < pi->rss_size; i++, queues++)
		rss[i] = rxq[*queues].rspq.abs_id;

	err = t4_config_rss_range(adapter, adapter->pf, pi->viid, 0,
				  pi->rss_size, rss, pi->rss_size);
	/* If Tunnel All Lookup isn't specified in the global RSS
	 * Configuration, then we need to specify a default Ingress
	 * Queue for any ingress packets which aren't hashed.  We'll
	 * use our first ingress queue ...
	 */
	if (!err)
		err = t4_config_vi_rss(adapter, adapter->mbox, pi->viid,
				       F_FW_RSS_VI_CONFIG_CMD_IP6FOURTUPEN |
				       F_FW_RSS_VI_CONFIG_CMD_IP6TWOTUPEN |
				       F_FW_RSS_VI_CONFIG_CMD_IP4FOURTUPEN |
				       F_FW_RSS_VI_CONFIG_CMD_IP4TWOTUPEN |
				       F_FW_RSS_VI_CONFIG_CMD_UDPEN,
				       rss[0]);
	kfree(rss);
	return err;
}

/**
 *	setup_rss - configure RSS
 *	@adap: the adapter
 *
 *	Sets up RSS to distribute packets to multiple receive queues.  We
 *	configure the RSS CPU lookup table to distribute to the number of HW
 *	receive queues, and the response queue lookup table to narrow that
 *	down to the response queues actually configured for each port.
 *	We always configure the RSS mapping for all ports since the mapping
 *	table has plenty of entries.
 */
static int setup_rss(struct adapter *adap)
{
	int i, j, err;
#ifdef CONFIG_PO_FCOE
	u32 rss_config;
#endif

	for_each_port(adap, i) {
		const struct port_info *pi = adap2pinfo(adap, i);

		/* Fill default values with equal distribution */
		for (j = 0; j < pi->rss_size; j++)
			pi->rss[j] = j % pi->nqsets;

		err = cxgb4_write_rss(pi, pi->rss);
		if (err)
			return err;
	}

#ifdef CONFIG_PO_FCOE
	rss_config = t4_read_reg(adap, A_TP_RSS_CONFIG);
	rss_config |= F_TNLFCOEEN | F_TNLFCOEMODE;
	t4_write_reg(adap, A_TP_RSS_CONFIG, rss_config);
#endif
	return 0;
}

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
/*
 * Return the channel of the ingress queue with the given qid.
 */
static unsigned int rxq_to_chan(const struct sge *p, unsigned int qid)
{
	qid -= p->ingr_start;
	return netdev2pinfo(p->ingr_map[qid]->netdev)->tx_chan;
}
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

/*
 * Wait until all NAPI handlers are descheduled.
 */
static void quiesce_rx(struct adapter *adap)
{
	int i;

	for (i = 0; i < adap->sge.ingr_sz; i++) {
		struct sge_rspq *q = adap->sge.ingr_map[i];

		if (q && q->handler) {
			napi_disable(&q->napi);
			local_bh_disable();
			while (!cxgb_poll_lock_napi(q))
				mdelay(1);
			local_bh_enable();
		}

	}
}

/* Disable interrupt and napi handler */
static void disable_interrupts(struct adapter *adap)
{
	if (adap->flags & FULL_INIT_DONE) {
		t4_intr_disable(adap);
		if (adap->flags & USING_MSIX) {
			free_msix_queue_irqs(adap);
			free_irq(adap->msix_info[0].vec, adap);
		} else {
			free_irq(adap->pdev->irq, adap);
		}
	}
}

/*
 * Enable NAPI scheduling and interrupt generation for all Rx queues.
 */
static void enable_rx(struct adapter *adap)
{
	int i;

	for (i = 0; i < adap->sge.ingr_sz; i++) {
		struct sge_rspq *q = adap->sge.ingr_map[i];

		if (!q)
			continue;
		if (q->handler) {
			cxgb_busy_poll_init_lock(q);
			napi_enable(&q->napi);
		}
		/* 0-increment GTS to start the timer and enable interrupts */
		t4_write_reg(adap, MYPF_REG(A_SGE_PF_GTS),
			     V_SEINTARM(q->intr_params) |
			     V_INGRESSQID(q->cntxt_id));
	}
}

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
static int alloc_ofld_rxqs(struct adapter *adap, struct sge_ofld_rxq *q,
			   unsigned int nq, unsigned int per_chan, int msi_idx,
			   u16 *ids, u8 lro)
{
	int i, err;

	for (i = 0; i < nq; i++, q++) {
		if (msi_idx > 0)
			msi_idx++;
		err = t4_sge_alloc_rxq(adap, &q->rspq, false,
				       adap->port[i / per_chan],
				       msi_idx, q->fl.size ? &q->fl : NULL,
				       uldrx_handler,
				       lro ? uldrx_flush_handler : NULL, 0);
		if (err)
			return err;
		memset(&q->stats, 0, sizeof(q->stats));
		if (ids)
			ids[i] = q->rspq.abs_id;
	}
	return 0;
}
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

/**
 *	setup_sge_queues - configure SGE Tx/Rx/response queues
 *	@adap: the adapter
 *
 *	Determines how many sets of SGE queues to use and initializes them.
 *	We support multiple queue sets per port if we have MSI-X, otherwise
 *	just one queue set per port.
 */
static int setup_sge_queues(struct adapter *adap)
{
	int err, msi_idx, i, j;
	struct sge *s = &adap->sge;

	bitmap_zero(s->starving_fl, s->egr_sz);
	bitmap_zero(s->txq_maperr, s->egr_sz);

	if (adap->flags & USING_MSIX)
		msi_idx = 1;         /* vector 0 is for non-queue interrupts */
	else {
		err = t4_sge_alloc_rxq(adap, &s->intrq, false, adap->port[0], 0,
				       NULL, NULL, NULL, -1);
		if (err)
			return err;
		msi_idx = -((int)s->intrq.abs_id + 1);
	}

	/* NOTE: If you add/delete any Ingress/Egress Queue allocations in here,
	 * don't forget to update the following which need to be
	 * synchronized to and changes here.
	 *
	 * 1. The calculations of MAX_INGQ in adapter.h.
	 *
	 * 2. Update cxgb_enable_msix/name_msix_vecs/request_msix_queue_irqs
	 *    to accommodate any new/deleted Ingress Queues
	 *    which need MSI-X Vectors.
	 *
	 * 3. Update sge_qinfo_show() to include information on the
	 *    new/deleted queues.
	 */
	err = t4_sge_alloc_rxq(adap, &s->fw_evtq, true, adap->port[0],
			       msi_idx, NULL, fwevtq_handler, NULL, -1);
	if (err) {
freeout:	t4_free_sge_resources(adap);
		return err;
	}

	for_each_port(adap, i) {
		struct net_device *dev = adap->port[i];
		struct port_info *pi = netdev_priv(dev);
		struct sge_eth_rxq *q = &s->ethrxq[pi->first_qset];
		struct sge_eth_txq *t = &s->ethtxq[pi->first_qset];

		for (j = 0; j < pi->nqsets; j++, q++) {
			if (msi_idx > 0)
				msi_idx++;
			err = t4_sge_alloc_rxq(adap, &q->rspq, false, dev,
					       msi_idx, &q->fl,
					       t4_ethrx_handler, NULL,
					       t4_get_mps_bg_map(adap,
								 pi->tx_chan));
			if (err)
				goto freeout;
			q->rspq.idx = j;
			memset(&q->stats, 0, sizeof(q->stats));
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
			memset(&q->hdr_buf, 0, sizeof(q->hdr_buf));
			if (is_t5(adap->params.chip))
				refill_vxlan_hdr_buf(adap, q, GFP_KERNEL);
#endif
		}
		for (j = 0; j < pi->nqsets; j++, t++) {
			err = t4_sge_alloc_eth_txq(adap, t, dev,
					netdev_get_tx_queue(dev, j),
					s->fw_evtq.cntxt_id);
			if (err)
				goto freeout;
		}
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
		if (is_t5(adap->params.chip)) {
			struct netdev_queue *netdevq;
			unsigned int iqid;

			t = &s->vxlantxq[pi->first_qset];
			iqid = s->fw_evtq.cntxt_id;

			/* Create a transmit queue to loopback vxlan packets
			 * for verifying checksum. We will create as many
			 * vxlan txqs as we have regular ethernet rxqs.
			 */
			s->nvxlanq += pi->nqsets;
			for (j = 0; j < pi->nqsets; j++, t++) {
				netdevq = netdev_get_tx_queue(dev, j);
				err = t4_sge_alloc_eth_txq(adap, t, dev,
							   netdevq, iqid);
				if (err)
					goto freeout;
				t->q.is_vxlan_lb = 1;
			}
		}
#endif
	}

	if (is_hashfilter(adap) && is_t5(adap->params.chip)) {
		j = s->ntraceq / adap->params.nports;
		for_each_tracerxq(s, i) {
			err = t4_sge_alloc_rxq(adap, &(s->traceq[i].rspq),
					       false,
					       adap->port[j ? (i / j) : i],
					       ++msi_idx, &(s->traceq[i].fl),
					       t4_trace_handler, NULL, 0);
			if (err)
				goto freeout;
			memset(&s->traceq[i].stats, 0, sizeof(s->traceq[i].stats));
		}
	}

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	j = s->ofldqsets / adap->params.nports; /* ofld queues per channel */
	for_each_ofldrxq(s, i) {
		err = t4_sge_alloc_ofld_txq(adap, &s->ofldtxq[i],
					    adap->port[i / j],
					    s->fw_evtq.cntxt_id);
		if (err)
			goto freeout;
	}

#define ALLOC_OFLD_RXQS(firstq, nq, per_chan, ids, lro) do { \
	err = alloc_ofld_rxqs(adap, firstq, nq, per_chan, msi_idx, ids, lro); \
	if (err) \
		goto freeout; \
	if (msi_idx > 0) \
		msi_idx += nq; \
} while (0)

	/* LRO is enabled only for TOE queues */
	ALLOC_OFLD_RXQS(s->ofldrxq, s->ofldqsets, j, s->ofld_rxq, 1);
	j = s->rdmaqs / adap->params.nports;
	ALLOC_OFLD_RXQS(s->rdmarxq, s->rdmaqs, j, s->rdma_rxq, 0);
	j = s->rdmaciqs / adap->params.nports; /* rdmaq queues per channel */
	ALLOC_OFLD_RXQS(s->rdmaciq, s->rdmaciqs, j, s->rdma_ciq, 0);
	j = s->niscsiq / adap->params.nports;
	ALLOC_OFLD_RXQS(s->iscsirxq, s->niscsiq, j, s->iscsi_rxq, 1);

#undef ALLOC_OFLD_RXQS

#ifdef CONFIG_T4_MA_FAILOVER
	if (is_offload(adap)) {
		err = t4_sge_alloc_rxq(adap, &(s->failoverq.rspq), false, adap->port[0],
				       ++msi_idx, &(s->failoverq.fl),
				       uldma_failover_handler, NULL,
				       0);
		if (err)
			goto freeout;
		memset(&s->failoverq.stats, 0, sizeof(s->failoverq.stats));
	}
#endif /* CONFIG_T4_MA_FAILOVER */
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

	for_each_port(adap, i) {
		/*
		 * Note that ->rdmarxq[i].rspq.cntxt_id below is 0 if we don't
		 * have RDMA queues, and that's the right value.
		 */
		err = t4_sge_alloc_ctrl_txq(adap, &s->ctrlq[i], adap->port[i],
					    s->fw_evtq.cntxt_id,
					    s->rdmarxq[i].rspq.cntxt_id);
		if (err)
			goto freeout;
	}
#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
	if (!is_t4(adap->params.chip)) {
		err = t4_sge_alloc_eth_txq(adap, &s->ptptxq, adap->port[0],
					   netdev_get_tx_queue(adap->port[0],
							       0),
					   s->fw_evtq.cntxt_id);
		if (err)
			goto freeout;
	}
#endif

	t4_write_reg(adap, is_t4(adap->params.chip) ?
				 A_MPS_TRC_RSS_CONTROL :
				 A_MPS_T5_TRC_RSS_CONTROL,
		     V_RSSCONTROL(netdev2pinfo(adap->port[0])->tx_chan) |
		     V_QUEUENUMBER(s->ethrxq[0].rspq.abs_id));
	return 0;
}

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
static int setup_loopback(struct adapter *adap)
{
	int i, err;
	u8 mac0[] = { 0, 0, 0, 0, 0, 0 };

	for_each_port(adap, i) {
		err = t4_change_mac(adap, adap->mbox, adap2pinfo(adap, i)->viid,
				    -1, mac0, true, false);
		if (err < 0)
			return err;
	}
	return 0;
}
#endif

/*
 * Allocate a chunk of memory using kmalloc or, if that fails, vmalloc.
 * The allocated memory is cleared.
 */
void *t4_alloc_mem(size_t size)
{
	void *p = kzalloc(size, GFP_KERNEL | __GFP_NOWARN);

	if (!p)
		p = vzalloc(size);
	return p;
}

/*
 * Free memory allocated through alloc_mem().
 */
void t4_free_mem(void *addr)
{
	if (is_vmalloc_addr(addr))
		vfree(addr);
	else
		kfree(addr);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
static u16 cxgb_select_queue(struct net_device *dev, struct sk_buff *skb)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
static u16 cxgb_select_queue(struct net_device *dev, struct sk_buff *skb,
			     void *accel_priv)
#else
static u16 cxgb_select_queue(struct net_device *dev, struct sk_buff *skb,
			     void *accel_priv, select_queue_fallback_t fallback)
#endif
{
	int txq;

#ifdef CONFIG_CXGB4_DCB
	/* If a Data Center Bridging has been successfully negotiated on this
	 * link then we'll use the skb's priority to map it to a TX Queue.
	 * The skb's priority is determined via the VLAN Tag Priority Code
	 * Point field.
	 */
	if (cxgb4_dcb_enabled(dev)) {
		if (unlikely(!skb_vlan_tag_present(skb))) {
			if (printk_ratelimit()) {
				struct adapter *adap = netdev2adap(dev);

				dev_warn(adap->pdev_dev,
					 "TX Packet without "
					 "VLAN Tag on DCB Link\n");
			}
			txq = 0;
		} else {
			u16 vlan_tci = skb_vlan_tag_get(skb);
			txq = (vlan_tci & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT;
#ifdef CONFIG_PO_FCOE
			if (skb->protocol == htons(ETH_P_FCOE))
				txq = skb->priority & 0x7;
#endif /* CONFIG_PO_FCOE */
		}
		return txq;
	}
#endif /* CONFIG_CXGB4_DCB */

	if (select_queue) {
		txq = (skb_rx_queue_recorded(skb)
			? skb_get_rx_queue(skb)
			: smp_processor_id());

		while (unlikely(txq >= dev->real_num_tx_queues))
			txq -= dev->real_num_tx_queues;

		return txq;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
	return skb_tx_hash(dev, skb);
#else
	return fallback(dev, skb) % dev->real_num_tx_queues;
#endif
}

static struct net_device_stats *cxgb_get_stats(struct net_device *dev)
{
	struct port_stats stats;
	struct port_info *p = netdev_priv(dev);
	struct adapter *adapter = p->adapter;
	struct net_device_stats *ns = &dev->stats;

	/* Block retrieving statistics during EEH error
	 * recovery. Otherwise, the recovery might fail
	 * and the PCI device will be removed permanently
	 */
	spin_lock(&adapter->stats_lock);
	if (!netif_device_present(dev)) {
		spin_unlock(&adapter->stats_lock);
		return ns;
	}
	t4_get_port_stats_offset(adapter, p->tx_chan, &stats,
				 &p->stats_base);
	spin_unlock(&adapter->stats_lock);

	ns->tx_bytes   = stats.tx_octets;
	ns->tx_packets = stats.tx_frames;
	ns->rx_bytes   = stats.rx_octets;
	ns->rx_packets = stats.rx_frames;
	ns->multicast  = stats.rx_mcast_frames;

	/* detailed rx_errors */
	ns->rx_length_errors = stats.rx_jabber + stats.rx_too_long +
			       stats.rx_runt;
	ns->rx_over_errors   = 0;
	ns->rx_crc_errors    = stats.rx_fcs_err;
	ns->rx_frame_errors  = stats.rx_symbol_err;
	ns->rx_fifo_errors   = stats.rx_ovflow0 + stats.rx_ovflow1 +
			       stats.rx_ovflow2 + stats.rx_ovflow3 +
			       stats.rx_trunc0 + stats.rx_trunc1 +
			       stats.rx_trunc2 + stats.rx_trunc3;
	ns->rx_missed_errors = 0;

	/* detailed tx_errors */
	ns->tx_aborted_errors   = 0;
	ns->tx_carrier_errors   = 0;
	ns->tx_fifo_errors      = 0;
	ns->tx_heartbeat_errors = 0;
	ns->tx_window_errors    = 0;

	ns->tx_errors = stats.tx_error_frames;
	ns->rx_errors = stats.rx_symbol_err + stats.rx_fcs_err +
		ns->rx_length_errors + stats.rx_len_err + ns->rx_fifo_errors;
	return ns;
}

int cxgb4_closest_timer(const struct sge *s, int time)
{
	int i, delta, match = 0, min_delta = INT_MAX;

	for (i = 0; i < ARRAY_SIZE(s->timer_val); i++) {
		delta = time - s->timer_val[i];
		if (delta < 0)
			delta = -delta;
		if (delta < min_delta) {
			min_delta = delta;
			match = i;
		}
	}
	return match;
}

static int closest_thres(const struct sge *s, int thres)
{
	int i, delta, match = 0, min_delta = INT_MAX;

	for (i = 0; i < ARRAY_SIZE(s->counter_val); i++) {
		delta = thres - s->counter_val[i];
		if (delta < 0)
			delta = -delta;
		if (delta < min_delta) {
			min_delta = delta;
			match = i;
		}
	}
	return match;
}

/**
 *	cxgb4_set_rspq_intr_params - set a queue's interrupt holdoff parameters
 *	@q: the Rx queue
 *	@us: the hold-off time in us, or 0 to disable timer
 *	@cnt: the hold-off packet count, or 0 to disable counter
 *
 *	Sets an Rx queue's interrupt hold-off time and packet count.  At least
 *	one of the two needs to be enabled for the queue to generate interrupts.
 */
int cxgb4_set_rspq_intr_params(struct sge_rspq *q,
			       unsigned int us, unsigned int cnt)
{
	struct adapter *adap = q->adap;

	if ((us | cnt) == 0)
		cnt = 1;

	if (cnt) {
		int err;
		u32 v, new_idx;

		new_idx = closest_thres(&adap->sge, cnt);
		if (q->desc && q->pktcnt_idx != new_idx) {
			/* the queue has already been created, update it */
			v = V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DMAQ) |
			    V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DMAQ_IQ_INTCNTTHRESH) |
			    V_FW_PARAMS_PARAM_YZ(q->cntxt_id);
			err = t4_set_params(adap, adap->mbox, adap->pf, 0, 1,
					    &v, &new_idx);
			if (err)
				return err;
		}
		q->pktcnt_idx = new_idx;
	}

	us = us == 0 ? X_TIMERREG_RESTART_COUNTER : cxgb4_closest_timer(&adap->sge, us);
	q->intr_params = V_QINTR_TIMER_IDX(us) | V_QINTR_CNT_EN(cnt > 0);

	return 0;
}

/*
 * offload upper-layer driver support
 */

/*
 * Allocate an active-open TID and set it to the supplied value.
 */
int cxgb4_alloc_atid(struct tid_info *t, void *data)
{
	int atid = -1;

	spin_lock_bh(&t->atid_lock);
	if (t->afree) {
		union aopen_entry *p = t->afree;

		atid = p - t->atid_tab;
		t->afree = p->next;
		p->data = data;
		t->atids_in_use++;
	}
	spin_unlock_bh(&t->atid_lock);
	return atid;
}
EXPORT_SYMBOL(cxgb4_alloc_atid);

/*
 * Release an active-open TID.
 */
void cxgb4_free_atid(struct tid_info *t, unsigned int atid)
{
	union aopen_entry *p = &t->atid_tab[atid];

	spin_lock_bh(&t->atid_lock);
	p->next = t->afree;
	t->afree = p;
	t->atids_in_use--;
	spin_unlock_bh(&t->atid_lock);
}
EXPORT_SYMBOL(cxgb4_free_atid);

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
#include <net/offload.h>
#include "cxgb4_ctl_defs.h"
/*
 * Allocate a UO TID and set it to the supplied value.
 */
int cxgb4_alloc_uotid(struct tid_info *t, void *data)
{
	int uotid;

	spin_lock_bh(&t->uotid_lock);
	uotid = find_first_zero_bit(t->uotid_bmap, t->nuotids);
	if (uotid < t->nuotids)
		__set_bit(uotid, t->uotid_bmap);
	else
		uotid = -1;

	if (uotid >= 0) {
		t->uotid_tab[uotid].data = data;
		uotid += t->uotid_base;
		t->uotids_in_use++;
	}
	spin_unlock_bh(&t->uotid_lock);
	return uotid;
}
EXPORT_SYMBOL(cxgb4_alloc_uotid);

/*
 * Release a server TID.
 */
void cxgb4_free_uotid(struct tid_info *t, unsigned int uotid)
{
	uotid -= t->uotid_base;
	spin_lock_bh(&t->uotid_lock);
	__clear_bit(uotid, t->uotid_bmap);
	t->uotid_tab[uotid].data = NULL;
	t->uotids_in_use--;
	spin_unlock_bh(&t->uotid_lock);
}
EXPORT_SYMBOL(cxgb4_free_uotid);

/*
 * Allocate a server TID and set it to the supplied value.
 */
int cxgb4_alloc_stid(struct tid_info *t, int family, void *data)
{
	int stid;

	spin_lock_bh(&t->stid_lock);
	if (family == PF_INET) {
		stid = find_first_zero_bit(t->stid_bmap, t->nstids);
		if (stid < t->nstids)
			__set_bit(stid, t->stid_bmap);
		else
			stid = -1;
	} else {
		stid = bitmap_find_free_region(t->stid_bmap, t->nstids, 1);
		if (stid < 0)
			stid = -1;
	}
	if (stid >= 0) {
		t->stid_tab[stid].data = data;
		stid += t->stid_base;
		/* IPv6 requires max of 520 bits or 16 cells in TCAM
		 * This is equivalent to 4 TIDs. With CLIP enabled it
		 * needs 2 TIDs.
		 */
		if (family == PF_INET6) {
			t->stids_in_use += 2;
			t->v6_stids_in_use += 2;
		} else
			t->stids_in_use++;
	}
	spin_unlock_bh(&t->stid_lock);
	return stid;
}
EXPORT_SYMBOL(cxgb4_alloc_stid);

/* Allocate a server filter TID and set it to the supplied value.
 */
int cxgb4_alloc_sftid(struct tid_info *t, int family, void *data)
{
	int stid;

	spin_lock_bh(&t->stid_lock);
	if (family == PF_INET) {
		stid = find_next_zero_bit(t->stid_bmap,
				t->nstids + t->nsftids, t->nstids);
		if (stid < (t->nstids + t->nsftids))
			__set_bit(stid, t->stid_bmap);
		else
			stid = -1;
	} else {
		stid = -1;
	}
	if (stid >= 0) {
		t->stid_tab[stid].data = data;
		stid -= t->nstids;
		stid += t->sftid_base;
		t->sftids_in_use++;
	}
	spin_unlock_bh(&t->stid_lock);
	return stid;
}
EXPORT_SYMBOL(cxgb4_alloc_sftid);

/* Release a server TID.
 */
void cxgb4_free_stid(struct tid_info *t, unsigned int stid, int family)
{
	/* Is it a server filter TID? */
	if (t->nsftids && (stid >= t->sftid_base)) {
		stid -= t->sftid_base;
		stid += t->nstids;
	} else {
		stid -= t->stid_base;
	}

	spin_lock_bh(&t->stid_lock);
	if (family == PF_INET)
		__clear_bit(stid, t->stid_bmap);
	else
		bitmap_release_region(t->stid_bmap, stid, 1);
	t->stid_tab[stid].data = NULL;
	if (stid < t->nstids) {
		if (family == PF_INET6) {
			t->stids_in_use -= 2;
			t->v6_stids_in_use -= 2;
		} else
			t->stids_in_use--;
	} else {
		t->sftids_in_use--;
	}
	spin_unlock_bh(&t->stid_lock);
}
EXPORT_SYMBOL(cxgb4_free_stid);
#endif

/*
 * Populate a TID_RELEASE WR.  Caller must properly size the skb.
 */
static void mk_tid_release(struct sk_buff *skb, unsigned int chan,
			   unsigned int tid)
{
	struct cpl_tid_release *req;

	set_wr_txq(skb, CPL_PRIORITY_SETUP, chan);
	req = (struct cpl_tid_release *)__skb_put(skb, sizeof(*req));
	INIT_TP_WR_MIT_CPL(req, CPL_TID_RELEASE, tid);
}

/*
 * Queue a TID release request and if necessary schedule a work queue to
 * process it.
 */
static void cxgb4_queue_tid_release(struct tid_info *t, unsigned int chan,
				    unsigned int tid)
{
	void **p = &t->tid_tab[tid];
	struct adapter *adap = container_of(t, struct adapter, tids);

	spin_lock_bh(&adap->tid_release_lock);
	*p = adap->tid_release_head;
	/* Low 2 bits encode the Tx channel number */
	adap->tid_release_head = (void **)((uintptr_t)p | chan);
	if (!*p)
		queue_work(adap->workq, &adap->tid_release_task);
	spin_unlock_bh(&adap->tid_release_lock);
}

/*
 * Process the list of pending TID release requests.
 */
static void process_tid_release_list(struct work_struct *work)
{
	struct sk_buff *skb;
	struct adapter *adap;

	adap = container_of(work, struct adapter, tid_release_task);

	spin_lock_bh(&adap->tid_release_lock);
	while (adap->tid_release_head) {
		void **p = adap->tid_release_head;
		unsigned int chan = (uintptr_t)p & 3;
		p = (void *)p - chan;

		adap->tid_release_head = *p;
		*p = NULL;
		spin_unlock_bh(&adap->tid_release_lock);

		while (!(skb = alloc_skb(sizeof(struct cpl_tid_release),
					 GFP_KERNEL)))
			yield();

		mk_tid_release(skb, chan, p - adap->tids.tid_tab);
		t4_ofld_send(adap, skb);
		spin_lock_bh(&adap->tid_release_lock);
	}
	spin_unlock_bh(&adap->tid_release_lock);
}

/*
 * Release a TID and inform HW.  If we are unable to allocate the release
 * message we defer to a work queue.
 */
void cxgb4_remove_tid(struct tid_info *t, unsigned int chan, unsigned int tid,
		      unsigned short family)
{
	struct sk_buff *skb;
	struct adapter *adap = container_of(t, struct adapter, tids);

	WARN_ON(tid >= t->ntids);

	if (t->tid_tab[tid]) {
		t->tid_tab[tid] = NULL;
		atomic_dec(&t->conns_in_use);
		if (t->hash_base && (tid >= t->hash_base)) {
			if (family == AF_INET6)
				atomic_sub(2, &t->hash_tids_in_use);
			else
				atomic_dec(&t->hash_tids_in_use);
		} else {
			if (family == AF_INET6)
				atomic_sub(2, &t->tids_in_use);
			else
				atomic_dec(&t->tids_in_use);
		}
	}

	skb = alloc_skb(sizeof(struct cpl_tid_release), GFP_ATOMIC);
	if (likely(skb)) {
		mk_tid_release(skb, chan, tid);
		t4_ofld_send(adap, skb);
	} else
		cxgb4_queue_tid_release(t, chan, tid);
}
EXPORT_SYMBOL(cxgb4_remove_tid);

/*
 * Allocate and initialize the TID tables.  Returns 0 on success.
 */
static int tid_init(struct tid_info *t)
{
	size_t size;
	unsigned int stid_bmap_size;
	unsigned int uotid_bmap_size;
	unsigned int ftid_bmap_size;
	unsigned int hpftid_bmap_size;
	unsigned int natids = t->natids;
	unsigned int max_ftids = t->nftids + t->nsftids + t->nhpftids;
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	struct adapter *adap = container_of(t, struct adapter, tids);
#endif

	stid_bmap_size = BITS_TO_LONGS(t->nstids + t->nsftids);
	uotid_bmap_size = BITS_TO_LONGS(t->nuotids);
	ftid_bmap_size = BITS_TO_LONGS(t->nftids);
	hpftid_bmap_size = BITS_TO_LONGS(t->nhpftids);
	size = t->ntids * sizeof(*t->tid_tab) +
	       natids * sizeof(*t->atid_tab) +
	       t->nstids * sizeof(*t->stid_tab) +
	       t->nsftids * sizeof(*t->stid_tab) +
	       stid_bmap_size * sizeof(long) +
	       uotid_bmap_size * sizeof(long) +
	       max_ftids * sizeof(*t->ftid_tab) +
	       ftid_bmap_size * sizeof(long) +
	       hpftid_bmap_size * sizeof(long) +
	       t->nuotids * sizeof(*t->uotid_tab);

	t->tid_tab = t4_alloc_mem(size);
	if (!t->tid_tab)
		return -ENOMEM;

	t->atid_tab = (union aopen_entry *)&t->tid_tab[t->ntids];
	t->stid_tab = (struct serv_entry *)&t->atid_tab[natids];
	t->stid_bmap = (unsigned long *)&t->stid_tab[t->nstids + t->nsftids];

	/* We will store normal as well as hi priority filters in this same
	 * structure pointed by ftid_tab. For T5, normal and hi prio filters
	 * can be stored anywhere in this structure. For T6, we will enforce
	 * the user to create hi prio filters at lower index followed by normal
	 * filters. We will still maintain separate bitmaps for normal and
	 * hi priotiry filters.
	 */
	t->ftid_tab = (struct filter_entry *)&t->stid_bmap[stid_bmap_size];
	t->ftid_bmap = (unsigned long *)&t->ftid_tab[max_ftids];
	t->hpftid_bmap = (unsigned long *)&t->ftid_bmap[ftid_bmap_size];
	t->uotid_tab = (struct uoconn_entry *)&t->hpftid_bmap[hpftid_bmap_size];
	t->uotid_bmap = (unsigned long *)&t->uotid_tab[t->nuotids];
	spin_lock_init(&t->stid_lock);
	spin_lock_init(&t->atid_lock);
	spin_lock_init(&t->uotid_lock);
	spin_lock_init(&t->ftid_lock);

	t->stids_in_use = 0;
	t->v6_stids_in_use = 0;
	t->sftids_in_use = 0;
	t->afree = NULL;
	t->atids_in_use = 0;
	t->uotids_in_use = 0;
	atomic_set(&t->tids_in_use, 0);
	atomic_set(&t->conns_in_use, 0);
	atomic_set(&t->hash_tids_in_use, 0);

	/* Setup the free list for atid_tab and clear the stid bitmap. */
	if (natids) {
		while (--natids)
			t->atid_tab[natids - 1].next = &t->atid_tab[natids];
		t->afree = t->atid_tab;
	}

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	bitmap_zero(t->stid_bmap, t->nstids + t->nsftids);
	/* Reserve stid 0 for T4/T5 adapters */
	if (!t->stid_base &&
	    (CHELSIO_CHIP_VERSION(adap->params.chip) <= CHELSIO_T5))
		__set_bit(0, t->stid_bmap);

	/* Reserve last sftid for default-rule filter */
	if (t->nsftids)
		__set_bit(t->nstids + t->nsftids - 1, t->stid_bmap);

	bitmap_zero(t->uotid_bmap, t->nuotids);
#endif
	bitmap_zero(t->ftid_bmap, t->nftids);
	return 0;
}

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
/**
 *	cxgb4_create_filter_info - return Compressed Filter Value/Mask tuple
 *	@adapter: the adapter
 *	@filter_value: Filter Value return value pointer
 *	@filter_mask: Filter Mask return value pointer
 *	@fcoe: FCoE filter selection
 *	@port: physical port filter selection
 *	@vnic: Virtual NIC ID filter selection
 *	@vlan: VLAN ID filter selection
 *	@vlan_pcp: VLAN Priority Code Point filter selection
 *	@vlan_dei: VLAN Drop Eligibility Indicator filter selection
 *	@tos: Type Of Server filter selection
 *	@protocol: IP Protocol filter selection
 *	@ethertype: Ethernet Type filter selection
 *	@macmatch: MPS MAC Index filter selection
 *	@matchtype: MPS Hit Type filter selection
 *	@frag: IP Fragmentation filter selection
 *
 *	Exported Symbold front end to the Common Code t4_create_filter_info()
 *	API.  On error, returns a negative error code.  On success, returns 0
 *	and Filter Value/Mask Tuple given the various file field selections.
 */
int cxgb4_create_filter_info(const struct adapter *adapter,
			     u64 *filter_value, u64 *filter_mask,
			     int fcoe, int port, int vnic,
			     int vlan, int vlan_pcp, int vlan_dei,
			     int tos, int protocol, int ethertype,
			     int macmatch, int matchtype, int frag)
{
	return t4_create_filter_info(adapter,
				     filter_value, filter_mask,
				     fcoe, port, vnic,
				     vlan, vlan_pcp, vlan_dei,
				     tos, protocol, ethertype,
				     macmatch, matchtype, frag);
}
EXPORT_SYMBOL(cxgb4_create_filter_info);

/**
 *	cxgb4_create_server_restricted - create a "restricted" IPv4 server
 *	@dev: the device
 *	@stid: the server TID
 *	@sip: local IP address to bind server to
 *	@sport: the server's TCP port
 *	@filter_value: Filter Value
 *	@filter_mask: Filter Mask
 *	@queue: queue to which to direct messages from this server
 *
 *	Creates an IPv4 Server for the given TCP Port and IPv4 Local
 *	Address.  (The Local end of a listening socket are often referred to
 *	as the "Source" for odd historical reasons.)
 *
 *	The Server entry is rewritten with the specified Filter Value/Mask
 *	tuple in order to restrict the incoming SYNs to which the Server
 *	Entry will match (and thus respond).  This uses the extended "Filter
 *	Information" capabilities of Server Control Blocks (SCB).  (See
 *	"Classification and Filtering" in the Data Book for a description
 *	of Ingress Packet pattern matching capabilities.  See also
 *	documentation on the TP_VLAN_PRI_MAP register.)
 *
 *	Returns <0 on error and one of the %NET_XMIT_* values on success.
 */
int cxgb4_create_server_restricted(const struct net_device *dev,
				   unsigned int stid,
				   __be32 sip, __be16 sport,
				   __u64 filter_value, __u64 filter_mask,
				   unsigned int queue)
{
	struct adapter *adap = netdev2adap(dev);
	unsigned int chan = rxq_to_chan(&adap->sge, queue);
	struct sk_buff *skb;
	unsigned int chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);
	int ret, i;

	/*
	 * We need to program the extended Filter Information for our
	 * Listening Server.  Unfortunately the Passive Open Request CPL only
	 * lets us program the "value" portion of the extended Filter
	 * Information which is stored in the LE TCAM for the Listening Server
	 * ... and programs the "mask" portion to 0 ... which doesn't do
	 * anyone any good.  So we have to send in the Passive Open Request
	 * _and_ several Set LE CPLs to completely reprogram the LE TCAM line
	 * associated with the Listening Server (the LE TCAM doesn't support
	 * partial writes).
	 *
	 * Since each Set LE TCAM CPL can write 128 bits and since an IPv4 LE
	 * TCAM Entry is 132 bits for T4 (136 for T5 and later), we need 2 Set
	 * LE TCAM CPLs.  We accomplish this by wrapping all of the messages
	 * in a Firmware ULP TX Work Request with the "atomic" bit set ...
	 *
	 * Note that each ULP_TXPKT wrapped CPL needs to be an integral number
	 * of 16-byte units ...
	 *
	 * Also note that the embedded CPLs are _only_ the CPLs themselves and
	 * do _not_ include the firmware Work Request Headers.  This is very
	 * awkward given the data structure definitions in t4_msg.h so we have
	 * to play some games here ...
	 */
	struct pass_open_req_ulp_txpkt {
		struct ulp_txpkt	ulptx;
		struct ulptx_idata	sc;
		char			req[sizeof(struct cpl_pass_open_req) -
					    sizeof(struct work_request_hdr)];
	} __aligned(16);

	struct set_le_req_ulp_txpkt {
		struct ulp_txpkt	ulptx;
		struct ulptx_idata	sc;
		char			req[sizeof(struct cpl_set_le_req) -
					    sizeof(struct work_request_hdr)];
	} __aligned(16);

	/* The number of 128-bit Set LE TCAM CPLs needed for IPv6 */
	#define SETLE128_IPV4 DIV_ROUND_UP(132, 128) /* match LE_SZ_132 */
	struct atomic_pass_open_req {
		struct fw_ulptx_wr		ulptx_wr;
		struct pass_open_req_ulp_txpkt	pass_open;
		struct set_le_req_ulp_txpkt	set_le[SETLE128_IPV4];
	} *req;

	struct cpl_pass_open_req *popenr;
	struct cpl_set_le_req *setler[SETLE128_IPV4];
	int reqlen = sizeof(*req);

	/*
	 * Allocate an skb large enough to hold our atomic request.
	 */
	skb = alloc_skb(reqlen, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	req = (struct atomic_pass_open_req *)__skb_put(skb, reqlen);
	memset(req, 0, reqlen);

	/*
	 * Initialize the Firmware ULP TX Work Request and all of the ULP
	 * TX Packet routing messages ...
	 */
	req->ulptx_wr.op_to_compl =
		cpu_to_be32(V_FW_WR_OP(FW_ULPTX_WR) | F_FW_WR_ATOMIC);
	req->ulptx_wr.flowid_len16 =
		cpu_to_be32(V_FW_WR_LEN16(reqlen/16));

	/* everything is going to TP */
	req->pass_open.ulptx.cmd_dest
		= cpu_to_be32(V_ULPTX_CMD(ULP_TX_PKT) |
			      V_ULP_TXPKT_DEST(ULP_TXPKT_DEST_TP));
	for (i = 0; i < SETLE128_IPV4; i++)
		req->set_le[i].ulptx.cmd_dest
			= cpu_to_be32(V_ULPTX_CMD(ULP_TX_PKT) |
				      V_ULP_TXPKT_DEST(ULP_TXPKT_DEST_TP));

	/* size of the ULP_TXPKT embedded CPL Passive Open Request */
	req->pass_open.ulptx.len
	= cpu_to_be32(sizeof(struct pass_open_req_ulp_txpkt)/16);

	/* size of the ULP_TXPKT embedded CPL Set LE Requests */
	for (i = 0; i < SETLE128_IPV4; i++)
		req->set_le[i].ulptx.len
			= cpu_to_be32(sizeof(struct set_le_req_ulp_txpkt)/16);

	/* fill in the Immediate Data information for the embedded CPLs */
	req->pass_open.sc.cmd_more
		= cpu_to_be32(V_ULPTX_CMD(ULP_TX_SC_IMM));
	for (i = 0; i < SETLE128_IPV4; i++)
		req->set_le[i].sc.cmd_more
			= cpu_to_be32(V_ULPTX_CMD(ULP_TX_SC_IMM));
	req->pass_open.sc.len
		= cpu_to_be32(sizeof(struct cpl_pass_open_req) -
			      sizeof(struct work_request_hdr));
	for (i = 0; i < SETLE128_IPV4; i++)
		req->set_le[i].sc.len
		= cpu_to_be32(sizeof(struct cpl_set_le_req) -
			      sizeof(struct work_request_hdr));

	/*
	 * Initialize the CPL Passive Open Request ...  Note again the
	 * need to deal with the omitted firmware Work Request Header ...
	 * Also note that as a result we do _not_ need to do the standard
	 * INIT_TP_WR() to initialize the non-existant Work Request header.
	 */
	popenr = (struct cpl_pass_open_req *)
		(req->pass_open.req - sizeof(struct work_request_hdr));
	OPCODE_TID(popenr) = htonl(MK_OPCODE_TID(CPL_PASS_OPEN_REQ, stid));
	popenr->local_port = sport;
	popenr->local_ip = sip;
	popenr->opt0 = cpu_to_be64(V_TX_CHAN(chan));
	popenr->opt1 = cpu_to_be64(V_CONN_POLICY(CPL_CONN_POLICY_ASK) |
				   F_SYN_RSS_ENABLE |
				   V_SYN_RSS_QUEUE(queue) |
				   (filter_value << ((chip_ver == CHELSIO_T4)
						  ? S_FILT_INFO
						  : S_T5_FILT_INFO)));

	/*
	 * And now the difficult part: rewriting the entire LE TCAM line
	 * for the Listen Server ...  First we initialize everything
	 * other than the values and masks ...
	 */
	for (i = 0; i < SETLE128_IPV4; i++) {
		setler[i] = (struct cpl_set_le_req *)
			(req->set_le[i].req - sizeof(struct work_request_hdr));
		OPCODE_TID(setler[i]) =
			cpu_to_be32(MK_OPCODE_TID(CPL_SET_LE_REQ, stid << 2));
		setler[i]->reply_ctrl = cpu_to_be16(F_NO_REPLY);
		setler[i]->params =
			cpu_to_be16(V_LE_REQ_IP6(0) |
				    V_LE_CHAN(chan) |
				    V_LE_OFFSET(i) |
				    V_LE_MORE(i != SETLE128_IPV4-1) |
				    V_LE_REQSIZE((chip_ver <= CHELSIO_T5) ?
						 LE_SZ_132 : 0) |
				    V_LE_REQCMD(LE_CMD_WRITE));
	}

	/*
	 * Now we need to write the value/mask portions of the Set LE TCAM
	 * Requests.  For T5 there are 136 bits in the IPv4 LE TCAM entry which
	 * are addressed as follows (T4 has 4 fewer bits in the Compressed
	 * Filter):
	 *
	 *   T5 IPv4 LE TCAM Entry:
	 *   ----------------------
	 *    135                                                    0
	 *   +--------------------------------------------------------+
	 *   |    Compressed  |   Local   | Foreign | Local | Foreign |
	 *   |    Filter      |   IP      | IP      | Port  | Port    |
	 *   +--------------------------------------------------------+
	 *           -40-          -32-       -32-     -16-     -16-
	 *
	 *   Set LE TCAM CPLs:
	 *   -----------------
	 *        127                   64 63                        0
	 *   +--------------------------------------------------------+
	 *   |1: |     0:val_hi/mask_hi   |      0:val_lo/mask_lo     |
	 *   +--------------------------------------------------------+
	 *    -8-            -64-                       -64-
	 *
	 * The Set LE Request with Offset=0 covers the lowest 128 bits and the
	 * one with Offset=1 covers the remaining 8 bits (4 bits for T4).  We
	 * need to replicate the TP logic for computing masks for the Local
	 * and Foreign IP Addresses and Ports which default to all 0s if the
	 * corresponding value is zero and all 1s if it's non-zero.
	 *
	 * Remember that when dealng with offsets within the Set LE Value/
	 * Mask High/Low fields, we're dealing with Big Endian objects.  So,
	 * for instance, the Local Port number is 4 bytes into the Low tuple
	 * of SetLEreq[0] ...
	 */
	if (sport) {
		((__be16 *)&setler[0]->val_lo)[2] = sport;
		((__be16 *)&setler[0]->mask_lo)[2] = (__force __be16)0xffff;
	}
	if (sip) {
		((__be32 *)&setler[0]->val_hi)[1] = sip;
		((__be32 *)&setler[0]->mask_hi)[1] = (__force __be32)0xffffffff;
	}

	/*
	 * The lower 32-bits of the Filter Value/Mask go into the high (first)
	 * four bytes of the Big Endian val_hi/mask_hi of the Set LE
	 * Request[0].  The high 8-bits go into the low (last) byte of the
	 * Big Endian val_lo/mask_lo of the Set LE Request[1].
	 */
	((__be32 *)&setler[0]->val_hi)[0] = cpu_to_be32((__u32)filter_value);
	((__be32 *)&setler[0]->mask_hi)[0] = cpu_to_be32((__u32)filter_mask);

	((__u8 *)&setler[1]->val_lo)[7] = (__u8)(filter_value >> 32);
	((__u8 *)&setler[1]->mask_lo)[7] = (__u8)(filter_mask >> 32);

	/*
	 * Finally it's time to send the whole thing off ...
	 */
	ret = t4_mgmt_tx(adap, skb);
	return net_xmit_eval(ret);
	#undef SETLE128_IPV4
}
EXPORT_SYMBOL(cxgb4_create_server_restricted);

/**
 *	cxgb4_create_server_vlan - create IPv4 server restricted to a VLAN
 *	@dev: the device
 *	@stid: the server TID
 *	@sip: local IP address to bind server to
 *	@sport: the server's TCP port
 *	@vlan: the VLAN to which to restrict the Offloaded Connections
 *	@queue: queue to which to direct messages from this server
 *
 *	This is mostly a convenience API front end to the far more general
 *	purpose cxgb4_create_server_restricted() API.  It also serves as a
 *	good example of how one would use the more general API.
 *	Returns <0 on error and one of the %NET_XMIT_* values on success.
 */
static int cxgb4_create_server_vlan(const struct net_device *dev,
				    unsigned int stid,
				    __be32 sip, __be16 sport,
				    __be16 vlan_id,
				    unsigned int queue)
{
	struct adapter *adapter = netdev2adap(dev);
	__u64 filter_value, filter_mask;

	/*
	 * Compute the extended Filter Information we'll be attaching to the
	 * Listen Server in the LE TCAM.  Note that all of the fields that
	 * we set here need to be specified in the Firmware Cnfiguration
	 * File "filterMask" specification.
	 *
	 * We also want to specify the TCP Protocol in order to avoid
	 * aliasing with UDP servers.
	 */
	if (t4_create_filter_info(adapter,
				  &filter_value, &filter_mask,
				  /*fcoe*/	-1,
				  /*port*/	-1,
				  /*vnic*/	-1,
				  /*vlan_id*/	be16_to_cpu(vlan_id) & 0xfff,
				  /*vlan_pcp*/	-1,
				  /*vlan_dei*/	-1,
				  /*tos*/	-1,
				  /*protocol*/	IPPROTO_TCP,
				  /*ethertype*/	-1,
				  /*macmatch*/	-1,
				  /*matchtype*/	-1,
				  /*frag*/	-1) < 0) {
		dev_warn(adapter->pdev_dev,
			 "Can't descriminate Offloaded incoming connections based on VLAN + TCP; not set in TP_VLAN_PRI_MAP\n");
		return -EOPNOTSUPP;
	}

	return cxgb4_create_server_restricted(dev, stid, sip, sport,
					      filter_value, filter_mask,
					      queue);
}

/**
 *	cxgb4_create_server - create an IP server
 *	@dev: the device
 *	@stid: the server TID
 *	@sip: local IP address to bind server to
 *	@sport: the server's TCP port
 *	@vlan: if not 0, the VLAN to restrict the Offloaded Connections
 *	@queue: queue to which to direct messages from this server
 *
 *	Create an IP server for the given port and address.
 *	Returns <0 on error and one of the %NET_XMIT_* values on success.
 */
int cxgb4_create_server(const struct net_device *dev, unsigned int stid,
			__be32 sip, __be16 sport, __be16 vlan,
			unsigned int queue)
{
	unsigned int chan;
	struct sk_buff *skb;
	struct adapter *adap;
	struct cpl_pass_open_req *req;
	int ret;

	/*
	 * This code demonstrates how one would selectively Offload
	 * (TOE) certain incoming connections by using the extended
	 * "Filter Information" capabilities of Server Control Blocks
	 * (SCB).  (See "Classification and Filtering" in the T4 Data
	 * Book for a description of Ingress Packet pattern matching
	 * capabilities.  See also documentation on the
	 * TP_VLAN_PRI_MAP register.)  Because this selective
	 * Offloading is happening in the chip, this allows
	 * non-Offloading and Offloading drivers to coexist.  For
	 * example, an Offloading Driver might be running in a
	 * Hypervisor while non-Offloading vNIC Drivers might be
	 * running in Virtual Machines.
	 *
	 * This particular example code demonstrates how one would
	 * selectively Offload incoming connections based on VLANs.
	 * We allow one VLAN to be designated as the "Offloading
	 * VLAN".  Ingress SYNs on this Offload VLAN will match the
	 * filter which we put into the Listen SCB and will result in
	 * Offloaded Connections on that VLAN.  Incoming SYNs on other
	 * VLANs will not match and will go through normal NIC
	 * processing.
	 *
	 * This is not production code since one would want a lot more
	 * infrastructure to allow a variety of filter specifications
	 * on a per-server basis.  But this demonstrates the
	 * fundamental mechanisms one would use to build such an
	 * infrastructure.
	 */
	if (vlan)
		return cxgb4_create_server_vlan(dev, stid, sip, sport,
						vlan, queue);

	skb = alloc_skb(sizeof(*req), GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	adap = netdev2adap(dev);
	req = (struct cpl_pass_open_req *)__skb_put(skb, sizeof(*req));
	INIT_TP_WR(req, 0);
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_PASS_OPEN_REQ, stid));
	req->local_port = sport;
	req->peer_port = htons(0);
	req->local_ip = sip;
	req->peer_ip = htonl(0);
	chan = rxq_to_chan(&adap->sge, queue);
	req->opt0 = cpu_to_be64(V_TX_CHAN(chan));
	req->opt1 = cpu_to_be64(V_CONN_POLICY(CPL_CONN_POLICY_ASK) |
				F_SYN_RSS_ENABLE | V_SYN_RSS_QUEUE(queue));
	ret = t4_mgmt_tx(adap, skb);
	return net_xmit_eval(ret);
}
EXPORT_SYMBOL(cxgb4_create_server);

/**
 *	cxgb4_create_server6_restricted - create a "restricted" IPv6 server
 *	@dev: the device
 *	@stid: the server TID
 *	@sip: local IPv6 address to bind server to
 *	@sport: the server's TCP port
 *	@filter_value: the Compressed Filter value
 *	@filter_mask: the Compressed Filter mask
 *	@queue: queue to direct messages from this server to
 *
 *	Creates an IPv6 Server for the given TCP Port and IPv6 Local
 *	Address.  (The Local end of a listening socket are often referred to
 *	as the "Source" for odd historical reasons.)
 *
 *	The Server entry is rewritten with the specified Filter Value/Mask
 *	tuple in order to restrict the incoming SYNs to which the Server
 *	Entry will match (and thus respond).  This uses the extended "Filter
 *	Information" capabilities of Server Control Blocks (SCB).  (See
 *	"Classification and Filtering" in the Data Book for a description
 *	of Ingress Packet pattern matching capabilities.  See also
 *	documentation on the TP_VLAN_PRI_MAP register.)
 *
 *	Returns <0 on error and one of the %NET_XMIT_* values on success.
 */
int cxgb4_create_server6_restricted(const struct net_device *dev,
				    unsigned int stid,
				    const struct in6_addr *sip, __be16 sport,
				    __be64 filter_value, __be64 filter_mask,
				    unsigned int queue)
{
	struct adapter *adap = netdev2adap(dev);
	unsigned int chan = rxq_to_chan(&adap->sge, queue);
	struct sk_buff *skb;
	unsigned int chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);
	int ret, i;

	/*
	 * We need to program the extended Filter Information for our
	 * Listening Server.  Unfortunately the Passive Open Request CPL only
	 * lets us program the "value" portion of the extended Filter
	 * Information which is stored in the LE TCAM for the Listening Server
	 * ... and programs the "mask" portion to 0 ... which doesn't do
	 * anyone any good.  So we have to send in the Passive Open Request
	 * _and_ several Set LE CPLs to completely reprogram the LE TCAM line
	 * associated with the Listening Server (the LE TCAM doesn't support
	 * partial writes).
	 *
	 * Since each Set LE TCAM CPL can write 128 bits and since an IPv4 LE
	 * TCAM Entry is 324 bits for T4 (328 for T5 and later), we need 3 Set
	 * LE TCAM CPLs.  We accomplish this by wrapping all of the messages
	 * in a Firmware ULP TX Work Request with the "atomic" bit set ...
	 *
	 * Note that each ULP_TXPKT wrapped CPL needs to be an integral number
	 * of 16-byte units ...
	 *
	 * Also note that the embedded CPLs are _only_ the CPLs themselves and
	 * do _not_ include the firmware Work Request Headers.  This is very
	 * awkward given the data structure definitions in t4_msg.h so we have
	 * to play some games here ...
	 */
	struct pass_open_req6_ulp_txpkt {
		struct ulp_txpkt	ulptx;
		struct ulptx_idata	sc;
		char			req[sizeof(struct cpl_pass_open_req6) -
					    sizeof(struct work_request_hdr)];
	} __aligned(16);

	struct set_le_req_ulp_txpkt {
		struct ulp_txpkt	ulptx;
		struct ulptx_idata	sc;
		char			req[sizeof(struct cpl_set_le_req) -
					    sizeof(struct work_request_hdr)];
	} __aligned(16);

	/* The number of 128-bit Set LE TCAM CPLs needed for IPv6 */
	#define SETLE128_IPV6 DIV_ROUND_UP(264, 128) /* match LE_SZ_264 */
	struct atomic_pass_open_req6 {
		struct fw_ulptx_wr		ulptx_wr;
		struct pass_open_req6_ulp_txpkt	pass_open6;
		struct set_le_req_ulp_txpkt	set_le[SETLE128_IPV6];
	} *req;
	__be64 vbuf[2*SETLE128_IPV6], mbuf[2*SETLE128_IPV6], *vbufp, *mbufp;
	unsigned char *vbcp, *mbcp;
	int offset, resid;

	struct cpl_pass_open_req6 *popenr;
	struct cpl_set_le_req *setler[SETLE128_IPV6];
	int reqlen = sizeof(*req);

	/*
	 * XXX We currently don't know how to do this for T6 and later
	 * XXX which use apparently a different LE TCAM rewrite.  We
	 * XXX also can't handle Local IPv6 Addresses which are
	 * XXX anything other than the "any" address (all 0s) because,
	 * XXX for T5 and earlier, we need the Clip Table Index for
	 * XXX the the IPv6 Address and the firmware Clip Table API
	 * XXX doesn't return that [yet] ...
	 */
	if (chip_ver > CHELSIO_T5 || ipv6_addr_type(sip) != IPV6_ADDR_ANY)
		return -EOPNOTSUPP;

	/*
	 * Allocate an skb large enough to hold our atomic request.
	 */
	skb = alloc_skb(reqlen, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	req = (struct atomic_pass_open_req6 *)__skb_put(skb, reqlen);
	memset(req, 0, reqlen);

	/*
	 * Initialize the Firmware ULP TX Work Request and all of the ULP
	 * TX Packet routing messages ...
	 */
	req->ulptx_wr.op_to_compl =
		cpu_to_be32(V_FW_WR_OP(FW_ULPTX_WR) | F_FW_WR_ATOMIC);
	req->ulptx_wr.flowid_len16 =
		cpu_to_be32(V_FW_WR_LEN16(reqlen/16));

	/* everything is going to TP */
	req->pass_open6.ulptx.cmd_dest
		= cpu_to_be32(V_ULPTX_CMD(ULP_TX_PKT) |
			      V_ULP_TXPKT_DEST(ULP_TXPKT_DEST_TP));
	for (i = 0; i < SETLE128_IPV6; i++)
		req->set_le[i].ulptx.cmd_dest
			= cpu_to_be32(V_ULPTX_CMD(ULP_TX_PKT) |
				      V_ULP_TXPKT_DEST(ULP_TXPKT_DEST_TP));

	/* size of the ULP_TXPKT embedded CPL Passive Open Request */
	req->pass_open6.ulptx.len
	= cpu_to_be32(sizeof(struct pass_open_req6_ulp_txpkt)/16);

	/* size of the ULP_TXPKT embedded CPL Set LE Requests */
	for (i = 0; i < SETLE128_IPV6; i++)
		req->set_le[i].ulptx.len
			= cpu_to_be32(sizeof(struct set_le_req_ulp_txpkt)/16);

	/* fill in the Immediate Data information for the embedded CPLs */
	req->pass_open6.sc.cmd_more
		= cpu_to_be32(V_ULPTX_CMD(ULP_TX_SC_IMM));
	for (i = 0; i < SETLE128_IPV6; i++)
		req->set_le[i].sc.cmd_more
			= cpu_to_be32(V_ULPTX_CMD(ULP_TX_SC_IMM));
	req->pass_open6.sc.len
		= cpu_to_be32(sizeof(struct cpl_pass_open_req6) -
			      sizeof(struct work_request_hdr));
	for (i = 0; i < SETLE128_IPV6; i++)
		req->set_le[i].sc.len
			= cpu_to_be32(sizeof(struct cpl_set_le_req) -
				      sizeof(struct work_request_hdr));

	/*
	 * Initialize the CPL Passive Open IPv6 Request ...  Note again the
	 * need to deal with the omitted firmware Work Request Header ...
	 * Also note that as a result we do _not_ need to do the standard
	 * INIT_TP_WR() to initialize the non-existent Work Request header.
	 */
	popenr = (struct cpl_pass_open_req6 *)
		(req->pass_open6.req - sizeof(struct work_request_hdr));
	OPCODE_TID(popenr) = htonl(MK_OPCODE_TID(CPL_PASS_OPEN_REQ6, stid));
	popenr->local_port = sport;
	popenr->local_ip_hi = *(__be64 *)(sip->s6_addr);
	popenr->local_ip_lo = *(__be64 *)(sip->s6_addr + 8);
	popenr->peer_ip_hi = cpu_to_be64(0);
	popenr->peer_ip_lo = cpu_to_be64(0);
	popenr->opt0 = cpu_to_be64(V_TX_CHAN(chan));
	popenr->opt1 = cpu_to_be64(V_CONN_POLICY(CPL_CONN_POLICY_ASK) |
				   F_SYN_RSS_ENABLE |
				   V_SYN_RSS_QUEUE(queue) |
				   (filter_value << ((chip_ver == CHELSIO_T4)
						  ? S_FILT_INFO
						  : S_T5_FILT_INFO)));

	/*
	 * And now the difficult part: rewriting the entire LE TCAM line
	 * for the Listen Server ...  First we initialize everything
	 * other than the values and masks ...
	 */
	for (i = 0; i < SETLE128_IPV6; i++) {
		setler[i] = (struct cpl_set_le_req *)
			(req->set_le[i].req - sizeof(struct work_request_hdr));
		OPCODE_TID(setler[i]) =
			cpu_to_be32(MK_OPCODE_TID(CPL_SET_LE_REQ, stid << 2));
		setler[i]->reply_ctrl = cpu_to_be16(F_NO_REPLY);
		setler[i]->params =
			cpu_to_be16(V_LE_REQ_IP6(1) |
				    V_LE_CHAN(chan) |
				    V_LE_OFFSET(i) |
				    V_LE_MORE(i != SETLE128_IPV6-1) |
				    V_LE_REQSIZE((chip_ver <= CHELSIO_T5) ?
						 LE_SZ_264 : 0) |
				    V_LE_REQCMD(LE_CMD_WRITE));
	}

	/*
	 * Now we need to write the value/mask portions of the Set LE TCAM
	 * Requests.  For T5 there are 213 bits in the IPv6 LE TCAM entry
	 * which are addressed as follows (T4 has 4 fewer bits in the
	 * Compressed Filter):
	 *
	 *   LE TCAM Entry:
	 *   --------------
	 *    212                                                     0
	 *   +---------------------------------------------------------+
	 *   |Cmprsd|Local IPv6|          Foreign        |Local|Foreign|
	 *   |Filter|Clip Index|          IPv6           |Port |Port   |
	 *   +---------------------------------------------------------+
	 *      -40-    -13-             -128-            -16-    -16-
	 *
	 *   Set LE TCAM CPLs:
	 *   -----------------
	 *    212                128 127                              0
	 *   +---------------------------------------------------------+
	 *   |  1:  val/mask hi/lo  |         0:  val/mask hi/lo       |
	 *   +---------------------------------------------------------+
	 *                 -85-                      -128-
	 *
	 * The Set LE Request with Offset=0 covers the lowest 128 bits and the
	 * one with Offset=1 covers the the remaining 85 bits (81 bits for T4).
	 * We need to replicate the TP logic for computing masks for the Local
	 * and Foreign IP Addresses and Ports which default to all 0s if the
	 * corresponding value is zero and all 1s if it's non-zero.
	 *
	 * Remember that when dealng with offsets within the Set LE Value/
	 * Mask High/Low fields, we're dealing with Big Endian objects.  So,
	 * for instance, the Local Port number is 4 bytes into the Low tuple
	 * of SetLEreq[0] ...
	 *
	 * The mapping of the various elements above is complex enough that
	 * it's worth our time to simply construct this in intermediate
	 * contiguous Value/Mask Buffers and then copy the individual 64-bit
	 * Big Endian values into the various Set LE Requeuest Value/Mask
	 * High/Low values.  The buffers contains Big-Endian values and are
	 * laid out in a Big-Endian format with 64-bit Word0 in *buf[5] and
	 * Word5 in *buf[0].
	 */
	memset(vbuf, 0, sizeof(vbuf));
	memset(mbuf,  0, sizeof(mbuf));

	/* Local TCP Port */
	if (sport) {
		offset = sizeof(vbuf) - 2 * 16/8;
		*(__be16 *)((char *)vbuf + offset) = sport;
		*(__be16 *)((char *)mbuf + offset) = (__force __be16)0xffff;
	}

	/* Local IPv6 Address */
	if (ipv6_addr_type(sip) != IPV6_ADDR_ANY) {
		/*
		 * XXX For T4/T5 we need the 13-bit Clip Table Index.
		 * XXX For T6 we apparently write the actual 128-bit Local
		 * XXX IPv6 Address and the CPL Set LE Request does the
		 * XXX Clip Table lookup (just like the CPL Passive Open
		 * XXX Request6).  It's a mess and we don't know how to
		 * XXX really handle this.  See the code above which
		 * XXX rejects calls to this function if we're working
		 * XXX with a T6 or the Local IPv6 Address is anything
		 * XXX other than the all-0 "any" address.
		 */
		BUG_ON(1);
	}

	/*
	 * Copy Filter Value/Mask tuple into Big-Endian Value/Mask Buffer.  We
	 * insert these a byte at a time so we completely cntrol the Big-
	 * Endian translation into the buffers.
	 */

	/* Offset of lowest order byte containing value/mask tuple */
	offset = sizeof(vbuf) - 2 * 16/8 - 128/8 - (13 + 8-1)/8;
	resid = 2*8 - 13;
	vbcp = (char *)vbuf + offset;
	mbcp = (char *)mbuf + offset;

	/* Lowest order byte holds the lowest order few bits ... */
	*vbcp-- |= (unsigned char)(filter_value << (8-resid));
	filter_value >>= (resid);
	*mbcp-- |= (unsigned char)(filter_mask << (8-resid));
	filter_mask >>= (resid);

	/* ... and then the remaining bits get streamed in ... */
	while (filter_value || filter_mask) {
		*vbcp-- |= (unsigned char)filter_value;
		filter_value >>= 8;
		*mbcp-- |= (unsigned char)filter_mask;
		filter_mask >>= 8;
	}

	/*
	 * Copy the completed Value/Mask Buffers into the Set LE Requests.
	 */
	vbufp = vbuf + 2*SETLE128_IPV6;
	mbufp = mbuf + 2*SETLE128_IPV6;
	for (i = 0; i < SETLE128_IPV6; i++) {
		setler[i]->val_lo = *--vbufp;
		setler[i]->val_hi = *--vbufp;
		setler[i]->mask_lo = *--mbufp;
		setler[i]->mask_hi = *--mbufp;
	}

	/*
	 * Finally it's time to send the whole thing off ...
	 */
	ret = t4_mgmt_tx(adap, skb);
	return net_xmit_eval(ret);
	#undef SETLE128_IPV6
}
EXPORT_SYMBOL(cxgb4_create_server6_restricted);

/**
 *	cxgb4_create_server6 - create an IPv6 server
 *	@dev: the device
 *	@stid: the server TID
 *	@sip: local IPv6 address to bind server to
 *	@sport: the server's TCP port
 *	@queue: queue to direct messages from this server to
 *
 *	Create an IPv6 server for the given port and address.
 *	Returns <0 on error and one of the %NET_XMIT_* values on success.
 */
int cxgb4_create_server6(const struct net_device *dev, unsigned int stid,
			 const struct in6_addr *sip, __be16 sport,
			 unsigned int queue)
{
	unsigned int chan;
	struct sk_buff *skb;
	struct adapter *adap;
	struct cpl_pass_open_req6 *req;
	int ret;

	skb = alloc_skb(sizeof(*req), GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	adap = netdev2adap(dev);
	req = (struct cpl_pass_open_req6 *)__skb_put(skb, sizeof(*req));
	INIT_TP_WR(req, 0);
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_PASS_OPEN_REQ6, stid));
	req->local_port = sport;
	req->peer_port = htons(0);
	req->local_ip_hi = *(__be64 *)(sip->s6_addr);
	req->local_ip_lo = *(__be64 *)(sip->s6_addr + 8);
	req->peer_ip_hi = cpu_to_be64(0);
	req->peer_ip_lo = cpu_to_be64(0);
	chan = rxq_to_chan(&adap->sge, queue);
	req->opt0 = cpu_to_be64(V_TX_CHAN(chan));
	req->opt1 = cpu_to_be64(V_CONN_POLICY(CPL_CONN_POLICY_ASK) |
				F_SYN_RSS_ENABLE | V_SYN_RSS_QUEUE(queue));
	ret = t4_mgmt_tx(adap, skb);
	return net_xmit_eval(ret);
}
EXPORT_SYMBOL(cxgb4_create_server6);

int cxgb4_remove_server(const struct net_device *dev, unsigned int stid,
			unsigned int queue, bool ipv6)
{
	struct sk_buff *skb;
	struct adapter *adap;
	struct cpl_close_listsvr_req *req;
	int ret;

	adap = netdev2adap(dev);
        skb = alloc_skb(sizeof(*req), GFP_KERNEL);
        if (!skb)
                return -ENOMEM;

        req = (struct cpl_close_listsvr_req *)__skb_put(skb, sizeof(*req));
        INIT_TP_WR(req, 0);
        OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_CLOSE_LISTSRV_REQ, stid));
	req->reply_ctrl = htons(V_NO_REPLY(0) | (ipv6 ? V_LISTSVR_IPV6(1) : V_LISTSVR_IPV6(0)) | V_QUEUENO(queue));
	ret = t4_mgmt_tx(adap, skb);
	return net_xmit_eval(ret);
}
EXPORT_SYMBOL(cxgb4_remove_server);

#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

static ssize_t show_cclk(struct device *d, struct device_attribute *attr,
			 char *buf)
{
	ssize_t len;
	struct adapter *adap = netdev2adap(to_net_dev(d));
	char temp[32];
	unsigned int cclk_ps = 1000000000 / adap->params.vpd.cclk;  /* in ps */

	/*
	 * Display the core clock in units of ns, the same way it is
	 * displayed in debugfs.
	 */
	len = sprintf(buf, "Core clock period: %s ns\n",
		   unit_conv(temp, sizeof(temp), cclk_ps, 1000));

	return len;
}

#define T4_DISPLAY_ATTR(name) \
static DEVICE_ATTR(name, S_IRUGO, show_##name, NULL)

T4_DISPLAY_ATTR(cclk);

static struct attribute *t4_attrs[] = {
	&dev_attr_cclk.attr,
	NULL
};

static struct attribute_group t4_attr_group = { .attrs = t4_attrs };

/**
 *	cxgb4_best_mtu - find the entry in the MTU table closest to an MTU
 *	@mtus: the HW MTU table
 *	@mtu: the target MTU
 *	@idx: index of selected entry in the MTU table
 *
 *	Returns the index and the value in the HW MTU table that is closest to
 *	but does not exceed @mtu, unless @mtu is smaller than any value in the
 *	table, in which case that smallest available value is selected.
 */
unsigned int cxgb4_best_mtu(const unsigned short *mtus, unsigned short mtu,
			    unsigned int *idx)
{
	unsigned int i = 0;

	while (i < NMTUS - 1 && mtus[i + 1] <= mtu)
		++i;
	if (idx)
		*idx = i;
	return mtus[i];
}
EXPORT_SYMBOL(cxgb4_best_mtu);

/**
 *	cxgb4_best_aligned_mtu - find best MTU, [hopefully] data size aligned
 *	@mtus: the HW MTU table
 *	@header_size: Header Size
 *	@data_size_max: maximum Data Segment Size
 *	@data_size_align: desired Data Segment Size Alignment (2^N)
 *	@mtu_idxp: HW MTU Table Index return value pointer (possibly NULL)
 *
 *	Similar to cxgb4_best_mtu() but instead of searching the Hardware
 *	MTU Table based solely on a Maximum MTU parameter, we break that
 *	parameter up into a Header Size and Maximum Data Segment Size, and
 *	provide a desired Data Segment Size Alignment.  If we find an MTU in
 *	the Hardware MTU Table which will result in a Data Segment Size with
 *	the requested alignment _and_ that MTU isn't "too far" from the
 *	closest MTU, then we'll return that rather than the closest MTU.
 */
unsigned int cxgb4_best_aligned_mtu(const unsigned short *mtus,
				    unsigned short header_size,
				    unsigned short data_size_max,
				    unsigned short data_size_align,
				    unsigned int *mtu_idxp)
{
	unsigned short max_mtu = header_size + data_size_max;
	unsigned short data_size_align_mask = data_size_align - 1;
	int mtu_idx, aligned_mtu_idx;

	/* Scan the MTU Table till we find an MTU which is larger than our
	 * Maximum MTU or we reach the end of the table.  Along the way,
	 * record the last MTU found, if any, which will result in a Data
	 * Segment Length matching the requested alignment.
	 */
	for (mtu_idx = 0, aligned_mtu_idx = -1; mtu_idx < NMTUS; mtu_idx++) {
		unsigned short data_size = mtus[mtu_idx] - header_size;

		/* If this MTU minus the Header Size would result in a
		 * Data Segment Size of the desired alignment, remember it.
		 */
		if ((data_size & data_size_align_mask) == 0)
			aligned_mtu_idx = mtu_idx;

		/* If we're not at the end of the Hardware MTU Table and the
		 * next element is larger than our Maximum MTU, drop out of
		 * the loop.
		 */
		if (mtu_idx+1 < NMTUS && mtus[mtu_idx+1] > max_mtu)
			break;
	}

	/* If we fell out of the loop because we ran to the end of the table,
	 * then we just have to use the last [largest] entry.
	 */
	if (mtu_idx == NMTUS)
		mtu_idx--;

	/* If we found an MTU which resulted in the requested Data Segment
	 * Length alignment and that's "not far" from the largest MTU which is
	 * less than or equal to the maximum MTU, then use that.
	 */
	if (aligned_mtu_idx >= 0 &&
	    mtu_idx - aligned_mtu_idx <= 1)
		mtu_idx = aligned_mtu_idx;

	/* If the caller has passed in an MTU Index pointer, pass the
	 * MTU Index back.  Return the MTU value.
	 */
	if (mtu_idxp)
		*mtu_idxp = mtu_idx;
	return mtus[mtu_idx];
}
EXPORT_SYMBOL(cxgb4_best_aligned_mtu);

/**
 *	cxgb4_tp_smt_idx - Get the Source Mac Table index for this VI
 *	@chip: chip type
 *	@viid: VI id of the given port
 *
 *	Return the SMT index for this VI.
 */
unsigned int cxgb4_tp_smt_idx(enum chip_type chip, unsigned int viid)
{
	/* In T4/T5, SMT contains 256 SMAC entries organized in
	 * 128 rows of 2 entries each.
	 * In T6, SMT contains 256 SMAC entries in 256 rows.
	 * TODO: The below code needs to be updated when we add support
	 * for 256 VFs.
	 */
	if (CHELSIO_CHIP_VERSION(chip) <= CHELSIO_T5)
		return ((viid & 0x7f) << 1);
	else
		return (viid & 0x7f);
}
EXPORT_SYMBOL(cxgb4_tp_smt_idx);

/**
 *	cxgb4_port_chan - get the HW channel of a port
 *	@dev: the net device for the port
 *
 *	Return the HW Tx channel of the given port.
 */
unsigned int cxgb4_port_chan(const struct net_device *dev)
{
	return netdev2pinfo(dev)->tx_chan;
}
EXPORT_SYMBOL(cxgb4_port_chan);

unsigned int cxgb4_dbfifo_count(const struct net_device *dev, int lpfifo)
{
	struct adapter *adap = netdev2adap(dev);
	u32 v1, lp_count, hp_count;

	v1 = t4_read_reg(adap, A_SGE_DBFIFO_STATUS);
	if (is_t4(adap->params.chip)) {
		lp_count = G_LP_COUNT(v1);
		hp_count = G_HP_COUNT(v1);
	} else {
		u32 v2;
		v2 = t4_read_reg(adap, A_SGE_DBFIFO_STATUS2);
		lp_count = G_LP_COUNT_T5(v1);
		hp_count = G_HP_COUNT_T5(v2);
	}
	return lpfifo ? lp_count : hp_count;
}
EXPORT_SYMBOL(cxgb4_dbfifo_count);

/**
 *	cxgb4_port_viid - get the VI id of a port
 *	@dev: the net device for the port
 *
 *	Return the VI id of the given port.
 */
unsigned int cxgb4_port_viid(const struct net_device *dev)
{
	return netdev2pinfo(dev)->viid;
}
EXPORT_SYMBOL(cxgb4_port_viid);

/**
 *	cxgb4_port_idx - get the index of a port
 *	@dev: the net device for the port
 *
 *	Return the index of the given port.
 */
unsigned int cxgb4_port_idx(const struct net_device *dev)
{
	return netdev2pinfo(dev)->port_id;
}
EXPORT_SYMBOL(cxgb4_port_idx);

void cxgb4_get_tcp_stats(struct pci_dev *pdev, struct tp_tcp_stats *v4,
			 struct tp_tcp_stats *v6)
{
	struct adapter *adap = pci_get_drvdata(pdev);

	spin_lock(&adap->stats_lock);
	t4_tp_get_tcp_stats(adap, v4, v6);
	spin_unlock(&adap->stats_lock);
}
EXPORT_SYMBOL(cxgb4_get_tcp_stats);

/**
 *	cxgb4_netdev_by_hwid - return the net device of a HW port
 *	@pdev: identifies the adapter
 *	@id: the HW port id
 *
 *	Return the net device associated with the interface with the given HW
 *	id.
 */
struct net_device *cxgb4_netdev_by_hwid(struct pci_dev *pdev, unsigned int id)
{
	const struct adapter *adap = pci_get_drvdata(pdev);

	if (!adap || id >= NCHAN)
		return NULL;
	id = adap->chan_map[id];
	return id < MAX_NPORTS ? adap->port[id] : NULL;
}
EXPORT_SYMBOL(cxgb4_netdev_by_hwid);

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
int cxgb4_wr_mbox(struct net_device *dev, const void *cmd,
		  int size, void *rpl)
{
	struct adapter *adap = netdev2adap(dev);

	return t4_wr_mbox(adap, adap->mbox, cmd, size, rpl);
}
EXPORT_SYMBOL(cxgb4_wr_mbox);

int cxgb4_flush_eq_cache(struct net_device *dev)
{
	struct adapter *adap = netdev2adap(dev);

	return t4_sge_ctxt_flush(adap, adap->mbox);
}
EXPORT_SYMBOL(cxgb4_flush_eq_cache);

static int read_eq_indices(struct adapter *adap, u16 qid, u16 *pidx, u16 *cidx)
{
	u32 addr = t4_read_reg(adap, A_SGE_DBQ_CTXT_BADDR) + 24 * qid + 8;
	__be64 indices;
	int ret;

	spin_lock(&adap->win0_lock);
	ret = t4_memory_rw(adap, MEMWIN_NIC, MEM_EDC0, addr,
			   sizeof(indices), (__be32 *)&indices,
			   T4_MEMORY_READ);
	spin_unlock(&adap->win0_lock);
	if (!ret) {
		*cidx = (be64_to_cpu(indices) >> 25) & 0xffff;
		*pidx = (be64_to_cpu(indices) >> 9) & 0xffff;
	}
	return ret;
}

int cxgb4_sync_txq_pidx(struct net_device *dev, u16 qid, u16 pidx,
			u16 size)
{
	struct adapter *adap = netdev2adap(dev);
	u16 hw_pidx, hw_cidx;
	int ret;

	ret = read_eq_indices(adap, qid, &hw_pidx, &hw_cidx);
	if (ret)
		goto out;

	if (pidx != hw_pidx) {
		u16 delta;
		u32 val;

		if (pidx >= hw_pidx)
			delta = pidx - hw_pidx;
		else
			delta = size - hw_pidx + pidx;

		if (is_t4(adap->params.chip))
			val = V_PIDX(delta);
		else
			val = V_PIDX_T5(delta);
		wmb();
		t4_write_reg(adap, MYPF_REG(A_SGE_PF_KDOORBELL),
			     V_QID(qid) | val);
	}
out:
	return ret;
}
EXPORT_SYMBOL(cxgb4_sync_txq_pidx);

int cxgb4_read_tpte(struct net_device *dev, u32 stag, __be32 *tpte)
{
	struct adapter *adap;
	u32 offset, memtype, memaddr;
	u32 edc0_size, edc1_size, mc0_size, mc1_size;
	u32 edc0_end, edc1_end, mc0_end, mc1_end;
	int ret;

	adap = netdev2adap(dev);

	offset = ((stag >> 8) * 32) + adap->vres.stag.start;

	/* Figure out where the offset lands in the Memory Type/Address scheme.
	 * This code assumes that the memory is laid out starting at offset 0
	 * with no breaks as: EDC0, EDC1, MC0, MC1. All cards have both EDC0
	 * and EDC1.  Some cards will have neither MC0 nor MC1, most cards have
	 * MC0, and some have both MC0 and MC1.
	 */
	edc0_size = G_EDRAM0_SIZE(t4_read_reg(adap, A_MA_EDRAM0_BAR)) << 20;
	edc1_size = G_EDRAM0_SIZE(t4_read_reg(adap, A_MA_EDRAM1_BAR)) << 20;
	mc0_size = G_EXT_MEM0_SIZE(t4_read_reg(adap, A_MA_EXT_MEMORY0_BAR)) << 20;

	edc0_end = edc0_size;
	edc1_end = edc0_end + edc1_size;
	mc0_end = edc1_end + mc0_size;

	if (offset < edc0_end) {
		memtype = MEM_EDC0;
		memaddr = offset;
	} else if (offset < edc1_end) {
		memtype = MEM_EDC1;
		memaddr = offset - edc0_end;
	} else {
		if (offset < mc0_end) {
			memtype = MEM_MC0;
			memaddr = offset - edc1_end;
		} else if (is_t5(adap->params.chip)) {
			mc1_size = G_EXT_MEM0_SIZE(t4_read_reg(adap, A_MA_EXT_MEMORY1_BAR)) << 20;
			mc1_end = mc0_end + mc1_size;
			if (offset < mc1_end) {
				memtype = MEM_MC1;
				memaddr = offset - mc0_end;
			} else {
				/* offset beyond the end of any memory */
				goto err;
			}
		} else {
			/* T4/T6 only has a single memory channel */
			goto err;
		}
	}

	spin_lock(&adap->win0_lock);
	ret = t4_memory_rw(adap, MEMWIN_NIC, memtype, memaddr, 32, tpte, T4_MEMORY_READ);
	spin_unlock(&adap->win0_lock);
	return ret;

err:
	dev_err(adap->pdev_dev, "stag %#x, offset %#x out of range\n",
		stag, offset);
	return -EINVAL;
}
EXPORT_SYMBOL(cxgb4_read_tpte);

static struct pci_driver cxgb4_driver;

static void check_neigh_update(struct neighbour *neigh)
{
	const struct device *parent = NULL;
	struct net_device *netdev = neigh->dev;
#if defined(BOND_SUPPORT)
	struct bonding *bond;
	struct slave *slave;
#endif

	if (netdev->priv_flags & IFF_802_1Q_VLAN)
		netdev = vlan_dev_real_dev(netdev);
#if defined(BOND_SUPPORT)
	if (netdev->flags & IFF_MASTER) {
		bond = (struct bonding *)netdev_priv(netdev);
		/* We select the first child since we can only bond
		 * offload devices belonging to the same adapter.
		 */
		bond_read_lock_compat(bond);
		slave = bond_first_slave_compat(bond);
		if (slave)
			netdev = slave->dev;
		else
			netdev = NULL;
		bond_read_unlock_compat(bond);
	}
#endif

	if (netdev)
		parent = netdev->dev.parent;

	if (parent && parent->driver == &cxgb4_driver.driver)
		t4_l2t_update(dev_get_drvdata(parent), neigh);
}

static int cxgb4_inet6addr_handler(struct notifier_block *this,
					unsigned long event, void *data)
{
	struct inet6_ifaddr *ifa = data;
	struct net_device *event_dev = ifa->idev->dev;
	const struct device *parent = NULL;
#if defined(BOND_SUPPORT)
	struct adapter *adap;
#endif
	if (event_dev->priv_flags & IFF_802_1Q_VLAN)
		event_dev = vlan_dev_real_dev(event_dev);
#if defined(BOND_SUPPORT)
	if (event_dev->flags & IFF_MASTER) {
		list_for_each_entry(adap, &adapter_list, list_node) {
			switch (event) {
			case NETDEV_UP:
				cxgb4_clip_get(adap->port[0],
							(const u32 *)ifa, 1);
				break;
			case NETDEV_DOWN:
				cxgb4_clip_release(adap->port[0],
							(const u32 *)ifa, 1);
				break;
			default:
				break;
			}
		}
		return NOTIFY_OK;
	}
#endif

	if (event_dev)
		parent = event_dev->dev.parent;

	if (parent && parent->driver == &cxgb4_driver.driver) {
		switch (event) {
		case NETDEV_UP:
			cxgb4_clip_get(event_dev, (const u32 *)ifa, 1);
			break;
		case NETDEV_DOWN:
			cxgb4_clip_release(event_dev, (const u32 *)ifa, 1);
			break;
		default:
			break;
		}
	}
	return NOTIFY_OK;
}


static struct notifier_block cxgb4_inet6addr_notifier = {
	.notifier_call = cxgb4_inet6addr_handler
};

int cxgb4_set_params(struct net_device *dev, unsigned int nparams,
		     const u32 *params, const u32 *val)
{
	struct adapter *adap;

	adap = netdev2adap(dev);
	return t4_set_params(adap, adap->mbox, adap->pf, 0, nparams, params,
			     val);
}
EXPORT_SYMBOL(cxgb4_set_params);

u64 cxgb4_read_sge_timestamp(struct net_device *dev)
{
	u32 hi, lo;
	struct adapter *adap;

	adap = netdev2adap(dev);
	lo = t4_read_reg(adap, A_SGE_TIMESTAMP_LO);
	hi = G_TSVAL(t4_read_reg(adap, A_SGE_TIMESTAMP_HI));

	return ((u64)hi << 32) | (u64)lo;
}
EXPORT_SYMBOL(cxgb4_read_sge_timestamp);

int cxgb4_bar2_sge_qregs(struct net_device *dev,
			 unsigned int qid,
			 enum cxgb4_bar2_qtype qtype,
			 int user,
			 u64 *pbar2_qoffset,
			 unsigned int *pbar2_qid)
{
	return t4_bar2_sge_qregs(netdev2adap(dev),
				 qid,
				 (qtype == CXGB4_BAR2_QTYPE_EGRESS
				  ? T4_BAR2_QTYPE_EGRESS
				  : T4_BAR2_QTYPE_INGRESS),
				 user,
				 pbar2_qoffset,
				 pbar2_qid);
}
EXPORT_SYMBOL(cxgb4_bar2_sge_qregs);

static int netevent_cb(struct notifier_block *nb, unsigned long event,
		       void *data)
{
	switch (event) {
	case NETEVENT_NEIGH_UPDATE:
		check_neigh_update(data);
		break;
	case NETEVENT_REDIRECT:
	default:
		break;
	}
	return 0;
}

static struct notifier_block cxgb4_netevent_nb = {
	.notifier_call = netevent_cb
};

static void uld_attach(struct adapter *adap, unsigned int uld)
{
	void *handle;
	struct cxgb4_lld_info lli;
	unsigned short i;

	if (!is_offload(adap))
		return;

	lli.pdev = adap->pdev;
	lli.pf = adap->pf;
	lli.l2t = adap->l2t;
	lli.tids = &adap->tids;
	lli.ports = adap->port;
	lli.vr = &adap->vres;
	lli.mtus = adap->params.mtus;
	if (uld == CXGB4_ULD_RDMA) {
		lli.rxq_ids = adap->sge.rdma_rxq;
		lli.ciq_ids = adap->sge.rdma_ciq;
		lli.nrxq = adap->sge.rdmaqs;
		lli.nciq = adap->sge.rdmaciqs;
	} else if (uld == CXGB4_ULD_ISCSI) {
		lli.rxq_ids = adap->sge.iscsi_rxq;
		lli.nrxq = adap->sge.niscsiq;
	} else if (uld == CXGB4_ULD_TOE) {
		lli.rxq_ids = adap->sge.ofld_rxq;
		lli.nrxq = adap->sge.ofldqsets;
	}
	lli.ntxq = adap->sge.ofldqsets;
	lli.nchan = adap->params.nports;
	lli.nports = adap->params.nports;
	lli.wr_cred = adap->params.ofldq_wr_cred;
	lli.nsched_cls = adap->params.nsched_cls;
	lli.adapter_type = adap->params.chip;
	lli.iscsi_iolen = G_MAXRXDATA(t4_read_reg(adap, A_TP_PARA_REG2));
	lli.iscsi_tagmask = t4_read_reg(adap, A_ULP_RX_ISCSI_TAGMASK);
	lli.iscsi_pgsz_order = t4_read_reg(adap, A_ULP_RX_ISCSI_PSZ);
	lli.iscsi_llimit = t4_read_reg(adap, A_ULP_RX_ISCSI_LLIMIT);
	lli.iscsi_ppm = &adap->iscsi_ppm;
	lli.cclk_ps = 1000000000 / adap->params.vpd.cclk;
	lli.udb_density = 1 << adap->params.sge.eq_qpp;
	lli.ucq_density = 1 << adap->params.sge.iq_qpp;
	lli.tx_db_wc = adap->tx_db_wc;
	lli.filt_mode = adap->params.tp.vlan_pri_map;
	
	for (i = 0; i < NCHAN; i++)
		lli.tx_modq[i] = adap->params.tp.tx_modq[i];
	lli.gts_reg = adap->regs + MYPF_REG(A_SGE_PF_GTS);
	lli.db_reg = adap->regs + MYPF_REG(A_SGE_PF_KDOORBELL);
	lli.fw_vers = adap->params.fw_vers;
	lli.dbfifo_int_thresh = G_LP_INT_THRESH(t4_read_reg(adap,
						A_SGE_DBFIFO_STATUS));
	lli.sge_ingpadboundary = adap->sge.fl_align;
	lli.sge_pktshift = adap->sge.pktshift;
	lli.sge_egrstatuspagesize = adap->sge.stat_len;
	lli.enable_fw_ofld_conn = adap->flags & FW_OFLD_CONN &&
				  !is_bypass(adap);
	lli.max_ordird_qp = adap->params.max_ordird_qp;
	lli.max_ird_adapter = adap->params.max_ird_adapter;
	lli.ulptx_memwrite_dsgl = adap->params.ulptx_memwrite_dsgl;
	lli.ulp_t10dif = adap->params.ulp_t10dif;
	lli.nodeid = dev_to_node(adap->pdev_dev);

	handle = cxgb4_ulds[uld].add(&lli);
	if (IS_ERR(handle)) {
		CH_WARN(adap, "could not attach to the %s driver, error %ld\n",
			uld_str[uld], PTR_ERR(handle));
		return;
	}

	adap->uld_handle[uld] = handle;

	if (!(registered_notifier_block & CXGB4_NETEVENT_REGISTERED)) {
		register_netevent_notifier(&cxgb4_netevent_nb);
		registered_notifier_block |= CXGB4_NETEVENT_REGISTERED;
	}

	if (adap->flags & FULL_INIT_DONE)
		cxgb4_ulds[uld].state_change(handle, CXGB4_STATE_UP);
}

static void attach_ulds(struct adapter *adap)
{
	unsigned int i;

	mutex_lock(&uld_mutex);
	list_add_tail(&adap->list_node, &adapter_list);
	for (i = 0; i < CXGB4_ULD_MAX; i++) {
		mutex_lock(&adap->uld_mutex);
		if (cxgb4_ulds[i].add)
			uld_attach(adap, i);
		mutex_unlock(&adap->uld_mutex);
	}
	mutex_unlock(&uld_mutex);
}

static void detach_ulds(struct adapter *adap)
{
	unsigned int i;

	mutex_lock(&uld_mutex);
	if (!list_empty(&adap->list_node))
		list_del_init(&adap->list_node);
	for (i = 0; i < CXGB4_ULD_MAX; i++) {
		mutex_lock(&adap->uld_mutex);
		if (adap->uld_handle[i]) {
			cxgb4_ulds[i].state_change(adap->uld_handle[i],
					     CXGB4_STATE_DETACH);
			adap->uld_handle[i] = NULL;
		}
		mutex_unlock(&adap->uld_mutex);
	}
	if ((registered_notifier_block & CXGB4_NETEVENT_REGISTERED) &&
	    list_empty(&adapter_list)) {
		unregister_netevent_notifier(&cxgb4_netevent_nb);
		registered_notifier_block &= ~CXGB4_NETEVENT_REGISTERED;
	}
	mutex_unlock(&uld_mutex);
}

static void notify_rdma_uld(struct adapter *adap, enum cxgb4_control cmd)
{
	if (adap->uld_handle[CXGB4_ULD_RDMA])
		cxgb4_ulds[CXGB4_ULD_RDMA].control(adap->uld_handle[CXGB4_ULD_RDMA],
					     cmd);
}

static void drain_db_fifo(struct adapter *adap, int usecs)
{
	u32 v1, lp_count, hp_count;

	do {
		v1 = t4_read_reg(adap, A_SGE_DBFIFO_STATUS);
		if (is_t4(adap->params.chip)) {
			lp_count = G_LP_COUNT(v1);
			hp_count = G_HP_COUNT(v1);
		} else {
			u32 v2;
			v2 = t4_read_reg(adap, A_SGE_DBFIFO_STATUS2);
			lp_count = G_LP_COUNT_T5(v1);
			hp_count = G_HP_COUNT_T5(v2);
		}

		if (lp_count == 0 && hp_count == 0)
			break;
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(usecs_to_jiffies(usecs));
	} while (1);
}

static void disable_txq_db(struct sge_txq *q)
{
	unsigned long flags;

	spin_lock_irqsave(&q->db_lock, flags);
	q->db_disabled = 1;
	spin_unlock_irqrestore(&q->db_lock, flags);
}

static void enable_txq_db(struct adapter *adap, struct sge_txq *q)
{
	unsigned long flags;

	spin_lock_irqsave(&q->db_lock, flags);
	if (q->db_pidx_inc) {
		wmb();
		t4_write_reg(adap, MYPF_REG(A_SGE_PF_KDOORBELL),
			     V_QID(q->cntxt_id) | V_PIDX(q->db_pidx_inc));
		q->db_pidx_inc = 0;
	}
	q->db_disabled = 0;
	spin_unlock_irqrestore(&q->db_lock, flags);
}

static void disable_dbs(struct adapter *adap)
{
	int i;

	for_each_ethrxq(&adap->sge, i)
		disable_txq_db(&adap->sge.ethtxq[i].q);
	for_each_ofldrxq(&adap->sge, i)
		disable_txq_db(&adap->sge.ofldtxq[i].q);
	for_each_port(adap, i)
		disable_txq_db(&adap->sge.ctrlq[i].q);
}

static void enable_dbs(struct adapter *adap)
{
	int i;

	for_each_ethrxq(&adap->sge, i)
		enable_txq_db(adap, &adap->sge.ethtxq[i].q);
	for_each_ofldrxq(&adap->sge, i)
		enable_txq_db(adap, &adap->sge.ofldtxq[i].q);
	for_each_port(adap, i)
		enable_txq_db(adap, &adap->sge.ctrlq[i].q);
}

static void process_db_full(struct work_struct *work)
{
	struct adapter *adap;

	adap = container_of(work, struct adapter, db_full_task);

	drain_db_fifo(adap, dbfifo_drain_delay);
	enable_dbs(adap);
	notify_rdma_uld(adap, CXGB4_CONTROL_DB_EMPTY);
	adap->db_stats.db_empty++;
	if (CHELSIO_CHIP_VERSION(adap->params.chip) <= CHELSIO_T5)
		t4_set_reg_field(adap, A_SGE_INT_ENABLE3,
				 F_DBFIFO_HP_INT | F_DBFIFO_LP_INT,
				 F_DBFIFO_HP_INT | F_DBFIFO_LP_INT);
	else
		t4_set_reg_field(adap, A_SGE_INT_ENABLE3,
				 F_DBFIFO_LP_INT, F_DBFIFO_LP_INT);
}

static void sync_txq_pidx(struct adapter *adap, struct sge_txq *q)
{
	u16 hw_pidx, hw_cidx;
	int ret;
	unsigned long flags;

	spin_lock_irqsave(&q->db_lock, flags);
	ret = read_eq_indices(adap, (u16)q->cntxt_id, &hw_pidx, &hw_cidx);
	if (ret)
		goto out;
	if (q->db_pidx != hw_pidx) {
		u16 delta;
		u32 val;

		if (q->db_pidx >= hw_pidx)
			delta = q->db_pidx - hw_pidx;
		else
			delta = q->size - hw_pidx + q->db_pidx;

		if (is_t4(adap->params.chip))
			val = V_PIDX(delta);
		else
			val = V_PIDX_T5(delta);
		wmb();
		t4_write_reg(adap, MYPF_REG(A_SGE_PF_KDOORBELL),
			     V_QID(q->cntxt_id) | val);
	}
out:
	q->db_disabled = 0;
	q->db_pidx_inc = 0;
	spin_unlock_irqrestore(&q->db_lock, flags);
	if (ret)
		CH_WARN(adap, "DB drop recovery failed.\n");
}

static void recover_all_queues(struct adapter *adap)
{
	int i;

	for_each_ethrxq(&adap->sge, i)
		sync_txq_pidx(adap, &adap->sge.ethtxq[i].q);
	for_each_ofldrxq(&adap->sge, i)
		sync_txq_pidx(adap, &adap->sge.ofldtxq[i].q);
	for_each_port(adap, i)
		sync_txq_pidx(adap, &adap->sge.ctrlq[i].q);
}

static void process_db_drop(struct work_struct *work)
{
	struct adapter *adap = container_of(work, struct adapter, db_drop_task);

	if (is_t4(adap->params.chip)) {
		drain_db_fifo(adap, dbfifo_drain_delay);
		notify_rdma_uld(adap, CXGB4_CONTROL_DB_DROP);
		drain_db_fifo(adap, dbfifo_drain_delay);
		recover_all_queues(adap);
		drain_db_fifo(adap, dbfifo_drain_delay);
		enable_dbs(adap);
		notify_rdma_uld(adap, CXGB4_CONTROL_DB_EMPTY);
	} else if (is_t5(adap->params.chip)) {
		u32 dropped_db = t4_read_reg(adap, 0x010ac);
		u16 qid = (dropped_db >> 15) & 0x1ffff;
		u16 pidx_inc = dropped_db & 0x1fff;
		u64 bar2_qoffset;
		unsigned int bar2_qid;
		int ret;

		ret = t4_bar2_sge_qregs(adap, qid, T4_BAR2_QTYPE_EGRESS, 0,
					&bar2_qoffset, &bar2_qid);
		if (ret)
			dev_err(adap->pdev_dev, "doorbell drop recovery: "
				"qid=%d, pidx_inc=%d\n", qid, pidx_inc);
		else
			writel(V_PIDX_T5(pidx_inc) | V_QID(bar2_qid),
			       adap->bar2 + bar2_qoffset + SGE_UDB_KDOORBELL);

		/* Re-enable BAR2 WC */
		t4_set_reg_field(adap, A_SGE_DOORBELL_THROTTLE_CONTROL,
				 F_CLRCOALESCEDISABLE,
				 F_CLRCOALESCEDISABLE);
	}

	if (CHELSIO_CHIP_VERSION(adap->params.chip) <= CHELSIO_T5)
		t4_set_reg_field(adap, A_SGE_DOORBELL_CONTROL, F_DROPPED_DB, 0);
}

void t4_db_full(struct adapter *adap)
{
	if (is_t4(adap->params.chip)) {
		disable_dbs(adap);
		notify_rdma_uld(adap, CXGB4_CONTROL_DB_FULL);
		t4_set_reg_field(adap, A_SGE_INT_ENABLE3,
				 F_DBFIFO_HP_INT | F_DBFIFO_LP_INT, 0);
		queue_work(adap->workq, &adap->db_full_task);
	}
	adap->db_stats.db_full++;
}

void t4_db_dropped(struct adapter *adap)
{
	if (is_t4(adap->params.chip)) {
		disable_dbs(adap);
		notify_rdma_uld(adap, CXGB4_CONTROL_DB_FULL);
	}
	queue_work(adap->workq, &adap->db_drop_task);
	adap->db_stats.db_drop++;
}

static void notify_ulds(struct adapter *adap, enum cxgb4_state new_state)
{
	unsigned int i;

	for (i = 0; i < CXGB4_ULD_MAX; i++) {
		mutex_lock(&adap->uld_mutex);
		if (adap->uld_handle[i])
			cxgb4_ulds[i].state_change(adap->uld_handle[i], new_state);
		mutex_unlock(&adap->uld_mutex);
	}
}

/**
 *	cxgb4_register_uld - register an upper-layer driver
 *	@type: the ULD type
 *	@p: the ULD methods
 *
 *	Registers an upper-layer driver with this driver and notifies the ULD
 *	about any presently available devices that support its type.  Returns
 *	%-EBUSY if a ULD of the same type is already registered.
 */
int cxgb4_register_uld(enum cxgb4_uld type, const struct cxgb4_uld_info *p)
{
	int ret = 0;
	struct adapter *adap;

	if (type >= CXGB4_ULD_MAX)
		return -EINVAL;
	mutex_lock(&uld_mutex);
	if (cxgb4_ulds[type].add) {
		ret = -EBUSY;
		goto out;
	}
	cxgb4_ulds[type] = *p;
	list_for_each_entry(adap, &adapter_list, list_node) {
		mutex_lock(&adap->uld_mutex);
		uld_attach(adap, type);
		mutex_unlock(&adap->uld_mutex);
	}
out:	mutex_unlock(&uld_mutex);

	return ret;
}
EXPORT_SYMBOL(cxgb4_register_uld);

/**
 *	cxgb4_unregister_uld - unregister an upper-layer driver
 *	@type: the ULD type
 *
 *	Unregisters an existing upper-layer driver.
 */
int cxgb4_unregister_uld(enum cxgb4_uld type)
{
	struct adapter *adap;

	if (type >= CXGB4_ULD_MAX)
		return -EINVAL;
	mutex_lock(&uld_mutex);
	list_for_each_entry(adap, &adapter_list, list_node) {
		mutex_lock(&adap->uld_mutex);
		adap->uld_handle[type] = NULL;
		mutex_unlock(&adap->uld_mutex);
	}
	cxgb4_ulds[type].add = NULL;
	mutex_unlock(&uld_mutex);
	return 0;
}
EXPORT_SYMBOL(cxgb4_unregister_uld);

#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

#ifndef CONFIG_CHELSIO_BYPASS
/*
 * Recurring task to kick the Adapter Shutdown Watchdog Timer.  This gets set
 * up when a non-zero Host Deadman Watchdog Timer has been specified
 * (deadman_watchdog module parameter).
 */
static void deadman_watchdog_task(struct work_struct *work)
{
	struct adapter *adapter = container_of(work, struct adapter,
					       deadman_watchdog_task.work);
	int ret, port;

	/*
	 * Kick the Adapter Shutdown Watchdog Timer and schedule the next time
	 * we get called.  Note that we reschedule ourselves at half the
	 * period of the watchdog timer so we can successfully come and kick
	 * it before it expires.
	 */
	ret = t4_config_watchdog(adapter, adapter->mbox, adapter->pf, 0,
				 deadman_watchdog[0],
				 deadman_watchdog[1] ?
				 FW_WATCHDOG_ACTION_PAUSEOFF :
				 FW_WATCHDOG_ACTION_SHUTDOWN);
 
	/*
	 * If the firmware WATCHDOG command succeeds, it' and the chip are
	 * still alive so schedule our next Watchdog Ping and return.
	 */
	if (ret == 0) {
		schedule_delayed_work(&adapter->deadman_watchdog_task,
				      (HZ * deadman_watchdog[0]) / 1000 / 2);
		return;
	}
 
	/*
	 * Otherwise, the firmware and/or chip are in trouble so issue error
	 * messages and mark all the adapter interfaces as down.  Note that
	 * normally we'd also call t4_enable_vi() to disable the Virtual
	 * Interfaces but if the firmware/chip are truly down, that would
	 * most likely lead to a long firmware command timeout for every
	 * interface.  So we don't do that here.
	 */
	t4_shutdown_adapter(adapter);
	for_each_port(adapter, port) {
		struct net_device *dev = adapter->port[port];
 
		netif_tx_stop_all_queues(dev);
		netif_carrier_off(dev);
		dev_err(adapter->pdev_dev, "%s stopped\n", dev->name);
	}
	dev_err(adapter->pdev_dev, "unable to contact firmware (%d); marked"
		" all interfaces as down\n", -ret);
}
#endif /* !CONFIG_CHELSIO_BYPASS */

/**
 *	cxgb_up - enable the adapter
 *	@adap: adapter being enabled
 *
 *	Called when the first port is enabled, this function performs the
 *	actions necessary to make an adapter operational, such as completing
 *	the initialization of HW modules, and enabling interrupts.
 *
 *	Must be called with the rtnl lock held.
 */
static int cxgb_up(struct adapter *adap)
{
	int err;

	err = setup_sge_queues(adap);
	if (err)
		goto out;
	err = setup_rss(adap);
	if (err)
		goto freeq;

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	if (is_offload(adap))
		setup_loopback(adap);
#endif

	if (adap->flags & USING_MSIX) {
		name_msix_vecs(adap);
		err = request_irq(adap->msix_info[0].vec, t4_nondata_intr, 0,
				  adap->msix_info[0].desc, adap);
		if (err)
			goto irq_err;

		err = request_msix_queue_irqs(adap);
		if (err) {
			free_irq(adap->msix_info[0].vec, adap);
			goto irq_err;
		}
	} else {
		err = request_irq(adap->pdev->irq, t4_intr_handler(adap),
				  (adap->flags & USING_MSI) ? 0 : IRQF_SHARED,
				  adap->name, adap);
		if (err)
			goto irq_err;
	}
	enable_rx(adap);
	t4_sge_start(adap);
	t4_intr_enable(adap);
	adap->flags |= FULL_INIT_DONE;
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	notify_ulds(adap, CXGB4_STATE_UP);
#endif

	/* Initialize hash mac addr list */
	INIT_LIST_HEAD(&adap->mac_hlist);

#ifndef CONFIG_CHELSIO_BYPASS
	/*
	 * If a non-zero Host Deadman Watchdog Timer has been specified, then
	 * set up the Adapter Shutdown Watchdog Timer and schedule our
	 * recurring task to keep kicking the watchdog ...
	 */
	if (deadman_watchdog[0]) {
		INIT_DELAYED_WORK(&adap->deadman_watchdog_task,
				  deadman_watchdog_task);

		err = t4_config_watchdog(adap, adap->mbox, adap->pf, 0,
					 deadman_watchdog[0],
					 deadman_watchdog[1] ?
					 FW_WATCHDOG_ACTION_PAUSEOFF :
					 FW_WATCHDOG_ACTION_SHUTDOWN);

		/*
		 * If there's an error there's not point in scheduling our
		 * recurring watchdog task but we want to let the system
		 * adminitrator know about this [non-fatal] problem.
		 */
		if (err) {
			dev_err(adap->pdev_dev, "Unable to schedule firmware Adapter "
				"Shutdown/Pauseoff Watchdog timer: error %d\n", -err);
			err = 0;
		} else {
			schedule_delayed_work(&adap->deadman_watchdog_task,
					(HZ * deadman_watchdog[0]) / 1000 / 2);
			dev_info(adap->pdev_dev,
				 "Successfully scheduled firmware Adapter "
				 "%s Watchdog timer with %d ms period\n",
				 deadman_watchdog[1] ? "Pauseoff" : "Shutdown",
				 deadman_watchdog[0]);
		}
	}
#endif /* !CONFIG_CHELSIO_BYPASS */

 out:
	return err;
 irq_err:
	CH_ERR(adap, "request_irq failed, err %d\n", err);
 freeq:
	t4_free_sge_resources(adap);
	goto out;
}

static void cxgb_down(struct adapter *adapter)
{

#ifndef CONFIG_CHELSIO_BYPASS
	/* If a non-zero Host Deadman Watchdog Timer has been specified, then
	 * cancel our recurring task to kick the Adapter Shutdown Watchdog and
	 * then disable the watchdog.  We do it in this order to prevent a race.
	 */
	if (deadman_watchdog[0]) {
		cancel_delayed_work_sync(&adapter->deadman_watchdog_task);
		t4_config_watchdog(adapter, adapter->mbox, adapter->pf, 0,
				   0, deadman_watchdog[1] ?
				   FW_WATCHDOG_ACTION_PAUSEOFF :
				   FW_WATCHDOG_ACTION_SHUTDOWN);
	}
#endif /* !CONFIG_CHELSIO_BYPASS */

	cancel_work_sync(&adapter->tid_release_task);
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	cancel_work_sync(&adapter->db_full_task);
	cancel_work_sync(&adapter->db_drop_task);
#endif

	t4_sge_stop(adapter);
	t4_free_sge_resources(adapter);
	adapter->flags &= ~FULL_INIT_DONE;
}

/*
 * Release resources when all the ports and offloading have been stopped.
 */
static int cxgb_open(struct net_device *dev)
{
	int err;
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;

	/*
	 * If we don't have a connection to the firmware there's nothing we
	 * can do.
	 */
	if (!(adapter->flags & FW_OK))
		return -ENXIO;

	netif_carrier_off(dev);

	if (!(adapter->flags & FULL_INIT_DONE)) {
		err = cxgb_up(adapter);
		if (err < 0)
			return err;
	}

	err = link_start(dev);
	if (err)
		return err;

	netif_tx_start_all_queues(dev);

	return 0;
}

static int cxgb_close(struct net_device *dev)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;

	netif_tx_stop_all_queues(dev);
	netif_carrier_off(dev);
	return t4_enable_vi(adapter, adapter->mbox, pi->viid, false, false);
}

/*
 * driver-specific ioctl support
 */

/* Return an error number if the indicated filter isn't writable ...
 */
int writable_filter(struct filter_entry *f)
{
	if (f->locked)
		return -EPERM;
	if (f->pending)
		return -EBUSY;

	return 0;
}

#ifdef CONFIG_CHELSIO_T4_OFFLOAD

int cxgb4_create_server_filter(const struct net_device *dev, unsigned int stid,
		__be32 sip, __be16 sport, __be16 vlan,
		unsigned int queue, unsigned char port, unsigned char mask)
{
	int ret;
	struct filter_entry *f;
	struct adapter *adap;
	int i;
	u8 *val;

	adap = netdev2adap(dev);

	/* Adjust stid to correct filter index */
	stid -= adap->tids.sftid_base;
	stid += adap->tids.nftids;

	/* Check to make sure the filter requested is writable ...
	 */
	f = &adap->tids.ftid_tab[stid];
	ret = writable_filter(f);
	if (ret)
		return ret;

	/* Clear out any old resources being used by the filter before
	 * we start constructing the new filter.
	 */
	if (f->valid)
		clear_filter(adap, f);

	/* Clear out filter specifications */
	memset(&f->fs, 0, sizeof(struct ch_filter_specification));
	f->fs.val.lport = cpu_to_be16(sport);
	f->fs.mask.lport  = ~0;
	val = (u8 *)&sip;
	if ((val[0] | val[1] | val[2] | val[3]) != 0) {
		for (i = 0; i < 4; i++) {
			f->fs.val.lip[i] = val[i];
			f->fs.mask.lip[i] = ~0;
		}
		if (adap->params.tp.vlan_pri_map & F_PORT) {
			f->fs.val.iport = port;
			f->fs.mask.iport = mask;
		}
	}

	if (adap->params.tp.vlan_pri_map & F_PROTOCOL) {
		f->fs.val.proto = IPPROTO_TCP;
		f->fs.mask.proto = ~0;
	}

	/*
	 * This code demonstrates how one would selectively Offload
	 * (TOE) certain incoming connections by using the extended
	 * "Filter Information" capabilities of Server Control Blocks
	 * (SCB).  (See "Classification and Filtering" in the T4 Data
	 * Book for a description of Ingress Packet pattern matching
	 * capabilities.  See also documentation on the
	 * TP_VLAN_PRI_MAP register.)  Because this selective
	 * Offloading is happening in the chip, this allows
	 * non-Offloading and Offloading drivers to coexist.  For
	 * example, an Offloading Driver might be running in a
	 * Hypervisor while non-Offloading vNIC Drivers might be
	 * running in Virtual Machines.
	 *
	 * This particular example code demonstrates how one would
	 * selectively Offload incoming connections based on VLANs.
	 * We allow one VLAN to be designated as the "Offloading
	 * VLAN".  Ingress SYNs on this Offload VLAN will match the
	 * filter which we put into the Listen SCB and will result in
	 * Offloaded Connections on that VLAN.  Incoming SYNs on other
	 * VLANs will not match and will go through normal NIC
	 * processing.
	 *
	 * This is not production code since one would want a lot more
	 * infrastructure to allow a variety of filter specifications
	 * on a per-server basis.  But this demonstrates the
	 * fundamental mechanisms one would use to build such an
	 * infrastructure.
	 *
	 */
	if (vlan && (adap->params.tp.vlan_pri_map & F_VLAN)) {
		f->fs.val.ivlan_vld = 1;
		f->fs.val.ivlan = be16_to_cpu(vlan);
		f->fs.mask.ivlan_vld = ~0;
		f->fs.mask.ivlan = ~0;
	}

	f->fs.dirsteer = 1;
	f->fs.iq = queue;
	/* Mark filter as locked */
	f->locked = 1;
	f->fs.rpttid = 1;

	/* Save the actual tid. We need this to get the corresponding
	 * filter entry structure in filter_rpl.
	 */
	f->tid = stid + adap->tids.ftid_base;
	ret = set_filter_wr(adap, stid, GFP_KERNEL);
	if (ret) {
		clear_filter(adap, f);
		return ret;
	}

	return 0;
}
EXPORT_SYMBOL(cxgb4_create_server_filter);

int cxgb4_remove_server_filter(const struct net_device *dev, unsigned int stid,
		unsigned int queue, bool ipv6)
{
	int ret;
	struct filter_entry *f;
	struct adapter *adap;

	adap = netdev2adap(dev);

	/* Adjust stid to correct filter index */
	stid -= adap->tids.sftid_base;
	stid += adap->tids.nftids;

	f = &adap->tids.ftid_tab[stid];
	/* Unlock the filter */
	f->locked = 0;

	ret = delete_filter(adap, stid, GFP_KERNEL);
	if (ret)
		return ret;

	return 0;
}
EXPORT_SYMBOL(cxgb4_remove_server_filter);

int cxgb4_filter_field_shift(const struct net_device *dev, int filter_sel)
{
	return t4_filter_field_shift(netdev2adap(dev), filter_sel);
}
EXPORT_SYMBOL(cxgb4_filter_field_shift);

#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

/*
 * net_device operations
 */

/* IEEE 802.3 specified MDIO devices */
enum {
	MDIO_DEV_PMA_PMD = 1,
	MDIO_DEV_VEND2   = 31
};

static int cxgb_ioctl(struct net_device *dev, struct ifreq *req, int cmd)
{
	int ret = 0, mmd;
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;
	struct mii_ioctl_data *data = (struct mii_ioctl_data *)&req->ifr_data;

	switch (cmd) {
	case SIOCGMIIPHY:
		data->phy_id = pi->mdio_addr;
		break;
	case SIOCGMIIREG: {
		u32 val;

		if (pi->link_cfg.supported & FW_PORT_CAP_SPEED_10G) {
			mmd = data->phy_id >> 8;
			if (!mmd)
				mmd = MDIO_DEV_PMA_PMD;
			else if (mmd > MDIO_DEV_VEND2)
				return -EINVAL;

			ret = t4_mdio_rd(adapter, adapter->mbox,
					 data->phy_id & 0x1f, mmd,
					 data->reg_num, &val);
		} else
			ret = t4_mdio_rd(adapter, adapter->mbox,
					 data->phy_id & 0x1f, 0,
					 data->reg_num & 0x1f, &val);
		if (!ret)
			data->val_out = val;
		break;
	}
	case SIOCSMIIREG:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (pi->link_cfg.supported & FW_PORT_CAP_SPEED_10G) {
			mmd = data->phy_id >> 8;
			if (!mmd)
				mmd = MDIO_DEV_PMA_PMD;
			else if (mmd > MDIO_DEV_VEND2)
				return -EINVAL;

			ret = t4_mdio_wr(adapter, adapter->mbox,
					 data->phy_id & 0x1f, mmd,
					 data->reg_num, data->val_in);
		} else
			ret = t4_mdio_wr(adapter, adapter->mbox,
					 data->phy_id & 0x1f, 0,
					 data->reg_num & 0x1f, data->val_in);
		break;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
	case SIOCGHWTSTAMP:
		return copy_to_user(req->ifr_data, &pi->tstamp_config,
				    sizeof(pi->tstamp_config)) ?
			-EFAULT : 0;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
	case SIOCSHWTSTAMP:
		if (copy_from_user(&pi->tstamp_config, req->ifr_data,
				   sizeof(pi->tstamp_config)))
			return -EFAULT;
#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
		/* For T5+ adapters */
		if (!is_t4(adapter->params.chip)) {
			switch (pi->tstamp_config.tx_type) {
			case HWTSTAMP_TX_OFF:
			case HWTSTAMP_TX_ON:
				break;
			default:
				return -ERANGE;
			}

			switch (pi->tstamp_config.rx_filter) {
			case HWTSTAMP_FILTER_NONE:
				pi->rxtstamp = false;
				break;
			case HWTSTAMP_FILTER_PTP_V1_L4_EVENT:
			case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
				cxgb4_ptprx_timestamping(pi, pi->port_id,
							 PTP_TS_L4);
				break;
			case HWTSTAMP_FILTER_PTP_V2_EVENT:
				cxgb4_ptprx_timestamping(pi, pi->port_id,
							 PTP_TS_L2_L4);
				break;
			case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
				cxgb4_ptprx_timestamping(pi, pi->port_id,
							 PTP_TS_L2);
				break;
			case HWTSTAMP_FILTER_ALL:
			case HWTSTAMP_FILTER_PTP_V1_L4_SYNC:
			case HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ:
			case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
			case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
			case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
				pi->rxtstamp = true;
				break;
			default:
				pi->tstamp_config.rx_filter =
					HWTSTAMP_FILTER_NONE;
				return -ERANGE;
			}

			if ((pi->tstamp_config.tx_type == HWTSTAMP_TX_OFF) &&
			    (pi->tstamp_config.rx_filter ==
			     HWTSTAMP_FILTER_NONE)) {
				if (cxgb4_ptp_txtype(adapter, pi->port_id) >= 0)
					pi->ptp_enable = false;
			}

			if (pi->tstamp_config.rx_filter !=
			    HWTSTAMP_FILTER_NONE) {
				if (cxgb4_ptp_redirect_rx_packet(adapter,
								 pi) >= 0)
					pi->ptp_enable = true;
			}
		} else
#endif
			/* For T4 Adapters */
		{
			switch (pi->tstamp_config.rx_filter) {
			case HWTSTAMP_FILTER_NONE:
				pi->rxtstamp = false;
				break;
			case HWTSTAMP_FILTER_ALL:
				pi->rxtstamp = true;
				break;
			default:
				pi->tstamp_config.rx_filter =
					HWTSTAMP_FILTER_NONE;
				return -ERANGE;
			}
		}
		return copy_to_user(req->ifr_data, &pi->tstamp_config,
				    sizeof(pi->tstamp_config)) ? -EFAULT : 0;
#endif
	case SIOCCHIOCTL:
		return cxgb_extension_ioctl(dev, (void __user *)req->ifr_data);
	default:
		return -EOPNOTSUPP;
	}
	return ret;
}

static int cxgb_change_mtu(struct net_device *dev, int new_mtu)
{
	int ret;
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;

	if (new_mtu < 81)         /* accommodate SACK */
		return -EINVAL;
	ret = t4_set_rxmode(adapter, adapter->mbox, pi->viid, new_mtu, -1, -1,
			    -1, -1, true);
	if (!ret)
		dev->mtu = new_mtu;
	return ret;
}

static int cxgb_set_mac_addr(struct net_device *dev, void *p)
{
	int ret;
	struct sockaddr *addr = p;
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EINVAL;

	ret = t4_change_mac(adapter, adapter->mbox, pi->viid,
			    pi->xact_addr_filt, addr->sa_data, true, true);
	if (ret < 0)
		return ret;

	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
	pi->xact_addr_filt = ret;
	return 0;
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void cxgb_netpoll(struct net_device *dev)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adap = pi->adapter;

	if (adap->flags & USING_MSIX) {
		int i;
		struct sge_eth_rxq *rx = &adap->sge.ethrxq[pi->first_qset];

		for (i = pi->nqsets; i; i--, rx++)
			t4_sge_intr_msix(0, &rx->rspq);
	} else
		t4_intr_handler(adap)(0, adap);
}
#endif

void t4_fatal_err(struct adapter *adap)
{
	int port;

	/* Avoid race between multiple fatal error/ AER / EEH
	 * If fatal error reset/recovery is already in progress return
	 */
	if (test_and_set_bit(ADAPTER_ERROR, &adap->adap_err_state))
		return;

	/* Disable the SGE since ULDs are going to free resources that
	 * could be exposed to the adapter.  RDMA MWs for example...
	 */
	t4_shutdown_adapter(adap);
	for_each_port(adap, port) {
		struct net_device *dev = adap->port[port];

		/* If we get here in very early initialization the network
		 * devices may not have been set up yet.
		 */
		if (dev == NULL)
			continue;

		netif_tx_stop_all_queues(dev);
		netif_carrier_off(dev);
		dev_err(adap->pdev_dev, "%s stopped\n", dev->name);
	}
	dev_alert(adap->pdev_dev, "encountered fatal error, adapter stopped\n");
	if (attempt_err_recovery && adap->eeh_workq)
		queue_work(adap->eeh_workq, &adap->fatal_err_task);
}

void cxgb4_fatal_err(struct net_device *dev)
{
	t4_fatal_err(netdev2adap(dev));
}
EXPORT_SYMBOL(cxgb4_fatal_err);

static void setup_memwin(struct adapter *adap)
{
	u32 nic_win_base = t4_get_util_window(adap, fw_attach);

	t4_setup_memwin(adap, nic_win_base, MEMWIN_NIC);
}

static void setup_memwin_rdma(struct adapter *adap)
{
	if (adap->vres.ocq.size) {
		u32 start;
		unsigned int sz_kb;

		start = t4_read_pcie_cfg4(adap, PCI_BASE_ADDRESS_2, fw_attach);
		start &= PCI_BASE_ADDRESS_MEM_MASK;
		start += OCQ_WIN_OFFSET(adap->pdev, &adap->vres);
		sz_kb = roundup_pow_of_two(adap->vres.ocq.size) >> X_WINDOW_SHIFT;

		/*
		 * Set up RDMA memory window for accessing adapter memory
		 * ranges.  (Read back MA register to ensure that changes
		 * propagate before we attempt to use the new values.)
		 */
		t4_write_reg(adap,
			     PCIE_MEM_ACCESS_REG(A_PCIE_MEM_ACCESS_BASE_WIN, MEMWIN_RDMA),
			     start | V_BIR(1) | V_WINDOW(ilog2(sz_kb)));
		t4_write_reg(adap,
			     PCIE_MEM_ACCESS_REG(A_PCIE_MEM_ACCESS_OFFSET, MEMWIN_RDMA),
			     adap->vres.ocq.start);
		t4_read_reg(adap,
			    PCIE_MEM_ACCESS_REG(A_PCIE_MEM_ACCESS_OFFSET, MEMWIN_RDMA));
	}
}

/*
 * Max # of ATIDs.  The absolute HW max is 16K but we keep it lower.
 */
#define MAX_ATIDS 8192U

#ifdef CONFIG_PO_FCOE
#if MAX_ATIDS > 8192U
#error "MAX_ATIDS > 8192"
#endif
#endif /* CONFIG_PO_FCOE */

/*
 * Phase 0 of initialization: contact FW, obtain config, perform basic init.
 *
 * If the firmware we're dealing with has Configuration File support, then
 * we use that to perform all configuration -- either using the configuration
 * file stored in flash on the adapter or using a filesystem-local file
 * if available.
 *
 * If we don't have configuration file support in the firmware, then we'll
 * have to set things up the old fashioned way with hard-coded register
 * writes and firmware commands ...
 */

/*
 * Tweak configuration based on module parameters, etc.  Most of these have
 * defaults assigned to them by Firmware Configuration Files (if we're using
 * them) but need to be explicitly set if we're using hard-coded
 * initialization.  But even in the case of using Firmware Configuration
 * Files, we'd like to expose the ability to change these via module
 * parameters so these are essentially common tweaks/settings for
 * Configuration Files and hard-coded initialization ...
 */
static int adap_init0_tweaks(struct adapter *adapter)
{
	/*
	 * Fix up various Host-Dependent Parameters like Page Size, Cache
	 * Line Size, etc.  The firmware default is for a 4KB Page Size and
	 * 64B Cache Line Size ...
	 */
	t4_fixup_host_params_compat(adapter, PAGE_SIZE, L1_CACHE_BYTES,
				    T5_LAST_REV);

	/*
	 * Process module parameters which affect early initialization.
	 */
	if (rx_dma_offset != 2 && rx_dma_offset != 0) {
		dev_err(&adapter->pdev->dev,
			"Ignoring illegal rx_dma_offset=%d, using 2\n",
			rx_dma_offset);
		rx_dma_offset = 2;
	}
	t4_set_reg_field(adapter, A_SGE_CONTROL,
			 V_PKTSHIFT(M_PKTSHIFT),
			 V_PKTSHIFT(rx_dma_offset));

	/*
	 * Don't include the "IP Pseudo Header" in CPL_RX_PKT checksums: Linux
	 * adds the pseudo header itself.
	 */
	t4_tp_wr_bits_indirect(adapter, A_TP_INGRESS_CONFIG,
			       F_CSUM_HAS_PSEUDO_HDR, 0);

	return 0;
}

/* 10Gb/s-BT PHY Support. chip-external 10Gb/s-BT PHYs are complex chips
 * unto themselves and they contain their own firmware to perform their
 * tasks ...
 */
static int phy_aq1202_version(const u8 *phy_fw_data,
			      size_t phy_fw_size)
{
	int offset;

	/* At offset 0x8 you're looking for the primary image's
	 * starting offset which is 3 Bytes wide
	 *
	 * At offset 0xa of the primary image, you look for the offset
	 * of the DRAM segment which is 3 Bytes wide.
	 *
	 * The FW version is at offset 0x27e of the DRAM and is 2 Bytes
	 * wide
	 */
	#define be16(__p) (((__p)[0] << 8) | (__p)[1])
	#define le16(__p) ((__p)[0] | ((__p)[1] << 8))
	#define le24(__p) (le16(__p) | ((__p)[2] << 16))

	offset = le24(phy_fw_data + 0x8) << 12;
	offset = le24(phy_fw_data + offset + 0xa);
	return be16(phy_fw_data + offset + 0x27e);

	#undef be16
	#undef le16
	#undef le24
}

static struct info_10gbt_phy_fw {
	unsigned int phy_fw_id;		/* PCI Device ID */
	char *phy_fw_file;		/* /lib/firmware/ PHY Firmware file */
	int (*phy_fw_version)(const u8 *phy_fw_data, size_t phy_fw_size);
	int phy_flash;			/* Has FLASH for PHY Firmware */
} phy_info_array[] = {
	{
		PHY_AQ1202_DEVICEID,
		PHY_AQ1202_FIRMWARE,
		phy_aq1202_version,
		1,
	},
	{
		PHY_BCM84834_DEVICEID,
		PHY_BCM84834_FIRMWARE,
		NULL,
		0,
	},
	{ 0, NULL, NULL },
};

static struct info_10gbt_phy_fw *find_phy_info(int devid)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(phy_info_array); i++) {
		if (phy_info_array[i].phy_fw_id == devid)
			return &phy_info_array[i];
	}
	return NULL;
}

/* Handle updating of chip-external 10Gb/s-BT PHY firmware.  This needs to
 * happen after the FW_RESET_CMD but before the FW_INITIALIZE_CMD.  On error
 * we return a negative error number.  If we transfer new firmware we return 1
 * (from t4_load_phy_fw()).  If we don't do anything we return 0.
 */
static int adap_init0_phy(struct adapter *adap)
{
	const struct firmware *phyf;
	int ret;
	struct info_10gbt_phy_fw *phy_info;

	/* Use the device ID to determine which PHY file to flash.
	 */
	phy_info = find_phy_info(adap->pdev->device);
	if (!phy_info) {
		dev_warn(adap->pdev_dev,
			 "No PHY Firmware file found for this PHY\n");
		return -EOPNOTSUPP;
	}

	/* If we have a T4 PHY firmware file under /lib/firmware/cxgb4/, then
	 * use that. The adapter firmware provides us with a memory buffer
	 * where we can load a PHY firmware file from the host if we want to
	 * override the PHY firmware File in flash.
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
	ret = request_firmware_direct(&phyf, phy_info->phy_fw_file,
				      adap->pdev_dev);
#else
	ret = request_firmware(&phyf, phy_info->phy_fw_file, adap->pdev_dev);
#endif
	if (ret < 0) {
		/* For adapters without FLASH attached to PHY for their
		 * firmware, it's obviously a fatal error if we can't get the
		 * firmware to the adapter.  For adapters with PHY firmware
		 * FLASH storage, it's worth a warning if we can't find the
		 * PHY Firmware but we'll neuter the error ...
		 */
		dev_err(adap->pdev_dev, "unable to find PHY Firmware image "
			"/lib/firmware/%s, error %d\n",
			phy_info->phy_fw_file, -ret);
		if (phy_info->phy_flash) {
			int cur_phy_fw_ver = 0;

			t4_phy_fw_ver(adap, &cur_phy_fw_ver);
			dev_warn(adap->pdev_dev, "continuing with, on-adapter "
				 "FLASH copy, version %#x\n", cur_phy_fw_ver);
			ret = 0;
		}

		return ret;
	}

	/* Load PHY Firmware onto adapter.
	 */
	ret = t4_load_phy_fw(adap, MEMWIN_NIC, &adap->win0_lock,
			     phy_info->phy_fw_version,
			     (u8 *)phyf->data, phyf->size);
	if (ret < 0)
		dev_err(adap->pdev_dev, "PHY Firmware transfer error %d\n",
			-ret);
	else if (ret > 0) {
		int new_phy_fw_ver = 0;

		if (phy_info->phy_fw_version)
			new_phy_fw_ver = phy_info->phy_fw_version(phyf->data,
								  phyf->size);
		dev_info(adap->pdev_dev, "Successfully transferred PHY "
			 "Firmware /lib/firmware/%s, version %#x\n",
			 phy_info->phy_fw_file, new_phy_fw_ver);
	}

	release_firmware(phyf);

	return ret;
}

/*
 * Attempt to initialize the adapter via a Firmware Configuration File.
 */
static int adap_init0_config(struct adapter *adapter, int reset)
{
	struct fw_caps_config_cmd caps_cmd;
	const struct firmware *cf;
	unsigned long mtype = 0, maddr = 0;
	u32 finiver, finicsum, cfcsum;
	int ret;
	int config_issued = 0;
	char *fw_config_file, fw_config_file_path[256];
	char *config_name = NULL;

	/*
	 * Reset device if necessary.
	 */
	if (reset) {
		ret = t4_fw_reset(adapter, adapter->mbox,
				  F_PIORSTMODE | F_PIORST);
		if (ret < 0) {
			dev_warn(adapter->pdev_dev, "Firmware reset failed, "
				 "error %d\n", -ret);
			goto bye;
		}
	}

	/* If this is a 10Gb/s-BT adapter make sure the chip-external
	 * 10Gb/s-BT PHYs have up-to-date firmware.  Note that this step needs
	 * to be performed after any global adapter RESET above since some
	 * PHYs only have local RAM copies of the PHY firmware.
	 */
	if (is_10gbt_device(adapter->pdev->device)) {
		ret = adap_init0_phy(adapter);
		if (ret < 0)
			goto bye;
	}
	/*
	 * If we have a T4 configuration file under /lib/firmware/cxgb4/,
	 * then use that.  Otherwise, use the configuration file stored
	 * in the adapter flash ...
	 */
	switch (CHELSIO_CHIP_VERSION(adapter->params.chip)) {
	case CHELSIO_T4:
		if (is_fpga(adapter->params.chip))
			fw_config_file = FW4_FPGA_CFNAME;
		else
			fw_config_file = FW4_CFNAME;
		break;
	case CHELSIO_T5:
		if (is_fpga(adapter->params.chip))
			fw_config_file = FW5_FPGA_CFNAME;
		else
			fw_config_file = FW5_CFNAME;
		break;
	case CHELSIO_T6:
		if (is_fpga(adapter->params.chip))
			fw_config_file = FW6_FPGA_CFNAME;
		else
			fw_config_file = FW6_CFNAME;
		break;
	default:
		CH_ERR(adapter, "Device %d is not supported\n",
		       adapter->pdev->device);
		ret = -EINVAL;
		goto bye;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
	ret = request_firmware_direct(&cf, fw_config_file, adapter->pdev_dev);
#else
	ret = request_firmware(&cf, fw_config_file, adapter->pdev_dev);
#endif
	if (ret < 0) {
		int cfg_addr = t4_flash_cfg_addr(adapter);

		if (cfg_addr < 0) {
			ret = cfg_addr;
			dev_warn(adapter->pdev_dev, "Finding address for firmware config "
				 "file in flash failed, error %d\n", -ret);
			goto bye;
		}

		config_name = "On FLASH";
		mtype = FW_MEMTYPE_CF_FLASH;
		maddr = cfg_addr;
	} else {
		u32 param, val;

		sprintf(fw_config_file_path,
			"/lib/firmware/%s", fw_config_file);
		config_name = fw_config_file_path;

		if (cf->size >= FLASH_CFG_MAX_SIZE) {
			ret = -ENOMEM;
			dev_warn(adapter->pdev_dev, "Not enough memory in flash "
				 "to hold config file, error %d\n", -ret);
		}
		else {
			param = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
				 V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_CF));
			ret = t4_query_params(adapter, adapter->mbox,
					      adapter->pf, 0, 1, &param, &val);
			if (ret == 0) {
				mtype = val >> 8;
				maddr = (val & 0xff) << 16;

				spin_lock(&adapter->win0_lock);
				ret = t4_memory_rw(adapter, MEMWIN_NIC, mtype, maddr,
						   cf->size, (__be32*)cf->data,
						   T4_MEMORY_WRITE);
				spin_unlock(&adapter->win0_lock);
				if (ret)
					dev_warn(adapter->pdev_dev, "Writing firmware config "
						 "file to adapter failed, "
						 "error %d\n", -ret);
			} else
				dev_warn(adapter->pdev_dev, "Finding adapter memory address to "
					 "write firmware config file failed, "
					 "error %d\n", -ret);
		}

		release_firmware(cf);
		if (ret)
			goto bye;
	}

	/*
	 * Issue a Capability Configuration command to the firmware to get it
	 * to parse the Configuration File.  We don't use t4_fw_config_file()
	 * because we want the ability to modify various features after we've
	 * processed the configuration file ...
	 */
	memset(&caps_cmd, 0, sizeof(caps_cmd));
	caps_cmd.op_to_write =
		htonl(V_FW_CMD_OP(FW_CAPS_CONFIG_CMD) |
		      F_FW_CMD_REQUEST |
		      F_FW_CMD_READ);
	caps_cmd.cfvalid_to_len16 =
		htonl(F_FW_CAPS_CONFIG_CMD_CFVALID |
		      V_FW_CAPS_CONFIG_CMD_MEMTYPE_CF(mtype) |
		      V_FW_CAPS_CONFIG_CMD_MEMADDR64K_CF(maddr >> 16) |
		      FW_LEN16(caps_cmd));
	ret = t4_wr_mbox(adapter, adapter->mbox, &caps_cmd, sizeof(caps_cmd),
			 &caps_cmd);

	/* If the CAPS_CONFIG failed with an ENOENT (for a Firmware
	 * Configuration File in FLASH), our last gasp effort is to use the
	 * Firmware Configuration File which is embedded in the firmware.  A
	 * very few early versions of the firmware didn't have one embedded
	 * but we can ignore those.
	 */
	if (ret == -ENOENT) {
		memset(&caps_cmd, 0, sizeof(caps_cmd));
		caps_cmd.op_to_write =
			htonl(V_FW_CMD_OP(FW_CAPS_CONFIG_CMD) |
					F_FW_CMD_REQUEST |
					F_FW_CMD_READ);
		caps_cmd.cfvalid_to_len16 = htonl(FW_LEN16(caps_cmd));
		ret = t4_wr_mbox(adapter, adapter->mbox, &caps_cmd,
				sizeof(caps_cmd), &caps_cmd);
		config_name = "Firmware Default";
	}

	config_issued = 1;
	if (ret < 0)
		goto bye;

	finiver = ntohl(caps_cmd.finiver);
	finicsum = ntohl(caps_cmd.finicsum);
	cfcsum = ntohl(caps_cmd.cfcsum);
	if (finicsum != cfcsum)
		dev_warn(adapter->pdev_dev, "Configuration File checksum "
			 "mismatch: [fini] csum=%#x, computed csum=%#x\n",
			 finicsum, cfcsum);

#ifndef CONFIG_CHELSIO_T4_OFFLOAD
	/*
	 * If we're a pure NIC driver then disable all offloading facilities.
	 * This will allow the firmware to optimize aspects of the hardware
	 * configuration which will result in improved performance.
	 */
	caps_cmd.niccaps &= htons(~FW_CAPS_CONFIG_NIC_ETHOFLD);
	if (!(use_ddr_filters && (is_t5(adapter->params.chip) ||
				  is_t6(adapter->params.chip))))
		caps_cmd.niccaps &= htons(~(FW_CAPS_CONFIG_NIC_HASHFILTER));
	caps_cmd.toecaps = 0;
	caps_cmd.iscsicaps = 0;
	caps_cmd.rdmacaps = 0;
	caps_cmd.fcoecaps = 0;
#endif

	/*
	 * And now tell the firmware to use the configuration we just loaded.
	 */
	caps_cmd.op_to_write =
		htonl(V_FW_CMD_OP(FW_CAPS_CONFIG_CMD) |
		      F_FW_CMD_REQUEST |
		      F_FW_CMD_WRITE);
	caps_cmd.cfvalid_to_len16 = htonl(FW_LEN16(caps_cmd));
	ret = t4_wr_mbox(adapter, adapter->mbox, &caps_cmd, sizeof(caps_cmd),
			 NULL);
	if (ret < 0) {
		dev_warn(adapter->pdev_dev, "Unable to finalize Firmware Capabilities "
			"%d\n", -ret);
		goto bye;
	}

	/*
	 * Tweak configuration based on system architecture, module
	 * parameters, etc.
	 */
	ret = adap_init0_tweaks(adapter);
	if (ret < 0)
		goto bye;

	/*
	 * And finally tell the firmware to initialize itself using the
	 * parameters from the Configuration File.
	 */
	ret = t4_fw_initialize(adapter, adapter->mbox);
	if (ret < 0) {
		dev_warn(adapter->pdev_dev, "Initializing Firmware failed, "
			 "error %d\n", -ret);
		goto bye;
	}

	/* Emit Firmware Configuration File information and return
	 * successfully.
	 */
	dev_info(adapter->pdev_dev, "Successfully configured using Firmware "
		 "Configuration File \"%s\", version %#x, computed checksum %#x\n",
		 config_name, finiver, cfcsum);
	return 0;

	/*
	 * Something bad happened.  Return the error ...  (If the "error"
	 * is that there's no Configuration File on the adapter we don't
	 * want to issue a warning since this is fairly common.)
	 */
bye:
	if (config_issued && ret != -ENOENT)
		dev_warn(adapter->pdev_dev, "Configuration error %d. "
			 "Configuration file \"%s\".\n",
			 -ret, config_name);
	return ret;
}

static struct fw_info fw_info_array[] = {
	{
		.chip = CHELSIO_T4,
		.fs_name = FW4_CFNAME,
		.fw_mod_name = FW4_FNAME,
		.fw_hdr = {
			.chip = FW_HDR_CHIP_T4,
			.fw_ver = __cpu_to_be32(FW_VERSION(T4)),
			.intfver_nic = FW_INTFVER(T4, NIC),
			.intfver_vnic = FW_INTFVER(T4, VNIC),
			.intfver_ofld = FW_INTFVER(T4, OFLD),
			.intfver_ri = FW_INTFVER(T4, RI),
			.intfver_iscsipdu = FW_INTFVER(T4, ISCSIPDU),
			.intfver_iscsi = FW_INTFVER(T4, ISCSI),
			.intfver_fcoepdu = FW_INTFVER(T4, FCOEPDU),
			.intfver_fcoe = FW_INTFVER(T4, FCOE),
		},
	}, {
		.chip = CHELSIO_T5,
		.fs_name = FW5_CFNAME,
		.fw_mod_name = FW5_FNAME,
		.fw_hdr = {
			.chip = FW_HDR_CHIP_T5,
			.fw_ver = __cpu_to_be32(FW_VERSION(T5)),
			.intfver_nic = FW_INTFVER(T5, NIC),
			.intfver_vnic = FW_INTFVER(T5, VNIC),
			.intfver_ofld = FW_INTFVER(T5, OFLD),
			.intfver_ri = FW_INTFVER(T5, RI),
			.intfver_iscsipdu = FW_INTFVER(T5, ISCSIPDU),
			.intfver_iscsi = FW_INTFVER(T5, ISCSI),
			.intfver_fcoepdu = FW_INTFVER(T5, FCOEPDU),
			.intfver_fcoe = FW_INTFVER(T5, FCOE),
		},
	}, {
		.chip = CHELSIO_T6,
		.fs_name = FW6_CFNAME,
		.fw_mod_name = FW6_FNAME,
		.fw_hdr = {
			.chip = FW_HDR_CHIP_T6,
			.fw_ver = __cpu_to_be32(FW_VERSION(T6)),
			.intfver_nic = FW_INTFVER(T6, NIC),
			.intfver_vnic = FW_INTFVER(T6, VNIC),
			.intfver_ofld = FW_INTFVER(T6, OFLD),
			.intfver_ri = FW_INTFVER(T6, RI),
			.intfver_iscsipdu = FW_INTFVER(T6, ISCSIPDU),
			.intfver_iscsi = FW_INTFVER(T6, ISCSI),
			.intfver_fcoepdu = FW_INTFVER(T6, FCOEPDU),
			.intfver_fcoe = FW_INTFVER(T6, FCOE),
		},
	}

};

static struct fw_info *find_fw_info(int chip)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(fw_info_array); i++) {
		if (fw_info_array[i].chip == chip)
			return (&fw_info_array[i]);
	}
	return (NULL);
}

static int adap_init_check_config(struct adapter *adap, int reset)
{
	u32 params, val;
	int ret;

	dev_info(adap->pdev_dev, "Coming up as MASTER: "
		 "Initializing adapter\n");

	/* Find out whether we're dealing with a version of the
	 * firmware which has configuration file support.
	 */
	params = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
		     V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_CF));
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1,
			      &params, &val);

	/* If the firmware doesn't support Configuration Files, return
	 * an error.
	 */
	if (ret < 0) {
		dev_err(adap->pdev_dev, "firmware doesn't support "
			"Firmware Configuration Files\n");
		return ret;
	}

	/* The firmware provides us with a memory buffer where we can
	 * load a Configuration File from the host if we want to
	 * override the Configuration File in flash.
	 */
	ret = adap_init0_config(adap, reset);
	if (ret == -ENOENT)
		dev_err(adap->pdev_dev, "no Configuration File "
				"present on adapter.\n");
	if (ret < 0)
		dev_err(adap->pdev_dev, "could not initialize "
				"adapter, error %d\n", -ret);
	return ret;
}

static int adap_init1(struct adapter *adap, struct fw_caps_config_cmd *c)
{
	int ret=0;
	u32 params, val;

	ret = adap_init_check_config(adap, 0); /* reset = 0 */
	if (ret < 0)
		goto bye;

	/* Give the SGE code a chance to pull in anything that it needs ...
	 * Note that this must be called after we retrieve our VPD parameters
	 * in order to know how to convert core ticks to seconds, etc.
	 */
	ret = t4_sge_init(adap);
	if (ret < 0)
		goto bye;

	/* Grab some of our basic fundamental operating parameters.
	 */
#define FW_PARAM_DEV(param) \
	V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) | \
	V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_##param)

#define FW_PARAM_PFVF(param) \
	V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_PFVF) | \
	V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_PFVF_##param)|  \
	V_FW_PARAMS_PARAM_Y(0) | \
	V_FW_PARAMS_PARAM_Z(0)

	/* If we're running on newer firmware, let it know that we're
	 * prepared to deal with encapsulated CPL messages.  Older
	 * firmware won't understand this and we'll just get
	 * unencapsulated messages ...
	 */
	params = FW_PARAM_PFVF(CPLFW4MSG_ENCAP);
	val = 1;
	(void) t4_set_params(adap, adap->mbox, adap->pf, 0, 1, &params, &val);

	/* Find out whether we're allowed to use the T5+ ULPTX MEMWRITE DSGL
	 * capability.  Earlier versions of the firmware didn't have the
	 * ULPTX_MEMWRITE_DSGL so we'll interpret a query failure as no
	 * permission to use ULPTX MEMWRITE DSGL.
	 */
	if (is_t4(adap->params.chip))
		adap->params.ulptx_memwrite_dsgl = false;
	else {
		params = FW_PARAM_DEV(ULPTX_MEMWRITE_DSGL);
		ret = t4_query_params(adap, adap->mbox, adap->pf, 0,
				      1, &params, &val);
		adap->params.ulptx_memwrite_dsgl = (ret == 0 && val != 0);
		t4_write_reg(adap, A_SGE_STAT_CFG, V_STATSOURCE_T5(7) |
			     (is_t5(adap->params.chip) ? V_STATMODE(0) :
			      V_T6_STATMODE(0)));

	}

#undef FW_PARAM_PFVF
#undef FW_PARAM_DEV

bye:
	if (ret != -ETIMEDOUT && ret != -EIO)
		t4_fw_bye(adap, adap->mbox);
	return ret;
}

#ifdef CONFIG_CUDBG
/* 2MB is the maxuimum debug data we can write to adapter flash */
#define DUMP_BUF_SIZE (2 * 1024 * 1024)
static int panic_notify(struct notifier_block *this, unsigned long event,
			void *ptr)
{
	struct adapter *adap = container_of(this, struct adapter, panic_nb);

	dev_info(adap->pdev_dev, "Initialized cxgb4 crash handler");

	adap->flags |= K_CRASH;
	do_collect(adap, adap->dump_buf, DUMP_BUF_SIZE);
	dev_info(adap->pdev_dev, "cxgb4 debug collection succeeded..");

	return NOTIFY_DONE;
}
#endif

static int adap_init0(struct adapter *adap)
{
	int ret;
	u32 v, port_vec;
	enum dev_state state;
	u32 params[7], val[7];
	struct fw_caps_config_cmd caps_cmd;
	int reset = 1;

	/* Grab Firmware Device Log parameters as early as possible so we have
	 * access to it for debugging, etc.
	 */
	ret = t4_init_devlog_params(adap, fw_attach);
	if (ret < 0)
		return !fw_attach ? 0 : ret;

	/*
	 * If we're not attaching to the firmware, there's nothing more we do
	 * here ...
	 */
	if (!fw_attach)
		return 0;

	/* Contact FW, advertising Master capability */
	ret = t4_fw_hello(adap, adap->mbox, adap->mbox, MASTER_MAY, &state);
	if (ret < 0) {
		CH_ERR(adap, "could not connect to FW, error %d\n", -ret);
		return ret;
	}
	if (ret == adap->mbox)
		adap->flags |= MASTER_PF;

	/*
	 * If we're the Master PF Driver and the device is uninitialized,
	 * then let's consider upgrading the firmware ...  (We always want
	 * to check the firmware version number in order to A. get it for
	 * later reporting and B. to warn if the currently loaded firmware
	 * is excessively mismatched relative to the driver.)
	 */
	t4_get_fw_version(adap, &adap->params.fw_vers);
	t4_get_tp_version(adap, &adap->params.tp_vers);
	ret = t4_check_fw_version(adap);
	/* If firmware is too old (not supported by driver) force an update. */
	if (ret == -EFAULT)
		state = DEV_STATE_UNINIT;
	if ((adap->flags & MASTER_PF) && state != DEV_STATE_INIT) {
		struct fw_info *fw_info;
		struct fw_hdr *card_fw;
		const struct firmware *fw;
		const u8 *fw_data = NULL;
		unsigned int fw_size = 0;

		/* This is the firmware whose headers the driver was compiled
		 * against
		 */
		fw_info = find_fw_info(CHELSIO_CHIP_VERSION(adap->params.chip));
		if (fw_info == NULL) {
			CH_ERR(adap,
				"unable to look up firmware information for chip %d.\n",
				CHELSIO_CHIP_VERSION(adap->params.chip));
			return -EINVAL;
		}

		/* allocate memory to read the header of the firmware on the
		 * card
		 */
		card_fw = t4_alloc_mem(sizeof(*card_fw));

		/* Get FW from from /lib/firmware/ */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
		ret = request_firmware_direct(&fw, fw_info->fw_mod_name,
					      adap->pdev_dev);
#else
		ret = request_firmware(&fw, fw_info->fw_mod_name,
				       adap->pdev_dev);
#endif
		if (ret < 0) {
			dev_err(adap->pdev_dev,
				"unable to load firmware image %s, error %d\n",
				fw_info->fw_mod_name, ret);
		} else {
			fw_data = fw->data;
			fw_size = fw->size;
		}

		/* upgrade FW logic */
		ret = t4_prep_fw(adap, fw_info, fw_data, fw_size, card_fw,
				 t4_fw_install, state, &reset);

		/* Cleaning up */
		release_firmware(fw);
		t4_free_mem(card_fw);

		if (ret < 0)
			goto bye;
	}

	/*
	 * Grab VPD parameters.  This should be done after we establish a
	 * connection to the firmware since some of the VPD parameters
	 * (notably the Core Clock frequency) are retrieved via requests to
	 * the firmware.  On the other hand, we need these fairly early on
	 * so we do this right after getting ahold of the firmware.
	 */
	ret = t4_get_vpd_params(adap, &adap->params.vpd);
	if (ret < 0)
		goto bye;

	/*
	 * Find out what ports are available to us.
	 */
	v =
	    V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
	    V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_PORTVEC);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1, &v, &port_vec);
	if (ret < 0)
		goto bye;

#ifdef CHELSIO_T4_DIAGS
	/*
	 * If attach_pf0 is specified we can only access a single port because
	 * the default configuration only provisions a single Virtual Interface
	 * for PF0. So we whack the Port Vector bitmask to only include the
	 * lowest available port number.
	 */
	if (attach_pf0)
		port_vec ^= (port_vec & (port_vec - 1));
#endif

	adap->params.nports = hweight32(port_vec);
	adap->params.portvec = port_vec;

	/* If the firmware is initialized already, emit a simply note to that
	 * effect. Otherwise, it's time to try initializing the adapter.
	 */
	if (state == DEV_STATE_INIT)
		dev_info(adap->pdev_dev, "Coming up as %s: "
			 "Adapter already initialized\n",
			 adap->flags & MASTER_PF ? "MASTER" : "SLAVE");
	else {
		if(adap_init_check_config(adap, reset))
			goto bye;
	}

	/* Give the SGE code a chance to pull in anything that it needs ...
	 * Note that this must be called after we retrieve our VPD parameters
	 * in order to know how to convert core ticks to seconds, etc.
	 */
	ret = t4_sge_init(adap);
	if (ret < 0)
		goto bye;

	if (is_bypass_device(adap->pdev->device))
		adap->params.bypass = 1;

	/*
	 * Grab some of our basic fundamental operating parameters.
	 */
#define FW_PARAM_DEV(param) \
	V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) | \
	V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_##param)

#define FW_PARAM_PFVF(param) \
	V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_PFVF) | \
	V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_PFVF_##param)|  \
	V_FW_PARAMS_PARAM_Y(0) | \
	V_FW_PARAMS_PARAM_Z(0)

	params[0] = FW_PARAM_PFVF(EQ_START);
	params[1] = FW_PARAM_PFVF(L2T_START);
	params[2] = FW_PARAM_PFVF(L2T_END);
	params[3] = FW_PARAM_PFVF(FILTER_START);
	params[4] = FW_PARAM_PFVF(FILTER_END);
	params[5] = FW_PARAM_PFVF(IQFLINT_START);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 6, params, val);
	if (ret < 0)
		goto bye;
	adap->sge.egr_start = val[0];
	adap->l2t_start = val[1];
	adap->l2t_end = val[2];
	adap->tids.ftid_base = val[3];
	adap->tids.nftids = val[4] - val[3] + 1;
	adap->sge.ingr_start = val[5];

	/* T6 TCAM can contain about 4 regions
	 * (Hi-Priority filter, Active, Server and
	 * Normal priority filter regions).
	 */
	if (CHELSIO_CHIP_VERSION(adap->params.chip) > CHELSIO_T5) {
		params[0] = FW_PARAM_PFVF(HPFILTER_START);
		params[1] = FW_PARAM_PFVF(HPFILTER_END);
		ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2,
				      params, val);
		if (ret < 0)
			goto bye;
		adap->tids.hpftid_base = val[0];
		adap->tids.nhpftids = val[1] - val[0] + 1;

		/* Read the raw mps entries. In T6, the last 2 tcam entries
		 * are reserved for raw mac addresses (rawf = 2, one per port).
		 */
		params[0] = FW_PARAM_PFVF(RAWF_START);
		params[1] = FW_PARAM_PFVF(RAWF_END);
		ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2,
				      params, val);
		if (ret == 0) {
			adap->rawf_start = val[0];
			adap->rawf_cnt = val[1] - val[0] + 1;
		}
	}

	/* qids (ingress/egress) returned from firmware can be anywhere
	 * in the range from EQ(IQFLINT)_START to EQ(IQFLINT)_END.
	 * Hence driver needs to allocate memory for this range to
	 * store the queue info. Get the highest IQFLINT/EQ index returned
	 * in FW_EQ_*_CMD.alloc command.
	 */
	params[0] = FW_PARAM_PFVF(EQ_END);
	params[1] = FW_PARAM_PFVF(IQFLINT_END);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2, params, val);
	if (ret < 0)
		goto bye;
	adap->sge.egr_sz = val[0] - adap->sge.egr_start + 1;
	adap->sge.ingr_sz = val[1] - adap->sge.ingr_start + 1;

	adap->sge.egr_map = kcalloc(adap->sge.egr_sz,
				    sizeof(*adap->sge.egr_map), GFP_KERNEL);
	if (!adap->sge.egr_map) {
		ret = -ENOMEM;
		goto bye;
	}

	adap->sge.ingr_map = kcalloc(adap->sge.ingr_sz,
				     sizeof(*adap->sge.ingr_map), GFP_KERNEL);
	if (!adap->sge.ingr_map) {
		ret = -ENOMEM;
		goto bye;
	}

	/* Allocate the memory for the vaious egress queue bitmaps
	 * ie starving_fl, txq_maperr and blocked_fl.
	 */
	adap->sge.starving_fl =	kcalloc(BITS_TO_LONGS(adap->sge.egr_sz),
					sizeof(long), GFP_KERNEL);
	if (!adap->sge.starving_fl) {
		ret = -ENOMEM;
		goto bye;
	}

	adap->sge.txq_maperr = kcalloc(BITS_TO_LONGS(adap->sge.egr_sz),
				       sizeof(long), GFP_KERNEL);
	if (!adap->sge.txq_maperr) {
		ret = -ENOMEM;
		goto bye;
	}

	adap->sge.blocked_fl = kcalloc(BITS_TO_LONGS(adap->sge.egr_sz),
				       sizeof(long), GFP_KERNEL);
	if (!adap->sge.blocked_fl) {
		ret = -ENOMEM;
		goto bye;
	}

	params[0] = FW_PARAM_PFVF(CLIP_START);
	params[1] = FW_PARAM_PFVF(CLIP_END);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2, params, val);
	if (ret < 0)
		goto bye;
	adap->clipt_start = val[0];
	adap->clipt_end = val[1];

	/*
	 * We don't yet have a PARAMs calls to retrieve the number of Traffic
	 * Classes supported by the hardware/firmware so we hard code it here
	 * for now.
	 */
	adap->params.nsched_cls = is_t4(adap->params.chip) ? 15 : 16;

	/* query params related to active filter region */
	params[0] = FW_PARAM_PFVF(ACTIVE_FILTER_START);
	params[1] = FW_PARAM_PFVF(ACTIVE_FILTER_END);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2, params, val);
	/* If Active filter size is set we enable establishing
	 * offload connection through firmware work request
	 */
	if ((val[0] != val[1]) && (ret >= 0)) {
		adap->flags |= FW_OFLD_CONN;
		adap->tids.aftid_base = val[0];
		adap->tids.aftid_end = val[1];
	}

	/* If we're running on newer firmware, let it know that we're
	 * prepared to deal with encapsulated CPL messages.  Older
	 * firmware won't understand this and we'll just get
	 * unencapsulated messages ...
	 */
	params[0] = FW_PARAM_PFVF(CPLFW4MSG_ENCAP);
	val[0] = 1;
	(void)t4_set_params(adap, adap->mbox, adap->pf, 0, 1, params, val);

	/*
	 * Find out whether we're allowed to use the T5+ ULPTX MEMWRITE DSGL
	 * capability.  Earlier versions of the firmware didn't have the
	 * ULPTX_MEMWRITE_DSGL so we'll interpret a query failure as no
	 * permission to use ULPTX MEMWRITE DSGL.
	 */
	if (is_t4(adap->params.chip)) {
		adap->params.ulptx_memwrite_dsgl = false;
	} else {
		params[0] = FW_PARAM_DEV(ULPTX_MEMWRITE_DSGL);
		ret = t4_query_params(adap, adap->mbox, adap->pf, 0,
				      1, params, val);
		adap->params.ulptx_memwrite_dsgl = (ret == 0 && val[0] != 0);
	}

	/*
	 * Get device capabilities so we can determine what resources we need
	 * to manage.
	 */
	memset(&caps_cmd, 0, sizeof(caps_cmd));
	caps_cmd.op_to_write = htonl(V_FW_CMD_OP(FW_CAPS_CONFIG_CMD) |
				     F_FW_CMD_REQUEST | F_FW_CMD_READ);
	caps_cmd.cfvalid_to_len16 = htonl(FW_LEN16(caps_cmd));
	ret = t4_wr_mbox(adap, adap->mbox, &caps_cmd, sizeof(caps_cmd),
			 &caps_cmd);
	if (ret < 0)
		goto bye;
	if ((caps_cmd.niccaps & htons(FW_CAPS_CONFIG_NIC_HASHFILTER)) &&
	     use_ddr_filters && (is_t5(adap->params.chip) ||
		     		 is_t6(adap->params.chip))) {
		if (init_hash_filter(adap) < 0)
			goto bye;
	}

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	if (caps_cmd.toecaps) {
		/* query offload-related parameters */
		params[0] = FW_PARAM_DEV(NTID);
		params[1] = FW_PARAM_PFVF(SERVER_START);
		params[2] = FW_PARAM_PFVF(SERVER_END);
		params[3] = FW_PARAM_PFVF(TDDP_START);
		params[4] = FW_PARAM_PFVF(TDDP_END);
		params[5] = FW_PARAM_DEV(FLOWC_BUFFIFO_SZ);
		ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 6,
				      params, val);
		if (ret < 0)
			goto bye;
		adap->tids.ntids = val[0];
		adap->tids.natids = min(adap->tids.ntids / 2, MAX_ATIDS);

		adap->tids.stid_base = val[1];
		adap->tids.nstids = val[2] - val[1] + 1;
		/*
		 * Setup server filter region. Divide the available filter
		 * region into two parts. Regular filters get 1/3rd and server
		 * filters get 2/3rd part. This is only enabled if workarond
		 * path is enabled.
		 * 1. For regular filters.
		 * 2. Server filter: This are special filters which are used
		 * to redirect SYN packets to offload queue.
		 */
		if (adap->flags & FW_OFLD_CONN && !is_bypass(adap)) {
			unsigned int n_user_filters;
			if (user_filter_perc >= 0 && user_filter_perc <= 100) {
				n_user_filters = mult_frac(adap->tids.nftids,
							   user_filter_perc,
							   100);
			} else {
				/*
				 * If we have invalid value in module-param then,
				 * use default value of 33% for user-filters.
				 */
				n_user_filters = mult_frac(adap->tids.nftids,
							   33, 100);
			}
			adap->tids.sftid_base = adap->tids.ftid_base + n_user_filters;
			adap->tids.nsftids = adap->tids.nftids - n_user_filters;
			adap->tids.nftids = adap->tids.sftid_base -
						adap->tids.ftid_base;
		}
		adap->vres.ddp.start = val[3];
		adap->vres.ddp.size = val[4] - val[3] + 1;
		adap->params.ofldq_wr_cred = val[5];

#ifdef CONFIG_PO_FCOE
		if (ntohs(caps_cmd.fcoecaps) & FW_CAPS_CONFIG_POFCOE_TARGET)
			cxgb_fcoe_init_ddp(adap);
#endif /* CONFIG_PO_FCOE */

		params[0] = FW_PARAM_PFVF(ETHOFLD_START);
		params[1] = FW_PARAM_PFVF(ETHOFLD_END);
		ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2, params, val);
		if ((val[0] != val[1]) && (ret >= 0)) {
			adap->tids.uotid_base = val[0];
			adap->tids.nuotids = val[1] - val[0] + 1;
		}

		adap->params.offload = 1;
	}
	if (caps_cmd.rdmacaps) {
		params[0] = FW_PARAM_PFVF(STAG_START);
		params[1] = FW_PARAM_PFVF(STAG_END);
		params[2] = FW_PARAM_PFVF(RQ_START);
		params[3] = FW_PARAM_PFVF(RQ_END);
		params[4] = FW_PARAM_PFVF(PBL_START);
		params[5] = FW_PARAM_PFVF(PBL_END);
		ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 6,
				      params, val);
		if (ret < 0)
			goto bye;
		adap->vres.stag.start = val[0];
		adap->vres.stag.size = val[1] - val[0] + 1;
		adap->vres.rq.start = val[2];
		adap->vres.rq.size = val[3] - val[2] + 1;
		adap->vres.pbl.start = val[4];
		adap->vres.pbl.size = val[5] - val[4] + 1;

		params[0] = FW_PARAM_PFVF(SRQ_START);
		params[1] = FW_PARAM_PFVF(SRQ_END);
		ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2,
				      params, val);
		if (!ret) {
			adap->vres.srq.start = val[0];
			adap->vres.srq.size = val[1] - val[0] + 1;
		}
 		if (adap->vres.srq.size) {
 			adap->srq = t4_init_srq(adap->vres.srq.size);
 			if (!adap->srq)
 				dev_warn(&adap->pdev->dev, "could not allocate SRQ, continuing\n");
 		}

		params[0] = FW_PARAM_PFVF(SQRQ_START);
		params[1] = FW_PARAM_PFVF(SQRQ_END);
		params[2] = FW_PARAM_PFVF(CQ_START);
		params[3] = FW_PARAM_PFVF(CQ_END);
		params[4] = FW_PARAM_PFVF(OCQ_START);
		params[5] = FW_PARAM_PFVF(OCQ_END);
		ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 6, params,
				      val);
		if (ret < 0)
			goto bye;
		adap->vres.qp.start = val[0];
		adap->vres.qp.size = val[1] - val[0] + 1;
		adap->vres.cq.start = val[2];
		adap->vres.cq.size = val[3] - val[2] + 1;
		adap->vres.ocq.start = val[4];
		adap->vres.ocq.size = val[5] - val[4] + 1;

		params[0] = FW_PARAM_DEV(MAXORDIRD_QP);
		params[1] = FW_PARAM_DEV(MAXIRD_ADAPTER);
		ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2, params,
				      val);
		if (ret < 0) {
			adap->params.max_ordird_qp = 8;
			adap->params.max_ird_adapter = 32 * adap->tids.ntids;
			ret = 0;
		} else {
			adap->params.max_ordird_qp = val[0];
			adap->params.max_ird_adapter = val[1];
		}
		dev_info(adap->pdev_dev,
			 "max_ordird_qp %d max_ird_adapter %d\n",
			 adap->params.max_ordird_qp,
			 adap->params.max_ird_adapter);
	}
	if (caps_cmd.iscsicaps) {
		params[0] = FW_PARAM_PFVF(ISCSI_START);
		params[1] = FW_PARAM_PFVF(ISCSI_END);
		ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2,
				      params, val);
		if (ret < 0)
			goto bye;
		adap->vres.iscsi.start = val[0];
		adap->vres.iscsi.size = val[1] - val[0] + 1;
		if  (ntohs(caps_cmd.iscsicaps) & FW_CAPS_CONFIG_ISCSI_T10DIF)
			adap->params.ulp_t10dif |= ULP_T10DIF_ISCSI;
	}

	/*
	 * On-chip queues are available only on T4 adapters
	 */
	if (is_t4(adap->params.chip)) {
		ret = ocqp_pool_create(adap);
		if (ret) {
			printk(KERN_ERR "%s: could not create OCQP memory pool",
			       __func__);
		} else {
			adap->oc_mw_pa = pci_resource_start(adap->pdev, 2) +
					 (pci_resource_len(adap->pdev, 2) -
					 roundup_pow_of_two(adap->vres.ocq.size));

			adap->oc_mw_kva = ioremap_wc(adap->oc_mw_pa,
						     adap->vres.ocq.size);
		}
	}

#undef FW_PARAM_PFVF
#undef FW_PARAM_DEV
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

	/*
	 * The MTU/MSS Table is initialized by now, so load their values.  If
	 * we're initializing the adapter, then we'll make any modifications
	 * we want to the MTU/MSS Table and also initialize the congestion
	 * parameters.
	 */
	t4_read_mtu_tbl(adap, adap->params.mtus, NULL);
	if (state != DEV_STATE_INIT) {
		int i;

		/*
		 * The default MTU Table contains values 1492 and 1500.
		 * However, for TCP, it's better to have two values which are
		 * a multiple of 8 +/- 4 bytes apart near this popular MTU.
		 * This allows us to have a TCP Data Payload which is a
		 * multiple of 8 regardless of what combination of TCP Options
		 * are in use (always a multiple of 4 bytes) which is
		 * important for performance reasons.  For instance, if no
		 * options are in use, then we have a 20-byte IP header and a
		 * 20-byte TCP header.  In this case, a 1500-byte MSS would
		 * result in a TCP Data Payload of 1500 - 40 == 1460 bytes
		 * which is not a multiple of 8.  So using an MSS of 1488 in
		 * this case results in a TCP Data Payload of 1448 bytes which
		 * is a multiple of 8.  On the other hand, if 12-byte TCP Time
		 * Stamps have been negotiated, then an MTU of 1500 bytes
		 * results in a TCP Data Payload of 1448 bytes which, as
		 * above, is a multiple of 8 bytes ...
		 */
		for (i = 0; i < NMTUS; i++)
			if (adap->params.mtus[i] == 1492) {
				adap->params.mtus[i] = 1488;
				break;
			}

		t4_load_mtus(adap, adap->params.mtus, adap->params.a_wnd,
			     adap->params.b_wnd);
	}
	t4_init_sge_params(adap);
	adap->flags |= FW_OK;
	t4_init_tp_params(adap);

#ifdef CONFIG_CUDBG
	/* cudbg feature is only supported for T5 cards for now */
	if (is_t5(adap->params.chip)) {
		adap->dump_buf = t4_alloc_mem(DUMP_BUF_SIZE);

		if (!adap->dump_buf)
			dev_err(adap->pdev_dev,
				"Not enough memory for debug buffers.\n"
				"Continuing without crash debug collection.");
		else {
			dev_info(adap->pdev_dev,
				 "Registering cxgb4 panic handler.., "
				 "Buffer start address = %p", adap->dump_buf);
			adap->panic_nb.notifier_call = panic_notify;
			adap->panic_nb.priority = INT_MAX;

			atomic_notifier_chain_register(&panic_notifier_list,
						       &adap->panic_nb);
		}
	}
#endif

	adap->params.drv_memwin = MEMWIN_NIC;
	return 0;

	/*
	 * Something bad happened.  If a command timed out or failed with EIO
	 * FW does not operate within its spec or something catastrophic
	 * happened to HW/FW, stop issuing commands.
	 */
bye:
	kfree(adap->sge.egr_map);
	kfree(adap->sge.ingr_map);
	kfree(adap->sge.starving_fl);
	kfree(adap->sge.txq_maperr);
	kfree(adap->sge.blocked_fl);
	if (ret != -ETIMEDOUT && ret != -EIO)
		t4_fw_bye(adap, adap->mbox);
#ifdef CONFIG_PO_FCOE
	cxgb_fcoe_exit_ddp(adap);
#endif /* CONFIG_PO_FCOE */
	return ret;
}

#ifndef PCI_RESET_SLOTBUS
static int pci_parent_bus_reset(struct pci_dev *dev)
{
        u16 ctrl;
        struct pci_dev *pdev;

        if (pci_is_root_bus(dev->bus) || dev->subordinate || !dev->bus->self)
                return -ENOTTY;

        list_for_each_entry(pdev, &dev->bus->devices, bus_list) {
		if (pdev->vendor == 0x1425)
			pci_save_state(pdev);
	}

	/* Assert the Secondary Bus Reset */
	pci_read_config_word(dev->bus->self, PCI_BRIDGE_CONTROL, &ctrl);
	ctrl |= PCI_BRIDGE_CTL_BUS_RESET;
	pci_write_config_word(dev->bus->self, PCI_BRIDGE_CONTROL, ctrl);

	/* Read config again to flush previous write */
	pci_read_config_word(dev->bus->self, PCI_BRIDGE_CONTROL, &ctrl);

	msleep(100);

	/* De-assert the Secondary Bus Reset */
	ctrl &= ~PCI_BRIDGE_CTL_BUS_RESET;
	pci_write_config_word(dev->bus->self, PCI_BRIDGE_CONTROL, ctrl);

	/* Wait for completion */
	msleep(1000);

	list_for_each_entry(pdev, &dev->bus->devices, bus_list) {
		if (pdev->vendor == 0x1425) {
			pci_restore_state(pdev);
			pci_save_state(pdev);
		}
	}
        return 0;
}
#endif

#define FATAL_ERR_RETRY_COUNT 3

static int cxgb_reset_pci(struct adapter *adap, int reset)
{
	int i, ret = 0;

	if (adap->flags & DEV_ENABLED) {
		struct pci_dev *pdev = adap->pdev;

		if (reset) {
			for (i = 0; i < FATAL_ERR_RETRY_COUNT; i++) {
#ifdef PCI_RESET_SLOTBUS
				if (!pci_probe_reset_slot(pdev->slot))
					ret = pci_try_reset_slot(pdev->slot);
				else if (!pci_probe_reset_bus(pdev->bus))
					ret = pci_try_reset_bus(pdev->bus);
#else
				msleep(10);
				ret = pci_parent_bus_reset(pdev);
#endif
				if (!ret)
					break;
			}
		}

		pci_disable_device(pdev);
		adap->flags &= ~DEV_ENABLED;
	}
	return ret;
}

static int t4_fatal_err_detected(struct adapter *adap, int reset)
{
	int i;

	adap->flags &= ~FW_OK;

	if (adap->flags & FULL_INIT_DONE)
		quiesce_rx(adap);

	rtnl_lock();
	spin_lock(&adap->stats_lock);
	for_each_port(adap, i) {
		struct net_device *dev = adap->port[i];

		netif_device_detach(dev);
		netif_carrier_off(dev);
	}
	spin_unlock(&adap->stats_lock);
	rtnl_unlock();

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	if (is_offload(adap)) {

		/* let any in-flight DMA finish */
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(usecs_to_jiffies(1000000));

		/*
		 * Flush any pending skbs from all l2t entries to
		 * ensure that ULD arp failure handlers are not called
		 * after we begin ULD recovery.
		 */
		t4_flush_l2t_arpq(adap->l2t);

		notify_ulds(adap, CXGB4_STATE_START_RECOVERY);
		detach_ulds(adap);
	}
#endif

	/* reenable the SGE */
	t4_set_reg_field(adap, A_SGE_CONTROL, F_GLOBALENABLE, F_GLOBALENABLE);

	if (adap->flags & FULL_INIT_DONE) {
		/* If we allocated filters, free up state associated with any
		 * valid filters ...
		 */
		clear_all_filters(adap);

		disable_interrupts(adap);
		rtnl_lock();
		cxgb_down(adap);
		rtnl_unlock();
	}

	return cxgb_reset_pci(adap, reset);
}

static int cxgb_enable_pci_device(struct adapter *adap)
{
	int i;
	struct pci_dev *pdev = adap->pdev;

	for (i = 0; i < FATAL_ERR_RETRY_COUNT; i++) {
		if (!cxgb_reset_pci(adap, /*reset=*/1)) {
			if (!(adap->flags & DEV_ENABLED)) {
				if (pci_enable_device(pdev)) {
					dev_err(&pdev->dev,
						"Cannot reenable PCI device after reset\n");
					continue;
				}
				adap->flags |= DEV_ENABLED;
			}

			pci_set_master(pdev);
			pci_restore_state(pdev);
			pci_save_state(pdev);
			if (!t4_wait_dev_ready(adap))
				return 0;
		}
	}

	if (adap->flags & DEV_ENABLED) {
		pci_disable_device(pdev);
		adap->flags &= ~DEV_ENABLED;
	}
	return PCI_ERS_RESULT_DISCONNECT;
}

static pci_ers_result_t t4_fatal_slot_reset(struct adapter *adap, bool aer)
{
	struct pci_dev *pdev = adap->pdev;
	int ret, i;
	struct fw_caps_config_cmd c;
	enum dev_state state;

	if (!(adap->flags & DEV_ENABLED)) {
		if (pci_enable_device(pdev)) {
			dev_err(&pdev->dev, "Cannot reenable PCI "
				"device after reset\n");
			return PCI_ERS_RESULT_DISCONNECT;
		}
		adap->flags |= DEV_ENABLED;
	}

	pci_set_master(pdev);
	pci_restore_state(pdev);
	pci_save_state(pdev);

	if (aer)
		pci_cleanup_aer_uncorrect_error_status(pdev);

	if (t4_wait_dev_ready(adap) < 0) {
		ret = cxgb_enable_pci_device(adap);
		if (ret < 0)
			return PCI_ERS_RESULT_DISCONNECT;
	}

	setup_memwin(adap);
	setup_memwin_rdma(adap);

	/* Grab Firmware Device Log parameters as early as possible so we have
	 * access to it for debugging, etc.
	 */
        ret = t4_init_devlog_params(adap, fw_attach);
        if (ret < 0)
               	goto out;

	ret = t4_fw_hello(adap, adap->mbox, adap->mbox, MASTER_MAY, &state);
	if (ret < 0) {
		CH_ERR(adap, "could not connect to FW, error %d\n", -ret);
		goto out;
	}

	adap->params.drv_memwin = MEMWIN_NIC;
	adap->flags |= FW_OK;
	if (ret == adap->mbox)
		adap->flags |= MASTER_PF;

	if (adap_init1(adap, &c))
		goto out;

	t4_sge_init_tasklet(adap);

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	if (t4_reset_l2t(adap->l2t)) {
		dev_alert(adap->pdev_dev, "L2T not empty after reset\n");
		goto out_stop_sge;
	}
#endif
	for_each_port(adap, i) {
		struct port_info *pi = adap2pinfo(adap, i);

		ret = t4_alloc_vi(adap, adap->pf, pi->tx_chan, adap->pf, 0, 1,
				  NULL, NULL);
		if (ret < 0)
			goto out_free_vi;
		pi->viid = ret;
		pi->xact_addr_filt = -1;
	}

	/*
	 * The MTU/MSS Table is initialized by now, so load their values.  If
	 * we're initializing the adapter, then we'll make any modifications
	 * we want to the MTU/MSS Table and also initialize the congestion
	 * parameters.
	 */
	t4_read_mtu_tbl(adap, adap->params.mtus, NULL);
	if (state != DEV_STATE_INIT) {
		int i;

		/*
		 * The default MTU Table contains values 1492 and 1500.
		 * However, for TCP, it's better to have two values which are
		 * a multiple of 8 +/- 4 bytes apart near this popular MTU.
		 * This allows us to have a TCP Data Payload which is a
		 * multiple of 8 regardless of what combination of TCP Options
		 * are in use (always a multiple of 4 bytes) which is
		 * important for performance reasons.  For instance, if no
		 * options are in use, then we have a 20-byte IP header and a
		 * 20-byte TCP header.  In this case, a 1500-byte MSS would
		 * result in a TCP Data Payload of 1500 - 40 == 1460 bytes
		 * which is not a multiple of 8.  So using an MSS of 1488 in
		 * this case results in a TCP Data Payload of 1448 bytes which
		 * is a multiple of 8.  On the other hand, if 12-byte TCP Time
		 * Stamps have been negotiated, then an MTU of 1500 bytes
		 * results in a TCP Data Payload of 1448 bytes which, as
		 * above, is a multiple of 8 bytes ...
		 */
		for (i = 0; i < NMTUS; i++)
			if (adap->params.mtus[i] == 1492) {
				adap->params.mtus[i] = 1488;
				break;
			}

		t4_load_mtus(adap, adap->params.mtus, adap->params.a_wnd,
			     adap->params.b_wnd);
	}

	rtnl_lock();
	if (cxgb_up(adap)) {
		rtnl_unlock();
		goto out_free_vi;
	}
	rtnl_unlock();

	dev_alert(adap->pdev_dev, "adapter recovered from fatal error\n");
	return PCI_ERS_RESULT_RECOVERED;

out_free_vi:
	for_each_port(adap, i)
		if (adap->port[i]) {
			struct port_info *pi = netdev_priv(adap->port[i]);
			if (pi->viid != 0)
				t4_free_vi(adap, adap->mbox, adap->pf,
					   0, pi->viid);
		}
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
out_stop_sge:
#endif
	t4_sge_stop(adap);
out:
	return PCI_ERS_RESULT_DISCONNECT;
}

static pci_ers_result_t t4_fatal_err_resume(struct adapter *adap)
{
	int i, ret;

	rtnl_lock();
	for_each_port(adap, i) {
		struct net_device *dev = adap->port[i];

		if (netif_running(dev)) {
			ret = link_start(dev);
			if (ret) {
				rtnl_unlock();
				goto fail;
			}
			cxgb_set_rxmode(dev);
		}
		netif_device_attach(dev);
	}

	smp_mb__before_atomic();
	clear_bit(ADAPTER_ERROR, &adap->adap_err_state);
	rtnl_unlock();
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	if (is_offload(adap)) {
		attach_ulds(adap);
	}
#endif
	return PCI_ERS_RESULT_RECOVERED;
fail:
	return PCI_ERS_RESULT_DISCONNECT;
}

/* Processes a fatal error.
 * Bring the ports down, reset the chip, bring the ports back up.
 */
static void process_fatal_err(struct work_struct *work)
{
	struct adapter *adap = container_of(work, struct adapter, fatal_err_task);
	int i;
	pci_ers_result_t pci_err = PCI_ERS_RESULT_DISCONNECT;

	pci_err = t4_fatal_err_detected(adap, /*slot reset=*/1);
	if (!pci_err) {
		for (i = 0; i < FATAL_ERR_RETRY_COUNT; i++) {
			pci_err = t4_fatal_slot_reset(adap, 0);
			if (pci_err == PCI_ERS_RESULT_RECOVERED) {
				pci_err = t4_fatal_err_resume(adap);
				if (pci_err != PCI_ERS_RESULT_RECOVERED ) {
					t4_fatal_err_detected(adap, 1);
				} else
					break;
			} else {
				cxgb_reset_pci(adap, 1);
			}
		}
	}

	CH_ALERT(adap, "adapter reset %s\n", pci_err != PCI_ERS_RESULT_RECOVERED ?
					     "failed" : "succeeded");

	/* If recovery failed after multiple attempts, set adapter state to
	 * ADAPTER_DEAD
	 */
	if (pci_err != PCI_ERS_RESULT_RECOVERED)
		set_bit(ADAPTER_DEAD, &adap->adap_err_state);
}

/* EEH callbacks */

static pci_ers_result_t eeh_err_detected(struct pci_dev *pdev,
					 pci_channel_state_t state)
{
	struct adapter *adap = pci_get_drvdata(pdev);

	if (!adap)
		goto out;

	/* Wait over here if fatal error recovery is in progress, if fatal error
	 * recovery fails after multiple attempts we need to break from the
	 * while loop else we will up in an infinite loop.
	 * Since this is called from the aer/eeh stack we cannot return, we
	 * have to wait if recovery is in progress
	 */
	while (test_and_set_bit(ADAPTER_ERROR, &adap->adap_err_state)) {
		if (test_bit(ADAPTER_DEAD, &adap->adap_err_state))
			return PCI_ERS_RESULT_DISCONNECT;
		usleep_range(1000, 2000);
	}

	t4_fatal_err_detected(adap, /*slot reset=*/1);
out:
	return state == pci_channel_io_perm_failure ?
		PCI_ERS_RESULT_DISCONNECT : PCI_ERS_RESULT_NEED_RESET;
}

static pci_ers_result_t eeh_slot_reset(struct pci_dev *pdev)
{
	struct adapter *adap = pci_get_drvdata(pdev);

	if (!adap) {
		pci_restore_state(pdev);
		pci_save_state(pdev);
		return PCI_ERS_RESULT_RECOVERED;
	}

	return t4_fatal_slot_reset(adap, 1);
}

static void eeh_resume(struct pci_dev *pdev)
{
	struct adapter *adap = pci_get_drvdata(pdev);

	if (!adap)
		return;

	t4_fatal_err_resume(adap);
}

static PCI_ERR_HANDLERS_CONST struct pci_error_handlers cxgb4_eeh = {
	.error_detected = eeh_err_detected,
	.slot_reset     = eeh_slot_reset,
	.resume         = eeh_resume,
};

static inline bool is_x_10g_port(const struct link_config *lc)
{
	return ((lc->supported & FW_PORT_CAP_SPEED_10G) != 0 ||
		(lc->supported & FW_PORT_CAP_SPEED_40G) != 0 ||
		(lc->supported & FW_PORT_CAP_SPEED_100G) != 0);
}

static inline void init_rspq(struct adapter *adap, struct sge_rspq *q,
			     unsigned int us, unsigned int cnt,
			     unsigned int size, unsigned int iqe_size)
{
	q->adap = adap;
	cxgb4_set_rspq_intr_params(q, us, cnt);
	q->iqe_len = iqe_size;
	q->size = size;
}

/*
 * Perform default configuration of DMA queues depending on the number and type
 * of ports we found and the number of available CPUs.  Most settings can be
 * modified by the admin prior to actual use.
 */
static void cfg_queues(struct adapter *adap)
{
	struct sge *s = &adap->sge;
	int i, n10g = 0, qidx = 0;
#ifndef CONFIG_CXGB4_DCB
	int q10g = 0;
#endif
	int ciq_size;

	for_each_port(adap, i) {
		if (mq_with_1G || is_fpga(adap->params.chip))
			n10g += 1;
		else
			n10g += is_x_10g_port(&adap2pinfo(adap, i)->link_cfg);
	}

#ifdef CONFIG_CXGB4_DCB
	/* For Data Center Bridging support we need to be able to support up
	 * to 8 Traffic Priorities; each of which will be assigned to its
	 * own TX Queue in order to prevent Head-Of-Line Blocking.
	 */
	if (adap->params.nports * 8 > max_eth_qsets) {
		dev_err(adap->pdev_dev, "max_eth_qsets=%d < %d!\n",
			max_eth_qsets, adap->params.nports * 8);
		BUG_ON(1);
	}

	for_each_port(adap, i) {
		struct port_info *pi = adap2pinfo(adap, i);

		pi->first_qset = qidx;
		pi->nqsets = 8;
		qidx += pi->nqsets;
	}
#else /* !CONFIG_CXGB4_DCB */
	/*
	 * We default to 1 queue per non-10G port and up to # of cores queues
	 * per 10G port.
	 */
	if (n10g)
		q10g = (max_eth_qsets - (adap->params.nports - n10g)) / n10g;
	if (q10g > num_online_cpus())
		q10g = num_online_cpus();

	for_each_port(adap, i) {
		struct port_info *pi = adap2pinfo(adap, i);

		pi->first_qset = qidx;
		pi->nqsets = (is_x_10g_port(&pi->link_cfg) ||
			      mq_with_1G || is_fpga(adap->params.chip))
				? q10g : 1;
		if (pi->nqsets > pi->rss_size)
			pi->nqsets = pi->rss_size;
		qidx += pi->nqsets;
	}
#endif /* !CONFIG_CXGB4_DCB */

	s->ethqsets = qidx;
	s->max_ethqsets = qidx;   /* MSI-X may lower it later */

	if (is_offload(adap)) {
		/*
		 * For offload we use 1 queue/channel if all ports are up to 1G,
		 * otherwise we divide all available queues amongst the channels
		 * capped by the number of available cores.
		 */
		if (n10g) {
			i = min_t(int, DEFAULT_OFLD_QSETS,
						num_online_cpus());
			s->ofldqsets = roundup(i, adap->params.nports);
		} else
			s->ofldqsets = adap->params.nports;
		/* For RDMA one Rx queue per channel suffices */
		s->rdmaqs = adap->params.nports;
		/* Try and allow at least 1 CIQ per cpu rounding down
		 * to the number of ports, with a minimum of 1 per port.
		 * A 2 port card in a 6 cpu system: 6 CIQs, 3 / port.
		 * A 4 port card in a 6 cpu system: 4 CIQs, 1 / port.
		 * A 4 port card in a 2 cpu system: 4 CIQs, 1 / port.
		 */
		s->rdmaciqs = min_t(int, DEFAULT_RDMA_CIQS,
							num_online_cpus());
		s->rdmaciqs = (s->rdmaciqs / adap->params.nports) *
				adap->params.nports;
		s->rdmaciqs = max_t(int, s->rdmaciqs, adap->params.nports);

#ifdef SCSI_CXGB4_ISCSI
		if (n10g)
			s->niscsiq = adap->params.nports*2;
		else
			s->niscsiq = adap->params.nports;
#endif
	}

	/* This max may be lowered by cxgb_enable_msix() */
	s->max_ofldqsets = s->ofldqsets + s->rdmaqs + s->rdmaciqs + s->niscsiq;

	for (i = 0; i < ARRAY_SIZE(s->ethrxq); i++) {
		struct sge_eth_rxq *r = &s->ethrxq[i];

		init_rspq(adap, &r->rspq, 5, 10, 1024, 64);
		r->fl.size = 72;
	}

	if (is_hashfilter(adap) && is_t5(adap->params.chip)) {
		s->ntraceq = 4;

		for (i = 0; i < ARRAY_SIZE(s->traceq); i++) {
			struct sge_eth_rxq *r = &s->traceq[i];

			init_rspq(adap, &r->rspq, 5, 10, 1024, 64);
			r->fl.size = 72;
		}
	}

	for (i = 0; i < ARRAY_SIZE(s->ethtxq); i++)
#ifdef CONFIG_PO_FCOE
		s->ethtxq[i].q.size = 8192;
#else
		s->ethtxq[i].q.size = 1024;
#endif /* CONFIG_PO_FCOE */

	for (i = 0; i < ARRAY_SIZE(s->ctrlq); i++)
		s->ctrlq[i].q.size = 512;

	for (i = 0; i < ARRAY_SIZE(s->ofldtxq); i++)
		s->ofldtxq[i].q.size = 1024;

	for (i = 0; i < ARRAY_SIZE(s->ofldrxq); i++) {
		struct sge_ofld_rxq *r = &s->ofldrxq[i];

		init_rspq(adap, &r->rspq, 5, offload_rx_intr_cnt, 1024, 64);
		r->rspq.uld = CXGB4_ULD_TOE;
		r->fl.size = 72;
	}

	for (i = 0; i < ARRAY_SIZE(s->rdmarxq); i++) {
		struct sge_ofld_rxq *r = &s->rdmarxq[i];

		init_rspq(adap, &r->rspq, 5, 1, 511, 64);
		r->rspq.uld = CXGB4_ULD_RDMA;
		r->fl.size = 72;
	}

	ciq_size = 64 + adap->vres.cq.size + adap->tids.nftids;
	if (ciq_size > SGE_MAX_IQ_SIZE) {
		CH_WARN(adap, "CIQ size too small for available IQs\n");
		ciq_size = SGE_MAX_IQ_SIZE;
	}

	for (i = 0; i < ARRAY_SIZE(s->rdmaciq); i++) {
		struct sge_ofld_rxq *r = &s->rdmaciq[i];

		init_rspq(adap, &r->rspq, 5, 1, ciq_size, 64);
		r->rspq.uld = CXGB4_ULD_RDMA;
	}

	for (i = 0; i < ARRAY_SIZE(s->iscsirxq); i++) {
		struct sge_ofld_rxq *r = &s->iscsirxq[i];

		init_rspq(adap, &r->rspq, 5, 8, 1024, 64);
		r->rspq.uld = CXGB4_ULD_ISCSI;
		r->fl.size = 72;
	}

	init_rspq(adap, &s->fw_evtq, 0, 1, 1024, 64);
	init_rspq(adap, &s->intrq, 0, 1, 2 * MAX_INGQ, 64);

#ifdef CONFIG_T4_MA_FAILOVER
	if (is_offload(adap)) {
		struct sge_ofld_rxq *r = &s->failoverq;
		s->nfailoverq = MAX_FAILOVER_QUEUES;
		init_rspq(adap, &r->rspq, 5, 1, 1024, 64);
		r->rspq.uld = CXGB4_ULD_TOE;
		r->fl.size = 72;
	}
#endif /* CONFIG_T4_MA_FAILOVER */

#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
	if (!is_t4(adap->params.chip))
		s->ptptxq.q.size = 8;
#endif

#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
	if (is_t5(adap->params.chip)) {
		for (i = 0; i < ARRAY_SIZE(s->vxlantxq); i++)
			s->vxlantxq[i].q.size = 1024;
	}
#endif
}

/*
 * Interrupt handler used to check if MSI/MSI-X works on this platform.
 */
static irqreturn_t check_intr_handler(int irq, void *data)
{
	struct adapter *adap = data;

	adap->swintr = 1;
	t4_write_reg(adap, MYPF_REG(A_PL_PF_INT_CAUSE), F_PFSW);
	t4_read_reg(adap, MYPF_REG(A_PL_PF_INT_CAUSE));          /* flush */
	return IRQ_HANDLED;
}

static void check_msi(struct adapter *adap)
{
	int vec;

	vec = (adap->flags & USING_MSI) ? adap->pdev->irq :
					  adap->msix_info[0].vec;

	if (request_irq(vec, check_intr_handler, 0, adap->name, adap))
		return;

	adap->swintr = 0;
	t4_write_reg(adap, MYPF_REG(A_PL_PF_INT_ENABLE), F_PFSW);
	t4_write_reg(adap, MYPF_REG(A_PL_PF_CTL), F_SWINT);
	msleep(10);
	t4_write_reg(adap, MYPF_REG(A_PL_PF_INT_ENABLE), 0);
	free_irq(vec, adap);

	if (!adap->swintr) {
		const char *s = (adap->flags & USING_MSI) ? "MSI" : "MSI-X";

		cxgb_disable_msi(adap);
		dev_info(adap->pdev_dev,
			 "the kernel believes that %s is available on this "
			 "platform\nbut the driver's %s test has failed.  "
			 "Proceeding with INTx interrupts.\n", s, s);
	}
}

/*
 * Reduce the number of Ethernet queues across all ports to at most n.
 * n provides at least one queue per port.
 */
static void reduce_ethqs(struct adapter *adap, int n)
{
	int i;
	struct port_info *pi;

	while (n < adap->sge.ethqsets)
		for_each_port(adap, i) {
			pi = adap2pinfo(adap, i);
			if (pi->nqsets > 1) {
				pi->nqsets--;
				adap->sge.ethqsets--;
				if (adap->sge.ethqsets <= n)
					break;
			}
		}

	n = 0;
	for_each_port(adap, i) {
		pi = adap2pinfo(adap, i);
		pi->first_qset = n;
		n += pi->nqsets;
	}
}

/* 2 MSI-X vectors needed for the FW queue and non-data interrupts */
#define EXTRA_VECS 2

static int cxgb_enable_msix(struct adapter *adap)
{
	int ofld_need = 0;
	int i, want, need, allocated;
	struct sge *s = &adap->sge;
	unsigned int nchan = adap->params.nports;
	struct msix_entry *entries;

	entries = kmalloc(sizeof(struct msix_entry) * (MAX_INGQ + 1),
			  GFP_KERNEL);
	if (!entries)
		return -ENOMEM;

	for (i = 0; i < MAX_INGQ + 1; ++i)
		entries[i].entry = i;

	want = s->max_ethqsets + EXTRA_VECS +
	       (is_hashfilter(adap) && is_t5(adap->params.chip) ? s->ntraceq : 0);
	if (is_offload(adap)) {
		want += s->rdmaqs + s->rdmaciqs + s->ofldqsets;
#ifdef CONFIG_T4_MA_FAILOVER
		want += 1; /* +1 for MA Failover Queue */
#endif
#ifdef SCSI_CXGB4_ISCSI
		want += s->niscsiq;
#endif
		/* need 2*nchan for RDMA, nchan for OFLD */
		ofld_need = 3 * nchan;
#ifdef SCSI_CXGB4_ISCSI
		/* need nchan for iscsi */
		ofld_need += nchan;
#endif
#ifdef CONFIG_T4_MA_FAILOVER
		ofld_need += 1; /* +1 for MA Failover Queue */
#endif
	}
#ifdef CONFIG_CXGB4_DCB
	/* For Data Center Bridging we need 8 Ethernet TX Priority Queues for
	 * each port.
	 */
	need = 8 * adap->params.nports + EXTRA_VECS + ofld_need;
#else /* !CONFIG_CXGB4_DCB */
	need = adap->params.nports + EXTRA_VECS + ofld_need;
#endif /* !CONFIG_CXGB4_DCB */
	allocated = pci_enable_msix_range(adap->pdev, entries, need, want);
	if (allocated < 0) {
		dev_info(adap->pdev_dev, "not enough MSI-X vectors left,"
			 " not using MSI-X\n");
		kfree(entries);
		return allocated;
	}

	/* Distribute available vectors to the various queue groups.
	 * Every group gets its minimum requirement and NIC gets top
	 * priority for leftovers.
	 */
	i = allocated - EXTRA_VECS - ofld_need;
	if (i < s->max_ethqsets) {
		s->max_ethqsets = i;
		if (i < s->ethqsets)
			reduce_ethqs(adap, i);
	}
	if (is_offload(adap)) {
		if (allocated < want) {
			s->rdmaqs = nchan;
			s->rdmaciqs = nchan;
#ifdef SCSI_CXGB4_ISCSI
			s->niscsiq = nchan;
#endif
		}

		/* leftovers go to OFLD */
		i = allocated - EXTRA_VECS - s->max_ethqsets -
		    s->rdmaqs - s->rdmaciqs;
#ifdef SCSI_CXGB4_ISCSI
		i -= s->niscsiq;
#endif
#ifdef CONFIG_T4_MA_FAILOVER
		/* only 1 failover queue */
		i -= s->nfailoverq;
#endif
		/* allocate the remaining between ofld and ciqs */
		s->ofldqsets = min_t(int, i, DEFAULT_OFLD_QSETS);
		/* round down */
		s->ofldqsets = (s->ofldqsets / nchan) * nchan;
		i -= s->ofldqsets;
		if (i > 0) {
			/* allocate the remaining to ciqs and round down */
			s->rdmaciqs = min_t(int, (s->rdmaciqs + i),
							DEFAULT_RDMA_CIQS);
			s->rdmaciqs = (s->rdmaciqs / nchan) * nchan;
		}
	}

	/* This is the max no of vectors available for
	 * the various offload queues (ofld + rdma + rciq + iscsi)
	 */
	s->max_ofldqsets = s->ofldqsets + s->rdmaqs + s->rdmaciqs + s->niscsiq;

	for (i = 0; i < allocated; ++i)
		adap->msix_info[i].vec = entries[i].vector;
	dev_info(adap->pdev_dev, "%d MSI-X vectors allocated, "
	         "nic %d ofld %d rdma cpl %d rdma ciq %d iscsi %d\n",
		 allocated, s->max_ethqsets, s->ofldqsets, s->rdmaqs,
		 s->rdmaciqs, s->niscsiq);

	kfree(entries);
	return 0;
}

#undef EXTRA_VECS

static int init_rss(struct adapter *adap)
{
	unsigned int i;
	int err;

	err = t4_init_rss_mode(adap, adap->mbox);
	if (err)
		return err;

	for_each_port(adap, i) {
		struct port_info *pi = adap2pinfo(adap, i);

		pi->rss = kcalloc(pi->rss_size, sizeof(u16), GFP_KERNEL);
		if (!pi->rss)
			return -ENOMEM;
	}
	return 0;
}

#define PCI_SPEED_SIZE 8
#define PCI_WIDTH_SIZE 8

static void cxgb4_check_pcie_caps(struct adapter *adap)
{
	u16 link_status;
	char speed[PCI_SPEED_SIZE] = "Unknown";
	char width[PCI_WIDTH_SIZE] = "Unknown";
	enum terminator_bus_speed bus_speed;
	enum terminator_bus_width bus_width;

	/* Get the negotiated link width and speed from PCI config
	 * space
	 */
	pcie_capability_read_word(adap->pdev, PCI_EXP_LNKSTA,
				  &link_status);

	switch (link_status & PCI_EXP_LNKSTA_NLW) {
	case PCI_EXP_LNKSTA_NLW_X1:
		bus_width = terminator_bus_width_pcie_x1;
		strncpy(width, "1", PCI_WIDTH_SIZE); break;
		break;
	case PCI_EXP_LNKSTA_NLW_X2:
		bus_width = terminator_bus_width_pcie_x2;
		strncpy(width, "2", PCI_WIDTH_SIZE); break;
		break;
	case PCI_EXP_LNKSTA_NLW_X4:
		bus_width = terminator_bus_width_pcie_x4;
		strncpy(width, "4", PCI_WIDTH_SIZE); break;
		break;
	case PCI_EXP_LNKSTA_NLW_X8:
		bus_width = terminator_bus_width_pcie_x8;
		strncpy(width, "8", PCI_WIDTH_SIZE); break;
		break;
	default:
		bus_width = terminator_bus_width_unknown;
		break;
	}

	switch (link_status & PCI_EXP_LNKSTA_CLS) {
	case PCI_EXP_LNKSTA_CLS_2_5GB:
		bus_speed = terminator_bus_speed_2500;
		strncpy(speed, "2.5", PCI_SPEED_SIZE); break;
		break;
	case PCI_EXP_LNKSTA_CLS_5_0GB:
		bus_speed = terminator_bus_speed_5000;
		strncpy(speed, "5.0", PCI_SPEED_SIZE); break;
		break;
	case PCI_EXP_LNKSTA_CLS_8_0GB:
		bus_speed = terminator_bus_speed_8000;
		strncpy(speed, "8.0", PCI_SPEED_SIZE); break;
		break;
	default:
		bus_speed = terminator_bus_speed_unknown;
		break;
	}

	dev_info(adap->pdev_dev, "PCI-Express: Speed %sGT/s Width x%s\n",
		 speed, width);
	if (bus_width < terminator_bus_width_pcie_x8 ||
	    bus_speed < (is_t4(adap->params.chip) ?
			 terminator_bus_speed_5000 :
			 terminator_bus_speed_8000)) {
		dev_warn(adap->pdev_dev,
			 "PCI-Express bandwidth available for this device may"
			 " be insufficient for optimal performance.\n");
		dev_warn(adap->pdev_dev,
			 "Please move the device to a different PCI-e link with"
			 " more lanes and/or higher transfer rate.\n");
	}
}

static void print_port_info(adapter_t *adap)
{
	int i;
	char buf[80];
	const char *spd="";

	if (adap->params.pci.speed == PCI_EXP_LNKSTA_CLS_2_5GB)
		spd = " 2.5 GT/s";
	else if (adap->params.pci.speed == PCI_EXP_LNKSTA_CLS_5_0GB)
		spd = " 5 GT/s";
	else if (adap->params.pci.speed == PCI_EXP_LNKSTA_CLS_8_0GB)
		spd = " 8 GT/s";

	for_each_port(adap, i) {
		struct net_device *dev = adap->port[i];
		const struct port_info *pi = netdev_priv(dev);
		char *bufp = buf;

		if (!test_bit(i, &adap->registered_device_map))
			continue;

		if (pi->link_cfg.supported & FW_PORT_CAP_SPEED_100M)
			bufp += sprintf(bufp, "100/");
		if (pi->link_cfg.supported & FW_PORT_CAP_SPEED_1G)
			bufp += sprintf(bufp, "1000/");
		if (pi->link_cfg.supported & FW_PORT_CAP_SPEED_10G)
			bufp += sprintf(bufp, "10G/");
		if (pi->link_cfg.supported & FW_PORT_CAP_SPEED_40G)
			bufp += sprintf(bufp, "40G/");
		if (bufp != buf)
			--bufp;
		sprintf(bufp, "BASE-%s",
			t4_get_port_type_description(pi->port_type));

		printk(KERN_INFO "%s: Chelsio %s rev %d %s %sNIC %s, %s capable\n",
		       dev->name, adap->params.vpd.id,
		       CHELSIO_CHIP_RELEASE(adap->params.chip),
		       buf, is_offload(adap) ? "R" : "",
		       (adap->flags & USING_MSIX) ? " MSI-X" :
		       (adap->flags & USING_MSI) ? " MSI" : "",
		       is_offload(adap) ? "Offload" : "non-Offload");

		printk(KERN_INFO "%s: S/N: %s, P/N: %s\n", adap->name,
		       adap->params.vpd.sn, adap->params.vpd.pn);
	}
}

#ifdef CONFIG_PCI_IOV
/**
 *	vf_monitor - monitor VFs for potential problems
 *	@work: the adapter's vf_monitor_task
 *
 *	VFs can get into trouble in various ways so we monitor them to see if
 *	they need to be kicked, reset, etc.
 */
static void vf_monitor(struct work_struct *work)
{
	struct adapter *adapter = container_of(work, struct adapter,
					       vf_monitor_task.work);
	struct pci_dev *pdev;
	u32 pcie_cdebug;
	unsigned int reqfn;
	const unsigned int vf_offset = 8;
	const unsigned int vf_stride = 4;
	unsigned int vfdevfn, pf, vf;
	struct pci_dev *vfdev;
	int pos, i;
	u16 control;

	/*
	 * Read the PCI-E Debug Register to see if it's hanging with a
	 * Request Valid condition.  But we check it several times to be
	 * Absolutely Sure since we can see the PCI-E block being busy
	 * transiently during normal operation.
	 */
	for (i = 0; i < 4; i++) {
		t4_write_reg(adapter, A_PCIE_CDEBUG_INDEX, 0x3c003c);
		pcie_cdebug = t4_read_reg(adapter, A_PCIE_CDEBUG_DATA_HIGH);
		if ((pcie_cdebug & 0x100) == 0)
			goto reschedule_vf_monitor;
	}

	/*
	 * We're not prepared to deal with anything other than a VF.
	 */
	pdev = adapter->pdev;
	reqfn = (pcie_cdebug >> 24) & 0xff;
	if (reqfn < vf_offset) {
		dev_info(&pdev->dev, "vf_monitor: hung ReqFn %d is a PF!\n",
			 reqfn);
		goto reschedule_vf_monitor;
	}

	/*
	 * Grab a handle on the VF's PCI State.
	 */
	pf = (reqfn - vf_offset) & (vf_stride - 1);
	vf = ((reqfn - vf_offset) & ~(vf_stride - 1))/vf_stride + 1;
	vfdevfn = PCI_SLOT(pdev->devfn) + reqfn;
	vfdev = pci_get_slot(pdev->bus, vfdevfn);
	if (vfdev == NULL) {
		dev_info(&pdev->dev, "vf_monitor: can't find PF%d/VF%d",
			 pf, vf);
		goto reschedule_vf_monitor;
	}

	/*
	 * Now that we have a handle on the VF which is hung, we need to
	 * mask and re-enable its interrupts, reset it and then disable its
	 * interrupts again.
	 */
	pos = pci_find_capability(vfdev, PCI_CAP_ID_MSIX);
	if (!pos) {
		dev_err(&pdev->dev, "vf_monitor: can't find MSI-X PF%d/VF%d\n",
			pf, vf);
		goto drop_vfdev_reference;
	}
	pci_read_config_word(vfdev, pos+PCI_MSIX_FLAGS, &control);
	if (control & PCI_MSIX_FLAGS_ENABLE) {
		dev_info(&pdev->dev, "vf_monitor: MSI-X already enabled PF%d/VF%d\n",
			 pf, vf);
		goto drop_vfdev_reference;
	}
	pci_write_config_word(vfdev, pos+PCI_MSIX_FLAGS,
			      control |
			      PCI_MSIX_FLAGS_ENABLE |
			      PCI_MSIX_FLAGS_MASKALL);
	pci_reset_function(vfdev);
	pci_write_config_word(vfdev, pos+PCI_MSIX_FLAGS, control);
	dev_warn(&pdev->dev, "vf_monitor: reset hung PF%d/VF%d\n", pf, vf);

drop_vfdev_reference:
	/*
	 * Drop reference to the VF's CI State.
	 */
	pci_dev_put(vfdev);

reschedule_vf_monitor:
	/*
	 * Set up for the next time we need to check things ...
	 */
	schedule_delayed_work(&adapter->vf_monitor_task, VF_MONITOR_PERIOD);
}
#endif

#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))

static void cxgb_del_vxlan_port(struct net_device *netdev,
				sa_family_t sa_family, __be16 port)
{
	struct port_info *pi = netdev_priv(netdev);
	struct adapter *adapter = pi->adapter;

	if (is_t4(adapter->params.chip))
		return;

	if (!adapter->vxlan_port_cnt || adapter->vxlan_port != port)
		return; /* Invalid VxLAN destination port */

	adapter->vxlan_port_cnt--;
	if (adapter->vxlan_port_cnt)
		return;

	adapter->vxlan_port = 0;
	netdev->hw_enc_features = 0;
	netdev->hw_features &= ~(NETIF_F_GSO_UDP_TUNNEL);
	netdev->features &= ~(NETIF_F_GSO_UDP_TUNNEL);
	t4_write_reg(adapter, A_MPS_RX_VXLAN_TYPE, 0);

	/* TODO: Deletion of raw mac entries is not working.
	 * Hence not doing anything here.
	 */
}

static void cxgb_add_vxlan_port(struct net_device *netdev,
				sa_family_t sa_family, __be16 port)
{
	struct port_info *pi = netdev_priv(netdev);
	struct adapter *adapter = pi->adapter;
	unsigned int chip_ver = CHELSIO_CHIP_VERSION(adapter->params.chip);
	u8 match_all_mac[] = { 0, 0, 0, 0, 0, 0 };
	int i, ret;

	if (chip_ver == CHELSIO_T4)
		return;

	/* For T6 fw reserves last 2 entries for
	 * storing match all mac filter (config file entry).
	 */
	if ((chip_ver > CHELSIO_T5) && !adapter->rawf_cnt)
		return;

	/* Callback for adding vxlan port can be called with the same port
	 * for both IPv4 and IPv6. We should not disable the offloading when
	 * the same port for both protocols is added and
	 * later one of them is removed.
	 */
	if (adapter->vxlan_port_cnt && adapter->vxlan_port == port) {
		adapter->vxlan_port_cnt++;
		return;
	}

	/* We will support only one VxLAN port */
	if (adapter->vxlan_port_cnt) {
		netdev_info(netdev, "UDP port %d already offloaded, "
			    "not adding port %d\n",
			    be16_to_cpu(adapter->vxlan_port),
			    be16_to_cpu(port));
		return;
	}

	adapter->vxlan_port = port;
	adapter->vxlan_port_cnt = 1;
	netdev->hw_enc_features |= NETIF_F_IP_CSUM |
				   NETIF_F_IPV6_CSUM |
				   NETIF_F_RXCSUM |
				   NETIF_F_GSO_UDP_TUNNEL |
				   NETIF_F_TSO | NETIF_F_TSO6;
	netdev->hw_features |= NETIF_F_GSO_UDP_TUNNEL;
	netdev->features |= NETIF_F_GSO_UDP_TUNNEL;

	if (chip_ver < CHELSIO_T6)
		return;

	t4_write_reg(adapter, A_MPS_RX_VXLAN_TYPE,
		     V_VXLAN(be16_to_cpu(port)) | F_VXLAN_EN);
	/* Create a 'match all' mac filter entry for inner mac,
	 * if raw mac interface is supported. Once the linux kernel provides
	 * driver entry points for adding/deleting the inner mac addresses,
	 * we will remove this 'match all' entry and fallback to adding
	 * exact match filters.
	 * Deleting of this entry is not working.
	 */
	if (adapter->rawf_cnt) {
		for_each_port(adapter, i) {
			pi = adap2pinfo(adapter, i);

			ret = t4_alloc_raw_mac_filt(adapter, pi->viid,
						    match_all_mac,
						    match_all_mac,
						    adapter->rawf_start +
						    pi->port_id,
						    1, true);
			if (ret < 0) {
				netdev_info(netdev, "Failed to allocate a mac "
					"filter entry, not adding port %d\n",
					be16_to_cpu(port));
				cxgb_del_vxlan_port(netdev, sa_family, port);
				return;
			}
		}
	}
}

#endif

#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,4))
static netdev_features_t cxgb_features_check(struct sk_buff *skb,
					     struct net_device *dev,
					     netdev_features_t features)
{
	struct port_info *pi = netdev_priv(dev);
	struct adapter *adapter = pi->adapter;

	if (is_t4(adapter->params.chip))
		return features;

	/* Check if hw supports offload for this packet */
	if (!skb->encapsulation || cxgb_encap_offload_supported(skb))
		return features;

	/* Offload is not supported for this encapsulated packet */
	return features & ~(NETIF_F_ALL_CSUM | NETIF_F_GSO_MASK);
}
#endif

static struct net_device_ops cxgb4_netdev_ops = {
	.ndo_open             = cxgb_open,
	.ndo_stop             = cxgb_close,
	.ndo_start_xmit       = t4_eth_xmit,
	.ndo_select_queue     = cxgb_select_queue,
	.ndo_get_stats        = cxgb_get_stats,
	.ndo_set_rx_mode      = cxgb_set_rxmode,
	.ndo_set_mac_address  = cxgb_set_mac_addr,
	.ndo_validate_addr    = eth_validate_addr,
	.ndo_do_ioctl         = cxgb_ioctl,
	.ndo_change_mtu       = cxgb_change_mtu,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller  = cxgb_netpoll,
#endif
#ifdef CONFIG_PO_FCOE
	.ndo_fcoe_ddp_target  = cxgb_fcoe_ddp_setup,
	.ndo_fcoe_ddp_done    = cxgb_fcoe_ddp_done,
	.ndo_fcoe_enable      = cxgb_fcoe_enable,
	.ndo_fcoe_disable     = cxgb_fcoe_disable,
#endif /* CONFIG_PO_FCOE */
#ifdef CONFIG_NET_RX_BUSY_POLL
	.ndo_busy_poll        = cxgb_busy_poll,
#endif
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
	.ndo_add_vxlan_port   = cxgb_add_vxlan_port,
	.ndo_del_vxlan_port   = cxgb_del_vxlan_port,
#endif
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,4))
	.ndo_features_check   = cxgb_features_check,
#endif
};

#define TSO_FLAGS (NETIF_F_TSO | NETIF_F_TSO6 | NETIF_F_TSO_ECN)
#define VLAN_FEAT (NETIF_F_SG | NETIF_F_IP_CSUM | TSO_FLAGS | \
		   NETIF_F_IPV6_CSUM | NETIF_F_HIGHDMA)

static void enable_pcie_relaxed_ordering(struct pci_dev *dev)
{
	pcie_capability_set_word(dev, PCI_EXP_DEVCTL, PCI_EXP_DEVCTL_RELAX_EN);
}

static int init_one(struct pci_dev *pdev,
			      const struct pci_device_id *ent)
{
	static int version_printed;

	u32 whoami;
	int func;
	int i, err, pci_using_dac = 0;
	struct adapter *adapter = NULL;
	struct port_info *pi;
	u64 hw_features;
	enum chip_type chip;
	u16 device_id;

	if (!version_printed) {
		printk(KERN_INFO "%s - version %s\n", DRV_DESC, DRV_VERSION);
		++version_printed;
	}

	err = pci_request_regions(pdev, KBUILD_MODNAME);
	if (err) {
		/* Just info, some other driver may have claimed the device. */
		dev_info(&pdev->dev, "cannot obtain PCI resources\n");
		return err;
	}

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "cannot enable PCI device\n");
		goto out_release_regions;
	}

	pci_enable_pcie_error_reporting(pdev);

	if (!pci_set_dma_mask(pdev, DMA_BIT_MASK(64))) {
		pci_using_dac = 1;
		err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64));
		if (err) {
			dev_err(&pdev->dev, "unable to obtain 64-bit DMA for "
				"coherent allocations\n");
			goto out_disable_device;
		}
	} else if ((err = pci_set_dma_mask(pdev, DMA_BIT_MASK(32))) != 0) {
		dev_err(&pdev->dev, "no usable DMA configuration\n");
		goto out_disable_device;
	}

	enable_pcie_relaxed_ordering(pdev);
	pci_set_master(pdev);

	adapter = kzalloc(sizeof(*adapter), GFP_KERNEL);
	if (!adapter) {
		err = -ENOMEM;
		goto out_disable_device;
	}

	/*
	 * Initialize fields early which are accessed all over the place ...
	 */
	adapter->pdev = pdev;
	adapter->pdev_dev = &pdev->dev;
	adapter->name = pci_name(pdev);
	adapter->msg_enable = dflt_msg_enable;

	adapter->workq = create_singlethread_workqueue("cxgb4");
	if (!adapter->workq) {
		err = -ENOMEM;
		goto out_free_adapter;
	}

	adapter->eeh_workq = create_singlethread_workqueue ("cxgb4_eeh");
	if (!adapter->eeh_workq) {
		err = -ENOMEM;
		goto out_free_adapter;
	}

	adapter->mbox_log = kzalloc(sizeof (struct mbox_cmd_log) +
				    (sizeof (struct mbox_cmd) *
				     T4_OS_LOG_MBOX_CMDS),
				    GFP_KERNEL);
	if (!adapter->mbox_log) {
		err = -ENOMEM;
		goto out_free_adapter;
	}
	adapter->mbox_log->size = T4_OS_LOG_MBOX_CMDS;

	/*
	 * Copy all applicable "Module Parameters" into their slots within the
	 * adapter data structure early so all driver code can depend on them.
	 * We also do sanity checking here for conflicting Module arameters,
	 * etc.
	 */

	/*
	 * If the "tx_vm" module parameter is specified we'll end up using the
	 * t4vf_eth_xmit() routine which has no TX Coalescing capabilities so
	 * we should warn the administrator if they attempt to enable TX
	 * Coalescing at the same time.
	 */
	if (tx_vm && tx_coal)
		dev_warn(&pdev->dev, "cannot use 'tx_vm with tx_coal; "
			 " tx_vm takes precidence\n");

#ifndef ARCH_HAS_IOREMAP_WC
	if (tx_db_wc)
		dev_warn(&pdev->dev,
			 "Turning on tx_db_wc will lower performance\n");
#endif
	adapter->tx_db_wc = tx_db_wc;
	adapter->tx_coal = tx_coal;

	/* PCI device has been enabled */
	adapter->flags |= DEV_ENABLED;

	adapter->regs = pci_ioremap_bar(pdev, 0);
	if (!adapter->regs) {
		dev_err(&pdev->dev, "cannot map device registers\n");
		err = -ENOMEM;
		goto out_free_adapter;
	}

	/*
	 * We control everything via a single PF (which we refer to as the
	 * "Master PF").  This Master PF is identifed with a special PCI
	 * Device ID separate from the "normal" NIC Device IDs so for the most
	 * part we just advertise that we want to be hooked up with the
	 * Unified PF and everything works out.
	 *
	 * However, note that the "PE10K" FPGA is very annoying since both of
	 * its two Physical Functions have the same Device ID so we need to
	 * explcitly skip working with any PF other than Master PF, which we
	 * hardwire to PF0.  This means that we have to undo all the I/O
	 * mapping, etc.  once we get here and discover that we're actually
	 * dealing with PF1.  Hopefully the next FPGA will use different PCI
	 * Device IDs for each of the PFs.
	 *
	 * Note that we use the PL_WHOAMI register to figure out to which PF
	 * we're actually attached rather than PCI_FUNC(pdev->devfn).  We do
	 * this because we could be operating within a Virtual Machine where,
	 * say, PF4 has been inserted via some form of "PCI Pass Through"
	 * resulting in the VM PCI Device having a completely different PCI
	 * Function Number, say, PF0.  However, there are many communications
	 * with the firmware (and the hardware) where we need to use the
	 * actual Physical Function Number and we can get this from the
	 * PL_WHOAMI register ...
	 */
	err = t4_wait_dev_ready(adapter);
	if (err < 0)
		goto out_unmap_bar0;
	whoami = t4_read_reg(adapter, A_PL_WHOAMI);
	pci_read_config_word(pdev, PCI_DEVICE_ID, &device_id);
	chip = t4_get_chip_type(adapter, CHELSIO_PCI_ID_VER(device_id));
	if (chip < 0)
		goto out_unmap_bar0;
	func = (CHELSIO_CHIP_VERSION(chip) <= CHELSIO_T5 ?
			G_SOURCEPF(whoami) : G_T6_SOURCEPF(whoami));
	if ((pdev->device == 0xa000 || pdev->device == 0xc106) && func != 0) {
		err = 0;
		goto out_unmap_bar0;
	}

#ifdef CHELSIO_T4_DIAGS
	/*
	 * The PCI Device ID Table includes PCI Device IDs both for PF4 and
	 * for PF0 (which is the same ID used for PF1..3).  So we'll get
	 * called for PF0..3 as well as PF4.  If the module parameter
	 * "attach_pf0" is specified, then we want to continue forward only
	 * with PF0 and ingnore the rest.  If attach_pf0 is not specified,
	 * then we want to continue forward only with PF4.
	 */
	if ((attach_pf0 && func != 0) ||
	    (!attach_pf0 && func != 4)) {
		err = 0;
		goto out_unmap_bar0;
	}

	if (attach_pf0)
		dev_info(&pdev->dev, "Attaching to pci func %d\n", func);

#endif

	adapter->mbox = func;
	adapter->pf = func;
	memset(adapter->chan_map, 0xff, sizeof(adapter->chan_map));

	spin_lock_init(&adapter->mdio_lock);
	spin_lock_init(&adapter->win0_lock);
	spin_lock_init(&adapter->work_lock);
	spin_lock_init(&adapter->stats_lock);
	spin_lock_init(&adapter->tid_release_lock);
	t4_os_lock_init(&adapter->mbox_lock);
	mutex_init(&adapter->user_mutex);
	mutex_init(&adapter->uld_mutex);
	INIT_LIST_HEAD(&adapter->mbox_list.list);

	INIT_WORK(&adapter->tid_release_task, process_tid_release_list);
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	INIT_WORK(&adapter->db_full_task, process_db_full);
	INIT_WORK(&adapter->db_drop_task, process_db_drop);
#endif
	INIT_WORK(&adapter->fatal_err_task, process_fatal_err);

	err = t4_prep_adapter(adapter, false);
	if (err)
		goto out_unmap_bar0;

#ifdef CHELSIO_T4_DIAGS
	/*
	 * FW may not always initialize external memories.  This flag tells
	 * FW to initialize memory (mainly for BIST test).  Need to run this
	 * after t4_prep_adapter() so params.chip gets initialized.
	 */
	if (extmem_init) {
		/* Do not attach to firmware */
		fw_attach = 0;
		err = 0;
		if (is_t5(adapter->params.chip))
			err = t5_fw_init_extern_mem(adapter);
		if (err)
			dev_err(&pdev->dev,
					"Failed to initialize external memory, error %d", -err);
	}

#endif

	setup_memwin(adapter);
	err = adap_init0(adapter);
	if (err)
		dev_err(&pdev->dev, "Adapter initialization failed, error %d.  "
			"Continuing in debug mode\n", -err);

	bitmap_zero(adapter->sge.blocked_fl, adapter->sge.egr_sz);

	if (!is_t4(adapter->params.chip)) {
		adapter->bar2 = ioremap_wc(pci_resource_start(pdev, 2),
					   pci_resource_len(pdev, 2));
		if (!adapter->bar2) {
			dev_err(&pdev->dev, "cannot map device bar2 region\n");
			err = -ENOMEM;
			goto out_unmap_bar0;
		}
		t4_write_reg(adapter, A_SGE_STAT_CFG, V_STATSOURCE_T5(7) |
			     (is_t5(adapter->params.chip) ? V_STATMODE(0) :
			      V_T6_STATMODE(0)));
	}

	setup_memwin_rdma(adapter);

	/*
	 * Hardware features that we support ...
	 */
	hw_features = NETIF_F_SG | TSO_FLAGS |
		NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM | NETIF_F_RXCSUM |
		NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_CTAG_RX;

#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
	/* T5 and T6 will support VxLAN and GRE offload */
	if (!is_t4(adapter->params.chip)) {
		hw_features |= NETIF_F_GSO_UDP_TUNNEL;
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,4))
		/* Adding GRE offload for T6 and onwards */
		if (!is_t5(adapter->params.chip)) {
			hw_features |= NETIF_F_GSO_GRE;
			t4_write_reg(adapter, A_MPS_RX_GRE_PROT_TYPE,
				     F_GRE_EN | F_NVGRE_EN |
				     V_GRE(IPPROTO_GRE));
		}
#endif
	}
#endif
	if (pci_using_dac)
		hw_features |= NETIF_F_HIGHDMA;

	if ((max_eth_qsets < 32) || (max_eth_qsets > 64))
		max_eth_qsets = 32;

	for_each_port(adapter, i) {
		struct net_device *netdev;

		netdev = alloc_etherdev_mq(sizeof(struct port_info),
					   max_eth_qsets);
		if (!netdev) {
			err = -ENOMEM;
			goto out_free_dev;
		}

		SET_NETDEV_DEV(netdev, &pdev->dev);

		adapter->port[i] = netdev;
		pi = netdev_priv(netdev);
		pi->adapter = adapter;
		pi->xact_addr_filt = -1;
		pi->port_id = i;
		netdev->irq = pdev->irq;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
		netdev->hw_features = hw_features;
#endif
		netdev->features |= hw_features;
#ifdef CONFIG_CXGB4_GRO
		netdev->features |= NETIF_F_GRO;
#endif
		netdev->vlan_features = netdev->features & VLAN_FEAT;

#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0))
		if (!is_t4(adapter->params.chip)) {
			netdev->hw_enc_features |= NETIF_F_IP_CSUM |
						   NETIF_F_IPV6_CSUM |
						   NETIF_F_RXCSUM |
						   NETIF_F_GSO_UDP_TUNNEL |
						   NETIF_F_TSO | NETIF_F_TSO6;
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,4))
			/* Adding GRE offload for T6 and onwards */
			if (!is_t5(adapter->params.chip))
				netdev->hw_enc_features |= NETIF_F_GSO_GRE;
#endif
		}
#endif

		/*
		 * If the "tx_vm" module parameter is specified, use the
		 * t4vf_eth_xmit() transmit routine instead of the normal one.
		 */
		if (tx_vm)
			cxgb4_netdev_ops.ndo_start_xmit = t4vf_eth_xmit;
		netdev->netdev_ops = &cxgb4_netdev_ops;

#ifdef CONFIG_CXGB4_DCB
		netdev->dcbnl_ops = &cxgb4_dcb_ops;
		cxgb4_dcb_state_init(netdev);
		cxgb4_dcb_version_init(netdev);
#endif

		cxgb4_set_ethtool_ops(netdev);
	}

	pci_set_drvdata(pdev, adapter);

	if (adapter->flags & FW_OK) {
		err = t4_port_init(adapter, adapter->mbox, adapter->pf, 0);
		if (err)
			goto out_free_dev;

		for_each_port(adapter, i) {
			struct port_info *p = adap2pinfo(adapter, i);
			init_ma_fail_data(p);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
			adapter->port[i]->dev_port = p->tx_chan;
#endif
		}
	} else if (adapter->params.nports == 1) {
		/* If we don't have a connection to the firmware -- either
		 * because of an error or because fw_attach=0 was specified --
		 * grab the raw VPD parameters so we can set the proper MAC
		 * Address on the debug network interface that we've created.
		 */
		u8 hw_addr[ETH_ALEN];
		u8 *na = adapter->params.vpd.na;

		err = t4_get_raw_vpd_params(adapter, &adapter->params.vpd);
		if (!err) {
			for (i = 0; i < ETH_ALEN; i++)
				hw_addr[i] = (hex2val(na[2 * i + 0]) * 16 +
					      hex2val(na[2 * i + 1]));
			t4_os_set_hw_addr(adapter, 0, hw_addr);
		}
	}

	cfg_queues(adapter);  // XXX move after we know interrupt type

	chip = CHELSIO_CHIP_VERSION(adapter->params.chip);
	if (!(adapter->flags & FW_OK))
		goto fw_attach_fail;

	adapter->smt = t4_init_smt();
	if (!adapter->smt)
		dev_warn(&pdev->dev, "could not allocate SMT, continuing\n");

	adapter->l2t = t4_init_l2t(adapter->l2t_start, adapter->l2t_end);
	if (!adapter->l2t) {
		/* We tolerate a lack of L2T, giving up some functionality */
		dev_warn(&pdev->dev, "could not allocate L2T, continuing\n");
		adapter->params.offload = 0;
	}
	if ((CHELSIO_CHIP_VERSION(adapter->params.chip) <= CHELSIO_T5) &&
	    (!(t4_read_reg(adapter, A_LE_DB_CONFIG) & F_ASLIPCOMPEN))) {
		/* CLIP functionality is not present in hardware,
		 * hence disable all offload features
 		 */
		dev_warn(&pdev->dev,
			 "CLIP not enabled in hardware, continuing\n");
		adapter->params.offload = 0;
	} else {
		adapter->clipt = t4_init_clip_tbl(adapter->clipt_start,
						  adapter->clipt_end);
		if (!adapter->clipt) {
			/* We tolerate a lack of clip_table, giving up
			 * some functionality
			 */
			dev_warn(&pdev->dev,
				 "could not allocate Clip table, continuing\n");
			adapter->params.offload = 0;
		}
	}

	if (tid_init(&adapter->tids) < 0) {
		dev_warn(&pdev->dev, "could not allocate TID table, "
			 "continuing\n");
		if (is_offload(adapter))
			adapter->params.offload = 0;
		adapter->params.hash_filter = 0;
	}

	if (is_offload(adapter) || is_hashfilter(adapter)) {
		if (is_offload(adapter))
			__set_bit(OFFLOAD_DEVMAP_BIT,
				&adapter->registered_device_map);
		if (t4_read_reg(adapter, A_LE_DB_CONFIG) & F_HASHEN) {
			u32 hash_base, hash_reg;
			if (chip <= CHELSIO_T5) {
				hash_reg = A_LE_DB_TID_HASHBASE;
				hash_base = t4_read_reg(adapter, hash_reg);
				adapter->tids.hash_base = hash_base / 4;
			} else {
				hash_reg = A_T6_LE_DB_HASH_TID_BASE;
				hash_base = t4_read_reg(adapter, hash_reg);
				adapter->tids.hash_base = hash_base;
			}
		}
	}

#ifdef CONFIG_CHELSIO_BYPASS
	/*
	 * We need to call the Bypass Adapter's setup routine very early on in
	 * order to set the current and failure modes correctly.  These will
	 * be set to the failover mode of the previous incarnation of the
	 * driver.  This early call also means that these are reported
	 * correctly via the interface even though the interfaces haven't been
	 * brought up yet.
	 */
	if (is_bypass(adapter))
		t4_bypass_setup(adapter);
#endif

	err = init_rss(adapter);
	if (err)
		goto out_disable_interrupts;

	/*
	 * See what interrupts we'll be using.  Note that we need to enable
	 * our interrupts before we register the network devices since certain
	 * installations can have the network devices setup for automatic
	 * configuration.  When that happens, we can get a Port Link Status
	 * message from the firmware on our Asynchronous Firmware Event Queue
	 * and end up losing the interrupt.
	 */
	if (msi > 1 && cxgb_enable_msix(adapter) == 0)
		adapter->flags |= USING_MSIX;
	else if (msi > 0 && pci_enable_msi(pdev) == 0)
		adapter->flags |= USING_MSI;
	if (adapter->flags & (USING_MSIX | USING_MSI))
		check_msi(adapter);

	/* check for PCI Express bandwidth capabiltites */
	cxgb4_check_pcie_caps(adapter);

fw_attach_fail:
	/*
	 * The card is now ready to go.  If any errors occur during device
	 * registration we do not fail the whole card but rather proceed only
	 * with the ports we manage to register successfully.  However we must
	 * register at least one net device.
	 */
	for_each_port(adapter, i) {
		pi = adap2pinfo(adapter, i);
		adapter->port[i]->dev_id = pi->tx_chan;
		netif_set_real_num_tx_queues(adapter->port[i], pi->nqsets);
		netif_set_real_num_rx_queues(adapter->port[i], pi->nqsets);

		err = register_netdev(adapter->port[i]);
		if (err)
			dev_warn(&pdev->dev,
				 "cannot register net device %s, skipping\n",
				 adapter->port[i]->name);
		else {
			/*
			 * Change the name we use for messages to the name of
			 * the first successfully registered interface.
			 */
			if (!adapter->registered_device_map)
				adapter->name = adapter->port[i]->name;

			__set_bit(i, &adapter->registered_device_map);
			adapter->chan_map[pi->tx_chan] = i;

			netif_carrier_off(adapter->port[i]);
		}
	}
	if (!adapter->registered_device_map) {
		dev_err(&pdev->dev, "could not register any net devices\n");
		goto out_disable_interrupts;
	}

	if (cxgb4_debugfs_root) {
		adapter->debugfs_root = debugfs_create_dir(pci_name(pdev),
							   cxgb4_debugfs_root);
		cxgb4_setup_debugfs(adapter);
	}

	/*
	 * Setup sysfs
	 */
	for_each_port(adapter, i)
		if (sysfs_create_group(&adapter->port[i]->dev.kobj,
				       &t4_attr_group))
			dev_warn(&pdev->dev,
				 "cannot create sysfs t4_attr_group net device "
				 "%s\n", adapter->port[i]->name);

#ifdef CONFIG_CHELSIO_BYPASS
	if (is_bypass(adapter))
		bypass_sysfs_create(adapter);
#endif

	/* PCIe EEH recovery on powerpc platforms needs fundamental reset */
	pdev->needs_freset = 1;

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	if (is_offload(adapter)) {
		attach_ulds(adapter);
	}
	if (!(registered_notifier_block & CXGB4_INET6ADDR_REGISTERED)) {
		register_inet6addr_notifier(&cxgb4_inet6addr_notifier);
		registered_notifier_block |= CXGB4_INET6ADDR_REGISTERED;
	}
#endif

	print_port_info(adapter);

#ifdef CONFIG_PCI_IOV
	/*
	 * If we want to instantiate Virtual Functions, then our parent
	 * bridge's PCI-E needs to support Alternative Routing ID (ARI)
	 * because our VFs will show up at function offset 8 and above.  One
	 * could easily argue that the core Linux functions should do all of
	 * this checking but they don't ...
	 */
	for (func = 0; func < ARRAY_SIZE(num_vf); func++) {
		struct pci_dev *pbridge;
		int pos;
		u16 flags;
		u32 devcap2;

		if (num_vf[func] <= 0)
			continue;

		/*
		 * So we have at least one set of VFs that we want to
		 * instantiate.  If our parent bridge is at least version 2.0
		 * and supports ARI, we can drop out of this loop and do the
		 * work to instantiate all the desired VFs.
		 */
		pbridge = pdev->bus->self;
		pos = pci_find_capability(pbridge, PCI_CAP_ID_EXP);
		pci_read_config_word(pbridge, pos+PCI_EXP_FLAGS, &flags);
		if ((flags & PCI_EXP_FLAGS_VERS) >= 2) {
			pci_read_config_dword(pbridge, pos+PCI_EXP_DEVCAP2, &devcap2);
			if (devcap2 & PCI_EXP_DEVCAP2_ARI)
				break;
		}

		/*
		 * Our parent bridge does not support ARI so issue a warning
		 * and skip instantiating the VFs.  They won't be reachable.
		 */
		dev_warn(&pdev->dev, "Parent bridge %02x:%02x.%x doesn't "
			 "support ARI; can't instantiate Virtual Functions\n",
			 pbridge->bus->number,
			 PCI_SLOT(pbridge->devfn), PCI_FUNC(pbridge->devfn));
		goto no_vfs;
	}

	/*
	 * Loop accross SR-IOV PFs to see if any VFs need to be
	 * instantiated.
	 */
	for (func = 0; func < ARRAY_SIZE(num_vf); func++) {
		struct pci_dev *pf;

		if (num_vf[func] <= 0)
			continue;

		pf = pci_get_slot(pdev->bus,
				  PCI_DEVFN(PCI_SLOT(pdev->devfn),
					    func));
		if (pf == NULL) {
			dev_warn(&pdev->dev, "failed to find PF%d; not"
				 " enabling %d virtual functions\n",
				 func, num_vf[func]);
			continue;
		}
		err = pci_enable_sriov(pf, num_vf[func]);
		if (err < 0)
			dev_warn(&pf->dev, "failed to instantiate %d"
				 " virtual functions; err=%d\n",
				 num_vf[func], err);
		else {
			dev_info(&pf->dev,
				 "instantiated %u virtual functions\n",
				 num_vf[func]);

			/*
			 * We need to monitor T4 chips to make sure
			 * that their VFs haven't gotten into any
			 * trouble ...
			 */
			if (is_t4(adapter->params.chip))
				adapter->vf_monitor_mask |= 1U << func;
		}
		pci_dev_put(pf);
	}

	/*
	 * If we instantiated any VFs, set up and start recurrant task
	 * to monitor the state of the VFs.
	 */
	if (adapter->vf_monitor_mask) {
		INIT_DELAYED_WORK(&adapter->vf_monitor_task,
				  vf_monitor);
		schedule_delayed_work(&adapter->vf_monitor_task,
				      VF_MONITOR_PERIOD);
	}

 no_vfs:
#endif
#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
	if (!is_t4(adapter->params.chip) && fw_attach)
		cxgb4_ptp_init(adapter);
#endif
	return 0;

	/*
	 * Non-standard returns ...
	 */
 out_disable_interrupts:
	cxgb_disable_msi(adapter);

 out_free_dev:
	if (!is_t4(adapter->params.chip))
		iounmap(adapter->bar2);
	t4_free_mem(adapter->l2t);
	t4_free_mem(adapter->smt);
	t4_free_mem(adapter->srq);
	for_each_port(adapter, i)
		if (adapter->port[i]) {
			pi = netdev_priv(adapter->port[i]);
			if (pi->viid != 0)
				t4_free_vi(adapter, adapter->mbox, adapter->pf,
					   0, pi->viid);
			kfree(adap2pinfo(adapter, i)->rss);
			free_netdev(adapter->port[i]);
		}
	if (adapter->flags & FW_OK)
		t4_fw_bye(adapter, adapter->mbox);
 out_unmap_bar0:
	iounmap(adapter->regs);
 out_free_adapter:
	if (adapter->eeh_workq)
		destroy_workqueue(adapter->eeh_workq);
	if (adapter->workq)
		destroy_workqueue(adapter->workq);

	kfree(adapter->mbox_log);
	kfree(adapter);
 out_disable_device:
	pci_disable_device(pdev);
 out_release_regions:
	pci_release_regions(pdev);
	return err;
}

static void remove_one(struct pci_dev *pdev)
{
	struct adapter *adapter = pci_get_drvdata(pdev);
	int i;

	/*
	 * There are some cases where we end up probing more than one function
	 * in init_one() -- the T4 FPGA where both PFs have the Device ID of
	 * 0xa000, the Diagnostics driver which attaches to PF0 because of a
	 * mis-design "feature" in T4 where PF0..3 all have the same PCI
	 * Device ID, etc.  init_one() doesn't return an error for these
	 * probes because that would unnecessarily confuse people with
	 * warnings in the System Logs, etc.  However, that means that we'll
	 * also get called on all of those same devices here.  We could
	 * perform the same Device/Function ID checks that are in init_one()
	 * but it's simpler to just see if init_one() left an adapter
	 * structure in the Linux PCI Driver Data pointer ...
	 */
	if (!adapter)
		return;

	/*
	 * Tear down per-adapter Work Queue first since it can contain
	 * references to our adapter data structure.
	 */
	destroy_workqueue(adapter->eeh_workq);
	destroy_workqueue(adapter->workq);

#ifdef CONFIG_PCI_IOV
	/*
	 * Tear down VF Monitoring.
	 */
	if (adapter->vf_monitor_mask)
		cancel_delayed_work_sync(&adapter->vf_monitor_task);

	/*
	 * Loop accross SR-IOV PFs to see if any VFs need to be
	 * uninstantiated.
	 */
	{
		int func;

		for (func = 0; func < ARRAY_SIZE(num_vf); func++) {
			struct pci_dev *pf;

			if (num_vf[func] <= 0)
				continue;

			pf = pci_get_slot(pdev->bus,
					  PCI_DEVFN(PCI_SLOT(pdev->devfn),
						    func));
			if (pf == NULL) {
				dev_warn(&pdev->dev, "failed to find PF%d; not"
					 " disabling %d virtual functions\n",
					 func, num_vf[func]);
				continue;
			}
			pci_disable_sriov(pf);
			pci_dev_put(pf);
		}
	}
#endif

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	if (is_t4(adapter->params.chip))
		ocqp_pool_destroy(adapter);
#endif

#ifdef CONFIG_CHELSIO_BYPASS
	/*
	 * We call the Bypass Adapter's shutdown logic here, redundantly with
	 * same call in cxgb_down().  We do this because the interface may
	 * never have been brought up but the adapter's failover mode may have
	 * been set to a new value ...
	 */
	if (is_bypass(adapter)) {
		t4_bypass_shutdown(adapter);
		bypass_sysfs_remove(adapter);
	}
#endif

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
	if (is_offload(adapter)) {
		if (!test_bit(ADAPTER_ERROR, &adapter->adap_err_state))
			detach_ulds(adapter);
	}
	if ((registered_notifier_block & CXGB4_INET6ADDR_REGISTERED) &&
	    list_empty(&adapter_list)) {
		unregister_inet6addr_notifier(&cxgb4_inet6addr_notifier);
		registered_notifier_block &= ~CXGB4_INET6ADDR_REGISTERED;
	}
#endif

	if (adapter->debugfs_root) {
		free_trace_bufs(adapter);
#if DMABUF
		dma_free_coherent(adapter->pdev_dev, DMABUF_SZ,
				adapter->dma_virt, adapter->dma_phys);
#endif
	}

	debugfs_remove_recursive(adapter->debugfs_root);
	/*
	 * Remove sysfs group
	 */
	for_each_port(adapter, i)
		sysfs_remove_group(&adapter->port[i]->dev.kobj,
				   &t4_attr_group);
	disable_interrupts(adapter);
	quiesce_rx(adapter);

	for_each_port(adapter, i)
		if (test_bit(i, &adapter->registered_device_map))
			unregister_netdev(adapter->port[i]);

#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
	if (!is_t4(adapter->params.chip))
		cxgb4_ptp_remove(adapter);
#endif

	/*
	 * If we allocated filters, free up state associated with any
	 * valid filters ...
	 */
	clear_all_filters(adapter);

	if (adapter->flags & FULL_INIT_DONE)
		cxgb_down(adapter);
	t4_free_mem(adapter->l2t);
	t4_free_mem(adapter->smt);
	t4_free_mem(adapter->srq);
	t4_free_mem(adapter->tids.tid_tab);
	t4_free_mem(adapter->filters);
	kfree(adapter->sge.egr_map);
	kfree(adapter->sge.ingr_map);
	kfree(adapter->sge.starving_fl);
	kfree(adapter->sge.txq_maperr);
	kfree(adapter->sge.blocked_fl);
	if (is_t5(adapter->params.chip)) {
		ehash_filter_locks_free(&adapter->filter_tcphash);
		ehash_filter_locks_free(&adapter->filter_udphash);
		t4_free_mem(adapter->filter_tcphash.ehash);
		t4_free_mem(adapter->filter_udphash.ehash);
	}
	cxgb_disable_msi(adapter);

	for_each_port(adapter, i)
		if (adapter->port[i]) {
			struct port_info *pi = adap2pinfo(adapter, i);
			if (pi->viid != 0)
				t4_free_vi(adapter, adapter->mbox,
					   adapter->pf, 0, pi->viid);
			kfree(adap2pinfo(adapter, i)->rss);
			free_netdev(adapter->port[i]);
		}

	if (adapter->flags & FW_OK)
		t4_fw_bye(adapter, adapter->mbox);

	t4_cleanup_clip_tbl(adapter);

	iounmap(adapter->regs);
	if (!is_t4(adapter->params.chip))
		iounmap(adapter->bar2);
#ifdef CONFIG_PO_FCOE
	cxgb_fcoe_exit_ddp(adapter);
#endif /* CONFIG_PO_FCOE */
	pci_disable_pcie_error_reporting(pdev);
	if ((adapter->flags & DEV_ENABLED)) {
		pci_disable_device(pdev);
		adapter->flags &= ~DEV_ENABLED;
	}
	pci_release_regions(pdev);
	kfree(adapter->mbox_log);
	if (adapter->dump_buf) {
		t4_free_mem(adapter->dump_buf);
		atomic_notifier_chain_unregister(&panic_notifier_list,
						 &adapter->panic_nb);
	}
	kfree(adapter);
}

/*
 * "Shutdown" quiesces the device, stopping Ingress Packet and Interrupt
 * delivery.  This is essentially a stripped down version of the PCI remove()
 * function where we do the minimal amount of work necessary to shutdown any
 * further activity.
 *
 * Caveat by DM :  We're leaving stale state behind, hot unplug might trip on that
 */
static void shutdown_one(struct pci_dev *pdev)
{
	struct adapter *adapter = pci_get_drvdata(pdev);
	int i;

	/*
	 * As with remove_one() above (see extended comment), we only want do
	 * do cleanup on PCI Devices which went all the way through init_one()
	 * ...
	 */
	if (!adapter)
		return;

#ifdef CONFIG_PCI_IOV
	/*
 	 * Loop accross SR-IOV PFs to see if any VFs need to be
 	 * uninstantiated.
 	 */
	{
		int func;

		for (func = 0; func < ARRAY_SIZE(num_vf); func++) {
			struct pci_dev *pf;

			if (num_vf[func] <= 0)
				continue;

			pf = pci_get_slot(pdev->bus,
					  PCI_DEVFN(PCI_SLOT(pdev->devfn),
						    func));
			if (pf == NULL) {
				dev_warn(&pdev->dev, "failed to find PF%d; not"
					 " disabling %d virtual functions\n",
					 func, num_vf[func]);
				continue;
			}
			pci_disable_sriov(pf);
			pci_dev_put(pf);
		}
	}
#endif

#ifdef CONFIG_CHELSIO_BYPASS
	/*
	 * We call the Bypass Adapter's shutdown logic here, redundantly with
	 * same call in cxgb_down().  We do this because the interface may
	 * never have been brought up but the adapter's failover mode may have
	 * been set to a new value ...
	 */
	if (is_bypass(adapter))
		t4_bypass_shutdown(adapter);
#endif

	for_each_port(adapter, i)
		if (test_bit(i, &adapter->registered_device_map))
			cxgb_close(adapter->port[i]);

	disable_interrupts(adapter);
	quiesce_rx(adapter);

	cxgb_disable_msi(adapter);

	t4_sge_stop(adapter);
	if (adapter->flags & FW_OK)
		t4_fw_bye(adapter, adapter->mbox);
}

static struct pci_driver cxgb4_driver = {
	.name     = KBUILD_MODNAME,
	.id_table = cxgb4_pci_tbl,
	.probe    = init_one,
	.remove   = remove_one,
	.shutdown = shutdown_one,
	.err_handler = &cxgb4_eeh,
};


static int __init cxgb4_init_module(void)
{
	int ret;

	/* Debugfs support is optional, just warn if this fails */
	cxgb4_debugfs_root = debugfs_create_dir(KBUILD_MODNAME, NULL);
	if (!cxgb4_debugfs_root)
		pr_warn("could not create debugfs entry, continuing\n");

#ifndef CONFIG_CHELSIO_BYPASS
	/*
	 * If we have an Adapter Shutdown Watchdog Timer configured make sure
	 * that A. we can service the requested watchdog timer frequently
	 * enough (i.e. the timer needs to be at least twice the minumum
	 * ersceduling time: HZ) and B. that the timer is at least as large as
	 * the minimum firmware watchdog scheduling quantum (10ms).  Finally,
	 * to prevent absurd performance problems, we limit the minimum period
	 * to DEADMAN_WATCHDOG_MIN.  Since this last constraint is likely to
	 * be larger than the other two constraints we could just use that but
	 * it's better to be explicit about things and let the compiler
	 * optimize the condition ...
	 */
	if (deadman_watchdog[0]) {
		const int min_sched = 1000/HZ * 2;
		const int min_quanta = 10;
		const int min_watchdog = DEADMAN_WATCHDOG_MIN;
		const int max_watchdog = DEADMAN_SHUTDOWN_MAX; 
			
		deadman_watchdog[0] =
			min(max_watchdog,max(deadman_watchdog[0],
			    max(min_sched, max(min_quanta, min_watchdog))));
	}
#endif /* !CONFIG_CHELSIO_BYPASS */

	ret = pci_register_driver(&cxgb4_driver);
	if (ret < 0)
		debugfs_remove(cxgb4_debugfs_root);
	return ret;
}

static void __exit cxgb4_cleanup_module(void)
{
	pci_unregister_driver(&cxgb4_driver);
	debugfs_remove(cxgb4_debugfs_root);  /* NULL ok */
}

module_init(cxgb4_init_module);
module_exit(cxgb4_cleanup_module);
