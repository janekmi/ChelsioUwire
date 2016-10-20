/*
 * Copyright (C) 2003-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/* This file should not be included directly.  Include common.h instead. */

#ifndef __CSIO_ADAPTER_H__
#define __CSIO_ADAPTER_H__

#include <linux/pci.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/timer.h>
#include <linux/cache.h>
#include <linux/bitops.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/vmalloc.h>
#include <asm/io.h>
#include "t4_regs_values.h"
#include "csio_compat.h"

#ifdef T4_TRACE
# define NTRACEBUFS 8
#endif

#define CH_INFO(adap, fmt, ...)   dev_info(adap->pdev_dev, fmt, ## __VA_ARGS__)
#define CH_ERR(adap, fmt, ...)   dev_err(adap->pdev_dev, fmt, ## __VA_ARGS__)
#define CH_WARN(adap, fmt, ...)  dev_warn(adap->pdev_dev, fmt, ## __VA_ARGS__)
#define CH_ALERT(adap, fmt, ...) dev_alert(adap->pdev_dev, fmt, ## __VA_ARGS__)

#define CH_WARN_RATELIMIT(adap, fmt, ...)  do {\
	if (printk_ratelimit()) \
		dev_warn(adap->pdev_dev, fmt, ## __VA_ARGS__); \
} while (0)

/*
 * More powerful macro that selectively prints messages based on msg_enable.
 * For info and debugging messages.
 */
#define CH_MSG(adapter, level, category, fmt, ...) do { \
	if ((adapter)->msg_enable & NETIF_MSG_##category) \
		dev_printk(KERN_##level, adapter->pdev_dev, fmt, \
			   ## __VA_ARGS__); \
} while (0)

#ifdef DEBUG
# define CH_DBG(adapter, category, fmt, ...) \
	CH_MSG(adapter, DEBUG, category, fmt, ## __VA_ARGS__)
#else
# define CH_DBG(adapter, category, fmt, ...)
#endif

#define CH_DUMP_MBOX(adap, mbox, data_reg, size) \
	CH_MSG(adap, INFO, MBOX, \
	       "mbox %u: %llx %llx %llx %llx %llx %llx %llx %llx\n", (mbox), \
	       (unsigned long long)t4_read_reg64(adap, data_reg), \
	       (unsigned long long)t4_read_reg64(adap, data_reg + 8), \
	       (unsigned long long)t4_read_reg64(adap, data_reg + 16), \
	       (unsigned long long)t4_read_reg64(adap, data_reg + 24), \
	       (unsigned long long)t4_read_reg64(adap, data_reg + 32), \
	       (unsigned long long)t4_read_reg64(adap, data_reg + 40), \
	       (unsigned long long)t4_read_reg64(adap, data_reg + 48), \
	       (unsigned long long)t4_read_reg64(adap, data_reg + 56));

/* Additional NETIF_MSG_* categories */
#define NETIF_MSG_DDRFILTER     0x2000000
#define NETIF_MSG_MBOX          0x4000000
#define NETIF_MSG_MMIO          0x8000000

enum {  
	MAX_ETH_QSETS = 32,           /* # of Ethernet Tx/Rx queue sets */
	MAX_OFLD_QSETS = 32,          /* # of offload Tx/Rx queue sets */
	MAX_CTRL_QUEUES = NCHAN,      /* # of control Tx queues */
	MAX_RDMA_QUEUES = NCHAN,      /* # of streaming RDMA Rx queues */
	MAX_RDMA_CIQS = NCHAN,        /* # of  RDMA concentrator IQs */
	MAX_ISCSI_QUEUES = NCHAN,     /* # of streaming iSCSI Rx queues */
	MAX_TRACE_QUEUES = NCHAN,     /* # of Trace Rx queueus */
};

/*      
 * We need to size various arrays and bitmaps to be able to use Ingress and
 * Egress Queue IDs (minus the base starting Ingress/Egress Queue IDs) to
 * index into those arrays/bitmaps.
 *      
 * The maximum number of Egress Queue IDs is determined by the maximum number
 * of Ethernet "Queue Sets" which we support plus Control, Offload "Queue
 * Sets", RDMA and iSCSI RX Queues.  The maximum number of Ingress Queue IDs
 * is also determined by the maximum number of Ethernet "Queue Sets" plus
 * Offload RX Queues, the Asynchronous Firmware Event Queue and the Forwarded
 * Interrupt Queue.
 *
 * Each Ethernet "Queue Set" requires one Ingress Queue for RX Packet Ingress
 * Event notifications and two Egress Queues for a Free List and an Ethernet
 * TX list (remember that a Free List is really an Egress Queue since it
 * contains pointer to host side buffers which the host send to the hardware)
 * The same is true for the Offload "Queue Sets".  And the RDMA and iSCSI RX
 * Queues also have Free Lists, so we need to count those in the Egress Queue
 * count Each Offload "Queue Set" has one Ingress and one Egress Queue.
 */
enum {
	INGQ_EXTRAS = 2,        /* firmware event queue and */
	/*   forwarded interrupts */
	MAX_EGRQ = MAX_ETH_QSETS*2 + MAX_OFLD_QSETS*2
		+ MAX_CTRL_QUEUES
		+ MAX_RDMA_QUEUES + MAX_ISCSI_QUEUES,
	MAX_INGQ = MAX_ETH_QSETS + MAX_OFLD_QSETS
		+ MAX_RDMA_QUEUES + MAX_RDMA_CIQS + MAX_ISCSI_QUEUES
		+ INGQ_EXTRAS,
};

struct adapter;
struct vlan_group;
struct sge_eth_rxq;
struct sge_rspq;

struct port_info {
	struct adapter *adapter;
	struct vlan_group *vlan_grp;
	struct sge_eth_rxq *qs;       /* first Rx queue for this port */
	u16    viid;
	s16    xact_addr_filt;        /* index of exact MAC address filter */
	u16    rss_size;              /* size of VI's RSS table slice */
	s8     mdio_addr;
	u8     port_type;
	u8     mod_type;
	u8     port_id;
	u8     tx_chan;
	u8     lport;                 /* associated offload logical port */
	u8     nqsets;                /* # of qsets */
	u8     first_qset;            /* index of first qset */
	u8     rss_mode;
	struct link_config link_cfg;
	struct port_stats stats_base;
};

struct work_struct;
struct dentry;

enum {                                 /* adapter flags */
	FULL_INIT_DONE     = (1 << 0),
	USING_MSI          = (1 << 1),
	USING_MSIX         = (1 << 2),
	QUEUES_BOUND       = (1 << 3),
	FW_OK              = (1 << 4),
	RSS_TNLALLLOOKUP   = (1 << 5),
	USING_SOFT_PARAMS  = (1 << 6),
	MASTER_PF          = (1 << 7),
	BYPASS_DROP        = (1 << 8),
	FW_OFLD_CONN       = (1 << 9),
	K_CRASH		   = (1 << 10),
};

struct sge_fl;
struct pkt_gl;

typedef int (*rspq_handler_t)(struct sge_rspq *q, const __be64 *rsp,
			      const struct pkt_gl *gl);

struct sge_ofld_rxq;
struct sge_eth_txq;
struct sge_ofld_txq;
struct sge_ctrl_txq;

#define for_each_ethrxq(sge, i) for (i = 0; i < (sge)->ethqsets; i++)
#define for_each_ofldrxq(sge, i) for (i = 0; i < (sge)->ofldqsets; i++)
#define for_each_rdmarxq(sge, i) for (i = 0; i < (sge)->rdmaqs; i++)
#define for_each_rdmaciq(sge, i) for (i = 0; i < (sge)->rdmaciqs; i++)
#define for_each_iscsirxq(sge, i) for (i = 0; i < (sge)->niscsiq; i++)
#define for_each_tracerxq(sge, i) for (i = 0; i < (sge)->ntraceq; i++)

struct l2t_entry;
struct l2t_data;
struct filter_info;

/*
 * The Linux driver needs locking around mailbox accesses ...
 */
#define T4_OS_NEEDS_MBOX_LOCKING 1

/*
 * OS Lock/List primitives for those interfaces in the Common Code which
 * need this.
 */
typedef spinlock_t t4_os_lock_t;
typedef struct t4_os_list {
	struct list_head list;
} t4_os_list_t;


struct adapter {
	void __iomem *regs;
	void __iomem *bar2;
	u32 t4_bar0;
	struct pci_dev *pdev;
	struct device *pdev_dev;
	unsigned long flags;
	u32 use_bd;

	const char *name;
	unsigned int mbox;
	unsigned int pf;
	unsigned int vpd_busy;
	unsigned int vpd_flag;
	int msg_enable;

	struct adapter_params params;

#ifdef T4_TRACE
	struct trace_buf *tb[NTRACEBUFS];
#endif
	struct dentry *debugfs_root; 		/* Debug FS */
	void *dma_virt;
	dma_addr_t dma_phys;

	spinlock_t stats_lock;

	struct net_device *port[MAX_NPORTS];

	/* support for single-threading access to adapter mailbox registers */
	t4_os_lock_t mbox_lock;
	t4_os_list_t mbox_list;
	/* support for mailbox command/reply logging */
	#define T4_OS_LOG_MBOX_CMDS 256
	struct mbox_cmd_log *mbox_log;

	spinlock_t win0_lock ____cacheline_aligned_in_smp;
};

/**
 * t4_read_reg - read a HW register
 * @adapter: the adapter
 * @reg_addr: the register address
 *
 * Returns the 32-bit value of the given HW register.
 */
static inline u32 t4_read_reg(adapter_t *adapter, u32 reg_addr)
{
	u32 val = readl(adapter->regs + reg_addr);

	CH_DBG(adapter, MMIO, "read register 0x%x value 0x%x\n", reg_addr,
	       val);
	return val;
}

/**
 * t4_write_reg - write a HW register
 * @adapter: the adapter
 * @reg_addr: the register address
 * @val: the value to write
 *
 * Write a 32-bit value into the given HW register.
 */
static inline void t4_write_reg(adapter_t *adapter, u32 reg_addr, u32 val)
{
	CH_DBG(adapter, MMIO, "setting register 0x%x to 0x%x\n", reg_addr,
	       val);
	writel(val, adapter->regs + reg_addr);
}

#ifndef readq
static inline u64 readq(const volatile void __iomem *addr)
{
	return readl(addr) + ((u64)readl(addr + 4) << 32);
}

static inline void writeq(u64 val, volatile void __iomem *addr)
{
	writel(val, addr);
	writel(val >> 32, addr + 4);
}
#endif

/**
 * t4_read_reg64 - read a 64-bit HW register
 * @adapter: the adapter
 * @reg_addr: the register address
 *
 * Returns the 64-bit value of the given HW register.
 */
static inline u64 t4_read_reg64(adapter_t *adapter, u32 reg_addr)
{
	u64 val = readq(adapter->regs + reg_addr);

	CH_DBG(adapter, MMIO, "64-bit read register %#x value %#llx\n",
	       reg_addr, (unsigned long long)val);
	return val;
}

/**
 * t4_write_reg64 - write a 64-bit HW register
 * @adapter: the adapter
 * @reg_addr: the register address
 * @val: the value to write
 *
 * Write a 64-bit value into the given HW register.
 */
static inline void t4_write_reg64(adapter_t *adapter, u32 reg_addr, u64 val)
{
	CH_DBG(adapter, MMIO, "setting register %#x to %#llx\n", reg_addr,
	       (unsigned long long)val);
	writeq(val, adapter->regs + reg_addr);
}

/**
 * t4_os_pci_write_cfg4 - 32-bit write to PCI config space
 * @adapter: the adapter
 * @reg: the register address
 * @val: the value to write
 *
 * Write a 32-bit value into the given register in PCI config space.
 */
static inline void t4_os_pci_write_cfg4(adapter_t *adapter, int reg, u32 val)
{
	pci_write_config_dword(adapter->pdev, reg, val);
}

/**
 * t4_os_pci_read_cfg4 - read a 32-bit value from PCI config space
 * @adapter: the adapter
 * @reg: the register address
 * @val: where to store the value read
 *
 * Read a 32-bit value from the given register in PCI config space.
 */
static inline void t4_os_pci_read_cfg4(adapter_t *adapter, int reg, u32 *val)
{
	pci_read_config_dword(adapter->pdev, reg, val); 
}

/**
 * t4_os_pci_write_cfg2 - 16-bit write to PCI config space
 * @adapter: the adapter
 * @reg: the register address
 * @val: the value to write
 *
 * Write a 16-bit value into the given register in PCI config space.
 */
static inline void t4_os_pci_write_cfg2(adapter_t *adapter, int reg, u16 val)
{
	pci_write_config_word(adapter->pdev, reg, val);
}

/**
 * t4_os_pci_read_cfg2 - read a 16-bit value from PCI config space
 * @adapter: the adapter
 * @reg: the register address
 * @val: where to store the value read
 *
 * Read a 16-bit value from the given register in PCI config space.
 */
static inline void t4_os_pci_read_cfg2(adapter_t *adapter, int reg, u16 *val)
{
	pci_read_config_word(adapter->pdev, reg, val); 
}

/**
 * t4_os_find_pci_capability - lookup a capability in the PCI capability list
 * @adapter: the adapter
 * @cap: the capability
 *
 * Return the address of the given capability within the PCI capability list.
 */
static inline int t4_os_find_pci_capability(adapter_t *adapter, int cap)
{
	return pci_find_capability(adapter->pdev, cap);
}

/**
 * t4_os_pci_read_seeprom - read four bytes of SEEPROM/VPD contents
 * @adapter: the adapter
 * @addr: SEEPROM/VPD Address to read
 * @valp: where to store the value read
 *
 * Read a 32-bit value from the given address in the SEEPROM/VPD.  The address
 * must be four-byte aligned.  Returns 0 on success, a negative erro number
 * on failure.
 */
static inline int t4_os_pci_read_seeprom(adapter_t *adapter,
					 int addr, u32 *valp)
{
	ssize_t ret;

	/*
	 * For newer versions of Linux we use the OS APIs in order to
	 * serialize accesses to the PCI VPD Capability.  For older versions
	 * we just have to use our VPD Capability directly since Linux didn't
	 * export an interface in the past.
	 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
	int t4_seeprom_read(struct adapter *adapter, u32 addr, u32 *data);

	ret = t4_seeprom_read(adapter, addr, valp);
#else
	ret = pci_read_vpd(adapter->pdev, addr, sizeof(u32), valp);
#endif

	return ret >= 0 ? 0 : ret;
}

/**
 * t4_os_pci_write_seeprom - write four bytes of SEEPROM/VPD contents
 * @adapter: the adapter
 * @addr: SEEPROM/VPD Address to write
 * @val: the value write
 *
 * Write a 32-bit value to the given address in the SEEPROM/VPD.  The address
 * must be four-byte aligned.  Returns 0 on success, a negative erro number
 * on failure.
 */
static inline int t4_os_pci_write_seeprom(adapter_t *adapter,
					  int addr, u32 val)
{
	ssize_t ret;

	/*
	 * For newer versions of Linux we use the OS APIs in order to
	 * serialize accesses to the PCI VPD Capability.  For older versions
	 * we just have to use our VPD Capability directly since Linux didn't
	 * export an interface in the past.
	 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
	int t4_seeprom_write(struct adapter *adapter, u32 addr, u32 data);

	ret = t4_seeprom_write(adapter, addr, val);
#else
	ret = pci_write_vpd(adapter->pdev, addr, sizeof(u32), &val);
#endif

	return ret >= 0 ? 0 : ret;
}

/**
 * t4_os_set_hw_addr - store a port's MAC address in SW
 * @adapter: the adapter
 * @port_idx: the port index
 * @hw_addr: the Ethernet address
 *
 * Store the Ethernet address of the given port in SW.  Called by the common
 * code when it retrieves a port's Ethernet address from EEPROM.
 */
static inline void t4_os_set_hw_addr(adapter_t *adapter, int port_idx,
				     u8 hw_addr[])
{
	memcpy(adapter->port[port_idx]->dev_addr, hw_addr, ETH_ALEN);
	memcpy(adapter->port[port_idx]->perm_addr, hw_addr, ETH_ALEN);
}

/**
 * adap2pinfo - return the port_info of a port
 * @adap: the adapter
 * @idx: the port index
 *
 * Return the port_info structure for the port of the given index.
 */
static inline struct port_info *adap2pinfo(struct adapter *adap, int idx)
{
	return netdev_priv(adap->port[idx]);
}

/**
 * t4_os_lock_init - initialize spinlock
 * @lock: the spinlock
 */
static inline void t4_os_lock_init(t4_os_lock_t *lock)
{
	spin_lock_init(lock);
}

/**
 * t4_os_trylock - try to acquire a spinlock
 * @lock: the spinlock
 *
 * Returns 1 if successful and 0 otherwise.
 */
static inline int t4_os_trylock(t4_os_lock_t *lock)
{
	return spin_trylock_bh(lock);
}

/**
 * t4_os_lock - spin until lock is acquired
 * @lock: the spinlock
 */
static inline void t4_os_lock(t4_os_lock_t *lock)
{
	spin_lock_bh(lock);
}

/**
 * t4_os_unlock - unlock a spinlock
 * @lock: the spinlock
 */
static inline void t4_os_unlock(t4_os_lock_t *lock)
{
	spin_unlock_bh(lock);
}

/**
 * t4_os_init_list_head - initialize 
 * @head: head of list to initialize [to empty]
 */
static inline void t4_os_init_list_head(t4_os_list_t *head)
{
	INIT_LIST_HEAD(&head->list);
}

static inline struct t4_os_list *t4_os_list_first_entry(t4_os_list_t *head)
{
	return list_first_entry(&head->list, t4_os_list_t, list);
}

/**
 * t4_os_atomic_add_tail - Enqueue list element atomically onto list
 * @new: the entry to be addded to the queue
 * @head: current head of the linked list
 * @lock: lock to use to guarantee atomicity
 */
static inline void t4_os_atomic_add_tail(t4_os_list_t *new,
					 t4_os_list_t *head,
					 t4_os_lock_t *lock)
{
	t4_os_lock(lock);
	list_add_tail(&new->list, &head->list);
	t4_os_unlock(lock);
}

/**
 * t4_os_atomic_list_del - Dequeue list element atomically from list
 * @entry: the entry to be remove/dequeued from the list.
 * @lock: the spinlock
 */
static inline void t4_os_atomic_list_del(t4_os_list_t *entry,
					 t4_os_lock_t *lock)
{
	t4_os_lock(lock);
	list_del(&entry->list);
	t4_os_unlock(lock);
}

/*
 *  * Allocate a chunk of memory using kmalloc or, if that fails, vmalloc.
 *   * The allocated memory is cleared.
 *    */
static inline void *t4_alloc_mem(size_t size)
{
        void *p = kmalloc(size, GFP_KERNEL);

        if (!p)
                p = vmalloc(size);
        if (p)
                memset(p, 0, size);
        return p;
}

/*
 *  * Free memory allocated through alloc_mem().
 *   */
static inline void t4_free_mem(void *addr)
{
        if (is_vmalloc_addr(addr))
                vfree(addr);
        else
                kfree(addr);
}

static inline unsigned int t4_use_ldst(struct adapter *adap)
{
	return (adap->flags & FW_OK) || (!adap->use_bd);
}

/**
 *     t4_os_timestamp - return an opaque OS-dependent 64-bit timestamp
 *
 *     This is used by the Common Code to timestamp various things.
 *     It's up to OS-dependent code to use these later ...
 */
static inline u64 t4_os_timestamp(void)
{
	return jiffies;
}

static inline void t4_db_full(struct adapter *adap) {}
static inline void t4_db_dropped(struct adapter *adap) {}

#define OFFLOAD_DEVMAP_BIT 15

static inline void t4_os_portmod_changed(const struct adapter *adap, 
		int port_id) {}
static inline void t4_os_link_changed(struct adapter *adap, int port_id, 
		int link_stat) {}

void *t4_alloc_mem(size_t size);
void t4_free_mem(void *addr);
#define t4_os_alloc(_size)     t4_alloc_mem((_size))
#define t4_os_free(_ptr)       t4_free_mem((_ptr))

void t4_free_sge_resources(struct adapter *adap);
void t4_free_ofld_rxqs(struct adapter *adap, int n, struct sge_ofld_rxq *q);
irq_handler_t t4_intr_handler(struct adapter *adap);
int t4_eth_xmit(struct sk_buff *skb, struct net_device *dev);
int t4vf_eth_xmit(struct sk_buff *skb, struct net_device *dev);
int t4_ethrx_handler(struct sge_rspq *q, const __be64 *rsp,
		     const struct pkt_gl *gl);
int t4_trace_handler(struct sge_rspq *q, const __be64 *rsp,
		     const struct pkt_gl *gl);
int t4_mgmt_tx(adapter_t *adap, struct sk_buff *skb);
int t4_ofld_send(struct adapter *adap, struct sk_buff *skb);
int t4_sge_alloc_rxq(struct adapter *adap, struct sge_rspq *iq, bool fwevtq,
		     struct net_device *dev, int intr_idx,
		     struct sge_fl *fl, rspq_handler_t hnd, int cong);
int t4_sge_alloc_eth_txq(struct adapter *adap, struct sge_eth_txq *txq,
			 struct net_device *dev, struct netdev_queue *netdevq,
			 unsigned int iqid);
int t4_sge_alloc_ctrl_txq(struct adapter *adap, struct sge_ctrl_txq *txq,
			  struct net_device *dev, unsigned int iqid,
			  unsigned int cmplqid);
int t4_sge_alloc_ofld_txq(struct adapter *adap, struct sge_ofld_txq *txq,
			  struct net_device *dev, unsigned int iqid);
irqreturn_t t4_sge_intr_msix(int irq, void *cookie);
int t4_sge_init(struct adapter *adap);
void t4_sge_init_tasklet(struct adapter *adap);
void t4_sge_start(struct adapter *adap);
void t4_sge_stop(struct adapter *adap);
int t4_sge_coalesce_handler(struct adapter *adap, struct sge_eth_txq *q);


extern int dbfifo_int_thresh;

/* Enable stats via debugfs/procfs */
#define __DRIVER_ETHTOOL_UNSUPPORTED__
/* Required for meminfo_show compilation */
#define __NO_DRIVER_OCQ_SUPPORT__
#endif /* __T4_ADAPTER_H__ */
