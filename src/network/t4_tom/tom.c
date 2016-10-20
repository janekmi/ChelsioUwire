/*
 * Copyright (C) 2003-2015 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */
#include "defs.h"
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/hash.h>
#include <linux/ip.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include <linux/toedev.h>
#include <net/addrconf.h>
#include <net/offload.h>
#include "l2t.h"
#include "tom.h"
#include "t4_ddp.h"
#include "cxgb4_ctl_defs.h"
#include "cxgb4_ofld.h"
#include "clip_tbl.h"
#include "t4_regs.h"
#include "t4fw_interface.h"
#include "t4_ma_failover.h"
#include "version.h"
#include "trace.h"
#include "offload.h"
#include "common.h"

#ifdef WD_TOE
/* needed by WD-TOE library */
#include <linux/cdev.h>
#include <linux/device.h>
#include "wd_qp.h"
#include "ntuples.h"

#define wdtoe "wdtoe"
#endif

#ifdef WD_TOE
/*
 * WD-TOE char dev structures for US <-> KS mapping communication
 */
dev_t wdtoe_dev;
struct class *wdtoe_devclass;
static struct cdev wdtoe_cdev;
static struct device *wdtoe_devnode;
struct conn_tuple *conn_tuple;
struct wdtoe_listen_device *listen_table;
struct passive_tuple *passive_conn_tuple;
#endif

#ifdef T4_TRACE_TOM
static struct dentry *tom_debugfs_root;
#endif

static int activated = 1;
module_param(activated, int, 0644);
MODULE_PARM_DESC(activated, "whether to enable TOE at init time or not");

/*
 * Module unloading doesn't work reliably at this time.  This module
 * parameter allows the administrator to explicitly enable the ability
 * to unload the module when the module is loaded.  This ability is
 * unsupported and may very well not work and/or result in the system
 * crashing.
 */
static int unsupported_allow_unload = 0;
module_param_unsafe(unsupported_allow_unload, int, 0644);
MODULE_PARM_DESC(unsupported_allow_unload, "allow UNSUPPORTED unloading of module");

/*
 * By default, we offload every connection and listener of which we are
 * capable.  Setting cop_managed_offloading to a non-zero value puts
 * offloading decisions under the sole purview of a Connection Offload Policy
 * (COP).  As a consequence, if there is no COP loaded, then no connections,
 * listeners, etc. will be offloaded.  And thus, when this module is first
 * loaded and cop_managed_offloading is set, no offloading will be done until
 * the first COP is loaded.
 *
 * Note that loading a new COP cannot retroactively revoke offloading
 * decisions made by previous COPs.  In order to accomplish that semantic, the
 * existing offloaded services must be restarted with the new COP in effect.
 */
static int cop_managed_offloading = 0;
module_param(cop_managed_offloading, int, 0644);
MODULE_PARM_DESC(cop_managed_offloading,
		 "all connection offloading decision managed by COP");

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
static int offload_vlan = 0;
module_param(offload_vlan, int, 0644);
MODULE_PARM_DESC(offload_vlan,
		 "Only Offload connections on the indicated VLAN");

#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
static uint send_page_order;
#else
static uint send_page_order = (14 - PAGE_SHIFT < 0) ? 0 : 14 - PAGE_SHIFT;
#endif
module_param(send_page_order, uint, 0644);
MODULE_PARM_DESC(send_page_order, "order of page allocation for sendmsg");

static LIST_HEAD(tdev_list);
static DEFINE_MUTEX(tdev_list_lock);
static LIST_HEAD(tdev_na_list);
static LIST_HEAD(tdev_rcu_list);
static DEFINE_SPINLOCK(tdev_rcu_lock);

static struct offload_id t4_toe_id_tab[] = {
        { TOE_ID_CHELSIO_T4, 0 },
        { 0 }
};

bool in_shutdown = true;

#ifdef WD_TOE
/*
 * Get a free entry from the kernel table where the active 
 * connection information is stored
 */
static ssize_t wdtoe_get_conn_tuples(struct cxgb4_lld_info *lldi,
					const char __user *buf,
					int in_len, int out_len)
{
	struct wdtoe_conn_tuples_cmd cmd;

	if (copy_from_user(&cmd, buf, sizeof(cmd)))
		return -EFAULT;

	if (copy_to_user((void __user *)(unsigned long)cmd.response,
				conn_tuple,
				sizeof(*conn_tuple) * NWDTOECONN))
		return -EFAULT;

	return in_len;
}
#endif

#ifdef WD_TOE
/*
 * Get a free entry from the kernel table where the passive
 * connection information is stored
 */
static ssize_t wdtoe_get_passive_tuples(struct cxgb4_lld_info *lldi,
					const char __user *buf,
					int in_len, int out_len)
{

	struct wdtoe_passive_tuples_cmd cmd;

	if (copy_from_user(&cmd, buf, sizeof(cmd)))
		return -EFAULT;

	if (copy_to_user((void __user *)(unsigned long)cmd.response,
			passive_conn_tuple,
			sizeof(*passive_conn_tuple) * NWDTOECONN))
		return -EFAULT;

	return in_len;
}
#endif

#ifdef WD_TOE
/*
 * This is the function handler table to receive command from the 
 * user land WD-TOE library via the per stack char device.
 *
 * These functions do things that are specific to a stack. Such as
 * create the IQ/FL for the stack, passing CPLs back to kernel..
 */
/* XXX need an exit for bad command */
static ssize_t (*wdtoe_cmd_table_new[])(struct cxgb4_lld_info *lldi,
					struct wdtoe_device *wd_dev,
                                    const char __user *buf, int in_len,
                                    int out_len) = {
	[WDTOE_CMD_CREATE_RXQ]  = wdtoe_create_rxq,
	/*
	[WDTOE_CMD_PASS_PID] = wdtoe_pass_pid,
	[WDTOE_CMD_CPL_TO_TOM] = wdtoe_pass_cpl_to_tom,
	[WDTOE_CMD_CONN_TUPLES] = wdtoe_get_conn_tuples,
	[WDTOE_CMD_PASS_TUPLES] = wdtoe_get_passive_tuples,
	[WDTOE_CMD_UPDATE_RX_CREDITS] = wdtoe_update_rx_credits,
	[WDTOE_CMD_COPY_RXQ] = wdtoe_copy_rxq,
	[WDTOE_CMD_GET_PORT_NUM] = wdtoe_get_port_num,
	[WDTOE_CMD_CREATE_DEV] = wdtoe_create_dev,
	*/
	[WDTOE_CMD_PASS_PID] = NULL,
	[WDTOE_CMD_CPL_TO_TOM] = wdtoe_pass_cpl_to_tom,
	[WDTOE_CMD_CONN_TUPLES] = NULL,
	[WDTOE_CMD_PASS_TUPLES] = NULL,
	[WDTOE_CMD_UPDATE_RX_CREDITS] = wdtoe_update_rx_credits,
	[WDTOE_CMD_COPY_RXQ] = wdtoe_copy_rxq,
	[WDTOE_CMD_GET_PORT_NUM] = NULL,
	[WDTOE_CMD_CREATE_DEV] = NULL,
	[WDTOE_CMD_REG_LISTEN] = wdtoe_reg_listen,
	[WDTOE_CMD_REMOVE_LISTEN] = wdtoe_remove_listen,
	[WDTOE_CMD_CREATE_MEMPOOL] = wdtoe_create_mempool,
	[WDTOE_CMD_COPY_TXQ] = wdtoe_copy_txq,
	[WDTOE_CMD_REG_STACK] = wdtoe_reg_stack,
	[WDTOE_CMD_SEND_FLOWC] = wdtoe_send_tx_flowc_wr,
};
#endif

#ifdef WD_TOE
/*
 * This is the function handler table to receive command from the 
 * user land WD-TOE library via the global, management char device.
 *
 * These functions are for managment of WD-TOE stacks. It does things
 * like create a per stack char dev for a new WD-TOE stack, enquiry 
 * the physical port number of the adapter
 */
/* XXX need an exit for bad command */
static ssize_t (*wdtoe_cmd_table[])(struct cxgb4_lld_info *lldi,
                                    const char __user *buf, int in_len,
                                    int out_len) = {
	[WDTOE_CMD_CREATE_RXQ]  = NULL,
	[WDTOE_CMD_PASS_PID] = wdtoe_pass_pid, /* XXX not used? to remove. */
	[WDTOE_CMD_CPL_TO_TOM] = NULL,
	[WDTOE_CMD_CONN_TUPLES] = wdtoe_get_conn_tuples,
	[WDTOE_CMD_PASS_TUPLES] = wdtoe_get_passive_tuples,
	[WDTOE_CMD_UPDATE_RX_CREDITS] = NULL,
	[WDTOE_CMD_COPY_RXQ] = NULL,
	[WDTOE_CMD_GET_PORT_NUM] = wdtoe_get_port_num,
	[WDTOE_CMD_CREATE_DEV] = wdtoe_create_dev,
	[WDTOE_CMD_REG_LISTEN] = NULL,
	[WDTOE_CMD_REMOVE_LISTEN] = NULL,
	[WDTOE_CMD_CREATE_MEMPOOL] = NULL,
	[WDTOE_CMD_COPY_TXQ] = NULL,
	[WDTOE_CMD_REG_STACK] = NULL,
	[WDTOE_CMD_SEND_FLOWC] = NULL,
};
#endif

#ifdef WD_TOE
/*
 * XXX currently the "lld" and "tom_data" are both cached when 
 * XXX uld has a state change, i.e. when t4_tom module is inserted
 */
struct cxgb4_lld_info *cached_lldi = NULL;
struct tom_data *cached_td = NULL;

/*
 * Size of FL is 256 and size of IQ is 1024
 */
#define WDTOE_FL_BUF_NUMBER 256
struct wdtoe_device_table *wdtoe_dev_table;
#endif

/*
 * Add an skb to the deferred skb queue for processing from process context.
 */
void t4_defer_reply(struct sk_buff *skb, struct toedev *dev,
		    defer_handler_t handler)
{
	struct tom_data *td = TOM_DATA(dev);

	DEFERRED_SKB_CB(skb)->handler = handler;
	spin_lock_bh(&td->deferq.lock);
	__skb_queue_tail(&td->deferq, skb);
	if (skb_queue_len(&td->deferq) == 1)
		schedule_work(&td->deferq_task);
	spin_unlock_bh(&td->deferq.lock);
}

/*
 * Process the defer queue.
 */
DECLARE_TASK_FUNC(process_deferq, task_param)
{
	struct sk_buff *skb;
	struct tom_data *td = WORK2TOMDATA(task_param, deferq_task);

	spin_lock_bh(&td->deferq.lock);
	while ((skb = __skb_dequeue(&td->deferq)) != NULL) {
		spin_unlock_bh(&td->deferq.lock);
		DEFERRED_SKB_CB(skb)->handler(&td->tdev, skb);
		spin_lock_bh(&td->deferq.lock);
	}
	spin_unlock_bh(&td->deferq.lock);
}

/*
 * Process a received packet with an unknown/unexpected CPL opcode.
 */
static int do_bad_cpl(struct tom_data *td, struct sk_buff *skb)
{
	printk(KERN_ERR "%s: received bad CPL command %u\n", td->tdev.name,
	       *skb->data);
	return CPL_RET_BUF_DONE | CPL_RET_BAD_MSG;
}

/*
 * Handlers for each CPL opcode
 */
static t4tom_cpl_handler_func tom_cpl_handlers[NUM_CPL_CMDS];

/*
 * tom_cpl_iscsi_callback -
 * iscsi and tom would share the following cpl messages, so when any of these
 * message is received, after tom is done with processing it, the messages
 * needs to be forwarded to iscsi for further processing:
 * - CPL_SET_TCB_RPL
 * - CPL_RX_DATA_DDP 
 */
void (*tom_cpl_iscsi_callback)(struct tom_data *, struct sock *,
				struct sk_buff *, unsigned int);
int (*fp_iscsi_lro_rcv)(struct sock *sk, u8 op, const __be64 *rsp,
			struct napi_struct *napi,
			const struct pkt_gl *gl, struct t4_lro_mgr *lro_mgr,
			void (*t4tom_flush)(struct t4_lro_mgr *,
					    struct sk_buff *));
void (*fp_iscsi_lro_proc_rx)(struct sock *sk, struct sk_buff *skb);

/*
 * Add a new handler to the CPL dispatch table.  A NULL handler may be supplied
 * to unregister an existing handler.
 */
void t4tom_register_cpl_handler(unsigned int opcode, t4tom_cpl_handler_func h)
{
	if (opcode < NUM_CPL_CMDS)
		tom_cpl_handlers[opcode] = h ? h : do_bad_cpl;
	else
		printk(KERN_ERR "Chelsio T4/T5/T6 TOM: handler registration for "
		       "opcode %u failed\n", opcode);
}
EXPORT_SYMBOL(t4tom_register_cpl_handler);

/*
 * Check if the handler function is set for a given CPL
 * return 0 if the function is NULL or do_bad_cpl, 1 otherwise.
 */
int t4tom_cpl_handler_registered(unsigned int opcode)
{
	if (opcode < NUM_CPL_CMDS)
		return (tom_cpl_handlers[opcode]) &&
			(tom_cpl_handlers[opcode] != do_bad_cpl);
	else {
		printk(KERN_ERR "Chelsio T4/T5/T6 TOM: CPL opcode %u INVALID.\n",
			opcode);
		return -EINVAL;
	}
}
EXPORT_SYMBOL(t4tom_cpl_handler_registered);

/*
 * set the tom_cpl_iscsi_callback function, this function should be used
 * whenever both toe and iscsi need to process the same cpl msg.
 */
void t4tom_register_cpl_iscsi_callback(void (*fp)(struct tom_data *,
					struct sock *, struct sk_buff *,
					unsigned int))
{
	tom_cpl_iscsi_callback = fp;
}
EXPORT_SYMBOL(t4tom_register_cpl_iscsi_callback);

void t4tom_register_iscsi_lro_handler(
			int (*fp_rcv)(struct sock *, u8,
				const __be64 *,
				struct napi_struct *napi,
				const struct pkt_gl *,
				struct t4_lro_mgr *,
				void (*t4_lro_fluch_func)(struct t4_lro_mgr *,
					struct sk_buff *)),
			void (*fp_proc)(struct sock *, struct sk_buff *))
{
	fp_iscsi_lro_rcv = fp_rcv;
	fp_iscsi_lro_proc_rx = fp_proc;
}
EXPORT_SYMBOL(t4tom_register_iscsi_lro_handler);

int t4_close(struct toedev *dev)
{
	struct tom_data *d = TOM_DATA(dev);
	struct tid_info *t = d->tids;

	if (atomic_read(&t->tids_in_use) + atomic_read(&t->hash_tids_in_use) +
			t->atids_in_use)
		return -EIO;
	return 0;
}

/*
 * Make a preliminary determination if a connection can be offloaded.  It's OK
 * to fail the offload later if we say we can offload here.  For now this
 * always accepts the offload request unless there are IP options.
 */
int t4_can_offload(struct toedev *dev, struct sock *sk)
{
	struct tom_data *d = TOM_DATA(dev);
	struct tid_info *t = d->tids;

        return inet_sk(sk)->inet_opt == NULL && d->conf.activated &&
            (d->conf.max_conn < 0 ||
	     atomic_read(&t->tids_in_use) +
	     atomic_read(&t->hash_tids_in_use) +
	     t->atids_in_use < d->conf.max_conn);
}

static int listen_offload(void *dev, struct sock *sk)
{
	struct offload_req req;

	offload_req_from_sk(&req, sk, OPEN_TYPE_LISTEN);
	t4_listen_start(dev, sk, &req);
	return 0;
}

/*
 * This is called through a notifier chain when a socket listen event is
 * published.  We iterate through all the TOEs we are handling and establish
 * or close listening servers as appropriate.
 */
static int listen_notify_handler(struct notifier_block *this,
                                 unsigned long event, void *data)
{
        struct sock *sk = data;
	struct tom_data *td;
        struct toedev *tdev;
        struct offload_req req;

        if (event == OFFLOAD_LISTEN_START)
                offload_req_from_sk(&req, sk, OPEN_TYPE_LISTEN);

        switch (event) {
        case OFFLOAD_LISTEN_START:
        case OFFLOAD_LISTEN_STOP:
                mutex_lock(&tdev_list_lock);
                list_for_each_entry(td, &tdev_list, list_node) {
			tdev = &td->tdev;
                        if (event == OFFLOAD_LISTEN_START)
                                t4_listen_start(tdev, sk, &req);
                        else
                                t4_listen_stop(tdev, sk);
                }
                mutex_unlock(&tdev_list_lock);
                break;
        }
        return NOTIFY_DONE;
}

/*
 * Add a T4 offload device to the list of devices we are managing.
 */
static void toedev_add(struct toedev *t)
{
	struct tom_data *td = TOM_DATA(t);

	mutex_lock(&tdev_list_lock);
	list_add_tail(&td->list_node, &tdev_list);
	list_del(&td->na_node);
	mutex_unlock(&tdev_list_lock);

	spin_lock(&tdev_rcu_lock);
	list_add_tail_rcu(&td->rcu_node, &tdev_rcu_list);
	spin_unlock(&tdev_rcu_lock);
}

#ifdef CONFIG_PROC_FS
#include <linux/proc_fs.h>
#include "t4_linux_fs.h"

static int proc_info_show(struct seq_file *seq, void *v)
{
        struct tom_data *d = seq->private;

	seq_printf(seq, "MSS: %u\n", d->conf.mss);

#ifdef DEBUG
	seq_printf(seq, "RSPQ alloc_skb: %u\n", atomic_read(&d->rspq_alloc_count));
	seq_printf(seq, "RSPQ reuse_skb: %u\n", atomic_read(&d->rspq_reuse_count));
#endif
        return 0;
}

static int proc_info_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_info_show, PDE_DATA(inode));
}

static const struct file_operations proc_info_fops = {
	.open = proc_info_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static void tom_info_proc_free(struct proc_dir_entry *dir)
{
        if (dir)
                remove_proc_entry("info", dir);
}

static int tom_info_proc_setup(struct proc_dir_entry *dir, struct tom_data *d)
{
        struct proc_dir_entry *p;

        if (!dir)
                return -EINVAL;

	p = proc_create_data("info", S_IRUGO, dir,
			     &proc_info_fops, d);
        if (!p)
                return -ENOMEM;

        SET_PROC_NODE_OWNER(p, THIS_MODULE);
        return 0;
}

static void tom_proc_init(struct toedev *dev)
{
        t4_listen_proc_setup(dev->proc_dir, TOM_DATA(dev));
        tom_info_proc_setup(dev->proc_dir, TOM_DATA(dev));
}

static void tom_proc_cleanup(struct toedev *dev)
{
	if (dev->offload_mod) {
		t4_listen_proc_free(dev->proc_dir);
		tom_info_proc_free(dev->proc_dir);
	}
}
#else
#define tom_proc_init(dev)
#define tom_proc_cleanup(dev)
#endif

#ifndef NETEVENT
static void tom_neigh_update(struct toedev *dev, struct neighbour *neigh)
{
	struct tom_data *t = TOM_DATA(dev);

}
#endif

static int tom_ctl(struct toedev *tdev, unsigned int req, void *data)
{
	struct tom_data *d = TOM_DATA(tdev);
	struct bond_ports *bond_ports;

	switch(req) {
		case FAILOVER_ACTIVE_SLAVE:
		case FAILOVER_PORT_DOWN:
		case FAILOVER_PORT_UP:
		case FAILOVER_PORT_RELEASE:
			bond_ports = data;
			t4_ports_failover(tdev->lldev[bond_ports->port], req,
					  bond_ports, d->lldi->l2t, 0);
			break;
		case FAILOVER_BOND_DOWN:
			bond_ports = data;
			t4_bond_port_disable(tdev->lldev[bond_ports->port], false,
					     bond_ports);
			break;
		case FAILOVER_BOND_UP:
			bond_ports = data;
			t4_bond_port_disable(tdev->lldev[bond_ports->port], true,
					     bond_ports);
			break;
		default:
			return -EOPNOTSUPP;
	}
	return 0;
}

/*
 ** Allocate a chunk of memory using kmalloc or, if that fails, vmalloc.
 ** The allocated memory is cleared.
 **/
static void *t4tom_alloc_mem(unsigned long size)
{
	void *p = kmalloc(size, GFP_KERNEL);

	if (!p)
		p = vmalloc(size);
	if (p)
		memset(p, 0, size);
	return p;
}

/*
 * Free memory allocated through t4tom_alloc_mem().
 */
void t4tom_free_mem(void *addr)
{
        unsigned long p = (unsigned long) addr;

        if (p >= VMALLOC_START && p < VMALLOC_END)
                vfree(addr);
        else
                kfree(addr);
}

static int t4_toe_attach(struct toedev *dev, const struct offload_id *entry)
{
	struct tom_data *t = TOM_DATA(dev);

	toedev_add(dev);
	T4_INIT_WORK(&t->deferq_task, process_deferq, t);
	spin_lock_init(&t->listen_lock);
	spin_lock_init(&t->synq_lock);

	/* On 32bit arches, an skb frag is limited to 2^15 */
	t->send_page_order = min_t(uint, get_order(32768), send_page_order);
	t->tx_max_chunk = 1 << 20; /* 1MB */
	t4_init_tunables(t);

	/* Adjust TOE activation for this module */
	t->conf.activated = activated;
	t->conf.cop_managed_offloading = cop_managed_offloading;
	
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
	t->conf.offload_vlan = offload_vlan;

	rcu_assign_pointer(dev->can_offload, t4_can_offload);
	rcu_assign_pointer(dev->in_shutdown, NULL);
	dev->connect = t4_connect;
	dev->ctl = tom_ctl;
	dev->failover = t4_failover;
	init_completion(&dev->shutdown_completion);
#ifndef NETEVENT
	dev->neigh_update = tom_neigh_update;
#endif
	dev->close = t4_close;
	tom_proc_init(dev);
#ifdef CONFIG_SYSCTL
	t->sysctl = t4_sysctl_register(dev, &t->conf);
#endif
	synchronize_rcu();
	return 0;
}

void t4_stop_all_listeners(struct toedev *tdev)
{
        struct tom_data *t = TOM_DATA(tdev);
        struct tid_info *tinfo = t->tids;
        struct serv_entry *tstid = (struct serv_entry *)tinfo->stid_tab;
        struct sock **tids = NULL;
        unsigned int stids_in_use, stopped = 0;

        spin_lock(&tinfo->stid_lock);
        stids_in_use = (tinfo->stids_in_use - tinfo->v6_stids_in_use) +
			(tinfo->v6_stids_in_use >> 1);
        if (stids_in_use) {
                tids = kzalloc(stids_in_use*sizeof(struct sock *), GFP_ATOMIC);
                if (!tids) {
                        spin_unlock(&tinfo->stid_lock);
                        return;
                }
                do {
                        if (tstid) {
                                struct listen_ctx *listen_ctx = (struct listen_ctx *)tstid->data;
                                if (listen_ctx) {
                                        struct sock *lsk = listen_ctx->lsk;
                                        struct tom_data *d = listen_ctx->tom_data;

                                        if (lsk && (d == t)) {
                                                sock_hold(lsk);
                                                tids[stopped] = lsk;
                                                stopped++;
						tstid++;
						if (lsk->sk_family == PF_INET6)
							tstid++;
                                        }
                                }
                        }
			if (tstid > &tinfo->stid_tab[tinfo->nstids+tinfo->nsftids-1])
				break;
                } while (tstid && (stopped < stids_in_use));
        }
        spin_unlock(&tinfo->stid_lock);

        if (tids && stopped) {
                unsigned int idx;

                for (idx=0; idx < stopped; idx++) {
                        struct sock *sk;
			unsigned int refcnt;
			unsigned int counter = 0;

                        sk = tids[idx];
                        lock_sock(sk);
			refcnt = atomic_read(&sk->sk_refcnt);
                        t4_listen_stop(&t->tdev, sk);
                        release_sock(sk);
			while ((atomic_read(&sk->sk_refcnt) >= refcnt) && (counter < 1000)) {
				udelay(10);
				counter++;
			}
                        sock_put(sk);
                }
                kfree(tids);
        }
}

void bl_abort_ofld_conn(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios;
	struct tcp_sock *tp;

	tp = tcp_sk(sk);
	cplios = CPL_IO_STATE(sk);

	if (cplios_flag(sk, CPLIOS_ABORT_REQ_RCVD) ||
			cplios_flag(sk, CPLIOS_ABORT_SHUTDOWN))
		return;

	t4_purge_receive_queue(sk);
	t4_purge_write_queue(sk);
	t4_send_reset(sk, CPL_ABORT_SEND_RST, skb);
}



static int abort_ofld_conn(struct sock *sk, struct net_device *egress_dev)
{

	struct sk_buff *skb;
	struct net_device *netdev = NULL;
	struct cpl_io_state *cplios;
	struct tcp_sock *tp;
	struct toe_hash_params hash_params;
	struct neighbour *neigh;

	sock_hold(sk);
	bh_lock_sock(sk);
	tp = tcp_sk(sk);
	cplios = CPL_IO_STATE(sk);

	neigh = cplios->l2t_entry->neigh;
	if (sk->sk_family == AF_INET) {
		init_toe_hash_params(&hash_params, neigh->dev, neigh,
				     inet_sk(sk)->inet_saddr,
				     inet_sk(sk)->inet_daddr,
				     inet_sk(sk)->inet_sport,
				     inet_sk(sk)->inet_dport,
				     NULL, NULL, false, IPPROTO_TCP);
		netdev = offload_get_phys_egress(&hash_params, TOE_FAILOVER);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	} else {
		init_toe_hash_params(&hash_params, neigh->dev, neigh,
				     0, 0, inet_sk(sk)->inet_sport,
				     inet_sk(sk)->inet_dport,
				     &inet6_sk_saddr(sk).s6_addr32[0],
				     &inet6_sk_daddr(sk).s6_addr32[0],
				     true, IPPROTO_TCP);
		netdev = offload_get_phys_egress(&hash_params, TOE_FAILOVER);
#endif
	}

	if (netdev != egress_dev)
		goto unlock;

	if (cplios_flag(sk, CPLIOS_ABORT_REQ_RCVD) ||
			cplios_flag(sk, CPLIOS_ABORT_SHUTDOWN))
		goto unlock;


	if (sk->sk_state != TCP_CLOSE) {
		skb = alloc_skb(sizeof(struct cpl_abort_req), GFP_ATOMIC);
		if(!skb) {
			printk("%s: skb allocation failed\n", __func__);
			goto unlock;
		}

		sk->sk_err = ECONNRESET;
		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_error_report (sk);

		if (sock_owned_by_user(sk)
#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
				|| cplios->zcopy_dma_unacked
#endif
		   ) {
			BLOG_SKB_CB(skb)->backlog_rcv = bl_abort_ofld_conn;
			__sk_add_backlog(sk, skb);

			goto unlock;
		}

		t4_purge_receive_queue(sk);
		t4_purge_write_queue(sk);
		t4_send_reset(sk, CPL_ABORT_SEND_RST, skb);
	}
	bh_unlock_sock(sk);
	sock_put(sk);
	return 0;

unlock:
	bh_unlock_sock(sk);
	sock_put(sk);
	return 1;
}


/*
 * Reset all active open connections running on egress_dev
 * Bug 20103 workaround, connection migration needs to be implemented to
 * exactly mimic NIC behavior.
 */
unsigned int t4_rst_all_conn(struct toedev *dev, struct net_device *egress_dev)
{
	struct tom_data *td = TOM_DATA(dev);
	struct tid_info *tinfo = td->tids;
	struct sock *sk;
	struct cpl_io_state *cplios;
	int tid, atid;
	unsigned int tids_in_use, tids_signalled = 0;
	unsigned int atids_in_use, atids_signalled = 0;

	tids_in_use = atomic_read(&tinfo->tids_in_use) +
			atomic_read(&tinfo->hash_tids_in_use);

	for (tid = 0; tid < tinfo->ntids && tids_signalled < tids_in_use ; tid++) {
		sk = lookup_tid(tinfo, tid);
		if (sk) {
			if (!abort_ofld_conn(sk, egress_dev))
				tids_signalled++;
		}
	}

	atids_in_use = tinfo->atids_in_use;
	for (atid = 0; atid < tinfo->natids && atids_signalled < atids_in_use; atid++) {
		cplios = lookup_atid(tinfo, atid);
		if (cplios) {
			if (!abort_ofld_conn(cplios->sk, egress_dev))
				atids_signalled++;
		}
	}
	return (tids_in_use ?: atids_in_use);
}

static void t4_stop_ofld_tx(struct toedev *dev)
{
	struct tom_data *td = TOM_DATA(dev);
	struct tid_info *tinfo = td->tids;
	struct sock *sk;
	struct cpl_io_state *cplios;
	int tid, atid;
	unsigned int tids_in_use, tids_signalled = 0;
	unsigned int atids_in_use, atids_signalled = 0;

	tids_in_use = atomic_read(&tinfo->tids_in_use) +
			atomic_read(&tinfo->hash_tids_in_use);

	for (tid = 0; tid < tinfo->ntids && tids_signalled < tids_in_use ; tid++) {
		sk = lookup_tid(tinfo, tid);
		if (sk) {
			sock_hold(sk);
			lock_sock(sk);
			cplios_set_flag(sk, CPLIOS_TX_WAIT_IDLE);
			release_sock(sk);
			sock_put(sk);
			tids_signalled++;
		}
	}

	atids_in_use = tinfo->atids_in_use;
	for (atid = 0; atid < tinfo->natids && atids_signalled < atids_in_use; atid++) {
		cplios = lookup_atid(tinfo, atid);
		if (cplios) {
			sk = cplios->sk;
			sock_hold(sk);
			lock_sock(sk);
			cplios_set_flag(sk, CPLIOS_TX_WAIT_IDLE);
			release_sock(sk);
			sock_put(sk);
			atids_signalled++;
		}
	}
}

extern void t4_release_offload_resources(struct sock *sk);

static int t4_toe_detach(struct toedev *dev)
{
	int i;

	for (i = 0; i < dev->nlldev; i++)
		netdev_clear_offload(dev->lldev[i]);
	rcu_assign_pointer(dev->can_offload, NULL);
	synchronize_rcu();
	t4_stop_all_listeners(dev);
	return 0;
}

static struct tom_info t4_tom_info = {
	.attach = t4_toe_attach,
	.detach = t4_toe_detach,
	.id_table = t4_toe_id_tab,
	.name = "Chelsio-T4",
	.owner = THIS_MODULE,
	.refcnt = ATOMIC_INIT(0)
};

static struct notifier_block listen_notifier = {
        .notifier_call = listen_notify_handler
};

static void update_clip(struct tom_data *t)
{
#if defined(CONFIG_TCPV6_OFFLOAD)
	int i;

	rcu_read_lock();

	/* note that we explicitly don't itterate over the loopback ports */
	for (i = 0; i < NCHAN; i++) {
		struct net_device *dev = t->egr_dev[i];
		int ret = 0;

		if (dev)
			ret = cxgb4_update_root_dev_clip(dev);

		if (ret < 0)
			break;
	}
	rcu_read_unlock();
#endif
}

static void *t4tom_uld_add(const struct cxgb4_lld_info *infop)
{
	struct cxgb4_lld_info *lldi;
	struct tom_data *t;
	struct toedev *tdev;
	struct adap_ports *port_info;
	int i, j;

	t = kcalloc(1, sizeof(*t), GFP_KERNEL);
	if (!t)
		goto out;

	lldi = kcalloc(1, sizeof(struct cxgb4_lld_info), GFP_KERNEL);
	if (!lldi)
		goto out;

	*lldi = *infop;

	port_info = kcalloc(1, sizeof(*port_info), GFP_KERNEL);
        if (!port_info)
                goto out;

	t->lldi = lldi;
	t->pdev = lldi->pdev;
	t->max_wr_credits = lldi->wr_cred - DIV_ROUND_UP(sizeof(struct cpl_abort_req), 16);
	t->mtus = lldi->mtus;
	t->tids = lldi->tids;
	port_info->nports = lldi->nports;
	for (i = 0 ; i < lldi->nports ; i++)
		port_info->lldevs[i] = lldi->ports[i];
	t->ports = port_info;

        /* Register TCP offload device */
        tdev = &t->tdev;
	init_offload_dev(tdev);
	tdev->ttid = TOE_ID_CHELSIO_T4;
	tdev->nlldev = lldi->nports;
        tdev->lldev = lldi->ports;
	t->pfvf = G_FW_VIID_PFN(cxgb4_port_viid(tdev->lldev[0])) << S_FW_VIID_PFN;

	/* OK if this fails, we just can't do DDP */
	spin_lock_init(&t->ppod_map_lock);
	t->start_tag = 0;
	if (lldi->vr->ddp.size) {
		unsigned int ppod_bmap_size;

                t->ddp_llimit = lldi->vr->ddp.start;
                t->nppods = lldi->vr->ddp.size / PPOD_SIZE;
		t->nppods -= (t->nppods % PPOD_CLUSTER_SIZE);
		ppod_bmap_size = BITS_TO_LONGS(t->nppods);
		t->ppod_bmap = t4tom_alloc_mem(sizeof(*t->ppod_bmap)*ppod_bmap_size);
        } else {
		t->ddp_llimit = 0;
                t->nppods = 0;
                t->ppod_bmap = NULL;
        }


        if (register_toedev(tdev, "toe%d")) {
                printk("unable to register offload device");
                goto out;
        }

	for (i = 0; i < (1 << TOM_RSPQ_HASH_BITS); i++) {
		unsigned int size = 64 - sizeof(struct rsp_ctrl) - 8;

		t->rspq_skb_cache[i] = __alloc_skb(size, gfp_any(), 0, lldi->nodeid);
	}

#ifdef DEBUG
	atomic_set(&t->rspq_alloc_count, 0);
	atomic_set(&t->rspq_reuse_count, 0);
#endif

	/* NULL out port and loopback ports */
	for (i = 0; i < ARRAY_SIZE(t->egr_dev); i++)
		t->egr_dev[i] = NULL;

       for (i = 0; i < tdev->nlldev; i++)
                netdev_set_offload(tdev->lldev[i]);

       for (i = 0; i < NCHAN; i++)
		for (j = 0; j < tdev->nlldev; j++)
			if (cxgb4_port_chan(tdev->lldev[j]) == i) {
				t->egr_dev[i] =		// Port
				t->egr_dev[i+NCHAN] =	// Loopback
					tdev->lldev[j];
				break;
			}

        /* Update bonding devices capabilities */
        t4_update_master_devs(tdev);

	skb_queue_head_init(&t->deferq);
        INIT_LIST_HEAD(&t->list_node);
	INIT_LIST_HEAD(&t->rcu_node);
	INIT_LIST_HEAD(&t->na_node);

	mutex_lock(&tdev_list_lock);
	list_add_tail(&t->na_node, &tdev_na_list);
	mutex_unlock(&tdev_list_lock);
out:
	return t;
}

inline struct sk_buff *copy_gl_to_skb_pkt(const struct pkt_gl *gl,
					     const __be64 *rsp,
					     u32 pktshift)
{
        struct sk_buff *skb;

	/* Allocate space for cpl_pass_accpet_req which will be synthesized by
	 * driver. Once driver synthesizes cpl_pass_accpet_req the skb will go
	 * through the regular cpl_pass_accept_req processing in TOM.
	 */
	skb = alloc_skb(gl->tot_len + sizeof(struct cpl_pass_accept_req) - pktshift, GFP_ATOMIC);
	if (unlikely(!skb))
		return NULL;

	 __skb_put(skb, gl->tot_len + sizeof(struct cpl_pass_accept_req) - pktshift);
	/* For now we will copy  cpl_rx_pkt in the skb */
	skb_copy_to_linear_data(skb, rsp, sizeof(struct cpl_rx_pkt));
	skb_copy_to_linear_data_offset(skb, sizeof(struct cpl_pass_accept_req)
						, gl->va + pktshift, gl->tot_len - pktshift);

	return skb;
}

/* T4 LLD delivers one skb at a time */
static inline int t4_recv(struct tom_data *td, struct sk_buff **skbs, const __be64 *rsp)
{
        struct sk_buff *skb = *skbs;
	const struct cpl_tx_data *rpl = cplhdr(skb);
        unsigned int opcode = G_CPL_OPCODE(ntohl(OPCODE_TID(rpl)));
	int ret;

	__skb_push(skb, sizeof(struct rss_header));
	skb_copy_to_linear_data(skb, rsp, sizeof(struct rss_header));

	ret = tom_cpl_handlers[opcode](td, skb);

#if VALIDATE_TID
        if (ret & CPL_RET_UNKNOWN_TID)
                printk(KERN_ERR "t4_recv %s: CPL message (opcode %u) had "
                       "unknown TID %u\n", td->tdev.name, opcode, GET_TID(rpl));
#endif
        if (ret & CPL_RET_BUF_DONE)
		kfree_skb(skb);

        return 0;
}

int t4_recv_rsp(struct tom_data *td, const __be64 *rsp)
{
	const struct cpl_act_establish *rpl = (struct cpl_act_establish *)rsp;
	unsigned int opcode = G_CPL_OPCODE(ntohl(OPCODE_TID(rpl)));
        unsigned int len = 64 - sizeof(struct rsp_ctrl) - 8;
        struct sk_buff *skb;
	unsigned long rspq_bin;
	int ret;

	/* skb's put on socket receive queues currently use
	   sk_eat_skb() which calls __kfree_skb(). */
	if ((*(u8 *)rsp == CPL_RX_DATA_DDP) ||
		(*(u8 *)rsp == CPL_RX_DDP_COMPLETE) ||
		(*(u8 *)rsp == CPL_SET_TCB_RPL))
		goto new_skb;

	rspq_bin = hash_ptr((void *)rsp, TOM_RSPQ_HASH_BITS);
	skb = td->rspq_skb_cache[rspq_bin];
        if (skb && !skb_is_nonlinear(skb) &&
		!skb_shared(skb) && !skb_cloned(skb)) {
			if (atomic_inc_return(&skb->users) == 2) {
                		__skb_trim(skb, 0);
                		if (skb_tailroom(skb) >= len) {
#ifdef DEBUG
					atomic_inc(&td->rspq_reuse_count);
#endif
                        		goto copy_out;
				}
			}
			atomic_dec(&skb->users);
        }
new_skb:
        skb = alloc_skb(len, GFP_ATOMIC);
        if (unlikely(!skb))
		return -1;
#ifdef DEBUG
	atomic_inc(&td->rspq_alloc_count);
#endif
copy_out:
        __skb_put(skb, len);
        skb_copy_to_linear_data(skb, rsp, len);

	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);

	ret = tom_cpl_handlers[opcode](td, skb);
#if VALIDATE_TID
        if (ret & CPL_RET_UNKNOWN_TID)
                printk(KERN_ERR "t4_recv %s: CPL message (opcode %u) had "
                       "unknown TID %u\n", td->tdev.name, opcode, GET_TID(rpl));
#endif
		
	if (ret & CPL_RET_BUF_DONE)
		kfree_skb(skb);
	return 0;
}

static inline int t4_recv_pkt(struct tom_data *td, struct napi_struct *napi,
			      const struct pkt_gl *gl, const __be64 *rsp)
{
	unsigned int opcode = *(u8 *)rsp;
	struct sk_buff *skb;
	int ret;

	skb = copy_gl_to_skb_pkt(gl, rsp, td->lldi->sge_pktshift);
	if (skb == NULL)
		return -ENOMEM;
	ret = tom_cpl_handlers[opcode](td, skb);

	if (ret & CPL_RET_BUF_DONE)
		kfree_skb(skb);

        return 1;
}

#define RX_PULL_LEN 128
extern int t4_lro_receive_gl(struct cpl_io_state *cplios,
			     struct napi_struct *napi,
			     const struct pkt_gl *gl,
			     struct t4_lro_mgr *lro_mgr,
			     const __be64 *rsp);

extern void t4_lro_flush_all(struct t4_lro_mgr *lro_mgr);
extern void t4_lro_flush(struct t4_lro_mgr *lro_mgr,
			 struct sk_buff *skb);

void t4tom_uld_lro_flush(struct t4_lro_mgr *lro_mgr)
{
	t4_lro_flush_all(lro_mgr);
}

/**
 *	t4tom_uld_rx_handler - process an ingress offload packet
 *	@q: the response queue that received the packet
 *	@rsp: the response queue descriptor holding the offload message
 *	@gl: the gather list of packet fragments
 *
 *	Process an ingress offload packet and deliver it to the offload modules.
 */
#define IS_ISCSI_OPCODE(op)	\
	((op) == CPL_ISCSI_HDR || (op) == CPL_ISCSI_DATA || \
	(op) == CPL_RX_ISCSI_DDP || (op) == CPL_RX_ISCSI_DIF)

int t4tom_uld_rx_handler(void *handle, const __be64 *rsp,
			 const struct pkt_gl *gl,
			 struct t4_lro_mgr *lro_mgr, struct napi_struct *napi)
{
	struct tom_data *td = handle;
	struct sk_buff *skb;
	struct sock *sk = NULL;
	struct cpl_io_state *cplios = NULL;
	unsigned int op = *(u8 *)rsp;
	bool rxdata = (op == CPL_RX_DATA);

	if (unlikely(op == CPL_RX_PKT)) {
		if (t4_recv_pkt(td, napi, gl, rsp) < 0)
			goto nomem;
		return 0;
	}

	/* Get the socket structure for this packet */
	if (lro_mgr && (op != CPL_FW6_MSG) &&
		/* no RX_DATA yet to flush */
		       (op != CPL_ACT_OPEN_RPL)) {
		unsigned int hwtid;

		/* Get the TID of this connection */
		if (gl) {
			struct cpl_tx_data *rpl = gl->va;
			hwtid = GET_TID(rpl);
		} else {
			struct cpl_act_establish *rpl =
				 (struct cpl_act_establish *)rsp;
			hwtid = GET_TID(rpl);
		}
		sk = lookup_tid(td->tids, hwtid);
		if (sk)
			cplios = CPL_IO_STATE(sk);
	}

	if (cplios && (IS_ISCSI_OPCODE(op)) && fp_iscsi_lro_rcv) {
		if (!fp_iscsi_lro_rcv(sk, op, rsp, napi, gl,
				      lro_mgr, t4_lro_flush))
			return 0;
	}

	/* Flush the LROed skb on receiving any cpl
	 * other than FW4_ACK and RX_DATA
	 */
	if (cplios && cplios->lro_skb && !rxdata && (op != CPL_FW4_ACK))
		t4_lro_flush(lro_mgr, cplios->lro_skb);

	if (gl == NULL)
		return t4_recv_rsp(td, rsp);
	else {
		 /* Try to aggregate if,
		 * 1. Gather list uses pages
		 * 2. It is CPL_RX_DATA packet
		 * 3. DDP is disabled
		 * 4. LRO is enabled
		 */
		if (cplios && cplios->lro && rxdata &&
		      (cplios->ulp_mode != ULP_MODE_TCPDDP)) {
			if (!t4_lro_receive_gl(cplios, napi, gl, lro_mgr, rsp))
					return 0;
		}

		skb = cxgb4_pktgl_to_skb(napi, gl, RX_PULL_LEN, RX_PULL_LEN);
		if (unlikely(!skb))
			goto nomem;
		tom_skb_set_napi_id(skb, napi->napi_id);
	}
	t4_recv(td, &skb, rsp);
	return 0;
	
nomem:
	return -1;
}

static void t4tom_remove(struct tom_data *dev)
{ 
	struct toedev *tdev = &dev->tdev;
	struct sk_buff *skb;
	int i;

	dev->conf.activated = 0;
	cancel_work_sync(&dev->deferq_task);
	tom_proc_cleanup(tdev);

	if (deactivate_offload(tdev) == 0) {
#ifdef CONFIG_SYSCTL
		t4_sysctl_unregister(dev->sysctl);
#endif
		unregister_toedev(tdev);
	}
	spin_lock_bh(&dev->deferq.lock);
	while ((skb = __skb_dequeue(&dev->deferq)) != NULL) {
		kfree_skb(skb);
	}
	spin_unlock_bh(&dev->deferq.lock);

	if (dev->ppod_bmap) {
		t4tom_free_mem(dev->ppod_bmap);
		dev->ppod_bmap = NULL;
	}
	for (i = 0; i < (1 << TOM_RSPQ_HASH_BITS); i++) {
		kfree_skb(dev->rspq_skb_cache[i]);
		dev->rspq_skb_cache[i] = NULL;
	}
}

static int t4tom_uld_state_change(void *handle, enum cxgb4_state new_state)
{
	struct tom_data *t = handle;
	struct toedev *tdev = &t->tdev;

	switch(new_state) {
	case CXGB4_STATE_UP: {
		t->rss_qid = t->lldi->rxq_ids[0];
		if (!activate_offload(&t->tdev))
			walk_listens(&t->tdev, listen_offload);

		update_clip(t);
#ifdef T4_TRACE_TOM
		if (tom_debugfs_root) {
			struct toedev *tdev = &t->tdev;

			t->debugfs_root = debugfs_create_dir(tdev->name,
							     tom_debugfs_root);
			if (t->debugfs_root) {
				char s[16];
				int i;

				for (i = 0; i < T4_TRACE_TOM_BUFFERS ; i++) {
					sprintf(s, "tid%d", i);
					t->tb[i] = t4_trace_alloc(t->debugfs_root,
								  s, 512);
				}
			}
		}
#endif
#ifdef WD_TOE
		/* XXX caching the "lldi" and "td"(tom_data) */
		cached_lldi = t->lldi;
		cached_td = handle;
#endif
		break;
	}
	case CXGB4_STATE_DOWN:
		break;
	case CXGB4_STATE_START_RECOVERY:
		break;
	case CXGB4_STATE_DETACH:
		mutex_lock(&tdev_list_lock);
#ifdef T4_TRACE_TOM
		if (t->debugfs_root) {
			int i;

			for (i = 0; i < T4_TRACE_TOM_BUFFERS ; i++)
				t4_trace_free(t->tb[i]);

			debugfs_remove(t->debugfs_root);
               	}
#endif
		t4tom_remove(t);
		mutex_unlock(&tdev_list_lock);
		break;
	case CXGB4_STATE_SHUTDOWN:
		{
			rcu_assign_pointer(tdev->in_shutdown, &in_shutdown);
			synchronize_rcu();
			t4_stop_ofld_tx(tdev);
			break;
		}
	}
	return 0;
}

static int t4tom_uld_control(void *handle, enum cxgb4_control control, ...)
{
	struct tom_data *t = handle;
	va_list ap;
	int ret = 0;

	switch (control) {
	case CXGB4_CONTROL_SET_OFFLOAD_POLICY:
		va_start(ap, control);
		ret = set_offload_policy(&t->tdev,
					 va_arg(ap, struct ofld_policy_file *));
		va_end(ap);
		break;

	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

/*
 * Initialize the CPL dispatch table.
 */
static void __init init_cpl_handlers(void)
{
	int i;

	for (i = 0; i < NUM_CPL_CMDS; ++i) {
		tom_cpl_handlers[i] = do_bad_cpl;
	}
	t4_init_listen_cpl_handlers();
}

static struct cxgb4_uld_info t4tom_uld_info = {
	.name = "t4_tom",
	.add = t4tom_uld_add,
	.ma_failover_handler = t4tom_ma_failover_handler,
	.state_change = t4tom_uld_state_change,
	.control = t4tom_uld_control,
	.lro_rx_handler = t4tom_uld_rx_handler,
	.lro_flush = t4tom_uld_lro_flush,
};

#ifdef WD_TOE
/*
 * Catch the write() call to the per-stack char dev
 */
static ssize_t wdtoe_write_new(struct file *filp, const char __user *buf,
				size_t len, loff_t *loff)
{
	struct wdtoe_cmd_hdr hdr;
	struct wdtoe_device *wd_dev;

	wd_dev = (struct wdtoe_device *)filp->private_data;

	if (wd_dev == NULL) {
		return -EFAULT;
	}

	/* error out if we have not received the entire cmd from user's write */
	if (len < sizeof hdr)
		return -EINVAL;

	/* copy the generic cmd part from user space */
	if (copy_from_user(&hdr, buf, sizeof hdr))
		return -EFAULT;

	if (hdr.in_words * 4 != len)
		return -EINVAL;

	if (cached_lldi == NULL) {
		printk(KERN_ERR "t4_tom: [wdtoe] cached_lldi is null (aborting)");
		return -EINVAL;
	}
	if (cached_td == NULL) {
		printk(KERN_ERR "t4_tom: [wdtoe] cached_td is null (aborting)");
		return -EINVAL;
	}

	/* call the function according to the CMD opcode */
	/* XXX need an error out if command is not in the table */
	return wdtoe_cmd_table_new[hdr.command](cached_lldi, wd_dev,
						buf + sizeof hdr, 
						hdr.in_words * 4,
						hdr.out_words * 4);
}
#endif

#ifdef WD_TOE
/*
 * Catch the write() call to the global, management char dev of WD-TOE lib
 */
static ssize_t wdtoe_write(struct file *filp, const char __user *buf,
				size_t len, loff_t *loff)
{
    struct wdtoe_cmd_hdr hdr;

    /* error out if we have not received the entire cmd from user's write */
    if (len < sizeof hdr)
        return -EINVAL;

    /* copy the generic cmd part from user space */
    if (copy_from_user(&hdr, buf, sizeof hdr))
        return -EFAULT;

    if (hdr.in_words * 4 != len)
        return -EINVAL;

	if (cached_lldi == NULL) {
		printk(KERN_ERR "t4_tom: [wdtoe] cached_lldi is null (aborting)");
		return -EINVAL;
	}
	if (cached_td == NULL) {
		printk(KERN_ERR "t4_tom: [wdtoe] cached_td is null (aborting)");
		return -EINVAL;
	}

    /* call the function according to the CMD opcode */
    /* XXX need an error out if command is not in the table */
    return wdtoe_cmd_table[hdr.command](cached_lldi, buf + sizeof hdr, 
                                            hdr.in_words * 4, hdr.out_words * 4);
}
#endif

#ifdef WD_TOE
/*
 * file operation handler for the global, stack-management char dev
 */
static struct file_operations wdtoe_fops = {
	.write = wdtoe_write,
};
#endif

#ifdef WD_TOE
/*
 * file operation handler for the per-stack char dev
 */
struct file_operations per_stack_wdtoe_fops = {
	.open = wdtoe_open,
	.write = wdtoe_write_new,
	.mmap = wdtoe_mmap,
	.release = wdtoe_close,
};
#endif

#ifdef WD_TOE
/*
 * WD-TOE init function, being called when t4_tom's init time
 */
static int wdtoe_init(void)
{
	int ret = 0;
	int i;

	ret = alloc_chrdev_region(&wdtoe_dev, 0, NWDTOECONN, wdtoe);
	if (ret < 0) {
		printk(KERN_ERR "%s: could not allocate major number\n", __func__);
		goto out;
	}

	cdev_init(&wdtoe_cdev, &wdtoe_fops);
	if ((ret = cdev_add(&wdtoe_cdev, wdtoe_dev, 1)) < 0)
		goto out_unalloc_region;

	wdtoe_devclass = class_create(THIS_MODULE, wdtoe);
	if (IS_ERR(wdtoe_devclass))
		goto out_unalloc_region;

	wdtoe_devnode = device_create(wdtoe_devclass, NULL, MKDEV(MAJOR(wdtoe_dev), 0),
								  NULL, wdtoe);
	if (IS_ERR(wdtoe_devnode))
		goto out_unregister_devnode;
	
	/* everything in wdtoe_dev_table is init to 0 or NULL */
	wdtoe_dev_table = kcalloc(WDTOE_DEV_TABLE_ENTRY, 
				sizeof(struct wdtoe_device_table), GFP_KERNEL);
	if (!wdtoe_dev_table)
		goto out_unregister_devnode;
	/* initialize the lock associated with each entry */
	for (i = 0; i < WDTOE_DEV_TABLE_ENTRY; i++) {
		/*XXX error check on the return value? */
		spin_lock_init(&wdtoe_dev_table[i].lock);
	}

	conn_tuple = kcalloc(NWDTOECONN, sizeof(*conn_tuple), GFP_KERNEL);

	if (!conn_tuple)
		goto out_unregister_devnode;

	/* Here we rely on the kcalloc to zero the passive_conn_tuple */
	passive_conn_tuple = kcalloc(NWDTOECONN, sizeof(*passive_conn_tuple),
					GFP_KERNEL);
	if (!passive_conn_tuple)
		goto out_unregister_devnode;

	for (i = 0; i < NWDTOECONN; i++) {
		passive_conn_tuple[i].tid = -2;
	}

	listen_table = kcalloc(NWDTOECONN, sizeof(*listen_table), GFP_KERNEL);
	if (!listen_table)
		goto out_unregister_devnode;

	return ret;

out_unregister_devnode:
	class_destroy(wdtoe_devclass);
out_unalloc_region:
	unregister_chrdev_region(wdtoe_dev, 1);
out:
	return ret;
}
#endif

#ifdef WD_TOE
/*
 * Clean up WD-TOE when tom is removed from the system
 */
static void wdtoe_cleanup(void)
{
	device_destroy(wdtoe_devclass, MKDEV(MAJOR(wdtoe_dev), 0));
	class_destroy(wdtoe_devclass);
	cdev_del(&wdtoe_cdev);
	unregister_chrdev_region(wdtoe_dev, 1);
}
#endif

static
int __init t4_tom_init(void)
{
#ifdef WD_TOE
	int ret = 0;
#endif
	int err;
	struct socket *sock;

	CPLIOS_SKB_CB_CHECK;

#ifdef CONFIG_CHELSIO_T4_OFFLOAD_MODULE
	err = prepare_tom_for_offload();
	if (err)
		return err;
#endif
	err = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	if (err < 0) {
		printk(KERN_ERR "Could not create TCP socket, error %d\n", err);
		return err;
	}

	sock_release(sock);

	init_cpl_handlers();
	if (t4_init_cpl_io() < 0)
		return -1;

	t4_init_offload_ops();

	 /* Register with the TOE device layer. */

	if (register_tom(&t4_tom_info) != 0) {
		printk(KERN_ERR
		       "Unable to register Chelsio T4/T5/T6 TCP offload module.\n");
		return -1;
	}

	register_listen_offload_notifier(&listen_notifier);

#ifdef T4_TRACE_TOM
        tom_debugfs_root = debugfs_create_dir("t4_tom", NULL);
        if (!tom_debugfs_root)
                printk(KERN_WARNING
                        "t4_tom: could not create debugfs entry, continuing\n");
#endif

	cxgb4_register_uld(CXGB4_ULD_TOE, &t4tom_uld_info);

#ifdef UDP_OFFLOAD
	/*Initialize UDP offload */
	udpoffload4_register();
#endif

#ifdef CONFIG_MODULE_UNLOAD
#ifndef LINUX_2_4
	if (unsupported_allow_unload)
		printk(KERN_ALERT "t4_tom: Unloading module may not work"
		       " and is an unsupported option ...\n");
	else
#endif
		THIS_MODULE->exit = NULL;
#endif
#ifdef WD_TOE
	/*
	 * WD-TOE init
	 */
	ret = wdtoe_init();
	if (ret)
		printk(KERN_ERR "t4_tom: could not initialize wdtoe\n");
#endif
	return 0;
}

late_initcall(t4_tom_init);   /* initialize after TCP */

static void __exit t4_tom_exit(void)
{
	struct tom_data *dev, *tmp;

#ifdef T4_TRACE_TOM
	if (tom_debugfs_root)
		debugfs_remove(tom_debugfs_root);
#endif

	unregister_listen_offload_notifier(&listen_notifier);

	t4_inet_twsk_purge(&tcp_hashinfo, &tcp_death_row, AF_INET);
#if defined(CONFIG_TCPV6_OFFLOAD)
	t4_inet_twsk_purge(&tcp_hashinfo, &tcp_death_row, AF_INET6);
#endif

	mutex_lock(&tdev_list_lock);
	list_for_each_entry_safe(dev, tmp, &tdev_na_list, na_node) {
		t4tom_remove(dev);
		list_del(&dev->na_node);
		kfree(dev->lldi);
		kfree(dev->ports);
		kfree(dev);
	}
	list_for_each_entry_safe(dev, tmp, &tdev_list, list_node) {
		t4tom_remove(dev);
		list_del(&dev->list_node);
	}
	mutex_unlock(&tdev_list_lock);

	list_for_each_entry_safe(dev, tmp, &tdev_rcu_list, rcu_node) {
		list_del_rcu(&dev->rcu_node);
		synchronize_rcu();
		kfree(dev->lldi);
		kfree(dev->ports);
		kfree(dev);
	}

#ifdef UDP_OFFLOAD
	/*Unregister UDP offload */
	udpoffload4_unregister();
#endif
	unregister_tom(&t4_tom_info);
	cxgb4_unregister_uld(CXGB4_ULD_TOE);

#ifdef WD_TOE
	wdtoe_cleanup();
#endif
	t4_free_sk_filter();
}
module_exit(t4_tom_exit);

MODULE_DESCRIPTION("TCP offload module for Chelsio T4/T5/T6-based network cards");
MODULE_AUTHOR("Chelsio Communications");
MODULE_LICENSE("GPL");
MODULE_VERSION(TOM_VERSION);
