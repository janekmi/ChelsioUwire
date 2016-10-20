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
#include <linux/param.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <linux/netdevice.h>
#include <linux/toedev.h>
#include "l2t.h"
#include "cpl_io_state.h"
#include "tom.h"
#include "cxgb4_ofld.h"
#include "tom_compat.h"
#include "offload.h"

static int vmdirectio = 0;
module_param(vmdirectio, int, 0644);
MODULE_PARM_DESC(vmdirectio, "VMDirectPath tuning");

/* This belongs in linux/sysctl.h */
#define CTL_TOE 11

/* sysctl ids for tunables */
enum {
	TOE_CONF_MAX_HOST_SNDBUF = 1,
	TOE_CONF_TX_HOLD_THRES,
	TOE_CONF_MAX_WR_CREDITS,
	TOE_CONF_RX_CREDIT_THRES,
	TOE_CONF_MSS,
	TOE_CONF_DELACK,
	TOE_CONF_MAX_CONN,
	TOE_CONF_SOFT_BACKLOG_LIMIT,
	TOE_CONF_KSEG_DDP,
	TOE_CONF_DDP,
	TOE_CONF_DDP_THRES,
	TOE_CONF_DDP_XLTHRES,
	TOE_CONF_DDP_MAXPAGES,
	TOE_CONF_DDP_MAXFAIL,
	TOE_CONF_DDP_PSH_WAIT,
	TOE_CONF_DDP_RCVCOALESCE,
#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
	TOE_CONF_ZCOPY_SENDMSG_PARTIAL_THRES,
	TOE_CONF_ZCOPY_SENDMSG_PARTIAL_XLTHRES,
	TOE_CONF_ZCOPY_SENDMSG_PARTIAL_COPY,
	TOE_CONF_ZCOPY_SENDMSG_THRES,
	TOE_CONF_ZCOPY_SENDMSG_COPY,
	TOE_CONF_ZCOPY_SENDMSG_RET_PENDING_DMA,
#endif
	TOE_CONF_ACTIVATED,
	TOE_CONF_COP_MANAGED_OFFLOADING,
#if defined(CONFIG_CHELSIO_IO_SPIN)
	TOE_CONF_RECVMSG_SPIN_US,
#endif
	TOE_CONF_RECVMSG_DDP_WAIT_US,
	TOE_CONF_LRO,

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
	TOE_CONF_OFFLOAD_VLAN,

	TOE_CONF_LAST           /* must be last */
};

static struct tom_tunables default_tunable_vals = {
	.max_host_sndbuf = 48 * 1024, /* for 16KB Tx pages */
	.tx_hold_thres = 0,
	.max_wr_credits = 64,
	.rx_credit_thres = 15 * 1024,
	.mss = 16384,
	.delack = 1,
	.max_conn = -1,
	.soft_backlog_limit = 1,
	.kseg_ddp = 0,
	.ddp = 1,
	.ddp_thres = 40960,
	.ddp_xlthres = DDP_RSVD_WIN<<2,
#if PAGE_SHIFT >= 14
	.ddp_maxpages = (M_TCB_RX_DDP_BUF0_LEN + 1ULL)>>PAGE_SHIFT, 
#else
	.ddp_maxpages = 1024, /* supports 4m buffer using 4k pages */
#endif
	.ddp_maxfail = 3,
	.ddp_push_wait = 1,
	.ddp_rcvcoalesce = 0,
#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
#if defined(CONFIG_PPC64)
	.zcopy_sendmsg_partial_thres = 131072,
	.zcopy_sendmsg_partial_xlthres = 180224,
#else
	.zcopy_sendmsg_partial_thres = 40960,
	.zcopy_sendmsg_partial_xlthres = 180224,
#endif
	.zcopy_sendmsg_partial_copy = 4096 * 3,
	.zcopy_sendmsg_ret_pending_dma = 1,
#endif
	.activated = 1,
	.cop_managed_offloading = 1,
#if defined(CONFIG_CHELSIO_IO_SPIN)
	.recvmsg_spin_us = 0,
#endif
	.recvmsg_ddp_wait_us = 0,
	.lro = 1,

	/*
	 * This code demonstrates how one would selectively Offload (TOE)
	 * certain incoming connections by using the extended "Filter
	 * Information" capabilities of Server Control Blocks (SCB).  (See
	 * "Classification and Filtering" in the T4 Data Book for a
	 * description of Ingress Packet pattern matching capabilities.  See
	 * also documentation on the TP_VLAN_PRI_MAP register.)  Because this
	 * selective Offloading is happening in the chip, this allows
	 * non-Offloading and Offloading drivers to coexist.  For example, an
	 * Offloading Driver might be running in a Hypervisor while
	 * non-Offloading vNIC Drivers might be running in Virtual Machines.
	 *
	 * This particular example code demonstrates how one would selectively
	 * Offload incoming connections based on VLANs.  We allow one VLAN to
	 * be designated as the "Offloading VLAN".  Ingress SYNs on this
	 * Offload VLAN will match the filter which we put into the Listen SCB
	 * and will result in Offloaded Connections on that VLAN.  Incoming
	 * SYNs on other VLANs will not match and will go through normal NIC
	 * processing.
	 *
	 * This is not production code since one would want a lot more
	 * infrastructure to allow a variety of filter specifications on a
	 * per-server basis.  But this demonstrates the fundamental mechanisms
	 * one would use to build such an infrastructure.
	 */
	.offload_vlan = 0,
};

static int min_wr_credits = 5;  /* Min # of WR 16-byte blocks for a connection */
static int min_mss = 1;		/* Min length of TX_DATA payload */
static int min_rx_credits = 1;	/* Min RX credit threshold */
static int min_delack = 0;      /* Min value for delayed ACK mode */
static int max_delack = 3;      /* Max value for delayed ACK mode */
static int min_ddp_thres = 0;   /* Min read size to enter DDP */
static int min_ddp_pages = 4;   /* Min pages set to one page pod */
static int max_ddp_pages = (M_TCB_RX_DDP_BUF0_LEN + 1ULL)>>PAGE_SHIFT;

/* Number of fields in tom_tunables */
#define NUM_TUNABLES (TOE_CONF_LAST - 1)

#if defined(SYSCTL_CTL_NAME)
#define TUNABLE_INT(name, proc_name, field_name) \
	{ .ctl_name = TUNABLE_INT_CTL_NAME(name),\
	  .procname = proc_name,\
	  .data = &default_tunable_vals.field_name,\
	  .maxlen = sizeof(default_tunable_vals.field_name),\
	  .mode = 0644,\
	  .proc_handler = &proc_dointvec }

#define TUNABLE_INT_RANGE(name, proc_name, field_name, minp, maxp) \
	{ .ctl_name = TUNABLE_INT_RANGE_CTL_NAME(name),\
	  .procname = proc_name,\
	  .data = &default_tunable_vals.field_name,\
	  .maxlen = sizeof(default_tunable_vals.field_name),\
	  .mode = 0644,\
	  .proc_handler = &proc_dointvec_minmax,\
          .strategy = &sysctl_intvec,\
	  .extra1 = minp,\
	  .extra2 = maxp }
#else
#define TUNABLE_INT(name, proc_name, field_name) \
        {  .procname = proc_name,\
          .data = &default_tunable_vals.field_name,\
          .maxlen = sizeof(default_tunable_vals.field_name),\
          .mode = 0644,\
          .proc_handler = &proc_dointvec }

#define TUNABLE_INT_RANGE(name, proc_name, field_name, minp, maxp) \
        {  .procname = proc_name,\
          .data = &default_tunable_vals.field_name,\
          .maxlen = sizeof(default_tunable_vals.field_name),\
          .mode = 0644,\
          .proc_handler = &proc_dointvec_minmax,\
          .extra1 = minp,\
          .extra2 = maxp }
#endif

/*
 * Sysctl table template.  This is cloned for each TOM instance.
 */
struct tom_sysctl_table {
	struct ctl_table_header *sysctl_header;

	char tom_instance_dir_name[TOENAMSIZ + 4];
	struct ctl_table tunables[NUM_TUNABLES + 1];
	struct ctl_table tom_instance_dir[2];
	struct ctl_table root_dir[2];
};

static struct tom_sysctl_table tom_sysctl = {
	.tunables = {
		TUNABLE_INT(MAX_HOST_SNDBUF, "max_host_sndbuf",
			    max_host_sndbuf),
		TUNABLE_INT(TX_HOLD_THRES, "tx_hold_thres", tx_hold_thres),
		TUNABLE_INT_RANGE(MAX_WR_CREDITS, "max_wr_credits", max_wr_credits, &min_wr_credits, NULL),
		TUNABLE_INT_RANGE(RX_CREDIT_THRES, "rx_credit_thres",
				  rx_credit_thres, &min_rx_credits, NULL),
		TUNABLE_INT_RANGE(MSS, "mss", mss, &min_mss, NULL),
		TUNABLE_INT_RANGE(DELACK, "delayed_ack", delack, &min_delack,
				  &max_delack),
		TUNABLE_INT(MAX_CONN, "max_conn", max_conn),
		TUNABLE_INT(SOFT_BACKLOG_LIMIT, "soft_backlog_limit",
			    soft_backlog_limit),
		TUNABLE_INT(KSEG_DDP, "kseg_ddp", kseg_ddp),
		TUNABLE_INT(DDP, "ddp", ddp),
		TUNABLE_INT_RANGE(DDP_THRES, "ddp_thres", ddp_thres,
				  &min_ddp_thres, NULL),
		TUNABLE_INT_RANGE(DDP_XLTHRES, "ddp_xlthres", ddp_xlthres,
				&min_ddp_thres, NULL),
		TUNABLE_INT_RANGE(DDP_MAXPAGES, "ddp_maxpages", ddp_maxpages,
				&min_ddp_pages, &max_ddp_pages),
		TUNABLE_INT(DDP_MAXFAIL, "ddp_maxfail", ddp_maxfail),
		TUNABLE_INT(DDP_PSH_WAIT, "ddp_push_wait", ddp_push_wait),
		TUNABLE_INT(DDP_RCVCOALESCE, "ddp_rcvcoalesce",
			    ddp_rcvcoalesce),
#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
		TUNABLE_INT(ZCOPY_SENDMSG_PARTIAL_THRES,
			    "zcopy_sendmsg_partial_thres",
			    zcopy_sendmsg_partial_thres),
		TUNABLE_INT(ZCOPY_SENDMSG_PARTIAL_XLTHRES,
				"zcopy_sendmsg_partial_xlthres",
				zcopy_sendmsg_partial_xlthres),
		TUNABLE_INT(ZCOPY_SENDMSG_PARTIAL_COPY,
			    "zcopy_sendmsg_partial_copy",
			    zcopy_sendmsg_partial_copy),
		TUNABLE_INT(ZCOPY_SENDMSG_RET_PENDING_DMA,
			    "zcopy_sendmsg_ret_pending_dma",
			    zcopy_sendmsg_ret_pending_dma),
#endif
		TUNABLE_INT(ACTIVATED, "activated",
			    activated),
		TUNABLE_INT(COP_MANAGED_OFFLOADING, "cop_managed_offloading",
			    cop_managed_offloading),
#if defined(CONFIG_CHELSIO_IO_SPIN)
		TUNABLE_INT(RECVMSG_SPIN_US, "recvmsg_spin_us",
			    recvmsg_spin_us),
#endif
		TUNABLE_INT(RECVMSG_DDP_WAIT_US, "recvmsg_ddp_wait_us",
                            recvmsg_ddp_wait_us),
		TUNABLE_INT(LRO, "lro", lro),

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
		TUNABLE_INT(OFFLOAD_VLAN, "offload_vlan",
                            offload_vlan),
	},
	.tom_instance_dir = {
		{
#if defined(SYSCTL_CTL_NAME)
			.ctl_name = TOM_INSTANCE_DIR_CTL_NAME,
#endif
			.procname = tom_sysctl.tom_instance_dir_name,
			.mode = 0555,
			.child = tom_sysctl.tunables,
		},
	},
	.root_dir = {
		{
#if defined(SYSCTL_CTL_NAME)
			.ctl_name = ROOT_DIR_CTL_NAME,
#endif
			.procname = "toe",
			.mode = 0555,
			.child = tom_sysctl.tom_instance_dir,
		},
	}
};

/*
 * Register the sysctl table for a TOM instance associated with the supplied
 * TOE device.
 */
struct tom_sysctl_table *t4_sysctl_register(struct toedev *dev,
					    const struct tom_tunables *p)
{
	int i;
	struct tom_data *td = TOM_DATA(dev);
	struct tom_sysctl_table *t = kmalloc(sizeof(*t), GFP_KERNEL);

	if (!t)
		return NULL;

	memcpy(t, &tom_sysctl, sizeof(*t));
	snprintf(t->tom_instance_dir_name, sizeof(t->tom_instance_dir_name),
		 "%s_tom", dev->name);
	for (i = 0; i < NUM_TUNABLES; ++i) {
		t->tunables[i].data +=
			(char *)p - (char *)&default_tunable_vals;
		tom_sysctl_set_de(&t->tunables[i]);
	}

	t->tunables[TOE_CONF_MSS - 1].extra2 = &td->tx_max_chunk;
	t->tunables[TOE_CONF_MAX_WR_CREDITS - 1].extra2 = &td->max_wr_credits;

	t->tom_instance_dir[0].procname = t->tom_instance_dir_name;
	t->tom_instance_dir[0].child = t->tunables;
	tom_sysctl_set_de(&t->tom_instance_dir[0]);
	t->root_dir[0].child = t->tom_instance_dir;
	tom_sysctl_set_de(&t->root_dir[0]);

	t->sysctl_header = tom_register_sysctl_table(t->root_dir, 0);
	if (!t->sysctl_header) {
		kfree(t);
		t = NULL;
	}
	return t;
}

void t4_sysctl_unregister(struct tom_sysctl_table *t)
{
	if (t) {
		unregister_sysctl_table(t->sysctl_header);
		kfree(t);
	}
}

void t4_init_tunables(struct tom_data *t)
{
	t->conf = default_tunable_vals;

	if (t->max_wr_credits < t->conf.max_wr_credits)
		t->conf.max_wr_credits = t->max_wr_credits;
	t->conf.mss = t->tx_max_chunk;

#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
	if (vmdirectio)
		t->conf.zcopy_sendmsg_partial_thres = t->conf.zcopy_sendmsg_partial_xlthres;
#endif
}
