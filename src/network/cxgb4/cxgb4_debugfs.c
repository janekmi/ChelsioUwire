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

#include <linux/seq_file.h>
#include <linux/debugfs.h>

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
#include "cxgb4_dcb.h"
#include "smt.h"
#include "srq.h"
#include "l2t.h"
#include "clip_tbl.h"
#include "cxgb4_debugfs.h"

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
#include "cxgb4_ofld.h"
#include "ocqp.h"
#endif /* CONFIG_CHELSIO_T4_OFFLOAD */

/*
 * Objects declared in other files.
 */
extern int attempt_err_recovery;
extern struct mutex uld_mutex;
extern const char *uld_str[];

/*
 * debugfs support
 */

DEFINE_SIMPLE_DEBUGFS_FILE(clip_tbl);

/*
 * Read a vector of numbers from a user space buffer.  Each number must be
 * between min and max inclusive and in the given base.
 */
static int rd_usr_int_vec(const char __user *buf, size_t usr_len, int vec_len,
			  unsigned long *vals, unsigned long min,
			  unsigned long max, int base)
{
	size_t l;
	unsigned long v;
	char c, word[68], *end;

	while (usr_len) {
		/* skip whitespace to beginning of next word */
		while (usr_len) {
			if (get_user(c, buf))
				return -EFAULT;
			if (!isspace(c))
				break;
			usr_len--;
			buf++;
		}

		if (!usr_len)
			break;
		if (!vec_len)
			return -EINVAL;              /* too many numbers */

		/* get next word (possibly going beyond its end) */
		l = min(usr_len, sizeof(word) - 1);
		if (copy_from_user(word, buf, l))
			return -EFAULT;
		word[l] = '\0';

		v = simple_strtoul(word, &end, base);
		l = end - word;
		if (!l)
			return -EINVAL;              /* catch embedded '\0's */
		if (*end && !isspace(*end))
			return -EINVAL;
		/*
		 * Complain if we encountered a too long sequence of digits.
		 * The most we can consume in one iteration is for a 64-bit
		 * number in binary.  Too bad simple_strtoul doesn't catch
		 * overflows.
		 */
		if (l > 64)
			return -EINVAL;
		if (v < min || v > max)
			return -ERANGE;
		*vals++ = v;
		vec_len--;
		usr_len -= l;
		buf += l;
	}
	if (vec_len)
		return -EINVAL;                      /* not enough numbers */
	return 0;
}

#ifdef CONFIG_CXGB4_DCB
extern char *dcb_ver_array[];

/*
 * Data Center Briging information for each port.
 */
static int dcb_info_show(struct seq_file *seq, void *v)
{
	struct adapter *adap = seq->private;

	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "Data Center Bridging Information\n");
	else {
		int port = (uintptr_t)v - 2;
		struct net_device *dev = adap->port[port];
		struct port_info *pi = netdev2pinfo(dev);
		struct port_dcb_info *dcb = &pi->dcb;

		seq_puts(seq, "\n");
		seq_printf(seq, "Port: %d (DCB negotiated: %s)\n",
			   port,
			   cxgb4_dcb_enabled(dev) ? "yes" : "no");

		if (cxgb4_dcb_enabled(dev))
			seq_printf(seq, "[ DCBx Version %s ]\n",
				   dcb_ver_array[dcb->dcb_version]);

		if (dcb->msgs) {
			int i;

			seq_puts(seq, "\n  Index\t\t\t  :\t");
			for (i = 0; i < 8; i++)
				seq_printf(seq, " %3d", i);
			seq_puts(seq, "\n\n");
		}

		if (dcb->msgs & CXGB4_DCB_FW_PGID) {
			int prio, pgid;

			seq_puts(seq, "  Priority Group IDs\t  :\t");
			for (prio = 0; prio < 8; prio++) {
				pgid = (dcb->pgid >> 4*(7 - prio)) & 0xf;
				seq_printf(seq, " %3d", pgid);
			}
			seq_puts(seq, "\n");
		}

		if (dcb->msgs & CXGB4_DCB_FW_PGRATE) {
			int pg;

			seq_puts(seq, "  Priority Group BW(%)\t  :\t");
			for (pg = 0; pg < 8; pg++)
				seq_printf(seq, " %3d", dcb->pgrate[pg]);
			seq_puts(seq, "\n");

			if (dcb->dcb_version == FW_PORT_DCB_VER_IEEE) {
				seq_puts(seq, "  TSA Algorithm\t\t  :\t");
				for (pg = 0; pg < 8; pg++)
					seq_printf(seq, " %3d", dcb->tsa[pg]);
				seq_puts(seq, "\n");
			}

			seq_printf(seq, "  Max PG Traffic Classes  [%3d  ]\n",
				   dcb->pg_num_tcs_supported);

			seq_puts(seq, "\n");
		}

		if (dcb->msgs & CXGB4_DCB_FW_PRIORATE) {
			int prio;

			seq_puts(seq, "  Priority Rate\t:\t");
			for (prio = 0; prio < 8; prio++)
				seq_printf(seq, " %3d", dcb->priorate[prio]);
			seq_puts(seq, "\n");
		}

		if (dcb->msgs & CXGB4_DCB_FW_PFC) {
			int prio;

			seq_puts(seq, "  Priority Flow Control   :\t");
			for (prio = 0; prio < 8; prio++) {
				int pfcen = (dcb->pfcen >> 1*(7 - prio)) & 0x1;
				seq_printf(seq, " %3d", pfcen);
			}
			seq_puts(seq, "\n");

			seq_printf(seq, "  Max PFC Traffic Classes [%3d  ]\n",
				   dcb->pfc_num_tcs_supported);

			seq_puts(seq, "\n");
		}

		if (dcb->msgs & CXGB4_DCB_FW_APP_ID) {
			int app, napps;

			seq_puts(seq, "  Application Information:\n");
			seq_puts(seq, "  App    Priority    Selection         Protocol\n");
			seq_puts(seq, "  Index  Map         Field             ID\n");
			for (app = 0, napps = 0; app < CXGB4_MAX_DCBX_APP_SUPPORTED; app++) {
				struct app_priority *ap = &dcb->app_priority[app];
				const char *sel_names[] = {
					"Ethertype",
					"Socket TCP",
					"Socket UDP",
					"Socket All",
				};
				const char *sel_name;

				/* skip empty slots */
				if (ap->protocolid == 0)
					continue;
				napps++;

				if (ap->sel_field < ARRAY_SIZE(sel_names))
					sel_name = sel_names[ap->sel_field];
				else
					sel_name = "UNKNOWN";

				seq_printf(seq, "  %3d    %#04x        %-10s (%d)"
					   "    %#06x (%d)\n",
					   app,
					   ap->user_prio_map,
					   sel_name, ap->sel_field,
					   ap->protocolid, ap->protocolid);
			}
			if (napps == 0)
				seq_puts(seq, "    --- None ---\n");
		}
	}
	return 0;
}

static inline void *dcb_info_get_idx(struct adapter *adap, loff_t pos)
{
	return (pos <= adap->params.nports
		? (void *)((uintptr_t)pos + 1)
		: NULL);
}

static void *dcb_info_start(struct seq_file *seq, loff_t *pos)
{
	struct adapter *adap = seq->private;

	return (*pos
		? dcb_info_get_idx(adap, *pos)
		: SEQ_START_TOKEN);
}

static void dcb_info_stop(struct seq_file *seq, void *v)
{
}

static void *dcb_info_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct adapter *adap = seq->private;

	(*pos)++;
	return dcb_info_get_idx(adap, *pos);
}

static const struct seq_operations dcb_info_seq_ops = {
	.start = dcb_info_start,
	.next  = dcb_info_next,
	.stop  = dcb_info_stop,
	.show  = dcb_info_show
};

static int dcb_info_open(struct inode *inode, struct file *file)
{
	int res = seq_open(file, &dcb_info_seq_ops);

	if (!res) {
		struct seq_file *seq = file->private_data;
		seq->private = inode->i_private;
	}
	return res;
}

static const struct file_operations dcb_info_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = dcb_info_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};
#endif /* CONFIG_CXGB4_DCB */

/**
 * ethqset2pinfo - return port_info of an Ethernet Queue Set
 * @adap: the adapter
 * @qset: Ethernet Queue Set
 */
static inline struct port_info *ethqset2pinfo(struct adapter *adap, int qset)
{
	int pidx;

	for_each_port(adap, pidx) {
		struct port_info *pi = adap2pinfo(adap, pidx);

		if (qset >= pi->first_qset &&
		    qset < pi->first_qset + pi->nqsets)
			return pi;
	}

	/* should never happen! */
	BUG_ON(1);
	return NULL;
}

static int sge_qinfo_show(struct seq_file *seq, void *v)
{
	struct adapter *adap = seq->private;
	int eth_entries = DIV_ROUND_UP(adap->sge.ethqsets, 4);
	int toe_entries = DIV_ROUND_UP(adap->sge.ofldqsets, 4);
	int rdma_entries = DIV_ROUND_UP(adap->sge.rdmaqs, 4);
	int ciq_entries = DIV_ROUND_UP(adap->sge.rdmaciqs, 4);
	int iscsi_entries = DIV_ROUND_UP(adap->sge.niscsiq, 4);
	int ctrl_entries = DIV_ROUND_UP(MAX_CTRL_QUEUES, 4);
	int trace_entries = DIV_ROUND_UP(adap->sge.ntraceq, 4);
	int flover_entries = DIV_ROUND_UP(adap->sge.nfailoverq, 4);
	int vxlan_entries = DIV_ROUND_UP(adap->sge.nvxlanq, 4);
	int i, r = (uintptr_t)v - 1;

	if (r)
		seq_putc(seq, '\n');

#define S3(fmt_spec, s, v) \
	seq_printf(seq, "%-12s", s); \
	for (i = 0; i < n; ++i) \
		seq_printf(seq, " %16" fmt_spec, v); \
		seq_putc(seq, '\n');
#define S(s, v) S3("s", s, v)
#define T(s, v) S3("u", s, tx[i].v)
#define R(s, v) S3("u", s, rx[i].v)

	if (r < eth_entries) {
		int base_qset = r * 4;
		const struct sge_eth_rxq *rx = &adap->sge.ethrxq[base_qset];
		const struct sge_eth_txq *tx = &adap->sge.ethtxq[base_qset];
		int n = min(4, adap->sge.ethqsets - 4 * r);

		S("QType:", "Ethernet");
		S("Interface:",
		  rx[i].rspq.netdev ? rx[i].rspq.netdev->name : "N/A");
		T("TxQ ID:", q.cntxt_id);
		T("TxQ size:", q.size);
		T("TxQ inuse:", q.in_use);
		T("TxQ CIDX:", q.cidx);
		T("TxQ PIDX:", q.pidx);
#ifdef CONFIG_CXGB4_DCB
		T("DCB Prio:", dcb_prio);
		S3("u", "DCB PGID:",
		   (ethqset2pinfo(adap, base_qset + i)->dcb.pgid >>
		    4*(7-tx[i].dcb_prio)) & 0xf);
		S3("u", "DCB PFC:",
		   (ethqset2pinfo(adap, base_qset + i)->dcb.pfcen >>
		    1*(7-tx[i].dcb_prio)) & 0x1);
#endif
		R("RspQ ID:", rspq.abs_id);
		R("RspQ size:", rspq.size);
		R("RspQE size:", rspq.iqe_len);
		R("RspQ CIDX:", rspq.cidx);
		R("RspQ Gen:", rspq.gen);
		S3("u", "Intr delay:", qtimer_val(adap, &rx[i].rspq));
		S3("u", "Intr pktcnt:",
		   adap->sge.counter_val[rx[i].rspq.pktcnt_idx]);
		R("FL ID:", fl.cntxt_id);
		R("FL size:", fl.size - 8);
		R("FL pend:", fl.pend_cred);
		R("FL avail:", fl.avail);
		R("FL PIDX:", fl.pidx);
		R("FL CIDX:", fl.cidx);
	} else {
		if (!is_hashfilter(adap)) {
			if ((r -= eth_entries) < toe_entries) {
				const struct sge_ofld_rxq *rx = &adap->sge.ofldrxq[r * 4];
				const struct sge_ofld_txq *tx = &adap->sge.ofldtxq[r * 4];
				int n = min(4, adap->sge.ofldqsets - 4 * r);

				S("QType:", "TOE");
				T("TxQ ID:", q.cntxt_id);
				T("TxQ size:", q.size);
				T("TxQ inuse:", q.in_use);
				T("TxQ CIDX:", q.cidx);
				T("TxQ PIDX:", q.pidx);
				R("RspQ ID:", rspq.abs_id);
				R("RspQ size:", rspq.size);
				R("RspQE size:", rspq.iqe_len);
				R("RspQ CIDX:", rspq.cidx);
				R("RspQ Gen:", rspq.gen);
				S3("u", "Intr delay:", qtimer_val(adap, &rx[i].rspq));
				S3("u", "Intr pktcnt:",
				   adap->sge.counter_val[rx[i].rspq.pktcnt_idx]);
				R("FL ID:", fl.cntxt_id);
				R("FL size:", fl.size - 8);
				R("FL pend:", fl.pend_cred);
				R("FL avail:", fl.avail);
				R("FL PIDX:", fl.pidx);
				R("FL CIDX:", fl.cidx);
			} else if ((r -= toe_entries) < rdma_entries) {
				const struct sge_ofld_rxq *rx = &adap->sge.rdmarxq[r * 4];
				int n = min(4, adap->sge.rdmaqs - 4 * r);

				S("QType:", "RDMA-CPL");
				S("Interface:",
				  rx[i].rspq.netdev ? rx[i].rspq.netdev->name : "N/A");
				R("RspQ ID:", rspq.abs_id);
				R("RspQ size:", rspq.size);
				R("RspQE size:", rspq.iqe_len);
				R("RspQ CIDX:", rspq.cidx);
				R("RspQ Gen:", rspq.gen);
				S3("u", "Intr delay:", qtimer_val(adap, &rx[i].rspq));
				S3("u", "Intr pktcnt:",
				   adap->sge.counter_val[rx[i].rspq.pktcnt_idx]);
				R("FL ID:", fl.cntxt_id);
				R("FL size:", fl.size - 8);
				R("FL pend:", fl.pend_cred);
				R("FL avail:", fl.avail);
				R("FL PIDX:", fl.pidx);
				R("FL CIDX:", fl.cidx);
			} else if ((r -= rdma_entries) < ciq_entries) {
				const struct sge_ofld_rxq *rx = &adap->sge.rdmaciq[r * 4];
				int n = min(4, adap->sge.rdmaciqs - 4 * r);

				S("QType:", "RDMA-CIQ");
				S("Interface:",
				  rx[i].rspq.netdev ? rx[i].rspq.netdev->name : "N/A");
				R("RspQ ID:", rspq.abs_id);
				R("RspQ size:", rspq.size);
				R("RspQE size:", rspq.iqe_len);
				R("RspQ CIDX:", rspq.cidx);
				R("RspQ Gen:", rspq.gen);
				S3("u", "Intr delay:", qtimer_val(adap, &rx[i].rspq));
				S3("u", "Intr pktcnt:",
				   adap->sge.counter_val[rx[i].rspq.pktcnt_idx]);
			} else if ((r -= ciq_entries) < iscsi_entries) {
				const struct sge_ofld_rxq *rx = &adap->sge.iscsirxq[r * 4];
				int n = min(4, adap->sge.niscsiq - 4 * r);

				S("QType:", "iSCSI");
				R("RspQ ID:", rspq.abs_id);
				R("RspQ size:", rspq.size);
				R("RspQE size:", rspq.iqe_len);
				R("RspQ CIDX:", rspq.cidx);
				R("RspQ Gen:", rspq.gen);
				S3("u", "Intr delay:", qtimer_val(adap, &rx[i].rspq));
				S3("u", "Intr pktcnt:",
				   adap->sge.counter_val[rx[i].rspq.pktcnt_idx]);
				R("FL ID:", fl.cntxt_id);
				R("FL size:", fl.size - 8);
				R("FL pend:", fl.pend_cred);
				R("FL avail:", fl.avail);
				R("FL PIDX:", fl.pidx);
				R("FL CIDX:", fl.cidx);
			} else if ((r -= iscsi_entries) < flover_entries) {
#ifdef CONFIG_T4_MA_FAILOVER
				const struct sge_ofld_rxq *rx = &adap->sge.failoverq;
				int n = min(4, adap->sge.nfailoverq - 4 * r);

				S("QType:", "MA Failover");
				R("RspQ ID:", rspq.abs_id);
				R("RspQ size:", rspq.size);
				R("RspQE size:", rspq.iqe_len);
				R("RspQ CIDX:", rspq.cidx);
				R("RspQ Gen:", rspq.gen);
				S3("u", "Intr delay:", qtimer_val(adap, &rx[i].rspq));
				S3("u", "Intr pktcnt:",
						adap->sge.counter_val[rx[i].rspq.pktcnt_idx]);
				R("FL ID:", fl.cntxt_id);
				R("FL size:", fl.size - 8);
				R("FL pend:", fl.pend_cred);
				R("FL avail:", fl.avail);
				R("FL PIDX:", fl.pidx);
				R("FL CIDX:", fl.cidx);
#endif /* CONFIG_T4_MA_FAILOVER */
			} else if ((r -= flover_entries) < vxlan_entries) {
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
				int base_qset = r * 4;
				const struct sge_eth_txq *tx;
				const struct sge_eth_rxq *rx;
				int n = min(4, adap->sge.ethqsets - 4 * r);

				tx = &adap->sge.vxlantxq[base_qset];
				rx = &adap->sge.ethrxq[base_qset];
				S("QType:", "VxLAN");
				S("Interface:",
				  rx[i].rspq.netdev ?
				  rx[i].rspq.netdev->name : "N/A");
				T("TxQ ID:", q.cntxt_id);
				T("TxQ size:", q.size);
				T("TxQ inuse:", q.in_use);
				T("TxQ CIDX:", q.cidx);
				T("TxQ PIDX:", q.pidx);
#endif
			} else if ((r -= vxlan_entries) < ctrl_entries) {

				const struct sge_ctrl_txq *tx = &adap->sge.ctrlq[r * 4];
				int n = min(4, adap->params.nports - 4 * r);

				S("QType:", "Control");
				T("TxQ ID:", q.cntxt_id);
				T("TxQ size:", q.size);
				T("TxQ inuse:", q.in_use);
				T("TxQ CIDX:", q.cidx);
				T("TxQ PIDX:", q.pidx);
			} else if ((r -= ctrl_entries) == 0) {
				const struct sge_rspq *evtq = &adap->sge.fw_evtq;

				seq_printf(seq, "%-12s %16s\n", "QType:", "FW event queue");
				seq_printf(seq, "%-12s %16u\n", "RspQ ID:", evtq->abs_id);
				seq_printf(seq, "%-12s %16u\n", "RspQ size:", evtq->size);
				seq_printf(seq, "%-12s %16u\n", "RspQE size:", evtq->iqe_len);
				seq_printf(seq, "%-12s %16u\n", "RspQ CIDX:", evtq->cidx);
				seq_printf(seq, "%-12s %16u\n", "RspQ Gen:", evtq->gen);
				seq_printf(seq, "%-12s %16u\n", "Intr delay:",
					   qtimer_val(adap, evtq));
				seq_printf(seq, "%-12s %16u\n", "Intr pktcnt:",
					   adap->sge.counter_val[evtq->pktcnt_idx]);
			}
		} else {
			if ((r -= eth_entries) < trace_entries) {
				const struct sge_eth_rxq *rx = &adap->sge.traceq[r * 4];
				int n = min(4, adap->sge.ntraceq - 4 * r);

				S("QType:", "Trace");
				S("Interface:",
				  rx[i].rspq.netdev ? rx[i].rspq.netdev->name : "N/A");
				R("RspQ ID:", rspq.abs_id);
				R("RspQ size:", rspq.size);
				R("RspQE size:", rspq.iqe_len);
				R("RspQ CIDX:", rspq.cidx);
				R("RspQ Gen:", rspq.gen);
				S3("u", "Intr delay:", qtimer_val(adap, &rx[i].rspq));
				S3("u", "Intr pktcnt:",
				   adap->sge.counter_val[rx[i].rspq.pktcnt_idx]);
				R("FL ID:", fl.cntxt_id);
				R("FL size:", fl.size - 8);
				R("FL pend:", fl.pend_cred);
				R("FL avail:", fl.avail);
				R("FL PIDX:", fl.pidx);
				R("FL CIDX:", fl.cidx);
			} else if ((r -= trace_entries) < vxlan_entries) {
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
				int base_qset = r * 4;
				const struct sge_eth_txq *tx;
				const struct sge_eth_rxq *rx;
				int n = min(4, adap->sge.ethqsets - 4 * r);

				tx = &adap->sge.vxlantxq[base_qset];
				rx = &adap->sge.ethrxq[base_qset];
				S("QType:", "VxLAN");
				S("Interface:",
				  rx[i].rspq.netdev ?
				  rx[i].rspq.netdev->name : "N/A");
				T("TxQ ID:", q.cntxt_id);
				T("TxQ size:", q.size);
				T("TxQ inuse:", q.in_use);
				T("TxQ CIDX:", q.cidx);
				T("TxQ PIDX:", q.pidx);
#endif
			} else if ((r -= vxlan_entries) < ctrl_entries) {
				const struct sge_ctrl_txq *tx = &adap->sge.ctrlq[r * 4];
				int n = min(4, adap->params.nports - 4 * r);

				S("QType:", "Control");
				T("TxQ ID:", q.cntxt_id);
				T("TxQ size:", q.size);
				T("TxQ inuse:", q.in_use);
				T("TxQ CIDX:", q.cidx);
				T("TxQ PIDX:", q.pidx);
			} else if ((r -= ctrl_entries) == 0) {
				const struct sge_rspq *evtq = &adap->sge.fw_evtq;

				seq_printf(seq, "%-12s %16s\n", "QType:", "FW event queue");
				seq_printf(seq, "%-12s %16u\n", "RspQ ID:", evtq->abs_id);
				seq_printf(seq, "%-12s %16u\n", "RspQ size:", evtq->size);
				seq_printf(seq, "%-12s %16u\n", "RspQE size:", evtq->iqe_len);
				seq_printf(seq, "%-12s %16u\n", "RspQ CIDX:", evtq->cidx);
				seq_printf(seq, "%-12s %16u\n", "RspQ Gen:", evtq->gen);
				seq_printf(seq, "%-12s %16u\n", "Intr delay:",
					   qtimer_val(adap, evtq));
				seq_printf(seq, "%-12s %16u\n", "Intr pktcnt:",
					   adap->sge.counter_val[evtq->pktcnt_idx]);
			}
		}
	}
#undef R
#undef T
#undef S
#undef S3
	return 0;
}

int sge_queue_entries(const struct adapter *adap)
{
	return DIV_ROUND_UP(adap->sge.ethqsets, 4) +
	       DIV_ROUND_UP(adap->sge.ntraceq, 4) +
	       DIV_ROUND_UP(adap->sge.ofldqsets, 4) +
	       DIV_ROUND_UP(adap->sge.rdmaqs, 4) +
	       DIV_ROUND_UP(adap->sge.rdmaciqs, 4) +
	       DIV_ROUND_UP(adap->sge.niscsiq, 4) +
	       DIV_ROUND_UP(MAX_CTRL_QUEUES, 4) +
	       DIV_ROUND_UP(adap->sge.ethqsets, 4) +
	       DIV_ROUND_UP(adap->sge.nfailoverq, 4) + 1;

}

void *sge_queue_start(struct seq_file *seq, loff_t *pos)
{
	int entries = sge_queue_entries(seq->private);

	return *pos < entries ? (void *)((uintptr_t)*pos + 1) : NULL;
}

void sge_queue_stop(struct seq_file *seq, void *v)
{
}

void *sge_queue_next(struct seq_file *seq, void *v, loff_t *pos)
{
	int entries = sge_queue_entries(seq->private);

	++*pos;
	return *pos < entries ? (void *)((uintptr_t)*pos + 1) : NULL;
}

static const struct seq_operations sge_qinfo_seq_ops = {
	.start = sge_queue_start,
	.next  = sge_queue_next,
	.stop  = sge_queue_stop,
	.show  = sge_qinfo_show
};

static int sge_qinfo_open(struct inode *inode, struct file *file)
{
	int res = seq_open(file, &sge_qinfo_seq_ops);

	if (!res) {
		struct seq_file *seq = file->private_data;
		seq->private = inode->i_private;
	}
	return res;
}

static const struct file_operations sge_qinfo_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = sge_qinfo_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

static int intr_holdoff_show(struct seq_file *seq, void *v)
{

	struct adapter *adap = seq->private;
	struct sge *s = &adap->sge;
	int i;

	for (i=0; i < SGE_NTIMERS; i ++)
		seq_printf(seq, "%u ", s->timer_val[i]);
	seq_printf(seq, "\n");

	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(intr_holdoff);

static int intr_cnt_show(struct seq_file *seq, void *v)
{

	struct adapter *adap = seq->private;
	struct sge *s = &adap->sge;
	int i;

	for (i=0; i < SGE_NCOUNTERS; i ++)
		seq_printf(seq, "%u ", s->counter_val[i]);
	seq_printf(seq, "\n");

	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(intr_cnt);

static int uld_show(struct seq_file *seq, void *v)
{
	struct adapter *adap = seq->private;
	int i;

	for (i = 0; i < CXGB4_ULD_MAX; i++)
		if (adap->uld_handle[i])
			seq_printf(seq, "%s: %s\n", uld_str[i], cxgb4_ulds[i].name);
	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(uld);

/* Inject parity error, only for debug purpose */
static int inject_err_show(struct seq_file *seq, void *v)
{
	struct adapter *adap = seq->private;
	struct fw_ldst_cmd c;

	if (!attempt_err_recovery)
		return 0;

	memset(&c, 0, sizeof(c));
	c.op_to_addrspace = cpu_to_be32(V_FW_CMD_OP(FW_LDST_CMD) |
		F_FW_CMD_REQUEST | F_FW_CMD_READ |
		V_FW_LDST_CMD_ADDRSPACE(FW_LDST_ADDRSPC_FIRMWARE));
	c.cycles_to_len16 = cpu_to_be32(FW_LEN16(c));
	c.u.addrval.addr = cpu_to_be32(0xffffffff);
	c.u.addrval.val = cpu_to_be32(0xffffffff);

	t4_wr_mbox(adap, adap->mbox, &c, sizeof(c), NULL);
	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(inject_err);

static int blocked_fl_open(struct inode *inode, struct file *file)
{
	file->private_data = inode->i_private;
	return 0;
}

static ssize_t blocked_fl_read(struct file *filp, char __user *ubuf,
			       size_t count, loff_t *ppos)
{
	int len;
	const struct adapter *adap = filp->private_data;
	char *buf;
	ssize_t size = (adap->sge.egr_sz + 3) / 4 +
			adap->sge.egr_sz / 32 + 2; /* includes ,/\n/\0 */

	buf = kzalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
	len = bitmap_scnprintf(buf, size - 1,
			       adap->sge.blocked_fl, adap->sge.egr_sz);
#else
	len = snprintf(buf, size - 1, "%*pb\n",
		       adap->sge.egr_sz, adap->sge.blocked_fl);
#endif
	len += sprintf(buf + len, "\n");
	size = simple_read_from_buffer(ubuf, count, ppos, buf, len);
	t4_free_mem(buf);
	return size;
}

static ssize_t blocked_fl_write(struct file *filp, const char __user *ubuf,
				size_t count, loff_t *ppos)
{
	int err;
	unsigned long *t;
	struct adapter *adap = filp->private_data;

	t = kcalloc(BITS_TO_LONGS(adap->sge.egr_sz), sizeof(long), GFP_KERNEL);
	if (!t)
		return -ENOMEM;

	err = bitmap_parse_user(ubuf, count, t, adap->sge.egr_sz);
	if (err)
		return err;

	bitmap_copy(adap->sge.blocked_fl, t, adap->sge.egr_sz);
	t4_free_mem(t);
	return count;
}

static const struct file_operations blocked_fl_fops = {
	.owner   = THIS_MODULE,
	.open    = blocked_fl_open,
	.read    = blocked_fl_read,
	.write   = blocked_fl_write,
	.llseek  = generic_file_llseek,
};

static int tid_info_show(struct seq_file *seq, void *v)
{
	struct adapter *adap = seq->private;
	const struct tid_info *t = &adap->tids;
	unsigned int chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);

	if (t4_read_reg(adap, A_LE_DB_CONFIG) & F_HASHEN) {
		unsigned int sb;
		seq_printf(seq, "Connections in use: %u\n",
			   atomic_read(&t->conns_in_use));
		if (chip_ver <= CHELSIO_T5)
			sb = t4_read_reg(adap, A_LE_DB_SERVER_INDEX) / 4;
		else
			sb = t4_read_reg(adap, A_LE_DB_SRVR_START_INDEX);

		if (sb) {
			seq_printf(seq, "TID range: 0..%u/%u..%u", sb - 1,
				   adap->tids.hash_base,
				   t->ntids - 1);
			seq_printf(seq, ", in use: %u/%u\n",
				   atomic_read(&t->tids_in_use),
				   atomic_read(&t->hash_tids_in_use));
		} else if (adap->flags & FW_OFLD_CONN) {
			seq_printf(seq, "TID range: %u..%u/%u..%u", t->aftid_base,
				   t->aftid_end,
				   adap->tids.hash_base,
				   t->ntids - 1);
			seq_printf(seq, ", in use: %u/%u\n",
				   atomic_read(&t->tids_in_use),
				   atomic_read(&t->hash_tids_in_use));
		} else {
			seq_printf(seq, "TID range: %u..%u",
				   adap->tids.hash_base,
				   t->ntids - 1);
			seq_printf(seq, ", in use: %u\n",
				   atomic_read(&t->hash_tids_in_use));
		}
	} else if (t->ntids) {
		seq_printf(seq, "Connections in use: %u\n",
			   atomic_read(&t->conns_in_use));
		seq_printf(seq, "TID range: 0..%u", t->ntids - 1);
		seq_printf(seq, ", in use: %u\n",
			   atomic_read(&t->tids_in_use));
	}

	if (!is_hashfilter(adap) && t->nstids)
		seq_printf(seq, "STID range: %u..%u, in use-IPv4/IPv6: %u/%u\n",
			   (!t->stid_base &&
			   (chip_ver <= CHELSIO_T5)) ?
			   t->stid_base + 1 : t->stid_base,
			   t->stid_base + t->nstids - 1,
			   t->stids_in_use - t->v6_stids_in_use,
			   t->v6_stids_in_use);
	if (t->natids)
		seq_printf(seq, "ATID range: 0..%u, in use: %u\n",
			t->natids - 1, t->atids_in_use);
	seq_printf(seq, "FTID range: %u..%u\n", t->ftid_base,
		   t->ftid_base + t->nftids - 1);
	if (t->nsftids)
		seq_printf(seq, "SFTID range: %u..%u in use: %u\n",
			   t->sftid_base, t->sftid_base + t->nsftids - 2,
			   t->sftids_in_use);
	if (t->nhpftids && (chip_ver > CHELSIO_T5))
		seq_printf(seq, "HPFTID range: %u..%u\n", t->hpftid_base,
			   t->hpftid_base + t->nhpftids - 1);
	if (!is_hashfilter(adap) && t->nuotids)
		seq_printf(seq, "UOTID range: %u..%u, in use: %u\n", t->uotid_base,
			   t->uotid_base + t->nuotids - 1, t->uotids_in_use);
	if (t->ntids)
		seq_printf(seq, "HW TID usage: %u IP users, %u IPv6 users\n",
			   t4_read_reg(adap, A_LE_DB_ACT_CNT_IPV4),
			   t4_read_reg(adap, A_LE_DB_ACT_CNT_IPV6));
	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(tid_info);

static int mtutab_show(struct seq_file *seq, void *v)
{
	u16 mtus[NMTUS];
	struct adapter *adap = seq->private;

	spin_lock(&adap->stats_lock);
	t4_read_mtu_tbl(adap, mtus, NULL);
	spin_unlock(&adap->stats_lock);

	seq_printf(seq, "%u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u\n",
		   mtus[0], mtus[1], mtus[2], mtus[3], mtus[4], mtus[5],
		   mtus[6], mtus[7], mtus[8], mtus[9], mtus[10], mtus[11],
		   mtus[12], mtus[13], mtus[14], mtus[15]);
	return 0;
}

static int mtutab_open(struct inode *inode, struct file *file)
{
	return single_open(file, mtutab_show, inode->i_private);
}

static ssize_t mtutab_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *pos)
{
	int i;
	unsigned long mtus[NMTUS];
	struct inode const * const ino = FILE_DATA(file);
	struct adapter * const adap = ino->i_private;

	/* Require min MTU of 81 to accommodate SACK */
	i = rd_usr_int_vec(buf, count, NMTUS, mtus, 81, MAX_MTU, 10);
	if (i)
		return i;

	/* MTUs must be in ascending order */
	for (i = 1; i < NMTUS; ++i)
		if (mtus[i] < mtus[i - 1])
			return -EINVAL;

	/* can't change the MTU table if offload is in use */
	mutex_lock(&uld_mutex);
	for (i = 0; i < CXGB4_ULD_MAX; i++)
		if (adap->uld_handle[i]) {
			mutex_unlock(&uld_mutex);
			return -EBUSY;
		}

	for (i = 0; i < NMTUS; ++i)
		adap->params.mtus[i] = mtus[i];
	t4_load_mtus(adap, adap->params.mtus, adap->params.a_wnd,
		     adap->params.b_wnd);
	mutex_unlock(&uld_mutex);
	return count;
}

static const struct file_operations mtutab_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = mtutab_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write   = mtutab_write
};

static int mps_trc_show(struct seq_file *seq, void *v)
{
	int enabled, i;
	struct trace_params tp;
	unsigned int trcidx = (uintptr_t)seq->private & 3;
	struct adapter *adap = seq->private - trcidx;

	t4_get_trace_filter(adap, &tp, trcidx, &enabled);
	if (!enabled) {
		seq_puts(seq, "tracer is disabled\n");
		return 0;
	}

	if (tp.skip_ofst * 8 >= TRACE_LEN) {
		dev_err(adap->pdev_dev, "illegal trace pattern skip offset\n");
		return -EINVAL;
	}
	if (tp.port < 8) {
		i = adap->chan_map[tp.port & 3];
		if (i >= MAX_NPORTS) {
			dev_err(adap->pdev_dev, "tracer %u is assigned "
				"to non-existing port\n", trcidx);
			return -EINVAL;
		}
		seq_printf(seq, "tracer is capturing %s %s, ",
			   adap->port[i]->name, tp.port < 4 ? "Rx" : "Tx");
	} else
		seq_printf(seq, "tracer is capturing loopback %d, ",
			   tp.port - 8);
	seq_printf(seq, "snap length: %u, min length: %u\n", tp.snap_len,
		   tp.min_len);
	seq_printf(seq, "packets captured %smatch filter\n",
		   tp.invert ? "do not " : "");

	if (tp.skip_ofst) {
		seq_puts(seq, "filter pattern: ");
		for (i = 0; i < tp.skip_ofst * 2; i += 2)
			seq_printf(seq, "%08x%08x", tp.data[i], tp.data[i + 1]);
		seq_putc(seq, '/');
		for (i = 0; i < tp.skip_ofst * 2; i += 2)
			seq_printf(seq, "%08x%08x", tp.mask[i], tp.mask[i + 1]);
		seq_puts(seq, "@0\n");
	}

	seq_puts(seq, "filter pattern: ");
	for (i = tp.skip_ofst * 2; i < TRACE_LEN / 4; i += 2)
		seq_printf(seq, "%08x%08x", tp.data[i], tp.data[i + 1]);
	seq_putc(seq, '/');
	for (i = tp.skip_ofst * 2; i < TRACE_LEN / 4; i += 2)
		seq_printf(seq, "%08x%08x", tp.mask[i], tp.mask[i + 1]);
	seq_printf(seq, "@%u\n", (tp.skip_ofst + tp.skip_len) * 8);
	return 0;
}

static int mps_trc_open(struct inode *inode, struct file *file)
{
	return single_open(file, mps_trc_show, inode->i_private);
}

static unsigned int xdigit2int(unsigned char c)
{
	return isdigit(c) ? c - '0' : tolower(c) - 'a' + 10;
}

#define TRC_PORT_NONE 0xff

/*
 * Set an MPS trace filter.  Syntax is:
 *
 * disable
 *
 * to disable tracing, or
 *
 * interface [snaplen=<val>] [minlen=<val>] [not] [<pattern>]...
 *
 * where interface is one of rxN, txN, or loopbackN, N = 0..3, and pattern
 * has the form
 *
 * <pattern data>[/<pattern mask>][@<anchor>]
 *
 * Up to 2 filter patterns can be specified.  If 2 are supplied the first one
 * must be anchored at 0.  An omited mask is taken as a mask of 1s, an omitted
 * anchor is taken as 0.
 */
static ssize_t mps_trc_write(struct file *file, const char __user *buf,
			     size_t count, loff_t *pos)
{
	int i, j, enable;
	u32 *data, *mask;
	struct trace_params tp;
	const struct inode *ino;
	unsigned int trcidx;
	char *s, *p, *word, *end;
	struct adapter *adap;

	ino = FILE_DATA(file);
	trcidx = (uintptr_t)ino->i_private & 3;
	adap = ino->i_private - trcidx;

	/*
	 * Don't accept input more than 1K, can't be anything valid except lots
	 * of whitespace.  Well, use less.
	 */
	if (count > 1024)
		return -EFBIG;
	p = s = kzalloc(count + 1, GFP_USER);
	if (!s)
		return -ENOMEM;
	if (copy_from_user(s, buf, count)) {
		count = -EFAULT;
		goto out;
	}

	if (s[count - 1] == '\n')
		s[count - 1] = '\0';

	enable = strcmp("disable", s) != 0;
	if (!enable)
		goto apply;

	memset(&tp, 0, sizeof(tp));
	tp.port = TRC_PORT_NONE;
	i = 0;                                      /* counts pattern nibbles */

	while (p) {
		while (isspace(*p))
			p++;
		word = strsep(&p, " ");
		if (!*word)
			break;

		if (!strncmp(word, "snaplen=", 8)) {
			j = simple_strtoul(word + 8, &end, 10);
			if (*end || j > 9600) {
inval:				count = -EINVAL;
				goto out;
			}
			tp.snap_len = j;
			continue;
		}
		if (!strncmp(word, "minlen=", 7)) {
			j = simple_strtoul(word + 7, &end, 10);
			if (*end || j > M_TFMINPKTSIZE)
				goto inval;
			tp.min_len = j;
			continue;
		}
		if (!strcmp(word, "not")) {
			tp.invert = !tp.invert;
			continue;
		}
		if (!strncmp(word, "loopback", 8) && tp.port == TRC_PORT_NONE) {
			if (word[8] < '0' || word[8] > '3' || word[9])
				goto inval;
			tp.port = word[8] - '0' + 8;
			continue;
		}
		if (!strncmp(word, "tx", 2) && tp.port == TRC_PORT_NONE) {
			if (word[2] < '0' || word[2] > '3' || word[3])
				goto inval;
			tp.port = word[2] - '0' + 4;
			if (adap->chan_map[tp.port & 3] >= MAX_NPORTS)
				goto inval;
			continue;
		}
		if (!strncmp(word, "rx", 2) && tp.port == TRC_PORT_NONE) {
			if (word[2] < '0' || word[2] > '3' || word[3])
				goto inval;
			tp.port = word[2] - '0';
			if (adap->chan_map[tp.port] >= MAX_NPORTS)
				goto inval;
			continue;
		}
		if (!isxdigit(*word))
			goto inval;

		/* we have found a trace pattern */
		if (i) {                            /* split pattern */
			if (tp.skip_len)            /* too many splits */
				goto inval;
			tp.skip_ofst = i / 16;
		}

		data = &tp.data[i / 8];
		mask = &tp.mask[i / 8];
		j = i;

		while (isxdigit(*word)) {
			if (i >= TRACE_LEN * 2) {
				count = -EFBIG;
				goto out;
			}
			*data = (*data << 4) + xdigit2int(*word++);
			if (++i % 8 == 0)
				data++;
		}
		if (*word == '/') {
			word++;
			while (isxdigit(*word)) {
				if (j >= i)         /* mask longer than data */
					goto inval;
				*mask = (*mask << 4) + xdigit2int(*word++);
				if (++j % 8 == 0)
					mask++;
			}
			if (i != j)                 /* mask shorter than data */
				goto inval;
		} else {                            /* no mask, use all 1s */
			for ( ; i - j >= 8; j += 8)
				*mask++ = 0xffffffff;
			if (i % 8)
				*mask = (1 << (i % 8) * 4) - 1;
		}
		if (*word == '@') {
			j = simple_strtoul(word + 1, &end, 10);
			if (*end && *end != '\n')
				goto inval;
			if (j & 7)          /* doesn't start at multiple of 8 */
				goto inval;
			j /= 8;
			if (j < tp.skip_ofst)     /* overlaps earlier pattern */
				goto inval;
			if (j - tp.skip_ofst > 31)            /* skip too big */
				goto inval;
			tp.skip_len = j - tp.skip_ofst;
		}
		if (i % 8) {
			*data <<= (8 - i % 8) * 4;
			*mask <<= (8 - i % 8) * 4;
			i = (i + 15) & ~15;         /* 8-byte align */
		}
	}

	if (tp.port == TRC_PORT_NONE)
		goto inval;

#if 0
	if (tp.port < 8)
		printk("tracer is capturing %s %s, ",
			adap->port[adap->chan_map[tp.port & 3]]->name,
			tp.port < 4 ? "Rx" : "Tx");
	else
		printk("tracer is capturing loopback %u, ", tp.port - 8);
	printk("snap length: %u, min length: %u\n", tp.snap_len, tp.min_len);
	printk("packets captured %smatch filter\n", tp.invert ? "do not " : "");

	if (tp.skip_ofst) {
		printk("filter pattern: ");
		for (i = 0; i < tp.skip_ofst * 2; i += 2)
			printk("%08x%08x", tp.data[i], tp.data[i + 1]);
		printk("/");
		for (i = 0; i < tp.skip_ofst * 2; i += 2)
			printk("%08x%08x", tp.mask[i], tp.mask[i + 1]);
		printk("@0\n");
	}

	printk("filter pattern: ");
	for (i = tp.skip_ofst * 2; i < TRACE_LEN / 4; i += 2)
		printk("%08x%08x", tp.data[i], tp.data[i + 1]);
	printk("/");
	for (i = tp.skip_ofst * 2; i < TRACE_LEN / 4; i += 2)
		printk("%08x%08x", tp.mask[i], tp.mask[i + 1]);
	printk("@%u\n", (tp.skip_ofst + tp.skip_len) * 8);
#endif

apply:
	i = t4_set_trace_filter(adap, &tp, trcidx, enable);
	if (i)
		count = i;
out:
	kfree(s);
	return count;
}

static const struct file_operations mps_trc_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = mps_trc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write   = mps_trc_write
};

static int sge_stats_show(struct seq_file *seq, void *v)
{
	struct adapter *adap = seq->private;
	int eth_entries = DIV_ROUND_UP(adap->sge.ethqsets, 4);
	int toe_entries = DIV_ROUND_UP(adap->sge.ofldqsets, 4);
	int rdma_entries = DIV_ROUND_UP(adap->sge.rdmaqs, 4);
	int rdma_ciq_entries = DIV_ROUND_UP(adap->sge.rdmaciqs, 4);
	int iscsi_entries = DIV_ROUND_UP(adap->sge.niscsiq, 4);
	int ctrl_entries = DIV_ROUND_UP(MAX_CTRL_QUEUES, 4);
	int trace_entries = DIV_ROUND_UP(adap->sge.ntraceq, 4);
	int vxlan_entries = DIV_ROUND_UP(adap->sge.nvxlanq, 4);
	int i, r = (uintptr_t)v - 1;

	if (r)
		seq_putc(seq, '\n');

#define S3(fmt_spec, s, v) \
	seq_printf(seq, "%-12s", s); \
	for (i = 0; i < n; ++i) \
		seq_printf(seq, " %16" fmt_spec, v); \
		seq_putc(seq, '\n');
#define S(s, v) S3("s", s, v)
#define T3(fmt_spec, s, v) S3(fmt_spec, s, tx[i].v)
#define T(s, v) T3("lu", s, v)
#define R3(fmt_spec, s, v) S3(fmt_spec, s, qs[i].v)
#define R(s, v) R3("lu", s, v)

	if (r < eth_entries) {
		const struct sge_eth_rxq *qs = &adap->sge.ethrxq[r * 4];
		const struct sge_eth_txq *tx = &adap->sge.ethtxq[r * 4];
		int n = min(4, adap->sge.ethqsets - 4 * r);

		S("QType:", "Ethernet");
		S("Interface:",
		  qs[i].rspq.netdev ? qs[i].rspq.netdev->name : "N/A");
		R("RxPackets:", stats.pkts);
		R("RxCSO:", stats.rx_cso);
		R("VLANxtract:", stats.vlan_ex);
		R("LROmerged:", stats.lro_merged);
		R("LROpackets:", stats.lro_pkts);
		R("RxDrops:", stats.rx_drops);
		T("TSO:", tso);
		T("TxCSO:", tx_cso);
		T("VLANins:", vlan_ins);
		T("TxQFull:", q.stops);
		T("TxQRestarts:", q.restarts);
		T("TxMapErr:", mapping_err);
		T("TxCoalWR:", coal_wr);
		T("TxCoalPkt:", coal_pkts);
		R("FLAllocErr:", fl.alloc_failed);
		R("FLLrgAlcErr:", fl.large_alloc_failed);
		R("FLMapErr:", fl.mapping_err);
		R("FLLow:", fl.low);
		R("FLStarving:", fl.starving);
	} else {
		if (!(is_hashfilter(adap) && is_t5(adap->params.chip))) {
			if ((r -= eth_entries) < toe_entries) {
				const struct sge_ofld_rxq *qs = &adap->sge.ofldrxq[r * 4];
				const struct sge_ofld_txq *tx = &adap->sge.ofldtxq[r * 4];
				int n = min(4, adap->sge.ofldqsets - 4 * r);

				S("QType:", "TOE");
				R("RxPackets:", stats.pkts);
				R("RxImmPkts:", stats.imm);
				R("RxNoMem:", stats.nomem);
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
				R("LROmerged:", rspq.lro_mgr.lro_merged);
				R("LROpackets:", rspq.lro_mgr.lro_pkts);
#endif
				T("TxPkts:", q.txp);
				T("TxQFull:", q.stops);
				T("TxQRestarts:", q.restarts);
				T("TxMapErr:", mapping_err);
				R("FLAllocErr:", fl.alloc_failed);
				R("FLLrgAlcErr:", fl.large_alloc_failed);
				R("FLMapErr:", fl.mapping_err);
				R("FLLow:", fl.low);
				R("FLStarving:", fl.starving);
			} else if ((r -= toe_entries) < rdma_entries) {
				const struct sge_ofld_rxq *qs = &adap->sge.rdmarxq[r * 4];
				int n = min(4, adap->sge.rdmaqs - 4 * r);

				S("QType:", "RDMA-CPL");
				R("RxPackets:", stats.pkts);
				R("RxImmPkts:", stats.imm);
				R("RxNoMem:", stats.nomem);
				R("FLAllocErr:", fl.alloc_failed);
				R("FLLrgAlcErr:", fl.large_alloc_failed);
				R("FLMapErr:", fl.mapping_err);
				R("FLLow:", fl.low);
				R("FLStarving:", fl.starving);
			} else if ((r -= rdma_entries) < rdma_ciq_entries) {
				const struct sge_ofld_rxq *qs = &adap->sge.rdmaciq[r * 4];
				int n = min(4, adap->sge.rdmaciqs - 4 * r);

				S("QType:", "RDMA-CIQ");
				R("RxAN:", stats.an);
				R("RxNoMem:", stats.nomem);
			} else if ((r -= rdma_ciq_entries) < iscsi_entries) {
				const struct sge_ofld_rxq *qs = &adap->sge.iscsirxq[r * 4];
				int n = min(4, adap->sge.niscsiq - 4 * r);

				S("QType:", "iSCSI");
				R("RxPackets:", stats.pkts);
				R("RxImmPkts:", stats.imm);
				R("RxNoMem:", stats.nomem);
				R("FLAllocErr:", fl.alloc_failed);
				R("FLLrgAlcErr:", fl.large_alloc_failed);
				R("FLMapErr:", fl.mapping_err);
				R("FLLow:", fl.low);
				R("FLStarving:", fl.starving);
			} else if ((r -= iscsi_entries) < ctrl_entries) {
				const struct sge_ctrl_txq *tx = &adap->sge.ctrlq[r * 4];
				int n = min(4, adap->params.nports - 4 * r);

				S("QType:", "Control");
				T("TxPkts:", q.txp);
				T("TxQFull:", q.stops);
				T("TxQRestarts:", q.restarts);
			} else if ((r -= ctrl_entries) < vxlan_entries) {
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
				int base_qset = r * 4;
				const struct sge_eth_txq *tx;
				const struct sge_eth_rxq *rx;
				int n = min(4, adap->sge.ethqsets - 4 * r);

				tx = &adap->sge.vxlantxq[base_qset];
				rx = &adap->sge.ethrxq[base_qset];
				S("QType:", "VxLAN");
				S("Interface:",
				  rx[i].rspq.netdev ?
				  rx[i].rspq.netdev->name : "N/A");
				T("VLANins:", vlan_ins);
				T("TxQFull:", q.stops);
#endif
			} else if ((r -= vxlan_entries) == 0) {
				seq_printf(seq, "%-12s %16s\n", "QType:", "FW event queue");
			}
		} else {
			if ((r -= eth_entries) < trace_entries) {
				const struct sge_eth_rxq *qs = &adap->sge.traceq[r * 4];
				int n = min(4, adap->sge.ntraceq - 4 * r);

				S("QType:", "Trace");
				S("Interface:",
				  qs[i].rspq.netdev ? qs[i].rspq.netdev->name : "N/A");
				R("RxPackets:", stats.pkts);
				R("RxCSO:", stats.rx_cso);
				R("VLANxtract:", stats.vlan_ex);
				R("LROmerged:", stats.lro_merged);
				R("LROpackets:", stats.lro_pkts);
				R("RxDrops:", stats.rx_drops);
				R("FLAllocErr:", fl.alloc_failed);
				R("FLLrgAlcErr:", fl.large_alloc_failed);
				R("FLMapErr:", fl.mapping_err);
				R("FLLow:", fl.low);
				R("FLStarving:", fl.starving);
			} else if((r -= trace_entries) < ctrl_entries) {
				const struct sge_ctrl_txq *tx = &adap->sge.ctrlq[r * 4];
				int n = min(4, MAX_CTRL_QUEUES - 4 * r);

				S("QType:", "Control");
				T("TxPkts:", q.txp);
				T("TxQFull:", q.stops);
				T("TxQRestarts:", q.restarts);
			} else if ((r -= ctrl_entries) < vxlan_entries) {
#if IS_ENABLED(CONFIG_VXLAN) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
				int base_qset = r * 4;
				const struct sge_eth_txq *tx;
				const struct sge_eth_rxq *rx;
				int n = min(4, adap->sge.ethqsets - 4 * r);

				tx = &adap->sge.vxlantxq[base_qset];
				rx = &adap->sge.ethrxq[base_qset];
				S("QType:", "VxLAN");
				S("Interface:",
				  rx[i].rspq.netdev ?
				  rx[i].rspq.netdev->name : "N/A");
				T("VLANins:", vlan_ins);
				T("TxQFull:", q.stops);
#endif
			} else if ((r -= vxlan_entries) == 0) {
				seq_printf(seq, "%-12s %16s\n", "QType:", "FW event queue");
			}
		}
	}
#undef R
#undef T
#undef S
#undef R3
#undef T3
#undef S3
	return 0;
}

static const struct seq_operations sge_stats_seq_ops = {
	.start = sge_queue_start,
	.next  = sge_queue_next,
	.stop  = sge_queue_stop,
	.show  = sge_stats_show
};

static int sge_stats_open(struct inode *inode, struct file *file)
{
	int res = seq_open(file, &sge_stats_seq_ops);

	if (!res) {
		struct seq_file *seq = file->private_data;
		seq->private = inode->i_private;;
	}
	return res;
}

static const struct file_operations sge_stats_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = sge_stats_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};
/*
 * Add an array of Debug FS files.
 */
static void cxgb4_add_debugfs_files(struct adapter *adap,
					struct t4_linux_debugfs_entry *files,
					unsigned int nfiles)
{
	int i;
	int ofld = is_offload(adap);

	/* debugfs support is best effort */
	for (i = 0; i < nfiles; i++) {
		unsigned int req = files[i].req;

		if ((req & ADAP_NEED_OFLD) && !ofld)
			continue;
		if ((req & ADAP_NEED_L2T) && !adap->l2t)
			continue;
                if ((req & ADAP_NEED_SMT) && !adap->smt)
                        continue;
		if ((req & ADAP_NEED_SRQ) && !adap->srq)
			continue;
		debugfs_create_file(files[i].name,
				    files[i].mode,
				    adap->debugfs_root,
				    (void *)adap + files[i].data,
				    files[i].ops);
	}
}

int cxgb4_setup_debugfs(struct adapter *adap)
{
	static struct t4_linux_debugfs_entry cxgb4_debugfs_files[] = {
		{ "blocked_fl", &blocked_fl_fops, S_IRUSR | S_IWUSR, 0, 0},
#ifdef CONFIG_CXGB4_DCB
		{ "dcb_info", &dcb_info_debugfs_fops, S_IRUSR, 0, 0 },
#endif
		{ "sge_qinfo", &sge_qinfo_debugfs_fops, S_IRUSR, 0, 0 },
		{ "intr_holdoff", &intr_holdoff_debugfs_fops, S_IRUSR, 0, 0 },
		{ "intr_cnt", &intr_cnt_debugfs_fops, S_IRUSR, 0, 0 },
		{ "uld", &uld_debugfs_fops, S_IRUSR, 0, 0 },
		{ "inject_err", &inject_err_debugfs_fops, S_IRUSR, 0, 0 },
		{ "clip_tbl", &clip_tbl_debugfs_fops, S_IRUSR, 0, 0 },
		{ "tids", &tid_info_debugfs_fops, S_IRUSR, 0, ADAP_NEED_FILT },
		{ "path_mtus", &mtutab_debugfs_fops, S_IRUSR|S_IWUSR, 0, 0 },
		{ "filters", &filters_debugfs_fops, S_IRUSR, 0, 0 },
		{ "hash_filters", &hash_filters_debugfs_fops, S_IRUSR, 0, 0 },
		{ "trace0", &mps_trc_debugfs_fops, S_IRUSR | S_IWUSR, 0, 0 },
		{ "trace1", &mps_trc_debugfs_fops, S_IRUSR | S_IWUSR, 1, 0 },
		{ "trace2", &mps_trc_debugfs_fops, S_IRUSR | S_IWUSR, 2, 0 },
		{ "trace3", &mps_trc_debugfs_fops, S_IRUSR | S_IWUSR, 3, 0 },
		{ "qstats", &sge_stats_debugfs_fops, S_IRUSR, 0, 0},
		{ "l2t", &t4_l2t_debugfs_fops, S_IRUSR, 0, ADAP_NEED_L2T },
		{ "smt", &t4_smt_debugfs_fops, S_IRUSR, 0, ADAP_NEED_SMT },
		{ "srq", &t4_srq_debugfs_fops, S_IRUSR, 0, ADAP_NEED_SRQ },
	};

	if (setup_debugfs(adap))
		return -1;

	cxgb4_add_debugfs_files(adap,
			  cxgb4_debugfs_files,
			  ARRAY_SIZE(cxgb4_debugfs_files));

	return 0;
}

