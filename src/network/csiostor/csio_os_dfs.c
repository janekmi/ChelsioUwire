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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/mm.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include <linux/proc_fs.h>
#include <linux/ctype.h>
#include <linux/sort.h>
#include <linux/string_helpers.h>
#include <linux/version.h>
#include <asm/div64.h>
#include <csio_version.h>
#include <csio_os_init.h>
#include "t4_linux_fs.h"

/* Debug FS support */
static struct dentry *cstor_debugfs_root;
#define DRV_NAME	KBUILD_MODNAME

static int trace_buf_show(struct seq_file *seq, void *v, int idx)
{
	struct csio_oss_trace_msg *trace_msg = v;

	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "Idx  Timestamp     File:line    val1    val2 "
			 "val3    val4\n");

	else {
		if (trace_msg->type == CSIO_TRACE_IO) {
			seq_printf(seq, "%3u: %x %s:%d %llx %llx %llx %llx\n",
			idx, trace_msg->ts, trace_msg->file_name,
			trace_msg->line_no, trace_msg->val[0],
			trace_msg->val[1], trace_msg->val[2],
			trace_msg->val[3]);
		}
		else if (trace_msg->type == CSIO_TRACE_SMS) {
			seq_printf(seq, "%3u: %x %s:%d Set module [%llx] "
				   "to State [%llx]\n",
				   idx, trace_msg->ts, trace_msg->file_name,
				   trace_msg->line_no, trace_msg->val[0],
				   trace_msg->val[1]);
		}
		else {
			seq_printf(seq, "%3u: %x %s:%d Post module [%llx] "
				   "an Event[%llx]\n",
				   idx, trace_msg->ts, trace_msg->file_name,
				   trace_msg->line_no, trace_msg->val[0],
				   trace_msg->val[1]);
		}	
	}
	return 0;
}

static int trace_buf_open(struct inode *inode, struct file *file)
{
	struct seq_tab *p;
	struct adapter *adap = (struct adapter *)inode->i_private;
	struct csio_hw *hw = csio_oshw_to_hw(csio_adap_to_oshw(adap));
	struct csio_oss_trace_buf *trace_buf = NULL;
	struct csio_oss_trace_msg *trace_msg;
	size_t sz = 1024;

	p = seq_open_tab(file, sz, sizeof(struct csio_oss_trace_msg), 1,
			 trace_buf_show);
	if (!p)
		return -ENOMEM;

	trace_msg = (struct csio_oss_trace_msg *) p->data;
	trace_buf = csio_hw_to_tbuf(hw);
	
	while (sz != 0) {
		if (!(csio_oss_trace_readmsg(trace_buf, trace_msg++, 1))) {
			/* No more msg */
			break;
		}
		sz--;
	}
	return 0;
}

static const struct file_operations trace_buf_fops = {
	.owner   = THIS_MODULE,
	.open    = trace_buf_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release_private
};

#ifdef CSIO_DATA_CAPTURE
static int dcap_buf_show(struct seq_file *seq, void *v, int idx)
{
	struct csio_oss_dcap *dcap_msg = v;

	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "ioreq  cdb|len lba dma_addr dma_len data1 data2"
			 "data3 data4\n");

	else {
		seq_printf(seq, "%3u %08llx %08x %08x %08llx %08d %08llx "
			   "%08llx %08llx %08llx\n", idx, dcap_msg->ioreq,
			   dcap_msg->flags, dcap_msg->lba,
			   dcap_msg->addr, dcap_msg->len, dcap_msg->val1,
			   dcap_msg->val2, dcap_msg->val3, dcap_msg->val4);
	}
	return 0;
}

static int dcap_buf_open(struct inode *inode, struct file *file)
{
	int ret;
	struct seq_tab *p;
	struct adapter *adap = (struct adapter *)inode->i_private;
	struct csio_hw *hw = csio_oshw_to_hw(csio_adap_to_oshw(adap));
	struct csio_oss_dcap_buf *dcap_buf = NULL;
	struct csio_oss_dcap *dcap;
	size_t sz = 1024;

	p = seq_open_tab(file, sz, sizeof(struct csio_oss_dcap), 1,
			 dcap_buf_show);
	if (!p)
		return -ENOMEM;

	dcap = (struct csio_oss_dcap *) p->data;
	dcap_buf = hw->dcap_buf;
	
	while (sz != 0) {
		if (!(CSIO_DCAP_READ(dcap_buf, dcap++, 1))) {
			/* No more msg */
			break;
		}
		sz--;
	}
	return 0;
}
static const struct file_operations dcap_buf_fops = {
	.owner   = THIS_MODULE,
	.open    = dcap_buf_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release_private
};
#endif
static int fcf_show(struct seq_file *seq, void *v)
{
	struct csio_os_hw *oshw = csio_adap_to_oshw((struct adapter *)seq->private);
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_fcf_info *fcf;
	uint32_t fcfi, id = 0;
	
	fcfi = CSIO_INVALID_IDX;
	while ((fcf = csio_fcoe_get_next_fcf(hw, fcfi)) != NULL) {
		seq_printf(seq, "*****************[Index:%3u]***************\n",
			 id++);
		seq_printf(seq, "prio: %3u\n", fcf->priority);
		seq_printf(seq, "fcf mac: %02x%02x%02x%02x%02x%02x\n",
			  fcf->mac[0], fcf->mac[1], fcf->mac[2], fcf->mac[3],
			  fcf->mac[4], fcf->mac[5]);
		seq_printf(seq, "name id: %02x%02x%02x%02x%02x%02x%02x%02x\n",
			  fcf->name_id[0], fcf->name_id[1], fcf->name_id[2],
			  fcf->name_id[3], fcf->name_id[4], fcf->name_id[5],
			  fcf->name_id[6], fcf->name_id[7]);
		seq_printf(seq, "fabric: %02x%02x%02x%02x%02x%02x%02x%02x\n",
			  fcf->fabric[0], fcf->fabric[1], fcf->fabric[2],
			  fcf->fabric[3], fcf->fabric[4], fcf->fabric[5],
			  fcf->fabric[6], fcf->fabric[7]);
		seq_printf(seq, "vf_id: %u\n", fcf->vf_id);
		seq_printf(seq, "vlan id: %u\n", fcf->vlan_id);
		seq_printf(seq, "max frame size: %u\n", fcf->max_fcoe_size);
		seq_printf(seq, "fcf map: %02x%02x%02x\n", fcf->fc_map[0],
			  fcf->fc_map[1], fcf->fc_map[2]);
		seq_printf(seq, "fka adv period: %d\n", fcf->fka_adv);
		seq_printf(seq, "fcfi: %u\n", fcf->fcfi);
		seq_printf(seq, "link affected: %u\n", fcf->link_aff);
		seq_printf(seq, "fpma: %u\n", fcf->fpma);
		seq_printf(seq, "spma: %u\n", fcf->spma);
		seq_printf(seq, "available for login: %u\n", fcf->login);
		seq_printf(seq, "port id: %u\n", fcf->portid);
		seq_printf(seq, "spma mac: %02x%02x%02x%02x%02x%02x\n",
			  fcf->spma_mac[0], fcf->spma_mac[1], fcf->spma_mac[2],
			  fcf->spma_mac[3], fcf->spma_mac[4], fcf->spma_mac[5]);
		fcfi = fcf->fcfi;
	}
	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(fcf);

static int lnode_show(struct seq_file *seq, void *v)
{
	struct csio_os_hw *oshw = csio_adap_to_oshw((struct adapter *)seq->private);
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_lnode *ln;
	struct csio_lnode_fcoe *lnf;	
	uint32_t vnpi, id = 0, ii;
	
	csio_spin_lock_irq(hw, &hw->lock);
	vnpi = CSIO_INVALID_IDX;
	while ((ln = csio_fcoe_get_next_lnode(hw, vnpi)) != NULL) {
		lnf = csio_lnode_to_fcoe(ln);
		seq_printf(seq, "*****************[Index:%3u]***************\n",
			   id++);
		seq_printf(seq, "device id: %u\n", ln->dev_num);
		seq_printf(seq, "vnpi: %u\n", lnf->vnp_flowid);
		seq_printf(seq, "fcfi: %u\n", lnf->fcf_flowid);
		seq_printf(seq, "mac: %02x%02x%02x%02x%02x%02x\n", lnf->mac[0],
			  lnf->mac[1], lnf->mac[2], lnf->mac[3], lnf->mac[4],
			  lnf->mac[5]);
		seq_printf(seq, "nport id: %x\n", lnf->nport_id);
		seq_printf(seq, "wwnn: %02x%02x%02x%02x%02x%02x%02x%02x\n",
			  lnf->ln_sparm.wwnn[0], lnf->ln_sparm.wwnn[1],
			  lnf->ln_sparm.wwnn[2], lnf->ln_sparm.wwnn[3],
			  lnf->ln_sparm.wwnn[4], lnf->ln_sparm.wwnn[5],
			  lnf->ln_sparm.wwnn[6], lnf->ln_sparm.wwnn[7]);
		seq_printf(seq, "wwpn: %02x%02x%02x%02x%02x%02x%02x%02x\n",
			  lnf->ln_sparm.wwpn[0], lnf->ln_sparm.wwpn[1],
			  lnf->ln_sparm.wwpn[2], lnf->ln_sparm.wwpn[3],
			  lnf->ln_sparm.wwpn[4], lnf->ln_sparm.wwpn[5],
			  lnf->ln_sparm.wwpn[6], lnf->ln_sparm.wwpn[7]);
		seq_printf(seq, "num rnodes: %3u\n", ln->num_reg_rnodes);
		seq_printf(seq, "npiv: %s\n", lnf->flags & CSIO_LNFFLAG_NPIVSUPP
			   ? "SUPPORTED":"NOT SUPPORTED");
		seq_printf(seq, "common service params:\n");
		seq_printf(seq, "\thi ver:%02x\n", lnf->ln_sparm.csp.hi_ver);
		seq_printf(seq, "\tlow ver:%02x\n", lnf->ln_sparm.csp.lo_ver);
		seq_printf(seq, "\tbb credit:%d\n",
			   lnf->ln_sparm.csp.bb_credit);
		seq_printf(seq, "\tword1(31:16) flags:%x\n", lnf->ln_sparm.csp.
			  word1_flags);
		seq_printf(seq, "\trcv size:%d\n", lnf->ln_sparm.csp.rcv_sz);
		seq_printf(seq, "\tmaxsq_reloff:%d\n", lnf->ln_sparm.csp.un1.
			  maxsq_reloff);
		seq_printf(seq, "\tratov:%d\n", lnf->ln_sparm.csp.un1.r_a_tov);
		seq_printf(seq, "\tedtov:%d\n", lnf->ln_sparm.csp.e_d_tov);
		seq_printf(seq, "class service params:\n");
		for (ii = 0; ii < 4; ii++) {
			seq_printf(seq, "class %d:%s\n", ii + 1,
			G_SP_CLASS_SUPPORT(lnf->ln_sparm.clsp[ii].serv_option)
			? "SUPPORTED" : "NOT SUPPORTED");

			if (!G_SP_CLASS_SUPPORT(
			   lnf->ln_sparm.clsp[ii].serv_option))
				continue;
			
			seq_printf(seq, "initiator ctl:%x\n",
				lnf->ln_sparm.clsp[ii].init_ctl_option);	
			seq_printf(seq, "recipient ctl:%x\n",
				lnf->ln_sparm.clsp[ii].rcv_ctl_option);	
			seq_printf(seq, "rcv size:%d\n",
				lnf->ln_sparm.clsp[ii].rcv_data_sz);	
			seq_printf(seq, "Total concurrent seq:%d\n",
				lnf->ln_sparm.clsp[ii].concurrent_seq);	
			seq_printf(seq, "ee credit:%d\n",
				lnf->ln_sparm.clsp[ii].ee_credit);	
			seq_printf(seq, "open sequence per exch:%d\n\n",
				lnf->ln_sparm.clsp[ii].openseq_per_xchg);	
		}
		vnpi = lnf->vnp_flowid;	
	}
	csio_spin_unlock_irq(hw, &hw->lock);
	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(lnode);

static int lnode_stat_show(struct seq_file *seq, void *v)
{
	struct csio_os_hw *oshw = csio_adap_to_oshw((struct adapter *)seq->private);
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_lnode *ln;
	struct csio_lnode_fcoe *lnf;	
	struct csio_lnode_fcoestats *stat;
	uint32_t vnpi, id = 0;
	int ii;
	char   state[32];
	
	csio_spin_lock_irq(hw, &hw->lock);
	vnpi = CSIO_INVALID_IDX;
	while ((ln = csio_fcoe_get_next_lnode(hw, vnpi)) != NULL) {
		lnf = csio_lnode_to_fcoe(ln);

					
		seq_printf(seq, "******************Index :%3u***************\n",
			 id++);

		seq_printf(seq, "lnf addr: %p\n", lnf);
		seq_printf(seq, "vnpi: %u\n", lnf->vnp_flowid);
		seq_printf(seq, "fcfi: %u\n", lnf->fcf_flowid);
		seq_printf(seq, "nport id: %x\n", lnf->nport_id);
		seq_printf(seq, "wwpn: %02x%02x%02x%02x%02x%02x%02x%02x\n",
			  lnf->ln_sparm.wwpn[0], lnf->ln_sparm.wwpn[1],
			  lnf->ln_sparm.wwpn[2], lnf->ln_sparm.wwpn[3],
			  lnf->ln_sparm.wwpn[4], lnf->ln_sparm.wwpn[5],
			  lnf->ln_sparm.wwpn[6], lnf->ln_sparm.wwpn[7]);
		csio_lnf_stateto_str(lnf, state);
		seq_printf(seq, "state: %s\n", state);
		seq_printf(seq, "\tcurrent evt:%s\n",
				csio_rnf_fwevt_name(lnf->cur_evt));
		seq_printf(seq, "\tprevious evt:%s\n",
				csio_rnf_fwevt_name(lnf->prev_evt) ?
				csio_rnf_fwevt_name(lnf->prev_evt) : "NONE");
		stat = &lnf->stats;
		seq_printf(seq, "statistics\n");
		seq_printf(seq, "\tlink up: %d\n", stat->n_link_up);
		seq_printf(seq, "\tlink down: %d\n", stat->n_link_down);
		seq_printf(seq, "\terrors: %d\n", stat->n_err);
		seq_printf(seq, "\tmemory failures: %d\n", stat->n_err_nomem);
		seq_printf(seq, "\tinval param: %d\n", stat->n_inval_parm);
		seq_printf(seq, "\trnode match: %d\n", stat->n_rnode_match);
		seq_printf(seq, "\tunexpected events: %d\n", stat->n_evt_unexp);
		seq_printf(seq, "\tdropped events: %d\n", stat->n_evt_drop);
		seq_printf(seq, "fw rdev events stats\n");
		for (ii = PLOGI_ACC_RCVD; ii < RSCN_DEV_LOST; ii++) {
			seq_printf(seq, "\t%s: %d\n", csio_rnf_fwevt_name(ii),
				stat->n_evt_fw[ii]);
		}
		seq_printf(seq, "sm events stats\n");
		for (ii=0; ii < CSIO_LNFE_MAX_EVENT; ii++) {
			seq_printf(seq, "\t%s: %d\n", csio_lnf_evt_name(ii),
				stat->n_evt_sm[ii]);
		}	
		vnpi = lnf->vnp_flowid;	
	}
	csio_spin_unlock_irq(hw, &hw->lock);
	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(lnode_stat);

static int rnode_show(struct seq_file *seq, void *v)
{
	struct csio_os_hw *oshw = csio_adap_to_oshw((struct adapter *)seq->private);
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_lnode *ln;
	struct csio_lnode_fcoe *lnf;	
	struct csio_rnode *rn;
	struct csio_rnode_fcoe *rnf;	
	uint32_t vnpi, ssni, id = 0, ii;
	
	csio_spin_lock_irq(hw, &hw->lock);
	vnpi = CSIO_INVALID_IDX;
	while ((ln = csio_fcoe_get_next_lnode(hw, vnpi)) != NULL) {
		lnf = csio_lnode_to_fcoe(ln);
		ssni = CSIO_INVALID_IDX;
		while ((rn = csio_get_next_rnode(ln, ssni)) != NULL) {
			seq_printf(seq, "******************Index :%3u**********"
				   "****\n", id++);
			rnf = csio_rnode_to_fcoe(rn);
			seq_printf(seq, "ssni: %u\n", rn->flowid);
			seq_printf(seq, "vnpi: %u\n", lnf->vnp_flowid);
			seq_printf(seq, "fcfi: %u\n", lnf->fcf_flowid);
			seq_printf(seq,
				   "wwnn: %02x%02x%02x%02x%02x%02x%02x%02x\n",
				   rnf->rn_sparm.wwnn[0], rnf->rn_sparm.wwnn[1],
				   rnf->rn_sparm.wwnn[2], rnf->rn_sparm.wwnn[3],
				   rnf->rn_sparm.wwnn[4], rnf->rn_sparm.wwnn[5],
				   rnf->rn_sparm.wwnn[6],
				   rnf->rn_sparm.wwnn[7]);
			seq_printf(seq,
				   "wwpn: %02x%02x%02x%02x%02x%02x%02x%02x\n",
				   rnf->rn_sparm.wwpn[0], rnf->rn_sparm.wwpn[1],
				   rnf->rn_sparm.wwpn[2], rnf->rn_sparm.wwpn[3],
				   rnf->rn_sparm.wwpn[4], rnf->rn_sparm.wwpn[5],
				   rnf->rn_sparm.wwpn[6],
				   rnf->rn_sparm.wwpn[7]);
			seq_printf(seq, "nport id: %x\n", rnf->nport_id);
			seq_printf(seq, "fcp flags: %x\n", rnf->fcp_flags);
			if (rnf->role & CSIO_RNFR_INITIATOR)
				seq_printf(seq, "role: %s\n", "initiator");
			else if (rnf->role & CSIO_RNFR_TARGET)
				seq_printf(seq, "role: %s\n", "target");
			else if (rnf->role & CSIO_RNFR_FABRIC)
				seq_printf(seq, "role: %s\n", "fabric");
			else if (rnf->role & CSIO_RNFR_NS)
				seq_printf(seq, "role: %s\n", "nameserver");
			else
				seq_printf(seq, "role: %s\n", "nport");
#if 0
			seq_printf(seq, "common service params:\n");
			seq_printf(seq, "\thi ver:%02x\n",
				rnf->rn_sparm.csp.hi_ver);
			seq_printf(seq, "\tlow ver:%02x\n",
				rnf->rn_sparm.csp.lo_ver);
			seq_printf(seq, "\tbb credit:%d\n",
				rnf->rn_sparm.csp.bb_credit);
			seq_printf(seq, "\tword1(31:16) flags:%x\n",
				rnf->rn_sparm.csp.word1_flags);
			seq_printf(seq, "\trcv size:%d\n",
				rnf->rn_sparm.csp.rcv_sz);
			seq_printf(seq, "\tmaxsq_reloff:%d\n",
				rnf->rn_sparm.csp.un1.maxsq_reloff);
			seq_printf(seq, "\tratov:%d\n",
				rnf->rn_sparm.csp.un1.r_a_tov);
			seq_printf(seq, "\tedtov:%d\n",
				rnf->rn_sparm.csp.e_d_tov);
#endif
			seq_printf(seq, "class service params:\n");
			for (ii = 0; ii < 4; ii++) {
				seq_printf(seq, "class %d:%s\n", ii + 1,
				G_SP_CLASS_SUPPORT(rnf->rn_sparm.clsp[ii].
				serv_option) ? "SUPPORTED" : "NOT SUPPORTED");
				
				if (!G_SP_CLASS_SUPPORT(
				   lnf->ln_sparm.clsp[ii].serv_option))
					continue;

#if 0
				seq_printf(seq, "initiator ctl:%x\n",
					rnf->rn_sparm.clsp[ii].init_ctl_option);
				seq_printf(seq, "recipient ctl:%x\n",
					rnf->rn_sparm.clsp[ii].rcv_ctl_option);	
				seq_printf(seq, "rcv size:%d\n",
					rnf->rn_sparm.clsp[ii].rcv_data_sz);	
				seq_printf(seq, "Total concurrent seq:%d\n",
					rnf->rn_sparm.clsp[ii].concurrent_seq);	
				seq_printf(seq, "ee credit:%d\n",
					rnf->rn_sparm.clsp[ii].ee_credit);	
				seq_printf(seq, "open seqs per exch:%d\n\n",
					   rnf->rn_sparm.clsp[ii].
					   openseq_per_xchg);
#endif
			}
			ssni = rn->flowid;	
		}
		vnpi = lnf->vnp_flowid;	
	}
	csio_spin_unlock_irq(hw, &hw->lock);
	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(rnode);

static int rnode_stat_show(struct seq_file *seq, void *v)
{
	struct csio_os_hw *oshw = csio_adap_to_oshw((struct adapter *)seq->private);
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_lnode *ln;
	struct csio_lnode_fcoe *lnf;	
	struct csio_rnode *rn;
	struct csio_rnode_fcoe *rnf;	
	struct csio_rnode_fcoestats *stat;
	uint32_t vnpi, ssni, id = 0;
 	uint32_t ii;
 	char   state[32];
	
	csio_spin_lock_irq(hw, &hw->lock);
	vnpi = CSIO_INVALID_IDX;
	while ((ln = csio_fcoe_get_next_lnode(hw, vnpi)) != NULL) {
		lnf = csio_lnode_to_fcoe(ln);
		ssni = CSIO_INVALID_IDX;
		while ((rn = csio_get_next_rnode(ln, ssni)) != NULL) {
			seq_printf(seq, "******************Index :%3u**********"
				   "****\n", id++);
			rnf = csio_rnode_to_fcoe(rn);
			seq_printf(seq, "rnf addr: %p\n", rnf);
			seq_printf(seq, "ssni: %u\n", rn->flowid);
			seq_printf(seq, "vnpi: %u\n", lnf->vnp_flowid);
			seq_printf(seq, "fcfi: %u\n", lnf->fcf_flowid);
			seq_printf(seq,
				"wwpn: %02x%02x%02x%02x%02x%02x%02x%02x\n",
				rnf->rn_sparm.wwpn[0], rnf->rn_sparm.wwpn[1],
				rnf->rn_sparm.wwpn[2], rnf->rn_sparm.wwpn[3],
				rnf->rn_sparm.wwpn[4], rnf->rn_sparm.wwpn[5],
				rnf->rn_sparm.wwpn[6], rnf->rn_sparm.wwpn[7]);
			seq_printf(seq, "nport id: %x\n", rnf->nport_id);
			csio_rnf_stateto_str(rnf, state);
			seq_printf(seq, "state: %s\n", state);
			seq_printf(seq, "\tcurrent evt:%s\n",
				   csio_rnf_fwevt_name(rnf->cur_evt));
			seq_printf(seq, "\tprevious evt:%s\n",
				   csio_rnf_fwevt_name(rnf->prev_evt) ?
				   csio_rnf_fwevt_name(rnf->prev_evt) : "None");
			stat = &rnf->stats;
			seq_printf(seq, "statistics\n");
			seq_printf(seq, "\terrors: %d\n", stat->n_err);
			seq_printf(seq, "\tmemory failures: %d\n",
					stat->n_err_nomem);
			seq_printf(seq, "\tunexpected events: %d\n",
				stat->n_evt_unexp);
			seq_printf(seq, "\tdropped events: %d\n",
				   stat->n_evt_drop);
			seq_printf(seq, "fw rdev events stats\n");
			for (ii = PLOGI_ACC_RCVD; ii < RSCN_DEV_LOST; ii++) {
				seq_printf(seq, "%s: %d\n",
					csio_rnf_fwevt_name(ii),
					stat->n_evt_fw[ii]);
			}
			seq_printf(seq, "sm events stats\n");
			for (ii=0; ii < CSIO_RNFE_MAX_EVENT; ii++) {
				seq_printf(seq, "\t%s: %d\n",
					csio_rnf_evt_name(ii),
					stat->n_evt_sm[ii]);
			}	
			ssni = rn->flowid;	
		}
		vnpi = lnf->vnp_flowid;	
	}
	csio_spin_unlock_irq(hw, &hw->lock);
	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(rnode_stat);

#ifdef __CSIO_FOISCSI_ENABLED__
static int isession_show(struct seq_file *seq, void *v)
{
	struct csio_os_hw *oshw = csio_adap_to_oshw((struct adapter *)seq->private);
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_list *tmp = NULL, *sln_head = &hw->sln_head;
	struct csio_lnode *ln;
	struct csio_lnode_iscsi *lni;
	struct csio_list *rnhead, *curr_rnode, *next;
	struct csio_rnode *rn;
	struct csio_rnode_iscsi *rni;

	csio_spin_lock_irq(hw, &hw->lock);

	csio_list_for_each(tmp, sln_head) {
		ln = (struct csio_lnode *)tmp;
		lni = csio_lnode_to_iscsi(ln);
		if (!lni->valid)
			continue;
		seq_printf(seq, "instance name: %s\n", lni->inst.name);
		seq_printf(seq, "alias: %s\n", lni->inst.alias);
		seq_printf(seq, "chapid: %s\n", lni->inst.chap_id);
		seq_printf(seq, "chap secret: %s\n", lni->inst.chap_sec);

		rnhead = &ln->rnhead;
		curr_rnode = rnhead->next;
		next = curr_rnode->next;
		csio_list_for_each_safe(curr_rnode, next, rnhead) {
			rn = (struct csio_rnode *)curr_rnode;
			rni = csio_rnode_to_iscsi(rn);
			seq_printf(seq, "\tsession: %u\n", rni->sess_id);
			if (rni->login_info.ip_type == TYPE_IPV4)
				seq_printf(seq, "\tsrc ip: %u.%u.%u.%u\n",
				  (rni->login_info.src_ip.ip4 >> 24) & 0xff,
				  (rni->login_info.src_ip.ip4 >> 16) & 0xff,
				  (rni->login_info.src_ip.ip4 >> 8) & 0xff,
				  rni->login_info.src_ip.ip4 & 0xff);
			else if (rni->login_info.ip_type == TYPE_IPV6)
				seq_printf(seq, "\tsrc ip: %pI6\n",
				  	rni->login_info.src_ip.ip6);

			seq_printf(seq, "\ttarget: %s\n", rni->login_info.tgt_name);
			if (rni->login_info.ip_type == TYPE_IPV4)
				seq_printf(seq,
				   "\ttarget ip: %u.%u.%u.%u:%u\n\n",
				   (rni->login_info.tgt_ip.ip4 >> 24) & 0xff,
				   (rni->login_info.tgt_ip.ip4 >> 16) & 0xff,
				   (rni->login_info.tgt_ip.ip4 >> 8) & 0xff,
				   rni->login_info.tgt_ip.ip4 & 0xff,
				   rni->login_info.tgt_port);
			else if (rni->login_info.ip_type == TYPE_IPV6)
				seq_printf(seq,
				   "\ttarget ip: [%pI6]:%u\n\n",
				   rni->login_info.tgt_ip.ip6,
				   rni->login_info.tgt_port);
		}
		seq_printf(seq, "\n");
	}


	csio_spin_unlock_irq(hw, &hw->lock);
	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(isession);
#endif

static int hw_show(struct seq_file *seq, void *v)
{
	struct csio_os_hw *oshw = csio_adap_to_oshw((struct adapter *)seq->private);
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_scsi_cpu_info *info = NULL;
	int i,j;

	seq_printf(seq, "device id: %u\n", hw->dev_num);
	seq_printf(seq, "name: %s\n", hw->name);
	seq_printf(seq, "model: %s\n", hw->adap.params.vpd.id);
	seq_printf(seq, "serial no: %s\n", hw->adap.params.vpd.sn);
	seq_printf(seq, "firmware rev: 0x%x\n", hw->fwrev);
	seq_printf(seq, "pf number: %d\n", hw->pfn);
	seq_printf(seq, "port vector: 0x%x\n", hw->port_vec);
	seq_printf(seq, "num ports: %d\n", hw->num_t4ports);
	for (i=0; i < CSIO_MAX_T4PORTS; i++) {
		seq_printf(seq, "Port:%d status:%s\n", i,
			hw->t4port[i].link_status ? "LINK UP": "LINK DOWN");

		if (!(hw->t4port[i].link_status))
			continue;

		switch (hw->t4port[i].link_speed) {
			case FW_PORT_CAP_SPEED_100M:
				seq_printf(seq, "Port:%d speed:100M\n", i);
				break;
			case FW_PORT_CAP_SPEED_1G:
				seq_printf(seq, "Port:%d speed:1G\n", i);
				break;
			case FW_PORT_CAP_SPEED_2_5G:
				seq_printf(seq, "Port:%d speed:2.5G\n", i);
				break;
			case FW_PORT_CAP_SPEED_10G:
				seq_printf(seq, "Port:%d speed:10G\n", i);
				break;
			case FW_PORT_CAP_SPEED_40G:
				seq_printf(seq, "Port:%d speed:40G\n", i);
				break;
			case FW_PORT_CAP_SPEED_100G:
				seq_printf(seq, "Port:%d speed:100G\n", i);
				break;
			default:
				seq_printf(seq, "Port:%d speed:unknown\n", i);
				break;
		}		
	}	

	if (hw->intr_mode == CSIO_IM_INTX)
		seq_printf(seq, "intr mode: INTX\n");
	else if (hw->intr_mode == CSIO_IM_MSI)
		seq_printf(seq, "intr mode: MSI\n");
	else if (hw->intr_mode == CSIO_IM_MSIX)
		seq_printf(seq, "intr mode: MSIX\n");
	else
		seq_printf(seq, "intr mode: NONE\n");
		
	seq_printf(seq, "fwevt: iqidx %d msix %d\n", hw->fwevt_iq_idx,
			csio_get_fwevt_intr_idx(hw));
	seq_printf(seq, "Total scsi qsets: %d\n", oshw->num_sqsets);
	for (i = 0; i < hw->num_t4ports; i++) {
		info = &oshw->scsi_cpu_info[i];
		for (j = 0; j < info->max_cpus; j++) {
			struct csio_scsi_qset *sqset;
			sqset = &oshw->sqset[hw->t4port[i].portid][j];
			seq_printf(seq, "scsi qset(%d): iqidx %d eqidx %d "
				   "msix %d\n", (i * 2 + j), sqset->iq_idx,
				   sqset->eq_idx, sqset->intr_idx);
		}
	}	
	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(hw);

static int hw_stat_show(struct seq_file *seq, void *v)
{
	struct csio_os_hw *oshw = csio_adap_to_oshw((struct adapter *)seq->private);
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_hw_stats *stat;
//	struct csio_mbm_stats *mb_stat;
	csio_hw_ev_t ii;
	char   state[32];

	csio_hw_stateto_str(hw, state);
	seq_printf(seq, "hw addr: %p\n", hw);
	seq_printf(seq, "state: %s\n", state);
	seq_printf(seq, "\tcurrent evt:%s\n",
		   csio_hw_evt_name(hw->cur_evt));
	seq_printf(seq, "\tprevious evt:%s\n",
		   csio_hw_evt_name(hw->prev_evt) ?
		   csio_hw_evt_name(hw->prev_evt) : "None");

	stat = &hw->stats;
	seq_printf(seq, "statistics\n");
	seq_printf(seq, "\tactiveq events: %d\n", stat->n_evt_activeq);
	seq_printf(seq, "\tfreeq events: %d\n", stat->n_evt_freeq);
	seq_printf(seq, "\tdropped events: %d\n", stat->n_evt_drop);
	seq_printf(seq, "\tunexpected events: %d\n", stat->n_evt_unexp);
	seq_printf(seq, "\tunexpected cpl msg: %d\n", stat->n_cpl_unexp);
	seq_printf(seq, "\tpcich offline: %d\n", stat->n_pcich_offline);
	seq_printf(seq, "\tlnlkup miss: %d\n", stat->n_lnlkup_miss);
	seq_printf(seq, "\tcpl fw6 msg: %d\n", stat->n_cpl_fw6_msg);
	seq_printf(seq, "\tcpl fw6 pld: %d\n", stat->n_cpl_fw6_pld);
	seq_printf(seq, "\tplint unexp: %d\n", stat->n_plint_unexp);
	seq_printf(seq, "\tplint cnt: %d\n", stat->n_plint_cnt);
	seq_printf(seq, "\tstray int: %d\n", stat->n_int_stray);
	seq_printf(seq, "\terr: %d\n", stat->n_err);
	seq_printf(seq, "\terr fatal: %d\n", stat->n_err_fatal);
	seq_printf(seq, "\terr nomem: %d\n", stat->n_err_nomem);
	seq_printf(seq, "\terr io: %d\n", stat->n_err_io);

	seq_printf(seq, "sm events stats\n");
	for (ii=CSIO_HWE_CFG; ii < CSIO_HWE_MAX; ii++) {
		seq_printf(seq, "\t%s: %d\n", csio_hw_evt_name(ii),
			stat->n_evt_sm[ii]);
	}	
	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(hw_stat);

static int sge_q_show(struct seq_file *seq, void *v)
{
	struct csio_os_hw *oshw = csio_adap_to_oshw((struct adapter *)seq->private);
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_wrm *wrm = csio_hw_to_wrm(hw);
	struct csio_q   *q;
	struct csio_dma_buf	*buf;
	int i,j;

	seq_printf(seq, "Num sge queues: %d\n", wrm->free_qidx);
	for (i = 0; i < wrm->free_qidx; i++) {
		q = wrm->q_arr[i];
		seq_printf(seq, "qidx: %d\n", i);
		seq_printf(seq, "pidx: %d\n", q->pidx);
		seq_printf(seq, "cidx: %d\n", q->cidx);
		seq_printf(seq, "base addr: %p\n", q->vstart);
		seq_printf(seq, "qsize: %d\n", q->size);
		seq_printf(seq, "inc idx: %d\n", q->inc_idx);
		seq_printf(seq, "wr size: %d\n", q->wr_sz);
		seq_printf(seq, "credits: %d\n", q->credits);

		if (q->type == CSIO_INGRESS) {
			struct csio_iq *iq;
			seq_printf(seq, "qtype: INGRESS\n");
			iq = &q->un.iq;
			seq_printf(seq, "iqid: %d\n", iq->iqid);
			seq_printf(seq, "phy iqid: %d\n", iq->physiqid);
			seq_printf(seq, "genbit: %d\n", iq->genbit);
			seq_printf(seq, "flq idx: %d\n", iq->flq_idx);
		}	
		else if (q->type == CSIO_EGRESS) {
			struct csio_eq *eq;
			seq_printf(seq, "qtype: EGRESS\n");
			eq = &q->un.eq;
			seq_printf(seq, "eqid: %d\n", eq->eqid);
			seq_printf(seq, "phy eqid: %d\n", eq->physeqid);
			seq_printf(seq, "aqid: %d\n", eq->aqid);
		}	
		else if (q->type == CSIO_FREELIST) {
			struct csio_fl *flq;
			seq_printf(seq, "qtype: FREELIST\n");
			flq = &q->un.fl;
			seq_printf(seq, "flqid: %d\n", flq->flid);
			seq_printf(seq, "packen: %d\n", flq->packen);
			seq_printf(seq, "offset: %d\n", flq->offset);
			seq_printf(seq, "sreg: %d\n", flq->sreg);
			if (!q->un.fl.bufs)
				continue;
			for (j = 0; j < q->credits; j++) {
				buf = &q->un.fl.bufs[j];
				if (!buf->vaddr)
					continue;
				seq_printf(seq, "flbuf[%d]:%p len:%d\n", j,
					buf->vaddr, buf->len);
			}
		}	
		else
			seq_printf(seq, "qtype: UNKNOWN\n");
		seq_printf(seq, "stats: \n");
		seq_printf(seq, "\t qentries: %d\n", q->stats.n_qentry);
		seq_printf(seq, "\t qempty: %d\n", q->stats.n_qempty);
		seq_printf(seq, "\t qfull: %d\n", q->stats.n_qfull);
		seq_printf(seq, "\t qwrap: %d\n", q->stats.n_qwrap);
		seq_printf(seq, "\t n_tot_reqs: %d\n", q->stats.n_tot_reqs);
		seq_printf(seq, "\t eq_wr_split: %d\n", q->stats.n_eq_wr_split);
		seq_printf(seq, "\t n_tot_rsps: %d\n", q->stats.n_tot_rsps);
		seq_printf(seq, "\t rsp_unknown: %d\n", q->stats.n_rsp_unknown);
		seq_printf(seq, "\t stray_comp: %d\n", q->stats.n_stray_comp);
		seq_printf(seq, "\t flq_refill: %d\n", q->stats.n_flq_refill);
	}	
	return 0;
}

DEFINE_SIMPLE_DEBUGFS_FILE(sge_q);

static int sge_qentry_show(struct seq_file *seq, void *v, int idx)
{
	const u32 *p = v;

	seq_printf(seq, "%#06x: %08x %08x %08x %08x\n", idx * 16,
		cpu_to_be32(p[0]), cpu_to_be32(p[1]),
		cpu_to_be32(p[2]), cpu_to_be32(p[3]));
	return 0;
}

static int set_qidx;
static int sge_qentry_open(struct inode *inode, struct file *file)
{
	struct seq_tab *p;
	struct adapter *adap = (struct adapter *)inode->i_private;
	struct csio_hw *hw = csio_oshw_to_hw(csio_adap_to_oshw(adap));
	struct csio_wrm *wrm = csio_hw_to_wrm(hw);
	struct csio_q   *q;
	size_t sz;

	if (set_qidx >= wrm->num_q || set_qidx < 0)
		return -EINVAL;

	q = wrm->q_arr[set_qidx];
	sz = q->size / (4 * sizeof(u32));
	p = seq_open_tab(file, sz, 4 * sizeof(u32), 0,
			 sge_qentry_show);
	if (!p)
		return -ENOMEM;

	memcpy(p->data, q->vstart, q->size);
	return 0;
}

static ssize_t sge_qentry_write(struct file *file, const char __user *buf,
			  size_t count, loff_t *pos)
{
	int data;
	char c = '\n', s[256];
	struct csio_hw *hw;
	struct csio_wrm *wrm;
	const struct inode *ino;
	struct adapter *adap;
	struct csio_os_hw *oshw;

	if (count > sizeof(s) - 1 || !count)
		return -EINVAL;
	if (copy_from_user(s, buf, count))
		return -EFAULT;
	s[count] = '\0';

	if (sscanf(s, "%d %c", &data, &c) < 1 || c != '\n')
		return -EINVAL;

	ino = FILE_DATA(file);
	adap = ino->i_private;
	oshw = csio_adap_to_oshw(adap);
	hw = csio_oshw_to_hw(oshw);
	wrm = csio_hw_to_wrm(hw);
	if (data >= wrm->num_q || data < 0)
		return -EINVAL;
	set_qidx = data;
	return count;
}

static const struct file_operations sge_qentry_fops = {
	.owner   = THIS_MODULE,
	.open    = sge_qentry_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.write   = sge_qentry_write,
	.release = seq_release_private
};

static int vaddr_show(struct seq_file *seq, void *v, int idx)
{
	const u32 *p = v;

	seq_printf(seq, "%#06x: %08x %08x %08x %08x\n", idx * 16,
		cpu_to_be32(p[0]), cpu_to_be32(p[1]),
		cpu_to_be32(p[2]), cpu_to_be32(p[3]));
	return 0;
}

static void *csio_vaddr = NULL;
static int vsize = 0;
static int vaddr_open(struct inode *inode, struct file *file)
{
	struct seq_tab *p;
	size_t sz;


	sz = vsize / (4 * sizeof(u32));
	p = seq_open_tab(file, sz, 4 * sizeof(u32), 0,
			 vaddr_show);
	if (!p)
		return -ENOMEM;

	if (csio_vaddr)	
		memcpy(p->data, csio_vaddr, vsize);
	return 0;
}

static ssize_t vaddr_write(struct file *file, const char __user *buf,
			  size_t count, loff_t *pos)
{
	unsigned long long data1;
	int data2;
	char c = '\n', s[256];

	if (count > sizeof(s) - 1 || !count)
		return -EINVAL;
	if (copy_from_user(s, buf, count))
		return -EFAULT;
	s[count] = '\0';

	if (sscanf(s, "%llx %d %c", &data1, &data2, &c) < 2 || c != '\n')
		return -EINVAL;

	csio_vaddr = (void *) ((uintptr_t) data1);
	vsize = data2;
	return count;
}
static const struct file_operations vaddr_fops = {
	.owner   = THIS_MODULE,
	.open    = vaddr_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.write   = vaddr_write,
	.release = seq_release_private
};

#ifdef __CSIO_SCSI_PERF__
static int scsi_perf_show(struct seq_file *seq, void *v)
{
	struct csio_os_hw *oshw = csio_adap_to_oshw((struct adapter *)seq->private);
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_scsim *scsim = csio_hw_to_scsim(hw);
	struct csio_scsi_stats *stats = &scsim->stats;
	int64_t iops, bw;
	
	if (!stats->saved_delta_secs)
		return -EINVAL;

	/* NOTE: Use do_div instead of direct division to work on 32-bit */
	/* NOTE: do_div replaces the dividend in-place with the quotient */
	iops = stats->saved_reads + stats->saved_writes;
	do_div(iops, stats->saved_delta_secs);

	bw = stats->saved_rbytes + stats->saved_wbytes;
	do_div(bw, stats->saved_delta_secs);
	bw = bw * 8; 		/* bits per sec */	
	do_div(bw, 1000000000);	/* Gigabits per sec */

	seq_printf(seq, "\tSample time(secs): %lld\n", stats->saved_delta_secs);
	seq_printf(seq, "\tNum Reads: %lld\n", stats->saved_reads);
	seq_printf(seq, "\tNum Writes: %lld\n", stats->saved_writes);
	seq_printf(seq, "\tNum Read bytes: %lld\n", stats->saved_rbytes);
	seq_printf(seq, "\tNum Write bytes: %lld\n", stats->saved_wbytes);
	/* printk cannot print floating point numbers */
	seq_printf(seq, "\tIOPS: %lld\n", iops);
	seq_printf(seq, "\tBandwidth (Gbps): %lld\n", bw);

	return 0;
}

static int scsi_perf_open(struct inode *inode, struct file *file)
{
	return single_open(file, scsi_perf_show, inode->i_private);
}

static ssize_t scsi_perf_write(struct file *file, const char __user *buf,
			  size_t count, loff_t *pos)
{
	struct timespec ts;
	__kernel_time_t sec;
	int data;
	char c = '\n', s[256];
	struct csio_hw *hw;
	struct csio_scsim *scsim;
	const struct inode *ino;
	struct adapter *adap;
	struct csio_os_hw *oshw;
	struct csio_scsi_stats  *stats;

	if (count > sizeof(s) - 1 || !count)
		return -EINVAL;
	if (copy_from_user(s, buf, count))
		return -EFAULT;
	s[count] = '\0';

	if (sscanf(s, "%d %c", &data, &c) < 1 || c != '\n')
		return -EINVAL;

	ino = FILE_DATA(file);
	if (data != 1)
		return -EINVAL;

	adap = ino->i_private;
	oshw = csio_adap_to_oshw(adap);
	hw = csio_oshw_to_hw(oshw);
	scsim = csio_hw_to_scsim(hw);
	stats = &scsim->stats;

	/*
	 * NOTE: Since we read the clock before we spin on hw_lock, the
	 * time of day at which we actually start the test may not be the most
	 * accurate.
	 */
	getnstimeofday(&ts);
	sec = ts.tv_sec;

	csio_spin_lock_irq(hw, &hw->lock);
	stats->saved_rbytes = stats->rbytes;
	stats->saved_wbytes = stats->wbytes;
	stats->saved_reads = stats->reads;
	stats->saved_writes = stats->writes;
	stats->saved_delta_secs = sec - stats->start_sec;
	stats->start_sec = sec;
	stats->rbytes = 0;
	stats->wbytes = 0;
	stats->reads = 0;
	stats->writes = 0;
	csio_spin_unlock_irq(hw, &hw->lock);

	return count;
}

static const struct file_operations scsi_perf_fops = {
	.owner   = THIS_MODULE,
	.open    = scsi_perf_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.write   = scsi_perf_write,
	.release = single_release
};
#endif /* __CSIO_SCSI_PERF__ */

#ifdef __CSIO_TARGET__

static int
csio_tgt_stats_show(struct seq_file *seq, void *v)
{
	struct csio_os_hw *oshw = csio_adap_to_oshw((struct adapter *)seq->private);
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_tgtm *tgtm = csio_hw_to_tgtm(hw);
	struct csio_tgtm_stats *stats = &tgtm->stats;;

	seq_printf(seq, "Target Module Statistics:\n");
	seq_printf(seq, "\tGood completions: %lld\n", stats->n_good_cmpl);
	seq_printf(seq, "\tAR read completions: %lld\n", stats->n_ar_reads);
	seq_printf(seq, "\tMax outstanding I/Os reached: %d\n",
		   stats->n_max_active);
	seq_printf(seq, "\tNo. of I/Os Aborted at SAL: %d\n",
		   stats->n_abrtd_sal);
	seq_printf(seq, "\tNo. of I/Os Aborted at FW: %d\n",
		   stats->n_abrtd_fw);
	seq_printf(seq, "\tNo. of Closed I/Os: %d\n", stats->n_closed);
	seq_printf(seq, "\tNo. of LUN resets: %d\n", stats->n_lun_rst);
	seq_printf(seq, "\tNo. of target resets: %d\n", stats->n_tgt_rst);
	seq_printf(seq, "\tNo. of out-of-request drops: %d\n",
		   stats->n_drop_no_reqs);
	seq_printf(seq, "\tNo. of unsol abort misses: %d\n",
		   stats->n_un_abrt_miss);
	seq_printf(seq, "\tNo. of link down errors: %d\n",
		   stats->n_err_link_down);
	seq_printf(seq, "\tNo. of rdev-not-ready errors: %d\n",
		   stats->n_err_rdev_not_rdy);
	seq_printf(seq, "\tNo. of rdev lost errors: %d\n",
		   stats->n_err_rdev_lost);
	seq_printf(seq, "\tNo. of rdev logo errors: %d\n",
		   stats->n_err_rdev_logo);
	seq_printf(seq, "\tNo. of rdev implied logo errors: %d\n",
		   stats->n_err_rdev_impl_logo);
	seq_printf(seq, "\tNo. of SAL SCSI response errors: %d\n",
		   stats->n_err_sal_rsp);

	seq_printf(seq, "Target Module Counters:\n");
	seq_printf(seq, "\tNo. of Active I/Os: %d\n", stats->n_active);
	seq_printf(seq, "\tNo. of I/Os being drained: %d\n",
		   stats->n_draining);
	seq_printf(seq, "\tNo. of I/Os in freelist: %d\n",
		   stats->n_free_tgtreq);

	return 0;
}

static int
csio_tgt_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, csio_tgt_stats_show, inode->i_private);
}

static ssize_t
csio_tgt_stats_clear(struct file *file, const char __user *buf,
		     size_t count, loff_t *pos)
{
	int data;
	char c = '\n', s[256];
	struct csio_hw *hw;
	struct csio_tgtm *tgtm;
	const struct inode *ino;
	struct adapter *adap;
	struct csio_os_hw *oshw;
	struct csio_tgtm_stats *stats;

	if (count > sizeof(s) - 1 || !count)
		return -EINVAL;
	if (copy_from_user(s, buf, count))
		return -EFAULT;
	s[count] = '\0';

	if (sscanf(s, "%d %c", &data, &c) < 1 || c != '\n')
		return -EINVAL;

	ino = file->f_path.dentry->d_inode;
	if (data != 1)
		return -EINVAL;

	adap = ino->i_private;
	oshw = csio_adap_to_oshw(adap);
	hw = csio_oshw_to_hw(oshw);
	tgtm = csio_hw_to_tgtm(hw);
	stats = &tgtm->stats;

	stats->n_good_cmpl = 0;
	stats->n_ar_reads = 0;
	stats->n_max_active = 0;
	stats->n_abrtd_sal = 0;
	stats->n_abrtd_fw = 0;
	stats->n_closed = 0;
	stats->n_lun_rst = 0;
	stats->n_tgt_rst = 0;
	stats->n_drop_no_reqs = 0;
	stats->n_un_abrt_miss = 0;
	stats->n_err_link_down = 0;
	stats->n_err_rdev_not_rdy = 0;
	stats->n_err_rdev_lost = 0;
	stats->n_err_rdev_logo = 0;
	stats->n_err_sal_rsp = 0;
	stats->n_err_rdev_impl_logo = 0;

	return count;
}

static const struct file_operations csio_tgt_stats_fops = {
	.owner   = THIS_MODULE,
	.open    = csio_tgt_stats_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write   = csio_tgt_stats_clear
};

#endif /* __CSIO_TARGET__ */

static int csio_setup_debugfs(struct csio_os_hw *oshw)
{

	/*
	 * Debug FS nodes common to all T4 and later adapters.
	 */
	static struct t4_linux_debugfs_entry csio_t4_debugfs_files[] = {
		{ "trace_buf", &trace_buf_fops, S_IRUSR, 0 },
		{ "hw", &hw_debugfs_fops, S_IRUSR, 0 },
		{ "hw_stats", &hw_stat_debugfs_fops, S_IRUSR, 0 },
		{ "sge_queues", &sge_q_debugfs_fops, S_IRUSR, 0 },
		{ "sge_queue_entry", &sge_qentry_fops, S_IRUSR | S_IWUSR, 0 },
		{ "dump_vaddr", &vaddr_fops, S_IRUSR | S_IWUSR, 0 },
	};

	static struct t4_linux_debugfs_entry fcoe_debugfs_files[] = {
		{ "fcfs", &fcf_debugfs_fops, S_IRUSR, 0 },
		{ "lnodes", &lnode_debugfs_fops, S_IRUSR, 0 },
		{ "rnodes", &rnode_debugfs_fops, S_IRUSR, 0 },
		{ "lnodes_stats", &lnode_stat_debugfs_fops, S_IRUSR, 0 },
		{ "rnodes_stats", &rnode_stat_debugfs_fops, S_IRUSR, 0 },
	};

#ifdef __CSIO_FOISCSI_ENABLED__
	static struct t4_linux_debugfs_entry iscsi_debugfs_files[] = {
		{ "iscsi_sessions", &isession_debugfs_fops, S_IRUSR, 0 },
	};
#endif
#ifdef __CSIO_TARGET__
	static struct t4_linux_debugfs_entry tgt_debugfs_files[] = {
		{ "tgt_stats", &csio_tgt_stats_fops, S_IRUSR | S_IWUSR, 0 },
	};
#endif

#ifdef __CSIO_SCSI_PERF__
	static struct t4_linux_debugfs_entry perf_debugfs_files[] = {
		{ "scsi_perf", &scsi_perf_fops, S_IRUSR | S_IWUSR, 0 },
	};
#endif

#ifdef CSIO_DATA_CAPTURE
	 static struct t4_linux_debugfs_entry dcap_debugfs_files[] = {
		{ "dcap_buf", &dcap_buf_fops, S_IRUSR, 0 },
	};
#endif

	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct adapter *adap = csio_oshw_to_adap(oshw);

	if (setup_debugfs(adap))
		return -1;

	add_debugfs_files(adap,
			  csio_t4_debugfs_files,
			  ARRAY_SIZE(csio_t4_debugfs_files));

	if (!csio_is_iscsi(hw))
		add_debugfs_files(adap,
				  fcoe_debugfs_files,
				  ARRAY_SIZE(fcoe_debugfs_files));

#ifdef __CSIO_FOISCSI_ENABLED__
	if (!csio_is_fcoe(hw))
		add_debugfs_files(adap,
				  iscsi_debugfs_files,
				  ARRAY_SIZE(iscsi_debugfs_files));
#endif

#ifdef __CSIO_TARGET__
	add_debugfs_files(adap,
			  tgt_debugfs_files,
			  ARRAY_SIZE(tgt_debugfs_files));
#endif

#ifdef __CSIO_SCSI_PERF__
	add_debugfs_files(adap,
			  perf_debugfs_files,
			  ARRAY_SIZE(perf_debugfs_files));
#endif

#ifdef CSIO_DATA_CAPTURE
	add_debugfs_files(adap,
			  dcap_debugfs_files,
			  ARRAY_SIZE(dcap_debugfs_files));
#endif

	return 0;
}

/**
 * csio_osdfs_create Creates debug filesystem and proc fs for the given HW.
 *
 */
int __devinit csio_osdfs_create(struct csio_os_hw *oshw)
{
	 if (cstor_debugfs_root) {
		csio_oshw_to_adap(oshw)->debugfs_root = debugfs_create_dir(pci_name(oshw->pdev),
				    	cstor_debugfs_root);
		csio_setup_debugfs(oshw);
	}

	return 0;
}

/**
 * csio_osdfs_destroy - Deletes debugfs and procfs entries for the given HW.
 *
 */
int
csio_osdfs_destroy(struct csio_os_hw *oshw)
{
	struct adapter *adap = csio_oshw_to_adap(oshw);

	if (adap->debugfs_root) {
		if (adap->dma_virt) {
			dma_free_coherent(&oshw->pdev->dev, DMABUF_SZ,
				  adap->dma_virt, adap->dma_phys);
			csio_dbg(&oshw->hw, "DMA FREED at bus address %#llx, "
					"virtual 0x%p\n",
				(unsigned long long)adap->dma_phys,
				 adap->dma_virt);

			adap->dma_virt = NULL;
			adap->dma_phys = 0;
		}
		debugfs_remove_recursive(adap->debugfs_root);
	}
	return 0;
}

/**
 * csio_osdfs_init - Debug filesystem initialization.
 *
 * This is function is called during driver load to initialize debugfs, procfs
 * used for debugging.
 */
int
csio_osdfs_init(void)
{
#ifndef pr_warn
#define pr_warn pr_warning
#endif
	/* Debugfs support is optional, just warn if this fails */
	cstor_debugfs_root = debugfs_create_dir(DRV_NAME, NULL);
	if (!cstor_debugfs_root)
		pr_warn(DRV_NAME
			": could not create debugfs entry, continuing\n");

	return 0;
}

/**
 * csio_osdfs_exit - Cleans up debugfs and  procfs created during driver load.
 * Function that gets called in the unload path.
 */
void
csio_osdfs_exit(void)
{
	debugfs_remove(cstor_debugfs_root);
	return;
}
