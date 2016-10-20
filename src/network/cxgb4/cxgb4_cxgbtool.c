/*
 *  Copyright (C) 2008-2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 */
#include "common.h"
#include "cxgbtool.h"
#include "cxgb4_cxgbtool.h"
#include "cxgb4_filter.h"
#include "t4_regs.h"

#ifdef CONFIG_CHELSIO_T4_OFFLOAD

#define ERR(fmt, ...) do {\
	printk(KERN_ERR "%s: " fmt "\n", dev->name, ## __VA_ARGS__); \
	return -EINVAL; \
} while (0)

/*
 * Perform device independent validation of offload policy.
 */
static int validate_offload_policy(const struct net_device *dev,
				   const struct ofld_policy_file *f,
				   size_t len)
{
	int i, inst;
	const u32 *p;
	const struct ofld_prog_inst *pi;

	/*
	 * We validate the following:
	 * - Program sizes match what's in the header
	 * - Branch targets are within the program
	 * - Offsets do not step outside struct offload_req
	 * - Outputs are valid
	 */
	printk(KERN_DEBUG "version %u, program length %zu bytes, alternate "
	       "program length %zu bytes\n", f->vers,
	       f->prog_size * sizeof(*pi), f->opt_prog_size * sizeof(*p));

	if (sizeof(*f) + (f->nrules + 1) * sizeof(struct offload_settings) +
	    f->prog_size * sizeof(*pi) + f->opt_prog_size * sizeof(*p) != len)
		ERR("bad offload policy length %zu", len);

	if (f->output_everything >= 0 && f->output_everything > f->nrules)
		ERR("illegal output_everything %d in header",
		    f->output_everything);

	pi = f->prog;

	for (i = 0; i < f->prog_size; i++, pi++) {
		if (pi->offset < 0 ||
		    pi->offset >= sizeof(struct offload_req) / 4)
			ERR("illegal offset %d at instruction %d", pi->offset,
			    i);
		if (pi->next[0] < 0 && -pi->next[0] > f->nrules)
			ERR("illegal output %d at instruction %d",
			    -pi->next[0], i);
		if (pi->next[1] < 0 && -pi->next[1] > f->nrules)
			ERR("illegal output %d at instruction %d",
			    -pi->next[1], i);
		if (pi->next[0] > 0 && pi->next[0] >= f->prog_size)
			ERR("illegal branch target %d at instruction %d",
			    pi->next[0], i);
		if (pi->next[1] > 0 && pi->next[1] >= f->prog_size)
			ERR("illegal branch target %d at instruction %d",
			    pi->next[1], i);
	}

	p = (const u32 *)pi;

	for (inst = i = 0; i < f->opt_prog_size; inst++) {
		unsigned int off = *p & 0xffff, nvals = *p >> 16;

		if (off >= sizeof(struct offload_req) / 4)
			ERR("illegal offset %u at opt instruction %d",
			    off, inst);
		if ((int32_t)p[1] < 0 && -p[1] > f->nrules)
			ERR("illegal output %d at opt instruction %d",
			    -p[1], inst);
		if ((int32_t)p[2] < 0 && -p[2] > f->nrules)
			ERR("illegal output %d at opt instruction %d",
			    -p[2], inst);
		if ((int32_t)p[1] > 0 && p[1] >= f->opt_prog_size)
			ERR("illegal branch target %d at opt instruction %d",
			    p[1], inst);
		if ((int32_t)p[2] > 0 && p[2] >= f->opt_prog_size)
			ERR("illegal branch target %d at opt instruction %d",
			    p[2], inst);
		p += 4 + nvals;
		i += 4 + nvals;
		if (i > f->opt_prog_size)
			ERR("too many values %u for opt instruction %d",
			    nvals, inst);
	}

	return 0;
}

#undef ERR

static int validate_policy_settings(const struct net_device *dev,
				    struct adapter *adap,
				    const struct ofld_policy_file *f)
{
	int i;
	const u32 *op = (const u32 *)&f->prog[f->prog_size];
	const struct offload_settings *s = (void *)&op[f->opt_prog_size];

	for (i = 0; i <= f->nrules; i++, s++) {
		if (s->cong_algo > 3) {
			printk(KERN_ERR "%s: illegal congestion algorithm %d\n",
			       dev->name, s->cong_algo);
			return -EINVAL;
		}
		if (s->rssq >= adap->sge.ofldqsets) {
			printk(KERN_ERR "%s: illegal RSS queue %d\n", dev->name,
			       s->rssq);
			return -EINVAL;
		}
		if (s->sched_class >= 0 &&
		    s->sched_class >= adap->params.nsched_cls) {
			printk(KERN_ERR "%s: illegal scheduling class %d\n",
			       dev->name, s->sched_class);
			return -EINVAL;
		}
	}
	return 0;
}
#endif

/* clear port-related stats maintained by the port's associated queues */
static void clear_sge_port_stats(struct adapter *adap, struct port_info *p)
{
	int i;
	struct sge_eth_txq *tx = &adap->sge.ethtxq[p->first_qset];
	struct sge_eth_rxq *rx = &adap->sge.ethrxq[p->first_qset];

	for (i = 0; i < p->nqsets; i++, rx++, tx++) {
		memset(&rx->stats, 0, sizeof(rx->stats));
		tx->tso = 0;
		tx->tx_cso = 0;
		tx->vlan_ins = 0;
		tx->coal_wr = 0;
		tx->coal_pkts = 0;
		rx->stats.lro_pkts = 0;
		rx->stats.lro_merged = 0;
	}
}

/* clear statistics for the given Ethernet Tx and Rx queues */
static void clear_ethq_stats(struct sge *p, unsigned int idx)
{
	struct sge_eth_rxq *rxq = &p->ethrxq[idx];
	struct sge_eth_txq *txq = &p->ethtxq[idx];

	memset(&rxq->stats, 0, sizeof(rxq->stats));
	rxq->fl.alloc_failed = rxq->fl.large_alloc_failed = 0;
	rxq->fl.starving = 0;

	txq->tso = txq->tx_cso = txq->vlan_ins = 0;
	txq->q.stops = txq->q.restarts = 0;
	txq->mapping_err = 0;
}

/* clear statistics for the Ethernet queues associated with the given port */
static void clear_port_qstats(struct adapter *adap, const struct port_info *pi)
{
	int i;

	for (i = 0; i < pi->nqsets; i++)
		clear_ethq_stats(&adap->sge, pi->first_qset + i);
}

/**
 *	t4_get_desc - dump an SGE descriptor for debugging purposes
 *	@p: points to the sge structure for the adapter
 *	@category: the type of queue
 *	@qid: the absolute SGE QID of the specific queue within the category
 *	@idx: the descriptor index in the queue
 *	@data: where to dump the descriptor contents
 *
 *	Dumps the contents of a HW descriptor of an SGE queue.  Returns the
 *	size of the descriptor or a negative error.
 */
static int get_qdesc(const struct sge *p, int category, unsigned int qid,
		     unsigned int idx, unsigned char *data)
{
	int i, len = sizeof(struct tx_desc);

	/*
	 * For Tx queues allow reading the status entry too.
	 */
	if (category == SGE_QTYPE_TX_ETH) {
		const struct sge_eth_txq *q = p->ethtxq;

		for (i = 0; i < ARRAY_SIZE(p->ethtxq); i++, q++)
			if (q->q.cntxt_id == qid && q->q.desc &&
			    idx <= q->q.size) {
				memcpy(data, &q->q.desc[idx], len);
				return len;
			}
	}
	if (category == SGE_QTYPE_TX_OFLD) {
		const struct sge_ofld_txq *q = p->ofldtxq;

		for (i = 0; i < ARRAY_SIZE(p->ofldtxq); i++, q++)
			if (q->q.cntxt_id == qid && q->q.desc &&
			    idx <= q->q.size) {
				memcpy(data, &q->q.desc[idx], len);
				return len;
			}
	}
	if (category == SGE_QTYPE_TX_CTRL) {
		const struct sge_ctrl_txq *q = p->ctrlq;

		for (i = 0; i < ARRAY_SIZE(p->ctrlq); i++, q++)
			if (q->q.cntxt_id == qid && q->q.desc &&
			    idx <= q->q.size) {
				memcpy(data, &q->q.desc[idx], len);
				return len;
			}
	}
	if (category == SGE_QTYPE_FL) {
		const struct sge_fl *q = NULL;

		if (qid < p->egr_start + p->egr_sz)
			q = p->egr_map[qid - p->egr_start];
		if (q && q >= &p->ethrxq[0].fl && idx < q->size) {
			*(__be64 *)data = q->desc[idx];
			return sizeof(u64);
		}
	}
	if (category == SGE_QTYPE_RSP) {
		const struct sge_rspq *q = NULL;

		if (qid < p->ingr_start + p->ingr_sz)
			q = p->ingr_map[qid - p->ingr_start];
		if (q && idx < q->size) {
			len = q->iqe_len;
			idx *= len / sizeof(u64);
			memcpy(data, &q->desc[idx], len);
			return len;
		}
	}
	return -EINVAL;
}

/*
 * Retrieve a list of bypass ports.
 */
static int get_bypass_ports(struct adapter *adapter, 
				struct ch_bypass_ports *cba)
{
	const struct net_device *dev;
	int i = 0;

	for_each_port(adapter, i) {
		dev = adapter->port[i];
		strncpy(cba->ba_if[i].if_name, dev->name, IFNAMSIZ);
	}
	cba->port_count = adapter->params.nports;

	return 0;
}

/*
 *  Helper function to set Ethernet Queue Sets
 */
static int set_eth_qsets(struct net_device *dev, int nqueues)
{

	struct adapter *adapter = netdev2adap(dev);
	struct port_info *pi = netdev_priv(dev);
	int port, first_qset, other_queues, ncpus;

	/*
	 * Check legitimate range for number of Queue Sets.  We need
	 * at least one Queue Set and we can't have more that
	 * max_eth_qsets.  (Note that the incoming value from User
	 * Space is an unsigned 32-bit value.  Since that includes
	 * 0xffff == (u32)-1, if we depend solely on the test below
	 * for "edata.val + other_qsets > adapter->sge.max_ethqsets",
	 * then we'll miss such bad values because of wrap-around
	 * arithmetic.)
	 */
	if (nqueues < 1 || nqueues > adapter->sge.max_ethqsets)
		return -EINVAL;

	/*
	 * For Ethernet Queue Sets, it doesn't make sense to have more than
	 * the number of CPUs.
	 */
	ncpus   = num_online_cpus();
	if (nqueues > ncpus)
		nqueues = ncpus;

	other_queues = adapter->sge.ethqsets - pi->nqsets;
	if (nqueues + other_queues > adapter->sge.max_ethqsets ||
			nqueues > pi->rss_size)
		return -EINVAL;

	pi->nqsets = nqueues;
	netif_set_real_num_tx_queues(dev, pi->nqsets);
	netif_set_real_num_rx_queues(dev, pi->nqsets);
	adapter->sge.ethqsets = other_queues + pi->nqsets;

	first_qset = 0;
	for_each_port(adapter, port)
		if (adapter->port[port]) {
			pi = adap2pinfo(adapter, port);
			pi->first_qset = first_qset;
			first_qset += pi->nqsets;
		}
	return 0;
}


/*
 * Simple predicate to vet incoming Chelsio ioctl() parameters to make sure
 * they are either not set (value < 0) or within the indicated range.
 */
static int in_range(int val, int lo, int hi)
{
	return val < 0 || (val <= hi && val >= lo);
}


int cxgb_extension_ioctl(struct net_device *dev, void __user *useraddr)
{
	int ret;
	u32 cmd;
	struct adapter *adapter = netdev2adap(dev);

	if (copy_from_user(&cmd, useraddr, sizeof(cmd)))
		return -EFAULT;

	switch (cmd) {
	case CHELSIO_SETREG: {
		struct ch_reg edata;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;
		if ((edata.addr & 3) != 0 ||
		    edata.addr >= pci_resource_len(adapter->pdev, 0))
			return -EINVAL;
		writel(edata.val, adapter->regs + edata.addr);
		break;
	}
	case CHELSIO_GETREG: {
		struct ch_reg edata;

		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;
		if ((edata.addr & 3) != 0 ||
		    edata.addr >= pci_resource_len(adapter->pdev, 0))
			return -EINVAL;
		edata.val = readl(adapter->regs + edata.addr);
		if (copy_to_user(useraddr, &edata, sizeof(edata)))
			return -EFAULT;
		break;
	}
	case CHELSIO_GET_I2C_DATA: {
		struct ch_i2c_data edata;
		u8 *i2c_data;

		if (!capable(CAP_SYS_RAWIO))
			return -EPERM;
		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;
		if (!edata.len)
			return -EINVAL;

		i2c_data = t4_alloc_mem(edata.len);
		if (!i2c_data)
			return -ENOMEM;

		ret = t4_i2c_rd(adapter, adapter->mbox,
				(edata.port == ~0 ? -1 : edata.port),
				edata.devid, edata.offset, edata.len,
				i2c_data);
		if (!ret)
			if (copy_to_user(useraddr + sizeof edata,
					 i2c_data, edata.len))
				ret = -EFAULT;

		t4_free_mem(i2c_data);
		break;
	}
	case CHELSIO_SET_I2C_DATA: {
		struct ch_i2c_data edata;
		u8 *i2c_data;

		if (!capable(CAP_SYS_RAWIO))
			return -EPERM;
		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;
		if (!edata.len)
			return -EINVAL;

		i2c_data = t4_alloc_mem(edata.len);
		if (!i2c_data)
			return -ENOMEM;

		if (copy_from_user(i2c_data, useraddr + sizeof edata,
				   edata.len))
			ret = -EFAULT;
		else
			ret = t4_i2c_wr(adapter, adapter->mbox,
					(edata.port == ~0 ? -1 : edata.port),
					edata.devid, edata.offset, edata.len,
					i2c_data);

		t4_free_mem(i2c_data);
		break;
	}
	case CHELSIO_GET_TCB: {
		struct ch_tcb edesc;
		
		if (!capable(CAP_SYS_RAWIO))
			return -EPERM;
		if (copy_from_user(&edesc, useraddr, sizeof(edesc)))
			return -EFAULT;
		if (edesc.tcb_index >= adapter->tids.ntids)
			return -ERANGE;

		spin_lock(&adapter->win0_lock);
		ret = t4_read_tcb(adapter, MEMWIN_NIC, edesc.tcb_index,
				  edesc.tcb_data);
		spin_unlock(&adapter->win0_lock);
		if (ret)
			return ret;

		if (copy_to_user(useraddr, &edesc, sizeof(edesc)))
			return -EFAULT;
		break;
	}
	case CHELSIO_GET_SGE_CTXT: {
		struct ch_mem_range t;
		u32 buf[SGE_CTXT_SIZE / 4];

		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;
		if (t.len < SGE_CTXT_SIZE || t.addr > M_CTXTQID)
			return -EINVAL;

		if (t.mem_id == CNTXT_TYPE_RSP || t.mem_id == CNTXT_TYPE_CQ)
			ret = CTXT_INGRESS;
		else if (t.mem_id == CNTXT_TYPE_EGRESS)
			ret = CTXT_EGRESS;
		else if (t.mem_id == CNTXT_TYPE_FL)
			ret = CTXT_FLM;
		else if (t.mem_id == CNTXT_TYPE_CONG)
			ret = CTXT_CNM;
		else
			return -EINVAL;

		if ((adapter->flags & FW_OK) && !adapter->use_bd)
			ret = t4_sge_ctxt_rd(adapter, adapter->mbox, t.addr,
					     ret, buf);
		else
			ret = t4_sge_ctxt_rd_bd(adapter, t.addr, ret, buf);
		if (ret)
			return ret;

		t.version = mk_adap_vers(adapter);
		if (copy_to_user(useraddr + sizeof(t), buf, SGE_CTXT_SIZE) ||
		    copy_to_user(useraddr, &t, sizeof(t)))
			return -EFAULT;
		break;
	}
	case CHELSIO_GET_SGE_DESC2: {
		unsigned char buf[128];
		struct ch_mem_range edesc;

		if (copy_from_user(&edesc, useraddr, sizeof(edesc)))
			return -EFAULT;
		/*
		 * Upper 8 bits of mem_id is the queue type, the rest the qid.
		 */
		ret = get_qdesc(&adapter->sge, edesc.mem_id >> 24,
				edesc.mem_id & 0xffffff, edesc.addr, buf);
		if (ret < 0)
			return ret;
		if (edesc.len < ret)
			return -EINVAL;

		edesc.len = ret;
		edesc.version = mk_adap_vers(adapter);
		if (copy_to_user(useraddr + sizeof(edesc), buf, edesc.len) ||
		    copy_to_user(useraddr, &edesc, sizeof(edesc)))
			return -EFAULT;
		break;
	}
	case CHELSIO_SET_QSET_PARAMS: {
		struct sge_eth_rxq *rq;
		struct sge_eth_txq *tq;
		struct ch_qset_params t;
		const struct port_info *pi = netdev_priv(dev);

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;
		if (t.qset_idx >= pi->nqsets)
			return -EINVAL;
		if (t.txq_size[1] >= 0 || t.txq_size[2] >= 0 ||
		    t.fl_size[1] >= 0 || t.cong_thres >= 0 || t.polling >= 0)
			return -EINVAL;
		if (//!in_range(t.intr_lat, 0, M_NEWTIMER) ||
		    //!in_range(t.cong_thres, 0, 255) ||
		    !in_range(t.txq_size[0], MIN_TXQ_ENTRIES,
			      MAX_TXQ_ENTRIES) ||
		    !in_range(t.fl_size[0], MIN_FL_ENTRIES, MAX_RX_BUFFERS) ||
		    !in_range(t.rspq_size, MIN_RSPQ_ENTRIES, MAX_RSPQ_ENTRIES))
			return -EINVAL;

		if (t.lro > 0)
			return -EINVAL;

		if ((adapter->flags & FULL_INIT_DONE) &&
		    (t.rspq_size >= 0 || t.fl_size[0] >= 0 ||
		     t.txq_size[0] >= 0))
			return -EBUSY;

		tq = &adapter->sge.ethtxq[t.qset_idx + pi->first_qset];
		rq = &adapter->sge.ethrxq[t.qset_idx + pi->first_qset];

		if (t.rspq_size >= 0)
			rq->rspq.size = t.rspq_size;
		if (t.fl_size[0] >= 0)
			rq->fl.size = t.fl_size[0] + 8; /* need an empty desc */
		if (t.txq_size[0] >= 0)
			tq->q.size = t.txq_size[0];
		if (t.intr_lat >= 0)
			rq->rspq.intr_params =
				(rq->rspq.intr_params &
				 ~V_QINTR_TIMER_IDX(M_QINTR_TIMER_IDX)) |
				V_QINTR_TIMER_IDX(cxgb4_closest_timer(&adapter->sge, t.intr_lat));
		break;
	}
	case CHELSIO_GET_QSET_PARAMS: {
		struct sge_eth_rxq *rq;
		struct sge_eth_txq *tq;
		struct ch_qset_params t;
		const struct port_info *pi = netdev_priv(dev);

		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;
		if (t.qset_idx >= pi->nqsets)
			return -EINVAL;

		tq = &adapter->sge.ethtxq[t.qset_idx + pi->first_qset];
		rq = &adapter->sge.ethrxq[t.qset_idx + pi->first_qset];
		t.rspq_size   = rq->rspq.size;
		t.txq_size[0] = tq->q.size;
		t.txq_size[1] = 0;
		t.txq_size[2] = 0;
		t.fl_size[0]  = rq->fl.size - 8; /* sub unused descriptor */
		t.fl_size[1]  = 0;
		t.polling     = 1;
		t.lro         = ((dev->features & NETIF_F_GRO) != 0);
		t.intr_lat    = qtimer_val(adapter, &rq->rspq);
		t.cong_thres  = 0;

		if (adapter->flags & USING_MSIX)
			t.vector = adapter->msix_info[pi->first_qset +
						      t.qset_idx + 2].vec;
		else
			t.vector = adapter->pdev->irq;

		if (copy_to_user(useraddr, &t, sizeof(t)))
			return -EFAULT;
		break;
	}
	case CHELSIO_SET_QUEUE_INTR_PARAMS: {
		struct ch_queue_intr_params op;
		struct sge_rspq *rq;
		unsigned int cur_us, cur_cnt;
		unsigned int new_us, new_cnt;
		struct sge *s = &adapter->sge;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (copy_from_user(&op, useraddr, sizeof(op)))
			return -EFAULT;
		if (op.qid < s->ingr_start ||
		    op.qid >= s->ingr_start + s->ingr_sz)
			return -EINVAL;
		rq = s->ingr_map[op.qid - s->ingr_start];
		if (rq == NULL)
			return -EINVAL;

		cur_us = qtimer_val(adapter, rq);
		cur_cnt = ((rq->intr_params & F_QINTR_CNT_EN)
			   ? s->counter_val[rq->pktcnt_idx]
			   : 0);

		new_us = op.timer >= 0 ? op.timer : cur_us;
		new_cnt  = op.count >= 0 ? op.count : cur_cnt;
		ret = cxgb4_set_rspq_intr_params(rq, new_us, new_cnt);

		break;

	}
	case CHELSIO_GET_QUEUE_INTR_PARAMS: {
		struct ch_queue_intr_params op;
		struct sge_rspq *rq;
		struct sge *s = &adapter->sge;

		if (copy_from_user(&op, useraddr, sizeof(op)))
			return -EFAULT;
		if (op.qid < s->ingr_start ||
		    op.qid >= s->ingr_start + s->ingr_sz)
			return -EINVAL;
		rq = s->ingr_map[op.qid - s->ingr_start];
		if (rq == NULL)
			return -EINVAL;

		op.timer = qtimer_val(adapter, rq);
		op.count = ((rq->intr_params & F_QINTR_CNT_EN)
			    ? s->counter_val[rq->pktcnt_idx]
			    : 0);
		if (copy_to_user(useraddr, &op, sizeof(op)))
			return -EFAULT;

		break;
	}
#ifndef CONFIG_CXGB4_DCB
	/*
	 * Not allowed to change the number of Ethernet Queue Sets if we're
	 * configured for Data Center Bridging.
	 */
	case CHELSIO_SET_QSET_NUM: {
		struct ch_reg edata;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (adapter->flags & FULL_INIT_DONE)
			return -EBUSY;
		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;

		return set_eth_qsets(dev, edata.val);
	}
#endif /* !CONFIG_CXGB4_DCB */
	case CHELSIO_GET_QSET_NUM: {
		struct ch_reg edata;
		struct port_info *pi = netdev_priv(dev);

		edata.cmd = CHELSIO_GET_QSET_NUM;
		edata.val = pi->nqsets;
		if (copy_to_user(useraddr, &edata, sizeof(edata)))
			return -EFAULT;
		break;
	}
	/* Allow to configure the various Queue Types */
	case CHELSIO_SET_QTYPE_NUM: {
		struct sge *s = &adapter->sge;
		struct ch_qtype_num edata;
		uint16_t qtype_max[QTYPE_MAX]  = {
			[QTYPE_OFLD]  = MAX_OFLD_QSETS,
			[QTYPE_RCIQ]  = MAX_RDMA_CIQS,
			[QTYPE_ISCSI] = MAX_ISCSI_QUEUES
		};
		uint16_t *ofld_qval[QTYPE_MAX] = {
			[QTYPE_OFLD]  = &s->ofldqsets,
			[QTYPE_RDMA]  = &s->rdmaqs,
			[QTYPE_RCIQ]  = &s->rdmaciqs,
			[QTYPE_ISCSI] = &s->niscsiq
		};
		int qpp, nqueues, other_queues, qtype;

		/* RDMA Queues are limited to one per port */
		qtype_max[QTYPE_RDMA] = adapter->params.nports;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (adapter->flags & FULL_INIT_DONE)
			return -EBUSY;
		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;

		/* Sanity chedk for reasonalbe values */
		if (edata.val == 0 || edata.qtype >= QTYPE_MAX)
			return -EINVAL;

		/*
		 * Ethernet Queue Sets have their own rules.  We just like
		 * providing a single API entrance point to allow any type
		 * of queue to be managed ...
		 */
		if (edata.qtype == QTYPE_ETH)
			return set_eth_qsets(dev, edata.val);

		/*
		 * For Offload Ingress Queues, the code assumes that we have
		 * exactly the same number for all ports, so we need to round
		 * the requested value up to a multiple of the number of
		 * ports.  It doesn't really make sense to have more per port
		 * than the number of CPUs, so we silently limit the number of
		 * Offload Queues/Port to nCPUs.
		 */
		qpp = edata.val;
		if (qpp > num_online_cpus())
			qpp = num_online_cpus();
		nqueues = qpp * adapter->params.nports;
		if (nqueues > qtype_max[edata.qtype])
			return -ERANGE;

		for (qtype = 0, other_queues = 0; qtype < QTYPE_MAX; qtype++)
			if (qtype != edata.qtype && qtype != QTYPE_ETH)
				other_queues += *ofld_qval[qtype];

		if (nqueues + other_queues > s->max_ofldqsets)
			return -EINVAL;

		*ofld_qval[edata.qtype] = nqueues;
		return 0;
	}
	case CHELSIO_GET_QTYPE_NUM: {
		struct port_info *pi = netdev_priv(dev);
		struct sge *s = &adapter->sge;
		struct ch_qtype_num edata;
		uint16_t *ofld_qval[QTYPE_MAX] = {
			[QTYPE_ETH]   = &s->ethqsets,
			[QTYPE_OFLD]  = &s->ofldqsets,
			[QTYPE_RDMA]  = &s->rdmaqs,
			[QTYPE_RCIQ]  = &s->rdmaciqs,
			[QTYPE_ISCSI] = &s->niscsiq
		};
		int nports = adapter->params.nports;

		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;
		if (edata.qtype >= QTYPE_MAX)
			return -EINVAL;
		if (edata.qtype == QTYPE_ETH)
			edata.val = pi->nqsets;
		else
			edata.val = *ofld_qval[edata.qtype]/nports;
		if (copy_to_user(useraddr, &edata, sizeof(edata)))
			return -EFAULT;
		break;
	}
	case CHELSIO_LOAD_FW: {
		u8 *fw_data;
		struct ch_mem_range t;
		unsigned int mbox = M_PCIE_FW_MASTER + 1;
		u32 pcie_fw;
		unsigned int master;
		u8 master_vld = 0;

		if (!capable(CAP_SYS_RAWIO))
			return -EPERM;
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;
		if (!t.len)
			return -EINVAL;

		pcie_fw = t4_read_reg(adapter, A_PCIE_FW);
		master = G_PCIE_FW_MASTER(pcie_fw);
		if (pcie_fw & F_PCIE_FW_MASTER_VLD)
			master_vld = 1;
		/* if csiostor is the master return */
		if (master_vld && (master != adapter->pf)) {
			dev_warn(adapter->pdev_dev,
				 "cxgb4 driver needs to be loaded as MASTER to support FW flash\n");
			return -EOPNOTSUPP;
		}

		fw_data = t4_alloc_mem(t.len);
		if (!fw_data)
			return -ENOMEM;

		if (copy_from_user(fw_data, useraddr + sizeof(t), t.len)) {
			t4_free_mem(fw_data);
			return -EFAULT;
		}

		/*
		 * If the adapter has been fully initialized then we'll go
		 * ahead and try to get the firmware's cooperation in
		 * upgrading to the new firmware image otherwise we'll try to
		 * do the entire job from the host ... and we always "force"
		 * the operation in this path.
		 */
		if ((adapter->flags & FULL_INIT_DONE) && fw_attach)
			mbox = adapter->mbox;

		ret = t4_fw_upgrade(adapter, mbox,
				    fw_data, t.len, /*force=*/true);
		t4_free_mem(fw_data);
		if (ret)
			return ret;
		break;
	}
#ifdef CHELSIO_T4_DIAGS
	case CHELSIO_CLEAR_FLASH: {
		ret = t4_erase_sf(adapter);

		if (ret)
			return ret;
		break;
	}
#endif
	case CHELSIO_LOAD_BOOT: {
		u8 *boot_data;
		struct ch_mem_range t;
		unsigned int pcie_pf_exprom_ofst, offset;

		if (!capable(CAP_SYS_RAWIO))
			return -EPERM;
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;

		/*
		 * Check if user selected a valid PF index or offset
		 * mem_id:	type of access 0: PF index, 1: offset
		 * addr: 	pf index or offset
		 */
		if (t.mem_id == 0) {
			/*
			 * Flash boot image to the offset defined by the PFs
			 * EXPROM_OFST defined in the serial configuration file.
			 * Read PCIE_PF_EXPROM_OFST register
		 	 */

			/*
			 * Check PF index
			 */
			if (t.addr > 7 || t.addr < 0) {
				CH_ERR(adapter, "PF index is too small/large\n");
				return EFAULT;
			}

			pcie_pf_exprom_ofst = t4_read_reg(adapter,
					PF_REG(t.addr, A_PCIE_PF_EXPROM_OFST));
			offset = G_OFFSET(pcie_pf_exprom_ofst);

		} else if (t.mem_id == 1) {
			/*
			 * Flash boot image to offset specified by the user.
			 */
			offset = G_OFFSET(t.addr);

		} else
			return -EINVAL;

		/*
		 * If a length of 0 is supplied that implies the desire to
		 * clear the FLASH area associated with the option ROM
		 */
		if (t.len == 0)
			ret = t4_load_boot(adapter, NULL, offset, 0);
		else {
			boot_data = t4_alloc_mem(t.len);
			if (!boot_data)
				return -ENOMEM;

			if (copy_from_user(boot_data, useraddr + sizeof(t),
						t.len)) {
				t4_free_mem(boot_data);
				return -EFAULT;
			}

			ret = t4_load_boot(adapter, boot_data, offset, t.len);
			t4_free_mem(boot_data);
		}
		if (ret)
			return ret;
		break;
	}

	case CHELSIO_LOAD_BOOTCFG: {
		u8 *cfg_data;
		struct struct_load_cfg t;

		if (!capable(CAP_SYS_RAWIO))
			return -EPERM;
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;

		if (t.len == 0)
			ret = t4_load_bootcfg(adapter, NULL, 0);
		else {
			cfg_data = t4_alloc_mem(t.len);
			if (!cfg_data)
				return -ENOMEM;

			if (copy_from_user(cfg_data, useraddr + sizeof(t), t.len)) {
				t4_free_mem(cfg_data);
				return -EFAULT;
			}
			ret = t4_load_bootcfg(adapter, cfg_data, t.len);
			t4_free_mem(cfg_data);
		}	

		if (ret)
			return ret;
		break;
	}

        case CHELSIO_LOAD_CFG: {
                u8 *cfg_data;
		struct struct_load_cfg t;
		

		if (!capable(CAP_SYS_RAWIO))
			return -EPERM;
                if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;

		/*
		 * If a length of 0 is supplied that implies the desire to
		 * clear the FLASH area associated with the Firmware
		 * Configuration File.
		 */
		if (t.len == 0)
			ret = t4_load_cfg(adapter, NULL, 0);
		else {
			cfg_data = t4_alloc_mem(t.len);
			if (!cfg_data)
				return -ENOMEM;

			if (copy_from_user(cfg_data, useraddr + sizeof(t), t.len)) {
				t4_free_mem(cfg_data);
				return -EFAULT;
			}
			ret = t4_load_cfg(adapter, cfg_data, t.len);
			t4_free_mem(cfg_data);
		}
		if (ret)
			return ret;
		break;
        }
#ifdef CHELSIO_T4_DIAGS
	case CHELSIO_LOAD_PHY_FW: {
		u8 *phy_data;
		struct ch_mem_range t;

		if (!capable(CAP_SYS_RAWIO))
			return -EPERM;
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;

		phy_data = t4_alloc_mem(t.len);
		if (!phy_data)
			return -ENOMEM;

		if (copy_from_user(phy_data, useraddr + sizeof(t), t.len)) {
			t4_free_mem(phy_data);
			return -EFAULT;
		}

		/*
		 * Execute loading of PHY firmware.  We have to RESET the
		 * chip/firmware because we need the chip in uninitialized
		 * state for loading new PHY firmware.
		 */
		ret = t4_fw_reset(adapter, adapter->mbox,
				  F_PIORSTMODE | F_PIORST);
		if (!ret)
			ret = t4_load_phy_fw(adapter, MEMWIN_NIC, &adapter->win0_lock,
					     NULL, phy_data, t.len);
		t4_free_mem(phy_data);
		if (ret)
			return ret;
		break;
	}
#endif /* CHELSIO_T4_DIAGS */
	case CHELSIO_SET_FILTER: {
		struct ch_filter t;

		/*
		 * Vet the filter specification against our hardware filter
		 * configuration and capabilities.
		 */

		if (!allow_nonroot_filters && !capable(CAP_NET_ADMIN))
			return -EPERM;
		if (adapter->tids.nftids == 0 ||
		    adapter->tids.ftid_tab == NULL)
			return -EOPNOTSUPP;
		if (!(adapter->flags & FULL_INIT_DONE))
			return -EAGAIN;  /* can still change nfilters */
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;
		if (t.filter_ver != CH_FILTER_SPECIFICATION_ID)
			return -EINVAL;
		if (!t.fs.cap)
			return cxgb4_set_filter(dev, t.filter_id, &t.fs, NULL,
						GFP_KERNEL);
		else {
			struct filter_ctx ctx;
			int ret;

			init_completion(&ctx.completion);

			ret = cxgb4_set_filter(dev, t.filter_id, &t.fs, &ctx,
					       GFP_KERNEL);
			if (!ret) {
				ret = wait_for_completion_timeout(&ctx.completion, 10*HZ);
				if (!ret)
					printk("%s: filter creation timed out\n", __func__);
				else {
					ret = ctx.result;
					t.filter_id = ctx.tid;

					if(copy_to_user(useraddr, &t, sizeof(t)))
						return -EFAULT;
				}
			}
			return ret;
		}
	}
	case CHELSIO_DEL_FILTER: {
		struct ch_filter t;

		if (!allow_nonroot_filters && !capable(CAP_NET_ADMIN))
			return -EPERM;
		if (adapter->tids.nftids == 0 ||
		    adapter->tids.ftid_tab == NULL)
			return -EOPNOTSUPP;
		if (!(adapter->flags & FULL_INIT_DONE))
			return -EAGAIN;  /* can still change nfilters */
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;
		if (t.filter_ver != CH_FILTER_SPECIFICATION_ID)
			return -EINVAL;
		if (!t.fs.cap)
			return cxgb4_del_filter(dev, t.filter_id, &t.fs, NULL,
						GFP_KERNEL);
		else {
			struct filter_ctx ctx;
			int ret;

			init_completion(&ctx.completion);

			ret = cxgb4_del_filter(dev, t.filter_id, &t.fs, &ctx,
					       GFP_KERNEL);
			if (!ret) {
				ret = wait_for_completion_timeout(&ctx.completion, 10*HZ);
				if (!ret)
					printk("%s: filter deletion timed out\n", __func__);
				else
					return ctx.result;
			}
			return ret;
		}
	}
	case CHELSIO_GET_FILTER: {
		struct ch_filter t;
		struct filter_entry *f;

		if (!allow_nonroot_filters && !capable(CAP_NET_ADMIN))
			return -EPERM;
		if (adapter->tids.nftids == 0 ||
		    adapter->tids.ftid_tab == NULL)
			return -EOPNOTSUPP;
		if (!(adapter->flags & FULL_INIT_DONE))
			return -EAGAIN;  /* can still change nfilters */
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;
		if (t.filter_ver != CH_FILTER_SPECIFICATION_ID)
			return -EINVAL;
		if (t.filter_id >= adapter->tids.nftids)
			return -E2BIG;

		f = &adapter->tids.ftid_tab[t.filter_id];
		if (f->pending)
			return -EBUSY;
		if (!f->valid)
			return -ENOENT;

		t.fs = f->fs;
		if (copy_to_user(useraddr, &t, sizeof(t)))
			return -EFAULT;
		break;
	}
	case CHELSIO_GET_FILTER_COUNT: {
		struct ch_filter_count count;

		if (copy_from_user(&count, useraddr, sizeof(count)))
			return -EFAULT;
		if (adapter->tids.nftids == 0 ||
		    adapter->tids.ftid_tab == NULL)
			return -EOPNOTSUPP;
		if (!(adapter->flags & FULL_INIT_DONE))
			return -EAGAIN;  /* can still change nfilters */

		if (count.filter_id >= adapter->tids.nftids)
			return -E2BIG;

		ret = cxgb4_get_filter_count(adapter, count.filter_id,
				       &count.pkt_count, 0);

		if (copy_to_user(useraddr, &count, sizeof(count)))
			return -EFAULT;
		break;
	}
	case CHELSIO_GET_BYPASS_PORTS: {
		struct ch_bypass_ports cbp;

		if (!is_bypass(adapter))
			return -EINVAL;

		get_bypass_ports(adapter, &cbp);

		if (copy_to_user(useraddr, &cbp, sizeof(cbp)))
			return -EFAULT;
		break;
	}
	case CHELSIO_CLEAR_STATS: {
		struct ch_reg edata;
		struct port_info *pi = netdev_priv(dev);

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (copy_from_user(&edata, useraddr, sizeof(edata)))
			return -EFAULT;
		if ((edata.val & STATS_QUEUE) && edata.addr != -1 &&
		    edata.addr >= pi->nqsets)
			return -EINVAL;
		if (edata.val & STATS_PORT) {
			/*
			 * T4 can't reliably clear its statistics registers
			 * while traffic is running, so we just snapshot the
			 * statistics registers and then subtract off this
			 * Base Offset for future statistics reports ...
			 */
			if (is_t4(adapter->params.chip))
				t4_get_port_stats(adapter, pi->tx_chan,
						  &pi->stats_base);
			else
				t4_clr_port_stats(adapter, pi->tx_chan);
			clear_sge_port_stats(adapter, pi);

			/*
			 * For T5 and later we also want to clear out any SGE
			 * statistics which may be being gathered ...
			 */
			if (!is_t4(adapter->params.chip)) {
				u32 cfg = t4_read_reg(adapter, A_SGE_STAT_CFG);
				t4_write_reg(adapter, A_SGE_STAT_CFG, 0);
				t4_write_reg(adapter, A_SGE_STAT_CFG, cfg);
			}

			/*
			 * Snapshot new base for various statistics registers
			 * which are either difficult or impossible to clear
			 * while the adapter/traffic is running ...
			 */
			t4_tp_get_cpl_stats(adapter, &adapter->tp_cpl_stats_base);
			t4_tp_get_err_stats(adapter, &adapter->tp_err_stats_base);
			t4_get_fcoe_stats(adapter, pi->port_id, &pi->fcoe_stats_base);
			t4_get_lb_stats(adapter, pi->port_id, &pi->lb_port_stats_base);
		}
		if (edata.val & STATS_QUEUE) {
			if (edata.addr == -1)
				clear_port_qstats(adapter, pi);
			else
				clear_ethq_stats(&adapter->sge,
						 pi->first_qset + edata.addr);
		}
		break;
	}
#ifdef CONFIG_CHELSIO_T4_OFFLOAD
#if 0
	case CHELSIO_DEVUP:
		if (!is_offload(adapter))
			return -EOPNOTSUPP;
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		return activate_offload(&adapter->tdev);
#endif
	case CHELSIO_SET_SCHED_CLASS: {
		struct ch_sched_params p;
		int fw_subcmd, fw_type;
		ret = -EINVAL;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (!adapter->flags & FULL_INIT_DONE)
			return -EAGAIN;        /* uP and SGE must be running */
		if (copy_from_user(&p, useraddr, sizeof(p)))
			return -EFAULT;

		/*
		 * Translate the cxgbtool parameters into T4 firmware
		 * parameters.  (The sub-command and type are in common
		 * locations.)
		 */
		if (p.subcmd == SCHED_CLASS_SUBCMD_CONFIG)
			fw_subcmd = FW_SCHED_SC_CONFIG;
		else if (p.subcmd == SCHED_CLASS_SUBCMD_PARAMS)
			fw_subcmd = FW_SCHED_SC_PARAMS;
		else
			return -EINVAL;
		if (p.type == SCHED_CLASS_TYPE_PACKET)
			fw_type = FW_SCHED_TYPE_PKTSCHED;
		else if (p.type == SCHED_CLASS_TYPE_STREAM)
			fw_type = FW_SCHED_TYPE_STREAMSCHED;
		else
			return -EINVAL;

		if (fw_subcmd == FW_SCHED_SC_CONFIG) {
			/*
			 * Vet our parameters ...
			 */
			if (p.u.config.minmax < 0)
				return -EINVAL;

			/*
			 * The Min/Max Mode can only be enabled _before_ the
			 * FW_INITIALIZE_CMD is issued and there's no real way
			 * to do that in this driver's architecture ...
			 */
			if (p.u.config.minmax)
				return -EINVAL;

			/*
			 * And pass the request to the firmware ...
			 */
			return t4_sched_config(adapter,
					       fw_type,
					       p.u.config.minmax);
		}

		if (fw_subcmd == FW_SCHED_SC_PARAMS) {
			int fw_level;
			int fw_mode;
			int fw_rateunit;
			int fw_ratemode;

			if (p.u.params.level == SCHED_CLASS_LEVEL_CL_RL)
				fw_level = FW_SCHED_PARAMS_LEVEL_CL_RL;
			else if (p.u.params.level == SCHED_CLASS_LEVEL_CL_WRR)
				fw_level = FW_SCHED_PARAMS_LEVEL_CL_WRR;
			else if (p.u.params.level == SCHED_CLASS_LEVEL_CH_RL)
				fw_level = FW_SCHED_PARAMS_LEVEL_CH_RL;
			else
				return -EINVAL;

			if (p.u.params.level == SCHED_CLASS_LEVEL_CL_RL) {
				if (p.u.params.mode == SCHED_CLASS_MODE_CLASS)
					fw_mode = FW_SCHED_PARAMS_MODE_CLASS;
				else if (p.u.params.mode == SCHED_CLASS_MODE_FLOW)
					fw_mode = FW_SCHED_PARAMS_MODE_FLOW;
				else
					return -EINVAL;
			} else
				fw_mode = 0;

			if (p.u.params.level == SCHED_CLASS_LEVEL_CL_RL ||
			    p.u.params.level == SCHED_CLASS_LEVEL_CH_RL) {
				if (p.u.params.rateunit == SCHED_CLASS_RATEUNIT_BITS)
					fw_rateunit = FW_SCHED_PARAMS_UNIT_BITRATE;
				else if (p.u.params.rateunit == SCHED_CLASS_RATEUNIT_PKTS)
					fw_rateunit = FW_SCHED_PARAMS_UNIT_PKTRATE;
				else
					return -EINVAL;
			} else
				fw_rateunit = 0;

			if (p.u.params.level == SCHED_CLASS_LEVEL_CL_RL ||
			    p.u.params.level == SCHED_CLASS_LEVEL_CH_RL) {
				if (p.u.params.ratemode == SCHED_CLASS_RATEMODE_REL)
					fw_ratemode = FW_SCHED_PARAMS_RATE_REL;
				else if (p.u.params.ratemode == SCHED_CLASS_RATEMODE_ABS)
					fw_ratemode = FW_SCHED_PARAMS_RATE_ABS;
				else
					return -EINVAL;
			} else
				fw_ratemode = 0;

			/*
			 * Vet our parameters ...
			 */
			if (!in_range(p.u.params.channel, 0, 3) ||
			    ((p.u.params.level == SCHED_CLASS_LEVEL_CL_RL ||
			      p.u.params.level == SCHED_CLASS_LEVEL_CL_WRR) &&
			      !in_range(p.u.params.class, 0,
				        adapter->params.nsched_cls-1)) ||
			    ((p.u.params.ratemode == SCHED_CLASS_RATEMODE_ABS ||
			      p.u.params.ratemode == SCHED_CLASS_RATEMODE_REL) &&
			     (!in_range(p.u.params.minrate, 0, 10000000) ||
			      !in_range(p.u.params.maxrate, 1, 10000000))) ||
			    !in_range(p.u.params.weight, 0, 100))
				return -ERANGE;
			if (p.u.params.level == SCHED_CLASS_LEVEL_CL_RL &&
			    (p.u.params.minrate > p.u.params.maxrate))
				return -EINVAL;

			/*
			 * Translate any unset parameters into the firmware's
			 * nomenclature and/or fail the call if the parameters
			 * are required ...
			 */
			if (p.u.params.channel < 0)
				return -EINVAL;
			if (p.u.params.rateunit < 0 || p.u.params.ratemode < 0) {
				if (p.u.params.level == SCHED_CLASS_LEVEL_CL_RL ||
				    p.u.params.level == SCHED_CLASS_LEVEL_CH_RL)
					return -EINVAL;
				else {
					p.u.params.rateunit = 0;
					p.u.params.ratemode = 0;
				}
			}
			if (p.u.params.class < 0) {
				if (p.u.params.level == SCHED_CLASS_LEVEL_CL_RL ||
				    p.u.params.level == SCHED_CLASS_LEVEL_CL_WRR)
					return -EINVAL;
				else
					p.u.params.class = 0;
			}
			if (p.u.params.minrate < 0)
				p.u.params.minrate = 0;
			if (p.u.params.maxrate < 0) {
				if (p.u.params.level == SCHED_CLASS_LEVEL_CL_RL ||
				    p.u.params.level == SCHED_CLASS_LEVEL_CH_RL)
					return -EINVAL;
				else
					p.u.params.maxrate = 0;
			}
			if (p.u.params.weight < 0) {
				if (p.u.params.level == SCHED_CLASS_LEVEL_CL_WRR)
					return -EINVAL;
				else
					p.u.params.weight = 0;
			}
			if (p.u.params.pktsize < 0) {
				if (p.u.params.level == SCHED_CLASS_LEVEL_CL_RL)
					return -EINVAL;
				else
					p.u.params.pktsize = 0;
			}

			/*
			 * See what the firmware thinks of the request ...
			 */
			return t4_sched_params(adapter,
					       fw_type,
					       fw_level,
					       fw_mode,
					       fw_rateunit,
					       fw_ratemode,
					       p.u.params.channel,
					       p.u.params.class,
					       p.u.params.minrate,
					       p.u.params.maxrate,
					       p.u.params.weight,
					       p.u.params.pktsize);
		}

		return -EINVAL;
	}
	case CHELSIO_SET_SCHED_QUEUE: {
		struct ch_sched_queue p;
		struct port_info *pi = netdev_priv(dev);
		struct sge_eth_txq *txq;
		u32 fw_mnem, fw_queue, fw_class;
		int err, q;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (!adapter->flags & FULL_INIT_DONE)
			return -EAGAIN;        /* uP and SGE must be running */
		if (copy_from_user(&p, useraddr, sizeof(p)))
			return -EFAULT;

		if (!in_range(p.queue, 0, pi->nqsets - 1) ||
		    !in_range(p.class, 0,
		              adapter->params.nsched_cls-1))
			return -EINVAL;

		/*
		 * Create a template for the FW_PARAMS_CMD mnemonic and
		 * value (TX Scheduling Class in this case).
		 */
		fw_mnem = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DMAQ) |
			   V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DMAQ_EQ_SCHEDCLASS_ETH));
		fw_class = p.class < 0 ? 0xffffffff : p.class;

		/*
		 * If op.queue is non-negative, then we're only changing the
		 * scheduling on a single specified TX queue.
		 */
		if (p.queue >= 0) {
			txq = &adapter->sge.ethtxq[pi->first_qset + p.queue];
			fw_queue = (fw_mnem |
				    V_FW_PARAMS_PARAM_YZ(txq->q.cntxt_id));
			err = t4_set_params(adapter, adapter->mbox,
					    adapter->pf, 0, 1,
					    &fw_queue, &fw_class);
			return err;
		}

		/*
		 * Change the scheduling on all the TX queues for the
		 * interface.
		 */
		txq = &adapter->sge.ethtxq[pi->first_qset];
		for (q = 0; q < pi->nqsets; q++, txq++) {
			fw_queue = (fw_mnem |
				    V_FW_PARAMS_PARAM_YZ(txq->q.cntxt_id));
			err = t4_set_params(adapter, adapter->mbox,
					    adapter->pf, 0, 1,
					    &fw_queue, &fw_class);
			if (err)
				return err;
		}

		return 0;
	}
	case CHELSIO_SET_SCHED_PFVF: {
		struct ch_sched_pfvf p;
		u32 fw_pfvf, fw_class;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (!adapter->flags & FULL_INIT_DONE)
			return -EAGAIN;        /* uP and SGE must be running */
		if (copy_from_user(&p, useraddr, sizeof(p)))
			return -EFAULT;
		if (!in_range(p.class, 0, adapter->params.nsched_cls-1))
			return -EINVAL;

		fw_pfvf = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_PFVF) |
			   V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_PFVF_SCHEDCLASS_ETH));
		fw_class = p.class < 0 ? 0xffffffff : p.class;
		return t4_set_params(adapter, adapter->mbox,
				     p.pf, p.vf, 1,
				     &fw_pfvf, &fw_class);
	}
	case CHELSIO_SET_OFLD_POLICY: {
		struct ch_mem_range t;
		struct ofld_policy_file *opf;
		struct cxgb4_uld_info *toe_uld = &cxgb4_ulds[CXGB4_ULD_TOE];
		void *toe_handle = adapter->uld_handle[CXGB4_ULD_TOE];

		if (!test_bit(OFFLOAD_DEVMAP_BIT,
			      &adapter->registered_device_map))
			return -EOPNOTSUPP;
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (copy_from_user(&t, useraddr, sizeof(t)))
			return -EFAULT;
		if (!toe_uld->control || !TOEDEV(dev))
			return -EOPNOTSUPP;

		/* len == 0 removes any existing policy */
		if (t.len == 0) {
			toe_uld->control(toe_handle,
					 CXGB4_CONTROL_SET_OFFLOAD_POLICY,
					 NULL);
			break;
		}

		opf = t4_alloc_mem(t.len);
		if (!opf)
			return -ENOMEM;

		if (copy_from_user(opf, useraddr + sizeof(t), t.len)) {
			t4_free_mem(opf);
			return -EFAULT;
		}

		ret = validate_offload_policy(dev, opf, t.len);
		if (!ret)
			ret = validate_policy_settings(dev, adapter, opf);
		if (!ret)
			ret = toe_uld->control(toe_handle,
					       CXGB4_CONTROL_SET_OFFLOAD_POLICY,
					       opf);
		t4_free_mem(opf);
		return ret;
	}
#endif
	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

