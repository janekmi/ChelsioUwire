#include "wd_qp.h"
#include "ntuples.h"
#include "offload.h"
#include <linux/module.h>

extern dev_t wdtoe_dev;
extern struct class *wdtoe_devclass;
extern struct file_operations per_stack_wdtoe_fops;
extern struct wdtoe_device_table *wdtoe_dev_table;
extern struct wdtoe_listen_device *listen_table;
extern struct conn_tuple *conn_tuple;
static int relaxed_ordering = 1;
static int stacks = 0;
static int original_tx_hold_thres;
static int wd_alloc_raw_rxq(struct wd_raw_rxq *, 
				struct cxgb4_lld_info *);
static void *wd_alloc_rxq_buf(struct cxgb4_lld_info *, int, 
                            dma_addr_t *, unsigned long *);

#define POISON_BUF_VAL -1
static inline void wdtoe_poison_buf(struct page *pg, size_t sz)
{
#if POISON_BUF_VAL >=0
	memset(page_address(pg), POISON_BUF_VAL, sz);
#endif
}

static inline void set_fl_sw_desc(struct fl_sw_desc *sd, void *buf,
				dma_addr_t mapping)
{
	sd->buf = buf;
	sd->dma_addr = mapping;
}

/* 
 * Stolen from cxgb4's code, allocate pages for the FL, but we do not 
 * ring the FL DoorBell from kernel. Ring DB is moved to user space 
 */
static int wdtoe_refil_fl(struct adapter *adap, struct t4_fl *q, int n, gfp_t gfp)
{
	struct page *pg;
	dma_addr_t mapping;
	unsigned int cred = q->avail;
	__be64 *d = &q->desc[q->pidx];
	struct fl_sw_desc *sd = &q->sdesc[q->pidx];

	gfp |= __GFP_NOWARN;

	while (n--) {
		pg = alloc_pages(gfp, 0);
		if (!pg) {
			printk(KERN_ERR "[wdtoe] %s: allocate FL buf from "
					"kernel failed\n", __func__);
			break;
		}

		wdtoe_poison_buf(pg, PAGE_SIZE);
		mapping = dma_map_page(adap->pdev_dev, pg, 0, 
					PAGE_SIZE, PCI_DMA_FROMDEVICE);
		if (dma_mapping_error(adap->pdev_dev, mapping)) {
			printk(KERN_ERR "[wdtoe] %s: allocate FL buf from "
					"kernel failed\n", __func__);
			__free_pages(pg, 0);
			break;
		}

		mapping |= 0x0;
		*d++ = cpu_to_be64(mapping);

		set_fl_sw_desc(sd, pg, mapping);
		sd++;

		/*
		 * As we are allocating all the FL buffers in FL here,
		 * only increase pidx, but not reset pidx back to 0
		 * even when pidx == fl->size
		 */
		q->avail++;
		q->pidx++;
	}

	cred = q->avail - cred;
	q->pend_cred += cred;
	
	return cred;
}

/*
 * Alloc ring buffer for IQ and FL
 */
static void *wd_alloc_rxq_buf(struct cxgb4_lld_info *lldi, int len, 
                dma_addr_t *dma_addr, unsigned long *phys_addr)
{
	void *p;
	p = dma_alloc_coherent(&lldi->pdev->dev, len, dma_addr, 
                                GFP_KERNEL);
	if(!p)
		return NULL;

	*phys_addr = virt_to_phys(p);
	memset(p, 0, len);

	return p;
}

static void *wdtoe_alloc_txq_ring(struct net_device *dev,
				  struct wdtoe_raw_txq *txq,
				  unsigned int onchip)
{
	void *p;
	unsigned int nentries;
	dma_addr_t *dma_addr = &txq->txq.dma_addr;
	unsigned long *phys_addr = &txq->txq.phys_addr;
	unsigned int *len = &txq->txq.memsize;
	struct adapter *adap = netdev2adap(dev);
	struct sge *s = &adap->sge;

	nentries = txq->txq.size + s->stat_len / sizeof(struct tx_desc);

	if (onchip) {
		*len = PAGE_ALIGN(nentries * sizeof(struct tx_desc)
					     + 16 * sizeof(__be64));

		*dma_addr = cxgb4_ocqp_pool_alloc(dev, *len);

		if (!*dma_addr)
			goto offchip;

		*phys_addr = adap->oc_mw_pa + *dma_addr -
			     adap->vres.ocq.start;
		p = (void *)(adap->oc_mw_kva + *dma_addr -
			     adap->vres.ocq.start);

		txq->flags |= T4_TX_ONCHIP;
	} else {
offchip:
		*len = PAGE_ALIGN(nentries * sizeof(struct tx_desc));

		p = dma_alloc_coherent(adap->pdev_dev, *len, dma_addr,
				       GFP_KERNEL);
		if(!p)
			return NULL;
		*phys_addr = virt_to_phys(p);
	}

	memset(p, 0, *len);
	return p;
}

/*
 * This is the function where we have IQ/FL, i.e. a "rxq", created.
 * We constructed a mailbox command and send to T4
 */
static int wd_alloc_raw_rxq(struct wd_raw_rxq *rxq, 
				struct cxgb4_lld_info *lldi)
{
	int ret, flsz = 0;
	struct fw_iq_cmd c;
	struct t4_iq *iq = &rxq->iq;
	struct t4_fl *fl = &rxq->fl;
	struct t4_iq_shared_params *iq_params = &rxq->iq_params;
	struct t4_fl_shared_params *fl_params = &rxq->fl_params;
	u16 rid = lldi->rxq_ids[cxgb4_port_idx(rxq->netdev)];
	struct net_device *dev = NULL;
	int t4_eq_status_entries = 0;
	struct adapter *adapter;

	adapter = ((struct port_info *)netdev_priv(lldi->ports[0]))->adapter;
	if (adapter == NULL) {
		printk(KERN_ERR "[wdtoe] %s: adapter is NULL, "
				"aborting rxq creation\n", __func__);
		ret = -1;
		goto out;
	}
	iq->adapter = adapter;
	dev = rxq->netdev;

	/* get t4_eq_status_entries from lldi */
	t4_eq_status_entries = lldi->sge_ingpadboundary > 64 ? 2 : 1;
	/* XXX printk needs replacement */

	iq->desc = wd_alloc_rxq_buf(lldi, iq->memsize, &iq->dma_addr,
		&iq->phys_addr);
	if (!iq->desc) {
		ret = -ENOMEM;
		goto out;
	}
	iq->queue = (struct t4_iqe *)iq->desc;

	/* XXX these memsize need PAGE_ALIGN as well!? */
	iq_params->memsize = sizeof(struct t4_iq_shared_params_entry);
	iq_params->desc = wd_alloc_rxq_buf(lldi, iq_params->memsize,
				&iq_params->dma_addr, &iq_params->phys_addr);
	if (!iq_params->desc) {
		ret = -ENOMEM;
		goto err1;
	}
	iq->iq_shared_params = 
			(struct t4_iq_shared_params_entry *)iq_params->desc;

	fl_params->memsize = sizeof(struct t4_fl_shared_params_entry);
	fl_params->desc = wd_alloc_rxq_buf(lldi, fl_params->memsize,
				&fl_params->dma_addr, &fl_params->phys_addr);
	if (!fl_params->desc) {
		ret = -ENOMEM;
		goto err2;
	}

	fl->size = roundup(fl->size, 8);
	fl->desc = wd_alloc_rxq_buf(lldi, fl->memsize, &fl->dma_addr,
		&fl->phys_addr);
	if (!fl->desc) {
		ret = -ENOMEM;
		goto err3;
	}

	fl->sdesc_memsize = sizeof(struct fl_sw_desc) * fl->size;
	fl->sdesc = wd_alloc_rxq_buf(lldi, fl->sdesc_memsize,
					&fl->sdesc_dma_addr,
					&fl->sdesc_phys_addr);
	if (!fl->sdesc) {
		ret = -ENOMEM;
		goto err4;
	}

	flsz = fl->size / 8 + t4_eq_status_entries;

	/* XXX do we need fid? */

	memset(&c, 0, sizeof(c));
	c.op_to_vfn = htonl(V_FW_CMD_OP(FW_IQ_CMD) | F_FW_CMD_REQUEST |
			F_FW_CMD_WRITE | F_FW_CMD_EXEC |
			V_FW_IQ_CMD_PFN(lldi->pf) |
			V_FW_IQ_CMD_VFN(0));
	c.alloc_to_len16 = htonl(F_FW_IQ_CMD_ALLOC | F_FW_IQ_CMD_IQSTART |
			(sizeof(c) / 16));
	c.type_to_iqandstindex = htonl( V_FW_IQ_CMD_TYPE(FW_IQ_TYPE_FL_INT_CAP) |
		V_FW_IQ_CMD_IQASYNCH(0) |
		V_FW_IQ_CMD_VIID(cxgb4_port_viid(rxq->netdev)) |
		V_FW_IQ_CMD_IQANDST(X_INTERRUPTDESTINATION_IQ) |
		V_FW_IQ_CMD_IQANUD(X_UPDATEDELIVERY_INTERRUPT) |
		V_FW_IQ_CMD_IQANUS(X_UPDATESCHEDULING_TIMER) |
		V_FW_IQ_CMD_IQANDSTINDEX(rid));
	c.iqdroprss_to_iqesize = htons(
		V_FW_IQ_CMD_IQPCIECH(cxgb4_port_chan(rxq->netdev)) |
				F_FW_IQ_CMD_IQGTSMODE |
		V_FW_IQ_CMD_IQINTCNTTHRESH(0) |
		V_FW_IQ_CMD_IQESIZE(ilog2(T4_IQE_LEN) - 4));
	c.iqsize = htons(iq->size);
	c.iqaddr = cpu_to_be64(iq->dma_addr);
	c.iqns_to_fl0congen = htonl(
		V_FW_IQ_CMD_FL0HOSTFCMODE(X_HOSTFCMODE_NONE) |
		F_FW_IQ_CMD_FL0CONGEN |
		F_FW_IQ_CMD_FL0CONGCIF |
		V_FW_IQ_CMD_FL0FETCHRO(relaxed_ordering) |
		V_FW_IQ_CMD_FL0DATARO(relaxed_ordering) |
#ifdef notyet                
                F_FW_IQ_CMD_FL0PACKEN |
#endif
                F_FW_IQ_CMD_FL0PADEN);
	c.fl0dcaen_to_fl0cidxfthresh = htons(
                V_FW_IQ_CMD_FL0FBMIN(X_FETCHBURSTMIN_64B) |
                V_FW_IQ_CMD_FL0FBMAX(X_FETCHBURSTMAX_512B));
	c.fl0size = htons(flsz);
	c.fl0addr = cpu_to_be64(fl->dma_addr);

	rtnl_lock();
	ret = cxgb4_wr_mbox(rxq->netdev, &c, sizeof(c), &c);
	rtnl_unlock();

	if (ret) {
		printk(KERN_ERR "[wdtoe] %s: mbox error %d\n", __func__, ret);
		goto err5;
	}

	iq->cntxt_id = ntohs(c.iqid);
	iq->size--;		/* subtract status entry */
	
	fl->cntxt_id = ntohs(c.fl0id);
	fl->avail = fl->pend_cred = 0;
	fl->pidx = fl->cidx = 0;
	fl->db = lldi->db_reg;
	/* XXX need to insert debug code */
	/*
	 * PDBG("%s fl cntxt_id %d, size %d memsize %d, "
	 *   "iq cntxt_id %d size %d memsize %d\n", __func__, fl->cntxt_id,
	 *     fl->size, fl->memsize, iq->cntxt_id, iq->size, iq->memsize);
	 */

	//XXX now put the refil_fl code here in kernel:
	wdtoe_refil_fl(adapter, fl, fl->size, GFP_KERNEL);
	
	return ret;

err5:
	if (fl->sdesc)
		dma_free_coherent(&lldi->pdev->dev, fl->sdesc_memsize,
				fl->sdesc, fl->sdesc_dma_addr);
err4:
	if (fl && fl->desc)
		dma_free_coherent(&lldi->pdev->dev, fl->memsize,
				fl->desc, fl->dma_addr);
err3:
	if (fl_params->desc)
		dma_free_coherent(&lldi->pdev->dev, fl_params->memsize,
				fl_params->desc, fl_params->dma_addr);
err2:
	if (iq_params->desc)
		dma_free_coherent(&lldi->pdev->dev, iq_params->memsize,
				iq_params->desc, iq_params->dma_addr);
err1:
	if (iq->desc)
		dma_free_coherent(&lldi->pdev->dev, iq->memsize,
				iq->desc, iq->dma_addr);
out:
	return ret;
}


/*
 * Determine the size of IQ and FL, then call wd_alloc_raw_rxq()
 * to create them
 */
struct wd_raw_rxq *wd_create_raw_rxq(struct cxgb4_lld_info *lldi,
					struct net_device *netdev) 
{
	struct wd_raw_rxq *rxq;
	/* flsize needs to be multiple of 16 */
	int flsize = 16 * WDTOE_FLSIZE;
	int iqsize = flsize * 4;
	int status;
	unsigned int t4_stat_len = 0;

	/* get t4_stat_len from lldi */
	t4_stat_len = lldi->sge_egrstatuspagesize;

	rxq = kzalloc(sizeof(*rxq), GFP_KERNEL);
	if (!rxq)
		goto out;

	rxq->fl.size = flsize;
	rxq->iq.size = iqsize;
	rxq->netdev = netdev;
	if(rxq->netdev == NULL) {
		printk(KERN_ERR "[wdtoe] %s: netdev is NULL, "
				"aborting RxQ allocation.\n",
				__func__);
		goto err;
	}
    
	/* specifying the memory size of iq and fl */
	rxq->iq.memsize = PAGE_ALIGN(rxq->iq.size * T4_IQE_LEN);
	rxq->fl.memsize = PAGE_ALIGN(rxq->fl.size * sizeof(__be64) 
							+ t4_stat_len);
	status = wd_alloc_raw_rxq(rxq, lldi);
	if (status < 0) {
		printk(KERN_ERR "[wdtoe] %s: RxQ allocation failed "
				"with err %d\n", __func__, status);
		goto err;
	}

	return rxq;
err:
	kfree(rxq);
out:
	return NULL;
}

static void insert_node(struct pid_node **list, pid_t new_pid)
{
	struct pid_node *new_node;
	/* allocate memory for the new node */
	new_node = kmalloc(sizeof(struct pid_node), GFP_KERNEL);
	new_node->pid = new_pid;
	new_node->next = *list;
	*list = new_node;
}

/* return 0 if found, otherwise return -1 */
static int find_node(struct pid_node *list, pid_t pid)
{
	while (list) {
		if (list->pid == pid)
			return 0;
		list = list->next;
	}
	return -1;
}

/*
 * After a stack is created, register this "wdtoe_device" in the kernel
 * "wdtoe_device_table". This function needs to be called with
 * the per stack spin-lock held.
 */
static int wdtoe_register_dev(struct wdtoe_device_table *t,
				int idx, 
				struct wdtoe_device *wd_dev,
				int pid)
{
	if (idx >= WDTOE_DEV_TABLE_ENTRY || idx < 0) {
		printk(KERN_ERR "[wdtoe] %s: invalid index [%d] "
				"for pid [%d]\n", __func__, idx, pid);
		return -1;
	}

	t[idx].wd_dev = wd_dev;
	insert_node(&t[idx].pid_list, pid);
	/* flag the device entry to be "CREATED" now */
	t[idx].in_use = WD_DEV_CREATED;
	return 0;
}

/*
 * This is for an active connection to figure out which "wdtoe_device"
 * it is using for the specific "pid".
 */
int wdtoe_find_dev_by_pid(struct wdtoe_device_table *t,
			int *idx,
			int pid)
{
	int i;

	/* note that index starts from 1, index 0 is not used */
	for (i = 1; i < WDTOE_DEV_TABLE_ENTRY; i++) {
		/* we only care about those entries that are marked "CREATED" */
		if (t[i].in_use == WD_DEV_CREATED) {
			spin_lock(&t[i].wd_dev->lock);
			if (!find_node(t[i].pid_list, pid)) {
				/* we find the entry with the right pid */
				*idx = i;
				spin_unlock(&t[i].wd_dev->lock);
				return 0;
			}
			spin_unlock(&t[i].wd_dev->lock);
		}
	}

	return -1;
}

/*
 * Pass the "tid" of the connection to the wdtoe device table
 * return the index to the wdtoe device/stack that contains the tid
 */
int wdtoe_find_dev_by_tid(struct wdtoe_device_table *t,
			int *dev_idx, int *tbl_idx, int tid)
{
	int i, j;

	/* note that index starts from 1, index 0 is not used */
	for (i = 1; i < WDTOE_DEV_TABLE_ENTRY; i++) {
		/* we only care about those entries that are marked "CREATED" */
		if (t[i].in_use == WD_DEV_CREATED) {
			if (t[i].wd_dev != NULL) {
				struct wdtoe_stack_info_entry *stack;

				stack = t[i].wd_dev->k_stack_info;
				for (j = 0; j < NWDTOECONN; j++) {
					if (tid == stack->conn_info[j].tid) {
						/* we found the entry */
						*dev_idx = i;
						*tbl_idx = j;
						return 0;
					}
				}
			}
		}
	}

	return -1;
}

static int wdtoe_alloc_raw_txq(struct wdtoe_raw_txq *txq,
				struct cxgb4_lld_info *lldi,
				unsigned int onchip)
{
	struct sge *s;
	struct fw_eq_ofld_cmd c;
	struct adapter *adapter = NULL;
	int ret = 0;
	int nentries;

	adapter = ((struct port_info *)netdev_priv(lldi->ports[0]))->adapter;

	if (!adapter) {
		printk(KERN_ERR "[wdtoe] %s: adapter is NULL, "
				"aborting txq creation\n", __func__);
		ret = -1;
		goto err1;
	}

	s = &adapter->sge;

	txq->txq.size = WDTOE_TXQ_SIZE;
	txq->txq.desc = wdtoe_alloc_txq_ring(txq->netdev, txq, onchip);

	if (!txq->txq.desc) {
		ret = -ENOMEM;
		goto err1;
	}

	txq->txq_params.memsize = sizeof(struct t4_txq_shared_params_entry);
	txq->txq_params.desc = wd_alloc_rxq_buf(lldi,
					txq->txq_params.memsize,
					&txq->txq_params.dma_addr,
					&txq->txq_params.phys_addr);

	if (!txq->txq_params.desc) {
		ret = -ENOMEM;
		goto err2;
	}

	nentries = txq->txq.size + s->stat_len / sizeof(struct tx_desc);

	/* construct the mailbox command */
	memset(&c, 0, sizeof(c));
	c.op_to_vfn = htonl(V_FW_CMD_OP(FW_EQ_OFLD_CMD) | F_FW_CMD_REQUEST |
			F_FW_CMD_WRITE | F_FW_CMD_EXEC |
			V_FW_EQ_OFLD_CMD_PFN(lldi->pf) |
			V_FW_EQ_OFLD_CMD_VFN(0));
	c.alloc_to_len16 = htonl(F_FW_EQ_OFLD_CMD_ALLOC |
				F_FW_EQ_OFLD_CMD_EQSTART | (sizeof(c) / 16));
	/* XXX we do not know iqid ??? */
	c.fetchszm_to_iqid = 
		htonl(V_FW_EQ_OFLD_CMD_HOSTFCMODE(X_HOSTFCMODE_STATUS_PAGE) |
			V_FW_EQ_OFLD_CMD_PCIECHN(
					cxgb4_port_chan(txq->netdev)) |
			(t4_txq_onchip(txq) ? F_FW_EQ_OFLD_CMD_ONCHIP :
						  V_FW_EQ_OFLD_CMD_ONCHIP(0)) |
			F_FW_EQ_OFLD_CMD_FETCHRO |
			V_FW_EQ_OFLD_CMD_IQID(s->fw_evtq.cntxt_id));
	c.dcaen_to_eqsize =
		htonl(V_FW_EQ_OFLD_CMD_FBMIN(X_FETCHBURSTMIN_64B) |
			V_FW_EQ_OFLD_CMD_FBMAX(t4_txq_onchip(txq) ?
						X_FETCHBURSTMAX_256B :
						X_FETCHBURSTMAX_512B) |
			V_FW_EQ_OFLD_CMD_CIDXFTHRESH(X_CIDXFLUSHTHRESH_32) |
			V_FW_EQ_OFLD_CMD_EQSIZE(nentries));
	c.eqaddr = cpu_to_be64(txq->txq.dma_addr);

	rtnl_lock();
	ret = cxgb4_wr_mbox(txq->netdev, &c, sizeof(c), &c);
	rtnl_unlock();

	/*
	 * If the mbox command failed (returned a non-zero value)
	 * we make sure to free the memory allocated for both
	 * the TxQ and the TxQ metadata section.
	 */
	if (ret) {
		printk(KERN_ERR "[wdtoe] %s: mbox error [%d]\n",
				__func__, ret);
		goto err3;
	}
	txq->txq.cntxt_id = G_FW_EQ_OFLD_CMD_EQID(ntohl(c.eqid_pkd));
	return 0;

err3:
	if (txq->txq_params.desc)
		dma_free_coherent(&lldi->pdev->dev,
				txq->txq_params.memsize,
				txq->txq_params.desc,
				txq->txq_params.dma_addr);
err2:
	if (txq->txq.desc) {
		if (t4_txq_onchip(txq))
			cxgb4_ocqp_pool_free(txq->netdev,
					txq->txq.dma_addr,
					txq->txq.memsize);
		else
			dma_free_coherent(&lldi->pdev->dev,
					txq->txq.memsize,
					txq->txq.desc,
					txq->txq.dma_addr);
	}
err1:
	return ret;
}

static struct wdtoe_raw_txq *wdtoe_create_raw_txq(struct cxgb4_lld_info *lldi,
						 struct net_device *netdev,
						 unsigned int onchip)
{
	struct wdtoe_raw_txq *txq;
	int ret;

	if (!netdev) {
		printk(KERN_ERR "[wdtoe] %s: netdev is NULL, "
				"aborting TxQ allocation.\n",
				__func__);
		goto out;
	}

	txq = kzalloc(sizeof(struct wdtoe_raw_txq), GFP_KERNEL);

	if (!txq)
		goto out;

	txq->netdev = netdev;
	ret = wdtoe_alloc_raw_txq(txq, lldi, onchip);

	if (ret) {
		printk(KERN_ERR "[wdtoe] %s: TxQ allocation failed "
				"with error %d\n", __func__, ret);
		goto free_out;
	}

	return txq;

free_out:
	kfree(txq);
out:
	return NULL;
}

/*
 * Destroy a TxQ via T4 mailbox command
 */
static void wdtoe_free_raw_txq(struct wdtoe_raw_txq *txq,
				struct cxgb4_lld_info *lldi)
{
	struct fw_eq_ofld_cmd c;
	int ret;


	memset(&c, 0, sizeof(c));
	c.op_to_vfn = htonl(V_FW_CMD_OP(FW_EQ_OFLD_CMD) | F_FW_CMD_REQUEST |
			F_FW_CMD_EXEC |
			V_FW_EQ_OFLD_CMD_PFN(lldi->pf) |
			V_FW_EQ_OFLD_CMD_VFN(0));
	c.alloc_to_len16 = htonl(F_FW_EQ_OFLD_CMD_FREE | FW_LEN16(c));
	c.eqid_pkd = htonl(V_FW_EQ_OFLD_CMD_EQID(txq->txq.cntxt_id));
	rtnl_lock();
	ret = cxgb4_wr_mbox(txq->netdev, &c, sizeof(c), &c);
	rtnl_unlock();

	if (ret) {
		printk(KERN_ERR "[wdtoe] %s: mbox error [%d]\n", __func__, ret);
		goto out;
	}

	if (t4_txq_onchip(txq)) {
		cxgb4_ocqp_pool_free(lldi->ports[0], txq->txq.dma_addr,
				     txq->txq.memsize);
	} else {
		dma_free_coherent(&lldi->pdev->dev,
				  txq->txq.memsize,
				  txq->txq.desc,
				  txq->txq.dma_addr);
	}

	dma_free_coherent(&lldi->pdev->dev,
			  txq->txq_params.memsize,
			  txq->txq_params.desc,
			  txq->txq_params.dma_addr);
out:
	return;
}

/*
 * Destroy an IQ/FL pair via T4 mailbox command
 */
static void wdtoe_free_raw_rxq(struct wd_raw_rxq *rxq,
				struct cxgb4_lld_info *lldi)
{
	struct fw_iq_cmd c;
	int i;
	int ret;

	memset(&c, 0, sizeof(c));
	c.op_to_vfn = htonl(V_FW_CMD_OP(FW_IQ_CMD) | F_FW_CMD_REQUEST |
			F_FW_CMD_EXEC |
			V_FW_IQ_CMD_PFN(lldi->pf) |
			V_FW_IQ_CMD_VFN(0));
	c.alloc_to_len16 = htonl(F_FW_IQ_CMD_FREE | FW_LEN16(c));
	c.type_to_iqandstindex = htonl(V_FW_IQ_CMD_TYPE(FW_IQ_TYPE_FL_INT_CAP));
	c.iqid = htons(rxq->iq.cntxt_id);
	c.fl0id = htons(rxq->fl.cntxt_id);
	c.fl1id = htons(0xffff);
	rtnl_lock();
	ret = cxgb4_wr_mbox(rxq->netdev, &c, sizeof(c), &c);
	rtnl_unlock();

	if (ret) {
		printk(KERN_ERR "[wdtoe] %s: mbox error [%d]\n", __func__, ret);
		goto out;
	}
	dma_free_coherent(&lldi->pdev->dev, rxq->iq.memsize, 
					rxq->iq.desc, rxq->iq.dma_addr);
	dma_free_coherent(&lldi->pdev->dev, rxq->fl.memsize,
					rxq->fl.desc, rxq->fl.dma_addr);
	dma_free_coherent(&lldi->pdev->dev, rxq->iq_params.memsize,
				rxq->iq_params.desc, rxq->iq_params.dma_addr);
	dma_free_coherent(&lldi->pdev->dev, rxq->fl_params.memsize,
				rxq->fl_params.desc, rxq->fl_params.dma_addr);
	/* Free up the FL buffer */
	for (i = 0; i < rxq->fl.size; i++) {
		__free_page(rxq->fl.sdesc[i].buf);
	}
	dma_free_coherent(&lldi->pdev->dev, rxq->fl.sdesc_memsize,
				rxq->fl.sdesc, rxq->fl.sdesc_dma_addr);
out:
	return;
}

/*
 * Calculate a Txq's udb address from kernel. This is lifted from cxgb4.
 */
static int get_udb(struct cxgb4_lld_info *lldi, unsigned int qid, u64 *udb)
{
	struct adapter *adap = NULL;
	unsigned int s_qpp;
	unsigned short udb_density;
	unsigned long qpshift;
	int page;
	u64 kudb;

	adap = ((struct port_info *)netdev_priv(lldi->ports[0]))->adapter;
	if (!adap) {
		printk(KERN_ERR "[wdtoe] %s: adapter is NULL, and can not "
				"get udb in the kernel!\n", __func__);
		return -1;
	}

	s_qpp = (S_QUEUESPERPAGEPF0 +
		(S_QUEUESPERPAGEPF1 - S_QUEUESPERPAGEPF0) * adap->pf);
	udb_density = 1 << ((t4_read_reg(adap,
			A_SGE_EGRESS_QUEUES_PER_PAGE_PF) >> s_qpp)
			& M_QUEUESPERPAGEPF0);
	qpshift = PAGE_SHIFT - ilog2(udb_density);
	kudb = qid << qpshift;
	kudb &= PAGE_MASK;
	page = kudb / PAGE_SIZE;
	kudb += (qid - (page * udb_density)) * 128;
	*udb = (u64)(adap->bar2 + kudb + 8);

	return 0;
}

/*
 * function to create a WD-TOE stack. For each physical port on a T4
 * adapter, an IQ/FL pair is created.
 */
ssize_t wdtoe_create_rxq(struct cxgb4_lld_info *cached_lldi, 
					struct wdtoe_device *wd_dev,
					const char __user *buf,
					int in_len, int out_len)
{
	struct wdtoe_create_qp_cmd cmd;
	struct wd_raw_rxq *rxq = NULL;
	struct wdtoe_raw_txq *txq = NULL;
	struct create_rxq_resp uresp;

	int i, j;
	int mmap_num;
	int mmap_index = 0;
	int ret = 0;
	u64 kudb;

	if (copy_from_user(&cmd, buf, sizeof cmd)) {
		ret = -EFAULT;
		goto err1;
	}

	wd_dev->rxq_list = kcalloc(cached_lldi->nports, 
				sizeof(struct wd_raw_rxq *), GFP_KERNEL);
	if (!wd_dev->rxq_list) {	
		ret = -ENOMEM;
		goto err1;
	}
	wd_dev->txq_list = kcalloc(cached_lldi->nports,
				sizeof(struct wdtoe_raw_txq *), GFP_KERNEL);
	if (!wd_dev->txq_list) {
		ret = -ENOMEM;
		goto err2;
	}
	/* The extra "1" here is for the stack_info */
	mmap_num = cached_lldi->nports * WDTOE_MMAPNUM_RXQ  + 
			cached_lldi->nports * WDTOE_MMAPNUM_TXQ + 1;

	wd_dev->mmap_element_offset = mmap_num;
	/* XXX wd_dev->address_list can be freed when RxQ creation is done */
	wd_dev->address_list = kcalloc(mmap_num, 
				sizeof (struct wdtoe_mm), GFP_KERNEL);
	if (!wd_dev->address_list)
		goto err3;
	uresp.nports = cached_lldi->nports;

	for (i = 0; i < cached_lldi->nports; i++) {
		int idx;
		idx = i * WDTOE_MMAPNUM_RXQ;

		rxq = wd_create_raw_rxq(cached_lldi, cached_lldi->ports[i]);
		if (!rxq) {
			ret = -ENOMEM;
			goto err4;
		}

		spin_lock(&wd_dev->lock);
		wd_dev->address_list[0 + idx].paddr = (u64)rxq->iq.phys_addr;
		wd_dev->address_list[0 + idx].vaddr = (u64)rxq->iq.desc;
		wd_dev->address_list[0 + idx].len = (unsigned)rxq->iq.memsize;

		wd_dev->address_list[1 + idx].paddr = (u64)rxq->fl.phys_addr;
		wd_dev->address_list[1 + idx].vaddr = (u64)rxq->fl.desc;
		wd_dev->address_list[1 + idx].len = (unsigned)rxq->fl.memsize;

		wd_dev->address_list[2 + idx].paddr =
				(pci_resource_start(cached_lldi->pdev, 0) +
				MYPF_REG(A_SGE_PF_KDOORBELL)) & PAGE_MASK;
		wd_dev->address_list[2 + idx].vaddr = 
				(u64)__va(wd_dev->address_list[2 + idx].paddr);
		wd_dev->address_list[2 + idx].len = PAGE_SIZE;

		wd_dev->address_list[3 + idx].paddr = 
						(u64)rxq->iq_params.phys_addr;
		wd_dev->address_list[3 + idx].vaddr = (u64)rxq->iq_params.desc;
		wd_dev->address_list[3 + idx].len = PAGE_SIZE;

		wd_dev->address_list[4 + idx].paddr = 
						(u64)rxq->fl_params.phys_addr;
		wd_dev->address_list[4 + idx].vaddr = (u64)rxq->fl_params.desc;
		wd_dev->address_list[4 + idx].len = PAGE_SIZE;
		spin_unlock(&wd_dev->lock);

		for (j = 0; j < rxq->fl.size; j++) {
			void *temp_va;
			unsigned long temp_pa;

			temp_va = page_address(rxq->fl.sdesc[j].buf);
			temp_pa = virt_to_phys(temp_va);

			spin_lock(&wd_dev->lock);
			wd_dev->address_list[5 + idx + j].vaddr = (u64) temp_va;
			wd_dev->address_list[5 + idx + j].paddr = (u64) temp_pa;
			/* Each chunk of FL buf is PAGE_SIZE large */
			wd_dev->address_list[5 + idx + j].len = PAGE_SIZE;
			spin_unlock(&wd_dev->lock);
			/* Store the index into address_list */
			mmap_index = 5 + idx + j;
		}

		/* now put the created RxQ into the global list */
		spin_lock(&wd_dev->lock);
		wd_dev->rxq_list[i] = rxq;
		spin_unlock(&wd_dev->lock);
	}

	/* save qpshift and qpmask, and prepare for udb calculation */
	wd_dev->qpshift = PAGE_SHIFT - ilog2(cached_lldi->udb_density);
	wd_dev->qpmask = cached_lldi->udb_density - 1;

	for (i = 0; i < cached_lldi->nports; i++) {
		/* Allocating onchip-memory TxQs */
		unsigned int onchip = is_t4(cached_lldi->adapter_type);
		txq = wdtoe_create_raw_txq(cached_lldi, cached_lldi->ports[i],
					   onchip);

		if (!txq) {
			ret = -ENOMEM;
			goto err5;
		}
		/*
		 * Calculating the udb page address for each Txq, this
		 * is preparing the mmap of udb from the user space.
		 */
		txq->txq.udb = (pci_resource_start(cached_lldi->pdev, 2) +
			(txq->txq.cntxt_id << wd_dev->qpshift)) & PAGE_MASK;

		/*
		 * Calculate and save a Txq's udb address from kernel 
		 * as well. This is in case we will need to flush this
		 * txq before the wdtoe stack is destroyed.
		 */
		ret = get_udb(cached_lldi, txq->txq.cntxt_id, &kudb);
		txq->txq.kudb = ret < 0 ? 0 : kudb;

		mmap_index++;
		wd_dev->address_list[mmap_index].paddr = 
						(u64)txq->txq.phys_addr;
		wd_dev->address_list[mmap_index].vaddr = 
						(u64)txq->txq.desc;
		wd_dev->address_list[mmap_index].len = 
						(unsigned)txq->txq.memsize;

		mmap_index++;
		wd_dev->address_list[mmap_index].paddr =
						(u64)txq->txq_params.phys_addr;
		wd_dev->address_list[mmap_index].vaddr =
						(u64)txq->txq_params.desc;
		wd_dev->address_list[mmap_index].len = PAGE_SIZE;

		mmap_index++;
		wd_dev->address_list[mmap_index].paddr = (u64)txq->txq.udb;
		wd_dev->address_list[mmap_index].vaddr =
						(u64)__va(txq->txq.udb);
		wd_dev->address_list[mmap_index].len = PAGE_SIZE;

		/* put the created TxQ into the per WD-TOE stack/device list */
		spin_lock(&wd_dev->lock);
		wd_dev->txq_list[i] = txq;
		spin_unlock(&wd_dev->lock);
	}

	/* 
	 * We have finished creation of one queue per port, 
	 * now allocate the connection info for each queue set
	 */
	wd_dev->stack_info.memsize = 
			PAGE_ALIGN(sizeof(struct wdtoe_stack_info_entry));
	/* get this memsize to user space, and later use for mmap */
	uresp.stack_info_memsize = wd_dev->stack_info.memsize;
	wd_dev->stack_info.desc = wd_alloc_rxq_buf(cached_lldi, 
						wd_dev->stack_info.memsize, 
						&wd_dev->stack_info.dma_addr, 
						&wd_dev->stack_info.phys_addr);
	if (!wd_dev->stack_info.desc) {
		printk(KERN_ERR "[wdtoe] %s: could not allocate memory "
				"to hold stack info\n", __func__);
		ret = -ENOMEM;
		goto err6;
	}
	wd_dev->k_stack_info = (struct wdtoe_stack_info_entry *)
						wd_dev->stack_info.desc;
	/* initialize listen server table */
	for (i = 0; i < NWDTOECONN; i++) {
		wd_dev->k_stack_info->svr_info[i].sockfd = 0;
		wd_dev->k_stack_info->svr_info[i].idx = -1;
		wd_dev->k_stack_info->svr_info[i].listen_port = 0;
		atomic_set(&wd_dev->k_stack_info->
					svr_info[i].ref_cnt, 0);
	}
	/* we put the stack_info as the last entry in wd_dev->address_list[] */
	mmap_index++;
	spin_lock(&wd_dev->lock);
	wd_dev->address_list[mmap_index].paddr = 
					(u64)wd_dev->stack_info.phys_addr;
	wd_dev->address_list[mmap_index].vaddr = 
					(u64)wd_dev->stack_info.desc;
	wd_dev->address_list[mmap_index].len = PAGE_SIZE;

	spin_unlock(&wd_dev->lock);

	if (is_t4(cached_lldi->adapter_type)) {
		wd_dev->hca_type = T4_WDTOE;
	} else {
		wd_dev->hca_type = T5_WDTOE;
	}
	uresp.hca_type = wd_dev->hca_type;
	uresp.qid_mask = wd_dev->qpmask;
	/*
	 * We are setting the tx_hold_thres according to the value
	 * found in the /etc/wdtoe.conf configuration file.
	 * We are getting this value from the lib in User Space.
	 *
	 * It will be set only when bringing the first stack up.
	 */
	if (!stacks) {
		original_tx_hold_thres = cached_td->conf.tx_hold_thres;
		cached_td->conf.tx_hold_thres = cmd.tx_hold_thres;
	}
	stacks++;

	if (copy_to_user((void __user *) (unsigned long)cmd.response,
                                    &uresp, sizeof uresp)) {
		ret = -EFAULT;
		goto err6;
	}
	/* marking this WD-TOE stack as up */
	wd_dev->in_use = 1;
	return in_len;
err6:
	dma_free_coherent(&cached_lldi->pdev->dev,
				wd_dev->stack_info.memsize,
				wd_dev->stack_info.desc,
				wd_dev->stack_info.dma_addr);
err5:
	for (i = 0; i < cached_lldi->nports; i++)
		if (wd_dev->txq_list[i])
			wdtoe_free_raw_txq(wd_dev->txq_list[i], cached_lldi);
err4:
	for (i = 0; i < cached_lldi->nports; i++)
		if (wd_dev->rxq_list[i])
			wdtoe_free_raw_rxq(wd_dev->rxq_list[i], cached_lldi);
	kfree(wd_dev->address_list);
err3:
	kfree(wd_dev->txq_list);
err2:
	kfree(wd_dev->rxq_list);
err1:
	wd_dev->in_use = 0;
	return ret;
}

/*
 * This function is to created the memory for data cache each connection
 * We create a mem-pool, and each of the 4KB page in this pool is mmap
 * back to user space
 */
ssize_t wdtoe_create_mempool(struct cxgb4_lld_info *cached_lldi, 
					struct wdtoe_device *wd_dev,
					const char __user *buf,
					int in_len, int out_len)
{
	struct create_mempool cmd;
	__be64 *desc;
	unsigned long phys_addr;
	dma_addr_t dma_addr;
	int i, j;
	int cur_idx;

	if (copy_from_user(&cmd, buf, sizeof cmd))
		return -EFAULT;

	wd_dev->mempool_size = cmd.page_num;
	/* XXX need error to user space and error out */
	if (cmd.page_num != NWDTOECONN * (NTXBUF + NRXBUF))
		printk(KERN_ERR "[wdtoe] incorrect number of pages when "
				"allocating Rx Tx buffers\n");

	wd_dev->address_list_mempool = kcalloc(cmd.page_num,
					sizeof (struct wdtoe_mm),
					GFP_KERNEL);
	/*
	 * XXX 2 problems here:
	 * XXX 1) what if memory allocation fails?
	 * XXX 2) why use device buffer?
	 */
	/* keep current index */
	cur_idx = 0;
	for (i = 0; i < cur_idx + NWDTOECONN * NTXBUF; i++) {
		desc = wd_alloc_rxq_buf(cached_lldi, PAGE_SIZE,
						&dma_addr, &phys_addr);
		wd_dev->address_list_mempool[i].paddr = (u64)phys_addr;
		wd_dev->address_list_mempool[i].vaddr = (u64)desc;
		wd_dev->address_list_mempool[i].daddr = dma_addr;
		wd_dev->address_list_mempool[i].len = PAGE_SIZE;
		j = i - cur_idx;
		wd_dev->k_stack_info->buf.sw_txq[j/NTXBUF].queue[j%NTXBUF].
					dma_addr = (u64)dma_addr;
		wd_dev->k_stack_info->buf.sw_txq[j/NTXBUF].
					queue[j%NTXBUF].copied = 0;
		if (j%NTXBUF == 0) {
			wd_dev->k_stack_info->buf.sw_txq[j/NTXBUF].cidx = 0;
			wd_dev->k_stack_info->buf.sw_txq[j/NTXBUF].pidx = 0;
			atomic_set(&wd_dev->k_stack_info->
					buf.sw_txq[j/NTXBUF].in_use, 0);
			wd_dev->k_stack_info->buf.sw_txq[j/NTXBUF].size =
								NTXBUF;
		}
	}
	cur_idx = i;
	for ( ; i < cur_idx + NWDTOECONN * NRXBUF; i++) {
		/* XXX what if alloc fails?? */
		desc = wd_alloc_rxq_buf(cached_lldi, PAGE_SIZE,
						&dma_addr, &phys_addr);
		wd_dev->address_list_mempool[i].paddr = (u64)phys_addr;
		wd_dev->address_list_mempool[i].vaddr = (u64)desc;
		wd_dev->address_list_mempool[i].daddr = dma_addr;
		wd_dev->address_list_mempool[i].len = PAGE_SIZE;
		j = i - cur_idx;
		if (j%NRXBUF == 0) {
			wd_dev->k_stack_info->buf.sw_fl[j/NRXBUF].size =
								NRXBUF;
			wd_dev->k_stack_info->buf.sw_fl[j/NRXBUF].cidx = 0;
			wd_dev->k_stack_info->buf.sw_fl[j/NRXBUF].pidx = 0;
			atomic_set(&wd_dev->k_stack_info->
					buf.sw_fl[j/NRXBUF].in_use, 0);
		}
	}
	/* init the credit queue */
	for (i = 0; i < NWDTOECONN; i++) {
		for (j = 0; j < NCRED; j++) {
			wd_dev->k_stack_info->buf.credq[i].queue[j].cred = 0;
			wd_dev->k_stack_info->buf.credq[i].queue[j].n_bufs = 0;
		}
		wd_dev->k_stack_info->buf.credq[i].size = NCRED;
		wd_dev->k_stack_info->buf.credq[i].cidx = 0;
		wd_dev->k_stack_info->buf.credq[i].pidx = 0;
	}
	/* init the flag array */
	for (j = 0; j < NWDTOECONN; j++) {
		wd_dev->k_stack_info->buf.flags[j] = 0;
	}
	return in_len;
}

/* XXX un-used, to be removed */
/* no need to copy anything back to user, so cmd.response should be NULL */
/* out_len should be 0 */
ssize_t wdtoe_pass_pid(struct cxgb4_lld_info *cached_lldi, 
                                    const char __user *buf,
                                    int in_len, int out_len)
{
	struct wdtoe_pass_pid_cmd cmd;
	
	if (copy_from_user(&cmd, buf, sizeof cmd))
		return -EFAULT;

	/* XXX need to store the pid from cmd */
	/* cmd.pid */
	/* printk(KERN_INFO "cmd.pid: %u\n", cmd.pid); */

	return in_len;
}

/*
 * Update the copied sequence number for the connection, i.e. the "sk"
 */
static inline void wdtoe_update_copied_seq(struct sock *sk, 
					unsigned int copied)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tp->copied_seq += copied;
}

/*
 * This is the function for returning Rx credits, we do two things here
 *    1) update the connection's copied sequence number by calling
 *       "wdtoe_update_copied_seq()"
 *    2) change the receive advertise window size by calling 
 *       "t4_cleanup_rbuf()"
 */
ssize_t wdtoe_update_rx_credits(struct cxgb4_lld_info *cached_lldi,
					struct wdtoe_device *wd_dev,
					const char __user *buf,
					int in_len, int out_len)
{
	struct wdtoe_update_rx_credits_cmd cmd;
	struct sock *sk;

	if (copy_from_user(&cmd, buf, sizeof cmd))
		return -EFAULT;

	sk = lookup_tid(cached_td->tids, cmd.tid);

	if (sk == NULL) {
		printk(KERN_ERR "[wdtoe] %s: invalid *sk from tid [%u]\n",
				__func__, cmd.tid);
		return -EFAULT;
	}
 
	lock_sock(sk);
	wdtoe_update_copied_seq(sk, cmd.copied);
	/* update the RX credits */
	/* XXX we do not need cmd.buf_len now */
	t4_cleanup_rbuf(sk, 0);
	release_sock(sk);

	return in_len;
}

/*
 * This is the main function for processing the CPL messages from
 * WD-TOE's user library. The user land WD-TOE library copies the CPL
 * it receives and passes it here. We call the existing CPL processing 
 * handler in TOM.
 *
 * One thing to notice is that we do not the "tom_data" here, so we 
 * are using a cached copy of it, i.e. "cached_td". It was saved when 
 * TOM module was inserted in to kernel.
 */
ssize_t wdtoe_pass_cpl_to_tom(struct cxgb4_lld_info * cached_lldi,
					struct wdtoe_device *wd_dev,
					const char __user *buf,
					int in_len,
					int out_len)
{
	struct t4_iqe *iqe;
	struct wdtoe_pass_cpl_to_tom_cmd cmd;
	const __be64 *rsp;
	const struct cpl_act_establish *cpl_msg;
	unsigned int opcode;
	int ret;

	if (copy_from_user(&cmd, buf, sizeof(cmd)) )
		return -EFAULT;

	iqe = &cmd.full_iqe;
	rsp = (__be64 *) iqe;

	if (cached_td == NULL) {
		printk(KERN_ERR "[wdtoe] %s: cached_td is NULL (aborting)",
				__func__);
		return -EINVAL;
	}

	ret = t4_recv_rsp(cached_td, rsp);

	cpl_msg = (struct cpl_act_establish *)rsp;
	opcode = G_CPL_OPCODE(ntohl(OPCODE_TID(cpl_msg)));
	switch (opcode) {
	case CPL_PASS_ESTABLISH:
	case CPL_ACT_ESTABLISH:
		spin_lock(&wd_dev->lock);
		wd_dev->conn_num++;
		spin_unlock(&wd_dev->lock);
		break;
	case CPL_CLOSE_CON_RPL:
		spin_lock(&wd_dev->lock);
		wd_dev->conn_num--;
		spin_unlock(&wd_dev->lock);
		break;
	default:
		break;
	}

	return in_len;
}

/*
 * This is the main function to copy the IQ/FL pair to user space.
 */
ssize_t wdtoe_copy_rxq(struct cxgb4_lld_info *cached_lldi, 
					struct wdtoe_device *wd_dev,
					const char __user *buf,
					int in_len, int out_len)
{
	struct wdtoe_copy_rxq_cmd cmd;
	struct copy_rxq_resp uresp;
	struct wd_raw_rxq *rxq = NULL;

	if (copy_from_user(&cmd, buf, sizeof(cmd)))
		return -EFAULT;
	/* now use cmd.port_num as the index to access wd_dev->rxq_list[] */
	spin_lock(&wd_dev->lock);
	rxq = wd_dev->rxq_list[cmd.port_num];
	spin_unlock(&wd_dev->lock);

	if (rxq == NULL) {
		printk(KERN_ERR "[wdtoe] %s: could not get RxQ from "
				"wd_dev->rxq_list [%u]\n", __func__,
				 cmd.port_num);
		return -1;
	}

	uresp.fl_id = rxq->fl.cntxt_id;
	uresp.iq_id = rxq->iq.cntxt_id;
	uresp.fl_size = rxq->fl.size;
	uresp.iq_size = rxq->iq.size;
	uresp.fl_memsize = rxq->fl.memsize;
	uresp.iq_memsize = rxq->iq.memsize;
	uresp.fl_pidx = rxq->fl.pidx;
	uresp.fl_pend_cred = rxq->fl.pend_cred;
	uresp.fl_avail = rxq->fl.avail;

	if (copy_to_user((void __user *) (unsigned long)cmd.response,
					&uresp, sizeof uresp)) {
		return -EFAULT;
	}

	return in_len;
}

/*
 * This is the main function to copy the Txq to user space.
 */
ssize_t wdtoe_copy_txq(struct cxgb4_lld_info *cached_lldi, 
					struct wdtoe_device *wd_dev,
					const char __user *buf,
					int in_len, int out_len)
{
	struct wdtoe_copy_txq_cmd cmd;
	struct wdtoe_copy_txq_resp uresp;
	struct wdtoe_raw_txq *txq = NULL;

	if (copy_from_user(&cmd, buf, sizeof(cmd)))
		return -EFAULT;
	/* use cmd.port_num as the index to access wd_dev->txq_list[] */
	spin_lock(&wd_dev->lock);
	txq = wd_dev->txq_list[cmd.port_num];
	spin_unlock(&wd_dev->lock);

	if (txq == NULL) {
		printk(KERN_ERR "[wdtoe] %s: could not get TxQ from "
				"wd_dev->rxq_list [%u]\n", __func__,
				 cmd.port_num);
		return -1;
	}

	uresp.txq_id = txq->txq.cntxt_id;
	uresp.txq_size = txq->txq.size;
	uresp.txq_memsize = txq->txq.memsize;
	uresp.flags = t4_txq_onchip(txq) ? txq->flags : 0;

	if (copy_to_user((void __user *) (unsigned long)cmd.response,
					&uresp, sizeof uresp)) {
		return -EFAULT;
	}

	return in_len;
}

ssize_t wdtoe_reg_stack(struct cxgb4_lld_info *cached_lldi,
				struct wdtoe_device *wd_dev,
				const char __user *buf,
				int in_len, int out_len)
{
	int ret;
	/* with spin lock held */
	spin_lock(&wd_dev->lock);
	/*XXX why this could fail? */
	ret = wdtoe_register_dev(wdtoe_dev_table, wd_dev->index,
				wd_dev, current->pid);
	if (ret < 0) {
		printk(KERN_ERR "[wdtoe] %s: process [%d] could not "
				"get registered for wd_dev index [%d]\n",
				__func__, current->pid, wd_dev->index);
		spin_unlock(&wd_dev->lock);
		return -EFAULT;
	}
	spin_unlock(&wd_dev->lock);
	return in_len;
}

ssize_t wdtoe_send_tx_flowc_wr(struct cxgb4_lld_info *cached_lldi,
				struct wdtoe_device *wd_dev,
				const char __user *buf,
				int in_len, int out_len)
{
	struct wdtoe_flowc_cmd cmd;
	struct wdtoe_flowc_resp uresp;
	struct sock *sk;
	struct tom_data *d;
	const struct cpl_io_state *cplios;
	const struct tcp_sock *tp;

	if (copy_from_user(&cmd, buf, sizeof(cmd)))
		return -EFAULT;

	sk = lookup_tid(cached_td->tids, cmd.tid);
	if (sk == NULL) {
		printk(KERN_ERR "[wdtoe] %s: invalid *sk from tid [%u]\n",
				__func__, cmd.tid);
		return -EFAULT;
	}
	tp = tcp_sk(sk);
	cplios = CPL_IO_STATE(sk);
	d = TOM_DATA(cplios->toedev);
	uresp.snd_nxt = tp->snd_nxt;
	uresp.rcv_nxt = tp->rcv_nxt;
	uresp.advmss = tp->advmss;
	uresp.sndbuf = cplios->sndbuf;
	uresp.tx_c_chan = cplios->tx_c_chan;
	uresp.pfvf = d->pfvf;
	uresp.txplen_max = cplios->txplen_max;
	if (copy_to_user((void __user *)(unsigned long)cmd.response,
				&uresp, sizeof(uresp)));
		return -EFAULT;

	return in_len;
}

/* 
 * get a free entry in the listen<->wd_dev table
 */
static int wdtoe_get_listen_table_entry(struct wdtoe_listen_device *t, 
					int * idx)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if (t[i].in_use == 0) {
			/* mark the entry to be in use */
			t[i].in_use = 1;
			*idx = i;
			return 0;
		}
	}

	/* no free entry available */
	return -1;
}

/* 
 * remove an entry in the listen<->wd_dev table, with the matching
 * listen port. And clear that entry for later use.
 */
static int wdtoe_remove_listen_table_listen_port(
				struct wdtoe_listen_device *t, 
				u16 port)
{
	int i;
	for (i = 0; i < NWDTOECONN; i++) {
		if (t[i].in_use == 1 && t[i].listen_port == port) {
			/* clear this entry */
			t[i].idx_dev = 0;
			t[i].in_use = 0;
			t[i].listen_port = 0;
			return 0;
		}
	}
	return -1;
}

/*
 * Remove an entry from listen<->wd_dev table
 */
static void wdtoe_remove_listen_table_entry(struct wdtoe_listen_device *t, 
					int idx_dev)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if (t[i].in_use == 1 && t[i].idx_dev == idx_dev) {
			/* clear this entry */
			t[i].idx_dev = 0;
			t[i].in_use = 0;
			t[i].listen_port = 0;
		}
	}
}

/*
 * This function is invoked when an application calls listen(), on a 
 * listening fd from user land. We figure out which port it is listening
 * on, pass that here, and then mark that port down in WD-TOE's 
 * listening table.
 *
 * When a SYN arrives, we are going to use the information in the table 
 * to figure out which "wdtoe_device" this SYN should be associated
 */
ssize_t wdtoe_reg_listen(struct cxgb4_lld_info *cached_lldi,
				struct wdtoe_device *wd_dev,
				const char __user *buf,
				int in_len, int out_len)
{
	struct wdtoe_reg_listen_cmd cmd;
	int idx;
	int lport;
	int ret;
	int listen_idx;

	/* get the "response" address */
	if (copy_from_user(&cmd, buf, sizeof(cmd)))
		return -EFAULT;

	idx = cmd.dev_idx;
	lport = cmd.listen_port;

	/* update an entry in the listen<->wd_dev table */
	ret = wdtoe_get_listen_table_entry(listen_table, &listen_idx);
	if (ret < 0) {
		printk(KERN_ERR "[wdtoe] %s: could not get a free "
				"entry from the listen table\n",
				__func__);
		return -EFAULT;
	}
	listen_table[listen_idx].listen_port = lport;
	listen_table[listen_idx].idx_dev = idx;

	return in_len;
}

ssize_t wdtoe_remove_listen(struct cxgb4_lld_info *cached_lldi,
				struct wdtoe_device *wd_dev,
				const char __user *buf,
				int in_len, int out_len)
{
	struct wdtoe_remove_listen_cmd cmd;
	u16 listen_port;
	int ret;

	/* get the "response" address */
	if (copy_from_user(&cmd, buf, sizeof(cmd)))
		return -EFAULT;

	listen_port = cmd.listen_port;
	ret = wdtoe_remove_listen_table_listen_port(listen_table, listen_port);
	if (ret < 0)
		printk(KERN_INFO "[wdtoe] %s: error removing server, "
				"port [%u]\n", __func__, listen_port);

	return in_len;
}

/*
 * This fuction is to answer the user space enquiry that for a tid, which 
 * physical port on T4 it is associated.
 */
ssize_t wdtoe_get_port_num(struct cxgb4_lld_info *cached_lldi,
				const char __user *buf,
				int in_len, int out_len)
{
	struct wdtoe_get_port_num_cmd cmd;
	struct wdtoe_get_port_num_resp uresp;
	struct sock *sk;
	const struct cpl_io_state *cplios;

	if (copy_from_user(&cmd, buf, sizeof(cmd)))
		return -EFAULT;

	sk = lookup_tid(cached_td->tids, cmd.tid);

	if (sk == NULL) {
		printk(KERN_ERR "[wdtoe] %s: invalid *sk from tid [%u]\n",
				__func__, cmd.tid);
		return -EFAULT;
	}

	cplios = CPL_IO_STATE(sk);
	uresp.port_num = cplios->port_id;
	uresp.max_cred = cplios->wr_max_credits;

	if (copy_to_user((void __user *)(unsigned long)cmd.response,
				&uresp, sizeof(uresp)))
		return -EFAULT;

	return in_len;
}

static int wdtoe_setup_cdev(struct wdtoe_device *dev, int index)
{
	int devno;
	int major;
	int minor;
	int ret;
	
	major = MAJOR(wdtoe_dev);
	minor = MINOR(wdtoe_dev);
	devno = MKDEV(major, minor + index);
	dev->devno = devno;
	dev->index = index;

	cdev_init(&dev->cdev, &per_stack_wdtoe_fops);
	dev->cdev.owner = THIS_MODULE;
	dev->cdev.ops = &per_stack_wdtoe_fops;
	ret = cdev_add(&dev->cdev, devno, 1);

	if (ret < 0)
		printk(KERN_ERR "[wdtoe] %s: error [%d] while adding "
				"char device [%d]\n", __func__, ret, index);
	return ret;
}

/*
 * actual creation of a char dev
 */
static int wdtoe_create_cdev_entry(struct wdtoe_device *dev, int index)
{
	char cdevname[20];

	/* XXX possible overflow here? */
	scnprintf(cdevname, 20, "wdtoe%d", index);

	if (IS_ERR(wdtoe_devclass)) {
		printk(KERN_ERR "[wdtoe] %s: could create device as it "
				"cannot be linked to a dev class\n",
				__func__);
		return -1;
	}

	dev->pdev = device_create(wdtoe_devclass,
				NULL, dev->devno, 
				NULL, cdevname);
	if (IS_ERR(dev->pdev)) {
		printk(KERN_ERR "[wdtoe] %s: failed to create device [%s]",
				__func__, cdevname);
		return -1;
	}

	return 0;
}

static inline int wdtoe_get_next_idx(struct wdtoe_device_table *t)
{
	int i;

	/* Note that index starts from 1 as index 0 is reserved */
	for (i = 1; i < WDTOE_DEV_TABLE_ENTRY; i++) {
		spin_lock(&t[i].lock);
		if (t[i].in_use == WD_DEV_FREE) {
			/* we flag the entry to be "ENGAGED" now */
			/* it will be flaged as "CREATED" when creation done */
			t[i].in_use = WD_DEV_ENGAGED;
			spin_unlock(&t[i].lock);
			return i;
		}
		spin_unlock(&t[i].lock);
	}
	return -1;
}

static void free_pid_list(struct pid_node *list)
{
	struct pid_node *node;

	while (list) {
		node = list;
		list = list->next;
		kfree(node);
	}
}

static inline void wdtoe_recycle_idx(struct wdtoe_device_table *t, int idx)
{
	spin_lock(&t[idx].lock);
	/* recycle this entry by flagging it's free now */
	t[idx].in_use = WD_DEV_FREE;
	free_pid_list(t[idx].pid_list);
	t[idx].pid_list = NULL;
	kfree(t[idx].wd_dev);

	/* We're keeping a counter of active stacks */
	stacks--;
	spin_unlock(&t[idx].lock);
}

/*
 * This is the main function to create a new char dev for a WD-TOE stack.
 * This function is the first thing when the user land decides to create a 
 * new stack, before IQ/FL being created.
 *
 * It get an index number "N", created a char dev at "/dev/wdtoeN", then 
 * register it with the kernel. Finally it copy this index "N" back to 
 * user land as well.
 */
ssize_t wdtoe_create_dev(struct cxgb4_lld_info *cached_lldi,
				const char __user *buf,
				int in_len, int out_len)
{
	int index;
	struct wdtoe_create_dev_cmd cmd;
	struct wdtoe_create_dev_resp uresp;
	struct wdtoe_device *wdtoe_dev;

	wdtoe_dev = kzalloc(sizeof *wdtoe_dev, GFP_KERNEL);

	if (wdtoe_dev == NULL)
		goto out_err;
	spin_lock_init(&wdtoe_dev->lock);
	/* XXX need to error check index if we can get one any longer */
	index = wdtoe_get_next_idx(wdtoe_dev_table);

	if (index < 0)
		goto out_err;

	/* XXX need error check for the following two functions */
	wdtoe_setup_cdev(wdtoe_dev, index);
	/* Create the char device entry on disk, i.e. under "/dev/" */
	wdtoe_create_cdev_entry(wdtoe_dev, index);
	uresp.dev_idx = index;

	/* Get the address where the uresp should be copy to */
	if (copy_from_user(&cmd, buf, sizeof(cmd)))
		return -EFAULT;

	/* Copy the uresp back to user space */
	if (copy_to_user((void __user *)(unsigned long)cmd.response,
				&uresp, sizeof(uresp)))
		return -EFAULT;

	return in_len;

out_err:
	printk(KERN_ERR "[wdtoe] %s: could not create a new "
			"WD-TOE device\n", __func__);
	return -EFAULT;
}

/*
 * Catch the "open()" call to the char dev for a WD-TOE stack. 
 * Save the "wdtoe_device" into kernel file pointer's private data, i.e.,
 * "filp->private_data". So next time a "wirte()" or "close()" happen, 
 * we can figure which "wdtoe_device" it is associated.
 */
int wdtoe_open(struct inode *inode, struct file *filp)
{
	struct wdtoe_device *dev;

	dev = container_of(inode->i_cdev, struct wdtoe_device, cdev);
	if (dev == NULL) {
		printk(KERN_ERR "[wdtoe] %s: could not get "
				"'struct wdtoe_device *'\n",
				__func__);
		/* XXX we need an error out here */
	}
	filp->private_data = dev;	/* store the dev pointer */

	return 0;
}

void t4_dump_iqe(const char *func_name, struct t4_iqe *iqe)
{
	int flit = -1;
	int len = sizeof(*iqe);
	int *value = (int *)iqe;

	while (len > 0) {
		if (len % 8 == 0)
			flit++;

		printk(KERN_ERR "%s: IQE [flit %d]: %#010x\n",
		       func_name, flit, ntohl(*value));
		value++;
		len -= 4;
	}
}

static inline int t4_valid_iqe(struct t4_iq *iq, struct t4_iqe *iqe)
{
	return (IQE_GENBIT(iqe) == iq->iq_shared_params->gen);
}

/* return 0 if there is an entry, -ENODATA otherwise */
static inline int t4_next_iqe(struct t4_iq *iq, struct t4_iqe **iqe)
{
	int ret;

	if (t4_valid_iqe(iq, &iq->queue[iq->iq_shared_params->cidx])) {
		*iqe = &iq->queue[iq->iq_shared_params->cidx];
		ret = 0;
	} else
		ret = -ENODATA;

	return ret;
}

static inline void t4_iq_consume(struct t4_iq *iq)
{
	/*
	 * write to GTS reg to update the
	 * cidx that has already been processed
	 */
	if (++iq->iq_shared_params->cidx_inc == (iq->size >> 4)) {
		uint32_t val;

		val = V_CIDXINC(iq->iq_shared_params->cidx_inc) | 
				V_TIMERREG(7) |
				V_INGRESSQID(iq->cntxt_id);
		/* write to the kernel GTS register */
		t4_write_reg(iq->adapter, MYPF_REG(A_SGE_PF_GTS), val);
		iq->iq_shared_params->cidx_inc = 0;
	}
	if (++iq->iq_shared_params->cidx == iq->size) {
		iq->iq_shared_params->cidx = 0;
		iq->iq_shared_params->gen ^= 1;
	}
}

static int wdtoe_process_responses( struct t4_iq *iq )
{
	struct t4_iqe *iqe;
	__be64 *rsp;
	u8 opcode;
	int ret;

	/* return 0 if there is an entry, -ENODATA otherwise */
	ret = t4_next_iqe(iq, &iqe);
	if (ret) 
		return ret;

	rsp = (__be64 *)iqe;

	/* we only cares about CPLs now, if the IQE is a FL entry */
	/* we just move on with the IQE, I.E. drop the data */
	if (IQE_IQTYPE(iqe) == X_RSPD_TYPE_CPL) {
		opcode = ((const struct rss_header *)rsp)->opcode;

		/*
		 * CPL_FW4_MSG is used by the firmware to encapsulate
		 * small CPLs. This has to do with the ULPTx bug.
		 * Wish I had the Bugzilla PR#, though.
		 */
		if (opcode == CPL_FW4_MSG &&
		    ((const struct cpl_fw4_msg *)rsp)->type == FW_TYPE_RSSCPL) {
			/*
			 * Move rsp pointer until we hit the RSS_HDR
			 * of the encapsulated CPL.
			 */
			rsp += 2;
		}

		t4_recv_rsp(cached_td, rsp);
	}

	/* move the index of the IQ */
	t4_iq_consume(iq);

	return ret;
}

static void wdtoe_drain_iq(struct t4_iq *iq)
{
	int ret = 0;
	/* process all the CPLs in the iq */
	while (!ret)
		ret = wdtoe_process_responses(iq);

}

/*
 * This is the main function to destroy a WD-TOE stack and release 
 * the resources.
 */
int wdtoe_close(struct inode *inode, struct file *filp)
{
	struct wdtoe_device *wd_dev;
	int i;
	int idx;
	int spin = 50000;

	wd_dev = (struct wdtoe_device *)filp->private_data;
	idx = wd_dev->index;
	/* If this wd_dev is marked as not up, no need to free resources */
	if (!wd_dev->in_use)
		goto out;

	/* Drain the IQ for the CPLs before releasing resources */

	/* FIXME here we need to spin a while before we give up */
	/* FIXME this is because when we reach here, we may have not */
	/* FIXME received the ACK of FIN from the peer. I.E. the IQ is */
	/* FIXME drained to be empty, but there will be more CPL coming. */
	/* FIXME The right thing to do is to have our own connection */
	/* FIXME management within WD-TOE: */
	/* FIXME We should look at all the connections associated with */
	/* FIXME this WD-TOE stack and if there is connection outstanding */
	/* FIXME we just spin here to wait... */
	/* FIXME Now we are spinning for 50k times, we probably want to */
	/* FIXME make this to be a fixed time duration, e.g. 100ms */

	while(spin) {
		for (i = 0; i < cached_lldi->nports; i++) {
			wdtoe_drain_iq(&wd_dev->rxq_list[i]->iq);
		}
		spin--;
	}

	/* As the stack has walked away from user space, */
	/* here we clear that entry from the listening_table */
	wdtoe_remove_listen_table_entry(listen_table, wd_dev->index);

	for (i = 0; i < cached_lldi->nports; i++) {
		wdtoe_free_raw_rxq(wd_dev->rxq_list[i], cached_lldi);
		wdtoe_free_raw_txq(wd_dev->txq_list[i], cached_lldi);
	}

	/* free up the memory for the data cache */
	for (i = 0; i < wd_dev->mempool_size; i++) {
		dma_free_coherent(&cached_lldi->pdev->dev,
				wd_dev->address_list_mempool[i].len,
				(void *) wd_dev->address_list_mempool[i].vaddr,
				wd_dev->address_list_mempool[i].daddr);
	}

	/* free up the memory for the "stack_info" structure */
	dma_free_coherent(&cached_lldi->pdev->dev, 
				wd_dev->stack_info.memsize,
				wd_dev->stack_info.desc,
				wd_dev->stack_info.dma_addr);
out:
	/* Unregister the "cdev" with system */
	cdev_del(&wd_dev->cdev);
	device_destroy(wdtoe_devclass, wd_dev->devno);

	/* Now it's time to recycle the entry for the index */
	wdtoe_recycle_idx(wdtoe_dev_table, idx);

	/*
	 * We are setting the tx_hold_thres according to the value
	 * that we found prior to setting it according to the
	 * /etc/wdtoe.conf configuration file.
	 *
	 * This operation takes effect only if there's no more
	 * WD-TOE stack up.
	 */
	if (!stacks)
		cached_td->conf.tx_hold_thres = original_tx_hold_thres;

	return 0;
}

unsigned int wdtoe_calc_opt2(const struct sock *sk,
			     const struct offload_settings *s,
			     struct wdtoe_device *wd_dev)
{
	const struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	unsigned int iq_id;

	/* XXX could iq_id fail by any chance? */
	iq_id = wd_dev->rxq_list[cplios->port_id]->iq.cntxt_id;

	return t4_calc_opt2(sk, s, iq_id);
}

/**
 * wdtoe_get_free_conn_tuple_slot - finds an empty tuple-array entry
 * @c: array of connection tuples
 * @idx: index of the free entry found, if any
 *
 * returns: pointer to the free entry and its index in the array
 */
static struct conn_tuple *wdtoe_get_free_conn_tuple_slot(struct conn_tuple *c,
							 unsigned short *idx)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if (!c[i].in_use) {
			*idx = i;
			return &c[i];
		}
	}

	return NULL;
}

/**
 * wdtoe_tuple_exists - checks if an (atid,lport) tuple exists in c
 * @c: array of connection tuples
 * @atid: atid part of the tuple [active tid]
 * @lport: lport part of the tuple [local port given by kernel stack]
 *
 * returns: 1 if tuple exists, 0 otherwise
 */
static int wdtoe_tuple_exists(struct conn_tuple *c, unsigned int atid,
						unsigned int lport)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if (c[i].in_use && c[i].atid == atid
				&& c[i].lport == lport)
			return 1;
	}

	return 0;
}

/**
 * wdtoe_insert_conn_tuple - inserts a conn_tuple in c (the conn_tuple array)
 * @c: array of connection tuples
 * @atid: atid part of the tuple [active tid]
 * @lport: lport part of the tuple [local port given by kernel stack]
 *
 * returns: index of the conn_tuple array where the tuple got inserted into,
 * or returns -1 if the tuple was found in the array or if there is no
 * empty slot in the array
 */
int wdtoe_insert_conn_tuple(struct conn_tuple *c, unsigned int atid,
			    unsigned int lport)
{
	int ret;
	unsigned short idx;
	struct conn_tuple *free_slot;

	ret = wdtoe_tuple_exists(c, atid, lport);

	if (ret)
		return -1;

	free_slot = wdtoe_get_free_conn_tuple_slot(c, &idx);

	if (!free_slot)
		return -1;

	free_slot->atid = atid;
	free_slot->lport = lport;
	free_slot->in_use = 1;

	return idx;
}

static inline int wdtoe_onchip_pa(struct cxgb4_lld_info *lldi, u64 pa)
{
	unsigned long oc_mw_pa = pci_resource_start(lldi->pdev, 2) +
				  (pci_resource_len(lldi->pdev, 2) -
				  roundup_pow_of_two(lldi->vr->ocq.size));

	return pa >= oc_mw_pa && pa < oc_mw_pa + lldi->vr->ocq.size;
}

static inline pgprot_t t4_pgprot_wc(pgprot_t prot)
{
#if defined(__i386__) || defined(__x86_64__)
        return pgprot_writecombine(prot);
#elif defined(CONFIG_PPC64)
        return __pgprot((pgprot_val(prot) | _PAGE_NO_CACHE) &
			~(pgprot_t)_PAGE_GUARDED);
#else
        return pgprot_noncached(prot);
#endif
}

int wdtoe_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct wdtoe_device *wd_dev;
	int len = vma->vm_end - vma->vm_start;
 	/* if a user calls mmap() with offset = N * PAGE_SIZE, */
	/* here we will receive N in vma->vm_pgoff. */
	/* We use N as the index to the wd_dev->address_list[] */
	int idx = (int)vma->vm_pgoff;
	int ret = 0;
	int offset;
	u64 paddr;
	u64 vaddr;

	wd_dev = (struct wdtoe_device *)filp->private_data;
	offset = wd_dev->mmap_element_offset;

	if (idx < wd_dev->mmap_element_offset) {
		// XXX we do not really need vaddr here, to be removed.
		spin_lock(&wd_dev->lock);
		paddr = wd_dev->address_list[idx].paddr;
		vaddr = wd_dev->address_list[idx].vaddr;
		spin_unlock(&wd_dev->lock);
	} else {
		spin_lock(&wd_dev->lock);
		paddr = wd_dev->address_list_mempool[idx - offset].paddr;
		vaddr = wd_dev->address_list_mempool[idx - offset].vaddr;
		spin_unlock(&wd_dev->lock);
	}

	if ((paddr >= pci_resource_start(cached_lldi->pdev, 0)) && 
		(paddr < (pci_resource_start(cached_lldi->pdev, 0) +
			pci_resource_len(cached_lldi->pdev, 0)))) {
		/*
		 * mapping kernel DB to user space
 		 */
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		ret = io_remap_pfn_range(vma, vma->vm_start,
						paddr >> PAGE_SHIFT,
						len, vma->vm_page_prot);
	} else if ((paddr >= pci_resource_start(cached_lldi->pdev, 2)) &&
		(paddr < (pci_resource_start(cached_lldi->pdev, 2) +
		 pci_resource_len(cached_lldi->pdev, 2)))) {
		/*
		 * Map user DB or OCQP memory...
 		 */
		if (wdtoe_onchip_pa(cached_lldi, paddr))
			vma->vm_page_prot = t4_pgprot_wc(vma->vm_page_prot);
		else {
			if (wd_dev->hca_type == T5_WDTOE)
				vma->vm_page_prot =
					t4_pgprot_wc(vma->vm_page_prot);
			else
				vma->vm_page_prot =
					pgprot_noncached(vma->vm_page_prot);
		}
		ret = io_remap_pfn_range(vma, vma->vm_start,
					paddr >> PAGE_SHIFT,
					len, vma->vm_page_prot);
	} else {
		/*
		 * mapping IQ anf FL to user space
 		 */
		ret = remap_pfn_range(vma, vma->vm_start, paddr >> PAGE_SHIFT,
						len, vma->vm_page_prot);
	}

	return ret;
}

int wdtoe_act_open_req(struct sock *sk, unsigned int atid, __be16 lport,
		       const struct offload_settings *s, __be32 *opt2)
{
	int idx;
	int ret;
	int idx_dev;
	struct wdtoe_device *wd_dev = NULL;

	idx = wdtoe_insert_conn_tuple(conn_tuple, atid, ntohs(lport));

	if (idx == -1)
		printk(KERN_ERR "[wdtoe] %s: could not insert tuple in "
				"'conn_tuple' array\n", __func__);

	/* get the wd-toe device according to the pid */
	ret = wdtoe_find_dev_by_pid(wdtoe_dev_table, &idx_dev,
				    current->pid);

	if (ret != 0) {
		printk(KERN_INFO "[wdtoe] could not get the wd_dev from "
				 "pid [%d]\n", current->pid);
		return -1;
	}

	wd_dev = wdtoe_dev_table[idx_dev].wd_dev;

	if (!wd_dev)
		return -1;

	/* follow the same logic as TOE but call wdtoe_calc_opt2() */
	if (likely(s))
		tcp_sk(sk)->rcv_tstamp = wdtoe_calc_opt2(sk, s, wd_dev);

	*opt2 = htonl(tcp_sk(sk)->rcv_tstamp);

	return 0;
}

int is_wdtoe(struct sock *sk)
{
	return sk->sk_priority == WDTOE_COOKIE;
}
