/*
 * Copyright 2014-2015 (C) Chelsio Communications.  All rights reserved.
 *
 * Written by Kumar Sanghvi (kumaras@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Software in this file is covered under US Patent "Failover and migration
 * for full-offload network interface devices : US 8346919 B1".
 */

#include <linux/module.h>
#include "t4_ma_failover.h"
#include "cxgbtool.h"

#ifdef CONFIG_T4_MA_FAILOVER

extern void clear_filter(struct adapter *adap, struct filter_entry *f);
extern int writable_filter(struct filter_entry *f);
extern int set_filter_wr(struct adapter *adapter, int fidx, gfp_t gfp_mask);
extern int delete_filter(struct adapter *adapter, unsigned int fidx, gfp_t gfp_mask);

void init_ma_fail_data(struct port_info *p)
{

	p->ma_fail_data.flags = MA_FAILOVER_NONE;
	p->ma_fail_data.this_dev = p->ma_fail_data.backup_dev = NULL;
	atomic_set(&p->ma_fail_data.conn_moved, 0);
	p->ma_fail_data.fidx = p->ma_fail_data.fidx6 = -1;
}

int ma_fail_check_rx_pkt(struct port_info *pi, struct sk_buff *skb)
{
	if (pi->ma_fail_data.flags == MA_FAILOVER
			&& (skb->cb[0] == CPL_RX_PKT)) {
		/*
		 * If we are in ma-failover and above condition is
		 * true then, this packet is coming from peer, and
		 * is intended for the connection which still exists
		 * on failed_dev. So, loopback it.
		 */
		return 1;
	} else
		return 0;
}

int cxgb4_create_ma_failover_filter(const struct net_device *dev, 
				    u8 loop_port, unsigned int queue,
				    __be32 sip, u8 use_ipv6,
				    const struct in6_addr *sip6)
{
	int ret;
	struct filter_entry *f;
	struct adapter *adap;
	int i;
	int fidx;
	u8 *val;
	unsigned int chip_ver;
	u32 tid;

	adap = netdev2adap(dev);
	chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);

	if (chip_ver <= CHELSIO_T5) {
		if (use_ipv6)
			fidx = cxgb4_alloc_ftid(&adap->tids, PF_INET6);
		else
			fidx = cxgb4_alloc_ftid(&adap->tids, PF_INET);
		if (fidx < 0) {
			printk("%s: Could not get valid fidx..\n", __func__);
			return fidx;
		}
		tid = fidx + adap->tids.ftid_base;
	} else {
		if (use_ipv6)
			fidx = cxgb4_alloc_hpftid(&adap->tids, PF_INET6);
		else
			fidx = cxgb4_alloc_hpftid(&adap->tids, PF_INET);
		if (fidx < 0) {
			printk("%s: Could not get valid fidx..\n", __func__);
			return fidx;
		}
		tid = fidx + adap->tids.hpftid_base;
	}

	/*
	 * Check to make sure the filter requested is writable ...
	 */
	f = &adap->tids.ftid_tab[fidx];
	ret = writable_filter(f);
	if (ret)
		goto free_ftid;

	/*
	 * Clear out any old resources being used by the filter before
	 * we start constructing the new filter.
	 */
	if (f->valid)
		clear_filter(adap, f);

	/* Clear out filter specifications */
	memset(&f->fs, 0, sizeof(struct ch_filter_specification));
	f->fs.val.iport = loop_port;
	f->fs.mask.iport = ~0;

	if (use_ipv6) {
		val = (u8 *)sip6->s6_addr;
		for (i = 0; i < 16; i++) {
			f->fs.val.fip[i] = val[i];
			f->fs.mask.fip[i] = ~0;
		}
		f->fs.type = 1;
	} else {
		val = (u8 *)&sip;
		if ((val[0] | val[1] | val[2] | val[3]) != 0)
			for (i = 0; i < 4; i++) {
				f->fs.val.fip[i] = val[i];
				f->fs.mask.fip[i] = ~0;
			}
	}
	f->fs.dirsteer = 1;
	f->fs.iq = queue;
	/* Mark filter as locked */
	f->locked = 1;
	f->fs.rpttid = 1;
	f->fs.hitcnts = 1;
	f->fs.prio = 1;
	f->tid = tid;

	ret = set_filter_wr(adap, fidx, GFP_ATOMIC);
	if (ret) {
		clear_filter(adap, f);
		goto free_ftid;
	}

	return fidx;

free_ftid:
	if (is_t5(adap->params.chip)) {
		if (use_ipv6)
			cxgb4_clear_ftid(&adap->tids, fidx, PF_INET6);
		else
			cxgb4_clear_ftid(&adap->tids, fidx, PF_INET);
	} else {
		if (use_ipv6)
			cxgb4_clear_hpftid(&adap->tids, fidx, PF_INET6);
		else
			cxgb4_clear_hpftid(&adap->tids, fidx, PF_INET);
	}
	return ret;
}
EXPORT_SYMBOL(cxgb4_create_ma_failover_filter);

int cxgb4_delete_ma_failover_filter(const struct net_device *dev,
				    u8 use_ipv6, int fidx)
{

	int ret;
	struct adapter *adap;
	struct filter_entry *f;
	unsigned int chip_ver;

	adap = netdev2adap(dev);
	chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);

	f = &adap->tids.ftid_tab[fidx];
	/* Unlock the filter */
	f->locked = 0;

	ret = delete_filter(adap, fidx, GFP_ATOMIC);
	if(ret)
		return ret;

	if (chip_ver <= CHELSIO_T5) {
		if (use_ipv6)
			cxgb4_clear_ftid(&adap->tids, fidx, PF_INET6);
		else
			cxgb4_clear_ftid(&adap->tids, fidx, PF_INET);
	} else {
		if (use_ipv6)
			cxgb4_clear_hpftid(&adap->tids, fidx, PF_INET6);
		else
			cxgb4_clear_hpftid(&adap->tids, fidx, PF_INET);
	}

	return 0;

}
EXPORT_SYMBOL(cxgb4_delete_ma_failover_filter);

#endif /* CONFIG_T4_MA_FAILOVER */
