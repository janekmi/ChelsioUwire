/*
 *  This file is part of the Chelsio T4 Ethernet driver for Linux.
 *  Copyright (C) 2003-2015 Chelsio Communications.  All rights reserved.
 *  
 *  This program is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 *  release for licensing terms and conditions.
 */

extern int max_eth_qsets;
extern int allow_nonroot_filters;
extern struct cxgb4_uld_info cxgb4_ulds[];
int cxgb4_closest_timer(const struct sge *s, int time);
int cxgb_extension_ioctl(struct net_device *dev, void __user *useraddr);

#ifdef CONFIG_CHELSIO_T4_OFFLOAD
int cxgb4_get_filter_count(struct adapter *adapter, unsigned int fidx,
			    u64 *c, int hash);
#endif
