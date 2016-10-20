/*
 * Copyright (C) 2003-2006 Chelsio Communications.  All rights reserved.
 *
 * Written by Divy Le Ray (divy@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */
#ifndef _TOE_BONDING_H
#define _TOE_BONDING_H

#if defined(BOND_SUPPORT)

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
#include <drivers/net/bonding/bonding.h>
#include <drivers/net/bonding/bond_3ad.h>
#else
#include <net/bonding.h>
#include <net/bond_3ad.h>
#endif

static inline int is_bmode_supported(struct net_device *bond_dev)
{
	struct bonding *bond = (struct bonding *)netdev_priv(bond_dev);
	int ret = 0;

	switch (bond->params.mode) {
	case BOND_MODE_ROUNDROBIN:
	case BOND_MODE_ACTIVEBACKUP:
	case BOND_MODE_8023AD:
	case BOND_MODE_XOR:
		ret = 1;
		break;
	case BOND_MODE_TLB:
	case BOND_MODE_ALB:
		/* unsupported or not yet supported */
		break;
	}
	return ret;
}

static inline struct toedev * toe_bond_slave_toedev(struct net_device *slave_dev)
{

        /* Do nothing if slaves are also bonding devices */
        if (slave_dev && !(slave_dev->flags & IFF_MASTER)) 
                return(TOEDEV(slave_dev));

        return NULL;
}

static inline int toe_bond_slavecnt(struct net_device *bond_dev)
{
	struct bonding *bond = (struct bonding *)netdev_priv(bond_dev);
	return bond->slave_cnt;
}

struct net_device * toe_bond_get_slave(struct toe_hash_params *hash_params,
				       int context);
void toe_bond_neigh_propagate(struct net_device *dev, struct neighbour *neigh);
#else
static inline int is_bmode_supported(struct net_device *bond_dev)
{
	return 0;
}

static inline struct net_device * toe_bond_get_slave(struct toe_hash_params *hash_params,
						     int context)
{
	return NULL;
}

static inline int toe_bond_slavecnt(struct net_device *bond_dev)
{
	return 0;
}

static inline struct toedev * toe_bond_slave_toedev(struct net_device *slave_dev)
{
	return NULL;
}

void toe_bond_neigh_propagate(struct net_device *dev, struct neighbour *neigh)
{}
#endif
#endif /* _TOE_BONDING_H */
