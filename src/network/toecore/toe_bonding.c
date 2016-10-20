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

#include <linux/netdevice.h>
#include <net/sock.h>
#include <linux/toedev.h>
#include <linux/if_vlan.h>
#include <linux/version.h>
#include <net/ip.h>


#include "toe_bonding.h"

#include "toe_compat.h"

static struct net_device* (*toe_bond_rr_select_cb)(int slave_no,
						   struct net_device *bond_dev);
static struct net_device* (*toe_bond_acb_select_cb)(struct net_device *bond_dev);
static struct net_device* (*toe_bond_8023AD_select_cb)(int slave_agg_no,
						       struct net_device *dev);
static struct net_device* (*toe_bond_xor_select_cb)(int slave_no,
						    struct net_device *dev);

void register_toe_bond_rr_select_cb(struct net_device* (*fn)(int slave_no,
							     struct net_device *bond_dev))
{
	toe_bond_rr_select_cb = fn;
}
EXPORT_SYMBOL(register_toe_bond_rr_select_cb);

void register_toe_bond_acb_select_cb(struct net_device* (*fn)(struct net_device *bond_dev))
{
	toe_bond_acb_select_cb = fn;
}
EXPORT_SYMBOL(register_toe_bond_acb_select_cb);

void register_toe_bond_8023AD_select_cb(struct net_device* (*fn)(int slave_agg_no,
								 struct net_device *dev))
{
	toe_bond_8023AD_select_cb = fn;
}
EXPORT_SYMBOL(register_toe_bond_8023AD_select_cb);

void register_toe_bond_xor_select_cb(struct net_device* (*fn)(int slave_no,
							      struct net_device *dev))
{
	toe_bond_xor_select_cb = fn;
}
EXPORT_SYMBOL(register_toe_bond_xor_select_cb);

/*
 * Bonding for TOE.
 * Limitation(s):
 *	The slaves of a bonding device share the same TOEDEV:
 *	They are either ports of the same adapter,
 *	or bonding devices themselves.
 */

/* The NIC bonding driver sends packets for a single stream through available
 * slaves in a round robin manner, but in case of offload we do round robin
 * for connections. So the fist connection will go through first slave and the
 * second will go through second slave and third on first slave and so on for a
 * bond with two slaves.
 */
static struct net_device * toe_bond_rr_select(struct toe_hash_params *hash_params,
					       int context)
{
	struct bonding *bond = (struct bonding *)netdev_priv(hash_params->dev);
	struct net_device *slave_dev = NULL;
	int slave_no;

	if (context == TOE_OPEN)
		bond_read_lock_compat(bond);

	if (bond->slave_cnt == 0)
		goto out;

	/* toe_bond_rr_select() is called twice for a single offload
	  * connection and the hash genereated should be same. Hence using
	  * BOND_XMIT_POLICY_LAYER34 policy which uses 4 tuple to find out the
	  * hash, instead of using the nic bonding hash generation algo.
	  */
	slave_no = toe_bond_get_hash(hash_params, BOND_XMIT_POLICY_LAYER34,
				     bond->slave_cnt);
	if (likely(toe_bond_rr_select_cb))
		slave_dev = toe_bond_rr_select_cb(slave_no, hash_params->dev);

out:
	if (context == TOE_OPEN)
		bond_read_unlock_compat(bond);
	return (slave_dev);
}

/* Adapted from drivers/net/bonding/bond_main.c:bond_xmit_activebackup() */
static struct net_device * toe_bond_acb_select(struct net_device *dev,
					       int context)
{
	struct bonding *bond __attribute__((unused))
		= (struct bonding *)netdev_priv(dev);
	struct net_device *slave_dev = NULL;

	if (context == TOE_OPEN)
		bond_read_lock_compat(bond);

	if (likely(toe_bond_acb_select_cb))
		slave_dev = toe_bond_acb_select_cb(dev);

	if (context == TOE_OPEN)
		bond_read_unlock_compat(bond);
	return (slave_dev);
}

/*
 * Copy of Linux XOR Bonding Selection algorithm from
 * drivers/net/bonding/bond_main.c:bond_xmit_hash_policy_l34().
 */
static struct net_device * toe_bond_xor_select(struct toe_hash_params *hash_params,
					       int context)
{
	struct bonding *bond = (struct bonding *)netdev_priv(hash_params->dev);
	struct net_device *slave_dev = NULL;
	int slave_no;

	if (context == TOE_OPEN)
		bond_read_lock_compat(bond);

	if (bond->slave_cnt == 0)
		goto out;

	slave_no = toe_bond_get_hash(hash_params, bond->params.xmit_policy,
				     bond->slave_cnt);
	if (likely(toe_bond_xor_select_cb))
		slave_dev = toe_bond_xor_select_cb(slave_no, hash_params->dev);
out:
	if (context == TOE_OPEN)
		bond_read_unlock_compat(bond);
	return slave_dev;
}

/* Adapted from drivers/net/bonding/bond_3ad.c:__get_bond_by_port() */
static inline struct bonding *toe_bond_get_bond_by_port(struct port *port)
{
	if (port->slave == NULL) {
		return NULL;
	}

	return bond_get_bond_by_slave(port->slave);
}

/* Adapted from
 * drivers/net/bonding/bond_3ad.c:bond_3ad_get_active_agg_info() */
static int toe_bond_3ad_get_active_agg_info(struct bonding *bond,
					    struct ad_info *ad_info)
{
	struct aggregator *aggregator = NULL;
	bond_list_iter bond_list_iter;
	struct slave *slave;
	struct port *port;

	bond_for_each_slave_compat(bond, slave, bond_list_iter) {
		port = &(SLAVE_AD_INFO_COMPAT(slave))->port;
		if (port->aggregator && port->aggregator->is_active) {
			aggregator = port->aggregator;
			break;
		}
	}

	if (aggregator) {
		ad_info->aggregator_id = aggregator->aggregator_identifier;
		ad_info->ports = aggregator->num_of_ports;
		ad_info->actor_key = aggregator->actor_oper_aggregator_key;
		ad_info->partner_key = aggregator->partner_oper_aggregator_key;
		memcpy(ad_info->partner_system,
		       aggregator->partner_system.mac_addr_value, ETH_ALEN);
		return 0;
	}

	return -1;
}

/* Adapted from drivers/net/bonding/bond_3ad.c:bond_3ad_xmit_xor() */
static struct net_device * toe_bond_8023AD_select(struct toe_hash_params *hash_params,
                                         	  int context)
{
	struct bonding *bond = (struct bonding *)netdev_priv(hash_params->dev);
	struct net_device *slave_dev = NULL;
	int slave_agg_no;
	int slaves_in_agg;
	int agg_id;
	struct ad_info ad_info;

	if (context == TOE_OPEN)
		bond_read_lock_compat(bond);


	if (toe_bond_3ad_get_active_agg_info(bond, &ad_info)) {
		printk("%s: %s: Error: bond_3ad_get_active_agg_info failed\n",
			__func__, hash_params->dev->name);
		goto out;
	}

        slaves_in_agg = ad_info.ports;
        agg_id = ad_info.aggregator_id;

        if (slaves_in_agg == 0) {
                /*the aggregator is empty*/
                pr_debug("%s: Error: active aggregator is empty\n", hash_params->dev->name);
                goto out;
        }

	slave_agg_no = toe_bond_get_hash(hash_params, bond->params.xmit_policy,
					 slaves_in_agg);
	if (likely(toe_bond_8023AD_select_cb))
		slave_dev = toe_bond_8023AD_select_cb(slave_agg_no,
						      hash_params->dev);
	if (!slave_dev) {
		printk(KERN_ERR ": %s: Error: Couldn't find a slave "
		       "to tx on for aggregator ID %d\n", hash_params->dev->name, agg_id);
		goto out;
	}
out:
	if (context == TOE_OPEN)
		bond_read_unlock_compat(bond);

	return slave_dev;
}



struct net_device * toe_bond_get_slave(struct toe_hash_params *hash_params,
                                       int context)
{
	struct bonding *bond = (struct bonding *)netdev_priv(hash_params->dev);

	switch (bond->params.mode) {
	case BOND_MODE_ROUNDROBIN:
		return toe_bond_rr_select(hash_params, context);
	case BOND_MODE_ACTIVEBACKUP:
		return toe_bond_acb_select(hash_params->dev, context);
	case BOND_MODE_XOR:
		return toe_bond_xor_select(hash_params, context);
	case BOND_MODE_8023AD:
		return toe_bond_8023AD_select(hash_params, context);
	default:
		/* For unsupport bonding mode, return NULL */
		return NULL;
	}
}

void toe_bond_neigh_propagate(struct net_device *dev, struct neighbour *neigh)
{
	struct bonding *bond = (struct bonding *)netdev_priv(dev);
	struct slave *slave;
	bond_list_iter bond_list_iter;

	bond_for_each_slave_compat(bond, slave, bond_list_iter) {
		struct toedev *tdev = TOEDEV(slave->dev);

		/* Slave is a bonding device */
		if (slave->dev->flags & IFF_MASTER)
			toe_bond_neigh_propagate(slave->dev, neigh);

		/* Slave is a physical device. */
		else if (netdev_is_offload(dev) && tdev)
			tdev->neigh_update(tdev, neigh);
	}
}
