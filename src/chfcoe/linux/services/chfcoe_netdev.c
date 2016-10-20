/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <linux/kernel.h>
#include <linux/notifier.h>
#include <linux/netdevice.h>
#include <net/dcbnl.h>
#include <net/dcbevent.h>
#include <linux/pci.h>

#include "chfcoe_os.h"

const unsigned int os_notifier_block_size = sizeof(struct notifier_block);

int os_dcb_get_prio(void *ndev)
{
	struct net_device *netdev = ndev;
	int dcbx;
	u8 up;
	struct dcb_app app = {
		.priority = 0,
		.protocol = ETH_P_FCOE
	};

	/* setup DCB priority attributes. */
	if (netdev && netdev->dcbnl_ops && netdev->dcbnl_ops->getdcbx) {
		dcbx = netdev->dcbnl_ops->getdcbx(netdev);

		if (dcbx & DCB_CAP_DCBX_VER_IEEE) {
			app.selector = IEEE_8021QAZ_APP_SEL_ETHERTYPE;
			up = dcb_ieee_getapp_mask(netdev, &app);
			if (up)
				return ffs(up) ? ffs(up) - 1 : 0;
		} 
		if (dcbx & DCB_CAP_DCBX_VER_CEE) {
			app.selector = DCB_APP_IDTYPE_ETHTYPE;
			up = dcb_getapp(netdev, &app);
			return ffs(up) ? ffs(up) - 1 : 0;
		}
	}

	return 0;
}

const char *os_netdev_name(void *ndev)
{
	return ((struct net_device *)ndev)->name;
}

bool os_netif_running(void *ndev)
{
	return netif_running((struct net_device *)ndev);
}

bool os_netif_carrier_ok(void *ndev)
{
	return netif_carrier_ok((struct net_device *)ndev);
}

unsigned short os_pdev_vendor(void *pdev)
{
	return ((struct pci_dev *)pdev)->vendor;
}

unsigned short os_pdev_device(void *pdev)
{
	return ((struct pci_dev *)pdev)->device;
}

void os_netdev_mac(void *ndev, void *mac)
{
	memcpy(mac, ((struct net_device *)ndev)->perm_addr, 6);
}

int os_netdev_mtu(void *ndev)
{
	return ((struct net_device *)ndev)->mtu;
}

int os_netdev_speed(void *devp)
{
	struct net_device *netdev = (struct net_device *)devp;
	struct ethtool_cmd etool;
	int rv;

	if (!netdev->ethtool_ops)
		return -EINVAL;

	if (!netdev->ethtool_ops->get_settings)
		return -EINVAL;

	rv = netdev->ethtool_ops->get_settings(netdev, &etool);
	if (rv < 0)
		return rv;

	if (etool.speed == SPEED_40000)
		return 40000;
	if (etool.speed == SPEED_10000)
		return 10000;
	if (etool.speed == SPEED_2500)
		return 2500;
	if (etool.speed == SPEED_1000)
		return 1000;
	if (etool.speed == SPEED_100)
		return 100;
	if (etool.speed == SPEED_10)
		return 10;

	return 0;
}

