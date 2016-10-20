/*
 * network device
 */

#include <linux/version.h>
#ifdef KERNEL_HAS_EXPORT_H
#include <linux/export.h>
#endif
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/notifier.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/ethtool.h>
#include <linux/inetdevice.h>
#include <linux/if_vlan.h>
#include <net/addrconf.h>

#include <common/iscsi_queue.h>
#include <common/iscsi_offload.h>
#include <common/os_export.h>
#include <common/cxgb_dev.h>
#include <kernel/linux_compat.h>

chiscsi_queue *odevq = NULL;
struct offload_device_template odev_template[2];

struct offload_device_template * odev_template_get(int idx)
{
	return odev_template + idx;
}
EXPORT_SYMBOL(odev_template_get);

#if defined(__CH_DCB_SUPPORT__) && defined(CONFIG_DCB)
struct net_device *os_find_netdev_by_ipv4(__be32 ip)
{
	struct net_device *dev;

	for_each_netdev(&init_net, dev)
	{
		if (dev->flags & IFF_LOOPBACK)
			continue;
		if (inet_select_addr(dev, 0, RT_SCOPE_LINK) == ip) {
			if (dev->priv_flags & IFF_802_1Q_VLAN) 
				dev = vlan_dev_real_dev(dev);
			return dev;
		}
	}
	return NULL;
}
#endif

struct net_device *os_find_netdev_by_ipv6(struct in6_addr *addr, int check_lladdr)
{
	struct net_device *dev = NULL;
	struct inet6_dev *idev = NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	read_lock(&dev_base_lock);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
	for (dev = dev_base; dev; dev = dev->next)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	for_each_netdev(dev)
#else   
	for_each_netdev(&init_net, dev)
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22) */
#else
	rcu_read_lock();
	for_each_netdev_rcu(&init_net, dev) 
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33) */
	{
		idev = __in6_dev_get(dev);
		if (idev) {
			struct inet6_ifaddr *ifp;

			read_lock_bh(&idev->lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
			list_for_each_entry_reverse(ifp, &idev->addr_list, if_list)
#else
			for (ifp = idev->addr_list; ifp; ifp = ifp->if_next)
#endif
			{
				if (ifp->scope != IFA_LINK && check_lladdr)
					break;

				if (!(ifp->flags & IFA_F_TENTATIVE)) {
					if(!memcmp(addr, &ifp->addr, 16)) {
						read_unlock_bh(&idev->lock);
						rcu_read_unlock();
						return dev;
					}
				}

			}
                	read_unlock_bh(&idev->lock);
        	}
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	read_unlock(&dev_base_lock);
#else
	rcu_read_unlock();
#endif

	return NULL;
}

/* 
 * offload device 
 */
offload_device *offload_device_find_by_tdev(void *tdev)
{
        offload_device *odev;

        if (!odevq)
                return NULL;

        offload_device_qsearch_by_tdev(lock, odevq, odev, tdev);
        return odev;
}
EXPORT_SYMBOL(offload_device_find_by_tdev);

void offload_device_delete(offload_device *odev)
{
	offload_device_ch_qremove(lock, odevq, odev);
}
EXPORT_SYMBOL(offload_device_delete);

offload_device *offload_device_new_by_tdev(void *tdev)
{
        offload_device *odev;

        if (!odevq)
                return NULL;

        odev = os_alloc(sizeof(offload_device), 1, 1);
        if (odev) {
                /* os_alloc does the memset() */
                odev->d_tdev = tdev;
                offload_device_enqueue(lock, odevq, odev);
        }
        return odev;
}
EXPORT_SYMBOL(offload_device_new_by_tdev);

void os_sock_offload_info(iscsi_socket *isock)
{
	int i;
	unsigned int ttid = 0;
	void *tdev;

	for (i = 0; i < 2; i++)
		if (odev_template[i].ttid_min) {
			ttid = odev_template[i].isock_get_ttid(isock, &tdev);
			if (ttid)
				break;
		}
	if (!ttid)
		return;

	for (i = 0; i < 2; i++)
		if (ttid >= odev_template[i].ttid_min &&
			ttid <= odev_template[i].ttid_max) {
			odev_template[i].isock_offload_info(isock, tdev);
			break;
		}
}

void offload_device_remove_by_version(int version)
{
       offload_device *odev, *next;

       if (!odevq)
               return;
       
       os_lock(odevq->q_lock);
       for (odev = odevq->q_head; odev; odev = next) {
               next = odev->d_next;
               if (odev->d_version == version) {
                       offload_device_dequeue(nolock, odevq, odev);
                       if (odev->dev_release)
                               odev->dev_release(odev);
                       os_free(odev);
               }
       }
       os_unlock(odevq->q_lock); 
}
EXPORT_SYMBOL(offload_device_remove_by_version);


void offload_device_cleanup(void)
{
	if (odevq) {
		offload_device *odev, *next;
		os_lock(odevq->q_lock);
		for (odev = odevq->q_head; odev; odev = next) {
			next = odev->d_next;
			offload_device_dequeue(nolock, odevq, odev);
			if (odev->dev_release)
				odev->dev_release(odev);
			os_free(odev);
                }
		os_unlock(odevq->q_lock); 

		ch_queue_free(odevq);
		odevq = NULL;
	}
}

int offload_device_init(void)
{
	ch_queue_alloc(odevq);
	if (!odevq) 
		 return -ISCSI_ENOMEM;
	return 0;

q_lock_fail:
	ch_queue_free(odevq);
	return -ISCSI_ENOMEM;

}
