#ifndef __LIBCXGBI_COMPAT_H__
#define __LIBCXGBI_COMPAT_H__

#include <linux/version.h> 
#include "../cxgbi_compat.h"

#if !defined(_VLAN_DEV_API_)
#include <linux/if_vlan.h>
#if defined(VLAN_DEV_INFO)
static inline struct vlan_dev_info *vlan_dev_info(const struct net_device *dev)
{
        return VLAN_DEV_INFO(dev);
}
#endif

static inline u16 vlan_dev_vlan_id(const struct net_device *dev)
{
        return vlan_dev_info(dev)->vlan_id;
}

static inline struct net_device *vlan_dev_real_dev(const struct net_device *dev)
{
        return vlan_dev_info(dev)->real_dev;
}
#endif /* _VLAN_DEV_API_ */

#ifndef IP_ROUTE_OUTPUT_NET
#define ip_route_output_flow(inet, rp, flp, sk, flags) \
        ip_route_output_flow(rp, flp, sk, flags) 
#endif

#if !defined(_IP6_RT_API_) && defined(CXGBI_IPV6_SUPPORT)
void ip6_rt_put(struct rt6_info *rt)
{
	struct dst_entry *dst;

	if (rt) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
		dst = &rt->u.dst;
#else
		dst = &rt->dst;
#endif
		dst_release(dst);
	}

}
#endif

#ifndef IP_DEV_FIND_NET
#define ip_dev_find(net, addr) ip_dev_find(addr)
#endif

#ifndef PDEV_MAPPING
#define dma_mapping_error(dev, dma_addr) \
        dma_mapping_error(dma_addr)
#endif

#if  !(defined FORMAT_MAC) && (defined __LIBCXGBI__)
static ssize_t sysfs_format_mac(char *buf, const unsigned char *addr, int len)
{
        int i;
        char *cp = buf;

        for (i = 0; i < len; i++)
                cp += sprintf(cp, "%02x%c", addr[i],
                              i == (len - 1) ? '\n' : ':');
        return cp - buf;
}
#endif

#ifndef LOG2_U32
static int __ilog2_u32(u32 n)
{
	return fls(n) - 1;
}
#endif

#endif
