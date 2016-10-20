#ifndef __LINUX_COMPAT_H__
#define __LINUX_COMPAT_H__

#include <linux/version.h>

/*
 * 2.6.24 updated struct scatterlist
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#include <linux/scatterlist.h>
#define SG_GET_ADDR(sg)	sg_virt(sg)
#define SG_GET_PAGE(sg) sg_page(sg)
#define SG_SET_PAGE(sg, page) sg_assign_page(sg, page)

#else
#include <asm/scatterlist.h>
#define SG_GET_ADDR(sg)	(page_address((sg)->page) + (sg)->offset)
#define SG_GET_PAGE(sg)	((sg)->page)
#define SG_SET_ADDR(sg,page)	(sg)->page = page

#endif

/*
 * net_device
 */

/* netdev to device */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,21)
#define netdev_to_device(ndev)	(ndev)->dev.parent
#else
#define netdev_to_device(ndev)	(ndev)->class_dev.dev
#endif

/* virtual/perm mac address */
#define netdev_virt_addr_offset(dev) \
		(char *)(&(dev.dev_addr)) - ((char *)(&dev))

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,13)
#define netdev_perm_addr_offset(dev) \
		(((char *)&dev.perm_addr) - ((char *)&dev))
#else
#define netdev_perm_addr_offset		netdev_virt_addr_offset
#endif

#if (defined CONFIG_SUSE_KERNEL && LINUX_VERSION_CODE >= 132635)
#define SLE_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#if LINUX_VERSION_CODE == 132635
#define SLE_VERSION_CODE SLE_VERSION(11,0,0)
#elif LINUX_VERSION_CODE == 132640
#define SLE_VERSION_CODE SLE_VERSION(11,1,0)
#endif
#endif

#if (defined UBUNTU_VERSION_CODE && LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
#define UB_VFS_COMPAT
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
#include <linux/blkdev.h>
#define BIO_UPTODATE    0       /* ok after I/O completion */

static inline int bio_get_nr_vecs(struct block_device *bdev)
{
	struct request_queue *q = bdev_get_queue(bdev);
	int nr_pages;

	nr_pages = min_t(unsigned,
		     queue_max_segments(q),
		     queue_max_sectors(q) / (PAGE_SIZE >> 9) + 1);

	return min_t(unsigned, nr_pages, BIO_MAX_PAGES);
}
#endif

#endif /* ifndef __LINUX_COMPAT_H__ */
