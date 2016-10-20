/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/*
 * Description:
 * 	This chfcoe_os_init.h header file have OS specific adapter defines.
 */

#ifndef __CHFCOE_OS_INIT_H__
#define __CHFCOE_OS_INIT_H__
#if defined(__KERNEL__)
#include <linux/kernel.h>
#include <linux/kref.h>
#include <asm/io.h>
#include <asm/bug.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <scsi/scsi.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_eh.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_tcq.h>
#include <scsi/scsi_cmnd.h>
#include <scst.h>
#include <asm/scatterlist.h>
#include <linux/mempool.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <asm/page.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/completion.h>
#include <linux/workqueue.h>
#include <linux/utsname.h>
#include <linux/skbuff.h>

#include <linux/cdev.h>
#include <chfcoe_adap.h>
#include <chfcoe_lib.h>
#include <common.h>

#define CHFCOE_DRV_AUTHOR	"Chelsio Communications, Inc"
#define CHFCOE_DRV_DESC		"Chelsio Partial Offload FCoE Driver"
#define CHFCOE_DRV_LICENSE	"GPL"
#define CHFCOE_DRV_VERSION	"2.12.0.3"

#define CHFCOE_MAX_CMINORS	1024
#define CHFCOE_CDEVFILE		KBUILD_MODNAME
#define CHFCOE_DRV_NAME		CHFCOE_CDEVFILE

#define chfcoe_param_check(name, def, min, max, typ)			\
static int __attribute__((used)) chfcoe_##name##_check(typ val)		\
{									\
        if (val >= min && val <= max) {					\
                chfcoe_##name = val;					\
                return 0;						\
        }								\
									\
	printk(KERN_ERR KBUILD_MODNAME": chfcoe_"#name" cannot be set to %d, "\
			  "Setting to default of "#def"\n", val);	\
        chfcoe_##name = def;						\
        return -EINVAL;							\
}

#define CHFCOE_MODULE_PARAM(name, def, min, max, desc, typ)		\
module_param(chfcoe_##name, typ, S_IRUGO);			\
MODULE_PARM_DESC(chfcoe_##name, desc);					\
chfcoe_param_check(name, def, min, max, typ)

typedef struct chfcoe_os_adap_info {
	struct chfcoe_list              lentry;
	struct chfcoe_adap_info		*adap;		/* Common Adap struct */
	struct cxgb4_lld_info		*lldi;		/* Lower-level driver
							 * Info struct
							 */
	struct pci_dev			*pdev;		/* Associated PCI dev */
	unsigned int                    id;
	unsigned char			max_wr_credits;	/* WR 16-byte credits */
#ifdef __CHFCOE_DEBUGFS__
	struct dentry			*debugfs_root;	/* Debug FS */
#endif
	struct cdev			cdev; 		/* IOCTL */
	enum chip_type                  adapter_type;
#ifdef __CHFCOE_TRACE_SUPPORT__
	struct chfcoe_oss_trace_buf	*trace_buffer;	/* Trace buffer */
#endif
} chfcoe_os_adap_info_t;

#define chfcoe_os_adap_info_size	(sizeof(struct chfcoe_os_adap_info) + chfcoe_adap_info_size)

#ifdef __CHFCOE_DEBUGFS__
/*
 * DebugFS related Defines
 */
int chfcoe_osdfs_init(void);
void chfcoe_osdfs_exit(void);
int chfcoe_osdfs_adap_init(chfcoe_os_adap_info_t *);
void chfcoe_osdfs_adap_exit(chfcoe_os_adap_info_t *);
#endif
#endif

/* This is shared between user and kernel space */
typedef struct chfcoe_ioctl_hdr {
	uint32_t cmd;
	uint32_t len;
	uint32_t dir;
} ioctl_hdr_t;
#endif
