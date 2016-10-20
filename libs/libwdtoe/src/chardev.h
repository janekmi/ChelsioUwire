#ifndef __LIBWDTOE_CHARDEV_H__
#define __LIBWDTOE_CHARDEV_H__

#include <asm/types.h>
#include "device.h"

#define GLOBAL_DEV_NODE		"/dev/wdtoe"
#define DEV_NODE_NAME_FMT	"/dev/wdtoe%u"

int open_global_chardev(void);
int create_wd_dev(struct wdtoe_device **wd_dev, int global_devfd);
int open_wd_dev(struct wdtoe_device *wd_dev);
int create_qp_set(struct wdtoe_device *wd_dev, int tx_hold_thres,
		  unsigned int *offset);
int map_stack_info(struct wdtoe_device *wd_dev, unsigned int *offset);
int create_sw_fl_and_sw_txq(struct wdtoe_device *wd_dev);
int map_sw_txq(struct wdtoe_device *wd_dev, unsigned int *idx);
int map_sw_fl(struct wdtoe_device *wd_dev, unsigned int idx);
int register_stack(struct wdtoe_device *wd_dev);
#endif
