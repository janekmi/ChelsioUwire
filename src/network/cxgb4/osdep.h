/*
 * This file is part of the Chelsio T4 Ethernet driver.
 *
 * Copyright (C) 2003-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __CXGB4_OSDEP_H
#define __CXGB4_OSDEP_H

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/ethtool.h>

#ifdef CONFIG_CHELSIO_T4_OFFLOAD_MODULE
# define CONFIG_CHELSIO_T4_OFFLOAD
#endif

typedef struct adapter adapter_t;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
#define CONFIG_CXGB4_GRO 1
#endif

#endif  /* !__CXGB4_OSDEP_H */
