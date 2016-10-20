/*
 * Copyright (c) 2015 Chelsio Communications, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *	copyright notice, this list of conditions and the following
 *	disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *	copyright notice, this list of conditions and the following
 *	disclaimer in the documentation and/or other materials
 *	provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef _COMMON_H
#define _COMMON_H

#include <linux/types.h>
#include <linux/string.h>
#include <asm/byteorder.h>

#include "profile.h"
#include "rbd_compat.h"

#define DBG(fmt, args...) \
do { \
	if (debug) \
		printk(fmt, ## args); \
} while (0)

#define htonll cpu_to_be64
#define ntohll be64_to_cpu
#define SINP(p) ((struct sockaddr_in *)(p))

#define DESTROY_TIMEOUT  200  /* 200iterations*10milliseconds = 2 sec */

/* Bitset representing status of active events. */
enum target_event_state {
	CM_ACTIVE_BIT = 0,
	CM_ACTIVE = (1 << CM_ACTIVE_BIT),

	POLL_ACTIVE_BIT = 1,
	POLL_ACTIVE = (1 << POLL_ACTIVE_BIT),

	DELETING_TARGET_BIT = 2,
	DELETING_TARGET = (1 << DELETING_TARGET_BIT)
};

#endif /* _COMMON_H */
