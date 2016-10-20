/*
 * This file is part of the Chelsio T4 TOM driver for Linux.
 *
 * Copyright (C) 2009-2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef _T4TOM_OFFLOAD_H
#define _T4TOM_OFFLOAD_H

#include <linux/list.h>
#include <linux/skbuff.h>
#include <net/offload.h>

#include "t4_tcb.h"
#include "l2t.h"

#include "t4_msg.h"

void t4tom_offload_init(void);
void t4tom_offload_exit(void);

enum {
	OFFLOAD_STATUS_UP,
	OFFLOAD_STATUS_DOWN
};

/* Flags for return value of CPL message handlers */
enum {
	CPL_RET_BUF_DONE = 1,   // buffer processing done, buffer may be freed
	CPL_RET_BAD_MSG = 2,    // bad CPL message (e.g., unknown opcode)
	CPL_RET_UNKNOWN_TID = 4	// unexpected unknown TID
};

/*
 * Returns a pointer to the first byte of the CPL header in an sk_buff that
 * contains a CPL message.
 */
static inline void *cplhdr(struct sk_buff *skb)
{
	return skb->data;
}

#endif
