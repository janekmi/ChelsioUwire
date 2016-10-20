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
 * 	This header file, contains DDP & page pod related defines.
 */
#ifndef __CHFCOE_DDP_H__
#define __CHFCOE_DDP_H__

#include "chfcoe_adap.h"

/* # of sentinel invalid page pods at the end of a group of valid page pods */
#define NUM_SENTINEL_PPODS	0

/* page pods are allocated in groups of this size (must be power of 2) */
#define PPOD_CLUSTER_SIZE	16

/* # of pages a pagepod can hold without needing another pagepod */
#define PPOD_PAGES		4U

struct chfcoe_pagepod {
	__be64 vld_tid_pgsz_tag_color;
	__be64 len_offset;
	__be64 rsvd;
	__be64 addr[PPOD_PAGES + 1];
};

#define CHFCOE_PPOD_SIZE	sizeof(struct chfcoe_pagepod)

#define S_PPOD_COLOR    0
#define M_PPOD_COLOR    0x3F
#define V_PPOD_COLOR(x) ((x) << S_PPOD_COLOR)

#define S_PPOD_TAG    6
#define M_PPOD_TAG    0xFFFFFF
#define V_PPOD_TAG(x) ((x) << S_PPOD_TAG)

#define S_PPOD_PGSZ    30
#define M_PPOD_PGSZ    0x3
#define V_PPOD_PGSZ(x) ((x) << S_PPOD_PGSZ)

#define S_PPOD_TID    32
#define M_PPOD_TID    0xFFFFFF
#define V_PPOD_TID(x) ((__u64)(x) << S_PPOD_TID)

#define S_PPOD_VALID    56
#define V_PPOD_VALID(x) ((__u64)(x) << S_PPOD_VALID)
#define F_PPOD_VALID    V_PPOD_VALID(1ULL)

#define S_PPOD_LEN    32
#define M_PPOD_LEN    0xFFFFFFFF
#define V_PPOD_LEN(x) ((__u64)(x) << S_PPOD_LEN)

#define S_PPOD_OFST    0
#define M_PPOD_OFST    0xFFFFFFFF
#define V_PPOD_OFST(x) ((x) << S_PPOD_OFST)

#define S_CPL_FCOE_HDR_RCTL     24
#define M_CPL_FCOE_HDR_RCTL     0xff
#define V_CPL_FCOE_HDR_RCTL(x)  ((x) << S_CPL_FCOE_HDR_RCTL)
#define G_CPL_FCOE_HDR_RCTL(x)  \
	(((x) >> S_CPL_FCOE_HDR_RCTL) & M_CPL_FCOE_HDR_RCTL)

#define S_CPL_FCOE_HDR_FCTL     0
#define M_CPL_FCOE_HDR_FCTL     0xffffff
#define V_CPL_FCOE_HDR_FCTL(x)  ((x) << S_CPL_FCOE_HDR_FCTL)
#define G_CPL_FCOE_HDR_FCTL(x)  \
	(((x) >> S_CPL_FCOE_HDR_FCTL) & M_CPL_FCOE_HDR_FCTL)

struct chfcoe_tid_to_xid {
	struct chfcoe_ioreq *req;
};


/*
 * Return the # of page pods needed to accommodate a # of pages.
 */
static inline unsigned int chfcoe_pages2ppods(unsigned int pages)
{
	return (pages + PPOD_PAGES - 1) / PPOD_PAGES + NUM_SENTINEL_PPODS;
} /* pages2ppods */

/* ddp flags */
enum {
	CHFCOE_DDP_VALID     = (1 << 0),
	CHFCOE_DDP_ERROR     = (1 << 1),
};

#define CHFCOE_TID_INVALID	0xffffffffU

typedef struct chfcoe_ddp {
	struct chfcoe_list list;
	unsigned int tid;
	unsigned int nppods;
	int ppod_tag;
	u8 flags;
	uint8_t chan;
} chfcoe_ddp_t;


#define NUM_IMM_PPODS		4
#define NUM_IMM_PPOD_BYTES	(NUM_IMM_PPODS * CHFCOE_PPOD_SIZE)
#define WR_LEN_MAX_PPODS	\
	(sizeof(struct ulp_mem_io) + \
	sizeof(struct ulptx_idata) + \
	NUM_IMM_PPOD_BYTES)

#define WR_CRED_MAX_PPODS	(CHFCOE_DIV_ROUND_UP(WR_LEN_MAX_PPODS, X_IDXSIZE_UNIT))

#define CHFCOE_MAX_PAGE_CNT		256 	/* To support 1MB, at 4K pagesize */
struct chfcoe_ioreq;
int chfcoe_pofcoe_tcb_wr_handler(struct chfcoe_adap_info *, const uint64_t *);
int chfcoe_cplrx_fcoe_ddp_handler(struct chfcoe_adap_info *, const uint64_t *);
int chfcoe_cplrx_fcoe_hdr_handler(struct chfcoe_adap_info *, const uint64_t *);
int chfcoe_ddp_setup(struct chfcoe_port_info *, struct chfcoe_ioreq *, 
		chfcoe_fc_buffer_t *fb);
int chfcoe_ppod_setup(struct chfcoe_port_info *, uint16_t, fc_header_t *);
int chfcoe_ddp_done(struct chfcoe_port_info *pi, struct chfcoe_ioreq *);

#endif /* __CHFCOE_DDP_H__ */
