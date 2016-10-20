/*
 * This file is part of the Chelsio T4/T5/T6 Virtual Function (VF) Ethernet
 * driver for Linux.
 *
 * Copyright (C) 2003-2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __T4VF_DEFS_H__
#define __T4VF_DEFS_H__

#include "t4_regs.h"

/*
 * The VF Register Map.
 *
 * The Scatter Gather Engine (SGE), Multiport Support module (MPS), PIO Local
 * bus module (PL) and CPU Interface Module (CIM) components are mapped via
 * the Slice to Module Map Table (see below) in the Physical Function Register
 * Map.  The Mail Box Data (MBDATA) range is mapped via the PCI-E Mailbox Base
 * and Offset registers in the PF Register Map.  The MBDATA base address is
 * quite constrained as it determines the Mailbox Data addresses for both PFs
 * and VFs, and therefore must fit in both the VF and PF Register Maps without
 * overlapping other registers.
 */
#define T4VF_SGE_BASE_ADDR	0x0000
#define T4VF_MPS_BASE_ADDR	0x0100
#define T4VF_PL_BASE_ADDR	0x0200
#define T4VF_MBDATA_BASE_ADDR	0x0240
#define T6VF_MBDATA_BASE_ADDR	0x0280
#define T4VF_CIM_BASE_ADDR	0x0300

#define T4VF_REGMAP_START	0x0000
#define T4VF_REGMAP_SIZE	0x0400

/*
 * There's no hardware limitation which requires that the addresses of the
 * Mailbox Data in the fixed CIM PF map and the programmable VF map must
 * match.  However, it's a useful convention ...
 */
#if T4VF_MBDATA_BASE_ADDR != A_CIM_PF_MAILBOX_DATA
#error T4VF_MBDATA_BASE_ADDR must match A_CIM_PF_MAILBOX_DATA!
#endif

/*
 * Virtual Function "Slice to Module Map Table" definitions.
 *
 * This table allows us to map subsets of the various module register sets
 * into the T4VF Register Map.  Each table entry identifies the index of the
 * module whose registers are being mapped, the offset within the module's
 * register set that the mapping should start at, the limit of the mapping,
 * and the offset within the T4VF Register Map to which the module's registers
 * are being mapped.  All addresses and qualtities are in terms of 32-bit
 * words.  The "limit" value is also in terms of 32-bit words and is equal to
 * the last address mapped in the T4VF Register Map 1 (i.e. it's a "<="
 * relation rather than a "<").
 */
#define T4VF_MOD_MAP(module, index, first, last) \
	T4VF_MOD_MAP_##module##_INDEX  = (index), \
	T4VF_MOD_MAP_##module##_FIRST  = (first), \
	T4VF_MOD_MAP_##module##_LAST   = (last), \
	T4VF_MOD_MAP_##module##_OFFSET = ((first)/4), \
	T4VF_MOD_MAP_##module##_BASE = \
		(T4VF_##module##_BASE_ADDR/4 + (first)/4), \
	T4VF_MOD_MAP_##module##_LIMIT = \
		(T4VF_##module##_BASE_ADDR/4 + (last)/4),

enum {
    T4VF_MOD_MAP(SGE, 2, A_SGE_VF_KDOORBELL, A_SGE_VF_GTS)
    T4VF_MOD_MAP(MPS, 0, A_MPS_VF_CTL, A_MPS_VF_STAT_RX_VF_ERR_FRAMES_H)
    T4VF_MOD_MAP(PL,  3, A_PL_VF_WHOAMI, A_PL_VF_WHOAMI)
    T4VF_MOD_MAP(CIM, 1, A_CIM_VF_EXT_MAILBOX_CTRL, A_CIM_VF_EXT_MAILBOX_STATUS)
};

/*
 * There isn't a Slice to Module Map Table entry for the Mailbox Data
 * registers, but it's convenient to use similar names as above.  There are 8
 * little-endian 64-bit Mailbox Data registers.  Note that the "instances"
 * value below is in terms of 32-bit words which matches the "word" addressing
 * space we use above for the Slice to Module Map Space.
 */
#define NUM_CIM_VF_MAILBOX_DATA_INSTANCES \
	NUM_CIM_PF_MAILBOX_DATA_INSTANCES

#define T4VF_MBDATA_FIRST	0
#define T4VF_MBDATA_LAST	((NUM_CIM_VF_MAILBOX_DATA_INSTANCES-1)*4)

#endif /* __T4T4VF_DEFS_H__ */
