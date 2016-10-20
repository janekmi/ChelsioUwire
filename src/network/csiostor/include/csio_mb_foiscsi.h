/*
 *  Copyright (C) 2008-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description:
 *
 */

#ifndef __CSIO_MB_FOISCSI_H__
#define __CSIO_MB_FOISCSI_H__

#include <csio_foiscsi_persistent.h>

/* The forced speed, 10Mb, 100Mb, gigabit, 10GbE. */
#define SPEED_10				10
#define SPEED_100				100
#define SPEED_1000				1000
#define SPEED_10000				10000

/*#define ISCSI_MAX_SESSIONS_PER_ADAPTER		255*/
#define ISCSI_MAX_TARGETS_PER_BUS		255

/* FW guys said that they wont be supporting multiconnections for now */
#define ISCSI_MAX_CONNECTIONS_PER_SESSION	1

struct fw_ifconf_dhcp_info {
	__be32          addr;
	__be32          mask;
	__be16		vlanid;
	__be16		resv;
	__be32          bcaddr;
	__be32          gw;
};

struct fw_ifconf_addr6_info {
        __u8    prefix_len;
        __u8    res0;
        __u16   vlanid;
        __u32   res1;
        __be64  addr_hi;
        __be64  addr_lo;
        __be64  router_hi;
        __be64  router_lo;
};

struct iscsi_node_attr {
	u32 node_id;
	u32 init_r2t;
	u32 imm_data;
	u32 d_pdu_inorder;
	u32 d_seq_inorder;
	u32 err_rec_lvl;
	u32 auth_type;
	u32 h_digest;
	u32 d_digest;
	u32 max_recv_ds_len;
	u32 max_brst_len;
	u32 frst_brst_len;
	u32 max_out_r2t;
	u32 time_2_wait;
	u32 time_2_retain;
	u32 num_sessions;
	u8    name[FW_FOISCSI_NAME_MAX_LEN];
	u8    alias[FW_FOISCSI_NAME_MAX_LEN];
};

csio_retval_t csio_foiscsi_mb_fwevt_handler(struct csio_hw *, __be64 *);
void csio_foiscsi_fwevt_handler(struct csio_hw *, uint8_t, __be64 *);

#endif /* ifndef __CSIO_HW_ISCSI_H__ */
