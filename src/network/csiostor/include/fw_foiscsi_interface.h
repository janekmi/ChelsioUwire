/*
 * ----------------------------------------------------------------------------
 * >>>>>>>>>>>>>>>>>>>>>>>>>>>>> COPYRIGHT NOTICE <<<<<<<<<<<<<<<<<<<<<<<<<<<<<
 * ----------------------------------------------------------------------------
 * Copyright (C) 2009-2014 Chelsio Communications, Inc. (Chelsio)
 *
 * Chelsio Communications, Inc. owns the sole copyright to this software.
 * You may not make a copy, you may not derive works herefrom, and you may
 * not distribute this work to others. Other restrictions of rights may apply
 * as well. This is unpublished, confidential information. All rights reserved.
 * This software contains confidential information and trade secrets of Chelsio
 * Communications, Inc. Use, disclosure, or reproduction is prohibited without
 * the prior express written permission of Chelsio Communications, Inc.
 * ----------------------------------------------------------------------------
 * >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Warranty <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
 * ----------------------------------------------------------------------------
 * CHELSIO MAKES NO WARRANTY OF ANY KIND WITH REGARD TO THE USE OF THIS
 * SOFTWARE, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 * ----------------------------------------------------------------------------
 *
 * Written May 2012 by Rakesh Ranjan (rakesh@chelsio.com)
 */

#ifndef __FW_FOISCSI_INTERFACE_H__
#define __FW_FOISCSI_INTERFACE_H__

/* 
 * FOiSCSI API private definitions
 *
 * */
struct fw_scsi_iscsi_data {
	__u8   r0;
	__u8   fbit_to_tattr;
	__be16 r2;
	__be32 r3;
	__u8   lun[8];
	__be32 r4;
	__be32 dlen;
	__be32 r5;
	__be32 r6;
	__u8   cdb[16];
} __attribute__((packed));

#define S_FW_SCSI_ISCSI_DATA_FBIT	7
#define M_FW_SCSI_ISCSI_DATA_FBIT	0x1
#define V_FW_SCSI_ISCSI_DATA_FBIT(x)	((x) << S_FW_SCSI_ISCSI_DATA_FBIT)
#define G_FW_SCSI_ISCSI_DATA_FBIT(x)	\
    (((x) >> S_FW_SCSI_ISCSI_DATA_FBIT) & M_FW_SCSI_ISCSI_DATA_FBIT)
#define F_FW_SCSI_ISCSI_DATA_FBIT	V_FW_SCSI_ISCSI_DATA_FBIT(1U)

#define S_FW_SCSI_ISCSI_DATA_RBIT	6
#define M_FW_SCSI_ISCSI_DATA_RBIT	0x1
#define V_FW_SCSI_ISCSI_DATA_RBIT(x)	((x) << S_FW_SCSI_ISCSI_DATA_RBIT)
#define G_FW_SCSI_ISCSI_DATA_RBIT(x)	\
    (((x) >> S_FW_SCSI_ISCSI_DATA_RBIT) & M_FW_SCSI_ISCSI_DATA_RBIT)
#define F_FW_SCSI_ISCSI_DATA_RBIT	V_FW_SCSI_ISCSI_DATA_RBIT(1U)

#define S_FW_SCSI_ISCSI_DATA_WBIT	5
#define M_FW_SCSI_ISCSI_DATA_WBIT	0x1
#define V_FW_SCSI_ISCSI_DATA_WBIT(x)	((x) << S_FW_SCSI_ISCSI_DATA_WBIT)
#define G_FW_SCSI_ISCSI_DATA_WBIT(x)	\
    (((x) >> S_FW_SCSI_ISCSI_DATA_WBIT) & M_FW_SCSI_ISCSI_DATA_WBIT)
#define F_FW_SCSI_ISCSI_DATA_WBIT	V_FW_SCSI_ISCSI_DATA_WBIT(1U)

#define S_FW_SCSI_ISCSI_DATA_TATTR	0
#define M_FW_SCSI_ISCSI_DATA_TATTR	0x7
#define V_FW_SCSI_ISCSI_DATA_TATTR(x)	((x) << S_FW_SCSI_ISCSI_DATA_TATTR)
#define G_FW_SCSI_ISCSI_DATA_TATTR(x)	\
    (((x) >> S_FW_SCSI_ISCSI_DATA_TATTR) & M_FW_SCSI_ISCSI_DATA_TATTR)

#define FW_SCSI_ISCSI_DATA_TATTR_UNTAGGED	0
#define FW_SCSI_ISCSI_DATA_TATTR_SIMPLE		1
#define	FW_SCSI_ISCSI_DATA_TATTR_ORDERED	2
#define FW_SCSI_ISCSI_DATA_TATTR_HEADOQ		3
#define FW_SCSI_ISCSI_DATA_TATTR_ACA		4

#define FW_SCSI_ISCSI_TMF_OP			0x02
#define FW_SCSI_ISCSI_ABORT_FUNC		0x01
#define FW_SCSI_ISCSI_LUN_RESET_FUNC		0x05
#define FW_SCSI_ISCSI_RESERVED_TAG		0xffffffff

struct fw_scsi_iscsi_rsp {
	__u8   r0;
	__u8   sbit_to_uflow;
	__u8   response;
	__u8   status;
	__be32 r4;
	__u8   r5[32];
	__be32 bidir_res_cnt;
	__be32 res_cnt;
	__u8   sense_data[128];
}__attribute__((packed)) ;

#define S_FW_SCSI_ISCSI_RSP_SBIT	7
#define M_FW_SCSI_ISCSI_RSP_SBIT	0x1
#define V_FW_SCSI_ISCSI_RSP_SBIT(x)	((x) << S_FW_SCSI_ISCSI_RSP_SBIT)
#define G_FW_SCSI_ISCSI_RSP_SBIT(x)	\
    (((x) >> S_FW_SCSI_ISCSI_RSP_SBIT) & M_FW_SCSI_ISCSI_RSP_SBIT)
#define F_FW_SCSI_ISCSI_RSP_SBIT	V_FW_SCSI_ISCSI_RSP_SBIT(1U)

#define S_FW_SCSI_ISCSI_RSP_BIDIR_OFLOW		4
#define M_FW_SCSI_ISCSI_RSP_BIDIR_OFLOW		0x1
#define V_FW_SCSI_ISCSI_RSP_BIDIR_OFLOW(x)	\
    ((x) << S_FW_SCSI_ISCSI_RSP_BIDIR_OFLOW)
#define G_FW_SCSI_ISCSI_RSP_BIDIR_OFLOW(x)	\
    (((x) >> S_FW_SCSI_ISCSI_RSP_BIDIR_OFLOW) & \
     M_FW_SCSI_ISCSI_RSP_BIDIR_OFLOW)
#define F_FW_SCSI_ISCSI_RSP_BIDIR_OFLOW	V_FW_SCSI_ISCSI_RSP_BIDIR_OFLOW(1U)

#define S_FW_SCSI_ISCSI_RSP_BIDIR_UFLOW		3
#define M_FW_SCSI_ISCSI_RSP_BIDIR_UFLOW		0x1
#define V_FW_SCSI_ISCSI_RSP_BIDIR_UFLOW(x)	\
    ((x) << S_FW_SCSI_ISCSI_RSP_BIDIR_UFLOW)
#define G_FW_SCSI_ISCSI_RSP_BIDIR_UFLOW(x)	\
    (((x) >> S_FW_SCSI_ISCSI_RSP_BIDIR_UFLOW) & \
     M_FW_SCSI_ISCSI_RSP_BIDIR_UFLOW)
#define F_FW_SCSI_ISCSI_RSP_BIDIR_UFLOW	V_FW_SCSI_ISCSI_RSP_BIDIR_UFLOW(1U)

#define S_FW_SCSI_ISCSI_RSP_OFLOW	2
#define M_FW_SCSI_ISCSI_RSP_OFLOW	0x1
#define V_FW_SCSI_ISCSI_RSP_OFLOW(x)	((x) << S_FW_SCSI_ISCSI_RSP_OFLOW)
#define G_FW_SCSI_ISCSI_RSP_OFLOW(x)	\
    (((x) >> S_FW_SCSI_ISCSI_RSP_OFLOW) & M_FW_SCSI_ISCSI_RSP_OFLOW)
#define F_FW_SCSI_ISCSI_RSP_OFLOW	V_FW_SCSI_ISCSI_RSP_OFLOW(1U)

#define S_FW_SCSI_ISCSI_RSP_UFLOW	1
#define M_FW_SCSI_ISCSI_RSP_UFLOW	0x1
#define V_FW_SCSI_ISCSI_RSP_UFLOW(x)	((x) << S_FW_SCSI_ISCSI_RSP_UFLOW)
#define G_FW_SCSI_ISCSI_RSP_UFLOW(x)	\
    (((x) >> S_FW_SCSI_ISCSI_RSP_UFLOW) & M_FW_SCSI_ISCSI_RSP_UFLOW)
#define F_FW_SCSI_ISCSI_RSP_UFLOW	V_FW_SCSI_ISCSI_RSP_UFLOW(1U)

enum fw_foiscsi_ctrl_io_state {
	FW_FOISCSI_CTRL_IO_STATE_ONLINE = 0,
	FW_FOISCSI_CTRL_IO_STATE_BLOCK,
	FW_FOISCSI_CTRL_IO_STATE_BLOCKED
};

#endif	/* __FW_FOISCSI_INTERFACE_H__ */
