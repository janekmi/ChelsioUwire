/*
 * Copyright (C) 2009-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 */

enum wr_opcodes {
	FW_FCOE_ELS_CT_WR              = 0x30,
	FW_SCSI_WRITE_WR               = 0x31,
	FW_SCSI_READ_WR                = 0x32,
	FW_SCSI_CMD_WR                 = 0x33,
	FW_SCSI_ABRT_CLS_WR            = 0x34,
	FW_SCSI_TGT_ACC_WR             = 0x35,
	FW_SCSI_TGT_XMIT_WR            = 0x36,
	FW_SCSI_TGT_RSP_WR             = 0x37,
	FW_RDEV_WR                     = 0x38,
	FW_RX_FCOE_DDP_WR              = 0x39,
        FW_FCOE_HDR_WR                 = 0x3a,
        FW_FIP_BP_WR                   = 0x3b,
        FW_SCSI_ABRT_RSP_WR            = 0x3f,
        FW_FCOE_ERR_WR                 = 0x40,
        FW_FCOE_ALLOC_TCB_WR           = 0x49,
};

enum fcoe_cmn_type {
	FCOE_ELS,
	FCOE_CT,
	FCOE_SCSI_CMD,
	FCOE_UNSOL_ELS,
};

#define SCSI_ABORT 0
#define SCSI_CLOSE 1

struct fw_fcoe_els_ct_wr {
	__be32 op_immdlen;
	__be32 flowid_len16;
	__be64 cookie;
	__be16 iqid;
	__u8   tmo_val;
	__u8   els_ct_type;
	__u8   ctl_pri;
	__u8   cp_en_class;
	__be16 xfer_cnt;
	__u8   fl_to_sp;
	__u8   l_id[3];
	__u8   r5;
	__u8   r_id[3];
	__be64 rsp_dmaaddr;
	__be32 rsp_dmalen;
	__be32 r6;
};

#define S_FW_FCOE_ELS_CT_WR_OPCODE	24
#define M_FW_FCOE_ELS_CT_WR_OPCODE	0xff
#define V_FW_FCOE_ELS_CT_WR_OPCODE(x)	((x) << S_FW_FCOE_ELS_CT_WR_OPCODE)
#define G_FW_FCOE_ELS_CT_WR_OPCODE(x)	\
    (((x) >> S_FW_FCOE_ELS_CT_WR_OPCODE) & M_FW_FCOE_ELS_CT_WR_OPCODE)

#define S_FW_FCOE_ELS_CT_WR_IMMDLEN	0
#define M_FW_FCOE_ELS_CT_WR_IMMDLEN	0xff
#define V_FW_FCOE_ELS_CT_WR_IMMDLEN(x)	((x) << S_FW_FCOE_ELS_CT_WR_IMMDLEN)
#define G_FW_FCOE_ELS_CT_WR_IMMDLEN(x)	\
    (((x) >> S_FW_FCOE_ELS_CT_WR_IMMDLEN) & M_FW_FCOE_ELS_CT_WR_IMMDLEN)

#define S_FW_FCOE_ELS_CT_WR_FLOWID	8
#define M_FW_FCOE_ELS_CT_WR_FLOWID	0xfffff
#define V_FW_FCOE_ELS_CT_WR_FLOWID(x)	((x) << S_FW_FCOE_ELS_CT_WR_FLOWID)
#define G_FW_FCOE_ELS_CT_WR_FLOWID(x)	\
    (((x) >> S_FW_FCOE_ELS_CT_WR_FLOWID) & M_FW_FCOE_ELS_CT_WR_FLOWID)

#define S_FW_FCOE_ELS_CT_WR_LEN16	0
#define M_FW_FCOE_ELS_CT_WR_LEN16	0xff
#define V_FW_FCOE_ELS_CT_WR_LEN16(x)	((x) << S_FW_FCOE_ELS_CT_WR_LEN16)
#define G_FW_FCOE_ELS_CT_WR_LEN16(x)	\
    (((x) >> S_FW_FCOE_ELS_CT_WR_LEN16) & M_FW_FCOE_ELS_CT_WR_LEN16)

#define S_FW_FCOE_ELS_CT_WR_CP_EN	6
#define M_FW_FCOE_ELS_CT_WR_CP_EN	0x3
#define V_FW_FCOE_ELS_CT_WR_CP_EN(x)	((x) << S_FW_FCOE_ELS_CT_WR_CP_EN)
#define G_FW_FCOE_ELS_CT_WR_CP_EN(x)	\
    (((x) >> S_FW_FCOE_ELS_CT_WR_CP_EN) & M_FW_FCOE_ELS_CT_WR_CP_EN)

#define S_FW_FCOE_ELS_CT_WR_CLASS	4
#define M_FW_FCOE_ELS_CT_WR_CLASS	0x3
#define V_FW_FCOE_ELS_CT_WR_CLASS(x)	((x) << S_FW_FCOE_ELS_CT_WR_CLASS)
#define G_FW_FCOE_ELS_CT_WR_CLASS(x)	\
    (((x) >> S_FW_FCOE_ELS_CT_WR_CLASS) & M_FW_FCOE_ELS_CT_WR_CLASS)

#define S_FW_FCOE_ELS_CT_WR_FL		2
#define M_FW_FCOE_ELS_CT_WR_FL		0x1
#define V_FW_FCOE_ELS_CT_WR_FL(x)	((x) << S_FW_FCOE_ELS_CT_WR_FL)
#define G_FW_FCOE_ELS_CT_WR_FL(x)	\
    (((x) >> S_FW_FCOE_ELS_CT_WR_FL) & M_FW_FCOE_ELS_CT_WR_FL)
#define F_FW_FCOE_ELS_CT_WR_FL	V_FW_FCOE_ELS_CT_WR_FL(1U)

#define S_FW_FCOE_ELS_CT_WR_NPIV	1
#define M_FW_FCOE_ELS_CT_WR_NPIV	0x1
#define V_FW_FCOE_ELS_CT_WR_NPIV(x)	((x) << S_FW_FCOE_ELS_CT_WR_NPIV)
#define G_FW_FCOE_ELS_CT_WR_NPIV(x)	\
    (((x) >> S_FW_FCOE_ELS_CT_WR_NPIV) & M_FW_FCOE_ELS_CT_WR_NPIV)
#define F_FW_FCOE_ELS_CT_WR_NPIV	V_FW_FCOE_ELS_CT_WR_NPIV(1U)

#define S_FW_FCOE_ELS_CT_WR_SP		0
#define M_FW_FCOE_ELS_CT_WR_SP		0x1
#define V_FW_FCOE_ELS_CT_WR_SP(x)	((x) << S_FW_FCOE_ELS_CT_WR_SP)
#define G_FW_FCOE_ELS_CT_WR_SP(x)	\
    (((x) >> S_FW_FCOE_ELS_CT_WR_SP) & M_FW_FCOE_ELS_CT_WR_SP)
#define F_FW_FCOE_ELS_CT_WR_SP	V_FW_FCOE_ELS_CT_WR_SP(1U)

struct fw_scsi_write_wr {
	__be32 op_immdlen;
	__be32 flowid_len16;
	__be64 cookie;
	__be16 iqid;
	__u8   tmo_val;
	__u8   use_xfer_cnt;
	union fw_scsi_write_priv {
		struct fcoe_write_priv {
			__u8   ctl_pri;
			__u8   cp_en_class;
			__u8   r3_lo[2];
		} fcoe;
		struct iscsi_write_priv {
			__u8   r3[4];
		} iscsi;
	} u;
	__be32 xfer_cnt;
	__be32 ini_xfer_cnt;
	__be64 rsp_dmaaddr;
	__be32 rsp_dmalen;
	__be32 r4;
};

#define S_FW_SCSI_WRITE_WR_OPCODE	24
#define M_FW_SCSI_WRITE_WR_OPCODE	0xff
#define V_FW_SCSI_WRITE_WR_OPCODE(x)	((x) << S_FW_SCSI_WRITE_WR_OPCODE)
#define G_FW_SCSI_WRITE_WR_OPCODE(x)	\
    (((x) >> S_FW_SCSI_WRITE_WR_OPCODE) & M_FW_SCSI_WRITE_WR_OPCODE)

#define S_FW_SCSI_WRITE_WR_IMMDLEN	0
#define M_FW_SCSI_WRITE_WR_IMMDLEN	0xff
#define V_FW_SCSI_WRITE_WR_IMMDLEN(x)	((x) << S_FW_SCSI_WRITE_WR_IMMDLEN)
#define G_FW_SCSI_WRITE_WR_IMMDLEN(x)	\
    (((x) >> S_FW_SCSI_WRITE_WR_IMMDLEN) & M_FW_SCSI_WRITE_WR_IMMDLEN)

#define S_FW_SCSI_WRITE_WR_FLOWID	8
#define M_FW_SCSI_WRITE_WR_FLOWID	0xfffff
#define V_FW_SCSI_WRITE_WR_FLOWID(x)	((x) << S_FW_SCSI_WRITE_WR_FLOWID)
#define G_FW_SCSI_WRITE_WR_FLOWID(x)	\
    (((x) >> S_FW_SCSI_WRITE_WR_FLOWID) & M_FW_SCSI_WRITE_WR_FLOWID)

#define S_FW_SCSI_WRITE_WR_LEN16	0
#define M_FW_SCSI_WRITE_WR_LEN16	0xff
#define V_FW_SCSI_WRITE_WR_LEN16(x)	((x) << S_FW_SCSI_WRITE_WR_LEN16)
#define G_FW_SCSI_WRITE_WR_LEN16(x)	\
    (((x) >> S_FW_SCSI_WRITE_WR_LEN16) & M_FW_SCSI_WRITE_WR_LEN16)

#define S_FW_SCSI_WRITE_WR_CP_EN	6
#define M_FW_SCSI_WRITE_WR_CP_EN	0x3
#define V_FW_SCSI_WRITE_WR_CP_EN(x)	((x) << S_FW_SCSI_WRITE_WR_CP_EN)
#define G_FW_SCSI_WRITE_WR_CP_EN(x)	\
    (((x) >> S_FW_SCSI_WRITE_WR_CP_EN) & M_FW_SCSI_WRITE_WR_CP_EN)

#define S_FW_SCSI_WRITE_WR_CLASS	4
#define M_FW_SCSI_WRITE_WR_CLASS	0x3
#define V_FW_SCSI_WRITE_WR_CLASS(x)	((x) << S_FW_SCSI_WRITE_WR_CLASS)
#define G_FW_SCSI_WRITE_WR_CLASS(x)	\
    (((x) >> S_FW_SCSI_WRITE_WR_CLASS) & M_FW_SCSI_WRITE_WR_CLASS)

struct fw_scsi_read_wr {
	__be32 op_immdlen;
	__be32 flowid_len16;
	__be64 cookie;
	__be16 iqid;
	__u8   tmo_val;
	__u8   use_xfer_cnt;
	union fw_scsi_read_priv {
		struct fcoe_read_priv {
			__u8   ctl_pri;
			__u8   cp_en_class;
			__u8   r3_lo[2];
		} fcoe;
		struct iscsi_read_priv {
			__u8   r3[4];
		} iscsi;
	} u;
	__be32 xfer_cnt;
	__be32 ini_xfer_cnt;
	__be64 rsp_dmaaddr;
	__be32 rsp_dmalen;
	__be32 r4;
};

#define S_FW_SCSI_READ_WR_OPCODE	24
#define M_FW_SCSI_READ_WR_OPCODE	0xff
#define V_FW_SCSI_READ_WR_OPCODE(x)	((x) << S_FW_SCSI_READ_WR_OPCODE)
#define G_FW_SCSI_READ_WR_OPCODE(x)	\
    (((x) >> S_FW_SCSI_READ_WR_OPCODE) & M_FW_SCSI_READ_WR_OPCODE)

#define S_FW_SCSI_READ_WR_IMMDLEN	0
#define M_FW_SCSI_READ_WR_IMMDLEN	0xff
#define V_FW_SCSI_READ_WR_IMMDLEN(x)	((x) << S_FW_SCSI_READ_WR_IMMDLEN)
#define G_FW_SCSI_READ_WR_IMMDLEN(x)	\
    (((x) >> S_FW_SCSI_READ_WR_IMMDLEN) & M_FW_SCSI_READ_WR_IMMDLEN)

#define S_FW_SCSI_READ_WR_FLOWID	8
#define M_FW_SCSI_READ_WR_FLOWID	0xfffff
#define V_FW_SCSI_READ_WR_FLOWID(x)	((x) << S_FW_SCSI_READ_WR_FLOWID)
#define G_FW_SCSI_READ_WR_FLOWID(x)	\
    (((x) >> S_FW_SCSI_READ_WR_FLOWID) & M_FW_SCSI_READ_WR_FLOWID)

#define S_FW_SCSI_READ_WR_LEN16		0
#define M_FW_SCSI_READ_WR_LEN16		0xff
#define V_FW_SCSI_READ_WR_LEN16(x)	((x) << S_FW_SCSI_READ_WR_LEN16)
#define G_FW_SCSI_READ_WR_LEN16(x)	\
    (((x) >> S_FW_SCSI_READ_WR_LEN16) & M_FW_SCSI_READ_WR_LEN16)

#define S_FW_SCSI_READ_WR_CP_EN		6
#define M_FW_SCSI_READ_WR_CP_EN		0x3
#define V_FW_SCSI_READ_WR_CP_EN(x)	((x) << S_FW_SCSI_READ_WR_CP_EN)
#define G_FW_SCSI_READ_WR_CP_EN(x)	\
    (((x) >> S_FW_SCSI_READ_WR_CP_EN) & M_FW_SCSI_READ_WR_CP_EN)

#define S_FW_SCSI_READ_WR_CLASS		4
#define M_FW_SCSI_READ_WR_CLASS		0x3
#define V_FW_SCSI_READ_WR_CLASS(x)	((x) << S_FW_SCSI_READ_WR_CLASS)
#define G_FW_SCSI_READ_WR_CLASS(x)	\
    (((x) >> S_FW_SCSI_READ_WR_CLASS) & M_FW_SCSI_READ_WR_CLASS)

struct fw_scsi_cmd_wr {
	__be32 op_immdlen;
	__be32 flowid_len16;
	__be64 cookie;
	__be16 iqid;
	__u8   tmo_val;
	__u8   r3;
	union fw_scsi_cmd_priv {
		struct fcoe_cmd_priv {
			__u8   ctl_pri;
			__u8   cp_en_class;
			__u8   r4_lo[2];
		} fcoe;
		struct iscsi_cmd_priv {
			__u8   r4[4];
		} iscsi;
	} u;
	__u8   r5[8];
	__be64 rsp_dmaaddr;
	__be32 rsp_dmalen;
	__be32 r6;
};

#define S_FW_SCSI_CMD_WR_OPCODE		24
#define M_FW_SCSI_CMD_WR_OPCODE		0xff
#define V_FW_SCSI_CMD_WR_OPCODE(x)	((x) << S_FW_SCSI_CMD_WR_OPCODE)
#define G_FW_SCSI_CMD_WR_OPCODE(x)	\
    (((x) >> S_FW_SCSI_CMD_WR_OPCODE) & M_FW_SCSI_CMD_WR_OPCODE)

#define S_FW_SCSI_CMD_WR_IMMDLEN	0
#define M_FW_SCSI_CMD_WR_IMMDLEN	0xff
#define V_FW_SCSI_CMD_WR_IMMDLEN(x)	((x) << S_FW_SCSI_CMD_WR_IMMDLEN)
#define G_FW_SCSI_CMD_WR_IMMDLEN(x)	\
    (((x) >> S_FW_SCSI_CMD_WR_IMMDLEN) & M_FW_SCSI_CMD_WR_IMMDLEN)

#define S_FW_SCSI_CMD_WR_FLOWID		8
#define M_FW_SCSI_CMD_WR_FLOWID		0xfffff
#define V_FW_SCSI_CMD_WR_FLOWID(x)	((x) << S_FW_SCSI_CMD_WR_FLOWID)
#define G_FW_SCSI_CMD_WR_FLOWID(x)	\
    (((x) >> S_FW_SCSI_CMD_WR_FLOWID) & M_FW_SCSI_CMD_WR_FLOWID)

#define S_FW_SCSI_CMD_WR_LEN16		0
#define M_FW_SCSI_CMD_WR_LEN16		0xff
#define V_FW_SCSI_CMD_WR_LEN16(x)	((x) << S_FW_SCSI_CMD_WR_LEN16)
#define G_FW_SCSI_CMD_WR_LEN16(x)	\
    (((x) >> S_FW_SCSI_CMD_WR_LEN16) & M_FW_SCSI_CMD_WR_LEN16)

#define S_FW_SCSI_CMD_WR_CP_EN		6
#define M_FW_SCSI_CMD_WR_CP_EN		0x3
#define V_FW_SCSI_CMD_WR_CP_EN(x)	((x) << S_FW_SCSI_CMD_WR_CP_EN)
#define G_FW_SCSI_CMD_WR_CP_EN(x)	\
    (((x) >> S_FW_SCSI_CMD_WR_CP_EN) & M_FW_SCSI_CMD_WR_CP_EN)

#define S_FW_SCSI_CMD_WR_CLASS		4
#define M_FW_SCSI_CMD_WR_CLASS		0x3
#define V_FW_SCSI_CMD_WR_CLASS(x)	((x) << S_FW_SCSI_CMD_WR_CLASS)
#define G_FW_SCSI_CMD_WR_CLASS(x)	\
    (((x) >> S_FW_SCSI_CMD_WR_CLASS) & M_FW_SCSI_CMD_WR_CLASS)

struct fw_scsi_abrt_cls_wr {
	__be32 op_immdlen;
	__be32 flowid_len16;
	__be64 cookie;
	__be16 iqid;
	__u8   tmo_val;
	__u8   sub_opcode_to_chk_all_io;
	__u8   r3[4];
	__be64 t_cookie;
};

#define S_FW_SCSI_ABRT_CLS_WR_OPCODE	24
#define M_FW_SCSI_ABRT_CLS_WR_OPCODE	0xff
#define V_FW_SCSI_ABRT_CLS_WR_OPCODE(x)	((x) << S_FW_SCSI_ABRT_CLS_WR_OPCODE)
#define G_FW_SCSI_ABRT_CLS_WR_OPCODE(x)	\
    (((x) >> S_FW_SCSI_ABRT_CLS_WR_OPCODE) & M_FW_SCSI_ABRT_CLS_WR_OPCODE)

#define S_FW_SCSI_ABRT_CLS_WR_IMMDLEN		0
#define M_FW_SCSI_ABRT_CLS_WR_IMMDLEN		0xff
#define V_FW_SCSI_ABRT_CLS_WR_IMMDLEN(x)	\
    ((x) << S_FW_SCSI_ABRT_CLS_WR_IMMDLEN)
#define G_FW_SCSI_ABRT_CLS_WR_IMMDLEN(x)	\
    (((x) >> S_FW_SCSI_ABRT_CLS_WR_IMMDLEN) & M_FW_SCSI_ABRT_CLS_WR_IMMDLEN)

#define S_FW_SCSI_ABRT_CLS_WR_FLOWID	8
#define M_FW_SCSI_ABRT_CLS_WR_FLOWID	0xfffff
#define V_FW_SCSI_ABRT_CLS_WR_FLOWID(x)	((x) << S_FW_SCSI_ABRT_CLS_WR_FLOWID)
#define G_FW_SCSI_ABRT_CLS_WR_FLOWID(x)	\
    (((x) >> S_FW_SCSI_ABRT_CLS_WR_FLOWID) & M_FW_SCSI_ABRT_CLS_WR_FLOWID)

#define S_FW_SCSI_ABRT_CLS_WR_LEN16	0
#define M_FW_SCSI_ABRT_CLS_WR_LEN16	0xff
#define V_FW_SCSI_ABRT_CLS_WR_LEN16(x)	((x) << S_FW_SCSI_ABRT_CLS_WR_LEN16)
#define G_FW_SCSI_ABRT_CLS_WR_LEN16(x)	\
    (((x) >> S_FW_SCSI_ABRT_CLS_WR_LEN16) & M_FW_SCSI_ABRT_CLS_WR_LEN16)

#define S_FW_SCSI_ABRT_CLS_WR_SUB_OPCODE	2
#define M_FW_SCSI_ABRT_CLS_WR_SUB_OPCODE	0x3f
#define V_FW_SCSI_ABRT_CLS_WR_SUB_OPCODE(x)	\
    ((x) << S_FW_SCSI_ABRT_CLS_WR_SUB_OPCODE)
#define G_FW_SCSI_ABRT_CLS_WR_SUB_OPCODE(x)	\
    (((x) >> S_FW_SCSI_ABRT_CLS_WR_SUB_OPCODE) & \
     M_FW_SCSI_ABRT_CLS_WR_SUB_OPCODE)

#define S_FW_SCSI_ABRT_CLS_WR_UNSOL	1
#define M_FW_SCSI_ABRT_CLS_WR_UNSOL	0x1
#define V_FW_SCSI_ABRT_CLS_WR_UNSOL(x)	((x) << S_FW_SCSI_ABRT_CLS_WR_UNSOL)
#define G_FW_SCSI_ABRT_CLS_WR_UNSOL(x)	\
    (((x) >> S_FW_SCSI_ABRT_CLS_WR_UNSOL) & M_FW_SCSI_ABRT_CLS_WR_UNSOL)
#define F_FW_SCSI_ABRT_CLS_WR_UNSOL	V_FW_SCSI_ABRT_CLS_WR_UNSOL(1U)

#define S_FW_SCSI_ABRT_CLS_WR_CHK_ALL_IO	0
#define M_FW_SCSI_ABRT_CLS_WR_CHK_ALL_IO	0x1
#define V_FW_SCSI_ABRT_CLS_WR_CHK_ALL_IO(x)	\
    ((x) << S_FW_SCSI_ABRT_CLS_WR_CHK_ALL_IO)
#define G_FW_SCSI_ABRT_CLS_WR_CHK_ALL_IO(x)	\
    (((x) >> S_FW_SCSI_ABRT_CLS_WR_CHK_ALL_IO) & \
     M_FW_SCSI_ABRT_CLS_WR_CHK_ALL_IO)
#define F_FW_SCSI_ABRT_CLS_WR_CHK_ALL_IO	\
    V_FW_SCSI_ABRT_CLS_WR_CHK_ALL_IO(1U)

struct fw_scsi_tgt_acc_wr {
	__be32 op_immdlen;
	__be32 flowid_len16;
	__be64 cookie;
	__be16 iqid;
	__u8   r3;
	__u8   use_burst_len;
	union fw_scsi_tgt_acc_priv {
		struct fcoe_tgt_acc_priv {
			__u8   ctl_pri;
			__u8   cp_en_class;
			__u8   r4_lo[2];
		} fcoe;
		struct iscsi_tgt_acc_priv {
			__u8   r4[4];
		} iscsi;
	} u;
	__be32 burst_len;
	__be32 rel_off;
	__be64 r5;
	__be32 r6;
	__be32 tot_xfer_len;
};

#define S_FW_SCSI_TGT_ACC_WR_OPCODE	24
#define M_FW_SCSI_TGT_ACC_WR_OPCODE	0xff
#define V_FW_SCSI_TGT_ACC_WR_OPCODE(x)	((x) << S_FW_SCSI_TGT_ACC_WR_OPCODE)
#define G_FW_SCSI_TGT_ACC_WR_OPCODE(x)	\
    (((x) >> S_FW_SCSI_TGT_ACC_WR_OPCODE) & M_FW_SCSI_TGT_ACC_WR_OPCODE)

#define S_FW_SCSI_TGT_ACC_WR_IMMDLEN	0
#define M_FW_SCSI_TGT_ACC_WR_IMMDLEN	0xff
#define V_FW_SCSI_TGT_ACC_WR_IMMDLEN(x)	((x) << S_FW_SCSI_TGT_ACC_WR_IMMDLEN)
#define G_FW_SCSI_TGT_ACC_WR_IMMDLEN(x)	\
    (((x) >> S_FW_SCSI_TGT_ACC_WR_IMMDLEN) & M_FW_SCSI_TGT_ACC_WR_IMMDLEN)

#define S_FW_SCSI_TGT_ACC_WR_FLOWID	8
#define M_FW_SCSI_TGT_ACC_WR_FLOWID	0xfffff
#define V_FW_SCSI_TGT_ACC_WR_FLOWID(x)	((x) << S_FW_SCSI_TGT_ACC_WR_FLOWID)
#define G_FW_SCSI_TGT_ACC_WR_FLOWID(x)	\
    (((x) >> S_FW_SCSI_TGT_ACC_WR_FLOWID) & M_FW_SCSI_TGT_ACC_WR_FLOWID)

#define S_FW_SCSI_TGT_ACC_WR_LEN16	0
#define M_FW_SCSI_TGT_ACC_WR_LEN16	0xff
#define V_FW_SCSI_TGT_ACC_WR_LEN16(x)	((x) << S_FW_SCSI_TGT_ACC_WR_LEN16)
#define G_FW_SCSI_TGT_ACC_WR_LEN16(x)	\
    (((x) >> S_FW_SCSI_TGT_ACC_WR_LEN16) & M_FW_SCSI_TGT_ACC_WR_LEN16)

#define S_FW_SCSI_TGT_ACC_WR_CP_EN	6
#define M_FW_SCSI_TGT_ACC_WR_CP_EN	0x3
#define V_FW_SCSI_TGT_ACC_WR_CP_EN(x)	((x) << S_FW_SCSI_TGT_ACC_WR_CP_EN)
#define G_FW_SCSI_TGT_ACC_WR_CP_EN(x)	\
    (((x) >> S_FW_SCSI_TGT_ACC_WR_CP_EN) & M_FW_SCSI_TGT_ACC_WR_CP_EN)

#define S_FW_SCSI_TGT_ACC_WR_CLASS	4
#define M_FW_SCSI_TGT_ACC_WR_CLASS	0x3
#define V_FW_SCSI_TGT_ACC_WR_CLASS(x)	((x) << S_FW_SCSI_TGT_ACC_WR_CLASS)
#define G_FW_SCSI_TGT_ACC_WR_CLASS(x)	\
    (((x) >> S_FW_SCSI_TGT_ACC_WR_CLASS) & M_FW_SCSI_TGT_ACC_WR_CLASS)

struct fw_scsi_tgt_xmit_wr {
	__be32 op_immdlen;
	__be32 flowid_len16;
	__be64 cookie;
	__be16 iqid;
	__u8   auto_rsp;
	__u8   use_xfer_cnt;
	union fw_scsi_tgt_xmit_priv {
		struct fcoe_tgt_xmit_priv {
			__u8   ctl_pri;
			__u8   cp_en_class;
			__u8   r3_lo[2];
		} fcoe;
		struct iscsi_tgt_xmit_priv {
			__u8   r3[4];
		} iscsi;
	} u;
	__be32 xfer_cnt;
	__be32 r4;
	__be64 r5;
	__be32 r6;
	__be32 tot_xfer_len;
};

#define S_FW_SCSI_TGT_XMIT_WR_OPCODE	24
#define M_FW_SCSI_TGT_XMIT_WR_OPCODE	0xff
#define V_FW_SCSI_TGT_XMIT_WR_OPCODE(x)	((x) << S_FW_SCSI_TGT_XMIT_WR_OPCODE)
#define G_FW_SCSI_TGT_XMIT_WR_OPCODE(x)	\
    (((x) >> S_FW_SCSI_TGT_XMIT_WR_OPCODE) & M_FW_SCSI_TGT_XMIT_WR_OPCODE)

#define S_FW_SCSI_TGT_XMIT_WR_IMMDLEN		0
#define M_FW_SCSI_TGT_XMIT_WR_IMMDLEN		0xff
#define V_FW_SCSI_TGT_XMIT_WR_IMMDLEN(x)	\
    ((x) << S_FW_SCSI_TGT_XMIT_WR_IMMDLEN)
#define G_FW_SCSI_TGT_XMIT_WR_IMMDLEN(x)	\
    (((x) >> S_FW_SCSI_TGT_XMIT_WR_IMMDLEN) & M_FW_SCSI_TGT_XMIT_WR_IMMDLEN)

#define S_FW_SCSI_TGT_XMIT_WR_FLOWID	8
#define M_FW_SCSI_TGT_XMIT_WR_FLOWID	0xfffff
#define V_FW_SCSI_TGT_XMIT_WR_FLOWID(x)	((x) << S_FW_SCSI_TGT_XMIT_WR_FLOWID)
#define G_FW_SCSI_TGT_XMIT_WR_FLOWID(x)	\
    (((x) >> S_FW_SCSI_TGT_XMIT_WR_FLOWID) & M_FW_SCSI_TGT_XMIT_WR_FLOWID)

#define S_FW_SCSI_TGT_XMIT_WR_LEN16	0
#define M_FW_SCSI_TGT_XMIT_WR_LEN16	0xff
#define V_FW_SCSI_TGT_XMIT_WR_LEN16(x)	((x) << S_FW_SCSI_TGT_XMIT_WR_LEN16)
#define G_FW_SCSI_TGT_XMIT_WR_LEN16(x)	\
    (((x) >> S_FW_SCSI_TGT_XMIT_WR_LEN16) & M_FW_SCSI_TGT_XMIT_WR_LEN16)

#define S_FW_SCSI_TGT_XMIT_WR_CP_EN	6
#define M_FW_SCSI_TGT_XMIT_WR_CP_EN	0x3
#define V_FW_SCSI_TGT_XMIT_WR_CP_EN(x)	((x) << S_FW_SCSI_TGT_XMIT_WR_CP_EN)
#define G_FW_SCSI_TGT_XMIT_WR_CP_EN(x)	\
    (((x) >> S_FW_SCSI_TGT_XMIT_WR_CP_EN) & M_FW_SCSI_TGT_XMIT_WR_CP_EN)

#define S_FW_SCSI_TGT_XMIT_WR_CLASS	4
#define M_FW_SCSI_TGT_XMIT_WR_CLASS	0x3
#define V_FW_SCSI_TGT_XMIT_WR_CLASS(x)	((x) << S_FW_SCSI_TGT_XMIT_WR_CLASS)
#define G_FW_SCSI_TGT_XMIT_WR_CLASS(x)	\
    (((x) >> S_FW_SCSI_TGT_XMIT_WR_CLASS) & M_FW_SCSI_TGT_XMIT_WR_CLASS)

struct fw_scsi_tgt_rsp_wr {
	__be32 op_immdlen;
	__be32 flowid_len16;
	__be64 cookie;
	__be16 iqid;
	__u8   r3[2];
	union fw_scsi_tgt_rsp_priv {
		struct fcoe_tgt_rsp_priv {
			__u8   ctl_pri;
			__u8   cp_en_class;
			__u8   r4_lo[2];
		} fcoe;
		struct iscsi_tgt_rsp_priv {
			__u8   r4[4];
		} iscsi;
	} u;
	__u8   r5[8];
};

#define S_FW_SCSI_TGT_RSP_WR_OPCODE	24
#define M_FW_SCSI_TGT_RSP_WR_OPCODE	0xff
#define V_FW_SCSI_TGT_RSP_WR_OPCODE(x)	((x) << S_FW_SCSI_TGT_RSP_WR_OPCODE)
#define G_FW_SCSI_TGT_RSP_WR_OPCODE(x)	\
    (((x) >> S_FW_SCSI_TGT_RSP_WR_OPCODE) & M_FW_SCSI_TGT_RSP_WR_OPCODE)

#define S_FW_SCSI_TGT_RSP_WR_IMMDLEN	0
#define M_FW_SCSI_TGT_RSP_WR_IMMDLEN	0xff
#define V_FW_SCSI_TGT_RSP_WR_IMMDLEN(x)	((x) << S_FW_SCSI_TGT_RSP_WR_IMMDLEN)
#define G_FW_SCSI_TGT_RSP_WR_IMMDLEN(x)	\
    (((x) >> S_FW_SCSI_TGT_RSP_WR_IMMDLEN) & M_FW_SCSI_TGT_RSP_WR_IMMDLEN)

#define S_FW_SCSI_TGT_RSP_WR_FLOWID	8
#define M_FW_SCSI_TGT_RSP_WR_FLOWID	0xfffff
#define V_FW_SCSI_TGT_RSP_WR_FLOWID(x)	((x) << S_FW_SCSI_TGT_RSP_WR_FLOWID)
#define G_FW_SCSI_TGT_RSP_WR_FLOWID(x)	\
    (((x) >> S_FW_SCSI_TGT_RSP_WR_FLOWID) & M_FW_SCSI_TGT_RSP_WR_FLOWID)

#define S_FW_SCSI_TGT_RSP_WR_LEN16	0
#define M_FW_SCSI_TGT_RSP_WR_LEN16	0xff
#define V_FW_SCSI_TGT_RSP_WR_LEN16(x)	((x) << S_FW_SCSI_TGT_RSP_WR_LEN16)
#define G_FW_SCSI_TGT_RSP_WR_LEN16(x)	\
    (((x) >> S_FW_SCSI_TGT_RSP_WR_LEN16) & M_FW_SCSI_TGT_RSP_WR_LEN16)

#define S_FW_SCSI_TGT_RSP_WR_CP_EN	6
#define M_FW_SCSI_TGT_RSP_WR_CP_EN	0x3
#define V_FW_SCSI_TGT_RSP_WR_CP_EN(x)	((x) << S_FW_SCSI_TGT_RSP_WR_CP_EN)
#define G_FW_SCSI_TGT_RSP_WR_CP_EN(x)	\
    (((x) >> S_FW_SCSI_TGT_RSP_WR_CP_EN) & M_FW_SCSI_TGT_RSP_WR_CP_EN)

#define S_FW_SCSI_TGT_RSP_WR_CLASS	4
#define M_FW_SCSI_TGT_RSP_WR_CLASS	0x3
#define V_FW_SCSI_TGT_RSP_WR_CLASS(x)	((x) << S_FW_SCSI_TGT_RSP_WR_CLASS)
#define G_FW_SCSI_TGT_RSP_WR_CLASS(x)	\
    (((x) >> S_FW_SCSI_TGT_RSP_WR_CLASS) & M_FW_SCSI_TGT_RSP_WR_CLASS)

struct fw_rdev_wr {
	__be32 op_to_immdlen;
	__be32 alloc_to_len16;
	__be64 cookie;
	__u8   protocol;
	__u8   event_cause;
	__u8   cur_state;
	__u8   prev_state;
	__be32 flags_to_assoc_flowid;
	union rdev_entry {
		struct fcoe_rdev_entry {
			__be32 flowid;
			__u8   protocol;
			__u8   event_cause;
			__u8   flags;
			__u8   rjt_reason;
			__u8   cur_login_st;
			__u8   prev_login_st;
			__be16 rcv_fr_sz;
			__u8   rd_xfer_rdy_to_rport_type;
			__u8   vft_to_qos;
			__u8   org_proc_assoc_to_acc_rsp_code;
			__u8   enh_disc_to_tgt;
			__u8   wwnn[8];
			__u8   wwpn[8];
			__be16 iqid;
			__u8   fc_oui[3];
			__u8   r_id[3];
		} fcoe_rdev;
		struct iscsi_rdev_entry {
			__be32 flowid;
			__u8   protocol;
			__u8   event_cause;
			__u8   flags;
			__u8   r3;
			__be16 iscsi_opts;
			__be16 tcp_opts;
			__be16 ip_opts;
			__be16 max_rcv_len;
			__be16 max_snd_len;
			__be16 first_brst_len;
			__be16 max_brst_len;
			__be16 r4;
			__be16 def_time2wait;
			__be16 def_time2ret;
			__be16 nop_out_intrvl;
			__be16 non_scsi_to;
			__be16 isid;
			__be16 tsid;
			__be16 port;
			__be16 tpgt;
			__u8   r5[6];
			__be16 iqid;
		} iscsi_rdev;
	} u;
};

#define S_FW_RDEV_WR_IMMDLEN	0
#define M_FW_RDEV_WR_IMMDLEN	0xff
#define V_FW_RDEV_WR_IMMDLEN(x)	((x) << S_FW_RDEV_WR_IMMDLEN)
#define G_FW_RDEV_WR_IMMDLEN(x)	\
    (((x) >> S_FW_RDEV_WR_IMMDLEN) & M_FW_RDEV_WR_IMMDLEN)

#define S_FW_RDEV_WR_ALLOC	31
#define M_FW_RDEV_WR_ALLOC	0x1
#define V_FW_RDEV_WR_ALLOC(x)	((x) << S_FW_RDEV_WR_ALLOC)
#define G_FW_RDEV_WR_ALLOC(x)	\
    (((x) >> S_FW_RDEV_WR_ALLOC) & M_FW_RDEV_WR_ALLOC)
#define F_FW_RDEV_WR_ALLOC	V_FW_RDEV_WR_ALLOC(1U)

#define S_FW_RDEV_WR_FREE	30
#define M_FW_RDEV_WR_FREE	0x1
#define V_FW_RDEV_WR_FREE(x)	((x) << S_FW_RDEV_WR_FREE)
#define G_FW_RDEV_WR_FREE(x)	\
    (((x) >> S_FW_RDEV_WR_FREE) & M_FW_RDEV_WR_FREE)
#define F_FW_RDEV_WR_FREE	V_FW_RDEV_WR_FREE(1U)

#define S_FW_RDEV_WR_MODIFY	29
#define M_FW_RDEV_WR_MODIFY	0x1
#define V_FW_RDEV_WR_MODIFY(x)	((x) << S_FW_RDEV_WR_MODIFY)
#define G_FW_RDEV_WR_MODIFY(x)	\
    (((x) >> S_FW_RDEV_WR_MODIFY) & M_FW_RDEV_WR_MODIFY)
#define F_FW_RDEV_WR_MODIFY	V_FW_RDEV_WR_MODIFY(1U)

#define S_FW_RDEV_WR_FLOWID	8
#define M_FW_RDEV_WR_FLOWID	0xfffff
#define V_FW_RDEV_WR_FLOWID(x)	((x) << S_FW_RDEV_WR_FLOWID)
#define G_FW_RDEV_WR_FLOWID(x)	\
    (((x) >> S_FW_RDEV_WR_FLOWID) & M_FW_RDEV_WR_FLOWID)

#define S_FW_RDEV_WR_LEN16	0
#define M_FW_RDEV_WR_LEN16	0xff
#define V_FW_RDEV_WR_LEN16(x)	((x) << S_FW_RDEV_WR_LEN16)
#define G_FW_RDEV_WR_LEN16(x)	\
    (((x) >> S_FW_RDEV_WR_LEN16) & M_FW_RDEV_WR_LEN16)

#define S_FW_RDEV_WR_FLAGS	24
#define M_FW_RDEV_WR_FLAGS	0xff
#define V_FW_RDEV_WR_FLAGS(x)	((x) << S_FW_RDEV_WR_FLAGS)
#define G_FW_RDEV_WR_FLAGS(x)	\
    (((x) >> S_FW_RDEV_WR_FLAGS) & M_FW_RDEV_WR_FLAGS)

#define S_FW_RDEV_WR_GET_NEXT		20
#define M_FW_RDEV_WR_GET_NEXT		0xf
#define V_FW_RDEV_WR_GET_NEXT(x)	((x) << S_FW_RDEV_WR_GET_NEXT)
#define G_FW_RDEV_WR_GET_NEXT(x)	\
    (((x) >> S_FW_RDEV_WR_GET_NEXT) & M_FW_RDEV_WR_GET_NEXT)

#define S_FW_RDEV_WR_ASSOC_FLOWID	0
#define M_FW_RDEV_WR_ASSOC_FLOWID	0xfffff
#define V_FW_RDEV_WR_ASSOC_FLOWID(x)	((x) << S_FW_RDEV_WR_ASSOC_FLOWID)
#define G_FW_RDEV_WR_ASSOC_FLOWID(x)	\
    (((x) >> S_FW_RDEV_WR_ASSOC_FLOWID) & M_FW_RDEV_WR_ASSOC_FLOWID)

#define S_FW_RDEV_WR_RJT	7
#define M_FW_RDEV_WR_RJT	0x1
#define V_FW_RDEV_WR_RJT(x)	((x) << S_FW_RDEV_WR_RJT)
#define G_FW_RDEV_WR_RJT(x)	(((x) >> S_FW_RDEV_WR_RJT) & M_FW_RDEV_WR_RJT)
#define F_FW_RDEV_WR_RJT	V_FW_RDEV_WR_RJT(1U)

#define S_FW_RDEV_WR_REASON	0
#define M_FW_RDEV_WR_REASON	0x7f
#define V_FW_RDEV_WR_REASON(x)	((x) << S_FW_RDEV_WR_REASON)
#define G_FW_RDEV_WR_REASON(x)	\
    (((x) >> S_FW_RDEV_WR_REASON) & M_FW_RDEV_WR_REASON)

#define S_FW_RDEV_WR_RD_XFER_RDY	7
#define M_FW_RDEV_WR_RD_XFER_RDY	0x1
#define V_FW_RDEV_WR_RD_XFER_RDY(x)	((x) << S_FW_RDEV_WR_RD_XFER_RDY)
#define G_FW_RDEV_WR_RD_XFER_RDY(x)	\
    (((x) >> S_FW_RDEV_WR_RD_XFER_RDY) & M_FW_RDEV_WR_RD_XFER_RDY)
#define F_FW_RDEV_WR_RD_XFER_RDY	V_FW_RDEV_WR_RD_XFER_RDY(1U)

#define S_FW_RDEV_WR_WR_XFER_RDY	6
#define M_FW_RDEV_WR_WR_XFER_RDY	0x1
#define V_FW_RDEV_WR_WR_XFER_RDY(x)	((x) << S_FW_RDEV_WR_WR_XFER_RDY)
#define G_FW_RDEV_WR_WR_XFER_RDY(x)	\
    (((x) >> S_FW_RDEV_WR_WR_XFER_RDY) & M_FW_RDEV_WR_WR_XFER_RDY)
#define F_FW_RDEV_WR_WR_XFER_RDY	V_FW_RDEV_WR_WR_XFER_RDY(1U)

#define S_FW_RDEV_WR_FC_SP	5
#define M_FW_RDEV_WR_FC_SP	0x1
#define V_FW_RDEV_WR_FC_SP(x)	((x) << S_FW_RDEV_WR_FC_SP)
#define G_FW_RDEV_WR_FC_SP(x)	\
    (((x) >> S_FW_RDEV_WR_FC_SP) & M_FW_RDEV_WR_FC_SP)
#define F_FW_RDEV_WR_FC_SP	V_FW_RDEV_WR_FC_SP(1U)

#define S_FW_RDEV_WR_RPORT_TYPE		0
#define M_FW_RDEV_WR_RPORT_TYPE		0x1f
#define V_FW_RDEV_WR_RPORT_TYPE(x)	((x) << S_FW_RDEV_WR_RPORT_TYPE)
#define G_FW_RDEV_WR_RPORT_TYPE(x)	\
    (((x) >> S_FW_RDEV_WR_RPORT_TYPE) & M_FW_RDEV_WR_RPORT_TYPE)

#define S_FW_RDEV_WR_VFT	7
#define M_FW_RDEV_WR_VFT	0x1
#define V_FW_RDEV_WR_VFT(x)	((x) << S_FW_RDEV_WR_VFT)
#define G_FW_RDEV_WR_VFT(x)	(((x) >> S_FW_RDEV_WR_VFT) & M_FW_RDEV_WR_VFT)
#define F_FW_RDEV_WR_VFT	V_FW_RDEV_WR_VFT(1U)

#define S_FW_RDEV_WR_NPIV	6
#define M_FW_RDEV_WR_NPIV	0x1
#define V_FW_RDEV_WR_NPIV(x)	((x) << S_FW_RDEV_WR_NPIV)
#define G_FW_RDEV_WR_NPIV(x)	\
    (((x) >> S_FW_RDEV_WR_NPIV) & M_FW_RDEV_WR_NPIV)
#define F_FW_RDEV_WR_NPIV	V_FW_RDEV_WR_NPIV(1U)

#define S_FW_RDEV_WR_CLASS	4
#define M_FW_RDEV_WR_CLASS	0x3
#define V_FW_RDEV_WR_CLASS(x)	((x) << S_FW_RDEV_WR_CLASS)
#define G_FW_RDEV_WR_CLASS(x)	\
    (((x) >> S_FW_RDEV_WR_CLASS) & M_FW_RDEV_WR_CLASS)

#define S_FW_RDEV_WR_SEQ_DEL	3
#define M_FW_RDEV_WR_SEQ_DEL	0x1
#define V_FW_RDEV_WR_SEQ_DEL(x)	((x) << S_FW_RDEV_WR_SEQ_DEL)
#define G_FW_RDEV_WR_SEQ_DEL(x)	\
    (((x) >> S_FW_RDEV_WR_SEQ_DEL) & M_FW_RDEV_WR_SEQ_DEL)
#define F_FW_RDEV_WR_SEQ_DEL	V_FW_RDEV_WR_SEQ_DEL(1U)

#define S_FW_RDEV_WR_PRIO_PREEMP	2
#define M_FW_RDEV_WR_PRIO_PREEMP	0x1
#define V_FW_RDEV_WR_PRIO_PREEMP(x)	((x) << S_FW_RDEV_WR_PRIO_PREEMP)
#define G_FW_RDEV_WR_PRIO_PREEMP(x)	\
    (((x) >> S_FW_RDEV_WR_PRIO_PREEMP) & M_FW_RDEV_WR_PRIO_PREEMP)
#define F_FW_RDEV_WR_PRIO_PREEMP	V_FW_RDEV_WR_PRIO_PREEMP(1U)

#define S_FW_RDEV_WR_PREF	1
#define M_FW_RDEV_WR_PREF	0x1
#define V_FW_RDEV_WR_PREF(x)	((x) << S_FW_RDEV_WR_PREF)
#define G_FW_RDEV_WR_PREF(x)	\
    (((x) >> S_FW_RDEV_WR_PREF) & M_FW_RDEV_WR_PREF)
#define F_FW_RDEV_WR_PREF	V_FW_RDEV_WR_PREF(1U)

#define S_FW_RDEV_WR_QOS	0
#define M_FW_RDEV_WR_QOS	0x1
#define V_FW_RDEV_WR_QOS(x)	((x) << S_FW_RDEV_WR_QOS)
#define G_FW_RDEV_WR_QOS(x)	(((x) >> S_FW_RDEV_WR_QOS) & M_FW_RDEV_WR_QOS)
#define F_FW_RDEV_WR_QOS	V_FW_RDEV_WR_QOS(1U)

#define S_FW_RDEV_WR_ORG_PROC_ASSOC	7
#define M_FW_RDEV_WR_ORG_PROC_ASSOC	0x1
#define V_FW_RDEV_WR_ORG_PROC_ASSOC(x)	((x) << S_FW_RDEV_WR_ORG_PROC_ASSOC)
#define G_FW_RDEV_WR_ORG_PROC_ASSOC(x)	\
    (((x) >> S_FW_RDEV_WR_ORG_PROC_ASSOC) & M_FW_RDEV_WR_ORG_PROC_ASSOC)
#define F_FW_RDEV_WR_ORG_PROC_ASSOC	V_FW_RDEV_WR_ORG_PROC_ASSOC(1U)

#define S_FW_RDEV_WR_RSP_PROC_ASSOC	6
#define M_FW_RDEV_WR_RSP_PROC_ASSOC	0x1
#define V_FW_RDEV_WR_RSP_PROC_ASSOC(x)	((x) << S_FW_RDEV_WR_RSP_PROC_ASSOC)
#define G_FW_RDEV_WR_RSP_PROC_ASSOC(x)	\
    (((x) >> S_FW_RDEV_WR_RSP_PROC_ASSOC) & M_FW_RDEV_WR_RSP_PROC_ASSOC)
#define F_FW_RDEV_WR_RSP_PROC_ASSOC	V_FW_RDEV_WR_RSP_PROC_ASSOC(1U)

#define S_FW_RDEV_WR_IMAGE_PAIR		5
#define M_FW_RDEV_WR_IMAGE_PAIR		0x1
#define V_FW_RDEV_WR_IMAGE_PAIR(x)	((x) << S_FW_RDEV_WR_IMAGE_PAIR)
#define G_FW_RDEV_WR_IMAGE_PAIR(x)	\
    (((x) >> S_FW_RDEV_WR_IMAGE_PAIR) & M_FW_RDEV_WR_IMAGE_PAIR)
#define F_FW_RDEV_WR_IMAGE_PAIR	V_FW_RDEV_WR_IMAGE_PAIR(1U)

#define S_FW_RDEV_WR_ACC_RSP_CODE	0
#define M_FW_RDEV_WR_ACC_RSP_CODE	0x1f
#define V_FW_RDEV_WR_ACC_RSP_CODE(x)	((x) << S_FW_RDEV_WR_ACC_RSP_CODE)
#define G_FW_RDEV_WR_ACC_RSP_CODE(x)	\
    (((x) >> S_FW_RDEV_WR_ACC_RSP_CODE) & M_FW_RDEV_WR_ACC_RSP_CODE)

#define S_FW_RDEV_WR_ENH_DISC		7
#define M_FW_RDEV_WR_ENH_DISC		0x1
#define V_FW_RDEV_WR_ENH_DISC(x)	((x) << S_FW_RDEV_WR_ENH_DISC)
#define G_FW_RDEV_WR_ENH_DISC(x)	\
    (((x) >> S_FW_RDEV_WR_ENH_DISC) & M_FW_RDEV_WR_ENH_DISC)
#define F_FW_RDEV_WR_ENH_DISC	V_FW_RDEV_WR_ENH_DISC(1U)

#define S_FW_RDEV_WR_REC	6
#define M_FW_RDEV_WR_REC	0x1
#define V_FW_RDEV_WR_REC(x)	((x) << S_FW_RDEV_WR_REC)
#define G_FW_RDEV_WR_REC(x)	(((x) >> S_FW_RDEV_WR_REC) & M_FW_RDEV_WR_REC)
#define F_FW_RDEV_WR_REC	V_FW_RDEV_WR_REC(1U)

#define S_FW_RDEV_WR_TASK_RETRY_ID	5
#define M_FW_RDEV_WR_TASK_RETRY_ID	0x1
#define V_FW_RDEV_WR_TASK_RETRY_ID(x)	((x) << S_FW_RDEV_WR_TASK_RETRY_ID)
#define G_FW_RDEV_WR_TASK_RETRY_ID(x)	\
    (((x) >> S_FW_RDEV_WR_TASK_RETRY_ID) & M_FW_RDEV_WR_TASK_RETRY_ID)
#define F_FW_RDEV_WR_TASK_RETRY_ID	V_FW_RDEV_WR_TASK_RETRY_ID(1U)

#define S_FW_RDEV_WR_RETRY	4
#define M_FW_RDEV_WR_RETRY	0x1
#define V_FW_RDEV_WR_RETRY(x)	((x) << S_FW_RDEV_WR_RETRY)
#define G_FW_RDEV_WR_RETRY(x)	\
    (((x) >> S_FW_RDEV_WR_RETRY) & M_FW_RDEV_WR_RETRY)
#define F_FW_RDEV_WR_RETRY	V_FW_RDEV_WR_RETRY(1U)

#define S_FW_RDEV_WR_CONF_CMPL		3
#define M_FW_RDEV_WR_CONF_CMPL		0x1
#define V_FW_RDEV_WR_CONF_CMPL(x)	((x) << S_FW_RDEV_WR_CONF_CMPL)
#define G_FW_RDEV_WR_CONF_CMPL(x)	\
    (((x) >> S_FW_RDEV_WR_CONF_CMPL) & M_FW_RDEV_WR_CONF_CMPL)
#define F_FW_RDEV_WR_CONF_CMPL	V_FW_RDEV_WR_CONF_CMPL(1U)

#define S_FW_RDEV_WR_DATA_OVLY		2
#define M_FW_RDEV_WR_DATA_OVLY		0x1
#define V_FW_RDEV_WR_DATA_OVLY(x)	((x) << S_FW_RDEV_WR_DATA_OVLY)
#define G_FW_RDEV_WR_DATA_OVLY(x)	\
    (((x) >> S_FW_RDEV_WR_DATA_OVLY) & M_FW_RDEV_WR_DATA_OVLY)
#define F_FW_RDEV_WR_DATA_OVLY	V_FW_RDEV_WR_DATA_OVLY(1U)

#define S_FW_RDEV_WR_INI	1
#define M_FW_RDEV_WR_INI	0x1
#define V_FW_RDEV_WR_INI(x)	((x) << S_FW_RDEV_WR_INI)
#define G_FW_RDEV_WR_INI(x)	(((x) >> S_FW_RDEV_WR_INI) & M_FW_RDEV_WR_INI)
#define F_FW_RDEV_WR_INI	V_FW_RDEV_WR_INI(1U)

#define S_FW_RDEV_WR_TGT	0
#define M_FW_RDEV_WR_TGT	0x1
#define V_FW_RDEV_WR_TGT(x)	((x) << S_FW_RDEV_WR_TGT)
#define G_FW_RDEV_WR_TGT(x)	(((x) >> S_FW_RDEV_WR_TGT) & M_FW_RDEV_WR_TGT)
#define F_FW_RDEV_WR_TGT	V_FW_RDEV_WR_TGT(1U)


