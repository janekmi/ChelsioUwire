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
enum fw_fcoe_link_sub_op {
	FCOE_LINK_DOWN	= 0x0,
	FCOE_LINK_UP	= 0x1,
	FCOE_LINK_COND	= 0x2,
};

enum fw_fcoe_link_status {
	FCOE_LINKDOWN	= 0x0,
	FCOE_LINKUP	= 0x1,
};

enum fw_ofld_prot {
	PROT_FCOE 	= 0x1,
	PROT_ISCSI	= 0x2,
};

enum rport_type_fcoe {
	FLOGI_VFPORT	= 0x1,		/* 0xfffffe */
	FDISC_VFPORT	= 0x2,		/* 0xfffffe */
	NS_VNPORT	= 0x3,		/* 0xfffffc */
	REG_FC4_VNPORT	= 0x4,		/* any FC4 type VN_PORT */
	REG_VNPORT	= 0x5,		/* 0xfffxxx - non FC4 port in switch */
	FDMI_VNPORT	= 0x6,		/* 0xfffffa */
	FAB_CTLR_VNPORT	= 0x7,		/* 0xfffffd */
};

enum event_cause_fcoe {
	PLOGI_ACC_RCVD		= 0x01,
	PLOGI_RJT_RCVD		= 0x02,
	PLOGI_RCVD		= 0x03,
	PLOGO_RCVD		= 0x04,
	PRLI_ACC_RCVD		= 0x05,
	PRLI_RJT_RCVD		= 0x06,
	PRLI_RCVD		= 0x07,
	PRLO_RCVD		= 0x08,
	NPORT_ID_CHGD		= 0x09,
	FLOGO_RCVD		= 0x0a,
	CLR_VIRT_LNK_RCVD	= 0x0b,
	FLOGI_ACC_RCVD		= 0x0c,
	FLOGI_RJT_RCVD		= 0x0d,
	FDISC_ACC_RCVD		= 0x0e,
	FDISC_RJT_RCVD		= 0x0f,
	FLOGI_TMO_MAX_RETRY	= 0x10,
	IMPL_LOGO_ADISC_ACC	= 0x11,
	IMPL_LOGO_ADISC_RJT	= 0x12,
	IMPL_LOGO_ADISC_CNFLT	= 0x13,
	PRLI_TMO		= 0x14,
	ADISC_TMO		= 0x15,
	RSCN_DEV_LOST		= 0x16,
	SCR_ACC_RCVD		= 0x17,
	ADISC_RJT_RCVD		= 0x18,
	LOGO_SNT		= 0x19,
	PROTO_ERR_IMPL_LOGO	= 0x1a,
};


enum fw_opcodes {
	FW_FCOE_RES_INFO_CMD           = 0x31,
	FW_FCOE_LINK_CMD               = 0x32,
	FW_FCOE_VNP_CMD                = 0x33,
	FW_FCOE_SSN_CMD                = 0x34,
	FW_FCOE_SPARAMS_CMD            = 0x35,
	FW_FCOE_SEEPROM_CMD            = 0x36,
	FW_FCOE_STATS_CMD              = 0x37,
	FW_FCOE_FCF_CMD                = 0x38,
};

struct fw_fcoe_res_info_cmd {
	__be32 op_to_read;
	__be32 retval_len16;
	__be16 e_d_tov;
	__be16 r_a_tov_seq;
	__be16 r_a_tov_els;
	__be16 r_r_tov;
	__be32 max_xchgs;
	__be32 max_ssns;
	__be32 used_xchgs;
	__be32 used_ssns;
	__be32 max_fcfs;
	__be32 max_vnps;
	__be32 used_fcfs;
	__be32 used_vnps;
};

struct fw_fcoe_link_cmd {
	__be32 op_to_portid;
	__be32 retval_len16;
	__be32 sub_opcode_fcfi;
	__u8   r3;
	__u8   lstatus;
	__be16 flags;
	__u8   r4;
	__u8   set_vlan;
	__be16 vlan_id;
	__be32 vnpi_pkd;
	__be16 r6;
	__u8   phy_mac[6];
	__u8   vnport_wwnn[8];
	__u8   vnport_wwpn[8];
};

#define S_FW_FCOE_LINK_CMD_PORTID	0
#define M_FW_FCOE_LINK_CMD_PORTID	0xf
#define V_FW_FCOE_LINK_CMD_PORTID(x)	((x) << S_FW_FCOE_LINK_CMD_PORTID)
#define G_FW_FCOE_LINK_CMD_PORTID(x)	\
    (((x) >> S_FW_FCOE_LINK_CMD_PORTID) & M_FW_FCOE_LINK_CMD_PORTID)

#define S_FW_FCOE_LINK_CMD_SUB_OPCODE		24
#define M_FW_FCOE_LINK_CMD_SUB_OPCODE		0xff
#define V_FW_FCOE_LINK_CMD_SUB_OPCODE(x)	\
    ((x) << S_FW_FCOE_LINK_CMD_SUB_OPCODE)
#define G_FW_FCOE_LINK_CMD_SUB_OPCODE(x)	\
    (((x) >> S_FW_FCOE_LINK_CMD_SUB_OPCODE) & M_FW_FCOE_LINK_CMD_SUB_OPCODE)

#define S_FW_FCOE_LINK_CMD_FCFI		0
#define M_FW_FCOE_LINK_CMD_FCFI		0xffffff
#define V_FW_FCOE_LINK_CMD_FCFI(x)	((x) << S_FW_FCOE_LINK_CMD_FCFI)
#define G_FW_FCOE_LINK_CMD_FCFI(x)	\
    (((x) >> S_FW_FCOE_LINK_CMD_FCFI) & M_FW_FCOE_LINK_CMD_FCFI)

#define S_FW_FCOE_LINK_CMD_VNPI		0
#define M_FW_FCOE_LINK_CMD_VNPI		0xfffff
#define V_FW_FCOE_LINK_CMD_VNPI(x)	((x) << S_FW_FCOE_LINK_CMD_VNPI)
#define G_FW_FCOE_LINK_CMD_VNPI(x)	\
    (((x) >> S_FW_FCOE_LINK_CMD_VNPI) & M_FW_FCOE_LINK_CMD_VNPI)

struct fw_fcoe_vnp_cmd {
	__be32 op_to_fcfi;
	__be32 alloc_to_len16;
	__be32 gen_wwn_to_vnpi;
	__be32 vf_id;
	__be16 iqid;
	__u8   vnport_mac[6];
	__u8   vnport_wwnn[8];
	__u8   vnport_wwpn[8];
	__u8   cmn_srv_parms[16];
	__u8   clsp_word_0_1[8];
};

#define S_FW_FCOE_VNP_CMD_FCFI		0
#define M_FW_FCOE_VNP_CMD_FCFI		0xfffff
#define V_FW_FCOE_VNP_CMD_FCFI(x)	((x) << S_FW_FCOE_VNP_CMD_FCFI)
#define G_FW_FCOE_VNP_CMD_FCFI(x)	\
    (((x) >> S_FW_FCOE_VNP_CMD_FCFI) & M_FW_FCOE_VNP_CMD_FCFI)

#define S_FW_FCOE_VNP_CMD_ALLOC		31
#define M_FW_FCOE_VNP_CMD_ALLOC		0x1
#define V_FW_FCOE_VNP_CMD_ALLOC(x)	((x) << S_FW_FCOE_VNP_CMD_ALLOC)
#define G_FW_FCOE_VNP_CMD_ALLOC(x)	\
    (((x) >> S_FW_FCOE_VNP_CMD_ALLOC) & M_FW_FCOE_VNP_CMD_ALLOC)
#define F_FW_FCOE_VNP_CMD_ALLOC	V_FW_FCOE_VNP_CMD_ALLOC(1U)

#define S_FW_FCOE_VNP_CMD_FREE		30
#define M_FW_FCOE_VNP_CMD_FREE		0x1
#define V_FW_FCOE_VNP_CMD_FREE(x)	((x) << S_FW_FCOE_VNP_CMD_FREE)
#define G_FW_FCOE_VNP_CMD_FREE(x)	\
    (((x) >> S_FW_FCOE_VNP_CMD_FREE) & M_FW_FCOE_VNP_CMD_FREE)
#define F_FW_FCOE_VNP_CMD_FREE	V_FW_FCOE_VNP_CMD_FREE(1U)

#define S_FW_FCOE_VNP_CMD_MODIFY	29
#define M_FW_FCOE_VNP_CMD_MODIFY	0x1
#define V_FW_FCOE_VNP_CMD_MODIFY(x)	((x) << S_FW_FCOE_VNP_CMD_MODIFY)
#define G_FW_FCOE_VNP_CMD_MODIFY(x)	\
    (((x) >> S_FW_FCOE_VNP_CMD_MODIFY) & M_FW_FCOE_VNP_CMD_MODIFY)
#define F_FW_FCOE_VNP_CMD_MODIFY	V_FW_FCOE_VNP_CMD_MODIFY(1U)

#define S_FW_FCOE_VNP_CMD_GEN_WWN	22
#define M_FW_FCOE_VNP_CMD_GEN_WWN	0x1
#define V_FW_FCOE_VNP_CMD_GEN_WWN(x)	((x) << S_FW_FCOE_VNP_CMD_GEN_WWN)
#define G_FW_FCOE_VNP_CMD_GEN_WWN(x)	\
    (((x) >> S_FW_FCOE_VNP_CMD_GEN_WWN) & M_FW_FCOE_VNP_CMD_GEN_WWN)
#define F_FW_FCOE_VNP_CMD_GEN_WWN	V_FW_FCOE_VNP_CMD_GEN_WWN(1U)

#define S_FW_FCOE_VNP_CMD_PERSIST	21
#define M_FW_FCOE_VNP_CMD_PERSIST	0x1
#define V_FW_FCOE_VNP_CMD_PERSIST(x)	((x) << S_FW_FCOE_VNP_CMD_PERSIST)
#define G_FW_FCOE_VNP_CMD_PERSIST(x)	\
    (((x) >> S_FW_FCOE_VNP_CMD_PERSIST) & M_FW_FCOE_VNP_CMD_PERSIST)
#define F_FW_FCOE_VNP_CMD_PERSIST	V_FW_FCOE_VNP_CMD_PERSIST(1U)

#define S_FW_FCOE_VNP_CMD_VFID_EN	20
#define M_FW_FCOE_VNP_CMD_VFID_EN	0x1
#define V_FW_FCOE_VNP_CMD_VFID_EN(x)	((x) << S_FW_FCOE_VNP_CMD_VFID_EN)
#define G_FW_FCOE_VNP_CMD_VFID_EN(x)	\
    (((x) >> S_FW_FCOE_VNP_CMD_VFID_EN) & M_FW_FCOE_VNP_CMD_VFID_EN)
#define F_FW_FCOE_VNP_CMD_VFID_EN	V_FW_FCOE_VNP_CMD_VFID_EN(1U)

#define S_FW_FCOE_VNP_CMD_VNPI		0
#define M_FW_FCOE_VNP_CMD_VNPI		0xfffff
#define V_FW_FCOE_VNP_CMD_VNPI(x)	((x) << S_FW_FCOE_VNP_CMD_VNPI)
#define G_FW_FCOE_VNP_CMD_VNPI(x)	\
    (((x) >> S_FW_FCOE_VNP_CMD_VNPI) & M_FW_FCOE_VNP_CMD_VNPI)

struct fw_fcoe_ssn_cmd {
	__be32 op_to_vnpi;
	__be32 alloc_to_len16;
	__be16 iqid;
	__u8   d_mac[6];
	__u8   rport_wwnn[8];
	__u8   rport_wwpn[8];
	__be32 cmn_sp_word1;
	__be32 cmn_sp_word2;
	__be32 ssni_pkd;
	__be32 e_d_tov;
	__u8   cls_srv_parms[16];
};

#define S_FW_FCOE_SSN_CMD_VNPI		0
#define M_FW_FCOE_SSN_CMD_VNPI		0xfffff
#define V_FW_FCOE_SSN_CMD_VNPI(x)	((x) << S_FW_FCOE_SSN_CMD_VNPI)
#define G_FW_FCOE_SSN_CMD_VNPI(x)	\
    (((x) >> S_FW_FCOE_SSN_CMD_VNPI) & M_FW_FCOE_SSN_CMD_VNPI)

#define S_FW_FCOE_SSN_CMD_ALLOC		31
#define M_FW_FCOE_SSN_CMD_ALLOC		0x1
#define V_FW_FCOE_SSN_CMD_ALLOC(x)	((x) << S_FW_FCOE_SSN_CMD_ALLOC)
#define G_FW_FCOE_SSN_CMD_ALLOC(x)	\
    (((x) >> S_FW_FCOE_SSN_CMD_ALLOC) & M_FW_FCOE_SSN_CMD_ALLOC)
#define F_FW_FCOE_SSN_CMD_ALLOC	V_FW_FCOE_SSN_CMD_ALLOC(1U)

#define S_FW_FCOE_SSN_CMD_FREE		30
#define M_FW_FCOE_SSN_CMD_FREE		0x1
#define V_FW_FCOE_SSN_CMD_FREE(x)	((x) << S_FW_FCOE_SSN_CMD_FREE)
#define G_FW_FCOE_SSN_CMD_FREE(x)	\
    (((x) >> S_FW_FCOE_SSN_CMD_FREE) & M_FW_FCOE_SSN_CMD_FREE)
#define F_FW_FCOE_SSN_CMD_FREE	V_FW_FCOE_SSN_CMD_FREE(1U)

#define S_FW_FCOE_SSN_CMD_MODIFY	29
#define M_FW_FCOE_SSN_CMD_MODIFY	0x1
#define V_FW_FCOE_SSN_CMD_MODIFY(x)	((x) << S_FW_FCOE_SSN_CMD_MODIFY)
#define G_FW_FCOE_SSN_CMD_MODIFY(x)	\
    (((x) >> S_FW_FCOE_SSN_CMD_MODIFY) & M_FW_FCOE_SSN_CMD_MODIFY)
#define F_FW_FCOE_SSN_CMD_MODIFY	V_FW_FCOE_SSN_CMD_MODIFY(1U)

#define S_FW_FCOE_SSN_CMD_SSNI		0
#define M_FW_FCOE_SSN_CMD_SSNI		0xfffff
#define V_FW_FCOE_SSN_CMD_SSNI(x)	((x) << S_FW_FCOE_SSN_CMD_SSNI)
#define G_FW_FCOE_SSN_CMD_SSNI(x)	\
    (((x) >> S_FW_FCOE_SSN_CMD_SSNI) & M_FW_FCOE_SSN_CMD_SSNI)

struct fw_fcoe_sparams_cmd {
	__be32 op_to_portid;
	__be32 retval_len16;
	__u8   r3[7];
	__u8   cos;
	__u8   lport_wwnn[8];
	__u8   lport_wwpn[8];
	__u8   cmn_srv_parms[16];
	__u8   cls_srv_parms[16];
};

#define S_FW_FCOE_SPARAMS_CMD_PORTID	0
#define M_FW_FCOE_SPARAMS_CMD_PORTID	0xf
#define V_FW_FCOE_SPARAMS_CMD_PORTID(x)	((x) << S_FW_FCOE_SPARAMS_CMD_PORTID)
#define G_FW_FCOE_SPARAMS_CMD_PORTID(x)	\
    (((x) >> S_FW_FCOE_SPARAMS_CMD_PORTID) & M_FW_FCOE_SPARAMS_CMD_PORTID)

struct fw_fcoe_seeprom_cmd {
	__be32 op_to_vfn;
	__be32 retval_len16;
	__be16 pri_to_spma_enb;
	__u8   spma_mac[6];
	__u8   rport_wwnn[8];
	__u8   rport_wwpn[8];
	__u8   cmn_srv_parms[16];
	__u8   cls_srv_parms[16];
};

#define S_FW_FCOE_SEEPROM_CMD_PFN	8
#define M_FW_FCOE_SEEPROM_CMD_PFN	0x7
#define V_FW_FCOE_SEEPROM_CMD_PFN(x)	((x) << S_FW_FCOE_SEEPROM_CMD_PFN)
#define G_FW_FCOE_SEEPROM_CMD_PFN(x)	\
    (((x) >> S_FW_FCOE_SEEPROM_CMD_PFN) & M_FW_FCOE_SEEPROM_CMD_PFN)

#define S_FW_FCOE_SEEPROM_CMD_VFN	0
#define M_FW_FCOE_SEEPROM_CMD_VFN	0xff
#define V_FW_FCOE_SEEPROM_CMD_VFN(x)	((x) << S_FW_FCOE_SEEPROM_CMD_VFN)
#define G_FW_FCOE_SEEPROM_CMD_VFN(x)	\
    (((x) >> S_FW_FCOE_SEEPROM_CMD_VFN) & M_FW_FCOE_SEEPROM_CMD_VFN)

#define S_FW_FCOE_SEEPROM_CMD_PRI	3
#define M_FW_FCOE_SEEPROM_CMD_PRI	0x1
#define V_FW_FCOE_SEEPROM_CMD_PRI(x)	((x) << S_FW_FCOE_SEEPROM_CMD_PRI)
#define G_FW_FCOE_SEEPROM_CMD_PRI(x)	\
    (((x) >> S_FW_FCOE_SEEPROM_CMD_PRI) & M_FW_FCOE_SEEPROM_CMD_PRI)
#define F_FW_FCOE_SEEPROM_CMD_PRI	V_FW_FCOE_SEEPROM_CMD_PRI(1U)

#define S_FW_FCOE_SEEPROM_CMD_SEC	2
#define M_FW_FCOE_SEEPROM_CMD_SEC	0x1
#define V_FW_FCOE_SEEPROM_CMD_SEC(x)	((x) << S_FW_FCOE_SEEPROM_CMD_SEC)
#define G_FW_FCOE_SEEPROM_CMD_SEC(x)	\
    (((x) >> S_FW_FCOE_SEEPROM_CMD_SEC) & M_FW_FCOE_SEEPROM_CMD_SEC)
#define F_FW_FCOE_SEEPROM_CMD_SEC	V_FW_FCOE_SEEPROM_CMD_SEC(1U)

#define S_FW_FCOE_SEEPROM_CMD_FPMA_ENB		1
#define M_FW_FCOE_SEEPROM_CMD_FPMA_ENB		0x1
#define V_FW_FCOE_SEEPROM_CMD_FPMA_ENB(x)	\
    ((x) << S_FW_FCOE_SEEPROM_CMD_FPMA_ENB)
#define G_FW_FCOE_SEEPROM_CMD_FPMA_ENB(x)	\
    (((x) >> S_FW_FCOE_SEEPROM_CMD_FPMA_ENB) & M_FW_FCOE_SEEPROM_CMD_FPMA_ENB)
#define F_FW_FCOE_SEEPROM_CMD_FPMA_ENB	V_FW_FCOE_SEEPROM_CMD_FPMA_ENB(1U)

#define S_FW_FCOE_SEEPROM_CMD_SPMA_ENB		0
#define M_FW_FCOE_SEEPROM_CMD_SPMA_ENB		0x1
#define V_FW_FCOE_SEEPROM_CMD_SPMA_ENB(x)	\
    ((x) << S_FW_FCOE_SEEPROM_CMD_SPMA_ENB)
#define G_FW_FCOE_SEEPROM_CMD_SPMA_ENB(x)	\
    (((x) >> S_FW_FCOE_SEEPROM_CMD_SPMA_ENB) & M_FW_FCOE_SEEPROM_CMD_SPMA_ENB)
#define F_FW_FCOE_SEEPROM_CMD_SPMA_ENB	V_FW_FCOE_SEEPROM_CMD_SPMA_ENB(1U)

struct fw_fcoe_stats_cmd {
	__be32 op_to_flowid;
	__be32 free_to_len16;
	union fw_fcoe_stats {
		struct fw_fcoe_stats_ctl {
			__u8   nstats_port;
			__u8   port_valid_ix;
			__be16 r6;
			__be32 r7;
			__be64 stat0;
			__be64 stat1;
			__be64 stat2;
			__be64 stat3;
			__be64 stat4;
			__be64 stat5;
		} ctl;
		struct fw_fcoe_port_stats {
			__be64 tx_bcast_bytes;
			__be64 tx_bcast_frames;
			__be64 tx_mcast_bytes;
			__be64 tx_mcast_frames;
			__be64 tx_ucast_bytes;
			__be64 tx_ucast_frames;
			__be64 tx_drop_frames;
			__be64 tx_offload_bytes;
			__be64 tx_offload_frames;
			__be64 rx_bcast_bytes;
			__be64 rx_bcast_frames;
			__be64 rx_mcast_bytes;
			__be64 rx_mcast_frames;
			__be64 rx_ucast_bytes;
			__be64 rx_ucast_frames;
			__be64 rx_err_frames;
		} port_stats;
		struct fw_fcoe_fcf_stats {
			__be32 fip_tx_bytes;
			__be32 fip_tx_fr;
			__be64 fcf_ka;
			__be64 mcast_adv_rcvd;
			__be16 ucast_adv_rcvd;
			__be16 sol_sent;
			__be16 vlan_req;
			__be16 vlan_rpl;
			__be16 clr_vlink;
			__be16 link_down;
			__be16 link_up;
			__be16 logo;
			__be16 flogi_req;
			__be16 flogi_rpl;
			__be16 fdisc_req;
			__be16 fdisc_rpl;
			__be16 fka_prd_chg;
			__be16 fc_map_chg;
			__be16 vfid_chg;
			__u8   no_fka_req;
			__u8   no_vnp;
		} fcf_stats;
		struct fw_fcoe_pcb_stats {
			__be64 tx_bytes;
			__be64 tx_frames;
			__be64 rx_bytes;
			__be64 rx_frames;
			__be32 vnp_ka;
			__be32 unsol_els_rcvd;
			__be64 unsol_cmd_rcvd;
			__be16 implicit_logo;
			__be16 flogi_inv_sparm;
			__be16 fdisc_inv_sparm;
			__be16 flogi_rjt;
			__be16 fdisc_rjt;
			__be16 no_ssn;
			__be16 mac_flt_fail;
			__be16 inv_fr_rcvd;
		} pcb_stats;
		struct fw_fcoe_scb_stats {
			__be64 tx_bytes;
			__be64 tx_frames;
			__be64 rx_bytes;
			__be64 rx_frames;
			__be32 host_abrt_req;
			__be32 adap_auto_abrt;
			__be32 adap_abrt_rsp;
			__be32 host_ios_req;
			__be16 ssn_offl_ios;
			__be16 ssn_not_rdy_ios;
			__u8   rx_data_ddp_err;
			__u8   ddp_flt_set_err;
			__be16 rx_data_fr_err;
			__u8   bad_st_abrt_req;
			__u8   no_io_abrt_req;
			__u8   abort_tmo;
			__u8   abort_tmo_2;
			__be32 abort_req;
			__u8   no_ppod_res_tmo;
			__u8   bp_tmo;
			__u8   adap_auto_cls;
			__u8   no_io_cls_req;
			__be32 host_cls_req;
			__be64 unsol_cmd_rcvd;
			__be32 plogi_req_rcvd;
			__be32 prli_req_rcvd;
			__be16 logo_req_rcvd;
			__be16 prlo_req_rcvd;
			__be16 plogi_rjt_rcvd;
			__be16 prli_rjt_rcvd;
			__be32 adisc_req_rcvd;
			__be32 rscn_rcvd;
			__be32 rrq_req_rcvd;
			__be32 unsol_els_rcvd;
			__u8   adisc_rjt_rcvd;
			__u8   scr_rjt;
			__u8   ct_rjt;
			__u8   inval_bls_rcvd;
			__be32 ba_rjt_rcvd;
		} scb_stats;
	} u;
};

#define S_FW_FCOE_STATS_CMD_FLOWID	0
#define M_FW_FCOE_STATS_CMD_FLOWID	0xfffff
#define V_FW_FCOE_STATS_CMD_FLOWID(x)	((x) << S_FW_FCOE_STATS_CMD_FLOWID)
#define G_FW_FCOE_STATS_CMD_FLOWID(x)	\
    (((x) >> S_FW_FCOE_STATS_CMD_FLOWID) & M_FW_FCOE_STATS_CMD_FLOWID)

#define S_FW_FCOE_STATS_CMD_FREE	30
#define M_FW_FCOE_STATS_CMD_FREE	0x1
#define V_FW_FCOE_STATS_CMD_FREE(x)	((x) << S_FW_FCOE_STATS_CMD_FREE)
#define G_FW_FCOE_STATS_CMD_FREE(x)	\
    (((x) >> S_FW_FCOE_STATS_CMD_FREE) & M_FW_FCOE_STATS_CMD_FREE)
#define F_FW_FCOE_STATS_CMD_FREE	V_FW_FCOE_STATS_CMD_FREE(1U)

#define S_FW_FCOE_STATS_CMD_NSTATS	4
#define M_FW_FCOE_STATS_CMD_NSTATS	0x7
#define V_FW_FCOE_STATS_CMD_NSTATS(x)	((x) << S_FW_FCOE_STATS_CMD_NSTATS)
#define G_FW_FCOE_STATS_CMD_NSTATS(x)	\
    (((x) >> S_FW_FCOE_STATS_CMD_NSTATS) & M_FW_FCOE_STATS_CMD_NSTATS)

#define S_FW_FCOE_STATS_CMD_PORT	0
#define M_FW_FCOE_STATS_CMD_PORT	0x3
#define V_FW_FCOE_STATS_CMD_PORT(x)	((x) << S_FW_FCOE_STATS_CMD_PORT)
#define G_FW_FCOE_STATS_CMD_PORT(x)	\
    (((x) >> S_FW_FCOE_STATS_CMD_PORT) & M_FW_FCOE_STATS_CMD_PORT)

#define S_FW_FCOE_STATS_CMD_PORT_VALID		7
#define M_FW_FCOE_STATS_CMD_PORT_VALID		0x1
#define V_FW_FCOE_STATS_CMD_PORT_VALID(x)	\
    ((x) << S_FW_FCOE_STATS_CMD_PORT_VALID)
#define G_FW_FCOE_STATS_CMD_PORT_VALID(x)	\
    (((x) >> S_FW_FCOE_STATS_CMD_PORT_VALID) & M_FW_FCOE_STATS_CMD_PORT_VALID)
#define F_FW_FCOE_STATS_CMD_PORT_VALID	V_FW_FCOE_STATS_CMD_PORT_VALID(1U)

#define S_FW_FCOE_STATS_CMD_IX		0
#define M_FW_FCOE_STATS_CMD_IX		0x3f
#define V_FW_FCOE_STATS_CMD_IX(x)	((x) << S_FW_FCOE_STATS_CMD_IX)
#define G_FW_FCOE_STATS_CMD_IX(x)	\
    (((x) >> S_FW_FCOE_STATS_CMD_IX) & M_FW_FCOE_STATS_CMD_IX)

struct fw_fcoe_fcf_cmd {
	__be32 op_to_fcfi;
	__be32 retval_len16;
	__be16 priority_pkd;
	__u8   mac[6];
	__u8   name_id[8];
	__u8   fabric[8];
	__be16 vf_id;
	__be16 max_fcoe_size;
	__u8   vlan_id;
	__u8   fc_map[3];
	__be32 fka_adv;
	__be32 r6;
	__u8   r7_hi;
	__u8   fpma_to_portid;
	__u8   spma_mac[6];
	__be64 r8;
};

#define S_FW_FCOE_FCF_CMD_FCFI		0
#define M_FW_FCOE_FCF_CMD_FCFI		0xfffff
#define V_FW_FCOE_FCF_CMD_FCFI(x)	((x) << S_FW_FCOE_FCF_CMD_FCFI)
#define G_FW_FCOE_FCF_CMD_FCFI(x)	\
    (((x) >> S_FW_FCOE_FCF_CMD_FCFI) & M_FW_FCOE_FCF_CMD_FCFI)

#define S_FW_FCOE_FCF_CMD_PRIORITY	0
#define M_FW_FCOE_FCF_CMD_PRIORITY	0xff
#define V_FW_FCOE_FCF_CMD_PRIORITY(x)	((x) << S_FW_FCOE_FCF_CMD_PRIORITY)
#define G_FW_FCOE_FCF_CMD_PRIORITY(x)	\
    (((x) >> S_FW_FCOE_FCF_CMD_PRIORITY) & M_FW_FCOE_FCF_CMD_PRIORITY)

#define S_FW_FCOE_FCF_CMD_FPMA		6
#define M_FW_FCOE_FCF_CMD_FPMA		0x1
#define V_FW_FCOE_FCF_CMD_FPMA(x)	((x) << S_FW_FCOE_FCF_CMD_FPMA)
#define G_FW_FCOE_FCF_CMD_FPMA(x)	\
    (((x) >> S_FW_FCOE_FCF_CMD_FPMA) & M_FW_FCOE_FCF_CMD_FPMA)
#define F_FW_FCOE_FCF_CMD_FPMA	V_FW_FCOE_FCF_CMD_FPMA(1U)

#define S_FW_FCOE_FCF_CMD_SPMA		5
#define M_FW_FCOE_FCF_CMD_SPMA		0x1
#define V_FW_FCOE_FCF_CMD_SPMA(x)	((x) << S_FW_FCOE_FCF_CMD_SPMA)
#define G_FW_FCOE_FCF_CMD_SPMA(x)	\
    (((x) >> S_FW_FCOE_FCF_CMD_SPMA) & M_FW_FCOE_FCF_CMD_SPMA)
#define F_FW_FCOE_FCF_CMD_SPMA	V_FW_FCOE_FCF_CMD_SPMA(1U)

#define S_FW_FCOE_FCF_CMD_LOGIN		4
#define M_FW_FCOE_FCF_CMD_LOGIN		0x1
#define V_FW_FCOE_FCF_CMD_LOGIN(x)	((x) << S_FW_FCOE_FCF_CMD_LOGIN)
#define G_FW_FCOE_FCF_CMD_LOGIN(x)	\
    (((x) >> S_FW_FCOE_FCF_CMD_LOGIN) & M_FW_FCOE_FCF_CMD_LOGIN)
#define F_FW_FCOE_FCF_CMD_LOGIN	V_FW_FCOE_FCF_CMD_LOGIN(1U)

#define S_FW_FCOE_FCF_CMD_PORTID	0
#define M_FW_FCOE_FCF_CMD_PORTID	0xf
#define V_FW_FCOE_FCF_CMD_PORTID(x)	((x) << S_FW_FCOE_FCF_CMD_PORTID)
#define G_FW_FCOE_FCF_CMD_PORTID(x)	\
    (((x) >> S_FW_FCOE_FCF_CMD_PORTID) & M_FW_FCOE_FCF_CMD_PORTID)


