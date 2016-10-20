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
#ifndef __CSIO_FCOE_PROTO_H__
#define __CSIO_FCOE_PROTO_H__

/* FC header type */
#define FC_TYPE_ELS_DATA	0x1
#define FC_TYPE_CT_DATA		0x20
#define FC_TYPE_FCP_DATA	0x8

/* FC header rctl */
#define FC_RCTL_ELS_REQ		0x22
#define FC_RCTL_ELS_RSP		0x23
#define FC_RCTL_FCP_CMND	0x6	

/* Well known Fibre channel Address */
#define FDMI_DID	0xFFFFFA	/* Management server */		
#define NS_DID		0xFFFFFC	/* Name server */	
#define FABCTL_DID	0xFFFFFD	/* Fabric Controller */
#define FABRIC_DID	0xFFFFFE	/* Fabric Login */
#define BCAST_DID	0xFFFFFF	/* Broadcast */
#define UNKNOWN_DID	0x000000	/* Unknown DID */
#define DID_MASK	0xFFFFFF	/* DID Mask */
#define WK_DID_MASK	0xFFFFF0	/* Well known did mask */

/* FC4 Device Data Frame - TYPE */
#define FC4_FCP_TYPE	0x8		/* FCP */

/* MAX FC Payload */
#define MAX_FC_PAYLOAD	2112

/*Service option: Shift & Mask bits defines */
#define SP_CLASS_SUPPORT_EN	1 	/* Class support enable */
#define S_SP_CLASS_SUPPORT	7	
#define M_SP_CLASS_SUPPORT	1	
#define V_SP_CLASS_SUPPORT(x)	((x) << S_SP_CLASS_SUPPORT)
#define G_SP_CLASS_SUPPORT(x)	(((x) >> S_SP_CLASS_SUPPORT) & M_SP_CLASS_SUPPORT)

/* Class service parameters */
struct csio_class_sp {
	uint8_t		serv_option;		/* Service option */
	uint8_t		rsvd1;
	uint8_t		init_ctl_option;	/* initiator cntl option */
	uint8_t		rsvd2;
	uint8_t		rcv_ctl_option;		/* receiver cntl option */
	uint8_t		rsvd3;
	uint16_t	rcv_data_sz;		/* receive data size */
	uint16_t	concurrent_seq;		/* Total concurent sequence */
	uint16_t	ee_credit;		/* EE credit */
	uint16_t	openseq_per_xchg;	/* Open sequence per exch */
	uint16_t	rsvd4;
};

/* Common service parameters defines */

/* FC Phy version */
#define FC_PH_VER3			0x20	

/* WORD1 (31:16) flags: shift & mask bit defines */
/* NPIV support */
#define MULTIPLE_NPORT_ID_SUPPORT_EN	1
#define S_MULTIPLE_NPORT_ID_SUPPORT	15	
#define M_MULTIPLE_NPORT_ID_SUPPORT	1
#define V_MULTIPLE_NPORT_ID_SUPPORT(x)	((x) << S_MULTIPLE_NPORT_ID_SUPPORT)
#define G_MULTIPLE_NPORT_ID_SUPPORT(x)	(((x) >> S_MULTIPLE_NPORT_ID_SUPPORT) \
					 & M_MULTIPLE_NPORT_ID_SUPPORT)	

/* Continuously increasing relative offset */
#define CONTI_INCR_OFFSET_SUPPORT_EN	1
#define S_CONTI_INCR_OFFSET_SUPPORT	15	
#define M_CONTI_INCR_OFFSET_SUPPORT	1
#define V_CONTI_INCR_OFFSET_SUPPORT(x)	((x) << S_CONTI_INCR_OFFSET_SUPPORT)
#define G_CONTI_INCR_OFFSET_SUPPORT(x)	(((x) >> S_CONTI_INCR_OFFSET_SUPPORT) \
					 & M_CONTI_INCR_OFFSET_SUPPORT)	
/* Continuously increasing relative offset */
#define CLEAN_ADDR_EN		1
#define S_CLEAN_ADDR		15	
#define M_CLEAN_ADDR		1
#define V_CLEAN_ADDR(x)		((x) << S_CLEAN_ADDR)
#define G_CLEAN_ADDR(x)		(((x) >> S_CLEAN_ADDR) & M_CLEAN_ADDR)

/* NPIV supported by Fabric */
#define NPIV_SUPPORTED_EN	1
#define S_NPIV_SUPPORTED	13	
#define M_NPIV_SUPPORTED	1
#define V_NPIV_SUPPORTED(x)	((x) << S_NPIV_SUPPORTED)
#define G_NPIV_SUPPORTED(x)	(((x) >> S_NPIV_SUPPORTED) & M_NPIV_SUPPORTED)

/* N_Port or F_Port */
#define FABRIC_PORT			1
#define S_FABRIC_PORT			12	
#define M_FABRIC_PORT			1
#define V_FABRIC_PORT(x)		((x) << S_FABRIC_PORT)
#define G_FABRIC_PORT(x) 		(((x) >> S_FABRIC_PORT) & M_FABRIC_PORT)

/* Alternate B2B credit management support */
#define ALT_B2B_CREDIT_MGMT_SUPPORT_EN		1
#define S_ALT_B2B_CREDIT_MGMT_SUPPORT		11
#define M_ALT_B2B_CREDIT_MGMT_SUPPORT		1
#define V_ALT_B2B_CREDIT_MGMT_SUPPORT(x) 	\
	((x) << S_ALT_B2B_CREDIT_MGMT_SUPPORT)	
#define G_ALT_B2B_CREDIT_MGMT_SUPPORT(x) 	\
	(((x) >> S_ALT_B2B_CREDIT_MGMT_SUPPORT) & M_ALT_B2B_CREDIT_MGMT_SUPPORT)


/* WORD2 (31: 0) : shift and mask bit defines */
#define S_MAX_SEQ_CNT		16 
#define M_MAX_SEQ_CNT		0xFFFF
#define V_MAX_SEQ_CNT(x)	((x) << S_MAX_SEQ_CNT)
#define G_MAX_SEQ_CNT(x)	(((x) >> S_MAX_SEQ_CNT) & M_MAX_SEQ_CNT)
		 
#define S_REL_OFFSET_BY_CATEGORY	0 
#define M_REL_OFFSET_BY_CATEGORY	0xFFFF
#define V_REL_OFFSET_BY_CATEGORY(x)	((x) << S_REL_OFFSET_BY_CATEGORY)
#define G_REL_OFFSET_BY_CATEGORY(x)	\
	(((x) >> S_REL_OFFSET_BY_CATEGORY) & M_REL_OFFSET_BY_CATEGORY)

/* Common service parameters */
struct csio_cmn_sp {
	uint8_t		hi_ver;		/* High PH version */
	uint8_t		lo_ver;		/* low PH version */	
	uint16_t	bb_credit;	/* B2B credit */
	uint16_t	word1_flags;	/* Word1 Flags (31:16)*/
	uint16_t	rcv_sz;		/* Receive data size */
	union {
			uint32_t maxsq_reloff;	/* Max seq / Relative offset */
			uint32_t r_a_tov;	/* R_A_TOV */
	}un1;
	uint32_t	e_d_tov;		/*E_D_TOV */
};

/*
 * REVISIT: Do we need a Os specific __packed__ attribute for this struct ?
 * Like this:
 * struct csio_service_parms {
 * ..
 * } __csio_attribute_packed__ ;
 *
 * in defs:
 * #define __csio_attribute_packed__		__csio_oss_attribute_packed__
 *
 * and then in Linux CDHS:
 * #define __csio_oss_attribute_packed__ 	__attribute__((__packed__))
 */
struct csio_service_parms {
	struct csio_cmn_sp	csp;		/* Common service parms */
	uint8_t			wwpn[8];	/* WWPN */
	uint8_t			wwnn[8];	/* WWNN */
	struct csio_class_sp	clsp[4];	/* Class service params */
	uint8_t			vvl[16];	/* Vendor version level */
};

/* Common Transport (CT)  defines */
#define CT_BASIC_IU_LEN		0x10
#define CT_REVISION		0x1

/* GS Types */
#define CT_GS_MGMT_SERVICE		0xFA
#define CT_GS_TIME_SERVICE		0xFB
#define CT_GS_DIR_SERVICE		0xFC
#define CT_GS_FABRIC_CNTL_SERVICE	0xFD

/* Directory service Subtypes */
#define CT_DIR_SERVICE_NAME_SERVER	0x02

/* FDMI MGMT service Subtypes */
#define CT_FDMI_HBA_MGMT_SERVER		0x10

/* CT Response code */
#define CT_RESPONSE_FS_RJT		0x8001
#define CT_RESPONSE_FS_ACC		0x8002

/* CT Reason code */
#define  CT_NO_ADDITIONAL_EXPLANATION	0x00
#define  CT_INVALID_COMMAND		0x01
#define  CT_INVALID_VERSION_LEVEL	0x02
#define  CT_LOGICAL_ERROR		0x03
#define  CT_INVALID_IU_SIZE		0x04
#define  CT_LOGICAL_BUSY		0x05
#define  CT_PROTOCOL_ERROR		0x07
#define  CT_UNABLE_TO_PERFORM_CMD_REQ 	0x09
#define  CT_CMD_NOT_SUPPORTED		0x0B
#define  CT_VENDOR_UNIQUE		0xff

/* Name Server explanation for Reason code CT_UNABLE_TO_PERFORM_CMD_REQ */
#define  CT_NS_PORT_ID_NOT_REG			0x01
#define  CT_NS_PORT_NAME_NOT_REG		0x02
#define  CT_NS_NODE_NAME_NOT_REG		0x03
#define  CT_NS_CLASS_OF_SERVICE_NOT_REG		0x04
#define  CT_NS_IP_ADDRESS_NOT_REG		0x05
#define  CT_NS_IPA_NOT_REG			0x06
#define  CT_NS_FC4_TYPES_NOT_REG		0x07
#define  CT_NS_SYMBOLIC_PORT_NAME_NOT_REG	0x08
#define  CT_NS_SYMBOLIC_NODE_NAME_NOT_REG	0x09
#define  CT_NS_PORT_TYPE_NOT_REG		0x0A
#define  CT_NS_ACCESS_DENIED			0x10
#define  CT_NS_INVALID_PORT_ID			0x11
#define  CT_NS_DATABASE_EMPTY			0x12

/* Name Server Command Codes */
#define  CT_NS_GA_NXT	0x0100
#define  CT_NS_GPN_ID	0x0112
#define  CT_NS_GNN_ID	0x0113
#define  CT_NS_GCS_ID	0x0114
#define  CT_NS_GFT_ID	0x0117
#define  CT_NS_GSPN_ID	0x0118
#define  CT_NS_GPT_ID	0x011A
#define  CT_NS_GFF_ID	0x011F
#define  CT_NS_GID_PN	0x0121
#define  CT_NS_GID_NN	0x0131
#define  CT_NS_GIP_NN	0x0135
#define  CT_NS_GIPA_NN	0x0136
#define  CT_NS_GSNN_NN	0x0139
#define  CT_NS_GNN_IP	0x0153
#define  CT_NS_GIPA_IP	0x0156
#define  CT_NS_GID_FT	0x0171
#define  CT_NS_GPN_FT	0x0172
#define  CT_NS_GID_PT	0x01A1
#define  CT_NS_RPN_ID	0x0212
#define  CT_NS_RNN_ID	0x0213
#define  CT_NS_RCS_ID	0x0214
#define  CT_NS_RFT_ID	0x0217
#define  CT_NS_RSPN_ID	0x0218
#define  CT_NS_RPT_ID	0x021A
#define  CT_NS_RFF_ID	0x021F
#define  CT_NS_RIP_NN	0x0235
#define  CT_NS_RIPA_NN	0x0236
#define  CT_NS_RSNN_NN	0x0239
#define  CT_NS_DA_ID	0x0300

/* FDMI HBA management Server Command Codes */
#define  CT_FDMI_HBA_GRHL	0x100	/* Get registered HBA list */
#define  CT_FDMI_HBA_GHAT	0x101	/* Get HBA attributes */
#define  CT_FDMI_HBA_GRPL	0x102	/* Get registered Port list */
#define  CT_FDMI_HBA_GPAT	0x110	/* Get Port attributes */
#define  CT_FDMI_HBA_RHBA	0x200	/* Register HBA */
#define  CT_FDMI_HBA_RHAT	0x201	/* Register HBA atttributes */
#define  CT_FDMI_HBA_RPRT	0x210	/* Register Port */
#define  CT_FDMI_HBA_RPA	0x211	/* Register Port attributes */
#define  CT_FDMI_HBA_DHBA	0x300	/* De-register HBA */
#define  CT_FDMI_HBA_DPRT	0x310	/* De-register Port */

/* HBA Attribute Types */
#define  NODE_NAME               0x1
#define  MANUFACTURER            0x2
#define  SERIAL_NUMBER           0x3
#define  MODEL                   0x4
#define  MODEL_DESCRIPTION       0x5
#define  HARDWARE_VERSION        0x6
#define  DRIVER_VERSION          0x7
#define  OPTION_ROM_VERSION      0x8
#define  FIRMWARE_VERSION        0x9
#define  OS_NAME_VERSION         0xa
#define  MAX_CT_PAYLOAD_LEN      0xb

/* Port Attrubute Types */
#define  SUPPORTED_FC4_TYPES     0x1
#define  SUPPORTED_SPEED         0x2
#define  PORT_SPEED              0x3
#define  MAX_FRAME_LEN		 0x4
#define  OS_DEVICE_NAME          0x5
#define  HOST_NAME               0x6

#define CSIO_HBA_PORTSPEED_1GBIT	0x0001  /* 1 GBit/sec */
#define CSIO_HBA_PORTSPEED_2GBIT	0x0002  /* 2 GBit/sec */
#define CSIO_HBA_PORTSPEED_4GBIT	0x0008  /* 4 GBit/sec */
#define CSIO_HBA_PORTSPEED_10GBIT	0x0004  /* 10 GBit/sec */
#define CSIO_HBA_PORTSPEED_8GBIT	0x0010  /* 8 GBit/sec */
#define CSIO_HBA_PORTSPEED_16GBIT	0x0020  /* 16 GBit/sec */
#define CSIO_HBA_PORTSPEED_UNKNOWN	0x0800  /* Unknown */

/* Port Types */
#define  CT_PORT_TYPE_N_PORT	0x01
#define  CT_PORT_TYPE_NL_PORT	0x02
#define  CT_PORT_TYPE_FNL_PORT	0x03
#define  CT_PORT_TYPE_IP	0x04
#define  CT_PORT_TYPE_FCP	0x08
#define  CT_PORT_TYPE_NX_PORT	0x7F
#define  CT_PORT_TYPE_F_PORT	0x81
#define  CT_PORT_TYPE_FL_PORT	0x82
#define  CT_PORT_TYPE_E_PORT	0x84

/* FC4 Feature bit defination */
#define FC4_FEATURE_TARGET_EN		1
#define S_FC4_FEATURE_TARGET		0 
#define M_FC4_FEATURE_TARGET		1
#define V_FC4_FEATURE_TARGET(x)		((x) << S_FC4_FEATURE_TARGET)
#define G_FC4_FEATURE_TARGET(x)	\
	(((x) >> S_FC4_FEATURE_TARGET) & M_FC4_FEATURE_TARGET)

#define FC4_FEATURE_INITIATOR_EN	1 
#define S_FC4_FEATURE_INITIATOR		1 
#define M_FC4_FEATURE_INITIATOR		1
#define V_FC4_FEATURE_INITIATOR(x)	((x) << S_FC4_FEATURE_INITIATOR)
#define G_FC4_FEATURE_INITIATOR(x)	\
	(((x) >> S_FC4_FEATURE_INITIATOR) & M_FC4_FEATURE_INITIATOR)

/* GPN_FT ACC Control bit defination */
#define GPN_FT_ACC_CONTROL_EN		1
#define S_GPN_FT_ACC_CONTROL		31 
#define M_GPN_FT_ACC_CONTROL		1
#define V_GPN_FT_ACC_CONTROL(x)		((x) << S_GPN_FT_ACC_CONTROL)
#define G_GPN_FT_ACC_CONTROL(x)	\
	(((x) >> S_GPN_FT_ACC_CONTROL) & M_GPN_FT_ACC_CONTROL)

/* CT command */
struct csio_ct_cmd {
	uint8_t		rev;		/* Revision */
	uint8_t		in_id[3];	/* Unused */
	uint8_t		gs_type;	/* Type of service */
	uint8_t		gs_subtype;	/* Sub type */
	uint8_t		opt;		/* Options */
	uint8_t		rsvd1;
	uint16_t	op;		/* Command or response code */		
	uint16_t	size;		/* Maximum or Residual size */
	uint8_t		rsvd2;
	uint8_t		reason_code;	/* Reason code */
	uint8_t		explanation;	/* Explanation code */
	uint8_t		vendor_unique;	/* Vendor specific reason code */
	
	union {
		uint32_t port_id;	/* Port_id list for GID_FT ACC */

		struct	gid_ft {
			uint8_t port_type;	/* Port Type */
			uint8_t	domain_scope;	/* Domain scope */
			uint8_t	area_scope;	/* Area scope */
			uint8_t	fc4_type;       /* FC4 Type = FCP(0x8) */
		} gid_ft;
		
		struct	gpn_ft {
			uint8_t rsvd;		
			uint8_t	domain_scope;	/* Domain scope */
			uint8_t	area_scope;	/* Area scope */
			uint8_t	fc4_type;       /* FC4 Type = FCP(0x8) */
		} gpn_ft;

		/* Port_id & Port name list for GPN_FT ACC */
		struct	gpn_ft_acc {  
			uint32_t port_id;	/* port id */
			uint32_t rsvd;		
			uint8_t	 wwpn[8];	/* Port name */
		} gpn_ft_acc;

		struct	rft_id {
			uint32_t port_id;	/* port id */
			uint16_t rsvd1;
			uint8_t	 fcp;		/* FCP Type */ 
			uint8_t	 rsvd2;
			uint8_t	 rsvd3[28];
		} rft_id;	
	
		struct rnn_id {
			uint32_t port_id;	/* Port id */
			uint8_t	 wwnn[8];	/* Node name */
		} rnn_id;

		struct da_id {
			uint32_t port_id;	/* Port id */
		} da_id;

		struct	rff_id {
			uint32_t port_id;	/* Port id */
			uint8_t  rsvd1[2];	
			uint8_t  fc4_fbits;	/* FC4 feature bits */
			uint8_t  fc4_type;	/* FC4 Type = FCP(0x8) */
		} rff_id;

		struct gspn_id {
			uint32_t port_id;	/* Port id */
		}gspn_id;
	} un;
};

#define csio_ct_rsp(cp)		(((struct csio_ct_cmd *) cp)->op)
#define csio_ct_reason(cp)	(((struct csio_ct_cmd *) cp)->reason_code)
#define csio_ct_expl(cp)	(((struct csio_ct_cmd *) cp)->explanation)
#define csio_ct_get_pld(cp)	((void *)(((uint8_t *)cp) + CT_BASIC_IU_LEN))

static inline void
csio_fill_ct_iu(void *buf, uint8_t type, uint8_t sub_type,
		uint16_t op)
{		
	struct csio_ct_cmd *cmd = (struct csio_ct_cmd *) buf;
	cmd->rev = CT_REVISION;
	cmd->gs_type = type;
	cmd->gs_subtype = sub_type;
	cmd->op = op;
}	
		
/* FDMI HBA cmd */

/* Attribute entry */
struct csio_attrib_entry {
	uint16_t type;		/* Entry type */
	uint16_t len;		/* Entry length */
	union	{
		uint8_t	string[256];	/* Attribute value in string */
		uint32_t integer;	/* Attribute value in integer */	
	} val;
};	


/* attribute block */
struct csio_attrib_block {
	uint32_t entry_count;		/* Entry count */
	struct csio_attrib_entry entry; /* list of attributes */
};	

/* HBA identifier */
struct csio_hba_identifier {
	uint8_t	 wwpn[8];	/* Port name */
};	

/* Port entry */
struct csio_port_entry {
	uint8_t	 wwpn[8];	/* Port name */
};	

/* register port list */
struct csio_reg_port_list {
	uint32_t entry_count;		/* Entry count */
	struct csio_port_entry entry; 	/* list of port entry */
};	

/* register HBA */
struct csio_reg_hba {
	struct csio_hba_identifier id;		/* HBA identifier */
	struct csio_reg_port_list port_list;	/* port entry list */
};	

/* register HBA attributes */
struct csio_reg_hba_attrib {
	struct csio_hba_identifier id;		/* HBA identifier */
	struct csio_attrib_block attrib_list; 	/* Attribute list */
};	

/* register Port attributes */
struct csio_reg_port_attrib {
	uint8_t	 wwpn[8];	/* Port name */
	struct csio_attrib_block attrib_list; /* Attribute list */
};	

/* Get register hba list(GRHL) accept payload */
struct csio_grhl_acc_pld  {
	uint32_t entry_count;		/* Entry count */
	struct csio_hba_identifier id;	/* HBA identifier list */
};	

/* Get register port list(GRPL) accept payload */
struct csio_grpl_acc_pld  {
	uint32_t entry_count;		/* Entry count */
	struct csio_port_entry entry;	/* port entry list */
};	

/* Get port attributes (GPAT) accept payload */
struct csio_gpat_acc_pld  {
	struct csio_attrib_block attrib_list; /* Attribute list */
};	

/* ELS CMD HDR length */
#define ELS_CMD_HDR_LEN		0x4

/* ELS COMMAND CODES */
#define ELS_CMD_CODE_MASK	0xff
#define ELS_CMD_CODE_LS_RJT	0x01
#define ELS_CMD_CODE_ACC	0x02
#define ELS_CMD_CODE_PLOGI	0x03
#define ELS_CMD_CODE_FLOGI	0x04
#define ELS_CMD_CODE_LOGO	0x05
#define ELS_CMD_CODE_RES	0x08
#define ELS_CMD_CODE_RSS	0x09
#define ELS_CMD_CODE_RSI	0x0A
#define ELS_CMD_CODE_ESTS	0x0B
#define ELS_CMD_CODE_ESTC	0x0C
#define ELS_CMD_CODE_ADVC	0x0D
#define ELS_CMD_CODE_RTV	0x0E
#define ELS_CMD_CODE_RLS	0x0F
#define ELS_CMD_CODE_ECHO	0x10
#define ELS_CMD_CODE_TEST	0x11
#define ELS_CMD_CODE_PRLI	0x20
#define ELS_CMD_CODE_PRLO	0x21
#define ELS_CMD_CODE_PDISC	0x50
#define ELS_CMD_CODE_FDISC	0x51
#define ELS_CMD_CODE_ADISC	0x52
#define ELS_CMD_CODE_RPS	0x56
#define ELS_CMD_CODE_RPL	0x57
#define ELS_CMD_CODE_RSCN	0x61
#define ELS_CMD_CODE_SCR	0x62
#define ELS_CMD_CODE_RNID	0x78
#define ELS_CMD_CODE_LIRR	0x7A

/* LS_RJT reason codes */
#define LS_RJT_INVALID_CMD     0x01
#define LS_RJT_LOGICAL_ERR     0x03
#define LS_RJT_LOGICAL_BSY     0x05
#define LS_RJT_PROTOCOL_ERR    0x07
#define LS_RJT_UNABLE_TPC      0x09      
#define LS_RJT_CMD_UNSUPPORTED 0x0B
#define LS_RJT_VENDOR_UNIQUE   0xFF 

/* LS_RJT reason explanation */
#define LS_RJT_EXPL_NONE	      0x00
#define LS_RJT_EXPL_SPARM_OPTIONS     0x01
#define LS_RJT_EXPL_SPARM_ICTL        0x03
#define LS_RJT_EXPL_SPARM_RCTL        0x05
#define LS_RJT_EXPL_SPARM_RCV_SIZE    0x07
#define LS_RJT_EXPL_SPARM_CONCUR_SEQ  0x09
#define LS_RJT_EXPL_SPARM_CREDIT      0x0B
#define LS_RJT_EXPL_INVALID_PNAME     0x0D
#define LS_RJT_EXPL_INVALID_NNAME     0x0E
#define LS_RJT_EXPL_INVALID_CSP       0x0F
#define LS_RJT_EXPL_INVALID_ASSOC_HDR 0x11
#define LS_RJT_EXPL_ASSOC_HDR_REQ     0x13
#define LS_RJT_EXPL_INVALID_O_SID     0x15
#define LS_RJT_EXPL_INVALID_OX_RX     0x17
#define LS_RJT_EXPL_CMD_IN_PROGRESS   0x19
#define LS_RJT_EXPL_PORT_LOGIN_REQ    0x1E
#define LS_RJT_EXPL_INVALID_NPORT_ID  0x1F
#define LS_RJT_EXPL_INVALID_SEQ_ID    0x21
#define LS_RJT_EXPL_INVALID_XCHG      0x23
#define LS_RJT_EXPL_INACTIVE_XCHG     0x25
#define LS_RJT_EXPL_RQ_REQUIRED       0x27
#define LS_RJT_EXPL_OUT_OF_RESOURCE   0x29
#define LS_RJT_EXPL_CANT_GIVE_DATA    0x2A
#define LS_RJT_EXPL_REQ_UNSUPPORTED   0x2C

/* PRLI Page and Payload length  */
#define PRLI_PAGE_LEN		0x10
#define PRLI_PAYLOAD_LEN	0x14

/* PRLI/PRLO PROCESS FLAGS */
/* Originator Proc Associator valid */
#define PRLILO_ORG_PA_VALID		1	 
#define S_PRLILO_ORG_PA_VALID		7 
#define M_PRLILO_ORG_PA_VALID		1
#define V_PRLILO_ORG_PA_VALID(x)	((x) << S_PRLILO_ORG_PA_VALID)
#define G_PRLILO_ORG_PA_VALID(x)	\
	(((x) >> S_PRLILO_ORG_PA_VALID) & M_PRLILO_ORG_PA_VALID)

/* Responder Proc Associator valid */
#define PRLILO_RSP_PA_VALID		1 
#define S_PRLILO_RSP_PA_VALID		6 
#define M_PRLILO_RSP_PA_VALID		1
#define V_PRLILO_RSP_PA_VALID(x)	((x) << S_PRLILO_RSP_PA_VALID)
#define G_PRLILO_RSP_PA_VALID(x)	\
	(((x) >> S_PRLILO_RSP_PA_VALID) & M_PRLILO_RSP_PA_VALID)

/* Image pair established */
#define PRLILO_IMG_PAIR_ESTB		1 
#define S_PRLILO_IMG_PAIR_ESTB		5 
#define M_PRLILO_IMG_PAIR_ESTB		1
#define V_PRLILO_IMG_PAIR_ESTB(x)	((x) << S_PRLILO_IMG_PAIR_ESTB)
#define G_PRLILO_IMG_PAIR_ESTB(x)	\
	(((x) >> S_PRLILO_IMG_PAIR_ESTB) & M_PRLILO_IMG_PAIR_ESTB)

/* PRLI Response code  */
#define PRLI_RSP_CODE		
#define S_PRLI_RSP		0 
#define M_PRLI_RSP		0xf
#define V_PRLI_RSP(x)	((x) << S_PRLI_RSP)
#define G_PRLI_RSP(x)	\
	(((x) >> S_PRLI_RSP) & M_PRLI_RSP)

/* PRLI Service Parameter flags */
/* FCP Write xfer ready disabled */
#define PRLI_FCP_WRITE_XFER_RD_DIS	1 
#define S_PRLI_FCP_WRITE_XFER_RD_DIS	0 
#define M_PRLI_FCP_WRITE_XFER_RD_DIS	1
#define V_PRLI_FCP_WRITE_XFER_RD_DIS(x)	((x) << S_PRLI_FCP_WRITE_XFER_RD_DIS)
#define G_PRLI_FCP_WRITE_XFER_RD_DIS(x)	\
	(((x) >> S_PRLI_FCP_WRITE_XFER_RD_DIS) & M_PRLI_FCP_WRITE_XFER_RD_DIS)

/* FCP read xfer ready disabled */
#define PRLI_FCP_READ_XFER_RD_DIS	1 
#define S_PRLI_FCP_READ_XFER_RD_DIS	1 
#define M_PRLI_FCP_READ_XFER_RD_DIS	1
#define V_PRLI_FCP_READ_XFER_RD_DIS(x)	((x) << S_PRLI_FCP_READ_XFER_RD_DIS)
#define G_PRLI_FCP_READ_XFER_RD_DIS(x)	\
	(((x) >> S_PRLI_FCP_READ_XFER_RD_DIS) & M_PRLI_FCP_READ_XFER_RD_DIS)

/* FCP data response mix disabled */
#define PRLI_FCP_DATA_RSP_MIX_DIS	1 
#define S_PRLI_FCP_DATA_RSP_MIX_DIS	2 
#define M_PRLI_FCP_DATA_RSP_MIX_DIS	1
#define V_PRLI_FCP_DATA_RSP_MIX_DIS(x)	((x) << S_PRLI_FCP_DATA_RSP_MIX_DIS)
#define G_PRLI_FCP_DATA_RSP_MIX_DIS(x)	\
	(((x) >> S_PRLI_FCP_DATA_RSP_MIX_DIS) & M_PRLI_FCP_DATA_RSP_MIX_DIS)

/* FCP cmd data mix disabled */
#define PRLI_FCP_CMD_DATA_MIX_DIS	1 
#define S_PRLI_FCP_CMD_DATA_MIX_DIS	3 
#define M_PRLI_FCP_CMD_DATA_MIX_DIS	1
#define V_PRLI_FCP_CMD_DATA_MIX_DIS(x)	((x) << S_PRLI_FCP_CMD_DATA_MIX_DIS)
#define G_PRLI_FCP_CMD_DATA_MIX_DIS(x)	\
	(((x) >> S_PRLI_FCP_CMD_DATA_MIX_DIS) & M_PRLI_FCP_CMD_DATA_MIX_DIS)

/* FCP Target function */
#define PRLI_FCP_TARGET_FUNC		1 
#define S_PRLI_FCP_TARGET_FUNC		4 
#define M_PRLI_FCP_TARGET_FUNC		1
#define V_PRLI_FCP_TARGET_FUNC(x)	((x) << S_PRLI_FCP_TARGET_FUNC)
#define G_PRLI_FCP_TARGET_FUNC(x)	\
	(((x) >> S_PRLI_FCP_TARGET_FUNC) & M_PRLI_FCP_TARGET_FUNC)

/* FCP Initiator function */
#define PRLI_FCP_INITIATOR_FUNC		1 
#define S_PRLI_FCP_INITIATOR_FUNC	5 
#define M_PRLI_FCP_INITIATOR_FUNC	1
#define V_PRLI_FCP_INITIATOR_FUNC(x)	((x) << S_PRLI_FCP_INITIATOR_FUNC)
#define G_PRLI_FCP_INITIATOR_FUNC(x)	\
	(((x) >> S_PRLI_FCP_INITIATOR_FUNC) & M_PRLI_FCP_INITIATOR_FUNC)

/* FCP Data overlay */
#define PRLI_FCP_DATA_OVERLAY		1 
#define S_PRLI_FCP_DATA_OVERLAY		6 
#define M_PRLI_FCP_DATA_OVERLAY		1
#define V_PRLI_FCP_DATA_OVERLAY(x)	((x) << S_PRLI_FCP_DATA_OVERLAY)
#define G_PRLI_FCP_DATA_OVERLAY(x)	\
	(((x) >> S_PRLI_FCP_DATA_OVERLAY) & M_PRLI_FCP_DATA_OVERLAY)

/* FCP confirmed completion */
#define PRLI_FCP_CONF_COMPL_ALLOWED	 1 
#define S_PRLI_FCP_CONF_COMPL_ALLOWED	 7 
#define M_PRLI_FCP_CONF_COMPL_ALLOWED	 1
#define V_PRLI_FCP_CONF_COMPL_ALLOWED(x) ((x) << S_PRLI_FCP_CONF_COMPL_ALLOWED)
#define G_PRLI_FCP_CONF_COMPL_ALLOWED(x)	\
	(((x) >> S_PRLI_FCP_CONF_COMPL_ALLOWED) & M_PRLI_FCP_CONF_COMPL_ALLOWED)

/* FCP retry */
#define PRLI_FCP_RETRY		1 
#define S_PRLI_FCP_RETRY	8 
#define M_PRLI_FCP_RETRY	1
#define V_PRLI_FCP_RETRY(x)	((x) << S_PRLI_FCP_RETRY)
#define G_PRLI_FCP_RETRY(x)	(((x) >> S_PRLI_FCP_RETRY) & M_PRLI_FCP_RETRY)

/* FCP Task retry id request */
#define PRLI_FCP_TASK_ID_REQ		1 
#define S_PRLI_FCP_TASK_ID_REQ		9 
#define M_PRLI_FCP_TASK_ID_REQ		1
#define V_PRLI_FCP_TASK_ID_REQ(x)	((x) << S_PRLI_FCP_TASK_ID_REQ)
#define G_PRLI_FCP_TASK_ID_REQ(x)	\
	(((x) >> S_PRLI_FCP_TASK_ID_REQ) & M_PRLI_FCP_TASK_ID_REQ)

/* SCR Function */
#define SCR_FUNCTION_FABRIC	0x01
#define SCR_FUNCTION_NPORT	0x02
#define SCR_FUNCTION_FULL	0x03
#define SCR_FUNCTION_CLEAR	0xFF

/* PRLI accept response code */
#define PRLI_REQ_COMPLETED   		0x1       
#define PRLI_RES_UNAVAIL		0x2
#define PRLI_INIT_NOT_COMPLETE 		0x3
#define PRLI_RESP_PA_NO_FOUND  		0x4
#define PRLI_REQ_CONDITIONAL   		0x5
#define PRLI_RECP_PRECONFIG  		0x6
#define PRLI_MULTIPAGE_REQ_FAILED  	0x7
#define PRLI_INVALID_SP 		0x8


/* MAX RETIRES */
#define MAX_ELS_RETRY		3

/* ELS request */
struct csio_els_cmd {
	uint8_t	op;	/* ELS command code*/
	uint8_t byte1;
	uint8_t	byte2;
	uint8_t	byte3;

	union {
		struct ls_rjt {
			uint8_t	rsvd1;
			uint8_t	reason_code;	/* Reason code */
			uint8_t	reason_exp;	/* Explanation */
			uint8_t vendor_unique;	/* Vendor unique code */
		} ls_rjt;
		
		struct ls_logi {
			/* Service Parameters */
			struct csio_service_parms sp;
		} ls_logi;

		struct logo {
			uint32_t nport_id;	/* NPort Id */
			uint8_t	 wwpn[8];	/* Port name */	
		} logo;

		struct prli {
			uint8_t	 type;		/* Type code */
			uint8_t	 rsvd1;	
			uint8_t	 proc_flags;	/* Process Flags */
			uint8_t  rsvd2;		

			/* Originator Process Associator */
			uint32_t ori_proc_assoc; 

			/* Responder Process Associator */
			uint32_t rsp_proc_assoc;

			/* Service parameter flags */
			uint32_t serv_parms_flags;	
		} prli;

		struct prlo {
			uint8_t	 type;		/* Type code */
			uint8_t	 rsvd1;
			uint8_t	 proc_flags;	/* Process flags */
			uint8_t  rsvd2;

			/* Originator Process Associator */
			uint32_t ori_proc_assoc;

			/* Responder Process Associator */
			uint32_t rsp_proc_assoc;
			uint32_t rsvd3;
		} prlo;
	
		struct adisc {
			uint32_t hard_addr;	/* Hard address of originator */
			uint8_t	 wwpn[8];	/* Port name */
			uint8_t	 wwnn[8];	/* Node name */
			uint32_t nport_id;	/* Nport id */
		} adisc;

		struct scr {
			uint8_t	rsvd[3];	
			uint8_t	func;		/* SCR Function */
		} scr;

		struct rscn {
			uint32_t nport_id;	/* Nport id list */
		} rscn;
	} un;
};

/* FCP defines */
/*
 * pri_ta.
 */
#define FCP_PTA_SIMPLE		0x0		/* simple queue tag */
#define FCP_PTA_HEADQ		0x1		/* head of queue tag */
#define FCP_PTA_ORDERED		0x2		/* ordered task attribute */
#define FCP_PTA_ACA		0x4		/* auto. contigent allegiance */
#define FCP_PTA_UNTAGGED	0x5 

#define FCP_PRI_SHIFT		3		/* priority field starts 
						 * in bit 3
						 */
#define FCP_PRI_RESVD_MASK	0x80		/* reserved bits in priority
						 * field
						 */

/*
 * tm_flags - task management flags field.
 */
#define FCP_TMF_ABT_TASK_SET    0x02		/* abort task set */
#define FCP_TMF_CLR_TASK_SET    0x04		/* clear task set */
#define FCP_TMF_BUS_RESET       0x08		/* bus reset */
#define FCP_TMF_LUN_RESET       0x10		/* LUN reset */
#define FCP_TMF_TGT_RESET       0x20		/* Target reset */
#define FCP_TMF_CLR_ACA         0x40		/* clear ACA condition */
#define FCP_TMF_TERM_TASK       0x80		/* Terminate task */

/*
 * flags.
 * Bits 7:2 are the additional FCP_CDB length / 4.
 */
#define FCP_CFL_LEN_MASK        0xfc    /* mask for additional length */
#define FCP_CFL_LEN_SHIFT       2       /* shift bits for additional length */
#define FCP_CFL_RDDATA          0x02    /* read data */
#define FCP_CFL_WRDATA          0x01    /* write data */

struct csio_fcp_cmnd {
        uint8_t		lun[8];			/* logical unit number */
        uint8_t		cmdref;      		/* commmand reference number */
        uint8_t		pri_ta;			/* priority and task 
						 * attribute
						 */
	uint8_t		tm_flags;		/* task management flags */
	uint8_t		flags;			/* additional len & flags */
	uint8_t 	cdb[16];		/* CDB */
	uint32_t 	dl;			/* data length */
};

/* Response Flags */
#define FCP_BIDI_RSP		0x80		/* bidirectional read rsp */
#define FCP_BIDI_READ_UNDER 	0x40		/* bidi read underrun */
#define FCP_BIDI_READ_OVER  	0x20		/* bidi read overrun */
#define FCP_CONF_REQ		0x10		/* confirmation requested */
#define FCP_RESID_UNDER		0x08		/* transfer shorter than
						 * expected
						 */
#define FCP_RESID_OVER		0x04		/* DL insufficient for 
						 * full transfer
						 */
#define FCP_SNS_LEN_VAL		0x02		/* SNS_LEN field is valid */
#define FCP_RSP_LEN_VAL		0x01		/* RSP_LEN field is valid */

/* Response codes */
#define FCP_TMF_CMPL		0x00
#define FCP_DATA_LEN_INVALID	0x01
#define FCP_CMND_FIELDS_INVALID 0x02
#define FCP_DATA_PARAM_MISMATCH	0x03
#define FCP_TMF_REJECTED	0x04
#define FCP_TMF_FAILED		0x05
#define FCP_TMF_SUCCEEDED	0x05
#define FCP_TMF_INVALID_LUN	0x09

struct csio_fcp_resp {
	uint8_t		rsvd0[8];
	uint16_t	retry_delay;		/* retry delay timer */
        uint8_t		flags;			/* flags */
        uint8_t		scsi_status;		/* SCSI status code */
	uint32_t	resid;			/* Residual bytes */
	uint32_t	sns_len;		/* Length of sense data */
	uint32_t	rsp_len;		/* Length of response */
	uint8_t		rsvd1;
	uint8_t		rsvd2;
	uint8_t		rsvd3;
	uint8_t		rsp_code;		/* Response code */
	uint8_t		sns_data[128];
};

#endif /* __CSIO_FCOE_PROTO_H__ */
