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

#ifndef __CSIO_LNODE_FCOE_H__
#define __CSIO_LNODE_FCOE_H__

#include <csio_defs.h>
#include <csio_wr.h>
#include <csio_scsi.h>
#include <csio_mb_helpers.h>
#include <csio_fcoe_proto.h>
#include <csio_fcoe_boot.h>

/* FW interface FCoE defines */
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

enum fcoe_cmn_type {
	FCOE_ELS,
	FCOE_CT,
	FCOE_SCSI_CMD,
	FCOE_UNSOL_ELS,
};

#define CSIO_FCOE_MAX_NPIV		128
#define CSIO_MAX_FCF			16	/* As per config file */	

#define CSIO_FCOE_NEQ			0	
#define CSIO_FCOE_NIQ			0	
#define CSIO_FCOE_NFLQ			0	
#define	CSIO_FCOE_NUMQ			0		
#define CSIO_FCOE_FLLEN			CSIO_MGMT_FLLEN

extern int csio_max_fcf;
extern int csio_cos;
extern int csio_fcoe_rnodes;
extern int csio_fdmi_enable;

/* State machine evets */
typedef enum {
	CSIO_LNFE_NONE = (uint32_t)0,
	CSIO_LNFE_LINK_INIT,
	CSIO_LNFE_NPIV_INIT,
	CSIO_LNFE_LINKUP,
	CSIO_LNFE_FAB_INIT_DONE,
	CSIO_LNFE_NAME_REGD,
	CSIO_LNFE_SCAN,
	CSIO_LNFE_LINK_DOWN,
	CSIO_LNFE_DOWN_LINK,
	CSIO_LNFE_LINK_DOWN_DONE,
	CSIO_LNFE_LOGO,
	CSIO_LNFE_RESET,
	CSIO_LNFE_CLOSE,
	CSIO_LNFE_MAX_EVENT,
} csio_lnf_ev_t;

/* FCoE Lnode stats */
struct csio_lnode_fcoestats {

	/*
	 * NOTE: Make sure the following fields are in sync with
	 *      struct _csio_lnode_fcoestats in csio_fcoe_ioctl.h
	 *
	 */

	uint32_t	n_link_up;	/* Link down */
	uint32_t	n_link_down;	/* Link up */
	uint32_t	n_err;		/* error */
	uint32_t	n_err_nomem;	/* memory not available */
	uint32_t	n_inval_parm;   /* Invalid parameters */
	uint32_t	n_evt_unexp;	/* unexpected event */
	uint32_t	n_evt_drop;	/* dropped event */
	uint32_t	n_rnode_match;  /* matched rnode */
	uint32_t	n_dev_loss_tmo; /* Device loss timeout */
	uint32_t	n_fdmi_err;	/* fdmi err */
	uint32_t  	n_evt_fw[RSCN_DEV_LOST]; 	/* fw events */
	csio_lnf_ev_t   n_evt_sm[CSIO_LNFE_MAX_EVENT]; 	/* State m/c events */
	uint32_t	rsvd1;
};

/* FCoe Lnode params */
struct csio_lnode_fcoeparams {
	uint32_t	ra_tov;
	uint32_t	fcfi;	
	uint32_t	rsvd1;
};

struct csio_fcf_info {
	struct csio_list	list;
	uint8_t			priority;
	uint8_t			mac[6];
	uint8_t			name_id[8];
	uint8_t			fabric[8];
	uint16_t		vf_id;
	uint8_t			vlan_id;
	uint16_t		max_fcoe_size;
	uint8_t			fc_map[3];
	uint32_t		fka_adv;
	uint32_t		fcfi;
	uint8_t			get_next:1;
	uint8_t			link_aff:1;
	uint8_t			fpma:1;
	uint8_t			spma:1;
	uint8_t			login:1;
	uint8_t   		portid;
	uint8_t			spma_mac[6];
	csio_kref_t			kref;
};


/* Defines for flags */
#define	CSIO_LNFFLAG_FIPSUPP		0x00000001	/* Fip Supported */
#define	CSIO_LNFFLAG_NPIVSUPP		0x00000002	/* NPIV supported */
#define CSIO_LNFFLAG_CLEAN_ADDR		0x00000004	/* Clean Address set */	
#define CSIO_LNFFLAG_LINK_ENABLE	0x00000008	/* Link enabled */
#define	CSIO_LNFFLAG_FDMI_ENABLE	0x00000010	/* FDMI support */

struct csio_lnode_fcoe {
	struct csio_sm		sm;	 		/* State machine */
					 		/* should be the 1st 
							 * member 
							 */
	struct csio_lnode	*ln; 	 		/* Owning lnode */
	uint32_t		flags;	 		/* Flags */
	struct csio_list 	fcf_lsthead;		/* FCF entries */
	struct csio_fcf_info	*fcfinfo;		/* FCF in use */
	struct csio_ioreq 	*mgmt_req;		/* MGMT request */

	/* FCoE identifiers for this Lnode */
	uint8_t			mac[6];
	uint32_t		nport_id;

	struct csio_service_parms ln_sparm; 		/* Service parms */
	/* Firmware identifiers */
	uint32_t		fcf_flowid;		/*fcf flowid */
	uint32_t		vnp_flowid;
	uint16_t		ssn_cnt;		/* Registered Session */
	uint8_t			cur_evt;		/* Current event */
	uint8_t			prev_evt;		/* Previous event */

	struct csio_lnode_fcoestats  stats;		/* Common lnode stats */
	struct csio_lnode_fcoeparams tparams;		/* Common lnode params*/
};

#define	csio_lnf_to_elsct(lnf)		((lnf)->elsctm)
#define	csio_lnf_to_fcoescsi(lnf)	((lnf)->scsim)
#define	csio_lnf_flowid(lnf)		((lnf)->vnp_flowid)
#define csio_lnf_wwpn(lnf)		((lnf)->ln_sparm.wwpn)
#define csio_lnf_wwnn(lnf)		((lnf)->ln_sparm.wwnn)

#define csio_root_lnf(lnf)	(csio_lnode_to_fcoe(csio_root_lnode((lnf)->ln)))
#define csio_parent_lnf(lnf)	(csio_lnode_to_fcoe(csio_parent_lnode((lnf)->ln)))
#define csio_is_root_lnf(lnf)	(((lnf) == csio_root_lnf((lnf))) ? 1 : 0)
#define csio_is_phys_lnf(lnf)	(((lnf)->ln->pln == NULL) ? 1 : 0)
#define csio_is_npiv_lnf(lnf)	(((lnf)->ln->pln != NULL) ? 1 : 0)

void csio_fcoe_fwevt_handler(struct csio_hw *,  __u8 cpl_op, __be64 *);

int csio_is_lnf_ready(struct csio_lnode_fcoe *);
enum csio_oss_error csio_lnf_start(struct csio_lnode_fcoe *);
csio_retval_t csio_fcoe_enable_link(struct csio_lnode_fcoe *, bool);
void csio_lnf_stop(struct csio_lnode_fcoe *);
void csio_lnf_close(struct csio_lnode_fcoe *);
void csio_lnf_down(struct csio_lnode_fcoe *);
csio_retval_t csio_lnf_init(struct csio_lnode_fcoe *);
void csio_lnf_exit(struct csio_lnode_fcoe *);

struct csio_lnode *csio_fcoe_get_next_lnode(struct csio_hw *hw, uint32_t vnpi);
struct csio_fcf_info *csio_fcoe_get_next_fcf(struct csio_hw *hw, uint32_t fcfi);
void csio_lnf_stateto_str(struct csio_lnode_fcoe *lnf, int8_t *str);

struct csio_lnode_fcoe *
csio_lnf_lookup_by_portid(struct csio_hw *hw, uint8_t portid);
struct csio_lnode_fcoe *
csio_lnf_lookup_by_wwpn(struct csio_hw *hw, uint8_t *wwpn);
struct csio_lnode_fcoe *
csio_lnf_lookup_by_wwpn_ex(struct csio_hw *hw, uint8_t *wwpn, 
			csio_sm_state_t state);
struct csio_lnode_fcoe *
csio_lnf_lookup_by_wwnn(struct csio_hw *hw, uint8_t *wwnn);
struct csio_lnode_fcoe *
csio_lnf_lookup_by_vnpi(struct csio_hw *hw, uint32_t vnp_id);

csio_retval_t
csio_fcoe_get_lnode_info(struct csio_hw *hw, void *buffer, uint32_t buffer_len);
csio_retval_t
csio_fcoe_get_fcf_info(struct csio_hw *hw, void *buffer, uint32_t buffer_len);
csio_retval_t
csio_fcoe_ioctl_handler(struct csio_hw *hw, uint32_t opcode, void *buffer, 
		uint32_t buffer_len);
const char *csio_lnf_evt_name(csio_lnf_ev_t evt);

void
csio_read_fcoe_boot_hdr(struct csio_hw *hw, void *boot_hdr_buffer, 
				size_t buf_size);
void
csio_read_fcoe_bootdev_info(struct csio_hw *hw, void *boot_dev_buffer, 
				size_t buf_size);
csio_retval_t
csio_write_fcoe_bootdev_info(struct csio_hw *hw, void *boot_dev_info, 
							size_t buf_size);
csio_retval_t csio_erase_fcoe_boot_info(struct csio_hw *hw);

/* FCOE MGMT API */
csio_retval_t 
csio_lnf_mgmt_submit_req(struct csio_ioreq *io_req, 
		void (*io_cbfn) (struct csio_hw *, struct csio_ioreq *),
		enum fcoe_cmn_type req_type, struct csio_dma_buf *pld, 
		uint32_t pld_len);
csio_retval_t  
csio_lnf_mgmt_cancel_req(struct csio_ioreq *io_req, uint8_t abort_flag);

csio_retval_t 
csio_lnf_fdmi_start(struct csio_lnode_fcoe *lnf, void *context);

uint32_t
csio_fcoe_find_ct_type(struct csio_hw *hw, void *ct_cmd_buf, 
			uint32_t ct_cmd_len);
#endif /* ifndef __CSIO_LNODE_FCOE_H__ */
