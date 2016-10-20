/*
 *  Copyright (C) 2008-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: This is the FCoE ioctl header file.
 *
 */
#ifndef __CSIO_FCOE_IOCTL_H__
#define __CSIO_FCOE_IOCTL_H__

/*
 * Pack all the structures to 1-byte alignment.
 *
 */

#pragma pack (1)

/* TODO: This should be simply be some max value, and not be based
 * on RSCN_DEV_LOST. We shoudlnt be including the FW header files
 * for the app.
 */
#define RSCN_DEV_LOST			0x16

typedef enum _fc_id {
	NPORT_ID = 0,
	WWPN,
	WWNN,
	FW_HANDLE
}FC_ID, *PFC_ID, fc_id_t;

typedef enum _CSIO_NPIV_STATUS {
	CSIO_NPIV_SUCCESS = (int)0,
	CSIO_NPIV_UNKNOWN_ERROR = -1,
	CSIO_NPIV_NOT_SUPPORTED_HOST = -2,
	CSIO_NPIV_NOT_SUPPORTED_FABRIC = -3,
	CSIO_NPIV_OUT_OF_RESOURCES = -4,
	CSIO_NPIV_MAX_VPORT_COUNT = -5,
	CSIO_NPIV_WWPN_IN_USE = -6,
	CSIO_NPIV_WWPN_INVALID_FORMAT = -7,
	CSIO_NPIV_LINK_DOWN = -8,
	CSIO_NPIV_WWPN_NOT_FOUND = -9,
}CSIO_NPIV_STATUS, *PCSIO_NPIV_STATUS, csio_npiv_status_t;

typedef struct _npiv_params {

	uint8_t npiv_wwpn[8];
	uint8_t npiv_wwnn[8];

	uint8_t parent_wwpn[8];
	uint8_t parent_wwnn[8];

	csio_npiv_status_t npiv_status;

}NPIV_PARAMS, *PNPIV_PARAMS, npiv_params_t;

typedef struct _npiv_port_info {

	uint8_t 	npiv_wwpn[8];
	uint8_t 	npiv_wwnn[8];

	uint8_t		mac[6];
	uint32_t	nport_id;

}NPIV_PORT_INFO, *PNPIV_PORT_INFO, npiv_port_info_t;


typedef struct _npiv_port_list {

	uint32_t count;

	uint8_t parent_wwpn[8];
	uint8_t parent_wwnn[8];

	npiv_port_info_t npiv_list[0]; /* Make sure this field is always
					* the last member. If not it will
					* not compile for Windows */

}NPIV_PORT_LIST, *PNPIV_PORT_LIST, npiv_port_list_t;

#ifndef CSIO_FCOE_MAX_NPIV
#define CSIO_FCOE_MAX_NPIV		128
#endif

#define NPIV_PORT_LIST_HDR_SIZE		(sizeof(npiv_port_list_t))

typedef struct _fcoe_stats {

	uint64_t tx_frames;
	uint64_t rx_frames;

}FCOE_STATS, *PFCOE_STATS, fcoe_stats_t;

typedef struct _vn_port_info {

	uint8_t nport_id[3];

	uint8_t wwpn[8];
	uint8_t wwnn[8];

	uint8_t vn_port_mac[6];
	uint8_t enode_mac[6];

	uint8_t is_fpma;

	uint8_t is_npiv_port;

}VN_PORT_INFO, *PVN_PORT_INFO, vn_port_info_t;

//new

/* Defines for flags */
#ifndef CSIO_LNFFLAG_FIPSUPP
#define	CSIO_LNFFLAG_FIPSUPP		0x00000001	/* Fip Supported */
#endif

#ifndef CSIO_LNFFLAG_NPIVSUPP
#define	CSIO_LNFFLAG_NPIVSUPP		0x00000002	/* NPIV supported */
#endif

#ifndef CSIO_LNFFLAG_CLEAN_ADDR
#define CSIO_LNFFLAG_CLEAN_ADDR		0x00000004	/* Clean Address set */
#endif

/* FCoE Lnode stats */
typedef struct _csio_lnode_fcoestats {
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
	uint32_t  	n_evt_fw[RSCN_DEV_LOST + 1]; 	/* fw events */
	uint32_t   	n_evt_sm[14]; 	/* State m/c events */
	uint32_t	rsvd1;
}CSIO_LNODE_FCOESTATS, *PCSIO_LNODE_FCOESTATS, csio_lnode_fcoestats_t;

/* FCoE Lnode params */
typedef struct _csio_lnode_fcoeparams {
	uint32_t	ra_tov;
	uint32_t	rsvd1;
}CSIO_LNODE_FCOEPARAMS, *PCSIO_LNODE_FCOEPARAMS, csio_lnode_fcoeparams_t;

/* FCoE rnode stats */
typedef struct _csio_rnode_fcoestats {
	uint32_t	n_err;		/* error */
	uint32_t	n_err_inval;	/* invalid parameter */
	uint32_t	n_err_nomem;	/* error nomem */
	uint32_t	n_evt_unexp;	/* unexpected event */
	uint32_t	n_evt_drop;	/* unexpected event */
	uint32_t  	n_evt_fw[RSCN_DEV_LOST + 1]; 	/* fw events */
	uint32_t   	n_evt_sm[16]; 	/* State m/c events */

}CSIO_RNODE_FCOESTATS, *PCSIO_RNODE_FCOESTATS, csio_rnode_fcoestats_t;

/* FcoE  rnode params */
typedef struct _csio_rnode_fcoeparams {
	uint32_t	param1;
	uint32_t	param2;
}CSIO_RNODE_FCOEPARAMS, *PCSIO_RNODE_FCOEPARAMS, csio_rnode_fcoeparams_t;

typedef struct _csio_port_info_t {
	uint8_t			  portid;
	struct fw_fcoe_port_stats port_stats;

} CSIO_PORT_INFO, *PCSIO_PORT_INFO, csio_port_info_t;
typedef struct _csio_fcf_info_t {

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
	struct fw_fcoe_fcf_stats fcf_stats;
	uint8_t			reserved[32];

}CSIO_FCF_INFO, *PCSIO_FCF_INFO, csio_fcf_info_t;

typedef struct _csio_fcoe_lnode_t {

	uint8_t			portid;		/* Port ID */
	uint32_t		num_reg_rnodes;	/* Number of rnodes registered
						 * with the host.
						 */
	uint32_t		dev_num;	/* Device number */
	uint64_t		opq_handle;	/* Opaque handle given
						 * by driver. */

	/* FCoE identifiers for this Lnode */
	uint8_t			mac[6];
	uint32_t		nport_id;
	uint8_t			is_vport;		/* Is VPort?*/
	uint32_t		num_vports;		/* Total VPorts.*/

	struct csio_service_parms ln_sparm; 		/* Service parms */
	int			fcf_flowid;		/* fcf flowid */
	uint32_t		flags;	 		/* Flags */

	/* Firmware identifiers */
	uint32_t		vnp_flowid;
	uint16_t		ssn_cnt;		/* Registered Session */

	uint8_t			sess_ofld;
	uint8_t			cur_evt;		/* Current event */
	uint8_t			prev_evt;		/* Previous event */
	uint8_t			max_lnf_events;
	char			lnf_evt_name[16][32];
	char			fw_evt_name[RSCN_DEV_LOST + 1][32];

	csio_lnode_fcoestats_t	stats;
	char			state[32];

	struct fw_fcoe_pcb_stats vnp_stats;  
	uint8_t			reserved[32];

}CSIO_FCOE_LNODE, *PCSIO_FCOE_LNODE, csio_fcoe_lnode_t;

typedef struct _csio_rnode_stats_t {

	uint32_t        n_lun_rst;      /* Number of resets of LUNs under this
					 * target
					 */
	uint32_t        n_lun_rst_fail; /* Number of LUN reset failures. */
	uint32_t        n_tgt_rst;      /* Number of target resets */
	uint32_t        n_tgt_rst_fail; /* Number of target reset failures. */

}CSIO_RNODE_STATS, *PCSIO_RNODE_STATS, csio_rnode_stats_t;

typedef struct _csio_fcoe_rnode_t {

	uint32_t		ssn_flowid;	/* Firmware ID */
	uint32_t		vnp_flowid;	/* Its LNode's VNP Flow-id */

	/* FC identifiers for remote node */
	uint32_t		nport_id;
	uint16_t		fcp_flags;		/* FCP Flags */
	char			role[32];		/* Fabric/Target/
							 * Initiator/NS
							 */

	struct csio_service_parms     rn_sparm;

	uint8_t			cur_evt;		/* Current event */
	uint8_t			prev_evt;		/* Previous event */
	uint8_t			max_rnf_events;
	char			rnf_evt_name[16][32];
	char			fw_evt_name[RSCN_DEV_LOST + 1][32];

	csio_rnode_stats_t	rnode_stats;
	csio_rnode_fcoestats_t	rnf_stats;
	char			state[32];

	struct fw_fcoe_scb_stats ssn_stats;
	uint8_t			reserved[32];

}CSIO_FCOE_RNODE, *PCSIO_FCOE_RNODE, csio_fcoe_rnode_t;

/* ELS/CT module stats */
typedef struct _csio_elsctm_stats_t {

	uint32_t	els_xmit_flogi;		/* Total Flogi transmitted */
	uint32_t	els_xmit_fdisc;		/* Total fdisc transmitted */
	uint32_t	els_xmit_plogi;		/* Total plogi transmitted */
	uint32_t	els_xmit_prli;		/* Total prli transmitted */
	uint32_t	els_xmit_scr;		/* Total scr transmitted */
	uint32_t	els_xmit_rnid;		/* Total rnid transmitted */
	uint32_t	els_xmit_logo;		/* Total logo transmitted */
	uint32_t	els_xmit_lsacc;		/* Total ls_acc transmitted */
	uint32_t	els_xmit_lsrjt;		/* Total ls_rjt transmitted */
	uint32_t	els_xmit_adisc;		/* Total adisc transmitted */
	uint32_t	els_xmit_req;	    	/* Total els req transmitted */

	uint32_t	els_rcv_lsacc;		/* Total ls_acc received */
	uint32_t	els_rcv_lsrjt;		/* Total ls_rjt received */
	uint32_t	els_rcv_rscn;		/* Total rscn received */
	uint32_t	els_rcv_rsp;		/* Total els resp received */
	uint32_t	els_rcv_unsol;		/* Total unsol els received */

	uint32_t	ct_xmit_gpnft;		/* Total GPN_FT transmitted */
	uint32_t	ct_xmit_acc;		/* Total CT ACC transmitted */
	uint32_t	ct_xmit_req;	       /* Total CT req transmitted */
	uint32_t	ct_rcv_acc;		/* Total CT ACC received */
	uint32_t	ct_rcv_rjt;		/* Total CT RJT received */
	uint32_t	ct_rcv_rsp;		/* Total CT rsp received */

	uint32_t	abort_req;		/* Total abort request */
	uint32_t	abort_rsp;		/* Total abort response */
	uint32_t	close_req;		/* Total close request */
	uint32_t	close_rsp;		/* Total close response */
	uint32_t	retries;		/* Total retries */
	uint32_t	n_err;			/* Total Errors */
	uint32_t	n_drop;			/* Total request dropped */
	uint32_t	n_res_wait;   		/* Count of res_wait_q */
	uint32_t	n_active;     		/* Count of active_q */
	uint32_t	n_retry;     		/* Count of retry_q */
	uint32_t	n_cbfn;     		/* Count of cbfn_q */
	uint32_t 	n_free_elsct_req;	/* Number of freelist entries */

}CSIO_ELSCTM_STATS, *PCSIO_ELSCTM_STATS, csio_elsctm_stats_t;

typedef struct _csio_tp_fcoe_stats {
	uint32_t framesDDP;
	uint32_t framesDrop;
	uint64_t octetsDDP;
}CSIO_TP_FCOE_STATS, *PCSIO_TP_FCOE_STATS, csio_tp_fcoe_stats_t;

typedef struct _csio_lu_map_info {
	uint8_t lnode_wwpn[8];
	uint8_t rnode_wwpn[8];
	uint64_t fc_luid[256];
}CSIO_LU_MAP_INFO, *PCSIO_LU_MAP_INFO, csio_lu_map_info_t;


enum fcoe_pt_cmd_type {
	FCOE_ELS_CMD,
	FCOE_CT_CMD,
	FCOE_SCSI_PT_CMD,
	FCOE_UNSOL_ELS_CMD,
};

typedef struct _csio_els_ct_passthru {
	uint8_t cmd_type; /* fcoe_pt_cmd_type */
	int8_t tmo_val; /* in seconds */
	uint8_t	lnode_wwpn[8];

	uint8_t rnode_wwpn[8];
	uint32_t rnode_nport_id; /*Either RNode's WWPN or NPort-id is needed.*/

	uint32_t cmd_payload_size; /* Should be multiples of 4*/

	uint32_t cmd_resp_buf_size;
	uint32_t cmd_resp_buf_offset;

	/* Based on the following 2 values the app can determine, whether to
	 * retry the command with higher resp buffer size!*/
	uint32_t actual_resp_size;
	uint32_t resp_copied_size;

	uint8_t buffer[0];
}CSIO_ELS_CT_PASSTHRU, *PCSIO_ELS_CT_PASSTHRU, csio_els_ct_passthru_t;


#pragma pack () /* Reset the pack to default value. */
#endif /* __CSIO_FCOE_IOCTL_H__ */
