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
 * 	The chfcoe_rnode.h header file contains remote node related defines.
 *
 * Authors:
 * 	Deepti Vadde <deepti@chelsio.com>
 */

#ifndef __CHFCOE_RNODE_H__
#define __CHFCOE_RNODE_H__

#include "chfcoe_lnode.h"
#include "chfcoe_port.h"
#include "chfcoe_worker.h"

#ifdef __CSIO_TARGET__
#include "csio_sal_api.h"
#endif
/* Defines for rnode role */
#define	CHFCOE_RNFR_INITIATOR	0x1 
#define	CHFCOE_RNFR_TARGET	0x2
#define CHFCOE_RNFR_FABRIC	0x4
#define	CHFCOE_RNFR_NS		0x8
#define CHFCOE_RNFR_NPORT	0x10

#define CHFCOE_RNODE_ULP_READY	0

#define CHFCOE_RNODES		(2 * 1024)

static const char * const chfcoe_rnode_state_str[] = {
	"UNINIT",
	"AWAIT PLOGI",
	"PLOGI DONE",
	"PRLO DONE",
	"AWAIT PRLI",
	"RTV DONE",
	"READY",
	"OFFLINE",
	"AWAIT FLOGI",
	"AWAIT PLOGI",
	"RNN ID",
	"RSNN NN",
	"RSPN ID",
	"RFT ID",
	"RFF ID",
	"GPN ID",
	"GPN FT",
	"SCR"
};


typedef enum {
	CHFCOE_RN_ST_UNINIT,			/* Rnode Uninit state */
	CHFCOE_RN_ST_AWAIT_PLOGI_RESP,		/* Await PLOGI response */
	CHFCOE_RN_ST_PLOGI_DONE,		/* Rnode PLOGI done */
	CHFCOE_RN_ST_PRLO_DONE,
	CHFCOE_RN_ST_AWAIT_PRLI_RESP,		/* Await PRLI response */
	CHFCOE_RN_ST_RTV_DONE,
	CHFCOE_RN_ST_READY,			/* Rnode in READY state */
	CHFCOE_RN_ST_OFFLINE,			/* Rnode gone OFFLINE */
	CHFCOE_RN_ST_AWAIT_FLOGI,		/* In VN2VN, await FLOGI cmpl */
	CHFCOE_RN_ST_AWAIT_PLOGI,		/* In VN2VN, await PLOGI */
	CHFCOE_RN_ST_RNN_ID,
	CHFCOE_RN_ST_RSNN_NN,
	CHFCOE_RN_ST_RSPN_ID,
	CHFCOE_RN_ST_RFT_ID,
	CHFCOE_RN_ST_RFF_ID,
	CHFCOE_RN_ST_GPN_ID,
	CHFCOE_RN_ST_GPN_FT,
	CHFCOE_RN_ST_SCR
} chfcoe_rn_state_t;

typedef enum {
	CHFCOE_RN_EVT_FLOGI_RECVD,		/* FLOGI Recvd */
	CHFCOE_RN_EVT_FLOGI_ACC_RECVD,		/* FLOGI Accept Recvd */
	CHFCOE_RN_EVT_FLOGI_REJ_RECVD,		/* FLOGI Reject Recvd */
	CHFCOE_RN_EVT_PLOGI_SENT,		/* PLOGI sent */
	CHFCOE_RN_EVT_PLOGI_RECVD,		/* PLOGI Recvd */
	CHFCOE_RN_EVT_PLOGI_ACC_RECVD,		/* PLOGI Accept Recvd */
	CHFCOE_RN_EVT_PLOGI_ACC_SENT,		/* PLOGI Accept Sent */
	CHFCOE_RN_EVT_PLOGI_REJ_RECVD,		/* PLOGI Reject Recvd */
	CHFCOE_RN_EVT_PRLI_RECVD,		/* PRLI Recvd */
	CHFCOE_RN_EVT_PRLI_SENT,		/* PRLI sent */
	CHFCOE_RN_EVT_PRLO_RECVD,		/* PRLO Recvd */
	CHFCOE_RN_EVT_RTV_RECVD,		/* RTV Recvd */
	CHFCOE_RN_EVT_ADISC_RECVD,		/* ADISC Recvd */
	CHFCOE_RN_EVT_RRQ_RECVD,		/* RRQ Recvd */
	CHFCOE_RN_EVT_RSCN_RECVD,		/* RSCN Recvd */
	CHFCOE_RN_EVT_LOGO_RECVD,		/* LOGO Recvd */
	CHFCOE_RN_EVT_READY,			/* Rnode ready event */
	CHFCOE_RN_EVT_UP,			/* Link UP/Lnode online */
	CHFCOE_RN_EVT_DOWN,			/* Link Down/Lnode offline */
} chfcoe_rn_evt_t;

typedef struct chfcoe_rnode_stats {
	uint32_t		n_tx_bytes;	/* Tx Bytes */
	uint32_t		n_tx_frames;	/* Tx Frames */
	uint32_t		n_rx_bytes;	/* Rx Bytes */
	uint32_t		n_rx_frames;	/* Rx Frames */
	uint64_t		n_rx_unsol_cmd; /* Unsol cmds rcvd */

/* Error path stats */
	uint32_t		n_lun_rst;	/* Number of resets of
						 * of LUNs under this
						 * target
						 */
	uint32_t		n_lun_rst_fail;	/* Number of LUN reset
						 * failures.
						 */
	uint32_t		n_tgt_rst;	/* Number of target resets */
	uint32_t		n_tgt_rst_fail;	/* Number of target reset
						 * failures.
						 */
	uint32_t		n_ios_rcvd;	/* No of IOs recvd */
	uint32_t		n_ios_rspd;	/* No of IOs responded */
	uint16_t		n_ios_rcvd_rn_offl;
						/* No of IOs rcvd when
						 * Rnode is offline
						 */
	uint16_t		n_ios_rcvd_rn_not_rdy;
						/* No of IOs rcvd when
						 * Rnode is not ready
						 */
	uint8_t			n_fcp_data_fr_rcvd;
						/* No of FCP data
						 * Frames rcvd
						 */
	uint8_t			n_fcoe_ddp_err;	/* No. of DDP err */
	uint16_t		n_err_fcoe_rx_data_fr;
						/* No. of fcoe data
						 * Frames recvd
						 */
	uint8_t			n_abrt_req_in_bad_st;
						/* No of aborts recvd
						 * in offline st
						 */
	uint8_t			n_abrt_req_no_xchg;
						/* No of aborts due to
						 * no exchange
						 */
	uint8_t			n_2nd_abrt_sent;
						/* No of 2nd abts sent */
	uint8_t			n_2nd_abrt_timeout;
						/* No of 2nd abts timeout */
	uint32_t		n_abrt_recvd;
						/* No of aborts rcvd */
	/* ELS/CT stats */

	uint32_t		n_plogi_rcvd;	/* No of Plogi rcvd */
	uint32_t		n_prli_rcvd;	/* No of Prli rcvd */
	uint16_t		n_logo_rcvd;	/* No of Logo rcvd */
	uint16_t		n_prlo_rcvd;	/* No of Prlo rcvd */
	uint16_t		n_plogi_rjt;	/* no of plogi_rjt rcvd */
	uint16_t		n_prli_rjt;	/* No of prli rjt rcvd */
	uint32_t		n_adisc_rcvd;	/* No of adisc rcvd */
	uint32_t		n_rscn_rcvd;	/* No of rscn rcvd */
	uint32_t		n_rrq_rcvd;	/* No of rrq rcvd */
	uint32_t		n_rx_unsol_els_fr;
						/* No of unsol els rcvd */
	uint16_t		n_adisc_rjt;	/* No of adisc rcvd */
	uint8_t			n_scr_rjt;	/* no fo scr rjt rcvd */
	uint8_t			n_ct_rjt;	/* No of CT rcvd */
	uint8_t			n_inval_bls_rcvd;
						/* No of inval BLS rcvd */
	uint8_t			n_barjt_rcvd;	/* no of BA rjt rcvd */
} chfcoe_rnode_stats_t;

typedef struct chfcoe_rnode {
	struct chfcoe_list	rnlist;		/* Rnode list */
	void			*os_rnode;	/* OS Rnode */
	struct chfcoe_lnode	*lnode;		/* Parent Lnode */
	uint8_t			state;		/* state machine state */
	uint32_t		nport_id;	/* nport_id */
	uint8_t			type;		/* fabric or fcp */
	uint8_t			mode;		/* initiator or tgt */
	uint8_t			wwnn[8];	/* Node name */
	uint8_t			wwpn[8];	/* port name */
	uint8_t			vn_mac[6];	/* VN Mac address */
	uint8_t			mac[6];		/* Enode mac address */
	uint8_t			smac[6];	/* source Mac address */
	uint8_t			cmn_serv_params[16];
						/* Rnode's common service
						 * paramters */
	uint16_t		max_pldlen;	/* Max payload len */
	struct csio_service_parms sp;  		/* service parameters */
	uint32_t		r_a_tov;
	uint32_t		e_d_tov;	/* ED Time-Out Value */
	uint16_t                max_seq;	/* max concurrent sequence */
	uint16_t		fcp_flags;
	int			retries;
	void                    **xchg_tbl;     /* Exchange table */
	unsigned long fc_xchg_bm[CHFCOE_BITS_TO_LONGS(CHFCOE_MAX_XID)];
#ifdef __CSIO_TARGET__
	csio_ssn_handle_t       ssn_hdl;
#endif
	struct chfcoe_list	ini_active_q;	/* Initiator ioreq active q */
	struct chfcoe_list      ioreq_activeq;  /* Target ioreq active q */
	chfcoe_dwork_t   	*rnode_free_work;
	void		       	*lock;
	void	 		*submit_pending __attribute__((__aligned__(64)));
	uint8_t			node_index;		
	void			*refcnt __attribute__((__aligned__(64)));
	uint16_t		cur_event;	/* Current Rnode Event */
	uint16_t		prev_event;	/* Previous Rnode Event */
	unsigned long 		flags;
	chfcoe_rnode_stats_t	stats;		/* Rnode Statistics */
} chfcoe_rnode_t;

#define chfcoe_rnode_size	(sizeof(struct chfcoe_rnode) + os_spinlock_size \
				+ (os_atomic_size) + chfcoe_dwork_size)

void
chfcoe_rnode_init(struct chfcoe_rnode *, struct chfcoe_lnode *, 
		struct chfcoe_port_parms *);
void
chfcoe_rnode_exit(struct chfcoe_rnode *);
int chfcoe_rn_count(struct chfcoe_lnode *);
struct chfcoe_rnode *chfcoe_rn_lookup_portid(struct chfcoe_lnode *, uint32_t);
struct chfcoe_rnode *__chfcoe_rn_lookup_portid(struct chfcoe_lnode *, uint32_t);
struct chfcoe_rnode *chfcoe_get_rnode(struct chfcoe_lnode *, uint32_t, 
		struct chfcoe_port_parms *);
void chfc_rnode_recv_req(struct chfcoe_lnode *, chfcoe_fc_buffer_t *);
void chfc_rnode_do_plogi(struct chfcoe_lnode *, uint32_t);
void chfcoe_rnode_remove_destroy(struct chfcoe_rnode *rnode);
void chfcoe_rnode_destroy(struct chfcoe_rnode *);
void chfcoe_rnode_fcf_sm(struct chfcoe_rnode *rn, chfcoe_rn_evt_t evt, 
		void *evt_msg);
void chfcoe_rnode_vn2vn_sm(struct chfcoe_rnode *rn, chfcoe_rn_evt_t evt, 
		void *evt_msg);
void chfcoe_rnode_free(struct chfcoe_rnode *rnode);
struct chfcoe_rnode * 
chfcoe_confirm_rnode(struct chfcoe_lnode *ln, struct chfcoe_port_parms *rdevp);

static inline void chfcoe_set_dmac(struct chfcoe_lnode *lnode,
		struct chfcoe_rnode *rnode, uint8_t *dmac)
{
	if (lnode->fip_type == CHFCOE_FCF)
		chfcoe_memcpy(dmac, lnode->fcf_mac, ETH_ALEN);
	else {
		if (rnode)
			chfcoe_memcpy(dmac, rnode->vn_mac, ETH_ALEN);
		else {
			CHFCOE_ASSERT(0);
		}
	}
}
#endif /* __CHFCOE_RNODE_H__ */
