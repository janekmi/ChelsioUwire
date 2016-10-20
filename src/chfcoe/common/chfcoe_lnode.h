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
 * 	The chfcoe_lnode.h header file contains local node related defines.
 *
 * Authors:
 * 	Deepti Vadde <deepti@chelsio.com>
 */

#ifndef __CHFCOE_LNODE_H__
#define __CHFCOE_LNODE_H__

#include "chfcoe_proto.h"
#include "chfcoe_defs.h"
#include "chfcoe_port.h"
#include "chfcoe_fcf.h"
#include <csio_sal_api.h>
#include "chfcoe_vn2vn.h"

#define CHFCOE_LNODE_FABRIC	1
#define CHFCOE_LNODE_VN2VN	2

static const char * const chfcoe_lnode_state_str[] = {
	"UNKNOWN",
	"UNINIT",
	"AWAIT LOGIN",
	"ONLINE",
	"READY",
	"OFFLINE",
	"NS REGISTER"
};

typedef enum {
	CHFCOE_LN_ST_UNINIT = 1,		/* Lnode UNINIT state */
	CHFCOE_LN_ST_AWAIT_LOGIN,		/* Await FLOGI state */
	CHFCOE_LN_ST_ONLINE,
	CHFCOE_LN_ST_READY,			/* Lnode READY state */
	CHFCOE_LN_ST_OFFLINE,			/* Lnode OFFLINE state */
	CHFCOE_LN_ST_NS
} chfcoe_ln_state_t;

typedef enum {
	CHFCOE_LN_EVT_NONE = 0,			/* None event */
	CHFCOE_LN_EVT_DISC_DONE,		/* Discovery Done event */
	CHFCOE_LN_EVT_LOGIN_DONE,		/* FLOGI Done event */
	CHFCOE_LN_EVT_NS_DONE,			/* Name server registeration 
						 * done event 
						 */
	CHFCOE_LN_EVT_FKA_EXPIRED,		/* FIP KeepAlive exp */
	CHFCOE_LN_EVT_LINK_DOWN, 		/* Link Down event */
	CHFCOE_LN_EVT_LINK_UP, 			/* Link Up event */
	CHFCOE_LN_EVT_RDEV, 			/* Remote node event */
	CHFCOE_LN_EVT_ELS, 			/* ELS frame recv event */
} chfcoe_ln_evt_t;

typedef struct chfcoe_lnode_stats {
	uint32_t		n_link_up;	/* Link down */
	uint32_t		n_link_down;	/* Link up */
	uint32_t		n_err;		/* error */
	uint32_t		n_err_nomem;	/* memory not available */
	uint32_t		n_inval_parm;	/* Invalid parameters */
	uint32_t		n_rnode_match;	/* matched rnode */
	uint32_t		n_dev_loss_tmo;	/* Device loss timeout */
	uint32_t		n_fdmi_err;	/* fdmi err */
	uint32_t		n_tx_bytes;	/* Tx Bytes */
	uint32_t		n_tx_frames;	/* Tx Frames */
	uint32_t		n_rx_bytes;	/* Rx Bytes */
	uint32_t		n_rx_frames;	/* Rx Frames */
	uint32_t		n_unsol_els_sent;
						/* Unsolicitated ELS sent */
	uint32_t		n_unsol_els_rcvd;
						/* Unsolicitated ELS recvd */
	uint32_t		n_unsol_cmd_sent;
						/* Unsolicitated CMD sent */
	uint32_t		n_unsol_cmd_rcvd;
						/* Unsolicitated CMD recvd */
	uint32_t		n_implicit_logo;
						/* Implicit LOGOUT */
	uint32_t		n_flogi_inv_sparm;
						/* Invalid service parms */
	uint32_t		n_fdisc_inv_sparm;
						/* Invalid service parms */
	uint32_t		n_flogi_rjt;	/* FLOGI REJECT */
	uint32_t		n_fdisc_rjt;	/* FDISC reject */
	uint32_t		n_inv_fr_rcvd;	/* Invalid Frame recvd */
} chfcoe_lnode_stats_t;

struct chfcoe_port_parms {
	uint32_t	nport_id;	/* nport id */
	uint8_t 	mac[6];		/* Enode mac addr */
	uint8_t 	vn_mac[6];	/* VN mac addr */
	uint8_t 	wwnn[8];	/* WWNN */
	uint8_t		wwpn[8];	/* WWPN */
	uint16_t	max_fcoe_sz; 	/* Max fcoe size */
	uint16_t	vlan_id;	/* vlan id */
};

typedef struct chfcoe_bufl {
	struct chfcoe_list 	buf_next; /* Next buffer */
	uint16_t 		pld_len;  /*  payload len */	
	void 			*pld;	  /* payload */
} chfcoe_bufl_t;

/* Defines for lnode flags */
#define CHFCOE_LN_DISC_PENDING	0x01		/* Discovery pending */
#define CHFCOE_LN_DISC_RESTART	0x02		/* Discovery restart */

typedef struct chfcoe_lnode {
	struct chfcoe_list      list;
	void			*fip_ctrl;	/* fip control  */
	void			*os_lnode;	/* Os dependent Lnode */
	struct chfcoe_adap_info *adap;		/* adapter info */
	struct chfcoe_port_info *pi;

	uint16_t		fcoe_mac_idx;	/* MPS id of FCoE MAC */
	uint8_t			state;		/* state */
	uint32_t		nport_id;	/* nport_id */
	enum fip_mode_type	fip_type;	/* fip type */
	uint8_t			mode;		/* Initiator or target
						 * or both
						 */
	/* FCOE/FC identifiers for this node */
	uint8_t			fcoe_mac[6];	/* FCOE Mac */
	uint8_t			fcf_mac[6];	/* FCF Mac */

	uint8_t			wwnn[8];	/* world wide node name */
	uint8_t			wwpn[8];	/* world wide port name */
	uint32_t		r_a_tov;
	uint32_t		e_d_tov;

	uint8_t			flags;		/* fpma, rec/p2p, etc */
	uint8_t			port_num;	/* Port num */
	uint16_t		vlan_id;	/* vlan id */
	uint32_t                dev_num;        /* Device number */

	struct csio_service_parms sp;	/* class service parameters */

	/* NPIV */
	struct chfcoe_list	cln_head;	/* Head of children lnode
						 * for NPIV
						 */
	struct chfcoe_lnode	*pln;	/* Parent lnode (NPIV) */
	uint32_t		num_vports;	/* Number of Vports */
	/* Rnode */
	struct chfcoe_list	rn_head;	/* rnode list head */
	struct chfcoe_list      rn_head_drain;  /* draining rnode list head */
	void		        *rn_lock;
	uint32_t		num_regd_rnodes;/* Number of registered
						 * rnodes
						 */
	uint32_t		num_scsi_tgts;	/* Scsi Tgts found */
	uint16_t                max_pldlen;
	chfcoe_lnode_stats_t	lnode_stats;		/* lnode stats */
	void		        *ln_mutex;
	struct chfcoe_list	ctbuf_head;	/* CT buffer head */
#ifdef __CSIO_TARGET__
        csio_tgt_handle_t       tgt_hdl;        /* tgt handle */
#endif /* __CSIO_TARGET__ */
	struct chfcoe_scsi_stats	stats;  /* scsi stats */

} chfcoe_lnode_t;

#define chfcoe_lnode_size	(sizeof(struct chfcoe_lnode) + os_rwlock_size + os_mutex_size	\
				+ (5 * os_atomic_size))

#define chfcoe_is_phys_lnode(lnode)					\
	(((lnode)->pln == NULL) ? 1 : 0)
#define chfcoe_is_npiv_lnode(lnode)					\
	(((lnode)->pln != NULL) ? 1 : 0)
#define chfcoe_is_fcf_lnode(lnode)					\
	(((lnode)->type == CHFCOE_LNODE_FABRIC) ? 1 : 0)
#define chfcoe_is_vn2vn_lnode(lnode)					\
	(((lnode)->type == CHFCOE_LNODE_VN2VN) ? 1 : 0)

#define chfcoe_lnode_to_fcf(ln)						\
	(struct chfcoe_fcf *)&ln->fip_ctrl
#define chfcoe_lnode_to_vn2vn(ln)					\
	(struct chfcoe_vn2vn *)&ln->fip_ctrl;
#define chfcoe_parent_lnode(ln)		((ln)->pln)
#define chfcoe_lnode_to_os(ln)		((ln)->os_ln)

#define chfcoe_ln_dbg(_ln, _fmt, ...)	\
	chfcoe_dbg(_ln, "%x:%x "_fmt, CSIO_DEVID_HI(_ln), \
		 CSIO_DEVID_LO(_ln), ##__VA_ARGS__);
	
#define chfcoe_ln_err(_ln, _fmt, ...)	\
	chfcoe_err(_ln, "%x:%x "_fmt, CSIO_DEVID_HI(_ln), \
		 CSIO_DEVID_LO(_ln), ##__VA_ARGS__);

#define chfcoe_ln_warn(_ln, _fmt, ...)	\
	chfcoe_warn(_ln, "%x:%x "_fmt, CSIO_DEVID_HI(_ln), \
		 CSIO_DEVID_LO(_ln), ##__VA_ARGS__);

/* FCoE IOCTL handler */
/* lnode event handler */
void chfcoe_lnode_fcf_sm(struct chfcoe_lnode *ln, chfcoe_ln_evt_t evt,
			void *evt_msg);
void chfcoe_lnode_evt_handler(struct chfcoe_lnode *ln, chfcoe_ln_evt_t evt,
			void *evt_msg);
int chfc_set_maxfs(struct chfcoe_lnode *);

struct chfcoe_lnode *
chfcoe_lnode_alloc(struct chfcoe_port_info *pi);
void
chfcoe_lnode_init(struct chfcoe_lnode *ln, void *ctrl_dev, 
		enum fip_mode_type fip_type, struct chfcoe_lnode *pln);
void chfcoe_lnode_exit(struct chfcoe_lnode *);
struct chfcoe_lnode *
chfcoe_lnode_create(void *ctrl_dev, enum fip_mode_type fip_type, 
		 struct chfcoe_port_info *pi);
void chfcoe_lnode_destroy(struct chfcoe_lnode *lnode);
struct chfcoe_lnode *chfcoe_get_lnode(struct chfcoe_port_info *pi, 
		chfcoe_fc_buffer_t *fcb);
typedef void (*fc4_handler_t)(struct chfcoe_lnode *, chfcoe_fc_buffer_t *);
void chfcoe_register_fc4(enum proto_fc_fh_type fc4_type, fc4_handler_t fc4_hndl);
void chfc_lnode_recv_req(struct chfcoe_lnode *, chfcoe_fc_buffer_t *);
struct chfcoe_rnode;
int chfc_elsct_build_tx(struct chfcoe_lnode *, struct chfcoe_rnode *,
		chfcoe_fc_buffer_t *, uint32_t,
		uint32_t, void (*)(chfcoe_fc_buffer_t *, void *), void *, 
		uint32_t);
int chfc_elsct_build(struct chfcoe_lnode *, 
		chfcoe_fc_buffer_t *, uint32_t,
		uint32_t, void (*)(chfcoe_fc_buffer_t *, void *), void *, 
		uint32_t);
void chfc_lnode_enter_sm(struct chfcoe_lnode *, int, bool);
int chfc_els_resp_send(struct chfcoe_lnode *, struct chfcoe_rnode *,
		chfcoe_fc_buffer_t *, chfcoe_fc_buffer_t *, bool);
int chfc_lnode_resp_send(struct chfcoe_lnode *, struct chfcoe_rnode *,
		chfcoe_fc_buffer_t *, uint32_t, uint8_t, uint8_t);
uint8_t chfcoe_is_lnode_ready(struct chfcoe_lnode *);

static inline struct chfcoe_lnode *chfcoe_get_lnode_cached(
		struct chfcoe_port_info *pi)
{
	return pi->root_ln;
}

static inline void __chfc_plogi_build(struct chfcoe_lnode *lnode,
		chfcoe_fc_buffer_t *fr)
{
	struct proto_fc_els_cmd *pl;
	struct csio_service_parms *sp;
	struct csio_cmn_sp *csp;
	struct csio_class_sp *cp;

	pl = proto_fc_frame_payload_get(fr, sizeof(*sp) + PROTO_ELS_DESC_SIZE);
	pl->op = PROTO_ELS_CMD_CODE_PLOGI;
	pl->byte1 = 0;
	pl->byte2 = 0;
	pl->byte3 = 0;
	sp = &pl->un.proto_ls_logi.sp;

	chfcoe_memcpy(sp, &lnode->sp, sizeof(lnode->sp));
	chfcoe_memcpy(sp->wwpn, lnode->wwpn, sizeof(lnode->wwpn));
	chfcoe_memcpy(sp->wwnn, lnode->wwnn, sizeof(lnode->wwnn));
	csp = &sp->csp;
	csp->rcv_sz = chfcoe_htons(lnode->max_pldlen);
	cp = &sp->clsp[3 - 1];
	cp->rcv_data_sz = chfcoe_htons(lnode->max_pldlen);
}

static inline void __chfc_flogi_build(struct chfcoe_lnode *lnode,
		chfcoe_fc_buffer_t *fr)
{
	struct proto_fc_els_cmd *pl;
	struct csio_service_parms *sp;

	pl = proto_fc_frame_payload_get(fr, sizeof(*sp) + PROTO_ELS_DESC_SIZE);
	pl->op = PROTO_ELS_CMD_CODE_FLOGI;
	pl->byte1 = 0;
	pl->byte2 = 0;
	pl->byte3 = 0;
	sp = &pl->un.proto_ls_logi.sp;

	chfcoe_memcpy(sp, &lnode->sp, sizeof(lnode->sp));
	chfcoe_memcpy(sp->wwpn, lnode->wwpn, sizeof(lnode->wwpn));
	chfcoe_memcpy(sp->wwnn, lnode->wwnn, sizeof(lnode->wwnn));
}

static inline void __chfc_adisc_build(struct chfcoe_lnode *lnode,
                chfcoe_fc_buffer_t *fr)
{
	struct proto_fc_els_cmd *pl;
	struct proto_adisc *resp;

	pl = proto_fc_frame_payload_get(fr, PAYLOAD_SZ(sizeof(*resp)));
	pl->op = PROTO_ELS_CMD_CODE_ADISC;
	pl->byte1 = 0;
	pl->byte2 = 0;
	pl->byte3 = 0;
	resp = &pl->un.proto_adisc;
	chfcoe_memcpy(resp->wwpn, lnode->wwpn, 8);
	chfcoe_memcpy(resp->wwnn, lnode->wwnn, 8);
	resp->nport_id = lnode->nport_id;
}

static inline void __chfc_scr_build(
		struct chfcoe_lnode *lnode __attribute__((unused)),
                chfcoe_fc_buffer_t *fr)
{
	struct proto_fc_els_cmd *pl;
	struct proto_scr *resp;

	pl = proto_fc_frame_payload_get(fr, PAYLOAD_SZ(sizeof(*resp)));
	pl->op = PROTO_ELS_CMD_CODE_SCR;
	pl->byte1 = 0;
	pl->byte2 = 0;
	pl->byte3 = 0;
	resp = &pl->un.proto_scr;
	resp->func = PROTO_SCRF_FULL;
}

static inline int chfc_els_build(struct chfcoe_lnode *lnode,
		chfcoe_fc_buffer_t *fr, uint8_t cmd)
{
	switch (cmd) {
	case PROTO_ELS_CMD_CODE_FLOGI:
		__chfc_flogi_build(lnode, fr);
		break;
	case PROTO_ELS_CMD_CODE_PLOGI:
		__chfc_plogi_build(lnode, fr);
		break;
	case PROTO_ELS_CMD_CODE_ADISC:
		__chfc_adisc_build(lnode, fr);
		break;
	case PROTO_ELS_CMD_CODE_SCR:
		__chfc_scr_build(lnode, fr);
		break;
	}

	return 0;
}

static inline struct fc_ct_cmd *fc_ct_preamble_build(
                chfcoe_fc_buffer_t *fr, int cmd, size_t req_size)
{
	struct fc_ct_cmd *pmbl;
	size_t iu_len;

	iu_len  = PROTO_CT_IU_PMBL_SIZE + req_size;
	pmbl = proto_fc_frame_payload_get(fr, iu_len);
	chfcoe_memset(pmbl, 0, iu_len);
	pmbl->rev = PROTO_CT_REVISION;
	pmbl->gs_type = PROTO_CT_GS_DIR_SERVICE;
	pmbl->gs_subtype = PROTO_CT_DIR_SERVICE_NS;
	pmbl->op = chfcoe_htons((uint16_t)cmd);
	return pmbl;
}

static inline int chfc_ct_build(struct chfcoe_lnode *lnode,
		chfcoe_fc_buffer_t *fr, uint16_t cmd)
{
	struct fc_ct_cmd *iu;
	struct rnn_id *rn;
	struct rft_id *rft;
	struct rff_id *rff;

	switch (cmd) {
	case PROTO_CT_NS_RNN_ID:
		iu = fc_ct_preamble_build(fr, cmd, sizeof(struct rnn_id));
		rn  = &iu->un.rnn_id;
		rn->port_id = chfcoe_htonl(lnode->nport_id);
		chfcoe_memcpy(rn->wwnn, lnode->wwnn, 8);
		break;

	case PROTO_CT_NS_RFT_ID:
		iu = fc_ct_preamble_build(fr, cmd, sizeof(struct rft_id));
		rft = &iu->un.rft_id;
		rft->port_id = chfcoe_htonl(lnode->nport_id);
		rft->fcp = 1;
		break;

	case PROTO_CT_NS_RFF_ID:
		iu = fc_ct_preamble_build(fr, cmd, sizeof(struct rff_id));
		rff = &iu->un.rff_id;
		rff->port_id = chfcoe_htonl(lnode->nport_id);
		rff->fc4_type = PROTO_FC_TYPE_FCP;
		rff->fc4_fbits = PROTO_FCP_FEAT_TARG;
		break;

	default:
		return -CHFCOE_INVAL;
	}

	return 0;
}

#endif /* __CHFCOE_LNODE_H__ */
