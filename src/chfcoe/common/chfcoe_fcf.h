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
 * 	This is chfcoe_fcf.h header file, contains FCF(Fabric) related defines.
 *
 * Authors:
 * 	Deepti Vadde <deepti@chelsio.com>
 */
#ifndef __CHFCOE_FCF_H__
#define __CHFCOE_FCF_H__

#include "chfcoe_adap.h"
#include "chfcoe_port.h"

#define CHFCOE_FCF_ST_UNINIT 0
#define CHFCOE_FCF_ST_ONLINE 1
#define CHFCOE_FCF_ST_OFFLINE 2

typedef struct chfcoe_fcf_stats {
	uint32_t		n_fip_tx_bytes;		/* FIP Tx bytes */
	uint32_t		n_fip_tx_fr;		/* FIP Tx Frames */
	uint64_t		n_fcf_ka_sent;		/* Keep Alives sent */
	uint64_t		n_fcf_mcast_adv_rcvd;	/* Multi-cast Adv */
	uint16_t		n_fcf_ucast_adv_rcvd;	/* Uni-cast Adv */
	uint16_t		n_sol_sent;		/* Solicitation sent */
	uint16_t		n_vlan_req;		/* VLAN request */
	uint16_t		n_vlan_rpl;		/* VLAN reply */
	uint16_t		n_clr_vlink;		/* Clear Virtual Link */
	uint16_t		n_logo;			/* Log Out */
	uint16_t		n_virt_ln_req;		/* Virtual login req */
	uint16_t		n_virt_ln_rpl;		/* Virtual login rep */
	uint16_t		n_flogi_req;		/* FLOGI request sent */
	uint16_t		n_flogi_rpl;		/* FLOGI reply recvd */
	uint16_t		n_fdisc_req;		/* FDISC request sent */
	uint16_t		n_fdisc_rpl;		/* FDISC reply recvd */
	uint16_t		n_adv_prd_chg;		/* Adv Period Change */
	uint16_t		n_fc_map_chg;		/* FC MAP Change */
	uint16_t		n_vf_id_chg;		/* VF ID Change */
	uint8_t			n_fka_not_req;		/* FIP Keep Alive */
	uint8_t			n_out_of_vnp;		/* Out of VNP */
	uint8_t			n_sol_rcvd;		/* Solicitation recvd */
	uint8_t			n_flogi_inv_srv_parms;	/* Invalid parms */
	uint8_t			n_fdisc_inv_srv_parms;	/* Invalid parms */
} chfcoe_fcf_stats_t;

typedef struct chfcoe_fcf {
	struct chfcoe_list	sibling_fcf;	/* Sibling fcf list */
	struct chfcoe_lnode 	*lnode;		/* Pointer to lnode */
	struct chfcoe_port_info	*pi;		/* Pointer to parent
						 * port_info structure
						 */
	uint16_t		max_fcoe_size;	/* Max FCOE size */
	uint8_t			flags;		/* FCF flags */
	uint8_t			fcf_prio;	/* FCF priority */
	uint32_t		fka_adv_prd;	/* FCF KeepAlive
						 * Timeout Value
						 */
	uint8_t			mcast_fip_adv_rcvd; /* set to 1,
						     * when mcast adv
						     * is recvd
						     */
	uint16_t		vf_id;		/* Virtual Fabric Tag */
	uint16_t		vlan_id;	/* VLAN ID */
	uint8_t			fcf_mac[6];	/* FCF MAC address */
	uint8_t			phy_mac[6];	/* FCF Physical Mac */
	uint8_t			fab_wwn[8];	/* Fabric WWN */
	uint8_t			port_num;	/* port num */
	uint8_t			fc_map[3];	/* FC MAP value */
	uint8_t			state;		/* FCF state */
	chfcoe_dwork_t   	*fcf_ka_timer_work;      /* FCF KA timer */

	chfcoe_fcf_stats_t	stats;	/* FCF stats */
} chfcoe_fcf_t;

#define chfcoe_fcf_size		(sizeof(struct chfcoe_fcf) + chfcoe_dwork_size)

#define chfcoe_fcf_to_pi(fcf)		((fcf)->pi)
#define chfcoe_fcf_to_ln(fcf)		((fcf)->lnode)

struct chfcoe_fcf *
chfcoe_alloc_fcf(struct chfcoe_port_info *pi);
chfcoe_retval_t
chfcoe_init_fcf(struct chfcoe_fcf *fcf, void *desc_pld, uint32_t desc_len);
void
chfcoe_free_fcf(struct chfcoe_fcf *fcf);
void
chfcoe_stop_fcf(struct chfcoe_fcf *fcf);
struct chfcoe_fcf *
chfcoe_get_fcf(struct chfcoe_port_info *pi, uint8_t *wwn, uint16_t vlan_id);
struct chfcoe_fcf *
chfcoe_detach_fcf(struct chfcoe_port_info *pi, uint8_t *wwn, uint16_t vlan_id);
#endif /* __CHFCOE_FCF_H__ */
