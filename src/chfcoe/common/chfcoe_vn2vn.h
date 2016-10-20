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
 * 	This chfcoe_vn2vn.h file contains VN2VN mode defines
 *
 * Authors:
 * 	Praveen M <praveenm@chelsio.com>
 */

#ifndef __CHFCOE_VN2VN_H__
#define __CHFCOE_VN2VN_H__
struct chfcoe_vn2vn_stats {
	uint32_t	tx_bytes;
	uint32_t	tx_frames;
	uint32_t	rx_bytes;
	uint32_t	rx_frames;
	uint32_t	beacons_sent;
	uint32_t	probes_sent;
	uint32_t	probe_reply_sent;
	uint32_t	claims_sent;
	uint32_t	probes_recvd;
	uint32_t	claims_rcvd;
	uint32_t	probe_replies_recvd;
	uint32_t	claim_resp_recvd;
	uint32_t	beacons_recvd;
	uint32_t	ignore_evt;
	uint32_t	vlan_req_sent;
	uint32_t	vlan_reply_recvd;
	uint32_t	vlan_req_recvd;
	uint32_t	vlan_rep_sent;
};


enum chfcoe_vn2vn_state {
	CHFCOE_VN2VN_UINIT_STATE,
	CHFCOE_VN2VN_PROBE_STATE,
	CHFCOE_VN2VN_CLAIM_STATE,
	CHFCOE_VN2VN_READY_STATE,
	CHFCOE_VN2VN_OFFLINE_STATE,
};

enum vn2vn_evt {
	CHFCOE_VN2VN_START_EVT,
	CHFCOE_VN2VN_STOP_EVT,
	CHFCOE_VN2VN_PROBE_TMO_EVT,
	CHFCOE_VN2VN_BEACON_TMO_EVT,
	CHFCOE_VN2VN_PROBE_REQ_EVT,
	CHFCOE_VN2VN_PROBE_REP_EVT,
	CHFCOE_VN2VN_CLAIM_NOTIFY_EVT,
	CHFCOE_VN2VN_CLAIM_RESP_EVT,
	CHFCOE_VN2VN_BEACON_RCV_EVT,
};

#define CHFCOE_MAX_PROBE_TMO	4
#define LUID_MASK		0xFFFE
#define CHFCOE_MAX_NEIGHBHOR	32

struct chfcoe_vn2vn_parms {
	uint32_t	luid;		/* LUID */
	uint16_t	fip_flags;	/* fip flags */
	uint8_t 	mac[6];		/* Enode mac addr */
	uint8_t 	vn_mac[6];	/* VN mac addr */
	uint8_t 	wwnn[8];	/* WWNN */
	uint8_t		wwpn[8];	/* WWPN */
	uint16_t	max_fcoe_sz; 	/* Max fcoe size */
};

struct chfcoe_vn2vn {
	struct chfcoe_list list;	/* VN2VN list */
	uint32_t	luid;		/* LUID */
	uint16_t	vlan_id;	/* VLAN ID */
	int 		prio;		/* Priority */
	struct chfcoe_port_info *pi;  	/* port info */
	struct chfcoe_lnode    *ln;	/* lnode structure */
	enum chfcoe_vn2vn_state	state;	/* VN2VN lnode state */
	uint8_t		event;		/* vn2vn event */
	uint8_t 	wwnn[8];	/* WWNN of the local node */
	uint8_t		wwpn[8];	/* WWPN of the local node */
	uint8_t		vn_mac[6];	/* VN mac of the local node */
	uint8_t		mac[6];		/* Enode mac of the local node */

	uint8_t		p2p_claim;	/* P2P claim response */
	uint8_t		probe_tmo;
	uint64_t	stop_tmo;	/* stop timeout */
	uint16_t	max_fcoe_sz; 	/* Max fcoe size */
	chfcoe_dwork_t	*probe_timer;	/* Probing timer */
	chfcoe_dwork_t	*beacon_timer;	/* Beacon timer */
	struct chfcoe_vn2vn_stats  stats;	/* vn2vn stats */
};

#define chfcoe_vn2vn_size	(sizeof(struct chfcoe_vn2vn) + (2 * chfcoe_dwork_size))

chfcoe_retval_t chfcoe_vn2vn_init(struct chfcoe_port_info *);
chfcoe_retval_t chfcoe_vn2vn_exit(struct chfcoe_port_info *);
void  chfcoe_recv_vn2vn_fip(struct chfcoe_adap_info *, uint16_t,
                    uint8_t, chfcoe_fc_buffer_t *, uint32_t);
struct chfcoe_vn2vn *
chfcoe_get_vn2vn(struct chfcoe_port_info *pi, uint8_t *mac, uint16_t vlan_id);
struct chfcoe_vn2vn *
chfcoe_get_vn2vn_vnmac(struct chfcoe_port_info *pi, uint8_t *mac, 
		uint16_t vlan_id);
chfcoe_retval_t chfcoe_start_vn2vn(struct chfcoe_port_info *);
chfcoe_retval_t chfcoe_stop_vn2vn(struct chfcoe_port_info *);
#endif /* __CHFCOE_VN2VN_H__ */

