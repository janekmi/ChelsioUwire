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
 * 	The chfcoe_proto.h header file contains FCOE/FC protocol related defines.
 *
 * Authors:
 * 	Deepti Vadde <deepti@chelsio.com>
 */

#ifndef __CHFCOE_FCOE_PROTO_H__
#define __CHFCOE_FCOE_PROTO_H__


#include "chfcoe_defs.h"

/* FC buffer */
#define chfcoe_fc_hdr(fp)      		((fc_header_t *)(chfcoe_skb_data((void *)fp)))
#define chfcoe_fc_len(fp)      		chfcoe_skb_len((void *)fp)
#define chfcoe_fc_dtr(fp, dtr)          chfcoe_skb_dtr((void *)(fp), (void *)(dtr))

/*
 * Frame Headers
 */

/* 
 * Extended Header
 */
struct proto_fc_fr_hdr_ext {
	uint32_t	r_ctl	: 8;		/* Routing Control */
	uint32_t	ver	: 2;		/* Version */
	uint32_t	type	: 4;		/* Type of tagged frame */
	uint32_t	ersvd1	: 1;		/* Reserved */
	uint32_t	esp_hdr	: 1;		/* link by link ESP_Hdr processing */
	uint32_t	pri	: 3;		/* Priority...QoS */
	uint32_t	vf_id	: 12;		/* Virtual Fabric ID */
	uint32_t	ersvd2	: 1;		/* Reserved */
	uint32_t	hop_ct	: 8;		/* Hop Count */
	uint32_t	ersvd3	: 24;		/* Reserved */
}; /* struct proto_fc_fr_hdr_ext */

/*
 * Basic Header
 */
struct proto_fc_fr_hdr {
	uint8_t		r_ctl;		/* Routing Control */
	uint8_t		d_id[3];	/* Remote Port's Node Port ID */
	uint8_t		cs_ctl_pri;	/* Class Control or Priority */
	uint8_t		s_id[3];	/* Local Port's Node Port ID */
	uint8_t		type;		/* Protocol Service Type */
	uint8_t		f_ctl[3];	/* Frame Control */
	uint8_t		seq_id;		/* Sequence Identifier */
	uint8_t		df_ctl;		/* Data Field Control */
	uint16_t	seq_cnt;	/* Sequence Count */
	uint16_t	ox_id;		/* Exchange Originator ID */
	uint16_t	rx_id;		/* Exchange Receiver ID */
	uint32_t	params;		/* Parameters */
} __attribute__((packed)); /* struct proto_fc_fr_hdr */

typedef struct proto_fc_fr_hdr fc_header_t;
/* 
 * Frame Header with both Extended and Basic Headers
 */
struct proto_fc_fh_w_ext {
	struct 	proto_fc_fr_hdr_ext	ext;
	struct 	proto_fc_fr_hdr	hdr;
}; /* proto_fc_fh_w_ext */

struct proto_fc_fh_wo_ext {
	struct 	proto_fc_fr_hdr	hdr;
}; /* fc_fh_wo_ext */


#define PROTO_FC_FR_BASIC_HDR_LEN 	24 /* basic fr hdr len in bytes */
#define PROTO_FC_FR_VFT_HDR_LEN 	8  /* VFT hdr len in bytes */

#define PROTO_FC_MAX_RECV_PAYLOAD  	2048 /* max payload length in bytes */
#define PROTO_FC_MAX_PAYLOAD  		2112 /* max payload length in bytes */
#define PROTO_FC_MIN_MAX_PAYLOAD  	256  /* lower limit on max payload */

#define PROTO_FC_MAX_FRAME						\
	(PROTO_FC_MAX_PAYLOAD +	PROTO_FC_FR_BASIC_HDR_LEN)
/* Not Supported
 * 	+ PROTO_FC_FR_VFT_HDR_LEN) */
#define PROTO_FC_MIN_MAX_FRAME 						\
	(PROTO_FC_MIN_MAX_PAYLOAD + PROTO_FC_FR_BASIC_HDR_LEN)

/*
 * FIP - FCoE Initialization Protocol
 */
#ifndef ETH_P_PROTO_FIP
#define ETH_P_PROTO_FIP	0x8914  /* FIP Ethertype */
#endif

#define PROTO_FIP_DEF_PRI	128	/* default selection priority */
#define PROTO_FIP_DEF_FC_MAP	0x0efc00 /* default FCoE MAP (MAC OUI) value */
#define PROTO_FIP_VN2VN_FC_MAP	0x0efd00 /* default FCoE MAP (MAC OUI) value */
#define PROTO_FIP_ADV_TOV	2	/* default FCF sol disc adv period (Secs) */
#define PROTO_FIP_DEF_FKA	8000	/* default FCF ka period (mS) */
#define PROTO_FIP_VN_KA_PERIOD 90	/* required VN_port ka period (Secs) */
#define PROTO_FIP_FCF_FUZZ	100	/* random time added by FCF (mS) */


#define PROTO_FIP_BEACON_PERIOD	(8 * os_hz)/* default beacon period (mS) */
#define PROTO_FIP_PROBE_WAIT	os_hz/10	/* default probe wait period */
#define PROTO_FIP_ANNONCE_WAIT	(4 * os_hz/10) /* default annonce wait period */
/*
 * Multicast MAC addresses.  T11-adopted.
 */
#define PROTO_FIP_ALL_FCOE_MACS		{ 1, 0x10, 0x18, 1, 0, 0 }
#define PROTO_FIP_ALL_ENODE_MACS	{ 1, 0x10, 0x18, 1, 0, 1 }
#define PROTO_FIP_ALL_FCF_MACS		{ 1, 0x10, 0x18, 1, 0, 2 }
#define PROTO_FIP_ALL_VN2VN_MACS	{ 1, 0x10, 0x18, 1, 0, 4 }
#define PROTO_FIP_ALL_P2P_MACS		{ 1, 0x10, 0x18, 1, 0, 5 }	

#define PROTO_FIP_VER		1		/* version for fip_header */
#define PROTO_FIP_VER_SHIFT	4
#define PROTO_FIP_VER_ENCAPS(v) ((v) << PROTO_FIP_VER_SHIFT)
#define PROTO_FIP_VER_DECAPS(v) ((v) >> PROTO_FIP_VER_SHIFT)
#define PROTO_FIP_BPW		4		/* bytes per word for lengths */

struct proto_fip_header {
	uint8_t		fip_ver;	/* upper 4 bits are the version */
	uint8_t		fip_resv1;	/* reserved */
	uint16_t	fip_op;		/* operation code */
	uint8_t		fip_resv2;	/* reserved */
	uint8_t		fip_subcode;	/* lower 4 bits are sub-code */
	uint16_t	fip_dl_len;	/* length of descriptors in words */
	uint16_t	fip_flags;	/* header flags */
}__attribute__ ((packed));

/*
 * fip_op.
 */
enum proto_fip_opcode {
	PROTO_FIP_OP_DISC =	1,	/* discovery, advertisement, etc. */
	PROTO_FIP_OP_LS =	2,	/* Link Service request or reply */
	PROTO_FIP_OP_CTRL =	3,	/* Keep Alive / Link Reset */
	PROTO_FIP_OP_VLAN =	4,	/* VLAN discovery */
	PROTO_FIP_OP_VN2VN =	5,	/* VN2VN */
	PROTO_FIP_OP_VENDOR_MIN = 0xfff8,
					/* min vendor-specific opcode */
	PROTO_FIP_OP_VENDOR_MAX = 0xfffe,
					/* max vendor-specific opcode */
};

/*
 * Subcodes for FIP_OP_DISC.
 */
enum proto_fip_disc_subcode {
	PROTO_FIP_SC_SOL =	1,	/* solicitation */
	PROTO_FIP_SC_ADV =	2,	/* advertisement */
};

/*
 * Subcodes for FIP_OP_LS.
 */
enum proto_fip_trans_subcode {
	PROTO_FIP_SC_REQ =	1,	/* request */
	PROTO_FIP_SC_REP =	2,	/* reply */
};

/*
 * Subcodes for FIP_OP_RESET.
 */
enum proto_fip_reset_subcode {
	PROTO_FIP_SC_KEEP_ALIVE = 1,	/* keep-alive from VN_Port */
	PROTO_FIP_SC_CLR_VLINK = 2,	/* clear virtual link from VF_Port */
};

/*
 * Subcodes for FIP_OP_VLAN.
 */
enum proto_fip_vlan_subcode {
	PROTO_FIP_SC_VL_REQ =	1,	/* request */
	PROTO_FIP_SC_VL_REP =	2,	/* reply */
};
/*
 * Subcodes for FIP_OP_VN2VN.
 */
enum proto_fip_vn2vn_subcode {
	PROTO_FIP_SC_VN_PROBE_REQ = 1,  /* probe request */
	PROTO_FIP_SC_VN_PROBE_REP = 2,  /* probe reply */
	PROTO_FIP_SC_VN_CLAIM_NOTIFY = 3,
				     	/* claim notification */
	PROTO_FIP_SC_VN_CLAIM_REP = 4,
				        /* claim response */
	PROTO_FIP_SC_VN_BEACON = 5,     /* beacon */
};

/*
 * flags in header fip_flags.
 */
enum proto_fip_flag {
	PROTO_FIP_FL_FPMA =	0x8000, /* supports FPMA fabric-provided MACs */
	PROTO_FIP_FL_SPMA =	0x4000,	/* supports SPMA server-provided MACs */
	PROTO_FIP_FL_REC_OR_P2P = 0x0008,
					/* configured addr or point-to-point */
	PROTO_FIP_FL_AVAIL =	0x0004, /* available for FLOGI/ELP */
	PROTO_FIP_FL_SOL =	0x0002,	/* this is a solicited message */
	PROTO_FIP_FL_FPORT =	0x0001,	/* sent from an F port */
};

/*
 * Common descriptor header format.
 */
struct proto_fip_desc {
	uint8_t	fip_dtype;		/* type - see below */
	uint8_t	fip_dlen;		/* length - in 32-bit words */
};

enum proto_fip_desc_type {
	PROTO_FIP_DT_PRI =	1,	/* priority for forwarder selection */
	PROTO_FIP_DT_MAC =	2,	/* MAC address */
	PROTO_FIP_DT_MAP_OUI = 3,	/* FC-MAP OUI */
	PROTO_FIP_DT_NAME =	4,	/* switch name or node name */
	PROTO_FIP_DT_FAB =	5,	/* fabric descriptor */
	PROTO_FIP_DT_FCOE_SIZE = 6,	/* max FCoE frame size */
	PROTO_FIP_DT_FLOGI =	7,	/* FLOGI request or response */
	PROTO_FIP_DT_FDISC =	8,	/* FDISC request or response */
	PROTO_FIP_DT_LOGO =	9,	/* LOGO request or response */
	PROTO_FIP_DT_ELP =	10,	/* ELP request or response */
	PROTO_FIP_DT_VN_ID =	11,	/* VN_Node Identifier */
	PROTO_FIP_DT_FKA =	12,	/* advertisement keep-alive period */
	PROTO_FIP_DT_VENDOR =	13,	/* vendor ID */
	PROTO_FIP_DT_VLAN =	14,	/* vlan number */
	PROTO_FIP_DT_FC4F =   15,       /* FC-4 features */
	PROTO_FIP_DT_LIMIT,		/* max defined desc_type + 1 */
	PROTO_FIP_DT_VENDOR_BASE = 128,	/* first vendor-specific desc_type */
};

/*
 * FIP_DT_PRI - priority descriptor.
 */
struct proto_fip_pri_desc {
	struct proto_fip_desc fd_desc;
	uint8_t		fd_resvd;
	uint8_t		fd_pri;		/* FCF priority:  higher is better */
}__attribute__ ((packed));

/*
 * FIP_DT_MAC - MAC address descriptor.
 */
struct proto_fip_mac_desc {
	struct proto_fip_desc fd_desc;
	uint8_t		fd_mac[6];
}__attribute__ ((packed));

/*
 * FIP_DT_MAP - descriptor.
 */
struct proto_fip_map_desc {
	struct proto_fip_desc fd_desc;
	uint8_t		fd_resvd[3];
	uint8_t		fd_map[3];
}__attribute__ ((packed));

/*
 * FIP_DT_NAME descriptor.
 */
struct proto_fip_wwn_desc {
	struct proto_fip_desc 	fd_desc;
	uint8_t			fd_resvd[2];
	uint64_t		fd_wwn;	/* 64-bit WWN, unaligned */
}__attribute__ ((packed));

/*
 * FIP_DT_FAB descriptor.
 */
struct proto_fip_fab_desc {
	struct proto_fip_desc 	fd_desc;
	uint16_t		fd_vfid;	/* virtual fabric ID */
	uint8_t			fd_resvd;
	uint8_t			fd_map[3];	/* FC-MAP value */
	uint64_t		fd_wwn;		/* fabric name, unaligned */
}__attribute__ ((packed));

/*
 * FIP_DT_FCOE_SIZE descriptor.
 */
struct proto_fip_size_desc {
	struct proto_fip_desc 	fd_desc;
	uint16_t		fd_size;
}__attribute__ ((packed));

/*
 * FC4-types object.
 */
#define PROTO_FC_NS_TYPES     256     /* number of possible FC-4 types */
#define PROTO_FC_NS_BPW       32      /* bits per word in bitmap */

struct proto_fc_ns_fts {
        uint32_t ff_type_map[PROTO_FC_NS_TYPES / PROTO_FC_NS_BPW]; 
					/* bitmap of FC-4 types */
};

/*
 * FC4-features object.
 */
struct proto_fc_ns_ff {
        uint32_t fd_feat[PROTO_FC_NS_TYPES * 4 / PROTO_FC_NS_BPW]; 
					/* 4-bits per FC-type */
};
/*
 * FIP_DT_FC4F - FC-4 features.
 */
struct proto_fip_fc4_desc {
	struct 	proto_fip_desc 	fd_desc;
	uint8_t        		fd_resvd[2];
	struct proto_fc_ns_fts 	fd_fts;
	struct proto_fc_ns_ff 	fd_ff;
}__attribute__ ((packed));

/*
 * FIP_FLOGI descriptor.
 */
struct proto_fip_flogi_desc {
	struct proto_fip_desc 	fd_desc;
	uint8_t			fd_resvd[2];
	struct proto_fc_fr_hdr 	fc_hdr;
	uint8_t			fc_els_pld[116];
}__attribute__ ((packed));

/*
 * FIP_LOGO descriptor.
 */
struct proto_fip_logo_desc {
	struct proto_fip_desc 	fd_desc;
	uint8_t			fd_resvd[2];
	struct proto_fc_fr_hdr 	fc_hdr;
	uint8_t			fc_els_pld[16];
}__attribute__ ((packed));

/*
 * FIP_DT_VLAN descriptor.
 */
struct proto_fip_vlan_desc {
	struct proto_fip_desc 	fd_desc;
	uint16_t		fd_fcoe_vid;
}__attribute__ ((packed));

/*
 * Descriptor that encapsulates an ELS or ILS frame.
 * The encapsulated frame immediately follows this header, without
 * SOF, EOF, or CRC.
 */
struct proto_fip_encaps {
	struct proto_fip_desc 	fd_desc;
	uint8_t			fd_resvd[2];
}__attribute__ ((packed));

/*
 * FIP_DT_VN_ID - VN_Node Identifier descriptor.
 */
struct proto_fip_vn_desc {
	struct proto_fip_desc 	fd_desc;
	uint8_t			fd_mac[6];
	uint8_t			fd_resvd;
	uint8_t			fd_fc_id[3];
	uint64_t		fd_wwpn;	/* port name, unaligned */
}__attribute__ ((packed));

/*
 * FIP_DT_FKA - Advertisement keep-alive period.
 */
struct proto_fip_fka_desc {
	struct proto_fip_desc 	fd_desc;
	uint16_t		fd_resvd : 15;
	uint16_t		d : 1;
	uint32_t		fd_fka_period;	/* adv./keep-alive period in mS */
}__attribute__ ((packed));

/*
 * FIP_DT_VENDOR descriptor.
 */
struct proto_fip_vendor_desc {
	struct proto_fip_desc 	fd_desc;
	uint8_t			fd_resvd[2];
	uint8_t			fd_vendor_id[8];
}__attribute__ ((packed));

struct proto_ethhdr {
	uint8_t		dmac[6];	/* FCF MAC address */
	uint8_t		smac[6];	/* Source FCoE MAC address */
	uint32_t	vlan_tag;	/* VLAN tag */
	uint16_t	et;		/* Ethernet type
					 * always set to FCoE or FIP 
					 */
} __attribute__((packed));

struct proto_ethhdr_novlan {
	uint8_t		dmac[6];	/* FCF MAC address */
	uint8_t		smac[6];	/* Source FCoE MAC address */
	uint16_t	et;		/* Ethernet type
					 * always set to FCoE or FIP 
					 */
} __attribute__((packed));

struct proto_fip_sol {
	//struct ethhdr eth;
	struct proto_ethhdr_novlan eth;
	struct proto_fip_header fip;
	struct {
		struct proto_fip_mac_desc mac;
		struct proto_fip_wwn_desc wwnn;
		struct proto_fip_size_desc size;
	}desc;
}__attribute__ ((packed));

struct proto_fip_fcf_ka {
	struct proto_ethhdr_novlan eth;
	struct proto_fip_header fip;
	struct {
		struct proto_fip_mac_desc mac;
	}desc;
}__attribute__ ((packed));

struct proto_fip_vlan_req {
	struct proto_ethhdr_novlan eth;
	struct proto_fip_header fip;
	struct {
		struct proto_fip_mac_desc mac;
		struct proto_fip_wwn_desc wwnn;
	}desc;
}__attribute__ ((packed));

struct proto_fip_vlan_notif {
	struct proto_ethhdr_novlan eth;
	struct proto_fip_header fip;
	struct {
		struct proto_fip_mac_desc mac;
		struct proto_fip_vlan_desc vlan;
	}desc;
}__attribute__ ((packed));

struct proto_fip_vnp_ka {
	struct proto_ethhdr_novlan eth;
	struct proto_fip_header fip;
	struct {
		struct proto_fip_mac_desc mac;
		struct proto_fip_vn_desc vn;
	}desc;
}__attribute__ ((packed));

struct proto_fip_virt_ln_req {
	struct proto_ethhdr_novlan eth;
	struct proto_fip_header fip;
	struct {
		struct proto_fip_flogi_desc logi;
		struct proto_fip_mac_desc mac;
	}desc;
}__attribute__ ((packed));

struct proto_fip_virt_ln_rsp {
	struct proto_ethhdr_novlan eth;
	struct proto_fip_header fip;
	struct {
		struct proto_fip_flogi_desc logi;
		struct proto_fip_mac_desc mac;
	}desc;
}__attribute__ ((packed));

struct proto_fip_virt_logo_req {
	struct proto_ethhdr_novlan eth;
	struct proto_fip_header fip;
	struct {
		struct proto_fip_logo_desc logo;
		struct proto_fip_mac_desc mac;
	}desc;
}__attribute__ ((packed));

struct proto_fip_clr_virt_lnk {
	struct proto_ethhdr_novlan eth;
	struct proto_fip_header fip;
	struct {
		struct proto_fip_mac_desc mac;
		struct proto_fip_wwn_desc wwnn;
		struct proto_fip_vn_desc vn;
	}desc;
}__attribute__ ((packed));

struct proto_fip_nport_probe {
	struct proto_ethhdr_novlan eth;
	struct proto_fip_header fip;
	struct {
		struct proto_fip_mac_desc mac;
		struct proto_fip_wwn_desc wwnn;
		struct proto_fip_vn_desc vn;
	}desc;
}__attribute__ ((packed));

struct proto_fip_beacon {
	struct proto_ethhdr_novlan eth;
	struct proto_fip_header fip;
	struct {
		struct proto_fip_mac_desc mac;
		struct proto_fip_wwn_desc wwnn;
		struct proto_fip_vn_desc vn;
	}desc;
}__attribute__ ((packed));

struct proto_fip_nport_claim {
	struct proto_ethhdr_novlan eth;
	struct proto_fip_header fip;
	struct {
		struct proto_fip_mac_desc mac;
		struct proto_fip_wwn_desc wwnn;
		struct proto_fip_vn_desc vn;
		struct proto_fip_size_desc size; 
		struct proto_fip_fc4_desc fc4_attr;
	}desc;
}__attribute__ ((packed));

/*
 * The FCoE ethertype eventually goes in net/if_ether.h.
 */
#ifndef PROTO_ETH_P_FCOE
#define PROTO_ETH_P_FCOE      0x8906          /* FCOE ether type */
#endif

/*
 * FC_FCOE_OUI hasn't been standardized yet.   XXX TBD.
 */
#ifndef PROTO_FC_FCOE_OUI
#define	PROTO_FC_FCOE_OUI	0xfcfcfc	/* upper 24 bits of FCOE dest MAC TBD */
#endif
/*
 * The destination MAC address for the fabric login may get a different OUI.
 * This isn't standardized yet.
 */
#ifndef PROTO_FC_FCOE_FLOGI_MAC
/* gateway MAC - TBD */
#define	FC_FCOE_FLOGI_MAC { 0xfc, 0xfc, 0xfc, 0xff, 0xff, 0xfe }
#endif

#define	PROTO_FC_FCOE_VER	0		/* version */
#define PROTO_MAX_FCOE_SIZE 2128
#define PROTO_MIN_FCOE_SIZE 68 
/*
 * Ethernet Addresses based on FC S_ID and D_ID.
 * Generated by FC_FCOE_OUI | S_ID/D_ID
 */
#define	PROTO_FC_FCOE_ENCAPS_ID(n)	\
	(((u_int64_t)PROTO_FC_FCOE_OUI << 24) | (n))
#define	PROTO_FC_FCOE_DECAPS_ID(n)	((n) >> 24)

/*
 * FCoE frame header - 14 bytes
 *
 * This is the August 2007 version of the FCoE header as defined by T11.
 * This follows the VLAN header, which includes the ethertype.
 */
struct proto_fcoe_hdr {
	uint8_t		fcoe_ver;	/* version field - upper 4 bits */
	uint8_t		fcoe_resvd[12];	/* reserved - send zero and ignore */
	uint8_t		fcoe_sof;	/* start of frame per RFC 3643 */
};

#define PROTO_FC_FCOE_DECAPS_VER(hp)	    	((hp)->proto_fcoe_ver >> 4)
#define PROTO_FC_FCOE_ENCAPS_VER(hp, ver) 	\
	((hp)->proto_fcoe_ver = (ver) << 4)

/*
 * FCoE CRC & EOF - 8 bytes.
 */
struct proto_fcoe_crc_eof {
	uint32_t	fcoe_crc32;	/* CRC for FC packet */
	uint8_t		fcoe_eof;	/* EOF from RFC 3643 */
	uint8_t		fcoe_resvd[3];	/* reserved - send zero and ignore */
} __attribute__ ((packed));


/*
 * Store OUI + DID into MAC address field.
 */
static inline void proto_fc_fcoe_set_mac(uint8_t *mac, uint8_t *did)
{
	mac[0] = (uint8_t) (PROTO_FC_FCOE_OUI >> 16);
	mac[1] = (uint8_t) (PROTO_FC_FCOE_OUI >> 8);
	mac[2] = (uint8_t) PROTO_FC_FCOE_OUI;
	mac[3] = did[0];
	mac[4] = did[1];
	mac[5] = did[2];
}

/*
 * set vn2vn mac
 */
static inline void proto_fip_vn2vn_set_mac(uint8_t *mac, uint32_t nport_id)
{
	uint8_t did[3];
	mac[0] = (uint8_t) (PROTO_FIP_VN2VN_FC_MAP >> 16);
	mac[1] = (uint8_t) (PROTO_FIP_VN2VN_FC_MAP >> 8);
	mac[2] = (uint8_t) PROTO_FIP_VN2VN_FC_MAP;

	chfcoe_hton24(did, nport_id);
	mac[3] = did[0];
	mac[4] = did[1];
	mac[5] = did[2];
}

/*
 * VLAN header.  This is also defined in linux/if_vlan.h, but for kernels only.
 */
struct proto_fcoe_vlan_hdr {
	uint16_t 	vlan_tag;	/* VLAN tag including priority */
	uint16_t	vlan_ethertype;	/* encapsulated ethertype ETH_P_FCOE */
};

#ifndef ETH_P_8021Q
#define	ETH_P_8021Q				0x8100
#endif

#ifndef VLAN_PRIO_SHIFT
#define VLAN_PRIO_SHIFT         13
#endif

struct proto_fcoe_fr_hdr {
        /* Ethernet part of the Header */
        struct proto_ethhdr_novlan    eth;
        uint16_t	        ver;
        /* FCM part of the Header */
        uint64_t	       rsvd; /* Reserved */
        /* FC part of the Header */
        uint32_t     sof;                    /* FC Start of Fr Delimiter */
        struct proto_fc_fr_hdr hdr;           /* Basic Header */
} __attribute__ ((packed));

struct proto_fcoe_fr_novlan_hdr {
        /* Ethernet part of the Header */
        struct proto_ethhdr_novlan eth;
        uint16_t     ver __attribute__ ((packed));
        /* FCM part of the Header */
        uint64_t     rsvd;                   /* Reserved */

        /* FC part of the Header */
        uint32_t     sof;                    /* FC Start of Fr Delimiter */

        struct proto_fc_fr_hdr hdr;           /* Basic Header */

} __attribute__ ((packed));

struct proto_fcoe_fr_trlr {
        uint32_t     fc_crc;                 /* FC CRC */
        uint8_t      eof;                    /* FC End of Fr Delimiter */
        uint8_t      rsvd[3];
};
/*
 * Get frame payload from message in fc_frame structure.
 * This hides a cast and provides a place to add some checking.
 * The len parameter is the minimum length for the payload portion.
 * Returns NULL if the frame is too short.
 *
 * This assumes the interesting part of the payload is in the first part
 * of the buffer for received data.  This may not be appropriate to use for
 * buffers being transmitted.
 */
static inline void *proto_fc_frame_payload_get(const chfcoe_fc_buffer_t *fb,
                                         size_t len)
{
        void *pp = NULL;

        if (chfcoe_fc_len(fb) >= sizeof(struct proto_fc_fr_hdr) + len)
                pp = (fc_header_t *) chfcoe_fc_hdr(fb) + 1;
        return pp;
}

struct chfcoe_skb_cb {
	uint8_t port;
	uint8_t fc_sof;  /* start of frame delimiter */
	uint8_t fc_eof;  /* end of frame delimiter */
	uint16_t vlan_tci;
	union {
		struct {
			uint8_t txq;
			unsigned int dma_len;
			unsigned int page_dma_len;
			void *pdev;      
			void *page;
			chfcoe_dma_addr_t dma_addr;
			chfcoe_dma_addr_t page_dma_addr;

		} __attribute__((packed)) tx;

		struct {
			unsigned int worker_id;
			unsigned int data_len; 
			void *lnode;      
			void *cmpl; 
			void *rnode;
			unsigned char *data_ptr;

		} __attribute__((packed)) rx;
	}a;
	
	uint16_t mcast:1;	/* RX is mcast frame */
	uint16_t rsvd:6;	
	uint16_t mpsid:9;	/* MPS ID hit */
} __attribute__((packed));

#define chfcoe_fcb_cb(fp)		((struct chfcoe_skb_cb *)((unsigned char *)(fp) + os_skbcb_offset))
#define chfcoe_fc_mpsid(fp)		(chfcoe_fcb_cb(fp)->mpsid)
#define chfcoe_fc_mcast(fp)		(chfcoe_fcb_cb(fp)->mcast)
#define chfcoe_fc_sof(fp)		(chfcoe_fcb_cb(fp)->fc_sof)
#define chfcoe_fc_eof(fp)		(chfcoe_fcb_cb(fp)->fc_eof)
#define chfcoe_fc_txq(fp)         	(chfcoe_fcb_cb(fp)->a.tx.txq)
#define chfcoe_fc_dma_len(fp)           (chfcoe_fcb_cb(fp)->a.tx.dma_len)
#define chfcoe_fc_page_dma_len(fp)     	(chfcoe_fcb_cb(fp)->a.tx.page_dma_len)
#define chfcoe_fc_pdev(fp)	        (chfcoe_fcb_cb(fp)->a.tx.pdev)
#define chfcoe_fc_sg_page(fp)           (chfcoe_fcb_cb(fp)->a.tx.page)
#define chfcoe_fc_dma_addr(fp)          (chfcoe_fcb_cb(fp)->a.tx.dma_addr)
#define chfcoe_fc_page_dma_addr(fp)	(chfcoe_fcb_cb(fp)->a.tx.page_dma_addr)
#define chfcoe_fc_worker_id(fp)         (chfcoe_fcb_cb(fp)->a.rx.worker_id)
#define chfcoe_fc_data_len(fp)          (chfcoe_fcb_cb(fp)->a.rx.data_len)
#define chfcoe_fc_lnode(fp)             (chfcoe_fcb_cb(fp)->a.rx.lnode)
#define chfcoe_fc_cmpl(fp)          	(chfcoe_fcb_cb(fp)->a.rx.cmpl)
#define chfcoe_fc_rnode(fp)             (chfcoe_fcb_cb(fp)->a.rx.rnode)
#define chfcoe_fc_data_ptr(fp)		(chfcoe_fcb_cb(fp)->a.rx.data_ptr)

static inline void chfcoe_fcb_pull_rx(chfcoe_fc_buffer_t *fcb, unsigned int len)
{
	chfcoe_fc_data_ptr(fcb) += len;
	chfcoe_fc_data_len(fcb) -= len;
}

static inline void chfcoe_fcb_trim_rx(chfcoe_fc_buffer_t *fcb, unsigned int len)
{
	chfcoe_fc_data_len(fcb) -= len;
}

/*
 * Get frame payload from message in fc_frame structure.
 * This hides a cast and provides a place to add some checking.
 * The len parameter is the minimum length for the payload portion.
 * Returns NULL if the frame is too short.
 *
 * This assumes the interesting part of the payload is in the first part
 * of the buffer for received data.  This may not be appropriate to use for
 * buffers being transmitted.
 */
static inline void *proto_fc_frame_payload_get_rx(const chfcoe_fc_buffer_t *fb,
                                         size_t len)
{
        void *pp = NULL;

        if (chfcoe_fc_data_len(fb) >= sizeof(struct proto_fc_fr_hdr) + len)
                pp = ((fc_header_t *)chfcoe_fc_data_ptr(fb)) + 1;
        return pp;
}

#define CHFCOE_MAX_CTRL_WR_LEN  512
static inline int chfcoe_is_imm(const chfcoe_fc_buffer_t *fr)
{
        return chfcoe_fc_len(fr) <= CHFCOE_MAX_CTRL_WR_LEN;
}

chfcoe_fc_buffer_t *chfcoe_fc_ctrl_alloc(size_t payload_len);
chfcoe_fc_buffer_t *chfcoe_fc_buffer_alloc(size_t payload_len, int atomic);
chfcoe_fc_buffer_t *chfcoe_fip_buffer_alloc(size_t payload_len);
chfcoe_fc_buffer_t *chfcoe_fip_els_buffer_alloc(size_t payload_len);
chfcoe_fc_buffer_t *chfcoe_fc_buffer_alloc_pkts(const uint16_t *fill_bytes, fc_header_t **fc_hdr,
		uint16_t sense_buffer_len);

static inline void
chfcoe_fill_fip_hdr(void *hdr, uint8_t *dmac, uint8_t *smac, uint16_t op,
		uint8_t sub_op, uint32_t dl, uint16_t flags)
{
	struct proto_ethhdr_novlan *eth = (struct proto_ethhdr_novlan *)hdr;
	struct proto_fip_header *fip = (struct proto_fip_header *) (eth + 1);

       	chfcoe_memcpy(eth->dmac, dmac, 6);
        chfcoe_memcpy(eth->smac, smac, 6);
        eth->et	= chfcoe_htons(ETH_P_PROTO_FIP);

        fip->fip_ver 	= PROTO_FIP_VER_ENCAPS(1);
        fip->fip_op 	= chfcoe_htons(op);
        fip->fip_subcode = sub_op;
        fip->fip_dl_len = chfcoe_htons(dl / PROTO_FIP_BPW);
        fip->fip_flags 	= chfcoe_htons(flags);
}

static inline void
chfcoe_fill_fip_mac_desc(struct proto_fip_mac_desc *desc, uint8_t *mac)
{
        desc->fd_desc.fip_dtype = PROTO_FIP_DT_MAC;
        desc->fd_desc.fip_dlen 	= sizeof(*desc) / PROTO_FIP_BPW;
        chfcoe_memcpy(desc->fd_mac, mac, 6);
}	

static inline void
chfcoe_fill_fip_name_desc(struct proto_fip_wwn_desc *desc, uint8_t *wwn)
{
        desc->fd_desc.fip_dtype = PROTO_FIP_DT_NAME;
        desc->fd_desc.fip_dlen  = sizeof(*desc) / PROTO_FIP_BPW;
        chfcoe_memcpy(&desc->fd_wwn, wwn, 8);
}

static inline void
chfcoe_fill_fip_vn_desc(struct proto_fip_vn_desc *desc, uint8_t *mac, 
		uint32_t nport_id, uint8_t *wwpn)
{
        desc->fd_desc.fip_dtype = PROTO_FIP_DT_VN_ID;
        desc->fd_desc.fip_dlen 	= sizeof(*desc) / PROTO_FIP_BPW;
        chfcoe_memcpy(desc->fd_mac, mac, 6);
	chfcoe_memcpy(&desc->fd_wwpn, wwpn, 8);	
	chfcoe_hton24(desc->fd_fc_id, nport_id);
}

static inline void
chfcoe_fill_fip_size_desc(struct proto_fip_size_desc *desc, uint16_t size)
{
        desc->fd_desc.fip_dtype = PROTO_FIP_DT_FCOE_SIZE;
        desc->fd_desc.fip_dlen  = sizeof(*desc) / PROTO_FIP_BPW;
	desc->fd_size = chfcoe_htons(size);
}

static inline void
chfcoe_fill_fip_fc4_desc(struct proto_fip_fc4_desc *desc, 
		struct proto_fc_ns_fts *fts, struct proto_fc_ns_ff *ff)
{
        desc->fd_desc.fip_dtype = PROTO_FIP_DT_FC4F;
        desc->fd_desc.fip_dlen  = sizeof(*desc) / PROTO_FIP_BPW;
	chfcoe_memcpy(&desc->fd_fts, fts, sizeof(struct proto_fc_ns_fts));
	chfcoe_memcpy(&desc->fd_ff, ff, sizeof(struct proto_fc_ns_ff));
}

/*
 * SOF / EOF bytes.
 */
enum proto_fc_sof {

    PROTO_FC_SOF_F =      	(uint8_t)0x28,  	/* fabric */
    PROTO_FC_SOF_I2 =     		0x2d,  	/* initiate class 2 */
    PROTO_FC_SOF_I3 =     		0x2e,   /* initiate class 3 */
    PROTO_FC_SOF_N2 =     		0x35, 	/* normal class 2 */
    PROTO_FC_SOF_N3 =     		0x36, 	/* normal class 3 */

}; /* enum proto_fc_sof */

enum proto_fc_eof {

    PROTO_FC_EOF_N =      	(uint8_t)0x41, 	/* normal (not last frame of seq) */
    PROTO_FC_EOF_T =      		0x42,  	/* terminate (last frame of sequence) */
    PROTO_FC_EOF_NI =     		0x49,  	/* normal-invalid */
    PROTO_FC_EOF_A =      		0x50,   /* abort */

}; /* enum proto_fc_eof */

#define PROTO_FC_SOF_CLASS_MASK   	0x06	/* mask for class of service in SOF */

/*
 * Define classes in terms of the SOF code (initial).
 */
enum proto_fc_class {

    PROTO_FC_CLASS_NONE = 	(uint8_t)0,	/* software value indicating no class */
    PROTO_FC_CLASS_2 =    		PROTO_FC_SOF_I2,
    PROTO_FC_CLASS_3 =    		PROTO_FC_SOF_I3,
    PROTO_FC_CLASS_F =    		PROTO_FC_SOF_F,

}; /* enum proto_fc_class */


/*
 * R_CTL - Routing control definitions.
 */

/*
 * FC-4 device_data.
 */
enum proto_fc_rctl {
	PROTO_FC_RCTL_DD_UNCAT = 	0x00,	/* uncategorized information */
	PROTO_FC_RCTL_DD_SOL_DATA = 	0x01,	/* solicited data */
	PROTO_FC_RCTL_DD_UNSOL_CTL = 	0x02,	/* unsolicited control */
	PROTO_FC_RCTL_DD_SOL_CTL = 	0x03,	/* solicited control or reply */
	PROTO_FC_RCTL_DD_UNSOL_DATA =	0x04,	/* unsolicited data */
	PROTO_FC_RCTL_DD_DATA_DESC = 	0x05,	/* data descriptor */
	PROTO_FC_RCTL_DD_UNSOL_CMD = 	0x06,	/* unsolicited command */
	PROTO_FC_RCTL_DD_CMD_STATUS = 	0x07,	/* command status */

#define PROTO_FC_RCTL_ILS_REQ FC_RCTL_DD_UNSOL_CTL	/* ILS request */
#define PROTO_FC_RCTL_ILS_REP PROTO_FC_RCTL_DD_SOL_CTL	/* ILS reply */

	/*
	 * Extended Link_Data
	 */
	PROTO_FC_RCTL_ELS_REQ = 	0x22,	/* extended link services request */
	PROTO_FC_RCTL_ELS_REP = 	0x23,	/* extended link services reply */
	PROTO_FC_RCTL_ELS4_REQ = 	0x32, /* PROTO_FC-4 ELS request */
	PROTO_FC_RCTL_ELS4_REP = 	0x33, /* PROTO_FC-4 ELS reply */
	/*
	 * Optional Extended Headers
	 */
	PROTO_FC_RCTL_VFTH = 		0x50,	/* virtual fabric tagging header */
	PROTO_FC_RCTL_IFRH = 		0x51,	/* inter-fabric routing header */
	PROTO_FC_RCTL_ENCH = 		0x52,	/* encapsulation header */
	/*
	 * Basic Link Services fh_r_ctl values.
	 */
	PROTO_FC_RCTL_BA_NOP = 		0x80,	/* basic link service NOP */
	PROTO_FC_RCTL_BA_ABTS = 	0x81,	/* basic link service abort */
	PROTO_FC_RCTL_BA_RMC = 		0x82,	/* remove connection */
	PROTO_FC_RCTL_BA_ACC = 		0x84,	/* basic accept */
	PROTO_FC_RCTL_BA_RJT = 		0x85,	/* basic reject */
	PROTO_FC_RCTL_BA_PRMT = 	0x86,	/* dedicated connection preempted */
	/*
	 * Link Control Information.
	 */
	PROTO_FC_RCTL_ACK_1 = 		0xc0,	/* acknowledge_1 */
	PROTO_FC_RCTL_ACK_0 = 		0xc1,	/* acknowledge_0 */
	PROTO_FC_RCTL_P_RJT = 		0xc2,	/* port reject */
	PROTO_FC_RCTL_F_RJT = 		0xc3,	/* fabric reject */
	PROTO_FC_RCTL_P_BSY = 		0xc4,	/* port busy */
	PROTO_FC_RCTL_F_BSY = 		0xc5,	/* fabric busy to data frame */
	PROTO_FC_RCTL_F_BSYL = 		0xc6,	/* fabric busy to link control frame */
	PROTO_FC_RCTL_LCR = 		0xc7,	/* link credit reset */
	PROTO_FC_RCTL_END = 		0xc9,	/* end */
};
/*
 * Well-known fabric addresses.
 */
enum proto_fc_well_known_fid {
	PROTO_FC_FID_BCAST =		0xffffff,	/* broadcast */
	PROTO_FC_FID_FLOGI =		0xfffffe,	/* fabric login */
	PROTO_FC_FID_FCTRL =		0xfffffd,	/* fabric controller */
	PROTO_FC_FID_DIR_SERV =		0xfffffc,	/* directory server */
	PROTO_FC_FID_TIME_SERV =	0xfffffb,	/* time server */
	PROTO_FC_FID_MGMT_SERV =	0xfffffa,	/* management server */
	PROTO_FC_FID_QOS =		0xfffff9,	/* QoS Facilitator */
	PROTO_FC_FID_ALIASES =		0xfffff8,	/* alias server (FC-PH2) */
	PROTO_FC_FID_SEC_KEY =		0xfffff7,	/* Security key dist. server */
	PROTO_FC_FID_CLOCK =		0xfffff6,	/* clock synch server */
	PROTO_FC_FID_MCAST_SERV =	0xfffff5,	/* multicast server */
};

/*
 * Other well-known addresses, outside the above contiguous range.
 */
#define PROTO_FC_FID_DOM_MGR		0xfffc00	/* domain manager base */

/*
 * Fabric ID bytes.
 */
#define PROTO_FC_FID_DOMAIN		0
#define PROTO_FC_FID_PORT		1
#define PROTO_FC_FID_LINK		2

/*
 * Protocol Service Types
 */
enum proto_fc_fh_type {
	FC_TYPE_BLS =			0x00,	/* basic link service */
	PROTO_FC_TYPE_ELS =		0x01,	/* extended link service */
	PROTO_FC_TYPE_IP =		0x05,	/* IP over FC, RFC 4338 */
	PROTO_FC_TYPE_FCP =		0x08,	/* SCSI FCP */
	PROTO_FC_TYPE_CT =		0x20,	/* Fibre Channel Services (FC-CT) */
	PROTO_FC_TYPE_ILS =		0x22,	/* internal link service */
};
/*
 * Exchange IDs.
 */
#define PROTO_FC_XID_UNKNOWN  		0xffff		/* unknown exchange ID */

/*
 * F_CTL - Frame control flags.
 */
#define	PROTO_FC_EX_CTX			(1 << 23)	/* sent by responder to exchange */
#define	PROTO_FC_SEQ_CTX		(1 << 22)	/* sent by responder to sequence */
#define	PROTO_FC_FIRST_SEQ 		(1 << 21)	/* first sequence of this exchange */
#define	PROTO_FC_LAST_SEQ		(1 << 20)	/* last sequence of this exchange */
#define	PROTO_FC_END_SEQ		(1 << 19)	/* last frame of sequence */
#define	PROTO_FC_END_CONN		(1 << 18)	/* end of class 1 connection pending */
#define	PROTO_FC_RES_B17		(1 << 17)	/* reserved */
#define	PROTO_FC_SEQ_INIT		(1 << 16)	/* transfer of sequence initiative */
#define	PROTO_FC_X_ID_REASS 		(1 << 15)	/* exchange ID has been changed */
#define	PROTO_FC_X_ID_INVAL 		(1 << 14)	/* exchange ID invalidated */

#define	PROTO_FC_ACK_1			(1 << 12)	/* 13:12 = 1: ACK_1 expected */
#define	PROTO_FC_ACK_N			(2 << 12)	/* 13:12 = 2: ACK_N expected */
#define	PROTO_FC_ACK_0			(3 << 12)	/* 13:12 = 3: ACK_0 expected */

#define	PROTO_FC_RES_B11		(1 << 11)	/* reserved */
#define	PROTO_FC_RES_B10		(1 << 10)	/* reserved */
#define	PROTO_FC_RETX_SEQ		(1 << 9)	/* retransmitted sequence */
#define	PROTO_FC_UNI_TX			(1 << 8)	/* unidirectional transmit (class 1) */
#define	PROTO_FC_CONT_SEQ(i) 		((i) << 6)
#define	PROTO_FC_ABT_SEQ(i) 		((i) << 4)
#define	PROTO_FC_REL_OFF		(1 << 3)	/* parameter is relative offset */
#define	PROTO_FC_RES2			(1 << 2)	/* reserved */
#define	PROTO_FC_FILL(i)		((i) & 3)	/* 1:0: bytes of trailing fill */

/*
 * BA_ACC payload.
 */
struct proto_fc_ba_acc {
	uint8_t				ba_seq_id_val;	/* SEQ_ID validity */
#define PROTO_FC_BA_SEQ_ID_VAL 		0x80
	uint8_t				ba_seq_id;	/* SEQ_ID of seq last deliverable */
	uint8_t				ba_resvd[2];	/* reserved */
	uint16_t			ba_ox_id;	/* OX_ID for aborted seq or exch */
	uint16_t			ba_rx_id;	/* RX_ID for aborted seq or exch */
	uint16_t			ba_low_seq_cnt;	/* low SEQ_CNT of aborted seq */
	uint16_t			ba_high_seq_cnt;/* high SEQ_CNT of aborted seq */
} __attribute__((packed)); /* struct proto_fc_ba_acc */

/*
 * BA_RJT reason codes.
 * From FC-FS-2.
 */
#define PROTO_FC_BA_RJT_INVL_CMD  	0x01	/* invalid command code */
#define PROTO_FC_BA_RJT_LOG_ERR  	0x03	/* logical error */
#define PROTO_FC_BA_RJT_LOG_BUSY  	0x05	/* logical busy */
#define PROTO_FC_BA_RJT_PROTO_ERR  	0x07	/* protocol error */
#define PROTO_FC_BA_RJT_UNABLE  	0x09	/* unable to perform request */
#define PROTO_FC_BA_RJT_VENDOR  	0xff	/* vendor-specific error */

/*
 * BA_RJT: Basic Reject parameter field.
 */
struct proto_fc_ba_rjt {
	unsigned char br_resvd;			/* reserved */
	unsigned char br_reason;		/* reason code */
	unsigned char br_explan;		/* reason explanation */
	unsigned char br_vendor;		/* vendor unique code */
} __attribute__((packed)); /* struct proto_fc_ba_rjt */

/*
 * BA_RJT reason code explanations.
 */
#define PROTO_FC_BA_RJT_EXP_NONE  	0x00	/* no additional expanation */
#define PROTO_FC_BA_RJT_INV_XID  	0x03	/* invalid OX_ID-RX_ID combination */
#define PROTO_FC_BA_RJT_ABT  		0x05	/* sequence aborted, no seq info */

/*
 * P_RJT or F_RJT: Port Reject or Fabric Reject parameter field.
 */
struct proto_fc_pf_rjt {
	uint8_t	rj_action;		/* reserved */
	uint8_t	rj_reason;		/* reason code */
	uint8_t	rj_resvd;		/* reserved */
	uint8_t	rj_vendor;		/* vendor unique code */
}; /* struct proto_fc_pf_rjt */

/*
 * P_RJT and F_RJT reject reason codes.
 */
#define PROTO_FC_RJT_NONE 		0	/* non-reject (reserved by standard) */
#define PROTO_FC_RJT_INVL_DID 		0x01	/* invalid destination ID */
#define PROTO_FC_RJT_INVL_SID 		0x02	/* invalid source ID */
#define PROTO_FC_RJT_P_UNAV_T 		0x03	/* port unavailable, temporary */
#define PROTO_FC_RJT_P_UNAV 		0x04	/* port unavailable, permanent */
#define PROTO_FC_RJT_CLS_UNSUP 		0x05	/* class not supported */
#define PROTO_FC_RJT_DEL_USAGE 		0x06	/* delimiter usage error */
#define PROTO_FC_RJT_TYPE_UNSUP 	0x07	/* type not supported */
#define PROTO_FC_RJT_LINK_CTL 		0x08	/* invalid link control */
#define PROTO_FC_RJT_R_CTL 		0x09	/* invalid R_CTL field */
#define PROTO_FC_RJT_F_CTL 		0x0a	/* invalid F_CTL field */
#define PROTO_FC_RJT_OX_ID 		0x0b	/* invalid originator exchange ID */
#define PROTO_FC_RJT_RX_ID 		0x0c	/* invalid responder exchange ID */
#define PROTO_FC_RJT_SEQ_ID 		0x0d	/* invalid sequence ID */
#define PROTO_FC_RJT_DF_CTL 		0x0e	/* invalid DF_CTL field */
#define PROTO_FC_RJT_SEQ_CNT 		0x0f	/* invalid SEQ_CNT field */
#define PROTO_FC_RJT_PARAM 		0x10	/* invalid parameter field */
#define PROTO_FC_RJT_EXCH_ERR 		0x11	/* exchange error */
#define PROTO_FC_RJT_PROTO 		0x12	/* protocol error */
#define PROTO_FC_RJT_LEN 		0x13	/* incorrect length */
#define PROTO_FC_RJT_UNEXP_ACK 		0x14	/* unexpected ACK */
#define PROTO_FC_RJT_FAB_CLASS 		0x15	/* class unsupported by fabric entity */
#define PROTO_FC_RJT_LOGI_REQ 		0x16	/* login required */
#define PROTO_FC_RJT_SEQ_XS 		0x17	/* excessive sequences attempted */
#define PROTO_FC_RJT_EXCH_EST 		0x18	/* unable to establish exchange */
#define PROTO_FC_RJT_FAB_UNAV 		0x1a	/* fabric unavailable */
#define PROTO_FC_RJT_VC_ID 		0x1b	/* invalid VC_ID (class 4) */
#define PROTO_FC_RJT_CS_CTL 		0x1c	/* invalid CS_CTL field */
#define PROTO_FC_RJT_INSUF_RES 		0x1d	/* insuff. resources for VC (Class 4) */
#define PROTO_FC_RJT_INVL_CLS 		0x1f	/* invalid class of service */
#define PROTO_FC_RJT_PREEMT_RJT 	0x20	/* preemption request rejected */
#define PROTO_FC_RJT_PREEMT_DIS 	0x21	/* preemption not enabled */
#define PROTO_FC_RJT_MCAST_ERR 		0x22	/* multicast error */
#define PROTO_FC_RJT_MCAST_ET 		0x23	/* multicast error terminate */
#define PROTO_FC_RJT_PRLI_REQ 		0x24	/* process login required */
#define PROTO_FC_RJT_INVL_ATT 		0x25	/* invalid attachment */
#define PROTO_FC_RJT_VENDOR 		0xff	/* vendor specific reject */

/*
 * Data descriptor format (R_CTL == PROTO_FC_RCTL_DD_DATA_DESC).
 * This is used for FCP SCSI transfer ready.
 */
struct proto_fc_data_desc {
	uint32_t	dd_offset;	/* data relative offset in bytes */
	uint32_t	dd_len;		/* transfer buffer size in bytes */
	uint8_t		_dd_resvd[4];
};

#define PROTO_FC_DATA_DESC_LEN    	12	/* expected length of structure */


static inline void proto_fc_fill_fc_hdr(fc_header_t *fc_hdr,
				  enum proto_fc_rctl r_ctl,
				  u32 did, u32 sid, enum proto_fc_fh_type type,
	                          u32 f_ctl, u32 parm_offset)
{
	fc_hdr->r_ctl = r_ctl;
	chfcoe_hton24(fc_hdr->d_id, did);
	chfcoe_hton24(fc_hdr->s_id, sid);
	fc_hdr->type = type;
	chfcoe_hton24(fc_hdr->f_ctl, f_ctl);
	fc_hdr->cs_ctl_pri = 0;
	fc_hdr->df_ctl = 0;
	fc_hdr->params = chfcoe_htonl(parm_offset);
}

/*
 * Determine whether SOF code indicates the need for a BLS ACK.
 */
static inline int
proto_fc_sof_needs_ack(enum proto_fc_sof sof)
{
    return ((~sof) & 0x02);     /* true for class 1, 2, 4, 6, or F */

} /* proto_fc_sof_needs_ack */

/*
 * Given an proto_fc_class, return the normal (non-initial) SOF value.
 */
static inline enum proto_fc_sof
proto_fc_sof_normal(enum proto_fc_class class)
{
    return (class + PROTO_FC_SOF_N3 - PROTO_FC_SOF_I3);      /* diff is always 8 */

} /* proto_fc_sof_normal */

/*
 * Compute class from SOF value.
 */
static inline enum proto_fc_class
proto_fc_sof_class(enum proto_fc_sof sof)
{
    return ((sof & 0x7) | PROTO_FC_SOF_F);

} /* proto_fc_sof_class */

/*
 * Determine whether SOF is for the initial frame of a sequence.
 */
static inline int
proto_fc_sof_is_init(enum proto_fc_sof sof)
{
    return (sof < 0x30);
} /* proto_fc_sof_is_init */

/* Well known Fibre channel Address */
#define PROTO_FDMI_DID				0xFFFFFA /* Management server */
#define PROTO_NS_DID				0xFFFFFC /* Name server */	
#define PROTO_FABCTL_DID			0xFFFFFD /* Fabric Controller */
#define PROTO_FABRIC_DID			0xFFFFFE /* Fabric Login */
#define PROTO_BCAST_DID				0xFFFFFF /* Broadcast */
#define PROTO_UNKNOWN_DID			0x000000 /* Unknown DID */
#define PROTO_DID_MASK				0xFFFFFF /* DID Mask */
#define PROTO_WK_DID_MASK			0xFFFFF0 /* Well known did mask*/

/* FC4 Device Data Frame - TYPE */
#define PROTO_FC4_FCP_TYPE			0x8	/* FCP */

/* MAX FC Payload */
#define PROTO_MAX_FC_PAYLOAD			2112

/* FC Phy version */
#define PROTO_FC_PH_VER3			0x20	

/*Service option: Shift & Mask bits defines */
#define SP_CLASS_SUPPORT_EN	1       /* Class support enable */
#define S_SP_CLASS_SUPPORT	7
#define M_SP_CLASS_SUPPORT	1
#define V_SP_CLASS_SUPPORT(x)	((x) << S_SP_CLASS_SUPPORT)
#define G_SP_CLASS_SUPPORT(x)	(((x) >> S_SP_CLASS_SUPPORT) & \
		M_SP_CLASS_SUPPORT)

/* Sequential Delivery option: Shift & Mask bits defines */
#define SP_SEQ_DEL              1       /* In-order Sequential support enable */
#define S_SEQ_DEL               3
#define M_SEQ_DEL               1
#define V_SEQ_DEL(x)            ((x) << S_SEQ_DEL)
#define G_SEQ_DEL(x)            (((x) >> S_SEQ_DEL) & M_SEQ_DEL)
/*
 * sp_features
 */
#define PROTO_FC_SP_FT_CIRO		0x8000	/* continuously increasing rel. off. */
#define PROTO_FC_SP_FT_CLAD		0x8000	/* clean address (in FLOGI LS_ACC) */
#define PROTO_FC_SP_FT_RAND		0x4000	/* random relative offset */
#define PROTO_FC_SP_FT_VAL		0x2000	/* valid vendor version level */
#define PROTO_FC_SP_FT_FPORT		0x1000	/* F port (1) vs. N port (0) */
#define PROTO_FC_SP_FT_ABB		0x0800	/* alternate BB_credit management */
#define PROTO_FC_SP_FT_EDTR		0x0400	/* E_D_TOV Resolution is nanoseconds */
#define PROTO_FC_SP_FT_MCAST		0x0200	/* multicast */
#define PROTO_FC_SP_FT_BCAST		0x0100	/* broadcast */
#define PROTO_FC_SP_FT_HUNT		0x0080	/* hunt group */
#define PROTO_FC_SP_FT_SIMP		0x0040	/* dedicated simplex */
#define PROTO_FC_SP_FT_SEC		0x0020	/* reserved for security */
#define PROTO_FC_SP_FT_CSYN		0x0010	/* clock synch. supported */
#define PROTO_FC_SP_FT_RTTOV		0x0008	/* R_T_TOV value 100 uS, else 100 mS */
#define PROTO_FC_SP_FT_HALF		0x0004	/* dynamic half duplex */
#define PROTO_FC_SP_FT_SEQC		0x0002	/* SEQ_CNT */
#define PROTO_FC_SP_FT_PAYL		0x0001	/* FLOGI payload length 256, else 116 */

/*      
 * cp_class flags.
 */     
#define PROTO_FC_CPC_VALID		0x8000	/* class valid */
#define PROTO_FC_CPC_IMIX		0x4000	/* intermix mode */
#define PROTO_FC_CPC_SEQ		0x0800	/* sequential delivery */
#define PROTO_FC_CPC_CAMP		0x0200	/* camp-on */
#define PROTO_FC_CPC_PRI		0x0080	/* priority */

#define PROTO_FC_SP_BB_DATA_MASK 0xfff /* mask for data field size in sp_bb_data */
/* Class service parameters */
struct csio_class_sp {
        uint16_t	serv_option;		/* Service option */
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

/* Common service parameters */
struct csio_cmn_sp {
	uint8_t		hi_ver;		/* High PH version */
	uint8_t		lo_ver;		/* low PH version */	
	uint16_t	bb_credit;	/* B2B credit */
	uint16_t	word1_flags;	/* Word1 Flags (31:16)*/
	uint16_t	rcv_sz;		/* Receive data size */
	union {
		struct {
			uint16_t maxsq;		/* Max seq */
			uint16_t reloff;	/* Relative offset */
		} s1;
		uint32_t r_a_tov;	/* R_A_TOV */
	} un1;
	uint32_t	e_d_tov;		/*E_D_TOV */
};

#define sp_tot_seq      un1.s1.maxsq
#define sp_rel_off      un1.s1.reloff
#define sp_r_a_tov      un1.r_a_tov

struct csio_service_parms {
	struct csio_cmn_sp		csp;	/* Common service parms */
	uint8_t				wwpn[8];/* WWPN */
	uint8_t				wwnn[8];/* WWNN */
	struct csio_class_sp		clsp[4];/* Class service params */
	uint8_t				vvl[16];/* Vendor version level */
};
/* Common service parameters defines */

/* FC Phy version */
#define FC_PH_VER3                      0x20

/* WORD1 (31:16) flags: shift & mask bit defines */
/* NPIV support */
#define MULTIPLE_NPORT_ID_SUPPORT_EN    1
#define S_MULTIPLE_NPORT_ID_SUPPORT     15
#define M_MULTIPLE_NPORT_ID_SUPPORT     1
#define V_MULTIPLE_NPORT_ID_SUPPORT(x)  ((x) << S_MULTIPLE_NPORT_ID_SUPPORT)
#define G_MULTIPLE_NPORT_ID_SUPPORT(x)  (((x) >> S_MULTIPLE_NPORT_ID_SUPPORT) \
                                         & M_MULTIPLE_NPORT_ID_SUPPORT)

/* Continuously increasing relative offset */
#define CONTI_INCR_OFFSET_SUPPORT_EN    1
#define S_CONTI_INCR_OFFSET_SUPPORT     15
#define M_CONTI_INCR_OFFSET_SUPPORT     1
#define V_CONTI_INCR_OFFSET_SUPPORT(x)  ((x) << S_CONTI_INCR_OFFSET_SUPPORT)
#define G_CONTI_INCR_OFFSET_SUPPORT(x)  (((x) >> S_CONTI_INCR_OFFSET_SUPPORT) \
                                         & M_CONTI_INCR_OFFSET_SUPPORT)

/* Continuously increasing relative offset */
#define CLEAN_ADDR_EN           1
#define S_CLEAN_ADDR            15
#define M_CLEAN_ADDR            1
#define V_CLEAN_ADDR(x)         ((x) << S_CLEAN_ADDR)
#define G_CLEAN_ADDR(x)         (((x) >> S_CLEAN_ADDR) & M_CLEAN_ADDR)

/* Virtual Fabric Bit */
#define VFT_BIT                 1
#define S_VFT_BIT               14
#define M_VFT_BIT               1
#define V_VFT_BIT(x)            ((x) << S_VFT_BIT)
#define G_VFT_BIT(x)            (((x) >> S_VFT_BIT) & M_VFT_BIT)

/* Random Relative Offset */
#define RRO_BIT                 1
#define S_RRO_BIT               14
#define M_RRO_BIT               1
#define V_RRO_BIT(x)            ((x) << S_RRO_BIT)
#define G_RRO_BIT(x)            (((x) >> S_RRO_BIT) & M_RRO_BIT)
/* NPIV supported by Fabric */
#define NPIV_SUPPORTED_EN       1
#define S_NPIV_SUPPORTED        13
#define M_NPIV_SUPPORTED        1
#define V_NPIV_SUPPORTED(x)     ((x) << S_NPIV_SUPPORTED)
#define G_NPIV_SUPPORTED(x)     (((x) >> S_NPIV_SUPPORTED) & M_NPIV_SUPPORTED)

/* N_Port or F_Port */
#define FABRIC_PORT                     1
#define S_FABRIC_PORT                   12
#define M_FABRIC_PORT                   1
#define V_FABRIC_PORT(x)                ((x) << S_FABRIC_PORT)
#define G_FABRIC_PORT(x)                (((x) >> S_FABRIC_PORT) & M_FABRIC_PORT)

/* Alternate B2B credit management support */
#define ALT_B2B_CREDIT_MGMT_SUPPORT_EN          1
#define S_ALT_B2B_CREDIT_MGMT_SUPPORT           11
#define M_ALT_B2B_CREDIT_MGMT_SUPPORT           1
#define V_ALT_B2B_CREDIT_MGMT_SUPPORT(x)        \
        ((x) << S_ALT_B2B_CREDIT_MGMT_SUPPORT)
#define G_ALT_B2B_CREDIT_MGMT_SUPPORT(x)        \
        (((x) >> S_ALT_B2B_CREDIT_MGMT_SUPPORT) & M_ALT_B2B_CREDIT_MGMT_SUPPORT)

/* FC-SP support */
#define FC_SP                           1
#define S_FC_SP                         5
#define M_FC_SP                         1
#define V_FC_SP(x)                      ((x) << S_FC_SP)
#define G_FC_SP(x)                      (((x) >> S_FC_SP) & M_FC_SP)


/* WORD2 (31: 0) : shift and mask bit defines */
#define S_MAX_SEQ_CNT           16
#define M_MAX_SEQ_CNT           0xFFFF
#define V_MAX_SEQ_CNT(x)        ((x) << S_MAX_SEQ_CNT)
#define G_MAX_SEQ_CNT(x)        (((x) >> S_MAX_SEQ_CNT) & M_MAX_SEQ_CNT)

#define S_REL_OFFSET_BY_CATEGORY        0
#define M_REL_OFFSET_BY_CATEGORY        0xFFFF
#define V_REL_OFFSET_BY_CATEGORY(x)     ((x) << S_REL_OFFSET_BY_CATEGORY)
#define G_REL_OFFSET_BY_CATEGORY(x)     \
        (((x) >> S_REL_OFFSET_BY_CATEGORY) & M_REL_OFFSET_BY_CATEGORY)


/* ELS CMD HDR length */
#define PROTO_ELS_CMD_HDR_LEN			0x4

/* ELS COMMAND CODES */
#define PROTO_ELS_CMD_CODE_MASK			0xff
#define PROTO_ELS_CMD_CODE_LS_RJT		0x01
#define PROTO_ELS_CMD_CODE_ACC			0x02
#define PROTO_ELS_CMD_CODE_PLOGI		0x03
#define PROTO_ELS_CMD_CODE_FLOGI		0x04
#define PROTO_ELS_CMD_CODE_LOGO			0x05
#define PROTO_ELS_CMD_CODE_RES			0x08
#define PROTO_ELS_CMD_CODE_RSS			0x09
#define PROTO_ELS_CMD_CODE_RSI			0x0A
#define PROTO_ELS_CMD_CODE_ESTS			0x0B
#define PROTO_ELS_CMD_CODE_ESTC			0x0C
#define PROTO_ELS_CMD_CODE_ADVC			0x0D
#define PROTO_ELS_CMD_CODE_RTV			0x0E
#define PROTO_ELS_CMD_CODE_RLS			0x0F
#define PROTO_ELS_CMD_CODE_ECHO			0x10
#define PROTO_ELS_CMD_CODE_TEST			0x11
#define PROTO_ELS_CMD_CODE_RRQ			0x12
#define PROTO_ELS_CMD_CODE_SRR			0x14
#define PROTO_ELS_CMD_CODE_PRLI			0x20
#define PROTO_ELS_CMD_CODE_PRLO			0x21
#define PROTO_ELS_CMD_CODE_PDISC		0x50
#define PROTO_ELS_CMD_CODE_FDISC		0x51
#define PROTO_ELS_CMD_CODE_ADISC		0x52
#define PROTO_ELS_CMD_CODE_RPS			0x56
#define PROTO_ELS_CMD_CODE_RPL			0x57
#define PROTO_ELS_CMD_CODE_RSCN			0x61
#define PROTO_ELS_CMD_CODE_SCR			0x62
#define PROTO_ELS_CMD_CODE_RNID			0x78
#define PROTO_ELS_CMD_CODE_LIRR			0x7A
#define PROTO_ELS_CMD_CODE_SRL                  0x7b    /* scan remote loop */
#define PROTO_ELS_CMD_CODE_SBRP                 0x7c    /* set bit-error reporting params */
#define PROTO_ELS_CMD_CODE_RPSC                 0x7d    /* report speed capabilities */
#define PROTO_ELS_CMD_CODE_QSA                  0x7e    /* query security attributes */
#define PROTO_ELS_CMD_CODE_EVFP                 0x7f    /* exchange virt. fabrics params */
#define PROTO_ELS_CMD_CODE_LKA                  0x80    /* link keep-alive */
#define PROTO_ELS_CMD_CODE_AUTH_ELS             0x90    /* authentication ELS */


/* LS_RJT reason codes */
#define PROTO_LS_RJT_INVALID_CMD		0x01
#define PROTO_LS_RJT_LOGICAL_ERR     		0x03
#define PROTO_LS_RJT_LOGICAL_BSY     		0x05
#define PROTO_LS_RJT_PROTOCOL_ERR    		0x07
#define PROTO_LS_RJT_UNABLE_TPC      		0x09      
#define PROTO_LS_RJT_CMD_UNSUPPORTED 		0x0B
#define PROTO_LS_RJT_CMD_IN_PROGRESS 		0x0E
#define PROTO_LS_RJT_VENDOR_UNIQUE   		0xFF 

/* LS_RJT reason explanation */
#define PROTO_LS_RJT_EXPL_NONE	     	 	0x00
#define PROTO_LS_RJT_EXPL_SPARM_OPTIONS  	0x01
#define PROTO_LS_RJT_EXPL_SPARM_ICTL     	0x03
#define PROTO_LS_RJT_EXPL_SPARM_RCTL     	0x05
#define PROTO_LS_RJT_EXPL_SPARM_RCV_SIZE    	0x07
#define PROTO_LS_RJT_EXPL_SPARM_CONCUR_SEQ  	0x09
#define PROTO_LS_RJT_EXPL_SPARM_CREDIT      	0x0B
#define PROTO_LS_RJT_EXPL_INVALID_PNAME     	0x0D
#define PROTO_LS_RJT_EXPL_INVALID_NNAME     	0x0E
#define PROTO_LS_RJT_EXPL_INVALID_CSP       	0x0F
#define PROTO_LS_RJT_EXPL_INVALID_ASSOC_HDR 	0x11
#define PROTO_LS_RJT_EXPL_ASSOC_HDR_REQ     	0x13
#define PROTO_LS_RJT_EXPL_INVALID_O_SID     	0x15
#define PROTO_LS_RJT_EXPL_INVALID_OX_RX     	0x17
#define PROTO_LS_RJT_EXPL_CMD_IN_PROGRESS   	0x19
#define PROTO_LS_RJT_EXPL_PORT_LOGIN_REQ    	0x1E
#define PROTO_LS_RJT_EXPL_INVALID_NPORT_ID  	0x1F
#define PROTO_LS_RJT_EXPL_INVALID_SEQ_ID    	0x21
#define PROTO_LS_RJT_EXPL_INVALID_XCHG      	0x23
#define PROTO_LS_RJT_EXPL_INACTIVE_XCHG     	0x25
#define PROTO_LS_RJT_EXPL_RQ_REQUIRED       	0x27
#define PROTO_LS_RJT_EXPL_OUT_OF_RESOURCE   	0x29
#define PROTO_LS_RJT_EXPL_CANT_GIVE_DATA    	0x2A
#define PROTO_LS_RJT_EXPL_REQ_UNSUPPORTED   	0x2C

struct proto_elsct_rjt {
	uint8_t reason, expln;
};

/* PRLI Page and Payload length  */
#define PROTO_PRLI_PAGE_LEN			0x10
#define PROTO_PRLI_PAYLOAD_LEN			0x14

/* Common Transport (CT)  defines */
#define PROTO_CT_BASIC_IU_LEN			0x10
#define PROTO_CT_REVISION			0x1

/* GS Types */
#define PROTO_CT_GS_MGMT_SERVICE		0xFA
#define PROTO_CT_GS_TIME_SERVICE		0xFB
#define PROTO_CT_GS_DIR_SERVICE			0xFC
#define PROTO_CT_GS_FABRIC_CNTL_SERVICE		0xFD

/* Directory service Subtypes */
#define PROTO_CT_DIR_SERVICE_NS		0x02

/* CT Response code */
#define PROTO_CT_RESP_FS_RJT		0x8001
#define PROTO_CT_RESP_FS_ACC		0x8002

/* CT Reason code */
#define  PROTO_CT_NO_ADDITIONAL_EXPLANATION	0x00
#define  PROTO_CT_INVALID_COMMAND		0x01
#define  PROTO_CT_INVALID_VERSION_LEVEL		0x02
#define  PROTO_CT_LOGICAL_ERROR			0x03
#define  PROTO_CT_INVALID_IU_SIZE		0x04
#define  PROTO_CT_LOGICAL_BUSY			0x05
#define  PROTO_CT_PROTOCOL_ERROR		0x07
#define  PROTO_CT_UNABLE_TO_PERF_CMD	 	0x09
#define  PROTO_CT_CMD_NOT_SUPPORTED		0x0B
#define  PROTO_CT_VENDOR_UNIQUE			0xff

/* Name Server explanation for Reason code CT_UNABLE_TO_PERFORM_CMD_REQ */
#define  PROTO_CT_NS_PORT_ID_NOT_REG		0x01
#define  PROTO_CT_NS_PORT_NAME_NOT_REG		0x02
#define  PROTO_CT_NS_NODE_NAME_NOT_REG		0x03
#define  PROTO_CT_NS_CLASS_OF_SERVICE_NOT_REG	0x04
#define  PROTO_CT_NS_IP_ADDRESS_NOT_REG		0x05
#define  PROTO_CT_NS_IPA_NOT_REG		0x06
#define  PROTO_CT_NS_FC4_NOT_REG		0x07
#define  PROTO_CT_NS_SYMBOLIC_PORT_NAME_NOT_REG	0x08
#define  PROTO_CT_NS_SYMBOLIC_NODE_NAME_NOT_REG	0x09
#define  PROTO_CT_NS_PORT_TYPE_NOT_REG		0x0A
#define  PROTO_CT_NS_OBSOLETE1			0x0B
#define  PROTO_CT_NS_FAB_PORT_NAME_NOT_REG	0x0C
#define  PROTO_CT_NS_HARD_ADDR_NOT_REG		0x0D
#define  PROTO_CT_NS_OBSOLETE2			0x0E
#define  PROTO_CT_NS_FC4_FEAT_NOT_REG		0x0F
#define  PROTO_CT_NS_ACCESS_DENIED		0x10
#define  PROTO_CT_NS_INVALID_PORT_ID		0x11
#define  PROTO_CT_NS_DATABASE_EMPTY		0x12
#define  PROTO_CT_NS_NO_OBJ_REG			0x13
#define  PROTO_CT_NS_DOMID_NOT_PRESENT		0x14
#define  PROTO_CT_NS_PORT_NUM_NOT_PRESENT	0x15
#define  PROTO_CT_NS_NO_DEV_ATTACHED		0x16

/* Name Server Command Codes */
#define  PROTO_CT_NS_GA_NXT			0x0100
#define  PROTO_CT_NS_GPN_ID			0x0112
#define  PROTO_CT_NS_GNN_ID			0x0113
#define  PROTO_CT_NS_GCS_ID			0x0114
#define  PROTO_CT_NS_GFT_ID			0x0117
#define  PROTO_CT_NS_GSPN_ID			0x0118
#define  PROTO_CT_NS_GPT_ID			0x011A
#define  PROTO_CT_NS_GFF_ID			0x011F
#define  PROTO_CT_NS_GID_PN			0x0121
#define  PROTO_CT_NS_GID_NN			0x0131
#define  PROTO_CT_NS_GIP_NN			0x0135
#define  PROTO_CT_NS_GIPA_NN			0x0136
#define  PROTO_CT_NS_GSNN_NN			0x0139
#define  PROTO_CT_NS_GNN_IP			0x0153
#define  PROTO_CT_NS_GIPA_IP			0x0156
#define  PROTO_CT_NS_GID_FT			0x0171
#define  PROTO_CT_NS_GPN_FT			0x0172
#define  PROTO_CT_NS_GID_PT			0x01A1
#define  PROTO_CT_NS_RPN_ID			0x0212
#define  PROTO_CT_NS_RNN_ID			0x0213
#define  PROTO_CT_NS_RCS_ID			0x0214
#define  PROTO_CT_NS_RFT_ID			0x0217
#define  PROTO_CT_NS_RSPN_ID			0x0218
#define  PROTO_CT_NS_RPT_ID			0x021A
#define  PROTO_CT_NS_RFF_ID			0x021F
#define  PROTO_CT_NS_RIP_NN			0x0235
#define  PROTO_CT_NS_RIPA_NN			0x0236
#define  PROTO_CT_NS_RSNN_NN			0x0239
#define  PROTO_CT_NS_DA_ID			0x0300

/* Port Types */
#define  PROTO_CT_PORT_TYPE_N_PORT		0x01
#define  PROTO_CT_PORT_TYPE_NL_PORT		0x02
#define  PROTO_CT_PORT_TYPE_FNL_PORT		0x03
#define  PROTO_CT_PORT_TYPE_IP			0x04
#define  PROTO_CT_PORT_TYPE_FCP			0x08
#define  PROTO_CT_PORT_TYPE_NX_PORT		0x7F
#define  PROTO_CT_PORT_TYPE_F_PORT		0x81
#define  PROTO_CT_PORT_TYPE_FL_PORT		0x82
#define  PROTO_CT_PORT_TYPE_E_PORT		0x84

/* PROTO_FCP defines */
/*
 * pri_ta.
 */

#define PROTO_FCP_PRI_SHIFT			3    /* priority field starts 
						      * in bit 3
						      */
#define PROTO_FCP_PRI_RESVD_MASK		0x80 /* reserved bits in priority
						      * field
						      */

/*
 * tm_flags - task management flags field.
 */
#define PROTO_FCP_TMF_ABT_TASK_SET    		0x02	/* abort task set */
#define PROTO_FCP_TMF_CLR_TASK_SET    		0x04	/* clear task set */
#define PROTO_FCP_TMF_BUS_RESET       		0x08	/* bus reset */
#define PROTO_FCP_TMF_LUN_RESET       		0x10	/* LUN reset */
#define PROTO_FCP_TMF_TGT_RESET       		0x20	/* Target reset */
#define PROTO_FCP_TMF_CLR_ACA         		0x40	/* clear ACA condition */
#define PROTO_FCP_TMF_TERM_TASK       		0x80	/* Terminate task */

/*
 * flags.
 * Bits 7:2 are the additional FCP_CDB length / 4.
 */
#define PROTO_FCP_CFL_LEN_MASK        		0xfc /* mask for adnl length */
#define PROTO_FCP_CFL_LEN_SHIFT       		2    /* shift bits for adnl length */
#define PROTO_FCP_CFL_RDDATA          		0x02 /* read data */
#define PROTO_FCP_CFL_WRDATA          		0x01 /* write data */

struct proto_fcp_cmnd {
        uint8_t		lun[8];			/* logical unit number */
        uint8_t		cmdref;      		/* commmand reference number */
        uint8_t		pri_ta;			/* priority and task 
						 * attribute
						 */
	uint8_t		tm_flags;		/* task management flags */
	uint8_t		flags;			/* additional len & flags */
	uint8_t		cdb[16];		/* CDB */
	uint32_t 	dl;			/* data length */
} __attribute__((packed));

/* Response Flags */
#define PROTO_FCP_BIDI_RSP		0x80		/* bidirectional read rsp */
#define PROTO_FCP_BIDI_READ_UNDER 	0x40		/* bidi read underrun */
#define PROTO_FCP_BIDI_READ_OVER  	0x20		/* bidi read overrun */
#define PROTO_FCP_CONF_REQ		0x10		/* confirmation requested */
#define PROTO_FCP_RESID_UNDER		0x08		/* transfer shorter than
							 * expected
							 */
#define PROTO_FCP_RESID_OVER		0x04		/* DL insufficient for 
							 * full transfer
							 */
#define PROTO_FCP_SNS_LEN_VAL		0x02		/* SNS_LEN field is valid */
#define PROTO_FCP_RSP_LEN_VAL		0x01		/* RSP_LEN field is valid */

/* Response codes */
#define PROTO_FCP_TMF_CMPL		0x00
#define PROTO_FCP_DATA_LEN_INVALID	0x01
#define PROTO_FCP_CMND_FIELDS_INVALID 	0x02
#define PROTO_FCP_DATA_PARAM_MISMATCH	0x03
#define PROTO_FCP_TMF_REJECTED		0x04
#define PROTO_FCP_TMF_FAILED		0x05
#define PROTO_FCP_TMF_INVALID_LUN	0x06

/* default timeout values */
#define PROTO_DEF_E_D_TOV  2000UL
#define PROTO_DEF_R_A_TOV  10000UL

struct proto_fcp_resp {
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
} __attribute__((packed));

struct proto_fcp_tmresp {
	uint8_t		rsvd0[8];
	uint16_t	retry_delay;		/* retry delay timer */
	uint8_t		flags;			/* flags */
	uint8_t         scsi_status;		/* SCSI status code */
	uint32_t	resid;			/* Residual bytes */
	uint32_t	sns_len;		/* Length of sense data */
	uint32_t	rsp_len;		/* Length of response */
	uint8_t		rsvd1[3];
	uint8_t		rsp_code;		/* Response code */
	uint8_t		rsvd2[4];
} __attribute__((packed));

struct proto_fcp_xfer_rdy {
	uint32_t	data_ro;		/* relative offset */
	uint32_t	burst_len;		/* burst length */
	uint8_t		rsvd[4];
} __attribute__((packed));

                                
/*                      
 * Service parameter page parameters (word 3 bits) for Process Login.
 */
#define PROTO_FCP_SPPF_TASK_RETRY_ID  0x0200  /* task retry ID requested */
#define PROTO_FCP_SPPF_RETRY          0x0100  /* retry supported */
#define PROTO_FCP_SPPF_CONF_COMPL     0x0080  /* confirmed completion allowed */
#define PROTO_FCP_SPPF_OVLY_ALLOW     0x0040  /* data overlay allowed */
#define PROTO_FCP_SPPF_INIT_FCN       0x0020  /* initiator function */
#define PROTO_FCP_SPPF_TARG_FCN       0x0010  /* target function */
#define PROTO_FCP_SPPF_RD_XRDY_DIS    0x0002  /* disable XFER_RDY for reads */
#define PROTO_FCP_SPPF_WR_XRDY_DIS    0x0001  /* disable XFER_RDY for writes */

/*
 * Feature bits in name server FC-4 Features object.
 */
#define PROTO_FCP_FEAT_TARG   (1 << 0)        /* target function supported */
#define PROTO_FCP_FEAT_INIT   (1 << 1)        /* initiator function supported */

/*              
 * spp_flags.   
 */             
#define PROTO_FC_SPP_OPA_VAL      0x80        /* originator proc. assoc. valid */
#define PROTO_FC_SPP_RPA_VAL      0x40        /* responder proc. assoc. valid */
#define PROTO_FC_SPP_EST_IMG_PAIR 0x20        /* establish image pair */
#define PROTO_FC_SPP_RESP_MASK    0x0f        /* mask for response code (below) */
                                
/*                      
 * SPP response code in spp_flags - lower 4 bits.
 */                             
enum proto_fc_els_prli_resp {          
	PROTO_FC_SPP_RESP_ACK =       1,      /* request executed */
	PROTO_FC_SPP_RESP_RES =       2,      /* unable due to lack of resources */
	PROTO_FC_SPP_RESP_INIT =      3,      /* initialization not complete */
	PROTO_FC_SPP_RESP_NO_PA =     4,      /* unknown process associator */
	PROTO_FC_SPP_RESP_CONF =      5,      /* configuration precludes image pair */
	PROTO_FC_SPP_RESP_COND =      6,      /* request completed conditionally */
	PROTO_FC_SPP_RESP_MULT =      7,      /* unable to handle multiple SPPs */
	PROTO_FC_SPP_RESP_INVL =      8,      /* SPP is invalid */
};              

enum proto_els_scr_func {
	PROTO_SCRF_FAB =  1,      /* fabric-detected registration */
	PROTO_SCRF_NPORT = 2,     /* Nx_Port-detected registration */
	PROTO_SCRF_FULL = 3,      /* full registration */
	PROTO_SCRF_CLEAR = 255,   /* remove any current registrations */
};

enum fc_els_rscn_ev_qual {
	PROTO_RSCN_EV_QUAL_NONE = 0,           /* unspecified */
	PROTO_RSCN_EV_QUAL_NS_OBJ = 1,         /* changed name server object */
	PROTO_RSCN_EV_QUAL_PORT_ATTR = 2,      /* changed port attribute */
	PROTO_RSCN_EV_QUAL_SERV_OBJ = 3,       /* changed service object */
	PROTO_RSCN_EV_QUAL_SW_CONFIG = 4,      /* changed switch configuration */
	PROTO_RSCN_EV_QUAL_REM_OBJ = 5,        /* removed object */
};

enum proto_els_rscn_addr_fmt {
	PROTO_RSCN_ADDR_FMT_PORT = 0,  /* port_id is a port address */
	PROTO_RSCN_ADDR_FMT_AREA = 1,  /* port_id is a area address */
	PROTO_RSCN_ADDR_FMT_DOM = 2,   /* port_id is a domain address */
	PROTO_RSCN_ADDR_FMT_FAB = 3,   /* anything on fabric may have changed */
};

struct proto_rscn_priv {
	void *rnode;
	uint32_t port_id;
};	

#define CHFCOE_MAX_PROTO_RETRY	3
/* ELS request */
#define PROTO_ELS_DESC_SIZE    4
#define PAYLOAD_SZ(x) ((x) + PROTO_ELS_DESC_SIZE)
struct proto_fc_els_cmd {
        u8      op;     /* ELS command code*/
        u8      byte1;
        u8      byte2;
        u8      byte3;

        union {
                /*
                 * LS_ACC payload.
                 */
                struct proto_ls_acc {
                        u8      cmd;            /* command code ELS_LS_ACC */
                        u8      rsvd[3];        /* reserved */
                } proto_ls_acc;

                struct proto_ls_rjt {
                        u8      rsvd1;
                        u8      reason_code;    /* Reason code */
                        u8      reason_exp;     /* Explanation */
                        u8      vendor_unique;  /* Vendor unique code */
                } proto_ls_rjt;

                struct proto_ls_logi {
                        /* Service Parameters */
                        struct csio_service_parms sp;
                } proto_ls_logi;

                struct proto_logo {
                        u32 nport_id;   /* NPort Id */
                        u8       wwpn[8];       /* Port name */
                } proto_logo;

                struct proto_prli {
                        u8      type;           /* Type code */
                        u8      rsvd1;
                        u8      proc_flags;     /* Process Flags */
                        u8      rsvd2;

                        /* Originator Process Associator */
                        u32     ori_proc_assoc;

                        /* Responder Process Associator */
                        u32     rsp_proc_assoc;

                        /* Service parameter flags */
                        u32     serv_parms_flags;
                } proto_prli;

		struct proto_prlo {
                        u8       type;          /* Type code */
                        u8       rsvd1;
                        u8       proc_flags;    /* Process flags */
                        u8  rsvd2;

                        /* Originator Process Associator */
                        u32 ori_proc_assoc;

                        /* Responder Process Associator */
                        u32 rsp_proc_assoc;
                        u32 rsvd3;
                } proto_prlo;

                struct proto_adisc {
                        u32 hard_addr;  /* Hard address of originator */
                        u8       wwpn[8];       /* Port name */
                        u8       wwnn[8];       /* Node name */
                        u32 nport_id;   /* Nport id */
                } proto_adisc;

                /*
                 * ELS_RRQ - Reinstate Recovery Qualifier
                 */
                struct proto_rrq {
                        u8      rrq_resvd;      /* reserved */
                        u8      rrq_s_id[3];    /* originator FID */
                        u16     rrq_ox_id;      /* originator exchange ID */
                        u16     rrq_rx_id;      /* responders exchange ID */
                } proto_rrq;

                struct proto_scr {
                        u8      rsvd[3];
                        u8      func;           /* SCR Function */
                } proto_scr;

                struct proto_rscn {
			uint8_t flag;
			uint8_t port_id[3];   /* Nport id list */
                } proto_rscn;

		/* LS_ACC resp - read timeout value. */
		/* timout qualifier bits. */
#define RTV_EDRES (1 << 26)      /* E_D_TOV resolution is nS else mS */
#define RTV_RTTOV (1 << 19)      /* R_T_TOV is 100 uS else 100 mS */
		struct proto_rtv_resp{
			uint32_t	r_a_tov;    /* resource allocation timeout value */
			uint32_t	e_d_tov;    /* error detection timeout value */
			uint32_t	toq;        /* timeout qualifier */
		} proto_rtv_resp;
        } un;
};

#define PROTO_NS_ID_LAST  	0x80            /* last object */
#define PROTO_CT_IU_PMBL_SIZE   16
#define PAYLOAD_CT_SZ(x) ((x) + PROTO_CT_IU_PMBL_SIZE)
struct fc_ct_cmd {
	u8      rev;            /* Revision */
	u8      in_id[3];       /* Unused */
	u8      gs_type;        /* Type of service */
	u8      gs_subtype;     /* Sub type */
	u8      opt;            /* Options */
	u8      rsvd1;
	u16     op;             /* Command or response code */
	u16     size;           /* Maximum or Residual size */
	u8      rsvd2;
	u8      reason_code;    /* Reason code */
	u8      explanation;    /* Explanation code */
	u8      vendor_unique;  /* Vendor specific reason code */

	union {
		u32 port_id;    /* Port_id list for GID_FT ACC */

		struct gpn_id {
			uint8_t	flag;       /* flags for responses only */
			uint8_t	port_id[3];
		} gpn_id;

		struct gpn_id_acc {
			uint8_t	wwpn[8];
		} gpn_id_acc;

		struct gid_ft {
			u8      port_type;      /* Port Type */
			u8      domain_scope;   /* Domain scope */
			u8      area_scope;     /* Area scope */
			u8      fc4_type;       /* FC4 Type = FCP(0x8) */
		} gid_ft;

		struct gpn_ft {
			u8      flag;
			u8      domain_scope;   /* Domain scope */
			u8      area_scope;     /* Area scope */
			u8      fc4_type;       /* FC4 Type = FCP(0x8) */
		} gpn_ft;

		/* Port_id & Port name list for GPN_FT ACC */
		struct gpn_ft_acc {
			uint8_t	flags;
			uint8_t	port_id[3];    /* port id */
			u32 	rsvd;
			u8	wwpn[8];       /* Port name */
		} gpn_ft_acc;

		struct rft_id {
			u32 port_id;    /* port id */
			u16 rsvd1;
			u8       fcp;           /* FCP Type */
			u8       rsvd2;
			u8       rsvd3[28];
		} rft_id;

		struct rnn_id {
			u32 port_id;    /* Port id */
			u8       wwnn[8];       /* Node name */
		} rnn_id;

		struct da_id {
			u32 port_id;    /* Port id */
		} da_id;

		struct rff_id {
			u32 port_id;    /* Port id */
			u8  rsvd1[2];
			u8  fc4_fbits;  /* FC4 feature bits */
			u8  fc4_type;   /* FC4 Type = FCP(0x8) */
		} rff_id;
	} un;
};

#endif /* __CHFCOE_FCOE_PROTO_H__ */
