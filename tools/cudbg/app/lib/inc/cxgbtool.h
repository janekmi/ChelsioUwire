/*
 * This file is part of the Chelsio NIC management interface.
 *
 * Copyright (C) 2003-2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */
#ifndef __CXGBTOOL_H__
#define __CXGBTOOL_H__

#define SIOCCHIOCTL SIOCDEVPRIVATE

enum {
	CHELSIO_SETREG			= 1024,
	CHELSIO_GETREG			= 1025,
	CHELSIO_SETTPI                  = 1026,
	CHELSIO_GETTPI                  = 1027,
	CHELSIO_DEVUP			= 1028,
	CHELSIO_GETMTUTAB		= 1029,
	CHELSIO_SETMTUTAB		= 1030,
	CHELSIO_GETMTU			= 1031,
	CHELSIO_SET_PM			= 1032,
	CHELSIO_GET_PM			= 1033,
	CHELSIO_SET_TCAM		= 1035,
	CHELSIO_GET_TCB			= 1036,
	CHELSIO_READ_TCAM_WORD		= 1037,
	CHELSIO_GET_MEM			= 1038,
	CHELSIO_GET_SGE_CONTEXT		= 1039,
	CHELSIO_GET_SGE_DESC		= 1040,
	CHELSIO_LOAD_FW			= 1041,
	CHELSIO_SET_TRACE_FILTER        = 1044,
	CHELSIO_SET_QSET_PARAMS		= 1045,
	CHELSIO_GET_QSET_PARAMS		= 1046,
	CHELSIO_SET_QSET_NUM		= 1047,
	CHELSIO_GET_QSET_NUM		= 1048,
	CHELSIO_SET_PKTSCHED		= 1049,
	CHELSIO_SET_HW_SCHED		= 1051,
	CHELSIO_LOAD_BOOT		= 1054,
	CHELSIO_CLEAR_STATS             = 1055,
	CHELSIO_GET_UP_LA		= 1056,
	CHELSIO_GET_UP_IOQS		= 1057,
	CHELSIO_GET_TRACE_FILTER	= 1058,
	CHELSIO_GET_SGE_CTXT            = 1059,
	CHELSIO_GET_SGE_DESC2		= 1060,

	CHELSIO_SET_OFLD_POLICY         = 1062,

	CHELSIO_SET_FILTER		= 1063,
	CHELSIO_DEL_FILTER		= 1064,
	CHELSIO_GET_PKTSCHED            = 1065,
	CHELSIO_LOAD_CFG                = 1066,
	CHELSIO_REG_DUMP		= 1067,
	CHELSIO_GET_FILTER_COUNT	= 1068,
	CHELSIO_GET_BYPASS_PORTS	= 1069,
	CHELSIO_SET_SCHED_CLASS		= 1070,
	CHELSIO_LOAD_PHY_FW		= 1071,
	CHELSIO_SET_SCHED_QUEUE		= 1072,

	CHELSIO_GET_FILTER		= 1073,
#ifdef CHELSIO_T4_DIAGS
	CHELSIO_CLEAR_FLASH		= 1080,
#endif
	CHELSIO_LOAD_BOOTCFG		= 1081,

	CHELSIO_GET_I2C_DATA		= 1082,
	CHELSIO_SET_I2C_DATA		= 1083,

	CHELSIO_SET_SCHED_PFVF		= 1084,

	CHELSIO_SET_QUEUE_INTR_PARAMS	= 1085,
	CHELSIO_GET_QUEUE_INTR_PARAMS	= 1086,

	CHELSIO_GET_QTYPE_NUM	= 1087,
	CHELSIO_SET_QTYPE_NUM	= 1088,

#if 0 /* Unsupported */
	CHELSIO_SETTPI			= 1026,
	CHELSIO_GETTPI			= 1027,
	CHELSIO_GET_TCAM		= 1034,
	CHELSIO_GET_PROTO		= 1042,
	CHELSIO_SET_PROTO		= 1043,
#endif
};

/* statistics categories */
enum {
	STATS_PORT  = 1 << 1,
	STATS_QUEUE = 1 << 2,
};

/* queue types for "qdesc" command */
enum {
	SGE_QTYPE_TX_ETH = 1,
	SGE_QTYPE_TX_OFLD,
	SGE_QTYPE_TX_CTRL,
	SGE_QTYPE_FL,
	SGE_QTYPE_RSP,
};

struct ch_reg {
	uint32_t cmd;
	uint32_t addr;
	uint32_t val;
};

struct ch_qtype_num {
	uint32_t cmd;
	uint32_t qtype;
	uint32_t val;
};

enum ch_qtype {
	QTYPE_ETH,
	QTYPE_OFLD,
	QTYPE_RDMA,
	QTYPE_RCIQ,
	QTYPE_ISCSI,
	QTYPE_MAX
};

struct ch_cntxt {
	uint32_t cmd;
	uint32_t cntxt_type;
	uint32_t cntxt_id;
	uint32_t data[4];
};

/* context types */
enum {
	CNTXT_TYPE_EGRESS,
	CNTXT_TYPE_FL,
	CNTXT_TYPE_RSP,
	CNTXT_TYPE_CQ,
	CNTXT_TYPE_CONG
};

struct ch_desc {
	uint32_t cmd;
	uint32_t queue_num;
	uint32_t idx;
	uint32_t size;
	uint8_t  data[128];
};

struct ch_i2c_data {
	uint32_t cmd;
	uint32_t port;
	uint32_t devid;
	uint32_t offset;
	uint32_t len;
	uint8_t data[0];
};

struct ch_mem_range {
	uint32_t cmd;
	uint32_t mem_id;
	uint32_t addr;
	uint32_t len;
	uint32_t version;
	uint8_t  buf[0];
};

struct struct_load_cfg {
	uint32_t cmd;
	uint32_t len;
	uint8_t  buf[0];
};

/* ch_mem_range.mem_id values */
enum {
	MEM_CM,
	MEM_PMRX,
	MEM_PMTX,
	MEM_FLASH
};

struct ch_qset_params {
	uint32_t cmd;
	uint32_t qset_idx;
	int32_t  txq_size[3];
	int32_t  rspq_size;
	int32_t  fl_size[2];
	int32_t  intr_lat;
	int32_t  polling;
	int32_t  lro;
	int32_t  cong_thres;
	int32_t  vector;
	int32_t  qnum;
};

/*
 * Data structure to support CHELSIO_SET_QUEUE_INTR_PARAMS and
 * CHELSIO_GET_QUEUE_INTR_PARAMS commands to set/get Response Queue Interrupt
 * Coalescing parameters.
 */
struct ch_queue_intr_params {
	uint32_t cmd;
	uint32_t qid;			/* Response Queue ID */
	int32_t timer;			/* holdoff threshold timer (us) */
	int32_t count;			/* threshold override packet count */
};

struct ch_pktsched_params {
	uint32_t cmd;
	uint8_t  sched;
	uint8_t  idx;
	uint8_t  min;
	uint8_t  max;
	uint8_t  binding;
};

enum {
	PKTSCHED_PORT = 0,
	PKTSCHED_TUNNELQ = 1,
};

enum {
	PKTSCHED_MODE_CLASS = 0,
	PKTSCHED_MODE_FLOW = 1,
};

enum {
	PKTSCHED_UNIT_BIT = 0,
	PKTSCHED_UNIT_PKTSIZE = 1,
};

struct ch_hw_sched {
	uint32_t cmd;
	uint8_t  sched;
	int8_t   mode;
	int8_t   channel;
	int8_t   weight;
	int32_t  kbps;
	int32_t  class_ipg;
	int32_t  flow_ipg;
};

/*
 * Support for "sched-class" command to allow a TX Scheduling Class to be
 * programmed with various parameters.
 */
struct ch_sched_params {
	uint32_t cmd;			/* CHELSIO_SET_SCHED_CLASS */
	int8_t   subcmd;		/* sub-command */
	int8_t   type;			/* packet or flow */
	union {
	    struct {			/* sub-command SCHED_CLASS_CONFIG */
		int8_t   minmax;	/* minmax enable */
	    } config;
	    struct {			/* sub-command SCHED_CLASS_PARAMS */
		int8_t   level;		/* scheduler hierarchy level */
		int8_t   mode;		/* per-class or per-flow */
		int8_t   rateunit;	/* bit or packet rate */
		int8_t   ratemode;	/* %port relative or kbps absolute */
		int8_t   channel;	/* scheduler channel [0..N] */
		int8_t   class;		/* scheduler class [0..N] */
		int32_t  minrate;	/* minimum rate */
		int32_t  maxrate;	/* maximum rate */
		int16_t  weight;	/* percent weight */
		int16_t  pktsize;	/* average packet size */
	    } params;
	    uint8_t     reserved[6 + 8*8];
	} u;
};

enum {
	SCHED_CLASS_SUBCMD_CONFIG,	/* config sub-command */
	SCHED_CLASS_SUBCMD_PARAMS,	/* params sub-command */
};

enum {
	SCHED_CLASS_TYPE_PACKET,
	SCHED_CLASS_TYPE_STREAM,
};

enum {
	SCHED_CLASS_LEVEL_CL_RL,	/* class rate limiter */
	SCHED_CLASS_LEVEL_CL_WRR,	/* class weighted round robin */
	SCHED_CLASS_LEVEL_CH_RL,	/* channel rate limiter */
	SCHED_CLASS_LEVEL_CH_WRR,	/* channel weighted round robin */
};

enum {
	SCHED_CLASS_MODE_CLASS,		/* per-class scheduling */
	SCHED_CLASS_MODE_FLOW,		/* per-flow scheduling */
};

enum {
	SCHED_CLASS_RATEUNIT_BITS,	/* bit rate scheduling */
	SCHED_CLASS_RATEUNIT_PKTS,	/* packet rate scheduling */
};

enum {
	SCHED_CLASS_RATEMODE_REL,	/* percent of port bandwidth */
	SCHED_CLASS_RATEMODE_ABS,	/* Kb/s */
};

/*
 * Support for "sched_queue" command to allow one or more NIC TX Queues
 * to be bound to a TX Scheduling Class.
 */
struct ch_sched_queue {
	uint32_t cmd;			/* CHELSIO_SET_SCHED_QUEUE */
	int8_t   queue;			/* queue index; -1 => all queues */
	int8_t   class;			/* class index; -1 => unbind */
};

/*
 * Support for "sched_pfvf" command to allow a PF/VF to be bound to a
 * TX Scheduling Class.
 */
struct ch_sched_pfvf {
	uint32_t cmd;			/* CHELSIO_SET_SCHED_PFVF */
	uint8_t  pf;			/* PF */
	uint8_t  vf;			/* VF; 0 => PF, 1..N => VF */
	int8_t   class;			/* class index; -1 => unbind */
};

/*
 * Defined bit width of user definable filter tuples
 */
#define ETHTYPE_BITWIDTH 16
#define FRAG_BITWIDTH 1
#define MACIDX_BITWIDTH 9
#define FCOE_BITWIDTH 1
#define IPORT_BITWIDTH 3
#define MATCHTYPE_BITWIDTH 3
#define PROTO_BITWIDTH 8
#define TOS_BITWIDTH 8
#define PF_BITWIDTH 8
#define VF_BITWIDTH 8
#define IVLAN_BITWIDTH 16
#define OVLAN_BITWIDTH 16

/*
 * Filter matching rules.  These consist of a set of ingress packet field
 * (value, mask) tuples.  The associated ingress packet field matches the
 * tuple when ((field & mask) == value).  (Thus a wildcard "don't care" field
 * rule can be constructed by specifying a tuple of (0, 0).)  A filter rule
 * matches an ingress packet when all of the individual individual field
 * matching rules are true.
 *
 * Partial field masks are always valid, however, while it may be easy to
 * understand their meanings for some fields (e.g. IP address to match a
 * subnet), for others making sensible partial masks is less intuitive (e.g.
 * MPS match type) ...
 *
 * Most of the following data structures are modeled on T4 capabilities.
 * Drivers for earlier chips use the subsets which make sense for those chips.
 * We really need to come up with a hardware-independent mechanism to
 * represent hardware filter capabilities ...
 */
struct ch_filter_tuple {
	/*
	 * Compressed header matching field rules.  The TP_VLAN_PRI_MAP
	 * register selects which of these fields will participate in the
	 * filter match rules -- up to a maximum of 36 bits.  Because
	 * TP_VLAN_PRI_MAP is a global register, all filters must use the same
	 * set of fields.
	 */
	uint32_t ethtype:ETHTYPE_BITWIDTH;	/* Ethernet type */
	uint32_t frag:FRAG_BITWIDTH;		/* IP fragmentation header */
	uint32_t ivlan_vld:1;			/* inner VLAN valid */
	uint32_t ovlan_vld:1;			/* outer VLAN valid */
	uint32_t pfvf_vld:1;			/* PF/VF valid */
	uint32_t macidx:MACIDX_BITWIDTH;	/* exact match MAC index */
	uint32_t fcoe:FCOE_BITWIDTH;		/* FCoE packet */
	uint32_t iport:IPORT_BITWIDTH;		/* ingress port */
	uint32_t matchtype:MATCHTYPE_BITWIDTH;	/* MPS match type */
	uint32_t proto:PROTO_BITWIDTH;		/* protocol type */
	uint32_t tos:TOS_BITWIDTH;		/* TOS/Traffic Type */
	uint32_t pf:PF_BITWIDTH;		/* PCI-E PF ID */
	uint32_t vf:VF_BITWIDTH;		/* PCI-E VF ID */
	uint32_t ivlan:IVLAN_BITWIDTH;		/* inner VLAN */
	uint32_t ovlan:OVLAN_BITWIDTH;		/* outer VLAN */

	/*
	 * Uncompressed header matching field rules.  These are always
	 * available for field rules.
	 */
	uint8_t lip[16];	/* local IP address (IPv4 in [3:0]) */
	uint8_t fip[16];	/* foreign IP address (IPv4 in [3:0]) */
	uint16_t lport;		/* local port */
	uint16_t fport;		/* foreign port */

	/* reservations for future additions */
	uint8_t rsvd[12];
};

/*
 * A filter ioctl command.
 */
struct ch_filter_specification {
	/*
	 * Administrative fields for filter.
	 */
	uint32_t hitcnts:1;	/* count filter hits in TCB */
	uint32_t prio:1;	/* filter has priority over active/server */

	/*
	 * Fundamental filter typing.  This is the one element of filter
	 * matching that doesn't exist as a (value, mask) tuple.
	 */
	uint32_t type:1;	/* 0 => IPv4, 1 => IPv6 */
	uint32_t cap:1;		/* 0 => LE-TCAM, 1 => Hash */

	/*
	 * Packet dispatch information.  Ingress packets which match the
	 * filter rules will be dropped, passed to the host or switched back
	 * out as egress packets.
	 */
	uint32_t action:2;	/* drop, pass, switch */

	uint32_t rpttid:1;	/* report TID in RSS hash field */

	uint32_t dirsteer:1;	/* 0 => RSS, 1 => steer to iq */
	uint32_t iq:10;		/* ingress queue */

	uint32_t maskhash:1;	/* dirsteer=0: store RSS hash in TCB */
	uint32_t dirsteerhash:1;/* dirsteer=1: 0 => TCB contains RSS hash */
				/*             1 => TCB contains IQ ID */

	/*
	 * Switch proxy/rewrite fields.  An ingress packet which matches a
	 * filter with "switch" set will be looped back out as an egress
	 * packet -- potentially with some Ethernet header rewriting.
	 */
	uint32_t eport:2;	/* egress port to switch packet out */
	uint32_t newdmac:1;	/* rewrite destination MAC address */
	uint32_t newsmac:1;	/* rewrite source MAC address */
	uint32_t swapmac:1;     /* swap SMAC/DMAC for loopback packet */
	uint32_t newvlan:2;	/* rewrite VLAN Tag */
	uint32_t nat_mode:1;	/* specify NAT operation mode */
	uint32_t nat_seq_chk:1;	/* check sequence before NAT'ing */	
	uint32_t nat_flag_chk:1;/* check TCP flags before NAT'ing */
	uint8_t dmac[ETH_ALEN];	/* new destination MAC address */
	uint8_t smac[ETH_ALEN];	/* new source MAC address */
	uint16_t vlan;		/* VLAN Tag to insert */

	uint8_t nat_lip[16];	/* local IP to use after NAT'ing */
	uint8_t nat_fip[16];	/* foreign IP to use after NAT'ing */
	uint16_t nat_lport;	/* local port to use after NAT'ing */
	uint16_t nat_fport;	/* foreign port to use after NAT'ing */

	/* reservation for future additions */
	uint8_t rsvd[10];

	/*
	 * Filter rule value/mask pairs.
	 */
	struct ch_filter_tuple val;
	struct ch_filter_tuple mask;
};

#define CH_FILTER_SPECIFICATION_ID 0x1

enum {
	FILTER_PASS = 0,	/* default */
	FILTER_DROP,
	FILTER_SWITCH
};

enum {
	VLAN_NOCHANGE = 0,	/* default */
	VLAN_REMOVE,
	VLAN_INSERT,
	VLAN_REWRITE
};

enum {                         /* Ethernet address match types */
	UCAST_EXACT = 0,       /* exact unicast match */
	UCAST_HASH  = 1,       /* inexact (hashed) unicast match */
	MCAST_EXACT = 2,       /* exact multicast match */
	MCAST_HASH  = 3,       /* inexact (hashed) multicast match */
	PROMISC     = 4,       /* no match but port is promiscuous */
	HYPPROMISC  = 5,       /* port is hypervisor-promisuous + not bcast */
	BCAST       = 6,       /* broadcast packet */
};

enum {                         /* selection of Rx queue for accepted packets */
	DST_MODE_QUEUE,        /* queue is directly specified by filter */
	DST_MODE_RSS_QUEUE,    /* filter specifies RSS entry containing queue */
	DST_MODE_RSS,          /* queue selected by default RSS hash lookup */
	DST_MODE_FILT_RSS      /* queue selected by hashing in filter-specified
				  RSS subtable */
};

#if !defined(__LITTLE_ENDIAN_BITFIELD) && !defined(__BIG_ENDIAN_BITFIELD)
#include <asm/byteorder.h>
#endif

struct ch_filter {
	uint32_t cmd;		/* common "cxgbtool" command header */
#if defined(__LITTLE_ENDIAN_BITFIELD)
        uint32_t filter_id:28;  /* the filter index to set */
        uint32_t filter_ver:4;  /* filter spec version */
#else
        uint32_t filter_ver:4;  /* filter spec version */
        uint32_t filter_id:28;  /* the filter index to set */
#endif
	struct ch_filter_specification fs;
};

struct ch_filter_count {
	uint32_t cmd;		/* common "cxgbtool" command header */
	uint32_t filter_id;	/* the filter index to retrieve count */
	uint64_t pkt_count;	/* number of packets that matched filter */
};

#define	MAX_BA_IFS	8

struct ch_bypass_ports {
	uint32_t cmd;			/* common "cxgbtool" command header */
	char port_count;		/* number of ports on adapter */
	struct ba_if {
		char if_name[16];	/* port name, e.g. "eth0" */
	} ba_if[MAX_BA_IFS];
};

#define MAX_NMTUS 16

struct ch_mtus {
	uint32_t cmd;
	uint32_t nmtus;
	uint16_t mtus[MAX_NMTUS];
};

struct ch_pm {
	uint32_t cmd;
	uint32_t tx_pg_sz;
	uint32_t tx_num_pg;
	uint32_t rx_pg_sz;
	uint32_t rx_num_pg;
	uint32_t pm_total;
};

struct ch_tcam {
	uint32_t cmd;
	uint32_t tcam_size;
	uint32_t nservers;
	uint32_t nroutes;
	uint32_t nfilters;
};

#define TCB_SIZE 128
#define TCB_WORDS (TCB_SIZE / 4)

struct ch_tcb {
	uint32_t cmd;
	uint32_t tcb_index;
	uint32_t tcb_data[TCB_WORDS];
};

struct ch_tcam_word {
	uint32_t cmd;
	uint32_t addr;
	uint32_t buf[3];
};

struct ch_trace {
	uint32_t cmd;
	uint32_t sip;
	uint32_t sip_mask;
	uint32_t dip;
	uint32_t dip_mask;
	uint16_t sport;
	uint16_t sport_mask;
	uint16_t dport;
	uint16_t dport_mask;
	uint32_t vlan:12;
	uint32_t vlan_mask:12;
	uint32_t intf:4;
	uint32_t intf_mask:4;
	uint8_t  proto;
	uint8_t  proto_mask;
	uint8_t  invert_match:1;
	uint8_t  config_tx:1;
	uint8_t  config_rx:1;
	uint8_t  trace_tx:1;
	uint8_t  trace_rx:1;
};

struct ch_up_la {
	uint32_t cmd;
	uint32_t stopped;
	uint32_t idx;
	uint32_t bufsize;
	uint32_t la[0];
};

struct ioq_entry {
	uint32_t ioq_cp;
	uint32_t ioq_pp;
	uint32_t ioq_alen;
	uint32_t ioq_stats;
};

struct ch_up_ioqs {
	uint32_t cmd;

	uint32_t ioq_rx_enable;
	uint32_t ioq_tx_enable;
	uint32_t ioq_rx_status;
	uint32_t ioq_tx_status;

	uint32_t bufsize;
	struct ioq_entry ioqs[0];
};

#endif /* __CXGBTOOL_H__ */
