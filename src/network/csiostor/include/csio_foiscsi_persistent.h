/******************************************************************************
 *
 *  Copyright (C) 2008-2014 Chelsio Communications.  All rights reserved.
 *
 *   THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
 *   KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 *   IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
 *   PURPOSE.
 *
 * Module Name:
 *
 *    csio_iscsi_persistent.h
 *
 * Abstract:
 *
 *    csio_iscsi_persistent.h -
 *	contains the data-structures for the iscsi persistent info in the flash.
 *
 * Environment:
 *
 *    Kernel mode
 *
 * Revision History:
 *
 *	Vijay S - Creation.
 *
 *****************************************************************************/


#ifndef _CSIO_FOISCSI_PERSISTENT_H_
#define _CSIO_FOISCSI_PERSISTENT_H_
#include <csio_defs.h>
#include <csio_hw.h>
#include <csio_foiscsi_ioctl.h>

#define FOISCSI_PERSISTENT_SIGNATURE		0xC1
#define VALID_REC				0xAB
#define INVALID_REC				0xDE
#define MAX_ISCSI_PERSISTENT_TARGETS		64
#define MAX_T4_PORTS				4


/* Flash pointers */
#define SF_FOISCSI_SECTOR_NO	29
#define FOISCSI_DB_START	(SF_FOISCSI_SECTOR_NO * SF_SEC_SIZE)

struct ipaddr {
	uint8_t  ipv6_address[16];
	uint32_t ipv4_address;
};/* 20 bytes */

struct iscsi_portal {
	struct ipaddr		taddr;
	uint16_t         	tcpport;
	uint8_t			rsvd[2]; /* unused */
}; /* 24 bytes */

struct iscsi_attr {
	uint32_t		sess_type_to_erl;
	uint16_t		max_conn;
	uint16_t		max_r2t;
	uint16_t		time2wait;
	uint16_t		time2retain;
	uint32_t		max_burst;
	uint32_t		first_burst;
	uint32_t		max_rcv_dsl;
	uint16_t		ping_tmo;
	uint16_t		login_retry_count;
	uint32_t		hdigest_to_ddp_pgsz;
	uint16_t		recovery_tmo;
	uint16_t		rsvd[1]; /* unused */
};/* 36 bytes */

/* Persistent Target record */
struct iscsi_persistent_target {
	uint16_t			node_id; 			
	uint16_t			targ_offset_id; /* Used by ESXi */	
	uint8_t              		targname[FW_FOISCSI_NAME_MAX_LEN];	
	uint8_t				tgt_id[FW_FOISCSI_NAME_MAX_LEN];	
	uint8_t				tgt_sec[FW_FOISCSI_CHAP_SEC_MAX_LEN+1];
	uint8_t				valid;
	uint8_t				rsvd[2]; /* unused */
	struct iscsi_portal		portal;		
	struct iscsi_attr		attr;
	union {
	 	uint32_t			saddr;
		uint32_t			saddr6[4];
	};
	uint32_t			flag;
}; /* 652 bytes */  

struct static_ip {
	struct ipaddr	ipaddr;
	struct ipaddr   netmask;
	struct ipaddr   gateway;
	struct ipaddr	bcaddr;
	uint16_t	mtu;
	uint16_t	vlan;
}; /* 84 bytes*/

struct net_info {
	uint8_t			valid;
	uint8_t			if_id;
	uint8_t                 dhcp_en;
	uint8_t                 rsvd[1]; /* unused */
	uint32_t		flag;
	struct static_ip	sip;
};/* 92 bytes */

struct iscsi_node {
	uint8_t			valid;
	uint8_t                 name[FW_FOISCSI_NAME_MAX_LEN];	
	uint8_t                 alias[FW_FOISCSI_ALIAS_MAX_LEN];
	uint8_t			id;
	uint8_t			chap_id[FW_FOISCSI_NAME_MAX_LEN]; 
	uint8_t			chap_sec[FW_FOISCSI_CHAP_SEC_MAX_LEN+1]; 
	uint8_t                 rsvd[1]; /* unused */
	struct iscsi_attr       node_attr;
};/* 840 bytes*/

/* initiator global info - to be stored in the registry/file */
struct iscsi_initiator {
	struct net_info	    	net[MAX_T4_PORTS];
	struct iscsi_node	node[FW_FOISCSI_INIT_NODE_MAX];
};/* 7088 bytes*/

struct iscsi_persistent_target_db {
	uint8_t			signature;
	uint8_t			num_persistent_targets;
	uint8_t			num_valid_targets;
	uint8_t			rsvd[1]; /* unused */

	/* initiator global info- 7088 bytes */
	struct iscsi_initiator	initiator; 
	
	/* persistent targets 652 x 64 = 41728 bytes */
	struct iscsi_persistent_target	target[MAX_ISCSI_PERSISTENT_TARGETS];

	/* total 48820 bytes occupied in this sector..
	 * 16716 more bytes available.
	 */
};

#endif	/*_CSIO_FOISCSI_PERSISTENT_H_*/
