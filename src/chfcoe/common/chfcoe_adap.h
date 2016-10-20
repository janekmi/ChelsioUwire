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
 * 	This is chfcoe_adap.h header file, contains FCoE Ports related defines.
 */

#ifndef __CHFCOE_ADAP_H__
#define __CHFCOE_ADAP_H__

#include "chfcoe_defs.h"

enum fip_mode_type {
	CHFCOE_FCF,		/* FCF mode */
	CHFCOE_VN2VN,		/* VN2VN mode */
	CHFCOE_FIP_BOTH,	/* Both FCF and VN2VN Multipoint mode */
};

struct chfcoe_port_lld_info {
	void				*os_dev;	/* OS related Port
							 * Information.
							 * For Linux, its
							 * net_device.
							 */
	uint8_t				vi_id;		/* VI ID given
							 * by cxgb4 driver
							 */

	uint8_t				phy_mac[6];	/* physical MAC */
	int 				fcoe_nqsets;
};


struct chfcoe_lld_ops {
	chfcoe_retval_t (*set_mac_addr)(void *, u8 *mac, u16 *idx,
					bool clear);
	chfcoe_retval_t (*fcoe_enable)(void *, 
					bool enable);
	chfcoe_retval_t (*send_frame)(chfcoe_fc_buffer_t *,
			void *, uint8_t chan);
};

typedef struct chfcoe_adap_info {
	struct chfcoe_port_info 	*pi;		/* Port Info */
	struct chfcoe_lld_ops 		*lld_ops;	/* lower level driver
							   ops */
	uint8_t				nports;		/* # of ports */
	uint16_t			fw_evtq_cntxt_id;
	enum fip_mode_type		fip_mode;	/* Fip mode */
	void				*os_dev;	/* OS specific Adap */
	int                             ddp_thres;      /* DDP threshold */

	void				*lock;		/* lock */
	uint32_t			last_freed_ppod; /* Last freed ppod
							    index. */
	/* TCB related information */
	struct chfcoe_tid_to_xid	*tid2xid;	/* TID to XID table*/

	/* To Cache information from LLD (cxgb4) */
	const uint16_t			*mtus;		/* MTU table */
	const uint16_t			*txq_ids;	/* ULD's Tx Q ids */
	const uint16_t			*rxq_ids;	/* ULD's Rx Q ids */
	uint8_t				pf;		/* Physical fun  */

	struct tid_info			*tids;		/* TID table */ 
	uint64_t			ntids;		/* Total FCoE TIDs */

	uint32_t			ddp_llimit;	/* DDP start region */
	uint32_t			ddp_ulimit;	/* DDP end region */
	uint8_t				*ppod_map;	/* ppod mapping addr */
	uint32_t			nppods;		/* FCoE # of ppods */
	uint16_t			ntxq;		/* # of Tx queues */
	uint16_t			nrxq;		/* # of Rx queues */
	uint32_t                        toe_nppods;
#ifdef __CHFCOE_TRACE_SUPPORT__
	chfcoe_trace_buf_t		*trace_buffer;	/* Pointer to trace
							 * buffer
							 */
#endif
	uint8_t				log_level;	/* log level */
	uint16_t			rsvd1;		/* Reserved field */
	char				drv_version[32];/* Driver Version */
	uint16_t			devid;		/* device id */

	void (*queue_frame)(struct chfcoe_adap_info *, chfcoe_fc_buffer_t *,
			unsigned char *, unsigned int, uint8_t,
			uint16_t, uint32_t);
} chfcoe_adap_info_t;

#define chfcoe_adap_info_size		(sizeof(struct chfcoe_adap_info) + os_spinlock_size)

#endif /* __CHFCOE_ADAP_H__ */
