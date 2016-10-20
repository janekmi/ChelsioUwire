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

#ifndef __CSIO_MB_HELPERS_H__
#define __CSIO_MB_HELPERS_H__

#include <t4fw_interface.h>

#define CSIO_STATS_OFFSET (2)
#define CSIO_NUM_STATS_PER_MB (6)

struct fw_fcoe_vnp_cmd_params {

	uint32_t 	fcfi;
	uint32_t 	vnpi;
	uint16_t	iqid;

	uint32_t 	vf_id;
	bool 		vfid_en;

	uint8_t  	vnport_mac[6];
	uint8_t  	vnport_wwnn[8];
	uint8_t  	vnport_wwpn[8];
	uint8_t  	cmn_srv_parms[16];
	uint8_t  	cls_srv_parms[8];
	uint8_t         idx;
	uint8_t         nstats;
};

struct fw_fcoe_ssn_cmd_params {

	uint32_t 	vnpi;
	uint16_t	iqid;

	uint32_t 	ssni;

	uint8_t 	d_mac[6];
	uint8_t		rport_wwnn[8];
	uint8_t		rport_wwpn[8];
	uint8_t		cmn_srv_parms[8];
	uint8_t		cls_srv_parms[16];
	uint8_t         idx;
	uint8_t         nstats;
};

struct fw_fcoe_port_cmd_params {
	uint8_t 	portid;
	uint8_t		idx;
	uint8_t		nstats;
};

struct fw_fcoe_fcf_cmd_params {

	uint8_t		priority;
	uint8_t		mac[6];
	uint8_t		name_id[8];
	uint8_t		fabric[8];
	uint16_t	vf_id;
	uint8_t		vlan_id;
	uint8_t		max_fcoe_size;
	uint8_t		idx;
	uint8_t		fc_map[3];
	uint32_t	fka_adv;
	uint32_t	fcfi;

	uint8_t		get_next:1;
	uint8_t		link_aff:1;
	uint8_t		fpma:1;
	uint8_t		spma:1;
	uint8_t		login:1;

	uint8_t   	portid;
	uint8_t 	nstats;
	uint8_t		r7;
	uint8_t		spma_mac[6];

};

struct fw_fcoe_stats_cmd_params {
        uint64_t tx_bytes;
        uint64_t tx_words;
        uint64_t tx_frames;
        uint64_t tx_acl_err;
        uint64_t tx_fip_acl_err;
        uint64_t rx_bytes;
        uint64_t rx_words;
        uint64_t rx_frames;
        uint64_t rx_mcast;
        uint64_t rx_ucast;
        uint64_t rx_mtu_err;
        uint64_t rx_mtu_crc_err;
        uint64_t rx_crc_err;
        uint64_t rx_len_err;
        uint64_t rx_acl_err;
        uint64_t rx_ddp_err;
        uint64_t rx_fip_acl_err;
};
struct csio_mb;

/* helper functions - one per MB cmd */

void csio_fcoe_read_res_info_init_mb(struct fw_fcoe_res_info_cmd *);

void csio_write_fcoe_link_cond_init_mb(struct fw_fcoe_link_cmd *,
			uint8_t, uint32_t, uint8_t, bool, uint32_t);

void csio_fcoe_vnp_alloc_init_mb(struct fw_fcoe_vnp_cmd *,
		uint32_t , uint32_t , uint16_t,	uint8_t [8], uint8_t [8]);

void csio_process_fcoe_vnp_alloc_mb_rsp(struct fw_fcoe_vnp_cmd *,
		struct fw_fcoe_vnp_cmd_params *);

void csio_fcoe_vnp_write_init_mb(struct fw_fcoe_vnp_cmd *,
			bool , uint32_t , uint32_t , uint16_t ,
			uint32_t, uint8_t [6], uint8_t [8], uint8_t [8],
			uint8_t [16], uint8_t [8]);

void csio_fcoe_vnp_alloc_and_write_init_mb(
		struct fw_fcoe_vnp_cmd *, uint32_t ,
		uint32_t , uint16_t, uint32_t , uint8_t [6],
		uint8_t [16], uint8_t [8]);

void csio_process_fcoe_vnp_alloc_and_write_mb_rsp(struct fw_fcoe_vnp_cmd *,
		struct fw_fcoe_vnp_cmd_params *);

void csio_fcoe_vnp_read_init_mb(struct fw_fcoe_vnp_cmd *, uint32_t, uint32_t);

void csio_fcoe_vnp_free_init_mb(struct fw_fcoe_vnp_cmd *, uint32_t , uint32_t);

void csio_fw_fcoe_read_fcf_init_mb( struct fw_fcoe_fcf_cmd *,
			uint32_t, uint32_t);

void csio_fcoe_get_stats_init_mb(struct csio_lnode *, struct csio_mb *, 
			uint32_t , 
			void (*) (struct csio_hw *, struct csio_mb *));

void csio_process_fcoe_get_stats_mb_rsp(struct csio_lnode *, struct csio_mb *,
			enum fw_retval *,  struct fw_fcoe_stats_cmd_params *);


void
csio_fcoe_read_portparams_init_mb(struct fw_fcoe_stats_cmd *,
			struct fw_fcoe_port_cmd_params *);
void
csio_mb_process_portparams_rsp(struct fw_fcoe_stats_cmd *,
		struct fw_fcoe_port_cmd_params *,
		struct fw_fcoe_port_stats *);
void 
csio_fcoe_read_ssnparams_init_mb(struct fw_fcoe_stats_cmd *,
		struct fw_fcoe_ssn_cmd_params *ssnparams);
void
csio_mb_process_ssnparams_rsp(struct fw_fcoe_stats_cmd *,
		struct fw_fcoe_ssn_cmd_params *ssnparams,
		struct fw_fcoe_scb_stats  *ssnstats);
void
csio_fcoe_read_vnpparams_init_mb(struct fw_fcoe_stats_cmd *,
		struct fw_fcoe_vnp_cmd_params *);
void
csio_mb_process_vnpparams_rsp(struct fw_fcoe_stats_cmd *,
		struct fw_fcoe_vnp_cmd_params *,
		struct fw_fcoe_pcb_stats *);
void 
csio_fcoe_read_fcfparams_init_mb(struct fw_fcoe_stats_cmd *,
		struct fw_fcoe_fcf_cmd_params *);
void
csio_mb_process_fcfparams_rsp(struct fw_fcoe_stats_cmd *, 
		struct fw_fcoe_fcf_cmd_params *fcfparams, 
		struct fw_fcoe_fcf_stats  *fcfstats); 

#endif /* ifndef __CSIO_MB_HELPERS_H__ */
