/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */


#ifndef __CHFCOE_LIB_H__
#define __CHFCOE_LIB_H__
#include <chfcoe_adap.h>

void *chfcoe_port_alloc(uint8_t);
void chfcoe_port_free(void *);
void chfcoe_port_exit(struct chfcoe_adap_info *, uint8_t);
int chfcoe_port_init(struct chfcoe_adap_info *,
		struct chfcoe_port_lld_info *, uint8_t);
void chfcoe_port_close(struct chfcoe_adap_info *);
void chfcoe_port_set_dcbprio(struct chfcoe_adap_info *,
		uint8_t, uint8_t);
void *chfcoe_port_get_osdev(struct chfcoe_adap_info *, uint8_t);
uint8_t chfcoe_port_get_linkstate(struct chfcoe_adap_info *, uint8_t);
void chfcoe_port_set_linkstate(struct chfcoe_adap_info *,
		uint8_t, uint8_t);

void chfcoe_flush_dtr_list(void);

void chfcoe_queue_fcb(struct chfcoe_adap_info *,
		chfcoe_fc_buffer_t *, unsigned char *,
		unsigned int, uint8_t,
		uint16_t, uint32_t);

int chfcoe_module_init(void);
void chfcoe_module_exit(void);
chfcoe_retval_t chfcoe_init(struct chfcoe_adap_info *);
void chfcoe_exit(struct chfcoe_adap_info *);
void chfcoe_flush_skb_queue(void);

void chfcoe_rmmod_port_lookup(struct chfcoe_adap_info *);

/* ddp */
int chfcoe_adap_ddp_init(struct chfcoe_adap_info *);
int chfcoe_ddp_disable(struct chfcoe_adap_info *);
int chfcoe_pofcoe_tcb_wr_handler(struct chfcoe_adap_info *, const uint64_t *);
int chfcoe_cplrx_fcoe_ddp_handler(struct chfcoe_adap_info *, const uint64_t *);
int chfcoe_cplrx_fcoe_hdr_handler(struct chfcoe_adap_info *, const uint64_t *);

/* ioctl */
chfcoe_retval_t chfcoe_fcoe_ioctl_handler(struct chfcoe_adap_info *, uint32_t,
	       	void *, uint32_t);
chfcoe_retval_t
chfcoe_adap_ioctl_handler(struct chfcoe_adap_info *,
			  uint32_t, void *, uint32_t);

int chfcoe_cpl_rx_handler(struct chfcoe_adap_info *, const uint64_t *);
#ifdef __CSIO_TARGET__
chfcoe_retval_t chfcoe_tgt_init(void);
void chfcoe_tgt_exit(void);
#endif
#endif
