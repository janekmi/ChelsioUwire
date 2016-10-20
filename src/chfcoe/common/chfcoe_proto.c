/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/*
 * Authors:
 * 	Deepti Vadde <deepti@chelsio.com>
 */

#ifndef __LITTLE_ENDIAN_BITFIELD
#define __LITTLE_ENDIAN_BITFIELD
#endif

#include "chfcoe_defs.h"
#include <t4_msg.h>
#include <t4fw_interface.h>
#include "chfcoe_proto.h"


chfcoe_fc_buffer_t *chfcoe_fc_ctrl_alloc(size_t payload_len)
{
        chfcoe_fc_buffer_t *fb;

        fb = chfcoe_fcb_alloc_atomic(payload_len);
        if (!fb)
                return NULL;

        chfcoe_fcb_put(fb, payload_len);

        chfcoe_memset(chfcoe_fcb_cb(fb), 0, sizeof(struct chfcoe_skb_cb));
	chfcoe_fc_txq(fb) = chfcoe_smp_id();	
	
        chfcoe_memset((char *) chfcoe_fc_hdr(fb), 0, payload_len);

        return fb;
}

chfcoe_fc_buffer_t *chfcoe_fc_buffer_alloc(size_t payload_len, int atomic)
{
	chfcoe_fc_buffer_t *fb;
	size_t fill, len = 0, total, sgl = 0;

	fill = payload_len % 4;
	if (fill != 0)
		fill = 4 - fill;

	/* pad with 4 for dsgl alignment */
	if (!payload_len) {
		sgl = sizeof (struct ulptx_sgl) +
			sizeof (struct ulptx_idata) + 4;
		fill = 4;
	}

	len = sizeof(struct proto_fc_fr_hdr) + payload_len;
	total = len + sizeof (struct cpl_tx_pkt_xt) +
		sizeof(struct proto_ethhdr_novlan) +
		sizeof(struct proto_fcoe_crc_eof) +
		sizeof(struct proto_fcoe_hdr) + sgl + fill;
	
	if (chfcoe_likely(atomic == CHFCOE_ATOMIC))
		fb = chfcoe_fcb_alloc_atomic(total);
	else
		fb = chfcoe_fcb_alloc(total);

	if (!fb)
		return NULL;

	chfcoe_memset(chfcoe_fcb_cb(fb), 0, sizeof(struct chfcoe_skb_cb));
	chfcoe_fc_txq(fb) = chfcoe_smp_id();	
	chfcoe_fcb_reserve(fb, sizeof (struct cpl_tx_pkt_xt) + 
			sizeof(struct proto_ethhdr_novlan) +
			sizeof(struct proto_fcoe_hdr));
	chfcoe_fcb_put(fb, len);
	chfcoe_memset((char *) chfcoe_fc_hdr(fb), 0, len);
	/* trim is OK, we just allocated it so there are no fragments */
	chfcoe_fcb_trim(fb, len); 

	return fb;
}

const size_t mclen1 = sizeof(struct ulp_txpkt) + sizeof(struct ulptx_idata) + 
	sizeof(struct cpl_tx_pkt_core)+ sizeof(struct proto_ethhdr_novlan) +
	sizeof(struct proto_fcoe_hdr) + sizeof(fc_header_t)+ 4 +
	sizeof(struct ulptx_sgl) + sizeof(struct ulptx_idata) + sizeof(struct proto_fcoe_crc_eof);

const size_t mclen2 = sizeof(struct ulp_txpkt) + sizeof(struct ulptx_idata) +
	sizeof(struct cpl_tx_pkt_core)+ sizeof(struct proto_ethhdr_novlan) +
	sizeof(struct proto_fcoe_hdr) + sizeof(fc_header_t) +
	24 + sizeof(struct proto_fcoe_crc_eof);

const size_t fc_hdr_off = sizeof(struct ulp_txpkt) + sizeof(struct ulptx_idata) +
	sizeof(struct cpl_tx_pkt_core) + sizeof(struct proto_ethhdr_novlan) +
	sizeof(struct proto_fcoe_hdr);

chfcoe_fc_buffer_t *chfcoe_fc_buffer_alloc_pkts(const uint16_t *fill_bytes, fc_header_t **fc_hdr,
		uint16_t sense_buffer_len)
{
	chfcoe_fc_buffer_t *fb = NULL;
	size_t len = 0, data_len16 = 0, rsp_len16 = 0;

	data_len16 = CHFCOE_DIV_ROUND_UP(mclen1 + fill_bytes[0], 16);
	rsp_len16 = CHFCOE_DIV_ROUND_UP(mclen2 + sense_buffer_len + fill_bytes[1], 16);

	len = CHFCOE_DIV_ROUND_UP(sizeof(struct fw_eth_tx_pkts_wr) + (data_len16 * 16) + (rsp_len16 * 16), 16);
	len *= 16;

	fb = chfcoe_fcb_alloc_atomic(len);
	if (chfcoe_unlikely(!fb)) {
		chfcoe_err(ln, "Failed to alloc fc buffer\n");
		for (;;) {
			fb = chfcoe_fcb_alloc(len);
			if (!fb)
				chfcoe_schedule();
			else {
				break;
			}
		}
	}

	chfcoe_fcb_put(fb, len);
	chfcoe_memset(chfcoe_fcb_cb(fb), 0, sizeof(struct chfcoe_skb_cb));
	chfcoe_memset(chfcoe_skb_data(fb), 0, len);

	fc_hdr[0] = (fc_header_t *)(((unsigned char *)(chfcoe_skb_data(fb))) + sizeof(struct fw_eth_tx_pkts_wr) +
			fc_hdr_off);

	fc_hdr[1] = (fc_header_t *)(((unsigned char *) (chfcoe_skb_data(fb))) + sizeof(struct fw_eth_tx_pkts_wr) + 
			(data_len16 * 16) + fc_hdr_off);

	return fb;
}

/* 
 * chfcoe_fip_buffer_alloc - Alloc the frame buffer for fip frames
 */
chfcoe_fc_buffer_t * chfcoe_fip_buffer_alloc(size_t payload_len)
{
	chfcoe_fc_buffer_t *fb;
	size_t fill, len = 0;

	payload_len += sizeof(struct cpl_tx_pkt_xt);

	fill = payload_len % 4;
	if (fill != 0)
		fill = 4 - fill;
	len = payload_len + fill;
	fb = chfcoe_fcb_alloc_atomic(len);
	if (!fb) {
		fb = chfcoe_fcb_alloc(len);
		if (!fb) {
			return NULL;
		}
	}
	chfcoe_memset(chfcoe_fcb_cb(fb), 0, sizeof(struct chfcoe_skb_cb));
	chfcoe_fc_txq(fb) = chfcoe_smp_id();	
	chfcoe_fcb_put(fb, len);
	if (fb) {
		chfcoe_memset((char *) chfcoe_fc_hdr(fb) + payload_len, 0, fill);
		/* trim is OK, we just allocated it so there are no fragments */
		chfcoe_fcb_trim(fb, payload_len); 
	}
	return fb;
}

/* 
 * chfcoe_fip_els_buffer_alloc - Alloc the frame buffer for fip frames
 */
chfcoe_fc_buffer_t *chfcoe_fip_els_buffer_alloc(size_t payload_len)
{
	chfcoe_fc_buffer_t *fb;
	size_t fill, len = 0;

	fill = payload_len % 4;
	if (fill != 0)
		fill = 4 - fill;
	payload_len += sizeof(struct proto_fc_fr_hdr);
	len = payload_len + sizeof(struct cpl_tx_pkt_xt) + 
		CHFCOE_OFFSETOF(struct proto_fip_virt_ln_req, 
		desc.logi.fc_els_pld[0]) + 
		sizeof(struct proto_fip_mac_desc) +
		fill;
	fb = chfcoe_fcb_alloc_atomic(len);
	if (!fb) {
		fb = chfcoe_fcb_alloc(len);
		if (!fb) {
			return NULL;
		}
	}
	chfcoe_memset(chfcoe_fcb_cb(fb), 0, sizeof(struct chfcoe_skb_cb));
	chfcoe_fc_txq(fb) = chfcoe_smp_id();	
	chfcoe_fcb_reserve(fb, (sizeof(struct cpl_tx_pkt_xt) + 
			CHFCOE_OFFSETOF(struct proto_fip_virt_ln_req,
			desc.logi.fc_hdr)));
	chfcoe_fcb_put(fb, payload_len);
	if (fb) {
		chfcoe_memset((char *) chfcoe_fc_hdr(fb) + payload_len, 0, fill);
		/* trim is OK, we just allocated it so there are no fragments */
		chfcoe_fcb_trim(fb, payload_len); 
	}
	return fb;
}
