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
 * 	This chfcoe_cpl_io.c file contains cpl core routines for IO.
 *
 * Authors:
 * 	Praveen M <praveenm@chelsio.com>
 */

#ifndef __LITTLE_ENDIAN_BITFIELD
#define __LITTLE_ENDIAN_BITFIELD
#endif

#include "chfcoe_defs.h"
#include "chfcoe_proto.h"
#include "chfcoe_adap.h"

#include <t4_msg.h>
#include <t4fw_interface.h>
#include <chfcoe_xchg.h>

#define FCOE_TXPKT_CSUM_START   28
#define FCOE_TXPKT_CSUM_END     8

extern const size_t mclen1;
extern const size_t mclen2;

int chfcoe_fip_xmit(struct chfcoe_lnode *lnode, struct chfcoe_rnode *rnode,
                chfcoe_fc_buffer_t *fr)
{
	struct chfcoe_adap_info *adap;
	struct chfcoe_port_info *pi;
	struct proto_fip_virt_ln_req *req;
	struct proto_fip_mac_desc *desc_mac;
	fc_header_t *hdr;
	hdr = (fc_header_t *)chfcoe_fc_hdr(fr);

	pi = lnode->pi;
	adap = pi->adap;

	req = (struct proto_fip_virt_ln_req *)chfcoe_fcb_push(fr,
                        (CHFCOE_OFFSETOF(struct proto_fip_virt_ln_req,
				desc.logi.fc_hdr))); 
        req->eth.et		= chfcoe_htons(ETH_P_PROTO_FIP);
	if (lnode->fip_type == CHFCOE_FCF)
		chfcoe_memcpy(req->eth.dmac, lnode->fcf_mac, 6);
	else { 
		if(rnode)		
			chfcoe_memcpy(req->eth.dmac, rnode->mac, 6);
		else {
			CHFCOE_ASSERT(0);
		}
	}
	chfcoe_memcpy(req->eth.smac, pi->phy_mac, 6);

	/* FIP header */
        req->fip.fip_ver 	= PROTO_FIP_VER_ENCAPS(1);
	req->fip.fip_resv1	= 0;
        req->fip.fip_op 	= chfcoe_htons(PROTO_FIP_OP_LS);
	req->fip.fip_resv2	= 0;
        req->fip.fip_subcode 	= hdr->r_ctl == PROTO_FC_RCTL_ELS_REQ ? 
				PROTO_FIP_SC_REQ : PROTO_FIP_SC_REP;
	req->fip.fip_dl_len	= chfcoe_htons(sizeof(req->desc) / PROTO_FIP_BPW);
	if (lnode->fip_type == CHFCOE_FCF)
        	req->fip.fip_flags 	= chfcoe_htons(PROTO_FIP_FL_FPMA);
	req->desc.logi.fd_desc.fip_dtype = chfcoe_is_phys_lnode(lnode) ? 
		PROTO_FIP_DT_FLOGI : PROTO_FIP_DT_FDISC;
	req->desc.logi.fd_desc.fip_dlen	= 36;
	req->desc.logi.fd_resvd[0] = 0;
	req->desc.logi.fd_resvd[1] = 0;

	chfcoe_fcb_push(fr, sizeof (struct cpl_tx_pkt_xt));
	chfcoe_fill_cpl_tx(fr, adap->pf, sizeof(struct proto_fip_virt_ln_req), 
			pi->port_num, (lnode->vlan_id | 
			pi->dcb_prio << VLAN_PRIO_SHIFT));

	desc_mac = (struct proto_fip_mac_desc *) 
		chfcoe_fcb_put(fr, sizeof(*desc_mac));
	chfcoe_memset(desc_mac, 0, sizeof(*desc_mac));
	desc_mac->fd_desc.fip_dtype	= PROTO_FIP_DT_MAC;
	desc_mac->fd_desc.fip_dlen 	= sizeof(req->desc.mac)/PROTO_FIP_BPW;
	if (lnode->fip_type != CHFCOE_FCF)
		chfcoe_memcpy(desc_mac->fd_mac, lnode->fcoe_mac, 6);
	CHFCOE_INC_STATS(pi, n_fip_tx_fr);
	return chfcoe_adap_send_frame(fr, pi);
}

int chfcoe_fcb_xmit(struct chfcoe_lnode *lnode, struct chfcoe_rnode *rnode,
                chfcoe_fc_buffer_t *fr)
{
	struct fw_eth_tx_pkt_wr *wr;
	struct cpl_tx_pkt_core *cpl;
	struct proto_ethhdr_novlan *eh;
	struct proto_fcoe_hdr *fcoeh;
	struct proto_fcoe_crc_eof *fcoet;
	uint64_t ctrl1 = 0;
	fc_header_t *fh;
	int clen, imm, wrlen, imlen;
	struct chfcoe_adap_info *adap;
	struct chfcoe_port_info *pi;
	struct ulptx_sgl *sgl;
	struct ulptx_idata *im;
	uint32_t vidx;
	int pad = 0;

	pi = lnode->pi;
	adap = pi->adap;

	fh = (fc_header_t *)chfcoe_fc_hdr(fr);
	eh = (struct proto_ethhdr_novlan *)chfcoe_fcb_push(fr,
			sizeof(struct proto_fcoe_hdr) +
			sizeof(struct proto_ethhdr_novlan));
	eh->et = chfcoe_htons(PROTO_ETH_P_FCOE);
	if (lnode->fip_type == CHFCOE_FCF)
		chfcoe_memcpy(eh->dmac, lnode->fcf_mac, 6);
	else { 
		if(rnode)		
			chfcoe_memcpy(eh->dmac, rnode->vn_mac, 6);
		else {
			CHFCOE_ASSERT(0);
		}
	}
	chfcoe_memcpy(eh->smac, lnode->fcoe_mac, 6);

	fcoeh = (struct proto_fcoe_hdr *)(eh + 1);
	chfcoe_memset(fcoeh, 0, sizeof(struct proto_fcoe_hdr));
	fcoeh->fcoe_ver = 0;
	fcoeh->fcoe_sof = chfcoe_fc_sof(fr);

	clen = chfcoe_fc_len(fr);
	imm = (chfcoe_fc_dma_addr(fr)) ? 0 : 1;

	wr = (struct fw_eth_tx_pkt_wr *)chfcoe_fcb_push(fr,
			sizeof (struct cpl_tx_pkt_xt));
	cpl = (struct cpl_tx_pkt_core *)(wr + 1);
	wrlen = chfcoe_fc_len(fr);

	ctrl1 = V_TXPKT_CSUM_TYPE(TX_CSUM_FCOE) |
		F_TXPKT_L4CSUM_DIS | F_TXPKT_IPCSUM_DIS |
		V_TXPKT_CSUM_START(FCOE_TXPKT_CSUM_START) |
		V_TXPKT_CSUM_END(FCOE_TXPKT_CSUM_END) |
		V_TXPKT_CSUM_LOC(FCOE_TXPKT_CSUM_END);

	if (!imm) {
		imlen = chfcoe_fc_len(fr) - WR_HDR_SIZE;
		sgl = (struct ulptx_sgl *)(chfcoe_fcb_put(fr, sizeof(*sgl) +
				sizeof (*im) + 4) + 4);	/* 4 byte padding for dsgl alignment */

		sgl->cmd_nsge = chfcoe_htonl(V_ULPTX_CMD(ULP_TX_SC_DSGL) |
						V_ULPTX_NSGE(1) |
						V_ULP_TX_SC_MORE(1));
		sgl->addr0 = chfcoe_cpu_to_be64(chfcoe_fc_dma_addr(fr));
		sgl->len0 = chfcoe_htonl(chfcoe_fc_dma_len(fr));
		pad = chfcoe_fc_dma_len(fr) % 4;
		if (chfcoe_unlikely(pad)) {
			pad = 4 - pad;
			fh->f_ctl[2] |= (pad & 3);
		}

		im = (struct ulptx_idata *)(sgl + 1);
		im->cmd_more = chfcoe_htonl(V_ULPTX_CMD(ULP_TX_SC_IMM) | 
				V_ULP_TX_SC_MORE(0));
		im->len = chfcoe_htonl(sizeof(*fcoet) + pad);
		clen += chfcoe_fc_dma_len(fr);
		wrlen += sizeof(*sgl) + sizeof(*im) + 4;
	} else {
		pad = chfcoe_fc_len(fr) % 4;
		if (chfcoe_unlikely(pad)) {
			pad = 4 - pad;
			fh->f_ctl[2] |= (pad & 3);
		}

		imlen = chfcoe_fc_len(fr) - WR_HDR_SIZE + sizeof(*fcoet) + pad;
	}

	fcoet = (struct proto_fcoe_crc_eof *)
		(chfcoe_fcb_put(fr, sizeof(*fcoet) + pad) + pad);
	chfcoe_memset(fcoet, 0, sizeof(*fcoet));
	fcoet->fcoe_eof = chfcoe_fc_eof(fr);
	clen += sizeof(*fcoet) + pad;
	wrlen += sizeof(*fcoet) + pad;

	wr->equiq_to_len16 = chfcoe_htonl(V_FW_WR_LEN16(CHFCOE_DIV_ROUND_UP(wrlen, 16)));
	wr->op_immdlen = chfcoe_htonl(V_FW_WR_OP(FW_ETH_TX_PKT_WR) | 
			V_FW_WR_IMMDLEN(imlen));
	wr->r3 = 0;

	if (lnode->vlan_id) {
		ctrl1 |= F_TXPKT_VLAN_VLD | V_TXPKT_VLAN(lnode->vlan_id | 
			pi->dcb_prio << VLAN_PRIO_SHIFT);
		vidx = lnode->vlan_id >> VLAN_PRIO_SHIFT;
		if (!vidx)
			vidx = pi->dcb_prio;
	} else {
		vidx = 0;
	}

	cpl->ctrl0 = chfcoe_htonl(V_TXPKT_OPCODE(CPL_TX_PKT_XT) |
			V_TXPKT_INS_OVLAN(0) |
			V_TXPKT_OVLAN_IDX(vidx) |
			V_TXPKT_INTF(lnode->port_num) |
			V_TXPKT_PF(adap->pf) |
			F_TXPKT_VF_VLD | V_TXPKT_VF(G_FW_VIID_VIN(pi->vi_id)));

	cpl->pack = 0;
	cpl->len = chfcoe_htons(clen);
	cpl->ctrl1 = chfcoe_cpu_to_be64(ctrl1);

	if (chfcoe_unlikely(!chfcoe_is_imm(fr)))
		chfcoe_err(lnode, "not imm: skb len %d\n", chfcoe_fc_len(fr));

	CHFCOE_INC_STATS(pi, n_fcoe_tx_fr);
	return chfcoe_adap_send_frame(fr, pi);
}

void chfcoe_pkts_xmit(struct chfcoe_rnode *rn, chfcoe_fc_buffer_t *fb)
{
	struct chfcoe_lnode *ln = rn->lnode;
	struct chfcoe_port_info *pi = ln->pi;

	struct fw_eth_tx_pkts_wr *wr;
	struct ulp_txpkt *mc;
	struct ulptx_idata *sc_imm1, *sc_imm2;
	struct cpl_tx_pkt_core *cpl;
	struct proto_ethhdr_novlan *eh;
	struct proto_fcoe_hdr *fcoeh;
	fc_header_t *fc_hdr;
	struct ulptx_sgl *sc_dsgl;
	struct proto_fcoe_crc_eof *fcoet;
	struct proto_fcp_resp *fcp_resp;

	uint16_t fill_data = 0, fill_rsp = 0, sense_buffer_len = 0;
	size_t data_len16 = 0, rsp_len16 = 0, wr_len16 = 0;
	size_t hdr_len = 0;
	uint32_t ctrl0 = 0;
	uint64_t ctrl1 = 0;
	uint32_t vidx = 0;
	

	ctrl1 = V_TXPKT_CSUM_TYPE(TX_CSUM_FCOE) |
		F_TXPKT_L4CSUM_DIS | F_TXPKT_IPCSUM_DIS |
		V_TXPKT_CSUM_START(FCOE_TXPKT_CSUM_START) |
		V_TXPKT_CSUM_END(FCOE_TXPKT_CSUM_END) |
		V_TXPKT_CSUM_LOC(FCOE_TXPKT_CSUM_END);

	if (ln->vlan_id) {
		ctrl1 |= F_TXPKT_VLAN_VLD | V_TXPKT_VLAN(ln->vlan_id | 
				pi->dcb_prio << VLAN_PRIO_SHIFT);
		vidx = ln->vlan_id >> VLAN_PRIO_SHIFT;
		if (!vidx)
			vidx = pi->dcb_prio;
	} else {
		vidx = 0;
	}
	
	ctrl0 = chfcoe_cpu_to_be32(V_TXPKT_OPCODE(CPL_TX_PKT_XT) |
			V_TXPKT_INS_OVLAN(0) |
			V_TXPKT_OVLAN_IDX(vidx) |
			V_TXPKT_INTF(ln->port_num) |
			V_TXPKT_PF(pi->adap->pf) |
			F_TXPKT_VF_VLD | V_TXPKT_VF(G_FW_VIID_VIN(pi->vi_id)));
	
	hdr_len = sizeof(*eh) + sizeof(*fcoeh) + sizeof(*fc_hdr) + sizeof(*fcoet);

	wr = (struct fw_eth_tx_pkts_wr *)(chfcoe_skb_data(fb));
	wr_len16 = CHFCOE_DIV_ROUND_UP(chfcoe_skb_len(fb), 16);

	/* data frame */
	mc = (struct ulp_txpkt *)(wr + 1);
	sc_imm1 = (struct ulptx_idata *)(mc + 1);
	cpl = (struct cpl_tx_pkt_core *)(sc_imm1 + 1);
	eh = (struct proto_ethhdr_novlan *)(cpl + 1);
	fcoeh = (struct proto_fcoe_hdr *)(eh + 1);

	fc_hdr = (fc_header_t *)(fcoeh + 1);
	fill_data = (fc_hdr->f_ctl[2]) & 0x3;
	data_len16 = CHFCOE_DIV_ROUND_UP(mclen1 + fill_data, 16);

	sc_dsgl = (struct ulptx_sgl *)(((unsigned char *)(fc_hdr + 1)) + 4);
	sc_imm2 = (struct ulptx_idata *)(sc_dsgl + 1);
	fcoet = (struct proto_fcoe_crc_eof *)(((unsigned char *)(sc_imm2 + 1)) + fill_data);

	/* data frame ethernet header */
	eh->et = chfcoe_htons(PROTO_ETH_P_FCOE);
	if (ln->fip_type == CHFCOE_FCF)
		chfcoe_memcpy(eh->dmac, ln->fcf_mac, 6);
	else  
		chfcoe_memcpy(eh->dmac, rn->vn_mac, 6);
	
	chfcoe_memcpy(eh->smac, ln->fcoe_mac, 6);


	/* data frame fcoe header */
	if (chfcoe_ntohs(fc_hdr->seq_cnt)) 
		fcoeh->fcoe_sof = PROTO_FC_SOF_N3;
	else 
		fcoeh->fcoe_sof = PROTO_FC_SOF_I3;
	
	fcoeh->fcoe_ver = 0;

	/* data frame fcoe trailer */
	fcoet->fcoe_eof = PROTO_FC_EOF_T;

	
	cpl->ctrl0 = ctrl0;
	cpl->pack = 0;
	cpl->len = chfcoe_cpu_to_be16(hdr_len + chfcoe_fc_dma_len(fb) + fill_data);
	cpl->ctrl1 = chfcoe_cpu_to_be64(ctrl1);

	sc_dsgl->cmd_nsge = chfcoe_cpu_to_be32(V_ULPTX_CMD(ULP_TX_SC_DSGL) |
			V_ULPTX_NSGE(1) | F_ULP_TX_SC_MORE);
	sc_dsgl->addr0 = chfcoe_cpu_to_be64(chfcoe_fc_dma_addr(fb));
	sc_dsgl->len0 = chfcoe_cpu_to_be32(chfcoe_fc_dma_len(fb));

	sc_imm2->cmd_more = chfcoe_cpu_to_be32(V_ULPTX_CMD(ULP_TX_SC_IMM) | 
			V_ULP_TX_SC_MORE(0));
	sc_imm2->len = chfcoe_cpu_to_be32(sizeof(*fcoet) + fill_data);


	sc_imm1->cmd_more = chfcoe_cpu_to_be32(V_ULPTX_CMD(ULP_TX_SC_IMM) | 
			F_ULP_TX_SC_MORE);
	sc_imm1->len = chfcoe_cpu_to_be32(sizeof(*cpl) + hdr_len - sizeof(*fcoet));

	mc->cmd_dest = chfcoe_cpu_to_be32(V_ULPTX_CMD(4) | V_ULP_TXPKT_DEST(0) |
			V_ULP_TXPKT_FID(pi->adap->fw_evtq_cntxt_id) |
			F_ULP_TXPKT_RO);
	mc->len = chfcoe_cpu_to_be32(data_len16);


	/* rsp frame */
	mc = (struct ulp_txpkt *)((unsigned char *)(wr + 1) + (data_len16 * 16));
	sc_imm1 = (struct ulptx_idata *)(mc + 1);
	cpl = (struct cpl_tx_pkt_core *)(sc_imm1 + 1);
	eh = (struct proto_ethhdr_novlan *)(cpl + 1);
	fcoeh = (struct proto_fcoe_hdr *)(eh + 1);

	fc_hdr = (fc_header_t *)(fcoeh + 1);
	fill_rsp = (fc_hdr->f_ctl[2]) & 0x3;

	fcp_resp = (struct proto_fcp_resp *)(fc_hdr + 1);
	sense_buffer_len = chfcoe_be32_to_cpu(fcp_resp->sns_len);
	fcoet = (struct proto_fcoe_crc_eof *)((unsigned char *)(fcp_resp) +
			24 + sense_buffer_len  + fill_rsp);

	rsp_len16 = CHFCOE_DIV_ROUND_UP(mclen2 + sense_buffer_len + fill_rsp, 16);

	/* rsp frame ethernet header */
	eh->et = chfcoe_htons(PROTO_ETH_P_FCOE);
	if (ln->fip_type == CHFCOE_FCF)
		chfcoe_memcpy(eh->dmac, ln->fcf_mac, 6);
	else  
		chfcoe_memcpy(eh->dmac, rn->vn_mac, 6);
	
	chfcoe_memcpy(eh->smac, ln->fcoe_mac, 6);

	/* rsp frame fcoe header */
	fcoeh->fcoe_sof = PROTO_FC_SOF_I3;
	fcoeh->fcoe_ver = 0;

	/* rsp frame fcoe trailer */
	fcoet->fcoe_eof = PROTO_FC_EOF_T;

	cpl->ctrl0 = ctrl0;
	cpl->pack = 0;
	cpl->len = chfcoe_cpu_to_be16(hdr_len + 24 + sense_buffer_len + fill_rsp);
	cpl->ctrl1 = chfcoe_cpu_to_be64(ctrl1);

	sc_imm1->cmd_more = chfcoe_cpu_to_be32(V_ULPTX_CMD(ULP_TX_SC_IMM) | 
			V_ULP_TX_SC_MORE(0));
	sc_imm1->len = chfcoe_cpu_to_be32(sizeof(*cpl) + hdr_len + 24 + sense_buffer_len + fill_rsp);

	mc->cmd_dest = chfcoe_cpu_to_be32(V_ULPTX_CMD(4) | V_ULP_TXPKT_DEST(0) |
			V_ULP_TXPKT_FID(pi->adap->fw_evtq_cntxt_id) |
			F_ULP_TXPKT_RO);
	mc->len = chfcoe_cpu_to_be32(rsp_len16);

	wr->op_pkd = chfcoe_cpu_to_be32(V_FW_WR_OP(FW_ETH_TX_PKTS_WR));
	wr->equiq_to_len16 = chfcoe_cpu_to_be32(wr_len16);
	wr->plen = chfcoe_cpu_to_be16((hdr_len * 2) + chfcoe_fc_dma_len(fb) + fill_data +
		       24 + sense_buffer_len + fill_rsp);
	wr->npkt = 2;
	wr->r3 = 0;
	wr->type = 0;

	CHFCOE_INC_STATS(ln->pi, n_fcoe_tx_fr);
	chfcoe_adap_send_frame(fb, ln->pi);
}


/*
 * chfcoe_fill_cpl_tx - fill the eth_tx_wr and cpl_tx_pkt 
 */
void *
chfcoe_fill_cpl_tx(chfcoe_fc_buffer_t *p, uint8_t pf, size_t payload_len,
		   uint8_t port_num, uint16_t vlan_id)
{
	struct cpl_tx_pkt_core *cpl;
	struct fw_eth_tx_pkt_wr *wr;
	uint64_t                cntrl;
	uint32_t                vidx;

	wr = (struct fw_eth_tx_pkt_wr *)chfcoe_fc_hdr(p);
	/* Fill the work request first */
	chfcoe_memset(wr, 0, sizeof(struct fw_eth_tx_pkt_wr));
	wr->op_immdlen = chfcoe_htonl(V_FW_WR_OP(FW_ETH_TX_PKT_WR) |
			V_FW_WR_IMMDLEN(payload_len + sizeof(struct cpl_tx_pkt_core)));
	wr->equiq_to_len16 = chfcoe_htonl(V_FW_WR_LEN16(
				CHFCOE_DIV_ROUND_UP((payload_len + sizeof(struct cpl_tx_pkt)) , 16)));


	wr->r3 = 0;

	/* Now fill the cpl_tx_pkt */
	cpl = (struct cpl_tx_pkt_core *)(wr + 1);
	chfcoe_memset(cpl, 0, sizeof(struct cpl_tx_pkt_core));

	cntrl = F_TXPKT_L4CSUM_DIS | F_TXPKT_IPCSUM_DIS;

	if (vlan_id)
		cntrl |= F_TXPKT_VLAN_VLD | V_TXPKT_VLAN(vlan_id);

	vidx = vlan_id >> VLAN_PRIO_SHIFT;
	cpl->ctrl0 = chfcoe_htonl(V_TXPKT_OPCODE(CPL_TX_PKT) |
			V_TXPKT_INS_OVLAN(0) |
			V_TXPKT_OVLAN_IDX(vidx) |
			V_TXPKT_INTF(port_num) | 
			V_TXPKT_PF(pf));


	cpl->pack = chfcoe_htons(0);
	cpl->len = chfcoe_htons(payload_len);
	cpl->ctrl1 = chfcoe_cpu_to_be64(cntrl);

	/* Move the pointer past the cpl_tx_pkt and return it */
	return cpl + 1;
}	

int chfcoe_cpl_rx_handler(struct chfcoe_adap_info *adap, const uint64_t *rsp)
{
	int ret = 0;

//      chfcoe_dbg(adap, "chfcoe_cpl_rx_handler(): cpl %d\n", *(uint8_t *)rsp);
	switch (*(uint8_t *)rsp) {
	case CPL_FCOE_HDR:
		ret = chfcoe_cplrx_fcoe_hdr_handler(adap, rsp);
		break;

	case CPL_FW6_MSG:
		ret = chfcoe_pofcoe_tcb_wr_handler(adap, rsp);
		break;

	case CPL_RX_FCOE_DDP:
		ret = chfcoe_cplrx_fcoe_ddp_handler(adap, rsp);
		break;

	default:
		chfcoe_err(rsp, "chfcoe_cpl_rx_handler(): unexpected cpl %d\n",
				*(uint8_t *)rsp);
		break;
	}

	return ret;
}

