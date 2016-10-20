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

#include <csio_hw.h>
#include <csio_lnode.h>
#include <csio_rnode.h>
#include <csio_mb.h>
#include <csio_mb_helpers.h>

/*****************************************************************************/
/* MB FCoE Command/Response Helpers */
/*****************************************************************************/

/* Mailbox helper functions - one per command */

/*
 * csio_write_fcoe_link_cond_init_mb - Initialize Mailbox to write FCoE link
 *				 condition.
 *
 * @ln: The Lnode structure
 * @mbp: Mailbox structure to initialize
 * @mb_tmo: Mailbox time-out period (in ms).
 * @cbfn: The call back function.
 *
 *
 */
void
csio_write_fcoe_link_cond_init_mb(struct fw_fcoe_link_cmd *cmdp,
		uint8_t port_id, uint32_t sub_opcode,
		uint8_t cos, bool link_status, uint32_t fcfi)
{
	csio_memset(cmdp, 0, sizeof(*cmdp));
	cmdp->op_to_portid = csio_htonl((
			V_FW_CMD_OP(FW_FCOE_LINK_CMD)		|
			F_FW_CMD_REQUEST			|
			F_FW_CMD_WRITE				|
			V_FW_FCOE_LINK_CMD_PORTID(port_id)));

	cmdp->sub_opcode_fcfi = csio_htonl(
			V_FW_FCOE_LINK_CMD_SUB_OPCODE(sub_opcode) 	|
			V_FW_FCOE_LINK_CMD_FCFI(fcfi));

	cmdp->lstatus = link_status;

	/* REVISIT: Use r4 for now until it has a proper name */
	cmdp->r4 = cos;
	cmdp->retval_len16 = csio_htonl(
				V_FW_CMD_LEN16(sizeof(*cmdp) / 16));

	return;

} /* csio_write_fcoe_link_cond_init_mb */

/*
 * csio_fcoe_read_res_info_init_mb - Initializes the mailbox for reading FCoE
 *				resource information(FW_GET_RES_INFO_CMD).
 *
 * @hw: The HW structure
 * @mbp: Mailbox structure to initialize
 * @mb_tmo: Mailbox time-out period (in ms).
 * @cbfn: The call-back function
 *
 *
 */
void
csio_fcoe_read_res_info_init_mb(struct fw_fcoe_res_info_cmd *cmdp)
{
	csio_memset(cmdp, 0, sizeof(*cmdp));
	cmdp->op_to_read = csio_htonl((
			V_FW_CMD_OP(FW_FCOE_RES_INFO_CMD)	|
			F_FW_CMD_REQUEST			|
			F_FW_CMD_READ));

	cmdp->retval_len16 = csio_htonl(
			V_FW_CMD_LEN16(sizeof(*cmdp) / 16));

	return;
}/* csio_fcoe_read_res_info_init_mb */

/*
 * csio_fcoe_vnp_alloc_init_mb - Initializes the mailbox for allocating VNP
 *				in the firmware (FW_FCOE_VNP_CMD).
 *
 * @ln: The Lnode structure.
 * @mbp: Mailbox structure to initialize.
 * @mb_tmo: Mailbox time-out period (in ms).
 * @fcfi: FCF Index.
 * @vnpi: vnpi
 * @iqid: iqid
 * @vnport_wwnn: vnport WWNN
 * @vnport_wwpn: vnport WWPN
 * @cbfn: The call-back function.
 *
 *
 */
void
csio_fcoe_vnp_alloc_init_mb(struct fw_fcoe_vnp_cmd *cmdp,
		uint32_t fcfi, uint32_t vnpi, uint16_t iqid,
		uint8_t vnport_wwnn[8],	uint8_t vnport_wwpn[8])
{
	csio_memset(cmdp, 0, sizeof(*cmdp));
	cmdp->op_to_fcfi = csio_htonl((
			V_FW_CMD_OP(FW_FCOE_VNP_CMD)	|
			F_FW_CMD_REQUEST		|
			F_FW_CMD_EXEC			|
			V_FW_FCOE_VNP_CMD_FCFI(fcfi)));

	cmdp->alloc_to_len16 = csio_htonl(
			F_FW_FCOE_VNP_CMD_ALLOC		|
			V_FW_CMD_LEN16(sizeof(*cmdp) / 16));

	cmdp->gen_wwn_to_vnpi = csio_htonl(V_FW_FCOE_VNP_CMD_VNPI(vnpi));

	cmdp->iqid = csio_htons(iqid);

	if(!csio_wwn_to_u64(vnport_wwnn) && !csio_wwn_to_u64(vnport_wwpn))
		cmdp->gen_wwn_to_vnpi |= csio_htonl(F_FW_FCOE_VNP_CMD_GEN_WWN);

	if (vnport_wwnn)
		csio_memcpy(cmdp->vnport_wwnn, vnport_wwnn, 8);
	if (vnport_wwpn)
		csio_memcpy(cmdp->vnport_wwpn, vnport_wwpn, 8);
	return;

} /* csio_fcoe_vnp_alloc_init_mb */

/*
 * csio_process_fcoe_vnp_alloc_mb_rsp - Process the VNP allocation mailbox's
 *					response.
 *
 * @ln: The Lnode structure.
 * @mbp: Mailbox structure to initialize.
 * @retval: firmware return value.
 * @vnp_params: VNP command parameters.
 *
 */
void
csio_process_fcoe_vnp_alloc_mb_rsp(struct fw_fcoe_vnp_cmd *rsp,
		struct fw_fcoe_vnp_cmd_params *vnp_params)
{
	vnp_params->vnpi = G_FW_FCOE_VNP_CMD_VNPI(
			csio_ntohl(rsp->gen_wwn_to_vnpi));

	csio_memcpy(vnp_params->vnport_wwnn, rsp->vnport_wwnn,
			sizeof(vnp_params->vnport_wwnn));
	csio_memcpy(vnp_params->vnport_wwpn, rsp->vnport_wwpn,
			sizeof(vnp_params->vnport_wwpn));

	return;

} /* csio_process_fcoe_vnp_alloc_mb_rsp */

/*
 * csio_fcoe_vnp_write_init_mb - Initializes the mailbox for writing to VNP
 *				in the firmware (FW_FCOE_VNP_CMD).
 *
 * @ln: The Lnode structure.
 * @mbp: Mailbox structure to initialize.
 * @mb_tmo: Mailbox time-out period (in ms).
 * @cascaded_req: TRUE - if this request is cascased with vnp-alloc request.
 * @vnp_params: VNP command parameters.
 * @cbfn: The call-back function.
 *
 * For cascaded write request, we *donot* want to overwrite values in any
 * fields. We do inclusive-OR write on all fields.
 *
 */
void
csio_fcoe_vnp_write_init_mb(struct fw_fcoe_vnp_cmd *cmdp,
		bool cascaded_req, uint32_t fcfi,
		uint32_t vnpi, uint16_t iqid, uint32_t vf_id,
		uint8_t vnport_mac[6], uint8_t vnport_wwnn[8],
		uint8_t vnport_wwpn[8],
		uint8_t cmn_srv_parms[16], uint8_t cls_srv_parms[8])
{
	/*
	 * If this VNP write is cascaded with VNP alloc request, do not
	 * re-initialize with 0's.
	 *
	 */

	if (!cascaded_req)
		csio_memset(cmdp, 0, sizeof(*cmdp));


	cmdp->op_to_fcfi |= csio_htonl(
				V_FW_CMD_OP(FW_FCOE_VNP_CMD)	|
				F_FW_CMD_REQUEST		|
				F_FW_CMD_WRITE			|
				V_FW_FCOE_VNP_CMD_FCFI(fcfi));

	cmdp->alloc_to_len16 |= csio_htonl(
			V_FW_CMD_LEN16(sizeof(*cmdp) / 16));

	csio_memcpy(cmdp->vnport_mac, vnport_mac, sizeof(cmdp->vnport_mac));
	if (vnport_wwnn)
		csio_memcpy(cmdp->vnport_wwnn, vnport_wwnn, 8);
	if (vnport_wwpn)
		csio_memcpy(cmdp->vnport_wwpn, vnport_wwpn, 8);

	cmdp->gen_wwn_to_vnpi |= csio_htonl(V_FW_FCOE_VNP_CMD_VNPI(vnpi));

	if (vf_id) {
		cmdp->gen_wwn_to_vnpi |= csio_htonl(F_FW_FCOE_VNP_CMD_VFID_EN);
		cmdp->vf_id |= csio_htonl(vf_id);
	}

	cmdp->iqid |= csio_htons(iqid);

	csio_memcpy(cmdp->cmn_srv_parms, cmn_srv_parms,
						sizeof(cmdp->cmn_srv_parms));

#if 0 /* FIXME */
	/*TODO: Identify the class specific parameters(16 bytes) that
	  needs to packed into 8 bytes for this cmd */
	csio_memcpy(cmdp->cls_srv_parms, cls_srv_parms,
						sizeof(cmdp->cls_srv_parms));
#endif


	return;

} /* csio_fcoe_vnp_write_init_mb */

/*
 * csio_fcoe_vnp_alloc_and_write_init_mb - Initializes the mailbox for
 *			allocation & writing into an FCoE VNPort.
 *
 * @ln: The Lnode structure
 * @mbp: Mailbox structure to initialize
 * @mb_tmo: Mailbox time-out period (in ms).
 * @vnp_params: VNP command parameters.
 * @cbfn: The call-back function
 *
 *
 */
void
csio_fcoe_vnp_alloc_and_write_init_mb(struct fw_fcoe_vnp_cmd *cmdp,
		uint32_t fcfi, uint32_t vnpi, uint16_t iqid, uint32_t vf_id,
		uint8_t vnport_mac[6], uint8_t cmn_srv_parms[16],
		uint8_t cls_srv_parms[8])
{
	csio_fcoe_vnp_alloc_init_mb(cmdp, fcfi, vnpi, iqid, NULL, NULL);

	csio_fcoe_vnp_write_init_mb(cmdp, CSIO_TRUE, fcfi, vnpi,
		iqid, vf_id, vnport_mac, NULL, NULL, cmn_srv_parms, cls_srv_parms);

	return;

} /* csio_fcoe_vnp_alloc_and_write_init_mb */

/*
 * csio_process_fcoe_vnp_alloc_write_mb_rsp - Process the VNP allocation
 *					+ write mailbox's response.
 *
 * @ln: The Lnode structure.
 * @mbp: Mailbox structure to initialize.
 * @retval: firmware return value.
 * @vnp_params: VNP command parameters.
 *
 */
void
csio_process_fcoe_vnp_alloc_and_write_mb_rsp(struct fw_fcoe_vnp_cmd *rsp,
		struct fw_fcoe_vnp_cmd_params *vnp_params)
{
	vnp_params->vnpi = G_FW_FCOE_VNP_CMD_VNPI(
			csio_ntohl(rsp->gen_wwn_to_vnpi));

	csio_memcpy(vnp_params->vnport_wwnn, rsp->vnport_wwnn,
			sizeof(vnp_params->vnport_wwnn));
	csio_memcpy(vnp_params->vnport_wwpn, rsp->vnport_wwpn,
			sizeof(vnp_params->vnport_wwpn));

	return;
} /* csio_process_fcoe_vnp_alloc_write_mb_rsp */

/*
 * csio_fcoe_vnp_read_init_mb - Prepares VNP read cmd.
 * @ln: The Lnode structure.
 * @mbp: Mailbox structure to initialize.
 * @mb_tmo: Mailbox time-out period (in ms).
 * @fcfi: FCF Index.
 * @vnpi: vnpi
 * @cbfn: The call-back handler.
 */
void
csio_fcoe_vnp_read_init_mb(struct fw_fcoe_vnp_cmd *cmdp, uint32_t fcfi,
		uint32_t vnpi)
{
	csio_memset(cmdp, 0, sizeof(*cmdp));
	cmdp->op_to_fcfi = csio_htonl(
				V_FW_CMD_OP(FW_FCOE_VNP_CMD)	|
				F_FW_CMD_REQUEST		|
				F_FW_CMD_READ			|
				V_FW_FCOE_VNP_CMD_FCFI(fcfi));
	cmdp->alloc_to_len16 = csio_htonl(
			V_FW_CMD_LEN16(sizeof(*cmdp) / 16));
	cmdp->gen_wwn_to_vnpi = csio_htonl(V_FW_FCOE_VNP_CMD_VNPI(vnpi));
	return;
}

/*
 * csio_fcoe_vnp_free_init_mb - Initializes the mailbox for freeing an
 *			alloacted VNP in the firmware (FW_FCOE_VNP_CMD).
 *
 * @ln: The Lnode structure.
 * @mbp: Mailbox structure to initialize.
 * @mb_tmo: Mailbox time-out period (in ms).
 * @fcfi: FCF flow id
 * @vnpi: VNP flow id
 * @cbfn: The call-back function.
 * Return: None
 */
void
csio_fcoe_vnp_free_init_mb(struct fw_fcoe_vnp_cmd *cmdp,
		uint32_t fcfi, uint32_t vnpi)
{
	csio_memset(cmdp, 0, sizeof(*cmdp));
	cmdp->op_to_fcfi = csio_htonl(
				V_FW_CMD_OP(FW_FCOE_VNP_CMD)	|
				F_FW_CMD_REQUEST		|
				F_FW_CMD_EXEC			|
				V_FW_FCOE_VNP_CMD_FCFI(fcfi));

	cmdp->alloc_to_len16 = csio_htonl(
			F_FW_FCOE_VNP_CMD_FREE			|
			V_FW_CMD_LEN16(sizeof(*cmdp) / 16));

	cmdp->gen_wwn_to_vnpi = csio_htonl(V_FW_FCOE_VNP_CMD_VNPI(vnpi));

	return;
}

/*
 * csio_fw_fcoe_read_fcf_init_mb - Initializes the mailbox to read the
 *				FCF records.
 *
 * @ln: The Lnode structure
 * @mbp: Mailbox structure to initialize
 * @mb_tmo: Mailbox time-out period (in ms).
 * @fcf_params: FC-Forwarder parameters.
 * @cbfn: The call-back function
 *
 *
 */
void
csio_fw_fcoe_read_fcf_init_mb(struct fw_fcoe_fcf_cmd *cmdp, uint32_t portid,
		uint32_t fcfi)
{
	csio_memset(cmdp, 0, sizeof(*cmdp));
	cmdp->op_to_fcfi = csio_htonl(V_FW_CMD_OP(FW_FCOE_FCF_CMD)	|
					F_FW_CMD_REQUEST 		|
					F_FW_CMD_READ			|
					V_FW_FCOE_FCF_CMD_FCFI(fcfi));
	cmdp->retval_len16 = csio_htonl(V_FW_CMD_LEN16(sizeof(*cmdp) / 16));

	return;

} /* csio_fw_fcoe_read_fcf_init_mb */

void
csio_fcoe_read_ssnparams_init_mb(struct fw_fcoe_stats_cmd *cmdp,
		struct fw_fcoe_ssn_cmd_params *ssnparams)
{
	csio_memset(cmdp, 0, sizeof(*cmdp));
 	cmdp->op_to_flowid = csio_htonl (
				V_FW_CMD_OP(FW_FCOE_STATS_CMD)	 |
				F_FW_CMD_REQUEST | F_FW_CMD_READ       |
				V_FW_FCOE_STATS_CMD_FLOWID(ssnparams->ssni));
	cmdp->free_to_len16 = csio_htonl(V_FW_CMD_LEN16(CSIO_MAX_MB_SIZE/16));

	cmdp->u.ctl.nstats_port = V_FW_FCOE_STATS_CMD_NSTATS(ssnparams->nstats);

	cmdp->u.ctl.port_valid_ix =  V_FW_FCOE_STATS_CMD_IX(ssnparams->idx);
}

void
csio_mb_process_ssnparams_rsp(struct fw_fcoe_stats_cmd *rsp,
		struct fw_fcoe_ssn_cmd_params *ssnparams,
		struct fw_fcoe_scb_stats *ssnstats)
{
	struct fw_fcoe_scb_stats stats;	
	uint8_t *src;
	uint8_t *dst;

	csio_memset(&stats, 0, sizeof(struct fw_fcoe_scb_stats));

	dst = (uint8_t *)(&stats) + ((ssnparams->idx - 1) * 8);
	src = (uint8_t *)rsp + (CSIO_STATS_OFFSET * 8);
	csio_memcpy(dst, src, (ssnparams->nstats * 8));

	if (ssnparams->idx == 1) {
		/* Get the first 6 flits from the first Mailbox */
		ssnstats->tx_bytes 	=
			csio_be64_to_cpu(stats.tx_bytes);
		ssnstats->tx_frames 	=
			csio_be64_to_cpu(stats.tx_frames);
		ssnstats->rx_bytes 	=
			csio_be64_to_cpu(stats.rx_bytes);
		ssnstats->rx_frames 	=
			csio_be64_to_cpu(stats.rx_frames);
		ssnstats->host_abrt_req =
			csio_be32_to_cpu(stats.host_abrt_req);
		ssnstats->adap_auto_abrt =
			csio_be32_to_cpu(stats.adap_auto_abrt);
		ssnstats->host_ios_req 	=
			csio_be32_to_cpu(stats.host_ios_req);
		ssnstats->adap_abrt_rsp 	=
			csio_be32_to_cpu(stats.adap_abrt_rsp);
	}
	if (ssnparams->idx == 7) {
		/* Get next 6 flits for the second Mailbox */
		ssnstats->ssn_offl_ios 	=
			csio_be16_to_cpu(stats.ssn_offl_ios);
		ssnstats->ssn_not_rdy_ios =
			csio_be16_to_cpu(stats.ssn_not_rdy_ios);
		ssnstats->rx_data_ddp_err = stats.rx_data_ddp_err;
		ssnstats->ddp_flt_set_err = stats.ddp_flt_set_err;
		ssnstats->rx_data_fr_err =
			csio_be16_to_cpu(stats.rx_data_fr_err);
		ssnstats->bad_st_abrt_req = stats.bad_st_abrt_req;
		ssnstats->no_io_abrt_req = stats.no_io_abrt_req;
		ssnstats->abort_tmo = stats.abort_tmo;
		ssnstats->abort_tmo_2 = stats.abort_tmo_2;
		//csio_memcpy(ssnstats->abort_req, stats.abort_req, 4);
		ssnstats->no_ppod_res_tmo = stats.no_ppod_res_tmo;
		ssnstats->bp_tmo = stats.bp_tmo;
		ssnstats->adap_auto_cls = stats.adap_auto_cls;
		ssnstats->no_io_cls_req = stats.no_io_cls_req;
		//csio_memcpy(ssnstats->host_cls_req, stats.host_cls_req, 4);
		ssnstats->unsol_cmd_rcvd =
			csio_be64_to_cpu(stats.unsol_cmd_rcvd);
		ssnstats->plogi_req_rcvd =
			csio_be32_to_cpu(stats.plogi_req_rcvd);
		ssnstats->prli_req_rcvd =
			csio_be32_to_cpu(stats.prli_req_rcvd);
		ssnstats->logo_req_rcvd =
			csio_be16_to_cpu(stats.logo_req_rcvd);
		ssnstats->prlo_req_rcvd =
			csio_be16_to_cpu(stats.prlo_req_rcvd);
		ssnstats->plogi_rjt_rcvd =
			csio_be16_to_cpu(stats.plogi_rjt_rcvd);
		ssnstats->prli_rjt_rcvd =
			csio_be16_to_cpu(stats.prli_rjt_rcvd);
	}
	if (ssnparams->idx == 13) {
		/* Get third 6 flits for third Mailbox */
		ssnstats->adisc_req_rcvd =
			csio_be32_to_cpu(stats.adisc_req_rcvd);
		ssnstats->rscn_rcvd =
			csio_be32_to_cpu(stats.rscn_rcvd);
		ssnstats->rrq_req_rcvd =
			csio_be32_to_cpu(stats.rrq_req_rcvd);
		ssnstats->unsol_els_rcvd =
			csio_be32_to_cpu(stats.unsol_els_rcvd);
		ssnstats->adisc_rjt_rcvd = stats.adisc_rjt_rcvd;
		ssnstats->scr_rjt = stats.scr_rjt;
		ssnstats->ct_rjt = stats.ct_rjt;
		ssnstats->inval_bls_rcvd = stats.inval_bls_rcvd;
		ssnstats->ba_rjt_rcvd =
			csio_be32_to_cpu(stats.ba_rjt_rcvd);
	}
	return;
}


void
csio_fcoe_read_vnpparams_init_mb(struct fw_fcoe_stats_cmd *cmdp,
		struct fw_fcoe_vnp_cmd_params *vnpparams)
{
	csio_memset(cmdp, 0, sizeof(*cmdp));	
	cmdp->op_to_flowid = csio_htonl (
				V_FW_CMD_OP(FW_FCOE_STATS_CMD)	 |
				F_FW_CMD_REQUEST | F_FW_CMD_READ       |
				V_FW_FCOE_STATS_CMD_FLOWID(vnpparams->vnpi));
	cmdp->free_to_len16 = csio_htonl(V_FW_CMD_LEN16(CSIO_MAX_MB_SIZE/16));

	cmdp->u.ctl.nstats_port = V_FW_FCOE_STATS_CMD_NSTATS(vnpparams->nstats);

	cmdp->u.ctl.port_valid_ix = V_FW_FCOE_STATS_CMD_IX(vnpparams->idx);
}

void
csio_mb_process_vnpparams_rsp(struct fw_fcoe_stats_cmd *rsp,
		struct fw_fcoe_vnp_cmd_params *vnpparams,
		struct fw_fcoe_pcb_stats  *vnpstats)
{
	struct fw_fcoe_pcb_stats stats;
	uint8_t *src;
	uint8_t *dst;

	csio_memset(&stats, 0, sizeof(struct fw_fcoe_pcb_stats));

	dst = (uint8_t *)(&stats) + ((vnpparams->idx - 1) * 8);
	src = (uint8_t *)rsp + (CSIO_STATS_OFFSET * 8);
	csio_memcpy(dst, src, (vnpparams->nstats * 8));

	if (vnpparams->idx == 1) {
		/* Get first 6 flits from first Mailbox */
		vnpstats->tx_bytes 		=
			csio_be64_to_cpu(stats.tx_bytes);
		vnpstats->tx_frames 		=
			csio_be64_to_cpu(stats.tx_frames);
		vnpstats->rx_bytes 		=
			csio_be64_to_cpu(stats.rx_bytes);
		vnpstats->rx_frames 		=
			csio_be64_to_cpu(stats.rx_frames);
		vnpstats->vnp_ka 		=
			csio_be32_to_cpu(stats.vnp_ka);
		vnpstats->unsol_els_rcvd 	=
			csio_be32_to_cpu(stats.unsol_els_rcvd);
		vnpstats->unsol_cmd_rcvd 	=
			csio_be64_to_cpu(stats.unsol_cmd_rcvd);
	}
	if (vnpparams->idx == 7) {
		/* Get next 6 flits from the second Mailbox */
		vnpstats->implicit_logo 	=
			csio_be16_to_cpu(stats.implicit_logo);
		vnpstats->flogi_inv_sparm 	=
			csio_be16_to_cpu(stats.flogi_inv_sparm);
		vnpstats->fdisc_inv_sparm 	=
			csio_be16_to_cpu(stats.fdisc_inv_sparm);
		vnpstats->flogi_rjt 		=
			csio_be16_to_cpu(stats.flogi_rjt);
		vnpstats->fdisc_rjt 		=
			csio_be16_to_cpu(stats.fdisc_rjt);
		vnpstats->no_ssn 		=
			csio_be16_to_cpu(stats.no_ssn);
		vnpstats->mac_flt_fail 		=
			csio_be16_to_cpu(stats.mac_flt_fail);
		vnpstats->inv_fr_rcvd 		=
			csio_be16_to_cpu(stats.inv_fr_rcvd);
	}
	return;
}

void
csio_fcoe_read_portparams_init_mb(struct fw_fcoe_stats_cmd *cmdp,
				struct fw_fcoe_port_cmd_params *portparams)
{
	csio_memset(cmdp, 0, sizeof(*cmdp));

	cmdp->op_to_flowid = csio_htonl(
				V_FW_CMD_OP(FW_FCOE_STATS_CMD) |
				F_FW_CMD_REQUEST | F_FW_CMD_READ);
	cmdp->free_to_len16 = csio_htonl( V_FW_CMD_LEN16(CSIO_MAX_MB_SIZE/16));

	cmdp->u.ctl.nstats_port =
				V_FW_FCOE_STATS_CMD_NSTATS(portparams->nstats) |
				V_FW_FCOE_STATS_CMD_PORT(portparams->portid);

	cmdp->u.ctl.port_valid_ix =
				V_FW_FCOE_STATS_CMD_IX(portparams->idx) |
				F_FW_FCOE_STATS_CMD_PORT_VALID;

	return;
} /* csio_fcoe_get_stats_init_mb */

void
csio_mb_process_portparams_rsp(struct fw_fcoe_stats_cmd *rsp,
				struct fw_fcoe_port_cmd_params *portparams,
				struct fw_fcoe_port_stats  *portstats)
{
	struct fw_fcoe_port_stats stats;
	uint8_t *src;
	uint8_t *dst;

	csio_memset(&stats, 0, sizeof(struct fw_fcoe_port_stats));

	dst = (uint8_t *)(&stats) + ((portparams->idx - 1) * 8);
	src = (uint8_t *)rsp + (CSIO_STATS_OFFSET * 8);
	csio_memcpy(dst, src, (portparams->nstats * 8));
	if (portparams->idx == 1) {
		/* Get the first 6 flits from the Mailbox */
		portstats->tx_bcast_bytes 	=
			csio_be64_to_cpu(stats.tx_bcast_bytes);
		portstats->tx_bcast_frames 	=
			csio_be64_to_cpu(stats.tx_bcast_frames);
		portstats->tx_mcast_bytes 	=
			csio_be64_to_cpu(stats.tx_mcast_bytes);
		portstats->tx_mcast_frames 	=
			csio_be64_to_cpu(stats.tx_mcast_frames);
		portstats->tx_ucast_bytes 	=
			csio_be64_to_cpu(stats.tx_ucast_bytes);
		portstats->tx_ucast_frames 	=
			csio_be64_to_cpu(stats.tx_ucast_frames);
	}
	if (portparams->idx == 7) {
		/* Get the second 6 flits from the Mailbox */
		portstats->tx_drop_frames 	=
			csio_be64_to_cpu(stats.tx_drop_frames);
		portstats->tx_offload_bytes 	=
			csio_be64_to_cpu(stats.tx_offload_bytes);
		portstats->tx_offload_frames 	=
			csio_be64_to_cpu(stats.tx_offload_frames);
#if 0
		portstats->rx_pf_bytes 		=
			csio_be64_to_cpu(stats.rx_pf_bytes);
		portstats->rx_pf_frames 	=
			csio_be64_to_cpu(stats.rx_pf_frames);
#endif
		portstats->rx_bcast_bytes 	=
			csio_be64_to_cpu(stats.rx_bcast_bytes);
		portstats->rx_bcast_frames 	=
			csio_be64_to_cpu(stats.rx_bcast_frames);
		portstats->rx_mcast_bytes 	=
			csio_be64_to_cpu(stats.rx_mcast_bytes);
	}
	if (portparams->idx == 13){
		/* Get the last 4 flits from the Mailbox */
		portstats->rx_mcast_frames 	=
			csio_be64_to_cpu(stats.rx_mcast_frames);
		portstats->rx_ucast_bytes 	=
			csio_be64_to_cpu(stats.rx_ucast_bytes);
		portstats->rx_ucast_frames 	=
			csio_be64_to_cpu(stats.rx_ucast_frames);
		portstats->rx_err_frames 	=
			csio_be64_to_cpu(stats.rx_err_frames);
	}
	return;
}

void
csio_fcoe_read_fcfparams_init_mb(struct fw_fcoe_stats_cmd *cmdp,
		struct fw_fcoe_fcf_cmd_params *fcfparams)
{
	csio_memset(cmdp, 0, sizeof(*cmdp));
	cmdp->op_to_flowid = csio_htonl((
				V_FW_CMD_OP(FW_FCOE_STATS_CMD)	       |
				F_FW_CMD_REQUEST | F_FW_CMD_READ       |
				V_FW_FCOE_STATS_CMD_FLOWID(fcfparams->fcfi)));
	cmdp->free_to_len16 = csio_htonl(V_FW_CMD_LEN16(CSIO_MAX_MB_SIZE/16));
	cmdp->u.ctl.nstats_port =
				V_FW_FCOE_STATS_CMD_NSTATS(fcfparams->nstats);
	cmdp->u.ctl.port_valid_ix =  V_FW_FCOE_STATS_CMD_IX(fcfparams->idx);

	return;

} /* csio_fcoe_get_stats_init_mb */

void
csio_mb_process_fcfparams_rsp(struct fw_fcoe_stats_cmd *rsp,
		struct fw_fcoe_fcf_cmd_params *fcfparams,
		struct fw_fcoe_fcf_stats *fcfstats)
{
	struct fw_fcoe_fcf_stats stats;
	uint8_t *src;
	uint8_t *dst;

	csio_memset(&stats, 0, sizeof(struct fw_fcoe_fcf_stats));

	dst = (uint8_t *)(&stats) + ((fcfparams->idx - 1) * 8);
	src = (uint8_t *)rsp + (CSIO_STATS_OFFSET * 8);
	csio_memcpy(dst, src, (fcfparams->nstats * 8));

	if (fcfparams->idx == 1) {
		fcfstats->fip_tx_bytes 	=
			csio_be32_to_cpu(stats.fip_tx_bytes);
		fcfstats->fip_tx_fr    	=
			csio_be32_to_cpu(stats.fip_tx_fr);
		fcfstats->fcf_ka       	=
			csio_be64_to_cpu(stats.fcf_ka);
		fcfstats->mcast_adv_rcvd=
			csio_be64_to_cpu(stats.mcast_adv_rcvd);
		fcfstats->ucast_adv_rcvd=
			csio_be16_to_cpu(stats.ucast_adv_rcvd);
		fcfstats->sol_sent 	=
			csio_be16_to_cpu(stats.sol_sent);
		fcfstats->vlan_req 	=
			csio_be16_to_cpu(stats.vlan_req);
		fcfstats->vlan_rpl 	=
			csio_be16_to_cpu(stats.vlan_rpl);
		fcfstats->clr_vlink 	=
			csio_be16_to_cpu(stats.clr_vlink);
		fcfstats->link_down 	=
			csio_be16_to_cpu(stats.link_down);
		fcfstats->link_up 	=
			csio_be16_to_cpu(stats.link_up);
		fcfstats->logo 		=
			csio_be16_to_cpu(stats.logo);
		fcfstats->flogi_req 	=
			csio_be16_to_cpu(stats.flogi_req);
		fcfstats->flogi_rpl 	=
			csio_be16_to_cpu(stats.flogi_rpl);
		fcfstats->fdisc_req 	=
			csio_be16_to_cpu(stats.fdisc_req);
		fcfstats->fdisc_rpl  	=
			csio_be16_to_cpu(stats.fdisc_rpl);
	}else {
		fcfstats->fka_prd_chg 	=
			csio_be16_to_cpu(stats.fka_prd_chg);
		fcfstats->fc_map_chg 	=
			csio_be16_to_cpu(stats.fc_map_chg);
		fcfstats->vfid_chg 	=
			csio_be16_to_cpu(stats.vfid_chg);
		fcfstats->no_fka_req 	= stats.no_fka_req;
		fcfstats->no_vnp 	= stats.no_vnp;
	}
	return;
}
