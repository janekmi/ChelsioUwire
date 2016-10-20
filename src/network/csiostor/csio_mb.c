/*
 *  Copyright (C) 2008-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: The mailbox module.
 *
 */

#include <csio_hw.h>
#include <csio_mb.h>
#include <csio_wr.h>
#include <t4fw_interface.h>
#include <t4_regs_values.h>

#define csio_mb_is_host_owner(__owner)		((__owner) == X_MBOWNER_PL)

/* OS stage - for FW_HELLO_CMD. */
uint8_t csio_os_stage = FW_HELLO_CMD_STAGE_OS;

/******************************************************************************/
/* MB Generic Command/Response Helpers */
/******************************************************************************/

/*
 * csio_mb_ldst - FW LDST command
 * @ldst_cmdp: Command to initialize
 * @hw: The HW structure
 * @reg: register
 *
 */
void
csio_mb_ldst(struct fw_ldst_cmd *ldst_cmd, struct csio_hw *hw, int reg)
{
	csio_memset(ldst_cmd, 0, sizeof(*ldst_cmd));
	/*
	 * Construct and send the Firmware LDST Command to retrieve the
	 * specified PCI-E Configuration Space register.
	 */
	ldst_cmd->op_to_addrspace =
		csio_htonl(V_FW_CMD_OP(FW_LDST_CMD) |
		      F_FW_CMD_REQUEST |
		      F_FW_CMD_READ |
		      V_FW_LDST_CMD_ADDRSPACE(FW_LDST_ADDRSPC_FUNC_PCIE));
	ldst_cmd->cycles_to_len16 = csio_htonl(FW_LEN16(struct fw_ldst_cmd));
	ldst_cmd->u.pcie.select_naccess = V_FW_LDST_CMD_NACCESS(1);
	ldst_cmd->u.pcie.ctrl_to_fn =
		(F_FW_LDST_CMD_LC | V_FW_LDST_CMD_FN(hw->pfn));
	ldst_cmd->u.pcie.r = (uint8_t)reg;
	return;
}

/*
 *
 * csio_mb_caps_config - FW Read/Write Capabilities command helper
 * 			 for FCoE/iSCSI
 * @hw: The HW structure
 * @cmdp: Command to initialize
 * @wr: Write if 1, Read if 0
 * @fcoe: FCoE if 1, 0 if iSCSI
 * @init: Turn on initiator mode.
 * @tgt: Turn on target mode.
 * @cofld:  If 1, Control Offload for FCoE
 * @pdu: If 1, PDU mode for iSCSI
 *
 * This helper assumes that cmdp has MB payload from a previous CAPS
 * read command.
 */
void csio_mb_caps_config(struct csio_hw *hw, struct fw_caps_config_cmd *cmdp,
		bool wr, int fcoe, bool init, bool tgt, bool cofld, bool pdu)
{

	if (!wr)
		csio_memset(cmdp, 0, sizeof(*cmdp));

	cmdp->op_to_write = csio_htonl(V_FW_CMD_OP(FW_CAPS_CONFIG_CMD) |
				       F_FW_CMD_REQUEST |
				       (wr ? F_FW_CMD_WRITE : F_FW_CMD_READ));
	cmdp->cfvalid_to_len16 = csio_htonl(V_FW_CMD_LEN16(sizeof(*cmdp) / 16));
	
	/* Read config */
	if (!wr)
		return;

	/* Write config */
	if (fcoe) {
		/* Clear capabilities first */
		cmdp->fcoecaps = 0;

		if (cofld)
			cmdp->fcoecaps |=
				csio_htons(FW_CAPS_CONFIG_FCOE_CTRL_OFLD);
				
		if (init)
			cmdp->fcoecaps |=
				csio_htons(FW_CAPS_CONFIG_FCOE_INITIATOR);

		if (tgt)
			cmdp->fcoecaps |=
				csio_htons(FW_CAPS_CONFIG_FCOE_TARGET);

	} else { /* iSCSI */
		cmdp->iscsicaps = 0;

		if (init) {
			csio_info(hw, "iscsiCap before: 0x%x\n",
				cmdp->iscsicaps);
			if (pdu)
				cmdp->iscsicaps |= csio_htons(
					FW_CAPS_CONFIG_ISCSI_INITIATOR_PDU);
			else
				cmdp->iscsicaps |= csio_htons(
					FW_CAPS_CONFIG_ISCSI_INITIATOR_SSNOFLD);

			csio_info(hw, "iscsiCap after: 0x%x\n",
				cmdp->iscsicaps);
		}

		if (tgt) {
			if (pdu)
				cmdp->iscsicaps |= csio_htons(
					FW_CAPS_CONFIG_ISCSI_TARGET_PDU);
			else
				cmdp->iscsicaps |= csio_htons(
					FW_CAPS_CONFIG_ISCSI_TARGET_SSNOFLD);
		}
	} /* iscsi */
}

#define CSIO_ADVERT_MASK  (FW_PORT_CAP_SPEED_100M | FW_PORT_CAP_SPEED_1G |\
			   FW_PORT_CAP_SPEED_10G | FW_PORT_CAP_SPEED_40G | \
			   FW_PORT_CAP_SPEED_100G | FW_PORT_CAP_ANEG)

/*
 * csio_mb_port- FW PORT command helper
 * @cmdp: Command to initialize
 * @portid: Port ID to get/set info
 * @wr: Write/Read PORT information.
 * @fc: Flow control
 * @caps: Port capabilites to set.
 *
 */
void
csio_mb_port(struct fw_port_cmd *cmdp, uint8_t portid, bool wr, uint32_t fc,
		uint16_t caps)
{
	unsigned int lfc = 0, mdi = V_FW_PORT_CAP_MDI(FW_PORT_CAP_MDI_AUTO);

	csio_memset(cmdp, 0, sizeof(*cmdp));
	cmdp->op_to_portid = csio_htonl(V_FW_CMD_OP(FW_PORT_CMD) |
				       F_FW_CMD_REQUEST |
				       (wr ? F_FW_CMD_EXEC : F_FW_CMD_READ) |
				       V_FW_PORT_CMD_PORTID(portid));
	if (!wr) {
		cmdp->action_to_len16 = csio_htonl(
			V_FW_PORT_CMD_ACTION(FW_PORT_ACTION_GET_PORT_INFO) |
			V_FW_CMD_LEN16(sizeof(*cmdp) / 16));
		return;
	}

	/* Set port */
	cmdp->action_to_len16 = csio_htonl(
			V_FW_PORT_CMD_ACTION(FW_PORT_ACTION_L1_CFG) |
			V_FW_CMD_LEN16(sizeof(*cmdp) / 16));

	if (fc & PAUSE_RX)
		lfc |= FW_PORT_CAP_FC_RX;
	if (fc & PAUSE_TX)
		lfc |= FW_PORT_CAP_FC_TX;

	if (!(caps & FW_PORT_CAP_ANEG))
		cmdp->u.l1cfg.rcap = csio_htonl((caps & CSIO_ADVERT_MASK) |
									lfc);
	else
		cmdp->u.l1cfg.rcap = csio_htonl((caps & CSIO_ADVERT_MASK) |
								lfc | mdi);

	return;
}

/*
 * csio_mb_iq_alloc - Initializes the mailbox command to allocate an
 *				Ingress DMA queue in the firmware.
 *
 * @cmdp: Command to initialize
 * @iq_params: Ingress queue params needed for allocation.
 *
 *
 */
void
csio_mb_iq_alloc(struct fw_iq_cmd *cmdp,
		struct csio_iq_params *iq_params)
{
	/*
	 * Set REQUEST, EXEC bits. And also set PFN, VFN.
	 *
	 */

	csio_memset(cmdp, 0, sizeof(*cmdp));
	cmdp->op_to_vfn = csio_htonl(V_FW_CMD_OP(FW_IQ_CMD) 		|
				F_FW_CMD_REQUEST | F_FW_CMD_EXEC	|
				V_FW_IQ_CMD_PFN(iq_params->pfn) 	|
				V_FW_IQ_CMD_VFN(iq_params->vfn));

	/*
	 * Set ALLOC & LEN16.
	 *
	 */

	cmdp->alloc_to_len16 = csio_htonl(F_FW_IQ_CMD_ALLOC |
				V_FW_CMD_LEN16(sizeof(*cmdp) / 16));

	/*
	 * Set VIID, TYPE, IQ_ASYNC.
	 *
	 */

	cmdp->type_to_iqandstindex = csio_htonl(
				V_FW_IQ_CMD_VIID(iq_params->viid)	|
				V_FW_IQ_CMD_TYPE(iq_params->type)	|
				V_FW_IQ_CMD_IQASYNCH(iq_params->iqasynch));

	/*
	 * Set Free-list 0 & 1 size.
	 *
	 */

	cmdp->fl0size = csio_htons(iq_params->fl0size);
	cmdp->fl0size = csio_htons(iq_params->fl1size);

	return;

} /* csio_mb_iq_alloc */

/*
 * csio_mb_iq_write - Initializes the mailbox command for writing into an
 *				Ingress DMA Queue.
 *
 * @cmdp: Command to initialize
 * @cascaded_req: TRUE - if this request is cascased with iq-alloc request.
 * @iq_params: Ingress queue params needed for writing.
 *
 * NOTE: We OR relevant bits with cmdp->XXX, instead of just equating,
 * because this IQ write request can be cascaded with a previous
 * IQ alloc request, and we dont want to over-write the bits set by
 * that request. This logic will work even in a non-cascaded case, since the
 * cmdp structure is zeroed out by CSIO_INIT_MBP.
 */
void
csio_mb_iq_write(struct fw_iq_cmd *cmdp, bool cascaded_req,
		struct csio_iq_params *iq_params)
{

	uint32_t iq_start_stop = (iq_params->iq_start)	?
				F_FW_IQ_CMD_IQSTART 	:
				F_FW_IQ_CMD_IQSTOP;

	/*
	 * If this IQ write is cascaded with IQ alloc request, do not
	 * re-initialize with 0's.
	 *
	 */

	if (!cascaded_req)
		csio_memset(cmdp, 0, sizeof(*cmdp));

	/*
	 * Set REQUEST, WRITE bits. And also set PFN, VFN.
	 *
	 */

	cmdp->op_to_vfn |= csio_htonl(V_FW_CMD_OP(FW_IQ_CMD) 		|
				F_FW_CMD_REQUEST | F_FW_CMD_WRITE	|
				V_FW_IQ_CMD_PFN(iq_params->pfn) 	|
				V_FW_IQ_CMD_VFN(iq_params->vfn));

	/*
	 * Set  IQSTART/IQSTOP and LEN16.
	 *
	 */

	cmdp->alloc_to_len16 |= csio_htonl( iq_start_stop |
				V_FW_CMD_LEN16(sizeof(*cmdp) / 16));

	/*
	 * Set the Ingress Id.
	 *
	 */

	cmdp->iqid |= csio_htons(iq_params->iqid);

	/*
	 * Set the free-list 0 & 1 id.
	 *
	 */

	cmdp->fl0id |= csio_htons(iq_params->fl0id);
	cmdp->fl1id |= csio_htons(iq_params->fl1id);

	/*
	 * Set the configuration of ingress queue.
	 *
	 */

	cmdp->type_to_iqandstindex |= csio_htonl(
				V_FW_IQ_CMD_IQANDST(iq_params->iqandst)	|
				V_FW_IQ_CMD_IQANUS(iq_params->iqanus)	|
				V_FW_IQ_CMD_IQANUD(iq_params->iqanud)	|
				V_FW_IQ_CMD_IQANDSTINDEX(
						iq_params->iqandstindex));

	cmdp->iqdroprss_to_iqesize |= csio_htons(
			V_FW_IQ_CMD_IQDROPRSS(iq_params->iqdroprss)	|
			V_FW_IQ_CMD_IQPCIECH(iq_params->iqpciech)	|
			V_FW_IQ_CMD_IQDCAEN(iq_params->iqdcaen)		|
			V_FW_IQ_CMD_IQDCACPU(iq_params->iqdcacpu)	|
			V_FW_IQ_CMD_IQINTCNTTHRESH(iq_params->iqintcntthresh) |
			V_FW_IQ_CMD_IQO(iq_params->iqo)			|
			V_FW_IQ_CMD_IQCPRIO(iq_params->iqcprio)		|
			V_FW_IQ_CMD_IQESIZE(iq_params->iqesize));

	/*cmdp->iqdroprss_to_iqesize |= csio_htons(F_FW_IQ_CMD_IQGTSMODE);*/

	cmdp->iqsize |= csio_htons(iq_params->iqsize);

	cmdp->iqaddr |= csio_cpu_to_be64(iq_params->iqaddr);

	/*
	 * Parameters specific ingress queue with free list(s) and interrupt
	 * capability.
	 *
	 */

	if (iq_params->type == 0) {

		cmdp->iqns_to_fl0congen |= csio_htonl(
		V_FW_IQ_CMD_IQFLINTIQHSEN(iq_params->iqflintiqhsen)	|
		V_FW_IQ_CMD_IQFLINTCONGEN(iq_params->iqflintcongen)
		);

#if 0 /* REVISIT: CNGCHMAP is now a FL 0 setting */
		cmdp->iqns_to_fl0congen |= csio_htonl(
		V_FW_IQ_CMD_IQFLINTIQHSEN(iq_params->iqflintiqhsen)	|
		V_FW_IQ_CMD_IQFLINTCONGEN(iq_params->iqflintcongen)	|
		V_FW_IQ_CMD_IQFLINTCNGCHMAP(iq_params->iqflintcngchmap)
		);
#endif
	}

	/*
	 * Set parameters specific Free-lists.
	 *
	 */

	if (iq_params->fl0size && iq_params->fl0addr &&
			(iq_params->fl0id != 0xFFFF)) {

		cmdp->iqns_to_fl0congen |= csio_htonl(
		V_FW_IQ_CMD_FL0HOSTFCMODE(iq_params->fl0hostfcmode)	|
		V_FW_IQ_CMD_FL0CPRIO(iq_params->fl0cprio)		|
		V_FW_IQ_CMD_FL0PADEN(iq_params->fl0paden)		|
		V_FW_IQ_CMD_FL0PACKEN(iq_params->fl0packen)		|
		V_FW_IQ_CMD_FL0CONGEN(iq_params->fl0congen));


		cmdp->fl0dcaen_to_fl0cidxfthresh |= csio_htons(
		V_FW_IQ_CMD_FL0DCAEN(iq_params->fl0dcaen)		|
		V_FW_IQ_CMD_FL0DCACPU(iq_params->fl0dcacpu)		|
		V_FW_IQ_CMD_FL0FBMIN(iq_params->fl0fbmin)		|
		V_FW_IQ_CMD_FL0FBMAX(iq_params->fl0fbmax)		|
		V_FW_IQ_CMD_FL0CIDXFTHRESHO(iq_params->fl0cidxfthresho)	|
		V_FW_IQ_CMD_FL0CIDXFTHRESH(iq_params->fl0cidxfthresh));

		cmdp->fl0size |= csio_htons(iq_params->fl0size);


		cmdp->fl0addr |= csio_cpu_to_be64(iq_params->fl0addr);

	}

	if (iq_params->fl1size && iq_params->fl1addr &&
			(iq_params->fl1id != 0xFFFF)) {

		cmdp->fl1cngchmap_to_fl1congen |= csio_htonl(
		V_FW_IQ_CMD_FL1HOSTFCMODE(iq_params->fl1hostfcmode)	|
		V_FW_IQ_CMD_FL1CPRIO(iq_params->fl1cprio)		|
		V_FW_IQ_CMD_FL1PADEN(iq_params->fl1paden)		|
		V_FW_IQ_CMD_FL1PACKEN(iq_params->fl1packen)		|
		V_FW_IQ_CMD_FL1CONGEN(iq_params->fl1congen));


		cmdp->fl1dcaen_to_fl1cidxfthresh |= csio_htons(
		V_FW_IQ_CMD_FL1DCAEN(iq_params->fl1dcaen)		|
		V_FW_IQ_CMD_FL1DCACPU(iq_params->fl1dcacpu)		|
		V_FW_IQ_CMD_FL1FBMIN(iq_params->fl1fbmin)		|
		V_FW_IQ_CMD_FL1FBMAX(iq_params->fl1fbmax)		|
		V_FW_IQ_CMD_FL1CIDXFTHRESHO(iq_params->fl1cidxfthresho)	|
		V_FW_IQ_CMD_FL1CIDXFTHRESH(iq_params->fl1cidxfthresh));


		cmdp->fl1size |= csio_htons(iq_params->fl1size);

		cmdp->fl1addr |= csio_cpu_to_be64(iq_params->fl1addr);

	}

	return;

} /* csio_mb_iq_write */

/*
 * csio_mb_iq_alloc_write - Initializes the mailbox command for allocation
 *				writing into an Ingress DMA Queue.
 *
 * @cmdp: Command to initialize
 * @iq_params: Ingress queue params needed for allocation & writing.
 *
 *
 */
void
csio_mb_iq_alloc_write(struct fw_iq_cmd *cmdp,
		struct csio_iq_params *iq_params)
{
	csio_mb_iq_alloc(cmdp, iq_params);

	csio_mb_iq_write(cmdp, CSIO_TRUE, iq_params);

	return;

} /* csio_mb_iq_alloc_write */

/*
 * csio_mb_iq_alloc_write_rsp - Process the allocation & writing
 *				of ingress DMA queue mailbox's response.
 *
 * @cmdp: Mailbox response.
 * @iq_params: Ingress queue parameters, after allocation and write.
 *
 */
void
csio_mb_iq_alloc_write_rsp(struct fw_iq_cmd *rsp,
			   struct csio_iq_params *iq_params)
{

	/*
	 * Get the Physiqid & Iqid
	 *
	 */

	iq_params->physiqid = csio_ntohs(rsp->physiqid);
	iq_params->iqid = csio_ntohs(rsp->iqid);

	/*
	 * Get the Free-list 0 & 1 IDs.
	 *
	 */

	iq_params->fl0id = csio_ntohs(rsp->fl0id);
	iq_params->fl1id = csio_ntohs(rsp->fl1id);

	return;

} /* csio_mb_iq_alloc_write_rsp */

/*
 * csio_mb_iq_start_stop - Initializes the mailbox command for starting or
 *				stopping an Ingress DMA Queue.
 *
 * @cmdp: Command to initialize
 * @iq_params: Ingress queue params - for starting/stopping the queue.
 *
 *
 */
void
csio_mb_iq_start_stop(struct fw_iq_cmd *cmdp, struct csio_iq_params *iq_params)
{

	uint32_t iq_start_stop = (iq_params->iq_start)	?
				F_FW_IQ_CMD_IQSTART 	:
				F_FW_IQ_CMD_IQSTOP;

	csio_memset(cmdp, 0, sizeof(*cmdp));
	/*
	 * Set REQUEST, WRITE bits. And also set PFN, VFN.
	 *
	 */

	cmdp->op_to_vfn = csio_htonl(V_FW_CMD_OP(FW_IQ_CMD) 		|
				F_FW_CMD_REQUEST | F_FW_CMD_WRITE	|
				V_FW_IQ_CMD_PFN(iq_params->pfn) 	|
				V_FW_IQ_CMD_VFN(iq_params->vfn));

	/*
	 * Set  IQSTART/IQSTOP and LEN16.
	 *
	 */

	cmdp->alloc_to_len16 = csio_htonl( iq_start_stop |
				V_FW_CMD_LEN16(sizeof(*cmdp) / 16));

	/*
	 * Set the Ingress Id.
	 *
	 */

	cmdp->iqid = csio_htons(iq_params->iqid);

	/*
	 * Set the free-list 0 & 1 id.
	 *
	 */

	cmdp->fl0id = csio_htons(iq_params->fl0id);
	cmdp->fl1id = csio_htons(iq_params->fl1id);

	return;

} /* csio_mb_iq_start_stop */

/*
 * csio_mb_iq_free - Initializes the mailbox command for freeing a
 *				specified Ingress DMA Queue.
 *
 * @cmdp: Command to initialize
 * @iq_params: Parameters of ingress queue, that is to be freed.
 *
 *
 */
void
csio_mb_iq_free(struct fw_iq_cmd *cmdp,	struct csio_iq_params *iq_params)
{
	csio_memset(cmdp, 0, sizeof(*cmdp));
	/*
	 * Set REQUEST, WRITE bits. And also set PFN, VFN.
	 */
	cmdp->op_to_vfn = csio_htonl(V_FW_CMD_OP(FW_IQ_CMD) 		|
				F_FW_CMD_REQUEST | F_FW_CMD_EXEC	|
				V_FW_IQ_CMD_PFN(iq_params->pfn) 	|
				V_FW_IQ_CMD_VFN(iq_params->vfn));
	/*
	 * Set FREE-bit and LEN16.
	 */
	cmdp->alloc_to_len16 = csio_htonl(F_FW_IQ_CMD_FREE |
				V_FW_CMD_LEN16(sizeof(*cmdp) / 16));
	cmdp->type_to_iqandstindex = csio_htonl(
					V_FW_IQ_CMD_TYPE(iq_params->type));

	/*
	 * Set the Ingress Id.
	 */
	cmdp->iqid = csio_htons(iq_params->iqid);

	/*
	 * Set the free-list 0 & 1 id.
	 */
	cmdp->fl0id = csio_htons(iq_params->fl0id);
	cmdp->fl1id = csio_htons(iq_params->fl1id);

	return;

} /* csio_mb_iq_free */

/*
 * csio_mb_eq_ofld_alloc - Initializes the mailbox command for allocating
 *				an offload-egress queue.
 *
 * @cmdp: Command to initialize
 * @eq_ofld_params: (Offload) Egress queue paramters.
 *
 *
 */
void
csio_mb_eq_ofld_alloc(struct fw_eq_ofld_cmd *cmdp,
		struct csio_eq_params *eq_ofld_params)
{
	csio_memset(cmdp, 0, sizeof(*cmdp));
	cmdp->op_to_vfn = csio_htonl(V_FW_CMD_OP(FW_EQ_OFLD_CMD)	|
				F_FW_CMD_REQUEST | F_FW_CMD_EXEC	|
				V_FW_EQ_OFLD_CMD_PFN(eq_ofld_params->pfn) |
				V_FW_EQ_OFLD_CMD_VFN(eq_ofld_params->vfn));

	cmdp->alloc_to_len16 = csio_htonl(F_FW_EQ_OFLD_CMD_ALLOC	|
				V_FW_CMD_LEN16(sizeof(*cmdp) / 16));

	return;

} /* csio_mb_eq_ofld_alloc */

/*
 * csio_mb_eq_ofld_write - Initializes the mailbox command for writing
 *				an alloacted offload-egress queue.
 *
 * @cmdp: Command to initialize
 * @cascaded_req: TRUE - if this request is cascased with Eq-alloc request.
 * @eq_ofld_params: (Offload) Egress queue paramters.
 *
 *
 * NOTE: We OR relevant bits with cmdp->XXX, instead of just equating,
 * because this EQ write request can be cascaded with a previous
 * EQ alloc request, and we dont want to over-write the bits set by
 * that request. This logic will work even in a non-cascaded case, since the
 * cmdp structure is zeroed out by CSIO_INIT_MBP.
 */
void
csio_mb_eq_ofld_write(struct fw_eq_ofld_cmd *cmdp, bool cascaded_req,
		struct csio_eq_params *eq_ofld_params)
{
	uint32_t eq_start_stop = (eq_ofld_params->eqstart) 	?
				F_FW_EQ_OFLD_CMD_EQSTART	:
				F_FW_EQ_OFLD_CMD_EQSTOP;

	/*
	 * If this EQ write is cascaded with EQ alloc request, do not
	 * re-initialize with 0's.
	 *
	 */

	if (!cascaded_req)
		csio_memset(cmdp, 0, sizeof(*cmdp));

	cmdp->op_to_vfn |= csio_htonl(V_FW_CMD_OP(FW_EQ_OFLD_CMD)	|
				F_FW_CMD_REQUEST | F_FW_CMD_WRITE	|
				V_FW_EQ_OFLD_CMD_PFN(eq_ofld_params->pfn) |
				V_FW_EQ_OFLD_CMD_VFN(eq_ofld_params->vfn));

	cmdp->alloc_to_len16 |= csio_htonl(eq_start_stop		|
				V_FW_CMD_LEN16(sizeof(*cmdp) / 16));

	cmdp->eqid_pkd |= csio_htonl(
				V_FW_EQ_OFLD_CMD_EQID(eq_ofld_params->eqid));

	cmdp->fetchszm_to_iqid |= csio_htonl(
		V_FW_EQ_OFLD_CMD_HOSTFCMODE(eq_ofld_params->hostfcmode)	|
		V_FW_EQ_OFLD_CMD_CPRIO(eq_ofld_params->cprio)		|
		V_FW_EQ_OFLD_CMD_PCIECHN(eq_ofld_params->pciechn)	|
		V_FW_EQ_OFLD_CMD_IQID(eq_ofld_params->iqid));

	cmdp->dcaen_to_eqsize |= csio_htonl(
		V_FW_EQ_OFLD_CMD_DCAEN(eq_ofld_params->dcaen)		|
		V_FW_EQ_OFLD_CMD_DCACPU(eq_ofld_params->dcacpu)		|
		V_FW_EQ_OFLD_CMD_FBMIN(eq_ofld_params->fbmin)		|
		V_FW_EQ_OFLD_CMD_FBMAX(eq_ofld_params->fbmax)		|
		V_FW_EQ_OFLD_CMD_CIDXFTHRESHO(eq_ofld_params->cidxfthresho) |
		V_FW_EQ_OFLD_CMD_CIDXFTHRESH(eq_ofld_params->cidxfthresh) |
		V_FW_EQ_OFLD_CMD_EQSIZE(eq_ofld_params->eqsize));

	cmdp->eqaddr |= csio_cpu_to_be64(eq_ofld_params->eqaddr);

	return;

} /* csio_mb_eq_ofld_write */

/*
 * csio_mb_eq_ofld_alloc_write - Initializes the mailbox command for allocation
 *				writing into an Engress DMA Queue.
 *
 * @cmdp: Command to initialize
 * @eq_ofld_params: (Offload) Egress queue paramters.
 *
 *
 */
void
csio_mb_eq_ofld_alloc_write(struct fw_eq_ofld_cmd *cmdp,
		struct csio_eq_params *eq_ofld_params)
{
	csio_mb_eq_ofld_alloc(cmdp, eq_ofld_params);

	csio_mb_eq_ofld_write(cmdp, CSIO_TRUE, eq_ofld_params);

	return;

} /* csio_mb_eq_ofld_alloc_write */

/*
 * csio_mb_eq_ofld_alloc_write_rsp - Process the allocation
 *				& write egress DMA queue mailbox's response.
 *
 * @rsp: Mailbox response
 * @eq_ofld_params: (Offload) Egress queue paramters.
 *
 */
void
csio_mb_eq_ofld_alloc_write_rsp(struct fw_eq_ofld_cmd *rsp,
		struct csio_eq_params *eq_ofld_params)
{
	eq_ofld_params->eqid = G_FW_EQ_OFLD_CMD_EQID(
			csio_ntohl(rsp->eqid_pkd));
	eq_ofld_params->physeqid = G_FW_EQ_OFLD_CMD_PHYSEQID(
			csio_ntohl(rsp->physeqid_pkd));

	return;

} /* csio_mb_eq_ofld_alloc_write_rsp */

/*
 * csio_mb_eq_ofld_start_stop - Initializes the mailbox command for starting or
 *				stopping an Engress DMA Queue.
 *
 * @cmdp: Command to initialize
 * @eq_ofld_params: (Offload) Egress queue params - for starting/stopping.
 *
 *
 */
void
csio_mb_eq_ofld_start_stop(struct fw_eq_ofld_cmd *cmdp,
		struct csio_eq_params *eq_ofld_params)
{
	uint16_t eq_start_stop = (eq_ofld_params->eqstart) 	?
				F_FW_EQ_OFLD_CMD_EQSTART	:
				F_FW_EQ_OFLD_CMD_EQSTOP;

	csio_memset(cmdp, 0, sizeof(*cmdp));		
	cmdp->op_to_vfn = csio_htonl(V_FW_CMD_OP(FW_EQ_OFLD_CMD)	|
				F_FW_CMD_REQUEST | F_FW_CMD_EXEC	|
				V_FW_EQ_OFLD_CMD_PFN(eq_ofld_params->pfn) |
				V_FW_EQ_OFLD_CMD_VFN(eq_ofld_params->vfn));

	cmdp->alloc_to_len16 = csio_htonl(eq_start_stop			|
				V_FW_CMD_LEN16(sizeof(*cmdp) / 16));

	cmdp->eqid_pkd = csio_htonl(
				V_FW_EQ_OFLD_CMD_EQID(eq_ofld_params->eqid));

	return;

} /* csio_mb_eq_ofld_start_stop */


/*
 * csio_mb_eq_ofld_free - Initializes the mailbox command for freeing a
 *				specified Engress DMA Queue.
 *
 * @cmdp: Command to initialize
 * @eq_ofld_params: (Offload) Egress queue paramters, that is to be freed.
 *
 *
 */
void
csio_mb_eq_ofld_free(struct fw_eq_ofld_cmd *cmdp,
		struct csio_eq_params *eq_ofld_params)
{
	csio_memset(cmdp, 0, sizeof(*cmdp));		
	cmdp->op_to_vfn = csio_htonl(V_FW_CMD_OP(FW_EQ_OFLD_CMD)	|
				F_FW_CMD_REQUEST | F_FW_CMD_EXEC	|
				V_FW_EQ_OFLD_CMD_PFN(eq_ofld_params->pfn) |
				V_FW_EQ_OFLD_CMD_VFN(eq_ofld_params->vfn));

	/*
	 * Set FREE-bit and LEN16.
	 */
	cmdp->alloc_to_len16 = csio_htonl( F_FW_EQ_OFLD_CMD_FREE |
				V_FW_CMD_LEN16(sizeof(*cmdp) / 16));
	cmdp->eqid_pkd = csio_htonl(
				V_FW_EQ_OFLD_CMD_EQID(eq_ofld_params->eqid));

	return;

} /* csio_mb_eq_ofld_free */

void
csio_mb_dcbx_read_port_init_mb(struct fw_port_cmd *cmdp,
			     uint8_t portid,
			     enum fw_port_action action,
			     enum fw_port_dcb_type type)
{
	csio_memset(cmdp, 0, sizeof(*cmdp));		
	cmdp->op_to_portid = csio_htonl(V_FW_CMD_OP(FW_PORT_CMD) |
					F_FW_CMD_REQUEST |
					F_FW_CMD_READ |
					V_FW_PORT_CMD_PORTID(portid));
	cmdp->action_to_len16 = csio_htonl(
			V_FW_PORT_CMD_ACTION(action) |
			V_FW_CMD_LEN16(2));
	/* Type is being set for all port params through pgid union */
	cmdp->u.dcb.pgid.type = type;
	cmdp->u.dcb.pgid.apply_pkd = 0;
}

void
csio_mb_dump_fw_dbg(struct csio_hw *hw, __be64 *cmd)
{
	struct fw_debug_cmd 	*dbg = (struct fw_debug_cmd *)cmd;	

	/* REVISIT: FW today uses 1 for prt and 0 for assert - undocumented */
	if ((G_FW_DEBUG_CMD_TYPE(csio_ntohl(dbg->op_type))) == 1) {
		csio_info(hw, "FW print message:\n");
		csio_info(hw, "\tdebug->dprtstridx = %d\n",
			    csio_ntohs(dbg->u.prt.dprtstridx));
		csio_info(hw, "\tdebug->dprtstrparam0 = 0x%x\n",
			    csio_ntohl(dbg->u.prt.dprtstrparam0));
		csio_info(hw, "\tdebug->dprtstrparam1 = 0x%x\n",
			    csio_ntohl(dbg->u.prt.dprtstrparam1));
		csio_info(hw, "\tdebug->dprtstrparam2 = 0x%x\n",
			    csio_ntohl(dbg->u.prt.dprtstrparam2));
		csio_info(hw, "\tdebug->dprtstrparam3 = 0x%x\n",
			    csio_ntohl(dbg->u.prt.dprtstrparam3));
	} else {
		/* This is a FW assertion */
		csio_fatal(hw, "FW assertion at %.16s:%u, val0 %#x, val1 %#x\n",
			    dbg->u.assert.filename_0_7,
			    csio_ntohl(dbg->u.assert.line),
			    csio_ntohl(dbg->u.assert.x),
			    csio_ntohl(dbg->u.assert.y));
	}

	return;
}

static void
csio_mb_portmod_changed(struct csio_hw *hw, uint8_t port_id)
{
	static const char *mod_str[] = {
		NULL, "LR", "SR", "ER", "TWINAX", "active TWINAX", "LRM"
	};

	struct csio_t4port *port = &hw->t4port[port_id];

	if (port->mod_type == FW_PORT_MOD_TYPE_NONE)
		csio_info(hw, "Port:%d - port module unplugged\n", port_id);
	else if (port->mod_type < CSIO_ARRAY_SIZE(mod_str))
		csio_info(hw, "Port:%d - %s port module inserted\n", port_id,
			  mod_str[port->mod_type]);
	else if (port->mod_type == FW_PORT_MOD_TYPE_NOTSUPPORTED)
		csio_info(hw, "Port:%d - unsupported optical port module "
			  "inserted\n", port_id);
	else if (port->mod_type == FW_PORT_MOD_TYPE_UNKNOWN)
		csio_info(hw, "Port:%d - unknown port module inserted, forcing "
			  "TWINAX\n", port_id);
	else if (port->mod_type == FW_PORT_MOD_TYPE_ERROR)
		csio_info(hw, "Port:%d - transceiver module error\n", port_id);
	else
		csio_info(hw, "Port:%d - unknown module type %d inserted\n",
			  port_id, port->mod_type);
}

csio_retval_t
csio_mb_fwevt_handler(struct csio_hw *hw, __be64 *cmd)
{
	uint8_t opcode = *(uint8_t *)cmd;
	struct fw_port_cmd *pcmd;
	uint8_t port_id;
	uint32_t link_status;
	uint16_t action;
	uint8_t mod_type;

	if (opcode == FW_PORT_CMD) {
		pcmd = (struct fw_port_cmd *)cmd;
		port_id = G_FW_PORT_CMD_PORTID(
				csio_ntohl(pcmd->op_to_portid));
		action = G_FW_PORT_CMD_ACTION(
				csio_ntohl(pcmd->action_to_len16));
		if (action != FW_PORT_ACTION_GET_PORT_INFO) {
			csio_err(hw, "Unhandled FW_PORT_CMD action: %u\n",
				action);
			return CSIO_INVAL;
		}

		link_status = csio_ntohl(pcmd->u.info.lstatus_to_modtype);
		mod_type = G_FW_PORT_CMD_MODTYPE(link_status);

		hw->t4port[port_id].link_status =
			G_FW_PORT_CMD_LSTATUS(link_status);
		hw->t4port[port_id].link_speed =
			G_FW_PORT_CMD_LSPEED(link_status);

		csio_info(hw, "Port:%x - LINK %s\n", port_id,
			G_FW_PORT_CMD_LSTATUS(link_status) ? "UP":"DOWN");

		if (mod_type != hw->t4port[port_id].mod_type) {
			hw->t4port[port_id].mod_type = mod_type;
			csio_mb_portmod_changed(hw, port_id);
		}
	} else if (opcode == FW_DEBUG_CMD) {
		csio_mb_dump_fw_dbg(hw, cmd);
	} else {
		csio_dbg(hw, "Gen MB can't handle op:0x%x on evtq.\n", opcode);
		return CSIO_INVAL;
	}

	return CSIO_SUCCESS;
}
