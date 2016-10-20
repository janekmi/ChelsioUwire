/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description:
 *
 */
#include <linux/version.h>
#include <linux/spinlock.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/ctype.h>
#include <linux/pci.h>
#include <scsi/scsi_host.h>

#include <scst.h>

#include <csio_sal_api.h>

#define SCST_SAL_DESC "Chelsio Target SCST SCSI Abstraction Layer (SAL)"

/* 
 * Here are the different levels :
 * EMERG   
 * ALERT   
 * CRIT    
 * ERR     
 * WARNING 
 * NOTICE  
 * INFO    
 * DEBUG   
*/
#define csio_scst_msg(level, fmt, ...)	\
		printk(KERN_##level  fmt, ## __VA_ARGS__)

#ifdef __CSIO_DEBUG__
#define csio_scst_dbg(fmt, ...)		printk(fmt, ## __VA_ARGS__)
#define CSIO_SCST_ASSERT(__cond)	BUG_ON(!__cond)
#else
#define csio_scst_dbg(fmt, ...)
#define CSIO_SCST_ASSERT(__cond)
#endif

static struct scst_tgt_template csio_scst_data;
static int csio_scst_fcoe_init_transport_id(struct scst_tgt *,
					    struct scst_session *, uint8_t **);

int csio_ddp_thres = -1;

/* Registry functions */
/* This is called if SCST_ATOMIC is used above */
static void
csio_scst_regssn_cbfn(struct scst_session *sess, void *data, int status)
{
	/* 
	 * Do nothin for now. If we ever use SCST_ATOMIC below, then
	 * this function will be called once a session is established.
	 * If there was a failure in establishing a session, then 
	 * this function needs to unregister the session, and also
	 * notify the target driver about the failure. We will
	 * define a driver-exported function that SAL can call upon
	 * session registration failure. Until then do nothing.
	 */
	return;
}

csio_ssn_handle_t
csio_scst_reg_ssn(csio_tgt_handle_t tgt, csio_sal_reg_params_t *params)
{
	char name[32];
	uint8_t	*wwpn;

	wwpn = &params->un.fcoe_params.wwpn[0];
	sprintf(name, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
		wwpn[0], wwpn[1], wwpn[2], wwpn[3],
		wwpn[4], wwpn[5], wwpn[6], wwpn[7]);

	return (csio_ssn_handle_t)scst_register_session(
					(struct scst_tgt *)tgt,
					SCST_NON_ATOMIC, name,
					params->priv, params->priv,
					csio_scst_regssn_cbfn);
}

void sess_unreg_done(struct scst_session *sess)
{
	csio_sal_ops_t *sops = NULL;
	void *rn = scst_sess_get_tgt_priv(sess);
	sops = csio_sal_get_sops(CSIO_SAL_PROT_FCOE);

	if (sops)
		csio_sal_sess_unreg_done(sops, rn);
}

void
csio_scst_unreg_ssn(csio_ssn_handle_t ssn)
{
	if (ssn)
		scst_unregister_session((struct scst_session *)ssn, 0, sess_unreg_done);
}

csio_tgt_handle_t
csio_scst_reg_tgt(csio_sal_lport_params_t *params)
{
	char name[32];
	uint8_t *wwpn;

	wwpn = &params->un.fcoe_params.wwpn[0];
	sprintf(name, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
		wwpn[0], wwpn[1], wwpn[2], wwpn[3],
		wwpn[4], wwpn[5], wwpn[6], wwpn[7]);

	csio_scst_dbg("csioscst: Registering target %s..\n", name);
	return (csio_tgt_handle_t)scst_register_target(
					&csio_scst_data, name);
}

void
csio_scst_unreg_tgt(csio_tgt_handle_t tgt)
{
	csio_scst_dbg("csioscst: Unregistering target %p\n", tgt);

	scst_unregister_target((struct scst_tgt *)tgt);
}

csio_cmd_handle_t
csio_scst_rcv_cmd(csio_ssn_handle_t ssn, csio_sal_cmd_t *scmd)
{
	struct scst_cmd *cmd;
	csio_sal_req_t *req;

	cmd = scst_rx_cmd((struct scst_session *)ssn, scmd->lun, scmd->slun,
			  scmd->cdb, scmd->scdb,
			  scmd->atomic ? SCST_ATOMIC : SCST_NON_ATOMIC);
	if (unlikely(!cmd))
		return NULL;

	scst_cmd_set_tag(cmd, scmd->tag);
	scst_cmd_set_tgt_priv(cmd, scmd->priv);
	scst_cmd_set_no_sgv(cmd);

	req = scmd->priv;

	switch (req->ta & PROTO_FCP_PTA_MASK) {
	case PROTO_FCP_PTA_SIMPLE:
		scst_cmd_set_queue_type(cmd, SCST_CMD_QUEUE_SIMPLE);
		break;
	case PROTO_FCP_PTA_HEADQ:
		scst_cmd_set_queue_type(cmd, SCST_CMD_QUEUE_HEAD_OF_QUEUE);
		break;
	case PROTO_FCP_PTA_ORDERED:
		scst_cmd_set_queue_type(cmd, SCST_CMD_QUEUE_ORDERED);
		break;
	case PROTO_FCP_PTA_ACA:
		scst_cmd_set_queue_type(cmd, SCST_CMD_QUEUE_ACA);
		break;
	case PROTO_FCP_PTA_UNTAGGED:
		scst_cmd_set_queue_type(cmd, SCST_CMD_QUEUE_UNTAGGED);
		break;
	default:
		csio_scst_dbg("csio_scst_rcv_data cmd:%p "
			       "req:%p illegal ta\n", cmd, req);
	}
	
	return (csio_cmd_handle_t)cmd;
}

/* Called from interrupt context */
void
csio_scst_start_cmd(csio_cmd_handle_t cmd)
{
	scst_cmd_init_done((struct scst_cmd *)cmd, SCST_CONTEXT_DIRECT);
}

void
csio_scst_rcv_data(csio_cmd_handle_t cmd, int rx_status)
{
	csio_sal_req_t *req;
	struct scst_cmd *lcmd = (struct scst_cmd *)cmd;
	uint16_t data_direction;
	
	CSIO_SCST_ASSERT(cmd);
	
	data_direction = scst_cmd_get_data_direction(lcmd);
	req = scst_cmd_get_tgt_priv(lcmd);

	if (req->nsge_map > 0) {
		pci_unmap_sg((struct pci_dev *)req->os_dev,
				scst_cmd_get_sg(lcmd), scst_cmd_get_sg_cnt(lcmd),
				scst_to_tgt_dma_dir(data_direction));
		req->nsge_map = 0;
	}

	if (likely(req->req_status == CSIO_DRV_ST_SUCCESS))
		scst_rx_data(lcmd, SCST_RX_STATUS_SUCCESS,
				SCST_CONTEXT_DIRECT);
	else {
		scst_rx_data(lcmd, SCST_RX_STATUS_ERROR_FATAL, SCST_CONTEXT_DIRECT);
	}
}

void
csio_scst_cmd_done(csio_cmd_handle_t cmd, csio_sal_req_t *req)
{
	struct scst_cmd *lcmd = (struct scst_cmd *)cmd;
	uint16_t data_direction;
	
	/*
	 * There is no 'done' SCST operation for Task Management, hence
	 * do not access 'cmd', as it maye be invalid. Instead just free
	 * the driver request.
	 */
	if (unlikely(req->tm_op)) {
		csio_sal_free(req);
		return;
	}

	CSIO_SCST_ASSERT(cmd);
	
	data_direction = scst_cmd_get_data_direction(lcmd);
	
	if (likely(req->req_status == CSIO_DRV_ST_SUCCESS))
		scst_set_delivery_status(lcmd, SCST_CMD_DELIVERY_SUCCESS);
	else if (req->req_status == CSIO_DRV_ST_FAILED)
		scst_set_delivery_status(lcmd, SCST_CMD_DELIVERY_FAILED);
	else if (req->req_status == CSIO_DRV_ST_ABORTED)
		scst_set_delivery_status(lcmd, SCST_CMD_DELIVERY_ABORTED);

	scst_tgt_cmd_done(lcmd, SCST_CONTEXT_SAME);
}

csio_tret_t
csio_scst_rcv_tm(csio_ssn_handle_t ssn, csio_sal_cmd_t *scmd, 
		 csio_cmd_handle_t *cmdp)
{
	struct scst_rx_mgmt_params params;

	*cmdp = NULL;

	memset(&params, 0, sizeof(params));
	switch (scmd->tm_op) {
	case CSIO_SAL_TM_ABORT_TASK:
		/*
		 * NOTE: An abort of a task management function is a no-op
		 * at SCST. A management function request is enqueued into the
		 * 'scst_active_mgmt_cmd_list' list, whereas the tag for an
		 * abort TM is searched in a session's 'sess->sess_cmd_list'
		 * (see __scst_find_cmd_by_tag()). As a result, an abort sent
		 * for a TM (like lun reset) is always going to return a
		 * SCST_MGMT_STATUS_TASK_NOT_EXIST status. Additionally, it
		 * also creates an addition scst_mcmd structure, referencing
		 * our csio_sal_req. This doesnt go down well with our state
		 * machine. Instead, we just return from here, if the abort is
		 * for a TM request. When the TM returns from scst, the core
		 * target driver handles the response appropriately, since it
		 * has already marked the TM as aborted.
		 */
		params.fn = SCST_ABORT_TASK;
		params.tag_set = 1;
		params.tag = scmd->tag;
		break;
	case CSIO_SAL_TM_ABORT_TASK_SET:
		params.fn = SCST_ABORT_TASK_SET;
		params.lun = scmd->lun;
		params.lun_len = scmd->slun;
		params.lun_set = 1;
		break;
	case CSIO_SAL_TM_CLEAR_ACA:
		params.fn = SCST_CLEAR_ACA;
		params.lun = scmd->lun;
		params.lun_len = scmd->slun;
		params.lun_set = 1;
		break;
	case CSIO_SAL_TM_CLEAR_TASK_SET:
		params.fn = SCST_CLEAR_TASK_SET;
		params.lun = scmd->lun;
		params.lun_len = scmd->slun;
		params.lun_set = 1;
		break;
	case CSIO_SAL_TM_LUN_RESET:
		params.fn = SCST_LUN_RESET;
		params.lun = scmd->lun;
		params.lun_len = scmd->slun;
		params.lun_set = 1;
		break;
	case CSIO_SAL_TM_TARGET_RESET:
		params.fn = SCST_TARGET_RESET;
		break;
	default:
		csio_scst_dbg("csio_scst_rcv_tm ssn:%p"
			      "priv:%p illegal TM op %d\n", ssn,
			      scmd->priv, scmd->tm_op);
		return CSIO_TINVAL;
	}
	
	params.atomic = (scmd->atomic ? SCST_ATOMIC : SCST_NON_ATOMIC);
	params.tgt_priv = scmd->priv;

	if (!scst_rx_mgmt_fn((struct scst_session *)ssn, &params))
		return CSIO_TSUCCESS;

	return CSIO_TINVAL;
}

/* Target driver interfaces */
static csio_sal_ops_t csio_scst_sal_ops = {
	.sal_version = CHTGT_SAL_VERSION,
	.proto = CSIO_SAL_PROT_FCOE,
	.sal_reg_tgt = csio_scst_reg_tgt,
	.sal_unreg_tgt = csio_scst_unreg_tgt,
	.sal_reg_ssn = csio_scst_reg_ssn,
	.sal_unreg_ssn = csio_scst_unreg_ssn,
	.sal_rcv_cmd = csio_scst_rcv_cmd,
	.sal_start_cmd = csio_scst_start_cmd,
	.sal_rcv_data = csio_scst_rcv_data,
	.sal_cmd_done = csio_scst_cmd_done,
	.sal_rcv_tm = csio_scst_rcv_tm
};

/* SCST callbacks */
static int
csio_scst_xmit_response(struct scst_cmd *cmd)
{
	int status = SCST_TGT_RES_SUCCESS;
	csio_sal_req_t *req = scst_cmd_get_tgt_priv(cmd);
	uint16_t data_direction;
	csio_tret_t ret;
	uint8_t *cdb;
	uint8_t cdb_len, i;

	if (unlikely(scst_cmd_aborted(cmd))) {
		scst_set_delivery_status(cmd, SCST_CMD_DELIVERY_ABORTED);
		csio_scst_dbg("csioscst: Cmd %p (req: %p) aborted\n", cmd, req);
		return SCST_TGT_RES_FATAL_ERROR;
	}
	
	req->send_status = scst_cmd_get_is_send_status(cmd);
	if (unlikely(!req->send_status)) {
		csio_scst_dbg("csioscst: Cmd %p (req: %p) no status\n", cmd, req);
		scst_set_delivery_status(cmd, SCST_CMD_DELIVERY_FAILED);
		return SCST_TGT_RES_FATAL_ERROR;
	}

	req->buff_len = scst_cmd_get_bufflen(cmd);
	data_direction = scst_cmd_get_data_direction(cmd);
	req->scsi_status = scst_cmd_get_status(cmd);
	req->sense_buffer = scst_cmd_get_sense_buffer(cmd);
	req->sense_buffer_len = scst_cmd_get_sense_buffer_len(cmd);
	req->data_len = scst_cmd_get_resp_data_len(cmd);
	req->nsge_map = 0;

	if (req->data_len > 0) {
		if (unlikely((scst_cmd_get_bufflen(cmd) <= 0)
					|| (scst_cmd_get_sg_cnt(cmd) <= 0)
					|| (scst_cmd_get_sg(cmd) == NULL))) {
			csio_scst_msg(ERR, "csioscst: xmit_response DMA"
					" mapping failed %p(req: %p) buff_len:%u direction:%u scsi_status:%u"
					" sense_buffer_len:%u data_len:%u sg:%p sg_cnt:%d\n",
					cmd ,req, req->buff_len, data_direction, req->scsi_status,
					req->sense_buffer_len, req->data_len, scst_cmd_get_sg(cmd),
					scst_cmd_get_sg_cnt(cmd));
			cdb = (uint8_t *)scst_cmd_get_cdb(cmd);
			cdb_len = scst_cmd_get_cdb_len(cmd);
			csio_scst_msg(ERR,"cdb_len %u\n", cdb_len);

			for (i = 0; i < cdb_len; i++) {
				csio_scst_msg(ERR,"cdb: 0x%x\n", cdb[i]);
			}
			scst_set_delivery_status(cmd, SCST_CMD_DELIVERY_FAILED);
			return SCST_TGT_RES_FATAL_ERROR;
		}
		req->os_sge = (void *)scst_cmd_get_sg(cmd);
		req->nsge = scst_cmd_get_sg_cnt(cmd);

		ret = csio_sal_xmit(req);
		if (unlikely(ret != CSIO_TSUCCESS)) {
			csio_scst_msg(ERR, "csioscst: xmit error %d req:%p\n",
					ret, req);
			if (ret == CSIO_TBUSY)
				return SCST_TGT_RES_QUEUE_FULL;
			else {
				scst_set_delivery_status(cmd, SCST_CMD_DELIVERY_FAILED);
				return SCST_TGT_RES_FATAL_ERROR;
			}
		}
	} else if (req->send_status) {
		ret = csio_sal_rsp(req);
		if (unlikely(ret != CSIO_TSUCCESS)) {
			csio_scst_msg(ERR, "csioscst: rsp error %d req:%p\n",
				      ret, req);
			if (ret == CSIO_TBUSY)
				return SCST_TGT_RES_QUEUE_FULL;
			else {
				scst_set_delivery_status(cmd, SCST_CMD_DELIVERY_FAILED);
				return SCST_TGT_RES_FATAL_ERROR;
			}
		}

	} else {
		csio_scst_msg(ERR, "csioscst: bad xmit_response call %p"
			      " (req:%p)\n", cmd, req);
		scst_set_delivery_status(cmd, SCST_CMD_DELIVERY_FAILED);
		return SCST_TGT_RES_FATAL_ERROR;
	}

	return status;
}

static int
csio_scst_rdy_to_xfer(struct scst_cmd *cmd)
{
        int result = SCST_TGT_RES_SUCCESS;
	csio_sal_req_t *req = scst_cmd_get_tgt_priv(cmd);
	uint16_t data_direction;
	csio_tret_t ret;

	data_direction = scst_cmd_get_data_direction(cmd);
	req->write_data_len = scst_cmd_get_data_len(cmd);
	/* 0 for now */
	req->rel_off = 0;

	/* 
	 * Set this to zero, so we can check for this during cmd_done.
	 * CAVEAT: In future, if SCST supports auto-response for WRITE, 
	 * we will have to use some other field to deal with this. 
	 * There isnt much sense for auto-response for WRITES, and it isnt 
	 * supported, so we should be OK.
	 */
	req->send_status = 0;
	
	/* Validate direction */
	if (unlikely(data_direction != SCST_DATA_WRITE)) {
		csio_scst_msg(ERR, "csioscst: rdy_to_xfer invalid data direction"
				": %p (req:%p) direction %u\n", cmd, req, data_direction);
		return SCST_TGT_RES_FATAL_ERROR;
	}


	if (unlikely((scst_cmd_get_bufflen(cmd) <= 0)
				|| (scst_cmd_get_sg_cnt(cmd) <= 0)
				|| (scst_cmd_get_sg(cmd) == NULL))) {
		csio_scst_msg(ERR, "csioscst: rdy_to_xfer invalid sg"
				" %p(req: %p) nsge %d\n", cmd ,req, scst_cmd_get_sg_cnt(cmd));
		return SCST_TGT_RES_FATAL_ERROR;
	}

	req->buff_len = scst_cmd_get_bufflen(cmd);
	req->os_sge = (void *)scst_cmd_get_sg(cmd);
	req->nsge = scst_cmd_get_sg_cnt(cmd);
	req->nsge_map = 0;

	if ((csio_ddp_thres >= 0) &&
			(req->buff_len >= (uint32_t)csio_ddp_thres)) {

		req->nsge_map = pci_map_sg(req->os_dev,
				scst_cmd_get_sg(cmd),
				scst_cmd_get_sg_cnt(cmd),
				scst_to_tgt_dma_dir(data_direction));

		if (unlikely(req->nsge_map <= 0)) {
			req->nsge_map = 0;
			csio_scst_msg(ERR, "csioscst: rdy_to_xfer DMA mapping failed"
					" %p(req: %p)\n", cmd ,req);
		}
	}

	ret = csio_sal_acc(req);
	if (unlikely(ret != CSIO_TSUCCESS)) {
		csio_scst_msg(ERR, "csioscst: acc error %d req: %p\n",
				ret, req);
		if (ret == CSIO_TBUSY)
			result = SCST_TGT_RES_QUEUE_FULL;
		else {
			result = SCST_TGT_RES_FATAL_ERROR;
		}

		if (req->nsge_map > 0) {
			pci_unmap_sg(req->os_dev, scst_cmd_get_sg(cmd), 
					scst_cmd_get_sg_cnt(cmd),
					scst_to_tgt_dma_dir(data_direction));
			req->nsge_map = 0;
		}
	}

	return result;
}

/* Called by SCST when it has finished processing a TM cmd */
static void
csio_scst_task_mgmt_fn_done(struct scst_mgmt_cmd *scst_mcmd)
{
	int status;
	csio_tm_st_t tm_status;
	csio_sal_req_t *req = scst_mgmt_cmd_get_tgt_priv(scst_mcmd);

	if(!req) {
		return;
	}
	status = scst_mgmt_cmd_get_status(scst_mcmd);
	switch (status) {
	case SCST_MGMT_STATUS_SUCCESS:
		tm_status = CSIO_SAL_TM_ST_SUCCESS;
		break;
	case SCST_MGMT_STATUS_TASK_NOT_EXIST:
		tm_status = CSIO_SAL_TM_ST_INVALID_TASK;
		break;
	case SCST_MGMT_STATUS_LUN_NOT_EXIST:
		tm_status = CSIO_SAL_TM_ST_INVALID_LUN;
		break;
	case SCST_MGMT_STATUS_FN_NOT_SUPPORTED:
		tm_status = CSIO_SAL_TM_ST_UNSUPP_FN;
		break;
	case SCST_MGMT_STATUS_REJECTED:
		tm_status = CSIO_SAL_TM_ST_REJECTED;
		break;
	case SCST_MGMT_STATUS_FAILED:
		tm_status = CSIO_SAL_TM_ST_FAILED;
		break;
	default:
		tm_status = CSIO_SAL_TM_ST_REJECTED;
	}

	csio_sal_tm_done(req, tm_status, scst_mcmd);
}

static void
csio_scst_on_free_cmd(struct scst_cmd *cmd)
{
	csio_sal_req_t *req = scst_cmd_get_tgt_priv(cmd);
	
	csio_sal_free(req);
}

/*
 * Probe target ports for SCST. Mandatory but unused
 * entry point. scst_register_target() is used later
 * when drivers responds to PRLI.
 */
static int
csio_scst_detect(struct scst_tgt_template *tgt_template)
{
        return 0;
}

/* Called by SCST when the target is being shutdown. */
static int
csio_scst_release(struct scst_tgt *tgt)
{
        return SCST_TGT_RES_SUCCESS;
}

static int
csio_scst_fcoe_init_transport_id(struct scst_tgt *tgt,
				 struct scst_session *scst_sess,
				 uint8_t **transport_id)
{
	uint8_t *tr_id;
	csio_sal_params_t params;
	void *tgt_priv;

	if (scst_sess == NULL)
		return SCSI_TRANSPORTID_PROTOCOLID_FCP2;
	
	memset(&params, 0, sizeof(params)); 

	tgt_priv = scst_sess_get_tgt_priv(scst_sess);

	tr_id = kzalloc(24, GFP_KERNEL);
	if (tr_id == NULL) {
		csio_scst_msg(ERR, "csioscst: Allocation of TransportID"
				   " (size 24) failed\n");
		return -ENOMEM;
	}

	csio_scst_dbg("csioscst: Trying to get transport ID, sess %p,"
		      " tgt_priv %p\n", scst_sess, tgt_priv);
	
	params.cmdhdr.dev_handle = tgt_priv;
	if (csio_sal_get_param(&csio_scst_sal_ops, CSIO_SAL_SESSION_PARAM,
				&params) == CSIO_TSUCCESS) 
	{
		/* From section 7.6.4.2 SCSI SPC-4 */
		tr_id[0] = SCSI_TRANSPORTID_PROTOCOLID_FCP2;
		memcpy(&tr_id[8], params.un.fcoe_params.wwpn, 8);
		*transport_id = tr_id;
	}
	else {
		kfree(tr_id);
		return -ENOMEM;
	}	

	return 0;
}

static struct scst_tgt_template csio_scst_data = {
	.sg_tablesize = 512, /* FIXME - use macro */
	.use_clustering = 0,
	.no_clustering = 1,
	.xmit_response_atomic = 0,
	.rdy_to_xfer_atomic = 0,
	.detect = csio_scst_detect,
	.release = csio_scst_release,
	.xmit_response = csio_scst_xmit_response,
	.rdy_to_xfer = csio_scst_rdy_to_xfer,
	.task_mgmt_fn_done = csio_scst_task_mgmt_fn_done,
	/* 
	 * This will be replaced by the proto-specific transport handler during
	 * target registration. The following is just to avoid the warning 
	 * message from SCST during template registration.
	 */
	.get_initiator_port_transport_id = csio_scst_fcoe_init_transport_id,
	.enabled_attr_not_needed = 1,
	.on_free_cmd = csio_scst_on_free_cmd,
	.name = "csio_tgt",
	.threads_num = 1,
	.multithreaded_init_done = 1

};

int
csio_scst_sal_init(void)
{
	int rv;
	csio_tret_t retval;

	csio_scst_msg(INFO, "Loading %s v%s\n", 
		      SCST_SAL_DESC, CHTGT_SAL_VERSION_STR);

	retval = csio_sal_init(&csio_scst_sal_ops);
	if (retval) {
		csio_scst_msg(ERR, "csioscst: Failed to register SAL template"
			 	   ", ret:%d\n", retval);
		return -ENOMEM;
	}

	rv = scst_register_target_template(&csio_scst_data);
	if (rv) {
		csio_scst_msg(ERR, "csioscst: Failed to register SCST template"
			 	   ", ret:%d\n", rv);
		csio_sal_exit(&csio_scst_sal_ops);
		return rv;
	}

	csio_scst_msg(INFO, "Loaded %s\n", SCST_SAL_DESC);

	return 0;
}

void 
csio_scst_sal_exit(void)
{
	scst_unregister_target_template(&csio_scst_data);
	csio_sal_exit(&csio_scst_sal_ops);

	csio_scst_msg(INFO, "Unloaded %s v%s\n", 
			SCST_SAL_DESC, CHTGT_SAL_VERSION_STR);
}
