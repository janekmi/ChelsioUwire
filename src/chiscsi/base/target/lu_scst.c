/*
 * DISCLAIMER:
 *
 * The Chelsio SCST Subsystem for Open Source Functionality is for developers
 * who want to leverage the Open Source community SCST architecture in
 * designing Linux-based storage solutions, Chelsio provides a Chelsio SCST
 * helper, which transparently maps the code to the Open Source SCST Subsystem.
 * SCST is an Open Source standard developed by the Linux community, and is an
 * alternative implementation of a SCSI target subsystem for Linux.
 *
 */

/*
 * iscsi target device -- scst passthru io
 */

#ifdef __ISCSI_SCST__
#include <linux/wait.h>

#include <common/iscsi_target_class.h>
#include <common/iscsi_sgvec.h>
#include <common/os_export.h>
#include <common/iscsi_debug.h>
#include <common/iscsi_pdu.h>
#include <kernel/linux_compat.h>

#include <scst.h>
#include <scst_const.h>
#include <scst_debug.h>

#define CMD_ATTR_MASK     0x07
enum task_attr {
	CMD_UNTAGGED = 0,
	CMD_SIMPLE,
	CMD_ORDERED,
	CMD_HEAD_OF_QUEUE,
	CMD_ACA
};

typedef struct scst_tgt_priv {
	chiscsi_scsi_command *scmd;
	chiscsi_sgvec *sgvec;
	atomic_t ref_cnt;
} scst_tgt_priv_t;

typedef struct scst_tmf_priv {
	chiscsi_scsi_command *scmd;
	unsigned long hndl;
	int tmf_done;
	atomic_t ref_cnt;
} scst_tmf_priv_t;

static inline int ch_scst_fill_sgvec(struct chiscsi_sgvec *sgv, 
				struct scst_cmd *cmd)
{
	int i;
	struct scatterlist *sg = scst_cmd_get_sg(cmd);
	int sg_cnt = scst_cmd_get_sg_cnt(cmd);

	if (unlikely((sg == NULL) || (sg_cnt == 0))) {
		os_log_warn("lu_scst: scst buffer alloc failed. w %d\n",
			(cmd->data_direction == SCST_DATA_WRITE) ? 1 : 0);
		return -1;
	}

	for (i = 0; i < sg_cnt; i++) {
		sgv[i].sg_page = SG_GET_PAGE(&sg[i]);
		sgv[i].sg_offset = sg[i].offset;
		/* cmd->may_need_dma_sync gets set here */
		sgv[i].sg_length = (i == 0) ? 
				scst_get_buf_first(cmd,	&sgv[i].sg_addr) :
				scst_get_buf_next(cmd, &sgv[i].sg_addr);
	}

	return 0;
}

static void ch_scst_free_cmd_priv(scst_tgt_priv_t *scst_priv)
{
	if (!scst_priv)
		return;
	if (scst_priv->sgvec)
		os_free(scst_priv->sgvec);
	os_free(scst_priv);
	return;
}

static void ch_scst_free_cmd(struct scst_cmd *cmd)
{
	scst_tgt_priv_t *scst_private = scst_cmd_get_tgt_priv(cmd);
	chiscsi_scsi_command *sc;

	if (!scst_private)
		return;

	sc = scst_private->scmd;
	os_log_info("%s Aborting scst cmd 0x%p sess 0x%p scsi cmd 0x%p\n",
		__func__, cmd, sc->pthru_sess, sc);

	scmd_fscsi_clear_bit(sc, CH_SFSCSI_TIMER_SET_BIT);
	chiscsi_scsi_cmd_abort(sc);

	ch_scst_free_cmd_priv(scst_private);
	scst_cmd_set_tgt_priv(cmd, NULL);
	return;
}

int cb_scst_xmit_response(struct scst_cmd *cmd)
{
	int send_status = scst_cmd_get_is_send_status(cmd);
	int status = scst_cmd_get_status(cmd);
	uint8_t *sense = scst_cmd_get_sense_buffer(cmd);
	int sense_len = scst_cmd_get_sense_buffer_len(cmd);
	scst_tgt_priv_t *scst_private = scst_cmd_get_tgt_priv(cmd);
	chiscsi_scsi_command *sc;
	int resp_data_len = scst_cmd_get_resp_data_len(cmd);
	chiscsi_sgvec *sgv;
	int atomic = scst_cmd_atomic(cmd);
	int sg_cnt = scst_cmd_get_sg_cnt(cmd);
	int io_is_write;

	/* check if command is aborted */
	if (unlikely(scst_cmd_aborted_on_xmit(cmd)) || !scst_private) {
		scst_set_delivery_status(cmd, SCST_CMD_DELIVERY_ABORTED);
		os_log_info("%s cmd:0x%p state 0x%x tag:0x%x resp_data_len:%d "
			" send_status:%d cmd aborted\n", __func__, cmd,
			cmd->state, cmd->tag, resp_data_len, send_status);

		return SCST_TGT_RES_FATAL_ERROR;
	}

	sc = scst_private->scmd;
	io_is_write = (sc->sc_flag & SC_FLAG_WRITE);

#if 0
	os_log_debug(ISCSI_DBG_TARGET_SCST,"%s: SCST: IN itt 0x%x xfer_len %u "
			"resp_data_len %d, sgcnt=%d, send_status %d\n",
			__func__, sc->sc_itt, sc->sc_xfer_len,
			resp_data_len, sg_cnt, send_status);
#endif

	if (unlikely(!send_status)) {
		scst_set_delivery_status(cmd, SCST_CMD_DELIVERY_FAILED);
		return SCST_TGT_RES_FATAL_ERROR;
	}

	if ((resp_data_len != 0) && !send_status) {
		/* This check is from iscsi_scst and signifies that
		 * LUN_CLASS_MULTI_PHASE_DATA_BIT is currently not supported and
		 * for read both data and status will come in one shot.
		 */
		os_log_error("SCST: %s Sending DATA without STATUS is " 
					"unsupported\n", __func__);
		sBUG();
	}

	if (send_status) {
		sc->sc_response = ISCSI_RESPONSE_COMPLETED;
		sc->sc_status = status;
		sc->sc_sense_buflen = sense_len;

		//if (sense && sense_len && SCST_SENSE_VALID(sense)) {
		if (sense && sense_len) {
			os_log_debug(ISCSI_DBG_TARGET_SCST,
				"SCST: %s has sense. sense 0x%x senselen "
				"%d\n", __func__, sense[0], sense_len);

			/* Key is not given by SCST. Just set it so that 
			 * chiscsi looks into the sense.
			 */
			sc->sc_sense_key = 1;
			memcpy(sc->sc_sense_buf, sense, 
					SCSI_SENSE_BUFFERSIZE);
		}
		os_log_debug(ISCSI_DBG_TARGET_SCST,
			"SCST: status=0x%x, key=0x%x\n",
			sc->sc_status, sc->sc_sense_key);
	}

	/* resp_data_len is non-zero for READ path. */
	if (resp_data_len > 0) {
		sgv = os_alloc(sizeof(struct chiscsi_sgvec) * sg_cnt, !atomic, 1);
		if (!sgv)
			return (atomic) ? SCST_TGT_RES_NEED_THREAD_CTX :
				SCST_TGT_RES_FATAL_ERROR;

		if (ch_scst_fill_sgvec(sgv, cmd)) {
			return SCST_TGT_RES_FATAL_ERROR;
		}

		scst_private->sgvec = sgv;
	}

	if (resp_data_len != sc->sc_xfer_len) {
		os_log_debug(ISCSI_DBG_TARGET_SCST, "SCST: %s over/under itt 0x%x\n",
			__func__, sc->sc_itt);
		if (resp_data_len >  sc->sc_xfer_len) {
			sc->sc_xfer_residualcount = 
				resp_data_len - sc->sc_xfer_len;
			sc->sc_flag |= SC_FLAG_XFER_OVERFLOW;
		} else {
			sc->sc_xfer_residualcount = 
				sc->sc_xfer_len - resp_data_len;
			sc->sc_flag |= SC_FLAG_XFER_UNDERFLOW;
		}
		sc->sc_xfer_len = sc->sc_xfer_left = resp_data_len;
	}

	os_log_debug(ISCSI_DBG_TARGET_SCST, "SCST: scst_private->sgvec=%p, sgcnt=%d\n", 
			scst_private->sgvec, sg_cnt);

	scmd_fscsi_clear_bit(sc, CH_SFSCSI_TIMER_SET_BIT);
	/* For writes, scst_private->sgvec is still valid here. It gets freed
	 * after this.
	 */
	if (unlikely(scst_cmd_aborted_on_xmit(cmd)) ||
		chiscsi_scsi_cmd_execution_status(sc,
		(unsigned char *)scst_private->sgvec, scst_cmd_get_sg_cnt(cmd),
		 0, resp_data_len) < 0) {
		os_log_info("%s returning FATAL_ERROR sc->sc_flag 0x%x"
			" scsi sc 0x%p scst cmd 0x%p sess 0x%p\n",
			__func__, sc ? sc->sc_flag : 0, sc, cmd,
			sc ? sc->pthru_sess : 0);
		return SCST_TGT_RES_FATAL_ERROR;
	}

	/* For write; the status delivery is assumed to be success. Since,
	 * chiscsi doesn't provide a callback for response delivery, free the
	 * command here.
	 */
	if (io_is_write) { /*TODO shoud this code be moved to cb_scst_on_free_cmd ?? */
		if (atomic_dec_and_test(&scst_private->ref_cnt)) {
			ch_scst_free_cmd_priv(scst_private);
			scst_cmd_set_tgt_priv(cmd, NULL);
		}
		sc->sc_sdev_hndl = NULL;
		scst_set_delivery_status(cmd, (scst_cmd_aborted(cmd)) ?
			 SCST_CMD_DELIVERY_ABORTED : SCST_CMD_DELIVERY_SUCCESS);
		scst_tgt_cmd_done(cmd, SCST_CONTEXT_SAME);
	}
	else if (sc->sc_status ||sc->sc_sense_key) {
		scst_tgt_cmd_done(cmd, SCST_CONTEXT_THREAD);
		ch_scst_free_cmd_priv(scst_private);
		scst_cmd_set_tgt_priv(cmd, NULL);
		sc->sc_sdev_hndl = NULL;
	}

	os_log_debug(ISCSI_DBG_TARGET_SCST,
		"SCST: OUT %s itt 0x%x\n", __func__, sc->sc_itt);
	return SCST_TGT_RES_SUCCESS;
}

static unsigned int ch_scst_resp(int status)
{
	switch (status) {
		case SCST_MGMT_STATUS_SUCCESS:
			return ISCSI_RESPONSE_TMF_COMPLETE;

		case SCST_MGMT_STATUS_TASK_NOT_EXIST:
			return ISCSI_RESPONSE_TMF_INVALID_TASK;

		case SCST_MGMT_STATUS_LUN_NOT_EXIST:
			return ISCSI_RESPONSE_TMF_INVALID_LUN;

		case SCST_MGMT_STATUS_FN_NOT_SUPPORTED:
			return ISCSI_RESPONSE_TMF_NOT_SUPPORTED;

		case SCST_MGMT_STATUS_REJECTED:
		case SCST_MGMT_STATUS_FAILED:
		default:
			return ISCSI_RESPONSE_TMF_FUNCTION_REJECTED;
	}
}
	

int cb_scst_rdy_to_xfer(struct scst_cmd *cmd)
{
#if 0
	scst_tgt_priv_t *scst_private = scst_cmd_get_tgt_priv(cmd);
	chiscsi_sgvec *sgv;
	int sg_cnt = scst_cmd_get_sg_cnt(cmd);
	int atomic;

	os_log_info("SCST: IN %s itt 0x%x\n", 
			__func__, scst_private->scmd->sc_itt);
	atomic = scst_cmd_atomic(cmd);

	sgv = os_alloc(sizeof(struct chiscsi_sgvec) * sg_cnt, !atomic, 1);
	if (!sgv)
		return (atomic) ? SCST_TGT_RES_NEED_THREAD_CTX :
				SCST_TGT_RES_FATAL_ERROR; //PKJ: FATAL return?

	if (ch_scst_fill_sgvec(sgv, cmd)) {
		// No memory available
		return SCST_TGT_RES_FATAL_ERROR; //PKJ: whether the right value
	}

	scst_private->sgvec = sgv;
	os_log_debug(ISCSI_DBG_TARGET_SCST, "SCST: %s resp_data_len=%d, "
		"bufflen=%d sgcnt=%d, send_status=%d\n",
		__func__, scst_cmd_get_resp_data_len(cmd),
		scst_cmd_get_bufflen(cmd),
		sg_cnt, scst_cmd_get_is_send_status(cmd));

	atomic_inc(&scst_private->ref_cnt);
	smp_mb__after_atomic_inc();
	scst_private->buffer_available = 1;
	wake_up(&scst_private->scst_waitq);
	if (atomic_dec_and_test(&scst_private->ref_cnt))
		ch_scst_free_cmd_priv(scst_private);

	os_log_debug(ISCSI_DBG_TARGET_SCST, "SCST: OUT %s itt 0x%x\n",
			 __func__, scst_private->scmd->sc_itt);
#endif
	return SCST_TGT_RES_SUCCESS;
}

static int cb_scst_detect(struct scst_tgt_template *tgt_template)
{
	return 0;
}

static int cb_scst_release(struct scst_tgt *tgt)
{
	return 0;
}

static void cb_scst_return_cmd_to_scst(struct scst_cmd *cmd)
{
	os_log_debug(ISCSI_DBG_TARGET_SCST,
		"%s: cmd:0x%x tag:0x%x\n", __func__, cmd, cmd->tag);
	if (cmd->data_direction & SCST_DATA_WRITE) {
		if (cmd->state != SCST_CMD_STATE_DATA_WAIT) {
			os_log_debug(ISCSI_DBG_TARGET_SCST,
				"We don't own cmd:0x%p state:%d itt:0x%x\n",
				cmd, cmd->state, cmd->tag);
			return;
		}
		scst_set_delivery_status(cmd, SCST_CMD_DELIVERY_ABORTED);
		scst_cmd_set_tgt_priv(cmd, NULL);
		scst_rx_data(cmd, SCST_RX_STATUS_ERROR_FATAL,
			 SCST_CONTEXT_THREAD);
	} else  {
		if (cmd->state != SCST_CMD_STATE_XMIT_WAIT) {
			os_log_debug(ISCSI_DBG_TARGET_SCST,
				"We don't own cmd:0x%p state:%d itt:0x%x\n",
				cmd, cmd->state, cmd->tag);
			return;
		}
		scst_set_delivery_status(cmd, SCST_CMD_DELIVERY_ABORTED);
		scst_cmd_set_tgt_priv(cmd, NULL);
		scst_tgt_cmd_done(cmd, SCST_CONTEXT_THREAD);
	}
	return;
}

/* command timeout handler called by SCST */
void cb_scst_cmd_timeout(struct scst_cmd *cmd)
{
	scst_tgt_priv_t *scst_private = scst_cmd_get_tgt_priv(cmd);
	chiscsi_scsi_command *sc;

	if (!scst_private)
		return;

	cb_scst_return_cmd_to_scst(cmd);
	sc = scst_private->scmd;
	os_log_info("%s scst cmd 0x%p state 0x%x op %s scsi cmd 0x%p",
				__func__, cmd, cmd->state, cmd->op_name, sc);

	if (sc) {
		os_log_info("TIMEOUT-cmd:%p itt:0x%x sc:0x%p state:%d "
				"sc_flag:0x%x\n",
				cmd, cmd->tag, sc, sc->sc_state, sc->sc_flag);
		sc->sc_sdev_hndl = NULL;
	}
	ch_scst_free_cmd(cmd);
}

/* called by SCST in response to a TMF command */
static void cb_scst_task_mgmt_fn_done(struct scst_mgmt_cmd *mgmt_cmd)
{
	scst_tmf_priv_t *tmf_priv;
	unsigned int response;

	tmf_priv = (scst_tmf_priv_t *)scst_mgmt_cmd_get_tgt_priv(mgmt_cmd);
	response = ch_scst_resp(scst_mgmt_cmd_get_status(mgmt_cmd));

	os_log_info("%s: tpmf:0x%x sc:0x%x cmd:0x%p tmf_priv:%p response:%u\n",
	__func__, tmf_priv->hndl, tmf_priv->scmd, mgmt_cmd, tmf_priv, response);

	scst_mgmt_cmd_set_tgt_priv(mgmt_cmd, NULL);

	chiscsi_tmf_execution_done(tmf_priv->hndl, response, tmf_priv->scmd);

	os_free(tmf_priv);
	return;
}

static void
cb_scst_on_free_cmd(struct scst_cmd *cmd)
{
#if 0
	scst_tgt_priv_t *scst_private = scst_cmd_get_tgt_priv(cmd);
	chiscsi_scsi_command *sc = scst_private->scmd;

	os_log_info("%s: cmd:%p itt:0x%x priv:%p\n", __func__, cmd, cmd->tag, scst_private);
	ch_scst_free_cmd_priv(scst_private);
	/* TODO: call chiscsi function which does below */
	sc->sc_state = CH_SC_STATE_DONE;
	iscsi_target_scsi_command_done(sc, 0);
#endif
}

static void
cb_scst_on_abort_cmd(struct scst_cmd *cmd)
{
	scst_tgt_priv_t *scst_private = scst_cmd_get_tgt_priv(cmd);
	chiscsi_scsi_command *sc;

	/*
	 * For Write commands scst_private is set to NULL in xmit_response,
	 * which means we already freed scst_private.
	 *
	 * For Read commands if scst_private is NULL, xfer_status is already
	 * freed it and scsi command will be freed by it_scmd_acked.
	 */
	if (!scst_private)
		return;

	sc = scst_private->scmd;
	cb_scst_return_cmd_to_scst(cmd);
	sc->sc_sdev_hndl = NULL;
	if (cmd->state == SCST_CMD_STATE_XMIT_RESP ||
			 cmd->state == SCST_CMD_STATE_XMIT_WAIT ||
			 cmd->state == SCST_CMD_STATE_FINISHED) {
		if (cmd->data_direction == SCST_DATA_READ) {
			ch_scst_free_cmd_priv(scst_private);
			scst_cmd_set_tgt_priv(cmd, NULL);
		}
		return;
	}

	os_log_info("%s Aborting scst cmd 0x%p state 0x%x sess 0x%p"
		" scsi cmd 0x%p, sc_fscsi 0x%lx\n",
		__func__, cmd, cmd->state, sc->pthru_sess, sc, sc->sc_fscsi);

	scmd_fscsi_clear_bit(sc, CH_SFSCSI_TIMER_SET_BIT);
	chiscsi_scsi_cmd_abort(sc);
	ch_scst_free_cmd_priv(scst_private);
	scst_cmd_set_tgt_priv(cmd, NULL);
	return;
}

struct scst_tgt_template chiscsi_scst_tgt_template = {
	.sg_tablesize = 0xFFFF,
	.unchecked_isa_dma = 0,
	.use_clustering = 0,
	.no_clustering = 1,
	.xmit_response_atomic = 1,
	.rdy_to_xfer_atomic = 1,
	.xmit_response = cb_scst_xmit_response,
	.rdy_to_xfer = cb_scst_rdy_to_xfer,
	.on_hw_pending_cmd_timeout = cb_scst_cmd_timeout,
	.task_mgmt_fn_done = cb_scst_task_mgmt_fn_done,
	.detect = cb_scst_detect,
	.release = cb_scst_release,
	.on_free_cmd = cb_scst_on_free_cmd,
	.on_abort_cmd = cb_scst_on_abort_cmd,
	.report_aen = NULL,
	.max_hw_pending_time =  20,
	.name = "CHISCSI",
	.threads_num = 0,
};

static int cb_chiscsi_attach(chiscsi_target_lun *lu, char *ebuf, int ebuflen)
{
	return 0;
}

static int cb_chiscsi_reattach(chiscsi_target_lun *old_lu, 
			chiscsi_target_lun *new_lu, char *ebuf, int ebuflen)
{
	return 0;
}

static void cb_chiscsi_detach(chiscsi_target_lun *lu)
{
	return;
}

int cb_chiscsi_scsi_cmd_cdb_rcved(chiscsi_scsi_command *scmd)
{
	struct scst_cmd *scst_cmd;
	scst_data_direction dir;
	scst_tgt_priv_t *scst_priv;
	int ret = 0, atomic, sg_cnt;
	struct scst_session *sess = (struct scst_session *)scmd->pthru_sess;
	chiscsi_sgvec *sgv;
	struct scsi_lun lun;
	unsigned char *cdb = (unsigned char *)scmd->sc_cmd;
	unsigned int opcode;

	os_log_debug(ISCSI_DBG_TARGET_SCST,
		"SCST: IN %s itt 0x%x lun %u xfer_len:0x%x, "
		"Read %d sc_flag:0x%x scfscsi:0x%x\n", __func__, scmd->sc_itt,
		 scmd->sc_lun, scmd->sc_xfer_len,
		(scmd->sc_flag & SC_FLAG_READ), scmd->sc_flag, scmd->sc_fscsi);

	int_to_scsilun(scmd->sc_lun, &lun);
	scst_cmd = scst_rx_cmd(sess, lun.scsi_lun, 
			sizeof(lun), scmd->sc_cmd, scmd->sc_cmdlen, 
			SCST_NON_ATOMIC);
	if (!scst_cmd) {
		os_log_error("%s: scst_rx_cmd() allocation failed\n", __func__);
		return -1;
	}

	opcode = cdb[0];
	scst_cmd_set_tag(scst_cmd, scmd->sc_itt);

	scst_priv = (scst_tgt_priv_t *)os_alloc(sizeof(scst_tgt_priv_t), 1, 1);
	if (!scst_priv)
		return -1;

	scst_priv->scmd = scmd;
	scst_cmd_set_tgt_priv(scst_cmd, scst_priv); // locked version?
	scmd_fscsi_set_bit(scmd, CH_SFSCSI_TIMER_SET_BIT);
	scst_priv->sgvec = NULL;
	
	if (scmd->sc_flag & SC_FLAG_READ) {
		/* CHISCSI treats all non-write commands as READs.
		 * For SYNCHRONIZE_10 &  ATA PASS-THROUGH_16 SCST wants
		 * data_direction to be set as SCST_DATA_NONE. 
		 */
		if (opcode == 0x35 || (opcode == 0x85 && !(cdb[2] & 3)))
			dir = SCST_DATA_NONE;
		else
			dir = SCST_DATA_READ;
		//scst_cmd_set_tgt_need_alloc_data_buf(scst_cmd);
	} else if (scmd->sc_flag & SC_FLAG_WRITE) {
		atomic_inc(&scst_priv->ref_cnt);
		dir = SCST_DATA_WRITE;
	} else
		dir = SCST_DATA_NONE;
	scst_cmd_set_expected(scst_cmd, dir, scmd->sc_xfer_len);

	switch (scmd->sc_attribute & CMD_ATTR_MASK) {
		case CMD_SIMPLE:
			scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_SIMPLE);
			break;
		case CMD_HEAD_OF_QUEUE:
			scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_HEAD_OF_QUEUE);
			break;
		case CMD_ORDERED:
			scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_ORDERED);
			break;
		case CMD_ACA:
			scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_ACA);
			break;
		case CMD_UNTAGGED:
			scst_cmd_set_queue_type(scst_cmd, SCST_CMD_QUEUE_UNTAGGED);
			break;
		default:
			scst_cmd->queue_type = SCST_CMD_QUEUE_ORDERED;
			break;
	}

	scst_cmd_set_tgt_sn(scst_cmd, scmd->sc_cmdsn);
	scmd->sc_sdev_hndl = scst_cmd;

	scst_cmd_init_done(scst_cmd, SCST_CONTEXT_DIRECT);

	/* In case of write, wait for the buffers from scst. */
	if (scmd->sc_flag & SC_FLAG_WRITE) {
		sg_cnt = scst_cmd_get_sg_cnt(scst_cmd);
		if (!sg_cnt)
			return -ENOMEM;
		atomic = scst_cmd_atomic(scst_cmd);

		sgv = os_alloc(sizeof(struct chiscsi_sgvec) * sg_cnt, !atomic, 1);
		if (!sgv) {
			os_log_error("%s: sgv allocation failed\n", __func__);
			return -ENOMEM;
		}

		if (ch_scst_fill_sgvec(sgv, scst_cmd)) {
			os_free(sgv);
			os_log_warn("lu_scst: scst buffer fill failed. w %d\n",
					(scst_cmd->data_direction == SCST_DATA_WRITE) ? 1 : 0);
			return -ENOMEM;
		}

		scst_priv->sgvec = sgv;
		os_log_debug(ISCSI_DBG_TARGET_SCST, "SCST: %s resp_data_len=%d, "
				"bufflen=%d sgcnt=%d, send_status=%d\n",
				__func__, scst_cmd_get_resp_data_len(scst_cmd),
				scst_cmd_get_bufflen(scst_cmd),
				sg_cnt, scst_cmd_get_is_send_status(scst_cmd));

		/*
		 * Right now its one shot allocation (no support for
		 * LUN_CLASS_MULTI_PHASE_DATA_BIT)
		 */
		ret = chiscsi_scsi_cmd_buffer_ready(scst_priv->scmd, 
				(unsigned char *)scst_priv->sgvec, scst_cmd_get_sg_cnt(scst_cmd), 
				0, scst_cmd_get_bufflen(scst_cmd));

		/* if buffer check failed, log something and keep going */
		if (ret < 0) 
			os_log_info("SCST: %s write buffer check failed in chiscsi "
					"itt 0x%x\n", __func__, scmd->sc_itt);
	}

	os_log_debug(ISCSI_DBG_TARGET_SCST,
			"SCST: OUT %s itt 0x%x\n", __func__, scmd->sc_itt);
	return ret;
}

void cb_chiscsi_scsi_cmd_data_xfer_status(chiscsi_scsi_command *scmd, 
			unsigned char *xfer_sreq_buf, unsigned int xfer_sgcnt,
			unsigned int xfer_offset, unsigned int xfer_buflen)
{
	struct scst_cmd *cmd = scmd->sc_sdev_hndl;
	scst_tgt_priv_t *scst_private;
	chiscsi_sgvec *sgv;
	int sg_cnt, bufflen;

	if (cmd == NULL) {
		os_log_info("%s: sc:0x%p itt:0x%x state:%d sc_flag:0x%x"
			" scst_cmd is NULL\n", __func__, scmd, scmd->sc_itt,
			scmd->sc_state, scmd->sc_flag);
		return;
	}

	if (scmd->sc_flag & SC_FLAG_READ &&
				cmd->state != SCST_CMD_STATE_XMIT_WAIT) {
		os_log_info("%s: sc:0x%p itt:0x%x state:%d sc_flag:0x%x "
			"scst_cmd 0x%p state 0x%x op 0x%x %s\n",
			__func__, scmd, scmd->sc_itt, scmd->sc_state,
			scmd->sc_flag, cmd, cmd->state, cmd->data_direction,
			cmd->op_name);

		if (cmd->state == SCST_CMD_STATE_EXEC_WAIT) {
			ch_scst_free_cmd_priv(scst_cmd_get_tgt_priv(cmd));
			scst_cmd_set_tgt_priv(cmd, NULL);
			return;
		}
		//Todo: Fix this else case
		else if (cmd->state == SCST_CMD_STATE_FINISHED ||
				cmd->data_direction == SCST_DATA_WRITE)
			return;
	}

	scst_private = scst_cmd_get_tgt_priv(cmd);
	sgv = scst_private->sgvec;
	sg_cnt = scst_cmd_get_sg_cnt(cmd);
	bufflen = scst_cmd_get_bufflen(cmd);

	os_log_debug(ISCSI_DBG_TARGET_SCST, "SCST: IN %s itt 0x%x Read %d\n",
		 __func__, scmd->sc_itt, (scmd->sc_flag & SC_FLAG_READ));

	os_log_debug(ISCSI_DBG_TARGET_SCST, "SCST: %s itt 0x%x sgvec=%p "
		"SCST: %s itt 0x%x sgvec=%p "
		"sgcnt=%u offset=%d buflen=%d\n", __func__, scmd->sc_itt, 
		xfer_sreq_buf, xfer_sgcnt, xfer_offset, xfer_buflen);

	if (scmd_fpriv_test_bit(scmd, CH_SFP_RWIO_BIT) && 
		((unsigned char *)sgv != xfer_sreq_buf || sg_cnt != xfer_sgcnt ||
		 0 != xfer_offset || bufflen != xfer_buflen))
		os_log_warn("%s: itt 0x%x, SGL mismatch: 0x%p/0x%p, %u/%u,"
				"%u/%u+%u/%u.\n", __func__, scmd->sc_itt, 
				sgv, xfer_sreq_buf, sg_cnt, xfer_sgcnt,
				0, xfer_offset, bufflen, xfer_buflen);

	if (scmd->sc_flag & SC_FLAG_WRITE) {
		os_log_debug(ISCSI_DBG_TARGET_SCST,
			"WRITE-itt:0x%x xfer_len:0x%x sent scst_rx_data\n",
			scmd->sc_itt, scmd->sc_xfer_len);
		scst_rx_data(cmd, SCST_RX_STATUS_SUCCESS, SCST_CONTEXT_DIRECT);
	}
	else {
		ch_scst_free_cmd_priv(scst_private);/*TODO should this be moved to cb_scst_on_free_cmd()?? */
		scst_cmd_set_tgt_priv(cmd, NULL);
		os_log_debug(ISCSI_DBG_TARGET_SCST,
			"READ-itt:0x%x xfer_len:0x%x sent scst_tgt_cmd_done\n",
			scmd->sc_itt, scmd->sc_xfer_len);
		scst_tgt_cmd_done(cmd, SCST_CONTEXT_DIRECT);
		scmd->sc_sdev_hndl = NULL;
	}

	os_log_debug(ISCSI_DBG_TARGET_SCST, "SCST: OUT %s itt 0x%x\n",
			 __func__, scmd->sc_itt);
}

static int cb_chiscsi_scsi_cmd_abort(chiscsi_scsi_command *sc)
{
	struct scst_cmd *cmd = sc->sc_sdev_hndl;

	os_log_info("%s: sc:0x%x tag:0x%x sc_state:%d cmd:%p cmd_state:%d\n",
		__func__, sc, sc->sc_itt, sc->sc_state, cmd, cmd->state);

	cb_scst_return_cmd_to_scst(cmd);
	sc->sc_sdev_hndl = NULL;

	/* setup error codes */
        sc->sc_response = ISCSI_RESPONSE_TARGET_FAILURE;
        sc->sc_status = 0x02; //SCSI_STATUS_CHECK_CONDITION;
        sc->sc_sense_key = 0x0b; //SCSI_SENSE_ABORTED_COMMAND;
        sc->sc_sense_asc = 0x44; /* internal target failure */
        sc->sc_sense_ascq = 0;

	chiscsi_scsi_cmd_abort_status(sc);
	return 0;
}

void cb_chiscsi_scsi_cmd_memory_release(chiscsi_scsi_command *sc)
{
	sc->sc_sgl.sgl_vecs_nr = 0;
	sc->sc_sgl.sgl_vecs = NULL;
	sc->sc_sgl.sgl_vec_last = NULL;

	return;
}

static int cb_chiscsi_tmf_execute(unsigned long sess_hndl, unsigned long hndl,
		unsigned char immediate_cmd, unsigned char tmf_func,
		unsigned int lu, chiscsi_scsi_command *scmd)
{
	iscsi_tmf *pdu = (iscsi_tmf *)hndl;
	struct scst_rx_mgmt_params params;
	int rc = 0;
	unsigned int status = ISCSI_RESPONSE_TMF_FUNCTION_REJECTED;
	scst_tmf_priv_t *tmf_priv;
	struct scsi_lun lun;
	unsigned long **conn;
	struct scst_session *scst_sess;

	/* Getting scst_sess pointer here depends on the position of the
	 * iscsi and scst session pointers in the respective structures. Any
	 * change in their positions will corrupt the pointer.
	 */
	if (pdu == NULL) {
		os_log_info("%s: tmf recved pdu:%p\n", __func__, pdu);
		return rc;
	}
	if (pdu->p_conn == NULL) {
		os_log_info("%s: tmf recved pdu:%p conn is NULL.\n", __func__, pdu);
		return rc;
	}
	conn = (unsigned long **)pdu->p_conn;
	scst_sess = (struct scst_session *)conn[0][0];

	os_log_info("%s: tmf recved ptmf:0x%p conn:%p lu:%d scst_sess:%p\n",
			__func__, pdu, conn, lu, scst_sess);
	
	if (scmd)
		int_to_scsilun(scmd->sc_lun, &lun);
	else
		int_to_scsilun(lu, &lun);

	tmf_priv = (scst_tmf_priv_t *)os_alloc(sizeof(scst_tmf_priv_t), 1, 1);
	tmf_priv->scmd = scmd;
	tmf_priv->hndl = hndl;

	scst_rx_mgmt_params_init(&params);
	params.atomic = SCST_NON_ATOMIC;
	params.tgt_priv = (void *)tmf_priv;

	switch (tmf_func) {
		case ISCSI_TMF_FUNCTION_ABORT_TASK:
			params.fn = SCST_ABORT_TASK;
			params.tag = scmd->sc_itt;
			params.tag_set = 1;
			params.lun = (uint8_t *)&lun;
			params.lun_len = sizeof(lun);
			params.lun_set = 1;
			params.cmd_sn = pdu->p_sn;
			params.cmd_sn_set = 1;
			break;
		case ISCSI_TMF_FUNCTION_ABORT_TASK_SET:
			params.fn = SCST_ABORT_TASK_SET;
			params.lun = (uint8_t *)&lun;
			params.lun_len = sizeof(lun);
			params.lun_set = 1;
			params.cmd_sn = pdu->p_sn;
			params.cmd_sn_set = 1;
			break;
		case ISCSI_TMF_FUNCTION_CLEAR_TASK_SET:
			params.fn = SCST_CLEAR_TASK_SET;
			params.lun = (uint8_t *)&lun;
			params.lun_len = sizeof(lun);
			params.lun_set = 1;
			params.cmd_sn = pdu->p_sn;
			params.cmd_sn_set = 1;
			break;
		case ISCSI_TMF_FUNCTION_CLEAR_ACA:
			params.fn = SCST_CLEAR_ACA;
			params.lun = (uint8_t *)&lun;
			params.lun_len = sizeof(lun);
			params.lun_set = 1;
			params.cmd_sn = pdu->p_sn;
			params.cmd_sn_set = 1;
			break;
		case ISCSI_TMF_FUNCTION_TARGET_COLD_RESET:
		case ISCSI_TMF_FUNCTION_TARGET_WARM_RESET:
			params.fn = SCST_TARGET_RESET;
			params.cmd_sn = pdu->p_sn;
			params.cmd_sn_set = 1;
			break;
		case ISCSI_TMF_FUNCTION_LOGICAL_UNIT_RESET:
			params.fn = SCST_LUN_RESET;
			params.lun = (uint8_t *)&lun;
			params.lun_len = sizeof(lun);
			params.lun_set = 1;
			params.cmd_sn = pdu->p_sn;
			params.cmd_sn_set = 1;
			break;
		case ISCSI_TMF_FUNCTION_TASK_REASSIGN:
			rc = -1;
			status = ISCSI_RESPONSE_TMF_NO_TASK_FAILOVER;
			return rc;
		default:
			os_log_error("SCST: %s Unknown TM function %d",
					__func__, tmf_func);
			rc = -1;
			return rc;
	}
	rc = scst_rx_mgmt_fn(scst_sess, &params);
	if (rc)
		os_log_error("TMF failed itt:0x%x\n", scmd->sc_itt);

	/* Send TMF response. CHISCSI wants TMF response to be sent in the
	 * same context as TMF request is received */
	//it_send_tmf_response(pdu, pdu->p_offset);
	// chiscsi_tmf_execution_done(hndl, ISCSI_RESPONSE_TMF_COMPLETE, sc);
	return rc;
};

chiscsi_target_lun_class lun_class_scst = {
	.class_name = "SCST",
	.property = 1 << LUN_CLASS_SCSI_PASS_THRU_BIT | 
			1 << LUN_CLASS_HAS_CMD_QUEUE_BIT |
			1 << LUN_CLASS_TYPE_SCST_BIT,
	.fp_attach = cb_chiscsi_attach,
	.fp_reattach = cb_chiscsi_reattach,
	.fp_detach = cb_chiscsi_detach,
	.fp_scsi_cmd_cdb_rcved = cb_chiscsi_scsi_cmd_cdb_rcved,
	.fp_scsi_cmd_data_xfer_status = cb_chiscsi_scsi_cmd_data_xfer_status,
	.fp_scsi_cmd_abort = cb_chiscsi_scsi_cmd_abort,
	.fp_scsi_cmd_abort_status = NULL,
	.fp_scsi_cmd_cleanup = cb_chiscsi_scsi_cmd_memory_release,
	.fp_tmf_execute = cb_chiscsi_tmf_execute
};
#endif
