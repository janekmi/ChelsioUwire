/*
 * chiscsi_scsi_command.c -- chiscsi_scsi_command struct manipulation
 */
#include <common/os_builtin.h>
#include <iscsi_structs.h>
#include <iscsi_global.h>
#include <iscsi_socket_api.h>
#include <iscsi_target_api.h>

extern chiscsi_queue *it_sc_pend_q;

static void scmd_free(chiscsi_scsi_command *sc)
{
	int i;

	for (i = 0; i < CH_SCMD_Q_MAX; i++) {
		ch_queue_free(sc->sc_queue[i]);
	}
	os_free(sc->sc_lock);

	os_data_free(sc->os_data);
	os_free(sc);
}

static chiscsi_scsi_command *scmd_alloc(void)
{
	chiscsi_scsi_command *sc = os_alloc(ISCSI_SCSI_COMMAND_SIZE, 1, 1);
	int i;

	if (!sc)
		return NULL;
	if (!(sc->os_data = os_data_init((void *)sc))) {
		os_free(sc);
		return NULL;
	}	

	os_data_counter_set(sc->os_data, 0);

	sc->sc_lock = os_alloc(os_lock_size, 1, 1);
	if (!sc->sc_lock) {
		os_data_free(sc->os_data);
		os_free(sc);
		return NULL;
	}
	for (i = 0; i < CH_SCMD_Q_MAX; i++) {
		ch_queue_alloc(sc->sc_queue[i]);
	}
	return sc;

q_lock_fail:
	scmd_free(sc);
	return NULL;
}

static void scmd_init(chiscsi_scsi_command *sc)
{
	int     offset = sizeof(chiscsi_scsi_command);
	int     i;
	/* backup sc_queue and sc_lock before memset */
	void	*tmp = sc->sc_lock;
	void	*tmp2 = sc->os_data;
	chiscsi_queue *sc_queue[CH_SCMD_Q_MAX];

	for (i = 0; i < CH_SCMD_Q_MAX; i++)
		sc_queue[i] = sc->sc_queue[i];

	memset(sc, 0, ISCSI_SCSI_COMMAND_SIZE);

	if (tmp) {
		memset(tmp, 0, os_lock_size);
		sc->sc_lock = tmp;
	}
	os_lock_init(sc->sc_lock);
	for (i = 0; i < CH_SCMD_Q_MAX; i++, offset += ISCSI_QUEUE_SIZE) {
		sc->sc_queue[i] = sc_queue[i];
		ch_queue_init(sc->sc_queue[i]);
	}
	sc->os_data = tmp2;
	os_data_counter_set(sc->os_data, 0);

	sc->sc_ddp_tag = sc->sc_itt = ISCSI_INVALID_TAG;
}


void chiscsi_scsi_command_display(chiscsi_scsi_command *sc, int detail)
{
	static const char *const scmd_tmstamp_str[CH_SCMD_TM_MAX] = {
		"bhs_parsed",
		"fp_cdb_rcved",
		"fp_data_xfer_status",
		"chiscsi_buffer_ready",
		"chiscsi_exe_status",
		"it_scmd_done",
		"fp_abort",
		"fp_abort_status",
		"fp_tmf",
		"fp_cleanup",
		"chiscsi_abort",
		"chiscsi_abort_status",
		"chiscsi_tmf_done",
		"chiscsi_ready_2_release",
		"exe_submit",
		"exe_done_n",
		"exe_complete",
		"state_2_init",
		"state_2_exe_ready",
		"state_2_executing",
		"state_2_r_xfer",
		"state_2_w_buf_wait",
		"state_2_w_buf_ready",
		"state_2_w_xfer",
		"state_2_status",
		"state_2_done",
		"state_2_closed"
	};
	int i;

	if (!sc) {
		os_log_error("%s: sc NULL.\n", __func__);
		return;
	}

	os_log_info("SCMD: 0x%p, 0x%p,0x%p, %u, f 0x%x,0x%lx,0x%lx, itt 0x%x.\n",
		sc, sc->sc_sess, sc->sc_conn, sc->sc_idx, sc->sc_flag,
		sc->sc_fscsi, sc->sc_fpriv, sc->sc_itt);
	os_log_info("\t0x%p, lu %u/%u, xfer %u,%u,%u, blk %llu,%u, tag %u,0x%x,0x%x.\n",
		sc, sc->sc_lun, sc->sc_lun_acl, sc->sc_xfer_len,
		sc->sc_xfer_left, sc->sc_xfer_cnt, sc->sc_lba, sc->sc_blk_cnt,
		sc->sc_idx, sc->sc_sw_tag, sc->sc_ddp_tag);
	os_log_info("\t0x%p, s %u, sn %u,%u, rsp 0x%x,0x%x, sess 0x%p, conn 0x%p.\n",
		sc, sc->sc_state, sc->sc_cmdsn, sc->sc_statsn, sc->sc_status,
		sc->sc_response, sc->sc_sess, sc->sc_conn);

	if (!detail)
		return;

#if 0
	if (sc->sc_ieps) {
		char buf[80];
		chiscsi_tcp_endpoints_sprintf(sc->sc_ieps, buf);
		os_log_info("SCMD: 0x%p, %s.\n", sc, buf);
	}
#endif

	chiscsi_sgl_display("SCMD:", &sc->sc_sgl, detail, 0);

	os_log_info("SCMD timstamp:\n", 0);
	for (i = 0; i < CH_SCMD_TM_MAX; i++)
		os_log_info("\t%s: %lu.\n",
			scmd_tmstamp_str[i], sc->timestamps[i]);
}

void chiscsi_iscsi_command_dump(chiscsi_scsi_command *sc)
{
	chiscsi_scsi_command_display(sc, 1);
}

chiscsi_scsi_command *iscsi_session_find_scmd_by_itt(iscsi_session * sess,
				iscsi_connection *conn, unsigned int itt,
				int check_doneq)
{
	chiscsi_scsi_command *sc;
	chiscsi_queue *q = sess->s_queue[SESS_SCMDQ_NEW];

	scmd_qsearch_by_ITT(nolock, q, sc, itt);
	if (sc && (sc->sc_conn == conn))
		return sc;
	return NULL;
}


static int isgl_alloc_single_buffer(chiscsi_sgl *sgl, unsigned int dlen)
{
	sgl->sgl_vecs = (unsigned char *)os_alloc(dlen, 1, 1);
	if (!sgl->sgl_vecs)
		return -ISCSI_ENOMEM;

	sgl->sgl_flag = ISCSI_SGLF_LOCAL;
	sgl->sgl_vecs_nr = 0;
	sgl->sgl_length = dlen;

	return 0;
}

static int isgl_alloc_pages(chiscsi_sgl *sgl, unsigned int dlen)
{
	unsigned int len = dlen & (~os_page_mask);
	int npages = (dlen + os_page_size - 1) >> os_page_shift;
        chiscsi_sgvec *sg = chiscsi_sglist_alloc_with_page(npages, 1);

        if (!sg)
                return -ISCSI_ENOMEM;

        if (len)
                sg[npages - 1].sg_length = len;

        sgl->sgl_flag = ISCSI_SGLF_LOCAL;
        sgl->sgl_vecs_nr = npages;
        sgl->sgl_length = dlen;
        sgl->sgl_vecs = (unsigned char *)sg;

	return 0;
}

int chiscsi_scsi_command_allocate_local_data(chiscsi_scsi_command *sc)
{
	int rv;

	if (sc->sc_xfer_len >= (os_page_size >> 1))
		rv = isgl_alloc_pages(&sc->sc_sgl, sc->sc_xfer_len);
	else
		rv = isgl_alloc_single_buffer(&sc->sc_sgl, sc->sc_xfer_len);
	if (rv < 0)
		return rv;

	scmd_fpriv_set_bit(sc, CH_SFP_BUF_LOCAL_BIT);
	return 0;
}

static void scmd_release_local_data(chiscsi_scsi_command *sc)
{
	if (!scmd_fpriv_test_bit(sc, CH_SFP_BUF_LOCAL_BIT))
		return;

	if (sc->sc_sgl.sgl_vecs_nr) {
		/* sgl */
		chiscsi_sgvec *sgl = (chiscsi_sgvec *)sc->sc_sgl.sgl_vecs;

		if (sgl) {
			int     i;
			for (i = 0; i < sc->sc_sgl.sgl_vecs_nr; i++) {
				os_free_one_page(sgl[i].sg_page);
				sgl[i].sg_page = NULL;
				sgl[i].sg_addr = NULL;
			}
		}
		sc->sc_sgl.sgl_vecs_nr = 0;

		os_free(sgl);
		sc->sc_sgl.sgl_vecs = NULL;
		sc->sc_sgl.sgl_vec_last = NULL;

	} else if (sc->sc_sgl.sgl_vecs) {
		/* single buffer */
               	os_free(sc->sc_sgl.sgl_vecs);
		sc->sc_sgl.sgl_vecs = NULL;
		sc->sc_sgl.sgl_vec_last = NULL;
	}
}

void chiscsi_scsi_command_release_ddp_tag(chiscsi_scsi_command *sc)
{
	/* release ddp tag */
	if (scmd_fpriv_test_bit(sc, CH_SFP_BUF_DDP_MAPPED_BIT)) {
		scmd_fpriv_clear_bit(sc, CH_SFP_BUF_DDP_MAPPED_BIT);
		if (scmd_fpriv_test_bit(sc, CH_SFP_LU_MULTIPHASE_BIT)) {
			iscsi_target_task_tag_release_woff(sc->sc_odev, sc->sc_ddp_tag);
		} else {
			iscsi_tag_release(sc);
		}
	}
}

void chiscsi_scsi_command_release(chiscsi_scsi_command *sc,
					chiscsi_queue *freeq)
{
	int i;
	int async = scmd_fpriv_test_bit(sc, CH_SFP_LU_QUEUE_BIT) ? 1:0;

	if (async) os_lock_irq(sc->sc_lock);

	if (scmd_fscsi_test_bit(sc, CH_SFSCSI_HOLD_BIT) ||
			scmd_fscsi_test_bit(sc, CH_SFSCSI_TIMER_SET_BIT)) {
		os_log_info("sc 0x%p, itt 0x%x locked, %u,%u,%u, s %u, "
				"f 0x%x,0x%lx,0x%lx.\n",
			sc, sc->sc_itt, sc->sc_xfer_len, sc->sc_xfer_left,
			sc->sc_xfer_cnt, sc->sc_state, sc->sc_flag,
			sc->sc_fscsi, sc->sc_fpriv);
		//chiscsi_scsi_command_display(sc, 0);
		chiscsi_scsi_command_release_ddp_tag(sc);
		scmd_fscsi_set_bit(sc, CH_SFSCSI_FORCE_RELEASE_BIT);
		sc->sc_conn = NULL;
		sc->sc_sess = NULL;
		sc->sc_state = CH_SC_STATE_CLOSED;
		scmd_set_timestamp(sc, CH_SCMD_TM_STATE_2_CLOSED);
		if (async) os_unlock_irq(sc->sc_lock);
		return;
	} 
	if (async) os_unlock_irq(sc->sc_lock);

	/* release ddp tag */
	chiscsi_scsi_command_release_ddp_tag(sc);

	/* release data memory */
	if (scmd_fpriv_test_bit(sc, CH_SFP_BUF_LOCAL_BIT)) {
		scmd_release_local_data(sc);
	} else {
		if (sc->lu_class && sc->lu_class->fp_scsi_cmd_cleanup) {
			scmd_set_timestamp(sc, CH_SCMD_TM_FP_CLEANUP);
			sc->lu_class->fp_scsi_cmd_cleanup(sc);
		} else if (sc->sc_sgl.sgl_vecs_nr || sc->sc_sgl.sgl_vecs) {
			os_log_warn("lun class %s, itt 0x%x memory leak?.\n",
				sc->lu_class ? sc->lu_class->class_name : "?",
				sc, sc->sc_itt);
			chiscsi_scsi_command_display(sc, 1);
		}
	}

	/* any saved data pdus */
	for (i = 0; i < CH_SCMD_Q_MAX; i++)
		iscsi_pduq_free_all(sc->sc_queue[i], NULL);

	/* if (sess && sc->sc_idx > (sess->s_scmdqlen << 1))*/
	if (sc->sc_flag & SC_FLAG_RELEASE_WAIT) {
		/* hold on to the structure until
		 * chiscsi_scsi_command_ready_to_release() is called
		 */
		scmd_enqueue(lock, it_sc_pend_q, sc);
		/* allocate a new one to fill the freeq */
		if (freeq) {
			i = sc->sc_idx;
			sc = scmd_alloc();
			if (sc) {
				scmd_init(sc);
				sc->sc_idx = i;
				scmd_enqueue(nolock, freeq, sc);
			}
		}
	} else if (freeq) {
		scmd_enqueue(nolock, freeq, sc);
	} else {
		scmd_free(sc);
	}
}

void chiscsi_scsi_cmd_ready_to_release(chiscsi_scsi_command *sc)
{
	os_lock_irq(sc->sc_lock);
	scmd_fpriv_clear_bit(sc, CH_SFP_LU_SCSI_RELEASE_WAIT);
	if (sc->sc_flag & SC_FLAG_RELEASE_WAIT) {
		os_unlock_irq(sc->sc_lock);
		scmd_ch_qremove(lock, it_sc_pend_q, sc);
		scmd_free(sc);
	} else 
		os_unlock_irq(sc->sc_lock);
}

int chiscsi_scsi_command_pool_init(chiscsi_queue *scq, int max)
{
	int i;

	if (scq->q_cnt)
		return scq->q_cnt;

	for (i = 0; i < max; i++) {
		chiscsi_scsi_command *sc = scmd_alloc();

		if (!sc)
			break;

		scmd_init(sc);
		sc->sc_idx = i;
		scmd_enqueue(nolock, scq, sc);
	} 

	return i;
}

chiscsi_scsi_command *chiscsi_scsi_command_alloc(iscsi_connection *conn,
					unsigned int xfer)
{
	iscsi_session *sess = conn->c_sess;
	chiscsi_queue *freeq;
	chiscsi_scsi_command *sc;

	if (!sess) {
		os_log_info("%s: conn 0x%p, sess NULL.\n",
			__func__, conn);
		return NULL;
	}
        if (iscsi_sess_flag_test(sess, SESS_FLAG_CLOSE_BIT)) {
		os_log_info("%s: conn 0x%p, sess 0x%p closing.\n",
			__func__, conn, sess);
		return NULL;
	}

 	freeq = sess->s_queue[SESS_SCMDQ_FREE];
	scmd_dequeue(nolock, freeq, sc);
	if (sc) {
                unsigned int idx = sc->sc_idx;

		scmd_init(sc);
		sc->sc_idx = idx;
	} else {
		chiscsi_queue *connq = sess->s_queue[SESS_CONNQ];
		iscsi_connection *tmpconn;
		chiscsi_queue *newq = sess->s_queue[SESS_SCMDQ_NEW];

		os_log_info("sess 0x%p, %u~%u, scmd freeq %u, used %u, qlen %u/%u.\n",
			sess, sess->s_expcmdsn, sess->s_maxcmdsn,
			freeq->q_cnt, newq->q_cnt, sess->s_scmdqlen,
			sess->s_scmdmax);

		for (tmpconn = connq->q_head; tmpconn;
			tmpconn = tmpconn->c_next)
			iscsi_connection_display(tmpconn, NULL, 0, 0);

                for (sc = newq->q_head; sc; sc = sc->sc_next)
                        chiscsi_scsi_command_display(sc, 0);

#if 0
		if (conn->c_isock->s_mode & ISCSI_OFFLOAD_MODE_DDP)
			return NULL;
#endif
		sc = scmd_alloc();
		if (!sc)
			return NULL;
		scmd_init(sc);
		sc->sc_idx = sess->s_scmdmax;

		sess->s_scmdmax++;
	}

	return sc;
}

void iscsi_scmdq_free_by_conn(chiscsi_queue *scq, iscsi_connection * conn)
{
	chiscsi_scsi_command *sc, *scnext;

	for (sc = scq->q_head; sc; sc = scnext) {
		scnext = sc->sc_next;
		if (sc->sc_conn == conn) {
			scmd_ch_qremove(nolock, scq, sc);
			chiscsi_scsi_command_release(sc, NULL);
		}
	}
}

void iscsi_scmdq_free_all(chiscsi_queue *q)
{
	chiscsi_scsi_command *sc, *scnext;

	for (sc = q->q_head; sc; sc = scnext) {
		scnext = sc->sc_next;
		scmd_ch_qremove(nolock, q, sc);
		chiscsi_scsi_command_release(sc, NULL);
	}
}

/**
 * send data pdus from the scmd
 */
int chiscsi_scsi_command_burst_send_pdus(chiscsi_scsi_command * sc, int push)
{
	iscsi_connection *conn = sc->sc_conn;
	chiscsi_queue *fromq = sc->sc_queue[CH_SCMD_PDUQ];
	chiscsi_queue *toq = conn->c_queue[CONN_PDUQ_SEND];
	iscsi_pdu *pdu;

	if (!fromq->q_head) return 0;

	for (pdu = fromq->q_head; pdu; pdu = pdu->p_next) {
		int rv;
		rv = iscsi_pdu_prepare_to_send(pdu);
		if (rv < 0) return rv;
		sc->sc_xfer_left -= pdu->p_datalen;
	}
os_lock_irq(toq->q_lock);
	if (toq->q_head) {
		((iscsi_pdu *)toq->q_tail)->p_next = fromq->q_head;
	} else {
		toq->q_head = fromq->q_head;
	}
	toq->q_tail = fromq->q_tail;
	toq->q_cnt += fromq->q_cnt;

	fromq->q_cnt = 0;
	fromq->q_head = fromq->q_tail = NULL;
os_unlock_irq(toq->q_lock);

	/* Fix - Possible Starvation if iscsi_connection_push_pdus was called only if toq->q_cnt > 1 */
	if (push || toq->q_cnt > 1)
		return (iscsi_connection_push_pdus(conn));
	else 
		return 0;
}

/**
 * chiscsi_scsi_command_burst_build_data_pdus -- build pdus for a data burst of 
 *	"burstlen" and starting from "offset" into the sc data buffer
 * @sc -- the iscsi scsi command
 * @bhs_offset -- pdu BHS buffer offset value
 * @sgl_offset -- offset into the sc buffer
 * @burstlen --
 *
 * NOTE: the data pdus built will only have the following BHS field set
 *		- buffer offset
 *		- data segment length
 *		- lun
 *		- itt
 * 	the last pdu of the burst will have F bit set
 *
 * The calling function should make sure to fill the rest BHS fields such as
 *		- opcode
 *		- ttt
 *		- maxcmdsn
 *
 */
int chiscsi_scsi_command_burst_build_data_pdus(chiscsi_scsi_command * sc,
					     unsigned int sgl_offset,
					     unsigned int bhs_offset,
					     unsigned int burstlen)
{
	iscsi_connection *conn;
	chiscsi_queue *q;
	chiscsi_sgvec *sglist;
	unsigned int sgmax;
	unsigned int sgidx = 0, sgoffset = 0;
	int cnt = 0;
	int rv = 0;

	if (!burstlen)
		os_log_warn("%s: sc 0x%p, itt 0x%x, off %u/%u, burst 0.\n",
			__func__, sc, sc->sc_itt, sgl_offset, bhs_offset);

	os_lock_irq(sc->sc_lock);

	conn = sc->sc_conn;
	q = sc->sc_queue[CH_SCMD_PDUQ];
	sglist = (chiscsi_sgvec *)sc->sc_sgl.sgl_vecs;
	sgmax = sc->sc_sgl.sgl_vecs_nr;

	if ((sgl_offset >= sc->sc_sgl.sgl_length) ||
	    (burstlen > sc->sc_sgl.sgl_length) ||
	    (sgl_offset + burstlen) > sc->sc_sgl.sgl_length) {
		os_log_info("sc itt 0x%x, xfer %u, buf %u+%u, off %u,%u, NOT enough data.\n",
			sc->sc_itt, sc->sc_xfer_len, sc->sc_sgl.sgl_boff,
			sc->sc_sgl.sgl_length, sgl_offset, bhs_offset); 
		rv = -ISCSI_EINVAL;
		goto err_out;
	}

	if (sgmax) {
		sgidx = chiscsi_sglist_find_offset(sglist, sgmax, sgl_offset, &sgoffset);
		if (sgidx >= sgmax) {
			os_log_info("sc itt 0x%x, xfer %u, buf %u+%u, find sgl off %u failed.\n",
				sc->sc_itt, sc->sc_xfer_len,
				sc->sc_sgl.sgl_boff, sc->sc_sgl.sgl_length,
				sgl_offset);
			rv = -ISCSI_EINVAL;
			goto err_out;
		}
	}

	while (burstlen) {
		iscsi_pdu *pdu;
		unsigned int datalen =
			MINIMUM(burstlen, conn->c_pdudatalen_tmax);
		unsigned int nvecs = 1;

		if (sgmax) {	/* scatterlist */
			unsigned int len = sglist[sgidx].sg_length - sgoffset;
			unsigned int i = sgidx;
			for (++i; i < sgmax && len < datalen; i++) {
				len += sglist[i].sg_length;
				nvecs++;
			}

			if (len < datalen) {
				os_log_warn("sc build burst pdus, itt 0x%x, off %u/%u, not enought data %u < %u, idx %u.\n",
					 sc->sc_itt, sgl_offset,
					 sc->sc_sgl.sgl_length,
					 sgl_offset, len, datalen, sgidx);
				rv = -ISCSI_EINVAL;
				goto err_out;
			}
		}

		pdu = iscsi_pdu_get(conn, nvecs, 0, 0);
		if (!pdu) {
			os_log_info("get pdu nvecs %u OOM.\n", nvecs);
			return -ISCSI_ENOMEM;
		}

		pdu->p_sgcnt_used = nvecs;

		if (sgmax) {	/* scatterlist */
			unsigned int i, j = sgidx;
			unsigned int len = sglist[j].sg_length - sgoffset;

			pdu->p_sglist[0].sg_flag = sglist[j].sg_flag;

			pdu->p_sglist[0].sg_length = len;
			pdu->p_sglist[0].sg_page = sglist[j].sg_page;
			pdu->p_sglist[0].sg_offset =
				sglist[j].sg_offset + sgoffset;
			if (sglist[j].sg_addr)
				pdu->p_sglist[0].sg_addr =
					sglist[j].sg_addr + sgoffset;
			if (sglist[j].sg_dma_addr)
				pdu->p_sglist[0].sg_dma_addr =
					sglist[j].sg_dma_addr + sgoffset;

			for (i = 1, ++j; i < nvecs; i++, j++) {
				sgoffset = 0;
				len += sglist[j].sg_length;
				memcpy(&pdu->p_sglist[i], &sglist[j],
				       sizeof(chiscsi_sgvec));
			}
			/* last vec not used up */
			if (len > datalen) {
				nvecs--;
				pdu->p_sglist[nvecs].sg_length -=
					(len - datalen);
				sgoffset += pdu->p_sglist[nvecs].sg_length;
			} else {
				sgoffset = 0;
			}

			sgidx += nvecs;

		} else {	/* a single buffer */
			pdu->p_sglist[0].sg_addr =
				((unsigned char *)sc->sc_sgl.sgl_vecs) +
				sgl_offset;
			pdu->p_sglist[0].sg_length = datalen;
		}

		SET_PDU_DATA_SEGMENT_LENGTH(pdu, datalen);
		SET_PDU_LUN(pdu, sc->sc_lun);
		SET_PDU_ITT(pdu, sc->sc_itt);
		SET_PDU_BUFFER_OFFSET(pdu, bhs_offset);
		
		iscsi_pdu_enqueue(nolock, q, pdu);

		sgl_offset += datalen;
		bhs_offset += datalen;
		burstlen -= datalen;
		cnt++;

		if (!burstlen)
			SET_PDU_F(pdu);
	}

	os_unlock_irq(sc->sc_lock);
	return cnt;

err_out:
	os_unlock_irq(sc->sc_lock);
	return rv;
}

int chiscsi_scsi_command_check_data_pattern(chiscsi_scsi_command *sc,
					  unsigned int offset,
					  unsigned int dlen,
					  unsigned char pattern,
					  int check_before_offset)
{
	chiscsi_sgvec *sglist = (chiscsi_sgvec *)sc->sc_sgl.sgl_vecs;
	unsigned int sgmax = sc->sc_sgl.sgl_vecs_nr;
	int     rv;


	if ((offset >= sc->sc_xfer_len) || (dlen > sc->sc_xfer_len) ||
	    (offset + dlen) > sc->sc_xfer_len) {
		return -ISCSI_EINVAL;
	}

	if (sgmax) {	/* scatterlist */
		/* check 0 ~ offset */
		if (check_before_offset)
			rv = chiscsi_sglist_check_pattern(sglist, sgmax, 0,
							offset + dlen, pattern); 
		else 
			rv = chiscsi_sglist_check_pattern(sglist, sgmax, offset,
							dlen, pattern); 

		if (rv < 0) {
			os_log_error("sc itt 0x%x, off %u+%u, check pattern failed %d.\n",
			 	     sc->sc_itt, offset, dlen);
			return rv;
		}

	} else {	/* a single buffer */
		unsigned int pos = 0;
		unsigned int pos_max = offset + dlen;
		unsigned char *byte = (unsigned char *)sc->sc_sgl.sgl_vecs;

		if (check_before_offset) {
			pos = offset;
			byte += offset;
		}
		for (; pos < pos_max; pos++, byte++) {
			if (*byte != pattern) {
				os_log_error("sc itt 0x%x, off %u+%u, pos %u, 0x%x != 0x%x.\n",
					     sc->sc_itt, offset, dlen, pos,
					     *byte, pattern);
                        	return -ISCSI_EMISMATCH;
			}
                }
	}

	return 0;
}

