/*
 * iscsi_pdu.c -- iscsi pdu manipulation
 */

#include <common/os_builtin.h>
#include <iscsi_structs.h>
#include <iscsi_global.h>
#include <iscsi_control_defs.h>
#include <iscsi_pdu_defs.h>
#include <iscsi_target_api.h>

STATIC void iscsi_pdu_init(iscsi_pdu *, iscsi_connection *);
/*
 * display 
 */
int iscsi_pdu_display(iscsi_pdu * pdu, char *obuf, int obuflen, int detail)
{
	iscsi_connection *conn = pdu->p_conn;
	int     len = 0;
	char   *buf = obuf;
	int     buflen = obuflen;

	if (obuf) {
		len += sprintf(buf + len,
			       "PDU: mode 0x%x, %u=48+%u+%u+%u+%u+%u, f 0x%x, op 0x%x, off 0x%x, sg %u/%u.\n",
			       conn ? conn->c_offload_mode : 0xFF,
			       pdu->p_totallen, pdu->p_ahslen, pdu->p_hdlen,
			       pdu->p_datalen, pdu->p_padlen, pdu->p_ddlen,
			       pdu->p_flag, pdu->p_opcode, pdu->p_offset,
			       pdu->p_sgcnt_used, pdu->p_sgcnt_total);
		if (len >= buflen) {
			buflen = 0;
			goto out;
		}
		buf += len;
		buflen -= len;
	} else {
		os_log_info
			("PDU 0x%p: mode 0x%x, %u=48+%u+%u+%u+%u+%u, f 0x%x, op 0x%x, off 0x%x, sg %u/%u.\n",
			 pdu, conn ? conn->c_offload_mode : 0xFF, 
			 pdu->p_totallen, pdu->p_ahslen, pdu->p_hdlen, 
 			 pdu->p_datalen, pdu->p_padlen, pdu->p_ddlen,
			 pdu->p_flag, pdu->p_opcode, pdu->p_offset,
			 pdu->p_sgcnt_used, pdu->p_sgcnt_total);
	}

	if (!detail)
		goto out;
	len = iscsi_display_byte_string("PDU BHS", pdu->p_bhs, 0,
					ISCSI_BHS_SIZE, buf, buflen);
	if (obuf) {
		if (len >= buflen) {
			buflen = 0;
			goto out;
		}
		buf += len;
		buflen -= len;
	}

	if (pdu->p_hdlen) {
		unsigned int digest = os_ntohl(*pdu->p_hdigest);
		len = iscsi_display_byte_string("    HeaderDigest",
						(unsigned char *) &digest, 0, 4,
						buf, buflen);
		if (obuf) {
			if (len >= buflen) {
				buflen = 0;
				goto out;
			}
			buf += len;
			buflen -= len;
		}
	}

	if (pdu->p_ddlen) {
		unsigned int digest = os_ntohl(*pdu->p_ddigest);
		len = iscsi_display_byte_string("    DataDigest",
						(unsigned char *) &digest, 0, 4,
						buf, buflen);
		if (obuf) {
			if (len >= buflen) {
				buflen = 0;
				goto out;
			}
			buf += len;
			buflen -= len;
		}
	}

	if (pdu->p_datalen && pdu->p_sgcnt_used) {
		len = chiscsi_sglist_display("PDU", pdu->p_sglist,
					   pdu->p_sgcnt_used, buf, buflen, 0);
		if (obuf) {
			if (len >= buflen) {
				buflen = 0;
				goto out;
			}
			buf += len;
			buflen -= len;
		}
	}
#ifdef __DEBUG_DUMP_WHOLE_PDU__
{
	int i;
	for (i = 0; i < pdu->p_sgcnt_used; i++) {
		len += iscsi_display_byte_string("PDU sg",
					pdu->p_sglist[i].sg_addr,
					0, pdu->p_sglist[i].sg_length,
					obuf, buflen);
		if (obuf) {
			if (len >= buflen)
				goto out;
			buf = obuf + len;
			buflen -= len;
		}
	}
}
#endif
#if 0
	int     wlen;
	wlen = pdu->p_sglist[0].sg_length;
	len += iscsi_display_byte_string("PDU DATA 1st 16",
					 pdu->p_sglist[0].sg_addr,
					 0, MINIMUM(wlen, 16), buf, buflen);
	if (obuf) {
		if (len >= buflen)
			goto out;
		buf = wbuf + len;
		buflen -= len;
	}
	wlen = pdu->p_sglist[pdu->p_sgcnt_used - 1].sg_length;
	len += iscsi_display_byte_string("PDU DATA last 16",
					 pdu->p_sglist[pdu->p_sgcnt_used -
						       1].sg_addr,
					 (wlen > 16) ? (wlen - 16) : 0,
					 MINIMUM(wlen, 16), buf, buflen);
#endif

      out:
	return (obuf ? (obuflen - buflen) : 0);
}

/*
 * fill or release pdu structures in a queue
 */
void iscsi_connection_pdu_pool_release(iscsi_connection *conn)
{
	chiscsi_queue *q = conn->c_queue[CONN_PDUQ_FREE];
	iscsi_pdu *pdu;

	iscsi_pdu_dequeue(nolock, q, pdu);
	while (pdu) {
		os_free(pdu);
		iscsi_pdu_dequeue(nolock, q, pdu);
	}
}

void iscsi_connection_pdu_pool_fill(iscsi_connection *conn)
{
	chiscsi_queue *pduq = conn->c_queue[CONN_PDUQ_FREE];
	int	i;

	for (i = pduq->q_cnt; i < conn->c_pdupool_max; i++) {
		iscsi_pdu *pdu = os_alloc(ISCSI_PDU_CACHE_SIZE, 1, 1);
		if (!pdu) break;
		iscsi_pdu_init(pdu, conn);
		iscsi_pdu_enqueue(nolock, pduq, pdu);	
	}
}

/*
 * iscsi_pdu structure setup and cleanup
 */

/* free extra allocated memory in a pdu structure */
STATIC void iscsi_pdu_release_memory(iscsi_pdu * pdu)
{
	unsigned int flag = pdu->p_flag;
	unsigned int sgcnt = pdu->p_sgcnt_used;
	chiscsi_sgvec *sgl = pdu->p_sglist;

	os_log_debug(ISCSI_DBG_PDU, " release pdu 0x%p, flag 0x%x.\n", pdu, flag);

	os_log_debug(ISCSI_DBG_PDU, 
			" sgl 0x%p, sg_dma_addr 0x%p, sg_addr 0x%p\n",
			sgl, sgl->sg_dma_addr, sgl->sg_addr );
	
	pdu->p_flag = 0;
	/* for received pdus only */
	if (flag & ISCSI_PDU_FLAG_DATA_MAPPED) {
		os_chiscsi_sglist_page_unmap(sgl, sgcnt);
	}

	/* free data/ahs/sglist */
	if (sgcnt && (flag & ISCSI_PDU_FLAG_DATA_BUF_LOCAL)) {
		chiscsi_sglist_free_memory(sgl, sgcnt);
		pdu->p_sgcnt_used = 0;
	}

	if (pdu->p_ahs) {
		os_free(pdu->p_ahs);
		pdu->p_ahs = NULL;
	}

	if (pdu->p_sgcnt_total > ISCSI_PDU_SGCNT_DFLT) {
		os_free(pdu->p_sglist);
	}
}

void iscsi_pdu_done(iscsi_pdu * pdu)
{
	iscsi_connection *conn = pdu->p_conn;
	chiscsi_queue *pduq = conn ? conn->c_queue[CONN_PDUQ_FREE] : NULL;

	if (!pdu || (pdu->p_flag & ISCSI_PDU_FLAG_LOCKED)) {
		return;
	}

	os_log_debug(ISCSI_DBG_PDU, "pdu 0x%p done.\n", pdu);

	iscsi_pdu_release_memory(pdu);
	if (conn && pduq && pduq->q_cnt < conn->c_pdupool_max) {
		iscsi_pdu_enqueue(nolock, pduq, pdu);
	} else {
		os_free(pdu);
	}

	return;
}

STATIC void iscsi_pdu_init(iscsi_pdu *pdu, iscsi_connection *conn)
{
	int     offset = sizeof(iscsi_pdu);
//	void	*pg = pdu->p_page;

	memset(pdu, 0, ISCSI_PDU_CACHE_SIZE);

	pdu->p_sglist = (chiscsi_sgvec *) (PTR_OFFSET(pdu, offset));
	offset += ISCSI_PDU_SGCNT_DFLT * (sizeof(chiscsi_sgvec));

//	pdu->p_page = pg;
	pdu->p_conn = conn;
	pdu->p_itt = ISCSI_INVALID_TAG;
	pdu->p_sgcnt_total = ISCSI_PDU_SGCNT_DFLT;

	/* set up pdu structure, and allocate ahs/data/sglist */
	pdu->p_bhs = pdu->p_head;
	pdu->p_hdigest = (unsigned int *) (&(pdu->p_head[ISCSI_BHS_SIZE]));
	pdu->p_ddigest = (unsigned int *) (&(pdu->p_tail[ISCSI_PDU_MAX_PAD_SIZE]));

	pdu->p_prot_sglist = pdu->p_pi_sglist;
	pdu->p_pi_sgcnt_total = ISCSI_PDU_PI_SGBUF_COUNT;
}

iscsi_pdu *iscsi_pdu_get(iscsi_connection * conn, unsigned int sgcnt,
			 unsigned int ahslen, unsigned int datalen)
{
	chiscsi_queue *pduq = NULL;
	iscsi_pdu *pdu;
	int     rv = 0;

	if(!conn)
		return NULL;
	
	if (sgcnt && datalen) {
		os_log_error("alloc pdu with sgcnt %u, and datalen %u.\n",
				sgcnt, datalen);
		return NULL;
	}

	pduq = conn->c_queue[CONN_PDUQ_FREE];

	if (pduq->q_head) {
		iscsi_pdu_dequeue(nolock, pduq, pdu);
	} else {
		pdu = os_alloc(ISCSI_PDU_CACHE_SIZE, 1, 1);
	}

	if (pdu == NULL) {
		//os_log_warn("conn 0x%p, OOM, pool %u, sg %u, ahs %u, data %u.\n",
		//	    conn, pduq->q_cnt, sgcnt, ahslen, datalen);
		return NULL;
	}

	/* set up the basic structure */
	iscsi_pdu_init(pdu, conn);

	if (sgcnt > pdu->p_sgcnt_total) {
		rv = iscsi_pdu_enlarge_sglist(pdu, sgcnt);
		if (rv < 0) {
			goto err_out;
		}
	}

	if (ahslen) {
		ahslen = (ahslen + 3) & (~0x3);
		pdu->p_ahs = os_alloc(ahslen, 1, 1);
		if (!pdu->p_ahs) {
			goto err_out;
		}
		/* os_alloc does memset() */
		pdu->p_ahslen = ahslen;
	}

	if (datalen) {
		rv = iscsi_pdu_alloc_data_buffer(pdu, datalen);
		if (rv < 0)
			goto err_out;
	}

	os_log_debug(ISCSI_DBG_PDU, "get pdu 0x%p.\n", pdu);
	return pdu;

err_out:
	if (pdu) {
		iscsi_pdu_done(pdu);
	}
	return NULL;
}

/* the calling function should hold the queue lock if necessary */
iscsi_pdu *iscsi_pduq_search(chiscsi_queue * pduq, unsigned char opcode,
			     unsigned int itt, unsigned int ttt,
			     unsigned int search_flag)
{
	iscsi_pdu *pdu;

	for (pdu = pduq->q_head; pdu; pdu = pdu->p_next) {
		unsigned int flag = 0;
		if (GET_PDU_OPCODE(pdu) == opcode)
			flag |= ISCSI_PDU_MATCH_OPCODE;
		if (GET_PDU_ITT(pdu) == itt)
			flag |= ISCSI_PDU_MATCH_ITT;
		if (GET_PDU_TTT(pdu) == ttt)
			flag |= ISCSI_PDU_MATCH_TTT;
		if ((flag & search_flag) == search_flag)
			break;
	}
	return pdu;
}

void iscsi_pduq_free_by_conn(chiscsi_queue * q, iscsi_connection * conn)
{
	iscsi_pdu *pdu = q->q_head;
	while (pdu) {
		iscsi_pdu *next = pdu->p_next;
		if (pdu->p_conn == conn) {
			iscsi_pdu_ch_qremove(nolock, q, pdu);
			pdu->p_flag &= ~ISCSI_PDU_FLAG_LOCKED;
			iscsi_pdu_done(pdu);
		}
		pdu = next;
	}
}

void iscsi_pduq_free_all(chiscsi_queue * q, iscsi_pdu *reserved_pdu)
{
	iscsi_pdu *pdu;
	iscsi_pdu_dequeue(nolock, q, pdu);
	while (pdu) {
		pdu->p_flag &= ~ISCSI_PDU_FLAG_LOCKED;
		if (!reserved_pdu || pdu != reserved_pdu) {
			pdu->p_conn = NULL;
			iscsi_pdu_done(pdu);
		}
		iscsi_pdu_dequeue(nolock, q, pdu);
	}
}

int iscsi_pdu_enlarge_sglist(iscsi_pdu * pdu, unsigned int new_sgcnt)
{
	unsigned int old_sgcnt = pdu->p_sgcnt_total;
	unsigned int size = sizeof(chiscsi_sgvec);
	chiscsi_sgvec *sglist;
		
	sglist = iscsi_enlarge_memory((void *) pdu->p_sglist,
				      old_sgcnt * size, new_sgcnt * size, 0);
	if (!sglist)
		return -ISCSI_ENOMEM;

	if (pdu->p_sgcnt_total > ISCSI_PDU_SGCNT_DFLT)
		os_free(pdu->p_sglist);

	pdu->p_sglist = sglist;
	pdu->p_sgcnt_total = new_sgcnt;

	os_log_debug(ISCSI_DBG_PDU,
		     "pdu 0x%p, enlarge sglist %u -> %u.\n",
		     pdu, old_sgcnt, new_sgcnt);
	return 0;
}

int iscsi_pdu_alloc_data_buffer(iscsi_pdu * pdu, unsigned int datalen)
{
	chiscsi_sgvec *sgl;
	unsigned int npage = 0;
	int rv;

	if (datalen && datalen >= os_page_size)
		npage = (datalen + os_page_size - 1) >> os_page_shift;

	if (npage > pdu->p_sgcnt_total) {
		rv = iscsi_pdu_enlarge_sglist(pdu, npage);
		if (rv < 0) return rv;
	}

	pdu->p_datalen = datalen;
	sgl = pdu->p_sglist;

	if (npage) {
		unsigned int len = datalen & (~os_page_mask);
		rv = chiscsi_sglist_add_pages(sgl, npage, 1);
		if (rv < 0) return rv;
		if (len)
			sgl[npage - 1].sg_length = len;
		pdu->p_sgcnt_used = npage;
	} else {
		rv = chiscsi_sglist_add_buffer(sgl, datalen, 0);
		if (rv < 0) return rv;
		sgl->sg_length = datalen;
		pdu->p_sgcnt_used = 1;
	}

	pdu->p_flag |= ISCSI_PDU_FLAG_DATA_BUF_LOCAL;
	return 0;
}

int iscsi_pdu_sglist_setup_by_offset(iscsi_pdu *pdu, unsigned int offset,
				chiscsi_sgvec *fsgl, unsigned int fsgmax)
{
	unsigned int datalen = pdu->p_datalen;

	/* one continuous buffer */
	if (!fsgmax) {
		pdu->p_sglist[0].sg_addr = ((unsigned char *)(fsgl)) + offset;
		pdu->p_sglist[0].sg_length = datalen;
		pdu->p_sgcnt_used = 1;

	} else if (fsgmax == 1) {
		pdu->p_sglist[0].sg_addr = fsgl[0].sg_addr + offset;
		pdu->p_sglist[0].sg_length = datalen;
		pdu->p_sgcnt_used = 1;
		os_log_debug(ISCSI_DBG_PDU,
				"sg_addr 0x%p = 0x%p+ %d\n",
				pdu->p_sglist[0].sg_addr, fsgl[0].sg_addr, offset );
		os_log_debug(ISCSI_DBG_PDU,
				"fsgmax %d, sg_dma_addr 0x%p\n", fsgmax,
				pdu->p_sglist[0].sg_dma_addr);
	} else {
		unsigned int sgoffset = 0;
		unsigned int sgcnt = 1;
		unsigned int sglen;
		int rv;
		int j;
		chiscsi_sgvec *sg = NULL, *sgstart = NULL;

		/* find offset and associated sg*/
		rv = chiscsi_sglist_find_offset(fsgl, fsgmax, offset, &sgoffset);
		if (rv >= fsgmax)
			return -ISCSI_EINVAL;
		sg = fsgl + rv;

		sgstart = sg;
		sglen = sg->sg_length - sgoffset;
		for (sg = sg->sg_next ; sglen < datalen && sg; sgcnt++, sg = sg->sg_next) {
			sglen += sg->sg_length;
		}

		if (pdu->p_sgcnt_total < sgcnt) {
			rv = iscsi_pdu_enlarge_sglist(pdu, sgcnt);
			if (rv < 0) return rv;
		}
	
		/* data will be copied, so only need addr + len */
		for (sg = sgstart, j = 0; j < sgcnt && sg; j++, sg = sg->sg_next) {
			pdu->p_sglist[j].sg_addr = sg->sg_addr;
			pdu->p_sglist[j].sg_length = sg->sg_length;
		}

		pdu->p_sgcnt_used = sgcnt;

		/* resize the first buffer */
		pdu->p_sglist[0].sg_addr += sgoffset;
		pdu->p_sglist[0].sg_length -= sgoffset;

		/* resize the last buffer */
		if (sglen > datalen) {
			sgcnt--;
			pdu->p_sglist[sgcnt].sg_length -= sglen - datalen;
		}
	}

	return 0;
}

int iscsi_pdu_pi_sglist_setup_by_offset(iscsi_pdu *pdu, unsigned int pi_offset,
		chiscsi_sgvec *sgl, unsigned int fsgmax)
{
	unsigned int pi_len = pdu->pi_info.pi_len;

	/* Setup sgl in pdu->p_prot_sglist to copy pi */
	if (!fsgmax) {
		pdu->p_prot_sglist[0].sg_addr =
			((unsigned char *)sgl) + pi_offset;
		pdu->p_prot_sglist[0].sg_length = pi_len;
		pdu->p_pi_sgcnt_used =  1;
	} else if (fsgmax == 1) {
		pdu->p_prot_sglist[0].sg_addr = sgl[0].sg_addr + pi_offset;
		pdu->p_prot_sglist[0].sg_length = pi_len;
		pdu->p_pi_sgcnt_used =  1;

	} else {
		unsigned int sgoffset = 0;
		unsigned int sgcnt = 1;
		unsigned int sglen;
		int rv;
		int j;
		chiscsi_sgvec *sg = NULL, *sgstart = NULL;

		/* Find offset and associated sg */
		rv = chiscsi_sglist_find_offset(sgl, fsgmax, pi_offset, &sgoffset);
		if (rv >= fsgmax)
			return -ISCSI_EINVAL;
		sg = sgl + rv;

		sgstart = sg;
		sglen = sg->sg_length - sgoffset;
		for (sg = sg->sg_next; sglen < pi_len && sg;
					sgcnt++, sg = sg->sg_next) {
			sglen += sg->sg_length;
		}
		if (pdu->p_pi_sgcnt_total < sgcnt) {
			/* Error. Debug it */
			os_log_error("pi sgcnt %u must be less than total sg %u\n",
				sgcnt, pdu->p_pi_sgcnt_total);
			return -ISCSI_EINVAL;
		}
		/* data will be copied, so only need addr + len */
		for (sg = sgstart, j = 0; j < sgcnt && sg; j++, sg = sg->sg_next) {
			pdu->p_prot_sglist[j].sg_addr  = sg->sg_addr;
			pdu->p_prot_sglist[j].sg_length  = sg->sg_length;
		}
		pdu->p_pi_sgcnt_used = sgcnt;

		/* resize first buffer */
		pdu->p_prot_sglist[0].sg_addr += sgoffset;
		pdu->p_prot_sglist[0]. sg_length -= sgoffset;

		/* resize the last buffer */
		if (sglen > pi_len) {
			sgcnt--;
			pdu->p_prot_sglist[sgcnt].sg_length -= sglen - pi_len;
		}
	}

	return 0;
}

/**
 * iscsi_pdu_parse_bhs
 */
int iscsi_pdu_parse_header(iscsi_pdu *pdu)
{
	iscsi_connection	*conn = NULL;
	unsigned char opcode = GET_PDU_OPCODE(pdu);
	unsigned int datalen = GET_PDU_DATA_SEGMENT_LENGTH(pdu);

	conn = pdu->p_conn;
	
	if (!conn || pdu->p_offset != ISCSI_BHS_SIZE) {
		os_log_info("pdu parse header: 0x%p, conn 0x%p, offset %u.\n",
			pdu, conn, pdu->p_offset);
		return 0; 
	}

	pdu->p_opcode = opcode;
	pdu->p_hdlen = conn->c_hdigest_len;
	pdu->p_ahslen = (GET_PDU_TOTAL_AHS_LENGTH(pdu)) << 2;  
	if (pdu->pi_info.prot_op) {
#if 0
		unsigned int rcvd_offset = GET_PDU_BUFFER_OFFSET(pdu);
#endif
		unsigned int exp_num_sector = pdu->pi_info.pi_len >> 3;
		/* Lets decide the exact prot_op. is it DIF or DIX? */
		/* At this point pdu->p_totallen hold the DDP'ed size. i.e.
 		 * In DIF:
 		 * 	pdu->p_totallen = ISCSI_BHS_SIZE + data length + pi_len.
 		 * In DIX:
 		 * 	pdu->p_totallen = ISCSI_BHS_SIZE + data length.
 		 * 	pi_len is not included in p_totallen.
 		 *
 		 * Therefore:
 		 * 	num_sector = pi_len >> 3;
 		 * 	expected datalen = num_sector << lu_sect_shift.
 		 *	if (pdu->p_totallen ==
 		 * 	   	(ISCSI_BHS_SIZE + expected_datalen + pi_len))
 		 * 	   	Its DIF.
 		 * 	   else
 		 * 	   	Its DIX
 		 */
		if (pdu->p_totallen == (ISCSI_BHS_SIZE +
					 (exp_num_sector << lu_sect_shift) +
					   pdu->pi_info.pi_len)) /* DIF */
			pdu->pi_info.prot_op = ISCSI_PI_OP_SCSI_PROT_READ_PASS;
		else /* DIX */
			pdu->pi_info.prot_op =
					ISCSI_PI_OP_SCSI_PROT_READ_INSERT;

#if 0
		os_log_info("%s: prot_op %u, pi_len %u, "
			"datalen %u, pdu->p_totallen %u, rcvd_offset %u\n",
			__func__, pdu->pi_info.prot_op,
			pdu->pi_info.pi_len,
			datalen, pdu->p_totallen, rcvd_offset);
#endif

		if (pdu->pi_info.prot_op == ISCSI_PI_OP_SCSI_PROT_READ_PASS) {
			datalen -= pdu->pi_info.pi_len;
		}
	}
	pdu->p_datalen = datalen;
	pdu->p_sn = GET_PDU_CMDSN(pdu);
	pdu->p_itt = GET_PDU_ITT(pdu);

	if (datalen) {
		unsigned char l = datalen & 0x3;
		pdu->p_padlen = l ? (4 - l) : 0; 
		pdu->p_ddlen = conn->c_ddigest_len; 
	} 
	pdu->p_totallen = ISCSI_BHS_SIZE + pdu->p_ahslen + pdu->p_hdlen +
			  pdu->p_datalen + pdu->p_padlen + pdu->p_ddlen;

	os_log_debug(ISCSI_DBG_PDU_RX,
		"conn 0x%p, rx pdu bhs 0x%p, op 0x%x, sn 0x%x, itt 0x%x, 48+%u+%u+%u+%u+%u.\n",
		conn, pdu, pdu->p_opcode, pdu->p_sn, pdu->p_itt,
		pdu->p_ahslen, pdu->p_hdlen, pdu->p_datalen,
		pdu->p_padlen, pdu->p_ddlen);
	//iscsi_display_byte_string("PDU BHS", pdu->p_bhs, 0, ISCSI_BHS_SIZE, NULL, 0);

	if (pdu->p_ahslen) {
		if (pdu->p_ahs)
			os_log_info("pdu 0x%p ahs already allocated?.\n", pdu);
		else
			pdu->p_ahs = os_alloc(pdu->p_ahslen, 1, 1);
		if (!pdu->p_ahs)
			return (-ISCSI_ENOMEM);
	}

	return 0;
}

/**
 * iscsi_pdu_prepare_to_send -- prepare a list of pdus to be sent on a connection
 * conn -- connection the pdu will be sent
 * pdulist --
 *
 * Return value: 
 *	# of pdus processed 
 *
 * This function sets pdus' digests, calculate the padding bytes, and queue 
 *	them up in the connection's tx queue.
 *
 */
int iscsi_pdu_prepare_to_send(iscsi_pdu * pdu)
{
	iscsi_connection *conn = pdu->p_conn;
	unsigned int total = pdu->p_totallen;
	unsigned int pi_on_wire = 0;
	unsigned int num_pdu = 1, hdr_len, iso_extra = 0;

	if (pdu->pi_info.prot_op == ISCSI_PI_OP_SCSI_PROT_WRITE_PASS)
		pi_on_wire = pdu->pi_info.pi_len;

	pdu->p_opcode = GET_PDU_OPCODE(pdu);
	pdu->p_offset = 0;
	pdu->p_ahslen = (GET_PDU_TOTAL_AHS_LENGTH(pdu)) << 2;
	/* If iso enabled, pdu->p_datalen is the data length of
	 * all the pdus included in ISO and pdu->p_pdulen is the length
	 * of a pdu. */
	pdu->p_datalen = GET_PDU_DATA_SEGMENT_LENGTH(pdu) - pi_on_wire;
	if (!(pdu->p_flag & ISCSI_PDU_FLAG_TX_ISO))
		pdu->p_pdulen = pdu->p_datalen;

	if (pdu->p_datalen) {
		/* ISO: add a new field pdu->p_pdulen and use it here
		 * instead of p_datalen */
		unsigned int len = pdu->p_pdulen & 0x3;
		pdu->p_padlen = len ? (4 - len) : 0;
	}

	/* no digest in the login phase */
	if (pdu->p_opcode != ISCSI_OPCODE_LOGIN_RESPONSE) {
		pdu->p_hdlen = conn->c_hdigest_len;
		if (pdu->p_datalen)
			pdu->p_ddlen = conn->c_ddigest_len;
	}

	hdr_len = ISCSI_BHS_SIZE + pdu->p_ahslen + pdu->p_hdlen +
		pdu->p_padlen + pdu->p_ddlen;
	/* if iso in pdu then compensate for iscsi hdrs for all
 	 * the PDUs adapter is going to form and send out of burst. */
	if (pdu->p_flag & ISCSI_PDU_FLAG_TX_ISO) {
		num_pdu = pdu->iso_info.num_pdu;
		/* include hdr_len in iso transfer. */
		pdu->iso_info.len = pdu->p_datalen + pi_on_wire + hdr_len -
			/* Not including digestlen as its generated in hw */
			pdu->p_hdlen - pdu->p_ddlen;
			/* Do not include pi_len in DIX case.
 			 * DIF case its needed TODO */
		iso_extra = pdu->iso_info.iso_extra = hdr_len * (num_pdu - 1);
	}

	pdu->p_totallen = hdr_len + pdu->p_datalen;

	if (pdu->p_flag & ISCSI_PDU_FLAG_TX_SEQ) {
		if (total != pdu->p_totallen) {
			conn->c_snd_nxt -= total;
			conn->c_snd_nxt += pdu->p_totallen + pi_on_wire +
						iso_extra;
		}
	} else {
		conn->c_snd_nxt += pdu->p_totallen + pi_on_wire + iso_extra;
		pdu->p_flag |= ISCSI_PDU_FLAG_TX_SEQ;
	}

	os_log_debug(ISCSI_DBG_PDU_TX,
		     "tx pdu 0x%p, total %u = 48+%u+%u+%u+%u+%u, op 0x%x, "
		     "prot_op %u, pi_on_wire %u, iso_extra %u, sg=%u.\n",
		     pdu, pdu->p_totallen, pdu->p_ahslen, pdu->p_hdlen,
		     pdu->p_datalen, pdu->p_padlen, pdu->p_ddlen,
		     pdu->p_opcode, pdu->pi_info.prot_op, pi_on_wire,
		     iso_extra, pdu->p_sgcnt_used);

	if (pdu->p_hdlen)
		iscsi_header_digest_set(pdu);
	if (pdu->p_ddlen)
		iscsi_data_digest_set(pdu);

	return 0;
}


/*
 *
 * copy a pdu or all the pdus in a queue to a buffer or scatter-gather list
 *
 */

/*
 * copy the pdu data to one buffer, if buffer is NULL, allocate buffer 
 * the calling function should make sure the pdu->p_offset is set properly
 */
int iscsi_pdu_data_to_one_buffer(iscsi_pdu * pdu, char **bufpp)
{
	int     i, len = pdu->p_datalen;
	char *bufp = *bufpp;

	if (!len)
		return 0;

	if (!bufp) {
		bufp = os_alloc(len, 1, 1);
		if (!bufp)
			return -ISCSI_ENOMEM;
		*bufpp = bufp;
	}

	bufp += pdu->p_offset;
	for (i = 0; i < pdu->p_sgcnt_used; i++) {
		memcpy(bufp, pdu->p_sglist[i].sg_addr,
		       pdu->p_sglist[i].sg_length);
		bufp += pdu->p_sglist[i].sg_length;
	}

	return pdu->p_datalen;
}

int iscsi_pduq_data_to_one_buffer(chiscsi_queue * pduq, char **bufpp)
{
	iscsi_pdu *pdu;
	char *bufp = *bufpp;
	int     i;
	int     len = 0;

	for (pdu = pduq->q_head; pdu; pdu = pdu->p_next) {
		len += pdu->p_datalen;
	}
	if (!len)
		return 0;

	if (!bufp) {
		bufp = os_alloc(len, 1, 1);
		if (!bufp)
			return -ISCSI_ENOMEM;
		*bufpp = bufp;
	}

	for (pdu = pduq->q_head; pdu; pdu = pdu->p_next) {
		char *dp = bufp + pdu->p_offset;
		for (i = 0; i < pdu->p_sgcnt_used; i++) {
			memcpy(dp, pdu->p_sglist[i].sg_addr,
			       pdu->p_sglist[i].sg_length);
			dp += pdu->p_sglist[i].sg_length;
		}
	}

	return len;
}

/* copy the pdu data to the sg: the data will be copied to the sg at
   (pdu's buffer offset) - sgoffset */
int iscsi_pdu_data_to_sglist(iscsi_pdu * pdu, chiscsi_sgvec * sg,
			     unsigned int sgcnt, unsigned int sgoffset)
{
	if (pdu->p_sgcnt_used) {
		unsigned int offset = pdu->p_offset;
		int     rv;

		if (sgoffset) {
			if (offset < sgoffset) {
				return 0;
			}
			offset -= sgoffset;
		}

		rv = chiscsi_sglist_copy_sgdata(offset, pdu->p_sglist, 
						   pdu->p_sgcnt_used, 
						   sg, sgcnt);

		if (rv != pdu->p_datalen) {
			int     i;
			os_log_warn
				("pdu data (%u) to sglist copied %d != %u.\n",
				 pdu->p_sgcnt_used, rv, pdu->p_datalen);

			for (i = 0; i < pdu->p_sgcnt_used; i++) {
				os_log_warn
					("pdu data: %d, len %u, off %u, addr 0x%p=0x%p+0x%x, 0x%x.\n",
					 i, pdu->p_sglist[i].sg_length,
					 pdu->p_sglist[i].sg_addr,
					 pdu->p_sglist[i].sg_page,
					 pdu->p_sglist[i].sg_offset,
					 pdu->p_sglist[i].sg_flag);
			}
			return -ISCSI_EINVAL;
		}
		return pdu->p_datalen;
	}
	return 0;
}

int iscsi_pduq_data_to_sglist(chiscsi_queue * pduq, chiscsi_sgvec * sg,
			      unsigned int sgcnt, unsigned int sgoffset)
{
	iscsi_pdu *pdu;
	int     copied = 0;
	int     rv;

	for (pdu = pduq->q_head; pdu; pdu = pdu->p_next) {
		rv = iscsi_pdu_data_to_sglist(pdu, sg, sgcnt, sgoffset);
		if (rv < 0)
			return rv;
		copied += rv;
	}

	return copied;
}

/*
 * iscsi digest
 */

/*
 *
 * CRC LOOKUP TABLE
 * ================
 * The following CRC lookup table was generated automatically
 * by the Rocksoft^tm Model CRC Algorithm Table Generation
 * Program V1.0 using the following model parameters:
 *
 * 	Width	: 4 bytes.
 *	Poly	: 0x1EDC6F41L
 *	Reverse	: TRUE
 *
 * For more information on the Rocksoft^tm Model CRC Algorithm,
 * see the document titled "A Painless Guide to CRC Error 
 * Detection Algorithms" by Ross Williams (ross@guest.adelaide.edu.au.).
 * This document is likely to be in the FTP archive 
 * "ftp.adelaide.edu.au/pub/rocksoft".  
 */

static unsigned int crc32Table[256] = {
	0x00000000L, 0xF26B8303L, 0xE13B70F7L, 0x1350F3F4L,
	0xC79A971FL, 0x35F1141CL, 0x26A1E7E8L, 0xD4CA64EBL,
	0x8AD958CFL, 0x78B2DBCCL, 0x6BE22838L, 0x9989AB3BL,
	0x4D43CFD0L, 0xBF284CD3L, 0xAC78BF27L, 0x5E133C24L,
	0x105EC76FL, 0xE235446CL, 0xF165B798L, 0x030E349BL,
	0xD7C45070L, 0x25AFD373L, 0x36FF2087L, 0xC494A384L,
	0x9A879FA0L, 0x68EC1CA3L, 0x7BBCEF57L, 0x89D76C54L,
	0x5D1D08BFL, 0xAF768BBCL, 0xBC267848L, 0x4E4DFB4BL,
	0x20BD8EDEL, 0xD2D60DDDL, 0xC186FE29L, 0x33ED7D2AL,
	0xE72719C1L, 0x154C9AC2L, 0x061C6936L, 0xF477EA35L,
	0xAA64D611L, 0x580F5512L, 0x4B5FA6E6L, 0xB93425E5L,
	0x6DFE410EL, 0x9F95C20DL, 0x8CC531F9L, 0x7EAEB2FAL,
	0x30E349B1L, 0xC288CAB2L, 0xD1D83946L, 0x23B3BA45L,
	0xF779DEAEL, 0x05125DADL, 0x1642AE59L, 0xE4292D5AL,
	0xBA3A117EL, 0x4851927DL, 0x5B016189L, 0xA96AE28AL,
	0x7DA08661L, 0x8FCB0562L, 0x9C9BF696L, 0x6EF07595L,
	0x417B1DBCL, 0xB3109EBFL, 0xA0406D4BL, 0x522BEE48L,
	0x86E18AA3L, 0x748A09A0L, 0x67DAFA54L, 0x95B17957L,
	0xCBA24573L, 0x39C9C670L, 0x2A993584L, 0xD8F2B687L,
	0x0C38D26CL, 0xFE53516FL, 0xED03A29BL, 0x1F682198L,
	0x5125DAD3L, 0xA34E59D0L, 0xB01EAA24L, 0x42752927L,
	0x96BF4DCCL, 0x64D4CECFL, 0x77843D3BL, 0x85EFBE38L,
	0xDBFC821CL, 0x2997011FL, 0x3AC7F2EBL, 0xC8AC71E8L,
	0x1C661503L, 0xEE0D9600L, 0xFD5D65F4L, 0x0F36E6F7L,
	0x61C69362L, 0x93AD1061L, 0x80FDE395L, 0x72966096L,
	0xA65C047DL, 0x5437877EL, 0x4767748AL, 0xB50CF789L,
	0xEB1FCBADL, 0x197448AEL, 0x0A24BB5AL, 0xF84F3859L,
	0x2C855CB2L, 0xDEEEDFB1L, 0xCDBE2C45L, 0x3FD5AF46L,
	0x7198540DL, 0x83F3D70EL, 0x90A324FAL, 0x62C8A7F9L,
	0xB602C312L, 0x44694011L, 0x5739B3E5L, 0xA55230E6L,
	0xFB410CC2L, 0x092A8FC1L, 0x1A7A7C35L, 0xE811FF36L,
	0x3CDB9BDDL, 0xCEB018DEL, 0xDDE0EB2AL, 0x2F8B6829L,
	0x82F63B78L, 0x709DB87BL, 0x63CD4B8FL, 0x91A6C88CL,
	0x456CAC67L, 0xB7072F64L, 0xA457DC90L, 0x563C5F93L,
	0x082F63B7L, 0xFA44E0B4L, 0xE9141340L, 0x1B7F9043L,
	0xCFB5F4A8L, 0x3DDE77ABL, 0x2E8E845FL, 0xDCE5075CL,
	0x92A8FC17L, 0x60C37F14L, 0x73938CE0L, 0x81F80FE3L,
	0x55326B08L, 0xA759E80BL, 0xB4091BFFL, 0x466298FCL,
	0x1871A4D8L, 0xEA1A27DBL, 0xF94AD42FL, 0x0B21572CL,
	0xDFEB33C7L, 0x2D80B0C4L, 0x3ED04330L, 0xCCBBC033L,
	0xA24BB5A6L, 0x502036A5L, 0x4370C551L, 0xB11B4652L,
	0x65D122B9L, 0x97BAA1BAL, 0x84EA524EL, 0x7681D14DL,
	0x2892ED69L, 0xDAF96E6AL, 0xC9A99D9EL, 0x3BC21E9DL,
	0xEF087A76L, 0x1D63F975L, 0x0E330A81L, 0xFC588982L,
	0xB21572C9L, 0x407EF1CAL, 0x532E023EL, 0xA145813DL,
	0x758FE5D6L, 0x87E466D5L, 0x94B49521L, 0x66DF1622L,
	0x38CC2A06L, 0xCAA7A905L, 0xD9F75AF1L, 0x2B9CD9F2L,
	0xFF56BD19L, 0x0D3D3E1AL, 0x1E6DCDEEL, 0xEC064EEDL,
	0xC38D26C4L, 0x31E6A5C7L, 0x22B65633L, 0xD0DDD530L,
	0x0417B1DBL, 0xF67C32D8L, 0xE52CC12CL, 0x1747422FL,
	0x49547E0BL, 0xBB3FFD08L, 0xA86F0EFCL, 0x5A048DFFL,
	0x8ECEE914L, 0x7CA56A17L, 0x6FF599E3L, 0x9D9E1AE0L,
	0xD3D3E1ABL, 0x21B862A8L, 0x32E8915CL, 0xC083125FL,
	0x144976B4L, 0xE622F5B7L, 0xF5720643L, 0x07198540L,
	0x590AB964L, 0xAB613A67L, 0xB831C993L, 0x4A5A4A90L,
	0x9E902E7BL, 0x6CFBAD78L, 0x7FAB5E8CL, 0x8DC0DD8FL,
	0xE330A81AL, 0x115B2B19L, 0x020BD8EDL, 0xF0605BEEL,
	0x24AA3F05L, 0xD6C1BC06L, 0xC5914FF2L, 0x37FACCF1L,
	0x69E9F0D5L, 0x9B8273D6L, 0x88D28022L, 0x7AB90321L,
	0xAE7367CAL, 0x5C18E4C9L, 0x4F48173DL, 0xBD23943EL,
	0xF36E6F75L, 0x0105EC76L, 0x12551F82L, 0xE03E9C81L,
	0x34F4F86AL, 0xC69F7B69L, 0xD5CF889DL, 0x27A40B9EL,
	0x79B737BAL, 0x8BDCB4B9L, 0x988C474DL, 0x6AE7C44EL,
	0xBE2DA0A5L, 0x4C4623A6L, 0x5F16D052L, 0xAD7D5351L
};

#define CRC32C_PRELOAD 0xffffffff

STATIC unsigned int calculate_crc32c(const void *buf, int len, unsigned int crc)
{
	unsigned char *p = (unsigned char *) buf;
	if (!len)
		return crc;
	while (len-- > 0)
		crc = crc32Table[(crc ^ *p++) & 0xff] ^ (crc >> 8);
	return crc;
}

/* set the PDU's header digest appropriately */
int iscsi_header_digest_set(iscsi_pdu * pdu)
{
	iscsi_connection *conn = pdu->p_conn;
	if (!conn->c_hdigest_len)
		return 0;
	if (conn->c_offload_mode & ISCSI_OFFLOAD_MODE_CRC)
		return 0;
	*pdu->p_hdigest = (~calculate_crc32c(pdu->p_bhs, 48, CRC32C_PRELOAD));
	return 0;
}

/* set the PDU's data digest appropriately */
int iscsi_data_digest_set(iscsi_pdu * pdu)
{
	iscsi_connection *conn = pdu->p_conn;
	unsigned int i, crc = CRC32C_PRELOAD;
	int flag=0;

	if (!conn->c_ddigest_len)
		return 0;
	if (conn->c_offload_mode & ISCSI_OFFLOAD_MODE_CRC)
		return 0;
	if (!pdu->p_sgcnt_used)
		return 0;

	os_lock_os_data(conn->os_data);
	if ((pdu->p_sglist[0].sg_page != NULL) && !pdu->p_sglist[0].sg_addr){
		for (i = 0; i < pdu->p_sgcnt_used; i++) {
		if (!(pdu->p_sglist[i].sg_flag & CHISCSI_SG_SBUF_MAPPED)) 
			pdu->p_sglist[i].sg_flag |= CHISCSI_SG_SBUF_MAP_NEEDED;
		}
		os_chiscsi_sglist_page_map(pdu->p_sglist,pdu->p_sgcnt_used);
		flag = 1;
	}

	for (i = 0; i < pdu->p_sgcnt_used; i++) {
		if (!pdu->p_sglist[i].sg_addr)
			break;
		crc = calculate_crc32c(pdu->p_sglist[i].sg_addr,
				pdu->p_sglist[i].sg_length, crc);
	}

	if (flag == 1){
		for (i = 0; i < pdu->p_sgcnt_used; i++) {
			pdu->p_sglist[i].sg_flag &= ~CHISCSI_SG_SBUF_MAP_NEEDED;
		}
		os_chiscsi_sglist_page_unmap(pdu->p_sglist,pdu->p_sgcnt_used);
	}
	os_unlock_os_data(conn->os_data);

	if (pdu->p_padlen) {
		int offset = 4 - pdu->p_padlen;
		crc = calculate_crc32c(pdu->p_tail + offset, pdu->p_padlen, crc);
	}
	*pdu->p_ddigest = ~crc;
	return 0;
}

/* check the validity of a PDU's header digest */
int iscsi_header_digest_check(iscsi_pdu * pdu)
{
	iscsi_connection *conn = pdu->p_conn;
	unsigned int crc;

	if (!conn->c_hdigest_len)
		return 0;

	crc = calculate_crc32c(pdu->p_bhs, 48 + pdu->p_ahslen, CRC32C_PRELOAD);
	if ((~crc) != *(pdu->p_hdigest)) {
		iscsi_session *sess = conn->c_sess;
		os_log_info("%s, pdu 0x%p, header digest exp 0x%x, got 0x%x.\n",
			    sess ? sess->s_peer_name : " ",
			    pdu, (~crc), *(pdu->p_hdigest));
		return 1;
	}

	return 0;
}

/* check the validity of a PDU's data digest */
int iscsi_data_digest_check(iscsi_pdu * pdu)
{
	int     i;
	unsigned int crc = CRC32C_PRELOAD;
	iscsi_connection *conn = pdu->p_conn;

	if (!conn->c_ddigest_len || !pdu->p_datalen ||
	    (pdu->p_flag & ISCSI_PDU_FLAG_DATA_SKIP))
		return 0;

	for (i = 0; i < pdu->p_sgcnt_used; i++)
		crc = calculate_crc32c(pdu->p_sglist[i].sg_addr,
				       pdu->p_sglist[i].sg_length, crc);

	if (pdu->p_padlen) {
		int offset = 4 - pdu->p_padlen;
		crc = calculate_crc32c(pdu->p_tail + offset, pdu->p_padlen, crc);
	}

	if ((~crc) != *(pdu->p_ddigest)) {
		iscsi_session *sess = conn->c_sess;
		os_log_info("%s, pdu 0x%p, data digest exp 0x%x, got 0x%x.\n",
			    sess ? sess->s_peer_name : " ",
			    pdu, (~crc), *(pdu->p_ddigest));
		return 1;
	}

	return 0;
}

/*
 *
 */
int iscsi_pduq_check_pdu(char *caption, chiscsi_queue *pduq)
{
	iscsi_pdu *pdu;
	int bad = 0; 

	for (pdu = pduq->q_head; pdu; pdu = pdu->p_next) {
		if (pdu->p_datalen != pdu->p_sglist[0].sg_length) {
			os_log_error("%s, 0x%p, %u, addr 0x%p, len %u.\n", 
				     caption, pdu, pdu->p_datalen, 
				     pdu->p_sglist[0].sg_addr, 
				     pdu->p_sglist[0].sg_length);
			bad = 1;
			break;
		}
	}

	if (bad) {
		int cnt = 0;
		for (pdu = pduq->q_head; pdu; pdu = pdu->p_next, cnt++) {
			os_log_error("%s, pdu %d, 0x%p:\n", caption, cnt, pdu);
			iscsi_pdu_display(pdu, NULL, 0, 1);
		}
		return -ISCSI_EIO;
	}

	return 0;
}
