/*
 * login.c -- iscsi target loing phase processing
 */
#include <common/os_builtin.h>
#include <iscsi_auth_api.h>

#include <iscsi_target_api.h>
#include "iscsi_target_private.h"
#include <common/iscsi_target_notif.h>

extern iscsi_node *it_target_dflt;	/* default target */
extern chiscsi_queue *it_portal_q;

static char ulp_key[] = "X-Target.CH.ulp=1";

static inline void login_callback_incr(iscsi_connection *conn)
{
	conn_login *login = &conn->login;
	os_lock_irq_os_data(conn->os_data);
	login->wait++;
	os_unlock_irq_os_data(conn->os_data);
}

static inline void set_login_status(iscsi_connection *conn,
				    unsigned char status_class,
				    unsigned char status_detail)
{
	char* ini_err_desc[] = ISCSI_LOGIN_STATUS_CLASS_INITIATOR_ERROR_DESC;
	char* tar_err_desc[] = ISCSI_LOGIN_STATUS_CLASS_TARGET_ERROR_DESC;
	char *ini_name, *tar_name;
	conn_login *login = &conn->login;

	os_lock_irq_os_data(conn->os_data);
	login->status_class = status_class;
	login->status_detail = status_detail;
	os_unlock_irq_os_data(conn->os_data);

	ini_name=conn->c_sess? (conn->c_sess->s_node? conn->c_sess->s_node->n_name: NULL): NULL;
	tar_name=conn->c_sess? conn->c_sess->s_peer_name: NULL;
	switch(status_class)
	{
		case ISCSI_LOGIN_STATUS_CLASS_INITIATOR_ERROR:
			os_chiscsi_notify_event( (status_detail==ISCSI_LOGIN_STATUS_DETAIL_AUTH_FAILURE)? 
					CHISCSI_AUTH_FAILURE: CHISCSI_LOGIN_FAILURE,
                        	"Initiator Error: %s %s%s %s%s", 
				ini_err_desc[status_detail],
				ini_name?"Initiator: ":"",
				ini_name?ini_name:"",
				tar_name?"Target: ":"",
				tar_name?tar_name:"");
			break;
			
		case ISCSI_LOGIN_STATUS_CLASS_TARGET_ERROR:
			os_chiscsi_notify_event(CHISCSI_LOGIN_FAILURE,
                        	"Target Error: %s %s %s",
				tar_err_desc[status_detail],
				ini_name? "Initiator: ": "",
				ini_name? ini_name: "",
				tar_name? "Target: ": "",
				tar_name? tar_name: "");
	}
}

#define set_target_error(conn,detail) \
	set_login_status(conn, \
			ISCSI_LOGIN_STATUS_CLASS_TARGET_ERROR, \
			detail ? detail : ISCSI_LOGIN_STATUS_DETAIL_TARG_ERROR)
#define set_initiator_error(conn,detail) \
	set_login_status(conn, \
			 ISCSI_LOGIN_STATUS_CLASS_INITIATOR_ERROR, \
			detail ? detail : ISCSI_LOGIN_STATUS_DETAIL_INIT_ERROR)

static inline void release_response_data(iscsi_connection *conn)
{
	if (conn->c_datap) {
		os_free(conn->c_datap);
		conn->c_datap = NULL;
	}
	conn->c_datap_max = conn->c_datap_cnt = 0;
}

static inline void it_login_stage_transit(iscsi_connection *conn)
{
	conn_login *login = &conn->login;

	/* manage login stage transitions */
	if ((login->csg == ISCSI_LOGIN_STAGE_SECURITY) &&
	    !iscsi_connection_auth_done(conn, conn->c_sess->s_node->n_auth)) 
		login->transit_resp = 0;
	else {
		login->transit_resp = 1;
		if (login->nsg == ISCSI_LOGIN_STAGE_OPERATIONAL)
			conn->c_state = CONN_STATE_LOGINOPERATIONAL;
		else if (login->nsg == ISCSI_LOGIN_STAGE_FULL_FEATURE_PHASE)
			conn->c_state = CONN_STATE_FFP;
	}
}

static int it_ffp_prepare(iscsi_connection *conn, int offload)
{
	int     rv;
	iscsi_session *sess = conn->c_sess;

	if (!conn->c_keys) {
		conn->c_keys = iscsi_connection_key_alloc();
		if (!conn->c_keys)
			return -ISCSI_ENOMEM;
	}

	rv = iscsi_connection_key_fill_default(conn->c_keys);
	if (rv < 0)
		return rv;

	rv = iscsi_connection_keys_read_setting(conn);
	if (rv < 0)
		return rv;

	/* If Target Redirection is enabled, we need not go into ULP mode
	 * as there is a race condition which prevents the redirection pdu from
	 * being sent */
	if (offload) {
		/* prepare for rx path */
		iscsi_connection_adjust_offload_mode(conn);
		if (rv < 0)
			return rv;
	}

	if (iscsi_conn_flag_test(conn, CONN_FLAG_LEADING_CONN_BIT)) {
		if (!sess->s_keys) {
			sess->s_keys = iscsi_session_key_alloc();
			if (!sess->s_keys)
				return -ISCSI_ENOMEM;
		}
		rv = iscsi_session_key_fill_default(sess->s_keys);
		if (rv < 0)
			return rv;

		rv = iscsi_get_session_key_settings(&sess->setting,
						sess->s_keys);
		if (rv < 0)
			return rv;

		iscsi_session_key_free(sess->s_keys);
	}

	iscsi_connection_key_free(conn->c_keys);

	if (sess->s_type != ISCSI_SESSION_TYPE_NORMAL) {
		sess->s_scmdqlen = 1;
	} 

	/* set up cmdsn window: maxcmdsn - expcmdsn + 1 */
	sess->s_maxcmdsn = uint_serial_add(sess->s_expcmdsn, sess->s_scmdqlen);
	uint_serial_dec(sess->s_maxcmdsn);

	/* login done, decr target's login ip cnt */
	if (iscsi_conn_flag_testnclear(conn, CONN_FLAG_LOGINIP_BIT)) {
		iscsi_node *node = sess->s_node;
		os_data_counter_dec(node->os_data);
	}

	return 0;
}

static inline void it_login_reponse_bhs_set(iscsi_pdu *pdu, unsigned int dlen,
					    int cbit)
{
	iscsi_connection *conn = (iscsi_connection *)pdu->p_conn;
	conn_login *login = &conn->login;
	iscsi_session *sess = conn->c_sess;

	pdu->p_opcode = ISCSI_OPCODE_LOGIN_RESPONSE;

	SET_PDU_OPCODE(pdu, ISCSI_OPCODE_LOGIN_RESPONSE);
	if (login->status_detail == ISCSI_LOGIN_STATUS_DETAIL_UNSUP_VERSION)
		SET_PDU_LOGIN_VERSION_MAX(pdu, login->version);
	else
		SET_PDU_LOGIN_VERSION_MAX(pdu, GET_PDU_LOGIN_VERSION_MAX(pdu));
	SET_PDU_LOGIN_VERSION_ACTIVE(pdu, login->version);

	if (sess) {
		SET_PDU_LOGIN_ISID(pdu, sess->s_isid);
		/* Bug Fix iscsi/6179 */
		SET_PDU_EXPCMDSN(pdu, sess->s_expcmdsn);
	}
	SET_PDU_ITT(pdu, login->itt);

	if (cbit)
		SET_PDU_C(pdu);

	/* report status */
	uint_serial_inc(conn->c_statsn);
	SET_PDU_STATSN(pdu, conn->c_statsn);
	pdu->p_sn = conn->c_statsn;
	SET_PDU_LOGIN_STATUS_CLASS(pdu, login->status_class);
	SET_PDU_LOGIN_STATUS_DETAIL(pdu, login->status_detail);

	if (conn->login.status_class && 
	    (conn->login.status_class != ISCSI_LOGIN_STATUS_CLASS_REDIRECTION)) {
		SET_PDU_LOGIN_CSG(pdu, 0);
		SET_PDU_LOGIN_NSG(pdu, 0);
		return;
	} 

	SET_PDU_LOGIN_CSG(pdu, login->csg);
	SET_PDU_LOGIN_NSG(pdu, login->nsg);

	SET_PDU_DATA_SEGMENT_LENGTH(pdu, dlen);

	if (login->transit_resp) {
		login->transit_resp = 0;

		SET_PDU_LOGIN_T(pdu);

		if (conn->c_state == CONN_STATE_FFP) {
			/* set TSIH on final response */
			SET_PDU_LOGIN_TSIH(pdu, sess->s_tsih);
			SET_PDU_EXPCMDSN(pdu, sess->s_expcmdsn);
			SET_PDU_MAXCMDSN(pdu, sess->s_maxcmdsn);
		}
	}
}

static int it_login_respond_no_data(iscsi_connection *conn, iscsi_pdu *pdu)
{
	if (!pdu)
		pdu = iscsi_pdu_get(conn, 0, 0, 0);
	if (!pdu)
		return -ISCSI_ENOMEM;

	release_response_data(conn);
	it_login_reponse_bhs_set(pdu, 0, 0);
	return (iscsi_connection_send_pdu(conn, pdu));
}

int target_login_respond(iscsi_connection *conn)
{
	conn_login *login = &conn->login;
	iscsi_session *sess = conn->c_sess;
        iscsi_node *node = sess->s_node;
	iscsi_pdu *pdu;
	unsigned int len = 0;
	unsigned int adjust = 0;
	unsigned int extra = 0;
	unsigned int zero_pad = 0;
	int ffp_nxt = 0;
	int rv;
	
	if (login->status_class &&
		login->status_class != ISCSI_LOGIN_STATUS_CLASS_REDIRECTION)
		return (it_login_respond_no_data(conn, NULL));

	len = conn->c_datap_max - conn->c_datap_cnt;
	if (len > conn->c_pdudatalen_tmax)
		len = conn->c_pdudatalen_tmax;

	if (login->transit_req && 
	   (len == conn->c_datap_max - conn->c_datap_cnt)) {
		
		it_login_stage_transit(conn);
		if (login->transit_resp && conn->c_state == CONN_STATE_FFP) {
			if (os_strstr(sess->s_peer_name,
					iscsi_chelsio_ini_idstr))
				iscsi_sess_flag_set(sess,
					SESS_FLAG_CHELSIO_PEER);

			if((login->status_class ==
					ISCSI_LOGIN_STATUS_CLASS_REDIRECTION)
				|| (conn->c_sess->s_type == 
					ISCSI_SESSION_TYPE_DISCOVERY))
				rv = it_ffp_prepare(conn, 0);
			else
				rv = it_ffp_prepare(conn, 1);
			if (rv < 0) {
				set_login_status(conn, 
				ISCSI_LOGIN_STATUS_CLASS_TARGET_ERROR,
				ISCSI_LOGIN_STATUS_DETAIL_NO_RESOURCES);
			} else
				ffp_nxt = 1;
		}
	}

	
	if (login->status_class == ISCSI_LOGIN_STATUS_CLASS_REDIRECTION) {
		chiscsi_tcp_endpoints eps;

		memcpy(&eps, &conn->c_isock->s_tcp,
			sizeof(chiscsi_tcp_endpoints));

		conn->c_datap = os_alloc(conn->c_pdudatalen_tmax, 1, 1);
		if (!conn->c_datap) {
			set_target_error(conn, 0);
			return -ISCSI_ENOMEM;
		}
		len = sprintf(conn->c_datap, "TargetAddress=");

		if (node->tclass->fp_select_redirection_portal) {
			rv = node->tclass->fp_select_redirection_portal(
				node->n_name, sess->s_peer_name, &eps);
			if (rv < 0)
				os_log_info("%s, redirect %s, "
					"fp_select_redirection_portal %d.\n",
					node->n_name, sess->s_peer_name, rv);
			else {
				len += tcp_endpoint_sprintf(&eps.taddr,
						conn->c_datap + len);
				conn->c_datap[len++] = 0;
				conn->c_datap_max = len;
			}
		} else {
			os_log_info("%s, redirect %s, "
				"NO fp_select_redirection_portal.\n",
				node->n_name, sess->s_peer_name);
			rv = -ISCSI_EINVAL;
		}

		if (rv < 0) {
			set_target_error(conn, ISCSI_LOGIN_STATUS_DETAIL_NO_RESOURCES);
			len = 0;
		}

	} else if (login->status_class) {
		len = 0;
	}

	/*
	 * last login rsp pdu, offloaded in ULP mode
	 * send ulp key out to identify as chelsio target
         * also pad the key so that pdu ends at the 8 byte boundary
	 */
	if (len && (len & 0x7U) && ffp_nxt &&
	    (conn->c_offload_mode & ISCSI_OFFLOAD_MODE_CRC) &&
	    (conn->c_datap_cnt + len) >= conn->c_datap_max) {
		if (iscsi_sess_flag_test(sess, SESS_FLAG_CHELSIO_PEER)) {
			/*
			 * pad the login pdus with zero,
			 * open-iscsi initiator does not complain
			 */
			zero_pad = 8 - (len & 7U);
			os_log_info("%s: last login pdu len %u, pad %u %u.\n",
				sess->s_peer_name, len, zero_pad);
		} else if (iscsi_perf_params & ISCSI_PERF_VENDOR_KEY) {
			extra = os_strlen(ulp_key) + 1;
			adjust = 8 - ((len + extra + 1) & 7U);
		}
	}

	/* allocate and setup pdu */
	pdu = iscsi_pdu_get(conn, 0, 0, len + extra + adjust + zero_pad);
	if (!pdu)
		return -ISCSI_ENOMEM;

	/* copy text data */
	if (len) {
		rv = chiscsi_sglist_copy_bufdata(
				conn->c_datap + conn->c_datap_cnt, len,
				pdu->p_sglist, pdu->p_sgcnt_used);
		if (rv < 0) {
			set_target_error(conn, 
					ISCSI_LOGIN_STATUS_DETAIL_NO_RESOURCES);
		} else {
			conn->c_datap_cnt += len;
			if (conn->c_datap_cnt >= conn->c_datap_max) {
				release_response_data(conn);

			}
		}

		if (extra) {
			char *buf = pdu->p_sglist[0].sg_addr + len;

			memcpy(buf, ulp_key, extra);
			buf += extra - 1;

			if (adjust)
				memset(buf, '1', adjust);

			buf += adjust + 1;
			*buf = 0;
		} else if (zero_pad) {
			memset(pdu->p_sglist[0].sg_addr + len, 0, zero_pad);
		}
	}

	if (login->status_class) {
		if (login->status_class == ISCSI_LOGIN_STATUS_CLASS_REDIRECTION)
			set_login_status(conn, 
				ISCSI_LOGIN_STATUS_CLASS_REDIRECTION,
				ISCSI_LOGIN_STATUS_DETAIL_REDIR_TEMP);
		else
			return (it_login_respond_no_data(conn, pdu));
	}
	
	it_login_reponse_bhs_set(pdu, len + adjust + extra + zero_pad,
				(len && conn->c_datap));

	rv = iscsi_connection_send_pdu(conn, pdu);
	return rv;
}

static int it_build_response_data(iscsi_connection *conn)
{
	conn_login *login = &conn->login;
	iscsi_session *sess = conn->c_sess;
	chiscsi_queue *pairq = conn->c_queue[CONN_PAIRQ];
	int auth_datalen, len;
	char *cp;
	int rv;
	
	if (conn->c_datap)
		return 0;
	/* calculate data size first */
	rv = iscsi_connection_auth_size_resp(conn);
	if (rv < 0) {
		set_target_error(conn, 0);
		return rv;
	}
	auth_datalen = len = rv;

	if (pairq->q_head) {
		rv = iscsi_string_pairq_size_response(pairq,
					      ISCSI_KV_FLAG_NOTUNDERSTOOD);
		if (rv < 0) {
			set_target_error(conn, 0);
			return rv;
		}
		len += rv;
	}

	rv = iscsi_size_connection_keys(conn->c_keys);
	if (rv < 0) {
		set_target_error(conn, 0);
		return rv;
	}
	len += rv;

	/* only get the session keys if leading conn. */
	if (login->csg == ISCSI_LOGIN_STAGE_OPERATIONAL &&
	    !(iscsi_sess_flag_test(sess, SESS_FLAG_FFP_BIT))) {
		rv = iscsi_size_session_keys(sess->s_keys);
		if (rv < 0) {
			set_target_error(conn, 0);
			return rv;
		}
		len += rv;
	}

	if (!len)
		return 0;

	cp = os_alloc(len, 1, 1);
	if (!cp) {
		set_target_error(conn, 0);
		return rv;
	}
	/* os_alloc does memset() */
	conn->c_datap = cp;
	conn->c_datap_max = len;
	conn->c_datap_cnt = 0;

	*cp = 0;
	rv = iscsi_string_pairq_write_text(pairq, cp,
					   ISCSI_KV_FLAG_NOTUNDERSTOOD);
	if (rv < 0) {
		set_target_error(conn, 0);
		return rv;
	}
	len -= rv;
	conn->c_datap_cnt += rv;

	if (len && auth_datalen) {
		cp = conn->c_datap + conn->c_datap_cnt;
		*cp = 0;
		rv = iscsi_connection_auth_write_resp(conn, cp, len);
		if (rv < 0) {
			set_target_error(conn, 0);
			return rv;
		}
		len -= rv;
		conn->c_datap_cnt += rv;
	}

	if (len) {
		cp = conn->c_datap + conn->c_datap_cnt;
		*cp = 0;
		rv = iscsi_connection_keys_send(conn->c_keys, cp, len);
		if (rv < 0) {
			set_target_error(conn, 0);
			return rv;
		}
		len -= rv;
		conn->c_datap_cnt += rv;
	}

	if (len && (login->csg == ISCSI_LOGIN_STAGE_OPERATIONAL) &&
	    !(iscsi_sess_flag_test(sess, SESS_FLAG_FFP_BIT))) {
		cp = conn->c_datap + conn->c_datap_cnt;
		*cp = 0;
		rv = iscsi_session_keys_send(sess->s_keys, cp, len);
		if (rv < 0) {
			set_target_error(conn, 0);
			return rv;
		}
		len -= rv;
		conn->c_datap_cnt += rv;
	}

	conn->c_datap_max = conn->c_datap_cnt;
	conn->c_datap_cnt = 0;

	return 0;
}

static iscsi_session *it_isid_existing(iscsi_node * node,
				       unsigned char * isid, char *ii_name)
{
	iscsi_session *sess;
	chiscsi_queue *q = node->n_queue[NODE_SESSQ];

#ifdef __LABTEST__
	/* temp workaround for iitt testing */
	return NULL;
#endif

	os_lock(q->q_lock);
	for (sess = q->q_head; sess; sess = sess->s_next) {
		/* skip the session in the process of being closed */
		if (iscsi_sess_flag_test(sess, SESS_FLAG_CLOSE_BIT))
			continue;
		if (!os_strcmp(ii_name, sess->s_peer_name) &&
		    !(memcmp(sess->s_isid, isid, 6)))
			break;
	}
	os_unlock(q->q_lock);
	return sess;
}

static iscsi_session *it_create_new_session(unsigned char *isid, char *iiname,
					    iscsi_node * node,
					    unsigned int pgtag,
					    unsigned short tsih)
{
	chiscsi_queue *q = node->n_queue[NODE_SESSQ];
	iscsi_session *sess;

	sess = iscsi_session_alloc();
	if (!sess)
		return NULL;

	os_strcpy(sess->s_peer_name, iiname);

	if (node == it_target_dflt) {
		sess->s_type = ISCSI_SESSION_TYPE_DISCOVERY;
	} else {
		sess->s_type = ISCSI_SESSION_TYPE_NORMAL;
		sess->s_portalgrouptag = pgtag;
	}

	sess->s_node = (void *) node;
	memcpy(sess->s_isid, isid, 6);

	sess->s_scmdqlen = node->config_keys.sess_max_cmds;

	if (!tsih) {
		os_lock_os_data(node->os_data);
		if (!node->t_tsih_next)
			node->t_tsih_next = 1;
		node->t_tsih_next++;
		tsih = node->t_tsih_next;
		os_unlock_os_data(node->os_data);
	}
	sess->s_tsih = tsih;

	/* add session to the target */
	session_enqueue(lock, q, sess);

	return sess;
}

static int it_login_check_redirect(iscsi_connection *conn, iscsi_node *node)
{
	/* normal session only */
	if (conn->c_state < CONN_STATE_FFP &&
	    node != it_target_dflt && node->n_redirect_on) {
		iscsi_target_portal *p;
		int i;

		for (i = 0; i < node->portal_cnt; i++) {
			p = node->portal_list + i;

			if ((p->flag & ISCSI_PORTAL_FLAG_REDIRECT_FROM) &&
			    !memcmp(&conn->c_isock->s_tcp.taddr, &p->ep,
				sizeof(struct tcp_endpoint))) {
				conn_login *login = &conn->login;

				os_log_info("conn 0x%p target %s redirect.\n",
					node->n_name);
				login->status_class =
					ISCSI_LOGIN_STATUS_CLASS_REDIRECTION;
				login->status_detail =
					ISCSI_LOGIN_STATUS_DETAIL_REDIR_TEMP;
				return 1;
			}
		}
	}

	return 0;
}

static void it_rcv_first_login_req(iscsi_connection *conn,
				   iscsi_keyval * kv_sess,
				   iscsi_keyval * kv_conn, iscsi_pdu * pdu)
{
	conn_login *login = &conn->login;
	iscsi_session *sess = NULL;
	iscsi_node *node = NULL;
	iscsi_keyval *kvp;
	unsigned int vmin, vmax;
	unsigned int pgtag = 0, cid;
	unsigned short tsih, tsih_rsp = 0;
	unsigned char isid[6];
	int     rv;

	/* this is the 1st login request */
	login->itt = GET_PDU_ITT(pdu);
	cid = GET_PDU_CID(pdu);
	tsih = GET_PDU_LOGIN_TSIH(pdu);
	GET_PDU_LOGIN_ISID(pdu, isid);

	/* version checking */
	vmin = GET_PDU_LOGIN_VERSION_MIN(pdu);
	vmax = GET_PDU_LOGIN_VERSION_MAX(pdu);

	if ((vmin > ISCSI_PROTOCOL_VERSION_MAX) ||
	    (vmax < ISCSI_PROTOCOL_VERSION_MIN)) {
		os_log_info("login ERR! Unsupported version range %d-%d\n",
			    vmin, vmax);
		/* "reject" & send version_active = version_min */
		login->version = ISCSI_PROTOCOL_VERSION_MIN;
		set_initiator_error(conn,
				    ISCSI_LOGIN_STATUS_DETAIL_UNSUP_VERSION);
		return;
	}

	if (vmax < ISCSI_PROTOCOL_VERSION_MAX)
		login->version = vmax;
	else
		login->version = ISCSI_PROTOCOL_VERSION_MAX;

	/* RFC3720, 3.2.6.1: The Initiator MUST present both its iSCSI 
	   Initiator name and the iSCSI Target Name in the 1st login-request
	   if Normal session */
	kvp = kv_conn + ISCSI_KEY_CONN_INITIATOR_NAME;
	if (!kvp->kv_valp || kvp->kv_valp->v_next) {
		os_log_info("Initiator name missing/duplicate 0x%p.\n",
			    kvp->kv_valp);
		set_initiator_error(conn,
				    ISCSI_LOGIN_STATUS_DETAIL_MISSING_PARAM);
		return;
	}

	/* try to find the target */
	kvp = kv_sess + ISCSI_KEY_SESS_SESSION_TYPE;
	if (kvp->kv_valp &&
	    kvp->kv_valp->v_num[0] == ISCSI_SESSION_TYPE_DISCOVERY) {

		kvp = kv_conn + ISCSI_KEY_CONN_TARGET_NAME;
		if (kvp->kv_valp) {
			os_log_error("discovery: rcv'ed target name %s.\n",
				     kvp->kv_valp->v_str[0]);
			kvp->kv_flags |=
				(ISCSI_KV_FLAG_REJECT | ISCSI_KV_FLAG_SEND);
			iscsi_value_free(kvp->kv_valp, kvp->kv_name);
			kvp->kv_valp = NULL;
		}
		node = it_target_dflt;

	} else {
		kvp = kv_conn + ISCSI_KEY_CONN_TARGET_NAME;
		/* no target specified */
		if (!kvp->kv_valp) {
			os_log_info("login, NO target name specified 0x%p.\n",
				    kvp->kv_valp);
			set_initiator_error(conn,
				ISCSI_LOGIN_STATUS_DETAIL_MISSING_PARAM);
			return;
		}

		node = iscsi_node_find_by_name(kvp->kv_valp->v_str[0]);
		if (!node) {
			os_log_info("login ERR! target %s not found, ha %d.\n",
				    kvp->kv_valp->v_str[0], iscsi_ha_mode);
			if (iscsi_ha_mode) {
                		iscsi_conn_flag_set(conn, CONN_FLAG_CLOSE_BIT);
                		iscsi_conn_flag_set(conn, CONN_FLAG_RST_BIT);
			}
			set_initiator_error(conn,
				ISCSI_LOGIN_STATUS_DETAIL_TARGET_NOT_FOUND);
			return;
		}
	}

	/* incr target's login cnt */
	os_data_counter_inc(node->os_data);
	iscsi_conn_flag_set(conn, CONN_FLAG_LOGINIP_BIT);

	if (iscsi_node_flag_test(node, NODE_FLAG_UPDATING_BIT)) {
		os_log_info("login ERR! target %s busy!\n", node->n_name);
		set_target_error(conn,
				ISCSI_LOGIN_STATUS_DETAIL_NO_RESOURCES);
		goto err_out;
	}

	if (node != it_target_dflt) {
                /* check for initiator authorization */
                if (iscsi_node_acl_enable(node) && 
		    !(iscsi_auth_order == ISCSI_AUTH_ORDER_CHAP_FIRST)) {
                        kvp = kv_conn + ISCSI_KEY_CONN_INITIATOR_NAME;
			if (!iscsi_acl_target_accessible(node,
					kvp->kv_valp->v_str[0],
					&conn->c_isock->s_tcp)) {
                                os_log_error("%s authorization failed.\n",
                                             kvp->kv_valp->v_str[0]);
                                os_chiscsi_notify_event(CHISCSI_ACL_DENY,
                                        "Initiator:%s, Target:%s",
					kvp->kv_valp->v_str[0], node->n_name);
				set_login_status(conn,
					ISCSI_LOGIN_STATUS_CLASS_INITIATOR_ERROR,
					ISCSI_LOGIN_STATUS_DETAIL_NO_PERMS);
                                goto err_out;
                        }
                        iscsi_conn_flag_set(conn, CONN_FLAG_AUTH_ACL_BIT);
		} 

		/* found the portal group tag */
		rv = iscsi_target_portal_find(node, conn->c_portal, &pgtag,
					       &conn->c_timeout);
		if (rv < 0) {
			char tbuf[80];

			tcp_endpoint_sprintf(&conn->c_portal->p_ep, tbuf);
			os_log_error("portal %s not in %s.\n",
					tbuf, node->n_name);
			set_initiator_error(conn, 
					ISCSI_LOGIN_STATUS_DETAIL_INIT_ERROR);
			goto err_out;
		}
	}

	/* save my MaxRecvSegmentLength */
	kvp = node->n_keys[NODE_KEYS_CONNECTION] +
		ISCSI_KEY_CONN_MAX_RECV_DATA_SEGMENT_LENGTH;
	conn->c_pdudatalen_rmax = kvp->kv_valp->v_num[0];
	iscsi_conn_adjust_pdudatalen_rmax(conn);

	kvp = kv_conn + ISCSI_KEY_CONN_INITIATOR_NAME;
	if (it_login_check_redirect(conn, node))
		goto create_session;

	/* ISID existing */
	sess = it_isid_existing(node, isid, kvp->kv_valp->v_str[0]);
	if (sess && tsih && sess->s_tsih != tsih)
		sess = NULL;

	if (!sess && tsih) {
		/* TSIH non-zero new, fail the login */
		os_log_error("ISID exists, TSIH 0x%x, NO session found.", tsih);
		set_initiator_error(conn,
				    ISCSI_LOGIN_STATUS_DETAIL_SESS_NOT_FOUND);
		goto err_out;
	}

	/* session's TSIH matches */
	if (sess && tsih) {
		iscsi_connection *tmp_conn;
		chiscsi_queue *q = sess->s_queue[SESS_CONNQ];
		iscsi_conn_qsearch_by_cid(lock, q, tmp_conn, cid);
		/* existing CID, connection re-instatement */
		if (tmp_conn) {
			os_log_error("connection reinstatement NOT supported,"
				    " cid=0x%x!\n", cid);
			set_initiator_error(conn,
				ISCSI_LOGIN_STATUS_DETAIL_SESS_NOT_FOUND);
			goto err_out;
		} else {
			unsigned int maxconn;
			/* new CID, add connection to session */
			/* checking: same initiator, portal group */
			if (sess->s_portalgrouptag != pgtag) {
				os_log_error("add new conn. exp pgtag %u, "
					     "got %u.\n", pgtag, 
					     sess->s_portalgrouptag);
				set_initiator_error(conn, 0);
				goto err_out;
			}
			maxconn = sess->setting.max_conns;
			if (sess->s_queue[SESS_CONNQ]->q_cnt >= maxconn) {
				os_log_error("add new conn.exceed max %u.\n",
					     maxconn);
				set_initiator_error(conn,
				ISCSI_LOGIN_STATUS_DETAIL_TOO_MANY_CONN);
				goto err_out;
			}
			conn->c_cid = cid;
			conn->c_sess = sess;
			rv = iscsi_session_add_connection(sess, conn);
			if (rv < 0) {
				set_target_error(conn, 0);
				goto err_out;
			}
		}
	} 

	if (sess && !tsih) {
		/* ISID existing, TSIH zero, session reinstatement */
		tsih_rsp = sess->s_tsih;
		/* close session */
		os_lock_os_data(sess->os_data);
		sess->s_tsih = 0;
		os_unlock_os_data(sess->os_data);

		if (sess->s_thinfo.thp) {
			/* session is handled by a worker thread */
			iscsi_sess_flag_set(sess, SESS_FLAG_CLOSE_BIT);
			iscsi_schedule_session(sess);
		} else {
			iscsi_target_session_close(sess);
		} 
		sess = NULL;
	}

	if (!sess && tsih) {
		/* ISID new, TSIH non-zero, fail the login */
		os_log_error("ISID new, TSIH 0x%x, fail login.\n", tsih);
		set_login_status(conn,
			ISCSI_LOGIN_STATUS_CLASS_INITIATOR_ERROR,
			ISCSI_LOGIN_STATUS_DETAIL_SESS_NOT_FOUND);
		goto err_out;
	}

create_session:
	if (!sess) {
		sess = it_create_new_session(isid, kvp->kv_valp->v_str[0],
					     node, pgtag, tsih_rsp);
		if (!sess) {
			conn->login.status_class = 
				ISCSI_LOGIN_STATUS_CLASS_TARGET_ERROR;
			goto err_out;
		}
		sess->s_expcmdsn = GET_PDU_CMDSN(pdu);

		/* the session's s_thread will be set in distribute_connection,
		   once the login phase is complete */
		iscsi_session_add_connection(sess, conn);

		/* link connection and session, we will add the connection to
		   session once in FFP */
		conn->c_sess = sess;
		conn->c_cid = cid;
		iscsi_conn_flag_set(conn, CONN_FLAG_LEADING_CONN_BIT);
	}

	return;

err_out:
	os_data_counter_dec(node->os_data);
	iscsi_conn_flag_clear(conn, CONN_FLAG_LOGINIP_BIT);
}

static int it_login_process_session_keys(iscsi_connection * conn,
					 iscsi_keyval ** kvlistpp)
{
	iscsi_keyval *kv_sess = *kvlistpp;
	iscsi_session *sess = conn->c_sess;
	iscsi_node *node = sess->s_node;
	iscsi_keyval *kvp, *kvp2;
	int     i, rv;

	/* if not the leading connection, check for any LO keys */
	if (!iscsi_conn_flag_test(conn, CONN_FLAG_LEADING_CONN_BIT)) {
		int     i, lo = 0;
		for (i = 0; i < ISCSI_KEY_SESS_COUNT && !lo; i++) {
			if (kv_sess[i].kv_rcvcnt &&
			    i != ISCSI_KEY_SESS_SESSION_TYPE) {
				os_log_error("%s in non-leading connection.\n",
					     kv_sess[i].kv_name);
				goto initiator_error;
			}
		}
		return 0;
	}

	/* compute keys */
	rv = iscsi_kvlist_compute_value(ISCSI_KEY_SESS_COUNT,
					node->n_keys[NODE_KEYS_SESSION],
					kv_sess);
	if (rv < 0) 
		goto initiator_error;

	if (sess->s_keys) {
		rv = iscsi_kvlist_merge_value(0, ISCSI_KEY_SESS_COUNT,
					      kv_sess, sess->s_keys);
		if (rv < 0)
			goto initiator_error;
	} else {
		sess->s_keys = kv_sess;
		*kvlistpp = NULL;
	}

	if (sess->s_type == ISCSI_SESSION_TYPE_DISCOVERY) {
		rv = iscsi_session_key_discovery_check(sess->s_keys);
		if (rv < 0)
			goto initiator_error;
	} else {		/* normal session */
		/* make sure first burst <= max burst */
		kvp = sess->s_keys + ISCSI_KEY_SESS_FIRST_BURST_LENGTH;
		kvp2 = sess->s_keys + ISCSI_KEY_SESS_MAX_BURST_LENGTH;
		if ((kvp->kv_valp && !(kvp->kv_flags & ISCSI_KV_FLAG_RESPONSE))
		    || (kvp2->kv_valp
			&& !(kvp2->kv_flags & ISCSI_KV_FLAG_RESPONSE))) {
			int     new_max = 0, new_first = 0;
			if (!kvp->kv_valp) {
				rv = iscsi_kvp_fill_default(kvp);
				if (rv < 0)
					goto target_error;
				new_first = 1;
			}
			if (!kvp2->kv_valp) {
				rv = iscsi_kvp_fill_default(kvp2);
				if (rv < 0)
					goto target_error;
				new_max = 1;
			}
			if (kvp->kv_valp->v_num[0] > kvp2->kv_valp->v_num[0]) {
				kvp->kv_valp->v_num[0] =
					kvp2->kv_valp->v_num[0];
				kvp->kv_flags |= ISCSI_KV_FLAG_COMPUTED;
				os_log_error("%s > %s, reset %s to %u.\n",
					     kvp->kv_name, kvp2->kv_name,
					     kvp->kv_name,
					     kvp->kv_valp->v_num[0]);
			}
			if (new_first)
				kvp->kv_flags |= ISCSI_KV_FLAG_DROP_AFTER_SEND;
			if (new_max)
				kvp2->kv_flags |= ISCSI_KV_FLAG_DROP_AFTER_SEND;
		}
	}

	/* setup to send declarative/negotiated keys back automatically */
	for (i = 0, kvp = sess->s_keys; i < ISCSI_KEY_SESS_COUNT; i++, kvp++) {
		if (!(kvp->kv_flags & ISCSI_KV_FLAG_SENT) &&
		    ((kvp->kv_flags & ISCSI_KV_FLAG_RESPONSE) ||
		     ((kvp->kv_def->property & ISCSI_KEY_DECLARATIVE) &&
		      (kvp->kv_def->property & (ISCSI_KEY_SENDER_TARGET |
						ISCSI_KEY_SENDER_TARGET_LOGIN))
		      && (kvp->kv_valp) && kvp->kv_rcvcnt == 0)
		     || (kvp->kv_flags & ISCSI_KV_FLAG_COMPUTED))) {
			kvp->kv_flags |= ISCSI_KV_FLAG_SEND;
		}
	}

	return 0;

initiator_error:
	conn->login.status_class = ISCSI_LOGIN_STATUS_CLASS_INITIATOR_ERROR;
	return -ISCSI_EINVAL;
target_error:
	set_login_status(conn,
			 ISCSI_LOGIN_STATUS_CLASS_TARGET_ERROR,
			 ISCSI_LOGIN_STATUS_DETAIL_NO_RESOURCES);
	return -ISCSI_EINVAL;
}

static int it_login_process_connection_keys(iscsi_connection * conn,
					    iscsi_keyval ** kvlistpp)
{
	iscsi_keyval *kv_conn = *kvlistpp;
	iscsi_session *sess = conn->c_sess;
	iscsi_node *node = sess->s_node;
	iscsi_keyval *kvp;
	int     i, rv;

	rv = iscsi_kvlist_compute_value(ISCSI_KEY_CONN_COUNT,
					node->n_keys[NODE_KEYS_CONNECTION],
					kv_conn);
	if (rv < 0) 
		goto initiator_error;

	/* if peer sends MaxRecvDataSegmentLength, save it */
	kvp = kv_conn + ISCSI_KEY_CONN_MAX_RECV_DATA_SEGMENT_LENGTH;
	if (kvp->kv_valp && !(kvp->kv_flags & ISCSI_KV_FLAG_RESPONSE)) {
		conn->c_pdudatalen_tmax = kvp->kv_valp->v_num[0];
		iscsi_conn_adjust_pdudatalen_tmax(conn);
	}

	if (conn->c_keys) {
		rv = iscsi_kvlist_merge_value(0, ISCSI_KEY_CONN_COUNT,
					      kv_conn, conn->c_keys);
		if (rv < 0)
			goto initiator_error;
	} else {
		conn->c_keys = kv_conn;
		*kvlistpp = NULL;
	}

	/* TargetPortalGroupTag: send back to the 1st login request pdu that
	 * has the C-bit set to 0 when TargetName is given */
	kvp = conn->c_keys + ISCSI_KEY_CONN_TARGET_PORTAL_GROUP_TAG;
	if ((conn->c_keys + ISCSI_KEY_CONN_TARGET_NAME)->kv_valp &&
	    !(kvp->kv_valp)) {
		kvp->kv_flags |= ISCSI_KV_FLAG_SEND;
		kvp->kv_valp = iscsi_value_alloc();
		if (!kvp->kv_valp)
			goto target_error;
		kvp->kv_valp->v_num[0] = conn->c_sess->s_portalgrouptag;
	}

	/* calculate data size first */

	/* not in operational yet, no need to send any keys */
	if (conn->c_state != CONN_STATE_LOGINOPERATIONAL)
		return 0;

	if (sess->s_type == ISCSI_SESSION_TYPE_NORMAL) {
		kvp = conn->c_keys + ISCSI_KEY_CONN_TARGET_ALIAS;
		/* send the TargetAlias back */
		if (!(kvp->kv_flags & ISCSI_KV_FLAG_RESPONSE) &&
		    !kvp->kv_valp && node->n_alias) {
			rv = iscsi_kvp_decode_buffer(ISCSI_KV_DECODE_OP_ADD,
						     ISCSI_INITIATOR,
						     conn->c_state, kvp,
						     node->n_alias, NULL, 0);
			if (rv < 0) {
				return -LOGIN_TARGET_ERROR;
			}
			kvp->kv_flags |= ISCSI_KV_FLAG_SEND;
		}
	}

	/* setup to send declarative/negotiated keys back automatically */
	for (i = 0, kvp = conn->c_keys; i < ISCSI_KEY_CONN_COUNT; i++, kvp++) {
		if (!(kvp->kv_flags & ISCSI_KV_FLAG_SENT) &&
		    ((kvp->kv_flags & ISCSI_KV_FLAG_RESPONSE) ||
		     ((kvp->kv_def->property & ISCSI_KEY_DECLARATIVE) &&
		      (kvp->kv_def->property & ISCSI_KEY_SENDER_TARGET) &&
		      (kvp->kv_valp) &&
		      kvp->kv_rcvcnt == 0) ||
		     (kvp->kv_flags & ISCSI_KV_FLAG_COMPUTED))) {
			kvp->kv_flags |= ISCSI_KV_FLAG_SEND;
		}
	}

	/* send our MaxRecvDataSegmentLength back */
	kvp = conn->c_keys + ISCSI_KEY_CONN_MAX_RECV_DATA_SEGMENT_LENGTH;
	if (!kvp->kv_valp) {
		kvp->kv_valp = iscsi_value_alloc();
		if (!kvp->kv_valp)
			return -LOGIN_TARGET_ERROR;
		kvp->kv_flags |= ISCSI_KV_FLAG_DROP_AFTER_SEND;
	}
	kvp->kv_valp->v_num[0] = conn->c_pdudatalen_rmax;
	if (!(kvp->kv_flags & ISCSI_KV_FLAG_SENT))
		kvp->kv_flags |= ISCSI_KV_FLAG_SEND;

	/* do not send the target address */
	kvp = conn->c_keys + ISCSI_KEY_CONN_TARGET_ADDRESS;
	if (!(kvp->kv_flags & ISCSI_KV_FLAG_RESPONSE)) {
		kvp->kv_flags &= ~ISCSI_KV_FLAG_SEND;
	}
	/* do not send the target name */
	kvp = conn->c_keys + ISCSI_KEY_CONN_TARGET_NAME;
	if (!(kvp->kv_flags & ISCSI_KV_FLAG_RESPONSE)) {
		kvp->kv_flags &= ~ISCSI_KV_FLAG_SEND;
	}
	if (sess->s_type == ISCSI_SESSION_TYPE_DISCOVERY) {
		/* if discovery, do not send the target alias */
		kvp = conn->c_keys + ISCSI_KEY_CONN_TARGET_ALIAS;
		if (!(kvp->kv_flags & ISCSI_KV_FLAG_RESPONSE)) {
			kvp->kv_flags &= ~ISCSI_KV_FLAG_SEND;
		}
	}
	return 0;

initiator_error:
	conn->login.status_class = ISCSI_LOGIN_STATUS_CLASS_INITIATOR_ERROR;
	return -ISCSI_EINVAL;
target_error:
	set_login_status(conn,
			 ISCSI_LOGIN_STATUS_CLASS_TARGET_ERROR,
			 ISCSI_LOGIN_STATUS_DETAIL_NO_RESOURCES);
	return -ISCSI_EINVAL;
}

static void it_login_request_bhs_check(iscsi_pdu *pdu)
{
	iscsi_connection *conn = (iscsi_connection *)pdu->p_conn;
	conn_login *login = &conn->login;
	unsigned char csg, nsg, tbit;

	nsg = GET_PDU_LOGIN_NSG(pdu);
	csg = GET_PDU_LOGIN_CSG(pdu);
	tbit = GET_PDU_LOGIN_T(pdu);

	if (tbit && nsg < csg ) {
		os_log_info("nsg %u < csg %u.\n", nsg, csg);
		login->status_class = ISCSI_LOGIN_STATUS_CLASS_INITIATOR_ERROR;
	}
	else if (csg >= ISCSI_LOGIN_STAGE_FULL_FEATURE_PHASE){
		os_log_info("csg %u invalid.\n", csg);
		login->status_class = ISCSI_LOGIN_STATUS_CLASS_INITIATOR_ERROR;
	}
	else if (nsg > ISCSI_LOGIN_STAGE_FULL_FEATURE_PHASE || nsg == 2) {
		/*UNH 04_4_tbit warn fix, nsg=2 & tbit=0, set nsg=0*/
                if (tbit) {
                        os_log_info("nsg %u invalid.\n", nsg);
                        login->status_class = ISCSI_LOGIN_STATUS_CLASS_INITIATOR_ERROR;
                } else {
                        nsg = 0;
                        goto response;
                }
        }
	else if ((conn->c_state > CONN_STATE_LOGIN) && 
	     (csg < login->csg)) {
		os_log_info("csg %u < saved csg %u.\n", csg, login->csg);
		login->status_class = ISCSI_LOGIN_STATUS_CLASS_INITIATOR_ERROR;
	}
	else 
response: {
		login->transit_req = GET_PDU_LOGIN_T(pdu) ? 1 : 0;
		login->csg = csg;
		login->nsg = nsg;
	}
}

int it_rcv_login_request(iscsi_pdu *pdu)
{
	iscsi_connection *conn = (iscsi_connection *)pdu->p_conn;
	iscsi_session *sess = conn->c_sess;
	conn_login *login = &conn->login;
	chiscsi_queue *pairq = conn->c_queue[CONN_PAIRQ];
	iscsi_node *node = sess ? sess->s_node : NULL;
	iscsi_keyval *kv_sess = NULL, *kv_conn = NULL;

	unsigned char csg = login->csg;
	char *buf = NULL;
	int initial_login = 0;
	int rv = 0;
	unsigned int datalen, auth_datalen = 0;
	unsigned int buflen = 0;
	int state = conn->c_state;

	if (conn->c_state >= CONN_STATE_FFP) {
		os_log_info("conn 0x%p, state=0x%x, rejecting.\n", conn,
			    conn->c_state);
		rv = iscsi_target_xmt_reject(pdu, ISCSI_REJECT_REASON_PROTOCOL_ERROR);
		return rv;
	}
	it_login_request_bhs_check(pdu);
	if (login->status_class)
		return (it_login_respond_no_data(conn, NULL));


	datalen = GET_PDU_DATA_SEGMENT_LENGTH(pdu);
	/* if there is more login pdus to come, send empty response */
	if (GET_PDU_C(pdu)) {
		os_log_info("login request C bit NOT supported.\n", 0);
		return -ISCSI_EIO;

		if (datalen) {
			chiscsi_queue *q = conn->c_queue[CONN_PDUQ_TMP];
			pdu->p_flag |= ISCSI_PDU_FLAG_LOCKED;
			iscsi_pdu_enqueue(nolock, q, pdu);
		}
		return (it_login_respond_no_data(conn, NULL));
	}

	/* initialize the login state */
	if (conn->c_state == CONN_STATE_LOGIN) {
		initial_login = 1;
		/*set itt in first login request, fix for ITT warnings in UNH tests*/
                login->itt = GET_PDU_ITT(pdu);
		if (login->csg == ISCSI_LOGIN_STAGE_SECURITY)
			conn->c_state = CONN_STATE_LOGINSECURITY;
		else
			conn->c_state = CONN_STATE_LOGINOPERATIONAL;
	}

	kv_sess = iscsi_session_key_alloc();
	kv_conn = iscsi_connection_key_alloc();
	if (!kv_sess || !kv_conn) {
		login->status_class =
                                ISCSI_LOGIN_STATUS_CLASS_TARGET_ERROR;
		goto send_login_response;
	}

	if (conn->c_queue[CONN_PDUQ_TMP]->q_head) {
		chiscsi_queue *q = conn->c_queue[CONN_PDUQ_TMP];
		iscsi_pdu *tmppdu;
		unsigned int offset = 0;

		iscsi_pdu_enqueue(nolock, q, pdu);

		/* set up the p_offset */
		for (tmppdu = q->q_head; tmppdu;
		     offset += tmppdu->p_datalen, tmppdu = tmppdu->p_next)
			tmppdu->p_offset = offset;

		rv = iscsi_pduq_data_to_one_buffer(q, &buf);

		/* free accumulated login pdus */
		iscsi_pdu_dequeue(nolock, q, tmppdu);
		while (tmppdu) {
			tmppdu->p_flag &= ~ISCSI_PDU_FLAG_LOCKED;
			if (tmppdu != pdu)
				iscsi_pdu_done(tmppdu);
			iscsi_pdu_dequeue(nolock, q, tmppdu);
		}

		if (rv < 0) {
			set_target_error(conn, 0);
			goto send_login_response;
		}	
		buflen = rv;

	} else if (datalen) {
		/* split buffer to key-value string pairs */
		rv = iscsi_pdu_data_to_one_buffer(pdu, &buf);
		if (rv < 0) {
			set_target_error(conn, 0);
			goto send_login_response;
		}	
		buflen = rv;
	}

#if 1

	if (!buflen) {		/* empty pdu */
		/* if we are in LoginSecurity state and not ready to transit,
		   then fail the login */
		if (login->transit_req && (
		    login->csg == ISCSI_LOGIN_STAGE_SECURITY) &&
		    !(iscsi_connection_auth_done(conn, node->n_auth))) {
			os_log_warn
				("%s: state transit req. before authentication is done, reject.\n",
				 node->n_name);
			set_login_status(conn,
			 ISCSI_LOGIN_STATUS_CLASS_INITIATOR_ERROR,
			 ISCSI_LOGIN_STATUS_DETAIL_AUTH_FAILURE);
		}
		goto send_login_response;
	}
#endif

	rv = iscsi_kv_text_to_string_pairq(buflen, (char *) buf, pairq, NULL,
					   0);
	if (rv < 0) {
		os_log_info("conn 0x%p, text -> pairq, rv %d.\n", conn, rv);
		set_initiator_error(conn, 0);
		goto send_login_response;
	}

	rv = iscsi_session_key_decode(ISCSI_TARGET, conn->c_state, kv_sess,
				      pairq, NULL, 0);
	if (rv < 0) {
		os_log_info("conn 0x%p, sess decode, rv %d.\n", conn, rv);
		set_initiator_error(conn, 0);
		goto send_login_response;
	}
	rv = iscsi_connection_key_decode(ISCSI_TARGET, conn->c_state, kv_conn,
					 pairq, NULL, 0);
	if (rv < 0) {
		os_log_info("conn 0x%p, conn decode, rv %d.\n", conn, rv);
		set_initiator_error(conn, 0);
		goto send_login_response;
	}
		

	/* this is the 1st login request */
	if (initial_login) {
		it_rcv_first_login_req(conn, kv_sess, kv_conn, pdu);
		
		if (login->status_class /* &&
			login->status_class !=
					ISCSI_LOGIN_STATUS_CLASS_REDIRECTION */)
			goto send_login_response;

		sess = conn->c_sess;
		node = sess->s_node;

		if (conn->c_state == CONN_STATE_LOGINSECURITY) {
			/* authentication prepare */
			rv = iscsi_connection_auth_init(conn, node->n_auth);
			if (rv < 0) {
				os_log_info("conn 0x%p, 1st login, auth init failed %d.\n", conn, rv);
				goto send_login_response;
			}
		} else if (!iscsi_connection_auth_done(conn, node->n_auth)) {
			/* security negotiations forced? */
			os_log_warn
				("%s: security negotiation forced, reject.\n",
				 node->n_name);
			set_initiator_error(conn,
				ISCSI_LOGIN_STATUS_DETAIL_AUTH_FAILURE);
			goto send_login_response;
		}


		/* check for hook */
		if (sess->s_type == ISCSI_SESSION_TYPE_NORMAL &&
		    node->tclass->fp_first_login_check) {
			os_log_debug(ISCSI_DBG_TARGET_API,
				     "sess 0x%p, conn 0x%p, fp_first_login_check.\n",
				     sess, conn);
			login_callback_incr(conn);
			iscsi_conn_flag_set(conn, CONN_FLAG_LOCKED_BIT);
			node->tclass->fp_first_login_check((unsigned long)conn,
					sess->s_peer_name,
					node->n_name,
					&conn->c_isock->s_tcp);
		}

	} else {
		unsigned short tsih = GET_PDU_LOGIN_TSIH(pdu);
		unsigned char isid[6];

		GET_PDU_LOGIN_ISID(pdu, isid);

		sess = conn->c_sess;
		node = sess->s_node;

		/* verify ISID matches */
		if (memcmp(sess->s_isid, isid, 6)) {
			os_log_info("login ERR! sess 0x%p ISID mismatch.\n",
				    sess);
			set_initiator_error(conn, 0);
			goto send_login_response;
		}
		/* verify TSIH matches */
		if (tsih && tsih != sess->s_tsih) {
			os_log_info("login ERR! TSIH mismatch 0x%x != 0x%x.\n",
				    tsih, sess->s_tsih);
			set_initiator_error(conn, 0);
			goto send_login_response;
		}
	}

	/* set up cmdsn window: maxcmdsn - expcmdsn + 1 */
	sess->s_maxcmdsn = uint_serial_add(sess->s_expcmdsn, sess->s_scmdqlen);
	uint_serial_dec(sess->s_maxcmdsn);

	rv = it_login_process_connection_keys(conn, &kv_conn);
	if (rv < 0) {
		os_log_info("conn 0x%p, proc conn keys, rv %d.\n", conn, rv);
		goto send_login_response;
	}
	rv = it_login_process_session_keys(conn, &kv_sess);
	if (rv < 0) {
		os_log_info("conn 0x%p, proc sess keys, rv %d.\n", conn, rv);
		goto send_login_response;
	}

	if (login->status_class == ISCSI_LOGIN_STATUS_CLASS_REDIRECTION)
			goto send_login_response;

	auth_datalen = 0;
	
	if (conn->c_state == CONN_STATE_LOGINSECURITY) {	
		iscsi_connection_auth_target_process(conn, node->tclass, pairq);
		if (login->status_class) {

			if(sess)
				os_chiscsi_notify_event(CHISCSI_AUTH_FAILURE,
	                        	"Initiator=%s, Target=%s",
					sess->s_peer_name, node->n_name);
			goto send_login_response;
		}	
		goto prepare_response;
	}

	/* Do the acl check here */
	if (sess->s_type == ISCSI_SESSION_TYPE_NORMAL &&
	    (csg != login->csg) &&
	    (node->tclass->fp_login_stage_check)) {
		os_log_debug(ISCSI_DBG_TARGET_API,
			     "conn 0x%p, fp_login_stage_check.\n", conn);
		login_callback_incr(conn);
		iscsi_conn_flag_set(conn, CONN_FLAG_LOCKED_BIT);
		node->tclass->fp_login_stage_check(
					(unsigned long)conn,
					login->csg,
					sess->s_peer_name,
					node->n_name,
					&conn->c_isock->s_tcp);
	}



prepare_response:
	rv = it_build_response_data(conn);
	if (rv < 0) {
		os_log_info("conn 0x%p, build response data failed, rv %d.\n",
			     conn, rv);
		goto cleanup;
	}

send_login_response:
	if (rv < 0 || 
	    (login->status_class &&
	     login->status_class != ISCSI_LOGIN_STATUS_CLASS_REDIRECTION)) {

		if (!iscsi_conn_flag_test(conn, CONN_FLAG_RST_BIT))
			rv = it_login_respond_no_data(conn, NULL); 

                iscsi_conn_flag_set(conn, CONN_FLAG_CLOSE_BIT);
                /* revert the state */
                conn->c_state = state;
                if (!rv)
                        rv = -ISCSI_EINVAL;
		goto cleanup;
	}

	/* check for ACL */
	if (!login->status_class &&
	    conn->c_state == CONN_STATE_LOGINOPERATIONAL &&
	    sess && sess->s_type == ISCSI_SESSION_TYPE_NORMAL &&
	    node && iscsi_node_acl_enable(node) &&
	    iscsi_acl_connection_check(conn) < 0) {
		login->status_class = ISCSI_LOGIN_STATUS_CLASS_INITIATOR_ERROR;
		login->status_detail = ISCSI_LOGIN_STATUS_DETAIL_INIT_ERROR;
	}

	if (!iscsi_conn_flag_test(conn, CONN_FLAG_LOCKED_BIT)) {
		iscsi_conn_flag_clear(conn, CONN_FLAG_LOGIN_CALLBACK_BIT);
		rv = target_login_respond(conn);
	}
cleanup:
	if (kv_sess) {
		iscsi_kvlist_free(ISCSI_KEY_SESS_COUNT, kv_sess);
	}
	if (kv_conn) {
		iscsi_kvlist_free(ISCSI_KEY_CONN_COUNT, kv_conn);
	}
	if (buf)
		os_free(buf);

	return rv;
}

static int target_callback_check_valid(iscsi_connection *conn,
				       unsigned char status_class,
				       unsigned char status_detail)
{
	conn_login *login = &conn->login;

	os_lock_irq_os_data(conn->os_data);
	login->status_class = status_class;
	login->status_detail = status_detail;

	login->wait--;
	if (!login->wait)
		iscsi_conn_flag_clear(conn, CONN_FLAG_LOCKED_BIT);
	os_unlock_irq_os_data(conn->os_data);
		
	/* connection already closed, just waiting for this callback */
	if (!iscsi_conn_flag_test(conn, CONN_FLAG_LOCKED_BIT) &&
	    iscsi_conn_flag_test(conn, CONN_FLAG_CLOSING_BIT) && 
	    conn->c_state == CONN_STATE_CLOSED) {
		iscsi_connection_destroy(conn);
		return 0;
	}
	return 1;
}
					
void chiscsi_target_first_login_check_done(unsigned long hndl,
					   unsigned char status_class,
					   unsigned char status_detail,
					   unsigned int max_cmd)
{
	iscsi_connection *conn = (iscsi_connection *)hndl;
	iscsi_session *sess = conn->c_sess;

	os_log_debug(ISCSI_DBG_TARGET_API,
		     "conn 0x%p first login check done.\n", conn);

	/* if Storage driver sends us Redirection status class, */
 	/* or any other value than Initiator/target error, 	*/
	/* treat it as Success					*/
        if((status_class != ISCSI_LOGIN_STATUS_CLASS_INITIATOR_ERROR) &&
           (status_class != ISCSI_LOGIN_STATUS_CLASS_TARGET_ERROR)  &&
           (status_class != ISCSI_LOGIN_STATUS_CLASS_SUCCESS) ) {
		os_log_warn(
			    "Status class is not Initiator/Target error (%d), treat it as Success.\n",
	                status_class);
                status_class = ISCSI_LOGIN_STATUS_CLASS_SUCCESS;
                status_detail = 0;
        }

	if (sess &&
	    target_callback_check_valid(conn, status_class, status_detail)) {
		if (!max_cmd)
			max_cmd = ISCSI_SESSION_SCMDQ_DEFAULT;

		sess->s_scmdqlen = sess->s_scmdqlen ? 
				   MINIMUM(max_cmd, sess->s_scmdqlen) : 
				   max_cmd;

		iscsi_conn_flag_set(conn, CONN_FLAG_LOGIN_CALLBACK_BIT);
		iscsi_schedule_connection(conn);
	}
}

void chiscsi_target_login_stage_check_done(unsigned long hndl,
					   unsigned char status_class,
					   unsigned char status_detail)
{
	iscsi_connection *conn = (iscsi_connection *)hndl;

	os_log_debug(ISCSI_DBG_TARGET_API,
		     "conn 0x%p login stage check done.\n", conn);

	if (target_callback_check_valid(conn, status_class, status_detail)) {
		iscsi_conn_flag_set(conn, CONN_FLAG_LOGIN_CALLBACK_BIT);
		iscsi_schedule_connection(conn);
	}
}
