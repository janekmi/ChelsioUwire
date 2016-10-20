#include <crypto_md5.h>
#include <crypto_sha1.h>
#include "iscsi_chap_private.h"
#include "iscsi_chap_api.h"

/* 
 * CHAP session/connection processing
 */

void chap_session_free(void *data)
{
	chap_session *csess = (chap_session *) data;
	iscsi_value *vp;

	for (vp = csess->kvp_chap_i.kv_valp; vp; vp = vp->v_next)
		vp->v_flag = 0;
	for (vp = csess->kvp_chap_c_sent.kv_valp; vp; vp = vp->v_next)
		vp->v_flag = 0;

	iscsi_value_free(csess->kvp_chap_i.kv_valp, csess->kvp_chap_i.kv_name);
	iscsi_value_free(csess->kvp_chap_c_sent.kv_valp,
			 csess->kvp_chap_c_sent.kv_name);
	iscsi_value_free(csess->kvp_chap_c_rcv.kv_valp,
			 csess->kvp_chap_c_rcv.kv_name);
	os_free(csess);
}

STATIC int chap_session_check_duplicate_id(chap_session * csess,
					   unsigned char id)
{
	iscsi_value *vp = csess->kvp_chap_i.kv_valp;

	for (; vp; vp = vp->v_next) {
		if (vp->v_num[0] == id)
			return 1;
	}
	return 0;
}

STATIC int chap_session_check_duplicate_challenge(chap_session * csess,
						  unsigned int challenge_length,
						  unsigned char *challenge)
{
	iscsi_value *vp = csess->kvp_chap_c_sent.kv_valp;
//iscsi_display_byte_string("challenge", challenge, 0, challenge_length, NULL, 0);

	/* check for reflection */
	for (; vp; vp = vp->v_next) {
//iscsi_display_byte_string("sent challenge", vp->v_data[0], 0, vp->v_num[0], NULL, 0);
		if ((vp->v_num[0] == challenge_length) &&
		    !(memcmp(vp->v_data[0], challenge, challenge_length))) {
			os_log_warn("chap challenge reflected, len %u.\n",
				    challenge_length);
			return 1;
		}
	}

	/* check for re-use */
	for (vp = csess->kvp_chap_c_rcv.kv_valp; vp; vp = vp->v_next) {
//iscsi_display_byte_string("rcv challenge", vp->v_data[0], 0, vp->v_num[0], NULL, 0);
		if ((vp->v_num[0] == challenge_length) &&
		    !(memcmp(vp->v_data[0], challenge, challenge_length))) {
			os_log_warn("chap challenge re-used, len %u.\n",
				    challenge_length);
			return 1;
		}
	}

	return 0;
}

STATIC void chap_calc_digest_md5(unsigned char id, char *secret,
				 unsigned char *challenge, int challenge_len,
				 unsigned char *digest)
{
	crypto_md5_context mctx;

	crypto_md5_init(&mctx);
	crypto_md5_update(&mctx, &id, 1);
	crypto_md5_update(&mctx, (unsigned char *) secret, os_strlen(secret));
	crypto_md5_update(&mctx, challenge, challenge_len);
	crypto_md5_finish(&mctx, digest);
}

STATIC void chap_calc_digest_sha1(unsigned char id, char *secret,
				  unsigned char *challenge, int challenge_len,
				  unsigned char *digest)
{
	crypto_sha1_context sctx;

	crypto_sha1_init(&sctx);
	crypto_sha1_update(&sctx, &id, 1);
	crypto_sha1_update(&sctx, (unsigned char *) secret, os_strlen(secret));
	crypto_sha1_update(&sctx, challenge, challenge_len);
	crypto_sha1_finish(&sctx, digest);
}

/*
 * CHAP processing state machine
 *
 * after AuthMethod=CHAP
 *	initiator 		target
 *	CHAP_A		->
 *			<-	CHAP_A, CHAP_I, CHAP_C
 *	if one-way chap:
 *	CHAP_N, CHAP_R	->
 *			<-	-- (none)
 *	if two-way chap:
 *	CHAP_N, CHAP_R, CHAP_I, CHAP_C ->
 *			<-	CHAP_N, CHAP_R
 *
 */

#define chap_shows_rcvd_keys(kvlist) \
	os_log_info("chap keys rcvd: A %u, N %u, R %u, I %u, C %u.\n", \
		kvlist[CHAP_KEY_AUTH_ALGORITHM].kv_rcvcnt, \
		kvlist[CHAP_KEY_AUTH_NAME].kv_rcvcnt, \
		kvlist[CHAP_KEY_AUTH_RESPONSE].kv_rcvcnt, \
		kvlist[CHAP_KEY_AUTH_ID].kv_rcvcnt, \
		kvlist[CHAP_KEY_AUTH_CHALLENGE])


static int chap_target_process_connection(iscsi_auth_connection * aconn,
			    chiscsi_target_class *tclass, 
			    char *iname, char *tname, 
			    unsigned char *status_class,
			    unsigned char *status_detail)
{
	chap_connection *cconn = (chap_connection *) aconn->c_method_data;
	chap_session *csess = cconn->csess;
	chap_node *cnode = csess->node;
	chap_info *cinfo = &cconn->cinfo;
	iscsi_keyval *kvlist = aconn->c_kvlist;
	iscsi_keyval *kvp;
	iscsi_value *vp;
	chap_string_pair *cpair;
	unsigned char id;
	unsigned int chap_response_vtype = 0;
	unsigned char digest[CHAP_DIGEST_LEN_MAX];
	int     digest_len = 0;
	int     rv = 0;

	/* we are done but still get chap keys */
	if (cconn->state == CHAP_STATE_DONE) {
		os_log_error("CHAP done, but still rcv extra CHAP keys.\n", rv);
		goto initiator_error;
	}

	switch (cconn->state) {
		case CHAP_STATE_UNKNOWN:
			/* should receive CHAP_A and nothing else */
			if (!kvlist[CHAP_KEY_AUTH_ALGORITHM].kv_rcvcnt ||
			    kvlist[CHAP_KEY_AUTH_NAME].kv_rcvcnt ||
			    kvlist[CHAP_KEY_AUTH_RESPONSE].kv_rcvcnt ||
			    kvlist[CHAP_KEY_AUTH_ID].kv_rcvcnt ||
			    kvlist[CHAP_KEY_AUTH_CHALLENGE].kv_rcvcnt) {
				os_log_error
					("chap start: bad keys! A %u, N %u, R %u, I %u, C %u.\n",
					 kvlist[CHAP_KEY_AUTH_ALGORITHM].
					 kv_rcvcnt,
					 kvlist[CHAP_KEY_AUTH_NAME].kv_rcvcnt,
					 kvlist[CHAP_KEY_AUTH_RESPONSE].
					 kv_rcvcnt,
					 kvlist[CHAP_KEY_AUTH_ID].kv_rcvcnt,
					 kvlist[CHAP_KEY_AUTH_CHALLENGE].
					 kv_rcvcnt);
				goto auth_failure;
			}

			/* set the algorithm, take the 1st valid value and free the rest */
			vp = kvlist[CHAP_KEY_AUTH_ALGORITHM].kv_valp;
			cconn->algorithm = vp->v_num[0];
			if (vp->v_next) {
				iscsi_value_free(vp->v_next,
						 kvlist
						 [CHAP_KEY_AUTH_ALGORITHM].
						 kv_name);
				vp->v_next = NULL;
			}

			/* generate challenge */
			os_get_random_bytes(&cconn->id, 1);
			os_get_random_bytes(cconn->challenge,
					    cconn->challenge_length);
			cconn->state = CHAP_STATE_CHALLENGE;

			/* send CHAP_A */
			kvp = kvlist + CHAP_KEY_AUTH_ALGORITHM;
			kvp->kv_flags |= ISCSI_KV_FLAG_SEND;

			/* send CHAP_I */
			kvp = kvlist + CHAP_KEY_AUTH_ID;
			vp = iscsi_value_alloc();
			if (!vp)
				goto target_error;
			vp->v_num[0] = cconn->id;
			vp->v_num_used = 1;
			kvp->kv_flags |= ISCSI_KV_FLAG_SEND;
			kvp->kv_valp = vp;
			/* save the CHAP_I we sent */
			vp->v_flag = ISCSI_VALUE_FLAG_LOCKED;
			iscsi_value_list_append(&csess->kvp_chap_i.kv_valp, vp);

			/* send CHAP_C */
			kvp = kvlist + CHAP_KEY_AUTH_CHALLENGE;
			vp = iscsi_value_alloc();
			if (!vp)
				goto target_error;
			vp->v_data[0] = os_alloc(cconn->challenge_length, 1, 1);
			if (!vp->v_data[0]) {
				iscsi_value_free(vp, "CHAP_C sent");
				goto target_error;
			}
			vp->v_data_used = 1;
			vp->v_type = ISCSI_VALUE_TYPE_NUMERIC_ENCODE_BASE64;
			vp->v_num[0] = cconn->challenge_length;
			//      vp->v_data[0] = cconn->challenge;
			memcpy(vp->v_data[0], cconn->challenge,
			       cconn->challenge_length);
			kvp->kv_valp = vp;
			kvp->kv_flags |= ISCSI_KV_FLAG_SEND;

			/* save the CHAP_C we sent */
			vp->v_flag = ISCSI_VALUE_FLAG_LOCKED;
			iscsi_value_list_append(&csess->kvp_chap_c_sent.kv_valp,
						vp);

			break;

		case CHAP_STATE_CHALLENGE:
			/* find CHAP_N, CHAP_R */
			if (!kvlist[CHAP_KEY_AUTH_NAME].kv_rcvcnt ||
			    !kvlist[CHAP_KEY_AUTH_RESPONSE].kv_rcvcnt ||
			    kvlist[CHAP_KEY_AUTH_ALGORITHM].kv_rcvcnt) {
				os_log_error
					("chap challenge: bad keys! N %u, R %u, A %u.\n",
					 kvlist[CHAP_KEY_AUTH_NAME].kv_rcvcnt,
					 kvlist[CHAP_KEY_AUTH_RESPONSE].
					 kv_rcvcnt,
					 kvlist[CHAP_KEY_AUTH_ALGORITHM].
					 kv_rcvcnt);
				goto auth_failure;
			}

			kvp = kvlist + CHAP_KEY_AUTH_NAME;
			os_strcpy(cinfo->remote_name, kvp->kv_valp->v_str[0]);
			cinfo->flag |= CHAP_FLAG_REMOTE_NAME_VALID;
			if (tclass && tclass->fp_chap_info_get) {
				tclass->fp_chap_info_get(iname, tname, cinfo);
			} else {
				cpair = chap_search_pairq_by_name(cnode->remoteq,
							  kvp->kv_valp->
							  v_str[0]);
				if (cpair) {
					os_strcpy(cinfo->remote_secret, cpair->secret);
					cinfo->remote_secret_length = os_strlen(cpair->secret);
					cinfo->flag |= CHAP_FLAG_REMOTE_SECRET_VALID;
				}
				cpair = cnode->localq->q_head;
				if (cpair) {
					os_strcpy(cinfo->local_name, cpair->name);
					os_strcpy(cinfo->local_secret, cpair->secret);
					cinfo->local_secret_length = os_strlen(cpair->secret);
					cinfo->flag |= CHAP_FLAG_LOCAL_NAME_VALID | CHAP_FLAG_LOCAL_SECRET_VALID;
				}
			}

			if (!(cinfo->flag & CHAP_FLAG_REMOTE_SECRET_VALID)) {
				os_log_error("Chap initiator name %s not found.\n",
					 kvp->kv_valp->v_str[0]);
				goto auth_failure;
			}

			kvp = kvlist + CHAP_KEY_AUTH_RESPONSE;
			vp = kvp->kv_valp;
			if (cconn->algorithm == MD5_ALGORITHM) {
				unsigned char digest[CHAP_MD5_DIGEST_LEN];
				chap_calc_digest_md5(cconn->id,
						     cinfo->remote_secret,
						     cconn->challenge,
						     cconn->challenge_length,
						     digest);
				if (memcmp
				    (digest, vp->v_data[0],
				     CHAP_MD5_DIGEST_LEN)) {
					os_log_error("Chap MD5 digest bad.\n",
						     cconn->state);
					iscsi_display_byte_string
						("rcv challenge", vp->v_data[0],
						 0, vp->v_num[0], NULL, 0);
					iscsi_display_byte_string
						("computed challenge",
						 cconn->challenge, 0,
						 cconn->challenge_length, NULL,
						 0);
					goto auth_failure;
				}
			} else if (cconn->algorithm == SHA1_ALGORITHM) {
				unsigned char digest[CHAP_SHA1_DIGEST_LEN];
				chap_calc_digest_sha1(cconn->id,
						      cinfo->remote_secret,
						      cconn->challenge,
						      cconn->challenge_length,
						      digest);
				if (memcmp
				    (digest, vp->v_data[0],
				     CHAP_SHA1_DIGEST_LEN)) {
					os_log_error("Chap SHA1 digest bad.\n",
						     cconn->state);
					iscsi_display_byte_string
						("rcv challenge", vp->v_data[0],
						 0, vp->v_num[0], NULL, 0);
					iscsi_display_byte_string
						("computed challenge",
						 cconn->challenge, 0,
						 cconn->challenge_length, NULL,
						 0);
					goto auth_failure;
				}
			}

			/* fall through */
			cconn->state = CHAP_STATE_RESPONSE;

		case CHAP_STATE_RESPONSE:
			/* look for CHAP_I and CHAP_C */

			/* no target authentication */
			if (!kvlist[CHAP_KEY_AUTH_ID].kv_rcvcnt &&
			    !kvlist[CHAP_KEY_AUTH_CHALLENGE].kv_rcvcnt) {
				/* mutual chap required */
				if (cconn->policy == CHAP_POLICY_MUTUAL ||
				    cinfo->flag & CHAP_FLAG_MUTUAL_REQUIRED) {
					os_log_error("mutual chap required.\n",
						     cconn->state);
					goto auth_failure;
				} else {
					cconn->state = CHAP_STATE_DONE;
					aconn->c_state = AUTH_STATE_DONE;
					goto done;
				}
			}

			/* only CHAP_I or CHAP_C is present */
			if (!kvlist[CHAP_KEY_AUTH_ID].kv_rcvcnt ||
			    !kvlist[CHAP_KEY_AUTH_CHALLENGE].kv_rcvcnt) {
				os_log_error
					("chap respond: bad keys! I %u, C %u.\n",
					 kvlist[CHAP_KEY_AUTH_ID].kv_rcvcnt,
					 kvlist[CHAP_KEY_AUTH_CHALLENGE].
					 kv_rcvcnt);

				goto auth_failure;
			}

			kvp = kvlist + CHAP_KEY_AUTH_ID;
			id = (unsigned char) kvp->kv_valp->v_num[0];
			if (chap_session_check_duplicate_id(csess, id)) {
				os_log_error("chap id 0x%x reflected.\n", id);
				//return -LOGIN_INITIATOR_ERROR;
			}

			/* make sure CHAP_C is not reflected in the same session */
			kvp = kvlist + CHAP_KEY_AUTH_CHALLENGE;
			vp = kvp->kv_valp;
			if (chap_session_check_duplicate_challenge
			    (csess, vp->v_num[0], vp->v_data[0])) {
				goto auth_failure;
			}
			/* save rcv'd CHAP_C */
			iscsi_value_list_append(&csess->kvp_chap_c_rcv.kv_valp,
						vp);
		
			/* Save the encoding - needed for sending the CHAP_R response */
			chap_response_vtype = vp->v_type; 	
	
			kvp->kv_valp = NULL;
			
			if (!(cinfo->flag & CHAP_FLAG_LOCAL_NAME_VALID) ||
			    !(cinfo->flag & CHAP_FLAG_LOCAL_SECRET_VALID)) {
				os_log_error
					("chap target secret not provisioned.\n",
					 cconn->state);
				goto auth_failure;
			}

			if (cconn->algorithm == MD5_ALGORITHM) {
				digest_len = CHAP_MD5_DIGEST_LEN;
				chap_calc_digest_md5(id,
						     cinfo->local_secret,
						     vp->v_data[0],
						     vp->v_num[0], digest);
			} else if (cconn->algorithm == SHA1_ALGORITHM) {
				digest_len = CHAP_SHA1_DIGEST_LEN;
				chap_calc_digest_sha1(id,
						      cinfo->local_secret,
						      vp->v_data[0],
						      vp->v_num[0], digest);
			} else {
				os_log_error
					("chap respond: unknown algorithm 0x%x.\n",
					 cconn->algorithm);
				goto auth_failure;
			}

			/* send CHAP_R */
			kvp = kvlist + CHAP_KEY_AUTH_RESPONSE;
			if (kvp->kv_valp) {
				vp = kvp->kv_valp;
				os_free(vp->v_data[0]);
			} else {
				vp = iscsi_value_alloc();
				if (!vp)
					goto target_error;
				kvp->kv_valp = vp;
			}
			
			/* Set the encoding to what we had received on CHAP_C */
			vp->v_type = chap_response_vtype;
			
			vp->v_num[0] = digest_len;
			vp->v_data[0] = os_alloc(digest_len, 1, 1);
			if (!vp->v_data[0])
				goto target_error;
			memcpy(vp->v_data[0], digest, digest_len);
			vp->v_data_used = 1;
			kvp->kv_flags |= ISCSI_KV_FLAG_SEND;

			/* send CHAP_N */
			kvp = kvlist + CHAP_KEY_AUTH_NAME;
			if (kvp->kv_valp) {
				vp = kvp->kv_valp;
				os_free(vp->v_str[0]);
			} else {
				vp = iscsi_value_alloc();
				if (!vp)
					goto target_error;
				kvp->kv_valp = vp;
			}
			vp->v_str[0] = os_strdup(cinfo->local_name);
			if (!vp->v_str[0])
				goto target_error;
			vp->v_str_used = 1;
			kvp->kv_flags |= ISCSI_KV_FLAG_SEND;

			cconn->state = CHAP_STATE_DONE;
			aconn->c_state = AUTH_STATE_DONE;
			break;
		default:
			os_log_error("UNKNOWN target chap state 0x%x.\n", cconn->state);
			goto target_error;
	}

done:
	return 0;

initiator_error:
        *status_class = ISCSI_LOGIN_STATUS_CLASS_INITIATOR_ERROR;
        *status_detail = ISCSI_LOGIN_STATUS_DETAIL_INIT_ERROR;
        return 0;
target_error:
        *status_class = ISCSI_LOGIN_STATUS_CLASS_TARGET_ERROR;
        *status_detail = ISCSI_LOGIN_STATUS_DETAIL_NO_RESOURCES;
        return 0;
auth_failure:
        *status_class = ISCSI_LOGIN_STATUS_CLASS_INITIATOR_ERROR;
        *status_detail = ISCSI_LOGIN_STATUS_DETAIL_AUTH_FAILURE;
        return 0;
}

int chap_connection_process(iscsi_auth_connection *aconn, 
			    chiscsi_target_class *tclass, 
			    char *iname, char *tname, 
			    unsigned char *status_class,
			    unsigned char *status_detail)
{
	iscsi_auth_session *asess = aconn->c_sess;
	iscsi_auth_node *anode = asess->s_node;
	chap_session *csess = asess->s_method_data[AUTH_METHOD_CHAP];
	chap_connection *cconn = (chap_connection *) aconn->c_method_data;
	int     rv = -LOGIN_TARGET_ERROR;

	if (!csess) {
		csess = os_alloc(sizeof(chap_session), 1, 1);
		if (!csess)
			return -LOGIN_TARGET_ERROR;
		/* os_alloc does memset() */
		csess->kvp_chap_i.kv_name =
			chap_auth_key_table[CHAP_KEY_AUTH_ID].name;
		csess->kvp_chap_c_sent.kv_name =
			chap_auth_key_table[CHAP_KEY_AUTH_CHALLENGE].name;
		csess->kvp_chap_c_rcv.kv_name =
			chap_auth_key_table[CHAP_KEY_AUTH_CHALLENGE].name;

		asess->s_method_data[AUTH_METHOD_CHAP] = csess;
		csess->node = anode->n_method_data[AUTH_METHOD_CHAP];
	}

	if (!cconn) {
		cconn = os_alloc(sizeof(chap_connection), 1, 1);
		if (!cconn)
			return -LOGIN_TARGET_ERROR;
		/* os_alloc does memset() */
		aconn->c_method_data = (void *) cconn;
		cconn->challenge_length = csess->node->challenge_length;
		cconn->policy = csess->node->policy;
		cconn->csess = csess;
	}

	if (anode->n_type == ISCSI_TARGET)
		rv = chap_target_process_connection(aconn, tclass, iname, tname,
						    status_class, status_detail);
	return rv;
}
