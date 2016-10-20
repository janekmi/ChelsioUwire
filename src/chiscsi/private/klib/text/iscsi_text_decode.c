/*
 * iscsi_text.c
 * iscsi keys definitions
 */

#include <common/iscsi_common.h>
#include <iscsi_structs.h>
#include <iscsi_global.h>
#include "iscsi_text_private.h"

/*
 * The following routines scan the text buffer and try to decode the
 * key-value pair.
 */

/* given a buffer, break it into key and value part: <key>=<value> 
   key must not be empty, but empty value is allowed */
int iscsi_get_keyval_string(int buflen, char *buf, char **key, char **val,
			    char *ebuf)
{
	int     i = 0;

	*key = *val = NULL;

	/* the buffer should contain <key>=<value> followed by NULL */
	*key = buf;
	while (buf[i] && (buf[i] != '=') && i < buflen)
		i++;
	if (buf[i] != '=') {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"key-value pair %s, missing \"=\".\n",
				*key);
		os_log_info("key-value pair %s, missing \"=\".\n", *key);
		return -ISCSI_EFORMAT;
	}
	/* terminate key string */
	buf[i] = '\0';
	i++;

	*val = buf + i;
	while (buf[i] && i < buflen)
		i++;
	if (i == buflen)
		i--;

	/* the key value pair should end with a NULL character */
	if (buf[i]) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"key-value pair %s not terminated with NULL.\n",
				*key);
		os_log_info("key-value pair %s, not terminated with NULL.\n",
			    *key);
		return -ISCSI_EFORMAT_STR;
	}

	/*
	 * ignore the extra NULL characters at the end
	 * NOTE: this is not strict according to RFC 3720, but most
	 * 	initiator/target does not seem to enforce this.
	 * 	and we need this to pad the last login pdu, so that the 1st pdu
	 *	in the FFP phase would start on the 8-byte boundary
	 */
	for (; i < buflen && !buf[i]; i++)
		;

	return (i);
}

/* given a iscsi_keyval, check the key property */
STATIC int kv_check_key_property(iscsi_keyval * kvp, int state, int node,
				 char *ebuf)
{
	iscsi_keydef *kdefp = kvp->kv_def;

	if (!kdefp)
		return -ISCSI_ENULL;

	/* we received key multiple times */
	if (kvp->kv_rcvcnt > 1 &&
	    !(kdefp->property & ISCSI_KEY_DECLARE_MULTIPLE)) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"%s: rcv'd %u times.\n", kvp->kv_name,
				kvp->kv_rcvcnt);
		os_log_info("%s, rcv'd %u times.\n", kvp->kv_name,
			    kvp->kv_rcvcnt);
		kvp->kv_flags |= ISCSI_KV_FLAG_DUPLICATE;
		if (state < CONN_STATE_FFP) {
			return -ISCSI_EINVAL_STATE;
		}
	}

	/* empty value allowed ? */
	if ((kvp->kv_flags & ISCSI_KV_FLAG_NO_VALUE) &&
	    !(kdefp->property & ISCSI_KEY_ALLOW_EMPTY_VALUE)) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"%s: rcv'd empty value.\n", kvp->kv_name);
		os_log_info("%s: rcv'd empty value.\n", kvp->kv_name);
		return -ISCSI_EINVAL;
	}

	if (state == CONN_STATE_CLOSED) {	/* during configuration */
		if ((node == ISCSI_TARGET) &&
		    !(kdefp->property & ISCSI_KEY_SENDER_TARGET_CONFIG)) {
			if (ebuf)
				sprintf(ebuf + os_strlen(ebuf),
					"%s: unexpected target key.\n",
					kvp->kv_name);
			os_log_info("%s: unexpected target key.\n",
				    kvp->kv_name);
			return -ISCSI_EINVAL;
		}

	} else {		/* for an iscsi connection */
		if (state >= CONN_STATE_FFP) {	/* during FFP */
			/* state check */
			if (!(kdefp->property & ISCSI_KEY_STAGE_FFP)) {
				os_log_info("%s: unexpected in FFP, reject.\n",
					    kvp->kv_name);
				kvp->kv_flags |= ISCSI_KV_FLAG_REJECT;
			}
			/* node check */
			if ((node == ISCSI_TARGET) &&
			    !(kdefp->property & (ISCSI_KEY_SENDER_INITIATOR |
						 ISCSI_KEY_SENDER_INITIATOR_FFP)))
			{
				os_log_info
					("%s: unexpected from initiator in FFP, reject.\n",
					 kvp->kv_name);
				kvp->kv_flags |= ISCSI_KV_FLAG_REJECT;
			}
			if ((node == ISCSI_INITIATOR) &&
			    !(kdefp->property & (ISCSI_KEY_SENDER_TARGET |
						 ISCSI_KEY_SENDER_TARGET_FFP)))
			{
				os_log_info
					("%s: unexpected from target in FFP, reject.\n",
					 kvp->kv_name);
				kvp->kv_flags |= ISCSI_KV_FLAG_REJECT;
			}

		} else {	/* during login */
			/* state check */
			if ((state == CONN_STATE_LOGINOPERATIONAL) &&
			    !(kdefp->
			      property & ISCSI_KEY_STAGE_LOGIN_OPERATIONAL)) {
				os_log_info
					("%s: unexpected in LoginOperational, reject.\n",
					 kvp->kv_name);
				kvp->kv_flags |= ISCSI_KV_FLAG_REJECT;
			}
			if ((state == CONN_STATE_LOGINSECURITY) &&
			    !(kdefp->
			      property & ISCSI_KEY_STAGE_LOGIN_SECURITY)) {
				os_log_info
					("%s: unexpected in LoginSecurity, reject.\n",
					 kvp->kv_name);
				kvp->kv_flags |= ISCSI_KV_FLAG_REJECT;
			}
			/* node check */
			if ((node == ISCSI_TARGET) &&
			    !(kdefp->property & (ISCSI_KEY_SENDER_INITIATOR |
						 ISCSI_KEY_SENDER_INITIATOR_LOGIN)))
			{
				os_log_info
					("%s: unexpected from initiator in login, reject.\n",
					 kvp->kv_name);
				kvp->kv_flags |= ISCSI_KV_FLAG_REJECT;
			}
			if ((node == ISCSI_INITIATOR) &&
			    !(kdefp->property & (ISCSI_KEY_SENDER_TARGET |
						 ISCSI_KEY_SENDER_TARGET_LOGIN)))
			{
				os_log_info
					("%s: unexpected from target in login, reject.\n",
					 kvp->kv_name);
				kvp->kv_flags |= ISCSI_KV_FLAG_REJECT;
			}

		}
	}

	/* for rejected keys, drop the value list */
	if (kvp->kv_flags & ISCSI_KV_FLAG_REJECT) {
		iscsi_value *vp = kvp->kv_valp;
		kvp->kv_valp = NULL;
		iscsi_value_free(vp, kvp->kv_name);
	}
	return 0;
}

/* given a iscsi_keyval, check the value property */
STATIC int kv_check_value_property(iscsi_value * vp, iscsi_keydef * kdefp,
				   char *ebuf, int ebuflen)
{
	int     rv = 0;
	int     len = os_strlen(ebuf);

	for (; vp; vp = vp->v_next) {
		int     i;
		for (i = 0; i < vp->v_num_used; i++) {
			if (kdefp->property & ISCSI_KEY_HAS_MIN) {
				if (vp->v_num[i] < kdefp->val_min) {
					rv = -ISCSI_EINVAL;
					if (ebuf && len < ebuflen)
						len += sprintf(ebuf + len,
							       "%s ERR: %u < min %u.\n",
							       kdefp->name,
							       vp->v_num[i],
							       kdefp->val_min);
					os_log_info("%s ERR: %u < min %u.\n",
						    kdefp->name, vp->v_num[i],
						    kdefp->val_min);
				}
			}
			if (kdefp->property & ISCSI_KEY_HAS_MAX) {
				if (vp->v_num[i] > kdefp->val_max) {
					rv = -ISCSI_EINVAL;
					if (ebuf && len < ebuflen)
						len += sprintf(ebuf + len,
							       "%s ERR: %u > max %u.\n",
							       kdefp->name,
							       vp->v_num[i],
							       kdefp->val_max);
					os_log_info("%s ERR: %u > max %u.\n",
						    kdefp->name, vp->v_num[i],
						    kdefp->val_max);
				}
			}
		}
	}

	return rv;
}


/* scan the buffer and break into key-value pair strings,
   save the strings (make a copy) in iscsi_string_pair and
   push to the kvq */

int iscsi_kv_text_to_string_pairq(unsigned int buflen, char *buffer,
				  chiscsi_queue * pairq, char *ebuf, int ebuflen)
{
	char   *key, *val;
	iscsi_string_pair *spair;
	int     key_len;
	int     len;
	int     rv = 0;
	unsigned int seq = 0;

	if (!buffer || !pairq) {
		return -ISCSI_ENULL;
	}

	len = 0;
	while (len < buflen) {
		unsigned int flag = 0;

		rv = iscsi_get_keyval_string(buflen - len, buffer + len, &key,
					     &val, ebuf);
		if (rv < 0) {
			goto cleanup;
		}
		if (!key)
			return -ISCSI_EFORMAT;
		seq++;
		len += rv;

		key_len = os_strlen(key);
		if (key_len > ISCSI_KEY_NAME_MAX_LEN) {
			if (ebuf)
				sprintf(ebuf + os_strlen(ebuf), "%s: key length %d > max %d.\n",
					key, key_len, ISCSI_KEY_NAME_MAX_LEN);
			os_log_info("%s: key length %d > max %d.\n",
				    key, key_len, ISCSI_KEY_NAME_MAX_LEN);
			rv = -ISCSI_EFORMAT_LONG;
			goto cleanup;
		}

		/* check if the value is Reject/NotUnderstood/Irrelevant */
		if (val) {
			rv = kv_decode_response(ISCSI_KV_DECODE_OP_ADD, val, &flag);
			if (!rv) {
				val = NULL;
			} else if (rv < 0) {
				/* not Reject/NotUnderstood/Irrelevant, save */
				if (val[0] == 0)
					flag |= ISCSI_KV_FLAG_NO_VALUE;
				rv = 0;
			}
		} else {
			flag |= ISCSI_KV_FLAG_NO_VALUE;
		}

		/* search the pairq to see if the same key has been received */
		for (spair = pairq->q_head; spair; spair = spair->p_next) {
			if ((key_len == spair->p_keylen) &&
			    !(os_strcmp(spair->p_key, key))) {
				break;
			}
		}

		/* new key */
		if (!spair) {
			spair = os_alloc(sizeof(iscsi_string_pair), 1, 1);
			if (!spair) {
				os_log_info("%s: out of memory.\n", key);
				rv = -ISCSI_ENOMEM;
				goto cleanup;
			}

			/* os_alloc does memset() */

			/* save the 1st occurance, seq is useful if need to check the 
			   order of the key-value pair being sent */
			spair->p_seq = seq;

			if (val) {
				spair->p_val.s_str = val;
			}

			spair->p_keylen = key_len;
			//os_strncpy(spair->p_key, key, key_len);
			spair->p_key = key;
			string_pair_enqueue(nolock, pairq, spair);

		} else {
			iscsi_string *s_valp, *prev;
			s_valp = os_alloc(sizeof(iscsi_string), 1, 1);
			if (!s_valp) {
				os_log_info("%s: value out of memory.\n", key);
				rv = -ISCSI_ENOMEM;
				goto cleanup;
			}
			/* os_alloc does memset() */
			if (val) {
				s_valp->s_str = val;
			}

			/* append to the end of the value string list */
			for (prev = spair->p_val.s_next; prev && prev->s_next;
			     prev = prev->s_next) ;
			if (prev)
				prev->s_next = s_valp;
			else
				spair->p_val.s_next = s_valp;
		}

		spair->p_flag |= flag;

	}
	//iscsi_pairq_display(__FUNCTION__, pairq);
	return 0;

      cleanup:
	iscsi_empty_string_pairq(pairq);
	return rv;
}

/*
 * text decoding APIs
 */

/* decoding a buffer according to a key */
int iscsi_kvp_decode_buffer(int mode, int ntype, int state, iscsi_keyval * kvp,
			    char *buf, char *ebuf, int ebuflen)
{
	int     rv;
	int     pos = kvp->kv_rcvcnt;
	iscsi_keydef *kdefp = kvp->kv_def;
	iscsi_value *vp;

	kvp->kv_rcvcnt++;

	rv = kv_check_key_property(kvp, state, ntype, ebuf);
	if (rv < 0)
		return rv;

	if (kvp->kv_flags & ISCSI_KV_FLAG_RESPONSE) {
		if (state == CONN_STATE_CLOSED) {
			os_log_info("%s: received response in closed state.\n",
				    kdefp->name);
			return -ISCSI_EINVAL;
		} else
			return 0;
	}

	if (kdefp->vtype == ISCSI_VALUE_TYPE_LIST) {
		/* multiple value */
		int     good_cnt = 0;
		char   *start;
		char   *ch = buf;

		while (*ch) {
			iscsi_value value;

			/* skip any extraneous commas (missing/empty list values) */
			while (*ch && (*ch == ','))
				ch++;
			/* look for end of current value (comma or EOS) */
			start = ch;
			while (*ch && (*ch != ','))
				ch++;
			if (*ch) {
				*ch = '\0';
				ch++;
			}

			memset(&value, 0, sizeof(iscsi_value));
			rv = kdefp->fp_decode(mode, start, &value, ebuf);
			/* for multiple values, we will decode as much as we can, and
			   discard the bad part */
			if (rv < 0)
				continue;

			if (kdefp->fp_post_decode) {
				rv = kdefp->fp_post_decode(kvp, &value, ebuf);
				if (rv < 0)
					continue;
			}

			rv = kv_check_value_property(&value, kdefp, ebuf,
						     ebuflen);
			if (rv < 0)
				continue;

			good_cnt++;

			/* allocate new value */
			vp = iscsi_value_alloc();
			if (!vp)
				return -ISCSI_ENOMEM;
			memcpy(vp, &value, sizeof(iscsi_value));
			
			vp->v_next = value.v_next;
			iscsi_value_list_append(&kvp->kv_valp, vp);
			/* mark the value as together */
			for (; vp; vp = vp->v_next)
				vp->v_pos = pos;
		}

		/* let it pass, as long as there is at least one valid value */
		if (!good_cnt) {
			if (ebuf)
				sprintf(ebuf + os_strlen(ebuf),
					"%s, ERR! NO valid value found.\n",
					kvp->kv_name);
			os_log_info("%s: NO valid value found.\n",
				    kvp->kv_name);
			return -ISCSI_EINVAL;
			//kvp->kv_flags |= ISCSI_KV_FLAG_REJECT;
		}

	} else {		/* single value */
		iscsi_value value;
		memset(&value, 0, sizeof(iscsi_value));

		rv = kdefp->fp_decode(mode, buf, &value, ebuf);
		if (rv < 0)
			return rv;

		if (kdefp->fp_post_decode) {
			rv = kdefp->fp_post_decode(kvp, &value, ebuf);
			if (rv < 0)
				return rv;
		}

		rv = kv_check_value_property(&value, kdefp, ebuf, ebuflen);
		if (rv < 0) {
			if (state == CONN_STATE_CLOSED)
				return rv;
			/* if value is invalid, do not fail, just set reject bit */
			kvp->kv_flags |= ISCSI_KV_FLAG_REJECT;
			rv = 0;
		} else {
			/* add the value */
			vp = iscsi_value_alloc();
			if (!vp)
				return -ISCSI_ENOMEM;
			memcpy(vp, &value, sizeof(iscsi_value));

			vp->v_next = value.v_next;
			iscsi_value_list_append(&kvp->kv_valp, vp);
			/* mark the value as together */
			for (; vp; vp = vp->v_next)
				vp->v_pos = pos;
		}
	}

	return 0;
}

int iscsi_kvp_decode_pair(int node, int state, iscsi_keyval * kvp,
			  iscsi_string_pair * pair, char *ebuf, int ebuflen)
{
	iscsi_string *svalp = &(pair->p_val);

	if (!kvp->kv_def) {
		os_log_info("%s, kvp has no def.\n", pair->p_key);
		return -ISCSI_EINVAL;
	}

	kvp->kv_rcvseq = pair->p_seq;
	kvp->kv_flags = pair->p_flag;

	/* empty value */
	for (; svalp; svalp = svalp->s_next) {
		int     rv;
		rv = iscsi_kvp_decode_buffer(ISCSI_KV_DECODE_OP_ADD, node, state, kvp, svalp->s_str,
					     ebuf, ebuflen);
		if (rv < 0)
			return rv;
	}

	return 0;
}

/* given a key definition table, take out the matched keys from pairq,
   decode it, then save it to the kvlist
   the matched key pair will be removed from the pairq,
   return # of pairs decoded */
int iscsi_kvlist_decode_pairq_discovery(int state, int node, int kmax,
			      iscsi_keyval * kvlist, chiscsi_queue * pairq,
			      char *ebuf, int ebuflen)
{
	iscsi_keyval *kvp;
	int i, count = 0;
	int rv = 0;
	iscsi_string_pair *spair;
	
	/* create key-val string pair */
	spair = os_alloc(sizeof(iscsi_string_pair), 1, 1);
	if (!spair) {
		os_log_info("%s: out of memory.\n", __func__);
		return -ISCSI_ENOMEM;
	}

	for (kvp = kvlist, i = 0; i < kmax; kvp++, i++) {
		iscsi_keydef *kdef = kvp->kv_def;
		char buff[80] ;
		int flag = 0;
		int len;

		spair->p_val.s_str = NULL;
		spair->p_val.s_next = NULL;

		if ((os_strlen("Auth_CHAP_ChallengeLength") ==
				os_strlen(kdef->name)) &&
			!os_strcmp(kdef->name,"Auth_CHAP_ChallengeLength")) {
			continue;
		}

		/* go through the queue, looking for the matching key */
		if ((os_strlen("Auth_CHAP_Target") == os_strlen(kdef->name)) &&
			!os_strcmp(kdef->name,"Auth_CHAP_Target") &&
			(disc_auth_chap_target[0] != 0)) {
			spair->p_val.s_str = os_strdup(disc_auth_chap_target);
			flag = 1;
		}
		
		if ((os_strlen("Auth_CHAP_Initiator") == os_strlen(kdef->name))
			&& !os_strcmp(kdef->name,"Auth_CHAP_Initiator") &&
			(disc_auth_chap_initiator[0] != 0)) {
			spair->p_val.s_str = os_strdup(disc_auth_chap_initiator);
			flag = 1;
		} 

		if (!os_strcmp(kdef->name,"Auth_CHAP_Policy")) {
			if(disc_auth_chap_policy)
				len = sprintf(buff, "%s","Mutual");
			else
				len = sprintf(buff, "%s","Oneway");
			buff[len] = 0;

			spair->p_val.s_str = buff;
			flag = 1;
		}
		
		if (!flag)
			continue;

		/* a match is find */
		count++;

		rv = iscsi_kvp_decode_pair(node, state, kvp, spair, ebuf,
					   ebuflen);
		if (rv < 0)
			break;
	}

	spair->p_val.s_str = NULL;
	iscsi_string_pair_free(spair);

	return rv < 0 ? rv : count;
}

/* given a key definition table, take out the matched keys from pairq,
   decode it, then save it to the kvlist
   the matched key pair will be removed from the pairq,
   return # of pairs decoded */
int iscsi_kvlist_decode_pairq(int state, int node, int kmax,
			      iscsi_keyval * kvlist, chiscsi_queue * pairq,
			      char *ebuf, int ebuflen)
{
	iscsi_keyval *kvp;
	int     i, count = 0;
	int     rv = 0;

	for (kvp = kvlist, i = 0; i < kmax; kvp++, i++) {
		iscsi_string_pair *spair;
		iscsi_keydef *kdef = kvp->kv_def;

		/* go through the queue, looking for the matching key */
		spair = iscsi_string_pair_find_by_key(pairq, kdef->name);
		if (!spair)
			continue;

		/* a match is find */
		count++;
			
		rv = iscsi_kvp_decode_pair(node, state, kvp, spair, ebuf,
					   ebuflen);
		if (rv < 0)
			return rv;

		string_pair_ch_qremove(nolock, pairq, spair);
		iscsi_string_pair_free(spair);
	}

	return count;
}
