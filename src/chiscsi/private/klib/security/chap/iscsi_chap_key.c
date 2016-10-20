#include "iscsi_chap_private.h"
#include "iscsi_chap_api.h"
#include "../../text/iscsi_text_private.h"

/*
 * Functions for CHAP Login Key Table
 */

/* CHAP_A, v_num[0] -- algorithm */
STATIC int kv_decode_chap_algorithm(int mode, char *buf, iscsi_value * vp, char *ebuf)
{
	int     rv;

	rv = kv_decode_number(mode, buf, vp, ebuf);
	if (rv < 0)
		return rv;

	if (vp->v_num[0] == 0x5) {
		vp->v_num[0] = MD5_ALGORITHM;
		return 0;
	} else if (vp->v_num[0] == 0x7) {
		vp->v_num[0] = SHA1_ALGORITHM;
		return 0;
	}

	vp->v_num_used = 0;
	if (ebuf)
		sprintf(ebuf + os_strlen(ebuf),
			"invaild chap algorithm %u.\n", vp->v_num[0]);
	os_log_info("invaild chap algorithm %u.\n", vp->v_num[0]);
	return -ISCSI_EFORMAT;
}

STATIC int kv_encode_chap_algorithm(char *buf, iscsi_value * vp)
{
	int     rv = -ISCSI_EINVAL;

	if (vp->v_num[0] == MD5_ALGORITHM) {
		rv = sprintf(buf, "5");
	} else if (vp->v_num[0] == SHA1_ALGORITHM) {
		rv = sprintf(buf, "7");
	}
	return rv;
}

STATIC int kv_size_chap_algorithm(iscsi_value * vp)
{
	return 1;
}

/* CHAP_N */
STATIC int kv_decode_chap_name(int mode, char *buf, iscsi_value * vp, char *ebuf)
{
	int	len = os_strlen(buf);
	int i = 0;
	
	if (len < CHAP_NAME_LEN_MIN || len > CHAP_NAME_LEN_MAX) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"ERR! chap id needs to be %d ~ %d characters.\n",
				CHAP_NAME_LEN_MIN, CHAP_NAME_LEN_MAX);
		os_log_error("chap id needs to be %d ~ %d characters: %s.\n",
			     CHAP_NAME_LEN_MIN, CHAP_NAME_LEN_MAX, buf);
		return -ISCSI_EFORMAT;
	}
	
	for(i=0;i<=len;i++)
	{
		if(buf[i] == ' ' || buf[i] == ',') {
			if (ebuf)
				sprintf(ebuf + os_strlen(ebuf),
						"ERR! Invalid character %c in chap id .\n",buf[i]);
			os_log_error("Invalid character %c in chap id .\n",buf[i]);
			return -ISCSI_EFORMAT;
		}
	}
		

	vp->v_str[0] = os_strdup(buf);
	if (!vp->v_str[0])
		return -ISCSI_ENOMEM;
	vp->v_str_used = 1;
	return 0;
}

/* CHAP_R */
/* CHAP_I */
/* CHAP_C */
STATIC int kv_decode_chap_challenge(int mode, char *buf, iscsi_value * vp, char *ebuf)
{
	int     rv = kv_decode_encoded_numeric(mode, buf, vp, ebuf);
	int	len = os_strlen(buf);
	int i = 0;
	if (rv < 0)
		return rv;
	/* challenge value should be between 1 and 1024 bytes */
	if (!vp->v_num[0] || vp->v_num[0] > 1024) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf), 
				"challenge length %u > 1024.\n",
				vp->v_num[0]);
		os_log_error("challenge length %u > 1024.\n", vp->v_num[0]);
		return -ISCSI_EINVAL;
	}
	for(i=0;i<=len;i++)
	{
		if(buf[i] == ' ' || buf[i] == ',') {
			if (ebuf)
				sprintf(ebuf + os_strlen(ebuf),
						"ERR! Invalid character %c in chap secret .\n",buf[i]);
			os_log_error("Invalid character %c in chap secret .\n",buf[i]);
			return -ISCSI_EFORMAT;
                }
        }

	return 0;
}

/*
 * CHAP Login Key Table
 */
iscsi_keydef chap_auth_key_table[CHAP_KEY_AUTH_COUNT] = {
	/* CHAP_KEY_AUTH_ALGORITHM */
	{
	 .name = "CHAP_A",
	 .vtype = ISCSI_VALUE_TYPE_LIST,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_TARGET | ISCSI_KEY_STAGE_LOGIN_SECURITY),
	 .fp_decode = kv_decode_chap_algorithm,
	 .fp_encode = kv_encode_chap_algorithm,
	 .fp_size = kv_size_chap_algorithm}
	,
	/* CHAP_KEY_AUTH_NAME */
	{
	 .name = "CHAP_N",
	 .vtype = ISCSI_VALUE_TYPE_TEXT,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_TARGET | ISCSI_KEY_STAGE_LOGIN_SECURITY),
	 .fp_decode = kv_decode_chap_name,
	 .fp_encode = kv_encode_text,
	 .fp_size = kv_size_text}
	,
	/* CHAP_KEY_AUTH_RESPONSE */
	{
	 .name = "CHAP_R",
	 .vtype = ISCSI_VALUE_TYPE_NUMERIC_ENCODE,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_TARGET | ISCSI_KEY_STAGE_LOGIN_SECURITY),
	 .fp_decode = kv_decode_encoded_numeric,
	 .fp_encode = kv_encode_encoded_numeric,
	 .fp_size = kv_size_encoded_numeric}
	,
	/* CHAP_KEY_AUTH_ID */
	{
	 .name = "CHAP_I",
	 .vtype = ISCSI_VALUE_TYPE_NUMERIC,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_TARGET |
		      ISCSI_KEY_STAGE_LOGIN_SECURITY | ISCSI_KEY_HAS_MAX),
	 .val_max = 0xFF,
	 .fp_decode = kv_decode_number,
	 .fp_encode = kv_encode_number,
	 .fp_size = kv_size_number}
	,
	/* CHAP_KEY_AUTH_CHALLENGE */
	{
	 .name = "CHAP_C",
	 .vtype = ISCSI_VALUE_TYPE_NUMERIC_ENCODE,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_TARGET | ISCSI_KEY_STAGE_LOGIN_SECURITY),
	 .fp_decode = kv_decode_chap_challenge,
	 .fp_encode = kv_encode_encoded_numeric,
	 .fp_size = kv_size_encoded_numeric}
};

/*
 * Functions for CHAP Config Key Table
 */

/* 
 * Initiator/Target: Auth_CHAP_Target/Auth_CHAP_Initiator=
 * string pair seperated by CHAP_PAIR_SEPERATOR, 
 * (i.e., "<id>"<CHAP_PAIR_SEPERATOR>"<secret>"),
 * both <id> and <secret> should be enclosed by a pair of double quotes
 *		v_str[0] -- id
 *		v_str[1] -- secret
 */
STATIC int kv_decode_chap_pair(int mode, char *buf, iscsi_value * vp, char *ebuf)
{
	char   *ch = buf, *id, *secret;
	int     len;
	int i = 0;

	if (*ch != '"') {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"ERR! chap id should be in double quote.\n");
		os_log_error("chap id should be in double quote: %s.\n", ch);
		return -ISCSI_EFORMAT;
	}
	/* id portion */
	ch++;
	id = ch;
	/* look for the 2nd double quote */
	while (*ch && (*ch != '"'))
		ch++;
	if (*ch != '"') {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"ERR! chap id missing 2nd double quote.\n");
		os_log_error("chap id missing 2nd double quote: %s.\n", id);
		return -ISCSI_EFORMAT;
	}
	*ch = 0;
	ch++;

	if (*ch != CHAP_PAIR_SEPERATOR) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"ERR! chap pair missing seperator %c.\n",
				CHAP_PAIR_SEPERATOR);
		os_log_error("chap pair missing seperator %c: %s\n",
			     CHAP_PAIR_SEPERATOR, id);
		return -ISCSI_EFORMAT;
	}
	*ch = 0;
	ch++;

	/* secret portion */
	if (*ch != '"') {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"ERR! chap secret should be in double quote.\n");
		os_log_error("chap secret should be in double quote.\n", ch);
		return -ISCSI_EFORMAT;
	}

	ch++;
	secret = ch;
	/* look for the 2nd double quote */
	while (*ch && (*ch != '"'))
		ch++;
	if (*ch != '"') {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"ERR! chap secret missing 2nd double quote.\n");
		os_log_error("chap secret missing 2nd double quote: %s.\n",
			     secret);
		return -ISCSI_EFORMAT;
	}
	*ch = 0;

	len = os_strlen(id);
	if (len < CHAP_NAME_LEN_MIN || len > CHAP_NAME_LEN_MAX) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"ERR! chap id needs to be %d ~ %d characters.\n",
				CHAP_NAME_LEN_MIN, CHAP_NAME_LEN_MAX);
		os_log_error("chap id needs to be %d ~ %d characters: %s.\n",
			     CHAP_NAME_LEN_MIN, CHAP_NAME_LEN_MAX, id);
		return -ISCSI_EFORMAT;
	}
	for(i=0;i<=len;i++)
	{
		if(buf[i] == ' ' || buf[i] == ',') {
			if (ebuf)
				sprintf(ebuf + os_strlen(ebuf),
						"ERR! chap id cannot contain spaces or commas.\n");
			os_log_error("chap id cannot contain %s.\n","spaces or commas");
			return -ISCSI_EFORMAT;
		}
	}

	len = os_strlen(secret);
	if (len < CHAP_SECRET_LEN_MIN || len > CHAP_SECRET_LEN_MAX) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"ERR! chap secret needs to be %d ~ %d characters.\n",
				CHAP_SECRET_LEN_MIN, CHAP_SECRET_LEN_MAX);
		os_log_error
			("chap secret needs to be %d ~ %d characters: %s.\n",
			 CHAP_SECRET_LEN_MIN, CHAP_SECRET_LEN_MAX, secret);
		return -ISCSI_EFORMAT;
	}
	if(secret[0] == ' ')
	{
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
					"ERR! chap secret cannot begin with a space character.\n");
		os_log_error("chap id cannot begin with a %s.\n","space character");
		return -ISCSI_EFORMAT;
	}
        for(i=0;i<=len;i++)
        {
                if(secret[i] == ',') {
                        if (ebuf)
                                sprintf(ebuf + os_strlen(ebuf),
                                                "ERR! chap secret cannot contain commas\n");
                        os_log_error("chap secret cannot contain %s.\n","commas");
                        return -ISCSI_EFORMAT;
                }
        }
	vp->v_str[0] = os_strdup(id);
	if (!vp->v_str[0])
		return -ISCSI_ENOMEM;
	vp->v_str[1] = os_strdup(secret);
	if (!vp->v_str[1]) {
		os_free(vp->v_str[0]);
		return -ISCSI_ENOMEM;
	}
	vp->v_str_used = 2;
	return 0;
}

STATIC int kv_post_decode_chap_pair(iscsi_keyval * kvp, iscsi_value * vp,
				    char *ebuf)
{
	iscsi_value *tmp;

	for (tmp = kvp->kv_valp; tmp; tmp = tmp->v_next) {
		if (!os_strcmp(tmp->v_str[0], vp->v_str[0]) ||
		    !os_strcmp(tmp->v_str[1], vp->v_str[1])) {
			if (ebuf)
				sprintf(ebuf + os_strlen(ebuf),
					"duplicate chap name or secret for %s.\n",
					vp->v_str[0]);
			os_log_error("duplicate chap name or secret for %s.\n",
				     vp->v_str[0]);
			return -ISCSI_EDUP;
		}
	}
	return 0;
}

/* 
 * Initiator/Target: Auth_CHAP_ChallengeLength=	
 *		v_num[0] -- challenge length  
 */
STATIC int kv_decode_chap_challenge_length(int mode, char *buf, iscsi_value * vp,
					   char *ebuf)
{
	int     rv;
	rv = kv_decode_number(mode, buf, vp, ebuf);
	/* challenge length can not be 0, and must be multiple of 16 */
	if (!rv && (!vp->v_num[0] || (vp->v_num[0] & 0xF))) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"ERR! Invalid ChallengeLength %u.\n",
				vp->v_num[0]);
		os_log_error("Invalid ChallengeLength %u.\n", vp->v_num[0]);
		return -ISCSI_EINVAL;
	}
	return rv;
}

/* 
 * Initiator/Target: Auth_CHAP_Policy=	
 *		v_num[0] -- policy 
 */
STATIC int kv_decode_chap_policy(int mode, char *buf, iscsi_value * vp, char *ebuf)
{
	if (!os_strcmp(buf, CHAP_POLICY_ONEWAY_STR)) {
		vp->v_num[0] = CHAP_POLICY_ONEWAY;
	} else if (!os_strcmp(buf, CHAP_POLICY_MUTUAL_STR)) {
		vp->v_num[0] = CHAP_POLICY_MUTUAL;
	} else {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"ERR! invalid policy %s.\n", buf);
		os_log_error("invalid policy %s.\n", buf);
		return -ISCSI_EINVAL;
	}
	vp->v_num_used = 1;
	return 0;
}

/*
 * CHAP Config Key Table
 */
iscsi_keydef chap_config_key_table[CHAP_KEY_CONFIG_COUNT] = {
	/* CHAP_KEY_CONFIG_TARGET */
	{
	 .name = "Auth_CHAP_Target",
	 .vtype = ISCSI_VALUE_TYPE_TEXT,
	 .property = (ISCSI_KEY_SENDER_ALL_CONFIG |
		      ISCSI_KEY_DECLARE_MULTIPLE | ISCSI_KEY_CHANGABLE),
	 .fp_decode = kv_decode_chap_pair,
	 .fp_post_decode = kv_post_decode_chap_pair}
	,
	/* CHAP_KEY_CONFIG_INITIATOR */
	{
	 .name = "Auth_CHAP_Initiator",
	 .vtype = ISCSI_VALUE_TYPE_TEXT,
	 .property = (ISCSI_KEY_SENDER_ALL_CONFIG |
		      ISCSI_KEY_DECLARE_MULTIPLE | ISCSI_KEY_CHANGABLE),
	 .fp_decode = kv_decode_chap_pair,
	 .fp_post_decode = kv_post_decode_chap_pair}
	,
	/* CHAP_KEY_CONFIG_CHALLENGE_LENGTH */
	{
	 .name = "Auth_CHAP_ChallengeLength",
	 .vtype = ISCSI_VALUE_TYPE_NUMERIC,
	 .property = (ISCSI_KEY_SENDER_ALL_CONFIG |
		      ISCSI_KEY_CHANGABLE | ISCSI_KEY_HAS_DEFAULT |
		      ISCSI_KEY_HAS_MIN | ISCSI_KEY_HAS_MAX),
	 .val_dflt = CHAP_CHALLENGE_LENGTH_DFLT,
	 .val_min = CHAP_CHALLENGE_LENGTH_MIN,
	 .val_max = CHAP_CHALLENGE_LENGTH_MAX,
	 .fp_decode = kv_decode_chap_challenge_length}
	,
	/* CHAP_KEY_CONFIG_POLICY */
	{
	 .name = "Auth_CHAP_Policy",
	 .vtype = ISCSI_VALUE_TYPE_TEXT,
	 .property = (ISCSI_KEY_SENDER_ALL_CONFIG |
		      ISCSI_KEY_CHANGABLE | ISCSI_KEY_HAS_DEFAULT),
	 .val_dflt = CHAP_POLICY_DFLT,
	 .fp_decode = kv_decode_chap_policy}
};

/* 
 * Initiator/Target: CHAP name/secret queue
 */
chap_string_pair *chap_search_pairq_by_name_secret(chiscsi_queue * pairq,
						   char *name, char *secret)
{
	chap_string_pair *cpair;
	for (cpair = pairq->q_head; cpair; cpair = cpair->next) {
		if (!os_strcmp(name, cpair->name) &&
		    !os_strcmp(secret, cpair->secret))
			break;
	}
	return cpair;
}

chap_string_pair *chap_search_pairq_by_name(chiscsi_queue * pairq, char *name)
{
	chap_string_pair *cpair;
	for (cpair = pairq->q_head; cpair; cpair = cpair->next) {
		if (!os_strcmp(name, cpair->name))
			break;
	}
	return cpair;
}

chap_string_pair *chap_search_pairq_by_secret(chiscsi_queue * pairq, char *secret)
{
	chap_string_pair *cpair;
	for (cpair = pairq->q_head; cpair; cpair = cpair->next) {
		if (!os_strcmp(secret, cpair->secret))
			break;
	}
	return cpair;
}

STATIC void chap_empty_pairq(chiscsi_queue * pairq)
{
	chap_string_pair *cpair;

	chap_string_pair_dequeue(nolock, pairq, cpair);
	while (cpair) {
		os_free(cpair);
		chap_string_pair_dequeue(nolock, pairq, cpair);
	}
}

STATIC int chap_add_pairq(chiscsi_queue * pairq, iscsi_value * vp)
{
	if (!vp)
		return 0;
	if (!pairq)
		return -ISCSI_ENULL;

	for (; vp; vp = vp->v_next) {
		chap_string_pair *cpair;
		cpair = os_alloc(sizeof(chap_string_pair), 1, 1);
		if (!cpair)
			return -ISCSI_ENOMEM;
		/* os_alloc does memset() */
		os_strcpy(cpair->name, vp->v_str[0]);
		os_strcpy(cpair->secret, vp->v_str[1]);
		chap_string_pair_enqueue(nolock, pairq, cpair);
	}
	return 0;
}

/*
 * CHAP API -- alloc/free per node
 */
void chap_node_free(void *arg)
{
	chap_node *cnode = (chap_node *) arg;

	if (!cnode)
		return;

	chap_empty_pairq(cnode->localq);
	chap_empty_pairq(cnode->remoteq);
	ch_queue_free(cnode->localq);
	ch_queue_free(cnode->remoteq);
	os_free(cnode);
}

STATIC chap_node *chap_node_alloc(void)
{
	chap_node *cnode;

	cnode = os_alloc(CHAP_NODE_SIZE, 1, 1);
	if (!cnode)
		return NULL;

	/* os_alloc does memset() */
	ch_queue_alloc(cnode->localq);
	ch_queue_alloc(cnode->remoteq);

	return ((void *) cnode);

q_lock_fail:
	ch_queue_free(cnode->localq);
	ch_queue_free(cnode->remoteq);
	os_free(cnode);
	return NULL;
}

STATIC int chap_config_check_one_node(iscsi_auth_node * anode, char *ebuf,
				      int ebuflen)
{
	chap_node *cnode = anode->n_method_data[AUTH_METHOD_CHAP];
	chap_string_pair *cpair_local;

	if (cnode->localq->q_cnt > 1) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"too many %s chap id/secret: %u.",
				(anode->n_type ==
				 ISCSI_TARGET) ? "target" : "initiator",
				cnode->localq->q_cnt);
		os_log_error("too many %s chap id/secret: %u.",
			     (anode->n_type ==
			      ISCSI_TARGET) ? "target" : "initiator",
			     cnode->localq->q_cnt);
		return -ISCSI_EINVAL;
	}

	/* make sure the same secret is not used in both local and remote */
	for (cpair_local = cnode->localq->q_head; cpair_local;
	     cpair_local = cpair_local->next) {
		if (chap_search_pairq_by_secret
		    (cnode->remoteq, cpair_local->secret)) {
			if (ebuf)
				sprintf(ebuf + os_strlen(ebuf),
					"same secret %s used for target and initiator!\n",
					cpair_local->secret);
			os_log_error
				("same secret %s used for target and initiator!\n",
				 cpair_local->secret);
			return -ISCSI_EINVAL;
		}
	}

	return 0;
}

int chap_node_config(iscsi_auth_node * anode, iscsi_keyval * kvlist,
		     char *ebuf, int ebuflen)
{
	int     rv = 0;
	chap_node *cnode = NULL;
	iscsi_keyval *kvp;
	chiscsi_queue *it_pairq;
	chiscsi_queue *ii_pairq;

	if (anode->n_method_data[AUTH_METHOD_CHAP]) {
		os_log_error("chap node method data not NULL.\n", anode);
		return -ISCSI_EINVAL;
	}

	cnode = chap_node_alloc();
	if (!cnode)
		return -ISCSI_ENOMEM;
	anode->n_method_data[AUTH_METHOD_CHAP] = (void *) cnode;

	if (anode->n_type == ISCSI_TARGET) {
		it_pairq = cnode->localq;
		ii_pairq = cnode->remoteq;
	} else if (anode->n_type == ISCSI_INITIATOR) {
		ii_pairq = cnode->localq;
		it_pairq = cnode->remoteq;
	} else {
		rv = -ISCSI_EINVAL;
		goto err_out;
	}

	rv = iscsi_kvlist_fill_default(CHAP_KEY_CONFIG_COUNT, kvlist);
	if (rv < 0)
		goto err_out;

	kvp = kvlist + CHAP_KEY_CONFIG_TARGET;
	rv = chap_add_pairq(it_pairq, kvp->kv_valp);
	if (rv < 0)
		goto err_out;

	kvp = kvlist + CHAP_KEY_CONFIG_INITIATOR;
	rv = chap_add_pairq(ii_pairq, kvp->kv_valp);
	if (rv < 0)
		goto err_out;

	kvp = kvlist + CHAP_KEY_CONFIG_CHALLENGE_LENGTH;
	cnode->challenge_length = kvp->kv_valp->v_num[0];

	kvp = kvlist + CHAP_KEY_CONFIG_POLICY;
	cnode->policy = kvp->kv_valp->v_num[0];

	rv = chap_config_check_one_node(anode, ebuf, ebuflen);
	if (rv < 0)
		goto err_out;

	return 0;

      err_out:
	if (cnode) {
		chap_node_free(cnode);
		anode->n_method_data[AUTH_METHOD_CHAP] = NULL;
	}
	return rv;
}

STATIC int chap_text_size_pairq(char *prefix, chiscsi_queue * q)
{
	int     len = 0;
	/* prefix = " ":" " */
	int     prefix_len = os_strlen(prefix) + 12;
	chap_string_pair *cpair;

	for (cpair = q->q_head; cpair; cpair = cpair->next) {
		len += prefix_len + os_strlen(cpair->name) +
			os_strlen(cpair->secret);
	}

	return len;
}

STATIC int chap_display_pairq(char *prefix, chiscsi_queue * q, char *buf,
			      int buflen)
{
	int     baselen = os_strlen(buf);
	int	len = baselen;
	chap_string_pair *cpair;

	for (cpair = q->q_head; cpair; cpair = cpair->next) {
	/* Fix for PR 1575 - Do not display unencrypted password in cpair->secret */
		len += sprintf(buf + len, "\t%s=\"%s\"%c\"%s\"\n", prefix,
			       cpair->name, CHAP_PAIR_SEPERATOR, "********");
		if (len >= buflen)
			break;
	}

	if (len >= buflen)
		len = buflen;
	return (len - baselen);
}

/* dump config settings */
int chap_node_config_text_size(iscsi_auth_node * anode, int kidx)
{
	chap_node *cnode = (chap_node *) anode->n_method_data[AUTH_METHOD_CHAP];
	int     dump_all = (kidx == CHAP_KEY_CONFIG_COUNT) ? 1 : 0;
	int     len = 0;

	if (!cnode)
		return 0;

	/* target name/secret */
	if (dump_all || kidx == CHAP_KEY_CONFIG_TARGET) {
		iscsi_keydef *kdef =
			&chap_config_key_table[CHAP_KEY_CONFIG_TARGET];
		chiscsi_queue *q =
			(anode->n_type ==
			 ISCSI_TARGET) ? cnode->localq : cnode->remoteq;
		len += chap_text_size_pairq(kdef->name, q);
	}

	/* initiator name/secret */
	if (dump_all || kidx == CHAP_KEY_CONFIG_INITIATOR) {
		iscsi_keydef *kdef =
			&chap_config_key_table[CHAP_KEY_CONFIG_INITIATOR];
		chiscsi_queue *q =
			(anode->n_type ==
			 ISCSI_TARGET) ? cnode->remoteq : cnode->localq;
		len += chap_text_size_pairq(kdef->name, q);
	}

	if (dump_all || kidx == CHAP_KEY_CONFIG_CHALLENGE_LENGTH) {
		iscsi_keydef *kdef =
			&chap_config_key_table
			[CHAP_KEY_CONFIG_CHALLENGE_LENGTH];
		len += os_strlen(kdef->name) + 2 + 4;	/* max. challenge length is 4-digit decimal */
	}

	if (dump_all || kidx == CHAP_KEY_CONFIG_POLICY) {
		iscsi_keydef *kdef =
			&chap_config_key_table[CHAP_KEY_CONFIG_POLICY];
		len += os_strlen(kdef->name) + 2 + 8;	/* max. string length is "Oneway" */
	}

	return len;
}

int chap_node_config_display(iscsi_auth_node * anode, int kidx, char *buf,
			     int buflen)
{
	chap_node *cnode = (chap_node *) anode->n_method_data[AUTH_METHOD_CHAP];
	int     dump_all = (kidx == CHAP_KEY_CONFIG_COUNT) ? 1 : 0;
	int     baselen = os_strlen(buf);
	int	len = baselen;

	if (!cnode)
		return 0;

	if (dump_all || kidx == CHAP_KEY_CONFIG_TARGET) {
		iscsi_keydef *kdef =
			&chap_config_key_table[CHAP_KEY_CONFIG_TARGET];
		chiscsi_queue *q =
			(anode->n_type ==
			 ISCSI_TARGET) ? cnode->localq : cnode->remoteq;
		len += chap_display_pairq(kdef->name, q, buf + len,
					  buflen - len);
		if (len >= buflen)
			goto done;
	}

	if (dump_all || kidx == CHAP_KEY_CONFIG_INITIATOR) {
		iscsi_keydef *kdef =
			&chap_config_key_table[CHAP_KEY_CONFIG_INITIATOR];
		chiscsi_queue *q =
			(anode->n_type ==
			 ISCSI_TARGET) ? cnode->remoteq : cnode->localq;
		len += chap_display_pairq(kdef->name, q, buf + len,
					  buflen - len);
		if (len >= buflen)
			goto done;
	}

#if 0
	/* already covered in chiscsi_chap_settings_sprintf() */
	if (dump_all || kidx == CHAP_KEY_CONFIG_CHALLENGE_LENGTH) {
		iscsi_keydef *kdef =
			&chap_config_key_table
			[CHAP_KEY_CONFIG_CHALLENGE_LENGTH];
		len += sprintf(buf + len, "\t%s=%u\n", kdef->name,
			       cnode->challenge_length);
		if (len >= buflen)
			goto done;
	}

	if (dump_all || kidx == CHAP_KEY_CONFIG_POLICY) {
		iscsi_keydef *kdef =
			&chap_config_key_table[CHAP_KEY_CONFIG_POLICY];

		len += sprintf(buf + len, "\t%s=", kdef->name);
		if (cnode->policy == CHAP_POLICY_ONEWAY) {
			len += sprintf(buf + len, "%s\n",
				       CHAP_POLICY_ONEWAY_STR);
		} else if (cnode->policy == CHAP_POLICY_MUTUAL) {
			len += sprintf(buf + len, "%s\n",
				       CHAP_POLICY_MUTUAL_STR);
		}

		if (len >= buflen)
			goto done;
	}
#endif

      done:
	if (len >= buflen)
		len = buflen;
	return (len - baselen);
}

/* add config settings */
int chap_node_config_add(iscsi_auth_node * anode, iscsi_keyval * kvp, int kidx,
			 char *ebuf, int ebuflen)
{
	chap_node *cnode = (chap_node *) anode->n_method_data[AUTH_METHOD_CHAP];
	iscsi_value *vp = kvp->kv_valp;
	int     rv = 0;

	if (!vp)
		return -ISCSI_ENULL;
	if (!cnode)
		return -ISCSI_ENULL;

	switch (kidx) {
		case CHAP_KEY_CONFIG_TARGET:
			if (anode->n_type == ISCSI_TARGET) {
				chap_empty_pairq(cnode->localq);
				rv = chap_add_pairq(cnode->localq, vp);
				return rv;
			} else if (anode->n_type == ISCSI_INITIATOR) {
				chap_string_pair *cpair;
				cpair = chap_search_pairq_by_name(cnode->
								  remoteq,
								  vp->v_str[0]);
				if (!cpair) {
					/* new name/secret pair */
					rv = chap_add_pairq(cnode->remoteq, vp);
				} else {
					/* existing name/secret pair */
					os_strcpy(cpair->secret, vp->v_str[1]);
				}
				return rv;
			}
			break;
		case CHAP_KEY_CONFIG_INITIATOR:
			if (anode->n_type == ISCSI_TARGET) {
				chap_string_pair *cpair;
				cpair = chap_search_pairq_by_name(cnode->
								  remoteq,
								  vp->v_str[0]);
				if (!cpair) {
					/* new name/secret pair */
					rv = chap_add_pairq(cnode->remoteq, vp);
				} else {
					/* existing name/secret pair */
					os_strcpy(cpair->secret, vp->v_str[1]);
				}
				return rv;
			} else if (anode->n_type == ISCSI_INITIATOR) {
				chap_empty_pairq(cnode->localq);
				rv = chap_add_pairq(cnode->localq, vp);
				return rv;
			}
			break;
		case CHAP_KEY_CONFIG_CHALLENGE_LENGTH:
			cnode->challenge_length = vp->v_num[0];
			return 0;
			break;
		case CHAP_KEY_CONFIG_POLICY:
			cnode->policy = vp->v_num[0];
			return 0;
			break;
	}
	return -ISCSI_EINVAL;
}

/* remove config settings */
int chap_node_config_remove(iscsi_auth_node * anode, iscsi_keyval * kvp,
			    int kidx, char *ebuf, int ebuflen)
{
	chap_node *cnode = anode->n_method_data[AUTH_METHOD_CHAP];
	iscsi_value *vp;

	if (!cnode)
		return -ISCSI_ENULL;

	/* remove everything */
	if (!kvp) {
		switch (kidx) {
			case CHAP_KEY_CONFIG_TARGET:
				if (anode->n_type == ISCSI_TARGET) {
					chap_empty_pairq(cnode->localq);
				} else if (anode->n_type == ISCSI_INITIATOR) {
					chap_empty_pairq(cnode->remoteq);
				}
				return 0;
			case CHAP_KEY_CONFIG_INITIATOR:
				if (anode->n_type == ISCSI_TARGET) {
					chap_empty_pairq(cnode->remoteq);
				} else if (anode->n_type == ISCSI_INITIATOR) {
					chap_empty_pairq(cnode->localq);
				}
				return 0;
			case CHAP_KEY_CONFIG_CHALLENGE_LENGTH:
				cnode->challenge_length =
					CHAP_CHALLENGE_LENGTH_DFLT;
				return 0;
			case CHAP_KEY_CONFIG_POLICY:
				cnode->policy = CHAP_POLICY_DFLT;
				return 0;
		}
		return -ISCSI_EINVAL;
	}

	/* remove selected values, only for CHAP_KEY_CONFIG_TARGET/INITIATOR */
	vp = kvp->kv_valp;
	if (kidx == CHAP_KEY_CONFIG_TARGET) {
		/* both name and secret have to match to remove the pair */
		if (anode->n_type == ISCSI_TARGET) {
			chap_string_pair *cpair;
			cpair = chap_search_pairq_by_name_secret(cnode->localq,
								 vp->v_str[0],
								 vp->v_str[1]);
			if (cpair)
				chap_empty_pairq(cnode->localq);
			else if (ebuf)
				sprintf(ebuf + os_strlen(ebuf),
					"No match found for \"%s\":\"%s\".\n",
					vp->v_str[0], vp->v_str[1]);
			return 0;
		} else if (anode->n_type == ISCSI_INITIATOR) {
			chap_string_pair *cpair;
			cpair = chap_search_pairq_by_name_secret(cnode->remoteq,
								 vp->v_str[0],
								 vp->v_str[1]);
			/* existing name/secret pair */
			if (cpair)
				chap_string_pair_ch_qremove(lock, cnode->remoteq,
							 cpair);
			else {
				if (ebuf)
					sprintf(ebuf + os_strlen(ebuf),
						"No match found for \"%s\":\"%s\".\n",
						vp->v_str[0], vp->v_str[1]);
				os_log_info
					("No match found for \"%s\":\"%s\".\n",
					 vp->v_str[0], vp->v_str[1]);
			}
			return 0;
		}
	} else if (kidx == CHAP_KEY_CONFIG_INITIATOR) {
		/* both name and secret have to match to remove the pair */
		/* vp should not be NULL */
		if (anode->n_type == ISCSI_TARGET) {
			chap_string_pair *cpair;
			cpair = chap_search_pairq_by_name_secret(cnode->remoteq,
								 vp->v_str[0],
								 vp->v_str[1]);
			/* existing name/secret pair */
			if (cpair)
				chap_string_pair_ch_qremove(lock, cnode->remoteq,
							 cpair);
			else {
				if (ebuf)
					sprintf(ebuf + os_strlen(ebuf),
						"No match found for \"%s\":\"%s\".\n",
						vp->v_str[0], vp->v_str[1]);
				os_log_warn
					("No match found for \"%s\":\"%s\".\n",
					 vp->v_str[0], vp->v_str[1]);
			}
			return 0;
		} else if (anode->n_type == ISCSI_INITIATOR) {
			chap_string_pair *cpair;
			cpair = chap_search_pairq_by_name_secret(cnode->localq,
								 vp->v_str[0],
								 vp->v_str[1]);
			if (cpair)
				chap_empty_pairq(cnode->localq);
			else {
				if (ebuf)
					sprintf(ebuf + os_strlen(ebuf),
						"No match found for \"%s\":\"%s\".\n",
						vp->v_str[0], vp->v_str[1]);
				os_log_warn
					("No match found for \"%s\":\"%s\".\n",
					 vp->v_str[0], vp->v_str[1]);
			}
			return 0;
		}
	}

	return -ISCSI_EINVAL;
}

int iscsi_get_node_chap_settings(struct iscsi_chap_settings *chap, void *anodep)
{
        iscsi_auth_node *anode = (iscsi_auth_node *)anodep;
	chap_node *cnode = anode->n_method_data[AUTH_METHOD_CHAP];

        chap->chap_required = anode->n_forced;
        chap->chap_en = (anode->n_method_flag[AUTH_METHOD_CHAP] &
                        AUTH_NODE_METHOD_FLAG_ENABLE) ? 1 : 0;

	if (cnode) {
		chap->challenge_length = cnode->challenge_length;
		chap->mutual_chap_forced = 
			(cnode->policy == CHAP_POLICY_MUTUAL) ? 1 : 0;
	} else if (chap->chap_en) {
		//os_debug_msg("node chap enabled, but chap_node is NULL.\n", 1);
		chap->chap_en = 0;
//		return -ISCSI_EINVAL;
	}

	return 0;
}

