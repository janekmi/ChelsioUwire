/*
 * iSCSI Connection-wide Keys 
 */
#include <common/os_builtin.h>
#include <common/iscsi_common.h>
#include <iscsi_structs.h>
#include <iscsi_global.h>
#include <iscsi_auth_api.h>
#include <iscsi_connection_keys.h>
#include "iscsi_text_private.h"

/* Initiator/Target: HeaderDigest/DataDigest=	*/
/*		v_num[0] -- digest  */
STATIC int kv_decode_digest(int mode, char *buf, iscsi_value * vp, char *ebuf)
{
	if (!os_strcmp(buf, "CRC32C"))
		vp->v_num[0] = ISCSI_DIGEST_CRC32C;
	else if (!os_strcmp(buf, "None"))
		vp->v_num[0] = ISCSI_DIGEST_NONE;
	else {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"ERR! digest %s.\n", buf);
		os_log_info("ERR! digest %s.\n", buf);
		return -ISCSI_EFORMAT;
	}
	vp->v_num_used = 1;
	return 0;
}

STATIC int kv_encode_digest(char *buf, iscsi_value * vp)
{
	int     rv = -ISCSI_EINVAL;
	if (vp->v_num[0] == ISCSI_DIGEST_CRC32C)
		rv = sprintf(buf, "%s", "CRC32C");
	else if (vp->v_num[0] == ISCSI_DIGEST_NONE)
		rv = sprintf(buf, "%s", "None");
	return (rv);
}

STATIC int kv_size_digest(iscsi_value * vp)
{
	if (vp->v_num[0] == ISCSI_DIGEST_CRC32C)
		return (os_strlen("CRC32C"));
	else if (vp->v_num[0] == ISCSI_DIGEST_NONE)
		return (os_strlen("None"));
	return -ISCSI_EINVAL;
}

STATIC int kv_compute_digest(iscsi_keyval * kvp_f, iscsi_keyval * kvp_t)
{
	iscsi_value *vp_f, *vp_t;
	int     found = 0;

	for (vp_t = kvp_t->kv_valp; vp_t; vp_t = vp_t->v_next) {
		for (vp_f = kvp_f->kv_valp; vp_f; vp_f = vp_f->v_next) {
			if (vp_t->v_num[0] == vp_f->v_num[0]) {
				found = 1;
				break;
			}
		}
		if (found)
			break;
	}

	if (!found) {
		os_log_info("%s: no match is found.\n", kvp_f->kv_name);
		return -ISCSI_ENOMATCH;
	}

	kvp_t->kv_valp->v_num[0] = vp_f->v_num[0];
	kvp_t->kv_valp->v_num_used = 1;

	/* free all the other values */
	vp_t = kvp_t->kv_valp->v_next;
	if (vp_t) {
		kvp_t->kv_valp->v_next = NULL;
		iscsi_value_free(vp_t, kvp_t->kv_name);
	}

	return 0;
}

/* Initiator only: SendTargets=	*/
/*		v_num[0] --   */
STATIC int kv_decode_send_targets(int mode, char *buf, iscsi_value * vp, char *ebuf)
{
	if (buf && os_strlen(buf)) {
		if (os_strcmp(buf, "All") == 0) {
			vp->v_num[0] = ISCSI_SEND_TARGETS_ALL;
		} else {	/* must be specifying a target name */
			vp->v_str[0] = os_strdup(buf);
			if (!vp->v_str[0])
				return -ISCSI_ENOMEM;
			vp->v_str_used = 1;
			vp->v_num[0] = ISCSI_SEND_TARGETS_SPECIFIED;
		}
	} else {
		vp->v_num[0] = ISCSI_SEND_TARGETS_SESSION;
	}
	vp->v_num_used = 1;
	return 0;
}

STATIC int kv_encode_send_targets(char *buf, iscsi_value * vp)
{
	int     rv = -ISCSI_EINVAL;
	if (vp->v_num[0] == ISCSI_SEND_TARGETS_ALL)
		rv = sprintf(buf, "%s", "All");
	else if (vp->v_num[0] == ISCSI_SEND_TARGETS_SPECIFIED)
		rv = sprintf(buf, "%s", vp->v_str[0]);
	else if (vp->v_num[0] == ISCSI_SEND_TARGETS_SESSION)
		rv = 0;
	return (rv);
}

STATIC int kv_size_send_targets(iscsi_value * vp)
{
	if (vp->v_num[0] == ISCSI_SEND_TARGETS_ALL)
		return (os_strlen("All"));
	else if (vp->v_num[0] == ISCSI_SEND_TARGETS_SPECIFIED)
		return (os_strlen(vp->v_str[0]));
	else if (vp->v_num[0] == ISCSI_SEND_TARGETS_SESSION)
		return 0;
	return -ISCSI_EINVAL;
}

/* Initiator and Target: TargetName/InitiatorName	*/
/*		v_str[0] --   */
int kv_decode_iscsi_name(int mode, char *buf, iscsi_value * vp, char *ebuf)
{
	unsigned char *ch;

	/* RFC 3722, section 1 
 	 * iSCSI names are generalized using a normalized character set
 	 * (converted to lower case or equivalent), with no white space allowed,
 	 * and very limited punctuation.  
 	 * ....
 	 * In addition, any upper-case characters input via a user interface
 	 * MUST be mapped to their lower-case equivalents.
 	 */
	os_str2lower(buf);

	if (os_strncmp(buf, "iqn.", 4) && os_strncmp(buf, "eui.", 4) &&
	    os_strncmp(buf, "all", 3) && os_strncmp(buf, "ALL", 3)) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"ERR! INVALID iscsi name format %s.\n", buf);
		os_log_info("INVALID iscsi name format %s.\n", buf);
		return -ISCSI_EFORMAT;
	}
	if (os_strlen(buf) > ISCSI_NAME_LEN_MAX) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"ERR! iscsi name %s, length %d > %d.\n",
				buf, (int) os_strlen(buf), ISCSI_NAME_LEN_MAX);
		os_log_info("ERR! iscsi name %s, length %d > %d.\n",
			    buf, (int) os_strlen(buf), ISCSI_NAME_LEN_MAX);
		return -ISCSI_EFORMAT;
	}
	/* RFC3720 section 3.2.6.2 referring to RFC-3722 section 6.2 */
	for (ch = (unsigned char *) buf; *ch; ch++) {
		if (((*ch <= 0x2c) || (*ch >= 0x80)) ||
		    (*ch == 0x2f) ||
		    ((*ch >= 0x3b) && (*ch <= 0x40)) ||
		    ((*ch >= 0x5b) && (*ch <= 0x60)) ||
		    ((*ch >= 0x7b) && (*ch <= 0x7f))) {
			if (ebuf)
				sprintf(ebuf + os_strlen(ebuf),
					"iSCSI name %s contains prohibited ASCII '%c' (0x%04x).\n",
					buf, *ch, *ch);
			os_log_error
				("iSCSI name %s contains prohibited ASCII '%c' (0x%04x).\n",
				 buf, *ch, *ch);
			return -ISCSI_EFORMAT;
		}
	}

	vp->v_str[0] = os_strdup(buf);
	if (!vp->v_str[0])
		return -ISCSI_ENOMEM;
	vp->v_str_used = 1;
	return 0;
}

/* Initiator and Target: TargetAlias/InitiatorAlias */
/*		v_str[0] --   */
STATIC int kv_decode_iscsi_alias(int mode, char *buf, iscsi_value * vp, char *ebuf)
{
	/*  Do not allow zero-length alias */
	if (!buf || !os_strlen(buf)) {
		return 0;
	}
	/*  Do not allow multiple aliases */
	if (os_strchr(buf,',')) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
					"ERR! Multiple Aliases not allowed\n");
		os_log_error
			("%s: Multiple Aliases not allowed\n", buf);
		return -ISCSI_EFORMAT;
	}
	if (os_strlen(buf) > ISCSI_ALIAS_LEN_MAX) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"ERR! iscsi alias %s, length %d > %d.\n",
				buf, (int) os_strlen(buf), ISCSI_ALIAS_LEN_MAX);
		os_log_info("alias %s, length %d > %d.\n",
			    buf, (int) os_strlen(buf), ISCSI_ALIAS_LEN_MAX);
		return -ISCSI_EFORMAT;
	}
	vp->v_str[0] = os_strdup(buf);
	if (!vp->v_str[0])
		return -ISCSI_ENOMEM;
	vp->v_str_used = 1;
	return 0;
}

STATIC int kv_encode_target_address(char *buf, iscsi_value * vp)
{
	int     len;

	len = tcp_endpoint_sprintf((struct tcp_endpoint *)vp->v_num, buf);
	len += sprintf(buf + len, ",%u", vp->v_num[ISCSI_VALUE_NUM_IDX_PG_TAG]);
	return (len);

}

STATIC int kv_size_target_address(iscsi_value * vp)
{
	struct tcp_endpoint *ep = (struct tcp_endpoint *)vp->v_num;
	int len;

 	/* <ip address>:<port>,<tag>, 2 = ":" + "," */
	len = (tcp_endpoint_is_ipv6(ep)) ? ISCSI_IPV6_ADDR_STR_MAXLEN : ISCSI_IPV4_ADDR_STR_MAXLEN;
	len += 2;

	len += kv_calc_numeric_size(vp->v_num[ISCSI_VALUE_NUM_IDX_PG_TAG]);
	len += kv_calc_numeric_size(vp->v_num[ISCSI_VALUE_NUM_IDX_PG_PORT]);
	
	return len;
}

/* Initiator / Target: OFMarkerInt/IFMarkInter=	*/
/*		v_num[0] --   */
STATIC int kv_compute_markerint(iscsi_keyval * kvp_f, iscsi_keyval * kvp_t)
{
	/* marker NOT supported, mark as irrelevant */
	kvp_t->kv_flags |= ISCSI_KV_FLAG_IRRELEVANT;
	return 0;
}

iscsi_keydef iscsi_keydef_connection_tbl[ISCSI_KEY_CONN_COUNT] = {
	/* ISCSI_KEY_CONN_HEADER_DIGEST */
	{
	 .name = "HeaderDigest",
	 .vtype = ISCSI_VALUE_TYPE_LIST,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_TARGET |
		      ISCSI_KEY_SENDER_ALL_CONFIG |
		      ISCSI_KEY_STAGE_LOGIN_OPERATIONAL |
		      ISCSI_KEY_CHANGABLE | ISCSI_KEY_HAS_DEFAULT |
		      ISCSI_KEY_DISPLAY_MODE_DETAIL),
	 .val_dflt = ISCSI_DIGEST_NONE,
	 .fp_decode = kv_decode_digest,
	 .fp_encode = kv_encode_digest,
	 .fp_size = kv_size_digest,
	 .fp_compute = kv_compute_digest,
	 .fp_compute_check = kv_check_compute_list_selection }
	,
	/* ISCSI_KEY_CONN_DATA_DIGEST */
	{
	 .name = "DataDigest",
	 .vtype = ISCSI_VALUE_TYPE_LIST,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_TARGET |
		      ISCSI_KEY_SENDER_ALL_CONFIG |
		      ISCSI_KEY_STAGE_LOGIN_OPERATIONAL |
		      ISCSI_KEY_CHANGABLE | ISCSI_KEY_HAS_DEFAULT |
		      ISCSI_KEY_DISPLAY_MODE_DETAIL),
	 .val_dflt = ISCSI_DIGEST_NONE,
	 .fp_decode = kv_decode_digest,
	 .fp_encode = kv_encode_digest,
	 .fp_size = kv_size_digest,
	 .fp_compute = kv_compute_digest,
	 .fp_compute_check = kv_check_compute_list_selection }
	,
	/* ISCSI_KEY_CONN_SEND_TARGETS */
	{
	 .name = "SendTargets",
	 .vtype = ISCSI_VALUE_TYPE_TEXT,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_STAGE_FFP | ISCSI_KEY_ALLOW_EMPTY_VALUE),
	 .fp_decode = kv_decode_send_targets,
	 .fp_encode = kv_encode_send_targets,
	 .fp_size = kv_size_send_targets}
	,
	/* ISCSI_KEY_CONN_TARGET_NAME */
	{
	 .name = "TargetName",
	 .vtype = ISCSI_VALUE_TYPE_TEXT,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_TARGET_FFP |
		      ISCSI_KEY_SENDER_TARGET_CONFIG |
		      ISCSI_KEY_STAGE_ALL | ISCSI_KEY_DECLARATIVE),
	 .fp_decode = kv_decode_iscsi_name,
	 .fp_encode = kv_encode_text,
	 .fp_size = kv_size_text}
	,
	/* ISCSI_KEY_CONN_INITIATOR_NAME */
	{
	 .name = "InitiatorName",
	 .vtype = ISCSI_VALUE_TYPE_TEXT,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_INITIATOR_CONFIG |
		      ISCSI_KEY_STAGE_ALL | ISCSI_KEY_DECLARATIVE),
	 .fp_decode = kv_decode_iscsi_name,
	 .fp_encode = kv_encode_text,
	 .fp_size = kv_size_text}
	,
	/* ISCSI_KEY_CONN_TARGET_ALIAS */
	{
	 .name = "TargetAlias",
	 .vtype = ISCSI_VALUE_TYPE_TEXT,
	 .property = (ISCSI_KEY_SENDER_TARGET |
		      ISCSI_KEY_SENDER_TARGET_CONFIG |
		      ISCSI_KEY_STAGE_ALL |
		      ISCSI_KEY_DECLARATIVE |
		      ISCSI_KEY_ALLOW_EMPTY_VALUE),
	 .fp_decode = kv_decode_iscsi_alias,
	 .fp_encode = kv_encode_text,
	 .fp_size = kv_size_text}
	,
	/* ISCSI_KEY_CONN_INITIATOR_ALIAS */
	{
	 .name = "InitiatorAlias",
	 .vtype = ISCSI_VALUE_TYPE_TEXT,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_INITIATOR_CONFIG |
		      ISCSI_KEY_STAGE_ALL |
		      ISCSI_KEY_DECLARATIVE |
		      ISCSI_KEY_ALLOW_EMPTY_VALUE),
	 .fp_decode = kv_decode_iscsi_alias,
	 .fp_encode = kv_encode_text,
	 .fp_size = kv_size_text}
	,
	/* ISCSI_KEY_CONN_TARGET_ADDRESS */
	{
	 .name = "TargetAddress",
	 .vtype = ISCSI_VALUE_TYPE_TEXT,
	 .property = (ISCSI_KEY_SENDER_TARGET |
		      ISCSI_KEY_STAGE_ALL |
		      ISCSI_KEY_DECLARATIVE | ISCSI_KEY_DECLARE_MULTIPLE),
	 .fp_encode = kv_encode_target_address,
	 .fp_size = kv_size_target_address}
	,
	/* ISCSI_KEY_CONN_TARGET_PORTAL_GROUP_TAG */
	{
	 .name = "TargetPortalGroupTag",
	 .vtype = ISCSI_VALUE_TYPE_NUMERIC,
	 .property = (ISCSI_KEY_SENDER_TARGET |
		      ISCSI_KEY_STAGE_ALL | ISCSI_KEY_DECLARATIVE),
	 .fp_decode = kv_decode_number,
	 .fp_encode = kv_encode_number,
	 .fp_size = kv_size_number}
	,
	/* ISCSI_KEY_CONN_MAX_RECV_DATA_SEGMENT_LENGTH */
	{
	 .name = "MaxRecvDataSegmentLength",
	 .vtype = ISCSI_VALUE_TYPE_NUMERIC,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_TARGET |
		      ISCSI_KEY_SENDER_ALL_CONFIG |
		      ISCSI_KEY_STAGE_ALL |
		      ISCSI_KEY_CHANGABLE | ISCSI_KEY_DECLARATIVE |
		      ISCSI_KEY_HAS_DEFAULT | ISCSI_KEY_HAS_MIN |
		      ISCSI_KEY_HAS_MAX | ISCSI_KEY_DISPLAY_MODE_DETAIL),
	 .val_dflt = 8192,
	 .val_min = 512,
	 .val_max = ((1UL << 24) - 1) /* 16777215 */ ,
	 .fp_decode = kv_decode_number,
	 .fp_encode = kv_encode_number,
	 .fp_size = kv_size_number}
	,
	/* ISCSI_KEY_CONN_OF_MARKER */
	{
	 .name = "OFMarker",
	 .vtype = ISCSI_VALUE_TYPE_BOOLEAN,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_TARGET |
		      ISCSI_KEY_SENDER_ALL_CONFIG |
		      ISCSI_KEY_STAGE_LOGIN_OPERATIONAL |
		      /* ISCSI_KEY_CHANGABLE | */
		      ISCSI_KEY_HAS_DEFAULT | ISCSI_KEY_DISPLAY_MODE_DETAIL),
	 .val_dflt = 0,
	 .fp_decode = kv_decode_boolean,
	 .fp_encode = kv_encode_boolean,
	 .fp_size = kv_size_boolean,
	 .fp_compute = kv_compute_boolean_and,
	 .fp_compute_check = kv_check_compute_boolean_and }
	,
	/* ISCSI_KEY_CONN_IF_MARKER */
	{
	 .name = "IFMarker",
	 .vtype = ISCSI_VALUE_TYPE_BOOLEAN,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_TARGET |
		      ISCSI_KEY_SENDER_ALL_CONFIG |
		      ISCSI_KEY_STAGE_LOGIN_OPERATIONAL |
		      /* ISCSI_KEY_CHANGABLE | */
		      ISCSI_KEY_HAS_DEFAULT | ISCSI_KEY_DISPLAY_MODE_DETAIL),
	 .val_dflt = 0,
	 .fp_decode = kv_decode_boolean,
	 .fp_encode = kv_encode_boolean,
	 .fp_size = kv_size_boolean,
	 .fp_compute = kv_compute_boolean_and,
	 .fp_compute_check = kv_check_compute_boolean_and }
	,
	/* ISCSI_KEY_CONN_IF_MARK_INT */
	{
	 .name = "IFMarkInt",
	 .vtype = ISCSI_VALUE_TYPE_NUMERIC_RANGE,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_TARGET |
		      ISCSI_KEY_SENDER_ALL_CONFIG |
		      ISCSI_KEY_STAGE_LOGIN_OPERATIONAL |
		      ISCSI_KEY_CHANGABLE |
		      ISCSI_KEY_HAS_DEFAULT |
		      ISCSI_KEY_HAS_MIN | ISCSI_KEY_HAS_MAX),
	 .val_dflt = 2048,
	 .val_min = 1,
	 .val_max = 65535,
	 .fp_decode = kv_decode_number_range,
	 .fp_encode = kv_encode_number_range,
	 .fp_size = kv_size_number_range,
	 .fp_compute = kv_compute_markerint}
	,
	/* ISCSI_KEY_CONN_OF_MARK_INT */
	{
	 .name = "OFMarkInt",
	 .vtype = ISCSI_VALUE_TYPE_NUMERIC_RANGE,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_TARGET |
		      ISCSI_KEY_SENDER_ALL_CONFIG |
		      ISCSI_KEY_STAGE_LOGIN_OPERATIONAL |
		      ISCSI_KEY_CHANGABLE |
		      ISCSI_KEY_HAS_DEFAULT |
		      ISCSI_KEY_HAS_MIN | ISCSI_KEY_HAS_MAX),
	 .val_dflt = 2048,
	 .val_min = 1,
	 .val_max = 65535,
	 .fp_decode = kv_decode_number_range,
	 .fp_encode = kv_encode_number_range,
	 .fp_size = kv_size_number_range,
	 .fp_compute = kv_compute_markerint}
	,
	/* ISCSI_KEY_CONN_AUTH_METHOD */
	{
	 .name = "AuthMethod",
	 .vtype = ISCSI_VALUE_TYPE_LIST,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_TARGET |
		      ISCSI_KEY_SENDER_ALL_CONFIG |
		      ISCSI_KEY_STAGE_LOGIN_SECURITY | ISCSI_KEY_CHANGABLE |
		      ISCSI_KEY_DISPLAY_MODE_DETAIL),
	 .fp_decode = iscsi_kv_decode_authmethod,
	 .fp_encode = iscsi_kv_encode_authmethod,
	 .fp_size = iscsi_kv_size_authmethod,
	 .fp_compute_check = kv_check_compute_list_selection }
};

/*
 * connections keys API
 */
int iscsi_connection_keys_validate_value(iscsi_keyval * kvlist,
					 char *ebuf, int ebuflen)
{
	iscsi_keyval *kvp;
	iscsi_value *vp1 = kvlist[ISCSI_KEY_CONN_OF_MARKER].kv_valp;
	iscsi_value *vp2 = kvlist[ISCSI_KEY_CONN_IF_MARKER].kv_valp;

	/* required keys: name */
	kvp = kvlist + ISCSI_KEY_CONN_TARGET_NAME;
	if (!kvp->kv_valp || !kvp->kv_valp->v_str[0]) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"%s missing!\n", kvp->kv_name);
		os_log_info("%s missing!\n", kvp->kv_name);
		return -ISCSI_EINVAL;
	}

	/* marker not supported */
	if ((vp1 && vp1->v_num[0]) || (vp2 && vp2->v_num[0])) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"Marker NOT supported!\n");
		os_log_info("Marker NOT supported!\n", 0);
		return -ISCSI_EINVAL;
	}

	return 0;
}

/**
 * iscsi_connection_keys_read_setting -- called after login is complete,
 *      read the connection key settings and free the keylist
 * @conn -- connection
 * return value:
 *      0 for success, < 0 for error
 */
int iscsi_connection_keys_read_setting(iscsi_connection * conn)
{
	iscsi_keyval *kvlist = conn->c_keys;
	iscsi_keyval *kvp;

	kvp = kvlist + ISCSI_KEY_CONN_HEADER_DIGEST;
	conn->c_hdigest_len =
		(kvp->kv_valp->v_num[0] == ISCSI_DIGEST_CRC32C) ? 4 : 0;

	kvp = kvlist + ISCSI_KEY_CONN_DATA_DIGEST;
	conn->c_ddigest_len =
		(kvp->kv_valp->v_num[0] == ISCSI_DIGEST_CRC32C) ? 4 : 0;

	/* re-adjust max data segment since we know the crc settings now */
	iscsi_conn_adjust_pdudatalen_tmax(conn);
	iscsi_conn_adjust_pdudatalen_rmax(conn);

	conn->c_text_tag = ISCSI_INVALID_TAG;

	conn->c_keys = NULL;
	if (kvlist)
		iscsi_connection_key_free(kvlist);

	return 0;
}

static void read_digest_setting(unsigned char *digest, iscsi_keyval *kvp,
				int idx)
{
	iscsi_keyval *kvlist = kvp + idx;
	iscsi_value *vp = kvlist->kv_valp;
	unsigned int val;
	int i = 0;

	if (!vp) {
		iscsi_kvlist_get_value_by_index(idx, NULL,
					iscsi_keydef_connection_tbl, &val);
		*digest = val;
		return; 
	}

	while (vp) {
		digest[i] = vp->v_num[0];
		vp = vp->v_next;
		i++;
		if (i >= 2)
			break;
	}
}

int iscsi_get_connection_key_settings(struct iscsi_conn_settings *setting,
				iscsi_keyval *kvlist)
{
	int rv;

	read_digest_setting(setting->header_digest, kvlist,
			ISCSI_KEY_CONN_HEADER_DIGEST);
	read_digest_setting(setting->data_digest, kvlist,
			ISCSI_KEY_CONN_DATA_DIGEST);

	rv = iscsi_kvlist_get_value_by_index(
			ISCSI_KEY_CONN_MAX_RECV_DATA_SEGMENT_LENGTH,
			kvlist, iscsi_keydef_connection_tbl,
			&setting->max_recv_data_segment);
	if (rv < 0)
		return rv;
	
	return 0;
}
