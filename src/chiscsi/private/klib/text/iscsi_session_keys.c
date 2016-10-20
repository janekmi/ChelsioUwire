#include <common/iscsi_common.h>
#include <iscsi_structs.h>
#include <iscsi_global.h>
#include <iscsi_session_keys.h>
#include "iscsi_text_private.h"

/*
 * iSCSI session-wide keys
 */

/* Initiator/Target: 
 *		v_num[0] -- session type  */
STATIC int kv_decode_session_type(int mode, char *buf, iscsi_value * vp, char *ebuf)
{
	if (!os_strcmp(buf, "Normal"))
		vp->v_num[0] = ISCSI_SESSION_TYPE_NORMAL;
	else if (!os_strcmp(buf, "Discovery"))
		vp->v_num[0] = ISCSI_SESSION_TYPE_DISCOVERY;
	else {
		if (ebuf)
			sprintf(ebuf, "ERR! session type %s.\n", buf);
		os_log_info("ERR! session type %s.\n", buf);
		return -ISCSI_EFORMAT;
	}
	vp->v_num_used = 1;
	return 0;
}

STATIC int kv_encode_session_type(char *buf, iscsi_value * vp)
{
	int     rv = -ISCSI_EINVAL;
	if (vp->v_num[0] == ISCSI_SESSION_TYPE_NORMAL)
		rv = sprintf(buf, "%s", "Normal");
	else if (vp->v_num[0] == ISCSI_SESSION_TYPE_DISCOVERY)
		rv = sprintf(buf, "%s", "Discovery");
	return (rv);
}

STATIC int kv_size_session_type(iscsi_value * vp)
{
	if (vp->v_num[0] == ISCSI_SESSION_TYPE_NORMAL)
		return (os_strlen("Normal"));
	else if (vp->v_num[0] == ISCSI_SESSION_TYPE_DISCOVERY)
		return (os_strlen("Discovery"));
	return -ISCSI_EINVAL;
}

iscsi_keydef iscsi_keydef_session_tbl[ISCSI_KEY_SESS_COUNT] = {
	/* ISCSI_KEY_SESS_MAX_CONNECTIONS */
	{
	 .name = "MaxConnections",
	 .vtype = ISCSI_VALUE_TYPE_NUMERIC,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_TARGET |
		      ISCSI_KEY_SENDER_ALL_CONFIG |
		      ISCSI_KEY_STAGE_LOGIN_OPERATIONAL |
		      ISCSI_KEY_IRRELEVANT_IN_DISCOVERY |
		      ISCSI_KEY_CHANGABLE | ISCSI_KEY_HAS_DEFAULT |
		      ISCSI_KEY_HAS_MIN | ISCSI_KEY_HAS_MAX |
		      ISCSI_KEY_DISPLAY_MODE_DETAIL),
	 .val_dflt = 1,
	 .val_min = 1,
	 .val_max = 65535,
	 .fp_decode = kv_decode_number,
	 .fp_encode = kv_encode_number,
	 .fp_size = kv_size_number,
	 .fp_compute = kv_compute_number_min,
	 .fp_compute_check = kv_check_compute_number_min }
	,
	/* ISCSI_KEY_SESS_INITIAL_R2T */
	{
	 .name = "InitialR2T",
	 .vtype = ISCSI_VALUE_TYPE_BOOLEAN,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_TARGET |
		      ISCSI_KEY_SENDER_ALL_CONFIG |
		      ISCSI_KEY_STAGE_LOGIN_OPERATIONAL |
		      ISCSI_KEY_IRRELEVANT_IN_DISCOVERY |
		      ISCSI_KEY_CHANGABLE | ISCSI_KEY_HAS_DEFAULT |
		      ISCSI_KEY_DISPLAY_MODE_DETAIL),
	 .val_dflt = 1,
	 .fp_decode = kv_decode_boolean,
	 .fp_encode = kv_encode_boolean,
	 .fp_size = kv_size_boolean,
	 .fp_compute = kv_compute_boolean_or,
	 .fp_compute_check = kv_check_compute_boolean_or }
	,
	/* ISCSI_KEY_SESS_MAX_OUTSTANDING_R2T */
	{
	 .name = "MaxOutstandingR2T",
	 .vtype = ISCSI_VALUE_TYPE_NUMERIC,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_TARGET |
		      ISCSI_KEY_SENDER_ALL_CONFIG |
		      ISCSI_KEY_STAGE_LOGIN_OPERATIONAL |
		      ISCSI_KEY_IRRELEVANT_IN_DISCOVERY |
		      ISCSI_KEY_CHANGABLE | ISCSI_KEY_HAS_DEFAULT |
		      ISCSI_KEY_HAS_MIN | ISCSI_KEY_HAS_MAX |
		      ISCSI_KEY_DISPLAY_MODE_DETAIL),
	 .val_dflt = 1,
	 .val_min = 1,
	 .val_max = 65535,
	 //.val_max = ISCSI_SESSION_MAX_OUTSTANDING_R2T,
	 .fp_decode = kv_decode_number,
	 .fp_encode = kv_encode_number,
	 .fp_size = kv_size_number,
	 .fp_compute = kv_compute_number_min,
	 .fp_compute_check = kv_check_compute_number_min }
	,
	/* ISCSI_KEY_SESS_IMMEDIATE_DATA */
	{
	 .name = "ImmediateData",
	 .vtype = ISCSI_VALUE_TYPE_BOOLEAN,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_TARGET |
		      ISCSI_KEY_SENDER_ALL_CONFIG |
		      ISCSI_KEY_STAGE_LOGIN_OPERATIONAL |
		      ISCSI_KEY_IRRELEVANT_IN_DISCOVERY |
		      ISCSI_KEY_CHANGABLE | ISCSI_KEY_HAS_DEFAULT |
		      ISCSI_KEY_DISPLAY_MODE_DETAIL),
	 .val_dflt = 1,
	 .fp_decode = kv_decode_boolean,
	 .fp_encode = kv_encode_boolean,
	 .fp_size = kv_size_boolean,
	 .fp_compute = kv_compute_boolean_and,
	 .fp_compute_check = kv_check_compute_boolean_and }
	,
	/* ISCSI_KEY_SESS_FIRST_BURST_LENGTH */
	{
	 .name = "FirstBurstLength",
	 .vtype = ISCSI_VALUE_TYPE_NUMERIC,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_TARGET |
		      ISCSI_KEY_SENDER_ALL_CONFIG |
		      ISCSI_KEY_STAGE_LOGIN_OPERATIONAL |
		      ISCSI_KEY_IRRELEVANT_IN_DISCOVERY |
		      ISCSI_KEY_CHANGABLE | ISCSI_KEY_HAS_DEFAULT |
		      ISCSI_KEY_HAS_MIN | ISCSI_KEY_HAS_MAX |
		      ISCSI_KEY_DISPLAY_MODE_DETAIL),
	 .val_dflt = 65536,
	 .val_min = 512,
	 .val_max = ((1UL << 24) - 1) /* 16777215 */ ,
	 .fp_decode = kv_decode_number,
	 .fp_encode = kv_encode_number,
	 .fp_size = kv_size_number,
	 .fp_compute = kv_compute_number_min,
	 .fp_compute_check = kv_check_compute_number_min}
	,
	/* ISCSI_KEY_SESS_MAX_BURST_LENGTH */
	{
	 .name = "MaxBurstLength",
	 .vtype = ISCSI_VALUE_TYPE_NUMERIC,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_TARGET |
		      ISCSI_KEY_SENDER_ALL_CONFIG |
		      ISCSI_KEY_STAGE_LOGIN_OPERATIONAL |
		      ISCSI_KEY_IRRELEVANT_IN_DISCOVERY |
		      ISCSI_KEY_CHANGABLE | ISCSI_KEY_HAS_DEFAULT |
		      ISCSI_KEY_HAS_MIN | ISCSI_KEY_HAS_MAX |
		      ISCSI_KEY_DISPLAY_MODE_DETAIL),
	 .val_dflt = 262144,
	 .val_min = 512,
	 .val_max = ((1UL << 24) - 1) /* 16777215 */ ,
	 .fp_decode = kv_decode_number,
	 .fp_encode = kv_encode_number,
	 .fp_size = kv_size_number,
	 .fp_compute = kv_compute_number_min,
	 .fp_compute_check = kv_check_compute_number_min}
	,
	/* ISCSI_KEY_SESS_DEFAULT_TIME2WAIT */
	{
	 .name = "DefaultTime2Wait",
	 .vtype = ISCSI_VALUE_TYPE_NUMERIC,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_TARGET |
		      ISCSI_KEY_SENDER_ALL_CONFIG |
		      ISCSI_KEY_STAGE_LOGIN_OPERATIONAL |
		      ISCSI_KEY_CHANGABLE | ISCSI_KEY_HAS_DEFAULT |
		      ISCSI_KEY_HAS_MIN | ISCSI_KEY_HAS_MAX |
		      ISCSI_KEY_DISPLAY_MODE_DETAIL),
	 .val_dflt = 2,
	 .val_min = 0,
	 .val_max = 3600,
	 .fp_decode = kv_decode_number,
	 .fp_encode = kv_encode_number,
	 .fp_size = kv_size_number,
	 .fp_compute = kv_compute_number_max,
	 .fp_compute_check = kv_check_compute_number_max}
	,
	/* ISCSI_KEY_SESS_DEFAULT_TIME2RETAIN */
	{
	 .name = "DefaultTime2Retain",
	 .vtype = ISCSI_VALUE_TYPE_NUMERIC,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_TARGET |
		      ISCSI_KEY_SENDER_ALL_CONFIG |
		      ISCSI_KEY_STAGE_LOGIN_OPERATIONAL |
		      ISCSI_KEY_CHANGABLE | ISCSI_KEY_HAS_DEFAULT |
		      ISCSI_KEY_HAS_MIN | ISCSI_KEY_HAS_MAX |
		      ISCSI_KEY_DISPLAY_MODE_DETAIL),
	 .val_dflt = 20,
	 .val_min = 0,
	 .val_max = 3600,
	 .fp_decode = kv_decode_number,
	 .fp_encode = kv_encode_number,
	 .fp_size = kv_size_number,
	 .fp_compute = kv_compute_number_min,
	 .fp_compute_check = kv_check_compute_number_min}
	,
	/* ISCSI_KEY_SESS_DATA_PDU_ORDER */
	{
	 .name = "DataPDUInOrder",
	 .vtype = ISCSI_VALUE_TYPE_BOOLEAN,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_TARGET |
		      ISCSI_KEY_SENDER_ALL_CONFIG |
		      ISCSI_KEY_STAGE_LOGIN_OPERATIONAL |
		      ISCSI_KEY_IRRELEVANT_IN_DISCOVERY |
		      ISCSI_KEY_HAS_DEFAULT | ISCSI_KEY_DISPLAY_MODE_DETAIL),
	 .val_dflt = 1,
	 .fp_decode = kv_decode_boolean,
	 .fp_encode = kv_encode_boolean,
	 .fp_size = kv_size_boolean,
	 .fp_compute = kv_compute_boolean_or,
	 .fp_compute_check = kv_check_compute_boolean_or}
	,
	/* ISCSI_KEY_SESS_DATA_SEQUENCE_ORDER */
	{
	 .name = "DataSequenceInOrder",
	 .vtype = ISCSI_VALUE_TYPE_BOOLEAN,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_TARGET |
		      ISCSI_KEY_SENDER_ALL_CONFIG |
		      ISCSI_KEY_STAGE_LOGIN_OPERATIONAL |
		      ISCSI_KEY_IRRELEVANT_IN_DISCOVERY |
		      ISCSI_KEY_HAS_DEFAULT | ISCSI_KEY_DISPLAY_MODE_DETAIL),
	 .val_dflt = 1,
	 .fp_decode = kv_decode_boolean,
	 .fp_encode = kv_encode_boolean,
	 .fp_size = kv_size_boolean,
	 .fp_compute = kv_compute_boolean_or,
	 .fp_compute_check = kv_check_compute_boolean_or}
	,
	/* ISCSI_KEY_SESS_ERROR_RECOVERY_LEVEL */
	{
	 .name = "ErrorRecoveryLevel",
	 .vtype = ISCSI_VALUE_TYPE_NUMERIC,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_TARGET |
		      ISCSI_KEY_SENDER_ALL_CONFIG |
		      ISCSI_KEY_STAGE_LOGIN_OPERATIONAL |
		      /* ISCSI_KEY_CHANGABLE | */
		      ISCSI_KEY_HAS_DEFAULT | ISCSI_KEY_HAS_MIN |
		      ISCSI_KEY_HAS_MAX | ISCSI_KEY_DISPLAY_MODE_DETAIL),
	 .val_dflt = 0,
	 .val_min = 0,
	 .val_max = 2,
	 .fp_decode = kv_decode_number,
	 .fp_encode = kv_encode_number,
	 .fp_size = kv_size_number,
	 .fp_compute = kv_compute_number_min,
	 .fp_compute_check = kv_check_compute_number_min}
	,
	/* ISCSI_KEY_SESS_SESSION_TYPE */
	{
	 .name = "SessionType",
	 .vtype = ISCSI_VALUE_TYPE_TEXT,
	 .property = (ISCSI_KEY_SENDER_INITIATOR |
		      ISCSI_KEY_SENDER_INITIATOR_CONFIG |
		      ISCSI_KEY_STAGE_ALL |
		      ISCSI_KEY_DECLARATIVE | ISCSI_KEY_HAS_DEFAULT),
	 .val_dflt = ISCSI_SESSION_TYPE_NORMAL,
	 .fp_decode = kv_decode_session_type,
	 .fp_encode = kv_encode_session_type,
	 .fp_size = kv_size_session_type}
};

/*
 * session keys API
 */

int iscsi_session_keys_validate_value(iscsi_keyval *kvlist, char *ebuf, int ebuflen)
{
	iscsi_keyval *kvp, *kvp2;
	unsigned int firstburst, maxburst;

	/* check for NOT supported value */
	kvp = kvlist + ISCSI_KEY_SESS_DATA_SEQUENCE_IN_ORDER;
	if (kvp->kv_valp && (kvp->kv_valp->v_num[0] == 0)) {
		if (ebuf)
			sprintf(ebuf, "%s=No NOT supported.\n", kvp->kv_name);
		os_log_info("%s=No NOT supported.\n", kvp->kv_name);
		return -ISCSI_EINVAL;
	}

	kvp = kvlist + ISCSI_KEY_SESS_DATA_PDU_IN_ORDER;
	if (kvp->kv_valp && (kvp->kv_valp->v_num[0] == 0)) {
		if (ebuf)
			sprintf(ebuf, "%s=No NOT supported.\n", kvp->kv_name);
		os_log_info("%s=No NOT supported.\n", kvp->kv_name);
		return -ISCSI_EINVAL;
	}

	kvp = kvlist + ISCSI_KEY_SESS_ERROR_RECOVERY_LEVEL;
	if (kvp->kv_valp && (kvp->kv_valp->v_num[0] > 0)) {
		if (ebuf)
			sprintf(ebuf, "%s > 0 NOT supported.\n", kvp->kv_name);
		os_log_info("%s > 0 NOT supported.\n", kvp->kv_name);
		return -ISCSI_EINVAL;
	}

	/* first burst <= max burst */
	kvp = kvlist + ISCSI_KEY_SESS_FIRST_BURST_LENGTH;
	firstburst =
		kvp->kv_valp ? kvp->kv_valp->v_num[0] : kvp->kv_def->val_dflt;

	kvp2 = kvlist + ISCSI_KEY_SESS_MAX_BURST_LENGTH;
	maxburst =
		kvp2->kv_valp ? kvp2->kv_valp->v_num[0] : kvp2->kv_def->
		val_dflt;

	if (firstburst > maxburst) {
		if (ebuf)
			sprintf(ebuf, "%s=%u > %s=%u.\n", kvp->kv_name,
				firstburst, kvp2->kv_name, maxburst);
		os_log_info("%s=%u > %s=%u.\n", kvp->kv_name, firstburst,
			    kvp2->kv_name, maxburst);
		return -ISCSI_EINVAL;
	}

	return 0;
}

int iscsi_get_session_key_settings(struct iscsi_session_settings *setting,
				iscsi_keyval *kvlist)
{
	unsigned int val;
	int rv;

	rv = iscsi_kvlist_get_value_by_index(
			ISCSI_KEY_SESS_ERROR_RECOVERY_LEVEL,
			kvlist, iscsi_keydef_session_tbl, &val);
        if (rv < 0)
                return rv;
	setting->erl = val;

	rv = iscsi_kvlist_get_value_by_index(ISCSI_KEY_SESS_DEFAULT_TIME2WAIT,
			kvlist, iscsi_keydef_session_tbl,
			&setting->time2wait);
        if (rv < 0)
                return rv;

	rv = iscsi_kvlist_get_value_by_index(ISCSI_KEY_SESS_DEFAULT_TIME2RETAIN,
			kvlist, iscsi_keydef_session_tbl,
			&setting->time2retain);
        if (rv < 0)
                return rv;

	rv = iscsi_kvlist_get_value_by_index(ISCSI_KEY_SESS_MAX_CONNECTIONS,
			kvlist, iscsi_keydef_session_tbl,
			&setting->max_conns);
        if (rv < 0)
                return rv;


	rv = iscsi_kvlist_get_value_by_index( ISCSI_KEY_SESS_INITIAL_R2T,
			kvlist, iscsi_keydef_session_tbl, &val);
        if (rv < 0)
                return rv;
	setting->initial_r2t = val ? 1 : 0;

	rv = iscsi_kvlist_get_value_by_index(ISCSI_KEY_SESS_IMMEDIATE_DATA,
			kvlist, iscsi_keydef_session_tbl, &val);
        if (rv < 0)
                return rv;
	setting->immediate_data = val ? 1 : 0;

	rv = iscsi_kvlist_get_value_by_index(ISCSI_KEY_SESS_MAX_OUTSTANDING_R2T,
			kvlist, iscsi_keydef_session_tbl,
			&setting->max_r2t);
        if (rv < 0)
                return rv;


	rv = iscsi_kvlist_get_value_by_index(ISCSI_KEY_SESS_FIRST_BURST_LENGTH,
			kvlist, iscsi_keydef_session_tbl,
			&setting->first_burst);
        if (rv < 0)
                return rv;

	rv = iscsi_kvlist_get_value_by_index(ISCSI_KEY_SESS_MAX_BURST_LENGTH,
			kvlist, iscsi_keydef_session_tbl,
			&setting->max_burst);
        if (rv < 0)
                return rv;

	rv = iscsi_kvlist_get_value_by_index(ISCSI_KEY_SESS_DATA_PDU_IN_ORDER,
			kvlist, iscsi_keydef_session_tbl, &val);
        if (rv < 0)
                return rv;
	setting->data_pdu_in_order = val ? 1 : 0;

	rv = iscsi_kvlist_get_value_by_index(
			ISCSI_KEY_SESS_DATA_SEQUENCE_IN_ORDER,
			kvlist, iscsi_keydef_session_tbl, &val);
        if (rv < 0)
                return rv;
	setting->data_sequence_in_order = val ? 1 : 0;

	if (setting->first_burst > setting->max_burst)
		setting->first_burst = setting->max_burst;

	return 0;
}
