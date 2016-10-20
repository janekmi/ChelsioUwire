/*
 * config.c  
 */
#include <common/os_export.h>
#include <security/iscsi_auth_private.h>
#include <iscsi_target_api.h>
#include <iscsi_node.h>
#include <iscsi_global.h>
#include "iscsi_target_private.h"


/* display of iscsi_info.h structures */

int chiscsi_session_settings_sprintf(struct iscsi_session_settings *setting,
				char *buf)
{
	int len = 0;

	len += sprintf(buf + len, "\tErrorRecoveryLevel=%u\n", setting->erl);
	len += sprintf(buf + len, "\tInitialR2T=%s\n",
			setting->initial_r2t ? "Yes" : "No");
	len += sprintf(buf + len, "\tImmediateData=%s\n",
			setting->immediate_data ? "Yes" : "No");
	len += sprintf(buf + len, "\tDataPDUInOrder=%s\n",
			setting->data_pdu_in_order ? "Yes" : "No");
	len += sprintf(buf + len, "\tDataSequenceInOrder=%s\n",
			setting->data_sequence_in_order ? "Yes" : "No");
	len += sprintf(buf + len, "\tMaxConnections=%u\n", setting->max_conns);
	len += sprintf(buf + len, "\tMaxOutstandingR2T=%u\n", setting->max_r2t);
	len += sprintf(buf + len, "\tFirstBurstLength=%u\n",
			setting->first_burst);
	len += sprintf(buf + len, "\tMaxBurstLength=%u\n", setting->max_burst);
	len += sprintf(buf + len, "\tDefaultTime2Wait=%u\n",
			setting->time2wait);
	len += sprintf(buf + len, "\tDefaultTime2Retain=%u\n",
			setting->time2retain);
	
	buf[len] = '\0';
	return len;
}

static int digests_sprintf(unsigned char *setting, char *buf)
{
	int i;
	int len = 0;

	for (i = 0; i < 2 && setting[i]; i++) {
		if (setting[i] == ISCSI_DIGEST_NONE)
			len += sprintf(buf + len, "None,");
		else if (setting[i] == ISCSI_DIGEST_CRC32C)
			len += sprintf(buf + len, "CRC32C,");
		else
			len += sprintf(buf + len, "0x%x,", setting[i]);
	}
	len--;
	return len;
}

int chiscsi_conn_settings_sprintf(struct iscsi_conn_settings *setting,
				char *buf)
{
	int len;

	len = sprintf(buf, "\tHeaderDigest=");
	len += digests_sprintf(setting->header_digest, buf + len);
	len += sprintf(buf + len, "\n\tDataDigest=");
	len += digests_sprintf(setting->data_digest, buf + len);
	len += sprintf(buf + len, "\n\tMaxRecvDataSegmentLength=%u\n",
			setting->max_recv_data_segment);
#if 0
	len += sprintf(buf + len, "\tPortalGroupTag=%u\n",
			setting->portal_group_tag);
	len += sprintf(buf + len, "\tMaxXmitDataSegmentLength=%u\n",
			setting->max_xmit_data_segment);
#endif
	buf[len] = '\0';
	return len;
}

int chiscsi_chap_settings_sprintf(struct iscsi_chap_settings *setting,
				char *buf)
{
	int len = 0;

	if (setting->chap_en) {
		if (setting->chap_required)
			len += sprintf(buf + len, "\tAuthMethod=CHAP\n");
		else
			len += sprintf(buf + len, "\tAuthMethod=None,CHAP\n");

		len += sprintf(buf + len, "\tAuth_CHAP_Policy=%s\n",
			setting->mutual_chap_forced ? "Mutual" : "Oneway");
		
		len += sprintf(buf + len, "\tAuth_CHAP_ChallengeLength=%u\n",
			setting->challenge_length);
	} else
		len += sprintf(buf + len, "\tAuthMethod=None\n");
	buf[len] = '\0';
	return len;
}

int chiscsi_target_config_settings_sprintf(
				struct iscsi_target_config_settings *setting,
				char *buf)
{
	int len;

	len = sprintf(buf, "\tACL_Enable=%s\n", setting->acl_en ? "Yes" : "No");
	len += sprintf(buf + len, "\tRegisteriSNS=%s\n",
			setting->isns_register ? "Yes" : "No");
	len += sprintf(buf + len, "\tShadowMode=%s\n",
			setting->shadow_mode ? "Yes" : "No");
	len += sprintf(buf + len, "\tTargetSessionMaxCmd=%u\n",
			setting->sess_max_cmds);
	buf[len] = '\0';
	return len;
}

int chiscsi_target_info_sprintf(struct chiscsi_target_info *setting, char *buf)
{
	int len;

	len = sprintf(buf, "\tTargetName=%s\n", setting->name);
	if (setting->alias[0])
		len += sprintf(buf + len, "\tTargetAlias=%s\n",
			setting->alias);
	len += chiscsi_session_settings_sprintf(&setting->sess_keys, buf + len);
	len += chiscsi_conn_settings_sprintf(&setting->conn_keys, buf + len);
	len += chiscsi_chap_settings_sprintf(&setting->chap, buf + len);
	len += chiscsi_target_config_settings_sprintf(&setting->config_keys,
			buf + len);
	buf[len] = '\0';
	return len;
}

int chiscsi_perf_info_sprintf(struct chiscsi_perf_info *perf, char *buf)
{
	int len;

	len = sprintf(buf, "\tRead bytes: %lu, Write bytes: %lu\n",
			perf->read_bytes, perf->write_bytes);
	len += sprintf(buf + len, "\tRead Cmd: %lu, Write Cmd: %lu\n",
			perf->read_cmd_cnt, perf->write_cmd_cnt);
	buf[len] = '\0';
	return len;
}
 
int chiscsi_session_info_sprintf(struct chiscsi_session_info *info, char *buf)
{
	int i;
	int len = 0;

	len += sprintf(buf + len, "\thndl: 0x%lx, SessionType=%s\n",
		info->hndl, info->type == ISCSI_SESSION_TYPE_NORMAL ?
		"Normal" : "Discovery");
	len += sprintf(buf + len, "\tInitiatorName=%s\n", info->peer_name);
	if (info->peer_alias[0])
		len += sprintf(buf + len, "\tInitiatorAlias=%s\n",
				info->peer_alias);
	len += sprintf(buf + len, "\tISID: 0x");
	for (i = 0; i < 6; i++)
		len += sprintf(buf + len, "%02x", info->isid[i]);
	len += sprintf(buf + len, ", TSIH: 0x%x\n", info->tsih);

	len += sprintf(buf + len,
			"\tcmdsn: %u (0x%x), exp. %u (0x%x), max %u (0x%x)\n",
		 	info->cmdsn, info->cmdsn, info->expcmdsn,
			info->expcmdsn, info->maxcmdsn, info->maxcmdsn);
	len += sprintf(buf + len, "\tconns: %u\n", info->conn_cnt);

	len += chiscsi_session_settings_sprintf(&info->sess_keys, buf + len);
	len += chiscsi_perf_info_sprintf(&info->perf, buf + len);

	buf[len] = '\0';
	return len;
}

int chiscsi_connection_info_sprintf(struct chiscsi_connection_info *info,
				char *buf)
{
	int len = 0;

	len += sprintf(buf + len,
			"\thndl: 0x%lx, CID %u, offloaded %u, statsn %u,%u.\n",
			info->hndl, info->cid, info->offloaded,
			info->statsn, info->expstatsn);

	len += sprintf(buf + len, "\t");
	len += chiscsi_tcp_endpoints_sprintf(&info->tcp_endpoints, buf + len);

	len += sprintf(buf + len, "\n");
	len += chiscsi_conn_settings_sprintf(&info->conn_keys, buf + len);

	buf[len] = '\0';
	return len;
}

int chiscsi_portal_info_sprintf(struct chiscsi_portal_info *info, char *buf)
{
	int len;

	len = tcp_endpoint_sprintf(&info->ep, buf);
	len += sprintf(buf + len, ", flag 0x%x\n", info->flag);
	len += chiscsi_perf_info_sprintf(&info->perf, buf + len);

	buf[len] = '\0';
	return len;
}

#ifdef __API_DEBUG__
static void dump_buffers(char *target_name, char *buffer, int buflen)
{
        os_log_info("target_name 0x%p, buffer 0x%p buflen %d.\n",
                    target_name, buffer, buflen);
        if (target_name)
                os_log_info("   target_name: %s.\n", target_name);
        if (buffer)
                os_log_info("   buffer: %s.\n", buffer);
}
#else
#define dump_buffers(t,b,l)
#endif

STATIC int check_buffers(char *node_name, char *buffer, int buflen) 
{
       /*make sure targetname and the buffer are present*/
       if (!node_name) {
               os_log_info("Missing target name\n", "");
               return -ISCSI_ENONAME;
       }

       if (!buffer || !buflen ) {
               os_log_info("Empty parameter list buffer\n", "");
               return -ISCSI_ENOBUF;
       }

       dump_buffers(target_name, buffer, buflen);
        
       if (!os_strlen(buffer)) {
               os_log_info("Missing key=value parameter list\n", "");
               return -ISCSI_EFORMAT;
       }

       return 0;
}

int chiscsi_target_remove(void *target_priv, char *target_name)
{
	iscsi_node *node;

	if (!target_name) {
		os_log_info("Missing target name\n", "");
		return -ISCSI_ENONAME;
	}

	node =  iscsi_node_find_by_name(target_name);
	if (!node) {
		os_log_info("Target \"%s\" not found!\n", target_name);
		return -ISCSI_ENOTFOUND;
	}
	return (iscsi_node_remove(node, 0, NULL, 0));
}

int chiscsi_target_add(void *target_priv, char *target_name,
		       char *target_class_name, char *buffer, int buflen)
{
	iscsi_node *node;
	chiscsi_target_class *tclass;
	int rv;
	
	if (!target_name) {
		os_log_error("Missing target name\n", "");
		return -ISCSI_ENONAME;
	}

	check_buffers(target_name, buffer, buflen);

	tclass = iscsi_target_class_find_by_name(target_class_name);
	if (!tclass) {
		os_log_error("Target class \"%s\" dose not exists!\n", target_class_name);
		return -ISCSI_EINVAL;
	}

	node = iscsi_node_find_by_name(target_name);
	if (node) {
		os_log_error("Target \"%s\" exists!\n", target_name);
		return -ISCSI_EINVAL;
	}
	
	rv = iscsi_node_add( buffer, buflen, NULL, 0, tclass);
	
	if (rv < 0)
		return rv;

	return 0;
}

int chiscsi_target_reconfig(void *target_priv, char *target_name, 
			char *target_class_name, char *buffer, int buflen)
{
	iscsi_node *node;
	chiscsi_target_class *tclass;
	int rv;

	if (!target_name) {
		os_log_error("Missing target name\n", "");
		return -ISCSI_ENONAME;
	}

	check_buffers(target_name, buffer, buflen);
	
	tclass = iscsi_target_class_find_by_name(target_class_name);
	if (!tclass) {
		os_log_error("Target class \"%s\" does not exists!\n", 
			target_class_name);
		return -ISCSI_EINVAL;
	}

	node = iscsi_node_find_by_name(target_name);
	if (!node) {
		os_log_error("Target \"%s\" does not exists!\n", target_name);
		return -ISCSI_EINVAL;
	} 

	rv  = iscsi_node_reconfig( node, buffer, buflen, NULL, 0, tclass);
	
	if (rv < 0)
		return rv;

	return 0;
}
		
int chiscsi_target_session_abort(unsigned long sess_hndl)
{
	iscsi_session *sess = (iscsi_session *)sess_hndl;

	if (!sess) 
		return -ISCSI_EINVAL;
	iscsi_sess_flag_set(sess, SESS_FLAG_CLOSE_BIT);
	iscsi_schedule_session(sess);
	return 0;
}

int chiscsi_get_connection_info(unsigned long sess_hndl, int conn_idx,
                                 struct chiscsi_connection_info *conn_info)
{
	iscsi_session *sess = (iscsi_session *)sess_hndl;
	chiscsi_queue *connq;
	iscsi_connection *conn;
	int i;

	if (!sess)
		return -ISCSI_EINVAL;

	connq = sess->s_queue[SESS_CONNQ];
	conn = connq->q_head;

	if (!conn)
		return -ISCSI_EINVAL;

	for (i = 0; conn && (i < connq->q_cnt); i++, conn = conn->c_next) {
		if (i == conn_idx)
			break;
	}
	if (!conn) {
		os_log_error("%s: NO matching conn_idx %d found.\n", conn_idx);
		return -ISCSI_EINVAL;
	}

	conn_info->cid = conn->c_cid;
	conn_info->expstatsn = conn->c_expstatsn;
	conn_info->statsn = conn->c_statsn;
	conn_info->hndl = (unsigned long)conn;

	if (conn->c_offload_mode &&
	    conn->c_offload_mode != ISCSI_OFFLOAD_MODE_NIC)
		conn_info->offloaded = 1;

	memcpy(&conn_info->tcp_endpoints, &conn->c_isock->s_tcp,
		sizeof(struct chiscsi_tcp_endpoints));

	conn_info->conn_keys.portal_group_tag = sess->s_portalgrouptag;
	conn_info->conn_keys.max_recv_data_segment = conn->c_pdudatalen_rmax;
	conn_info->conn_keys.max_xmit_data_segment = conn->c_pdudatalen_tmax;
	conn_info->conn_keys.header_digest[0] = conn->c_hdigest_len ?
				ISCSI_DIGEST_CRC32C : ISCSI_DIGEST_NONE;
	conn_info->conn_keys.data_digest[0] = conn->c_ddigest_len ?
				ISCSI_DIGEST_CRC32C : ISCSI_DIGEST_NONE;

	return 0;
}


int chiscsi_get_one_session_info(void *sess_ptr,
                        struct chiscsi_session_info *sess_info)
{
	iscsi_session *sess;
	chiscsi_queue *connq;

	if (!sess_ptr)
		return -ISCSI_EINVAL;

	sess = (iscsi_session *)sess_ptr;
	sess_info->hndl = (unsigned long)sess;
	os_strcpy(sess_info->peer_name, sess->s_peer_name);
	sess_info->peer_alias[0] = '\0';

	connq = sess->s_queue[SESS_CONNQ];
	sess_info->conn_cnt = connq->q_cnt;

	memcpy(sess_info->isid, sess->s_isid, 6);

	sess_info->type = sess->s_type;
	sess_info->tsih = sess->s_tsih;
	sess_info->maxcmdsn = sess->s_maxcmdsn;
	sess_info->expcmdsn = sess->s_expcmdsn;

	memcpy(&sess_info->sess_keys, &sess->setting,
		sizeof(struct iscsi_session_settings));	
	memcpy(&sess_info->perf, &sess->s_perf_info,
		sizeof(struct chiscsi_perf_info));
	
	return 0;
}

int chiscsi_get_session_info (char *target_name, char *init_name,
		int sess_info_max, struct chiscsi_session_info *sess_info_list)
{
	iscsi_node *node;
	iscsi_session *sess;
	chiscsi_queue *q, *connq;
	struct chiscsi_session_info *info = sess_info_list;
	int i = 0;

	if (sess_info_max <= 0) {
		os_log_info("session_info, %s session %d.\n",
				target_name, sess_info_max);
		return -ISCSI_EINVAL;
	}

	if (!target_name)
		return -ISCSI_EINVAL;

	node = iscsi_node_find_by_name(target_name);
	if (!node)
		return -ISCSI_EINVAL;

	q = node->n_queue[NODE_SESSQ];
	sess = q->q_head;
	if (!sess)
		return 0;
	
	for (i = 0, sess = q->q_head; sess; sess = sess->s_next) {
		if (!init_name || !os_strcmp(init_name, sess->s_peer_name)) {
			info->hndl = (unsigned long)sess;
			info->peer_alias[0] = '\0';
			os_strcpy(info->peer_name, sess->s_peer_name);
			
			connq = sess->s_queue[SESS_CONNQ];
			info->conn_cnt = connq->q_cnt;

			memcpy(info->isid, sess->s_isid, 6);

			info->type = sess->s_type;
			info->tsih = sess->s_tsih;
			info->maxcmdsn = sess->s_maxcmdsn;
			info->expcmdsn = sess->s_expcmdsn;

			memcpy(&info->sess_keys, &sess->setting,
				sizeof(struct iscsi_session_settings));
			memcpy(&info->perf, &sess->s_perf_info,
				sizeof(struct chiscsi_perf_info));

			i++;
			info++;
		}

		if (i >= sess_info_max)
			break;
	}

	return i;
}

int chiscsi_get_target_info(char *target_name,
			struct chiscsi_target_info *target_info)
{
	iscsi_node *node;
	int rv;

	if (!target_name) {
		os_log_info( "missing target name.\n","");
		return -ISCSI_ENONAME;
	}

	node = iscsi_node_find_by_name(target_name);
	if (!node) {
		os_log_info("Target %s not found!!\n", target_name);
		return -ISCSI_ENOTFOUND;
	}

	target_info->hndl = (unsigned long)node;
	os_strcpy (target_info->name, node->n_name);

	/* alias name */
	if (node->n_alias)
		os_strcpy(target_info->alias, node->n_alias);
	else
		target_info->alias[0] = '\0';

	memcpy(&target_info->sess_keys, &node->sess_keys,
		sizeof(struct iscsi_session_settings));
	memcpy(&target_info->conn_keys, &node->conn_keys,
		sizeof(struct iscsi_conn_settings));
	memcpy(&target_info->chap, &node->chap,
		sizeof(struct iscsi_chap_settings));

	if (iscsi_auth_order == ISCSI_AUTH_ORDER_CHAP_FIRST)
		target_info->auth_order = AUTH_METHOD_CHAP;

        /* Config key settings */
        rv = iscsi_get_target_config_key_settings (&target_info->config_keys,
                                        node->n_keys[NODE_KEYS_CONFIG]);

        if (rv < 0)
                return rv;

	return 0;
}

