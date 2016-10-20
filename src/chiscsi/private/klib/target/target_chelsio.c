#include <common/version.h>
#include <common/iscsi_target_device.h>
#include <common/iscsi_scst.h>
#include <common/iscsi_target_notif.h>
#include <iscsi_target_api.h>
#include "iscsi_target_private.h"

static int config_parse_luns(chiscsi_target_lun *lu, char *buf, int buflen,
			     char *ebuf)
{
	/* parse chelsio configuration key "TargetDevice": 
	 *	"TargetDevice" = <path/id>[options/lun class]
	 *		common options:
	 *			- RO
	 *			- NULLRW
	 *			- SYNC
	 *			- ScsiID
	 *			- WWN
	 */
	iscsi_node *node = (iscsi_node *)lu->tnode_hndl;
	chiscsi_target_class *tclass = node->tclass;
	chiscsi_target_lun_class *lclass = NULL;
	char *path;
	char *s;
	int plen;
	unsigned int flags = 0;
	int options = 0;
	int i, rv = 0;

	/* break the buffer into tokens */
	for(s = buf; *s; s++)
		if (*s == ',')
			*s = '\0';

	/* save the path/id */
	plen = os_strlen(buf);
	path = buf;

	/*
	 * check for lun class and common options:
	 * - RO
	 * - NULLRW
	 * - WWN
	 * - ScsiID
	 * - PROD
	 * - PSMODE, passthru mode
	 */
	for (i = plen + 1; i < buflen; ) {
		char *s = buf + i;
		int slen = os_strlen(s);
		int match = 1;
		i += slen + 1;

		if (!slen)
			continue;

		if (!lclass) {
			lclass = chiscsi_target_lun_class_find_by_name(1,
						tclass, s);
			if (lclass) {
				memset(s, 0, slen);
				continue;
			}
		}

		if (!os_strcmp(s, "RO")) {
			flags |= 1 << LUN_RO_BIT;
		} else if (!os_strcmp(s, "NULLRW")) {
			flags |= 1 << LUN_NULLRW_BIT;
		} else if (!os_strcmp(s, "SYNC")) {
			flags |= 1 << LUN_SYNC_BIT;
		} else if (!os_strcmp(s, "NONEXCL")) {
			flags |= 1 << LUN_NONEXCL_BIT;
		} else if (!os_strcmp(s, "NOWCACHE")) {
			flags |= 1 << LUN_NOWCACHE_BIT;
		} else if (!os_strcmp(s, "DIX")) {
			flags |= 1 << LUN_T10DIX_BIT;
		} else if (!os_strcmp(s, "DIF")) {
			flags |= 1 << LUN_T10DIX_BIT;
			flags |= 1 << LUN_T10DIF_BIT;
		} else if (!os_strncmp(s, "SN=", 3)) {
			os_strcpy(lu->scsi_sn, s + 3);	
		} else if (!os_strncmp(s, "ID=", 3)) {
			os_strcpy(lu->scsi_id, s + 3);	
		} else if (!os_strncmp(s, "WWN=", 4)) {
			os_strcpy(lu->scsi_wwn, s + 4);	
		} else if (!os_strncmp(s, "PROD=", 5)) {
			os_strcpy(lu->prod_id, s + 5);
		} else if (!os_strncmp(s, "PSMODE=", 7)) {
			unsigned long v = os_strtoul(s + 7, NULL, 0);

			if (v == 1)
				flags |= 1 << LUN_PASSTHRU_UNKNOWN_ONLY_BIT;
			else if (v == 2)
				flags |= 1 << LUN_PASSTHRU_ALL_BIT;
			else if (v) {
				os_log_error("%s, Unknown %s.\n",
						path, s);
				if (ebuf)
					sprintf(ebuf, "%s, Unknown %s.\n",
						path, s);
				rv = -ISCSI_EFORMAT;
				goto out;
			}
		} else {
			options++;
			match = 0;
		}
		if (match) /* match found */
			memset(s, 0, slen);
	}

	if (!lclass) {
		lclass = chiscsi_target_lun_class_default(tclass);
		if (!lclass) {
			os_log_error("%s, Unknown lun type.\n", buf);
			if (ebuf)
				sprintf(ebuf, "%s, Unknown lun type.\n", buf);
			rv = -ISCSI_EFORMAT;
			goto out;
		}
	}

	lu->path = os_strdup(path);
	if (!lu->path) {
		rv = -ISCSI_ENOMEM;
		goto out;
	}
	lu->class = lclass;
	lu->flags = flags;

	if (options) {
		if (lclass->fp_config_parse_options) {
			rv = lclass->fp_config_parse_options(lu, 
							 buf + plen + 1,
							 buflen - plen, ebuf);
		} else {
			/* no extra options */
			os_log_error("%s: Unknown options for %s luns.\n", 
					buf, lclass->class_name);
			if (ebuf)
				sprintf(ebuf, "%s: Unknown options for %s luns.\n", 
					buf, lclass->class_name);
			rv = -ISCSI_EINVAL;
		}
	}

out:
	return rv;
}

#ifdef __ISCSI_SCST__
static void first_login_check(unsigned long hndl, char *initiator_name,
		char *target_name, chiscsi_tcp_endpoints *eps)
{
	iscsi_connection *conn = (iscsi_connection *)hndl;
	iscsi_session *sess = conn->c_sess;
	iscsi_node *node = sess->s_node;

	/* scst luns are currently restricted to queue depth of 32. */
	if (node->scst_target)
		chiscsi_target_first_login_check_done(hndl, 0, 0, 32);
	else
		chiscsi_target_first_login_check_done(hndl, 0, 0, 0);
}
#endif

static void login_stage_acl_check(unsigned long hndl, unsigned char login_stage,
				  char *initiator_name, char *target_name,
				  chiscsi_tcp_endpoints *eps)
{
	iscsi_connection *conn = (iscsi_connection *)hndl;
	iscsi_session *sess = conn->c_sess;
	iscsi_node *node = sess->s_node;
	unsigned char status_class = 0;
	unsigned char status_detail = 0; 
		
	if (!node) {
		status_class = ISCSI_LOGIN_STATUS_CLASS_INITIATOR_ERROR;
		status_detail = ISCSI_LOGIN_STATUS_DETAIL_TARGET_NOT_FOUND;
		goto done;
	} 

	if (!iscsi_node_acl_enable(node) ||
	    (iscsi_conn_flag_test(conn, CONN_FLAG_AUTH_ACL_BIT)))
		goto done; 
	

	if ((iscsi_auth_order == ISCSI_AUTH_ORDER_ACL_FIRST) ||
	    (login_stage == ISCSI_LOGIN_STAGE_OPERATIONAL)) {
		if (iscsi_acl_connection_check(conn) < 0) {
			os_log_error("%s - %s ACL check failed.\n",
				     initiator_name, target_name);
			os_chiscsi_notify_event(CHISCSI_ACL_DENY,
					"Initiator:%s, Target:%s", initiator_name, target_name);
			status_class = ISCSI_LOGIN_STATUS_CLASS_INITIATOR_ERROR; 
			status_detail = ISCSI_LOGIN_STATUS_DETAIL_INIT_ERROR;
		}
	}
done:
	chiscsi_target_login_stage_check_done(hndl, status_class, status_detail);
}

#ifdef __ISCSI_SCST__
static unsigned long session_added(unsigned long hndl, unsigned char isid[6],
			  char *initiator_name, char *target_name)
{
	iscsi_session *sess = (iscsi_session *)hndl;
	iscsi_node *node = sess->s_node;

	if (node->scst_target) {
		sess->scst_session = iscsi_scst_reg_session(node->scst_target,
				initiator_name);
		os_log_info("scst sess %p logged in\n", sess->scst_session);
	}

	return 0UL;
}

static void session_removed(unsigned long hndl, char *initiator_name,
			    char *target_name)
{
	struct iscsi_session *sess = (struct iscsi_session *)hndl;

	if (sess->scst_session) {
		os_log_info("scst sess %p logging out\n", sess->scst_session);
		iscsi_scst_unreg_session(sess->scst_session);
		sess->scst_session = NULL;
	}

	return;
}
#endif

static int select_redirect_portal(char *tname, char *iname,
				chiscsi_tcp_endpoints *eps)
{
	iscsi_node *node = iscsi_node_find_by_name(tname);
	iscsi_target_portal *fp = NULL, *tp = NULL;
	char *tbuf = NULL;
	int last_select;
	int len;
	int i, j;

	tbuf = os_alloc(512, 1, 1);
	if (!tbuf) {
		return -ISCSI_ENOMEM;
	}

	len = chiscsi_tcp_endpoints_sprintf(eps, tbuf);
	if (!node) {
		os_log_info("%s: target NOT found.\n", tname);
		return -ISCSI_EINVAL;
	}
	
	for (i = 0; i < node->portal_cnt; i++) {
		fp = node->portal_list + i;

		if ((fp->flag & ISCSI_PORTAL_FLAG_REDIRECT_FROM) &&
		    !(memcmp(&eps->taddr, &fp->ep,
				sizeof(struct tcp_endpoint))))
			break;		
	}

	if (!fp) {
		os_log_info("%s: no matching portal found %s.\n",
				node->n_name, tbuf);
		return -ISCSI_EINVAL;
	}

	last_select = fp->redirect_last_select;
	last_select++;
	if (last_select >= node->portal_cnt)
		last_select = 1;
	fp->redirect_last_select = last_select;

	for (i = 0; i < fp->redirect_to_ntags; i++) {
		for (j = 0; j < node->portal_cnt; j++) {
			tp = node->portal_list + j;
	
			if ((tp->flag & ISCSI_PORTAL_FLAG_REDIRECT_TO) &&
		     		tp->grouptag == fp->redirect_to_list[i]) {
				tp->redirect_last_select = last_select;
			}
		}
	}

	do {
		for (i = 0; i < fp->redirect_to_ntags; i++) {
			for (j = 0; j < node->portal_cnt; j++) {
				tp = node->portal_list + j;
	
				if ((tp->flag & ISCSI_PORTAL_FLAG_REDIRECT_TO)
					&&
				     tp->grouptag == fp->redirect_to_list[i]) {
					last_select--;
					if (!last_select)
						break;
				}
			}
			if (!last_select)
				break;
		}
	} while (last_select);

	memcpy(&eps->taddr, &tp->ep, sizeof(struct tcp_endpoint));

	len += sprintf(tbuf + len, " -> ");
	tcp_endpoint_sprintf(&eps->taddr, tbuf + len);
	os_log_info("%s: redirect %s.\n", node->n_name, tbuf);

	if (tbuf)
		os_free(tbuf);

	return 0;
}

chiscsi_target_class tclass_chelsio = {
	.class_name = CHELSIO_TARGET_CLASS,	
	.property = 0,
	.fp_config_parse_luns = config_parse_luns,
#ifdef __ISCSI_SCST__
	.fp_first_login_check = first_login_check,
	.fp_session_removed = session_removed,
	.fp_session_added = session_added,
#else
	.fp_first_login_check = NULL,
	.fp_session_removed = NULL,
	.fp_session_added = NULL,
#endif
	.fp_login_stage_check = login_stage_acl_check,
	.fp_chap_info_get = NULL,
	.fp_discovery_target_accessible = NULL,
	.fp_select_redirection_portal = select_redirect_portal, 
};
