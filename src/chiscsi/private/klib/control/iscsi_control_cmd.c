/* 
 * iscsi_control_cmd.c -- iSCSI control command handling
 */

#include <common/os_builtin.h>
#include <common/iscsi_common.h>
#include <common/iscsi_control.h>
#include <common/iscsi_lib_export.h>
#include <iscsi_control_defs.h>
#include <iscsi_structs.h>
#include <iscsi_global.h>
#include <iscsi_control_api.h>
#include <iscsi_node.h>
#include <iscsi_target_api.h>

//#define __CONTROL_DEBUG__

/*
 * Control Request Handler
 */
#define check_data_buffer_present(ebuf,dbuf,dbuflen)	\
		if (!dbuf || !dbuflen) {	\
			sprintf(ebuf, "Missing data buffer.\n"); \
			return -ISCSI_ENOBUF; \
		}
#define check_req_buffer_not_empty(ebuf,rbuf)	\
		if (!rbuf[0]) {	\
			sprintf(ebuf, "Empty request buffer.\n"); \
			return -ISCSI_ENOBUF; \
		}

#ifdef __CONTROL_DEBUG_ 
static void dump_request(int opcode, char *rbuf, char *ebuf, int ebuflen,
			 char *dbuf, int dbuflen)
{
	os_log_info("control req: %d, rbuf 0x%p, ebuf 0x%p, dbuf 0x%p %d.\n",
		    opcode, rbuf, ebuf, dbuf, dbuflen);
	if (rbuf)
		os_log_info("   rbuf: %s.\n", rbuf);
	if (dbuf)
		os_log_info("   dbuf: %s.\n", dbuf);
}
#endif


/**
 * iscsi_control_settings_get - system, get driver settings
 * @rbuf: not used
 * @ebuf -- result	
 * @dbuf -- not used
 */
static int iscsi_control_settings_get(int opcode, char *rbuf,
				      char *ebuf, int ebuflen, char *dbuf,
				      int dbuflen, unsigned int flag)
{
	iscsi_global_settings_display(ebuf, ebuflen, 0);
	return 0;
}

/**
 * iscsi_control_settings_set - system, set driver settings
 * @rbuf -- req, <key>=<val><null>
 * @ebuf -- error message
 * @dbuf -- not used
 */

extern int iscsi_config_disc_chap(iscsi_node *);
extern iscsi_node *it_target_dflt;
static int iscsi_control_settings_set(int opcode, char *rbuf,
				      char *ebuf, int ebuflen, char *dbuf,
				      int dbuflen, unsigned int flag)
{
	int     rc = 0;
	char   *ch, *key, *val;
	int	disc_auth_settings_changed = 0;

	check_req_buffer_not_empty(ebuf, rbuf);

	ch = rbuf;
	key = ch;
	for (; *ch && (*ch != '='); ch++) ;
	if (*ch)
		*ch = 0;
	else {
		if (ebuf)
			sprintf(ebuf, "Invalid key=value pair format %s\n",
				rbuf);
		return (-ISCSI_EFORMAT);
	}

	val = ch + 1;

	if (!os_strcmp(key, "iscsi_chelsio_ini_idstr")) {
		if (os_strlen(val) > ISCSI_ALIAS_LEN_MAX) {
			rc = -ISCSI_EINVAL;
			if (ebuf)
				sprintf(ebuf, "%s: length %d > max. %d.",
					val, (int) os_strlen(val),
					ISCSI_ALIAS_LEN_MAX);
		} else {
			os_strcpy(iscsi_chelsio_ini_idstr, val);
			os_log_info("%s -> %s.\n",
				key, iscsi_chelsio_ini_idstr);
		}
		return (rc);
	}

	if (!os_strcmp(key, "iscsi_target_vendor_id")) {
		if (os_strlen(val) > ISCSI_TARGET_VENDOR_ID_MAXLEN) {
			rc = -ISCSI_EINVAL;
			if (ebuf)
				sprintf(ebuf, "%s: length %d > max. %d.",
					val, (int) os_strlen(val),
					ISCSI_TARGET_VENDOR_ID_MAXLEN);
		} else {
			os_strcpy(iscsi_target_vendor_id, val);
			os_log_info("%s -> %s.\n", key, iscsi_target_vendor_id);
		}
		return (rc);
	}
	if (!os_strcmp(key, "iscsi_offload_mode")) {

		rc = iscsi_offload_mode_str2val(val);
		if (rc < 0) {
			if (ebuf)
				sprintf(ebuf,
					"Invalid %s, must be AUTO/ULP.\n",
					val);
		} else {
			iscsi_offload_mode = rc;
			os_log_info("%s -> %d.\n", key, iscsi_offload_mode);
		}
	} else if (!os_strcmp(key, "iscsi_login_complete_time")) {

		rc = os_strtoul(val, NULL, 0);
		if (rc < 0 || rc > 3600) {
			if (ebuf)
				sprintf(ebuf,
					"Invalid %s, must be 0 ~ 3600.\n",
					val);
		} else {
			iscsi_login_complete_time = rc;
			os_log_info("%s -> 0x%x.\n", key,
				iscsi_login_complete_time);
		}

	} else if (!os_strcmp(key, "iscsi_perf_params")) {

		rc = os_strtoul(val, NULL, 0);
		if (rc < 0) {
			if (ebuf)
				sprintf(ebuf,
					"Invalid %s, must be a hex integar.\n",
					val);
			os_log_info("%s=0x%x.\n", key, iscsi_perf_params);
		} else {
			iscsi_perf_params = rc;
			os_log_info("%s -> 0x%x.\n", key, iscsi_perf_params);
		}

	} else if (!os_strcmp(key, "iscsi_worker_policy")) {

		rc = iscsi_worker_policy_str2val(val);
		if (rc < 0) {
			if (ebuf)
				sprintf(ebuf,
					"Invalid %s, must be QSET/RR.\n",
					val);
			os_log_info("%s=%s.\n", key,
			   iscsi_worker_policy_val2str(iscsi_worker_policy));
		} else {
			iscsi_worker_policy = rc;
			os_log_info("%s -> %s.\n", key,
			   iscsi_worker_policy_val2str(iscsi_worker_policy));
		}

	} else if (!os_strcmp(key, "iscsi_HA_mode")) {

		rc = iscsi_boolean_str2val(val);
		if (rc < 0) {
			if (ebuf)
				sprintf(ebuf,
					"Invalid %s, must be Yes/No.\n",
					val);
		} else {
			iscsi_ha_mode = rc;
			os_log_info("%s -> %d.\n", key, iscsi_ha_mode);
		}

	} else if (!os_strcmp(key, "iscsi_auth_order")) {
		rc = iscsi_auth_order_str2val(val);
		if (rc < 0) {
			if (ebuf)
				sprintf(ebuf, "Invalid %s, must be ACL/CHAP.\n",
					val);
		} else {
			iscsi_auth_order = rc;
			os_log_info("%s -> %d.\n", key, iscsi_auth_order);
		}

	} else if (!os_strcmp(key, "iscsi_acl_order")) {
                rc = iscsi_acl_order_str2val(val);
                if (rc < 0) {
                        if (ebuf)
                                sprintf(ebuf, "Invalid %s, must be CONFIG/ISNS.\n",
                                        val);
                } else {
                        iscsi_acl_order = rc;
			os_log_info("%s -> %d.\n", key, iscsi_acl_order);
                }

	} else if (!os_strcmp(key, "iscsi_verbose_level")) {
		/* iscsi_verbose_level=<iscsi_msg_level>[,<iscsi_msg_debug_level>] */
		char   *v2 = NULL;

		/* check for comma */
		for (ch = val; *ch && (*ch != ','); ch++) ;
		if (*ch == ',') {
			*ch = '\0';
			v2 = ch + 1;
		}

		iscsi_msg_level = os_strtoul(val, NULL, 0);
		if (v2) {
			iscsi_msg_debug_level = os_strtoul(v2, NULL, 0);
			if (iscsi_msg_debug_level)
				iscsi_msg_level |= 1 << ISCSI_MSG_DEBUG;
		}

		if (ebuf)
			sprintf(ebuf, "iscsi_verbose_level=0x%x,0x%lx\n",
				iscsi_msg_level, iscsi_msg_debug_level);
#ifdef __UIT_PDTEST_CHECK__
	} else if (!os_strcmp(key, "pdtest_check")) {
		rc = os_strtoul(val, NULL, 0);
		if (rc != 0 && rc != 1) {
			rc = -ISCSI_EINVAL;
			if (ebuf)
				sprintf(ebuf,
					"please enter 0 or 1 for pdtest_check, %s.\n",
					rbuf);
		} else {
			pdtest_check = rc;
			if (ebuf)
				sprintf(ebuf, "pdtest_check=%d.\n",
						pdtest_check);
		}
		rc = 0;
	}
#endif
	} else if (!os_strcmp(key, "DISC_AuthMethod")) {
		rc = iscsi_disc_auth_str2val(val);
                
		if (rc < 0) {
			if (ebuf)
				sprintf(ebuf, "Invalid %s, must be None/CHAP.\n",
						val);
		} else {
			disc_auth_method = rc;
		}
		disc_auth_settings_changed = 1;
	} else if (!os_strcmp(key, "DISC_Auth_CHAP_Policy")) {
		rc = iscsi_disc_auth_policy_str2val(val);
	
		if (rc < 0) {
			if (ebuf)
				sprintf(ebuf, "Invalid %s, must be Oneway/Mutual.\n",
					val);
		} else {
			disc_auth_chap_policy = rc;
		}
		disc_auth_settings_changed = 1;
	} else if (!os_strcmp(key, "DISC_Auth_CHAP_Target")) {
		os_strcpy(disc_auth_chap_target, val);
		disc_auth_settings_changed = 1;
	} else if (!os_strcmp(key, "DISC_Auth_CHAP_Initiator")) {
		os_strcpy(disc_auth_chap_initiator, val);
		disc_auth_settings_changed = 1;
	} else if (!os_strcmp(key, "iscsi_test_mode")) {
		unsigned int value = os_strtoul(val, NULL, 0);
		if (ebuf)
			sprintf(ebuf, "iscsi_test_mode 0x%x -> 0x%x.\n",
				iscsi_test_mode, value);
		os_log_warn("iscsi_test_mode 0x%x -> 0x%x.\n",
				iscsi_test_mode, value);
		iscsi_test_mode = value;
	} else {
		if (ebuf)
			sprintf(ebuf, "Unknown variable %s.\n", key);
		rc = -ISCSI_EKEY;
	}
	if(disc_auth_settings_changed)
		iscsi_config_disc_chap(it_target_dflt);

	return (rc > 0 ? 0 : rc);
}

/**
 * iscsi_control_stats_get - system, get driver statistics
 * @rbuf -- not used
 * @ebuf -- result
 * @dbuf -- not used
 */
static int iscsi_control_stats_get(int opcode, char *rbuf,
				   char *ebuf, int ebuflen, char *dbuf,
				   int dbuflen, unsigned int flag)
{
	iscsi_stats_display(ebuf, ISCSI_CONTROL_REQ_MAX_BUFLEN);
	return (os_strlen(ebuf));
}

/**
 * iscsi_control_target_flush - target, flush data to disk
 * @rbuf -- req. <target name><null><lun string><null>
 *              *<target name> can be NULL or "ALL"
 * @ebuf -- error msg
 * @dbuf -- not used
 */
static int iscsi_control_target_flush(int opcode, char *rbuf, char *ebuf,
				int ebuflen, char *dbuf, int dbuflen,
				unsigned int flag)
{
	int     rv;
	char   *name = rbuf;

	if (rbuf)
		rbuf += os_strlen(rbuf) + 1;

	if (!name || !name[0] || !os_strcmp(name, "ALL")) {
		rv = iscsi_target_flush(NULL, rbuf, dbuf, dbuflen);
	} else {
		iscsi_node *node = iscsi_node_find_by_name(name);
		if (!node) {
			sprintf(ebuf, "target %s NOT found.\n", name);
			return -ISCSI_ENOTFOUND;
		}
		rv = iscsi_target_flush(node, rbuf, dbuf, dbuflen);
	}
	return rv;
}

/**
 * iscsi_control_node_get_names - target, retrieve all names
 * @rbuf -- not used
 * @ebuf -- error msg
 * @dbuf -- result, <name>,<name>,...
 */
static int iscsi_control_node_get_names(int opcode, char *rbuf, char *ebuf,
					int ebuflen, char *dbuf, int dbuflen,
					unsigned int flag)
{
	check_data_buffer_present(ebuf, dbuf, dbuflen);
	memset(dbuf, 0, dbuflen);

	return(iscsi_node_get_target_names(dbuf, dbuflen));
}

/**
 * iscsi_control_node_get_config - initiator/target, retrieve config
 * @rbuf -- req, < name><null>
 *		* <name> can be ALL.
 * @ebuf -- error msg
 * @dbuf -- result.
 */
static int iscsi_control_node_get_config(int opcode, char *rbuf, char *ebuf,
					int ebuflen, char *dbuf, int dbuflen,
					unsigned int flag)
{
	int     rv;
	int	detail = flag & ISCSI_CONTROL_FLAG_DETAIL ? 1 : 0;

	check_req_buffer_not_empty(ebuf, rbuf);
	check_data_buffer_present(ebuf, dbuf, dbuflen);
	memset(dbuf, 0, dbuflen);

	if (!os_strcmp(rbuf, "ALL")) {
		rv = iscsi_node_retrieve_config(NULL, dbuf, dbuflen, detail);
	} else {
		iscsi_node *node = iscsi_node_find_by_name(rbuf);

		if (!node) {
			sprintf(ebuf, "target %s NOT found.\n", rbuf);
			rv = -ISCSI_ENOTFOUND;
		} else
			rv = iscsi_node_retrieve_config(node, dbuf, dbuflen, detail);
	}

	return rv;
}

/**
 * iscsi_control_node_get_config_write - target, retrieve config to be written
 * or updated to the config file.
 * @rbuf -- req, < name><null>
 *		* <name> can be ALL.
 * @ebuf -- error msg
 * @dbuf -- result.
 */
static int iscsi_control_node_get_config_write(int opcode, char *rbuf,
					 char *ebuf, int ebuflen, char *dbuf,
					 int dbuflen, unsigned int flag)
{
	int     rv;

	rv = iscsi_control_node_get_config(opcode, rbuf, ebuf, ebuflen,
					dbuf, dbuflen, flag);
	return rv;
}
/**
 * iscsi_control_node_add - initiator/target, start
 * @rbuf -- req, <name><null>
 *		* <name> can NOT be ALL.
 * @ebuf -- error msg
 * @dbuf -- req, <initiator/target key-value pairs><null>
 */
static int iscsi_control_node_add(int opcode, char *rbuf, char *ebuf,
				int ebuflen, char *dbuf, int dbuflen,
				unsigned int flag)
{
	int     rv;
	iscsi_node *node;
	chiscsi_target_class *tclass;
	
	check_req_buffer_not_empty(ebuf, rbuf);
	check_data_buffer_present(ebuf, dbuf, dbuflen);

	tclass = iscsi_target_class_find_by_name(CHELSIO_TARGET_CLASS);

	node = iscsi_node_find_by_name(rbuf);

	if (!node)
		rv = iscsi_node_add(dbuf, dbuflen, ebuf,
				ISCSI_CONTROL_REQ_MAX_BUFLEN, tclass);
	else
		rv = iscsi_node_reconfig(node, dbuf, dbuflen, ebuf,
					 ISCSI_CONTROL_REQ_MAX_BUFLEN, tclass);
	return rv;
}

/**
 * iscsi_control_node_reload - initiator/target, reload
 * @rbuf -- req, <name><null>
 *		* <name> can NOT be ALL.
 * @ebuf -- error msg
 * @dbuf -- req, <key-value pairs><null>
 */
static int iscsi_control_node_reload(int opcode, char *rbuf, char *ebuf,
				int ebuflen, char *dbuf, int dbuflen,
				unsigned int flag)
{
	int     rv;
	iscsi_node *node;
	chiscsi_target_class *tclass;

	check_req_buffer_not_empty(ebuf, rbuf);
	check_data_buffer_present(ebuf, dbuf, dbuflen);

	tclass = iscsi_target_class_find_by_name(CHELSIO_TARGET_CLASS);

	node = iscsi_node_find_by_name(rbuf);
	if (!node) {
		sprintf(ebuf, "%s not started, ignore.\n", rbuf);
		return 0;
	}

	rv = iscsi_node_reconfig(node, dbuf, dbuflen, ebuf,
				 ISCSI_CONTROL_REQ_MAX_BUFLEN, tclass);

	return rv;
}

/**
 * iscsi_control_node_stop - target, stop
 * @rbuf -- req, <node name><null>
 *		* <node name> can be ALL.
 * @ebuf -- error msg
 * @dbuf -- not used.
 */
static int iscsi_control_node_remove(int opcode, char *rbuf,
				     char *ebuf, int ebuflen, char *dbuf,
				     int dbuflen, unsigned int flag)
{
	int     rv = 0;
	int     single_node = os_strcmp(rbuf, "ALL");
	iscsi_node *node = NULL;

	check_req_buffer_not_empty(ebuf, rbuf);

	if (single_node) {
		node = iscsi_node_find_by_name(rbuf);
		if (!node) {
			sprintf(ebuf, "%s is not found.\n", rbuf);
			return -ISCSI_ENOTFOUND;
		}
	}

	rv = iscsi_node_remove(node, 0, ebuf, ISCSI_CONTROL_REQ_MAX_BUFLEN);
	return rv;
}


static int iscsi_control_node_drop_session(int opcode, char *rbuf, char *ebuf,
                                        int ebuflen, char *dbuf, int dbuflen,
					unsigned int flag)
{
	int rv;
	unsigned long sess_hndl;	
	
	sess_hndl = os_strtoul(rbuf, NULL, 16);
	rv = iscsi_node_drop_session(sess_hndl);

	return rv;
}

/**
 * iscsi_control_node_get_session - initiator/target, display session
 * @rbuf -- req, <node name><null><peer node name><null>
 * @ebuf -- error msg
 * @dbuf -- result
 */
static int iscsi_control_node_get_session(int opcode, char *rbuf, char *ebuf,
					int ebuflen, char *dbuf, int dbuflen,
					unsigned int flag)
{
	int     rv;
	char   *peername = rbuf + os_strlen(rbuf) + 1;
	iscsi_node *node;

	check_req_buffer_not_empty(ebuf, rbuf);
	check_data_buffer_present(ebuf, dbuf, dbuflen);
	memset(dbuf, 0, dbuflen);

	node = iscsi_node_find_by_name(rbuf);
	if (!node) {
		sprintf(ebuf, "%s is not found.\n", rbuf);
		return -ISCSI_ENOTFOUND;
	}

	if (!(*peername))
		peername = NULL;
	
	rv = iscsi_node_get_session(node, peername, dbuf, dbuflen);

	return rv;
}

/**
 * iscsi_control_isns_get_target_portals - target, retrieve all portals
 *	used for isns client
 * @rbuf -- not used
 * @ebuf -- error msg
 * @dbuf -- result
 */
static int iscsi_control_isns_get_target_portals(int opcode, char *rbuf,
						char *ebuf, int ebuflen,
						char *dbuf, int dbuflen,
						unsigned int flag)
{
	int     rv;

	check_data_buffer_present(ebuf, dbuf, dbuflen);
	memset(dbuf, 0, dbuflen);

	rv = iscsi_target_write_all_target_portal_config(dbuf, dbuflen);
	return rv;
}

/**
 * iscsi_control_isns_get_targets - target, retrieve all config
 *	used for isns client
 * @rbuf -- not used
 * @ebuf -- error msg
 * @dbuf -- result
 */
static int iscsi_control_isns_get_targets(int opcode, char *rbuf, char *ebuf,
					int ebuflen, char *dbuf, int dbuflen,
					unsigned int flag)
{
	int     rv;

	check_data_buffer_present(ebuf, dbuf, dbuflen);
	memset(dbuf, 0, dbuflen);

	rv = iscsi_target_write_all_target_config(dbuf, dbuflen);
	return rv;
}

/**
 * iscsi_control_isns_set_target_acls - add to target acls
 *	used for isns client
 * @rbuf -- req: <targetname><null><isns id><null>
 * @ebuf -- error msg
 * @dbuf -- ACL=<val><null>ACL=<val><null>...
 */
static int iscsi_control_isns_set_target_acl(int opcode, char *rbuf, char *ebuf,
					int ebuflen, char *dbuf, int dbuflen,
					unsigned int flag)
{
	int     rv = 0;
	iscsi_node *target;
	char   *ch;
	unsigned long id;

	check_req_buffer_not_empty(ebuf, rbuf);
	check_data_buffer_present(ebuf, dbuf, dbuflen);

	target = iscsi_node_find_by_name(rbuf);
	if (!target) {
		sprintf(ebuf, "Target %s is NOT found.\n", rbuf);
		return -ISCSI_ENOTFOUND;
	}

	id = os_strtoul(rbuf + os_strlen(rbuf) + 1, &ch, 10);
	if (!id) {
		sprintf(ebuf, "Target %s, ID not valid.\n", rbuf);
		return -ISCSI_EINVAL;
	}
#ifdef __CONTROL_DEBUG__
	dump_request(opcode, rbuf, ebuf, ebuflen, dbuf, dbuflen);
#endif
	/*update/create/delete the iSNS ACL queue) */
       	rv = iscsi_acl_isns_config(id, target, dbuf, dbuflen, ebuf);

	return rv;
}

/**
 * iscsi_ctrl_handlers - control request dispatcher table
 */
typedef int (*iscsi_ctrl_handler_t) (int, char *, char *, int, char *,
		int, unsigned int);
static iscsi_ctrl_handler_t iscsi_ctrl_handlers[ISCSI_CONTROL_OPCODE_MAX];

#define iscsi_control_set_handler(op, fp) \
			iscsi_ctrl_handlers[op] = fp

static int iscsi_control_bad_request(int opcode, char *req, char *ebuf,
					int ebuflen, char *dbuf, int dlen,
					unsigned int flag)
{
	if (ebuf)
		sprintf(ebuf, "cmd %d not supported.\n", opcode);
	return -ISCSI_ECMD;
}

/**
 * iscsi_control_process_request - control device dispatcher
 */
int iscsi_control_process_request(int opcode, char *rbuf, char *ebuf,
				  int ebuflen, char *dbuf, int dlen,
				unsigned int flag)
{
	int     rv = 0;

	if (ebuf) {
		memset(ebuf, 0, ebuflen);
	}

	if (opcode < ISCSI_CONTROL_OPCODE_MAX) {
#ifdef __CONTROL_DEBUG__
		dump_request(opcode, rbuf, ebuf, ebuflen, dbuf, dlen);
#endif
		rv = iscsi_ctrl_handlers[opcode](opcode, rbuf, ebuf,
					ebuflen, dbuf, dlen, flag);
	} else if (ebuf) {
		sprintf(ebuf, "cmd %d invalid.\n", opcode);
		rv = -ISCSI_ECMD;
	}

	return (rv < 0 ? rv : 0);
}

/*
 * control init & cleanup
 */
int iscsi_control_init(void)
{
	int     i;

	for (i = 0; i < ISCSI_CONTROL_OPCODE_MAX; i++) {
		iscsi_ctrl_handlers[i] = iscsi_control_bad_request;
	}

	iscsi_control_set_handler(ISCSI_CONTROL_OPCODE_DRV_GET,
				  iscsi_control_settings_get);
	iscsi_control_set_handler(ISCSI_CONTROL_OPCODE_DRV_SET,
				  iscsi_control_settings_set);
	iscsi_control_set_handler(ISCSI_CONTROL_OPCODE_STAT_GET,
				  iscsi_control_stats_get);

	iscsi_control_set_handler(ISCSI_CONTROL_OPCODE_TARGET_FLUSH,
				  iscsi_control_target_flush);
	iscsi_control_set_handler(ISCSI_CONTROL_OPCODE_TARGET_GET_NAMES,
				  iscsi_control_node_get_names);
	iscsi_control_set_handler(ISCSI_CONTROL_OPCODE_TARGET_GET,
				  iscsi_control_node_get_config);
	iscsi_control_set_handler(ISCSI_CONTROL_OPCODE_TARGET_GET_WRITE,
				  iscsi_control_node_get_config_write);
	iscsi_control_set_handler(ISCSI_CONTROL_OPCODE_TARGET_ADD,
				  iscsi_control_node_add);
	iscsi_control_set_handler(ISCSI_CONTROL_OPCODE_TARGET_RELOAD,
				  iscsi_control_node_reload);
	iscsi_control_set_handler(ISCSI_CONTROL_OPCODE_TARGET_REMOVE,
				  iscsi_control_node_remove);
	iscsi_control_set_handler(ISCSI_CONTROL_OPCODE_DBGDUMP,
				  iscsi_control_node_get_session);
	iscsi_control_set_handler(ISCSI_CONTROL_OPCODE_DROP_SESSION,
				  iscsi_control_node_drop_session);

	/* iSNS only */
	iscsi_control_set_handler(ISCSI_CONTROL_OPCODE_ISNS_GET_TARGET_PORTALS,
				  iscsi_control_isns_get_target_portals);
	iscsi_control_set_handler(ISCSI_CONTROL_OPCODE_ISNS_GET_TARGETS,
				  iscsi_control_isns_get_targets);
	iscsi_control_set_handler(ISCSI_CONTROL_OPCODE_ISNS_SET_TARGET_ACL,
				  iscsi_control_isns_set_target_acl);

	return 0;
}

void iscsi_control_cleanup(void)
{
	return;
}
