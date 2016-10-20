/*
 * iscsi target configuration (via iscsi control interface)
 */

#include <iscsi_auth_api.h>
#include <iscsi_target_api.h>
#include "iscsi_target_private.h"
#include <common/iscsi_scst.h>

extern chiscsi_queue *it_portal_q;	/* all the target portals */

extern unsigned int node_max_lun_count;

/*
 * Target config -- add/remove/reload
 */

void iscsi_node_target_free(iscsi_node * node)
{
	node->lu_cnt = 0;
	if (node->lu_list)
		os_free(node->lu_list);
	node->lu_list = NULL;

	node->portal_cnt = 0;
	if (node->portal_list)
		os_free(node->portal_list);
	node->portal_list = NULL;

	if (node->acl_list)
		iscsi_acl_list_free(node->acl_list);
        node->acl_list = NULL;

	if (node->acl_isns_list)
		iscsi_acl_list_free(node->acl_isns_list);
        node->acl_isns_list = NULL;

#ifdef __ISCSI_SCST__
        if (node->scst_target) {
                iscsi_scst_unregister(node->scst_target);
                node->scst_target = NULL;
        }
#endif
}

iscsi_node *iscsi_node_target_alloc(iscsi_keyval *kv_conf)
{
	iscsi_keyval *kvp;
	iscsi_node *node = NULL;
	void *lu_list = NULL;
	iscsi_target_portal *portal_list = NULL;
	int lu_cnt = 0;
	int portal_cnt = 0;

	/* for default discovery target this is no luns */
 	kvp = kv_conf + ISCSI_KEY_CONF_TARGET_DEVICE;
	if (kvp->kv_rcvcnt) {
		lu_cnt = kvp->kv_rcvcnt;
		lu_list = os_alloc(lu_cnt * sizeof(chiscsi_target_lun *), 1, 1);
		if (!lu_list)
			return NULL;
	}
 	kvp = kv_conf + ISCSI_KEY_CONF_PORTALGROUP;
	if (kvp->kv_rcvcnt) {
		iscsi_value *vp = kvp->kv_valp;
		unsigned int *p;
		int i;

		for (portal_cnt = 0; vp; vp = vp->v_next, portal_cnt++)
			;
		portal_list = os_alloc(portal_cnt *
				(sizeof(iscsi_target_portal) + 
				/* for redirect_to_list */
				 sizeof(unsigned int) * portal_cnt),
					1, 1);
		if (!portal_list)
			goto error;

		p = (unsigned int *)(portal_list + portal_cnt);
		for (i = 0; i < portal_cnt; i++) {
			iscsi_target_portal *tp = portal_list + i;
		
			tp->redirect_to_list = p;
			p += portal_cnt;
		}
	}
	
	node = iscsi_node_alloc();
	if (!node)
		goto error;

        node->lu_list = (chiscsi_target_lun **)lu_list;
        node->portal_list = (iscsi_target_portal *)portal_list;

        node->lu_cnt = lu_cnt;
        node->portal_cnt = portal_cnt;

	return node;

error:
	if (lu_list)
		os_free(lu_list);
	if (portal_list)
		os_free(portal_list);
	return NULL;
}

int iscsi_node_target_scst_configured(iscsi_node *node)
{
	return (node->scst_target != NULL);
}

static void target_node_fill_settings(iscsi_node *node)
{
	int rv;
	
	/* session setttings */
	rv = iscsi_get_session_key_settings(&node->sess_keys,
				node->n_keys[NODE_KEYS_SESSION]);
	/* connection setttings */
	rv = iscsi_get_connection_key_settings(&node->conn_keys,
				node->n_keys[NODE_KEYS_CONNECTION]);

	/* config setttings */
	rv = iscsi_get_node_chap_settings(&node->chap, node->n_auth);
	
	rv = iscsi_get_target_config_key_settings(&node->config_keys,
				node->n_keys[NODE_KEYS_CONFIG]);
}

static void target_node_adjust_parameter(iscsi_node *node)
{
	int multi_phase_data = 0;

	if (node->lu_cnt) {
		if (chiscsi_target_luns_has_property(node,
			 LUN_CLASS_MULTI_PHASE_DATA_BIT))
			multi_phase_data = 1;
	} else if (iscsi_target_class_luns_has_property(0,
			LUN_CLASS_MULTI_PHASE_DATA_BIT, node->tclass)) 
		multi_phase_data = 1;

	if (multi_phase_data) {
		iscsi_keyval *kvp;
		os_log_debug(ISCSI_DBG_TARGET_API,
				"node %s, has MULTI_PHASE_DATA lun, "
				"disable immediate/unsolicited data.\n", 
				node->n_name);
		kvp = node->n_keys[NODE_KEYS_SESSION] + 
			ISCSI_KEY_SESS_IMMEDIATE_DATA;
		kvp->kv_valp->v_num[0] = 0;
		kvp = node->n_keys[NODE_KEYS_SESSION] + 
			ISCSI_KEY_SESS_INITIAL_R2T;
		kvp->kv_valp->v_num[0] = 1;
	}
}

int iscsi_node_target_read_config(iscsi_node *node, char *ebuf, int ebuflen)
{
	iscsi_keyval *kvp;
	int rv = 0;
	int parse_lun = 1;

	iscsi_get_target_config_key_settings(&node->config_keys,
					node->n_keys[NODE_KEYS_CONFIG]);

	/* start all portals */
	rv = iscsi_target_portals_update(node, ebuf);
	if (rv < 0)
		goto err_out;

	if (node->config_keys.shadow_mode) {
		int i;

		kvp = node->n_keys[NODE_KEYS_CONFIG] +
				ISCSI_KEY_CONF_TARGET_DEVICE;
		parse_lun = 0;
		/* check if any local portal, which is not related to
		 * redirection has been started */
		for (i = 0; i < node->portal_cnt; i++) {
			iscsi_target_portal *tp = node->portal_list + i;
			if (tp->portal &&
			    !(tp->flag & ISCSI_PORTAL_FLAG_REDIRECT_FROM)) {
				parse_lun = 1;	
				break;
			}
		}

		if (!parse_lun && kvp->kv_rcvcnt) {
			os_log_warn("%s ShadowMode on, TargetDevice ignored.\n",
					node->n_name);
			if (ebuf)
				sprintf(ebuf,
				"%s ShadowMode on, TargetDevice ignored.\n",
					node->n_name);

			kvp->kv_rcvcnt = 0;
			node->lu_cnt = 0;
			os_free(node->lu_list);
			node->lu_list = NULL;
		}
	}

	if (parse_lun) {
        	/* parse target device, will NOT attach here */
        	rv = iscsi_target_lu_read_config(node, ebuf, ebuflen);
		if (rv < 0)
			goto err_out;
		if (node->lu_cnt > node_max_lun_count) {
			os_log_error("%s exceeds max lun allowed %u > %u\n",
				node->n_name, node->lu_cnt, node_max_lun_count);
			if (ebuf)
				sprintf(ebuf,
					"%s exeeds max lun allowed %u > %u.\n",
					node->n_name, node->lu_cnt,
					node_max_lun_count);
			rv = -ISCSI_EINVAL;
			goto err_out;
		}
	}

	/* do acl after portal start, so we can cross check */
	rv = iscsi_acl_config(node, ebuf);
	if (rv < 0)
		goto err_out;


	target_node_adjust_parameter(node);
	target_node_fill_settings(node);
	return 0;	

err_out:
	iscsi_target_lu_offline(node);
	iscsi_target_portals_remove(node);
	return rv;
}

/*
 * Target flush
 */
int iscsi_target_flush(iscsi_node * node, char *reqbuf, char *ebuf, int ebuflen)
{
	unsigned int lun_min = 0, lun_max = 0;
	int     single_node = node ? 1 : 0;
	int     lun_set = 0;
	int     rv;

	/* the reqbuf contains either
	 *              <lun number str><null> or
	 *              <null> which means all luns
	 */
	if (reqbuf && *reqbuf) {
		iscsi_value kv_value;
		memset(&kv_value, 0, sizeof(iscsi_value));
		rv = kv_decode_number_range(ISCSI_KV_DECODE_OP_ADD, reqbuf, &kv_value, ebuf);
		if (rv < 0)
			return rv;

		if (kv_value.v_num[0] == kv_value.v_num[1]) {
			lun_min = lun_max = kv_value.v_num[0];
		} else {	/* a range */
			lun_min = kv_value.v_num[0];
			lun_max = kv_value.v_num[1];
		}
		lun_set = 1;
	}

	if (!node)
		node = iscsi_nodeq->q_head;

	for (; node; node = node->n_next) {
		if (!lun_set) {
			rv = iscsi_target_lu_flush(node, 0, 1);
		} else {
			unsigned int lun;
			for (lun = lun_min; lun <= lun_max; lun++)
				rv = iscsi_target_lu_flush(node, lun, 0);
		}

		/* if a single target,stop */
		if (single_node)
			break;
	}

	return 0;
}

/*
 * Discovery CHAP configuration
 */
int iscsi_config_disc_chap(iscsi_node *node)
{
	int len, rv = 0;
	char    buffer[256];
	iscsi_keyval *kv_conn;
	iscsi_keyval *kvp;
	void   *authp = NULL;

	if (!node)
		return -ISCSI_EINVAL;
	kv_conn = node->n_keys[NODE_KEYS_CONNECTION];

	if (node->n_auth)
		iscsi_auth_node_free(node->n_auth);

	authp = iscsi_auth_node_alloc(ISCSI_TARGET);
	if (!authp)
		return -ISCSI_ENOMEM;

	if (disc_auth_method)
		len = sprintf(buffer,"%s", "CHAP");
	else
		len = sprintf(buffer,"%s", "None");

	buffer[len] = 0;
	kvp = kv_conn + ISCSI_KEY_CONN_AUTH_METHOD;
	if (kvp->kv_valp) {
		iscsi_value_free(kvp->kv_valp, NULL);
		kvp->kv_valp = NULL;
	}
	if(kvp->kv_rcvcnt)
		kvp->kv_rcvcnt--;
	rv = iscsi_kvp_decode_buffer(ISCSI_KV_DECODE_OP_ADD,
					ISCSI_TARGET,
					CONN_STATE_CLOSED,
					kvp, buffer, NULL, 0);
	if (rv < 0)
		return rv;

	rv = iscsi_auth_method_changed(authp, kvp);
	if (rv < 0)
		return rv;

	rv = iscsi_auth_config_discovery(authp);
	if (rv < 0)
		return rv;

	node->n_auth = authp;
	iscsi_get_node_chap_settings(&node->chap, node->n_auth);

	return rv;
}

/*
 * initialization/cleanup 
 */
iscsi_node *target_create_default_keys(char *name, char *alias, int enqueue)
{
	char    buffer[256];
	int     len, rv;
	iscsi_keyval *kv_sess = NULL;
	iscsi_keyval *kv_conn = NULL;
	iscsi_keyval *kv_conf = NULL;
	iscsi_node *node = NULL;

	if (!name || !os_strlen(name))
		return NULL;

	kv_sess = iscsi_session_key_alloc();
	kv_conn = iscsi_connection_key_alloc();
	kv_conf = iscsi_config_key_alloc();

	if (!kv_sess || !kv_conn || !kv_conf)
		goto cleanup;

	/* set header digest */
	len = sprintf(buffer, "CRC32C,None");
	buffer[len] = 0;
	rv = iscsi_kvp_decode_buffer(ISCSI_KV_DECODE_OP_ADD,
					ISCSI_TARGET,
					CONN_STATE_CLOSED,
					kv_conn + ISCSI_KEY_CONN_HEADER_DIGEST,
					buffer, NULL, 0);
	if (rv < 0)
		goto cleanup;

	/* set data digest */
	len = sprintf(buffer, "CRC32C,None");
	buffer[len] = 0;
	rv = iscsi_kvp_decode_buffer(ISCSI_KV_DECODE_OP_ADD,
					ISCSI_TARGET,
					CONN_STATE_CLOSED,
					kv_conn + ISCSI_KEY_CONN_DATA_DIGEST,
					buffer, NULL, 0);
	if (rv < 0)
		goto cleanup;

	/* set up the target name and alias */
	len = sprintf(buffer, "%s", name);
	buffer[len] = 0;
	rv = iscsi_kvp_decode_buffer(ISCSI_KV_DECODE_OP_ADD,
					ISCSI_TARGET,
					CONN_STATE_CLOSED,
					kv_conn + ISCSI_KEY_CONN_TARGET_NAME,
					buffer, NULL, 0);
	if (rv < 0)
		goto cleanup;

	if (alias && os_strlen(alias)) {
		len = sprintf(buffer, "%s", alias);
		buffer[len] = 0;
		rv = iscsi_kvp_decode_buffer(ISCSI_KV_DECODE_OP_ADD,
					ISCSI_TARGET, CONN_STATE_CLOSED,
					kv_conn + ISCSI_KEY_CONN_TARGET_ALIAS,
					buffer, NULL, 0);
		if (rv < 0)
			goto cleanup;
	}

	rv = iscsi_session_key_fill_default(kv_sess);
	if (rv < 0)
		goto cleanup;

	rv = iscsi_connection_key_fill_default(kv_conn);
	if (rv < 0)
		goto cleanup;

	rv = iscsi_config_key_fill_default(kv_conf);
	if (rv < 0)
		goto cleanup;

	node = iscsi_node_target_alloc(kv_conf);
	if (!node)
		goto cleanup;

	os_strcpy(node->n_name, name);
	if (alias)
		os_strcpy(node->n_alias, alias);

	node->n_keys[NODE_KEYS_CONNECTION] = kv_conn;
	node->n_keys[NODE_KEYS_SESSION] = kv_sess;
	node->n_keys[NODE_KEYS_CONFIG] = kv_conf;
	kv_conn = NULL;
	kv_sess = NULL;
	kv_conf = NULL;

	rv = iscsi_config_disc_chap(node);
	if (rv < 0)
		goto cleanup;

	if (enqueue)
		iscsi_node_enqueue(lock, iscsi_nodeq, node);

	return node;

cleanup:
	if (kv_conn)
		iscsi_connection_key_free(kv_conn);
	if (kv_sess)
		iscsi_session_key_free(kv_sess);
	if (kv_conf)
		iscsi_config_key_free(kv_conf);
	if (node && node->n_auth)
		iscsi_auth_node_free(node->n_auth);

	if (node)
		iscsi_node_remove(node, 0, NULL, 0);

	return NULL;
}
