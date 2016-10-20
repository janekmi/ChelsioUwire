/*
 * iscsi_node.c -- iscsi node (initiator/target) management
 */

#include <common/os_builtin.h>
#include <iscsi_structs.h>
#include <iscsi_global.h>
#include <iscsi_target_api.h>
#include <iscsi_auth_api.h>
#include <iscsi_config_keys.h>
#include <iscsi_connection_keys.h>
#include <iscsi_session_keys.h>
#include <common/iscsi_target_notif.h>
#include <target/iscsi_target_private.h>
#include <security/iscsi_auth_private.h>
#include <common/iscsi_scst.h>

unsigned int iscsi_node_id = 0x1;

/*
 * iscsi_node struct alloc and free
 */
void iscsi_node_free(iscsi_node * node)
{
	int     i;

	iscsi_node_target_free(node);

	/* release authentication setup */
	if (node->n_auth)
		iscsi_auth_node_free(node->n_auth);

	/* release keys */
	for (i = 0; i < NODE_KEYS_TYPE_MAX; i++) {
		if (node->n_keys[i])
			iscsi_kvlist_free(node->n_keys_max[i], node->n_keys[i]);
	}
	
	for (i = 0; i < NODE_TARGET_Q_MAX; i++) {
		ch_queue_free(node->n_queue[i]);
	}
	os_data_free(node->os_data);
	os_free(node);
}

iscsi_node *iscsi_node_alloc(void)
{
	int	total_size = ISCSI_NODE_SIZE;
	int     i;
	iscsi_node *node;

	node = os_alloc(total_size, 1, 1);
	if (!node)
		return NULL;

	node->n_id = iscsi_node_id++;

	if (!(node->os_data = os_data_init((void *)node)))
		goto os_data_fail;
	os_data_counter_set(node->os_data, 0);
	for (i = 0; i < NODE_TARGET_Q_MAX; i++) {
		ch_queue_alloc(node->n_queue[i]);
	}

	node->n_keys_max[NODE_KEYS_CONNECTION] = ISCSI_KEY_CONN_COUNT;
	node->n_keys_max[NODE_KEYS_SESSION] = ISCSI_KEY_SESS_COUNT;
	node->n_keys_max[NODE_KEYS_CONFIG] = ISCSI_KEY_CONFIG_COUNT;

	os_log_debug(ISCSI_DBG_NODE,
		     "create node 0x%p.\n", node);

	return node;
q_lock_fail:
	for (i = 0; i < NODE_TARGET_Q_MAX; i++) {
		ch_queue_free(node->n_queue[i]);
	}
	os_data_free(node->os_data);
os_data_fail:
	os_free(node);
	return NULL;
}

/*
 * search iscsi_nodeq by name or alias
 */
iscsi_node *iscsi_node_find_by_name(char *name)
{
	iscsi_node *node;

	os_lock(iscsi_nodeq->q_lock);
	for (node = iscsi_nodeq->q_head; node; node = node->n_next) {
		/* skip the node being removed */
		if (iscsi_node_flag_test(node, NODE_FLAG_OFFLINE_BIT)) {
			continue;
		}
		/* iqn names are Case insensitive */
		if (!os_strcmp(node->n_name, name))
			break;
	}
	os_unlock(iscsi_nodeq->q_lock);
	return (void *) node;
}

iscsi_node *iscsi_node_find_by_alias(char *alias)
{
	iscsi_node *node;

	os_lock(iscsi_nodeq->q_lock);
	for (node = iscsi_nodeq->q_head; node; node = node->n_next) {
		/* skip the node being removed */
		if (iscsi_node_flag_test(node, NODE_FLAG_OFFLINE_BIT)) {
			continue;
		}
		if (node->n_alias && (!os_strcmp(node->n_alias, alias)))
			break;
	}
	os_unlock(iscsi_nodeq->q_lock);
	return (void *) node;
}

/*
 * display all the configured nodes' name
 */
int iscsi_node_get_target_names(char *buf, int buflen)
{
	iscsi_node *node;
	int     baselen = os_strlen(buf);
	int	len = baselen;
	int     cnt = 0;

	len += sprintf(buf + len, "target=");
	for (node = iscsi_nodeq->q_head; node; node = node->n_next) {
		cnt++;
		len += sprintf(buf + len, "%s,", node->n_name);
		if (len > buflen)
			break;
	}

	if (!cnt)
		return 0;

	if (len > buflen)
		len = buflen - 1;

	if (buf[len - 1] == ',')
		len--;
	buf[len++] = 0;

	return (len - baselen);
}

/*
 * node add, reconfig, and remove
 */

static int node_sessq_empty(void *arg)
{
	iscsi_node *node = (iscsi_node *) arg;
	return ((node->n_queue[NODE_SESSQ]->q_head == NULL));
}

extern iscsi_node *it_target_dflt;
int iscsi_node_remove(iscsi_node *node, int reconfig, char *ebuf,
			unsigned int ebuflen)
{
	int 	len = 0;
	int     all_node = node ? 0 : 1;

	if (!iscsi_nodeq)
		return 0;

	if (all_node) {
		node = iscsi_nodeq->q_head;
		reconfig = 0;
	}

	while (node) {
		iscsi_node *next = node->n_next;
		chiscsi_queue *sessq = node->n_queue[NODE_SESSQ];
		iscsi_session *sess;
		int     cnt = 0;

		os_log_debug(ISCSI_DBG_NODE,
			     "removing node 0x%p, %s.\n", node, node->n_name);

		iscsi_node_flag_set(node, NODE_FLAG_OFFLINE_BIT);

		os_lock(sessq->q_lock);
		cnt = sessq->q_cnt;
		/* close all normal sessions */
		for (sess = sessq->q_head; sess; sess = sess->s_next){
			if(sess)
				iscsi_session_schedule_close(sess);
		}
		os_unlock(sessq->q_lock);

		iscsi_target_portals_remove(node);
		iscsi_conn_portal_remove(sessq);
		iscsi_target_lu_offline(node);

		/* wait for all session to be gone */
		if (cnt)
			os_data_wait_on_ackq(node->os_data,
				   (int (*)(void *)) node_sessq_empty, node,
				   30);

		if (sessq->q_head) {
			if (!all_node && ebuf) {
				len += sprintf(ebuf + len,
					       "%s busy.\n", node->n_name);
			}
			os_log_warn("%s busy, sess %u/%u.\n",
				    node->n_name, sessq->q_cnt, cnt);
		} else {
			if (!all_node && ebuf)
				len += sprintf(ebuf + len,
					       "%s removed.\n", node->n_name);
			if (!reconfig) {
				os_log_info("%s removed.\n", node->n_name);
				os_chiscsi_notify_event(CHISCSI_NODE_REMOVE,
	                                        "Node name=%s", node->n_name);

				os_log_debug(ISCSI_DBG_NODE,
						"node 0x%p, %s removed.\n",
						node, node->n_name);

				if (node != it_target_dflt)
					os_module_put(node);
			}

			iscsi_node_ch_qremove(lock, iscsi_nodeq, node);

			iscsi_node_free(node);
		}
		node = all_node ? next : NULL;
	}

	if (all_node && ebuf) {
		if (iscsi_nodeq->q_cnt)
			len += sprintf(ebuf + len, "NOT all targets removed.\n");
		else
			len += sprintf(ebuf + len, "All targets removed.\n");
	}

	return 0;
}

static iscsi_node *iscsi_node_read_config(int check_dup, char *buf,
			unsigned int buflen, char *ebuf, 
			unsigned int ebuflen, 
			 chiscsi_target_class *tclass)
{
	iscsi_node *node = NULL;
	chiscsi_queue *pairq = NULL;
	iscsi_keyval *kv_conf = NULL;
	iscsi_keyval *kv_sess = NULL;
	iscsi_keyval *kv_conn = NULL;
	iscsi_keyval *kvp;
	void   *authp = NULL;
	char   *name = NULL, *alias = NULL;
	iscsi_string_pair *pair;
	int     rv = 0;
	int 	len = ebuf ? os_strlen(ebuf) : 0;
	int	is_chelsio_target = ( !os_strcmp(tclass->class_name, CHELSIO_TARGET_CLASS) ? 1: 0);

	ch_queue_alloc(pairq);
	authp = iscsi_auth_node_alloc(ISCSI_TARGET);
	kv_conf = iscsi_config_key_alloc();
	kv_sess = iscsi_session_key_alloc();
	kv_conn = iscsi_connection_key_alloc();
	if (!pairq || !authp || !kv_conf || !kv_sess || !kv_conn) {
		if (ebuf && len < ebuflen)
			len += sprintf(ebuf + len, "Target out of memory.\n");
		os_log_info("Target OOM.\n", 0);
		goto done;
	}

	/* split buffer to key-value string pairs */
	rv = iscsi_kv_text_to_string_pairq(buflen, buf, pairq, ebuf, ebuflen);
	if (rv < 0) {
		goto done;
	}

	rv = iscsi_config_key_decode(ISCSI_TARGET, kv_conf, pairq, ebuf, ebuflen);
	if (rv < 0) {
		goto done;
	}

	rv = iscsi_session_key_decode(ISCSI_TARGET, CONN_STATE_CLOSED,
				      kv_sess, pairq, ebuf, ebuflen);
	if (rv < 0) {
		goto done;
	}

	rv = iscsi_connection_key_decode(ISCSI_TARGET, CONN_STATE_CLOSED,
					 kv_conn, pairq, ebuf, ebuflen);
	if (rv < 0) {
		goto done;
	}

	/* decode CHAP keys */
	kvp = kv_conn + ISCSI_KEY_CONN_AUTH_METHOD;
	if (!kvp->kv_valp) {
		rv = iscsi_auth_method_set_default(kvp);
		if (rv < 0) {
			goto done;
		}
	}
	rv = iscsi_auth_method_changed(authp, kvp);
	if (rv < 0) {
		goto done;
	}
	if (pairq->q_head) {
		
		rv = iscsi_auth_config(authp, pairq, ebuf, ebuflen);
		if (rv < 0) {
			goto done;
		}
	}
	len = os_strlen(ebuf);

	/* all key-value strings should be decoded by now */
	if ((pair = pairq->q_head)) {
		if (ebuf && len < ebuflen)
			sprintf(ebuf + len, "unrecognized key %s.\n", pair->p_key);
		os_log_info("unrecognized key %s.\n", pair->p_key);
		goto done;
	}

	rv = iscsi_config_key_fill_default(kv_conf);
	rv |= iscsi_session_key_fill_default(kv_sess);
	rv |= iscsi_connection_key_fill_default(kv_conn);
	if (rv < 0) {
		goto done;
	}

	/* validate the keys */
	rv = iscsi_config_keys_validate_value(kv_conf, ebuf, ebuflen, is_chelsio_target);
	rv |= iscsi_session_keys_validate_value(kv_sess, ebuf, ebuflen);
	rv |= iscsi_connection_keys_validate_value(kv_conn, ebuf, ebuflen);
	if (rv < 0) {
		goto done;
	}

	len = os_strlen(ebuf);

	/* name */
	name = (kv_conn + ISCSI_KEY_CONN_TARGET_NAME)->kv_valp->v_str[0];
	
	/* alias */
	kvp = (kv_conn + ISCSI_KEY_CONN_TARGET_ALIAS);
	if (kvp->kv_valp)
		alias = kvp->kv_valp->v_str[0];

	/* check for name and alias duplication */
	if (check_dup) {
		if (iscsi_node_find_by_name(name)) {
			if (ebuf && len < ebuflen)
				sprintf(ebuf + len,
					"An target with name %s "
					"already exists.\n", name);
			goto done;
		}

		if (alias && iscsi_node_find_by_alias(alias)) {
			if (ebuf && len < ebuflen)
				sprintf(ebuf + len,
					"An target with alias %s "
					"already exists.\n", alias);
			goto done;
		}
	}

	/* lu not needed if shadow mode is on */
	kvp = kv_conf + ISCSI_KEY_CONF_SHADOW_MODE;
	if (!kvp->kv_valp || kvp->kv_valp->v_num[0] == 0) {
		kvp = kv_conf + ISCSI_KEY_CONF_TARGET_DEVICE;
		if ((kvp->kv_rcvcnt && !tclass->fp_config_parse_luns) || 
	    	    (!kvp->kv_rcvcnt && tclass->fp_config_parse_luns)) {
			os_log_error("%s: class %s, fp_config_parse_luns 0x%p, lun %u.\n",
				name, tclass->class_name, kvp->kv_rcvcnt);
			if (ebuf)
				sprintf(ebuf, "%s: class %s, fp_config_parse_luns 0x%p, lun %u.\n",
					name, tclass->class_name,
					tclass->fp_config_parse_luns,
					kvp->kv_rcvcnt);
			goto done;
		}
	}

	node = iscsi_node_target_alloc(kv_conf);
	if (!node) {
		if (ebuf && len < ebuflen)
			sprintf(ebuf, "iscsi target add/update: OOM.\n");
		os_log_info("%s: OOM.\n", name);
		goto done;
	}

	rv = iscsi_get_session_key_settings(&node->sess_keys, kv_sess);
	if (rv < 0)
		goto done;
	rv = iscsi_get_connection_key_settings(&node->conn_keys, kv_conn);
	if (rv < 0)
		goto done;
	rv = iscsi_get_node_chap_settings(&node->chap, authp);
	if (rv < 0)
		goto done;

	node->tclass = tclass;
	os_strcpy(node->n_name, name);
	if (alias)
		os_strcpy(node->n_alias, alias);
	node->n_auth = authp;
	authp = NULL;
	node->n_keys[NODE_KEYS_SESSION] = kv_sess;
	kv_sess = NULL;
	node->n_keys[NODE_KEYS_CONNECTION] = kv_conn;
	kv_conn = NULL;
	node->n_keys[NODE_KEYS_CONFIG] = kv_conf;
	kv_conf = NULL;

	rv = iscsi_node_target_read_config(node, ebuf, ebuflen);
	if (rv < 0)
		goto done;

	if (iscsi_node_has_dif_dix_enabled_lun(node, LUN_T10DIX_BIT ||
	    iscsi_node_has_dif_dix_enabled_lun(node, LUN_T10DIF_BIT)) &&
	    !(node->sess_keys.initial_r2t)) {
		os_log_error("%s: InitialR2T=Yes must since T10DIX enabled"
			" on atleast one lun.\n",
			node->n_name, node->sess_keys.initial_r2t);
		rv = -ISCSI_EINVAL;
	}
done:
	if (rv < 0) {
		if (node) {
			iscsi_node_free(node);
			node = NULL;
		}
	}
	if (authp)
		iscsi_auth_node_free(authp);
	if (kv_conf)
		iscsi_config_key_free(kv_conf);
	if (kv_sess)
		iscsi_session_key_free(kv_conf);
	if (kv_conn)
		iscsi_connection_key_free(kv_conf);
	if (pairq) {
		iscsi_empty_string_pairq(pairq);
		ch_queue_free(pairq);
	}

	return node;
q_lock_fail:
	ch_queue_free(pairq);
	return NULL;
}

int iscsi_node_add(char *buf, unsigned int buflen, char *ebuf,
		unsigned int ebuflen, chiscsi_target_class *tclass) 
{
	extern chiscsi_queue *it_lu_q;
	iscsi_node *node;
	int i;
	int rv;
	node = iscsi_node_read_config(1, buf, buflen, ebuf, ebuflen, tclass);
	if (!node)
		return -ISCSI_EINVAL;

	rv = iscsi_target_lu_duplicate_validate(0, node, ebuf, ebuflen);
	if (rv < 0)
		goto node_remove;
		
	/* bring the node online */
	for (i = 0; i < node->lu_cnt; i++) {
		chiscsi_target_lun *lu = node->lu_list[i];
		rv = lu->class->fp_attach(lu, ebuf, ebuflen);
		if (rv < 0)
			goto node_remove;
		iscsi_target_lu_init_reservation(lu);
#ifdef __ISCSI_SCST__
		/* Only if a SCST lun is configured, register with scst. */
		if (!os_strcmp(lu->class->class_name, "SCST") &&
			!node->scst_target)
			node->scst_target = iscsi_scst_register(node->n_name);
#endif
	}

	iscsi_node_enqueue(lock, iscsi_nodeq, node);

	for (i = 0; i < node->lu_cnt; i++) {
		chiscsi_target_lun *lu = node->lu_list[i];
		chiscsi_target_lun_enqueue(lock, it_lu_q, lu);
	}
	
	if (ebuf)
		sprintf(ebuf + os_strlen(ebuf), "target %s added.\n",
			node->n_name);

        os_chiscsi_notify_event(CHISCSI_NODE_ADD,
       	                "Node name=%s", node->n_name);

	os_module_get(node);

	if (!it_target_dflt) {
		it_target_dflt = target_create_default_keys(
				"iqn.chiscsi.iscsi.default-target",
				"chiscsi_default_target", 0);

		if (!it_target_dflt)
			return -ISCSI_ENOMEM;
	}

	return 0;

node_remove:
	iscsi_target_lu_offline(node);
	iscsi_target_portals_remove(node);
	iscsi_node_free(node);
	return rv;
}

static int config_listening_server_removed(iscsi_node *old, iscsi_node *new)
{
	int i, j;

	/* portal removal: any portal in the old list but not in the new list */
	for (i = 0; i < old->portal_cnt; i++) {
		iscsi_target_portal *p1 = old->portal_list + i;
		if (!p1->portal)
			continue;
		for (j = 0; j < new->portal_cnt; j++) {
			iscsi_target_portal *p2 = new->portal_list + j;
			if (!p2->portal)
				continue;
			if (p1->portal == p2->portal)
				break;
		}
		if (j == new->portal_cnt)
			return 1;
	}
	return 0;
}

static int config_listening_server_timeout_changed(iscsi_node *old,
						iscsi_node *new)
{
	int i, j;

	for (i = 0; i < old->portal_cnt; i++) {
		iscsi_target_portal *p1 = old->portal_list + i;
		if (!p1->portal)
			continue;
		for (j = 0; j < new->portal_cnt; j++) {
			iscsi_target_portal *p2 = new->portal_list + j;
			if (!p2->portal)
				continue;
			if (p1->portal == p2->portal &&
				p1->timeout != p2->timeout) {
				os_log_info("%s: portal %u timeout %u -> %u.\n",
					old->n_name, p2->grouptag,
					p1->timeout, p2->timeout);
				return 1;
			}
		}
	}
	return 0;
}

static void lun_copy_property(chiscsi_target_lun *to, chiscsi_target_lun *from)
{
	int i;

	for (i = LUN_FLAG_MODIFIER_BIT_START; i <= LUN_FLAG_MODIFIER_BIT_END;
		i++) 
		/* copy over the SYNC, NULLRW, NONEXCL, ... */
		if (chiscsi_target_lun_flag_test(from, i))
			chiscsi_target_lun_flag_set(to, i);
		else
			chiscsi_target_lun_flag_clear(to, i);

	to->size = from->size;
	
	memcpy(to->scsi_id, from->scsi_id, IT_SCSI_ID_MAX);
	memcpy(to->scsi_sn, from->scsi_sn, IT_SCSI_SN_MAX);
	memcpy(to->scsi_wwn, from->scsi_wwn, IT_SCSI_WWN_MAX);
}

extern unsigned long long total_size_of_ramdisks;
int iscsi_node_reconfig(iscsi_node *old, char *buf, unsigned int buflen,
			char *ebuf, unsigned int ebuflen,
			chiscsi_target_class *tclass)
{
	extern chiscsi_queue *it_lu_q;
	chiscsi_queue *tq;
	iscsi_node *new = NULL;
	int lun_order_changed = 0;
	int lun_rescan_needed = 0;
	int acl_changed = 0;
	int portal_removed = 0;
	int portal_timeout = 0;
	void *tmp;
	int i;
	int rv = 0;
	iscsi_session *sess;
	int old_total_size_of_ramdisks = total_size_of_ramdisks;

	/* For node reconfiguration, first we alloc/re-alloc luns and then free the
	 * the old luns. reset total_size_of_ramdisks during reconfig */
	total_size_of_ramdisks = 0;
#ifdef __ISCSI_SCST__
	if (iscsi_node_target_scst_configured(old)) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf), 
			"ERR! target %s has SCST luns.\nRefresh not supported.\n",
					old->n_name);
		os_log_info("Refresh denied for SCST target %s.\n", old->n_name);
		return -ISCSI_ENOTSUPP;
	}
#endif
	new = iscsi_node_read_config(0, buf, buflen, ebuf, ebuflen, tclass);
	if (!new)
		return -ISCSI_EINVAL;

	/* make sure the lun class and RO/NONEXCL flags are not modified */
	rv = iscsi_target_lu_duplicate_validate(1, new, ebuf, ebuflen);
	if (rv < 0)
		goto done;

	for (i = 0; i < new->lu_cnt; i++) {
		chiscsi_target_lun *lu2 = new->lu_list[i];
		chiscsi_target_lun *lu1 = lu2->lun_tmp;
		
		if (lu1) {
			/* NOTE: RO, NONEXCL and class change NOT allowed
			 * during target reconfig/updating */
			rv = lu2->class->fp_reattach(lu1, lu2, ebuf, ebuflen);
			if (rv < 0)
				goto done;
			lu1->lun_tmp = lu2;
			if (lu1->lun != lu2->lun) {
				/* no need to check further */
				lun_order_changed = 1;
				continue;
			}
			if (lu1->size != lu2->size ||
			    memcmp(lu1->scsi_id, lu2->scsi_id, IT_SCSI_ID_MAX) ||
			    memcmp(lu1->scsi_sn, lu2->scsi_sn, IT_SCSI_SN_MAX) ||
			    memcmp(lu1->scsi_wwn, lu2->scsi_wwn, IT_SCSI_WWN_MAX)) {
				os_log_info("node %s, lun %d, %s/%s rescan needed.\n",
					new->n_name, i, lu2->path, lu1->path);
					lun_rescan_needed = 1;
			}
		} else {
			lun_order_changed = 1;
			/* new target device */
			rv = lu2->class->fp_attach(lu2, ebuf, ebuflen);
			if (rv < 0)
				goto done;
			/* XXX: init persisten reservation */
			iscsi_target_lu_init_reservation(lu2);
			/* XXX: add lun to the global lu list */
#ifdef __ISCSI_SCST__
			/* Only if a SCST lun is configured, register with scst. */
			if (!os_strcmp(lu2->class->class_name, "SCST") &&
				!new->scst_target)
				new->scst_target = iscsi_scst_register(new->n_name);
#endif
		}
	}
	if (new->lu_cnt != old->lu_cnt)
		lun_order_changed = 1;

	portal_removed = config_listening_server_removed(old, new);
	portal_timeout = config_listening_server_timeout_changed(old, new);

	if (lun_order_changed || lun_rescan_needed || portal_removed)
		os_log_info("%s: lun changed %d, rescan %d, portal removed %d.\n",
			old->n_name, lun_order_changed, lun_rescan_needed,
			portal_removed);

	if (iscsi_acl_permission_check(old, new) < 0)
		acl_changed = 1;
 
	/* copy over the settings */
	iscsi_node_flag_set(old, NODE_FLAG_UPDATING_BIT);

	os_strcpy(old->n_alias, new->n_alias);
	memcpy(&old->sess_keys, &new->sess_keys,
		sizeof(struct iscsi_session_settings));
	memcpy(&old->conn_keys, &new->conn_keys,
		sizeof(struct iscsi_conn_settings));
	memcpy(&old->chap, &new->chap, sizeof(struct iscsi_chap_settings));
	for (i = 0; i < NODE_KEYS_TYPE_MAX; i++) {
		tmp = (void *)old->n_keys[i];
		old->n_keys[i] = new->n_keys[i];
		new->n_keys[i] = (iscsi_keyval *)tmp;
	}
	tmp = old->n_auth;
	old->n_auth = new->n_auth;
	new->n_auth = tmp;

	old->n_redirect_on = new->n_redirect_on;

	memcpy(&old->config_keys, &new->config_keys,
		sizeof(struct iscsi_target_config_settings));

	tmp = (void *)old->portal_list;
	old->portal_list = new->portal_list;
	new->portal_list = (iscsi_target_portal *)tmp;
	i = old->portal_cnt;
	old->portal_cnt = new->portal_cnt;
	new->portal_cnt = i;
	i = old->portal_active;
	old->portal_active = new->portal_active;
	new->portal_active = i;

	/* ACL */
	old->config_keys.acl_en = new->config_keys.acl_en;
	i = old->acl_mask_len;
	old->acl_mask_len = new->acl_mask_len;
	new->acl_mask_len = i;
	tmp = (void *)old->acl_list;	
	old->acl_list = new->acl_list;
	new->acl_list = tmp;

	if (lun_order_changed || lun_rescan_needed) {
		for (i = 0; i < new->lu_cnt; i++) {
			chiscsi_target_lun *lu = new->lu_list[i];
			chiscsi_target_lun *dup = lu->lun_tmp;
			
			/* if the lu already existed, just copy over */
			if (dup) {
				if (os_strcmp(lu->class->class_name, "MEM")) {
					new->lu_list[i] = dup;
					old->lu_list[dup->lun] = lu;
					lu->lun = dup->lun;
					dup->lun = i;
				}
				dup->size = lu->size; //Fix for lvm rescan after its size changed
				lun_copy_property(lu, dup);
				dup->lun_tmp = NULL;
			}
			/* PR 3165 fix: 
			 * ensure the tnode_hndl is updated before enqueing
			 */
			lu->tnode_hndl = (unsigned long)old;
			chiscsi_target_lun_enqueue(lock, it_lu_q, lu);
		}

		tmp = (void *)old->lu_list;
		old->lu_list = new->lu_list;
		new->lu_list = (chiscsi_target_lun **)tmp;
		i = old->lu_cnt;
		old->lu_cnt = new->lu_cnt;
		new->lu_cnt = i;

		tmp = old->scst_target;
		old->scst_target = new->scst_target;
		new->scst_target = tmp;
	} else {
		for (i = 0; i < old->lu_cnt; i++) {
			chiscsi_target_lun *lu = old->lu_list[i];

			lun_copy_property(lu, lu->lun_tmp);
			lu->lun_tmp = NULL;
		}
	}

	/* mark all sessions with proper change info. */
	tq = old->n_queue[NODE_SESSQ];
	os_lock(tq->q_lock);
	for (sess = tq->q_head; sess; sess = sess->s_next) {
		/* reset ACL */
		if (acl_changed || iscsi_node_acl_enable(old))
			iscsi_sess_flag_set(sess, SESS_FLAG_NODE_ACL_CHNG_BIT);
		if (lun_order_changed)
			iscsi_sess_flag_set(sess, SESS_FLAG_NODE_LUN_CHNG_BIT);
		if (lun_rescan_needed)
			iscsi_sess_flag_set(sess, SESS_FLAG_DEVICE_RESCAN_BIT);
		if (portal_removed)
			iscsi_sess_flag_set(sess, SESS_FLAG_NODE_PORTAL_CHNG_BIT);
	}
	os_unlock(tq->q_lock);

	iscsi_node_flag_clear(old, NODE_FLAG_UPDATING_BIT);

	if (ebuf)
                sprintf(ebuf + os_strlen(ebuf),
			"target %s updated.\n", old->n_name);
	os_log_info("target %s updated.\n", old->n_name);

	if (portal_timeout && old->n_queue[NODE_SESSQ]->q_cnt)
		iscsi_thread_wakeup_all(THREAD_FLAG_TIMEOUT_UPDATE_BIT);

done:
	total_size_of_ramdisks += old_total_size_of_ramdisks;
	iscsi_node_remove(new, 1, NULL, 0);

	return rv;
}

int iscsi_node_drop_session(unsigned long sess_hndl)
{
	iscsi_session *sess = (iscsi_session *)sess_hndl;
	
	if (!sess)
		return -ISCSI_EINVAL;

	iscsi_sess_flag_set(sess, SESS_FLAG_CLOSE_BIT);
	iscsi_schedule_session(sess);

	return 0;
}

int iscsi_node_get_session(iscsi_node *node, char *peername, char *buf,
			int buflen)
{
	chiscsi_queue *q = node->n_queue[NODE_SESSQ];
	int sess_max = q->q_cnt;
	struct  chiscsi_session_info *sess_info_list = NULL, *info;
	int baselen = os_strlen(buf);
	int len = baselen;
	int cnt;
	int i;

	if (!sess_max)
		return 0;

	sess_info_list = os_alloc(sess_max *
			sizeof(struct chiscsi_session_info), 1, 1);
	if (!sess_info_list)
		return -ISCSI_ENOMEM;

	cnt = chiscsi_get_session_info(node->n_name, peername, sess_max,
					sess_info_list);
	if (cnt < 0)
		goto out;

	len += sprintf(buf + len, "%s: session=%u, login_ip=%d.\n",
			node->n_name, q->q_cnt,
			os_data_counter_read(node->os_data));

	for (i = 0, info = sess_info_list; i < cnt; i++, info++) {
		iscsi_session *sess = (iscsi_session *)info->hndl;
		chiscsi_queue *connq = sess->s_queue[SESS_CONNQ];
		int j;

		len += sprintf(buf + len, "\nSESS: ");
		len += chiscsi_session_info_sprintf(info, buf + len);

 		for (j = 0; j < connq->q_cnt; j++) {
			struct chiscsi_connection_info cinfo;
			int rv;

			memset(&cinfo, 0,
				sizeof(struct chiscsi_connection_info));
			rv = chiscsi_get_connection_info(info->hndl, j, &cinfo);
			if (rv < 0)
				break;
			len += sprintf(buf + len, "\n\tCONN %d: \n", j);
			len += chiscsi_connection_info_sprintf(&cinfo,
								buf + len);
		}
	}

out:
	os_free (sess_info_list);
	if (cnt < 0)
		return cnt;
	return len;
}

static int node_config_display(iscsi_node *node, char *buf, int buflen,
				int detail)
{
	struct chiscsi_target_info tinfo;
	chiscsi_target_lun 	*lu;
	int baselen = os_strlen(buf);
	int len = baselen;
	int i = 0;
	int rv;

	memset(&tinfo, 0, sizeof(struct chiscsi_target_info));

	rv = chiscsi_get_target_info(node->n_name, &tinfo);
	if (rv < 0)
		return rv;

	if (len >= buflen) return 0;

	if (!detail)
		len += sprintf(buf + len, "\nTARGET: %s, id=%u, login_ip=%u\n",
				node->n_name, node->n_id,
				os_data_counter_read(node->os_data));
	else {
		len += sprintf(buf + len, "\ntarget:\n");
		len += chiscsi_target_info_sprintf(&tinfo, buf + len);
		if (len >= buflen)
			goto done;

		if (tinfo.config_keys.acl_en)
			len += iscsi_acl_config_display (node, buf + len,
						buflen - len);
		if (node->n_auth)
			len += iscsi_auth_config_display (node->n_auth,
						buf + len, buflen - len);
	}
	if (len >= buflen)
		goto done;

	len += iscsi_node_portal_display(node, buf + len, buflen - len);

	if (len >= buflen)
		goto done;

	for (i = 0; i < node->lu_cnt; i++) {
		lu = node->lu_list[i];
		len += sprintf(buf + len, "\tTargetDevice=%s,%s,",
				lu->path,
				lu->class ? lu->class->class_name : "?");
		if (lu->flags & (1 << LUN_RO_BIT))
			len += sprintf(buf + len, "RO,");
		if (lu->flags & (1 << LUN_NULLRW_BIT))
			len += sprintf(buf + len, "NULLRW,");
		if (lu->flags & (1 << LUN_SYNC_BIT))
			len += sprintf(buf + len, "SYNC,");
		if (lu->flags & (1 << LUN_NONEXCL_BIT))
			len += sprintf(buf + len, "NONEXCL,");
		if (lu->flags & (1 << LUN_NOWCACHE_BIT))
			len += sprintf(buf + len, "NOWCACHE,");
		if (lu->flags & (1 << LUN_PASSTHRU_UNKNOWN_ONLY_BIT))
			len += sprintf(buf + len, "PSMODE=1,");
		if (lu->flags & (1 << LUN_PASSTHRU_ALL_BIT))
			len += sprintf(buf + len, "PSMODE=2,");
		if (os_strlen(lu->prod_id) > 0)
			len += sprintf(buf + len, "PROD=%s,", lu->prod_id);
		if (lu->scsi_sn)
			len += sprintf(buf + len, "SN=%s,", lu->scsi_sn);
		if (lu->scsi_id)
			len += sprintf(buf + len, "ID=%s,", lu->scsi_id);
		if (lu->scsi_wwn)
			len += sprintf(buf + len, "WWN=%s,", lu->scsi_wwn);
		buf[len - 1] = '\n';
	}

done:
	return (len - baselen);
}

/*
 * node configuration retrieval
 */
int iscsi_node_retrieve_config(void *data, char *buf, int buflen, int detail)
{
	iscsi_node *node = (iscsi_node *) data;
	int     len = buf ? os_strlen(buf) : 0;

	if (node) {
		len += node_config_display(node, buf + len, buflen - len, detail);
		return len;
	}

	/* no node specified, display all */
#if 0
	iscsi_target_display_all_portals(buf + len, buflen - len);
	len = os_strlen(buf);
#endif

	for (node = iscsi_nodeq->q_head; node; node = node->n_next) {
		int     rv;

		rv = node_config_display(node, buf + len, buflen - len, detail);
		if (rv < 0)
			continue;
		len += rv;
		if (len > buflen)
			break;
	}

	return (len > buflen ? buflen : len);
}

int iscsi_node_has_dif_dix_enabled_lun(iscsi_node *node, unsigned int flag)
{
	int i;

	for (i = 0; i < node->lu_cnt; i++) {
		chiscsi_target_lun *lu = node->lu_list[i];
		if (lu && chiscsi_target_lun_flag_test(lu, flag)) {
			os_log_info("DIF/DIX flag 0x%x set for %s\n",
				flag, lu->path);
			return 1;
		}
	}
	return 0;
}
