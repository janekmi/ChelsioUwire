/*
 * iscsi authentication
 */

#include <common/os_builtin.h>
#include "iscsi_auth_private.h"
#include "iscsi_auth_api.h"
#include <iscsi_connection_keys.h>

extern iscsi_auth_method iscsi_auth_method_tbl[];

/*
 * alloc & free of node/session/connection auth struct 
 */
void iscsi_auth_node_free(void *data)
{
	iscsi_auth_node *anode = (iscsi_auth_node *) data;
	int     i;

	if (!anode)
		return;

	for (i = 0; i < AUTH_METHOD_MAX; i++) {
		if (anode->n_method_data[i]) {
			iscsi_auth_method *method = &(iscsi_auth_method_tbl[i]);
			if (method && method->fp_node_cleanup)
				method->fp_node_cleanup(anode->
							n_method_data[i]);
			else
				os_free(anode->n_method_data[i]);
			anode->n_method_data[i] = NULL;
		}
	}

	os_free(anode);
}

void iscsi_auth_session_free(void *data)
{
	iscsi_auth_session *asess = (iscsi_auth_session *) data;
	int     i;

	if (!asess)
		return;

	for (i = 0; i < AUTH_METHOD_MAX; i++) {
		if (asess->s_method_data[i]) {
			iscsi_auth_method *method = &(iscsi_auth_method_tbl[i]);
			if (method && method->fp_session_cleanup) {
				method->fp_session_cleanup(asess->
							   s_method_data[i]);
			} else {
				os_free(asess->s_method_data[i]);
			}
			asess->s_method_data[i] = NULL;
		}
	}

	os_free(asess);
}

void iscsi_auth_connection_free(void *data)
{
	iscsi_auth_connection *aconn = (iscsi_auth_connection *) data;
	iscsi_auth_method *method;

	if (!aconn)
		return;

	method = &(iscsi_auth_method_tbl[aconn->c_method_idx]);

	if (aconn->c_method_data) {
		if (method && method->fp_connection_cleanup)
			method->fp_connection_cleanup(aconn->c_method_data);
		else
			os_free(aconn->c_method_data);
		aconn->c_method_data = NULL;
	}

	if (aconn->c_kvlist) {
		iscsi_kvlist_free(method->auth_key_max, aconn->c_kvlist);
	}

	os_free(aconn);
}

int iscsi_auth_node_size(int nodetype)
{
	return sizeof(iscsi_auth_node);
}

void   *iscsi_auth_node_alloc(int nodetype)
{
	iscsi_auth_node *anode;

	anode = os_alloc(sizeof(iscsi_auth_node), 1, 1);
	if (!anode)
		return NULL;
	/* os_alloc does memset() */
	anode->n_type = nodetype;

	return (void *) anode;
}

void   *iscsi_auth_session_alloc(void *anode)
{
	iscsi_auth_session *asess;

	asess = os_alloc(sizeof(iscsi_auth_session), 1, 1);
	if (!asess)
		return NULL;
	/* os_alloc does memset() */
	asess->s_node = anode;

	return (void *) asess;
}

void   *iscsi_auth_connection_alloc(void *asess)
{
	iscsi_auth_connection *aconn;

	aconn = os_alloc(sizeof(iscsi_auth_connection), 1, 1);
	if (!aconn)
		return NULL;
	/* os_alloc does memset() */
	aconn->c_sess = asess;

	return (void *) aconn;
}


/*
 * AuthMethod 
 */
static int auth_method_name_2_index(char *name)
{
	int     i;
	for (i = 0; i < AUTH_METHOD_MAX; i++) {
		if (!os_strcmp(name, iscsi_auth_method_tbl[i].name))
			return i;
	}
	return -ISCSI_ENOMATCH;
}

int iscsi_kv_decode_authmethod(int mode, char *buf, iscsi_value * vp, char *ebuf)
{
	int     rv;

	rv = auth_method_name_2_index(buf);
	if (rv < 0) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"WARN! AuthMethod, %s, not supported.\n",
				buf);
		os_log_info("WARN! AuthMethod: %s, not supported.\n", buf);
		return -ISCSI_EFORMAT;;
	}
	vp->v_num[0] = rv;
	vp->v_num_used = 1;
	return 0;
}

int iscsi_kv_encode_authmethod(char *buf, iscsi_value * vp)
{
	int     rv = -ISCSI_EINVAL;
	rv = sprintf(buf, "%s", iscsi_auth_method_tbl[vp->v_num[0]].name);
	return rv;
}

int iscsi_kv_size_authmethod(iscsi_value * vp)
{
	return (os_strlen(iscsi_auth_method_tbl[vp->v_num[0]].name) + 1);
}

int iscsi_auth_method_set_default(iscsi_keyval * kvp)
{
	if (!kvp->kv_valp) {
		int     i;
		/* default to all the methods we support */
		for (i = AUTH_METHOD_MAX - 1; i >= 0; i--) {
			iscsi_value *vp = iscsi_value_alloc();
			if (!vp)
				return -ISCSI_ENOMEM;
			vp->v_num[0] = i;
			vp->v_num_used = 1;
			iscsi_value_list_append(&kvp->kv_valp, vp);
		}
	}
	return 0;
}

int iscsi_auth_method_changed(void *arg, iscsi_keyval * kvp_method)
{
	iscsi_auth_node *anode = (iscsi_auth_node *) arg;
	iscsi_value *vp = kvp_method->kv_valp;
	int     i, method_cnt = 0;

	if (!vp) {
		/* should not happend */
		os_log_info("ERR! No built in auth. method found, 0x%p.\n", vp);
		return -ISCSI_EINVAL;
	}
//      iscsi_display_kvp(kvp_method, NULL, 0);

	/* mark all method as disabled */
	for (i = 0; i < AUTH_METHOD_MAX; i++) {
		anode->n_method_flag[i] &= ~AUTH_NODE_METHOD_FLAG_ENABLE;
	}

	/* now go through the value list and enable the corresponding method */
	for (vp = kvp_method->kv_valp; vp; vp = vp->v_next) {
		unsigned int idx = vp->v_num[0];
		if (idx >= AUTH_METHOD_MAX) {
			os_log_info("ERR! Auth. method invalid %u, skip.\n",
				    idx);
			continue;
		}
		anode->n_method_flag[idx] |= AUTH_NODE_METHOD_FLAG_ENABLE;
		method_cnt++;
	}

	/* check auth forced or not */
	if (anode->
	    n_method_flag[AUTH_METHOD_NONE] & AUTH_NODE_METHOD_FLAG_ENABLE) {
		anode->n_forced = 0;
		anode->n_flag &= ~AUTH_NODE_AUTHENTICATION_FORCED;
		if (method_cnt == 1)
			anode->n_flag |= AUTH_NODE_AUTHENTICATION_NONE;
	} else {
		anode->n_forced = 1;
		anode->n_flag = AUTH_NODE_AUTHENTICATION_FORCED;
		anode->n_flag &= ~AUTH_NODE_AUTHENTICATION_NONE;
	}
	return 0;
}

int iscsi_get_node_auth_settings(struct iscsi_chap_settings *chap, void *anodep)
{
	iscsi_auth_node *anode = (iscsi_auth_node *)anodep;

	chap->chap_required = anode->n_forced;
	if (anode->n_method_flag[AUTH_METHOD_CHAP] &
		AUTH_NODE_METHOD_FLAG_ENABLE)
		chap->chap_en = 1;
	return 0;
}

int iscsi_auth_config_discovery(void *arg)
{
	int i;
	iscsi_auth_node *anode = (iscsi_auth_node *) arg;

	if (!anode)
		return -ISCSI_ENULL;

	for (i = 0; i < AUTH_METHOD_MAX; i++) {
		iscsi_auth_method *method = &(iscsi_auth_method_tbl[i]);
		iscsi_keyval *kvlist;
		int rv;

		/* this method has no config keys */
		if (!method->config_key_max)
			continue;

		kvlist = iscsi_kvlist_alloc(method->config_key_max,
					    method->config_key_tbl);
		if (!kvlist)
			return -ISCSI_ENOMEM;

		rv = iscsi_kvlist_decode_pairq_discovery(CONN_STATE_CLOSED,
					       anode->n_type,
					       method->config_key_max, kvlist,
					       NULL, NULL,0);
		/* match find */
		if (rv > 0) {
			rv = method->fp_node_config(anode, kvlist, NULL,
						    0);
		}

		iscsi_kvlist_free(method->config_key_max, kvlist);
		
		if (rv < 0)
			return rv;
	}

	return 0;
}


/*
 * initiator/target node configuration -- method specific
 */

/* method specific configuration */
int iscsi_auth_config(void *arg, chiscsi_queue * pairq, char *ebuf, int ebuflen)
{
	iscsi_auth_node *anode = (iscsi_auth_node *) arg;
	int     i;

	if (!anode)
		return -ISCSI_ENULL;

	for (i = 0; i < AUTH_METHOD_MAX; i++) {
		iscsi_auth_method *method = &(iscsi_auth_method_tbl[i]);
		iscsi_keyval *kvlist;
		int     rv;

		/* config allowed even if the method is disabled */

		/* this method have no config keys */
		if (!method->config_key_max)
			continue;

		kvlist = iscsi_kvlist_alloc(method->config_key_max,
					    method->config_key_tbl);
		if (!kvlist)
			return -ISCSI_ENOMEM;

		rv = iscsi_kvlist_decode_pairq(CONN_STATE_CLOSED,
					       anode->n_type,
					       method->config_key_max, kvlist,
					       pairq, ebuf, ebuflen);
		/* match find */
		if (rv > 0) {
			rv = method->fp_node_config(anode, kvlist, ebuf,
						    ebuflen);
		}

		iscsi_kvlist_free(method->config_key_max, kvlist);
		if (rv < 0)
			return rv;
	}

	return 0;
}

/* check if the skey is one of the method's key, return the method index */
int iscsi_auth_key_match(int *kidx, char *skey)
{
	int     i;

	for (i = 0; i < AUTH_METHOD_MAX; i++) {
		iscsi_auth_method *method = &(iscsi_auth_method_tbl[i]);
		iscsi_keydef *kdef = method->config_key_tbl;
		int     j;

		/* this method have no config keys */
		if (!method->config_key_max)
			continue;

		for (j = 0; j < method->config_key_max; j++, kdef++) {
			if (!os_strcmp(skey, kdef->name)) {
				*kidx = j;
				return i;
			}
		}
	}

	return -ISCSI_ENOMATCH;
}

int iscsi_auth_config_text_size(void *arg)
{
	iscsi_auth_node *anode = (iscsi_auth_node *) arg;
	int     i;
	int     len = 0;

	if (!anode)
		return 0;

	for (i = 0; i < AUTH_METHOD_MAX; i++) {
		iscsi_auth_method *method = &(iscsi_auth_method_tbl[i]);

		/* this method is disabled */
		if (!(anode->n_method_flag[i] & AUTH_NODE_METHOD_FLAG_ENABLE))
			continue;
		/* this method has no config. keys */
		if (!method->config_key_max)
			continue;

		if (method->fp_node_text_size)
			len += method->fp_node_text_size(anode,
							 method->
							 config_key_max);
	}

	return len;
}

int iscsi_auth_config_display(void *arg, char *buf, int buflen)
{
	iscsi_auth_node *anode = (iscsi_auth_node *) arg;
	int     i;
	int     len = 0;

	if (!anode)
		return 0;

	for (i = 0; i < AUTH_METHOD_MAX; i++) {
		iscsi_auth_method *method = &(iscsi_auth_method_tbl[i]);

		/* this method is disabled */
		if (!(anode->n_method_flag[i] & AUTH_NODE_METHOD_FLAG_ENABLE))
			continue;

		/* this method has no config. keys */
		if (!method->config_key_max)
			continue;

		len += method->fp_node_display(anode, method->config_key_max,
					       buf + len, buflen - len);
		if (len >= buflen)
			break;
	}

	return ((len >= buflen) ? buflen : len);
}

int iscsi_auth_config_key_size(void *arg, int midx, int kidx)
{
	iscsi_auth_node *anode = (iscsi_auth_node *) arg;
	iscsi_auth_method *method = &(iscsi_auth_method_tbl[midx]);

	if (midx >= AUTH_METHOD_MAX) {
		os_log_info("ERR! method invalid %d, kidx %d.\n", midx, kidx);
		return -ISCSI_EINVAL;
	}
	if (!anode)
		return 0;

	method = &(iscsi_auth_method_tbl[midx]);

	if (method->fp_node_text_size)
		return (method->fp_node_text_size(anode, kidx));

	return 0;
}

static int iscsi_auth_config_set_method_default(iscsi_auth_node * anode,
						int midx, char *ebuf,
						int ebuflen)
{
	int len = ebuf ? os_strlen(ebuf) : 0;

	if (midx >= AUTH_METHOD_MAX) {
		if (ebuf && len < ebuflen)
			sprintf(ebuf + len,
				"ERR! Method invalid %d, default not set.\n",
				midx);
		os_log_info("ERR! Method invalid %d, default not set.\n", midx);
		return -ISCSI_EINVAL;
	}

	if (!anode->n_method_data[midx]) {
		int     rv;
		iscsi_auth_method *method = &(iscsi_auth_method_tbl[midx]);
		iscsi_keyval *kvlist =
			iscsi_kvlist_alloc(method->config_key_max,
					   method->config_key_tbl);
		if (!kvlist)
			return -ISCSI_ENOMEM;
		rv = method->fp_node_config(anode, kvlist, ebuf + len, ebuflen - len);
		iscsi_kvlist_free(method->config_key_max, kvlist);
		return rv;
	}
	return 0;
}

int iscsi_auth_config_get(void *arg, int midx, int kidx, char *ebuf,
			  int ebuflen)
{
	iscsi_auth_node *anode = (iscsi_auth_node *) arg;
	iscsi_auth_method *method;
	int	baselen = ebuf ? os_strlen(ebuf) : 0;
	int	len = baselen;
	int     rv;

	if (midx >= AUTH_METHOD_MAX) {
		if (ebuf && len < ebuflen)
			sprintf(ebuf + len,
				"ERR! Method invalid %d, no config get.\n",
				midx);
		os_log_info("ERR! Method invalid %d, no config get.\n", midx);
		return -ISCSI_EINVAL;
	}

	if (!anode)
		return 0;

	method = &(iscsi_auth_method_tbl[midx]);
	if (!anode->n_method_data[midx]) {
		rv = iscsi_auth_config_set_method_default(anode, midx,
							  ebuf + len,
							  ebuflen - len);
		if (rv < 0)
			return rv;
	}

	rv = method->fp_node_display(anode, kidx, ebuf + len, ebuflen - len);
	return rv;
}

int iscsi_auth_config_add(void *arg, int midx, int kidx, char *vbuf, char *ebuf,
			  int ebuflen)
{
	iscsi_auth_node *anode = (iscsi_auth_node *) arg;
	iscsi_auth_method *method;
	iscsi_keyval *kvp;
	int	len = ebuf ? os_strlen(ebuf) : 0;
	int     rv;

	if (!anode)
		return -ISCSI_ENULL;

	if (midx >= AUTH_METHOD_MAX) {
		if (ebuf)
			sprintf(ebuf + len,
				"ERR! Method invalid %d, no config add.\n",
				midx);
		os_log_info("ERR! Method invalid %d, no config add.\n", midx);
		return -ISCSI_EINVAL;
	}

	/* config changed is allowed even if the method is disabled */

	method = &(iscsi_auth_method_tbl[midx]);

	kvp = iscsi_kvp_alloc();
	if (!kvp)
		return -ISCSI_ENOMEM;

	kvp->kv_def = method->config_key_tbl + kidx;
	kvp->kv_name = kvp->kv_def->name;
	rv = iscsi_kvp_decode_buffer(ISCSI_KV_DECODE_OP_ADD,
				     anode->n_type, CONN_STATE_CLOSED,
				     kvp, vbuf, ebuf, ebuflen);
	if (rv < 0)
		goto done;

	/* no error in decoding */
	if (!anode->n_method_data[midx]) {
		rv = iscsi_auth_config_set_method_default(anode, midx, ebuf,
							  ebuflen);
		if (rv < 0)
			goto done;
	}
	rv = method->fp_node_config_add(anode, kvp, kidx, ebuf, ebuflen);

      done:
	iscsi_kvp_free(kvp);
	return rv;
}

int iscsi_auth_config_remove(void *arg, int midx, int kidx, char *vbuf,
			     char *ebuf, int ebuflen)
{
	iscsi_auth_node *anode = (iscsi_auth_node *) arg;
	iscsi_auth_method *method;
	iscsi_keydef *kdefp;
	iscsi_keyval *kvp = NULL;
	int	len = ebuf ? os_strlen(ebuf) : 0;
	int     rv = 0;

	if (midx >= AUTH_METHOD_MAX) {
		if (ebuf && len < ebuflen)
			sprintf(ebuf + len,
				"ERR! Method invalid %d, no config removed.\n",
				midx);
		os_log_info("ERR! Method invalid %d, no config removed.\n",
			    midx);
		return -ISCSI_EINVAL;
	}

	if (!anode)
		return -ISCSI_ENULL;

	/* config changed is allowed even if the method is disabled */
	method = &(iscsi_auth_method_tbl[midx]);
	kdefp = method->config_key_tbl + kidx;

	if (vbuf && !(kdefp->property & ISCSI_KEY_DECLARE_MULTIPLE)) {
		if (ebuf && len < ebuflen)
			len += sprintf(ebuf + len,
				"%s: previously configured value removed.\n",
				kdefp->name);
		os_log_warn
			("remove %s: ignore %s, remove previously configured value.\n",
			 kdefp->name, vbuf);
		vbuf = NULL;
	}

	if (vbuf) {
		kvp = iscsi_kvp_alloc();
		if (!kvp)
			return -ISCSI_ENOMEM;
		kvp->kv_def = kdefp;
		kvp->kv_name = kdefp->name;
		rv = iscsi_kvp_decode_buffer(ISCSI_KV_DECODE_OP_REMOVE,
					     anode->n_type, CONN_STATE_CLOSED,
					     kvp, vbuf, ebuf, ebuflen);
	}
	if (rv < 0)
		goto done;

	/* no error in decoding */
	if (!anode->n_method_data[midx]) {
		rv = iscsi_auth_config_set_method_default(anode, midx, ebuf,
							  ebuflen);
		if (rv < 0)
			goto done;
	}

	rv = method->fp_node_config_remove(anode, kvp, kidx, ebuf, ebuflen);

      done:
	iscsi_kvp_free(kvp);
	return rv;
}


/*
 * iscsi connection authentication processing
 */
int iscsi_connection_auth_done(iscsi_connection * conn, void *arg)
{
	iscsi_auth_node *anode = (iscsi_auth_node *) arg;
	iscsi_auth_connection *aconn = (iscsi_auth_connection *) conn->c_auth;
	
	/* went through the authentication phase */
	if (aconn) {
		return ((aconn->c_state == AUTH_STATE_DONE) ? 1 : 0);
	}

	if (anode->n_type == ISCSI_INITIATOR) {
		/* no authentication method other than "NONE" is configured */
		if (anode->n_flag & AUTH_NODE_AUTHENTICATION_NONE)
			return 1;
	} else {
		/* have not gone through the authentication phase */
		if (!anode->n_forced)
			return 1;
	}

	return 0;
}

int iscsi_connection_auth_size_resp(iscsi_connection * conn)
{
	iscsi_auth_connection *aconn = (iscsi_auth_connection *) conn->c_auth;

	if (aconn && aconn->c_kvlist) {
		return (iscsi_kvlist_size_text
			(aconn->c_kv_max, aconn->c_kvlist));
	}
	return 0;
}

int iscsi_connection_auth_write_resp(iscsi_connection * conn, char *buf,
				     int buflen)
{
	iscsi_auth_connection *aconn = (iscsi_auth_connection *) conn->c_auth;

	if (aconn && aconn->c_kvlist) {
		return (iscsi_kvlist_write_text
			(aconn->c_kv_max, aconn->c_kvlist, 0,
			 ISCSI_KV_FLAG_SEND, ISCSI_KV_WRITE_NO_SEPERATOR, 0,
			 buf, buflen, 1));
	}

	return 0;
}

int iscsi_connection_auth_init(iscsi_connection *conn, void *arg)
{
	iscsi_auth_node *anode = (iscsi_auth_node *) arg;
	iscsi_session *sess = conn->c_sess;
	iscsi_auth_session *asess = (iscsi_auth_session *) sess->s_auth;
	iscsi_auth_connection *aconn = (iscsi_auth_connection *) conn->c_auth;


	if (!asess) {
		asess = iscsi_auth_session_alloc(anode);
		if (!asess)
			goto err_out;
		asess->s_state = AUTH_STATE_PROCESS;
		asess->s_node = anode;
		sess->s_auth = (void *) asess;
	}

	aconn = iscsi_auth_connection_alloc(asess);
	if (!aconn)
		goto err_out;
	conn->c_auth = (void *) aconn;

	return 0;

err_out:
	conn->login.status_class = ISCSI_LOGIN_STATUS_CLASS_TARGET_ERROR;
	conn->login.status_detail = ISCSI_LOGIN_STATUS_DETAIL_NO_RESOURCES;
	return -ISCSI_ENOMEM;
}

void iscsi_connection_auth_target_process(iscsi_connection *conn, 
					  chiscsi_target_class *tclass,
					  chiscsi_queue *pairq)
{
	iscsi_session *sess = conn->c_sess;
	iscsi_node *node = sess->s_node;
	iscsi_auth_session *asess = (iscsi_auth_session *) sess->s_auth;
	iscsi_auth_node *anode = asess->s_node;
	iscsi_auth_connection *aconn = (iscsi_auth_connection *) conn->c_auth;
	iscsi_auth_method *method;
	int     rv;
	/* select the method */
	if (aconn->c_state == AUTH_STATE_UNKNOWN) {
		iscsi_keyval *kvp = conn->c_keys + ISCSI_KEY_CONN_AUTH_METHOD;
		iscsi_value *vp = kvp->kv_valp;

		if (kvp->kv_flags & ISCSI_KV_FLAG_REJECT) {
			kvp->kv_flags |= ISCSI_KV_FLAG_SEND;
			return;
		}

		/* no AuthMethod specified */
		if (!vp) {
			/* is authentication forced on this node ? */
			if (anode->n_forced) {
				os_log_warn
					("No valid AuthMethod, Authentication forced %d.\n",
					 anode->n_forced);
				goto auth_failure;
			} else {
				aconn->c_method_idx = AUTH_METHOD_NONE;
				aconn->c_state = AUTH_STATE_DONE;
				return;
			}
		}

		for (; vp; vp = vp->v_next) {
			unsigned int method = vp->v_num[0];
			if ( (anode->n_method_flag[method] &
			      AUTH_NODE_METHOD_FLAG_ENABLE) &&
			     ( (method == AUTH_METHOD_NONE) || 
				(anode->n_method_data[method]) ) ) {
				break;
			}
		}
		/* no matching auth method find */
		if (!vp) {
			os_log_info("No valid AuthMethod found, 0x%p.\n",
				    kvp->kv_valp);
			kvp->kv_flags |= ISCSI_KV_FLAG_REJECT;
			goto initiator_error;
		}

		aconn->c_method_idx = vp->v_num[0];

		if (aconn->c_method_idx == AUTH_METHOD_NONE && !anode->n_forced)
			aconn->c_state = AUTH_STATE_DONE;
		else
			aconn->c_state = AUTH_STATE_PROCESS;

		/* update the AuthMethod, and send back */
		kvp->kv_valp->v_num[0] = vp->v_num[0];
		vp = kvp->kv_valp->v_next;
		kvp->kv_valp->v_next = NULL;
		if (vp)
			iscsi_value_free(vp, kvp->kv_name);
		kvp->kv_flags |= ISCSI_KV_FLAG_SEND;
		return;
	}

	/* no authentication needed, stop right here */
	if (aconn->c_method_idx == AUTH_METHOD_NONE) {
		if (aconn->c_state != AUTH_STATE_DONE)
			aconn->c_state = AUTH_STATE_DONE;
	}

	method = &(iscsi_auth_method_tbl[aconn->c_method_idx]);

	/* free the last round of kvlist */
	if (aconn->c_kvlist) {
		iscsi_kvlist_free(method->auth_key_max, aconn->c_kvlist);
		aconn->c_kvlist = NULL;
	}

	if (!method->auth_key_max)
		return;

	aconn->c_kv_max = method->auth_key_max;
	aconn->c_kvlist = iscsi_kvlist_alloc(method->auth_key_max,
					     method->auth_key_tbl);
	if (!aconn->c_kvlist)
		goto target_error;

	if (!pairq)
		goto initiator_error;

	rv = iscsi_kvlist_decode_pairq(conn->c_state, anode->n_type,
				       method->auth_key_max,
				       aconn->c_kvlist, pairq, NULL, 0);
	if (rv < 0)
		goto initiator_error;

	/* match find */
	/* check for key decoding error */
	if (rv > 0) {
		int     i;
		iscsi_keyval *kvp;

		for (kvp = aconn->c_kvlist, i = 0; i < aconn->c_kv_max;
		     i++, kvp++) {
			if (kvp->kv_rcvcnt
			    && (kvp->kv_flags & ISCSI_KV_FLAG_RESPONSE))
				goto initiator_error;
		}
	}

#if 1
	method->fp_conn_process(aconn, tclass, sess->s_peer_name,
				node->n_name, &conn->login.status_class, 
				&conn->login.status_detail);
#endif

	return;

initiator_error:
	conn->login.status_class = ISCSI_LOGIN_STATUS_CLASS_INITIATOR_ERROR;
	conn->login.status_detail = ISCSI_LOGIN_STATUS_DETAIL_INIT_ERROR;
	return;
target_error:
	conn->login.status_class = ISCSI_LOGIN_STATUS_CLASS_TARGET_ERROR;
       	conn->login.status_detail = ISCSI_LOGIN_STATUS_DETAIL_NO_RESOURCES;
	return;
auth_failure:
	conn->login.status_class = ISCSI_LOGIN_STATUS_CLASS_INITIATOR_ERROR;
	conn->login.status_detail = ISCSI_LOGIN_STATUS_DETAIL_AUTH_FAILURE;
	return;
}

int iscsi_connection_auth_process(iscsi_connection * conn, void *arg,
				  chiscsi_queue * pairq, char *next_state_done)
{
	iscsi_session *sess = conn->c_sess;
	iscsi_auth_node *anode = (iscsi_auth_node *) arg;
	iscsi_auth_session *asess = (iscsi_auth_session *) sess->s_auth;
	iscsi_auth_connection *aconn = (iscsi_auth_connection *) conn->c_auth;
	iscsi_auth_method *method;
	int     rv;

	*next_state_done = 0;
	if (!asess) {
		asess = iscsi_auth_session_alloc(anode);
		if (!asess)
			return -LOGIN_TARGET_ERROR;
		asess->s_state = AUTH_STATE_PROCESS;
		asess->s_node = anode;
		sess->s_auth = (void *) asess;
	}

	if (!aconn) {
		aconn = iscsi_auth_connection_alloc(asess);
		if (!aconn)
			return ((anode->n_type == ISCSI_INITIATOR) ?
				-LOGIN_INITIATOR_ERROR : -LOGIN_TARGET_ERROR);
		conn->c_auth = (void *) aconn;

		if (anode->n_type == ISCSI_INITIATOR) {
			char method_none = 0;
			/* send AuthMethod back */
			iscsi_keyval *kvp =
				conn->c_keys + ISCSI_KEY_CONN_AUTH_METHOD;
			iscsi_value *vlist = NULL;
			iscsi_value *vpnext, *vp = kvp->kv_valp;

			kvp->kv_flags |= ISCSI_KV_FLAG_SEND;

			/* the default is all methods supported, but the user
			   may not have configured all of them, so send only 
			   configured ones back */
			for (vp = kvp->kv_valp; vp; vp = vpnext) {
				unsigned int method = vp->v_num[0];
				vpnext = vp->v_next;
				vp->v_next = NULL;

				if ( (anode->n_method_flag[method] &
				      AUTH_NODE_METHOD_FLAG_ENABLE) &&
				     ( (method == AUTH_METHOD_NONE) || 
				       (anode->n_method_data[method]) ) ) {
					iscsi_value_list_append(&vlist, vp);
					if  (method == AUTH_METHOD_NONE)
					   method_none = 1;
					continue;
				}

				/* drop the method */
				iscsi_value_free(vp, kvp->kv_name);
			}

			kvp->kv_valp = vlist;
			/* if method "None" is selected, the next state could
			   be done depends on the target selection */ 
			if (method_none)
				*next_state_done = 1;
			return 0;
		}
	}

	/* select the method */
	if (aconn->c_state == AUTH_STATE_UNKNOWN) {
		iscsi_keyval *kvp = conn->c_keys + ISCSI_KEY_CONN_AUTH_METHOD;
		iscsi_value *vp = kvp->kv_valp;

		if (kvp->kv_flags & ISCSI_KV_FLAG_REJECT) {
			kvp->kv_flags |= ISCSI_KV_FLAG_SEND;
			return 0;
		}

		/* no AuthMethod specified */
		if (!vp) {
			/* is authentication forced on this node ? */
			if (anode->n_forced) {
				os_log_warn
					("No valid AuthMethod, Authentication forced %d.\n",
					 anode->n_forced);
				return -LOGIN_FAILED_AUTH;
			} else {
				aconn->c_method_idx = AUTH_METHOD_NONE;
				aconn->c_state = AUTH_STATE_DONE;
				return 0;
			}
		}

		for (; vp; vp = vp->v_next) {
			unsigned int method = vp->v_num[0];
			if ( (anode->n_method_flag[method] &
			      AUTH_NODE_METHOD_FLAG_ENABLE) &&
			     ( (method == AUTH_METHOD_NONE) || 
				(anode->n_method_data[method]) ) ) {
				break;
			}
		}
		/* no matching auth method find */
		if (!vp) {
			os_log_info("No valid AuthMethod found, 0x%p.\n",
				    kvp->kv_valp);
			kvp->kv_flags |= ISCSI_KV_FLAG_REJECT;
			return -LOGIN_INITIATOR_ERROR;
		}

		aconn->c_method_idx = vp->v_num[0];

		if (aconn->c_method_idx == AUTH_METHOD_NONE && !anode->n_forced)
			aconn->c_state = AUTH_STATE_DONE;
		else
			aconn->c_state = AUTH_STATE_PROCESS;

		/* update the AuthMethod, and send back */
		kvp->kv_valp->v_num[0] = vp->v_num[0];
		vp = kvp->kv_valp->v_next;
		kvp->kv_valp->v_next = NULL;
		if (vp)
			iscsi_value_free(vp, kvp->kv_name);
		kvp->kv_flags |= ISCSI_KV_FLAG_SEND;
		return 0;
	}

	/* no authentication needed, stop right here */
	if (aconn->c_method_idx == AUTH_METHOD_NONE) {
		if (aconn->c_state != AUTH_STATE_DONE)
			aconn->c_state = AUTH_STATE_DONE;
	}

	method = &(iscsi_auth_method_tbl[aconn->c_method_idx]);

	/* free the last round of kvlist */
	if (aconn->c_kvlist) {
		iscsi_kvlist_free(method->auth_key_max, aconn->c_kvlist);
		aconn->c_kvlist = NULL;
	}

	if (!method->auth_key_max)
		return 0;

	aconn->c_kv_max = method->auth_key_max;
	aconn->c_kvlist = iscsi_kvlist_alloc(method->auth_key_max,
					     method->auth_key_tbl);
	if (!aconn->c_kvlist)
		return -LOGIN_TARGET_ERROR;

	/* the pairq could be NULL for initiator node: the 1st login request */
	if (pairq)
		rv = iscsi_kvlist_decode_pairq(conn->c_state, anode->n_type,
					       method->auth_key_max,
					       aconn->c_kvlist, pairq, NULL, 0);
	else
		rv = -ISCSI_EINVAL;

	if (rv < 0)
		return rv;

	/* match find */

	/* check for key decoding error */
	if (rv > 0) {
		int     error = -LOGIN_INITIATOR_ERROR;
		int     i;
		iscsi_keyval *kvp;

		for (kvp = aconn->c_kvlist, i = 0; i < aconn->c_kv_max;
		     i++, kvp++) {
			if (kvp->kv_rcvcnt
			    && (kvp->kv_flags & ISCSI_KV_FLAG_RESPONSE))
				return error;
		}
	}

	rv = method->fp_conn_process(aconn,NULL,NULL,NULL,NULL,NULL);
	if (rv > 0) *next_state_done = 1;

	return rv;
}
