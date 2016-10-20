/*
 * iscsi target configuration (via iscsi control interface)
 */

#include <iscsi_auth_api.h>
#include <iscsi_target_api.h>
#include "iscsi_target_private.h"

extern chiscsi_queue *it_portal_q;	/* all the target portals */

static inline int redirect_to_display(iscsi_target_portal *tp,
					char *buf, int buflen)
{
	int i;
	int len = 0;

	if (!tp->redirect_to_ntags)
		return 0;

	for (i = 0; i < tp->redirect_to_ntags; i++)
		len += sprintf(buf + len, "%u,", tp->redirect_to_list[i]);
	buf[len - 1] = ']';

	return len;
}

int iscsi_node_portal_display(iscsi_node *node, char *buf, int buflen)
{
	iscsi_target_portal *p, *prev = NULL;
	unsigned int tag = node->portal_list->grouptag;
	unsigned int redirect = 0;
	int len = 0;
	int i = 0;

	/* should have at least one portal */
	for (i = 0; i < node->portal_cnt; i++, prev = p) {
		p = node->portal_list + i;
		if (!i || tag != p->grouptag) {
			if (prev) {
				len += sprintf(buf + len, "timeout=%u,",
						prev->timeout);
				if (redirect) {
					buf[len] = '[';
					len++;
					len += redirect_to_display(prev,
						buf + len, buflen - len);
				} else
					len--;
			}
			tag = p->grouptag;
			redirect = p->flag & ISCSI_PORTAL_FLAG_REDIRECT_FROM;
			if (len)
				buf[len++] = '\n';
			len += sprintf(buf + len, "\tPortalGroup=%u@", tag);
		} 

		len += tcp_endpoint_sprintf(&p->ep, buf + len);
		len += sprintf(buf + len, ",");
	}

	if (prev) {
		len += sprintf(buf + len, "timeout=%u,", prev->timeout);
		if (redirect) {
			buf[len] = '[';
			len++;
			len += redirect_to_display(prev, buf + len,
						buflen - len);
		} else
			len--;
	}

	len += sprintf(buf + len, "\n");
	return len;
}

#if 0
static void iscsi_node_portal_dump(iscsi_node *node)
{
	int i;

	os_log_info("%s, redirect_on %d, portal %u/%u:\n",
		node->n_name, node->n_redirect_on, node->portal_active,
		node->portal_cnt);
	for (i = 0; i < node->portal_cnt; i++) {
		iscsi_target_portal *tp = node->portal_list + i;
		char tbuf[80];
		int len;

		tcp_endpoint_sprintf(&tp->ep, tbuf);
		os_log_info("0x%p, %s, f 0x%x, tag %u, p 0x%p.\n",
			tp, tbuf, tp->flag, tp->grouptag, tp->portal);

		len = redirect_to_display(tp, tbuf, 80);
		if (len) {
			tbuf[len] = '\0';
			os_log_info("0x%p, redirect_to %u, %s, last %u.\n",
				tp, tp->redirect_to_ntags, tbuf,
				tp->redirect_last_select);
		}
	}
}
#endif

/*
 * iSCSI Target Portal add/remove 
 * NOTE: a portal can be in multiple portalgroups
 */
static int it_portal_start(iscsi_value *vp, iscsi_portal ** pportal)
{
	iscsi_portal *portal;
	iscsi_connection *conn;
	iscsi_thread *thp = th_main_ptr;
	int     rv = 0;
	struct tcp_endpoint ep;

	*pportal = NULL;

	memcpy (ep.ip, vp->v_num, ISCSI_IPADDR_LEN);
	ep.port = vp->v_num[ISCSI_VALUE_NUM_IDX_PG_PORT];

	portal = iscsi_portalq_find_by_addr(it_portal_q, &ep, 1);

	if (portal && portal->p_conn) {
		os_data_counter_inc(portal->os_data);
		*pportal = portal;
		return 0;
	}

	if (!portal) {
		portal = iscsi_portal_alloc(vp);
		if (!portal)
			return -ISCSI_ENOMEM;
	}

	/* open/bind/listen connection */
	conn = iscsi_connection_listen(&portal->p_ep);
	if (!conn) {
		rv = -ISCSI_EINVAL;
		goto err_out;
	}

	/* setup connection to wait for login */
	rv = iscsi_thread_add_data(thp, &conn->c_thinfo, conn);
	if (rv < 0) {
		rv = -ISCSI_EINVAL;
		goto err_out;
	}
	iscsi_conn_flag_set(conn, CONN_FLAG_THREAD_BIT);

	conn->c_portal = portal;
	portal->p_conn = conn;

	os_data_counter_set(portal->os_data, 1);

	portal_enqueue(lock, it_portal_q, portal);

	*pportal = portal;
	return 0;

err_out:
	if (conn) {
		iscsi_connection_closing(conn);
		iscsi_connection_destroy(conn);
	}
	portal_ch_qremove(lock, it_portal_q, portal);
	iscsi_portal_free(portal);
	return rv;
}


static void it_portal_fill_info(iscsi_target_portal *tp, iscsi_value *vp)
{
	memcpy(tp->ep.ip, vp->v_num, ISCSI_IPADDR_LEN);
	tp->ep.port = vp->v_num[ISCSI_VALUE_NUM_IDX_PG_PORT];
	tp->grouptag = vp->v_num[ISCSI_VALUE_NUM_IDX_PG_TAG];
	tp->timeout = vp->v_num[ISCSI_VALUE_NUM_IDX_PG_TIMEOUT];
}

static void it_portal_fill_iscsi_value(iscsi_target_portal *tp, iscsi_value *vp)
{
	/* only ip addr, port and portal group tag needed */
	memcpy(vp->v_num, tp->ep.ip, ISCSI_IPADDR_LEN);
	vp->v_num[ISCSI_VALUE_NUM_IDX_PG_PORT] = tp->ep.port;
	vp->v_num[ISCSI_VALUE_NUM_IDX_PG_TAG] = tp->grouptag;
	vp->v_num_used = ISCSI_VALUE_NUM_IDX_PG_TAG + 1;

}

static int it_portal_fill_kv_target_address(iscsi_node *node,
					iscsi_value *vp_head)
{
	int i, cnt = 0;
	iscsi_target_portal *tp;
	iscsi_value *vp;

	for (i = 0, vp = vp_head; i < node->portal_cnt; i++) {
		iscsi_value *vnext = vp->v_next;

		tp = node->portal_list + i;
		if (tp->flag & ISCSI_PORTAL_FLAG_REDIRECT_TO)
			continue;

		cnt++;
		memset(vp, 0, sizeof(iscsi_value));
		vp->v_next = vnext;

		it_portal_fill_iscsi_value(tp, vp);
		vp = vnext;
	}

	return cnt;
}

int iscsi_target_portal_find(iscsi_node *node, iscsi_portal *portal,
				unsigned int *tag, unsigned int *timeout)
{
	int i;
	
	for (i = 0; i < node->portal_cnt; i++) {
		iscsi_target_portal *tp = node->portal_list + i;
		if (tp->portal && tp->portal == portal) {
			*tag = tp->grouptag;
			*timeout = tp->timeout;
			return 0;
		}
	}
	return -ISCSI_EINVAL;
}

static int it_portal_redirect_correlate(iscsi_node *node, char *ebuf)
{
	int len = 0;
	int i, k;
	iscsi_target_portal *tp1, *tp2;
	
	for (i = 0; i < node->portal_cnt; i++) {
		char *ch;
		unsigned int tag;
		int j = 0;

		tp1 = node->portal_list + i;

		if (!tp1->redirect_str) 
			continue;
		ch = tp1->redirect_str;
		tp1->redirect_str = NULL;
		/* redirect_str is a sequence of numbers seperated by comma */
		while (*ch) {
			int found = 0;

			tag = os_strtoul(ch, &ch, 10);
			if (*ch == ',')
				ch++;

			tp1->redirect_last_select = node->portal_cnt;
			tp1->redirect_to_list[j] = tag;
			j++;

			for (k = 0; k < node->portal_cnt; k++) {
				tp2 = node->portal_list + k;
				if (tag != tp2->grouptag)
					continue;

				found = 1;
				tp2->flag |= node->config_keys.shadow_mode ?
					ISCSI_PORTAL_FLAG_REDIRECT_TO_REMOTE :
					ISCSI_PORTAL_FLAG_REDIRECT_TO_LOCAL;
				if (tp2->portal)
					tp2->portal->p_flag |= tp2->flag;
			}

			if (!found) {
				if (ebuf)
					len = sprintf(ebuf + len,
					"redirect portalgroup %u not found.\n",
					tag);
				os_log_error("redirect portal group tag %u not found.\n", tag);
				return -ISCSI_EINVAL;
			}
		}
		tp1->redirect_to_ntags = j;
	}

	for (i = 0; i < node->portal_cnt; i++) {
		tp1 = node->portal_list + i;
		if ((tp1->flag & (ISCSI_PORTAL_FLAG_REDIRECT_FROM |
			ISCSI_PORTAL_FLAG_REDIRECT_TO)) == 0) {
			char tbuf[80];

			tcp_endpoint_sprintf(&tp1->ep, tbuf);
			if (ebuf)
				len = sprintf(ebuf + len,
					"%s unknown to redirection.\n", tbuf);
			os_log_error("%s unknown to redirection.\n", tbuf);
			return -ISCSI_EINVAL;
		}
	}

	return 0;
}

int iscsi_target_portals_remove(iscsi_node *node)
{
	iscsi_target_portal *tp;
	int i;

	for (i = 0; i < node->portal_cnt; i++) {
		iscsi_portal *portal;

		tp = node->portal_list + i;
		portal = tp->portal;
		tp->portal = NULL;
		if (portal) {
			/* stop portal's connection */
			iscsi_portal_stop_connection(portal);

			if (os_data_counter_read(portal->os_data) == 0) {
				char buf[80];

				tp->portal = NULL;

				tcp_endpoint_sprintf(&tp->ep, buf);
				os_log_info("target portal stopped: %s.\n", buf);
				portal_ch_qremove(lock, it_portal_q, portal);
				iscsi_portal_free(portal);
			}
		}
	}

	return 0;
}

int iscsi_target_portals_update(iscsi_node *node, char *ebuf)
{
	int len = 0;
	iscsi_keyval *kv_portal = node->n_keys[NODE_KEYS_CONFIG] +
				ISCSI_KEY_CONF_PORTALGROUP;
	iscsi_keyval *kv_taddr = node->n_keys[NODE_KEYS_CONNECTION] +
				ISCSI_KEY_CONN_TARGET_ADDRESS;
	int shadow_mode = node->config_keys.shadow_mode;
	iscsi_value *vp;
	int cnt = 0, failed = 0;
	int rv = 0;
	iscsi_target_portal *tp;

	vp = kv_portal->kv_valp;
	while (vp && !rv) {
		int has_redirect_str = vp->v_str_used;
		char *redirect_str = has_redirect_str ? vp->v_str[0] : NULL;
		unsigned int tag = vp->v_num[ISCSI_VALUE_NUM_IDX_PG_TAG];
		int started = 0;

		if (has_redirect_str) 
			node->n_redirect_on = 1;

		/* process all of the portals in a group */
		for (; vp; vp = vp->v_next) {
			iscsi_portal *portal;
			char tbuf[80];

			if (vp->v_num[ISCSI_VALUE_NUM_IDX_PG_TAG] != tag)
				break;

			tp = node->portal_list + cnt;

			it_portal_fill_info(tp, vp);
			if (has_redirect_str)
				tp->flag |= ISCSI_PORTAL_FLAG_REDIRECT_FROM;
			else if (shadow_mode) {
				/* redirected to is a remote portal */
				tp->flag |= ISCSI_PORTAL_FLAG_REDIRECT_TO_REMOTE;
				cnt++;
				continue;
			}

			tcp_endpoint_sprintf(&tp->ep, tbuf);
			rv = it_portal_start(vp, &portal);
			if (rv < 0) {
				unsigned int *p = tp->redirect_to_list;

				if (ebuf)
					len += sprintf(ebuf + os_strlen(ebuf),
						"failed to start %s.\n", tbuf);
				os_log_error("failed to start %s.\n", tbuf);
				failed++;

				/* error out if this is for redirect */
				if (has_redirect_str)
					break;
				rv = 0;

				memset(tp, 0, sizeof(*tp));
				tp->redirect_to_list = p;
				continue;
			}

			/* listening server started okay */
			tp->portal = portal;
			if (os_data_counter_read(portal->os_data) == 1)
				os_log_info("target portal %s started.\n", tbuf);

			if (!started)
				tp->redirect_str = redirect_str;
			started++;
			node->portal_active++;
			cnt++;
		}
	}

	if (!node->portal_active) {
		os_log_info( "%s: No valid portal started!\n", node->n_name);
		if (ebuf)
			len += sprintf(ebuf + os_strlen(ebuf),
				"%s: No valid portal started!\n", node->n_name);
		rv = -ISCSI_EINVAL;
		goto err_out;
	}

	if (node->n_redirect_on) {
		rv = it_portal_redirect_correlate(node, ebuf);
		if (rv < 0)
			goto err_out;
	}

	node->portal_cnt -= failed;

	/* duplicate portal info to TargetAddress, for redirect only from
	 * address will be included (for discovery) */
	if (kv_taddr->kv_valp) {
		os_log_info("%s: TargetAddress NOT empty.\n", node->n_name);
		vp = kv_taddr->kv_valp;
		kv_taddr->kv_valp = NULL;
		iscsi_value_free(vp, kv_taddr->kv_name);
	}

	/* use portal's value list, it should have enough entries */
	vp = kv_portal->kv_valp;
	kv_portal->kv_valp = NULL;
	kv_portal->kv_rcvcnt = 0;

	//iscsi_node_portal_dump(node);

	kv_taddr->kv_valp = vp;
	kv_taddr->kv_rcvcnt = node->portal_cnt;
	rv = it_portal_fill_kv_target_address(node, vp);
	if (rv < 0)
		goto err_out;
	if (rv < node->portal_cnt) {
		/* if there are vp's left, release them. */
		kv_taddr->kv_rcvcnt = rv;
		vp = kv_taddr->kv_valp;
		for (cnt = 1; vp && cnt < kv_taddr->kv_rcvcnt;
			vp = vp->v_next, cnt++)
			;
		iscsi_value_free(vp->v_next, kv_taddr->kv_name);
		vp->v_next = NULL;
	}

	/* each value of TargetAddress be on seperate line */
	for (vp = kv_taddr->kv_valp, cnt = 0; vp; vp = vp->v_next, cnt++)
		vp->v_pos = cnt;

	return 0;

err_out:
	iscsi_target_portals_remove(node);
	return rv;
}


/* for iSNS client */
STATIC int it_portal_write_config(iscsi_portal *portal, char *buffer,
				  unsigned int buflen)
{
	int     len = 0;
	char   *buf = buffer;

	/* save the portal ip and port */
	buf = buffer + len;
	len += ISCSI_IPADDR_LEN;
	if (len > buflen)
		goto out;

	memcpy(buf, portal->p_ep.ip, ISCSI_IPADDR_LEN);
	
	buf = buffer + len;
	len += sizeof(unsigned int);
	if (len > buflen)
		goto out;
	*((unsigned int *) buf) = portal->p_ep.port;

      out:
	if (len > buflen) {
		return -ISCSI_ENOMEM;
	}

	return len;
}

int iscsi_target_write_all_target_portal_config(char *buffer,
						unsigned int buflen)
{
	int     rc = 0, redirect = 0;
	int     len = sizeof(unsigned int);
	iscsi_portal *portal;

	os_lock(it_portal_q->q_lock);
	for (portal = it_portal_q->q_head; portal; portal = portal->p_next) {
		if(!(portal->p_flag & ISCSI_PORTAL_FLAG_REDIRECT_TO)) {
			rc = it_portal_write_config(portal, buffer + len, buflen - len);
			if (rc < 0)
				break;
			len += rc;
		} else redirect++;
	}
	*((unsigned int *) (buffer)) = it_portal_q->q_cnt - redirect;
	os_unlock(it_portal_q->q_lock);
	return len;
}

/*
 * node.n_queues NODE_TARGET_PORTALQ --
 *	the per target portalgroup configuration
 */

int chiscsi_get_perf_info(struct tcp_endpoint *ep, 
			  struct chiscsi_perf_info *pdata)
{
	iscsi_portal *portal;

	if (!ep) {
		os_log_error("IP Address or port can not be empty.\n","");
		return -ISCSI_EINVAL;
	}

	portal = iscsi_portalq_find_by_addr(it_portal_q, ep, 1);

        if (!portal) {
                os_log_error("Portal not found!\n","");
                return -ISCSI_ENOTFOUND;
        }
       
	pdata->write_bytes	= portal_counter_read(portal->os_data, 
							WR_B_CTR);
	pdata->read_bytes	= portal_counter_read(portal->os_data, 
							RD_B_CTR);
	pdata->read_cmd_cnt	= portal_counter_read(portal->os_data,
							RD_CMD_CTR);
	pdata->write_cmd_cnt	= portal_counter_read(portal->os_data,
							WR_CMD_CTR);
	return 0;
}
