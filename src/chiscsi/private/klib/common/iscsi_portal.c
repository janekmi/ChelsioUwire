/*
 * iscsi_portal.c -- portal struct
 */

#include <common/os_builtin.h>
#include <common/iscsi_common.h>
#include <iscsi_structs.h>
#include <iscsi_global.h>

iscsi_portal *iscsi_portal_alloc(iscsi_value * vp)
{
	iscsi_portal *portal;

	portal = os_alloc(ISCSI_PORTAL_SIZE, 1, 1);
	if (!portal) {
		return NULL;
	}

	/* os_alloc does memset() */
	if (!(portal->os_data = os_data_init((void *)portal)))
		goto os_data_fail;
	portal_counter_set(portal->os_data, 0, RD_B_CTR);
	portal_counter_set(portal->os_data, 0, WR_B_CTR);
	portal_counter_set(portal->os_data, 0, RD_CMD_CTR);
	portal_counter_set(portal->os_data, 0, WR_CMD_CTR);

	memcpy(portal->p_ep.ip, vp->v_num, ISCSI_IPADDR_LEN);
	portal->p_ep.port = vp->v_num[ISCSI_VALUE_NUM_IDX_PG_PORT];
	portal->p_timeout = vp->v_num[ISCSI_VALUE_NUM_IDX_PG_TIMEOUT];

	return portal;
os_data_fail:
	iscsi_portal_free(portal);
	return NULL;
}

int iscsi_portal_display(iscsi_portal * portal, char *buf, int buflen, char prefix, char postfix)
{
	int     baselen = os_strlen(buf);
	int     len = baselen;

	if (len >= buflen) return 0;

	if (prefix)
		buf[len++] = prefix;
	len += tcp_endpoint_sprintf(&portal->p_ep, buf + len);
	len += sprintf(buf + len, ", max. timeout=%u sec.",
				portal->p_timeout);
	if (postfix)
		buf[len++] = postfix;

	return (len - baselen);
}

/* stop portal's underlying tcp connection */
int iscsi_portal_stop_connection(iscsi_portal *portal)
{
	iscsi_connection *conn = NULL;
	char buf[256];
	int len;

	buf[0] = '\0';
	len = iscsi_portal_display(portal, buf, 256, 0, 0);
	buf[len] = '\0';

	conn = portal->p_conn;

	if (os_data_counter_read(portal->os_data) == 0)
		return 0;

	os_data_counter_dec(portal->os_data);

	if (!conn || os_data_counter_read(portal->os_data))
		return 0;

	portal->p_conn = NULL;

	iscsi_conn_flag_set(conn, CONN_FLAG_CLOSE_BIT);
	iscsi_schedule_connection(conn);

	return 0;
}

/*
 * portal queue for ipv6
 */

iscsi_portal *iscsi_portalq_find_by_addr(chiscsi_queue * q, struct tcp_endpoint *ep,
					 int lock)
{
        iscsi_portal *portal;

        if (lock)
                os_lock(q->q_lock);
        for (portal = q->q_head; portal; portal = portal->p_next) {
		if (portal->p_ep.port == ep->port &&
		    !memcmp(portal->p_ep.ip, ep->ip, ISCSI_IPADDR_LEN))
			break;
	}
	if (lock)
		os_unlock(q->q_lock);

//os_debug_msg(" portal 0x%p\n", portal);
	return portal;
}

int iscsi_portalq_free_portal(chiscsi_queue * q, iscsi_portal * portal, int lock)
{
	/* do not free the portal if there the reference count > 1 or has conn */
	if (os_data_counter_read(portal->os_data))
		return 0;
	if (portal->p_conn)
		return 0;

	if (lock)
		portal_ch_qremove(lock, q, portal);
	else
		portal_ch_qremove(nolock, q, portal);
	iscsi_portal_free(portal);
	return 1;
}

int iscsi_portalq_display(chiscsi_queue *q, char *buf, int buflen, 
			char prefix, char postfix, int lock)
{
	int     baselen = os_strlen(buf);
	int	len = baselen;
	iscsi_portal *portal;

	if (lock)
		os_lock(q->q_lock);

	for (portal = q->q_head; portal; portal = portal->p_next) {
		len += iscsi_portal_display(portal, buf + len, buflen - len, prefix, postfix);
		if (len >= buflen) 
			goto out;
	}
      out:
	if (lock)
		os_unlock(q->q_lock);

	if (len >= buflen) 
		len = buflen;
	return (len - baselen);
}
