/*
 * iSCSI Target ACL
 */

#include <iscsi_text.h>
#include <iscsi_target_api.h>
#include "iscsi_target_private.h"

int iscsi_string_is_address_ipv6(char *);
int iscsi_string_to_ip(char *buf, unsigned int *, char *, int);
int iscsi_string_to_ipv4(char *buf, unsigned int *, char *);

static void acl_ep_dump(struct tcp_endpoint *ep_list, int cnt, char *name)
{
	struct tcp_endpoint *ep = ep_list;
	char buf[80];
	int len = 0;
	int i, j;

	for (i = 0; i < cnt; i++, ep++) {
		for (j = 0; j < ISCSI_IPADDR_LEN; j++)
			len += sprintf(buf + len, "%02x ", ep->ip[j]);
		buf[len] = '\0';
		os_log_info("%s %d: %s.\n", name, i, buf);
		len = 0;
	}
}

static void acl_mask_dump(unsigned char *mask, int mask_len, char *name)
{
	char buf[80];
	int i, j, len = 0;

	for (i = 0, j = 0; j < mask_len; j++) {
		if (j && j % 16 == 0) {
			buf[len] = '\0';
			os_log_info("%s %d ~ %d: %s.\n", name, i, j - 1, buf);
			len = 0;
			i = j;
		}
		len += sprintf(buf + len, "0x%02x ", mask[j]);
	}
	buf[len] = '\0';
	os_log_info("%s %d ~ %d: %s.\n", name, i, j - 1, buf);
}

static void acl_dump(iscsi_target_acl *a, int mask_len)
{
	int i;

	os_log_info("f 0x%x, pos %u, cnt %u,%u,%u, mask 0x%p,0x%p.\n",
		a->flag, a->pos, a->iname_cnt, a->iaddr_cnt, a->taddr_cnt,
		a->rmask, a->wmask);

	if (a->iname_cnt) {
		char *s = a->iname;

		for (i = 0; i < a->iname_cnt; i++) {
			os_log_info("iname %d: %s.\n", i, s);
			s += os_strlen(s) + 1;
		}
	}

	if (a->iaddr_cnt)
		acl_ep_dump(a->iaddr_list, a->iaddr_cnt, "iaddr");

	if (a->taddr_cnt)
		acl_ep_dump(a->taddr_list, a->taddr_cnt, "taddr");

	if (a->rmask)
		acl_mask_dump(a->rmask, mask_len, "rmask");
	if (a->wmask)
		acl_mask_dump(a->wmask, mask_len, "wmask");
}

static void iscsi_acl_list_dump(iscsi_target_acl *list, unsigned int mask_len)
{
	iscsi_target_acl *a;

	for (a = list; a; a = a->next)
		acl_dump(a, mask_len);
}

static int acl_fill_in_ipaddr(int cnt, char *addr_str_list,
				struct tcp_endpoint *ep_list, char *ebuf)
{
	struct tcp_endpoint *ep = ep_list;
	char *s = addr_str_list;
	int i;
	int rv = 0;

	for (i = 0; i < cnt; i++, ep++) {
		rv = iscsi_string_to_ip(s, (unsigned int *)ep->ip,
				ebuf, iscsi_string_is_address_ipv6(s));	
		if (rv < 0)
			return rv;

		s += os_strlen(s) + 1;
	}

	return 0;
}

void iscsi_acl_list_free(iscsi_target_acl *list)
{
	iscsi_target_acl *a, *next;
	
	for (a = list; a; a = next) {
		next = a->next;
		if (a->iname_cnt)
			os_free(a->iname);
		os_free(a);
	}
}

static inline void acl_value_cleanup(iscsi_value *vp)
{
	vp->v_str_used = 0;

	if (vp->v_str[ISCSI_VALUE_STR_ACL_INAME_IDX]) {
		os_free(vp->v_str[ISCSI_VALUE_STR_ACL_INAME_IDX]); 
		vp->v_str[ISCSI_VALUE_STR_ACL_INAME_IDX] = NULL;
	}

	if (vp->v_str[ISCSI_VALUE_STR_ACL_SADDR_IDX]) {
		os_free(vp->v_str[ISCSI_VALUE_STR_ACL_SADDR_IDX]);
		vp->v_str[ISCSI_VALUE_STR_ACL_SADDR_IDX] = NULL;
	}

	if (vp->v_str[ISCSI_VALUE_STR_ACL_DADDR_IDX]) {
		os_free(vp->v_str[ISCSI_VALUE_STR_ACL_DADDR_IDX]);
		vp->v_str[ISCSI_VALUE_STR_ACL_DADDR_IDX] = NULL;
	}

	if (vp->v_str[ISCSI_VALUE_STR_ACL_LUN_IDX]) {
		os_free(vp->v_str[ISCSI_VALUE_STR_ACL_LUN_IDX]);
		vp->v_str[ISCSI_VALUE_STR_ACL_LUN_IDX] = NULL;
	}
}

static iscsi_target_acl *acl_configure(iscsi_value *vp, int luncnt,
					int mask_len, char *ebuf)
{
	iscsi_target_acl *a;
	unsigned int lunmask = vp->v_num[ISCSI_VALUE_NUM_ACL_LUN_IDX];
	unsigned int iname_cnt = vp->v_num[ISCSI_VALUE_NUM_ACL_INAME_IDX];
	unsigned int iaddr_cnt = vp->v_num[ISCSI_VALUE_NUM_ACL_SADDR_IDX];
	unsigned int taddr_cnt = vp->v_num[ISCSI_VALUE_NUM_ACL_DADDR_IDX];
	int i, j, k;
	int rv;
#ifdef __ACL_LM__
	int elen = 0;
#endif

	if (!luncnt && lunmask) {
		os_log_info("No LUN configured, ACL assume ALL:RW.\n", luncnt);
		lunmask = 0;
		vp->v_num[ISCSI_VALUE_NUM_ACL_LUNALL_IDX] = ACL_FLAG_ALLRW;
	}
	
	i = lunmask ? mask_len * 2 : 0;
	j = iaddr_cnt * sizeof(struct tcp_endpoint);
	k = taddr_cnt * sizeof(struct tcp_endpoint);
	a = os_alloc(sizeof(iscsi_target_acl) + i + j + k, 1, 1);
	if (!a) {
		os_log_error("ACL %d OOM.\n", vp->v_pos);
		return NULL;
	}

	a->iaddr_list = (struct tcp_endpoint *)(a + 1);
	a->taddr_list = a->iaddr_list + iaddr_cnt;
	if (lunmask) {
		a->rmask = (unsigned char *)(a->taddr_list + taddr_cnt);
		a->wmask = a->rmask + mask_len;
	}

	a->pos = vp->v_pos;
	if (iaddr_cnt) {
		rv = acl_fill_in_ipaddr(iaddr_cnt,
			vp->v_str[ISCSI_VALUE_STR_ACL_SADDR_IDX],
			a->iaddr_list, ebuf);
		if (rv < 0) {
			os_log_error("ACL %d sip bad.\n", vp->v_pos);
			goto err_out;
		}
		a->iaddr_cnt = iaddr_cnt;
	}
	if (taddr_cnt) {
		rv = acl_fill_in_ipaddr(taddr_cnt,
			vp->v_str[ISCSI_VALUE_STR_ACL_DADDR_IDX],
			a->taddr_list, ebuf);
		if (rv < 0) {
			os_log_error("ACL %d dip bad.\n", vp->v_pos);
			goto err_out;
		}
		a->taddr_cnt = taddr_cnt;
	}

#ifdef __ACL_LM__
        if (lunmask) {
		int rv;
		unsigned char mask;

		i = luncnt % 8;
		if (i)
			mask = (1U << i) - 1;
		else
			mask = 0xFF;

		elen = sprintf(ebuf, "ACL ");
		rv = lm_config_parse(a->rmask, a->wmask, luncnt,
				vp->v_str[ISCSI_VALUE_STR_ACL_LUN_IDX],
				ebuf + elen);
		if (rv < 0)
			goto err_out;

		/* W implies R */
		for (i = 0; i < mask_len; i++)
			a->rmask[i] |= a->wmask[i];

		/* check for ALL equivalent */
		for (i = 0; i < (mask_len - 1); i++)
			if ((a->rmask[i] & 0xFF) != 0xFF)
				break;
		if (i == (mask_len - 1) && (a->rmask[i] & mask) == mask)
			a->flag |= ACL_FLAG_ALLR;

		for (i = 0; i < (mask_len - 1); i++)
			if ((a->wmask[i] & 0xFF) != 0xFF)
				break;
		if (i == (mask_len - 1) && (a->wmask[i] & mask) == mask)
			a->flag |= ACL_FLAG_ALLW;
	} else
#endif
	{
		a->flag = vp->v_num[ISCSI_VALUE_NUM_ACL_LUNALL_IDX];
		/* W implies R */
		if (a->flag & ACL_FLAG_ALLW)
			a->flag |= ACL_FLAG_ALLR;

		/* must have at least ALLR set */
		if (a->rmask && (a->flag & ACL_FLAG_ALLR)) { 
			for (i = 0; i < mask_len; i++)
				a->rmask[i] = 0xFF;
			i = luncnt % 8;
			if (i)
				a->rmask[i] &= (1U << i) - 1;
		}
		if (a->wmask && (a->flag & ACL_FLAG_ALLW)) { 
			for (i = 0; i < mask_len; i++)
				a->wmask[i] = 0xFF;
			i = luncnt % 8;
			if (i)
				a->rmask[i] &= (1U << i) - 1;
		}
	}

	if (iname_cnt) {
		a->iname_cnt = iname_cnt;
		a->iname = vp->v_str[ISCSI_VALUE_STR_ACL_INAME_IDX];
		vp->v_str[ISCSI_VALUE_STR_ACL_INAME_IDX] = NULL;
	}

	/* clean up vp */
	acl_value_cleanup(vp);
	return a;

err_out:
	os_free(a);
	return NULL;
}

/* check dip against existing portals */
static int acl_crosscheck_dip(iscsi_target_acl *a, iscsi_node *node, char *ebuf)
{
	struct tcp_endpoint *ep = a->taddr_list;
	int i, j;

	if (!a->taddr_cnt)
		return 0;

	for (i = 0; i < a->taddr_cnt; i++, ep++) {
		for (j = 0; j < node->portal_cnt; j++) {
			iscsi_target_portal *p = node->portal_list + j;
			/* not active */
			if (!p->portal)
				continue;
			if (!memcmp(ep->ip, p->ep.ip, ISCSI_IPADDR_LEN))
				break;
		}

		if (j == node->portal_cnt) {
			char tbuf[80];

			tcp_endpoint_sprintf(ep, tbuf);
			if (ebuf)
				sprintf(ebuf, "ACL dip invalid: %s.\n", tbuf);
			os_log_info("ACL dip invalid: %s.\n", tbuf);

			return -ISCSI_EINVAL;
		}
	}

	return 0;
}

	
int iscsi_acl_config(iscsi_node *node, char *ebuf)
{
	iscsi_keyval *kvp;
	iscsi_value *vp;
	iscsi_target_acl *a, *tail = NULL;
	unsigned int lu_cnt = node->lu_cnt;

	if (!lu_cnt) {
		kvp = node->n_keys[NODE_KEYS_CONFIG] +
			ISCSI_KEY_CONF_TARGET_DEVICE;
		lu_cnt = kvp->kv_rcvcnt;
	}
	if (!lu_cnt)
		os_log_info("%s, NO lun, ACL lun list ignored.\n", node->n_name);

	/* byte mask */
	node->acl_mask_len = (node->lu_cnt + 7) / 8;

	kvp = node->n_keys[NODE_KEYS_CONFIG] + ISCSI_KEY_CONF_ACL;
	if (!node->config_keys.acl_en) {
		if (kvp->kv_rcvcnt) {
			os_log_info("%s, ACL disabled, ignore ACL settings %d.\n",
				node->n_name, kvp->kv_rcvcnt);
			kvp->kv_rcvcnt = 0;
			iscsi_value_free(kvp->kv_valp, kvp->kv_name);	
			kvp->kv_valp = NULL;
		}
		return 0;
	}

	/* acl enabled */
	if (!kvp->kv_rcvcnt) {
		os_log_warn("%s: ACLEnable=Yes, NO ACL configured.\n",
				node->n_name);
		return 0;
	}

	for (vp = kvp->kv_valp; vp; vp = vp->v_next) {
		a = acl_configure(vp, lu_cnt, node->acl_mask_len, ebuf);
		if (!a)
			return -ISCSI_EFORMAT;
		if (!node->acl_list)
			node->acl_list = a;
		else
			tail->next = a;
		tail = a;
	}

	iscsi_acl_list_dump(node->acl_list, node->acl_mask_len);

	/* check dip against existing portals */
	for (a = node->acl_list; a; a = a->next) {
		int rv = acl_crosscheck_dip(a, node, ebuf);
		if (rv < 0)
			return rv;
	}

	return 0;
}

static int acl_display(iscsi_target_acl *a, int lunmax, char *buf, int buflen)
{
	int len = 0;
	int i;

	if (a->iname_cnt) {
		char *s = a->iname;

		len += sprintf(buf + len, "iname=");
		for (i = 0; i < a->iname_cnt; i++) {
			len += sprintf(buf + len, "%s,", s);
			s += os_strlen(s) + 1;
		}
		buf[len - 1] = ';';
	}

	/* sip */
	if (a->iaddr_cnt) {
		struct tcp_endpoint *ep = a->iaddr_list;

		len += sprintf(buf + len, "sip=");
		for (i = 0; i < a->iaddr_cnt; i++, ep++) {
			len += tcp_endpoint_sprintf(ep, buf + len);
			buf[len] = ',';
			len++;
		}
		buf[len - 1] = ';';
	}

	/* dip */
	if (a->taddr_cnt) {
		struct tcp_endpoint *ep = a->taddr_list;

		len += sprintf(buf + len, "dip=");
		for (i = 0; i < a->taddr_cnt; i++, ep++) {
			len += tcp_endpoint_sprintf(ep, buf + len);
			buf[len] = ',';
			len++;
		}
		buf[len - 1] = ';';
	}

	len += sprintf(buf + len, "lun=");
	if ((a->flag & ACL_FLAG_ALLR) && (a->flag & ACL_FLAG_ALLW))
		len += sprintf(buf + len, "ALL:RW");
	else {
		if (a->flag & ACL_FLAG_ALLR)
			len += sprintf(buf + len, "ALL:R");
#ifdef __ACL_LM__
		if (a->wmask) {
			/* lun list present */
			len += lm_config_display(a->rmask, a->wmask,
					lunmax, buf + len, buflen - len);
		}
#endif
	}

	if (buf[len - 1] == ',')
		len--;
	buf[len] = '\n';
	len++;

	return len;
}

int iscsi_acl_permission_check(iscsi_node *org_node, iscsi_node *new_node)
{
	iscsi_target_acl *a = org_node->acl_list;
	iscsi_target_acl *na = new_node->acl_list;

	if (org_node->config_keys.acl_en != new_node->config_keys.acl_en)
		return  -ISCSI_ENOTSUPP;

	while(a && na) {
                if( a->flag != na->flag) {  
		       return -ISCSI_ENOTSUPP;
		}
		a++; na++;
	}

	return 0;
}

int iscsi_acl_config_display(iscsi_node *node, char *buf, int buflen)
{
	iscsi_target_acl *a;
	int len = 0;

	for (a = node->acl_list; a; a = a->next) {
		len += sprintf(buf + len, "\tACL=");	
		len += acl_display(a, node->lu_cnt, buf + len, buflen - len);
	}

	return len;
}

int iscsi_acl_isns_config(unsigned long pid, iscsi_node *node, char *buf,
			int buflen, char *ebuf)
{
	iscsi_target_acl *rm_list = NULL, *rm_tail = NULL;
	iscsi_target_acl *a, *prev, *next;
	int len = 0;
	int rv = 0;

	if (!node->config_keys.acl_en)
		return 0;

	/* remove the old acl from the same client */
	for (prev = NULL, a = node->acl_isns_list; a; a = next) {
		next = a->next;
		if (a->isns_pid == pid) {
			a->next = NULL;
			if (prev)
				prev->next = next;
			if (!rm_list)
				rm_list = a;
			else
				rm_tail->next = a;
			rm_tail =a ;
		} else
			prev = a;
	}
	if (rm_list)
		iscsi_acl_list_free(rm_list);

	while (len < buflen) {
		iscsi_value v;
		char *s = buf + len;
		int l = os_strlen(s);

		len += l + 1;

		memset(&v, 0, sizeof(iscsi_value));
		rv = kv_decode_acl(0, s, &v, ebuf);
		if (rv < 0)
			return rv;

		a = acl_configure(&v, node->lu_cnt, node->acl_mask_len, ebuf);
		if (a) {
			a->isns_pid = pid;
			a->next = node->acl_isns_list;
			node->acl_isns_list = a;
		}
		acl_value_cleanup(&v);

		if (!a)
			return -ISCSI_EFORMAT;
	}

iscsi_acl_list_dump(node->acl_isns_list, node->acl_mask_len);
	
	return rv;
}

/*
 * acl run time check
 */
static int acl_ep_match(struct tcp_endpoint *ep, struct tcp_endpoint *ep_list,
			int cnt)
{
	int i;

	for (i = 0; i < cnt; i++, ep_list++)
		if (!memcmp(ep->ip, ep_list->ip, ISCSI_IPADDR_LEN))
			return 1;
	return 0;
}

static iscsi_target_acl *acl_list_search(iscsi_target_acl *list, char *iname,
			struct tcp_endpoint *iep, struct tcp_endpoint *tep)
{
	iscsi_target_acl *a;
	iscsi_target_acl *sav = NULL;
	int match_max = 0;

	/* iname, sip and dip would NOT be null */
	for (a = list; a; a = a->next) {
		int iname_match = 1, iaddr_match = 1, taddr_match = 1;
		int match_cnt = 0;
		int i;

		if (a->iname_cnt) {
			char *s = a->iname;

			iname_match = 0;
			for (i = 0; i < a->iname_cnt; i++) {
				int l = os_strlen(s);
				if (!os_strcmp(s, iname)) {
					iname_match = 1;
					match_cnt++;
					break;
				}
				s += l + 1;
			}
		}
		if (!iname_match)
			continue;

		if (a->iaddr_cnt) {
			iaddr_match = acl_ep_match(iep, a->iaddr_list,
						a->iaddr_cnt);
			if (!iaddr_match)
				continue;
			match_cnt++;
		}

		if (a->taddr_cnt) {
			taddr_match = acl_ep_match(tep, a->taddr_list,
						a->taddr_cnt);
			if (!taddr_match)
				continue;
			match_cnt++;
		}

		/* there could be multiple matches, pick the most matches */
		if (match_cnt == 3)
			return a;

		if (match_cnt > match_max) {
			match_max = match_cnt;
			sav = a;
		}
	}

	return sav;
}

static int acl_rw_compare(iscsi_target_acl *a1, iscsi_target_acl *a2, int mask_len)
{
	if ((a1->flag & ACL_FLAG_ALLRW) != (a2->flag & ACL_FLAG_ALLRW)) {
		os_log_info("aclcmp f 0x%x != 0x%x.\n", a1->flag, a2->flag);
		return 1;
	}

	if ((a1->rmask && !a2->rmask) || (!a1->rmask && a2->rmask) ||
	    (a1->wmask && !a2->wmask) || (!a1->wmask && a2->wmask)) {
		os_log_info("aclcmp masks differ.\n", a1);
		return 1;
	}

	if (a1->rmask && a2->rmask &&
	    memcmp(a1->rmask, a2->rmask, mask_len)) {
		os_log_info("aclcmp rmasks differ.\n", a1);
		return 1;
	}

	if (a1->wmask && a2->wmask &&
	    memcmp(a1->wmask, a2->wmask, mask_len)) {
		os_log_info("aclcmp wmasks differ.\n", a1);
		return 1;
	}

	return 0;
}

static int acl_build_session_lu_list(iscsi_session *sess)
{
	iscsi_target_acl *a = sess->acl;
	iscsi_node *node = sess->s_node;

	if (a->flag & ACL_FLAG_ALLR)
		sess->acl_lu_cnt = node->lu_cnt;

#ifdef __ACL_LM__
	if (a->rmask) {
		if (sess->acl_lun_max < node->lu_cnt) {
			if (sess->acl_lun_list)
				os_free(sess->acl_lun_list);
			sess->acl_lun_list = os_alloc(sizeof(unsigned int) *
						node->lu_cnt, 1, 1);
			if (!sess->acl_lun_list) {
				os_log_info("sess 0x%p, acl lu list %d OOM.\n",
					sess, node->lu_cnt);
				return -ISCSI_ENOMEM;
			}
			sess->acl_lun_max = node->lu_cnt;
		}
		sess->acl_lu_cnt = lm_make_lun_list(a->rmask,
					sess->acl_lun_list, node->lu_cnt);
	}
#endif

	return 0;
}

static iscsi_target_acl *acl_match_connection(iscsi_session *sess,
				iscsi_connection *conn, iscsi_node *node)
{
	iscsi_target_acl *a = NULL; 

	if (node->acl_list) {
		a = acl_list_search(node->acl_list, sess->s_peer_name,
					&conn->c_isock->s_tcp.iaddr,
					&conn->c_isock->s_tcp.taddr);
	}
	if (!a && node->acl_isns_list) {
		a = acl_list_search(node->acl_isns_list, sess->s_peer_name,
					&conn->c_isock->s_tcp.iaddr,
					&conn->c_isock->s_tcp.taddr);
	}

	return a;
}	

int iscsi_acl_session_check(iscsi_session *sess)
{
	iscsi_node *node = sess->s_node;
	chiscsi_queue *connq = sess->s_queue[SESS_CONNQ];
	iscsi_connection *conn;
	iscsi_target_acl *a = NULL;
	int fail = 0;
	int rv = 0;

	os_log_info("%s, sess 0x%p, %s, acl check.\n", node->n_name, sess, sess->s_peer_name);
	for (conn = connq->q_head; conn; conn = conn->c_next) {
		iscsi_target_acl *tmp_a = acl_match_connection(sess, conn, node);
	
		if (!tmp_a) {
			os_log_info("conn 0x%p, sess 0x%p, %s, acl failed.\n",
				conn, sess, sess->s_peer_name);
			iscsi_conn_flag_set(conn, CONN_FLAG_CLOSE_BIT);
			fail++;
			continue;
		}

		if (a && tmp_a != a) {
			/* need to make sure lunmasks are the same */
			if (acl_rw_compare(a, tmp_a, node->acl_mask_len)) {
				os_log_info("sess 0x%p, conn %d, %s, acl differ.\n",
					sess, connq->q_cnt, sess->s_peer_name);
				rv = -ISCSI_ENOMATCH;
				break;
			}
		}
		a = tmp_a;
	}

	if (!a || fail == connq->q_cnt)
		rv = -ISCSI_ENOMATCH;

	if (rv < 0) {
		iscsi_sess_flag_set(sess, SESS_FLAG_CLOSE_BIT);
		return rv;
	}
	sess->acl = a;

	rv = acl_build_session_lu_list(sess);
	return rv;
}

int iscsi_acl_session_true_lun(iscsi_session *sess, int lun)
{
	iscsi_node *node = (iscsi_node *)sess->s_node;

	if (!node) {
		os_log_info("sess 0x%p, node NULL, acl fail.\n", sess);
		return -ISCSI_EINVAL;
	}

	if (lun >= node->lu_cnt) {
		if (node->lu_cnt)
			os_log_info("sess 0x%p, lun out-of-range %d/%u.\n",
				sess, lun, node->lu_cnt);
		return -ISCSI_EINVAL;
	}

	if (!iscsi_node_acl_enable(node))
		return lun;

	if (!sess->acl) {
		if (iscsi_acl_session_check(sess) < 0)
			return -ISCSI_ENOMATCH;
	}

	if (sess->acl_lu_cnt < node->lu_cnt) {
		if (lun >= node->lu_cnt) {
			os_log_info("sess 0x%p, acl lun out-of-range %d/%u.\n",
				sess, lun, sess->acl_lu_cnt);
			return -ISCSI_EINVAL;
		}
		return sess->acl_lun_list[lun];
	}

	return lun;
}

int iscsi_acl_target_accessible(iscsi_node *node, char *iname,
				struct chiscsi_tcp_endpoints *eps)
{
	if (!iscsi_node_acl_enable(node))
		return 1;

	if (node->acl_list &&
	    acl_list_search(node->acl_list, iname, &eps->iaddr, &eps->taddr))
		return 1; 

	if (node->acl_isns_list &&
	    acl_list_search(node->acl_isns_list, iname, &eps->iaddr, &eps->taddr))
		return 1;

	return 0;
}

static inline int acl_conn_precheck(iscsi_connection *conn)
{
	iscsi_session *sess = conn->c_sess;
	iscsi_node *node;

	if (!sess) {
		os_log_info("conn 0x%p, sess NULL, acl check failed.\n", conn);
		return -ISCSI_EINVAL;
	}
	node = (iscsi_node *)sess->s_node;
	if (!node) {
		os_log_info("sess 0x%p, node NULL, acl check failed.\n", sess);
		return -ISCSI_EINVAL;
	}

	if (!iscsi_node_acl_enable(node))
		return 0;

	/* need to redo the acl check */
	if (!sess->acl) {
		if (iscsi_acl_session_check(sess) < 0)
			return -ISCSI_ENOMATCH;
	}

	if (iscsi_conn_flag_test(conn, CONN_FLAG_CLOSE_BIT))
		return -ISCSI_ENOMATCH;

	return 0;
}

int iscsi_acl_connection_check(iscsi_connection *conn)
{
	iscsi_session *sess = conn->c_sess;
	iscsi_node *node;
	iscsi_target_acl *a;
	int rv;

	rv = acl_conn_precheck(conn);
	if (rv < 0)
		return rv;

	sess = conn->c_sess;
	node = (iscsi_node *)sess->s_node;
	a = acl_match_connection(sess, conn, node);
	if (!a) {
		os_log_info("conn 0x%p, sess 0x%p, %s, acl no match.\n",
			conn, sess, sess->s_peer_name);
		return -ISCSI_ENOMATCH;
	}

	if (a != sess->acl) {
		/* need to make sure lunmasks are the same */
		if (acl_rw_compare(a, sess->acl, node->acl_mask_len)) {
			os_log_info("sess 0x%p, conn 0x%p, acl differ.\n",
				sess, conn, sess->s_peer_name);
			return -ISCSI_ENOMATCH;
		}
	}

	return 0;
}

int iscsi_acl_scsi_command_check(chiscsi_scsi_command *sc)
{
	iscsi_connection *conn = sc->sc_conn;
	iscsi_session *sess = sc->sc_sess;
	iscsi_node *node;
	iscsi_target_acl *a;
	int rv, lun;

	rv = acl_conn_precheck(conn);
	if (rv < 0)
		return rv;

	rv = iscsi_acl_session_true_lun(sess, sc->sc_lun);
	if (rv < 0) {
		sc->sc_flag |= SC_FLAG_LUN_OOR;
		return 0;
	}
	sc->sc_lun_acl = lun = rv;

	sess = conn->c_sess;
	node = (iscsi_node *)sess->s_node;

	if (!iscsi_node_acl_enable(node)) {
		sc->sc_flag |= SC_FLAG_LUN_ACL_R | SC_FLAG_LUN_ACL_W;
		return 0;
	}
	a = sess->acl;

	/* always allow read */
	sc->sc_flag |= SC_FLAG_LUN_ACL_R;
	if (a->flag & ACL_FLAG_ALLW)
		sc->sc_flag |= SC_FLAG_LUN_ACL_W;
#ifdef __ACL_LM__
	else if (a->wmask) {
		rv = lm_lun_writable(a->rmask, a->wmask,
				sess->acl_lun_list[sc->sc_lun]);
		if (rv)
			sc->sc_flag |= SC_FLAG_LUN_ACL_W;
	}
#endif

	return 0;
}
