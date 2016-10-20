#include <iscsi_target_api.h>
#include "iscsi_target_private.h"


/* for isns */
STATIC int iscsi_write_target_config(iscsi_node * node, char *buffer,
				     unsigned int buflen)
{
	unsigned int len = sizeof(unsigned int);
	unsigned int tag,cnt = 0;
	unsigned int *vp = NULL;
	unsigned int *pc = NULL;
	iscsi_target_portal *p = node->portal_list;
	char   *buf;
	int i;

	/* save room at the begining to write total len */

	/* target name */
	buf = buffer + len;
	len += os_strlen(node->n_name) + 1;
	if (len > buflen)
		goto out;
	os_strcpy(buf, node->n_name);

	/* target alias */
	if (node->n_alias) {
		buf = buffer + len;
		len += os_strlen(node->n_alias) + 1;
		if (len > buflen)
			goto out;
		os_strcpy(buf, node->n_alias);
	} else {
		buffer[len] = 0;
		len++;
	}

	buf = buffer + len;
	/* total number of portal groups */
	len += sizeof(unsigned int);
	if (len > buflen)
		goto out;
	pc = (unsigned int *) buf;
	*pc = 0;

	/* portal group tag */
	tag = p->grouptag;

	for (i = 0; i < node->portal_cnt; i++, p = node->portal_list + i) {
		/* do not include the redirect to portals */
		if (!(p->flag & ISCSI_PORTAL_FLAG_REDIRECT_TO)) {
			if(!i || p->grouptag != tag) {
				(*pc)++;
				/* order is tag,per portal count,<portal,ip>,... */
				buf = buffer + len;
				len += sizeof(unsigned int);
				if (len > buflen)
					goto out;
				*((unsigned int *) buf) = p->grouptag;
				
				if(i) {
					tag = p->grouptag;
					*vp = cnt;
					cnt = 0;
				}

				buf = buffer + len;
				len += sizeof(unsigned int);
				if (len > buflen)
					goto out;
				vp = (unsigned int *) buf;
			}
			cnt++;
			/* save portal ip and port (not ipv6 safe yet) */
			buf = buffer + len;
			len += ISCSI_IPADDR_LEN;
			if (len > buflen)
				goto out;
			memcpy(buf, p->ep.ip, ISCSI_IPADDR_LEN);

			buf = buffer + len;
			len += sizeof(unsigned int);
			if (len > buflen)
				goto out;
			*((unsigned int *) buf) = p->ep.port;
		}
	}
	*vp = cnt;
	
      out:
	if (len > buflen) {
//		os_log_error("%s: target %s need %u bytes > %u.\n", __FUNCTION__, node->n_name, len, buflen);
		return -ISCSI_ENOMEM;
	}

	*((unsigned int *) buffer) = len;
	return len;
}

/* for isns */
int iscsi_target_write_all_target_config(char *buffer, unsigned int buflen)
{
	int     rc = 0;
	int     len = sizeof(unsigned int);
	iscsi_node *node;

	os_lock(iscsi_nodeq->q_lock);
	for (node = iscsi_nodeq->q_head; node;
	     node = node->n_next) 
		if (node->config_keys.isns_register) {
			rc = iscsi_write_target_config(node, buffer + len,
						       buflen - len);
			if (rc < 0)
				break;
			len += rc;
		}
	*((unsigned int *) (buffer)) = iscsi_nodeq->q_cnt;
	os_unlock(iscsi_nodeq->q_lock);

	return len;
}
