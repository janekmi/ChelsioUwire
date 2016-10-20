/*
 * isns iscsi target functions
 */

#include "isns.h"
#include "isns_sock.h"
#include "isns_pdu.h"
#include "isns_globals.h"
#include "isns_target.h"
#include "../common/iscsictl_private.h"

/* an iscsi target */
struct target {
	struct target *t_next;
	unsigned int t_flag;
	char    t_name[256];
	char    t_alias[256];
	queue   t_portalq;
	queue   t_peerq;
	unsigned int t_transaction;
};
#define target_enqueue(Q,P) ch_enqueue_tail(struct target,t_next,Q,P)
#define target_dequeue(Q,P) ch_dequeue_head(struct target,t_next,Q,P)
#define target_ch_qremove(Q,P) ch_qremove(struct target,t_next,Q,P)
#define target_qsearch_by_transaction(Q,P,V)  \
		qsearch_by_field(struct target,t_next,Q,P,t_transaction,V)

#define targetq_find_by_name(Q,name) ({\
		struct target	*__t; 	\
		for (__t = (Q)->q_head; __t; __t = __t->t_next) { \
			if (!(strcmp(name, __t->t_name))) break; \
		} \
		__t; })

#define target_alloc() ({ \
		struct target	*__t = malloc(sizeof(struct target)); \
		if (__t) { \
			isns_log_debug("target alloc %p.\n", __t); \
			memset(__t, 0, sizeof(struct target)); \
			ch_queue_init(&(__t->t_peerq));\
			ch_queue_init(&(__t->t_portalq));\
		} else { \
			isns_log_error("out of memory (target).\n"); \
		} \
		__t; })

#define target_free(target) \
		do { \
			if (target) { \
				struct portal	*__p, *__n = NULL; \
				struct peer	*__pr, *__nr = NULL; \
				for (__p = (target)->t_portalq.q_head; __p; __p = __n) { \
					__n = __p->p_next; \
					portal_free(__p); \
				} \
				for (__pr = (target)->t_peerq.q_head; __pr; __pr = __nr) { \
					__nr = __pr->p_next; \
					peer_free(__pr); \
				} \
				isns_log_debug("target free %p.\n", target); \
				free(target); \
				/* target = NULL;*/ \
			} \
		} while(0)

#define target_dump(t) \
		do { \
			isns_log_msg("\ntarget: %s.\n", (t)->t_name); \
			isns_log_msg_to_file("target\t: %s\n",(t)->t_name); \
			isns_log_msg_to_file("\ttargetalias \t: %s\n",t->t_alias); \
			isns_log_msg("\ttarget portals:\n"); \
			portalq_dump(&(t)->t_portalq); \
			isns_log_msg("\ttarget peers (initiators):\n"); \
			peerq_dump(&(t)->t_peerq); \
		} while(0)

queue   targetq;		/* all targets */
queue   portalq;		/* all target portals */
struct target *lead_target = NULL;

extern int isns_log;
extern FILE* fp;
/*
 * iscsi target portals configuration
 */
static void isns_target_set_all_portals(char *pdu)
{
	struct portal *p;
	/* write all available portals */
	for (p = portalq.q_head; p; p = p->p_next) {
		isns_pdu_write_attr_ip(pdu, p->p_ip, ISNS_ATTR_PORTALIP_TAG,
				       ISNS_ATTR_PORTALIP_LENGTH);
		isns_pdu_write_attr(pdu, ISNS_ATTR_PORTALPORT_TAG,
				    ISNS_ATTR_PORTALPORT_LENGTH, NULL,
				    p->p_port);
	}
}

int isns_update_target_portals(isns_sock * sock, char *buf, int blen)
{
	int     rv = 0, i;
	unsigned int pcnt;

	/* build portalq */
	isns_log_debug("target portalq release all portals.\n");
	portalq_release_all(&portalq);

	pcnt = *((unsigned int *) buf);
	buf += sizeof(unsigned int);
	if (!pcnt)
		return 0;

	for (i = 0; i < pcnt; i++) {
		struct portal *portal = portal_alloc();
		if (!portal)
			return -ENOMEM;

		memcpy(portal->p_ip, (unsigned int *) buf, sizeof(unsigned int) * 4);
		buf += sizeof(unsigned int) * 4;

		portal->p_port = *((unsigned int *) buf);
		buf += sizeof(unsigned int);

		portal_enqueue(&portalq, portal);

		isns_log_debug
			("target portalq: add portal %p, ip=0x%x, port=%u.\n",
			 portal, portal->p_ip, portal->p_port);
	}

	return rv;
}

/*
 * iscsi target configuration
 */
static int isns_target_parse_info(char *buf, int blen)
{
	int     rv = 0;
	int     i, j, k;
	unsigned int target_cnt, pg_cnt, portal_cnt, target_len;
	struct target *target;

	target_cnt = *((unsigned int *) buf);
	buf += sizeof(unsigned int);

	for (i = 0; i < target_cnt; i++) {
		int     changed = 0;
		int     target_new = 0;
		u_int32_t tpgt;

		target_len = *((unsigned int *) buf);
		buf += sizeof(unsigned int);

		/* prevent isns from exporting empty portals with no targets */	
		if(!target_len)
			return 0;

		/* target name */
		target = targetq_find_by_name(&targetq, buf);
		if (!target) {
			target_new = 1;
			target = target_alloc();
			if (!target)
				return -ENOMEM;
			strcpy(target->t_name, buf);
			isns_log_debug("targetq: add target %p, %s.\n", target,
				       target->t_name);
		} else {
			struct portal *p;
			for (p = target->t_portalq.q_head; p; p = p->p_next)
				p->p_flag = ISNS_FLAG_UPDATING;
		}
		buf += strlen(buf) + 1;

		/* target alias */
		if (!target_new) {
			/* check for alias change */
			if (strcmp(target->t_alias, buf))
				changed = 1;
		}
		if (*buf) {
			strcpy(target->t_alias, buf);
			buf += strlen(buf) + 1;
		} else {
			target->t_alias[0] = 0;
			buf++;
		}

		pg_cnt = *((unsigned int *) buf);
		buf += sizeof(unsigned int);

		for (j = 0; j < pg_cnt; j++) {
			tpgt = *((unsigned int *) buf);
			buf += sizeof(unsigned int);

			portal_cnt = *((unsigned int *) buf);
			buf += sizeof(unsigned int);

			for (k = 0; k < portal_cnt; k++) {
				int     portal_new = 0;
				unsigned int ip[4], port;
				struct portal *portal = NULL;

				memcpy(ip, (unsigned int *) buf, sizeof(unsigned int) * 4);
				buf += sizeof(unsigned int) * 4;

				port = *((unsigned int *) buf);
				buf += sizeof(unsigned int);

				if (!target_new) {
					portal = portalq_find_by_addr(&target->
								      t_portalq,
								      ip, port);
					if (portal) {
						portal->p_flag &=
							~ISNS_FLAG_UPDATING;
						if (portal->p_tag != tpgt) {
							changed = 1;
						}
					}
				}
				if (!portal) {
					portal_new = 1;
					changed = 1;
					portal = portal_alloc();
					if (!portal) {
						rv = -ENOMEM;
						goto err_out;
					}
					isns_log_debug
						("targetq: target %s(%p), add portal %p.\n",
						 target->t_name, target,
						 portal);
				}

				memcpy(portal->p_ip, ip, sizeof(unsigned int) * 4);
				portal->p_port = port;
				portal->p_tag = tpgt;

				if (portal_new) {
					portal_enqueue(&target->t_portalq,
						       portal);
				}
			}
		}

		if (target_new) {
			target_enqueue(&targetq, target);
		} else {
			struct portal *p;
			for (p = target->t_portalq.q_head; p;) {
				struct portal *next = p->p_next;
				if (p->p_flag & ISNS_FLAG_UPDATING) {
					isns_log_debug
						("targetq: target %s(%p), remove portal %p.\n",
						 target->t_name, target, p);
					changed = 1;
					portal_ch_qremove(&target->t_portalq, p);
					portal_free(p);
				}
				p = next;
			}
			target->t_flag &= ~ISNS_FLAG_UPDATING;
			if (changed) {
				target->t_flag |= ISNS_FLAG_CHANGED;
			}
		}

		continue;

err_out:
		/* free target */
		if (target_new && target) {
			isns_log_debug("error, target %p remove.\n", target);
			target_free(target);
		}
		return rv;
	}

	return 0;
}

static int isns_target_register(isns_sock * sock, struct target *t)
{
	char    pdu[ISNS_PDU_MAX_LENGTH];
	int     rv;
	struct portal *portal;

	memset(pdu, 0, ISNS_PDU_MAX_LENGTH);
	isns_pdu_write_hdr(pdu, ISNS_DEV_ATTR_REG_REQ, 0,
			   (lead_target == t) ? ISNS_PDU_FLAG_REPLACE : 0,
			   ++transaction_id);
	/* src */
	isns_pdu_write_attr(pdu, ISNS_ATTR_ISCSINAME_TAG,
			    strlen(lead_target->t_name) + 1,
			    lead_target->t_name, 0);
	/* msg key */
	isns_pdu_write_attr(pdu, ISNS_ATTR_ENTITYID_TAG, strlen(t_eid) + 1, t_eid,
			    0);
	isns_pdu_write_attr(pdu, ISNS_ATTR_DELIMITER_TAG,
			    ISNS_ATTR_DELIMITER_LENGTH, NULL, 0);
	/* opr attr */
	isns_pdu_write_attr(pdu, ISNS_ATTR_ENTITYID_TAG, strlen(t_eid) + 1, t_eid,
			    0);

	/* first target */
	if (t == lead_target) {
		isns_pdu_write_attr(pdu, ISNS_ATTR_ENTITYPROTOCOL_TAG,
				    ISNS_ATTR_ENTITYPROTOCOL_LENGTH, NULL,
				    ISNS_ATTR_ENTITYPROTOCOL_ISCSI);

		/* write out all target portals */
		isns_target_set_all_portals(pdu);

		if (main_lsock.sport) {
			isns_pdu_write_attr(pdu, ISNS_ATTR_ESIPORT_TAG,
					    ISNS_ATTR_ESIPORT_LENGTH, NULL,
					    main_lsock.sport);

			isns_pdu_write_attr(pdu, ISNS_ATTR_SCNPORT_TAG,
					    ISNS_ATTR_SCNPORT_LENGTH, NULL,
					    main_lsock.sport);
		}
	}

	isns_pdu_write_attr(pdu, ISNS_ATTR_ISCSINAME_TAG, strlen(t->t_name) + 1,
			    t->t_name, 0);
	if (t->t_alias[0])
		isns_pdu_write_attr(pdu, ISNS_ATTR_ISCSIALIAS_TAG,
				    strlen(t->t_alias) + 1, t->t_alias, 0);
	isns_pdu_write_attr(pdu, ISNS_ATTR_ISCSINODETYPE_TAG,
			    ISNS_ATTR_ISCSINODETYPE_LENGTH, NULL,
			    ISNS_ATTR_ISCSINODETYPE_TARGET);

	/* portal groups */
	isns_pdu_write_attr(pdu, ISNS_ATTR_PGISCSINAME_TAG,
			    strlen(t->t_name) + 1, t->t_name, 0);

	portal = t->t_portalq.q_head;
	if (portal) {
		for (; portal; portal = portal->p_next) {
			isns_pdu_write_attr_ip(pdu, portal->p_ip,
					       ISNS_ATTR_PGIP_TAG,
					       ISNS_ATTR_PGIP_LENGTH);
			isns_pdu_write_attr(pdu, ISNS_ATTR_PGPORT_TAG,
					    ISNS_ATTR_PGPORT_LENGTH, NULL,
					    portal->p_port);
			isns_pdu_write_attr(pdu, ISNS_ATTR_PGTAG_TAG,
					    ISNS_ATTR_PGTAG_LENGTH, NULL,
					    portal->p_tag);
		}
	}

	rv = isns_pdu_send_n_recv(sock, pdu, ISNS_PDU_MAX_LENGTH);
	if (rv < 0)
		return rv;

	return 0;
}


/*
 * query available initiators
 */
static int isns_target_parse_isns_initiator(struct target *t, char *pdu)
{
	int     rv = 0;
	char   *data;
	unsigned int fid;
	unsigned int dlen, len;
	struct peer *peer = NULL;
	struct portal *p = NULL;
	queue   peerq_new;

	ch_queue_init(&peerq_new);

	fid = GET_ISNS_PDU_FUNCTIONID(pdu);
	dlen = GET_ISNS_PDU_LENGTH(pdu);

	data = pdu + ISNS_PDU_HDR_LEN + 4;
	len = 4;
	while (len < dlen) {
		u_int16_t tag, tlen;

		tag = htonl(*((u_int32_t *) data));
		data += ISNS_ATTR_TAG_LENGTH;
		len += ISNS_ATTR_TAG_LENGTH;

		tlen = htonl(*((u_int32_t *) (data)));
		data += ISNS_ATTR_TAGLEN_LENGTH;
		len += ISNS_ATTR_TAGLEN_LENGTH;

		switch (tag) {
			case ISNS_ATTR_ISCSINAME_TAG:
				peer = peer_alloc();
				if (!peer) {
					rv = -ENOMEM;
					goto err_out;
				}
				strcpy(peer->p_name, data);
				peer_enqueue(&peerq_new, peer);
				isns_log_debug
					("target %s(%p) query: found peer %p (%s).\n",
					 t->t_name, t, peer, peer->p_name);
				break;
			case ISNS_ATTR_PORTALIP_TAG:
			{
				unsigned int ip[4];
				memcpy(ip, (unsigned int *)data, sizeof(unsigned int) * 4);

				if (peer) {
					p = portal_alloc();
					if (!p) {
						rv = -ENOMEM;
						goto err_out;
					}
					memcpy(p->p_ip, ip, sizeof(unsigned int) * 4);
					portal_enqueue(&peer->p_portalq, p);
					isns_log_debug
						("target %s(%p) query: peer %p portal %p.\n",
						 t->t_name, t, peer, p);
				}
			}
				break;
			case ISNS_ATTR_PORTALPORT_TAG:
			{
				p->p_port = htonl(*(( u_int32_t *)(data)));
				break;
			}
		}

		data += tlen;
		len += tlen;
	}

	/* check for any changes in the initiator info */
	for (peer = peerq_new.q_head;
	     peer && !(t->t_flag & ISNS_FLAG_PEER_CHANGED);
	     peer = peer->p_next) {
		struct peer *old_peer;
		struct portal *portal;

		old_peer = peerq_find_by_name(&t->t_peerq, peer->p_name);
		if (!old_peer) {	/* new initiator is found */
			t->t_flag |= ISNS_FLAG_PEER_CHANGED;
			break;
		}

		/* check to see if the initiator IP changed or not */
		for (portal = peer->p_portalq.q_head; portal;
		     portal = portal->p_next) {
			struct portal *dup;
			dup = portalq_find_by_ip(&old_peer->p_portalq,
						 portal->p_ip);
			if (!dup) {	/* new portal */
				t->t_flag = ISNS_FLAG_CHANGED;
				break;
			}
			isns_log_debug
				("target %s(%p) query: remove old peer %p portal %p.\n",
				 t->t_name, t, old_peer, dup);
			portal_ch_qremove(&old_peer->p_portalq, dup);
			portal_free(dup);
		}

		/* some portals are removed */
		if (old_peer->p_portalq.q_head) {
			t->t_flag = ISNS_FLAG_CHANGED;
			break;
		}

		peer_ch_qremove(&t->t_peerq, old_peer);
		isns_log_debug("target %s(%p) query: remove old peer %p.\n",
			       t->t_name, t, old_peer);
		peer_free(old_peer);
	}

	if (!(t->t_flag & ISNS_FLAG_PEER_CHANGED) && t->t_peerq.q_head) {
		/* whatever left in the t_peerq is removed */
		t->t_flag |= ISNS_FLAG_PEER_CHANGED;
	}

	/* save the initiators' info */
	isns_log_debug("target %s(%p) query: remove old peers.\n", t->t_name,
		       t);
	peerq_release_all(&t->t_peerq);
	ch_queue_move_content(&t->t_peerq, &peerq_new);

	return 0;

err_out:
	isns_log_debug("target %s(%p) query: error remove new peers.\n",
		       t->t_name, t);
	peerq_release_all(&peerq_new);
	return rv;
}

static int isns_target_query(isns_sock * sock, struct target *t,int truncate)
{
	char    pdu[ISNS_PDU_MAX_LENGTH];
	int     rv = 0;

	rv = isns_query_peers(sock, t->t_name,
			      ISNS_ATTR_ISCSINODETYPE_INITIATOR,
			      pdu, ISNS_PDU_MAX_LENGTH);
	if (rv < 0)
		return rv;

	rv = isns_target_parse_isns_initiator(t, pdu);
	if (rv < 0)
		return rv;
	
	if (t->t_flag & ISNS_FLAG_PEER_CHANGED) {
		if(isns_log && !truncate) {
                        isns_log = 2;
                        while ( isns_log > 1 ) {}
                }

		target_dump(t);
	}

	return 0;
}

#if 1
static int isns_target_set_acl(struct target *t, int fd)
{
	int     rv = 0;
	int     size = 0, dlen = 0, rlen;
	char    rbuf[512];
	char   *dbuf = NULL;
	struct peer *peer;
	struct portal *portal;

	if (!(t->t_flag & ISNS_FLAG_PEER_CHANGED))
		return 0;

	/* estimate buffer size */
	/* iname=<peer name>;sip=<ip address> */
	for (peer = t->t_peerq.q_head; peer; peer = peer->p_next) {
		int     hlen = strlen("iname=") + strlen(peer->p_name) + 2 +
				strlen(";sip=");
		for (portal = peer->p_portalq.q_head; portal;
		     portal = portal->p_next) {
			size += hlen + IP_STRING_LENGTH + 1;
		}
	}

	if(size)
		dbuf = malloc(size);
	if (!dbuf)
		return -ENOMEM;
	for (peer = t->t_peerq.q_head; peer; peer = peer->p_next) {
		/* follow the config file ACL format */
		dlen += sprintf(dbuf + dlen, "iname=%s;sip=", peer->p_name);
		for (portal = peer->p_portalq.q_head; portal;
		     portal = portal->p_next) {
			dlen += sprintf(dbuf + dlen, FORMAT_IPV4,
					ADDR_IPV4(portal->p_ip));
			dbuf[dlen++] = ',';
		}
		dbuf[dlen - 1] = 0;
	}

	rlen = sprintf(rbuf, "%s", t->t_name);
	rbuf[rlen++] = 0;
	rlen += sprintf(rbuf + rlen, "%lu", (unsigned long) self_pid);
	rbuf[rlen++] = 0;

	rv = iscsictl_isns_cmd(fd, rbuf, rlen, dbuf, dlen, ISNS_REQ_TARGET_ACL);
	if (rv < 0)
		goto out;

	t->t_flag &= ~ISNS_FLAG_PEER_CHANGED;

out:
	if (dbuf)
		free(dbuf);
	return rv;
}
#endif

static int isns_target_query_initiators(isns_sock * sock, int fd)
{
	struct target *t;
	int     good_cnt = 0;
	int     fail_cnt = 0;
	int	truncate = 0; /* truncate log file before the first target */

	/* query for the initiators */
	for (t = targetq.q_head; t; t = t->t_next) {
		int     rv;

		if (!(t->t_flag & ISNS_FLAG_REGISTERED)) {
			continue;
		}

		t->t_flag &= ~ISNS_FLAG_PEER_CHANGED;
		rv = isns_target_query(sock, t, truncate++);
		if (rv < 0) {
			fail_cnt++;
			continue;
		} else {
			good_cnt++;
		}

		rv = isns_target_set_acl(t, fd);
	}

	/* if all query failed, return error */
	if (fail_cnt && !good_cnt)
		return -EIO;

	return 0;
}

int isns_update_targets(isns_sock * sock, char *buf, int blen)
{
	int     rv;
	int     update_needed = 0;
	struct target *t;

	for (t = targetq.q_head; t; t = t->t_next)
		t->t_flag |= ISNS_FLAG_UPDATING;

	rv = isns_target_parse_info(buf, blen);
	if (rv < 0)
		return rv;

	/* de-register any target that is removed */
	for (t = targetq.q_head; t;) {
		struct target *tnext = t->t_next;
		if (t->t_flag & ISNS_FLAG_UPDATING) {
			if (lead_target == t)
				lead_target = NULL;
			/* this target should be removed since did not get updated. */
			if (t->t_flag & ISNS_FLAG_REGISTERED) {
				rv = isns_scn_deregister(sock, t->t_name);
				rv = isns_entity_deregister(sock, t->t_name);
			}
			target_ch_qremove(&targetq, t);
			isns_log_debug("targetq, remove target %s(%p).\n",
				       t->t_name, t);
			target_free(t);
		}
		t = tnext;
	}

	/* check for any changes or new target */
	for (t = targetq.q_head; t; t = t->t_next) {
		if ((t->t_flag & ISNS_FLAG_CHANGED) ||
		    (!(t->t_flag & ISNS_FLAG_REGISTERED))) {
			t->t_flag &= ~ISNS_FLAG_CHANGED;
			update_needed = 1;
			break;
		}
	}

	if (!update_needed)
		return 0;

	lead_target = NULL;
	for (t = targetq.q_head; t; t = t->t_next) {
		if (!lead_target)
			lead_target = t;
		rv = isns_target_register(sock, t);
		if (rv < 0)
			return rv;
		rv = isns_scn_register(sock, t->t_name);
		if (rv < 0)
			return rv;
		t->t_flag |= ISNS_FLAG_REGISTERED;
	}

	return 0;
}

int isns_target_client(isns_sock * sock, int update, int poll)
{
	int     rv = 0;
	int     fd = -1;

	if (update) {

		if ((fd = iscsictl_open_device()) < 0) {
			isns_log_error("unable to open chiscsi %d.\n", fd);
			return -EINVAL;
		}

		/* read target portal config from iscsi */
		iscsictl_buffer[0] = 0;
		rv = iscsictl_isns_get_portals(fd, iscsictl_buffer,
					       ISCSI_CONTROL_DATA_MAX_BUFLEN);
		if (rv < 0) {
			isns_log_error("read target portals failed, %d!\n", rv);
			goto out;
		}

		rv = isns_update_target_portals(sock, iscsictl_buffer,
						ISCSI_CONTROL_DATA_MAX_BUFLEN);
		if (rv < 0) {
			isns_log_msg("update target failed %d.\n", rv);
			goto out;
		}

		/* read target config from iscsi */
		iscsictl_buffer[0] = 0;
		rv = iscsictl_isns_get_targets(fd, iscsictl_buffer,
					       ISCSI_CONTROL_DATA_MAX_BUFLEN);
		if (rv < 0) {
			isns_log_error("read target config failed, %d!\n", rv);
			goto out;
		}

		/* register all targets */
		rv = isns_update_targets(sock, iscsictl_buffer,
					 ISCSI_CONTROL_DATA_MAX_BUFLEN);
		if (rv < 0) {
			isns_log_msg("update target failed %d.\n", rv);
			goto out;
		}
	}

	if (update || poll) {

		if (fd < 0 && (fd = iscsictl_open_device()) < 0) {
			isns_log_error("unable to open chiscsi %d.\n", fd);
			return -EINVAL;
		}
		rv = isns_target_query_initiators(sock, fd);
		if (rv < 0) {
			isns_log_msg("target query failed %d.\n", rv);
			goto out;
		}
	}

out:
	if (fd >= 0)
		iscsictl_close_device(fd);
	return rv;
}

/*
 * Initialization & Cleanups
 */
int isns_target_cleanup(isns_sock * sock)
{
	struct target *t;

	target_dequeue(&targetq, t);
	while (t) {
		isns_scn_deregister(sock, t->t_name);
		isns_entity_deregister(sock, t->t_name);
		isns_log_debug("targetq cleanup: remove target %s(%p).\n",
			       t->t_name, t);
		target_free(t);
		target_dequeue(&targetq, t);
	}

	portalq_release_all(&portalq);

	return 0;
}

int isns_target_init(void)
{
	ch_queue_init(&targetq);
	ch_queue_init(&portalq);
	return 0;
}
