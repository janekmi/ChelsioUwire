#ifndef __ISCSI_PORTAL_H__
#define __ISCSI_PORTAL_H__

/*
 * iscsi portal
 * 	- p_flag:
 *		bit 0 ~ 3: configuration flag defined in iscsi_struct.h
 *			   ISCSI_CONFIG_FLAG_XXX
 *		bit 4 ~ 7: connection status
 */

#define ISCSI_PORTAL_FLAG_CONN_MASK		0xF0

#define ISCSI_PORTAL_FLAG_CONN_NOTCP		0x10	/* tcp conn. failed */
#define ISCSI_PORTAL_FLAG_CONN_LOGIN_FAIL	0x20	/* iscsi login failed */
#define ISCSI_PORTAL_FLAG_ADDR_INVALID		0x40	/* interface invalid */

#define ISCSI_PORTAL_FLAG_REDIRECT_FROM		0x100
#define ISCSI_PORTAL_FLAG_REDIRECT_TO_LOCAL	0x200
#define ISCSI_PORTAL_FLAG_REDIRECT_TO_REMOTE	0x400
#define ISCSI_PORTAL_FLAG_REDIRECT_TO	\
	(ISCSI_PORTAL_FLAG_REDIRECT_TO_LOCAL | \
	 ISCSI_PORTAL_FLAG_REDIRECT_TO_REMOTE)

struct iscsi_portal {
	/* os dependent */
	void	*os_data;

	/* os independent */
	struct iscsi_portal *p_next;
	iscsi_connection *p_conn;
	struct tcp_endpoint p_ep;
	unsigned int p_timeout;
	unsigned int p_flag;
};

#define ISCSI_PORTAL_SIZE	(sizeof(iscsi_portal))
#define iscsi_portal_free(portal)	\
	do {	\
		os_data_free((portal)->os_data); \
		os_free(portal); \
	} while (0)

#define portal_enqueue(L,Q,P)   ch_enqueue_tail(L,iscsi_portal,p_next,Q,P)
#define portal_dequeue(L,Q,P)   ch_dequeue_head(L,iscsi_portal,p_next,Q,P)
#define portal_ch_qremove(L,Q,P)   ch_qremove(L,iscsi_portal,p_next,Q,P)

/* function proto-types */
iscsi_portal *iscsi_portal_alloc(iscsi_value *);
int     iscsi_portal_display(iscsi_portal *, char *, int, char, char);
int     iscsi_portal_stop_connection(iscsi_portal *);

iscsi_portal *iscsi_portalq_find_by_addr(chiscsi_queue *, struct tcp_endpoint *, int);
int     iscsi_portalq_free_portal(chiscsi_queue *, iscsi_portal *, int);
int     iscsi_portalq_display(chiscsi_queue *, char *, int, char, char, int);

#endif /* ifndef __ISCSI_PORTAL_H__ */
