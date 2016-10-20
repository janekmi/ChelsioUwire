#ifndef __ISCSI_CONNECTION_H__
#define __ISCSI_CONNECTION_H__

#include <iscsi_portal.h>
/*
 * iscsi connection
 */

enum iscsi_conn_state {
	CONN_STATE_CLOSED,
	CONN_STATE_LISTEN,	/* for conn. */
	CONN_STATE_CONNECTED,	/* for conn. */
	CONN_STATE_LOGIN,	/* for conn. */
	CONN_STATE_LOGINSECURITY,	/* for conn. */
	CONN_STATE_LOGINOPERATIONAL,	/* for conn. */
	CONN_STATE_FFP,		/* for conn. */
	CONN_STATE_LOGOUT,	/* for conn. */
	CONN_STATE_CLOSING	/* for conn. */
};


enum connection_flag_bits {
	CONN_FLAG_THREAD_BIT,	/* conn. assigned a thread */
	CONN_FLAG_CLOSING_BIT,	/* conn. is being closed */
	CONN_FLAG_CLOSE_BIT,	/* conn. to be closed, no more processing */
	CONN_FLAG_RST_BIT,	/* conn. to be closed, send abort */

	CONN_FLAG_LEADING_CONN_BIT,	/* leading connection of a session */
	CONN_FLAG_RX_READY_BIT,	/* there is data waiting to be read */

	CONN_FLAG_TX_PUSH_BIT,	/* push all pdus in the tx queue */
	CONN_FLAG_FFP_READY_BIT,	/* conn. completed login phase */
	CONN_FLAG_AUTH_ACL_BIT,	/* ACL re-check needed */

	CONN_FLAG_LOGINIP_BIT,	/* conn. in login phase, counted towards node's login ip count */
	CONN_FLAG_TIMEOUT_BIT,	/* timeout occured */
	CONN_FLAG_PINGED_BIT,	/* ping has sent, used for timeout check */
	CONN_FLAG_BUSY_BIT,	/* used for timeout check */

	CONN_FLAG_LOCKED_BIT,

	CONN_FLAG_LOGIN_CALLBACK_BIT,
	CONN_FLAG_CLOSED_BIT,	/* conn. is closed */
};

enum iscsi_connection_qtypes {
	CONN_PDUQ_FREE,
	CONN_PDUQ_TMP,
	CONN_PDUQ_SEND,
	CONN_PDUQ_RECV,
	CONN_PDUQ_SENT,
	CONN_PDUQ_SENTREQ,
	CONN_PAIRQ,

	CONN_Q_MAX
};

typedef struct conn_login	conn_login;
struct conn_login {
	unsigned int itt;
	unsigned char version;
	unsigned char status_class;
	unsigned char status_detail;
	unsigned char csg:2;
	unsigned char nsg:2;
	unsigned char transit_req:1;
	unsigned char transit_resp:1;
	unsigned char wait:2;   /* callback wait */
};

#define ISCSI_RX_PDU_SGCNT	17	/* enough to support 64K pdu */
struct iscsi_connection {
	iscsi_session *c_sess;	/* session - This should remain in the first
				position to enable easy access in lu_scst.c */
	/* os dependent */
	void   *os_data;
	chiscsi_queue *c_queue[CONN_Q_MAX];

	/* os independent */
	iscsi_connection *c_next;

	iscsi_portal *c_portal;	/* target portal used */
	iscsi_thread_entry c_thinfo;

	unsigned long c_fbits;
	unsigned char c_state;
	unsigned char c_offload_mode;	/* offload mode in */
	unsigned char c_hdigest_len;	/* header digest length */
	unsigned char c_ddigest_len;	/* data digest length */
	unsigned int  c_snd_nxt;
	unsigned int c_cid;
	unsigned int c_statsn;
	unsigned int c_expstatsn;

	unsigned int c_pdudatalen_tmax;
	unsigned int c_pdudatalen_rmax;
	unsigned int c_pdupool_max;

	iscsi_pdu *c_rxpdu;
	
	iscsi_pdu c_pdu_rx;
	chiscsi_sgvec rx_sglist[ISCSI_RX_PDU_SGCNT];

	unsigned int c_text_tag;
	unsigned int c_text_itt;
	unsigned int c_datap_cnt;
	unsigned int c_datap_max;
	char   *c_datap;
	iscsi_keyval *c_keys;

	/* for timeout check */
	unsigned int c_timeout;
	unsigned int c_idle;

	unsigned int difdix_mode;
	/* login in/out */
	conn_login login;

	iscsi_socket *c_isock;
	void   *c_auth;
};

#define	ISCSI_CONNECTION_SIZE	(sizeof(iscsi_connection))

#define iscsi_conn_flag_set(conn,bit)	\
			os_set_bit_atomic(&((conn)->c_fbits),bit)
#define iscsi_conn_flag_clear(conn,bit) \
			os_clear_bit_atomic(&((conn)->c_fbits),bit)
#define iscsi_conn_flag_test(conn,bit)	\
			os_test_bit_atomic(&((conn)->c_fbits),bit)
#define iscsi_conn_flag_testnset(conn,bit)	\
			os_test_and_set_bit_atomic(&((conn)->c_fbits),bit)
#define iscsi_conn_flag_testnclear(conn,bit) \
			os_test_and_clear_bit_atomic(&((conn)->c_fbits),bit)

#define iscsi_conn_enqueue(L,Q,P)	\
			ch_enqueue_tail(L,iscsi_connection,c_next,Q,P)
#define iscsi_conn_dequeue(L,Q,P)	\
			ch_dequeue_head(L,iscsi_connection,c_next,Q,P)
#define iscsi_conn_ch_qremove(L,Q,P)	\
			ch_qremove(L,iscsi_connection,c_next,Q,P)
#define iscsi_conn_qsearch_by_cid(L,Q,P,V)	\
			ch_qsearch_by_field_value(L,iscsi_connection,c_next,Q,P,c_cid,V)

/* resize max transmit/recv pdu data length according to the socket's max packet size */
#define iscsi_conn_adjust_pdudatalen_tmax(conn)	\
	if (conn->c_isock->s_tmax)  { \
		/* BHS + AHS + digests */ \
		unsigned int __v = conn->c_isock->s_tmax - ISCSI_BHS_SIZE - 256 - 8; \
		/* if (conn->c_hdigest_len) __v -= conn->c_hdigest_len; */ \
		/* if (conn->c_ddigest_len) __v -= conn->c_ddigest_len; */ \
		if (__v < conn->c_pdudatalen_tmax) \
			conn->c_pdudatalen_tmax = __v; \
	} else if (conn->c_pdudatalen_tmax > 16384) { \
		conn->c_pdudatalen_tmax = 16384; \
	}

#define iscsi_conn_adjust_pdudatalen_rmax(conn) 	\
	if (conn->c_isock->s_rmax)  { \
		/* BHS + AHS + digests */ \
		unsigned int __v = conn->c_isock->s_rmax - ISCSI_BHS_SIZE - 256 - 8; \
		if (__v < conn->c_pdudatalen_rmax) \
			conn->c_pdudatalen_rmax = __v; \
	} else if (conn->c_pdudatalen_rmax > 16384) { \
		conn->c_pdudatalen_rmax = 16384; \
	}

#define iscsi_conn_get_iso_max(conn)	(conn->c_isock->s_isomax)

/* flag bits */
#define iscsi_conn_logged_in(conn) 	iscsi_conn_flag_test(conn, CONN_FLAG_FFP_READY_BIT)

/* if the connection is ready for session processing */
#define conn_ready_for_session_process(conn) \
		( (iscsi_conn_flag_test(conn, CONN_FLAG_FFP_READY_BIT)) && \
		  !(iscsi_conn_flag_test(conn, CONN_FLAG_CLOSE_BIT)) )

#define conn_ready_for_initiator_session_process(conn) \
		(iscsi_conn_flag_test(conn, CONN_FLAG_FFP_READY_BIT))

#define conn_timeout_clear(conn) \
	do { \
		(conn)->c_idle = 0; \
		iscsi_conn_flag_clear(conn, CONN_FLAG_PINGED_BIT); \
		iscsi_conn_flag_clear(conn, CONN_FLAG_TIMEOUT_BIT); \
	} while(0)

/* iscsi connection */
int     iscsi_connection_display(iscsi_connection *, char *, int, int);

iscsi_connection *iscsi_connection_create(void);
int     iscsi_connection_closing(iscsi_connection *);
int     iscsi_connection_destroy(iscsi_connection *);
int     iscsi_connection_reset(iscsi_connection *);

int	iscsi_connection_is_ffp(void *);

int     iscsi_connection_push_pdus(iscsi_connection *);
int     iscsi_connection_send_pdu(iscsi_connection *, iscsi_pdu *);
int 	iscsi_connection_queue_r2t_pdu(iscsi_connection *, iscsi_pdu *);
void    iscsi_connection_clean_sentq(iscsi_connection *, unsigned int);
int iscsi_conn_portal_remove(chiscsi_queue *);

#endif /* ifndef __ISCSI_CONNECTION_H__ */
