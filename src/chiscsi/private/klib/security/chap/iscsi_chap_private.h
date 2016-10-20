#ifndef __ISCSI_CHAP_PRIVATE_H__
#define __ISCSI_CHAP_PRIVATE_H__

#include <common/iscsi_common.h>
#include <common/iscsi_queue.h>
#include <common/iscsi_chap.h>
#include <iscsi_text.h>

/*
 * CHAP configuration
 */

#define CHAP_PAIR_SEPERATOR		':'	/* seperates the "id" and "secret" portion */

#define CHAP_CHALLENGE_LENGTH_MIN	16
#define CHAP_CHALLENGE_LENGTH_MAX	1024
#define CHAP_CHALLENGE_LENGTH_DFLT	16

#define CHAP_MD5_DIGEST_LEN		16
#define CHAP_SHA1_DIGEST_LEN		20
#define CHAP_DIGEST_LEN_MAX		CHAP_SHA1_DIGEST_LEN

#define CHAP_POLICY_ONEWAY_STR		"Oneway"
#define CHAP_POLICY_MUTUAL_STR		"Mutual"

enum chap_policy {
	CHAP_POLICY_ONEWAY = 1,
	CHAP_POLICY_MUTUAL
};
#define CHAP_POLICY_DFLT		CHAP_POLICY_ONEWAY

enum chap_algorithm {
	MD5_ALGORITHM = 1,
	SHA1_ALGORITHM
};

/* 
 * CHAP Authentication Processing
 */

/* chap processing state */
enum chap_state {
	CHAP_STATE_UNKNOWN,
	CHAP_STATE_CHALLENGE,
	CHAP_STATE_RESPONSE,
	CHAP_STATE_DONE
};

typedef struct chap_string_pair chap_string_pair;
typedef struct chap_connection chap_connection;
typedef struct chap_session chap_session;
typedef struct chap_node chap_node;

/* used for storing chap name/secret pair */
struct chap_string_pair {
	chap_string_pair *next;
	char    name[CHAP_NAME_LEN_MAX + 1];
	char    secret[CHAP_SECRET_LEN_MAX + 1];
};
#define chap_string_pair_enqueue(L,Q,P) \
			ch_enqueue_tail(L,chap_string_pair,next,Q,P)
#define chap_string_pair_dequeue(L,Q,P) \
			ch_dequeue_head(L,chap_string_pair,next,Q,P)
#define chap_string_pair_ch_qremove(L,Q,P) \
			ch_qremove(L,chap_string_pair,next,Q,P)

/* chap info pertaining to an iscsi node (target or initiator) */
struct chap_node {
	unsigned char forced;
	unsigned char filler[3];
	unsigned int policy;
	unsigned int challenge_length;
	chiscsi_queue *localq;
	chiscsi_queue *remoteq;
};
#define CHAP_NODE_SIZE	(sizeof(chap_node))

/* chap info pertaining to an iscsi session */
struct chap_session {
	chap_node *node;
	iscsi_keyval kvp_chap_i;
	iscsi_keyval kvp_chap_c_sent;
	iscsi_keyval kvp_chap_c_rcv;
};

/* chap info pertaining to an iscsi connection */
struct chap_connection {
	chap_connection *next;
	int     state;
	unsigned char id;
	unsigned char algorithm;
	unsigned char policy;
	unsigned char filler[1];
	unsigned char challenge[CHAP_CHALLENGE_LENGTH_MAX];
	unsigned int challenge_length;
	chap_session *csess;
	chap_info cinfo;
};

#define chap_iscsi_conn_enqueue(L,Q,P) \
			ch_enqueue_tail(L,chap_connection,next,Q,P)
#define chap_conn_dequeue(L,Q,P) \
			ch_dequeue_head(L,chap_connection,next,Q,P)
#define chap_conn_ch_qremove(L,Q,P) \
			ch_qremove(L,chap_connection,next,Q,P)

chap_string_pair *chap_search_pairq_by_name_secret(chiscsi_queue *, char *,
						   char *);
chap_string_pair *chap_search_pairq_by_name(chiscsi_queue *, char *);
chap_string_pair *chap_search_pairq_by_secret(chiscsi_queue *, char *);


#endif /* ifndef __CHAP_KEY_PRIVATE_H__ */
