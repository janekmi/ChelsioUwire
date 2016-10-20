#ifndef __ISCSI_KEY_CONNECTION_H__
#define __ISCSI_KEY_CONNECTION_H__

/*
 * iscsi connection keys
 */

#include <iscsi_text.h>

extern iscsi_keydef iscsi_keydef_connection_tbl[];

enum connection_keys {
	ISCSI_KEY_CONN_HEADER_DIGEST,
	ISCSI_KEY_CONN_DATA_DIGEST,
	ISCSI_KEY_CONN_SEND_TARGETS,
	ISCSI_KEY_CONN_TARGET_NAME,
	ISCSI_KEY_CONN_INITIATOR_NAME,
	ISCSI_KEY_CONN_TARGET_ALIAS,
	ISCSI_KEY_CONN_INITIATOR_ALIAS,
	ISCSI_KEY_CONN_TARGET_ADDRESS,
	ISCSI_KEY_CONN_TARGET_PORTAL_GROUP_TAG,
	ISCSI_KEY_CONN_MAX_RECV_DATA_SEGMENT_LENGTH,
	ISCSI_KEY_CONN_OF_MARKER,
	ISCSI_KEY_CONN_IF_MARKER,
	ISCSI_KEY_CONN_IF_MARK_INT,
	ISCSI_KEY_CONN_OF_MARK_INT,
	ISCSI_KEY_CONN_AUTH_METHOD,

	ISCSI_KEY_CONN_COUNT
};


#define iscsi_connection_key_decode(ntype,state,kvlist,pairq,ebuf,ebuflen) \
		iscsi_kvlist_decode_pairq(state, ntype, ISCSI_KEY_CONN_COUNT, \
					 kvlist, pairq, ebuf, ebuflen)

#define iscsi_connection_key_fill_default(kvlist) \
		iscsi_kvlist_fill_default(ISCSI_KEY_CONN_COUNT, kvlist)

#define iscsi_connection_key_free(kvlist)   \
		do { \
			iscsi_kvlist_free(ISCSI_KEY_CONN_COUNT, kvlist); \
			kvlist = NULL;	\
		} while(0)

#define iscsi_connection_key_alloc()   \
		iscsi_kvlist_alloc(ISCSI_KEY_CONN_COUNT, iscsi_keydef_connection_tbl)

#define iscsi_connection_key_duplicate(f,t)   ({ \
		int __rc; \
		t = iscsi_kvlist_alloc(ISCSI_KEY_CONN_COUNT, iscsi_keydef_connection_tbl); \
		__rc = iscsi_kvlist_duplicate_value(ISCSI_KEY_CONN_COUNT, f, t); \
		__rc; \
	})

#define iscsi_connection_key_display(kvlist)   \
		iscsi_kvlist_display(ISCSI_KEY_CONN_COUNT, kvlist)

#define iscsi_size_connection_keys(kvlist)	\
		iscsi_kvlist_size_text(ISCSI_KEY_CONN_COUNT, kvlist)

#define iscsi_connection_keys_send(kvlist,buf,buflen)	\
		 iscsi_kvlist_write_text(ISCSI_KEY_CONN_COUNT, kvlist, 0, \
			 ISCSI_KV_FLAG_SEND, ISCSI_KV_WRITE_NO_SEPERATOR, 0, \
			 buf, buflen, 1)

#define iscsi_connection_key_get_default(kidx) \
			iscsi_keydef_connection_tbl[kidx].val_dflt

#define iscsi_connection_key_match(buf)	\
		iscsi_match_key_string(buf, ISCSI_KEY_CONN_COUNT, \
					iscsi_keydef_connection_tbl)

#define iscsi_connection_kvp_init(i)   ({\
			iscsi_keyval *__kvp = iscsi_kvp_alloc(); \
			iscsi_keydef *__kdefp = iscsi_keydef_connection_tbl + i; \
			if (__kvp) { \
				__kvp->kv_def = __kdefp; \
				__kvp->kv_name = __kdefp->name; \
			} \
			__kvp; \
		})


int     iscsi_connection_keys_validate_value(iscsi_keyval *, char *, int);
int     iscsi_connection_keys_read_setting(iscsi_connection *);

int iscsi_get_connection_key_settings(struct iscsi_conn_settings *setting,
				iscsi_keyval *kvlist);

#endif /* ifndef __ISCSI_KEY_CONNECTION_H__ */
