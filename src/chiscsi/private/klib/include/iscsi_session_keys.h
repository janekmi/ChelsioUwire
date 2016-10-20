#ifndef __ISCSI_KEY_SESSION_H__
#define __ISCSI_KEY_SESSION_H__

/*
 * iscsi session keys
 */

#include "iscsi_text.h"

extern iscsi_keydef iscsi_keydef_session_tbl[];

enum session_keys {
	ISCSI_KEY_SESS_MAX_CONNECTIONS,
	ISCSI_KEY_SESS_INITIAL_R2T,
	ISCSI_KEY_SESS_MAX_OUTSTANDING_R2T,
	ISCSI_KEY_SESS_IMMEDIATE_DATA,
	ISCSI_KEY_SESS_FIRST_BURST_LENGTH,
	ISCSI_KEY_SESS_MAX_BURST_LENGTH,
	ISCSI_KEY_SESS_DEFAULT_TIME2WAIT,
	ISCSI_KEY_SESS_DEFAULT_TIME2RETAIN,
	ISCSI_KEY_SESS_DATA_PDU_IN_ORDER,
	ISCSI_KEY_SESS_DATA_SEQUENCE_IN_ORDER,
	ISCSI_KEY_SESS_ERROR_RECOVERY_LEVEL,
	ISCSI_KEY_SESS_SESSION_TYPE,

	ISCSI_KEY_SESS_COUNT
};

#define iscsi_session_key_decode(ntype,state,kvlist,pairq,ebuf,ebuflen) \
		iscsi_kvlist_decode_pairq(state, ntype, ISCSI_KEY_SESS_COUNT, \
					kvlist, pairq, ebuf, ebuflen)

#define iscsi_session_key_fill_default(kvlist) \
		iscsi_kvlist_fill_default(ISCSI_KEY_SESS_COUNT, kvlist)

#define iscsi_session_key_free(kvlist)   \
		do { \
			iscsi_kvlist_free(ISCSI_KEY_SESS_COUNT, kvlist); \
			kvlist = NULL;	\
		} while(0)

#define iscsi_session_key_alloc()   \
		iscsi_kvlist_alloc(ISCSI_KEY_SESS_COUNT, iscsi_keydef_session_tbl)

#define iscsi_session_key_duplicate(f,t)   ({ \
		int __rc; \
		t = iscsi_kvlist_alloc(ISCSI_KEY_SESS_COUNT, iscsi_keydef_session_tbl); \
		__rc = iscsi_kvlist_duplicate_value(ISCSI_KEY_SESS_COUNT, f, t); \
		__rc; \
	})

#define iscsi_size_session_keys(kvlist)	\
		iscsi_kvlist_size_text(ISCSI_KEY_SESS_COUNT, kvlist)

#define iscsi_session_key_display(kvlist)   \
		iscsi_kvlist_display(ISCSI_KEY_SESS_COUNT, kvlist)

#define iscsi_session_keys_send(kvlist,buf,buflen)	\
		iscsi_kvlist_write_text(ISCSI_KEY_SESS_COUNT, kvlist, 0, \
			ISCSI_KV_FLAG_SEND, ISCSI_KV_WRITE_NO_SEPERATOR, 0, \
			buf, buflen, 1)\

#define iscsi_session_key_match(buf)	\
		iscsi_match_key_string(buf, ISCSI_KEY_SESS_COUNT, \
					iscsi_keydef_session_tbl)

#define iscsi_session_key_discovery_check(kvlist)	\
		iscsi_kvlist_check_key_property_in_discovery(ISCSI_KEY_SESS_COUNT, \
								kvlist)
#define iscsi_session_kvp_init(i)   ({\
			iscsi_keyval *__kvp = iscsi_kvp_alloc(); \
			iscsi_keydef *__kdefp = iscsi_keydef_session_tbl + i; \
			if (__kvp) { \
				__kvp->kv_def = __kdefp; \
				__kvp->kv_name = __kdefp->name; \
			} \
			__kvp; \
		})

int     iscsi_session_keys_validate_value(iscsi_keyval *, char *, int);

int iscsi_get_session_key_settings(struct iscsi_session_settings *setting,
				iscsi_keyval *kvlist);
#endif /* ifndef __ISCSI_KEY_SESSION_H__ */
