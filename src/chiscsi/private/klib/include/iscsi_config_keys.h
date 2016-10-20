#ifndef __ISCSI_KEY_CONFIG_H__
#define __ISCSI_KEY_CONFIG_H__

#include <iscsi_mask.h>
#include <iscsi_text.h>

/*
 * iscsi configuration keys
 */

extern iscsi_keydef iscsi_keydef_config_tbl[];

enum config_keys {
	ISCSI_KEY_CONF_PORTALGROUP,
	ISCSI_KEY_CONF_TARGET_SESSION_MAXCMD,
	ISCSI_KEY_CONF_TARGET_CLASS,
	ISCSI_KEY_CONF_TARGET_DEVICE,
	
	ISCSI_KEY_CONF_ACL_ENABLE,
	ISCSI_KEY_CONF_ACL,
	ISCSI_KEY_CONF_SHADOW_MODE,
	ISCSI_KEY_CONF_REGISTER_ISNS,
	ISCSI_KEY_CONFIG_COUNT
};

#define iscsi_config_key_decode(ntype,kvlist,pairq,ebuf,ebuflen) \
		iscsi_kvlist_decode_pairq(CONN_STATE_CLOSED, ntype, \
						ISCSI_KEY_CONFIG_COUNT, \
						kvlist, pairq, ebuf, ebuflen)

#define iscsi_config_key_fill_default(kvlist) \
		iscsi_kvlist_fill_default(ISCSI_KEY_CONFIG_COUNT, kvlist)

#define iscsi_config_key_free(kvlist)	\
		do { \
			iscsi_kvlist_free(ISCSI_KEY_CONFIG_COUNT, kvlist); \
			kvlist = NULL;	\
		} while(0)

#define iscsi_config_key_alloc()   \
		iscsi_kvlist_alloc(ISCSI_KEY_CONFIG_COUNT, iscsi_keydef_config_tbl)

#define iscsi_config_key_display(kvlist)   \
		iscsi_kvlist_display(ISCSI_KEY_CONFIG_COUNT, kvlist)

#define iscsi_size_config_keys(kvlist)	\
		iscsi_kvlist_size_text(ISCSI_KEY_CONFIG_COUNT, kvlist)


#define iscsi_config_key_match(buf)	\
		iscsi_match_key_string(buf, ISCSI_KEY_CONFIG_COUNT, \
					iscsi_keydef_config_tbl)

#define iscsi_config_kvp_init(i)   ({\
			iscsi_keyval *__kvp = iscsi_kvp_alloc(); \
			iscsi_keydef *__kdefp = iscsi_keydef_config_tbl + i; \
			if (__kvp) { \
				__kvp->kv_def = __kdefp; \
				__kvp->kv_name = __kdefp->name; \
			} \
			__kvp; \
		})

int     iscsi_config_keys_validate_value(iscsi_keyval *, char *, int, int);
int	iscsi_get_target_config_key_settings(struct iscsi_target_config_settings *,
			iscsi_keyval *);

#endif /* ifndef __ISCSI_KEY_CONFIG_H__ */
