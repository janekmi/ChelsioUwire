#ifndef __ISCSI_CHAP_API_H__
#define __ISCSI_CHAP_API_H__

#include <common/iscsi_common.h>
#include <common/iscsi_queue.h>
#include <common/iscsi_chap.h>
#include <iscsi_text.h>
#include "../iscsi_auth_private.h"

extern iscsi_keydef chap_auth_key_table[];
extern iscsi_keydef chap_config_key_table[];

/*
 * CHAP-related keys
 */

enum chap_config_keys {
	CHAP_KEY_CONFIG_TARGET,
	CHAP_KEY_CONFIG_INITIATOR,
	CHAP_KEY_CONFIG_CHALLENGE_LENGTH,
	CHAP_KEY_CONFIG_POLICY,

	CHAP_KEY_CONFIG_COUNT
};

enum chap_login_keys {
	CHAP_KEY_AUTH_ALGORITHM,
	CHAP_KEY_AUTH_NAME,
	CHAP_KEY_AUTH_RESPONSE,
	CHAP_KEY_AUTH_ID,
	CHAP_KEY_AUTH_CHALLENGE,

	CHAP_KEY_AUTH_COUNT
};

void    chap_node_free(void *);
void    chap_session_free(void *);
void    chap_connection_free(void *);

int     chap_node_config(iscsi_auth_node *, iscsi_keyval *, char *, int);
int     chap_node_config_display(iscsi_auth_node *, int, char *, int);
int     chap_node_config_text_size(iscsi_auth_node *, int);
int     chap_node_config_add(iscsi_auth_node *, iscsi_keyval *, int, char *,
			     int);
int     chap_node_config_remove(iscsi_auth_node *, iscsi_keyval *, int, char *,
				int);

//int     chap_connection_process(iscsi_auth_connection *);
int	chap_connection_process(iscsi_auth_connection *,
				chiscsi_target_class *, char *, char *,
				unsigned char *, unsigned char *);

#endif /* ifndef __ISCSI_CHAP_API_H__ */
