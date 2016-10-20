#ifndef __ISCSI_AUTH_PRIVATE_H__
#define __ISCSI_AUTH_PRIVATE_H__

#include <common/os_builtin.h>
#include <common/iscsi_error.h>
#include <common/iscsi_target_class.h>
#include <iscsi_structs.h>

/*
 * support authentication method: CHAP only.
 */
enum methods {
	AUTH_METHOD_NONE,
	AUTH_METHOD_CHAP,

	AUTH_METHOD_MAX
};

enum auth_state {
	AUTH_STATE_UNKNOWN,
	AUTH_STATE_PROCESS,
	AUTH_STATE_DONE
};

typedef struct iscsi_auth_method iscsi_auth_method;
typedef struct iscsi_auth_node iscsi_auth_node;
typedef struct iscsi_auth_session iscsi_auth_session;
typedef struct iscsi_auth_connection iscsi_auth_connection;

#define AUTH_NODE_METHOD_FLAG_ENABLE    0x1
struct iscsi_auth_node {
	unsigned int n_flag;
#define AUTH_NODE_AUTHENTICATION_NONE	0x1
#define AUTH_NODE_AUTHENTICATION_FORCED	0x2
	int     n_type;		/* initiator or target */
	int     n_forced;
	unsigned int n_method_flag[AUTH_METHOD_MAX];
	void   *n_method_data[AUTH_METHOD_MAX];
};

struct iscsi_auth_session {
	int     s_state;
	iscsi_auth_node *s_node;
	void   *s_method_data[AUTH_METHOD_MAX];
};

struct iscsi_auth_connection {
	unsigned char c_state;
	unsigned char c_method_idx;
	int     c_kv_max;
	iscsi_auth_session *c_sess;
	unsigned char *c_method_data;
	iscsi_keyval *c_kvlist;
};

struct iscsi_auth_method {
	char    name[12];
	unsigned int config_key_max;
	unsigned int auth_key_max;
	iscsi_keydef *config_key_tbl;
	iscsi_keydef *auth_key_tbl;

	void    (*fp_node_cleanup) (void *);
	void    (*fp_session_cleanup) (void *);
	void    (*fp_connection_cleanup) (void *);

	int     (*fp_node_display) (iscsi_auth_node *, int, char *, int);
	int     (*fp_node_text_size) (iscsi_auth_node *, int);
	int     (*fp_node_config) (iscsi_auth_node *, iscsi_keyval *, char *,
				   int);
	int     (*fp_node_config_add) (iscsi_auth_node *, iscsi_keyval *, int,
				       char *, int);
	int     (*fp_node_config_remove) (iscsi_auth_node *, iscsi_keyval *,
					  int, char *, int);

	int     (*fp_conn_process) (iscsi_auth_connection *,
				    chiscsi_target_class *, char *, char *,
					unsigned char *, unsigned char *);
};

#endif /* ifndef define __ISCSI_AUTH_PRIVATE_H__ */
