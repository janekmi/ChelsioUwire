#ifndef __ISCSI_AUTH_API_H__
#define __ISCSI_AUTH_API_H__

/*
 * authentication function prototypes
 */

#include <common/iscsi_target_class.h>
#include <iscsi_structs.h>
#include <iscsi_text.h>

void    iscsi_auth_node_free(void *);
void    iscsi_auth_session_free(void *);
void    iscsi_auth_connection_free(void *);

void   *iscsi_auth_node_alloc(int);
void   *iscsi_auth_session_alloc(void *);
void   *iscsi_auth_connection_alloc(void *);

int     iscsi_kv_decode_authmethod(int, char *, iscsi_value *, char *);
int     iscsi_kv_encode_authmethod(char *, iscsi_value *);
int     iscsi_kv_size_authmethod(iscsi_value *);
int     iscsi_auth_method_changed(void *, iscsi_keyval *);
int     iscsi_auth_method_set_default(iscsi_keyval *);

int     iscsi_auth_config(void *, chiscsi_queue *, char *, int);
int     iscsi_auth_config_discovery(void *);
int     iscsi_auth_config_display(void *, char *, int);
int     iscsi_auth_config_text_size(void *);

int     iscsi_auth_config_key_size(void *, int, int);
int     iscsi_auth_config_get(void *, int, int, char *, int);
int     iscsi_auth_config_add(void *, int, int, char *, char *, int);
int     iscsi_auth_config_remove(void *, int, int, char *, char *, int);

int	iscsi_connection_auth_init(iscsi_connection *, void *);
int     iscsi_connection_auth_done(iscsi_connection *, void *);
int     iscsi_connection_auth_size_resp(iscsi_connection *);
int     iscsi_connection_auth_write_resp(iscsi_connection *, char *, int);
int     iscsi_connection_auth_process(iscsi_connection *, void *, chiscsi_queue *, char *);
void    iscsi_connection_auth_target_process(iscsi_connection *,
			chiscsi_target_class *, chiscsi_queue *);

int     iscsi_auth_key_match(int *, char *);

int iscsi_get_node_chap_settings(struct iscsi_chap_settings *, void *);

#endif /* ifndef __ISCSI_AUTH_API_H__ */
