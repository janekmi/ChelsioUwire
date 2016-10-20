#include "iscsi_auth_private.h"
#include "chap/iscsi_chap_api.h"

/*
 * authenticaion method table
 */
const iscsi_auth_method iscsi_auth_method_tbl[AUTH_METHOD_MAX] = {
	/* AUTH_METHOD_NONE */
	{
	 .name = "None"},
	/* AUTH_METHOD_CHAP */
	{
	 .name = "CHAP",
	 .config_key_max = CHAP_KEY_CONFIG_COUNT,
	 .auth_key_max = CHAP_KEY_AUTH_COUNT,
	 .config_key_tbl = chap_config_key_table,
	 .auth_key_tbl = chap_auth_key_table,
	 .fp_node_cleanup = chap_node_free,
	 .fp_session_cleanup = chap_session_free,
	 .fp_node_display = chap_node_config_display,
	 .fp_node_text_size = chap_node_config_text_size,
	 .fp_node_config = chap_node_config,
	 .fp_node_config_add = chap_node_config_add,
	 .fp_node_config_remove = chap_node_config_remove,
	 .fp_conn_process = chap_connection_process}
};
