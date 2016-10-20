#ifndef __CHISCSI_INFO_H__
#define __CHISCSI_INFO_H__

#include "iscsi_defs.h"
#include "iscsi_tcp.h"
#include "iscsi_offload.h"

#define ISCSI_SESSION_INFO_MAX		2048
#define ISCSI_CONNECTION_INFO_MAX	2048
#define ISCSI_IP_INFO_MAX		32

struct iscsi_session_settings {
	unsigned char initial_r2t:1;
	unsigned char immediate_data:1;
	unsigned char erl:2;
	unsigned char data_pdu_in_order:1;
	unsigned char data_sequence_in_order:1;
	unsigned char filler:2;

	unsigned int max_conns;
	unsigned int max_r2t;
	unsigned int first_burst;
	unsigned int max_burst;
	unsigned int time2wait;
	unsigned int time2retain;
};
int chiscsi_session_settings_sprintf(struct iscsi_session_settings *, char *);

struct iscsi_conn_settings {
	unsigned char header_digest[2];
	unsigned char data_digest[2];

	unsigned int portal_group_tag;
	unsigned int max_recv_data_segment;
	unsigned int max_xmit_data_segment;
};
int chiscsi_conn_settings_sprintf(struct iscsi_conn_settings *, char *);

struct iscsi_chap_settings {
	unsigned char chap_en:1;
	unsigned char chap_required:1;
	unsigned char mutual_chap_forced:1;
	unsigned char filler:5;

	unsigned int challenge_length;
};
int chiscsi_chap_settings_sprintf(struct iscsi_chap_settings *, char *);

struct iscsi_target_config_settings {
	unsigned char acl_en:1;
	unsigned char isns_register:1;
	unsigned char shadow_mode:1;
	unsigned char filler:5;

	unsigned int sess_max_cmds;
};
int chiscsi_target_config_settings_sprintf(
				struct iscsi_target_config_settings *, char *);

struct chiscsi_target_info {
	char name[256];
	char alias[256];

	struct iscsi_session_settings sess_keys;
	struct iscsi_conn_settings conn_keys;

	struct iscsi_chap_settings chap;

	struct iscsi_target_config_settings config_keys;

	unsigned char auth_order;
	/* private to Chelsio Stack */
	unsigned long hndl;
};
int chiscsi_target_info_sprintf(struct chiscsi_target_info *, char *);

struct chiscsi_perf_info {
	unsigned long read_bytes;
	unsigned long write_bytes;
	unsigned long read_cmd_cnt;
	unsigned long write_cmd_cnt;
};
int chiscsi_perf_info_sprintf(struct chiscsi_perf_info *, char *);
 
struct chiscsi_session_info {
	char peer_name[256];
	char peer_alias[256];

	struct iscsi_session_settings sess_keys;

	unsigned char type;
	unsigned char isid[6];
	unsigned char conn_cnt;
	unsigned short tsih;

	unsigned int cmdsn;
	unsigned int maxcmdsn;
	unsigned int expcmdsn;

	struct chiscsi_perf_info perf;

	/* private to Chelsio Stack */
	unsigned long hndl;
};
int chiscsi_session_info_sprintf(struct chiscsi_session_info *, char *);

struct chiscsi_connection_info {
	struct chiscsi_tcp_endpoints tcp_endpoints;

	struct iscsi_conn_settings conn_keys;
	
	unsigned char offloaded:1;
	unsigned char filler:7;

	unsigned int cid;
	unsigned int statsn;
	unsigned int expstatsn;

	/* private to Chelsio Stack */
	unsigned long hndl;
};
int chiscsi_connection_info_sprintf(struct chiscsi_connection_info *, char *);

struct chiscsi_portal_info {
	unsigned int flag;
	struct tcp_endpoint ep;

	struct chiscsi_perf_info perf;
};
int chiscsi_portal_info_sprintf(struct chiscsi_portal_info *, char *);


int chiscsi_get_target_info(char *tname,
			struct chiscsi_target_info *target_info);
int chiscsi_get_one_session_info(void *sess_ptr,
			struct chiscsi_session_info *sess_info);
int chiscsi_get_session_info(char *tname, char *iname,
			int sess_info_max,
			struct chiscsi_session_info *sess_info);
/*
 * chiscsi_get_connection_info()
 * should be called after chiscsi_get_session_info()
 *	for (i = 0; i < chiscsi_session_info.conn_cnt; i++)
 *		chiscsi_get_connection_info(chiscsi_session_info.hndl, i,
 *						&conn_info);
 */
int chiscsi_get_connection_info(unsigned long sess_hndl, int conn_idx,
			struct chiscsi_connection_info *conn_info);

int chiscsi_get_perf_info(struct tcp_endpoint *ep, 
			  struct chiscsi_perf_info *pdata);

#endif /* __CHISCSI_INFO_H__ */
