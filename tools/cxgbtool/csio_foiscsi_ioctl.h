/*
 *  Copyright (C) 2008-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description:
 *
 */
#ifndef __CSIO_FOISCSI_IOCTL_H__
#define __CSIO_FOISCSI_IOCTL_H__

#define ISCSI_SEND_TARGETS_BUF_LEN 	(512 * 2048)
#define MAX_PORTS			4
#define	MAX_IDX				8

struct csio_foiscsi_iface_ioctl {
	uint8_t	op;
	uint8_t ifid;
	uint8_t retval;
	uint8_t flags;
};

struct csio_foiscsi_ifconf_ioctl {
	/* header */
	uint8_t		ifid;
	uint8_t		subop;
	uint16_t	type;
	uint8_t		retval;
	
	/* L2 */
	uint16_t	vlanid;
	uint16_t	mtu;
	uint8_t		mac[8];

	union {
		struct _v4 {
			/* L3 IPV4 */
			uint32_t	ipv4_addr;
			uint32_t	ipv4_mask;
			uint32_t	ipv4_gw;
		}v4;
		struct _v6 {
			/* L3 IPV6 */
			uint8_t		ipv6_addr[16];
			uint8_t		ipv6_gw[16];
			uint8_t		prefix_len;
		}v6;
	};
	uint16_t	address_state;
};

enum iscsi_stat {
	ISCSI_STATUS_SUCCESS,
	ISCSI_STATUS_MORE_BUF,
	ISCSI_STATUS_FAILURE,
	ISCSI_STATUS_IP_CONFLICT,
	ISCSI_STATUS_INVALID_IP,
	ISCSI_STATUS_HOST_UNREACHABLE,
	ISCSI_STATUS_NETWORK_DOWN,
	ISCSI_STATUS_TIMEOUT,
	ISCSI_STATUS_INVALID_HANDLE
};


enum foiscsi_err {
	FOISCSI_ERR_INVALID_PARAM = 1,
	FOISCSI_ERR_OOM,
	FOISCSI_ERR_NOT_IMPLEMENTED,
	FOISCSI_ERR_NODEV,
	FOISCSI_ERR_INVALID_INDEX,
	FOISCSI_ERR_INST_EEXISTS,
	FOISCSI_ERR_MAX_INST_EXCEEDS,
	FOISCSI_ERR_ENORES,
	FOISCSI_ERR_INVALID_INST_NAME,
	FOISCSI_ERR_INVALID_OPER,
	FOISCSI_ERR_INST_NOT_FOUND,
	FOISCSI_ERR_INST_BUSY,
	FOISCSI_ERR_ZERO_OBJ_FOUND,
	FOISCSI_ERR_IFACE_NOT_PROVISIONED,
	FOISCSI_ERR_SESSION_EXISTS,
	FOISCSI_ERR_PARAM,
	FOISCSI_ERR_INVALID_REQUEST,
	FOISCSI_ERR_LOGIN_TIMEDOUT,
	FOISCSI_ERR_IFACE_INVALID_PORT,
	FOISCSI_ERR_IFACE_BUSY,
	FOISCSI_ERR_IFACE_ENOLINK,
	FOISCSI_ERR_LAST,
};

enum cxgbtool_foiscsi_mode {
	CXGBTOOL_FOISCSI_MODE_NONE = -1,
	
	MODE_INIT_INSTANCE = 0,
	MODE_SESSION,
	MODE_DISCOVERY,
	MODE_IFACE,
	MODE_IFCONF,
	MODE_PERSISTENT,
	MODE_HW,

	CXGBTOOL_FOISCSI_MODE_MAX,
};

enum cxgbtool_foiscsi_op {
	OP_NOOP		= 0x00,
	OP_ASSIGN	= 0x01,
	OP_CLEAR	= 0x02,
	OP_SHOW		= 0x03,
	OP_LOGIN	= 0x04,
	OP_LOGOUT	= 0x05,
	OP_UP		= 0x06,
	OP_DOWN		= 0x07,
	OP_MTU		= 0x08,
	OP_VLAN		= 0x09,
	OP_DCBX		= 0x0a,
	OP_LLOCAL	= 0x0b,
	OP_LAST		= 0x0c,
};

enum cxgbtool_foiscsi_l3config_type {
	TYPE_NONE	= 0x00,
	TYPE_IPV4	= 0x01,
	TYPE_IPV6	= 0x02,
	TYPE_VLAN_IPV4	= 0x03,
	TYPE_VLAN_IPV6	= 0x04,
	TYPE_DHCP	= 0x05,
	TYPE_VLAN_DHCP	= 0x06,
	TYPE_DHCPV6	= 0x07,
	TYPE_VLAN_DHCP6 = 0x08,
	TYPE_RTADV6	= 0x09,
	TYPE_VLN_RTADV6	= 0x0a,
	TYPE_LINKLOCAL6 = 0x0b,
};


struct foiscsi_instance {
	int		op;
	int		id;
	uint8_t		retval;
	uint8_t		res[3];
	uint16_t	login_retry_cnt;
	uint16_t	recovery_timeout;
	char		name[FW_FOISCSI_NAME_MAX_LEN];
	char		alias[FW_FOISCSI_ALIAS_MAX_LEN];
	char		chap_id[FW_FOISCSI_NAME_MAX_LEN];
	char		chap_sec[FW_FOISCSI_CHAP_SEC_MAX_LEN + 1];
	char		res1[3];
};

enum foiscsi_count_type {
	FOISCSI_INSTANCE_COUNT = 0,
	FOISCSI_SESSION_COUNT,
	FOISCSI_IFACE_COUNT,
};

struct foiscsi_count {
	int type;
	int count;
	int inode_idx;
};

struct num_target {
	uint32_t	port;
	uint32_t	num_reg_target; 
};

struct ip_addr {
	union {
		uint32_t	ip4;
		uint8_t		ip6[16];
	};
};

struct targ_del {
	uint8_t		name[FW_FOISCSI_NAME_MAX_LEN];
	uint8_t		ip_type;  /* ipv4 or ipv6 */
	struct ip_addr	ip;
	uint16_t	port;
	uint32_t	status;
	uint8_t		pad;
};

struct foiscsi_sess_info {
	int		inode_idx;
	int		sess_idx;
	int 		ip_type;
	struct ip_addr	init_ip;
	struct ip_addr	targ_ip;
	uint16_t	targ_port;
	uint8_t		tpgt;
	uint8_t		port;
	uint8_t		state;
	uint8_t		rsvd[3];
	uint8_t		targ_name[FW_FOISCSI_NAME_MAX_LEN];
	uint8_t		targ_alias[FW_FOISCSI_NAME_MAX_LEN];
};

struct foiscsi_login_info {
	int				op;
	uint16_t			login_retry_cnt;
	uint16_t			abort_timeout;
	uint16_t			lur_timeout;
	uint16_t			recovery_tmo; /* currently used by ESXi only */
	int				inode_id;
	int				sess_id; /* out param. driver returns */
	int				ip_type;
	struct ip_addr			tgt_ip; /* discovery target ip */
	struct ip_addr			src_ip; /* initiator ip */
	uint32_t			buf_len; /* length of the buf having sendtargets resp */
	uint32_t			status;
	uint32_t			vlanid;
	int				sess_idx;
	void				*disc_buf;
	struct fw_foiscsi_sess_attr	sess_attr;
	struct fw_foiscsi_conn_attr	conn_attr;
	uint16_t			tgt_port; /* disc target tcp port */
	uint8_t				persistent;
	uint8_t				tgt_name[FW_FOISCSI_NAME_MAX_LEN];
	uint8_t				tgt_alias[FW_FOISCSI_ALIAS_MAX_LEN];
	char				tgt_id[FW_FOISCSI_NAME_MAX_LEN];
	char				tgt_sec[FW_FOISCSI_CHAP_SEC_MAX_LEN + 1];
};

struct foiscsi_logout_info {
	int		op;
	int		inode_id;
	int		sess_id;
	int		status;
};

int foiscsi_manage_instance(int, int, int, char *, char *,
		char *ini_user, char *ini_sec);
int foiscsi_manage_session(int hw, int op, int dbindex,
		char *sip, char *targetname, char *dip, int tcp_port,
		int sid,  char *auth_method, char *policy, char *tgt_user, char *tgt_sec,
		int persistent, unsigned int vlanid);
int foiscsi_do_discovery(int hw, int op, int dbindex,
		char *sip, char *dip, int tcp_port, unsigned int vlanid,
		struct foiscsi_login_info *);

#endif/*__CSIO_FOISCSI_IOCTL_H__*/
