#ifndef __ISCSI_CONTROL_DEFS_H__
#define __ISCSI_CONTROL_DEFS_H__

#include <common/iscsi_offload.h>

/*
 * iscsi control interface (user <-> kernel) 
 */

/* defines for initiator redirect */
#define ISCSI_MAX_REDIRECT_DEFAULT		10
#define ISCSI_MAX_REDIRECT_MAX			100

/*
 * control opcode
 */
enum iscsi_control_opcode {
	ISCSI_CONTROL_OPCODE_UNKNOWN,

	/* user space opcode: used only in user space */

	ISCSI_CONTROL_OPCODE_CONFIG_FILE_WRITE,

	ISCSI_CONTROL_OPCODE_CONFIG_GET,

	ISCSI_CONTROL_OPCODE_DBGDUMP,

	/* kernel space opcode: user -> kernel space */

	ISCSI_CONTROL_OPCODE_DRV_GET,
	ISCSI_CONTROL_OPCODE_DRV_SET,

	ISCSI_CONTROL_OPCODE_STAT_GET,

	ISCSI_CONTROL_OPCODE_TARGET_FLUSH,
	ISCSI_CONTROL_OPCODE_TARGET_GET_NAMES,
	ISCSI_CONTROL_OPCODE_TARGET_GET,
	ISCSI_CONTROL_OPCODE_TARGET_GET_WRITE,
	ISCSI_CONTROL_OPCODE_TARGET_ADD,
	ISCSI_CONTROL_OPCODE_TARGET_RELOAD,
	ISCSI_CONTROL_OPCODE_TARGET_REMOVE,
	ISCSI_CONTROL_OPCODE_TARGET_DBG_SESSION,
	ISCSI_CONTROL_OPCODE_DROP_SESSION,

	ISCSI_CONTROL_OPCODE_ISNS_BASE,

	ISCSI_CONTROL_OPCODE_ISNS_GET_TARGET_PORTALS =
				ISCSI_CONTROL_OPCODE_ISNS_BASE,
	ISCSI_CONTROL_OPCODE_ISNS_GET_TARGETS,
	ISCSI_CONTROL_OPCODE_ISNS_SET_TARGET_ACL,

	ISCSI_CONTROL_OPCODE_MAX
};

/*
 * iscsi_control_args - control request/response struct
 * @buf -- used for request
 * @addr/@len -- additional data buffers for more request data or response
 *		 if needed
 */
#define ISCSI_CONTROL_REQ_MAX_BUFLEN	512
typedef struct iscsi_control_args iscsi_control_args;
struct iscsi_control_args {
	char    buf[ISCSI_CONTROL_REQ_MAX_BUFLEN];
	unsigned long timestamp;
	unsigned int flag;
#define ISCSI_CONTROL_FLAG_EXTRA_DATA	0x1
#define ISCSI_CONTROL_FLAG_DETAIL	0x2
	unsigned int len[2];
	unsigned long addr[2];
};

#endif /* ifndef __ISCSI_CONTROL_DEFS_H__ */
