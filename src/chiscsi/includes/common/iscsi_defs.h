#ifndef __ISCSI_DEFS_H__
#define __ISCSI_DEFS_H__

#define STATIC  static
#define INLINE  inline

#define PTR_OFFSET(p,offset)	(((unsigned char *)(p)) + (offset))
/* min & max for two numbers */
#define MINIMUM(a,b)	(((a) < (b)) ? (a) : (b))
#define MAXIMUM(a,b)	(((a) > (b)) ? (a) : (b))

#define ISCSI_PROTOCOL_VERSION_MIN	0
#define ISCSI_PROTOCOL_VERSION_MAX	0

#define ISCSI_PORT_DEFAULT	3260
#define ISCSI_INVALID_TAG	0xFFFFFFFF

#define ISCSI_NAME_LEN_MAX	223
#define ISCSI_ALIAS_LEN_MAX	255
#define ISCSI_KEY_NAME_MAX_LEN	63
#define ISCSI_TEXT_VALUE_MAX_LEN 255

/* max. number of bits in a unsigned long bitmask */
#define ISCSI_BITMASK_BIT_MAX	(8*(sizeof(unsigned long)))

/* iscsi heartbeat: nop-out */
#define ISCSI_HEARTBEAT_DEFAULT		0

/* time allowed for an initiator to complete login phase: 5min */
#define ISCSI_LOGIN_COMPLETE_TIME_DEFAULT		300

/* iscsi session MaxOutstandingR2T */
#define ISCSI_SESSION_MAX_OUTSTANDING_R2T 4	/* must be power of 2 */

/* iscsi session scsi command queue depth maximum */
#define ISCSI_SESSION_SCMDQ_DEFAULT	128
#define ISCSI_SESSION_SCMDQ_MAX		2048	/* must be power of 2 */

/* wait for the exp. statsn before sending an explicit nop-in */
#define ISCSI_SESSION_CH_SCMD_ACK_WAIT_TIME	2

/* target: maximum number LU supported by an iSCSI target */
/* make sure it is multiple of ISCSI_BITMASK_BIT_MAX */
#define ISCSI_TARGET_LUN_MAX		(8 * 128)

/* target: device identification for SCSI Inquiry */
#define ISCSI_TARGET_VENDOR_ID_MAXLEN	8
#define ISCSI_TARGET_VENDOR_ID_DFLT	"CHISCSI"	/* 8 bytes */

enum node_type {
	ISCSI_TARGET,
	ISCSI_INITIATOR,

	ISCSI_NODETYPE_MAX
};

enum iscsi_digest_types {
	ISCSI_DIGEST_NONE = 1,
	ISCSI_DIGEST_CRC32C
};

enum iscsi_session_types {
	ISCSI_SESSION_TYPE_NORMAL = 1,
	ISCSI_SESSION_TYPE_DISCOVERY
};

enum iscsi_send_targets {
	ISCSI_SEND_TARGETS_SESSION = 1,
	ISCSI_SEND_TARGETS_SPECIFIED,
	ISCSI_SEND_TARGETS_ALL
};

/**
 * iscsi pdu defines
 **/

/* initiator opcodes */
#define ISCSI_OPCODE_NOP_OUT		0x00
#define ISCSI_OPCODE_SCSI_COMMAND	0x01
#define ISCSI_OPCODE_TMF_REQUEST	0x02
#define ISCSI_OPCODE_LOGIN_REQUEST	0x03
#define ISCSI_OPCODE_TEXT_REQUEST	0x04
#define ISCSI_OPCODE_SCSI_DATA_OUT	0x05
#define ISCSI_OPCODE_LOGOUT_REQUEST	0x06
#define ISCSI_OPCODE_SNACK_REQUEST	0x10
/* (0x1c - 0x1e vendor specific opcodes) */

/* target opcodes */
#define ISCSI_OPCODE_NOP_IN		0x20
#define ISCSI_OPCODE_SCSI_RESPONSE	0x21
#define ISCSI_OPCODE_TMF_RESPONSE	0x22
#define ISCSI_OPCODE_LOGIN_RESPONSE	0x23
#define ISCSI_OPCODE_TEXT_RESPONSE	0x24
#define ISCSI_OPCODE_SCSI_DATA_IN	0x25
#define ISCSI_OPCODE_LOGOUT_RESPONSE	0x26
#define ISCSI_OPCODE_READY_TO_TRANSFER	0x31
#define ISCSI_OPCODE_ASYNC_MESSAGE	0x32
/* (0x3c - 0x3e vendor specific opcodes) */
#define ISCSI_OPCODE_REJECT		0x3f

/* TMF Response values */
#define ISCSI_TMF_RSP_COMPLETE          0x00
#define ISCSI_TMF_RSP_NO_TASK           0x01
#define ISCSI_TMF_RSP_NO_LUN            0x02
#define ISCSI_TMF_RSP_TASK_ALLEGIANT    0x03
#define ISCSI_TMF_RSP_NO_FAILOVER       0x04
#define ISCSI_TMF_RSP_NOT_SUPPORTED     0x05
#define ISCSI_TMF_RSP_AUTH_FAILED       0x06
#define ISCSI_TMF_RSP_REJECTED          0xff

#define IS_INITIATOR_OPCODE(op)	\
	(((op) <= 0x06) || \
	 ((op) == 0x10) || \
	 ((op) >= 0x1c && (op) <= 0x1e))

/* 
 * iscsi pdu header field defines
 */
#define ISCSI_AHS_TYPE_CODE_EXTENDED_CDB	1
#define ISCSI_AHS_TYPE_CODE_EXP_BI_READ_LENGTH	2

#define ISCSI_RESPONSE_COMPLETED		0x00
#define ISCSI_RESPONSE_TARGET_FAILURE		0x01

/* for login request pdu */
#define ISCSI_LOGIN_STAGE_SECURITY		0
#define ISCSI_LOGIN_STAGE_OPERATIONAL		1
#define ISCSI_LOGIN_STAGE_FULL_FEATURE_PHASE	3

#define ISCSI_ISID_TYPE_IEEE_OUI		0
#define ISCSI_ISID_TYPE_IANA_EN			1
#define ISCSI_ISID_TYPE_RANDOM			2

/* for login response pdu */
#define ISCSI_LOGIN_STATUS_CLASS_SUCCESS	0
#define ISCSI_LOGIN_STATUS_CLASS_REDIRECTION	1
#define ISCSI_LOGIN_STATUS_CLASS_INITIATOR_ERROR 2
#define ISCSI_LOGIN_STATUS_CLASS_TARGET_ERROR	3
	/* status detail when status class is redirection */
#define ISCSI_LOGIN_STATUS_DETAIL_REDIR_TEMP	1
#define ISCSI_LOGIN_STATUS_DETAIL_REDIR_PERM	2
	/* status detail when status class is initiator error */
#define ISCSI_LOGIN_STATUS_DETAIL_INIT_ERROR	0
#define ISCSI_LOGIN_STATUS_DETAIL_AUTH_FAILURE	1
#define ISCSI_LOGIN_STATUS_DETAIL_NO_PERMS	2
#define ISCSI_LOGIN_STATUS_DETAIL_TARGET_NOT_FOUND 3
#define ISCSI_LOGIN_STATUS_DETAIL_TARGET_REMOVED 4
#define ISCSI_LOGIN_STATUS_DETAIL_UNSUP_VERSION	5
#define ISCSI_LOGIN_STATUS_DETAIL_TOO_MANY_CONN	6
#define ISCSI_LOGIN_STATUS_DETAIL_MISSING_PARAM	7
#define ISCSI_LOGIN_STATUS_DETAIL_CANT_JOIN_SESS 8
#define ISCSI_LOGIN_STATUS_DETAIL_UNSUP_SESS_TYPE 9
#define ISCSI_LOGIN_STATUS_DETAIL_SESS_NOT_FOUND 10
#define ISCSI_LOGIN_STATUS_DETAIL_INVALID_REQUEST 11

#define ISCSI_LOGIN_STATUS_CLASS_INITIATOR_ERROR_DESC {\
        "Generic failure",	\
        "Authentication failure",\
        "No permission",	\
        "Target node not found",\
        "Target node removed",	\
        "Unsupported version",	\
        "Too many connections",	\
        "Parameter missing",	\
        "Can't join sessions",	\
        "Unsupported session type",\
        "Session not found",	\
        "Invalid login request",\
}

/* status detail when status class is target error */
#define ISCSI_LOGIN_STATUS_DETAIL_TARG_ERROR	0
#define ISCSI_LOGIN_STATUS_DETAIL_SERVICE_UNAVAIL 1
#define ISCSI_LOGIN_STATUS_DETAIL_NO_RESOURCES	2

#define ISCSI_LOGIN_STATUS_CLASS_TARGET_ERROR_DESC {\
        "Generic failure",	\
        "Service unavailable",	\
        "No resources",		\
}

/* for logout request */
#define ISCSI_LOGOUT_REASON_CLOSE_SESSION	0
#define ISCSI_LOGOUT_REASON_CLOSE_CONNECTION	1
#define ISCSI_LOGOUT_REASON_REMOVE_CONNECTION_FOR_RECOVERY 2
#define ISCSI_LOGOUT_REASON_AUTO_SELECT		0xf

/* for logout repsonse pdu */
#define ISCSI_RESPONSE_LOGOUT_SUCCESS		0
#define ISCSI_RESPONSE_LOGOUT_INVALID_CID	1
#define ISCSI_RESPONSE_LOGOUT_NO_RECOVERY	2
#define ISCSI_RESPONSE_LOGOUT_CLEANUP_FAILED	3

/* for reject pdu */
#define ISCSI_REJECT_REASON_DATA_DIGEST_ERROR	0x2
#define ISCSI_REJECT_REASON_SNACK_REJECT	0x3
#define ISCSI_REJECT_REASON_PROTOCOL_ERROR	0x4
#define ISCSI_REJECT_REASON_CMD_NOT_SUPPORTED	0x5
#define ISCSI_REJECT_REASON_IMMEDIATE_CMD_REJECT 0x6
#define ISCSI_REJECT_REASON_TASK_IN_PROGRESS	0x7
#define ISCSI_REJECT_REASON_INVALID_DATA_ACK	0x8
#define ISCSI_REJECT_REASON_INVALID_PDU_FIELD	0x9
#define ISCSI_REJECT_REASON_LONG_OPERATION_REJECT 0xa
#define ISCSI_REJECT_REASON_NEGOTIATION_RESET	0xb
#define ISCSI_REJECT_REASON_WAITING_FOR_LOGOUT	0xc

/* for scsi command pdu */
#define ISCSI_TASK_ATTRIBUTES_UNTAGGED		0
#define ISCSI_TASK_ATTRIBUTES_SIMPLE		1
#define ISCSI_TASK_ATTRIBUTES_ORDERED		2
#define ISCSI_TASK_ATTRIBUTES_HEAD_OF_QUEUE	3
#define ISCSI_TASK_ATTRIBUTES_ACA		4

/* for snack request pdu */
#define ISCSI_SNACK_TYPE_DATA_R2T_SNACK		0
#define ISCSI_SNACK_TYPE_STATUS_SNACK		1
#define ISCSI_SNACK_TYPE_DATA_ACK		2
#define ISCSI_SNACK_TYPE_RDATA_SNACK		3

/* for tmf request pdu */
#define ISCSI_TMF_FUNCTION_ABORT_TASK		1
#define ISCSI_TMF_FUNCTION_ABORT_TASK_SET	2
#define ISCSI_TMF_FUNCTION_CLEAR_ACA		3
#define ISCSI_TMF_FUNCTION_CLEAR_TASK_SET	4
#define ISCSI_TMF_FUNCTION_LOGICAL_UNIT_RESET	5
#define ISCSI_TMF_FUNCTION_TARGET_WARM_RESET	6
#define ISCSI_TMF_FUNCTION_TARGET_COLD_RESET	7
#define ISCSI_TMF_FUNCTION_TASK_REASSIGN	8

/* for tmf response pdu */
#define ISCSI_RESPONSE_TMF_COMPLETE		0x00
#define ISCSI_RESPONSE_TMF_INVALID_TASK		0x01
#define ISCSI_RESPONSE_TMF_INVALID_LUN		0x02
#define ISCSI_RESPONSE_TMF_TASK_STILL_ALLEGIANT	0x03
#define ISCSI_RESPONSE_TMF_NO_TASK_FAILOVER	0x04
#define ISCSI_RESPONSE_TMF_NOT_SUPPORTED	0x05
#define ISCSI_RESPONSE_TMF_AUTH_FAILED		0x06
#define ISCSI_RESPONSE_TMF_FUNCTION_REJECTED	0xff

/* for async message pdu */
#define ISCSI_ASYNC_EVENT_SCSI			0
#define ISCSI_ASYNC_EVENT_TARGET_PDU_REQ_LOGOUT	1
#define ISCSI_ASYNC_EVENT_TARGET_PDU_DROP_CONN	2
#define ISCSI_ASYNC_EVENT_TARGET_PDU_DROP_SESS	3
#define ISCSI_ASYNC_EVENT_TARGET_PDU_REQ_NEGOTIATION 4
#define ISCSI_ASYNC_EVENT_ALL_ACTIVE_TASKS_TERMINATED 5
#define ISCSI_ASYNC_EVENT_VENDOR		255

#define DEFAULT_ABORT_TIMEOUT         15
#define DEFAULT_LU_RESET_TIMEOUT      30
#define DEFAULT_HOST_RESET_TIMEOUT    60 

#define DEFAULT_SECT_SIZE_SHIFT		9
#endif
