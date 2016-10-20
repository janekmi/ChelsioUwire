#ifndef __ISCSI_ERROR_H__
#define __ISCSI_ERROR_H__

/*
 * iSCSI error code
 */

enum iscsi_login_error_code {
	LOGIN_NO_ERROR,
	LOGIN_TARGET_ERROR,
	LOGIN_INITIATOR_ERROR,
	LOGIN_FAILED_AUTH
};

enum iscsi_errors {
	ISCSI_GOOD,
	ISCSI_EFAIL,		/* general failure */
	ISCSI_EUSER,		/* copy from/to user space failed */
	ISCSI_ECHRDEV,		/* unable to register ioctl device */
	ISCSI_ECMD,		/* unknown control command */
	ISCSI_EREQ,		/* unknown control command request */
	ISCSI_ENOBUF,		/* no ioctl buffer */
	ISCSI_ENONODE,		/* initiator/target not found */
	ISCSI_ENONAME,		/* initiator/target name missing */
	ISCSI_ENOTFOUND,	/* entity not found */
	ISCSI_ENOMATCH,		/* no match found */
	ISCSI_EMISMATCH,	/* mismatch */
	ISCSI_EOPFAILED,	/* operation failed */
	ISCSI_EDUP,		/* duplicate, already existed */
	ISCSI_EOVERLAP,		/* overlapping values */
	ISCSI_EMULTI,		/* multiple values */
	ISCSI_EKEY,		/* invalid key */
	ISCSI_EFORMAT,		/* invalid format */
	ISCSI_EFORMAT_STR,	/* string unterminated */
	ISCSI_EFORMAT_LONG,	/* longer than max. */
	ISCSI_EFORMAT_SHORT,	/* short than min. */
	ISCSI_EFORMAT_BIG,	/* larger than max. */
	ISCSI_ENOMEM,		/* out of memory */
	ISCSI_ENOTREADY,	/* busy */
	ISCSI_EBUSY,		/* busy */
	ISCSI_EFULL,		/* full */
	ISCSI_EINVAL,		/* invalid value */
	ISCSI_EINVAL_OOR,	/* invalid value, out of range */
	ISCSI_EINVAL_STATE,	/* invalid state */
	ISCSI_EZERO,		/* all zero value */
	ISCSI_ESOCK,
	ISCSI_EIO,
	ISCSI_ETHREAD,

	ISCSI_ENULL,		/* null pointer */
	ISCSI_ENOTSUPP,		/* functionality not supported */
	ISCSI_ESBUF_R,		/* socket buffer read error */

	ISCSI_EAGAIN,		/* try again */
	ISCSI_ESTATE,		/* socket buffer read error */
	ISCSI_EUNDERFLOW,	/* socket buffer read error */
	ISCSI_EOVERFLOW,	/* socket buffer read error */
        ISCSI_EREDIRECT,        /* redirect */
};

#endif /* ifndef __ISCSI_ERROR_H__ */
