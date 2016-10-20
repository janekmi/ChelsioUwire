#ifndef __ISCSI_OFFLOAD_H__
#define __ISCSI_OFFLOAD_H__

#define ISCSI_OFFLOAD_MODE_AUTO		0x0
#define ISCSI_OFFLOAD_MODE_NIC		0x1
#define ISCSI_OFFLOAD_MODE_TOE		0x2
#define ISCSI_OFFLOAD_MODE_CRC		0x4
#define ISCSI_OFFLOAD_MODE_DDP		0x8
#define ISCSI_OFFLOAD_MODE_T10DIX	0x10
#define ISCSI_OFFLOAD_MODE_ULP  \
	(ISCSI_OFFLOAD_MODE_CRC | ISCSI_OFFLOAD_MODE_DDP | \
					ISCSI_OFFLOAD_MODE_T10DIX)
#define ISCSI_CTL_OFFLOAD_MODE_CHNG	0x20
#define ISCSI_OFFLOAD_MODE_FORCE	0x40

#define ISCSI_OFFLOAD_MODE_DEFAULT	ISCSI_OFFLOAD_MODE_ULP

enum t10_dif_dix {
	ISCSI_OFFLOAD_NOPROT = 0,		/* No protection operation */
	ISCSI_OFFLOAD_T10DIX = 1 << 0,		/* Support t10 dix operation,
					   	   no dif i.e. hba to backend */
	ISCSI_OFFLOAD_T10DIXDIF = 1 << 1,	/* Support t10 dix and dif both
						   i.e. end to end */
};

/* offload performance tunables */
#define ISCSI_PERF_ALIGN8		0x1
#define ISCSI_PERF_VENDOR_KEY		0x2

/* worker thread distribution policy */
enum wth_distro_policy {
	ISCSI_WORKER_POLICY_QSET,	/* 0: go with toeq */
	ISCSI_WORKER_POLICY_RR,		/* 1: round-robin */
	ISCSI_WORKER_POLICY_MAX = ISCSI_WORKER_POLICY_RR
};
#define ISCSI_WORKER_POLICY_DEFAULT	ISCSI_WORKER_POLICY_RR

/* defines for target authentication order */
#define ISCSI_AUTH_ORDER_NONE		0x0
#define ISCSI_AUTH_ORDER_ACL_FIRST	0x1
#define ISCSI_AUTH_ORDER_CHAP_FIRST	0x2

/* defines for the target acl order */
#define ISCSI_ACL_ORDER_CONFIG_FIRST	0x1
#define ISCSI_ACL_ORDER_ISNS_FIRST	0x2

/* defines for discovery chap support */
#define ISCSI_DISC_AUTH_METHOD_NONE	0x0
#define ISCSI_DISC_AUTH_METHOD_CHAP	0x1
#define ISCSI_DISC_AUTH_POLICY_ONEWAY	0x0
#define ISCSI_DISC_AUTH_POLICY_MUTUAL	0x1
#define ISCSI_CHAP_CHALLENGE_LENGTH_MAX	1024

#endif /* ifndef __ISCSI_OFFLOAD_H__ */
