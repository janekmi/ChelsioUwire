#ifndef __ISCSI_PDU_H__
#define __ISCSI_PDU_H__

/*
 * iscsi_pdu.h -- iscsi_pdu structure
 */
#include <common/iscsi_sgvec.h>
#include <common/cxgbi_t10.h>

#define ISCSI_BHS_SIZE			48
#define ISCSI_PDU_DIGEST_SIZE		4	/* CRC32C */
#define ISCSI_PDU_MAX_PAD_SIZE		4	/* padding bytes */
#define ISCSI_PDU_HEAD_BUFLEN		\
	(ISCSI_BHS_SIZE + ISCSI_PDU_DIGEST_SIZE)
#define ISCSI_PDU_TAIL_BUFLEN		\
	(ISCSI_PDU_MAX_PAD_SIZE + ISCSI_PDU_DIGEST_SIZE)

/* to hold rx pi */
#define ISCSI_PDU_PI_SGBUF_COUNT	2

#if 0

/* pdu t10dif information */
enum iscsi_scsi_prot_op {
	ISCSI_PI_OP_SCSI_PROT_NORMAL = 0,

	ISCSI_PI_OP_SCSI_PROT_READ_INSERT,
	ISCSI_PI_OP_SCSI_PROT_WRITE_STRIP,

	ISCSI_PI_OP_SCSI_PROT_READ_STRIP,
	ISCSI_PI_OP_SCSI_PROT_WRITE_INSERT,

	ISCSI_PI_OP_SCSI_PROT_READ_PASS,
	ISCSI_PI_OP_SCSI_PROT_WRITE_PASS,

};

enum iscsi_scsi_pi_interval {
	ISCSI_SCSI_PI_INTERVAL_512 = 0,
	ISCSI_SCSI_PI_INTERVAL_4K,
};

enum pi_guard_type {
	ISCSI_PI_GUARD_TYPE_IP = 0,
	ISCSI_PI_GUARD_TYPE_CRC
};

enum pi_dif_type {
	ISCSI_PI_DIF_TYPE_0 = 0,
	ISCSI_PI_DIF_TYPE_1,
	ISCSI_PI_DIF_TYPE_2,
	ISCSI_PI_DIF_TYPE_3
};

struct cxgbi_pdu_pi_info {
	unsigned char  prot_op:3,
		       guard:1,
		       interval:1,
		       linear:1,
		       dif_type:2;
	unsigned char  pi_sgcnt;
	unsigned short pi_len;
	unsigned short pi_offset;
	unsigned short app_tag;
	unsigned int   ref_tag;
};
#endif

#define ISCSI_PDU_ISO_INFO_FLAGS_FSLICE 0x01
#define ISCSI_PDU_ISO_INFO_FLAGS_LSLICE 0x02

struct iscsi_pdu_iso_info {
	unsigned char flags;
	unsigned char num_pdu;
	unsigned int  mpdu;
	unsigned int  burst_size;
	unsigned int  len;
	unsigned int  segment_offset;
	unsigned int  datasn_offset;
	unsigned int  buffer_offset;
	unsigned int  iso_extra;
};

/* 
 * pdu flag (p_flag) 
 */

/* 
   PDU flags
*/
#define ISCSI_PDU_FLAG_LOCKED		0x1
#define ISCSI_PDU_FLAG_OOR		0x2
#define ISCSI_PDU_FLAG_DATA_BUF_LOCAL	0x4
#define ISCSI_PDU_FLAG_DATA_SKIP	0x8

#define ISCSI_PDU_FLAG_BHS_PROC_DELAY	0x10

/* for RX */
#define ISCSI_PDU_FLAG_DATA_MAPPED	0x20
#define ISCSI_PDU_FLAG_DATA_DDPED	0x40
#define ISCSI_PDU_FLAG_REJECT		0x80

#define ISCSI_PDU_FLAG_ERR_HDR_DIGEST	0x100
#define ISCSI_PDU_FLAG_ERR_DATA_DIGEST	0x200
#define ISCSI_PDU_FLAG_ERR_DATA_PAD	0x400

#define ISCSI_PDU_FLAG_DROP		0x800
/* for TX */
#define ISCSI_PDU_FLAG_TX_SEQ		0x20
#define ISCSI_PDU_FLAG_TX_ISO		0x40

/* for TMF */
#define ISCSI_PDU_FLAG_TMF_ABORT	0x1000
#define ISCSI_PDU_FLAG_TMF_SENSE	0x2000
#define ISCSI_PDU_FLAG_TMF_RESPONDED 	0x4000
#define ISCSI_PDU_FLAG_TMF_POSTPONED 	0x8000

/* for RX PI */
#define ISCSI_PDU_FLAG_PI_RCVD		0x10000
#define ISCSI_PDU_FLAG_PI_DDPD		0x20000
#define ISCSI_PDU_FLAG_PI_ERR		0x40000

/* for RX Completion */
#define ISCSI_PDU_FLAG_RX_CMPL		0x80000

typedef struct iscsi_pdu iscsi_pdu;

struct iscsi_pdu {
	/* os dependent */

	/* os independent */
	struct iscsi_pdu *p_next;

	void   *p_conn;
	unsigned int p_flag;

	unsigned char p_head[ISCSI_PDU_HEAD_BUFLEN];
	unsigned char p_tail[ISCSI_PDU_TAIL_BUFLEN];

	unsigned int p_ahslen;
	unsigned int p_pdulen;  /* ISO */
	unsigned int p_datalen;
	unsigned int p_totallen;
	unsigned char p_ddlen;
	unsigned char p_padlen;
	unsigned char p_hdlen;

	/* commonly used bhs field */
	unsigned char p_opcode;
	/* p_offset - when reading from socket, keeps track of how many 
		      bytes we've read, after the whole pdu is read, 
		      the p_offset is set to buffer offset in BHS */
	unsigned int p_offset;
	unsigned int p_sn;	/* target:    tx - statsn, rx - cmdsn */ 
				/* initiator: tx - cmdsn */
	unsigned int p_itt;

	unsigned int p_sgcnt_used;
	unsigned int p_sgcnt_total;

	/* pi related */
	struct cxgbi_pdu_pi_info pi_info;

	struct iscsi_pdu_iso_info iso_info;

	/* data pointers */
	unsigned char *p_bhs;
	unsigned char *p_ahs;
	unsigned int *p_hdigest;
	unsigned int *p_ddigest;

	chiscsi_queue	*p_saveq;

	void *p_scmd;		/* rx, scsi command, tx/rx: nop-out/in */
	union {
		void *p_scmd_burst;	/* rx, scsi command data burst */
		void *p_skb;		/* tx, skb, offload mode */
	};

	chiscsi_sgvec *p_sglist;

	/* Used only in read direction */
	chiscsi_sgvec *p_prot_sglist;
	chiscsi_sgvec p_pi_sglist[ISCSI_PDU_PI_SGBUF_COUNT];
	unsigned int p_pi_sgcnt_used;
	unsigned int p_pi_sgcnt_total;

	unsigned int p_ppod_totallen;
	void *p_ppod_skb_list;
};

#define ISCSI_PDU_SIZE	sizeof(iscsi_pdu)

#define iscsi_pdu_enqueue(L,Q,P)      ch_enqueue_tail(L,iscsi_pdu,p_next,Q,P)
#define iscsi_pdu_ch_enqueue_head(L,Q,P) ch_enqueue_head(L,iscsi_pdu,p_next,Q,P)
/* insert by pdu->p_offset */
#define iscsi_pdu_enqueue_by_offset(L,Q,P) \
                ch_enqueue_by_field_incr(L,iscsi_pdu,p_next,Q,P,p_offset)
/* insert by pdu->p_sn */
#define iscsi_pdu_enqueue_by_cmdsn(L,Q,P) \
                ch_enqueue_by_field_incr(L,iscsi_pdu,p_next,Q,P,p_sn)
#define iscsi_pdu_dequeue(L,Q,P)      ch_dequeue_head(L,iscsi_pdu,p_next,Q,P)
#define iscsi_pdu_ch_qremove(L,Q,P)      ch_qremove(L,iscsi_pdu,p_next,Q,P)
#define iscsi_pdu_qsearch_by_ITT(L,Q,P,V) \
                ch_qsearch_by_field_value(L,iscsi_pdu,p_next,Q,P,p_itt,V)
#define iscsi_pdu_qsearch_by_cmdsn(L,Q,P,V) \
                ch_qsearch_by_field_value(L,iscsi_pdu,p_next,Q,P,p_sn,V)
#define iscsi_pdu_qsearch_by_skb(L,Q,P,V) \
                ch_qsearch_by_field_value(L,iscsi_pdu,p_next,Q,P,p_skb,V)

typedef struct iscsi_tmf iscsi_tmf;

struct iscsi_tmf {
        unsigned char p_itt;
        unsigned char p_func;
        unsigned char p_resp;
        unsigned char p_filler;
	unsigned int p_lun;
        unsigned long p_flag;
	unsigned int p_sn;
        void *p_conn;
	void *p_sess;
        void *p_task;
	void *p_lock;
        struct iscsi_tmf *p_next;
};

/* provided by the iSCSI core library */
int iscsi_pdu_enlarge_sglist(iscsi_pdu *, unsigned int);
int iscsi_pdu_parse_header(iscsi_pdu *);

#endif /* ifndef __ISCSI_PDU_H__ */
