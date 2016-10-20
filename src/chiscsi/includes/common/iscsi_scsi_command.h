#ifndef __ISCSI_SCSI_COMMAND_H__
#define __ISCSI_SCSI_COMMAND_H__

#include <linux/dma-mapping.h>


#include <common/iscsi_queue.h>
#include <common/iscsi_sgvec.h>
#include <common/iscsi_pdu.h>
#include <common/iscsi_tcp.h>
#include <common/iscsi_defs.h>

#define SCSI_SENSE_BUFFERSIZE	96

struct chiscsi_target_lun_class;
struct chiscsi_target_lun;

/* scsi command */
typedef struct chiscsi_scsi_command chiscsi_scsi_command;
typedef struct chiscsi_scsi_cmd_cb chiscsi_scsi_cmd_cb;
typedef struct chiscsi_scsi_read_cb chiscsi_scsi_read_cb;
typedef struct chiscsi_scsi_write_cb chiscsi_scsi_write_cb;
typedef struct chiscsi_scsi_write_burst_cb chiscsi_scsi_write_burst_cb;

/*
 * iscsi scsi command read/write data tracking
 */
struct chiscsi_scsi_read_cb {
	unsigned int r_maxburst;	/* sess's max. burst length */
	unsigned int r_burst;	/* initiator: rcv len. of current burst  
				   target: # of bursts built */
	unsigned int r_offset;
	unsigned int r_acked;
	unsigned int r_datasn;
	unsigned int r_sgoffset;
	chiscsi_sgvec *r_sg;
};

struct chiscsi_scsi_write_burst_cb {
	unsigned int wb_ttt;
	unsigned int wb_burstlen;	/* tracker based on payload rcved */
	unsigned int wb_dlen;		/* tracker based on length in bhs */
	unsigned int wb_offset;
	unsigned int wb_datasn;
};

struct chiscsi_scsi_write_cb {
	unsigned int w_immediate;
	unsigned int w_unsolicited;
	unsigned int w_maxburst;
	unsigned int w_r2t_offset;
	unsigned int w_r2tsn;
	unsigned int w_r2t_count;
	/* unsolicited + r2t */
	chiscsi_scsi_write_burst_cb w_burst_unsol;
	chiscsi_scsi_write_burst_cb w_bursts[ISCSI_SESSION_MAX_OUTSTANDING_R2T];
};

struct chiscsi_scsi_cmd_cb {
	union {
		chiscsi_scsi_read_cb rcb;
		chiscsi_scsi_write_cb wcb;
	};
};

struct chiscsi_tag_ppod {
	struct sk_buff *pskb_list;
	unsigned char *pdata;
	unsigned int plen;
	dma_addr_t paddr;
};

/*
 * iscsi scsi command
 */

enum sc_state {
	CH_SC_STATE_CLOSED,
	CH_SC_STATE_INITIALIZED,

	CH_SC_STATE_EXE_READY,
	CH_SC_STATE_EXECUTING,

	CH_SC_STATE_R_XFER,

	CH_SC_STATE_W_BUFFER_WAIT,
	CH_SC_STATE_W_BUFFER_READY,
	CH_SC_STATE_W_XFER,

	CH_SC_STATE_STATUS,
	CH_SC_STATE_DONE,
};

/* for sc_scsi_flag, used between scsi and iscsi */
enum sc_scsi_flag_bits {
	CH_SFSCSI_HOLD_BIT,		/* ref. held by SCSI */
	CH_SFSCSI_BUF_READY_BIT,	/* data buffer available */
	CH_SFSCSI_EXECUTED_BIT,		/* SCSI execution done */
	CH_SFSCSI_R_XFER_ACKED_BIT,	/* read xfer acked */

	CH_SFSCSI_STATUS_ACKED_BIT,	/* T: initiator acked status */
	CH_SFSCSI_FORCE_RELEASE_BIT,	/* need to be released, used w/ TMF,
					   with SCSI still holding the ref. */
	CH_SFSCSI_ABORT_REQ_BIT,		/* I: scsi request abort */
	CH_SFSCSI_QFULL_BIT,               /* scsi status is qfull */

	CH_SFSCSI_READ_BUF_BIT,
	CH_SFSCSI_TIMER_SET_BIT,
};

/* for scf_priv, private to iscsi stack */
enum sc_private_flag_bits {
	CH_SFP_RWIO_BIT,		/* true read/write IO command */
	CH_SFP_PROT_BIT,		/* T10 DIF protection enabled */

	CH_SFP_TMF_SENSE_BIT,	/* aborted due to TMF, need sense data */
	CH_SFP_XFER_ERR_BIT,	/* protocol xfer error occured */
	CH_SFP_SGL_LOCAL_BIT,	/* SGL locally allocated by iscsi */

	CH_SFP_BUF_LAST_BIT,	/* last buffer available */
	CH_SFP_BUF_LOCAL_BIT,	/* buffer locally allocated by iscsi */
	CH_SFP_BUF_DDP_MAPPED_BIT,	/* buffer ddp mapped */
	CH_SFP_CHLU_BIT,		/* chelsio backend */

	CH_SFP_CHLU_SINK_BIT,	/* chelsio backend, sink/discard data */
	CH_SFP_LU_QUEUE_BIT,	/* backend storage, maintains own queue */
	CH_SFP_LU_MULTIPHASE_BIT,	/* backend storage, multi-phase data */
	CH_SFP_LU_PASSTHRU_BIT,	/* backend storage, pass-thru */

	CH_SFP_TLU_THREAD_BIT,	/* assigned to a lu worker thread */
        CH_SFP_LU_TYPE_SCST_BIT,   /* backend storage, type scst */
	CH_SFP_LU_SCSI_RELEASE_WAIT,
};

enum chiscsi_scsi_command_queue_types {
	CH_SCMD_PDUQ,
	CH_SCMD_PDU_SENTQ,

	CH_SCMD_Q_MAX
};

/*
 * debug timestamp
 */
enum scmd_timestamp_types {
	CH_SCMD_TM_BHS_RCVED,
	CH_SCMD_TM_FP_CDB_RCVED,
	CH_SCMD_TM_FP_DATA_XFER_STATUS,
	CH_SCMD_TM_CHISCSI_BUFFER_READY,
	CH_SCMD_TM_CHISCSI_EXE_STATUS,
	CH_SCMD_TM_CH_SCMD_DONE,
	CH_SCMD_TM_FP_ABORT,
	CH_SCMD_TM_FP_ABORT_STATUS,
	CH_SCMD_TM_FP_TMF,
	CH_SCMD_TM_FP_CLEANUP,
	CH_SCMD_TM_CHISCSI_ABORT,
	CH_SCMD_TM_CHISCSI_ABORT_STATUS,
	CH_SCMD_TM_CHISCSI_TMF_DONE,
	CH_SCMD_TM_CHISCSI_READY_2_RELEASE,

	CH_SCMD_TM_EXE_SUBMIT,
	CH_SCMD_TM_EXE_DONE_N,
	CH_SCMD_TM_EXE_COMPLETE,

	/* state transition */
	CH_SCMD_TM_STATE_2_INIT,
	CH_SCMD_TM_STATE_2_EXE_READY,
	CH_SCMD_TM_STATE_2_EXECUTING,
	CH_SCMD_TM_STATE_2_R_XFER,
	CH_SCMD_TM_STATE_2_W_BUFFER_WAIT,
	CH_SCMD_TM_STATE_2_W_BUFFER_READY,
	CH_SCMD_TM_STATE_2_W_XFER,
	CH_SCMD_TM_STATE_2_STATUS,
	CH_SCMD_TM_STATE_2_DONE,
	CH_SCMD_TM_STATE_2_CLOSED,

	CH_SCMD_TM_MAX
};

/* 
 * sc_flag
 */
#define SC_FLAG_READ			0x1
#define SC_FLAG_WRITE			0x2
#define SC_FLAG_SENSE			0x4
#define SC_FLAG_TMF_ABORT		0x8

#define SC_FLAG_SESS_ABORT		0x10
#define SC_FLAG_CMD_ABORT		0x20	
#define SC_FLAG_XFER_OVERFLOW		0x40
#define SC_FLAG_XFER_UNDERFLOW		0x80

#define SC_FLAG_XFER_BI_OVERFLOW	0x100
#define SC_FLAG_XFER_BI_UNDERFLOW	0x200
#define SC_FLAG_IMMEDIATE_CMD		0x400
#define SC_FLAG_LUN_ACL_R		0x800

#define SC_FLAG_LUN_ACL_W		0x1000
#define SC_FLAG_LUN_OOR			0x2000
#define SC_FLAG_PASSTHRU		0x4000
#define SC_FLAG_T10DIX			0x8000

#define SC_FLAG_T10DIF			0x10000
#define SC_FLAG_RELEASE_WAIT		0x20000

#define SC_FLAG_ABORT	(SC_FLAG_TMF_ABORT | SC_FLAG_SESS_ABORT | \
			 SC_FLAG_CMD_ABORT)

struct chiscsi_scsi_command {
	/*
	 * public
	 */
	void *sc_sdev_hndl;  /* set by the scsi device,
				iscsi stack does NOT use it.
				can be used to hold any private data by the
				backend storage/scsi device */
	unsigned long sc_tclass_sess_priv;
	chiscsi_tcp_endpoints *sc_ieps;
	void *sc_sess;
	void *pthru_sess;	/* scst session ptr copy from sc_sess */
	void *sc_conn;
	void *sc_sock;
	void *sc_offload_pdev;	/* if offloaded, points to the pci_dev */

	unsigned int sc_flag;
	unsigned char sc_attribute;
	unsigned char sc_state;
	unsigned char sc_status;
	unsigned char sc_cmdlen;/* intiator: cdb length, target: 16 */
	unsigned char sc_cmd[16]; /* initiator: scmd->cmnd, target: cdb */

	unsigned int sc_cmdsn;
	unsigned int sc_itt;
	unsigned int sc_lun;
	unsigned int sc_lun_acl;
	unsigned int sc_xfer_len;

	unsigned int sc_xfer_residualcount;

	/* for final response */
	unsigned char sc_response;
	unsigned char sc_sense_key;
	unsigned char sc_sense_asc;
	unsigned char sc_sense_ascq;

	unsigned int sc_sense_buflen;
	unsigned char sc_sense_buf[SCSI_SENSE_BUFFERSIZE];

	/*
	 * private to chelsio iscsi stack
	 */

	/* os dependent part */
	void   *sc_lock;
	/* waitq not used, disabling */
	/* void   *sc_waitq; */
	chiscsi_queue *sc_queue[CH_SCMD_Q_MAX];

	/* os independent part */
	struct chiscsi_scsi_command *sc_next;
	iscsi_pdu *sc_pdu;	/* the request pdu */
	unsigned int sc_thp_id;
	unsigned long sc_fscsi;	/* flag, for scsi/backend status */
	unsigned long sc_fpriv;	/* flag, private iscsi-related status/state */

	unsigned long long sc_lba;
	unsigned int sc_blk_cnt;

	unsigned int sc_statsn;
	unsigned int sc_datasn;

	unsigned int sc_xfer_left;
	unsigned int sc_xfer_cnt;
	chiscsi_sgl sc_sgl;
	chiscsi_sgl sc_protsgl;

	unsigned int sc_idx;
	unsigned int sc_ddp_tag;
	unsigned int sc_sw_tag;
	void *sc_odev;

	unsigned long timestamps[CH_SCMD_TM_MAX];
	
	chiscsi_scsi_cmd_cb sc_cb;

	unsigned int lsc_tlu;
	chiscsi_scsi_command *lsc_next;
	struct chiscsi_target_lun_class *lu_class;
	struct chiscsi_target_lun	*lu;
	chiscsi_sgl		lsc_sc_sgl;
	chiscsi_sgl		lsc_sc_protsgl;
	struct cxgbi_pdu_pi_info 	pi_info;
	
	void   *sc_nodedata;
	struct chiscsi_tag_ppod ppod_info;

	void *os_data;
};
#define ISCSI_SCSI_COMMAND_SIZE	(sizeof(chiscsi_scsi_command))

#define scmd_set_timestamp(sc,type)    \
		(sc)->timestamps[type] = os_get_timestamp()

#define scmd_enqueue(L,Q,P) \
		ch_enqueue_tail(L,chiscsi_scsi_command,sc_next,Q,P)
#define scmd_ch_enqueue_head(L,Q,P) \
		ch_enqueue_head(L,chiscsi_scsi_command,sc_next,Q,P)
#define scmd_enqueue_by_cmdsn(L,Q,P) \
		ch_enqueue_by_field_incr(L,chiscsi_scsi_command,sc_next,Q,P,sc_cmdsn)
#define scmd_dequeue(L,Q,P) \
		ch_dequeue_head(L,chiscsi_scsi_command,sc_next,Q,P)
#define scmd_ch_qremove(L,Q,P) \
		ch_qremove(L,chiscsi_scsi_command,sc_next,Q,P)
#define scmd_qsearch_by_ITT(L,Q,P,V) \
		ch_qsearch_by_field_value(L,chiscsi_scsi_command,sc_next,Q,P,sc_itt,V)
#define scmd_qsearch_by_cmdsn(L,Q,P,V) \
		ch_qsearch_by_field_value(L,chiscsi_scsi_command,sc_next,Q,P,sc_cmdsn,V)

#define scmd_fpriv_set_bit(sc,bit)	(sc)->sc_fpriv |= 1 << (bit)
#define scmd_fpriv_clear_bit(sc,bit)	(sc)->sc_fpriv &= ~(1 << bit)
#define scmd_fpriv_test_bit(sc,bit)	((sc)->sc_fpriv & (1 << bit))

#define scmd_fscsi_set_bit(sc,bit)	os_set_bit_atomic(&(sc)->sc_fscsi,bit)
#define scmd_fscsi_clear_bit(sc,bit)	os_clear_bit_atomic(&(sc)->sc_fscsi,bit)
#define scmd_fscsi_test_bit(sc,bit)	os_test_bit_atomic(&(sc)->sc_fscsi,bit)
#define scmd_fscsi_test_and_set_bit(sc,bit)	os_test_and_set_bit_atomic(&(sc)->sc_fscsi,bit)



/* exported by the iscsi core libary */
void chiscsi_scsi_command_scsi_flag_change(chiscsi_scsi_command *sc,
				unsigned int set_mask, unsigned int unset_mask);
int chiscsi_scsi_command_scsi_flag_test(chiscsi_scsi_command *sc,
				unsigned int test_mask);
int chiscsi_scsi_command_scsi_flag_testnset(chiscsi_scsi_command *sc,
				unsigned int test_mask, unsigned int set_mask);

void	iscsi_target_scsi_command_done(chiscsi_scsi_command *, int err);

static inline void chiscsi_scsi_command_target_failure(chiscsi_scsi_command *sc)
{
	sc->sc_response = ISCSI_RESPONSE_TARGET_FAILURE;
	sc->sc_status = 0x2; /* SCSI_STATUS_CHECK_CONDITION */
	sc->sc_sense_key = 0x0b; /* SCSI_SENSE_ABORTED_COMMAND */
	sc->sc_sense_asc = 0x44; /* internal target failure */
	sc->sc_sense_ascq = 0;
}

static inline void chiscsi_scsi_command_read_error(chiscsi_scsi_command *sc)
{
	sc->sc_response = ISCSI_RESPONSE_COMPLETED;
	sc->sc_status = 0x2; /* SCSI_STATUS_CHECK_CONDITION */
	//sc->sc_sense_key = 0x03; /* SCSI_SENSE_MEDIUM_ERROR */
	sc->sc_sense_key = 0x06; /* SCSI_UNIT_ATTENTION */
	sc->sc_sense_asc = 0x11; /* read error */
	sc->sc_sense_ascq = 0;
}

static inline void chiscsi_scsi_command_write_error(chiscsi_scsi_command *sc)
{
	sc->sc_response = ISCSI_RESPONSE_COMPLETED;
	sc->sc_status = 0x2; /* SCSI_STATUS_CHECK_CONDITION */
	//sc->sc_sense_key = 0x03; /* SCSI_SENSE_MEDIUM_ERROR */
	sc->sc_sense_key = 0x06; /* SCSI_UNIT_ATTENTION */
	sc->sc_sense_asc = 0xC; /* write error */
	sc->sc_sense_ascq = 0;
}

static inline void chiscsi_scsi_command_aborted(chiscsi_scsi_command *sc)
{
	sc->sc_response = ISCSI_RESPONSE_COMPLETED;
	sc->sc_status = 0x2; /* SCSI_STATUS_CHECK_CONDITION */
	sc->sc_sense_key = 0x0b; /* SCSI_SENSE_ABORTED_COMMAND */
	if (sc->sc_flag & SC_FLAG_WRITE)
		sc->sc_sense_asc = 0xC; /* write error */
	else
		sc->sc_sense_asc = 0x11; /* read error */
	sc->sc_sense_ascq = 0;
}

#endif
