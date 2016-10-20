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

#ifndef __CSIO_WR_H__
#define __CSIO_WR_H__

#include <csio_defs.h>
#include <t4fw_interface.h>
#ifdef __CSIO_FOISCSI_ENABLED__
#include <fw_foiscsi_interface.h>
#endif

/* WR status is at the same position as retval in a CMD header */
#define csio_wr_status(_wr)		\
		(G_FW_CMD_RETVAL(csio_ntohl(((struct fw_cmd_hdr *)(_wr))->lo)))
/* FIXME */
struct csio_hw;

extern int csio_intr_coalesce_cnt;
extern int csio_intr_coalesce_time;

/* Ingress queue params */
struct csio_iq_params {

	uint8_t		iq_start:1;
	uint8_t		iq_stop:1;
	uint8_t		pfn:3;

	uint8_t 	vfn;

	uint16_t	physiqid;
	uint16_t	iqid;

	uint16_t	fl0id;
	uint16_t	fl1id;

	uint8_t		viid;

	uint8_t		type;
	uint8_t		iqasynch;
	uint8_t		reserved4;

	uint8_t		iqandst;
	uint8_t		iqanus;
	uint8_t		iqanud;

	uint16_t	iqandstindex;

	uint8_t		iqdroprss;
	uint8_t		iqpciech;
	uint8_t		iqdcaen;

	uint8_t		iqdcacpu;
	uint8_t		iqintcntthresh;
	uint8_t		iqo;

	uint8_t		iqcprio;
	uint8_t		iqesize;

	uint16_t	iqsize;

	uint64_t	iqaddr;

	uint8_t		iqflintiqhsen;
	uint8_t		reserved5;
	uint8_t		iqflintcongen;
	uint8_t		iqflintcngchmap;

	uint32_t	reserved6;

	uint8_t		fl0hostfcmode;
	uint8_t		fl0cprio;
	uint8_t		fl0paden;
	uint8_t		fl0packen;
	uint8_t		fl0congen;
	uint8_t		fl0dcaen;

	uint8_t		fl0dcacpu;
	uint8_t		fl0fbmin;

	uint8_t		fl0fbmax;
	uint8_t		fl0cidxfthresho;
	uint8_t		fl0cidxfthresh;

	uint16_t	fl0size;

	uint64_t	fl0addr;

	uint64_t	reserved7;

	uint8_t		fl1hostfcmode;
	uint8_t		fl1cprio;
	uint8_t		fl1paden;
	uint8_t		fl1packen;
	uint8_t		fl1congen;
	uint8_t		fl1dcaen;

	uint8_t		fl1dcacpu;
	uint8_t		fl1fbmin;

	uint8_t		fl1fbmax;
	uint8_t		fl1cidxfthresho;
	uint8_t		fl1cidxfthresh;

	uint16_t	fl1size;

	uint64_t	fl1addr;
};

/* Egress queue params */
struct csio_eq_params {

	uint8_t		pfn;
	uint8_t		vfn;

	uint8_t		eqstart:1;
	uint8_t		eqstop:1;

	uint16_t        physeqid;
	uint32_t	eqid;

	uint8_t		hostfcmode:2;
	uint8_t		cprio:1;
	uint8_t		pciechn:3;

	uint16_t	iqid;

	uint8_t		dcaen:1;
	uint8_t		dcacpu:5;

	uint8_t		fbmin:3;
	uint8_t		fbmax:3;

	uint8_t		cidxfthresho:1;
	uint8_t		cidxfthresh:3;

	uint16_t	eqsize;

	uint64_t	eqaddr;
};

struct csio_dma_buf {
	struct csio_list	list;
	csio_dma_obj_t		dmahdl;		/* Handle for DMA allocation */
	void			*vaddr;		/* Virtual address */
	csio_physaddr_t		paddr;		/* Physical address */
	uint32_t		len;		/* Buffer size */
};

/* Defines for csio_ioreq->datadir */
enum {
	CSIO_IOREQF_DMA_BIDI 	= 0x0,
	CSIO_IOREQF_DMA_WRITE 	= 0x1,
	CSIO_IOREQF_DMA_READ	= 0x2,
	CSIO_IOREQF_DMA_NONE	= 0x4,
};
	
#define CSIO_STOR_MAX_WRSZ	64		/* REVISIT */

/* Generic I/O request structure */
struct csio_ioreq {
	struct csio_sm		sm;	   	/* SM, List
						 * should be the first member
						 */
	int			iq_idx;		/* Ingress queue index */
	int			eq_idx;		/* Egress queue index */
	uint32_t		nsge;		/* Number of SG elements */
	uint32_t		tmo;	   	/* Driver timeout */
	uint32_t		datadir;	/* Data direction */
	struct csio_dma_buf	dma_buf;	/* Req/resp DMA buffers */	
	uint16_t		wr_status;	/* WR completion status */
	uint16_t		drv_status;	/* Driver internal status */
	struct csio_lnode	*lnode;		/* Owner lnode */
	struct csio_rnode	*rnode;		/* Src/destination rnode */
	void (*io_cbfn) (struct csio_hw *, struct csio_ioreq *);
						/* completion callback */
	void			*scratch1;	/* Scratch area 1.
						 * Usage example:
						 * This can be used to
						 * squirrel in the OS-specific
 						 * SCSI command pointer (SRB,
 						 * scsi_cmnd etc).
 						 */
	void			*scratch2;	/* Scratch area 2. */
	uint8_t			fw_wr[CSIO_STOR_MAX_WRSZ];
						/* WR response
						 */
	struct csio_list	gen_list;	/* Any list associated with
						 * this ioreq. 
						 */
	uint64_t		fw_handle; 	/* Unique handle passed
						 * to FW
						 */
	uint16_t		retry_cnt; 	/* Retry count */
	uint16_t		max_retries;	/* max num of retries */
	uint8_t			dcopy;		/* Data copy required */
	uint8_t			reserved1;
	uint16_t		reserved2;
	csio_cmpl_t             cmplobj;	/* ioreq completion object */
#ifdef __CSIO_DEBUG__
	uint8_t                 data[64];	/* Debug data */
#endif
} __csio_cacheline_aligned;

/* 
 * Egress status page for egress cidx updates 
 */ 
struct csio_qstatus_page {
	__be32 qid;
	__be16 cidx;
	__be16 pidx;
};


enum {
	CSIO_MAX_FLBUF_PER_IQWR = 4,
	CSIO_QCREDIT_SZ  = 64,			/* pidx/cidx increments
						 * in bytes 
						 */ 
	CSIO_MAX_QID = 0xFFFF,
	CSIO_MAX_IQ = 128,

	CSIO_SGE_NTIMERS = 6,
	CSIO_SGE_NCOUNTERS = 4,
	CSIO_SGE_FL_SIZE_REGS = 16,
};

/* Defines for type */
enum {
	CSIO_EGRESS 	= 1,
	CSIO_INGRESS 	= 2,
	CSIO_FREELIST	= 3,
};

/*
 * Structure for footer (last 2 flits) of Ingress Queue Entry.
 */
struct csio_iqwr_footer {
	__be32			hdrbuflen_pidx;
	__be32 			pldbuflen_qid;
	union {
		u8 		type_gen;
		__be64 		last_flit;
	} u;
};

#define S_IQWRF_NEWBUF		31
#define V_IQWRF_NEWBUF(x) 	((x) << S_IQWRF_NEWBUF)
#define F_IQWRF_NEWBUF    	V_IQWRF_NEWBUF(1U)

#define S_IQWRF_LEN		0
#define M_IQWRF_LEN		0x7fffffff
#define V_IQWRF_LEN(x)		((x) << S_IQWRF_LEN)
#define G_IQWRF_LEN(x)		(((x) >> S_IQWRF_LEN) & M_IQWRF_LEN)

#define S_IQWRF_GEN		7
#define V_IQWRF_GEN(x)		((x) << S_IQWRF_GEN)
#define F_IQWRF_GEN		V_IQWRF_GEN(1U)

#define S_IQWRF_TYPE		4
#define M_IQWRF_TYPE		0x3
#define V_IQWRF_TYPE(x)		((x) << S_IQWRF_TYPE)
#define G_IQWRF_TYPE(x)		(((x) >> S_IQWRF_TYPE) & M_IQWRF_TYPE)


/** 
 * WR pair:
 * ========
 * A WR can start towards the end of a queue, and then continue at the
 * beginning, since the queue is considered to be circular. This will
 * require a pair of address/len to be passed back to the caller -
 * hence the Work request pair structure.
 */
struct csio_wr_pair {
	void			*addr1;
	uint32_t		size1;
	void			*addr2;
	uint32_t		size2;
};

/*
 * The following structure is used by ingress processing to return the
 * free list buffers to consumers.
 */
struct csio_fl_dma_buf {
	struct csio_dma_buf	flbufs[CSIO_MAX_FLBUF_PER_IQWR];
						/* Freelist DMA buffers */
	int			offset;		/* Offset within the
						 * first FL buf.
						 */
	uint32_t		totlen;		/* Total length */
	uint8_t			defer_free;	/* Free of buffer can 
						 * deferred
						 */
};

/* Data-types */
typedef void (*iq_handler_t)(struct csio_hw *, void *, uint32_t,
			     struct csio_fl_dma_buf *, void *);

struct csio_iq {
	uint16_t		iqid;		/* Queue ID */
	uint16_t		physiqid;	/* Physical Queue ID */
	uint16_t		genbit;		/* Generation bit,
						 * initially set to 1 
						 */
	uint16_t		prfi;		/* Profile ID */
	int			flq_idx;	/* Freelist queue index */
	iq_handler_t		iq_intx_handler; /* IQ INTx handler routine */
};

struct csio_eq {
	uint16_t		eqid;		/* Qid */
	uint16_t		physeqid;	/* Physical Queue ID */
	uint16_t		aqid;		/* Associated queue id */
};

struct csio_fl {
	uint16_t		flid;		/* Qid */
	uint16_t		packen;		/* Packing enabled? */
	int			offset;		/* Offset within FL buf */
	int			sreg;		/* Size register */
	int			md_idx;		/* Memory desc index */
	struct csio_dma_buf	*bufs;		/* Free list buffer ptr array
						 * indexed using flq->cidx/pidx
						 */
};

struct csio_qstats {
	uint32_t	n_tot_reqs;		/* Total no. of Requests */
	uint32_t	n_tot_rsps;		/* Total no. of responses */
	uint32_t	n_qwrap;		/* Queue wraps */
	uint32_t	n_eq_wr_split;		/* Number of split EQ WRs */
	uint32_t 	n_qentry;		/* Queue entry */
	uint32_t	n_qempty;		/* Queue empty */
	uint32_t	n_qfull;		/* Queue fulls */
	uint32_t	n_rsp_unknown;		/* Unknown response type */
	uint32_t	n_stray_comp;		/* Stray completion intr */
	uint32_t	n_flq_refill;		/* Number of FL refills */
};

/* Queue metadata */
struct csio_q {
	uint16_t		type;		/* Type: Ingress/Egress/FL */
	uint16_t		pidx;		/* producer index */
	uint16_t		cidx;		/* consumer index */
	uint16_t		inc_idx;	/* Incremental index */
	uint32_t		wr_sz;		/* Size of all WRs in this q
						 * if fixed 
						 */ 
	void			*vstart;	/* Base virtual address
						 * of queue
						 */
	void			*vwrap; 	/* Virtual end address to
						 * wrap around at 
						 */
	uint32_t		credits;	/* Size of queue in credits */
	void			*owner; 	/* REVISIT: Owner area,
						 * NULL if free. Needed?
						 */
	union {					/* Queue contexts */
		struct csio_iq	iq;
		struct csio_eq	eq;
		struct csio_fl	fl;
	} un;
	struct csio_qstats 	stats;		/* Statistics */

	csio_dma_obj_t		dmahdl;		/* Handle for DMA allocation */
	csio_physaddr_t		pstart;		/* Base physical address of
						 * queue 
						 */
	uint32_t		portid;		/* PCIE Channel - TOBE removed */
	uint32_t		size;		/* Size of queue in bytes */
	void __iomem		*bar2_addr;	/* address of BAR2 Queue registers */
	unsigned int		bar2_qid;	/* Queue ID for BAR2 Queue registers */
} __csio_cacheline_aligned;

struct csio_sge {
	uint32_t 	csio_fl_align;		/* Calculated and cached
						 * for fast path
						 */
	uint32_t 	sge_control;		/* padding, boundaries, 
						 * lengths, etc.
						 */
	uint32_t 	sge_host_page_size;	/* Host page size */
	uint32_t 	sge_fl_buf_size[CSIO_SGE_FL_SIZE_REGS];
						/* free list buffer sizes */
	uint16_t 	timer_val[CSIO_SGE_NTIMERS];
	uint8_t		counter_val[CSIO_SGE_NCOUNTERS];
};

/* Work request module */
struct csio_wrm {
	int			num_q;		/* Number of queues */
	struct csio_q		**q_arr;	/* Array of queue pointers
						 * allocated dynamically 
						 * based on configured values
						 */
	uint32_t		fw_iq_start;	/* Start ID of IQ for this fn*/
	uint32_t		fw_eq_start;	/* Start ID of EQ for this fn*/

	struct csio_q		*intr_map[CSIO_MAX_IQ]; 
						/* IQ-id to IQ map table. */
	int			free_qidx;	/* queue idx of free queue */
	struct csio_sge		sge;		/* SGE params */
};

#define csio_get_q(__hw, __idx)		((__hw)->wrm.q_arr[__idx])
#define	csio_q_type(__hw, __idx)	((__hw)->wrm.q_arr[(__idx)]->type)
#define	csio_q_pidx(__hw, __idx)	((__hw)->wrm.q_arr[(__idx)]->pidx)
#define	csio_q_cidx(__hw, __idx)	((__hw)->wrm.q_arr[(__idx)]->cidx)
#define	csio_q_inc_idx(__hw, __idx)	((__hw)->wrm.q_arr[(__idx)]->inc_idx)
#define	csio_q_vstart(__hw, __idx)	((__hw)->wrm.q_arr[(__idx)]->vstart)
#define	csio_q_pstart(__hw, __idx)	((__hw)->wrm.q_arr[(__idx)]->pstart)
#define	csio_q_size(__hw, __idx)	((__hw)->wrm.q_arr[(__idx)]->size)
#define	csio_q_credits(__hw, __idx)	((__hw)->wrm.q_arr[(__idx)]->credits)
#define	csio_q_portid(__hw, __idx)	((__hw)->wrm.q_arr[(__idx)]->portid)
#define	csio_q_bar2qaddr(__hw, __idx)	((__hw)->wrm.q_arr[(__idx)]->bar2_addr)
#define	csio_q_bar2qid(__hw, __idx)	((__hw)->wrm.q_arr[(__idx)]->bar2_qid)
#define csio_q_vend(__hw, __idx)					\
	((void *)((uintptr_t)((__hw)->wrm.q_arr[(__idx)]->vstart) +	\
					(__hw)->wrm.q_arr[(__idx)]->size))
#define	csio_q_wr_sz(__hw, __idx)	((__hw)->wrm.q_arr[(__idx)]->wr_sz)
#define	csio_q_iqid(__hw, __idx)	((__hw)->wrm.q_arr[(__idx)]->un.iq.iqid)
#define csio_q_physiqid(__hw, __idx)					\
				((__hw)->wrm.q_arr[(__idx)]->un.iq.physiqid)
#define	csio_q_iq_prfi(__hw, __idx)	((__hw)->wrm.q_arr[(__idx)]->un.iq.prfi)
#define csio_q_iq_flq_idx(__hw, __idx)					\
				((__hw)->wrm.q_arr[(__idx)]->un.iq.flq_idx)
#define	csio_q_eqid(__hw, __idx)	((__hw)->wrm.q_arr[(__idx)]->un.eq.eqid)
#define	csio_q_aqid(__hw, __idx)	((__hw)->wrm.q_arr[(__idx)]->un.eq.aqid)
#define	csio_q_flid(__hw, __idx)	((__hw)->wrm.q_arr[(__idx)]->un.fl.flid)

#define csio_q_physeqid(__hw, __idx)					\
				((__hw)->wrm.q_arr[(__idx)]->un.eq.physeqid)
#define csio_iq_has_fl(__iq)		((__iq)->un.iq.flq_idx != -1)
#define csio_q_owner(__hw, __idx)       ((__hw)->wrm.q_arr[(__idx)]->owner)

#define csio_q_iq_to_flid(__hw, __iq_idx)				\
	csio_q_flid((__hw), (__hw)->wrm.q_arr[(__iq_qidx)]->un.iq.flq_idx)
#define csio_q_set_intr_map(__hw, __iq_idx, __rel_iq_id)		\
		(__hw)->wrm.intr_map[__rel_iq_id] = csio_get_q(__hw, __iq_idx)

#define CSIO_DUMP_WR(__hw, __wr)   \
do {    \
	csio_vdbg(__hw,							\
                "################ FW WR DUMP len:%d ################\n", \
                __wr.size1 + __wr.size2);				\
        CSIO_DUMP_BUF((uint8_t *) __wr.addr1, __wr.size1);	\
        CSIO_DUMP_BUF((uint8_t *) __wr.addr2, __wr.size2);	\
} while(0) 

struct csio_mb;

csio_retval_t csio_get_sge_q_info(struct csio_hw *, void *, uint32_t);
csio_retval_t csio_get_sge_flq_buf_info(struct csio_hw *, void *, uint32_t);

/* Entry points for WR module */
int csio_wr_alloc_q(struct csio_hw *, uint32_t, uint32_t,
		    uint16_t, void *, uint32_t, int, int, iq_handler_t);
csio_retval_t csio_wr_iq_create(struct csio_hw *, int,
		uint32_t, uint8_t, bool);
csio_retval_t csio_wr_iq_create_rsp(struct csio_hw *, struct fw_iq_cmd *, int);
csio_retval_t csio_wr_eq_create(struct csio_hw *, int, int, uint8_t);
csio_retval_t csio_wr_eq_create_rsp(struct csio_hw *, struct fw_eq_ofld_cmd *, int);
csio_retval_t csio_wr_iq_destroy(struct csio_hw *, int);
csio_retval_t csio_wr_iq_destroy_rsp(struct csio_hw *, struct csio_mb *, int);
csio_retval_t csio_wr_destroy_queues(struct csio_hw *, bool cmd);


csio_retval_t csio_wr_get(struct csio_hw *, int, uint32_t, 
			  struct csio_wr_pair *);
void csio_wr_copy_to_wrp(void *, struct csio_wr_pair *, uint32_t, uint32_t);
csio_retval_t csio_wr_issue(struct csio_hw *, int, bool);
bool csio_wr_iq_entries(struct csio_hw *hw, int);
void csio_wr_free_flbuf(struct csio_hw *, struct csio_fl_dma_buf *);
enum csio_oss_error csio_wr_process_iq(struct csio_hw *, struct csio_q *, 
				 void (*)(struct csio_hw *, void *,
				 	  uint32_t, struct csio_fl_dma_buf *,
					  void *),
				 void *);
csio_retval_t csio_wr_process_iq_idx(struct csio_hw *, int, 
				 void (*)(struct csio_hw *, void *,
				 	  uint32_t, struct csio_fl_dma_buf *,
					  void *),
				 void *);

void csio_wr_sge_init(struct csio_hw *);
csio_retval_t csio_wrm_init(struct csio_wrm *, struct csio_hw *);
void csio_wrm_exit(struct csio_wrm *, struct csio_hw *);

#endif /* ifndef __CSIO_WR_H__ */
