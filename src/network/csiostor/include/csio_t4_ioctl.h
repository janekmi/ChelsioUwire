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
#ifndef __CSIO_T4_IOCTL_H__
#define __CSIO_T4_IOCTL_H__

#ifdef __cplusplus
extern "C" {
#endif

enum { /* taken from t4_hw.h */

	CSIO_PM_NSTATS      = 5,     /* # of PM stats */
 	CSIO_CIM_NUM_IBQ    = 6,     /* # of CIM IBQs */
 	CSIO_CIM_NUM_OBQ    = 6,     /* # of CIM OBQs */
 	CSIO_CIMLA_SIZE     = 2048,  /* # of 32-bit words in CIM LA */
 	CSIO_CIM_PIFLA_SIZE = 64,    /* # of 192-bit words in CIM PIF LA */
 	CSIO_CIM_MALA_SIZE  = 64,    /* # of 160-bit words in CIM MA LA */
 	CSIO_CIM_IBQ_SIZE   = 128,   /* # of 128-bit words in a CIM IBQ */
 	CSIO_TPLA_SIZE      = 128,   /* # of 64-bit words in TP LA */
 	CSIO_ULPRX_LA_SIZE  = 512,   /* # of 256-bit words in ULP_RX LA */
 	CSIO_NEXACT_MAC     = 336,   /* # of exact MAC address filters */

};

enum { _MEM_EDC0, _MEM_EDC1, _MEM_MC, _MEM_MC0 = _MEM_MC, _MEM_MC1 };

enum {
	CFG_STORE_FLASH	= (uint8_t) 0,
	CFG_STORE_EDC0,
	CFG_STORE_EDC1,
	CFG_STORE_EXTMEM,
	CFG_STORE_FILESYSTEM
};

#define CSIO_ETH_ALEN			6
#define CSIO_MAX_CIMLA_SIZE_IN_BYTES	((2 * CSIO_CIMLA_SIZE) * 4)
#define CSIO_MIN_CIMLA_SIZE_IN_BYTES	(CSIO_CIMLA_SIZE * 4)

#define CSIO_MAX_CIM_PIFLA_SIZE	\
		((2 * CSIO_CIM_PIFLA_SIZE) * (6 * sizeof(uint32_t)))
#define CSIO_MAX_CIM_MALA_SIZE	\
		((2 * CSIO_CIM_MALA_SIZE) * (5 * sizeof(uint32_t)))

#define CSIO_MAX_CIM_IBQ_SIZE_IN_BYTES	\
		(CSIO_CIM_IBQ_SIZE * (4 * sizeof(uint32_t)))

#define CSIO_MAX_CIM_OBQ_SIZE_IN_BYTES	\
		((6 * CSIO_CIM_IBQ_SIZE) * (4 * sizeof(uint32_t)))

#define CSIO_TP_LA_SIZE_IN_BYTES	(CSIO_TPLA_SIZE * sizeof(uint64_t))

#define CSIO_MAX_ULPRX_LA_SIZE		\
		(CSIO_ULPRX_LA_SIZE * 8 * sizeof(uint32_t))

#define CSIO_NEXACT_MAC			336

typedef enum _link_speed {

	Undefined = 0,
	SPEED_1G,
	SPEED_10G,

}link_speed_t;

typedef struct _version_t {

	uint16_t major_no;
	uint16_t minor_no;
	uint16_t build;
	uint16_t revision;

}version_t;

typedef struct _t4_port_stats {

	uint8_t port_no;

	uint64_t tx_frames;
	uint64_t rx_frames;

}T4_PORT_STATS, *PT4_PORT_STATS, t4_port_stats_t;

typedef struct _t4_mem_desc_t {
	int mem_type;
	int offset;
	int done;
	int embedded_buf_size;
	char embedded_buf[1];
}T4_MEM_DESC, *PT4_MEM_DESC, t4_mem_desc_t;

//new

#ifndef CSIO_MAX_T4PORTS
#define CSIO_MAX_T4PORTS	4
#endif

#define CSIO_SGE_CTXT_SIZE 	(4 * 8)

/* Defines for type */
enum {
	CHSTOR_EGRESS 	= 1,
	CHSTOR_INGRESS 	= 2,
	CHSTOR_FREELIST	= 3,
};

/* Has to match with ctxt_type required for A_SGE_CTXT_CMD */
enum {
        CHSTOR_CNTXT_TYPE_EGRESS,
        CHSTOR_CNTXT_TYPE_RSP,
        CHSTOR_CNTXT_TYPE_FL,
        CHSTOR_CNTXT_TYPE_CONG
};

typedef struct _csio_sge_ctx {
	uint32_t cntx_type;
	uint32_t cntx_id;

	uint8_t	 buf[CSIO_SGE_CTXT_SIZE];
}CSIO_SGE_CTX, *PCSIO_SGE_CTX, csio_sge_ctx_t;

typedef struct _csio_mbm_stats {
	uint32_t	n_req;		/* number of mbox req */
	uint32_t	n_rsp;		/* number of mbox rsp */
	uint32_t	n_activeq;	/* number of mbox req active Q */
	uint32_t	n_cbfnq;	/* number of mbox req cbfn Q */
	uint32_t	n_tmo;		/* number of mbox timeout */
	uint32_t	n_cancel;	/* number of mbox cancel */
	uint32_t	n_err;		/* number of mbox error */
}csio_mb_stats_t;

typedef struct _csio_hw_stats_t {
	/* struct csio_hw_stats */
	uint32_t	n_evt_activeq;	/* Number of event in active Q */
	uint32_t	n_evt_freeq;	/* Number of event in free Q */
	uint32_t	n_evt_drop;	/* Number of event droped */
	uint32_t	n_evt_unexp;	/* Number of unexpected events */
	uint32_t	n_pcich_offline;/* Number of pci channel offline */
	uint32_t	n_lnlkup_miss;  /* Number of lnode lookup miss */
	uint32_t	n_cpl_fw6_msg;	/* Number of cpl fw6 message*/
	uint32_t	n_cpl_fw6_pld;	/* Number of cpl fw6 payload*/
	uint32_t	n_cpl_unexp;	/* Number of unexpected cpl */
	uint32_t	n_plint_unexp;	/* Number of unexpected PL */
					/* interrupt */
	uint32_t	n_plint_cnt;	/* Number of PL interrupt */
	uint32_t	n_int_stray;	/* Number of stray interrupt */
	uint32_t	n_err;		/* Number of hw errors */
	uint32_t	n_err_fatal;	/* Number of fatal errors */
	uint32_t	n_err_nomem;	/* Number of memory alloc failure */
	uint32_t	n_err_io;	/* Number of IO failure */
	uint32_t	n_evt_sm[16];	/* Number of sm events */
	uint32_t	rsvd1;
}CSIO_HW_STATS, *PCSIO_HW_STATS, csio_hw_stats_t;

typedef struct _csio_adapter_info {
	uint64_t	adapter_handle;
	uint64_t	reserved[16];
}CSIO_ADAPTER_INFO, *PCSIO_ADAPTER_INFO, csio_adapter_info_t;

typedef struct _csio_t4port_t {
	uint16_t	pcap;
	uint8_t		portid;
	uint8_t		link_status;
	uint16_t	link_speed;
	uint8_t		enode_mac[6];
}CSIO_T4PORT, *PCSIO_T4PORT, csio_t4port_t;

typedef union _csio_pci_info_t {

	uint32_t	vendor_specific_id;

	struct {
		uint16_t	vendor_id;
		uint16_t	device_id;
	}s;

}CSIO_PCI_INFO, *PCSIO_PCI_INFO, csio_pci_info_t;

typedef struct _csio_hw_info_t {

	/* board related info */
	char 			name[32];
	char 			pci_name[32];
	char 			model[32];
	char 			sl_no[32];

	char			hw_version[32];
	char 			drv_version[32];

	csio_pci_info_t		pci_id;

	uint32_t		optrom_ver;
	uint32_t		chip_rev;
	uint32_t		fwrev;
	uint32_t 		cfg_finiver;
	uint32_t		cfg_finicsum;
	uint32_t		cfg_cfcsum;
	uint8_t			cfg_csum_status;
	uint8_t			cfg_store;

	uint8_t			master;			/* Is master function? */
	uint8_t			pfn;	 		/* Physical Function
							 * number
							 */
	uint32_t		port_vec;		/* Port vector */
	uint8_t			num_t4ports;		/* Actual number of
							 * ports.
							 */
	csio_t4port_t		t4port[CSIO_MAX_T4PORTS];/* Ports (XGMACs) */
	char 			intr_mode_str[32];
	uint32_t		fwevt_intr_idx;		/* FW evt MSIX/interrupt
							 * index
							 */
	int 			fwevt_iq_msix;
	int			fwevt_iq_idx;		/* FW evt queue */

	int			wrm_num_sge_q;		/* Num sge queues*/

	char   			state[32];
	uint8_t			cur_evt;		/* current s/m evt */
	uint8_t			prev_evt;		/* Previous s/m evt */
	uint32_t		dev_num;		/* device number */

	csio_hw_stats_t		stats;

	uint8_t			max_events;
	char			evt_name[16][32];
	uint8_t			partial_offload;
	uint8_t			initiator;
	uint8_t			target;
	uint8_t			reserved[30];

}CSIO_HW_INFO, *PCSIO_HW_INFO, csio_hw_info_t;


typedef struct _csio_iq_t {
	uint16_t		iqid;		/* Queue ID */
	uint16_t		physiqid;	/* Physical Queue ID */
	uint16_t		genbit;		/* Generation bit,
						 * initially set to 1
						 */
	uint16_t		prfi;		/* Profile ID */
	int			flq_idx;	/* Freelist queue index */

}CSIO_IQ, *PCSIO_IQ, csio_iq_t;

typedef struct _csio_eq_t {
	uint16_t		eqid;		/* Qid */
	uint16_t		physeqid;	/* Physical Queue ID */
	uint16_t		aqid;		/* Associated queue id */
}CSIO_EQ, *PCSIO_EQ, csio_eq_t;

typedef struct _csio_fl_t {
	uint16_t		flid;		/* Qid */
	uint16_t		packen;		/* Packing enabled? */
	int			offset;		/* Offset within FL buf */
	int			sreg;		/* Size register */

}CSIO_FL, *PCSIO_FL, csio_fl_t;

typedef struct _csio_fl_dma_info_t {
	int			q_idx;
	uint32_t		fl_entry;

	uintptr_t		vaddr;		/* Virtual address */
	uint64_t		paddr;		/* Physical address */
	uint32_t		len;		/* Buffer size */
}CSIO_FL_DMA_INFO, *PCSIO_FL_DMA_INFO, csio_fl_dma_info_t;

typedef struct _csio_qstats_t {
	uint32_t 	n_qentry;		/* Queue entry */
	uint32_t	n_qempty;		/* Queue empty */
	uint32_t	n_qfull;		/* Queue fulls */
	uint32_t	n_qwrap;		/* Queue wraps */
	uint32_t	n_tot_reqs;		/* Total no. of Requests */
	uint32_t	n_eq_wr_split;		/* Number of split EQ WRs */
	uint32_t	n_tot_rsps;		/* Total no. of responses */
	uint32_t	n_rsp_unknown;		/* Unknown response type */
	uint32_t	n_stray_comp;		/* Stray completion intr */
	uint32_t	n_flq_refill;		/* Number of FL refills */

}CSIO_QSTATS, *PCSIO_QSTATS, csio_qstats_t;

typedef struct _csio_q_info_t {

	int			q_idx;

	uint16_t		type;		/* Type: Ingress/Egress/FL */
	uint16_t		pidx;		/* producer index */
	uint16_t		cidx;		/* consumer index */
	uint16_t		inc_idx;	/* Incremental index */
	uint32_t		wr_sz;		/* Size of all WRs in this q
						 * if fixed
						 */
	uintptr_t		vstart;
	uint32_t		size;		/* Size of queue in bytes */
	uint32_t		credits;	/* Size of queue in credits */
	uint8_t			portid;		/* PCIE Channel */

	union {					/* Queue contexts */
		csio_iq_t	iq_info;
		csio_eq_t	eq_info;
		csio_fl_t	fl_info;
	} un;

	csio_qstats_t 	stats;			/* Statistics */

	uint8_t			reserved[32];

}CSIO_Q_INFO, *PCSIO_Q_INFO, csio_q_info_t;


typedef struct _scsi_q_set_t {

	int		iq_idx;			/* Ingress index */
	int		eq_idx;			/* Egress index */
	uint32_t	intr_idx;		/* MSIX Vector index */

}scsi_q_set_t;

typedef struct _scsi_q_t {

	uint16_t 	num_scsi_qsets;
	uint16_t 	done;

	scsi_q_set_t	q_sets[1];

}scsi_q_t;

typedef struct _csio_scsi_stats_t {
	uint64_t		n_tot_success;	/* Total number of good I/Os */
	uint32_t		n_rn_nr_error;	/* No. of remote-node-not-
						 * ready errors
						 */
	uint32_t		n_hw_nr_error;	/* No. of hw-module-not-
						 * ready errors
						 */
	uint32_t		n_dmamap_error;	/* No. of DMA map erros */
	uint32_t		n_unsupp_sge_error; /* No. of too-many-SGes
						     * errors.
						     */
	uint32_t		n_no_req_error;	/* No. of Out-of-ioreqs error */
	uint32_t		n_busy_error;	/* No. of CSIO_BUSY errors */
	uint32_t		n_hosterror;	/* No. of FW_HOSTERROR I/O */
	uint32_t		n_rsperror;	/* No. of response errors */
	uint32_t		n_autosense;	/* No. of auto sense replies */
	uint32_t		n_ovflerror;	/* No. of overflow errors */
	uint32_t		n_unflerror;	/* No. of underflow errors */
	uint32_t                n_rdev_nr_error;/* No. of rdev not
						 * ready errors
						 */
	uint32_t                n_rdev_lost_error;/* No. of rdev lost errors */
	uint32_t                n_rdev_logo_error;/* No. of rdev logo errors */
	uint32_t                n_link_down_error;/* No. of link down errors */
	uint32_t                n_unknown_error;/* No. of unhandled errors */
	uint32_t		n_aborted;	/* No. of aborted I/Os */
	uint32_t		n_abrt_timedout; /* No. of abort timedouts */
	uint32_t		n_abrt_fail;	/* No. of abort failures */
	uint32_t		n_abrt_race_comp; /* No. of aborts that raced
						   * with completions.
						   */
	uint32_t		n_abrt_busy_error;/* No. of abort failures
						   * due to CSIO_BUSY.
						   */
	uint32_t		n_closed;	/* No. of closed I/Os */
	uint32_t		n_cls_busy_error; /* No. of close failures
						   * due to CSIO_BUSY.
						   */
	uint32_t		n_res_wait;	/* No. of IOs in res_wait_q */
	uint32_t		n_active;	/* No. of IOs in active_q */
	uint32_t		n_tm_active;	/* No. of TMs in active_q */
	uint32_t		n_wcbfn;	/* No. of I/Os in worker
						 * cbfn q
						 */
	uint32_t		n_free_ioreq;	/* No. of freelist entries */
	uint32_t		n_ddp_miss;	/* No. of DDP misses */
	uint32_t		n_inval_cplop;	/* No. invalid CPL op's in IQ */
	uint32_t		n_inval_scsiop;	/* No. invalid scsi op's in IQ*/

	uint8_t			reserved[32];

}CSIO_SCSI_STATS, *PCSIO_SCSI_STATS, csio_scsi_stats_t;

typedef struct _csio_oslnode_info_t {
	uint32_t		vnp_id;
	uint8_t			os_bus_id;
	uint8_t			reserved[256+32];
}CSIO_OSLNODE_INFO, *PCSIO_OSLNODE_INFO, csio_oslnode_info_t;

typedef struct _csio_osrnode_info_t {
	uint32_t		vnp_id;
	uint32_t		ssn_id;
	uint8_t			os_target_id;
	uint8_t			reserved[256+32];
}CSIO_OSRNODE_INFO, *PCSIO_OSRNODE_INFO, csio_osrnode_info_t;


typedef struct _csio_reg_t {
	uint32_t	addr;
	uint32_t	val;
}CSIO_REG, *PCSIO_REG, csio_reg_t;

typedef struct _csio_mem_range {
	uint32_t mem_id;
	uint32_t addr;
	uint32_t len;
	uint32_t version;
#if !(defined C99_NOT_SUPPORTED)
	uint8_t  buf[0];
#endif
} CSIO_MEM_RANGE, *PCSIO_MEM_RANGE, csio_mem_range_t;

typedef struct _csio_load_cfg {
	uint32_t cmd;
	uint32_t len;
	uint8_t  buf[0];
} CSIO_LOAD_CFG, *PCSIO_LOAD_CFG, csio_load_cfg_t;

typedef struct _csio_mailbox_data {

#ifndef CSIO_MAX_MB_SIZE
#define CSIO_MAX_MB_SIZE	64
#endif

	uint32_t number;
	uint32_t owner_info;
	char buffer[CSIO_MAX_MB_SIZE];

}CSIO_MAILBOX_DATA, *PCSIO_MAILBOX_DATA, csio_mailbox_data_t;

typedef struct _csio_cim_q_config {

	uint16_t base[CSIO_CIM_NUM_IBQ + CSIO_CIM_NUM_OBQ];
	uint16_t size[CSIO_CIM_NUM_IBQ + CSIO_CIM_NUM_OBQ];
	uint16_t thres[CSIO_CIM_NUM_IBQ];
	uint32_t obq_wr[2 * CSIO_CIM_NUM_OBQ];
	uint32_t stat[4 * (CSIO_CIM_NUM_IBQ + CSIO_CIM_NUM_OBQ)];

}CSIO_CIM_Q_CONFIG, *PCSIO_CIM_Q_CONFIG, csio_cim_q_config_t;

typedef struct _csio_cim_la {

	uint32_t complete_data;
	uint32_t size;
	uint8_t buffer[CSIO_MAX_CIMLA_SIZE_IN_BYTES];

}CSIO_CIM_LA, *PCSIO_CIM_LA, csio_cim_la_t;

typedef struct _csio_cim_pifla {

	uint8_t buffer[CSIO_MAX_CIM_PIFLA_SIZE];

}CSIO_CIM_PIFLA, *PCSIO_CIM_PIFLA, csio_cim_pifla_t;

typedef struct _csio_cim_mala {

	uint8_t buffer[CSIO_MAX_CIM_MALA_SIZE];

}CSIO_CIM_MALA, *PCSIO_CIM_MALA, csio_cim_mala_t;

typedef struct _csio_mps_tcam_data {

	uint32_t index;

	uint8_t eth_addr[CSIO_ETH_ALEN];
	uint64_t mask;
	uint64_t tcamx;
	uint64_t tcamy;
	uint32_t cls_low;
	uint32_t cls_hi;

}CSIO_MPS_TCAM_DATA, *PCSIO_MPS_TCAM_DATA, csio_mps_tcam_data_t;

typedef struct _csio_cim_ibq {

	uint32_t queue_id;
	uint8_t buffer[CSIO_MAX_CIM_IBQ_SIZE_IN_BYTES];

}CSIO_CIM_IBQ, *PCSIO_CIM_IBQ, csio_cim_ibq_t;

typedef struct _csio_cim_obq {

	uint32_t queue_id;
	uint8_t buffer[CSIO_MAX_CIM_OBQ_SIZE_IN_BYTES];

}CSIO_CIM_OBQ, *PCSIO_CIM_OBQ, csio_cim_obq_t;

typedef struct _csio_tp_la_data {

	uint32_t dbg_la_mode;
	uint8_t buffer[CSIO_TP_LA_SIZE_IN_BYTES];

}CSIO_TP_LA_DATA, *PCSIO_TP_LA_DATA, csio_tp_la_data_t;

typedef struct _csio_ulprx_la_data {
	//uint32_t buffer[CSIO_ULPRX_LA_SIZE][8];
	uint8_t buffer[CSIO_MAX_ULPRX_LA_SIZE];
}CSIO_ULPRX_LA_DATA, *PCSIO_ULPRX_LA_DATA, csio_ulprx_la_data_t;

typedef struct _csio_tp_tcp_stats {
	uint32_t tcpOutRsts;
	uint64_t tcpInSegs;
	uint64_t tcpOutSegs;
	uint64_t tcpRetransSegs;
}CSIO_TP_TCP_STATS, *PCSIO_TP_TCP_STATS, csio_tp_tcp_stats_t;

typedef struct _csio_tp_usm_stats {
	uint32_t frames;
	uint32_t drops;
	uint64_t octets;
}CSIO_TP_USM_STATS, *PCSIO_TP_USM_STATS, csio_tp_usm_stats_t ;

typedef struct _csio_tp_err_stats {
	uint32_t macInErrs[4];
	uint32_t hdrInErrs[4];
	uint32_t tcpInErrs[4];
	uint32_t tnlCongDrops[4];
	uint32_t ofldChanDrops[4];
	uint32_t tnlTxDrops[4];
	uint32_t ofldVlanDrops[4];
	uint32_t tcp6InErrs[4];
	uint32_t ofldNoNeigh;
	uint32_t ofldCongDefer;
}CSIO_TP_ERR_STATS, *PCSIO_TP_ERR_STATS, csio_tp_err_stats_t;

typedef struct _csio_tp_proxy_stats {
	uint32_t proxy[4];
}CSIO_TP_PROXY_STATS, *PCSIO_TP_PROXY_STATS, csio_tp_proxy_stats_t;

typedef struct _csio_tp_cpl_stats {
	uint32_t req[4];
	uint32_t rsp[4];
}CSIO_TP_CPL_STATS, *PCSIO_TP_CPL_STATS, csio_tp_cpl_stats_t;

typedef struct _csio_pm_stats {
	uint32_t tx_cnt[CSIO_PM_NSTATS];
	uint32_t rx_cnt[CSIO_PM_NSTATS];
	uint64_t tx_cyc[CSIO_PM_NSTATS];
	uint64_t rx_cyc[CSIO_PM_NSTATS];
}CSIO_PM_STATS, *PCSIO_PM_STATS, csio_pm_stats_t;

typedef struct _csio_lb_port_stats {

	int idx;

	uint64_t octets;
	uint64_t frames;
	uint64_t bcast_frames;
	uint64_t mcast_frames;
	uint64_t ucast_frames;
	uint64_t error_frames;

	uint64_t frames_64;
	uint64_t frames_65_127;
	uint64_t frames_128_255;
	uint64_t frames_256_511;
	uint64_t frames_512_1023;
	uint64_t frames_1024_1518;
	uint64_t frames_1519_max;

	uint64_t drop;

	uint64_t ovflow0;
	uint64_t ovflow1;
	uint64_t ovflow2;
	uint64_t ovflow3;
	uint64_t trunc0;
	uint64_t trunc1;
	uint64_t trunc2;
	uint64_t trunc3;
}CSIO_LB_PORT_STATS, *PCSIO_LB_PORT_STATS, csio_lb_port_stats_t;

typedef struct _csio_fwdevlog_info {

	uint32_t memtype;		/* which memory (EDC0, EDC1, MC) */
	uint32_t start;			/* start of log in firmware memory */
	uint32_t size;			/* size of log */

}CSIO_FWDEVLOG_INFO, *PCSIO_FWDEVLOG_INFO, csio_fwdevlog_info_t;

#define CSIO_FW_DEVLOG_HDR_SIZE		(sizeof(csio_fw_devlog_t) - 	\
						sizeof(struct fw_devlog_e))

typedef struct _csio_fw_devlog {
	unsigned int nentries;		/* number of entries in log[] */
	unsigned int first;		/* first [temporal] entry in log[] */
	struct fw_devlog_e log[1];	/* Firmware Device Log */
}CSIO_FW_DEVLOG, *PCSIO_FW_DEVLOG, csio_fw_devlog_t;


typedef enum _drv_params {
	LUN_QUEUE_DEPTH = 0,
	MAX_TX_LENGTH,
	MAX_SGL_LENGTH,
	MAX_NPIV,
	MAX_LNODES,
	MAX_RNODES,
	MAX_LUNS,
	TIME_SCSI_IO,
	MAX_BOOT_INIT_DELAY,
	NODE_SYM_NAME,

	MAX_DRV_PARAMS
}DRV_PARAMS_LIST;


typedef struct _csio_drv_params {
	uint8_t is_supported;
	uint8_t reboot_reload_req;
	uint8_t rsvd1;
	uint8_t rsvd2;

	union param_val{
		struct _int_val{
			int64_t min_val;
			int64_t max_val;
			int64_t default_val;
			int64_t current_val;
		}v;
		char str[32];
	}u;
}CSIO_DRV_PARAMS, *PCSIO_DRV_PARAMS, csio_drv_params_t;


#define drv_supported(_x)	drv_params[(_x)].is_supported
#define drv_reboot_req(_x)	drv_params[(_x)].reboot_reload_req
#define drv_min_val(_x)		drv_params[(_x)].u.v.min_val
#define drv_max_val(_x)		drv_params[(_x)].u.v.max_val
#define drv_default_val(_x)	drv_params[(_x)].u.v.default_val
#define drv_current_val(_x)	drv_params[(_x)].u.v.current_val
#define drv_val_str(_x)		drv_params[(_x)].u.str


#ifdef __cplusplus
}
#endif

#endif /* __CSIO_T4_IOCTL_H__ */
