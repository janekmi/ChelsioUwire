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

#ifndef __CSIO_HW_H__
#define __CSIO_HW_H__

#include <csio_wr.h>
#include <csio_mb.h>
#include <csio_scsi.h>
#ifdef __CSIO_TARGET__
#include <csio_tgt.h>
#endif
#include <csio_mgmt.h>
#include <t4_regs.h>
#include <t4_regs_values.h>
#include <t4_msg.h>
#include <csio_defs.h>
#include <common.h>

/*
 * An error value used by host. Should not clash with FW defined return values,
 * so choose an arbitrarily high value
 */
#define	FW_HOSTERROR			255

extern int csio_dbg_level;
extern int csio_exit_no_mb;
extern unsigned int csio_port_mask;
extern int csio_msi;
extern uint32_t csio_evtq_sz;

#define CSIO_VENDOR_ID				0x1425

#define CSIO_ASIC_DEVID_PROTO_MASK		0xFF00
#define CSIO_ASIC_DEVID_TYPE_MASK		0x00FF
#define CSIO_CUSTOM_ASIC_DEVID_TYPE_MASK	0xFFF0


/* TODO: Dont know why this name is useful, should probably come from VPD */
#define CSIO_HW_NAME			"Chelsio Storage Controller"
#define CSIO_MAX_PFN			8
#define CSIO_MAX_T4PORTS		4

/* Max reset retries */
#define CSIO_MAX_RESET_RETRIES		3

/* Defines for link_speed */
#define CSIO_LINK_10G			0x1

/* os_flags defines */
#define	CSIO_HWOSF_INTR_ENABLED		0x00000001
#define	CSIO_HWOSF_FN_FCOE		0x00000002	/* 1-FCOE 0-iSCSI */

/* Defines for flags */
#define CSIO_HWF_MASTER			0x00000001 	/* This is the Master 
							 * function for the 
							 * card.
							 */
#define	CSIO_HWF_INTR_ENABLED		0x00000002	/* Are Interrupt
							 * enable bits of
							 * various registers
							 * set?
							 */

#define	CSIO_HWF_FWEVT_PENDING		0x00000004	/* FW events pending */
#define	CSIO_HWF_Q_MEM_ALLOCED		0x00000008	/* Queues have been 
							 * allocated memory.
							 */
#define	CSIO_HWF_Q_FW_ALLOCED		0x00000010	/* Queues have been 
							 * allocated in FW.
							 */
#define CSIO_HW_VPD_VALID		0x00000020	/* Valid VPD copied */
#define CSIO_HW_DEVID_CACHED		0X00000040	/* PCI vendor & device 
							 * id cached */
#define	CSIO_HWF_FWEVT_STOP		0x00000080	/* Stop processing 
							 * FW events 
							 */
#define CSIO_HWF_USING_SOFT_PARAMS	0x00000100      /* Using FW config 
							 * params 
							 */
#define csio_is_hw_intr_enabled(__hw)	((__hw)->flags & CSIO_HWF_INTR_ENABLED)
#define csio_is_hw_master(__hw)		((__hw)->flags & CSIO_HWF_MASTER)
#define csio_is_valid_vpd(__hw)		((__hw)->flags & CSIO_HW_VPD_VALID)
#define csio_is_dev_id_cached(__hw)	((__hw)->flags & CSIO_HW_DEVID_CACHED)

#define csio_valid_vpd_copied(__hw)	((__hw)->flags |= CSIO_HW_VPD_VALID)
#define csio_invalidate_vpd(__hw)	((__hw)->flags &= ~CSIO_HW_VPD_VALID)

#define csio_dev_id_cached(__hw)	((__hw)->flags |= CSIO_HW_DEVID_CACHED)
#define csio_invalidate_devid(__hw)	((__hw)->flags &= ~CSIO_HW_DEVID_CACHED)

/* Memory descriptor indices, CSIO_MAX_MD has to be the last descriptor */
enum {
	CSIO_LN_MD = 0,
	CSIO_RN_MD,
	CSIO_Q_ARR_MD,
	CSIO_Q_MD,
	CSIO_FLB_FWEVT_MD,
	CSIO_DDP_MD,
	CSIO_SCSIREQ_MD,
	CSIO_MGMTREQ_MD,
	CSIO_EVTQ_MD,
	CSIO_FCOE_FCF_MD,
#ifdef __CSIO_TARGET__
	CSIO_FLB_SCSI_MD,
	CSIO_TGTREQ_MD,
#endif /* __CSIO_TARGET__ */
	CSIO_ISCSI_PERSISTENT_DB_MD,
	CSIO_ISCSI_TLOGIN_MD,
	CSIO_ISCSI_RSESS_MD,
	CSIO_MAX_MD
};

#define CSIO_MAX_MEM_DESCS	CSIO_MAX_MD

/* Types of MSI[X] vectors */
enum csio_msi_type {
	CSIO_MSI_NONDATA	= 0,
	CSIO_MSI_MB 		= 1,
	CSIO_MSI_FWEVT 		= 2,
	CSIO_MSI_FCOECTRL	= 3,
	CSIO_MSI_SCSI 		= 4,
};

/* HW Queues */
enum {
	CSIO_FWEVT_WRSIZE = 128,
	CSIO_FWEVT_IQLEN = 128,
	CSIO_FWEVT_FLBUFS = 64,
};
#define CSIO_FWEVT_IQSIZE	(CSIO_FWEVT_WRSIZE * CSIO_FWEVT_IQLEN)
#define CSIO_HW_NIQ		1
#define CSIO_HW_NFLQ		1
#define CSIO_HW_NEQ		1 /* mgmt EQ */
#define CSIO_HW_NINTXQ		1

/* Defines for intr_mode */
enum csio_intr_mode {
	CSIO_IM_NONE = 0,
	CSIO_IM_INTX = 1,
	CSIO_IM_MSI  = 2,
	CSIO_IM_MSIX = 3,
};

/* Defines for INTx type */
#define INTX_INTA		0x0
#define INTX_INTB		0x1
#define INTX_INTC		0x2
#define INTX_INTD		0x3

/* T4 PCI config space uses the following logic for interrupt pin */
#define csio_intx_type(__hw)		((__hw)->pfn % 4)

/* Defines for scsi_mode */
#define CSIO_SCSI_MODE_INITIATOR	0x1
#define CSIO_SCSI_MODE_TARGET		0x2
#define CSIO_SCSI_MODE_MIXED		\
		(CSIO_SCSI_MODE_INITIATOR | CSIO_SCSI_MODE_TARGET)


/* 
 * Hard parameters used to initialize the card in the absence of a 
 * configuration file.
 */
enum {
	/* General */
	CSIO_SGE_DBFIFO_INT_THRESH 	= 10,

	CSIO_SGE_RX_DMA_OFFSET		= 2,

	CSIO_SGE_FLBUF_SIZE1 		= 65536,
	CSIO_SGE_FLBUF_SIZE2		= 1536,
	CSIO_SGE_FLBUF_SIZE3		= 9024,
	CSIO_SGE_FLBUF_SIZE4		= 9216,
	CSIO_SGE_FLBUF_SIZE5		= 2048,
	CSIO_SGE_FLBUF_SIZE6		= 128,
	CSIO_SGE_FLBUF_SIZE7		= 8192,
	CSIO_SGE_FLBUF_SIZE8		= 16384,

	CSIO_SGE_TIMER_VAL_0		= 5,
	CSIO_SGE_TIMER_VAL_1		= 10,
	CSIO_SGE_TIMER_VAL_2		= 20,
	CSIO_SGE_TIMER_VAL_3		= 50,
	CSIO_SGE_TIMER_VAL_4		= 100,
	CSIO_SGE_TIMER_VAL_5		= 200,

	CSIO_SGE_INT_CNT_VAL_0		= 1,
	CSIO_SGE_INT_CNT_VAL_1		= 4,
	CSIO_SGE_INT_CNT_VAL_2		= 8,
	CSIO_SGE_INT_CNT_VAL_3		= 16,

	/* Storage specific - used by FW_PFVF_CMD */
	CSIO_WX_CAPS			= FW_CMD_CAP_PF, /* w/x all */
	CSIO_R_CAPS			= FW_CMD_CAP_PF, /* r all */
	CSIO_NVI			= 4,
	CSIO_NIQ_FLINT			= 34,
	CSIO_NETH_CTRL			= 32,
	CSIO_NEQ			= 66,
	CSIO_NEXACTF			= 32,
	CSIO_CMASK			= M_FW_PFVF_CMD_CMASK,
	CSIO_PMASK			= M_FW_PFVF_CMD_PMASK,
};
 
#define csio_target_mode(__hw)		\
		((__hw)->scsi_mode & CSIO_SCSI_MODE_TARGET)
#define csio_initiator_mode(__hw)	\
		((__hw)->scsi_mode & CSIO_SCSI_MODE_INITIATOR)
#define csio_mixed_mode(__hw)		\
		((__hw)->scsi_mode & CSIO_SCSI_MODE_MIXED)
 
/* Defines for Generic events */
typedef enum csio_evt {
	CSIO_EVT_FW  = 0,	/* FW event */
	CSIO_EVT_SCN,		/* State change notification */
	CSIO_EVT_DEV_LOSS,	/* Device loss event */
	CSIO_EVT_MAX,		/* Max supported event */
} csio_evt_t;

/* Max event msg size */
#define EVT_MSG_SIZE		512
#define CSIO_EVTQ_SIZE		512

/* Event msg  */
struct csio_evt_msg {
	struct csio_list	list;	/* evt queue*/	
	csio_evt_t		type;
	uint8_t			data[EVT_MSG_SIZE];
}; 

/* HW State machine Events */
typedef enum {
	CSIO_HWE_CFG = (uint32_t)1, /* Starts off the State machine */
	CSIO_HWE_INIT,	         /* Config done, start Init      */
	CSIO_HWE_INIT_DONE,      /* Init Mailboxes sent, HW ready */
	CSIO_HWE_FATAL,		 /* Fatal error during initialization */
	CSIO_HWE_PCIERR_DETECTED,/* PCI error recovery detetced */
	CSIO_HWE_PCIERR_SLOT_RESET, /* Slot reset after PCI recoviery */
	CSIO_HWE_PCIERR_RESUME,  /* Resume after PCI error recovery */
	CSIO_HWE_QUIESCED,	 /* HBA quiesced */
	CSIO_HWE_HBA_RESET,      /* HBA reset requested */
	CSIO_HWE_HBA_RESET_DONE, /* HBA reset completed */
	CSIO_HWE_FW_DLOAD,       /* FW download requested */
	CSIO_HWE_PCI_REMOVE,     /* PCI de-instantiation */
	CSIO_HWE_SUSPEND,        /* HW suspend for Online(hot) replacement */
	CSIO_HWE_RESUME,         /* HW resume for Online(hot) replacement */
	CSIO_HWE_MAX,		 /* Max HW event */			
} csio_hw_ev_t;

enum {
        SF_SIZE = SF_SEC_SIZE * 16,   /* serial flash size */
};

/* serial flash and firmware constants */
enum {
	SF_ATTEMPTS = 10,             /* max retries for SF operations */

	/* flash command opcodes */
	SF_PROG_PAGE    = 2,          /* program page */
	SF_WR_DISABLE   = 4,          /* disable writes */
	SF_RD_STATUS    = 5,          /* read status register */
	SF_WR_ENABLE    = 6,          /* enable writes */
	SF_RD_DATA_FAST = 0xb,        /* read flash */
	SF_RD_ID	= 0x9f,	      /* read ID */
	SF_ERASE_SECTOR = 0xd8,       /* erase sector */
};

/* Common hw stats */
struct csio_hw_stats {
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
	csio_hw_ev_t	n_evt_sm[CSIO_HWE_MAX];	/* Number of sm events */	
	uint64_t	n_reset_start;  /* Start time after the reset */
	uint32_t	rsvd1;
};

/* User configurable hw parameters */
struct csio_hw_params {
	uint32_t		log_level;		/* Module-level for
							 * debug log.
							 */
};

struct csio_t4port {
	uint16_t	pcap;
	uint8_t		portid;
	uint8_t		link_status;
	uint16_t	link_speed;
	uint8_t		mac[6];
	uint8_t		mod_type;
	uint8_t		rsvd1;
	uint8_t		rsvd2;
	uint8_t		rsvd3;
};

#include <t4fw_interface.h>

/* fcoe resource information */
struct csio_fcoe_res_info {
	uint16_t	e_d_tov;
	uint16_t 	r_a_tov_seq;
	uint16_t 	r_a_tov_els;
	uint16_t 	r_r_tov;
	uint32_t 	max_xchgs;
	uint32_t 	max_ssns;
	uint32_t 	used_xchgs;
	uint32_t 	used_ssns;
	uint32_t 	max_fcfs;
	uint32_t 	max_vnps;
	uint32_t 	used_fcfs;
	uint32_t 	used_vnps;
};

/* HW OS callback ops */
struct csio_hw_os_ops {
	struct csio_lnode *(*os_alloc_lnode)(struct csio_hw *);
	csio_retval_t (*os_config_queues)(struct csio_hw *);
	struct csio_rnode *(*os_alloc_rnode)(struct csio_lnode *);
	void (*os_free_rnode)(struct csio_rnode *);
	void (*os_ln_async_event)(struct csio_lnode *, uint32_t);
	void (*os_ln_block_reqs)(struct csio_lnode *);
	void (*os_ln_unblock_reqs)(struct csio_lnode *);
	void (*os_rn_reg_rnode)(struct csio_rnode *);
	void (*os_rn_unreg_rnode)(struct csio_rnode *);
	void (*os_rn_async_event)(struct csio_rnode *, uint32_t);
	void (*os_abrt_cls)(struct csio_ioreq *, void *);
	int (*os_flash_fw)(struct csio_hw *);
	int (*os_flash_config)(struct csio_hw *,u32 *, char *);
	int (*os_flash_hw_phy)(struct csio_hw *);
#ifdef __CSIO_TARGET__
	void (*os_tgt_assign_queues)(struct csio_rnode *);
#endif /* __CSIO_TARGET__ */
};

/*****************************************************************************/
/* Master HW structure: One per PCIe function                                */
/*****************************************************************************/
struct csio_hw {
	struct csio_sm 		sm;   	 		/* State machine: should
							 * be the 1st member.
							 */
	struct adapter 		adap;
	csio_spinlock_t		lock;    		/* Lock for hw */
	struct csio_scsim	scsim; 			/* SCSI module*/
	struct csio_wrm		wrm; 			/* Work request module*/
	uint32_t		evtflag; 		/* Event flag  */
	uint32_t		flags;   		/* HW flags */

	/* Modules */
#ifdef __CSIO_TARGET__
	struct csio_tgtm	tgtm;			/* Target module */
#endif /* __CSIO_TARGET__ */
	struct csio_mgmtm	mgmtm; 			/* management module */

	/* Children */
	struct csio_lnode 	*rln; 			/* Root lnode */
	struct csio_list	sln_head;  		/* Sibling node list
							 * list 
							 */
	int			intr_iq_idx;		/* Forward interrupt
							 * queue.
							 */
	int			fwevt_iq_idx;		/* FW evt queue */ 
	csio_work_t		evtq_work;		/* Worker thread for 
							 * HW events.
							 */
	struct csio_list	evt_free_q;		/* freelist of evt 
							 * elements
							 */
	csio_spinlock_t		evt_fq_lock;  		/* Lock for above */
	struct csio_list	evt_active_q;		/* active evt queue*/	
	csio_spinlock_t		evt_aq_lock;  		/* Lock for above */

	/* board related info */
	char 			name[32];
	char 			hw_ver[16];
	char			model_desc[32];
	char 			drv_version[32];
	char			fwrev_str[32];
	uint32_t		optrom_ver;
	uint32_t		fwrev;
	uint32_t 		tp_vers;
	uint32_t 		cfg_finiver;
	uint32_t		cfg_finicsum;
	uint32_t		cfg_cfcsum;
	uint8_t			cfg_csum_status;
	uint8_t			cfg_store;
	enum dev_state 		fw_state;

	uint8_t			pfn;	 		/* Physical Function
							 * number 
							 */
	uint8_t			scsi_mode;		/* SCSI mode: 
							 * Initiator/target
							 */
	uint32_t		port_vec;		/* Port vector */
	uint8_t			num_t4ports;		/* Actual number of
							 * ports.
							 */
	uint8_t			rst_retries;		/* Reset retries */
	uint8_t			cur_evt;		/* current s/m evt */
	uint8_t			prev_evt;		/* Previous s/m evt */
	uint32_t		dev_num;		/* device number */
	struct csio_t4port	t4port[CSIO_MAX_T4PORTS];/* Ports (XGMACs) */

	struct csio_hw_stats	stats; 			/* Hw statistics */
	struct csio_hw_params	params; 		/* Hw parameters */
	csio_trace_buf_t	*trace_buf;		/* Trace buffer */
#ifdef CSIO_DATA_CAPTURE
 	csio_dcap_buf_t         *dcap_buf;               /* Data capture buf */
#endif
	/*********************************************************************/
	/* The following fields are filled in by the OS-dependent code */
	/*********************************************************************/
	void 			*os_hwp;  		/* Ref pointer to OS 
							 * HW 
							 */
	void			*os_dev;		/* The OS's 
							 * representation of 
							 * the function, in 
							 * case OS services 
							 * requires a 
							 * reference. 
							 */
	struct csio_hw_os_ops	*os_ops;		/* Os ops */
	uint32_t		os_flags; 		/* OS flags */

	/* Pre-allocated handles - Virtual memory + DMA */
	struct csio_list	mem_descs[CSIO_MAX_MEM_DESCS];
							/* Array of pre-
							 * allocated memory
							 * descriptors for
							 * memory allocation.
							 */
	/* Interrupt related */
	enum csio_intr_mode	intr_mode; 		/* INTx, MSI, MSIX */
	uint8_t			intx_type; 		/* INTA,INTB,INTC,INTD*/
	uint32_t		fwevt_intr_idx;		/* FW evt MSIX/interrupt
							 * index 
							 */
	uint32_t		nondata_intr_idx;	/* nondata MSIX/intr
							 * idx
							 */

	uint8_t			cfg_neq;		/* FW configured no of 
							 * egress queues 
							 */
	uint8_t			cfg_niq;		/* FW configured no of
                                                         * iq queues.
							 */

	uint32_t		num_lns;		/* Number of lnodes */
	union { 
		struct csio_fcoe_res_info  fres_info;	/* Fcoe resource info */
	} un;	
};

/*************************************************************************/
/*       Core clocks <==> uSecs						 */
/*************************************************************************/

static inline uint32_t
csio_core_ticks_to_us(struct csio_hw *hw, uint32_t ticks)
{
        /* add Core Clock / 2 to round ticks to nearest uS */
        return ((ticks * 1000 + hw->adap.params.vpd.cclk/2) / hw->adap.params.vpd.cclk);
}

static inline uint32_t 
csio_us_to_core_ticks(struct csio_hw *hw, uint32_t us)
{
        return (us * hw->adap.params.vpd.cclk) / 1000;
}

/*****************************************************************************/
/* Easy access macros */
/*****************************************************************************/
#define csio_hw_to_os(hw)		((hw)->os_hwp)

#define csio_hw_to_wrm(hw)		((struct csio_wrm *)(&(hw)->wrm))
#define csio_hw_to_scsim(hw)		((struct csio_scsim *)(&(hw)->scsim))
#ifdef __CSIO_TARGET__
#define csio_hw_to_tgtm(hw)		((struct csio_tgtm *)(&(hw)->tgtm))
#endif /* __CSIO_TARGET__ */
#define csio_hw_to_mgmtm(hw)		((struct csio_mgmtm *)(&(hw)->mgmtm))

#define csio_md(hw, idx)		(&(hw)->mem_descs[(idx)])
#define csio_hw_to_tbuf(hw)		((hw)->trace_buf)
#define csio_hw_to_ops(hw)		((hw)->os_ops)

static inline int
csio_is_fcoe(struct csio_hw *hw)
{
	return ((hw->os_flags & CSIO_HWOSF_FN_FCOE)? 1 : 0);
}

static inline int
csio_is_iscsi(struct csio_hw *hw)
{
	return ((hw->os_flags & CSIO_HWOSF_FN_FCOE)? 0 : 1);
}

#define csio_set_fwevt_intr_idx(_h, _i)		((_h)->fwevt_intr_idx = (_i))
#define csio_get_fwevt_intr_idx(_h)		((_h)->fwevt_intr_idx)
#define csio_set_nondata_intr_idx(_h, _i)	((_h)->nondata_intr_idx = (_i))
#define csio_get_nondata_intr_idx(_h)		((_h)->nondata_intr_idx)

/*****************************************************************************/
/* Start of T4/T5 specific operations					     */
/*****************************************************************************/

#define CH_PCI_FN_MASK(__PF, __DeviceID) \
	((__DeviceID) | ((__PF) << 8))

#define CHECK_PF_MASK(__PF, __DeviceID) \
        ((__PF) == (((__DeviceID) >> 8) & 0xf))

#define PF_FCOE       	0x06
#define PF_ISCSI       	0x05
#define PF_FPGA       	0x00
#define T6_PF_FPGA	0x01

#define CSIO_HW_T4		0x4000
#define CSIO_HW_T5		0x5000
#define CSIO_HW_T4FPGA		0xA000
#define CSIO_HW_T5FPGA		0xB000
#define CSIO_HW_T6FPGA_FOISCSI	0xC106
#define CSIO_HW_CHIP_MASK	0xF000
#define CSIO_FPGA		0xA000
#define CSIO_T4_FCOE_ASIC	0x4600
#define CSIO_T5_FCOE_ASIC	0x5600
#define CSIO_T4_CS_FCOE_ASIC	0x4680
#define CSIO_T4_ISCSI_ASIC	0x4500
#define CSIO_T5_ISCSI_ASIC	0X5500
#define CSIO_T4_HS_ISCSI_ASIC	0x4580

#define CSIO_T4_ISCSI_PHY_AQ1202_DEVICEID	0x4509
#define CSIO_T4_FCOE_PHY_AQ1202_DEVICEID	0x4609
#define CSIO_T4_ISCSI_PHY_BCM84834_DEVICEID	0x4586
#define CSIO_T4_FCOE_PHY_BCM84834_DEVICEID	0x4686

static inline int csio_chip_id(struct csio_hw *hw)
{
	return CHELSIO_CHIP_VERSION(hw->adap.params.chip);
}

#define CSIO_HW_MPS_TRC_FILTER_FLAG(hw, tp)				\
	(is_t4(hw->adap.params.chip) ? (V_TFPORT(tp->port) | F_TFEN |	\
				    V_TFINVERTMATCH(tp->invert)) :	\
				   (V_T5_TFPORT(tp->port) | F_T5_TFEN |	\
				    V_T5_TFINVERTMATCH(tp->invert)))

#define CSIO_HW_F_TFEN(hw)						\
	(is_t4(hw->adap.params.chip) ? (F_TFEN) : (F_T5_TFEN))

#define CSIO_HW_G_TFPORT(hw, val)					\
	(is_t4(hw->adap.params.chip) ? (G_TFPORT(val)) : (G_T5_TFPORT(val)))

#define CSIO_HW_LP_INT_THRESH(hw, val)					\
	(is_t4(hw->adap.params.chip) ? (V_LP_INT_THRESH(val)) :		\
				   (V_LP_INT_THRESH_T5(val)))

#define CSIO_HW_M_LP_INT_THRESH(hw)					\
	(is_t4(hw->adap.params.chip) ? (M_LP_INT_THRESH) : (M_LP_INT_THRESH_T5))

#define CSIO_MAX_MAC_ADDR(hw)						\
	(is_t4(hw->adap.params.chip) ? (NUM_MPS_CLS_SRAM_L_INSTANCES) :	\
				   (NUM_MPS_T5_CLS_SRAM_L_INSTANCES))

#define CSIO_CIM_NUM_OBQ(hw)						\
	(is_t4(hw->adap.params.chip) ? (CIM_NUM_OBQ) : (CIM_NUM_OBQ_T5))

#define CSIO_IBQ_RDADDR(hw)						\
	(is_t4(hw->adap.params.chip) ? (A_UP_IBQ_0_RDADDR) :		\
				   (A_UP_IBQ_0_SHADOW_RDADDR))

#define CSIO_OBQ_REALADDR(hw)						\
	(is_t4(hw->adap.params.chip) ? (A_UP_OBQ_0_REALADDR) :		\
				   (A_UP_OBQ_0_SHADOW_REALADDR))

#define CSIO_PORT_REG(hw, port, reg)					\
	(is_t4(hw->adap.params.chip) ? (PORT_REG(port, reg)) :		\
				   (T5_PORT_REG(port, reg)))

#define CSIO_PAGES_USED(hw, lo)						\
	(is_t4(hw->adap.params.chip) ? (G_USED(lo)) : (G_T5_USED(lo)))

#define CSIO_PAGES_ALLOC(hw, lo)					\
	(is_t4(hw->adap.params.chip) ? (G_ALLOC(lo)) : (G_T5_ALLOC(lo)))

#define CSIO_INT_CAUSE_REG(hw, port)					\
	(is_t4(hw->adap.params.chip) ? (PORT_REG(port, A_XGMAC_PORT_INT_CAUSE)) : \
				   (T5_PORT_REG(port, A_MAC_PORT_INT_CAUSE)))

/*****************************************************************************/
/* End of T4/T5 specific operations					     */
/*****************************************************************************/

/*****************************************************************************/
/* Entry points                                                              */
/*****************************************************************************/
/* HW initialization */
csio_retval_t csio_hw_init(struct csio_hw *, struct csio_hw_os_ops *);
void csio_hw_exit(struct csio_hw *);

/* HW info related */
csio_retval_t csio_hw_get_vpd_params(struct csio_hw *hw, struct vpd_params *p);
csio_retval_t csio_hw_get_device_id(struct csio_hw *hw);
int csio_hw_set_mem_win(struct csio_hw *hw);

/* Interrupt related */
csio_retval_t csio_fwevtq_handler(struct csio_hw *);
void csio_hw_intr_enable(struct csio_hw *);
void csio_hw_intr_disable(struct csio_hw *);
int csio_hw_slow_intr_handler(struct csio_hw *hw);

/* HW start, reset */
csio_retval_t csio_hw_start(struct csio_hw *);
csio_retval_t csio_hw_stop(struct csio_hw *);
csio_retval_t csio_hw_reset(struct csio_hw *);
void csio_hw_stateto_str(struct csio_hw *hw, int8_t *str); 
const char *csio_hw_evt_name(csio_hw_ev_t evt); 

/* Flash routines */
csio_retval_t
csio_hw_flash_erase_sectors(struct csio_hw *hw, int32_t start, int32_t end);

csio_retval_t
csio_hw_write_flash(struct csio_hw *hw, uint32_t addr,
		    uint32_t n, const uint8_t *data);

csio_retval_t
csio_hw_read_flash(struct csio_hw *hw, uint32_t addr, uint32_t nwords,
		  uint32_t *data, int32_t byte_oriented);
          
/* DPC workers. */
void csio_evtq_worker(void *data);

/* HW IOCTL handler */
csio_retval_t
csio_hw_ioctl_handler(struct csio_hw *hw, uint32_t opcode, void *buffer,
			uint32_t buffer_len);

int csio_hw_check_fwconfig(struct csio_hw *hw, u32 *param);

/* PHY fw fn */
int csio_hw_get_phy_fw_ver(struct csio_hw *hw, u32 *phy_fw_ver);
int csio_hw_get_phy_fw_addr_rw(struct csio_hw *hw, u32 *val);
int csio_hw_set_phy_fw_load_addr(struct csio_hw *hw, u32 val);

csio_retval_t csio_hw_get_fw_version(struct csio_hw *, uint32_t *);

void 
csio_hw_get_fcoe_stats(struct csio_hw *hw, uint32_t idx,
		       struct tp_fcoe_stats *st);
int
csio_hw_set_trace_filter(struct csio_hw *hw, const struct trace_params *tp,
			 int idx, int enable);
void
csio_hw_get_trace_filter(struct csio_hw *hw, struct trace_params *tp, int idx,
			 int *enabled);

int csio_is_hw_ready(struct csio_hw *hw); 
int csio_is_hw_removing(struct csio_hw *hw); 

/* Event queue */
csio_retval_t
csio_enqueue_evt(struct csio_hw *hw, csio_evt_t type, void *evt_msg, 
			uint16_t len);
csio_retval_t
csio_enqueue_evt_lock(struct csio_hw *hw, csio_evt_t type, void *evt_msg, 
			uint16_t len, bool msg_sg);
struct csio_evt_msg *csio_dequeue_evt(struct csio_hw *hw);
void csio_free_evt(struct csio_hw *hw, struct csio_evt_msg *evt_entry);
void csio_evtq_flush(struct csio_hw *hw); 
void csio_evtq_cleanup(struct csio_hw *hw); 
csio_retval_t
csio_hw_get_dcbx_info(struct csio_hw *hw, void *buffer, uint32_t buffer_len);

#ifdef __CSIO_FOISCSI_ENABLED__
csio_retval_t csio_enable_foiscsi_ipv6(struct csio_hw *hw);
#endif

#ifdef __CSIO_DEBUG__
void csio_assert_fw(struct csio_hw *hw);
#else
#define csio_assert_fw(__hw)
#endif /* __CSIO_DEBUG__ */

#endif /* ifndef __CSIO_HW_H__ */
