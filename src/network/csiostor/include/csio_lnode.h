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

#ifndef __CSIO_LNODE_H__
#define __CSIO_LNODE_H__
#include <csio_lnode_fcoe.h>
#include <csio_defs.h>
#include <csio_fcoe_ioctl.h>

#ifdef __CSIO_TARGET__
#include <csio_tgt_api.h>
#endif /* __CSIO_TARGET__ */ 

#ifdef __CSIO_FOISCSI_ENABLED__
#include <csio_lnode_foiscsi.h>
#endif

/* Common Lnode stats */
struct csio_lnode_stats {
	uint32_t	rsvd1;
	uint32_t	n_rnode_alloc;	/* rnode allocated */
	uint32_t	n_rnode_free;	/* rnode freed */
	uint32_t	n_rnode_nomem;	/* rnode alloc failure */
	uint32_t        n_input_requests; /* Input Requests */
	uint32_t        n_output_requests; /* Output Requests */
	uint32_t        n_control_requests; /* Control Requests */
	uint32_t        n_input_bytes; /* Input Bytes */
	uint32_t        n_output_bytes; /* Output Bytes */
};

/* Common Lnode params */
struct csio_lnode_params {
	uint32_t	rsvd1;
	uint32_t	log_level;	/* Module level for debugging */	
};

struct csio_lnode {
	struct csio_list	slist;		/* Sibling lnode list - should 
						 * be the first member in this 
						 * structure.
						 */
	struct csio_hw		*hwp;		/* Pointer to the HW module */
	void 			*os_lnp;	/* The OS dependent lnode */
	uint8_t			portid;		/* Port ID */
	uint8_t			rsvd1;
	uint16_t		rsvd2;
	uint32_t		dev_num;	/* Device number */	

	/* Transport module */
	union { 				/* Transport module */
		struct csio_lnode_fcoe	lnf;
#ifdef __CSIO_FOISCSI_ENABLED__
		struct csio_lnode_iscsi	lni;
#endif
	} un;
	
	/* Children */
	struct csio_list	cln_head;	/* Head of the children lnode
						 * list.
						 */
	uint32_t 		num_vports;	/* Total NPIV/children LNodes*/
	struct csio_lnode	*pln;		/* Parent lnode of child 
						 * lnodes.
						 */
	struct csio_list	cmpl_q;		/* Pending I/Os on this lnode */
#ifdef __CSIO_TARGET__
        csio_tgt_handle_t	tgt_hdl;	/* tgt handle */
#endif /* __CSIO_TARGET__ */

	/* Remote node information */
	struct csio_list	rnhead;		/* Head of rnode list */
	uint32_t		num_reg_rnodes;	/* Number of rnodes registered
						 * with the host.
						 */
	
	struct csio_lnode_stats stats;		/* Common lnode stats */
	struct csio_lnode_params params;	/* Common lnode params */
	uint32_t		n_scsi_tgts;	/* Number of scsi targets 
						 * found 
						 */
	uint32_t		last_scan_ntgts;/* Number of scsi targets 
						 * found per last scan. 
						 */
	uint32_t		tgt_scan_tick;	/* timer started after 
						 * new tgt found
						 */
};

/* Common->OS events */
typedef enum {
	/* FCOE lnode events */
	CSIO_LNF_OSE_LINKUP = 1,
	CSIO_LNF_OSE_LINKDOWN,
	CSIO_LNF_OSE_RSCN,
	CSIO_LNF_OSE_ATTRIB_UPDATE,

	/* iSCSI lnode events */
} csio_ln_os_evt_t;

#define	csio_lnode_to_os(ln)	((ln)->os_lnp)
#define	csio_lnode_to_hw(ln)	((ln)->hwp)
#define csio_lnode_to_fcoe(ln)	(&(ln)->un.lnf)
#define csio_lnode_to_iscsi(ln)	(&(ln)->un.lni)
#define csio_root_lnode(ln)	(csio_lnode_to_hw((ln))->rln)
#define csio_parent_lnode(ln)	((ln)->pln)

#define csio_ln_dbg(_ln, _fmt, ...)	\
	csio_dbg(_ln->hwp, "%x:%x "_fmt, CSIO_DEVID_HI(_ln), \
		 CSIO_DEVID_LO(_ln), ##__VA_ARGS__);
	
#define csio_ln_err(_ln, _fmt, ...)	\
	csio_err(_ln->hwp, "%x:%x "_fmt, CSIO_DEVID_HI(_ln), \
		 CSIO_DEVID_LO(_ln), ##__VA_ARGS__);

#define csio_ln_warn(_ln, _fmt, ...)	\
	csio_warn(_ln->hwp, "%x:%x "_fmt, CSIO_DEVID_HI(_ln), \
		 CSIO_DEVID_LO(_ln), ##__VA_ARGS__);

/* HW->Lnode notifications */
typedef enum {
	CSIO_LN_NOTIFY_HWREADY = 1,
	CSIO_LN_NOTIFY_HWSTOP,
	CSIO_LN_NOTIFY_HWREMOVE,
	CSIO_LN_NOTIFY_HWRESET,
} csio_ln_notify_t;

int csio_scan_done(struct csio_lnode *, unsigned long, unsigned long,
		   unsigned long, unsigned long);
void csio_notify_lnodes(struct csio_hw *, csio_ln_notify_t);
void csio_disable_lnodes(struct csio_hw *hw, uint8_t portid, bool disable);
csio_retval_t csio_lnode_init(struct csio_lnode *, struct csio_hw *,
			      struct csio_lnode *);
void csio_lnode_exit(struct csio_lnode *);
csio_retval_t 
csio_get_phy_port_stats(struct csio_hw *, uint8_t , struct fw_fcoe_port_stats *);

#endif /* ifndef __CSIO_LNODE_H__ */
