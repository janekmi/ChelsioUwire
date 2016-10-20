/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/*
 * Description:
 * 	This is chfcoe_port.h header file, contains FCoE Ports related defines.
 */
#ifndef __CHFCOE_PORT_H__
#define __CHFCOE_PORT_H__

#include "chfcoe_defs.h"
#include "chfcoe_proto.h"
#include "chfcoe_adap.h"

typedef struct chfcoe_port_stats {
	uint32_t		n_link_up;	/* No of link up */
	uint32_t		n_link_down;	/* No of link down */
	uint32_t		n_fcf;		/* No of FCFs */
	uint32_t		n_vn2vn;	/* No. of vn2vn */
	uint32_t		n_fip_rx_fr;	/* No. of FIP Rx frame */
	uint32_t		n_fcoe_rx_fr;	/* No. of FCOE Rx frame */
	uint32_t		n_fip_tx_fr;	/* No. of FIP Tx Frames */
	uint32_t		n_fcoe_tx_fr;	/* No. of FCOE Tx Frames */
	uint32_t		n_fip_drop;	/* No. fip frame droped */
	uint32_t		n_nomem;	/* No. memory failures */
	uint32_t		n_unknown_fr;	/* No. unknown frame */
#ifdef __CHFCOE_SCSI_PERF__
	/* Performance stats */
	uint64_t		start_sec;
	atomic64_t		rbytes;
	atomic64_t		wbytes;
	atomic64_t		reads;
	atomic64_t		writes;
	uint64_t		saved_delta_secs;
	uint64_t		saved_rbytes;
	uint64_t		saved_wbytes;
	uint64_t		saved_reads;
	uint64_t		saved_writes;
#endif /* __CHFCOE_SCSI_PERF__ */
} chfcoe_port_stats_t;

typedef struct chfcoe_scsi_stats {
	uint32_t		n_abrt_tsk;	/* No. ABORT TASK */
	uint32_t		n_lun_rst;	/* Number of LUN RESET */
	uint32_t		n_tgt_rst;	/* Number of TARGET RESET */
	uint32_t		n_abrt_tsk_set;	/* No. of ABORT TASK SET */
	uint32_t		n_clr_tsk_set;	/* No. of CLEAR TASK SET */
	uint32_t		n_clr_aca;	/* No. of CLEAR ACA */

	uint64_t		n_read_cmd;	/* Total number of reads */
	uint64_t		n_write_cmd;	/* Total number of writes */
	uint64_t		n_none_cmd;	/* Total number of non read, write cmd*/
	uint64_t		n_tot_success;	/* Total number of good I/Os */
	uint32_t		n_rn_nr_error;	/* No. of remote-node-not-
						 * ready errors
						 */
	uint32_t		n_ar_reads;	/* No. of auto rsp reads */
	uint32_t		n_adap_nr_error;/* No. of adap-not-
						 * ready errors
						 */
	uint32_t		n_dmamap_error;	/* No. of DMA map erros */
	uint32_t		n_unsupp_sge_error;
						/* No. of too-many-SGes
						 * errors.
						 */
	uint32_t		n_no_req_error;	/* No. of Out-of-ioreqs error */
	uint32_t		n_busy_error;	/* No. of CHFCOE_BUSY errors */
	uint32_t		n_rsperror;	/* No. of response errors */
	uint32_t		n_autosense;	/* No. of auto sense replies */
	uint32_t		n_ovflerror;	/* No. of overflow errors */
	uint32_t		n_unflerror;	/* No. of underflow errors */
	uint32_t		n_rdev_nr_error;/* No. of rdev not
						 * ready errors
						 */
	uint32_t		n_err_sal_rsp;	/* No. of sal response errors */
	uint32_t		n_rdev_lost_error;
						/* No. of rdev lost errors */
	uint32_t		n_rdev_logo_error;
						/* No. of rdev logo errors */
	uint32_t		n_rdev_impl_logo_error;
						/* No. of rdev implicit logo errors */
	uint32_t		n_link_down_error;
						/* No. of link down errors */
	uint32_t		n_no_xchg_error;/* No. no exchange error */
	uint32_t		n_unknown_error;/* No. of unhandled errors */
	uint32_t		n_abrt_timedout;/* No. of abort timedouts */
	uint32_t		n_abrt_fail;	/* No. of abort failures */
	uint32_t		n_abrt_dups;	/* No. of duplicate aborts */
	uint32_t		n_abrt_race_comp;
						/* No. of aborts that raced
						 * with completions.
						 */
	uint32_t		n_abrt_busy_error;
						/* No. of abort failures
						 * due to CSIO_BUSY.
						 */
	uint32_t		n_closed;	/* No. of closed I/Os */
	uint32_t		n_cls_busy_error;
						/* No. of close failures
						 * due to CSIO_BUSY.
						 */
	uint32_t		n_active;	/* No. of IOs in active_q */
	uint32_t		n_max_active;	/* No. of max active IOs */ 
	uint32_t		n_tm_active;	/* No. of TMs in active_q */
	uint32_t		n_wcbfn;	/* No. of I/Os in worker
						 * cbfn q
						 */
	uint32_t		n_free_ioreq;	/* No. of freelist entries */
	uint32_t		n_free_ddp;	/* No. of DDP freelist */
	uint32_t		n_ddp_miss;	/* No. of DDP misses */
	uint32_t		n_ppod_used;	/* No. of ppod allocated */
	void			*n_tid_alloc;
	void			*n_tid_free;
	void			*n_ddp_data;
	void			*n_ddp_qd;
	void			*n_xfer_rdy;
	uint32_t		n_inval_cplop;	/* No. invalid CPL op's in IQ */
	uint32_t		n_inval_scsiop;	/* No. invalid scsi op's in IQ*/
	uint32_t		n_free_exch;	/* No. of free exchanges */
	uint32_t		n_free_exch_xid;/* No. of free exch ids */
	uint32_t		n_xid_not_found;/* No. of Exch ID not found */
	uint32_t		n_xid_busy;	/* No. of Exch ID being busy */
	uint32_t		n_seq_not_found;/* No. of seq not found */
	uint32_t		n_non_bls_resp;	/* No. of non-bls responses */
	uint32_t		n_draining; 	/* No. of req in draining q */
	uint16_t 		n_abrtd_sal;	/* Number of I/Os while at SAL*/
} chfcoe_scsi_stats_t;

enum chfcoe_port_state {
	CHFCOE_PORT_INIT,
	CHFCOE_PORT_ONLINE,
	CHFCOE_PORT_OFFLINE
};

typedef struct chfcoe_port_info {
	struct chfcoe_adap_info		*adap;		/* Pointer to
							 * parent adap
							 */
	void				*os_dev;	/* OS related Port
							 * Information.
							 * For Linux, its
							 * net_device.
							 */
	void				*mtx_lock;	/* Mutex lock */	
	struct chfcoe_list		fcf_head;	/* fcf list */
	struct chfcoe_list		vn2vn_head;	/* vn2vn list */
	struct chfcoe_list		ln_head;	/* lnode list */
	struct chfcoe_lnode		*root_ln;	/* root lnode */
	uint8_t				port_num;	/* Port Number */
	uint8_t				vi_id;		/* VI ID given
							 * by cxgb4 driver
							 */
	uint8_t				link_state;	/* physical link */
	uint8_t				num_ln;		/* Number of lnodes */
	uint8_t				dcb_prio;	/* dcbx priority */
	uint8_t				phy_mac[6];	/* physical MAC */
	uint8_t 			wwnn[8];	/* WWNN */
	uint8_t				wwpn[8];	/* WWPN */
	uint16_t			num_fcf;	/* Number of FCF */
	uint16_t			num_vn2vn;	/* Number of VN2VN */
	uint16_t			fcf_mpsid;	/* MPS ID of FCF MCAST 
							 * addr 
							 */
	uint16_t			vn2vn_mpsid;	/* MPS ID of VN2VN 
							 * MCAST addr 
							 */
	struct chfcoe_port_stats	stats;		/* port statistics */
	chfcoe_work_t			*fip_rx_work;
	void				*fip_rx_list;
	
	void	                        *n_active_rnode;
	void			        *lock;           /* port lock */
#ifdef __CHFCOE_DEBUGFS__
	void                            *debugfs_root; 	/* debugfs  pointer */
#endif

	/* ddp stuff */
	void				*tid_list_lock;	/* TID list lock */
	struct chfcoe_list		tid_list;	/* TID's list head */
	uint32_t			tid_list_len;	/* TID list length */
	struct chfcoe_ddp               *ddp;
	void		                *ddp_mutex;
	int				nqsets;
	void **                         txqlock;        /* Tx queue locks for DDP */
} chfcoe_port_info_t;

#define chfcoe_port_info_size		(sizeof(struct chfcoe_port_info) + (2 * os_spinlock_size) \
					+ (2 * os_mutex_size) + os_atomic_size \
					+ chfcoe_work_size + os_sk_buff_head_size)


#define chfcoe_pi_to_adap(pi) 		((pi)->adap)
#define chfcoe_adap_to_pi(adap, port)	CHFCOE_PTR_OFFSET((adap)->pi, ((port) * chfcoe_port_info_size))

chfcoe_retval_t
chfcoe_port_lnode_init(struct chfcoe_adap_info *adap, uint8_t port_num);

void chfcoe_port_lnode_exit(struct chfcoe_adap_info *adap, uint8_t port_num);
chfcoe_retval_t
chfcoe_adap_ioctl_handler(struct chfcoe_adap_info *,
			  uint32_t, void *, uint32_t);


chfcoe_retval_t chfcoe_start_fip(struct chfcoe_port_info *pi);
chfcoe_retval_t chfcoe_stop_fip(struct chfcoe_port_info *);

void *
chfcoe_fill_cpl_tx(chfcoe_fc_buffer_t *p, uint8_t pf, size_t payload_len,
		   uint8_t port_num, uint16_t vlan_id);

extern void *chfcoe_workq;

static inline
int chfcoe_adap_set_macaddr(struct chfcoe_port_info *pi, u8 *mac, u16 *idx, 
		bool clear)
{
	struct chfcoe_adap_info *adap = pi->adap;
	return adap->lld_ops->set_mac_addr(pi->os_dev, mac, idx, clear);
}

static inline
int chfcoe_adap_send_frame(chfcoe_fc_buffer_t *fb, struct chfcoe_port_info *pi)
{
	struct chfcoe_adap_info *adap = pi->adap;
	return adap->lld_ops->send_frame(fb, pi->os_dev, chfcoe_fc_txq(fb));
}
#endif /* __CHFCOE_ADAP_H__ */
