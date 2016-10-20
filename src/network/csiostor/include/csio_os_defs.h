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

#ifndef __CSIO_OS_DEFS_H__
#define __CSIO_OS_DEFS_H__

#include <csio_os_lnode.h>
#include <csio_os_rnode.h>
#include <csio_os_hw.h>

/*****************************************************************************
 * Easy access macros OS<==>Common                                           *
 *****************************************************************************/
/* HW */
#define csio_oshw_to_hw(oshw)	((struct csio_hw *)(&(oshw)->hw))
#define csio_hw_to_osdev(oshw)	((csio_oshw_to_hw((oshw)))->os_dev)
#define csio_oshw_to_adap(oshw)	((struct adapter *)(&((oshw)->hw.adap)))

/* Lnode */
#define csio_osln_to_ln(osln)	((struct csio_lnode *)(&(osln)->lnode))

/* Rnode */
#define csio_osrn_to_rn(osrn)	((struct csio_rnode *)(&(osrn)->rnode))

/*****************************************************************************
 * Easy access macros OS<==>Transport module members                         * 
 *****************************************************************************/

#define csio_lnode_wwnn(osln)					\
		(csio_lnf_wwnn(csio_lnode_to_fcoe(csio_osln_to_ln((osln)))))
#define csio_lnode_wwpn(osln)					\
		(csio_lnf_wwpn(csio_lnode_to_fcoe(csio_osln_to_ln((osln)))))
#define csio_lnode_sparm(osln) ((struct csio_service_parms *)	\
		(&(csio_lnode_to_fcoe(csio_osln_to_ln((osln))))->ln_sparm))
#define csio_lnode_maxnpiv(osln)				\
	((csio_lnode_to_hw(					\
		csio_osln_to_ln((osln))))->un.fres_info.max_vnps)

#define csio_rnode_wwnn(osrn)					\
		(csio_rnf_wwnn(csio_rnode_to_fcoe(csio_osrn_to_rn((osrn)))))
#define csio_rnode_wwpn(osrn)					\
		(csio_rnf_wwpn(csio_rnode_to_fcoe(csio_osrn_to_rn((osrn)))))
#define csio_rnode_sparm(osrn) ((struct csio_service_parms *)	\
		(&(csio_rnode_to_fcoe(csio_osrn_to_rn((osrn))))->rn_sparm))

/*****************************************************************************
 * Conversion functions                                                      *
 *****************************************************************************/
static inline struct Scsi_Host *
csio_osln_to_shost(struct csio_os_lnode *osln)
{
        return container_of((void *)osln, struct Scsi_Host, hostdata[0]);
}

/* hw<==>lnode<==>rnode */
static inline struct csio_os_hw *
csio_osln_to_oshw(struct csio_os_lnode *osln)
{
	struct csio_hw *hw = csio_lnode_to_hw(csio_osln_to_ln(osln));

	return (csio_hw_to_os(hw));
}

static inline struct csio_hw *
csio_osln_to_hw(struct csio_os_lnode *osln)
{
	return csio_lnode_to_hw(csio_osln_to_ln(osln));
}

static inline struct csio_os_lnode *
csio_osrn_to_osln(struct csio_os_rnode *osrn)
{
	struct csio_lnode *ln = csio_rnode_to_lnode(csio_osrn_to_rn(osrn));

	return (csio_lnode_to_os(ln));
}

static inline struct csio_lnode *
csio_osrn_to_lnode(struct csio_os_rnode *osrn)
{
	return csio_rnode_to_lnode(csio_osrn_to_rn(osrn));
}

static inline struct csio_os_hw *
csio_adap_to_oshw(struct adapter *adap)
{
	struct csio_hw *hw = container_of((void *)adap, struct csio_hw, adap);
	return (csio_hw_to_os(hw));
}

/* SCSI -- locking version of get/put ioreqs  */
static inline struct csio_ioreq *
csio_get_scsi_ioreq_lock(struct csio_hw *hw, struct csio_scsim *scsim)
{
	struct csio_ioreq *ioreq;
	unsigned long flags;

	csio_spin_lock_irqsave(hw, &scsim->freelist_lock, flags);
	ioreq = csio_get_scsi_ioreq(scsim);
	csio_spin_unlock_irqrestore(hw, &scsim->freelist_lock, flags);

	return ioreq;
}

static inline void
csio_put_scsi_ioreq_lock(struct csio_hw *hw, struct csio_scsim *scsim,
			 struct csio_ioreq *ioreq)
{
	unsigned long flags;

	csio_spin_lock_irqsave(hw, &scsim->freelist_lock, flags);
	csio_put_scsi_ioreq(scsim, ioreq);
	csio_spin_unlock_irqrestore(hw, &scsim->freelist_lock, flags);

	return;
}

static inline void
csio_put_scsi_ioreq_list_lock(struct csio_hw *hw, struct csio_scsim *scsim,
			      struct csio_list *reqlist, int n)
{
	unsigned long flags;

	csio_spin_lock_irqsave(hw, &scsim->freelist_lock, flags);
	csio_put_scsi_ioreq_list(scsim, reqlist, n);
	csio_spin_unlock_irqrestore(hw, &scsim->freelist_lock, flags);

	return;
}

static inline void
csio_put_scsi_ddp_list_lock(struct csio_hw *hw, struct csio_scsim *scsim,
			      struct csio_list *reqlist, int n)
{
	unsigned long flags;

	csio_spin_lock_irqsave(hw, &hw->lock, flags);
	csio_put_scsi_ddp_list(scsim, reqlist, n);
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

	return;
}

#endif /*ifndef  __CSIO_OS_DEFS_H__ */
