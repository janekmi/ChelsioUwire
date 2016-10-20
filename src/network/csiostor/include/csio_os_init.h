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

#ifndef __CIOS_OS_INIT_H__
#define __CIOS_OS_INIT_H__

#include <linux/pci.h>
#include <linux/if_ether.h>
#include <scsi/scsi.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_transport_fc.h>
#include <scsi/scsi_transport_iscsi.h>

#include <csio_os_defs.h>
#include <csio_os_scsi.h>

#define CSIO_FCOE_WORD_TO_BYTE       4

#define csio_param_check(name, def, min, max, typ)			\
static int								\
csio_##name##_check(typ val)						\
{									\
        if (val >= min && val <= max) {					\
                csio_##name = val;					\
                return 0;						\
        }								\
									\
	printk(KERN_ERR KBUILD_MODNAME": csio_"#name" cannot be set to %d, "\
			  "Setting to default of "#def"\n", val);	\
        csio_##name = def;						\
        return -EINVAL;							\
}

#define CSIO_MODULE_PARAM(name, def, min, max, desc, typ)		\
module_param(csio_##name, typ, S_IRUGO|S_IWUSR);			\
MODULE_PARM_DESC(csio_##name, desc);					\
csio_param_check(name, def, min, max, typ)

#define CSIO_DEVICE(devid, idx) 				\
{ PCI_VENDOR_ID_CHELSIO, (devid), PCI_ANY_ID, PCI_ANY_ID, 0, 0, (idx) }

struct csio_alloc_desc {
	int	alloc_size;		/* Size of the allocation */	
	int	idx;			/* Index into alloc list */
};

extern struct fc_function_template csio_fc_transport_funcs;
extern struct fc_function_template csio_fc_transport_vport_funcs;

void csio_rnf_reg_rnode(struct csio_rnode *rn);
void csio_rnf_unreg_rnode(struct csio_rnode *rn);
void csio_rnf_async_event(struct csio_rnode *rn, csio_rn_os_evt_t os_evt);
void csio_lnf_async_event(struct csio_lnode *ln, csio_ln_os_evt_t os_evt);

void csio_fchost_attr_init(struct csio_os_lnode *);

/* IOCTL handlers */
int csio_os_create_npiv_vport(struct csio_hw *hw, void *buffer,int len);
int csio_os_delete_npiv_vport(struct csio_hw *hw, void *buffer,int len);
int csio_os_list_npiv_vport(struct csio_hw *hw, void *buffer,int len);

void csio_os_abort_cls(struct csio_ioreq *, void *);

/* INTx handlers */
void csio_os_scsi_intx_handler(struct csio_hw *, void *, uint32_t,
			       struct csio_fl_dma_buf *, void *);

void csio_os_fwevt_intx_handler(struct csio_hw *, void *, uint32_t,
				struct csio_fl_dma_buf *, void *);

/* Common os lnode APIs */
void csio_oslnodes_block_request(struct csio_os_hw *oshw);
void csio_oslnodes_unblock_request(struct csio_os_hw *oshw);
void csio_oslnodes_block_by_port(struct csio_os_hw *oshw, uint8_t portid);
void csio_oslnodes_unblock_by_port(struct csio_os_hw *oshw, uint8_t portid);

struct csio_os_lnode *csio_oslnode_init(struct csio_os_hw *, 
					struct device *, bool,
					struct csio_os_lnode *);
void csio_oslnode_exit(struct csio_os_lnode *);
void csio_oslnodes_exit(struct csio_os_hw *, bool);

#endif /* ifndef __CIOS_OS_INIT_H__ */
