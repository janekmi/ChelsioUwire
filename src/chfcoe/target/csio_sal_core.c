/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: This file defines unified sal layer which provides api required
 * for upper SCSI Target stack to interface with Chelsio fcoe/iscsi interface
 * driver. This also provides interface for lower chelsio interface driver to 
 * register its proto handlers with unified sal layer.
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <csio_sal_api.h>

csio_sal_ops_t *sal_ops_tbl[CSIO_SAL_PROT_MAX];

csio_sal_ops_t *csio_sal_get_sops(csio_sal_prot_t proto)
{
	if (proto > CSIO_SAL_PROT_MAX) {
		return NULL;
	}

	if (!sal_ops_tbl[proto])
		return NULL;

	return sal_ops_tbl[proto];
}

csio_sal_ops_t *csio_sal_register_proto(csio_proto_ops_t *proto_ops, 
		csio_sal_prot_t proto)
{
	csio_sal_ops_t *sops;
	if (proto > CSIO_SAL_PROT_MAX) {
		return NULL;
	}	

	if (!sal_ops_tbl[proto])
		return NULL;

	sops = sal_ops_tbl[proto];
	sops->proto_ops = proto_ops;
	return sops;
}

void csio_sal_unregister_proto(csio_sal_prot_t proto)
{
	csio_sal_ops_t *sops;
	if (proto > CSIO_SAL_PROT_MAX) {
		return;
	}	

	if (!sal_ops_tbl[proto])
		return;

	sops = sal_ops_tbl[proto];
	sops->proto_ops = NULL;
}

csio_tret_t csio_sal_init(csio_sal_ops_t *sops)
{
	csio_sal_prot_t proto = sops->proto;
	if (proto > CSIO_SAL_PROT_MAX) {
		return CSIO_TINVAL;
	}	

	if (sal_ops_tbl[proto])
		return CSIO_TDUP;

	sal_ops_tbl[proto] = sops;
	printk(KERN_DEBUG "sal init proto:%d\n", proto);
	return CSIO_TSUCCESS;
}

void csio_sal_exit(csio_sal_ops_t *sops)
{
	csio_sal_prot_t proto = sops->proto;
	if (proto > CSIO_SAL_PROT_MAX) {
		return;
	}	

	sal_ops_tbl[proto] = NULL;
	printk(KERN_DEBUG "sal exit proto:%d\n", proto);
}
