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

#ifndef __CSIO_OS_LNODE_H__
#define __CSIO_OS_LNODE_H__

#include <csio_lnode.h>

extern struct device_attribute *csio_lnode_attrs[];

/* Lnode */
struct csio_os_lnode {
	struct csio_lnode 	lnode;			/* Common Lnode */

	/* FC transport data */
	struct fc_vport 	*fc_vport;
};
 
#endif /* ifndef __CSIO_OS_LNODE_H__ */
