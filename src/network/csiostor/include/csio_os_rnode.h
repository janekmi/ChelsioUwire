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

#ifndef __CSIO_OS_RNODE_H
#define __CSIO_OS_RNODE_H

#include <csio_rnode.h>
#ifdef __CSIO_FOISCSI_ENABLED__
#include <foiscsi_transport.h>
#endif

struct csio_os_rnode {
	struct csio_rnode	rnode;		/* Common rnode */

	/* FC transport attributes */
	struct fc_rport 	*rport;		/* FC transport rport */
	uint32_t		supp_classes;	/* Supported FC classes */ 
	uint32_t		maxframe_size;	/* Max Frame size */ 
	uint32_t		scsi_id;	/* Transport given SCSI id */

#ifdef __CSIO_FOISCSI_ENABLED__
	/* foiscsi session objects */
	struct foiscsi_cls_session *rsess;
#endif
};

#endif /* ifndef __CSIO_OS_RNODE_H */
