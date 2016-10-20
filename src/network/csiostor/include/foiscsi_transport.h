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

#ifndef __FOISCSI_TRANSPORT_H__
#define __FOISCSI_TRANSPORT_H__

struct foiscsi_cls_session {
	void			*osrn;
	struct scsi_target      *starget;
	struct device           dev;            /*  dev for iscsi session */
	csio_work_t		foiscsi_block;
	csio_work_t		foiscsi_unblock;
	csio_work_t		foiscsi_scan;
	csio_work_t		foiscsi_cleanup;
};

#endif /* ifndef __FOISCSI_TRANSPORT_H___ */
