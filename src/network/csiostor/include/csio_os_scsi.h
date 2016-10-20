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

#ifndef __CSIO_OS_SCSI_H__
#define __CSIO_OS_SCSI_H__

#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_eh.h>
#include <scsi/scsi_tcq.h>

extern struct scsi_host_template csio_fcoe_shost_template;
extern struct scsi_host_template csio_fcoe_shost_vport_template;
extern struct scsi_host_template csio_iscsi_shost_template;

#endif /* ifndef __CSIO_OS_SCSI_H__ */
