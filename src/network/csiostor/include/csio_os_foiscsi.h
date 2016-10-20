/******************************************************************************
 *
 *  Copyright (C) 2008-2014 Chelsio Communications.  All rights reserved.
 *
 *   THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
 *   KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 *   IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
 *   PURPOSE.
 *
 * Module Name:
 *
 *    csio_os_foiscsi.h
 *
 * Abstract:
 *
 *    csio_os_foiscsi.h -  contains the data types and data-structures that are
 *			specific to iSCSI transport protocol.
 *
 * Environment:
 *
 *    Kernel mode
 *
 * Revision History:
 *
 *	Swati - Dec-2010 - ISCSI Specific macros and structure.
 *
 *****************************************************************************/


#ifndef __CSIO_OS_FOISCSI_H__
#define __CSIO_OS_FOISCSI_H__

#include <csio_lnode_foiscsi.h>
#include <csio_rnode_foiscsi.h>
#include <csio_trans_foiscsi.h>
#include <linux/module.h>

/* 32 entries * 64 bytes per entry*/
#define CSIO_ISCSI_OFLDQ_SZ                     2048

#define CSIO_ISCSI_Q_NUM                	((CSIO_MAX_SCSI_QSETS * 2) + \
	  CSIO_HW_NEQ + CSIO_HW_NIQ + \
	  CSIO_HW_NFLQ + CSIO_HW_NINTXQ)

/* No of FL buffers in the fw event Q */
#define CSIO_ISCSI_FWQ_FLLEN    64

struct csio_os_foiscsi_iface {
	struct csio_foiscsi_iface	*iface;
	struct mutex			mlock;
};

struct csio_host {
	struct scsi_Host  *shost;
};

struct os_iscsi_node {
	struct csio_host   csio_host[CSIO_MAX_T4PORTS];
};

/*
 * ISCSI Login Types
 */
enum {
	ISCSI_LOGIN_TYPE_BOOT,
	ISCSI_LOGIN_TYPE_WMI,
	ISCSI_LOGIN_TYPE_IOCTL,
	ISCSI_LOGIN_TYPE_PERSISTENT,
};

void __foiscsi_unblock_session(void *);
void __foiscsi_block_session(void *);
void foiscsi_scan_session(void *);
void foiscsi_session_cleanup(void *);

int csio_iscsi_scan_finished(struct Scsi_Host *, unsigned long);
int csio_iscsi_session_chkready(struct csio_rnode *);
int csio_iscsi_send_logout(struct csio_hw *, struct csio_rnode *);



#endif /* __CSIO_OS_FOISCSI_H__ */

