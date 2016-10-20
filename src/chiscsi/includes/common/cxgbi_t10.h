/*
 * cxgbi_pi.h: Chelsio common library for iSCSI T10 operation 
 *
 * Copyright (c) 2015 Chelsio Communications, Inc. All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Written by: Karen Xie (kxie@chelsio.com)
 */

#ifndef	__CXGBIT10_H__
#define	__CXGBIT10_H__

/* pdu t10dif information */
enum iscsi_scsi_prot_op {
	ISCSI_PI_OP_SCSI_PROT_NORMAL = 0,

	ISCSI_PI_OP_SCSI_PROT_READ_INSERT,
	ISCSI_PI_OP_SCSI_PROT_WRITE_STRIP,

	ISCSI_PI_OP_SCSI_PROT_READ_STRIP,
	ISCSI_PI_OP_SCSI_PROT_WRITE_INSERT,

	ISCSI_PI_OP_SCSI_PROT_READ_PASS,
	ISCSI_PI_OP_SCSI_PROT_WRITE_PASS,

};
enum iscsi_scsi_pi_interval {
	ISCSI_SCSI_PI_INTERVAL_512 = 0,
	ISCSI_SCSI_PI_INTERVAL_4K,
};

enum pi_guard_type {
	ISCSI_PI_GUARD_TYPE_IP = 0,
	ISCSI_PI_GUARD_TYPE_CRC
};

enum pi_dif_type {
	ISCSI_PI_DIF_TYPE_0 = 0,
	ISCSI_PI_DIF_TYPE_1,
	ISCSI_PI_DIF_TYPE_2,
	ISCSI_PI_DIF_TYPE_3
};

struct cxgbi_pdu_pi_info {
	unsigned char	prot_op:3,
			guard:1,
			interval:1,
			offset_updated:1,
			dif_type:2;
	unsigned char	pi_sgcnt;
	unsigned short	pi_len;
	unsigned short	pi_offset;
	unsigned short	app_tag;
	unsigned int	ref_tag;
};

#endif
