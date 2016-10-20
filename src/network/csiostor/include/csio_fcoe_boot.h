/******************************************************************************
 *
 *  Copyright (C) 2008-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Module Name:
 *
 *    csio_fcoe_boot.h
 *
 * Abstract:
 *
 *    csio_fcoe_boot.h -  contains the data types and data-structures of FCoE
 *			  Boot information.
 *
 * Revision History:
 *
 *	Mahendra Boopathy - 09-Aug-11 -	Creation
 *
 * NOTE:
 *	Any changes to this file needs to be reviewed by both FCoE and Boot
 *	team.
 *
 *****************************************************************************/

#ifndef __CSIO_FCOE_BOOT_H__
#define __CSIO_FCOE_BOOT_H__

#define CBFE_SIG		"CBFE"

#define MAX_OS_FCOE_DEVICES     1
#define MAX_OS_FCOE_ADAPTERS    128

#define OPTROM_FLASH_BYTE_ORDER	0

#pragma pack(1)
typedef struct
{
	uint8_t Signature[4];

	uint32_t BootVersion;

	/* PCI bus:dev:fn */
	uint16_t PCIBusDevFunc;

	uint8_t BootValidFlag;

	/* Reserved */
	uint8_t Resvd[245];
}CBFEHead, fcoe_boot_info_hdr_t;	// 256 bytes

typedef struct
{
	/* Initiator WWPN */
	uint8_t InitiatorWWPN[8];

	uint32_t PortNumber:  8;
	uint32_t NPortId   : 24;

	/* Target WWPN */
	uint8_t TargetWWPN[8];

	/* Target LUN */
	uint8_t TargetLun[8];

	/* OS Bus/Target/Lun Info */
	uint32_t OSBusId    : 8;
	uint32_t OSTargetId : 8;
	uint32_t OSLunId    : 8;
	uint32_t OSRsvd     : 8;

} BootDeviceInfo, fcoe_boot_dev_info_t; // 32 bytes

typedef struct
{
	CBFEHead	Hdr;
	BootDeviceInfo	BootDevice[MAX_OS_FCOE_DEVICES];
} CBFEStruct;

#pragma pack()

#endif //__CSIO_FCOE_BOOT_H__
