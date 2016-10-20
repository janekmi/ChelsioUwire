/*
 * Copyright (C) 2008-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description:
 *
 */

#ifndef __CSIO_IBFT_H__
#define __CSIO_IBFT_H__

#include <csio_defs.h>
#include <csio_hw.h>

#define IBFT_SIGN_LEN 4
#ifndef CONFIG_ISCSI_IBFT_FIND
#define IBFT_START 0x80000 /* 512kB */
#define IBFT_END 0x100000 /* 1MB */
#define VGA_MEM 0xA0000 /* VGA buffer */
#define VGA_SIZE 0x20000 /* 128kB */
#endif

#define IBFT_REVISION 1
#define ISCSI_CONTROL_REQ_MAX_BUFLEN 512
#define IBFT_BLOCK_FLAG_VALID 0x1
#define IBFT_BLOCK_FLAG_FW_BOOT_SEL 0x2
#define IBFT_TARGET_CHAP_NONE    0
#define IBFT_TARGET_CHAP_ONEWAY  1
#define IBFT_TARGET_CHAP_MUTUAL  2

void csio_foiscsi_ibft_login(struct csio_foiscsi_devinst *foiscsi_inst);

#ifndef CONFIG_ISCSI_IBFT_FIND
#ifdef EFI_BOOT
#define csio_efi_enabled efi_enabled(EFI_BOOT)
#else
#define csio_efi_enabled efi_enabled
#endif
#endif /* !defined(CONFIG_ISCSI_IBFT_FIND) */

#ifndef CONFIG_ACPI
struct csio_name {
	char ascii[4];
};
#endif
#endif /* ifndef __CSIO_LNODE_FOISCSI_H__ */
