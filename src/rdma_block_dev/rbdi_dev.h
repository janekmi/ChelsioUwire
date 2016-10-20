/*
 * Copyright (c) 2015 Chelsio Communications, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *	copyright notice, this list of conditions and the following
 *	disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *	copyright notice, this list of conditions and the following
 *	disclaimer in the documentation and/or other materials
 *	provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef __RBDI_DEV_H__
#define __RBDI_DEV_H__

#ifndef _KERNEL_
#include <stdint.h>
#define __u8 uint8_t
#define u8 uint8_t
#define __u16 uint16_t
#define __be16 uint16_t
#define u16 uint16_t
#define __u32 uint32_t
#define __be32 uint32_t
#define u32 uint32_t
#define __u64 uint64_t
#define __be64 uint64_t
#define u64 uint64_t
#endif

enum {
	RBDI_DEV_HELLO,
	RBDI_DEV_ADD,
	RBDI_DEV_REM,
	RBDI_DEV_LIST,
};

enum {
	RBDI_DEV_VERSION = 1,
};

struct rbdi_dev_cmd_hdr {
	__u32 cmd;
	__u16 in;
	__u16 out;
};

struct rbdi_dev_hello_req {
#ifndef _KERNEL_
	struct rbdi_dev_cmd_hdr hdr;
#endif
	__u64 response;
	__u32 pid;
};

struct rbdi_dev_hello_rep {
	__u32 version;
	__u32 reserved;
	__u8  output[256];
};

struct rbdi_dev_add_req {
#ifndef _KERNEL_
	struct rbdi_dev_cmd_hdr hdr;
#endif
	__u64 response;
	__u32 res1;
	__u16 res2;
	__u16 port;
	__u8  addr[64];
	__u8  device[64];
};

struct rbdi_dev_add_rep {
	__u32 error_num;
	__u32 reserved;
};

struct rbdi_dev_rem_req {
#ifndef _KERNEL_
	struct rbdi_dev_cmd_hdr hdr;
#endif
	__u64 response;
	__u8  device[256];
};

struct rbdi_dev_rem_rep {
	__u32 error_num;
	__u32 reserved;
};

struct rbdi_dev_list_req {
#ifndef _KERNEL_
	struct rbdi_dev_cmd_hdr hdr;
#endif
	__u64 response;
	__u32 response_size;
};

struct rbdi_dev_list_rep {
	__u32 response_size;
	__u32 reserved;
	__u8  output[0];
};

#define RBDI_DEV_NAME "/dev/rbdi_dev"

#ifdef _KERNEL_
extern size_t rbdi_list_targets(__u64 response_buf, __u32 response_size);
extern int rbdi_dev_init(void);
extern void rbdi_dev_cleanup(void);
extern int rbdi_add_target(__u8 *addrstr, __u16 port, __u8 *device);
extern int rbdi_remove_device(__u8 *device);
#endif
#endif
