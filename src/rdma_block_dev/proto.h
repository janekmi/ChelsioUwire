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
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
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
#ifndef _PROTO_H
#define _PROTO_H

#include <linux/types.h>

enum rbdp_flags {
	RBDP_IMMD = 	1, /* payload in request or reply message */
};

struct rbdp_sge {
	__u64 to;
	__u32 stag;
	__u32 len;
};

struct rbdp_request {
	__u32 xid;
	__u32 cmd;
	__u32 flags;
	__u32 num_sge;
	__u32 start_sector;
	__u32 tot_len;
	struct rbdp_sge sgl[0];
};

struct rbdp_reply {
	__u32 xid;
	__u32 flags;
	__u32 status;
	__u32 pad;
};

union rbdp_reqrep {
	struct rbdp_request req;
	struct rbdp_reply rep;
};

enum {
	RBDP_VERSION = 4,
	RBDP_MAX_REQUESTS = 256,
	RBDP_BUFSZ = (2*1024),
	RBDP_MAX_IMMD = (RBDP_BUFSZ - sizeof(union rbdp_reqrep)),
	RBDP_CMD_WRITE = 0,
	RBDP_CMD_READ = 1,
	RBDP_MAX_IO_SIZE = (32*PAGE_SIZE), /* XXX must be < max fastreg size */
	RBDP_MAX_READ_DEPTH = 32,
	RBDP_DEVLEN = 32,
	RBDP_ADDRLEN = 64,
};

#ifdef notyet
#define RBDP_MAX_SGES ((RBDP_BUFSZ - sizeof(struct rbdp_request)) / \
		      sizeof(struct rbdp_sge))
#else
#define RBDP_MAX_SGES 1
#endif

#define RBDP_MAX_FR_DEPTH (RBDP_MAX_IO_SIZE / PAGE_SIZE)

struct rbdp_connect_data {
	__u32 version;
	__u32 max_requests;
	__u32 max_io_size;
	__u32 max_read_depth;
	__u32 max_sges;
	__u8 dev[RBDP_DEVLEN];
};

struct rbdp_accept_data {
	__u64 start_sec;
	__u64 sectors;
	__u32 sec_size;
	__u32 max_io_size;
	__u32 max_sges;
};

#endif /* _PROTO_H */
