/*
 * Copyright (c) 2015 Chelsio Corporation.  All rights reserved.
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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>
#include <getopt.h>
#include <fcntl.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "../rbdi_dev.h"

#define INIT_REQ(req, req_size, op)		\
do {						\
	memset(req, 0, req_size);		\
	(req)->hdr.cmd = RBDI_DEV_##op;		\
	(req)->hdr.in  = req_size - sizeof (req)->hdr;   \
} while (0)

#define INIT_REQ_REP(req, req_size, op, rep, rep_size) \
do {						\
	INIT_REQ(req, req_size, op);	        \
	(req)->hdr.out = rep_size;		\
	(req)->response = (uintptr_t) (rep);	\
} while (0)

static void usage(const char *argv0)
{
	printf("Usage:\n");
	printf("  %s -l\n", argv0);
	printf("  %s -n -a <addr> -d <target device> [-p <port number>]\n", argv0);
	printf("  %s -r -d <initiator device>\n", argv0);
	printf("Options:\n");
	printf("  -l, --list                       List connected targets\n");
	printf("  -n, --new                        Add a new target device\n");
	printf("  -r, --rem                        Remove a target device\n");
	printf("  -a, --addr <hostname|address>    Target Node RDMA Address\n");
	printf("  -p, --port <port number>         Target Node IP port number (default 65000)\n");
	printf("  -d, --dev <device>               Target device name to attach or Initiator device name to detach\n");
	printf("  -h, --help                       Display his help message\n");
	printf("\nEG:\n");
	printf("  %s -n -a 192.168.1.112 -d /dev/nvme0n1\n", argv0);
	printf("  %s -r -d /dev/rbdi0\n", argv0);
}

static int list_tgts(int fd)
{
	struct rbdi_dev_list_req req;
	struct rbdi_dev_list_rep rep, *repp;
	int response_size;
	int ret;

	INIT_REQ_REP(&req, sizeof req, LIST, &rep, sizeof rep);

	req.response_size = 0;
	ret = write(fd, &req, sizeof req);
	if (ret != sizeof req) {
		fprintf(stderr, "%s returned errno %d in error\n", RBDI_DEV_NAME, errno);
		return -1;
	}
	response_size = sizeof rep + rep.response_size;
	repp = (struct rbdi_dev_list_rep *)malloc(response_size);
	if (!repp) {
		perror("malloc");
		return -1;
	}
	memset(repp, 0, response_size);
	INIT_REQ_REP(&req, sizeof req, LIST, repp, response_size);
	req.response_size = rep.response_size;
	ret = write(fd, &req, sizeof req);
	if (ret != sizeof req) {
		fprintf(stderr, "%s returned errno %d in error\n", RBDI_DEV_NAME, errno);
		return -1;
	}
	if (rep.response_size < 0)
		fprintf(stderr, "warning: output truncated!\n");
	printf("%s", (char *)&repp->output);

	return 0;
}

static int get_dst_addr(const char *dst, u16 port, struct sockaddr_in *sin)
{
	struct addrinfo *res, hints = {0};
	int ret;

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	ret = getaddrinfo(dst, NULL, &hints, &res);
	if (ret) {
		perror("getaddrinfo");
		return -1;
	}
	if (res->ai_family == PF_INET) {
		memcpy(&sin->sin_addr, &((struct sockaddr_in*)res->ai_addr)->sin_addr, 4);
		sin->sin_family = PF_INET;
		sin->sin_port = htons(port);
	} else 
		return -1;

	freeaddrinfo(res);
	return 0;
}

static int remove_device(int fd, char *devname)
{
	struct rbdi_dev_rem_req req;
	struct rbdi_dev_rem_rep rep;
	int ret;

	INIT_REQ_REP(&req, sizeof req, REM, &rep, sizeof rep);
	if (strlen(devname) > (sizeof req.device - 1)) {
		fprintf(stderr, "device name %s too big.  Must be < 255 characters\n", devname);
		return -1;
	}
	memcpy(req.device, devname, strlen(devname));
	ret = write(fd, &req, sizeof req);
	if (ret != sizeof req) {
		fprintf(stderr, "%s returned errno %d in error\n", RBDI_DEV_NAME, errno);
		return -1;
	}
	if (rep.error_num) {
		fprintf(stderr, "%s returned an error adding device %s: %d\n", RBDI_DEV_NAME, devname, rep.error_num);
		return -1;
	}
	return 0;
}

static int add_device(int fd, char *addr, u16 port, char *devname)
{
	struct rbdi_dev_add_req req;
	struct rbdi_dev_add_rep rep;
	int ret;

	INIT_REQ_REP(&req, sizeof req, ADD, &rep, sizeof rep);

	req.port = port;
	if (strlen(addr) > (sizeof req.addr - 1)) {
		fprintf(stderr, "address %s too big.  Must be < %lu characters\n", devname, sizeof req.addr);
		return -1;
	}
	memcpy(req.addr, addr, strlen(addr));

	if (strlen(devname) > (sizeof req.device - 1)) {
		fprintf(stderr, "device name %s too big.  Must be < %lu characters\n", devname, sizeof req.device);
		return -1;
	}
	memcpy(req.device, devname, strlen(devname));
	ret = write(fd, &req, sizeof req);
	if (ret != sizeof req) {
		fprintf(stderr, "%s returned errno %d in error\n", RBDI_DEV_NAME, errno);
		return -1;
	}
	if (rep.error_num) {
		fprintf(stderr, "%s returned an error adding device %s: %d\n", RBDI_DEV_NAME, devname, rep.error_num);
		return -1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	struct rbdi_dev_hello_req req;
	struct rbdi_dev_hello_rep rep;
	static struct option long_options[] = {
		{ .name = "list", .has_arg = 0, .val = 'l' },
		{ .name = "new", .has_arg = 0, .val = 'n' },
		{ .name = "remove", .has_arg = 0, .val = 'r' },
		{ .name = "addr", .has_arg = 1, .val = 'a' },
		{ .name = "dev", .has_arg = 1, .val = 'd' },
		{ .name = "port", .has_arg = 1, .val = 'p' },
		{ .name = "help", .has_arg = 0, .val = 'h' },
		{ 0 }
	};
	struct sockaddr_in server_sin = {0};
	char *servername = NULL;
	char *devname = NULL;
	u16 port = 65000;
	int new = 0;
	int remove = 0;
	int list = 0;
	int fd;
	int ret;
	int c;

	fd = open(RBDI_DEV_NAME, O_RDWR);
	if (fd < 0) {
		perror("opening rbdi_dev");
		return -1;
	}

	INIT_REQ_REP(&req, sizeof req, HELLO, &rep, sizeof rep);
	req.pid = (__u32)getpid();
	ret = write(fd, &req, sizeof req);
	if (ret != sizeof req) {
		fprintf(stderr, "%s returned %d in error\n", RBDI_DEV_NAME, ret);
		return -1;
	}
	if (rep.version != RBDI_DEV_VERSION) {
		fprintf(stderr, "%s version mismatch! kernel %d user %d\n", RBDI_DEV_NAME, rep.version, RBDI_DEV_VERSION);
		return -1;
	}

	if (argc < 2) {
		usage(argv[0]);
		return -1;
	}
	while (1) {
		c = getopt_long(argc, argv, "hlnra:d:p:", long_options, NULL);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'l':
			list = 1;
			break;
		case 'n':
			new = 1;
			break;
		case 'r':
			remove = 1;
			break;
		case 'p': {
			long l = strtol(optarg, NULL, 0);
			if (l < 0 || l > 65535) {
				fprintf(stderr, "Invalid port number %ld\n", l);
				return 1;
			}
			port = l;
			break;
		}
		case 'd':
			devname = optarg;
			break;
		case 'a':
			servername = optarg;
			break;
		default:
			return -1;
		}
	}
	if (!new && !remove && !list) {
		fprintf(stderr, "You must specify one of: -l, -n or -r\n");
		return -1;
	}
	if ((new + remove + list) > 1) {
		fprintf(stderr, "You must specify only one of: -l, -n or -r\n");
		return -1;
	}
	if (list) {
		ret = list_tgts(fd);
	} else if (new) {
		char p[64];

		if (!servername) {
			fprintf(stderr, "You must specify a server name!\n");
			return -1;
		}
		if (!devname) {
			fprintf(stderr, "You must specify a device name!\n");
			return -1;
		}
		if (get_dst_addr(servername, port, &server_sin)) {
			fprintf(stderr, "Cannot resolve %s to an IPv4 address\n", servername);
			return -1;
		}
		inet_ntop(AF_INET, &server_sin.sin_addr.s_addr, p, sizeof p);
		ret = add_device(fd, p, port, devname);
		
	} else {
		ret = remove_device(fd, devname);
	}
	if (ret)
		fprintf(stderr, "Command failed\n");
	return ret;
}
