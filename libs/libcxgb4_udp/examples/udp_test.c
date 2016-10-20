/*
 * Copyright (c) 2010-2015 Chelsio Communications. All rights reserved.
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <malloc.h>
#include <getopt.h>
#include <signal.h>
#include <assert.h>
#include <sys/mman.h>

#include <chelsio/cxgb4_udp.h>

#include "crc.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) < (b) ? (b) : (a))

enum {
	COAL = 20,
	SQ_DEPTH = COAL * 4,
	RQ_DEPTH = 1000,
	BUFSZ = 4096,
	MAX_QPS = 64,
};

static int bufsz;

/*
 * Max IO size computations need to account for:
 * 2B  reserved at the front of a recv buffer
 * 42B eth/ip/udp headers
 * 64B reserved at the front of send bufs for UDP_SEND_HDR_ROOM.
 */
#define MAX_IO_SIZE (9000 - 2 - 14 - 20 - 8 - 64)
#define MAX_PAGE_IO_SIZE (BUFSZ - 2 - 14 - 20 - 8 - 64)

static struct timespec start_time, stop_time, interval_time, last_interval;
static int iters = -1;
static int verbose = 0;

#define LOG(fmt, args...) do { if (verbose) printf(fmt, ##args); fflush(stdout); } while (0)

#define SEC_TO_NANO(n) ((n) * 1000000000)
#define SEC_TO_MICRO(n) ((n) * 1000000)
#define NANO_TO_MICRO(n) (((n) + 500) / 1000)

#define TIME_DIFF_in_MICRO(start, end) \
	(SEC_TO_MICRO((end).tv_sec - (start).tv_sec) + \
	 (NANO_TO_MICRO((end).tv_nsec - (start).tv_nsec)))

#define TIME_DIFF_in_NANO(start,end) \
	(SEC_TO_NANO((end).tv_sec-(start).tv_sec) + \
	 ((end).tv_nsec-(start).tv_nsec))

#define TIME_DIFF_in_SEC(start,end) \
	(double)TIME_DIFF_in_NANO(start,end)/1000000000

static double calc_rtt()
{
	double rtt = 0.0;
	rtt = TIME_DIFF_in_MICRO(start_time, stop_time);
	return rtt / iters;
}

#define SAMPLES 4096
#define SKIP 1024

enum {
	POLL,
	SEND,
	RECV,
	PROD_POLL,
	RTT,
	LAST
};

static void usage(const char *argv0)
{
	printf("Usage:\n");
	printf("  %s [options] <laddr>         start a server on <laddr>\n", argv0);
	printf("  %s [options] <laddr> <raddr> start a client on <laddr> to server at <raddr>\n", argv0);
	printf("\n");
	printf("Options:\n");
	printf("  -t, --test=rr|stream   run request/response or streaming test (default is rr)\n");
	printf("  -p, --port=<port>      listen on/connect to port <port> (default 9999)\n");
	printf("  -s, --size=<size>      size of message to exchange (default 1)\n");
	printf("  -b, --block    	 Block for completions (default is polling)\n");
	printf("  -i, --iters=<count>  	 Run test for <count> iterations (default is 1000)\n");
	printf("  -T, --time=<count>  	 Run test for <count> seconds (default is 1000 iterations)\n");
	printf("  -I, --inline    	 use UDP_SEND_INLINE if possible.\n");
	printf("  -v, --verbose    	 be verbose.\n");
	printf("  -V, --vlan=vid    	 Use vlan id vid\n");
	printf("  -a, --any		 Bind to the 'unspecified' address\n");
	printf("  -m, --mapped=v4addr	 Support v4 mapped ipv6 mode using this v4 address (forces -a)\n");
	printf("  -P, --packedmode	 Use packed rx buffers\n");
	printf("  -q, --qps=count	 Create <count> UDP streams (max %d)\n", MAX_QPS);
	printf("  -S, --srq		 Use a srq for all udp qps (required for >1 qp tests)\n");
	printf("  -d, --data-verify	 Verify packets using a CRC\n");
}

enum {
	RR,
	STREAM,
};

#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000
#endif

/*
 * XXX these should be gleaned from the OS.
 * Also, HUGE_PAGE_SIZE must be a multiple of HUGE_BUF_SIZE to avoid
 * buffers that span huge pages.
 */
#define HUGE_PAGE_SIZE (2 * 1024 * 1024)
#define HUGE_BUF_SIZE (16384)
#define HUGE_BUFS_PER_PAGE (HUGE_PAGE_SIZE / HUGE_BUF_SIZE)

static uint8_t *alloc_huge_pages(int size)
{
	void *p;

	LOG("Allocating %uKB from the huge pool.\n", size/1024);

	p = mmap(0x0UL, size, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, 0, 0);
	if (p == MAP_FAILED) {
		perror("mmap(MAP_HUGETLB)");
		return NULL;
	}
	return p;
}


struct ctx {
	struct udp_qp *qp;
	unsigned long long count;
	unsigned long long scnt;
	unsigned long long pcnt;
	unsigned long long rcnt;
	unsigned long long ccnt;
	struct sockaddr_in peer;
	struct sockaddr_in6 peer6;
	struct sockaddr *peer_sa;
	struct ibv_sge ssge[SQ_DEPTH];
	struct udp_send_wr send_wr[SQ_DEPTH];
};

static struct ctx ctx[MAX_QPS];
static int socks[MAX_QPS];
static struct udp_dev *dev;
static int ret;
static struct ibv_cq *scq, *rcq;
static int addrlen;
static int family;
struct sockaddr *sa, *peer_sa;
static struct sockaddr_in sin, peer;
static struct sockaddr_in6 sin6, peer6;
static struct ibv_mr *rmr, *smr;
static uint8_t *rbuf, *sbuf, *sbp, *rbp;
static struct ibv_sge rsge;
static struct udp_recv_wr recv_wr;
static struct ibv_wc wc, swc;
static struct ibv_comp_channel *ch = NULL;
static int client = 0;
static int size = 1;
static int block = 0;
static int ind;
static unsigned short vlan = 0xfff;
static int test = RR;
static int use_inline = 0;
static int runtime = -1;
static int packed;
static int qpcount = 1;
static int use_srq;
static struct udp_srq *srq;
static int verification;
static unsigned int seed;

static struct option long_options[] = {
	{ .name = "laddr",          .has_arg = 1, .val = 'l' },
	{ .name = "port",           .has_arg = 1, .val = 'p' },
	{ .name = "size",           .has_arg = 1, .val = 's' },
	{ .name = "block", 	    .has_arg = 0, .val = 'b' },
	{ .name = "iters",          .has_arg = 1, .val = 'i' },
	{ .name = "time",           .has_arg = 1, .val = 'T' },
	{ .name = "verbose",        .has_arg = 0, .val = 'v' },
	{ .name = "vlan",           .has_arg = 1, .val = 'V' },
	{ .name = "test",           .has_arg = 1, .val = 't' },
	{ .name = "inline",         .has_arg = 0, .val = 'I' },
	{ .name = "any",            .has_arg = 0, .val = 'a' },
	{ .name = "mapped",         .has_arg = 1, .val = 'm' },
	{ .name = "packedmode",     .has_arg = 0, .val = 'P' },
	{ .name = "qps",     	    .has_arg = 1, .val = 'q' },
	{ .name = "srq",     	    .has_arg = 0, .val = 'S' },
	{ .name = "data-verify",    .has_arg = 0, .val = 'd' },
	{ 0 }
};

static int stream_done;

static void dump_buf(unsigned char *b, int size)
{
	int i = 0, j;
	int len;
	int rem = size;
	
	while (i < size) {
		len = MIN(rem, 16);
		printf("%04u: ", i);
		for (j=0; j < len; j++)
			printf("%02x ", b[i+j]);	
		printf("\n");
		rem -= len;
		i += len;
	}
}

void streamc_handler(int foo)
{
	LOG("ALARM\n");
	stream_done = 1;
}

static int find_qp(int qpnum)
{
	int c;

	for (c = 0; c < qpcount; c++)
		if (ctx[c].qp->raw_qp->qp_num == qpnum)
			return c;
	printf("bad qpnum %d\n", qpnum);
	exit(1);
}

static int run_stream()
{
	unsigned long long scnt = 0, pcnt = 0, rcnt = 0;
	double t;
	int i;
	int c;

	if (client) {

		if (runtime > 0) {
			signal(SIGALRM, streamc_handler);
			alarm(runtime);
		}
		clock_gettime(CLOCK_REALTIME, &start_time);
		last_interval = start_time;
		while (!stream_done) {
			for (c = 0; c < qpcount; c++) {
				if (iters > 0 && ctx[c].scnt >= iters) {
					stream_done = 1;
					break;
				}
				while ((ctx[c].scnt - ctx[c].ccnt) < SQ_DEPTH) {
					int j;

					i = MIN(COAL, SQ_DEPTH - ctx[c].scnt + ctx[c].ccnt);
					assert(i == COAL);
					if (verification)
						for (j = 0; j < i; j++)
							randomize_buf((unsigned char *)(uintptr_t)ctx[c].ssge[(ctx[c].scnt % SQ_DEPTH) + j].addr, size, &seed);
					ret = udp_post_send_many(ctx[c].qp, &ctx[c].send_wr[ctx[c].scnt % SQ_DEPTH], i);
					if (ret) {
						printf("udp_post_send failed: %s\n",
						       strerror(ret));
						return ret;
					}
					ctx[c].scnt += i;
					ctx[c].pcnt += i;
				}
			}
			if (stream_done)
				break;

			do {
				ret = udp_poll_cq(scq, &swc, NULL, 0);
			} while (ret == ENODATA);
			if (ret) {
				printf("poll error %d\n", ret);
				return ret;
			}
			if (swc.status != 0) {
				printf("Send completion error status %d\n",
				       swc.status);
				return EIO;
			}
			ctx[swc.wr_id].ccnt += COAL;

			if (verbose) {
				clock_gettime(CLOCK_REALTIME, &interval_time);
				t = TIME_DIFF_in_SEC(last_interval, interval_time);
				if (t > 10) {
					for (i = 0; i < qpcount; i ++) {
						printf("Elapsed time: %.3f seconds, conn %d: pkt cnt %llu MIOPS: %.3f Througput %.3f Gbps scnt %llu\n", t, i, ctx[i].pcnt, (double)ctx[i].pcnt / t / 1000000, (double)ctx[i].pcnt * (double)size * 8 / 1000000000 / t, ctx[i].scnt);
						ctx[i].pcnt = 0;
					}
					last_interval = interval_time;
				}
			}
		}
		clock_gettime(CLOCK_REALTIME, &stop_time);
		t = TIME_DIFF_in_SEC(start_time, stop_time);
		scnt = 0;
		for (c = 0; c < qpcount; c++) {
			scnt += ctx[c].scnt;
		}
		printf("Elapsed time: %.3f seconds, pkt cnt %llu MIOPS: %.3f Througput %.3f Gbps\n", t, scnt, (double)scnt / t / 1000000, (double)scnt * (double)size * 8 / 1000000000 / t);
	} else {
		struct ibv_wc prev = prev;
		
		clock_gettime(CLOCK_REALTIME, &start_time);
		last_interval = start_time;
		prev.status = -1;
		while (1) {
			int hdr_len = 2 + 14 + (addrlen == 4 ? 20 : 40) + 8;

			if (verbose) {
				clock_gettime(CLOCK_REALTIME, &interval_time);
				t = TIME_DIFF_in_SEC(last_interval, interval_time);
				if (t > 10) {
					printf("Elapsed time: %.3f seconds, pkt cnt %llu MIOPS: %.3f Througput %.3f Gbps, rcnt %llu\n", t, pcnt, (double)pcnt / t / 1000000, (double)pcnt * (double)size * 8 / 1000000000 / t, rcnt);
					last_interval = interval_time;
					pcnt=0;
				}
			}
			ret = udp_poll_cq(rcq, &wc, peer_sa, 0);
			if (ret == ENODATA)
				continue;
			if (ret) {
				printf("udp_poll_cq failed: %s\n", strerror(ret));
				return ret;
			}
			if (wc.status != 0) {
				printf("Recv completion status %d\n", wc.status);
				return EIO;
			}
			rcnt++;
			pcnt++;

			if (verification && !data_valid(rbuf + wc.wr_id * bufsz + hdr_len, wc.byte_len)) {
				fprintf(stderr, "data validation error!\n");
				dump_buf(rbuf + wc.wr_id * bufsz + hdr_len, wc.byte_len);
				fflush(stderr);
				abort();
			}

			if (wc.sl && (!packed || prev.status != -1)) {
				if (packed) {
					rsge.addr = (unsigned long)(rbuf + prev.wr_id * bufsz);
					recv_wr.wr_id = prev.wr_id;
				} else {
					rsge.addr = (unsigned long)(rbuf + wc.wr_id * bufsz);
					recv_wr.wr_id = wc.wr_id;
				}
				if (use_srq)
					ret = udp_post_srq_recv(srq, &recv_wr);
				else
					ret = udp_post_recv(ctx[0].qp, &recv_wr);
				if (ret) {
					printf("udp_post_recv failed: %s\n", strerror(ret));
					return ret;
				}
			}
			prev = wc;
		}
	}

	return 0;
}

int rr_done;

void rr_handler(int foo)
{
	LOG("ALARM\n");
	rr_done = 1;
}

static int run_rr()
{
	struct ibv_wc prev = prev;
	int sumcount = 0;
	int c = 0, cq_evt;

	if (client) {
		if (runtime > 0) {
			signal(SIGALRM, rr_handler);
			alarm(runtime);
		}
		clock_gettime(CLOCK_REALTIME, &start_time);
		for (c = 0; c < qpcount; c++) {
			if (verification)
				randomize_buf((unsigned char *)(uintptr_t)ctx[c].ssge[0].addr, size, &seed);
			ret = udp_post_send(ctx[c].qp, &ctx[c].send_wr[0]);
			if (ret) {
				printf("udp_post_send failed: %s\n", strerror(ret));
				return ret;
			}
			ctx[c].count++;
			sumcount++;
		}
	}

	prev.status = -1;
	while (!rr_done || !client) {
		int hdr_len = 2 + 14 + (addrlen == 4 ? 20 : 40) + 8;

		cq_evt = 0;
		while (1) {
			ret = udp_poll_cq(scq, &swc, NULL, 0);
			if (!ret && swc.status != 0) {
				printf("Send completion error status %d\n",
				       swc.status);
				return EIO;
			}
			ret = udp_poll_cq(rcq, &wc, peer_sa, 0);
			if (!ret)
				break;
			if (ret != ENODATA) {
				printf("udp_poll_cq failed: %s\n", strerror(ret));
				return ret;
			}
			if (rr_done) {
				break;
			}
			if (!cq_evt && block && ret == ENODATA) {
				struct ibv_cq *lcq;
				void *c;

				ret = ibv_get_cq_event(ch, &lcq, &c);
				if (ret) {
					printf("ibv_get_cq_event error!\n");
					return ret;
				}
				if (lcq != rcq) {
					printf("bogus cq event for cq %p\n", lcq);
					return EINVAL;
				}
				ibv_ack_cq_events(lcq, 1);
				cq_evt = 1;
			}
		}
		if (rr_done)
			break;
		if (wc.status != 0) {
			printf("Recv completion status %d\n", wc.status);
			return EIO;
		}

		if (cq_evt && block && ibv_req_notify_cq(rcq, 0)) {
			ret = errno;
			perror("ibv_req_notify");
			return ret;
		}

		if (verification && !data_valid(rbuf + wc.wr_id * bufsz + hdr_len, wc.byte_len)) {
			fprintf(stderr, "data validation error!\n");
			dump_buf(rbuf + wc.wr_id * bufsz + hdr_len, wc.byte_len);
			fflush(stderr);
			abort();
		}

		if (!client || (sumcount != (qpcount * iters))) {
			c = find_qp(wc.qp_num);
			ctx[c].ssge[0].length = wc.byte_len;
			if (((ctx[c].count + 1) % (SQ_DEPTH>>1)) == 0)
				ctx[c].send_wr[0].send_flags |= UDP_SEND_SIGNALED;
			else
				ctx[c].send_wr[0].send_flags &= ~UDP_SEND_SIGNALED;
			if (verification)
				randomize_buf((unsigned char *)(uintptr_t)ctx[c].ssge[0].addr, wc.byte_len, &seed);
			ctx[c].send_wr[0].peer = peer_sa;
			ret = udp_post_send(ctx[c].qp, &ctx[c].send_wr[0]);
			if (ret) {
				printf("udp_post_send failed: %s qp count %lld\n", strerror(ret), ctx[wc.qp_num].count);
				return ret;
			}
		}
		if (wc.sl && (!packed || prev.status != -1)) {
			if (packed) {
				rbp = rbuf + prev.wr_id * bufsz;
				rsge.addr = (unsigned long)rbp;
				recv_wr.wr_id = prev.wr_id;
			} else {
				rbp = rbuf + wc.wr_id * bufsz;
				rsge.addr = (unsigned long)rbp;
				recv_wr.wr_id = wc.wr_id;
			}
			if (use_srq)
				ret = udp_post_srq_recv(srq, &recv_wr);
			else
				ret = udp_post_recv(ctx[c].qp, &recv_wr);
			if (ret) {
				printf("udp_post_recv failed: %s\n", strerror(ret));
				return ret;
			}
		}
		ctx[c].count++;
		sumcount++;
		if (client && iters > 0 && (iters*qpcount) == sumcount)
			break;
		prev = wc;
	}
	if (client) {
		iters = sumcount;
		clock_gettime(CLOCK_REALTIME, &stop_time);
		printf("Average RTT: %.3lf usec, RTT/2: %.3lf usec\n", calc_rtt(), calc_rtt()/2);
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int mrsize;
	int bind_to_any = 0;
	struct sockaddr_in any;
	struct sockaddr_in6 any6;
	struct sockaddr *any_sa;
	uint8_t addr[16];
	int use_mapped = 0;
	int flags = 0;
	int c;
	int i;
	uint16_t port = 9999;
	int rq_depth = RQ_DEPTH;
	struct timespec now;

	crcInit();
	memset(&any, 0, sizeof any);
	any.sin_family = AF_INET;
	memset(&any6, 0, sizeof any6);
	any6.sin6_family = AF_INET6;
	sin.sin_family = AF_INET;
	peer.sin_family = AF_INET;
	sin6.sin6_family = AF_INET6;
	peer6.sin6_family = AF_INET6;

	while (1) {
		int c;
		c = getopt_long(argc, argv, "dSq:m:aT:It:p:Ps:bi:vV:", long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'd':
			verification = 1;
			fflush(stdout);
			clock_gettime(CLOCK_REALTIME, &now);
			seed = (unsigned int)now.tv_nsec;
			break;
		case 'S': {
			use_srq = 1;
			break;
		}
		case 'q': {
			qpcount = atoi(optarg);
			if (!qpcount || qpcount > MAX_QPS) {
				printf("qp count must be > 0 and <= %d\n", MAX_QPS);
				usage(argv[0]);
				return EINVAL;
			}
			break;
		}
		case 'm': {
			if (!inet_pton(AF_INET, optarg, addr)) {
				printf("bogus mapped v4 address %s\n", optarg);
				usage(argv[0]);
				return -1;
			}
			memcpy(&sin.sin_addr.s_addr, addr, 4);
			use_mapped = 1;
			break;
		}
		case 'a':
			bind_to_any = 1;
			break;
		case 'I':
			use_inline = 1;
			break;
		case 't':
			if (!strncmp(optarg, "rr", 2)) {
				test = RR;
			} else if (!strncmp(optarg, "stream", 6)) {
				test = STREAM;
			} else {
				printf("Invalid test %s\n", optarg);
				usage(argv[0]);
				return EINVAL;
			}
			break;
		case 'P':
			flags |= UDP_PACKED_MODE;
			packed = 1;
                        printf("packed\n");
			break;
		case 'p':
			port = atoi(optarg);
			if (port == 0) {
				printf("Pick a valid port!\n");
				usage(argv[0]);
				return EINVAL;
			}
			break;
		case 's':
			size = atoi(optarg);
			if (!size || size > MAX_IO_SIZE) {
				printf("size must be > 0 and <= %d\n", MAX_IO_SIZE);
				usage(argv[0]);
				return EINVAL;
			}
			break;
		case 'b':
			block = 1;
			break;
		case 'i':
			iters = atoi(optarg);
			if (!iters) {
				printf("infinite run (iters == 0)\n");
			}
			break;
		case 'T':
			runtime = atoi(optarg);
			if (runtime < 0) {
				printf("bogus runtime %d\n", runtime);
				usage(argv[0]);
				return EINVAL;
			}
			break;
		case 'v':
			verbose = 1;
			printf("Being verbose!\n");
			break;
		case 'V':
			vlan = atoi(optarg);
			if (vlan < 2 || vlan > 4094) {
				printf("vlan must be between 2..4094\n");
				usage(argv[0]);
				return EINVAL;
			}
			break;
		default:
			usage(argv[0]);
			return EINVAL;
		}
	}

	if (optind == argc) {
		usage(argv[0]);
		return EINVAL;
	}
	if (runtime >= 0 && iters >= 0) {
		printf("Specify a run time or iteration count...not both!\n");
		return EINVAL;
	}
	if (qpcount > 1 && !use_srq) {
		printf("Using srq for qp count %d\n", qpcount);
		use_srq = 1;
	}
	if (runtime == -1 && iters == -1)
		iters = 1000;
	if (verification && size < 4) {
		printf("Data verification requires a size >= 4.\n");
		return EINVAL;
	}
	if (verification)
		LOG("data verifcation enabled.\n");

	ind = optind;

	/*
	 * Determine the local and remote ipaddrs/ports.
	 */
	if (inet_pton(AF_INET, argv[ind], addr)) {
		family = AF_INET;
		addrlen = 4;
		memcpy(&sin.sin_addr.s_addr, addr, addrlen);
		sin.sin_port = htons(port);
		any.sin_port = htons(port);
		sa = (struct sockaddr *)&sin;
		peer_sa = (struct sockaddr *)&peer;
		any_sa = (struct sockaddr *)&any;
	} else if (inet_pton(AF_INET6, argv[ind], addr)) {
		family = AF_INET6;
		addrlen = 16;
		memcpy(sin6.sin6_addr.s6_addr, addr, addrlen);
		sin6.sin6_port = htons(port);
		any6.sin6_port = htons(port);
		sa = (struct sockaddr *)&sin6;
		peer_sa = (struct sockaddr *)&peer6;
		any_sa = (struct sockaddr *)&any6;
		flags |= use_mapped ? 0 : UDP_IPV6ONLY;
	} else {
		fprintf(stderr, "bogus ip/ip6 addr %s\n", argv[ind]);
		return -1;
	}

	ind++;
	if (ind == argc - 1) {
		client = 1;
		if (family == AF_INET) {
			if (!inet_pton(AF_INET, argv[ind], addr)) {
				fprintf(stderr, "bogus peer ip/ip6 addr %s\n", argv[ind]);
				return -1;
			}
			memcpy(&peer.sin_addr.s_addr, addr, addrlen);
			peer.sin_port = htons(port);
		} else {
			if (!inet_pton(AF_INET6, argv[ind], addr)) {
				fprintf(stderr, "bogus peer ip/ip6 addr %s\n", argv[ind]);
				return -1;
			}
			memcpy(peer6.sin6_addr.s6_addr, addr, addrlen);
			peer6.sin6_port = htons(port);
		}
	}

	/*
	 * Adjust rq_depth down for packed mode with multiple qps.  Otherwise
	 * we exceed the max iqe depth with just 2 qps.
	 */
	if (packed && qpcount > 1)
		rq_depth /= qpcount;

	/*
	 * Allocate the memory needed for the send/recv buffers for all qps.
	 * Use huge pages if the IO size exceeds the host page size.
	 */
	if (size <= MAX_PAGE_IO_SIZE) {
		bufsz = BUFSZ;
		mrsize = (rq_depth + SQ_DEPTH) * BUFSZ * qpcount;
		rbuf = memalign(4096, mrsize);
		if (!rbuf) {
			ret = errno;
			perror("memalign");
			return ret;
		}
		sbuf = rbuf + (BUFSZ * rq_depth * qpcount);
	} else {
		bufsz = HUGE_BUF_SIZE;
		mrsize = qpcount * (rq_depth + SQ_DEPTH) / HUGE_BUFS_PER_PAGE *
		         HUGE_PAGE_SIZE;
		if (mrsize < (qpcount * (rq_depth + SQ_DEPTH) * HUGE_BUF_SIZE))
			mrsize += HUGE_PAGE_SIZE;
		rbuf = alloc_huge_pages(mrsize);
		if (!rbuf) {
			ret = errno;
			perror("alloc_huge_pages");
			return ret;
		}
		sbuf = rbuf + (HUGE_BUF_SIZE * rq_depth * qpcount);
	}
	LOG("mrsize %d, bufsz %d rbuf %p sbuf %p\n", mrsize, bufsz, rbuf, sbuf);

	/*
	 * allocated and start the WD-UDP device.
	 */
	ret = udp_alloc_dev(&sin, &sin6, &dev);
	if (ret) {
		printf("udp_alloc_dev failed: %s\n", strerror(ret));
		return ret;
	}
	ret = udp_start_dev(dev, NULL);
	if (ret) {
		printf("udp_start_dev failed: %s\n", strerror(ret));
		return ret;
	}

	/*
	 * Create the send and recv cqs to be shared for all qps.
	 */
	scq = ibv_create_cq(dev->verbs, qpcount * SQ_DEPTH * 2, NULL, NULL, 0);
	if (!scq) {
		ret = errno;
		perror("ibv_create_cq");
		return ret;
	}

	if (block) {
		ch = ibv_create_comp_channel(dev->verbs);
		if (!ch) {
			ret = errno;
			perror("ibv_create_comp_channel");
			return ret;
		}
	}

	rcq = ibv_create_cq(dev->verbs, MIN(64000, qpcount * rq_depth * (packed ? BUFSZ / 64 : 1)), NULL, ch, 0);
	if (!rcq) {
		ret = errno;
		perror("ibv_create_cq");
		return ret;
	}

	/*
	 * Create the srq if needed.
	 */
	if (use_srq) {
		ret = udp_create_srq(dev, qpcount * rq_depth, flags, &srq);
		if (ret) {
			printf("udp_create_srq failed: %s\n", strerror(ret));
			return ret;
		}
	}
	/*
	 * register the shared memory region.
	 */
	rmr = ibv_reg_mr(dev->pd, rbuf, mrsize, IBV_ACCESS_LOCAL_WRITE);
	if (!rmr) {
		ret = errno;
		perror("ibv_reg_mr");
		return ret;
	}
	smr =  rmr;

	/*
	 * For each qp:
	 */
	memset(sbuf, 0, qpcount * bufsz * SQ_DEPTH);
	sbp = sbuf + 64;
	for (c = 0; c < qpcount; c++) {
		char p1[64], p2[64];
		unsigned short lport, rport;
		int on = 1;

		/*
		 * allocate/bind a host socket to reserve the port.
		 */
		socks[c] = socket(family, SOCK_DGRAM, 0);
		if (socks[c] < 0) {
			ret = errno;
			perror("socket");
			return ret;
		}
		if (setsockopt(socks[c], SOL_SOCKET, SO_REUSEADDR, &on, sizeof on)) {
			perror("setsockopt");
			ret = errno;
			return ret;
		}

		/*
		 * setup the local and remote sockaddrs.
		 */
		if (family == AF_INET) {
			sin.sin_port = htons(port + c);
			peer.sin_port = htons(port + c);
			any.sin_port = htons(port + c);
			inet_ntop(family, &sin.sin_addr.s_addr, p1, sizeof p1);
			inet_ntop(family, &peer.sin_addr.s_addr, p2, sizeof p2);
			lport = ntohs(sin.sin_port);
			rport = ntohs(peer.sin_port);
			ctx[c].peer = peer;
			ctx[c].peer_sa = (struct sockaddr *)&ctx[c].peer;
		} else {
			sin6.sin6_port = htons(port + c);
			peer6.sin6_port = htons(port + c);
			any6.sin6_port = htons(port + c);
			inet_ntop(family, sin6.sin6_addr.s6_addr, p1, sizeof p1);
			inet_ntop(family, peer6.sin6_addr.s6_addr, p2, sizeof p2);
			lport = ntohs(sin6.sin6_port);
			rport = ntohs(peer6.sin6_port);
			ctx[c].peer6 = peer6;
			ctx[c].peer_sa = (struct sockaddr *)&ctx[c].peer6;
		}
		if (bind(socks[c], bind_to_any ? any_sa : sa, family == AF_INET ? sizeof sin : sizeof sin6)) {
			ret = errno;
			perror("bind");
			return ret;
		}

		/*
		 * Setup the send wrs.
		 */
		for (i = 0; i < SQ_DEPTH; i++) {
			if (verification)
				randomize_buf(sbp, size, &seed);
			else
				memset(sbp, 0xaa, size);
			ctx[c].ssge[i].length = size;
			ctx[c].ssge[i].addr = (unsigned long)sbp;
			ctx[c].ssge[i].lkey = smr->lkey;
			ctx[c].send_wr[i].wr_id = c;
			ctx[c].send_wr[i].sg_list = &ctx[c].ssge[i];
			ctx[c].send_wr[i].num_sge = 1;
			ctx[c].send_wr[i].peer = ctx[c].peer_sa;
			ctx[c].send_wr[i].send_flags = UDP_SEND_HDR_ROOM;
			if (size <= udp_max_inline(sa->sa_family) && use_inline)
				ctx[c].send_wr[i].send_flags |= UDP_SEND_INLINE;
			if (i && !((i+1) % COAL))
				ctx[c].send_wr[i].send_flags |= UDP_SEND_SIGNALED;
			sbp += bufsz;
		}

		/*
		 * Create the UDP QP.
		 */
		ret = udp_create_qp(dev, scq, rcq, SQ_DEPTH, use_srq ? 0 : rq_depth, srq, bind_to_any || use_mapped ? any_sa : sa, peer_sa, vlan, 0, flags, &ctx[c].qp);
		if (ret) {
			printf("udp_create_qp failed: %s\n", strerror(ret));
			return ret;
		}
		LOG("ctx %d qp_num %d laddr %s lport %d raddr %s rport %d\n",
			c, ctx[c].qp->raw_qp->qp_num, p1, lport, p2, rport);
	}


	/*
	 * Post all the recv bufs to all qps or to the srq if using one.
	 */
	memset(rbuf, 0, qpcount * bufsz * rq_depth);
	rbp = rbuf;
	rsge.length = bufsz;
	rsge.lkey = rmr->lkey;
	recv_wr.sg_list = &rsge;
	recv_wr.num_sge = 1;
	c = -1;
	for (i = 0; i < qpcount * rq_depth; i++) {
		
		if ((i % rq_depth) == 0)
			c++;
		rsge.addr = (unsigned long)rbp + i * bufsz;
		recv_wr.wr_id = i;
		if (use_srq)
			ret = udp_post_srq_recv(srq, &recv_wr);
		else
			ret = udp_post_recv(ctx[c].qp, &recv_wr);
		if (ret) {
			printf("udp_post_recv failed: %s\n", strerror(ret));
			return ret;
		}
	}

	if (block && ibv_req_notify_cq(rcq, 0)) {
		ret = errno;
		perror("ibv_req_notify");
		return ret;
	}
		
	switch (test) {
	case RR:
		ret = run_rr();
		break;
	case STREAM:
		ret = run_stream();
		break;
	};

	if (ret)
		return ret;

	for (i = 0; i < qpcount ; i++) {
		ret = udp_destroy_qp(ctx[i].qp);
		if (ret) {
			printf("udp_destroy_qp failed: %s\n", strerror(ret));
			return ret;
		}
	}

	ret = ibv_destroy_cq(scq);
	if (ret) {
		ret = errno;
		perror("ibv_destroy_cq");
		return ret;
	}

	ret = ibv_destroy_cq(rcq);
	if (ret) {
		ret = errno;
		perror("destroy_cq");
		return ret;
	}

	ret = udp_stop_dev(dev);
	if (ret) {
		printf("udp_stop_dev failed: %s\n", strerror(ret));
		return ret;
	}

	ret = udp_dealloc_dev(dev);
	if (ret) {
		printf("udp_dealloc_dev failed: %s\n", strerror(ret));
		return ret;
	}
	return 0;
}
