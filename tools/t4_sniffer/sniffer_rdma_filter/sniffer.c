/*
 * Copyright (C) 2011 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <malloc.h>
#include <getopt.h>
#include <signal.h>
#include <assert.h>

#include <net/if.h>

#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <netinet/ether.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <infiniband/verbs.h>

#include "cxgbtool.h"
#include "get_clock.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#ifndef IBV_QPT_RAW_ETH
#define IBV_QPT_RAW_ETH 8
#endif

static int page_size;

enum {
	COAL = 21,
	SQ_DEPTH = COAL * 4,
	RQ_DEPTH = COAL * 80,
};

static struct timespec start_time, stop_time;
static int iters = -1;
static int verbose = 0;

#define DBG(fmt, args...) do { if (verbose) printf(fmt, ##args); } while (0)

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
	(double)TIME_DIFF_in_NANO(start,end)/(double)1000000000

char ifname[IFNAMSIZ];
static struct ibv_context *ctx;
static int port;
static struct ibv_pd *pd;
static int fid, iqid;
static struct ibv_cq *scq, *rcq;
static struct ether_addr laddr, raddr;
static struct ibv_qp *qp;
static struct ibv_mr *rmr, *smr;
static char *rbuf, *sbuf;
static struct ibv_sge rsge, ssge;
static struct ibv_send_wr send_wr;
static struct ibv_recv_wr recv_wr;
static struct ibv_comp_channel *ch;
static int client = 0;
static int size = ETHER_MIN_LEN;
static int block = 0;
static int ind;
static int use_inline = 0;
static int runtime = -1;
static unsigned short etype = 0x8888;

static struct option long_options[] = {
	{ .name = "size",           .has_arg = 1, .val = 's' },
	{ .name = "block", 	    .has_arg = 0, .val = 'b' },
	{ .name = "iters",          .has_arg = 1, .val = 'i' },
	{ .name = "time",           .has_arg = 1, .val = 'T' },
	{ .name = "verbose",        .has_arg = 0, .val = 'v' },
	{ .name = "inline",         .has_arg = 0, .val = 'I' },
	{ 0 }
};

char progname[256];

#define CHELSIO_VID 0x1425

#define IFI_RTA(p) ((struct rtattr*)(((char*)(p)) + \
		   NLMSG_ALIGN(sizeof(struct ifinfomsg))))

static void usage(const char *argv0)
{
	printf("Usage:\n");
	printf("  %s [options] <lmac>         start a server on <lmac>\n", argv0);
	printf("  %s [options] <lmac>  <rmac> start a client on <lmac> to server at <rmac>\n", argv0);
	printf("\n");
	printf("Options:\n");
	printf("  -s, --size=<size>      size of message to exchange (default 60)\n");
	printf("  -b, --block    	 Block for completions (default is polling)\n");
	printf("  -i, --iters=<count>  	 Run test for <count> iterations (default is 1000)\n");
	printf("  -T, --time=<count>  	 Run test for <count> seconds (default is 1000 iterations)\n");
	printf("  -I, --inline    	 use IBV_SEND_INLINE if possible.\n");
	printf("  -v, --verbose    	 be verbose.\n");
}

static int set_filter(struct ibv_qp *qp, int fid, char *ifname)
{
	struct ifreq ifr;
	struct ch_filter op;
	int ret;
	int fd;

	/* setting filter to accept all packets */
	memset(&op, 0, sizeof op);
	op.filter_id = fid;
	op.filter_ver = CH_FILTER_SPECIFICATION_ID;
	op.fs.action = FILTER_PASS;
	op.fs.dirsteer = 1;
	op.fs.iq = iqid;
	op.fs.val.iport = port - 1;
	op.fs.mask.iport = ~0;
	op.cmd = CHELSIO_SET_FILTER;
	memset(&ifr, 0, sizeof ifr);
	strncpy(ifr.ifr_name, ifname, sizeof ifr.ifr_name - 1);
	ifr.ifr_data = (void *)&op;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		return errno;
	}
	ret = ioctl(fd, SIOCCHIOCTL, &ifr);
	if (ret) {
		return errno;
	}

	close(fd);
	return 0;
}

static int set_rem_promisc_mode(const char *ifname, int en)
{
	struct ifreq ifr;
	int ret;

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;	

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
	ret = ioctl(fd, SIOCGIFFLAGS, &ifr);
	if (ret < 0) {
		close(fd);
		return -1;
	}

	if (en)
		ifr.ifr_flags |= IFF_PROMISC;
	else
		ifr.ifr_flags &= ~IFF_PROMISC;

	ret = ioctl(fd, SIOCSIFFLAGS, &ifr);
	if (ret < 0) {
		close(fd);
		return -1;
	}

	close (fd);
	return 0;
}

static int get_t4name(struct ether_addr *laddr, char *ifname)
{
	struct {
		struct nlmsghdr n;
		struct ifinfomsg ifi;
	} req;

	int status;
	char buf[16384];
	struct nlmsghdr *nlmp;
	struct ifinfomsg *rtmp;
	struct rtattr *rtap;
	int rtattrlen;
	int found = 0, end = 0;
	int fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof req.ifi);
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.n.nlmsg_type = RTM_GETLINK;
	req.ifi.ifi_change = 0xffffffff;
	status = send(fd, &req, sizeof req, 0);
	if (status < 0) {
		fprintf(stderr, "%s: send() failed with error %d.\n",
				progname, errno);
		return -1;
	}

	while (!end) {
		status = recv(fd, buf, sizeof(buf), 0);
		if (status < 0) {
			fprintf(stderr, "%s: recv() failed with error %d.\n",
					progname, errno);
			return -1;
		}
		if (status == 0){
			fprintf(stderr, "%s: EOF\n", progname);
			return -1;
		}

		for(nlmp = (struct nlmsghdr *)buf; status > sizeof(*nlmp);){
			int len = nlmp->nlmsg_len;
			int req_len = len - sizeof(*nlmp);
			unsigned char *hwaddr = NULL;
			unsigned mtu = 0;
			char *name = NULL;

			if (req_len < 0 || len > status) {
				fprintf(stderr, "%s: reply fmt error\n", progname);
				return -1;
			}
			if (!NLMSG_OK(nlmp, status)) {
				fprintf(stderr, "%s: NLMSG not OK\n", progname);
				return -1;
			}

			if (nlmp->nlmsg_type == NLMSG_DONE) {
				end++;
				break;
			}

			rtmp = (struct ifinfomsg *)NLMSG_DATA(nlmp);
			rtap = (struct rtattr *)IFI_RTA(rtmp);
			rtattrlen = IFA_PAYLOAD(nlmp);
			for (; RTA_OK(rtap, rtattrlen);
			     rtap = RTA_NEXT(rtap, rtattrlen)) {
				if (rtap->rta_type == IFLA_ADDRESS) {
					hwaddr = (unsigned char *)RTA_DATA(rtap);
					if (!memcmp(hwaddr, laddr, ETH_ALEN))
						found = 1;
				}
				if (rtap->rta_type == IFLA_MTU) {
					mtu = *((unsigned *)RTA_DATA(rtap));
				}
				if (rtap->rta_type == IFLA_IFNAME) {
					name = (char *)RTA_DATA(rtap);
				}
			}
			assert(hwaddr && mtu && name);
			if (found) {
				memcpy(ifname, name, IFNAMSIZ);
				end++;
				break;
			}
			status -= NLMSG_ALIGN(len);
			nlmp = (struct nlmsghdr*)((char*)nlmp + NLMSG_ALIGN(len));
		}
	}
	close(fd);
	return !found;
}

static int is_t4dev(struct ibv_device_attr *attr)
{
	int subdev;

	if (attr->vendor_id != CHELSIO_VID)
		return 0;

	/* T4 and later ASICs use a PCI Device ID scheme of 0xVFPP where:
	 *
	 * V  = "4" for T4; "5" for T5, etc.
	 * F  = "0" for PF 0..3; "4".."7" for PF4..7; and "8" for VFs
	 * PP = adapter product designation
	 *
	 * Unfortunately the FPGA PCI Device IDs don't follow the ASIC PCI
	 * Device ID numbering convetions for the Physical Functions.  The
	 * T4 FPGA is 0xa000 for both PF0 and PF1) and the T5 FPGA is 0xb000
	 * for PF0 and 0xb001 for PF1.  Hopefully we'll stop that nonsense in
	 * the future.
	 */
	subdev = (attr->vendor_part_id >> 12) & 0xf;

	return (subdev == 4 || subdev == 0xa ||
		subdev == 5 || subdev == 0xb);
}

static int find_t4dev(struct ether_addr *laddr, struct ibv_context **ctxp,
		      int *portp)
{
	struct ibv_device **devs;
	struct ibv_context *ctx;
	union ibv_gid gid;
	struct ibv_device_attr attr;
	int num;
	int i, j = 0;
	int ret;

	devs = ibv_get_device_list(&num);
	if (!devs) 
		return ENODEV;

	while (num--) {
		ctx = ibv_open_device(devs[j++]);
		if (!ctx) {
			ret = errno;
			fprintf(stderr, "%s: ibv_open_device() failed\n.",
					progname);
			return ret;
		}
		ret = ibv_query_device(ctx, &attr);
		if (ret) {
			ret = errno;
			fprintf(stderr, "%s: ibv_query_device() failed with "
					"error %d.\n", progname, ret);
			return ret;
		}
		if (is_t4dev(&attr)) {
			for (i = 1; i <= attr.phys_port_cnt; i++) {
				ret = ibv_query_gid(ctx, i, 0, &gid);
				if (ret) {
					ret = errno;
					fprintf(stderr, "%s: ibv_query_gid() "
							"failed with error %d."
							"\n", progname, ret);
					return ret;
				}
				if (!memcmp(gid.raw, laddr, 6)) {
					*portp = i;
					*ctxp = ctx;
					goto out;
				}
			}
		}
		ibv_close_device(ctx);
		ctx = NULL;
	}
 out:
	ibv_free_device_list(devs);
	return !ctx;
}

static int stream_done;

void streamc_handler(int foo)
{
	DBG("ALARM\n");
	stream_done = 1;
}

static int run_stream()
{
	int rcnt = 0;
	int scnt = 0, ccnt = 0;
	double t;
	struct ibv_send_wr wrs[COAL];
	int i;
	int ret = 0;
	int ne;
	struct ibv_send_wr *bad_wr;
	struct ibv_recv_wr *bad_recv_wr;
	struct ibv_wc wc[10];
	struct ibv_wc swc;

	if (client) {
		struct ibv_send_wr *wrp;

		for (i = 0; i < COAL; i++) {
			wrs[i] = send_wr;
			wrs[i].next = &wrs[i+1];
		}
		wrs[COAL-1].next = NULL;
		wrs[COAL-1].send_flags |= IBV_SEND_SIGNALED;

		if (runtime > 0) {
			signal(SIGALRM, streamc_handler);
			alarm(runtime);
		}
		clock_gettime(CLOCK_REALTIME, &start_time);
		while (!stream_done) {
			if (iters > 0 && ccnt >= iters)
				break;
			while ((scnt - ccnt) < SQ_DEPTH) {
				i = MIN(COAL, SQ_DEPTH - scnt + ccnt);
				assert(i == COAL);
				wrp = wrs;
				ret = ibv_post_send(qp, wrp, &bad_wr);
				if (ret) {
					fprintf(stderr, "%s: ibv_post_send() "
							"failed: %s\n",
							progname,
							strerror(ret));
					return ret;
				}
				scnt += i;
			}

			if (ccnt < scnt) {
				do {
					ne = ibv_poll_cq(scq, 1, &swc);
				} while (ne == 0);
				if (ne < 0) {
					fprintf(stderr, "%s: ibv_poll_cq() "
							"failed with error "
							"%d.\n",
							progname, errno);
					return ne;
				}
				if (swc.status != 0) {
					fprintf(stderr, "%s: send completion "
						"error status %d\n", progname,
					       swc.status);
					return EIO;
				}
				ccnt += COAL;
			}
		}
		while (ccnt < scnt) {
			do {
				ne = ibv_poll_cq(scq, 1, &swc);
			} while (ne == 0);
			if (ne < 0) {
				fprintf(stderr, "%s: ibv_poll_cq() "
						"failed with error "
						"%d.\n",
						progname, errno);
				return ne;
			}
			if (swc.status != 0) {
				fprintf(stderr, "%s: recv completion "
						"error status %d\n", progname,
						swc.status);

				return EIO;
			}
			ccnt += COAL;
		}
		clock_gettime(CLOCK_REALTIME, &stop_time);
		assert(ccnt == scnt);
		t = TIME_DIFF_in_SEC(start_time, stop_time);
		printf("Elapsed time %.3f seconds, TX Pkts %d (%.3f MPkts), Pkts/Sec %.3f (%.3f MPkts/Sec), througput %.3f Gbps\n", t, scnt, (double)scnt / 1000000, (double)scnt / t, (double)scnt / t / 1000000, (double)scnt * (double)size * 8 / 1000000000 / t);
	} else {
		int started = 0;
		unsigned long long rbytes = 0;

		while (!stream_done) {

			ne = ibv_poll_cq(rcq, 10, wc);
			if (ne == 0)
				continue;
			if (ne < 0) {
				fprintf(stderr, "%s: ibv_poll_cq() "
					"failed with error %d.\n",
						progname, errno);
				return ret;
			}
			if (!started) {
				clock_gettime(CLOCK_REALTIME, &start_time);
				started = 1;
				if (runtime > 0) {
					signal(SIGALRM, streamc_handler);
					alarm(runtime);
				}
			}
			for (i = 0; i < ne; i++) {
				if (wc[i].status != 0) {
					fprintf(stderr, "%s: recv completion "
							"error status %d\n", progname, 
							wc[i].status);
					return EIO;
				}
				rcnt++;
				rbytes += wc[i].byte_len;
				rsge.addr = (unsigned long)(rbuf + wc[i].wr_id * page_size);
				recv_wr.wr_id = wc[i].wr_id;
				ret = ibv_post_recv(qp, &recv_wr, &bad_recv_wr);
				if (ret) {
					fprintf(stderr, "%s: ibv_post_recv() "
						"failed: %s\n", progname,
						strerror(ret));
					return ret;
				}
			}
		}
		clock_gettime(CLOCK_REALTIME, &stop_time);
		t = TIME_DIFF_in_SEC(start_time, stop_time);
		printf("Elapsed time %.3f seconds, RX Pkts %d (%.3f MPkts), Pkts/Sec %.3f (%.3f MPkts/Sec), througput %.3f Gbps\n", t, rcnt, (double)rcnt / 1000000, (double)rcnt / t, (double)rcnt / t / 1000000, ((double)rbytes / t) * 8 / 1000000000);
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int ret;
	int i;
	struct ether_header *hdr;
	char *rbp;

	strcpy(progname, argv[0]);

	page_size = sysconf(_SC_PAGESIZE);
	while (1) {
		int c;
		c = getopt_long(argc, argv, "e:T:It:s:bi:vV:", long_options,
				NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'I':
			use_inline = 1;
			break;
		case 's':
			size = atoi(optarg);
			if (size < ETHER_MIN_LEN || size > page_size) {
				fprintf(stderr, "%s: size must be >= %d and < "
						"%d\n", progname, ETHER_MIN_LEN,
						page_size);
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
				fprintf(stderr, "%s: infinite run (iters == 0)"
						"\n", progname);
			}
			break;
		case 'T':
			runtime = atoi(optarg);
			if (runtime < 0) {
				fprintf(stderr, "%s: bogus runtime %d\n",
						progname, runtime);
				usage(argv[0]);
				return EINVAL;
			}
			break;
		case 'v':
			verbose = 1;
			printf("Being verbose!\n");
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
		fprintf(stderr, "%s: specify a run time or iteration count..."
				"not both!\n", progname);
		return EINVAL;
	}
	if (runtime == -1 && iters == -1)
		iters = 1000;

	ind = optind;
	if (!ether_aton(argv[ind])) {
		fprintf(stderr, "%s: invalid local address %s\n",
				progname, argv[ind]);
		usage(argv[0]);
		return EINVAL;
	}
	memcpy(laddr.ether_addr_octet, ether_aton(argv[ind]), ETH_ALEN);
	ind++;
	if (ind == argc - 1) {
		if (!ether_aton(argv[ind])) {
			fprintf(stderr, "%s: invalid remote address %s\n",
					progname, argv[ind]);
			usage(argv[0]);
			return EINVAL;
		}
		memcpy(raddr.ether_addr_octet, ether_aton(argv[ind]), ETH_ALEN);
		client = 1;
	} 

	rbuf = memalign(page_size, page_size * RQ_DEPTH);
	if (!rbuf) {
		ret = errno;
		fprintf(stderr, "%s: failure to allocate memory for receive "
				"buffer, aligned to %d"
				" bytes.\n", progname, page_size);
		return ret;
	}
	sbuf = memalign(page_size, page_size);
	if (!sbuf) {
		ret = errno;
		fprintf(stderr, "%s: failure to allocate memory for send "
				"buffer, aligned to %d bytes.\n",
				progname, page_size);

		return ret;
	}

	ret = find_t4dev(&laddr, &ctx, &port);
	if (ret) {
		fprintf(stderr, "%s: iWARP device not found. Make sure iWARP "
				"driver is loaded\n", progname);
		return ENODEV;
	}
	ret = get_t4name(&laddr, ifname);
	if (ret) {
		fprintf(stderr, "%s: cannot find ifname!\n", progname);
		return ENODEV;
	}
	
	printf ("ifname = %s\n", ifname);

	pd = ibv_alloc_pd(ctx);
	if (!pd) {
		ret = errno;
		fprintf(stderr, "%s: ibv_alloc_pd() failed with error %d.\n", 
				progname, ret);
		return ret;
	}

	scq = ibv_create_cq(ctx, SQ_DEPTH, NULL, NULL, 0);
	if (!scq) {
		ret = errno;
		fprintf(stderr, "%s: ibv_create_cq() failed with error %d.\n", 
				progname, ret);
		return ret;
	}

	if (block) {
		ch = ibv_create_comp_channel(ctx);
		if (!ch) {
			ret = errno;
			fprintf(stderr, "%s: ibv_create_com_channel() failed\n"
					" with error %d.\n", progname, ret);
			return ret;
		}
	}

	rcq = ibv_create_cq(ctx, RQ_DEPTH, NULL, ch, 0);
	if (!rcq) {
		ret = errno;
		fprintf(stderr, "%s: ibv_create_cq() failed with error %d.\n",
				progname, ret);
		return ret;
	}
{
	struct ibv_qp_init_attr attr = {
		.send_cq = scq,
		.recv_cq = rcq,
		.cap = {
			.max_send_wr = SQ_DEPTH,
			.max_recv_wr = RQ_DEPTH,
			.max_send_sge = 1,
			.max_recv_sge = 1,
		},
		.qp_type = IBV_QPT_RAW_ETH,
                .sq_sig_all = ((((7) << 13) | (0xfff)) << 16) | port << 8
	};
	struct ibv_qp_attr attr2 = {
		.qp_state = IBV_QPS_RTS,
		.port_num = port
	};

	/* Overload bits 3:1 with the number
	 * of filters needed.  IPv4 needs 1
	 */
	attr.sq_sig_all |= 1<<1;
	qp = ibv_create_qp(pd, &attr);
	if (!qp) {
		ret = errno;
		fprintf(stderr, "%s: ibv_create_qp() failed with error %d.\n",
				progname, ret);
		return ret;
	}

	ret = ibv_modify_qp(qp, &attr2, IBV_QP_STATE|IBV_QP_PORT);
	if (ret) {
		ret = errno;
		fprintf(stderr, "%s: ibv_modify_qp() failed with error %d.\n",
				progname, ret);
		return ret;
	}

	ret = ibv_query_qp(qp, &attr2, IBV_QP_RQ_PSN|IBV_QP_SQ_PSN, NULL);
	if (ret) {
		ret = errno;
		fprintf(stderr, "%s: ibv_query_qp() failed with error %d.",
				progname, ret);
		return ret;
	}
	fid = attr2.rq_psn;
	iqid = attr2.sq_psn;
}
	if (set_rem_promisc_mode(ifname, 0)) {
		fprintf(stderr, "%s: failure to set promiscuous mode for "
				"interface %s.\n", progname, ifname);
		return 1;
	}

	rmr = ibv_reg_mr(pd, rbuf, RQ_DEPTH * page_size, IBV_ACCESS_LOCAL_WRITE);
	if (!rmr) {
		ret = errno;
		fprintf(stderr, "%s: ibv_reg_mr() failed to register receive "
				"memory region. Error %d.\n",
				progname, ret);
		return ret;
	}

	smr = ibv_reg_mr(pd, sbuf, page_size, 0);
	if (!smr) {
		ret = errno;
		fprintf(stderr, "%s: ibv_reg_mr() failed to register send "
				"memory region. Error %d.\n",
				progname, ret);

		return ret;
	}

	memset(rbuf, 0, page_size * RQ_DEPTH);
	rbp = rbuf;

	rsge.length = page_size;
	rsge.lkey = rmr->lkey;
	recv_wr.sg_list = &rsge;
	recv_wr.num_sge = 1;
	recv_wr.next = NULL;
	for (i = 0; i < RQ_DEPTH; i++) {
		struct ibv_recv_wr *bad_wr;
		
		rsge.addr = (unsigned long)rbp + i * page_size;
		recv_wr.wr_id = i;
		ret = ibv_post_recv(qp, &recv_wr, &bad_wr);
		if (ret) {
			fprintf(stderr, "%s: ibv_post_recv() failed with error "
				       "%d.\n", progname, ret);
			return ret;
		}
	}
	ret = set_filter(qp, fid, ifname);
	if (ret) {
		fprintf(stderr, "%s: set_filter failed.\n", progname);
		return ret;
	}

	memset(sbuf, 0, page_size);
	
	if (client) {
		hdr = (struct ether_header *)sbuf;
		memcpy(hdr->ether_dhost, &raddr, ETH_ALEN);
		memcpy(hdr->ether_shost, &laddr, ETH_ALEN);
		hdr->ether_type = htons(etype);
	}
	ssge.length = size;
	ssge.addr = (unsigned long)sbuf;
	ssge.lkey = smr->lkey;
	
	send_wr.sg_list = &ssge;
	send_wr.num_sge = 1;
	send_wr.wr_id = 0xabbaabba;
	send_wr.send_flags = 0;
	if (size <= 64 && use_inline)
		send_wr.send_flags |= IBV_SEND_INLINE;
	if (block && ibv_req_notify_cq(rcq, 0)) {
		ret = errno;
		fprintf(stderr, "%s: ibv_req_notify() failed with error %d.\n",
				progname, ret);
		return ret;
	}
		
	ret = run_stream();

	ibv_destroy_qp(qp);
	ibv_destroy_cq(scq);
	ibv_destroy_cq(rcq);
	ibv_dereg_mr(smr);
	free(sbuf);
	ibv_dereg_mr(rmr);
	free(rbuf);
	ibv_dealloc_pd(pd);
	ibv_close_device(ctx);
	if (set_rem_promisc_mode(ifname, 0))
		fprintf(stderr, "%s: Cannot remove promiscuous mode for "
				"interface %s.\n", argv[0], ifname);
	return ret;
}
