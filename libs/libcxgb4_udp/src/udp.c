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
#include <errno.h>
#include <string.h>
#include <malloc.h>
#include <assert.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>

#include <chelsio/cxgb4_udp.h>
#include "cxgbtool.h"

unsigned dbg_flags;
unsigned dbg_dst = DBG_DST_SYSLOG;
FILE *dbg_file = NULL;

#define ALIGN(l, size) (((l) + ((size) - 1)) / (size) * (size))
#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

#define SEC_TO_NANO(n) ((n) * 1000000000)
#define SEC_TO_MICRO(n) ((n) * 1000000)
#define NANO_TO_MICRO(n) (((n) + 500) / 1000)

#define TIME_DIFF_in_MICRO(start, end) \
	(SEC_TO_MICRO((end).tv_sec - (start).tv_sec) + \
	 (NANO_TO_MICRO((end).tv_nsec - (start).tv_nsec)))

#define TIME_DIFF_in_NANO(start,end) \
	(SEC_TO_NANO((end).tv_sec-(start).tv_sec) + \
	 ((end).tv_nsec-(start).tv_nsec))

#define SAMPLES 4096
#define SKIP 1024

enum {
	PSEND,
	LAST
};

static void prefetch(const void *x)
{
#if 1
	asm volatile("prefetcht0 (%0)" :: "r" (x));
#endif
}

static int page_size;

/*
 * Macros needed to support the PCI Device ID Table ...
 */
#define CH_PCI_DEVICE_ID_TABLE_DEFINE_BEGIN \
	static const uint32_t partids[] = {

#define CH_PCI_DEVICE_ID_FUNCTION \
		0x4

#define CH_PCI_ID_TABLE_ENTRY(__DeviceID) \
		(__DeviceID)

#define CH_PCI_DEVICE_ID_TABLE_DEFINE_END \
		(0), \
	}

#include "t4_pci_id_tbl.h"

#define sa_sin(a) ((struct sockaddr_in *)(a))
#define sa_sin6(a) ((struct sockaddr_in6 *)(a))
#define sa_sa(a) ((struct sockaddr *)(a))

static void sa_copy(struct sockaddr *dst, struct sockaddr *src)
{
	switch (src->sa_family) {
	case AF_INET:
		memcpy(dst, src, sizeof (struct sockaddr_in));
		break;
	case AF_INET6:
		memcpy(dst, src, sizeof (struct sockaddr_in6));
		break;
	}
}

static int sa_is_mcast(struct sockaddr *peer)
{
	if (peer->sa_family == AF_INET) 
		return IN_MULTICAST(ntohl(sa_sin(peer)->sin_addr.s_addr));
	return IN6_IS_ADDR_MULTICAST(sa_sin6(peer)->sin6_addr.s6_addr);
}

static int sa_addrlen(struct sockaddr *sa)
{
	return sa->sa_family == AF_INET ? 4 : 16;
}

static uint8_t *sa_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET)
		return (uint8_t *)&sa_sin(sa)->sin_addr.s_addr;
	else
		return sa_sin6(sa)->sin6_addr.s6_addr;
}

static uint16_t sa_port(struct sockaddr *sa)
{
	return ((struct sockaddr_in *)sa)->sin_port;
}

static void map_ip_mcast(uint32_t ipaddr, uint8_t *hwaddr)
{
	hwaddr[0] = 0x01;
	hwaddr[1] = 0x00;
	hwaddr[2] = 0x5e;
	hwaddr[3] = ((uint8_t *)&ipaddr)[1] & 0x7f;
	hwaddr[4] = ((uint8_t *)&ipaddr)[2];
	hwaddr[5] = ((uint8_t *)&ipaddr)[3];
}

static void map_ip6_mcast(uint8_t *ip6addr, uint8_t *hwaddr)
{
	hwaddr[0] = 0x33;
	hwaddr[1] = 0x33;
	hwaddr[2] = ip6addr[12];
	hwaddr[3] = ip6addr[13];
	hwaddr[4] = ip6addr[14];
	hwaddr[5] = ip6addr[15];
}

static void sa_map_mcast(struct sockaddr *peer, uint8_t *hwaddr)
{
	switch (peer->sa_family) {
	case AF_INET:
		map_ip_mcast(sa_sin(peer)->sin_addr.s_addr, hwaddr);
		break;
	case AF_INET6:
		map_ip6_mcast(sa_sin6(peer)->sin6_addr.s6_addr, hwaddr);
		break;
	}
}

static pthread_spinlock_t lock;

struct addr {
	int 	family;
	uint8_t	addr[16];
};

static void copy_sa(struct addr *a, struct sockaddr *sa)
{
	a->family = sa->sa_family;
	memcpy(a->addr, sa_addr(sa), sa_addrlen(sa));
}

static int addrlen(struct addr *a)
{
	return a->family == AF_INET ? 4 : 16;
}

struct neigh {
	SLIST_ENTRY(neigh)	list;
	uint8_t			hwaddr[6];
	int			family;
	struct addr		dst;
	struct addr		gw;
	struct addr		pref_src;
};

#define NEIGH_SIZE 61

SLIST_HEAD(, neigh) neighs[NEIGH_SIZE];

static int neigh_hash(struct sockaddr *sa)
{
	uint32_t key;

	if (sa->sa_family == AF_INET)
		key = sa_sin(sa)->sin_addr.s_addr;
	else
		key = *(uint32_t*)&sa_sin6(sa)->sin6_addr.s6_addr[12];
	return key % NEIGH_SIZE;
}

static int get_next_hop_from_kernel(struct neigh *np)
{
	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[256];
	} req;

	struct rtattr *rta;
	struct rtmsg *r;
	int len = addrlen(&np->dst);
	int fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	int status;
	struct addr gw, pref_src;
	int ret = 0;
	int found = 0;
	int pref_src_found = 0;

#ifdef DEBUG
{
	char p[64];
	inet_ntop(np->dst.family, np->dst.addr, p, sizeof p);
	DBG(DBG_ROUTE, "Enter dst %s\n", p);
}
#endif
	memset(&req, 0, sizeof req);
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_GETROUTE;
	req.r.rtm_family = np->dst.family;
	req.r.rtm_dst_len = len;
	req.r.rtm_table = RT_TABLE_DEFAULT;
	req.r.rtm_type = RTN_UNSPEC;
	req.r.rtm_scope = RT_SCOPE_UNIVERSE;
	rta = NLMSG_TAIL(&req.n);
	rta->rta_type = RTA_DST;
	rta->rta_len = RTA_LENGTH(len);
	memcpy(RTA_DATA(rta), np->dst.addr, len);
	req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) +
			  RTA_LENGTH(RTA_ALIGN(len));

	status = send(fd, &req, req.n.nlmsg_len, 0);
	if (status < 0) {
		DBG(DBG_ROUTE, "rtm send err %d", errno);
		ret = errno;
		goto err;
	}

	status = recv(fd, &req, sizeof req, 0);
	while (1) {
		if (status < 0) {
			DBG(DBG_ROUTE, "rtm recv err %d", errno);
			ret = errno;
			goto err;
		}
		if (status == 0) {
			DBG(DBG_ROUTE, "recv EOF");
			ret = EIO;
			goto err;
		}

		r = NLMSG_DATA(&req.n);
		len = RTM_PAYLOAD(&req.n);
		rta = RTM_RTA(r);
		for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
			switch (rta->rta_type) {
			case RTA_PREFSRC:
#ifdef DEBUG
			{
				char p[64];
				inet_ntop(np->dst.family, RTA_DATA(rta), p, sizeof p);
				DBG(DBG_ROUTE, "Preferred Src %s\n", p);
			}
#endif
				pref_src_found = 1;
				pref_src.family = np->dst.family;
				memcpy(pref_src.addr, RTA_DATA(rta), addrlen(&np->dst));
				break;
			
			case RTA_GATEWAY:
#ifdef DEBUG
			{
				char p[64];
				inet_ntop(np->dst.family, RTA_DATA(rta), p, sizeof p);
				DBG(DBG_ROUTE, "Gateway %s\n", p);
			}
#endif
				gw.family = np->dst.family;
				memcpy(gw.addr, RTA_DATA(rta), addrlen(&np->dst));
				found = 1;
				break;
			default:
				break;
			}
		}
		status = recv(fd, &req, sizeof req, MSG_DONTWAIT);
		if (status < 0 && errno == EAGAIN)
			break;
	}
	assert(len == 0);
	if (found)
		np->gw = gw;
	else
		np->gw = np->dst;
	if (pref_src_found)
		np->pref_src = pref_src;
err:
	close(fd);
	return ret;
}

static int get_neigh_from_kernel(struct neigh *np)
{
	struct {
		struct nlmsghdr n;
		struct ndmsg r;
	} req;
	int status;
	char buf[16384];
	struct nlmsghdr *nlmp;
	struct ndmsg *rtmp;
	struct rtattr *rtatp;
	int rtattrlen;
	void *inp;
	unsigned char *macp;
	int fd;

	fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (fd < 0) {
		status = errno;
		DBG(DBG_ROUTE, "socket failure %d\n", status);
		return status;
	}

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT | NLM_F_DUMP;
	req.n.nlmsg_type = RTM_GETNEIGH;
	req.r.ndm_family = np->dst.family;

	status = send(fd, &req, req.n.nlmsg_len, 0);
	if (status < 0) {
		status = errno;
		DBG(DBG_ROUTE, "send failure %d\n", status);
		goto out;
	}
	status = recv(fd, buf, sizeof(buf), 0);
	while (1) {
		if (status < 0) {
			status = errno;
			DBG(DBG_ROUTE, "recv failure %d\n", status);
			goto out;
		}
		if (status == 0) {
			status = EIO;
			DBG(DBG_ROUTE, "recv EOF\n");
			goto out;
		}

		for (nlmp = (struct nlmsghdr *)buf; status > sizeof *nlmp;) {
			int len = nlmp->nlmsg_len;
			int req_len = len - sizeof(*nlmp);

			if (req_len < 0 || len > status || !NLMSG_OK(nlmp, status)) {
				DBG(DBG_ROUTE, "bad rtnetlink message.\n");
				status = EHOSTUNREACH;
				goto out;
			}

			rtmp = (struct ndmsg *)NLMSG_DATA(nlmp);
			rtatp = (struct rtattr *)(rtmp + 1);
			rtattrlen = IFA_PAYLOAD(nlmp);
			inp = NULL;
			macp = NULL;
			for (; RTA_OK(rtatp, rtattrlen);
			     rtatp = RTA_NEXT(rtatp, rtattrlen)) {
				switch (rtatp->rta_type) {
				case NDA_DST:
					inp = RTA_DATA(rtatp);
#ifdef DEBUG
				{
					char p[64];
					inet_ntop(np->dst.family, inp, p, sizeof p);
					DBG(DBG_ROUTE, "addr %s\n", p);
				}
#endif
					break;
				case NDA_LLADDR:
					macp = (unsigned char *)RTA_DATA(rtatp);
					DBG(DBG_ROUTE, "mac %02x:%02x:%02x:%02x:%02x:%02x\n",
					    *macp, *(macp+1), *(macp+2), *(macp+3),
					    *(macp+4), *(macp+5));
					break;
				}
			}
			if (inp && macp && !memcmp(inp, np->gw.addr, addrlen(&np->gw))) {
				memcpy(np->hwaddr, macp, 6);
				status = 0;
				goto out;
			}
			status -= NLMSG_ALIGN(len);
			nlmp = (struct nlmsghdr*)((char*)nlmp + NLMSG_ALIGN(len));
		}
		status = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
		if (status < 0 && errno == EAGAIN)
			break;
	}
	status = EHOSTUNREACH;
out:
	close(fd);
	return status;
}

static int resolve(struct sockaddr *peer, struct neigh **npp)
{
	struct rdma_event_channel *rch;
	struct rdma_cm_id *id;
	struct rdma_cm_event *event;
	struct neigh *np;
	int ret;
	struct sockaddr *sa = peer;
	struct sockaddr_in sin;
	struct sockaddr_in6 *sin6p = (struct sockaddr_in6 *)peer;

	rch = rdma_create_event_channel();
	if (!rch)
		return ENOMEM;
	ret = rdma_create_id(rch, &id, NULL, RDMA_PS_TCP);
	if (ret) {
		ret = -ret;
		goto err1;
	}

	if (peer->sa_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(sin6p->sin6_addr.s6_addr)) {
		memset(&sin, 0, sizeof sin);
		sin.sin_family = AF_INET;
		memcpy(&sin.sin_addr.s_addr, &sin6p->sin6_addr.s6_addr[12], 4);
		sa = (struct sockaddr *)&sin;
	}
		
	ret = rdma_resolve_addr(id, NULL, sa, 20000);
	if (ret) {
		ret = -ret;
		goto err2;
	}

	ret = rdma_get_cm_event(rch, &event);
	if (ret) {
		ret = -ret;
		goto err2;
	}
	if (event->status) {
		ret = EHOSTUNREACH;
		goto err3;
	}
	if (event->event != RDMA_CM_EVENT_ADDR_RESOLVED) {
		ret = EIO;
		goto err3;
	}
	np = malloc(sizeof *np);
	if (!np) {
		ret = ENOMEM;
		goto err3;
	}
	copy_sa(&np->dst, sa);
	ret = get_next_hop_from_kernel(np);
	if (ret)
		goto err3;
	ret = get_neigh_from_kernel(np);
	if (ret) {
		DBG(DBG_ROUTE, "get_neigh_from_kernel err %d\n", ret);
		goto err3;
	}
#ifdef DEBUG
{
	char p1[64], p2[64], p3[64];

	inet_ntop(np->dst.family, np->dst.addr, p1, sizeof p1);
	inet_ntop(np->gw.family, np->gw.addr, p2, sizeof p2);
	inet_ntop(np->pref_src.family, np->pref_src.addr, p3, sizeof p3);

	DBG(DBG_ROUTE, "ipaddr %s, gw %s pref_src %s mac %02x:%02x:%02x:%02x:%02x:%02x\n",
	    p1, p2, p3, *np->hwaddr, *(np->hwaddr+1),
	    *(np->hwaddr+2), *(np->hwaddr+3), *(np->hwaddr+4), *(np->hwaddr+5));
}
#endif
	SLIST_INSERT_HEAD(&neighs[neigh_hash(peer)], np, list);
	*npp = np;
err3:
	rdma_ack_cm_event(event);
err2:
	rdma_destroy_id(id);
err1:
	rdma_destroy_event_channel(rch);
	if (ret) printf("%s ret %d\n", __func__, ret);
	return ret;
}

/* caller needs to gaurantee len >= 0 */
static int mem_cmp(uint8_t *s1, uint8_t *s2, int len) {
	int i;
	for (i = 0; i < len; i++) {
		if (*s1 ^ *s2)
			return -1;
	}
	return 0;
}

static int get_route_addrs(struct sockaddr *peer, uint8_t *eth_dhost, uint8_t *src_ip)
{
	struct neigh *np;
	int ret = 0;
	int alen;
	uint8_t *addr;

	if (sa_is_mcast(peer)) {
		sa_map_mcast(peer, eth_dhost);
		return 0;
	}
	pthread_spin_lock(&lock);
	SLIST_FOREACH(np, &neighs[neigh_hash(peer)], list) {
		if (peer->sa_family == AF_INET) {
			addr = (uint8_t *)&sa_sin(peer)->sin_addr.s_addr;
			alen = 4;
		} else {
			if (IN6_IS_ADDR_V4MAPPED(sa_sin6(peer)->sin6_addr.s6_addr)) {
				addr = &sa_sin6(peer)->sin6_addr.s6_addr[12];
				alen = 4;
			} else {
				addr = &sa_sin6(peer)->sin6_addr.s6_addr[0];
				alen = 16;
			}
		}
		if (!mem_cmp(np->dst.addr, addr, alen))
			break;
	}
	if (!np) {
		ret = resolve(peer, &np);
	}
	if (np) {
		memcpy(eth_dhost, np->hwaddr, 6);
		if (src_ip && np->pref_src.family)
			memcpy(src_ip, np->pref_src.addr, addrlen(&np->pref_src));
	}
	pthread_spin_unlock(&lock);
	return ret;
}

static int clear_udp_filter(struct udp_qp *qp)
{
	struct ifreq ifr;
	struct ch_filter op;
	int ioctl_fd, ret;

	ioctl_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ioctl_fd < 0) {
		ret = errno;
		DBG(DBG_UM, "socket() failure %d\n", ret);
		return ret;
	}

	memset(&op, 0, sizeof op);
	op.filter_id = qp->fid;
	op.filter_ver = CH_FILTER_SPECIFICATION_ID;
	op.cmd = CHELSIO_DEL_FILTER;
	memset(&ifr, 0, sizeof ifr);
	strncpy(ifr.ifr_name, qp->dev->ifname, sizeof ifr.ifr_name - 1);
	ifr.ifr_data = (void *)&op;
	ret = ioctl(ioctl_fd, SIOCCHIOCTL, &ifr);
	if (ret) {
		ret = errno;
		DBG(DBG_UM, "ioctl1 errno %d\n", ret);
		goto out;
	}

	if (qp->laddr.sa.sa_family == AF_INET6 && !qp->v6only &&
	    IN6_IS_ADDR_UNSPECIFIED(qp->laddr.sin6.sin6_addr.s6_addr) &&
	    IN6_IS_ADDR_UNSPECIFIED(qp->raddr.sin6.sin6_addr.s6_addr)) {

		op.filter_id += 4;
		ret = ioctl(ioctl_fd, SIOCCHIOCTL, &ifr);
		if (ret) {
			ret = errno;
			DBG(DBG_UM, "ioctl2 errno %d\n", ret);
		}
	}
out:
	(void)close(ioctl_fd);
	return ret;
}

static int set_udp_filter(struct udp_qp *qp)
{
	struct ifreq ifr;
	struct ch_filter op;
	int ioctl_fd, ret;

	ioctl_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ioctl_fd < 0) {
		ret = errno;
		DBG(DBG_UM, "socket() failure %d\n", ret);
		return ret;
	}

	memset(&op, 0, sizeof op);
	op.filter_id = qp->fid;
	op.filter_ver = CH_FILTER_SPECIFICATION_ID;
	if ((qp->vlan & 0xfff) != 0xfff) {
		op.fs.val.ivlan = qp->vlan;
		op.fs.mask.ivlan = 0xfff;
		op.fs.val.ivlan_vld = 1;
		op.fs.mask.ivlan_vld = 1;
	}
	op.fs.val.lport = ntohs(qp->udp_port);
	op.fs.mask.lport = -1;
	switch (qp->laddr.sa.sa_family) {
	case AF_INET:
		if (qp->bound_addr.sin.sin_addr.s_addr != INADDR_ANY) {
			memcpy(op.fs.val.lip, &qp->bound_addr.sin.sin_addr, 4);
			memset(op.fs.mask.lip, 0xff, 4);
		} else
			op.filter_id += qp->dev->nfids;
		if (qp->raddr.sin.sin_addr.s_addr != INADDR_ANY) {
			memcpy(op.fs.val.fip, &qp->raddr.sin.sin_addr, 4);
			memset(op.fs.mask.fip, 0xff, 4);
			op.fs.val.fport = ntohs(qp->raddr.sin.sin_port);
			op.fs.mask.fport = -1;
		}
		break;
	case AF_INET6:
		op.fs.type = 1;
		if (!IN6_IS_ADDR_UNSPECIFIED(qp->bound_addr.sin6.sin6_addr.s6_addr)) {
			memcpy(op.fs.val.lip, qp->bound_addr.sin6.sin6_addr.s6_addr, 16);
			memset(op.fs.mask.lip, 0xff, 16);
		} else
			op.filter_id += qp->dev->nfids;
		if (!IN6_IS_ADDR_UNSPECIFIED(qp->raddr.sin6.sin6_addr.s6_addr)) {
			memcpy(op.fs.val.fip, qp->raddr.sin6.sin6_addr.s6_addr, 16);
			memset(op.fs.mask.fip, 0xff, 16);
			op.fs.val.fport = ntohs(qp->raddr.sin6.sin6_port);
			op.fs.mask.fport = -1;
		}
		break;
	}
	op.fs.val.proto = IPPROTO_UDP;
	op.fs.mask.proto = -1;
	op.fs.action = FILTER_PASS;
	op.fs.dirsteer = 1;
	op.fs.iq = qp->iqid;
	op.fs.rpttid = 1;
	op.fs.hitcnts = 1;
	op.fs.eport = qp->dev->port_num - 1;
	op.cmd = CHELSIO_SET_FILTER;
	memset(&ifr, 0, sizeof ifr);
	strncpy(ifr.ifr_name, qp->dev->ifname, sizeof ifr.ifr_name - 1);
	ifr.ifr_data = (void *)&op;
	ret = ioctl(ioctl_fd, SIOCCHIOCTL, &ifr);
	if (ret) {
		ret = errno;
		DBG(DBG_UM, "ioctl1 errno %d\n", ret);
		goto out;
	}

	/* 
	 * Attempt to support dual stack mode for v6 apps bound to
	 * the UNSPECIFIED address.  This is done by creating
	 * an IPv4 filter for the bound udp local port.
	 */
	if (qp->laddr.sa.sa_family == AF_INET6 && !qp->v6only &&
	    IN6_IS_ADDR_UNSPECIFIED(qp->laddr.sin6.sin6_addr.s6_addr) &&
	    IN6_IS_ADDR_UNSPECIFIED(qp->raddr.sin6.sin6_addr.s6_addr)) {

		op.filter_id += 4;
		op.fs.val.fport = 0;
		op.fs.mask.fport = 0;
		op.fs.type = 0;
		memset(op.fs.val.fip, 0, 16);
		memset(op.fs.val.lip, 0, 16);
		memset(op.fs.mask.lip, 0, 16);
		memset(op.fs.mask.lip, 0, 16);
		ret = ioctl(ioctl_fd, SIOCCHIOCTL, &ifr);
		if (ret) {
			ret = errno;
			DBG(DBG_UM, "ioctl2 errno %d\n", ret);
		}
	}
out:
	(void)close(ioctl_fd);
	return ret;
}

static void destroy_srq_hbuf_pool(struct udp_srq *srq)
{
	ibv_dereg_mr(srq->hbufs_mr);
	srq->hbufs_mr = NULL;
	free(srq->hbufs);
	srq->hbufs = NULL;
}

static int create_srq_hbuf_pool(struct udp_srq *srq, int count)
{
	int ret;
	struct udp_hbuf *h;
	int size = count * sizeof *h;
	int i;

	h = memalign(page_size, size);
	if (!h)
		return errno;
	srq->hbufs_mr = ibv_reg_mr(srq->dev->pd, h, size, IBV_ACCESS_LOCAL_WRITE);
	if (!srq->hbufs_mr) {
		ret = errno;
		free(h);
		return ret;
	}
	srq->hbufs = h;
	for (i = 0; i < count ; i++) {
		h[i].srq = srq;
		h[i].qp = NULL;
	}
	return 0;
}

static void destroy_hbuf_pool(struct udp_qp *qp)
{
	ibv_dereg_mr(qp->hbufs_mr);
	qp->hbufs_mr = NULL;
	free(qp->sq_hbufs);
	qp->sq_hbufs = NULL;
	qp->rq_hbufs = NULL;
}

static void build_hbuf4_header(struct udp_qp *qp, struct udp_headers *hdrs, uint32_t ipaddr)
{
	struct udp4_headers *hdr;

	hdr = &hdrs->v4;
	memcpy(hdr->eth.ether_shost, qp->dev->hwaddr, 6);
	hdr->eth.ether_type = htons(ETHERTYPE_IP);
	hdr->ip.version = 4;
	hdr->ip.ihl = 5;
	hdr->ip.tos = 0;
	hdr->ip.id = 0;
	
	/*
	 * Setting the Don't Fragment bit to 1
	 * and Fragment Offset should now be 0.
	 *
	 * Linux iphdr struct in net/ip.h uses
	 * the frag_off field for both Flags
	 * and Fragment Offset (avoiding the
	 * use of bitfield).
	 */
	hdr->ip.frag_off = ntohs(IP_DF);
	
	hdr->ip.ttl = 64;
	hdr->ip.protocol = IPPROTO_UDP;
	hdr->ip.saddr = ipaddr;
	hdr->udp.source = qp->udp_port;
	return;
}

static void build_hbuf6_header(struct udp_qp *qp, struct udp_headers *hdrs)
{
	struct udp6_headers *hdr;
	hdr = &hdrs->v6;

	memcpy(hdr->eth.ether_shost, qp->dev->hwaddr, 6);
	hdr->eth.ether_type = htons(ETH_P_IPV6);

	hdr->ip.ip6_flow = htonl(0x60000000);
	hdr->ip.ip6_hlim = 64;
	hdr->ip.ip6_nxt = IPPROTO_UDP;
	memcpy(hdr->ip.ip6_src.s6_addr, qp->laddr.sin6.sin6_addr.s6_addr, 16);

	hdr->udp.source = qp->udp_port;

	if (!qp->v6only)
		build_hbuf4_header(qp, hdrs, qp->dev->sin.sin_addr.s_addr);
}

static void build_hbuf_header(struct udp_qp *qp, struct udp_headers *hdrs)
{
	switch (qp->laddr.sa.sa_family) {
	case AF_INET:
		build_hbuf4_header(qp, hdrs, qp->laddr.sin.sin_addr.s_addr);
		break;
	case AF_INET6:
		build_hbuf6_header(qp, hdrs);
		break;
	}
}

static int create_hbuf_pool(struct udp_qp *qp, int scount, int rcount)
{
	int ret;
	struct udp_hbuf *h;
	int size = (scount + rcount) * sizeof *h;
	int i;

	h = memalign(page_size, size);
	if (!h)
		return errno;
	qp->hbufs_mr = ibv_reg_mr(qp->dev->pd, h, size, IBV_ACCESS_LOCAL_WRITE);
	if (!qp->hbufs_mr) {
		ret = errno;
		free(h);
		return ret;
	}
	qp->sq_hbufs = h;
	if (rcount)
		qp->rq_hbufs = &h[scount];
	for (i = 0; i < (scount + rcount) ; i++) {
		h[i].qp = qp;
		h[i].srq = NULL;
		build_hbuf_header(qp, &h[i].hdrs);
	}
	return 0;
}

static struct udp_hbuf *next_sq_hbuf(struct udp_qp *qp)
{
	return &qp->sq_hbufs[qp->sq_idx];
}

static struct udp_hbuf *next_rq_hbuf(struct udp_qp *qp,
					    struct ibv_sge *sge)
{
	sge->addr = (uint64_t)(unsigned long)&qp->rq_hbufs[qp->rq_idx].hdrs.v6;
	sge->lkey = qp->hbufs_mr->lkey;
	sge->length = sizeof(struct udp6_headers);
	return &qp->rq_hbufs[qp->rq_idx];
}

static inline struct udp_hbuf *next_srq_hbuf(struct udp_srq *srq)
{
	return &srq->hbufs[srq->srq_idx];
}

static void inc_sq_idx(struct udp_qp *qp)
{
	if (++qp->sq_idx == qp->send_depth)
		qp->sq_idx = 0;
}

static void dec_sq_idx(struct udp_qp *qp)
{
	if (--qp->sq_idx > qp->send_depth)
		qp->sq_idx = qp->send_depth - 1;
}

static void inc_rq_idx(struct udp_qp *qp)
{
	if (++qp->rq_idx == qp->recv_depth)
		qp->rq_idx = 0;
}

static void inc_srq_idx(struct udp_srq *srq)
{
	if (++srq->srq_idx == srq->depth)
		srq->srq_idx = 0;
}

int udp_dealloc_dev(struct udp_dev *dev)
{
	ibv_dealloc_pd(dev->pd);
	rdma_destroy_id(dev->id);
	rdma_destroy_event_channel(dev->rch);
	free(dev->qpid2ptr);
	free(dev);
	return 0;
}

#define IFI_RTA(p) ((struct rtattr*)(((char*)(p)) + \
		    NLMSG_ALIGN(sizeof(struct ifinfomsg))))

static int get_ifname(struct udp_dev *dev)
{
	struct {
		struct nlmsghdr n;
		struct rtgenmsg r;
	} req;

	int status;
	char buf[16384];
	struct nlmsghdr *nlmp;
	struct ifinfomsg *rtmp;
	struct rtattr *rtap;
	int rtattrlen;
	int found;
	int fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof req.r);
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
	req.n.nlmsg_type = RTM_GETLINK;
	status = send(fd, &req, req.n.nlmsg_len, 0);
	if (status < 0) {
		perror("send");
		return EIO;
	}

	status = recv(fd, buf, sizeof(buf), 0);
	do {
		if (status < 0) {
			perror("recv");
			return EIO;
		}
		if (status == 0) {
			perror("recv EOF");
			return EIO;
		}

		for(nlmp = (struct nlmsghdr *)buf; status > sizeof(*nlmp);) {
			int len = nlmp->nlmsg_len;
			int req_len = len - sizeof(*nlmp);
			unsigned char *hwaddr = NULL;
			char *name = NULL;

			if (req_len < 0 || len > status) {
				printf("reply fmt error\n");
				return EIO;
			}
			if (!NLMSG_OK(nlmp, status)) {
				printf("NLMSG not OK\n");
				return EIO;
			}

			rtmp = (struct ifinfomsg *)NLMSG_DATA(nlmp);
			rtap = (struct rtattr *)IFI_RTA(rtmp);
			rtattrlen = IFA_PAYLOAD(nlmp);
			found = 0;
			for (; RTA_OK(rtap, rtattrlen);
			     rtap = RTA_NEXT(rtap, rtattrlen)) {
				if (rtap->rta_type == IFLA_ADDRESS) {
					hwaddr = (unsigned char *)RTA_DATA(rtap);
					if (!memcmp(hwaddr, dev->hwaddr, 6))
						found = 1;
				}
				if (rtap->rta_type == IFLA_IFNAME) {
					name = (char *)RTA_DATA(rtap);
				}
			}
			assert(hwaddr && name);
			if (found) {
				strcpy(dev->ifname, name);
				close(fd);
				return 0;
			}
			status -= NLMSG_ALIGN(len);
			nlmp = (struct nlmsghdr*)((char*)nlmp + NLMSG_ALIGN(len));
		}
		status = recv(fd, buf, sizeof(buf), 0);
		if (status < 0 && errno == EAGAIN)
			break;
	} while (1);
	close(fd);
	return ENODEV;
}

int udp_alloc_dev(struct sockaddr_in *sin, struct sockaddr_in6 *sin6, struct udp_dev **devp)
{
	struct udp_dev *dev;
	struct rdma_event_channel *rch;
	struct rdma_cm_id *id;
	int ret;
	struct ibv_device_attr attr;
	int i;
	union ibv_gid gid;
	struct sockaddr *sa;

	dev = calloc(1, sizeof *dev);
	if (!dev) {
		ret = ENOMEM;
		goto out;
	}

	dev->sin = *sin;
	dev->sin6 = *sin6;

	if (sin->sin_addr.s_addr != INADDR_ANY)
		sa = (struct sockaddr *)sin;
	else
		sa = (struct sockaddr *)sin6;

	rch = rdma_create_event_channel();
	if (!rch) {
		ret = ENOMEM;
		goto err1;
	}
	ret = rdma_create_id(rch, &id, NULL, RDMA_PS_TCP);
	if (ret) {
		ret = -ret;
		goto err2;
	}
	ret = rdma_bind_addr(id, sa);
	if (ret) {
		ret = -ret;
		goto err3;
	}

	ret = ibv_query_device(id->verbs, &attr);
	if (attr.vendor_id != UDP_CHELSIO_VID) {
		ret = ENODEV;
		goto err3;
	}
	for (i = 0; partids[i]; i++)
		if (attr.vendor_part_id == partids[i])
			break;
	if (partids[i] == 0) {
		ret = ENODEV;
		goto err3;
	}
	dev->nfids = attr.max_map_per_fmr; /* XXX */

	dev->qpid2ptr = calloc(attr.max_qp, sizeof *dev->qpid2ptr);
	if (!dev->qpid2ptr) {
		ret = ENOMEM;
		goto err3;
	}

	ret = ibv_query_gid(id->verbs, id->port_num, 0, &gid);
	if (ret)
		goto err4;

	dev->pd = ibv_alloc_pd(id->verbs);
	if (!dev->pd) {
		ret = errno;
		goto err4;
	}

	memcpy(dev->hwaddr, gid.raw, 6);
	ret = get_ifname(dev);
	if (ret)
		goto err4;
	dev->verbs = id->verbs;
	dev->port_num = id->port_num;
	dev->id = id;
	dev->rch = rch;
	*devp = dev;
	goto out;
err4:
	free(dev->qpid2ptr);
err3:
	rdma_destroy_id(id);
err2:
	rdma_destroy_event_channel(rch);
err1:
	free(dev);
out:
	return ret;
}

int udp_stop_dev(struct udp_dev *dev)
{
	return 0;
}

int udp_start_dev(struct udp_dev *dev, struct ibv_cq *frag_cq)
{
	int ret = 0;
	dev->pd = ibv_alloc_pd(dev->verbs);
	if (!dev->pd) {
		ret = errno;
	}
	return ret;
}

int udp_destroy_srq(struct udp_srq *srq)
{
	ibv_destroy_srq(srq->raw_srq);
	destroy_srq_hbuf_pool(srq);
	pthread_spin_destroy(&srq->lock);
	free(srq);
 	return 0;
}

int udp_create_srq(struct udp_dev *dev, int depth, uint32_t flags, struct udp_srq **srqp)
{
	struct udp_srq *srq;
	struct ibv_srq_init_attr init_attr = {
		.srq_context = dev,
		.attr = {
			.max_wr = depth,
			.max_sge = UDP_MAX_SGE + 1,
		},
	};
	struct ibv_srq_attr attr;
	int ret;

	srq = calloc(1, sizeof *srq);
	if (!srq) {
 		ret = errno;
		goto err0;
 	}
	srq->dev = dev;
	srq->packed = !!(flags & UDP_PACKED_MODE);

	/*
	 * Overload bits 3:0  of srq_limit for the port number.
	 * Overload bit 4:4 to indicate packed mode.
	 */
	init_attr.attr.srq_limit = dev->port_num,
	init_attr.attr.srq_limit |= srq->packed << 4;
	srq->raw_srq = ibv_create_srq(dev->pd, &init_attr);
	if (!srq->raw_srq) {
 		ret = errno;
		goto err1;
 	}

	/*
	 * Get the qid for the srq (returned in srq_attr.srq_limit XXX)
	 */
	ret = ibv_query_srq(srq->raw_srq, &attr);
 	if (ret) {
		ret = errno;
		goto err2;
 	}
	srq->iqid = attr.srq_limit;
	ret = create_srq_hbuf_pool(srq, depth);
 	if (ret) {
		goto err2;
 	}

	srq->depth = depth;
	pthread_spin_init(&srq->lock, PTHREAD_PROCESS_PRIVATE);
	*srqp = srq;
	return 0;

err2:
	ibv_destroy_srq(srq->raw_srq);
err1:
	free(srq);
err0:
 	return ret;

}

int udp_poll_frag(struct udp_dev *dev, uint8_t *buf, int *len)
{
	return 0;
}

int udp_destroy_qp(struct udp_qp *qp)
{
	if (qp->srq)
		SLIST_REMOVE(&qp->srq->qps, qp, udp_qp, srq_list);
	qp->dev->qpid2ptr[qp->raw_qp->qp_num] = NULL;
	ibv_destroy_qp(qp->raw_qp);
	destroy_hbuf_pool(qp);
	pthread_spin_destroy(&qp->lock);
	free(qp);
	return 0;
}

int udp_create_qp(struct udp_dev *dev, struct ibv_cq *send_cq,
		  struct ibv_cq *recv_cq, int send_depth, int recv_depth, struct udp_srq *srq,
		  struct sockaddr *laddr, struct sockaddr *raddr,
		  uint16_t vlan, uint8_t pri, uint32_t flags,
		  struct udp_qp **qpp)
{
	struct udp_qp *qp;
	struct ibv_qp_init_attr attr = {
		.send_cq = send_cq,
		.recv_cq = recv_cq,
		.cap = {
			.max_send_wr = send_depth,
			.max_recv_wr = recv_depth,
			.max_send_sge = UDP_MAX_SGE + 1,
			.max_recv_sge = UDP_MAX_SGE + 1,
			.max_inline_data = udp_max_inline(laddr->sa_family),
		},
		.qp_type = IBV_QPT_RAW_ETH,
		.sq_sig_all = ((((pri & 7) << 13) | (vlan & 0xfff)) << 16) |
			      dev->port_num << 8
	};
	struct ibv_qp_attr attr2 = {
		.qp_state = IBV_QPS_RTS,
		.port_num = dev->port_num
	};
	int ret;

	if (srq) {
		if (recv_depth)
			return EINVAL;
		attr.srq = srq->raw_srq;
	}
	qp = calloc(1, sizeof *qp);
	if (!qp)
		return ENOMEM;
	qp->dev = dev;

	/*
	 * Save the actual bound address for the filter.
	 */
	sa_copy(&qp->bound_addr.sa, laddr);

	/*
	 * if the laddr passed in is unspecified, then use the device
	 * ipaddress as the egress source ipaddr.
	 */
	if (laddr->sa_family == AF_INET) {
		if (sa_sin(laddr)->sin_addr.s_addr == INADDR_ANY ||
		    sa_is_mcast(laddr))
			sa_copy(&qp->laddr.sa, sa_sa(&qp->dev->sin));
		else
			sa_copy(&qp->laddr.sa, laddr);
	} else {
		if (IN6_IS_ADDR_UNSPECIFIED(sa_sin6(laddr)->sin6_addr.s6_addr) ||
		    sa_is_mcast(laddr))
			sa_copy(&qp->laddr.sa, sa_sa(&qp->dev->sin6));
		else
			sa_copy(&qp->laddr.sa, laddr);
	}
	sa_copy(&qp->raddr.sa, raddr);
#ifdef DEBUG
{
	char p1[64], p2[64], p3[64];
	const char *cp1, *cp2, *cp3;
	cp1 = inet_ntop(laddr->sa_family, sa_addr(&qp->laddr.sa), p1, sizeof p1);
	cp2 = inet_ntop(raddr->sa_family, sa_addr(&qp->bound_addr.sa), p2, sizeof p2);
	cp3 = inet_ntop(raddr->sa_family, sa_addr(&qp->raddr.sa), p3, sizeof p3);
	DBG(DBG_UM, "QP dev_laddr %s bound_laddr %s raddr %s\n", cp1, cp2, cp3);
}
#endif
	qp->udp_port = sa_port(laddr);
	qp->packed = !!(flags & UDP_PACKED_MODE);
	qp->v6only = !!(flags & UDP_IPV6ONLY);

	/*
	 * Overload bits 3:1 with the number
	 * of filters needed.  IPv4 needs 1,
	 * IPv6 needs 4 if v6only and 5 otherwise.
	 */
	if (laddr->sa_family == AF_INET)
		attr.sq_sig_all |= 1<<1;
	else if (qp->v6only)
		attr.sq_sig_all |= 4<<1;
	else
		attr.sq_sig_all |= 5<<1;

	/*
	 * Overload bit 4:4 to indicate packed mode.
	 */
	attr.sq_sig_all |= qp->packed << 4;

	qp->raw_qp = ibv_create_qp(dev->pd, &attr);
	if (!qp->raw_qp) {
		printf("ibv_create_qp failed\n");
		ret = errno;
		goto err1;
	}

	ret = ibv_modify_qp(qp->raw_qp, &attr2, IBV_QP_STATE|IBV_QP_PORT);
	if (ret) {
		goto err2;
	}

	ret = ibv_query_qp(qp->raw_qp, &attr2, IBV_QP_RQ_PSN|IBV_QP_SQ_PSN, NULL);
	if (ret) {
		goto err2;
	}
	qp->fid = attr2.rq_psn;
	qp->iqid = attr2.sq_psn;

	ret = create_hbuf_pool(qp, send_depth, recv_depth);
	if (ret)
		goto err2;
	qp->send_depth = send_depth;
	qp->recv_depth = recv_depth;
	qp->vlan = vlan;
	pthread_spin_init(&qp->lock, PTHREAD_PROCESS_PRIVATE);
	*qpp = qp;
	dev->qpid2ptr[qp->raw_qp->qp_num] = qp;

	if (srq) {
		qp->srq = srq;
		SLIST_INSERT_HEAD(&srq->qps, qp, srq_list);
	}

	goto out;

	destroy_hbuf_pool(qp);
err2:
	ibv_destroy_qp(qp->raw_qp);
err1:
	free(qp);
out:
	return ret;
}

static void build_v6_headers(struct udp_qp *qp, struct udp_send_wr *wr, struct ibv_send_wr *raw_wr,
			     struct udp_hbuf *h, uint8_t **eth_dhost, uint8_t **src_ip)
{
	int plen;
	struct udp6_headers *header;
	int i;

	if (wr->send_flags & UDP_SEND_HDR_ROOM) {
		raw_wr->num_sge = wr->num_sge;
		plen = 0;
		for (i = 0; i < wr->num_sge; i++) {
			raw_wr->sg_list[i] = wr->sg_list[i];
			plen += wr->sg_list[i].length;
		}
		raw_wr->sg_list[0].addr -= sizeof *header;
		raw_wr->sg_list[0].length += sizeof *header;
		header = (struct udp6_headers *)(intptr_t)raw_wr->sg_list[0].addr;
		memcpy(header->eth.ether_shost, qp->dev->hwaddr, 6);
		header->eth.ether_type = htons(ETH_P_IPV6);
		header->ip.ip6_flow = htonl(0x60000000);
		header->ip.ip6_hlim = 64;
		header->ip.ip6_nxt = IPPROTO_UDP;
		memcpy(header->ip.ip6_src.s6_addr, qp->laddr.sin6.sin6_addr.s6_addr, 16);
	} else {
		raw_wr->num_sge = wr->num_sge + 1;
		raw_wr->sg_list[0].addr = (uint64_t)(unsigned long)&h->hdrs.v6;
		raw_wr->sg_list[0].lkey = qp->hbufs_mr->lkey;
		raw_wr->sg_list[0].length = sizeof(struct udp6_headers);
		plen = 0;
		for (i = 0; i < wr->num_sge; i++) {
			raw_wr->sg_list[i+1] = wr->sg_list[i];
			plen += wr->sg_list[i].length;
		}
		header = (struct udp6_headers *)&h->hdrs.v6;
	}
	header->udp.source = qp->udp_port;
	header->ip.ip6_plen = htons(plen + sizeof header->udp);
	memcpy(header->ip.ip6_dst.s6_addr, sa_sin6(wr->peer)->sin6_addr.s6_addr, 16);
	header->udp.dest = sa_sin6(wr->peer)->sin6_port;
	header->udp.len = htons(plen + sizeof header->udp);
	raw_wr->send_flags |= IBV_SEND_IP6_CSUM;
	qp->stats.tx_pkts++;
	qp->stats.tx_bytes += sizeof *header + plen;
	*eth_dhost = header->eth.ether_dhost;
	if (IN6_IS_ADDR_UNSPECIFIED(qp->bound_addr.sin6.sin6_addr.s6_addr)) {
		*src_ip = header->ip.ip6_src.s6_addr;
	} else {
		*src_ip = NULL;
	}
	return;
}

static void build_v4_headers(struct udp_qp *qp, struct udp_send_wr *wr,
			     struct ibv_send_wr *raw_wr, struct udp_hbuf *h,
			     uint32_t daddr, uint16_t dport, uint8_t **eth_dhost, uint8_t **src_ip)
{
	int plen;
	struct udp4_headers *header;
	int i;


	if (wr->send_flags & UDP_SEND_HDR_ROOM) {
		raw_wr->num_sge = wr->num_sge;
		plen = 0;
		for (i = 0; i < wr->num_sge; i++) {
			raw_wr->sg_list[i] = wr->sg_list[i];
			plen += wr->sg_list[i].length;
		}
		raw_wr->sg_list[0].addr -= sizeof *header;
		raw_wr->sg_list[0].length += sizeof *header;
		header = (struct udp4_headers *)(uintptr_t)raw_wr->sg_list[0].addr;
		memcpy(header->eth.ether_shost, qp->dev->hwaddr, 6);
		header->eth.ether_type = htons(ETHERTYPE_IP);
		header->ip.version = 4;
		header->ip.ihl = 5;
		header->ip.tos = 0;
		header->ip.id = 0;
		header->ip.frag_off = ntohs(IP_DF);
		header->ip.ttl = 64;
		header->ip.protocol = IPPROTO_UDP;
		header->ip.saddr = qp->laddr.sin.sin_addr.s_addr;
	} else {
		raw_wr->num_sge = wr->num_sge + 1;
		raw_wr->sg_list[0].addr = (uint64_t)(unsigned long)&h->hdrs.v4;
		raw_wr->sg_list[0].lkey = qp->hbufs_mr->lkey;
		raw_wr->sg_list[0].length = sizeof(struct udp4_headers);
		plen = 0;
		for (i = 0; i < wr->num_sge; i++) {
			raw_wr->sg_list[i+1] = wr->sg_list[i];
			plen += wr->sg_list[i].length;
		}
		header = (struct udp4_headers *)&h->hdrs.v4;
	}
	header->udp.source = qp->udp_port;
	header->ip.tot_len = htons(sizeof *header + plen - sizeof header->eth);
	header->ip.daddr = daddr;
	header->udp.dest = dport;
	header->udp.len = htons(plen + sizeof header->udp);
	raw_wr->send_flags |= IBV_SEND_IP_CSUM;
	qp->stats.tx_pkts++;
	qp->stats.tx_bytes += sizeof *header + plen;
	*eth_dhost = header->eth.ether_dhost;
	if (qp->bound_addr.sin.sin_addr.s_addr == INADDR_ANY) {
		*src_ip = (uint8_t *)&header->ip.saddr;
	} else
		*src_ip = NULL;
	return;
}

static void build_headers(struct udp_qp *qp, struct udp_send_wr *wr, struct ibv_send_wr *raw_wr,
			  struct udp_hbuf *h, uint8_t **eth_dhost, uint8_t **src_ip)
{

	switch (qp->laddr.sa.sa_family) {
	case AF_INET:
		build_v4_headers(qp, wr, raw_wr, h, sa_sin(wr->peer)->sin_addr.s_addr,
				 sa_sin(wr->peer)->sin_port, eth_dhost, src_ip);
		break;
	case AF_INET6:
		if (IN6_IS_ADDR_V4MAPPED(sa_sin6(wr->peer)->sin6_addr.s6_addr))
			build_v4_headers(qp, wr, raw_wr, h, 
					 *(uint32_t *)&sa_sin6(wr->peer)->sin6_addr.s6_addr[12],
					 sa_sin6(wr->peer)->sin6_port, eth_dhost, src_ip);
		else
			build_v6_headers(qp, wr, raw_wr, h, eth_dhost, src_ip);
		break;
	}
	return;
}

int udp_post_send(struct udp_qp *qp, struct udp_send_wr *wr)
{
	struct ibv_send_wr raw_wr, *bad_raw_wr;
	struct ibv_sge sge[UDP_MAX_SGE + 1];
	struct udp_hbuf *h;
	uint8_t *eth_dhost;
	uint8_t *ip_src;
	int ret;

	if (wr->num_sge > UDP_MAX_SGE)
		return EINVAL;
	if (qp->send_count == qp->send_depth) {
		return ENOSPC;
	}

	raw_wr.next = NULL;
	raw_wr.send_flags = to_ibv_send_flags(wr->send_flags);
	raw_wr.opcode = IBV_WR_SEND;
	raw_wr.sg_list = sge;

	h = next_sq_hbuf(qp);
	h->cookie = wr->wr_id;
	h->wc_count = 1;
	if (wr->send_flags & IBV_SEND_SIGNALED) {
		h->wc_count += qp->sq_pending_count;
		qp->sq_pending_count = 0;
	} else
		qp->sq_pending_count++;
	raw_wr.wr_id = (uint64_t)(unsigned long)h;

	build_headers(qp, wr, &raw_wr, h, &eth_dhost, &ip_src);
	ret = get_route_addrs(wr->peer, eth_dhost, ip_src);
	if (ret) {
		return ret;
	}
	ret = ibv_post_send(qp->raw_qp, &raw_wr, &bad_raw_wr);
	if (!ret) {
		inc_sq_idx(qp);
		qp->send_count++;
		assert(qp->send_count <= qp->send_depth);
	}
	return ret;
}

int udp_post_send_many(struct udp_qp *qp, struct udp_send_wr *wr, int count)
{
	struct ibv_send_wr raw_wr[count], *bad_raw_wr;
	struct ibv_sge sge[count][UDP_MAX_SGE + 1];
	struct udp_hbuf *h;
	int i, j;
	int ret;
	uint8_t *eth_dhost, *src_ip;

	for (i = 0; i < count; i++) {
		if (wr->num_sge > UDP_MAX_SGE)
			return EINVAL;
		if (qp->send_count == qp->send_depth)
			return ENOSPC;

		raw_wr[i].send_flags = to_ibv_send_flags(wr->send_flags);
		raw_wr[i].opcode = IBV_WR_SEND;
		raw_wr[i].sg_list = &sge[i][0];

		h = next_sq_hbuf(qp);
		h->cookie = wr->wr_id;
		h->wc_count = 1;
		if (wr->send_flags & IBV_SEND_SIGNALED) {
			h->wc_count += qp->sq_pending_count;
			qp->sq_pending_count = 0;
		} else
			qp->sq_pending_count++;
		raw_wr[i].wr_id = (uint64_t)(unsigned long)h;

		build_headers(qp, wr, &raw_wr[i], h, &eth_dhost, &src_ip);
		ret = get_route_addrs(wr->peer, eth_dhost, src_ip);
		if (ret) {
			return ret;
		}
		raw_wr[i].next = (i == (count - 1)) ? NULL : &raw_wr[i+1];
		wr++;
		inc_sq_idx(qp);
		qp->send_count++;
		assert(qp->send_count <= qp->send_depth);
	}
	ret = ibv_post_send(qp->raw_qp, &raw_wr[0], &bad_raw_wr);
	if (ret) {
		j = 1 +
		    ((unsigned long)bad_raw_wr - (unsigned long)&raw_wr[0]) /
		    sizeof raw_wr[0];
		for (i = 0; i < j; i++) {
			dec_sq_idx(qp);
			qp->send_count--;
		}
		assert(qp->send_count <= qp->send_depth);
	}
	return ret;
}


int udp_post_srq_recv(struct udp_srq *srq, struct udp_recv_wr *wr)
{
	struct ibv_recv_wr raw_wr, *bad_raw_wr;
	struct udp_hbuf *h;
	struct udp_qp *qp;
	int ret;

	if (wr->num_sge > UDP_MAX_SGE)
		return EINVAL;
	if (srq->count == srq->depth)
		return ENOSPC;

	if (srq->count == 8) {
		SLIST_FOREACH(qp, &srq->qps, srq_list) {
			ret = set_udp_filter(qp);
			if (ret) {
				DBG(DBG_RECV, "set_udp_filter err %d\n", ret);
				return EIO;
			}
		}
	}

	raw_wr.wr_id = wr->wr_id;
	raw_wr.next = NULL;
	raw_wr.sg_list = wr->sg_list;
	raw_wr.num_sge = wr->num_sge;

	h = next_srq_hbuf(srq);
	h->cookie = wr->wr_id;
	h->hdrp = (uint8_t *)(uintptr_t)wr->sg_list->addr;
	raw_wr.wr_id = (uint64_t)(unsigned long)h;

	ret = ibv_post_srq_recv(srq->raw_srq, &raw_wr, &bad_raw_wr);
	if (!ret) {
		inc_srq_idx(srq);
		srq->count++;
		assert(srq->count <= srq->depth);
	}
	return ret;
}

int udp_post_recv(struct udp_qp *qp, struct udp_recv_wr *wr)
{
	struct ibv_recv_wr raw_wr, *bad_raw_wr;
	struct ibv_sge sge[UDP_MAX_SGE + 1];
	struct udp_hbuf *h;
	int ret;

	if (wr->num_sge > UDP_MAX_SGE)
		return EINVAL;
	if (qp->recv_count == qp->recv_depth)
		return ENOSPC;

	if (qp->recv_count == 8) {
		ret = set_udp_filter(qp);
		if (ret) {
			DBG(DBG_RECV, "set_udp_filter ret %d\n", ret);
			return EIO;
		}
	}

	raw_wr.wr_id = wr->wr_id;
	raw_wr.next = NULL;
	raw_wr.num_sge = wr->num_sge + 1;
	raw_wr.sg_list = sge;

	h = next_rq_hbuf(qp, &sge[0]);
	h->cookie = wr->wr_id;
	raw_wr.wr_id = (uint64_t)(unsigned long)h;

	h->hdrp = (uint8_t *)(uintptr_t)wr->sg_list->addr;
	raw_wr.sg_list = wr->sg_list;
	raw_wr.num_sge = wr->num_sge;

	ret = ibv_post_recv(qp->raw_qp, &raw_wr, &bad_raw_wr);
	if (!ret) {
		inc_rq_idx(qp);
		qp->recv_count++;
		assert(qp->recv_count <= qp->recv_depth);
	}
	return ret;
}

static struct udphdr *parse_v6header(struct udp_qp *qp, void *addr, struct sockaddr *from)
{
	struct udp6_headers *hdr = addr;
	struct sockaddr_in6 *sin6p;

	/*
	 * If the packet is IPv4, then do the mapped magic.
	 */
	if (ntohs(hdr->eth.ether_type) == ETHERTYPE_IP) {
		struct udp4_headers *hdr4 = addr;

		if (from) {
			sin6p = (struct sockaddr_in6 *)from;
			memset(sin6p, 0, sizeof *sin6p);
			sin6p->sin6_family = AF_INET6;
			memset(&sin6p->sin6_addr.s6_addr[10], 0xff, 2);
			memcpy(&sin6p->sin6_addr.s6_addr[12], &hdr4->ip.saddr, 4);
			sin6p->sin6_port = hdr4->udp.source;
		}
		return &hdr4->udp;
	}
	if (from) {
		sin6p = (struct sockaddr_in6 *)from;
		memset(sin6p, 0, sizeof *sin6p);
		sin6p->sin6_family = AF_INET6;
		memcpy(sin6p->sin6_addr.s6_addr, hdr->ip.ip6_src.s6_addr, 16);
		sin6p->sin6_port = hdr->udp.source;
	}
	return &hdr->udp;
}

static struct udphdr *parse_v4header(struct udp_qp *qp, void *addr, struct sockaddr *from)
{

	struct udp4_headers *hdr = addr;
	struct sockaddr_in *sinp;

	if (from) {
		sinp = (struct sockaddr_in *)from;
		memset(sinp, 0, sizeof *sinp);
		sinp->sin_family = AF_INET;
		sinp->sin_addr.s_addr = hdr->ip.saddr;
		sinp->sin_port = hdr->udp.source;
	}
	return &hdr->udp;
}

static struct udphdr *parse_header(struct udp_qp *qp, void *addr, struct sockaddr *from)
{
	struct udphdr *udp = NULL;

	switch (qp->laddr.sa.sa_family) {
	case AF_INET:
		udp = parse_v4header(qp, addr, from);
		break;
	case AF_INET6:
		udp = parse_v6header(qp, addr, from);
		break;
	}
	assert(udp);
	return udp;
}

int udp_poll_cq(struct ibv_cq *cq, struct ibv_wc *wc, struct sockaddr *from, int flags)
{
	int ret;
	struct udp_hbuf *h;
	struct udphdr *udp;
	int nopeek = !(flags & MSG_PEEK);
	int off;

	ret = ibv_poll_cq(cq, nopeek ? 1 : -1, wc);
	if (ret == 0) {
		return ENODATA;
	}
	if (ret < 0)
		return EIO;

	h = (struct udp_hbuf *)(uintptr_t)wc->wr_id;
	prefetch(h->hdrp);
	wc->wr_id = h->cookie;

	if (wc->sl) {
		off = 0;
		h->off = 0;
	} else {
		off = h->off;
	}

	if (!wc->status && wc->opcode == IBV_WC_RECV) {
		struct udp_qp *qp;

		if (h->srq) {
			qp = h->srq->dev->qpid2ptr[wc->qp_num];
			assert(qp);
		} else
			qp = h->qp;

		udp = parse_header(qp, h->hdrp + off + 2, from);
		qp->stats.rx_pkts++;
		qp->stats.rx_bytes += wc->byte_len;
		if (nopeek)
			h->off += ALIGN(wc->byte_len + 2, 64);
		wc->byte_len = ntohs(udp->len) - sizeof *udp;
	}
	if (wc->opcode == IBV_WC_SEND) {
		assert(!h->srq);
		h->qp->send_count -= h->wc_count;
		assert(h->qp->send_count <= h->qp->send_depth);
	} else {
		if (nopeek) {
			if (h->srq) {
				if (!h->srq->packed)
					h->srq->count--;
				else if (wc->sl) {
					if (h->srq->first_skipped) {
						h->srq->count--;
					} else {
						h->srq->first_skipped = 1;
					}
				}
			} else {
				if (!h->qp->packed)
					h->qp->recv_count--;
				else if (wc->sl) {
					if (h->qp->first_skipped)
						h->qp->recv_count--;
					else
						h->qp->first_skipped = 1;
				}
			}
		}

		if (h->qp) {
			assert(h->qp->recv_count <= h->qp->recv_depth);
			if (h->qp->recv_count == 0)
				clear_udp_filter(h->qp);
		} else {
			if (h->srq->count == 0) {
				struct udp_qp *qp;

				SLIST_FOREACH(qp, &h->srq->qps, srq_list) {
					ret = clear_udp_filter(qp);
					if (ret)
						return EIO;
				}
			}
			assert(h->srq);
			assert(h->srq->count <= h->srq->depth);
		}
	}
	return 0;
}

int udp_attach_mcast(struct udp_qp *qp, struct sockaddr *sa)
{
	union ibv_gid gid = { .global = { 0, 0} };

	map_ip_mcast(sa_sin(sa)->sin_addr.s_addr, gid.raw);
	return ibv_attach_mcast(qp->raw_qp, &gid, 0);
}

int udp_detach_mcast(struct udp_qp *qp, struct sockaddr *sa)
{
	union ibv_gid gid = { .global = { 0, 0} };

	map_ip_mcast(sa_sin(sa)->sin_addr.s_addr, gid.raw);
	return ibv_detach_mcast(qp->raw_qp, &gid, 0);
}

void __attribute__ ((constructor)) udp_init(void)
{

	page_size = sysconf(_SC_PAGESIZE);
	pthread_spin_init(&lock, PTHREAD_PROCESS_PRIVATE);

#ifdef DEBUG
{
	char *c;
	c = getenv("CXGB4_UDP_DEBUG");
	if (c) {
		dbg_flags = strtol(c, NULL, 0);
		DBG(DBG_INIT, "dbg_flags 0x%x\n", dbg_flags);
	}
	c = getenv("CXGB4_UDP_DEBUG_FILE");
	if (c) {
		if (!strncmp(c, "syslog", strlen("syslog"))) {
			dbg_dst = DBG_DST_SYSLOG;
		} else if (!strncmp(c, "stdout", strlen("stdout"))) {
			dbg_dst = DBG_DST_STDOUT;
			dbg_file = stdout;
		} else if (!strncmp(c, "stderr", strlen("stdout"))) {
			dbg_dst = DBG_DST_STDERR;
			dbg_file = stderr;
		} else {
			dbg_dst = DBG_DST_FILE;
			dbg_file = fopen(c, "a");
			if (!dbg_file) {
				perror("fopen() of log file");
				dbg_dst = DBG_DST_SYSLOG;
				DBG(DBG_INIT, "Using syslog...\n");
			}
		}

		DBG(DBG_INIT, "dbg_flags 0x%x dbg_dst %s\n", dbg_flags, c);
	}
}
#endif
}

void __attribute__ ((destructor)) udp_fini(void)
{
	pthread_spin_destroy(&lock);
}
