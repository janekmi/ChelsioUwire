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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/epoll.h>

#include <arpa/inet.h>

#include <netinet/tcp.h>
#include <netinet/in.h>

#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/ethtool.h>

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <fcntl.h>
#include <signal.h>
#include <malloc.h>

#include "libcxgb4_sock.h"

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

#ifdef DEBUG
static char *myinet_ntoa(in_addr_t a)
{
	struct in_addr ina;
	ina.s_addr = a;
	return inet_ntoa(ina);
}
#endif

static int get_route6(uint8_t *dst)
{
	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[1024];
	} req;

	struct rtattr *rta;
	struct rtmsg *r;
	int len = 16;
	int fd = lsocket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	int status;
	int ifindex = -1;

#ifdef DEBUG
{
	char p[INET6_ADDRSTRLEN];
	DBG(DBG_ROUTE, "Enter dst %s\n", inet_ntop(AF_INET6, dst, p, sizeof p));
}
#endif
	memset(&req, 0, sizeof req);
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_GETROUTE;
	req.r.rtm_family = AF_INET6;
	req.r.rtm_dst_len = len;
	req.r.rtm_table = RT_TABLE_DEFAULT;
	req.r.rtm_type = RTN_UNSPEC;
	req.r.rtm_scope = RT_SCOPE_UNIVERSE;
	rta = NLMSG_TAIL(&req.n);
	rta->rta_type = RTA_DST;
	rta->rta_len = RTA_LENGTH(len);
	memcpy(RTA_DATA(rta), dst, len);
	req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + RTA_ALIGN(RTA_LENGTH(len));

	status = lsend(fd, &req, req.n.nlmsg_len, 0);
	if (status < 0) {
		DBG(DBG_ROUTE, "rtm send err %d", errno);
		return -1;
	}

	status = lrecv(fd, &req, sizeof req, 0);
	while (1) {
		if (status < 0) {
			DBG(DBG_ROUTE, "rtm recv err %d", errno);
			return -1;
		}
		if(status == 0){
			DBG(DBG_ROUTE, "rtm recv 0 bytes");
			return -1;
		}

		r = NLMSG_DATA(&req.n);
		len = RTM_PAYLOAD(&req.n);
		rta = RTM_RTA(r);
		for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
			switch (rta->rta_type) {
			case RTA_DST: {
#ifdef DEBUG
				char p[INET6_ADDRSTRLEN];
				DBG(DBG_ROUTE, "RTA_DST %s\n", inet_ntop(AF_INET6, (uint8_t *)RTA_DATA(rta), p, sizeof p));
#endif
				break;
			}
			case RTA_OIF:
				ifindex = *((int *)RTA_DATA(rta));
				break;
			default:
				break;
			}
		}
		status = lrecv(fd, &req, sizeof req, MSG_DONTWAIT);
		if (status < 0 && errno == EAGAIN)
			break;
	}
	lclose(fd);
	return ifindex;
}

static int get_route(in_addr_t dst)
{
	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[256];
	} req;

	struct rtattr *rta;
	struct rtmsg *r;
	int len = RTA_LENGTH(4);
	int fd = lsocket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	int status;
	int ifindex = -1;

	DBG(DBG_ROUTE, "Enter dst %s\n", myinet_ntoa(dst));
	memset(&req, 0, sizeof req);
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_GETROUTE;
	req.r.rtm_family = AF_INET;
	req.r.rtm_dst_len = 32;
	req.r.rtm_table = RT_TABLE_DEFAULT;
	req.r.rtm_type = RTN_UNSPEC;
	req.r.rtm_scope = RT_SCOPE_UNIVERSE;
	rta = NLMSG_TAIL(&req.n);
	rta->rta_type = RTA_DST;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), &dst, 4);
	req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + RTA_ALIGN(len);

	status = lsend(fd, &req, req.n.nlmsg_len, 0);
	if (status < 0) {
		DBG(DBG_ROUTE, "rtm send err %d", errno);
		return -1;
	}

	status = lrecv(fd, &req, sizeof req, 0);
	while (1) {
		if (status < 0) {
			DBG(DBG_ROUTE, "rtm recv err %d", errno);
			return -1;
		}
		if(status == 0){
			DBG(DBG_ROUTE, "rtm recv 0 bytes");
			return -1;
		}

		r = NLMSG_DATA(&req.n);
		len = RTM_PAYLOAD(&req.n);
		rta = RTM_RTA(r);
		for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
			switch (rta->rta_type) {
			case RTA_DST: {
				assert(*((in_addr_t *)RTA_DATA(rta)) == dst);
				break;
			}
			case RTA_OIF:
				ifindex = *((int *)RTA_DATA(rta));
				break;
			default:
				break;
			}
		}
		status = lrecv(fd, &req, sizeof req, MSG_DONTWAIT);
		if (status < 0 && errno == EAGAIN)
			break;
	}
	lclose(fd);
	return ifindex;
}

static int route6_ours(struct cs_context *c, const struct sockaddr *sa)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

	if (IN6_IS_ADDR_MULTICAST(sin6->sin6_addr.s6_addr) && c->mcast_if)
		return 1;
	if (IN6_ARE_ADDR_EQUAL(c->rtcache_in6, sin6->sin6_addr.s6_addr))
		return c->rtcache_answer;
	memcpy(c->rtcache_in6, sin6->sin6_addr.s6_addr, 16);
	c->rtcache_answer = c->chelsio_dev->ifindex == get_route6(c->rtcache_in6);
	return c->rtcache_answer;
}

static int route4_ours(struct cs_context *c, const struct sockaddr *sa)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;

	if (IN_MULTICAST(ntohl(sa_ipaddr(sa))) && c->mcast_if)
		return 1;
	if (c->rtcache_in == sin->sin_addr.s_addr)
		return c->rtcache_answer;
	c->rtcache_in = sin->sin_addr.s_addr;
	c->rtcache_answer = c->chelsio_dev->ifindex == get_route(c->rtcache_in);
	return c->rtcache_answer;
}

int route_ours(struct cs_context *c, const struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return route4_ours(c, sa);
		break;
	case AF_INET6:
		return route6_ours(c, sa);
		break;
	}
	abort();
	return EIO;
}

static STAILQ_HEAD(, chelsio_dev) chelsio_devs =
				  STAILQ_HEAD_INITIALIZER(chelsio_devs);

static void add_chelsio_dev(int ifindex, uint8_t *v4addr, uint8_t *v6addr, char *name,
			    uint8_t *hwaddr, int mtu)
{
	struct chelsio_dev *dev;
	struct sockaddr_in *sinp;
	struct sockaddr_in6 *sin6p;

	dev = calloc(1, sizeof *dev);
	dev->ifindex = ifindex;
	dev->mtu = mtu;

	sinp = (struct sockaddr_in *)&dev->ipv4addr;
	sinp->sin_family = AF_INET;
	sinp->sin_port = 0;
	memcpy(&sinp->sin_addr.s_addr, v4addr, 4);

	sin6p = (struct sockaddr_in6 *)&dev->ipv6addr;
	sin6p->sin6_family = AF_INET6;
	sin6p->sin6_port = 0;
	memcpy(sin6p->sin6_addr.s6_addr, v6addr, 16);

	memcpy(dev->hwaddr, hwaddr, IFHWADDRLEN);
	memcpy(dev->name, name, IFNAMSIZ);
	STAILQ_INSERT_TAIL(&chelsio_devs, dev, list);
}

static int ethtool_call(const char *iff_name, void *data)
{
	struct ifreq ifr;
	int fd;
	int ret;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		printf("Cannot get control socket \n");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iff_name, sizeof(ifr.ifr_name) - 1);
	ifr.ifr_data = data;
	ret = ioctl(fd, SIOCETHTOOL, &ifr);
	close(fd);
	return ret;
}

static int get_link_name(int link, char *link_name)
{

	struct ifreq ifr;
	int fd;
	int ret;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		printf("Cannot get control socket \n");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = link;
	ret = ioctl(fd, SIOCGIFNAME, &ifr);
	if (!ret)
		memcpy(link_name, ifr.ifr_name, IFNAMSIZ);
	close(fd);
	return ret;
}

static int is_cxgb4_device(const char *iff_name, int link)
{
	struct ethtool_drvinfo drvinfo = {0};	
	char link_name[IFNAMSIZ];

	drvinfo.cmd = ETHTOOL_GDRVINFO;
	if (ethtool_call(iff_name, &drvinfo))
		return 0;
	if (!strncmp("cxgb4", drvinfo.driver, 5))
		return 1;

	if (link >= 0) {
		if (get_link_name(link, link_name))
			return 0;

		DBG(DBG_ROUTE, "Parent ifname |%s|\n", link_name);
		drvinfo.cmd = ETHTOOL_GDRVINFO;
		if (ethtool_call(link_name, &drvinfo))
			return 0;
		if (!strncmp("cxgb4", drvinfo.driver, 5))
			return 1;
	}

	return 0;
}

/*
 * if addrp is UNSPECIFIED, then return a valid IPv6 address if found.
 * Global scope is preferred, but return site scope if no global
 * is available.  Don't return link local. 
 * if addrp is not UNSPECIFIED, then see if this address is bound
 * to the interface ifindex.
 * return value 0 if the operation suceeded, else EADDRNOTAVAIL.
 *
 */
static int find_v6addr(int ifindex, uint8_t *addrp)
{
	struct {
		struct nlmsghdr n;
		struct ifaddrmsg ifa;
	} req;

	int status;
	char buf[16384];
	struct nlmsghdr *nlmp;
	struct ifaddrmsg *rtmp;
	struct rtattr *rtap;
	int rtattrlen;
	int fd = lsocket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	int ret = EADDRNOTAVAIL;
	int any = IN6_IS_ADDR_UNSPECIFIED(addrp);
	int sap_found = 0, gap_found = 0;
	uint8_t sap[16], gap[16];

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof req.ifa);
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
	req.n.nlmsg_type = RTM_GETADDR;
	req.ifa.ifa_index = ifindex;
	req.ifa.ifa_family = AF_INET6;
	status = lsend(fd, &req, req.n.nlmsg_len, 0);
	if (status < 0) {
		perror("send");
		return EIO;
	}

	status = lrecv(fd, buf, sizeof(buf), 0);
	while (1) {
		if (status < 0) {
			perror("recv");
			return EIO;
		}
		if(status == 0){
			printf("EOF\n");
			return EIO;
		}

		for(nlmp = (struct nlmsghdr *)buf; status > sizeof(*nlmp);) {
			int len = nlmp->nlmsg_len;
			int req_len = len - sizeof(*nlmp);

			if (req_len < 0 || len > status) {
				printf("reply fmt error\n");
				return EIO;
			}
			if (!NLMSG_OK(nlmp, status)) {
				printf("NLMSG not OK\n");
				return EIO;
			}

			rtmp = (struct ifaddrmsg *)NLMSG_DATA(nlmp);
			rtap = (struct rtattr *)IFA_RTA(rtmp);
			rtattrlen = IFA_PAYLOAD(nlmp);
			if (rtmp->ifa_index == ifindex)
				for (; RTA_OK(rtap, rtattrlen);
				     rtap = RTA_NEXT(rtap, rtattrlen)) {
					if (rtap->rta_type == IFA_ADDRESS) {
						uint8_t *ap = (uint8_t *)RTA_DATA(rtap);

						if (any) {
							if (IN6_IS_ADDR_LINKLOCAL(ap)) {
								continue;
							} else if (IN6_IS_ADDR_SITELOCAL(ap)) {
								if (!sap_found) {
									sap_found = 1;
									memcpy(sap, ap, 16);
								}
							} else if (!gap_found) {
								gap_found = 1;
								memcpy(gap, ap, 16);
							}
						} else if (!memcmp(addrp, ap, 16)) {
							ret = 0;
							break;
						}
					}
				}
			status -= NLMSG_ALIGN(len);
			nlmp = (struct nlmsghdr*)((char*)nlmp + NLMSG_ALIGN(len));
		}
		status = lrecv(fd, buf, sizeof(buf), MSG_DONTWAIT);
		if (status < 0 && errno == EAGAIN)
			break;
	}
	if (any) {
		if (gap_found) {
			memcpy(addrp, gap, 16);
			ret = 0;
		} else if (sap_found) {
			memcpy(addrp, sap, 16);
			ret = 0;
		}
	}
	lclose(fd);
	return ret;
}

/*
 * if addrp is INADDR_ANY, then return a valid IPv4 address if found.
 * The first address found is returned.
 * if addrp is not INADDR_ANY, then see if this address is bound
 * to the interface ifindex.
 * return value 0 if the operation suceeded, else EADDRNOTAVAIL.
 */
static int find_v4addr(int ifindex, uint8_t *addrp)
{
	struct {
		struct nlmsghdr n;
		struct ifaddrmsg ifa;
	} req;

	int status;
	char buf[16384];
	struct nlmsghdr *nlmp;
	struct ifaddrmsg *rtmp;
	struct rtattr *rtap;
	int rtattrlen;
	int fd = lsocket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	int ret = EADDRNOTAVAIL;
	int any = *((uint32_t *)addrp) == INADDR_ANY;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof req.ifa);
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
	req.n.nlmsg_type = RTM_GETADDR;
	req.ifa.ifa_index = ifindex;
	req.ifa.ifa_family = AF_INET;
	status = lsend(fd, &req, req.n.nlmsg_len, 0);
	if (status < 0) {
		perror("send");
		return EIO;
	}

	status = lrecv(fd, buf, sizeof(buf), 0);
	while (1) {
		if (status < 0) {
			perror("recv");
			return EIO;
		}
		if(status == 0){
			printf("EOF\n");
			return EIO;
		}

		for(nlmp = (struct nlmsghdr *)buf; status > sizeof(*nlmp);) {
			int len = nlmp->nlmsg_len;
			int req_len = len - sizeof(*nlmp);

			if (req_len < 0 || len > status) {
				printf("reply fmt error\n");
				return EIO;
			}
			if (!NLMSG_OK(nlmp, status)) {
				printf("NLMSG not OK\n");
				return EIO;
			}

			rtmp = (struct ifaddrmsg *)NLMSG_DATA(nlmp);
			rtap = (struct rtattr *)IFA_RTA(rtmp);
			rtattrlen = IFA_PAYLOAD(nlmp);
			if (rtmp->ifa_index == ifindex)
				for (; RTA_OK(rtap, rtattrlen);
				     rtap = RTA_NEXT(rtap, rtattrlen)) {
					if (rtap->rta_type == IFA_ADDRESS) {
						uint8_t *ap = (uint8_t *)RTA_DATA(rtap);

						if (any) {
							memcpy(addrp, ap, 4);
							ret = 0;
							break;
						} else if (!memcmp(addrp, ap, 4)) {
							ret = 0;
							break;
						}
					}
				}
			status -= NLMSG_ALIGN(len);
			nlmp = (struct nlmsghdr*)((char*)nlmp + NLMSG_ALIGN(len));
		}
		status = lrecv(fd, buf, sizeof(buf), MSG_DONTWAIT);
		if (status < 0 && errno == EAGAIN)
			break;
	}
	lclose(fd);
	return ret;
}

struct chelsio_dev *find_chelsio_dev(char *name, struct sockaddr *addrp)
{
	struct chelsio_dev *dev;

	DBG(DBG_ROUTE, "enter name %s addr %s\n", name,
	    inet_ntoa(((struct sockaddr_in *)addrp)->sin_addr));
	STAILQ_FOREACH(dev, &chelsio_devs, list) {

		/* If the bind-to address is ANY or MCAST, then
		 * use the name from the endpoint db to find the
		 * device.
		 */
		DBG(DBG_ROUTE, "dev->name %s\n", dev->name);
		if (addrp->sa_family == AF_INET) {
			struct sockaddr_in *sinp = (struct sockaddr_in *)addrp;

			if (sinp->sin_addr.s_addr == INADDR_ANY ||
			    IN_MULTICAST(ntohl(sinp->sin_addr.s_addr))) {
				if (!strcmp(name, dev->name)) {
					break;
				}
			} else if (!find_v4addr(dev->ifindex, sinx_addrp(addrp)))  {
				break;
			}
		} else {
			struct sockaddr_in6 *sin6p = (struct sockaddr_in6 *)addrp;

			if (IN6_IS_ADDR_UNSPECIFIED(sin6p->sin6_addr.s6_addr) ||
			    IN6_IS_ADDR_MULTICAST(sin6p->sin6_addr.s6_addr)) {
				if (!strcmp(name, dev->name)) {
					break;
				}
			} else if (!find_v6addr(dev->ifindex, sinx_addrp(addrp))) {
				break;
			}
		}
	}
	return dev;
}

static int t4_get_addrs(int ifindex, uint8_t *v4addrp, uint8_t *v6addrp)
{
	int ret1, ret2;
	
	memset(v4addrp, 0, 4);
	memset(v6addrp, 0, 16);
	ret1 = find_v4addr(ifindex, v4addrp);
	ret2 = find_v6addr(ifindex, v6addrp);
	return ret1 && ret2;
}

void build_t4_dev_list()
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
	int fd = lsocket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof req.r);
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
	req.n.nlmsg_type = RTM_GETLINK;
	status = lfcntl(fd, F_GETFL);
	if (status < 0) {
		perror("fcntl(F_GETFL)");
		goto out;
	}
	status = lfcntl(fd, F_SETFL, status | O_NONBLOCK);
	if (status < 0) {
		perror("fcntl(F_SETFL)");
		goto out;
	}
	status = lsend(fd, &req, req.n.nlmsg_len, 0);
	if (status < 0) {
		perror("send");
		goto out;
	}

	do {

		status = lrecv(fd, buf, sizeof buf, 0);
		if (status < 0) {
			if (errno != EAGAIN) {
				perror("recv");
				goto out;
			}
			break;
		}
		if (status == 0) {
			printf("EOF\n");
			break;
		}

		for(nlmp = (struct nlmsghdr *)buf; status > sizeof(*nlmp);) {
			int len = nlmp->nlmsg_len;
			int req_len = len - sizeof(*nlmp);
			unsigned char *hwaddr = NULL;
			unsigned mtu = 0;
			int link;
			char *name = NULL;

			if (req_len < 0 || len > status) {
				printf("reply fmt error\n");
				goto out;
			}
			if (!NLMSG_OK(nlmp, status)) {
				printf("NLMSG not OK\n");
				goto out;
			}

			rtmp = (struct ifinfomsg *)NLMSG_DATA(nlmp);
			rtap = (struct rtattr *)IFI_RTA(rtmp);
			rtattrlen = IFA_PAYLOAD(nlmp);
			if (!RTA_OK(rtap, rtattrlen)) {
				goto out;
			}
			link = -1;
			for (; RTA_OK(rtap, rtattrlen);
			     rtap = RTA_NEXT(rtap, rtattrlen)) {
				if (rtap->rta_type == IFLA_LINK) {
					link = *((unsigned *)RTA_DATA(rtap));
					DBG(DBG_ROUTE, "link %d\n", link);
				}
				if (rtap->rta_type == IFLA_IFNAME) {
					name = (char *)RTA_DATA(rtap);
					DBG(DBG_ROUTE, "name |%s|\n", name);
				}
				if (rtap->rta_type == IFLA_ADDRESS) {
					hwaddr = (unsigned char *)RTA_DATA(rtap);
					DBG(DBG_ROUTE, "hwaddr " NIPHW_FMT "\n", NIPHW(hwaddr));
				}
				if (rtap->rta_type == IFLA_MTU) {
					mtu = *((unsigned *)RTA_DATA(rtap));
					DBG(DBG_ROUTE, "mtu %u\n", mtu);
				}
			}
			if (is_cxgb4_device(name, link)) {
				uint8_t v4addr[4], v6addr[16];

				if (!t4_get_addrs(rtmp->ifi_index, v4addr, v6addr)) {
#ifdef DEBUG
					char p1[INET6_ADDRSTRLEN], p2[INET_ADDRSTRLEN];
					DBG(DBG_ROUTE, "%u: name %s mtu %u hwaddr " NIPHW_FMT
					    " ipaddr %s ip6addr %s\n",
					    rtmp->ifi_index, name, mtu,
					    NIPHW(hwaddr), inet_ntop(AF_INET, v4addr, p2, sizeof p2),
					    inet_ntop(AF_INET6, v6addr, p1, sizeof p1));
#endif
					add_chelsio_dev(rtmp->ifi_index, v4addr, v6addr, name,
							hwaddr, mtu);
				} else {
					DBG(DBG_ROUTE, "%u: name %s has no ip addrs, skipping...\n", rtmp->ifi_index, name);
				}
			}
			status -= NLMSG_ALIGN(len);
			nlmp = (struct nlmsghdr*)((char*)nlmp + NLMSG_ALIGN(len));
		}
	} while (1);
out:
	lclose(fd);
}
