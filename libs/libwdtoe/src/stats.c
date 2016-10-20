#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include "common.h"
#include "stats.h"

#define CHELSIO_VAR_DIR_ENTRY "/var/run/chelsio"
#define WD_VAR_DIR_ENTRY "/var/run/chelsio/WD"
#define LIBWDTOE_PID_FORMAT "/var/run/chelsio/WD/libwdtoe-%d"

#define STATS_REQ_CMD "stats"
#define DONE_MSG "@@DONE@@"

extern struct wdtoe_conn_info *conn_info_new;
extern struct sockaddr_un sun;

static int get_ifname(struct sockaddr_in *s, char *ifname, size_t len)
{
	struct ifaddrs *addrs, *iap;
	struct sockaddr_in *sa;
	int ret;

	ret = getifaddrs(&addrs);

	if (ret == -1) {
		DBG(DBG_LOOKUP | DBG_STATS, "%s\n", strerror(errno));
		goto out;
	}

	for (iap = addrs; iap != NULL; iap = iap->ifa_next) {
		if (iap->ifa_addr && iap->ifa_flags & IFF_UP
				  && iap->ifa_addr->sa_family == AF_INET) {

			sa = (struct sockaddr_in *)iap->ifa_addr;

			if (s->sin_addr.s_addr == sa->sin_addr.s_addr) {
				memset(ifname, 0, len);

				strcpy(ifname, iap->ifa_name);

				freeifaddrs(addrs);
				return 0;
			}

		}
	}
out:
	return -1;
}

static void dump_stats(int s, struct sockaddr_un *sunp)
{
	int i;
	int cc;
	int ret;
	char buf[256];
	struct wdtoe_conn_info *c;
	char laddr_name[16];
	char raddr_name[16];
	char ifname[32];
	struct sockaddr_in laddr;
	struct sockaddr_in raddr;
	socklen_t laddrlen = sizeof(laddr);
	socklen_t raddrlen = sizeof(raddr);
	char *states[] = {"IDLE", "ESTABLISHED", "CLOSE_WAIT"};

	if (!conn_info_new) {
		DBG(DBG_STATS, "no WD-TOE stack created yet\n");
		return;
	}

	for (i = 0; i < NWDTOECONN; i++) {
		if (conn_info_new[i].sockfd == -1)
			continue;

		c = &conn_info_new[i];

		if (c->tcp_state > TCP_IDLE) {
			ret = getsockname(c->sockfd, (struct sockaddr *)&laddr,
					  &laddrlen);

			if (ret == -1) {
				DBG(DBG_STATS, "failed while calling 'getsockname' "
				    "(%s)\n", strerror(errno));
				goto minimal_stats;
			}

			strncpy(laddr_name, inet_ntoa(laddr.sin_addr),
				sizeof(laddr_name));
			laddr_name[sizeof(raddr_name) - 1] = '\0';

			ret = getpeername(c->sockfd, (struct sockaddr *)&raddr,
					  &raddrlen);

			if (ret == -1) {
				DBG(DBG_STATS, "failed while calling 'getpeername' "
				    "(%s)\n", strerror(errno));
				goto minimal_stats;
			}

			strncpy(raddr_name, inet_ntoa(raddr.sin_addr),
				sizeof(raddr_name));
			raddr_name[sizeof(raddr_name) - 1] = '\0';

			ret = get_ifname(&laddr, ifname, sizeof(ifname));

			if (ret == -1) {
				DBG(DBG_STATS, "failed to obtain ifname "
				    "for sockfd %d\n", c->sockfd);
				goto minimal_stats;
			}

			cc = sprintf(buf, "sockfd %d, iface %s, lhost %s:%d, "
					  "rhost %s:%d, state %s, "
					  "fast_sends %llu, "
					  "fast_recvs %llu, "
					  "waits %llu\n",
					  c->sockfd, ifname, laddr_name,
					  ntohs(laddr.sin_port),
					  raddr_name, ntohs(raddr.sin_port),
					  states[c->tcp_state],
					  c->stats.fast_sends,
					  c->stats.fast_recvs,
					  c->stats.waits);
		} else {
minimal_stats:
			cc = sprintf(buf, "sockfd %d, state %s\n",
				     c->sockfd, states[c->tcp_state]);
		}

		if (sunp)
			sys_sendto(s, buf, cc + 1, 0,
				   (const struct sockaddr *)sunp,
				   sizeof(*sunp));
		else
			sys_write(s, buf, cc + 1);
	}
}

void *stats_thread_routine(void *arg)
{
	int ret;
	int s;
	socklen_t fromlen = sizeof(sun);
	ssize_t cc;
	char buf[100];

	s = sys_socket(PF_UNIX, SOCK_DGRAM, 0);

	if (s == -1) {
		DBG(DBG_STATS, "could not open stat socket\n");
		goto out;
	}

	ret = mkdir(CHELSIO_VAR_DIR_ENTRY, 0777);

	/*
	 * if the directory already exists, that's even
	 * better, right?
	 */
	if (ret == -1 && errno != EEXIST) {
		DBG(DBG_STATS, "could not create dir `%s'\n",
			       CHELSIO_VAR_DIR_ENTRY);
		goto bail;
	}

	ret = mkdir(WD_VAR_DIR_ENTRY, 0777);

	if (ret == -1 && errno != EEXIST) {
		DBG(DBG_STATS, "could not create dir `%s'. Reason: %s\n",
			       WD_VAR_DIR_ENTRY, strerror(errno));
		goto bail;
	}

	memset(&sun, 0, sizeof(sun));

	sun.sun_family = AF_UNIX;

	sprintf(sun.sun_path, LIBWDTOE_PID_FORMAT, getpid());

	unlink(sun.sun_path);

	/*
	 * XXX we may need to get the lower bind symbol instead,
	 * as 'bind()' may be hijacked by WD-TOE in the future.
	 */
	if (bind(s, (const struct sockaddr *)&sun, sizeof(sun)) == -1) {
		DBG(DBG_STATS, "could not bind to `%s'. No stats will "
			       "be availabe\n", sun.sun_path);
		goto bail;
	}

	while (1) {
		buf[0] = 0;

		cc = sys_recvfrom(s, buf, sizeof(buf), 0,
				  (struct sockaddr *)&sun,
				  &fromlen);

		if (cc < 0) {
			DBG(DBG_STATS, "failure when reading stat request\n");
			goto bail;
		}

		if (!cc) {
			DBG(DBG_STATS, "read EOF from mamangement socket\n");
			goto bail;
		}

		if (!strncmp(buf, STATS_REQ_CMD, strlen(STATS_REQ_CMD))) {
			dump_stats(s, &sun);
		} else {
			DBG(DBG_STATS, "unknown command `%s'\n", buf);
		}

		strcpy(buf, DONE_MSG);
		ret = sys_sendto(s, buf, strlen(DONE_MSG), 0,
				 (const struct sockaddr *)&sun,
				 sizeof(sun));

		if (ret == -1)
			DBG(DBG_STATS, "failed while sending final msg\n");

		/*
		 * Setting sun.sun_path back to the path to our
		 * listening socket so it can be removed
		 * by the destructor function on lib exit.
		 */
		memset(sun.sun_path, 0, sizeof(sun.sun_path));
		sprintf(sun.sun_path, LIBWDTOE_PID_FORMAT, getpid());
	}

bail:
	sys_close(s);

out:
	pthread_exit(NULL);
}
