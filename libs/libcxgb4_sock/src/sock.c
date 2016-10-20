/*
 * Copyright (c) 2004 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005-2006 Mellanox Technologies Ltd.  All rights reserved.
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

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <fcntl.h>
#include <signal.h>
#include <malloc.h>

#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>

#include <arpa/inet.h>

#include "libcxgb4_sock.h"

#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) < (b) ? (b) : (a))

#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000
#endif

#if 1

#ifdef USE_MUTEX
static int myspin_init(pthread_mutex_t *l, int pshared)
{
	pthread_mutexattr_t attr;
	int ret;
	int type;

	pthread_mutexattr_init(&attr);
#ifdef DEBUG
	type = PTHREAD_MUTEX_ERRORCHECK;
#else
	type = PTHREAD_MUTEX_NORMAL;
#endif
	pthread_mutexattr_settype(&attr, type);
	ret = pthread_mutex_init(l, &attr);
	assert(ret == 0);
	return ret;
}

static int myspin_lock(pthread_mutex_t *l)
{
	int ret = pthread_mutex_lock(l);
	assert(ret == 0);
	return ret;
}

static int myspin_unlock(pthread_mutex_t *l)
{
	int ret = pthread_mutex_unlock(l);
	assert(ret == 0);
	return ret;
}
#else
#define myspin_init(a, b) pthread_spin_init((a), (b))
#define myspin_lock(a) pthread_spin_lock((a))
#define myspin_unlock(a) pthread_spin_unlock((a))
#endif
#else
#define myspin_init(a, b)
#define myspin_lock(a)
#define myspin_unlock(a)
#endif

void __attribute__ ((constructor)) cs_init(void);
void __attribute__ ((destructor)) cs_fini(void);

static inline void call_cs_init(void)
{
	cs_init();
}

static int page_size;
struct socket_lib_funcs socket_funcs;
static void *libc_dl_handle = RTLD_NEXT;
static int init;
static int max_fds;
static struct cs_context **contexts;
static struct epoll_context **epoll_contexts;
int quiet;
static int hdr_room = 64;
static int use_huge_pages;
static int sq_coal = SQ_COAL;
static int sq_depth = SQ_DEPTH;
static int rq_depth = RQ_DEPTH;
static int packed = UDP_PACKED_MODE;
static int blast;

#define ALIGN(l, size) (((l) + ((size) - 1)) / (size) * (size))

static int sa_len(const struct sockaddr *sa)
{
	return sa->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
}

static void copy_sa(struct sockaddr *dst, const struct sockaddr *src)
{
	memcpy(dst, src, sa_len(src));
}

static inline uint16_t sinx_port(struct sockaddr *s)
{
	return s->sa_family == AF_INET ?
		((struct sockaddr_in *)s)->sin_port :
		((struct sockaddr_in6 *)s)->sin6_port;
}

#if 0
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
	FAST_SEL,
	SEL,
	LAST
};

#include <chelsio/get_clock.h>
static unsigned int prof_calls[LAST];
static unsigned int prof_sample_idx[LAST];
static cycles_t ts_func_enter[LAST][SAMPLES+1];
static cycles_t ts_func_exit[LAST][SAMPLES+1];

static void compute_report(unsigned int idx)
{
	unsigned int iters;
	double min = 0, max = 0, delta = 0, sum = 0, ave;
	int i;
	double cycles_to_usecs = get_cpu_mhz();

	iters = prof_sample_idx[idx];
	for (i = SKIP; i < iters; i++) {
		delta = ts_func_exit[idx][i] - ts_func_enter[idx][i];
		if (delta > max)
			max = delta;
		if (delta < min || min == 0)
			min = delta;
		sum += delta;
	}
	ave = sum / (iters - SKIP);
	printf("\tAve %g us, Min %g us, Max %g us\n",
		ave / cycles_to_usecs,
		min / cycles_to_usecs,
		max / cycles_to_usecs);
}

static void profile_report()
{
	if (prof_sample_idx[FAST_SEL]) {
		printf("FAST_SEL: calls %u samples %u\n", prof_calls[FAST_SEL],
		       prof_sample_idx[FAST_SEL] - SKIP);
		compute_report(FAST_SEL);
	}
	if (prof_sample_idx[SEL]) {
		printf("SEL: calls %u samples %u\n", prof_calls[SEL],
		       prof_sample_idx[SEL] - SKIP);
		compute_report(SEL);
	}
}

#define PENTER(_x) \
do { \
	prof_calls[_x]++; \
	if (prof_sample_idx[_x] < SAMPLES) { \
		prof_sample_idx[_x]++; \
		ts_func_enter[_x][prof_sample_idx[_x]] = get_cycles(); \
	} \
} while(0)

#define PRESET(_x) \
do { \
	prof_calls[_x]--; \
	prof_sample_idx[_x]--; \
} while(0)

#define PEXIT(_x) \
do { \
	if (prof_sample_idx[_x] <= SAMPLES) { \
		ts_func_exit[_x][prof_sample_idx[_x]] = get_cycles(); \
	} \
} while(0)

#else
#define PENTER(x)
#define PEXIT(x)
#define PRESET(X)
void profile_report()
{
}
#endif

#define SPIN_COUNT 5000
#define POLL_SPIN_COUNT 5000
static unsigned long spin_count = SPIN_COUNT;
static unsigned long poll_spin_count = POLL_SPIN_COUNT;
static unsigned long max_poll_spin_count = POLL_SPIN_COUNT;
static unsigned int wait_means_wait = 1;


static pthread_t stats_thread;
static int stats_thread_started;
#define INC_STAT(c, a) (c)->stats.a++;

static pthread_t sq_thread;
static int sq_thread_started;
static int sq_epoll_fd;

static long max_inline = 0;
static long max_inline_specified = 0;

static void dump_stats(int s, struct sockaddr_un *sunp)
{
	int i;
	char buf[256];
	int cc;
	struct cs_context *c;
	char *states[] = { "IDLE", "BOUND", "CONNECTED"};
	char devstr[INET6_ADDRSTRLEN], lastr[INET6_ADDRSTRLEN], rastr[INET6_ADDRSTRLEN];
	
	for (i = 0; i < max_fds; i++) {

		c = contexts[i];
		if (!c || c->sockfd == -1)
			continue;

		if (c->state > IDLE) {
			cc = sprintf(buf, "qp_num %d sockfd %d state %s dev %s devaddr %s fid %d laddr %s:%u raddr %s:%u vlan %d pri %d fast_sends %llu slow_sends "
				"%llu fast_recvs %llu slow_recvs %llu, waits %llu qp-txpkts %llu qp-txbytes %llu qp-rxpkts %llu qp_rxbytes %llu\n", 
				c->qp->raw_qp->qp_num, c->sockfd, states[c->state], 
				c->chelsio_dev->name,
				(c->laddr.sa.sa_family == AF_INET ? 
					inet_ntop(AF_INET, &c->chelsio_dev->ipv4addr.sin_addr.s_addr, devstr, sizeof devstr) :
					inet_ntop(AF_INET6, &c->chelsio_dev->ipv6addr.sin6_addr.s6_addr, devstr, sizeof devstr)),
				c->qp->fid,
				inet_ntop(c->laddr.sa.sa_family, sinx_addrp(&c->laddr.sa), lastr, sizeof lastr), ntohs(sinx_port(&c->laddr.sa)),
				inet_ntop(c->raddr.sa.sa_family, sinx_addrp(&c->raddr.sa), rastr, sizeof rastr), ntohs(sinx_port(&c->raddr.sa)),
				c->vlan == VLAN_ID_NA ? -1 : c->vlan,
				c->pri == VLAN_PRI_NA ? -1 : c->pri,
				c->stats.fast_sends, c->stats.slow_sends,
				c->stats.fast_recvs, c->stats.slow_recvs, c->stats.waits,
				c->qp->stats.tx_pkts, c->qp->stats.tx_bytes,
				c->qp->stats.rx_pkts, c->qp->stats.rx_bytes);
		} else {
			cc = sprintf(buf, "sockfd %d state %s\n", c->sockfd, states[c->state]);
		}
		if (sunp)
			socket_funcs.sendto(s, buf, cc + 1, 0, (const struct sockaddr *)sunp, sizeof *sunp);
		else
			socket_funcs.write(s, buf, cc + 1);
	}
}

struct sockaddr_un sun;

static void *stats_thread_routine(void *arg)
{
	int s;
	socklen_t fromlen = sizeof sun;
	ssize_t cc;
	char buf[100];

	s = lsocket(PF_UNIX, SOCK_DGRAM, 0);
	if (s == -1) {
		perror("WD: Cannot create management socket");
		goto out;
	}
	mkdir("/var/run/chelsio", 0777);
	mkdir("/var/run/chelsio/WD", 0777);
	sun.sun_family = AF_UNIX;
	memset(sun.sun_path, 0, sizeof sun.sun_path);
	sprintf(sun.sun_path, "/var/run/chelsio/WD/libcxgb4_sock-%d", getpid());
	unlink(sun.sun_path);
	if (lbind(s, (const struct sockaddr *)&sun, sizeof sun) == -1) {
		perror("WD: Cannot bind management socket");
		fprintf(stderr, "WD: Cannot bind to /var/run/chelsio/WD/libcxgb4_sock-%d\n", getpid());
		fprintf(stderr, "WD: No statistics will be available for this process\n");
		fprintf(stderr, "WD: Make sure /var/run/chelsio/WD exists and is read/write/executable by all\n");
		goto bail;
	}
	while (1) {
		buf[0] = 0;
		cc = recvfrom(s, buf, sizeof buf, 0, (struct sockaddr *)&sun, &fromlen);
		if (cc < 0) {
			perror("WD: recvfrom()");
			goto bail;
		}
		if (!cc) {
			fprintf(stderr, "WD: read EOF from management socket.\n");
			goto bail;
		}
		if (!strncmp(buf, "stats", strlen("stats"))) {
			dump_stats(s, &sun);
		} else {
			fprintf(stderr, "%s: unknown command %s\n", __func__, buf);
		}
		strcpy(buf, "@@DONE@@");
		socket_funcs.sendto(s, buf, strlen("@@DONE@@"), 0, (const struct sockaddr *)&sun, sizeof sun);
	}
 bail:
	lclose(s);
 out:
	pthread_exit(NULL);
}

static void destroy_buf_pool(struct cs_context *c)
{
	ibv_dereg_mr(c->bufs_mr);
	c->bufs_mr = NULL;
	if (c->huge_size)
		munmap(c->bufs, c->huge_size);
	else
		free(c->bufs);
	free(c->sq_bufs);
	c->sq_bufs = NULL;
	c->rq_bufs = NULL;
}


/*
 * XXX these should be gleaned from the OS.
 * Also, HUGE_PAGE_SIZE must be a multiple of HUGE_BUF_SIZE to avoid
 * buffers that span huge pages.
 */
#define HUGE_PAGE_SIZE (2 * 1024 * 1024)
static int huge_page_size = HUGE_PAGE_SIZE;
#define HUGE_BUF_SIZE (16384)
#define HUGE_BUFS_PER_PAGE (huge_page_size / HUGE_BUF_SIZE)

static uint8_t *alloc_huge_pages(struct cs_context *c, int size)
{
	void *p;

	VERBOSE(DBG_INIT, "Allocating %uKB from the huge pool.\n", size/1024);

	p = mmap(0x0UL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, 0, 0);
	if (p == MAP_FAILED) {
		perror("mmap(MAP_HUGETLB)");
		return NULL;
	}
	c->huge_size = size;
	return p;
}

static int create_buf_pool(struct cs_context *c, int scount, int rcount)
{
	int ret;
	struct cs_buf *b;
	uint8_t *p;
	int size;
	int i;

	if (use_huge_pages) {
		size = (scount + rcount) / HUGE_BUFS_PER_PAGE * huge_page_size;
		if (size < ((scount + rcount) * HUGE_BUF_SIZE))
			size += huge_page_size;
		c->buf_size = HUGE_BUF_SIZE;
		p = alloc_huge_pages(c, size);
		if (!p) {
			use_huge_pages = 0;
			VERBOSE(DBG_INIT, "Hugepage allocation failure...disabling huge page support.\n");
			size = (scount + rcount) * page_size;
			c->buf_size = page_size;
			p = memalign(page_size, size);
		}
	}
	else {
		size = (scount + rcount) * page_size;
		c->buf_size = page_size;
		p = memalign(page_size, size);
	}
	if (!p) {
		ret = errno;
		goto err;
	}
	b = calloc(scount + rcount, sizeof *b);
	if (!b) {
		ret = errno;
		goto err1;
	}
	c->sq_wrs = calloc(scount, sizeof *c->sq_wrs);
	if (!c->sq_wrs) {
		ret = errno;
		goto err2;
	}
	c->sq_sges = calloc(scount, sizeof *c->sq_sges);
	if (!c->sq_sges) {
		ret = errno;
		goto err3;
	}
	c->bufs_mr = ibv_reg_mr(c->dev->pd, p, size,
				IBV_ACCESS_LOCAL_WRITE);
	if (!c->bufs_mr) {
		ret = errno;
		goto err4;
	}
	c->sq_bufs = b;
	c->rq_bufs = &b[scount];
	c->bufs = p;
	for (i = 0; i < (scount + rcount); i++) {
		b[i].addr = p;
		p += c->buf_size;
		b[i].c = c;
	}
	return 0;
err4:
	free(c->sq_sges);
err3:
	free(c->sq_wrs);
err2:
	free(b);
err1:
	if (c->huge_size)
		munmap(p, c->huge_size);
	else
		free(p);
err:
	return ret;
}

static struct udp_send_wr *oldest_pending_sq_wr(struct cs_context *c)
{
	unsigned idx = c->sq_idx - c->sq_coal_count;

	if (idx >= sq_depth)
		idx += sq_depth;
	assert(idx < sq_depth);
	assert(c->sq_bufs[idx].status == PENDING);
	return &c->sq_wrs[idx];
}

static void cur_sq_buf(struct cs_context *c, struct cs_buf **b, struct udp_send_wr **wr)
{
	unsigned idx = c->sq_idx;

	if (idx-- == 0)
		idx = sq_depth - 1;
	assert(idx < sq_depth);
	*b = &c->sq_bufs[idx];
	*wr = &c->sq_wrs[idx];
	assert((*b)->status == PENDING);
}

static void next_sq_buf(struct cs_context *c, struct cs_buf **b,
			struct ibv_sge **sge, struct udp_send_wr **wr)
{
	*b = &c->sq_bufs[c->sq_idx];
	*sge = &c->sq_sges[c->sq_idx];
	*wr = &c->sq_wrs[c->sq_idx];
}

static void inc_sq_idx(struct cs_context *c)
{
	if (++c->sq_idx == sq_depth)
		c->sq_idx = 0;
}

static void dec_sq_idx(struct cs_context *c)
{
	if (c->sq_idx-- == 0)
		c->sq_idx = sq_depth - 1;
}

static void init_epoll_ctx(struct epoll_context *epc)
{
	memset(epc, 0, sizeof *epc);
	epc->epfd = -1;
}

static struct epoll_context *get_epoll_context(int fd)
{
	struct epoll_context **epcp;

	assert(fd >= 0);
	assert(fd < max_fds);
	epcp = &epoll_contexts[fd];
	if (!*epcp) {
		*epcp = malloc(sizeof **epcp);
		init_epoll_ctx(*epcp);
	}
	return *epcp;
}

static void init_ctx(struct cs_context *c)
{
	memset(c, 0, sizeof *c);
	c->state = IDLE;
	c->sockfd =  -1;
	myspin_init(&c->lock, PTHREAD_PROCESS_PRIVATE);
}

static struct cs_context *get_context(int fd)
{
	struct cs_context **cp;

	assert(fd >= 0);
	assert(fd < max_fds);
	cp = &contexts[fd];
	if (!*cp) {
		*cp = malloc(sizeof **cp);
		init_ctx(*cp);
	}
	return *cp;
}

static int drain_scq(struct cs_context *c)
{
	struct ibv_wc wc;
	struct cs_buf *b;
	int ret = 0;

	myspin_lock(&c->lock);
	while (c->snd_cnt) {
		ret = udp_poll_cq(c->scq, &wc, NULL, 0);
		if (!ret) {
			assert(wc.opcode == IBV_WC_SEND);
			b = (struct cs_buf *)(uintptr_t)wc.wr_id;
			c->snd_cnt -= b->wc_count;
			assert(c->snd_cnt < sq_depth);
			if (wc.status) {
				ret = -1;
				break;
			}
		}
	}
	myspin_unlock(&c->lock);
	return ret;
}

/*
 * assumes the lock is held!
 */
static void send_pending(struct cs_context *c)
{
	struct cs_buf *b;
	struct udp_send_wr *cur_wr, *oldest_wr;
	int ret;

	cur_sq_buf(c, &b, &cur_wr);
	oldest_wr = oldest_pending_sq_wr(c);
	assert(oldest_wr == (cur_wr - c->sq_coal_count + 1));
	cur_wr->send_flags |= IBV_SEND_SIGNALED;
	b->wc_count = c->sq_coal_count;
	b->status = POSTED;
	ret = udp_post_send_many(c->qp, oldest_wr, c->sq_coal_count);
	assert(!ret);
	c->coal_sum += c->sq_coal_count;
	c->coal_count++;
	c->sq_coal_count = 0;
	assert(c->snd_cnt < sq_depth);
}

static void mark_bufs_free(struct cs_context *c, struct cs_buf *b)
{
	int count = b->wc_count;
	while (count--) {
		b->status = FREE;
		if (b-- == c->sq_bufs)
			b = &c->sq_bufs[sq_depth -1 ];
	}
}

/*
 * assumes the lock is held!
 */
static int poll_one_scqe(struct cs_context *c)
{
	struct ibv_wc wc;
	int ret;
	int full;

	full = c->snd_cnt == sq_depth;
	ret = udp_poll_cq(c->scq, &wc, NULL, 0);
	if (!ret) {
		struct cs_buf *b;

		if (full)
			c->sq_full++;
		assert(wc.opcode == IBV_WC_SEND);
		b = (struct cs_buf *)(uintptr_t)wc.wr_id;
		assert(b->status == POSTED);
		mark_bufs_free(c, b);
		b->status = FREE;
		c->snd_cnt -= b->wc_count;
		assert(c->snd_cnt < sq_depth);
		if (wc.status) {
			abort();
			fprintf(stderr, "wc status %d\n", wc.status);
			ret = -1;
		}
	} else
		ret = 0;
	return ret;
}

static void *sq_thread_routine(void *arg)
{
	int ret;
	struct epoll_event e;
	struct cs_context *c;

	while (1) {
		ret = socket_funcs.epoll_wait(sq_epoll_fd, &e, 1, -1);
		if (ret == -1) {
			perror("epoll_wait");
			continue;
		}
		if (e.events != EPOLLIN) {
			fprintf(stderr, "%s unexpected epoll events 0x%x\n", __func__, e.events);
			continue;
		}
		c = e.data.ptr;

		myspin_lock(&c->lock);

		/*
		 * Pull at least one cqe from the sq if available.  This will
		 * free up sq_coal slots in the sq when in coalescing mode.
		 */
		poll_one_scqe(c);


		/*
		 * If the sq is low, we must exit coalesce mode and
		 * send any pending wrs.
		 */
		if (c->coalescing && c->snd_cnt < sq_coal) {

			if (c->sq_coal_count)
				send_pending(c);
			c->coal_transitions++;
			c->coalescing = 0;
			socket_funcs.epoll_ctl(sq_epoll_fd, EPOLL_CTL_DEL, c->sq_chan->fd, NULL);
		} else
			ibv_req_notify_cq(c->scq, 0);
		myspin_unlock(&c->lock);
	}
	pthread_exit(NULL);
}

static void free_um_udp(int s)
{
	struct cs_context *c = get_context(s);
	int ret;
	int onoff = 0;

	DBG(DBG_UM, "Enter\n");

	DBG(DBG_UM, "coal count %llu ave %g transitions %llu sq_full %llu\n",
	    c->coal_count, (float)c->coal_sum / (float)c->coal_count,
	    c->coal_transitions, c->sq_full);

	myspin_lock(&c->lock);
	if (c->sq_coal_count) {
		send_pending(c);
		do {
			ret = poll_one_scqe(c);
			assert(!ret);
		} while (c->snd_cnt);
	}
	myspin_unlock(&c->lock);
	ret = udp_destroy_qp(c->qp);
	if (ret) {
		DBG(DBG_UM, "udp_destroy_qp failed: %s\n", strerror(ret));
	}
	socket_funcs.epoll_ctl(sq_epoll_fd, EPOLL_CTL_DEL, c->sq_chan->fd, NULL);
	ret = ibv_destroy_cq(c->scq);
	if (ret) {
		DBG(DBG_UM, "ibv_destroy_cq scq");
	}

	ret = ibv_destroy_cq(c->rcq);
	if (ret) {
		DBG(DBG_UM, "ibv_destroy_cq rcq");
	}

	destroy_buf_pool(c);

	ret = udp_stop_dev(c->dev);
	if (ret) {
		DBG(DBG_UM, "udp_stop_dev failed: %s\n", strerror(ret));
	}

	ret = ibv_destroy_cq(c->frag_cq);
	if (ret) {
		DBG(DBG_UM, "ibv_destroy_cq frag_cq");
	}

	ret = ibv_destroy_comp_channel(c->rq_chan);
	if (ret) {
		DBG(DBG_UM, "ibv_destroy_comp_channel");
	}

	ret = ibv_destroy_comp_channel(c->sq_chan);
	if (ret) {
		DBG(DBG_UM, "ibv_destroy_comp_channel");
	}


	ret = udp_dealloc_dev(c->dev);
	if (ret) {
		DBG(DBG_UM, "udp_dealloc_dev failed: %s\n", strerror(ret));
	}

	if (!c->nonblocking) {
		DBG(DBG_UM, "Restoring sockfd to blocking\n");
		ret = ioctl(c->sockfd, FIONBIO, &onoff);
		if (ret) {
			DBG(DBG_UM, "failed to reset sockfd NBIO: %s\n", strerror(errno));
		}
	}
	DBG(DBG_UM, "c->spin_count %d\n", c->spin_count);
}

static int post_recv_buf(struct cs_context *c, struct cs_buf *b)
{
	struct udp_recv_wr wr;
	struct ibv_sge sge;

	assert(b);
	sge.addr = (uint64_t)(unsigned long)b->addr;
	sge.length = c->buf_size;
	sge.lkey = c->bufs_mr->lkey;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.wr_id = (uint64_t)(unsigned long)b;
	return udp_post_recv(c->qp, &wr);
}

static void update_epoll_groups(int fd);

static int setup_um_udp(struct cs_context *c)
{
	int ret;
	int i;
	const int onoff = 1;
	int flags = 0;

	assert(sinx_port(&c->laddr.sa));

	/*
 	 * We can only accelerate devices with an MTU <= the host
	 * page size.  This is due to the requirement that FL buffers
	 * be contiguous, and the memory we allocate and register in
	 * user mode may not be contigious.
	 */
	if (!use_huge_pages && c->chelsio_dev->mtu > (page_size - MAX_UDP_HDR_SIZE)) {
		VERBOSE(DBG_UM, "Device mtu (%d) exceeds available contiguous buffer space (%d)\n",
		    c->chelsio_dev->mtu, page_size - MAX_UDP_HDR_SIZE);
		return 1;
	}

#ifdef DEBUG
{
	char devstr[INET6_ADDRSTRLEN], lastr[INET6_ADDRSTRLEN], rastr[INET6_ADDRSTRLEN];
	
	DBG(DBG_UM, "Setting up UM-UDP for fd %d devaddr %s laddr:port %s:%u raddr:port %s:%u vlan %d pri %d\n",
	    c->sockfd,
	    (c->laddr.sa.sa_family == AF_INET ? 
	    inet_ntop(AF_INET, &c->chelsio_dev->ipv4addr.sin_addr.s_addr, devstr, sizeof devstr) :
	    inet_ntop(AF_INET6, &c->chelsio_dev->ipv6addr.sin6_addr.s6_addr, devstr, sizeof devstr)),
	    inet_ntop(c->laddr.sa.sa_family, sinx_addrp(&c->laddr.sa), lastr, sizeof lastr), ntohs(sinx_port(&c->laddr.sa)),
	    inet_ntop(c->raddr.sa.sa_family, sinx_addrp(&c->raddr.sa), rastr, sizeof rastr), ntohs(sinx_port(&c->raddr.sa)),
	    c->vlan == VLAN_ID_NA ? -1 : c->vlan,
	    c->pri == VLAN_PRI_NA ? -1 : c->pri);
}
#endif

	ret = udp_alloc_dev(&c->chelsio_dev->ipv4addr, &c->chelsio_dev->ipv6addr, &c->dev);
	if (ret) {
		VERBOSE(DBG_UM, "udp_alloc_dev failed: %s\n", strerror(ret));
		return 1;
	}
	c->rq_chan = ibv_create_comp_channel(c->dev->verbs);
	if (!c->rq_chan) {
		perror("ibv_create_comp_channel");
		return 1;
	}
	c->sq_chan = ibv_create_comp_channel(c->dev->verbs);
	if (!c->sq_chan) {
		perror("ibv_create_comp_channel");
		return 1;
	}
	ret = ioctl(c->rq_chan->fd, FIONBIO, &onoff);
	assert(!ret);

	c->frag_cq = ibv_create_cq(c->dev->verbs, UDP_FRAG_RQ_DEPTH,
				   c, NULL, 0); /* XXX - need comp chan */
	if (!c->frag_cq) {
		perror("ibv_create_cq");
		return 1;
	}
	ret = udp_start_dev(c->dev, c->frag_cq);
	if (ret) {
		VERBOSE(DBG_UM, "udp_start_dev failed: %s\n", strerror(ret));
		return 1;
	}
	c->scq = ibv_create_cq(c->dev->verbs, sq_depth, c, c->sq_chan, 0);
	if (!c->scq) {
		perror("ibv_create_cq");
		return 1;
	}

	ret = create_buf_pool(c, sq_depth, rq_depth);
	if (ret) {
		VERBOSE(DBG_UM, "create_buf_pool failed: %s\n", strerror(ret));
		return 1;
	}

	c->rcq = ibv_create_cq(c->dev->verbs, rq_depth * (packed ? c->buf_size / 64 : 1), c, c->rq_chan, 0);
	if (!c->rcq) {
		perror("ibv_create_cq");
		return 1;
	}

	ret = udp_create_qp(c->dev, c->scq, c->rcq, sq_depth, rq_depth, NULL,
			    &c->laddr.sa, &c->raddr.sa, c->vlan, c->pri, c->v6only | packed, &c->qp);
	if (ret) {
		VERBOSE(DBG_UM, "udp_create_qp failed: %s\n", strerror(ret));
		return 1;
	}
	for (i = 0; i < rq_depth; i++) {
		ret = post_recv_buf(c, &c->rq_bufs[i]);
		if (ret) {
			VERBOSE(DBG_UM, "post_recv_buf failed: %s\n", strerror(ret));
			if (use_huge_pages) {
				VERBOSE(DBG_UM, "This is probably due to using hugepages with system virtualization enabled.\n");
				VERBOSE(DBG_UM, "Disabling hugepage support.\n");
				use_huge_pages = 0;
			}
			return 1;
		}
	}

	flags = socket_funcs.fcntl(c->sockfd, F_GETFL);
	c->nonblocking = (flags & O_NONBLOCK) == O_NONBLOCK;
	if (!c->nonblocking) {
		DBG(DBG_UM, "making sockfd NB\n");
		ret = ioctl(c->sockfd, FIONBIO, &onoff);
		if (ret) {
			VERBOSE(DBG_UM, "failed to set sockfd NBIO: %s\n", strerror(errno));
			return 1;
		}
	}
	if (c->chelsio_dev->ipv4addr.sin_addr.s_addr != INADDR_ANY)  {
		in_addr_t addr;
		socklen_t addrlen = sizeof addr;

		if (getsockopt(c->sockfd, IPPROTO_IP, IP_MULTICAST_IF, &addr,
		    &addrlen) == 0) {
			if (addr == c->chelsio_dev->ipv4addr.sin_addr.s_addr) {
				c->mcast_if = 1;
			}
		}
	} else {
		int ifidx;
		socklen_t ifidx_len = sizeof ifidx;
		
		if (getsockopt(c->sockfd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifidx,
		    &ifidx_len) == 0) {
			if (ifidx ==  c->chelsio_dev->ifindex) {
				c->mcast_if = 1;
			}
		}
	}
	c->spin_count = spin_count;
	if (!stats_thread_started) {
		stats_thread_started = 1;
		pthread_create(&stats_thread, NULL, stats_thread_routine, NULL);
	}

	if (!sq_thread_started) {
		sq_thread_started = 1;
		pthread_create(&sq_thread, NULL, sq_thread_routine, NULL);
	}

	c->max_inline = udp_max_inline(c->laddr.sa.sa_family);
	if (max_inline_specified && max_inline < c->max_inline)
		c->max_inline = max_inline;
	DBG(DBG_UM, "Using max inline %d\n", c->max_inline);

	update_epoll_groups(c->sockfd);

	DBG(DBG_UM, "Setup success\n");
	return 0;
}

static void free_context(int s)
{
	struct cs_context *c;

	DBG(DBG_UM, "drop fd %d\n", s);

	c = contexts[s];
	assert(c);
	if (c->state > IDLE)
		free_um_udp(s);
	init_ctx(c);
}

static int valid_um_udp(int s)
{
	return s >= 0 && s < max_fds && contexts[s] && contexts[s]->state >= BOUND;
}

static int valid_context(int s)
{
	return s >= 0 && s < max_fds && contexts[s] && contexts[s]->sockfd != -1;
}

static int valid_epoll_context(int fd)
{
	return fd >= 0 && fd < max_fds && epoll_contexts[fd] && epoll_contexts[fd]->epfd != -1;
}

static void bind_context(int s, struct sockaddr *addr)
{
	struct chelsio_dev *chelsio_dev;
	char name[IFNAMSIZ];
	uint16_t vlan;
	uint8_t pri;

	if (lookup_endpoint(sinx_port(addr), name, &vlan, &pri)) {
		DBG(DBG_BIND, "not offloading...no config entry available\n");
		free_context(s);
		return ;
	}
	DBG(DBG_BIND, "endpoint db entry found for port %u: name %s vlan %u pri %u\n",
	    ntohs(sinx_port(addr)), name, vlan, pri);

	chelsio_dev = find_chelsio_dev(name, addr);
	if (chelsio_dev) {
		DBG(DBG_BIND, "binding fd %d to %s\n", s, chelsio_dev->name);
		struct cs_context *c = get_context(s);
		copy_sa(&c->laddr.sa, addr);
		c->raddr.sa.sa_family = c->laddr.sa.sa_family;
		c->chelsio_dev = chelsio_dev;
		c->vlan = vlan;
		c->pri = pri;
		if (setup_um_udp(c))
			free_context(s);
		else
			c->state = BOUND;
	} else
		free_context(s);
}

static void connect_context(int s, struct sockaddr *laddr,
			    const struct sockaddr *serv_addr)
{
	struct chelsio_dev *chelsio_dev;
	char name[IFNAMSIZ];
	uint16_t vlan;
	uint8_t pri;

	if (lookup_endpoint(sinx_port(laddr), name, &vlan, &pri)) {
		DBG(DBG_CONNECT, "not offloading...no config entry available\n");
		return ;
	}

	chelsio_dev = find_chelsio_dev(name, laddr);
	if (chelsio_dev) {
		struct cs_context *c = get_context(s);
		if (c->state == BOUND)
			free_um_udp(s);
		copy_sa(&c->laddr.sa, laddr);
		copy_sa(&c->raddr.sa, serv_addr);
		c->chelsio_dev = chelsio_dev;
		c->vlan = vlan;
		c->pri = pri;
		if (setup_um_udp(c)) {
			free_context(s);
			goto out;
		}
		c->state = CONNECTED;
		DBG(DBG_CONNECT, "binding fd %d to %s\n", s, chelsio_dev->name);
	} else {
		DBG(DBG_CONNECT, "No device found!\n");
		free_context(s);
	}
out:
	return;
}

static void free_epcontext(struct epoll_context *epc)
{
	struct epoller *e, *tmp;

	LIST_FOREACH_SAFE(e, &epc->pollers, list, tmp) {
		LIST_REMOVE(e, list);
		free(e);
	}
	epc->epfd = -1;
}

int close(int fd)
{
	if (!init)
		call_cs_init();
	assert(socket_funcs.close);
	if (valid_context(fd)) {
		DBG(DBG_CLOSE, "Enter fd %d\n", fd);
		assert(fd == contexts[fd]->sockfd);
		DBG(DBG_CLOSE, "freeing context for fd %d\n", fd);
		free_context(fd);
	}
	if (valid_epoll_context(fd)) {
		assert(fd == epoll_contexts[fd]->epfd);
		free_epcontext(epoll_contexts[fd]);
	}
	return socket_funcs.close(fd);
}

int dup(int oldfd)
{
	if (!init)
		call_cs_init();
	DBG(DBG_DUP, "Enter oldfd %u\n", oldfd);
	return socket_funcs.dup(oldfd);
}

int dup2(int oldfd, int newfd)
{
	if (!init)
		call_cs_init();
	DBG(DBG_DUP, "Enter oldfd %u newfd %u\n", oldfd, newfd);
	return socket_funcs.dup2(oldfd, newfd);
}

int dup3(int oldfd, int newfd, int flags)
{
	if (!init)
		call_cs_init();
	DBG(DBG_DUP, "Enter oldfd %u newfd %u flags 0x%x\n", oldfd, newfd,
	    flags);
	return socket_funcs.dup3(oldfd, newfd, flags);
}

#define SOCK_TYPE_MASK 0xf /* from kernel include/linux/net.h */

int socket(int domain, int type, int protocol)
{
	int s;
	int masked_type = type & SOCK_TYPE_MASK;

	if (!init)
		call_cs_init();
	s = socket_funcs.socket(domain, type, protocol);
	DBG(DBG_SOCKET, "Enter domain %u type %u masked_type %u fd %d\n", domain, type, masked_type, s);
	if ((s >= 0) && (domain == PF_INET || domain == PF_INET6) && (masked_type == SOCK_DGRAM)) {
		struct cs_context *c = get_context(s);
		if (c->sockfd != -1) {
			free_context(s);
		}
		c->sockfd = s;
		DBG(DBG_SOCKET, "Shadowing fd %d\n", s);
	}
	return s;
}

int bind(int sockfd, const struct sockaddr *my_addr, socklen_t addrlen)
{
	struct sockaddr_storage sas;
	socklen_t slen = addrlen;
	int ret;

	if (!init)
		call_cs_init();
#ifdef DEBUG
{
	char p[INET6_ADDRSTRLEN];
	if (!inet_ntop(my_addr->sa_family, sinx_addrp(SA(my_addr)), p, sizeof p))
		strcpy(p, "n/a");
	DBG(DBG_BIND, "enter addr %s port %u\n", p, ntohs(sinx_port(SA(my_addr))));
}
#endif
	ret = socket_funcs.bind(sockfd, my_addr, addrlen);
	if (ret || !valid_context(sockfd))
		return ret;
	if (getsockname(sockfd, SA(&sas), &slen)) {
		return ret;
	}

	bind_context(sockfd, SA(&sas));
	return ret;
}

int connect(int sockfd, const struct sockaddr *serv_addr, socklen_t addrlen)
{
	socklen_t slen = addrlen;
	struct sockaddr_storage sas;
	int ret;

	if (!init)
		call_cs_init();
	DBG(DBG_CONNECT, "enter addr %s port %u\n",
	    inet_ntoa(((struct sockaddr_in *)serv_addr)->sin_addr),
	    ntohs(((struct sockaddr_in *)serv_addr)->sin_port));
	ret = socket_funcs.connect(sockfd, serv_addr, addrlen);
	if (ret || !valid_context(sockfd))
		return ret;

	if (getsockname(sockfd, SA(&sas), &slen)) {
		return ret;
	}
#ifdef DEBUG
{
	char lastr[INET6_ADDRSTRLEN], rastr[INET6_ADDRSTRLEN];
	
	DBG(DBG_CONNECT, "fd %u laddr:port %s:%u raddr:port %s:%u\n",
	    sockfd,
	    inet_ntop(AF_INET, sinx_addrp(SA(&sas)), lastr, sizeof lastr), ntohs(sinx_port(SA(&sas))),
	    inet_ntop(AF_INET, sinx_addrp(SA(serv_addr)), rastr, sizeof rastr), ntohs(sinx_port(SA(serv_addr))));
}
#endif
	connect_context(sockfd, SA(&sas), serv_addr);
	return ret;
}

static void iov_copyfrom(void *dst, const struct msghdr *msg, size_t len)
{
	int i;

	for (i = 0; i < msg->msg_iovlen; i++) {
		memcpy(dst, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
		dst += msg->msg_iov[i].iov_len;
		len -= msg->msg_iov[i].iov_len;
	}
	assert(len == 0);
}

static void iov_copyto(struct msghdr *msg, void *src, size_t tot)
{
	int i = 0;
	void *dst = msg->msg_iov[0].iov_base;
	int rem = msg->msg_iov[0].iov_len, len;

	while (tot) {
		len = min(tot, rem);
		memcpy(dst, src, len);
		if (tot == len)
			break;
		tot -= len;
		rem -= len;
		src += len;
		if (rem == 0) {
			i++;
			if (i == msg->msg_iovlen) {
				msg->msg_flags = MSG_TRUNC;
				break;
			}
			dst = msg->msg_iov[i].iov_base;
			rem = msg->msg_iov[i].iov_len;
		} else
			dst += len;
	}
	return;
}

static ssize_t fast_sendto(struct cs_context *c, const void *buf,
			   size_t len, const struct sockaddr *to, const struct msghdr *msg)
{
	struct cs_buf *b;
	struct ibv_sge *sge;
	struct udp_send_wr *wr;
	int ret = 0;

	DBG(DBG_WR, "Enter sockfd %d\n", c->sockfd);

	INC_STAT(c, fast_sends);
	assert(c->snd_cnt < sq_depth);
	next_sq_buf(c, &b, &sge, &wr);
	if (buf)
		memcpy(b->addr + hdr_room, buf, len);
	else
		iov_copyfrom(b->addr + hdr_room, msg, len);
	sge->addr = (uint64_t)(unsigned long)b->addr + hdr_room;
	sge->length = len;
	sge->lkey = c->bufs_mr->lkey;
	wr->sg_list = sge;
	wr->num_sge = 1;
	wr->wr_id = (uint64_t)(unsigned long)b;
	b->wc_count = 1;

	myspin_lock(&c->lock);
	inc_sq_idx(c);
	c->snd_cnt++;
	assert(c->snd_cnt <= sq_depth);

	/*
	 * Enter coalescing mode once the SQ is at
	 * least sq_coal full of incomplete wrs.
	 */
	if (!c->coalescing && c->snd_cnt == sq_coal) {
		struct epoll_event e;

		c->coalescing = 1;
		if (!blast) {
			e.data.ptr = c;
			e.events = EPOLLIN;
			socket_funcs.epoll_ctl(sq_epoll_fd, EPOLL_CTL_ADD, c->sq_chan->fd, &e);
			ibv_req_notify_cq(c->scq, 0);
		}
	}

	if (len <= c->max_inline && !c->coalescing)
		wr->send_flags = UDP_SEND_INLINE;
	else
		wr->send_flags = 0;
	if (hdr_room)
		wr->send_flags |= UDP_SEND_HDR_ROOM;

	/*
	 * When in coalescing mode, we coalesce 
	 * until we hit sq_coal multiple's worth
 	 * of coalesced packets.  Then we force
	 * a signaled send of all pending packets.
	 * The result is that we send arrays of
	 * wrs of length sq_coal down at a time.
	 *
	 * NOTE: the algorithm requires these arrays
	 * of wrs be aligned on an sq_coal boundary in 
	 * the sq to avoid dealing with an array that
	 * crosses the end of the sq.
	 */
	assert(b->status == FREE);
	if (c->coalescing && (c->sq_idx % sq_coal)) {
		b->status = PENDING;
		copy_sa(SA(&b->peer), SA(to));
		wr->peer = SA(&b->peer);
		c->sq_coal_count++;
	} else {
		wr->peer = (struct sockaddr *)to;
		wr->send_flags |= IBV_SEND_SIGNALED;
		b->wc_count += c->sq_coal_count;
		b->status = POSTED;
		ret = udp_post_send_many(c->qp, wr - c->sq_coal_count, b->wc_count);
		assert(!ret);
		if (c->sq_coal_count) {
			c->coal_sum += c->sq_coal_count;
			c->coal_count++;
		}
		c->sq_coal_count = 0;
	}
	if (ret) {
		errno = ret;
		dec_sq_idx(c);
		c->snd_cnt--;
	} else {
		do {
			ret = poll_one_scqe(c);
			if (ret)
				goto out;
		} while (c->snd_cnt == sq_depth);
		ret = 0;
	}
out:
	myspin_unlock(&c->lock);
	return ret ? -1 : len;
}

static void update_slowpath_status(struct cs_context *c)
{
	if (c->slowpath) {
		int bytes;
		if (!ioctl(c->sockfd, SIOCOUTQ, &bytes) && bytes == 0) {
			c->slowpath = 0;
			DBG(DBG_IO, "exit slow path fd %d\n", c->sockfd);
		}
	}
}

ssize_t write(int fd, const void *buf, size_t count)
{
	struct cs_context *c;
	int ret;

	if (!init)
		call_cs_init();
	c = get_context(fd);
	if (c->state == CONNECTED) {
		DBG(DBG_WRITE, "Enter s %d sockfd %d\n", fd, c->sockfd);
		update_slowpath_status(c);
		DBG(DBG_WRITE, "slowpath %d count %ld ulp_mss %d\n", c->slowpath, count, ulp_mss(c));
		if (!c->slowpath && count <= ulp_mss(c) &&
		    route_ours(c, &c->raddr.sa)) {
			ret = fast_sendto(c, buf, count, &c->raddr.sa, NULL);
		} else {
			DBG(DBG_WRITE, "enter slow path fd %d\n", c->sockfd);
			c->slowpath = 1;
			ret = drain_scq(c);
			if (ret)
				goto out;
			do {
				ret = socket_funcs.write(fd, buf, count);
			} while (ret == -1 && errno == EAGAIN && !c->nonblocking);
			INC_STAT(c, slow_sends);
		}
	} else {
		ret = socket_funcs.write(fd, buf, count);
		INC_STAT(c, slow_sends);
	}
out:
	return ret;
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
	struct cs_context *c;
	int ret;

	if (!init)
		call_cs_init();
	c = get_context(fd);
	if (c->state == CONNECTED) {
		size_t count = 0;
		int i;

		DBG(DBG_WRITE, "Enter s %d sockfd %d\n", fd, c->sockfd);
		update_slowpath_status(c);
		DBG(DBG_WRITE, "slowpath %d count %ld ulp_mss %d\n", c->slowpath, count, ulp_mss(c));
		for (i = 0; i < iovcnt; i++)
			count += iov[i].iov_len;
		if (!c->slowpath && count <= ulp_mss(c) &&
		    route_ours(c, &c->raddr.sa)) {
			struct msghdr m;

			memset(&m, 0, sizeof m);
			m.msg_iov = (struct iovec *)iov;
			m.msg_iovlen = iovcnt;
			ret = fast_sendto(c, NULL, count, &c->raddr.sa, &m);
		} else {
			DBG(DBG_WRITE, "enter slow path fd %d\n", c->sockfd);
			c->slowpath = 1;
			ret = drain_scq(c);
			if (ret)
				goto out;
			do {
				ret = socket_funcs.writev(fd, iov, iovcnt);
			} while (ret == -1 && errno == EAGAIN && !c->nonblocking);
			INC_STAT(c, slow_sends);
		}
	} else {
		ret = socket_funcs.writev(fd, iov, iovcnt);
		INC_STAT(c, slow_sends);
	}
out:
	return ret;
}

ssize_t send(int s, const void *buf, size_t len, int flags)
{
	struct cs_context *c;
	int ret;

	if (!init)
		call_cs_init();
	c = get_context(s);
	if (c->state == CONNECTED) {
		DBG(DBG_SEND, "Enter s %d sockfd %d\n", s, c->sockfd);
		update_slowpath_status(c);
		if (!c->slowpath && len <= ulp_mss(c) &&
		    route_ours(c, &c->raddr.sa)) {
			ret = fast_sendto(c, buf, len, &c->raddr.sa, NULL);
		} else {
			int nonblocking = c->nonblocking || (flags & MSG_DONTWAIT);
			DBG(DBG_SEND, "enter slow path fd %d\n", c->sockfd);
			c->slowpath = 1;
			ret = drain_scq(c);
			if (ret)
				goto out;
			do {
				ret = socket_funcs.send(s, buf, len, flags);
			} while (ret == -1 && errno == EAGAIN && !nonblocking);
			INC_STAT(c, slow_sends);
		}
	} else {
		ret = socket_funcs.send(s, buf, len, flags);
		INC_STAT(c, slow_sends);
	}
out:
	DBG(DBG_SEND, "Exit sockfd %d ret %d\n", c->sockfd, ret);
	return ret;
}

ssize_t sendto(int s, const void *buf, size_t len, int flags,
	       const struct sockaddr *to, socklen_t tolen)
{
	struct cs_context *c;
	int ret;

	if (!init)
		call_cs_init();
	c = get_context(s);
	if (c->state >= BOUND) {
		DBG(DBG_SENDTO, "Enter s %d sockfd %d len %ld flags 0x%x\n", s, c->sockfd, len, flags);
		update_slowpath_status(c);
		if (!to)
			to =  &c->raddr.sa;
		if (!c->slowpath && len <= ulp_mss(c) &&
		    route_ours(c, to)) {
			ret = fast_sendto(c, buf, len, to, NULL);
		} else {
			int nonblocking = c->nonblocking || (flags & MSG_DONTWAIT);
			DBG(DBG_SENDTO, "enter slow path fd %d\n", c->sockfd);
			c->slowpath = 1;
			ret = drain_scq(c);
			if (ret)
				goto out;
			do {
				ret = socket_funcs.sendto(s, buf, len, flags,
							  to, tolen);
			} while (ret == -1 && errno == EAGAIN && nonblocking);
			INC_STAT(c, slow_sends);
		}
	} else {
		DBG(DBG_SENDTO, "slowpath sockfd %d\n", c->sockfd);
		ret = socket_funcs.sendto(s, buf, len, flags, to, tolen);
		INC_STAT(c, slow_sends);

		if (ret >= 0 && valid_context(s)) {
			struct sockaddr sa;
			socklen_t slen = sizeof sa;

			if (getsockname(s, &sa, &slen)) {
				goto out;
			}
			bind_context(s, &sa);
		}
	}
out:
	return ret;
}

static int tot_len(const struct msghdr *msg)
{
	int i;
	int len = 0;

	for (i = 0; i < msg->msg_iovlen; i++)
		len += msg->msg_iov[i].iov_len;
	return len;
}

ssize_t sendmsg(int s, const struct msghdr *msg, int flags)
{
	struct cs_context *c;
	int ret;
	int len;
	struct sockaddr *sap;

	if (!init)
		call_cs_init();
	c = get_context(s);
	if (c->state >= BOUND) {
		DBG(DBG_SENDMSG, "Enter s %d sockfd %d\n", s, c->sockfd);
		update_slowpath_status(c);
		if (c->state == CONNECTED)
			sap = &c->raddr.sa;
		else
			sap= (struct sockaddr *)msg->msg_name;
		if (!c->slowpath && !msg->msg_controllen && route_ours(c, sap) &&
		    ((len = tot_len(msg)) <= ulp_mss(c))) {
			ret = fast_sendto(c, NULL, len, sap, msg);
		} else {
			int nonblocking = c->nonblocking || (flags & MSG_DONTWAIT);
			DBG(DBG_SENDMSG, "enter slow path fd %d\n", c->sockfd);
			c->slowpath = 1;
			ret = drain_scq(c);
			if (ret)
				goto out;
			do {
				ret = socket_funcs.sendmsg(s, msg, flags);
			} while (ret == -1 && errno == EAGAIN && !nonblocking);
			INC_STAT(c, slow_sends);
		}
	} else {
		DBG(DBG_SENDMSG, "slowpath sockfd %d\n", c->sockfd);
		ret = socket_funcs.sendmsg(s, msg, flags);
		INC_STAT(c, slow_sends);
		if (ret >= 0 && valid_context(s)) {
			DBG(DBG_SENDMSG, "Trying to bind fd %d\n", s);
			struct sockaddr sa;
			socklen_t slen = sizeof sa;

			if (getsockname(s, &sa, &slen)) {
				DBG(DBG_SENDMSG, "getsockname failed fd %d\n", s);
				goto out;
			}
			bind_context(s, &sa);
		}
	}
out:
	DBG(DBG_SENDMSG, "Exit ret %d\n", ret);
	return ret;
}

static ssize_t udp_recvfrom(struct cs_context *c, void *buf, size_t len,
			     int flags, struct sockaddr *from,
			     socklen_t *fromlen, int count, struct msghdr *msg)
{
	int ret = 0;
	int tlen;
	struct ibv_wc wc;
	struct cs_buf *b;
	int nopeek = !(flags & MSG_PEEK);

	if (c->rbuf && nopeek) {
		post_recv_buf(c, c->rbuf);
		c->rbuf = NULL;
	}
	if (c->nonblocking || (flags & MSG_DONTWAIT))
		count = 1;
	while (count--) {
		ret = udp_poll_cq(c->rcq, &wc, from, flags);
		if (ret) {
			if (ret == ENODATA)
				continue;
			else
				break;
		}
		if (wc.status) {
			DBG(DBG_RD, "error cqe status %d\n", wc.status);
			errno = EIO;
			return -1;
		}
		break;
	}
	if (ret) {
		if (ret == ENODATA)
			errno = EAGAIN;
		else
			errno = ret;
		return -1;
	}
	if (nopeek)
		INC_STAT(c, fast_recvs);
	b = (struct cs_buf *)(uintptr_t)wc.wr_id;
	if (c->prev_rbuf || !packed) {
		if (wc.sl) {
			if (packed)
				c->rbuf = c->prev_rbuf;
			else
				c->rbuf = b;
			c->rbuf_curoff = 0;
			c->prev_rbuf = b;
		}
	} else {
		c->prev_rbuf = b;
	}
	if (wc.vendor_err) {
		syslog(LOG_NOTICE, "bad packet received - "
		       "err_vec 0x%x raw qpid %u\n",
		       wc.vendor_err, c->qp->raw_qp->qp_num);
		errno = EAGAIN;
		tlen = -1;
	} else {
		int offset;

		if (c->qp->laddr.sa.sa_family == AF_INET)
			offset = 2 + 14 + 20 + 8;
		else
			offset = 2 + 14 + 40 + 8;
		tlen = wc.byte_len > len ? len : wc.byte_len;
		if (buf)
			memcpy(buf, b->addr + c->rbuf_curoff + offset, tlen);
		else
			iov_copyto(msg, b->addr + c->rbuf_curoff + offset, tlen);
		c->rbuf_curoff += ALIGN(wc.byte_len + offset, 64); /* XXX hard coded ingpacklen! */
	}
	DBG(DBG_RD, "tlen %d\n", tlen);
	return tlen;
}

static ssize_t wait_for_data(struct cs_context *c, void *buf, size_t len,
			     int flags, struct sockaddr *from,
			     socklen_t *fromlen, struct msghdr *msg)
{
	int ret;
	int tlen;
	struct pollfd fds[2];
	struct ibv_cq *cq;
	void *ctx;

	DBG(DBG_RD, "Enter sockfd %d\n", c->sockfd);
again:
	DBG(DBG_RD, "arming CQ sockfd %d\n", c->sockfd);
	ret = ibv_req_notify_cq(c->rcq, 0);
	if (ret) {
		errno = EIO;
		return -1;
	}
	tlen = udp_recvfrom(c, buf, len, flags, from, fromlen, 1, msg);
	if (tlen == -1 && errno == EAGAIN) {
		INC_STAT(c, waits);
		DBG(DBG_RD, "Sleeping sockfd %d\n", c->sockfd);
		fds[0].revents = 0;
		fds[0].fd = c->sockfd;
		fds[0].events = POLLIN | POLLERR;
		fds[1].revents = 0;
		fds[1].fd = c->rq_chan->fd;
		fds[1].events = POLLIN | POLLERR;
		ret = socket_funcs.poll(fds, 2, -1);
		if (ret == -1) {
			DBG(DBG_RD, "poll error: %s\n", strerror(errno));
			return -1;
		}
		DBG(DBG_RD, "awakened ret %d\n", ret);
		if (fds[0].revents) {
			tlen = socket_funcs.recvfrom(c->sockfd, buf, len, flags,
						     from, fromlen);
			DBG(DBG_RD, "revents 0x%x recvfrom tlen %d\n", fds[0].revents,
			    tlen);
			if (tlen == -1 && errno == EAGAIN)
				goto again;
		} else if (fds[1].revents) {
			ibv_get_cq_event(c->rq_chan, &cq, &ctx);
			assert(c == ctx);
			assert(cq == c->rcq);
			ibv_ack_cq_events(cq, 1);
			tlen = udp_recvfrom(c, buf, len, flags, from, fromlen,
					    1, msg);
			DBG(DBG_RD, "revents 0x%x udp_recvfrom tlen %d\n",
			    fds[1].revents, tlen);
			if (tlen == -1 && errno == EAGAIN)
				goto again;
		} else {
			DBG(DBG_RD, "Bogosity!\n");
			assert(0);
		}
	}
	return tlen;
}


static ssize_t fast_recvfrom(struct cs_context *c, void *buf, size_t len,
			     int flags, struct sockaddr *from,
			     socklen_t *fromlen, struct msghdr *msg)
{
	int tlen;
	int nonblocking = c->nonblocking || (flags & MSG_DONTWAIT);

	DBG(DBG_RD, "Enter - sockfd %d\n", c->sockfd);
again:
	if (!(c->rmsn++ % 100000)) {
		tlen = buf ?
			socket_funcs.recvfrom(c->sockfd, buf, len, flags, from, fromlen) :
			socket_funcs.recvmsg(c->sockfd, msg, flags);
		if (tlen == -1 && errno == EAGAIN) {
			tlen = udp_recvfrom(c, buf, len, flags, from, fromlen,
					    c->spin_count, msg);
			if (tlen <= 0) {
				c->spin_count = min(c->spin_count * 2,
						    spin_count);
			}
		} else {
			c->spin_count = 1;
			INC_STAT(c, slow_recvs);
		}
	} else {
		tlen = udp_recvfrom(c, buf, len, flags, from, fromlen,
				    c->spin_count, msg);
		if (tlen == -1 && errno == EAGAIN) {
			tlen = buf ?
				socket_funcs.recvfrom(c->sockfd, buf, len, flags, from, fromlen) :
				socket_funcs.recvmsg(c->sockfd, msg, flags);
			if (tlen > 0) {
				INC_STAT(c, slow_recvs);
				c->spin_count = 1;
			} else {
				c->spin_count = min(c->spin_count * 2,
						    spin_count);
			}
		}
	}
	if (tlen == -1 && errno == EAGAIN && !nonblocking) {
		if (wait_means_wait)
			tlen = wait_for_data(c, buf, len, flags, from, fromlen, msg);
		else
			goto again;
	}

	return tlen;
}

ssize_t read(int fd, void *buf, size_t count)
{
	struct cs_context *c;
	int ret;

	if (!init)
		call_cs_init();
	c = get_context(fd);
	if (c->state >= BOUND) {
		errno = 0;
		DBG(DBG_READ, "fast s %d sockfd %d\n", fd, c->sockfd);
		ret = fast_recvfrom(c, buf, count, 0, NULL, NULL, NULL);
	} else {
		ret = socket_funcs.read(fd, buf, count);
		INC_STAT(c, slow_recvs);
	}
	return ret;
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt)
{
	struct cs_context *c;
	int ret;

	if (!init)
		call_cs_init();
	c = get_context(fd);
	if (c->state >= BOUND) {
		struct msghdr m;
		
		memset(&m, 0, sizeof m);
		m.msg_iov = (struct iovec *)iov;
		m.msg_iovlen = iovcnt;
		errno = 0;
		DBG(DBG_READ, "fast s %d sockfd %d\n", fd, c->sockfd);
		ret = fast_recvfrom(c, NULL, tot_len(&m), 0, NULL, NULL, &m);
	} else {
		ret = socket_funcs.readv(fd, iov, iovcnt);
		INC_STAT(c, slow_recvs);
	}
	return ret;
}

ssize_t recv(int s, void *buf, size_t len, int flags)
{
	struct cs_context *c;
	int ret;

	if (!init)
		call_cs_init();
	c = get_context(s);
	if (c->state >= BOUND) {
		DBG(DBG_RECV, "Enter s %d sockfd %d\n", s, c->sockfd);
		ret = fast_recvfrom(c, buf, len, flags, NULL, NULL, NULL);
	} else {
		ret = socket_funcs.recv(s, buf, len, flags);
		INC_STAT(c, slow_recvs);
	}
	return ret;
}

ssize_t recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from,
		 socklen_t *fromlen)
{
	struct cs_context *c;
	int ret;

	if (!init)
		call_cs_init();
	c = get_context(s);
	if (c->state >= BOUND) {
		DBG(DBG_RECVFROM, "Enter s %d sockfd %d len %ld flags 0x%x\n", s, c->sockfd, len, flags);
		ret = fast_recvfrom(c, buf, len, flags, from, fromlen, NULL);
	} else {
		ret = socket_funcs.recvfrom(s, buf, len, flags, from, fromlen);
		INC_STAT(c, slow_recvs);
	}
	return ret;
}

ssize_t recvmsg(int s, struct msghdr *msg, int flags)
{
	struct cs_context *c;
	int ret;
	int len;

	if (!init)
		call_cs_init();
	c = get_context(s);
	if (c->state >= BOUND && !msg->msg_controllen) {
		DBG(DBG_RECVMSG, "Enter s %d sockfd %d flags 0x%x\n", s, c->sockfd, flags);
		len = tot_len(msg);
		ret = fast_recvfrom(c, NULL, len, msg->msg_flags, msg->msg_name, &msg->msg_namelen, msg);
	} else {
		ret = socket_funcs.recvmsg(s, msg, flags);
		INC_STAT(c, slow_recvs);
	}
	return ret;
}

int getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen)
{
	if (!init)
		call_cs_init();
	DBG(DBG_OPT, "Enter s %d sockfd %d\n", s, get_context(s)->sockfd);
	return socket_funcs.getsockopt(s, level, optname, optval, optlen);
}

int fast_setsockopt(struct cs_context *c, int level, int optname,
		    const void *optval, socklen_t optlen)
{
	int ret;
	int forward = 1;
	struct ip_mreq *mreq = (struct ip_mreq *)optval;

	DBG(DBG_OPT, "Enter level %d optname %d\n", level, optname);
	switch (level) {
	case IPPROTO_IP:
		switch (optname) {
#ifdef needed
		case IP_ADD_MEMBERSHIP:
			if (mreq->imr_interface.s_addr ==
			    sa_ipaddr(&c->chelsio_dev->ipaddr)) {
				struct sockaddr_in sin;
				forward = 0;
				memset(&sin, 0, sizeof sin);
				sin.sin_family = AF_INET;
				sin.sin_addr.s_addr =
					mreq->imr_multiaddr.s_addr;
				ret = udp_attach_mcast(c->qp,
						       (struct sockaddr *)&sin);
			}
			break;
		case IP_DROP_MEMBERSHIP:
			if (mreq->imr_interface.s_addr ==
			    sa_ipaddr(&c->chelsio_dev->ipaddr)) {
				struct sockaddr_in sin;
				forward = 0;
				memset(&sin, 0, sizeof sin);
				sin.sin_family = AF_INET;
				sin.sin_addr.s_addr =
					mreq->imr_multiaddr.s_addr;
				ret = udp_detach_mcast(c->qp,
						       (struct sockaddr *)&sin);
			}
			break;
#endif
		case IP_MULTICAST_IF: {
			in_addr_t *addr;
			if (optlen == sizeof(struct in_addr))
				addr = (in_addr_t *)optval;
			else
				addr = &mreq->imr_interface.s_addr;
			if (*addr == c->chelsio_dev->ipv4addr.sin_addr.s_addr)
				c->mcast_if = 1;
			break;
		}
		default:
			break;
		}
		break;
	case IPPROTO_IPV6:
		switch (optname) {
		case IPV6_MULTICAST_IF:
			if (*((int *)optval) == c->chelsio_dev->ifindex)
				c->mcast_if = 1;
			break;
		case IPV6_V6ONLY:
			c->v6only = !!(*(int *)optval);
			break;
		default:
			break;
		}
		break;
	}
	if (forward)
		ret = socket_funcs.setsockopt(c->sockfd, level, optname, optval,
					      optlen);
	return ret;
}

int setsockopt(int s, int level, int optname, const void *optval,
	       socklen_t optlen)
{
	struct cs_context *c;
	int ret;

	if (!init)
		call_cs_init();
	c = get_context(s);
	DBG(DBG_OPT, "Enter s %d sockfd %d level %d optname %d\n", s, c->sockfd, level, optname);
	if (valid_um_udp(s))
		ret = fast_setsockopt(c, level, optname, optval, optlen);
	else
		ret = socket_funcs.setsockopt(s, level, optname, optval,
					      optlen);
	return ret;
}

int fcntl(int fd, int cmd, ... /* arg */ )
{
	struct cs_context *c;
	va_list argp, largp;
	int ret;
	long i;

	if (!init)
		call_cs_init();

	c = get_context(fd);
	DBG(DBG_OPT, "Enter fd %d sockfd %d cmd %d\n", fd, c->sockfd, cmd);
	va_start(argp, cmd);
	if (valid_um_udp(fd)) {
		switch (cmd) {
		case F_SETFL: 
			va_copy(largp, argp);
			va_start(largp, cmd);
			i = va_arg(largp, long);
			c->nonblocking = (i & O_NONBLOCK) == O_NONBLOCK;
			DBG(DBG_OPT,
			    "f_SETFL 0x%lx on sockfd %d c->nonblocking %d\n",
			    i, c->sockfd, c->nonblocking);
			va_end(largp);
			break;
		}
	}
	ret = socket_funcs.fcntl(fd, cmd, va_arg(argp, long));
	va_end(argp);
	return ret;
}

/*
 * if any of the um-udp cqs are polled and are not empty,
 * then return the count of non-empty.  If any fd is not an
 * accelerated socket, then we must return 0.
 */
static int fast_poll(struct pollfd *fds, nfds_t nfds, int spin)
{
	int i;
	int count = 0;
	struct epoll_context *epc;

	assert(spin);
	do {
		for (i = 0; i < nfds; i++) {
			fds[i].revents = 0;
			if (valid_um_udp(fds[i].fd)) {
				if ((fds[i].events & POLLIN) &&
				    ibv_poll_cq(contexts[fds[i].fd]->rcq, 0, NULL)) {
					DBG(DBG_POLL, "sockfd %d rq_chan %d ready\n", contexts[fds[i].fd]->sockfd,
					    contexts[fds[i].fd]->rq_chan->fd);
					fds[i].revents |= POLLIN;
				}
				if ((fds[i].events & POLLOUT) &&
				    contexts[fds[i].fd]->qp->send_count < contexts[fds[i].fd]->qp->send_depth) {
					fds[i].revents |= POLLOUT;
				}
			} else if ((epc = epoll_contexts[fds[i].fd]) && epc->epfd != -1) {
				struct epoller *e;

				LIST_FOREACH(e, &epc->pollers, list) {
					if (!e->c)
						continue;
					if ((fds[i].events & POLLIN) && ibv_poll_cq(e->c->rcq, 0, NULL)) {
						DBG(DBG_POLL, "sockfd %d rq_chan %d epoll_fd %d ready\n", e->sockfd,
						    e->c->rq_chan->fd, fds[i].fd);
						fds[i].revents |= POLLIN;
					}
					if ((fds[i].events & POLLOUT) && e->c->qp->send_count < e->c->qp->send_depth) {
						fds[i].revents |= POLLOUT;
					}
					if (fds[i].revents)
						break;
				}
			} else
				return 0;
			if (fds[i].revents)
				count++;
		}
		if (count) {
			DBG(DBG_POLL, "%d ready\n", count);
			break;
		}
	} while (--spin);
	return count;
}

static void drain_comp_chan(struct cs_context *c)
{
	int err;
	struct ibv_cq *cq;
	void *ctx;

	err = ibv_get_cq_event(c->rq_chan, &cq, &ctx);
	if (!err) {
		assert(c == ctx);
		assert(cq == c->rcq);
		ibv_ack_cq_events(cq, 1);
	}
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	int i;
	int count = 0;
	int ret;
	struct pollfd newfds[nfds * 2], *fd;
	struct epoll_context *epc;

	if (!init)
		call_cs_init();
	DBG(DBG_POLL, "enter nfds %d\n", (int)nfds);

	ret = fast_poll(fds, nfds, timeout == 0 ? 1 : poll_spin_count);
	if (ret) {
		poll_spin_count = min(poll_spin_count << 1, max_poll_spin_count);
		return ret;
	}
	poll_spin_count = max(poll_spin_count >> 1, 1);

	/*
	 * Build a new poll fds array that consists of the fds passed in,
	 * plus the comp channel fds for any UM-UDP sockets.
	 * So newfds[0..nfds-1] contains the socket/epoll fds, and
	 * newfds[nfds..] contain all the comp channel fds for the UM-UDP
	 * endpoints.
	 */
	fd = newfds + nfds;
	for (i = 0; i < nfds; i++) {
		newfds[i] = fds[i];
		DBG(DBG_POLL, "fds[%d].events %x\n", i, fds[i].events);
		if (valid_um_udp(fds[i].fd)) {
			if (fds[i].events & POLLIN) {
				struct cs_context *c = get_context(fds[i].fd);

				DBG(DBG_POLL, "adding comp chan %d for sockfd %d\n",
				    c->rq_chan->fd, fds[i].fd);
				fd->fd = c->rq_chan->fd;
				fd->events = POLLIN;
				fd++;
				drain_comp_chan(c);
				DBG(DBG_POLL, "arming CQ sockfd %d\n", c->sockfd);
				if (ibv_req_notify_cq(c->rcq, 0)) {
					errno = EIO;
					return -1;
				}
				count++;
				INC_STAT(c, waits);
			}
		} else if ((epc = epoll_contexts[fds[i].fd]) && epc->epfd != -1 && (fds[i].events & POLLIN)) {
			struct epoller *e;

			LIST_FOREACH(e, &epc->pollers, list) {
				if (e->c) {
					drain_comp_chan(e->c);
					DBG(DBG_POLL, "arming CQ sockfd %d\n", e->c->sockfd);
					if (ibv_req_notify_cq(e->c->rcq, 0)) {
						errno = EIO;
						return -1;
					}
					INC_STAT(e->c, waits);
				}
			}
		}
	}

	DBG(DBG_POLL, "call real poll with %d fds\n", (int)(nfds + count));
	ret = socket_funcs.poll(newfds, nfds + count, timeout);
	DBG(DBG_POLL, "real poll returned %d\n", ret);
	if (ret < 0)
		return ret;
	fd = newfds + nfds;
	count = 0;

	/*
	 * Now construct the return fds array.  For any UM-UDP endpoint,
	 * if the comp chan fd has an event, then we OR it into the real
	 * socket fd's return events.  We also adjust the count returned
	 * if the revents from the real poll call were set for _both_ the
	 * sock fd and the comp chan fd for a UM-UDP endpoint. Ugh.
	 */
	for (i = 0; i < nfds; i++) {
		fds[i].revents = newfds[i].revents;
		DBG(DBG_POLL, "fds[%d].revents 0x%x\n", i, fds[i].revents);
		if (fds[i].events & POLLIN) {
			if (valid_um_udp(fds[i].fd)) {
				if (fd->revents) {
					struct cs_context *c = get_context(fds[i].fd);

					fds[i].revents |= fd->revents;
					DBG(DBG_POLL, "UM! fds[%d].revents 0x%x\n", i, fds[i].revents);
					if (newfds[i].revents)
						count--;
					drain_comp_chan(c);
				}
				fd++;
			} else if ((epc = epoll_contexts[fds[i].fd]) && epc->epfd != -1) {
				struct epoller *e;

				LIST_FOREACH(e, &epc->pollers, list) {
					drain_comp_chan(e->c);
				}
			}
		}
		if (fds[i].revents)
			count++;
	}
	DBG(DBG_POLL, "returning count %d\n", count);
	return count;
}

static void clear_fds(int n, fd_set *fds)
{
	int i;

	for (i=0; i<n; i++) {
		FD_CLR(i, fds);
	}
}

/*
 * if any of the um-udp cqs are selected and are not empty,
 * then return the count of non-empty.  If any fd is not an
 * accelerated socket, then we must return 0.
 */
static int fast_select(int nfds, fd_set *readfds, fd_set *writefds,
		       fd_set *exceptfds, int spin)
{
	int i;
	int count = 0;
	struct epoll_context *epc;
	int found;

	assert(spin);

	do {
		found = 0;
		for (i = 0; i < nfds; i++) {
			if (valid_um_udp(i)) {
				if (FD_ISSET(i, readfds) &&
				    ibv_poll_cq(contexts[i]->rcq, 0, NULL)) {
					found = 1;
					continue;
				}
				if (writefds && FD_ISSET(i, writefds) &&
				    contexts[i]->qp->send_count < contexts[i]->qp->send_depth) {
					found = 1;
					continue;
				}
			} else if ((epc = epoll_contexts[i]) && epc->epfd != -1) {
				struct epoller *e;

				LIST_FOREACH(e, &epc->pollers, list) {
					if (!e->c)
						return 0;
					if (FD_ISSET(i, readfds) && ibv_poll_cq(e->c->rcq, 0, NULL)) {
						found = 1;
						continue;
					}
					if (writefds && FD_ISSET(i, writefds) &&
					    e->c->qp->send_count < e->c->qp->send_depth) {
						found = 1;
						continue;
					}
				}
			} else
				return 0;
		}
		if (found)
			break;
	} while (--spin);
	if (spin) {
		for (i = 0; i < nfds; i++) {
			if (valid_um_udp(i)) {
				if (FD_ISSET(i, readfds) &&
				    ibv_poll_cq(contexts[i]->rcq, 0, NULL)) {
					count++;
				} else {
					FD_CLR(i, readfds);
				}
				if (writefds) {
					if (FD_ISSET(i, writefds) &&
					    contexts[i]->qp->send_count < contexts[i]->qp->send_depth) {
						count++;
					} else {
						FD_CLR(i, writefds);
					}
				}
				if (exceptfds)
					FD_CLR(i, exceptfds);
			} else if ((epc = epoll_contexts[i]) && epc->epfd != -1) {
				struct epoller *e;
				int hit;

				LIST_FOREACH(e, &epc->pollers, list) {
					if (!e->c)
						continue;
					hit = 0;
					if (FD_ISSET(i, readfds) && ibv_poll_cq(e->c->rcq, 0, NULL)) {
						hit = 1;
					} else {
						FD_CLR(i, readfds);
					}
					if (writefds) {
						if (FD_ISSET(i, writefds) &&
						    e->c->qp->send_count < e->c->qp->send_depth) {
							hit = 1;
						} else {
							FD_CLR(i, writefds);
						}
					}
					if (exceptfds)
						FD_CLR(i, exceptfds);
					if (hit) {
						count++;
						break;
					}
				}
			} else {
				FD_CLR(i, readfds);
				if (writefds)
					FD_CLR(i, writefds);
				if (exceptfds)
					FD_CLR(i, exceptfds);
			}
		}
	}
	DBG(DBG_SELECT, "%d ready\n", count);
	return count;
}

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
	   struct timeval *timeout)
{
	int i;
	int count = 0;
	int ret;
	fd_set rfds, wfds, efds;
	int sockfds[max_fds];
	int newnfds = nfds - 1;
	int found;

	if (!init)
		call_cs_init();
	DBG(DBG_SELECT, "enter nfds %d timeout %p\n", (int)nfds, timeout);
	if (readfds) {
		ret = fast_select(nfds, readfds, writefds, exceptfds,
				  timeout && timeout->tv_sec == 0 &&
				  timeout->tv_usec == 0 ? 1 : poll_spin_count);
		if (ret) {
			poll_spin_count = min(poll_spin_count << 1, max_poll_spin_count);
			return ret;
		}
	}
	PENTER(SEL);
	poll_spin_count = max(poll_spin_count >> 1, 1);

	/*
	 * Create a new set of r, w, and e fd sets composed of the
	 * original fds passed in, plus the udp_qp comp channel fds
	 * and epoll fd sets, if any.
	 */
	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&efds);
	for (i = 0; i < nfds; i++) {
		if (readfds && FD_ISSET(i, readfds)) {
			struct epoll_context *epc;

			DBG(DBG_SELECT, "adding sockfd %d to rfds\n", i);
			FD_SET(i, &rfds);
			if (valid_um_udp(i)) {
				struct cs_context *c = get_context(i);

				DBG(DBG_SELECT, "adding comp chan fd %d to rfds\n",
				    c->rq_chan->fd);
				FD_SET(c->rq_chan->fd, &rfds);
				sockfds[c->rq_chan->fd] = i;
				assert(i != 0);
				if (c->rq_chan->fd > newnfds)
					newnfds = c->rq_chan->fd;
				drain_comp_chan(c);
				DBG(DBG_SELECT, "arming CQ sockfd %d\n", c->sockfd);
				ret = ibv_req_notify_cq(c->rcq, 0);
				if (ret) {
					errno = EIO;
					return -1;
				}
				INC_STAT(c, waits);
			} else if ((epc = epoll_contexts[i]) && epc->epfd != -1) {
				struct epoller *e;

				LIST_FOREACH(e, &epc->pollers, list) {
					if (!e->c)
						continue;

					drain_comp_chan(e->c);
					DBG(DBG_SELECT, "arming epfd member sockfd %d\n", e->c->sockfd);
					ret = ibv_req_notify_cq(e->c->rcq, 0);
					if (ret) {
						errno = EIO;
						return -1;
					}
					INC_STAT(e->c, waits);
				}
			}
			sockfds[i] = -1;
		}
		if (writefds && FD_ISSET(i, writefds)) {
			DBG(DBG_SELECT, "adding sockfd %d to wfds\n", i);
			FD_SET(i, &wfds);
			sockfds[i] = -1;
		}
		if (exceptfds && FD_ISSET(i, exceptfds)) {
			DBG(DBG_SELECT, "adding sockfd %d to efds\n", i);
			FD_SET(i, &efds);
			sockfds[i] = -1;
		}
	}
	newnfds++;

	DBG(DBG_SELECT, "calling real select newnfds %d\n", newnfds);
	ret = socket_funcs.select(newnfds, readfds ? &rfds : NULL, writefds ? &wfds : NULL,
				  exceptfds ? &efds : NULL, timeout);
	DBG(DBG_SELECT, "real select returned %d\n", ret);

	count = ret;
	if (count <= 0)
		goto out;

	/*
	 * Now construct the return fd sets. For each UM-UDP endpoint selected,
	 * we potentially can have 2 bits set in the fd sets returned from
	 * the real select call.  So we need to return to the user, only the
	 * real socket fd and not the comp chan fd.
	 * In addition we must adjust the return count if both were set.
	 */
	if (readfds)
		clear_fds(nfds, readfds);
	if (writefds)
		clear_fds(nfds, writefds);
	if (exceptfds)
		clear_fds(nfds, exceptfds);
	i = 0;
	found = 0;
	while (found < ret) {
		if (readfds && FD_ISSET(i, &rfds)) {
			if (sockfds[i] < 0) {
				struct epoll_context *epc;

				FD_SET(i, readfds);
				DBG(DBG_SELECT, "sock fd %d ready for read!\n",
				    i);
				if ((epc = epoll_contexts[i]) && epc->epfd != -1) {
					struct epoller *e;

					LIST_FOREACH(e, &epc->pollers, list) {
						if (!e->c)
							continue;
						DBG(DBG_SELECT, "draining efd chan fd %d\n",
						    e->c->rq_chan->fd);
						drain_comp_chan(e->c);
					}
				}
			} else {
				struct cs_context *c = get_context(sockfds[i]);

				assert(valid_um_udp(sockfds[i]));

				DBG(DBG_SELECT,
				    "comp chan fd %d sockfds[i] %d ready!\n",
				    i, sockfds[i]);

				if (FD_ISSET(sockfds[i], &rfds))
					count--;
				FD_SET(sockfds[i], readfds);
				drain_comp_chan(c);
			}
			found++;
		}
		if (writefds && FD_ISSET(i, &wfds)) {
			FD_SET(i, writefds);
			DBG(DBG_SELECT, "sock fd %d ready for write!\n", i);
			found++;
		}
		if (exceptfds && FD_ISSET(i, &efds)) {
			FD_SET(i, exceptfds);
			DBG(DBG_SELECT, "sock fd %d ready for except!\n", i);
			found++;
		}
		i++;
	}
out:
	PEXIT(SEL);
	DBG(DBG_SELECT, "returning %d\n", count);
	return count;
}

static struct epoller *find_poller(struct epoll_context *epc, int fd)
{
	struct epoller *e;

	LIST_FOREACH(e, &epc->pollers, list)
		if (e->sockfd == fd)
			return e;
	return NULL;
}

static void update_epoll_groups(int fd)
{
	int i;
	
	for (i = 0; i < max_fds; i++) {
		struct epoller *e;

		if (!epoll_contexts[i] || epoll_contexts[i]->epfd == -1)
			continue;
		e = find_poller(epoll_contexts[i], fd);
		if (e && !e->c) {
			e->c = get_context(fd);
			DBG(DBG_EPOLL, "updated epollfd %u sockfd %u rq_chan %u\n",
			    i, fd, e->c->rq_chan->fd);
		}
	}
}

int epoll_create(int size)
{
	int epfd;
	struct epoll_context *epc;

	if (!init)
		call_cs_init();
	epfd = socket_funcs.epoll_create(size*2);
	DBG(DBG_EPOLL, "fd %d size %d\n", epfd, size*2);
	if (epfd >= 0) {
		assert(!valid_epoll_context(epfd));
		epc = get_epoll_context(epfd);
		epc->epfd = epfd;
		LIST_INIT(&epc->pollers);
		epc->count = 0;
	}
	return epfd;
}

int epoll_create1(int flags)
{
	int epfd;
	struct epoll_context *epc;

	if (!init)
		call_cs_init();
	epfd = socket_funcs.epoll_create1(flags);
	DBG(DBG_EPOLL, "fd %d flags 0x%x\n", epfd, flags);
	if (epfd >= 0) {
		assert(!valid_epoll_context(epfd));
		epc = get_epoll_context(epfd);
		epc->epfd = epfd;
		LIST_INIT(&epc->pollers);
		epc->count = 0;
	}
	return epfd;
}

static int epoll_ctl_del(struct epoll_context *epc, int fd,
			 struct epoll_event *event)
{
	int ret;
	struct epoller *e;

	e = find_poller(epc, fd);
	if (!e) {
		return EBADF;
	}

	ret = socket_funcs.epoll_ctl(epc->epfd, EPOLL_CTL_DEL, fd, event);
	if (ret)
		goto out;

	if (valid_um_udp(fd)) {
		struct cs_context *c = get_context(fd);
		ret = socket_funcs.epoll_ctl(epc->epfd, EPOLL_CTL_DEL,
					     c->rq_chan->fd, event);
		if (ret)
			goto out;
	}
	LIST_REMOVE(e, list);
	epc->count--;
	free(e);
out:
	if (ret)
		ret = errno;
	return ret;
}

static int epoll_ctl_mod(struct epoll_context *epc, int fd,
			 struct epoll_event *event)
{
	struct epoll_event ev;
	struct epoller *e;
	int ret;

	e = find_poller(epc, fd);
	if (!e) {
		return EBADF;
	}

	e->org_data = event->data;
	e->events = event->events;
	ev.data.ptr = e;
	ev.events = event->events;

	ret = socket_funcs.epoll_ctl(epc->epfd, EPOLL_CTL_MOD, fd, &ev);
	if (!ret && valid_um_udp(fd)) {
		struct cs_context *c = get_context(fd);
		ret = socket_funcs.epoll_ctl(epc->epfd, EPOLL_CTL_MOD,
					     c->rq_chan->fd, &ev);
	}
	if (ret)
		ret = errno;
	return ret;
}

static int epoll_ctl_add(struct epoll_context *epc, int fd,
			 struct epoll_event *event)
{
	struct epoller *e;
	struct epoll_event ev;
	int ret;

	e = calloc(1, sizeof *e);
	if (!e) {
		return ENOMEM;
	}

	e->events = event->events;
	e->org_data = event->data;
	e->sockfd = fd;
	if (valid_um_udp(fd) && (event->events & EPOLLIN))
		e->c = get_context(fd);
	ev.events = event->events;
	ev.data.ptr = e;

	ret = socket_funcs.epoll_ctl(epc->epfd, EPOLL_CTL_ADD, fd, &ev);
	if (!ret && e->c) {
		ev.events = EPOLLIN;
		ret = socket_funcs.epoll_ctl(epc->epfd, EPOLL_CTL_ADD,
					     e->c->rq_chan->fd, &ev);
		if (ret) {
			ret = errno;
			free(e);
		}
	}
	if (!ret) {
		epc->count++;
		LIST_INSERT_HEAD(&epc->pollers, e, list);
		DBG(DBG_EPOLL, "added fd %d rq_chan %d\n", fd,
		    e->c ? e->c->rq_chan->fd : -1);
	}
	return ret;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
	struct epoll_context *epc = epoll_contexts[epfd];
	int ret;

	if (!init)
		call_cs_init();
	DBG(DBG_EPOLL, "op %d fd %d event->data.fd %d\n", op, fd, event ? event->data.fd : -1);
	if (!epc || epc->epfd != epfd) {
		errno = EBADF;
		return -1;
	}
	switch (op) {
	case EPOLL_CTL_DEL:
		ret = epoll_ctl_del(epc, fd, event);
		break;
	case EPOLL_CTL_MOD:
		ret = epoll_ctl_mod(epc, fd, event);
		break;
	case EPOLL_CTL_ADD:
		ret = epoll_ctl_add(epc, fd, event);
		break;
	default:
		ret = EBADF;
		break;
	}
	if (ret) {
		errno = ret;
		ret = -1;
	}
	return ret;
}

static struct epoll_event *find_event(struct epoll_event *events, uint64_t data,
				      int count)
{
	while (count--) {
		if (events->data.u64 == data)
			return events;
		events++;
	}
	return NULL;
}

/*
 * if any of the um-udp cqs are in the epoll set and are not empty,
 * then return the count of non-empty.  If any fd is not an
 * accelerated socket, then we must return 0.
 */
static int fast_epoll_wait(struct epoll_context *epc,
			   struct epoll_event *events, int maxevents, int spin)
{
	struct epoller *e = NULL;
	int count = 0;

	while (spin--) {
		LIST_FOREACH(e, &epc->pollers, list) {
			if (!e->c)
				return 0;
			events->events = 0;
			if ((e->events & EPOLLIN) && ibv_poll_cq(e->c->rcq, 0, NULL)) {
				DBG(DBG_EPOLL, "sockfd %d rq_chan %d ready\n", e->sockfd,
				    e->c->rq_chan->fd);
				events->events |= EPOLLIN;
			}
			if ((e->events & EPOLLOUT) && e->c->qp->send_count < e->c->qp->send_depth) {
				events->events |= EPOLLOUT;
			}
			if (events->events) {
				events->data = e->org_data;
				events++;
				count++;
				if (count == maxevents)
					break;
			}
		}
		if (count) {
			DBG(DBG_EPOLL, "%d ready\n", count);
			break;
		}
	}
	return count;
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
	struct epoll_event *newevents, *ret_events;
	struct epoller *e;
	int ret, count;
	int i;
	struct epoll_context *epc = epoll_contexts[epfd];

	if (!init)
		call_cs_init();
	if (!epc || epc->epfd != epfd) {
		errno = EBADF;
		return -1;
	}
	if (maxevents <= 0) {
		errno = EINVAL;
		return -1;
	}

	ret = fast_epoll_wait(epc, events, maxevents,
			      timeout == 0 ? 1 : poll_spin_count);
	if (ret) {
		poll_spin_count = min(poll_spin_count << 1, max_poll_spin_count);
		return ret;
	}
	poll_spin_count = max(poll_spin_count >> 1, 1);

	DBG(DBG_EPOLL, "waiting on maxevents %d\n", maxevents * 2);
	newevents = malloc(sizeof *events * maxevents * 2);
	if (!newevents) {
		errno = ENOMEM;
		return -1;
	}

	/*
	 * Arm all the cqs.
	 */
	LIST_FOREACH(e, &epc->pollers, list) {
		if (e->c) {
			drain_comp_chan(e->c);
			DBG(DBG_EPOLL, "arming cq for sockfd %d\n", e->sockfd);
			ret = ibv_req_notify_cq(e->c->rcq, 0);
			if (ret) {
				free(newevents);
				errno = EIO;
				return -1;
			}
			INC_STAT(e->c, waits);
		}
	}
	ret = socket_funcs.epoll_wait(epfd, newevents, maxevents * 2, timeout);
	count = ret;
	if (count <= 0)
		goto out;

	/*
	 * Walk through the returned events, adding events not yet in the
	 * callers' return array to that array, and merging sockfd + comp_chan
	 * events.
	 */
	count = 0;
	for (i = 0; i < ret; i++) {
		e = newevents[i].data.ptr;
		assert(e);
		DBG(DBG_EPOLL, "sockfd %d ready!\n", e->sockfd);
		if (e->c && ibv_poll_cq(e->c->rcq, 0, NULL)) {
			DBG(DBG_EPOLL, "rq_chan %d ready!\n", e->c->rq_chan->fd);
			drain_comp_chan(e->c);
		}
		ret_events = find_event(events, e->org_data.u64, count);
		if (!ret_events) {
			ret_events = events + count;
			ret_events->events = newevents[i].events;
			ret_events->data = e->org_data;
			count++;
		} else {
			ret_events->events |= newevents[i].events;
		}
		DBG(DBG_EPOLL, "ret_events->data.fd %d events 0x%x\n",
		    ret_events->data.fd, ret_events->events);
	}
out:
	free(newevents);
	DBG(DBG_EPOLL, "returning %d\n", count);
	return count;
}

void  __attribute__ ((constructor)) cs_init(void)
{
	char *error_str;
	struct rlimit l;
	char *c;

	if (init++)
		return;
#ifdef DEBUG
	c = getenv("CXGB4_SOCK_DEBUG");
	if (c) {
		dbg_flags = strtol(c, NULL, 0);
		DBG(DBG_INIT, "dbg_flags 0x%x\n", dbg_flags);
	}
	c = getenv("CXGB4_SOCK_DEBUG_FILE");
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
				VERBOSE(DBG_INIT, "failure opening %s (%s). Using syslog for logging...\n", c, sys_errlist[errno]);
				dbg_dst = DBG_DST_SYSLOG;
			}
		}

		DBG(DBG_INIT, "dbg_flags 0x%x dbg_dst %s\n", dbg_flags, c);
	}
#endif
	DBG(DBG_INIT, "Enter\n");
	c = getenv("CXGB4_SOCK_SPIN_COUNT");
	if (c) {
		spin_count = strtol(c, NULL, 0);
		if (spin_count < 0)
			spin_count = 1;
	}
	c = getenv("CXGB4_SOCK_POLL_SPIN_COUNT");
	if (c) {
		max_poll_spin_count = strtol(c, NULL, 0);
		if (max_poll_spin_count < 0)
			max_poll_spin_count = 1;
		poll_spin_count = max_poll_spin_count;
	}
	DBG(DBG_INIT, "spin_count %ld poll_spin_count %ld\n", spin_count, poll_spin_count);
#ifdef needed
	libc_dl_handle = dlopen( "/lib64/libc.so.6", RTLD_LAZY );
	if (!libc_dl_handle) {
		libc_dl_handle = dlopen( "/lib/libc.so.6", RTLD_LAZY );
		if (!libc_dl_handle) {
			fprintf(stderr, "%s\n", dlerror());
			return;
		}
	}
#endif
	socket_funcs.close = dlsym( libc_dl_handle, "close" );
	if ( NULL != ( error_str = dlerror(  ) ) ) {
		fprintf( stderr, "%s\n", error_str );
	}
	socket_funcs.socket = dlsym( libc_dl_handle, "socket" );
	if ( NULL != ( error_str = dlerror(  ) ) ) {
		fprintf( stderr, "%s\n", error_str );
	}
	socket_funcs.bind = dlsym( libc_dl_handle, "bind" );
	if ( NULL != ( error_str = dlerror(  ) ) ) {
		fprintf( stderr, "%s\n", error_str );
	}
	socket_funcs.connect = dlsym( libc_dl_handle, "connect" );
	if ( NULL != ( error_str = dlerror(  ) ) ) {
		fprintf( stderr, "%s\n", error_str );
	}
	socket_funcs.write = dlsym( libc_dl_handle, "write" );
	if ( NULL != ( error_str = dlerror(  ) ) ) {
		fprintf( stderr, "%s\n", error_str );
	}
	socket_funcs.writev = dlsym( libc_dl_handle, "writev" );
	if ( NULL != ( error_str = dlerror(  ) ) ) {
		fprintf( stderr, "%s\n", error_str );
	}
	socket_funcs.send = dlsym( libc_dl_handle, "send" );
	if ( NULL != ( error_str = dlerror(  ) ) ) {
		fprintf( stderr, "%s\n", error_str );
	}
	socket_funcs.sendto = dlsym( libc_dl_handle, "sendto" );
	if ( NULL != ( error_str = dlerror(  ) ) ) {
		fprintf( stderr, "%s\n", error_str );
	}
	socket_funcs.sendmsg = dlsym( libc_dl_handle, "sendmsg" );
	if ( NULL != ( error_str = dlerror(  ) ) ) {
		fprintf( stderr, "%s\n", error_str );
	}
	socket_funcs.read = dlsym( libc_dl_handle, "read" );
	if ( NULL != ( error_str = dlerror(  ) ) ) {
		fprintf( stderr, "%s\n", error_str );
	}
	socket_funcs.readv = dlsym( libc_dl_handle, "readv" );
	if ( NULL != ( error_str = dlerror(  ) ) ) {
		fprintf( stderr, "%s\n", error_str );
	}
	socket_funcs.recv = dlsym( libc_dl_handle, "recv" );
	if ( NULL != ( error_str = dlerror(  ) ) ) {
		fprintf( stderr, "%s\n", error_str );
	}
	socket_funcs.recvfrom = dlsym( libc_dl_handle, "recvfrom" );
	if ( NULL != ( error_str = dlerror(  ) ) ) {
		fprintf( stderr, "%s\n", error_str );
	}
	socket_funcs.recvmsg = dlsym( libc_dl_handle, "recvmsg" );
	if ( NULL != ( error_str = dlerror(  ) ) ) {
		fprintf( stderr, "%s\n", error_str );
	}
	socket_funcs.dup = dlsym( libc_dl_handle, "dup" );
	if ( NULL != ( error_str = dlerror(  ) ) ) {
		fprintf( stderr, "%s\n", error_str );
	}
	socket_funcs.dup2 = dlsym( libc_dl_handle, "dup2" );
	if ( NULL != ( error_str = dlerror(  ) ) ) {
		fprintf( stderr, "%s\n", error_str );
	}
	socket_funcs.dup3 = dlsym( libc_dl_handle, "dup3" );
	if ( NULL != ( error_str = dlerror(  ) ) ) {
		fprintf( stderr, "%s\n", error_str );
	}
	socket_funcs.setsockopt = dlsym( libc_dl_handle, "setsockopt" );
	if ( NULL != ( error_str = dlerror(  ) ) ) {
		fprintf( stderr, "%s\n", error_str );
	}
	socket_funcs.getsockopt = dlsym( libc_dl_handle, "getsockopt" );
	if ( NULL != ( error_str = dlerror(  ) ) ) {
		fprintf( stderr, "%s\n", error_str );
	}
	socket_funcs.poll = dlsym( libc_dl_handle, "poll" );
	if ( NULL != ( error_str = dlerror(  ) ) ) {
		fprintf( stderr, "%s\n", error_str );
	}
	socket_funcs.select = dlsym( libc_dl_handle, "select" );
	if ( NULL != ( error_str = dlerror(  ) ) ) {
		fprintf( stderr, "%s\n", error_str );
	}
	socket_funcs.epoll_create = dlsym( libc_dl_handle, "epoll_create" );
	if ( NULL != ( error_str = dlerror(  ) ) ) {
		fprintf( stderr, "%s\n", error_str );
	}
	socket_funcs.epoll_create1 = dlsym( libc_dl_handle, "epoll_create1" );
	if ( NULL != ( error_str = dlerror(  ) ) ) {
		fprintf( stderr, "%s\n", error_str );
	}
	socket_funcs.epoll_ctl = dlsym( libc_dl_handle, "epoll_ctl" );
	if ( NULL != ( error_str = dlerror(  ) ) ) {
		fprintf( stderr, "%s\n", error_str );
	}
	socket_funcs.epoll_wait = dlsym( libc_dl_handle, "epoll_wait" );
	if ( NULL != ( error_str = dlerror(  ) ) ) {
		fprintf( stderr, "%s\n", error_str );
	}
	socket_funcs.fcntl = dlsym( libc_dl_handle, "fcntl" );
	if ( NULL != ( error_str = dlerror(  ) ) ) {
		fprintf( stderr, "%s\n", error_str );
	}
	if (getrlimit(RLIMIT_NOFILE, &l))
		max_fds = 1024;
	else
		max_fds = l.rlim_cur;
	DBG(DBG_INIT, "max_fds %d\n", max_fds);
	page_size = sysconf(_SC_PAGESIZE);
	contexts = calloc(max_fds, sizeof *contexts);
	assert(contexts);
	epoll_contexts = calloc(max_fds, sizeof *epoll_contexts);
	assert(epoll_contexts);
	c = getenv("CXGB4_SOCK_QUIET");
	if (!c) {
		printf("Using WireDirect UDP 1.1 Copyright 2011-2013 "
		       "Chelsio Communications\n");
	} else
		quiet = 1;

	c = getenv("CXGB4_SOCK_MAX_INLINE");
	if (c) {
		max_inline_specified = 1;
		max_inline = strtol(c, NULL, 0);
		if (max_inline < 0)
			max_inline = 0;
	}
	DBG(DBG_INIT, "max_inline %ld max_inline_specified %ld\n", max_inline, max_inline_specified);

	c = getenv("CXGB4_SOCK_NO_HDR_ROOM");
	if (c) {
		hdr_room = 0;
		VERBOSE(DBG_INIT, "WD-UDP: UDP_SEND_HDR_ROOM disabled.\n");
	}
	c = getenv("CXGB4_SOCK_HUGE_PAGES");
	if (c) {
		use_huge_pages = strtol(c, NULL, 0);
		use_huge_pages = !!use_huge_pages;
	}
	c = getenv("CXGB4_SOCK_HUGE_PAGE_SIZE");
	if (c) {
		huge_page_size = strtol(c, NULL, 0);
		if (huge_page_size < HUGE_BUF_SIZE) {
			VERBOSE(DBG_INIT, "Invalid huge page size %d. Disabling huge page support.\n", huge_page_size);
			use_huge_pages = 0;
		}
	}
	if (use_huge_pages)
		VERBOSE(DBG_INIT, "Using huge pages, page_size = %d, buf_size = %u.\n", huge_page_size, HUGE_BUF_SIZE);
	c = getenv("CXGB4_SOCK_SQ_DEPTH");
	if (c) {
		sq_depth = strtol(c, NULL, 0);
		if (sq_depth <= 0) {
			VERBOSE(DBG_INIT, "Invalid CXGB4_SOCK_SQ_DEPTH %d. Using default %d.\n", sq_depth, SQ_DEPTH);
			sq_depth = SQ_DEPTH;
		}
	}
	c = getenv("CXGB4_SOCK_RQ_DEPTH");
	if (c) {
		rq_depth = strtol(c, NULL, 0);
		if (rq_depth <= 0) {
			VERBOSE(DBG_INIT, "Invalid CXGB4_SOCK_RQ_DEPTH %d. Using default %d.\n", rq_depth, RQ_DEPTH);
			rq_depth = RQ_DEPTH;
		}
	}
	c = getenv("CXGB4_SOCK_SQ_COAL");
	if (c) {
		sq_coal = strtol(c, NULL, 0);
		if (sq_coal <= 0) {
			VERBOSE(DBG_INIT, "Invalid CXGB4_SOCK_COAL %d. Using default %d.\n", sq_coal, SQ_COAL);
			sq_coal = SQ_COAL;
		}
	}
	sq_depth = ALIGN(sq_depth, sq_coal);
	c = getenv("CXGB4_SOCK_UDP_PACKED_MODE");
	if (c) {
		packed = strtol(c, NULL, 0);
		if (packed) {
			packed = UDP_PACKED_MODE;
			VERBOSE(DBG_INIT, "UDP_PACKED_MODE enabled.\n");
		} else
			packed = 0;
	}
	if (packed) {
		rq_depth /= 2;
		if (use_huge_pages)
			rq_depth /= 2;
	}
	VERBOSE(DBG_INIT, "Using RQ_DEPTH %d SQ_DEPTH %d SQ_COAL %d\n", rq_depth, sq_depth, sq_coal);
	c = getenv("CXGB4_SOCK_BLAST");
	if (c) {
		blast = strtol(c, NULL, 0);
		if (blast)
			VERBOSE(DBG_INIT, "BLAST mode for packet generation applications.\n");
	}
	c = getenv("CXGB4_SOCK_WAIT");
	if (c) {
		wait_means_wait = strtol(c, NULL, 0);
		if (!wait_means_wait)
			VERBOSE(DBG_INIT, "Never block/wait, always spin.\n");
	}
	build_t4_dev_list();
	c = getenv("CXGB4_SOCK_CFG");
	if (c)
		parse_config_file(c);
	else
		parse_config_file(CONFIG_FILE);

	sq_epoll_fd = socket_funcs.epoll_create1(0);
	assert(sq_epoll_fd >= 0);
}

void  __attribute__ ((destructor)) cs_fini(void)
{
	DBG(DBG_INIT, "Enter\n");
	profile_report();
	if (sun.sun_path) {
		unlink(sun.sun_path);
	}
}
