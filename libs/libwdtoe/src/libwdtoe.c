#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <dlfcn.h>
#include <math.h>
#include <pthread.h>
#include <net/if.h>
#include <limits.h>
#include <stddef.h>

#include "buffer.h"
#include "libwdtoe.h"
#include "common.h"
#include "t4_msg.h"
#include "t4_regs_values.h"
#include "t4fw_interface.h"
#include "ntuples.h"
#include "stats.h"
#include "conn_info.h"
#include "chardev.h"
#include "mmap.h"
#include "device.h"
#include "cpl.h"

#define CONFIG_FILE "/etc/wdtoe.conf"

#define min(a, b) ((a) > (b) ? (b) : (a))
#define max(a, b) ((a) > (b) ? (a) : (b))

#define POLL_SPIN_COUNT 50000

static unsigned long poll_spin_count = POLL_SPIN_COUNT;
static unsigned long max_poll_spin_count = POLL_SPIN_COUNT;

unsigned dbg_flags;
int ma_wr;

struct wdtoe_device *wd_dev = NULL;
static int stats_thread_started = 0;
static volatile int iq_created = 0;

int global_devfd;

static pthread_t global_thread;
static pthread_t stats_thread;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

struct sockaddr_un sun;

/*
 * Counter for the number of connections for this instance of the library
 */
static volatile int connections = 0;

/*
 * Information mapping (sockfd <-> tid). Here we cache the last tuple
 * we used for quick lookup
 */
static struct wdtoe_cached_conn_map latest_conn_map;

/*
 * Integer containing the value for the Tx hold threshold
 */
static int tx_hold_thres;

struct conn_tuple *k_conn_tuples;
struct passive_tuple *k_passive_tuples;
struct wdtoe_conn_info *conn_info_new;
struct wdtoe_listsvr *priv_svr_info;

unsigned long wdtoe_page_size;
unsigned long wdtoe_page_shift;
unsigned long wdtoe_page_mask;



/*
 * The code in the following '#if 0/#endif' section is used for perf tests
 * only. Turn to '#if 1' and place a PENTER(SEL), PEXIT(SEL) around a code
 * section you want to measure. You can have as many entries in the enum as
 * you want. 'SEL' is just one of them. In order for results to be printed
 * at the end of the application run, turn '#if 0' to '#if 1' in function
 * libwdtoe_fini().
 */
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
	SEL,
	RCV_MEMCPY,
	LAST
};

#include "get_clock.h"
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
	if (prof_sample_idx[RCV_MEMCPY]) {
		printf("RCV_MEMCPY: calls %u samples %u\n", prof_calls[RCV_MEMCPY],
		       prof_sample_idx[RCV_MEMCPY] - SKIP);
		compute_report(RCV_MEMCPY);
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

static void load_sym_fail(const char *fn, char *err_str)
{
	DBG(DBG_INIT, "failed to load `%s' dynamically (%s)\n", fn, err_str);
}

/*
 * The WD-TOE library intercepts most of the socket-related system calls in
 * order to perform connection acceleration. However, there are times when
 * we need to let the OS deal with the call. For that purpose we need to keep
 * pointers to the actual system calls, available through the libc.
 *
 * E.g. WD-TOE intercepts the send() syscall. Meaning that when an application
 * is linked against libwdtoe.so send() will be considered as a WD-TOE routine.
 * If for some reason the lib decides that this send call has to be dealt with
 * by the Kernel (slow path), we need a way to call the original send(). That's
 * why in the following function we are setting up function pointers to the
 * original send(), recv(), etc. symbols. So that in out send() implementation
 * we can call sys_send(), which will trigger the real system call.
 *
 * Note: It's actually a little bit more complex. Here we are grabbing the lower
 * symbols. Indeed, there may be another library that, just like WD-TOE, is
 * redefining socket calls. If that's the case we want to grab those symbols so
 * we don't by-pass that library. That's what we are doing through dlsym().
 */
static void hook_lower_symbols(void)
{
	char *err_str;
	dlerror();	/* clear any existing error */

	/* getting "lower/real" socket() symbol */
	if (!sys_socket)
		sys_socket = dlsym(RTLD_NEXT, "socket");
	if ((err_str = dlerror()) != NULL)
		load_sym_fail("socket", err_str);

	/* getting "lower/real" listen() symbol */
	if (!sys_listen)
		sys_listen = dlsym(RTLD_NEXT, "listen");
	if ((err_str = dlerror()) != NULL)
		load_sym_fail("listen", err_str);

	/* getting "lower/real" connect() symbol */
	if (!sys_connect)
		sys_connect = dlsym(RTLD_NEXT, "connect");
	if ((err_str = dlerror()) != NULL)
		load_sym_fail("connect", err_str);

	/*getting "lower/real accept() symbol */
	if (!sys_accept)
		sys_accept = dlsym(RTLD_NEXT, "accept");
	if ((err_str = dlerror()) != NULL)
		load_sym_fail("accept", err_str);

	/* getting "lower/real" write() symbol */
	if (!sys_write)
		sys_write = dlsym(RTLD_NEXT, "write");
	if ((err_str = dlerror()) != NULL)
		load_sym_fail("write", err_str);

	/* getting "lower/real" writev() symbol */
	if (!sys_writev)
		sys_writev = dlsym(RTLD_NEXT, "writev");
	if ((err_str = dlerror()) != NULL)
		load_sym_fail("writev", err_str);

	/* getting "lower/real" send() symbol */
	if (!sys_send)
		sys_send = dlsym(RTLD_NEXT, "send");
	if ((err_str = dlerror()) != NULL)
		load_sym_fail("send", err_str);

	/* getting "lower/real" sendto() symbol */
	if (!sys_sendto)
		sys_sendto = dlsym(RTLD_NEXT, "sendto");
	if ((err_str = dlerror()) != NULL)
		load_sym_fail("sendto", err_str);

	if (!sys_sendmsg)
		sys_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
	if ((err_str = dlerror()) != NULL)
		load_sym_fail("sendmsg", err_str);

	/* getting "lower/real" read() symbol */
	if (!sys_read)
		sys_read = dlsym(RTLD_NEXT, "read");
	if ((err_str = dlerror()) != NULL)
		load_sym_fail("read", err_str);

	/* getting "lower/real" readv() symbol */
	if (!sys_readv)
		sys_readv = dlsym(RTLD_NEXT, "readv");
	if ((err_str = dlerror()) != NULL)
		load_sym_fail("readv", err_str);

	/* getting "lower/real" recv() symbol */
	if (!sys_recv)
		sys_recv = dlsym(RTLD_NEXT, "recv");
	if ((err_str = dlerror()) != NULL)
		load_sym_fail("recv", err_str);

	/* getting "lower/real" recvfrom() symbol */
	if (!sys_recvfrom)
		sys_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
	if ((err_str = dlerror()) != NULL)
		load_sym_fail("recvfrom", err_str);

	if (!sys_recvmsg)
		sys_recvmsg = dlsym(RTLD_NEXT, "recvmsg");
	if ((err_str = dlerror()) != NULL)
		load_sym_fail("recvmsg", err_str);

	/* getting "lower/real select() */
	if (!sys_select)
		sys_select = dlsym(RTLD_NEXT, "select");
	if ((err_str = dlerror()) != NULL)
		load_sym_fail("select", err_str);

	if (!sys_poll)
		sys_poll = dlsym(RTLD_NEXT, "poll");
	if ((err_str = dlerror()) != NULL)
		load_sym_fail("poll", err_str);

	/* getting "lower/real" close() symbol */
	if (!sys_close)
		sys_close = dlsym(RTLD_NEXT, "close");
	if ((err_str = dlerror()) != NULL)
		load_sym_fail("close", err_str);

	/* getting "lower/real" shutdown() symbol */
	if (!sys_shutdown)
		sys_shutdown = dlsym(RTLD_NEXT, "shutdown");
	if ((err_str = dlerror()) != NULL)
		load_sym_fail("shutdown", err_str);

	/* getting "lower/real" fcntl() symbol */
	if (!sys_fcntl)
		sys_fcntl = dlsym(RTLD_NEXT, "fcntl");
	if ((err_str = dlerror()) != NULL)
		load_sym_fail("fcntl", err_str);

}

/*
 * Returns the adapter port number from a connection tid.
 */
static int get_port_from_tid(int fd, int tid, unsigned int *max_cred)
{
	int ret;
	struct wdtoe_get_port_num cmd;
	struct wdtoe_get_port_num_resp resp;

	cmd.tid = tid;

	ret = wdtoe_cmd_get_port_num(fd, &cmd, sizeof(cmd),
					&resp, sizeof(resp));

	if(ret != 0)
		return -1;

	if (max_cred)
		*max_cred = resp.max_cred;

	return resp.port_num;
}

static void parse_config_file(const char *filename)
{
	int ret;
	FILE *fp;

	fp = fopen(filename, "r");
	if (fp != NULL) {
		ret = fscanf(fp, "tx_hold_thres=%d", &tx_hold_thres);
		if (ret) {
			DBG(DBG_INIT, "config file: tx_hold_thres=%d\n",
			    tx_hold_thres);
		} else {
			DBG(DBG_INIT, "config file exists but bad contents\n");
		}
	} else {
		DBG(DBG_INIT, "could not open config file [%s]\n", filename);
		return;
	}
	fclose(fp);
}

/*
 * Returns the local port for a given connection identified by its sockfd.
 */
static int get_lport(int sockfd)
{
	struct sockaddr_in addr;
	int ret;
	int lport;
	socklen_t sin_size;

	sin_size = sizeof(addr);

	ret = getsockname(sockfd, (struct sockaddr *)&addr, &sin_size);

	if (!ret) {
		lport = ntohs(addr.sin_port);
		DBG(DBG_CONN, "sockfd [%d] is bound to local port [%d]\n",
		    sockfd, lport);

		return lport;
	}

	DBG(DBG_CONN, "could not determine local "
	    "port from sockfd [%d]\n", sockfd);

	return -1;
}

/*
 * Processes a data IQE (Ingress Queue Entry).
 *
 * Basically, when the polling thread finds an entry in the Ingress Queue that
 * represents Rx data (CPL_RX_DATA) the following function is being called to
 * copy the data from the hardware RxQ (RxQ := IQ + Free List [FL] + FL bufs)
 * into the Software Free List (per-connection FL) of the corresponding
 * connection.
 *
 * How do we know for which connection is the piece of data we're looking at
 * intended? Well, Every new piece of data is preceded by meta data contained
 * in a CPL_RX_DATA. The CPL_RX_DATA tells us the TID of the connection. Here,
 * in the User Space library, thanks to information we gathered from Kernel at
 * socket() call time, we maintain a table that holds information relative to
 * each connection. When we create a Software Free List for a new connection
 * we store the TID of the connection as well as a pointer to that SW-FL,
 * which allows us to find what demultiplexed queue is associated to a given
 * TID.
 */
static inline int t4_recv_gl(const struct wdtoe_pkt_gl *gl, size_t total_len)
{
	int idx;
	int buf_idx;
	int frags;
	int cur_pidx;
	int sw_fl_buf_len = wdtoe_page_size;
	size_t copied = 0;
	struct sw_t4_raw_fl *sw_fl = NULL;
	const struct cpl_rx_data *rpl = (struct cpl_rx_data *)gl->frags_va[0];
	unsigned int tid = GET_TID(rpl);
#ifndef NDEBUG
	unsigned int opcode = G_CPL_OPCODE(ntohl(OPCODE_TID(rpl)));
#endif
	DBG(DBG_RECV, "element in RxQ with opcode [%#x] "
	    "for tid [%d]\n", opcode, tid);

	idx = get_idx_from_tid(wd_dev->stack_info->conn_info, tid);
	if (idx < 0) {
		DBG(DBG_RECV, "can not find tid [%u] in the "
			"shared conn_info, exit.\n", tid);
		goto err;
	}

	buf_idx = wd_dev->stack_info->conn_info[idx].buf_idx;
	if (buf_idx < 0 || buf_idx >= NWDTOECONN) {
		DBG(DBG_RECV, "buf_idx wrong [%d] for tid [%u]"
			", exit.\n", buf_idx, tid);
		goto err;
	}

	sw_fl = &wd_dev->stack_info->buf.sw_fl[buf_idx];
	if (sw_fl != NULL) {
		/* spin until we have enough space for this gl */
		while ((sw_fl->size - atomic_read(&sw_fl->in_use))
		       <= gl->nfrags) {}

		/* get the cur_pidx and do the copy first */
		cur_pidx = sw_fl->pidx;
		for (frags = 0; frags < gl->nfrags; frags++) {
			copied = min(total_len, sw_fl_buf_len);
			memcpy( (char *)sw_fl->sw_queue[cur_pidx],
				(char *)gl->frags_va[frags],
				copied);
			if (++cur_pidx == sw_fl->size)
				cur_pidx = 0;
			total_len -= copied;
		}
		/* move the pidx after the actual data copy */
		for (frags = 0; frags < gl->nfrags; frags++)
			sw_t4_raw_fl_produce(sw_fl);
		assert(total_len == 0);
		return 0;
	}
err:
	return -1;
}

static inline int wdtoe_refill_fl(struct t4_raw_fl *f, int buf_count)
{
	int i;
	unsigned int cred;

	cred = 0;
	for (i = 0; i < buf_count; i++) {
		/* move the pidx */
		t4_raw_fl_produce(f);
		cred++;
	}

	f->fl_shared_params->pend_cred += cred;
	t4_ring_fl_db(f);
	return 0;
}

static inline unsigned int wdtoe_fl_cap(const struct t4_raw_fl *fl)
{
	return fl->size - 8;
}

static inline int wdtoe_process_responses(struct t4_iq *iq,
					  struct t4_raw_fl *fl)
{
	const __be64 *rsp;
	const __be64 *rsp_end;
	struct t4_iqe *iqe;
	int ret;
	int rsp_type;
	int len_refill_fl;
	int frags;
	u8 opcode;

	ret = t4_next_iqe(iq, &iqe);
	if (ret) {
		return ret;
	}

	rsp = (__be64 *)iqe;

	rsp_type = IQE_IQTYPE(iqe);

	if (rsp_type == X_RSPD_TYPE_FLBUF) {
		struct wdtoe_pkt_gl si;
		u32 len;

		len = IQE_DATADMALEN(iqe);

		/*
		 * XXX Assuming here that each FL buffer is
		 * PAGE_SIZE long. Should be more flexible.
		 *
		 * Determining on how many FL buffers the
		 * received data spans.
		 */
		si.nfrags = DIV_ROUND_UP(len, wdtoe_page_size);
		si.tot_len = len;

		DBG(DBG_RECV, "received new FL item of length [%u], "
		    "made of [%d] frags\n", len, si.nfrags);

		/*
		 * Building gather list
		 */
		for (frags = 0; frags < si.nfrags; frags++) {
			si.frags_va[frags] = (void *)fl->sw_queue[fl->fl_shared_params->cidx];
			t4_raw_fl_consume(fl);
		}

		ret = t4_recv_gl(&si, len);
		if (ret == -1) {
			t4_raw_fl_restore(fl, si.nfrags);
			goto out;
		}

	} else if (rsp_type == X_RSPD_TYPE_CPL) {
		opcode = ((const struct rss_header *)iqe)->opcode;

		DBG(DBG_RECV, "received a CPL msg (%#x)\n", opcode);

		/* determine where the iqe ends */
		rsp_end = (__be64 *)(iqe + 1);

		rsp++;	/* skip RSS header */

		/*
		 * CPL_FW4_MSG is used by the firmware to encapsulate
		 * small CPLs. This has to do with the ULPTx bug.
		 * Wish I had the Bugzilla PR#, though.
		 */
		if (opcode == CPL_FW4_MSG &&
		    ((const struct cpl_fw4_msg *)rsp)->type == FW_TYPE_RSSCPL) {
			/*
			 * Move rsp pointer until we hit the RSS_HDR
			 * of the encapsulated CPL.
			 */
			rsp++;

			/* opcode of encapsulated CPL (read from RSS_HDR) */
			opcode = ((const struct rss_header *)rsp)->opcode;

			DBG(DBG_RECV, "CPL msg (%#x) is encapsulated "
			    "in a CPL_FW4_MSG\n", opcode);
		} else {
			/*
			 * If we are not dealing with an encapsulated
			 * CPL, we have to move the response pointer
			 * back to the beginning of the IQE, as TOM
			 * is expecting all CPLs with their RSS_HDR.
			 */
			rsp--;
		}

		process_cpl(rsp, rsp_end, opcode);
	} else {
		DBG(DBG_RECV, "received unexpected response "
		    "type [%d]\n", rsp_type);
	}

	t4_iq_consume(iq);

	len_refill_fl = wdtoe_fl_cap(fl) - fl->fl_shared_params->in_use;
	if(len_refill_fl >= (fl->size >> 4))
		wdtoe_refill_fl(fl, len_refill_fl);

	return 0;

out:
	return ret;
}

static void wdtoe_pre_fork_hook(void) {
	int i;
	struct wdtoe_listsvr *svr = wd_dev->stack_info->svr_info;

	/* XXX need proper error out */
	if (!svr)
		return;

	for(i = 0; i < NWDTOECONN; i++) {
		if (svr[i].listen_port)
			atomic_incr(&svr[i].ref_cnt);
	}
}

/*
 * Changes the priority of a socket i(identified by @sockfd).
 *
 * So far this is the only way we have found to mark a socket in User Space
 * so that we can figure in Kernel Space that this socket was 'intercepted'
 * by the WD-TOE User Space lib.
 *
 * We need that information in Kernel Space because WD-TOE connections need
 * to receive special treatments in TOM (see t4_tom code.)
 */
static int setsockprio(int sockfd, unsigned int prio)
{
	int ret;
	socklen_t optlen;

	optlen = sizeof(prio);
	ret = setsockopt(sockfd, SOL_SOCKET, SO_PRIORITY, &prio, optlen);

	return ret;
}

static int mark_as_wdtoe(int sockfd)
{
	return setsockprio(sockfd, WDTOE_COOKIE);
}

static int unmark_wdtoe(int sockfd)
{
	return setsockprio(sockfd, 0);
}

/*
 * Alright. What we are doing here is ESSENTIAL. We are calling sys_socket(),
 * of course, because we need to return a sockfd (or an error) to the appli-
 * cation.
 *
 * But wait, there is more. When a process goes through this call for the first
 * time we allocate all the resources needed for acceleration. This is where we
 * ask the Kernel to create a new offload Queue Pair (QP, i.e. TxQ + RxQ), as
 * well as other buffers that will be used to buffer up large Tx payloads. This
 * is also where we perform the mapping of these resources from Kernel memory
 * to User Space so that we (the lib) can access them through the process
 * virtual memory.
 */
int socket(int domain, int type, int protocol)
{
	int sockfd;
	int ret;
	unsigned int cur_idx = 0;
	unsigned int idx_offset = 0;

	if (!sys_socket)
		hook_lower_symbols();

	DBG(DBG_CONN, "domain %d, type %d, protocol %d\n", domain, type,
	    protocol);

	/*
	 * WD-TOE does not support IPv6, yet but since we are given the choice,
	 * we're then forcing IPv4.
	 *
	 * Note that AF_INET6 will therefore be redirected to the lower socket()
	 * symbol.
	 */
	if (domain == AF_UNSPEC) {
		DBG(DBG_CONN, "socket domain is AF_UNSPEC. Forcing AF_INET\n");
		domain = AF_INET;
	}

	if (domain != AF_INET || !(type & SOCK_STREAM)) {
		DBG(DBG_CONN, "socket domain %d / type %d is not supported "
		    "by WD-TOE. Redirecting to lower sys_socket()\n",
		    domain, type);

		return sys_socket(domain, type, protocol);
	}

	/* call "real" socket() and get the sockfd */
	sockfd = sys_socket(domain, type, protocol);

	DBG(DBG_CONN, "sockfd %d\n", sockfd);

	ret = mark_as_wdtoe(sockfd);
	if (ret)
		DBG(DBG_CONN, "could not mark sockfd %d as WD-TOE accelerated\n",
		    sockfd);

	/*
	 * We have to lock most of the socket() callto make sure that the first
	 * thread has time to post the queue creation request.
	 *
	 * Failure to do so will result in nasty things such as kernel panic.
	 * That's explained by the fact that threads coming after ther first one
	 * may try to access a QP that hasn't been created yet.
	 */
	pthread_mutex_lock(&mutex);

	DBG(DBG_CONN, "we have %d active sockets so far\n", connections);

	if (connections)
		goto out_counter;

	global_devfd = open_global_chardev();
	if (global_devfd == -1)
		goto out;

	DBG(DBG_CHAR_DEV, "fd %d for device %s\n", global_devfd,
	    GLOBAL_DEV_NODE);

	ret = create_wd_dev(&wd_dev, global_devfd);
	if (ret == -1)
		goto out2;

	ret = open_wd_dev(wd_dev);
	if (ret == -1)
		goto out_free_wd_dev;

	ret = create_qp_set(wd_dev, tx_hold_thres, &idx_offset);
	if (ret == -1)
		goto out_free_wd_dev;

	/* mmap the stack_info for this stack */
	ret = map_stack_info(wd_dev, &idx_offset);
	if (ret == -1)
		goto out_free_wd_dev;

	/* Here allocate memory for "conn_info_new" */
	conn_info_new = alloc_conn_info(NWDTOECONN);
	if (!conn_info_new)
		goto out_free_wd_dev;

	/* Init private connection info table */
	ret = init_conn_info(conn_info_new, NWDTOECONN);
	if (ret == -1)
		goto out_free_wd_dev;

	/* Init shared connection info table */
	ret = init_conn_info(wd_dev->stack_info->conn_info, NWDTOECONN);
	if (ret == -1)
		goto out_free_private_conn_info;

	priv_svr_info = alloc_listsvr(NWDTOECONN);
	if (!priv_svr_info)
		goto out_free_private_conn_info;

	/* initialize the priv_svr_info table */
	ret = init_listsvr(priv_svr_info,NWDTOECONN);
	if (ret == -1)
		goto out_free_priv_svr_info;

	ret = create_sw_fl_and_sw_txq(wd_dev);
	if (ret == -1)
		goto out_free_priv_svr_info;

	ret = map_sw_txq(wd_dev, &cur_idx);
	if (ret == -1)
		goto out_free_priv_svr_info;

	ret = map_sw_fl(wd_dev, cur_idx);
	if (ret == -1)
		goto out_free_priv_svr_info;

	/* initialize the spinlock associated with the Rx/Tx buf */
	pthread_spin_init(&wd_dev->stack_info->buf.lock,
			  PTHREAD_PROCESS_SHARED);

	/* setup the fork() hooks */
	__register_atfork(wdtoe_pre_fork_hook, NULL, NULL, NULL);

	/* now the IQ, FL and memory mapping is finished, set the flag */
	iq_created = 1;

out_counter:
	/*
	 * Incremeting connections counter atomically
	 */
	(void)__sync_fetch_and_add(&connections, 1);
	DBG(DBG_CONN, "we have %d connections, latest sockfd %d\n",
	    connections, sockfd);

	if (!iq_created) {
		ret = unmark_wdtoe(sockfd);
		if (ret)
			DBG(DBG_CONN, "could not unmark sockfd %d\n", sockfd);
	}

	ret = register_stack(wd_dev);
	if (ret == -1)
		goto out_free_priv_svr_info;

	pthread_mutex_unlock(&mutex);
out:
	return sockfd;

out_free_priv_svr_info:
	free(priv_svr_info);
	priv_svr_info = NULL;

out_free_private_conn_info:
	free(conn_info_new);
	conn_info_new = NULL;

out_free_wd_dev:
	free(wd_dev);
	wd_dev = NULL;
out2:
	ret = unmark_wdtoe(sockfd);
	if (ret)
		DBG(DBG_CONN, "could not unmark sockfd %d\n", sockfd);

	pthread_mutex_unlock(&mutex);

	return sockfd;
}
 
int listen(int sockfd, int backlog)
{
	int ret;
	int sys_ret;
	unsigned listen_port;
	struct wdtoe_reg_listen cmd_reg_listen;
	struct wdtoe_reg_listen_resp resp_reg_listen;

	if (!sys_listen)
		hook_lower_symbols();

	if (!iq_created)
		goto listen_out;

	sys_ret = sys_listen(sockfd, backlog);

	cmd_reg_listen.dev_idx = wd_dev->dev_idx;
	listen_port = get_lport(sockfd);
	cmd_reg_listen.listen_port = listen_port;
	ret = wdtoe_cmd_reg_listen(wd_dev->devfd, 
					&cmd_reg_listen,
					sizeof(cmd_reg_listen),
					&resp_reg_listen,
					sizeof(resp_reg_listen));
	if (ret)
		DBG(DBG_CONN, "wdtoe_cmd_reg_listen() failed\n");

	DBG(DBG_CONN, "registering listening server at sockfd [%d], "
			"port [%u]\n", sockfd, listen_port);
	insert_listen_svr(priv_svr_info, sockfd, listen_port);
	insert_listen_svr(wd_dev->stack_info->svr_info,
						sockfd, listen_port);
	return sys_ret;
listen_out:
	return sys_listen(sockfd, backlog);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int ret;
	int connfd;
	int lport;
	int tid = -1;
	int port_num = -1;
	int idx = 0;
	unsigned int max_cred;

	if (!sys_connect)
		hook_lower_symbols();

	connfd = sys_connect(sockfd, addr, addrlen);
	if (!iq_created)
		goto out;

	DBG(DBG_CONN, "sys_connect() returns [%d] for sockfd [%d]\n",
	    connfd, sockfd);

	if (connfd < 0) {
		DBG(DBG_CONN, "errno [%d]\n", errno);
		goto out;
	}

	lport = get_lport(sockfd);
	if (lport == -1)
		goto out;

	if(conn_info_insert_sockfd_active(wd_dev->stack_info->conn_info, 
					lport, sockfd, &tid, &idx) == -1)
		DBG(DBG_LOOKUP, "could not insert active connection "
		    "sockfd [%d] in conn_info table\n", sockfd);

	/* 
	 * The connection is now established;
	 * now get the port number from
	 * kernel and store the port_num for
	 * this sockfd in the mapping table
	 */
	if (tid >= 0)
		port_num = get_port_from_tid(global_devfd, tid, &max_cred);

	if (port_num < 0) {
		DBG(DBG_LOOKUP, "could not obtain port_num from Kernel\n");
		goto out;
	}

	DBG(DBG_CREDITS, "maximum credits value [%u]\n", max_cred);

	if (conn_info_insert_info(wd_dev->stack_info->conn_info, 
					sockfd, tid, port_num, max_cred))
		DBG(DBG_LOOKUP, "could not insert port_num [%d] for "
		    "sockfd [%d] with credits [%u]\n", 
		     port_num, sockfd, max_cred);

	DBG(DBG_CONN | DBG_CREDITS, "now sockfd [%d] is mapped for "
	    "port_num [%d] with credits [%u]\n", sockfd, port_num, max_cred);

	/* the conn_info table now is updated with one entry, now copy it */
	/* idx is the index in the conn_info */
	ret = conn_info_copy_entry(wd_dev->stack_info->conn_info,
				   conn_info_new, idx);
	if (ret < 0)
		connfd = ret;

out:
	return connfd;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int connfd;
	int tid = -1;
	int port_num = -1;

	if (!sys_accept)
		hook_lower_symbols();

	/* WD-TOE stack is not up, go to the system path */
	if (!iq_created)
		goto out1;
	/*
	 * *addr and *addrlen from application could be NULL
	 */
	struct sockaddr wdtoe_addr;
	socklen_t wdtoe_addrlen = sizeof(wdtoe_addr);

	DBG(DBG_CONN, "entering accept() before polling thread, "
	    "sockfd [%d]\n", sockfd);

	connfd = sys_accept(sockfd, &wdtoe_addr, &wdtoe_addrlen);
	DBG(DBG_CONN, "sys_accept() returns [%d]\n", connfd);

	if (connfd < 0)
		DBG(DBG_CONN, "sys_accept() set errno [%d]\n", errno);

	if (connfd > 0) {
		__u16 pport;
		__u32 pip;
		int idx;
		unsigned int max_cred;

		pport = ntohs(((struct sockaddr_in *) &wdtoe_addr)->sin_port);
		pip = ntohl(((struct sockaddr_in *)
					&wdtoe_addr)->sin_addr.s_addr);

		if (conn_info_insert_sockfd_passive(
				wd_dev->stack_info->conn_info, 
				pip, pport, connfd, &tid, &idx) == -1)
			DBG(DBG_LOOKUP, "could not insert connfd [%d] "
			    "in table for passive connection\n", connfd);

		/* The connection is now established; now get the */
		/* port number from kernel and store the port_num */
		/* for this sockfd in the mapping table */
		if (tid >= 0)
			port_num = get_port_from_tid(global_devfd, 
						     tid, &max_cred);
		if (port_num < 0) {
			DBG(DBG_LOOKUP, "could not get port_num from Kernel\n");
			goto out2;
		}

		DBG(DBG_CREDITS, "maximum credits value [%u]\n", max_cred);

		if (conn_info_insert_info(
				wd_dev->stack_info->conn_info, 
				connfd, tid, port_num, max_cred)) {
			DBG(DBG_LOOKUP, "could not insert port_num [%d] for "
			    "sockfd [%d] with credits [%u]\n", 
			    port_num, connfd, max_cred);
			goto out2;
		}

		DBG(DBG_CONN | DBG_CREDITS, "sockfd [%d] is mapped for "
		    "port_num [%d] with credits [%u]\n",
		    connfd, port_num, max_cred);

		/* the conn_info table now is updated with one entry, */
		/* now copy it. idx is the index in the conn_info */
		DBG(DBG_LOOKUP, "copying from shared conn_info "
		    "to private conn_info, idx [%d]\n", idx);

		conn_info_copy_entry(wd_dev->stack_info->conn_info, 
							conn_info_new, idx);
	}

out2:
	if (addr != NULL)
		*addr = wdtoe_addr;

	if (addrlen != NULL)
		*addrlen = wdtoe_addrlen;

	return connfd;
out1:
	return sys_accept(sockfd, addr, addrlen);
}

/*
 * Tell the Kernel to update the Rx credits for a TID. Here @len is the appli-
 * cation buffer length, and @len_copied is the actual lengh we copied to the
 * application buffer.
 */
static void inline t4_rx_credit_return(unsigned int tid, int len,
				       int len_copied)
{
	int idx;
	int ret;
	struct wdtoe_update_rx_credits cmd;

	ret = conn_info_get_idx_from_tid(
				wd_dev->stack_info->conn_info, 
				tid, &idx);
	if (ret < 0) {
		DBG(DBG_LOOKUP, "could not find index of tid [%d] "
			" in conn_info table, Rx credits not updated\n",
			tid);
		return;
	}
	wd_dev->stack_info->conn_info[idx].copied += len_copied;
	wd_dev->stack_info->conn_info[idx].buf_len += len;
	if (wd_dev->stack_info->conn_info[idx].copied 
					>= WDTOE_RX_CRED_THRES) {
		DBG(DBG_RECV | DBG_CREDITS, "updating Rx credits [%u]\n", 
		    wd_dev->stack_info->conn_info[idx].copied);

		cmd.buf_len = 
			wd_dev->stack_info->conn_info[idx].buf_len;
		cmd.tid = tid;
		cmd.copied = 
			wd_dev->stack_info->conn_info[idx].copied;
		ret = wdtoe_cmd_update_rx_credits(wd_dev->devfd, &cmd, 
					sizeof(cmd), NULL, 0);
		if (!ret) {
			/* reset the buf_len and copied after we tell */
			/* kernel to update Rx credits successfully */
			wd_dev->stack_info->conn_info[idx].buf_len = 0;
			wd_dev->stack_info->conn_info[idx].copied = 0;
		} else {
			/* log the update Rx credits failure event */
			DBG(DBG_CREDITS, "updating Rx credits for "
					"tid [%u]fails\n", tid);
		}

	}
	return;
}

/*
 * This function is in charge of copying data from a Software Free List (SW-FL)
 * into the application user buffer. Reminder: an SW-FL is a demultiplexed
 * receive queue, i.e. it contains Rx data for one and only one connection,
 * identified by its sockfd (and TID).
 *
 * The operation is complex because we need to take care of cases where we have
 * more data available for this connection than we could copy to the user buffer
 * (buffer size too small). We therefore have to do some bookeeping in order to
 * feed the user buffer with the right data. The entire CPL_RX_DATA payload will
 * sit in the SW-FL until all the payload bytes have been copied to the user or
 * the connection is closed/aborted.
 *
 * Basically we are doing what the Kernel has to do for regular connections.
 *
 * Note on the '((noinline))' GCC attribute:
 * It seems like we're hitting a compiler bug here for older versions of GCC.
 * When the O2 optimization flag is set and GCC decides to inline
 * t4_recv_gl_from_sw_fl() GCC is getting scared of a potential uninit'ed
 * variable when there is absolutely no reason to panic.
 *
 * The GCC bug is known. See http://gcc.gnu.org/bugzilla/show_bug.cgi?id=20968
 * for details.
 */
static int __attribute__ ((noinline)) t4_recv_gl_from_sw_fl(struct wdtoe_pkt_gl *gl,
							    void *buf,
							    size_t ubuf_len,
							    size_t *p_len_copied,
							    int flags)
{
	int ret = 0;
	size_t frag;
	size_t start_frag;
	size_t cpl_len;				/* len of CPL_RX_DATA */
	size_t total_len;			/* len of data + CPL in gl */
	size_t fl_buf_len;
	size_t ubuf_remain_len = ubuf_len;
	size_t dst_offset = 0;			/* offset in user buffer */
	size_t cur_offset;			/* offset in this frag */
	size_t copied = 0;			/* len to copy per frag */
	unsigned int tid;			/* for Rx credits return */
	struct cpl_rx_data *rpl;		/* CPL stored in the gl's head */


	/* By design each FL buffer is PAGE_SIZE long */
	fl_buf_len = wdtoe_page_size;

	rpl = (struct cpl_rx_data *)gl->frags_va[0];
	tid = GET_TID(rpl);
	cpl_len = sizeof(*rpl);
	total_len = cpl_len + ntohs(rpl->len);

	/* Total amount of bytes copied in this call */
	*p_len_copied = 0;

	/*
	 *  We are trying to figure out where we had left off copying.
	 *
	 * Explanation:	If data is really large it can span over multiple FL
	 * buffers. However, it still corresponds to a single CPL_RX_DATA.
	 * The first FL buffer for a given payload hosts the CPL_RX_DATA, which
	 * is convenient, as it contains information about the payload itself,
	 * such as its length, for example, in addition to the first part of
	 * the payload.
	 *
	 * Suppose each FL buffer is 4kB long. We have received a 16'000-byte
	 * payload preceded by a CPL_RX_DATA (16 bytes). All of that spans over
	 * 4 FL buffers. So everything is fine, life is sweet and we are just
	 * waiting for the application to come and consume the payload.
	 *
	 * Now the application is posting a receive buffer. But that receive
	 * buffer is smaller than the payload we have. Say it's 2'000-byte
	 * long. That means all we can do is copy as much data as the user
	 * buffer can hold, i.e. 6'000 bytes. Btw, we want to make sure we
	 * don't copy the contents of the CPL_RX_DATA.
	 *
	 * Once we are done copying we store the number of bytes copied + the
	 * length of the CPL_RX_DATA into the "rsvd" field the CPL. In the
	 * present case, we store 2016 in rpl->rsvd.
	 *
	 * When the application posts a receive buffer again, we get here and
	 * check the number of bytes we copied last time. In our example we
	 * will read 2016 from rpl->rsvd, which means that we have to start
	 * copying from byte 2017 of the first FL buffer.
	 *
	 */
	start_frag = (rpl->rsvd + cpl_len) / fl_buf_len;
	DBG(DBG_RECV, "copying from offset %d\n", rpl->rsvd);
	DBG(DBG_RECV, "starting copy at frag %lu\n", start_frag);

	/* Loop over the fragment list */
	for (frag = start_frag; frag < gl->nfrags; frag++) {
		DBG(DBG_RECV, "frag %lu of %u\n", frag, gl->nfrags - 1);

		cur_offset = rpl->rsvd + cpl_len;
		cur_offset = cur_offset - frag * fl_buf_len;

		copied = min(fl_buf_len, total_len - (fl_buf_len * frag))
			     - cur_offset;

		DBG(DBG_RECV, "copy guess: %lu bytes\n", copied);

		/*
		 * if data in this frag is more than available user buf
		 * get ready to return -1 to keep this gl for the next run
		 */
		if (copied > ubuf_remain_len) {
			copied = ubuf_remain_len;
			ret = -1;
		}

		DBG(DBG_RECV, "about to copy %lu bytes to user buffer\n",
		    copied);
		DBG(DBG_RECV, "room left in user buffer: %lu bytes\n",
		    ubuf_remain_len);
		DBG(DBG_RECV, "offset for copy in user buffer: %lu\n",
		    dst_offset);

		memcpy((char *)buf + dst_offset,
		       ((char *)gl->frags_va[frag]) + cur_offset, copied);

		if (!(flags & MSG_PEEK)) {
			dst_offset += copied;
			rpl->rsvd += copied;
			ubuf_remain_len -= copied;
		}

		*p_len_copied += copied;

		DBG(DBG_RECV, "copied %lu, offset for next round is now %d\n",
		    copied, rpl->rsvd);

		if (*p_len_copied == ubuf_remain_len)
			break;
	}

	if (!(flags & MSG_PEEK))
		t4_rx_credit_return(tid, ubuf_len, *p_len_copied);

	DBG(DBG_RECV, "application advertises %lu bytes and we copied %lu "
	    "bytes\n", ubuf_len, *p_len_copied);
	DBG(DBG_RECV, "returning %d\n", ret);

	return ret;
}

/*
 * same error behaviour as recv(), i.e.
 * returns lenght of data copied if any
 * returns -1 and set errno = EAGAIN if no data
 */
static inline int wdtoe_recv_from_sw_fl(struct sw_t4_raw_fl *sw_fl, 
					void *buf, 
					size_t len, 
					size_t *p_len_copied, int flags)
{
	struct wdtoe_pkt_gl si;
	int frags;
	int cpl_len;
	int data_len = 0;
	int ret;
	int cur_cidx;
	const struct cpl_rx_data *cpl;

#ifndef NDEBUG
	if (flags & MSG_PEEK)
		DBG(DBG_RECV, "BEWARE: MSG_PEEK flag is set\n");
#endif
	/* if in_use is non-zero, there is data in sw FL */
	if (atomic_read(&sw_fl->in_use)) {
		/* read one more entry from the sw FL */
		cur_cidx = sw_fl->cidx;
		cpl = (struct cpl_rx_data *)sw_fl->sw_queue[cur_cidx];
		cpl_len = sizeof(*cpl);
		data_len = ntohs(cpl->len);
		si.tot_len = cpl_len + data_len;
		si.nfrags = DIV_ROUND_UP(si.tot_len, wdtoe_page_size);

		/* spin if not all fragments are present yet */
		while (si.nfrags > atomic_read(&sw_fl->in_use)) {}

		/* Build the gather list and log how many frags in it */
		DBG(DBG_RECV, "data spans over %u fragments\n", si.nfrags);
		for (frags = 0; frags < si.nfrags; frags++) {
			si.frags_va[frags] = 
				(void *)sw_fl->sw_queue[cur_cidx];
			if (++cur_cidx == sw_fl->size)
				cur_cidx = 0;
		}
		/*
		 * If ret is 0, this gl is completely consumed by this call
		 * of read()/recv() from the application, and we move the 
		 * cidx of the sw_fl. If ret is -1, we keep this gl for the 
		 * next read()/recv() from application.
		 */
		ret = t4_recv_gl_from_sw_fl(&si, buf, len, p_len_copied,
					    flags);
		if (!ret && !(flags & MSG_PEEK)) {
			for (frags = 0; frags < si.nfrags; frags++)
				sw_t4_raw_fl_consume(sw_fl);
		}
		return 0;
	}
	/* 
	 * As we already see no data coming in this read attempt, set the 
	 * copied length to 0 in case it does not come clean and the 
	 * caller is going to use it.
	 */
	*p_len_copied = 0;
	return -1;
}

/*
 * same error behaviour as recv(), i.e.
 * returns lenght of data copied if any
 * returns -1 and set errno = EAGAIN if no data
 */
static ssize_t wdtoe_recv(struct sw_t4_raw_fl *sw_fl, void *buf, size_t len,
			  const struct iovec *iov, int iovcnt, int flags)
{
	ssize_t ret = 0;
	ssize_t tot_copied = 0;
	size_t len_copied = 0;


	int i;

	if (buf) {	 /* receive into a "*buf" */
		ret = wdtoe_recv_from_sw_fl(sw_fl, buf, len, &len_copied,
					    flags);
		if ((ret != 0) && (len_copied == 0)) {
			errno = EAGAIN;
			return -1;
		}
		return len_copied;
	} else {	 /* receive into a "*iov" */
		for (i = 0; i < iovcnt; i++) {
			ret = wdtoe_recv_from_sw_fl(sw_fl, iov[i].iov_base,
						    iov[i].iov_len,
						    &len_copied, flags);
			tot_copied += len_copied;

			/*
			 * This chunk is full, but there could be more
			 * data, go for the next one in the iovector.
			 */
			if (!ret && len_copied == iov[i].iov_len)
				continue;

			/*
			 * This chunk is not fully filled in this go.
			 * Guess there is no more data in the buffer.
			 */
			if (!ret && len_copied < iov[i].iov_len)
				break;
			/*
			 * No data at all in this go. Time to return.
			 */
			if ((ret < 0) && (len_copied == 0)) {
				if (i == 0) {
					/*
					 * Tell caller there is no
					 * data if this is the first
					 * attempt.
					 */
					errno = EAGAIN;
					tot_copied = -1;
				}
				break;
			}
			/* XXX TODO error if len_copied > iov_len */
		}
		return tot_copied;
	}

	return len_copied;
}

static int check_peer_closed(int sockfd) 
{
	int peer_closed = 0;
	int tid = 0;
	tid = conn_info_get_tid(conn_info_new, sockfd, NULL, NULL);

	if (tid < 0) {
		/* this connection is not in the private conn_info */
		/* we go to the shared conn_info to find peer_closed state */
		/* XXX we may have it wrong if the sockfd is also */
		/* duplicated in the shared conn_info */
		peer_closed = check_sockfd_peer_closed(
			wd_dev->stack_info->conn_info, sockfd);
	} else {
		peer_closed = check_tid_peer_closed(
			wd_dev->stack_info->conn_info, tid);
	}

	return peer_closed;
}

/*
 * only returns length of data copied when there is any
 * otherwise polling IQ forever
 */
static ssize_t wdtoe_wait_for_data(int socket, struct sw_t4_raw_fl *sw_fl, 
				   void *buf, size_t len,
				   const struct iovec *iov,
				   int iovlen, int flags)
{
	ssize_t ret;
	int peer_closed = 0;

	/* spin until we have data available */
	for ( ; ; ) {
		ret = wdtoe_recv(sw_fl, buf, len, iov, iovlen, flags);
		/* check if the sockfd has already been closed */
		peer_closed = check_peer_closed(socket);

		/* stop waiting either when we get something */
		/* or the connection is peer_closed already */
		if (ret != -1 || peer_closed)
			break;
	}

	ret = (peer_closed && ret == -1) ? 0 : ret;

	return ret;
}

static inline size_t __fast_recv(int sockfd,
				 struct sw_t4_raw_fl *sw_fl,
				 void *buf, size_t len,
				 const struct iovec *iov,
				 int iovlen,
				 int flags,
				 struct wdtoe_conn_info *c)
{
	size_t tlen = 0;
	int nonblocking = flags & MSG_DONTWAIT || flags & O_NONBLOCK;

	tlen = wdtoe_recv(sw_fl, buf, len, iov, iovlen, flags);
	/*
	 * wait for data if it's blocking recv()
	 */
	if (tlen == -1 && errno == EAGAIN && !nonblocking) {
		INC_STAT(c, waits);
		tlen = wdtoe_wait_for_data(sockfd, sw_fl, buf, len,
					   iov, iovlen, flags);
	}

	return tlen;
}

/*
 * caller needs to make sure either *buf or *iov is valid, otherwise
 * do not enter this function. In this function, we check either *buf and
 * *iov to decide how we call the next layer.
 */
static ssize_t fast_recv(int sockfd,
			void *buf, size_t len,
			const struct iovec *iov, int iovcnt,
			int flags,
			struct sockaddr *src_addr,
			socklen_t *addrlen)
{
	int tid;
	int idx;
	int pr_idx;
	int buf_idx;
	struct wdtoe_conn_info *c;
	ssize_t ret;
	struct sw_t4_raw_fl *sw_fl = NULL;

	tid = conn_info_get_tid(conn_info_new, sockfd, NULL, &pr_idx);

	if (tid < 0) {
		DBG(DBG_LOOKUP, "could not get tid for socket [%d]\n",
				sockfd);
		ret = FALLBACK_TO_SYSPATH;
		goto out;
	}

	c = &conn_info_new[pr_idx];

	ret = conn_info_get_idx_from_tid(wd_dev->stack_info->conn_info,
					 tid, &idx);

	if (ret < 0) {
		DBG(DBG_LOOKUP, "could not get index of tid [%d] in the "
		    "wd_dev->stack_info->conn_info table\n", tid);
		errno = EBADF;
		ret = -1;
		goto out;
	}

	flags |= wd_dev->stack_info->conn_info[idx].sk_flags;

	buf_idx = c->buf_idx;

	if (buf_idx < 0 || buf_idx >= NWDTOECONN) {
		/* the sockfd belongs to us, but there is an error */
		DBG(DBG_RECV, "cannot find the Rx buffer for sockfd [%d], "
			"exiting.\n", sockfd);
		errno = EFAULT;
		ret = -1;
		goto out;
	}

	sw_fl = &wd_dev->stack_info->buf.sw_fl[buf_idx];
	if (!sw_fl) {
		DBG(DBG_LOOKUP, "could not get SW FL (cache) "
				 "for sockfd [%d]\n", sockfd);
		errno = EBADF;
		ret = -1;
		goto out;
	}

	INC_STAT(c, fast_recvs);

	ret = __fast_recv(sockfd, sw_fl, buf, len, iov, iovcnt, flags, c);

out:
	return ret;
}

ssize_t read(int fd, void *buf, size_t count)
{
	int ret;

	if (!sys_read)
		hook_lower_symbols();

	if (iq_created) {
		if (!buf)
			goto out;
		ret = fast_recv(fd, buf, count, NULL, 0, 0, NULL, 0);

		if (ret == FALLBACK_TO_SYSPATH)
			goto out;

		return ret;
	}

out:
	return sys_read(fd, buf, count);
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
	int ret;

	if (!sys_recv)
		hook_lower_symbols();

	if (iq_created) {
		if (!buf)
			goto out;
		ret = fast_recv(sockfd, buf, len, NULL, 0, flags, NULL, 0);

		if (ret == FALLBACK_TO_SYSPATH)
			goto out;

		return ret;
	}

out:
	return sys_recv(sockfd, buf, len, flags);
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
		 struct sockaddr *src_addr, socklen_t *addrlen)
{
	int ret;

	if (!sys_recvfrom)
		hook_lower_symbols();

	if (iq_created) {
		if (!buf)
			goto out;
		ret = fast_recv(sockfd, buf, len, NULL, 0,
				flags, src_addr, addrlen);

		if (ret == FALLBACK_TO_SYSPATH)
			goto out;

		return ret;
	}

out:
	return sys_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

/* FIXME: readv is non-blocking only */
ssize_t readv(int fd, const struct iovec *iov, int iovcnt)
{
	ssize_t ret;

	if (!sys_readv)
		hook_lower_symbols();

	if (iq_created) {
		if (!iov || iovcnt == 0)
			goto out;
		ret = fast_recv(fd, NULL, 0, iov, iovcnt, 0, NULL, 0);

		if (ret == FALLBACK_TO_SYSPATH)
			goto out;

		return ret;
	}
out:
	return sys_readv(fd, iov, iovcnt);
}

/* FIXME: recvmsg is non-blocking only, flag is not used */
ssize_t recvmsg(int fd, struct msghdr *msg, int flags)
{
	ssize_t ret;

	if (!sys_recvmsg)
		hook_lower_symbols();

	if (iq_created) {
		if (!msg || !msg->msg_iov || msg->msg_iovlen == 0)
			goto out;
		ret = fast_recv(fd, NULL, 0,
				msg->msg_iov, msg->msg_iovlen,
				0, NULL, 0);
		if (ret == FALLBACK_TO_SYSPATH)
			goto out;

		return ret;
	}
out:
	return sys_recvmsg(fd, msg, flags);
}

static void wdtoe_clear_fds(int n, fd_set *fds)
{
	int i;

	for (i = 0; i < n; i++) {
		FD_CLR(i, fds);
	}
}

static inline int wdtoe_tx_flowc_wr_credits( unsigned int txplen_max,
						int *nparamsp,
						int *flowclenp)
{
	int nparams, flowclen16, flowclen;

	nparams = 8;
	if (txplen_max)
		nparams++;
	flowclen = offsetof(struct fw_flowc_wr, mnemval[nparams]);
	flowclen16 = DIV_ROUND_UP(flowclen, 16);
	flowclen = flowclen16 * 16;

	if (nparamsp)
		*nparamsp = nparams;
	if (flowclenp)
		*flowclenp = flowclen;
	return flowclen16;
}

/*
 * We are building the flowc WR to send before the first Tx payload ourselves.
 *
 * It would be much easier to ask TOM to do it for us but that would force us
 * to spend some effort checking whether the WR has been processed by the FW
 * before we can start sending from User Space in our TxQ. In addition to being
 * complex it would have an impact on performance (although limited as it would
 * not apply to all the subsequent send calls.)
 */
static inline int wdtoe_make_tx_flowc_wr(int tid,
					union tx_desc *d,
					int compl,
					int port_num)
{
	struct wdtoe_send_tx_flowc cmd_flowc;
	struct wdtoe_send_tx_flowc_resp resp_flowc;
	struct fw_flowc_wr *flowc = &d->flowc;
	int nparams;
	int vparamidx;
	int flowclen16;
	int flowclen;
	int iq_id = wd_dev->iq_list[port_num]->qid;

	cmd_flowc.tid = tid;
	(void)wdtoe_cmd_send_tx_flowc(wd_dev->devfd, &cmd_flowc,
				      sizeof(cmd_flowc), &resp_flowc,
				      sizeof(resp_flowc));

	DBG(DBG_SEND, "[wdtoe] tid is %d, snd_nxt [%u], rcv_nxt [%u], "
			"advmss [%u], sndbuf [%u], tx_c_chan [%u], "
			"pfvf [%u], iq_id [%d], txplen_max [%u]\n",
			tid, resp_flowc.snd_nxt, resp_flowc.rcv_nxt,
			resp_flowc.advmss, resp_flowc.sndbuf,
			resp_flowc.tx_c_chan, resp_flowc.pfvf,
			iq_id, resp_flowc.txplen_max);

	flowclen16 = wdtoe_tx_flowc_wr_credits(resp_flowc.txplen_max,
						&nparams, &flowclen);
	DBG(DBG_SEND, "FW_TX_FLOWC_WR len16 [%d], nparams [%d]\n",
						flowclen16, nparams);
	/*
	 * Initialize the FlowC Work Request
	 */
	flowc->op_to_nparams = htonl(V_FW_WR_OP(FW_FLOWC_WR) |
				V_FW_WR_COMPL(compl) |
				V_FW_FLOWC_WR_NPARAMS(nparams));
	flowc->flowid_len16 = htonl(V_FW_WR_FLOWID(tid) |
				V_FW_WR_LEN16(flowclen16));
	flowc->mnemval[0].mnemonic = FW_FLOWC_MNEM_PFNVFN;
	flowc->mnemval[0].val = htonl(resp_flowc.pfvf);
	flowc->mnemval[1].mnemonic = FW_FLOWC_MNEM_CH;
	flowc->mnemval[1].val = htonl(resp_flowc.tx_c_chan);
	flowc->mnemval[2].mnemonic = FW_FLOWC_MNEM_PORT;
	flowc->mnemval[2].val = htonl(resp_flowc.tx_c_chan);
	flowc->mnemval[3].mnemonic = FW_FLOWC_MNEM_IQID;
	flowc->mnemval[3].val = htonl(iq_id);
	flowc->mnemval[4].mnemonic = FW_FLOWC_MNEM_SNDNXT;
	flowc->mnemval[4].val = htonl(resp_flowc.snd_nxt);
	flowc->mnemval[5].mnemonic = FW_FLOWC_MNEM_RCVNXT;
	flowc->mnemval[5].val = htonl(resp_flowc.rcv_nxt);
	flowc->mnemval[6].mnemonic = FW_FLOWC_MNEM_SNDBUF;
	flowc->mnemval[6].val = htonl(resp_flowc.sndbuf);
	flowc->mnemval[7].mnemonic = FW_FLOWC_MNEM_MSS;
	flowc->mnemval[7].val = htonl(resp_flowc.advmss);

	vparamidx = 8;	/* Variable parameters index */
	if (resp_flowc.txplen_max) {
		flowc->mnemval[vparamidx].mnemonic =
					FW_FLOWC_MNEM_TXDATAPLEN_MAX;
		flowc->mnemval[vparamidx].val =
					htonl(resp_flowc.txplen_max);
		vparamidx++;
	}

	return flowclen16;
}

static inline int iov_len(const struct iovec *iov, int iovcnt)
{
	int i, len = 0;

	for (i = 0; i < iovcnt; i++) {
		len += iov[i].iov_len;
	}

	return len;
}

/*
 * caller needs to make sure either buf or iov is valid
 */
static inline u32 wdtoe_make_tx_data_wr(int tid, union tx_desc *d,
					const void *buf, size_t len,
					const struct iovec *iov, int iovcnt,
					int flags)
{
	int i, total_len;
	void *dst;
	struct fw_ofld_tx_data_wr *req;
	u32 len16;

	if (buf)
		total_len = len;
	else
		total_len = iov_len(iov, iovcnt);

	len16 = DIV_ROUND_UP(total_len + sizeof(struct fw_ofld_tx_data_wr), 16);

	DBG(DBG_SEND, "FW_OFLD_TX_DATA_WR len16 size [%d]\n", len16);

	req = &d->req;

	/* We do have to zero out the memory we'll use for the WR */
	memset(req, 0, sizeof(*req));

	req->op_to_immdlen = htonl(V_WR_OP(FW_OFLD_TX_DATA_WR) |
				F_FW_WR_COMPL |
				V_FW_WR_IMMDLEN(total_len));
	req->flowid_len16 = htonl(V_FW_WR_FLOWID(tid) |
				V_FW_WR_LEN16(len16));
	req->plen = htonl(len);

	/*
	 * XXX Some of the following params should be
	 *     set according to what the application
	 *     gives us through the send() flags.
	 */
	req->lsodisable_to_flags = htonl(V_TX_ULP_MODE(0) | /* 0: TCP */
				   (flags & MSG_OOB ?
					F_TX_URG :
					V_TX_URG(0)) |
				   F_TX_SHOVE);

	/* Appending data to the FW WR */
	dst = req + 1;
	if (buf) {
		memcpy(dst, buf, len);
	} else {
		for (i = 0; i < iovcnt; i++) {
			memcpy(dst, iov[i].iov_base, iov[i].iov_len);
			dst += iov[i].iov_len;
		}
	}

	return len16;
}

/*
 * XXX Right now we are just checking there is something in the Software Free
 * List (demultiplexed queue). We are not 'polling'. The function name is
 * either misleading or the function behaviour is inapropriate.
 */
static inline int wdtoe_fast_select_poll(struct sw_t4_raw_fl *sw_fl)
{

	/* if in_use is non-zero, we think there is data in sw FL */
	if(atomic_read(&sw_fl->in_use)) {
		return 0;
	}

	return -1;
}

/* 
 * poll the IQ for spin times maximum
 * sets the bit in readfds and returns 1 if anything found
 * returns 0 if nothing found
 */
static int wdtoe_fast_select(int nfds, fd_set *readfds, fd_set *writefds,
			     fd_set *exceptfds, int spin)
{
	int i;
	int ret;
	int idx, buf_idx;
	struct sw_t4_raw_fl *sw_fl = NULL;

	/* we suppose to pass a positive spin value here */
	assert(spin);

	do {
		for (i = 4; i < nfds; i++) {
			sw_fl = NULL;
			/* get sw_fl */
			idx = get_idx_from_sockfd(conn_info_new, i);
			if (idx < 0)
				continue;

			buf_idx = conn_info_new[idx].buf_idx;
			if (buf_idx < 0 || buf_idx >= NWDTOECONN)
				continue;

			sw_fl = &wd_dev->stack_info->buf.sw_fl[buf_idx];
			if (sw_fl == NULL) {
				/* if there is no sw fl assigned */
				/* for this sockfd */
				continue;
			} else {
				/* look at sw_fl to see data */
				ret = wdtoe_fast_select_poll(sw_fl);
				if (ret == 0) {
					goto out;
				} else {
					/* we get nothing in the sw FL */
					/* we keep going then */
					continue;
				}
			}
		}
	} while (--spin);

out:
	if(i != nfds) {
		DBG(DBG_SELECT, "connection with sockfd [%d] ready\n", i);
		wdtoe_clear_fds(nfds, readfds);
		FD_SET(i, readfds);
	}
	return i != nfds;
}

/*
 * returning 0 means we get nothing after the
 * time-out
 */
int select(int nfds, fd_set *readfds, fd_set *writefds, 
		fd_set *exceptfds, struct timeval *timeout)
{
	fd_set rfds, wfds, efds;
	struct timeval nonblock_tv;
	int ret = 0;

	if (!sys_select)
		hook_lower_symbols();

	if (!iq_created)
		goto sys_select_out;

	nonblock_tv.tv_sec = 0;
	nonblock_tv.tv_usec = 0;

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&efds);

	/* Back up the fd_sets */
	if (readfds)
		rfds = *readfds;

	if (writefds)
		wfds = *writefds;

	if (exceptfds)
		efds = *exceptfds;

	if (timeout) {
		DBG(DBG_SELECT, "timeout (%lu sec, %lu usec)\n",
		    timeout->tv_sec, timeout->tv_usec);
	} else {
		DBG(DBG_SELECT, "no timeout set, i.e. willing to block forever\n");
	}

	DBG(DBG_SELECT, "calling fast_select()\n");

	do {
		/*
		 * XXX Need to check the tcp_state of the read sockfd. if the
		 * connection is not TCP_ESTABLISHED any more, we should report
		 * that nothing was found.
		 */
		if (readfds) {
			ret = wdtoe_fast_select(nfds, readfds, writefds,
						exceptfds,
						timeout && timeout->tv_sec == 0
						&& timeout->tv_usec == 0 ? 1 :
						poll_spin_count);

			if (ret) {
				DBG(DBG_SELECT, "fast_select() returning [%d]\n",
				    ret);
				poll_spin_count = min(poll_spin_count << 1,
						      max_poll_spin_count);
				return ret;
			}
		}

		poll_spin_count = max(poll_spin_count >> 1, 1);

		/*
		 * Call sys_select() if nothing was found through fast_select().
		 */
		if (!timeout) {
			ret = sys_select(nfds, readfds, writefds, exceptfds,
					 &nonblock_tv);

			if (ret) {
				goto out;
			}

			/*
			 * Look again if the non-blocking sys_select() found
			 * nothing.
			 */
			if (readfds)
				*readfds = rfds;

			if (writefds)
				*writefds = wfds;

			if (exceptfds)
				*exceptfds = efds;
		} else {
			goto sys_select_out;
		}
	} while (!ret);

sys_select_out:
	ret = sys_select(nfds, readfds, writefds, exceptfds, timeout);

out:
	DBG(DBG_SELECT, "sys_select() returning [%d]\n", ret);

	return ret;
}

/*
 * return 0 if find something, and return -1 if error
 */
static inline int __poll(int fd)
{
	int idx, buf_idx;
	struct sw_t4_raw_fl *sw_fl = NULL;

	idx = get_idx_from_sockfd(conn_info_new, fd);
	if (idx < 0)
		return -1;
	buf_idx = conn_info_new[idx].buf_idx;
	if (buf_idx < 0 || buf_idx >= NWDTOECONN)
		return -1;
	sw_fl = &wd_dev->stack_info->buf.sw_fl[buf_idx];
	if (sw_fl == NULL) {
		return -1;
	} else {
		return wdtoe_fast_select_poll(sw_fl);
	}
}

static inline int fast_poll(struct pollfd *fds, nfds_t nfds, int spin)
{
	int i;
	int ret;

	assert(spin);

	do {
		for (i = 0; i < nfds; i++) {
			/* Zero out the returned events */
			fds[i].revents = 0;

			/* Skip stin, stdout, stderr */
			if (fds[i].fd <= 2)
				continue;

			/* If this entry is test for read */
			if (fds[i].events & POLLIN) {
				ret = __poll(fds[i].fd);

				if (!ret) {
					DBG(DBG_SELECT, "%s: found data, "
					    "fds[%d] [%d]\n", __func__, i,
					    fds[i].fd);

					/* Flag sockfd as ready */
					fds[i].revents |= POLLIN;

					return 0;
				}
			}
		}
	} while (--spin);

	return -1;
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	int ret;
	int spin;
	int count = 0;
	int nonblock = 0;

	if (!sys_poll)
		hook_lower_symbols();

	if (!iq_created)
		goto out;

	/* XXX we should adjust the spin count based on data we have seen*/
	spin = !timeout ? 1 : max_poll_spin_count;

	do {
		/*
		 * XXX Currently, fast_poll() returns 0 when it finds something
		 * in the WD queues. We should probably make its return value
		 * similar to the system  poll function, i.e. returns > 0 if
		 * anything was found, 0 if nothing was found, and < 0 if an
		 * error occurred.
		 */
		ret = fast_poll(fds, nfds, spin);

		if (!ret) {
			count++;
			DBG(DBG_SELECT, "fast_poll() says %d sockets are "
			    "ready\n", count);

			return count;
		}

		if (timeout == -1) {
			ret = sys_poll(fds, nfds, nonblock);

			/*
			 * We either have found something or have an error
			 * retunred from the system poll() function.
			 */
			if (ret) {
				DBG(DBG_SELECT, "sys_poll() returns [%d]\n",
				    ret);

				return ret;
			}
		} else {
			/*
			 * No need to continue the loop if either:
			 *	timeout = 0 -> nonblocking mode, or
			 *	timeout > 0 -> block for timeout milliseconds.
			 */
			goto out;
		}
	} while(!ret);

out:
	ret = sys_poll(fds, nfds, timeout);
	DBG(DBG_SELECT, "sys_poll() returns [%d]\n", ret);

	return ret;
}

static void copy_wr_to_txq(struct t4_txq *t, struct t4_desc *d, int len)
{
	u64 *src, *dst;
	int t5;
	size_t desc_len = sizeof(*d);

	/*
	 * Rounding up total length (payload size + FW WR size)
	 * as we'll copy the WR to the TxQ in chunks of 8 bytes.
	 */
	size_t total_len = ROUND_UP(len, 8);
	int ndesc = DIV_ROUND_UP(total_len, desc_len);

	src = (u64 *)d;
	dst = (u64 *)((u8 *)t->desc + t->txq_params->pidx * desc_len);

	/*
	 * Actual FW WR + data copy to TxQ
	 *
	 * We're copying data in 8-byte chunks, meaning that in the
	 * worst case we will spend time copying 7 bytes for nothing.
	 * The impact on latency should not be noticeable, though.
	 *
	 * Note that the 7-for-nothing bytes may be garbage data,
	 * but we don't really care, as FW will only pass the payload
	 * to the chip.
	 */
	while (total_len) {
		*dst++ = *src++;
		if (dst == (u64 *)&t->desc[t->size])
			dst = (u64 *)t->desc;
		total_len -= 8;
	}

	/* Updating TxQ PIDX */
	t4_txq_produce(t, ndesc);
	/* Ring TxQ DB */
	t5 = (wd_dev->hca_type == CHELSIO_T5) ? 1 : 0;
	t4_ring_txq_db(t, ndesc, t5);
}

/*
 * Builds a scatter/gather list for Tx data when the payload is too big to be
 * inlined in the Work Request directly.
 */
static int write_sgl(struct ulptx_sgl *sgl, u32 *immdlen, void *end,
		     struct fast_send_wr *wr, size_t n_bufs, u32 *plen)
{
	struct ulptx_sge_pair *sp = (struct ulptx_sge_pair *)(sgl + 1);
	int pidx = wr->s_idx;
	int count = n_bufs;
	int sp_idx = 0;
	u32 copied = 0;

	*immdlen = 0;

	if ((unsigned long)(sgl + 1) > (unsigned long)end)
		return ENOSPC;

	copied = wr->sw_txq->queue[pidx].copied;
	assert(copied > 0);
	*plen += copied;
	sgl->len0 = htonl(copied);
	sgl->addr0 = cpu_to_be64(wr->sw_txq->queue[pidx].dma_addr);
	*immdlen += sizeof *sgl;
	n_bufs--;

	while (n_bufs) {
		if ((unsigned long)(sp + 1) > (unsigned long)end)
			return ENOSPC;
		/* get the next pidx of the sw txq */
		pidx = sw_txq_next_pidx(wr->sw_txq, pidx);
		copied = wr->sw_txq->queue[pidx].copied;
		assert(copied > 0);
		*plen += copied;
		sp->len[sp_idx] = htonl(copied);
		sp->addr[sp_idx] = cpu_to_be64(wr->sw_txq->queue[pidx].dma_addr);
		if (++sp_idx == 2) {
			sp_idx = 0;
			*immdlen += sizeof *sp;
			sp++;
		}
		n_bufs--;
	}
	if (sp_idx == 1) {
		sp->len[1] = 0;
		*immdlen += sizeof *sp - sizeof sp->addr[1];
	} else if ((unsigned long) sp & 8)
		*(u64 *)sp = 0;

	sgl->cmd_nsge = htonl(V_ULPTX_CMD(ULP_TX_SC_DSGL) |
			      V_ULPTX_NSGE(count));
	return 0;
}

static inline ssize_t build_tx_pkt(int tid, union tx_desc *d, int flags,
				   void *end, struct fast_send_wr *wr,
				   size_t n_bufs)
{
	int ret;
	struct fw_ofld_tx_data_wr *req;
	u32 immdlen;
	u32 len16;
	u32 plen = 0;

	req = &d->req;

	memset(req, 0, sizeof(*req));

	ret = write_sgl((struct ulptx_sgl *)(req + 1), &immdlen, end,
			wr, n_bufs, &plen);
	/*
	 * If plen <= 0 the DMA operation will fail/hang forever.
	 * We don't want that, do we?
	 */
	assert(plen > 0);

	if (ret) {
		errno = ret;
		DBG(DBG_SEND, "%s\n", strerror(errno));
		return -1;
	}

	len16 = DIV_ROUND_UP(immdlen + sizeof(*req), 16);

	req->op_to_immdlen = htonl(V_WR_OP(FW_OFLD_TX_DATA_WR) |
				F_FW_WR_COMPL |
				V_FW_WR_IMMDLEN(0));
	req->flowid_len16 = htonl(V_FW_WR_FLOWID(tid) |
				V_FW_WR_LEN16(len16));
	req->plen = htonl(plen);

	/*
	 * XXX Some of the following params should be
	 *     set according to what the application
	 *     gives us through the send() flags.
	 */
	req->lsodisable_to_flags = htonl(V_TX_ULP_MODE(0) | // 0: TCP
				   (flags & MSG_OOB ?
					F_TX_URG :
					V_TX_URG(0)) |
				   F_TX_SHOVE);
	return len16;
}

static inline size_t buf_count(union tx_desc *desc, void **desc_end)
{
	size_t buf_count;
	size_t desc_size;
	size_t sge_pairs;
	size_t left_for_sge_pairs;

	if (wd_dev->hca_type == CHELSIO_T5)
		*desc_end = &desc->desc[1];	/* 64 bytes */
	else
		*desc_end = desc + 1;		/* 256 bytes */

	desc_size = (__u64)*desc_end - (__u64)desc;
	DBG(DBG_SEND, "desc_size %ld\n", desc_size);

	left_for_sge_pairs = desc_size - sizeof(desc->req)
			     - sizeof(struct ulptx_sgl);
	sge_pairs = left_for_sge_pairs / sizeof(struct ulptx_sge_pair);
	buf_count = sge_pairs * 2 + 1;

	return buf_count;
}

static inline int fast_writev(int tid, int flags, int port_num, int idx,
			      struct fast_send_wr *wr)
{
	size_t n_bufs;
	size_t max_n_bufs;
	union tx_desc desc;
	unsigned int credits_needed;
	void *desc_end = NULL;

	while (wr->count) {
		/* Max number of buffers that will fit in a tx_desc */
		max_n_bufs = buf_count(&desc, &desc_end);
		n_bufs = min(wr->count, max_n_bufs);

		credits_needed = build_tx_pkt(tid, (void *)&desc, flags,
					      desc_end, wr, n_bufs);
		if (credits_needed < 0)
			return -1;

		/* spin wait if we do not have enough credits */
		while ((atomic_read(&wd_dev->stack_info->
			conn_info[idx].cur_credits)) < credits_needed) {}

		atomic_sub(credits_needed,
			&wd_dev->stack_info->conn_info[idx].cur_credits);

		assert(atomic_read(&wd_dev->stack_info->conn_info[idx].cur_credits) >= 0);

		DBG(DBG_CREDITS, "consuming Tx credits [%u], cur_credits [%d]\n",
			credits_needed,
			atomic_read(&wd_dev->stack_info->conn_info[idx].cur_credits));

		wr->count -= n_bufs;
		wr->credqe.n_bufs = n_bufs;
		wr->credqe.cred = credits_needed;
		wr->s_idx = (wr->s_idx + n_bufs) % wr->sw_txq->size;
		credit_enqueue(idx, wr->credqe);

		/*
		 * - Copy FW WR + payload to the right TxQ
		 * - Update PIDX
		 * - Ring Tx DB
		 */
		copy_wr_to_txq(wd_dev->txq_list[port_num], (void *)&desc,
			       16 * credits_needed);

	}
	return 0;
}

static inline int fast_send_tx_flowc(int tid, int port_num, int idx)
{
	union tx_desc desc;
	u32 credits_needed;

	/* zero out the descriptor entry */
	memset(&desc, 0, sizeof(desc));

	/* build the flowc wr */
	credits_needed = (u32) wdtoe_make_tx_flowc_wr(tid,
						(void *)&desc,
						0, port_num);
	/* spin wait if we do not have enough credits */
	while ((atomic_read(&wd_dev->stack_info->
			conn_info[idx].cur_credits)) < credits_needed) {

	}
	atomic_sub(credits_needed,
			&wd_dev->stack_info->conn_info[idx].cur_credits);
	DBG(DBG_CREDITS, "consuming Tx credits [%u], cur_credits [%d]\n",
				credits_needed, 
				atomic_read(&wd_dev->stack_info->
				conn_info[idx].cur_credits));
	copy_wr_to_txq(wd_dev->txq_list[port_num],
			(void *)&desc,
			16 * credits_needed);
	return (int) credits_needed;
}

static inline ssize_t send_inline_iov(int tid,
				const void *buf, int len,
				const struct iovec *iov, int iovcnt,
				int flags, int port_num, int idx,
				struct fast_send_wr *wr)
{
	union tx_desc desc;
	u32 credits_needed;
	ssize_t data_len = buf ? len : iov_len(iov, iovcnt);

	/* Building the FW WR and appending payload */
	credits_needed = wdtoe_make_tx_data_wr(tid,
				(void *)&desc,
				buf, len,
				iov, iovcnt,
				flags);
	/* spin wait if we do not have enough credits */
	while ((atomic_read(&wd_dev->stack_info->
		conn_info[idx].cur_credits)) < credits_needed)
	{}
	atomic_sub(credits_needed,
		&wd_dev->stack_info->conn_info[idx].cur_credits);
	DBG(DBG_CREDITS, "consuming Tx credits [%u], cur_credits [%d]\n",
				credits_needed,
				atomic_read(&wd_dev->stack_info->
					conn_info[idx].cur_credits));
	wr->credqe.cred = credits_needed;
	credit_enqueue(idx, wr->credqe);
	/*
	 * - Copy FW WR + payload to the right TxQ
	 * - Update PIDX
	 * - Ring Tx DB
	 */
	copy_wr_to_txq(wd_dev->txq_list[port_num], (void *)&desc,
				data_len + sizeof(struct fw_ofld_tx_data_wr));
	return data_len;
}

static inline size_t buffer_iov(const struct iovec *iov, int iovcnt,
				struct fast_send_wr *wr)
{
	int i;
	size_t data_len;
	void *dst = NULL;
	const void *src = NULL;
	int buf_left = wdtoe_page_size;
	size_t this_len = 0;
	size_t copied = 0;
	size_t total_copied = 0;

	DBG(DBG_SEND, "attempting to buffer %d iovs\n", iovcnt);

	dst = next_buffer(wr->sw_txq);

	for (i = 0; i < iovcnt; i++) {
		src = iov[i].iov_base;
		data_len = iov[i].iov_len;

		while (data_len) {
			if (!buf_left) {
				total_copied += copied;
				finish_buffer(wr->sw_txq, copied);
				dst = next_buffer(wr->sw_txq);
				buf_left = wdtoe_page_size;
				copied = 0;
			} else {
				dst += this_len;
			}

			this_len = min(data_len, buf_left);
			memcpy(dst, src, this_len);
			data_len -= this_len;
			buf_left -= this_len;
			copied += this_len;
			src += this_len;
		}
	}

	total_copied += copied;
	finish_buffer(wr->sw_txq, copied);

	return total_copied;
}

static inline size_t buffer_plain(const void *usr_buf, size_t len,
				  struct fast_send_wr *wr)
{
	void *dst = NULL;
	const void *src = NULL;
	size_t data_len = len;
	size_t buf_len = wdtoe_page_size;
	size_t this_len = 0;

	DBG(DBG_SEND, "attempting to buffer %ld bytes\n", len);

	src = usr_buf;

	while (data_len) {
		dst = next_buffer(wr->sw_txq);
		src += this_len;
		this_len = min(data_len, buf_len);
		memcpy(dst, src, this_len);
		finish_buffer(wr->sw_txq, this_len);
		data_len -= this_len;
	}

	return len;
}

/*
 * copy data into the wr's sw_txq, return the copied len,
 * or return -1 on error.
 */
static inline size_t buffer_data(const void *buf, int len,
				 const struct iovec *iov,
				 int iovcnt,
				 struct fast_send_wr *wr)
{
	int n_bufs;
	int total_len;
	size_t total_copied = 0;

	total_len = buf ? len : iov_len(iov, iovcnt);
	n_bufs = DIV_ROUND_UP(total_len, wdtoe_page_size);
	/* put the of buffers into credit queue entry */
	wr->credqe.n_bufs = n_bufs;
	wr->count = n_bufs;
	wr->s_idx = wr->sw_txq->pidx;

	DBG(DBG_SEND, "this Tx requires n_bufs [%d], "
			"total_len [%d]\n", n_bufs, total_len);

	/* spin wait for Tx buffers */
	while (NTXBUF - atomic_read(&wr->sw_txq->in_use) <= n_bufs)
	{}

	total_copied = buf ? buffer_plain(buf, len, wr)
			   : buffer_iov(iov, iovcnt, wr);

	return total_copied;
}

/*
 * len: length of the payload to be copied to the Tx queue
 * type: adapter type (model)
 */
static inline int is_inline(size_t len, enum wdtoe_hca_type type) {
	if (type == CHELSIO_T5)
		return len <= MAX_INLINE_T5;

	return len < MAX_INLINE;
}

/*
 * flags: 0 - blocking
 * wd_flags: not using actually
 */
static inline ssize_t __fast_send(int tid, const void *buf,
				  size_t len,
				  const struct iovec *iov,
				  int iovcnt, int flags,
				  int port_num, int idx)
{
	int err;
	struct sw_t4_txq *sw_txq;
	int buf_idx;
	int data_len;
	struct fast_send_wr wr;
	ssize_t ret = 0;

	memset(&wr, 0, sizeof(wr));

	/* XXX caller needs to look after error cases */
	/* XXX maybe this error check should happen in caller, and */
	/* XXX we only get sw_txq here? */
	if (idx < 0) {
		DBG(DBG_SEND, "wrong idx [%d], can not get sw_txq.\n",
				idx);
		return -1;
	}
	buf_idx = wd_dev->stack_info->conn_info[idx].buf_idx;
	if (buf_idx < 0 || buf_idx >= NWDTOECONN) {
		DBG(DBG_SEND, "get wrong buf_idx [%d] from idx [%d], "
				"can not continue.\n", buf_idx, idx);
		return -1;
	}
	sw_txq = &wd_dev->stack_info->buf.sw_txq[buf_idx];
	if (!sw_txq) {
		DBG(DBG_SEND, "get NULL sw_fl from buf_idx [%d], "
			"idx [%d], can not continue.\n", buf_idx, idx);
		return -1;
	}

	flags |= wd_dev->stack_info->conn_info[idx].sk_flags;

	data_len = buf ? len : iov_len(iov, iovcnt);

	if (is_inline(data_len, wd_dev->hca_type)) {
		/* no Tx buf associated if sent inline */
		wr.credqe.n_bufs = 0;
		ret = send_inline_iov(tid, buf, len, iov, iovcnt,
				      flags, port_num, idx, &wr);
	} else {
		wr.sw_txq = sw_txq;
		/* after the next line, the data's info is in wr */
		ret = buffer_data(buf, len, iov, iovcnt, &wr);

		/* build WR and push data out */
		err = fast_writev(tid, flags, port_num, idx, &wr);
		if (err) {
			DBG(DBG_SEND, "failed to process sgl data\n");
			errno = EIO;
			ret = -1;
		}
	}

	return ret;
}

/*
 * caller needs to make sure either *buf or *iov is valid, otherwise
 * do not enter this function. In this function, we check either *buf and
 * *iov to decide how we call the next layer.
 */
static ssize_t fast_send(int sockfd,
			const void *buf, size_t len,
			const struct iovec *iov, int iovcnt,
			int flags,
			const struct sockaddr *dest_addr,
			socklen_t addrlen)
{
	int tid;
	int idx;
	int pr_idx;
	int port_num;
	struct wdtoe_conn_info *c = NULL;
	int *wd_flags = NULL;
	ssize_t ret = 0;

	DBG(DBG_SEND, "send posted with %ld byte(s) of data\n", len);

	tid = conn_info_get_tid(conn_info_new, sockfd, &port_num, &pr_idx);

	if (tid < 0) {
		DBG(DBG_LOOKUP, "could not get tid for socket [%d]\n",
				sockfd);
		ret = FALLBACK_TO_SYSPATH;
		goto out;
	}

	c = &conn_info_new[pr_idx];
	if (!c) {
		DBG(DBG_LOOKUP, "conn_info_new is NULL\n");
		errno = EFAULT;
		ret = -1;
		goto out;
	}

	ret = conn_info_get_idx_from_tid(wd_dev->stack_info->conn_info,
					 tid, &idx);

	if (ret < 0) {
		DBG(DBG_LOOKUP, "could not get index of tid [%d] in the "
		    "wd_dev->stack_info->conn_info table\n", tid);
		errno = EBADF;
		ret = -1;
		goto out;
	}

	wd_flags = &wd_dev->stack_info->conn_info[idx].wd_flags;
	if (!wd_flags) {
		DBG(DBG_LOOKUP, "wd_flags is NULL\n");
		errno = EFAULT;
		ret = -1;
		goto out;
	}

	DBG(DBG_SEND, "initial flags [%#x]\n", *wd_flags);

	/*
	 * If we're about to send the first packet for this
	 * connection we'll send it through the slow path.
	 * This way TOM will send the FW_FLOWC_WR for us.
	 */
	if (!G_TX_DATA_SENT(*wd_flags)) {
		struct sw_cred_q_entry cdqe;

		cdqe.cred = fast_send_tx_flowc(tid, port_num, idx);
		*wd_flags |= F_TX_DATA_SENT;
		DBG(DBG_SEND, "just set TX_DATA_SENT flag [%#x]\n",
		    *wd_flags);
		/*
		 * Also consume credit for this FLOWC, n_bufs = 0
		 * means this credit entry is associated with 0 of
		 * Tx buffer entry.
		 */
		cdqe.n_bufs = 0;
		credit_enqueue(idx, cdqe);
	}

	ret = __fast_send(tid, buf, len, iov, iovcnt, flags,
			  port_num, idx);

	INC_STAT(c, fast_sends);
out:
	return ret;
}

ssize_t write(int fd, const void *buf, size_t len)
{
	int ret;

	if (!sys_write)
		hook_lower_symbols();

	if (iq_created) {
		if (!buf)
			goto out;
		ret = fast_send(fd, buf, len, NULL, 0, 0, NULL, 0);

		if (ret == FALLBACK_TO_SYSPATH)
			goto out;

		return ret;
	}

out:
	return sys_write(fd, buf, len);
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
	int ret;

	if (!sys_writev)
		hook_lower_symbols();

	if (iq_created) {
		if (!iov)
			goto out;
		ret = fast_send(fd, NULL, 0, iov, iovcnt, 0, NULL, 0);

		if (ret == FALLBACK_TO_SYSPATH)
			goto out;

		return ret;
	}
out:
	return sys_writev(fd, iov, iovcnt);
}

/*
 * FIXME we're doing blocking sendmsg only. And we need to have a unified way
 * to configure blocking or nonblocking send calls.
 */
ssize_t sendmsg(int fd, const struct msghdr *msg, int flags)
{
	int ret;

	if (!sys_sendmsg)
		hook_lower_symbols();

	if (iq_created) {
		if (!msg->msg_iov)
			goto out;
		ret = fast_send(fd, NULL, 0,
				msg->msg_iov,
				msg->msg_iovlen,
				0, NULL, 0);
		if (ret == FALLBACK_TO_SYSPATH)
			goto out;

		return ret;
	}
out:
	return sys_sendmsg(fd, msg, flags);
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
	int ret;

	if (!sys_send)
		hook_lower_symbols();

	if (iq_created) {
		if (!buf)
			goto out;
		ret = fast_send(sockfd, buf, len, NULL, 0, flags, NULL, 0);

		if (ret == FALLBACK_TO_SYSPATH)
			goto out;

		return ret;
	}

out:
	return sys_send(sockfd, buf, len, flags);
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
	       const struct sockaddr *dest_addr, socklen_t addrlen)
{
	int ret;

	if (!sys_sendto)
		hook_lower_symbols();

	if (iq_created) {
		if (!buf)
			goto out;
		ret = fast_send(sockfd, buf, len, NULL, 0, flags,
						dest_addr, addrlen);

		if (ret == FALLBACK_TO_SYSPATH)
			goto out;

		return ret;
	}

out:
	return sys_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

int close(int sockfd)
{
	int ret;
	__u16 listen_port = 0;

	if (!sys_close)
		hook_lower_symbols();

	/* only remove the sockfd entry if WD-TOE stack is up */
	if (iq_created) {

		DBG(DBG_CONN, "in close(), socket [%d]\n", sockfd);
		/* remove the entry */
		ret = conn_info_remove_sockfd_entry(conn_info_new, sockfd);
		if (ret == -1) {
			/*
			 * sockfd not found in conn_info, there is a 
			 * chance that this is a listening sockfd,
			 * so try to find it in the listen server tbl
			 */
			DBG(DBG_CONN, "in close(), socket [%d], not a data "
					"socket, trying listening sockets\n",
					sockfd);
			ret = remove_listen_svr(priv_svr_info,
						sockfd, &listen_port);
			DBG(DBG_CONN, "ret [%d], listen_port [%u]\n",
					ret, listen_port);
			/*
			 * Only decrement the ref count when the last call
			 * succeeded and we have a valid listening port.
			 */
			if (!ret && listen_port) {
				/*
				 * use the listen_port to lookup in the
				 * shared listening table and decrement
				 * the reference count.
				 */
				DBG(DBG_CONN, "decr ref_cnt, "
					"listen_port [%u]\n",
					listen_port);
				ret = decre_listen_svr(
					wd_dev->stack_info->svr_info,
					sockfd, listen_port);
				if (!ret) {
					struct wdtoe_remove_listen cmd;
					struct wdtoe_remove_listen_resp resp;
					/*
					 * if the ref cnt reaches 0, issue 
					 * a command to the kernel to 
					 * remove this listening server
					 */
					cmd.listen_port = listen_port;
					ret = wdtoe_cmd_remove_listen(
							wd_dev->devfd,
							&cmd, sizeof(cmd),
							&resp, sizeof(resp));
					if (ret)
						DBG(DBG_CONN, "wdtoe_cmd_"
						"remove_listen() fails\n");
				}
			}
		}
	}

	ret = sys_close(sockfd);

	DBG(DBG_CONN, "sys_close() returns [%d] for sockfd [%d]\n",
	    ret, sockfd);

	if (ret == -1)
		DBG(DBG_CONN, "sys_close() errno [%d]\n", errno);

	return ret;
}

int shutdown(int sockfd, int how)
{
	int ret;

	if (!sys_shutdown)
		hook_lower_symbols();

	/* same whether or not WD-TOE stack is up */
	ret = sys_shutdown(sockfd, how);

	DBG(DBG_CONN, "sys_shutdown() returns [%d] for sockfd [%d]\n",
	    ret, sockfd);

	if (ret == -1)
		DBG(DBG_CONN, "sys_shutdown() errno [%d]\n", errno);

	return ret;
}

/*
 * This function is invoked by the polling thread as soon as it is started,
 * which is when the library gets loaded into the application memory.
 *
 * The first socket() call performed by the application allocates all the
 * resources needed for WD-TOE acceleration. As soon as the the resource
 * allocation completes 'iq_created' is set to a non-zero value, allowing the
 * polling thread to poll the IQs (on per adapter-port) for data and CPLs.
 */
static void *global_thread_func(void *arg)
{
	int i;

	while (!iq_created)
		continue;

	do {
		for (i = 0; i < wd_dev->nports; i++) {
			wdtoe_process_responses(wd_dev->iq_list[i],
						wd_dev->fl_list[i]);
		}
	} while (1);

	/*NOTREACHED*/
	return NULL;
}

int fcntl(int fd, int cmd, ... /* arg */ )
{
	va_list argp, largp;
	int ret, idx, tid;
	long flag;

	if (!sys_fcntl)
		hook_lower_symbols();

	va_start(argp, cmd);
	if (!iq_created)
		goto out;
	if (fd < 3)	/* ignore stdout and stderr */
		goto out;
	tid = conn_info_get_tid(conn_info_new, fd, NULL, NULL);
	if (tid < 0)
		goto out;	/* fd does not belong to wdtoe */

	ret = conn_info_get_idx_from_tid(wd_dev->stack_info->conn_info,
					tid, &idx);
	if (ret < 0) {
		DBG(DBG_LOOKUP, "could not get index of tid [%d] in the "
		    "wd_dev->stack_info->conn_info table\n", tid);
		goto out;
	}
	/* OK now we have a valid idx */
	switch (cmd) {
	/* we only interested in the setting of non-blocking flags */
	case F_SETFL:
		va_copy(largp, argp);
		va_start(largp, cmd);
		flag = va_arg(largp, long);
		if (flag & O_NONBLOCK) {
			wd_dev->stack_info->conn_info[idx].sk_flags
							|= O_NONBLOCK;
			DBG(DBG_CONN, "for sockfd [%d], setting wd_dev"
				"->stack_info->conn_info[%d].sk_flags"
				" with O_NONBLOCK\n", fd, idx);
		}
		va_end(largp);
		break;
	}
out:
	ret = sys_fcntl(fd, cmd, va_arg(argp, long));
	va_end(argp);
	return ret;
}

/*
 * Constructor method (called at lib load time before user app main() fn)
 */
void libwdtoe_init(void)
{
	int err;
	char *env_var;

#ifndef NDEBUG
	env_var = getenv("WDTOE_DEBUG");
	if (env_var) {
		dbg_flags = strtol(env_var, NULL, 0);
		DBG(DBG_INIT, "dbg_flags [0x%x]\n", dbg_flags);
	}
#endif

	env_var = getenv("WDTOE_MA_WR");
	if (env_var) {
		ma_wr = strtol(env_var, NULL, 0);
		if (ma_wr != 1)
			ma_wr = 0;
	}

	env_var = getenv("WDTOE_POLL_SPIN_COUNT");
	if (env_var) {
		max_poll_spin_count = strtol(env_var, NULL, 0);
		if (max_poll_spin_count < 0)
			max_poll_spin_count = 1;
		poll_spin_count = max_poll_spin_count;
	}
	DBG(DBG_INIT, "poll_spin_count %lu\n", poll_spin_count);

	DBG(DBG_INIT, "PID [%d]\n", (int)getpid());

	/* reading config file */
	parse_config_file(CONFIG_FILE);

	/* allocating memory for the kernel connection tuples array */
	k_conn_tuples = calloc(NWDTOECONN, sizeof(*k_conn_tuples));
	if (!k_conn_tuples)
		DBG(DBG_INIT, "could not allocate memory for k_conn_tuples\n");

	/* Here again we rely on the calloc to zero the k_passive_tuples */
	k_passive_tuples = calloc(NWDTOECONN, sizeof(*k_passive_tuples));
	if (!k_passive_tuples)
		DBG(DBG_INIT, "could not allocate memory for k_passive_tuples\n");

	wdtoe_page_size = sysconf(_SC_PAGESIZE);
	wdtoe_page_shift = log2(wdtoe_page_size);
	wdtoe_page_mask = ~(wdtoe_page_size - 1);

	hook_lower_symbols();

	/*
	 * Setting the connection counter to 0 at init time
	 */
	connections = 0;

	latest_conn_map.sockfd = -1;
	latest_conn_map.tid = -1;

	/* start the global polling thread */
	err = pthread_create(&global_thread, NULL, global_thread_func, NULL);

	if (err)
		DBG(DBG_INIT, "could not start demux thread, "
			      "error [%d]\n", err);

	if (!stats_thread_started) {
		stats_thread_started = 1;
		err = pthread_create(&stats_thread, NULL,
				     stats_thread_routine, NULL);

		if (err)
			DBG(DBG_INIT, "could not start stats thread, "
				      "error [%d]\n", err);
	}
}

/*
 * Destructor function. Called when the application is exiting.
 */
void libwdtoe_fini(void)
{
	int ret;

	if (sun.sun_path)
		ret = unlink(sun.sun_path);

	if (ret == -1)
		DBG(DBG_STATS, "%s, %s\n", sun.sun_path, strerror(errno));
#if 0
	profile_report();
#endif
}
