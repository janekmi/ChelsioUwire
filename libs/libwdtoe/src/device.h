#ifndef __LIBWDTOE_DEVICE_H__
#define __LIBWDTOE_DEVICE_H__

#include <asm/types.h>
#include "t4.h"
#include "common.h"

#define MAX_INLINE_T5 48
#define WDTOE_FLSIZE 16
#define WDTOE_MMAPNUM_RXQ (WDTOE_FLSIZE * 16 + 5)
#define WDTOE_MMAPNUM_TXQ 3
#define NTXBUF 48
#define NCRED 64

enum wdtoe_hca_type {
	CHELSIO_T4 = 0,
	CHELSIO_T5 = 1,
};

struct wdtoe_listsvr {
	int sockfd;
	int idx;
	__u16 listen_port;
	atomic_t ref_cnt;
};

struct sw_txq_entry {
	__u64 dma_addr;
	int copied;
};

struct sw_t4_txq {
	struct sw_txq_entry queue[NTXBUF];
	__u64 sw_queue[NTXBUF];
	__u16 size;
	__u16 cidx;
	__u16 pidx;
	atomic_t in_use;
	__u16 pend_cred;
};

struct sw_cred_q_entry {
	int cred;
	int n_bufs;
};

struct sw_cred_q {
	struct sw_cred_q_entry queue[NCRED];
	__u16 size;
	__u16 cidx;
	__u16 pidx;
};

struct rx_tx_buffer {
	struct sw_t4_txq sw_txq[NWDTOECONN];
	struct sw_t4_raw_fl sw_fl[NWDTOECONN];
	struct sw_cred_q credq[NWDTOECONN];
	int flags[NWDTOECONN];
	pthread_spinlock_t lock;
};

struct wdtoe_stack_info {
	struct wdtoe_conn_info conn_info[NWDTOECONN];
	struct rx_tx_buffer buf;
	struct wdtoe_listsvr svr_info[NWDTOECONN];
};

struct wdtoe_device {
	int dev_idx;
	int devfd;
	struct t4_iq **iq_list;
	struct t4_raw_fl **fl_list;
	struct t4_txq **txq_list;
	int nports;
	struct wdtoe_stack_info *stack_info;
	__u32 stack_info_memsize;
	enum wdtoe_hca_type hca_type;
	__u32 qid_mask;
};

#endif
