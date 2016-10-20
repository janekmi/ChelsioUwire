#ifndef __LIBWDTOE_LIBWDTOE_H__
#define __LIBWDTOE_LIBWDTOE_H__

#include <sys/types.h>
#include <asm/types.h>
#include <linux/socket.h>
#include <sys/syscall.h>
#include "t4.h"
#include "t4_regs.h"
#include "atomic.h"
#include "debug.h"
#include "common.h"
#include "device.h"

/* for txq, we are mapping txq->queue, txq->shared_param, txq->udb */
#define WDTOE_RX_CRED_THRES 8192
#define MAX_WD_PATH_TX_DATA 4096

#define ROUND_UP(n, s) ((((n) + (s) - 1) / (s)) * (s))
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define MAX_INLINE	((int)((MAX_INLINE_OFLD_TX_DESC *	\
			sizeof(struct t4_desc)) -		\
			sizeof(struct fw_ofld_tx_data_wr)))
#define FALLBACK_TO_SYSPATH (-2)

struct wdtoe_pkt_gl {
	void *frags_va[256 - 8];	/* virtual address of first byte of each frag */
	unsigned int nfrags;		/* number of fragments */
	unsigned int tot_len;		/* total length of fragments */
};

struct fast_send_wr {
	struct sw_cred_q_entry credqe;
	struct sw_t4_txq *sw_txq;
	__u16 s_idx;
	int count;
};

struct wdtoe_cached_conn_map {
	int sockfd;
	int tid;
};

struct wdtoe_poll_in_kernel {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
};

struct temp_tx_buf {
	void *va_buf;
	__u64 dma_addr;
	int len;
};

struct wdtoe_pass_pid {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	/* XXX can add more elements */
	__u32 pid;
};

/* Prototypes */
void __attribute__ ((constructor)) libwdtoe_init(void);
void __attribute__ ((destructor)) libwdtoe_fini(void);

extern int __register_atfork(void (*prepare)(void), void (*parent)(void), 
			     void (*child)(void), void *dso);
#endif
