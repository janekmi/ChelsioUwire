#ifndef __LIBWDTOE_COMMON_H__
#define __LIBWDTOE_COMMON_H__

#include <poll.h>
#include "t4.h"
#include "stats.h"
#include "sysfns.h"
#include "kernelcom.h"

#define NWDTOECONN 64

enum wdtoe_conn_info_state {
	AVAILABLE,
	IN_USE,
	INCOMPLETE,
};

enum wdtoe_tcp_states {
	TCP_IDLE,
	TCP_ESTABLISHED,
	TCP_CLOSE_WAIT,
};

struct wdtoe_conn_info {
	unsigned int atid;
	unsigned int stid;
	unsigned int lport;
	__u32 pip;
	__u16 pport;
	int tid;
	int sockfd;
	enum wdtoe_conn_info_state state;
	enum wdtoe_tcp_states tcp_state;
	int port_num;
	/* unacked RX credits */
	__u32 copied;
	__u32 buf_len;
	int buf_idx;			/* index for Tx and Rx buffers */
	int wd_flags;
	int sk_flags;
	unsigned int max_credits;
	atomic_t cur_credits;
	unsigned int pend_credits;
	struct conn_stats stats;
};


/*
 * Macros to manipulate the 'flags' field in
 * the wdtoe_conn_info structure.
 */
#define S_TX_DATA_SENT		0
#define M_TX_DATA_SENT		0x1
#define V_TX_DATA_SENT(x)	((x) << S_TX_DATA_SENT)
#define G_TX_DATA_SENT(x)	(((x) >> S_TX_DATA_SENT) & M_TX_DATA_SENT)
#define F_TX_DATA_SENT		V_TX_DATA_SENT(1U)

#define S_TX_CURR_PATH		1
#define M_TX_CURR_PATH		0x1
#define V_TX_CURR_PATH(x)	((x) << S_TX_CURR_PATH)
#define G_TX_CURR_PATH(x)	(((x) >> S_TX_CURR_PATH) & M_TX_CURR_PATH)
#define F_TX_CURR_PATH		V_TX_CURR_PATH(1U)

#define S_TX_PREV_PATH		2
#define M_TX_PREV_PATH		0x1
#define V_TX_PREV_PATH(x)	((x) << S_TX_PREV_PATH)
#define G_TX_PREV_PATH(x)	(((x) >> S_TX_PREV_PATH) & M_TX_PREV_PATH)
#define F_TX_PREV_PATH		V_TX_PREV_PATH(1U)

#endif
