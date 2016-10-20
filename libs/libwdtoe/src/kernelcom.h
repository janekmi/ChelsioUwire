#ifndef __LIBWDTOE_KERNELCOM_H__
#define __LIBWDTOE_KERNELCOM_H__

#include <asm/types.h>
#include <stddef.h>
#include <stdint.h>
#include "ntuples.h"
#include "t4.h"

#define WDTOE_BUILD_CMD(cmd, size, opcode, out, outsize)		\
	do {								\
		(cmd)->command = WDTOE_CMD_##opcode;			\
		(cmd)->in_words = (size) / 4;				\
		(cmd)->out_words = (outsize) / 4;			\
		(cmd)->response = (uintptr_t) (out);			\
	    } while (0)

enum {
	WDTOE_CMD_CREATE_RXQ,
	WDTOE_CMD_PASS_PID,
	WDTOE_CMD_CPL_TO_TOM,
	WDTOE_CMD_CONN_TUPLES,
	WDTOE_CMD_PASS_TUPLES,
	WDTOE_CMD_UPDATE_RX_CREDITS,
	WDTOE_CMD_COPY_RXQ,
	WDTOE_CMD_GET_PORT_NUM,
	WDTOE_CMD_CREATE_DEV,
	WDTOE_CMD_REG_LISTEN,
	WDTOE_CMD_REMOVE_LISTEN,
	WDTOE_CMD_CREATE_MEMPOOL,
	WDTOE_CMD_COPY_TXQ,
	WDTOE_CMD_REG_STACK,
	WDTOE_CMD_SEND_FLOWC,
};

struct wdtoe_create_dev {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
};

struct wdtoe_create_dev_resp {
	__u16 dev_idx;
};

struct wdtoe_create_rxq {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	/* XXX can add more elements */
	__u32 tx_hold_thres;
};

struct wdtoe_create_rxq_resp {
	__u32 nports;
	__u32 stack_info_memsize;
	__u32 hca_type;
	__u32 qid_mask;
};

struct wdtoe_copy_rxq {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	/* specified element */
	/* XXX name confusing, change to nports? */
	__u32 port_num;
};

/* iq comes back from here */
struct wdtoe_copy_rxq_resp {
	__u64 db_key;
	__u64 fl_key;
	__u64 iq_key;
	__u64 fl_memsize;
	__u64 iq_memsize;
	__u32 fl_id;
	__u32 iq_id;
	__u32 fl_size;
	__u32 iq_size;
	__u32 fl_pidx;
	__u32 fl_pend_cred;
	__u32 fl_avail;
};

struct wdtoe_copy_txq {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	/* specified element */
	/* XXX name confusing, change to nports? */
	__u32 port_num;
};

/* iq comes back from here */
struct wdtoe_copy_txq_resp {
	//__u64 db_key;
	//__u64 txq_key;
	__u64 txq_memsize;
	__u32 txq_id;
	__u32 txq_size;
	__u16 flags;
	//__u32 tx_chan;
	//__u32 pf;
	//__u32 flags;
	//__u32 fid;
};

struct wdtoe_create_mempool {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	/* XXX can add more elements */
	/* number of free pages you want to create */
	__u32 page_num;
};

struct wdtoe_create_mempool_resp {
};

struct wdtoe_reg_stack {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
};

struct wdtoe_reg_stack_resp {
};

struct wdtoe_update_rx_credits {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	/* XXX can add more elements */
	__u32 tid;
	__u32 buf_len;
	__u32 copied;
};

struct wdtoe_update_rx_credits_resp {

};

struct wdtoe_send_tx_flowc {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	/* specified element */
	__u32 tid;
};

struct wdtoe_send_tx_flowc_resp {
	__u32 rcv_nxt;
	__u32 snd_nxt;
	__u16 advmss;
	__u32 sndbuf;
	__u32 tx_c_chan;
	__u32 pfvf;
	__u32 txplen_max;
};

struct wdtoe_get_conn_tuples {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	/* XXX can add more elements */
};

struct wdtoe_get_passive_tuples {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	/* XXX can add more elements */
};

struct wdtoe_cpl_act_establish {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	struct t4_iqe iqe_cpl;
};
struct wdtoe_cpl_act_establish_resp {
	__u32 reply;
};

struct wdtoe_reg_listen {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	__u16 dev_idx;
	__u16 listen_port;
};

struct wdtoe_reg_listen_resp {

};

struct wdtoe_remove_listen {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	__u16 listen_port;
};

struct wdtoe_remove_listen_resp {

};

struct wdtoe_get_port_num {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
	__u64 response;
	/* specified element */
	__u32 tid;
};

struct wdtoe_get_port_num_resp {
	__u32 port_num;
	__u32 max_cred;
};

int wdtoe_cmd_create_dev(int fd, struct wdtoe_create_dev *cmd,
			 size_t cmd_size,
			 struct wdtoe_create_dev_resp *resp,
			 size_t resp_size);

int wdtoe_cmd_create_rxq(int fd, struct wdtoe_create_rxq *cmd,
			 size_t cmd_size,
			 struct wdtoe_create_rxq_resp *resp,
			 size_t resp_size, int tx_hold_thres);

int wdtoe_cmd_copy_rxq(int fd, struct wdtoe_copy_rxq *cmd,
		       size_t cmd_size,
		       struct wdtoe_copy_rxq_resp *resp,
		       size_t resp_size);

int wdtoe_cmd_copy_txq(int fd, struct wdtoe_copy_txq *cmd,
		       size_t cmd_size,
		       struct wdtoe_copy_txq_resp *resp,
		       size_t resp_size);

int wdtoe_cmd_create_mempool(int fd, struct wdtoe_create_mempool *cmd,
			     size_t cmd_size,
			     struct wdtoe_create_mempool_resp *resp,
			     size_t resp_size);

int wdtoe_cmd_register_stack(int fd, struct wdtoe_reg_stack *cmd,
			     size_t cmd_size,
			     struct wdtoe_reg_stack_resp *resp,
			     size_t resp_size);

int wdtoe_cmd_update_rx_credits(int fd, struct wdtoe_update_rx_credits *cmd,
				size_t cmd_size,
				struct wdtoe_update_rx_credits *resp,
				size_t resp_size);

int wdtoe_cmd_send_tx_flowc(int fd, struct wdtoe_send_tx_flowc *cmd,
			    size_t cmd_size,
			    struct wdtoe_send_tx_flowc_resp *resp,
			    size_t resp_size);

int get_kernel_passive_tuples(int fd, struct wdtoe_get_passive_tuples *cmd,
			      size_t cmd_size, struct passive_tuple *resp,
			      size_t resp_size);

int get_kernel_conn_tuples(int fd, struct wdtoe_get_conn_tuples *cmd,
			   size_t cmd_size, struct conn_tuple *resp,
			   size_t resp_size);

int wdtoe_cmd_pass_cpl_to_tom(int fd, struct wdtoe_cpl_act_establish *cmd,
			      size_t cmd_size,
			      struct wdtoe_cpl_act_establish_resp *resp,
			      size_t resp_size);

int wdtoe_cmd_get_port_num(int fd, struct wdtoe_get_port_num *cmd,
			   size_t cmd_size,
			   struct wdtoe_get_port_num_resp *resp,
			   size_t resp_size);

int wdtoe_cmd_reg_listen(int fd, struct wdtoe_reg_listen *cmd,
			 size_t cmd_size,
			 struct wdtoe_reg_listen_resp *resp,
			 size_t resp_size);

int wdtoe_cmd_remove_listen(int fd, struct wdtoe_remove_listen *cmd,
			    size_t cmd_size,
			    struct wdtoe_remove_listen_resp *resp,
			    size_t resp_size);
#endif
