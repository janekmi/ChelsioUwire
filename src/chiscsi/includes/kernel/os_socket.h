#ifndef __OS_SOCK_H__
#define __OS_SOCK_H__

#include <linux/version.h>
#ifdef KERNEL_HAS_KCONFIG_H
#include <linux/kconfig.h>
#endif
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/pci.h>
#include <linux/skbuff.h>
#include <linux/socket.h>

#include <common/cxgb_dev.h>

/*
 * os_socket: linux socket encapsulation
 */
typedef struct os_socket os_socket;

#define COPY_STATE_DATA	0x0
#define COPY_STATE_PI	~COPY_STATE_DATA
struct extract_pi_ctx {
	unsigned int copy_state;
	unsigned int remaining_byte_in_blk;
	unsigned int sector_size;
};

struct rx_cb {
	struct sk_buff *skb;	
	unsigned char fmode;
#define RXCBF_COALESCED		0x1
#define RXCBF_LRO		0x2
	unsigned char pdu_idx;
	unsigned char filler[2];
	unsigned int offset;
	unsigned int frag_idx;
	unsigned int frag_offset;
	unsigned int ulp_len;	/* ulp mode only total pdu length */
	struct extract_pi_ctx pictx;
	void (*rx_skb_done)(struct os_socket *);
};

struct os_socket {
	struct rx_cb rcb;
	unsigned int txq_len;
	struct sk_buff	*skb_head;
	struct sk_buff	*skb_tail;
        struct socket *sock;
	struct offload_device *odev;
	struct iscsi_socket *isock;
        void (*orig_state_change) (struct sock * sk);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
	void (*orig_data_ready) (struct sock * sk);
#else
	void (*orig_data_ready) (struct sock * sk, int bytes);
#endif
        void (*orig_write_space) (struct sock * sk);
};
#define isock_2_osock(isock) \
	((os_socket *)((iscsi_socket *)(isock))->s_private)
#define isock_2_sk(isock) \
	isock_2_osock(isock)->sock->sk
#define osock_2_sk(osock)	(osock)->sock->sk
#define sk_2_isock(sk)		(iscsi_socket *)(sk)->sk_user_data

int os_sock_read_pdu_header_nic(iscsi_socket *, iscsi_pdu *);
int os_sock_read_pdu_data_nic(iscsi_socket *, iscsi_pdu *);
int os_sock_write_pdus_nic(iscsi_socket *, chiscsi_queue *, chiscsi_queue *);

struct sk_buff *os_sock_pdu_tx_skb(iscsi_socket *, struct offload_device *,
				iscsi_pdu *, int);

int os_sock_pdu_bhs_error(iscsi_socket *, unsigned char *, unsigned int);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
#define sock_create_kern(__a, __b, __c, __d) \
		sock_create_kern(&init_net, __a, __b, __c, __d)
#endif
#endif /* ifndef __OS_SOCK_H__ */

