/*
 * Copyright (C) 2003-2010 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com)
 *
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef _CHELSIO_TOM_DEFS_H
#define _CHELSIO_TOM_DEFS_H

#include <linux/version.h>
#include <linux/skbuff.h>
#include <net/tcp.h>
#include <net/offload.h>
#include "t4_hw.h"
#include "common.h"
#include "cxgb4_ofld.h"
#include "tom.h"

/* CPL message correctness validation switches */
#define VALIDATE_TID 1
#define VALIDATE_LEN 1
#define VALIDATE_SEQ 1

#define SCHED_CLS_NONE 0xff

#define RSS_HDR_VLD 1

#define INVALID_TAG 0xffffffffU
#define INVALID_TID 0xffffffffU

/*
 * Socket options handled by various Offload Sockets.  Not all socket types
 * (TCP, UDP Segmentation Offload, etc.) support all socket options but
 * they're constants are defined here so they all use the same values.
 */
enum {
	/*
	 * Bind a socket to a Transmit Scheduling Class.
	 */
	TCP_SCHEDCLASS = 290,
	UDP_SCHEDCLASS = TCP_SCHEDCLASS,

	/*
	 * Set the UDP Segmentation Size for a UDP "Offloaded" socket.
	 */
	UDP_FRAMESIZE = 291,

	/*
	 * Set the RTP header length.
	 */
	UDP_RTPHEADERLEN = 292,
};

struct proc_dir_entry;
struct toedev;
struct tom_data;

#include "tom_compat.h"

/*
 * Opaque version of structure the SGE stores at skb->head of TX_DATA packets
 * and for which we must reserve space.
 */
struct sge_opaque_hdr {
	void *dev;
	dma_addr_t addr[MAX_SKB_FRAGS + 1];
};

/*
 * Returns true if a socket cannot accept new Rx data.
 */
static inline int sk_no_receive(const struct sock *sk)
{
        return (sk->sk_shutdown & RCV_SHUTDOWN);
}

/*
 * Allocate an sk_buff when allocation failure is not an option.
 */
static inline struct sk_buff *alloc_skb_nofail(unsigned int len)
{
	return alloc_skb(len, GFP_KERNEL | __GFP_NOFAIL);
}

/*
 * Returns true if the socket is in one of the supplied states.
 */
static inline unsigned int sk_in_state(const struct sock *sk,
				       unsigned int states)
{
	return states & (1 << sk->sk_state);
}

/*
 * Release a socket's local TCP port if the socket is bound.  This is normally
 * done by tcp_done() but because we need to wait for HW to release TIDs we
 * usually call tcp_done at a later time than the SW stack would have.  This
 * can be used to release the port earlier so the SW stack can reuse it before
 * we are done with the connection.
 */
static inline void release_tcp_port(struct sock *sk)
{
	if (inet_csk(sk)->icsk_bind_hash)
		t4_inet_put_port(&tcp_hashinfo, sk);
}


/*
 * Max receive window supported by HW in bytes.  Only a small part of it can
 * be set through option0, the rest needs to be set through RX_DATA_ACK.
 */
#define MAX_RCV_WND ((1U << 27) - 1)

#include "cxgb4_ofld.h"

/* for TX: a skb must have a headroom of at least TX_HEADER_LEN bytes */
#define TX_HEADER_LEN \
		(sizeof(struct tx_data_wr) + sizeof(struct sge_opaque_hdr))

#define TX_HEADER_LEN_UO \
	(sizeof(struct cpl_tx_pkt_core) + sizeof(struct fw_eth_tx_eo_wr) + \
	sizeof(struct sge_opaque_hdr))

/*
 * Determine the value of a packet's ->priority field.  Bit 0 determines
 * whether the packet should use a control Tx queue, bits 1..3 determine
 * the queue set to use.
 */
static inline void set_queue(struct sk_buff *skb, unsigned int queue, const struct sock *sk)
{
	skb->queue_mapping = queue;
}

static inline void t4_purge_receive_queue(struct sock *sk)
{
	struct sk_buff *skb;

	while ((skb = __skb_dequeue(&sk->sk_receive_queue)) != NULL) {
		skb_gl_set(skb, NULL);
		kfree_skb(skb);
	}
}

void t4tom_register_cpl_handler(unsigned int opcode, t4tom_cpl_handler_func h);
int t4tom_cpl_handler_registered(unsigned int opcode);
void t4tom_register_cpl_iscsi_callback(void (*fp)(struct tom_data *td,
					struct sock *sk, struct sk_buff *skb,
					unsigned int opcode)); 
void t4tom_register_iscsi_lro_handler(
			int (*fp_rcv)(struct sock *, u8, 
					const __be64 *,
					struct napi_struct *napi,
					const struct pkt_gl *,
					struct t4_lro_mgr *,
					void (*flush)(struct t4_lro_mgr *,
						struct sk_buff *)),
			void (*fp_proc)(struct sock *, struct sk_buff *));
int t4tom_cpl_handler_rsp_registered(unsigned int opcode);
int t4_can_offload(struct toedev *dev, struct sock *sk);
void t4_listen_start(struct toedev *dev, struct sock *sk,
		     const struct offload_req *r);
void t4_listen_stop(struct toedev *dev, struct sock *sk);
int t4_push_frames(struct sock *sk, int);
unsigned int t4_calc_opt2(const struct sock *sk,
			  const struct offload_settings *s,
			  unsigned int iq_id);
u8 tcp_state_to_flowc_state(u8 state);
void send_tx_flowc_wr(struct sock *sk, int compl, u32 snd_nxt, u32 rcv_nxt);
int t4_sendskb(struct sock *sk, struct sk_buff *skb, int flags);
void t4_purge_write_queue(struct sock *sk);
void t4_set_migrating(struct sock *sk, int on);
void t4_set_tcb_field(struct sock *sk, u16 word, u64 mask, u64 val);
void t4_set_tcb_field_rpl(struct sock *sk, u16 word, u64 mask, u64 val, u8 cookie);
void t4_set_nagle(struct sock *sk);
void t4_set_tos(struct sock *sk);
void t4_set_keepalive(struct sock *sk, int on_off);
void t4_enable_ddp(struct sock *sk, int on);
void t4_disable_ddp(struct sock *sk);
void t4_set_ddp_tag(struct sock *sk, int buf_idx, unsigned int tag);
void t4_set_ddp_buf(struct sock *sk, int buf_idx, unsigned int offset,
		    unsigned int len);
void t4_set_ddp_indicate(struct sock *sk, int on);
void t4_setup_indicate_modrx(struct sock *sk);
void t4_write_space(struct sock *sk);
void t4_cleanup_rbuf(struct sock *sk, int copied);
int t4_send_reset(struct sock *sk, int mode, struct sk_buff *skb);
int t4_connect(struct toedev *dev, struct sock *sk, struct net_device *edev);
void t4_disconnect_acceptq(struct sock *sk);
void t4_reset_synq(struct sock *sk);
u32 t4_send_rx_credits(struct sock *sk, u32 credits, u32 dack, int nofail);
int t4_set_cong_control(struct sock *sk, const char *name);
int t4_listen_proc_setup(struct proc_dir_entry *dir, struct tom_data *d);
void t4_listen_proc_free(struct proc_dir_entry *dir);
void t4_set_rcv_coalesce_enable(struct sock *sk, int on);
void t4_set_dack(struct sock *sk, int on);
void t4_set_dack_mss(struct sock *sk, int on);
void failover_check(void *data);
unsigned int t4_select_delack(struct sock *sk);
void t4_select_window(struct sock *sk);
void t4_drain_migrating_receiver(struct sock *sk);
void t4_fail_act_open(struct sock *sk, int errno);
void t4_install_standard_ops(struct sock *sk);
void t4_cplios_release(struct kref *ref);
#ifdef UDP_OFFLOAD
int t4_udp_push_frames(struct sock *sk);
#endif

int t4_recv_rsp(struct tom_data *td, const __be64 *rsp);
struct sk_buff *alloc_ctrl_skb(struct sk_buff *skb, int len);

#if defined(CONFIG_T4_ZCOPY_SENDMSG) || defined(CONFIG_T4_ZCOPY_SENDMSG_MODULE)
void t4_zcopy_cleanup_skb(struct sock *, struct sk_buff *);
#endif

#if defined(BOND_SUPPORT)
void t4_failover(struct toedev *tdev, struct net_device *bond_dev,
		 struct net_device *slave_dev, int event, struct net_device *last);
void t4_update_master_devs(struct toedev *tdev);
void send_failover_flowc_wr(struct sock *sk);
#else
static inline void t4_failover(struct toedev *tdev, struct net_device *bond_dev,
			       struct net_device *slave_dev, int event, struct net_device *last)
{}

static inline void t4_update_master_devs(struct toedev *tdev) {}
static inline void send_failover_flowc_wr(struct sock *sk) {}
#endif

// initialization
void t4_init_offload_ops(void);
void t4_init_listen_cpl_handlers(void);
void t4_init_wr_tab(unsigned int wr_len);
int t4_init_cpl_io(void);
void t4_free_sk_filter(void);

#ifdef UDP_OFFLOAD
void udpoffload4_register(void);
void udpoffload4_unregister(void);
#ifdef CONFIG_UDPV6_OFFLOAD
int chelsio_udp_v6_push_pending_frames(struct sock *sk);
extern struct proto *udpv6_prot_p;
extern void (*ipv6_local_rxpmtu_p)(struct sock *sk, struct flowi6 *fl6,
				   u32 mtu);
extern void (*ipv6_local_error_p)(struct sock *sk, int err,
				  struct flowi6 *fl6, u32 info);
extern void (*ipv6_select_ident_p)(struct frag_hdr *fhdr, struct rt6_info *rt);
extern void (*ipv6_push_frag_opts_p)(struct sk_buff *skb,
				     struct ipv6_txoptions *opt, u8 *proto);
extern void udp_v6_flush_pending_frames(struct sock *sk);
extern int chelsio_ipv6_get_lladdr(struct net_device *dev,
					  struct in6_addr *addr,
					  unsigned char banned_flags);
#endif /* CONFIG_UDPV6_OFFLOAD */
#endif

#endif /* _CHELSIO_TOM_DEFS_H */
