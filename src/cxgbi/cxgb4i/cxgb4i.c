/*
 * cxgb4i.c: Chelsio T4 iSCSI driver.
 *
 * Copyright (c) 2012-2015 Chelsio Communications, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by:	Karen Xie (kxie@chelsio.com)
 *		Rakesh Ranjan (rranjan@chelsio.com)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ":%s: " fmt, __func__

#include <linux/version.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_cmnd.h>
#include <net/tcp.h>
#include <net/dst.h>
#include <linux/netdevice.h>
#include <net/addrconf.h>

#include "t4_regs.h"
#include "t4_msg.h"
#include "t4_tcb.h"
#ifndef __CXGB4TOE__
#include "cxgb4.h"
#include "cxgb4_uld.h"
#include "t4fw_api.h"
#endif
#include "l2t.h"
#include "clip_tbl.h"

#include "../cxgbi_compat.h"

#ifdef SLES10SP3
#undef pr_warning
#endif

#include "cxgb4i.h"
#include "cxgb4i_compat.h"
#ifdef __CONFIG_CXGB4_DCB__
#include <net/dcbevent.h>
#include "cxgb4_dcb.h"
#endif

#ifdef DEL_WORK
#undef delayed_work
#endif

#ifdef SLES10SP3
#undef rounddown_pow_of_two
#define fls_long __fls_long
#undef INIT_DELAYED_WORK
#undef INIT_WORK
#define INIT_WORK(work, func, _work) backport_INIT_WORK(work, func)
#endif

static unsigned int dbg_level;
#include "libcxgbi.h"

#define	DRV_MODULE_NAME		"cxgb4i"

#define DRV_MODULE_DESC		"Chelsio T4 iSCSI Driver"
#define	DRV_MODULE_VERSION	"2.12.0.3-1203"
#define	DRV_MODULE_RELDATE	"Apr 2015"

static char version[] =
	DRV_MODULE_DESC " " DRV_MODULE_NAME
	" v" DRV_MODULE_VERSION " (" DRV_MODULE_RELDATE ")";

MODULE_AUTHOR("Chelsio Communications, Inc.");
MODULE_DESCRIPTION(DRV_MODULE_DESC);
MODULE_VERSION(DRV_MODULE_VERSION);
MODULE_LICENSE("GPL");

module_param(dbg_level, uint, 0644);
MODULE_PARM_DESC(dbg_level, "Debug flag (default=0)");

#define CXGB4I_DEFAULT_SG_TABLESIZE	4096
static int cxgb4i_sg_tablesize = 0;
module_param(cxgb4i_sg_tablesize, int, 0644);
MODULE_PARM_DESC(cxgb4i_sg_tablesize,
		"scsi host template sg_tablesize,(default=4096)");

#define CXGB4I_DEFAULT_10G_RCV_WIN (256 * 1024)
static int cxgb4i_rcv_win = -1;
module_param(cxgb4i_rcv_win, int, 0644);
MODULE_PARM_DESC(cxgb4i_rcv_win, "TCP reveive window in bytes");

#define CXGB4I_DEFAULT_10G_SND_WIN (128 * 1024)
static int cxgb4i_snd_win = -1;
module_param(cxgb4i_snd_win, int, 0644);
MODULE_PARM_DESC(cxgb4i_snd_win, "TCP send window in bytes");

static int nocong;
module_param(nocong, int, 0644);
MODULE_PARM_DESC(nocong, "Turn of congestion control (default=0)");

static int enable_ecn = 0;
module_param(enable_ecn, int, 0644);
MODULE_PARM_DESC(enable_ecn, "Enable ECN (default=0/disabled)");

static int dack_mode = 0;
module_param(dack_mode, int, 0644);
MODULE_PARM_DESC(dack_mode, "Delayed ack mode (default=1)");

static int enable_tcp_tmstamps = 0;
module_param(enable_tcp_tmstamps, int, 0644);
MODULE_PARM_DESC(enable_tcp_tmstamps, "Enable tcp timestamps (default=0)");

static int enable_tcp_sack = 0;
module_param(enable_tcp_sack, int, 0644);
MODULE_PARM_DESC(enable_tcp_sack, "Enable tcp SACK (default=0)");

static int cxgb4i_rx_credit_thres = 10 * 1024;
module_param(cxgb4i_rx_credit_thres, int, 0644);
MODULE_PARM_DESC(cxgb4i_rx_credit_thres,
		"RX credits return threshold in bytes (default=10KB)");

static unsigned int cxgb4i_max_connect = (8 * 1024);
module_param(cxgb4i_max_connect, uint, 0644);
MODULE_PARM_DESC(cxgb4i_max_connect, "Maximum number of connections");

static unsigned short cxgb4i_sport_base = 20000;
module_param(cxgb4i_sport_base, ushort, 0644);
MODULE_PARM_DESC(cxgb4i_sport_base, "Starting port number (default 20000)");

static unsigned int ddp_off = 0;
module_param(ddp_off, uint, 0644);
MODULE_PARM_DESC(ddp_off, "turn off ddp (default=0)");

#ifdef CXGBI_T10DIF_SUPPORT
static unsigned int prot_en = 0;
module_param(prot_en, uint, 0644);
MODULE_PARM_DESC(prot_en, "enable t10 dif protection (default 0: disabled, "
	"1: HBA to host os, 2: end-to-end)");
#endif

static unsigned int iso_on = 1;
module_param(iso_on, uint, 0644);
MODULE_PARM_DESC(iso_on, "enable iscsi lso (default=1)");

static unsigned int ppod_ofldq = 1;
module_param(ppod_ofldq, uint, 0644);
MODULE_PARM_DESC(ppod_ofldq, "Use ofldq to send ppod write wr (default=1)");

static unsigned int lro_on = 1;
module_param(lro_on, uint, 0644);
MODULE_PARM_DESC(lro_on, "enable iscsi lro (default=1)");

unsigned int ppm_rsvd_factor = 2;
module_param(ppm_rsvd_factor, uint, 0644);
MODULE_PARM_DESC(ppm_rsvd_factor, "iscsi ppm cpu reserve factor N: 1/N reserved for cpu pool (default 2)");

typedef void (*cxgb4i_cplhandler_func)(struct cxgbi_device *, struct sk_buff *);

static struct scsi_host_template cxgb4i_host_template = {
	.module		= THIS_MODULE,
	.name		= DRV_MODULE_NAME,
	.proc_name	= DRV_MODULE_NAME,
	.can_queue	= CXGB4I_SCSI_HOST_QDEPTH_MAX,
	.queuecommand	= iscsi_queuecommand,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0))
	.change_queue_depth = scsi_change_queue_depth,
#else
	.change_queue_depth = iscsi_change_queue_depth,
#endif
	.sg_tablesize	= CXGB4I_DEFAULT_SG_TABLESIZE,
#if defined CXGBI_T10DIF_SUPPORT && defined SG_PROT_TABLESIZE
	/* Keep it same as sg_tablesize */
	.sg_prot_tablesize = CXGB4I_DEFAULT_SG_TABLESIZE,
#endif
	.cmd_per_lun	= ISCSI_DEF_CMD_PER_LUN,
	.eh_abort_handler = iscsi_eh_abort,
	.eh_device_reset_handler = iscsi_eh_device_reset,
#if defined OISCSI_SCSI_TARGET_RESET_HANDLER && defined OISCSI_DEFINED_RECOVER_TARGET
	.eh_target_reset_handler = iscsi_eh_recover_target,
#elif defined OISCSI_SCSI_TARGET_RESET_HANDLER && defined OISCSI_DEFINED_RESET_TARGET
	.eh_target_reset_handler = iscsi_eh_reset_target,
#endif
#if defined OISCSI_SCSI_HOST_RESET_HANDLER && defined OISCSI_DEFINED_RECOVER_TARGET
	.eh_host_reset_handler = iscsi_eh_recover_target,
#endif
	.slave_configure = cxgbi_slave_configure,
#ifdef OISCSI_SCSI_TARGET_ALLOC_HANDLER
	.target_alloc	= iscsi_target_alloc,
#endif
	.use_clustering	= DISABLE_CLUSTERING,
	.this_id	= -1,
};

static struct iscsi_transport cxgb4i_iscsi_transport = {
	.owner		= THIS_MODULE,
	.name		= DRV_MODULE_NAME,
	.caps		= CAP_RECOVERY_L0 | CAP_MULTI_R2T | CAP_HDRDGST |
				CAP_DATADGST | CAP_DIGEST_OFFLOAD |
				CAP_PADDING_OFFLOAD,
#ifdef OISCSI_TRANSPORT_HAS_ATTR_IS_VISIBLE
	.attr_is_visible = cxgbi_attr_is_visible,
#endif
#ifdef OISCSI_TRANSPORT_HAS_PARAM_MASK
	.param_mask	= ISCSI_MAX_RECV_DLENGTH | ISCSI_MAX_XMIT_DLENGTH |
				ISCSI_HDRDGST_EN | ISCSI_DATADGST_EN |
				ISCSI_INITIAL_R2T_EN | ISCSI_MAX_R2T |
				ISCSI_IMM_DATA_EN | ISCSI_FIRST_BURST |
				ISCSI_MAX_BURST | ISCSI_PDU_INORDER_EN |
				ISCSI_DATASEQ_INORDER_EN | ISCSI_ERL |
				ISCSI_CONN_PORT | ISCSI_CONN_ADDRESS |
				ISCSI_EXP_STATSN | ISCSI_PERSISTENT_PORT |
				ISCSI_PERSISTENT_ADDRESS |
				ISCSI_TARGET_NAME | ISCSI_TPGT |
				ISCSI_USERNAME | ISCSI_PASSWORD |
				ISCSI_USERNAME_IN | ISCSI_PASSWORD_IN |
				ISCSI_FAST_ABORT | ISCSI_ABORT_TMO |
				ISCSI_LU_RESET_TMO | ISCSI_TGT_RESET_TMO |
				ISCSI_PING_TMO | ISCSI_RECV_TMO |
				ISCSI_IFACE_NAME | ISCSI_INITIATOR_NAME,
	.host_param_mask	= ISCSI_HOST_HWADDRESS | ISCSI_HOST_IPADDRESS |
				ISCSI_HOST_INITIATOR_NAME |
				ISCSI_HOST_NETDEV_NAME,
#endif
	.get_host_param	= cxgbi_get_host_param,
	.set_host_param	= cxgbi_set_host_param,
	/* session management */
	.create_session	= cxgbi_create_session,
	.destroy_session	= cxgbi_destroy_session,
	.get_session_param = iscsi_session_get_param,
	/* connection management */
	.create_conn	= cxgbi_create_conn,
	.bind_conn		= cxgbi_bind_conn,
	.destroy_conn	= iscsi_tcp_conn_teardown,
	.start_conn		= iscsi_conn_start,
	.stop_conn		= iscsi_conn_stop,
	.get_conn_param	= cxgbi_get_conn_param,
	.set_param	= cxgbi_set_conn_param,
	.get_stats	= cxgbi_get_conn_stats,
	/* pdu xmit req from user space */
	.send_pdu	= iscsi_conn_send_pdu,
	/* task */
	.init_task	= iscsi_tcp_task_init,
	.xmit_task	= iscsi_tcp_task_xmit,
	.cleanup_task	= cxgbi_cleanup_task,
	/* pdu */
	.alloc_pdu	= cxgbi_conn_alloc_pdu,
	.init_pdu	= cxgbi_conn_init_pdu,
	.xmit_pdu	= cxgbi_conn_xmit_pdu,
	.parse_pdu_itt	= cxgbi_parse_pdu_itt,
	/* TCP connect/disconnect */
#ifdef OISCSI_TRANSPORT_HAS_GET_EP_PARAM
	.get_ep_param	= cxgbi_get_ep_param,
#endif
	.ep_connect	= cxgbi_ep_connect,
	.ep_poll	= cxgbi_ep_poll,
	.ep_disconnect	= cxgbi_ep_disconnect,
	/* Error recovery timeout call */
	.session_recovery_timedout = iscsi_session_recovery_timedout,
};

static int send_tx_flowc_wr(struct cxgbi_sock *csk, int compl);
#ifdef __CONFIG_CXGB4_DCB__
static int cxgb4_dcb_change_notify(struct notifier_block *, unsigned long,
                                void *);
static struct notifier_block cxgb4_dcb_change = {
        .notifier_call = cxgb4_dcb_change_notify,
};
#endif

static struct scsi_transport_template *cxgb4i_stt;

/*
 * CPL (Chelsio Protocol Language) defines a message passing interface between
 * the host driver and Chelsio asic.
 * The section below implments CPLs that related to iscsi tcp connection
 * open/close/abort and data send/receive.
 */
#define DIV_ROUND_UP(n, d)	(((n) + (d) - 1) / (d))
#define RCV_BUFSIZ_MASK		0x3FFU

#define MAX_IMM_TX_PKT_LEN	256

static int push_tx_frames(struct cxgbi_sock *, int);

/*
 * is_ofld_imm - check whether a packet can be sent as immediate data
 * @skb: the packet
 *
 * Returns true if a packet can be sent as an offload WR with immediate
 * data.  We currently use the same limit as for Ethernet packets.
 */
static inline int is_ofld_imm(const struct sk_buff *skb)
{
	int length = skb->len;

	if (likely(cxgbi_skcb_test_flag(skb, SKCBF_TX_NEED_HDR)))
		length += sizeof(struct fw_ofld_tx_data_wr);

#ifdef CXGBI_T10DIF_SUPPORT
	if (cxgbi_skcb_test_flag((struct sk_buff *)skb, SKCBF_TX_PI))
		length += sizeof(struct fw_tx_pi_header);
#endif

	if  (likely(cxgbi_skcb_test_flag((struct sk_buff *)skb, SKCBF_TX_ISO)))
		length += sizeof(struct cpl_tx_data_iso);

	return length <= MAX_IMM_TX_PKT_LEN;
}

static void best_mtu(struct cxgbi_sock *csk, const unsigned short *mtus,
			unsigned short mtu, unsigned int *idx, int ts)
{
	unsigned short hdr_size = sizeof(struct tcphdr) + (ts ? 12 : 0);
	unsigned short data_size = mtu;

	/* no tcp options */
	if (csk->csk_family == AF_INET)
		hdr_size += sizeof(struct iphdr);
	else
		hdr_size += sizeof(struct ipv6hdr);

	data_size -= hdr_size;

	cxgb4_best_aligned_mtu(mtus, hdr_size, data_size, 8, idx);

	log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_SOCK,
		"csk 0x%p,%u, mtu %u->%d.\n", csk, csk->tid, mtu, *idx);
}

static void send_act_open_req(struct cxgbi_sock *csk, struct sk_buff *skb,
				struct l2t_entry *e)
{
	struct cxgb4_lld_info *lldi = cxgbi_cdev_priv(csk->cdev);
	struct net_device *ndev = csk->cdev->ports[csk->port_id];
	int t4 = is_t4(lldi->adapter_type);
	int wscale = cxgbi_sock_compute_wscale(csk->rcv_win);
	unsigned long long opt0;
	unsigned int opt2;
	unsigned int qid_atid = ((unsigned int)csk->atid) |
				 (((unsigned int)csk->rss_qid) << 14);

	opt0 = KEEP_ALIVE(1) |
		(nocong ? F_NO_CONG : 0) |
		WND_SCALE(wscale) |
		MSS_IDX(csk->mss_idx) |
		L2T_IDX(((struct l2t_entry *)csk->l2t)->idx) |
		TX_CHAN(csk->tx_chan) |
		SMAC_SEL(csk->smac_idx) |
		ULP_MODE(ULP_MODE_ISCSI) |
		RCV_BUFSIZ(min(csk->rcv_win >> 10, RCV_BUFSIZ_MASK));

	opt2 =  F_WND_SCALE_EN | RX_CHANNEL(0) |
		V_CCTRL_ECN(enable_ecn) |
		RSS_QUEUE_VALID |
		RSS_QUEUE(csk->rss_qid) |
		V_TX_QUEUE(lldi->tx_modq[csk->tx_chan]);

	if (enable_tcp_tmstamps)
		opt2 |= F_TSTAMPS_EN;
	if (enable_tcp_sack)
		opt2 |= F_SACK_EN;

	switch (CHELSIO_CHIP_VERSION(lldi->adapter_type)) {
	case CHELSIO_T4: {
		struct cpl_act_open_req *req = 
				(struct cpl_act_open_req *)skb->head;

		INIT_TP_WR(req, 0);
		OPCODE_TID(req) = cpu_to_be32(MK_OPCODE_TID(CPL_ACT_OPEN_REQ,
					qid_atid));
		req->local_port = csk->saddr.sin_port;
		req->peer_port = csk->daddr.sin_port;
		req->local_ip = csk->saddr.sin_addr.s_addr;
		req->peer_ip = csk->daddr.sin_addr.s_addr;
		req->opt0 = cpu_to_be64(opt0);

		opt2 |= F_RX_FC_VALID;
		req->opt2 = cpu_to_be32(opt2);

		req->params = cpu_to_be32(cxgb4_select_ntuple(ndev, csk->l2t));
		}
		break;
	case CHELSIO_T5: {
		struct cpl_t5_act_open_req *req = 
				(struct cpl_t5_act_open_req *)skb->head;
		u32 isn = (prandom_u32() & ~7UL) - 1;

		INIT_TP_WR(req, 0);
		OPCODE_TID(req) = cpu_to_be32(MK_OPCODE_TID(CPL_ACT_OPEN_REQ,
					qid_atid));
		req->local_port = csk->saddr.sin_port;
		req->peer_port = csk->daddr.sin_port;
		req->local_ip = csk->saddr.sin_addr.s_addr;
		req->peer_ip = csk->daddr.sin_addr.s_addr;
		req->opt0 = cpu_to_be64(opt0);

		req->rsvd = cpu_to_be32(isn);
		opt2 |= F_T5_ISS;	
		opt2 |= F_T5_OPT_2_VALID;
		req->opt2 = cpu_to_be32(opt2);

		req->params = cpu_to_be64(V_FILTER_TUPLE(cxgb4_select_ntuple(
							ndev, csk->l2t)));
		 }
		break;
	case CHELSIO_T6:
	default: {
		struct cpl_t6_act_open_req *req = 
				(struct cpl_t6_act_open_req *)skb->head;
		u32 isn = (prandom_u32() & ~7UL) - 1;

		INIT_TP_WR(req, 0);
		OPCODE_TID(req) = cpu_to_be32(MK_OPCODE_TID(CPL_ACT_OPEN_REQ,
					qid_atid));
		req->local_port = csk->saddr.sin_port;
		req->peer_port = csk->daddr.sin_port;
		req->local_ip = csk->saddr.sin_addr.s_addr;
		req->peer_ip = csk->daddr.sin_addr.s_addr;
		req->opt0 = cpu_to_be64(opt0);

		req->rsvd = cpu_to_be32(isn);
		opt2 |= F_T5_ISS | F_RX_FC_DISABLE;
		opt2 |= F_T5_OPT_2_VALID;
		req->opt2 = cpu_to_be32(opt2);

		req->params = cpu_to_be64(V_FILTER_TUPLE(cxgb4_select_ntuple(
							ndev, csk->l2t)));
		 }
		break;
	}

	set_wr_txq(skb, CPL_PRIORITY_SETUP, csk->port_id);

	pr_info_ipaddr("t%d csk 0x%p,%u,0x%lx,%u, rss_qid %u.\n",
		(&csk->saddr),
		(&csk->daddr),
		t4 ? 4 : 5, csk, csk->state, csk->flags, csk->atid, csk->rss_qid);

#if (defined SLES10SP3) || (defined SLES11SP0) || (defined RHEL5SP3) 
	cxgb4_l2t_send(ndev, skb, csk->l2t);
#else
	cxgb4_l2t_send(ndev, skb, csk->l2t, NULL, NULL);
#endif
}

static void send_act_open_req6(struct cxgbi_sock *csk, struct sk_buff *skb,
				struct l2t_entry *e)
{
	struct cxgb4_lld_info *lldi = cxgbi_cdev_priv(csk->cdev);
	struct net_device *ndev = csk->cdev->ports[csk->port_id];
	int t4 = is_t4(lldi->adapter_type);
	int wscale = cxgbi_sock_compute_wscale(csk->rcv_win);
	unsigned long long opt0;
	unsigned int opt2;
	unsigned int qid_atid = ((unsigned int)csk->atid) |
				 (((unsigned int)csk->rss_qid) << 14);

	opt0 = KEEP_ALIVE(1) |
		WND_SCALE(wscale) |
		MSS_IDX(csk->mss_idx) |
		L2T_IDX(((struct l2t_entry *)csk->l2t)->idx) |
		TX_CHAN(csk->tx_chan) |
		SMAC_SEL(csk->smac_idx) |
		ULP_MODE(ULP_MODE_ISCSI) |
		RCV_BUFSIZ(min(csk->rcv_win >> 10, RCV_BUFSIZ_MASK));

	opt2 =  F_WND_SCALE_EN | RX_CHANNEL(0) |
		RSS_QUEUE_VALID |
		RSS_QUEUE(csk->rss_qid) |
		V_TX_QUEUE(lldi->tx_modq[csk->tx_chan]);

	switch (CHELSIO_CHIP_VERSION(lldi->adapter_type)) {
	case CHELSIO_T4: {
		struct cpl_act_open_req6 *req = 
				(struct cpl_act_open_req6 *)skb->head;

		INIT_TP_WR(req, 0);
		OPCODE_TID(req) = cpu_to_be32(MK_OPCODE_TID(CPL_ACT_OPEN_REQ6,
					qid_atid));
		req->local_port = csk->saddr6.sin6_port;
		req->peer_port = csk->daddr6.sin6_port;

		req->local_ip_hi = *(__be64 *)(csk->saddr6.sin6_addr.s6_addr);
		req->local_ip_lo = *(__be64 *)(csk->saddr6.sin6_addr.s6_addr +
									8);
		req->peer_ip_hi = *(__be64 *)(csk->daddr6.sin6_addr.s6_addr);
		req->peer_ip_lo = *(__be64 *)(csk->daddr6.sin6_addr.s6_addr +
									8);

		req->opt0 = cpu_to_be64(opt0);

		opt2 |= F_RX_FC_VALID;
		req->opt2 = cpu_to_be32(opt2);

		req->params = cpu_to_be32(cxgb4_select_ntuple(ndev, csk->l2t));
		 }
		break;
	case CHELSIO_T5: {	
		struct cpl_t5_act_open_req6 *req = 
				(struct cpl_t5_act_open_req6 *)skb->head;

		INIT_TP_WR(req, 0);
		OPCODE_TID(req) = cpu_to_be32(MK_OPCODE_TID(CPL_ACT_OPEN_REQ6,
					qid_atid));
		req->local_port = csk->saddr6.sin6_port;
		req->peer_port = csk->daddr6.sin6_port;
		req->local_ip_hi = *(__be64 *)(csk->saddr6.sin6_addr.s6_addr);
		req->local_ip_lo = *(__be64 *)(csk->saddr6.sin6_addr.s6_addr +
									8);
		req->peer_ip_hi = *(__be64 *)(csk->daddr6.sin6_addr.s6_addr);
		req->peer_ip_lo = *(__be64 *)(csk->daddr6.sin6_addr.s6_addr +
									8);
		req->opt0 = cpu_to_be64(opt0);

		opt2 |= F_T5_OPT_2_VALID;
		req->opt2 = cpu_to_be32(opt2);

		req->params = cpu_to_be64(V_FILTER_TUPLE(cxgb4_select_ntuple(
							ndev, csk->l2t)));
		 }
		break;
	case CHELSIO_T6:
	default: {
		struct cpl_t6_act_open_req6 *req = 
				(struct cpl_t6_act_open_req6 *)skb->head;

		INIT_TP_WR(req, 0);
		OPCODE_TID(req) = cpu_to_be32(MK_OPCODE_TID(CPL_ACT_OPEN_REQ6,
					qid_atid));
		req->local_port = csk->saddr6.sin6_port;
		req->peer_port = csk->daddr6.sin6_port;
		req->local_ip_hi = *(__be64 *)(csk->saddr6.sin6_addr.s6_addr);
		req->local_ip_lo = *(__be64 *)(csk->saddr6.sin6_addr.s6_addr +
									8);
		req->peer_ip_hi = *(__be64 *)(csk->daddr6.sin6_addr.s6_addr);
		req->peer_ip_lo = *(__be64 *)(csk->daddr6.sin6_addr.s6_addr +
									8);
		req->opt0 = cpu_to_be64(opt0);

		opt2 |= F_T5_OPT_2_VALID;
		req->opt2 = cpu_to_be32(opt2);

		req->params = cpu_to_be64(V_FILTER_TUPLE(cxgb4_select_ntuple(
							ndev, csk->l2t)));
		 }
		break;
	}

	set_wr_txq(skb, CPL_PRIORITY_SETUP, csk->port_id);

	pr_info("t%d csk 0x%p,%u,0x%lx,%u, [%pI6]:%u-[%pI6]:%u, rss_qid %u.\n",
		t4 ? 4 : 5, csk, csk->state, csk->flags, csk->atid,
		&csk->saddr6.sin6_addr, ntohs(csk->saddr.sin_port),
		&csk->daddr6.sin6_addr, ntohs(csk->daddr.sin_port),
		csk->rss_qid);
#if (defined SLES10SP3) || (defined SLES11SP0) || (defined RHEL5SP3) 
	cxgb4_l2t_send(ndev, skb, csk->l2t);
#else
	cxgb4_l2t_send(ndev, skb, csk->l2t, &csk->saddr6.sin6_addr,
			csk->dst);
#endif
}

static void send_close_req(struct cxgbi_sock *csk)
{
	struct sk_buff *skb = csk->cpl_close;
	struct cpl_close_con_req *req = (struct cpl_close_con_req *)skb->head;
	unsigned int tid = csk->tid;

	pr_info("csk 0x%p,%u,0x%lx, tid %u.\n",
		csk, csk->state, csk->flags, csk->tid);
	csk->cpl_close = NULL;
	INIT_TP_WR(req, tid);
	OPCODE_TID(req) = cpu_to_be32(MK_OPCODE_TID(CPL_CLOSE_CON_REQ, tid));
	req->rsvd = 0;

	cxgbi_skcb_clear_flag(skb, SKCBF_TX_NEED_HDR);
	skb_reset_transport_header(skb);
	cxgbi_sock_skb_entail(csk, skb);
	if (csk->state >= CTP_ESTABLISHED)
		push_tx_frames(csk, 1);
}

static void abort_arp_failure(void *handle, struct sk_buff *skb)
{
	struct cxgbi_sock *csk = (struct cxgbi_sock *)handle;
	struct cpl_abort_req *req;

	pr_info("csk 0x%p,%u,0x%lx, tid %u, abort.\n",
		csk, csk->state, csk->flags, csk->tid);
	req = (struct cpl_abort_req *)skb->data;
	req->cmd = CPL_ABORT_NO_RST;
	cxgb4_ofld_send(csk->cdev->ports[csk->port_id], skb);
}

static void send_abort_req(struct cxgbi_sock *csk)
{
	struct cpl_abort_req *req;
	struct sk_buff *skb = csk->cpl_abort_req;

	if (unlikely(csk->state == CTP_ABORTING) || !skb || !csk->cdev)
		return;
	if (!cxgbi_sock_flag(csk, CTPF_TX_DATA_SENT)) {
                send_tx_flowc_wr(csk, 0);
                cxgbi_sock_set_flag(csk, CTPF_TX_DATA_SENT);
        }
	cxgbi_sock_set_state(csk, CTP_ABORTING);
	cxgbi_sock_set_flag(csk, CTPF_ABORT_RPL_PENDING);
	cxgbi_sock_purge_write_queue(csk);

	csk->cpl_abort_req = NULL;
	req = (struct cpl_abort_req *)skb->head;
	set_wr_txq(skb, CPL_PRIORITY_DATA, csk->port_id);
	req->cmd = CPL_ABORT_SEND_RST;
	t4_set_arp_err_handler(skb, csk, abort_arp_failure);
	INIT_TP_WR(req, csk->tid);
	OPCODE_TID(req) = cpu_to_be32(MK_OPCODE_TID(CPL_ABORT_REQ, csk->tid));
	req->rsvd0 = htonl(csk->snd_nxt);
	req->rsvd1 = !cxgbi_sock_flag(csk, CTPF_TX_DATA_SENT);

	pr_info("csk 0x%p,%u,0x%lx,%u, snd_nxt %u, 0x%x.\n",
		csk, csk->state, csk->flags, csk->tid, csk->snd_nxt,
		req->rsvd1);

#if (defined SLES10SP3) || (defined SLES11SP0) || (defined RHEL5SP3) 
	cxgb4_l2t_send(csk->cdev->ports[csk->port_id], skb, csk->l2t);
#else
	if (csk->csk_family == AF_INET)
		cxgb4_l2t_send(csk->cdev->ports[csk->port_id], skb, csk->l2t,
				 NULL, NULL);
	else
		cxgb4_l2t_send(csk->cdev->ports[csk->port_id], skb, csk->l2t,
				&csk->saddr6.sin6_addr, csk->dst);
#endif
}

static void send_abort_rpl(struct cxgbi_sock *csk, int rst_status)
{
	struct sk_buff *skb = csk->cpl_abort_rpl;
	struct cpl_abort_rpl *rpl = (struct cpl_abort_rpl *)skb->head;

	pr_info("csk 0x%p,%u,0x%lx,%u, status %d.\n",
		csk, csk->state, csk->flags, csk->tid, rst_status);

	csk->cpl_abort_rpl = NULL;
	set_wr_txq(skb, CPL_PRIORITY_DATA, csk->port_id);
	INIT_TP_WR(rpl, csk->tid);
	OPCODE_TID(rpl) = cpu_to_be32(MK_OPCODE_TID(CPL_ABORT_RPL, csk->tid));
	rpl->cmd = rst_status;
	cxgb4_ofld_send(csk->cdev->ports[csk->port_id], skb);
}

/*
 * CPL connection rx data ack: host ->
 * Send RX credits through an RX_DATA_ACK CPL message. Returns the number of
 * credits sent.
 */
static u32 send_rx_credits(struct cxgbi_sock *csk, u32 credits)
{
	struct sk_buff *skb;
	struct cpl_rx_data_ack *req;
	u32 dack;

	if (cxgbi_sock_flag(csk, CTPF_PEER_ULP))
		dack = RX_DACK_CHANGE(1) | RX_DACK_MODE(0);
	else
		dack = RX_DACK_CHANGE(1) | RX_DACK_MODE(dack_mode);

	log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_PDU_RX,
		"csk 0x%p,%u,0x%lx,%u, credit %u.\n",
		csk, csk->state, csk->flags, csk->tid, credits);

	skb = alloc_wr(sizeof(*req), 0, GFP_ATOMIC);
	if (!skb) {
		pr_info("csk 0x%p, credit %u, OOM.\n", csk, credits);
		return 0;
	}
	req = (struct cpl_rx_data_ack *)skb->head;

	set_wr_txq(skb, CPL_PRIORITY_ACK, csk->port_id);
	INIT_TP_WR(req, csk->tid);
	OPCODE_TID(req) = cpu_to_be32(MK_OPCODE_TID(CPL_RX_DATA_ACK,
				      csk->tid));
	req->credit_dack = cpu_to_be32(RX_CREDITS(credits) | dack);
	cxgb4_ofld_send(csk->cdev->ports[csk->port_id], skb);
	return credits;
}

/*
 * sgl_len - calculates the size of an SGL of the given capacity
 * @n: the number of SGL entries
 * Calculates the number of flits needed for a scatter/gather list that
 * can hold the given number of entries.
 */
static inline unsigned int sgl_len(unsigned int n)
{
	n--;
	return (3 * n) / 2 + (n & 1) + 2;
}

/*
 * calc_tx_flits_ofld - calculate # of flits for an offload packet
 * @skb: the packet
 *
 * Returns the number of flits needed for the given offload packet.
 * These packets are already fully constructed and no additional headers
 * will be added.
 */
static inline unsigned int calc_tx_flits_ofld(const struct sk_buff *skb)
{
	unsigned int flits, cnt;

	if (is_ofld_imm(skb))
		return DIV_ROUND_UP(skb->len, 8);
	flits = skb_transport_offset(skb) / 8;
	cnt = skb_shinfo(skb)->nr_frags;
	if (skb_tail_pointer(skb) != skb_transport_header(skb))
		cnt++;
	return flits + sgl_len(cnt);
}

static inline int tx_flowc_wr_credits(int *nparamsp, int *flowclenp)
{
	int nparams, flowclen16, flowclen;

	nparams = 10;
#if defined __CXGB4TOE__ && defined __CONFIG_CXGB4_DCB__
	nparams++;
#endif

	flowclen = offsetof(struct fw_flowc_wr, mnemval[nparams]);
	flowclen16 = DIV_ROUND_UP(flowclen, 16);
	flowclen = flowclen16 * 16;

	/*
	 * Return the number of 16-byte credits used by the FlowC request.
	 * Pass back the nparams and actual FlowC length if requested.
	 */
	if (nparamsp)
		*nparamsp = nparams;
	if (flowclenp)
		*flowclenp = flowclen;

	return flowclen16;
}

static int send_tx_flowc_wr(struct cxgbi_sock *csk, int compl)
{
	struct sk_buff *skb;
	struct fw_flowc_wr *flowc;
	int nparams, flowclen16, flowclen;
#if defined __CXGB4TOE__ && defined __CONFIG_CXGB4_DCB__
	u16 vlan = ((struct l2t_entry *)csk->l2t)->vlan;
#endif

	flowclen16 = tx_flowc_wr_credits(&nparams, &flowclen);

	skb = alloc_wr(flowclen, 0, GFP_ATOMIC);
	flowc = (struct fw_flowc_wr *)skb->head;

	flowc->op_to_nparams =
		htonl(FW_WR_OP(FW_FLOWC_WR) | FW_FLOWC_WR_NPARAMS(nparams));
	flowc->flowid_len16 =
		htonl(FW_WR_LEN16(flowclen16) | FW_WR_FLOWID(csk->tid));
	flowc->mnemval[0].mnemonic = FW_FLOWC_MNEM_PFNVFN;
#ifdef __CXGB4TOE__
	flowc->mnemval[0].val = cpu_to_be32(csk->cdev->pfvf);
#else
	flowc->mnemval[0].val = cpu_to_be32(0);
#endif
	flowc->mnemval[1].mnemonic = FW_FLOWC_MNEM_CH;
	flowc->mnemval[1].val = cpu_to_be32(csk->tx_chan);
	flowc->mnemval[2].mnemonic = FW_FLOWC_MNEM_PORT;
	flowc->mnemval[2].val = cpu_to_be32(csk->tx_chan);
	flowc->mnemval[3].mnemonic = FW_FLOWC_MNEM_IQID;
	flowc->mnemval[3].val = cpu_to_be32(csk->rss_qid);
	flowc->mnemval[4].mnemonic = FW_FLOWC_MNEM_SNDNXT;
	flowc->mnemval[4].val = cpu_to_be32(csk->snd_nxt);
	flowc->mnemval[5].mnemonic = FW_FLOWC_MNEM_RCVNXT;
	flowc->mnemval[5].val = cpu_to_be32(csk->rcv_nxt);
	flowc->mnemval[6].mnemonic = FW_FLOWC_MNEM_SNDBUF;
	flowc->mnemval[6].val = cpu_to_be32(csk->snd_win);
	flowc->mnemval[7].mnemonic = FW_FLOWC_MNEM_MSS;
	flowc->mnemval[7].val = cpu_to_be32(csk->advmss);
	flowc->mnemval[8].mnemonic = FW_FLOWC_MNEM_TXDATAPLEN_MAX;
	if (csk->cdev->skb_iso_txhdr)
		flowc->mnemval[8].val = cpu_to_be32(CXGBI_MAX_ISO_DATA_IN_SKB);
	else
		flowc->mnemval[8].val = cpu_to_be32(16384);
	flowc->mnemval[9].mnemonic = FW_FLOWC_MNEM_RCV_SCALE;
	flowc->mnemval[9].val = cpu_to_be32(csk->snd_wscale);
#if defined __CXGB4TOE__ && defined __CONFIG_CXGB4_DCB__
        flowc->mnemval[10].mnemonic = FW_FLOWC_MNEM_DCBPRIO;
        if (vlan == CPL_L2T_VLAN_NONE) {
                if (printk_ratelimit())
			pr_warn("csk %u without VLAN Tag on DCB Link\n",
				csk->tid);
		flowc->mnemval[10].val = cpu_to_be32(0);
	} else
		flowc->mnemval[10].val = cpu_to_be32((vlan & VLAN_PRIO_MASK) >>
					VLAN_PRIO_SHIFT);
#endif

	set_wr_txq(skb, CPL_PRIORITY_DATA, csk->port_id);

	log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_SOCK,
		"csk 0x%p, tid 0x%x, %u,%u,%u,%u,%u,%u,%u.\n",
		csk, csk->tid, 0, csk->tx_chan, csk->rss_qid,
		csk->snd_nxt, csk->rcv_nxt, csk->snd_win,
		csk->advmss);

	cxgb4_ofld_send(csk->cdev->ports[csk->port_id], skb);

	return flowclen16;
}

#ifdef CXGBI_T10DIF_SUPPORT
static inline int get_tx_pi_control_bits(unsigned char prot_op,
		unsigned int *pi_inline, unsigned int *pi_validate,
		unsigned int *pi_control)
{
	unsigned int err = 0;

	/* based on ulptx t10dif control table */
	*pi_inline = 0;

	switch(prot_op) {
	case SCSI_PROT_WRITE_INSERT:
		*pi_validate = 0; *pi_control = 2;
		break;
	case SCSI_PROT_WRITE_PASS:
		*pi_validate = 1; *pi_control = 2;
		break;
	case SCSI_PROT_WRITE_STRIP:
		*pi_validate = 1; *pi_control = 0;
		break;
	default:
		err = -1;
	}

	return err;
}
static inline int get_pi_guard_type(int guard)
{
	unsigned int type = 0;

	if (guard == SHOST_DIX_GUARD_IP)
		type = 0;
	else if (guard == SHOST_DIX_GUARD_CRC)
		type = 1;
	return type;
}

static inline int get_dif_type(int dif)
{
	int type = 0;

	if (dif == SCSI_PROT_DIF_TYPE1)
		type = 1;
	else if (dif == SCSI_PROT_DIF_TYPE2)
		type = 2;
	if (dif == SCSI_PROT_DIF_TYPE3)
		type = 3;

	return type;
}

/* based on tag generation table in ulptx document */
static inline int get_tag_gen_ctrl(int prot_op, int dif)
{
	int tag_gen = 0;

	/* app tag and ref tag are part of the pi data in WRITE_PASS and
 	 * WRITE_STRIP cases and h/w doesn't need to touch them */
	if ((prot_op == SCSI_PROT_WRITE_INSERT) &&
		(dif == SCSI_PROT_DIF_TYPE1 || dif == SCSI_PROT_DIF_TYPE2))
			tag_gen = 3;

	return tag_gen;
}

static inline void make_tx_pi_header(struct sk_buff *skb,
						struct fw_tx_pi_header *pi_hdr)
{
	unsigned char prot_op = cxgbi_skcb_tx_prot_op(skb);
	unsigned int pi_inline = 0, pi_validate = 0, pi_control = 0;
	unsigned int guard_type, dif_type;
	unsigned int pi_len, pi_start4, pi_end4;
	unsigned int num_pi, sector_shift = 9; /* 512B sector */
	int tag_gen;
	int isohdr_len = 0;

	if (get_tx_pi_control_bits(prot_op, &pi_inline, &pi_validate,
				&pi_control))
		return;

	guard_type = get_pi_guard_type(cxgbi_skcb_tx_guard_type(skb));

	dif_type = get_dif_type(cxgbi_skcb_tx_dif_type(skb));
	if (prot_op == SCSI_PROT_WRITE_STRIP)
		dif_type = 1; /* Type 1 DIX */
	pi_len = cxgbi_skcb_tx_pi_len(skb);
	num_pi = pi_len>>3;
	if (cxgbi_skcb_tx_pi_interval(skb) == ISCSI_SCSI_PI_INTERVAL_4K)
		sector_shift = 12;

	/* exclude iso hdr from pi processing */
	if (cxgbi_skcb_test_flag(skb, SKCBF_TX_ISO))
		isohdr_len = sizeof(struct cpl_tx_data_iso);

	pi_start4 = (sizeof(struct cpl_tx_data) + isohdr_len +
			cxgbi_skcb_tx_iscsi_hdrlen(skb))>>2;
	pi_end4 = (sizeof(struct cpl_tx_data) + isohdr_len +
			cxgbi_skcb_tx_iscsi_hdrlen(skb) +
			(num_pi<<sector_shift))>>2;

	pi_hdr->op_to_inline = htons(FW_TX_PI_HEADER_PI_OP(ULP_TX_SC_PICTRL) |
				FW_TX_PI_HEADER_PI_ULPTXMORE |
				FW_TX_PI_HEADER_PI_CONTROL(pi_control) |
				FW_TX_PI_HEADER_GUARD_TYPE(guard_type) |
				FW_TX_PI_HEADER_VALIDATE(pi_validate) |
				FW_TX_PI_HEADER_INLINE(pi_inline));

	pi_hdr->pi_interval_tag_type = FW_TX_PI_HEADER_PI_INTERVAL(\
					cxgbi_skcb_tx_pi_interval(skb)) |
					FW_TX_PI_HEADER_TAG_TYPE(dif_type);
	pi_hdr->num_pi = num_pi;
	pi_hdr->pi_start4_pi_end4  = cpu_to_be32(
			FW_TX_PI_HEADER_PI_START4(pi_start4) |
			FW_TX_PI_HEADER_PI_END4(pi_end4));
	tag_gen = get_tag_gen_ctrl(prot_op, cxgbi_skcb_tx_dif_type(skb));

	pi_hdr->tag_gen_enabled_pkd =  FW_TX_PI_HEADER_TAG_GEN_ENABLED(tag_gen); 
	pi_hdr->num_pi_dsg = cxgbi_skcb_tx_pi_sgcnt(skb);
	pi_hdr->app_tag = htons(cxgbi_skcb_tx_pi_app_tag(skb));
	pi_hdr->ref_tag = cpu_to_be32(cxgbi_skcb_tx_pi_ref_tag(skb));
}
#endif

static inline void make_tx_iso_cpl(struct sk_buff *skb,
			struct cpl_tx_data_iso *cpl)
{
	struct cxgbi_iso_info *info = (struct cxgbi_iso_info *)skb->head;
	unsigned int submode = cxgbi_skcb_ulp_mode(skb) & 3;
	unsigned int pdu_type = (info->op == ISCSI_OP_SCSI_CMD) ? 0 : 1;
	unsigned int fslice = !!(info->flags & CXGBI_ISO_INFO_FSLICE),
			 lslice = !!(info->flags & CXGBI_ISO_INFO_LSLICE),
			 imm_en = !!(info->flags & CXGBI_ISO_INFO_IMM_ENABLE);

	cpl->op_to_scsi = htonl(V_CPL_TX_DATA_ISO_OP(CPL_TX_DATA_ISO) |
			V_CPL_TX_DATA_ISO_FIRST(fslice) |
			V_CPL_TX_DATA_ISO_LAST(lslice) |
			V_CPL_TX_DATA_ISO_CPLHDRLEN(0) | /* cpl_tx_data len
							    is 16B */
			V_CPL_TX_DATA_ISO_HDRCRC(submode & 1) |
			V_CPL_TX_DATA_ISO_PLDCRC(((submode >> 1) & 1)) |
			V_CPL_TX_DATA_ISO_IMMEDIATE(imm_en) |
			V_CPL_TX_DATA_ISO_SCSI(pdu_type));

	cpl->ahs_len = info->ahs;
	cpl->mpdu = htons(DIV_ROUND_UP(info->mpdu, 4));
	cpl->burst_size = htonl(info->burst_size);
	cpl->len = htonl(info->len);
	cpl->reserved2_seglen_offset =
			htonl(V_CPL_TX_DATA_ISO_SEGLEN_OFFSET(
						info->segment_offset));
	cpl->datasn_offset = htonl(info->datasn_offset);
	cpl->buffer_offset = htonl(info->buffer_offset);
	cpl->reserved3 = 0;
	log_debug(1 << CXGBI_DBG_ISCSI | 1 << CXGBI_DBG_PDU_TX,
		"iso: flags 0x%x, op %u, ahs %u, num_pdu %u, mpdu %u, "
		"burst_size %u, iso_len %u\n",
		info->flags, info->op, info->ahs, info->num_pdu,
		info->mpdu, info->burst_size << 2, info->len);
}

static inline void make_tx_data_wr(struct cxgbi_sock *csk, struct sk_buff *skb,
				   int dlen, int len, u32 credits, int compl)
{
	struct cxgbi_device *cdev = csk->cdev;
	struct cxgb4_lld_info *lldi = cxgbi_cdev_priv(cdev);
	struct fw_ofld_tx_data_wr *req;
	struct cpl_tx_data_iso *cpl;
	unsigned int submode = cxgbi_skcb_ulp_mode(skb) & 3;
	unsigned int wr_ulp_mode = 0;
	unsigned int hdr_size = sizeof(*req);
	unsigned int opcode = FW_OFLD_TX_DATA_WR;
	unsigned int immlen = 0;
	/* Bug 26798 In T5, set FORCE bit only if digests are disabled */
	unsigned int force =
	    is_t5(lldi->adapter_type)?V_TX_FORCE(!submode):cdev->force;

#ifdef CXGBI_T10DIF_SUPPORT
	if (cxgbi_skcb_test_flag(skb, SKCBF_TX_PI)) {
		hdr_size += sizeof(struct fw_tx_pi_header);
		opcode = FW_ISCSI_TX_DATA_WR;
		immlen = sizeof(struct fw_tx_pi_header);
		submode |= 4;
	}
#endif

	if (cxgbi_skcb_test_flag(skb, SKCBF_TX_ISO)) {
		hdr_size += sizeof(struct cpl_tx_data_iso);
		opcode = FW_ISCSI_TX_DATA_WR;
		immlen += sizeof(struct cpl_tx_data_iso);
		submode |= 8;
	}

	if (is_ofld_imm(skb))
		immlen += dlen;

	req = (struct fw_ofld_tx_data_wr *)__skb_push(skb,
							hdr_size);
		req->op_to_immdlen =
			cpu_to_be32(FW_WR_OP(opcode) |
					FW_WR_COMPL(compl) |
					FW_WR_IMMDLEN(immlen));
		req->flowid_len16 =
			cpu_to_be32(FW_WR_FLOWID(csk->tid) |
					FW_WR_LEN16(credits));
	req->plen = htonl(len);
	cpl =  (struct cpl_tx_data_iso *) (req + 1);

#ifdef CXGBI_T10DIF_SUPPORT
	if (cxgbi_skcb_test_flag(skb, SKCBF_TX_PI)) {
		make_tx_pi_header(skb, (struct fw_tx_pi_header *) (req+1));
		cpl = (struct cpl_tx_data_iso *)
				((struct fw_tx_pi_header *)(req + 1) + 1);
	}
#endif

	if (likely(cxgbi_skcb_test_flag(skb, SKCBF_TX_ISO)))
		make_tx_iso_cpl(skb, cpl);

	if (submode)
		wr_ulp_mode = FW_OFLD_TX_DATA_WR_ULPMODE(ULP2_MODE_ISCSI) |
				FW_OFLD_TX_DATA_WR_ULPSUBMODE(submode);

	req->lsodisable_to_flags = htonl((wr_ulp_mode) | force |
		 FW_OFLD_TX_DATA_WR_SHOVE(skb_peek(&csk->write_queue) ? 0 : 1));

	if (!cxgbi_sock_flag(csk, CTPF_TX_DATA_SENT))
		cxgbi_sock_set_flag(csk, CTPF_TX_DATA_SENT);

#if 0
	if (hdr_size > sizeof(*req))
		cxgbi_dump_bytes("WR", (unsigned char *)req, 0, hdr_size);
#endif
}

static void arp_failure_skb_discard(void *handle, struct sk_buff *skb)
{
	kfree_skb(skb);
}

static int push_tx_frames(struct cxgbi_sock *csk, int req_completion)
{
	int total_size = 0;
	struct sk_buff *skb;

	if (unlikely(csk->state < CTP_ESTABLISHED ||
		csk->state == CTP_CLOSE_WAIT_1 || csk->state >= CTP_ABORTING)) {
		log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_SOCK |
			 1 << CXGBI_DBG_PDU_TX,
			"csk 0x%p,%u,0x%lx,%u, in closing state.\n",
			csk, csk->state, csk->flags, csk->tid);
		return 0;
	}

	while (csk->wr_cred && (skb = skb_peek(&csk->write_queue)) != NULL &&
	       !cxgbi_sock_flag(csk, CTPF_TX_WAIT_IDLE)) {
		int dlen = skb->len;
		int len = skb->len;
		int pi_hdr = 0, iso_cpl_len = 0;
		unsigned int credits_needed;
		int flowclen16 = 0;
		int num_pdu = 1, hdr_len;
		struct cxgbi_iso_info *iso_cpl;

#if 0
		if ((skb->data[0] & 0x3F) == 0x5) {
			if (skb->data[40]) {
				pr_err("skb 0x%p, offset corrupted 0x%x?\n", skb, *(unsigned int *)(skb->data + 40));
				cxgbi_dump_bytes("bhs", skb->data, 0, 48);
			}
		}
#endif

#ifdef CXGBI_T10DIF_SUPPORT
		if (cxgbi_skcb_test_flag(skb, SKCBF_TX_PI))
			pi_hdr = sizeof(struct fw_tx_pi_header);
#endif
		if (cxgbi_skcb_test_flag(skb, SKCBF_TX_ISO))
			iso_cpl_len = sizeof(struct cpl_tx_data_iso);

		if (is_ofld_imm(skb))
			credits_needed = DIV_ROUND_UP(
					dlen + pi_hdr + iso_cpl_len, 16);
		else
			credits_needed = DIV_ROUND_UP(
					8 * calc_tx_flits_ofld(skb) +
					pi_hdr + iso_cpl_len, 16);

		if (likely(cxgbi_skcb_test_flag(skb, SKCBF_TX_NEED_HDR)))
			credits_needed += DIV_ROUND_UP(
					sizeof(struct fw_ofld_tx_data_wr),
					16);

		/*
		 * Assumes the initial credits is large enough to support
		 * fw_flowc_wr plus largest possible first payload
		 */
		if (!cxgbi_sock_flag(csk, CTPF_TX_DATA_SENT)) {
			flowclen16 = send_tx_flowc_wr(csk, 1);
			csk->wr_cred -= flowclen16;
			csk->wr_una_cred += flowclen16;
			cxgbi_sock_set_flag(csk, CTPF_TX_DATA_SENT);
		}

		if (csk->wr_cred < credits_needed) {
			log_debug(1 << CXGBI_DBG_PDU_TX,
				"csk 0x%p, skb %u/%u, wr %d < %u.\n",
				csk, skb->len, skb->data_len,
				credits_needed, csk->wr_cred);

			/* we may want to disable iso if it's enabled */
			csk->bb_tx_choke++;
			break;
		}

		/* reset the back to back tx choke counter*/
		csk->bb_tx_choke = 0;

		__skb_unlink(skb, &csk->write_queue);
		set_wr_txq(skb, CPL_PRIORITY_DATA, csk->port_id);
		skb->csum = credits_needed + flowclen16;
		csk->wr_cred -= credits_needed;
		csk->wr_una_cred += credits_needed;
		cxgbi_sock_enqueue_wr(csk, skb);

		log_debug(1 << CXGBI_DBG_PDU_TX,
			"csk 0x%p, skb %u/%u, wr %d, left %u, unack %u.\n",
			csk, skb->len, skb->data_len, credits_needed,
			csk->wr_cred, csk->wr_una_cred);

		/* set completion if requested or if we spill over threshold */
		if (!req_completion &&
		    ((csk->wr_una_cred >= (csk->wr_max_cred/2)) ||
		     after(csk->write_seq, (csk->snd_una + csk->snd_win/2))))
			req_completion = 1;

		if (likely(cxgbi_skcb_test_flag(skb, SKCBF_TX_NEED_HDR))) {
#ifdef CXGBI_T10DIF_SUPPORT
			len += cxgbi_skb_tx_pi_len_correction(skb);
#endif
			if (likely(cxgbi_skcb_test_flag(skb, SKCBF_TX_ISO))) {
				iso_cpl = (struct cxgbi_iso_info *) skb->head;
				num_pdu = iso_cpl->num_pdu;
				hdr_len = cxgbi_skcb_tx_iscsi_hdrlen(skb);
				len += cxgbi_ulp_extra_len(
					cxgbi_skcb_ulp_mode(skb)) * num_pdu +
					hdr_len * (num_pdu - 1);
			} else {
				len += cxgbi_ulp_extra_len(
					cxgbi_skcb_ulp_mode(skb));
			}
			make_tx_data_wr(csk, skb, dlen, len, credits_needed,
					req_completion);
			csk->snd_nxt += len;
			cxgbi_skcb_clear_flag(skb, SKCBF_TX_NEED_HDR);
#if 0
			if (num_pdu > 1)
                		print_hex_dump(KERN_CONT, "ISOWR: ",
					DUMP_PREFIX_OFFSET, 16, 1,
                			skb->data, 48, false);
#endif
		} else if (cxgbi_skcb_test_flag(skb, SKCBF_TX_FLAG_COMPL) &&
			   (csk->wr_una_cred >= csk->wr_max_cred/2)) {
			struct cpl_close_con_req *req =
				(struct cpl_close_con_req *) skb->data;
			req->wr.wr_hi |= htonl(F_FW_WR_COMPL);
		}
		total_size += skb->truesize;
		t4_set_arp_err_handler(skb, csk, arp_failure_skb_discard);

		log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_PDU_TX,
			"csk 0x%p,%u,0x%lx,%u, skb 0x%p, %u.\n",
			csk, csk->state, csk->flags, csk->tid, skb, len);

#if (defined SLES10SP3) || (defined SLES11SP0) || (defined RHEL5SP3) 
		cxgb4_l2t_send(csk->cdev->ports[csk->port_id], skb, csk->l2t);
#else
		if (csk->csk_family == AF_INET)
			cxgb4_l2t_send(csk->cdev->ports[csk->port_id], skb,
					csk->l2t, NULL, NULL);
		else
			cxgb4_l2t_send(csk->cdev->ports[csk->port_id], skb,
					csk->l2t, &csk->saddr6.sin6_addr,
					csk->dst);
#endif
	}
	return total_size;
}

static inline void free_atid(struct cxgbi_sock *csk)
{
	struct cxgb4_lld_info *lldi = cxgbi_cdev_priv(csk->cdev);

	if (cxgbi_sock_flag(csk, CTPF_HAS_ATID)) {
		cxgb4_free_atid(lldi->tids, csk->atid);
		cxgbi_sock_clear_flag(csk, CTPF_HAS_ATID);
		cxgbi_sock_put(csk);
	}
}

static void do_act_establish(struct cxgbi_device *cdev, struct sk_buff *skb)
{
	struct cxgbi_sock *csk;
	struct cpl_act_establish *req = (struct cpl_act_establish *)skb->data;
	unsigned short tcp_opt = ntohs(req->tcp_opt);
	unsigned int tid = GET_TID(req);
	unsigned int atid = GET_TID_TID(ntohl(req->tos_atid));
	struct cxgb4_lld_info *lldi = cxgbi_cdev_priv(cdev);
	struct tid_info *t = lldi->tids;
	u32 rcv_isn = be32_to_cpu(req->rcv_isn);

	csk = lookup_atid(t, atid);
	if (unlikely(!csk)) {
		pr_err("NO conn. for atid %u, cdev 0x%p.\n", atid, cdev);
		goto rel_skb;
	}

	if (csk->atid != atid) {
		pr_err("BAD conn. for atid %u, csk 0x%p,%u,0x%lx,tid %u/%u.\n",
			atid, csk, csk->state, csk->flags, csk->tid, csk->atid);
		goto rel_skb;
	}

	pr_info_ipaddr("atid 0x%x, tid 0x%x, csk 0x%p,%u,0x%lx, isn %u.\n",
		(&csk->saddr),
		(&csk->daddr),
		atid, tid, csk, csk->state, csk->flags, rcv_isn);

	module_put(THIS_MODULE);

	cxgbi_sock_get(csk);
	csk->tid = tid;
	cxgb4_insert_tid(lldi->tids, csk, tid, csk->csk_family);
	cxgbi_sock_set_flag(csk, CTPF_HAS_TID);

	free_atid(csk);

	spin_lock_bh(&csk->lock);
	if (unlikely(csk->state != CTP_ACTIVE_OPEN))
		pr_info("csk 0x%p,%u,0x%lx,%u, got EST.\n",
			csk, csk->state, csk->flags, csk->tid);

	if (csk->retry_timer.function) {
		del_timer(&csk->retry_timer);
		csk->retry_timer.function = NULL;
	}

	csk->copied_seq = csk->rcv_wup = csk->rcv_nxt = rcv_isn;
	/*
	 * Causes the first RX_DATA_ACK to supply any Rx credits we couldn't
	 * pass through opt0.
	 */
	if (csk->rcv_win > (RCV_BUFSIZ_MASK << 10))
		csk->rcv_wup -= csk->rcv_win - (RCV_BUFSIZ_MASK << 10);

	csk->advmss = lldi->mtus[G_TCPOPT_MSS(tcp_opt)] - sizeof(struct iphdr)
			- sizeof(struct tcphdr);
	if (G_TCPOPT_TSTAMP(tcp_opt))
		csk->advmss -= 12;
	if (csk->advmss < 128)
		csk->advmss = 128;
	if (csk->advmss & 7)
		pr_warn("misaligned mtu idx %u mss %u\n",
			G_TCPOPT_MSS(tcp_opt), csk->advmss);
	csk->snd_wscale = G_TCPOPT_SND_WSCALE(tcp_opt);

	log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_SOCK,
		"csk 0x%p, mss_idx %u, advmss %u.\n",
		csk, GET_TCPOPT_MSS(tcp_opt), csk->advmss);

	cxgbi_sock_established(csk, ntohl(req->snd_isn), ntohs(req->tcp_opt));

	if (unlikely(cxgbi_sock_flag(csk, CTPF_ACTIVE_CLOSE_NEEDED)))
		send_abort_req(csk);
	else {
		if (skb_queue_len(&csk->write_queue))
			push_tx_frames(csk, 0);
		cxgbi_conn_tx_open(csk);
	}
	spin_unlock_bh(&csk->lock);

rel_skb:
	__kfree_skb(skb);
}

static int act_open_rpl_status_to_errno(int status)
{
	switch (status) {
	case CPL_ERR_CONN_RESET:
		return -ECONNREFUSED;
	case CPL_ERR_ARP_MISS:
		return -EHOSTUNREACH;
	case CPL_ERR_CONN_TIMEDOUT:
		return -ETIMEDOUT;
	case CPL_ERR_TCAM_FULL:
		return -ENOMEM;
	case CPL_ERR_CONN_EXIST:
		return -EADDRINUSE;
	default:
		return -EIO;
	}
}

static void csk_act_open_retry_timer(unsigned long data)
{
	struct sk_buff *skb;
	struct cxgbi_sock *csk = (struct cxgbi_sock *)data;
	struct cxgb4_lld_info *lldi = cxgbi_cdev_priv(csk->cdev);
	void (*send_act_open_func)(struct cxgbi_sock *, struct sk_buff *,
				   struct l2t_entry *);
	int t4 = is_t4(lldi->adapter_type), size, size6;
	

	log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_SOCK,
		"csk 0x%p,%u,0x%lx,%u.\n",
		csk, csk->state, csk->flags, csk->tid);

	cxgbi_sock_get(csk);
	spin_lock_bh(&csk->lock);

	if (t4) {
		size = sizeof(struct cpl_act_open_req);
		size6 = sizeof(struct cpl_act_open_req6);
	} else {
		size = sizeof(struct cpl_t5_act_open_req);
		size6 = sizeof(struct cpl_t5_act_open_req6);
	}

	if (csk->csk_family == AF_INET) {
		send_act_open_func = send_act_open_req;
		skb = alloc_wr(size, 0, GFP_ATOMIC);
	} else {
		send_act_open_func = send_act_open_req6;
		skb = alloc_wr(size6, 0, GFP_ATOMIC);
	}
		
	if (!skb)
		cxgbi_sock_fail_act_open(csk, -ENOMEM);
	else {
		skb->sk = (struct sock *)csk;
		t4_set_arp_err_handler(skb, csk,
					cxgbi_sock_act_open_req_arp_failure);
		send_act_open_func(csk, skb, csk->l2t);
	}

	spin_unlock_bh(&csk->lock);
	cxgbi_sock_put(csk);
}

/*
 * Returns whether an ABORT_REQ_RSS/ACT_OPEN_RPL message is a negative advice.
 */
static inline int is_neg_adv(unsigned int status)
{
        return status == CPL_ERR_RTX_NEG_ADVICE ||
               status == CPL_ERR_KEEPALV_NEG_ADVICE ||
               status == CPL_ERR_PERSIST_NEG_ADVICE;
}

static void do_act_open_rpl(struct cxgbi_device *cdev, struct sk_buff *skb)
{
	struct cxgbi_sock *csk;
	struct cpl_act_open_rpl *rpl = (struct cpl_act_open_rpl *)skb->data;
	unsigned int tid = GET_TID(rpl);
	unsigned int atid =
		GET_TID_TID(GET_AOPEN_ATID(be32_to_cpu(rpl->atid_status)));
	unsigned int status = GET_AOPEN_STATUS(be32_to_cpu(rpl->atid_status));
	struct cxgb4_lld_info *lldi = cxgbi_cdev_priv(cdev);
	struct tid_info *t = lldi->tids;

	csk = lookup_atid(t, atid);
	if (unlikely(!csk)) {
		pr_err("NO matching conn. atid %u, tid %u.\n", atid, tid);
		goto rel_skb;
	}

	pr_info_ipaddr("tid %u/%u, status %u.\n"
		"csk 0x%p,%u,0x%lx. ",
		(&csk->saddr),
		(&csk->daddr),
		atid, tid, status, csk, csk->state, csk->flags);

	if (is_neg_adv(status))
		goto rel_skb;

	module_put(THIS_MODULE);

	if (status && status != CPL_ERR_TCAM_FULL &&
	    status != CPL_ERR_CONN_EXIST &&
	    status != CPL_ERR_ARP_MISS)
		cxgb4_remove_tid(lldi->tids, csk->port_id, GET_TID(rpl),
				csk->csk_family);

	cxgbi_sock_get(csk);
	spin_lock_bh(&csk->lock);

	if (status == CPL_ERR_CONN_EXIST &&
	    csk->retry_timer.function != csk_act_open_retry_timer) {
		csk->retry_timer.function = csk_act_open_retry_timer;
		mod_timer(&csk->retry_timer, jiffies + HZ / 2);
	} else
		cxgbi_sock_fail_act_open(csk,
					act_open_rpl_status_to_errno(status));

	spin_unlock_bh(&csk->lock);
	cxgbi_sock_put(csk);
rel_skb:
	__kfree_skb(skb);
}

static void do_peer_close(struct cxgbi_device *cdev, struct sk_buff *skb)
{
	struct cxgbi_sock *csk;
	struct cpl_peer_close *req = (struct cpl_peer_close *)skb->data;
	unsigned int tid = GET_TID(req);
	struct cxgb4_lld_info *lldi = cxgbi_cdev_priv(cdev);
	struct tid_info *t = lldi->tids;

	csk = lookup_tid(t, tid);
	if (unlikely(!csk)) {
		pr_err("can't find connection for tid %u.\n", tid);
		goto rel_skb;
	}

	 pr_info_ipaddr("csk 0x%p,%u,0x%lx,%u.\n",
		(&csk->saddr),
		(&csk->daddr),
		csk, csk->state, csk->flags, csk->tid);

	cxgbi_sock_rcv_peer_close(csk);
rel_skb:
	__kfree_skb(skb);
}

static void do_close_con_rpl(struct cxgbi_device *cdev, struct sk_buff *skb)
{
	struct cxgbi_sock *csk;
	struct cpl_close_con_rpl *rpl = (struct cpl_close_con_rpl *)skb->data;
	unsigned int tid = GET_TID(rpl);
	struct cxgb4_lld_info *lldi = cxgbi_cdev_priv(cdev);
	struct tid_info *t = lldi->tids;

	csk = lookup_tid(t, tid);
	if (unlikely(!csk)) {
		pr_err("can't find connection for tid %u.\n", tid);
		goto rel_skb;
	}

	pr_info_ipaddr("csk 0x%p,%u,0x%lx,%u.\n",
		(&csk->saddr),
		(&csk->daddr),
		csk, csk->state, csk->flags, csk->tid);
		
	cxgbi_sock_rcv_close_conn_rpl(csk, ntohl(rpl->snd_nxt));
rel_skb:
	__kfree_skb(skb);
}

static int abort_status_to_errno(struct cxgbi_sock *csk, int abort_reason,
								int *need_rst)
{
	switch (abort_reason) {
	case CPL_ERR_BAD_SYN: /* fall through */
	case CPL_ERR_CONN_RESET:
		return csk->state > CTP_ESTABLISHED ?
			-EPIPE : -ECONNRESET;
	case CPL_ERR_XMIT_TIMEDOUT:
	case CPL_ERR_PERSIST_TIMEDOUT:
	case CPL_ERR_FINWAIT2_TIMEDOUT:
	case CPL_ERR_KEEPALIVE_TIMEDOUT:
		return -ETIMEDOUT;
	default:
		return -EIO;
	}
}

/*
 * Build a CPL_SET_TCB_FIELD message as payload of a ULP_TX_PKT command.
 */
static inline void mk_set_tcb_field_ulp(struct cxgbi_sock *csk,
                                struct cpl_set_tcb_field *req,
                                unsigned int word,
                                u64 mask, u64 val, u8 cookie, int no_reply)
{
        struct ulp_txpkt *txpkt = (struct ulp_txpkt *)req;
        struct ulptx_idata *sc = (struct ulptx_idata *)(txpkt + 1);

        txpkt->cmd_dest = htonl(V_ULPTX_CMD(ULP_TX_PKT) | V_ULP_TXPKT_DEST(0));
        txpkt->len = htonl(DIV_ROUND_UP(sizeof(*req), 16));
        sc->cmd_more = htonl(V_ULPTX_CMD(ULP_TX_SC_IMM));
        sc->len = htonl(sizeof(*req) - sizeof(struct work_request_hdr));
        OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_SET_TCB_FIELD, csk->tid));
        req->reply_ctrl = htons(V_NO_REPLY(no_reply) | V_REPLY_CHAN(0) |
				V_QUEUENO(csk->rss_qid));

        req->word_cookie = htons(V_WORD(word) | V_COOKIE(cookie));
        req->mask = cpu_to_be64(mask);
        req->val = cpu_to_be64(val);
        sc = (struct ulptx_idata *)(req + 1);
        sc->cmd_more = htonl(V_ULPTX_CMD(ULP_TX_SC_NOOP));
        sc->len = htonl(0);
}

static void t4_set_maxseg(struct cxgbi_sock *csk, unsigned int mss_idx)
{
        struct sk_buff *skb;
        struct work_request_hdr *wr;
        struct ulptx_idata *aligner;
        struct cpl_set_tcb_field *req;
        struct cpl_set_tcb_field *tstampreq;
        unsigned int wrlen;

	if (unlikely(csk->state == CTP_ABORTING))
		return;

        wrlen = roundup(sizeof(*wr) + 2*(sizeof(*req) + sizeof(*aligner)), 16);

	skb = alloc_wr(wrlen, 0, GFP_ATOMIC);
        if (!skb)
                return;

        set_wr_txq(skb, CPL_PRIORITY_CONTROL, csk->port_id);

        req = (struct cpl_set_tcb_field *)skb->head;
        INIT_ULPTX_WR(req, wrlen, 0, 0);

        wr = (struct work_request_hdr *)req;
        wr++;
        req = (struct cpl_set_tcb_field *)wr;

        mk_set_tcb_field_ulp(csk, req, W_TCB_T_MAXSEG,
                                          V_TCB_T_MAXSEG(M_TCB_T_MAXSEG),
                                          mss_idx, 0, 1);

        aligner = (struct ulptx_idata *)(req + 1);
        tstampreq = (struct cpl_set_tcb_field *)(aligner + 1);

        /*
         * Clear bits 29:11 of the TCB Time Stamp field to trigger an
         * immediate retransmission with the new Maximum Segment Size.
         */
        mk_set_tcb_field_ulp(csk, tstampreq, W_TCB_TIMESTAMP,
                                             V_TCB_TIMESTAMP(0x7FFFFULL << 11),
                                             0, 0, 1);

	cxgb4_ofld_send(csk->cdev->ports[csk->port_id], skb);
}

static void do_abort_req_rss(struct cxgbi_device *cdev, struct sk_buff *skb)
{
	struct cxgbi_sock *csk;
	struct cpl_abort_req_rss *req = (struct cpl_abort_req_rss *)skb->data;
	unsigned int tid = GET_TID(req);
	struct cxgb4_lld_info *lldi = cxgbi_cdev_priv(cdev);
	struct tid_info *t = lldi->tids;
	int rst_status = CPL_ABORT_NO_RST;

	csk = lookup_tid(t, tid);
	if (unlikely(!csk)) {
		pr_err("can't find connection for tid %u.\n", tid);
		goto rel_skb;
	}

	pr_info_ipaddr("csk 0x%p,%u,0x%lx,%u, status %u.\n",
		(&csk->saddr),
		(&csk->daddr),
		csk, csk->state, csk->flags, csk->tid, req->status);

        /*
         * If the Abort is really a "Negative Advice" message from TP
         * indicating that it's having problems with the connection (multiple
         * retransmissions, etc.), then let's see if something has changed
         * like the Path MTU (typically indicated via an ICMP_UNREACH
         * ICMP_FRAG_NEEDED message from an intermediate router).
         */
        if (is_neg_adv(req->status)) {
		struct cxgb4_lld_info *lldi = cxgbi_cdev_priv(csk->cdev);
		unsigned int mss_idx;

		csk->mtu = dst_mtu(csk->dst);
		best_mtu(csk, lldi->mtus, csk->mtu, &mss_idx,
			enable_tcp_tmstamps);

                if (mss_idx < csk->mss_idx) {
                        t4_set_maxseg(csk, mss_idx);
                        csk->mss_idx = mss_idx;
                }

        	goto rel_skb;
	}

	cxgbi_sock_get(csk);
	spin_lock_bh(&csk->lock);

	cxgbi_sock_clear_flag(csk, CTPF_ABORT_REQ_RCVD);

	if (!cxgbi_sock_flag(csk, CTPF_TX_DATA_SENT)) {
		send_tx_flowc_wr(csk, 0);
		cxgbi_sock_set_flag(csk, CTPF_TX_DATA_SENT);
	}

	cxgbi_sock_set_flag(csk, CTPF_ABORT_REQ_RCVD);
	cxgbi_sock_set_state(csk, CTP_ABORTING);

	send_abort_rpl(csk, rst_status);

	if (!cxgbi_sock_flag(csk, CTPF_ABORT_RPL_PENDING)) {
		csk->err = abort_status_to_errno(csk, req->status, &rst_status);
		cxgbi_sock_closed(csk);
	}

	spin_unlock_bh(&csk->lock);
	cxgbi_sock_put(csk);
rel_skb:
	__kfree_skb(skb);
}

static void do_abort_rpl_rss(struct cxgbi_device *cdev, struct sk_buff *skb)
{
	struct cxgbi_sock *csk;
	struct cpl_abort_rpl_rss *rpl = (struct cpl_abort_rpl_rss *)skb->data;
	unsigned int tid = GET_TID(rpl);
	struct cxgb4_lld_info *lldi = cxgbi_cdev_priv(cdev);
	struct tid_info *t = lldi->tids;

	csk = lookup_tid(t, tid);
	if (!csk)
		goto rel_skb;

	log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_SOCK,
		"status 0x%x, csk 0x%p.\n",
		rpl->status, csk);

	if (csk) 
		pr_info_ipaddr("csk 0x%p,%u,0x%lx,%u, status %u.\n",
			(&csk->saddr),
			(&csk->daddr),
			csk, csk->state, csk->flags, csk->tid, rpl->status);

	if (rpl->status == CPL_ERR_ABORT_FAILED)
		goto rel_skb;

	cxgbi_sock_rcv_abort_rpl(csk);
rel_skb:
	__kfree_skb(skb);
}

static void do_rx_iscsi_hdr(struct cxgbi_device *cdev, struct sk_buff *skb)
{
	struct cxgbi_sock *csk;
	struct cpl_iscsi_hdr *cpl = (struct cpl_iscsi_hdr *)skb->data;
	unsigned short pdu_len_ddp = be16_to_cpu(cpl->pdu_len_ddp);
	unsigned int tid = GET_TID(cpl);
	struct cxgb4_lld_info *lldi = cxgbi_cdev_priv(cdev);
	struct tid_info *t = lldi->tids;
	struct sk_buff *lskb;
	int t4 = is_t4(lldi->adapter_type);

	csk = lookup_tid(t, tid);
	if (unlikely(!csk)) {
		pr_err("can't find conn. for tid %u.\n", tid);
		goto rel_skb;
	}

	log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_PDU_RX,
		"csk 0x%p,%u,0x%lx, tid %u, skb 0x%p,%u, 0x%x.\n",
		csk, csk->state, csk->flags, csk->tid, skb, skb->len,
		pdu_len_ddp);

	spin_lock_bh(&csk->lock);

	if (unlikely(csk->state >= CTP_PASSIVE_CLOSE)) {
		log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_SOCK,
			"csk 0x%p,%u,0x%lx,%u, bad state.\n",
			csk, csk->state, csk->flags, csk->tid);
		if (csk->state != CTP_ABORTING)
			goto abort_conn;
		else
			goto discard;
	}

	cxgbi_skcb_tcp_seq(skb) = ntohl(cpl->seq);
	cxgbi_skcb_flags(skb) = 0;

	skb_reset_transport_header(skb);
	__skb_pull(skb, sizeof(*cpl));
	__pskb_trim(skb, ntohs(cpl->len));

	if (!csk->skb_ulp_lhdr) {
		unsigned char *bhs;
		unsigned int hlen, dlen, plen;

		log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_PDU_RX,
			"csk 0x%p,%u,0x%lx, tid %u, skb 0x%p header.\n",
			csk, csk->state, csk->flags, csk->tid, skb);
		csk->skb_ulp_lhdr = skb;
		lskb = csk->skb_ulp_lhdr;
		cxgbi_skcb_set_flag(lskb, SKCBF_RX_HDR);

		if (cxgbi_skcb_tcp_seq(lskb) != csk->rcv_nxt) {
			pr_info("tid %u, CPL_ISCSI_HDR, bad seq, 0x%x/0x%x.\n",
				csk->tid, cxgbi_skcb_tcp_seq(lskb),
				csk->rcv_nxt);
			goto abort_conn;
		}

		bhs = lskb->data;
		hlen = ntohs(cpl->len);
		dlen = ntohl(*(unsigned int *)(bhs + 4)) & 0xFFFFFF;

		if (t4)
			plen = ISCSI_PDU_LEN(pdu_len_ddp) - 40;
		else
			plen = ISCSI_PDU_LEN(pdu_len_ddp);

		if ((hlen + dlen) != plen) {
			pr_info("tid 0x%x, CPL_ISCSI_HDR, pdu len "
				"mismatch %u != %u + %u, seq 0x%x.\n",
				csk->tid, plen, hlen, dlen,
				cxgbi_skcb_tcp_seq(skb));
			goto abort_conn;
		}

		cxgbi_skcb_rx_pdulen(skb) = (hlen + dlen + 3) & (~0x3);
		if (dlen)
			cxgbi_skcb_rx_pdulen(skb) += csk->dcrc_len;
		csk->rcv_nxt += cxgbi_skcb_rx_pdulen(skb);

		log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_PDU_RX,
			"csk 0x%p, skb 0x%p, 0x%x,%u+%u,0x%x,0x%x.\n",
			csk, skb, *bhs, hlen, dlen,
			ntohl(*((unsigned int *)(bhs + 16))),
			ntohl(*((unsigned int *)(bhs + 24))));

	} else {
		lskb = csk->skb_ulp_lhdr;
		cxgbi_skcb_set_flag(lskb, SKCBF_RX_DATA);

		log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_PDU_RX,
			"csk 0x%p,%u,0x%lx, skb 0x%p data, 0x%p.\n",
			csk, csk->state, csk->flags, skb, lskb);
	}

	__skb_queue_tail(&csk->receive_queue, skb);
	spin_unlock_bh(&csk->lock);
	return;

abort_conn:
	send_abort_req(csk);
discard:
	spin_unlock_bh(&csk->lock);
rel_skb:
	__kfree_skb(skb);
}

static void do_rx_iscsi_data(struct cxgbi_device *cdev, struct sk_buff *skb)
{
	struct cxgbi_sock *csk;
	struct cpl_iscsi_hdr *cpl = (struct cpl_iscsi_hdr *)skb->data;
	unsigned short pdu_len_ddp = be16_to_cpu(cpl->pdu_len_ddp);
	unsigned int tid = GET_TID(cpl);
	struct cxgb4_lld_info *lldi = cxgbi_cdev_priv(cdev);
	struct tid_info *t = lldi->tids;
	struct sk_buff *lskb;

	csk = lookup_tid(t, tid);
	if (unlikely(!csk)) {
		pr_err("can't find conn. for tid %u.\n", tid);
		goto rel_skb;
	}

	log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_PDU_RX,
		"csk 0x%p,%u,0x%lx, tid %u, skb 0x%p,%u, 0x%x.\n",
		csk, csk->state, csk->flags, csk->tid, skb,
		skb->len, pdu_len_ddp);

	spin_lock_bh(&csk->lock);

	if (unlikely(csk->state >= CTP_PASSIVE_CLOSE)) {
		log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_SOCK,
			"csk 0x%p,%u,0x%lx,%u, bad state.\n",
			csk, csk->state, csk->flags, csk->tid);
		if (csk->state != CTP_ABORTING)
			goto abort_conn;
		else
			goto discard;
	}

	cxgbi_skcb_tcp_seq(skb) = ntohl(cpl->seq);
	cxgbi_skcb_flags(skb) = 0;

	skb_reset_transport_header(skb);
	__skb_pull(skb, sizeof(*cpl));
	__pskb_trim(skb, ntohs(cpl->len));


	if (!csk->skb_ulp_lhdr) {
		/* It comes here only if iscsi completion feature is enabled */
		/* DDP failed for pdu */
		/* if completion feature is not enabled, its an error. TODO */
		csk->skb_ulp_lhdr = skb;
	}
	lskb = csk->skb_ulp_lhdr;
	cxgbi_skcb_set_flag(lskb, SKCBF_RX_DATA);

	log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_PDU_RX,
		"csk 0x%p,%u,0x%lx, skb 0x%p data, 0x%p.\n",
		csk, csk->state, csk->flags, skb, lskb);

	__skb_queue_tail(&csk->receive_queue, skb);
	spin_unlock_bh(&csk->lock);
	return;

abort_conn:
	send_abort_req(csk);
discard:
	spin_unlock_bh(&csk->lock);
rel_skb:
	__kfree_skb(skb);
}

static void do_rx_data_ddp(struct cxgbi_device *cdev,
				  struct sk_buff *skb)
{
	struct cxgbi_sock *csk;
	struct sk_buff *lskb;
	struct cpl_rx_data_ddp *rpl = (struct cpl_rx_data_ddp *)skb->data;
	unsigned int tid = GET_TID(rpl);
	struct cxgb4_lld_info *lldi = cxgbi_cdev_priv(cdev);
	struct tid_info *t = lldi->tids;
	unsigned int status = ntohl(rpl->ddpvld);

	csk = lookup_tid(t, tid);
	if (unlikely(!csk)) {
		pr_err("can't find connection for tid %u.\n", tid);
		goto rel_skb;
	}

	log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_PDU_RX,
		"csk 0x%p,%u,0x%lx, skb 0x%p,0x%x, lhdr 0x%p, len %u.\n",
		csk, csk->state, csk->flags, skb, status, csk->skb_ulp_lhdr,
		ntohs(rpl->len));

	spin_lock_bh(&csk->lock);

	if (unlikely(csk->state >= CTP_PASSIVE_CLOSE)) {
		log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_SOCK,
			"csk 0x%p,%u,0x%lx,%u, bad state.\n",
			csk, csk->state, csk->flags, csk->tid);
		if (csk->state != CTP_ABORTING)
			goto abort_conn;
		else
			goto discard;
	}

	if (!csk->skb_ulp_lhdr) {
		pr_err("tid 0x%x, rcv RX_DATA_DDP w/o pdu bhs.\n", csk->tid);
		goto abort_conn;
	}

	lskb = csk->skb_ulp_lhdr;
	csk->skb_ulp_lhdr = NULL;

	cxgbi_skcb_set_flag(lskb, SKCBF_RX_STATUS);
	cxgbi_skcb_rx_ddigest(lskb) = ntohl(rpl->ulp_crc);

	if (ntohs(rpl->len) != cxgbi_skcb_rx_pdulen(lskb))
		pr_info("tid 0x%x, RX_DATA_DDP pdulen %u != %u.\n",
			csk->tid, ntohs(rpl->len), cxgbi_skcb_rx_pdulen(lskb));

	if (status & (1 << CPL_RX_DDP_STATUS_HCRC_SHIFT)) {
		pr_info("csk 0x%p, lhdr 0x%p, status 0x%x, hcrc bad.\n",
			csk, lskb, status);
		cxgbi_skcb_set_flag(lskb, SKCBF_RX_HCRC_ERR);
	}
	if (status & (1 << CPL_RX_DDP_STATUS_DCRC_SHIFT)) {
		pr_info("csk 0x%p, lhdr 0x%p, status 0x%x, dcrc bad.\n",
			csk, lskb, status);
		cxgbi_skcb_set_flag(lskb, SKCBF_RX_DCRC_ERR);
	}
	if (status & (1 << CPL_RX_DDP_STATUS_PAD_SHIFT)) {
		pr_info("csk 0x%p, lhdr 0x%p, status 0x%x, pad bad.\n",
			csk, lskb, status);
		cxgbi_skcb_set_flag(lskb, SKCBF_RX_PAD_ERR);
	}
	if ((status & (1 << CPL_RX_DDP_STATUS_DDP_SHIFT)) &&
		!cxgbi_skcb_test_flag(lskb, SKCBF_RX_DATA)) {
		log_debug(1 << CXGBI_DBG_PDU_RX,
			"csk 0x%p, lhdr 0x%p, 0x%x, data ddp'ed.\n",
			csk, lskb, status);
		cxgbi_skcb_set_flag(lskb, SKCBF_RX_DATA_DDPD);
	}
	log_debug(1 << CXGBI_DBG_PDU_RX,
		"csk 0x%p, lskb 0x%p, f 0x%lx.\n",
		csk, lskb, cxgbi_skcb_flags(lskb));

	cxgbi_conn_pdu_ready(csk);
	spin_unlock_bh(&csk->lock);
	goto rel_skb;

abort_conn:
	send_abort_req(csk);
discard:
	spin_unlock_bh(&csk->lock);
rel_skb:
	__kfree_skb(skb);
}

/* iscsi completion feature will not work with lro_on=1 TODO */
static void do_rx_iscsi_cmp(struct cxgbi_device *cdev,
				  struct sk_buff *skb)
{
	struct cxgbi_sock *csk;
	struct sk_buff *lskb;
	struct cpl_rx_iscsi_cmp *rpl = (struct cpl_rx_iscsi_cmp *)skb->data;
	unsigned int tid = GET_TID(rpl);
	struct cxgb4_lld_info *lldi = cxgbi_cdev_priv(cdev);
	struct tid_info *t = lldi->tids;
	struct sk_buff *data_skb = NULL;
	unsigned int status = ntohl(rpl->ddpvld);
	unsigned short pdu_len_ddp = be16_to_cpu(rpl->pdu_len_ddp);
	unsigned char *bhs;
	unsigned int hlen, dlen, plen;
	unsigned int total_data;

	csk = lookup_tid(t, tid);
	if (unlikely(!csk)) {
		pr_err("can't find connection for tid %u.\n", tid);
		goto rel_skb;
	}

	log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_PDU_RX,
		"csk 0x%p,%u,0x%lx, skb 0x%p,0x%x, lhdr 0x%p, len %u, "
		"pdu_len_ddp %u, status %u.\n",
		csk, csk->state, csk->flags, skb, status, csk->skb_ulp_lhdr,
		ntohs(rpl->len), pdu_len_ddp,  rpl->status);

	spin_lock_bh(&csk->lock);

	if (unlikely(csk->state >= CTP_PASSIVE_CLOSE)) {
		log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_SOCK,
			"csk 0x%p,%u,0x%lx,%u, bad state.\n",
			csk, csk->state, csk->flags, csk->tid);
		if (csk->state != CTP_ABORTING)
			goto abort_conn;
		else
			goto discard;
	}

	cxgbi_skcb_tcp_seq(skb) = ntohl(rpl->seq);
	cxgbi_skcb_flags(skb) = 0;

	/* check tcp seq num TODO */

	skb_reset_transport_header(skb);
	__skb_pull(skb, sizeof(*rpl));
	__pskb_trim(skb, ntohs(rpl->len));

	/* This cpl carries last iscsi hdr of burst. In both the cases we may
 	 * have to modify iscsi hdr buffer to suit what is expected by
 	 * open-iscsi. TODO */
	bhs = skb->data;
	hlen = ntohs(rpl->len);
	dlen = ntohl(*(unsigned int *)(bhs + 4)) & 0xFFFFFF;

	plen = ISCSI_PDU_LEN(pdu_len_ddp);

#if 0
	print_hex_dump(KERN_CONT, "CMP BHS: ", DUMP_PREFIX_OFFSET, 16, 1,
                        bhs, hlen, false);
#endif

	/* tcp seq number in the cpl is the only way to know bout how much
 	 * data is DDP'ed till the time of receiving this cpl.
 	 */
	total_data = ntohl(rpl->seq) - csk->rcv_nxt +
					ntohs(rpl->pdu_len_ddp);
	cxgbi_skcb_rx_pdulen(skb) = total_data;

	/* useing sequence number to find how much data is DDP'ed for this cpl.
	 */
	csk->rcv_nxt = ntohl(rpl->seq);
	csk->rcv_nxt += ntohs(rpl->pdu_len_ddp);

	/* Note: Open-iscsi expects single pdu hdr but we are giving the header
 	 * from the last pdu of the burst. */
	if (csk->skb_ulp_lhdr) {
		/* we must have data skb in receive queue.
 		 * dequeue data skb, add hdr skb and then requeue data skb. */
		data_skb = skb_peek(&csk->receive_queue);
		if (!data_skb ||
			!cxgbi_skcb_test_flag(data_skb, SKCBF_RX_DATA)) {
			pr_err("Error! freelist data not found 0x%p, tid %u\n",
				 data_skb, tid);

			goto abort_conn;
		}
		__skb_unlink(data_skb, &csk->receive_queue);

		cxgbi_skcb_set_flag(skb, SKCBF_RX_DATA);

		__skb_queue_tail(&csk->receive_queue, skb);
		__skb_queue_tail(&csk->receive_queue, data_skb);
	} else {
		/* put hdr skb in queue and the continue the same ddp
 		 * processing */
		 __skb_queue_tail(&csk->receive_queue, skb);
	}
	lskb = skb;
	csk->skb_ulp_lhdr = NULL;

	cxgbi_skcb_set_flag(lskb, SKCBF_RX_HDR);

	cxgbi_skcb_set_flag(lskb, SKCBF_RX_STATUS);
	cxgbi_skcb_set_flag(lskb, SKCBF_RX_ISCSI_COMPL);
	cxgbi_skcb_rx_ddigest(lskb) = ntohl(rpl->ulp_crc);

	if (status & (1 << CPL_RX_DDP_STATUS_HCRC_SHIFT)) {
		pr_info("csk 0x%p, lhdr 0x%p, status 0x%x, hcrc bad.\n",
			csk, lskb, status);
		cxgbi_skcb_set_flag(lskb, SKCBF_RX_HCRC_ERR);
	}
	if (status & (1 << CPL_RX_DDP_STATUS_DCRC_SHIFT)) {
		pr_info("csk 0x%p, lhdr 0x%p, status 0x%x, dcrc bad.\n",
			csk, lskb, status);
		cxgbi_skcb_set_flag(lskb, SKCBF_RX_DCRC_ERR);
	}
	if (status & (1 << CPL_RX_DDP_STATUS_PAD_SHIFT)) {
		pr_info("csk 0x%p, lhdr 0x%p, status 0x%x, pad bad.\n",
			csk, lskb, status);
		cxgbi_skcb_set_flag(lskb, SKCBF_RX_PAD_ERR);
	}
	if ((status & (1 << CPL_RX_DDP_STATUS_DDP_SHIFT)) &&
		!cxgbi_skcb_test_flag(lskb, SKCBF_RX_DATA)) {
		log_debug(1 << CXGBI_DBG_PDU_RX,
			"csk 0x%p, lhdr 0x%p, 0x%x, data ddp'ed.\n",
			csk, lskb, status);
		cxgbi_skcb_set_flag(lskb, SKCBF_RX_DATA_DDPD);
	}
	log_debug(1 << CXGBI_DBG_PDU_RX,
		"csk 0x%p, lskb 0x%p, f 0x%lx.\n",
		csk, lskb, cxgbi_skcb_flags(lskb));

	cxgbi_conn_pdu_ready(csk);
	spin_unlock_bh(&csk->lock);
	/* Don't release skb because it carries hdr and we have it added in
	 * receive_queue */
	return;

abort_conn:
	send_abort_req(csk);
discard:
	spin_unlock_bh(&csk->lock);
rel_skb:
	__kfree_skb(skb);
}

#ifdef CXGBI_T10DIF_SUPPORT
static void do_rx_iscsi_dif(struct cxgbi_device *cdev,
				  struct sk_buff *skb)
{
	struct cxgbi_sock *csk;
	struct sk_buff *lskb;
	struct cpl_rx_iscsi_dif *rpl = (struct cpl_rx_iscsi_dif *)skb->data;
	unsigned int tid = GET_TID(rpl);
	struct cxgb4_lld_info *lldi = cxgbi_cdev_priv(cdev);
	struct tid_info *t = lldi->tids;
	unsigned int status = ntohl(rpl->ddpvld);
	/* fw ensures that if pi is ddp'd, msg_len is 0,
 	 * else it is the size of pi in this cpl. */
	unsigned int pi_len = ntohs(rpl->msg_len);

	csk = lookup_tid(t, tid);
	if (unlikely(!csk)) {
		pr_err("can't find connection for tid %u.\n", tid);
		goto rel_skb;
	}

	log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_PDU_RX,
		"do_rx_iscsi_dif csk 0x%p,%u,0x%lx, skb 0x%p,0x%x, lhdr 0x%p, "
		"len %u, pi_len %u.\n",
		csk, csk->state, csk->flags, skb, status, csk->skb_ulp_lhdr,
		ntohs(rpl->ddp_len), pi_len);

#if 0
	print_hex_dump(KERN_CONT, "DIF_CPL: ", DUMP_PREFIX_OFFSET, 16, 1,
		((void *)rpl)+sizeof(*rpl), pi_len, false);
#endif

	spin_lock_bh(&csk->lock);

	if (unlikely(csk->state >= CTP_PASSIVE_CLOSE)) {
		log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_SOCK,
			"csk 0x%p,%u,0x%lx,%u, bad state.\n",
			csk, csk->state, csk->flags, csk->tid);
		if (csk->state != CTP_ABORTING)
			goto abort_conn;
		else
			goto discard;
	}

	if (!csk->skb_ulp_lhdr) {
		pr_err("tid 0x%x, rcv RX_DATA_DDP w/o pdu bhs.\n", csk->tid);
		goto abort_conn;
	}

	lskb = csk->skb_ulp_lhdr;
	csk->skb_ulp_lhdr = NULL;

	/* indicates that pi is received separate from data */
	cxgbi_skcb_set_flag(lskb, SKCBF_RX_PI);

	if (cdev->flags & CXGBI_FLAG_T10DIF_OFFSET_UPDATED)
		cxgbi_skcb_set_flag(lskb, SKCBF_PI_OFFSET_UPDATED);

	cxgbi_skcb_set_flag(lskb, SKCBF_RX_STATUS);
	cxgbi_skcb_rx_ddigest(lskb) = ntohl(rpl->ulp_crc);
	cxgbi_skcb_rx_pi_len(lskb) = pi_len;

	/* Note: in READ_PASS and READ_STRIP cases, the expected pdulen
 	 * includes data and pi len while ddp_len is always only data len */
	if (ntohs(rpl->ddp_len) != cxgbi_skcb_rx_pdulen(lskb))
		pr_info("tid 0x%x, RX_ISCSI_DIF pdulen %u != %u.\n",
			csk->tid, ntohs(rpl->ddp_len),
			cxgbi_skcb_rx_pdulen(lskb));

	if (status & (1 << CPL_RX_DDP_STATUS_HCRC_SHIFT)) {
		pr_info(
			"csk 0x%p, lhdr 0x%p, status 0x%x, hcrc bad.\n",
			csk, lskb, status);
		cxgbi_skcb_set_flag(lskb, SKCBF_RX_HCRC_ERR);
	}
	if (status & (1 << CPL_RX_DDP_STATUS_DCRC_SHIFT)) {
		pr_info(
			"csk 0x%p, lhdr 0x%p, status 0x%x, dcrc bad.\n",
			csk, lskb, status);
		cxgbi_skcb_set_flag(lskb, SKCBF_RX_DCRC_ERR);
	}
	if (status & (1 << CPL_RX_DDP_STATUS_PAD_SHIFT)) {
		pr_info(
			"csk 0x%p, lhdr 0x%p, status 0x%x, pad bad.\n",
			csk, lskb, status);
		cxgbi_skcb_set_flag(lskb, SKCBF_RX_PAD_ERR);
	}
	if ((status & (1 << CPL_RX_DDP_STATUS_DDP_SHIFT)) &&
		!cxgbi_skcb_test_flag(lskb, SKCBF_RX_DATA)) {
		log_debug(1 << CXGBI_DBG_PDU_RX,
			"csk 0x%p, lhdr 0x%p, 0x%x, data ddp'ed.\n",
			csk, lskb, status);
		cxgbi_skcb_set_flag(lskb, SKCBF_RX_DATA_DDPD);
	}
	if (!pi_len) {
		log_debug(1 << CXGBI_DBG_PDU_RX,
			"csk 0x%p, lhdr 0x%p, pi ddp'ed.\n",
			csk, lskb);
		cxgbi_skcb_set_flag(lskb, SKCBF_RX_PI_DDPD);
	}

	/* pi verification status */
	if (rpl->err_vec) {
		pr_info(
			"csk 0x%p, lhdr 0x%p, err_vec 0x%x, pi verify failed.\n",
			csk, lskb, ntohl(rpl->err_vec));
		cxgbi_skcb_set_flag(lskb, SKCBF_RX_PI_ERR);
	}

	log_debug(1 << CXGBI_DBG_PDU_RX,
		"csk 0x%p, lskb 0x%p, f 0x%lx.\n",
		csk, lskb, cxgbi_skcb_flags(lskb));

	skb_reset_transport_header(skb);
	__skb_pull(skb, sizeof(*rpl));
	__pskb_trim(skb, pi_len);

	if (cxgbi_skcb_test_flag(lskb, SKCBF_RX_PI_DDPD))
		cxgbi_skcb_set_flag(skb, SKCBF_RX_PI_DDPD);

	__skb_queue_tail(&csk->receive_queue, skb);

	cxgbi_conn_pdu_ready(csk);
	spin_unlock_bh(&csk->lock);
	return;

abort_conn:
	send_abort_req(csk);
discard:
	spin_unlock_bh(&csk->lock);
rel_skb:
	__kfree_skb(skb);
}
#endif

static void do_fw4_ack(struct cxgbi_device *cdev, struct sk_buff *skb)
{
	struct cxgbi_sock *csk;
	struct cpl_fw4_ack *rpl = (struct cpl_fw4_ack *)skb->data;
	unsigned int tid = GET_TID(rpl);
	struct cxgb4_lld_info *lldi = cxgbi_cdev_priv(cdev);
	struct tid_info *t = lldi->tids;

	csk = lookup_tid(t, tid);
	if (unlikely(!csk))
		pr_err("can't find connection for tid %u.\n", tid);
	else {
		log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_SOCK,
			"csk 0x%p,%u,0x%lx,%u.\n",
			csk, csk->state, csk->flags, csk->tid);
		cxgbi_sock_rcv_wr_ack(csk, rpl->credits, ntohl(rpl->snd_una),
			rpl->flags & CPL_FW4_ACK_FLAGS_SEQVAL ? 1 : 0);
	}
	__kfree_skb(skb);
}

static void do_set_tcb_rpl(struct cxgbi_device *cdev, struct sk_buff *skb)
{
	struct cpl_set_tcb_rpl *rpl = (struct cpl_set_tcb_rpl *)skb->data;
	unsigned int tid = GET_TID(rpl);
	struct cxgb4_lld_info *lldi = cxgbi_cdev_priv(cdev);
	struct tid_info *t = lldi->tids;
	struct cxgbi_sock *csk;

	csk = lookup_tid(t, tid);
	if (!csk)
		pr_err("can't find conn. for tid %u.\n", tid);

	log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_SOCK,
		"csk 0x%p,%u,%lx,%u, status 0x%x.\n",
		csk, csk->state, csk->flags, csk->tid, rpl->status);

	if (rpl->status != CPL_ERR_NONE)
		pr_err("csk 0x%p,%u, SET_TCB_RPL status %u.\n",
			csk, tid, rpl->status);

	__kfree_skb(skb);
}

static void do_fw6_msg(struct cxgbi_device *cdev, struct sk_buff *skb)
{
#ifdef CXGBI_T10DIF_SUPPORT
	struct cxgbi_sock *csk;
	struct cpl_fw6_msg *rpl = (struct cpl_fw6_msg *)skb->data;
	struct fw_pi_error *pi_err = (struct fw_pi_error *)rpl->data;
	struct cxgb4_lld_info *lldi = cxgbi_cdev_priv(cdev);
	struct tid_info *t = lldi->tids;
	unsigned int tid = GET_FW_WR_FLOWID(ntohl(pi_err->flowid_len16));

	if (rpl->type != FW_TYPE_PI_ERR)
		goto out;

	print_hex_dump(KERN_CONT, "pi_err: ", DUMP_PREFIX_OFFSET, 16, 1,
		(void *)rpl->data, 32, false);
	pr_info("cxgb4i pi guard error tid 0x%x: app_tag 0x%x, ref_tag 0x%x\n",
			tid, ntohs(pi_err->app_tag), ntohl(pi_err->ref_tag));

	csk = lookup_tid(t, tid);
	if (!csk)
		pr_err("%s: can't find conn. for tid %u.\n", __func__, tid);
	else {
		spin_lock_bh(&csk->lock);
		send_abort_req(csk);
		spin_unlock_bh(&csk->lock);
	}
out:
#endif
	__kfree_skb(skb);
}

static void do_rx_data(struct cxgbi_device *cdev, struct sk_buff *skb)
{
	struct cxgbi_sock *csk;
	struct cpl_rx_data *cpl = (struct cpl_rx_data *)skb->data;
	unsigned int tid = GET_TID(cpl);
	struct cxgb4_lld_info *lldi = cxgbi_cdev_priv(cdev);
	struct tid_info *t = lldi->tids;

	csk = lookup_tid(t, tid);
	if (!csk)
		pr_err("%s: can't find conn. for tid %u.\n", __func__, tid);
	else {
		/* not expecting this, reset the connection. */
		pr_err("%s: csk 0x%p, tid %u, rcv cpl_rx_data.\n",
			__func__, csk, tid);
		spin_lock_bh(&csk->lock);
		send_abort_req(csk);
		spin_unlock_bh(&csk->lock);
        }

	__kfree_skb(skb);
}

static void do_rx_pkt(struct cxgbi_device *cdev, struct sk_buff *skb)
{
	pr_err("%s.\n", __func__);
	__kfree_skb(skb);
}

static struct sk_buff *lro_init_skb(struct cxgbi_sock *csk, unsigned int len);
static int alloc_cpls(struct cxgbi_sock *csk)
{
	csk->cpl_close = alloc_wr(roundup(sizeof(struct cpl_close_con_req), 16),
					0, GFP_NOIO);
	if (!csk->cpl_close)
		return -ENOMEM;

	csk->cpl_abort_req = alloc_wr(sizeof(struct cpl_abort_req),
					0, GFP_NOIO);
	if (!csk->cpl_abort_req)
		goto free_cpls;

	csk->cpl_abort_rpl = alloc_wr(sizeof(struct cpl_abort_rpl),
					0, GFP_NOIO);
	if (!csk->cpl_abort_rpl)
		goto free_cpls;

	csk->skb_lro_hold = lro_init_skb(csk, LRO_SKB_MIN_HEADROOM);
	if (unlikely(!csk->skb_lro_hold))
		goto free_cpls;
	cxgbi_sock_put(csk);
	
	return 0;

free_cpls:
	cxgbi_sock_free_cpl_skbs(csk);
	return -ENOMEM;
}

static inline void l2t_put(struct cxgbi_sock *csk)
{
	if (csk->l2t) {
		cxgb4_l2t_release(csk->l2t);
		csk->l2t = NULL;
		cxgbi_sock_put(csk);
	}
}

static void release_offload_resources(struct cxgbi_sock *csk)
{
	struct cxgb4_lld_info *lldi;
	struct net_device *ndev = csk->cdev->ports[csk->port_id];

	log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_SOCK,
		"csk 0x%p,%u,0x%lx,%u.\n",
		csk, csk->state, csk->flags, csk->tid);

	cxgbi_sock_free_cpl_skbs(csk);
	if (csk->wr_cred != csk->wr_max_cred) {
		cxgbi_sock_purge_wr_queue(csk);
		cxgbi_sock_reset_wr_list(csk);
	}

	l2t_put(csk);
#ifdef CXGBI_IPV6_SUPPORT
        if (csk->csk_family == AF_INET6)
                cxgb4_clip_release(ndev,
                        (const u32 *)&(csk->saddr6.sin6_addr), 1);
#endif
	if (cxgbi_sock_flag(csk, CTPF_HAS_ATID))
		free_atid(csk);
	else if (cxgbi_sock_flag(csk, CTPF_HAS_TID)) {
		lldi = cxgbi_cdev_priv(csk->cdev);
		cxgb4_remove_tid(lldi->tids, 0, csk->tid,
				csk->csk_family);
		cxgbi_sock_clear_flag(csk, CTPF_HAS_TID);
		cxgbi_sock_put(csk);
	}
	csk->dst = NULL;
	csk->cdev = NULL;
}

#ifdef __CONFIG_CXGB4_DCB__
static inline u8 get_iscsi_dcb_state(struct net_device *ndev)
{
	return ndev->dcbnl_ops->getstate(ndev);
}

static int select_priority(int pri_mask)
{
	if (!pri_mask)
		return 0;

	/*
 	 * TODO: Configure priority selection from the mask
 	 * For now, just always take the highest bit set
 	 */

	return (ffs(pri_mask) - 1);
}

static u8 get_iscsi_dcb_priority(struct net_device *ndev) 
{
	int rv;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38))
	uint8_t caps;

	struct dcb_app iscsi_dcb_app = {
		.protocol = 3260
	};

	rv = (int)ndev->dcbnl_ops->getcap(ndev, DCB_CAP_ATTR_DCBX, &caps);

	if (rv)
		return 0;

	if(caps & DCB_CAP_DCBX_VER_IEEE) {
		iscsi_dcb_app.selector = IEEE_8021QAZ_APP_SEL_ANY;

		rv = dcb_ieee_getapp_mask(ndev, &iscsi_dcb_app);

	} else if (caps & DCB_CAP_DCBX_VER_CEE) {
		iscsi_dcb_app.selector = DCB_APP_IDTYPE_PORTNUM;

		rv = dcb_getapp(ndev, &iscsi_dcb_app);
	}
#else
	/* Kernels below 2.6.38 have no getapp functions that can provide
	 * negotiated info, so we use an exported function to achieve the
	 * same */
	rv = cxgb4_getapp_external(ndev, DCB_APP_IDTYPE_PORTNUM, 3260);
#endif
	log_debug(1 << CXGBI_DBG_ISCSI,
		"iSCSI priority is set to %u\n", select_priority(rv));

	return select_priority(rv);
}
#endif

static int init_act_open(struct cxgbi_sock *csk)
{
	struct cxgbi_device *cdev = csk->cdev;
	struct cxgb4_lld_info *lldi = cxgbi_cdev_priv(cdev);
	struct net_device *ndev = cdev->ports[csk->port_id];
	struct neighbour *n = NULL;
	struct sk_buff *skb = NULL;
	void *daddr;
	unsigned int step, rxq_idx;
	unsigned int size, size6;
#ifdef __CONFIG_CXGB4_DCB__
	u8 priority = 0;
#endif
	unsigned int linkspeed;
	unsigned int rcv_winf, snd_winf;

	log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_SOCK,
		"csk 0x%p,%u,0x%lx,%u.\n",
		csk, csk->state, csk->flags, csk->tid);

	if (csk->csk_family == AF_INET)
		daddr = &csk->daddr.sin_addr.s_addr;
#ifdef CXGBI_IPV6_SUPPORT
	else
		daddr = &csk->daddr6.sin6_addr;
#else
	else {
		pr_err("address family 0x%x not supported\n", csk->csk_family);
		goto rel_resource;
	}
#endif

#if defined DEFINED_DST_NEIGH_LOOKUP
	n = dst_neigh_lookup(csk->dst, daddr);
#elif defined DEFINED_DST_GET_NEIGHBOUR_NOREF
	n = dst_get_neighbour_noref(csk->dst);
#elif defined DEFINED_DST_GET_NEIGHBOUR
	n = dst_get_neighbour(csk->dst);
#else
	n = csk->dst->neighbour;
#endif
	if (!n) {
		pr_err("%s, can't get neighbour of csk->dst.\n", ndev->name);
		goto rel_resource;
	}

	csk->atid = cxgb4_alloc_atid(lldi->tids, csk);
	if (csk->atid < 0) {
		pr_err("%s, NO atid available.\n", ndev->name);
		return -EINVAL;
	}
	cxgbi_sock_set_flag(csk, CTPF_HAS_ATID);
	cxgbi_sock_get(csk);

#ifdef __CONFIG_CXGB4_DCB__
	if(get_iscsi_dcb_state(ndev)) 
		priority = get_iscsi_dcb_priority(ndev);

	csk->dcb_priority = priority;

	csk->l2t = cxgb4_l2t_get(lldi->l2t, n, ndev, priority);
#else
	csk->l2t = cxgb4_l2t_get(lldi->l2t, n, ndev, 0);
#endif
	if (!csk->l2t) {
		pr_err("%s, cannot alloc l2t.\n", ndev->name);
		goto rel_resource_without_clip;
	}
	cxgbi_sock_get(csk);

#ifdef CXGBI_IPV6_SUPPORT
	if (csk->csk_family == AF_INET6)
                cxgb4_clip_get(ndev,
                        (const u32 *)&(csk->saddr6.sin6_addr), 1);
#endif

	switch (CHELSIO_CHIP_VERSION(lldi->adapter_type)) {
	case CHELSIO_T4:
		size = sizeof(struct cpl_act_open_req);
		size6 = sizeof(struct cpl_act_open_req6);
		break;
	case CHELSIO_T5:
		size = sizeof(struct cpl_t5_act_open_req);
		size6 = sizeof(struct cpl_t5_act_open_req6);
		break;
	case CHELSIO_T6:
	default:
		size = sizeof(struct cpl_t6_act_open_req);
		size6 = sizeof(struct cpl_t6_act_open_req6);
		break;
	}

	if (csk->csk_family == AF_INET)
		skb = alloc_wr(size, 0, GFP_NOIO);
	else
		skb = alloc_wr(size6, 0, GFP_NOIO);
		
	if (!skb)
		goto rel_resource;
	skb->sk = (struct sock *)csk;
	t4_set_arp_err_handler(skb, csk, cxgbi_sock_act_open_req_arp_failure);

	if (!csk->mtu)
		csk->mtu = dst_mtu(csk->dst);
	best_mtu(csk, lldi->mtus, csk->mtu, &csk->mss_idx, enable_tcp_tmstamps);
	csk->tx_chan = cxgb4_port_chan(ndev);
	csk->smac_idx = cxgb4_tp_smt_idx(lldi->adapter_type, 
			cxgb4_port_viid(ndev));
	step = lldi->ntxq / lldi->nchan;
	csk->txq_idx = cxgb4_port_idx(ndev) * step;
	step = lldi->nrxq / lldi->nchan;
	rxq_idx = cxgb4_port_idx(ndev) * step;
	rxq_idx += cdev->round_robin_cnt++;
	if (cdev->round_robin_cnt == step)
		cdev->round_robin_cnt = 0;
	csk->rss_qid = lldi->rxq_ids[rxq_idx];

	linkspeed = ((struct port_info *)netdev_priv(ndev))->link_cfg.speed;
	csk->snd_win = cxgb4i_snd_win;
	csk->rcv_win = cxgb4i_rcv_win;
	if (cxgb4i_rcv_win <= 0) {
		csk->rcv_win = CXGB4I_DEFAULT_10G_RCV_WIN;
		rcv_winf = linkspeed/SPEED_10000;
		if (rcv_winf)
			csk->rcv_win *= rcv_winf;
	}
	if (cxgb4i_snd_win <= 0) {
		csk->snd_win = CXGB4I_DEFAULT_10G_SND_WIN;
		snd_winf = linkspeed/SPEED_10000;
		if (snd_winf)
			csk->snd_win *= snd_winf;
	}
	csk->wr_cred = lldi->wr_cred -
		       DIV_ROUND_UP(sizeof(struct cpl_abort_req), 16);
	csk->wr_max_cred = csk->wr_cred;
	csk->wr_una_cred = 0;
	cxgbi_sock_reset_wr_list(csk);
	csk->err = 0;

	pr_info_ipaddr("csk 0x%p,%u,0x%lx,"
		"%u,%u,%u, mtu %u,%u, smac %u.\n",
		(&csk->saddr),
		(&csk->daddr),
		csk, csk->state, csk->flags, csk->tx_chan, csk->txq_idx,
		csk->rss_qid, csk->mtu, csk->mss_idx, csk->smac_idx);

	/* must wait for either a act_open_rpl or act_open_establish */
	try_module_get(THIS_MODULE);
	cxgbi_sock_set_state(csk, CTP_ACTIVE_OPEN);
	if (csk->csk_family == AF_INET)
		send_act_open_req(csk, skb, csk->l2t);
	else
		send_act_open_req6(csk, skb, csk->l2t);
#if defined DEFINED_DST_NEIGH_LOOKUP
	neigh_release(n);
#endif
	return 0;

rel_resource:
#ifdef CXGBI_IPV6_SUPPORT
	if (csk->csk_family == AF_INET6)
		cxgb4_clip_release(ndev,
			(const u32 *)&(csk->saddr6.sin6_addr), 1);
#endif
rel_resource_without_clip:
#if defined DEFINED_DST_NEIGH_LOOKUP
	if (n)
		neigh_release(n);
#endif
	if (skb)
		__kfree_skb(skb);
	return -EINVAL;
}

cxgb4i_cplhandler_func cxgb4i_cplhandlers[NUM_CPL_CMDS] = {
	[CPL_ACT_ESTABLISH] = do_act_establish,
	[CPL_ACT_OPEN_RPL] = do_act_open_rpl,
	[CPL_PEER_CLOSE] = do_peer_close,
	[CPL_ABORT_REQ_RSS] = do_abort_req_rss,
	[CPL_ABORT_RPL_RSS] = do_abort_rpl_rss,
	[CPL_CLOSE_CON_RPL] = do_close_con_rpl,
	[CPL_FW4_ACK] = do_fw4_ack,
	[CPL_SET_TCB_RPL] = do_set_tcb_rpl,
	[CPL_ISCSI_HDR] = do_rx_iscsi_hdr,
	[CPL_RX_ISCSI_DDP] = do_rx_data_ddp,
	[CPL_RX_ISCSI_CMP] = do_rx_iscsi_cmp,
	[CPL_ISCSI_DATA] = do_rx_iscsi_data,
	[CPL_RX_DATA_DDP] = do_rx_data_ddp,
#ifdef CXGBI_T10DIF_SUPPORT
	[CPL_RX_ISCSI_DIF] = do_rx_iscsi_dif,
#endif
	[CPL_FW6_MSG] = do_fw6_msg,
	[CPL_RX_DATA] = do_rx_data,
	[CPL_RX_PKT] = do_rx_pkt
};

int cxgb4i_ofld_init(struct cxgbi_device *cdev)
{
	int rc;

	if (cxgb4i_max_connect > CXGB4I_MAX_CONN)
		cxgb4i_max_connect = CXGB4I_MAX_CONN;

	rc = cxgbi_device_portmap_create(cdev, cxgb4i_sport_base,
					cxgb4i_max_connect);
	if (rc < 0)
		return rc;

	cdev->csk_release_offload_resources = release_offload_resources;
	cdev->csk_push_tx_frames = push_tx_frames;
	cdev->csk_send_abort_req = send_abort_req;
	cdev->csk_send_close_req = send_close_req;
	cdev->csk_send_rx_credits = send_rx_credits;
	cdev->csk_alloc_cpls = alloc_cpls;
	cdev->csk_init_act_open = init_act_open;

	pr_info("cdev 0x%p, offload up, added, flag 0x%x.\n",
		cdev, cdev->flags);
	return 0;
}

/*
 * functions to program the pagepod in h/w
 */
static inline void ulp_mem_io_set_hdr(struct cxgbi_device *cdev,
				struct ulp_mem_io *req,
				unsigned int wr_len, unsigned int dlen,
				unsigned int pm_addr,
				int tid, int imm_write)
{
	struct cxgb4_lld_info *lldi = cxgbi_cdev_priv(cdev);
	struct ulptx_idata *idata = (struct ulptx_idata *)(req + 1);

	INIT_ULPTX_WR(req, wr_len, 0, tid);
	req->wr.wr_hi = htonl(V_FW_WR_OP(FW_ULPTX_WR) |
		V_FW_WR_ATOMIC(0));
	req->cmd = htonl(ULPTX_CMD(ULP_TX_MEM_WRITE) |
		V_ULP_MEMIO_ORDER(is_t4(lldi->adapter_type)) |
		V_T5_ULP_MEMIO_IMM(!is_t4(lldi->adapter_type) && imm_write));
	req->dlen = htonl(ULP_MEMIO_DATA_LEN(dlen >> 5));
	req->lock_addr = htonl(ULP_MEMIO_ADDR(pm_addr >> 5));
	req->len16 = htonl(DIV_ROUND_UP(wr_len - sizeof(req->wr), 16));

	if (imm_write) {
		idata->cmd_more = htonl(ULPTX_CMD(ULP_TX_SC_IMM));
		idata->len = htonl(dlen);
	}
}

static struct sk_buff *ddp_ppod_init_idata(struct cxgbi_device *cdev,
					struct cxgbi_ppm *ppm,
					unsigned int idx, unsigned int npods,
					unsigned int tid)
{
	unsigned int pm_addr = (idx << PPOD_SIZE_SHIFT) + ppm->llimit;
	unsigned int dlen = npods << PPOD_SIZE_SHIFT;
	unsigned int wr_len = roundup(sizeof(struct ulp_mem_io) +
				sizeof(struct ulptx_idata) + dlen, 16);
	struct sk_buff *skb = alloc_wr(wr_len, 0, GFP_ATOMIC);

	if (!skb) {
		pr_err("%s: %s idx %u, npods %u, OOM.\n",
			__func__, ppm->ndev->name, idx, npods);
		return NULL;
	}
	
	ulp_mem_io_set_hdr(cdev, (struct ulp_mem_io *)skb->head, wr_len, dlen,
			 pm_addr, tid, 1);

	return skb;
}

static int ddp_ppod_write_idata(struct cxgbi_ppm *ppm, struct cxgbi_sock *csk,
				struct cxgbi_task_tag_info *ttinfo,
				unsigned int idx, unsigned int npods,
				struct scatterlist **sg_pp,
				unsigned int *sg_off)
{
	struct cxgbi_device *cdev = csk->cdev;
	struct sk_buff *skb = ddp_ppod_init_idata(cdev, ppm, idx, npods,
						csk->tid);
        struct ulp_mem_io *req;
	struct ulptx_idata *idata;
        struct cxgbi_pagepod *ppod;
	int i;

	if (!skb)
		return -ENOMEM;

        req = (struct ulp_mem_io *)skb->head;
 	idata = (struct ulptx_idata *)(req + 1);
	ppod = (struct cxgbi_pagepod *)(idata + 1);

	for (i = 0; i < npods; i++, ppod++)
		cxgbi_ddp_set_one_ppod(ppod, ttinfo, sg_pp, sg_off);

	if (cdev->flags & CXGBI_FLAG_USE_PPOD_OFLDQ) {
		cxgbi_skcb_set_flag(skb, SKCBF_TX_MEM_WRITE);
		cxgbi_skcb_set_flag(skb, SKCBF_TX_FLAG_COMPL);
		set_wr_txq(skb, CPL_PRIORITY_DATA, csk->port_id);

		spin_lock_bh(&csk->lock);
		cxgbi_sock_skb_entail(csk, skb);
		spin_unlock_bh(&csk->lock);
	} else {
		set_wr_txq(skb, CPL_PRIORITY_CONTROL, ttinfo->cid);
		cxgb4_ofld_send(cdev->ports[ttinfo->cid], skb);
	}

	return 0;
}

static int ddp_ppod_write_dsgl(struct cxgbi_ppm *ppm, struct cxgbi_sock *csk,
				struct cxgbi_task_tag_info *ttinfo,
				unsigned int idx, unsigned int npods,
				struct scatterlist **sg_pp,
				unsigned int *sg_off)
{
	struct cxgbi_device *cdev = csk->cdev;
	struct sk_buff *skb;
	struct ulp_mem_io *req;
	struct cxgbi_pagepod *ppod;
	unsigned int pm_addr = (idx << PPOD_SIZE_SHIFT) + ppm->llimit;
	unsigned int dlen = npods << PPOD_SIZE_SHIFT;
	unsigned int wr_len = roundup(sizeof(struct ulp_mem_io), 16);
	unsigned int i;

	skb = alloc_skb(cdev->skb_tx_rsvd + wr_len + dlen, GFP_ATOMIC);
	if (!skb) {
		pr_err("cdev 0x%p, idx %u, npods %u, OOM.\n",
			cdev, idx, npods);
		return -ENOMEM;
	}

	skb_reserve(skb, cdev->skb_tx_rsvd);
	req = (struct ulp_mem_io *)skb->data;

	skb_put(skb, wr_len + dlen);
	skb_set_transport_header(skb, wr_len);
	ulp_mem_io_set_hdr(cdev, req, (8 * calc_tx_flits_ofld(skb)),
				dlen, pm_addr, csk->tid, 0);

	ppod = (struct cxgbi_pagepod *)(req + 1);

	for (i = 0; i < npods; i++, ppod++)
		cxgbi_ddp_set_one_ppod(ppod, ttinfo, sg_pp, sg_off);

	cxgbi_skcb_set_flag(skb, SKCBF_TX_MEM_WRITE);
	cxgbi_skcb_set_flag(skb, SKCBF_TX_FLAG_COMPL);
	set_wr_txq(skb, CPL_PRIORITY_DATA, csk->port_id);

	spin_lock_bh(&csk->lock);
	cxgbi_sock_skb_entail(csk, skb);
	spin_unlock_bh(&csk->lock);

	return 0;
}

static int ddp_set_map(struct cxgbi_ppm *ppm, struct cxgbi_sock *csk,
			struct cxgbi_task_tag_info *ttinfo)
{
	unsigned int pidx = ttinfo->idx;
	unsigned int npods = ttinfo->npods;
	unsigned int i, cnt;
	int err = 0;
	unsigned int wr_len, dlen;
	struct scatterlist *sg = ttinfo->sgl;
	unsigned int offset = 0;

	ttinfo->cid = csk->port_id;

	for (i = 0; i < npods; i += cnt, pidx += cnt) {
		cnt = npods - i;
		dlen = IPPOD_SIZE * cnt;

		/* need to decide if we should use imm or dsg write to send
		 * cnt ppod. We are writing ppod using ofldq now. */
		wr_len = roundup(dlen, 16);
		if ((wr_len > MAX_IMM_TX_PKT_LEN) &&
			(csk->cdev->flags & CXGBI_FLAG_ULPTX_DSGL)) {
			if (cnt > ULPMEM_DSGL_MAX_NPPODS)
				cnt = ULPMEM_DSGL_MAX_NPPODS;
			err = ddp_ppod_write_dsgl(ppm, csk, ttinfo, pidx, cnt,
						&sg, &offset);
		} else {
			if (cnt > ULPMEM_IDATA_MAX_NPPODS)
				cnt = ULPMEM_IDATA_MAX_NPPODS;
			err = ddp_ppod_write_idata(ppm, csk, ttinfo, pidx, cnt,
						&sg, &offset);
		}
		if (err < 0)
			break;
	}

	return err;
}

static void ddp_clear_map(struct cxgbi_device *cdev, struct cxgbi_ppm *ppm,
			struct cxgbi_task_tag_info *ttinfo)
{
	struct sk_buff *skb;
	struct ulp_mem_io *req;
	struct ulptx_idata *idata;
	struct cxgbi_pagepod *ppod;

	if (cdev->flags & CXGBI_FLAG_USE_PPOD_OFLDQ)
		return;

	skb = ddp_ppod_init_idata(cdev, ppm, ttinfo->idx, 1, 0);
	if (!skb)
		return;

        req = (struct ulp_mem_io *)skb->head;
	idata = (struct ulptx_idata *)(req + 1);
	ppod = (struct cxgbi_pagepod *)(idata + 1);

	ppod->hdr.vld_tid = 0;

	set_wr_txq(skb, CPL_PRIORITY_CONTROL, ttinfo->cid);
	cxgb4_ofld_send(cdev->ports[ttinfo->cid], skb);
}

static int ddp_setup_conn_pgidx(struct cxgbi_sock *csk, unsigned int tid,
				int pg_idx, bool reply)
{
	struct sk_buff *skb;
	struct cpl_set_tcb_field *req;

	if (!pg_idx || pg_idx >= DDP_PGIDX_MAX)
		return 0;

	skb = alloc_wr(sizeof(*req), 0, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	req = (struct cpl_set_tcb_field *)skb->head;
	INIT_TP_WR(req, csk->tid);
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_SET_TCB_FIELD, csk->tid));
	req->reply_ctrl = htons(NO_REPLY(reply) | QUEUENO(csk->rss_qid));
	req->word_cookie = htons(0);
	req->mask = cpu_to_be64(0x3 << 8);
	req->val = cpu_to_be64(pg_idx << 8);
	set_wr_txq(skb, CPL_PRIORITY_CONTROL, csk->port_id);

	log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_SOCK,
		"csk 0x%p, tid 0x%x, pg_idx %u.\n", csk, csk->tid, pg_idx);

	cxgb4_ofld_send(csk->cdev->ports[csk->port_id], skb);
	return 0;
}

static int ddp_setup_conn_digest(struct cxgbi_sock *csk, unsigned int tid,
				 int hcrc, int dcrc, int reply)
{
	struct sk_buff *skb;
	struct cpl_set_tcb_field *req;

	if (!hcrc && !dcrc)
		return 0;

	skb = alloc_wr(sizeof(*req), 0, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	csk->hcrc_len = (hcrc ? 4 : 0);
	csk->dcrc_len = (dcrc ? 4 : 0);
	/*  set up ulp submode and page size */
	req = (struct cpl_set_tcb_field *)skb->head;
	INIT_TP_WR(req, tid);
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_SET_TCB_FIELD, tid));
	req->reply_ctrl = htons(NO_REPLY(reply) | QUEUENO(csk->rss_qid));
	req->word_cookie = htons(0);
	req->mask = cpu_to_be64(0x3 << 4);
	req->val = cpu_to_be64(((hcrc ? ULP_CRC_HEADER : 0) |
				(dcrc ? ULP_CRC_DATA : 0)) << 4);
	set_wr_txq(skb, CPL_PRIORITY_CONTROL, csk->port_id);

	log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_SOCK,
		"csk 0x%p, tid 0x%x, crc %d,%d.\n", csk, csk->tid, hcrc, dcrc);

	cxgb4_ofld_send(csk->cdev->ports[csk->port_id], skb);
	return 0;
}

static struct cxgbi_ppm *cdev2ppm(struct cxgbi_device *cdev)
{
	return (struct cxgbi_ppm *)(*((struct cxgb4_lld_info *)
					(cxgbi_cdev_priv(cdev)))->iscsi_ppm);
}

static int cxgb4i_ddp_init(struct cxgbi_device *cdev)
{
	struct cxgb4_lld_info *lldi = cxgbi_cdev_priv(cdev);
	struct net_device *ndev = cdev->ports[0];
	struct cxgbi_tag_format tformat;
	unsigned int ppmax;
	int i;

	if (!lldi->vr->iscsi.size) {
		pr_warn("%s, iscsi NOT enabled, check config!\n", ndev->name);
		return -EACCES; 
	}

	ppmax = lldi->vr->iscsi.size >> PPOD_SIZE_SHIFT;

	memset(&tformat, 0, sizeof(struct cxgbi_tag_format));
	for (i = 0; i < 4; i++)
		tformat.pgsz_order[i] = (lldi->iscsi_pgsz_order >> (i << 3))
					& 0xF;
	cxgbi_tagmask_check(lldi->iscsi_tagmask, &tformat);

	cxgbi_ddp_ppm_setup(lldi->iscsi_ppm, cdev, &tformat, ppmax,
				lldi->iscsi_llimit, lldi->vr->iscsi.start,
				ppm_rsvd_factor);

	cdev->csk_ddp_setup_digest = ddp_setup_conn_digest;
	cdev->csk_ddp_setup_pgidx = ddp_setup_conn_pgidx;
	cdev->csk_ddp_set_map = ddp_set_map;

	if (!(cdev->flags & CXGBI_FLAG_USE_PPOD_OFLDQ))
		cdev->csk_ddp_clear_map = ddp_clear_map;

	return 0;
}

#ifdef CXGBI_T10DIF_SUPPORT
static inline int is_t10dif_enabled(const struct cxgb4_lld_info *lldi)
{
	int t4 = is_t4(lldi->adapter_type);

	pr_info("cxgb4i lldi->ulp_t10dif  0x%x\n", lldi->ulp_t10dif);

	return (!t4 && (lldi->ulp_t10dif & ULP_T10DIF_ISCSI));
}
#endif

static void *t4_uld_add(const struct cxgb4_lld_info *lldi)
{
	struct cxgbi_device *cdev;
	struct net_device *ndev;
	struct port_info *pi;
	int i, rc;
#ifdef CXGBI_T10DIF_SUPPORT
	unsigned int dif_dix = 0, guard = SHOST_DIX_GUARD_IP;
#endif

	cdev = cxgbi_device_register(sizeof(*lldi), lldi->nports);
	if (!cdev) {
		pr_err("t4 device 0x%p, register failed.\n", lldi);
		return NULL;
	}
	pr_info("0x%p,0x%x, ports %u,%s, chan %u, q %u,%u, wr %u.\n",
		cdev, lldi->adapter_type, lldi->nports,
		lldi->ports[0]->name, lldi->nchan, lldi->ntxq,
		lldi->nrxq, lldi->wr_cred);

	if (!lldi->ntxq || !lldi->nrxq) {
		pr_err("cxgb4 iscsi support NOT enabled? qsets: %u,%u.\n",
			lldi->ntxq, lldi->nrxq);
		return NULL;
	}
	for (i = 0; i < lldi->nrxq; i++)
		log_debug(1 << CXGBI_DBG_DEV,
			"t4 0x%p, rxq id #%d: %u.\n",
			cdev, i, lldi->rxq_ids[i]);
 
	memcpy(cxgbi_cdev_priv(cdev), lldi, sizeof(*lldi));
	cdev->flags = CXGBI_FLAG_DEV_T4;

	cdev->lldev = cxgbi_cdev_priv(cdev);
	cdev->pdev = lldi->pdev;
	cdev->ports = lldi->ports;
	cdev->nports = lldi->nports;
	cdev->mtus = lldi->mtus;
	cdev->nmtus = NMTUS;
	cdev->rx_credit_thres = cxgb4i_rx_credit_thres;
	cdev->skb_tx_rsvd = CXGB4I_TX_HEADER_LEN;

	ndev = cdev->ports[0];
	if (ddp_off) {
		pr_info("%s, 0x%p, ddp off.\n", ndev->name, cdev);
		cdev->flags |= CXGBI_FLAG_DDP_OFF;
	}
	if (ppod_ofldq && !is_t4(lldi->adapter_type)) {
		pr_info("%s, 0x%p, using ofldq to write ppod.\n",
			ndev->name, cdev);
		cdev->flags |= CXGBI_FLAG_USE_PPOD_OFLDQ;
	}
	if (lldi->ulptx_memwrite_dsgl) {
		pr_info("%s, 0x%p, using dsg and ofldq to write ppod.\n",
			ndev->name, cdev);
		cdev->flags |= CXGBI_FLAG_ULPTX_DSGL;
		cdev->flags |= CXGBI_FLAG_USE_PPOD_OFLDQ;
	}

	if (is_t6(lldi->adapter_type))
		cdev->force = F_T6_TX_FORCE;

#ifdef CXGBI_T10DIF_SUPPORT
	/* Disable T10DIF offset workaround in T6. */
	if (is_t6(lldi->adapter_type))
		cdev->flags |= CXGBI_FLAG_T10DIF_OFFSET_UPDATED;

	if (prot_en && is_t10dif_enabled(lldi)) {
		cdev->skb_t10dif_txhdr = sizeof(struct fw_tx_pi_header);

		/* DIX */
		dif_dix = SHOST_DIX_TYPE0_PROTECTION |
			SHOST_DIX_TYPE1_PROTECTION |
			SHOST_DIX_TYPE2_PROTECTION |
			SHOST_DIX_TYPE3_PROTECTION;

		if (prot_en == 2) {
			/* end-to-end i.e. DIF and DIX */
			dif_dix |= SHOST_DIF_TYPE1_PROTECTION |
				SHOST_DIF_TYPE2_PROTECTION |
				SHOST_DIF_TYPE3_PROTECTION;
			/* Note: If DDP fails then guard conversion
 			 * from ip csum to CRC will not be done,
 			 * therefore set guard as CRC. */
			guard = SHOST_DIX_GUARD_CRC;

			/* iso and dif cannot work together on T5. PR 26709 */
			if (is_t5(lldi->adapter_type))
				iso_on = 0;
		}
	} else
		prot_en = 0;
#endif
	/* ISO feature is always enabled if its available in fw (added
 	 * in fw version 1.13.43 onwards */
	if (iso_on && !is_t4(lldi->adapter_type) &&
	    (lldi->fw_vers >= 0x10d2b00))
		cdev->skb_iso_txhdr = sizeof(struct cpl_tx_data_iso);

	cdev->skb_rx_extra = sizeof(struct cpl_iscsi_hdr);
	cdev->itp = &cxgb4i_iscsi_transport;

	cdev->pfvf = G_FW_VIID_PFN(cxgb4_port_viid(lldi->ports[0]))
			 << S_FW_VIID_PFN;
	log_debug(1 << CXGBI_DBG_DEV,
		"t4 0x%p, pfvf %u.\n", cdev, cdev->pfvf);

	cdev->tx_max_size = min_t(unsigned int, ULP2_MAX_PDU_PAYLOAD,
                                lldi->iscsi_iolen - ISCSI_PDU_NONPAYLOAD_LEN);
        cdev->rx_max_size = min_t(unsigned int, ULP2_MAX_PDU_PAYLOAD,
                                lldi->iscsi_iolen - ISCSI_PDU_NONPAYLOAD_LEN);

	cdev->cdev2ppm = cdev2ppm;

	rc = cxgb4i_ddp_init(cdev);
	if (rc) {
		pr_info("%s, 0x%p ddp init failed.\n", ndev->name, cdev);
		goto err_out;
	}
	rc = cxgb4i_ofld_init(cdev);
	if (rc) {
		pr_info("%s 0x%p ofld init failed.\n", ndev->name, cdev);
		goto err_out;
	}

	if (cxgb4i_sg_tablesize)
		cxgb4i_host_template.sg_tablesize = cxgb4i_sg_tablesize;
	rc = cxgbi_hbas_add(cdev, CXGB4I_MAX_LUN, CXGBI_MAX_CONN,
				CXGB4I_SCSI_HOST_QDEPTH_MAX,
				CXGB4I_SCSI_HOST_QDEPTH_MIN,
				&cxgb4i_host_template, cxgb4i_stt);
	if (rc)
		goto err_out;

	for (i = 0; i < cdev->nports; i++) {
		pi = netdev_priv(lldi->ports[i]);
		cdev->hbas[i]->port_id = pi->port_id;
	}

	pr_info("0x%p, lro %s, iso %s, sg_tablesize %u/%u.\n",
		cdev, (lro_on && is_t5(lldi->adapter_type)) ?
			 "enabled" : "disabled",
		cdev->skb_iso_txhdr ? "enabled" : "disabled",
		cxgb4i_host_template.sg_tablesize, cxgb4i_sg_tablesize);

#ifdef CXGBI_T10DIF_SUPPORT
	pr_info("t10dif %s, dif_dix 0x%x, guard %u\n",
			prot_en?"enabled":"disabled", dif_dix, guard);
	if (prot_en) {
		cxgbi_prot_register(cdev, dif_dix, guard);

		pr_info("tx pi rsvd pages %u\n", MAX_TX_PI_RSVD_PAGES);
		cxgbi_tx_pi_page_pool_init(cdev, MAX_TX_PI_RSVD_PAGES);
	}
#endif
	return cdev;

err_out:
	cxgbi_device_unregister(cdev);
	return ERR_PTR(-ENOMEM);
}

#define RX_PULL_LEN	128
#ifdef CXGB4_T4_PKTGL_TO_SKB
extern struct sk_buff *t4_pktgl_to_skb(const struct pkt_gl *gl,
					unsigned int skb_len,
					unsigned int pull_len);
#define cxgb4_pktgl_to_skb	t4_pktgl_to_skb
#endif

static int t4_uld_rx_handler(void *handle, const __be64 *rsp,
				const struct pkt_gl *pgl)
{
	const struct cpl_act_establish *rpl;
	struct sk_buff *skb;
	unsigned int opc;
	struct cxgbi_device *cdev = handle;

	if (pgl == NULL) {
		unsigned int len = 64 - sizeof(struct rsp_ctrl) - 8;

		skb = alloc_wr(len, 0, GFP_ATOMIC);
		if (!skb)
			goto nomem;
		skb_copy_to_linear_data(skb, &rsp[1], len);
	} else {
		if (unlikely(*(u8 *)rsp != *(u8 *)pgl->va)) {
			pr_info("? FL 0x%p,RSS%#llx,FL %#llx,len %u.\n",
				pgl->va, be64_to_cpu(*rsp),
				be64_to_cpu(*(u64 *)pgl->va),
				pgl->tot_len);
			return 0;
		}
#ifdef CXGB4_NAPI_ALLOC_SKB
		skb = cxgb4_pktgl_to_skb(NULL, pgl, RX_PULL_LEN,
					RX_PULL_LEN);
#else
		skb = cxgb4_pktgl_to_skb(pgl, RX_PULL_LEN, RX_PULL_LEN);
#endif
		if (unlikely(!skb))
			goto nomem;
	}

	rpl = (struct cpl_act_establish *)skb->data;
	opc = rpl->ot.opcode;
	log_debug(1 << CXGBI_DBG_TOE,
		"cdev %p, opcode 0x%x(0x%x,0x%x), skb %p.\n",
		 cdev, opc, rpl->ot.opcode_tid, ntohl(rpl->ot.opcode_tid), skb);
	if (opc < NUM_CPL_CMDS && cxgb4i_cplhandlers[opc])
		cxgb4i_cplhandlers[opc](cdev, skb);
	else {
		pr_err("No handler for opcode 0x%x.\n", opc);
		__kfree_skb(skb);
	}
	return 0;
nomem:
	log_debug(1 << CXGBI_DBG_TOE, "OOM bailing out.\n");
	return 1;
}

static int t4_uld_state_change(void *handle, enum cxgb4_state state)
{
	struct cxgbi_device *cdev = handle;

	switch (state) {
	case CXGB4_STATE_UP:
		pr_info("cdev 0x%p, UP.\n", cdev);
		/* re-initialize */
		break;
	case CXGB4_STATE_START_RECOVERY:
		pr_info("cdev 0x%p, RECOVERY.\n", cdev);
		/* close all connections */
		break;
	case CXGB4_STATE_DOWN:
		pr_info("cdev 0x%p, DOWN.\n", cdev);
		break;
	case CXGB4_STATE_DETACH:
		pr_info("cdev 0x%p, DETACH.\n", cdev);
		cxgbi_device_unregister(cdev);
		break;
	default:
		pr_info("cdev 0x%p, unknown state %d.\n", cdev, state);
		break;
	}
	return 0;
}

#ifdef __CONFIG_CXGB4_DCB__
static int cxgb4_dcb_change_notify(struct notifier_block *self,
				unsigned long val, void *data)
{
	int i, port = 0xFF;
	struct net_device *ndev;
	struct cxgbi_device *cdev = NULL;
	struct dcb_app_type *iscsi_app = data;
	struct cxgbi_ports_map *pmap;
	u8 priority;

	if (iscsi_app->dcbx & DCB_CAP_DCBX_VER_IEEE) {
		if (iscsi_app->app.selector != IEEE_8021QAZ_APP_SEL_ANY)
			return NOTIFY_DONE;

		priority = iscsi_app->app.priority;

	} else if (iscsi_app->dcbx & DCB_CAP_DCBX_VER_CEE) {
		if (iscsi_app->app.selector != DCB_APP_IDTYPE_PORTNUM)
			return NOTIFY_DONE;

		if (!iscsi_app->app.priority)
			return NOTIFY_DONE;

		priority = ffs(iscsi_app->app.priority) - 1;
	} else {
		return NOTIFY_DONE;
	}
	
	if (iscsi_app->app.protocol != 3260)
		return NOTIFY_DONE;

#ifdef DCB_APP_TYPE_HAS_IFIDX
	log_debug(1 << CXGBI_DBG_ISCSI,
		  "iSCSI priority for ifid %d is %u\n",
			iscsi_app->ifindex, priority);

	ndev = dev_get_by_index(&init_net, iscsi_app->ifindex);
#else
	/* instead of ifindex, it is dcb_app_type.name */
	log_debug(1 << CXGBI_DBG_ISCSI,
		  "iSCSI priority for %s is %u\n",
			iscsi_app->name, priority);

	ndev = dev_get_by_name(&init_net, iscsi_app->name);
#endif
	if (!ndev)
		return NOTIFY_DONE;

	cdev = cxgbi_device_find_by_netdev_rcu(ndev, &port);

	dev_put(ndev);

	if (!cdev)
		return NOTIFY_DONE;

	pmap = &cdev->pmap;
	for (i = 0; i < pmap->used; i++) {
		if (pmap->port_csk[i]) {
			struct cxgbi_sock *csk = pmap->port_csk[i];

			if (csk->dcb_priority != priority) {
				iscsi_conn_failure(csk->user_data,
						ISCSI_ERR_CONN_FAILED);
				pr_info("Restarting iSCSI connection %p with "
					"priority %u->%u.\n",
					csk, csk->dcb_priority,
					priority);
			}
		}
	}
	return NOTIFY_OK;
}
#endif

static void proc_ddp_status(unsigned int tid, struct cpl_rx_data_ddp *cpl,
			struct cxgbi_rx_pdu_cb *pdu_cb)
{
	unsigned int status = ntohl(cpl->ddpvld);
	
	cxgbi_rx_cb_set_flag(pdu_cb, SKCBF_RX_STATUS);

	pdu_cb->ddigest = ntohl(cpl->ulp_crc);
	pdu_cb->pdulen = ntohs(cpl->len);

	if (status & (1 << CPL_RX_ISCSI_DDP_STATUS_HCRC_SHIFT)) {
		pr_info("tid 0x%x, status 0x%x, hcrc bad.\n", tid, status);
		cxgbi_rx_cb_set_flag(pdu_cb, SKCBF_RX_HCRC_ERR);
        }
	if (status & (1 << CPL_RX_ISCSI_DDP_STATUS_DCRC_SHIFT)) {
		pr_info("tid 0x%x, status 0x%x, dcrc bad.\n", tid, status);
		cxgbi_rx_cb_set_flag(pdu_cb, SKCBF_RX_DCRC_ERR);
	}
	if (status & (1 << CPL_RX_ISCSI_DDP_STATUS_PAD_SHIFT)) {
		pr_info("tid 0x%x, status 0x%x, pad bad.\n", tid, status);
		cxgbi_rx_cb_set_flag(pdu_cb, SKCBF_RX_PAD_ERR);
	}
	if ((status & (1 << CPL_RX_ISCSI_DDP_STATUS_DDP_SHIFT)) &&
		!cxgbi_rx_cb_test_flag(pdu_cb, SKCBF_RX_DATA)) {
//pr_info("tid 0x%x, status 0x%x, data ddp'ed.\n", tid, status);
		cxgbi_rx_cb_set_flag(pdu_cb, SKCBF_RX_DATA_DDPD);
	}
}

static int lro_skb_add_packet_rsp(struct sk_buff *skb, u8 op,
					const __be64 *rsp) 
{
	struct cxgbi_rx_lro_cb *lro_cb = cxgbi_skb_rx_lro_cb(skb);
	struct cxgbi_rx_pdu_cb *pdu_cb = cxgbi_skb_rx_pdu_cb(skb, 0);
	struct cpl_rx_iscsi_ddp *cpl = (struct cpl_rx_iscsi_ddp *)(rsp + 1);

	if (lro_cb->pdu_cnt) {
		pr_err("ERR csk 0x%p, op 0x%x, hskb 0x%p pdu compl.\n",
			lro_cb->csk, op, skb);
		cxgbi_lro_skb_dump(skb);
		return -EINVAL;
	}
	
	proc_ddp_status(lro_cb->csk->tid, cpl, pdu_cb);

	lro_cb->pdu_totallen = pdu_cb->pdulen;
	lro_cb->pdu_cnt = 1;

	return 0;
}

static int lro_skb_add_packet_gl(struct sk_buff *skb, u8 op,
				const struct pkt_gl *gl)
{
	struct cxgbi_rx_lro_cb *lro_cb = cxgbi_skb_rx_lro_cb(skb);
	struct cxgbi_rx_pdu_cb *pdu_cb = cxgbi_skb_rx_pdu_cb(skb, 0);
	struct skb_shared_info *ssi = skb_shinfo(skb);
	int i = ssi->nr_frags;
	unsigned int offset;
	unsigned int len;

	if (lro_cb->pdu_cnt) {
		pr_err("csk 0x%p, op 0x%x, hskb 0x%p pdu compl.\n",
			lro_cb->csk, op, skb);
		cxgbi_lro_skb_dump(skb);
		return -EINVAL;
	}

	if (op == CPL_ISCSI_HDR) {
		struct cpl_iscsi_hdr *cpl = (struct cpl_iscsi_hdr *)gl->va;

		offset = sizeof(struct cpl_iscsi_hdr);
		cxgbi_rx_cb_set_flag(pdu_cb, SKCBF_RX_HDR);

		pdu_cb->seq = ntohl(cpl->seq);
		len = ntohs(cpl->len);
	} else {
		struct cpl_iscsi_data *cpl = (struct cpl_iscsi_data *)gl->va;

		offset = sizeof(struct cpl_iscsi_data);
		cxgbi_rx_cb_set_flag(pdu_cb, SKCBF_RX_DATA);

		len = ntohs(cpl->len);
	}

	memcpy(&ssi->frags[i], &gl->frags[0], gl->nfrags * sizeof(skb_frag_t));
	ssi->frags[i].page_offset += offset;
	ssi->frags[i].size -= offset;
        ssi->nr_frags += gl->nfrags;
	pdu_cb->frags += gl->nfrags;

	skb->len += len;
	skb->data_len += len;
	skb->truesize += len;

	/* Get a reference for the last page, we don't own it */
	get_page(gl->frags[gl->nfrags -1].page);

	return 0;
}

static inline int cxgbi_sock_check_rx_state(struct cxgbi_sock *csk)
{
	if (unlikely(csk->state >= CTP_PASSIVE_CLOSE)) {
		log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_SOCK,
			"csk 0x%p,%u,0x%lx,%u, bad state.\n",
			csk, csk->state, csk->flags, csk->tid);
		if (csk->state != CTP_ABORTING)
			send_abort_req(csk);
                return -1;
	}
	return 0;
}

static void do_rx_iscsi_lro(struct cxgbi_sock *csk, struct sk_buff *skb)
{
	struct cxgbi_rx_lro_cb *lro_cb = cxgbi_skb_rx_lro_cb(skb);
	struct cxgbi_rx_pdu_cb *pdu_cb = cxgbi_skb_rx_pdu_cb(skb, 0);

	log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_PDU_RX,
		"%s: csk 0x%p,%u,0x%lx, tid %u, skb 0x%p,%u, %u.\n",
		__func__, csk, csk->state, csk->flags, csk->tid, skb, skb->len,
		skb->data_len);

	cxgbi_skcb_set_flag(skb, SKCBF_RX_LRO);

	spin_lock_bh(&csk->lock);

	if (cxgbi_sock_check_rx_state(csk) < 0)
		goto discard;

	if (cxgbi_rx_cb_test_flag(pdu_cb, SKCBF_RX_HDR) &&
	    pdu_cb->seq != csk->rcv_nxt) {
		pr_info("ERR! csk 0x%p, tid 0x%x, seq 0x%x != 0x%x.\n",
			csk, csk->tid, pdu_cb->seq, csk->rcv_nxt);
		cxgbi_lro_skb_dump(skb);
		goto abort_conn;
	}

	if (!lro_cb->pdu_cnt) {
		pr_info("ERR! csk 0x%p, skb 0x%p, NO pdu.\n", csk, skb);
		cxgbi_lro_skb_dump(skb);
		goto abort_conn;
	} else {
		int i, cnt = 0;
		struct skb_shared_info *ssi = skb_shinfo(skb);

		for (i = 0; i < lro_cb->pdu_cnt; i++, pdu_cb++)
			cnt += pdu_cb->frags;
		if (cnt != ssi->nr_frags) {
			pr_info("ERR! csk 0x%p, skb 0x%p, frag %u/%u.\n",
				csk, skb, cnt, ssi->nr_frags);
			cxgbi_lro_skb_dump(skb);
			goto abort_conn;
		}
	}

	csk->rcv_nxt += lro_cb->pdu_totallen;

	skb_reset_transport_header(skb);
	__skb_queue_tail(&csk->receive_queue, skb);

	cxgbi_conn_pdu_ready(csk);
	spin_unlock_bh(&csk->lock);

	return;

abort_conn:
	send_abort_req(csk);
discard:
	spin_unlock_bh(&csk->lock);
	__kfree_skb(skb);
}

static struct sk_buff *lro_init_skb(struct cxgbi_sock *csk, unsigned int len)
{
	struct sk_buff *skb;
	struct cxgbi_rx_lro_cb *lro_cb;

	skb = alloc_skb(len, GFP_ATOMIC);
	if (unlikely(!skb))
		return NULL;

	memset(skb->head, 0, len);
	skb_reserve(skb, len);

	lro_cb = cxgbi_skb_rx_lro_cb(skb);
	cxgbi_sock_get(csk);
	lro_cb->csk = csk;
	
        return skb;
}

static void lro_flush(struct t4_lro_mgr *lro_mgr, struct sk_buff *skb)
{
	struct cxgbi_rx_lro_cb *lro_cb = cxgbi_skb_rx_lro_cb(skb);
	struct cxgbi_sock *csk = lro_cb->csk;

	if (skb->next || skb->prev)
		__skb_unlink(skb, &lro_mgr->lroq);
	if (lro_cb->pdu_cnt) {
       		csk->skb_lro = NULL;
        	do_rx_iscsi_lro(csk, skb);
	} else {
		pr_info("WARN: skb 0x%p, pdu %u, free, skb_lro 0x%p.\n",
			skb, lro_cb->pdu_cnt, csk->skb_lro);
        	csk->skb_lro = NULL;
		__kfree_skb(skb);	
	}
	cxgbi_sock_put(csk);

	lro_mgr->lro_pkts++;
	lro_mgr->lro_session_cnt--;
}

static int lro_skb_add_complete_pdu(struct cxgbi_sock *csk)
{
	struct sk_buff *hskb = csk->skb_lro_hold;
	struct sk_buff *skb = csk->skb_lro;
	struct cxgbi_rx_lro_cb *hlro_cb = cxgbi_skb_rx_lro_cb(hskb);
	struct cxgbi_rx_lro_cb *lro_cb = cxgbi_skb_rx_lro_cb(skb);
	struct cxgbi_rx_pdu_cb *fpdu_cb = cxgbi_skb_rx_pdu_cb(hskb, 0);
	struct cxgbi_rx_pdu_cb *tpdu_cb = cxgbi_skb_rx_pdu_cb(skb,
							lro_cb->pdu_cnt);
	struct skb_shared_info *fssi = skb_shinfo(hskb);
	struct skb_shared_info *tssi = skb_shinfo(skb);
	unsigned int flen = hskb->data_len;

	if (!hskb->len || !hskb->data_len || !fssi->nr_frags ||
	    (hskb->len != hskb->data_len) || fpdu_cb->frags != fssi->nr_frags) {
		pr_err("ERR! hskb len %u/%u, frags %u/%u.\n",
			hskb->len, hskb->data_len, fpdu_cb->frags,
			fssi->nr_frags);
		return -EINVAL;
	}

	lro_cb->pdu_totallen += fpdu_cb->pdulen;
	lro_cb->pdu_cnt++;

	memcpy(tpdu_cb, fpdu_cb, sizeof(struct cxgbi_rx_pdu_cb));

	/* copy frags over */
	memcpy(&tssi->frags[tssi->nr_frags], &fssi->frags[0],
		fssi->nr_frags * sizeof(skb_frag_t));
        tssi->nr_frags += fssi->nr_frags;

	skb->len += flen;
	skb->data_len += flen;
	skb->truesize += flen;

	/* re-initialize hskb */
	memset(hskb->head, 0, LRO_SKB_MIN_HEADROOM);
        fssi->nr_frags = 0;

	hskb->len = 0;
	hskb->data_len = 0;
	hskb->truesize -= flen;

	hlro_cb->csk = csk;

	return 0;
}

static int lro_receive(struct cxgbi_sock *csk, u8 op, const __be64 *rsp,
			const struct pkt_gl *gl, struct t4_lro_mgr *lro_mgr)
{
	struct sk_buff *hskb = csk->skb_lro_hold;
	struct sk_buff *skb = csk->skb_lro;
	struct cxgbi_rx_lro_cb *lro_cb;
	struct cxgb4_lld_info *lldi = cxgbi_cdev_priv(csk->cdev);
	int new_frag = 0;
	int err = 0;

	if (!lro_on || !is_t5(lldi->adapter_type))
		return -EOPNOTSUPP;

	if (!csk) {
		pr_err("%s: csk NULL, op 0x%x.\n", __func__, op);
		goto out;
	}

	/* add the packet to hskb until status is received */
	if (gl) {
		err = lro_skb_add_packet_gl(hskb, op, gl);
		if (err < 0)
			goto out;
	} else {
		struct cxgbi_rx_pdu_cb *pdu_cb = cxgbi_skb_rx_pdu_cb(hskb, 0);

		err = lro_skb_add_packet_rsp(hskb, op, rsp);
		if (err < 0)
			goto out;
		new_frag = pdu_cb->frags;
	} 
	lro_mgr->lro_merged++;

	/* need to flush ? */
	if (skb) {
		lro_cb = cxgbi_skb_rx_lro_cb(skb);

	    	/* lro_cb->pdu_cnt must be less than MAX_SKB_FRAGS */
		if (((skb_shinfo(skb)->nr_frags + new_frag) >= MAX_SKB_FRAGS) ||
		    (lro_cb->pdu_totallen >= LRO_FLUSH_TOTALLEN_MAX) ||
		    (lro_cb->pdu_cnt >= (MAX_SKB_FRAGS - 1))) {
			lro_flush(lro_mgr, skb);
			skb = NULL;
		}
	}

	/* no need to allocate new skb until pdu is complete */
	if (!skb && new_frag) {
		/* Did we reach the hash size limit */
		if (lro_mgr->lro_session_cnt >= MAX_LRO_SESSIONS) {
			pr_info("WARN, max lro sess reached %u >= %u.\n",
				lro_mgr->lro_session_cnt, MAX_LRO_SESSIONS);
			goto out;
		} 

		csk->skb_lro = skb = lro_init_skb(csk, LRO_SKB_MAX_HEADROOM);
		if (unlikely(!skb))
			goto out;
		lro_mgr->lro_session_cnt++;

		__skb_queue_tail(&lro_mgr->lroq, skb);
	}

	if (new_frag) {
		/* this pdu is complete */
		err = lro_skb_add_complete_pdu(csk);
		if (err < 0)
			goto out;
	}

	return 0;

out:
	return -1;
}

#if defined CXGB4_NAPI_ALLOC_SKB
static int t4_uld_rx_lro_handler(void *hndl, const __be64 *rsp,
				const struct pkt_gl *gl,
				struct t4_lro_mgr *lro_mgr,
				struct napi_struct *napi)
#elif defined CXGB4_LRO_HANDLER_NAPI_ID
static int t4_uld_rx_lro_handler(void *hndl, const __be64 *rsp,
				const struct pkt_gl *gl,
				struct t4_lro_mgr *lro_mgr,
				unsigned int napi_id)
#else
static int t4_uld_rx_lro_handler(void *hndl, const __be64 *rsp,
				const struct pkt_gl *gl,
				struct t4_lro_mgr *lro_mgr)
#endif
{
	struct cxgbi_device *cdev = hndl;
	struct cxgb4_lld_info *lldi = cxgbi_cdev_priv(cdev);
	struct cpl_tx_data *rpl = NULL;
	struct cxgbi_sock *csk = NULL;
	unsigned int tid = 0;
	struct sk_buff *skb;
	unsigned int op = *(u8 *)rsp;

	if (lro_mgr && op != CPL_FW6_MSG && 
		(op != CPL_RX_PKT) &&
		/* no RX_DATA yet to flush */
		(op != CPL_ACT_OPEN_RPL)) {
		/* Get the TID of this connection */
 		rpl = gl ? (struct cpl_tx_data *)gl->va :
				(struct cpl_tx_data *)(rsp + 1);
		tid = GET_TID(rpl);
		csk = lookup_tid(lldi->tids, tid);
	}

	/*
	 * Flush the LROed skb on receiving any cpl other than FW4_ACK and
	 * CPL_ISCSI_XXX
	 */
	if (csk && csk->skb_lro && op != CPL_FW6_MSG && op != CPL_ISCSI_HDR &&
		op != CPL_ISCSI_DATA && op != CPL_RX_ISCSI_DDP &&
		op != CPL_RX_ISCSI_DIF && op != CPL_RX_ISCSI_CMP) {
		lro_flush(lro_mgr, csk->skb_lro);
	}

	if (gl == NULL) {
		unsigned int len;

		if (op == CPL_RX_ISCSI_DDP || op == CPL_RX_ISCSI_DIF) {
			if (!lro_receive(csk, op, rsp, NULL, lro_mgr))
				return 0;
		}

 		len = 64 - sizeof(struct rsp_ctrl) - 8;
		skb = alloc_wr(len, 0, GFP_ATOMIC);
		if (!skb)
			goto nomem;
		skb_copy_to_linear_data(skb, &rsp[1], len);
	} else {
		if (unlikely(op != *(u8 *)gl->va)) {
			pr_info("? FL 0x%p,RSS%#llx,FL %#llx,len %u.\n",
				gl->va, be64_to_cpu(*rsp),
				be64_to_cpu(*(u64 *)gl->va),
				gl->tot_len);
			return 0;
		}

		if (op == CPL_ISCSI_HDR || op == CPL_ISCSI_DATA) {
			if (!lro_receive(csk, op, rsp, gl, lro_mgr))
				return 0;
		}

#ifdef CXGB4_NAPI_ALLOC_SKB
		skb = cxgb4_pktgl_to_skb(napi, gl, RX_PULL_LEN,
					RX_PULL_LEN);
#else
		skb = cxgb4_pktgl_to_skb(gl, RX_PULL_LEN, RX_PULL_LEN);
#endif
		if (unlikely(!skb))
			goto nomem;
	}

	rpl = (struct cpl_tx_data *)skb->data;
	op = rpl->ot.opcode;
	log_debug(1 << CXGBI_DBG_TOE,
		"cdev %p, opcode 0x%x(0x%x,0x%x), skb %p.\n",
		 cdev, op, rpl->ot.opcode_tid, ntohl(rpl->ot.opcode_tid), skb);

	if (op < NUM_CPL_CMDS && cxgb4i_cplhandlers[op])
		cxgb4i_cplhandlers[op](cdev, skb);
	else {
		pr_err("No handler for opcode 0x%x.\n", op);
		__kfree_skb(skb);
	}
	return 0;
nomem:
	log_debug(1 << CXGBI_DBG_TOE, "OOM bailing out.\n");
	return 1;
}

static void t4_uld_lro_flush_all(struct t4_lro_mgr *lro_mgr)
{
	struct sk_buff *skb;

	while ((skb = __skb_dequeue(&lro_mgr->lroq)) != NULL) {
		lro_flush(lro_mgr, skb);
	}
	__skb_queue_head_init(&lro_mgr->lroq);
}


static const struct cxgb4_uld_info cxgb4i_uld_info = {
	.name = DRV_MODULE_NAME,
	.add = t4_uld_add,
	.rx_handler = t4_uld_rx_handler,
	.state_change = t4_uld_state_change,
	.lro_rx_handler = t4_uld_rx_lro_handler,
	.lro_flush = t4_uld_lro_flush_all,
};


static int __init cxgb4i_init_module(void)
{
	int rc;

	printk(KERN_INFO "%s.\n", version);

	rc = cxgbi_iscsi_init(&cxgb4i_iscsi_transport, &cxgb4i_stt);
	if (rc < 0)
		return rc;
	cxgb4_register_uld(CXGB4_ULD_ISCSI, &cxgb4i_uld_info);

#if defined __CXGB4TOE__ && defined __CONFIG_CXGB4_DCB__
	printk(KERN_INFO "%s dcb enabled.\n", DRV_MODULE_NAME);
	register_dcbevent_notifier(&cxgb4_dcb_change);
#endif
	return 0;
}

static void __exit cxgb4i_exit_module(void)
{
#ifdef __CONFIG_CXGB4_DCB__
	unregister_dcbevent_notifier(&cxgb4_dcb_change);
#endif

	cxgb4_unregister_uld(CXGB4_ULD_ISCSI);
	cxgbi_device_unregister_all(CXGBI_FLAG_DEV_T4);
	cxgbi_iscsi_cleanup(&cxgb4i_iscsi_transport, &cxgb4i_stt);
}

module_init(cxgb4i_init_module);
module_exit(cxgb4i_exit_module);
