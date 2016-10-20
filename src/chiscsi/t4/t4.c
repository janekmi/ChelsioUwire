/*
 * Chelsio T4xx support
 * -- only coalesced iscsi cpl msg is supported
 */

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#ifdef KERNEL_HAS_KCONFIG_H
#include <linux/kconfig.h>
#endif

#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/highmem.h>
#include <net/sock.h>

#include <common/version.h>
#include <common/iscsi_offload.h>
#include <common/iscsi_lib_export.h>
#include <common/iscsi_sgvec.h>

#include <kernel/cxgbi_ippm.h>

#include <kernel/os_socket.h>
#include <kernel/base_export.h>

#include <toecore/toedev.h>
#include <toecore/offload.h>

#define RSS_HDR_VLD 1

#include <cxgb4/common.h>
#include <t4_tom/defs.h>
#include <t4_tom/tom.h>
#include <t4_tom/cpl_io_state.h>
#include <cxgb4/t4_msg.h>
#include <cxgb4/t4fw_interface.h>
#include <cxgb4/t4_regs.h>	/* for PCIE_MEM_ACCESS */
#include <cxgb4/cxgb4_ctl_defs.h>

#include <t4_tom/offload.h>

#include <kernel/cxgbi_ippm.c>
#include <kernel/os_socket_offload.h>

#include "libilro.h"

//#define __ULP_MEM_WRITE_USE_DSGL__

#define T4_ULP_MAX_SEGMENT_SIZE	16224
#define T4_PPOD_CPL_SIZE	(sizeof(struct ulp_mem_io) + ULP2_PPOD_SIZE)

/* iscsi module info */
MODULE_AUTHOR(MOD_AUTHOR);
MODULE_LICENSE(MOD_LICENSE);
MODULE_DESCRIPTION(DRIVER_STRING "4 v" DRIVER_VERSION);
MODULE_VERSION(DRIVER_VERSION "-" BUILD_VERSION);

unsigned int ppm_rsvd_factor = 2;
module_param(ppm_rsvd_factor, uint, 0644);
MODULE_PARM_DESC(ppm_rsvd_factor, "iscsi ppm cpu reserve factor N: 1/N reserved for cpu pool (default 2)");

unsigned int lro_on = 1;
module_param(lro_on, uint, 0644);
MODULE_PARM_DESC(lro_on, "T5 LRO (default 1: enabled)");

unsigned int iso_on = 1;
module_param(iso_on, uint, 0644);
MODULE_PARM_DESC(iso_on, "iscsi lso (default 1: enabled)");

unsigned int completion_on = 0;
module_param(completion_on, uint, 0644);
MODULE_PARM_DESC(completion_on, "iscsi completion (default 0: disabled)");

const unsigned long os_page_size = PAGE_SIZE;

static void inline t4_ulp_abort_conn(struct sock *sk)
{
	struct sk_buff *skb = alloc_skb(sizeof(struct cpl_abort_req),
					GFP_ATOMIC);

	if (skb)
		t4_send_reset(sk, CPL_ABORT_SEND_RST, skb);
	else
		os_log_info("%s: sk 0x%p, oom.\n", __func__, sk);
}

static struct sock * cpl_find_sock(struct tom_data *td, struct sk_buff *skb)
{
	struct sock *sk;
	struct cpl_iscsi_hdr_no_rss *cpl = (struct cpl_iscsi_hdr_no_rss *)(skb->data + sizeof(struct rss_header));
	unsigned int hwtid = GET_TID(cpl);

	//printk(KERN_ERR "%s: td 0x%p, skb 0x%p, 0x%p,0x%p, T4 CPL tid 0x%x, 0x%x.\n", __func__, td, skb, cpl, &cpl->ot, hwtid, hwtid1);

	sk = lookup_tid(td->tids, hwtid);
	if (!sk) {
		printk(KERN_ERR "T4 CPL tid 0x%x, sk NULL.\n", hwtid);
		iscsi_display_byte_string((char *)__func__, skb->data, 0,
				skb_headlen(skb), NULL, 0);
	}
	return sk;
}

static void sk_rx_credit_return(struct sock *sk, unsigned int used)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tp) {
		tp->copied_seq += used;
		t4_cleanup_rbuf(sk, used);
	} else
		os_log_warn("%s: sk 0x%p, tp NULL.\n", __func__, sk);
}

static int sk_excessive_rx_check(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	int rv = 0;

	if (unlikely(cplios_flag(sk, CPLIOS_ABORT_SHUTDOWN))) {
		printk(KERN_ERR
			"%s: tid 0x%x: sock 0x%p being aborted.\n",
			cplios->toedev->name, cplios->tid, sk);
		return -EINVAL;
	}
	if (unlikely(sk->sk_shutdown & RCV_SHUTDOWN)) {
		printk(KERN_ERR
			"%s: tid 0x%x: sock 0x%p rcv'ed shutdown, no more rx.\n",
			cplios->toedev->name, cplios->tid, sk);
		return -EINVAL;
	}
	read_lock(&sk->sk_callback_lock);
	if (unlikely(!sk->sk_user_data)) {
		printk(KERN_ERR
			"%s: tid 0x%x: sk 0x%p, isock is gone.\n",
			cplios->toedev->name, cplios->tid, sk);
		rv = -EINVAL;
	}
	read_unlock(&sk->sk_callback_lock);

	return rv;
}

static void process_rx_iscsi_hdr(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct cpl_iscsi_hdr *cpl = cplhdr(skb);
	struct tcp_sock *tp = tcp_sk(sk);
	struct ulp_skb_cb *cb = ULP_SKB_CB(skb);
	struct cxgbi_rx_lro_cb *lro_cb = cxgbi_skb_rx_lro_cb(skb);
	unsigned int seq = ntohl(cpl->seq);
	struct sk_buff *lskb;
	struct ulp_skb_cb *lcb;
	unsigned char *byte;

	os_log_debug(ISCSI_DBG_ULP,
		"%s: sk 0x%p, tid 0x%x, skb 0x%p, pdu_len_ddp %u, "
		"len %u, seq 0x%x/0x%x, urg 0x%x, rsvd 0x%x, status 0x%x.\n",
		__func__, sk, cplios->tid, skb, ntohs(cpl->pdu_len_ddp),
		ntohs(cpl->len), seq, tp->rcv_nxt, ntohs(cpl->urg), cpl->rsvd,
		cpl->status);

	if (sk_excessive_rx_check(sk) < 0) {
		kfree_skb(skb);
		return;
	}

	cb->seq = seq;

	skb_reset_transport_header(skb);
	__skb_pull(skb, sizeof(*cpl));
	if (!skb->data_len)
		__skb_trim(skb, ntohs(cpl->len));
	inet_csk(sk)->icsk_ack.lrcvtime = tcp_time_stamp;

	/* figure out if this is the pdu header or data */
	cb->ulp_mode = ULP_MODE_ISCSI;
	if (!cplios->skb_ulp_lhdr) {
		iscsi_socket *isock = sk_get_isock(sk);
		offload_device *odev = isock_get_odev(isock);

		if (!odev) {
			os_log_error("%s: tid 0x%x, sk 0x%p, isock 0x%p, "
				"odev null.\n",
				__func__, cplios->tid, sk, isock);
			goto err_out;
		}

		cplios->skb_ulp_lhdr = lskb = skb;
		lcb = cb;
		cb->flags = SBUF_ULP_FLAG_HDR_RCVD |
			SBUF_ULP_FLAG_COALESCE_OFF;
#if 0
		os_log_debug(ISCSI_DBG_ULP,
			"tid 0x%x skb 0x%p, pdu header.\n",
			cplios->tid, skb);
#endif

		/* we only update tp->rcv_nxt once per pdu */
		if (cb->seq != tp->rcv_nxt) {
			printk(KERN_ERR
				"%s: %s, tid 0x%x, bad seq 0x%x exp 0x%x.\n",
				__func__, cplios->toedev->name, cplios->tid,
				cb->seq, tp->rcv_nxt);
		//	goto err_out;
		}
		byte = skb->data;
		if (odev->d_version != ULP_VERSION_T4)
        		lcb->ulp.iscsi.pdulen = ntohs(cpl->pdu_len_ddp);
		else
        		lcb->ulp.iscsi.pdulen = ntohs(cpl->pdu_len_ddp) - 40;
		/* workaround for cpl->pdu_len_ddp since it does not include
		   the data digest count */
		if (byte[5] || byte[6] || byte[7])
			lcb->ulp.iscsi.pdulen += isock->s_dcrc_len;
		/* take into account of padding bytes */
		if (lcb->ulp.iscsi.pdulen & 0x3)
			lcb->ulp.iscsi.pdulen += 4 - (lcb->ulp.iscsi.pdulen & 0x3);
		tp->rcv_nxt += lcb->ulp.iscsi.pdulen;
	} else {
		lskb = cplios->skb_ulp_lhdr;
		lcb = ULP_SKB_CB(lskb);
		lcb->flags |= SBUF_ULP_FLAG_DATA_RCVD |
				SBUF_ULP_FLAG_COALESCE_OFF;
		cb->flags = SBUF_ULP_FLAG_DATA_RCVD;

		os_log_debug(ISCSI_DBG_ULP,
			"sk 0x%p, tid 0x%x skb 0x%p, pdu data, header 0x%p.\n",
			sk, cplios->tid, skb, lskb);
	}

	lro_cb->sk = sk;
	lro_cb->pdu_totallen = lcb->ulp.iscsi.pdulen;
	lro_cb->pdu_cnt = 1;
	lro_cb->lro_on = 0;

	__skb_queue_tail(&sk->sk_receive_queue, skb);
	return;

err_out:
	kfree_skb(skb);
	return;
}

static int do_rx_iscsi_hdr(struct tom_data *td, struct sk_buff *skb)
{
	struct sock *sk /* = cpl_find_sock(td, skb) */; 

	os_log_debug(ISCSI_DBG_ULP,
		"CPL_ISCSI_HDR skb 0x%p, len %u, datalen %u, headlen %u, frag %u.\n",
		skb, skb->len, skb->data_len, skb_headlen(skb),
		skb_shinfo(skb)->nr_frags);

	sk = cpl_find_sock(td, skb); 

	if (!sk)
		return CPL_RET_UNKNOWN_TID | CPL_RET_BUF_DONE;

	process_cpl_msg(process_rx_iscsi_hdr, sk, skb);
	return 0;
}

static void process_rx_iscsi_data(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct cpl_iscsi_data *cpl = cplhdr(skb);
	struct ulp_skb_cb *cb = ULP_SKB_CB(skb);
	iscsi_socket *isock = (iscsi_socket *)sk->sk_user_data;

	/* if iscsi completion feature is enabled, we could receive it
	 * when DDP failed for pdu */

	os_log_debug(ISCSI_DBG_ULP,
		"sk 0x%p, tid 0x%x CPL_ISCSI_DATA: skb 0x%p, len %u, seq 0x%x,"
		" rsvd1 0x%x, status 0x%x.\n",
		sk, cplios->tid, skb, ntohs(cpl->len), ntohl(cpl->seq),
		cpl->rsvd1, cpl->status);

	if (sk_excessive_rx_check(sk) < 0 || !isock) {
		goto err_out;
	}

	if (isock->s_pdu_data) {
		os_log_error("%s: cpl_iscsi_data already saved.\n", __func__);
		goto err_out;
	}

	isock->s_pdu_data = (void *)skb;

	cb->seq = ntohl(cpl->seq);
	skb_reset_transport_header(skb);
	__skb_pull(skb, sizeof(*cpl));
	__pskb_trim(skb, ntohs(cpl->len));
	inet_csk(sk)->icsk_ack.lrcvtime = tcp_time_stamp;

	cb->ulp_mode = ULP_MODE_ISCSI;
	cb->flags = SBUF_ULP_FLAG_DATA_RCVD | SBUF_ULP_FLAG_COALESCE_OFF;

	/* the skb will be queued to the rcvq when ddp status is received */
	return;

err_out:
	kfree_skb(skb);
	return;
}

static int do_rx_iscsi_data(struct tom_data *td, struct sk_buff *skb)
{
	struct sock *sk /* = cpl_find_sock(td, skb) */; 

	os_log_debug(ISCSI_DBG_ULP,
		"CPL_ISCSI_DATA skb 0x%p, len %u, datalen %u, headlen %u, frag %u.\n",
		skb, skb->len, skb->data_len, skb_headlen(skb),
		skb_shinfo(skb)->nr_frags);

	sk = cpl_find_sock(td, skb); 

	if (!sk)
		return CPL_RET_UNKNOWN_TID | CPL_RET_BUF_DONE;

	if (completion_on)
		process_cpl_msg(process_rx_iscsi_data, sk, skb);
	else
		process_cpl_msg(process_rx_iscsi_hdr, sk, skb);

	return 0;
}

#define ISCSI_DDP_ERR \
		(F_DDP_PPOD_MISMATCH | F_DDP_LLIMIT_ERR | F_DDP_ULIMIT_ERR |\
		 F_DDP_PPOD_PARITY_ERR | F_DDP_OFFSET_ERR | F_DDP_INVALID_TAG |\
		 F_DDP_COLOR_ERR | F_DDP_TID_MISMATCH | F_DDP_INVALID_PPOD |\
		 F_DDP_HDRCRC_ERR)

/*
 * ddpvld field: bit 27-24 23-20 19-16 15-12 XXX 
 *
 * bit 27: Invliad pagepod
 * bit 26: TID mismatch
 * bit 25: color mismatch
 * bit 24: offset mismatch
 *
 * bit 23: ulimit mismatch
 * bit 22: tag mismatch
 * bit 21: data crc error
 * bit 20: header crc error
 * 
 * bit 19: padding error
 * bit 18: parity error
 * bit 17: llimit error
 * bit 16: ddp'able
 *
 * bit 15: pagepod mismatch
 */

//#define __T4_DBG_DDP_FAILURE__
static void proc_ddp_status(unsigned int tid, unsigned int val,
			unsigned short *flags_p)
{
	unsigned short flags = SBUF_ULP_FLAG_STATUS_RCVD;
	
	if (val & F_DDP_PADDING_ERR) {
		printk(KERN_ERR "tid 0x%x, pad error, 0x%x.\n", tid, val);
		flags |= SBUF_ULP_FLAG_PAD_ERROR;
	}
	if (val & F_DDP_HDRCRC_ERR) {
		printk(KERN_ERR "tid 0x%x, hcrc error, 0x%x.\n", tid, val);
		flags |= SBUF_ULP_FLAG_HCRC_ERROR;
	}
	if (val & F_DDP_DATACRC_ERR) {
		printk(KERN_ERR "tid 0x%x, dcrc error, 0x%x.\n", tid, val);
		flags |= SBUF_ULP_FLAG_DCRC_ERROR;
	}
	if ((val & F_DDP_PDU) && !((*flags_p) & SBUF_ULP_FLAG_DATA_RCVD))
		flags |= SBUF_ULP_FLAG_DATA_DDPED;

	*flags_p |= flags;
}

static void process_rx_iscsi_cmp(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct cpl_rx_iscsi_cmp *cpl = cplhdr(skb);
	struct ulp_skb_cb *lcb = ULP_SKB_CB(skb);
	iscsi_socket *isock = (iscsi_socket *)sk->sk_user_data;
	struct sk_buff *data_skb = NULL;
	unsigned short pdu_len_ddp = be16_to_cpu(cpl->pdu_len_ddp);
	unsigned short plen = G_ISCSI_PDU_LEN(pdu_len_ddp);
	unsigned int seq = ntohl(cpl->seq);

	os_log_debug(ISCSI_DBG_ULP,
		"%s: sk 0x%p, tid 0x%x, skb 0x%p, pdu_len_ddp %u,%u, len %u, "
		"seq 0x%x/0x%x, rsvd 0x%x, status 0x%x, crc 0x%x, ddp 0x%x.\n",
		__func__, sk, cplios->tid, skb, pdu_len_ddp, plen,
		ntohs(cpl->len), seq, tp->rcv_nxt, cpl->rsvd, cpl->status,
		ntohs(cpl->ulp_crc), ntohl(cpl->ddpvld));

	if (sk_excessive_rx_check(sk) < 0 || !isock)
		goto err_out;

	skb_reset_transport_header(skb);
	__skb_pull(skb, sizeof(*cpl));
	__pskb_trim(skb, ntohs(cpl->len));
	inet_csk(sk)->icsk_ack.lrcvtime = tcp_time_stamp;

	lcb->ulp_mode = ULP_MODE_ISCSI;
	lcb->seq = seq;

	/* payload is the last bhs of the burst or pdu hdr of the failed ddp */
	lcb->ulp.iscsi.pdulen = plen;

	/* use seq. number to find how much data is DDP'ed for this cpl. */
        tp->rcv_nxt = seq + plen;

	lcb->flags = SBUF_ULP_FLAG_HDR_RCVD | SBUF_ULP_FLAG_COALESCE_OFF |
			SBUF_ULP_FLAG_CMPL_RCVD;
	
	lcb->ulp.iscsi.ddigest = ntohl(cpl->ulp_crc);
	proc_ddp_status(cplios->tid, ntohl(cpl->ddpvld), &lcb->flags);

	if (isock->s_pdu_data) {
 		data_skb = (struct sk_buff *)isock->s_pdu_data;
		isock->s_pdu_data = NULL;
                /* has data skb (i.e, ddp failed) */
		lcb->flags |= SBUF_ULP_FLAG_DATA_RCVD;
	}

	__skb_queue_tail(&sk->sk_receive_queue, skb);
	if (data_skb)
		__skb_queue_tail(&sk->sk_receive_queue, data_skb);

	if (!sock_flag(sk, SOCK_DEAD))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
		sk->sk_data_ready(sk);
#else
		sk->sk_data_ready(sk, 0);
#endif
	return;

err_out:
	kfree_skb(skb);
	return;
}

static int do_rx_iscsi_cmp(struct tom_data *td, struct sk_buff *skb)
{
	struct sock *sk; 

	os_log_debug(ISCSI_DBG_ULP,
		"CPL_ISCSI_DATA skb 0x%p, len %u, datalen %u, headlen %u, frag %u.\n",
		skb, skb->len, skb->data_len, skb_headlen(skb),
		skb_shinfo(skb)->nr_frags);

	sk = cpl_find_sock(td, skb); 

	if (!sk)
		return CPL_RET_UNKNOWN_TID | CPL_RET_BUF_DONE;

	process_cpl_msg(process_rx_iscsi_cmp, sk, skb);
	return 0;
}

static void process_rx_data_ddp(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct cpl_rx_data_ddp *cpl = cplhdr(skb);
	struct sk_buff *lskb;
	struct ulp_skb_cb *lcb;
	iscsi_socket *isock = (iscsi_socket *) sk->sk_user_data;
	offload_device *odev = isock_get_odev(isock);

	os_log_debug(ISCSI_DBG_ULP,
		"%s: tid 0x%x, sk 0x%p, skb 0x%p, urg 0x%x, len 0x%x, seq 0x%x,"
		" nxt_seq 0x%x, ulp_crc 0x%x, ddpvld 0x%x.\n",
		__func__, cplios->tid, sk, skb, ntohs(cpl->urg),
		ntohs(cpl->len), ntohl(cpl->seq), ntohl(cpl->nxt_seq),
		ntohl(cpl->ulp_crc), ntohl(cpl->ddpvld));

	if (sk_excessive_rx_check(sk) < 0) {
		kfree_skb(skb);
		return;
	}

	lskb = cplios->skb_ulp_lhdr;
	if (!lskb) {
		printk(KERN_ERR "tid 0x%x, rcv RX_DATA_DDP w/o pdu header.\n",
			cplios->tid);
		kfree_skb(skb);
		t4_ulp_abort_conn(sk);
		return;
	}
	lcb = ULP_SKB_CB(lskb);
	if (isock->s_pdu_data) {
		struct sk_buff *data_skb = (struct sk_buff *)isock->s_pdu_data;

		isock->s_pdu_data = NULL;
		/* has data skb (i.e, ddp failed) */
		lcb->flags |= SBUF_ULP_FLAG_DATA_RCVD;
		__skb_queue_tail(&sk->sk_receive_queue, data_skb);
       }

	lcb->flags |= SBUF_ULP_FLAG_STATUS_RCVD;

	cplios->skb_ulp_lhdr = NULL;

	if (ntohs(cpl->len) != lcb->ulp.iscsi.pdulen) {
		printk(KERN_ERR "tid 0x%x, RX_DATA_DDP pdulen %u != %u.\n",
			cplios->tid, ntohs(cpl->len), lcb->ulp.iscsi.pdulen);
	}

	lcb->ulp.iscsi.ddigest = ntohl(cpl->ulp_crc);
	lcb->ulp.iscsi.pdulen = ntohs(cpl->len);

	proc_ddp_status(cplios->tid, ntohl(cpl->ddpvld), &lcb->flags);

	inet_csk(sk)->icsk_ack.lrcvtime = tcp_time_stamp;
	
	kfree_skb(skb);

	if (odev && odev->d_version != ULP_VERSION_T6)
		sk_rx_credit_return(sk, lcb->ulp.iscsi.pdulen);

	if (!sock_flag(sk, SOCK_DEAD))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
		sk->sk_data_ready(sk);
#else
		sk->sk_data_ready(sk, 0);
#endif
}

static void process_rx_iscsi_dif(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct cpl_rx_iscsi_dif *cpl = cplhdr(skb);
	struct sk_buff *lskb;
	struct ulp_skb_cb *lcb;
	iscsi_socket *isock = (iscsi_socket *) sk->sk_user_data;
	offload_device *odev = isock_get_odev(isock);
	unsigned int pi_len = ntohs(cpl->msg_len);

	os_log_debug(ISCSI_DBG_ULP,
		"CPL_RX_ISCSI_DIF: tid 0x%x, sk 0x%p, skb 0x%p, "
		"ddp_len 0x%x, msg_len 0x%x, seq 0x%x, nxt_seq 0x%x, "
		"ulp_crc 0x%x, ddpvld 0x%x, err_vec 0x%x, pi_len %u.\n",
		__func__,
		cplios->tid, sk, skb, ntohs(cpl->ddp_len), ntohs(cpl->msg_len),
		ntohl(cpl->seq), ntohl(cpl->nxt_seq), ntohl(cpl->ulp_crc),
		ntohl(cpl->ddpvld), ntohl(cpl->err_vec), pi_len);

#if 0
	iscsi_display_byte_string("DIF_CPL:", (((void *)cpl) + sizeof(*cpl)),
			0, pi_len, NULL, 0);
#endif


	if (sk_excessive_rx_check(sk) < 0) {
		__kfree_skb(skb);
		return;
	}

	lskb = cplios->skb_ulp_lhdr;
	if (!lskb) {
		printk(KERN_ERR "tid 0x%x, rcv RX_DATA_DIF w/o pdu header.\n",
			cplios->tid);
		__kfree_skb(skb);
		t4_ulp_abort_conn(sk);
		return;
	}
	lcb = ULP_SKB_CB(skb);
	lcb->flags |= SBUF_ULP_FLAG_STATUS_RCVD;
	lcb->ulp_mode = ULP_MODE_ISCSI;

	lcb = ULP_SKB_CB(lskb);
	lcb->flags |= SBUF_ULP_FLAG_STATUS_RCVD;

	/* DIF cpl means pi received */
	lcb->ulp.iscsi.pi_len8 = (pi_len >> 3);

	if (!pi_len)
		lcb->ulp.iscsi.pi_flags |= SBUF_ULP_ISCSI_FLAGS_PI_DDPD;

	lcb->ulp.iscsi.pi_flags |= SBUF_ULP_ISCSI_FLAGS_PI_RCVD;

	if (cpl->err_vec) {
		os_log_error("tid 0x%x PI error in rcvd data. debug it"
			"err_vec 0x%x\n",
			cplios->tid, ntohl(cpl->err_vec));
		lcb->ulp.iscsi.pi_flags |= SBUF_ULP_ISCSI_FLAGS_PI_ERR;
	}

	cplios->skb_ulp_lhdr = NULL;

	lcb->ulp.iscsi.ddigest = ntohl(cpl->ulp_crc);
	lcb->ulp.iscsi.pdulen = ntohs(cpl->ddp_len);

	proc_ddp_status(cplios->tid, ntohl(cpl->ddpvld), &lcb->flags);

	skb_reset_transport_header(skb);
	__skb_pull(skb, sizeof(*cpl));
	/* Do this only if DDP is successful */
	/* if data is not ddp'ed and _dif cpl is received, means it may be
 	 * immediate data and pi is not extracted from data for sure. */
	if (lcb->flags & SBUF_ULP_FLAG_DATA_DDPED)
		__skb_trim(skb, pi_len);

	inet_csk(sk)->icsk_ack.lrcvtime = tcp_time_stamp;

	__skb_queue_tail(&sk->sk_receive_queue, skb);

	if (odev && odev->d_version != ULP_VERSION_T6)
		sk_rx_credit_return(sk, lcb->ulp.iscsi.pdulen);

	/* Do not free skb because we need to process pi bytes. */

	if (!sock_flag(sk, SOCK_DEAD))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
		sk->sk_data_ready(sk);
#else
		sk->sk_data_ready(sk, 0);
#endif
}

static void process_fw6_msg(struct sock *sk, struct sk_buff *skb)
{
	/* struct cpl_io_state *cplios = CPL_IO_STATE(sk); */
	struct cpl_fw6_msg *cpl = cplhdr(skb);
	struct fw_pi_error *pi_err = (struct fw_pi_error *)cpl->data;
	/* struct fw_tx_pi_header *pi_hdr =
  			(struct fw_tx_pi_header *)pi_err->pisc; */
	unsigned int tid = G_FW_WR_FLOWID(ntohl(pi_err->flowid_len16));

	if (cpl->type != FW_TYPE_PI_ERR)
		return;

	os_log_info("%s: pi guard error tid 0x%x: app_tag 0x%x, ref_tag 0x%x\n",
		__func__, tid, ntohs(pi_err->app_tag), ntohl(pi_err->ref_tag));
	os_log_info("%s: connection abort, pi error pi_hdr pisc "
		"[0x%04x 0x%04x 0x%04x 0x%04x]\n", __func__,
		ntohl(pi_err->pisc[0]), ntohl(pi_err->pisc[1]),
		ntohl(pi_err->pisc[2]), ntohl(pi_err->pisc[3]));

	/* drop connection or just drop the request? */
	__kfree_skb(skb);

	t4_ulp_abort_conn(sk);
}

static int do_rx_data_ddp(struct tom_data *td, struct sk_buff *skb)
{
	struct sock *sk /*= cpl_find_sock(td, skb) */;

#if 0
//	os_log_debug(ISCSI_DBG_ULP,
	os_log_error(
		"RX_DATA_DDP skb 0x%p, len %u, datalen %u, headlen %u, frag %u.\n",
                skb, skb->len, skb->data_len, skb_headlen(skb),
                skb_shinfo(skb)->nr_frags);
#endif

	sk = cpl_find_sock(td, skb);

	if (!sk)
		return CPL_RET_UNKNOWN_TID | CPL_RET_BUF_DONE;

	process_cpl_msg(process_rx_data_ddp, sk, skb);
	return 0;
}

static int do_rx_iscsi_dif(struct tom_data *td, struct sk_buff *skb)
{
	struct sock *sk;

	sk = cpl_find_sock(td, skb);

	if (!sk)
		return CPL_RET_UNKNOWN_TID | CPL_RET_BUF_DONE;

	process_cpl_msg(process_rx_iscsi_dif, sk, skb);

	return 0;
}

static int do_rx_fw6_msg(struct tom_data *td, struct sk_buff *skb)
{
	struct sock *sk;

	sk = cpl_find_sock(td, skb); 
	
	if (!sk)
		return CPL_RET_UNKNOWN_TID | CPL_RET_BUF_DONE;

	process_cpl_msg(process_fw6_msg, sk, skb);

	return 0;
}

static void process_set_tcb_rpl(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	iscsi_socket *isock = (iscsi_socket *) sk->sk_user_data;

#if 0
	struct cpl_set_tcb_rpl *cpl = cplhdr(skb);
	os_log_debug(ISCSI_DBG_ULP,
		"%s: sk 0x%p, tid 0x%x, rsvd 0x%x, cookie 0x%x, status 0x%x, oldval 0x%llx, isk 0x%p,%u.\n",
		__func__, sk, cplios->tid, ntohs(cpl->rsvd), cpl->cookie,
		cpl->status, (unsigned long long)be64_to_cpu(cpl->oldval),
		isock, isock ? isock->s_txhold : 0);
#endif

	kfree_skb(skb);

	if (unlikely(cplios->ulp_mode != ULP_MODE_ISCSI)) {
		os_log_warn("CPL_SET_TCB_RPL: sk 0x%p, tid 0x%x, skb 0x%p, "
			    " NOT in ULP mode.\n",
			sk, cplios->tid, skb);
		return;
	}

	/* probably should check if there is any error, but then
		if there is any, we are in deep trouble */
	if (isock) {
#if 0
		os_log_debug(ISCSI_DBG_ULP,
			"isock 0x%p, decr. tx hold -> %u.\n",
			isock, isock->s_txhold);
#endif
		if (isock->s_txhold) {
			isock->s_txhold--;
			iscsi_socket_write_space(isock, 0);
		} else
			iscsi_socket_write_space(isock, 1);

	}
}

static int do_set_tcb_rpl(struct tom_data *td, struct sk_buff *skb)
{
	struct sock *sk /* = cpl_find_sock(td, skb) */; 

#if 1
//	os_log_debug(ISCSI_DBG_ULP,
	os_log_info(
		"SET_TCB_RPL skb 0x%p, len %u, datalen %u, headlen %u, frag %u.\n",
                skb, skb->len, skb->data_len, skb_headlen(skb),
                skb_shinfo(skb)->nr_frags);
#endif

	sk = cpl_find_sock(td, skb); 
	
	if (!sk)
		return CPL_RET_UNKNOWN_TID | CPL_RET_BUF_DONE;

	process_cpl_msg(process_set_tcb_rpl, sk, skb);
	return 0;
}

/* for t4_tom, where both toe and iscsi ulp could receive same opcode */
static void iscsi_cpl_handler_callback(struct tom_data *td, struct sock *sk,
					struct sk_buff *skb, unsigned int op)
{
	os_log_debug(ISCSI_DBG_ULP,
		"sk 0x%p, td 0x%p, rcv op 0x%x from TOM.\n", sk, td, op);

	switch (op) {
	case CPL_RX_DATA_DDP:
		process_cpl_msg(process_rx_data_ddp, sk, skb);
		break;
	case CPL_SET_TCB_RPL:
		process_cpl_msg(process_set_tcb_rpl, sk, skb);
		break;
	case CPL_FW6_MSG:
		process_cpl_msg(process_fw6_msg, sk, skb);
		break;
	default:
		os_log_warn("sk 0x%p, op 0x%x from TOM, NOT supported.\n",
				sk, op);
		break;
	}
}

static void t4_sk_rx_tcp_consumed(iscsi_socket *isock, unsigned int used)
{
	offload_device *odev = isock_get_odev(isock);
	os_socket *osock = isock->s_private;

	/* no need to return rx credit on T6 as we are turning off
 	 * flow control */
	if (odev->d_version != ULP_VERSION_T6 && osock) {
		struct socket *sock = osock->sock;

		if (sock ) {
			struct sock *sk = sock->sk;

			if (sk)
				sk_rx_credit_return(sock->sk, used);
		} 
	}
}

/* if skb is result of ULP rx */
static int t4_sk_rx_ulp_skb(void *sbuf)
{
	struct sk_buff *skb = (struct sk_buff *)sbuf;
	struct ulp_skb_cb *cb = ULP_SKB_CB(skb);

	return (cb->ulp_mode & ULP_MODE_ISCSI) ? 1 : 0;
}

/* if skb is ready to read (i.e., CPL_RX_DATA_DDP has been received) */
static int t4_sk_rx_ulp_skb_ready(void *sbuf)
{
	struct sk_buff *skb = (struct sk_buff *)sbuf;
	struct ulp_skb_cb *cb = ULP_SKB_CB(skb);

	return cb->flags & SBUF_ULP_FLAG_STATUS_RCVD;
}

static int t4_sk_rx_ulp_ddpinfo(void *sbuf, iscsi_pdu *pdu, void *rcb_p)
{
	struct sk_buff *skb = (struct sk_buff *)sbuf;
	struct rx_cb *rcb = (struct rx_cb *)rcb_p;
	struct ulp_skb_cb *cb = ULP_SKB_CB(skb);
	u8 ddp_flags, pi_flags;

	if (cb->flags & SBUF_ULP_FLAG_LRO) {
		struct cxgbi_rx_lro_cb *lro_cb = cxgbi_skb_rx_lro_cb(skb);
		struct cxgbi_rx_pdu_cb *pdu_cb = cxgbi_skb_rx_pdu_cb(skb,
							(lro_cb->pdu_idx_off +
							rcb->pdu_idx));

		if (rcb->pdu_idx >= lro_cb->pdu_cnt) {
			os_log_error("%s: skb 0x%p, pdu idx %d >= %u.\n",
				__func__, skb, rcb->pdu_idx, lro_cb->pdu_cnt);
			return -EINVAL;
		}

		rcb->fmode = RXCBF_LRO;
 		ddp_flags = pdu_cb->flags;
		pi_flags = pdu_cb->pi_flags;

		pdu->p_totallen = pdu_cb->pdulen;
		*(pdu->p_ddigest) = pdu_cb->ddigest;
	} else {

		rcb->fmode = 0;
 		ddp_flags = cb->flags;
		pi_flags = cb->ulp.iscsi.pi_flags;

		pdu->p_totallen = cb->ulp.iscsi.pdulen;
		*(pdu->p_ddigest) = cb->ulp.iscsi.ddigest;
	}

	if (ddp_flags & SBUF_ULP_FLAG_HCRC_ERROR)
		pdu->p_flag |= ISCSI_PDU_FLAG_ERR_HDR_DIGEST;
	if (ddp_flags & SBUF_ULP_FLAG_DCRC_ERROR)
		pdu->p_flag |= ISCSI_PDU_FLAG_ERR_DATA_DIGEST;
	if (ddp_flags & SBUF_ULP_FLAG_PAD_ERROR)
		pdu->p_flag |= ISCSI_PDU_FLAG_ERR_DATA_PAD;
	if (ddp_flags & SBUF_ULP_FLAG_DATA_DDPED)
		pdu->p_flag |= ISCSI_PDU_FLAG_DATA_DDPED;

	if (pi_flags & SBUF_ULP_ISCSI_FLAGS_PI_RCVD) {
		pdu->p_flag |= ISCSI_PDU_FLAG_PI_RCVD;
		/* Cannot decide the exact protection op at the moment.
 		 * Just know that DIF cpl is received. */
		pdu->pi_info.prot_op = ISCSI_PI_OP_SCSI_PROT_READ_INSERT;

		pdu->pi_info.pi_len = (cb->ulp.iscsi.pi_len8 << 3);
	}

	if (pi_flags & SBUF_ULP_ISCSI_FLAGS_PI_DDPD)
		pdu->p_flag |= ISCSI_PDU_FLAG_PI_DDPD;

	if (pi_flags & SBUF_ULP_ISCSI_FLAGS_PI_ERR)
		pdu->p_flag |= ISCSI_PDU_FLAG_PI_ERR;

	if (cb->flags & SBUF_ULP_FLAG_CMPL_RCVD)
		pdu->p_flag |= ISCSI_PDU_FLAG_RX_CMPL;

	return 0;
}

/*
 * LRO handlers
 */
static void lro_skb_add_packet_rsp(struct sock *sk, struct sk_buff *skb, u8 op,
					const __be64 *rsp) 
{
	struct cxgbi_rx_lro_cb *lro_cb = cxgbi_skb_rx_lro_cb(skb);
	struct cxgbi_rx_pdu_cb *pdu_cb = cxgbi_skb_rx_pdu_cb(skb,
						lro_cb->pdu_cnt);
	struct cpl_rx_iscsi_ddp *cpl = (struct cpl_rx_iscsi_ddp *)
					((char *)(rsp + 1) - 8);
	struct cpl_io_state *cplios = CPL_IO_STATE(lro_cb->sk);
	struct tcp_sock *tp = tcp_sk(sk);

	iscsi_socket *isock = (iscsi_socket *) sk->sk_user_data;
	offload_device *odev = isock_get_odev(isock);

	pdu_cb->ddigest = ntohl(cpl->ulp_crc);
	pdu_cb->pdulen = ntohs(cpl->len);

	proc_ddp_status(cplios->tid, ntohl(cpl->ddpvld), &pdu_cb->flags);

	lro_cb->pdu_totallen += pdu_cb->pdulen;
	lro_cb->pdu_cnt++;

	tp->rcv_nxt += pdu_cb->pdulen;

	if (odev && odev->d_version != ULP_VERSION_T6)
		sk_rx_credit_return(sk, pdu_cb->pdulen);
}

static void lro_skb_add_packet_gl(struct sock *sk, struct sk_buff *skb, u8 op,
				const struct pkt_gl *gl)
{
	struct cxgbi_rx_lro_cb *lro_cb = cxgbi_skb_rx_lro_cb(skb);
	struct cxgbi_rx_pdu_cb *pdu_cb = cxgbi_skb_rx_pdu_cb(skb,
						lro_cb->pdu_cnt);
	struct skb_shared_info *ssi = skb_shinfo(skb);
	int i = ssi->nr_frags;
	unsigned int offset = sizeof(struct cpl_iscsi_hdr_no_rss); /* no RSS */
	struct cpl_iscsi_hdr_no_rss *cpl =
				(struct cpl_iscsi_hdr_no_rss *)gl->va;
	unsigned int len;

	if (op == CPL_ISCSI_HDR) {
		pdu_cb->flags = SBUF_ULP_FLAG_HDR_RCVD;

		pdu_cb->seq = ntohl(cpl->seq);
		len = ntohs(cpl->len);
	} else {
		pdu_cb->flags |= SBUF_ULP_FLAG_DATA_RCVD;

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
	get_page(gl->frags[gl->nfrags - 1].page);
}

static void lro_skb_cb_init(struct sk_buff *skb, struct sock *sk)
{
	struct cxgbi_rx_lro_cb *lro_cb = cxgbi_skb_rx_lro_cb(skb);
	struct ulp_skb_cb *cb = ULP_SKB_CB(skb);

	lro_cb->sk = sk;
	lro_cb->lro_on = 1;

	/* for compatibility of non-lro mode */
	cb->ulp_mode = ULP_MODE_ISCSI;
	cb->flags = SBUF_ULP_FLAG_STATUS_RCVD | SBUF_ULP_FLAG_LRO;
}

#ifdef USE_NAPI_ALLOC_SKB
static struct sk_buff *lro_init_skb(struct napi_struct *napi, struct sock *sk)
#else
static struct sk_buff *lro_init_skb(struct sock *sk)
#endif
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct sk_buff *skb;

#ifdef USE_NAPI_ALLOC_SKB
	skb = napi_alloc_skb(napi, LRO_SKB_MAX_HEADROOM);
#else
	skb = alloc_skb(LRO_SKB_MAX_HEADROOM, GFP_ATOMIC);
#endif
	if (unlikely(!skb))
		return NULL;

	/* zero out lro_cb + pdu_cb */
	memset(skb->head, 0, LRO_SKB_MAX_HEADROOM);

	lro_skb_cb_init(skb, sk);

	/* this is for t4_tom's lro flush routine */
	cplios->lro_skb = skb;
	sock_hold(sk);
	skb->sk = sk;

	return skb;
}

#ifdef USE_NAPI_ALLOC_SKB
int t4_iscsi_lro_recv(struct sock *sk, u8 op, const __be64 *rsp,
			struct napi_struct *napi,
			const struct pkt_gl *gl, struct t4_lro_mgr *lro_mgr,
			void (*t4tom_lro_flush)(struct t4_lro_mgr *,
						struct sk_buff *))
#else
int t4_iscsi_lro_recv(struct sock *sk, u8 op, const __be64 *rsp,
			const struct pkt_gl *gl, struct t4_lro_mgr *lro_mgr,
			void (*t4tom_lro_flush)(struct t4_lro_mgr *,
						struct sk_buff *))
#endif
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct sk_buff *skb;
	struct cxgbi_rx_lro_cb *lro_cb;
	iscsi_socket *isock = (iscsi_socket *) sk->sk_user_data;
	offload_device *odev;

	if (!isock) {
		os_log_info("%s: sk 0x%p, isock null, state 0x%x.\n",
			__func__, sk, sk->sk_state);
		return -1;
	}
 	odev = isock->s_odev;

	if(!lro_on || odev->d_version != ULP_VERSION_T5)
		return -EOPNOTSUPP;

	if (cplios->lro_skb)
		goto add_packet;

start_lro:
	/* Did we reach the hash size limit */
	if (lro_mgr->lro_session_cnt >= MAX_LRO_SESSIONS) {
		goto out;
	}

#ifdef USE_NAPI_ALLOC_SKB
	skb = lro_init_skb(napi, sk);
#else
	skb = lro_init_skb(sk);
#endif
	if (unlikely(!skb))
		goto out;
	lro_mgr->lro_session_cnt++;

	__skb_queue_tail(&lro_mgr->lroq, skb);

	/* continue to add the packet */
add_packet:
	skb = cplios->lro_skb;
	lro_cb = cxgbi_skb_rx_lro_cb(skb);

	/* Check if this packet can be aggregated */
	if (gl && ((skb_shinfo(skb)->nr_frags + gl->nfrags) >= MAX_SKB_FRAGS ||
		lro_cb->pdu_totallen >= LRO_FLUSH_TOTALLEN_MAX)) {
		t4tom_lro_flush(lro_mgr, skb);
		goto start_lro;
	}

	if (gl)
		lro_skb_add_packet_gl(sk, skb, op, gl);
	else
		lro_skb_add_packet_rsp(sk, skb, op, rsp);
	lro_mgr->lro_merged++;

	return 0;

out:
	return -1;
}

/* merge skb's [pdu_idx]th pdu into hskb */
static void skb_lro_merge(struct sk_buff *hskb, struct sk_buff *skb,
				 int pdu_idx)
{
	struct skb_shared_info *hssi = skb_shinfo(hskb);
	struct cxgbi_rx_lro_cb *hlro_cb = cxgbi_skb_rx_lro_cb(hskb);
	struct cxgbi_rx_pdu_cb *hpdu_cb = cxgbi_skb_rx_pdu_cb(hskb, 0);
	struct skb_shared_info *ssi = skb_shinfo(skb);
	struct cxgbi_rx_pdu_cb *pdu_cb = cxgbi_skb_rx_pdu_cb(skb, pdu_idx);
	int frag_idx = 0;
	int hfrag_idx = 0;

	/* either 1st or last */
	if (pdu_idx)
		frag_idx = ssi->nr_frags - pdu_cb->frags;

	if (pdu_cb->flags & SBUF_ULP_FLAG_HDR_RCVD) {
		unsigned int len = 0;

		hlro_cb->sk = (cxgbi_skb_rx_lro_cb(skb))->sk;
		hlro_cb->pdu_cnt = 1;
		hlro_cb->lro_on = 1;

		hpdu_cb->flags = pdu_cb->flags;
		hpdu_cb->seq = pdu_cb->seq;

		memcpy(&hssi->frags[0], &ssi->frags[frag_idx],
				sizeof(skb_frag_t));
		ssi->frags[frag_idx].size = 0;
		get_page(skb_frag_page(&hssi->frags[0]));
		frag_idx++;
		hfrag_idx++;
		hssi->nr_frags = 1;
		hpdu_cb->frags = 1;

		len = hssi->frags[0].size;
		hskb->len = len;
		hskb->data_len = len;
		hskb->truesize = len;

		skb->len -= len;
		skb->data_len -= len;
		skb->truesize -= len;
	}

	if (pdu_cb->flags & SBUF_ULP_FLAG_DATA_RCVD) {
		unsigned int len = 0;
		int i, n;

		hpdu_cb->flags |= pdu_cb->flags;

		for (i = 1, n = hfrag_idx; n < pdu_cb->frags; i++, frag_idx++, n++) {
			memcpy(&hssi->frags[i], &ssi->frags[frag_idx],
				sizeof(skb_frag_t));
			ssi->frags[frag_idx].size = 0;
			get_page(skb_frag_page(&hssi->frags[i]));
			len += hssi->frags[i].size;
			hssi->nr_frags++;
			hpdu_cb->frags++;
		}

		hskb->len += len;
		hskb->data_len += len;
		hskb->truesize += len;

		skb->len -= len;
		skb->data_len -= len;
		skb->truesize -= len;
	}

	if (pdu_cb->flags & SBUF_ULP_FLAG_STATUS_RCVD) {
		hpdu_cb->pi_flags = pdu_cb->pi_flags;
		hpdu_cb->flags |= pdu_cb->flags;

		if (hpdu_cb->flags & SBUF_ULP_FLAG_DATA_RCVD)
			hpdu_cb->flags &= ~SBUF_ULP_FLAG_DATA_DDPED;

		hpdu_cb->ddigest = pdu_cb->ddigest;
		hpdu_cb->pdulen = pdu_cb->pdulen;
		hlro_cb->pdu_totallen = pdu_cb->pdulen;
	}
}

void t4_iscsi_lro_proc_rx(struct sock *sk, struct sk_buff *skb)
{ 
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct cxgbi_rx_lro_cb *lro_cb = cxgbi_skb_rx_lro_cb(skb);
	struct cxgbi_rx_pdu_cb *pdu_cb;
	int merge = 0;
	int last;

	if (!lro_cb->pdu_cnt)
		lro_cb->pdu_cnt = 1;
	else if (lro_cb->pdu_cnt < MAX_SKB_FRAGS) {
		pdu_cb = cxgbi_skb_rx_pdu_cb(skb, lro_cb->pdu_cnt);
		if (!(pdu_cb->flags & SBUF_ULP_FLAG_STATUS_RCVD) &&
		    pdu_cb->frags)
			lro_cb->pdu_cnt++;
        }
 	last = lro_cb->pdu_cnt - 1;

	os_log_debug(ISCSI_DBG_ULP,
		"%s: sk 0x%p, tid 0x%x, skb 0x%p,%u, %u.\n",
		__func__, sk, cplios->tid, skb, skb->len, skb->data_len);


	if (sk_excessive_rx_check(sk) < 0) {
		__kfree_skb(skb);
		return;
	}

	/* partial 1st pdu, merge with head/data received */
 	pdu_cb = cxgbi_skb_rx_pdu_cb(skb, 0);
	if (!(pdu_cb->flags & SBUF_ULP_FLAG_HDR_RCVD)) {
		struct sk_buff *hskb = cplios->skb_ulp_lhdr;
		struct cxgbi_rx_pdu_cb *lpdu_cb;

		if (!hskb) {
			os_log_warn("%s: skb 0x%p, hskb NULL.\n",
					 __func__, skb);
			cxgbi_lro_skb_dump(skb);
			goto abort;
		}

		lpdu_cb = cxgbi_skb_rx_pdu_cb(hskb, 0);
		skb_lro_merge(hskb, skb, 0);

		if (lpdu_cb->flags & SBUF_ULP_FLAG_STATUS_RCVD) {
			struct ulp_skb_cb *cb = ULP_SKB_CB(hskb);

			cplios->skb_ulp_lhdr = NULL;
			cb->flags = lpdu_cb->flags;
			__skb_queue_tail(&sk->sk_receive_queue, hskb);
		}

		if (lro_cb->pdu_cnt == 1) {
			__kfree_skb(skb);
			goto data_ready;
		}

		lro_cb->pdu_idx_off = 1;
		lro_cb->frag_idx_off = pdu_cb->frags;
		merge++;
	}

	/* check if last pdu is partial */
	pdu_cb = cxgbi_skb_rx_pdu_cb(skb, last);

	if (!(pdu_cb->flags & SBUF_ULP_FLAG_STATUS_RCVD)) {
		/* allocate a new skb to hold the partial pdu */
		struct sk_buff *hskb = alloc_skb(LRO_SKB_MIN_HEADROOM,
							GFP_ATOMIC);
		if (unlikely(!hskb)) {
			os_log_info("%s: skb 0x%p, hskb oom.\n",
					 __func__, skb);
			goto abort;
		}
		memset(hskb->head, 0, LRO_SKB_MIN_HEADROOM);

		lro_skb_cb_init(hskb, lro_cb->sk);

		cplios->skb_ulp_lhdr = hskb;
		skb_lro_merge(hskb, skb, last);
		merge++;
	}

	lro_cb->pdu_cnt -= merge;
	if (lro_cb->pdu_cnt) {
		__skb_queue_tail(&sk->sk_receive_queue, skb);
	} else  {
		__kfree_skb(skb);
		return;
	}

data_ready:
	inet_csk(sk)->icsk_ack.lrcvtime = tcp_time_stamp;
	if (!sock_flag(sk, SOCK_DEAD))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
		sk->sk_data_ready(sk);
#else
		sk->sk_data_ready(sk, 0);
#endif
	return;

abort:
	__kfree_skb(skb);
	t4_ulp_abort_conn(sk);	
}

/*
 * ULP2 TX sendskb
 */
static void t4_sk_tx_skb_setmode(void *sbuf, unsigned char mode,
				unsigned char hcrc, unsigned char dcrc)
{
	if (mode & ISCSI_OFFLOAD_MODE_ULP) {
		struct sk_buff *skb = (struct sk_buff *)sbuf;

		ULP_SKB_CB(skb)->ulp_mode = ULP_MODE_ISCSI << 4;
		if (hcrc)
			ULP_SKB_CB(skb)->ulp_mode |=
				ULPCB_MODE_SUBMODE_ISCSI_HCRC;
		if (dcrc)
			ULP_SKB_CB(skb)->ulp_mode |=
				ULPCB_MODE_SUBMODE_ISCSI_DCRC;
	}
}

static void t4_sk_tx_skb_setforce(void *sbuf, unsigned char adapter_type,
			unsigned char force)
{
	struct sk_buff *skb = (struct sk_buff *)sbuf;
	unsigned char submod_mask = ULPCB_MODE_SUBMODE_ISCSI_HCRC |
					ULPCB_MODE_SUBMODE_ISCSI_DCRC;

	if ((adapter_type == ULP_VERSION_T5) &&
	    (ULP_SKB_CB(skb)->ulp_mode & submod_mask))
		force = 0;

	if (force)
		ULP_SKB_CB(skb)->flags |= ULPCB_FLAG_ISCSI_FORCE;
}

/* this bit is not defined in hw. Its valid only between host and fw */
static void t4_sk_tx_skb_setmode_pi(void *sbuf, unsigned char mode,
				    unsigned char prot_op)
{
	struct sk_buff *skb = (struct sk_buff *)sbuf;

	if ((mode & ISCSI_OFFLOAD_MODE_ULP) && prot_op)
		ULP_SKB_CB(skb)->ulp_mode |= 4;
}

/* this bit is not defined in hw. Its valid only between host and fw */
static void t4_sk_tx_skb_setmode_iso(void *sbuf, unsigned char mode,
				    unsigned char iso)
{
	struct sk_buff *skb = (struct sk_buff *)sbuf;

	if ((mode & ISCSI_OFFLOAD_MODE_ULP) && iso)
		ULP_SKB_CB(skb)->ulp_mode |= 8;
}

static inline int t4_get_tx_pi_control_bits(unsigned char prot_op,
		unsigned int *pi_inline, unsigned int *pi_validate,
		unsigned int *pi_control)
{
	unsigned int err = 0;

	/* based on ulptx t10dif control table */
	*pi_inline = 0;

	switch(prot_op) {
	case ISCSI_PI_OP_SCSI_PROT_WRITE_INSERT:
		*pi_validate = 0; *pi_control = 2;
		break;
	case ISCSI_PI_OP_SCSI_PROT_WRITE_PASS:
		*pi_validate = 1; *pi_control = 2;
		break;
	case ISCSI_PI_OP_SCSI_PROT_WRITE_STRIP:
		*pi_validate = 1; *pi_control = 0;
		break;
	default:
		err = -1;
	}

	return err;
}

static inline int t4_get_guard_type(int guard)
{
	unsigned int type = 0;

	/* T10DIF TODO remove these if checks */
	if (guard == ISCSI_PI_GUARD_TYPE_IP)
		type = 0;
	else if (guard == ISCSI_PI_GUARD_TYPE_CRC)
		type = 1;

	return type;
}

static inline int t4_get_dif_type(int dif)
{
	int type = 0;

	/* T10DIF TODO remove these if checks */
	if (dif == ISCSI_PI_DIF_TYPE_1)
		type = 1;
	else if (dif == ISCSI_PI_DIF_TYPE_2)
		type = 2;
	else if (dif == ISCSI_PI_DIF_TYPE_3)
		type = 3;

	return type;
}

static inline int t4_get_pi_interval(int interval)
{
	int ret_intval = 0; /* default 512B */

	if (interval == ISCSI_SCSI_PI_INTERVAL_4K)
		ret_intval = 1;

	return ret_intval;
}

static inline int t4_get_tag_gen_ctrl(int prot_op, int dif)
{
	int tag_gen = 0;

	/* app tag and ref tag are part of the pi data in WRITE_PASS and
 	 * WRITE_STRIP cases and h/w doesn't need to touch them */
	if (prot_op == ISCSI_PI_OP_SCSI_PROT_WRITE_INSERT &&
		(dif == ISCSI_PI_DIF_TYPE_1 || dif == ISCSI_PI_DIF_TYPE_2))
		tag_gen = 3;

	return tag_gen;
}

static inline int t4_skb_tx_pi_len_correction(unsigned int prot_op,
						unsigned int pi_len)
{
	int update_len = 0;

	if (prot_op == ISCSI_PI_OP_SCSI_PROT_WRITE_INSERT)
		update_len = pi_len;
	else if (prot_op == ISCSI_PI_OP_SCSI_PROT_WRITE_STRIP)
		update_len = -pi_len;

	return (update_len - sizeof(struct fw_tx_pi_header));
}

int t4_sk_tx_make_pi_hdr(void *sbuf, iscsi_pdu *pdu)
{
	struct sk_buff *skb = (struct sk_buff *)sbuf;
	struct fw_tx_pi_header *pi_hdr;
	struct cxgbi_pdu_pi_info *pi_info = &pdu->pi_info;
	unsigned int prot_op = pi_info->prot_op;
	unsigned int pi_inline = 0, pi_validate = 0, pi_control = 0;
	unsigned int guard_type, dif_type, interval;
	unsigned int num_pi, sector_shift = 9; /* 512B sector */
	unsigned int isohdr_len = 0, pi_start4, pi_end4;
	int tag_gen;

	if (t4_get_tx_pi_control_bits(prot_op, &pi_inline, &pi_validate,
				&pi_control))
		return 0;

	guard_type = t4_get_guard_type(pi_info->guard);
	dif_type = t4_get_dif_type(pi_info->dif_type);
	interval = t4_get_pi_interval(pi_info->interval);
	num_pi = pi_info->pi_len >> 3;
	if (pi_info->interval == ISCSI_SCSI_PI_INTERVAL_4K)
		sector_shift = 12;

	/* exclude iso hdr from pi processing */
	if (pdu->p_flag & ISCSI_PDU_FLAG_TX_ISO)
		isohdr_len = sizeof(struct cpl_tx_data_iso);

	pi_start4 = (sizeof(struct cpl_tx_data) + isohdr_len +
				ISCSI_BHS_SIZE + pdu->p_hdlen)>>2;
	pi_end4 = (sizeof(struct cpl_tx_data) + isohdr_len + ISCSI_BHS_SIZE +
			pdu->p_hdlen +
			(num_pi<<sector_shift))>>2;

	/* Tell tom to use FW_ISCSI_TX_DATA_WR in place of default
 	 * FW_OFLD_TX_DATA_WR */
	ULP_SKB_CB(skb)->flags |= ULPCB_FLAG_ISCSI_WR;

	skb_ulp_len_adjust(skb) = t4_skb_tx_pi_len_correction(prot_op,
						pi_info->pi_len);
#if 0
	os_log_info("%s: guard_type %u, dif_type %u, interval %u, num_pi %u, "
		"sector_shift %u, pi_start4 %u, pi_end4 %u, pi_sgcnt %u\n",
		__func__, guard_type, dif_type, interval, num_pi, sector_shift,
		pi_start4, pi_end4, pi_info->pi_sgcnt);
#endif
	pi_hdr = (struct fw_tx_pi_header *)skb_put(skb,
				sizeof(struct fw_tx_pi_header));

	pi_hdr->op_to_inline = htons(V_FW_TX_PI_HEADER_OP(ULP_TX_SC_PICTRL) |
				F_FW_TX_PI_HEADER_ULPTXMORE |
				V_FW_TX_PI_HEADER_PI_CONTROL(pi_control) |
				V_FW_TX_PI_HEADER_GUARD_TYPE(guard_type) |
				V_FW_TX_PI_HEADER_VALIDATE(pi_validate) |
				V_FW_TX_PI_HEADER_INLINE(pi_inline));

	pi_hdr->pi_interval_tag_type = V_FW_TX_PI_HEADER_PI_INTERVAL(interval) |
					V_FW_TX_PI_HEADER_TAG_TYPE(dif_type);
	pi_hdr->num_pi = num_pi;
	pi_hdr->pi_start4_pi_end4 =
			cpu_to_be32(V_FW_TX_PI_HEADER_PI_START4(pi_start4) |
				    V_FW_TX_PI_HEADER_PI_END4(pi_end4));

	tag_gen = t4_get_tag_gen_ctrl(prot_op, pi_info->dif_type);
	pi_hdr->tag_gen_enabled_pkd =
			V_FW_TX_PI_HEADER_TAG_GEN_ENABLED(tag_gen);

	pi_hdr->num_pi_dsg = pi_info->pi_sgcnt; /* Only between (host<-->fw) */
	pi_hdr->app_tag = htons(pi_info->app_tag);
	pi_hdr->ref_tag = cpu_to_be32(pi_info->ref_tag);

	return sizeof(struct fw_tx_pi_header);
}

int t4_sk_tx_make_iso_cpl(void *sbuf, iscsi_pdu *pdu)
{
	struct sk_buff *skb = (struct sk_buff *)sbuf;
	struct cpl_tx_data_iso *cpl;
	struct iscsi_pdu_iso_info *iso_info = &pdu->iso_info;

	cpl = (struct cpl_tx_data_iso *)skb_put(skb,
				sizeof(struct cpl_tx_data_iso));

	cpl->op_to_scsi = htonl(V_CPL_TX_DATA_ISO_OP(CPL_TX_DATA_ISO) |
			V_CPL_TX_DATA_ISO_FIRST(!!(iso_info->flags & ISCSI_PDU_ISO_INFO_FLAGS_FSLICE)) |
			V_CPL_TX_DATA_ISO_LAST(!!(iso_info->flags & ISCSI_PDU_ISO_INFO_FLAGS_LSLICE)) |
			V_CPL_TX_DATA_ISO_CPLHDRLEN(0) |/* cpl_tx_data len
							  is 16B */
			V_CPL_TX_DATA_ISO_HDRCRC(!!pdu->p_hdlen) |
			V_CPL_TX_DATA_ISO_PLDCRC(!!pdu->p_ddlen) |
			V_CPL_TX_DATA_ISO_SCSI(2)); /* Data-in pdu */

	cpl->ahs_len = (char) pdu->p_ahslen; /* No loss here.
						ahslen has only 8 bits */
	cpl->mpdu = htons(DIV_ROUND_UP(iso_info->mpdu, 4));
	cpl->burst_size = htonl((iso_info->burst_size) >> 2);
	cpl->len = htonl(iso_info->len);
	cpl->reserved2_seglen_offset = htonl(
		V_CPL_TX_DATA_ISO_SEGLEN_OFFSET(iso_info->segment_offset));
	cpl->datasn_offset = htonl(iso_info->datasn_offset);
	cpl->buffer_offset = htonl(iso_info->buffer_offset);
	cpl->reserved3 = 0;

	ULP_SKB_CB(skb)->flags |= ULPCB_FLAG_ISCSI_WR;
	skb_ulp_len_adjust(skb) += iso_info->iso_extra -
			sizeof(struct cpl_tx_data_iso); /* cpl is not part of
							   the actual payload
							   but its counted in
							   skb->len */
#if 0
	os_log_info("%s: op_to_sci 0x%04x, ahs_len 0x%x, mpdu 0x%02x, "
		"burst_size 0x%04x, iso_size 0x%04x\n", __func__,
		ntohl(cpl->op_to_scsi),  pdu->p_ahslen, ntohs(cpl->mpdu),
		ntohl(cpl->burst_size), ntohl(cpl->len));
#endif

	return sizeof(struct cpl_tx_data_iso);
}

/*
 * ULP2: TOE -> ULP transition 
 */
static void __mk_set_tcb_field(struct sock *sk, struct sk_buff *skb, u16 word,
				u64 mask, u64 val, int no_reply)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct cpl_set_tcb_field *req;

	req = (struct cpl_set_tcb_field *)__skb_put(skb, sizeof(*req));
	INIT_TP_WR(req, cplios->tid);
        OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_SET_TCB_FIELD, cplios->tid));
        req->reply_ctrl = htons(V_NO_REPLY(no_reply) | V_QUEUENO(cplios->rss_qid));
	req->word_cookie = htons(V_WORD(word));
        req->mask = cpu_to_be64(mask);
        req->val = cpu_to_be64(val);
}

static int send_set_tcb_field(struct sock *sk, u16 word, u64 mask, u64 val,
				int no_reply)
{
	struct sk_buff *skb;
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);

	if (sk->sk_state == TCP_CLOSE ||
		cplios_flag(sk, CPLIOS_ABORT_SHUTDOWN))
		return -EINVAL;

	skb = alloc_skb(sizeof(struct cpl_set_tcb_field), GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	set_wr_txq(skb, CPL_PRIORITY_CONTROL, cplios->port_id);
	__mk_set_tcb_field(sk, skb, word, mask, val, no_reply);
	cxgb4_ofld_send(cplios->egress_dev, skb);

	return 0;
}

static int t4_sk_set_ulp_mode(iscsi_socket *isock, unsigned char hcrc,
				unsigned char dcrc, unsigned char t10dif)
{
	offload_device *odev = (offload_device *)isock->s_odev;
	os_socket *osock = (os_socket *) isock->s_private;
	struct sock *sk = osock->sock->sk;
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct cxgbi_ppm *ppm = (struct cxgbi_ppm *)odev->odev2ppm(odev);
	u64 val = 0UL;
	int rv;

	isock->s_ddp_pgidx = ppm->tformat.pgsz_idx_dflt;

	isock->s_txhold = 1; /* we will wait for one CPL_SET_TCB_RPL */

	/* ddp page selection */
	val = (isock->s_ddp_pgidx & 0x3) << 4;
	/* digest settings */
	if (hcrc)
		 val |= ULP_CRC_HEADER;
	if (dcrc)
		 val |= ULP_CRC_DATA;
	val <<= 4;
	/* ulp mode */
	val |= ULP_MODE_ISCSI;

	/* set the ULP_MODE_ISCSI on the socket, so that when the reply
 	 * comes back, tom would call us */
	cplios->ulp_mode = ULP_MODE_ISCSI;

	/* W_TCB_ULP_TYPE = W_TCB_ULP_RAW */
	rv = send_set_tcb_field(sk, 0, 0xFFF, val, 0);
	if (rv < 0)
		return rv;

	if (t10dif) {
		unsigned int pi_check, pi_report;
		/* Set the pi bits in tcb */

		/* Set this based on DIF or DIX. */
		if (t10dif & ISCSI_OFFLOAD_T10DIXDIF)  {
			os_log_info("isock 0x%p, set TCB for DIF\n", isock);
			/* DIF case, but T5 doesn't remove pi from data */
			pi_check = 0x1; pi_report = 0x0;
		} else {
			/* DIX case */
			os_log_info("isock 0x%p, set TCB for DIX\n", isock);
			pi_check = 0x3; pi_report = 0;
		}

		val = pi_check << 2 | pi_report;

		rv = send_set_tcb_field(sk, W_TCB_ULP_EXT,
				V_TCB_ULP_EXT((u64)M_TCB_ULP_EXT),
				V_TCB_ULP_EXT((u64)val), 0);
		if (rv < 0)
			return rv;
	}

	/* for T6 disable flow control */
	if (odev->d_version == ULP_VERSION_T6) {
		val = V_TF_RX_FLOW_CONTROL_DISABLE(1ULL);
		rv = send_set_tcb_field(sk, W_TCB_T_FLAGS, val, val, 0);
		if (rv < 0)
			return rv;
	}

	return 0;
}

static int t4_sk_display (iscsi_socket *isock, char *buf, int buflen)
{
	struct sock *sk = ((os_socket *) isock->s_private)->sock->sk;
	struct tcp_sock *tp = tcp_sk(sk);
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	int len = 0;
	char buffer[80];
	int dump = 0;

	if (!buf || !buflen) {
		buf = buffer;
		dump = 1;
	}

	len += sprintf(buf + len,
			"sk 0x%p, tid 0x%x, rcv_nxt 0x%x, copied_seq 0x%x.\n",
			sk, cplios->tid, tp->rcv_nxt, tp->copied_seq);
	if (dump) {
		buffer[len] = 0;
		os_log_info("%s", buffer);
		buf = buffer;
		len = 0;
	} else if (len >= buflen)
                goto done;

done:
	return (len > buflen) ? buflen : len;
}

/*
 * functions to program the pagepod in h/w
 */
static void* t4_odev2ppm(offload_device *odev)
{
	return odev ?
		*(((struct cxgb4_lld_info *)odev->d_lldev)->iscsi_ppm) :
		NULL;
}

static inline void ulp_mem_io_set_hdr(struct ulp_mem_io *req,
				unsigned int wr_len, unsigned int dlen,
				unsigned int pm_addr, int tid, int idata)
{	
	INIT_ULPTX_WR(req, wr_len, 0, tid);

#ifdef __ULP_MEM_WRITE_USE_DSGL__
	req->cmd = htonl(V_ULPTX_CMD(ULP_TX_MEM_WRITE));
#else
	req->cmd = htonl(V_ULPTX_CMD(ULP_TX_MEM_WRITE) | F_ULP_MEMIO_ORDER);
#endif
	req->dlen = htonl(V_ULP_MEMIO_DATA_LEN(dlen >> 5));
	req->len16 = htonl(DIV_ROUND_UP(wr_len - sizeof(req->wr), 16));
	req->lock_addr = htonl(V_ULP_MEMIO_ADDR(pm_addr >> 5));
	if (idata) {
		struct ulptx_idata *idata = (struct ulptx_idata *)(req + 1);

		idata->cmd_more = htonl(V_ULPTX_CMD(ULP_TX_SC_IMM));
		idata->len = htonl(dlen);
	} else {
		struct ulptx_sgl *dsgl = (struct ulptx_sgl *)(req + 1);

		dsgl->cmd_nsge = htonl(V_ULPTX_CMD(ULP_TX_SC_DSGL) |
					V_ULPTX_NSGE(1));
		dsgl->len0 = htonl(dlen);
	}
}

static void ddp_set_one_ppod(struct cxgbi_pagepod *ppod,
			struct cxgbi_task_tag_info *ttinfo,
                        unsigned int *sg_idx, unsigned int *sg_offset)
{
	chiscsi_sgvec *sg = (chiscsi_sgvec *)ttinfo->sgl;
	unsigned int sgcnt = ttinfo->nents;
	unsigned int idx = *sg_idx;
	unsigned int offset = *sg_offset;
	unsigned int pg_sz = 1 << ttinfo->pg_shift;
	int i;

	memcpy(ppod, &ttinfo->hdr, sizeof(struct cxgbi_pagepod_hdr));

	sg += idx;
	for (i = 0; i < PPOD_PAGES_MAX; i++) {
		if (idx < sgcnt) {
			ppod->addr[i] = cpu_to_be64(sg->sg_dma_addr + offset);
			offset += pg_sz;
			if (offset == (sg->sg_offset + sg->sg_length)) {
				offset = 0;
				idx++;
				sg++;
			}
		} else
			ppod->addr[i] = 0ULL;
	}

	/*
	 * the fifth address needs to be repeated in the next ppod, so do
	 * not move sg
	 */
	*sg_offset = offset;
	*sg_idx = idx;

	ppod->addr[i] = (idx < sgcnt) ?
			cpu_to_be64(sg->sg_dma_addr + offset) : 0ULL;
}

#ifndef __ULP_MEM_WRITE_USE_DSGL__
static struct sk_buff *ppod_write_idata(iscsi_socket *isock,
				struct cxgbi_ppm *ppm,
				struct cxgbi_task_tag_info *ttinfo,
				unsigned int idx, unsigned int npods,
				unsigned *sg_idx, unsigned int *sg_offset)
{
	unsigned int dlen = IPPOD_SIZE * npods;
	unsigned int pm_addr = idx * IPPOD_SIZE + ppm->llimit;
	unsigned int wr_len = roundup(sizeof(struct ulp_mem_io) +
				 sizeof(struct ulptx_idata) + dlen, 16);
	struct ulp_mem_io *req;
	struct ulptx_idata *idata;
	struct cxgbi_pagepod *ppod;
	unsigned int i;
	struct sk_buff *skb = alloc_skb(wr_len, GFP_KERNEL);

	if (!skb)
		return NULL;
	skb_reset_transport_header(skb);
	memset(skb->data, 0, wr_len);

	req = (struct ulp_mem_io *)__skb_put(skb, wr_len);
	ulp_mem_io_set_hdr(req, wr_len, dlen, pm_addr, isock->s_tid, 1);
	idata = (struct ulptx_idata *)(req + 1);

	ppod = (struct cxgbi_pagepod *)(idata + 1);

	for (i = 0; i < npods; i++, ppod++)
		ddp_set_one_ppod(ppod, ttinfo, sg_idx, sg_offset);

	return skb;
}

#else

static struct sk_buff *ppod_write_dsgl(iscsi_socket *isock,
				struct cxgbi_ppm *ppm,
				struct cxgbi_task_tag_info *ttinfo,
				unsigned int idx, unsigned int npods,
				dma_addr_t paddr)
{
	unsigned int dlen = IPPOD_SIZE * npods;
	unsigned int pm_addr = idx * IPPOD_SIZE + ppm->llimit;
	unsigned int wr_len = roundup(sizeof(struct ulp_mem_io) +
				 sizeof(struct ulptx_sgl), 16);
	struct ulp_mem_io *req;
	struct ulptx_sgl *dsgl;
	struct sk_buff *skb = alloc_skb(wr_len, GFP_KERNEL);

	if (!skb)
		return NULL;

	skb_reset_transport_header(skb);
	memset(skb->data, 0, wr_len);

	req = (struct ulp_mem_io *)__skb_put(skb, wr_len);
	ulp_mem_io_set_hdr(req, wr_len, dlen, pm_addr, isock->s_tid, 0);
	dsgl = (struct ulptx_sgl *)(req + 1);
	dsgl->addr0 = cpu_to_be64(paddr);

	return skb;
}
#endif

static void t4_ddp_clear_map(offload_device *odev, unsigned int idx,
			struct chiscsi_tag_ppod *ppod_info)
{
	/* the ddp programming is sent via ofldq so the order
	 * (ddp then r2t) is garanteed.
	 * so we don't need to do any clearing of the map, just 
	 * release the resource is enough
	 */
#ifdef __ULP_MEM_WRITE_USE_DSGL__
	if (ppod_info->pdata) {
		struct pci_dev *pdev = (struct pci_dev *)odev->d_pdev;
		struct sk_buff *skb = ppod_info->pskb_list;

        	dma_unmap_single(&pdev->dev, ppod_info->paddr,
				ppod_info->plen, DMA_TO_DEVICE);
		kfree(ppod_info->pdata);
		ppod_info->pdata = NULL;

		for (; skb; skb = skb->next)
			__kfree_skb(skb);
		ppod_info->pskb_list = NULL;
	}
#endif
}

static int t4_ddp_set_map(iscsi_socket *isock, void *ttinfo_p,
			struct chiscsi_tag_ppod *ppod_info)	
{
	struct cxgbi_task_tag_info *ttinfo =
				(struct cxgbi_task_tag_info *)ttinfo_p;
	struct offload_device *odev = isock->s_odev;
	struct cxgbi_ppm *ppm = (struct cxgbi_ppm *)odev->odev2ppm(odev);
	unsigned int sg_offset = 0;
	unsigned int sg_idx = 0;
	unsigned int w_npods = 0;
	unsigned int cnt;
	unsigned int idx = ttinfo->idx;
	unsigned int npods = ttinfo->npods;
	int err = 0;
	struct sk_buff *skb = NULL;
	struct sk_buff *skb_head = NULL, *skb_tail = NULL;
#ifdef __ULP_MEM_WRITE_USE_DSGL__
	struct pci_dev *pdev = (struct pci_dev *)odev->d_pdev;
	struct cxgbi_pagepod *ppod;
	unsigned char *pdata = NULL;
	unsigned int plen = 0;
	dma_addr_t paddr;
	int i;
#endif

	if (!isock || !isock->s_odev) {
		os_log_error("%s: isock 0x%p, odev 0x%p.\n",
			 __func__, isock, isock ? isock->s_odev : NULL);
		return -EINVAL;
	}

	/*
 	 * on T4, if we use a mix of IMMD and DSGL with ULP_MEM_WRITE,
 	 * the order would not be garanteed, so we will stick with IMMD
 	 */
#ifdef __ULP_MEM_WRITE_USE_DSGL__
	plen = npods << PPOD_SIZE_SHIFT;
	pdata = kmalloc(plen, GFP_KERNEL);
        if (!pdata) {
		os_log_info("%s: dsgl ppod %u oom.\n", __func__, plen);
                return -ISCSI_ENOMEM;
	}
        paddr = dma_map_single(&pdev->dev, pdata, plen, DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(&pdev->dev, paddr))) {
		os_log_info("%s: dsgl ppod %u dma mapping error.\n",
			 __func__, plen);
		kfree(pdata);
		return -ISCSI_ENOMEM;
        }

	ppod = (struct cxgbi_pagepod *)pdata;
	for (i = 0; i < npods; i++, ppod++)
		ddp_set_one_ppod(ppod, ttinfo, &sg_idx, &sg_offset);

	ppod_info->pdata = pdata;
	ppod_info->plen = plen;
	ppod_info->paddr = paddr;
	
	for (; w_npods < npods; idx += cnt, w_npods += cnt) {
		cnt = npods - w_npods;
		if (cnt > ULPMEM_DSGL_MAX_NPPODS)
			cnt = ULPMEM_DSGL_MAX_NPPODS;

		skb = ppod_write_dsgl(isock, ppm, ttinfo, idx, cnt, paddr);
		if (!skb) {
			os_log_error("%s:ppod dsgl write err.\n", __func__);
			err = -ENOMEM;
			goto rel_resource;
			break;
		}
		skb_chain_up(skb, skb_head, skb_tail);

		paddr += cnt << PPOD_SIZE_SHIFT;
	}
#else
	/* send via immediate data */
	for (; w_npods < npods; idx += cnt, w_npods += cnt) {
		cnt = npods - w_npods;
		if (cnt > ULPMEM_IDATA_MAX_NPPODS)
			cnt = ULPMEM_IDATA_MAX_NPPODS;
		skb = ppod_write_idata(isock, ppm, ttinfo, idx, cnt, &sg_idx,
					&sg_offset);
		if (!skb) {
			/* continue writing rest of the ppod */
			os_log_error("%s:ppod imm write err.\n", __func__);
			err = -ENOMEM;
			goto rel_resource;
			break;
		}
		skb_chain_up(skb, skb_head, skb_tail);
	}
#endif
	ppod_info->pskb_list = skb_head;

	return 0;

rel_resource:
	t4_ddp_clear_map(odev, idx, ppod_info);
	return err;
}


static void ppm_make_ppod_hdr(void *ppm, u32 tag, unsigned int tid,
				unsigned int offset, unsigned int length,
				void *pi, void *hdr)
{
	cxgbi_ppm_make_ppod_hdr((struct cxgbi_ppm *)ppm, tag, tid, offset,
				length, (struct cxgbi_pdu_pi_info *)pi,
				(struct cxgbi_pagepod_hdr *)hdr);
}

static void ppm_ppod_release(void *ppm, u32 idx)
{
	cxgbi_ppm_ppod_release((struct cxgbi_ppm *)ppm, idx);
}

static int ppm_ppods_reserve(void *ppm, unsigned short nr_pages,
			u32 per_tag_pg_idx, u32 *ppod_idx, u32 *ddp_tag,
                        unsigned long caller_data)
{
	return cxgbi_ppm_ppods_reserve((struct cxgbi_ppm *)ppm, nr_pages,
                        	per_tag_pg_idx, ppod_idx, ddp_tag,
				caller_data);
}

static int t4_ddp_init(offload_device *odev)
{
	struct net_device *ndev = odev->d_ndev;
	struct toedev *tdev = odev->d_tdev;
	struct tom_data *td = TOM_DATA(tdev);
	struct cxgb4_lld_info *lldi = td->lldi;
	struct cxgbi_tag_format tformat;
	unsigned int ppmax;
	int i;
	int rv;

	if (!lldi->vr->iscsi.size) {
		os_log_warn("%s, iscsi NOT enabled, check config!\n",
			ndev->name);
		return -EACCES;
	}
	ppmax = lldi->vr->iscsi.size >> PPOD_SIZE_SHIFT;

	memset(&tformat, 0, sizeof(struct cxgbi_tag_format));
	for (i = 0; i < 4; i++) 
		tformat.pgsz_order[i] = (lldi->iscsi_pgsz_order >> (i << 3))
					 & 0xF;
	cxgbi_tagmask_check(lldi->iscsi_tagmask, &tformat);

	/* return 0, if new, 1 if exists */
	rv = cxgbi_ppm_init(lldi->iscsi_ppm, ndev, lldi->pdev, lldi, &tformat,
			ppmax, lldi->iscsi_llimit, lldi->vr->iscsi.start,
			ppm_rsvd_factor);
	if (rv >= 0) {
		struct cxgbi_ppm *ppm = (struct cxgbi_ppm *)(*lldi->iscsi_ppm);

		os_log_info("%s ppm 0x%p/0x%p, %u, pg %u, ref 0x%x.\n",
			ndev->name, t4_odev2ppm(odev), ppm, ppm->ppmax,
			ppm->tformat.pgsz_idx_dflt,
			atomic_read(&ppm->refcnt.refcount));

		if (ppm->ppmax >= 1024 &&
		    ppm->tformat.pgsz_idx_dflt < DDP_PGIDX_MAX)
			odev->d_flag |= ODEV_FLAG_ULP_DDP_ENABLED;

		odev->ppm_make_ppod_hdr = ppm_make_ppod_hdr;
		odev->ppm_ppod_release = ppm_ppod_release;
		odev->ppm_ppods_reserve = ppm_ppods_reserve;
	}

	return rv < 0 ? rv : 0;
}

/*
 * T4 offload device 
 */
static void t4_odev_cleanup(offload_device *odev)
{
	chiscsi_sgvec *sg;

	os_log_info("T%d %s odev 0x%p cleanup.\n", odev->d_version,
		((struct net_device *)odev->d_ndev)->name, odev);

	cxgbi_ppm_release(odev->odev2ppm(odev));

	sg = &odev->d_pad_pg;
	if (sg->sg_page) {
		if (sg->sg_flag & CHISCSI_SG_SBUF_DMABLE)
			pci_unmap_page(odev->d_pdev,
					sg->sg_dma_addr,
					os_page_size,
					PCI_DMA_TODEVICE);
		os_free_one_page(sg->sg_page);
	}
}

static void t4_sock_setup(iscsi_socket * isock, void *toedev);

/*
 * dma premapped address handling for tx
 */
#ifdef __SKB_HAS_PEEKED__
static void t4_skb_reset_premapped(struct sk_buff *skb)
{
	struct skb_shared_info *si = skb_shinfo(skb);

	iscsi_stats_dec(ISCSI_STAT_SBUF_TX);

	os_log_debug(ISCSI_DBG_PREMAP,
		"skb 0x%p, len %u,%u,%u, cnt %d.\n",
		 skb, skb->len, skb->data_len, skb->truesize,
		 iscsi_stats_read(ISCSI_STAT_SBUF_TX));

	ofld_skb_set_premapped_frags(skb, 0);
	si->nr_frags = 0;
	skb->truesize -= skb->data_len;
	skb->len -= skb->data_len;
}

static void skb_deferred_unmap_destructor(struct sk_buff *skb)
{
	/* skb->dev is set by sge.c when xmit happens */
	if  (skb->dev) {
		struct device *dev = netdev2adap(skb->dev)->pdev_dev;
		dma_addr_t *addr = (dma_addr_t *)skb->head;

		/* only need to unmap the pdu BHS */
        	BUG_ON(!dev);
		dma_unmap_single(dev, *addr, skb_headlen(skb), DMA_TO_DEVICE);
	}
	t4_skb_reset_premapped(skb);
}

static inline int t4_skb_set_premapped_sgl(struct sk_buff *skb,
			struct chiscsi_sgvec *sgl, unsigned int sgcnt)
{
	dma_addr_t *addr = (dma_addr_t *)skb->head;
	struct skb_shared_info *si = skb_shinfo(skb);
	int i, len = 0;


	ofld_skb_set_premapped_frags(skb, 1);
	/* leave the addr[0] for later mapping of the skb->data */
	si->nr_frags = sgcnt;
	for (i = 0; i < sgcnt; i++, sgl++) {
		addr[i + 1] = sgl->sg_dma_addr;
		si->frags[i].size = sgl->sg_length;
		len += sgl->sg_length;

		/* explicitly set page pointer to NULL */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
		si->frags[i].page = NULL;
#else
		/* do not use skb_fill_page_desc() as the page cannot be NULL
		 * in __skb_fill_page_desc() */
		si->frags[i].page.p = NULL;
#endif
		os_log_debug(ISCSI_DBG_PREMAP,
                        "skb 0x%p, frag %d/%u, %u, 0x%lx.\n",
                        skb, i, sgcnt, si->frags[i].size, sgl->sg_dma_addr);
	}
	skb->data_len = len;
	skb->len += len;
	skb->truesize += len;
	skb->destructor = skb_deferred_unmap_destructor;
	/* sge.c sets skb->dev when it processes it */
	skb->dev = NULL;

	iscsi_stats_inc(ISCSI_STAT_SBUF_TX);
	os_log_debug(ISCSI_DBG_PREMAP,
		"skb 0x%p, len %u,%u,%u, cnt %d.\n",
		 skb, skb->len, skb->data_len, skb->truesize,
		 iscsi_stats_read(ISCSI_STAT_SBUF_TX));

	 /* just to see if we made any that could be inlined */
	if (skb->len <= MAX_IMM_TX_PKT_LEN) {
		os_log_info("%s: skb 0x%p, len %u,%u,%u, sg %u.\n",
			skb, skb->len, skb->data_len, skb->truesize, sgcnt);
	}

	return len;
}
#endif

static offload_device * add_cxgb4_dev(struct net_device *ndev,
					struct toedev *tdev)
{
	struct tom_data *td = TOM_DATA(tdev);
	offload_device *odev = offload_device_new_by_tdev(tdev);
	chiscsi_sgvec *sg;

	if (!odev)
		return NULL;

	if (is_t4(td->lldi->adapter_type)) {
		odev->d_version = ULP_VERSION_T4;
		odev->d_force = 0;
	} else if (is_t5(td->lldi->adapter_type)){
		odev->d_version = ULP_VERSION_T5;
		odev->d_force = 1;
	} else {
		odev->d_version = ULP_VERSION_T6;
		odev->d_force = 1;
	}
	odev->d_flag = ODEV_FLAG_ULP_CRC_ENABLED;
	odev->d_flag |= ODEV_FLAG_TX_ZCOPY_DMA_ADDR;

	if (td->lldi->ulp_t10dif & ULP_T10DIF_ISCSI)
		odev->d_flag |= ODEV_FLAG_ULP_T10DIF_ENABLED;

	/* Enable ISO from fw version 1.13.43.0 onwards */
	if (iso_on && !is_t4(td->lldi->adapter_type) &&
	    (td->lldi->fw_vers >= 0x10d2b00)) {
		odev->d_flag |= ODEV_FLAG_ULP_ISO_ENABLED;
	}
	odev->d_ndev = ndev;
	odev->d_lldev = td->lldi;
	odev->d_tdev = tdev;
	odev->d_pdev = td->lldi->pdev;
	os_log_info("T%d %s, lldev 0x%p, tdev 0x%p, odev 0x%p, pdev 0x%p, "
		"lro %s, iso %s.\n",
		odev->d_version, ndev->name, odev->d_lldev, tdev, odev,
		odev->d_pdev, lro_on ? "enabled" : "disabled",
		(odev->d_flag & ODEV_FLAG_ULP_ISO_ENABLED) ?
				 "enabled" : "disabled");

	odev->d_tx_hdrlen = TX_HEADER_LEN;
	odev->d_payload_tmax = min_t(unsigned int, ULP2_MAX_PDU_PAYLOAD,
			td->lldi->iscsi_iolen - ISCSI_PDU_NONPAYLOAD_LEN);
	odev->d_payload_rmax = min_t(unsigned int, ULP2_MAX_PDU_PAYLOAD,
			td->lldi->iscsi_iolen - ISCSI_PDU_NONPAYLOAD_LEN);
	odev->sk_display = t4_sk_display;
	odev->sk_rx_tcp_consumed = t4_sk_rx_tcp_consumed; 
	odev->sk_tx_skb_push = t4_sendskb;
	odev->sk_tx_skb_setmode = t4_sk_tx_skb_setmode;
	//odev->sk_bind_to_cpu = t4_sk_bind_to_cpu;
	odev->sk_tx_skb_setforce = t4_sk_tx_skb_setforce;

	odev->d_pi_hdrlen = sizeof(struct fw_tx_pi_header);
	odev->sk_tx_skb_setmode_pi = t4_sk_tx_skb_setmode_pi;
	odev->sk_tx_make_pi_hdr = t4_sk_tx_make_pi_hdr;

	/* ISO: */
	odev->d_iso_hdrlen = sizeof(struct cpl_tx_data_iso);
	odev->sk_tx_skb_setmode_iso = t4_sk_tx_skb_setmode_iso;
	odev->sk_tx_make_iso_cpl = t4_sk_tx_make_iso_cpl;
		
	odev->dev_release = t4_odev_cleanup;
	odev->dev_get = odev_get;
	odev->dev_put = odev_put;
	odev->sk_set_ulp_mode = t4_sk_set_ulp_mode;
	odev->sk_rx_ulp_skb = t4_sk_rx_ulp_skb;
	odev->sk_rx_ulp_skb_ready = t4_sk_rx_ulp_skb_ready;
	odev->sk_rx_ulp_ddpinfo = t4_sk_rx_ulp_ddpinfo;

	odev->odev2ppm = t4_odev2ppm;

	odev->sk_ddp_off = os_sock_ddp_off;
	odev->isock_read_pdu_header_toe = os_sock_read_pdu_header_toe;
	odev->isock_read_pdu_data_toe = os_sock_read_pdu_data_toe;
	odev->isock_read_pdu_header_ulp = os_sock_read_pdu_header_ulp;
	odev->isock_read_pdu_data_ulp = os_sock_read_pdu_data_ulp;
	odev->isock_read_pdu_pi_ulp = os_sock_read_pdu_pi_ulp;
	odev->isock_write_pdus_toe = os_sock_write_pdus_sendskb_toe;
	odev->isock_write_pdus_ulp = os_sock_write_pdus_sendskb_ulp;
	odev->ddp_set_map = t4_ddp_set_map;
	odev->ddp_clear_map = t4_ddp_clear_map;

#ifdef __SKB_HAS_PEEKED__
	odev->skb_set_premapped_sgl = t4_skb_set_premapped_sgl;
	odev->skb_reset_premapped_sgl = t4_skb_reset_premapped;
	os_log_info("%s, skb premap enabled, destructor fp 0x%p.\n",
		 ndev->name, skb_deferred_unmap_destructor);
#else
	os_log_info("%s, skb premap disabled.\n", ndev->name);
#endif

	sg = &odev->d_pad_pg;
	sg->sg_page = os_alloc_one_page(1, &sg->sg_addr);
	if (sg->sg_page)
		memset(sg->sg_addr, 0, os_page_size);

	t4_ddp_init(odev);

	os_log_info("New T%d %s, odev 0x%p, max %u/%u.\n",
		odev->d_version, ndev->name, odev, odev->d_payload_tmax,
		odev->d_payload_rmax);

	return odev;
}

static void t4_sock_setup(iscsi_socket *isock, void *toedev)
{
	os_socket *osock = (os_socket *) isock->s_private;
	struct sock *sk = osock->sock->sk;
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	//struct toedev *tdev = cplios->toedev;
	struct toedev *tdev = (struct toedev *)toedev;
	unsigned int ulp_mode = cplios->ulp_mode;
	unsigned int tid = cplios->tid;
	struct net_device *dev = cplios->egress_dev;
	offload_device *odev;
	int     mss;

	/* if ULP_MODE is set by TOE driver, treat it as non-offloaded */
	if (ulp_mode) {
		os_log_warn("T4 sk 0x%p, ulp mode already set 0x%x.\n",
				sk, ulp_mode);
		return;
	}

	/* if toe dev is not set, treat it as non-offloaded */
	if (!tdev) {
		os_log_warn("T4 sk 0x%p, tdev NULL.\n", sk);
		return;
	}

	odev = offload_device_find_by_tdev(tdev);
	if (!odev) {
		odev = add_cxgb4_dev(dev, tdev);
		if (!odev) {
			os_log_warn("T4 sk 0x%p, tdev %s, 0x%p, odev NULL.\n",
				sk, dev->name, tdev);
			return;
		}
	}

	isock->s_odev = odev;

	mss = TOM_TUNABLE(tdev, mss);
	isock->s_tid = tid;
	isock->s_mss = mss;

	/* for connection distribution if cop is enabled. */
#ifdef DEFINED_CPLIOS_TXQ_IDX
	isock->s_cpuno = cplios->txq_idx;
#else
	isock->s_cpuno = cplios->qset_idx;
#endif
	isock->s_port_id = cplios->port_id;
	isock->s_egress_dev = (void *)cplios->egress_dev;

	os_log_info("isock 0x%p, sk 0x%p, T%d tid %u/0x%x, qset %u.\n",
		isock, sk, odev->d_version, isock->s_tid, isock->s_tid,
		isock->s_cpuno);

	/*
	 * Starting from cxgb3toe 1.1, the driver support mutiple fl entries
	 * per cpl.
	 * So on rx we don't need to force the iscsi pdu to fit into 1 fl entry
	 * any more.
	 * On tx, we just need to observe TOE's mss settings
	 */
	isock->s_rmax = odev->d_payload_rmax;
	isock->s_tmax = min_t(unsigned int, odev->d_payload_tmax,
				mss - ISCSI_PDU_NONPAYLOAD_LEN);
	isock->s_isomax = 0;

	/* XXX cap the xmit pdu size to be 12K for now until f/w is ready */
#ifdef DEFINED_CPLIOS_TXPLEN_MAX
	if (odev->d_flag & ODEV_FLAG_ULP_ISO_ENABLED) {
		/* with iso enabled, target is able to send more than 1 pdu data
	 	 * with single WR. */
		cplios->txplen_max = min_t(unsigned int,
			(MAX_SKB_FRAGS << PAGE_SHIFT), 65535);
		isock->s_isomax = cplios->txplen_max;
		os_log_info("isock 0x%p, max data in iso %u\n",
			isock, isock->s_isomax);
	} else
		cplios->txplen_max = 16384;
#endif

	if (isock->s_tmax > (12288 + ISCSI_PDU_NONPAYLOAD_LEN))
		isock->s_tmax = 12288 + ISCSI_PDU_NONPAYLOAD_LEN;

	isock->s_flag |= ISCSI_SOCKET_OFFLOADED;

//os_debug_msg("isock 0x%p, max %u,%u.\n", isock, isock->s_tmax, isock->s_rmax);
}

static unsigned char t4tom_cpl_handler_register_flag;
enum {
	TOM_CPL_ISCSI_HDR_REGISTERED_BIT,
	TOM_CPL_SET_TCB_RPL_REGISTERED_BIT,
	TOM_CPL_RX_DATA_DDP_REGISTERED_BIT,
	TOM_CPL_FW6_MSG_REGISTERED_BIT
};

static int __init t4_init(void)
{
	struct offload_device_template *odev_template = odev_template_get(1);

	os_log_info("%s: register cpl with tom.\n", __func__);
	t4tom_register_cpl_iscsi_callback(iscsi_cpl_handler_callback);
	if (lro_on)
		t4tom_register_iscsi_lro_handler(t4_iscsi_lro_recv,
					t4_iscsi_lro_proc_rx);
	if (!t4tom_cpl_handler_registered(CPL_ISCSI_HDR)) {
		t4tom_register_cpl_handler(CPL_ISCSI_HDR, do_rx_iscsi_hdr);
		t4tom_register_cpl_handler(CPL_ISCSI_DATA, do_rx_iscsi_data);
		t4tom_cpl_handler_register_flag |=
			1 << TOM_CPL_ISCSI_HDR_REGISTERED_BIT;
		os_log_info("%s: register t4 cpl handler CPL_ISCSI_HDR.\n", __func__);
	} else
		os_log_info("%s: CPL_ISCSI_HDR already registered.\n", __func__);

	if (!t4tom_cpl_handler_registered(CPL_SET_TCB_RPL)) {
		t4tom_register_cpl_handler(CPL_SET_TCB_RPL, do_set_tcb_rpl);
		t4tom_cpl_handler_register_flag |=
			1 << TOM_CPL_SET_TCB_RPL_REGISTERED_BIT;
		os_log_info("%s: register t4 cpl handler CPL_SET_TCB_RPL.\n", __func__);
	} else
		os_log_info("%s: CPL_SET_TCB_RPL handled by tom.\n", __func__);

	t4tom_register_cpl_handler(CPL_RX_ISCSI_DDP, do_rx_data_ddp);
	t4tom_register_cpl_handler(CPL_RX_ISCSI_CMP, do_rx_iscsi_cmp);
	t4tom_register_cpl_handler(CPL_RX_ISCSI_DIF, do_rx_iscsi_dif);
	if (!t4tom_cpl_handler_registered(CPL_FW6_MSG)) {
		t4tom_register_cpl_handler(CPL_FW6_MSG, do_rx_fw6_msg);
		t4tom_cpl_handler_register_flag |=
			1 << TOM_CPL_FW6_MSG_REGISTERED_BIT;
		os_log_info("%s: register t4 cpl handler CPL_FW6_MSG.\n", __func__);
	} else
		os_log_info("%s: CPL_FW6_MSG handled by tom.\n", __func__);

	if (!t4tom_cpl_handler_registered(CPL_RX_DATA_DDP)) {
		t4tom_register_cpl_handler(CPL_RX_DATA_DDP, do_rx_data_ddp);
		t4tom_cpl_handler_register_flag |=
			1 << TOM_CPL_RX_DATA_DDP_REGISTERED_BIT;
		os_log_info("%s: register t4 cpl handler CPL_RX_DATA_DDP.\n", __func__);
	} else
		os_log_info("%s: CPL_RX_DATA_DDP handled by tom.\n", __func__);

	if (!odev_template)
		return -EINVAL;

	odev_template->ttid_min = TOE_ID_CHELSIO_T4;
        odev_template->ttid_max = TOE_ID_CHELSIO_T4;
        odev_template->isock_get_ttid = isock_get_ttid;
        odev_template->isock_offload_info = t4_sock_setup;

#ifdef __ULP_MEM_WRITE_USE_DSGL__
	os_log_info("%s: ulp_mem_write via dsgl.\n", __func__);
#endif
	return 0;
}

static void t4_cleanup(void)
{
	struct offload_device_template *odev_template = odev_template_get(1);

	os_log_info("%s: de-register cpl handler with tom.\n", __func__);

	/* de-register CPL handles */
	t4tom_register_cpl_iscsi_callback(NULL);

	if (lro_on)
		t4tom_register_iscsi_lro_handler(NULL, NULL);
	if (t4tom_cpl_handler_register_flag &
		(1 << TOM_CPL_ISCSI_HDR_REGISTERED_BIT)) {
		t4tom_register_cpl_handler(CPL_ISCSI_HDR, NULL);
		t4tom_register_cpl_handler(CPL_ISCSI_DATA, NULL);
	}
	if (t4tom_cpl_handler_register_flag &
		(1 << TOM_CPL_SET_TCB_RPL_REGISTERED_BIT))
		t4tom_register_cpl_handler(CPL_SET_TCB_RPL, NULL);

	t4tom_register_cpl_handler(CPL_RX_ISCSI_CMP, NULL);
	t4tom_register_cpl_handler(CPL_RX_ISCSI_DDP, NULL);
	t4tom_register_cpl_handler(CPL_RX_ISCSI_DIF, NULL);
	if (t4tom_cpl_handler_register_flag &
		(1 << TOM_CPL_RX_DATA_DDP_REGISTERED_BIT)) {
		t4tom_register_cpl_handler(CPL_RX_DATA_DDP, NULL);
	}
	if (t4tom_cpl_handler_register_flag &
		(1 << TOM_CPL_FW6_MSG_REGISTERED_BIT)) {
		t4tom_register_cpl_handler(CPL_FW6_MSG, NULL);
	}
	t4tom_cpl_handler_register_flag = 0;

	if (odev_template)
	 	memset(odev_template, 0, sizeof(*odev_template));

	offload_device_remove_by_version(ULP_VERSION_T4);
	offload_device_remove_by_version(ULP_VERSION_T5);
	offload_device_remove_by_version(ULP_VERSION_T6);
}

module_init(t4_init);
module_exit(t4_cleanup);
