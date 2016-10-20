/*
 * Chelsio T3xx support
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
#include <common/version.h>
#include <common/iscsi_offload.h>
#include <common/iscsi_lib_export.h>

#include <kernel/cxgbi_ippm.h>
#include <kernel/os_socket.h>
#include <kernel/base_export.h>

#include <toecore/toedev.h>
#include <toecore/offload.h>
#include <t3_tom/defs.h>
#include <cxgb3/firmware_exports.h>
#include <cxgb3/cxgb3_ctl_defs.h>
#include <cxgb3/t3_cpl.h>
#include <t3_tom/cpl_io_state.h>
#include <t3_tom/tom.h>	/* T3C_DEV */

#include <kernel/cxgbi_ippm.c>

#define T3_ULP_MAX_SEGMENT_SIZE	16224
#define T3_PPOD_CPL_SIZE	(sizeof(struct ulp_mem_io) + ULP2_PPOD_SIZE)

/* iscsi module info */
MODULE_AUTHOR(MOD_AUTHOR);
MODULE_LICENSE(MOD_LICENSE);
MODULE_DESCRIPTION(DRIVER_STRING "3 v" DRIVER_VERSION);
MODULE_VERSION(DRIVER_VERSION "-" BUILD_VERSION);

/*
 * ULP2 CPL Messages
 */
struct cpl_iscsi_hdr_norss {
	union opcode_tid ot;
	u16     pdu_len_ddp;
	u16     len;
	u32     seq;
	u16     urg;
	u8      rsvd;
	u8      status;
};

struct cpl_rx_data_ddp_norss {
	union opcode_tid ot;
	u16     urg;
	u16     len;
	u32     seq;
	u32     nxt_seq;
	u32     ulp_crc;
	u32     ddp_status;
};

/* cpl rx_data_ddp status bits */
#define RX_DDP_STATUS_IPP_SHIFT         27	/* invalid pagepod */
#define RX_DDP_STATUS_TID_SHIFT         26	/* tid mismatch */
#define RX_DDP_STATUS_COLOR_SHIFT       25	/* color mismatch */
#define RX_DDP_STATUS_OFFSET_SHIFT      24	/* offset mismatch */
#define RX_DDP_STATUS_ULIMIT_SHIFT      23	/* ulimit error */
#define RX_DDP_STATUS_TAG_SHIFT         22	/* tag mismatch */
#define RX_DDP_STATUS_DCRC_SHIFT        21	/* dcrc error */
#define RX_DDP_STATUS_HCRC_SHIFT        20	/* hcrc error */
#define RX_DDP_STATUS_PAD_SHIFT         19	/* pad error */
#define RX_DDP_STATUS_PPP_SHIFT         18	/* pagepod parity error */
#define RX_DDP_STATUS_LLIMIT_SHIFT      17	/* llimit error */
#define RX_DDP_STATUS_DDP_SHIFT         16	/* ddp'able */
#define RX_DDP_STATUS_PMM_SHIFT         15	/* pagepod mismatch */

const unsigned long os_page_size = PAGE_SIZE;
 
static void* t3_odev2ppm(offload_device *odev)
{
	return odev ?  ((struct t3cdev *)odev->d_lldev)->ulp_iscsi : NULL;
}


static void t3_ulp_abort_conn(struct sock *sk)
{
	struct sk_buff *skb = alloc_skb_nofail(sizeof(struct cpl_abort_req));
	skb_ulp_lhdr(sk) = NULL;
	t3_send_reset(sk, CPL_ABORT_SEND_RST, skb);
}

static void t3_ulp_proc_rx_data_ddp(struct sk_buff *skb,
				    struct cpl_rx_data_ddp_norss *ddp_cpl)
{
	u32     val;
	u8      flag = skb_ulp_mode(skb);

	skb_ulp_ddigest(skb) = ntohl(ddp_cpl->ulp_crc);
	skb_ulp_pdulen(skb) = ntohs(ddp_cpl->len);

	val = ntohl(ddp_cpl->ddp_status);

	if (val & (1 << RX_DDP_STATUS_HCRC_SHIFT))
		flag |= SBUF_ULP_FLAG_HCRC_ERROR;
	if (val & (1 << RX_DDP_STATUS_DCRC_SHIFT))
		flag |= SBUF_ULP_FLAG_DCRC_ERROR;
	if (val & (1 << RX_DDP_STATUS_PAD_SHIFT))
		flag |= SBUF_ULP_FLAG_PAD_ERROR;

	if (!(flag & SBUF_ULP_FLAG_DATA_RCVD))
		flag |= SBUF_ULP_FLAG_DATA_DDPED;

	if (flag & SBUF_ULP_FLAG_COALESCE_OFF)
		flag &= ~SBUF_ULP_FLAG_DATA_RCVD;

	skb_ulp_mode(skb) = flag | SBUF_ULP_FLAG_STATUS_RCVD;

#if 0
	os_log_debug(ISCSI_DBG_ULP,
		     "skb 0x%p, pdu %u, dcrc 0x%x, 0x%x -> 0x%x.\n",
		     skb, skb_ulp_pdulen(skb), skb_ulp_ddigest(skb),
		     val, skb_ulp_mode(skb));
#endif
}

/* supports only coalesced msg */
static void iscsi_process_rx_iscsi_hdr(struct sock *sk, struct sk_buff *skb)
{
	struct cpl_iscsi_hdr *header_cpl = cplhdr(skb);
	struct cpl_iscsi_hdr_norss data_cpl;
	struct cpl_rx_data_ddp_norss ddp_cpl;
	u32     dlen;
	u32     header_len;
	int     rv;

	data_cpl.len = 0;
	if (unlikely(sk_in_state(sk, TCPF_FIN_WAIT1 | TCPF_FIN_WAIT2) &&
		     (sk->sk_shutdown & RCV_SHUTDOWN))) {
		goto err_out;
	}

	/*
	   RX_ISCSI_HDR can be coalesced.
	   An coalesced RX_ISCSI_HDR msg could contain either
	   1). RX_ISCSI_HDR + RX_ISCSI_HDR + RX_DATA_DDP or
	   2). RX_ISCSI_HDR + RX_DATA_DDP
	   The resulting skb's length will include the 2nd RX_ISCSI_HDR(16).
	 */

	header_len = ntohs(header_cpl->len);
	__skb_pull(skb, sizeof(struct cpl_iscsi_hdr));

	/* msg coalesce is off */
	if (skb->len <= header_len) {
		os_log_warn("t3 iscsi msg coalesce off is NOT supported.\n", sk);
		t3_ulp_abort_conn(sk);
		goto err_out;
	}

#if 0
	os_log_debug(ISCSI_DBG_ULP,
		     "sk 0x%p, skb 0x%p, len %u, 1st cpl len %u.\n",
		     sk, skb, skb->len, header_len);
#endif


	dlen = header_len;
	skb_ulp_mode(skb) |= SBUF_ULP_FLAG_HDR_RCVD;

	rv = skb_copy_bits(skb, skb->len - sizeof(struct cpl_rx_data_ddp_norss),
			&ddp_cpl, sizeof(struct cpl_rx_data_ddp_norss));
	if (rv < 0) {
		os_log_warn("t3 failed to get CPL_RX_DATA_DDP %d, skb 0x%p, len %u.\n",
			 rv, skb, skb->len);
		t3_ulp_abort_conn(sk);
		goto err_out;
	}

	/* pdu data included */
	if (skb->len > (header_len + sizeof(struct cpl_rx_data_ddp_norss))) {
		rv = skb_copy_bits(skb, header_len, &data_cpl,
				   sizeof(struct cpl_iscsi_hdr_norss));
		if (rv < 0) {
			os_log_warn("t3 failed to get 2nd CPL_ISCSI_HDR %d, skb 0x%p, len %u.\n",
				 rv, skb, skb->len);
			t3_ulp_abort_conn(sk);
			goto err_out;
		}

		/* include the cpl header length for the pdu payload */
		dlen += ntohs(data_cpl.len) +
			sizeof(struct cpl_iscsi_hdr_norss);
		skb_ulp_mode(skb) |= SBUF_ULP_FLAG_DATA_RCVD;
//os_debug_msg("pdu not ddp'ed, opcode 0x%x.\n", skb->data[header_len]);
	}

	/* parse rx_data_ddp */
	t3_ulp_proc_rx_data_ddp(skb, &ddp_cpl);

	tcp_sk(sk)->rcv_nxt = ntohl(ddp_cpl.seq) + ntohs(ddp_cpl.len);
	inet_csk(sk)->icsk_ack.lrcvtime = tcp_time_stamp;

	__pskb_trim(skb, dlen);
	__skb_queue_tail(&sk->sk_receive_queue, skb);

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_data_ready(sk, 0);

	return;

err_out:
	kfree_skb(skb);
	return;
}

static int t3_ulp_rx_iscsi_hdr_callback(struct t3cdev *cdev,
					struct sk_buff *skb, void *ctx)
{
	struct sock *sk = (struct sock *) ctx;

	process_cpl_msg(iscsi_process_rx_iscsi_hdr, sk, skb);
	return 0;
}

static void iscsi_process_set_tcb_rpl(struct sock *sk, struct sk_buff *skb)
{
	iscsi_socket *isock = (iscsi_socket *) sk->sk_user_data;
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);

	if (cplios->ulp_mode == ULP_MODE_ISCSI) {
		/* probably should check if there is any error, but then
		   if there is any, we are in deep trouble */
		//struct cpl_set_tcb_rpl *hdr = cplhdr(skb);
		if (isock && isock->s_txhold) {
			isock->s_txhold--;
			if (!isock->s_txhold) 
				iscsi_socket_write_space(isock, 0);
		} else if (isock) {
			iscsi_socket_write_space(isock, 1);
		}
	}

	kfree_skb(skb);
	return;
}

static int t3_ulp_set_tcb_rpl_callback(struct t3cdev *cdev, struct sk_buff *skb,
				       void *ctx)
{
	struct sock *sk = (struct sock *) ctx;

	//if (sk->sk_state == TCP_ESTABLISHED)
		process_cpl_msg(iscsi_process_set_tcb_rpl, sk, skb);
	return 0;
}

/* 
 * ULP2 RX read skb
 */

static void t3_sk_rx_tcp_consumed(iscsi_socket * isock, unsigned int used)
{
	struct sock *sk = ((os_socket *) isock->s_private)->sock->sk;

	if (tcp_sk(sk)) {
		tcp_sk(sk)->copied_seq += used;
		t3_cleanup_rbuf(sk, used, 0);
	}
}

/* if skb is result of ULP rx */
static int t3_sk_rx_ulp_skb(void *sbuf)
{
	struct sk_buff *skb = (struct sk_buff *)sbuf;
	return (skb_ulp_mode(skb) ? 1 : 0);
}

/* if skb is ready to read (i.e., CPL_RX_DATA_DDP has been received) */
static int t3_sk_rx_ulp_skb_ready(void *sbuf)
{
	struct sk_buff *skb = (struct sk_buff *)sbuf;
	return ((skb_ulp_mode(skb)) &
		(SBUF_ULP_FLAG_STATUS_RCVD | SBUF_ULP_FLAG_DATA_RCVD));
}

/* read out the ulp ddp status and data digest */
static int t3_sk_rx_ulp_ddpinfo(void *sbuf, iscsi_pdu *pdu, void *rcb_p)
{
	struct sk_buff *skb = (struct sk_buff *)sbuf;
	struct rx_cb *rcb = (struct rx_cb *)rcb_p;
	unsigned char flag = skb_ulp_mode(skb);

	if (rcb->pdu_idx) {
		os_log_error("%s: skb 0x%p, pdu idx %d >= 1.\n",
				__func__, skb, rcb->pdu_dix);
                return -EINVAL;
        }

	rcb->fmode = RXCBF_COALESCED;

	pdu->p_totallen = skb_ulp_pdulen(skb);
	*(pdu->p_ddigest) = skb_ulp_ddigest(skb);

	if (flag & SBUF_ULP_FLAG_HCRC_ERROR)
		pdu->p_flag |= ISCSI_PDU_FLAG_ERR_HDR_DIGEST;
	if (flag & SBUF_ULP_FLAG_DCRC_ERROR)
		pdu->p_flag |= ISCSI_PDU_FLAG_ERR_DATA_DIGEST;
	if (flag & SBUF_ULP_FLAG_PAD_ERROR)
		pdu->p_flag |= ISCSI_PDU_FLAG_ERR_DATA_PAD;
	if (flag & SBUF_ULP_FLAG_DATA_DDPED)
		pdu->p_flag |= ISCSI_PDU_FLAG_DATA_DDPED;

	return 0;
}

/*
 * ULP2 TX sendskb
 */
static void t3_sk_tx_skb_setmode(void *sbuf, unsigned char mode,
				unsigned char hcrc, unsigned char dcrc)
{
	struct sk_buff *skb = (struct sk_buff *)sbuf;

	if (mode & ISCSI_OFFLOAD_MODE_ULP) {
		u8      ulp_mode = 0;

		if (hcrc)
			ulp_mode |= 1;
		if (dcrc)
			ulp_mode |= 2;
		skb_ulp_mode(skb) = (ULP_MODE_ISCSI << 4) | ulp_mode;
	} else 
		skb_ulp_mode(skb) = 0;
}

static void t3_sk_tx_skb_setforce(void *sbuf, unsigned char adapter_type,
			unsigned char force)
{
	/* Nothing to do */
	return;
}

/*
 * ULP2: TOE -> ULP transition 
 */

/**
 * t3_setup_conn_pgidx - setup the conn.'s ddp page size
 * @tdev: t3cdev adapter
 * @tid: connection id
 * @pg_idx: ddp page size index
 * @reply: request reply from h/w
 * set up the ddp page size based on the host PAGE_SIZE for a connection
 * identified by tid
 */
static int t3_setup_conn_pgidx(struct t3cdev *tdev, unsigned int tid,
				int pg_idx, int reply)
{
	struct sk_buff *skb = alloc_skb(sizeof(struct cpl_set_tcb_field),
					GFP_KERNEL);
	struct cpl_set_tcb_field *req;
	u64 val = pg_idx < DDP_PGIDX_MAX ? pg_idx : 0;

	if (!skb)
		return -ENOMEM;

	/* set up ulp submode and page size */
	req = (struct cpl_set_tcb_field *)skb_put(skb, sizeof(*req));
	req->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_FORWARD));
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_SET_TCB_FIELD, tid));
	req->reply = V_NO_REPLY(reply ? 0 : 1);
	req->cpu_idx = 0;
	req->word = htons(31);
	req->mask = cpu_to_be64(0xF0000000);
	req->val = cpu_to_be64(val << 28);
	skb->priority = CPL_PRIORITY_CONTROL;

	cxgb3_ofld_send(tdev, skb);
	return 0;
}

/**
 * t3_setup_conn_digest - setup conn. digest setting
 * @tdev: t3cdev adapter
 * @tid: connection id
 * @hcrc: header digest enabled
 * @dcrc: data digest enabled
 * @reply: request reply from h/w
 * set up the iscsi digest settings for a connection identified by tid
 */
static int t3_setup_conn_digest(struct t3cdev *tdev, unsigned int tid,
			     int hcrc, int dcrc, int reply)
{
	struct sk_buff *skb = alloc_skb(sizeof(struct cpl_set_tcb_field),
					GFP_KERNEL);
	struct cpl_set_tcb_field *req;
	u64 val = (hcrc ? 1 : 0) | (dcrc ? 2 : 0);

	if (!skb)
		return -ENOMEM;

	/* set up ulp submode and page size */
	req = (struct cpl_set_tcb_field *)skb_put(skb, sizeof(*req));
	req->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_FORWARD));
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_SET_TCB_FIELD, tid));
	req->reply = V_NO_REPLY(reply ? 0 : 1);
	req->cpu_idx = 0;
	req->word = htons(31);
	req->mask = cpu_to_be64(0x0F000000);
	req->val = cpu_to_be64(val << 24);
	skb->priority = CPL_PRIORITY_CONTROL;

	cxgb3_ofld_send(tdev, skb);
	return 0;
}

/**
 * t3_setup_conn_ulpmode - setup the conn. to be offloaded as iscsi conn.
 * @tdev: t3cdev adapter
 * @tid: connection id
 * @reply: request reply from h/w
 * set up a TCP connection to be offloaded as iscsi connection identified by
 * tid
 */
static int t3_setup_conn_ulpmode(struct t3cdev *tdev, unsigned int tid,
				    int reply)
{
	struct sk_buff *skb = alloc_skb(sizeof(struct cpl_set_tcb_field),
					GFP_KERNEL);
	struct cpl_set_tcb_field *req;

	if (!skb)
		return -ENOMEM;

	/* set up ulp submode and page size */
	req = (struct cpl_set_tcb_field *)skb_put(skb, sizeof(*req));
	req->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_FORWARD));
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_SET_TCB_FIELD, tid));
	req->reply = V_NO_REPLY(reply ? 0 : 1);
	req->cpu_idx = 0;
	req->word = htons(25);
	req->mask = cpu_to_be64(0x3C000000);
	req->val = cpu_to_be64(0x8000000);
	skb->priority = CPL_PRIORITY_CONTROL;

	cxgb3_ofld_send(tdev, skb);
	return 0;
}

static int t3_sk_set_ulp_mode(iscsi_socket *isock, unsigned char hcrc,
				unsigned char dcrc, unsigned char t10dif)
{
	offload_device *odev = isock->s_odev;
	os_socket *osock = (os_socket *) isock->s_private;
	struct sock *sk = osock->sock->sk;
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct cxgbi_ppm *ppm = (struct cxgbi_ppm *)odev->odev2ppm(odev);
	int rv;

	isock->s_txhold = 3; /* we will wait for three CPL_SET_TCB_RPL */

	/* set up ulp mode */
	rv = t3_setup_conn_ulpmode(odev->d_lldev, isock->s_tid, 1);
	if (rv < 0)
		return rv;
	/* set mode for TOM */
	cplios->ulp_mode = ULP_MODE_ISCSI;

	/* set up ddp page size */
	isock->s_ddp_pgidx = ppm->tformat.pgsz_idx_dflt;
	rv = t3_setup_conn_pgidx(odev->d_lldev, isock->s_tid,
				isock->s_ddp_pgidx, 1);
	if (rv < 0)
		return rv;

	/* set up digest setttings */
	rv = t3_setup_conn_digest(odev->d_lldev, isock->s_tid, hcrc, dcrc, 1);
	return rv;
}

static int t3_sk_bind_to_cpu(iscsi_socket * isock, unsigned int cpuno)
{
	u32     tid = isock->s_tid;
	offload_device *dev = isock->s_odev;
	struct sk_buff *skb =
		alloc_skb_nofail(sizeof(struct cpl_set_tcb_field));
	struct cpl_set_tcb_field *req;

	/* set up ulp mode */
	req = (struct cpl_set_tcb_field *)__skb_put(skb, sizeof(*req));
	req->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_FORWARD));
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_SET_TCB_FIELD, tid));
	req->reply = 0;		/* we want a reply */
	req->cpu_idx = 0;
	req->word = htons(25);
	req->mask = cpu_to_be64(0x3F80000);
	req->val = cpu_to_be64(cpuno << 19);
	skb->priority = CPL_PRIORITY_CONTROL;
	cxgb3_ofld_send(dev->d_lldev, skb);

	return 0;
}

/*
 * functions to program the pagepod in h/w
 */
static inline void ulp_mem_io_set_hdr(struct sk_buff *skb, unsigned int addr)
{
	struct ulp_mem_io *req = (struct ulp_mem_io *)skb->head;

	req->wr.wr_lo = 0;
	req->wr.wr_hi = htonl(V_WR_OP(FW_WROPCODE_BYPASS));
	req->cmd_lock_addr = htonl(V_ULP_MEMIO_ADDR(addr >> 5) |
				   V_ULPTX_CMD(ULP_MEM_WRITE));
	req->len = htonl(V_ULP_MEMIO_DATA_LEN(IPPOD_SIZE >> 5) |
			 V_ULPTX_NFLITS((IPPOD_SIZE >> 3) + 1));
}

#define DDP_MSG_SIZE	(sizeof(struct ulp_mem_io) + IPPOD_SIZE)
static int t3_ddp_set_map(struct cxgbi_ppm *ppm, unsigned int idx,
			unsigned int npods,
			struct cxgbi_ddp_tag_info *pdata)
{
	unsigned int pm_addr = (idx << PPOD_SIZE_SHIFT) + ppm->llimit;
	struct cxgbi_pagepod_hdr *hdr = tag_info->hdr;,
	struct cxgbi_gather_list *gl = (struct cxgbi_gather_list *)tag_info->sgl;
	int i;

	for (i = 0; i < npods; i++, idx++, pm_addr += IPPOD_SIZE) {
		struct cxgbi_pagepod *ppod;
		int j, pidx;
		struct sk_buff *skb = alloc_skb(DDP_MSG_SIZE,
						GFP_KERNEL | __GFP_NOFAIL);

		if (!skb)
			return -ENOMEM;
		memset(skb->data, 0, DDP_MSG_SIZE);
		__skb_put(skb, DDP_MSG_SIZE);

		ulp_mem_io_set_hdr(skb, pm_addr);
		ppod = (struct cxgbi_pagepod *)(skb->head +
						sizeof(struct ulp_mem_io));
		memcpy(&(ppod->hdr), hdr, sizeof(struct cxgbi_pagepod));
		for (pidx = 4 * i, j = 0; j < 5; ++j, ++pidx)
			ppod->addr[j] = pidx < gl->nelem ?
				     cpu_to_be64(gl->phys_addr[pidx]) : 0UL;

		skb->priority = CPL_PRIORITY_CONTROL;
		cxgb3_ofld_send(ppm->lldev, skb);
	}

	/* if reply is needed, send a set_tcb_field */
        if (tag_info->reply)
                t3_setup_conn_ulpmode(ppm->lldev, htonl(hdr->vld_tid), 1);
	return 0;
}

static void t3_ddp_clear_map(struct cxgbi_ppm *ppm, void *dev,
			unsigned int idx, int reply, 
			struct cxgbi_ppod_data *pdata)
{
	unsigned int pm_addr = (idx << PPOD_SIZE_SHIFT) + ppm->llimit;
	struct sk_buff *skb = alloc_skb(DDP_MSG_SIZE, GFP_KERNEL | __GFP_NOFAIL);

	if (!skb)
		return;
	memset(skb->data, 0, DDP_MSG_SIZE);
	__skb_put(skb, DDP_MSG_SIZE);
	ulp_mem_io_set_hdr(skb, pm_addr);
	skb->priority = CPL_PRIORITY_CONTROL;
	cxgb3_ofld_send(ppm->lldev, skb);
}

static int t3_sk_ddp_tag_reserve(iscsi_socket *isock, unsigned int xferlen,
				chiscsi_sgvec *sgl, unsigned int sgcnt,
				unsigned int sw_tag, unsigned int *ddp_tag,
				void *pi_info)
{
	offload_device *odev = isock->s_odev;
	struct cxgbi_ppm *ppm = (struct cxgbi_ppm *)odev->odev2ppm(odev);
	struct cxgbi_gather_list *gl;
	struct cxgbi_pagepod_hdr hdr;
	struct cxgbi_ddp_tag_info tag_info;
	int err = -EINVAL;

	gl = cxgbi_ddp_make_gl_from_chiscsi_sgvec(ppm, isock->s_ddp_pgidx,
				xferlen, sgl, sgcnt, GFP_ATOMIC);
	if (!gl)
		return err;

	err = cxgbi_ddp_gl_map(ppm, gl);
	if (err < 0)
		goto err_out;

	memset(&tag_info, 0, sizeof(tag_info));
	tag_info.tid = isock->s_tid;
	tag_info.base_tag = sw_tag;
	tag_info.caller_data = (unsigned long)sw_tag;
	tag_info.ddp_tag = *ddp_tag;

	tag_info.sgl = (void *)gl;
	tag_info.sgcnt = gl->nelem;
	tag_info.length = gl->length 
	tag_info.offset = gl->offset;
	tag_info.reply = sgl->sg_flag & CHISCSI_SG_SBUF_DMA_ONLY ? 1 : 0;
	tag_info.isk = (void *)isock;
	tag_info.hdr = &hdr;

	err = cxgbi_ppm_tag_reserve(ppm, &tag_info, t3_ddp_set_map);
	if (err < 0)
		goto err_out;

	*ddp_tag = tag_info.ddp_tag;
	return 0;

err_out:
	if (err < 0)
		cxgbi_ddp_release_gl(ppm, gl);
	return err;
}

static int t3_sk_ddp_tag_release(iscsi_socket *isock, unsigned int ddp_tag)
{
	offload_device *odev = isock->s_odev;
	struct cxgbi_ppm *ppm = (struct cxgbi_ppm *)odev->odev2ppm(odev);

	cxgbi_ppm_tag_release(ppm, ddp_tag, isock, 0, t3_ddp_clear_map);
	return 0;
}


static void t3_odev_cleanup(offload_device *odev)
{
	chiscsi_sgvec *sg;

	os_log_info("T3 %s odev 0x%p cleanup.\n",
		((struct net_device *)odev->d_ndev)->name, odev);

	cxgbi_ppm_release(odev->odev2ppm(odev));

	sg = &odev->d_pad_pg;
	if (sg->sg_page) {
		if (sg->sg_flag & CHISCSI_SG_SBUF_DMABLE)
			pci_unmap_page(odev->d_pdev, sg->sg_dma_addr,
					os_page_size, PCI_DMA_TODEVICE);
		os_free_one_page(sg->sg_page);
		sg->sg_page = NULL;
	}
}

static int t3_ddp_init(offload_device *odev)
{
	struct t3cdev *t3dev = odev->d_lldev;
	struct net_device *ndev = t3dev->lldev;
	struct ulp_iscsi_info uinfo;
	struct cxgbi_tag_format tformat;
	unsigned int ppmax, tagmask;
	int i, err;

	memset(&uinfo, 0, sizeof(struct ulp_iscsi_info));
	err = t3dev->ctl(t3dev, ULP_ISCSI_GET_PARAMS, &uinfo);
	if (err < 0) {
		os_log_error("T3 %s, failed to get iscsi param err=%d.\n",
			t3dev->name, err);
		return err;
	}
	if (uinfo.llimit >= uinfo.ulimit) {
		os_log_warn("T3 %s, iscsi NOT enabled %u ~ %u!\n",
			ndev->name, uinfo.llimit, uinfo.ulimit);
                return -EACCES;
	}
	ppmax = (uinfo.ulimit - uinfo.llimit + 1) >> PPOD_SIZE_SHIFT;
	tagmask = cxgbi_tagmask_set(ppmax);

	os_log_info("T3 %s: 0x%x~0x%x, 0x%x, tagmask 0x%x -> 0x%x.\n",
		ndev->name, uinfo.llimit, uinfo.ulimit, uinfo.tagmask, tagmask);

	memset(&tformat, 0, sizeof(struct cxgbi_tag_format));
	for (i = 0; i < 4; i++)
		tformat.pgsz_order[i] = uinfo.pgsz_factor[i];
	cxgbi_tagmask_check(tagmask, &tformat);

        /* return 0, if new, 1 if exists */
	err = cxgbi_ppm_init(&t3dev->ulp_iscsi, t3dev->lldev, uinfo.pdev,
			t3dev, &tformat, ppmax, uinfo.llimit, uinfo.llimit, 0);
	if (err >= 0) {
		struct cxgbi_ppm *ppm = (struct cxgbi_ppm *)t3dev->ulp_iscsi;

		uinfo.tagmask = tagmask;
		uinfo.ulimit = uinfo.llimit + (ppm->nppods << PPOD_SIZE_SHIFT);
		err = t3dev->ctl(t3dev, ULP_ISCSI_SET_PARAMS, &uinfo);
		if (err < 0)
			os_log_error("T3 %s fail to set iscsi param %d.\n",
				ndev->name, err);
		else if (ppm->nppods >= 1024 &&
			ppm->tformat.pgsz_idx_dflt < DDP_PGIDX_MAX)
			odev->d_flag |= ODEV_FLAG_ULP_DDP_ENABLED;

		err = 0;
        }

	odev->d_payload_tmax = min_t(unsigned int, ULP2_MAX_PDU_PAYLOAD,
                                uinfo.max_txsz - ISCSI_PDU_NONPAYLOAD_LEN);
        odev->d_payload_rmax = min_t(unsigned int, ULP2_MAX_PDU_PAYLOAD,
                                uinfo.max_rxsz - ISCSI_PDU_NONPAYLOAD_LEN);
	
	return err;
}

static void t3_sock_setup(iscsi_socket *isock, void *toedev)
{
	os_socket *osock = (os_socket *) isock->s_private;
	struct sock *sk = osock->sock->sk;
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	unsigned int ulp_mode = cplios->ulp_mode;
	unsigned int tid = cplios->tid;
	struct toedev *tdev = (struct toedev *)toedev;
	struct tom_data *d = NULL;
	struct t3cdev *t3dev = NULL;
	offload_device *odev;
	int     mss;

	/* if ULP_MODE is set by TOE driver, treat it as non-offloaded */
	if (ulp_mode) {
		os_log_warn("t3 sk 0x%p, ulp mode already set 0x%x.\n",
				sk, ulp_mode);
		return;
	}

//	os_log_info("t3 sk 0x%p, tdev 0x%p/0x%p.\n", sk, tdev, cplios->toedev);

	/* if toe dev or t3cdev is not set, treat it as non-offloaded */
	if (!tdev) {
		os_log_warn("t3 sk 0x%p, state 0x%x, tdev NULL.\n",
			sk, sk->sk_state);
		return;
	}
	d = TOM_DATA(tdev);
	if (!d || !d->cdev) {
		os_log_warn("t3 sk 0x%p, tdev 0x%p, tom_data 0x%p.\n",
			sk, tdev, d);
		return;
	}
	t3dev = d->cdev;
	if (!t3dev) {
		os_log_warn("t3 sk 0x%p, state 0x%x, t3cdev NULL.\n",
			sk, sk->sk_state);
		return;
	}

	odev = offload_device_find_by_tdev(tdev);
	if (!odev) {
		os_log_warn("t3 sk 0x%p, t3dev 0x%p, odev NULL.\n", sk, t3dev);
		return;
	}

	isock->s_odev = odev;

	mss = TOM_TUNABLE(tdev, mss);
	isock->s_tid = tid;
	isock->s_mss = mss;

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

	isock->s_flag |= ISCSI_SOCKET_OFFLOADED;
os_log_info("%s: isock 0x%p offloaded.\n", __func__, isock);
}

#include <kernel/os_socket_offload.h>
static void open_cxgb3_dev(struct t3cdev *t3dev)
{
	struct net_device *ndev = t3dev->lldev;
	struct toedev *tdev = TOEDEV(ndev);
	offload_device *odev = offload_device_new_by_tdev(tdev);
	chiscsi_sgvec *sg;

	if (!odev)
		return; 

	odev->d_version = ULP_VERSION_T3;
	odev->d_ulp_rx_datagap = sizeof(struct cpl_iscsi_hdr_norss);
	odev->d_flag = ODEV_FLAG_ULP_CRC_ENABLED;

	odev->d_lldev = t3dev;
	odev->d_tdev = tdev;
	os_log_info("New T3 %s, lld 0x%p, tdev 0x%p, odev 0x%p.\n",
		ndev->name, t3dev, odev->d_tdev, odev);

	odev->d_tx_hdrlen = TX_HEADER_LEN;
	odev->sk_rx_tcp_consumed = t3_sk_rx_tcp_consumed; 
	odev->sk_tx_skb_push = t3_sendskb;
	odev->sk_tx_skb_setmode = t3_sk_tx_skb_setmode;
	odev->sk_tx_skb_setforce = t3_sk_tx_skb_setforce;
	odev->sk_bind_to_cpu = t3_sk_bind_to_cpu;

	odev->dev_release = t3_odev_cleanup;
	odev->sk_set_ulp_mode = t3_sk_set_ulp_mode;
	odev->sk_rx_ulp_skb = t3_sk_rx_ulp_skb;
	odev->sk_rx_ulp_skb_ready = t3_sk_rx_ulp_skb_ready;
	odev->sk_rx_ulp_ddpinfo = t3_sk_rx_ulp_ddpinfo;

	odev->odev2ppm = t3_odev2ppm;

	odev->sk_ddp_off = os_sock_ddp_off;
	odev->isock_read_pdu_header_toe = os_sock_read_pdu_header_toe;
	odev->isock_read_pdu_data_toe = os_sock_read_pdu_data_toe;
	odev->isock_read_pdu_header_ulp = os_sock_read_pdu_header_ulp;
	odev->isock_read_pdu_data_ulp = os_sock_read_pdu_data_ulp;
	odev->isock_write_pdus_toe = os_sock_write_pdus_sendskb_toe;
	odev->isock_write_pdus_ulp = os_sock_write_pdus_sendskb_ulp;
	odev->isock_ddp_tag_reserve = t3_sk_ddp_tag_reserve;
	odev->isock_ddp_tag_release = t3_sk_ddp_tag_release;

	t3tom_register_cpl_handler(CPL_ISCSI_HDR,
				   t3_ulp_rx_iscsi_hdr_callback);
	t3tom_register_cpl_handler(CPL_SET_TCB_RPL,
				   t3_ulp_set_tcb_rpl_callback);
#if 0
	/* disable handling non-coalesced iscsi message, since tcp ddp will be 
	   using the same cpl */
	t3tom_register_cpl_handler(CPL_RX_DATA_DDP,
				   t3_ulp_rx_data_ddp_callback);
#endif

	sg = &odev->d_pad_pg;
	sg->sg_page = os_alloc_one_page(1, &sg->sg_addr);
	if (sg->sg_page)
		memset(sg->sg_addr, 0, os_page_size);

	t3_ddp_init(odev);

	os_log_info("New T3 %s, odev 0x%p, max %u/%u.\n",
		ndev->name, odev, odev->d_payload_tmax, odev->d_payload_rmax);
}

static void close_cxgb3_dev(struct t3cdev *t3dev)
{
	struct net_device *ndev = t3dev->lldev;
	struct toedev *tdev = TOEDEV(ndev);
	offload_device *odev = offload_device_find_by_tdev(tdev);

	/* de-register CPL handles */
	t3tom_register_cpl_handler(CPL_ISCSI_HDR, NULL);
	t3tom_register_cpl_handler(CPL_SET_TCB_RPL, NULL);

	if (!odev)
		return;

	offload_device_delete(odev);
	t3_odev_cleanup(odev);
	os_free(odev);
}

static struct cxgb3_client t3c_client = {
        .name = "chiscsi_t3",
        .add = open_cxgb3_dev,
        .remove = close_cxgb3_dev,
};

static int __init t3_init(void)
{
	struct offload_device_template *odev_template = odev_template_get(0);

	if (!odev_template)
		return -EINVAL;
	odev_template->ttid_min = TOE_ID_CHELSIO_T3;
	odev_template->ttid_max = TOE_ID_CHELSIO_T3C;
	odev_template->isock_get_ttid = isock_get_ttid;
	odev_template->isock_offload_info = t3_sock_setup;
	
	cxgb3_register_client(&t3c_client);
	return 0;
}

static void t3_cleanup(void)
{
	struct offload_device_template *odev_template = odev_template_get(0);

	cxgb3_unregister_client(&t3c_client);

	if (odev_template)
		memset(odev_template, 0, sizeof(*odev_template));

	offload_device_remove_by_version(ULP_VERSION_T3);
}

module_init(t3_init);
module_exit(t3_cleanup);
