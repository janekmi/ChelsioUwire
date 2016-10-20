/*
 * kernel socket buffer (skb) send and receive
 */
#ifdef KERNEL_HAS_EXPORT_H
#include <linux/export.h>
#endif
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <net/sock.h>

#include <common/iscsi_common.h>
#include <common/iscsi_lib_export.h>
#include <common/iscsi_offload.h>
#include <kernel/os_socket.h>

extern struct page *dummy_page;
extern unsigned char *dummy_page_addr;
extern unsigned int iscsi_test_mode;
extern struct page *rsvd_pages[];
extern unsigned char *rsvd_pages_addr[];

/* NOTE:
	- if sk is offloaded, pdu < mss (TOM):
	  since pdu size is negotiated at the login phase, a user
	  should NOT change mss (or at least not decrease it) after
	  iSCSI is up and running.
*/

/*
 *
 * sk pdu read
 *
 */

int os_sock_pdu_bhs_error(iscsi_socket *isock, unsigned char *bhs,
			unsigned int blen)
{
	unsigned int dlen = ntohl(*(unsigned int *)(bhs + 4)) & 0xFFFFFF;
	unsigned char opcode = *bhs & 0x3F;

	if (!(IS_INITIATOR_OPCODE(opcode)))
		return 1;
	if (isock && dlen >= isock->s_rmax)
		return 1;
	if (dlen >= 16224)
		return 1;
	return 0;
}

/*
 * NIC mode: pdu read via sock_recvmsg()
 */
static int sock_read_data(iscsi_socket * isock, unsigned char *buf, int len)
{
	struct socket 	*sock = ((os_socket *) (isock->s_private))->sock;
	mm_segment_t fs;
	int rv;
	struct kvec iov = {
		.iov_base = (char *) buf,
		.iov_len = (__kernel_size_t) len,
	};
	struct msghdr msg = {
		.msg_flags = (MSG_DONTWAIT | MSG_NOSIGNAL)
	};

	fs = get_fs();
	set_fs(KERNEL_DS);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0))
	msg.msg_iovlen = 1;
	msg.msg_iov = (struct iovec *)&iov;
	rv = sock_recvmsg(sock, &msg, len, msg.msg_flags);
#else
	rv = kernel_recvmsg(sock, &msg, &iov, 1, len, msg.msg_flags);
#endif
	set_fs(fs);

	if (rv >= 0)
		return rv;

	if (rv == -EAGAIN)
		return 0;

	os_log_info("%s: rv %d, sock state 0x%x.\n", __func__,
		rv, sock->sk ? sock->sk->sk_state : 0xFF);

	return rv;
}

int os_sock_read_pdu_header_nic(iscsi_socket *isock, iscsi_pdu *pdu)
{
	unsigned int offset = pdu->p_offset;
	unsigned int pmin, pmax;
	int len, rv = 0;

	do {
		/* BHS */
		pmin = pmax = ISCSI_BHS_SIZE;

		if (pdu->p_offset < ISCSI_BHS_SIZE) {
			len = ISCSI_BHS_SIZE - pdu->p_offset;
			rv = sock_read_data(isock, pdu->p_head + pdu->p_offset,
					len);
			if (rv > 0)
				pdu->p_offset += rv;
			if (rv < len)
				goto done;

			if (pdu->p_offset == ISCSI_BHS_SIZE) {
				rv = iscsi_pdu_parse_header(pdu);
				if (rv < 0) {
					os_log_info("isock 0x%p, nic, parse BHS failed, %d.\n",
						isock, rv);
					return rv;
				}
			} else
				continue;
		}

		/* AHS */
		pmax += pdu->p_ahslen;
		if (pdu->p_offset < pmax) {
			len = pmax - pdu->p_offset;
			rv = sock_read_data(isock,
				    pdu->p_ahs + (pdu->p_offset - pmin), len);
			if (rv > 0)
				pdu->p_offset += rv;
			if (rv < len)
				goto done;
		}
		pmin = pmax;

		/* Header Digest */
		pmax += pdu->p_hdlen;
		if (pdu->p_offset < pmax) {
			unsigned char *buf = (unsigned char *)pdu->p_hdigest;
			len = pmax - pdu->p_offset;

			rv = sock_read_data(isock,
				    buf + (pdu->p_offset - pmin), len);
			if (rv > 0)
				pdu->p_offset += rv;
			if (rv < len)
				goto done;
		}

	} while (pdu->p_offset < pmax);

done:
	return (rv < 0) ? rv : (pdu->p_offset - offset);
}

int os_sock_read_pdu_data_nic(iscsi_socket *isock, iscsi_pdu *pdu)
{
	unsigned int offset = pdu->p_offset;
	unsigned int pmin, pmax;
	int len, rv = 0;

	do {
		pmin = pmax = ISCSI_BHS_SIZE + pdu->p_ahslen + pdu->p_hdlen;
		/* data */
		pmax += pdu->p_datalen;
		if (pdu->p_offset < pmax) {

			if (pdu->p_flag & ISCSI_PDU_FLAG_DATA_SKIP) {
				while (pdu->p_offset < pmax) {
					len = pmax - pdu->p_offset;
					if (len > os_page_size)
						len = os_page_size;
					rv = sock_read_data(isock,
						dummy_page_addr, len);
					if (rv > 0)
						pdu->p_offset += rv;
					if (rv < len)
						goto done;
				}
			} else {
				chiscsi_sgvec *sgl = pdu->p_sglist;
				int sgmax = pdu->p_sgcnt_used;
				int i = 0;
				unsigned int rmax = pmin;
				unsigned int rmin = pmin;

				rmax += sgl->sg_length;
				while (i < sgmax) {
					if (pdu->p_offset < rmax) {
						len = rmax - pdu->p_offset;
						rv = sock_read_data(isock,
							sgl->sg_addr +
							(pdu->p_offset - rmin),
							len);
						if (rv > 0)
							pdu->p_offset += rv;
						if (rv < len)
							goto done;
					}
					if (pdu->p_offset >= rmax) {
						rmin = rmax;
						i++;
						sgl++;
						rmax += sgl->sg_length;
					}
				}
			}
		}
		pmin = pmax;
	
		/* pad + Data Digest */
		pmax += pdu->p_padlen + pdu->p_ddlen;
		if (pdu->p_offset < pmax) {
			unsigned char *buf = pdu->p_tail;
			unsigned char boffset = 4 - pdu->p_padlen;

			len = pmax - pdu->p_offset;
			rv = sock_read_data(isock,
				buf + boffset + (pdu->p_offset - pmin), len);
			if (rv > 0)
				pdu->p_offset += rv;
			if (rv < len)
				goto done;
		}
	} while (pdu->p_offset < pmax);

done:
	return (rv < 0) ? rv : (pdu->p_offset - offset);
}

/*
 *
 * pdu write
 *
 */
static inline int via_sendmsg(struct iscsi_socket *isock, unsigned char *buf,
			unsigned int blen, int more)
{
	os_socket	*osock = (os_socket *)isock->s_private;
	struct socket 	*sock = osock->sock;
        struct msghdr msg = {.msg_flags = MSG_DONTWAIT};
        struct kvec iov = {
			.iov_base = buf,
			.iov_len = blen
		};

	if (isock->s_flag & ISCSI_SOCKET_NO_TX)
		return -EPIPE;

	if (more)
		msg.msg_flags |= MSG_MORE;

        return kernel_sendmsg(sock, &msg, &iov, 1, blen);
}

static inline int send_sgl(struct iscsi_socket *isock, chiscsi_sgvec *sgl,
			unsigned int sgcnt, unsigned int offset, int more)
{
	os_socket	*osock = (os_socket *) isock->s_private;
	struct socket 	*sock = osock->sock;
	ssize_t (*sendpage)(struct socket *, struct page *, int, size_t, int);
	chiscsi_sgvec *sg = sgl;
	unsigned int sgoffset = 0;
	unsigned int sent = 0;
	int i = 0;
	int rv = 0;

	sendpage = sock->ops->sendpage ? sock->ops->sendpage : sock_no_sendpage;
	if (offset) {
		i = chiscsi_sglist_find_offset(sgl, sgcnt, offset, &sgoffset);
		if (i >= sgcnt) {
			os_log_info("%s: sgl 0x%p,%u, off %u too big.\n",
				__func__, sgl, sgcnt, offset);
			return -EINVAL;
		}
	}

	sg += i;
	for (; i < sgcnt; i++, sg++) {
		unsigned int sglen = sg->sg_length - sgoffset;

		while (sglen) {
			if (sg->sg_page) {
				int tflag = MSG_DONTWAIT;

				if (more || i < (sgcnt - 1))
					tflag |= MSG_MORE;

				if (isock->s_flag & ISCSI_SOCKET_NO_TX) {
					rv = -EPIPE;
					goto out;
				}

				rv = sendpage(sock, sg->sg_page,
					sg->sg_offset + sgoffset,
					sglen, tflag);
			} else
				rv = via_sendmsg(isock, sg->sg_addr + sgoffset,
					sglen, more || i < (sgcnt - 1));

			if (rv <= 0)
				goto out;

			sent += rv;
			sglen -= rv;
			sgoffset += rv;
		}
		sgoffset = 0;
	}

out:
	if (rv < 0 && rv != -EAGAIN)
		return rv;
	
	return sent;
}

int os_sock_pdu_tx_nic(struct iscsi_socket *isock, iscsi_pdu *pdu)
{
	unsigned int ptotal = pdu->p_totallen;
	unsigned int pmax = ISCSI_BHS_SIZE + pdu->p_hdlen;
	unsigned int pmin = 0;
	unsigned int start = pdu->p_offset;
	int rv = 0;

	/* bhs + digest */
	if (pdu->p_offset < pmax) {
		rv = via_sendmsg(isock, pdu->p_bhs + pdu->p_offset,
				pmax - pdu->p_offset, pmax < ptotal);
		if (rv <= 0)
			goto done;
		pdu->p_offset += rv;
		if (pdu->p_offset < pmax)
			goto done;
	}
	pmin = pmax;

	/* data */
	pmax += pdu->p_datalen;
	if (pdu->p_offset < pmax) {
		rv = send_sgl(isock, pdu->p_sglist, pdu->p_sgcnt_used,
				pdu->p_offset - pmin, pmax < ptotal);
		if (rv <= 0)
			goto done;
		pdu->p_offset += rv;
		if (pdu->p_offset < pmax)
			goto done;
	}
	pmin = pmax;

	/* data pad + data digest */
	pmax += pdu->p_padlen + pdu->p_ddlen;
	if (pdu->p_offset < pmax) {
		unsigned char blen = pmax - pdu->p_offset;

		rv = via_sendmsg(isock,
				pdu->p_tail + ISCSI_PDU_TAIL_BUFLEN - blen,
				blen, 0);
		if (rv <= 0)
			goto done;
		pdu->p_offset += rv;
	}

done:
	if (rv < 0 && rv != -EAGAIN)
		return rv;

	return pdu->p_offset - start;
}

int os_sock_write_pdus_nic(iscsi_socket *isock, chiscsi_queue *pduq,
			   chiscsi_queue *pdu_sentq)
{
	iscsi_pdu	*pdu, *next;
	int		rv = 0;

	for (pdu = pduq->q_head; pdu; ) {
		next = pdu->p_next;

		rv = os_sock_pdu_tx_nic(isock, pdu);
		if (rv <= 0)
			return rv;

		if (pdu->p_offset == pdu->p_totallen) {
			os_log_debug(ISCSI_DBG_PDU_TX,
				"0x%p tx pdu 0x%p, %u = 48+%u+%u+%u+%u+%u,"
				" op 0x%x, sg=%u.\n",
				isock, pdu, pdu->p_totallen, pdu->p_ahslen,
				pdu->p_hdlen, pdu->p_datalen, pdu->p_padlen,
				pdu->p_ddlen, pdu->p_opcode, pdu->p_sgcnt_used);

			iscsi_pdu_dequeue(nolock, pduq, pdu);
			if (pdu->p_saveq)
				iscsi_pdu_enqueue(nolock, pdu->p_saveq, pdu);
			else
				iscsi_pdu_enqueue(nolock, pdu_sentq, pdu);

			pdu = next;
		}
	}

	return 0;
}

static inline void skb_set_frag(struct sk_buff *skb, struct page *pg,
			 unsigned int off, unsigned sz)
{
	get_page(pg);
	skb_fill_page_desc(skb, skb_shinfo(skb)->nr_frags, pg, off, sz);
	skb->len += sz;
	skb->data_len += sz;
	skb->truesize += sz;
}

static inline int skb_set_sgl_page(struct sk_buff *skb,
			 struct chiscsi_sgvec *sgl, unsigned int sgcnt)
{
	unsigned int len = 0;
	int i;

	for (i = 0; i < sgcnt; i++, sgl++) {
		get_page(sgl->sg_page);
		skb_fill_page_desc(skb, skb_shinfo(skb)->nr_frags, sgl->sg_page,
				sgl->sg_offset, sgl->sg_length);
		len += sgl->sg_length;
	}
	skb->data_len = len;
	skb->len += len;
	skb->truesize += len;

	return len;
}

static inline void free_sgl_and_pages(chiscsi_sgvec *sgl, unsigned int sgcnt)
{
	int i;
	chiscsi_sgvec *sg = sgl;

	for (i = 0; i < sgcnt; i++, sg++) {
		if (!sg->sg_page)
			break;
		os_free_one_page(sg->sg_page);
	}
	os_free(sgl);
}

static int pdu_sgl_copy_to_pages(iscsi_pdu *pdu, chiscsi_sgvec **sgl_pp)
{
	unsigned int len = pdu->p_datalen + pdu->p_padlen;
	unsigned int nr_pages = (len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	chiscsi_sgvec *sg;
	int i;
	int rv;

	*sgl_pp = sg = os_alloc(sizeof(chiscsi_sgvec) * nr_pages, 1, 1);
	if (!sg)
		return -ISCSI_ENOMEM;

	for (i = 0; i < nr_pages; i++, sg++) {
		sg->sg_page = os_alloc_one_page(1, &sg->sg_addr);
		if (!sg->sg_page) {
			free_sgl_and_pages(*sgl_pp, nr_pages);
			*sgl_pp = NULL;
			return 0;
		}
		sg->sg_offset = 0;
		sg->sg_length = PAGE_SIZE;
		sg->sg_next = sg + 1;
	}

	/* adjust last sg size */
	sg = (*sgl_pp) + nr_pages - 1;
	i = (nr_pages << PAGE_SHIFT) - len;
	if (i)
		sg->sg_length -= i;

	rv = chiscsi_sglist_copy_sgdata(0, pdu->p_sglist, pdu->p_sgcnt_used,
				*sgl_pp, nr_pages);
	if (rv != pdu->p_datalen)
		os_log_warn("%s: copy %u != %u.\n",
			 __func__, pdu->p_datalen, rv); 

	/* zero-out the padding */
	if (pdu->p_padlen) {
		memset(sg->sg_addr + sg->sg_length - pdu->p_padlen, 0,
			pdu->p_padlen);
		pdu->p_datalen += pdu->p_padlen;
		pdu->p_padlen = 0;
	}

	return nr_pages;
}

static inline int chk_payload_copy(int *recopy, iscsi_pdu *pdu,
			int ulp, unsigned int copymax,
			offload_device *odev)
{
	chiscsi_sgvec *sgl = pdu->p_sglist;
	int frag = pdu->p_sgcnt_used;

	*recopy = 0;

	if (pdu->p_padlen || (!ulp && pdu->p_ddlen))
		frag++;

	/* cannot all in to the skb frags */
	if (frag > MAX_SKB_FRAGS) {
		*recopy = 1;
		return 0;
	}

	/* all sg either contain the page or not */
	if (sgl->sg_page)
		return 0;

	/* CHISCSI_SG_SBUF_DMABLE applies to all sg entries */

	/* bus addr, but LLD does not support it */
	if ((sgl->sg_flag & CHISCSI_SG_SBUF_DMABLE)) {
		if (pdu->p_datalen < 512)
			return 1;
		if (!(odev->d_flag & ODEV_FLAG_TX_ZCOPY_DMA_ADDR) ||
		    (iscsi_test_mode_on(iscsi_test_mode,
					ISCSI_TST_BIT_NOZCOPY_DMA))) {
			if (pdu->p_totallen > copymax) {
				*recopy = 1;
				return 0;
			} else
				return 1;
		}
	} else { /* single linear buffer */
		if (pdu->p_totallen > copymax) {
			*recopy = 1;
			return 0;
		} else
			return 1;
	}
	return 0;
}
	
struct sk_buff *os_sock_pdu_tx_skb(iscsi_socket *isock, offload_device *odev,
			iscsi_pdu *pdu, int ulp)
{
	chiscsi_sgvec *sgl = pdu->p_sglist;
	chiscsi_sgvec *pg_sgl =  NULL;
	struct sk_buff *skb;
	unsigned char *dst;
	unsigned int sgcnt = pdu->p_sgcnt_used;
	unsigned int skb_max;
	unsigned int copymax;
	unsigned int copylen = ISCSI_BHS_SIZE;
	unsigned int total = pdu->p_totallen;
	char ulp_alloc_digest = odev->d_flag & ODEV_FLAG_ULP_TX_ALLOC_DIGEST;
	char payload_copy = 0;
	int len;
        int rv;
	unsigned int pi_hdr_len = 0, pi_on_wire = 0;
	unsigned int iso_hdr_len = 0, iso_extra_on_wire = 0;
	unsigned transport_offset = 0;

	if (pdu->pi_info.prot_op == ISCSI_PI_OP_SCSI_PROT_WRITE_PASS)
                pi_on_wire = pdu->pi_info.pi_len;

	skb_max = SKB_MAX_HEAD(odev->d_tx_hdrlen);
        copymax = min(isock->s_mss, skb_max);

	os_log_debug(ISCSI_DBG_TRANSPORT_MEM,
		"isock 0x%p, ulp %u, 0x%p, %u=48+%u+%u+%u+%u+%u, sg=%u/%u, %u/%u.\n",
		isock, ulp, pdu, pdu->p_totallen, pdu->p_ahslen,
		pdu->p_hdlen, pdu->p_datalen, pdu->p_padlen,
		pdu->p_ddlen, pdu->p_sgcnt_used, MAX_SKB_FRAGS,
		copymax, skb_max);

	/* one pdus per skb: pdu length < mss */
	if (ulp) {
		if (ulp_alloc_digest)
			copylen += pdu->p_hdlen + pdu->p_ddlen;
		else
			pdu->p_totallen -= pdu->p_hdlen + pdu->p_ddlen;
	} else
		copylen += pdu->p_hdlen;

	/* copy payload ? */
	if (pdu->p_datalen) {
		int copy_to_pages = 0;

		if (sgl->sg_flag & CHISCSI_SG_SBUF_DMABLE) {
			if (!odev->skb_set_premapped_sgl) {
				struct net_device *ndev = odev->d_ndev;
				os_log_error("%s: %s NO premap handler.\n",
					 __func__, ndev->name);
				return NULL;
			}
		} else {

			payload_copy = chk_payload_copy(&copy_to_pages,
					pdu, ulp, copymax, odev);

			os_log_debug(ISCSI_DBG_TRANSPORT_MEM,
				"%s: pdu 0x%p %u/%u, copy %d,%d sg %u, "
				"pg 0x%p, f 0x%x.\n",
				__func__, pdu, pdu->p_datalen, pdu->p_totallen,
				payload_copy, copy_to_pages, pdu->p_sgcnt_used,
				sgl->sg_page, sgl->sg_flag);

			if (copy_to_pages) {
				/* cannot fit in skb, copy to pages first */
				sgcnt = pdu_sgl_copy_to_pages(pdu, &pg_sgl);
				if (!sgcnt)
					return NULL;
				sgl = pg_sgl;
			} else if (payload_copy) 
				copylen = pdu->p_totallen;
		}
	}

	/* need to send pi header to fw */
	if (pdu->pi_info.prot_op)
		pi_hdr_len = odev->d_pi_hdrlen;

	/* ISO: Add iso wr hdr len */
	if (pdu->p_flag & ISCSI_PDU_FLAG_TX_ISO)
		iso_hdr_len = odev->d_iso_hdrlen;

	skb = alloc_skb(copylen + pi_hdr_len + iso_hdr_len +
				odev->d_tx_hdrlen, GFP_KERNEL);
	if (!skb) {
		os_log_warn("%s: skb nomeme, %u+%u.\n",
			 __func__, copylen, odev->d_tx_hdrlen);
		if (pg_sgl)
			free_sgl_and_pages(pg_sgl, sgcnt);
		return NULL;
	}

	skb_reserve(skb, odev->d_tx_hdrlen);
	if (ulp) {
		odev->sk_tx_skb_setmode(skb, isock->s_mode,
                                        pdu->p_hdlen, pdu->p_ddlen);

		odev->sk_tx_skb_setforce(skb, odev->d_version, odev->d_force);

		/* set pi bit in ulpsubmode. This flag needed between
 		 * host<-->fw only. */
		odev->sk_tx_skb_setmode_pi(skb, isock->s_mode, pdu->pi_info.prot_op);

		/* ISO: enable iso bit in ulpsubmode. This flag needed
 		  * between host <--> fw only */
		odev->sk_tx_skb_setmode_iso(skb, isock->s_mode,
			(pdu->p_flag & ISCSI_PDU_FLAG_TX_ISO));

		/* Copy pi hdr */
		if (pdu->pi_info.prot_op)
			transport_offset = odev->sk_tx_make_pi_hdr(skb, pdu);

		/* ISO: Copy iso hdr */
		if (pdu->p_flag & ISCSI_PDU_FLAG_TX_ISO) {
			iso_extra_on_wire = pdu->iso_info.iso_extra;
			transport_offset += odev->sk_tx_make_iso_cpl(skb, pdu);
		}

		/* zero out digest len, so it won't be copied/added */
		if (!ulp_alloc_digest)
			pdu->p_hdlen = pdu->p_ddlen = 0;
	}
	skb_set_transport_header(skb, transport_offset);

	/* copy BHS */
	dst = skb_put(skb, copylen);
	if (ulp)
		len = ISCSI_BHS_SIZE;
	else
		len = ISCSI_BHS_SIZE + pdu->p_hdlen;

	memcpy(dst, pdu->p_head, len);
	dst += len;
	copylen -= len;

	if (ulp && ulp_alloc_digest) {
		len = pdu->p_hdlen + pdu->p_ddlen;
		dst += len;
		copylen -= len;
	}

	/* payload */
	if (payload_copy) {
		chiscsi_sgvec *sg = sgl;
		int i;

		for (i = 0; i < sgcnt; i++, sg++) {
			memcpy(dst, sg->sg_addr, sg->sg_length);
			dst += sg->sg_length;
			copylen -= sg->sg_length;
		}

		if (pdu->p_padlen) {
			memset(dst, 0, pdu->p_padlen);
			dst += pdu->p_padlen;
			copylen -= pdu->p_padlen;
		}

		if (!ulp && pdu->p_ddlen) {
			memcpy(dst, pdu->p_ddigest,
				ISCSI_PDU_DIGEST_SIZE);
			dst += pdu->p_ddlen;
			copylen -= pdu->p_ddlen;
		}

	} else if (pdu->p_datalen) {
		/* zero copy */
		if (sgl->sg_flag & CHISCSI_SG_SBUF_DMABLE) {
			odev->skb_set_premapped_sgl(skb, sgl, sgcnt);
			if (pdu->p_padlen)
				os_log_error("%s: %u=48+%u+%u+%u+%u+%u, DMA.\n",
					__func__, pdu->p_totallen,
					pdu->p_ahslen, pdu->p_hdlen,
					pdu->p_datalen, pdu->p_padlen,
					 pdu->p_ddlen);
		} else if (sgl->sg_page) {
			rv = skb_set_sgl_page(skb, sgl, sgcnt);

			if (pdu->p_padlen)
				skb_set_frag(skb, rsvd_pages[0],0, pdu->p_padlen);
		} else {
			os_log_error("%s: %u=48+%u+%u+%u+%u,sg %u, bad zcp.\n",
				__func__, pdu->p_totallen, pdu->p_hdlen,
				pdu->p_datalen, pdu->p_padlen, pdu->p_ddlen,
				pdu->p_sgcnt_used);
			goto err_out;
		}
	}

	if (copylen) {
		os_log_error("%s: %u=48+%u+%u+%u+%u+%u, %u, left %u,%u/%u.\n",
			__func__, pdu->p_totallen, pdu->p_ahslen, pdu->p_hdlen,
			pdu->p_datalen, pdu->p_padlen, pdu->p_ddlen,
			pdu->p_sgcnt_used, copylen, copymax, skb_max);
		goto err_out;
	}

	if (pg_sgl)
		free_sgl_and_pages(pg_sgl, sgcnt);

	isock->s_sndnxt += total + pi_on_wire + iso_extra_on_wire;
	return skb;

err_out:
	__kfree_skb(skb);
	return NULL;
}

EXPORT_SYMBOL(chiscsi_sglist_find_offset);
EXPORT_SYMBOL(iscsi_pdu_parse_header);
EXPORT_SYMBOL(os_sock_pdu_tx_skb);
