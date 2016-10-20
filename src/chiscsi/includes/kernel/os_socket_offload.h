static void odev_get(struct offload_device *odev)
{
	try_module_get(THIS_MODULE);
}

static void odev_put(struct offload_device *odev)
{
	module_put(THIS_MODULE);
}

static void os_sock_ddp_off(struct sock *sk)
{
	sock_set_flag(sk, SOCK_NO_DDP);
}

static int isock_get_ttid(iscsi_socket *isock, void **tdev_pp)
{
	struct sock *sk = isock_2_sk(isock);
	struct net_device *root_dev;
        struct net_device *edev = NULL;
	struct toedev *tdev = NULL;
	struct dst_entry *dst;
#ifdef OFFLOAD_GET_PHYS_EGRESS_PARAM2
        struct neighbour *neigh;
        struct toe_hash_params hash_params;
#endif

	*tdev_pp = NULL;
	if (!sock_flag(sk, SOCK_OFFLOADED)) {
		os_log_info("%s: isock 0x%p offload flag NOT set.\n",
				__func__, isock);
		return 0;
	}

 	dst = __sk_dst_get(sk);
	root_dev = dst->dev;

#ifdef OFFLOAD_GET_PHYS_EGRESS_PARAM2
	if (sk->sk_family == AF_INET) {
		neigh = t4_dst_neigh_lookup(dst, &inet_sk(sk)->inet_daddr);
		if (neigh) {
			init_toe_hash_params(&hash_params, root_dev, neigh,
					inet_sk(sk)->inet_saddr,
					inet_sk(sk)->inet_daddr,
					inet_sk(sk)->inet_sport,
					inet_sk(sk)->inet_dport,
					NULL, NULL, false, IPPROTO_TCP);
			edev = offload_get_phys_egress(&hash_params, TOE_OPEN);
			t4_dst_neigh_release(neigh);
		}
	} else {
#ifdef CHISCSI_IPV6_SUPPORT
		neigh = t4_dst_neigh_lookup(dst, &inet6_sk_daddr(sk));
		if (neigh) {
			init_toe_hash_params(&hash_params, root_dev, neigh,
					0, 0, inet_sk(sk)->inet_sport,
					inet_sk(sk)->inet_dport,
					&inet6_sk_saddr(sk).s6_addr32[0],
					&inet6_sk_daddr(sk).s6_addr32[0],
					true, IPPROTO_TCP);
			edev = offload_get_phys_egress(&hash_params, TOE_OPEN);
			t4_dst_neigh_release(neigh);
		}
#else
		os_log_error("%s ipv6 not supported; isock 0x%p \n",
							__func__, isock);
		return 0;
#endif
	}
#else
	edev = offload_get_phys_egress(root_dev, sk, TOE_OPEN);
#endif

	if (!edev) {
		os_log_info("%s: isock 0x%p edev NULL.\n", __func__, isock);
		return 0;
	}

	if (edev && netdev_is_offload(edev))
                tdev = TOEDEV(edev);

	if (!tdev) {
		os_log_info("%s: isock 0x%p tdev NULL.\n", __func__, isock);
		return 0;
	}
	os_log_info("%s: isock 0x%p, sk 0x%p, tdev 0x%p, ttid %u.\n",
			__func__, isock, sk, tdev, tdev->ttid);

	*tdev_pp = tdev;
	return tdev->ttid;
}

static iscsi_socket *sk_get_isock(struct sock *sk)
{
	return (iscsi_socket *)sk->sk_user_data;
}

static offload_device *isock_get_odev(iscsi_socket *isock)
{
	return isock ? isock->s_odev : NULL;
}


#ifdef CXGB_SGE_SKB_H
#include <sge_skb.h>
#endif

#ifndef DEFINED_SKB_FRAG_PAGE
static inline struct page *skb_frag_page(const skb_frag_t *frag)
{
	return frag->page;
}
#endif


/*
 * Offload mode: pdu read
 */
static int osock_read_to_buffer(struct os_socket *osock, char *dst,
				unsigned int len)
{
	struct rx_cb *rcb = &osock->rcb;
	struct sk_buff *skb = rcb->skb;
	unsigned int offset = rcb->offset;
	unsigned int headlen;
	unsigned int read;

	if (!skb)
		return 0;
 	headlen = skb_headlen(skb);

	if (offset >= skb->len)
		return 0;

	/* data in header */
	if (headlen > offset) {
		read = min_t(unsigned int, len, (headlen - offset));

		if (dst) {
			memcpy(dst, skb->data + offset, read);
			dst += read;
		} 

		offset += read;
		len -= read;
		if (!len)
			goto done;
	}

	/* read from fragment */
	while (rcb->frag_idx < skb_shinfo(skb)->nr_frags) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[rcb->frag_idx];

		read = min_t(unsigned int, len,
			     (frag->size - rcb->frag_offset));

		if (dst) {
			struct page *pg = skb_frag_page(frag);
			unsigned char *vaddr = kmap(pg);

			memcpy(dst,
				vaddr + frag->page_offset + rcb->frag_offset,
				read);
			kunmap(pg);
			dst += read;
		}

		rcb->frag_offset += read;
		if (rcb->frag_offset == frag->size) {
			rcb->frag_idx++;
			rcb->frag_offset = 0;
		}

		offset += read;
		len -= read;
		if (!len)
			goto done;
	}

done:
	read = offset - rcb->offset;
	rcb->offset = offset;
	if (rcb->offset == skb->len)
		rcb->rx_skb_done(osock);
		
	return read;
}

/* avail_len: number of bytes available in source for copy.
 * This function consumes all the avail_len bytes.
 * returns number of bytes copied to dst.*/

static int osock_copy_data_no_pi(unsigned char *dst, unsigned char *src,
			unsigned int avail_len,
			struct rx_cb *rcb)
{
	unsigned int copied = 0, consumed = 0;
	unsigned int copy;

	while (avail_len) {
		if (!rcb->pictx.remaining_byte_in_blk) {
			/* time to change state */
			rcb->pictx.copy_state = ~rcb->pictx.copy_state;
			rcb->pictx.remaining_byte_in_blk =
				(rcb->pictx.copy_state == COPY_STATE_DATA)?\
						    rcb->pictx.sector_size:8;
		}
		copy = min(avail_len, rcb->pictx.remaining_byte_in_blk);
		/* copy only data and skip pi */
		if (rcb->pictx.copy_state == COPY_STATE_DATA) {
			memcpy(dst + copied, src + consumed, copy);
			copied += copy;
		}
		rcb->pictx.remaining_byte_in_blk -= copy;
		avail_len -= copy;
		consumed += copy;
	}
	return copied;
}

static int osock_read_to_buffer_no_pi(struct os_socket *osock, char *dst,
				unsigned int len)
{
	struct rx_cb *rcb = &osock->rcb;
	struct sk_buff *skb = rcb->skb;
	unsigned int offset = rcb->offset;
	unsigned int headlen;
	unsigned int read;
	unsigned int copied = 0;

	if (!skb)
		return 0;
 	headlen = skb_headlen(skb);

	if (offset >= skb->len)
		return 0;

	/* data in header */
	if  (headlen > offset) {
		read = min_t(unsigned int, len, (headlen - offset));

		if (dst) {
			copied = osock_copy_data_no_pi(dst, skb->data + offset,
					read, rcb);
			dst += copied;
		} else
			copied =  read;

		offset += read;
		len -= copied;

		if (!len)
			goto done;
	}
read_again:
	/* read from fragment */
	while (rcb->frag_idx < skb_shinfo(skb)->nr_frags) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[rcb->frag_idx];

		read = min_t(unsigned int, len,
			     (frag->size - rcb->frag_offset));

		if (dst) {
			struct page *pg = skb_frag_page(frag);
			unsigned char *vaddr = kmap(pg);

			copied = osock_copy_data_no_pi(dst,
				vaddr + frag->page_offset + rcb->frag_offset,
				read, rcb);
			kunmap(pg);
			dst += copied;
		} else
			copied = read;

		rcb->frag_offset += read;
		if (rcb->frag_offset == frag->size) {
			rcb->frag_idx++;
			rcb->frag_offset = 0;
		}

		offset += read;
		len -= copied;

		if (!len)
			goto done;
	}

	if (len && offset < skb->len)
		goto read_again;

done:
	read = offset - rcb->offset;
	rcb->offset = offset;
#if 0
	os_log_info("%s: offset %u, rcb->offset %u, read %u\n",
		__func__, offset, rcb->offset, read);
#endif
	if (rcb->offset == skb->len)
		rcb->rx_skb_done(osock);

	return read;
}

/*
 * TOE mode: pdu read
 */
static inline void toe_rx_skb_done(struct os_socket *osock)
{
	struct rx_cb *rcb = &osock->rcb;
	struct sock *sk = osock_2_sk(osock);
	struct offload_device *odev = osock->odev;

	if (rcb->skb) {
		if (odev) {
			lock_sock(sk);
			odev->sk_rx_tcp_consumed(osock->isock, rcb->skb->len);
			release_sock(sk);
		}
		kfree_skb(rcb->skb);
		iscsi_stats_dec(ISCSI_STAT_SBUF_RX);
		memset(rcb, 0, sizeof(*rcb));
	}
}

static inline void toe_rx_skb_get_next(struct os_socket *osock)
{
	struct rx_cb *rcb = &osock->rcb;
	struct sock *sk = osock_2_sk(osock);
	struct sk_buff *skb;

	lock_sock(sk);
	skb = skb_peek(&sk->sk_receive_queue);
	if (skb)
		__skb_unlink(skb, &sk->sk_receive_queue);
	release_sock(sk);

	if (skb) {
		iscsi_stats_inc(ISCSI_STAT_SBUF_RX);
		rcb->skb = skb;
		rcb->rx_skb_done = toe_rx_skb_done;
	}
}

int os_sock_read_pdu_header_toe(iscsi_socket *isock, iscsi_pdu *pdu)
{
	struct os_socket *osock = isock_2_osock(isock);
	struct rx_cb *rcb = &osock->rcb;
	unsigned int poffset = pdu->p_offset;
	unsigned int pmin, pmax;
	unsigned int read = 0;
	unsigned int rlen;
	int	rv = 0;

	do {
		struct sk_buff *skb;

		if (!rcb->skb)
			toe_rx_skb_get_next(osock);
		if (!rcb->skb)
			break;
		skb = rcb->skb;

		pmin = pmax = ISCSI_BHS_SIZE;

		/* BHS */
		if (poffset < ISCSI_BHS_SIZE) {
			rlen = ISCSI_BHS_SIZE - poffset;
			rv = osock_read_to_buffer(osock,
					pdu->p_head + poffset, rlen);
			if (rv < 0) {
				os_log_info("toe read BHS failed %d, %u+%u.\n",
					rv, poffset, rlen);
				break;
			}
			read += rv;
			poffset += rv;

			if (poffset == ISCSI_BHS_SIZE) {
				pdu->p_offset = poffset;
				rv = iscsi_pdu_parse_header(pdu);
				if (rv < 0) {
					os_log_info("toe parse BHS failed %d.\n", rv);
					break;
				}
			}
			if (rv < rlen)
				continue;
			if (poffset == pdu->p_totallen)
				break;
		}
		
		/* AHS */
		pmax += pdu->p_ahslen;
		if (poffset < pmax) {
			rlen = pmax - poffset;
			rv = osock_read_to_buffer(osock,
					pdu->p_ahs + (poffset - pmin), rlen);
			if (rv < 0) {
				os_log_info("toe read AHS failed %d, %u+%u.\n",
					rv, poffset, rlen);
				break;
			}
			read += rv;
			poffset += rv;
			if (rv < rlen)
				continue;
			if (poffset == pmax)
				break;
		}
		pmin = 	pmax;
	
		/* header digest */
		pmax += pdu->p_hdlen;
		if (poffset < pmax) {
			rlen = pmax - poffset;
			rv = osock_read_to_buffer(osock,
				((char *)pdu->p_hdigest) + (poffset - pmin),
				rlen);
			if (rv < 0) {
				os_log_info("toe read hcrc failed %d, %u+%u.\n",
					rv, poffset, rlen);
				break;
			}
			read += rv;
			poffset += rv;
			if (rv < rlen)
				continue;
			if (poffset == pdu->p_totallen)
				break;
		}
		pmin = pmax;
	} while (poffset < pmax);

	pdu->p_offset = poffset;
	if (rv < 0)
		return rv;
	return read;
}

static int os_sock_read_pdu_data_toe(iscsi_socket *isock, iscsi_pdu *pdu)
{
	struct os_socket *osock = isock_2_osock(isock);
	struct rx_cb *rcb = &osock->rcb;
	unsigned int poffset = pdu->p_offset;
	unsigned int pmin, pmax;
	unsigned int read = 0;
	unsigned int rlen;
	int	rv = 0;

	do {
		struct sk_buff *skb;

		if (!rcb->skb)
			toe_rx_skb_get_next(osock);
		if (!rcb->skb)
			break;
		skb = rcb->skb;

		pmin = pmax = ISCSI_BHS_SIZE + pdu->p_ahslen + pdu->p_hdlen;

		/* Data */
		pmax += pdu->p_datalen;
		if (poffset < pmax) {
			rlen = pmax - poffset;
			if (pdu->p_flag & ISCSI_PDU_FLAG_DATA_SKIP) {
				rv = osock_read_to_buffer(osock, NULL, rlen);
				if (rv < 0) {
					os_log_info("toe skip data failed %d, %u+%u.\n",
						rv, poffset, rlen);
					break;
				}
				read += rv;
				poffset += rv;
				if (rv < rlen)
					continue;
			} else {
				/* copy into buffer */
				chiscsi_sgvec *sgl = pdu->p_sglist;
				unsigned int sgcnt = pdu->p_sgcnt_used;
				unsigned int dmin, dmax = pmin;
				int i;

				for (i = 0; i < sgcnt; i++, sgl++) {
					dmin = dmax;
					dmax += sgl->sg_length;
					if (poffset >= dmax) 
						continue;
					rlen = dmax - poffset;
					rv = osock_read_to_buffer(osock, 
						sgl->sg_addr + (poffset - dmin),
						rlen);
					if (rv < 0) {
						os_log_info("toe data failed %d, %u+%u.\n",
							rv, poffset, rlen);
						goto done;
					}
					read += rv;
					poffset += rv;
					if (rv < rlen)
						break;
				}

				if (poffset < pmax)
					continue;
			}
		}
		pmin = pmax; 

		/* data pad + data digest */
		pmax += pdu->p_padlen + pdu->p_ddlen;
		if (poffset < pmax) {
			rlen = pmax - poffset;
			rv = osock_read_to_buffer(osock,
				pdu->p_tail + (4 - pdu->p_padlen) +
					(poffset - pmin),
				rlen);
			if (rv < 0) {
				os_log_info("toe pad + dcrc failed %d, %u+%u.\n",
					rv, poffset, rlen);
				break;
			}
			read += rv;
			poffset += rv;
			if (rv < rlen)
				continue;
		}
	} while (poffset < pdu->p_totallen);

done:
	pdu->p_offset = poffset;
	if (rv < 0)
		return rv;
	return read;
}

/*
 * ULP mode: pdu read
 */
static inline void ulp_rx_skb_done(struct os_socket *osock)
{
	struct rx_cb *rcb = &osock->rcb;

	if (rcb->skb) {
		iscsi_stats_dec(ISCSI_STAT_SBUF_RX);
		kfree_skb(rcb->skb);
		memset(rcb, 0, sizeof(*rcb));
	}
}

static int ulp_rx_skb_get_next(struct os_socket *osock, int header)
{
	struct rx_cb *rcb = &osock->rcb;
	struct sock *sk = osock_2_sk(osock);
	struct offload_device *odev = osock->odev;
	struct sk_buff *skb;
	int rv = 0;

	lock_sock(sk);
	skb = skb_peek(&sk->sk_receive_queue);
	if (skb) {
		if (!odev->sk_rx_ulp_skb(skb)) {
			os_log_info("sk 0x%p, skb 0x%p, "
				"skb->len %u, skb->data_len %u, not in ULP.\n",
				sk, skb, skb->len, skb->data_len);
			skb = NULL;
			rv = -EIO;
			goto release;
		}
		if (header && !(odev->sk_rx_ulp_skb_ready(skb))) {
			skb = NULL;
			goto release;
		}
		__skb_unlink(skb, &sk->sk_receive_queue);
	}

release:
	release_sock(sk);
	if (rv < 0)
		return rv;

	if (skb) {
		iscsi_stats_inc(ISCSI_STAT_SBUF_RX);
		rcb->skb = skb;
		rcb->rx_skb_done = ulp_rx_skb_done;
		/* will set per pdu rcb->ulp_len later */
	}
	return 0;
}

static int os_sock_read_pdu_header_ulp(iscsi_socket *isock, iscsi_pdu *pdu)
{
	struct os_socket *osock = isock_2_osock(isock);
	struct rx_cb *rcb = &osock->rcb;
	struct offload_device *odev = osock->odev;
	int rv = 0;

	if (pdu->p_offset) {
		os_log_info("ulp read header, pdu offset %u.\n",
			pdu->p_offset);
		return -ISCSI_EINVAL;
	}

	if (!rcb->skb) {
		rv = ulp_rx_skb_get_next(osock, 1);
		if (rv < 0) {
			os_log_info("ulp header get next skb %d.\n", rv);
			return rv;
		}
		if (!rcb->skb)
			return 0;
	}

	rv = odev->sk_rx_ulp_ddpinfo(rcb->skb, pdu, (void *)rcb);
	rcb->pdu_idx++;
	if (rv < 0)
		return rv;

	if (rcb->fmode == 0 && rcb->offset) {
		os_log_info("ulp header skb 0x%p, len %u, off %u.\n",
			rcb->skb, rcb->skb->len, rcb->offset);
		ulp_rx_skb_done(osock);
		return -EIO;
	}

	rcb->ulp_len += pdu->p_totallen;

	rv = osock_read_to_buffer(osock, pdu->p_head, ISCSI_BHS_SIZE);
	if (rv < ISCSI_BHS_SIZE) {
		os_log_info("ulp read bhs %d, %u.\n", rv, rcb->skb->len);
		return -EIO;
	}

	pdu->p_offset = ISCSI_BHS_SIZE;
	rv = iscsi_pdu_parse_header(pdu);
	if (rv < 0) {
		os_log_info("ulp parse bhs %d.\n", rv);
		return rv;
	}
		
	/* AHS */
	if (pdu->p_ahslen) {
		rv = osock_read_to_buffer(osock, pdu->p_ahs, pdu->p_ahslen);
		if (rv < pdu->p_ahslen) {
			os_log_info("ulp read ahs %d, %u,%u.\n",
				rv, pdu->p_ahslen, rcb->skb->len);
			return -EIO;
		}
	}

	if (pdu->p_hdlen) {
		rv = osock_read_to_buffer(osock, (char *)pdu->p_hdigest,
					pdu->p_hdlen);
		if (rv < pdu->p_hdlen) {
			os_log_info("ulp read hcrc %d, %u,%u.\n",
				rv, pdu->p_hdlen, rcb->skb->len);
			return -EIO;
		}
	}

	pdu->p_offset += pdu->p_ahslen + pdu->p_hdlen;

#if 0
	if (pdu->p_offset == pdu->p_totallen)
		ulp_rx_skb_done(osock);
#endif

	return pdu->p_offset;
}

static int os_sock_read_pdu_data_ulp(iscsi_socket *isock, iscsi_pdu *pdu)
{
	struct os_socket *osock = isock_2_osock(isock);
	struct rx_cb *rcb = &osock->rcb;
	struct offload_device *odev = osock->odev;
	chiscsi_sgvec *sg = pdu->p_sglist;
	unsigned int sgcnt = pdu->p_sgcnt_used;
	int i;
	int rv = 0;
	int separate_pi = 0;

	if (pdu->p_datalen && pdu->p_flag & ISCSI_PDU_FLAG_DATA_DDPED) {
		goto done;
	}

	if (rcb->fmode == RXCBF_COALESCED) {
		/* coalesced */
		if (odev->d_ulp_rx_datagap) {
			rv = osock_read_to_buffer(osock, NULL,
						odev->d_ulp_rx_datagap);
			if (rv < odev->d_ulp_rx_datagap) {
				os_log_info("ulp skip cpl %d, %u.\n",
					rv, odev->d_ulp_rx_datagap);
				rv = -EIO;
				goto done;
			}
		}
		if (!rcb->skb) {
			os_log_info("ulp data skb 0x%p, len %u, off %u, "
				     "not coalesced.\n",
				rcb->skb, rcb->skb->len, rcb->offset);
			ulp_rx_skb_done(osock);
			rv = -EIO;
			goto done;
		}
	} else if (!rcb->skb) {
		rv = ulp_rx_skb_get_next(osock, 0);
		if (rv < 0 || !rcb->skb) {
			os_log_info("ulp data pdu null %d.\n", rv);
			rv = -EIO;
			goto done;
		}
	}

	if (!pdu->p_offset) {
		os_log_info("ulp pdu ERR read data! poffset %u.\n",
			pdu->p_offset);
		return -ISCSI_EINVAL;
	}

	if (pdu->p_offset >= pdu->p_totallen) {
		os_log_info("ulp pdu ERR read data! poffset %u/%u.\n",
			pdu->p_offset, pdu->p_totallen);
		return -ISCSI_EINVAL;
	}

	/* Data */
	if (pdu->p_flag & ISCSI_PDU_FLAG_DATA_SKIP) {
		rv = osock_read_to_buffer(osock, NULL, pdu->p_datalen);
		goto done;
	}

	if (pdu->p_flag & ISCSI_PDU_FLAG_PI_RCVD) {
		/* Data DDP failed but pi received means its
 		 * immediate data case and we need to remove pi before copying
 		 * the data if its DIF. In DIX case, PI is anyway generated
 		 * by HBA and already separate from data. */

		if (pdu->pi_info.prot_op == ISCSI_PI_OP_SCSI_PROT_READ_PASS) {
			separate_pi = 1;
			/* Initialize pictx */
			rcb->pictx.copy_state = COPY_STATE_DATA;

			if (pdu->pi_info.interval == ISCSI_SCSI_PI_INTERVAL_4K)
				rcb->pictx.sector_size = 4094;
			else
				rcb->pictx.sector_size = 512; /* default */

			rcb->pictx.remaining_byte_in_blk =
						rcb->pictx.sector_size;
		}
	}

	for (i = 0; i < sgcnt; i++, sg++) {
		if (!sg->sg_addr) {
			os_log_info("ulp read data, sg %d/%u, flag 0x%x, "
				"no addr.\n", i, sgcnt, sg->sg_flag);
			return -EIO;
		}
		if (separate_pi)
			rv = osock_read_to_buffer_no_pi(osock, sg->sg_addr,
						sg->sg_length);
		else
			rv = osock_read_to_buffer(osock, sg->sg_addr, sg->sg_length);
		if (rv < sg->sg_length) {
			os_log_info("ulp read data, sg %d/%u, %d < %u.\n",
                                       i, sgcnt, rv, sg->sg_length);
			return -EIO;
		}
	}

done:
	if (rcb->skb && rcb->fmode != RXCBF_LRO)
		ulp_rx_skb_done(osock);

	pdu->p_offset = pdu->p_totallen;

	if (rv < 0)
		return rv;
	return pdu->p_offset;
}

static int os_sock_read_pdu_pi_ulp(iscsi_socket *isock, iscsi_pdu *pdu)
{
	struct os_socket *osock = isock_2_osock(isock);
	struct rx_cb *rcb = &osock->rcb;
	chiscsi_sgvec *sg = pdu->p_prot_sglist;
	unsigned int sgcnt = pdu->p_pi_sgcnt_used;
	int i;
	int rv = 0;

	if (!rcb->skb) {
		rv = ulp_rx_skb_get_next(osock, 0);
		if (rv < 0 || !rcb->skb) {
			os_log_info("ulp pi pdu null %d.\n", rv);
			rv = -EIO;
			goto done;
		}
	}
	for (i = 0; i < sgcnt; i++, sg++) {
		if (!sg->sg_addr) {
			os_log_info("ulp read pi, sg %d/%u, flag 0x%x, "
				"no addr.\n", i, sgcnt, sg->sg_flag);
			return -EIO;
		}
		rv = osock_read_to_buffer(osock, sg->sg_addr, sg->sg_length);
		if (rv < sg->sg_length) {
			os_log_info("ulp read pi, sg %d/%u, %d < %u.\n",
                                       i, sgcnt, rv, sg->sg_length);
			return -EIO;
		}
	}

done:
	if (rcb->skb)
		ulp_rx_skb_done(osock);

	return rv;
}

#define skb_chain_up(skb,head,tail)	\
	do { \
		((struct sk_buff *)skb)->next = NULL; \
		if (!head) head = skb; \
		if (tail) tail->next = skb; \
		tail = skb; \
	} while(0)

#define pdu_move2sentq(pdu,pduq,sentq) \
	do { \
		iscsi_pdu_dequeue(nolock, pduq, pdu); \
		if (pdu->p_saveq) \
			iscsi_pdu_enqueue(nolock, pdu->p_saveq, pdu); \
		else \
			iscsi_pdu_enqueue(nolock, sentq, pdu); \
	} while(0)

static int sendskb_save_skb(const char *fname, os_socket *osock,
			struct sk_buff *skb, iscsi_pdu *pdu, chiscsi_queue *pduq,
			chiscsi_queue *pdu_sentq)
{
	unsigned int tx_totallen = pdu->p_totallen;

	skb_chain_up(skb, osock->skb_head, osock->skb_tail);

	if (pdu->pi_info.prot_op) {
		offload_device	*odev = osock->odev;
		/* wr pi hdr is already part of the skb at this point. */
		tx_totallen += pdu->pi_info.pi_len +
				odev->d_pi_hdrlen;
	}

	/* ISO: pdu->p_totallen doesn't includes HW generated iscsi hdr len */
	if (pdu->p_flag & ISCSI_PDU_FLAG_TX_ISO) {
		offload_device	*odev = osock->odev;
		/* iso cpl is already made part of the skb at this point */
		/* iso_extra bytes are generated by HW and not part of skb so
		   do not include them in tx_totallen; */
		os_log_debug(ISCSI_DBG_TRANSPORT_MEM,
			"%s tx_totallen %u, iso_info.iso_extra %u, "
			"d_iso_hdrlen %u\n", fname,
			tx_totallen, pdu->iso_info.iso_extra,
			odev->d_iso_hdrlen);
		tx_totallen += odev->d_iso_hdrlen;
	}

	if (skb->len != tx_totallen) {
		os_log_error("%s: pdu %u != skb %u,%u,%u, frag %u.\n",
			fname, tx_totallen, skb->len, skb->data_len,
			skb->truesize, skb_shinfo(skb)->nr_frags);
		return -EINVAL;
	}

	pdu->p_skb = skb;
	pdu->p_offset = pdu->p_totallen;
	pdu_move2sentq(pdu, pduq, pdu_sentq);
	/* if using ofldq for ppod write, then consider ppod len also. */
	osock->txq_len += tx_totallen + pdu->p_ppod_totallen;

	os_log_debug(ISCSI_DBG_TRANSPORT_MEM,
		"%s skb 0x%p, %u,%u,%u, frags %u, txq %u.\n",
		fname, skb, skb->len, skb->data_len, skb->truesize,
		skb_shinfo(skb)->nr_frags, osock->txq_len);

	return 0;
}

static int sendskb_rc_check(const char *fname, int rv, os_socket *osock,
			chiscsi_queue *pdu_sentq)
{
	iscsi_pdu *pdu;
	unsigned int tx_totallen;

	os_log_debug(ISCSI_DBG_TRANSPORT_MEM,
		"%s, push %d, rv %d.\n", fname, osock->txq_len, rv);

	if (rv < 0) {
		if (rv == -EAGAIN) return 0;
		return rv;
	}

	/* TOM should takes either none of the skbs or all of them */
	if (rv == osock->txq_len) {
		osock->skb_head = osock->skb_tail = NULL;
		osock->txq_len = 0;

		return 0;
	}

	if (!rv) {
		os_log_info("%s, sent 0 != %u.\n", fname, osock->txq_len);
		return -EINVAL;
	}

	/* partially taken */
	iscsi_pdu_qsearch_by_skb(nolock, pdu_sentq, pdu, osock->skb_head);	
	os_log_error("%s, sent %d != %u, pdu 0x%p.\n",
			fname, rv, osock->txq_len, pdu);
	while (pdu && rv) {
		tx_totallen = pdu->p_totallen + pdu->p_ppod_totallen;

		if (pdu->pi_info.prot_op) {
			offload_device	*odev = osock->odev;
			tx_totallen += pdu->pi_info.pi_len +
				odev->d_pi_hdrlen;
		}
		if (pdu->p_flag & ISCSI_PDU_FLAG_TX_ISO) {
			offload_device	*odev = osock->odev;
			tx_totallen += pdu->iso_info.iso_extra +
				odev->d_iso_hdrlen;
		}
		os_log_error("%s: part %d, skb 0x%p, pdu %u="
			"48+%u+%u+%u+%u+%u, op 0x%x, sg=%u.\n",
			fname, rv, pdu->p_skb, tx_totallen, pdu->p_ahslen,
			pdu->p_hdlen, pdu->p_datalen, pdu->p_padlen,
			pdu->p_ddlen, pdu->p_opcode, pdu->p_sgcnt_used);
		if (rv < tx_totallen)
			rv = 0;
		else
			rv -= tx_totallen;
		osock->txq_len -= tx_totallen;

		pdu->p_skb = NULL;
		pdu = pdu->p_next;
	}

	if (rv)
		os_log_error("%s, left sent %d/%u.\n",
			fname, rv, osock->txq_len, pdu);

	if (pdu)
		osock->skb_head = pdu->p_skb;
	else
		osock->skb_head = osock->skb_tail = NULL;

	return -EINVAL;
}

static int os_sock_write_pdus_sendskb_toe(iscsi_socket *isock,
			chiscsi_queue *pduq, chiscsi_queue *pdu_sentq)
{
	offload_device	*odev = isock->s_odev;
	os_socket	*osock = (os_socket *) isock->s_private;
	struct sock	*sk = osock->sock->sk;
	iscsi_pdu	*pdu;
	int rv;

	os_log_debug(ISCSI_DBG_TRANSPORT_MEM,
		"isock 0x%p, pduq 0x%p,%u, head 0x%p.\n",
		isock, pduq, pduq->q_cnt, pduq->q_head);

	while ((pdu = pduq->q_head)) {
		struct sk_buff	*skb = os_sock_pdu_tx_skb(isock, odev,
					pdu, 0);

		if (!skb)
			break;

		rv = sendskb_save_skb(__func__, osock, skb, pdu, pduq,
				pdu_sentq);
		if (rv < 0)
			return rv;
	}

	/* send skb to TOM */
	if (unlikely(!osock->skb_head))
		return 0;

	rv = odev->sk_tx_skb_push(sk, osock->skb_head,
				MSG_DONTWAIT | MSG_NOSIGNAL);

	return sendskb_rc_check(__func__, rv, osock, pdu_sentq);
}


static int os_sock_write_pdus_sendskb_ulp(iscsi_socket * isock,
			chiscsi_queue *pduq, chiscsi_queue *pdu_sentq)
{
	offload_device	*odev = isock->s_odev;
	os_socket	*osock = (os_socket *) isock->s_private;
	struct sock	*sk;
	iscsi_pdu	*pdu;
	int rv;

	if (!isock->s_odev) {
		os_log_error("%s: sock 0x%p, odev NULL.\n",
			__func__, isock);
        	return -ISCSI_ENULL;
	}

	if (!osock || !osock->sock || !osock->sock->sk) {
		os_log_error("%s: sock NULL.\n", __func__);
		return -EINVAL;	
	}
	sk = osock->sock->sk;

	/* one pdus per skb: pdu length < mss */
	while ( (pdu = pduq->q_head) ) {
		struct sk_buff	*skb = os_sock_pdu_tx_skb(isock, odev,
					pdu, 1);

		if (!skb)
			break;

		pdu->p_ppod_totallen = 0;
		/* if we have ppod skb present in pdu then add them to
		 * queue first */
		if (pdu->p_ppod_skb_list) {
			struct sk_buff *ppod_skb = pdu->p_ppod_skb_list;
			struct sk_buff *next = NULL;
			unsigned int ppod_skb_count = 0;

			while (ppod_skb) {
				pdu->p_ppod_totallen += ppod_skb->len;
				/* need ofld credit if using ofldq */
				ULP_SKB_CB(ppod_skb)->flags =
					ULPCB_FLAG_MEMWRITE | ULPCB_FLAG_COMPL;
				next = ppod_skb->next;
				skb_chain_up(ppod_skb, osock->skb_head,
					osock->skb_tail);
				ppod_skb = next;
				ppod_skb_count++;
			}
#if 0
			os_log_info("%s: ppod_skb_count %u, "
				"all ppod skb len %u\n", __func__,
				ppod_skb_count, pdu->p_ppod_totallen);
#endif
			pdu->p_ppod_skb_list = NULL;
		}
		rv = sendskb_save_skb(__func__, osock, skb, pdu, pduq,
				pdu_sentq);
		if (rv < 0)
			return rv;
	}

	/* send skb to TOM */
	if (unlikely(!osock->skb_head))
		return 0;

	rv = odev->sk_tx_skb_push(sk, osock->skb_head,
				MSG_DONTWAIT | MSG_NOSIGNAL);
		
	return sendskb_rc_check(__func__, rv, osock, pdu_sentq);
}
