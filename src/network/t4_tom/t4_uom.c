#include <net/udp.h>
#include <net/protocol.h>
#include <net/inet_common.h>
#include <net/arp.h>
#include <linux/if_vlan.h>
#include <net/neighbour.h>
#ifdef CONFIG_UDPV6_OFFLOAD
#include <net/ipv6.h>
#include <net/udplite.h>
#include <net/ip6_fib.h>
#include <net/addrconf.h>
#include <net/ip6_route.h>
#include <net/transp_v6.h>
#endif /* CONFIG_UDPV6_OFFLOAD */
#include "l2t.h"
#include "defs.h"
#include "tom.h"
#include "cpl_io_state.h"
#include "t4_msg.h"
#include "t4fw_interface.h"
#include "offload.h"

static struct proto udpoffload_prot;
static struct proto orig_udp_prot;
#ifdef CONFIG_UDPV6_OFFLOAD
static struct proto udpv6offload_prot;
static struct proto orig_udpv6_prot;
#endif /* CONFIG_UDPV6_OFFLOAD */

/**
 *      sgl_len - calculates the size of an SGL of the given capacity
 *      @n: the number of SGL entries
 *
 *      Calculates the number of flits needed for a scatter/gather list that
 *      can hold the given number of entries.
 */
static inline unsigned int sgl_len(unsigned int n)
{
	n--;
	return (3 * n) / 2 + (n & 1) + 2;
}

/**
 *      calc_tx_flits_ofld - calculate # of flits for an offload packet
 *      @skb: the packet
 *
 *      Returns the number of flits needed for the given offload packet.
 *      These packets are already fully constructed and no additional headers
 *      will be added.
 */
static inline unsigned int calc_tx_flits_ofld(const struct sk_buff *skb)
{
	unsigned int flits, cnt;


	flits = DIV_ROUND_UP(skb_transport_offset(skb), 8);   /* headers */
	cnt = skb_shinfo(skb)->nr_frags;
	return flits + sgl_len(cnt);
}

/*
 * Called for each sk_buff in a socket's receive backlog during
 * backlog processing.
 */
static int t4_backlog_rcv(struct sock *sk, struct sk_buff *skb)
{
	if (BLOG_SKB_CB(skb)->backlog_rcv != NULL &&
			skb_shinfo(skb)->gso_type == SKB_GSO_UDP)
		BLOG_SKB_CB(skb)->backlog_rcv(sk, skb);
	else {
		if (sk->sk_family == AF_INET)
			udp_prot.backlog_rcv(sk, skb);
#ifdef CONFIG_UDPV6_OFFLOAD
		else if (sk->sk_family == AF_INET6)
			udpv6_prot_p->backlog_rcv(sk, skb);
#endif /* CONFIG_UDPV6_OFFLOAD */
	}

	return 0;
}

int t4_udp_release_resources(struct sock *sk, int ipver)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	if (ipver == 4)
		sk->sk_prot = &udp_prot;
#ifdef CONFIG_UDPV6_OFFLOAD
	else
		sk->sk_prot = udpv6_prot_p;
#endif /* CONFIG_UDPV6_OFFLOAD */
	kfree(cplios);
	return 0;
}

int send_uo_flowc_wr(struct sock *sk, int compl, int state)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct tom_data *d = TOM_DATA(cplios->toedev);
	struct sk_buff *skb;
	struct fw_flowc_wr *flowc;
	int nparams, flowclen16, flowclen;

	/*
	 * Determine the number of parameters we're going to send and the
	 * consequent size of the Work Request.
	 */
	nparams = 6;
        flowclen = offsetof(struct fw_flowc_wr, mnemval[nparams]);
	flowclen16 = DIV_ROUND_UP(flowclen, 16);
	flowclen = flowclen16 * 16;

	/*
	 * Allocate the skb for the FlowC Work Request and clear it.
	 */
	skb = alloc_ctrl_skb(cplios->txdata_skb_cache, flowclen);
	if (!skb)
		return -ENOMEM;

	flowc = (struct fw_flowc_wr *)__skb_put(skb, flowclen);
	memset(flowc, 0, flowclen);

	flowc->op_to_nparams =
		htonl(V_FW_WR_OP(FW_FLOWC_WR) | V_FW_WR_COMPL(compl) |
		      V_FW_FLOWC_WR_NPARAMS(nparams));
	flowc->flowid_len16 =
		htonl(V_FW_WR_LEN16(flowclen16) |
		      V_FW_WR_FLOWID(cplios->tid));

	flowc->mnemval[0].mnemonic = FW_FLOWC_MNEM_PFNVFN;
	flowc->mnemval[0].val = htonl(d->pfvf);
	flowc->mnemval[1].mnemonic = FW_FLOWC_MNEM_CH;
	flowc->mnemval[1].val = htonl(cplios->tx_c_chan);
	flowc->mnemval[2].mnemonic = FW_FLOWC_MNEM_PORT;
	flowc->mnemval[2].val = htonl(cplios->tx_c_chan);
	flowc->mnemval[3].mnemonic = FW_FLOWC_MNEM_IQID;
	flowc->mnemval[3].val = htonl(cplios->rss_qid);
	flowc->mnemval[4].mnemonic = FW_FLOWC_MNEM_EOSTATE;
	flowc->mnemval[4].val = htonl(state);
	flowc->mnemval[5].mnemonic = FW_FLOWC_MNEM_SCHEDCLASS;
	flowc->mnemval[5].val = htonl(cplios->sched_cls);

	set_queue(skb, (cplios->txq_idx << 1) | CPL_PRIORITY_DATA, sk);
	skb->csum = flowclen16;
	cplios->wr_credits -= flowclen16;
	cplios->wr_unacked += flowclen16;
	enqueue_wr_shared(sk, skb);
	cxgb4_ofld_send(cplios->egress_dev, skb);

	return 0;
}

int t4_udpv4_offload_init(struct toedev *tdev, struct sock *sk,
			struct net_device *egress_dev)
{
	struct tom_data *d = TOM_DATA(tdev);
	struct cxgb4_lld_info *lldi = d->lldi;
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	int uotid, err;

	/*
	 * Now that we know the device we're dealing with, we can check the
	 * Scheduling Class parameter which may have been selected with
	 * setsockopt().
	 */
	if (cplios->sched_cls != SCHED_CLS_NONE &&
	    cplios->sched_cls >= lldi->nsched_cls)
		return -ERANGE;

	/* alloc udp offload tid */
	uotid = cxgb4_alloc_uotid(d->tids, sk);

	if (uotid < 0) {
		t4_udp_release_resources(sk, 4);
		return -ENOSPC;
	}

	sk->sk_backlog_rcv = t4_backlog_rcv;

	cplios->tid = uotid;
	cplios->egress_dev = egress_dev;
	cplios->toedev = tdev;
	cplios->tx_c_chan = cxgb4_port_chan(egress_dev);
	cplios->port_id = ((struct port_info *)netdev_priv(egress_dev))->port_id;
	cplios->txq_idx = cplios->port_id*d->lldi->ntxq/d->lldi->nchan;
	cplios->rss_qid = d->lldi->rxq_ids[cplios->port_id*d->lldi->nrxq/d->lldi->nchan];
	cplios->wr_max_credits = cplios->wr_credits = TOM_TUNABLE(tdev, max_wr_credits);
	cplios->wr_unacked = 0;
	skb_queue_head_init(&cplios->tx_queue);

	err = send_uo_flowc_wr(sk, 1, FW_FLOWC_MNEM_EOSTATE_ESTABLISHED);
	if (err < 0)
		return err;

	cplios_set_flag(sk, CPLIOS_TX_DATA_SENT);

	return 0;
}

#ifdef CONFIG_UDPV6_OFFLOAD
int t4_udpv6_offload_init(struct toedev *tdev, struct sock *sk,
			  struct net_device *egress_dev)
{
	struct tom_data *d = TOM_DATA(tdev);
	struct cxgb4_lld_info *lldi = d->lldi;
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	int uotid, err;

	/*
	 * Now that we know the device we're dealing with, we can check the
	 * Scheduling Class parameter which may have been selected with
	 * setsockopt().
	 */
	if (cplios->sched_cls != SCHED_CLS_NONE &&
	    cplios->sched_cls >= lldi->nsched_cls)
		return -ERANGE;

	/* alloc udp offload tid */
	uotid = cxgb4_alloc_uotid(d->tids, sk);

	if (uotid < 0) {
		t4_udp_release_resources(sk, 6);
		return -ENOSPC;
	}

	sk->sk_backlog_rcv = t4_backlog_rcv;

	cplios->tid = uotid;
	cplios->egress_dev = egress_dev;
	cplios->toedev = tdev;
	cplios->tx_c_chan = cxgb4_port_chan(egress_dev);
	cplios->port_id =
			((struct port_info *)netdev_priv(egress_dev))->port_id;
	cplios->txq_idx = cplios->port_id*d->lldi->ntxq/d->lldi->nchan;
	cplios->rss_qid =
	d->lldi->rxq_ids[cplios->port_id*d->lldi->nrxq / d->lldi->nchan];
	cplios->wr_max_credits = cplios->wr_credits =
				 TOM_TUNABLE(tdev, max_wr_credits);
	cplios->wr_unacked = 0;
	skb_queue_head_init(&cplios->tx_queue);

	err = send_uo_flowc_wr(sk, 1, FW_FLOWC_MNEM_EOSTATE_ESTABLISHED);
	if (err < 0)
		return err;

	cplios_set_flag(sk, CPLIOS_TX_DATA_SENT);

	return 0;
}
#endif /* CONFIG_UDPV6_OFFLOAD */

/* TODO - Similar to the one in sge.c */
static u64 hwcsum(const struct sk_buff *skb)
{
	int csum_type;
	const struct iphdr *iph = ip_hdr(skb);

	if (iph->version == 4) {
		if (iph->protocol == IPPROTO_TCP)
			csum_type = TX_CSUM_TCPIP;
		else if (iph->protocol == IPPROTO_UDP)
			csum_type = TX_CSUM_UDPIP;
		else {
nocsum:			/*
			 * unknown protocol, disable HW csum
			 * and hope a bad packet is detected
			 */
			return F_TXPKT_L4CSUM_DIS;
		}
	} else {
		/*
		 * this doesn't work with extension headers
		 */
		const struct ipv6hdr *ip6h = (const struct ipv6hdr *)iph;

		if (ip6h->nexthdr == IPPROTO_TCP)
			csum_type = TX_CSUM_TCPIP6;
		else if (ip6h->nexthdr == IPPROTO_UDP)
			csum_type = TX_CSUM_UDPIP6;
		else
			goto nocsum;
	}

	if (likely(csum_type >= TX_CSUM_TCPIP))
		return V_TXPKT_CSUM_TYPE(csum_type) |
			V_TXPKT_IPHDR_LEN(skb_network_header_len(skb)) |
			V_TXPKT_ETHHDR_LEN(0);
	else {
		int start = skb_transport_offset(skb);

		return V_TXPKT_CSUM_TYPE(csum_type) |
			V_TXPKT_CSUM_START(start) |
			V_TXPKT_CSUM_LOC(start + skb->csum_offset);
	}
}

/**
 *      is_eth_imm - can an Ethernet packet be sent as immediate data?
 *      @skb: the packet
 *
 *      Returns whether an Ethernet packet is small enough to fit as
 *      immediate data.
 */
static inline int is_eth_imm(int len)
{
	return len <= MAX_IMM_TX_PKT_LEN - sizeof(struct cpl_tx_pkt);
}

static inline void make_tx_pkt_wr(struct sock *sk, struct sk_buff *skb,
				  int credits)
{
	struct fw_eth_tx_eo_wr *req;
	struct fw_eth_tx_pkt_wr *wr;
	struct cpl_tx_pkt_core *cpl;
	int l3hdr_len = skb_network_header_len(skb);
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct net_device *dev = skb_dst(skb)->dev;
	int dlen, len, eth_hdr_len;
	u64 cntrl;

	dlen = skb->len;

	len = is_eth_imm(skb->len) ? skb->len + sizeof(*cpl) : sizeof(*cpl);

	cpl = (struct cpl_tx_pkt_core *)__skb_push(skb, sizeof(*cpl));
	memset(cpl, 0, sizeof(*cpl));
	cntrl = hwcsum(skb);

	if (dev->priv_flags & IFF_802_1Q_VLAN)
		cntrl |= F_TXPKT_VLAN_VLD | V_TXPKT_VLAN(vlan_dev_vlan_id(skb_dst(skb)->dev));

	cpl->ctrl0 = htonl(V_TXPKT_OPCODE(CPL_TX_PKT_XT) |
				V_TXPKT_INTF(cplios->tx_c_chan) |
				V_TXPKT_PF(TOM_DATA(cplios->toedev)->pfvf) >> S_FW_VIID_PFN);

	cpl->pack = htons(0);
	cpl->len = htons(skb->len - sizeof(*cpl));
	cpl->ctrl1 = cpu_to_be64(cntrl);

	if (is_eth_imm(dlen)) {
		wr = (struct fw_eth_tx_pkt_wr *)__skb_push(skb, sizeof(*wr));
		memset(wr, 0, sizeof(*wr));
		wr->equiq_to_len16 = htonl(V_FW_WR_FLOWID(cplios->tid) | V_FW_WR_LEN16(credits));
		wr->r3 = cpu_to_be64(0);
		wr->op_immdlen = htonl(V_FW_WR_OP(FW_ETH_TX_PKT_WR) |
					V_FW_WR_COMPL(1) |
					V_FW_WR_IMMDLEN(len));
		skb_set_transport_header(skb, skb_transport_offset(skb));
	} else {
		req = (struct fw_eth_tx_eo_wr *)__skb_push(skb, sizeof(*req));
		memset(req, 0, sizeof(*req));
		req->op_immdlen = htonl(V_FW_WR_OP(FW_ETH_TX_EO_WR) |
				V_FW_WR_COMPL(1) |
				V_FW_WR_IMMDLEN(l3hdr_len + 22 + sizeof(*cpl) +
				cplios->rtp_header_len));
		req->equiq_to_len16 = htonl(V_FW_WR_FLOWID(cplios->tid) | V_FW_WR_LEN16(credits));
		req->u.udpseg.type = FW_ETH_TX_EO_TYPE_UDPSEG;
		req->u.udpseg.ethlen = 14;
		req->u.udpseg.iplen = htons(l3hdr_len);
		req->u.udpseg.udplen = 8;
		req->u.udpseg.rtplen = cplios->rtp_header_len;
		if (dev->priv_flags & IFF_802_1Q_VLAN)
			eth_hdr_len = VLAN_ETH_HLEN;
		else
			eth_hdr_len = ETH_HLEN;
		req->u.udpseg.mss = htons(skb_shinfo(skb)->gso_size - l3hdr_len
				 - sizeof(struct udphdr) - eth_hdr_len -
				 cplios->rtp_header_len);
		req->u.udpseg.schedpktsize = req->u.udpseg.mss;
		req->u.udpseg.plen = htonl(skb->len - skb_headlen(skb));
		skb_set_transport_header(skb, skb_transport_offset(skb) + 8 +
					 cplios->rtp_header_len);
	}
	skb->csum = credits;
	cplios->wr_credits -= credits;
	cplios->wr_unacked += credits;
}

static void chelsio_ip_cork_release(struct inet_sock *inet)
{
	inet->cork.base.flags &= ~IPCORK_OPT;
	kfree(inet->cork.base.opt);
	inet->cork.base.opt = NULL;
	if (inet->cork.base.dst) {
		dst_release(inet->cork.base.dst);
		inet->cork.base.dst = NULL;
	}
}

/*
 * Retrieve the Destination MAC Hardware Address associated with sending the
 * IPv4 skb out on it's next hop.
 *
 * If successful, the Hardware Address will be filled in and 0 will be
 * returned.
 *
 * If unsuccessful, an ARP Solicitation will be startred (if the skb has a
 * dst), the skb will be freed and an error value will be returned.
 *
 * This code is modeled on the Linux kernel arp_find() and neigh_event_send()
 * routines along with the code in the cxgb4/l2t.c:l2t_send() routine.  The
 * former two Linux routines get us down to the point of knowing if we
 * currently have the Hardware Address cached and l2t_send() provides us with
 * the mechanism to start an ARP Solicitation.  It's really quite a
 * Frankenstein routine ...
 *
 * The motivation for this butchery is because if we pass in an skb to
 * arp_find() and there's no Hardware Address cached, neigh_event_send() will
 * call __neigh_event_send() with the original skb.  This will cause the skb
 * to get queued onto the neigh's ARP Queue and, eventually when an ARP
 * Resolution happens, the queued skbs will be sent to the Net Device's
 * Transmit routine.  Since we want to hand this skb to the firmware for "UDP
 * Segmentation", having it sent out the normal NIC Transmit Path would bypass
 * the firmware processing. (sigh)
 */
static int get_ipv4_hw_addr(unsigned char *haddr, struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	__be32 paddr;
	struct neighbour *n;
	unsigned long now;
	struct sk_buff *skb_ndisc;

	/*
	 * arp_find() ... mostly ...
	 */

	if (!skb_dst(skb)) {
		printk(KERN_WARNING "get_ipv4_hw_addr called with dst=NULL\n");
		kfree_skb(skb);
		return -EINVAL;
	}

	paddr = rt_nexthop(skb_rtable(skb), ip_hdr(skb)->daddr);

	/* and a bit of arp_set_predefined() ... */
	switch (inet_addr_type(dev_net(dev), paddr)) {
	case RTN_LOCAL:
		memcpy(haddr, dev->dev_addr, dev->addr_len);
		return 0;
	case RTN_MULTICAST:
		/* with arp_mc_map() replaced with ... */
		ip_eth_mc_map(paddr, haddr);
		return 0;
	case RTN_BROADCAST:
		memcpy(haddr, dev->broadcast, dev->addr_len);
		return 0;
	}

	n = __neigh_lookup(&arp_tbl, &paddr, dev, 1);
	if (!n) {
		kfree_skb(skb);
		return -EHOSTUNREACH;
	}

	now = jiffies;
	if (n->used != now)
		n->used = now;

	if ((n->nud_state & NUD_VALID) ||
	    (n->nud_state & (NUD_CONNECTED|NUD_DELAY|NUD_PROBE))) {
		neigh_ha_snapshot(haddr, n, dev);
		neigh_release(n);
		return 0;
	}

	/*
	 * End of arp_find() and bits of neigh_event_send() ...
	 */

	/*
	 * In the preceeding if-statement, arp_find() would have called
	 * neigh_event_send() which would check n->nud_state for and of
	 * (NUD_CONNECTED|NUD_DELAY|NUD_PROBE) set.  If not,
	 * neigh_event_send() would call __neigh_event_send() with our
	 * original skb.  So we toss the original skb -- hey, it _is_ UDP
	 * after all! -- and instead call __neigh_event_send() with a
	 * synthetic skb which will sponsor an ARP Solicitation.  This
	 * code is modeled on code from l2t_send().
	 */
	skb_ndisc = NULL;
	neigh_event_send(n, skb_ndisc);

	kfree_skb(skb);
	return -EAGAIN;
}

/*
 *	Combined all pending IP fragments on the socket as one IP datagram
 *	and push them out.
 */
int t4_send_udp(struct sock *sk)
{
	struct sk_buff *skb;
	struct net_device *dev;
	struct inet_sock *inet = inet_sk(sk);
	struct flowi4 *fl4 = &inet->cork.fl.u.ip4;
	struct net *net = sock_net(sk);
	struct ip_options *opt = NULL;
	struct rtable *rt = (struct rtable *)inet->cork.base.dst;
	struct iphdr *iph;
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	int credits, total_size = 0;
	__be16 df = 0;
	int imm = 0;
	int err = 0;

	/* move skb->data to ip header from ext header */
	while (cplios->wr_credits &&  !cplios_flag(sk, CPLIOS_TX_WAIT_IDLE)
			 && rt != NULL &&
			(skb = skb_peek(&cplios->tx_queue)) != NULL) {

		if (is_eth_imm(skb->len + ETH_HLEN)) {
			credits  =  DIV_ROUND_UP(skb->len + ETH_HLEN +
			sizeof(struct cpl_tx_pkt), 16);
			imm = 1;
		}  else
			credits =  DIV_ROUND_UP(8*(calc_tx_flits_ofld(skb))+
				   sizeof(struct fw_eth_tx_eo_wr) + 38 +
				   cplios->rtp_header_len, 16);


		if (cplios->wr_credits < credits)
			break;

		__skb_unlink(skb, &cplios->tx_queue);

		if (!skb_dst(skb))
			skb_dst_set(skb, dst_clone(&rt->dst));

		/* Unless user demanded real pmtu discovery (IP_PMTUDISC_DO), we allow
		 * to fragment the frame generated here. No matter, what transforms
		 * how transforms change size of the packet, it will come out.
		 */
		if (inet->pmtudisc < IP_PMTUDISC_DO)
			skb->ignore_df = 1;

		/* DF bit is set when we want to see DF on outgoing frames.
		 * If ignore_df is set too, we still allow to fragment this frame
		 * locally. */
		if (inet->pmtudisc >= IP_PMTUDISC_DO ||
		    (skb->len <= dst_mtu(skb_dst(skb)) &&
			ip_dont_fragment(sk, skb_dst(skb))))
			df = htons(IP_DF);

		if (inet->cork.base.flags & IPCORK_OPT)
			opt = inet->cork.base.opt;

		iph = (struct iphdr *)skb->data;
		iph->version = 4;
		iph->ihl = 5;
		iph->tos = inet->tos;
		iph->frag_off = df;
		iph->id = 0;
		iph->ttl = 64;
		iph->tot_len = htons(skb->len);
		iph->protocol = IPPROTO_UDP;
		iph->saddr = fl4->saddr;
		iph->daddr = fl4->daddr;

		skb->priority = sk->sk_priority;
		skb->mark = sk->sk_mark;
		skb->sk = sk;

		/* Netfilter gets whole the not fragmented skb. */
		if (skb->data == skb_network_header(skb)) {
			unsigned char hw_dest[MAX_ADDR_LEN];
			skb->protocol = htons(ETH_P_IP);
			skb->dev = skb_dst(skb)->dev;
			dev = skb->dev;
			err = get_ipv4_hw_addr(hw_dest, skb);
			if (err) {
				/*
				 * UDP Applications apparently aren't hep with
				 * getting an EAGAIN error indication ...
				 */
				if (err == -EAGAIN)
					err = 0;
				goto error;
			}

			if (dev_hard_header(skb, dev, ETH_P_IP, hw_dest,
					 dev->dev_addr, skb->len) < 0) {
				kfree_skb(skb);
				goto error;
			}
		}

		make_tx_pkt_wr(sk, skb, credits);
		set_wr_txq(skb, CPL_PRIORITY_DATA, cplios->port_id);
		total_size += skb->truesize;
		enqueue_wr(sk, skb);
		cxgb4_ofld_send(cplios->egress_dev, skb);
		err = 0;
	}

out:
	if (!imm)
		atomic_sub(total_size, &sk->sk_wmem_alloc);
	if (!skb_queue_len(&cplios->tx_queue)) {
		inet->cork.base.dst = NULL;
		chelsio_ip_cork_release(inet);
	}
	return err;

error:
	IP_INC_STATS(net, IPSTATS_MIB_OUTDISCARDS);
	goto out;
}

static inline int chelsio_ufo_append_data(struct sock *sk,
			int getfrag(void *from, char *to, int offset, int len,
			       int odd, struct sk_buff *skb),
			void *from, int length, int hh_len, int fragheaderlen,
			int transhdrlen, int mtu, unsigned int flags)
{
	struct sk_buff *skb;
	int err;
	struct udp_sock  *up = udp_sk(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct flowi *fl = &inet->cork.fl;
	struct udphdr *uh;
	unsigned char *rtp_hdr;
	int tot_len = up->len, len;
	len = hh_len + fragheaderlen + transhdrlen + 20 + TX_HEADER_LEN_UO +
	      cplios->rtp_header_len;

	/*
	 * when the sk->sk_sndbuf limit is reached, the
	 * sock_alloc_send_skb will sleep for sndbuf. If the sock lock is
	 * already held, the WR ack will be backlogged. To process the
	 * WR ack immediately, when the sock_alloc_send_skb is sleeping
	 * on availability of sndbuf, release the sock lock temporarily.
	 */
	release_sock(sk);
	skb = sock_alloc_send_skb(sk, len, (flags & MSG_DONTWAIT), &err);
	lock_sock(sk);

	if (!skb)
		return err;

	/* reserve space for Hardware header */
	skb_reserve(skb, hh_len + TX_HEADER_LEN_UO);

	/* create space for IP/UDP/RTP header */
	skb_put(skb, fragheaderlen + transhdrlen + cplios->rtp_header_len);

	/* initialize network header pointer */
	skb_reset_network_header(skb);

	/* initialize protocol header pointer
	 * This should use skb_set_transport_header() instead,
	 * watch for upstream changes to net/ipv6/ip6_output.c
	 */
	skb->transport_header = skb->network_header + fragheaderlen;

	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum = 0;
	sk_sendmessage_offset(sk) = 0;

	/*
	 * Create a UDP header
	 */
	uh = udp_hdr(skb);
	uh->source = fl->u.ip4.fl4_sport;
	uh->dest = fl->u.ip4.fl4_dport;
	uh->len = htons(tot_len);
	uh->check = 0;
	rtp_hdr = skb_transport_header(skb) + transhdrlen;

	err = memcpy_from_msg(rtp_hdr, from, cplios->rtp_header_len);
	if (err)
		goto error;

	err = skb_append_datato_frags(sk, skb, getfrag, from,
				       (length - transhdrlen -
				       cplios->rtp_header_len));
	if (!err) {
		/* specify the length of each IP datagram fragment */
		skb_shinfo(skb)->gso_size = mtu;
		if (sk->sk_gso_type && sk->sk_gso_type < mtu)
			skb_shinfo(skb)->gso_size = sk->sk_gso_type;
		skb_shinfo(skb)->gso_type = SKB_GSO_UDP;
		__skb_queue_tail(&cplios->tx_queue, skb);
		return err;
	}

error:
	/* There is not enough support to do UDP offload,
	 * so follow normal path
	 */
	kfree_skb(skb);

	return err;
}

int chelsio_ip_append_data(struct sock *sk,
		   int getfrag(void *from, char *to, int offset, int len,
			       int odd, struct sk_buff *skb),
		   void *from, int length, int transhdrlen,
		   struct ipcm_cookie *ipc, struct rtable **rtp,
		   unsigned int flags)
{
	struct inet_sock *inet = inet_sk(sk);

	struct ip_options_rcu *opt = NULL;
	int hh_len;
	int exthdrlen;
	int mtu;
	int err;
	unsigned int maxfraglen, fragheaderlen;
	int csummode = CHECKSUM_NONE;
	struct rtable *rt;

	if (flags&MSG_PROBE)
		return 0;

	opt = ipc->opt;
	if (opt) {
		if (inet->cork.base.opt == NULL) {
			inet->cork.base.opt = kmalloc(sizeof(struct ip_options)
						      + 40, sk->sk_allocation);
			if (unlikely(inet->cork.base.opt == NULL))
				return -ENOBUFS;
		}
		memcpy(inet->cork.base.opt, opt,
		       sizeof(struct ip_options)+opt->opt.optlen);
		inet->cork.base.flags |= IPCORK_OPT;
		inet->cork.base.addr = ipc->addr;
	}
	rt = *rtp;
	if (unlikely(!rt))
		return -EFAULT;
	/*
	 * We steal reference to this route, caller should not release it
	 */
	*rtp = NULL;
	inet->cork.base.fragsize = mtu = inet->pmtudisc == IP_PMTUDISC_PROBE ?
				    rt->dst.dev->mtu :
				    dst_mtu(&rt->dst);
	inet->cork.base.dst = &rt->dst;
	inet->cork.base.length = 0;
	sk_sendmessage_page(sk) = NULL;
	sk_sendmessage_offset(sk) = 0;
	if ((exthdrlen = rt->dst.header_len) != 0) {
		length += exthdrlen;
		transhdrlen += exthdrlen;
	}

	hh_len = LL_RESERVED_SPACE(rt->dst.dev);

	fragheaderlen = sizeof(struct iphdr) + (opt ? opt->opt.optlen : 0);
	maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen;

	if (inet->cork.base.length + length > 0xFFFF - fragheaderlen)
		return -EMSGSIZE;

	/*
	 * transhdrlen > 0 means that this is the first fragment and we wish
	 * it won't be fragmented in the future.
	 */
	if (transhdrlen &&
	    length + fragheaderlen <= mtu &&
	    rt->dst.dev->features & NETIF_F_V4_CSUM &&
	    !exthdrlen)
		csummode = CHECKSUM_PARTIAL;

	inet->cork.base.length += length;
	err = chelsio_ufo_append_data(sk, getfrag, from, length, hh_len,
				 fragheaderlen, transhdrlen, mtu,
				 flags);
	if (err)
		goto error;

	if (rt)
		dst_release(&rt->dst);
	return 0;

error:
	inet->cork.base.length -= length;
	IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTDISCARDS);
	return err;
}

int t4_udp_push_frames(struct sock *sk)
{
	struct udp_sock  *up = udp_sk(sk);
	struct inet_sock *inet = inet_sk(sk);
	int err = 0;
	int is_udplite = IS_UDPLITE(sk);

	err = t4_send_udp(sk);
	if (err) {
		if (err == -ENOBUFS && !inet->recverr) {
			UDP_INC_STATS_USER(sock_net(sk),
					   UDP_MIB_SNDBUFERRORS, is_udplite);
			err = 0;
		}
	} else
		UDP_INC_STATS_USER(sock_net(sk),
				   UDP_MIB_OUTDATAGRAMS, is_udplite);

	up->len = 0;
	up->pending = 0;
	return err;
}

void chelsio_udp_flush_pending_frames(struct sock *sk)
{
	struct udp_sock *up = udp_sk(sk);

	if (up->pending) {
		up->len = 0;
		up->pending = 0;
		/* Purge pending buffers from tx queue */
		skb_queue_purge(&CPL_IO_STATE(sk)->tx_queue);
		chelsio_ip_cork_release(inet_sk(sk));
	}
}

int udpoffload_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct udp_sock *up = udp_sk(sk);
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	int ulen = len;
	struct ipcm_cookie ipc;
	struct rtable *rt = NULL;
	struct flowi4 fl4_stack;
	struct flowi4 *fl4;
	int free = 0;
	int connected = 0;
	__be32 daddr, faddr, saddr;
	__be16 dport;
	u8  tos;
	int err, is_udplite = IS_UDPLITE(sk);
	int corkreq = up->corkflag || msg->msg_flags&MSG_MORE;
	int (*getfrag)(void *, char *, int, int, int, struct sk_buff *);
	struct dst_entry *dst;
	struct net_device *rdev, *dev;
	struct toe_hash_params hash_params;
	struct neighbour *neigh;

	if (len > 0xFFFF)
		return -EMSGSIZE;

	/*
	 *	Check the flags.
	 */

	if (msg->msg_flags & MSG_OOB) /* Mirror BSD error message compatibility */
		return -EOPNOTSUPP;

	ipc.opt = NULL;
	ipc.tx_flags = 0;

	fl4 = &inet->cork.fl.u.ip4;
	if (up->pending) {
		/*
		 * There are pending frames.
		 * The socket lock must be held while it's corked.
		 */
		lock_sock(sk);
		if (likely(up->pending)) {
			if (unlikely(up->pending != AF_INET)) {
				release_sock(sk);
				return -EINVAL;
			}
			goto do_append_data;
		}
		release_sock(sk);
	}
	ulen += sizeof(struct udphdr);

	/*
	 *	Get and verify the address.
	 */
	if (msg->msg_name) {
		struct sockaddr_in * usin = (struct sockaddr_in *)msg->msg_name;
		if (msg->msg_namelen < sizeof(*usin))
			return -EINVAL;
		if (usin->sin_family != AF_INET) {
			if (usin->sin_family != AF_UNSPEC)
				return -EAFNOSUPPORT;
		}

		daddr = usin->sin_addr.s_addr;
		dport = usin->sin_port;
		if (dport == 0)
			return -EINVAL;
	} else {
		if (sk->sk_state != TCP_ESTABLISHED)
			return -EDESTADDRREQ;
		daddr = inet->inet_daddr;
		dport = inet->inet_dport;
		/* Open fast path for connected socket.
		   Route will not be used, if at least one option is set.
		 */
		connected = 1;
	}
	ipc.addr = inet->inet_saddr;

	ipc.oif = sk->sk_bound_dev_if;
	sock_tx_timestamp(sk, &ipc.tx_flags);

	if (!ipc.opt)
		ipc.opt = inet->inet_opt;

	saddr = ipc.addr;
	ipc.addr = faddr = daddr;

	if (ipc.opt && ipc.opt->opt.srr) {
		if (!daddr)
			return -EINVAL;
		faddr = ipc.opt->opt.faddr;
		connected = 0;
	}
	tos = RT_TOS(inet->tos);
	if (sock_flag(sk, SOCK_LOCALROUTE) ||
	    (msg->msg_flags & MSG_DONTROUTE) ||
	    (ipc.opt && ipc.opt->opt.is_strictroute)) {
		tos |= RTO_ONLINK;
		connected = 0;
	}

	if (ipv4_is_multicast(daddr)) {
		if (!ipc.oif)
			ipc.oif = inet->mc_index;
		if (!saddr)
			saddr = inet->mc_addr;
		connected = 0;
	}

	if (connected)
		rt = (struct rtable *)sk_dst_check(sk, 0);

	if (rt == NULL) {
		struct net *net = sock_net(sk);
		fl4 = &fl4_stack;
		flowi4_init_output(fl4, ipc.oif, sk->sk_mark, tos,
				   RT_SCOPE_UNIVERSE, sk->sk_protocol,
				   inet_sk_flowi_flags(sk)|FLOWI_FLAG_CAN_SLEEP,
				   faddr, saddr, dport, inet->inet_sport);
		security_sk_classify_flow(sk, flowi4_to_flowi(fl4));
		rt = ip_route_output_flow(net, fl4, sk);
		if (IS_ERR(rt)) {
			err = PTR_ERR(rt);
			rt = NULL;
			if (err == -ENETUNREACH)
				IP_INC_STATS_BH(net, IPSTATS_MIB_OUTNOROUTES);
			goto out;
		}

		err = -EACCES;
		if ((rt->rt_flags & RTCF_BROADCAST) &&
		    !sock_flag(sk, SOCK_BROADCAST))
			goto out;
		if (connected)
			sk_dst_set(sk, dst_clone(&rt->dst));
	}

	dst = &rt->dst;
	dev = dst->dev;
	neigh = t4_dst_neigh_lookup(dst, &inet_sk(sk)->inet_daddr);
	init_toe_hash_params(&hash_params, neigh->dev, neigh,
			     inet_sk(sk)->inet_saddr, inet_sk(sk)->inet_daddr,
			     inet_sk(sk)->inet_sport, inet_sk(sk)->inet_dport,
			     NULL, NULL, false, IPPROTO_UDP);
	rdev = offload_get_phys_egress(&hash_params, TOE_OPEN);
	t4_dst_neigh_release(neigh);
	if (unlikely(!cplios_flag(sk, CPLIOS_TX_DATA_SENT))) {
		struct toedev *tdev;

		if (!netdev_is_offload(rdev))
			return -EOPNOTSUPP;

		/*
		 * Apps will send only the payload size. Driver will
		 * update the header size based on the
		 * network configuration
		 */
		if (dev->priv_flags & IFF_802_1Q_VLAN)
			sk->sk_gso_type += VLAN_ETH_HLEN;
		else
			sk->sk_gso_type += ETH_HLEN;

		sk->sk_gso_type += sizeof(struct iphdr) +
					sizeof(struct udphdr) +
					cplios->rtp_header_len;

		tdev = TOEDEV(rdev);
		if (!tdev || !tdev->can_offload(tdev, sk))
			return -EACCES;

		err = t4_udpv4_offload_init(tdev, sk, rdev);
		if (err)
			return err;
	} else if (unlikely(TOEDEV(rdev) != cplios->toedev))
		return -ENXIO;

	if (msg->msg_flags&MSG_CONFIRM)
		goto do_confirm;
back_from_confirm:

	saddr = fl4->saddr;
	if (!ipc.addr)
		daddr = ipc.addr = fl4->daddr;

	lock_sock(sk);
	if (unlikely(up->pending)) {
		/* The socket is already corked while preparing it. */
		/* ... which is an evident application bug. --ANK */
		release_sock(sk);

		net_dbg_ratelimited(KERN_DEBUG "udp cork app bug 2\n");
		err = -EINVAL;
		goto out;
	}
	/*
	 *	Now cork the socket to pend data.
	 */
	inet->cork.fl.u.ip4.daddr = daddr;
	inet->cork.fl.u.ip4.fl4_dport = dport;
	inet->cork.fl.u.ip4.saddr = saddr;
	inet->cork.fl.u.ip4.fl4_sport = inet->inet_sport;
	up->pending = AF_INET;

do_append_data:
	up->len += ulen;
	getfrag  = ip_generic_getfrag;
	err = chelsio_ip_append_data(sk, getfrag, msg, ulen,
			sizeof(struct udphdr), &ipc, &rt,
			corkreq ? msg->msg_flags|MSG_MORE : msg->msg_flags);
	if (err)
		chelsio_udp_flush_pending_frames(sk);
	else if (!corkreq)
		err = t4_udp_push_frames(sk);
	else if (unlikely(skb_queue_empty(&cplios->tx_queue)))
		up->pending = 0;
	release_sock(sk);

out:
	ip_rt_put(rt);
	if (free)
		kfree(ipc.opt);
	if (!err)
		return len;
	/*
	 * ENOBUFS = no kernel mem, SOCK_NOSPACE = no sndbuf space.  Reporting
	 * ENOBUFS might not be good (it's not tunable per se), but otherwise
	 * we don't have a good statistic (IpOutDiscards but it can be too many
	 * things).  We could add another new stat but at least for now that
	 * seems like overkill.
	 */
	if (err == -ENOBUFS || test_bit(SOCK_NOSPACE, &sk->sk_socket->flags))
		UDP_INC_STATS_USER(sock_net(sk),
				UDP_MIB_SNDBUFERRORS, is_udplite);

	return err;

do_confirm:
	dst_confirm(&rt->dst);
	if (!(msg->msg_flags&MSG_PROBE) || len)
		goto back_from_confirm;
	err = 0;
	goto out;
}

#ifdef CONFIG_UDPV6_OFFLOAD
static inline int chelsio_ip6_ufo_append_data(struct sock *sk,
			int getfrag(void *from, char *to, int offset, int len,
			int odd, struct sk_buff *skb),
			void *from, int length, int hh_len, int fragheaderlen,
			int transhdrlen, int mtu, unsigned int flags,
			struct rt6_info *rt)

{
	struct sk_buff *skb;
	int err;
	struct inet_sock *inet = inet_sk(sk);
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct flowi6 *fl6 = &inet->cork.fl.u.ip6;
	struct udphdr *uh;
	unsigned char *rtp_hdr;
	struct udp_sock  *up = udp_sk(sk);
	int tot_len = up->len, len;
	len = hh_len + fragheaderlen + transhdrlen + 20 + TX_HEADER_LEN_UO +
	      cplios->rtp_header_len;

	/* There is support for UDP large send offload by network
	 * device, so create one single skb packet containing complete
	 * udp datagram
	 */

	/*
	 * when the sk->sk_sndbuf limit is reached, the
	 * sock_alloc_send_skb will sleep for sndbuf. If the sock lock is
	 * already held, the WR ack will be backlogged. To process the
	 * WR ack immediately, when the sock_alloc_send_skb is sleeping
	 * on availability of sndbuf, releasing the sock lock temporarily.
	 */
	release_sock(sk);
	skb = sock_alloc_send_skb(sk, len, (flags & MSG_DONTWAIT), &err);
	lock_sock(sk);

	if (skb == NULL)
		return err;

	/* reserve space for Hardware header */
	skb_reserve(skb, hh_len + TX_HEADER_LEN_UO);

	/* create space for RTP/UDP/IP header */
	skb_put(skb, fragheaderlen + transhdrlen + cplios->rtp_header_len);

	/* initialize network header pointer */
	skb_reset_network_header(skb);

	/* initialize protocol header pointer
	 * This should use skb_set_transport_header() instead,
	 * watch for upstream changes to net/ipv6/ip6_output.c
	 */
	skb->transport_header = skb->network_header + fragheaderlen;

	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum = 0;
	sk_sendmessage_offset(sk) = 0;

	uh = udp_hdr(skb);
	uh->source = fl6->fl6_sport;
	uh->dest = fl6->fl6_dport;
	uh->len = htons(tot_len);
	uh->check = 0;
	rtp_hdr = skb_transport_header(skb) + transhdrlen;
	err = memcpy_from_msg(rtp_hdr, from, cplios->rtp_header_len);
	if (err)
		goto error;

	err = skb_append_datato_frags(sk, skb, getfrag, from,
				      (length - transhdrlen -
				       cplios->rtp_header_len));
	if (!err) {
		struct frag_hdr fhdr;

		/* Specify the length of each IPv6 datagram fragment. */

		skb_shinfo(skb)->gso_size = mtu;
		if (sk->sk_gso_type && sk->sk_gso_type < mtu)
			skb_shinfo(skb)->gso_size = sk->sk_gso_type;
		skb_shinfo(skb)->gso_type = SKB_GSO_UDP;
		ipv6_select_ident_p(&fhdr, rt);
		skb_shinfo(skb)->ip6_frag_id = fhdr.identification;
		 __skb_queue_tail(&cplios->tx_queue, skb);
		return 0;
	}
error:
	/* There is not enough support to do UDP offload,
	 * so follow normal path
	 */
	kfree_skb(skb);

	return err;
}

static inline struct ipv6_opt_hdr *chelsio_ip6_opt_dup(struct ipv6_opt_hdr *src,
						       gfp_t gfp)
{
	return src ? kmemdup(src, (src->hdrlen + 1) * 8, gfp) : NULL;
}

static inline struct ipv6_rt_hdr *chelsio_ip6_rthdr_dup(struct ipv6_rt_hdr *src,
							gfp_t gfp)
{
	return src ? kmemdup(src, (src->hdrlen + 1) * 8, gfp) : NULL;
}


int chelsio_ip6_append_data(struct sock *sk, int getfrag(void *from, char *to,
	int offset, int len, int odd, struct sk_buff *skb),
	void *from, int length, int transhdrlen,
	int hlimit, int tclass, struct ipv6_txoptions *opt, struct flowi6 *fl6,
	struct rt6_info *rt, unsigned int flags, int dontfrag)
{
	struct inet_sock *inet = inet_sk(sk);
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct inet_cork *cork;
	unsigned int maxfraglen, fragheaderlen;
	int exthdrlen;
	int dst_exthdrlen;
	int hh_len;
	int mtu;
	int err;
	__u8 tx_flags = 0;
	if (flags&MSG_PROBE)
		return 0;
	cork = &inet->cork.base;
	/*
	 * setup for corking
	 */
	if (opt) {
		if (WARN_ON(np->cork.opt))
			return -EINVAL;

		np->cork.opt = kmalloc(opt->tot_len, sk->sk_allocation);
		if (unlikely(np->cork.opt == NULL))
			return -ENOBUFS;

		np->cork.opt->tot_len = opt->tot_len;
		np->cork.opt->opt_flen = opt->opt_flen;
		np->cork.opt->opt_nflen = opt->opt_nflen;

		np->cork.opt->dst0opt = chelsio_ip6_opt_dup(opt->dst0opt,
						    sk->sk_allocation);
		if (opt->dst0opt && !np->cork.opt->dst0opt)
			return -ENOBUFS;

		np->cork.opt->dst1opt = chelsio_ip6_opt_dup(opt->dst1opt,
						    sk->sk_allocation);
		if (opt->dst1opt && !np->cork.opt->dst1opt)
			return -ENOBUFS;

		np->cork.opt->hopopt = chelsio_ip6_opt_dup(opt->hopopt,
						   sk->sk_allocation);
		if (opt->hopopt && !np->cork.opt->hopopt)
			return -ENOBUFS;

		np->cork.opt->srcrt = chelsio_ip6_rthdr_dup(opt->srcrt,
						    sk->sk_allocation);
		if (opt->srcrt && !np->cork.opt->srcrt)
			return -ENOBUFS;

	}
	dst_hold(&rt->dst);
	cork->dst = &rt->dst;
	inet->cork.fl.u.ip6 = *fl6;
	np->cork.hop_limit = hlimit;
	np->cork.tclass = tclass;
	if (rt->dst.flags & DST_XFRM_TUNNEL)
		mtu = np->pmtudisc == IPV6_PMTUDISC_PROBE ?
		      rt->dst.dev->mtu : dst_mtu(&rt->dst);
	else
		mtu = np->pmtudisc == IPV6_PMTUDISC_PROBE ?
		      rt->dst.dev->mtu : dst_mtu(rt->dst.path);
	if (np->frag_size < mtu) {
		if (np->frag_size)
			mtu = np->frag_size;
	}
	cork->fragsize = mtu;
	if (dst_allfrag(rt->dst.path))
		cork->flags |= IPCORK_ALLFRAG;
	cork->length = 0;
	sk_sendmessage_page(sk) = NULL;
	sk_sendmessage_offset(sk) = 0;
	exthdrlen = (opt ? opt->opt_flen : 0) - rt->rt6i_nfheader_len;
	length += exthdrlen;
	transhdrlen += exthdrlen;
	dst_exthdrlen = rt->dst.header_len;

	hh_len = LL_RESERVED_SPACE(rt->dst.dev);

	fragheaderlen = sizeof(struct ipv6hdr) + rt->rt6i_nfheader_len +
			(opt ? opt->opt_nflen : 0);
	maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen -
		     sizeof(struct frag_hdr);

	if (mtu <= sizeof(struct ipv6hdr) + IPV6_MAXPLEN) {
		if (cork->length + length > sizeof(struct ipv6hdr) +
			IPV6_MAXPLEN - fragheaderlen) {
			ipv6_local_error_p(sk, EMSGSIZE, fl6, mtu-exthdrlen);
			return -EMSGSIZE;
		}
	}

	/* For UDP, check if TX timestamp is enabled */
	if (sk->sk_type == SOCK_DGRAM)
		sock_tx_timestamp(sk, &tx_flags);

	/*
	 * Let's try using as much space as possible.
	 * Use MTU if total length of the message fits into the MTU.
	 * Otherwise, we need to reserve fragment header and
	 * fragment alignment (= 8-15 octects, in total).
	 *
	 * Note that we may need to "move" the data from the tail of
	 * of the buffer to the new fragment when we split
	 * the message.
	 *
	 * FIXME: It may be fragmented into multiple chunks
	 *        at once if non-fragmentable extension headers
	 *        are too large.
	 * --yoshfuji
	 */

	cork->length += length;
	err = chelsio_ip6_ufo_append_data(sk, getfrag, from,
				length, hh_len, fragheaderlen,
				transhdrlen, mtu, flags, rt);
	if (err)
		goto error;
	return 0;
error:
	cork->length -= length;
	IP6_INC_STATS(sock_net(sk), rt->rt6i_idev, IPSTATS_MIB_OUTDISCARDS);
	return err;
}

static void chelsio_ip6_cork_release_p(struct inet_sock *inet,
                                     struct ipv6_pinfo *np)
{
	if (np->cork.opt) {
		kfree(np->cork.opt->dst0opt);
		kfree(np->cork.opt->dst1opt);
		kfree(np->cork.opt->hopopt);
		kfree(np->cork.opt->srcrt);
		kfree(np->cork.opt);
		np->cork.opt = NULL;
	}

	if (inet->cork.base.dst) {
		dst_release(inet->cork.base.dst);
		inet->cork.base.dst = NULL;
		inet->cork.base.flags &= ~IPCORK_ALLFRAG;
	}
	memset(&inet->cork.fl, 0, sizeof(inet->cork.fl));
}

int chelsio_ip6_push_pending_frames(struct sock *sk)
{
	struct sk_buff *skb;
	struct in6_addr final_dst_buf, *final_dst = &final_dst_buf;
	struct inet_sock *inet = inet_sk(sk);
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct net *net = sock_net(sk);
	struct ipv6hdr *hdr;
	struct ipv6_txoptions *opt = np->cork.opt;
	struct rt6_info *rt = (struct rt6_info *)inet->cork.base.dst;
	struct flowi6 *fl6 = &inet->cork.fl.u.ip6;
	unsigned char proto = fl6->flowi6_proto;
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	int credits, total_size = 0, imm = 0;
	struct neighbour *n;
	unsigned long now;
	int err = 0, len;

	while (cplios->wr_credits &&
		!cplios_flag(sk, CPLIOS_TX_WAIT_IDLE) &&
		rt != NULL &&
		(skb = skb_peek(&cplios->tx_queue)) != NULL) {
		if (is_eth_imm(skb->len + ETH_HLEN)) {
			credits  =  DIV_ROUND_UP(skb->len + ETH_HLEN +
					sizeof(struct cpl_tx_pkt), 16);
			imm = 1;
		}  else
			credits =  DIV_ROUND_UP(8*(calc_tx_flits_ofld(skb))+
				   sizeof(struct fw_eth_tx_eo_wr) + 38 +
				   cplios->rtp_header_len, 16);

		if (cplios->wr_credits < credits)
			break;

		__skb_unlink(skb, &cplios->tx_queue);

		if (!skb_dst(skb))
			skb_dst_set(skb, dst_clone(&rt->dst));

		/* Allow local fragmentation. */
		if (np->pmtudisc < IPV6_PMTUDISC_DO)
			skb->ignore_df = 1;

		*final_dst = fl6->daddr;
		__skb_pull(skb, skb_network_header_len(skb));
		if (opt && opt->opt_flen)
			ipv6_push_frag_opts_p(skb, opt, &proto);
		if (opt && opt->opt_nflen)
			ipv6_push_nfrag_opts(skb, opt, &proto, &final_dst);

		skb_push(skb, sizeof(struct ipv6hdr));
		skb_reset_network_header(skb);
		hdr = ipv6_hdr(skb);

		ip6_flow_hdr(hdr, np->cork.tclass, fl6->flowlabel);
		hdr->hop_limit = np->cork.hop_limit;
		hdr->nexthdr = proto;
		hdr->saddr = fl6->saddr;
		hdr->daddr = *final_dst;

		len = skb->len - sizeof(struct ipv6hdr);
		if (len > IPV6_MAXPLEN)
			len = 0;
		hdr->payload_len = htons(len);

		skb->priority = sk->sk_priority;
		skb->mark = sk->sk_mark;

		skb->protocol = htons(ETH_P_IPV6);
		skb->dev = skb_dst(skb)->dev;

		IP6_UPD_PO_STATS(net, rt->rt6i_idev, IPSTATS_MIB_OUT, skb->len);
		if (proto == IPPROTO_ICMPV6) {
			struct inet6_dev *idev = ip6_dst_idev(skb_dst(skb));

			ICMP6MSGOUT_INC_STATS_BH(net, idev,
						 icmp6_hdr(skb)->icmp6_type);
			ICMP6_INC_STATS_BH(net, idev, ICMP6_MIB_OUTMSGS);
		}

		/*
		 * Replacement for call to neigh_resolve_output().
		 * ===============================================
		 */

		/*
		 * Resolve the Destination MAC Hardware Address associated
		 * with our next hop.  Unfortunately we can't use the Linux
		 * neigh_resolve_output() routine because it actually sends
		 * our skb and we want to embed it into a Work Request.
		 *
		 * See get_ipv4_hw_addr() above for more explanation of what
		 * we're doing here ...
		 */
		n = dst_neigh_lookup(&rt->dst, &hdr->daddr);
		now = jiffies;
		if (n->used != now)
			n->used = now;

		/*
		 * If we don't have the Destination MAC, then inject a
		 * solicitation (modeled on cxgb4_sk_l2t_send(), toss the skb and
		 * bail out.
		 */
		if (!((n->nud_state & NUD_VALID) ||
		      (n->nud_state & (NUD_CONNECTED|NUD_DELAY|NUD_PROBE)))) {
			struct in6_addr addr_buf;
			struct sk_buff *skb_ndisc = NULL;
			struct icmp6hdr icmp6h = {
				.icmp6_type = NDISC_NEIGHBOUR_SOLICITATION,
			};

			/*
			 * Bug #15808: When IPv6 link local address is
			 * removed, neighbour discovery fails as
			 * ndisc_solicit->ndisc_send_ns looks for link local
			 * address to send NEIGHBOUR_SOLICITATION packet. Here
			 * we are generating the NEIGHBOUR_SOLICITATION packet
			 * with the correct source address.
			 */
			if (chelsio_ipv6_get_lladdr(skb->dev, &addr_buf,
					(IFA_F_TENTATIVE|IFA_F_OPTIMISTIC))) {
				struct in6_addr *target = (struct in6_addr *)&n->primary_key;

				skb_ndisc = ndisc_build_skb(skb->dev, target,
							    &inet6_sk_rcv_saddr(sk),
							    &icmp6h, target, 0);
				if (!skb_dst(skb_ndisc))
					skb_dst_set(skb_ndisc,
						    dst_clone(__sk_dst_get(sk)));
			}
			neigh_event_send(n, skb_ndisc);
			t4_dst_neigh_release(n);

			/*
			 * We should _probably_ return -EAGAIN but apparently
			 * some UDP applications freak out over that.
			 */
			err = 0;
			goto error;
		}
		err = dev_hard_header(skb, skb->dev, ntohs(skb->protocol),
				      n->ha, NULL, skb->len);
		t4_dst_neigh_release(n);
		if (err < 0)
			goto error;
		err = 0;

		/*
		 * End of replacement for neigh_resolve_output().
		 * ==============================================
		 */

		make_tx_pkt_wr(sk, skb, credits);
		set_wr_txq(skb, CPL_PRIORITY_DATA, cplios->port_id);
		total_size += skb->truesize;
		enqueue_wr(sk, skb);
		cxgb4_ofld_send(cplios->egress_dev, skb);
		err = 0;
		dst_release(&rt->dst);
	}
out:
	if (!imm)
		atomic_sub(total_size, &sk->sk_wmem_alloc);
	if (!skb_queue_len(&cplios->tx_queue)) {
		inet->cork.base.dst = NULL;
		chelsio_ip6_cork_release_p(inet, np);
	}
	return err;

error:
	dst_release(&rt->dst);
	kfree_skb(skb);
	IP6_INC_STATS(net, rt->rt6i_idev, IPSTATS_MIB_OUTDISCARDS);
	goto out;
}

static void chelsio_udp6_hwcsum_outgoing(struct sock *sk, struct sk_buff *skb,
				 const struct in6_addr *saddr,
				 const struct in6_addr *daddr, int len)
{
	unsigned int offset;
	struct udphdr *uh = udp_hdr(skb);
	__wsum csum = 0;

	if (skb_queue_len(&CPL_IO_STATE(sk)->tx_queue) == 1) {
		/* Only one fragment on the socket.  */
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct udphdr, check);
		uh->check = ~csum_ipv6_magic(saddr, daddr, len, IPPROTO_UDP, 0);
	} else {
		/*
		 * HW-checksum won't work as there are two or more
		 * fragments on the socket so that all csums of sk_buffs
		 * should be together
		 */
		offset = skb_transport_offset(skb);
		skb->csum = skb_checksum(skb, offset, skb->len - offset, 0);

		skb->ip_summed = CHECKSUM_NONE;

		skb_queue_walk(&CPL_IO_STATE(sk)->tx_queue, skb) {
			csum = csum_add(csum, skb->csum);
		}

		uh->check = csum_ipv6_magic(saddr, daddr, len, IPPROTO_UDP,
					    csum);
		if (uh->check == 0)
			uh->check = CSUM_MANGLED_0;
	}
}

int chelsio_udp_v6_push_pending_frames(struct sock *sk)
{
	struct sk_buff *skb;
	struct udphdr *uh;
	struct udp_sock  *up = udp_sk(sk);
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct flowi6 *fl6 = &inet->cork.fl.u.ip6;
	int err = 0;
	int is_udplite = IS_UDPLITE(sk);
	__wsum csum = 0;

	/* Grab the skbuff where UDP header space exists. */
	skb = skb_peek(&cplios->tx_queue);
	if (skb == NULL)
		goto out;

	uh = udp_hdr(skb);
	uh->source = fl6->fl6_sport;
	uh->dest = fl6->fl6_dport;
	uh->len = htons(up->len);
	uh->check = 0;

	if (is_udplite)
		csum = udplite_csum_outgoing(sk, skb);
	else if (skb->ip_summed == CHECKSUM_PARTIAL) { /* UDP hardware csum */
		chelsio_udp6_hwcsum_outgoing(sk, skb, &fl6->saddr, &fl6->daddr,
				     up->len);
		goto send;
	} else
		csum = udp_csum_outgoing(sk, skb);

	/* add protocol-dependent pseudo-header */
	uh->check = csum_ipv6_magic(&fl6->saddr, &fl6->daddr,
				    up->len, fl6->flowi6_proto, csum);
	if (uh->check == 0)
		uh->check = CSUM_MANGLED_0;

send:
	err = chelsio_ip6_push_pending_frames(sk);
	if (err) {
		if (err == -ENOBUFS && !inet6_sk(sk)->recverr) {
			UDP6_INC_STATS_USER(sock_net(sk),
					    UDP_MIB_SNDBUFERRORS, is_udplite);
			err = 0;
		}
	} else
		UDP6_INC_STATS_USER(sock_net(sk),
				    UDP_MIB_OUTDATAGRAMS, is_udplite);
out:
	up->len = 0;
	up->pending = 0;
	return err;
}

/*
 * Throw away all pending data and cancel the corking. Socket is locked.
 */
static void chelsio_udp_v6_flush_pending_frames(struct sock *sk)
{
	struct udp_sock *up = udp_sk(sk);

	if (up->pending == AF_INET)
		chelsio_udp_flush_pending_frames(sk);
	else if (up->pending) {
		up->len = 0;
		up->pending = 0;
		/* Purge pending buffers from tx queue */
		skb_queue_purge(&CPL_IO_STATE(sk)->tx_queue);
		chelsio_ip6_cork_release_p(inet_sk(sk), inet6_sk(sk));
	}
}


int udpv6offload_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct ipv6_txoptions opt_space;
	struct udp_sock *up = udp_sk(sk);
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) msg->msg_name;
	struct in6_addr *daddr, *final_p, final;
	struct ipv6_txoptions *opt = NULL;
	struct ip6_flowlabel *flowlabel = NULL;
	struct flowi6 fl6;
	struct dst_entry *dst;
	struct neighbour *neigh;
	struct net_device *rdev, *dev;
	struct toe_hash_params hash_params;
	int addr_len = msg->msg_namelen;
	int ulen = len;
	int hlimit = -1;
	int tclass = -1;
	int dontfrag = -1;
	int corkreq = up->corkflag || msg->msg_flags&MSG_MORE;
	int err;
	int connected = 0;
	int is_udplite = IS_UDPLITE(sk);
	int (*getfrag)(void *, char *, int, int, int, struct sk_buff *);
	/* destination address check */
	if (sin6) {
		if (addr_len < offsetof(struct sockaddr, sa_data))
			return -EINVAL;

		switch (sin6->sin6_family) {
		case AF_INET6:
			if (addr_len < SIN6_LEN_RFC2133)
				return -EINVAL;
			daddr = &sin6->sin6_addr;
			break;
		case AF_INET:
			goto do_udp_sendmsg;
		case AF_UNSPEC:
			msg->msg_name = sin6 = NULL;
			msg->msg_namelen = addr_len = 0;
			daddr = NULL;
			break;
		default:
			return -EINVAL;
		}
	} else if (!up->pending) {
		if (sk->sk_state != TCP_ESTABLISHED)
			return -EDESTADDRREQ;
		daddr = &inet6_sk_daddr(sk);
	} else
		daddr = NULL;

	if (daddr) {
		if (ipv6_addr_v4mapped(daddr)) {
			struct sockaddr_in sin;
			sin.sin_family = AF_INET;
			sin.sin_port = sin6 ? sin6->sin6_port :
					inet->inet_dport;
			sin.sin_addr.s_addr = daddr->s6_addr32[3];
			msg->msg_name = &sin;
			msg->msg_namelen = sizeof(sin);
do_udp_sendmsg:
			if (__ipv6_only_sock(sk))
				return -ENETUNREACH;
			return udp_sendmsg(sk, msg, len);
		}
	}

	if (up->pending == AF_INET)
		return udp_sendmsg(sk, msg, len);

	/* Rough check on arithmetic overflow,
	   better check is made in ip6_append_data().
	   */
	if (len > INT_MAX - sizeof(struct udphdr))
		return -EMSGSIZE;

	if (up->pending) {
		/*
		 * There are pending frames.
		 * The socket lock must be held while it's corked.
		 */
		lock_sock(sk);
		if (likely(up->pending)) {
			if (unlikely(up->pending != AF_INET6)) {
				release_sock(sk);
				return -EAFNOSUPPORT;
			}
			dst = NULL;
			goto do_append_data;
		}
		release_sock(sk);
	}
	ulen += sizeof(struct udphdr);

	memset(&fl6, 0, sizeof(fl6));

	if (sin6) {
		if (sin6->sin6_port == 0)
			return -EINVAL;

		fl6.fl6_dport = sin6->sin6_port;
		daddr = &sin6->sin6_addr;

		if (np->sndflow) {
			fl6.flowlabel = sin6->sin6_flowinfo&IPV6_FLOWINFO_MASK;
			if (fl6.flowlabel&IPV6_FLOWLABEL_MASK) {
				flowlabel = fl6_sock_lookup(sk, fl6.flowlabel);
				if (flowlabel == NULL)
					return -EINVAL;
				daddr = &flowlabel->dst;
			}
		}

		/*
		 * Otherwise it will be difficult to maintain
		 * sk->sk_dst_cache.
		 */
		if (sk->sk_state == TCP_ESTABLISHED &&
		    ipv6_addr_equal(daddr, &inet6_sk_daddr(sk)))
			daddr = &inet6_sk_daddr(sk);

		if (addr_len >= sizeof(struct sockaddr_in6) &&
		    sin6->sin6_scope_id &&
		    ipv6_addr_type(daddr)&IPV6_ADDR_LINKLOCAL)
			fl6.flowi6_oif = sin6->sin6_scope_id;
	} else {
		if (sk->sk_state != TCP_ESTABLISHED)
			return -EDESTADDRREQ;

		fl6.fl6_dport = inet->inet_dport;
		daddr = &inet6_sk_daddr(sk);
		fl6.flowlabel = np->flow_label;
		connected = 1;
	}

	if (!fl6.flowi6_oif)
		fl6.flowi6_oif = sk->sk_bound_dev_if;

	if (!fl6.flowi6_oif)
		fl6.flowi6_oif = np->sticky_pktinfo.ipi6_ifindex;

	fl6.flowi6_mark = sk->sk_mark;

	if (msg->msg_controllen) {
		opt = &opt_space;
		memset(opt, 0, sizeof(struct ipv6_txoptions));
		opt->tot_len = sizeof(*opt);

		err = ip6_datagram_send_ctl(sock_net(sk), sk, msg, &fl6, opt,
					    &hlimit, &tclass, &dontfrag);
		if (err < 0) {
			fl6_sock_release(flowlabel);
			return err;
		}
		if ((fl6.flowlabel&IPV6_FLOWLABEL_MASK) && !flowlabel) {
			flowlabel = fl6_sock_lookup(sk, fl6.flowlabel);
			if (flowlabel == NULL)
				return -EINVAL;
		}
		if (!(opt->opt_nflen|opt->opt_flen))
			opt = NULL;
		connected = 0;
	}
	if (opt == NULL)
		opt = np->opt;
	if (flowlabel)
		opt = fl6_merge_options(&opt_space, flowlabel, opt);
	opt = ipv6_fixup_options(&opt_space, opt);

	fl6.flowi6_proto = sk->sk_protocol;
	if (!ipv6_addr_any(daddr))
		fl6.daddr = *daddr;
	else
		fl6.daddr.s6_addr[15] = 0x1; /* :: means loopback (BSD'ism) */
	if (ipv6_addr_any(&fl6.saddr) && !ipv6_addr_any(&inet6_sk_saddr(sk)))
		fl6.saddr = inet6_sk_saddr(sk);
	fl6.fl6_sport = inet->inet_sport;

	final_p = fl6_update_dst(&fl6, opt, &final);
	if (final_p)
		connected = 0;

	if (!fl6.flowi6_oif && ipv6_addr_is_multicast(&fl6.daddr)) {
		fl6.flowi6_oif = np->mcast_oif;
		connected = 0;
	} else if (!fl6.flowi6_oif)
		fl6.flowi6_oif = np->ucast_oif;

	security_sk_classify_flow(sk, flowi6_to_flowi(&fl6));

	dst = ip6_sk_dst_lookup_flow_compat(sk, &fl6, final_p, true);
	if (IS_ERR(dst)) {
		err = PTR_ERR(dst);
		dst = NULL;
		goto out;
	}

	if (hlimit < 0) {
		if (ipv6_addr_is_multicast(&fl6.daddr))
			hlimit = np->mcast_hops;
		else
			hlimit = np->hop_limit;
		if (hlimit < 0)
			hlimit = ip6_dst_hoplimit(dst);
	}

	if (tclass < 0)
		tclass = np->tclass;

	dev = dst->dev;
	neigh = t4_dst_neigh_lookup(dst, &inet6_sk_daddr(sk));
	init_toe_hash_params(&hash_params, neigh->dev, neigh, 0, 0,
			     inet_sk(sk)->inet_sport, inet_sk(sk)->inet_dport,
			     &inet6_sk_saddr(sk).s6_addr32[0],
			     &inet6_sk_daddr(sk).s6_addr32[0],
			     true, IPPROTO_UDP);
	rdev = offload_get_phys_egress(&hash_params, TOE_OPEN);
	t4_dst_neigh_release(neigh);
	if (unlikely(!cplios_flag(sk, CPLIOS_TX_DATA_SENT))) {
		struct toedev *tdev;

		if (!netdev_is_offload(rdev))
			return -EOPNOTSUPP;

		/*
		 * Apps will send only the payload size. Driver will
		 * update the header size based on the
		 * network configuration
		 */
		if (dev->priv_flags & IFF_802_1Q_VLAN)
			sk->sk_gso_type += VLAN_ETH_HLEN;
		else
			sk->sk_gso_type += ETH_HLEN;
		sk->sk_gso_type += sizeof(struct ipv6hdr) +
				       sizeof(struct udphdr) +
				       cplios->rtp_header_len;
		tdev = TOEDEV(rdev);
		if (!tdev || !tdev->can_offload(tdev, sk))
			return -EACCES;

		err = t4_udpv6_offload_init(tdev, sk, rdev);
		if (err)
			return err;
	} else if (unlikely(TOEDEV(rdev) != cplios->toedev))
		return -ENXIO;

	if (dontfrag < 0)
		dontfrag = np->dontfrag;

	if (msg->msg_flags&MSG_CONFIRM)
		goto do_confirm;
back_from_confirm:

	lock_sock(sk);
	if (unlikely(up->pending)) {
		/* The socket is already corked while preparing it. */
		/* ... which is an evident application bug. --ANK */
		release_sock(sk);

		net_dbg_ratelimited(KERN_DEBUG "udp cork app bug 2\n");
		err = -EINVAL;
		goto out;
	}

	up->pending = AF_INET6;

do_append_data:
	up->len += ulen;
	getfrag  =  is_udplite ?  udplite_getfrag : ip_generic_getfrag;
	err = chelsio_ip6_append_data(sk, getfrag, msg, ulen,
				      sizeof(struct udphdr), hlimit, tclass,
				      opt, &fl6, (struct rt6_info *)dst,
				      corkreq ? msg->msg_flags|MSG_MORE :
				      msg->msg_flags, dontfrag);
	if (err)
		chelsio_udp_v6_flush_pending_frames(sk);
	else if (!corkreq)
		err = chelsio_udp_v6_push_pending_frames(sk);
	else if (unlikely(skb_queue_empty(&cplios->tx_queue)))
		up->pending = 0;

	if (dst) {
		if (connected) {
			ip6_dst_store(sk, dst,
				      ipv6_addr_equal(&fl6.daddr, &inet6_sk_daddr(sk)) ?
				      &inet6_sk_daddr(sk) : NULL,
#ifdef CONFIG_IPV6_SUBTREES
				      ipv6_addr_equal(&fl6.saddr, &inet6_sk_saddr(sk)) ?
				      &inet6_sk_saddr(sk) :
#endif
				      NULL);
		} else {
			dst_release(dst);
		}
		dst = NULL;
	}

	if (err > 0)
		err = np->recverr ? net_xmit_errno(err) : 0;
	release_sock(sk);
out:
	dst_release(dst);
	fl6_sock_release(flowlabel);
	if (!err)
		return len;
	/*
	 * ENOBUFS = no kernel mem, SOCK_NOSPACE = no sndbuf space.  Reporting
	 * ENOBUFS might not be good (it's not tunable per se), but otherwise
	 * we don't have a good statistic (IpOutDiscards but it can be too many
	 * things).  We could add another new stat but at least for now that
	 * seems like overkill.
	 */
	if (err == -ENOBUFS || test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
		UDP6_INC_STATS_USER(sock_net(sk),
				UDP_MIB_SNDBUFERRORS, is_udplite);
	}
	return err;

do_confirm:
	dst_confirm(dst);
	if (!(msg->msg_flags&MSG_PROBE) || len)
		goto back_from_confirm;
	err = 0;
	goto out;
}

int udpv6offload_sendpage(struct sock *sk, struct page *page, int offset,
			  size_t size, int flags)
{
	return -EOPNOTSUPP;
}

void udpv6offload_destroy(struct sock *sk)
{
	int err;

	lock_sock(sk);
	chelsio_udp_v6_flush_pending_frames(sk);
	if (CPL_IO_STATE(sk)) {
		if (CPL_IO_STATE(sk)->tid) {
			err = send_uo_flowc_wr(sk, 1,
					       FW_FLOWC_MNEM_EOSTATE_CLOSING);
			BUG_ON(err < 0);
			cplios_set_flag(sk, CPLIOS_CLOSE_CON_REQUESTED);
			sock_hold(sk);
		} else
			t4_udp_release_resources(sk, 6);
	}
	release_sock(sk);
}
#endif /* CONFIG_UDPV6_OFFLOAD */

int udpoffload_sendpage(struct sock *sk, struct page *page, int offset,
				size_t size, int flags)
{
	return -EOPNOTSUPP;
}

void udpoffload_destroy(struct sock *sk)
{
	int err;

	lock_sock(sk);
	chelsio_udp_flush_pending_frames(sk);
	if (CPL_IO_STATE(sk)) {
		if (CPL_IO_STATE(sk)->tid) {
			err = send_uo_flowc_wr(sk, 1,
					       FW_FLOWC_MNEM_EOSTATE_CLOSING);
			BUG_ON(err < 0);
			cplios_set_flag(sk, CPLIOS_CLOSE_CON_REQUESTED);
			sock_hold(sk);
		} else
			t4_udp_release_resources(sk, 4);
	}
	release_sock(sk);
}

int udpoffload_setsockopt(struct sock *sk, int level, int optname,
				char __user *optval, unsigned int optlen)
{
	int val;
	struct cpl_io_state *cplios;

	/*
	 * We add new socket options for for getting pacing and segmenation
	 * parameters from the application.
	 */
	if (optname == UDP_SCHEDCLASS || optname == UDP_FRAMESIZE ||
	    optname == UDP_RTPHEADERLEN) {
		if (optlen < sizeof(int))
			return -EINVAL;

		if (get_user(val, (int __user *)optval))
			return -EFAULT;

		cplios =  CPL_IO_STATE(sk);
		if (!cplios) {
			/* Initialize cpl_io_state */
			cplios = kzalloc(sizeof *cplios, GFP_KERNEL);
			if (cplios == NULL)
				goto out_err;

			CPL_IO_STATE(sk) = cplios;
			sk->sk_prot = &udpoffload_prot;
		}

		if (optname == UDP_SCHEDCLASS) {
			/*
			 * Valid Scheduler Class values are:
			 *   val < 0: unbind the socket from any scheduling class
			 *   val < N: bind socket to indicated scheduling class
			 *
			 * Unfortunately N is dependent on the Offload Device
			 * and we can't check at this point ... we'll have to
			 * wait till we "bind" to an Offload Device ...
			 */
			if (val < 0)
				cplios->sched_cls = SCHED_CLS_NONE;
			else
				cplios->sched_cls = val;

			return 0;
		}

		if (optname == UDP_FRAMESIZE) {
			sk->sk_gso_type = val;
			return 0;
		}

		if (optname == UDP_RTPHEADERLEN) {
			cplios->rtp_header_len = val;
			return 0;
		}
	}

	return	orig_udp_prot.setsockopt(sk, level, optname, optval, optlen);

out_err:
	return -ENOMEM;
}

#ifdef CONFIG_UDPV6_OFFLOAD
int udpv6offload_setsockopt(struct sock *sk, int level, int optname,
			    char __user *optval, unsigned int optlen)
{
	int val;
	struct cpl_io_state *cplios;
	/*
	 * We add new socket options for for getting pacing and segmenation
	 * parameters from the application.
	 */
	if (optname == UDP_SCHEDCLASS || optname == UDP_FRAMESIZE ||
	    optname == UDP_RTPHEADERLEN) {
		if (optlen < sizeof(int))
			return -EINVAL;

		if (get_user(val, (int __user *)optval))
			return -EFAULT;
		cplios =  CPL_IO_STATE(sk);
		if (!cplios) {
			/* Initialize cpl_io_state */
			cplios = kzalloc(sizeof(struct cpl_io_state),
					 GFP_KERNEL);
			if (cplios == NULL)
				goto out_err;

			CPL_IO_STATE(sk) = cplios;
			sk->sk_prot = &udpv6offload_prot;
		}

		if (optname == UDP_SCHEDCLASS) {
			/*
			 * Valid Scheduler Class values are:
			 *   val < 0: unbind the socket from any scheduling class
			 *   val < N: bind socket to indicated scheduling class
			 *
			 * Unfortunately N is dependent on the Offload Device
			 * and we can't check at this point ... we'll have to
			 * wait till we "bind" to an Offload Device ...
			 */
			if (val < 0)
				cplios->sched_cls = SCHED_CLS_NONE;
			else
				cplios->sched_cls = val;

			return 0;

		}

		if (optname == UDP_FRAMESIZE) {
			sk->sk_gso_type = val;
			return 0;
		}

		if (optname == UDP_RTPHEADERLEN) {
			cplios->rtp_header_len = val;
			return 0;
		}
	}

	return	orig_udpv6_prot.setsockopt(sk, level, optname, optval, optlen);

out_err:
	return -ENOMEM;
}
#endif /* CONFIG_UDPV6_OFFLOAD */

#ifdef CONFIG_COMPAT
int compat_udpoffload_setsockopt(struct sock *sk, int level, int optname,
                          char __user *optval, unsigned int optlen)
{
	return orig_udp_prot.compat_setsockopt(sk, level, optname,
					       optval, optlen);
}

#ifdef CONFIG_UDPV6_OFFLOAD
int compat_udpv6offload_setsockopt(struct sock *sk, int level, int optname,
				   char __user *optval, unsigned int optlen)
{
	return orig_udpv6_prot.compat_setsockopt(sk, level, optname,
						 optval, optlen);
}
#endif /* CONFIG_UDPV6_OFFLOAD */
#endif

void __init udpoffload4_register(void)
{
	/*
	 * Grab a copy of the original system UDP Protocol structure so
	 * we can A. replace it when we unregister and B. initialize our
	 * Offloaded UDP Protocol with it's values and then substitutue in
	 * our Offload UDP Socket Operations.
	 */
	orig_udp_prot = udp_prot;
	udpoffload_prot  = udp_prot;
	strcpy(udpoffload_prot.name, "PACED-UDP");
	udpoffload_prot.setsockopt = udpoffload_setsockopt;
	udpoffload_prot.sendmsg = udpoffload_sendmsg;
	udpoffload_prot.sendpage = udpoffload_sendpage;
	udpoffload_prot.destroy = udpoffload_destroy;

	/*
	 * A UDP Socket becomes an Offloaded UDP Socket when it makes a
	 * setsockopt() call with one of our [hopefully] unique UDP Offload
	 * Socket Options.  So we interpose setsockopt() and if we get a
	 * request for an Offloaded UDP Socket Option, then we'll change
	 * the socket's Protocol Vector to our UDP Offload Vector above.
	 */
	udp_prot.setsockopt = udpoffload_setsockopt;
#ifdef CONFIG_COMPAT
	udp_prot.compat_setsockopt = compat_udpoffload_setsockopt;
#endif

#ifdef CONFIG_UDPV6_OFFLOAD
	/*
	 * Repeat the above steps for IPv6 UDP.
	 */
	orig_udpv6_prot = *udpv6_prot_p;
	udpv6offload_prot  = *udpv6_prot_p;
	strcpy(udpv6offload_prot.name, "PACED-UDPV6");
	udpv6offload_prot.setsockopt = udpv6offload_setsockopt;
	udpv6offload_prot.sendmsg = udpv6offload_sendmsg;
	udpv6offload_prot.sendpage = udpv6offload_sendpage;
	udpv6offload_prot.destroy = udpv6offload_destroy;

	udpv6_prot_p->setsockopt = udpv6offload_setsockopt;
#ifdef CONFIG_COMPAT
	udpv6_prot_p->compat_setsockopt = compat_udpv6offload_setsockopt;
#endif
#endif /* CONFIG_UDPV6_OFFLOAD */
	return;
}

void __exit udpoffload4_unregister(void)
{
	udp_prot = orig_udp_prot;
#ifdef CONFIG_UDPV6_OFFLOAD
	*udpv6_prot_p = orig_udpv6_prot;
#endif /* CONFIG_UDPV6_OFFLOAD */
}
