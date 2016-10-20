/*
 * kernel socket and Chelsio TOE driver support
 */
#include <linux/module.h>
#ifdef KERNEL_HAS_EXPORT_H
#include <linux/export.h>
#endif
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/ipv6.h>

#include <common/iscsi_common.h>
#include <common/iscsi_lib_export.h>
#include <common/iscsi_offload.h>
#include <common/iscsi_socket.h>
#include <common/cxgb_dev.h>
#include <kernel/linux_compat.h>
#if defined(__CH_DCB_SUPPORT__) && defined(CONFIG_DCB)
#include <net/dcbnl.h>
#endif
#include <kernel/os_socket.h>

#define __TCP_NAGLE_OFF__

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0) && !defined(RHEL7)
#define inet6_sk_saddr(__sk)		inet6_sk(__sk)->saddr
#define inet6_sk_rcv_saddr(__sk)	inet6_sk(__sk)->rcv_saddr
#define inet6_sk_daddr(__sk)		inet6_sk(__sk)->daddr
#else
#define inet6_sk_saddr(__sk)		inet6_sk(__sk)->saddr
#define inet6_sk_rcv_saddr(__sk)	(__sk)->sk_v6_rcv_saddr
#define inet6_sk_daddr(__sk)		(__sk)->sk_v6_daddr
#endif

#define sk_tx_closed(sk) \
	((sk)->sk_state == TCP_FIN_WAIT1 || \
	 (sk)->sk_state == TCP_FIN_WAIT2 || \
	 (sk)->sk_state == TCP_TIME_WAIT || \
	 (sk)->sk_state == TCP_CLOSE || \
	 (sk)->sk_state == TCP_LAST_ACK)
/* 
 *
 * iscsi_socket APIs
 * 
 */
static int os_sock_set_tcp_opt(os_socket * osock, int opt, int val)
{
	struct socket *sock = osock->sock;
	mm_segment_t fs;
	int     rv;

	fs = get_fs();
	set_fs(KERNEL_DS);
	rv = sock->ops->setsockopt(sock, SOL_TCP, opt, (void *) &val,
				   sizeof(int));
	set_fs(fs);

	return rv;
}

#if defined(__CH_DCB_SUPPORT__) && defined(CONFIG_DCB)
static int select_priority(int pri_mask)
{
        if (!pri_mask)
                return 0;

        /*
         * TODO: Configure priority selection from the mask
         * For now, just always take the highest
         */

        return (ffs(pri_mask) - 1);
}

int os_set_dcb_priority(os_socket * osock, struct net_device *netdev)
{
	struct socket *sock = osock->sock;
	struct dcb_app app;
	uint8_t caps;
	int rv, prio;

	if(!netdev)
		netdev = os_socket_netdev(osock->isock);

	if(!netdev) {
		os_log_warn("sock 0x%p, no netdev found!\n", sock);
		return -ENOENT;
	}
		
	/* dcb not supported */
	if(!netdev->dcbnl_ops) {
		os_log_info("sock 0x%p, %s no dcb support!\n",
			sock, netdev->name);
		rv = -EAGAIN;
		goto err_out;
	}

	rv = (int)netdev->dcbnl_ops->getcap(netdev, DCB_CAP_ATTR_DCBX, &caps);

	if(!rv) {
		/* check that we got one of the supported specs */
		if(!(caps & DCB_CAP_DCBX_VER_CEE) && !(caps & DCB_CAP_DCBX_VER_IEEE)) {
			os_log_info("sock 0x%p, %s dcb cap 0x%x, expect 0x%x|0x%x!\n",
				sock, netdev->name, caps,
				DCB_CAP_DCBX_VER_CEE, DCB_CAP_DCBX_VER_IEEE);
			goto out;
		}
	} else {
		os_log_info("sock 0x%p, %s dcb getcap returns %d!\n",
			sock, netdev->name, rv);
		rv = -EAGAIN;
		goto err_out;
	}

	app = (struct dcb_app) {
		.protocol = ISCSI_PORT_DEFAULT
	};

	if(caps & DCB_CAP_DCBX_VER_IEEE) {
		app.selector = IEEE_8021QAZ_APP_SEL_ANY;

		rv = dcb_ieee_getapp_mask(netdev, &app);
		prio = select_priority(rv);

		os_log_info("sock 0x%p, %s dcb IEEE, app.priority %d.\n",
			sock, netdev->name, prio);
	} else if (caps & DCB_CAP_DCBX_VER_CEE) {
		app.selector = DCB_APP_IDTYPE_PORTNUM;

		rv = dcb_getapp(netdev, &app);
		prio = select_priority(rv);

		os_log_info("sock 0x%p, %s dcb CEE, app.priority %d.\n",
			sock, netdev->name, prio);
	}

	os_log_debug(ISCSI_DBG_TRANSPORT,
		"Setting priority 0x%x on socket 0x%p.\n", prio, sock);

	rv = kernel_setsockopt(sock, SOL_SOCKET, SO_PRIORITY,
				(void *) &prio, sizeof(prio));
	if (rv)
		os_log_info("sock 0x%p, %s dcb set prio %d failed %d.\n",
			sock, netdev->name, prio, rv);
	else
		return 0;

err_out:
	if(rv == -EAGAIN)
		os_log_warn("DCBx negotiation incomplete or support unavailable for link. err : %d\n", rv);
	if(rv == -EINVAL)
		os_log_warn("Invalid DCBx parameters requested. err: %d\n", rv);

out:
	return rv;
}

int os_set_dcb_accept_priority(struct socket *lsock, struct socket *sock)
{
	int prio;

	if (!lsock || ! lsock->sk)
		return -1;

	prio = lsock->sk->sk_priority;

	return kernel_setsockopt(sock, SOL_SOCKET, SO_PRIORITY,
	                        (void *) &prio, sizeof(prio));
}
#endif /* __CH_DCB_SUPPORT__ */

int os_socket_display(iscsi_socket *isock, char *buf, int buflen)
{
	offload_device	*odev = isock->s_odev;

	if (odev && odev->sk_display)
		return odev->sk_display(isock, buf, buflen);
	return 0;
}

/*
 * allocation & release
 */
void os_socket_destroy(iscsi_socket * isock)
{
	os_socket *osock = (os_socket *) isock->s_private;

	if (!isock)
		return;

	os_log_info("%s: isock 0x%p, conn 0x%p, odev 0x%p, osock 0x%p, sock 0x%p.\n",
			__func__, isock, isock->s_appdata, isock->s_odev, osock,
			osock ? osock->sock : NULL);

	os_module_put(isock);

	if (osock) {
		struct socket *sock = osock->sock;

		if (sock) {
			struct sock *sk = sock->sk;

			sock_hold(sk);
			write_lock_bh(&sk->sk_callback_lock);
			sk->sk_user_data = NULL;
			isock->s_appdata = NULL;
			osock->sock = NULL;
			if (osock->orig_state_change)
				sk->sk_state_change = osock->orig_state_change;
			write_unlock_bh(&sk->sk_callback_lock);
			sock_put(sk);

			/* close socket */
			sock_release(sock);
		} 
	}

	if (isock->s_odev)
		((offload_device *)isock->s_odev)->dev_put(isock->s_odev);

	if (isock->s_pdu_data)
		kfree_skb(isock->s_pdu_data);

	os_free(isock);
}

void os_socket_release(iscsi_socket * isock)
{
	os_socket *osock = (os_socket *) isock->s_private;
	struct socket *sock = NULL;
	struct sock *sk = NULL;

	if (!isock)
		return;

	os_log_info("%s: 0x%p, conn 0x%p, odev 0x%p, osock 0x%p, sock 0x%p.\n",
		__func__, isock, isock->s_appdata, isock->s_odev, osock,
		osock ? osock->sock : NULL);

	if (osock) {
		struct sk_buff *skb = osock->skb_head;

		sock = osock->sock;
		if (sock) {
			sk = sock->sk;

			sock_hold(sk);
			write_lock_bh(&sk->sk_callback_lock);
			/* keep the state_change() around so we know when
 			 * the tcp is really closed on tx/rx */
			if (osock->orig_data_ready)
				sk->sk_data_ready = osock->orig_data_ready;
			if (osock->orig_write_space)
				sk->sk_write_space = osock->orig_write_space;
			write_unlock_bh(&sk->sk_callback_lock);
			sock_put(sk);

			if (isock->s_flag & ISCSI_SOCKET_RST) {
				/* send RST instead of FIN */
				sock_set_flag(sk, SOCK_LINGER);
				sk->sk_lingertime = 0;
			}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
			kernel_sock_shutdown(sock, SHUT_RDWR);
#else
			sock->ops->shutdown(sock, SEND_SHUTDOWN|RCV_SHUTDOWN);
#endif
		} 

		skb = osock->skb_head;
		osock->skb_head = osock->skb_tail = NULL;
		while (skb) {
			struct sk_buff *next = skb->next;

			skb->next = NULL;
			/* premapped frags */
			if (skb->destructor) {
				offload_device *odev = isock->s_odev;

				odev->skb_reset_premapped_sgl(skb);
			}
			__kfree_skb(skb);
			skb = next;
		}

		skb = osock->rcb.skb;
		osock->rcb.skb = NULL;
		if (skb)
			__kfree_skb(skb);
	}

	if (sk && sk_tx_closed(sk)) {
		isock->s_flag |= ISCSI_SOCKET_TX_CLOSED;	
		iscsi_socket_state_change(isock);
	}
}

static inline iscsi_socket *socket_alloc(void)
{
	iscsi_socket *isock;
	os_socket *osock;

	isock = os_alloc(sizeof(iscsi_socket) + sizeof(os_socket), 1, 1);
	if (!isock)
		return NULL;
	/* os_alloc does memset() */

	osock = isock->s_private = (void *)(isock + 1);
	isock->s_mode = ISCSI_OFFLOAD_MODE_NIC;
	isock->sk_read_pdu_header = os_sock_read_pdu_header_nic;
	isock->sk_read_pdu_data = os_sock_read_pdu_data_nic;
	isock->sk_write_pdus = os_sock_write_pdus_nic;
	isock->s_cpuno = num_possible_cpus();

	return isock;
}

/*
 *  socket callbacks
 */
void os_sock_write_space(struct sock *sk)
{
	iscsi_socket *isock = (iscsi_socket *) sk->sk_user_data;

	os_log_debug(ISCSI_DBG_TRANSPORT,
		     "sk 0x%p write space, isock 0x%p, osock 0x%p, conn 0x%p.\n",
		     sk, isock,
		     isock ? isock->s_private : NULL,
		     isock ? isock->s_appdata : NULL);

	if (isock) {
		os_socket *osock = (os_socket *) isock->s_private;
		if (osock) {
			if (osock->orig_write_space &&
			    (osock->orig_write_space != os_sock_write_space))
				osock->orig_write_space(sk);

			iscsi_socket_write_space(isock, 0);
		}
	}
}
EXPORT_SYMBOL(iscsi_socket_write_space);

/* the sk_data_ready callback could be called twice when a new connection is
 * being established as a child socket inherits everything from a parent
 * LISTEN socket, including the data_ready the parent. */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
static void os_sock_listen_data_ready(struct sock *sk)
#else
static void os_sock_listen_data_ready(struct sock *sk, int bytes)
#endif
{
	iscsi_socket *isock;

	read_lock(&sk->sk_callback_lock);
	isock = (iscsi_socket *) sk->sk_user_data;

	os_log_debug(ISCSI_DBG_TRANSPORT,
		     "sk 0x%p data ready, isock 0x%p, osock 0x%p, conn 0x%p.\n",
		     sk, isock,
		     isock ? isock->s_private : NULL,
		     isock ? isock->s_appdata : NULL);

	if ((sk->sk_state == TCP_LISTEN) && isock)
		iscsi_socket_data_ready(isock);

	read_unlock(&sk->sk_callback_lock);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
static void os_child_sock_data_ready(struct sock *sk)
#else
static void os_child_sock_data_ready(struct sock *sk, int bytes)
#endif
{
	iscsi_socket *isock;

	read_lock(&sk->sk_callback_lock);
	isock = (iscsi_socket *) sk->sk_user_data;

	os_log_debug(ISCSI_DBG_TRANSPORT,
		     "sk 0x%p data ready, isock 0x%p, osock 0x%p, conn 0x%p.\n",
		     sk, isock,
		     isock ? isock->s_private : NULL,
		     isock ? isock->s_appdata : NULL);

	if (isock && (sk->sk_state == TCP_ESTABLISHED))
		iscsi_socket_data_ready(isock);
	read_unlock(&sk->sk_callback_lock);
}

static void os_sock_state_change(struct sock *sk)
{
	iscsi_socket *isock;

	read_lock(&sk->sk_callback_lock);
	isock = (iscsi_socket *) sk->sk_user_data;

	//os_log_debug(ISCSI_DBG_TRANSPORT,
	os_log_info(
		     "sk 0x%p state change 0x%x, 0x%p, 0x%p, 0x%p.\n",
		     sk, sk->sk_state, isock, isock ? isock->s_private : NULL,
		     isock ? isock->s_appdata : NULL);

	if (isock) {
		os_socket *osock = (os_socket *) isock->s_private;
		if (osock) {
			if (osock->orig_state_change &&
			    (osock->orig_state_change != os_sock_state_change))
				osock->orig_state_change(sk);

			if (sk->sk_state != TCP_ESTABLISHED) {
				if (sk_tx_closed(sk))
					isock->s_flag |= ISCSI_SOCKET_TX_CLOSED;	
				isock->s_flag |= ISCSI_SOCKET_NO_TX;
				os_log_info("%s: isock 0x%p, f 0x%x, sk 0x%p,"
					"%u, f 0x%x.\n",
					__func__, isock, isock->s_flag, sk,
					sk->sk_state, sk->sk_flags);
				iscsi_socket_state_change(isock);
			}
		}
	}
	read_unlock(&sk->sk_callback_lock);
}

/*
 * socket operations: listen/connection/accept/close
 */
#if defined(__CH_DCB_SUPPORT__) && defined(CONFIG_DCB)
struct net_device *os_find_netdev_by_ipv4(__be32);
#endif
struct net_device * os_find_netdev_by_ipv6(struct in6_addr *addr, int check_lladdr);

/* appdata should be iscsi_connection */
iscsi_socket *os_socket_listen(struct tcp_endpoint *ep, int backlog)
{
	iscsi_socket *isock = NULL;
	os_socket *osock = NULL;
	struct socket *sock = NULL;
	struct net_device *ndev = NULL;
	int family;
	int     rv = 0,i;
	char tbuf[80];

	tcp_endpoint_sprintf(ep, tbuf);

	if (tcp_endpoint_is_ipv6(ep)) {
		struct sockaddr_in6 saddr6;
		unsigned int *ip = (unsigned int *)ep->ip;

		rv = sock_create_kern(PF_INET6, SOCK_STREAM, IPPROTO_TCP, &sock);
		if (rv < 0) {
			os_log_error("sock create ipv6 %s failed %d.\n",
					tbuf, rv);
			return NULL;
		}

		family = saddr6.sin6_family = AF_INET6;
		for(i = 0; i < 4; i++)
			saddr6.sin6_addr.s6_addr32[i] = ip[i];
		saddr6.sin6_port = htons(ep->port);

#if defined(__CH_DCB_SUPPORT__) && defined(CONFIG_DCB)
		ndev = os_find_netdev_by_ipv6(&saddr6.sin6_addr, 0);
#endif
		/* IPv6 link-local addresses need scope resolution */
		if ((ipv6_addr_type(&saddr6.sin6_addr) & IPV6_ADDR_LINKLOCAL)) {
			if (!ndev)
				ndev = os_find_netdev_by_ipv6(&saddr6.sin6_addr, 1);

			if (ndev)
				saddr6.sin6_scope_id = ndev->ifindex;
			else
				os_log_warn(
					    "scope resolution for link-local address %pI6 failed, bind will not succeed\n",
					    &saddr6.sin6_addr);
		}
			
		sock->sk->sk_reuse = 1;
		rv = sock->ops->bind(sock, (struct sockaddr *) &saddr6 ,
			     sizeof(struct sockaddr_in6));
		if (rv < 0) {
			os_log_error("sock bind ipv6 failed, %s, %d.\n",
					tbuf, rv);
			goto err_out;
		}
	} else {
		struct sockaddr_in saddr;

		rv = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
		if (rv < 0) {
			os_log_error("sock create ipv4 %s failed %d.\n",
					tbuf, rv);
			return NULL;
		}

		family = saddr.sin_family = AF_INET;
		saddr.sin_addr.s_addr = *((unsigned int *)
					(ep->ip + ISCSI_IPADDR_IPV4_OFFSET));
        	saddr.sin_port = htons(ep->port);

#if defined(__CH_DCB_SUPPORT__) && defined(CONFIG_DCB)
		/* dcbx, need to get the priority from the net_device */
		ndev = os_find_netdev_by_ipv4(saddr.sin_addr.s_addr);
#endif
 
		sock->sk->sk_reuse = 1;
		rv = sock->ops->bind(sock, (struct sockaddr *)&saddr,
					sizeof(struct sockaddr));
		if (rv < 0) {
			os_log_error("sock bind ipv4 failed, %s, %d.\n",
					tbuf, rv);
			goto err_out;
		}
	}

	rv = sock->ops->listen(sock, backlog);
	if (rv < 0) {
		os_log_error("sock listen failed %s, %d.\n", tbuf, rv);
		goto err_out;
	}

	/* FIXME!*/
	sock_set_flag(sock->sk, 30/* SOCK_NO_DDP */);

	isock = socket_alloc();
	if (!isock)
		goto err_out;

	osock = (os_socket *) isock->s_private;
	osock->sock = sock;

	memcpy(&isock->s_tcp.taddr, ep, sizeof(struct tcp_endpoint));
	isock->s_tcp.f_ipv6 = family == AF_INET6 ? 1 : 0;

#if defined(__CH_DCB_SUPPORT__) && defined(CONFIG_DCB)
	os_set_dcb_priority(osock, ndev);
#endif

	os_log_debug(ISCSI_DBG_TRANSPORT,
		     "listen isock 0x%p, 0x%p, sock 0x%p, sk 0x%p, ipv6 %d.\n",
		     isock, osock, sock, sock ? sock->sk : NULL,
		     family == AF_INET ? 0 : 1);

	write_lock_bh(&sock->sk->sk_callback_lock);
	osock->orig_data_ready = sock->sk->sk_data_ready;
	sock->sk->sk_user_data = isock;
	sock->sk->sk_data_ready = os_sock_listen_data_ready;
	write_unlock_bh(&sock->sk->sk_callback_lock);

	os_log_info("listening server started %s.\n", tbuf);

	os_module_get(isock);

	return isock;

err_out:
	if (isock) {
		os_socket_release(isock);
		os_socket_destroy(isock);
	} else if (sock)
		sock_release(sock);
	return NULL;
}

int os_socket_accept(iscsi_socket * listen_isock, void *newconn,
			iscsi_socket **isock_pp)
{
	int  rv = 0;
	char tbuf[100];
	os_socket *losock = (os_socket *) listen_isock->s_private;
	struct socket *lsock = losock->sock;
	iscsi_socket *isock = NULL;
	os_socket *osock = NULL;
	struct socket *sock = NULL;

	if (listen_isock->s_tcp.f_ipv6)
		rv = sock_create_kern(PF_INET6, SOCK_STREAM, IPPROTO_TCP, &sock);
	else
		rv = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	if (rv < 0) {
		os_log_error("%s: sock create, %d.\n", __func__, rv);
		return rv;
	}

	sock->type = lsock->type;
	sock->ops = lsock->ops;

	rv = lsock->ops->accept(lsock, sock, O_NONBLOCK);
	if (rv < 0 || !sock->sk) {
		if (rv != -EAGAIN)
			os_log_info("%s: accept return %d, sk 0x%p.\n",
				 __func__, rv, sock->sk);
		goto free_sock;
	}

	write_lock_bh(&sock->sk->sk_callback_lock);
	sock->sk->sk_user_data = NULL;
	sock->sk->sk_data_ready = losock->orig_data_ready;
	write_unlock_bh(&sock->sk->sk_callback_lock);

	lock_sock(sock->sk);
	if (sock->sk->sk_state != TCP_ESTABLISHED) {
		release_sock(sock->sk);
		os_log_info("%s: sk 0x%p tcp closed, state=0x%x.\n",
				__func__, sock->sk, sock->sk->sk_state);
		rv = 0;
		goto free_sock;
	}
	release_sock(sock->sk);

	isock = socket_alloc();
	if (!isock) {
		os_log_info("%s: sk 0x%p, isock OOM.\n", __func__, sock->sk);
		rv = -ISCSI_ENOMEM;
		goto free_sock;
	}

	osock = isock_2_osock(isock);
	osock->isock = isock;

	//os_log_debug(ISCSI_DBG_TRANSPORT,
	os_log_info(
		"%s: 0x%p, sock 0x%p, 0x%p, 0x%p, 0x%p, conn 0x%p.\n",
		__func__, listen_isock, isock, osock, sock, sock->sk, newconn);

	osock->sock = sock;

	if (listen_isock->s_tcp.f_ipv6) {
#ifdef CHISCSI_IPV6_SUPPORT
		memcpy(isock->s_tcp.iaddr.ip,
			inet6_sk_daddr(sock->sk).s6_addr32, ISCSI_IPADDR_LEN);
		isock->s_tcp.f_ipv6 = 1;
#else
		/* If ipv6 is not supported sock creation
		 * should fail and we should not reach here.
		 */
		rv = -ISCSI_ENOTSUPP;
		os_log_error("%s: ipv6 is not supported \n", __func__);
		goto free_sock;
#endif
	} else {
		unsigned int *addr;

		ipaddr_mark_as_ipv4(isock->s_tcp.iaddr.ip);

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
		addr = (unsigned int *)(isock->s_tcp.iaddr.ip +
					ISCSI_IPADDR_IPV4_OFFSET);
		*addr = inet_sk(sock->sk)->inet_daddr;
#else
		addr = (unsigned int *)(isock->s_tcp.iaddr.ip +
					ISCSI_IPADDR_IPV4_OFFSET);
		*addr = inet_sk(sock->sk)->daddr;
#endif
	}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
	isock->s_tcp.iaddr.port = ntohs(inet_sk(sock->sk)->inet_dport);
#else
	isock->s_tcp.iaddr.port = ntohs(inet_sk(sock->sk)->dport);
#endif
	memcpy(&isock->s_tcp.taddr, &listen_isock->s_tcp.taddr,
		sizeof(struct tcp_endpoint));
	chiscsi_tcp_endpoints_sprintf(&isock->s_tcp, tbuf);
	os_log_info("%s: ipv%c sock 0x%p, %s.\n",
		__func__, isock->s_tcp.f_ipv6 ? '6' : '4', isock, tbuf);

	os_sock_offload_info(isock);
	osock->odev = isock->s_odev;
	if (isock->s_odev) {
		os_log_info("%s: isock 0x%p set toe ddp off, odev 0x%p.\n",
				__func__, isock, isock->s_odev);
		((offload_device *)isock->s_odev)->sk_ddp_off(sock->sk);
		((offload_device *)isock->s_odev)->dev_get(isock->s_odev);
	}
	os_module_get(isock);

	write_lock_bh(&sock->sk->sk_callback_lock);
	isock->s_appdata = newconn;
	osock->orig_state_change = sock->sk->sk_state_change;
	osock->orig_data_ready = sock->sk->sk_data_ready;
	osock->orig_write_space = sock->sk->sk_write_space;

	sock->sk->sk_user_data = isock;
	sock->sk->sk_state_change = os_sock_state_change;
	sock->sk->sk_data_ready = os_child_sock_data_ready;
	sock->sk->sk_write_space = os_sock_write_space;
	write_unlock_bh(&sock->sk->sk_callback_lock);

	/* check one more time: will not get a state change notification if
	 * the state changed between the time of being accepted and now */
	lock_sock(sock->sk);
	if (sock->sk->sk_state != TCP_ESTABLISHED) {
		release_sock(sock->sk);
		os_log_info("%s: isock 0x%p, sk 0x%p tcp closed %d.\n",
			__func__, isock, sock->sk, sock->sk->sk_state);
		rv = 0;
		goto free_sock;
	}
	release_sock(sock->sk);

#ifdef __TCP_NAGLE_OFF__
	rv = os_sock_set_tcp_opt(osock, TCP_NODELAY, 1);
#endif

#if defined(__CH_DCB_SUPPORT__) && defined(CONFIG_DCB)
	rv = os_set_dcb_accept_priority(lsock, sock);
	if (rv)
		os_log_info("%s: could not set DCB priority %u on sk 0x%p\n",
			    __func__, lsock->sk->sk_priority, sock->sk);
#endif
	*isock_pp = isock;
	return 1;

free_sock:
	if (isock) {
		os_socket_release(isock);
		os_socket_destroy(isock);
	} else if (sock) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
		kernel_sock_shutdown(sock, SHUT_RDWR);
#else
		sock->ops->shutdown(sock, SEND_SHUTDOWN|RCV_SHUTDOWN);
#endif
		sock_release(sock);
	}

	return rv;
}


/*
 * Other Socket related APIs
 */
#ifndef _VLAN_DEV_API_
#ifdef VLAN_DEV_INFO
static inline struct vlan_dev_info *vlan_dev_info(const struct net_device *dev)
{
	return VLAN_DEV_INFO(dev);
}
#endif

static inline struct net_device *vlan_dev_real_dev(const struct net_device *dev)
{
	return vlan_dev_info(dev)->real_dev;
}
#endif /* _VLAN_DEV_API_ */

void   *os_socket_netdev(iscsi_socket * isock)
{
	struct socket *sock = NULL;
	struct dst_entry *dst = NULL;
	struct net_device *ndev = NULL;

	if (isock) {
		sock = ((os_socket *) isock->s_private)->sock;
		if (sock && sock->sk) {
			dst = sk_dst_get(sock->sk);
			if (dst) {
				ndev = dst->dev;
				dst_release(dst);

				if (ndev->priv_flags & IFF_802_1Q_VLAN)
					ndev = vlan_dev_real_dev(ndev);
				return ((void *)ndev);
			}
		}
	}
	os_log_info("sock 0x%p,0x%p,0x%p, dst 0x%p, nd 0x%p, %s.\n",
			isock, sock, sock ? sock->sk : NULL, dst, ndev,
			ndev ? ndev->name : "?");	
	return NULL;
}

int os_socket_set_offload_mode(iscsi_socket *isock, unsigned char mode,
				unsigned char hcrc, unsigned char dcrc,
				unsigned int difdix_mode)
{
	offload_device	*odev = isock->s_odev;
	unsigned char t10dif = 0;

	os_log_info("isock 0x%p, mode 0x%x, hcrc 0x%x, dcrc 0x%x, "
		"isock->s_flag 0x%x " "difdix_mode 0x%x\n",
		isock, mode, hcrc, dcrc, isock->s_flag, difdix_mode);

	isock->s_hcrc_len = hcrc;
	isock->s_dcrc_len = dcrc;

	if ((mode & ISCSI_OFFLOAD_MODE_T10DIX) &&
	    odev && odev->d_flag & ODEV_FLAG_ULP_T10DIF_ENABLED) {
		t10dif = difdix_mode;
		os_log_info("isock 0x%p, enabling t10dif mode 0x%x\n",
			isock, t10dif);
	}

	if (!odev || !(isock->s_flag & ISCSI_SOCKET_OFFLOADED)) {
		isock->s_mode = ISCSI_OFFLOAD_MODE_NIC;
		return isock->s_mode;
	}
		
	if ((mode & ISCSI_OFFLOAD_MODE_ULP) && 
	    (odev->d_flag & ODEV_FLAG_ULP_CRC_ENABLED || t10dif)) {
		int rv = odev->sk_set_ulp_mode(isock, hcrc, dcrc,
						t10dif);
		if (!rv)
			isock->s_mode = mode & ISCSI_OFFLOAD_MODE_ULP;
		else {
			os_log_info("isock 0x%p, ulp %d, revert to toe mode.\n",
				isock, rv);	
			isock->s_mode = mode & ISCSI_OFFLOAD_MODE_TOE;
		}
	}

	if (isock->s_mode & ISCSI_OFFLOAD_MODE_ULP) {
		isock->sk_read_pdu_header = odev->isock_read_pdu_header_ulp;
		isock->sk_read_pdu_data = odev->isock_read_pdu_data_ulp;
		if (t10dif) {
			isock->sk_read_pdu_pi = odev->isock_read_pdu_pi_ulp;
			isock->s_mode |= ISCSI_OFFLOAD_MODE_T10DIX;
		}
		isock->sk_write_pdus = odev->isock_write_pdus_ulp;

		if ((isock->s_mode & ISCSI_OFFLOAD_MODE_DDP) &&
		    !(odev->d_flag & ODEV_FLAG_ULP_DDP_ENABLED))
			isock->s_mode &= ~ISCSI_OFFLOAD_MODE_DDP;

		if (isock->s_flag & ISCSI_SOCKET_QUICKACK)
			os_sock_set_tcp_opt((os_socket *)isock->s_private,
					TCP_QUICKACK, 1);
	}

	os_log_info( "isock 0x%p,0x%x offload mode 0x%x -> 0x%x.\n",
		isock, isock->s_flag, mode, isock->s_mode);
	/* if going to ULP mode, hold tx */
	if (!(isock->s_mode & ISCSI_OFFLOAD_MODE_ULP))
		iscsi_socket_write_space(isock, 0);

	return isock->s_mode;
}

int os_socket_get_tcp_seq(iscsi_socket *isock, unsigned int *snd_nxt)
{
	struct socket *sock = ((os_socket *) isock->s_private)->sock;

	if (sock && sock->sk) {
		struct sock *sk = sock->sk;
		struct tcp_sock *tp = tcp_sk(sk);
		*snd_nxt = tp->snd_nxt;
	}
	return 0;
}

void * os_socket_get_offload_pci_device(iscsi_socket *isock)
{
	offload_device	*odev = isock->s_odev;

	return odev ? odev->d_pdev : NULL;
}

/*
 *
 * Init & Cleanup
 *
 */
//void os_netdev_event_subscribe(void);
//void os_netdev_event_unsubscribe(void);

struct page *dummy_page = NULL;
unsigned char *dummy_page_addr = NULL;

/*
 * rsvd page #1: for padding bytes in zero copy tx path
 * rsvd page #2: for ddp pagepod to fill the xfer offset
 */
#define RSVD_PAGE_MAX	2
struct page *rsvd_pages[RSVD_PAGE_MAX] = {NULL, NULL};
unsigned char *rsvd_pages_addr[RSVD_PAGE_MAX] = {NULL, NULL};

void os_transport_cleanup(void)
{
	int i;

//	os_netdev_event_unsubscribe();
	offload_device_cleanup();	
	if (dummy_page) {
		os_free_one_page(dummy_page);
		dummy_page = NULL;
	}

	for (i = 0; i < RSVD_PAGE_MAX; i++)
		if (rsvd_pages[i]) {
			os_free_one_page(rsvd_pages[i]);
			rsvd_pages[i] = NULL;
		}
}

int os_transport_init(void)
{
	int i, rv;

#if defined(__CH_DCB_SUPPORT__) && defined(CONFIG_DCB)
	os_log_info("DCBx support enabled %s.\n", NULL);
#endif
	dummy_page = (struct page *)(os_alloc_one_page(1, &dummy_page_addr));
	if (!dummy_page)
		return -ISCSI_ENOMEM;

	for (i = 0; i < RSVD_PAGE_MAX; i++) {
		rsvd_pages[i] = (struct page *)(os_alloc_one_page(1,
						&rsvd_pages_addr[i]));
		memset(rsvd_pages_addr[i], 0, os_page_size);
		if (!rsvd_pages[i])
			return -ISCSI_ENOMEM;
	}

	rv = offload_device_init();

//	os_netdev_event_subscribe();
	return rv;
}

EXPORT_SYMBOL(iscsi_display_byte_string);
