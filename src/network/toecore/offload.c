/*
 * TCP offload support.
 *
 * Copyright (C) 2003-2008 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifdef  LINUX_2_4
#include <linux/stddef.h>
#include <linux/netdevice.h>
#endif  /* LINUX_2_4 */
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/toedev.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/offload.h>
#include <linux/if_vlan.h>

#include "toe_compat.h"

#ifndef RAW_NOTIFIER_HEAD
# define RAW_NOTIFIER_HEAD(name) struct notifier_block *name
# define raw_notifier_call_chain notifier_call_chain
# define raw_notifier_chain_register notifier_chain_register
# define raw_notifier_chain_unregister notifier_chain_unregister
#endif

static DEFINE_MUTEX(notify_mutex);
static RAW_NOTIFIER_HEAD(listen_offload_notify_list);

int register_listen_offload_notifier(struct notifier_block *nb)
{
	int err;

	mutex_lock(&notify_mutex);
	err = raw_notifier_chain_register(&listen_offload_notify_list, nb);
	mutex_unlock(&notify_mutex);
	return err;
}
EXPORT_SYMBOL(register_listen_offload_notifier);

int unregister_listen_offload_notifier(struct notifier_block *nb)
{
	int err;

	mutex_lock(&notify_mutex);
	err = raw_notifier_chain_unregister(&listen_offload_notify_list, nb);
	mutex_unlock(&notify_mutex);
	return err;
}
EXPORT_SYMBOL(unregister_listen_offload_notifier);

#if defined(CONFIG_TCP_OFFLOAD) || \
    (defined(CONFIG_TCP_OFFLOAD_MODULE) && defined(MODULE))

static inline int connect_if_module_live(struct toedev *dev,
					struct sock *sk, struct net_device *netdev)
{
	struct tom_info *mod = dev->offload_mod;

	if (module_is_live(mod->owner)) {
		if (!module_refcount(mod->owner)) {
			if (atomic_inc_return(&mod->refcnt) == 1)
				__module_get(mod->owner);
			else
				atomic_dec(&mod->refcnt);
		}
		if (dev->connect(dev, sk, netdev) == 0) {
			offload_socket_ops(sk);
			return 1;
		}
		return 0;
	}
	rcu_read_unlock();
	return 0;
}

/*
 * Called when an active open has been requested through connect(2).  Decides
 * if the connection may be offloaded based on the system's offload policies
 * and the capabilities of the egress interface.
 *
 * Returns 1 if the connection is offloaded and 0 otherwise.
 */
int tcp_connect_offload(struct sock *sk)
{
	struct net_device *netdev = __sk_dst_get(sk)->dev;

	rcu_read_lock();
	if (netdev_is_offload(netdev)) {
		struct toedev *dev = TOEDEV(netdev);

		if (!dev || !rcu_access_pointer(dev->can_offload)) {
			rcu_read_unlock();
			return 0;
		}
		if (!dev->can_offload(dev, sk)) {
			rcu_read_unlock();
			return 0;
		}
		if (!dev->offload_mod) {
			if (dev->connect(dev, sk, netdev) == 0) {
				offload_socket_ops(sk);
				return 1;
			}
			return 0;
		}
		return connect_if_module_live(dev, sk, netdev);
	}
	rcu_read_unlock();
	return 0;
}
EXPORT_SYMBOL(tcp_connect_offload);

/*
 * TOE capable backlog handler.  This is used for offloaded listening sockets
 * so they can deal with non-IP (TOE) packets queued in their backlogs.  We
 * distinguish TOE from IP packets easily as the former lack network headers.
 * Such TOE packets are fed to a TOE-specific backlog handler.
 */
static int listen_backlog_rcv(struct sock *sk, struct sk_buff *skb)
{
	if (likely(skb_transport_header(skb) != skb_network_header(skb)))
		return tcp_v4_do_rcv(sk, skb);
	BLOG_SKB_CB(skb)->backlog_rcv(sk, skb);
	return 0;
}

static int locally_bound_v4(const struct sock *sk)
{
#ifdef	LINUX_2_4
	return LOOPBACK(sk->inet_rcv_saddr) ? 1 : 0;
#else
	return ipv4_is_loopback(inet_sk(sk)->inet_rcv_saddr) ? 1 : 0;
#endif	/* LINUX_2_4 */
}

/*
 * Called when the SW stack has transitioned a socket to listen state.
 * We check if the socket should be offloaded according to the current
 * offloading policies, and if so, publish an OFFLOAD_LISTEN_START event.
 */
int start_listen_offload(struct sock *sk)
{
	if (sk->sk_protocol != IPPROTO_TCP)
		return -EPROTONOSUPPORT;

	// filter out loopback listens
	if ((sk->sk_family == PF_INET) && locally_bound_v4(sk))
		return -EADDRNOTAVAIL;

	// Install a TOE capable backlog handler
	sk->sk_backlog_rcv = listen_backlog_rcv;

	// if needed install offload-capable socket ops
	offload_socket_ops(sk);

	mutex_lock(&notify_mutex);
	raw_notifier_call_chain(&listen_offload_notify_list,
				OFFLOAD_LISTEN_START, sk);
	mutex_unlock(&notify_mutex);
	return 0;
}
EXPORT_SYMBOL(start_listen_offload);

/*
 * Called when the SW stack is preparing to close an existing listening socket.
 * We publish an OFFLOAD_LISTEN_STOP event.
 */
int stop_listen_offload(struct sock *sk)
{
	if (sk->sk_protocol != IPPROTO_TCP)
		return -EPROTONOSUPPORT;

	mutex_lock(&notify_mutex);
	raw_notifier_call_chain(&listen_offload_notify_list,
				OFFLOAD_LISTEN_STOP, sk);
	mutex_unlock(&notify_mutex);
	return 0;
}
EXPORT_SYMBOL(stop_listen_offload);

void walk_listens(void *handle, int (*func)(void *handle, struct sock *sk))
{
#if 0
	/*
	 * Offloading existing listeners doesn't work in all configurations.
	 * Rather than try to confuse customers by describing when this can be
	 * done, we simply disable this code by default and tell customers
	 * that they will need to restart any services which they want
	 * offloaded _after_ the offload driver is installed.
	 */
	int i;
	struct sock *sk;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,28)
	struct inet_listen_hashbucket *ilb;
	struct hlist_nulls_node *node;

	mutex_lock(&notify_mutex);

	for (i = 0; i < INET_LHTABLE_SIZE; i++) {
		ilb = &tcp_hashinfo.listening_hash[i];
		spin_lock(&ilb->lock);
		sk_nulls_for_each(sk, node, &ilb->head) {
			if (sk->sk_family == PF_INET && locally_bound_v4(sk))
				continue;
			if (func(dev, sk) < 0) {
				spin_unlock(&ilb->lock);
				goto out;
			}
		
		}
		spin_unlock(&ilb->lock);
	}
out:
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2,6,13)
	struct hlist_node *node;

	mutex_lock(&notify_mutex);
	inet_listen_lock(&tcp_hashinfo);

	for (i = 0; i < INET_LHTABLE_SIZE; i++)
		sk_for_each(sk, node, &tcp_hashinfo.listening_hash[i]) {
			if (sk->sk_family == PF_INET && locally_bound_v4(sk))
				continue;
			if (func(handle, sk) < 0)
				goto out;
		}

out:	inet_listen_unlock(&tcp_hashinfo);
#else
	struct hlist_node *node;

	mutex_lock(&notify_mutex);
	tcp_listen_lock();

	for (i = 0; i < TCP_LHTABLE_SIZE; i++)
		sk_for_each(sk, node, &tcp_listening_hash[i]) {
			if (sk->sk_family == PF_INET && locally_bound_v4(sk))
				continue;
			if (func(dev, sk) < 0)
				goto out;
		}

out:	tcp_listen_unlock();
#endif
	mutex_unlock(&notify_mutex);
#endif /* CONFIG_CHELSIO_OFFLOAD_EXISTING_LISTENERS */
}
EXPORT_SYMBOL(walk_listens);

static int run_opt_classifier(const struct offload_policy *h,
			      const struct offload_req *req)
{
	const u32 *r = (const u32 *)req;
	const u32 *ip = h->opt_prog_start;  /* instruction pointer */

	while (1) {
		int off = ip[0] & 0xffff;
		u32 data = r[off] & ip[3];
		const u32 *vals = ip + 4;

		for (off = ip[0] >> 16; off; off--, vals++)
			if (*vals == data) {
				off = ip[2];
				goto next;
			}
		off = ip[1];
next:
		if (off <= 0)
			return -off;
		ip += off;
	}
}

/*
 * Note that the caller is responsible to call rcu_read_unlock().
 * linux-2.4: the caller is responsible to call read_unlock()
 */
const struct offload_settings *lookup_ofld_policy(const struct toedev *dev,
						  const struct offload_req *req,
						  int cop_managed_offloading)
{
	static struct offload_settings allow_offloading_settings = {
		1, -1, -1, -1, QUEUE_RANDOM, -1, -1, -1
	};
	static struct offload_settings disallow_offloading_settings = {
		0, -1, -1, -1, -1, -1, -1, -1
	};

	int match;
	const struct offload_policy *policy;

#ifndef LINUX_2_4
	policy = rcu_dereference(dev->policy);
#else
	read_lock(&dev->policy_lock);
	policy = dev->policy;
#endif
	/*
	 * If there's no Connection Offloading Policy attached to the device
	 * then we need to return a default static policy.  If
	 * "cop_managed_offloading" is true, then we need to disallow
	 * offloading until a COP is attached to the device.  Otherwise we
	 * allow offloading ...
	 */
	if (!policy)
		return (cop_managed_offloading
			? &disallow_offloading_settings
			: &allow_offloading_settings);
	if (policy->match_all >= 0)
		match = policy->match_all;
	else
		match = run_opt_classifier(policy, req);
	return &policy->settings[match];
}
EXPORT_SYMBOL(lookup_ofld_policy);

void offload_req_from_sk(struct offload_req *req, struct sock *sk, int otype)
{
	const struct dst_entry *dst;
	const struct net_device *ndev;

	dst = __sk_dst_get(sk);
	if (sk->sk_family == AF_INET) {
#ifndef LINUX_2_4
		req->sip[0] = inet_sk(sk)->inet_rcv_saddr;
#else
		req->sip[0] = sk->inet_rcv_saddr;
#endif
		req->sip[1] = req->sip[2] = req->sip[3] = 0;
#ifndef LINUX_2_4
		req->dip[0] = inet_sk(sk)->inet_daddr;
#else
		req->dip[0] = sk->inet_daddr;
#endif
		req->dip[1] = req->dip[2] = req->dip[3] = 0;
	}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else {
		int i;

		for (i=0; i < ARRAY_SIZE(req->sip); i++) {
			req->sip[i] = inet6_sk_rcv_saddr(sk).s6_addr32[i];
			req->dip[i] = inet6_sk_daddr(sk).s6_addr32[i];
		}
	}
#endif
#ifndef LINUX_2_4
	req->sport  = inet_sk(sk)->inet_sport;
	req->dport  = inet_sk(sk)->inet_dport;
#else
	req->sport  = sk->inet_sport;
	req->dport  = sk->inet_dport;
#endif
	req->ipvers_opentype = (otype << 4) | (sk->sk_family == AF_INET ? 4:6);
	req->tos    = inet_sk(sk)->tos;

	ndev = dst ? dst->dev : NULL;

	if (dst && (ndev->priv_flags & IFF_802_1Q_VLAN))
		req->vlan = htons(vlan_dev_vlan_id(ndev) & VLAN_VID_MASK);
	else
		req->vlan = htons(0xfff);
#ifdef SO_MARK
	req->mark = sk->sk_mark;
#else
	req->mark = 0;
#endif
}
EXPORT_SYMBOL(offload_req_from_sk);

#ifndef LINUX_2_4
static void rcu_free_policy(struct rcu_head *h)
{
	kfree(container_of(h, struct offload_policy, rcu_head));
}

static inline void free_policy(struct offload_policy *policy)
{
	if (policy)
		call_rcu(&policy->rcu_head, rcu_free_policy);
}
#endif

int set_offload_policy(struct toedev *dev, const struct ofld_policy_file *f)
{
	unsigned int len;
	struct offload_policy *p = NULL, *oldpolicy;

	if (f) {
		len = (f->nrules + 1) * sizeof(struct offload_settings) +
		      f->prog_size * sizeof(struct ofld_prog_inst) +
		      f->opt_prog_size * sizeof(u32);

		p = kmalloc(len + sizeof(*p), GFP_KERNEL);
		if (!p)
			return -ENOMEM;

#ifndef LINUX_2_4
		INIT_RCU_HEAD(&p->rcu_head);
#endif
		p->match_all = f->output_everything;
		p->use_opt = 1;
		memcpy(p->prog, f->prog, len);
		p->opt_prog_start = (const u32 *)&p->prog[f->prog_size];
		p->settings = (void *)&p->opt_prog_start[f->opt_prog_size];
	}
	oldpolicy = dev->policy;
#ifndef LINUX_2_4
	rcu_assign_pointer(dev->policy, p);
	free_policy(oldpolicy);
        if (dev->policy && dev->policy->match_all >= 0) {
                int match = dev->policy->match_all;
		struct tom_info *ti = dev->offload_mod;

		if (!ti)
			return 0;
                if (!dev->policy->settings[match].offload) {
			if (!dev->close(dev)) {
                        	if (atomic_read(&ti->refcnt)) {
					module_put(ti->owner);
					atomic_dec(&ti->refcnt);
				}
			} else if (printk_ratelimit())
				printk(KERN_INFO "%s: TID's still in use\n",
					dev->name);
                }
	}
#else
	write_lock(&dev->policy_lock);
	dev->policy = p;
	write_unlock(&dev->policy_lock);
#endif
	return 0;
}
EXPORT_SYMBOL(set_offload_policy);

#if defined(CONFIG_TCP_OFFLOAD)
/* If modular there's a separate definition in module_support.c */
void security_inet_conn_estab(struct sock *sk, struct sk_buff *skb)
{
#ifdef CONFIG_SECURITY_NETWORK
       security_inet_conn_established(sk, skb);
#endif
}
EXPORT_SYMBOL(security_inet_conn_estab);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
EXPORT_SYMBOL(skb_splice_bits);
#endif
#endif

#endif
