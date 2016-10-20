/*
 * This file handles offloading of listening sockets.
 *
 * Copyright (C) 2003-2015 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */
#include <linux/module.h>
#include <linux/toedev.h>
#include <net/tcp.h>
#include <net/offload.h>
#include "l2t.h"
#include "clip_tbl.h"
#include "defs.h"
#include "tom.h"
#include "cpl_io_state.h"
#include "t4_msg.h"
#include "t4fw_interface.h"
#include "offload.h"

static inline int listen_hashfn(const struct sock *sk)
{
	return ((unsigned long)sk >> 10) & (LISTEN_INFO_HASH_SIZE - 1);
}

/*
 * Create and add a listen_info entry to the listen hash table.  This and the
 * listen hash table functions below cannot be called from softirqs.
 */
static struct listen_info *listen_hash_add(struct tom_data *d, struct sock *sk,
					   unsigned int stid)
{
	struct listen_info *p = kmalloc(sizeof(*p), GFP_KERNEL);

	if (p) {
		int bucket = listen_hashfn(sk);

		p->sk = sk;	/* just a key, no need to take a reference */
		p->stid = stid;
		spin_lock(&d->listen_lock);
		p->next = d->listen_hash_tab[bucket];
		d->listen_hash_tab[bucket] = p;
		spin_unlock(&d->listen_lock);
	}
	return p;
}

/*
 * Given a pointer to a listening socket return its server TID by consulting
 * the socket->stid map.  Returns -1 if the socket is not in the map.
 */
static int listen_hash_find(struct tom_data *d, struct sock *sk)
{
	int stid = -1, bucket = listen_hashfn(sk);
	struct listen_info *p;

	spin_lock(&d->listen_lock);
	for (p = d->listen_hash_tab[bucket]; p; p = p->next)
		if (p->sk == sk) {
			stid = p->stid;
			break;
		}
	spin_unlock(&d->listen_lock);
	return stid;
}

/*
 * Delete the listen_info structure for a listening socket.  Returns the server
 * TID for the socket if it is present in the socket->stid map, or -1.
 */
static int listen_hash_del(struct tom_data *d, struct sock *sk)
{
	int stid = -1, bucket = listen_hashfn(sk);
	struct listen_info *p, **prev = &d->listen_hash_tab[bucket];

	spin_lock(&d->listen_lock);
	for (p = *prev; p; prev = &p->next, p = p->next)
		if (p->sk == sk) {
			stid = p->stid;
			*prev = p->next;
			kfree(p);
			break;
		}
	spin_unlock(&d->listen_lock);
	return stid;
}

/*
 * Start a listening server by sending a passive open request to HW.
 */
void t4_listen_start(struct toedev *dev, struct sock *sk,
		     const struct offload_req *orq)
{
	int stid;
	struct tom_data *d = TOM_DATA(dev);
	struct listen_ctx *ctx;
	const struct offload_settings *settings;
	int err = 0;
	int offload;
	unsigned char iport = 0, mask = 0;
	struct net_device *portdev;
	struct in_device *in_dev;
	struct in_ifaddr *ifa;
	int idx;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	int addr_type = 0;
#endif

	if (!d)
		return;

	rcu_read_lock();
	settings = lookup_ofld_policy(dev, orq, d->conf.cop_managed_offloading);
	offload = settings->offload;

	if (rcu_access_pointer(dev->in_shutdown)) {
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

	if (!offload)
		return;

        if (!TOM_TUNABLE(dev, activated))
                return;

	if (listen_hash_find(d, sk) >= 0)   /* already have it */
		return;

	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return;

	__module_get(THIS_MODULE);
	ctx->tom_data = d;
	ctx->lsk = sk;
	ctx->state = T4_LISTEN_START_PENDING;

	if (sk->sk_family == PF_INET && d->lldi->enable_fw_ofld_conn)
		stid = cxgb4_alloc_sftid(d->tids, sk->sk_family,
					ctx);
	else
		stid = cxgb4_alloc_stid(d->tids, sk->sk_family,
					ctx);

	if (stid < 0)
		goto free_ctx;
	
	sock_hold(sk);

	if (!listen_hash_add(d, sk, stid))
		goto free_stid;

	if (sk->sk_family == PF_INET) {
		rcu_read_lock();
		/* note that we explicitly skip loopback ports */
		for (idx = 0; idx < NCHAN ; idx++) {
			in_dev = NULL;
			portdev = d->egr_dev[idx];
			if (portdev && !netdev_master_upper_dev_get_rcu(portdev))
				in_dev = __in_dev_get_rcu(portdev);
			if (in_dev) {
				for (ifa = in_dev->ifa_list; ifa; ifa = ifa->ifa_next) {
					if (inet_ifa_match(inet_sk(sk)->inet_rcv_saddr, ifa))
						break;
				}
				if (ifa) {
					iport = cxgb4_port_idx(portdev);
					mask = ~0;
					break;
				}
			}
		}
		rcu_read_unlock();

		if (d->lldi->enable_fw_ofld_conn)
			err = cxgb4_create_server_filter(mask ? portdev : dev->lldev[0], stid,
							 inet_sk(sk)->inet_rcv_saddr,
							 inet_sk(sk)->inet_sport,
							 cpu_to_be16(TOM_TUNABLE(dev, offload_vlan)),
							 d->rss_qid, iport, mask);
		else
			err = cxgb4_create_server(dev->lldev[0], stid,
						  inet_sk(sk)->inet_rcv_saddr,
						  inet_sk(sk)->inet_sport,
						  cpu_to_be16(TOM_TUNABLE(dev, offload_vlan)),
						  d->rss_qid);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	} else {
		err = cxgb4_create_server6(dev->lldev[0], stid,
					   &inet6_sk_rcv_saddr(sk),
					   inet_sk(sk)->inet_sport, d->rss_qid);
#endif
	}
	if (err > 0)
		err = net_xmit_errno(err);
	if (err)
		goto del_hash;

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	if (sk->sk_family == PF_INET6) {
		addr_type = ipv6_addr_type((const struct in6_addr *)
					   &inet6_sk_rcv_saddr(sk));
		if (addr_type != IPV6_ADDR_ANY)
			err = cxgb4_clip_get(dev->lldev[0],
				(const u32 *)&inet6_sk_rcv_saddr(sk), 1);
		if (err)
			cxgb4_remove_server(dev->lldev[0], stid,
					    d->rss_qid, true);
	}
#endif

	if (!err)
		return;
del_hash:
	listen_hash_del(d, sk);
free_stid:
	cxgb4_free_stid(d->tids, stid, sk->sk_family);
	sock_put(sk);
free_ctx:
	kfree(ctx);
	module_put(THIS_MODULE);
}

/*
 * Stop a listening server by sending a close_listsvr request to HW.
 * The server TID is freed when we get the reply.
 */
void t4_listen_stop(struct toedev *tdev, struct sock *sk)
{
	struct tom_data *d = TOM_DATA(tdev);
	int stid;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	int addr_type = 0;
#endif

	rcu_read_lock();
	if (rcu_access_pointer(tdev->in_shutdown)) {
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

        stid = listen_hash_del(d, sk);
        if (stid < 0)
                return;

	t4_reset_synq(sk);

	cxgb4_remove_server(tdev->lldev[0], stid, d->rss_qid, sk->sk_family == PF_INET6);
	if (d->lldi->enable_fw_ofld_conn && sk->sk_family == PF_INET)
		cxgb4_remove_server_filter(tdev->lldev[0], stid, d->rss_qid, sk->sk_family == PF_INET6);

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	if (sk->sk_family == PF_INET6) {
		addr_type = ipv6_addr_type((const struct in6_addr *)
					&inet6_sk_rcv_saddr(sk));
		if (addr_type != IPV6_ADDR_ANY)
			cxgb4_clip_release(tdev->lldev[0],
			 (const u32 *)&inet6_sk_rcv_saddr(sk), 1);
	}
#endif
	t4_disconnect_acceptq(sk);
}

/*
 * Process a CPL_CLOSE_LISTSRV_RPL message.  If the status is good we release
 * the STID.
 */
static int do_close_server_rpl(struct tom_data *td, struct sk_buff *skb)
{
        struct cpl_close_listsvr_rpl *rpl = (struct cpl_close_listsvr_rpl *)cplhdr(skb);
        unsigned int stid = GET_TID(rpl);
	void *data = lookup_stid(td->tids, stid);

        if (rpl->status != CPL_ERR_NONE)
                printk(KERN_ERR "Unexpected CLOSE_LISTSRV_RPL status %u for "
                       "STID %u\n", rpl->status, stid);
        else {
                struct listen_ctx *listen_ctx = (struct listen_ctx *)data;

                cxgb4_free_stid(td->tids, stid, listen_ctx->lsk->sk_family);
                sock_put(listen_ctx->lsk);
                kfree(listen_ctx);
		module_put(THIS_MODULE);
        }

        return CPL_RET_BUF_DONE;
}

/*
 * Process a CPL_PASS_OPEN_RPL message.
 */
int do_pass_open_rpl(struct tom_data *td, struct sk_buff *skb)
{
	struct cpl_pass_open_rpl *rpl = (struct cpl_pass_open_rpl *)cplhdr(skb);
	unsigned int stid = GET_TID(rpl);
	struct listen_ctx *listen_ctx;

	listen_ctx = (struct listen_ctx *)lookup_stid(td->tids, stid);

	if (!listen_ctx) {
		printk(KERN_ERR "no listening context for STID %u\n", stid);
		return CPL_RET_BUF_DONE;
	}

	if (listen_ctx->state == T4_LISTEN_START_PENDING) {
		listen_ctx->state = T4_LISTEN_STARTED;
		return CPL_RET_BUF_DONE;
	}

	if (rpl->status != CPL_ERR_NONE)
		printk(KERN_ERR "Unexpected PASS_OPEN_RPL status %u for "
		       "STID %u\n", rpl->status, stid);
	else {
		cxgb4_free_stid(td->tids, stid, listen_ctx->lsk->sk_family);
		sock_put(listen_ctx->lsk);
		kfree(listen_ctx);
		module_put(THIS_MODULE);
	}

	return CPL_RET_BUF_DONE;
}

void __init t4_init_listen_cpl_handlers(void)
{
	t4tom_register_cpl_handler(CPL_PASS_OPEN_RPL, do_pass_open_rpl);
	t4tom_register_cpl_handler(CPL_CLOSE_LISTSRV_RPL, do_close_server_rpl);
}

#ifdef CONFIG_PROC_FS
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include "t4_linux_fs.h"

#define PROFILE_LISTEN_HASH 1

#if PROFILE_LISTEN_HASH
# define BUCKET_FIELD_NAME "Bucket"
# define BUCKET_FMT "%-9d"
# define BUCKET(sk) , listen_hashfn(sk)
#else
# define BUCKET_FIELD_NAME
# define BUCKET_FMT
# define BUCKET(sk)
#endif

/*
 * Return the first entry in the listen hash table that's in
 * a bucket >= start_bucket.
 */
static struct listen_info *listen_get_first(struct seq_file *seq,
					    int start_bucket)
{
	struct tom_data *d = seq->private;

	for (; start_bucket < LISTEN_INFO_HASH_SIZE; ++start_bucket)
		if (d->listen_hash_tab[start_bucket])
			return d->listen_hash_tab[start_bucket];
	return NULL;
}

static struct listen_info *listen_get_next(struct seq_file *seq,
					   const struct listen_info *p)
{
	return p->next ? p->next : listen_get_first(seq,
						    listen_hashfn(p->sk) + 1);
}

/*
 * Must be called with the listen_lock held.
 */
static struct listen_info *listen_get_idx(struct seq_file *seq, loff_t pos)
{
	struct listen_info *p = listen_get_first(seq, 0);

	if (p)
		while (pos && (p = listen_get_next(seq, p)))
			pos--;

	return pos ? NULL : p;
}

static struct listen_info *listen_get_idx_lock(struct seq_file *seq, loff_t pos)
{
	struct tom_data *d = seq->private;

	spin_lock(&d->listen_lock);
	return listen_get_idx(seq, pos);
}

static void *listen_seq_start(struct seq_file *seq, loff_t *pos)
{
	return *pos ? listen_get_idx_lock(seq, *pos - 1) : SEQ_START_TOKEN;
}

static void *listen_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	if (v == SEQ_START_TOKEN)
		v = listen_get_idx_lock(seq, 0);
	else
		v = listen_get_next(seq, v);
	++*pos;
	return v;
}

static void listen_seq_stop(struct seq_file *seq, void *v)
{
	if (v != SEQ_START_TOKEN)
		spin_unlock(&((struct tom_data *)seq->private)->listen_lock);
}

static int listen_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN)
		seq_puts(seq,
			 "TID     Port    " BUCKET_FIELD_NAME \
			 "   IP address\n");
	else {
		char ipaddr[40]; /* enough for full IPv6 address + NULL */
		struct listen_info *p = v;
		struct sock *sk = p->sk;
		if (sk->sk_family == AF_INET)
			sprintf(ipaddr, "%pI4", &inet_sk(sk)->inet_rcv_saddr);
#if defined(CONFIG_TCPV6_OFFLOAD)
		else
			sprintf(ipaddr, "%pI6c", &inet6_sk_rcv_saddr(sk));
#endif
			seq_printf(seq, "%-7d %-8u" BUCKET_FMT "%s\n", p->stid,
				   ntohs(inet_sk(sk)->inet_sport) BUCKET(sk),
				   ipaddr);
	}
	return 0;
}

static struct seq_operations listen_seq_ops = {
	.start = listen_seq_start,
	.next = listen_seq_next,
	.stop = listen_seq_stop,
	.show = listen_seq_show
};

static int proc_listeners_open(struct inode *inode, struct file *file)
{
	int rc = seq_open(file, &listen_seq_ops);

	if (!rc) {
		struct seq_file *seq = file->private_data;

		seq->private = PDE_DATA(inode);
	}
	return rc;
}

static struct file_operations proc_listeners_fops = {
	.owner = THIS_MODULE,
	.open = proc_listeners_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release
};

/*
 * Create the proc entry for the listening servers under dir.
 */
int t4_listen_proc_setup(struct proc_dir_entry *dir, struct tom_data *d)
{
	struct proc_dir_entry *p;

	if (!dir)
		return -EINVAL;

	p = proc_create_data("listeners", S_IRUGO, dir,
			     &proc_listeners_fops, d);
	if (!p)
		return -ENOMEM;

        SET_PROC_NODE_OWNER(p, THIS_MODULE);
	return 0;
}

void t4_listen_proc_free(struct proc_dir_entry *dir)
{
	if (dir)
		remove_proc_entry("listeners", dir);
}
#endif
