/*
 * TOE device support infrastructure.
 *
 * Copyright (C) 2003-2011 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include <linux/toedev.h>
#include <net/neighbour.h>
#include <net/sock.h>
#include <net/ip.h>

#if defined(CONFIG_XEN) && defined(CONFIG_XEN_TOE)
/* prevent collision with (struct mac_addr) definition in bond_3ad.h */
#define mac_addr __br_mac_addr
#include <net/bridge/br_private.h>
#undef mac_addr
#endif

#include "version.h"
#include "toe_bonding.h"
#include "toe_compat.h"

static DEFINE_MUTEX(offload_db_lock);
static LIST_HEAD(offload_dev_list);
static LIST_HEAD(offload_module_list);

/*
 * Returns the entry in the given table with the given offload id, or NULL
 * if the id is not found.
 */
static const struct offload_id *id_find(unsigned int id,
					const struct offload_id *table)
{
	for ( ; table->id; ++table)
		if (table->id == id)
			return table;
	return NULL;
}

/*
 * Returns true if an offload device is presently attached to an offload module.
 */
static inline int is_attached(const struct toedev *dev)
{
	return dev->offload_mod != NULL;
}

/*
 * Try to attach a new offload device to an existing TCP offload module that
 * can handle the device's offload id.  Returns 0 if it succeeds.
 *
 * Must be called with the offload_db_lock held.
 */
static int offload_attach(struct toedev *dev)
{
	struct tom_info *t;

	list_for_each_entry(t, &offload_module_list, list_node) {
		const struct offload_id *entry;

		entry = id_find(dev->ttid, t->id_table);
		if (entry && t->attach(dev, entry) == 0) {
			dev->offload_mod = t;
			return 0;
		}
	}
	return -ENOPROTOOPT;
}

static int offload_detach(struct toedev *dev)
{
	struct tom_info *t;

	list_for_each_entry(t, &offload_module_list, list_node) {
		if (t->detach(dev) == 0) {
			dev->offload_mod = NULL;
			return 0;
		}
	}
	return -ENOPROTOOPT;
}

/**
 * register_tom - register a TCP Offload Module (TOM)
 * @t: the offload module to register
 *
 * Register a TCP Offload Module (TOM).
 */
int register_tom(struct tom_info *t)
{
	mutex_lock(&offload_db_lock);
	list_add(&t->list_node, &offload_module_list);
	mutex_unlock(&offload_db_lock);
	return 0;
}
EXPORT_SYMBOL(register_tom);

/**
 * unregister_tom - unregister a TCP Offload Module (TOM)
 * @t: the offload module to register
 *
 * Unregister a TCP Offload Module (TOM).  Note that this does not affect any
 * TOE devices to which the TOM is already attached.
 */
int unregister_tom(struct tom_info *t)
{
	mutex_lock(&offload_db_lock);
	list_del(&t->list_node);
	mutex_unlock(&offload_db_lock);
	return 0;
}
EXPORT_SYMBOL(unregister_tom);

/*
 * Find an offload device by name.  Must be called with offload_db_lock held.
 */
static struct toedev *__find_offload_dev_by_name(const char *name)
{
	struct toedev *dev;

	list_for_each_entry(dev, &offload_dev_list, toe_list) {
		if (!strncmp(dev->name, name, TOENAMSIZ))
			return dev;
	}
	return NULL;
}

/*
 * Returns true if an offload device is already registered.
 * Must be called with the offload_db_lock held.
 */
static int is_registered(const struct toedev *dev)
{
	struct toedev *d;

	list_for_each_entry(d, &offload_dev_list, toe_list) {
		if (d == dev)
			return 1;
	}
	return 0;
}

/*
 * Finalize the name of an offload device by assigning values to any format
 * strings in its name.
 */
static int assign_name(struct toedev *dev, const char *name, int limit)
{
	int i;

	for (i = 0; i < limit; ++i) {
		char s[TOENAMSIZ];

		if (snprintf(s, sizeof(s), name, i) >= sizeof(s))
			return -1;                  /* name too long */
		if (!__find_offload_dev_by_name(s)) {
			strcpy(dev->name, s);
			return 0;
		}
	}
	return -1;
}

#ifdef CONFIG_PROC_FS
#include <linux/netdevice.h>
#include <linux/proc_fs.h>

static struct proc_dir_entry *offload_proc_root;

static int proc_devices_show(struct seq_file *seq, void *v)
{
	struct toedev *dev;

	seq_puts(seq,
		 "Device           Offload Module     Policy   Interfaces\n");

	mutex_lock(&offload_db_lock);
	list_for_each_entry(dev, &offload_dev_list, toe_list) {
		int i;

		seq_printf(seq, "%-16s %-18s   %-6s",
			   dev->name,
			   (is_attached(dev)
			    ? dev->offload_mod->name
			    : "<None>"),
			   (dev->policy
			    ? "yes"
			    : "no"));
		for (i = 0; i < dev->nlldev; i++)
			seq_printf(seq, " %s", dev->lldev[i]->name);
		seq_puts(seq, "\n");
	}
	mutex_unlock(&offload_db_lock);

	return 0;
}

static int proc_devices_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_devices_show, PDE_DATA(inode));
}

static const struct file_operations proc_devices_fops = {
	.open = proc_devices_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int proc_ipv6_offload_show(struct seq_file *seq, void *v)
{
	const static char *state =
#ifdef CONFIG_TCPV6_OFFLOAD
		"enabled";
#else
		"disabled";
#endif
	seq_printf(seq, "ipv6 offload support = %s\n", state);
        return 0;
}

static int proc_ipv6_offload_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_ipv6_offload_show, PDE_DATA(inode));
}

static const struct file_operations proc_ipv6_offload_fops = {
	.open = proc_ipv6_offload_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static void offload_proc_cleanup(void)
{
	if (offload_proc_root) {
		remove_proc_entry("devices", offload_proc_root);
		remove_proc_entry("ipv6_offload", offload_proc_root);
	}
	remove_proc_entry("offload", INET_PROC_DIR);
	offload_proc_root = NULL;
}

static struct proc_dir_entry *create_offload_proc_dir(const char *name)
{
	struct proc_dir_entry *d;

	if (!offload_proc_root)
		return NULL;

	d = proc_mkdir(name, offload_proc_root);
	if (d)
		SET_PROC_NODE_OWNER(d, THIS_MODULE);
	return d;
}

static void delete_offload_proc_dir(struct toedev *dev)
{
	if (dev->proc_dir) {
		remove_proc_entry(dev->name, offload_proc_root);
		dev->proc_dir = NULL;
	}
}

static int __init offload_proc_init(void)
{
	struct proc_dir_entry *d;

	offload_proc_root = proc_mkdir("offload", INET_PROC_DIR);
	if (!offload_proc_root)
		return -ENOMEM;
	SET_PROC_NODE_OWNER(offload_proc_root, THIS_MODULE);

	d = proc_create_data("devices", S_IRUGO, offload_proc_root,
			     &proc_devices_fops, NULL);
	if (!d)
		goto cleanup;
	SET_PROC_NODE_OWNER(d, THIS_MODULE);

	d = proc_create_data("ipv6_offload", S_IRUGO, offload_proc_root,
			     &proc_ipv6_offload_fops, NULL);
	if (!d)
		goto cleanup;
	SET_PROC_NODE_OWNER(d, THIS_MODULE);

#ifndef CONFIG_TCPV6_OFFLOAD
	printk(KERN_WARNING KBUILD_MODNAME
	       ": IPv6 Offload not supported with this module.\n");
#endif
	return 0;

cleanup:
	offload_proc_cleanup();
	return -ENOMEM;
}
#else
#define offload_proc_init() 0
#define offload_proc_cleanup()
#define create_offload_proc_dir(name) NULL
#define delete_offload_proc_dir(dev)
#endif

/*
 * Associate dev's Ethernet devices with the given offload device.
 */
static void set_netdev_assoc(const struct toedev *dev, struct toedev *val)
{
	int i;

	for (i = 0; i < dev->nlldev; i++)
		TOEDEV(dev->lldev[i]) = val;
}

/**
 * register_toedev - register a TOE device
 * @dev: the device
 * @name: a name template for the device
 *
 * Register a TOE device and try to attach an appropriate TCP offload module
 * to it.  @name is a template that may contain at most one %d format
 * specifier.
 */
int register_toedev(struct toedev *dev, const char *name)
{
	int ret;
	const char *p;

	/*
	 * Validate the name template.  Only one %d allowed and name must be
	 * a valid filename so it can appear in sysfs.
	 */
	if (!name || !*name || !strcmp(name, ".") || !strcmp(name, "..") ||
	    strchr(name, '/'))
		return -EINVAL;

	p = strchr(name, '%');
	if (p && (p[1] != 'd' || strchr(p + 2, '%')))
		return -EINVAL;

	mutex_lock(&offload_db_lock);
	if (is_registered(dev)) {  /* device already registered */
		ret = -EEXIST;
		goto out;
	}

	if ((ret = assign_name(dev, name, 32)) != 0)
		goto out;

	dev->proc_dir = create_offload_proc_dir(dev->name);
	dev->offload_mod = NULL;
#ifdef LINUX_2_4
	dev->policy = NULL;
	rwlock_init(&dev->policy_lock);
#endif
	set_netdev_assoc(dev, dev);
	list_add_tail(&dev->toe_list, &offload_dev_list);
out:
	mutex_unlock(&offload_db_lock);
	return ret;
}
EXPORT_SYMBOL(register_toedev);

/**
 * unregister_toedev - unregister a TOE device
 * @dev: the device
 *
 * Unregister a TOE device.  The device must not be attached to an offload
 * module.
 */
int unregister_toedev(struct toedev *dev)
{
	int ret = 0;

	mutex_lock(&offload_db_lock);
	if (!is_registered(dev)) {
		ret = -ENODEV;
		goto out;
	}
	if (is_attached(dev)) {
		ret = -EBUSY;
		goto out;
	}
	list_del(&dev->toe_list);
	delete_offload_proc_dir(dev);
	set_netdev_assoc(dev, NULL);
out:
	mutex_unlock(&offload_db_lock);
	return ret;
}
EXPORT_SYMBOL(unregister_toedev);

/**
 * activate_offload - activate an offload device
 * @dev: the device
 *
 * Activate an offload device by locating an appropriate registered offload
 * module.  If no module is found the operation fails and may be retried at
 * a later time.
 */
int activate_offload(struct toedev *dev)
{
	int ret = 0;

#ifdef CONFIG_TCP_OFFLOAD_MODULE
	ret = prepare_tcp_for_offload();
	if (ret)
		return ret;
#endif

	mutex_lock(&offload_db_lock);
	if (!is_registered(dev))
		ret = -ENODEV;
	else if (!is_attached(dev))
		ret = offload_attach(dev);
	mutex_unlock(&offload_db_lock);
	return ret;
}
EXPORT_SYMBOL(activate_offload);

int deactivate_offload(struct toedev *dev)
{
        int ret = 0;

        mutex_lock(&offload_db_lock);
        if (!is_registered(dev))
                ret = -ENODEV;
        else if (is_attached(dev))
                ret = offload_detach(dev);
        mutex_unlock(&offload_db_lock);
        return ret;
}
EXPORT_SYMBOL(deactivate_offload);

#if defined(CONFIG_TCP_OFFLOAD)
# include <net/tcp.h>

int tcp_timestamps_enabled(void)
{
	return sysctl_tcp_timestamps;
}

int tcp_sack_enabled(void)
{
	return sysctl_tcp_sack;
}

int tcp_win_scaling_enabled(void)
{
	return sysctl_tcp_window_scaling;
}

int tcp_ecn_enabled(struct net *net)
{
	return sysctl_tcp_ecn;
}
#else
int tcp_timestamps_enabled(void)
{
	extern int *sysctl_tcp_timestamps_p;

	return *sysctl_tcp_timestamps_p;
}

int tcp_sack_enabled(void)
{
	extern int *sysctl_tcp_sack_p;

	return *sysctl_tcp_sack_p;
}

int tcp_win_scaling_enabled(void)
{
	extern int *sysctl_tcp_window_scaling_p;

	return *sysctl_tcp_window_scaling_p;
}

int tcp_ecn_enabled(struct net *net)
{
	return t4_get_sysctl_tcp_ecn(net);
}
#endif

EXPORT_SYMBOL(tcp_timestamps_enabled);
EXPORT_SYMBOL(tcp_sack_enabled);
EXPORT_SYMBOL(tcp_win_scaling_enabled);
EXPORT_SYMBOL(tcp_ecn_enabled);

/**
 * toe_send - send a packet to a TOE device
 * @dev: the device
 * @skb: the packet
 *
 * Sends an sk_buff to a TOE driver after dealing with any active network taps.
 */
int toe_send(struct toedev *dev, struct sk_buff *skb)
{
	int r;

	local_bh_disable();
#if defined(CONFIG_TCP_OFFLOAD)
	if (unlikely(netdev_nit)) {      /* deal with active taps */
		skb_reset_network_header(skb);
		if (!skb->dev)
			skb->dev = dev->lldev[0];
		dev_queue_xmit_nit(skb, skb->dev);
	}
#endif
	r = dev->send(dev, skb);
	local_bh_enable();
	return r;
}
EXPORT_SYMBOL(toe_send);

#if 0
#if defined(CONFIG_TCP_OFFLOAD)
/**
 * toe_receive_skb - process n received TOE packets
 * @dev: the toe device
 * @skb: an array of offload packets
 * @n: the number of offload packets
 *
 * Process an array of ingress offload packets.  Each packet is forwarded
 * to any active network taps and then passed to the toe device's receive
 * method.  We optimize passing packets to the receive method by passing
 * it the whole array at once except when there are active taps.
 */
int toe_receive_skb(struct toedev *dev, struct sk_buff **skb, int n)
{
	if (likely(!netdev_nit))
		return dev->recv(dev, skb, n);

	for ( ; n; n--, skb++) {
		skb[0]->dev = dev->lldev[0];
		dev_queue_xmit_nit(skb[0], skb[0]->dev);
		skb[0]->dev = NULL;
		dev->recv(dev, skb, 1);
	}
	return 0;
}
EXPORT_SYMBOL(toe_receive_skb);
#endif
#endif

#if defined(CONFIG_XEN) && defined(CONFIG_XEN_TOE)
/**
 *	is_vif - return TRUE if a device is a Xen virtual interface (VIF)
 *	@dev: the device to test for VIF status ...
 *
 *	N.B. Xen virtual interfaces (VIFs) have a few distinguishing
 *	features that we can use to try to determine whether we're
 *	looking at one.  Unfortunately there's noting _really_ defined
 *	for them so this is just a hueristic and we probably ought to
 *	think about a better predicate.  For right now we look for a
 *	name of "vif*" and a MAC address of fe:ff:ff:ff:ff:ff ...
 */
static int is_vif(struct net_device *dev)
{
	const char vifname[3] = "vif";
	const char vifmac[6] = { 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff };

	return (memcmp(dev->name, vifname, sizeof(vifname)) == 0 &&
		memcmp(dev->dev_addr, vifmac, sizeof(vifmac)) == 0);
}

/**
 *	get_xenbrofldpif -- return the offload physical interface (PIF)
 *	associated with a Xen bridge.
 *
 *	Search a Xen bridge's port interface list for it's physical interface
 *	(PIF) and return it if it's an offload device.  Return NULL if the
 *	physical interface can't be found, it's not an offload device or
 *	there are more than one physical interfaces present (indicating that
 *	the bridge isn't a standard Xen bridge used to proxy a single PIF).
 */
static struct net_device * get_xenbrofldpif(struct net_device *xenbr)
{
	struct net_bridge *br = netdev_priv(xenbr);
	struct net_device *pif = NULL;
	struct net_bridge_port *port;

	list_for_each_entry(port, &br->port_list, list) {
		struct net_device *portdev = port->dev;
		if (!is_vif(portdev)) {
			if (pif || !netdev_is_offload(portdev))
				return NULL;
			pif = portdev;
		}
	}

	return pif;
}
#endif

void toe_neigh_update(struct neighbour *neigh)
{
	struct net_device *dev = neigh->dev;

	if (dev && netdev_is_offload(dev)) {
		struct toedev *tdev = TOEDEV(dev);

		if (tdev && tdev->neigh_update)
			tdev->neigh_update(tdev, neigh);
	}
}

/**
 * offload_get_phys_egress - find the physical egress device
 * @root_dev: the root device anchoring the search
 * @sk: the socket used to determine egress port in bonding mode
 * @context: in bonding mode, indicates a connection set up or failover
 *
 * Given a root network device it returns the physical egress device that is a
 * descendant of the root device.  The root device may be either a physical
 * device, in which case it is the device returned, or a virtual device, such
 * as a VLAN or bonding device.  In case of a bonding device the search
 * considers the decisions of the bonding device given its mode to locate the
 * correct egress device.
 */
struct net_device *offload_get_phys_egress(struct toe_hash_params *hash_params,
					   int context)
{
	struct net_device *root_dev = hash_params->dev;

	while (root_dev && netdev_is_offload(root_dev)) {
		if (root_dev->priv_flags & IFF_802_1Q_VLAN)
			root_dev = vlan_dev_real_dev(root_dev);
		else if (root_dev->flags & IFF_MASTER)
			root_dev = toe_bond_get_slave(hash_params,
						      context);
#if defined(CONFIG_XEN) && defined(CONFIG_XEN_TOE)
		else if (root_dev->priv_flags & IFF_EBRIDGE)
			root_dev = get_xenbrofldpif(root_dev);
#endif
		else
			break;

		hash_params->dev = root_dev;
	}
	return root_dev;
}
EXPORT_SYMBOL(offload_get_phys_egress);

void init_toe_hash_params(struct toe_hash_params *hash_params,
			  struct net_device *dev, struct neighbour *neigh,
			  __u32 saddr, __u32 daddr, __u16 sport, __u16 dport,
			  __be32 *s, __be32 *d, bool is_ipv6, u16 l4_prot)
{
	hash_params->dev = dev;
	hash_params->neigh = neigh;
	hash_params->saddr = saddr;
	hash_params->daddr = daddr;
	hash_params->sport = sport;
	hash_params->dport = dport;
	hash_params->s = s;
	hash_params->d = d;
	hash_params->is_ipv6 = is_ipv6;
	hash_params->l4_prot = l4_prot;
}
EXPORT_SYMBOL(init_toe_hash_params);

/*
 * The following few functions define the operations of a virtual offload
 * device that is attached to virtual net_devices, such as VLAN or bonding,
 * to endow them with offload support.  These operations simply find the
 * next net_device in a stack of net_devices and invoke the same operation on
 * the offload device associated with that net_device.  Eventually we reach
 * the physical net_device at the bottom of the stack, whose associated
 * offload device can then complete the operation.
 */

/*
 * Define a virtual offload device for VLANs that simply forwards offload
 * operations to the offload device associated with the VLAN device's child.
 */
static int virtual_can_offload(struct toedev *tdev, struct sock *sk)
{
	struct dst_entry *dst = __sk_dst_get(sk);
	struct net_device *root_dev = dst->dev;
	struct neighbour *neigh;
	struct toe_hash_params hash_params;
	struct net_device *edev = NULL;

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
	}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else {
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
	}
#endif
	if (edev && netdev_is_offload(edev)) {
		struct toedev *tdev = TOEDEV(edev);
		return tdev ? tdev->can_offload(tdev, sk) : 0;
	}
	return 0;
}

static inline int connect_if_module_live(struct toedev *dev,
				struct sock *sk, struct net_device *netdev)
{
	struct tom_info *mod;

	if (!is_attached(dev))
		return dev->connect(dev, sk, netdev);

	mod  = dev->offload_mod;

	if (module_is_live(mod->owner)) {
		if (!module_refcount(mod->owner)) {
			if (atomic_inc_return(&mod->refcnt) == 1)
				__module_get(mod->owner);
			else
				atomic_dec(&mod->refcnt);
		}
		return dev->connect(dev, sk, netdev);
	}
	rcu_read_unlock();
	return -1;
}

static int virtual_connect(struct toedev *dev, struct sock *sk,
			   struct net_device *egress_dev)
{
	struct dst_entry *dst = __sk_dst_get(sk);
	struct neighbour *neigh;
	struct toe_hash_params hash_params;
	struct net_device *edev = NULL;

        if (sk->sk_family == AF_INET) {
		neigh = t4_dst_neigh_lookup(dst, &inet_sk(sk)->inet_daddr);
		if (neigh) {
			init_toe_hash_params(&hash_params, egress_dev, neigh,
					     inet_sk(sk)->inet_saddr,
					     inet_sk(sk)->inet_daddr,
					     inet_sk(sk)->inet_sport,
					     inet_sk(sk)->inet_dport,
					     NULL, NULL, false, IPPROTO_TCP);
			edev = offload_get_phys_egress(&hash_params, TOE_OPEN);
			t4_dst_neigh_release(neigh);
		}
	}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else {
		neigh = t4_dst_neigh_lookup(dst, &inet6_sk_daddr(sk));
		if (neigh) {
			init_toe_hash_params(&hash_params, egress_dev, neigh,
					     0, 0, inet_sk(sk)->inet_sport,
					     inet_sk(sk)->inet_dport,
					     &inet6_sk_saddr(sk).s6_addr32[0],
					     &inet6_sk_daddr(sk).s6_addr32[0],
					     true, IPPROTO_TCP);
			edev = offload_get_phys_egress(&hash_params, TOE_OPEN);
			t4_dst_neigh_release(neigh);
		}
	}
#endif
	if (edev && netdev_is_offload(edev)) {
		struct toedev *tdev = TOEDEV(edev);

		if (!tdev || !tdev->can_offload)
			goto out_err;

		return connect_if_module_live(tdev, sk, edev);
	}
out_err:
	rcu_read_unlock();
	return -1;
}

static void virtual_neigh_update(struct toedev *dev, struct neighbour *neigh)
{
	struct net_device *child = neigh->dev;

	if (neigh->dev->priv_flags & IFF_802_1Q_VLAN)
		child = vlan_dev_real_dev(child);

	if (netdev_is_offload(child)) {
		struct toedev *tdev = TOEDEV(child);

		if (child->flags & IFF_MASTER)
			toe_bond_neigh_propagate(child, neigh);
		else
			if (tdev)
				tdev->neigh_update(tdev, neigh);
	}
}

static struct toedev virtual_offload_dev = {
	.can_offload  = virtual_can_offload,
	.connect      = virtual_connect,
	.neigh_update = virtual_neigh_update
};

/*
 * This handler monitors net_device registration and associates virtual offload
 * devices with virtual net_devices, such as VLAN and bonding devices.
 */
static int virt_dev_notify_handler(struct notifier_block *this,
				   unsigned long event, void *data)
{
	struct net_device *dev = netdev_notifier_info_to_dev(data);

	if (event == NETDEV_REGISTER)
		if (dev->priv_flags & IFF_802_1Q_VLAN ||
#if defined(CONFIG_XEN) && defined(CONFIG_XEN_TOE)
		    dev->priv_flags & IFF_EBRIDGE ||
#endif
		    dev->flags & IFF_MASTER) {
			TOEDEV(dev) = &virtual_offload_dev;
			netdev_set_offload(dev);
#if defined(CONFIG_XEN) && defined(CONFIG_XEN_TOE) && defined(NETIF_F_TCPIP_OFFLOAD)
			if (dev->priv_flags & IFF_EBRIDGE) {
				struct net_bridge *br = netdev_priv(dev);
				br_set_offload_mask(br);
			}
#endif
		}
	return NOTIFY_DONE;
}

/**
 * toe_enslave - check the enslaving procedure
 * for TOE enabled devices
 * @bond_dev: bonding master net device
 * @slave_dev: device to be enslaved
 *
 * Bonding in TOE context currently has these limitations:
 *	- all slaves must be TOE enabled,
 *
 */
int toe_enslave(struct net_device *bond_dev, struct net_device *slave_dev)
{
	int slave_count;
	int ret = 0;

	slave_count = toe_bond_slavecnt(bond_dev);

	/* First slave */
	if (slave_count == 1) {
		if (netdev_is_offload(slave_dev) &&
		    is_bmode_supported(bond_dev)) {
			netdev_set_offload(bond_dev);
			bond_dev->hard_header_len = slave_dev->hard_header_len;
		} else if (netdev_is_offload(slave_dev))
			ret = -EOPNOTSUPP;
		else
			netdev_clear_offload(bond_dev);
	} else {
		/* Mix of TOE enabled and regular devices not supported */
		if ((netdev_is_offload(bond_dev) ^ netdev_is_offload(slave_dev)) ||
		     !is_bmode_supported(bond_dev))
			ret = -EOPNOTSUPP;
	}

	return ret;
}
EXPORT_SYMBOL(toe_enslave);

/**
 * toe_failover - executes failover for offloaded connections
 * @bond_dev: bonding master net device
 * @dev: slave device triggering the failover event
 * @event: change of active slave, or 802.3ad port down|up
 *
 * Called under bond driver locks.
 */

int toe_failover(struct net_device *bond_dev, struct net_device *dev, int event, struct net_device *last)
{
	if (!bond_dev) {
		printk(KERN_WARNING "toe_failover: bond_dev is NULL\n");
		return -EINVAL;
	}
	if (!dev) {
		return -EINVAL;
	}
	if (bond_dev && netdev_is_offload(bond_dev)) {
		struct toedev *tdev;
		struct net_device *root_dev;

		if (dev->priv_flags & IFF_802_1Q_VLAN) {
			root_dev = vlan_dev_real_dev(dev);
			if (!root_dev)
				return -EINVAL;
		} else
			root_dev = dev;
		tdev = toe_bond_slave_toedev(root_dev);
		if (tdev && tdev->failover)
			tdev->failover(tdev, bond_dev, dev, event, last);
	}
	return 0;
}
EXPORT_SYMBOL(toe_failover);

static struct notifier_block virt_dev_notifier = {
	.notifier_call = virt_dev_notify_handler
};

static int __init offload_init(void)
{
	/* We tolerate proc failures */
	if (offload_proc_init())
		printk(KERN_WARNING "Unable to create /proc/net/offload\n");

	/* We tolerate notifier registration failures */
	if (register_netdevice_notifier(&virt_dev_notifier) < 0)
		printk(KERN_WARNING
		       "Unable to register virtual device offload notifier\n");
	return 0;
}

static void __exit offload_cleanup(void)
{
	unregister_netdevice_notifier(&virt_dev_notifier);
	offload_proc_cleanup();
#ifdef CONFIG_TCP_OFFLOAD_MODULE
#ifndef LINUX_2_4
	rcu_barrier();
#endif
	restore_tcp_to_nonoffload();
#endif
}

subsys_initcall(offload_init);
module_exit(offload_cleanup);

MODULE_DESCRIPTION("Support for TCP offload devices");
MODULE_AUTHOR("Chelsio Communications");
MODULE_LICENSE("GPL");
MODULE_VERSION(TOECORE_VERSION);
