/*
 * libcxgbi.c: Chelsio common library for T3/T4 iSCSI driver.
 *
 * Copyright (c) 2012-2015 Chelsio Communications, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Karen Xie (kxie@chelsio.com)
 * Written by: Rakesh Ranjan (rranjan@chelsio.com)
 */

#define pr_fmt(fmt)	KBUILD_MODNAME ":%s: " fmt, __func__

#ifdef KERNEL_HAS_KCONFIG_H
#include <linux/kconfig.h>
#endif
#ifdef KERNEL_HAS_EXPORT_H
#include <linux/export.h>
#endif
#include <linux/skbuff.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/pci.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_host.h>
#include <linux/blkdev.h>
#include <linux/if_vlan.h>
#include <linux/inet.h>
#include <net/arp.h>
#include <net/dst.h>
#include <net/route.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <net/addrconf.h>

#include <linux/inetdevice.h>	/* ip_dev_find */
#include <net/tcp.h>

#undef __VARIABLE_DDP_PAGE_SIZE__
#ifdef __VARIABLE_DDP_PAGE_SIZE__
#include <linux/random.h>
#endif

static unsigned int dbg_level;
#include "../cxgbi_compat_libiscsi2.h"
#include "libcxgbi_compat.h"
#include "libcxgbi.h"

#include "cxgbi_ippm.c"

#define DRV_MODULE_NAME		"libcxgbi"
#define DRV_MODULE_DESC		"Chelsio iSCSI driver library"
#define DRV_MODULE_VERSION	"2.12.0.3-1203"
#define DRV_MODULE_RELDATE	"Oct. 2010"

MODULE_AUTHOR("Chelsio Communications, Inc.");
MODULE_DESCRIPTION(DRV_MODULE_DESC);
MODULE_VERSION(DRV_MODULE_VERSION);
MODULE_LICENSE("GPL");

module_param(dbg_level, uint, 0644);
MODULE_PARM_DESC(dbg_level, "libiscsi debug level (default=0)");

module_param(ppm_dbg, uint, 0644);
MODULE_PARM_DESC(ppm_dbg, "iscsi ppm debug (default=0)");
  
static char *cht_idstr = "chelsio";
module_param(cht_idstr, charp, 0000);
MODULE_PARM_DESC(cht_idstr, "chelsio iscsi target keyword (default=\"chelsio\")");

/*
 * cxgbi device management
 * maintains a list of the cxgbi devices
 */
static LIST_HEAD(cdev_list);
static DEFINE_MUTEX(cdev_mutex);

static LIST_HEAD(cdev_rcu_list);
static DEFINE_SPINLOCK(cdev_rcu_lock);

int cxgbi_device_portmap_create(struct cxgbi_device *cdev, unsigned int base,
				unsigned int max_conn)
{
	struct cxgbi_ports_map *pmap = &cdev->pmap;

	pmap->port_csk = cxgbi_alloc_big_mem(max_conn *
					     sizeof(struct cxgbi_sock *),
					     GFP_KERNEL);
	if (!pmap->port_csk) {
		pr_warn("cdev 0x%p, portmap OOM %u.\n", cdev, max_conn);
		return -ENOMEM;
	}

	pmap->max_connect = max_conn;
	pmap->sport_base = base;
	spin_lock_init(&pmap->lock);
	return 0;
}
EXPORT_SYMBOL_GPL(cxgbi_device_portmap_create);

void cxgbi_device_portmap_cleanup(struct cxgbi_device *cdev)
{
	struct cxgbi_ports_map *pmap = &cdev->pmap;
	struct cxgbi_sock *csk;
	int i;

	for (i = 0; i < pmap->max_connect; i++) {
		if (pmap->port_csk[i]) {
			csk = pmap->port_csk[i];
			pmap->port_csk[i] = NULL;
			log_debug(1 << CXGBI_DBG_SOCK,
				"csk 0x%p, cdev 0x%p, offload down.\n",
				csk, cdev);
			spin_lock_bh(&csk->lock);
			cxgbi_sock_set_flag(csk, CTPF_OFFLOAD_DOWN);
			csk->saddr.sin_port = 0;
			cxgbi_sock_closed(csk);
			spin_unlock_bh(&csk->lock);
			cxgbi_sock_put(csk);
		}
	}
}
EXPORT_SYMBOL_GPL(cxgbi_device_portmap_cleanup);

#ifdef CXGBI_T10DIF_SUPPORT
/*
 * register supported dif/dix modes and guard type with scsi layer.
 */
int cxgbi_prot_register(struct cxgbi_device *cdev, unsigned int dif_dix,
			unsigned int guard_type)
{
	unsigned int i;

	for (i = 0; i < cdev->nports; i++) {
		scsi_host_set_prot(cdev->hbas[i]->shost, dif_dix);
		scsi_host_set_guard(cdev->hbas[i]->shost, guard_type);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(cxgbi_prot_register);

int cxgbi_tx_pi_page_pool_init(struct cxgbi_device *cdev,
			unsigned int num_page)
{
	struct cxgbi_pi_page_poolq *q = &cdev->tx_pi_page_poolq;
	struct page *page;
	unsigned int i;

	spin_lock_init(&q->lock);

	q->pool = cxgbi_alloc_big_mem(num_page * sizeof(void *), GFP_KERNEL);
	if (!q->pool)
		goto err;

	q->page_list = cxgbi_alloc_big_mem(num_page * sizeof(void *), GFP_KERNEL);
	if (!q->page_list)
		goto err;

	kfifo_init(&q->queue, q->pool, num_page * sizeof(void *));

	for (i = 0; i < num_page; i++) {
		page = alloc_page(GFP_KERNEL | GFP_DMA);
		if (!page)
			goto free_pages;
		q->page_list[i] = page;
		kfifo_in(&q->queue, &page, sizeof(void*));
	}
	q->max = num_page;

	return 0;

free_pages:
	while(kfifo_out(&q->queue, &page, sizeof(void*))) {
		__free_page(page);
	}
err:
	if (q->pool)
		cxgbi_free_big_mem(q->pool);
	q->pool = NULL;

	if (q->page_list)
		cxgbi_free_big_mem(q->page_list);
	q->page_list = NULL;

	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(cxgbi_tx_pi_page_pool_init);

int cxgbi_tx_pi_page_pool_free(struct cxgbi_device *cdev)
{
	struct cxgbi_pi_page_poolq *q = &cdev->tx_pi_page_poolq;
	struct page *page;
	int i;

	spin_lock_bh(&q->lock);

	while(kfifo_out(&q->queue, &page, sizeof(void*)));

	for (i = 0; i < q->max; i++)
		put_page(q->page_list[i]);

	if (q->pool)
		cxgbi_free_big_mem(q->pool);
	q->pool = NULL;

	if (q->page_list)
		cxgbi_free_big_mem(q->page_list);
	q->page_list = NULL;

	spin_unlock_bh(&q->lock);
	return 0;
}

static struct page *cxgbi_tx_pi_get_page(struct cxgbi_device *cdev)
{
	struct cxgbi_pi_page_poolq *q = &cdev->tx_pi_page_poolq;
	struct page *page;

	spin_lock_bh(&q->lock);
	if (!kfifo_out(&q->queue, &page, sizeof(void*)))
		page = NULL;
	spin_unlock_bh(&q->lock);

	return page;
}

static int cxgbi_tx_pi_put_page(struct cxgbi_device *cdev, struct page *page)
{
	struct cxgbi_pi_page_poolq *q = &cdev->tx_pi_page_poolq;

	spin_lock_bh(&q->lock);
	if (likely(q->page_list))
		kfifo_in(&q->queue, &page, sizeof(void*));
	spin_unlock_bh(&q->lock);
	return 0;
}
#endif

static inline void cxgbi_device_destroy(struct cxgbi_device *cdev)
{
	log_debug(1 << CXGBI_DBG_DEV,
		"cdev 0x%p, p# %u.\n", cdev, cdev->nports);
	cxgbi_hbas_remove(cdev);
	cxgbi_device_portmap_cleanup(cdev);
	
	cxgbi_ppm_release(cdev->cdev2ppm(cdev));

	if (cdev->pmap.max_connect)
		cxgbi_free_big_mem(cdev->pmap.port_csk);

#ifdef CXGBI_T10DIF_SUPPORT
	cxgbi_tx_pi_page_pool_free(cdev);
#endif

	kfree(cdev);
}

struct cxgbi_device *cxgbi_device_register(unsigned int extra,
					unsigned int nports)
{
	struct cxgbi_device *cdev;

	cdev = kzalloc(sizeof(*cdev) + extra + nports *
			(sizeof(struct cxgbi_hba *) +
			 sizeof(struct net_device *)),
			GFP_KERNEL);
	if (!cdev) {
		pr_warn("nport %d, OOM.\n", nports);
		return NULL;
	}
	cdev->ports = (struct net_device **)(cdev + 1);
	cdev->hbas = (struct cxgbi_hba **)(((char*)cdev->ports) + nports *
						sizeof(struct net_device *));
	if (extra)
		cdev->dd_data = ((char *)cdev->hbas) +
				nports * sizeof(struct cxgbi_hba *);
	spin_lock_init(&cdev->pmap.lock);

	mutex_lock(&cdev_mutex);
	list_add_tail(&cdev->list_head, &cdev_list);
	mutex_unlock(&cdev_mutex);

	spin_lock(&cdev_rcu_lock);
	list_add_tail_rcu(&cdev->rcu_node, &cdev_rcu_list);
	spin_unlock(&cdev_rcu_lock);

	log_debug(1 << CXGBI_DBG_DEV,
		"cdev 0x%p, p# %u.\n", cdev, nports);
	return cdev;
}
EXPORT_SYMBOL_GPL(cxgbi_device_register);

void cxgbi_device_unregister(struct cxgbi_device *cdev)
{
	log_debug(1 << CXGBI_DBG_DEV,
		"cdev 0x%p, p# %u,%s.\n",
		cdev, cdev->nports, cdev->nports ? cdev->ports[0]->name : "");

	mutex_lock(&cdev_mutex);
	list_del(&cdev->list_head);
	mutex_unlock(&cdev_mutex);

	spin_lock(&cdev_rcu_lock);
	list_del_rcu(&cdev->rcu_node);
	spin_unlock(&cdev_rcu_lock);
	synchronize_rcu();

	cxgbi_device_destroy(cdev);
}
EXPORT_SYMBOL_GPL(cxgbi_device_unregister);

void cxgbi_device_unregister_all(unsigned int flag)
{
	struct cxgbi_device *cdev, *tmp;
	
	mutex_lock(&cdev_mutex);
	list_for_each_entry_safe(cdev, tmp, &cdev_list, list_head) {
		if ((cdev->flags & flag) == flag) {
			mutex_unlock(&cdev_mutex);
			cxgbi_device_unregister(cdev);
			mutex_lock(&cdev_mutex);
		}
	}
	mutex_unlock(&cdev_mutex);
}
EXPORT_SYMBOL_GPL(cxgbi_device_unregister_all);

struct cxgbi_device *cxgbi_device_find_by_lldev(void *lldev)
{
	struct cxgbi_device *cdev, *tmp;

	mutex_lock(&cdev_mutex);
	list_for_each_entry_safe(cdev, tmp, &cdev_list, list_head) {
		if (cdev->lldev == lldev) {
			mutex_unlock(&cdev_mutex);
			return cdev;
		}
	}
	mutex_unlock(&cdev_mutex);
	log_debug(1 << CXGBI_DBG_DEV,
		"lldev 0x%p, NO match found.\n", lldev);
	return NULL;
}
EXPORT_SYMBOL_GPL(cxgbi_device_find_by_lldev);

struct cxgbi_device *cxgbi_device_find_by_netdev(struct net_device *ndev,
							int *port)
{
	struct net_device *vdev = NULL;
	struct cxgbi_device *cdev, *tmp;
	int i;

	if (ndev->priv_flags & IFF_802_1Q_VLAN) {
		vdev = ndev;
		ndev = vlan_dev_real_dev(ndev);
		pr_info("vlan dev %s -> %s.\n", vdev->name, ndev->name);
	}

	mutex_lock(&cdev_mutex);
	list_for_each_entry_safe(cdev, tmp, &cdev_list, list_head) {
		for (i = 0; i < cdev->nports; i++) {
			if (ndev == cdev->ports[i]) {
				cdev->hbas[i]->vdev = vdev;
				mutex_unlock(&cdev_mutex);
				if (port)
					*port = i;
				return cdev;
			}
		}
	}
	mutex_unlock(&cdev_mutex);

	log_debug(1 << CXGBI_DBG_DEV,
		"ndev 0x%p, %s, NO match found.\n", ndev, ndev->name);
	return NULL;
}
EXPORT_SYMBOL_GPL(cxgbi_device_find_by_netdev);

struct cxgbi_device *cxgbi_device_find_by_netdev_rcu(struct net_device *ndev,
							int *port)
{
	struct net_device *vdev = NULL;
	struct cxgbi_device *cdev;
	int i;

	if (ndev->priv_flags & IFF_802_1Q_VLAN) {
		vdev = ndev;
		ndev = vlan_dev_real_dev(ndev);
		pr_info("vlan dev %s -> %s.\n", vdev->name, ndev->name);
	}

	rcu_read_lock();
	list_for_each_entry_rcu(cdev, &cdev_rcu_list, rcu_node) {
		for (i = 0; i < cdev->nports; i++) {
			if (ndev == cdev->ports[i]) {
				cdev->hbas[i]->vdev = vdev;
				rcu_read_unlock();
				if (port)
					*port = i;
				return cdev;
			}
		}
	}
	rcu_read_unlock();

	log_debug(1 << CXGBI_DBG_DEV,
		"ndev 0x%p, %s, NO match found.\n", ndev, ndev->name);
	return NULL;
}
EXPORT_SYMBOL_GPL(cxgbi_device_find_by_netdev_rcu);

static struct cxgbi_device *cxgbi_device_find_by_mac(struct net_device *ndev,
							int *port)
{
	struct net_device *vdev = NULL;
	struct cxgbi_device *cdev, *tmp;
	int i;

	if (ndev->priv_flags & IFF_802_1Q_VLAN) {
		vdev = ndev;
		ndev = vlan_dev_real_dev(ndev);
		pr_info("vlan dev %s -> %s.\n", vdev->name, ndev->name);
	}

	mutex_lock(&cdev_mutex);
	list_for_each_entry_safe(cdev, tmp, &cdev_list, list_head) {
		for (i = 0; i < cdev->nports; i++) {
			if (!memcmp(ndev->dev_addr, cdev->ports[i]->dev_addr,
				MAX_ADDR_LEN)) {	
				cdev->hbas[i]->vdev = vdev;
				mutex_unlock(&cdev_mutex);
				if (port)
					*port = i;
				return cdev;
			}
		}
	}
	mutex_unlock(&cdev_mutex);
	log_debug(1 << CXGBI_DBG_DEV,
		"ndev 0x%p, %s, NO match mac found.\n",
		 ndev, ndev->name);
	return NULL;
}

struct cxgbi_hba *cxgbi_hba_find_by_netdev(struct net_device *dev,
					struct cxgbi_device *cdev)
{
	int i;

	if (dev->priv_flags & IFF_802_1Q_VLAN)
		dev = vlan_dev_real_dev(dev);

	for (i = 0; i < cdev->nports; i++) {
		if (cdev->hbas[i]->ndev == dev)
			return cdev->hbas[i];
	}
	log_debug(1 << CXGBI_DBG_DEV,
		"ndev 0x%p, %s, cdev 0x%p, NO match found.\n",
		dev, dev->name, cdev);
	return NULL;
}

void cxgbi_hbas_remove(struct cxgbi_device *cdev)
{
	int i;
	struct cxgbi_hba *chba;

	log_debug(1 << CXGBI_DBG_DEV,
		"cdev 0x%p, p#%u.\n", cdev, cdev->nports);

	for (i = 0; i < cdev->nports; i++) {
		chba = cdev->hbas[i];
		if (chba) {
			cdev->hbas[i] = NULL;
			iscsi_host_remove(chba->shost);
			pci_dev_put(cdev->pdev);
			iscsi_host_free(chba->shost);
		}
	}
}
EXPORT_SYMBOL_GPL(cxgbi_hbas_remove);

int cxgbi_hbas_add(struct cxgbi_device *cdev, unsigned int max_lun,
		unsigned int max_id, unsigned int max_cmds,
		unsigned int min_cmds, struct scsi_host_template *sht,
		struct scsi_transport_template *stt)
{
	struct cxgbi_hba *chba;
	struct Scsi_Host *shost;
	int i, err;

	log_debug(1 << CXGBI_DBG_DEV, "cdev 0x%p, p#%u.\n", cdev, cdev->nports);

	for (i = 0; i < cdev->nports; i++) {
		shost = iscsi_host_alloc(sht, sizeof(*chba), 1);
		if (!shost) {
			pr_info("0x%p, p%d, %s, host alloc failed.\n",
				cdev, i, cdev->ports[i]->name);
			err = -ENOMEM;
			goto err_out;
		}

		shost->transportt = stt;
		shost->max_lun = max_lun;
		shost->max_id = max_id;
		shost->max_channel = 0;
		shost->max_cmd_len = SCSI_MAX_VARLEN_CDB_SIZE;

		chba = iscsi_host_priv(shost);
		chba->cdev = cdev;
		chba->ndev = cdev->ports[i];
		chba->shost = shost;
		chba->cmds_max = max_cmds;
		chba->cmds_min = min_cmds;

		shost->can_queue = max_cmds - ISCSI_MGMT_CMDS_MAX;

		pr_info("cdev 0x%p, p#%d %s: chba 0x%p.\n",
			cdev, i, cdev->ports[i]->name, chba);

		pci_dev_get(cdev->pdev);
		err = iscsi_host_add(shost, &cdev->pdev->dev);
		if (err) {
			pr_info("cdev 0x%p, p#%d %s, host add failed.\n",
				cdev, i, cdev->ports[i]->name);
			pci_dev_put(cdev->pdev);
			scsi_host_put(shost);
			goto  err_out;
		}

		cdev->hbas[i] = chba;
	}

	return 0;

err_out:
	cxgbi_hbas_remove(cdev);
	return err;
}
EXPORT_SYMBOL_GPL(cxgbi_hbas_add);

/*
 * iSCSI offload
 *
 * - source port management
 *   To find a free source port in the port allocation map we use a very simple
 *   rotor scheme to look for the next free port.
 *
 *   If a source port has been specified make sure that it doesn't collide with
 *   our normal source port allocation map.  If it's outside the range of our
 *   allocation/deallocation scheme just let them use it.
 *
 *   If the source port is outside our allocation range, the caller is
 *   responsible for keeping track of their port usage.
 */

static struct cxgbi_sock *find_sock_on_port(struct cxgbi_device *cdev,
						unsigned char port_id)
{
	struct cxgbi_ports_map *pmap = &cdev->pmap;
	unsigned int i;
	unsigned int used;

	if (!pmap->max_connect || !pmap->used) 
		return NULL;

	spin_lock_bh(&pmap->lock);
	used = pmap->used;
	for (i = 0; used && i < pmap->max_connect; i++) {
		struct cxgbi_sock *csk = pmap->port_csk[i];

		if (csk) {
			if (csk->port_id == port_id) {
				spin_unlock_bh(&pmap->lock);
				return csk;
			}
			used--;
		}
	}
	spin_unlock_bh(&pmap->lock);

	return NULL;
}

static int sock_get_port(struct cxgbi_sock *csk)
{
	struct cxgbi_device *cdev = csk->cdev;
	struct cxgbi_ports_map *pmap = &cdev->pmap;
	unsigned int start;
	int idx;
	__be16 *port;

	if (!pmap->max_connect) {
		pr_err("cdev 0x%p, p#%u %s, NO port map.\n",
			   cdev, csk->port_id, cdev->ports[csk->port_id]->name);
		return -EADDRNOTAVAIL;
	}

	if (csk->csk_family == AF_INET)
		port = &csk->saddr.sin_port;
	else /* ipv6 */
		port = &csk->saddr6.sin6_port;

	if (*port) {
		pr_err("source port NON-ZERO %u.\n",
			ntohs(*port));
		return -EADDRINUSE;
	}

	spin_lock_bh(&pmap->lock);
	if (pmap->used >= pmap->max_connect) {
		spin_unlock_bh(&pmap->lock);
		pr_info("cdev 0x%p, p#%u %s, ALL ports used.\n",
			cdev, csk->port_id, cdev->ports[csk->port_id]->name);
		return -EADDRNOTAVAIL;
	}

	start = idx = pmap->next;
	do {
		if (++idx >= pmap->max_connect)
			idx = 0;
		if (!pmap->port_csk[idx]) {
			pmap->used++;
			*port = htons(pmap->sport_base + idx);
			pmap->next = idx;
			pmap->port_csk[idx] = csk;
			spin_unlock_bh(&pmap->lock);
			cxgbi_sock_get(csk);
			log_debug(1 << CXGBI_DBG_SOCK,
				"cdev 0x%p, p#%u %s, p %u, %u.\n",
				cdev, csk->port_id,
				cdev->ports[csk->port_id]->name,
				pmap->sport_base + idx, pmap->next);
			return 0;
		}
	} while (idx != start);
	spin_unlock_bh(&pmap->lock);

	/* should not happen */
	pr_warn("cdev 0x%p, p#%u %s, next %u?\n",
		cdev, csk->port_id, cdev->ports[csk->port_id]->name,
		pmap->next);
	return -EADDRNOTAVAIL;
}

static void sock_put_port(struct cxgbi_sock *csk)
{
	struct cxgbi_device *cdev = csk->cdev;
	struct cxgbi_ports_map *pmap = &cdev->pmap;
	__be16 *port;

	if (csk->csk_family == AF_INET)
		port = &csk->saddr.sin_port;
	else /* ipv6 */
		port = &csk->saddr6.sin6_port;

	if (*port) {
		int idx = ntohs(*port) - pmap->sport_base;

		*port = 0;
		if (idx < 0 || idx >= pmap->max_connect) {
			pr_err("cdev 0x%p, p#%u %s, port %u OOR.\n",
				cdev, csk->port_id,
				cdev->ports[csk->port_id]->name,
				ntohs(*port));
			return;
		}

		spin_lock_bh(&pmap->lock);
		pmap->port_csk[idx] = NULL;
		pmap->used--;
		spin_unlock_bh(&pmap->lock);

		log_debug(1 << CXGBI_DBG_SOCK,
			"cdev 0x%p, p#%u %s, release %u.\n",
			cdev, csk->port_id, cdev->ports[csk->port_id]->name,
			pmap->sport_base + idx);

		cxgbi_sock_put(csk);
	}
}

/*
 * iscsi tcp connection
 */
void cxgbi_sock_free_cpl_skbs(struct cxgbi_sock *csk)
{
	if (csk->cpl_close) {
		kfree_skb(csk->cpl_close);
		csk->cpl_close = NULL;
	}
	if (csk->cpl_abort_req) {
		kfree_skb(csk->cpl_abort_req);
		csk->cpl_abort_req = NULL;
	}
	if (csk->cpl_abort_rpl) {
		kfree_skb(csk->cpl_abort_rpl);
		csk->cpl_abort_rpl = NULL;
	}
	if (csk->skb_lro_hold) {
		kfree_skb(csk->skb_lro_hold);
		csk->skb_lro_hold = NULL;
	}
	
}
EXPORT_SYMBOL_GPL(cxgbi_sock_free_cpl_skbs);

static struct cxgbi_sock *cxgbi_sock_create(struct cxgbi_device *cdev)
{
	struct cxgbi_sock *csk = kzalloc(sizeof(*csk), GFP_NOIO);

	if (!csk) {
		pr_info("alloc csk %zu failed.\n", sizeof(*csk));
		return NULL;
	}

	spin_lock_init(&csk->lock);
	kref_init(&csk->refcnt);
	skb_queue_head_init(&csk->receive_queue);
	skb_queue_head_init(&csk->write_queue);
	setup_timer(&csk->retry_timer, NULL, (unsigned long)csk);
	rwlock_init(&csk->callback_lock);

	if (cdev->csk_alloc_cpls(csk) < 0) {
		pr_info("csk 0x%p, alloc cpls failed.\n", csk);
		kfree(csk);
		return NULL;
	}

	csk->cdev = cdev;
	csk->flags = 0;
	cxgbi_sock_set_state(csk, CTP_CLOSED);

	log_debug(1 << CXGBI_DBG_SOCK, "cdev 0x%p, new csk 0x%p.\n", cdev, csk);

	return csk;
}

static struct rtable *find_route_ipv4(
#ifdef DEFINED_DST_NEIGH_LOOKUP
					struct flowi4 *fl4,
#endif
					__be32 saddr, __be32 daddr,
					__be16 sport, __be16 dport, u8 tos)
{
	struct rtable *rt;
#ifdef DEFINED_DST_NEIGH_LOOKUP
 	rt = ip_route_output_ports(&init_net, fl4, NULL, daddr, saddr,
                                dport, sport, IPPROTO_TCP, tos, 0);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
	struct flowi4 fl4;

	rt = ip_route_output_ports(&init_net, &fl4, NULL, daddr, saddr,
				dport, sport, IPPROTO_TCP, tos, 0);

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
	struct flowi fl = {
		.oif = 0,
		.nl_u = {
			.ip4_u = {
				.daddr = daddr,
				.saddr = saddr,
				.tos = tos }
			},
		.proto = IPPROTO_TCP,
		.uli_u = {
			.ports = {
				.sport = sport,
				.dport = dport }
			}
	};

	if (ip_route_output_flow(&init_net, &rt, &fl, NULL, 0))
		return NULL;
#else
	rt = ip_route_output_ports(&init_net, NULL, daddr, saddr,
				dport, sport, IPPROTO_TCP, tos, 0);
#endif
	if (IS_ERR(rt))
		return NULL;

	return rt;
}

static struct cxgbi_sock *cxgbi_check_route(struct sockaddr *dst_addr)
{
	struct sockaddr_in *daddr = (struct sockaddr_in *)dst_addr;
	struct dst_entry *dst;
	struct net_device *ndev;
	struct cxgbi_device *cdev;
	struct rtable *rt = NULL;
	struct neighbour *n;
#ifdef DEFINED_DST_NEIGH_LOOKUP
	struct flowi4 fl4;
#endif
	struct cxgbi_sock *csk = NULL;
	unsigned int mtu = 0;
	int port = 0xFFFF;
	int err = 0;

#ifndef DEFINED_DST_NEIGH_LOOKUP
	rt = find_route_ipv4(0, daddr->sin_addr.s_addr, 0,
			daddr->sin_port, 0);
#else
	rt = find_route_ipv4(&fl4, 0, daddr->sin_addr.s_addr, 0,
			daddr->sin_port, 0);
#endif
	if (!rt) {
		pr_info("no route to ipv4 0x%x, port %u.\n",
				be32_to_cpu(daddr->sin_addr.s_addr),
				be16_to_cpu(daddr->sin_port));
		err = -ENETUNREACH;
		goto err_out;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
	dst = &rt->u.dst;
#else
	dst = &rt->dst;
#endif

#if defined DEFINED_DST_NEIGH_LOOKUP
	n = dst_neigh_lookup(dst, &daddr->sin_addr.s_addr);
#elif defined DEFINED_DST_GET_NEIGHBOUR_NOREF
	n = dst_get_neighbour_noref(dst);
#elif defined DEFINED_DST_GET_NEIGHBOUR
	n = dst_get_neighbour(dst);
#else
	n = dst->neighbour;
#endif
	if (!n) {
		pr_info(NIPQUAD_FMT ", port %u, dst no neighbour.\n",
			NIPQUAD(daddr->sin_addr.s_addr), ntohs(daddr->sin_port));
		err = -ENETUNREACH;
		goto rel_rt;
	}
	ndev = n->dev;

	if (rt->rt_flags & (RTCF_MULTICAST | RTCF_BROADCAST)) {
		pr_info("multi-cast route " NIPQUAD_FMT ", port %u, dev %s.\n",
			NIPQUAD(daddr->sin_addr.s_addr),
			ntohs(daddr->sin_port), ndev->name);
		err = -ENETUNREACH;
		goto rel_rt;
	}

	if (ndev->flags & IFF_LOOPBACK) {
		ndev = ip_dev_find(&init_net, daddr->sin_addr.s_addr);
		mtu = ndev->mtu;
		pr_info("rt dev %s, loopback -> %s, mtu %u.\n",
			n->dev->name, ndev->name, mtu);
	}

	cdev = cxgbi_device_find_by_netdev(ndev, &port);
	if (!cdev)
		cdev = cxgbi_device_find_by_mac(ndev, &port);
	if (!cdev) {
		pr_info("dst " NIPQUAD_FMT ", %s, NOT cxgbi device.\n",
			NIPQUAD(daddr->sin_addr.s_addr), ndev->name);
		err = -ENETUNREACH;
		goto rel_rt;
	}
	if (!(ndev->flags & IFF_UP)) {
		pr_info("%s: not up 0x%x.\n", ndev->name, ndev->flags);
		err = -ENETUNREACH;
		goto rel_rt;
	}
	if (!netif_carrier_ok(ndev)) {
		pr_info("%s: link down.\n", ndev->name);
		err = -ENETUNREACH;
		goto rel_rt;
	}
	log_debug(1 << CXGBI_DBG_SOCK,
		"route to " NIPQUAD_FMT ":%u, ndev p#%d,%s, cdev 0x%p.\n",
		NIPQUAD(daddr->sin_addr.s_addr), ntohs(daddr->sin_port),
			   port, ndev->name, cdev);

	csk = cxgbi_sock_create(cdev);
	if (!csk) {
		err = -ENOMEM;
		goto rel_rt;
	}
	csk->cdev = cdev;
	csk->port_id = port;
	csk->mtu = mtu;
	csk->dst = dst;

	csk->csk_family = AF_INET;
	csk->daddr.sin_addr.s_addr = daddr->sin_addr.s_addr;
	csk->daddr.sin_port = daddr->sin_port;
	csk->daddr.sin_family = daddr->sin_family;
	csk->saddr.sin_family = daddr->sin_family;
#ifndef DEFINED_DST_NEIGH_LOOKUP
	csk->saddr.sin_addr.s_addr = rt->rt_src;
#else
	csk->saddr.sin_addr.s_addr = fl4.saddr;
	neigh_release(n);
#endif

	return csk;

rel_rt:
#ifdef DEFINED_DST_NEIGH_LOOKUP
	if (n)
		neigh_release(n);
#endif
	ip_rt_put(rt);
	if (csk)
		cxgbi_sock_closed(csk);
err_out:
	return ERR_PTR(err);
}

#ifdef CXGBI_IPV6_SUPPORT
static struct rt6_info *find_route_ipv6(const struct in6_addr *saddr,
			const struct in6_addr *daddr)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
        struct flowi fl;

        if (saddr)
                ipv6_addr_copy(&fl.fl6_src, saddr);
        if (daddr)
                ipv6_addr_copy(&fl.fl6_dst, daddr);
#else
        struct flowi6 fl;
        if (saddr)
                memcpy(&fl.saddr, saddr, sizeof(struct in6_addr));
        if (daddr)
                memcpy(&fl.daddr, daddr, sizeof(struct in6_addr));
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
	return (struct rt6_info *)ip6_route_output(NULL, &fl);
#else
	return (struct rt6_info *)ip6_route_output(&init_net, NULL, &fl);
#endif
}

static struct cxgbi_sock *cxgbi_check_route6(struct sockaddr *dst_addr)
{
	struct sockaddr_in6 *daddr6 = (struct sockaddr_in6 *)dst_addr;
	struct dst_entry *dst;
	struct net_device *ndev;
	struct cxgbi_device *cdev;
	struct rt6_info *rt = NULL;
	struct neighbour *n;
	struct in6_addr pref_saddr;
	struct cxgbi_sock *csk = NULL;
	unsigned int mtu = 0;
	int port = 0xFFFF;
	int err = 0;

	rt = find_route_ipv6(NULL, &daddr6->sin6_addr);

	if (!rt) {
		pr_info("no route to ipv6 %pI6 port %u\n",
			daddr6->sin6_addr.s6_addr,
			be16_to_cpu(daddr6->sin6_port));
		err = -ENETUNREACH;
		goto err_out;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
	dst = &rt->u.dst;
#else
	dst = &rt->dst;
#endif

#if defined DEFINED_DST_NEIGH_LOOKUP
	n = dst_neigh_lookup(dst, &daddr6->sin6_addr);
#elif defined DEFINED_DST_GET_NEIGHBOUR_NOREF
	n = dst_get_neighbour_noref(dst);
#elif defined DEFINED_DST_GET_NEIGHBOUR
	n = dst_get_neighbour(dst);
#else
	n = dst->neighbour;
#endif
	if (!n) {
		pr_info("%pI6, port %u, dst no neighbour.\n",
			daddr6->sin6_addr.s6_addr,
			be16_to_cpu(daddr6->sin6_port));
		err = -ENETUNREACH;
		goto rel_rt;
	}
	ndev = n->dev;

	if (ipv6_addr_is_multicast(&rt->rt6i_dst.addr)) {
		pr_info("multi-cast route %pI6 port %u, dev %s.\n",
			daddr6->sin6_addr.s6_addr,
			ntohs(daddr6->sin6_port), ndev->name);
		err = -ENETUNREACH;
		goto rel_rt;
	}

#if 0
	/* TODO  ip_dev_find() for ipv6? */
	if (dst->dev->flags & IFF_LOOPBACK)
	if (ndev->flags & IFF_LOOPBACK) {
		ndev = ip_dev_find(&init_net, &daddr6->sin6_addr);
		mtu = ndev->mtu;
		pr_info("rt dev %s, loopback -> %s, mtu %u.\n",
			n->dev->name, ndev->name, mtu);
	}
#endif

	cdev = cxgbi_device_find_by_netdev(ndev, &port);
	if (!cdev)
		cdev = cxgbi_device_find_by_mac(ndev, &port);
	if (!cdev) {
		pr_info("dst %pI6 %s, NOT cxgbi device.\n",
			daddr6->sin6_addr.s6_addr, ndev->name);
		err = -ENETUNREACH;
		goto rel_rt;
	}
	log_debug(1 << CXGBI_DBG_SOCK,
		"route to %pI6 :%u, ndev p#%d,%s, cdev 0x%p.\n",
		daddr6->sin6_addr.s6_addr, ntohs(daddr6->sin6_port),
			   port, ndev->name, cdev);

	csk = cxgbi_sock_create(cdev);
	if (!csk) {
		err = -ENOMEM;
		goto rel_rt;
	}
	csk->cdev = cdev;
	csk->port_id = port;
	csk->mtu = mtu;
	csk->dst = dst;
#if !defined(_PREFSRC_ADDR_) && defined(CXGBI_IPV6_SUPPORT)
	if (ipv6_addr_any(&rt->rt6i_src.addr)) {
#else
	if (ipv6_addr_any(&rt->rt6i_prefsrc.addr)) {
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
		err = ipv6_get_saddr((struct dst_entry *)rt,
			&daddr6->sin6_addr, &pref_saddr);
		if (err) {
			pr_info("failed to get source address to reach %pI6\n",
				&daddr6->sin6_addr);
			goto rel_rt;
		}
#else
		struct inet6_dev *idev = ip6_dst_idev((struct dst_entry *)rt);
		err = ipv6_dev_get_saddr(&init_net, idev ? idev->dev : NULL,
					 &daddr6->sin6_addr, 0, &pref_saddr);
		if (err) {
			pr_info("failed to get source address to reach %pI6\n",
				&daddr6->sin6_addr);
			goto rel_rt;
		}
#endif
	} else {
#ifdef _PREFSRC_ADDR_
		pref_saddr = rt->rt6i_prefsrc.addr;
#else
		pref_saddr = rt->rt6i_src.addr;
#endif
	}

	csk->csk_family = AF_INET6;
	csk->daddr6.sin6_addr = daddr6->sin6_addr;
	csk->daddr6.sin6_port = daddr6->sin6_port;
	csk->daddr6.sin6_family = daddr6->sin6_family;
	csk->saddr6.sin6_family = daddr6->sin6_family;
	csk->saddr6.sin6_addr = pref_saddr;

#ifdef DEFINED_DST_NEIGH_LOOKUP
	neigh_release(n);
#endif
	return csk;

rel_rt:
#ifdef DEFINED_DST_NEIGH_LOOKUP
	if (n)
		neigh_release(n);
#endif
	ip6_rt_put(rt);
	if (csk)
		cxgbi_sock_closed(csk);
err_out:
	return ERR_PTR(err);
}
#endif

void cxgbi_sock_established(struct cxgbi_sock *csk, unsigned int snd_isn,
			unsigned int opt)
{
	csk->write_seq = csk->snd_nxt = csk->snd_una = snd_isn;
	dst_confirm(csk->dst);
	smp_mb();
	cxgbi_sock_set_state(csk, CTP_ESTABLISHED);
}
EXPORT_SYMBOL_GPL(cxgbi_sock_established);

static void cxgbi_inform_iscsi_conn_closing(struct cxgbi_sock *csk)
{
	struct iscsi_conn *conn;

	log_debug(1 << CXGBI_DBG_SOCK,
		"csk 0x%p, state %u, flags 0x%lx, conn 0x%p.\n",
		csk, csk->state, csk->flags, csk->user_data);

	if (csk->state != CTP_ESTABLISHED) {
		read_lock_bh(&csk->callback_lock);
		conn = csk->user_data;
		read_unlock_bh(&csk->callback_lock);
		if (conn)
#ifdef OISCSI_ERR_TCP_CLOSE
			iscsi_conn_failure(conn, ISCSI_ERR_TCP_CONN_CLOSE);
#else
			iscsi_conn_failure(conn, ISCSI_ERR_CONN_FAILED);
#endif
	}
}

void cxgbi_sock_closed(struct cxgbi_sock *csk)
{
	log_debug(1 << CXGBI_DBG_SOCK, "csk 0x%p,%u,0x%lx,%u.\n",
		csk, csk->state, csk->flags, csk->tid);
	cxgbi_sock_set_flag(csk, CTPF_ACTIVE_CLOSE_NEEDED);
	if (csk->state == CTP_ACTIVE_OPEN || csk->state == CTP_CLOSED)
		return;
	if (csk->saddr.sin_port)
		sock_put_port(csk);
	if (csk->dst)
		dst_release(csk->dst);
	csk->cdev->csk_release_offload_resources(csk);
	cxgbi_sock_set_state(csk, CTP_CLOSED);
	cxgbi_inform_iscsi_conn_closing(csk);
	cxgbi_sock_put(csk);
}
EXPORT_SYMBOL_GPL(cxgbi_sock_closed);

static void need_active_close(struct cxgbi_sock *csk)
{
	int data_lost;
	int close_req = 0;

	log_debug(1 << CXGBI_DBG_SOCK, "csk 0x%p,%u,0x%lx,%u.\n",
		csk, csk->state, csk->flags, csk->tid);
	spin_lock_bh(&csk->lock);
	dst_confirm(csk->dst);
	data_lost = skb_queue_len(&csk->receive_queue);
	__skb_queue_purge(&csk->receive_queue);

	if (csk->state == CTP_ACTIVE_OPEN)
		cxgbi_sock_set_flag(csk, CTPF_ACTIVE_CLOSE_NEEDED);
	else if (csk->state == CTP_ESTABLISHED) {
		close_req = 1;
		cxgbi_sock_set_state(csk, CTP_ACTIVE_CLOSE);
	} else if (csk->state == CTP_PASSIVE_CLOSE) {
		close_req = 1;
		cxgbi_sock_set_state(csk, CTP_CLOSE_WAIT_2);
	}

	if (close_req) {
		if (data_lost)
			csk->cdev->csk_send_abort_req(csk);
		else
			csk->cdev->csk_send_close_req(csk);
	}

	spin_unlock_bh(&csk->lock);
}

void cxgbi_sock_fail_act_open(struct cxgbi_sock *csk, int errno)
{
	 pr_info_ipaddr("csk 0x%p,%u,%lx,err %d.\n",
		(&csk->saddr),
		(&csk->daddr),
		csk, csk->state, csk->flags, errno);
		

	cxgbi_sock_set_state(csk, CTP_CONNECTING);
	csk->err = errno;
	cxgbi_sock_closed(csk);
}
EXPORT_SYMBOL_GPL(cxgbi_sock_fail_act_open);

void cxgbi_sock_act_open_req_arp_failure(void *handle, struct sk_buff *skb)
{
	struct cxgbi_sock *csk = (struct cxgbi_sock *)skb->sk;

	log_debug(1 << CXGBI_DBG_SOCK, "csk 0x%p,%u,0x%lx,%u.\n",
		csk, csk->state, csk->flags, csk->tid);
	cxgbi_sock_get(csk);
	spin_lock_bh(&csk->lock);
	if (csk->state == CTP_ACTIVE_OPEN)
		cxgbi_sock_fail_act_open(csk, -EHOSTUNREACH);
	spin_unlock_bh(&csk->lock);
	cxgbi_sock_put(csk);
	__kfree_skb(skb);
}
EXPORT_SYMBOL_GPL(cxgbi_sock_act_open_req_arp_failure);

void cxgbi_sock_rcv_abort_rpl(struct cxgbi_sock *csk)
{
	cxgbi_sock_get(csk);
	spin_lock_bh(&csk->lock);
	cxgbi_sock_set_flag(csk, CTPF_ABORT_RPL_RCVD);
	if (cxgbi_sock_flag(csk, CTPF_ABORT_RPL_PENDING)) {
		cxgbi_sock_clear_flag(csk, CTPF_ABORT_RPL_PENDING);
		if (cxgbi_sock_flag(csk, CTPF_ABORT_REQ_RCVD))
			pr_err("csk 0x%p,%u,0x%lx,%u,ABT_RPL_RSS.\n",
				csk, csk->state, csk->flags, csk->tid);
		cxgbi_sock_closed(csk);
	}
	spin_unlock_bh(&csk->lock);
	cxgbi_sock_put(csk);
}
EXPORT_SYMBOL_GPL(cxgbi_sock_rcv_abort_rpl);

void cxgbi_sock_rcv_peer_close(struct cxgbi_sock *csk)
{
	log_debug(1 << CXGBI_DBG_SOCK, "csk 0x%p,%u,0x%lx,%u.\n",
		csk, csk->state, csk->flags, csk->tid);
	cxgbi_sock_get(csk);
	spin_lock_bh(&csk->lock);

	if (cxgbi_sock_flag(csk, CTPF_ABORT_RPL_PENDING))
		goto done;

	switch (csk->state) {
	case CTP_ESTABLISHED:
		cxgbi_sock_set_state(csk, CTP_PASSIVE_CLOSE);
		break;
	case CTP_ACTIVE_CLOSE:
		cxgbi_sock_set_state(csk, CTP_CLOSE_WAIT_2);
		break;
	case CTP_CLOSE_WAIT_1:
		cxgbi_sock_closed(csk);
		break;
	case CTP_ABORTING:
		break;
	default:
		pr_err("csk 0x%p,%u,0x%lx,%u, bad state.\n",
			csk, csk->state, csk->flags, csk->tid);
	}
	cxgbi_inform_iscsi_conn_closing(csk);
done:
	spin_unlock_bh(&csk->lock);
	cxgbi_sock_put(csk);
}
EXPORT_SYMBOL_GPL(cxgbi_sock_rcv_peer_close);

void cxgbi_sock_rcv_close_conn_rpl(struct cxgbi_sock *csk, u32 snd_nxt)
{
	log_debug(1 << CXGBI_DBG_SOCK, "csk 0x%p,%u,0x%lx,%u.\n",
		csk, csk->state, csk->flags, csk->tid);
	cxgbi_sock_get(csk);
	spin_lock_bh(&csk->lock);

	csk->snd_una = snd_nxt - 1;
	if (cxgbi_sock_flag(csk, CTPF_ABORT_RPL_PENDING))
		goto done;

	switch (csk->state) {
	case CTP_ACTIVE_CLOSE:
		cxgbi_sock_set_state(csk, CTP_CLOSE_WAIT_1);
		break;
	case CTP_CLOSE_WAIT_1:
	case CTP_CLOSE_WAIT_2:
		cxgbi_sock_closed(csk);
		break;
	case CTP_ABORTING:
		break;
	default:
		pr_err("csk 0x%p,%u,0x%lx,%u, bad state.\n",
			csk, csk->state, csk->flags, csk->tid);
	}
done:
	spin_unlock_bh(&csk->lock);
	cxgbi_sock_put(csk);
}
EXPORT_SYMBOL_GPL(cxgbi_sock_rcv_close_conn_rpl);

void cxgbi_sock_rcv_wr_ack(struct cxgbi_sock *csk, unsigned int credits,
			   unsigned int snd_una, int seq_chk)
{
	log_debug(1 << CXGBI_DBG_TOE | 1 << CXGBI_DBG_SOCK,
			"csk 0x%p,%u,0x%lx,%u, cr %u,%u+%u, snd_una %u,%d.\n",
			csk, csk->state, csk->flags, csk->tid, credits,
			csk->wr_cred, csk->wr_una_cred, snd_una, seq_chk);

	spin_lock_bh(&csk->lock);

	csk->wr_cred += credits;
	if (csk->wr_una_cred > csk->wr_max_cred - csk->wr_cred)
		csk->wr_una_cred = csk->wr_max_cred - csk->wr_cred;

	while (credits) {
		struct sk_buff *p = cxgbi_sock_peek_wr(csk);

		if (unlikely(!p)) {
			pr_err("csk 0x%p,%u,0x%lx,%u, cr %u,%u+%u, empty.\n",
				csk, csk->state, csk->flags, csk->tid, credits,
				csk->wr_cred, csk->wr_una_cred);
			break;
		}

		if (unlikely(credits < p->csum)) {
			pr_warn("csk 0x%p,%u,0x%lx,%u, cr %u,%u+%u, < %u.\n",
				csk, csk->state, csk->flags, csk->tid,
				credits, csk->wr_cred, csk->wr_una_cred,
				p->csum);
			p->csum -= credits;
			break;
		} else {
			cxgbi_sock_dequeue_wr(csk);
			credits -= p->csum;
#ifdef CXGBI_T10DIF_SUPPORT
			if (cxgbi_skcb_tx_pi_page(p))
				cxgbi_tx_pi_put_page(csk->cdev,
					cxgbi_skcb_tx_pi_page(p));
#endif
			kfree_skb(p);
		}
	}

	cxgbi_sock_check_wr_invariants(csk);

	if (seq_chk) {
		if (unlikely(before(snd_una, csk->snd_una))) {
			pr_warn("csk 0x%p,%u,0x%lx,%u, snd_una %u/%u.",
				csk, csk->state, csk->flags, csk->tid, snd_una,
				csk->snd_una);
			goto done;
		}

		if (csk->snd_una != snd_una) {
			csk->snd_una = snd_una;
			dst_confirm(csk->dst);
			if (csk->snd_una == csk->snd_nxt)
				cxgbi_sock_clear_flag(csk, CTPF_TX_WAIT_IDLE);
		}
	}

	if (skb_queue_len(&csk->write_queue)) {
		if (csk->cdev->csk_push_tx_frames(csk, 0))
			cxgbi_conn_tx_open(csk);
	} else
		cxgbi_conn_tx_open(csk);
done:
	spin_unlock_bh(&csk->lock);
}
EXPORT_SYMBOL_GPL(cxgbi_sock_rcv_wr_ack);

static unsigned int cxgbi_sock_find_best_mtu(struct cxgbi_sock *csk,
					     unsigned short mtu)
{
	int i = 0;

	while (i < csk->cdev->nmtus - 1 && csk->cdev->mtus[i + 1] <= mtu)
		++i;

	return i;
}

unsigned int cxgbi_sock_select_mss(struct cxgbi_sock *csk, unsigned int pmtu)
{
	unsigned int idx;
	struct dst_entry *dst = csk->dst;

	csk->advmss = dst_metric(dst, RTAX_ADVMSS);

	if (csk->advmss > pmtu - 40)
		csk->advmss = pmtu - 40;
	if (csk->advmss < csk->cdev->mtus[0] - 40)
		csk->advmss = csk->cdev->mtus[0] - 40;
	idx = cxgbi_sock_find_best_mtu(csk, csk->advmss + 40);

	return idx;
}
EXPORT_SYMBOL_GPL(cxgbi_sock_select_mss);

void cxgbi_sock_skb_entail(struct cxgbi_sock *csk, struct sk_buff *skb)
{
	cxgbi_skcb_tcp_seq(skb) = csk->write_seq;
	__skb_queue_tail(&csk->write_queue, skb);
}
EXPORT_SYMBOL_GPL(cxgbi_sock_skb_entail);

void cxgbi_sock_purge_wr_queue(struct cxgbi_sock *csk)
{
	struct sk_buff *skb;

	while ((skb = cxgbi_sock_dequeue_wr(csk)) != NULL)
		kfree_skb(skb);
}
EXPORT_SYMBOL_GPL(cxgbi_sock_purge_wr_queue);

void cxgbi_sock_check_wr_invariants(const struct cxgbi_sock *csk)
{
	int pending = cxgbi_sock_count_pending_wrs(csk);

	if (unlikely(csk->wr_cred + pending != csk->wr_max_cred))
		pr_err("csk 0x%p, tid %u, credit %u + %u != %u.\n",
			csk, csk->tid, csk->wr_cred, pending, csk->wr_max_cred);
}
EXPORT_SYMBOL_GPL(cxgbi_sock_check_wr_invariants);

#ifdef CXGBI_T10DIF_SUPPORT
inline int cxgbi_skb_tx_pi_len_correction(struct sk_buff *skb)
{
	int update_len = 0;

	if (cxgbi_skcb_test_flag(skb, SKCBF_TX_PI)) {
		if (cxgbi_skcb_tx_prot_op(skb) == SCSI_PROT_WRITE_INSERT)
			update_len = cxgbi_skcb_tx_pi_len(skb);
		else if (cxgbi_skcb_tx_prot_op(skb) == SCSI_PROT_WRITE_STRIP)
			update_len = -cxgbi_skcb_tx_pi_len(skb);
	}
	return update_len;
}
EXPORT_SYMBOL_GPL(cxgbi_skb_tx_pi_len_correction);
#endif

static int cxgbi_sock_tx_queue_up(struct cxgbi_sock *csk, struct sk_buff *skb)
{
	struct cxgbi_device *cdev = csk->cdev;
	struct cxgbi_iso_info *iso_cpl;
	int frags = skb_shinfo(skb)->nr_frags + (skb->len != skb->data_len);
	int t10dif_tx_rsvd = 0, iso_tx_rsvd = 0;
	int extra_len, num_pdu, hdr_len;

	/* should hold csk->lock */

	if (csk->state != CTP_ESTABLISHED) {
		log_debug(1 << CXGBI_DBG_PDU_TX,
			"csk 0x%p,%u,0x%lx,%u, EAGAIN.\n",
			csk, csk->state, csk->flags, csk->tid);
		return -EPIPE;
	}

	if (csk->err) {
		log_debug(1 << CXGBI_DBG_PDU_TX,
			"csk 0x%p,%u,0x%lx,%u, EPIPE %d.\n",
			csk, csk->state, csk->flags, csk->tid, csk->err);
		return -EPIPE;
	}

	if (before((csk->snd_win + csk->snd_una), csk->write_seq)) {
		log_debug(1 << CXGBI_DBG_PDU_TX,
			"csk 0x%p,%u,0x%lx,%u, FULL %u-%u >= %u.\n",
			csk, csk->state, csk->flags, csk->tid, csk->write_seq,
			csk->snd_una, csk->snd_win);
		return -ENOBUFS;
	}

#ifdef CXGBI_T10DIF_SUPPORT
	if (cxgbi_skcb_test_flag(skb, SKCBF_TX_PI))
		t10dif_tx_rsvd = cdev->skb_t10dif_txhdr;
#endif
	if (cxgbi_skcb_test_flag(skb, SKCBF_TX_ISO))
		iso_tx_rsvd = cdev->skb_iso_txhdr;

	/*
	 * TODO: add the IMMEDIATE pdu to the head of the queue
 	 */

	if (unlikely(skb_headroom(skb) < (cdev->skb_tx_rsvd +
					t10dif_tx_rsvd + iso_tx_rsvd))) {
		pr_err("csk 0x%p, skb head %u < %u.\n",
			csk, skb_headroom(skb), cdev->skb_tx_rsvd);
		return -EINVAL;
	}

	if (frags >= SKB_WR_LIST_SIZE) {
		pr_err("csk 0x%p, frags %d, %u,%u >%u.\n",
			csk, skb_shinfo(skb)->nr_frags, skb->len,
			skb->data_len, (uint)(SKB_WR_LIST_SIZE));
		return -EINVAL;
	}

	cxgbi_skcb_set_flag(skb, SKCBF_TX_NEED_HDR);
	skb_reset_transport_header(skb);
	cxgbi_sock_skb_entail(csk, skb);

	extra_len =  cxgbi_ulp_extra_len(cxgbi_skcb_ulp_mode(skb));

	if (likely(cxgbi_skcb_test_flag(skb, SKCBF_TX_ISO))) {
		iso_cpl = (struct cxgbi_iso_info *) skb->head;
		num_pdu = iso_cpl->num_pdu;
		hdr_len = cxgbi_skcb_tx_iscsi_hdrlen(skb);
		extra_len = cxgbi_ulp_extra_len(
				cxgbi_skcb_ulp_mode(skb)) * num_pdu +
				hdr_len * (num_pdu - 1);
	}

#ifdef CXGBI_T10DIF_SUPPORT
	csk->write_seq += skb->len +
			extra_len +
			cxgbi_skb_tx_pi_len_correction(skb);
#else
	csk->write_seq += skb->len + extra_len;
#endif

	return 0;
}

static int cxgbi_sock_send_skb(struct cxgbi_sock *csk, struct sk_buff *skb)
{
	struct cxgbi_device *cdev = csk->cdev;
	int len = skb->len;
	int err;

	spin_lock_bh(&csk->lock);
	err = cxgbi_sock_tx_queue_up(csk, skb);
	if (err < 0) {
		spin_unlock_bh(&csk->lock);
		return err;
	}

	if (likely(skb_queue_len(&csk->write_queue)))
		cdev->csk_push_tx_frames(csk, 0);
	spin_unlock_bh(&csk->lock);
	return len;
}

void cxgbi_ddp_set_one_ppod(struct cxgbi_pagepod *ppod,
			struct cxgbi_task_tag_info *ttinfo,
			struct scatterlist **sg_pp, unsigned int *sg_off)
{
	struct scatterlist *sg = sg_pp ? *sg_pp : NULL;
	unsigned int offset = sg_off ? *sg_off : 0;
	dma_addr_t addr = 0UL;
	unsigned int len = 0;
	int i;

	memcpy(ppod, &ttinfo->hdr, sizeof(struct cxgbi_pagepod_hdr));

	if (sg) {
		addr = sg_dma_address(sg);
		len = sg_dma_len(sg);
	}
	
	for (i = 0; i < PPOD_PAGES_MAX; i++) {
		if (sg) {
			ppod->addr[i] = cpu_to_be64(addr + offset);
			offset += PAGE_SIZE;
			if (offset == (len + sg->offset)) {
				offset = 0;
				sg = sg_next(sg);	
				if (sg) {
					addr = sg_dma_address(sg);
					len = sg_dma_len(sg);
				}
			}
		} else 
			ppod->addr[i] = 0ULL;
	}

	/*
	 * the fifth address needs to be repeated in the next ppod, so do
	 * not move sg
	 */
	if (sg_pp) {
		*sg_pp = sg;
		*sg_off = offset;
	}

	if (offset == len) {
		offset = 0;
		sg = sg_next(sg);	
		if (sg) {
			addr = sg_dma_address(sg);
			len = sg_dma_len(sg);
		}
	}
	ppod->addr[i] = sg ? cpu_to_be64(addr + offset) : 0ULL;

#if 0
	print_hex_dump(KERN_CONT, "ppod: ",
			DUMP_PREFIX_OFFSET, 16, 1, (void *)ppod,
			sizeof(struct cxgbi_pagepod), false);
#endif

}
EXPORT_SYMBOL_GPL(cxgbi_ddp_set_one_ppod);

void cxgbi_dump_sgl(const char *cap, struct scatterlist *sgl, int nents)
{
	struct scatterlist *sg;
	int i;

	if (cap)
		pr_info("%s: sgl 0x%p, nents %u.\n", cap, sgl, nents);
	for_each_sg(sgl, sg, nents, i)
		pr_info("\t%d/%u, 0x%p: len %u, off %u, pg 0x%p, dma 0x%llx, %u\n",
			i, nents, sg, sg->length, sg->offset, sg_page(sg),
			sg_dma_address(sg), sg_dma_len(sg));
}
EXPORT_SYMBOL_GPL(cxgbi_dump_sgl);

static int cxgbi_ddp_sgl_check(struct scatterlist *sgl, int nents)
{
	int i;
	int last_sgidx = nents - 1;
	struct scatterlist *sg = sgl;

	for (i = 0; i < nents; i++, sg = sg_next(sg)) {
		unsigned int len = sg->length + sg->offset;
		if ((sg->offset & 0x3) || (i && sg->offset) ||
		    ((i != last_sgidx) && len != PAGE_SIZE)) {
			log_debug(1 << CXGBI_DBG_DDP,
				"sg %u/%u, %u,%u, not aligned.\n",
				i, nents, sg->offset, sg->length);
			goto err_out;
		}
	}

	return 0;

err_out:
	//cxgbi_dump_sgl(NULL, sgl, nents);
	return -EINVAL;
}

static int cxgbi_ddp_reserve(struct cxgbi_conn *cconn,
			struct cxgbi_task_data *tdata, u32 sw_tag,
			unsigned int xferlen, struct cxgbi_pdu_pi_info *pi_info)
{
	struct cxgbi_sock *csk = cconn->cep->csk;
	struct cxgbi_device *cdev = csk->cdev;
	struct cxgbi_ppm *ppm = cdev->cdev2ppm(cdev);
	struct cxgbi_task_tag_info *ttinfo = &tdata->ttinfo;
	struct scatterlist *sgl = ttinfo->sgl;
	unsigned int sgcnt = ttinfo->nents;
	unsigned int sg_offset = sgl->offset;
	int err;

	if (cdev->flags & CXGBI_FLAG_DDP_OFF) {
		log_debug(1 << CXGBI_DBG_DDP,
			"cdev 0x%p DDP off.\n", cdev);
		return -EINVAL;
	}

	if (!ppm || xferlen < DDP_THRESHOLD || !sgcnt ||
	    ppm->tformat.pgsz_idx_dflt >= DDP_PGIDX_MAX) { 
		log_debug(1 << CXGBI_DBG_DDP,
			"ppm 0x%p, pgidx %u, xfer %u, sgcnt %u, NO ddp.\n",
			ppm, ppm ? ppm->tformat.pgsz_idx_dflt : DDP_PGIDX_MAX,
			xferlen, ttinfo->nents);
		return -EINVAL;
	}

	/* make sure the buffer is suitable for ddp */
	if (cxgbi_ddp_sgl_check(sgl, sgcnt) < 0)
		return -EINVAL;

	ttinfo->nr_pages = (xferlen + sgl->offset + (1 << PAGE_SHIFT) - 1) >>
                                PAGE_SHIFT;
	
	/*
 	 * the ddp tag will be used for the itt in the outgoing pdu, 
 	 * the itt genrated by libiscsi is saved in the ppm and can be
 	 * retrieved via the ddp tag
 	 */
	err = cxgbi_ppm_ppods_reserve(ppm, ttinfo->nr_pages, 0, &ttinfo->idx,
				 &ttinfo->tag, (unsigned long)sw_tag);
	if (err < 0) {
		cconn->ddp_full++;
		return err;
	}
	ttinfo->npods = err;

	 /* setup dma from scsi command sgl */
	sgl->offset = 0;
	err = dma_map_sg(&ppm->pdev->dev, sgl, sgcnt, DMA_FROM_DEVICE);
	sgl->offset = sg_offset;
	if (err == 0) {
		pr_info("%s: 0x%x, xfer %u, sgl %u dma mapping err.\n",
			__func__, sw_tag, xferlen, sgcnt);
		goto rel_ppods;
	}
	if (err != ttinfo->nr_pages) {
		pr_info("%s: sw tag 0x%x, xfer %u, sgl %u, dma count %d.\n",
			__func__, sw_tag, xferlen, sgcnt, err);
		cxgbi_dump_sgl(__func__, sgl, sgcnt);
	}

	ttinfo->flags |= CXGBI_PPOD_INFO_FLAG_MAPPED;
	ttinfo->cid = csk->port_id;

	/* T6 fix: put extract flag in iscsi tag so that hw can fetch
 	 * the correct ppod after updating the iscsi offset value */
	/* TODO add sector size info in iscsi tag */
	if (pi_info && pi_info->prot_op && pi_info->offset_updated)
		ttinfo->tag |= (!!(pi_info->prot_op ==
				    ISCSI_PI_OP_SCSI_PROT_READ_PASS ||
				   pi_info->prot_op ==
					ISCSI_PI_OP_SCSI_PROT_READ_STRIP)) <<
							    PPOD_TAG_PI_SHIFT;

	cxgbi_ppm_make_ppod_hdr(ppm, ttinfo->tag, csk->tid, sgl->offset,
				xferlen, pi_info, &ttinfo->hdr);
				
	if (cdev->flags & CXGBI_FLAG_USE_PPOD_OFLDQ) {
		/* write ppod from xmit_pdu (of iscsi_scsi_command pdu) */
		ttinfo->flags |= CXGBI_PPOD_INFO_FLAG_VALID;
	} else {
		/* write ppod from control queue now */
		err = cdev->csk_ddp_set_map(ppm, csk, ttinfo);
		if (err < 0)
			goto rel_ppods;
	}

	return 0;

rel_ppods:
	cxgbi_ppm_ppod_release(ppm, ttinfo->idx);

	if (ttinfo->flags & CXGBI_PPOD_INFO_FLAG_MAPPED) {
		ttinfo->flags &= ~CXGBI_PPOD_INFO_FLAG_MAPPED;
		dma_unmap_sg(&ppm->pdev->dev, sgl, sgcnt, DMA_FROM_DEVICE);
	}
	return -EINVAL;
}

void cxgbi_ddp_ppm_setup(void **ppm_pp, struct cxgbi_device *cdev,
			struct cxgbi_tag_format *tformat, unsigned int ppmax,
			unsigned int llimit, unsigned int start,
			unsigned int rsvd_factor)
{
	int err = cxgbi_ppm_init(ppm_pp, cdev->ports[0], cdev->pdev,
				cdev->lldev, tformat, ppmax, llimit, start,
				rsvd_factor);

	if (err >= 0) {
		struct cxgbi_ppm *ppm = (struct cxgbi_ppm *)(*ppm_pp);

		if (ppm->ppmax < 1024 ||
			ppm->tformat.pgsz_idx_dflt >= DDP_PGIDX_MAX)
			cdev->flags |= CXGBI_FLAG_DDP_OFF;
		err = 0;
	} else
		cdev->flags |= CXGBI_FLAG_DDP_OFF;
}
EXPORT_SYMBOL_GPL(cxgbi_ddp_ppm_setup);

/* from libippm.c */
EXPORT_SYMBOL_GPL(cxgbi_tagmask_set);

/*
 * APIs interacting with open-iscsi libraries
 */

struct page *rsvd_page = NULL;

static void task_release_itt(struct iscsi_task *task, itt_t hdr_itt)
{
	struct scsi_cmnd *sc = task->sc;
	struct iscsi_tcp_conn *tcp_conn = task->conn->dd_data;
	struct cxgbi_conn *cconn = tcp_conn->dd_data;
	struct cxgbi_device *cdev = cconn->chba->cdev;
	struct cxgbi_ppm *ppm = cdev->cdev2ppm(cdev);
	u32 tag = ntohl((__force u32)hdr_itt);

	log_debug(1 << CXGBI_DBG_DDP,
		   "cdev 0x%p, task 0x%p, release tag 0x%x.\n",
		   cdev, task, tag);
	if (sc &&
	    (scsi_bidi_cmnd(sc) || sc->sc_data_direction == DMA_FROM_DEVICE) &&
	    cxgbi_ppm_is_ddp_tag(ppm, tag)) {
		struct cxgbi_task_data *tdata = iscsi_task_cxgbi_data(task);
		struct cxgbi_task_tag_info *ttinfo = &tdata->ttinfo;

		if (!(cdev->flags & CXGBI_FLAG_USE_PPOD_OFLDQ))
			cdev->csk_ddp_clear_map(cdev, ppm, ttinfo);
	
		cxgbi_ppm_ppod_release(ppm, ttinfo->idx);

		dma_unmap_sg(&ppm->pdev->dev, ttinfo->sgl, ttinfo->nents,
                                DMA_FROM_DEVICE);
	}
}

static inline void scmd_get_params(struct scsi_cmnd *sc,
			struct scatterlist **sgl, unsigned int *sgcnt,
			unsigned int *dlen, unsigned int prot)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
	/* No protection support */
       	if (scsi_sg_count(sc)) {
		*sgl = scsi_sglist(sc);	
		*sgcnt = scsi_sg_count(sc);
		*dlen = scsi_bufflen(sc);	
	}
#else
	struct scsi_data_buffer *sdb = prot ? scsi_prot(sc) : scsi_out(sc);

	*sgl = sdb->table.sgl;
	*sgcnt = sdb->table.nents;
	*dlen = sdb->length;
	/* Caution: for protection sdb, sdb->length is invalid */
#endif
}

#ifdef __VARIABLE_DDP_PAGE_SIZE__
static void task_release_realloc_pages(struct cxgbi_task_data *tdata,
				struct cxgbi_tag_format *tformat)
{
	struct scatterlist *sg = tdata->sgl;
	unsigned int pg_order = tformat->pgsz_order[tdata->pgsz_indx];
	int i;

	pr_warn("tdata 0x%p, release %u pages, ddp page idx %u.\n",
		tdata, tdata->npages, tdata->pgsz_indx);

	for (i = 0; i < tdata->npages; i++) {
		pr_warn("release sg 0x%p, page 0x%p.\n", sg, sg_page(sg));
		__free_pages(sg_page(sg), pg_order);
		sg = sg_next(sg);
	}
	kfree(tdata->sgl);
	tdata->sgl = NULL;
	tdata->npages = 0;
}

static int task_realloc_pages(struct cxgbi_task_data *tdata,
				struct cxgbi_tag_format *tformat)
{
	struct scatterlist *sgl, *sg;
	unsigned char indx;
	unsigned int pg_order = tformat->pgsz_order[tdata->pgsz_indx];
	unsigned int pg_shift = pg_order + DDP_PGSZ_BASE_SHIFT;
	unsigned int pg_size = 1 << pg_shift;
	unsigned int pg_nr; 
	unsigned int len = tdata->dlen;
	int i = 0;

	if (ddp_pgidx >= DDP_PGIDX_MAX) {
		unsigned char byte;

		get_random_bytes(&byte, 1);
		tdata->pgsz_indx = indx = byte % DDP_PGIDX_MAX;
	} else
		tdata->pgsz_indx = indx = ddp_pgidx;

	pr_warn("tdata 0x%p, xfer %u, ddp page idx %u.\n",
		tdata, len, tdata->pgsz_indx);

	/* same as PAGE_SIZE */
	if (!indx)
		return 0;

	pg_nr = DIV_ROUND_UP(len, pg_size);

	pr_warn("tdata 0x%p, xfer %u, idx %u, order %u, size %u, npages %u.\n",
		tdata, tdata->dlen, indx, pg_order, pg_size, pg_nr);

	sgl = kzalloc(sizeof(struct scatterlist) * pg_nr, GFP_ATOMIC);
	if (!sgl) {
		pr_warn("tdata 0x%p, xfer %u, ddp page idx %u, OOM %u.\n",
			tdata, tdata->dlen, tdata->pgsz_indx, pg_nr);
		return -ENOMEM;
	}

	sg_init_table(sgl, pg_nr);
	sg = sgl;
	for (i = 0; i < pg_nr; i++) {	
		unsigned int size = min_t(unsigned int, len, pg_size);
		struct page *pg = alloc_pages(GFP_ATOMIC, pg_order);

		if (!pg)
			goto err_page;
 
		sg_set_page(sg, pg, size, 0);
		pr_warn("alloc sg %d, 0x%p, page 0x%p, %u,%u.\n",
			i, sg, sg_page(sg), sg->offset, sg->length);
		if (sg->offset) {
			pr_warn("set sg offset %u -> 0.\n", sg->offset);
			sg->offset = 0;
		}
		if (sg->length < PAGE_SIZE && len > PAGE_SIZE) {
			sg->length = len < pg_size ? len : pg_size;
			size = sg->length;
			pr_warn("set sg len %u.\n", sg->length);
		}

		sg->length = size;

		len -= size;
		sg = sg_next(sg);
	}
	tdata->sgl = sgl;
	tdata->npages = pg_nr;

	pr_warn("tdata 0x%p, xfer %u, ddp page idx %u, %u pages.\n",
		tdata, tdata->dlen, tdata->pgsz_indx, tdata->npages);

	return 0;

err_page:
	pr_warn("tdata 0x%p, xfer %u, ddp page idx %u, OOM %u/%u.\n",
		tdata, tdata->dlen, tdata->pgsz_indx, i, pg_nr);
	sg = sgl;
	while (i >= 0) {
		__free_pages(sg_page(sg), pg_order);
		--i;
		sg = sg_next(sg);
	}
	kfree(sgl);
	return -ENOMEM;	
}

static void task_realloc_copy_payload(struct iscsi_task *task,
				unsigned int offset, unsigned int len)
{
	struct cxgbi_task_data *tdata = iscsi_task_cxgbi_data(task);
	struct scatterlist *to_sgl = NULL;
	struct scatterlist *tsg, *fsg;
	unsigned int to_sgcnt = 0;
	unsigned int tsgoff, fsgoff;
	int i = 0;

	if (!tdata->sgl)
		return;

	scmd_get_params(task->sc, &to_sgl, &to_sgcnt, &tsgoff);

	pr_warn("task 0x%p,0x%p, offset %u, %u, copy f 0x%p,%u, t 0x%p, %u.\n",
		task, tdata, offset, len, tdata->sgl, tdata->npages,
		to_sgl, to_sgcnt);

	tsgoff = offset;
	for_each_sg(to_sgl, tsg, to_sgcnt, i) {
		if (tsgoff < tsg->length)
			break;
		tsgoff -= tsg->length;
	}
	if (!tsg) {
		pr_err("task 0x%p,0x%p, offset %u, %u, ERR in tsg.\n",
			task, tdata, offset, len); 
		return;
	}

	i = 0;
	fsgoff = offset;
	for_each_sg(tdata->sgl, fsg, tdata->npages, i) {
		if (fsgoff < fsg->length)
			break;
		fsgoff -= fsg->length;
	}
	if (!fsg) {
		pr_err("task 0x%p,0x%p, offset %u, %u, ERR in fsg.\n",
			task, tdata, offset, len); 
		return;
	}

	while (len) {
		unsigned int copy = min_t(unsigned int, fsg->length - fsgoff,
					tsg->length - tsgoff);
		void *faddr, *taddr;

#ifdef KMAP_ATOMIC_ARGS
		faddr = kmap_atomic(sg_page(fsg), KM_SOFTIRQ0);
		taddr = kmap_atomic(sg_page(tsg), KM_SOFTIRQ0);
#else
		faddr = kmap_atomic(sg_page(fsg));
		taddr = kmap_atomic(sg_page(tsg));
#endif
		memcpy(taddr + tsg->offset + tsgoff,
			faddr + fsg->offset + fsgoff, copy);
#ifdef KMAP_ATOMIC_ARGS
		kunmap_atomic(taddr, KM_SOFTIRQ0);
		kunmap_atomic(faddr, KM_SOFTIRQ0);
#else
		kunmap_atomic(taddr);
		kunmap_atomic(faddr);
#endif

#if 0
		pr_warn("copy %u, sg 0x%p, pg 0x%p, %u+%u -> 0x%p, 0x%p, %u+%u.\n",
			copy, fsg, sg_page(fsg), fsg->offset, fsgoff,
			tsg, sg_page(tsg), tsg->offset, tsgoff);
#endif
		fsgoff += copy;
		if (fsgoff == fsg->length) {
			fsg = sg_next(fsg);
			fsgoff = 0;
		}
		tsgoff += copy;
		if (tsgoff == tsg->length) {
			tsg = sg_next(tsg);
			tsgoff = 0;
		}

		len -= copy;

		if (!fsg || !tsg) {
			pr_err("task 0x%p,0x%p, offset %u, %u, fsg 0x%p, tsg 0x%p.\n",
				task, tdata, offset, len, fsg, tsg); 
			return;
		}

		if (!sg_page(fsg) || !sg_page(tsg)) {
			pr_err("task 0x%p,0x%p, fsg 0x%p, 0x%p, tsg 0x%p,0x%p.\n",
				task, tdata, fsg, sg_page(fsg),
				tsg, sg_page(tsg));
			return;
		}
	}
}
#endif

static inline u32 cxgbi_build_sw_tag(u32 idx, u32 age)
{
	/* assume idx and age both are < 0x7FFF (32767) */
	return (idx << 16) | age;
}

static inline void cxgbi_decode_sw_tag(u32 sw_tag, int *idx, int *age)
{
	if (age)
		*age = sw_tag & 0x7FFF;
	if (idx)
		*idx = (sw_tag >> 16) & 0x7FFF;
}

#ifdef CXGBI_T10DIF_SUPPORT
static int cxgbi_get_prot_op(unsigned int prot_op)
{
	int ret_op = SCSI_PROT_NORMAL;

	switch (prot_op) {
		case SCSI_PROT_READ_INSERT:
			ret_op = ISCSI_PI_OP_SCSI_PROT_READ_INSERT;
			break;
		case SCSI_PROT_WRITE_STRIP:
			ret_op = ISCSI_PI_OP_SCSI_PROT_WRITE_STRIP;
			break;
		case SCSI_PROT_READ_STRIP:
			ret_op = ISCSI_PI_OP_SCSI_PROT_READ_STRIP;
			break;
		case SCSI_PROT_WRITE_INSERT:
			ret_op = ISCSI_PI_OP_SCSI_PROT_WRITE_INSERT;
			break;
		case SCSI_PROT_READ_PASS:
			ret_op = ISCSI_PI_OP_SCSI_PROT_READ_PASS;
			break;
		case SCSI_PROT_WRITE_PASS:
			ret_op = ISCSI_PI_OP_SCSI_PROT_WRITE_PASS;
			break;
	}
	return ret_op;
}

static int cxgbi_get_dif_type(unsigned int prot_type)
{
	int ret_type = ISCSI_PI_DIF_TYPE_0;

	switch(prot_type) {
		case SCSI_PROT_DIF_TYPE0:
			ret_type = ISCSI_PI_DIF_TYPE_0;
			break;
		case SCSI_PROT_DIF_TYPE1:
			ret_type = ISCSI_PI_DIF_TYPE_1;
			break;
		case SCSI_PROT_DIF_TYPE2:
			ret_type = ISCSI_PI_DIF_TYPE_2;
			break;
		case SCSI_PROT_DIF_TYPE3:
			ret_type = ISCSI_PI_DIF_TYPE_3;
			break;
	}
	return ret_type;
}

static inline unsigned int cxgbi_get_pi_interval(unsigned int sector_size)
{
	return ((sector_size==512)?ISCSI_SCSI_PI_INTERVAL_512:\
			ISCSI_SCSI_PI_INTERVAL_4K);
}
#endif

static int task_reserve_itt(struct iscsi_task *task, itt_t *hdr_itt)
{
	struct scsi_cmnd *sc = task->sc;
	struct iscsi_conn *conn = task->conn;
	struct iscsi_session *sess = conn->session;
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	struct cxgbi_conn *cconn = tcp_conn->dd_data;
	struct cxgbi_device *cdev = cconn->chba->cdev;
	struct cxgbi_ppm *ppm = cdev->cdev2ppm(cdev);
	u32 sw_tag = cxgbi_build_sw_tag(task->itt, sess->age);
	u32 tag = 0;
	int err = -EINVAL;

	if (sc &&
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
	    scsi_sg_count(task->sc) && sc->sc_data_direction == DMA_FROM_DEVICE
#else
	    (scsi_bidi_cmnd(sc) || sc->sc_data_direction == DMA_FROM_DEVICE)
#endif
	) {
		struct cxgbi_task_data *tdata = iscsi_task_cxgbi_data(task);
		struct cxgbi_task_tag_info *ttinfo = &tdata->ttinfo;
		struct cxgbi_pdu_pi_info pi_info;

#ifdef CXGBI_T10DIF_SUPPORT
		pi_info.prot_op = cxgbi_get_prot_op(sc->prot_op);
		if (pi_info.prot_op == ISCSI_PI_OP_SCSI_PROT_READ_INSERT) {
			/* DIX */
			/* sc->prot_type carries 0 */
			pi_info.dif_type = 1; /* Its DIX so default type 1 */
			pi_info.guard = 0;  /* T10DIF TODO IP */
		} else {
			/* DIF */
			pi_info.dif_type = cxgbi_get_dif_type(sc->prot_type);
			pi_info.guard = 1;  /* T10DIF TODO CRC */
		}
		pi_info.interval =
			cxgbi_get_pi_interval(sc->device->sector_size);

		if (cdev->flags & CXGBI_FLAG_T10DIF_OFFSET_UPDATED)
			pi_info.offset_updated = 1;
		else
			pi_info.offset_updated = 0;

#if 0
		printk(KERN_ERR "prot_op %u dif_type %u, interval %u "
			"sc->prot_type %u, guard %u\n",
			pi_info.prot_op, pi_info.dif_type, pi_info.interval,
			sc->prot_type, pi_info.guard);
#endif
#else
		pi_info.prot_op = 0;
#endif

		scmd_get_params(sc, &ttinfo->sgl, &ttinfo->nents,
				&tdata->dlen, 0);
#ifdef __VARIABLE_DDP_PAGE_SIZE__
		if (ttinfo->nents && tdata->dlen >= DDP_THRESHOLD) {
			struct scatterlist *sgl = NULL;
			unsigned int sgcnt = 0;

			task_realloc_pages(tdata, tformat);
			if (tdata->sgl) {
				struct scatterlist *sg;
				int i;

				sgcnt = ttinfo->nents;
				pr_warn("task 0x%p,0x%p, original sgcnt %u.\n",
					task, tdata, sgcnt);

				for_each_sg(sgl, sg, sgcnt, i)
					pr_warn("sgl %d, 0x%p: pg 0x%p, %u,%u.\n",						i, sg, sg_page(sg), sg->offset,
						sg->length);

				ttinfo->sgl = sgl = tdata->sgl;
				ttinfo->nents = sgcnt = tdata->npages;
			}
		}
#endif
		
		err = cxgbi_ddp_reserve(cconn, tdata, sw_tag, tdata->dlen,
					&pi_info);
		if (!err)
			tag = ttinfo->tag;
		else
			log_debug(1 << CXGBI_DBG_DDP,
				"csk 0x%p, R task 0x%p, %u,%u, no ddp.\n",
				cconn->cep->csk, task, tdata->dlen,
				ttinfo->nents);
	}

	if (err < 0) {
		err = cxgbi_ppm_make_non_ddp_tag(ppm, sw_tag, &tag);
		if (err < 0)
		return err;
	}
	/*  the itt need to sent in big-endian order */
	*hdr_itt = (__force itt_t)htonl(tag);

	log_debug(1 << CXGBI_DBG_DDP,
		"cdev 0x%p, task 0x%p, 0x%x(0x%x,0x%x)->0x%x/0x%x.\n",
		cdev, task, sw_tag, task->itt, sess->age, tag, *hdr_itt);
	return 0;
}

void cxgbi_parse_pdu_itt(struct iscsi_conn *conn, itt_t itt, int *idx, int *age)
{
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	struct cxgbi_conn *cconn = tcp_conn->dd_data;
	struct cxgbi_device *cdev = cconn->chba->cdev;
	struct cxgbi_ppm *ppm = cdev->cdev2ppm(cdev);
	u32 tag = ntohl((__force u32) itt);
	u32 sw_bits;

	if (ppm) {
		if (cxgbi_ppm_is_ddp_tag(ppm, tag))
			sw_bits = cxgbi_ppm_get_tag_caller_data(ppm, tag);
        else
            sw_bits = cxgbi_ppm_decode_non_ddp_tag(ppm, tag);
	} else
		sw_bits = tag;

	cxgbi_decode_sw_tag(sw_bits, idx, age); 
	log_debug(1 << CXGBI_DBG_DDP,
		"cdev 0x%p, tag 0x%x/0x%x, -> 0x%x(0x%x,0x%x).\n",
		cdev, tag, itt, sw_bits, idx ? *idx : 0xFFFFF,
		age ? *age : 0xFF);
}
EXPORT_SYMBOL_GPL(cxgbi_parse_pdu_itt);

void cxgbi_conn_tx_open(struct cxgbi_sock *csk)
{
	struct iscsi_conn *conn = csk->user_data;

	if (conn) {
		log_debug(1 << CXGBI_DBG_SOCK,
			"csk 0x%p, cid %d.\n", csk, conn->id);
		iscsi_conn_queue_work(conn);
	}
}
EXPORT_SYMBOL_GPL(cxgbi_conn_tx_open);

/*
 * pdu receive, interact with libiscsi_tcp
 */
static inline int read_pdu_skb(struct iscsi_conn *conn, struct sk_buff *skb,
				unsigned int offset, int offloaded,
				int pi_inline)
{
	int status = 0;
	int bytes_read;

#ifdef CXGBI_T10DIF_SUPPORT
	log_debug(1 << CXGBI_DBG_PDU_RX, "read_pdu_skb: offset %u, "
		"offloaded %u, pi_inline %u\n", offset, offloaded, pi_inline);

	bytes_read = __iscsi_tcp_recv_skb(conn, skb, offset, offloaded,
							pi_inline, &status);
#else
	bytes_read = iscsi_tcp_recv_skb(conn, skb, offset, offloaded,
							&status);
#endif
	switch (status) {
	case ISCSI_TCP_CONN_ERR:
		pr_info("skb 0x%p, off %u, %d, TCP_ERR, %d.\n",
			  skb, offset, offloaded, bytes_read);
		return -EIO;
	case ISCSI_TCP_SUSPENDED:
		log_debug(1 << CXGBI_DBG_PDU_RX,
			"skb 0x%p, off %u, %d, TCP_SUSPEND, rc %d.\n",
			skb, offset, offloaded, bytes_read);
		/* no transfer - just have caller flush queue */
		return bytes_read;
	case ISCSI_TCP_SKB_DONE:
		pr_info("skb 0x%p, off %u, %d, TCP_SKB_DONE, %d.\n",
			skb, offset, offloaded, bytes_read);
		/*
		 * pdus should always fit in the skb and we should get
		 * segment done notifcation.
		 */
		iscsi_conn_printk(KERN_ERR, conn, "Invalid pdu or skb.");
		return -EFAULT;
	case ISCSI_TCP_SEGMENT_DONE:
		log_debug(1 << CXGBI_DBG_PDU_RX,
			"skb 0x%p, off %u, %d, TCP_SEG_DONE, rc %d.\n",
			skb, offset, offloaded, bytes_read);
		return bytes_read;
	default:
		pr_info("skb 0x%p, off %u, %d, invalid status %d, %d.\n",
			skb, offset, offloaded, status, bytes_read);
		return -EINVAL;
	}
}

static int skb_read_pdu_bhs(struct iscsi_conn *conn, struct sk_buff *skb,
			unsigned int offset, unsigned long *flag)

{
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	int pi_inline = 0;

	log_debug(1 << CXGBI_DBG_PDU_RX,
		"conn 0x%p, skb 0x%p, len %u, flag 0x%lx.\n",
		conn, skb, skb->len, *flag);

	if (!iscsi_tcp_recv_segment_is_hdr(tcp_conn)) {
		pr_info("conn 0x%p, skb 0x%p, not hdr.\n", conn, skb);
		iscsi_conn_failure(conn, ISCSI_ERR_PROTO);
		return -EIO;
	}

	if (test_bit(SKCBF_RX_HCRC_ERR, flag)) {
		pr_info("conn 0x%p, skb 0x%p, hcrc.\n", conn, skb);
		if (conn->hdrdgst_en) {
			iscsi_conn_failure(conn, ISCSI_ERR_HDR_DGST);
			return -EIO;
		} else
			pr_info("conn 0x%p, skb 0x%p, hcrc, NOT en.\n",
				conn, skb);
	}

	if (cxgbi_skcb_test_flag(skb, SKCBF_RX_ISCSI_COMPL) &&
	    cxgbi_skcb_test_flag(skb, SKCBF_RX_DATA_DDPD)) {
		/* iscsi completion is enabled for this pdu.
 		 * if data is ddp'ed then update task->exp_datasn to the
 		 * current hdr because hw passed the iscsi hdr of the
 		 * last pdu of the burst. */
		unsigned int itt = ((struct iscsi_data *) skb->data)->itt;
		struct iscsi_task *task = iscsi_itt_to_ctask(conn, itt);
		unsigned int data_sn = ntohl(((struct iscsi_data *)
							skb->data)->datasn);
		if (task && task->sc) { /* is 2nd check necessary? TODO */
			struct iscsi_tcp_task *tcp_task = task->dd_data;
			tcp_task->exp_datasn = data_sn;
		}
	}

	/* if SKCBF_RX_PI is set, we are sure that we recived pi separately
	 * from data. If it not set, we are not sure if we recieved pi or not.
	 * So setting it inline by default. open-iscsi layer checks this
	 * flag only if the prot_op for the command is valid. */
#ifdef CXGBI_T10DIF_SUPPORT
	if (!cxgbi_skcb_test_flag(skb, SKCBF_RX_PI))
		pi_inline = 1;

	/* Chelsio workaround for DIF DDP */
	/* T10DIF_DDP_WORKAROUND */
	if (!cxgbi_skcb_test_flag(skb, SKCBF_PI_OFFSET_UPDATED) &&
	    cxgbi_skcb_test_flag(skb, SKCBF_RX_PI) &&
	    cxgbi_skcb_test_flag(skb, SKCBF_RX_DATA_DDPD)) {
		unsigned int itt = ((struct iscsi_data *) skb->data)->itt;
		struct iscsi_task *task = iscsi_itt_to_ctask(conn, itt);
		unsigned int pi_len = cxgbi_skcb_rx_pi_len(skb);
		unsigned int sector_shift;
		unsigned int num_sector = pi_len >> 3;
		/* Check if this is DIF case. If DIF case then
		 * we need to add pi_len to data_in->offset because
		 * our target didn't add pi len to buffer offset but
		 * open-iscsi need it to copy to proper pi buffer. */
		/* skb-> len is bhs len. */
		if (task && task->sc) {
			sector_shift = ilog2(task->sc->device->sector_size);
			if (((num_sector << sector_shift) + pi_len +
				skb->len) == cxgbi_skcb_rx_pdulen(skb)) {
				unsigned int offset =
					ntohl(((struct iscsi_data *)
							skb->data)->offset);
				num_sector = offset >> sector_shift;
				pi_len = num_sector << 3;
				offset += pi_len;
				((struct iscsi_data *) skb->data)->offset =
								htonl(offset);

				log_debug(1 << CXGBI_DBG_PDU_RX,
					"conn 0x%p, skb 0x%p, pdulen %u, "
					"pi_len %u, updated offset %u.\n",
					conn, skb, cxgbi_skcb_rx_pdulen(skb),
					cxgbi_skcb_rx_pi_len(skb), offset);
			}
		}
	}
#endif

	return read_pdu_skb(conn, skb, offset, 0, pi_inline);
}

static int skb_read_pdu_data(struct iscsi_conn *conn, struct sk_buff *lskb,
			     struct sk_buff *skb, unsigned int offset,
				unsigned long *flag)
{
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	bool offloaded = 0;
	int opcode = tcp_conn->in.hdr->opcode & ISCSI_OPCODE_MASK;

	log_debug(1 << CXGBI_DBG_PDU_RX,
		"conn 0x%p, skb 0x%p, len %u, flag 0x%lx.\n",
		conn, skb, skb->len, *flag);

	if (test_bit(SKCBF_RX_DCRC_ERR, flag)) {
		pr_info("conn 0x%p, skb 0x%p, dcrc error, f 0x%lx.\n",
			conn, lskb, *flag);
		if (conn->datadgst_en) {
			iscsi_conn_failure(conn, ISCSI_ERR_DATA_DGST);
			return -EIO;
		} else
			pr_info("conn 0x%p, skb 0x%p, dcrc, NOT en.\n",
				conn, lskb);
	}

	if (iscsi_tcp_recv_segment_is_hdr(tcp_conn))
		return 0;

	/* coalesced, add header digest length */
	if (lskb == skb && conn->hdrdgst_en)
		offset += ISCSI_DIGEST_SIZE;

	if (test_bit(SKCBF_RX_DATA_DDPD, flag)) {
		struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
		struct iscsi_task *task = iscsi_itt_to_ctask(conn,
						tcp_conn->in.hdr->itt);

		log_debug(1 << CXGBI_DBG_PDU_RX | 1 << CXGBI_DBG_DDP,
			"skb 0x%p, op 0x%x, itt 0x%x, %u ddp'ed.\n",
			skb, opcode, ntohl(tcp_conn->in.hdr->itt),
			tcp_conn->in.datalen);

		if (!task) {
			pr_warn("itt 0x%x, NO task!\n",
				tcp_conn->in.hdr->itt);
			return -EIO;
		}

#ifdef __VARIABLE_DDP_PAGE_SIZE__
		{
			struct iscsi_tcp_task *tcp_task = task->dd_data;
			task_realloc_copy_payload(task, tcp_task->data_offset,
						tcp_conn->in.datalen);
		}
#endif
		offloaded = 1;
	} else if (opcode == ISCSI_OP_SCSI_DATA_IN)
		log_debug(1 << CXGBI_DBG_PDU_RX | 1 << CXGBI_DBG_DDP,
			"skb 0x%p, op 0x%x, itt 0x%x, %u NOT ddp'ed.\n",
			skb, opcode, ntohl(tcp_conn->in.hdr->itt),
			tcp_conn->in.datalen);

#ifdef CXGBI_T10DIF_SUPPORT
	return read_pdu_skb(conn, skb, offset, offloaded, tcp_conn->in.pi_inline);
#else
	return read_pdu_skb(conn, skb, offset, offloaded, 0);
#endif
}

#ifdef CXGBI_T10DIF_SUPPORT
static int skb_read_pdu_pi(struct iscsi_conn *conn, struct sk_buff *lskb,
			     struct sk_buff *skb, unsigned int offset)
{
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	bool offloaded = 0;
	int opcode = tcp_conn->in.hdr->opcode & ISCSI_OPCODE_MASK;

	log_debug(1 << CXGBI_DBG_PDU_RX,
		"conn 0x%p, skb 0x%p, len %u, flag 0x%lx.\n",
		conn, skb, skb->len, cxgbi_skcb_flags(skb));

	if (cxgbi_skcb_test_flag(lskb, SKCBF_RX_PI_ERR)) {
		pr_info("conn 0x%p, skb 0x%p, dcrc 0x%lx.\n",
			conn, lskb, cxgbi_skcb_flags(lskb));
		/* Not sure if we should fail the connection? */
		iscsi_conn_failure(conn, ISCSI_ERR_INTEGRITY_FAILED);
		return -EIO;
	}

	if (iscsi_tcp_recv_segment_is_hdr(tcp_conn))
		return 0;

	if (cxgbi_skcb_test_flag(lskb, SKCBF_RX_PI_DDPD))
		offloaded = 1;
	else if (opcode == ISCSI_OP_SCSI_DATA_IN)
		log_debug(1 << CXGBI_DBG_PDU_RX,
			"skb 0x%p, op 0x%x, itt 0x%x, pi NOT ddp'ed.\n",
			skb, opcode, ntohl(tcp_conn->in.hdr->itt));

	return read_pdu_skb(conn, skb, offset, offloaded, 0);
}

static void piskb_insert_ref_tag(struct iscsi_conn *conn, struct sk_buff *piskb)
{
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	struct iscsi_task *task = iscsi_itt_to_ctask(conn,
                        tcp_conn->in.hdr->itt);
	struct iscsi_tcp_task *tcp_task;
	struct sd_dif_tuple *pi = (struct sd_dif_tuple *) piskb->data;
	unsigned int lba, sector_offset;
	unsigned int num_pi = piskb->len >> 3, i;

	if (!task || scsi_get_prot_op(task->sc) != SCSI_PROT_READ_INSERT)
		return;

	tcp_task = task->dd_data;

	sector_offset = tcp_task->data_offset/task->sc->device->sector_size;
	lba = (u32) scsi_get_lba(task->sc) + sector_offset;

	for (i = 0; i < num_pi; i++, pi++)
		pi->ref_tag = htonl(lba++);
}
#endif

static void csk_return_rx_credits(struct cxgbi_sock *csk, int copied)
{
	struct cxgbi_device *cdev = csk->cdev;
	int must_send;
	u32 credits;

	log_debug(1 << CXGBI_DBG_PDU_RX,
		"csk 0x%p,%u,0x%lu,%u, seq %u, wup %u, thre %u, %u.\n",
		csk, csk->state, csk->flags, csk->tid, csk->copied_seq,
		csk->rcv_wup, cdev->rx_credit_thres,
		csk->rcv_win);

	if (csk->state != CTP_ESTABLISHED)
		return;

	credits = csk->copied_seq - csk->rcv_wup;
	if (unlikely(!credits))
		return;
	if (unlikely(cdev->rx_credit_thres == 0))
		return;

	must_send = credits + 16384 >= csk->rcv_win;
	if (must_send || credits >= cdev->rx_credit_thres)
		csk->rcv_wup += cdev->csk_send_rx_credits(csk, credits);
}


static struct sk_buff *cxgbi_conn_rxq_get_skb(struct cxgbi_sock *csk)
{
	struct sk_buff *skb = skb_peek(&csk->receive_queue);

	if (!skb)
		return NULL;
	if (!(cxgbi_skcb_test_flag(skb, SKCBF_RX_LRO)) &&
		!(cxgbi_skcb_test_flag(skb, SKCBF_RX_STATUS))) {
		log_debug(1 << CXGBI_DBG_PDU_RX,
			"skb 0x%p, NOT ready 0x%lx.\n",
			skb, cxgbi_skcb_flags(skb));
		return NULL;
	}
	__skb_unlink(skb, &csk->receive_queue);
	return skb;
}

#ifndef HAS_SKB_FRAG_PAGE
static inline struct page *skb_frag_page(const skb_frag_t *frag)
{
	return frag->page;
}
#endif

void cxgbi_lro_skb_dump(struct sk_buff *skb)
{
	struct skb_shared_info *ssi = skb_shinfo(skb);
	struct cxgbi_rx_lro_cb *lro_cb = cxgbi_skb_rx_lro_cb(skb);
	struct cxgbi_rx_pdu_cb *pdu_cb = cxgbi_skb_rx_pdu_cb(skb, 0);
	int i;

	pr_info("skb 0x%p, head 0x%p, 0x%p, len %u,%u, frags %u.\n",
		skb, skb->head, skb->data, skb->len, skb->data_len,
		ssi->nr_frags);
	pr_info("skb 0x%p, lro_cb, csk 0x%p, pdu %u, %u.\n",
		skb, lro_cb->csk, lro_cb->pdu_cnt, lro_cb->pdu_totallen);

	for (i = 0; i < lro_cb->pdu_cnt; i++, pdu_cb++)
		pr_info("skb 0x%p, pdu %d, %u, f 0x%lx, seq 0x%x, dcrc 0x%x, "
			"frags %u.\n",
			skb, i, pdu_cb->pdulen, pdu_cb->flags, pdu_cb->seq,
			pdu_cb->ddigest, pdu_cb->frags);
	for (i = 0; i < ssi->nr_frags; i++)
		pr_info("skb 0x%p, frag %d, off %u, sz %u.\n",
			skb, i, ssi->frags[i].page_offset, ssi->frags[i].size);
}
EXPORT_SYMBOL_GPL(cxgbi_lro_skb_dump);

static int rx_skb_lro_read_pdu(struct sk_buff *skb, struct iscsi_conn *conn,
				unsigned int *off_p, int idx)
{
	struct cxgbi_rx_pdu_cb *pdu_cb = cxgbi_skb_rx_pdu_cb(skb, idx);
	unsigned int offset = *off_p;
	int err = 0;

	err = skb_read_pdu_bhs(conn, skb, offset, &pdu_cb->flags);
	if (err < 0) {
		pr_err("conn 0x%p, bhs, skb 0x%p, pdu %d, offset %u.\n",
			conn, skb, idx, offset);
		cxgbi_lro_skb_dump(skb);
		goto done;
	}
	offset += err;

	err = skb_read_pdu_data(conn, skb, skb, offset, &pdu_cb->flags);
	if (err < 0) {
		pr_err("%s: conn 0x%p data, skb 0x%p, pdu %d.\n",
			__func__, conn, skb, idx);
		cxgbi_lro_skb_dump(skb);
		goto done;
	}
	offset += err;
	if(conn->hdrdgst_en)
		offset += ISCSI_DIGEST_SIZE;

done:
	*off_p = offset;
	return err;
}

static int rx_skb_lro(struct sk_buff *skb, struct cxgbi_device *cdev,
			struct cxgbi_sock *csk, struct iscsi_conn *conn,
			unsigned int *read)
{
	struct cxgbi_rx_lro_cb *lro_cb = cxgbi_skb_rx_lro_cb(skb);
	struct cxgbi_rx_pdu_cb *pdu_cb = cxgbi_skb_rx_pdu_cb(skb, 0);
	int cnt = lro_cb->pdu_cnt;
	int i = 0;
	int err = 0;
	unsigned int offset = 0;

	for (i = 0; i < cnt; i++, pdu_cb++) {
		if (!cxgbi_rx_cb_test_flag(pdu_cb, SKCBF_RX_HDR) ||
		    !cxgbi_rx_cb_test_flag(pdu_cb, SKCBF_RX_STATUS)) {
			pr_err("conn 0x%p, skb 0x%p, pdu %d, INCOMPLETE.\n",
				conn, skb, i);
			cxgbi_lro_skb_dump(skb);
			err = -EINVAL;
		} else {
			err = rx_skb_lro_read_pdu(skb, conn, &offset, i);
		}
		if (err < 0)
			goto done;
	}
	
	*read += lro_cb->pdu_totallen;

done:
	__kfree_skb(skb);
	return err;
}

static int rx_skb_coalesced(struct sk_buff *skb, struct cxgbi_device *cdev,
				struct cxgbi_sock *csk, struct iscsi_conn *conn,
				unsigned int *read)
{
	int err = 0;

	*read += cxgbi_skcb_rx_pdulen(skb);

	err = skb_read_pdu_bhs(conn, skb, 0, &cxgbi_skcb_flags(skb));
	if (err < 0) {
		pr_err("bhs, csk 0x%p, skb 0x%p,%u, f 0x%lx, plen %u.\n",
			csk, skb, skb->len, cxgbi_skcb_flags(skb),
			cxgbi_skcb_rx_pdulen(skb));
		cxgbi_dump_bytes("bhs", skb->data, 0, 48);
		goto done;
	}

	err = skb_read_pdu_data(conn, skb, skb, err + cdev->skb_rx_extra,
				&cxgbi_skcb_flags(skb));
	if (err < 0) {
		pr_err("data, csk 0x%p, skb 0x%p,%u, f 0x%lx, plen %u.\n",
			csk, skb, skb->len, cxgbi_skcb_flags(skb),
			cxgbi_skcb_rx_pdulen(skb));
		cxgbi_dump_bytes("bhs", skb->data, 0, 48);
	}

done:
	__kfree_skb(skb);
	return err;
}

static int rx_skb(struct sk_buff *skb, struct cxgbi_device *cdev,
		struct cxgbi_sock *csk, struct iscsi_conn *conn,
		unsigned int *read)
{
	int err = 0;

	*read += cxgbi_skcb_rx_pdulen(skb);

	err = skb_read_pdu_bhs(conn, skb, 0, &cxgbi_skcb_flags(skb));
	if (err < 0) {
		pr_err("bhs, csk 0x%p, skb 0x%p,%u, f 0x%lx, plen %u.\n",
			csk, skb, skb->len, cxgbi_skcb_flags(skb),
			cxgbi_skcb_rx_pdulen(skb));
		cxgbi_dump_bytes("bhs", skb->data, 0, 48);
		goto done;
	}

	if (cxgbi_skcb_test_flag(skb, SKCBF_RX_DATA)) {
		struct sk_buff *dskb = skb_peek(&csk->receive_queue);

		if (!dskb) {
			pr_err("csk 0x%p, NO data.\n", csk);
			err = -EAGAIN;
			goto done;
		}
		__skb_unlink(dskb, &csk->receive_queue);

		err = skb_read_pdu_data(conn, skb, dskb, 0,
					&cxgbi_skcb_flags(skb));
		if (err < 0) {
			pr_err("data, csk 0x%p, skb 0x%p,%u, f 0x%lx, "
				"plen %u, dskb 0x%p %u.\n",
				csk, skb, skb->len,
				cxgbi_skcb_flags(dskb),
				cxgbi_skcb_rx_pdulen(dskb), dskb, dskb->len);
			cxgbi_dump_bytes("bhs", dskb->data, 0, 48);
		}
		__kfree_skb(dskb);
	} else
		err = skb_read_pdu_data(conn, skb, skb, 0,
					&cxgbi_skcb_flags(skb));

#ifdef CXGBI_T10DIF_SUPPORT
	if (cxgbi_skcb_test_flag(skb, SKCBF_RX_PI)) {
		/* pi is not inline and present in next buffer */
		struct sk_buff *piskb;

		piskb = skb_peek(&csk->receive_queue);
		if (!piskb) {
			pr_err("csk 0x%p, NO PI.\n", csk);
			err = -EAGAIN;
			goto done;
		}
		__skb_unlink(piskb, &csk->receive_queue);

		/* if its SCSI_PROT_READ_INSERT case, then pi
 		 * doesn't have the ref_tag but ml expects it.
 		 * Here is the workaround for the problem. */
		piskb_insert_ref_tag(conn, piskb);

		err = skb_read_pdu_pi(conn, skb, piskb, 0);
		if (err < 0) {
			pr_err("pi, csk 0x%p, skb 0x%p,%u, f 0x%lx, plen %u, "
				"piskb 0x%p, %u.\n",
				csk, skb, skb->len, cxgbi_skcb_flags(piskb),
				cxgbi_skcb_rx_pdulen(piskb), piskb, piskb->len);
			cxgbi_dump_bytes("pi", piskb->data, 0, piskb->len);
		}
		__kfree_skb(piskb);
	}
#endif

done:
	__kfree_skb(skb);
	return err;
}

void cxgbi_conn_pdu_ready(struct cxgbi_sock *csk)
{
	struct cxgbi_device *cdev = csk->cdev;
	struct iscsi_conn *conn = csk->user_data;
	struct sk_buff *skb = NULL;
	unsigned int read = 0;
	int err = 0;

	log_debug(1 << CXGBI_DBG_PDU_RX,
		"csk 0x%p, conn 0x%p.\n", csk, conn);

	if (unlikely(!conn || conn->suspend_rx)) {
		log_debug(1 << CXGBI_DBG_PDU_RX,
			"csk 0x%p, conn 0x%p, id %d, suspend_rx %lu!\n",
			csk, conn, conn ? conn->id : 0xFF,
			conn ? conn->suspend_rx : 0xFF);
		return;
	}

	while (!err) {
		skb = cxgbi_conn_rxq_get_skb(csk);
		if (!skb)
			break;

		log_debug(1 << CXGBI_DBG_PDU_RX,
			"csk 0x%p, skb 0x%p,%u,f 0x%lx, pdu len %u.\n",
			csk, skb, skb->len, cxgbi_skcb_flags(skb),
			cxgbi_skcb_rx_pdulen(skb));

		if (cxgbi_skcb_test_flag(skb, SKCBF_RX_LRO)) {
			err = rx_skb_lro(skb, cdev, csk, conn, &read);
		} else if (cxgbi_skcb_test_flag(skb, SKCBF_RX_COALESCED)) {
			err = rx_skb_coalesced(skb, cdev, csk, conn, &read);
		} else {
			err = rx_skb(skb, cdev, csk, conn, &read);
		}
		if (err < 0)
			break;
	}

	log_debug(1 << CXGBI_DBG_PDU_RX, "csk 0x%p, read %u.\n", csk, read);
	if (read) {
		csk->copied_seq += read;
		csk_return_rx_credits(csk, read);
		conn->rxdata_octets += read;
	}

	if (err < 0) {
		pr_info("csk 0x%p,0x%p, rx failed %d, read %u.\n",
			csk, conn, err, read);
		iscsi_conn_failure(conn, ISCSI_ERR_CONN_FAILED);
	}
}
EXPORT_SYMBOL_GPL(cxgbi_conn_pdu_ready);

static int sgl_seek_offset(struct scatterlist *sgl, unsigned int sgcnt,
				unsigned int offset, unsigned int *off,
				struct scatterlist **sgp)
{
	int i;
	struct scatterlist *sg;

	for_each_sg(sgl, sg, sgcnt, i) {
		if (offset < sg->length) {
			*off = offset;
			*sgp = sg;
			return 0;
		}
		offset -= sg->length;
	}
	return -EFAULT;
}

static int sgl_read_to_frags(struct scatterlist *sg, unsigned int sgoffset,
				unsigned int dlen, struct cxgbi_frag *cfrags,
				int cfrag_max, unsigned int *dlimit)
{
	unsigned int datalen = dlen;
	unsigned int sglen = sg->length - sgoffset;
	struct page *page = sg_page(sg);
	int i;

	i = 0;
	do {
		unsigned int copy;

		if (!sglen) {
			sg = sg_next(sg);
			if (!sg) {
				pr_warn("sg %d NULL, len %u/%u.\n",
					i, datalen, dlen);
				return -EINVAL;
			}
			sgoffset = 0;
			sglen = sg->length;
			page = sg_page(sg);

		}
		copy = min(datalen, sglen);
		if (i && page == cfrags[i - 1].page &&
		    sgoffset + sg->offset ==
			cfrags[i - 1].offset + cfrags[i - 1].size) {
			cfrags[i - 1].size += copy;
		} else {
			if (i >= cfrag_max) {
				log_debug(1 << CXGBI_DBG_ISCSI,
					"too many pages %u, dlen %u.\n",
					cfrag_max, dlen);
				/* how much data cfrags can hold */
				*dlimit = dlen - datalen;
				return -EINVAL;
			}

			cfrags[i].page = page;
			cfrags[i].offset = sg->offset + sgoffset;
			cfrags[i].size = copy;
			i++;
		}
		datalen -= copy;
		sgoffset += copy;
		sglen -= copy;
	} while (datalen);

	return i;
}


static void task_data_sgl_check(struct iscsi_task *task)
{
	struct scsi_cmnd *sc = task->sc;
	struct cxgbi_task_data *tdata = iscsi_task_cxgbi_data(task);
	struct scatterlist *sg, *sgl = NULL;
	unsigned int sgcnt = 0;
	int i;

	tdata->flag = TASK_SGL_CHECKED;
	if (!sc)
		return;

	tdata->flag |= TASK_SGL_COPY;
	scmd_get_params(sc, &sgl, &sgcnt, &tdata->dlen, 0);
	if (!sgl || !sgcnt)
		return;

	for_each_sg(sgl, sg, sgcnt, i)
		if (page_count(sg_page(sg)) < 1)
			return;
			
	tdata->flag &= ~TASK_SGL_COPY;
}

static int task_data_sgl_read(struct iscsi_task *task, unsigned int offset,
				unsigned int count, unsigned int *dlimit)
{
	struct scsi_cmnd *sc = task->sc;
	struct cxgbi_task_data *tdata = iscsi_task_cxgbi_data(task);
	struct scatterlist *sgl = NULL;
	struct scatterlist *sg;
	unsigned int dlen = 0;
	unsigned int sgcnt;
	int err;
	int frags_to_read = MAX_PDU_FRAGS;

	if (!sc)
		return 0;

	if (scsi_get_prot_op(sc))
		frags_to_read = MAX_PDU_FRAGS - MAX_PROT_FRAGS;

	scmd_get_params(sc, &sgl, &sgcnt, &dlen, 0);
	if (!sgl || !sgcnt)
		return 0;

	err = sgl_seek_offset(sgl, sgcnt, offset, &tdata->sgoffset, &sg);
	if (err < 0) {
		pr_warn("tpdu max, sgl %u, bad offset %u/%u.\n",
			sgcnt, offset, tdata->dlen);
		return err;
	}
	err = sgl_read_to_frags(sg, tdata->sgoffset, count,
				tdata->cfrags, frags_to_read, dlimit);
	if (err < 0) {
		log_debug(1 << CXGBI_DBG_ISCSI,
			"sgl max limit, sgl %u, offset %u, %u/%u, dlimit %u.\n",
			sgcnt, offset, count, tdata->dlen, *dlimit);
		return err;
	}
	tdata->offset = offset;
	tdata->count = count;
	tdata->nr_cfrags = err;
	tdata->total_count = tdata->pi_len + count;
	tdata->total_offset = tdata->prot_offset + offset;

	log_debug(1 << CXGBI_DBG_ISCSI | 1 << CXGBI_DBG_PDU_TX,
		"task_data_sgl_read: offset %u, count %u,\n"
		"err %u, total_count %u, total_offset %u\n",
		offset, count, err,  tdata->total_count, tdata->total_offset);

	return 0;
}

int sgl_read_copy_to_new_page(struct scatterlist *sg,
			unsigned int sgoffset, unsigned int dlen,
			struct cxgbi_frag *cfrags,
			struct page *page)
{
	void *dst_addr, *src_addr;
	unsigned int sglen = sg->length - sgoffset;
	unsigned int datalen = dlen, copy, offset = 0;
	int ret = 0;
	struct page *src_page = sg_page(sg);

	if (dlen > PAGE_SIZE) {
		pr_warn("err copy size exceed %u/%lu\n", dlen, PAGE_SIZE);
		return -EINVAL;
	}
	/* too many pi fragments are passed to us. Need to copy pi */
	dst_addr = page_address(page);

	if (!sglen)
		sgoffset = 0;
	/* read and copy pi_len bytes from sg to page */
	do {
		if (!sglen) {
			sg = sg_next(sg);
			if (unlikely(!sg)) {
				pr_warn("sg NULL, len %u/%u.\n",
					datalen, dlen);
				ret = -EINVAL;
				goto out;
			}
			sglen = sg->length;
			src_page = sg_page(sg);
		}
		copy =  min(datalen, sglen);

#ifdef KMAP_ATOMIC_ARGS
		src_addr = kmap_atomic(src_page, KM_SOFTIRQ0);
#else
		src_addr = kmap_atomic(src_page);
#endif
		memcpy(dst_addr + offset,
			src_addr + sg->offset + sgoffset,
			copy);
		offset += copy;
		datalen -= copy;
		sglen -= copy;
		sgoffset = 0;
#ifdef KMAP_ATOMIC_ARGS
		kunmap_atomic(src_addr, KM_SOFTIRQ0);
#else
		kunmap_atomic(src_addr);
#endif
	} while (datalen);

	ret = 1;
	cfrags[0].page = page;
	cfrags[0].offset = 0;
	cfrags[0].size = dlen;

out:
	return ret;
}

#ifdef CXGBI_T10DIF_SUPPORT
static int task_data_prot_sgl_read(struct iscsi_task *task,
		unsigned int prot_offset, unsigned int pi_len)
{
	struct scsi_cmnd *sc = task->sc;
	struct cxgbi_task_data *tdata = iscsi_task_cxgbi_data(task);
	struct scatterlist *sgl = NULL;
	struct scatterlist *sg;
	unsigned int dlen = 0, dlimit = 0;
	unsigned int sgcnt;
	int err;

	if (!sc)
		return 0;

	scmd_get_params(sc, &sgl, &sgcnt, &dlen, 1);
	if (!sgl || !sgcnt)
		return 0;

	err = sgl_seek_offset(sgl, sgcnt, prot_offset, &tdata->prot_sgoffset, &sg);
	if (err < 0) {
		pr_warn("prot tpdu max, sgl %u, bad offset %u/%u.\n",
			sgcnt, prot_offset, tdata->dlen);
		return err;
	}
	err = sgl_read_to_frags(sg, tdata->prot_sgoffset, pi_len,
				tdata->prot_cfrags, MAX_PROT_FRAGS, &dlimit);
	if (err < 0) {
		/* too many pi fragments are passed to us. Need to copy pi */
		if (!tdata->skb) {
			/* 1 page is enough. It can accomodate pi for 256KB data */
			tdata->pi_page = cxgbi_tx_pi_get_page(tdata->cdev);
			if (!tdata->pi_page) {
				pr_err(
				"task 0x%p, mem alloc failed for pi tx page\n",
				task);
				return -ENOMEM;
			}
		}
		err = sgl_read_copy_to_new_page(sg, tdata->prot_sgoffset, pi_len,
				tdata->prot_cfrags, tdata->pi_page);
		if (err < 0) {
			pr_err("prot tpdu max sgl %u, err bad offset %u/%u\n",
					sgcnt, prot_offset, tdata->dlen);
			cxgbi_tx_pi_put_page(tdata->cdev, tdata->pi_page);
			tdata->pi_page = NULL;
			return err;
		}
		tdata->flag |= TASK_USE_POOLPI_PAGE;
	}
	tdata->prot_offset = prot_offset;
	tdata->pi_len = pi_len;
	tdata->prot_nr_cfrags = err;

	log_debug(1 << CXGBI_DBG_ISCSI | 1 << CXGBI_DBG_PDU_TX,
	"task_data_prot_sgl_read: task 0x%p, prot_offset %u, pi_len %u, "
	"prot_nr_cfrags %u\n", task, prot_offset, pi_len, err);

	return 0;
}

static inline void cxgbi_tx_pi_inline(struct scsi_cmnd *sc,
			unsigned int *pi_inline, unsigned int *need_prot_sg)
{
	if (!sc)
		return;
	switch(scsi_get_prot_op(sc)) {
	case SCSI_PROT_WRITE_INSERT:
		/* count calculation includes pi bytes */
		*pi_inline = 1;
		/* No prot_sg processing here, because no prot_sg provided */
		*need_prot_sg = 0;
		break;
	case SCSI_PROT_WRITE_PASS:
		/* count calculation includes pi bytes */
		*pi_inline = 1;
		/* need to send pi_len bytes from prot_sg */
		*need_prot_sg = 1;
		break;
	case SCSI_PROT_WRITE_STRIP:
		/* count calculation doesn't include pi bytes */
		*pi_inline = 0;
		/* need to send pi_len bytes from prot_sg  */
		*need_prot_sg = 1;
		break;
	}
}

static int task_data_prot_sgl_handle(struct iscsi_task *task,
			unsigned int prot_offset, unsigned int pi_len,
			unsigned int pi_inline, unsigned int need_prot_sg)
{
	struct scsi_cmnd *sc = task->sc;
	struct cxgbi_task_data *tdata = iscsi_task_cxgbi_data(task);
	int err = 0;
	unsigned int count = 0;

	if (need_prot_sg && !scsi_prot_sg_count(sc)) {
		count = -EINVAL;
		goto out;
	}

	/* 'count' includes size of PI bytes also.
	 * Calculate how much PI data (say pi_len) and data (count)
	 * can be accomodated in count bytes. We always wants to send
	 * data in multiple of sector size. */

	/* Read pi_len bytes from prot_sg */
	if (need_prot_sg)
		/* prot_sg doesn't set total length so calculate it based on
		 * tdata->dlen. The prot_sg must have the data equal to
		 * calculated length, otherwise indicate BUG() */
		err = task_data_prot_sgl_read(task,
					prot_offset, pi_len);
	else {
		/* PROT_SCSI_WRITE_INSERT */
		tdata->prot_offset = prot_offset;
		tdata->pi_len = pi_len;
	}
	if (err < 0) {
		count = err;
		goto out;
	}
out:
	return count;
}

static inline int cxgbi_data_pi_len(struct scsi_cmnd *sc,
			unsigned int total_len, unsigned int *pi_len)
{
	unsigned int sector_size = sc->device->sector_size +
		(scsi_get_prot_op(sc)== SCSI_PROT_WRITE_STRIP ? 0 : 8);
	unsigned int num_sector = total_len/sector_size;
	unsigned int data_len = num_sector * sc->device->sector_size;

	*pi_len = num_sector << 3;

	return data_len;
}
#endif

static inline void tx_skb_setmode(struct sk_buff *skb, int hcrc, int dcrc)
{
	if (hcrc || dcrc) {
		u8 submode = 0;

		if (hcrc)
			submode |= 1;
		if (dcrc)
			submode |= 2;
		cxgbi_skcb_ulp_mode(skb) = (ULP2_MODE_ISCSI << 4) | submode;
	} else
		cxgbi_skcb_ulp_mode(skb) = 0;
}

#if 0
static int cxgbi_send_nopout(struct iscsi_conn *conn, int dlen)
{
	struct iscsi_session *session = conn->session;
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	struct cxgbi_conn *cconn = tcp_conn->dd_data;
	struct cxgbi_device *cdev = cconn->chba->cdev;
	struct cxgbi_sock *csk = (cconn && cconn->cep) ? cconn->cep->csk : NULL;
	struct iscsi_nopout *hdr;
	struct sk_buff *skb;
	int err = 0;

	skb = alloc_skb(cdev->skb_tx_rsvd + sizeof(struct iscsi_hdr)
				+ dlen, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, cdev->skb_tx_rsvd);
	hdr = (struct iscsi_nopout *)skb->data;
 
        memset(hdr, 0, sizeof(struct iscsi_hdr) + dlen);
        hdr->opcode = ISCSI_OP_NOOP_OUT | ISCSI_OP_IMMEDIATE;
        hdr->flags = ISCSI_FLAG_CMD_FINAL;
 
	hdr->itt = RESERVED_ITT;
	hdr->ttt = RESERVED_ITT;
	hdr->exp_statsn = cpu_to_be32(conn->exp_statsn);
	hdr->cmdsn = cpu_to_be32(session->cmdsn);
	if (dlen)
		hton24(hdr->dlength, dlen);

	skb_put(skb, sizeof(struct iscsi_hdr) + dlen);
	tx_skb_setmode(skb, conn->hdrdgst_en, dlen ? conn->datadgst_en : 0);

	cxgbi_skcb_set_flag(skb, SKCBF_TX_PUSH);

	spin_lock_bh(&csk->lock);
	err = cxgbi_sock_tx_queue_up(csk, skb);
	spin_unlock_bh(&csk->lock);

	if (err < 0) {
		pr_err("csk 0x%p, dlen %d, err %d.\n", csk, dlen, err);
		kfree_skb(skb);
	} 
	
	return err;
}
#endif /* !defined(CXGBI_T10DIF_SUPPORT) */

int cxgbi_conn_alloc_pdu(struct iscsi_task *task, u8 op)
{
	struct iscsi_conn *conn = task->conn;
	struct iscsi_session *session = task->conn->session;
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	struct cxgbi_conn *cconn = tcp_conn->dd_data;
	struct cxgbi_device *cdev = cconn->chba->cdev;
	struct cxgbi_sock *csk = (cconn && cconn->cep) ? cconn->cep->csk : NULL;
	struct iscsi_tcp_task *tcp_task = task->dd_data;
	struct cxgbi_task_data *tdata = iscsi_task_cxgbi_data(task);
	struct scsi_cmnd *sc = task->sc;
	int headroom = SKB_TX_ISCSI_PDU_HEADER_MAX;
	int t10dif_tx_rsvd = 0;
	unsigned int max_txdata_len = conn->max_xmit_dlength;
#ifdef CXGBI_T10DIF_SUPPORT
	unsigned int pi_inline = 0, need_prot_sg = 0;
	unsigned int pi_len, num_sector;
#endif
	unsigned int iso_tx_rsvd = 0, local_iso_info = 0;
	int err = 0;

	if (!tcp_task || !tdata) {
		pr_err("task 0x%p, tcp_task 0x%p, tdata 0x%p.\n",
			task, tcp_task, tdata);
		return -ENOMEM;
	}
	if (!csk) {
		pr_err("task 0x%p, csk gone.\n", task);
		return -EPIPE;
	}

	op &= ISCSI_OPCODE_MASK;

	/* alignment check: 1st PDU in FFP */
	if (!(cxgbi_sock_flag(csk, CTPF_PEER_CHECKED)) &&
	    op != ISCSI_OP_LOGIN) {
		struct iscsi_session *sess = conn->session;

		csk->xmit_dlength_save = conn->max_xmit_dlength;
		cxgbi_sock_set_flag(csk, CTPF_PEER_CHECKED);

		if (strstr(sess->targetname, cht_idstr)) {
			int err = 0;

			pr_info("conn 0x%p. csk 0x%p, chelsio target, 0x%x.\n",
				conn, csk, csk->write_seq);

			cxgbi_sock_set_flag(csk, CTPF_PEER_ULP);

			/*
		 	 * if current tcp seq. not aligned, send a nop-out, so
		 	 * the next pdu will start on the 8-byte boundary
		 	 */
			cxgbi_sock_set_flag(csk, CTPF_TX_LOGIN_ALIGNED);
#ifdef CXGBI_T10DIF_SUPPORT
			/* WORKAROUND: Do not send nopout with data now if
 			 * t10dif enabled. Because adapter will generate PI for
 			 * it without checking the pdu type */
			if ((csk->write_seq & 0x7U) &&
			    !(cdev->skb_t10dif_txhdr))
#else
			if (csk->write_seq & 0x7U)
#endif
			{
#if 0
				err = cxgbi_send_nopout(conn,
					conn->hdrdgst_en ? 0 : 4);
#endif
				pr_info("conn 0x%p, csk 0x%p, align nop+, %d.\n",
					conn, csk, err);
				if (err < 0)
					cxgbi_sock_clear_flag(csk,
							CTPF_TX_LOGIN_ALIGNED);
			}
		}
	}

	tdata->cdev = cdev;
	tcp_task->dd_data = tdata;
	task->hdr = NULL;

	/*
 	 * payload is aligned to 512, if only header or data digest is enabled,
	 * adjust payload size of the data pdus, so the max pdu size is 8-byte
	 * aligned.
 	 */
	conn->max_xmit_dlength = csk->xmit_dlength_save;
	if ((op == ISCSI_OP_SCSI_DATA_OUT || op == ISCSI_OP_SCSI_CMD) &&
	    cxgbi_sock_flag(csk, CTPF_PEER_ULP) &&
	    ((csk->hcrc_len + csk->dcrc_len) & 0x7)) {
			conn->max_xmit_dlength -= 4;
	}

	if (op == ISCSI_OP_SCSI_DATA_OUT ||
	    (op == ISCSI_OP_SCSI_CMD &&
	     (scsi_bidi_cmnd(sc) || sc->sc_data_direction == DMA_TO_DEVICE))) {
		unsigned int count;
		unsigned int remaining_data_tosend, dlimit = 0;
		unsigned int max_pdu_size, max_num_pdu, num_pdu;
#ifdef CXGBI_T10DIF_SUPPORT
		unsigned last_pi_len = 0, last_prot_offset = 0;
#endif

		/* preseve conn->max_xmit_dlength, becuase it may get updated to
		 * a new value to accomodate pi and to make it exact multiple of
		 * 1 sector + 1 sector PI data or equal to iso size */
		if (task->state == ISCSI_TASK_PENDING)
			tdata->max_xmit_dlength = conn->max_xmit_dlength;

		if (!tdata->offset) {
			task_data_sgl_check(task);
			/* No need to do similar check for prot_sdb, becuase if
 			 * operation is protected, prot_sg is must else its a
 			 * bug. */
		}
		remaining_data_tosend =
			tdata->dlen - tdata->offset - tdata->count;

recalculate_sgl:
		max_txdata_len = tdata->max_xmit_dlength;
		log_debug(1 << CXGBI_DBG_ISCSI | 1 << CXGBI_DBG_PDU_TX,
			"tdata->dlen %u, remaining to send %u "
			"conn->max_xmit_dlength %u, "
			"tdata->max_xmit_dlength %u\n",
			tdata->dlen, remaining_data_tosend,
			conn->max_xmit_dlength, tdata->max_xmit_dlength);

		/* use iso if need to send multiple pdu */
		if (cdev->skb_iso_txhdr && (!csk->disable_iso) &&
			(remaining_data_tosend > tdata->max_xmit_dlength)) {

			/* max 1 pdu data can go with immediate command if
 			 * imm_data_en. */
			if (op == ISCSI_OP_SCSI_CMD &&
			    session->initial_r2t_en)
				goto no_iso;

			max_pdu_size = tdata->max_xmit_dlength +
					ISCSI_PDU_NONPAYLOAD_LEN;

#ifdef CXGBI_T10DIF_SUPPORT
			/* cannot accomodate 65535B data's frags along with pi's 
 			 * frags in 1 skb. */
			if (scsi_get_prot_op(sc) == SCSI_PROT_WRITE_STRIP ||
				scsi_get_prot_op(sc) == SCSI_PROT_WRITE_PASS)
				max_num_pdu =
				 CXGBI_MAX_ISO_DATA_IN_SKB_WITH_PI/max_pdu_size;
			else
#endif
				max_num_pdu =
				 CXGBI_MAX_ISO_DATA_IN_SKB/max_pdu_size;

			num_pdu = (remaining_data_tosend + \
			  tdata->max_xmit_dlength - 1)/tdata->max_xmit_dlength;

			/* how many pdu can be sent in iso */
			if (num_pdu > max_num_pdu)
				num_pdu = max_num_pdu;

			conn->max_xmit_dlength = tdata->max_xmit_dlength * num_pdu;
			max_txdata_len = conn->max_xmit_dlength;
			iso_tx_rsvd = cdev->skb_iso_txhdr;
			local_iso_info = sizeof(struct cxgbi_iso_info);

			log_debug(1 << CXGBI_DBG_ISCSI | 1 << CXGBI_DBG_PDU_TX,
				"max_pdu_size %u, max_num_pdu %u, "
				"max_txdata %u, num_pdu %u\n",
				max_pdu_size, max_num_pdu,
				max_txdata_len, num_pdu);
		}
no_iso:
#ifdef CXGBI_T10DIF_SUPPORT
		cxgbi_tx_pi_inline(sc, &pi_inline, &need_prot_sg);
		if (pi_inline) {
			max_txdata_len = cxgbi_data_pi_len(sc,
				conn->max_xmit_dlength, &pi_len);
			log_debug(1 << CXGBI_DBG_ISCSI | 1 << CXGBI_DBG_PDU_TX,
				"pi_len %u, max_txdata_len %u\n",
				pi_len, max_txdata_len);
		}
#endif
		count  = min_t(unsigned int, max_txdata_len,
				tdata->dlen - tdata->offset - tdata->count);

#ifdef CXGBI_T10DIF_SUPPORT
		if (scsi_get_prot_op(sc)) {
			/* pi_len for count bytes of data */
			num_sector = count/sc->device->sector_size;
			pi_len = num_sector << 3;

			/* We may have to revert to the last prot_offset
 			 * and pi_len values if anything goes wrong while
 			 * reading data sgls. */
			last_pi_len = tdata->pi_len;
			last_prot_offset = tdata->prot_offset;

			err = task_data_prot_sgl_handle(task,
					tdata->prot_offset + tdata->pi_len,
					pi_len, pi_inline, need_prot_sg);
			if (err < 0) {
				log_debug(1 << CXGBI_DBG_ISCSI,
					"task 0x%p, tcp_task 0x%p, tdata 0x%p, "
					"prot sgl err %d\n",
					task, tcp_task, tdata, err);

				goto ret_err;
			}
			if (pi_inline) {
				count = num_sector * sc->device->sector_size;
				conn->max_xmit_dlength = count + pi_len;
			}
			t10dif_tx_rsvd = cdev->skb_t10dif_txhdr;
		}
#endif
		err = task_data_sgl_read(task, tdata->offset + tdata->count,
				count, &dlimit);
		if (unlikely(err < 0)) {
			log_debug(1 << CXGBI_DBG_ISCSI,
				"task 0x%p, tcp_task 0x%p, tdata 0x%p, "
				"sgl err %d, count %u, dlimit %u\n",
				task, tcp_task, tdata, err, count, dlimit);
			if (dlimit) {
				/* need to limit amount of data because number
 				 * of passed sgls are more than what we can
 				 * handle (MAX_PDU_FRAGS).
				 * Do not include any data len above exact
				 * multiple of pdu because ISO calculation above
				 * may again increase sgl requirement and we
				 * will be here forever. */
				remaining_data_tosend = dlimit -
                                        dlimit%tdata->max_xmit_dlength;
				dlimit = 0;
				/* revert back whatever is modified */
				conn->max_xmit_dlength =
						tdata->max_xmit_dlength;
#ifdef CXGBI_T10DIF_SUPPORT
				if (scsi_get_prot_op(sc)) {
					tdata->prot_offset = last_prot_offset;
					tdata->pi_len = last_pi_len;
					if (tdata->flag & TASK_USE_POOLPI_PAGE) {
						cxgbi_tx_pi_put_page(
						   tdata->cdev, tdata->pi_page);
						tdata->pi_page = NULL;
						tdata->flag &=
							~TASK_USE_POOLPI_PAGE;
					}
				}
#endif
				goto recalculate_sgl;
			}

			pr_err("task 0x%p, tcp_task 0x%p, tdata 0x%p, "
				"sgl err %d\n",
				task, tcp_task, tdata, err);
			goto ret_err;
		}

		if ((tdata->flag & TASK_SGL_COPY) ||
		    (tdata->nr_cfrags + tdata->prot_nr_cfrags) > MAX_SKB_FRAGS)
			/* data goes into skb head */
			headroom += conn->max_xmit_dlength;
#if 0
		pr_info("nr_cfrags %u, prot_nr_cfrags %u\n",
			tdata->nr_cfrags, tdata->prot_nr_cfrags);

		pr_info("cxgbi_conn_alloc_pdu: count %u, tdata->dlen %u,"
		"tdata->offset %u, tdata->count %u,\n"
		"tdata->total_count %u tdata->total_offset %u\n",
		count, tdata->dlen, tdata->offset, tdata->count,
		tdata->total_count, tdata->total_offset);
#endif
	}

	tdata->skb = alloc_skb(local_iso_info + cdev->skb_tx_rsvd +
			t10dif_tx_rsvd + iso_tx_rsvd + headroom, GFP_ATOMIC);
	if (!tdata->skb) {
#if 0
		pr_info("alloc skb %u+%u, op 0x%x oom, %u,%u,%u,%u,%u,0x%x.\n",
			cdev->skb_tx_rsvd, headroom, op,
			(unsigned int)SKB_MAX_HEAD(cdev->skb_tx_rsvd),
			(unsigned int)MAX_SKB_FRAGS,
			tdata->nr_cfrags, tdata->offset, tdata->count,
			tdata->flag);
		if (tdata->nr_cfrags) {
			int i;
			struct cxgbi_frag *cfrag = tdata->cfrags;

			for (i = 0; i < tdata->nr_cfrags; i++, cfrag++)
				pr_info("frag %d/%u: pg 0x%p, %u + %u.\n",
					i, tdata->nr_cfrags, cfrag->page,
					cfrag->offset, cfrag->size); 
		}
#endif
		err = -ENOMEM;
		goto ret_err;
	}
	
	skb_reserve(tdata->skb, local_iso_info + cdev->skb_tx_rsvd +
			t10dif_tx_rsvd + iso_tx_rsvd);
	task->hdr = (struct iscsi_hdr *)tdata->skb->data;
	task->hdr_max = SKB_TX_ISCSI_PDU_HEADER_MAX; /* BHS + AHS */

#ifdef CXGBI_T10DIF_SUPPORT
	/* Set SKCBF_TX_PI flag if needed to indicate that skb carries
	 * PI header data */
	if (t10dif_tx_rsvd) {
		cxgbi_skcb_set_flag(tdata->skb, SKCBF_TX_PI);
		if (cdev->flags & CXGBI_FLAG_T10DIF_OFFSET_UPDATED)
			cxgbi_skcb_set_flag(tdata->skb,
						SKCBF_PI_OFFSET_UPDATED);
		cxgbi_skcb_tx_guard_type(tdata->skb) =
			(scsi_host_get_guard(cconn->chba->shost) == \
				SHOST_DIX_GUARD_CRC)?1:0;
		cxgbi_skcb_tx_prot_op(tdata->skb) = scsi_get_prot_op(sc);
		cxgbi_skcb_tx_dif_type(tdata->skb) = scsi_get_prot_type(sc);
		cxgbi_skcb_tx_pi_interval(tdata->skb) =
			(sc->device->sector_size==512) ?\
			ISCSI_SCSI_PI_INTERVAL_512 : ISCSI_SCSI_PI_INTERVAL_4K;
	}
#endif
	if (iso_tx_rsvd)
		cxgbi_skcb_set_flag(tdata->skb, SKCBF_TX_ISO);


	/* data_out uses scsi_cmd's itt */
	if (op != ISCSI_OP_SCSI_DATA_OUT)
		task_reserve_itt(task, &task->hdr->itt);

	log_debug(1 << CXGBI_DBG_ISCSI | 1 << CXGBI_DBG_PDU_TX,
		"task 0x%p, op 0x%x, skb 0x%p,%u+%u/%u, itt 0x%x.\n",
		task, op, tdata->skb, cdev->skb_tx_rsvd, headroom,
		conn->max_xmit_dlength, ntohl(task->hdr->itt));

	return 0;

ret_err:
 	conn->max_xmit_dlength = tdata->max_xmit_dlength;
	return err;
}
EXPORT_SYMBOL_GPL(cxgbi_conn_alloc_pdu);

static int cxgbi_prep_iso_info(struct iscsi_task *task, struct sk_buff *skb,
			unsigned int count, unsigned int pi_len)
{
	/* we have reserved space for it in skb */
	struct cxgbi_iso_info *iso_info = (struct cxgbi_iso_info *)skb->head;
	struct iscsi_r2t_info *r2t = NULL;
	struct cxgbi_task_data *tdata = iscsi_task_cxgbi_data(task);
	struct iscsi_conn *conn = task->conn;
	struct iscsi_session *session = conn->session;
	struct iscsi_tcp_task *tcp_task = task->dd_data;
#ifdef CXGBI_T10DIF_SUPPORT
	struct scsi_cmnd *sc = task->sc;
	unsigned int data_in_pdu, pi_in_pdu;
#endif
	unsigned int num_pdu;
	unsigned int burst_size = 0, r2t_dlength = 0, dlength;
	unsigned int max_pdu_len = tdata->max_xmit_dlength;
	unsigned int segment_offset = 0;

	if (unlikely(!cxgbi_skcb_test_flag(skb, SKCBF_TX_ISO)))
		return 0;

	memset(iso_info, 0, sizeof(struct cxgbi_iso_info));

#ifdef CXGBI_T10DIF_SUPPORT
	if (scsi_get_prot_op(sc) == SCSI_PROT_WRITE_STRIP)
		pi_len = 0; /* DIX case. No need to consider pi in iso */

	if (pi_len) {
		data_in_pdu = cxgbi_data_pi_len(sc,
			tdata->max_xmit_dlength, &pi_in_pdu);
		max_pdu_len = data_in_pdu + pi_in_pdu;
	}
#endif

	if (task->hdr->opcode == ISCSI_OP_SCSI_CMD && session->imm_data_en) {
		iso_info->flags |= CXGBI_ISO_INFO_IMM_ENABLE;
		burst_size = count + pi_len;
	}

	/* update data length in task->hdr->dlength to single pdu */
	dlength = ntoh24(task->hdr->dlength);
	dlength = min(dlength, max_pdu_len);
	hton24(task->hdr->dlength, dlength);

	num_pdu = (count + pi_len + max_pdu_len -1)/max_pdu_len;

	if (iscsi_task_has_unsol_data(task))
		r2t = &task->unsol_r2t;
	else
		r2t = tcp_task->r2t;

	if (r2t) {
		log_debug(1 << CXGBI_DBG_ISCSI | 1 << CXGBI_DBG_PDU_TX,
			"count %u, tdata->count %u, pi_len %u, num_pdu %u,"
			"task->hdr_len %u, r2t->data_length %u, r2t->sent %u\n",
			count, tdata->count, pi_len, num_pdu, task->hdr_len,
			r2t->data_length, r2t->sent);
		r2t_dlength = r2t->data_length - r2t->sent;
		segment_offset = r2t->sent;

		/* update r2t->datasn with number of data-out pdu going in the
		 * iso. */
		r2t->datasn += num_pdu - 1;
	}

	/* T10DIF TODO handle case when unsolicited data-out has data bigger than 1 pdu.
	 * Then r2t->sent == 0 check is not correct */
	if (!r2t || r2t->sent == 0)
		iso_info->flags |= CXGBI_ISO_INFO_FSLICE;

	if (task->hdr->flags & ISCSI_FLAG_CMD_FINAL)
		iso_info->flags |= CXGBI_ISO_INFO_LSLICE;
	/* Sending ISO so do not set final flag in hdr */
	task->hdr->flags &= ~ISCSI_FLAG_CMD_FINAL;

	iso_info->op = task->hdr->opcode;
	iso_info->ahs = task->hdr->hlength;
	iso_info->num_pdu = num_pdu;
	iso_info->mpdu = max_pdu_len;
	iso_info->burst_size = (burst_size + r2t_dlength) >> 2;
	iso_info->len = count + pi_len + task->hdr_len;
	iso_info->segment_offset = segment_offset;
#if 0
	iso_info->datasn_offset = 0;
	iso_info->buffer_offset = 0;
#endif

	cxgbi_skcb_tx_iscsi_hdrlen(skb) = task->hdr_len;
	return 0;
}

int cxgbi_conn_init_pdu(struct iscsi_task *task, unsigned int offset,
			      unsigned int count)
{
	struct iscsi_conn *conn = task->conn;
	struct iscsi_tcp_task *tcp_task = task->dd_data;
	struct cxgbi_task_data *tdata = iscsi_task_cxgbi_data(task);
	struct sk_buff *skb = tdata->skb;
	struct scsi_cmnd *sc = task->sc;
	unsigned int datalen = count, dlimit = 0;
	int i, padlen = iscsi_padding(count);
	struct page *pg;
	int err;
	unsigned int pi_len = 0;
#ifdef CXGBI_T10DIF_SUPPORT
	unsigned int prot_offset = 0, pi_inline = 0, need_prot_sg = 0;
	unsigned int pi_count = 0;
	unsigned int ref_tag;
	unsigned int data_count = 0, data_offset = 0;
#endif
	unsigned int expected_count, expected_offset;

	if (!tcp_task || !tdata || tcp_task->dd_data != tdata) {
		pr_err("task 0x%p,0x%p, tcp_task 0x%p, tdata 0x%p/0x%p.\n",
                        task, task->sc, tcp_task,
			tcp_task ? tcp_task->dd_data : NULL, tdata);
		return -EINVAL;
	}

	log_debug(1 << CXGBI_DBG_ISCSI | 1 << CXGBI_DBG_PDU_TX,
		"task 0x%p,0x%p, skb 0x%p, 0x%x,0x%x,0x%x, %u+%u.\n",
		task, task->sc, skb, (*skb->data) & ISCSI_OPCODE_MASK,
		ntohl(task->cmdsn), ntohl(task->hdr->itt), offset, count);

	skb_put(skb, task->hdr_len);
	tx_skb_setmode(skb, conn->hdrdgst_en, datalen ? conn->datadgst_en : 0);
	if (!count) {
		tdata->count = count;
		tdata->offset = offset;
		tdata->nr_cfrags = 0;
		/* reset pi fields */
#ifdef CXGBI_T10DIF_SUPPORT
		cxgbi_skcb_clear_flag(skb, SKCBF_TX_PI);
		tdata->pi_len = 0;
		tdata->prot_offset = 0;
		tdata->prot_nr_cfrags = 0;
		if (tdata->pi_page) {
			cxgbi_tx_pi_put_page(tdata->cdev, tdata->pi_page);
			tdata->pi_page = NULL;
		}
#endif
		tdata->total_offset = 0;
		tdata->total_count = 0;
		if (tdata->max_xmit_dlength)
			conn->max_xmit_dlength = tdata->max_xmit_dlength;
		cxgbi_skcb_clear_flag(skb, SKCBF_TX_ISO);
		return 0;
	}
	/* Note that tdata->count is just the data length while the passed count
	 * value includes everything midlayer would send out of controller
	 * (i.e. incluing PI). */
	log_debug(1 << CXGBI_DBG_ISCSI | 1 << CXGBI_DBG_PDU_TX,
			"cxgbi_conn_init_pdu: tdata->total_count %u, "
			"tdata->total_offset %u\n",
			tdata->total_count, tdata->total_offset);

	expected_count = tdata->total_count;
	expected_offset = tdata->total_offset;

#ifdef CXGBI_T10DIF_SUPPORT
	cxgbi_tx_pi_inline(sc, &pi_inline, &need_prot_sg);
	if (sc && scsi_get_prot_op(sc)) {
		/* calculate new count, offset, pi_len and prot_offset values */
		data_count = cxgbi_data_pi_len(sc, count, &pi_count);
		data_offset = cxgbi_data_pi_len(sc, offset, &prot_offset);

		log_debug(1 << CXGBI_DBG_ISCSI | 1 << CXGBI_DBG_PDU_TX,
		"data_count %u, data_offset %u, pi_count %u, prot_offset %u\n",
		data_count, data_offset, pi_count, prot_offset);

		if (scsi_get_prot_op(sc) == SCSI_PROT_WRITE_STRIP) {
			expected_count = tdata->count;
			expected_offset = tdata->offset;
		}
	}
#endif
	if (count != expected_count ||
	    offset != expected_offset) {
		/* need to recalculate the size of pi and data */
#ifdef CXGBI_T10DIF_SUPPORT
		if (sc && scsi_get_prot_op(sc)) {
			err = task_data_prot_sgl_handle(task, prot_offset,
				pi_count, pi_inline, need_prot_sg);
			if (err < 0) {
				pr_err("task 0x%p,0x%p, tcp_task 0x%p, "
					"tdata 0x%p/0x%p "
					"prot sgl err %d.\n",
					task, task->sc, tcp_task,
					tcp_task ? tcp_task->dd_data : NULL,
					tdata, err);
				return err;
			}
			if (pi_inline) {
				count = data_count;
				offset = data_offset;
				conn->max_xmit_dlength = count + pi_count;

				log_debug(1 << CXGBI_DBG_ISCSI |
					  1 << CXGBI_DBG_PDU_TX,
					"count %u, offset %u, "
					"conn->max_xmit_dlength to %u\n",
					count, offset, conn->max_xmit_dlength);
			}
		}
#endif
		err = task_data_sgl_read(task, offset, count, &dlimit);
		if (err < 0) {
			pr_err("task 0x%p,0x%p, tcp_task 0x%p, tdata 0x%p/0x%p "
				"dlimit %u, sgl err %d.\n", task, task->sc,
				tcp_task, tcp_task ? tcp_task->dd_data : NULL,
				tdata, dlimit, err);
			return err;
		}
	}
#ifdef CXGBI_T10DIF_SUPPORT
	else {
		if (pi_inline) {
			count = data_count;
			offset = data_offset;
		}
	}
#endif
	/* restore original value of conn->max_xmit_dlength if it was updated
	 * during alloc_pdu. The update in pdu_alloc was needed because
	 * iscsi layer release the data in multiple of conn->max_xmit_dlength.
	 * its needed for pi_inline and iso. */
	conn->max_xmit_dlength = tdata->max_xmit_dlength;

	if (sc) {
		struct cxgbi_frag *cfrag = tdata->cfrags;

		if ((tdata->flag & TASK_SGL_COPY) ||
		    (tdata->nr_cfrags + tdata->prot_nr_cfrags) > MAX_SKB_FRAGS ||
		    (padlen && (tdata->nr_cfrags + tdata->prot_nr_cfrags) ==
					MAX_SKB_FRAGS)) {
			char *dst = skb->data + task->hdr_len;

			/* data fits in the skb's headroom */
			for (i = 0; i < tdata->nr_cfrags; i++, cfrag++) {
#ifdef KMAP_ATOMIC_ARGS
				char *src = kmap_atomic(cfrag->page,
							KM_SOFTIRQ0);
#else
				char *src = kmap_atomic(cfrag->page);
#endif

				memcpy(dst, src + cfrag->offset, cfrag->size);
				dst += cfrag->size;
#ifdef KMAP_ATOMIC_ARGS
				kunmap_atomic(src, KM_SOFTIRQ0);
#else
				kunmap_atomic(src);
#endif
			}
#ifdef CXGBI_T10DIF_SUPPORT
			/* better send prot_frags as frags only and never as
 			 * immediate FIXME*/
			cfrag = tdata->prot_cfrags;
			for(i=0; i < tdata->prot_nr_cfrags; i++, cfrag++) {
#ifdef KMAP_ATOMIC_ARGS
				char *src = kmap_atomic(cfrag->page,
							KM_SOFTIRQ0);
#else
				char *src = kmap_atomic(cfrag->page);
#endif

				memcpy(dst, src + cfrag->offset, cfrag->size);
				dst += cfrag->size;
				pi_len += cfrag->size;
#ifdef KMAP_ATOMIC_ARGS
				kunmap_atomic(src, KM_SOFTIRQ0);
#else
				kunmap_atomic(src);
#endif
			}
#endif
			if (padlen) {
				memset(dst, 0, padlen);
				padlen = 0;
			}
			skb_put(skb, count + pi_len + padlen);
		} else {
			/* data fit into frag_list */
			for (i = 0; i < tdata->nr_cfrags; i++, cfrag++) {
				get_page(cfrag->page);
				skb_fill_page_desc(skb, i, cfrag->page,
					cfrag->offset, cfrag->size);
			}

			skb->len += count;
			skb->data_len += count;
			skb->truesize += count;

#ifdef CXGBI_T10DIF_SUPPORT
			if (tdata->prot_nr_cfrags) {
				pi_len = tdata->pi_len;
				if (!pi_len) {
 				 	/* cannot proceed */
					pr_err("task 0x%p,0x%p, tcp_task 0x%p, "
					    "tdata 0x%p/0x%p, pi_len 0\n",
					    task, sc, tcp_task,
					    tcp_task ? tcp_task->dd_data : NULL,
					    tdata);
					return -EINVAL;
				}
				cfrag = tdata->prot_cfrags;

				for (i = 0; i < tdata->prot_nr_cfrags;
						i++, cfrag++) {
					get_page(cfrag->page);
					skb_fill_page_desc(skb,
						tdata->nr_cfrags + i,
						cfrag->page, cfrag->offset,
						cfrag->size);
				}
				skb->len += pi_len;
				skb->data_len += pi_len;
				skb->truesize += pi_len;
				cxgbi_skcb_tx_pi_sgcnt(skb) =
					tdata->prot_nr_cfrags;
			}
#endif
		}
#ifdef CXGBI_T10DIF_SUPPORT
		if (cxgbi_skcb_test_flag(skb, SKCBF_TX_PI)) {
			if (pi_len)
				BUG_ON((pi_len != tdata->pi_len)); /* DEBUG */
			else
				pi_len = tdata->pi_len;

			cxgbi_skcb_tx_iscsi_hdrlen(skb) = task->hdr_len;
			ref_tag = (u32)(scsi_get_lba(sc) & 0xffffffff) +
				tdata->total_offset/(sc->device->sector_size + 8);
			cxgbi_skcb_tx_pi_ref_tag(skb) = ref_tag;
			/* App tag? */
			if (pi_len) {
				cxgbi_skcb_tx_pi_len(skb) = pi_len;
				cxgbi_skcb_tx_pi_offset(skb) =
						tdata->tx_pi_offset;
				tdata->tx_pi_offset += pi_len;
				if (tdata->flag & TASK_USE_POOLPI_PAGE) {
					cxgbi_skcb_tx_pi_page(skb) =
							tdata->pi_page;
					tdata->pi_page = NULL;
					tdata->flag &= ~TASK_USE_POOLPI_PAGE;
				}
			}
			log_debug(1 << CXGBI_DBG_ISCSI | 1 << CXGBI_DBG_PDU_TX,
			"ref_tag 0x%x, nr_cfrags %u, prot_nr_cfrags %u\n",
			ref_tag, tdata->nr_cfrags, tdata->prot_nr_cfrags);
		}
#endif
	} else {
#ifdef VIRT_TO_HEAD_PAGE
		pg = virt_to_head_page(task->data);
#else
		pg = virt_to_page(task->data);
#endif

		get_page(pg);
		skb_fill_page_desc(skb, 0, pg,
				task->data - (char *)page_address(pg),
				count);
		skb->len += count;
		skb->data_len += count;
		skb->truesize += count;
	}

	if (padlen) {
		i = skb_shinfo(skb)->nr_frags;
		skb_fill_page_desc(skb, skb_shinfo(skb)->nr_frags,
				rsvd_page, 0, padlen);

		skb->data_len += padlen;
		skb->truesize += padlen;
		skb->len += padlen;
	}
	if (likely(count > tdata->max_xmit_dlength))
		cxgbi_prep_iso_info(task, skb, count, pi_len);
	else
		cxgbi_skcb_clear_flag(skb, SKCBF_TX_ISO);

	return 0;
}
EXPORT_SYMBOL_GPL(cxgbi_conn_init_pdu);

int cxgbi_conn_xmit_pdu(struct iscsi_task *task)
{
	struct iscsi_tcp_conn *tcp_conn = task->conn->dd_data;
	struct cxgbi_conn *cconn = tcp_conn->dd_data;
	struct iscsi_tcp_task *tcp_task = task->dd_data;
	struct cxgbi_task_data *tdata = iscsi_task_cxgbi_data(task);
	struct cxgbi_task_tag_info *ttinfo = &tdata->ttinfo;
	struct sk_buff *skb = tdata->skb;
	struct cxgbi_sock *csk = NULL;
	unsigned int datalen;
	int err;
	int pdulen = 0;

	if (!tcp_task || !tdata || tcp_task->dd_data != tdata) {
		pr_err("task 0x%p,0x%p, tcp_task 0x%p, tdata 0x%p/0x%p.\n",
                        task, task->sc, tcp_task,
			tcp_task ? tcp_task->dd_data : NULL, tdata);
		return -EINVAL;
	}

	if (!skb) {
		log_debug(1 << CXGBI_DBG_ISCSI | 1 << CXGBI_DBG_PDU_TX,
			"task 0x%p, skb NULL.\n", task);
		return 0;
	}

	if (cconn && cconn->cep)
		csk = cconn->cep->csk;

	if (!csk) {
		log_debug(1 << CXGBI_DBG_ISCSI | 1 << CXGBI_DBG_PDU_TX,
			"task 0x%p, csk gone.\n", task);
		return -EPIPE;
	}

	datalen = skb->data_len;
	tdata->skb = NULL;

	/* write ppod first if using ofldq to write ppod */
	if (ttinfo->flags & CXGBI_PPOD_INFO_FLAG_VALID) {
		struct cxgbi_ppm *ppm = csk->cdev->cdev2ppm(csk->cdev);

		ttinfo->flags &= ~CXGBI_PPOD_INFO_FLAG_VALID;
		if (csk->cdev->csk_ddp_set_map(ppm, csk, ttinfo) < 0)
			pr_err("task 0x%p, ppod writing using ofldq failed.\n",
				task);
			/* continue. Let fl get the data */
	}

#ifdef CXGBI_T10DIF_SUPPORT
	 /* T10DIF_DDP_WORKAROUND */
	/* task->hdr may point to the hdr in skb. look into skb if its carrying
	   tx pi and update the bufferoffset by removing pi_len from it */
	/* Do it only for data_out */
	if (!cxgbi_skcb_test_flag(skb, SKCBF_PI_OFFSET_UPDATED) &&
	    cxgbi_skcb_test_flag(skb, SKCBF_TX_PI) &&
	    cxgbi_skcb_tx_prot_op(skb) == SCSI_PROT_WRITE_PASS) {
		if (task &&
		    task->hdr &&
		    task->hdr->opcode == ISCSI_OP_SCSI_DATA_OUT) {
			unsigned int offset = ntohl(((struct iscsi_data *)
						task->hdr)->offset);
			unsigned int sect_shift = 9; /* 512B sector size */
			unsigned int num_sect;

			/* Chelsio T10-DIF workaround for target DDP */
			if (cxgbi_skcb_tx_pi_interval(skb) ==
					ISCSI_SCSI_PI_INTERVAL_4K)
				sect_shift = 12; /* 4KB sector size */
			num_sect = offset/((1 << sect_shift) + 8);
			/* Send offset pi-less */
			offset -= (num_sect << 3);
			((struct iscsi_data *) task->hdr)->offset =
							htonl(offset);
			cxgbi_skcb_set_flag(skb, SKCBF_PI_OFFSET_UPDATED);
		}
	}
#endif

#ifdef CXGBI_T10DIF_SUPPORT
	/* consider pi length here only if it is getting generated in
 	 * h/w */
	if (cxgbi_skcb_test_flag(skb, SKCBF_TX_PI))
		pdulen += cxgbi_skb_tx_pi_len_correction(skb);
#endif
	err = cxgbi_sock_send_skb(csk, skb);
	if (err > 0) {
		pdulen += err;

		log_debug(1 << CXGBI_DBG_PDU_TX, "task 0x%p,0x%p, rv %d.\n",
			task, task->sc, err);

		if (task->conn->hdrdgst_en)
			pdulen += ISCSI_DIGEST_SIZE;

		if (datalen && task->conn->datadgst_en)
			pdulen += ISCSI_DIGEST_SIZE;

		task->conn->txdata_octets += pdulen;
		/* enable iso if we have disabled it*/
		if (unlikely(is_iso_config(csk) &&
			    	is_iso_disabled(csk))) {
			/* FIXME: we should make this threshold
			 * into a sysfs entry(WIP)*/
			if (time_after(jiffies,
				csk->prev_iso_ts + ISO_HOLD_TICKS)) {
				csk->disable_iso = 0;
				csk->prev_iso_ts = 0;
				log_debug(1 << CXGBI_DBG_PDU_TX, 
					"enable iso: csk 0x%p\n", csk);
			}
		}
		
		return 0;
	}

	if (err == -EAGAIN || err == -ENOBUFS) {
		log_debug(1 << CXGBI_DBG_PDU_TX,
			"task 0x%p, skb 0x%p, len %u/%u, %d EAGAIN.\n",
			task, skb, skb->len, skb->data_len, err);
		/* reset skb to send when we are called again */
		tdata->skb = skb;

		/* 
		 * Workaround for bug#28219:
		 * if we are stuck in back to back tx
		 * credit crunch this may mean we have
		 * a slow peer, so disable iso temporarily;
		 */
		if(is_iso_config(csk) && !is_iso_disabled(csk) &&
			(csk->bb_tx_choke++ >= BB_TX_CR_THRESHOLD)) {
			csk->disable_iso = 1;
			csk->prev_iso_ts = jiffies;
			log_debug(1 << CXGBI_DBG_PDU_TX,
				"disable iso:csk 0x%p, ts:%lu\n",
					csk, csk->prev_iso_ts);
		}

		return err;
	}

	kfree_skb(skb);
	log_debug(1 << CXGBI_DBG_ISCSI | 1 << CXGBI_DBG_PDU_TX,
		"itt 0x%x, skb 0x%p, len %u/%u, xmit err %d.\n",
		task->itt, skb, skb->len, skb->data_len, err);
	iscsi_conn_printk(KERN_ERR, task->conn, "xmit err %d.\n", err);
	iscsi_conn_failure(task->conn, ISCSI_ERR_XMIT_FAILED);
	return err;
}
EXPORT_SYMBOL_GPL(cxgbi_conn_xmit_pdu);

void cxgbi_cleanup_task(struct iscsi_task *task)
{
	struct iscsi_tcp_task *tcp_task = task->dd_data;
	struct cxgbi_task_data *tdata = iscsi_task_cxgbi_data(task);

	if (!tcp_task || !tdata || tcp_task->dd_data != tdata) {
		/* task has not been initialized: cxgbi_alloc_pdu not called */
		//log_debug(1 << CXGBI_DBG_ISCSI,
		pr_info(
			"task 0x%p,0x%p, tcp_task 0x%p, tdata 0x%p/0x%p.\n",
                        task, task->sc, tcp_task,
			tcp_task ? tcp_task->dd_data : NULL, tdata);
		return;
	}

	log_debug(1 << CXGBI_DBG_ISCSI,
		"task 0x%p, skb 0x%p, itt 0x%x.\n",
		task, tdata->skb, task->hdr_itt);

	tcp_task->dd_data = NULL;
	/*  never reached the xmit task callout */
	if (tdata->skb)
		__kfree_skb(tdata->skb);
#ifdef __VARIABLE_DDP_PAGE_SIZE__
	if (tdata->sgl)
		task_release_realloc_pages(tdata);
#endif

	task_release_itt(task, task->hdr_itt);

	memset(tdata, 0, sizeof(*tdata));
	iscsi_tcp_cleanup_task(task);
}
EXPORT_SYMBOL_GPL(cxgbi_cleanup_task);

void cxgbi_get_conn_stats(struct iscsi_cls_conn *cls_conn,
				struct iscsi_stats *stats)
{
	struct iscsi_conn *conn = cls_conn->dd_data;
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	struct cxgbi_conn *cconn = tcp_conn->dd_data;

	stats->txdata_octets = conn->txdata_octets;
	stats->rxdata_octets = conn->rxdata_octets;
	stats->scsicmd_pdus = conn->scsicmd_pdus_cnt;
	stats->dataout_pdus = conn->dataout_pdus_cnt;
	stats->scsirsp_pdus = conn->scsirsp_pdus_cnt;
	stats->datain_pdus = conn->datain_pdus_cnt;
	stats->r2t_pdus = conn->r2t_pdus_cnt;
	stats->tmfcmd_pdus = conn->tmfcmd_pdus_cnt;
	stats->tmfrsp_pdus = conn->tmfrsp_pdus_cnt;
	stats->digest_err = 0;
	stats->timeout_err = 0;
	stats->custom_length = 3;
	strcpy(stats->custom[0].desc, "eh_abort_cnt");
	stats->custom[0].value = conn->eh_abort_cnt;
	strcpy(stats->custom[1].desc, "ddp_full");
	stats->custom[1].value = cconn->ddp_full;
	strcpy(stats->custom[2].desc, "ddp_tag_full");
	stats->custom[2].value = cconn->ddp_tag_full;
}
EXPORT_SYMBOL_GPL(cxgbi_get_conn_stats);

static int cxgbi_conn_max_xmit_dlength(struct iscsi_conn *conn)
{
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	struct cxgbi_conn *cconn = tcp_conn->dd_data;
	struct cxgbi_device *cdev = cconn->chba->cdev;
	unsigned int headroom = SKB_MAX_HEAD(cdev->skb_tx_rsvd);
	unsigned int max_def = 512 * MAX_SKB_FRAGS;
	unsigned int max = max(max_def, headroom);

	max = min(cconn->chba->cdev->tx_max_size, max);
	if (conn->max_xmit_dlength)
		conn->max_xmit_dlength = min(conn->max_xmit_dlength, max);
	else
		conn->max_xmit_dlength = max;
	cxgbi_align_pdu_size(conn->max_xmit_dlength);

	return 0;
}

static int cxgbi_conn_max_recv_dlength(struct iscsi_conn *conn)
{
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	struct cxgbi_conn *cconn = tcp_conn->dd_data;
	unsigned int max = cconn->chba->cdev->rx_max_size;

	cxgbi_align_pdu_size(max);

	if (conn->max_recv_dlength) {
		if (conn->max_recv_dlength > max) {
			pr_err("MaxRecvDataSegmentLength %u > %u.\n",
				conn->max_recv_dlength, max);
			return -EINVAL;
		}
		conn->max_recv_dlength = min(conn->max_recv_dlength, max);
		cxgbi_align_pdu_size(conn->max_recv_dlength);
	} else
		conn->max_recv_dlength = max;

	return 0;
}

int cxgbi_set_conn_param(struct iscsi_cls_conn *cls_conn,
			enum iscsi_param param, char *buf, int buflen)
{
	struct iscsi_conn *conn = cls_conn->dd_data;
	struct iscsi_session *session = conn->session;
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	struct cxgbi_conn *cconn = tcp_conn->dd_data;
	struct cxgbi_sock *csk = cconn->cep->csk;
	int value, err = 0;

	log_debug(1 << CXGBI_DBG_ISCSI,
		"cls_conn 0x%p, param %d, buf(%d) %s.\n",
		cls_conn, param, buflen, buf);

	switch (param) {
	case ISCSI_PARAM_HDRDGST_EN:
		err = iscsi_set_param(cls_conn, param, buf, buflen);
		if (!err && conn->hdrdgst_en)
			err = csk->cdev->csk_ddp_setup_digest(csk, csk->tid,
							conn->hdrdgst_en,
							conn->datadgst_en, 0);
		break;
	case ISCSI_PARAM_DATADGST_EN:
		err = iscsi_set_param(cls_conn, param, buf, buflen);
		if (!err && conn->datadgst_en)
			err = csk->cdev->csk_ddp_setup_digest(csk, csk->tid,
							conn->hdrdgst_en,
							conn->datadgst_en, 0);
		break;
	case ISCSI_PARAM_MAX_R2T:
		sscanf(buf, "%d", &value);
		if (value <= 0 || !is_power_of_2(value))
			return -EINVAL;
		if (session->max_r2t == value)
			break;
		iscsi_tcp_r2tpool_free(session);
		err = iscsi_set_param(cls_conn, param, buf, buflen);
		if (!err && iscsi_tcp_r2tpool_alloc(session))
			return -ENOMEM;
	case ISCSI_PARAM_MAX_RECV_DLENGTH:
		err = iscsi_set_param(cls_conn, param, buf, buflen);
		if (!err)
			err = cxgbi_conn_max_recv_dlength(conn);
		break;
	case ISCSI_PARAM_MAX_XMIT_DLENGTH:
		err = iscsi_set_param(cls_conn, param, buf, buflen);
		if (!err)
			err = cxgbi_conn_max_xmit_dlength(conn);
		break;
	default:
		return iscsi_set_param(cls_conn, param, buf, buflen);
	}
	return err;
}
EXPORT_SYMBOL_GPL(cxgbi_set_conn_param);

static inline int csk_print_port(struct cxgbi_sock *csk, char *buf)
{
	int len;

	cxgbi_sock_get(csk);
	len = sprintf(buf, "%hu\n", ntohs(csk->daddr.sin_port));
	cxgbi_sock_put(csk);

	return len;
}

static inline int csk_print_ip(struct cxgbi_sock *csk, char *buf)
{
	int len;

	cxgbi_sock_get(csk);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	len = sprintf(buf, "%pIS", &csk->daddr);
#else
	if (csk->csk_family == AF_INET)
		len = sprintf(buf, NIPQUAD_FMT,
			NIPQUAD(csk->daddr.sin_addr.s_addr));
	else
		len = sprintf(buf, "%pI6",
			&csk->daddr6.sin6_addr);
#endif
		
	cxgbi_sock_put(csk);

	return len;
}

int cxgbi_get_conn_param(struct iscsi_cls_conn *cls_conn,
			enum iscsi_param param, char *buf)
{
	struct iscsi_conn *conn = cls_conn->dd_data;
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	struct cxgbi_conn *cconn = tcp_conn->dd_data;

	log_debug(1 << CXGBI_DBG_ISCSI,
		"cls_conn 0x%p, param %d.\n", cls_conn, param);

	switch (param) {
	case ISCSI_PARAM_CONN_PORT:
 		if (!cconn || !cconn->cep || !cconn->cep->csk)
			return -ENOTCONN;
		return csk_print_port(cconn->cep->csk, buf);
	case ISCSI_PARAM_CONN_ADDRESS:
 		if (!cconn || !cconn->cep || !cconn->cep->csk)
			return -ENOTCONN;
		return csk_print_ip(cconn->cep->csk, buf);
	default:
		return iscsi_conn_get_param(cls_conn, param, buf);
	}
}
EXPORT_SYMBOL_GPL(cxgbi_get_conn_param);

#ifdef OISCSI_TRANSPORT_HAS_GET_EP_PARAM
int cxgbi_get_ep_param(struct iscsi_endpoint *ep,
			enum iscsi_param param, char *buf)
{
	struct cxgbi_endpoint *cep = ep->dd_data;

	log_debug(1 << CXGBI_DBG_ISCSI,
		"ep 0x%p, cep 0x%p, param %d.\n", ep, cep, param);

	switch (param) {
	case ISCSI_PARAM_CONN_PORT:
 		if (!cep || !cep->csk)
			return -ENOTCONN;
		return csk_print_port(cep->csk, buf);
	case ISCSI_PARAM_CONN_ADDRESS:
 		if (!cep || !cep->csk)
		return csk_print_ip(cep->csk, buf);
	default:
		return iscsi_conn_get_addr_param((struct sockaddr_storage *)
					&cep->csk->daddr, param, buf);
	}
}
EXPORT_SYMBOL_GPL(cxgbi_get_ep_param);
#endif

struct iscsi_cls_conn *cxgbi_create_conn(struct iscsi_cls_session *cls_session,
				u32 cid)
{
	struct iscsi_cls_conn *cls_conn;
	struct iscsi_conn *conn;
	struct iscsi_tcp_conn *tcp_conn;
	struct cxgbi_conn *cconn;

	cls_conn = iscsi_tcp_conn_setup(cls_session, sizeof(*cconn), cid);
	if (!cls_conn)
		return NULL;

	conn = cls_conn->dd_data;
	tcp_conn = conn->dd_data;
	cconn = tcp_conn->dd_data;
	cconn->iconn = conn;

	log_debug(1 << CXGBI_DBG_ISCSI,
		"cid %u(0x%x), cls 0x%p,0x%p, conn 0x%p,0x%p,0x%p.\n",
		cid, cid, cls_session, cls_conn, conn, tcp_conn, cconn);

	return cls_conn;
}
EXPORT_SYMBOL_GPL(cxgbi_create_conn);

int cxgbi_bind_conn(struct iscsi_cls_session *cls_session,
				struct iscsi_cls_conn *cls_conn,
				u64 transport_eph, int is_leading)
{
	struct iscsi_conn *conn = cls_conn->dd_data;
	struct iscsi_tcp_conn *tcp_conn = conn->dd_data;
	struct cxgbi_conn *cconn = tcp_conn->dd_data;
	struct cxgbi_ppm *ppm;
	struct cxgbi_hba *chba;
	struct iscsi_endpoint *ep;
	struct cxgbi_endpoint *cep;
	struct cxgbi_sock *csk;
	int err;

	ep = iscsi_lookup_endpoint(transport_eph);
	if (!ep)
		return -EINVAL;

	/*  setup ddp pagesize */
	cep = ep->dd_data;
	chba = cconn->chba = cep->chba;
	csk = cep->csk;
	ppm = csk->cdev->cdev2ppm(csk->cdev);
	err = csk->cdev->csk_ddp_setup_pgidx(csk, csk->tid,
					ppm->tformat.pgsz_idx_dflt, 0);
	if (err < 0)
		return err;

	err = iscsi_conn_bind(cls_session, cls_conn, is_leading);
	if (err)
		return -EINVAL;

	/*  calculate the tag idx bits needed for the conn based on cmds_max */
	cconn->task_idx_bits = (__ilog2_u32(conn->session->cmds_max - 1)) + 1;
	pr_info("csk 0x%p, session cmd max %u, bits %u.\n",
		csk, conn->session->cmds_max, cconn->task_idx_bits);

	write_lock_bh(&csk->callback_lock);
	csk->user_data = conn;
	cconn->chba = cep->chba;
	cconn->cep = cep;
	cep->cconn = cconn;
	write_unlock_bh(&csk->callback_lock);

	cxgbi_conn_max_xmit_dlength(conn);
	cxgbi_conn_max_recv_dlength(conn);

#ifdef OISCSI_CONN_HAS_PORTAL_ADDR
	spin_lock_bh(&conn->session->lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	sprintf(, "%pIS", &csk->daddr);
#else
	if (csk->csk_family == AF_INET) {
		sprintf(conn->portal_address, NIPQUAD_FMT,
			NIPQUAD(csk->daddr.sin_addr.s_addr));
	} else {
		sprintf(conn->portal_address, "%pI6",
			&csk->daddr6.sin6_addr);
	}
#endif
	/* addr union does not need a family check for accessing port */
	conn->portal_port = ntohs(csk->daddr.sin_port);
	spin_unlock_bh(&conn->session->lock);
#endif

	log_debug(1 << CXGBI_DBG_ISCSI,
		"cls 0x%p,0x%p, ep 0x%p, cconn 0x%p, csk 0x%p.\n",
		cls_session, cls_conn, ep, cconn, csk);
	/*  init recv engine */
	iscsi_tcp_hdr_recv_prep(tcp_conn);

	return 0;
}
EXPORT_SYMBOL_GPL(cxgbi_bind_conn);

struct iscsi_cls_session *cxgbi_create_session(struct iscsi_endpoint *ep,
						u16 cmds_max, u16 qdepth,
						u32 initial_cmdsn)
{
	struct cxgbi_endpoint *cep;
	struct cxgbi_hba *chba;
	struct Scsi_Host *shost;
	struct iscsi_cls_session *cls_session;
	struct iscsi_session *session;

	if (!ep) {
		pr_err("missing endpoint.\n");
		return NULL;
	}

	cep = ep->dd_data;
	chba = cep->chba;
	shost = chba->shost;

	BUG_ON(chba != iscsi_host_priv(shost));

	/*
 	 * there is a known problem of open-iscsi that the scsi layer is
 	 * sending too many commands to the iscsi layer (more than
 	 * target->can_queue). The iscsi layer can then end up using all the
 	 * IO structs for scsi command IO. So there would be no struct left
 	 * to send a nop-out, which could delay the detection and recovery of
 	 * connection error.
 	 * Mike Christie is aware of this problem, and it is being fixed in
 	 * upstream kernel http://marc.info/?l=linux-scsi&m=128477161105631&w=2
 	 * and in RHEL6 https://bugzilla.redhat.com/show_bug.cgi?id=643236
 	 *
 	 * The fix has not been released, so to work around this, cxgbi would
 	 * request shost->can_queue structs.
 	 */
//	cmds_max = chba->cmds_max;

	/* make sure # of commands is within limits */
#if 0
	if (cmds_max < chba->cmds_min)
		cmds_max = chba->cmds_min;
	else if (cmds_max > chba->cmds_max)
		cmds_max = chba->cmds_max;
#endif

	cls_session = iscsi_session_setup(chba->cdev->itp, shost,
					cmds_max, 0,
					sizeof(struct iscsi_tcp_task) + 
					sizeof(struct cxgbi_task_data),
					initial_cmdsn, ISCSI_MAX_TARGET);
	if (!cls_session)
		return NULL;

	session = cls_session->dd_data;

	if (iscsi_tcp_r2tpool_alloc(session))
		goto remove_session;

	log_debug(1 << CXGBI_DBG_ISCSI,
		"ep 0x%p, cls sess 0x%p, shost 0x%p, can queue %u.\n",
		ep, cls_session, shost, shost->can_queue);
	return cls_session;

remove_session:
	iscsi_session_teardown(cls_session);
	return NULL;
}
EXPORT_SYMBOL_GPL(cxgbi_create_session);

void cxgbi_destroy_session(struct iscsi_cls_session *cls_session)
{
	log_debug(1 << CXGBI_DBG_ISCSI,
		"cls sess 0x%p.\n", cls_session);

	iscsi_tcp_r2tpool_free(cls_session->dd_data);
	iscsi_session_teardown(cls_session);
}
EXPORT_SYMBOL_GPL(cxgbi_destroy_session);

int cxgbi_set_host_param(struct Scsi_Host *shost, enum iscsi_host_param param,
			char *buf, int buflen)
{
	struct cxgbi_hba *chba = iscsi_host_priv(shost);

	if (!chba->ndev) {
		shost_printk(KERN_ERR, shost, "Could not get host param. "
				"netdev for host not set.\n");
		return -ENODEV;
	}

	log_debug(1 << CXGBI_DBG_ISCSI,
		"shost 0x%p, hba 0x%p,%s, param %d, buf(%d) %s.\n",
		shost, chba, chba->ndev->name, param, buflen, buf);

	switch (param) {
	case ISCSI_HOST_PARAM_IPADDRESS:
	{
		__be32 addr = in_aton(buf);
		pr_info("hba %s, req. ipv4 " NIPQUAD_FMT ".\n",
			chba->ndev->name, NIPQUAD(addr));
		cxgbi_set_iscsi_ipv4(chba, addr);
		return 0;
	}
	case ISCSI_HOST_PARAM_HWADDRESS:
	case ISCSI_HOST_PARAM_NETDEV_NAME:
		return 0;
	default:
		return iscsi_host_set_param(shost, param, buf, buflen);
	}
}
EXPORT_SYMBOL_GPL(cxgbi_set_host_param);

int cxgbi_get_host_param(struct Scsi_Host *shost, enum iscsi_host_param param,
			char *buf)
{
	struct cxgbi_hba *chba = iscsi_host_priv(shost);
	int len = 0;

	if (!chba->ndev) {
		shost_printk(KERN_ERR, shost, "Could not get host param. "
				"netdev for host not set.\n");
		return -ENODEV;
	}

	log_debug(1 << CXGBI_DBG_ISCSI,
		"shost 0x%p, hba 0x%p,%s, param %d.\n",
		shost, chba, chba->ndev->name, param);

	switch (param) {
	case ISCSI_HOST_PARAM_HWADDRESS:
		len = sysfs_format_mac(buf, chba->ndev->dev_addr, 6);
		break;
	case ISCSI_HOST_PARAM_NETDEV_NAME:
		len = sprintf(buf, "%s\n", chba->ndev->name);
		break;
	case ISCSI_HOST_PARAM_IPADDRESS:
	{
		struct cxgbi_sock *csk = find_sock_on_port(chba->cdev,
							chba->port_id);
		if (csk) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
			len = sprintf(buf, "%pIS", &csk->saddr);
#else
			if (csk->csk_family == AF_INET)
				len = sprintf(buf, "%pI4",
					&csk->saddr.sin_addr.s_addr);
			else
				len = sprintf(buf, "%pI6",
					&csk->saddr6.sin6_addr);
#endif
		}
		log_debug(1 << CXGBI_DBG_ISCSI,
			"hba %s, addr %s.\n", chba->ndev->name, buf);
		break;
	}
	default:
		return iscsi_host_get_param(shost, param, buf);
	}

	return len;
}
EXPORT_SYMBOL_GPL(cxgbi_get_host_param);

struct iscsi_endpoint *cxgbi_ep_connect(struct Scsi_Host *shost,
					struct sockaddr *dst_addr,
					int non_blocking)
{
	struct iscsi_endpoint *ep;
	struct cxgbi_endpoint *cep;
	struct cxgbi_hba *hba = NULL;
	struct cxgbi_sock *csk;
	int err = -EINVAL;

	log_debug(1 << CXGBI_DBG_ISCSI | 1 << CXGBI_DBG_SOCK,
		"shost 0x%p, non_blocking %d, dst_addr 0x%p.\n",
		shost, non_blocking, dst_addr);

	if (shost) {
		hba = iscsi_host_priv(shost);
		if (!hba) {
			pr_info("shost 0x%p, priv NULL.\n", shost);
			goto err_out;
		}
	} else
		pr_info("shost NULL.\n");

	if (dst_addr->sa_family == AF_INET) {
		csk = cxgbi_check_route(dst_addr);
#ifdef CXGBI_IPV6_SUPPORT
	} else if (dst_addr->sa_family == AF_INET6) {
		csk = cxgbi_check_route6(dst_addr);
#endif
	} else {
		pr_info("address family 0x%x NOT supported.\n",
			dst_addr->sa_family);
		err = -EAFNOSUPPORT;
		return (struct iscsi_endpoint *)ERR_PTR(err);
	}

	if (IS_ERR(csk))
		return (struct iscsi_endpoint *)csk;
	cxgbi_sock_get(csk);

	if (!hba)
		hba = csk->cdev->hbas[csk->port_id];
	else if (hba != csk->cdev->hbas[csk->port_id]) {
		pr_info("Could not connect through requested host %u"
			"hba 0x%p != 0x%p (%u).\n",
			shost->host_no, hba,
			csk->cdev->hbas[csk->port_id], csk->port_id);
		err = -ENOSPC;
		goto release_conn;
	}

	err = sock_get_port(csk);
	if (err)
		goto release_conn;

	cxgbi_sock_set_state(csk, CTP_CONNECTING);
	err = csk->cdev->csk_init_act_open(csk);
	if (err)
		goto release_conn;

	if (cxgbi_sock_is_closing(csk)) {
		err = -ENOSPC;
		pr_info("csk 0x%p is closing.\n", csk);
		goto release_conn;
	}

	ep = iscsi_create_endpoint(sizeof(*cep));
	if (!ep) {
		err = -ENOMEM;
		pr_info("iscsi alloc ep, OOM.\n");
		goto release_conn;
	}

	cep = ep->dd_data;
	cep->csk = csk;
	cep->chba = hba;

	log_debug(1 << CXGBI_DBG_ISCSI | 1 << CXGBI_DBG_SOCK,
		"ep 0x%p, cep 0x%p, csk 0x%p, hba 0x%p,%s.\n",
		ep, cep, csk, hba, hba->ndev->name);
	return ep;

release_conn:
	cxgbi_sock_put(csk);
	cxgbi_sock_closed(csk);
err_out:
	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(cxgbi_ep_connect);

int cxgbi_ep_poll(struct iscsi_endpoint *ep, int timeout_ms)
{
	struct cxgbi_endpoint *cep = ep->dd_data;
	struct cxgbi_sock *csk = cep->csk;

	if (!cxgbi_sock_is_established(csk))
		return 0;
	return 1;
}
EXPORT_SYMBOL_GPL(cxgbi_ep_poll);

void cxgbi_ep_disconnect(struct iscsi_endpoint *ep)
{
	struct cxgbi_endpoint *cep = ep->dd_data;
	struct cxgbi_conn *cconn = cep->cconn;
	struct cxgbi_sock *csk = cep->csk;

	 pr_info_ipaddr("csk 0x%p,%u,%lx, "
		"ep 0x%p, cep 0x%p, cconn 0x%p.\n",
		(&csk->saddr),
		(&csk->daddr),
		csk, csk->state, csk->flags,
		ep, cep, cconn);

	if (cconn && cconn->iconn) {
		write_lock_bh(&csk->callback_lock);
		csk->user_data = NULL;
		cconn->cep = NULL;
		write_unlock_bh(&csk->callback_lock);
	}
	iscsi_destroy_endpoint(ep);

	/* if the socket is closed, then we've already informed iscsi of 
 	 * the connection failure */
	if (likely(csk->state >= CTP_ESTABLISHED))
		need_active_close(csk);
	else if (csk->state != CTP_CLOSED){
		cxgbi_sock_get(csk);
		spin_lock_bh(&csk->lock);
		cxgbi_sock_closed(csk);
		spin_unlock_bh(&csk->lock);
		cxgbi_sock_put(csk);
	}

	cxgbi_sock_put(csk);
}
EXPORT_SYMBOL_GPL(cxgbi_ep_disconnect);

int cxgbi_slave_configure(struct scsi_device *sdev)
{
	blk_queue_bounce_limit(sdev->request_queue, BLK_BOUNCE_ANY);
	blk_queue_dma_alignment(sdev->request_queue, 0);
	return 0;
}
EXPORT_SYMBOL_GPL(cxgbi_slave_configure);

int cxgbi_iscsi_init(struct iscsi_transport *itp,
			struct scsi_transport_template **stt)
{
	*stt = iscsi_register_transport(itp);
	if (*stt == NULL) {
		pr_err("unable to register %s transport 0x%p.\n",
			itp->name, itp);
		return -ENODEV;
	}
	log_debug(1 << CXGBI_DBG_ISCSI,
		"%s, registered iscsi transport 0x%p.\n",
		itp->name, stt);
	return 0;
}
EXPORT_SYMBOL_GPL(cxgbi_iscsi_init);

void cxgbi_iscsi_cleanup(struct iscsi_transport *itp,
			struct scsi_transport_template **stt)
{
	if (*stt) {
		log_debug(1 << CXGBI_DBG_ISCSI,
			"de-register transport 0x%p, %s, stt 0x%p.\n",
			itp, itp->name, *stt);
		*stt = NULL;
		iscsi_unregister_transport(itp);
	}
}
EXPORT_SYMBOL_GPL(cxgbi_iscsi_cleanup);

#ifdef OISCSI_TRANSPORT_HAS_ATTR_IS_VISIBLE
#ifdef OISCSI_TRANSPORT_UMODE_T
umode_t
#else
mode_t
#endif /* #ifdef OISCSI_TRANSPORT_UMODE_T */
cxgbi_attr_is_visible(int param_type, int param)
{
	switch (param_type) {
	case ISCSI_HOST_PARAM:
		switch (param) {
		case ISCSI_HOST_PARAM_NETDEV_NAME:
		case ISCSI_HOST_PARAM_HWADDRESS:
		case ISCSI_HOST_PARAM_IPADDRESS:
		case ISCSI_HOST_PARAM_INITIATOR_NAME:
			return S_IRUGO;
		default:
			return 0;
		}
	case ISCSI_PARAM:
		switch (param) {
		case ISCSI_PARAM_MAX_RECV_DLENGTH:
		case ISCSI_PARAM_MAX_XMIT_DLENGTH:
		case ISCSI_PARAM_HDRDGST_EN:
		case ISCSI_PARAM_DATADGST_EN:
		case ISCSI_PARAM_CONN_ADDRESS:
		case ISCSI_PARAM_CONN_PORT:
		case ISCSI_PARAM_EXP_STATSN:
		case ISCSI_PARAM_PERSISTENT_ADDRESS:
		case ISCSI_PARAM_PERSISTENT_PORT:
		case ISCSI_PARAM_PING_TMO:
		case ISCSI_PARAM_RECV_TMO:
		case ISCSI_PARAM_INITIAL_R2T_EN:
		case ISCSI_PARAM_MAX_R2T:
		case ISCSI_PARAM_IMM_DATA_EN:
		case ISCSI_PARAM_FIRST_BURST:
		case ISCSI_PARAM_MAX_BURST:
		case ISCSI_PARAM_PDU_INORDER_EN:
		case ISCSI_PARAM_DATASEQ_INORDER_EN:
		case ISCSI_PARAM_ERL:
		case ISCSI_PARAM_TARGET_NAME:
		case ISCSI_PARAM_TPGT:
		case ISCSI_PARAM_USERNAME:
		case ISCSI_PARAM_PASSWORD:
		case ISCSI_PARAM_USERNAME_IN:
		case ISCSI_PARAM_PASSWORD_IN:
		case ISCSI_PARAM_FAST_ABORT:
		case ISCSI_PARAM_ABORT_TMO:
		case ISCSI_PARAM_LU_RESET_TMO:
		case ISCSI_PARAM_TGT_RESET_TMO:
		case ISCSI_PARAM_IFACE_NAME:
		case ISCSI_PARAM_INITIATOR_NAME:
			return S_IRUGO;
		default:
			return 0;
		}
	}

	return 0;
}
EXPORT_SYMBOL_GPL(cxgbi_attr_is_visible);
#endif

void cxgbi_dump_bytes(char *cap, unsigned char *bytes, int start, int maxlen)
{
	char    buffer[256];
        char    *buf = buffer;
        unsigned char *dp;
        unsigned int i;
        int     len = 0;

        if (!bytes)
                return;

        if (cap)
                len = sprintf(buf, "%s: ", cap);
        len += sprintf(buf + len, "%u -- %u:\n", start, (start + maxlen - 1));
        buf[len] = 0;
        printk(KERN_INFO "cxgbi, %s", buf);
        len = 0;

        dp = bytes + start;
        for (i = 0; i < maxlen; i++, dp++) {
                /* 8 bytes a block, 3 blocks per line */
                if (i && (i % 24 == 0)) {
                        buf[len] = 0;
                        printk(KERN_INFO "cxgbi, %s\n", buf);
                        len = 0;
                } else if (i && (i % 8 == 0))
			buf[len++] = ' ';
                len += sprintf(buf + len, "%02x ", *dp);
        }

        if (len) {
                buf[len] = 0;
                printk(KERN_INFO "cxgbi, %s\n", buf);
                len = 0;
        }
}
EXPORT_SYMBOL_GPL(cxgbi_dump_bytes);

unsigned int cxgbi_select_delack(struct cxgbi_sock *csk, unsigned int dack_mode)
{
        unsigned short mss_clamp;

        mss_clamp = csk->cdev->mtus[csk->mss_idx];

        if (!dack_mode || cxgbi_sock_flag(csk, CTPF_PEER_ULP))
                return 0;

        if ((dack_mode == 2) && mss_clamp > 1680)
                dack_mode = 3;

        if ((dack_mode == 3) && (csk->rcv_win < 2 * 26880))
                dack_mode = 1;

        if ((dack_mode == 2) && (csk->rcv_win < 2 * 16 * mss_clamp))
                dack_mode = 1;

        if (csk->rcv_win > 2 * 2 * mss_clamp) // && delack_mode == 0
                dack_mode = 1;

        return dack_mode;
}
EXPORT_SYMBOL_GPL(cxgbi_select_delack);

static unsigned char sw_tag_idx_bits;
static unsigned char sw_tag_age_bits;

static int __init libcxgbi_init_module(void)
{
	sw_tag_idx_bits = (__ilog2_u32(ISCSI_ITT_MASK)) + 1;
	sw_tag_age_bits = (__ilog2_u32(ISCSI_AGE_MASK)) + 1;

	rsvd_page = alloc_page(GFP_KERNEL);;
	if (!rsvd_page)
		return -ENOMEM;
	memset(page_address(rsvd_page), 0, PAGE_SIZE);

	pr_info("tag itt 0x%x, %u bits, age 0x%x, %u bits.\n",
		ISCSI_ITT_MASK, sw_tag_idx_bits,
		ISCSI_AGE_MASK, sw_tag_age_bits);

	return 0;
}

static void __exit libcxgbi_exit_module(void)
{
	cxgbi_device_unregister_all(0xFF);
}

module_init(libcxgbi_init_module);
module_exit(libcxgbi_exit_module);
