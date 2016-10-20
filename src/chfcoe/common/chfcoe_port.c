/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include "chfcoe_defs.h"
#include "chfcoe_rnode.h"
#include "chfcoe_lnode.h"
#include "chfcoe_io.h"
#include "chfcoe_adap.h"
#include "chfcoe_xchg.h"
#include "chfcoe_lib.h"

void chfcoe_fip_recv(void *data);
int chfcoe_osdfs_port_init(struct chfcoe_port_info *pi);
void chfcoe_osdfs_port_exit(struct chfcoe_port_info *pi);

void chfcoe_fill_fcb_cpl_tx(struct chfcoe_adap_info *adap,
		chfcoe_fc_buffer_t *fr, fc_header_t *fh, 
		uint16_t vlan_id, uint8_t port_num,
		uint8_t dcb_prio, uint8_t vi_id);

void *chfcoe_port_alloc(uint8_t nports)
{
	return chfcoe_mem_alloc(nports * chfcoe_port_info_size);
}

void chfcoe_port_free(void *pi)
{
	chfcoe_mem_free(pi);
}

uint8_t chfcoe_port_get_linkstate(struct chfcoe_adap_info *adap, uint8_t port_num)
{
	struct chfcoe_port_info *pi;
	
	pi = CHFCOE_PTR_OFFSET(adap->pi, port_num * chfcoe_port_info_size);

	return pi->link_state;
}

void chfcoe_port_set_linkstate(struct chfcoe_adap_info *adap,
	       	uint8_t port_num, uint8_t link_state)
{
	struct chfcoe_port_info *pi;
	
	pi = CHFCOE_PTR_OFFSET(adap->pi, port_num * chfcoe_port_info_size);
	pi->link_state = link_state;

	switch (pi->link_state) {
	case CHFCOE_PORT_ONLINE:
		CHFCOE_INC_STATS(pi, n_link_up);
		break;
	}
}

void chfcoe_port_set_dcbprio(struct chfcoe_adap_info *adap,
		uint8_t port_num, uint8_t dcb_prio)
{
	struct chfcoe_port_info *pi;

	pi = CHFCOE_PTR_OFFSET(adap->pi, port_num * chfcoe_port_info_size);

	pi->dcb_prio = dcb_prio;

}
void *chfcoe_port_get_osdev(struct chfcoe_adap_info *adap, uint8_t port_num)
{
	struct chfcoe_port_info *pi;

	pi = CHFCOE_PTR_OFFSET(adap->pi, port_num * chfcoe_port_info_size);
	return pi->os_dev;
}

/*
 * chfcoe_resource_alloc - Allocate memory pool for IOreq, Rnodes.
 * @os_adap: OS specific Adapter information.
 *
 * Allocated memory pool for IO requests & Rnodes during driver initialization,
 * assign those memory pools to Adapter information (not OS specific Adap).
 */
static int chfcoe_port_resource_alloc(struct chfcoe_port_info *pi)
{
	int i, j;
	
        pi->txqlock = chfcoe_mem_alloc(pi->nqsets * sizeof(void *));
	if (!pi->txqlock)
		goto err_free_xchg;

	for (i=0; i<pi->nqsets; i++) {
		pi->txqlock[i] = chfcoe_mem_alloc(os_mutex_size);
		if (!pi->txqlock[i]) {
			for (j=i-1; j>=0; j--)
				chfcoe_mem_free(pi->txqlock[j]);
			goto err_free_txlock;
		}

		chfcoe_mutex_init(pi->txqlock[i]);
	}

	return 0;

err_free_txlock:
	chfcoe_mem_free(pi->txqlock);

err_free_xchg:
	return CHFCOE_NOMEM;
} /* chfcoe_resource_alloc */

/*
 * chfcoe_resource_free - Free allocated resources for IOreqs & Rnodes.
 * @os_adap - OS specific adapter information.
 */
void
chfcoe_port_resource_free(struct chfcoe_port_info *pi)
{
	int i;

	if (pi->txqlock) {
		for (i=0; i<pi->nqsets; i++)
			chfcoe_mem_free(pi->txqlock[i]);
		chfcoe_mem_free(pi->txqlock);
	}

} /* chfcoe_resource_free */

int chfcoe_port_init(struct chfcoe_adap_info *adap,
		struct chfcoe_port_lld_info *pi_lldi, uint8_t port_num)
{
	struct chfcoe_port_info *pi;

	pi = CHFCOE_PTR_OFFSET(adap->pi, (port_num * chfcoe_port_info_size));
	pi->lock = CHFCOE_PTR_OFFSET(pi, sizeof(struct chfcoe_port_info)); 
	pi->tid_list_lock = CHFCOE_PTR_OFFSET(pi, sizeof(struct chfcoe_port_info) + (os_spinlock_size));

	pi->mtx_lock = CHFCOE_PTR_OFFSET(pi, sizeof(struct chfcoe_port_info) + (2 * os_spinlock_size));
	pi->ddp_mutex = CHFCOE_PTR_OFFSET(pi, sizeof(struct chfcoe_port_info) + (2 * os_spinlock_size) +
			os_mutex_size);
	pi->n_active_rnode = CHFCOE_PTR_OFFSET(pi, sizeof(struct chfcoe_port_info) + (2 * os_spinlock_size) +
			(2 * os_mutex_size));
	pi->fip_rx_work = CHFCOE_PTR_OFFSET(pi, sizeof(struct chfcoe_port_info) + (2 * os_spinlock_size) +
			(2 * os_mutex_size) +  os_atomic_size);
	pi->fip_rx_work->work = CHFCOE_PTR_OFFSET(pi, sizeof(struct chfcoe_port_info) + (2 * os_spinlock_size) +
			(2 * os_mutex_size) + os_atomic_size + sizeof(chfcoe_work_t));
	pi->fip_rx_list = CHFCOE_PTR_OFFSET(pi, sizeof(struct chfcoe_port_info) + (2 * os_spinlock_size) +
			(2 * os_mutex_size) + os_atomic_size + chfcoe_work_size);

	pi->os_dev = (void *)pi_lldi->os_dev;
	pi->nqsets = pi_lldi->fcoe_nqsets;
	chfcoe_info(adap, "port %d, nqsets %d %s\n", port_num, pi->nqsets);
	pi->adap = adap;

	/* Get viid for each port */
	pi->vi_id = pi_lldi->vi_id;

	/* Copy MAC address for each port */
	chfcoe_memcpy(&(pi->phy_mac), &(pi_lldi->phy_mac), 6);
	pi->port_num = port_num;
	chfcoe_init_work(pi->fip_rx_work, chfcoe_fip_recv, pi);
	chfcoe_skb_queue_head_init(pi->fip_rx_list);
	pi->link_state = CHFCOE_PORT_INIT;
	chfcoe_atomic_set(pi->n_active_rnode, 0);

	/* Initialize port spin lock */
	chfcoe_spin_lock_init(pi->lock);

	/* Allocate Memory for IO requests & Rnodes */
	if (chfcoe_port_resource_alloc(pi)) 
		return CHFCOE_NOMEM;
#ifdef __CHFCOE_DEBUGFS__
	/* Initialize debufs for port */
	chfcoe_osdfs_port_init(pi);
#endif

	return CHFCOE_SUCCESS;
}

void chfcoe_port_exit(struct chfcoe_adap_info *adap, uint8_t port_num)
{
	struct chfcoe_port_info *pi;

	pi =  CHFCOE_PTR_OFFSET(adap->pi, (port_num * chfcoe_port_info_size));
	chfcoe_port_resource_free(pi);
#ifdef __CHFCOE_DEBUGFS__	
	chfcoe_osdfs_port_exit(pi);
#endif
}

void chfcoe_port_close(struct chfcoe_adap_info *adap)
{
	struct chfcoe_port_info *pi = adap->pi;
	int i;

	for (i=0; i<adap->nports; i++) {
		pi = CHFCOE_PTR_OFFSET(adap->pi, (i * chfcoe_port_info_size));
		pi->link_state = CHFCOE_PORT_OFFLINE;
		chfcoe_cancel_work_sync(pi->fip_rx_work);
		chfcoe_dbg(pi, "modlue exit port:%d close\n", i);
		/* Dropping all skbs */
		chfcoe_skb_queue_purge(pi->fip_rx_list);

		while(chfcoe_atomic_read(pi->n_active_rnode)) {
			chfcoe_err(pi, "Active rnodes:%d\n", chfcoe_atomic_read(pi->n_active_rnode));
			chfcoe_msleep(5000);
		}

		chfcoe_port_lnode_exit(pi->adap, pi->port_num);
		chfcoe_port_exit(pi->adap, pi->port_num);
	}

	chfcoe_ddp_disable(adap);
	if (adap->nppods)
		chfcoe_mem_free(adap->ppod_map);

	if (adap->pi)
		chfcoe_mem_free(adap->pi);
}
