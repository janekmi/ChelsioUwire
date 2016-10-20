/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __LITTLE_ENDIAN_BITFIELD
#define __LITTLE_ENDIAN_BITFIELD
#endif

#include "chfcoe_defs.h"
#include <t4_msg.h>
#include "chfcoe_adap.h"
#include "chfcoe_rnode.h"
#include "chfcoe_lnode.h"
#include "chfcoe_xchg.h"
#include "chfcoe_io.h"
#include "chfcoe_worker.h"
#include "chfcoe_lib.h"

struct chfcoe_node_info node_info[2] = {{0, 0, NULL, NULL}, {0, 0, NULL, NULL}};
struct chfcoe_control_work_data *control_d;
void *chfcoe_workq = NULL;
struct sk_buff;

extern unsigned int chfcoe_node_num;

static int chfcoe_fcoe_recv(void *data);

int chfcoe_create_workers(unsigned int node_index)
{
	struct chfcoe_perworker_data *d;
	unsigned int worker_id;

	node_info[node_index].counter = chfcoe_mem_alloc_node(os_atomic_size, node_info[node_index].node_id);
	if (!node_info[node_index].counter) {
		chfcoe_err(0, "create workers failed to alloc memory\n");
		goto err0;
	}
	chfcoe_atomic_set(node_info[node_index].counter, 0);

	node_info[node_index].worker_data = chfcoe_mem_alloc_node((node_info[node_index].worker_num *
				chfcoe_perworker_data_size), node_info[node_index].node_id);
	if (!node_info[node_index].worker_data) {
		chfcoe_err(0, "create workers failed to alloc memory\n");
		goto err1;
	}

	for (worker_id = 0; worker_id < node_info[node_index].worker_num; worker_id++) {
		d = CHFCOE_PTR_OFFSET(node_info[node_index].worker_data, (worker_id * chfcoe_perworker_data_size));
		d->chfcoe_rx_list = CHFCOE_PTR_OFFSET(d, sizeof(struct chfcoe_perworker_data));
		d->chfcoe_rx_tmp_list = CHFCOE_PTR_OFFSET(d, sizeof(struct chfcoe_perworker_data)
				+ os_sk_buff_head_size);
		
		chfcoe_skb_queue_head_init(d->chfcoe_rx_list);
		d->chfcoe_rx_list_lock = chfcoe_sk_buff_head_lock(d->chfcoe_rx_list);
		chfcoe_skb_queue_head_init(d->chfcoe_rx_tmp_list);

		d->task = chfcoe_kthread_create_on_node(chfcoe_fcoe_recv, (void *)d, node_info[node_index].node_id,
				"chfcoe_%d_%u", node_info[node_index].node_id, worker_id);

		if (chfcoe_unlikely(d->task == NULL)) {
			chfcoe_err(0, "create workers failed\n");
			while (worker_id) {
				worker_id--;
				d = CHFCOE_PTR_OFFSET(node_info[node_index].worker_data, (worker_id * chfcoe_perworker_data_size));
				chfcoe_kthread_stop(d->task);
			}
			goto err2;
		}
		else {	
			chfcoe_set_user_nice(d->task, -20);
			chfcoe_wake_up_process(d->task);
		}
	}
	return CHFCOE_SUCCESS;

err2:
	chfcoe_mem_free(node_info[node_index].worker_data);
err1:
	chfcoe_mem_free(node_info[node_index].counter);
err0:
	return CHFCOE_NOMEM;
}

void chfcoe_destroy_workers(unsigned int node_index)
{
	struct chfcoe_perworker_data *d;
	unsigned int worker_id;

	for (worker_id = 0 ; worker_id < node_info[node_index].worker_num; worker_id++) {
		d = CHFCOE_PTR_OFFSET(node_info[node_index].worker_data, (worker_id * chfcoe_perworker_data_size));
		chfcoe_kthread_stop(d->task);
	}

	chfcoe_mem_free(node_info[node_index].worker_data);
	chfcoe_mem_free(node_info[node_index].counter);
}

void chfcoe_worker_skb_queue_purge(void)
{
	struct chfcoe_perworker_data *d;
	unsigned int node_index = 0, worker_id = 0;

	for (node_index = 0; node_index < chfcoe_node_num; node_index++) {
		for (worker_id = 0; worker_id < node_info[node_index].worker_num; worker_id++) {
			d = CHFCOE_PTR_OFFSET(node_info[node_index].worker_data, (worker_id * chfcoe_perworker_data_size));
			chfcoe_skb_queue_purge(d->chfcoe_rx_list);
		}
	}
}

void chfcoe_flush_dtr(struct sk_buff *skb)
{
	chfcoe_fc_buffer_t *fcb = (chfcoe_fc_buffer_t *)skb;
	void *cmpl = chfcoe_fc_cmpl(fcb);

	chfcoe_complete(cmpl);
}

void chfcoe_flush_workers(unsigned int node_index)
{
	struct chfcoe_perworker_data *d;
	unsigned int i = 0;
	void *cmpl = NULL;
	chfcoe_fc_buffer_t *fcb = NULL;
	
	cmpl = chfcoe_mem_alloc(os_completion_size);
	
	if (cmpl == NULL) {
		chfcoe_err(0, "failed to alloc cmpl\n");
		for (;;) {
			cmpl = chfcoe_mem_alloc(os_completion_size);
			if (cmpl == NULL)
				chfcoe_schedule();
			else {
				break;
			}
		}
	}	
	
	chfcoe_init_completion(cmpl);
	chfcoe_dbg(ln, "flush workers\n");

	for (i = 0; i < node_info[node_index].worker_num; i++) {
		d = CHFCOE_PTR_OFFSET(node_info[node_index].worker_data, (i * chfcoe_perworker_data_size));
		fcb = chfcoe_fcb_alloc(0);
		if (fcb == NULL) {
			chfcoe_err(0, "failed to alloc skb\n");
			for (;;) {
				fcb = chfcoe_fcb_alloc(0);
				if (fcb == NULL)
					chfcoe_schedule();
				else {
					break;
				}
			}
		}

        	chfcoe_memset(chfcoe_fcb_cb(fcb), 0, sizeof(struct chfcoe_skb_cb));

		chfcoe_fc_lnode(fcb) = NULL;
		chfcoe_fc_cmpl(fcb) = cmpl;
		chfcoe_fc_dtr(fcb, chfcoe_flush_dtr);
		
		chfcoe_spin_lock_bh(d->chfcoe_rx_list_lock);
		__chfcoe_skb_queue_tail(d->chfcoe_rx_list, fcb);
		chfcoe_spin_unlock_bh(d->chfcoe_rx_list_lock);
		chfcoe_wake_up_process(d->task);

		chfcoe_wait_for_completion(cmpl);
		chfcoe_reinit_completion(cmpl);
	}

	chfcoe_mem_free(cmpl);
}

void chfcoe_control_recv(void *data __attribute__((unused)))
{
	chfcoe_fc_buffer_t *fcb;
	struct chfcoe_lnode *lnode;

	chfcoe_spin_lock_bh(control_d->chfcoe_rx_list_lock);
	while ((fcb = __chfcoe_skb_dequeue(control_d->chfcoe_rx_list))) {
		chfcoe_spin_unlock_bh(control_d->chfcoe_rx_list_lock);
		lnode = chfcoe_fc_lnode(fcb);
		chfcoe_xchg_recv(lnode, fcb);
		chfcoe_fcb_free(fcb);
		chfcoe_spin_lock_bh(control_d->chfcoe_rx_list_lock);
	}
	chfcoe_spin_unlock_bh(control_d->chfcoe_rx_list_lock);
}

void chfcoe_skb_destructor(struct sk_buff *skb)
{
	chfcoe_fc_buffer_t *fb = skb;
	void *pdev = chfcoe_fc_pdev(fb);
	void *page = chfcoe_fc_sg_page(fb);
	uint64_t dma_addr = chfcoe_fc_page_dma_addr(fb);
	unsigned int sg_len = chfcoe_fc_page_dma_len(fb);

	chfcoe_pci_unmap_page(pdev, page, dma_addr, sg_len);

}

static int chfcoe_fcoe_recv(void *data)
{
	struct chfcoe_perworker_data *d = data;
	chfcoe_fc_buffer_t *fcb;
	struct chfcoe_lnode *ln;
	struct chfcoe_rnode *rn;

	while (!chfcoe_kthread_should_stop()) {

		chfcoe_spin_lock_bh(d->chfcoe_rx_list_lock);
		chfcoe_skb_queue_splice_init(d->chfcoe_rx_list, d->chfcoe_rx_tmp_list);
		if ((!chfcoe_skb_queue_len(d->chfcoe_rx_tmp_list))) {
			chfcoe_task_state_interruptible();
			chfcoe_spin_unlock_bh(d->chfcoe_rx_list_lock);
			chfcoe_schedule();
			chfcoe_task_state_running();
			continue;
		}
		chfcoe_spin_unlock_bh(d->chfcoe_rx_list_lock);

		while ((fcb = __chfcoe_skb_dequeue(d->chfcoe_rx_tmp_list))) {
			
			ln = chfcoe_fc_lnode(fcb);

			if (chfcoe_likely(ln)) {
				chfcoe_xchg_recv(ln, fcb);
				rn = chfcoe_fc_rnode(fcb);
				chfcoe_atomic_dec(rn->submit_pending);
			}

			chfcoe_fcb_free(fcb);
		}
	}
	return 0;
}

static inline void chfcoe_queue_fcoe_fcb(struct chfcoe_adap_info *adap,
		chfcoe_fc_buffer_t *fcb)
{
	struct chfcoe_port_info *pi = CHFCOE_PTR_OFFSET(adap->pi,
			(chfcoe_fcb_cb(fcb)->port * chfcoe_port_info_size));
	struct chfcoe_perworker_data *d;
	struct chfcoe_lnode *ln;
	struct chfcoe_rnode *rn = NULL;
	struct proto_fcoe_hdr *fcoeh;
	struct proto_fcoe_crc_eof *fcoet;
	fc_header_t *fc_hdr;
	chfcoe_xchg_cb_t *xchg = NULL;
	unsigned int worker_id;
	unsigned int ucounter = 0;
	unsigned int node_index = 0;
	uint16_t rx_id;

	ln = chfcoe_get_lnode(pi, fcb);
	if (chfcoe_unlikely(!ln)) {
		chfcoe_dbg(pi, "err:couldn't find lnode\n");
		chfcoe_fcb_free(fcb);
		return;
	}
	fcoeh = (struct proto_fcoe_hdr *)chfcoe_fc_data_ptr(fcb);
	chfcoe_fc_sof(fcb) = fcoeh->fcoe_sof;
	
	fc_hdr = (fc_header_t *)(fcoeh + 1);
	
	fcoet = (struct proto_fcoe_crc_eof *)((chfcoe_fc_data_ptr(fcb)) +
		(chfcoe_fc_data_len(fcb) - sizeof(*fcoet)));
	chfcoe_fc_eof(fcb) = fcoet->fcoe_eof;
	
	chfcoe_fcb_pull_rx(fcb, sizeof(*fcoeh));
	chfcoe_fcb_trim_rx(fcb, sizeof(*fcoet));

	chfcoe_fc_lnode(fcb) = ln;

	if ((fc_hdr->type == PROTO_FC_TYPE_FCP) ||
			(fc_hdr->type == FC_TYPE_BLS)) {
		/* Get rnode pointer */
		chfcoe_read_lock(ln->rn_lock);
		rn = __chfcoe_rn_lookup_portid(ln, chfcoe_ntoh24(fc_hdr->s_id));

		if (chfcoe_likely((rn != NULL) && chfcoe_test_bit(CHFCOE_RNODE_ULP_READY, &rn->flags))) {
			chfcoe_atomic_inc(rn->submit_pending);
			node_index = rn->node_index;
		}
		else {
			chfcoe_read_unlock(ln->rn_lock);
			chfcoe_err(ln, "Command recvd for non-existent rnode:0x%x\n", chfcoe_ntoh24(fc_hdr->s_id));
			chfcoe_fcb_free(fcb);
			return;
		}	
		chfcoe_read_unlock(ln->rn_lock);

		chfcoe_fc_rnode(fcb) = rn;

		rx_id = chfcoe_ntohs(fc_hdr->rx_id);

		if (rx_id == PROTO_FC_XID_UNKNOWN) {
			ucounter = chfcoe_atomic_read(node_info[node_index].counter);
			chfcoe_atomic_inc(node_info[node_index].counter);

			worker_id = ucounter % node_info[node_index].worker_num;
			d = CHFCOE_PTR_OFFSET(node_info[node_index].worker_data,
					(worker_id * chfcoe_perworker_data_size));
			chfcoe_fc_worker_id(fcb) = worker_id;
		} else {
			if (chfcoe_unlikely(rx_id >= CHFCOE_MAX_XID)) {
				chfcoe_err(ln, "rnode:0x%x invalid rx id:0x%x\n",
						chfcoe_ntoh24(fc_hdr->s_id), rx_id);
				chfcoe_fcb_free(fcb);
				return;
			}

			xchg = CHFCOE_XID_TO_XCHG(rn, rx_id);
			d = CHFCOE_PTR_OFFSET(node_info[node_index].worker_data,
					(xchg->worker_id * chfcoe_perworker_data_size));
		}

		chfcoe_spin_lock(d->chfcoe_rx_list_lock);
		__chfcoe_skb_queue_tail(d->chfcoe_rx_list, fcb);
		chfcoe_spin_unlock(d->chfcoe_rx_list_lock);
		chfcoe_wake_up_process(d->task);
	}else {
		chfcoe_spin_lock(control_d->chfcoe_rx_list_lock);
		__chfcoe_skb_queue_tail(control_d->chfcoe_rx_list, fcb);
		chfcoe_spin_unlock(control_d->chfcoe_rx_list_lock);
		chfcoe_queue_work(chfcoe_workq, control_d->work);
	}
	CHFCOE_INC_STATS(pi, n_fcoe_rx_fr);
}

static inline void chfcoe_queue_fip_fcb(struct chfcoe_adap_info *adap,
		chfcoe_fc_buffer_t *fcb)
{
	struct chfcoe_port_info *pi = CHFCOE_PTR_OFFSET(adap->pi,
			(chfcoe_fcb_cb(fcb)->port * chfcoe_port_info_size));
	
	chfcoe_skb_queue_tail(pi->fip_rx_list, fcb);
	chfcoe_schedule_work(pi->fip_rx_work);
	CHFCOE_INC_STATS(pi, n_fip_rx_fr);
}

/*
 * chfcoe_queue_fcb - decides to call FIP/FCoE Rx handler.
 */
void chfcoe_queue_fcb(struct chfcoe_adap_info *adap,
		chfcoe_fc_buffer_t *fcb, unsigned char *fcb_data,
		unsigned int fcb_len, uint8_t port,
		uint16_t vlan_tci, uint32_t l2info)
{
	struct chfcoe_port_info *pi = CHFCOE_PTR_OFFSET(adap->pi,
			(port * chfcoe_port_info_size));
	struct proto_ethhdr_novlan *eh = (struct proto_ethhdr_novlan *)fcb_data;
	
	chfcoe_fcb_cb(fcb)->port = port;
	chfcoe_fcb_cb(fcb)->vlan_tci = vlan_tci;
	chfcoe_fc_mcast(fcb) = (G_RX_T5_PKTYPE(l2info) == 2) ? 1 : 0;
	chfcoe_fc_mpsid(fcb) = G_RX_MACIDX(l2info);
	chfcoe_fc_data_ptr(fcb) = fcb_data;
	chfcoe_fc_data_len(fcb) = fcb_len;

	switch(chfcoe_ntohs(eh->et)) {
	case PROTO_ETH_P_FCOE:
		chfcoe_fcb_pull_rx(fcb, sizeof(*eh));
		
		chfcoe_queue_fcoe_fcb(adap, fcb);
		break;

	case ETH_P_PROTO_FIP:
		chfcoe_queue_fip_fcb(adap, fcb);
		break;

	default:
		chfcoe_err(adap, "Unknown proto type : %d\n", chfcoe_ntohs(eh->et));
		CHFCOE_INC_STATS(pi, n_unknown_fr);
		break;
	}

	return;
}
