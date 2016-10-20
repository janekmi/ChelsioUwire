/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/*
 * Description:
 * 	This chfcoe_init.c file contains module initialization routines
 */

#include "chfcoe_fcf.h"
#include "chfcoe_defs.h"
#include "chfcoe_adap.h"
#include "chfcoe_io.h"
#include "chfcoe_xchg.h"
#include "chfcoe_vn2vn.h"
#include "chfcoe_worker.h"
#include "chfcoe_lib.h"


extern struct chfcoe_node_info node_info[2];
extern struct chfcoe_control_work_data *control_d;
extern void *chfcoe_workq;
extern unsigned int chfcoe_node_num;
extern unsigned int chfcoe_node_id[2];
extern unsigned int chfcoe_worker_num[2];

void chfc_lnode_recv_req(struct chfcoe_lnode *, chfcoe_fc_buffer_t *);

chfcoe_retval_t
chfcoe_port_lnode_init(struct chfcoe_adap_info *adap, uint8_t port_num)
{
	chfcoe_retval_t	rv = CHFCOE_SUCCESS;
	struct chfcoe_port_info	*pi;

	/* Link the adap and port info */
	pi = CHFCOE_PTR_OFFSET(adap->pi, (port_num *  chfcoe_port_info_size));
	pi->port_num = port_num;
	chfcoe_mutex_init(pi->mtx_lock);
	chfcoe_head_init(&pi->ln_head);
	chfcoe_head_init(&pi->fcf_head);

	/* Generate wwnn & wwpn for given port */
	chfcoe_get_wwnn(pi->wwnn, pi->phy_mac, port_num, 0);
	chfcoe_get_wwpn(pi->wwpn, pi->wwnn, 0);
	if (chfcoe_lnode_alloc(pi) == NULL) {
		CHFCOE_INC_STATS(pi, n_nomem);	
		return CHFCOE_NOMEM;
	}
	if (adap->fip_mode == CHFCOE_VN2VN || 
		adap->fip_mode == CHFCOE_FIP_BOTH) {
		rv = chfcoe_vn2vn_init(pi);
		if (rv)
			CHFCOE_INC_STATS(pi, n_nomem);	
	}	
	return rv;
} /* chfcoe_port_lnode_init */	

void chfcoe_port_lnode_exit(struct chfcoe_adap_info *adap, uint8_t port_num)
{
	struct chfcoe_port_info	*pi;
	struct chfcoe_fcf 	*fcf;
	struct chfcoe_lnode *lnode = NULL;	
	
	pi = CHFCOE_PTR_OFFSET(adap->pi, (port_num * chfcoe_port_info_size));
	if (adap->fip_mode == CHFCOE_FCF || 
		adap->fip_mode == CHFCOE_FIP_BOTH) {
		while (!chfcoe_list_empty(&pi->fcf_head)) {
			chfcoe_deq_from_head(&pi->fcf_head, &fcf);
			if(fcf->state != CHFCOE_FCF_ST_OFFLINE) {
				chfcoe_err(adap, "port:%d destroy fcf in " 
				"invalid state:%d\n", pi->port_num, fcf->state);
			}
			lnode = chfcoe_fcf_to_ln(fcf);
			chfcoe_lnode_destroy(lnode);
			chfcoe_mem_free(fcf);
			CHFCOE_DEC_STATS(pi, n_fcf);
			pi->num_fcf --;
		}
	}
	if (adap->fip_mode == CHFCOE_VN2VN || 
		adap->fip_mode == CHFCOE_FIP_BOTH) {
		chfcoe_vn2vn_exit(pi);
	}

	/* Destroy root lnode */
	lnode = pi->root_ln;
	if (lnode->tgt_hdl)  
		chfcoe_tgt_unregister(lnode);
	chfcoe_mem_free(lnode);
	return;
} /* chfcoe_port_lnode_exit */

chfcoe_retval_t chfcoe_init(struct chfcoe_adap_info *adap)
{
	uint8_t j;
	int err = CHFCOE_SUCCESS;
	/* Initialize the ports */
	chfcoe_for_each_port(adap, j) 
		chfcoe_port_lnode_init(adap, j);
	
	chfcoe_register_fc4(PROTO_FC_TYPE_ELS, chfc_lnode_recv_req);

	return err;

} /* chfcoe_init */

void chfcoe_exit(struct chfcoe_adap_info *adap)
{
	uint8_t i;

	chfcoe_for_each_port(adap, i) 
		chfcoe_port_lnode_exit(adap, i);
	return;
} /* chfcoe_exit */

void chfcoe_node_info_init(void)
{
	unsigned int node_index = 0;

	for (node_index = 0; node_index < chfcoe_node_num; node_index++) {
		node_info[node_index].node_id = chfcoe_node_id[node_index];
		node_info[node_index].worker_num = chfcoe_worker_num[node_index];
	}
}

int chfcoe_module_init(void)
{
	unsigned int node_index;

	chfcoe_node_info_init();

	chfcoe_workq = chfcoe_alloc_workqueue("chfcoe_workq");
	if (chfcoe_workq == NULL) {
		chfcoe_err(0, "chfcoe: error create WQ\n");
		goto err0;
	}

	control_d = chfcoe_mem_alloc(chfcoe_control_work_data_size);
	if (control_d == NULL) {
		chfcoe_err(0, "chfcoe: error create WQ\n");
		goto err1;
	}

	control_d->chfcoe_rx_list = CHFCOE_PTR_OFFSET(control_d, sizeof(struct chfcoe_control_work_data));
	control_d->work = CHFCOE_PTR_OFFSET(control_d, (sizeof(struct chfcoe_control_work_data)
				+ os_sk_buff_head_size));
	control_d->work->work = CHFCOE_PTR_OFFSET(control_d, (sizeof(struct chfcoe_control_work_data)
				+ os_sk_buff_head_size + sizeof(chfcoe_work_t)));

	chfcoe_skb_queue_head_init(control_d->chfcoe_rx_list);
	control_d->chfcoe_rx_list_lock = chfcoe_sk_buff_head_lock(control_d->chfcoe_rx_list);
	chfcoe_init_work(control_d->work, chfcoe_control_recv, NULL);

	
	for (node_index = 0; node_index < chfcoe_node_num; node_index++) {
		if (chfcoe_create_workers(node_index) != CHFCOE_SUCCESS) {
			chfcoe_err(0, "chfcoe: error create chfcoe workers\n");
			if (node_index)
				chfcoe_destroy_workers(node_index);
			goto err2;
		}
	}

	return CHFCOE_SUCCESS;

err2:
	chfcoe_mem_free(control_d);
err1:
	chfcoe_destroy_workqueue(chfcoe_workq);
err0:
	return CHFCOE_NOMEM;
}

void chfcoe_module_exit(void)
{
	unsigned int node_index;

	for (node_index = 0; node_index < chfcoe_node_num; node_index++)
		chfcoe_destroy_workers(node_index);

	chfcoe_mem_free(control_d);
	chfcoe_destroy_workqueue(chfcoe_workq);
}

void chfcoe_flush_skb_queue(void)
{
	chfcoe_worker_skb_queue_purge();
	chfcoe_skb_queue_purge(control_d->chfcoe_rx_list);
	chfcoe_flush_workqueue(chfcoe_workq);
}
