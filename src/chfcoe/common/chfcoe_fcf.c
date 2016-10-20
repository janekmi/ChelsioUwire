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
 * 	This chfcoe_fcf.c file contains fcoe fcf related routines
 *
 * Authors:
 * 	Deepti Vadde <deepti@chelsio.com>
 */

#include "chfcoe_defs.h"
#include "chfcoe_lnode.h"
#include "chfcoe_fcf.h"
#include "chfcoe_proto.h"

extern void chfcoe_fcf_ka_cbfn(void *data);
struct chfcoe_fcf *
chfcoe_alloc_fcf(struct chfcoe_port_info *pi)
{
	struct chfcoe_fcf *fcf;

	fcf = chfcoe_mem_alloc(chfcoe_fcf_size);
	if (!fcf) {
		chfcoe_err(pi, "port:%x Alloc of FCF failed\n", pi->port_num);
		CHFCOE_INC_STATS(pi, n_nomem);
		return NULL;
	}
	fcf->fcf_ka_timer_work = CHFCOE_PTR_OFFSET(fcf, sizeof(struct chfcoe_fcf)); 
	fcf->fcf_ka_timer_work->work = CHFCOE_PTR_OFFSET(fcf, sizeof(struct chfcoe_fcf)
			+ sizeof(chfcoe_dwork_t)); 
	/* Update fcf fields */
	chfcoe_fcf_to_pi(fcf) = pi;
	fcf->port_num = pi->port_num;
	chfcoe_memset(&fcf->stats, 0, sizeof (chfcoe_fcf_stats_t));
	chfcoe_init_delayed_work(fcf->fcf_ka_timer_work, chfcoe_fcf_ka_cbfn, fcf);

	/* Update the fcf list in port info */
	chfcoe_mutex_lock(pi->mtx_lock);
	chfcoe_enq_at_tail(&pi->fcf_head, fcf);
	chfcoe_mutex_unlock(pi->mtx_lock);
	pi->num_fcf++;
	return fcf;
} /* chfcoe_alloc_fcf */

void
chfcoe_free_fcf(struct chfcoe_fcf *fcf)
{
	/* First clear the FCF KA timer */
	chfcoe_cancel_delayed_work_sync(fcf->fcf_ka_timer_work);
	chfcoe_flush_delayed_work(fcf->fcf_ka_timer_work);
	
	/* reset all the fcf parameters. We dont know whether the same FCF will
	 * come back online
	 */
	chfcoe_dbg(pi, "free fcf:%p port:%x ln:%p\n", fcf, fcf->port_num, 
			fcf->lnode);
	fcf->state = CHFCOE_FCF_ST_OFFLINE;
	if (fcf->lnode) {
		chfcoe_lnode_evt_handler(fcf->lnode, CHFCOE_LN_EVT_LINK_DOWN,
				NULL);
		chfcoe_lnode_destroy(fcf->lnode);
	}
	chfcoe_mem_free(fcf);
	return;
} /* chfcoe_free_fcf */

void
chfcoe_stop_fcf(struct chfcoe_fcf *fcf)
{
	/* First clear the FCF KA timer */
	chfcoe_cancel_delayed_work_sync(fcf->fcf_ka_timer_work);
	chfcoe_flush_delayed_work(fcf->fcf_ka_timer_work);
	
	/* reset all the fcf parameters. We dont know whether the same FCF will
	 * come back online
	 */
	chfcoe_dbg(pi, "stop fcf:%p port:%x ln:%p\n", fcf, fcf->port_num, 
			fcf->lnode);
	fcf->state = CHFCOE_FCF_ST_OFFLINE;
	if (fcf->lnode) {
		chfcoe_lnode_evt_handler(fcf->lnode, CHFCOE_LN_EVT_LINK_DOWN,
				NULL);
	}
	return;
} /* chfcoe_stop_fcf */

chfcoe_retval_t
chfcoe_init_fcf(struct chfcoe_fcf *fcf, void *desc_pld, uint32_t desc_len)
{
	uint32_t len = 0, exp_desc_bm = 0;

	struct proto_fip_desc *desc = desc_pld;
	struct proto_fip_pri_desc *pri_desc;
	struct proto_fip_mac_desc *mac_desc;
	struct proto_fip_wwn_desc *wwn_desc;
	struct proto_fip_fab_desc *fab_desc;
	struct proto_fip_fka_desc *fka_desc;

	len = 0;
	exp_desc_bm = (1 << PROTO_FIP_DT_MAC) | (1 << PROTO_FIP_DT_NAME) | 
		      (1 << PROTO_FIP_DT_PRI) | (1 << PROTO_FIP_DT_FAB) | 
		      (1 << PROTO_FIP_DT_FKA);

	while (len < desc_len) {
		switch (desc->fip_dtype) {
		case PROTO_FIP_DT_PRI:
			exp_desc_bm &= ~(1 << PROTO_FIP_DT_PRI);
			pri_desc = (struct proto_fip_pri_desc *)desc;
			fcf->fcf_prio = pri_desc->fd_pri;
			break;

		case PROTO_FIP_DT_MAC:
			exp_desc_bm &= ~(1 << PROTO_FIP_DT_MAC);
			mac_desc = (struct proto_fip_mac_desc *)desc;
			chfcoe_memcpy(fcf->fcf_mac, mac_desc->fd_mac, 6);
			break;

		case PROTO_FIP_DT_NAME:
			exp_desc_bm &= ~(1 << PROTO_FIP_DT_NAME);
			wwn_desc = (struct proto_fip_wwn_desc *)desc;
			chfcoe_memcpy(fcf->fab_wwn, &wwn_desc->fd_wwn, 8);
			break;

		case PROTO_FIP_DT_FAB:
			exp_desc_bm &= ~(1 << PROTO_FIP_DT_FAB);
			fab_desc = (struct proto_fip_fab_desc *)desc;
			fcf->vf_id = chfcoe_ntohs(fab_desc->fd_vfid);
			chfcoe_memcpy(fcf->fc_map, fab_desc->fd_map, 3);
			chfcoe_memcpy(fcf->fab_wwn, &fab_desc->fd_wwn, 8);
			break;

		case PROTO_FIP_DT_FKA:
			exp_desc_bm &= ~(1 << PROTO_FIP_DT_FKA);
			fka_desc = (struct proto_fip_fka_desc *)desc;
			fcf->fka_adv_prd 	= 
					(fka_desc->fd_fka_period / 1000);
			break;

		default:
			break;
		}
		len += desc->fip_dlen;
		desc = (struct proto_fip_desc *)
				((uintptr_t)desc + (desc->fip_dlen * 4));
	}
	return CHFCOE_SUCCESS;
} /* fcoe_init_fcf */

struct chfcoe_fcf *
chfcoe_get_fcf(struct chfcoe_port_info *pi, uint8_t *mac, uint16_t vlan_id)
{
	struct chfcoe_fcf	*fcf;
        struct chfcoe_list	*fcf_tmp;
	uint8_t			fcf_mac[6];

	chfcoe_memcpy(fcf_mac, mac, 6);
	chfcoe_mutex_lock(pi->mtx_lock);
	chfcoe_list_for_each(fcf_tmp, &pi->fcf_head) {
		fcf = (struct chfcoe_fcf *)fcf_tmp;
		if (!chfcoe_memcmp(fcf->fcf_mac, fcf_mac, 6)) {
			if (fcf->vlan_id == vlan_id) {
				chfcoe_mutex_unlock(pi->mtx_lock);
				return fcf;
			}
		}
	}
	chfcoe_err(pi, "port:%x could not find FCF\n", pi->port_num);
	chfcoe_mutex_unlock(pi->mtx_lock);
	return NULL;
} /* chfcoe_get_fcf */

struct chfcoe_fcf *
chfcoe_detach_fcf(struct chfcoe_port_info *pi, uint8_t *mac, uint16_t vlan_id)
{
	struct chfcoe_fcf	*fcf;
        struct chfcoe_list	*fcf_tmp;
	uint8_t			fcf_mac[6];

	chfcoe_memcpy(fcf_mac, mac, 6);
	chfcoe_mutex_lock(pi->mtx_lock);
	chfcoe_list_for_each(fcf_tmp, &pi->fcf_head) {
		fcf = (struct chfcoe_fcf *)fcf_tmp;
		if (!chfcoe_memcmp(fcf->fcf_mac, fcf_mac, 6)) {
			if (fcf->vlan_id == vlan_id) {
				chfcoe_deq_elem(fcf);
				chfcoe_mutex_unlock(pi->mtx_lock);
				pi->num_fcf--;
				return fcf;
			}
		}
	}
	chfcoe_err(pi, "port:%x could not find FCF\n", pi->port_num);
	chfcoe_mutex_unlock(pi->mtx_lock);
	return NULL;
} /* chfcoe_get_fcf */
