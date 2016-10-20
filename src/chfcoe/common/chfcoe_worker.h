/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __CHFCOE_WORKER_H__
#define __CHFCOE_WORKER_H__

#include "chfcoe_defs.h"

struct chfcoe_control_work_data {
	void *chfcoe_rx_list;
	void *chfcoe_rx_list_lock;
	chfcoe_work_t *work;
};

#define chfcoe_control_work_data_size	(sizeof(struct chfcoe_control_work_data) \
	       				+ os_sk_buff_head_size + chfcoe_work_size)
struct chfcoe_perworker_data {
	struct task_struct *task;
	void *chfcoe_rx_list;
	void *chfcoe_rx_list_lock;
	void *chfcoe_rx_tmp_list;
};

#define chfcoe_perworker_data_size	(sizeof(struct chfcoe_perworker_data) +	(2 * os_sk_buff_head_size))

struct chfcoe_node_info {
	int node_id;
	unsigned int worker_num;
	struct chfcoe_per_worker_data *worker_data;
	void *counter;
};

void chfcoe_control_recv(void *data);
void chfcoe_flush_workers(unsigned int node_index);
int chfcoe_create_workers(unsigned int node_index);
void chfcoe_destroy_workers(unsigned int node_index);
void chfcoe_worker_skb_queue_purge(void);
#endif
