/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver for Linux.
 *
 * Copyright (C) 2003-2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

int cxgb4_setup_debugfs(struct adapter *adap);
int sge_queue_entries(const struct adapter *adap);
void *sge_queue_start(struct seq_file *seq, loff_t *pos);
void sge_queue_stop(struct seq_file *seq, void *v);
void *sge_queue_next(struct seq_file *seq, void *v, loff_t *pos);
