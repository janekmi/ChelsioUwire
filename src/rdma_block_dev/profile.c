/*
 * Copyright (c) 2015 Chelsio Communications, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifdef PROFILE

#include "profile.h"

unsigned int prof_calls[LAST];
unsigned int prof_sample_idx[LAST];
struct timespec ts_func_enter[LAST][SAMPLES+1];
struct timespec ts_func_exit[LAST][SAMPLES+1];

static char *pevent_names[][2] = {
	{ "TGT_POLL_RCQ", "poll the rcq to get the next RBDP request" },
	{ "TGT_REQUEST", "process the RBDP request and submitting to the backend" },
	{ "TGT_BACKEND", "schedule the backend and completing the BIO operation" },
	{ "TGT_WRITE", "build/post/send RDMA Write" },
	{ "TGT_REPLY", "build/post/send the SEND with the RBDP reply" },
	{ "INI_REQUEST", "process the blkdev request" },
	{ "INI_MAP", "dma-map and fast-register the request sgl" },
	{ "INI_SEND", "send the RBDP request to target" },
	{ "INI_POLL_RCQ", "poll the rcq to get the RBDP reply" },
	{ "INI_REPLY", "process the RBDP reply and complete the blkdev request" },
};

static void compute_report(struct seq_file *seq, unsigned int idx)
{
	struct timespec delta_ts;
	unsigned int iters;
	s64 delta = 0, min = 0, max = 0, sum = 0, ave;
	int i;

	iters = prof_sample_idx[idx];
	for (i = SKIP; i < iters; i++) {
		delta_ts = timespec_sub(ts_func_exit[idx][i],ts_func_enter[idx][i]);
		delta = timespec_to_ns(&delta_ts);
		if (delta > max)
			max = delta;
		if (delta < min || min == 0)
			min = delta;
		sum += delta;
	}
	ave = div64_s64(sum, (s64)(iters - SKIP));
	seq_printf(seq, "\tAve %lld ns, Min %lld ns, Max %lld ns\n", ave, min, max);
}

static int profile_show(struct seq_file *seq, void *v)
{
	int i;

	for (i = 0; i < LAST; i++) {
		if (prof_sample_idx[i] >= SKIP) {
			seq_printf(seq, "%s: %s\n", pevent_names[i][0], pevent_names[i][1]);
			compute_report(seq, i);
		}
	}
	return 0;
}

static int profile_open(struct inode *inode, struct file *file)
{
	return single_open(file, profile_show, inode->i_private);
}

static ssize_t profile_clear(struct file *file, const char __user *buf,
			     size_t count, loff_t *pos)
{
	memset(prof_sample_idx, 0, sizeof prof_sample_idx);
	return count;
}

static const struct file_operations profile_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = profile_open,
	.release = single_release,
	.read 	 = seq_read,
	.llseek  = seq_lseek,
	.write   = profile_clear,
};

void myprofile_init(struct dentry *root)
{
	struct dentry *de;

	de = debugfs_create_file("profile", S_IWUSR, root,
				 NULL, &profile_debugfs_fops);
}
#else
#endif
