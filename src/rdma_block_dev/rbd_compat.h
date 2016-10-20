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
 *      copyright notice, this list of conditions and the following
 *      disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials
 *      provided with the distribution.
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

#ifndef __RBD_COMPAT_H
#define __RBD_COMPAT_H

#include <linux/version.h>

#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,13,0)
#define RQ_FOR_EACH_SEGMENT(bv, bvp, req, iter)           \
	rq_for_each_segment(bvp, req, iter)               \
	for (bv = *bvp; bvp != NULL ; bvp = NULL)
#else
#define RQ_FOR_EACH_SEGMENT(bv, bvp, req, iter)           \
	(void)(bvp);/* to silence the compiler warning */ \
	rq_for_each_segment(bv, req, iter)

#endif


#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,13,0)
#define BI_SECTOR bi_sector
#define BI_SIZE bi_size
#define BI_IDX bi_idx
#else
#define BI_SECTOR bi_iter.bi_sector
#define BI_SIZE bi_iter.bi_size
#define BI_IDX bi_iter.bi_idx
#define BI_BVEC_DONE bi_iter.bi_bvec_done
#endif

static inline struct ib_cq *IB_CREATE_CQ(struct ib_device *device,
			ib_comp_handler comp_handler,
			void (*event_handler)(struct ib_event *, void *),
			void *cq_context, int cqe, int comp_vector)
{
#ifdef HAVE_IB_CQ_INIT_ATTR
	struct ib_cq_init_attr attr = { };

	attr.cqe = cqe;
	attr.comp_vector = comp_vector;
	return ib_create_cq(device, comp_handler, event_handler, cq_context,
			    &attr);
#else
	return ib_create_cq(device, comp_handler, event_handler, cq_context,
			    cqe, comp_vector);
#endif
}

#endif /*  __RBD_COMPAT_H */
