/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2006, 2007 Cisco Systems, Inc.  All rights reserved.
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

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "ibverbs.h"

int ibv_rate_to_mult(enum ibv_rate rate)
{
	switch (rate) {
	case IBV_RATE_2_5_GBPS: return  1;
	case IBV_RATE_5_GBPS:   return  2;
	case IBV_RATE_10_GBPS:  return  4;
	case IBV_RATE_20_GBPS:  return  8;
	case IBV_RATE_30_GBPS:  return 12;
	case IBV_RATE_40_GBPS:  return 16;
	case IBV_RATE_60_GBPS:  return 24;
	case IBV_RATE_80_GBPS:  return 32;
	case IBV_RATE_120_GBPS: return 48;
	default:           return -1;
	}
}

enum ibv_rate mult_to_ibv_rate(int mult)
{
	switch (mult) {
	case 1:  return IBV_RATE_2_5_GBPS;
	case 2:  return IBV_RATE_5_GBPS;
	case 4:  return IBV_RATE_10_GBPS;
	case 8:  return IBV_RATE_20_GBPS;
	case 12: return IBV_RATE_30_GBPS;
	case 16: return IBV_RATE_40_GBPS;
	case 24: return IBV_RATE_60_GBPS;
	case 32: return IBV_RATE_80_GBPS;
	case 48: return IBV_RATE_120_GBPS;
	default: return IBV_RATE_MAX;
	}
}

int ibv_rate_to_mbps(enum ibv_rate rate)
{
	switch (rate) {
	case IBV_RATE_2_5_GBPS: return 2500;
	case IBV_RATE_5_GBPS:   return 5000;
	case IBV_RATE_10_GBPS:  return 10000;
	case IBV_RATE_20_GBPS:  return 20000;
	case IBV_RATE_30_GBPS:  return 30000;
	case IBV_RATE_40_GBPS:  return 40000;
	case IBV_RATE_60_GBPS:  return 60000;
	case IBV_RATE_80_GBPS:  return 80000;
	case IBV_RATE_120_GBPS: return 120000;
	case IBV_RATE_14_GBPS:  return 14062;
	case IBV_RATE_56_GBPS:  return 56250;
	case IBV_RATE_112_GBPS: return 112500;
	case IBV_RATE_168_GBPS: return 168750;
	case IBV_RATE_25_GBPS:  return 25781;
	case IBV_RATE_100_GBPS: return 103125;
	case IBV_RATE_200_GBPS: return 206250;
	case IBV_RATE_300_GBPS: return 309375;
	default:               return -1;
	}
}

enum ibv_rate mbps_to_ibv_rate(int mbps)
{
	switch (mbps) {
	case 2500:   return IBV_RATE_2_5_GBPS;
	case 5000:   return IBV_RATE_5_GBPS;
	case 10000:  return IBV_RATE_10_GBPS;
	case 20000:  return IBV_RATE_20_GBPS;
	case 30000:  return IBV_RATE_30_GBPS;
	case 40000:  return IBV_RATE_40_GBPS;
	case 60000:  return IBV_RATE_60_GBPS;
	case 80000:  return IBV_RATE_80_GBPS;
	case 120000: return IBV_RATE_120_GBPS;
	case 14062:  return IBV_RATE_14_GBPS;
	case 56250:  return IBV_RATE_56_GBPS;
	case 112500: return IBV_RATE_112_GBPS;
	case 168750: return IBV_RATE_168_GBPS;
	case 25781:  return IBV_RATE_25_GBPS;
	case 103125: return IBV_RATE_100_GBPS;
	case 206250: return IBV_RATE_200_GBPS;
	case 309375: return IBV_RATE_300_GBPS;
	default:     return IBV_RATE_MAX;
	}
}

int __ibv_query_device(struct ibv_context *context,
		       struct ibv_device_attr *device_attr)
{
	return context->ops.query_device(context, device_attr);
}
default_symver(__ibv_query_device, ibv_query_device);

int __ibv_query_port(struct ibv_context *context, uint8_t port_num,
		     struct ibv_port_attr *port_attr)
{
	return context->ops.query_port(context, port_num, port_attr);
}
default_symver(__ibv_query_port, ibv_query_port);

int __ibv_query_gid(struct ibv_context *context, uint8_t port_num,
		    int index, union ibv_gid *gid)
{
	char name[24];
	char attr[41];
	uint16_t val;
	int i;

	snprintf(name, sizeof name, "ports/%d/gids/%d", port_num, index);

	if (ibv_read_sysfs_file(context->device->ibdev_path, name,
				attr, sizeof attr) < 0)
		return -1;

	for (i = 0; i < 8; ++i) {
		if (sscanf(attr + i * 5, "%hx", &val) != 1)
			return -1;
		gid->raw[i * 2    ] = val >> 8;
		gid->raw[i * 2 + 1] = val & 0xff;
	}

	return 0;
}
default_symver(__ibv_query_gid, ibv_query_gid);

int __ibv_query_pkey(struct ibv_context *context, uint8_t port_num,
		     int index, uint16_t *pkey)
{
	char name[24];
	char attr[8];
	uint16_t val;

	snprintf(name, sizeof name, "ports/%d/pkeys/%d", port_num, index);

	if (ibv_read_sysfs_file(context->device->ibdev_path, name,
				attr, sizeof attr) < 0)
		return -1;

	if (sscanf(attr, "%hx", &val) != 1)
		return -1;

	*pkey = htons(val);
	return 0;
}
default_symver(__ibv_query_pkey, ibv_query_pkey);

struct ibv_pd *__ibv_alloc_pd(struct ibv_context *context)
{
	struct ibv_pd *pd;

	pd = context->ops.alloc_pd(context);
	if (pd)
		pd->context = context;

	return pd;
}
default_symver(__ibv_alloc_pd, ibv_alloc_pd);

int __ibv_dealloc_pd(struct ibv_pd *pd)
{
	return pd->context->ops.dealloc_pd(pd);
}
default_symver(__ibv_dealloc_pd, ibv_dealloc_pd);

struct ibv_mr *__ibv_reg_mr(struct ibv_pd *pd, void *addr,
			    size_t length, int access)
{
	struct ibv_mr *mr;

	if (ibv_dontfork_range(addr, length))
		return NULL;

	mr = pd->context->ops.reg_mr(pd, addr, length, access);
	if (mr) {
		mr->context = pd->context;
		mr->pd      = pd;
		mr->addr    = addr;
		mr->length  = length;
	} else
		ibv_dofork_range(addr, length);

	return mr;
}
default_symver(__ibv_reg_mr, ibv_reg_mr);

int __ibv_dereg_mr(struct ibv_mr *mr)
{
	int ret;
	void *addr	= mr->addr;
	size_t length	= mr->length;

	ret = mr->context->ops.dereg_mr(mr);
	if (!ret)
		ibv_dofork_range(addr, length);

	return ret;
}
default_symver(__ibv_dereg_mr, ibv_dereg_mr);

static struct ibv_comp_channel *ibv_create_comp_channel_v2(struct ibv_context *context)
{
	struct ibv_abi_compat_v2 *t = context->abi_compat;
	static int warned;

	if (!pthread_mutex_trylock(&t->in_use))
		return &t->channel;

	if (!warned) {
		fprintf(stderr, PFX "Warning: kernel's ABI version %d limits capacity.\n"
			"    Only one completion channel can be created per context.\n",
			abi_ver);
		++warned;
	}

	return NULL;
}

struct ibv_comp_channel *ibv_create_comp_channel(struct ibv_context *context)
{
	struct ibv_comp_channel            *channel;
	struct ibv_create_comp_channel      cmd;
	struct ibv_create_comp_channel_resp resp;

	if (abi_ver <= 2)
		return ibv_create_comp_channel_v2(context);

	channel = malloc(sizeof *channel);
	if (!channel)
		return NULL;

	IBV_INIT_CMD_RESP(&cmd, sizeof cmd, CREATE_COMP_CHANNEL, &resp, sizeof resp);
	if (write(context->cmd_fd, &cmd, sizeof cmd) != sizeof cmd) {
		free(channel);
		return NULL;
	}

	(void) VALGRIND_MAKE_MEM_DEFINED(&resp, sizeof resp);

	channel->context = context;
	channel->fd      = resp.fd;
	channel->refcnt  = 0;

	return channel;
}

static int ibv_destroy_comp_channel_v2(struct ibv_comp_channel *channel)
{
	struct ibv_abi_compat_v2 *t = (struct ibv_abi_compat_v2 *) channel;
	pthread_mutex_unlock(&t->in_use);
	return 0;
}

int ibv_destroy_comp_channel(struct ibv_comp_channel *channel)
{
	struct ibv_context *context;
	int ret;

	context = channel->context;
	pthread_mutex_lock(&context->mutex);

	if (channel->refcnt) {
		ret = EBUSY;
		goto out;
	}

	if (abi_ver <= 2) {
		ret = ibv_destroy_comp_channel_v2(channel);
		goto out;
	}

	close(channel->fd);
	free(channel);
	ret = 0;

out:
	pthread_mutex_unlock(&context->mutex);

	return ret;
}

struct ibv_cq *__ibv_create_cq(struct ibv_context *context, int cqe, void *cq_context,
			       struct ibv_comp_channel *channel, int comp_vector)
{
	struct ibv_cq *cq;

	pthread_mutex_lock(&context->mutex);

	cq = context->ops.create_cq(context, cqe, channel, comp_vector);

	if (cq) {
		cq->context    	     	   = context;
		cq->channel		   = channel;
		if (channel)
			++channel->refcnt;
		cq->cq_context 	     	   = cq_context;
		cq->comp_events_completed  = 0;
		cq->async_events_completed = 0;
		pthread_mutex_init(&cq->mutex, NULL);
		pthread_cond_init(&cq->cond, NULL);
	}

	pthread_mutex_unlock(&context->mutex);

	return cq;
}
default_symver(__ibv_create_cq, ibv_create_cq);

int __ibv_resize_cq(struct ibv_cq *cq, int cqe)
{
	if (!cq->context->ops.resize_cq)
		return ENOSYS;

	return cq->context->ops.resize_cq(cq, cqe);
}
default_symver(__ibv_resize_cq, ibv_resize_cq);

int __ibv_destroy_cq(struct ibv_cq *cq)
{
	struct ibv_comp_channel *channel = cq->channel;
	int ret;

	if (channel)
		pthread_mutex_lock(&channel->context->mutex);

	ret = cq->context->ops.destroy_cq(cq);

	if (channel) {
		if (!ret)
			--channel->refcnt;
		pthread_mutex_unlock(&channel->context->mutex);
	}

	return ret;
}
default_symver(__ibv_destroy_cq, ibv_destroy_cq);

int __ibv_get_cq_event(struct ibv_comp_channel *channel,
		       struct ibv_cq **cq, void **cq_context)
{
	struct ibv_comp_event ev;

	if (read(channel->fd, &ev, sizeof ev) != sizeof ev)
		return -1;

	*cq         = (struct ibv_cq *) (uintptr_t) ev.cq_handle;
	*cq_context = (*cq)->cq_context;

	if ((*cq)->context->ops.cq_event)
		(*cq)->context->ops.cq_event(*cq);

	return 0;
}
default_symver(__ibv_get_cq_event, ibv_get_cq_event);

void __ibv_ack_cq_events(struct ibv_cq *cq, unsigned int nevents)
{
	pthread_mutex_lock(&cq->mutex);
	cq->comp_events_completed += nevents;
	pthread_cond_signal(&cq->cond);
	pthread_mutex_unlock(&cq->mutex);
}
default_symver(__ibv_ack_cq_events, ibv_ack_cq_events);

struct ibv_srq *__ibv_create_srq(struct ibv_pd *pd,
				 struct ibv_srq_init_attr *srq_init_attr)
{
	struct ibv_srq *srq;

	if (!pd->context->ops.create_srq)
		return NULL;

	srq = pd->context->ops.create_srq(pd, srq_init_attr);
	if (srq) {
		srq->context          = pd->context;
		srq->srq_context      = srq_init_attr->srq_context;
		srq->pd               = pd;
		srq->events_completed = 0;
		pthread_mutex_init(&srq->mutex, NULL);
		pthread_cond_init(&srq->cond, NULL);
	}

	return srq;
}
default_symver(__ibv_create_srq, ibv_create_srq);

int __ibv_modify_srq(struct ibv_srq *srq,
		     struct ibv_srq_attr *srq_attr,
		     int srq_attr_mask)
{
	return srq->context->ops.modify_srq(srq, srq_attr, srq_attr_mask);
}
default_symver(__ibv_modify_srq, ibv_modify_srq);

int __ibv_query_srq(struct ibv_srq *srq, struct ibv_srq_attr *srq_attr)
{
	return srq->context->ops.query_srq(srq, srq_attr);
}
default_symver(__ibv_query_srq, ibv_query_srq);

int __ibv_destroy_srq(struct ibv_srq *srq)
{
	return srq->context->ops.destroy_srq(srq);
}
default_symver(__ibv_destroy_srq, ibv_destroy_srq);

struct ibv_qp *__ibv_create_qp(struct ibv_pd *pd,
			       struct ibv_qp_init_attr *qp_init_attr)
{
	struct ibv_qp *qp = pd->context->ops.create_qp(pd, qp_init_attr);

	if (qp) {
		qp->context    	     = pd->context;
		qp->qp_context 	     = qp_init_attr->qp_context;
		qp->pd         	     = pd;
		qp->send_cq    	     = qp_init_attr->send_cq;
		qp->recv_cq    	     = qp_init_attr->recv_cq;
		qp->srq        	     = qp_init_attr->srq;
		qp->qp_type          = qp_init_attr->qp_type;
		qp->state	     = IBV_QPS_RESET;
		qp->events_completed = 0;
		pthread_mutex_init(&qp->mutex, NULL);
		pthread_cond_init(&qp->cond, NULL);
	}

	return qp;
}
default_symver(__ibv_create_qp, ibv_create_qp);

int __ibv_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		   int attr_mask,
		   struct ibv_qp_init_attr *init_attr)
{
	int ret;

	ret = qp->context->ops.query_qp(qp, attr, attr_mask, init_attr);
	if (ret)
		return ret;

	if (attr_mask & IBV_QP_STATE)
		qp->state = attr->qp_state;

	return 0;
}
default_symver(__ibv_query_qp, ibv_query_qp);

int __ibv_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		    int attr_mask)
{
	int ret;

	ret = qp->context->ops.modify_qp(qp, attr, attr_mask);
	if (ret)
		return ret;

	if (attr_mask & IBV_QP_STATE)
		qp->state = attr->qp_state;

	return 0;
}
default_symver(__ibv_modify_qp, ibv_modify_qp);

int __ibv_destroy_qp(struct ibv_qp *qp)
{
	return qp->context->ops.destroy_qp(qp);
}
default_symver(__ibv_destroy_qp, ibv_destroy_qp);

struct ibv_ah *__ibv_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr)
{
	struct ibv_ah *ah = pd->context->ops.create_ah(pd, attr);

	if (ah) {
		ah->context = pd->context;
		ah->pd      = pd;
	}

	return ah;
}
default_symver(__ibv_create_ah, ibv_create_ah);

static int ibv_find_gid_index(struct ibv_context *context, uint8_t port_num,
			      union ibv_gid *gid)
{
	union ibv_gid sgid;
	int i = 0, ret;

	do {
		ret = ibv_query_gid(context, port_num, i++, &sgid);
	} while (!ret && memcmp(&sgid, gid, sizeof *gid));

	return ret ? ret : i - 1;
}

int ibv_init_ah_from_wc(struct ibv_context *context, uint8_t port_num,
			struct ibv_wc *wc, struct ibv_grh *grh,
			struct ibv_ah_attr *ah_attr)
{
	uint32_t flow_class;
	int ret;

	memset(ah_attr, 0, sizeof *ah_attr);
	ah_attr->dlid = wc->slid;
	ah_attr->sl = wc->sl;
	ah_attr->src_path_bits = wc->dlid_path_bits;
	ah_attr->port_num = port_num;

	if (wc->wc_flags & IBV_WC_GRH) {
		ah_attr->is_global = 1;
		ah_attr->grh.dgid = grh->sgid;

		ret = ibv_find_gid_index(context, port_num, &grh->dgid);
		if (ret < 0)
			return ret;

		ah_attr->grh.sgid_index = (uint8_t) ret;
		flow_class = ntohl(grh->version_tclass_flow);
		ah_attr->grh.flow_label = flow_class & 0xFFFFF;
		ah_attr->grh.hop_limit = grh->hop_limit;
		ah_attr->grh.traffic_class = (flow_class >> 20) & 0xFF;
	}
	return 0;
}

struct ibv_ah *ibv_create_ah_from_wc(struct ibv_pd *pd, struct ibv_wc *wc,
				     struct ibv_grh *grh, uint8_t port_num)
{
	struct ibv_ah_attr ah_attr;
	int ret;

	ret = ibv_init_ah_from_wc(pd->context, port_num, wc, grh, &ah_attr);
	if (ret)
		return NULL;

	return ibv_create_ah(pd, &ah_attr);
}

int __ibv_destroy_ah(struct ibv_ah *ah)
{
	return ah->context->ops.destroy_ah(ah);
}
default_symver(__ibv_destroy_ah, ibv_destroy_ah);

int __ibv_attach_mcast(struct ibv_qp *qp, const union ibv_gid *gid, uint16_t lid)
{
	return qp->context->ops.attach_mcast(qp, gid, lid);
}
default_symver(__ibv_attach_mcast, ibv_attach_mcast);

int __ibv_detach_mcast(struct ibv_qp *qp, const union ibv_gid *gid, uint16_t lid)
{
	return qp->context->ops.detach_mcast(qp, gid, lid);
}
default_symver(__ibv_detach_mcast, ibv_detach_mcast);
