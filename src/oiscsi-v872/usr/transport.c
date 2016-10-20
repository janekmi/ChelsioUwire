/*
 * iSCSI transport
 *
 * Copyright (C) 2006 Mike Christie
 * Copyright (C) 2006 Red Hat, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include "initiator.h"
#include "transport.h"
#include "log.h"
#include "iscsi_util.h"
#include "iscsi_sysfs.h"
#include "cxgb3i.h"
#include "be2iscsi.h"

struct iscsi_transport_template iscsi_tcp = {
	.name		= "tcp",
	.ep_connect	= iscsi_io_tcp_connect,
	.ep_poll	= iscsi_io_tcp_poll,
	.ep_disconnect	= iscsi_io_tcp_disconnect,
};

struct iscsi_transport_template iscsi_iser = {
	.name		= "iser",
	.rdma		= 1,
	.ep_connect	= ktransport_ep_connect,
	.ep_poll	= ktransport_ep_poll,
	.ep_disconnect	= ktransport_ep_disconnect,
};

struct iscsi_transport_template cxgb3i = {
	.name		= "cxgb3i",
	.set_host_ip	= 2,
	.ep_connect	= ktransport_ep_connect,
	.ep_poll	= ktransport_ep_poll,
	.ep_disconnect	= ktransport_ep_disconnect,
	.create_conn	= cxgb3i_create_conn,
};

struct iscsi_transport_template cxgb4i = {
	.name		= "cxgb4i",
	.set_host_ip	= 2,
	.ep_connect	= ktransport_ep_connect,
	.ep_poll	= ktransport_ep_poll,
	.ep_disconnect	= ktransport_ep_disconnect,
	.create_conn	= cxgb3i_create_conn,
};

struct iscsi_transport_template bnx2i = {
	.name		= "bnx2i",
	.set_host_ip	= 1,
	.ep_connect	= ktransport_ep_connect,
	.ep_poll	= ktransport_ep_poll,
	.ep_disconnect	= ktransport_ep_disconnect,
};

struct iscsi_transport_template be2iscsi = {
	.name		= "be2iscsi",
	.create_conn	= be2iscsi_create_conn,
	.ep_connect	= ktransport_ep_connect,
	.ep_poll	= ktransport_ep_poll,
	.ep_disconnect	= ktransport_ep_disconnect,
};

struct iscsi_transport_template qla4xxx = {
	.name		= "qla4xxx",
};

static struct iscsi_transport_template *iscsi_transport_templates[] = {
	&iscsi_tcp,
	&iscsi_iser,
	&cxgb3i,
	&cxgb4i,
	&bnx2i,
	&qla4xxx,
	&be2iscsi,
	NULL
};

int set_transport_template(struct iscsi_transport *t)
{
	struct iscsi_transport_template *tmpl;
	int j;

	for (j = 0; iscsi_transport_templates[j] != NULL; j++) {
		tmpl = iscsi_transport_templates[j];

		if (!strcmp(tmpl->name, t->name)) {
			t->template = tmpl;
			log_debug(3, "Matched transport %s\n", t->name);
			return 0;
		}
	}

	log_error("Could not find uspace transport for %s\n", t->name);
	return ENOSYS;
}
