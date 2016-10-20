/*
 * Copyright (c) 2010-2015 Chelsio Communications. All rights reserved.
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
#include <string.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>

#include <sys/errno.h>

#include "libcxgb4_sock.h"

struct um_ep {
	LIST_ENTRY(um_ep)	list;
	char 			interface[IFNAMSIZ];
	uint16_t		port;
	uint16_t		vlan;
	uint8_t 		priority;
};

LIST_HEAD(, um_ep) um_eps;

void add_endpoint(char *interface, uint16_t port, uint16_t vlan,
		  uint8_t priority)
{
	struct um_ep *ep;
	static int wildcard;

	DBG(DBG_INIT, "endpoint: iface %s port %u vlan %u priority %u\n",
	    interface, ntohs(port), vlan, priority);

	LIST_FOREACH(ep, &um_eps, list)
		if (!strcmp(ep->interface, interface) && (ep->port == port)) {
			VERBOSE(DBG_INIT, "Warning - Duplicate endpoint in config file.\n");
			return;
		}
	ep = calloc(1, sizeof *ep);
	if (!ep) {
		VERBOSE(DBG_INIT, "Warning - Failed to add um-endpoint from config file.\n");
		return;
	}
	strcpy(ep->interface, interface);
	ep->port = port;
	ep->vlan = vlan ? vlan : VLAN_ID_NA;
	ep->priority = priority;
	LIST_INSERT_HEAD(&um_eps, ep, list);
	if (!port) {
		if (wildcard)
			VERBOSE(DBG_INIT, 
				"Warning - Multiple wildcard endpoints defined.  "
				"You might need to use per-process config files.  "
				"Please read the WD User Guide.\n");
		else
			wildcard = 1;
	}
	DBG(DBG_INIT, "Exit\n");
}

int lookup_endpoint(uint16_t port, char *name, uint16_t *pvlan,
		    uint8_t *ppriority)
{
	struct um_ep *ep, *wildcard_ep = NULL;

	/*
	 * Find an exact match first, and then if non exists, and a
	 * wildcard exists (port == 0), then use that one.
	 */
	LIST_FOREACH(ep, &um_eps, list) {
		if (!ep->port)
			wildcard_ep = ep;
		if (ep->port == port) {
			strcpy(name, ep->interface);
			*pvlan = ep->vlan;
			*ppriority = ep->priority;
			return 0;
		}
	}
	if (wildcard_ep) {
		strcpy(name, wildcard_ep->interface);
		*pvlan = wildcard_ep->vlan;
		*ppriority = wildcard_ep->priority;
		return 0;
	}
	return ENODATA;
}
