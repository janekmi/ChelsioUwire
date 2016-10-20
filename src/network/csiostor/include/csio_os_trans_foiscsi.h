/*
 *  Copyright (C) 2008-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: foiscsi transport functions. The possible transport could be
 * chelsio properietary interface (ioctl based),  open-iscsi or any other.
 *
 */

#ifndef __CSIO_OS_TRANS_FOISCSI_H__
#define __CSIO_OS_TRANS_FOISCSI_H__

#include <csio_defs.h>

char *csio_os_foiscsi_transport_get_name(struct foiscsi_transport *);
int csio_os_foiscsi_transport_count(void);
struct foiscsi_transport *csio_os_foiscsi_transport_get(unsigned int);

#endif /* __CSIO_OS_TRANS_FOISCSI_H__ */
