#ifdef OISCSI_LIBISCSI2
/*
 * cxgbi_compat_oiscsi2.h: Chelsio T3/T4 iSCSI driver backport compat header.
 * 		when compiling with in-kernel open-iscsi on RHEL systems 
 *
 * Copyright (c) 2012-2015 Chelsio Communications, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by:	Karen Xie (k...@chelsio.com)
 *		Rakesh Ranjan (rran...@chelsio.com)
 */
#ifndef __CXGBI_COMPAT_OISCSI2_H__
#define __CXGBI_COMPAT_OISCSI2_H__

#include <scsi/scsi.h>
#include <scsi/iscsi_compat2.h>
#include <scsi/iscsi_proto2.h>
#include <scsi/libiscsi2.h>
#include <scsi/scsi_transport_iscsi2.h>

#define iscsi_host_remove	iscsi2_host_remove
#define iscsi_host_free		iscsi2_host_free
#define iscsi_host_alloc	iscsi2_host_alloc
#define iscsi_host_add		iscsi2_host_add
#define iscsi_host_set_param	iscsi2_host_set_param
#define iscsi_host_get_param	iscsi2_host_get_param
#define iscsi_set_param		iscsi2_set_param
#define iscsi_get_param		iscsi2_get_param
#define iscsi_itt_to_ctask	iscsi2_itt_to_ctask
#define iscsi_conn_failure	iscsi2_conn_failure
#define iscsi_session_get_param	iscsi2_session_get_param
#define iscsi_conn_set_param	iscsi2_conn_set_param
#define iscsi_conn_get_param	iscsi2_conn_get_param
#define iscsi_lookup_endpoint	iscsi2_lookup_endpoint
#define iscsi_create_endpoint	iscsi2_create_endpoint
#define iscsi_destroy_endpoint	iscsi2_destroy_endpoint
#define iscsi_conn_start	iscsi2_conn_start
#define iscsi_conn_stop		iscsi2_conn_stop
#define iscsi_conn_bind		iscsi2_conn_bind
#define iscsi_conn_send_pdu	iscsi2_conn_send_pdu
#define iscsi_session_setup	iscsi2_session_setup
#define iscsi_session_teardown	iscsi2_session_teardown
#define iscsi_session_recovery_timedout	iscsi2_session_recovery_timedout
#define iscsi_suspend_tx	iscsi2_suspend_tx
#define iscsi_eh_abort		iscsi2_eh_abort
#define iscsi_eh_device_reset	iscsi2_eh_device_reset
#define iscsi_queuecommand	iscsi2_queuecommand
#define iscsi_change_queue_depth	iscsi2_change_queue_depth
#define iscsi_register_transport	iscsi2_register_transport
#define iscsi_unregister_transport	iscsi2_unregister_transport
#define iscsi_target_alloc		iscsi2_target_alloc

#define ISCSI_TGT_RESET_TMO	0

#define scsi_bidi_cmnd(scmd)	0

#define skb_transport_header(skb)	((skb)->h.raw)
#define skb_priority_queue(skb)		((skb)->priority)

#if 0
static inline int sysfs_format_mac(char *buf, char *addr, int max)
{
	int i;
	int len = 0;

	for (i = 0; i < max; i++) {
		len += sprintf(buf + len, "%02x:", addr[i]);
		buf[len] = '\0';
		len--;
	}
	return len;
}
#endif

int cxgbi_host_reset(struct scsi_cmnd *);
#endif /* __CXGBI_COMPAT_OISCSI2_H__ */

#endif /* ifdef OISCSI_LIBISCSI2 */
