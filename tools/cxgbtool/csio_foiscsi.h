/******************************************************************************
 *
 * Copyright (c) Chelsio Communications.  All rights reserved.
 *
 *   THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
 *   KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 *   IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
 *   PURPOSE.
 *
 * Module Name:
 *
 *    csio_iscsi.h
 *
 * Abstract:
 *
 *    csio_iscsi.h -  contains the common Chelsio iSCSI specific handlers'
 *		     definitions & headers.
 *
 * Environment:
 *
 *    User mode
 *
 * Revision History:
 *
 *	Vijay S J - 08-March-11 -	Creation
 *
 *****************************************************************************/



#ifndef __CSIO_ISCSI_H__
#define __CSIO_ISCSI_H__

#include <csio_hw.h>
#include <csio_defs.h>
#include <csio_stor_ioctl.h>
#include <csio_foiscsi_ioctl.h> /* Common header across user/kernel. */
#include <csio_foiscsi_persistent.h>

enum {
	ADD = 0,
	MOD,
	DEL
};

typedef void (*os_net_cfg_fn)(void *);
typedef int (*os_edit_inst_fn)(char *, int, int, char *, char *, char *, char *, char *);
typedef void (*os_show_insts_fn)(int);
typedef void (*os_show_netcfg_fn)(int, int);
typedef int (*os_read_ini_info_fn)(struct iscsi_initiator *);
typedef void (*os_del_net_cfg_fn)(int, int);
typedef int (*os_read_iscsi_param_fn)(struct foiscsi_login_info *, int);

typedef struct _csio_iscsi_ops {

	os_edit_inst_fn			os_edit_inst;
	os_show_insts_fn		os_show_inst;
	os_read_ini_info_fn		os_read_ini;
	os_net_cfg_fn			os_net_cfg;
	os_del_net_cfg_fn		os_del_net_cfg;
	os_show_netcfg_fn		os_show_net_cfg;
	os_read_iscsi_param_fn		os_read_iscsi_param;

} csio_iscsi_ops_t;

#ifdef CHSTORUTIL_INCLUDE_ISCSI_INITIALIZATIONS

	csio_iscsi_ops_t iscsi_ops	= {0};

#else

	extern csio_iscsi_ops_t 	iscsi_ops;

#endif /* (CHSTORUTIL_INCLUDE_ISCSI_INITIALIZATIONS) */

void convert_decimal_ip(char ip[], uint32_t ipaddr);

void csio_show_instances(adap_handle_t hw, int all);

void csio_edit_instance(adap_handle_t hw,
			char *, 
			int oper,
			int id,
			char *name,
			char *alias,
			char *auth,
			char *uname,
			char *pwd);

void csio_get_iscsi_name(adap_handle_t hw);

int csio_edit_net_cfg(adap_handle_t hw, 
		      int oper,
		      int idx,
		      char *ip, 
		      char *gateway, 
		      char *netmask,
		      char *bcaddr,
		      int mtu,
		      int dhcp,
		      int vlan,
		      int port);

int csio_del_net_cfg(adap_handle_t hw, int port, int idx);

int csio_show_sess_info(adap_handle_t hw);

int csio_show_net_cfg(adap_handle_t hw, int port, int all);

int csio_discover_targets(adap_handle_t hw,
			   char *discip,
			   int dport,
			   int vlan,
			   char *hostip);

int csio_del_target(adap_handle_t hw,
		    char *targname,
		    char *targip,
		    int targport);

int csio_login_to_target(adap_handle_t hw,
			 char *adapname,
			 char *targname,
			 char *targip,
			 int targport,
			 char *hostip,
			 char *initname,
			 char *initalias,
			 int vlan,
			 int persistent);

int csio_logout_from_target(adap_handle_t hw, 
			    uint32_t sess_hdl);

#endif//__CSIO_ISCSI_H__
