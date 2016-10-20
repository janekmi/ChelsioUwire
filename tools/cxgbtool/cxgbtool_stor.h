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
 *    cxgbtool_stor.h
 *
 * Abstract:
 *
 *    cxgbtool_stor.h -  contains all the required headers & definitions of
 *			   Chelsio Unified Storage Utility
 *
 * Environment:
 *
 *    User mode
 *
 * Revision History:
 *
 *
 *****************************************************************************/

#ifndef __CXGBTOOL_STOR_H__
#define __CXGBTOOL_STOR_H__

#include <csio_services.h>
#ifdef __CSIO_FOISCSI_ENABLED__
#include <csio_foiscsi.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern int run_stor(int, char **);
extern void cmdline_parser_print_help(void);
int  is_csiostor(const char *);

/*int csio_os_probe_adapter(adap_handle_t);*/
int csio_os_fw_download(adap_handle_t, char *);
int csio_os_fw_cfg_download(adap_handle_t, char *);
void csio_os_find_adapters(int quiet);
int csio_os_t4_reg_dump(adap_handle_t hw, char *reg);
int csio_os_print_host_trace_buf(adap_handle_t hw);
int csio_dump_regs_t4(int argc, char *argv[],
		                int start_arg, const uint32_t *regs);

#ifdef __CSIO_FOISCSI_ENABLED__
void csio_os_net_cfg(void *ctxt);
void csio_os_del_netcfg(int port, int idx);
void csio_os_show_netcfg(int port, int all);
void csio_os_show_inst(int);
int csio_os_read_ini(struct iscsi_initiator *ini);
int csio_os_edit_inst(char *, int, int, char *, char *, char *, char *, char *);
int csio_os_read_iscsi_param(struct foiscsi_login_info *linfo, int);
int csio_os_read_chap_param(struct foiscsi_instance *, int);
#endif

#ifdef __cplusplus
}
#endif

#endif /* __CXGBTOOL_STOR_H__ */
