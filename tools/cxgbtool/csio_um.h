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
 *    csio_um.h
 *
 * Abstract:
 *
 *    csio_um.h -  contains the definition for csio core transition and umlib
 *
 * Environment:
 *
 *    Unified Manager
 *
 * Revision History:
 *
 *    Anish Bhatt - 16-February-14 -  Creation
 *
 *****************************************************************************/

#ifndef __CSIO_UMLIB_H__
#define __CSIO_UMLIB_H__

#ifdef __cplusplus
extern "C" {
#endif
int um_foiscsi_do_discovery(int hw, struct foiscsi_login_info *um_disc);
int csio_get_hw_info(adap_handle_t hw, csio_hw_info_t *hw_info);
int um_foiscsi_get_count(adap_handle_t, struct foiscsi_count *);
int um_foiscsi_manage_instance(adap_handle_t, struct foiscsi_instance *);
int um_foiscsi_manage_session(int hw, int op,
       char *auth_method, char *policy, void *sess_buf);
int32_t um_csio_foiscsi_iface_do_op(adap_handle_t hw,
       struct csio_foiscsi_iface_ioctl *um_ioc,
       struct csio_foiscsi_ifconf_ioctl *um_req);
int32_t um_csio_foiscsi_ifconf_do_op(adap_handle_t hw,
       int32_t op, struct csio_foiscsi_ifconf_ioctl *um_req);
#ifdef __cplusplus
}
#endif

#endif/*__CSIO_UMLIB_H__*/
