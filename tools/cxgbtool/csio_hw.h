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
 *    csio_hw.h
 *
 * Abstract:
 *
 *    csio_hw.h -  contains the common Chelsio hardware handlers' definitions
 *		   & headers.
 *
 * Environment:
 *
 *    User mode
 *
 * Revision History:
 *
 *	Gokul TV - 04-May-10 -	Creation
 *
 *****************************************************************************/

#ifndef __CSIO_HW_H__
#define __CSIO_HW_H__

#include <csio_defs.h>
#include <csio_stor_ioctl.h>
#include <csio_t4_ioctl.h> /* Common header across user/kernel. */

#ifdef __cplusplus
extern "C" {
#endif


#define MAC_f1	"%02x-%02x-%02x-%02x-%02x-%02x"
#define MAC_f2	"%02x:%02x:%02x:%02x:%02x:%02x"

#define MAC_F1	"%02X-%02X-%02X-%02X-%02X-%02X"
#define MAC_F2	"%02X:%02X:%02X:%02X:%02X:%02X"

#define CSIO_DCBX_MAX_PRIORITIES 	7

#define EXPAND_MAC(mac)		mac[0], mac[1], mac[2], mac[3],	\
				mac[4], mac[5]

typedef int (*os_fw_download_fn)(adap_handle_t,
					char *); /* fw file name. */
typedef int (*os_fw_cfg_download_fn)(adap_handle_t,
					char *); /* fw config file name. */
typedef int (*os_t4_reg_dump_fn)(adap_handle_t,
					char *); /* T4 reg name. */
typedef int (*os_print_host_trace_buf_fn)(adap_handle_t);
typedef void (*os_find_adapters_fn)(int);
/*typedef int (*os_probe_adapter_fn)(adap_handle_t);*/

typedef struct _csio_oshw_ops {

	os_find_adapters_fn		os_find_adapters;
	/*os_probe_adapter_fn		os_probe_adapter;*/
	os_fw_download_fn		os_fw_download;
	os_fw_cfg_download_fn		os_fw_cfg_download;
	os_t4_reg_dump_fn		os_t4_reg_dump;
	os_print_host_trace_buf_fn	os_print_host_trace_buf;

}csio_oshw_ops_t;

typedef void
(*tpla_print_function)(uint8_t *buffer, uint32_t index);

static void
inline csio_print_version(version_t *ver_no)
{
	printf("%02d.%02d.%04d.%04d\n", ver_no->major_no,
			ver_no->minor_no, ver_no->build, ver_no->revision);
}

#define PRINT_VERSION(_x)	\
do {				\
	printf(#_x "	= ");	\
	csio_print_version(_x);	\
}while(0);


#define  csio_init_header(__h, __c, __m, __l, __d)			\
			csio_oss_init_header((__h), (__c), (__m), (__l), (__d))

#if 0
static void
inline csio_init_header(os_agnostic_hdr_t *header, uint32_t command,
			char magic[8], size_t os_agnostic_buffer_len)
{

	header->command = command;
	header->immediate_len = (uint32_t)(os_agnostic_buffer_len -
						sizeof(os_agnostic_hdr_t));

	memcpy(header->magic, magic, 8);

	return;
}
#endif

/*
 * Globals variables of Chelsio Storport miniport driver.
 *
 */

#ifdef CHSTORUTIL_INCLUDE_HW_INITIALIZATIONS

	csio_oshw_ops_t oshw_ops	= {0};

#else

	extern csio_oshw_ops_t oshw_ops;

#endif /* (CHSTORUTIL_INCLUDE_HW_INITIALIZATIONS) */


/* Functions declarations. */

int
csio_do_reset(adap_handle_t hw, uint32_t opcode);

int
csio_print_card_info(uint8_t adapter_no);

int
csio_print_port_stats(uint8_t adapter_no, uint8_t port_no);

int
csio_probe_adapter(adap_handle_t hw);

int
csio_print_hw_info(adap_handle_t hw);

int
csio_print_hw_stats(adap_handle_t hw);

int
csio_print_scsi_q(adap_handle_t hw);

int
csio_print_sge_q(adap_handle_t hw);

int
csio_print_scsi_stats(adap_handle_t hw);

int
csio_flash_fw(adap_handle_t hw, char *fw_file_str);

int
csio_flash_fw_cfg(adap_handle_t hw, char *fw_file_str);

int
csio_read_reg(adap_handle_t hw, uint32_t reg_addr, uint32_t *reg_val);

int
csio_print_reg_val(adap_handle_t hw, uint32_t reg_addr);

int
csio_write_reg(adap_handle_t hw, uint32_t reg_addr, uint32_t reg_val);

static uint32_t inline
csio_read_reg32(adap_handle_t hw, uint32_t reg_addr)
{
	uint32_t val = (uint32_t)0;

	(void)csio_read_reg(hw, reg_addr, &val);

	return val;
}

static void inline
csio_write_reg32(adap_handle_t hw, uint32_t reg_addr, uint32_t reg_val)
{
	(void)csio_write_reg(hw, reg_addr, reg_val);
	return ;
}

/* debug functions */

int
csio_print_mbox(adap_handle_t hw, int mailbox_no);

int
csio_print_cim_q_cfg(adap_handle_t hw);

int
csio_print_cim_la(adap_handle_t hw);

int
csio_print_cim_pif_la(adap_handle_t hw);

int
csio_print_cim_ma_la(adap_handle_t hw);

int
csio_print_mps_tcam(adap_handle_t hw);

int
csio_print_tp_la(adap_handle_t hw);

int
csio_print_ulprx_la(adap_handle_t hw);

int
csio_print_cim_ibq(adap_handle_t hw, int ibq_no);

int
csio_print_cim_obq(adap_handle_t hw, int obq_no);

int
csio_print_cpl_stats(adap_handle_t hw);

int
csio_print_ddp_stats(adap_handle_t hw);

int
csio_print_tp_err_stats(adap_handle_t hw);

int
csio_print_tp_tcp_stats(adap_handle_t hw);

int
csio_print_pm_stats(adap_handle_t hw);

int
csio_print_lb_stats(adap_handle_t hw);

int
csio_print_host_trace_buffer(adap_handle_t hw);

int
csio_print_t4_reg_dump(adap_handle_t hw, char *reg);

void
csio_print_meminfo(adap_handle_t hw);

int
csio_copy_hw_mem_to_file(adap_handle_t hw, int mem_type,
		file_handle_t file, int file_size, int display_progress);

int
csio_print_fw_logs(adap_handle_t hw);

int
csio_print_sge_cntx(adap_handle_t hw, uint32_t cntx_type, uint32_t cntx_id);

int
csio_print_all_dcbx_info(adap_handle_t hw);

int
csio_get_hw_info(adap_handle_t hw, csio_hw_info_t *hw_info);

int
csio_print_drv_params(adap_handle_t hw);

int
csio_print_cim_params(adap_handle_t hw);

#ifdef __cplusplus
}
#endif

#endif /* __CSIO_HW_H__ */
