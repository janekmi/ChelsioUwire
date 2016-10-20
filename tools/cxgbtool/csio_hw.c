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
 *    csio_hw.c
 *
 * Abstract:
 *
 *    csio_hw.c -  contains the common Chelsio hardware handlers. This file
 *		   shall be shared across OSes, with appropiate OS specific
 *		   services layer.
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

#define CHSTORUTIL_INCLUDE_HW_INITIALIZATIONS

#include <csio_defs.h>
#include <csio_hw.h>
#include <csio_t4.h>
#include <t4fw_interface.h>

enum csio_string_size_units {
	CSIO_STRING_UNITS_10,		/* use powers of 10^3 (standard SI) */
	CSIO_STRING_UNITS_2,		/* use binary powers of 2^10 */
};

static uint64_t
csio_do_div(uint64_t *number, uint32_t divisor)
{
	uint64_t remainder = *number % divisor;

	(*number) /= divisor;

	return remainder;
}/* csio_do_div */

/*
 * Define here although a service.
 */
static int
csio_string_get_size(uint64_t size, const enum csio_string_size_units units,
		char *buf, int len)
{
	const char *units_10[] = { "B", "kB", "MB", "GB", "TB", "PB",
				"EB", "ZB", "YB", NULL};
	const char *units_2[] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB",
				"EiB", "ZiB", "YiB", NULL };
	const char **units_str[2];// = {units_10, units_2};
	const unsigned int divisor[] = {1000, 1024};
	int i = 0, j = 0;
	uint64_t remainder = 0, sf_cap = 0;
	char tmp[8] = {0};

	tmp[0] = '\0';
	i = 0;

	units_str[CSIO_STRING_UNITS_10] = units_10;
	units_str[CSIO_STRING_UNITS_2] = units_2;

	if (size >= divisor[units])
	{
		while (size >= divisor[units] && units_str[units][i])
		{
			remainder = csio_do_div(&size, divisor[units]);
			i++;
		}

		sf_cap = size;

		for (j = 0; sf_cap*10 < 1000; j++)
		{
			sf_cap *= 10;
		}

		if (j)
		{
			remainder *= 1000;
			csio_do_div(&remainder, divisor[units]);

#if 0
			_snprintf_s(tmp, sizeof(tmp), sizeof(tmp), ".%03lld",
				(unsigned long long)remainder);
#endif
			csio_snprintf(tmp, sizeof(tmp), ".%03lld",
				(unsigned long long)remainder);
			tmp[j+1] = '\0';
		}
	}

#if 0
	_snprintf_s(buf, len, len, "%lld%s %s", (unsigned long long)size,
			tmp, units_str[units][i]);
#endif
	csio_snprintf(buf, len, "%lld%s %s", (unsigned long long)size,
			tmp, units_str[units][i]);

	return 0;
}

int
csio_probe_adapter(adap_handle_t adapter)
{
	void *probe_adapter = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(csio_adapter_info_t));
	int status = 0;
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_PROBE);

	probe_adapter = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (probe_adapter == NULL) {
		csio_printf("csio_os_probe_adapters: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(probe_adapter, cmd, CSIO_IOCTL_SIGNATURE, len,
			 CSIO_IOCD_RW);

	/* Issue the IOCTL. */
	status = issue_ioctl(adapter, probe_adapter, len);

	ioctl_buffer_free(probe_adapter);

	return status;

} /* csio_os_probe_adapters */

__csio_export int
csio_hw_get_dcbx_info(adap_handle_t hw,
		csio_dcbx_info_t *dcbx_info, uint8_t idx, int action)
{
	void *payload = NULL;
	void *buffer = NULL;
	csio_dcbx_info_t  *dcbx_info_request = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(csio_dcbx_info_t));
	int status = 0;
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_GET_DCBX_INFO);

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_hw_get_dcbx_info : "
				"Insufficient resources..!\n");
		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);

	/* Initialize the fcf_idx. */
	dcbx_info_request = get_payload(buffer);
	dcbx_info_request->portid = idx;
	dcbx_info_request->action = action;

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status == 0) {
		payload = get_payload(buffer);
		csio_memcpy(dcbx_info, payload, sizeof(csio_dcbx_info_t));
	}
	ioctl_buffer_free(buffer);
	return status;
}

int
csio_print_dcbx_info(adap_handle_t hw, uint8_t portid)
{
	int priorgroup;
	csio_dcbx_info_t dcbx_info = {0};
	int status = 0, act;
	char action[20];

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	for (act=FW_PORT_ACTION_DCB_READ_TRANS;
			act <= FW_PORT_ACTION_DCB_READ_DET;
			act++) {
		status = csio_hw_get_dcbx_info(hw, &dcbx_info, portid, act);
		if (status != 0)
			continue;

		switch(act) {
		case FW_PORT_ACTION_DCB_READ_TRANS:
			sprintf(action, "Desired");
			break;

		case FW_PORT_ACTION_DCB_READ_RECV:
			sprintf(action, "Peer");
			break;

		case FW_PORT_ACTION_DCB_READ_DET:
			sprintf(action, "Operational");
			break;
		}

		csio_printf("******************** %s DCBX Paramters[Port:%3u] *"
				"*******************\n", action, portid);
		for (priorgroup = 0; priorgroup <= CSIO_DCBX_MAX_PRIORITIES;
				priorgroup++) {
			csio_printf("Priority Group ID of Priority"
				       " %d\t\t: %d\n",	priorgroup, 
					(dcbx_info.pgid >> 
					 ((CSIO_DCBX_MAX_PRIORITIES - 
					   priorgroup) * 4)) & 0xf);
		}
		csio_printf("\nBandwidth Percentage :\n");
		csio_printf("----------------------\n");
		for (priorgroup = 0; priorgroup <= CSIO_DCBX_MAX_PRIORITIES;
				priorgroup++) {
			csio_printf("Bandwidth Percentage of Priority Group"
				       " %d: %d\n", priorgroup,
					dcbx_info.pgrate[priorgroup]);
		}
		csio_printf("\n\nNumber of Traffic Classes Supported\t: %d\n\n",
				dcbx_info.pg_num_tcs_supported);
		csio_printf("Strict Priorate :\n");
		csio_printf("-----------------\n");
		for (priorgroup = 0; priorgroup <= CSIO_DCBX_MAX_PRIORITIES;
				priorgroup++) {
			csio_printf("Strict Priorate for Priority %d\t\t: %d\n",
					priorgroup,
					dcbx_info.strict_priorate
					[CSIO_DCBX_MAX_PRIORITIES - 
					priorgroup]);
		}

		csio_printf("\nPFC Enabled/Disabled :\n");
		csio_printf("------------------------\n");
		csio_printf("\n\nNumber of Traffic Classes Supported\t: %d\n\n",
				dcbx_info.pfc_num_tcs_supported);
		for (priorgroup = 0; priorgroup <= CSIO_DCBX_MAX_PRIORITIES;
				priorgroup++) {
			csio_printf("PFC for Priotity %d\t\t\t: %s\n", 
					priorgroup,
					((dcbx_info.pfcen & 
					  (0x80 >> priorgroup)) ?
					 "Enabled" : "Disabled"));
		}
		csio_printf("\nUser priority map\t\t\t: 0x%x\n", 
				dcbx_info.prio);
		csio_printf("\nSelector field\t\t\t\t: %d\n", dcbx_info.sel);
		csio_printf("\nApplication Protocol ID\t\t\t: 0x%x\n\n\n",
				(dcbx_info.protocolid & 0xffff));
	}

	return 0;
}

int
csio_get_hw_info(adap_handle_t hw, csio_hw_info_t *hw_info)
{
	void *payload = NULL;
	void *buffer = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(csio_hw_info_t));
	int status = 0;
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_SHOW);

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_hw_show: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len,
			 CSIO_IOCD_READ);

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status == 0)	{
		payload = get_payload(buffer);
		csio_memcpy(hw_info, payload, sizeof(csio_hw_info_t));
	}

	ioctl_buffer_free(buffer);

	return status;
} /* csio_get_hw_info */

int
csio_print_all_dcbx_info(adap_handle_t hw)
{
	uint8_t port = 0;
	csio_hw_info_t hw_info;
	int status = 0;

	csio_memset(&hw_info, 0, sizeof(csio_hw_info_t));

	if (hw == (adap_handle_t)-1)
		return -1;

	status = csio_get_hw_info(hw, &hw_info);

	if (status != 0) {
		csio_printf("Unable to get the adapter information!\n");
		return status;
	}

	for (port = 0; port < hw_info.num_t4ports; port++)
		csio_print_dcbx_info(hw, port);

	return 0;
}/* csio_print_all_dcbx_info */


__csio_export int
csio_get_hw_cim_diag_info(adap_handle_t hw, csio_cim_diag_info_t *cim_info)
{
	void *payload = NULL;
	void *buffer = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(csio_cim_diag_info_t));
	int status = 0;
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_GET_CIM_DIAGS);

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_get_hw_cim_diag_info: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len,
			 CSIO_IOCD_READ);

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status == 0)	{
		payload = get_payload(buffer);
		csio_memcpy(cim_info, payload, sizeof(csio_cim_diag_info_t));
	}

	ioctl_buffer_free(buffer);

	return status;
} /* csio_get_hw_cim_diag_info */

int
csio_print_cim_params(adap_handle_t hw)
{
	csio_cim_diag_info_t cim_diag;
	int status = 0;

	csio_memset(&cim_diag, 0, sizeof(csio_cim_diag_info_t));

	if (hw == (adap_handle_t)-1)
		return -1;

	status = csio_get_hw_cim_diag_info(hw, &cim_diag);

	if (status != 0) {
		if(errno != EOPNOTSUPP) {
			csio_printf("Unable to get the CIM diags. information!\n");
			return status;
		} else {
			return 0;
		}
	}

	csio_printf("CIM/uP load\t: %d%%\n", cim_diag.cim_load);
	//csio_printf("CIM/uP temp.\t: %d\n", cim_diag.cim_tmp);

	return status;
} /* csio_print_cim_params */


__csio_export int
csio_hw_drv_params_info(adap_handle_t hw,
			csio_drv_params_t drv_params[MAX_DRV_PARAMS],
			uint8_t modify)
{
	void *payload = NULL;
	void *buffer = NULL;
	size_t buf_len = sizeof(csio_drv_params_t) * MAX_DRV_PARAMS;
	size_t len = os_agnostic_buffer_len(buf_len);
	int status = 0;
	uint32_t cmd = modify ?
			CSIO_OS_OPCODE(CSIO_OS_SET_DRV_PARAMS):
			CSIO_OS_OPCODE(CSIO_OS_GET_DRV_PARAMS);

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_hw_drv_params_info: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len,
			 CSIO_IOCD_RW);

	payload = get_payload(buffer);

	/* Copy the contents if required. */
	if (modify)
		csio_memcpy(payload, drv_params, buf_len);


	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status == 0)	{
		if (!modify)
			csio_memcpy(drv_params, payload, buf_len);
	}

	ioctl_buffer_free(buffer);

	return status;
} /* csio_hw_drv_params_info */

int
csio_print_drv_params(adap_handle_t hw)
{
	csio_drv_params_t drv_params[MAX_DRV_PARAMS];
	int status = 0, i = 0;
	csio_memset(&drv_params, 0, sizeof(csio_drv_params_t) * MAX_DRV_PARAMS);

	if (hw == (adap_handle_t)-1)
		return -1;

	status = csio_hw_drv_params_info(hw, drv_params, 0);

	if (status != 0) {
		if(errno != EOPNOTSUPP) {
			csio_printf("Unable to get the driver parameter information!\n");
			return status;
		} else {
			return 0;
		}
	}


	for (i = LUN_QUEUE_DEPTH; i < MAX_DRV_PARAMS; i++) {
		switch (i) {
			case LUN_QUEUE_DEPTH:
				if (drv_supported(LUN_QUEUE_DEPTH))
					csio_printf("LUN Queue depth\t\t: %"
						FS_S64"\n",
					drv_current_val(LUN_QUEUE_DEPTH));
				break;

			case MAX_TX_LENGTH:
				if (drv_supported(MAX_TX_LENGTH))
					csio_printf("Max Tx length\t\t: %"
						FS_S64"\n",
					drv_current_val(MAX_TX_LENGTH));
				break;

			case MAX_SGL_LENGTH:
				if (drv_supported(MAX_SGL_LENGTH))
					csio_printf("Max SG List length\t: %"
						FS_S64"\n",
					drv_current_val(MAX_SGL_LENGTH));
				break;

			case MAX_NPIV:
				if (drv_supported(MAX_NPIV))
					csio_printf("Max NPIVs\t: %"
						FS_S64"\n",
					drv_current_val(MAX_NPIV));
				break;

			case MAX_LNODES:
				if (drv_supported(MAX_LNODES))
					csio_printf("Max LNodes\t: %"
						FS_S64"\n",
					drv_current_val(MAX_LNODES));
				break;

			case MAX_RNODES:
				if (drv_supported(MAX_RNODES))
					csio_printf("Max targets\t: %"
						FS_S64"\n",
					drv_current_val(MAX_RNODES));
				break;

			case MAX_LUNS:
				if (drv_supported(MAX_LUNS))
					csio_printf("Max LUNs per target\t: %"
						FS_S64"\n",
					drv_current_val(MAX_LUNS));
				break;

			case TIME_SCSI_IO:
				if (drv_supported(TIME_SCSI_IO))
					csio_printf("Time SCSI IOs\t: %"
						FS_S64"\n",
					drv_current_val(TIME_SCSI_IO));
				break;

			case MAX_BOOT_INIT_DELAY:
				if (drv_supported(MAX_BOOT_INIT_DELAY))
					csio_printf("Max Boot init delay\t: %"
						FS_S64"\n",
					drv_current_val(MAX_BOOT_INIT_DELAY));
				break;

			case NODE_SYM_NAME:
				if (drv_supported(NODE_SYM_NAME))
					csio_printf("Node Symbolic name\t: %s\n",
					drv_val_str(NODE_SYM_NAME));
				break;

			default:
				CSIO_ASSERT(drv_supported(i) == FALSE);
				break;

		} /* switch (i) */
	} /* for (all params) */

	return 0;
} /* csio_print_drv_params */

int
csio_do_reset(adap_handle_t hw, uint32_t opcode)
{
	csio_hw_info_t hw_info;
	void *buffer = NULL;
	size_t len = os_agnostic_buffer_len(0); // no payload
	int status = 0;
	uint32_t cmd = CSIO_STOR_HW_OPCODE(opcode);

	csio_memset(&hw_info, 0, sizeof(csio_hw_info_t));

	if (hw == (adap_handle_t)-1) {
		return -1;
	}

	status = csio_get_hw_info(hw, &hw_info);

	if (status != 0) {
		csio_printf("Unable to get the adapter information!\n");
		return status;
	}

	/* Is it master function in this PCI card? */
	if (hw_info.master == 0 && opcode == CSIO_HW_CARD_RESET) {
		csio_printf("Only master function can reset the card!\n");
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (buffer == NULL) {
		csio_printf("csio_do_reset: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len,
			 CSIO_IOCD_NONE);

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	csio_printf("Reset %s %s!!\n",
			(opcode == CSIO_HW_CARD_RESET) ? "card" : "function",
			(status == 0) ? "successful" : "failed");

	ioctl_buffer_free(buffer);

	return status;
} /* csio_do_reset */

#if 0
__csio_export int
csio_do_card_reset(adap_handle_t hw)
{
	return csio_do_reset(hw, CSIO_HW_CARD_RESET);
} /* csio_do_card_reset */


__csio_export int
csio_do_function_reset(adap_handle_t hw)
{
	return csio_do_reset(hw, CSIO_HW_FUNCTION_RESET);
} /* csio_do_function_reset */
#endif

static void
csio_print_hw_cfg_file_info(csio_hw_info_t hw_info)
{
	char *cfg_store = NULL;

	if (!hw_info.master) {

		/*
		 * If the adapter is not master -
		 * do not worry about config file!
		 *
		 */

		return;
	}

	switch(hw_info.cfg_store) {
		case CFG_STORE_FLASH:
			cfg_store = "Flash";
			break;

		case CFG_STORE_EDC0:
			cfg_store = "EDC0";
			break;

		case CFG_STORE_EDC1:
			cfg_store = "EDC1";
			break;

		case CFG_STORE_EXTMEM:
			cfg_store = "Adapter's external memory";
			break;

		case CFG_STORE_FILESYSTEM:
			cfg_store = "File-system";
			break;

		default:
			cfg_store = "Unknown";
			break;
	} /* config file store */

	csio_printf("\nCONFIG File information:\n");
	csio_printf("\tVersion\t\t : %08X\n", hw_info.cfg_finiver);
	csio_printf("\tStore\t\t : %s\n", cfg_store);
	csio_printf("\tStatus\t\t : %s\n",
				(hw_info.cfg_csum_status) ?
				"Valid checksum":
				"Checksum mismatch / config file error!");
	csio_printf("\tComputed checksum: %08X\n", hw_info.cfg_cfcsum);

	if (!hw_info.cfg_csum_status) {
		csio_printf("\tEmbedded checksum: %08X\n",
						hw_info.cfg_finicsum);
	}

	return;
} /* csio_print_hw_cfg_file_info */

int
csio_print_hw_info(adap_handle_t hw)
{
	csio_hw_info_t hw_info;
	int status = 0, i = 0;

	csio_memset(&hw_info, 0, sizeof(csio_hw_info_t));

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	status = csio_get_hw_info(hw, &hw_info);

	if (status != 0) {
		return status;
	}

	/* print the hw info */

	csio_printf("Name\t\t: %s\n", hw_info.name);
	if (!hw_info.partial_offload) {
		csio_printf("Model\t\t: %s\n", hw_info.model);
		csio_printf("Serial No.\t: %s\n", hw_info.sl_no);
		csio_printf("HW Version\t: %s\n", hw_info.hw_version);
	}
	else
		csio_printf("pci device\t: %s\n", hw_info.pci_name);

	csio_printf("Driver Version\t: %s\n", hw_info.drv_version);
	if (hw_info.optrom_ver != 0 &&
		hw_info.optrom_ver != (uint32_t)-1) {
		csio_printf("OptionROM Version\t: "
			"%d.%02d.%02d.%02d\n",
			G_FW_HDR_FW_VER_MAJOR(hw_info.optrom_ver),
			G_FW_HDR_FW_VER_MINOR(hw_info.optrom_ver),
			G_FW_HDR_FW_VER_MICRO(hw_info.optrom_ver),
			G_FW_HDR_FW_VER_BUILD(hw_info.optrom_ver));
	}
	csio_printf("Vendor-Id\t: %X\n", hw_info.pci_id.s.vendor_id);
	csio_printf("Device-Id\t: %X\n", hw_info.pci_id.s.device_id);
	csio_printf("Device Instance\t: %d\n", hw_info.dev_num);
	csio_printf("ASIC Revision\t: %d\n", hw_info.chip_rev);
	csio_printf("Firmware rev\t: %d.%02d.%02d.%02d\n",
			G_FW_HDR_FW_VER_MAJOR(hw_info.fwrev),
			G_FW_HDR_FW_VER_MINOR(hw_info.fwrev),
			G_FW_HDR_FW_VER_MICRO(hw_info.fwrev),
			G_FW_HDR_FW_VER_BUILD(hw_info.fwrev));
	if (!hw_info.partial_offload) {
		csio_printf("PF number\t: %d\n", hw_info.pfn);
		csio_printf("Master function\t: %s\n",
				(hw_info.master) ? "TRUE" : "FALSE");
	}
	csio_printf("Initiator Mode\t: %s\nTarget Mode\t: %s\n",
		(hw_info.initiator) ? "TRUE" : "FALSE", (hw_info.target) ? "TRUE" : "FALSE");
	csio_printf("No.of ports\t: %d\n\n", hw_info.num_t4ports);

	if (hw_info.partial_offload)
		return status;
		
	CSIO_ASSERT(hw_info.num_t4ports <= CSIO_MAX_T4PORTS);

	for (i = 0; i < hw_info.num_t4ports; i++) {
		csio_printf("\nPort-%d Status\t:%s\n", i,
			hw_info.t4port[i].link_status ?
			" LINK UP": " LINK DOWN");
		csio_printf("ENode MAC\t: "MAC_F1"\n",
			EXPAND_MAC(hw_info.t4port[i].enode_mac));

		if (!(hw_info.t4port[i].link_status))
			continue;

		switch (hw_info.t4port[i].link_speed) {
			case FW_PORT_CAP_SPEED_100M:
				csio_printf("Speed\t\t: 100M\n");
				break;
			case FW_PORT_CAP_SPEED_1G:
				csio_printf("Speed\t\t: 1G\n");
				break;
			case FW_PORT_CAP_SPEED_2_5G:
				csio_printf("Speed\t\t: 2.5G\n");
				break;
			case FW_PORT_CAP_SPEED_10G:
				csio_printf("Speed\t\t: 10G\n");
				break;
			case FW_PORT_CAP_SPEED_40G:
				csio_printf("Speed\t\t: 40G\n");
				break;
			case FW_PORT_CAP_SPEED_100G:
				csio_printf("Speed\t\t: 100G\n");
				break;
			default:
				csio_printf("Speed\t\t: Unknown\n");
				break;
		}
	}

	csio_printf("\nInterrupt Mode\t: %s\n", hw_info.intr_mode_str);
	csio_printf("\nFirmware Event Queue:\n\tIQ-Idx\t: %d\n\tMSIX\t: %d\n", 
			hw_info.fwevt_iq_idx, hw_info.fwevt_iq_msix);
	csio_printf("\nNo.of SGE Queues: %d\n", hw_info.wrm_num_sge_q);
	csio_print_hw_cfg_file_info(hw_info);
	return status;
} /* csio_print_hw_info */

int
csio_print_hw_stats(adap_handle_t hw)
{
	csio_hw_info_t hw_info;
	csio_hw_stats_t *hw_stats = NULL;

	int status = 0, i = 0;

	csio_memset(&hw_info, 0, sizeof(csio_hw_info_t));

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	status = csio_get_hw_info(hw, &hw_info);

	if (hw_info.partial_offload) {
		errno = EOPNOTSUPP;
		return 0;
	}

	if (status != 0) {
		return status;
	}

	hw_stats = &hw_info.stats;

	/* print the hw stats */

	csio_printf("State\t: %s\n\n", hw_info.state);

	csio_printf("Active-Q events\t\t: %d\n", hw_stats->n_evt_activeq);
	csio_printf("Free-Q events\t\t: %d\n", hw_stats->n_evt_freeq);
	csio_printf("Dropped events\t\t: %d\n", hw_stats->n_evt_drop);
	csio_printf("Unexpected events\t: %d\n", hw_stats->n_evt_unexp);
	csio_printf("Unexpected CPL Message\t: %d\n", hw_stats->n_cpl_unexp);
	csio_printf("PCI-channel offline\t: %d\n", hw_stats->n_pcich_offline);
	csio_printf("Link-UP Miss\t\t: %d\n", hw_stats->n_lnlkup_miss);
	csio_printf("CPL FW6 Message\t\t: %d\n", hw_stats->n_cpl_fw6_msg);
	csio_printf("CPL FW6 payload\t\t: %d\n", hw_stats->n_cpl_fw6_pld);
	csio_printf("PL Unexpected Interrupt\t: %d\n",
						hw_stats->n_plint_unexp);
	csio_printf("PL Interrupt count\t: %d\n", hw_stats->n_plint_cnt);
	csio_printf("Stray Interrupts\t: %d\n", hw_stats->n_int_stray);
	csio_printf("Total Errors\t\t: %d\n", hw_stats->n_err);
	csio_printf("Fatal Errors\t\t: %d\n", hw_stats->n_err_fatal);
	csio_printf("NoMEM Errors\t\t: %d\n", hw_stats->n_err_nomem);
	csio_printf("IO Errors\t\t: %d\n", hw_stats->n_err_io);

	csio_printf("\nCurrent Event\t\t:%s\n",
				hw_info.evt_name[hw_info.cur_evt]);
	csio_printf("Previous Event\t\t:%s\n",
				hw_info.evt_name[hw_info.prev_evt]);

	csio_printf("\nHW State-Machine Events statistics\n");

	for (i = 1; i < hw_info.max_events; i++) {
		csio_printf("\t%-28s: %d\n", hw_info.evt_name[i],
						hw_stats->n_evt_sm[i]);
	}

	return status;
} /* csio_print_hw_stats */


/**
 * csio_get_scsi_q() - Gets the SCSI Queue-set information
 * @hw:	Adapter's handle
 * @buffer:
 * @buffer_len: Buffer length in bytes.
 *
 * If the routine finds the buffer is small in size, it returns -1
 * and also conveys the required buffer length size in @buffer_len.
 *
 * The calling function has to free the buffer. The calling function
 * can get the payload using get_payload() API.
 *
 */
__csio_export int
csio_get_scsi_q(adap_handle_t hw, void *buffer, size_t *buffer_len)
{
	scsi_q_t *scsi_q = NULL;
	int status = -1;
	uint32_t cmd = CSIO_OS_OPCODE(CSIO_OS_GET_SCSI_QUEUES);

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	if (buffer == NULL) {
		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, *buffer_len,
			 CSIO_IOCD_READ);

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, *buffer_len);

	if (status == 0) {
		scsi_q = get_payload(buffer);

		if (scsi_q->num_scsi_qsets == 0) {
			*buffer_len = 0;
			return -1;
		}

		if (scsi_q->num_scsi_qsets != 0 && scsi_q->done) {
			return 0;
		}

		if (scsi_q->num_scsi_qsets != 0 && !scsi_q->done) {
			size_t payload_len =
					(sizeof(scsi_q_t)
					+ ((scsi_q->num_scsi_qsets + 1)
					* sizeof(scsi_q_set_t)));

			*buffer_len = payload_len;

			return -1;
		}
	} else {
		*buffer_len = 0;
		return -1;
	}

	return 0;
} /* csio_get_scsi_q */


int
csio_print_scsi_q(adap_handle_t hw)
{
	void *buffer = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(scsi_q_t));
	int status = -1;
	int retry_count = 0;
	scsi_q_t *scsi_q = NULL;
	scsi_q_set_t *sqset = NULL;
	uint16_t i = 0;

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	while (retry_count++ <= 3) {

		buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

		if (buffer == NULL) {
			csio_printf("csio_print_scsi_q: "
				"Insufficient resources..!\n");
			return -1;
		}

		status = csio_get_scsi_q(hw, buffer, &len);
		scsi_q = get_payload(buffer);

		if (status == -1) {

			if (scsi_q->num_scsi_qsets != 0) {
				ioctl_buffer_free(buffer);

				/* The len should have the required buffer
				 * length. Use that and allocate a new buffer.
				 */
				len = os_agnostic_buffer_len(len);
				continue;
			} /* if (insufficient buffer)*/

			if (scsi_q->num_scsi_qsets == 0 && len == 0) {
				/* No SCSI Qs available! */
				if(errno != EOPNOTSUPP) {
					csio_printf("Total scsi qsets: 0\n");
				}

				ioctl_buffer_free(buffer);

				return 0;
			} /* if (no scsi-q available)*/

		} else { /* if (status) */

			if (scsi_q->num_scsi_qsets != 0 && scsi_q->done) {
				/* Success! */
				break;
			}
		} /* if (status) */
	} /* while */

	if (status == 0 && scsi_q->num_scsi_qsets != 0) {
		/* print SCSI qsets */
		csio_printf("Total scsi qsets: %d\n", scsi_q->num_scsi_qsets);

		for (i = 0; i < scsi_q->num_scsi_qsets; i++) {
			sqset = &scsi_q->q_sets[i];

			csio_printf("scsi qset(%2d): iqidx:%2d eqidx:%2d"
				   " msix:%2d\n", i, sqset->iq_idx,
				   sqset->eq_idx, sqset->intr_idx);
		}

	}

	ioctl_buffer_free(buffer);

	return status;

} /* csio_print_scsi_q */

int
csio_get_scsi_stats(adap_handle_t hw, csio_scsi_stats_t *scsi_stats)
{
	void *payload = NULL;
	void *buffer = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(csio_scsi_stats_t));
	int status = 0;
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_GET_SCSI_STATS);

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_get_scsi_stats: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len,
			 CSIO_IOCD_READ);

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status == 0)	{
		payload = get_payload(buffer);
		csio_memcpy(scsi_stats, payload, sizeof(csio_scsi_stats_t));
	}

	ioctl_buffer_free(buffer);

	return status;

} /* csio_get_scsi_stats */

int
csio_print_scsi_stats(adap_handle_t hw)
{
	csio_scsi_stats_t scsi_stats;
	int status = 0;

	csio_memset(&scsi_stats, 0, sizeof(csio_scsi_stats_t));

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	status = csio_get_scsi_stats(hw, &scsi_stats);

	if (status == 0) {
		/* Print SCSI stats information. */
		csio_printf("SCSI STATISTICS:\n");
		csio_printf("\tGood I/Os\t\t\t:%"FS_U64"\n", scsi_stats.n_tot_success);
		csio_printf("\tRemote-node-not-ready Errors\t:%d\n",  scsi_stats.n_rn_nr_error);
		csio_printf("\tHW-module-not-ready Errors\t:%d\n",  scsi_stats.n_hw_nr_error);
		csio_printf("\tDMA map Erros\t\t\t:%d\n", scsi_stats.n_dmamap_error);
		csio_printf("\tToo-many-SGEs Errors\t\t:%d\n",  scsi_stats.n_unsupp_sge_error);
		csio_printf("\tOut-of-IOReqs Errors\t\t:%d\n",  scsi_stats.n_no_req_error);
		csio_printf("\tCSIO_BUSY Errors\t\t:%d\n", scsi_stats.n_busy_error);
		csio_printf("\tFW_HOSTERROR I/O\t\t:%d\n", scsi_stats.n_hosterror);
		csio_printf("\tResponse Errors\t\t\t:%d\n", scsi_stats.n_rsperror);
		csio_printf("\tAuto-sense Replies\t\t:%d\n", scsi_stats.n_autosense);
		csio_printf("\tOverflow Errors\t\t\t:%d\n", scsi_stats.n_ovflerror);
		csio_printf("\tUnderflow Errors\t\t:%d\n", scsi_stats.n_unflerror);
		csio_printf("\tRemote-Device-Not-Ready Errors\t:%d\n",
						scsi_stats.n_rdev_nr_error);
		csio_printf("\tRemote-Device-Lost Errors\t:%d\n",
						scsi_stats.n_rdev_lost_error);
		csio_printf("\tRemote-Device-Logged-Out Errors\t:%d\n",
						scsi_stats.n_rdev_logo_error);
		csio_printf("\tLink-Down Errors\t\t:%d\n",
						scsi_stats.n_link_down_error);
		csio_printf("\tUnknown SCSI Errors\t\t:%d\n",
						scsi_stats.n_unknown_error);
		csio_printf("\tAborted I/Os\t\t\t:%d\n",  scsi_stats.n_aborted);
		csio_printf("\tAbort Timed-outs\t\t:%d\n",  scsi_stats.n_abrt_timedout);
		csio_printf("\tAbort Failures\t\t\t:%d\n",  scsi_stats.n_abrt_fail);
		csio_printf("\tAbort Race-Completions\t\t:%d\n",  scsi_stats.n_abrt_race_comp);
		csio_printf("\tAbort CSIO_BUSY Errors\t\t:%d\n", scsi_stats.n_abrt_busy_error);
		csio_printf("\tClosed IOs\t\t\t:%d\n",  scsi_stats.n_closed);
		csio_printf("\tClose CSIO_BUSY Errors\t\t:%d\n",  scsi_stats.n_cls_busy_error);
		csio_printf("\tIOs in Res_wait_q\t\t:%d\n",  scsi_stats.n_res_wait);
		csio_printf("\tIOs in Active_q\t\t\t:%d\n",  scsi_stats.n_active);
		csio_printf("\tTMs in Active_q\t\t\t:%d\n",  scsi_stats.n_tm_active);
		csio_printf("\tI/Os in Worker cbfn_q\t\t:%d\n", scsi_stats.n_wcbfn);
		csio_printf("\tIOReq Freelist Entries\t\t:%d\n",  scsi_stats.n_free_ioreq);
		csio_printf("\tDDP Misses\t\t\t:%d\n",  scsi_stats.n_ddp_miss);
		csio_printf("\tInvalid CPL Opcodes\t\t:%d\n",  scsi_stats.n_inval_cplop);
		csio_printf("\tInvalid SCSI Opcodes\t\t:%d\n",  scsi_stats.n_inval_scsiop);
	}

	return status;
}

__csio_export int
csio_get_sge_q_info(adap_handle_t hw, csio_q_info_t *q_info, int q_idx)
{
	void *payload = NULL;
	void *buffer = NULL;
	csio_q_info_t *q_info_request = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(csio_q_info_t));
	int status = 0;
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_GET_SGE_Q_INFO);


	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}
	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_get_sge_q_info: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);

	/* Initialize the q_idx. */
	q_info_request = get_payload(buffer);
	q_info_request->q_idx = q_idx;

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status == 0)	{
		payload = get_payload(buffer);
		csio_memcpy(q_info, payload, sizeof(csio_q_info_t));
	}

	ioctl_buffer_free(buffer);

	return status;
} /* csio_get_sge_q_info */

__csio_export int
csio_get_sge_flq_buf_info(adap_handle_t hw, csio_fl_dma_info_t *flq_info,
			int q_idx, int fl_entry)
{
	void *payload = NULL;
	void *buffer = NULL;
	csio_fl_dma_info_t *flq_info_request = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(csio_fl_dma_info_t));
	int status = 0;
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_GET_SGE_FLQ_BUF_INFO);

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_get_sge_flq_buf_info: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);

	/* Initialize the q_idx. */
	flq_info_request = get_payload(buffer);
	flq_info_request->q_idx = q_idx;
	flq_info_request->fl_entry = fl_entry;

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status == 0)	{
		payload = get_payload(buffer);
		csio_memcpy(flq_info, payload, sizeof(csio_fl_dma_info_t));
	}

	ioctl_buffer_free(buffer);

	return status;
} /* csio_get_sge_flq_buf_info */


int
csio_print_sge_q(adap_handle_t hw)
{
	csio_hw_info_t hw_info;
	csio_q_info_t q_info = {0};
	csio_fl_dma_info_t fl_dma = {0};

	csio_iq_t *iq = NULL;
	csio_eq_t *eq = NULL;
	csio_fl_t *flq = NULL;

	int status = 0, fl_status = 0;
	int i = 0, j = 0;

	csio_memset(&hw_info, 0, sizeof(csio_hw_info_t));

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	status = csio_get_hw_info(hw, &hw_info);

	if (status != 0) {
		return status;
	}

	csio_printf("Num sge queues: %d\n\n", hw_info.wrm_num_sge_q);

	for (i = 0; i < hw_info.wrm_num_sge_q; i++) {

		status = csio_get_sge_q_info(hw, &q_info, i);

		if (status == 0) {
			/* Print the SGE Queue info. */
			csio_printf("==================================\n\n");
			csio_printf("qidx\t\t: **%2d**\n\n", i);
			csio_printf("pidx\t\t: %d\n", q_info.pidx);
			csio_printf("cidx\t\t: %d\n", q_info.cidx);
			csio_printf("base addr\t: 0x%08"FS_U64x"\n",
				    (uint64_t)q_info.vstart);
			csio_printf("qsize\t\t: %d\n", q_info.size);
			csio_printf("inc idx\t\t: %d\n", q_info.inc_idx);
			csio_printf("wr size\t\t: %d\n", q_info.wr_sz);
			csio_printf("credits\t\t: %d\n", q_info.credits);

			switch (q_info.type) {

				case CHSTOR_INGRESS:

					iq = &q_info.un.iq_info;

					csio_printf("qtype\t\t: INGRESS\n");
					csio_printf("iqid\t\t: %d\n", iq->iqid);
					csio_printf("phy iqid\t: %d\n", iq->physiqid);
					csio_printf("genbit\t\t: %d\n", iq->genbit);
					csio_printf("flq idx\t\t: %d\n\n", iq->flq_idx);

					break;

				case CHSTOR_EGRESS:

					eq = &q_info.un.eq_info;

					csio_printf("qtype\t\t: EGRESS\n");
					csio_printf("eqid\t\t: %d\n", eq->eqid);
					csio_printf("phy eqid\t: %d\n", eq->physeqid);
					csio_printf("aqid\t\t: %d\n\n", eq->aqid);

					break;

				case CHSTOR_FREELIST:

					flq = &q_info.un.fl_info;

					csio_printf("qtype\t\t: FREELIST\n");
					csio_printf("flqid\t\t: %d\n", flq->flid);
					csio_printf("packen\t\t: %d\n", flq->packen);
					csio_printf("offset\t\t: %d\n", flq->offset);
					csio_printf("sreg\t\t: %d\n\n", flq->sreg);

					for (j = 0; j < q_info.credits; j++) {
						fl_status =
						csio_get_sge_flq_buf_info(hw,
							&fl_dma, i, j);

						if (fl_status != 0)
							continue;

						csio_printf(
							"flbuf[%2d]:%"FS_U64x" PhysAddr"
							":%016"FS_U64x" len:%d"
							"\n", j,
							(uint64_t)fl_dma.vaddr,
							fl_dma.paddr,
							fl_dma.len);
					}

					break;

				default:
					csio_printf("qtype\t\t: **UNKNOWN**\n");
					break;

			} /* switch (q_info.type) */

			csio_printf("\nStatistics: \n\n");
			csio_printf("qentries\t: %d\n", q_info.stats.n_qentry);
			csio_printf("qempty\t\t: %d\n", q_info.stats.n_qempty);
			csio_printf("qfull\t\t: %d\n", q_info.stats.n_qfull);
			csio_printf("qwrap\t\t: %d\n", q_info.stats.n_qwrap);
			csio_printf("n_tot_reqs\t: %d\n", q_info.stats.n_qwrap);
			csio_printf("eq_wr_split\t: %d\n", q_info.stats.n_eq_wr_split);
			csio_printf("n_tot_rsps\t: %d\n", q_info.stats.n_tot_rsps);
			csio_printf("rsp_unknown\t: %d\n", q_info.stats.n_rsp_unknown);
			csio_printf("stray_comp\t: %d\n", q_info.stats.n_stray_comp);
			csio_printf("flq_refill\t: %d\n", q_info.stats.n_flq_refill);

			csio_printf("\n\n");
		} else { /* if (status == 0) */
			csio_printf("Invalid SGE Queue index:(%d).\n", i);
		} /* if (status == 0) */

	} /* for (all SGE Queues) */

	return 0;

} /* csio_print_sge_q */

int
csio_flash_fw(adap_handle_t hw, char *fw_file_str)
{
	int status = 0;

	if (hw == (adap_handle_t)-1) {
		csio_printf("'--fw-flash' option depends on "
				"option 'adapter'\n");
		return -1;
	}

	if (!oshw_ops.os_fw_download) {
		csio_printf("os_fw_download - not implemented!\n");
		return -1;
	}

	/* Call OS specifc FW flash handler. */
	status = oshw_ops.os_fw_download(hw, fw_file_str);

	return status;

} /* csio_flash_fw */

int
csio_flash_fw_cfg(adap_handle_t hw, char *fw_file_str)
{
	int status = 0;

	if (hw == (adap_handle_t)-1) {
		csio_printf("'--fw-cfg-flash' option depends on "
				"option 'adapter'\n");
		return -1;
	}

	if (!oshw_ops.os_fw_cfg_download) {
		csio_printf("os_fw_cfg_download - not implemented!\n");
		return -1;
	}

	/* Call OS specifc FW config file flash handler. */
	status = oshw_ops.os_fw_cfg_download(hw, fw_file_str);

	return status;

} /* csio_flash_fw_cfg */

int
csio_read_reg(adap_handle_t hw, uint32_t reg_addr, uint32_t *reg_val)
{
	int status = 0;
	size_t len = os_agnostic_buffer_len(sizeof(csio_reg_t));
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_READ_REGISTER);

	void *buffer = NULL;
	csio_reg_t *reg = NULL;

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_read_reg: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);

	/* Set the register address */
	reg = get_payload(buffer);
	reg->addr = reg_addr;

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	/* On success, return the register value. */
	*reg_val = (status == 0) ? reg->val : *reg_val;

	ioctl_buffer_free(buffer);

	return status;

}/* csio_read_reg */

int
csio_print_reg_val(adap_handle_t hw, uint32_t reg_addr)
{
	uint32_t val = 0;
	int status = 0;

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	status = csio_read_reg(hw, reg_addr, &val);

	if (status ==0)
		csio_printf("0x%08x [%d]\n", val, val);
	else
		csio_printf("Read register(0x%08x) failed!\n", reg_addr);

	return status;

} /* csio_print_reg_val */


int
csio_write_reg(adap_handle_t hw, uint32_t reg_addr, uint32_t reg_val)
{
	int status = 0;
	size_t len = os_agnostic_buffer_len(sizeof(csio_reg_t));
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_WRITE_REGISTER);

	void *buffer = NULL;
	csio_reg_t *reg = NULL;

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_write_reg: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len,
			 CSIO_IOCD_WRITE);

	/* Set the register address & value. */
	reg = get_payload(buffer);
	reg->addr = reg_addr;
	reg->val = reg_val;

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	ioctl_buffer_free(buffer);

	return status;
}/* csio_write_reg */

int
csio_get_port_stats(uint8_t adapter_no,
		uint8_t port_no, t4_port_stats_t *port_stats)
{

	adap_handle_t hw;
	void *buffer = NULL;
	t4_port_stats_t *payload = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(t4_port_stats_t));
	int status = 0;
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_GET_PORT_STATS);

	hw = open_adapter(adapter_no);

	if (hw == (adap_handle_t)-1) {
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_get_port_stats: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);

	/* Set the port-no. */
	payload = (t4_port_stats_t *)get_payload(buffer);
	payload->port_no = port_no;

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status == 0) {
		csio_memcpy(port_stats, payload, sizeof(t4_port_stats_t));
	} else {
		csio_memset(port_stats, 0, sizeof(t4_port_stats_t));
	}
	ioctl_buffer_free(buffer);
	close_adapter(hw);

	return status;

} /* csio_get_port_stats */

int
csio_print_port_stats(uint8_t adapter_no, uint8_t port_no)
{
	t4_port_stats_t	port_stats = {0};

	if (!(csio_get_port_stats(adapter_no, port_no, &port_stats))) {
		csio_printf("adapter_no	= %d\n", adapter_no);
		csio_printf("port_no		= %d\n", port_stats.port_no);
		csio_printf("tx_frames	= %"FS_U64x"\n", port_stats.tx_frames);
		csio_printf("rx_frames	= %"FS_U64x"\n", port_stats.rx_frames);
	} else {
		csio_printf("Invalid port(%d) or adapter number(%d)\n.",
						adapter_no, port_no);
		return -1;
	}

	return 0;

} /* csio_print_port_stats */


/* Debug functions. */

__csio_export int
csio_get_mbox(adap_handle_t hw, int mailbox_no, csio_mailbox_data_t* mbox)
{
	csio_mailbox_data_t *mbox_info = NULL;
	void *buffer = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(csio_mailbox_data_t));
	int status = 0;
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_GET_MBOX);

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_get_mbox: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);

	/* Init mbox no. */
	mbox_info = get_payload(buffer);
	mbox_info->number = (uint32_t)mailbox_no;

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status == 0)	{
		csio_memcpy(mbox, mbox_info, sizeof(csio_mailbox_data_t));
	}

	ioctl_buffer_free(buffer);

	return status;
} /* csio_get_mbox */

int
csio_print_mbox(adap_handle_t hw, int mailbox_no)
{
	csio_mailbox_data_t mbox = {0};
	static const char *owner[] = { "none", "FW", "driver", "unknown" };
	int status = 0, i = 0, j = 0;
	uint64_t *data_dump = NULL;

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	status = csio_get_mbox(hw, mailbox_no, &mbox);

	if (status == 0)	{
		csio_printf("Mailbox owned by %s\n\n",
						owner[mbox.owner_info]);

		data_dump = (uint64_t *)mbox.buffer;

		for (i = 0; i < CSIO_MAX_MB_SIZE; i += 8, j++)
			csio_printf("%016"FS_U64x"\n", data_dump[j]);
	}

	return status;

} /* csio_print_mbox */

__csio_export int
csio_get_cim_q_cfg(adap_handle_t hw, csio_cim_q_config_t *q_cfg)
{
	void *buffer = NULL;
	void *payload = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(csio_cim_q_config_t));
	int status = 0;
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_GET_CIM_QCFG);

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_get_cim_q_cfg: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len,
			 CSIO_IOCD_READ);

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status == 0)	{
		payload = get_payload(buffer);
		csio_memcpy(q_cfg, payload, sizeof(csio_cim_q_config_t));
	}

	ioctl_buffer_free(buffer);

	return status;

} /* csio_get_cim_q_cfg */

int
csio_print_cim_q_cfg(adap_handle_t hw)
{
	csio_cim_q_config_t q_cfg;
	int status = 0;
	uint32_t i = 0, *p = NULL, *wr = NULL;
	static const char *qname[] = {
		"TP0", "TP1", "ULP", "SGE0", "SGE1", "NC-SI",
		"ULP0", "ULP1", "ULP2", "ULP3", "SGE", "NC-SI"
	};

	csio_memset(&q_cfg, 0, sizeof(csio_cim_q_config_t));

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	status = csio_get_cim_q_cfg(hw, &q_cfg);

	if (status != 0)
		return status;

	p = q_cfg.stat;
	wr = q_cfg.obq_wr;

	/* Dump the CIM Queue config contents.*/
	csio_printf("Queue  Base  Size Thres RdPtr WrPtr  SOP  EOP Avail\n");

	for (i = 0; i < CSIO_CIM_NUM_IBQ; i++, p += 4) {
		csio_printf("%5s %5x %5u %4u %6x  %4x %4u %4u %5u\n",
			   qname[i], q_cfg.base[i], q_cfg.size[i],
			   q_cfg.thres[i],
			   G_IBQRDADDR(p[0]), G_IBQWRADDR(p[1]),
			   G_QUESOPCNT(p[3]), G_QUEEOPCNT(p[3]),
			   G_QUEREMFLITS(p[2]) * 16);
	}

	for ( ; i < CSIO_CIM_NUM_IBQ + CSIO_CIM_NUM_OBQ; i++, p += 4, wr += 2) {
		csio_printf("%5s %5x %5u %11x  %4x %4u %4u %5u\n",
			   qname[i], q_cfg.base[i], q_cfg.size[i],
			   G_QUERDADDR(p[0]) & 0x3FFF, wr[0] - q_cfg.base[i],
			   G_QUESOPCNT(p[3]), G_QUEEOPCNT(p[3]),
			   G_QUEREMFLITS(p[2]) * 16);
	}


	return 0;

} /* csio_print_cim_q_cfg */

static void
cim_la_dump_buffer(uint8_t *buffer, uint32_t cim_la_size)
{
	uint32_t *p = (uint32_t *)buffer;
	uint32_t lines = cim_la_size / 8;

	csio_printf("Status   Data      PC     LS0Stat  LS0Addr "
			 "            LS0Data\n");

	while(lines--) {
		csio_printf("  %02x   %x%07x %x%07x %08x %08x %08x%08x%08x%08x\n",
			(p[0] >> 4) & 0xff, p[0] & 0xf, p[1] >> 4, p[1] & 0xf,
			p[2] >> 4, p[2] & 0xf, p[3], p[4], p[5], p[6], p[7]);

		p+=8;
	}

	return;
} /* cim_la_dump_buffer */


static void
cim_la_dump_3in1_buffer(uint8_t *buffer, uint32_t cim_la_size)
{
	uint32_t *p = (uint32_t *)buffer;
	uint32_t lines = cim_la_size / 8;

	csio_printf("Status   Data      PC\n");

	while(lines--) {
		csio_printf("  %02x   %08x %08x\n", p[5] & 0xff, p[6],
			   p[7]);
		csio_printf("  %02x   %02x%06x %02x%06x\n",
			   (p[3] >> 8) & 0xff, p[3] & 0xff, p[4] >> 8,
			   p[4] & 0xff, p[5] >> 8);
		csio_printf("  %02x   %x%07x %x%07x\n", (p[0] >> 4) & 0xff,
			   p[0] & 0xf, p[1] >> 4, p[1] & 0xf, p[2] >> 4);

		p+=8;
	}

	return;
} /* cim_la_dump_3in1_buffer */

__csio_export int
csio_get_cim_la(adap_handle_t hw, csio_cim_la_t *cim_la)
{
	void *buffer = NULL;
	void *payload = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(csio_cim_la_t));
	int status = 0;
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_GET_CIM_LA);

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_get_cim_la: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len,
			 CSIO_IOCD_READ);

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status == 0)	{
		payload = get_payload(buffer);
		csio_memcpy(cim_la, payload, sizeof(csio_cim_la_t));
	}

	ioctl_buffer_free(buffer);

	return status;
} /* csio_get_cim_la */

int
csio_print_cim_la(adap_handle_t hw)
{
	csio_cim_la_t cim_la = {0};
	int status = 0;

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	status = csio_get_cim_la(hw, &cim_la);

	if (status != 0)
		return status;

	if (cim_la.complete_data)
		cim_la_dump_buffer(cim_la.buffer, cim_la.size);
	else
		cim_la_dump_3in1_buffer(cim_la.buffer, cim_la.size);

	return 0;

} /* csio_print_cim_la */

static void
cim_pifla_dump_buffer(uint8_t *buffer)
{
	const uint32_t *p = (const uint32_t *)buffer;
	uint32_t idx = 0;

	csio_printf("Cntl ID DataBE   Addr                 Data\n");

	for(idx = 0; idx < 2*CSIO_CIM_PIFLA_SIZE; idx++) {

		if (idx < CSIO_CIM_PIFLA_SIZE) {
			csio_printf(" %02x  %02x  %04x  %08x %08x%08x%08x%08x\n",
			   (p[5] >> 22) & 0xff, (p[5] >> 16) & 0x3f,
			   p[5] & 0xffff, p[4], p[3], p[2], p[1], p[0]);

			p+=6;
		}

		if (idx == CSIO_CIM_PIFLA_SIZE) {
			csio_printf("\nCntl ID               Data\n");
		}

		if (idx > CSIO_CIM_PIFLA_SIZE) {
			csio_printf(" %02x  %02x %08x%08x%08x%08x\n",
			   (p[4] >> 6) & 0xff, p[4] & 0x3f,
			   p[3], p[2], p[1], p[0]);

			p+=5;
		}

		//p++;
	}

	return;

} /* cim_pifla_dump_buffer */


__csio_export int
csio_get_cim_pif_la(adap_handle_t hw, csio_cim_pifla_t *cim_pifla)
{
	void *buffer = NULL;
	void *payload = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(csio_cim_pifla_t));
	int status = 0;
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_GET_CIM_PIF_LA);

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_get_cim_pif_la: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len,
			 CSIO_IOCD_READ);

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status == 0)	{
		payload = get_payload(buffer);
		csio_memcpy(cim_pifla, payload, sizeof(csio_cim_pifla_t));
	}

	ioctl_buffer_free(buffer);

	return status;
} /* csio_get_cim_pif_la */

int
csio_print_cim_pif_la(adap_handle_t hw)
{
	csio_cim_pifla_t cim_pifla;
	int status = 0;

	csio_memset(&cim_pifla, 0, sizeof(csio_cim_pifla_t));

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	status = csio_get_cim_pif_la(hw, &cim_pifla);

	if (status != 0)
		return status;

	cim_pifla_dump_buffer(cim_pifla.buffer);

	return 0;

} /* csio_print_cim_pif_la */

static void
cim_mala_dump_buffer(uint8_t *buffer)
{
	uint32_t *p = (uint32_t *)buffer;
	uint32_t idx = 0;

	csio_printf("\n");

	for(idx = 0; idx < 2*CSIO_CIM_MALA_SIZE; idx++) {

		if (idx < CSIO_CIM_MALA_SIZE) {
			csio_printf("%02x%08x%08x%08x%08x\n",
				   p[4], p[3], p[2], p[1], p[0]);

			p+=4;
		} else {
			if (idx == CSIO_CIM_MALA_SIZE) {
				csio_printf("\nCnt ID Tag UE       "
					"Data       RDY VLD\n");
				csio_printf(
					"%3u %2u  %x   %u %08x%08x  %u   %u\n",
					(p[2] >> 10) & 0xff, (p[2] >> 7) & 7,
					(p[2] >> 3) & 0xf, (p[2] >> 2) & 1,
					(p[1] >> 2) | ((p[2] & 3) << 30),
					(p[0] >> 2) | ((p[1] & 3) << 30),
					(p[0] >> 1) & 1, p[0] & 1);
			}

			p+=3;
		}
	}

	return;

} /* cim_mala_dump_buffer */

__csio_export int
csio_get_cim_ma_la(adap_handle_t hw, csio_cim_mala_t *cim_mala)
{
	void *buffer = NULL;
	void *payload = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(csio_cim_mala_t));
	int status = 0;
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_GET_CIM_MA_LA);

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_get_cim_ma_la: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len,
			 CSIO_IOCD_READ);

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status == 0)	{
		payload = get_payload(buffer);
		csio_memcpy(cim_mala, payload, sizeof(csio_cim_mala_t));
	}

	ioctl_buffer_free(buffer);

	return status;
} /* csio_get_cim_ma_la */

int
csio_print_cim_ma_la(adap_handle_t hw)
{
	csio_cim_mala_t cim_mala;
	int status = 0;

	csio_memset(&cim_mala, 0, sizeof(csio_cim_mala_t));

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	status = csio_get_cim_ma_la(hw, &cim_mala);

	if (status != 0)
		return status;

	cim_mala_dump_buffer(cim_mala.buffer);

	return 0;

} /* csio_print_cim_ma_la */


static void
field_desc_show(uint64_t v, field_desc_t *p)
{
	char buf[64] = {0};
	int line_size = 0;

	while (p->name)
	{
		uint64_t mask = (1ULL << p->width) - 1;

#if 0
		int len = sprintf_s(buf, sizeof(buf), "%s: %llu", p->name,
				    ((uint64_t)v >> p->start) & mask);
#endif
		int len;

		csio_snprintf(buf, sizeof(buf), "%s: %"FS_U64, p->name,
				    (((uint64_t)v >> p->start) & mask));

		len = (int)strlen(buf);

		if (line_size + len >= 79)
		{
			line_size = 8;
			csio_printf("\n        ");
		}

		csio_printf("%s ", buf);
		line_size += len + 1;
		p++;

	}

	csio_printf("\n");

	return;

} /* field_desc_show */

static void
tpla_show(uint8_t *buffer, uint32_t index)
{
	const uint64_t *p = (const uint64_t *)buffer;

	UNREFERENCED_PARAMETER(index);

	field_desc_show(*p, tp_la0);

	return;

} /* tpla_show */

static void
tpla_show2(uint8_t *buffer, uint32_t index)
{
	const uint64_t *p = (const uint64_t *)buffer;

	if (index)
		csio_printf("\n");

	field_desc_show(p[0], tp_la0);

	if (index < (CSIO_TPLA_SIZE / 2 - 1) || p[1] != ~0ULL)
	{
		field_desc_show(p[1], tp_la0);
	}

	return;

} /* tpla_show2 */

static void
tpla_show3(uint8_t *buffer, uint32_t index)
{
	const uint64_t *p = (const uint64_t *)buffer;;

	if (index)
		csio_printf("\n");

	field_desc_show(p[0], tp_la1);

	if (index < (CSIO_TPLA_SIZE / 2 - 1) || p[1] != ~0ULL)
	{
		field_desc_show(p[1], tp_la0);
	}

	return;

} /* tpla_show3 */

__csio_export int
csio_get_tp_la(adap_handle_t hw, csio_tp_la_data_t *tpla)
{
	void *buffer = NULL;
	void *payload = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(csio_tp_la_data_t));
	int status = 0;
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_GET_TP_LA);

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_get_tp_la: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len,
			 CSIO_IOCD_READ);

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status == 0)	{
		payload = get_payload(buffer);
		csio_memcpy(tpla, payload, sizeof(csio_tp_la_data_t));
	}

	ioctl_buffer_free(buffer);

	return status;
} /* csio_get_tp_la */

int
csio_print_tp_la(adap_handle_t hw)
{
	csio_tp_la_data_t tpla = {0};
	int status = 0;

	tpla_print_function tpla_printf = NULL;
	uint8_t *buffer = NULL;
	uintptr_t end_buffer = 0;
	uint32_t rows = 0, width = 0, i = 0;

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	status = csio_get_tp_la(hw, &tpla);

	if (status != 0)
		return status;

	switch (tpla.dbg_la_mode)
	{
		case 2:
			tpla_printf = tpla_show2;

			rows = (CSIO_TPLA_SIZE / 2);
			width = (2 * sizeof(uint64_t));

			break;
		case 3:
			tpla_printf = tpla_show3;

			rows = (CSIO_TPLA_SIZE / 2);
			width = (2 * sizeof(uint64_t));

			break;
		default:
			tpla_printf = tpla_show;

			rows = (CSIO_TPLA_SIZE);
			width = (sizeof(uint64_t));

			break;
	} /* switch (tpla.dbg_la_mode) */

	buffer = tpla.buffer;
	end_buffer = (uintptr_t)buffer + CSIO_TP_LA_SIZE_IN_BYTES;

	for (i = 0; i < rows; i++) {
		tpla_printf(buffer, i);

		buffer = (uint8_t *)((uint8_t *)buffer + width);

		if ((uintptr_t)buffer > end_buffer) {
			csio_printf("CsioShowTpLa: Traversing beyond "
					"buffer.\n");
			break;
		}

	} /* for ()*/

	return 0;
} /* csio_print_tp_la */

__csio_export int
csio_get_ulprx_la(adap_handle_t hw, csio_ulprx_la_data_t *ulprx_la)
{
	void *buffer = NULL;
	void *payload = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(csio_ulprx_la_data_t));
	int status = 0;
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_GET_ULPRX_LA);

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_get_ulprx_la: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len,
			 CSIO_IOCD_READ);

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status == 0)	{
		payload = get_payload(buffer);
		csio_memcpy(ulprx_la, payload,
				sizeof(csio_ulprx_la_data_t));
	} else {
		csio_memset(ulprx_la, 0, sizeof(csio_ulprx_la_data_t));
	}

	ioctl_buffer_free(buffer);

	return status;

} /* csio_get_ulprx_la */

int
csio_print_ulprx_la(adap_handle_t hw)
{
	static csio_ulprx_la_data_t ulprx_la;
	int status = 0, i = 0;
	//uint32_t *p = NULL;
	uint32_t *p = (uint32_t *)&ulprx_la.buffer[0];

	csio_memset(&ulprx_la, 0, sizeof(csio_ulprx_la_data_t));

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	status = csio_get_ulprx_la(hw, &ulprx_la);

	if (status != 0) {
		if(errno == EOPNOTSUPP) {
			return 0;
		} else {
			return -1;
		}
	}

	csio_printf("      Pcmd        Type   Message"
		 "                Data\n");

	for (i = 0; i < CSIO_ULPRX_LA_SIZE; i++) {
		//p = ulprx_la.buffer[i];

		csio_printf("%08x%08x  %4x  %08x  %08x%08x%08x%08x\n",
			   p[1], p[0], p[2], p[3], p[7], p[6], p[5], p[4]);

		p+=8;
	}

	return 0;
} /* csio_print_ulprx_la */

__csio_export int
csio_get_mps_tcam(adap_handle_t hw, uint32_t index,
			csio_mps_tcam_data_t *mps_tcam)
{
	void *buffer = NULL;
	csio_mps_tcam_data_t *mps_tcam_info = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(csio_mps_tcam_data_t));
	int status = 0;
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_GET_MPS_TCAM);

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_get_mps_tcam: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Set the index */
	mps_tcam_info = get_payload(buffer);
	mps_tcam_info->index = index;

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status == 0)	{
		csio_memcpy(mps_tcam, mps_tcam_info,
				sizeof(csio_mps_tcam_data_t));
	} else {
		csio_memset(mps_tcam, 0, sizeof(csio_mps_tcam_data_t));
	}

	ioctl_buffer_free(buffer);

	return status;

} /* csio_get_mps_tcam */

int
csio_print_mps_tcam(adap_handle_t hw)
{
	csio_mps_tcam_data_t mps_tcam_data = {0};
	int status = 0;
	uint32_t index = 0;

	uint8_t *addr = NULL;
	uint64_t mask = 0;
	uint32_t cls_lo = 0;
	uint32_t cls_hi = 0;

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	// Get the TCAM index 0, to see whether print_mps_tcam is
	// a supported function. If not, don't print the below head
	// message.
	// Note: When printing the MPS tcam, again index 0 will be read
	status = csio_get_mps_tcam(hw, 0, &mps_tcam_data);

	if(errno != EOPNOTSUPP) {
		csio_printf("Idx  Ethernet address     Mask     Vld Ports PF"
				 "  VF Repl P0 P1 P2 P3  ML\n");
	} else {
		return 0;
	}

	for(index = 0; index < CSIO_NEXACT_MAC; index ++) {
		status = csio_get_mps_tcam(hw, index, &mps_tcam_data);

		if (status != 0)
			return status;

		addr = mps_tcam_data.eth_addr;
		mask = mps_tcam_data.mask;
		cls_lo = mps_tcam_data.cls_low;
		cls_hi = mps_tcam_data.cls_hi;

		if (mps_tcam_data.tcamx & mps_tcam_data.tcamy) {
			csio_printf("%3u         -\n", index);
			continue;
		}


		csio_printf("%3u %02x:%02x:%02x:%02x:%02x:%02x %012"FS_U64x
			"%3c   %#x%4u%4d%4c%4u%3u%3u%3u %#x\n",
			index, addr[0], addr[1], addr[2], addr[3], addr[4],
			addr[5], (uint64_t)mask,
			(cls_lo & F_SRAM_VLD) ? 'Y' : 'N', G_PORTMAP(cls_hi),
			G_PF(cls_lo),
			(cls_lo & F_VF_VALID) ? G_VF(cls_lo) : -1,
			(cls_lo & F_REPLICATE) ? 'Y' : 'N',
			G_SRAM_PRIO0(cls_lo), G_SRAM_PRIO1(cls_lo),
			G_SRAM_PRIO2(cls_lo), G_SRAM_PRIO3(cls_lo),
			(cls_lo >> S_MULTILISTEN0) & 0xf);
	} /* for() */

	return 0;
} /* csio_print_mps_tcam */

static void
csio_dump_cim_q_buffer(uint8_t *buffer, uint32_t lines)
{
	uint32_t *p = (uint32_t *)buffer;
	uint32_t idx = 0;

	while (lines--) {
		csio_printf("0x%04x: %08x %08x %08x %08x\n", idx * 16, p[0], p[1],
		   p[2], p[3]);

		p+=4;
		idx++;
	}

	return;
} /* csio_dump_cim_q_buffer */

__csio_export int
csio_get_cim_q_buffer(adap_handle_t hw, int q_id, int is_inbound_q,
		void *q_request)
{
	void *buffer = NULL;
	void *payload = NULL;
	uint32_t *q_idx = NULL;
	uint16_t opcode = (is_inbound_q) ?
				CSIO_HW_GET_CIM_IBQ :
				CSIO_HW_GET_CIM_OBQ;

	size_t req_len = (is_inbound_q) ? sizeof(csio_cim_ibq_t) :
					sizeof(csio_cim_obq_t);
	size_t len = os_agnostic_buffer_len(req_len);
	int status = 0;
	uint32_t cmd = CSIO_STOR_HW_OPCODE(opcode);

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	if (q_id == -1)
		return -1;

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_get_cim_q_buffer: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Set the index */
	q_idx = get_payload(buffer);
	*q_idx = (uint32_t)q_id;

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status == 0)	{
		payload = get_payload(buffer);
		csio_memcpy(q_request, payload, req_len);
	}

	ioctl_buffer_free(buffer);

	return status;
} /* csio_get_cim_q_buffer */

int
csio_print_cim_ibq(adap_handle_t hw, int q_id)
{
	csio_cim_ibq_t cim_ibq = {0};
	int status = 0;

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	if (q_id == -1)
		return -1;

	status = csio_get_cim_q_buffer(hw, q_id, TRUE, (void *)&cim_ibq);

	if (status != 0)
		return status;

	csio_dump_cim_q_buffer(cim_ibq.buffer, CSIO_CIM_IBQ_SIZE);

	return 0;
} /* csio_print_cim_ibq */

int
csio_print_cim_obq(adap_handle_t hw, int q_id)
{
	csio_cim_obq_t cim_obq = {0};
	int status = 0;

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	if (q_id == -1)
		return -1;

	status = csio_get_cim_q_buffer(hw, q_id, FALSE, (void *)&cim_obq);

	if (status != 0)
		return status;

	csio_dump_cim_q_buffer(cim_obq.buffer, (6 * CSIO_CIM_IBQ_SIZE));

	return 0;
} /* csio_print_cim_ibq */

__csio_export int
csio_get_cpl_stats(adap_handle_t hw, csio_tp_cpl_stats_t *stats)
{
	void *buffer = NULL;
	void *payload = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(csio_tp_cpl_stats_t));
	int status = 0;
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_GET_CPL_STATS);

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_get_cpl_stats: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len,
			 CSIO_IOCD_READ);

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status == 0)	{
		payload = get_payload(buffer);
		csio_memcpy(stats, payload, sizeof(csio_tp_cpl_stats_t));
	}

	ioctl_buffer_free(buffer);

	return status;
} /* csio_get_cpl_stats */

int
csio_print_cpl_stats(adap_handle_t hw)
{
	csio_tp_cpl_stats_t stats;
	int status = 0;

	csio_memset(&stats, 0, sizeof(csio_tp_cpl_stats_t));

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	status = csio_get_cpl_stats(hw, &stats);

	if (status == 0) {
		csio_printf("                 channel 0  channel 1  "
			      "channel 2  channel 3\n");
		csio_printf("CPL requests:   %10u %10u %10u %10u\n",
			   stats.req[0], stats.req[1], stats.req[2],
			   stats.req[3]);
		csio_printf("CPL responses:  %10u %10u %10u %10u\n",
			   stats.rsp[0], stats.rsp[1], stats.rsp[2],
			   stats.rsp[3]);
	}

	return status;
} /* csio_print_cpl_stats */

__csio_export int
csio_get_ddp_stats(adap_handle_t hw, csio_tp_usm_stats_t *stats)
{
	void *buffer = NULL;
	void *payload = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(csio_tp_usm_stats_t));
	int status = 0;
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_GET_DDP_STATS);

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_get_ddp_stats: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len,
			CSIO_IOCD_READ);

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status == 0)	{
		payload = get_payload(buffer);
		csio_memcpy(stats, payload, sizeof(csio_tp_usm_stats_t));
	}

	ioctl_buffer_free(buffer);

	return status;
} /* csio_get_ddp_stats */

int
csio_print_ddp_stats(adap_handle_t hw)
{
	csio_tp_usm_stats_t stats = {0};
	int status = 0;

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	status = csio_get_ddp_stats(hw, &stats);

	if (status == 0) {
		csio_printf("Frames: %u\n", stats.frames);
		csio_printf("Octets: %"FS_U64"\n", (uint64_t)stats.octets);
		csio_printf("Drops:  %u\n", stats.drops);
	}

	return status;
} /* csio_print_ddp_stats */

__csio_export int
csio_get_tp_err_stats(adap_handle_t hw, csio_tp_err_stats_t *stats)
{
	void *buffer = NULL;
	void *payload = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(csio_tp_err_stats_t));
	int status = 0;
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_GET_TP_ERR_STATS);

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_get_tp_err_stats: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len,
			CSIO_IOCD_READ);

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status == 0)	{
		payload = get_payload(buffer);
		csio_memcpy(stats, payload, sizeof(csio_tp_err_stats_t));
	}

	ioctl_buffer_free(buffer);

	return status;
} /* csio_get_tp_err_stats */

int
csio_print_tp_err_stats(adap_handle_t hw)
{
	csio_tp_err_stats_t stats;
	int status = 0;

	csio_memset(&stats, 0, sizeof(csio_tp_err_stats_t));

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	status = csio_get_tp_err_stats(hw, &stats);

	if (status == 0) {
		csio_printf("                 channel 0  channel 1  channel 2"
			      "  channel 3\n");
		csio_printf("macInErrs:      %10u %10u %10u %10u\n",
			   stats.macInErrs[0], stats.macInErrs[1],
			   stats.macInErrs[2], stats.macInErrs[3]);
		csio_printf("hdrInErrs:      %10u %10u %10u %10u\n",
			   stats.hdrInErrs[0], stats.hdrInErrs[1],
			   stats.hdrInErrs[2], stats.hdrInErrs[3]);
		csio_printf("tcpInErrs:      %10u %10u %10u %10u\n",
			   stats.tcpInErrs[0], stats.tcpInErrs[1],
			   stats.tcpInErrs[2], stats.tcpInErrs[3]);
		csio_printf("tcp6InErrs:     %10u %10u %10u %10u\n",
			   stats.tcp6InErrs[0], stats.tcp6InErrs[1],
			   stats.tcp6InErrs[2], stats.tcp6InErrs[3]);
		csio_printf("tnlCongDrops:   %10u %10u %10u %10u\n",
			   stats.tnlCongDrops[0], stats.tnlCongDrops[1],
			   stats.tnlCongDrops[2], stats.tnlCongDrops[3]);
		csio_printf("tnlTxDrops:     %10u %10u %10u %10u\n",
			   stats.tnlTxDrops[0], stats.tnlTxDrops[1],
			   stats.tnlTxDrops[2], stats.tnlTxDrops[3]);
		csio_printf("ofldVlanDrops:  %10u %10u %10u %10u\n",
			   stats.ofldVlanDrops[0], stats.ofldVlanDrops[1],
			   stats.ofldVlanDrops[2], stats.ofldVlanDrops[3]);
		csio_printf("ofldChanDrops:  %10u %10u %10u %10u\n\n",
			   stats.ofldChanDrops[0], stats.ofldChanDrops[1],
			   stats.ofldChanDrops[2], stats.ofldChanDrops[3]);
		csio_printf("ofldNoNeigh:    %u\nofldCongDefer:  %u\n",
			   stats.ofldNoNeigh, stats.ofldCongDefer);
	}

	return status;
} /* csio_print_tp_err_stats */

__csio_export int
csio_get_tp_tcp_stats(adap_handle_t hw, csio_tp_tcp_stats_t *v4,
			csio_tp_tcp_stats_t *v6)
{
	void *buffer = NULL;
	void *v4_payload = NULL, *v6_payload = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(csio_tp_tcp_stats_t) * 2);
	int status = 0;
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_GET_TCP_STATS);

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_get_tp_tcp_stats: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len,
			 CSIO_IOCD_READ);

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status == 0)	{
		v4_payload = get_payload(buffer);
		v6_payload = (void *)((uintptr_t)v4_payload +
					sizeof(csio_tp_tcp_stats_t));

		csio_memcpy(v4, v4_payload, sizeof(csio_tp_tcp_stats_t));
		csio_memcpy(v6, v6_payload, sizeof(csio_tp_tcp_stats_t));
	}

	ioctl_buffer_free(buffer);

	return status;
} /* csio_get_tp_tcp_stats */

int
csio_print_tp_tcp_stats(adap_handle_t hw)
{
	csio_tp_tcp_stats_t v4 = {0}, v6 = {0};
	int status = 0;

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	status = csio_get_tp_tcp_stats(hw, &v4, &v6);

	if (status == 0) {
		csio_printf(
			 "                                IPv4           "
			 "    IPv6\n");
		csio_printf("OutRsts:      %20u %20u\n", v4.tcpOutRsts,
							v6.tcpOutRsts);
		csio_printf("InSegs:       %20"FS_U64" %20"FS_U64"\n",
			(uint64_t)v4.tcpInSegs, (uint64_t)v6.tcpInSegs);
		csio_printf("OutSegs:      %20"FS_U64" %20"FS_U64"\n",
			(uint64_t)v4.tcpOutSegs, (uint64_t)v6.tcpOutSegs);
		csio_printf("RetransSegs:  %20"FS_U64" %20"FS_U64"\n",
			(uint64_t)v4.tcpRetransSegs,
			(uint64_t)v6.tcpRetransSegs);
	}

	return status;
} /* csio_print_tp_tcp_stats */

__csio_export int
csio_get_pm_stats(adap_handle_t hw, csio_pm_stats_t *stats)
{
	void *buffer = NULL;
	void *payload = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(csio_pm_stats_t));
	int status = 0;
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_GET_PM_STATS);

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_get_pm_stats: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len,
			 CSIO_IOCD_READ);

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status == 0) {
		payload = get_payload(buffer);
		csio_memcpy(stats, payload, sizeof(csio_pm_stats_t));
	}

	ioctl_buffer_free(buffer);

	return status;
} /* csio_get_pm_stats */

int
csio_print_pm_stats(adap_handle_t hw)
{
	csio_pm_stats_t stats;
	int status = 0, i = 0;
	static const char *pm_stats[] = {
		"Read:", "Write bypass:", "Write mem:", "Flush:", "FIFO wait:"
	};

	csio_memset(&stats, 0, sizeof(csio_pm_stats_t));

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	status = csio_get_pm_stats(hw, &stats);

	if (status == 0) {
		csio_printf("                Tx count            Tx cycles    "
			 "Rx count            Rx cycles\n");
		for (i = 0; i < CSIO_PM_NSTATS; i++)
			csio_printf("%-13s %10u %20"FS_U64"  %10u %20"FS_U64"\n",
				   pm_stats[i], stats.tx_cnt[i],
				   (uint64_t)stats.tx_cyc[i], stats.rx_cnt[i],
				   (uint64_t)stats.rx_cyc[i]);
	}

	return status;
} /* csio_print_pm_stats */

__csio_export int
csio_get_lb_stats(adap_handle_t hw, int idx, csio_lb_port_stats_t *stats)
{
	void *buffer = NULL;
	csio_lb_port_stats_t *lb_port_stats_info = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(csio_lb_port_stats_t));
	int status = 0;
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_GET_LB_STATS);

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_get_lb_stats: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len,
			 CSIO_IOCD_READ);

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	/* Set the idx. */
	lb_port_stats_info = get_payload(buffer);
	lb_port_stats_info->idx = idx;

	if (status == 0)	{
		csio_memcpy(stats, lb_port_stats_info,
					sizeof(csio_lb_port_stats_t));
	} else {
		csio_memset(stats, 0, sizeof(csio_lb_port_stats_t));
	}

	ioctl_buffer_free(buffer);

	return status;
} /* csio_get_lb_stats */

int
csio_print_lb_stats(adap_handle_t hw)
{
	csio_lb_port_stats_t stats[2];
	int status = 0, i = 0, j= 0;
	uint64_t *p0 = NULL, *p1 = NULL;
	static const char *stat_name[] = {
		"OctetsOK:", "FramesOK:", "BcastFrames:", "McastFrames:",
		"UcastFrames:", "ErrorFrames:", "Frames64:", "Frames65To127:",
		"Frames128To255:", "Frames256To511:", "Frames512To1023:",
		"Frames1024To1518:", "Frames1519ToMax:", "FramesDropped:",
		"BG0FramesDropped:", "BG1FramesDropped:", "BG2FramesDropped:",
		"BG3FramesDropped:", "BG0FramesTrunc:", "BG1FramesTrunc:",
		"BG2FramesTrunc:", "BG3FramesTrunc:"
	};

	csio_memset(stats, 0, 2 * sizeof(csio_lb_port_stats_t));

	for (i = 0; i < 4; i++) {

		status = csio_get_lb_stats(hw, i, &stats[0]);
		status += csio_get_lb_stats(hw, i+1, &stats[1]);

		if (status == 0) {

			p0 = &stats[0].octets;
			p1 = &stats[1].octets;
			csio_printf("%s                       Loopback %u    "
				"       Loopback %u\n", i == 0 ? "" : "\n",
				i, i + 1);

			for (j = 0; j < CSIO_ARRAY_SIZE(stat_name); j++)
				csio_printf("%-17s %20"FS_U64" %20"FS_U64"\n",
					stat_name[j],
					(uint64_t)*p0++,
					(uint64_t)*p1++);
		}

		status = 0;
	}

	return status;
} /* csio_print_lb_stats */

int
csio_print_host_trace_buffer(adap_handle_t hw)
{
	int status = 0;

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	if (!oshw_ops.os_print_host_trace_buf) {
		csio_printf("os_print_host_trace_buf - not implemented!\n");
		return -1;
	}

	/* Call OS specific handler. */
	status = oshw_ops.os_print_host_trace_buf(hw);

	if(errno == EOPNOTSUPP) {
		return 0;
	} else {
		return status;
	}
}

int
csio_print_t4_reg_dump(adap_handle_t hw, char *reg)
{
	int status = 0;

	if (hw == (adap_handle_t)-1 || reg == NULL) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	if (!oshw_ops.os_t4_reg_dump) {
		csio_printf("os_t4_reg_dump - not implemented!\n");
		return -1;
	}

	/* Call OS specific handler. */
	status = oshw_ops.os_t4_reg_dump(hw,
			(!csio_stricmp(reg, "all")) ? NULL : reg);

	return status;
}

struct mem_desc {
	unsigned int base;
	unsigned int limit;
	unsigned int idx;
};

static int
mem_desc_cmp(const void *a, const void *b)
{
	return ((const struct mem_desc *)a)->base -
	       ((const struct mem_desc *)b)->base;
} /* mem_desc_cmp */

static void
mem_region_show(const char *name, unsigned int from, unsigned int to)
{
	char buf[40] = {0};

	csio_string_get_size((uint64_t)to - from + 1, CSIO_STRING_UNITS_2,
								buf, sizeof(buf));
	csio_printf("%-14s %#x-%#x [%s]\n", name, from, to, buf);

	return;
} /* mem_region_show */

void
csio_print_meminfo(adap_handle_t hw)
{
	static const char *memory[] = { "EDC0:", "EDC1:", "MC:",
					"MC0:", "MC1:"};
	static const char *region[] = {
		"DBQ contexts:", "IMSG contexts:", "FLM cache:", "TCBs:",
		"Pstructs:", "Timers:", "Rx FL:", "Tx FL:", "Pstruct FL:",
		"Tx payload:", "Rx payload:", "LE hash:", "iSCSI region:",
		"TDDP region:", "TPT region:", "STAG region:", "RQ region:",
		"RQUDP region:", "PBL region:", "TXPBL region:", "ULPRX state:",
		"ULPTX state:"
	};

	int i = 0, n = 0;
	uint32_t lo = 0, hi = 0;
	struct mem_desc avail[3];
	struct mem_desc mem[CSIO_ARRAY_SIZE(region) + 3]; /* up to 3 holes */
	struct mem_desc *md = mem;

	csio_memset(avail, 0,  3 * sizeof(struct mem_desc));
	csio_memset(mem, 0, (CSIO_ARRAY_SIZE(region) + 3) *
						sizeof(struct mem_desc));

	for (i = 0; i < CSIO_ARRAY_SIZE(mem); i++) {
		mem[i].limit = 0;
		mem[i].idx = i;
	}

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return;
	}

	/* Find and sort the populated memory ranges */
	i = 0;
	lo = csio_read_reg32(hw, A_MA_TARGET_MEM_ENABLE);
	if (lo & F_EDRAM0_ENABLE) {
		hi = csio_read_reg32(hw, A_MA_EDRAM0_BAR);
		avail[i].base = G_EDRAM0_BASE(hi) << 20;
		avail[i].limit = avail[i].base + (G_EDRAM0_SIZE(hi) << 20);
		avail[i].idx = 0;
		i++;
	}
	if (lo & F_EDRAM1_ENABLE) {
		hi = csio_read_reg32(hw, A_MA_EDRAM1_BAR);
		avail[i].base = G_EDRAM1_BASE(hi) << 20;
		avail[i].limit = avail[i].base + (G_EDRAM1_SIZE(hi) << 20);
		avail[i].idx = 1;
		i++;
	}
	if (lo & F_EXT_MEM_ENABLE) {
		hi = csio_read_reg32(hw, A_MA_EXT_MEMORY_BAR);
		avail[i].base = G_EXT_MEM_BASE(hi) << 20;
		avail[i].limit = avail[i].base + (G_EXT_MEM_SIZE(hi) << 20);
		avail[i].idx = 2;
		i++;
	}
/* For T5 */
	else if (lo & F_EXT_MEM0_ENABLE) {
		hi = csio_read_reg32(hw, A_MA_EXT_MEMORY0_BAR);
		avail[i].base = G_EXT_MEM0_BASE(hi) << 20;
		avail[i].limit = avail[i].base + (G_EXT_MEM0_SIZE(hi) << 20);
		avail[i].idx = 3;
		i++;
	}
	else if (lo & F_EXT_MEM1_ENABLE) {
		hi = csio_read_reg32(hw, A_MA_EXT_MEMORY1_BAR);
		avail[i].base = G_EXT_MEM1_BASE(hi) << 20;
		avail[i].limit = avail[i].base + (G_EXT_MEM1_SIZE(hi) << 20);
		avail[i].idx = 4;
		i++;
	}

	if (!i)                                    /* no memory available */
		return;

	csio_heap_sort(avail, i, sizeof(struct mem_desc), mem_desc_cmp, NULL);
	(md++)->base = csio_read_reg32(hw, A_SGE_DBQ_CTXT_BADDR);
	(md++)->base = csio_read_reg32(hw, A_SGE_IMSG_CTXT_BADDR);
	(md++)->base = csio_read_reg32(hw, A_SGE_FLM_CACHE_BADDR);
	(md++)->base = csio_read_reg32(hw, A_TP_CMM_TCB_BASE);
	(md++)->base = csio_read_reg32(hw, A_TP_CMM_MM_BASE);
	(md++)->base = csio_read_reg32(hw, A_TP_CMM_TIMER_BASE);
	(md++)->base = csio_read_reg32(hw, A_TP_CMM_MM_RX_FLST_BASE);
	(md++)->base = csio_read_reg32(hw, A_TP_CMM_MM_TX_FLST_BASE);
	(md++)->base = csio_read_reg32(hw, A_TP_CMM_MM_PS_FLST_BASE);

	/* the next few have explicit upper bounds */
	md->base = csio_read_reg32(hw, A_TP_PMM_TX_BASE);
	md->limit = md->base - 1 +
		    csio_read_reg32(hw, A_TP_PMM_TX_PAGE_SIZE) *
		    G_PMTXMAXPAGE(csio_read_reg32(hw, A_TP_PMM_TX_MAX_PAGE));
	md++;

	md->base = csio_read_reg32(hw, A_TP_PMM_RX_BASE);
	md->limit = md->base - 1 +
		    csio_read_reg32(hw, A_TP_PMM_RX_PAGE_SIZE) *
		    G_PMRXMAXPAGE(csio_read_reg32(hw, A_TP_PMM_RX_MAX_PAGE));
	md++;

	if (csio_read_reg32(hw, A_LE_DB_CONFIG) & F_HASHEN) {
		hi = csio_read_reg32(hw, A_LE_DB_TID_HASHBASE) / 4;
		md->base = csio_read_reg32(hw, A_LE_DB_HASH_TID_BASE);
//		md->limit = (oshw->tids.ntids - hi) * 16 + md->base - 1;
	} else {
		md->base = 0;
		md->idx = CSIO_ARRAY_SIZE(region);  /* hide it */
	}
	md++;

#define ulp_region(reg) \
	md->base = csio_read_reg32(hw, A_ULP_ ## reg ## _LLIMIT);\
	(md++)->limit = csio_read_reg32(hw, A_ULP_ ## reg ## _ULIMIT)

	ulp_region(RX_ISCSI);
	ulp_region(RX_TDDP);
	ulp_region(TX_TPT);
	ulp_region(RX_STAG);
	ulp_region(RX_RQ);
	ulp_region(RX_RQUDP);
	ulp_region(RX_PBL);
	ulp_region(TX_PBL);
#undef ulp_region

	md->base = csio_read_reg32(hw, A_ULP_RX_CTX_BASE);
//	md->limit = md->base + oshw->tids.ntids - 1;
	md++;
	md->base = csio_read_reg32(hw, A_ULP_TX_ERR_TABLE_BASE);
//	md->limit = md->base + oshw->tids.ntids - 1;
	md++;

	/* add any address-space holes, there can be up to 3 */
	for (n = 0; n < i - 1; n++)
		if (avail[n].limit < avail[n + 1].base)
			(md++)->base = avail[n].limit;
	if (avail[n].limit)
		(md++)->base = avail[n].limit;

	n = (int)(md - mem);

	csio_heap_sort(mem, n, sizeof(struct mem_desc), mem_desc_cmp, NULL);

	for (lo = 0; lo < i; lo++)
	{
		mem_region_show(memory[avail[lo].idx], avail[lo].base,
				avail[lo].limit - 1);
	}

	csio_printf("\n");

	for (i = 0; i < n; i++)
	{
		if (mem[i].idx >= CSIO_ARRAY_SIZE(region))
			continue;                        /* skip holes */
		if (!mem[i].limit)
			mem[i].limit = i < n - 1 ? mem[i + 1].base - 1 : ~0;

		mem_region_show(region[mem[i].idx], mem[i].base,
				mem[i].limit);
	}

	csio_printf("\n");

	lo = csio_read_reg32(hw, A_CIM_SDRAM_BASE_ADDR);
	hi = csio_read_reg32(hw, A_CIM_SDRAM_ADDR_SIZE) + lo - 1;
	mem_region_show("uP RAM:", lo, hi);

	lo = csio_read_reg32(hw, A_CIM_EXTMEM2_BASE_ADDR);
	hi = csio_read_reg32(hw, A_CIM_EXTMEM2_ADDR_SIZE) + lo - 1;
	mem_region_show("uP Extmem2:", lo, hi);

	lo = csio_read_reg32(hw, A_TP_PMM_RX_MAX_PAGE);
	csio_printf("\n%u Rx pages of size %uKiB for %u channels\n",
		   G_PMRXMAXPAGE(lo),
		   csio_read_reg32(hw, A_TP_PMM_RX_PAGE_SIZE) >> 10,
		   (lo & F_PMRXNUMCHN) ? 2 : 1);

	lo = csio_read_reg32(hw, A_TP_PMM_TX_MAX_PAGE);
	hi = csio_read_reg32(hw, A_TP_PMM_TX_PAGE_SIZE);
	csio_printf("%u Tx pages of size %u%ciB for %u channels\n",
		   G_PMTXMAXPAGE(lo),
		   hi >= (1 << 20) ? (hi >> 20) : (hi >> 10),
		   hi >= (1 << 20) ? 'M' : 'K', 1 << G_PMTXNUMCHN(lo));
	csio_printf("%u p-structs\n\n",
		   csio_read_reg32(hw, A_TP_CMM_MM_MAX_PSTRUCT));

	for (i = 0; i < 4; i++) {
		lo = csio_read_reg32(hw, A_MPS_RX_PG_RSV0 + i * 4);
		csio_printf("Port %d using %u pages out of %u allocated\n",
			   i, G_USED(lo), G_ALLOC(lo));
	}

	csio_printf("\n");

	for (i = 0; i < 4; i++) {
		lo = csio_read_reg32(hw, A_MPS_RX_PG_RSV4 + i * 4);
		csio_printf(
			   "Loopback %d using %u pages out of %u allocated\n",
			   i, G_USED(lo), G_ALLOC(lo));
	}

	return;
} /* csio_print_meminfo */


__csio_export int
csio_get_hw_mem(adap_handle_t hw, int mem_type, int *offset,
		void *mem_buffer, size_t buf_len, int *done)
{
	int old_offset = *offset;
	int bytes_copied = -1;
	int status = 0;
	void *buffer = NULL;
	t4_mem_desc_t *mem_desc = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(t4_mem_desc_t) + buf_len);
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_GET_INTERNAL_MEM);

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_get_cim_q_cfg: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize the  t4_mem_desc_t*/
	mem_desc = (t4_mem_desc_t *)get_payload(buffer);

	mem_desc->mem_type		= mem_type;
	mem_desc->offset		= old_offset;
	mem_desc->embedded_buf_size	= (int)buf_len;

	*done = 0;

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status == 0) {
		bytes_copied = mem_desc->offset - old_offset;

		CSIO_ASSERT(bytes_copied <= buf_len);

		/* Set the new offset & copy the contents to the buffer! */
		*offset = mem_desc->offset;
		csio_memcpy(mem_buffer, mem_desc->embedded_buf,
			    csio_min(bytes_copied, buf_len));

		*done = mem_desc->done;
	}

	ioctl_buffer_free(buffer);

	return bytes_copied;

} /* csio_get_hw_mem */

int
csio_copy_hw_mem_to_file(adap_handle_t hw, int mem_type,
		file_handle_t file, int file_size, int display_progress)
{
	int hw_offset = 0, file_offset = 0;
	int bytes_copied = 0, done = 0;
	int file_status = 0;
	int buf_len = 4*1024; //4KB

	int step_size = 1024*1024; //1MB

	void *buffer = csio_malloc(buf_len);

	if (buffer == NULL) {
		csio_printf("Insufficient memory!!\n");
		return -1;
	}

	if (file_size <= 0) {
		csio_printf("Invalid file-size:%d\n", file_size);

		csio_memfree(buffer);
		return -1;
	}

	while (!done && file_offset < file_size) {

		/* Reset the buffer contents. */
		csio_memset(buffer, 0, buf_len);

		bytes_copied = csio_get_hw_mem(hw, mem_type, &hw_offset,
						buffer, buf_len, &done);

		if (bytes_copied == -1) {
			csio_printf("Couldn't read hw-mem [type:%d] "
				"@offset:%d\n", mem_type, hw_offset);

			csio_memfree(buffer);
			return -1;
		}

		file_offset = (hw_offset - bytes_copied);
		file_status = write_file(file, buffer, bytes_copied,
						(uint32_t *)&file_offset);

		if (file_status == -1) {
			csio_printf("Could write to file @offset:%d "
				"chunk-size:%d\n", file_offset, bytes_copied);

			csio_memfree(buffer);
			return -1;
		}

		CSIO_ASSERT(file_offset == hw_offset);

		if ((file_offset % step_size) == 0 && display_progress) {
			csio_printf("\r Progress: %5.2f%%",
				((float)(file_offset * 100))/
						((float)file_size));
		}

	}

	csio_memfree(buffer);
	return 0;
} /* csio_copy_hw_mem_to_file */


static const char *devlog_level_strings[] = {"EMERG", "CRIT", "ERR", "NOTICE", "INFO", "DEBUG"};

static const char *devlog_facility_strings[] = {"CORE", "UNKNOWN",	/* 0x0 */
						"SCHED", "UNKNOWN",
						"TIMER", "UNKNOWN",
						"RES", "UNKNOWN",
						"HW", "UNKNOWN",
						"UNKNOWN", "UNKNOWN",
						"UNKNOWN", "UNKNOWN",
						"UNKNOWN", "UNKNOWN",
						"FLR","UNKNOWN", 	/* 0x10 */
						"DMAQ", "UNKNOWN",
						"PHY", "UNKNOWN",
						"MAC", "UNKNOWN",
						"PORT", "UNKNOWN",
						"VI", "UNKNOWN",
						"FILTER", "UNKNOWN",
						"ACL", "UNKNOWN",
						"TM", "UNKNOWN",
						"QFC", "UNKNOWN",
						"DCB", "UNKNOWN",
						"ETH", "UNKNOWN",
						"OFLD", "UNKNOWN",
						"RI", "UNKNOWN",
						"ISCSI", "UNKNOWN",
						"FCOE", "UNKNOWN",
						"FOISCSI", "UNKNOWN",
						"FOFCOE"};

__csio_export int
csio_get_fw_log_info(adap_handle_t hw, csio_fwdevlog_info_t *fwdevlog_info)
{
	void *buffer = NULL;
	void *payload = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(csio_fwdevlog_info_t));
	int status = 0;
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_GET_FWDEVLOG_INFO);

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_get_fw_log_info: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len,
			 CSIO_IOCD_READ);

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status == 0) {
		payload = get_payload(buffer);
		csio_memcpy(fwdevlog_info, payload, sizeof(csio_fwdevlog_info_t));
	}

	ioctl_buffer_free(buffer);

	return status;

} /* csio_get_fw_log_info */

__csio_export int
csio_print_fw_logs_buffer(adap_handle_t hw, csio_fw_devlog_t *fw_devlog)
{
	uint32_t i = 0, index = 0;
	struct fw_devlog_e *e = NULL;

	if (fw_devlog->nentries == 0)
		return -1;

	csio_printf("%10s  %15s  %8s  %8s  %s\n",
			   "Seq#", "Tstamp", "Level", "Facility", "Message");


	for (i = 0; i < fw_devlog->nentries; i++) {

		/*
		 * Get a pointer to the log entry to display.  Skip unused log
		 * entries.
		 */

		index = fw_devlog->first + i;
		if (index >= fw_devlog->nentries)
			index -= fw_devlog->nentries;

		e = &fw_devlog->log[index];

		if (e->timestamp == 0)
			continue;

		/*
		 * Print the message.  This depends on the firmware using
		 * exactly the same formating strings as the kernel so we may
		 * eventually have to put a format interpreter in here ...
		 *
		 */

		csio_printf("%10d  %15lld  %8s  %8s  ",
			   e->seqno, (unsigned long long)e->timestamp,
			   (e->level < CSIO_ARRAY_SIZE(devlog_level_strings)
			    ? devlog_level_strings[e->level]
			    : "UNKNOWN"),
			   (e->facility < CSIO_ARRAY_SIZE(devlog_facility_strings)
			    ? devlog_facility_strings[e->facility]
			    : "UNKNOWN"));
		csio_printf((const char *)e->fmt, e->params[0], e->params[1],
			   e->params[2], e->params[3], e->params[4],
			   e->params[5], e->params[6], e->params[7]);

		//csio_printf("\n");

	}

	return 0;
} /* csio_print_fw_logs_buffer */

__csio_export
csio_fw_devlog_t *csio_alloc_fw_log_mem(adap_handle_t hw,
		csio_fwdevlog_info_t fwdevlog_info,
		size_t *buf_size)
{
	csio_fw_devlog_t *fw_devlog_buffer = NULL;
	size_t fw_devlog_size = 0;

	if (hw == (adap_handle_t)-1 || buf_size == NULL) {
		CSIO_ASSERT(FALSE);
		return NULL;
	}

	/* Initialize */
	fw_devlog_buffer = NULL;
	*buf_size = 0;

	fw_devlog_size = CSIO_FW_DEVLOG_HDR_SIZE + fwdevlog_info.size;
	fw_devlog_buffer = (csio_fw_devlog_t *)csio_malloc(fw_devlog_size);

	if (fw_devlog_buffer == NULL) {
		csio_printf("fw_devlog_buffer allocation failed!\n");
		return NULL;
	} else {
		csio_memset(fw_devlog_buffer, 0, fw_devlog_size);
		*buf_size = fw_devlog_size;
	}

	/*
	 * Record the basic log buffer information and read in the raw log.
	 *
	 */
	fw_devlog_buffer->nentries = (fwdevlog_info.size /
					sizeof (struct fw_devlog_e));
	fw_devlog_buffer->first = 0;

	return fw_devlog_buffer;

} /* csio_alloc_fw_log_mem */


__csio_export int
csio_get_fw_logs(adap_handle_t hw, csio_fwdevlog_info_t fwdevlog_info,
		csio_fw_devlog_t *fw_devlog_buffer, size_t buf_size)
{
	csio_fw_devlog_t *fw_devlog = fw_devlog_buffer;
	struct fw_devlog_e *devlog_entry = NULL;
	size_t expected_buf_size = 0;
	uint32_t i = 0, j = 0;
	uint64_t ftstamp = 0;
	int status = 0, done = 0, bytes_copied = 0, offset = 0;

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	if (!fw_devlog) {
		csio_printf("Invalid buffer!\n");
		return -1;
	}

	expected_buf_size = (fw_devlog->nentries * sizeof(struct fw_devlog_e)
				+ CSIO_FW_DEVLOG_HDR_SIZE);

	if (buf_size < expected_buf_size) {
		csio_printf("Insufficient buffer size!\n");
		return -1;
	}

	/* Read the FW DEVLOG */

	for (i = 0; i < fw_devlog->nentries; i++) {

		devlog_entry = &fw_devlog->log[i];
		offset = (int)fwdevlog_info.start +
			(int)(i * sizeof (struct fw_devlog_e));

		bytes_copied = csio_get_hw_mem(hw, fwdevlog_info.memtype,
					&offset, devlog_entry,
					sizeof(struct fw_devlog_e),
					&done);

		if (bytes_copied == -1) {
			csio_printf("Couldn't read FW DEVLOG "
				"(hw mem type:%d) @offset:%d\n",
				fwdevlog_info.memtype, offset);

			csio_memfree(fw_devlog);
			return -1;
		}

		if (done != 0) {
			csio_printf("Hit the end of HW memory!\n");
			csio_memfree(fw_devlog);
			CSIO_ASSERT(FALSE);
			return -1;
		}

		CSIO_ASSERT(bytes_copied == sizeof(struct fw_devlog_e));
	}

	/*
	 * Translate log multi-byte integral elements into host native format
	 * and determine where the first entry in the log is.
	 *
	 */
	for (ftstamp = ~0ULL, i = 0; i < fw_devlog->nentries; i++) {
		devlog_entry = &fw_devlog->log[i];

		if (devlog_entry->timestamp == 0)
			continue;

		devlog_entry->timestamp = be64_to_cpu(devlog_entry->timestamp);
		devlog_entry->seqno = be32_to_cpu(devlog_entry->seqno);
		for (j = 0; j < 8; j++)
			devlog_entry->params[j] = be32_to_cpu(devlog_entry->params[j]);

		if (devlog_entry->timestamp < ftstamp) {
			ftstamp = devlog_entry->timestamp;
			fw_devlog->first = i;
		}
	}
#if 0
	/* Print the FW DEVLOG */

	if (print_logs) {
		csio_print_fw_logs(hw, fw_devlog);
	}

	/* Free the buffer. */
	csio_memfree(fw_devlog);
#endif
	return status;

} /* csio_get_fw_logs */

int
csio_print_fw_logs(adap_handle_t hw)
{
	csio_fwdevlog_info_t fwdevlog_info;
	csio_fw_devlog_t *fw_devlog = NULL;
	size_t buf_size = 0;
	int status = 0;

	csio_memset(&fwdevlog_info, 0, sizeof(csio_fwdevlog_info_t));

	/* Get the FW DEVLOG information. */
	status = csio_get_fw_log_info(hw, &fwdevlog_info);

	if (status != 0) {
		if(errno != EOPNOTSUPP) {
			csio_printf("Failed to get FW DEVLOG information!\n");
			return -1;
		} else {
			return 0;
		}
	}

	/* Allocate the FW DEVLOG buffer. */
	fw_devlog = csio_alloc_fw_log_mem(hw, fwdevlog_info, &buf_size);

	if (fw_devlog == NULL || buf_size == 0) {
		csio_printf("Failed to alloc FW DEVLOG buffer!\n");
		return -1;
	}

	/* Get the FW DEVLOG */
	status = csio_get_fw_logs(hw, fwdevlog_info, fw_devlog, buf_size);

	if (status != 0) {
		csio_printf("Failed to fetch FW DEVLOGs from "
				"the adapter!\n");
		csio_memfree(fw_devlog);
		return -1;
	}

	/* Print the FW DEVLOG */
	csio_print_fw_logs_buffer(hw, fw_devlog);

	csio_memfree(fw_devlog);

	return status;
}/* csio_print_fw_logs */


__csio_export int
csio_get_hw_sge_cntx(adap_handle_t hw, csio_sge_ctx_t *sge_cntx_info,
				uint32_t cntx_type, uint32_t cntx_id)
{
	void *payload = NULL;
	void *buffer = NULL;
	csio_sge_ctx_t *sge_cntx_info_request = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(csio_sge_ctx_t));
	int status = 0;
	uint32_t cmd = CSIO_STOR_HW_OPCODE(CSIO_HW_GET_SGE_CNTX);

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("csio_get_hw_sge_cntx: "
			"Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);

	/* Initialize the cntx_type & cntx_id. */
	sge_cntx_info_request = get_payload(buffer);
	sge_cntx_info_request->cntx_type = cntx_type;
	sge_cntx_info_request->cntx_id = cntx_id;

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status == 0) {
		payload = get_payload(buffer);
		csio_memcpy(sge_cntx_info, payload, sizeof(csio_sge_ctx_t));
	}

	ioctl_buffer_free(buffer);

	return status;
} /* csio_get_hw_sge_cntx */

/*
 * Shows the fields of a multi-word structure.  The structure is considered to
 * consist of @nwords 32-bit words (i.e, it's an (@nwords * 32)-bit structure)
 * whose fields are described by @fd.  The 32-bit words are given in @words
 * starting with the least significant 32-bit word.
 */
static void
show_struct(const uint32_t *words, int nwords,
			const field_desc_ex_t *fd)
{
	uint32_t w = 0;
	field_desc_ex_t *p = NULL;

	for (p = (field_desc_ex_t *)fd; p->name; p++)
		w = csio_max(w, (uint32_t)strlen(p->name));

	while (fd->name) {
		unsigned long long data;
		int first_word = fd->start / 32;
		int shift = fd->start % 32;
		int width = fd->end - fd->start + 1;
		unsigned long long mask = (1ULL << width) - 1;

		data = (words[first_word] >> shift) |
		       ((uint64_t)words[first_word + 1] << (32 - shift));
		if (shift)
		       data |= ((uint64_t)words[first_word + 2] << (64 - shift));
		data &= mask;
		if (fd->islog2)
			data = (unsigned long long)1 << data;
		csio_printf("%-*s ", w, fd->name);
		csio_printf(fd->hex ? "%#llx\n" : "%llu\n", data << fd->shift);
		fd++;
	}
} /* show_struct */

static void
show_t4_sge_cnxt(const csio_sge_ctx_t *p)
{
	const uint32_t *data = (uint32_t *)p->buf;

	if (p->cntx_type == CHSTOR_CNTXT_TYPE_EGRESS)
		show_struct(data, 6, (data[0] & 2) ? fl : egress);
	else if (p->cntx_type == CHSTOR_CNTXT_TYPE_FL)
		show_struct(data, 3, flm);
	else if (p->cntx_type == CHSTOR_CNTXT_TYPE_RSP)
		show_struct(data, 5, ingress);
	else if (p->cntx_type == CHSTOR_CNTXT_TYPE_CONG)
		show_struct(data, 1, conm);

	return;
} /* show_t4_sge_cnxt */

int
csio_print_sge_cntx(adap_handle_t hw, uint32_t cntx_type, uint32_t cntx_id)
{
	csio_sge_ctx_t sge_cntx;
	int status = 0;

	csio_memset(&sge_cntx, 0, sizeof(csio_sge_ctx_t));

	status = csio_get_hw_sge_cntx(hw, &sge_cntx, cntx_type, cntx_id);

	if (status != 0) {
		csio_printf("Couldn't fetch the SGE context for "
				"Id:%d Type:%d\n", cntx_id, cntx_type);
		return status;
	}

	show_t4_sge_cnxt(&sge_cntx);

	return status;
}
