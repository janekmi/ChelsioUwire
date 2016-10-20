/*
 *  Copyright (C) 2008-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description:
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/aer.h>
#include <linux/mm.h>
#include <linux/notifier.h>
#include <linux/kdebug.h>
#include <linux/version.h>
#include <linux/firmware.h>

#include <csio_version.h>
#include <csio_os_init.h>
#include <csio_os_dfs.h>
#include <csio_stor_ioctl.h>
#include <csio_t4_ioctl.h>
#include <csio_defs.h>
#include <common.h>
#ifdef __CSIO_FOISCSI_ENABLED__
#include <csio_trans_foiscsi.h>
#endif

#ifdef __CSIO_TARGET__

static void csio_tgtm_unreg_cleanup(void *data);

/* Module parameter - Max TGT IO requests */
CSIO_MODULE_PARAM(tgt_reqs, 4096, 512, 4096, " Max IO req elements per"
		  " function. Default:4096, Min:512, Max:4096", int);

/*
 * csio_scsi_mode: determines target/initiator mode. This is expressed
 * as an array. Every successive pair indicates {n, m}, where "n" is
 * all:pci_bus:pci_device:pci_function (0xaabbddff) and "m" is
 * the mode.  Value range of "m" is [1, 2, 3] where 1 stands for
 * initiator, 2 stands for target and 3 for mixed mode (target + initiator).
 * The default value can be modified with the pair {0xaa000000, m}. This
 * will apply the mode to all the cards on the system.
 */
static uint32_t csio_scsi_mode[64] = {0xaa000000, CSIO_SCSI_MODE_TARGET};
static int num_scsi_mode_elem = 0;
module_param_array(csio_scsi_mode, int, &num_scsi_mode_elem, 0);
MODULE_PARM_DESC(csio_scsi_mode, " Array of elements representing pair of {n,m}"
				 " where n is 0xaabbddff, m is the mode");

#define CSIO_N_TO_ALL(__n)	(((__n) & 0xff000000) >> 24)
#define CSIO_N_TO_BUS(__n)	(((__n) & 0x00ff0000) >> 16)
#define CSIO_N_TO_DEV(__n)	(((__n) & 0x0000ff00) >> 8)
#define CSIO_N_TO_FN(__n)	((__n) & 0x000000ff)

static uint8_t csio_scsi_default_mode = 0;

static void
csio_scsi_mode_check(void)
{
	if (num_scsi_mode_elem & 1) {
		printk(KERN_ERR KBUILD_MODNAME":csio_scsi_mode needs pairs."
		       " Defaulting mode to Target mode.\n");
		csio_scsi_default_mode = CSIO_SCSI_MODE_TARGET;
		return;
	}

	if (CSIO_N_TO_ALL(csio_scsi_mode[0]) == 0xaa) {
		if ((csio_scsi_mode[1] == CSIO_SCSI_MODE_TARGET) ||
		    (csio_scsi_mode[1] == CSIO_SCSI_MODE_INITIATOR) ||
		    (csio_scsi_mode[1] == CSIO_SCSI_MODE_MIXED)) {
			csio_scsi_default_mode = csio_scsi_mode[1];
#if 1 /* Remove this code snippet once our cards can support mixed mode */
			if (csio_scsi_default_mode == CSIO_SCSI_MODE_MIXED)
				csio_scsi_default_mode = CSIO_SCSI_MODE_TARGET;
#endif
			printk(KERN_INFO KBUILD_MODNAME": SCSI mode set to"
			       " (%s) for all cards.\n",
				(csio_scsi_default_mode ==
							CSIO_SCSI_MODE_TARGET)?
					"Target" :
					((csio_scsi_default_mode ==
						CSIO_SCSI_MODE_INITIATOR)?
					"Initiator" : "Initiator,Target"));
		}
		else
			printk(KERN_INFO KBUILD_MODNAME": Incorrect mode"
			       " specified for all cards, defaulting to"
			       " Target Mode.\n");
	}
}

static void
csio_hw_get_scsi_mode(struct csio_hw *hw)
{
	struct csio_os_hw *oshw = csio_hw_to_os(hw);
	int i = 0, match = 0;
	uint8_t mode = CSIO_SCSI_MODE_TARGET;

	/* Have we already got user's scsi mode during load time? */
	if (csio_scsi_default_mode) {
		mode = csio_scsi_default_mode;
		goto out;
	}

	/* If not, check for per-device mode */
	for (i = 0; i < num_scsi_mode_elem; i += 2) {
		if ((CSIO_N_TO_BUS(csio_scsi_mode[i]) == CSIO_PCI_BUS(oshw)) &&
		    (CSIO_N_TO_DEV(csio_scsi_mode[i]) == CSIO_PCI_DEV(oshw)) &&
		    (CSIO_N_TO_FN(csio_scsi_mode[i]) == CSIO_PCI_FUNC(oshw))) {

			match = 1;
			mode = csio_scsi_mode[i + 1];

			/* Check for correctness */
			if ((mode != CSIO_SCSI_MODE_TARGET) &&
			    (mode != CSIO_SCSI_MODE_INITIATOR) &&
			    (mode != CSIO_SCSI_MODE_MIXED)) {
				csio_err(hw, "Incorrect mode specified,"
					     " defaulting to Target mode.\n");
				mode = CSIO_SCSI_MODE_TARGET;
			}

			break;
		}
	} /* for all {n,m} pairs */

	if (!match)
		csio_err(hw, "Unable to determine scsi mode,"
			     " defaulting to Target mode.\n");
out:
#if 1 /* Remove this code snippet once our cards can support mixed mode */
	if (mode == CSIO_SCSI_MODE_MIXED)
		mode = CSIO_SCSI_MODE_TARGET;
#endif
	csio_info(hw, "SCSI mode: %s\n", (mode == CSIO_SCSI_MODE_TARGET)?
					"Target" :
					((mode == CSIO_SCSI_MODE_INITIATOR)?
					"Initiator" : "Initiator,Target"));

	hw->scsi_mode = mode;
}

/* One extra queue for SCSI free list */
#define CSIO_FCOE_NUM_Q		(CSIO_FCOE_NUMQ + 		\
				(CSIO_MAX_SCSI_QSETS * 3) + 	\
				CSIO_HW_NEQ + CSIO_HW_NIQ + 	\
				CSIO_HW_NFLQ + CSIO_HW_NINTXQ)

EXPORT_SYMBOL(csio_sal_xmit);
EXPORT_SYMBOL(csio_sal_acc);
EXPORT_SYMBOL(csio_sal_rsp);
EXPORT_SYMBOL(csio_sal_tm_done);
EXPORT_SYMBOL(csio_sal_free);
EXPORT_SYMBOL(csio_sal_initiator_transport_id);
EXPORT_SYMBOL(csio_sal_start_stop_tgt);
EXPORT_SYMBOL(csio_sal_init);
EXPORT_SYMBOL(csio_sal_exit);

#else
#define CSIO_FCOE_NUM_Q		(CSIO_FCOE_NUMQ + 		\
				(CSIO_MAX_SCSI_QSETS * 2) + 	\
				CSIO_HW_NEQ + CSIO_HW_NIQ + 	\
				CSIO_HW_NFLQ + CSIO_HW_NINTXQ)
#endif /* __CSIO_TARGET__ */

static int pf_counter;
static int csio_lun_qdepth = 32;

/* #ifdef __CSIO_DEBUG__ */ /* Remove this once iscsi is ready */
#define FN_ALL 0
#define FN_FCOE 1
#define FN_ISCSI 2

#ifndef __CSIO_TARGET__
static int csio_proto = FN_ALL;
/* Module parameter - Protocol support */
CSIO_MODULE_PARAM(proto, 0, 0, 2," Load protocol."
		 " Default - 0(ALL), 1(FCoE), 2(FOiSCSI)", int);
#else
static int csio_proto = FN_FCOE;
#endif

static int csio_chip = 0;
/* Module parameter - Chip support */
CSIO_MODULE_PARAM(chip, 0, 0, 3," Chip support."
		 " Default - 0(T5), 1(T4), 2 (T6), 3(T4/T5/T6)", int);

/* Module parameter - Exit without issuing any Mailboxes */
CSIO_MODULE_PARAM(exit_no_mb, 0, 0, 1, " Exit without kick-starting firmware."
		 " Default - 0 (dont exit), 1 (exit)", int);

/* Module parameter - Port vector mask for linkup */
CSIO_MODULE_PARAM(port_mask, 0xf, 0x1, 0xf," Port vector mask for linkup."
		 " (4bits) Default - 0xf (all ports)", uint);

/* Module parameter - Default Log level */
CSIO_MODULE_PARAM(dbg_level, 0xFEFF, 0, 0xFFFF, " Debug level. "
		 "Default - 0xFEFF. Module[B15:B8]:Level[B7:B0]", int);

static int csio_dflt_msg_enable = 0;
/*  Default message set for the module */
CSIO_MODULE_PARAM(dflt_msg_enable, 0, 0, 0x8000000,
		  "Chelsio T4/T5 default message enable bitmap", uint);

/* Module parameter - lun qdepth */
CSIO_MODULE_PARAM(lun_qdepth, CSIO_MAX_CMD_PER_LUN, 1, 32,
		  " Lun queue depth (1-32), Default - 32", int);

/* Module parameter - FCoE Class of Service (CoS) */
CSIO_MODULE_PARAM(cos, 3, 1, 8, " FCoE Class of Service (CoS)"
		  " Default - 3, Range 1 - 8.", int);

/*
 * Module parameter - Interrupt mode
 * The driver uses the best interrupt scheme available on a platform in the
 * order MSI-X, MSI, legacy INTx interrupts.  This parameter determines
 * which
 * of these schemes the driver may consider as follows:
 *
 * csio_msi = 2: choose from among all three options
 * csio_msi = 1: only consider MSI and INTx interrupts
 * csio_msi = 0: force INTx interrupts
 */
CSIO_MODULE_PARAM(msi, 2, 0, 2, " whether to use MSI-X, MSI or INTx", int);

/* Module parameter - Interrupt coalesce count */
CSIO_MODULE_PARAM(intr_coalesce_cnt, 0, 0, 16,
		  " Interrupt coalesce count, Disable:0, Range:1-16, Default:0",
		  int);

/* Module parameter - Interrupt coalesce time */
CSIO_MODULE_PARAM(intr_coalesce_time, 10, 5, 200,
		  " Interrupt coalesce time (us), Min:5, Max:200,"
		  " Default: 10", int);

/* Module parameter - Max scan timeout*/
CSIO_MODULE_PARAM(max_scan_tmo, 0, 0, 30,
		 " Maximum time (seconds) to wait before declaring scan done.",
		 uint);

/* Module parameter - Delta scan timeout*/
CSIO_MODULE_PARAM(delta_scan_tmo, 5, 2, 5,
		  " Time (seconds) to wait between two FW scan events."
		  " Default - 5 seconds .", uint);

/* Module parameter - Ingress queue length */
CSIO_MODULE_PARAM(scsi_iqlen, 128, 32, 128,
		  " Max elements in SCSI Ingress queue."
		  " Default - 128.", int);

/* Module parameter - FDMI support */
CSIO_MODULE_PARAM(fdmi_enable, 1, 0, 1,
		  " fdmi support 1:enable 0:disable"
		  " Default - 1", int);

static int csio_fw_install = 1;
/*
 * Firmware auto-install by driver during attach (0, 1, 2 = prohibited, allowed,
 * encouraged respectively).
 */
CSIO_MODULE_PARAM(fw_install, 1, 0, 2,
		  "whether to have FW auto-installed by driver "
		  "during attach (0, 1, 2 = prohibited, allowed(Default) "
		  "encouraged respectively.", int);

static unsigned int csio_cdev_major;
static struct class *csio_class;
static DECLARE_BITMAP(csio_cdev_minors, CSIO_MAX_CMINORS);

static csio_retval_t csio_config_queues(struct csio_hw *);
static struct csio_lnode *csio_oslnode_alloc(struct csio_hw *);

static void
csio_module_params_check(void)
{
#ifndef __CSIO_TARGET__
	csio_proto_check(csio_proto);
#endif /* __CSIO_TARGET__ */
	csio_chip_check(csio_chip);
	csio_dbg_level_check(csio_dbg_level);
	csio_dflt_msg_enable_check(csio_dflt_msg_enable);
	csio_exit_no_mb_check(csio_exit_no_mb);
	csio_port_mask_check(csio_port_mask);
	csio_lun_qdepth_check(csio_lun_qdepth);
	csio_cos_check(csio_cos);
	csio_msi_check(csio_msi);
	csio_intr_coalesce_cnt_check(csio_intr_coalesce_cnt);
	csio_intr_coalesce_time_check(csio_intr_coalesce_time);
	csio_max_scan_tmo_check(csio_max_scan_tmo);
	csio_delta_scan_tmo_check(csio_delta_scan_tmo);
	csio_scsi_iqlen_check(csio_scsi_iqlen);
	csio_fdmi_enable_check(csio_fdmi_enable);
	csio_fw_install_check(csio_fw_install);
#ifdef __CSIO_TARGET__
	csio_scsi_mode_check();
	csio_tgt_reqs_check(csio_tgt_reqs);
#endif /* __CSIO_TARGET__ */
}

#if defined(__BIG_ENDIAN)
#define __BIG_ENDIAN_BITFIELD
#define htobe32_const(x) (x)
#elif defined(__LITTLE_ENDIAN)
#define __LITTLE_ENDIAN_BITFIELD
#define htobe32_const(x) (((x) >> 24) | (((x) >> 8) & 0xff00) | \
		    ((((x) & 0xffffff) << 8) & 0xff0000) | ((((x) & 0xff) << 24) & 0xff000000))
#else
#error "Must set BYTE_ORDER"
#endif

static struct fw_info fw_info_array[] = {
	{
		.chip = CHELSIO_T4,
		.fs_name = FW4_CFNAME,
		.fw_mod_name = FW4_FNAME,
		.fw_hdr = {
			.chip = FW_HDR_CHIP_T4,
			.fw_ver = htobe32_const(FW_VERSION(T4)),
			.intfver_nic = FW_INTFVER(T4, NIC),
			.intfver_vnic = FW_INTFVER(T4, VNIC),
			.intfver_ofld = FW_INTFVER(T4, OFLD),
			.intfver_ri = FW_INTFVER(T4, RI),
			.intfver_iscsipdu = FW_INTFVER(T4, ISCSIPDU),
			.intfver_iscsi = FW_INTFVER(T4, ISCSI),
			.intfver_fcoepdu = FW_INTFVER(T4, FCOEPDU),
			.intfver_fcoe = FW_INTFVER(T4, FCOE),
		},
	}, {
		.chip = CHELSIO_T5,
		.fs_name = FW5_CFNAME,
		.fw_mod_name = FW5_FNAME,
		.fw_hdr = {
			.chip = FW_HDR_CHIP_T5,
			.fw_ver = htobe32_const(FW_VERSION(T5)),
			.intfver_nic = FW_INTFVER(T5, NIC),
			.intfver_vnic = FW_INTFVER(T5, VNIC),
			.intfver_ofld = FW_INTFVER(T5, OFLD),
			.intfver_ri = FW_INTFVER(T5, RI),
			.intfver_iscsipdu = FW_INTFVER(T5, ISCSIPDU),
			.intfver_iscsi = FW_INTFVER(T5, ISCSI),
			.intfver_fcoepdu = FW_INTFVER(T5, FCOEPDU),
			.intfver_fcoe = FW_INTFVER(T5, FCOE),
		},
	}, {
		.chip = CHELSIO_T6,
		.fs_name = FW6_CFNAME,
		.fw_mod_name = FW6_FNAME,
		.fw_hdr = {
			.chip = FW_HDR_CHIP_T6,
			.fw_ver = __cpu_to_be32(FW_VERSION(T6)),
			.intfver_nic = FW_INTFVER(T6, NIC),
			.intfver_vnic = FW_INTFVER(T6, VNIC),
			.intfver_ofld = FW_INTFVER(T6, OFLD),
			.intfver_ri = FW_INTFVER(T6, RI),
			.intfver_iscsipdu = FW_INTFVER(T6, ISCSIPDU),
			.intfver_iscsi = FW_INTFVER(T6, ISCSI),
			.intfver_fcoepdu = FW_INTFVER(T6, FCOEPDU),
			.intfver_fcoe = FW_INTFVER(T6, FCOE),
		},
	}

};

static struct fw_info* find_fw_info(int chip)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(fw_info_array); i++) {
		if (fw_info_array[i].chip == chip)
			return (&fw_info_array[i]);
	}
	return (NULL);
}

/*
 * Returns CSIO_INVAL if attempts to flash the firmware failed
 * else returns CSIO_SUCCESS,
 * if flashing was not attempted because the card had the
 * latest firmware CSIO_CANCELLED is returned
 */
static int
csio_os_flash_fw(struct csio_hw *hw)
{
	int ret = CSIO_CANCELLED;
	const struct firmware *fw;
	int reset = 1;
	struct fw_info *fw_info;
	struct fw_hdr *card_fw;
	const u8 *fw_data = NULL;
	unsigned int fw_size = 0;
	struct csio_os_hw *oshw = csio_hw_to_os(hw);
	struct pci_dev *pci_dev = csio_hw_to_osdev(oshw);
	adapter_t *adap = &hw->adap;
	struct device *dev = &pci_dev->dev ;

	/*
	 * This is the firmware whose headers the driver was compiled against
	 */
	fw_info = find_fw_info(CHELSIO_CHIP_VERSION(adap->params.chip));
	if (fw_info == NULL) {
		csio_err(hw,
		       "unable to look up firmware information for chip %d.\n",
		       csio_chip_id(hw));
		return CSIO_INVAL;
	}

	/*
	 * allocate memory to read the header of the firmware on the card
	 */
	card_fw = kmalloc(sizeof(*card_fw), GFP_KERNEL);
	if (card_fw == NULL) {
		csio_err(hw, "failed to alloc memory for card fw\n");
		return CSIO_NOMEM;
	}	

	/*
	 * Get FW from from /lib/firmware/
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
	ret = request_firmware_direct(&fw, fw_info->fw_mod_name, dev);
#else
	ret = request_firmware(&fw, fw_info->fw_mod_name, dev);
#endif
	if (ret < 0) {
		csio_err(hw, "unable to load firmware image %s"
			", error %d\n", fw_info->fw_mod_name, ret);
	} else {
		fw_data = fw->data;
		fw_size = fw->size;
	}

	/*
	 * upgrade FW logic
	 */
	ret = t4_prep_fw(adap, fw_info, fw_data, fw_size, card_fw,
			csio_fw_install, hw->fw_state, &reset);

	hw->fwrev = adap->params.fw_vers;
	hw->tp_vers = adap->params.tp_vers;

	/* Cleaning up */
	if (fw != NULL)
		release_firmware(fw);
	kfree(card_fw);
	return ret;
}

static int
csio_os_flash_config(struct csio_hw *hw, u32 *fw_cfg_param, char *path)
{
	int ret = CSIO_SUCCESS;
	const struct firmware *cf;

	struct csio_os_hw *oshw = csio_hw_to_os(hw);
	struct pci_dev *pci_dev = csio_hw_to_osdev(oshw);
	struct adapter *adap = &hw->adap;
	struct device *dev = &pci_dev->dev;
	char *fw_config_file;

	unsigned int mtype = 0, maddr = 0;
	uint32_t *cfg_data;

	/*
	 * If we have a T4 configuration file under /lib/firmware/cxgb4/,
	 * then use that.  Otherwise, use the configuration file stored
	 * in the adapter flash ...
	 */

	switch (CHELSIO_CHIP_VERSION(adap->params.chip)) {
	case CHELSIO_T4:
		if (is_fpga(adap->params.chip))
			fw_config_file = FW4_FPGA_CFNAME;
		else
			fw_config_file = FW4_CFNAME;
		break;
	case CHELSIO_T5:
		if (is_fpga(adap->params.chip))
			fw_config_file = FW5_FPGA_CFNAME;
		else
			fw_config_file = FW5_CFNAME;
		break;
	case CHELSIO_T6:
		if (is_fpga(adap->params.chip))
			fw_config_file = FW6_FPGA_CFNAME;
		else
			fw_config_file = FW6_CFNAME;
		break;

	default:
		csio_err(hw, "%s: Device %d is not supported\n", __FUNCTION__,
		       pci_dev->device);
		ret = CSIO_INVAL;
		return ret;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
	ret = request_firmware_direct(&cf, fw_config_file, dev);
#else
	ret = request_firmware(&cf, fw_config_file, dev);
#endif
	if (ret < 0) {
		csio_err(hw, "could not find config file %s ,err: %d\n",
			 fw_config_file, ret);
		return CSIO_NOSUPP;
	}

	if (cf->size >= FLASH_CFG_MAX_SIZE)
		return CSIO_NOMEM;

	cfg_data =(uint32_t *) kzalloc(cf->size, GFP_KERNEL);
	if (cfg_data == NULL) {
		return CSIO_NOMEM;
	}
	memcpy((void *)cfg_data, (const void *)cf->data, cf->size);

	ret = csio_hw_check_fwconfig(hw, fw_cfg_param);
	if (ret != CSIO_SUCCESS)
		return CSIO_INVAL;

	mtype = G_FW_PARAMS_PARAM_Y(*fw_cfg_param);
	maddr = G_FW_PARAMS_PARAM_Z(*fw_cfg_param) << 16;

	t4_os_lock(&adap->win0_lock);
	ret = t4_memory_rw(adap, csio_is_fcoe(hw) ? MEMWIN_CSIOSTOR : MEMWIN_FOISCSI,
			   mtype, maddr, cf->size, cfg_data, T4_MEMORY_WRITE);
	t4_os_unlock(&adap->win0_lock);

	if (ret == CSIO_SUCCESS) {
		csio_info(hw, "config file upgraded to %s\n",
				fw_config_file);
		snprintf(path, 64, "%s%s", "/lib/firmware/", fw_config_file);
	}
	
	kfree(cfg_data);
	release_firmware(cf);
	return ret;
}

static int phy_aq1202_version(const u8 *phy_fw_data,
				size_t phy_fw_size)
{
	int offset;

	/*
	 * At offset 0x8 you're looking for the primary image's
	 * starting offset which is 3 Bytes wide
	 *
	 * At offset 0xa of the primary image, you look for the offset
	 * of the DRAM segment which is 3 Bytes wide.
	 *
	 * The FW version is at offset 0x27e of the DRAM and is 2 Bytes
	 * wide
	 */
	#define be16(__p) (((__p)[0] << 8) | (__p)[1])
	#define le16(__p) ((__p)[0] | ((__p)[1] << 8))
	#define le24(__p) (le16(__p) | ((__p)[2] << 16))

	offset = le24(phy_fw_data + 0x8) << 12;
	offset = le24(phy_fw_data + offset + 0xa);
	return be16(phy_fw_data + offset + 0x27e);

	#undef be16
	#undef le16
	#undef le24
}

static struct info_10gbt_phy_fw {
	unsigned int phy_fw_id;		/* PCI Device ID */
	char *phy_fw_file;		/* /lib/firmware PHY firmware file */
	int (*phy_fw_version)(const u8 *phy_fw_data, size_t phy_fw_size);
	int phy_flash;
} phy_info_array[] = {
	{
		CSIO_T4_ISCSI_PHY_AQ1202_DEVICEID,
		PHY_AQ1202_FIRMWARE,
		phy_aq1202_version,
		1,
	},
	{
		CSIO_T4_ISCSI_PHY_BCM84834_DEVICEID,
		PHY_BCM84834_FIRMWARE,
		NULL,
		0
	},
	{
		CSIO_T4_FCOE_PHY_AQ1202_DEVICEID,
		PHY_AQ1202_FIRMWARE,
		phy_aq1202_version,
		1,
	},
	{
		CSIO_T4_FCOE_PHY_BCM84834_DEVICEID,
		PHY_BCM84834_FIRMWARE,
		NULL,
		0
	},
	{ 0, NULL, NULL, 0},
};

static struct info_10gbt_phy_fw* find_phy_info(int devid)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(phy_info_array); i++) {
		if (phy_info_array[i].phy_fw_id == devid)
			return (&phy_info_array[i]);
	}
	return NULL;
}

static int csio_os_flash_phy_fw(struct csio_hw *hw)
{
	const struct firmware *phyf;
	struct info_10gbt_phy_fw *phy_info;
	struct csio_os_hw *oshw = csio_hw_to_os(hw);
	struct pci_dev *pci_dev = csio_hw_to_osdev(oshw);
	struct device *dev = &pci_dev->dev ;
	int ret;

	phy_info = find_phy_info(hw->adap.params.pci.device_id);
	if (phy_info == NULL) {
		csio_err(hw, "No PHY firmware file found for this PHY\n");
		return CSIO_NOSUPP;
	}

	/*
	 * If we have a T4 PHY firmware file under /lib/firmware/cxgb4/, then
	 * use that. The adapter firmware provides us with a memory buffer
	 * where we can load a PHY firmware file from the host if we want to
	 * override the PHY firmware File in flash.
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
	ret = request_firmware_direct(&phyf, phy_info->phy_fw_file, dev);
#else
	ret = request_firmware(&phyf, phy_info->phy_fw_file, dev);
#endif
	if (ret < 0) {
		/*
		 * For adapters without FLASH attached to PHY for their
		 * firmware, it's obviously a fatal error if we can't get the
		 * firmware to the adapter.  For adapters with PHY firmware
		 * FLASH storage, it's worth a warning if we can't find the
		 * PHY Firmware but we'll neuter the error ...
		 */
		csio_err(hw, "unable to find PHY Firmware image "
			"/lib/fimrware/%s, error %d\n",
			phy_info->phy_fw_file, -ret);
		if (phy_info->phy_flash) {
			int cur_phy_fw_ver = 0;

			t4_phy_fw_ver(&hw->adap, &cur_phy_fw_ver);
			csio_warn(hw, "continuing with, on-adapter "
				"FLASH copy, version %#x\n", cur_phy_fw_ver);
			ret = CSIO_SUCCESS;
		}
		return ret;
	}

	/* Load PHY Firmware onto adapter. */
	ret = t4_load_phy_fw(&hw->adap,
			(csio_is_fcoe(hw) ? MEMWIN_CSIOSTOR : MEMWIN_FOISCSI),
			&hw->adap.win0_lock,
			phy_info->phy_fw_version,
			(u8 *)phyf->data, phyf->size);
	if (ret < 0)
		csio_err(hw, "PHY Firmware transfer error %d\n",
			ret);
	else if (ret > 0) {
		int new_phy_fw_ver = 0;

		if (phy_info->phy_fw_version)
			new_phy_fw_ver = phy_info->phy_fw_version(phyf->data,
								phyf->size);
		csio_info(hw, "Successfully transferred PHY "
			"Firmware /lib/firmware/%s, version %#x\n",
			phy_info->phy_fw_file, new_phy_fw_ver);
		ret = CSIO_SUCCESS;
	}

	release_firmware(phyf);

	return ret;
}

static struct csio_rnode *
csio_alloc_rnode(struct csio_lnode *ln)
{
	struct csio_rnode *rn;
	struct csio_os_rnode *osrn =  csio_alloc(csio_md(ln->hwp,
							 CSIO_RN_MD),
					       	 sizeof(struct csio_os_rnode),
					       	 CSIO_MNOWAIT);
	if (!osrn)
		goto err;

	memset(osrn, 0, sizeof(struct csio_os_rnode));
	rn = csio_osrn_to_rn(osrn);
	csio_rnode_to_os(rn) = osrn;
	if (csio_rnode_init(rn, ln))
		goto err_free;

	CSIO_INC_STATS(ln, n_rnode_alloc);
	return rn;

err_free:
	csio_free(csio_md(ln->hwp, CSIO_RN_MD), osrn);
err:
	CSIO_INC_STATS(ln, n_rnode_nomem);
	return NULL;
}

static void
csio_free_rnode(struct csio_rnode *rn)
{
	struct csio_os_rnode *osrn = rn->os_rnp;

	csio_rnode_exit(rn);
	csio_rnode_to_os(rn) = NULL;
	CSIO_INC_STATS(rn->lnp, n_rnode_free);
	csio_free(csio_md(rn->lnp->hwp, CSIO_RN_MD), osrn);
	return;
}

/*
 * csio_ln_block_reqs - Blocks SCSI requests.
 * @ln: lnode representing local port.
 *
 * Request the upper layer(SCSI ML) to block any further IOs. This routine is
 * invoked by lnode SM if it enters offline state.
 */
static void
csio_ln_block_reqs(struct csio_lnode *ln)
{
	struct csio_os_lnode *osln	= csio_lnode_to_os(ln);
	struct Scsi_Host *shost		= csio_osln_to_shost(osln);

	scsi_block_requests(shost);
}	

/*
 * csio_ln_unblock_reqs - Allows SCSI requests
 * @ln: lnode representing local port.
 *
 * Request the upper layer(SCSI ML) to allow IOs. This routine is
 * invoked by lnode SM if it enters Ready state.
 */
static void
csio_ln_unblock_reqs(struct csio_lnode *ln)
{
	struct csio_os_lnode *osln	= csio_lnode_to_os(ln);
	struct Scsi_Host *shost		= csio_osln_to_shost(osln);

	scsi_unblock_requests(shost);
}

/*
 * Return a version number to identify the type of adapter.  The scheme is:
 * - bits 0..9: chip version
 * - bits 10..15: chip revision
 * - bits 16..23: register dump version
 */
static inline
unsigned int mk_adap_vers(const struct adapter *ap)
{
	return CHELSIO_CHIP_VERSION(ap->params.chip) |
		(CHELSIO_CHIP_RELEASE(ap->params.chip) << 10) | (1 << 16);
}

static void
get_regs(struct csio_hw *hw, struct ethtool_regs *regs, void *buf)
{
	struct adapter *adap = &hw->adap;
	size_t buf_size;

	if (is_t4(adap->params.chip))
		buf_size = T4_REGMAP_SIZE;
	else
		buf_size = T5_REGMAP_SIZE;

	if (regs)
		regs->version = mk_adap_vers(adap);

	t4_get_regs(adap, buf, buf_size);

}

static int
csio_os_ioctl_handler(struct csio_os_hw *oshw, uint32_t opcode,
		      unsigned long arg, void *kbuf, uint32_t len)
{
	int ret;
	uint8_t  *fw_data;
	csio_mem_range_t *t;
	csio_load_cfg_t *cfg;
	scsi_q_t *scsiq = NULL;
	scsi_q_set_t *qset = NULL;
	struct csio_scsi_cpu_info *info = NULL;
	size_t reqsize = 0;
	uint16_t i = 0, j = 0;
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct adapter *adap = &hw->adap;
	void __user *payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));

	switch (opcode) {
	case CSIO_OS_FW_DOWNLOAD:
		t = (csio_mem_range_t *)kbuf;
		if (!t->len)
			return -EINVAL;

		fw_data = kmalloc(t->len, GFP_KERNEL);
		if (!fw_data)
			return -ENOMEM;

		if (copy_from_user(fw_data, payload + sizeof(*t), t->len)) {
			kfree(fw_data);
			return -EFAULT;
		}

		/*
		 * If the adapter has been fully initialized then we'll go
		 * ahead and try to get the firmware's cooperation in
		 * upgrading to the new firmware image otherwise we'll try to
		 * do the entire job from the host ... and we always "force"
		 * the operation in this path.
		 */
		ret = t4_fw_upgrade(adap, (csio_is_hw_ready(hw) ? hw->pfn
					: M_PCIE_FW_MASTER + 1), fw_data,
				t->len, /*force=*/true);

		kfree(fw_data);
		if (ret)
			return -EINVAL;
		break;
		
	case CSIO_OS_FW_CONFIG_DOWNLOAD:
		cfg = (csio_load_cfg_t *)kbuf;
		/* (cfg->len == 0) implies clearing of config file */
		if (!cfg->len) {
			ret = t4_load_cfg(adap, NULL, 0);
			return ret;
		}

		fw_data = kmalloc(cfg->len, GFP_KERNEL);
		if (!fw_data)
			return -ENOMEM;

		if (copy_from_user(fw_data, payload + sizeof(*cfg), cfg->len)) {
			kfree(fw_data);
			return -EFAULT;
		}

		ret = t4_load_cfg(adap, fw_data, cfg->len);
		kfree(fw_data);
		if (ret)
			return -EINVAL;
		break;

	case CSIO_OS_GET_SCSI_QUEUES:
		scsiq = (scsi_q_t *)kbuf;
		scsiq->num_scsi_qsets = (uint16_t)oshw->num_sqsets;
		reqsize = sizeof(scsiq->num_scsi_qsets) +
			(scsiq->num_scsi_qsets * sizeof(scsi_q_set_t));

		/* Copy to user number of required bytes and return success */
		if (len < reqsize) {
			scsiq->done = 0;
			if (copy_to_user(payload, kbuf, sizeof(*scsiq)))
				return -EFAULT;
			return 0;
		}

		qset = &scsiq->q_sets[0];
		for (i = 0; i < hw->num_t4ports; i++) {
			info = &oshw->scsi_cpu_info[i];
			for (j = 0; j < info->max_cpus; j++) {
				struct csio_scsi_qset *sqset =
					&oshw->sqset[hw->t4port[i].portid][j];
				qset->iq_idx = sqset->iq_idx;
				qset->eq_idx = sqset->eq_idx;
				qset->intr_idx = sqset->intr_idx;
				qset++;
			}
		}

		scsiq->done = 1;

		if (copy_to_user(payload, kbuf, sizeof(*scsiq) +
					((oshw->num_sqsets - 1) *
							sizeof(*qset))))
			return -EFAULT;
		break;

	case CSIO_OS_CREATE_NPIV_VPORT:
		ret = csio_os_create_npiv_vport(hw, kbuf, len);
		if (ret)
			return ret;
		break;
	case CSIO_OS_DELETE_NPIV_VPORT:
		ret = csio_os_delete_npiv_vport(hw, kbuf, len);
		if (ret)
			return ret;
		break;
	case CSIO_OS_LIST_NPIV_VPORT:
		ret = csio_os_list_npiv_vport(hw, kbuf, len);
		if (ret)
			return ret;
		if (copy_to_user(payload, kbuf, len))
			return -EFAULT;
		break;

	case CSIO_OS_T4_REG_DUMP:
		get_regs(csio_oshw_to_hw(oshw), NULL, kbuf);
		if (copy_to_user(payload, kbuf, len))
			return -EFAULT;
		break;

	case CSIO_OS_GET_HOST_TRACE_BUF: {
		struct csio_oss_trace_msg trace_msg;
		int mlen;

		mlen = sizeof(struct csio_oss_trace_msg);
		while (len >= mlen) {
			if (!(csio_oss_trace_readmsg(csio_hw_to_tbuf(hw),
						     &trace_msg, 1))) {
				/* No more msg */
				break;
		}

			if (copy_to_user(payload, (void *) &trace_msg, mlen))
				return -EFAULT;
			payload += mlen;
			len -= mlen;
		}
		break;
	}
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static int
csio_os_hw_ioctl_handler(struct csio_os_hw *oshw, uint32_t opcode,
		      void *kbuf, uint32_t len)
{
	enum csio_oss_error rv;
	int ret = 0;

	/* Handle IOCTL that require OS specific handling */
	switch (opcode) {
	
	case CSIO_HW_CARD_RESET:
		/* Delete NPIV lnodes */
		/* TODO. Delete all non physical lnodes */
		csio_oslnodes_exit(oshw, 1);

		/* Block upper IOs */
		csio_oslnodes_block_request(oshw);
		rv = csio_hw_ioctl_handler(csio_oshw_to_hw(oshw),
			opcode, kbuf, len);

		if (rv != CSIO_SUCCESS) {
			ret = -EINVAL;
		}
		/* Unblock upper IOs */
		csio_oslnodes_unblock_request(oshw);
		break;
	default:
		/* For rest, Handle IOCTL directly */
		rv = csio_hw_ioctl_handler(csio_oshw_to_hw(oshw),
			opcode, kbuf, len);
		if (rv != CSIO_SUCCESS) {
			ret = -EINVAL;
		}
		break;
	}
	return ret;
}

/*
 * csio_cdev_open - Open entry point.
 *
 */
static int
csio_cdev_open(struct inode *inode, struct file *filep)
{
	struct csio_os_hw *oshw;

	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	/* Populate oshw * pointer for use by ioctl */
	oshw = container_of(inode->i_cdev, struct csio_os_hw, cdev);
	filep->private_data = oshw;

	return 0;
}

/*
 * csio_cdev_release - Release entry point.
 *
 * Called when all shared references to this open object have closed
 * their file descriptors (Eg: between parent/child processes).
 */
static int
csio_cdev_release(struct inode *inode, struct file *filep)
{
	filep->private_data = NULL;
	return 0;
}



/*
 * csio_cdev_ioctl - Driver ioctl entry point.
 *
 */
static long
csio_cdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret, len;
	struct csio_os_hw *oshw;
	struct csio_hw *hw;
	void *kbuf = NULL;
	int dir = _IOC_NONE;
	enum csio_oss_error rv;
	ioctl_hdr_t hdr;

	oshw = (struct csio_os_hw *)file->private_data;
	if (!oshw) {
		printk("csiostor: Unable to find HW instance\n");
		return -ENOTTY;
	}

	hw = csio_oshw_to_hw(oshw);

	if (copy_from_user((void *)&hdr, (void __user *)arg,
			   			sizeof(ioctl_hdr_t)))
		return -EFAULT;

	len = hdr.len;
	dir = hdr.dir;

	if (len < 0) {
		csio_err(hw, "Invalid ioctl lenght: %x\n", cmd);
		return -EINVAL;
	}

	if (dir != _IOC_NONE) {
		if (len == 0) {
			csio_err(hw, "Invalid ioctl length"
				 " or direction %x\n", cmd);
			return -EINVAL;
		}

		kbuf = kzalloc(len, GFP_KERNEL);
		if (!kbuf)
			return -ENOMEM;

		if ((dir & _IOC_WRITE) &&
				(copy_from_user(kbuf, (void __user *)
					(arg + sizeof(ioctl_hdr_t)), len))) {
			kfree(kbuf);
			return -EFAULT;
		}
	}

	ret = 0;
	switch (cmd & CSIO_STOR_IOCTL_MASK) {
	case CSIO_STOR_HW:
		rv = csio_os_hw_ioctl_handler(oshw,
					       CSIO_STOR_GET_OPCODE(cmd),
					       kbuf, len);
		if (rv != CSIO_SUCCESS) {
			ret = -EINVAL;
			goto out;
		}
	       	break;

	case CSIO_OS:
		ret = csio_os_ioctl_handler(oshw, CSIO_STOR_GET_OPCODE(cmd),
						arg, kbuf, len);
		goto out;

	case CSIO_STOR_FCOE:
		if (!csio_is_fcoe(hw)) {
			ret = -EINVAL;
			goto out;
		}

		rv = csio_fcoe_ioctl_handler(csio_oshw_to_hw(oshw),
					       CSIO_STOR_GET_OPCODE(cmd),
					       kbuf, len);
		if (rv != CSIO_SUCCESS) {
			ret = -EINVAL;
			goto out;
		}
		break;

	case CSIO_STOR_ISCSI:
		if (csio_is_fcoe(hw)) {
			ret = -EINVAL;
			goto out;
		}
#ifdef __CSIO_FOISCSI_ENABLED__		
		/* GLUE CHANGE */
		rv = csio_foiscsi_transport_ioctl_handler(csio_oshw_to_hw(oshw),
						CSIO_STOR_GET_OPCODE(cmd), arg, kbuf, len);
		if (rv != CSIO_SUCCESS) {
			ret = -EINVAL;
			goto out;
		}
#endif		
		break;

	default:
		csio_err(hw ,"Invalid IOCTL cmd: %x\n", cmd);
		ret = -EOPNOTSUPP;
		goto out;
	}

	if ((dir & _IOC_READ) && (copy_to_user((void __user *)
				(arg + sizeof(ioctl_hdr_t)), kbuf, len)))
		ret = -EFAULT;
out:
	if (dir != _IOC_NONE)
		kfree(kbuf);
	return ret;
}

static struct file_operations csio_cdev_fops = {
	.owner			= THIS_MODULE,
	.open			= csio_cdev_open,
	.release		= csio_cdev_release,
	.unlocked_ioctl		= csio_cdev_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl 		= csio_cdev_ioctl,
#endif
#if 0
	.fasync			= csio_cdev_fasync, /* Could use this to send
						     * async notifications to
						     *  a user process.
						     */
#endif
};

/*
 * Although we attach to the FC transport, the template is referred to
 * as csio_fcoe_transport, because this is an FCoE driver.
 */
static struct scsi_transport_template *csio_fcoe_transport = NULL;
static struct scsi_transport_template *csio_fcoe_transport_vport = NULL;

/**
 * csio_pci_init - PCI initialization.
 * @pdev: PCI device.
 * @bars: Bitmask of bars to be requested.
 *
 * Initializes the PCI function by enabling MMIO, setting bus
 * mastership and setting DMA mask.
 */
static int
csio_pci_init(struct pci_dev *pdev, int *bars)
{
	int rv = -ENODEV;

	*bars = pci_select_bars(pdev, IORESOURCE_MEM);

	if (pci_enable_device_mem(pdev))
		goto err;

	if (pci_request_selected_regions(pdev, *bars, KBUILD_MODNAME))
		goto err_disable_device;

	pci_set_master(pdev);
	pci_try_set_mwi(pdev);

	if (!pci_set_dma_mask(pdev, DMA_BIT_MASK(64))) {
		pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64));
	} else if (!pci_set_dma_mask(pdev, DMA_BIT_MASK(32))) {
		pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
	} else {
		dev_err(&pdev->dev, "No suitable DMA available.\n");
		goto err_release_regions;
	}

	return 0;

err_release_regions:
	pci_release_selected_regions(pdev, *bars);
err_disable_device:
	pci_disable_device(pdev);
err:
	return rv;

}

/**
 * csio_pci_exit - PCI unitialization.
 * @pdev: PCI device.
 * @bars: Bars to be released.
 *
 */
static void
csio_pci_exit(struct pci_dev *pdev, int *bars)
{
	pci_release_selected_regions(pdev, *bars);
	pci_disable_device(pdev);
	return;
}

/*
 * IMPORTANT NOTE:
 *
 * Anybody wishing to dynamically allocate memory for a new structure must do
 * the following:
 *
 * (1) Add a new memory descriptor index in csio_hw.h. Max index is
 *     CSIO_MAX_MEM_DESCS, so the new index must be placed before CSIO_MAX_MD.
 * (2) Make an entry in either csio_fcoe_alloc_descs[] or
 *     csio_iscsi_alloc_descs[], specifying size of the allocation, and the
 *     index obtained in step (1). This entry should be added before the entry
 *     with -1s in it.
 * (3) Have the max number of such possible allocations at any point in time
 *     passed back in either csio_fcoe_get_num_alloc() or
 *     csio_iscsi_get_num_alloc().
 *
 */

/**
 * csio_fcoe_get_num_alloc - Get number of allocations for the said descriptor.
 * @idx: Index into the memory descriptor array.
 *
 */
static int
csio_fcoe_get_num_alloc(int idx)
{
	switch (idx) {

	case CSIO_RN_MD:
		return csio_fcoe_rnodes;

	case CSIO_Q_ARR_MD:
		return 1;

	case CSIO_Q_MD:
		return CSIO_FCOE_NUM_Q;

	case CSIO_FLB_FWEVT_MD:
		return 1;

	case CSIO_DDP_MD:
		return csio_ddp_descs;

	case CSIO_SCSIREQ_MD:
		return csio_scsi_ioreqs;

	case CSIO_MGMTREQ_MD:
		return csio_max_fcf;

	case CSIO_EVTQ_MD:
		return CSIO_EVTQ_SIZE;

	case CSIO_FCOE_FCF_MD:
		return csio_max_fcf;

#ifdef __CSIO_TARGET__
	case CSIO_FLB_SCSI_MD:
		return CSIO_MAX_SCSI_QSETS;

	case CSIO_TGTREQ_MD:
		return csio_tgt_reqs;
#endif /* __CSIO_TARGET__ */
	
	default:
		return -1;
	}
}

/**
 * csio_iscsi_get_num_alloc - Get number of allocations for the said descriptor.
 * @idx: Index into the memory descriptor array.
 *
 */
#ifdef __CSIO_FOISCSI_ENABLED__
static int
csio_iscsi_get_num_alloc(int idx)
{
	switch (idx) {
	case CSIO_LN_MD:
		return CSIO_ISCSI_NUM_LNODES;

	case CSIO_RN_MD:
		return CSIO_ISCSI_NUM_RNODES;

	case CSIO_Q_ARR_MD:
		return 1;

	case CSIO_Q_MD:
		return CSIO_ISCSI_Q_NUM;

	case CSIO_FLB_FWEVT_MD:
		return 1;

	case CSIO_DDP_MD:
		return csio_ddp_descs;

	case CSIO_SCSIREQ_MD:
		return csio_scsi_ioreqs;
	
	case CSIO_EVTQ_MD:
		return CSIO_EVTQ_SIZE;

	case CSIO_ISCSI_PERSISTENT_DB_MD:
		return 1;

	case CSIO_ISCSI_RSESS_MD:
		return CSIO_ISCSI_NUM_RNODES;

	default:
		return -1;
	}
}
#endif

static struct csio_alloc_desc csio_fcoe_alloc_descs[CSIO_MAX_MEM_DESCS] = {

	{ sizeof(struct csio_os_rnode),		CSIO_RN_MD		},

	{ ((sizeof(struct csio_q *)) * CSIO_FCOE_NUM_Q),
						CSIO_Q_ARR_MD 		},

	{ sizeof(struct csio_q), 		CSIO_Q_MD		},

	{ CSIO_FWEVT_FLBUFS * sizeof(struct csio_dma_buf),
						CSIO_FLB_FWEVT_MD 	},

	{ sizeof(struct csio_dma_buf),		CSIO_DDP_MD 		},

	{ sizeof(struct csio_ioreq),		CSIO_SCSIREQ_MD 	},

	{ sizeof(struct csio_ioreq),		CSIO_MGMTREQ_MD 	},
	{ sizeof(struct csio_evt_msg),		CSIO_EVTQ_MD 		},

	{ sizeof(struct csio_fcf_info), 	CSIO_FCOE_FCF_MD 	},

#ifdef __CSIO_TARGET__
	{ CSIO_TGT_FLLEN * sizeof(struct csio_dma_buf),
						CSIO_FLB_SCSI_MD 	},

	{ sizeof(struct csio_tgtreq),		CSIO_TGTREQ_MD 		},
#endif /* __CSIO_TARGET__ */
	/* The following must be the last entry */
	{ 		-1,				-1		},
};

static struct csio_alloc_desc csio_iscsi_alloc_descs[CSIO_MAX_MEM_DESCS] = {

	{ sizeof(struct csio_os_lnode),		CSIO_LN_MD		},

	{ sizeof(struct csio_os_rnode),		CSIO_RN_MD		},

#ifdef __CSIO_FOISCSI_ENABLED__	
	{ ((sizeof(struct csio_q *)) * CSIO_ISCSI_Q_NUM),
						CSIO_Q_ARR_MD	   	},
#endif

	{ sizeof(struct csio_q),		CSIO_Q_MD		},

	{ CSIO_FWEVT_FLBUFS * sizeof(struct csio_dma_buf),
						CSIO_FLB_FWEVT_MD 	},

	{ sizeof(struct csio_dma_buf),		CSIO_DDP_MD		},

	{ sizeof(struct csio_ioreq),		CSIO_SCSIREQ_MD		},

	{ sizeof(struct csio_evt_msg),		CSIO_EVTQ_MD		},
#ifdef __CSIO_FOISCSI_ENABLED__
	{ sizeof(struct foiscsi_cls_session),	CSIO_ISCSI_RSESS_MD	},
#endif

	/* The following must be the last entry */
	{ 		-1,				-1		},
};

/**
 * csio_resource_alloc - Allocate memory, DMA resources
 * @pdev: PCI device.
 *
 * THis routine creates linked lists of pre-allocated memory and places them in
 * the list heads (mem_descs) in the 'hw' structure. If the required allocation
 * size if less than 'csio_list', it is rounded up to sizeof(csio_list). This
 * allows every element to be on a free-list, where the first 2 entries of the
 * element are used as list identifiers (next, prev). Once the element is pulled
 * off a list during allocation, the caller is free to use the element as
 * desired. On a free, the element is treated as a list entry and added back to
 * the list.
 *
 */
static int
csio_resource_alloc(struct csio_os_hw *oshw)
{
	int rv = -ENOMEM;
	int i, n, asize;
	void *addr;
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_wrm *wrm = &hw->wrm;
	struct csio_alloc_desc *adesc = (csio_is_fcoe(hw))?
					&csio_fcoe_alloc_descs[0] :
					&csio_iscsi_alloc_descs[0];
	struct csio_list *mdesc;
	int num_alloc;

	/* First initialize all the pool heads */
	for (i = 0; i <	CSIO_MAX_MEM_DESCS; i++) {
		mdesc = &hw->mem_descs[i];
		csio_head_init(mdesc);
	}

	for (i = 0; i <	CSIO_MAX_MEM_DESCS; i++, adesc++) {
		if (adesc->alloc_size == -1)
			break;
		
		asize = adesc->alloc_size;

		/* Round up size to accomodate a csio_list entry */
		if (asize < sizeof(struct csio_list))
			asize = sizeof(struct csio_list);
		
		mdesc = &hw->mem_descs[adesc->idx];

		num_alloc = (csio_is_fcoe(hw)?
			     csio_fcoe_get_num_alloc(adesc->idx) :
#ifdef __CSIO_FOISCSI_ENABLED__
			     csio_iscsi_get_num_alloc(adesc->idx));
#else
			     0);
#endif
		if (num_alloc < 0) {
			csio_err(hw, "Failed to get allocation count"
					" for idx = %d\n", adesc->idx);
			goto err_free;
		}

		csio_dbg(hw, "Allocating %d elems of size %d at idx %d\n",
			  num_alloc, asize, adesc->idx);

		for (n = 0; n < num_alloc; n++) {
			addr = kzalloc(asize, GFP_KERNEL);
			if (!addr) {
				csio_err(hw, "Allocation of %d bytes failed! "
					"idx = %d\n", asize, adesc->idx);
				goto err_free;
			}	
			
			csio_enq_at_tail(mdesc, addr);
		} /* for number of allocations */
	} /* For all alloc_descs */
	
	wrm->num_q = (csio_is_fcoe(hw)? CSIO_FCOE_NUMQ :
#ifdef __CSIO_FOISCSI_ENABLED__
		       	CSIO_FOISCSI_NUMQ);
#else
			0);
#endif
	wrm->num_q += ((CSIO_MAX_SCSI_QSETS * 2) + CSIO_HW_NIQ +
		       CSIO_HW_NEQ + CSIO_HW_NFLQ + CSIO_HW_NINTXQ);

	csio_dbg(hw, "hw:%p wrm:%p\n", hw, wrm);
	return 0;

err_free:
	/* Free existing allocations */
	while (i--) {
		while (!csio_list_empty(mdesc)) {
			csio_deq_from_head(mdesc, &addr);
			kfree(addr);
		}
		adesc--;
		mdesc = &hw->mem_descs[adesc->idx];
	}
	return rv;
}

/**
 * csio_resource_free - Free DMA, memory resources
 * @pdev: PCI device.
 *
 */
static void
csio_resource_free(struct csio_os_hw *oshw)
{
	int i;
#ifdef __CSIO_DEBUG__
	int j = 0;
	int num_alloc;
#endif /* __CSIO_DEBUG__ */
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_alloc_desc *adesc = csio_is_fcoe(hw)?
					&csio_fcoe_alloc_descs[0] :
					&csio_iscsi_alloc_descs[0];
	struct csio_list *mdesc;
	void *addr;

	for (i = 0; i <	CSIO_MAX_MEM_DESCS; i++, adesc++) {

		if (adesc->alloc_size == -1)
			break;

		mdesc = &hw->mem_descs[adesc->idx];
#ifdef __CSIO_DEBUG__
		j = 0;
#endif /* __CSIO_DEBUG__ */
		while (!csio_list_empty(mdesc)) {
#ifdef __CSIO_DEBUG__
			j++;
#endif /* __CSIO_DEBUG__ */
			csio_deq_from_head(mdesc, &addr);
			kfree(addr);
		}
#ifdef __CSIO_DEBUG__
		num_alloc = (csio_is_fcoe(hw)?
			     csio_fcoe_get_num_alloc(adesc->idx) :
#ifdef __CSIO_FOISCSI_ENABLED__
			     csio_iscsi_get_num_alloc(adesc->idx));
#else
			     0);
#endif
		if (num_alloc != j) {
			csio_dbg(hw, "*** Memory leak detected at idx:%d "
				     "original cnt:%d freed:%d ***\n",
				     adesc->idx, num_alloc, j);
			CSIO_DB_ASSERT(0);
		}
		csio_dbg(hw, "Freed %d elems of size %d at idx %d\n",
			 j, adesc->alloc_size, adesc->idx);
#endif /* __CSIO_DEBUG__ */
	}

	return;
}

/*
 * csio_hw_init_workers - Initialize the HW module's worker threads.
 * @hw: HW module.
 *
 * Although the worker threads themselves are declared in the common
 * HW module, their initialization needs to happen here during the
 * OS specific initialization, in order to accomodate the requirements
 * of different OS's.
 */
static void
csio_hw_init_workers(struct csio_hw *hw)
{
	struct csio_os_hw *oshw = csio_hw_to_os(hw);

	csio_work_init(&hw->evtq_work, csio_evtq_worker, (void *)hw,
		       (void *)oshw, NULL);
#ifdef __CSIO_TARGET__
	csio_work_init(&csio_hw_to_tgtm(hw)->unreg_cleanup_work,
		       csio_tgtm_unreg_cleanup, (void *)hw, (void *)oshw, NULL);
#endif /* __CSIO_TARGET__ */
	
	return;
}

static void
csio_hw_exit_workers(struct csio_hw *hw)
{
	csio_work_cleanup(&hw->evtq_work);
#ifdef __CSIO_TARGET__
	csio_work_cleanup(&csio_hw_to_tgtm(hw)->unreg_cleanup_work);
#endif /* __CSIO_TARGET__ */
	flush_scheduled_work();

	return;
}

/*
 * csio_get_cdev_minor - Get the next available minor number
 */
static unsigned short
csio_get_cdev_minor(void)
{
	int minor;

	minor = find_first_zero_bit(csio_cdev_minors, sizeof(csio_cdev_minors));
	__set_bit(minor, csio_cdev_minors);
	return minor;
}

/*
 * csio_put_cdev_minor - release the given minor number.
 */
static void
csio_put_cdev_minor(unsigned short minor)
{
	__clear_bit(minor, csio_cdev_minors);
}

/*
 * csio_cdev_init - Initialize the character device.
 * @oshw: The HW instance.
 *
 * Get a an unused minor number, initialize the character device
 * for this oshw instance and create the device file for it.
 */
static int
csio_cdev_init(struct csio_os_hw *oshw)
{
	int minor, rv;
	struct device *dev;

	minor = csio_get_cdev_minor();
	cdev_init(&oshw->cdev, &csio_cdev_fops);
	oshw->cdev.owner = THIS_MODULE;

	rv = cdev_add(&oshw->cdev, MKDEV(csio_cdev_major, minor), 1);
	if (rv) {
		csio_put_cdev_minor(minor);
	} else {
		dev = device_create(csio_class, NULL,
				MKDEV(csio_cdev_major, minor),
				NULL, "csiostor%u", minor);
		if (IS_ERR(dev)) {
			rv = PTR_ERR(dev);
			csio_err(csio_oshw_to_hw(oshw),
				"failed to create devfile: %d\n", rv);
			csio_put_cdev_minor(minor);
			cdev_del(&oshw->cdev);
			return rv;
		}
	}

	return rv;
}

/*
 * csio_cdev_exit - Cleanup the character device.
 *
 */
static void
csio_cdev_exit(struct csio_os_hw *oshw)
{
	csio_put_cdev_minor(MINOR(oshw->cdev.dev));
	device_destroy(csio_class, MKDEV(csio_cdev_major,
		       MINOR(oshw->cdev.dev)));
	cdev_del(&oshw->cdev);
}

static csio_retval_t
csio_create_queues(struct csio_hw *hw)
{
	int i, j;
	struct csio_os_hw *oshw = csio_hw_to_os(hw);
	struct csio_mgmtm *mgmtm = csio_hw_to_mgmtm(hw);
	enum csio_oss_error rv;
	struct csio_scsi_cpu_info *info;

	if (hw->flags & CSIO_HWF_Q_FW_ALLOCED)
		return CSIO_SUCCESS;

	if (hw->intr_mode != CSIO_IM_MSIX) {

		csio_dbg(hw, "Configuring Forward Interrupt IQ...\n");
		
		rv = csio_wr_iq_create(hw, hw->intr_iq_idx,
					0, hw->t4port[0].portid,
					CSIO_FALSE);
		if (rv != CSIO_SUCCESS) {
			csio_err(hw, " Forward Interrupt IQ failed!: %d\n", rv);
			return rv;
		}
	}
		
	/* FW event queue */
	rv = csio_wr_iq_create(hw, hw->fwevt_iq_idx,
			       csio_get_fwevt_intr_idx(hw),
			       hw->t4port[0].portid, CSIO_TRUE);
	if (rv != CSIO_SUCCESS) {
		csio_err(hw, "FW event IQ config failed!: %d\n", rv);
		return rv;
	}

	/* Create mgmt queue */
	rv = csio_wr_eq_create(hw, mgmtm->eq_idx, mgmtm->iq_idx,
			hw->t4port[0].portid);

	if (rv != CSIO_SUCCESS) {
		csio_err(hw, "Mgmt EQ create failed!: %d\n", rv);
		goto err;
	}

	/* Create SCSI queues */
	for (i = 0; i < hw->num_t4ports; i++) {
		info = &oshw->scsi_cpu_info[i];

		for (j = 0; j < info->max_cpus; j++) {
			struct csio_scsi_qset *sqset = &oshw->sqset[i][j];

			rv = csio_wr_iq_create(hw, sqset->iq_idx,
					       sqset->intr_idx, i,
					       CSIO_FALSE);
			if (rv != CSIO_SUCCESS) {
				csio_err(hw, "SCSI module IQ config failed"
					    "[%d][%d]:%d\n", i, j, rv);
				goto err;
			}
			rv = csio_wr_eq_create(hw, sqset->eq_idx,
					sqset->iq_idx, i);
			if (rv != CSIO_SUCCESS) {
				csio_err(hw, "SCSI module EQ config failed"
					    "[%d][%d]:%d\n", i, j, rv);
				goto err;
			}
		} /* for all CPUs */
	} /* For all ports */

	hw->flags |= CSIO_HWF_Q_FW_ALLOCED;
	return CSIO_SUCCESS;
err:
	csio_wr_destroy_queues(hw, CSIO_TRUE);
	return CSIO_INVAL;
}

/*
 * csio_config_queues - Configure the DMA queues.
 * @hw: HW module.
 *
 * Allocates memory for queues are registers them with FW.
 */
static csio_retval_t
csio_config_queues(struct csio_hw *hw)
{
	int i, j, idx, k = 0;
	struct csio_os_hw *oshw = csio_hw_to_os(hw);
	enum csio_oss_error rv;
	struct csio_scsi_qset *sqset;
	struct csio_mgmtm *mgmtm = csio_hw_to_mgmtm(hw);
	struct csio_scsi_qset *orig;
	struct csio_scsi_cpu_info *info;

	if (hw->flags & CSIO_HWF_Q_MEM_ALLOCED)
		return csio_create_queues(hw);		

	/* Calculate number of SCSI queues for MSIX we would like */
	oshw->num_scsi_msix_cpus = num_online_cpus();
	oshw->num_sqsets = num_online_cpus() * hw->num_t4ports;
	
	if (oshw->num_sqsets > CSIO_MAX_SCSI_QSETS) {
		oshw->num_sqsets = CSIO_MAX_SCSI_QSETS;
		oshw->num_scsi_msix_cpus = CSIO_MAX_SCSI_CPU;
	}

	/* Initialize max_cpus, may get reduced during msix allocations */
	for (i = 0; i < hw->num_t4ports; i++)
		oshw->scsi_cpu_info[i].max_cpus = oshw->num_scsi_msix_cpus;

	csio_dbg(hw, "nsqsets:%d scpus:%d\n",
		    oshw->num_sqsets, oshw->num_scsi_msix_cpus);

	csio_intr_enable(oshw);

	if (hw->intr_mode != CSIO_IM_MSIX) {

		/* Allocate Forward interrupt iq. */
		hw->intr_iq_idx = csio_wr_alloc_q(hw, CSIO_INTR_IQSIZE,
						CSIO_INTR_WRSIZE,
						CSIO_INGRESS, (void *)hw, 0, 0,
						0, NULL);
		if (hw->intr_iq_idx == -1) {
			csio_err(hw, "Forward interrupt queue creation "
				    "failed\n");
			goto intr_disable;
		}		
	}

	/* Allocate the FW evt queue */
	hw->fwevt_iq_idx = csio_wr_alloc_q(hw, CSIO_FWEVT_IQSIZE,
					   CSIO_FWEVT_WRSIZE,
					   CSIO_INGRESS, (void *)hw,
					   CSIO_FWEVT_FLBUFS, 0,
					   CSIO_FLB_FWEVT_MD,
					   csio_os_fwevt_intx_handler);
	if (hw->fwevt_iq_idx == -1) {
		csio_err(hw, "FW evt queue creation failed\n");
		goto intr_disable;
	}

	/* Allocate the mgmt queue */
	mgmtm->eq_idx = csio_wr_alloc_q(hw, CSIO_MGMT_EQSIZE,
				      CSIO_MGMT_EQ_WRSIZE,
				      CSIO_EGRESS, (void *)hw, 0, 0, 0, NULL);
	if (mgmtm->eq_idx == -1) {
		csio_err(hw, "Failed to alloc Egress queue"
			    "for FCoE Mgmt module\n");
		goto intr_disable;
	}
	
	/* Use FW IQ for MGMT req completion */
	mgmtm->iq_idx = hw->fwevt_iq_idx;

	/* Allocate SCSI queues */
	for (i = 0; i < hw->num_t4ports; i++) {
		info = &oshw->scsi_cpu_info[i];

		for (j = 0; j < oshw->num_scsi_msix_cpus; j++) {
			sqset = &oshw->sqset[i][j];

			if (j >= info->max_cpus) {
				k = j % info->max_cpus;
				orig = &oshw->sqset[i][k];

				sqset->eq_idx = orig->eq_idx;
				sqset->iq_idx = orig->iq_idx;

				csio_dbg(hw,
	    			    "sqset[%d][%d]->int:%d iq:%d eq:%d\n",
				    i, j, sqset->intr_idx,
				    sqset->iq_idx, sqset->eq_idx);

				continue;
			}

			idx = csio_wr_alloc_q(hw, csio_scsi_eqsize, 0,
					      CSIO_EGRESS, (void *)hw, 0, 0,
					      0, NULL);
			if (idx == -1) {
				csio_err(hw, "EQ creation failed for idx:%d\n",
					    idx);
				goto intr_disable;
			}
			sqset->eq_idx = idx;

#ifdef __CSIO_TARGET__
			idx = csio_wr_alloc_q(hw, CSIO_SCSI_IQSIZE,
					     CSIO_SCSI_IQ_WRSZ, CSIO_INGRESS,
					     (void *)hw, CSIO_TGT_FLLEN, 0,
					     CSIO_FLB_SCSI_MD,
					     csio_os_scsi_intx_handler);
#else
			idx = csio_wr_alloc_q(hw, CSIO_SCSI_IQSIZE,
					     CSIO_SCSI_IQ_WRSZ, CSIO_INGRESS,
					     (void *)hw, 0, 0, 0,
					     csio_os_scsi_intx_handler);
#endif /* __CSIO_TARGET__ */
			if (idx == -1) {
				csio_err(hw, "IQ creation failed for idx:%d\n",
					    idx);
				goto intr_disable;
			}
			sqset->iq_idx = idx;

			csio_dbg(hw, "sqset[%d][%d]->int:%d iq:%d eq:%d\n",
				    i, j, sqset->intr_idx,
				    sqset->iq_idx, sqset->eq_idx);
		} /* for all CPUs */
	} /* For all ports */

	hw->flags |= CSIO_HWF_Q_MEM_ALLOCED;

	rv = csio_create_queues(hw);
	if (rv != CSIO_SUCCESS)
		goto intr_disable;

	/*
	 * Now request IRQs for the vectors. In the event of a failure,
	 * cleanup is handled internally by this function.
	 */
	rv = csio_request_irqs(oshw);
	if (rv != CSIO_SUCCESS)
		return CSIO_INVAL;
	
	return CSIO_SUCCESS;

intr_disable:
	csio_intr_disable(oshw, CSIO_FALSE);

	return CSIO_INVAL;
}

#ifdef __CSIO_TARGET__

static void
csio_tgtm_unreg_cleanup(void *data)
{
	struct csio_hw *hw = (struct csio_hw *)data;
	struct csio_tgtm *tgtm = csio_hw_to_tgtm(hw);
	struct csio_list *tmp, *next;
	struct csio_tgtreq *tgtreq;
	int count = CSIO_ROUNDUP(5 * 1000, CSIO_TGTQ_POLL_MS);

	csio_spin_lock_irq(hw, &hw->lock);

	if (csio_list_empty(&tgtm->drain_q)) {
		csio_spin_unlock_irq(hw, &hw->lock);
		return;
	}

	/* There could be another worker cleaning up I/Os, just return */
	if (!csio_list_empty(&tgtm->unreg_cleanup_q)){
		csio_dbg(hw, "Another worker cleaning up, returning..\n");
		csio_spin_unlock_irq(hw, &hw->lock);
		return;
	}

	/* Wait until I/Os complete */
	csio_dbg(hw, "Worker waiting max %d secs for I/Os to drain out\n",
		 count * (CSIO_TGTQ_POLL_MS / 1000));
	while (!csio_list_empty(&tgtm->drain_q) && count--) {
		csio_spin_unlock_irq(hw, &hw->lock);
		csio_msleep(CSIO_TGTQ_POLL_MS);
		csio_spin_lock_irq(hw, &hw->lock);
	}

	if (csio_list_empty(&tgtm->drain_q)) {
		csio_spin_unlock_irq(hw, &hw->lock);
		return;
	}

	csio_dbg(hw, "Worker trying to clean up I/Os..\n");

	/*
	 * Pull only those I/Os that SAL is waiting for into unreg_cleanup_q.
	 * Use  tgtreq->unreg_list to enqueue these I/Os, so that the regular
	 * path continues to use tgtreq->list. We cannot use the latter, as
	 * we drop the lock when we call sal_cmd_done in the following loop,
	 * and there is a chance an I/O completed by FW ends up pulling this
	 * I/Os out of the list.
	 */
	csio_list_for_each_safe(tmp, next, &tgtm->drain_q) {
		tgtreq = (struct csio_tgtreq *)tmp;
		
		if (csio_tgt_unreg_req_needs_done(tgtreq))
			csio_enq_at_tail(&tgtm->unreg_cleanup_q,
					 &tgtreq->unreg_list);
	}

	/*
	 * Now walk the unreg_cleanup_q and return these I/Os to SAL.
	 */
	csio_list_for_each_safe(tmp, next, &tgtm->unreg_cleanup_q) {
		tgtreq = container_of(tmp, struct csio_tgtreq, unreg_list);

		csio_deq_elem(&tgtreq->unreg_list);

		/*
 		 * This means FW has not returned I/Os for a significant amount
 		 * of time, after the session itself is non-existent. We now
 		 * need to dequeue this tgtreq outta the unreg_cleanup_q,
 		 * clean up FW's reference to this tgtreq, and  return this
 		 * I/O to SAL.
 		 */
		if (csio_tgt_unreg_req_needs_done(tgtreq)) {
			CSIO_DB_ASSERT(csio_treq_fw_has_ref(tgtreq));
			csio_tgt_sal_cmd_err(hw, tgtreq);
		} else {
			/* Allow others to run */
			csio_spin_unlock_irq(hw, &hw->lock);
			csio_spin_lock_irq(hw, &hw->lock);
		}
	}

	csio_spin_unlock_irq(hw, &hw->lock);
}

static csio_retval_t
csio_os_start_stop_tgt(void *drv_dev, bool start)
{
	struct csio_os_hw *oshw = (struct csio_os_hw *)drv_dev;
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_list *cur_ln, *next_ln;
	struct csio_lnode *sln = NULL;
	enum csio_oss_error rv = CSIO_SUCCESS;
	struct csio_lnode_fcoe *lnf;

	/* Start/stop only target mode functions */
	if (!csio_target_mode(hw)) {
		csio_dbg(hw, "devid 0x%x is not a target\n",
			 oshw->pdev->device);
		return CSIO_INVAL;
	}

	if (start) {
		/* Traverse sibling lnodes */
		csio_list_for_each_safe(cur_ln, next_ln, &hw->sln_head) {
			sln = (struct csio_lnode *)cur_ln;

			csio_spin_lock_irq(hw, &hw->lock);

			if (csio_is_fcoe(hw)) {
				if (csio_lnf_start(csio_lnode_to_fcoe(sln)) !=
								CSIO_SUCCESS)
					rv = CSIO_INVAL;
			} else {
#ifdef __CSIO_FOISCSI_ENABLED__
				if (csio_lni_start(csio_lnode_to_iscsi(sln)) !=
								CSIO_SUCCESS)
					rv = CSIO_INVAL;
#endif
			}
		
			csio_spin_unlock_irq(hw, &hw->lock);
			if (rv)
				break;
		}
	} else {
		/*
		 * If target mode is being disabled, disable initiator mode as
		 * well by bringing link down, stopping hardware, and
		 * preparing for a removal of the entire driver. Removing
		 * target mode alone on the fly, and retaining initiator mode
		 * is very complex. If a user wants to change mode, the driver
		 * is unloaded and re-loaded back with the new mode.
		 */
		if (csio_initiator_mode(hw))
			csio_oslnodes_block_request(oshw);

		/* Stop all activity from the wire by bringing the link down */
		csio_list_for_each_safe(cur_ln, next_ln, &hw->sln_head) {
			sln = (struct csio_lnode *)cur_ln;

			csio_spin_lock_irq(hw, &hw->lock);
			if (csio_is_fcoe(hw)) {
				lnf = csio_lnode_to_fcoe(sln);
				if (csio_is_phys_lnf(lnf) &&
					(lnf->flags &
						CSIO_LNFFLAG_LINK_ENABLE)) {
					csio_fcoe_enable_link(lnf, 0);
					lnf->flags &= ~CSIO_LNFFLAG_LINK_ENABLE;
				}
			}
# if 0
			else {
				csio_lni_stop(csio_lnode_to_iscsi(sln));
			}
#endif
			csio_spin_unlock_irq(hw, &hw->lock);
		}

		/* Now stop the hardware */
		csio_spin_lock_irq(hw, &hw->lock);
		csio_hw_stop(hw);
		csio_spin_unlock_irq(hw, &hw->lock);

		/*
		 * Wait for all unregistration cleanup workers to completely
		 * exit at this point. All I/Os in the target module also
		 * better cleanup at this point.
		 */
		flush_scheduled_work();

		/* If there are any more of them left, clean them up now */
		csio_spin_lock_irq(hw, &hw->lock);
		csio_tgtm_cleanup(csio_hw_to_tgtm(hw));
		csio_spin_unlock_irq(hw, &hw->lock);
	}

	return rv;
}

/*
 * csio_tgt_assign_queues - Assign egress and ingress queues to the rnode.
 * @rn: remote node.
 *
 * The logic here is to round-robin the incoming rnodes based on
 * CPU. Since we maintain queue sets per-port per-CPU, the last
 * used queue-set index is maintained per-port. Every successive
 * remote node logging into our card on a port gets a queue-set
 * bound to the next available CPU.
 * NOTE: This is called with lock held.
 */
static void
csio_tgt_assign_queues(struct csio_rnode *rn)
{
	struct csio_lnode *ln = csio_rnode_to_lnode(rn);
	struct csio_hw *hw = csio_lnode_to_hw(ln);
	struct csio_os_hw *oshw = csio_hw_to_os(hw);
	struct csio_scsi_qset *sqset;
	struct csio_scsi_cpu_info *info = &oshw->scsi_cpu_info[ln->portid];
	
	sqset = &oshw->sqset[ln->portid][info->cur_iq_cpu];

	rn->eq_idx = sqset->eq_idx;
	rn->iq_idx = sqset->iq_idx;

	csio_dbg(hw, "Assigned idx:%d iqid:%d to rn:%p cpu:%d port:%d\n",
		     sqset->iq_idx, csio_q_physiqid(hw, sqset->iq_idx), rn,
		     info->cur_iq_cpu, ln->portid);

	info->cur_iq_cpu = (++info->cur_iq_cpu % info->max_cpus);
	
}
#endif /* __CSIO_TARGET__ */

/* OS callbacks from common layer for the HW */
static struct csio_hw_os_ops fcoe_os_ops = {
	.os_alloc_lnode 	= csio_oslnode_alloc,
	.os_config_queues	= csio_config_queues,
	.os_alloc_rnode 	= csio_alloc_rnode,
	.os_free_rnode 		= csio_free_rnode,
	.os_ln_async_event	= csio_lnf_async_event,
	.os_ln_block_reqs	= csio_ln_block_reqs,
	.os_ln_unblock_reqs	= csio_ln_unblock_reqs,
	.os_rn_reg_rnode	= csio_rnf_reg_rnode,
	.os_rn_unreg_rnode	= csio_rnf_unreg_rnode,
	.os_rn_async_event	= csio_rnf_async_event,
	.os_abrt_cls		= csio_os_abort_cls,
	.os_flash_fw		= csio_os_flash_fw,
	.os_flash_config	= csio_os_flash_config,
	.os_flash_hw_phy	= csio_os_flash_phy_fw,
#ifdef __CSIO_TARGET__
	.os_tgt_assign_queues	= csio_tgt_assign_queues,
#endif /* __CSIO_TARGET__ */
};

/* OS callbacks from common layer for the HW */
static struct csio_hw_os_ops iscsi_os_ops = {
	.os_alloc_lnode 	= csio_oslnode_alloc,
	.os_config_queues	= csio_config_queues,
	.os_alloc_rnode 	= csio_alloc_rnode,
	.os_free_rnode 		= csio_free_rnode,
	.os_ln_async_event	= NULL,
	.os_ln_block_reqs	= csio_ln_block_reqs,
	.os_ln_unblock_reqs	= csio_ln_unblock_reqs,
#ifdef __CSIO_FOISCSI_ENABLED__	
	.os_rn_reg_rnode	= csio_rni_reg_rnode,
	.os_rn_unreg_rnode	= csio_rni_unreg_rnode,
#endif
	.os_rn_async_event	= NULL,
	.os_abrt_cls		= csio_os_abort_cls,
	.os_flash_fw 		= csio_os_flash_fw,
	.os_flash_config	= csio_os_flash_config,
	.os_flash_hw_phy	= csio_os_flash_phy_fw,
#ifdef __CSIO_TARGET__
	.os_tgt_assign_queues	= csio_tgt_assign_queues,
#endif /* __CSIO_TARGET__ */
};

/**
 * csio_oshw_start - Start the HW module
 * @oshw: The HW module
 *
 * Kick off the HW state machine.
 */
static int
csio_oshw_start(struct csio_os_hw *oshw)
{
	struct csio_hw *hw = csio_oshw_to_hw(oshw);

	return csio_hw_start(hw);
}

static int csio_proto_supported(struct pci_dev *pdev)
{
	u8 csio_fn = -1;
	switch (pdev->device) {
	case CH_PCI_FN_MASK(PF_FPGA, 0xa000):
	case CH_PCI_FN_MASK(PF_FPGA, 0xa001):
	case CH_PCI_FN_MASK(PF_FPGA, 0xb000):
	case CH_PCI_FN_MASK(PF_FPGA, 0xb001):
		csio_fn = FN_FCOE;
		break;

	case CH_PCI_FN_MASK(PF_FPGA, 0xa002):
	case CH_PCI_FN_MASK(T6_PF_FPGA, 0xc006):
		csio_fn = FN_ISCSI;
		break;
	default:
		if (CHECK_PF_MASK(PF_FCOE, pdev->device))
			csio_fn = FN_FCOE;
		else if (CHECK_PF_MASK(PF_ISCSI,pdev->device))
			csio_fn = FN_ISCSI;
	}

	if (csio_fn == csio_proto)
		return 1;
	else
		return 0;
}

static int csio_adap_init(struct csio_os_hw *oshw)
{
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	adapter_t *adap = &hw->adap;

	adap->pdev_dev = &oshw->pdev->dev;
	adap->msg_enable = csio_dflt_msg_enable;
	adap->params.drv_memwin = csio_is_fcoe(hw) ? MEMWIN_CSIOSTOR : MEMWIN_FOISCSI;
	t4_os_lock_init(&adap->mbox_lock);
	INIT_LIST_HEAD(&adap->mbox_list.list);
	spin_lock_init(&adap->win0_lock);
	spin_lock_init(&adap->stats_lock);

	adap->mbox_log = kzalloc(sizeof(struct mbox_cmd_log) +
				 (sizeof(struct mbox_cmd) *
				 T4_OS_LOG_MBOX_CMDS),
				 GFP_KERNEL);
	if (!adap->mbox_log)
		return -ENOMEM;

	adap->mbox_log->size = T4_OS_LOG_MBOX_CMDS;

	return 0;
}

static void csio_adap_exit(struct csio_os_hw *oshw)
{
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	adapter_t *adap = &hw->adap;

	kfree(adap->mbox_log);
}

/**
 * csio_oshw_init - Initialize the HW module.
 * @pdev: PCI device.
 *
 * Allocates HW structure, DMA, memory resources, maps BARS to
 * host memory and initializes HW module.
 */
static struct csio_os_hw * __devinit
csio_oshw_init(struct pci_dev *pdev)
{
	struct csio_os_hw *oshw;
	struct csio_hw *hw;
	struct adapter *adap;
#ifdef __CSIO_TARGET__
	int i;
#endif /* __CSIO_TARGET__ */

	oshw = kzalloc(sizeof(struct csio_os_hw), GFP_KERNEL);
	if (!oshw)
		goto err;
	oshw->pdev = pdev;

	/* Link common hw to this hw */
	hw = csio_oshw_to_hw(oshw);
	csio_hw_to_os(hw) = oshw;
	csio_hw_to_osdev(oshw) = (void *)oshw->pdev;

	adap = &(hw->adap);
	/* Link OS trace-buffer to common hw */
	hw->trace_buf = &oshw->trace_buf;
#ifdef CSIO_DATA_CAPTURE	
	hw->dcap_buf  = &oshw->dcap_buf;
#endif	

	strncpy(hw->drv_version, CSIO_DRV_VERSION, sizeof(hw->drv_version) - 1);
	switch (pdev->device) {
		case CH_PCI_FN_MASK(PF_FPGA,0xa000):
		case CH_PCI_FN_MASK(PF_FPGA,0xa001):
		case CH_PCI_FN_MASK(PF_FPGA,0xb000):
		case CH_PCI_FN_MASK(PF_FPGA,0xb001):
			hw->os_flags |= CSIO_HWOSF_FN_FCOE;
			break;

		case CH_PCI_FN_MASK(PF_FPGA ,0xa002):
		case CH_PCI_FN_MASK(T6_PF_FPGA, 0xc006):
			hw->os_flags &= ~CSIO_HWOSF_FN_FCOE;
			break;
		default:
			if (CHECK_PF_MASK(PF_FCOE, pdev->device))
				hw->os_flags |= CSIO_HWOSF_FN_FCOE;
			else if (CHECK_PF_MASK(PF_ISCSI,pdev->device))
				hw->os_flags &= ~CSIO_HWOSF_FN_FCOE;
	}

	/* Needed for adap based resource allocation ahead of csio_adap_init() */
	adap->pdev = oshw->pdev;
	/* memory/memory pool/DMA allocation */
	if (csio_resource_alloc(oshw))
		goto err_free_hw;

	/* Get the start address of registers from BAR 0 */
	adap->regs = pci_ioremap_bar(pdev, 0);

	if (!(adap->regs)) {
		csio_err(hw, "Could not map BAR 0, regstart = %p\n",
			adap->regs);
		goto err_resource_free;
	}

	csio_hw_init_workers(hw);
	if (csio_hw_init(hw, csio_is_fcoe(hw)? &fcoe_os_ops: &iscsi_os_ops))
		goto err_unmap_bar0;

	if (!is_t4(adap->params.chip)) {
		adap->bar2 = ioremap_wc(pci_resource_start(pdev, 2),
						pci_resource_len(pdev, 2));
		if (!adap->bar2) {
			csio_err(hw, "Cannot map device bar2 region\n");
			goto err_unmap_bar0;
		}
	}

	if (csio_adap_init(oshw))
		goto err_adap_exit;

#ifdef __CSIO_TARGET__
	csio_hw_get_scsi_mode(hw);
	for (i = 0; i < CSIO_MAX_T4PORTS; i++)
		oshw->scsi_cpu_info[i].cur_iq_cpu = 0;
#endif /* __CSIO_TARGET__ */

	csio_osdfs_create(oshw);

	if (csio_cdev_init(oshw))
		goto err_hw_exit;

	return oshw;

err_hw_exit:
	csio_osdfs_destroy(oshw);
	csio_hw_exit(hw);

err_adap_exit:
	csio_adap_exit(oshw);

	/* Unmap BAR 2 if it is T5 */
	if (!is_t4(adap->params.chip))
		iounmap(adap->bar2);
err_unmap_bar0:
	csio_hw_exit_workers(hw);
	iounmap(hw->adap.regs);	
err_resource_free:
	csio_resource_free(oshw);
err_free_hw:
	kfree(oshw);
err:
	return NULL;
}

/**
 * csio_oshw_exit - Uninitialize the HW module.
 * @oshw: The HW module
 *
 * Disable interrupts, uninit the HW module, free resources.
 */
static void
csio_oshw_exit(struct csio_os_hw *oshw)
{
	csio_cdev_exit(oshw);
	csio_intr_disable(oshw, CSIO_TRUE);
	csio_hw_exit_workers(csio_oshw_to_hw(oshw));
	csio_hw_exit(csio_oshw_to_hw(oshw));
	csio_adap_exit(oshw);
	if (!is_t4(csio_oshw_to_adap(oshw)->params.chip))
		iounmap(csio_oshw_to_adap(oshw)->bar2);
	iounmap(csio_oshw_to_adap(oshw)->regs);
	csio_osdfs_destroy(oshw);
	csio_resource_free(oshw);
	kfree(oshw);
}

/*
 * csio_oshw_regs_init - Initialize card registers based on OS requirement.
 * @oshw: HW module.
 *
 */
static void
csio_oshw_regs_init(struct csio_os_hw *oshw)
{
	struct csio_hw *hw = csio_oshw_to_hw(oshw);

	/*
	 * NOTE: csiostor as master needs to clear this bit for cxgb4 to work
	 * correctly. This is a Linux-only requirement as of now.
	 * Comment from cxgb4:
	 * "Don't include the "IP Pseudo Header" in CPL_RX_PKT checksums: Linux
	 * adds the pseudo header itself."
	 */
	if (csio_is_hw_master(hw))
		t4_tp_wr_bits_indirect(&hw->adap, A_TP_INGRESS_CONFIG,
				       F_CSUM_HAS_PSEUDO_HDR, 0);

}

/**
 * csio_oslnode_init - Create and initialize the lnode module.
 * @oshw: The HW module
 * @dev: Device
 * @probe: Called from probe context or not?
 * @os_pln: Parent lnode if any.
 *
 * Allocates lnode structure via scsi_host_alloc, initializes
 * shost, initializes lnode module and registers with SCSI ML
 * via scsi_host_add. Wherever applicable, the FCoE/iSCSI switch
 * is applied.  In the case of FCoE, this function is shared
 * between physical and virtual node ports.
 */
struct csio_os_lnode *
csio_oslnode_init(struct csio_os_hw *oshw, struct device *dev,
		  bool probe, struct csio_os_lnode *os_pln)
{
	struct Scsi_Host  *shost = NULL;
	struct csio_os_lnode *osln;
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_lnode *pln = NULL;

	if (csio_is_fcoe(hw)) {
		if (csio_lun_qdepth > CSIO_MAX_CMD_PER_LUN) {
			csio_fcoe_shost_template.cmd_per_lun = csio_lun_qdepth;
			csio_fcoe_shost_vport_template.cmd_per_lun =
								csio_lun_qdepth;
		}

		/*
		 * oshw->pdev is the physical port's PCI dev structure,
		 * which will be different from the NPIV dev structure.
		 */
		if (dev == &oshw->pdev->dev)
			shost = scsi_host_alloc(
					&csio_fcoe_shost_template,
					sizeof(struct csio_os_lnode));
		else
			shost = scsi_host_alloc(
					&csio_fcoe_shost_vport_template,
					sizeof(struct csio_os_lnode));
	} else {	
		if (csio_lun_qdepth > CSIO_MAX_CMD_PER_LUN) {
			csio_iscsi_shost_template.cmd_per_lun = csio_lun_qdepth;
		}

		shost = scsi_host_alloc(
				&csio_iscsi_shost_template,
				sizeof(struct csio_os_lnode));
	}

	if (!shost)
		goto err;

	osln = shost_priv(shost);
	memset(osln, 0, sizeof(struct csio_os_lnode));

	/* Link common lnode to this lnode */
	csio_lnode_to_os(csio_osln_to_ln(osln)) = osln;
	csio_osln_to_ln(osln)->dev_num = (shost->host_no << 16); 	

	shost->can_queue = CSIO_MAX_QUEUE;
	shost->this_id = -1;
	shost->unique_id = shost->host_no;
	shost->max_cmd_len = 16; /* Max CDB length supported */
		
	if (csio_is_fcoe(hw)) {
		shost->max_id = csio_fcoe_rnodes;
		shost->max_lun = CSIO_MAX_LUN;
		if (dev == &oshw->pdev->dev) {
			shost->transportt = csio_fcoe_transport;
		} else {
			shost->transportt = csio_fcoe_transport_vport;
		}

	} else {
		shost->max_lun = CSIO_MAX_LUN;
	}

	/* root lnode */
	if (!hw->rln)
		hw->rln = csio_osln_to_ln(osln);
	
	if (os_pln)
		pln = csio_osln_to_ln(os_pln);

	/* Other initialization here: Common, Transport specific */
	if (csio_lnode_init(csio_osln_to_ln(osln), hw, pln))
		goto err_shost_put;
	
	if (scsi_add_host_with_dma(shost, dev, &oshw->pdev->dev))
		goto err_lnode_exit;

	return osln;

err_lnode_exit:
	csio_lnode_exit(csio_osln_to_ln(osln));
err_shost_put:
	scsi_host_put(shost);
err:
	return NULL;
}

/**
 * csio_oslnode_exit - Inform upper layers of lnode de-instantiation.
 * @osln: The lnode module
 *
 */
void
csio_oslnode_exit(struct csio_os_lnode *osln)
{
	struct Scsi_Host  *shost = csio_osln_to_shost(osln);
	struct csio_os_hw *oshw = csio_osln_to_oshw(osln);
	struct csio_hw *hw = csio_oshw_to_hw(oshw);

	/* Inform transport */
	if (csio_is_fcoe(csio_oshw_to_hw(oshw)))
		fc_remove_host(shost);

	/* Inform SCSI ML */
	scsi_remove_host(shost);

	/* Flush all the events, so that any rnode removal events
	 * already queued are all handled, before we remove the lnode.
	 */
	csio_spin_lock_irq(hw, &hw->lock);
	csio_evtq_flush(hw);
	csio_spin_unlock_irq(hw, &hw->lock);

	csio_lnode_exit(csio_osln_to_ln(osln));
	scsi_host_put(shost);

	return;
}

static struct csio_lnode *
csio_oslnode_alloc(struct csio_hw *hw)
{
	struct csio_os_hw *oshw = csio_hw_to_os(hw);
	struct csio_os_lnode *osln = NULL;
	struct csio_lnode *ln = NULL;

	osln = csio_oslnode_init(oshw, &oshw->pdev->dev, CSIO_FALSE, NULL);
	if (osln)
		ln = csio_osln_to_ln(osln);
	
	return ln;
}

void
csio_oslnodes_block_request(struct csio_os_hw *oshw)
{
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_os_lnode *osln;
	struct Scsi_Host  *shost;
	struct csio_lnode *sln;
	struct csio_list *cur_ln, *cur_cln;
	struct csio_lnode **lnode_list;
	int cur_cnt = 0, ii;
	
	lnode_list = kzalloc((sizeof(struct csio_lnode *) * hw->num_lns),
			GFP_KERNEL);
	if (!lnode_list) {
		csio_err(hw, "Failed to allocate lnodes_list");
		return;
	}	

	csio_spin_lock_irq(hw, &hw->lock);
	/* Traverse sibling lnodes */
	csio_list_for_each(cur_ln, &hw->sln_head) {
		sln = (struct csio_lnode *) cur_ln;
		lnode_list[cur_cnt++] = sln;
		
		/* Traverse children lnodes */
		csio_list_for_each(cur_cln, &sln->cln_head) {
			lnode_list[cur_cnt++] = (struct csio_lnode *) cur_cln;

		}
	}
	csio_spin_unlock_irq(hw, &hw->lock);

	for (ii = 0; ii < cur_cnt; ii++) {
		csio_dbg(hw, "Blocking IOs on lnode: %p\n", lnode_list[ii]);
		osln = csio_lnode_to_os(lnode_list[ii]);
		shost = csio_osln_to_shost(osln);
		scsi_block_requests(shost);	

	}
	kfree(lnode_list);
}

void
csio_oslnodes_unblock_request(struct csio_os_hw *oshw)
{
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_os_lnode *osln;
	struct Scsi_Host  *shost;
	struct csio_lnode *sln;
	struct csio_list *cur_ln, *cur_cln;
	struct csio_lnode **lnode_list;
	int cur_cnt = 0, ii;
	
	lnode_list = kzalloc((sizeof(struct csio_lnode *) * hw->num_lns),
			GFP_KERNEL);
	if (!lnode_list) {
		csio_err(hw, "Failed to allocate lnodes_list");
		return;
	}	

	csio_spin_lock_irq(hw, &hw->lock);
	/* Traverse sibling lnodes */
	csio_list_for_each(cur_ln, &hw->sln_head) {
		sln = (struct csio_lnode *) cur_ln;
		lnode_list[cur_cnt++] = sln;
		
		/* Traverse children lnodes */
		csio_list_for_each(cur_cln, &sln->cln_head) {
			lnode_list[cur_cnt++] = (struct csio_lnode *) cur_cln;

		}
	}
	csio_spin_unlock_irq(hw, &hw->lock);

	for (ii = 0; ii < cur_cnt; ii++) {
		csio_dbg(hw, "unblocking IOs on lnode: %p\n", lnode_list[ii]);
		osln = csio_lnode_to_os(lnode_list[ii]);
		shost = csio_osln_to_shost(osln);
		scsi_unblock_requests(shost);
	}
	kfree(lnode_list);
}

void
csio_oslnodes_block_by_port(struct csio_os_hw *oshw, uint8_t portid)
{
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_os_lnode *osln;
	struct Scsi_Host  *shost;
	struct csio_lnode *sln;
	struct csio_list *cur_ln, *cur_cln;
	struct csio_lnode **lnode_list;
	int cur_cnt = 0, ii;
	
	lnode_list = kzalloc((sizeof(struct csio_lnode *) * hw->num_lns),
			GFP_KERNEL);
	if (!lnode_list) {
		csio_err(hw, "Failed to allocate lnodes_list");
		return;
	}	

	csio_spin_lock_irq(hw, &hw->lock);
	/* Traverse sibling lnodes */
	csio_list_for_each(cur_ln, &hw->sln_head) {
		sln = (struct csio_lnode *) cur_ln;
		if (sln->portid != portid)
			continue;
		
		lnode_list[cur_cnt++] = sln;
		
		/* Traverse children lnodes */
		csio_list_for_each(cur_cln, &sln->cln_head) {
			lnode_list[cur_cnt++] = (struct csio_lnode *) cur_cln;

		}
	}
	csio_spin_unlock_irq(hw, &hw->lock);

	for (ii = 0; ii < cur_cnt; ii++) {
		csio_dbg(hw, "Blocking IOs on lnode: %p\n", lnode_list[ii]);
		osln = csio_lnode_to_os(lnode_list[ii]);
		shost = csio_osln_to_shost(osln);
		scsi_block_requests(shost);	
	}
	kfree(lnode_list);
}

void
csio_oslnodes_unblock_by_port(struct csio_os_hw *oshw, uint8_t portid)
{
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_os_lnode *osln;
	struct Scsi_Host  *shost;
	struct csio_lnode *sln;
	struct csio_list *cur_ln, *cur_cln;
	struct csio_lnode **lnode_list;
	int cur_cnt = 0, ii;
	
	lnode_list = kzalloc((sizeof(struct csio_lnode *) * hw->num_lns),
			GFP_KERNEL);
	if (!lnode_list) {
		csio_err(hw, "Failed to allocate lnodes_list");
		return;
	}	

	csio_spin_lock_irq(hw, &hw->lock);
	/* Traverse sibling lnodes */
	csio_list_for_each(cur_ln, &hw->sln_head) {
		sln = (struct csio_lnode *) cur_ln;
		if (sln->portid != portid)
			continue;
		lnode_list[cur_cnt++] = sln;
		
		/* Traverse children lnodes */
		csio_list_for_each(cur_cln, &sln->cln_head) {
			lnode_list[cur_cnt++] = (struct csio_lnode *) cur_cln;

		}
	}
	csio_spin_unlock_irq(hw, &hw->lock);

	for (ii = 0; ii < cur_cnt; ii++) {
		csio_dbg(hw, "unblocking IOs on lnode: %p\n", lnode_list[ii]);
		osln = csio_lnode_to_os(lnode_list[ii]);
		shost = csio_osln_to_shost(osln);
		scsi_unblock_requests(shost);	
	}
	kfree(lnode_list);
}

void
csio_oslnodes_exit(struct csio_os_hw *oshw, bool npiv)
{
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_lnode *sln;
	struct csio_os_lnode *osln;
	struct csio_list *cur_ln, *cur_cln;
	struct csio_lnode **lnode_list;
	int cur_cnt = 0, ii;
	
	lnode_list = kzalloc((sizeof(struct csio_lnode *) * hw->num_lns),
			GFP_KERNEL);
	if (!lnode_list) {
		csio_err(hw, "csio_oslnodes_exit: Failed to allocate"
				"lnodes_list\n");
		return;
	}	

	/* Get all child lnodes(NPIV ports) */
	csio_spin_lock_irq(hw, &hw->lock);
	csio_list_for_each(cur_ln, &hw->sln_head) {
		sln = (struct csio_lnode *) cur_ln;
		
		/* Traverse children lnodes */
		csio_list_for_each(cur_cln, &sln->cln_head) {
			lnode_list[cur_cnt++] = (struct csio_lnode *) cur_cln;

		}
	}
	csio_spin_unlock_irq(hw, &hw->lock);

	/* Delete NPIV lnodes */
	for (ii = 0; ii < cur_cnt; ii++) {
		csio_dbg(hw, "Deleting child lnode: %p\n", lnode_list[ii]);
		if (csio_is_fcoe(csio_oshw_to_hw(oshw))) {
			osln = csio_lnode_to_os(lnode_list[ii]);
			fc_vport_terminate(osln->fc_vport);
		}
	}
	
	/* Delete only npiv lnodes */
	if (npiv) {
		goto free_lnodes;
	}

	cur_cnt = 0;
	/* Get all physical lnodes */
	csio_spin_lock_irq(hw, &hw->lock);
	/* Traverse sibling lnodes */
	csio_list_for_each(cur_ln, &hw->sln_head) {
		sln = (struct csio_lnode *) cur_ln;
		lnode_list[cur_cnt++] = sln;
	}
	csio_spin_unlock_irq(hw, &hw->lock);

	/* Delete physical lnodes */
	for (ii = 0; ii < cur_cnt; ii++) {
		csio_dbg(hw, "Deleting parent lnode: %p\n", lnode_list[ii]);
		csio_oslnode_exit(csio_lnode_to_os(lnode_list[ii]));
	}

free_lnodes:
	kfree(lnode_list);
}

/*
 * csio_oslnode_init_post: Set lnode attributes after starting HW.
 * @osln: lnode.
 *
 * During HW startup, NVRAM parameters and such are read. This routine
 * tells the transport about these parameters. It also calls scsi_scan_host.
 */
static void
csio_oslnode_init_post(struct csio_os_lnode *osln)
{
	struct Scsi_Host  *shost = csio_osln_to_shost(osln);

	if (csio_is_fcoe(csio_osln_to_hw(osln)))
		csio_fchost_attr_init(osln);

#ifdef __CSIO_TARGET__
	/*
	 * No need to initiate the scan thread and needlessly hold up insmod,
	 * if we are not initiator
	 */
	if (!csio_initiator_mode(csio_osln_to_hw(osln)))
		return;
#endif /* __CSIO_TARGET__ */

	if (csio_is_fcoe(csio_osln_to_hw(osln)))
		scsi_scan_host(shost);

	return;
}

static int csio_oslnf_start(struct csio_os_hw *oshw, struct pci_dev *pdev)
{
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_os_lnode *osln;
	struct csio_lnode *ln = NULL;
	int i, rv = 0;

	for (i = 0; i < hw->num_t4ports; i++) {
		osln = csio_oslnode_init(oshw, &pdev->dev, CSIO_TRUE, NULL);
		if (!osln) {
			rv = -ENODEV;
			break;
		}
		/* Initialize portid */
		ln = csio_osln_to_ln(osln);
		ln->portid = hw->t4port[i].portid;

#ifdef __CSIO_TARGET__
		/*
		 * If target mode is enabled, we do not bring the link up
		 * until the SAL is loaded. The action will resume in the
		 * the SAL initialization code which will bring the link up.
		 */ 		
		if (csio_target_mode(hw) && !sal_ops)
			goto init_post;
#endif /* __CSIO_TARGET__ */

		csio_spin_lock_irq(hw, &hw->lock);
		if (csio_lnf_start(csio_lnode_to_fcoe(ln)) !=
				CSIO_SUCCESS) {
			rv = -ENODEV;
		}
		csio_spin_unlock_irq(hw, &hw->lock);
		if (rv)
			break;

#ifdef __CSIO_TARGET__
init_post:
#endif /* __CSIO_TARGET__ */
		csio_oslnode_init_post(osln);
	}

	return rv;
}

#ifdef __CSIO_FOISCSI_ENABLED__
static int csio_oslni_start(struct csio_os_hw *oshw, struct pci_dev *pdev)
{
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_os_lnode *osln;
	struct csio_lnode *ln = NULL;
	struct csio_lnode_iscsi *lni = NULL;
	int i, rv = 0;

	for (i = 0; i < FW_FOISCSI_INIT_NODE_MAX; i++) {
		osln = csio_oslnode_init(oshw, &pdev->dev, CSIO_TRUE, NULL);
		if (!osln) {
			rv = -ENODEV;
			break;
		}
		ln = csio_osln_to_ln(osln);
		lni = csio_lnode_to_iscsi(ln);
		/* Initialize portid */
		ln->portid = hw->t4port[(hw->num_t4ports ? (i % hw->num_t4ports) : 0)].portid;
		
		csio_spin_lock_irq(hw, &hw->lock);
		if (csio_lni_start(lni) !=
				CSIO_SUCCESS) {
			rv = -ENODEV;
		}
		csio_spin_unlock_irq(hw, &hw->lock);

		if (rv)
			break;

		csio_oslnode_init_post(osln);
	}

	return rv;
}
#endif

/**
 * csio_probe_one - Instantiate this function.
 * @pdev: PCI device
 * @id: Device ID
 *
 * This is the .probe() callback of the driver. This function:
 * - Initializes the PCI function by enabling MMIO, setting bus
 *   mastership and setting DMA mask.
 * - Allocates HW structure, DMA, memory resources, maps BARS to
 *   host memory and initializes HW module.
 * - Allocates lnode structure via scsi_host_alloc, initializes
 *   shost, initialized lnode module and registers with SCSI ML
 *   via scsi_host_add.
 * - Enables interrupts, and starts the chip by kicking off the
 *   HW state machine.
 * - Once hardware is ready, initiated scan of the host via
 *   scsi_scan_host.
 */
static int __devinit
csio_probe_one(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int rv;
	int bars;
	struct csio_os_hw *oshw;
	struct csio_hw *hw;
	bool is_t5 = 0, is_t6_fpga = 0;

	/* probe either T6, T5 or T4 cards */
	if (csio_chip < 3) {

		if (pdev->device == CSIO_HW_T6FPGA_FOISCSI)
			is_t6_fpga = 1;
		else if (((pdev->device & CSIO_HW_CHIP_MASK) == CSIO_HW_T5))
			is_t5 = 1;

		dev_dbg(&pdev->dev, "%s: pdev->device:0x%x\n", __FUNCTION__, pdev->device);
		
		/* probe only T5 cards */
		if (csio_chip == 0 && !is_t5)
			return -ENODEV;
		/* probe only T4 cards */
		else if (((csio_chip == 1) && is_t5) ||
			((csio_chip == 1) && is_t6_fpga))
			return -ENODEV;
		else if (csio_chip == 2 && !is_t6_fpga)
			return -ENODEV;
	}
	
	if (csio_proto == FN_ALL && is_t6_fpga) {
		dev_err(&pdev->dev, "Only FOiSCSI is enabled on T6 FPGA, "
				"please use option csio_proto=2,\n");
		return -ENODEV;
	}

	if (csio_proto != FN_ALL) {
		if (!csio_proto_supported(pdev))
			return -ENODEV;
	}
	
	if (pf_counter > 0 && (CSIO_IS_T4_FPGA(pdev->device))) {
		dev_err(&pdev->dev, "Driver claims only one FPGA function\n");
		return -ENODEV;
	}

	rv = csio_pci_init(pdev, &bars);
	if (rv)
		goto err;

	oshw = csio_oshw_init(pdev);
	if (!oshw) {
		rv = -ENODEV;
		goto err_pci_exit;
	}

	hw = csio_oshw_to_hw(oshw);
	pci_set_drvdata(pdev, oshw);

	rv = csio_oshw_start(oshw);
	if (rv) {
		if (rv == CSIO_FATAL) {
			/* Do not fail pci probe for now.
			 * Required for HW debugging
			 */
			dev_err(&pdev->dev, "Failed to start FW, continuing in"
				    " debug mode.\n");
			return 0;
		}
		rv = -ENODEV;
		goto err_lnode_exit;
	}
	
	csio_oshw_regs_init(oshw);

	sprintf(hw->fwrev_str, "%u.%u.%u.%u\n",
		    G_FW_HDR_FW_VER_MAJOR(hw->fwrev),
		    G_FW_HDR_FW_VER_MINOR(hw->fwrev),
		    G_FW_HDR_FW_VER_MICRO(hw->fwrev),
		    G_FW_HDR_FW_VER_BUILD(hw->fwrev));

	if (csio_is_fcoe(hw)) {
		rv = csio_oslnf_start(oshw, pdev);
	} else {
#ifdef __CSIO_FOISCSI_ENABLED__
		rv = csio_oslni_start(oshw, pdev);
#endif
	}

	if (rv)
		goto err_lnode_exit;
	
#ifdef __CSIO_TARGET__
	dev_info(&pdev->dev, "Awaiting SAL module to start target.\n");
#endif /* __CSIO_TARGET__ */

	pf_counter++;
	
	return 0;

err_lnode_exit:
	csio_oslnodes_block_request(oshw);
	csio_spin_lock_irq(hw, &hw->lock);
	csio_hw_stop(hw);
	csio_spin_unlock_irq(hw, &hw->lock);
	csio_oslnodes_unblock_request(oshw);
	pci_set_drvdata(oshw->pdev, NULL);
	csio_oslnodes_exit(oshw, 0);
	csio_oshw_exit(oshw);
err_pci_exit:
	csio_pci_exit(pdev, &bars);	
err:
	dev_err(&pdev->dev, "probe of device failed: %d\n", rv);
	return rv;
}

/**
 * csio_remove_one - Remove one instance of the driver at this PCI function.
 * @pdev: PCI device
 *
 * Used during hotplug operation.
 */
static void __devexit
csio_remove_one(struct pci_dev *pdev)
{
	struct csio_os_hw *oshw = pci_get_drvdata(pdev);
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	int bars = pci_select_bars(pdev, IORESOURCE_MEM);

	csio_oslnodes_block_request(oshw);
	csio_spin_lock_irq(hw, &hw->lock);
	
	/* Stops lnode, Rnode s/m
	 * Quiesce IOs.
	 * All sessions with remote ports are unregistered.
	 */
	csio_hw_stop(hw);
	csio_spin_unlock_irq(hw, &hw->lock);
	csio_oslnodes_unblock_request(oshw);
	
	csio_oslnodes_exit(oshw, 0);	
	csio_oshw_exit(oshw);
	pci_set_drvdata(pdev, NULL);
	csio_pci_exit(pdev, &bars);

	return;
}

/**
 * csio_pci_error_detected - PCI error was detected
 * @pdev: PCI device
 *
 */
static pci_ers_result_t
csio_pci_error_detected(struct pci_dev *pdev, pci_channel_state_t state)
{
	struct csio_os_hw *oshw = pci_get_drvdata(pdev);
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	
	csio_oslnodes_block_request(oshw);
	csio_spin_lock_irq(hw, &hw->lock);
	
	/* Post PCI error detected evt to HW s/m
	 * HW s/m handles this evt by quiescing IOs, unregisters rports
	 * and finally takes the device to offline.
	 */
	csio_post_event(&hw->sm, CSIO_HWE_PCIERR_DETECTED);
	csio_spin_unlock_irq(hw, &hw->lock);
	csio_oslnodes_unblock_request(oshw);
	csio_oslnodes_exit(oshw, 0);	
	csio_intr_disable(oshw, CSIO_TRUE);
	pci_disable_device(pdev);
	return state == pci_channel_io_perm_failure ?
		PCI_ERS_RESULT_DISCONNECT : PCI_ERS_RESULT_NEED_RESET;
}

/**
 * csio_pci_slot_reset - PCI slot has been reset.
 * @pdev: PCI device
 *
 */
static pci_ers_result_t
csio_pci_slot_reset(struct pci_dev *pdev)
{
	struct csio_os_hw *oshw = pci_get_drvdata(pdev);
	struct csio_hw *hw = csio_oshw_to_hw(oshw);

	if (pci_enable_device(pdev)) {
		dev_err(&pdev->dev, "cannot reenable device while"
			"in slot reset");
		return PCI_ERS_RESULT_DISCONNECT;
	}	

	pci_set_master(pdev);
	pci_restore_state(pdev);
	pci_save_state(pdev);
	pci_cleanup_aer_uncorrect_error_status(pdev);

	/* Bring HW s/m to ready state.
	 * but don't resume IOs.
	 */
	csio_spin_lock_irq(hw, &hw->lock);
	csio_post_event(&hw->sm, CSIO_HWE_PCIERR_SLOT_RESET);
	if (!csio_is_hw_ready(hw)) {
		csio_spin_unlock_irq(hw, &hw->lock);
		dev_err(&pdev->dev, "cannot initialize HW while"
			"in slot reset");
		return PCI_ERS_RESULT_DISCONNECT;
	}
	csio_spin_unlock_irq(hw, &hw->lock);
	return PCI_ERS_RESULT_RECOVERED;
}

/**
 * csio_pci_resume - Resume normal operations
 * @pdev: PCI device
 *
 */
static void
csio_pci_resume(struct pci_dev *pdev)
{
	struct csio_os_hw *oshw = pci_get_drvdata(pdev);
	struct csio_hw *hw = csio_oshw_to_hw(oshw);
	struct csio_os_lnode *osln;
	struct csio_lnode *ln;
	int rv = 0;
	int i;

	/* Bring the LINK UP and Resume IO */

	for (i = 0; i < hw->num_t4ports; i++) {
		osln = csio_oslnode_init(oshw, &pdev->dev, CSIO_TRUE, NULL);
		if (!osln) {
			rv = -ENODEV;
			break;
		}
		/* Initialize portid */
		ln = csio_osln_to_ln(osln);
		ln->portid = hw->t4port[i].portid;
	
#ifdef __CSIO_TARGET__
		/*
		 * If target mode is enabled, we do not bring the link up
		 * until the SAL is loaded. The action will resume in the
		 * the SAL initialization code which will bring the link up.
		 */ 		
		if (csio_target_mode(hw) && !sal_ops) {
			dev_info(&pdev->dev, "Await loading of SAL module\n");
			goto init_post;
		}
#endif /* __CSIO_TARGET__ */

		csio_spin_lock_irq(hw, &hw->lock);
		if (csio_is_fcoe(hw)) {
			if (csio_lnf_start(csio_lnode_to_fcoe(ln)) !=
				CSIO_SUCCESS) {
				rv = -ENODEV;
			}
		} else {
#ifdef __CSIO_FOISCSI_ENABLED__
			if (csio_lni_start(csio_lnode_to_iscsi(ln)) !=
				CSIO_SUCCESS) {
				rv = -ENODEV;
			}
			/* iSCSI */
#endif
		}
		csio_spin_unlock_irq(hw, &hw->lock);
		if (rv)
			break;

#ifdef __CSIO_TARGET__
init_post:
#endif /* __CSIO_TARGET__ */
		csio_oslnode_init_post(osln);
	}
	if (rv)
		goto err_resume_exit;
	
	return;

err_resume_exit:
	csio_oslnodes_block_request(oshw);
	csio_spin_lock_irq(hw, &hw->lock);
	csio_hw_stop(hw);
	csio_spin_unlock_irq(hw, &hw->lock);
	csio_oslnodes_unblock_request(oshw);
	csio_oslnodes_exit(oshw, 0);
	csio_oshw_exit(oshw);
	dev_err(&pdev->dev, "resume of device failed: %d\n", rv);
	return;
}

static struct pci_error_handlers csio_err_handler = {
	.error_detected = csio_pci_error_detected,
	.slot_reset 	= csio_pci_slot_reset,
	.resume 	= csio_pci_resume,
};

/*
 *  Macros needed to support the PCI Device ID Table ...
 */
#define CH_PCI_DEVICE_ID_TABLE_DEFINE_BEGIN \
	static const struct pci_device_id csio_pci_tbl[] = {

/* Define for iSCSI uses PF5, FCoE uses PF6 */
#define CH_PCI_DEVICE_ID_FUNCTION \
		0x5
#define CH_PCI_DEVICE_ID_FUNCTION2 \
		0x6

#define CH_PCI_ID_TABLE_ENTRY(__DeviceID) \
		{ PCI_VDEVICE(CHELSIO, (__DeviceID)), 0 }

#define CH_PCI_DEVICE_ID_TABLE_DEFINE_END \
		{ 0, } \
	}

/*
 *  ... and the PCI ID Table itself ...
 */
#include "t4_pci_id_tbl.h"

static struct pci_driver csio_pci_driver = {
	.name		= KBUILD_MODNAME,
	.driver		= {
		.owner	= THIS_MODULE,
	},
	.id_table	= csio_pci_tbl,
	.probe		= csio_probe_one,
	.remove		= csio_remove_one,
	.err_handler	= &csio_err_handler,
};

#ifdef __CSIO_DIE_NOTIFY__
int csiostor_module_callback(struct notifier_block *self,
			     unsigned long val, void *data)
{
	struct die_args *args = data;
	int ret = NOTIFY_DONE;

	printk("DIE val:%lu err %lx trap %d\n", val, args->err, args->trapnr);	
	dump_stack();
//	CSIO_ASSERT(0);

	if (args->regs && user_mode_vm(args->regs)) {
		printk("User mode:\n");	
		return ret;
	}
	return 0;	
}

static struct notifier_block csiostor_module_nb = {
	.notifier_call = csiostor_module_callback,
	.priority = 0
};
#endif /* __CSIO_DIE_NOTIFY__ */

/*
 * csio_init - Chelsio storage driver initialization function.
 *
 * This is the first function called in the driver load path.
 * Attach driver to FCOE as well as iSCSI transports. For FCOE, register
 * both physical and virtual port templates. Then Register with PCI subsystem.
 */
static int __init
csio_init(void)
{
	int rv = -ENOMEM;
	dev_t dev;

	printk("csiostor: Loading %s v%s\n", CSIO_DRV_DESC, CSIO_DRV_VERSION);

	csio_osdfs_init();
	csio_module_params_check();

	csio_fcoe_transport = fc_attach_transport(&csio_fc_transport_funcs);
	if (!csio_fcoe_transport)
		goto err;

	csio_fcoe_transport_vport =
			fc_attach_transport(&csio_fc_transport_vport_funcs);
	if (!csio_fcoe_transport_vport)
		goto err_vport;

	/*
	 * Create class before pci_register_driver(), since probe() will be
	 * called soon after registration, and the probe() callbacks need
	 * csio_class to be initialized.
	 */
	rv = alloc_chrdev_region(&dev, 0, CSIO_MAX_CMINORS, CSIO_CDEVFILE);
	if (rv) {
		printk("csiostor: failed to allocated device minor numbers.\n");
		goto err_cdev;
	}

	csio_cdev_major = MAJOR(dev);
	csio_class = class_create(THIS_MODULE, CSIO_CDEVFILE);

	if (IS_ERR(csio_class)) {
		rv = PTR_ERR(csio_class);
		printk("csiostor: failed to create %s class: %d\n",
							CSIO_CDEVFILE, rv);
		goto err_class;
	}

#ifdef __CSIO_TARGET__
	os_start_stop_tgt = csio_os_start_stop_tgt;
#endif /* __CSIO_TARGET__ */

	rv = pci_register_driver(&csio_pci_driver);
	if (rv)
		goto err_pci;

#ifdef __CSIO_DIE_NOTIFY__
	rv = register_die_notifier(&csiostor_module_nb);
	if (rv)
	 	printk("Failed to register die notifier\n");
#endif /* __CSIO_DIE_NOTIFY__ */
	printk("csiostor: Loaded %s\n", CSIO_DRV_DESC);
	return 0;

err_pci:
	class_destroy(csio_class);
err_class:
	unregister_chrdev_region(MKDEV(csio_cdev_major, 0), CSIO_MAX_CMINORS);
err_cdev:
	fc_release_transport(csio_fcoe_transport_vport);
err_vport:
	fc_release_transport(csio_fcoe_transport);
err:
	csio_osdfs_exit();
	return rv;
}

/*
 * csio_exit - Chelsio storage driver uninitialization .
 *
 * Function that gets called in the unload path.
 */
static void __exit
csio_exit(void)
{
	pci_unregister_driver(&csio_pci_driver);
	csio_osdfs_exit();
	class_destroy(csio_class);
	unregister_chrdev_region(MKDEV(csio_cdev_major, 0), CSIO_MAX_CMINORS);
	fc_release_transport(csio_fcoe_transport_vport);
	fc_release_transport(csio_fcoe_transport);

#ifdef __CSIO_DIE_NOTIFY__
	unregister_die_notifier(&csiostor_module_nb);
#endif /* __CSIO_DIE_NOTIFY__ */
	printk("Unloaded %s v%s\n", CSIO_DRV_DESC, CSIO_DRV_VERSION);
	return;
}

module_init(csio_init);
module_exit(csio_exit);
MODULE_AUTHOR(CSIO_DRV_AUTHOR);
MODULE_DESCRIPTION(CSIO_DRV_DESC);
MODULE_LICENSE(CSIO_DRV_LICENSE);
MODULE_DEVICE_TABLE(pci, csio_pci_tbl);
MODULE_VERSION(CSIO_DRV_VERSION);
MODULE_FIRMWARE(FW4_FNAME);
MODULE_FIRMWARE(FW5_FNAME);
MODULE_FIRMWARE(FW6_FNAME);
MODULE_FIRMWARE(FW4_CFNAME);
MODULE_FIRMWARE(FW5_CFNAME);
MODULE_FIRMWARE(FW6_CFNAME);
