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

#include <csio_hw.h>
#include <csio_lnode.h>
#include <csio_rnode.h>
#include <csio_stor_ioctl.h>
#include <csio_t4_ioctl.h>

#ifdef __CSIO_FOISCSI_ENABLED__
#include <csio_trans_foiscsi.h>
#endif

int csio_exit_no_mb = 0;
int csio_dbg_level = 0xFEFF;
unsigned int csio_port_mask = 0xf;
static char *csio_drv_ver;

/* Default FW event queue entries. */
uint32_t csio_evtq_sz = CSIO_EVTQ_SIZE;

/* Default MSI param level */
int csio_msi = 2;

/* T4 device instances */
static int dev_num;

/* State machine forward declarations */
static void csio_hws_uninit(struct csio_hw *, csio_hw_ev_t);
static void csio_hws_configuring(struct csio_hw *, csio_hw_ev_t);
static void csio_hws_initializing(struct csio_hw *, csio_hw_ev_t);
static void csio_hws_ready(struct csio_hw *, csio_hw_ev_t);
static void csio_hws_quiescing(struct csio_hw *, csio_hw_ev_t);
static void csio_hws_quiesced(struct csio_hw *, csio_hw_ev_t);
static void csio_hws_resetting(struct csio_hw *, csio_hw_ev_t);
static void csio_hws_removing(struct csio_hw *, csio_hw_ev_t);
static void csio_hws_pcierr(struct csio_hw *, csio_hw_ev_t);
static void csio_hws_offline(struct csio_hw *, csio_hw_ev_t);
static void csio_hw_initialize(struct csio_hw *hw);

void csio_evtq_stop(struct csio_hw *hw);
void csio_evtq_start(struct csio_hw *hw);
void csio_evtq_flush(struct csio_hw *hw);

static const char *hw_evt_names[] = { "NONE", "CSIO_HWE_CFG",
		"CSIO_HWE_INIT", "CSIO_HWE_INIT_DONE", "CSIO_HWE_FATAL",
		"CSIO_HWE_PCIERR_DETECTED", "CSIO_HWE_PCIERR_SLOT_RESET",
		"CSIO_HWE_PCIERR_RESUME", "CSIO_HWE_QUIESCED",
		"CSIO_HWE_HBA_RESET", "CSIO_HWE_HBA_RESET_DONE",
		"CSIO_HWE_FW_DLOAD", "CSIO_HWE_PCI_REMOVE", "CSIO_HWE_SUSPEND",
		"CSIO_HWE_RESUME", "CSIO_INVALID"};

int csio_is_hw_ready(struct csio_hw *hw)
{
	return csio_match_state(hw, csio_hws_ready);
}	

int csio_is_hw_removing(struct csio_hw *hw)
{
	return csio_match_state(hw, csio_hws_removing);
}	

static int csio_is_hw_10gbt_device(struct csio_hw *hw)
{
	int device = hw->adap.params.pci.device_id;

	switch(device) {
		case CSIO_T4_ISCSI_PHY_AQ1202_DEVICEID:
		case CSIO_T4_ISCSI_PHY_BCM84834_DEVICEID:
		case CSIO_T4_FCOE_PHY_AQ1202_DEVICEID:
		case CSIO_T4_FCOE_PHY_BCM84834_DEVICEID:
			return 1;

		default:
			return 0;
	}
}

/*
 * EEPROM reads take a few tens of us while writes can take a bit over 5 ms.
 */
#define EEPROM_MAX_RD_POLL 40
#define EEPROM_MAX_WR_POLL 6
#define EEPROM_STAT_ADDR   0x7bfc
#define VPD_BASE           0x400
#define VPD_BASE_OLD	   0
#define VPD_LEN            1024
#define VPD_INFO_FLD_HDR_SIZE	3

/**
 *	csio_hw_get_vpd_params - read VPD parameters from VPD EEPROM
 *	@hw: HW module
 *	@p: where to store the parameters
 *
 *	Reads card parameters stored in VPD EEPROM.
 */
csio_retval_t
csio_hw_get_vpd_params(struct csio_hw *hw, struct vpd_params *p)
{
	int ret;

	if (csio_unlikely(csio_is_valid_vpd(hw))) {
		csio_info(hw, "Contains valid VPD params. Exiting!\n");
		return CSIO_SUCCESS;
	}

	/* Reset the VPD flag! */
	csio_invalidate_vpd(hw);

	ret = t4_get_raw_vpd_params(&hw->adap, p);

	if(!ret)
		csio_valid_vpd_copied(hw);

	if (ret == -EINVAL)
		ret = CSIO_INVAL;
	return ret;
}

/**
 *	csio_hw_read_flash - read words from serial flash
 *	@hw: the HW module
 *	@addr: the start address for the read
 *	@nwords: how many 32-bit words to read
 *	@data: where to store the read data
 *	@byte_oriented: whether to store data as bytes or as words
 *
 *	Read the specified number of 32-bit words from the serial flash.
 *	If @byte_oriented is set the read data is stored as a byte array
 *	(i.e., big-endian), otherwise as 32-bit words in the platform's
 *	natural endianess.
 */
csio_retval_t
csio_hw_read_flash(struct csio_hw *hw, uint32_t addr, uint32_t nwords,
		  uint32_t *data, int32_t byte_oriented)
{
	enum csio_oss_error ret;

	ret = t4_read_flash(&hw->adap, addr, nwords, data, byte_oriented);
	if (ret == -EINVAL)
		return CSIO_INVAL;

	return CSIO_SUCCESS;
}

/**
 *	csio_hw_write_flash - write up to a page of data to the serial flash
 *	@hw: the hw
 *	@addr: the start address to write
 *	@n: length of data to write in bytes
 *	@data: the data to write
 *
 *	Writes up to a page of data (256 bytes) to the serial flash starting
 *	at the given address.  All the data must be written to the same page.
 */
csio_retval_t
csio_hw_write_flash(struct csio_hw *hw, uint32_t addr,
		    uint32_t n, const uint8_t *data)
{
	enum csio_oss_error ret = CSIO_INVAL;

	ret = t4_write_flash(&hw->adap, addr, n, data, 1);
	if (ret == -EINVAL)
		return CSIO_INVAL;

	return CSIO_SUCCESS;
}


/**
 *	csio_hw_flash_erase_sectors - erase a range of flash sectors
 *	@hw: the HW module
 *	@start: the first sector to erase
 *	@end: the last sector to erase
 *
 *	Erases the sectors in the given inclusive range.
 */
csio_retval_t
csio_hw_flash_erase_sectors(struct csio_hw *hw, int32_t start, int32_t end)
{
	enum csio_oss_error ret;

	ret = t4_flash_erase_sectors(&hw->adap, start, end);
	if (ret == -EINVAL)
		return CSIO_INVAL;

	return CSIO_SUCCESS;
}

static void
csio_hw_print_fw_version(struct csio_hw *hw, char *str)
{
	csio_info(hw, "T%d %s: %u.%u.%u.%u\n",
			is_t4(hw->adap.params.chip) ? 4 : 
			is_t5(hw->adap.params.chip) ? 5 : 6, str,
		    G_FW_HDR_FW_VER_MAJOR(hw->fwrev),
		    G_FW_HDR_FW_VER_MINOR(hw->fwrev),
		    G_FW_HDR_FW_VER_MICRO(hw->fwrev),
		    G_FW_HDR_FW_VER_BUILD(hw->fwrev));
}	

/*
 * csio_hw_get_fw_version - read the firmware version
 * @hw: HW module
 * @vers: where to place the version
 *
 * Reads the FW version from flash.
 */
csio_retval_t
csio_hw_get_fw_version(struct csio_hw *hw, uint32_t *vers)
{
	struct adapter *adap = &hw->adap;
	int rv;

	rv = t4_get_fw_version(adap, &adap->params.fw_vers);
	if (rv < 0)
		return CSIO_INVAL;

	hw->fwrev = adap->params.fw_vers;

	return CSIO_SUCCESS;
}

/**
 *	csio_hw_get_tp_version - read the TP microcode version
 *	@hw: HW module
 *	@vers: where to place the version
 *
 *	Reads the TP microcode version from flash.
 */
int csio_hw_get_tp_version(struct csio_hw *hw, u32 *vers)
{
	return t4_read_flash(&hw->adap, FLASH_FW_START +
			CSIO_OFFSETOF(struct fw_hdr, tp_microcode_ver), 1,
			vers, 0);
}

/*****************************************************************************/
/*  Card debug                                                               */
/*****************************************************************************/
#ifdef __CSIO_DEBUG__
/*
 * This function causes an assertion in FW (in debug mode ONLY) by  issuing a
 * duplicate INITIALIZE command. It means that this function can be used ONLY
 * after the first INITIALIZE command has already been issued.
 */
void
csio_assert_fw(struct csio_hw *hw)
{
	struct adapter *adap = &hw->adap;
	int ret;

	csio_dbg(hw, "Trying to assert FW to debug further....\n");
	ret = t4_fw_initialize(adap, adap->mbox);
	if (ret < 0)
		return;
	csio_dbg(hw, "Issued FW crash cmd.\n");
}
#endif /* __CSIO_DEBUG__ */

/**
 *	csio_hw_get_fcoe_stats - read TP's FCoE MIB counters for a port
 *	@hw: the hw
 *	@idx: the port index
 *	@st: holds the counter values
 *
 *	Returns the values of TP's FCoE counters for the selected port.
 */
void csio_hw_get_fcoe_stats(struct csio_hw *hw, uint32_t idx,
		       struct tp_fcoe_stats *st)
{
	uint32_t val[2];

	t4_read_indirect(&hw->adap, A_TP_MIB_INDEX, A_TP_MIB_DATA,
			 &st->frames_ddp, 1, A_TP_MIB_FCOE_DDP_0 + idx);
	t4_read_indirect(&hw->adap, A_TP_MIB_INDEX, A_TP_MIB_DATA,
			 &st->frames_drop, 1, A_TP_MIB_FCOE_DROP_0 + idx);
	t4_read_indirect(&hw->adap, A_TP_MIB_INDEX, A_TP_MIB_DATA, val,
			 2, A_TP_MIB_FCOE_BYTE_0_HI + 2 * idx);
	st->octets_ddp = ((uint64_t)val[0] << 32) | val[1];
}

/**
 *	csio_hw_set_trace_filter - configure one of the tracing filters
 *	@hw: the hw
 *	@tp: the desired trace filter parameters
 *	@idx: which filter to configure
 *	@enable: whether to enable or disable the filter
 *
 *	Configures one of the tracing filters available in HW.  If @enable is
 *	%0 @tp is not examined and may be %NULL.
 */
int csio_hw_set_trace_filter(struct csio_hw *hw, const struct trace_params *tp
				, int idx, int enable)
{
	int i, ofst = idx * 4;
	uint32_t data_reg, mask_reg, cfg;
	uint32_t multitrc = F_TRCMULTIFILTER;

	if (!enable) {
		t4_write_reg(&hw->adap, A_MPS_TRC_FILTER_MATCH_CTL_A + ofst, 0);
		goto out;
	}

	if (tp->port > 11 || tp->invert > 1 || tp->skip_len > M_TFLENGTH ||
	    tp->skip_ofst > M_TFOFFSET || tp->min_len > M_TFMINPKTSIZE ||
	    tp->snap_len > 9600 || (idx && tp->snap_len > 256))
		return CSIO_INVAL;

	if (tp->snap_len > 256) {            /* must be tracer 0 */
		if ((t4_read_reg(&hw->adap, A_MPS_TRC_FILTER_MATCH_CTL_A + 4) |
		     t4_read_reg(&hw->adap, A_MPS_TRC_FILTER_MATCH_CTL_A + 8) |
		     t4_read_reg(&hw->adap, A_MPS_TRC_FILTER_MATCH_CTL_A + 12)) &
		    F_TFEN)
			return CSIO_INVAL;  /* other tracers are enabled */
		multitrc = 0;
	} else if (idx) {
		i = t4_read_reg(&hw->adap, A_MPS_TRC_FILTER_MATCH_CTL_B);
		if (G_TFCAPTUREMAX(i) > 256 &&
		    (t4_read_reg(&hw->adap, A_MPS_TRC_FILTER_MATCH_CTL_A) & F_TFEN))
			return CSIO_INVAL;
	}

	/* stop the tracer we'll be changing */
	t4_write_reg(&hw->adap, A_MPS_TRC_FILTER_MATCH_CTL_A + ofst, 0);

	/* disable tracing globally if running in the wrong single/multi mode */
	cfg = t4_read_reg(&hw->adap, A_MPS_TRC_CFG);
	if ((cfg & F_TRCEN) && multitrc != (cfg & F_TRCMULTIFILTER)) {
		t4_write_reg(&hw->adap, A_MPS_TRC_CFG, cfg ^ F_TRCEN);
		t4_read_reg(&hw->adap, A_MPS_TRC_CFG);                  /* flush */
		csio_msleep(1);
		if (!(t4_read_reg(&hw->adap, A_MPS_TRC_CFG) & F_TRCFIFOEMPTY))
			return CSIO_TIMEOUT;
	}
	/*
	 * At this point either the tracing is enabled and in the right mode or
	 * disabled.
	 */

	idx *= (A_MPS_TRC_FILTER1_MATCH - A_MPS_TRC_FILTER0_MATCH);
	data_reg = A_MPS_TRC_FILTER0_MATCH + idx;
	mask_reg = A_MPS_TRC_FILTER0_DONT_CARE + idx;

	for (i = 0; i < TRACE_LEN / 4; i++, data_reg += 4, mask_reg += 4) {
		t4_write_reg(&hw->adap, data_reg, tp->data[i]);
		t4_write_reg(&hw->adap, mask_reg, ~tp->mask[i]);
	}
	t4_write_reg(&hw->adap, A_MPS_TRC_FILTER_MATCH_CTL_B + ofst,
		     V_TFCAPTUREMAX(tp->snap_len) |
		     V_TFMINPKTSIZE(tp->min_len));
	t4_write_reg(&hw->adap, A_MPS_TRC_FILTER_MATCH_CTL_A + ofst,
		     V_TFOFFSET(tp->skip_ofst) | V_TFLENGTH(tp->skip_len) |
		     CSIO_HW_MPS_TRC_FILTER_FLAG(hw, tp));
	cfg &= ~F_TRCMULTIFILTER;
	t4_write_reg(&hw->adap, A_MPS_TRC_CFG, cfg | F_TRCEN | multitrc);
out:	t4_read_reg(&hw->adap, A_MPS_TRC_CFG);  /* flush */
	return 0;
}

/**
 *	csio_hw_get_trace_filter - query one of the tracing filters
 *	@hw: the hw
 *	@tp: the current trace filter parameters
 *	@idx: which trace filter to query
 *	@enabled: non-zero if the filter is enabled
 *
 *	Returns the current settings of one of the HW tracing filters.
 */
void csio_hw_get_trace_filter(struct csio_hw *hw, struct trace_params *tp, int idx,
			 int *enabled)
{
	uint32_t ctla, ctlb;
	int i, ofst = idx * 4;
	uint32_t data_reg, mask_reg;

	ctla = t4_read_reg(&hw->adap, A_MPS_TRC_FILTER_MATCH_CTL_A + ofst);
	ctlb = t4_read_reg(&hw->adap, A_MPS_TRC_FILTER_MATCH_CTL_B + ofst);

	*enabled = !!(ctla & CSIO_HW_F_TFEN(hw));
	tp->port = CSIO_HW_G_TFPORT(hw, ctla);
	tp->snap_len = G_TFCAPTUREMAX(ctlb);
	tp->min_len = G_TFMINPKTSIZE(ctlb);
	tp->skip_ofst = G_TFOFFSET(ctla);
	tp->skip_len = G_TFLENGTH(ctla);
	tp->invert = !!(ctla & F_TFINVERTMATCH);

	ofst = (A_MPS_TRC_FILTER1_MATCH - A_MPS_TRC_FILTER0_MATCH) * idx;
	data_reg = A_MPS_TRC_FILTER0_MATCH + ofst;
	mask_reg = A_MPS_TRC_FILTER0_DONT_CARE + ofst;

	for (i = 0; i < TRACE_LEN / 4; i++, data_reg += 4, mask_reg += 4) {
		tp->mask[i] = ~t4_read_reg(&hw->adap, mask_reg);
		tp->data[i] = t4_read_reg(&hw->adap, data_reg) & tp->mask[i];
	}
}

static csio_retval_t
csio_hw_show(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	csio_hw_info_t *hw_info = buffer;
	size_t drv_ver_str_len = 0;
	int ii = 0;

	if (buffer_len < (uint32_t)sizeof(csio_hw_info_t))
		return CSIO_NOMEM;

	csio_memcpy(hw_info->name, hw->model_desc, 32);
	csio_memcpy(hw_info->model, hw->adap.params.vpd.id, sizeof(hw->adap.params.vpd.id));
	csio_memcpy(hw_info->sl_no, hw->adap.params.vpd.sn, sizeof(hw->adap.params.vpd.sn));
	csio_memcpy(hw_info->drv_version, hw->drv_version, 32);

	csio_memcpy(hw_info->hw_version, hw->hw_ver, sizeof(hw->hw_ver));

	hw_info->pci_id.s.vendor_id = hw->adap.params.pci.vendor_id;
	hw_info->pci_id.s.device_id = hw->adap.params.pci.device_id;	
	
	hw_info->fwrev 		= hw->fwrev;
	hw_info->chip_rev	= CHELSIO_CHIP_RELEASE(hw->adap.params.chip);
	hw_info->optrom_ver	= hw->optrom_ver;
	hw_info->cfg_finiver 	= hw->cfg_finiver;
	hw_info->cfg_finicsum 	= hw->cfg_finicsum;
	hw_info->cfg_cfcsum 	= hw->cfg_cfcsum;
	hw_info->cfg_csum_status = hw->cfg_csum_status;

	switch (hw->cfg_store) {
		case FW_MEMTYPE_CF_FLASH:
			hw_info->cfg_store = CFG_STORE_FLASH;
			break;

		case FW_MEMTYPE_CF_EDC0:
			hw_info->cfg_store = CFG_STORE_EDC0;
			break;

		case FW_MEMTYPE_CF_EDC1:
			hw_info->cfg_store = CFG_STORE_EDC1;
			break;

		case FW_MEMTYPE_CF_EXTMEM:
			hw_info->cfg_store = CFG_STORE_EXTMEM;
			break;
			
		default:
			hw_info->cfg_store = CFG_STORE_FILESYSTEM;
			break;
	}

	hw_info->dev_num	= hw->dev_num;
	hw_info->pfn		= hw->pfn;
	hw_info->port_vec	= hw->port_vec;
	hw_info->num_t4ports	= hw->num_t4ports;
	hw_info->master		= csio_is_hw_master(hw);

	hw_info->initiator	= csio_initiator_mode(hw);
	hw_info->target		= csio_target_mode(hw);

	for (ii = 0; ii < CSIO_MAX_T4PORTS; ii++) {
		csio_memcpy(&hw_info->t4port[ii], &hw->t4port[ii],
					sizeof(csio_t4port_t));
	}

	hw_info->fwevt_iq_idx	= hw->fwevt_iq_idx;
	hw_info->fwevt_iq_msix	= csio_get_fwevt_intr_idx(hw);

	hw_info->wrm_num_sge_q	= hw->wrm.free_qidx;

	csio_hw_stateto_str(hw, hw_info->state);
	
	if (hw->intr_mode == CSIO_IM_INTX)
		csio_strcpy(hw_info->intr_mode_str, "INTx");
	else if (hw->intr_mode == CSIO_IM_MSI)
		csio_strcpy(hw_info->intr_mode_str, "MSI");
	else if (hw->intr_mode == CSIO_IM_MSIX)
		csio_strcpy(hw_info->intr_mode_str, "MSI-X");
	else
		csio_strcpy(hw_info->intr_mode_str, "NONE");
	
	/* stats */
	csio_memcpy(&hw_info->stats, &hw->stats, sizeof(csio_hw_stats_t));

	/* Events */
	hw_info->max_events	= (uint8_t)CSIO_HWE_MAX;
	hw_info->cur_evt	= hw->cur_evt;
	hw_info->prev_evt	= hw->prev_evt;

	for (ii = 0; ii < CSIO_HWE_MAX; ii++) {
		csio_strncpy(hw_info->evt_name[ii],
				csio_hw_evt_name(ii), 32);
	}

	/* driver version */	
	if (csio_drv_ver != NULL && csio_strlen(csio_drv_ver) >0) {
		drv_ver_str_len =  csio_strlen(csio_drv_ver);
		csio_strncpy(hw_info->drv_version, csio_drv_ver,
			CSIO_MIN(CSIO_ARRAY_SIZE(hw_info->drv_version),
					drv_ver_str_len));
	}

	return CSIO_SUCCESS;
} /* csio_hw_show */

static csio_retval_t
csio_hw_get_scsi_stats(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	csio_scsi_stats_t *scsi_stats = buffer;
	struct csio_scsim *scsim = csio_hw_to_scsim(hw);

	if (buffer_len < (uint32_t)sizeof(csio_scsi_stats_t))
		return CSIO_NOMEM;

	scsi_stats->n_tot_success	= scsim->stats.n_tot_success;
	scsi_stats->n_rn_nr_error	= scsim->stats.n_rn_nr_error;
	scsi_stats->n_hw_nr_error	= scsim->stats.n_hw_nr_error;
	scsi_stats->n_dmamap_error	= scsim->stats.n_dmamap_error;
	scsi_stats->n_unsupp_sge_error	= scsim->stats.n_unsupp_sge_error;
	scsi_stats->n_busy_error	= scsim->stats.n_busy_error;
	scsi_stats->n_hosterror		= scsim->stats.n_hosterror;
	scsi_stats->n_rsperror		= scsim->stats.n_rsperror;
	scsi_stats->n_autosense		= scsim->stats.n_autosense;
	scsi_stats->n_ovflerror		= scsim->stats.n_ovflerror;
	scsi_stats->n_unflerror		= scsim->stats.n_unflerror;
	scsi_stats->n_rdev_nr_error	= scsim->stats.n_rdev_nr_error;
	scsi_stats->n_rdev_lost_error	= scsim->stats.n_rdev_lost_error;
	scsi_stats->n_rdev_logo_error	= scsim->stats.n_rdev_logo_error;
	scsi_stats->n_link_down_error	= scsim->stats.n_link_down_error;
	scsi_stats->n_unknown_error	= scsim->stats.n_unknown_error;
	scsi_stats->n_aborted		= scsim->stats.n_aborted;
	scsi_stats->n_abrt_timedout	= scsim->stats.n_abrt_timedout;
	scsi_stats->n_abrt_fail		= scsim->stats.n_abrt_fail;
	scsi_stats->n_abrt_race_comp	= scsim->stats.n_abrt_race_comp;
	scsi_stats->n_abrt_busy_error	= scsim->stats.n_abrt_busy_error;
	scsi_stats->n_closed		= scsim->stats.n_closed;
	scsi_stats->n_cls_busy_error	= scsim->stats.n_cls_busy_error;
	scsi_stats->n_res_wait		= 0;
	scsi_stats->n_active		= scsim->stats.n_active;
	scsi_stats->n_tm_active		= scsim->stats.n_tm_active;
	scsi_stats->n_wcbfn		= scsim->stats.n_wcbfn;
	scsi_stats->n_free_ioreq	= scsim->stats.n_free_ioreq;
	scsi_stats->n_ddp_miss		= scsim->stats.n_ddp_miss;
	scsi_stats->n_inval_cplop	= scsim->stats.n_inval_cplop;
	scsi_stats->n_inval_scsiop	= scsim->stats.n_inval_scsiop;

	return CSIO_SUCCESS;
} /* csio_hw_get_scsi_stats */

static csio_retval_t
csio_hw_read_reg(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	csio_reg_t *reg = buffer;

	if (buffer_len < (uint32_t)sizeof(csio_reg_t))
		return CSIO_NOMEM;

	/* disallow rogue addresses */
	if ((reg->addr & 3) != 0 || !csio_reg_valid(hw->os_dev, reg->addr))
		return CSIO_INVAL;

	reg->val = t4_read_reg(&hw->adap, reg->addr);

	return CSIO_SUCCESS;
} /* csio_hw_read_reg */


static csio_retval_t
csio_hw_write_reg(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	csio_reg_t *reg = buffer;

	if (buffer_len < (uint32_t)sizeof(csio_reg_t))
		return CSIO_NOMEM;

	/* disallow rogue addresses */
	if ((reg->addr & 3) != 0 || !csio_reg_valid(hw->os_dev, reg->addr))
		return CSIO_INVAL;

	t4_write_reg(&hw->adap, reg->addr, reg->val);

	return CSIO_SUCCESS;
} /* csio_hw_write_reg */

static csio_retval_t
csio_hw_get_mbox(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
/*	
	csio_iomem_t addr 		= (csio_iomem_t)0;
	csio_iomem_t ctrl 		= (csio_iomem_t)0;
*/
	uint32_t addr = 0;
	uint32_t ctrl = 0;

	csio_mailbox_data_t *mbox_data	= buffer;
	uint64_t *mbox_buffer 		= NULL;	
	int i = 0, j = 0;

	if (buffer_len < (uint32_t)sizeof(csio_mailbox_data_t))
		return CSIO_NOMEM;
	
/*	addr = CSIO_REG(hw, PF_REG(mbox_data->number, A_CIM_PF_MAILBOX_DATA)); */
/*	ctrl = addr + CSIO_MAX_MB_SIZE; */
	addr = PF_REG(mbox_data->number, A_CIM_PF_MAILBOX_DATA);
	ctrl = addr + CSIO_MAX_MB_SIZE;
	mbox_buffer = (uint64_t *)mbox_data->buffer;

	mbox_data->owner_info = (uint32_t)G_MBOWNER(
				t4_read_reg(&hw->adap, ctrl));

	for (i = 0, j = 0; i < CSIO_MAX_MB_SIZE; i += 8, j++)
		mbox_buffer[j] = t4_read_reg64(&hw->adap, (addr + i));

	return CSIO_SUCCESS;
} /* csio_hw_get_mbox */

static csio_retval_t
csio_hw_get_cim_qcfg(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	csio_cim_q_config_t *cim_q_cfg = buffer;
	uint32_t size = 4 * (CSIO_CIM_NUM_IBQ + CSIO_CIM_NUM_OBQ);
	int i = 0;
	
	if (buffer_len < (uint32_t)sizeof(csio_cim_q_config_t))
		return CSIO_NOMEM;

	i = t4_cim_read(&hw->adap, A_UP_IBQ_0_RDADDR, size, cim_q_cfg->stat);

	if (!i)
		i = t4_cim_read(&hw->adap, A_UP_OBQ_0_REALADDR,
			(2 * CSIO_CIM_NUM_OBQ), cim_q_cfg->obq_wr);
	
	if (i)
		return CSIO_INVAL;

	t4_read_cimq_cfg(&hw->adap, cim_q_cfg->base, cim_q_cfg->size,
						cim_q_cfg->thres);
	
	return CSIO_SUCCESS;
} /* csio_hw_get_cim_qcfg */

static csio_retval_t
csio_hw_get_cim_la(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	csio_cim_la_t *cim_la = buffer;
	uint32_t cfg = 0;
	int ret = 0;	

	if (buffer_len < (uint32_t)sizeof(csio_cim_la_t))
		return CSIO_NOMEM;

	ret = t4_cim_read(&hw->adap, A_UP_UP_DBG_LA_CFG, 1, &cfg);

	if (ret)
		return CSIO_INVAL;

	cim_la->complete_data = !(cfg & F_UPDBGLACAPTPCONLY);

	if (t4_read_reg(&hw->adap, A_SGE_PC0_REQ_BIST_CMD) != 0xffffffff)
		cim_la->size  = 2 * CIMLA_SIZE;
	else
		cim_la->size = CIMLA_SIZE;
	
	ret = t4_cim_read_la(&hw->adap, (uint32_t *)cim_la->buffer, NULL);

	return (ret) ? CSIO_INVAL : CSIO_SUCCESS;
} /* csio_hw_get_cim_la */

static csio_retval_t
csio_hw_get_cim_pif_la(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	csio_cim_pifla_t *cim_pifla = buffer;

	if (buffer_len < (uint32_t)sizeof(csio_cim_pifla_t))
		return CSIO_NOMEM;

	t4_cim_read_pif_la(&hw->adap, (uint32_t *)cim_pifla->buffer,
		(uint32_t *)cim_pifla->buffer + 6 * CSIO_CIM_PIFLA_SIZE,
		NULL, NULL);

	return CSIO_SUCCESS;
} /* csio_hw_get_cim_pif_la */

static csio_retval_t
csio_hw_get_cim_ma_la(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	csio_cim_mala_t *cim_mala = buffer;

	if (buffer_len < (uint32_t)sizeof(csio_cim_mala_t))
		return CSIO_NOMEM;

	t4_cim_read_ma_la(&hw->adap, (uint32_t *)cim_mala->buffer,
		(uint32_t *)cim_mala->buffer + 5 * CSIO_CIM_MALA_SIZE);

	return CSIO_SUCCESS;
} /* csio_hw_get_cim_ma_la */


static csio_retval_t
csio_hw_get_tp_la(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	csio_tp_la_data_t *tpla = buffer;

	if (buffer_len < (uint32_t)sizeof(csio_tp_la_data_t))
		return CSIO_NOMEM;

	tpla->dbg_la_mode = G_DBGLAMODE(t4_read_reg(&hw->adap, A_TP_DBG_LA_CONFIG));

	t4_tp_read_la(&hw->adap, (uint64_t *)tpla->buffer, NULL);

	return CSIO_SUCCESS;
} /* csio_hw_get_tp_la */

static csio_retval_t
csio_hw_get_ulprx_la(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	csio_ulprx_la_data_t *ulprx_la = buffer;

	if (buffer_len < (uint32_t)sizeof(csio_ulprx_la_data_t))
		return CSIO_NOMEM;

	t4_ulprx_read_la(&hw->adap, (uint32_t *)ulprx_la->buffer);

	return CSIO_SUCCESS;
} /* csio_hw_get_ulprx_la */

static inline void
tcamxy2valmask(uint64_t x, uint64_t y, uint8_t *addr, uint64_t *mask)
{
	*mask = x | y;
	y = csio_cpu_to_be64(y);
	csio_memcpy(addr, (uint8_t *)&y + 2, CSIO_ETH_ALEN);
} /* tcamxy2valmask */

static csio_retval_t
csio_hw_get_mps_tcam(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	csio_mps_tcam_data_t *mps_tcam = buffer;

	if (buffer_len < (uint32_t)sizeof(csio_mps_tcam_data_t))
		return CSIO_NOMEM;

	mps_tcam->tcamy	= t4_read_reg64(&hw->adap,
				MPS_CLS_TCAM_Y_L(mps_tcam->index));
	mps_tcam->tcamx = t4_read_reg64(&hw->adap,
				MPS_CLS_TCAM_X_L(mps_tcam->index));
	mps_tcam->cls_low = t4_read_reg(&hw->adap,
				MPS_CLS_SRAM_L(mps_tcam->index));
	mps_tcam->cls_hi = t4_read_reg(&hw->adap,
				MPS_CLS_SRAM_H(mps_tcam->index));

	if ((mps_tcam->tcamx) & (mps_tcam->tcamy))
		return CSIO_SUCCESS;

	tcamxy2valmask(mps_tcam->tcamx, mps_tcam->tcamy,
			mps_tcam->eth_addr, &mps_tcam->mask);

	return CSIO_SUCCESS;
} /* csio_hw_get_mps_tcam */
	
static csio_retval_t
csio_hw_get_cim_ibq(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	csio_cim_ibq_t *cim_ibq = buffer;

	if (buffer_len < (uint32_t)sizeof(csio_cim_ibq_t))
		return CSIO_NOMEM;

	t4_read_cim_ibq(&hw->adap, cim_ibq->queue_id,
			(uint32_t *)cim_ibq->buffer,
			CSIO_CIM_IBQ_SIZE * 4);

	return CSIO_SUCCESS;
} /* csio_hw_get_cim_ibq */

static csio_retval_t
csio_hw_get_cim_obq(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	csio_cim_obq_t *cim_obq = buffer;

	if (buffer_len < (uint32_t)sizeof(csio_cim_obq_t))
		return CSIO_NOMEM;

	t4_read_cim_obq(&hw->adap, cim_obq->queue_id,
			(uint32_t *)cim_obq->buffer,
			6 * CSIO_CIM_IBQ_SIZE * 4);

	return CSIO_SUCCESS;
} /* csio_hw_get_cim_obq */

static csio_retval_t
csio_hw_get_cpl_stats(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	csio_tp_cpl_stats_t *stats = buffer;

	if (buffer_len < (uint32_t)sizeof(csio_tp_cpl_stats_t))
		return CSIO_NOMEM;

	t4_tp_get_cpl_stats(&hw->adap, (struct tp_cpl_stats *)stats);

	return CSIO_SUCCESS;
} /* csio_hw_get_cpl_stats */

static csio_retval_t
csio_hw_get_ddp_stats(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	csio_tp_usm_stats_t *stats = buffer;

	if (buffer_len < (uint32_t)sizeof(csio_tp_usm_stats_t))
		return CSIO_NOMEM;

	t4_get_usm_stats(&hw->adap, (struct tp_usm_stats *)stats);

	return CSIO_SUCCESS;
} /* csio_hw_get_ddp_stats */

static csio_retval_t
csio_hw_get_tp_err_stats(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	csio_tp_err_stats_t *stats = buffer;

	if (buffer_len < (uint32_t)sizeof(csio_tp_err_stats_t))
		return CSIO_NOMEM;

	t4_tp_get_err_stats(&hw->adap, (struct tp_err_stats *)stats);

	return CSIO_SUCCESS;
} /* csio_hw_get_tp_err_stats */

static csio_retval_t
csio_hw_get_tcp_stats(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	csio_tp_tcp_stats_t *v4 = NULL;
	csio_tp_tcp_stats_t *v6 = NULL;

	if (buffer_len < (uint32_t)(sizeof(csio_tp_tcp_stats_t) * 2))
		return CSIO_NOMEM;

	v4 = (csio_tp_tcp_stats_t *)buffer;
	v6 = (csio_tp_tcp_stats_t *)((uintptr_t)v4 +
			sizeof(csio_tp_tcp_stats_t));

	t4_tp_get_tcp_stats(&hw->adap, (struct tp_tcp_stats *)v4,
				(struct tp_tcp_stats *)v6);

	return CSIO_SUCCESS;
} /* csio_hw_get_tcp_stats */

static csio_retval_t
csio_hw_get_pm_stats(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	csio_pm_stats_t *pm = buffer;

	if (buffer_len < (uint32_t)sizeof(csio_pm_stats_t))
		return CSIO_NOMEM;

	t4_pmtx_get_stats(&hw->adap, pm->tx_cnt, pm->tx_cyc);
	t4_pmrx_get_stats(&hw->adap, pm->rx_cnt, pm->rx_cyc);

	return CSIO_SUCCESS;
} /* csio_hw_get_pm_stats */

static csio_retval_t
csio_hw_get_lbstats(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	struct lb_port_stats s;
	csio_lb_port_stats_t *lb_stat_req = buffer;

	if (buffer_len < (uint32_t)(sizeof(csio_lb_port_stats_t)))
		return CSIO_NOMEM;

	t4_get_lb_stats(&hw->adap, lb_stat_req->idx, &s);

	lb_stat_req->octets		= s.octets;
	lb_stat_req->frames		= s.frames;
	lb_stat_req->bcast_frames	= s.bcast_frames;
	lb_stat_req->mcast_frames	= s.mcast_frames;
	lb_stat_req->ucast_frames	= s.ucast_frames;
	lb_stat_req->error_frames	= s.error_frames;

	lb_stat_req->frames_64		= s.frames_64;
	lb_stat_req->frames_65_127	= s.frames_65_127;
	lb_stat_req->frames_128_255	= s.frames_128_255;
	lb_stat_req->frames_256_511	= s.frames_256_511;
	lb_stat_req->frames_512_1023	= s.frames_512_1023;
	lb_stat_req->frames_1024_1518	= s.frames_1024_1518;
	lb_stat_req->frames_1519_max	= s.frames_1519_max;

	lb_stat_req->drop		= s.drop;

	lb_stat_req->ovflow0		= s.ovflow0;
	lb_stat_req->ovflow1		= s.ovflow1;
	lb_stat_req->ovflow2		= s.ovflow2;
	lb_stat_req->ovflow3		= s.ovflow3;
	lb_stat_req->trunc0		= s.trunc0;
	lb_stat_req->trunc1		= s.trunc1;
	lb_stat_req->trunc2		= s.trunc2;
	lb_stat_req->trunc3		= s.trunc3;

	return CSIO_SUCCESS;
} /* csio_hw_get_lb_stats */

static csio_retval_t
csio_hw_get_internal_mem(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	t4_mem_desc_t *mem = buffer;
	uint8_t *buf = NULL;
	int mem_type = -1;
	int pos = -1, count = 0;
	int ret;
	__be32 *data;
	struct adapter *adap = &hw->adap;

	if (buffer_len < (uint32_t)sizeof(t4_mem_desc_t))
		return CSIO_NOMEM;

	if (buffer_len < (uint32_t)(sizeof(t4_mem_desc_t) +
				mem->embedded_buf_size - sizeof(char)))
		return CSIO_NOMEM;

	/* Initialize mem_type */
	mem_type= mem->mem_type;

	pos	= mem->offset;
	buf	= mem->embedded_buf;
	count	= mem->embedded_buf_size;

	if (pos < 0)
		return -EINVAL;

	data = t4_alloc_mem(count);
	if (!data)
		return -ENOMEM;

	spin_lock(&adap->win0_lock);
	ret = t4_memory_rw(adap, adap->params.drv_memwin, mem_type, pos, count,
			data, T4_MEMORY_READ);
	spin_unlock(&adap->win0_lock);

	if (ret) {
		t4_free_mem(data);
		return ret;
	}
	ret = copy_to_user(buf, data, count);
	t4_free_mem(data);
	if (ret)
		return -EFAULT;

	/* Update the offset pointer */
	mem->offset += count;

	CSIO_DB_ASSERT(count == 0);

	return CSIO_SUCCESS;

} /* csio_hw_get_internal_mem */

static csio_retval_t
csio_hw_get_devlog_info(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	csio_fwdevlog_info_t *fwdevlog_info = buffer;

	if (buffer_len < (uint32_t)sizeof(csio_fwdevlog_info_t))
		return CSIO_NOMEM;

	fwdevlog_info->memtype	= hw->adap.params.devlog.memtype;
	fwdevlog_info->start	= hw->adap.params.devlog.start;
	fwdevlog_info->size	= hw->adap.params.devlog.size;

	return CSIO_SUCCESS;

} /* csio_hw_get_devlog_info */

static csio_retval_t
csio_hw_card_reset_handler(struct csio_hw *hw, void *buffer,
			uint32_t buffer_len)
{
	csio_dbg(hw, "(User/IOCTL Request) Resetting hardware!\n");

	/* Reset the adapter! */
	csio_spin_lock_irq(hw, &hw->lock);
	csio_hw_reset(hw);
	csio_spin_unlock_irq(hw, &hw->lock);

	return CSIO_SUCCESS;

} /* csio_hw_do_card_reset */

static csio_retval_t
csio_hw_get_sge_context(struct csio_hw *hw, void *buffer,
			uint32_t buffer_len)
{
	csio_sge_ctx_t *sge_ctx = buffer;
	int32_t status = 0;

	if (buffer_len < (uint32_t)sizeof(csio_sge_ctx_t))
		return CSIO_NOMEM;

	status = t4_sge_ctxt_rd_bd(&hw->adap, sge_ctx->cntx_id,
			sge_ctx->cntx_type, (uint32_t *)sge_ctx->buf);

	if (status != 0)
		return CSIO_INVAL;

	return CSIO_SUCCESS;
} /* csio_hw_get_sge_context */

static csio_retval_t
csio_hw_get_cim_diags(struct csio_hw *hw, void *buffer,
			uint32_t buffer_len)
{
	struct adapter *adap = &hw->adap;
	csio_cim_diag_info_t *info = buffer;
	uint32_t param[1], val[1];
	int ret;

	if (buffer_len < (uint32_t)sizeof(csio_cim_diag_info_t))
		return CSIO_NOMEM;

	/* Initialize the buffer */
	csio_memset(info, 0, sizeof(csio_cim_diag_info_t));
	info->cim_load = -1;
	info->cim_tmp = -1;

	/* Get CIM load information. */
	param[0] = FW_PARAM_DEV(LOAD);

	/* Get CIM temparature and other diag information. */

	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1, param, val);
	if (ret < 0)
		return CSIO_INVAL;

	/* Cache the info. */
	info->cim_load = val[0];
	/*info->cim_tmp = param[1];*/

	return CSIO_SUCCESS;
} /* csio_hw_get_cim_diags */

static csio_retval_t
csio_copy_adapter_info(struct csio_hw *hw, void *buffer,
			uint32_t buffer_len)
{
	csio_adapter_info_t *info = buffer;

	if (buffer_len < (uint32_t)sizeof(csio_adapter_info_t))
		return CSIO_NOMEM;

	csio_memset(info, 0, sizeof(csio_adapter_info_t));
	info->adapter_handle = (uintptr_t)hw->os_hwp;

	return CSIO_SUCCESS;
} /* csio_copy_adapter_info */

/**
 * csio_hw_ioctl_handler - Chelsio HW IOCTL handler
 * @hw - HW module
 * @opcode - HW IOCTL opcode
 *
 */
csio_retval_t
csio_hw_ioctl_handler(struct csio_hw *hw, uint32_t opcode, void *buffer,
		uint32_t buffer_len)
{
	enum csio_oss_error rv = CSIO_SUCCESS;

	switch (opcode) {

		case CSIO_HW_SHOW:
			rv = csio_hw_show(hw, buffer, buffer_len);
			break;

		case CSIO_HW_GET_SGE_Q_INFO:
			rv = csio_get_sge_q_info(hw, buffer, buffer_len);
			break;

		case CSIO_HW_GET_SGE_FLQ_BUF_INFO:
			rv = csio_get_sge_flq_buf_info(hw, buffer, buffer_len);
			break;

		case CSIO_HW_GET_SCSI_STATS:
			rv = csio_hw_get_scsi_stats(hw, buffer, buffer_len);
			break;			
		
		case CSIO_HW_READ_REGISTER:
			rv = csio_hw_read_reg(hw, buffer, buffer_len);
			break;			

		case CSIO_HW_WRITE_REGISTER:
			rv = csio_hw_write_reg(hw, buffer, buffer_len);
			break;	

		case CSIO_HW_GET_MBOX:
			rv = csio_hw_get_mbox(hw, buffer, buffer_len);
			break;

		case CSIO_HW_GET_CIM_QCFG:
			rv = csio_hw_get_cim_qcfg(hw, buffer, buffer_len);
			break;

		case CSIO_HW_GET_CIM_LA:
			rv = csio_hw_get_cim_la(hw, buffer, buffer_len);
			break;

		case CSIO_HW_GET_CIM_PIF_LA:
			rv = csio_hw_get_cim_pif_la(hw, buffer, buffer_len);
			break;

		case CSIO_HW_GET_CIM_MA_LA:
			rv = csio_hw_get_cim_ma_la(hw, buffer, buffer_len);
			break;

		case CSIO_HW_GET_TP_LA:
			rv = csio_hw_get_tp_la(hw, buffer, buffer_len);
			break;

		case CSIO_HW_GET_ULPRX_LA:
			rv = csio_hw_get_ulprx_la(hw, buffer, buffer_len);
			break;

		case CSIO_HW_GET_MPS_TCAM:
			rv = csio_hw_get_mps_tcam(hw, buffer, buffer_len);
			break;

		case CSIO_HW_GET_CIM_IBQ:
			rv = csio_hw_get_cim_ibq(hw, buffer, buffer_len);
			break;			

		case CSIO_HW_GET_CIM_OBQ:
			rv = csio_hw_get_cim_obq(hw, buffer, buffer_len);
			break;

		case CSIO_HW_GET_CPL_STATS:
			rv = csio_hw_get_cpl_stats(hw, buffer, buffer_len);
			break;			

		case CSIO_HW_GET_DDP_STATS:
			rv = csio_hw_get_ddp_stats(hw, buffer, buffer_len);
			break;

		case CSIO_HW_GET_TP_ERR_STATS:
			rv = csio_hw_get_tp_err_stats(hw, buffer, buffer_len);
			break;

		case CSIO_HW_GET_TCP_STATS:
			rv = csio_hw_get_tcp_stats(hw, buffer, buffer_len);
			break;

		case CSIO_HW_GET_PM_STATS:
			rv = csio_hw_get_pm_stats(hw, buffer, buffer_len);
			break;

		case CSIO_HW_GET_LB_STATS:
			rv = csio_hw_get_lbstats(hw, buffer, buffer_len);
			break;

		case CSIO_HW_GET_INTERNAL_MEM:
			rv = csio_hw_get_internal_mem(hw, buffer, buffer_len);
			break;

		case CSIO_HW_GET_FWDEVLOG_INFO:
			rv = csio_hw_get_devlog_info(hw, buffer, buffer_len);
			break;

		case CSIO_HW_GET_CARD_INFO:
			//rv = csio_hw_get_card_info();
			break;

		case CSIO_HW_GET_PORT_STATS:
			//rv = t4_get_port_stats(&hw->adap,,);
			break;

		case CSIO_HW_CARD_RESET:
			rv = csio_hw_card_reset_handler(hw, buffer, buffer_len);
			break;
			
		case CSIO_HW_FUNCTION_RESET:
			//rv = csio_hw_fn_reset_handler();
			break;
			
		case CSIO_HW_PROBE:
			/*
			 * Validity of the IOCTL is verified
			 * at the CDHI (OS specific) code
			 * itself. Copy the adapter specific
			 * information and return.
			 *
			 */
			rv = csio_copy_adapter_info(hw, buffer, buffer_len);
			break;

		case CSIO_HW_GET_SGE_CNTX:
			rv = csio_hw_get_sge_context(hw, buffer, buffer_len);
			break;
		
		case CSIO_HW_GET_DCBX_INFO:
			rv = csio_hw_get_dcbx_info(hw, buffer, buffer_len);
			break;

		case CSIO_HW_GET_CIM_DIAGS:
			rv = csio_hw_get_cim_diags(hw, buffer, buffer_len);
			break;

		case CSIO_HW_PORT_DCB_PARAMS:
		default:
			rv = CSIO_INVAL;

	} /* switch */

	return rv;
} /* csio_hw_ioctl_handler */

/*****************************************************************************/
/* HW State machine assists                                                  */
/*****************************************************************************/

static csio_retval_t
csio_hw_dev_ready(struct csio_hw *hw)
{
	__VOLATILE uint32_t	whoami;
	int			ret;

	ret = t4_wait_dev_ready(&hw->adap);
	whoami = t4_read_reg(&hw->adap, A_PL_WHOAMI);
	if (ret) {
		csio_err(hw, "PL_WHOAMI returned %#x\n", whoami);
		return CSIO_EIO;
	}

	hw->pfn = (CHELSIO_CHIP_VERSION(hw->adap.params.chip) <= CHELSIO_T5
		   ? G_SOURCEPF(whoami)
		   : G_T6_SOURCEPF(whoami));
	hw->adap.pf = hw->pfn;
	hw->adap.mbox = hw->pfn;

	return CSIO_SUCCESS;
}

/**
 * csio_do_hello - Perform the HELLO FW Mailbox command and process response.
 * @hw: HW module
 * @state: Device state
 *
 * FW_HELLO_CMD has to be polled for completion.
 */
static csio_retval_t
csio_do_hello(struct csio_hw *hw, enum dev_state *state)
{
	struct adapter *adap = &hw->adap;
	char state_str[16];
	int mpfn;

	/*
	 * Contact FW, advertising Master capability.
	 */
	mpfn = t4_fw_hello(adap, adap->mbox, adap->mbox, MASTER_MAY, state);

	switch (*state) {
	case DEV_STATE_UNINIT:
		csio_strcpy(state_str, "initializing");
		break;
	case DEV_STATE_INIT:
		csio_strcpy(state_str, "Initialized");
		break;
	case DEV_STATE_ERR:
		csio_strcpy(state_str, "Error");
		break;
	default:
		csio_strcpy(state_str, "Unknown");
		break;
	}

	if (mpfn < 0)
		return CSIO_INVAL;

	if (mpfn == adap->mbox) {
		hw->flags |= CSIO_HWF_MASTER;
		csio_info(hw, "PF: %d, Coming up as MASTER, HW state: %s\n",
			adap->mbox, state_str);
	} else {
		hw->flags &= ~CSIO_HWF_MASTER;
		csio_info(hw, "PF: %d, Coming up as SLAVE, Master PF: %d, "
			 "HW state: %s\n", adap->mbox, mpfn, state_str);
	}

	return CSIO_SUCCESS;
}

/**
 * csio_do_bye - Perform the BYE FW Mailbox command and process response.
 * @hw: HW module
 *
 */
static csio_retval_t
csio_do_bye(struct csio_hw *hw)
{
	struct adapter *adap = &hw->adap;
	int ret;

	if (csio_exit_no_mb)
		return CSIO_SUCCESS;

	csio_spin_unlock_irq(hw, &hw->lock);
	ret = t4_fw_bye(adap, adap->mbox);
	csio_spin_lock_irq(hw, &hw->lock);

	return (ret < 0) ? CSIO_INVAL : CSIO_SUCCESS;
}

/**
 * csio_do_reset- Perform the device reset.
 * @hw: HW module
 * @fw_rst: FW reset
 *
 * If fw_rst is set, issues FW reset mbox cmd otherwise
 * does PIO reset.
 * Performs reset of the function.
 */
static csio_retval_t
csio_do_reset(struct csio_hw *hw, bool fw_rst)
{
	struct adapter *adap = &hw->adap;
	int ret;

	if (!fw_rst) {
		/* PIO reset */
		t4_write_reg(&hw->adap, A_PL_RST, F_PIORSTMODE | F_PIORST);
		csio_mdelay(2000);
		return CSIO_SUCCESS;
	}

	csio_spin_unlock_irq(hw, &hw->lock);
	ret = t4_fw_reset(adap, adap->mbox, F_PIORSTMODE | F_PIORST);
	csio_spin_lock_irq(hw, &hw->lock);

	return (ret < 0) ? CSIO_INVAL : CSIO_SUCCESS;
}

static csio_retval_t
csio_hw_validate_caps(struct csio_hw *hw, struct fw_caps_config_cmd *rsp)
{
	uint16_t caps;
	
	if (csio_is_fcoe(hw)) {
		caps = csio_ntohs(rsp->fcoecaps);

		if (csio_initiator_mode(hw) &&
			(!(caps & FW_CAPS_CONFIG_FCOE_INITIATOR))) {
			csio_err(hw, "No FCoE Initiator capability "
				 "in the firmware.\n");
			return CSIO_INVAL;
		}
			
		if (csio_target_mode(hw) &&
			(!(caps & FW_CAPS_CONFIG_FCOE_TARGET))) {
			csio_err(hw, "No FCoE Target capability "
				 "in the firmware.\n");
			return CSIO_INVAL;
		}

		if (!(caps & FW_CAPS_CONFIG_FCOE_CTRL_OFLD)) {
			csio_err(hw, "No FCoE Control Offload capability\n");
			return CSIO_INVAL;
		}
		
	} else {
		caps = csio_ntohs(rsp->iscsicaps);
	}

	return CSIO_SUCCESS;
}


/**
 *	csio_hw_fw_config_file - setup an adapter via a Configuration File
 *	@hw: the HW module
 * 	@mbox: mailbox to use for the FW command
 *	@mtype: the memory type where the Configuration File is located
 *	@maddr: the memory address where the Configuration File is located
 *	@finiver: return value for CF [fini] version
 *	@finicsum: return value for CF [fini] checksum
 *	@cfcsum: return value for CF computed checksum
 *
 *	Issue a command to get the firmware to process the Configuration
 *	File located at the specified mtype/maddress.  If the Configuration
 *	File is processed successfully and return value pointers are
 *	provided, the Configuration File "[fini] section version and
 *	checksum values will be returned along with the computed checksum.
 *	It's up to the caller to decide how it wants to respond to the
 *	checksums not matching but it recommended that a prominant warning
 *	be emitted in order to help people rapidly identify changed or
 *	corrupted Configuration Files.
 *
 *	Also note that it's possible to modify things like "niccaps",
 *	"toecaps",etc. between processing the Configuration File and telling
 *	the firmware to use the new configuration.  Callers which want to
 *	do this will need to "hand-roll" their own CAPS_CONFIGS commands for
 *	Configuration Files if they want to do this.
 */
static csio_retval_t
csio_hw_fw_config_file(struct csio_hw *hw, uint32_t *using_flash,
		      unsigned int mtype, unsigned int maddr,
		      uint32_t *finiver, uint32_t *finicsum, uint32_t *cfcsum)
{
	struct adapter *adap = &hw->adap;
	struct fw_caps_config_cmd caps_cmd;
	enum csio_oss_error ret;

	/*
	 * Issue a Capability Configuration command to the firmware to get it
	 * to parse the Configuration File.  We don't use t4_fw_config_file()
	 * because we want the ability to modify various features after we've
	 * processed the configuration file ...
	 */
	memset(&caps_cmd, 0, sizeof(caps_cmd));
	caps_cmd.op_to_write =
		htonl(V_FW_CMD_OP(FW_CAPS_CONFIG_CMD) |
				F_FW_CMD_REQUEST |
				F_FW_CMD_READ);
	caps_cmd.cfvalid_to_len16 =
		htonl(F_FW_CAPS_CONFIG_CMD_CFVALID |
				V_FW_CAPS_CONFIG_CMD_MEMTYPE_CF(mtype) |
				V_FW_CAPS_CONFIG_CMD_MEMADDR64K_CF(maddr >> 16) |
				FW_LEN16(caps_cmd));
	ret = t4_wr_mbox(adap, adap->mbox, &caps_cmd, sizeof(caps_cmd),
			&caps_cmd);

	/*
	 * If the CAPS_CONFIG failed with an ENOENT (for a Firmware
	 * Configuration File in FLASH), our last gasp effort is to use the
	 * Firmware Configuration File which is embedded in the firmware. A
	 * very few early versions of the firmware didn't have one embedded
	 * but we can ignore those.
	 */
	if (ret == -CSIO_NOENT) {
		memset(&caps_cmd, 0, sizeof(caps_cmd));
		caps_cmd.op_to_write =
			htonl(V_FW_CMD_OP(FW_CAPS_CONFIG_CMD) |
					F_FW_CMD_REQUEST |
					F_FW_CMD_READ);
		caps_cmd.cfvalid_to_len16 = htonl(FW_LEN16(caps_cmd));
		ret = t4_wr_mbox(adap, adap->mbox, &caps_cmd,
				sizeof(caps_cmd), &caps_cmd);
		*using_flash = 2;
	}

	if (ret < 0)
		goto out;

	if (finiver)
		*finiver = csio_ntohl(caps_cmd.finiver);
	if (finicsum)
		*finicsum = csio_ntohl(caps_cmd.finicsum);
	if (cfcsum)
		*cfcsum = csio_ntohl(caps_cmd.cfcsum);

	/* Validate device capabilities */
	if (csio_hw_validate_caps(hw, &caps_cmd)) {
		ret = CSIO_NOSUPP;
		goto out;
	}

	/*
	 * And now tell the firmware to use the configuration we just loaded.
	 */
	caps_cmd.op_to_write =
		htonl(V_FW_CMD_OP(FW_CAPS_CONFIG_CMD) |
				F_FW_CMD_REQUEST |
				F_FW_CMD_WRITE);
	caps_cmd.cfvalid_to_len16 = htonl(FW_LEN16(caps_cmd));
	ret = t4_wr_mbox(adap, adap->mbox, &caps_cmd, sizeof(caps_cmd),	NULL);

out:
	return ret;
}

static csio_retval_t
csio_get_dcbx_info(struct csio_hw *hw, csio_dcbx_info_t *dcbx_info)
{
	struct adapter *adap = &hw->adap;
	struct fw_port_cmd c, *rsp;
	enum fw_port_dcb_type type;
	uint8_t	i;

	for( i = 0; i < CSIO_DCBX_NUM_PARAMS; i++ ) {
		csio_spin_lock_irq(hw, &hw->lock);
		switch (i) {
		case 0 :
			type = FW_PORT_DCB_TYPE_PGID;
			break;
		case 1 :
			type = FW_PORT_DCB_TYPE_PGRATE;
			break;
		case 2 :
			type = FW_PORT_DCB_TYPE_PRIORATE;
			break;
		case 3 :
			type = FW_PORT_DCB_TYPE_PFC;
			break;
		case 4 :
			type = FW_PORT_DCB_TYPE_APP_ID;
			break;
		default :
			csio_spin_unlock_irq(hw, &hw->lock);
			csio_dbg(hw, "CSIO: csio_get_dcbx_info: "
					"Type mismatch\n");
			return CSIO_INVAL;
		}
		csio_mb_dcbx_read_port_init_mb(&c, dcbx_info->portid,
				dcbx_info->action, type);
		csio_spin_unlock_irq(hw, &hw->lock);
		if (t4_wr_mbox(adap, adap->mbox, &c, sizeof(c), &c)) {
			csio_err(hw, "CSIO: Issue of DCBX PARAMS"
						"command failed!\n");
			return CSIO_INVAL;
		}
		csio_spin_lock_irq(hw, &hw->lock);

		rsp = &c;

		switch (type) {
		case FW_PORT_DCB_TYPE_PGID :
				dcbx_info->pgid =
					csio_be32_to_cpu(rsp->u.dcb.pgid.pgid);
				break;
		case FW_PORT_DCB_TYPE_PGRATE :
				dcbx_info->pg_num_tcs_supported =
					rsp->u.dcb.pgrate.num_tcs_supported;
				csio_memcpy(dcbx_info->pgrate,
					rsp->u.dcb.pgrate.pgrate, 8);
				csio_memcpy(dcbx_info->tsa,
					rsp->u.dcb.pgrate.tsa, 8);
				break;
		case FW_PORT_DCB_TYPE_PRIORATE :
				csio_memcpy(dcbx_info->strict_priorate,
					rsp->u.dcb.priorate.strict_priorate, 8);
				break;
		case FW_PORT_DCB_TYPE_PFC :
				dcbx_info->pfcen = rsp->u.dcb.pfc.pfcen;
				dcbx_info->pfc_num_tcs_supported =
					rsp->u.dcb.pfc.max_pfc_tcs;
				break;
		case FW_PORT_DCB_TYPE_APP_ID :
				dcbx_info->prio = rsp->u.dcb.
						app_priority.user_prio_map;
				dcbx_info->sel = rsp->u.dcb.
						app_priority.sel_field;
				dcbx_info->protocolid = csio_be16_to_cpu(
					rsp->u.dcb.app_priority.protocolid);
				break;
		default :
				csio_dbg(hw, "csio_get_dcbx_info : "
						"Type mismatch\n");
		}
		csio_spin_unlock_irq(hw, &hw->lock);
	}

	return CSIO_SUCCESS;	
}

csio_retval_t
csio_hw_get_dcbx_info(struct csio_hw *hw, void *buffer, uint32_t buffer_len)
{
	csio_dcbx_info_t   *dcbx_info = buffer;
	enum csio_oss_error rv;
	
	if (buffer_len < sizeof(csio_dcbx_info_t))
		return CSIO_NOMEM;

	rv = csio_get_dcbx_info(hw, dcbx_info);

	return rv;
}


/**
 * csio_get_device_params - Get device parameters.
 * @hw: HW module
 *
 */
static csio_retval_t
csio_get_device_params(struct csio_hw *hw)
{
	struct adapter *adap = &hw->adap;
	struct csio_wrm *wrm = csio_hw_to_wrm(hw);
	u32 param[7], val[7];
	int ret, i, j = 0;

	csio_spin_unlock_irq(hw, &hw->lock);

	/* Initialize portids to -1 */
	for (i = 0; i < CSIO_MAX_T4PORTS; i++)
		hw->t4port[i].portid = -1;

	/* Get port vec information. */
	param[0] = FW_PARAM_DEV(PORTVEC);

	/* Get Core clock. */
	param[1] = FW_PARAM_DEV(CCLK);

	/* Get EQ id start and end. */
	param[2] = FW_PARAM_PFVF(EQ_START);
	param[3] = FW_PARAM_PFVF(EQ_END);

	/* Get IQ id start and end. */
	param[4] = FW_PARAM_PFVF(IQFLINT_START);
	param[5] = FW_PARAM_PFVF(IQFLINT_END);

	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 6, param, val);
	if (ret < 0) {
		csio_spin_lock_irq(hw, &hw->lock);
		return CSIO_INVAL;
	}

	/* cache the information. */
	hw->port_vec = val[0];
	hw->adap.params.vpd.cclk = val[1];
	wrm->fw_eq_start = val[2];
	wrm->fw_iq_start = val[4];

	/* Using FW configured max iqs & eqs */
	if ((hw->flags & CSIO_HWF_USING_SOFT_PARAMS) ||
		!csio_is_hw_master(hw)) {
		hw->cfg_niq = val[5] - val[4] + 1;
		hw->cfg_neq = val[3] - val[2] + 1;
		csio_dbg(hw, "Using fwconfig max niqs %d neqs %d\n",
			hw->cfg_niq, hw->cfg_neq);
	}

	hw->port_vec &= csio_port_mask;

	hw->num_t4ports	= csio_hweight32(hw->port_vec);

	csio_dbg(hw, "Port vector: 0x%x, #ports: %d\n",
		    hw->port_vec, hw->num_t4ports);

	for (i = 0; i < hw->num_t4ports; i++) {
		while ((hw->port_vec & (1 << j)) == 0)
			j++;
		hw->t4port[i].portid = j++;
		csio_dbg(hw, "Found Port:%d\n", hw->t4port[i].portid);
	}

	csio_spin_lock_irq(hw, &hw->lock);

	return CSIO_SUCCESS;
}


/*
 * csio_config_device_caps - Get and set device capabilities.
 * @hw: HW module
 *
 */
static csio_retval_t
csio_config_device_caps(struct csio_hw *hw)
{
	struct adapter *adap = &hw->adap;
	struct fw_caps_config_cmd c;
	enum csio_oss_error rv = CSIO_INVAL;
	int ret;
	bool pdu = 0;
	bool cofld = 1;

	csio_spin_unlock_irq(hw, &hw->lock);

	/* Get device capabilities */
	csio_mb_caps_config(hw, &c, 0, 0, 0, 0, 0, 0);

	ret = t4_wr_mbox(adap, adap->mbox, &c, sizeof(c), &c);
       	if (ret) {
		csio_err(hw, "READ CAPS CONFIG cmd returned %d!\n", ret);
		goto out;
	}

	/* Validate device capabilities */
	if (csio_hw_validate_caps(hw, &c))
		goto out;

	/* Don't config device capabilities if already configured */
	if (hw->fw_state == DEV_STATE_INIT) {
		rv = CSIO_SUCCESS;
		goto out;
	}

	/* Write back desired device capabilities */
	csio_mb_caps_config(hw, &c, 1, csio_is_fcoe(hw),
			    csio_initiator_mode(hw), csio_target_mode(hw),
			    cofld, pdu);

	ret = t4_wr_mbox(adap, adap->mbox, &c, sizeof(c), NULL);
	if (ret) {
		csio_err(hw, "WRITE CAPS CONFIG cmd returned %d!\n", ret);
		goto out;
	}

	rv = CSIO_SUCCESS;
out:
	csio_spin_lock_irq(hw, &hw->lock);

	return rv;
}

/**
 * csio_get_devlog - Read firmware devlog parameters
 * @hw: HW module
 *
 */
static csio_retval_t
csio_get_devlog(struct csio_hw *hw)
{
	struct adapter *adap = &hw->adap;
	struct fw_devlog_cmd devlog_cmd;
	uint32_t devlog_meminfo;
	enum csio_oss_error ret;

	memset(&devlog_cmd, 0, sizeof devlog_cmd);
	devlog_cmd.op_to_write = htonl(V_FW_CMD_OP(FW_DEVLOG_CMD) |
			F_FW_CMD_REQUEST | F_FW_CMD_READ);
	devlog_cmd.retval_len16 = htonl(FW_LEN16(devlog_cmd));
	ret = t4_wr_mbox(adap, adap->mbox, &devlog_cmd, sizeof(devlog_cmd),
			&devlog_cmd);
	if (ret < 0)
		return ret;

	devlog_meminfo = ntohl(devlog_cmd.memtype_devlog_memaddr16_devlog);
	adap->params.devlog.memtype =
		G_FW_DEVLOG_CMD_MEMTYPE_DEVLOG(devlog_meminfo);
	adap->params.devlog.start =
		G_FW_DEVLOG_CMD_MEMADDR16_DEVLOG(devlog_meminfo) << 4;
	adap->params.devlog.size = ntohl(devlog_cmd.memsize_devlog);

	return ret;
}

static csio_retval_t
csio_config_global_rss(struct csio_hw *hw)
{
	struct adapter *adap = &hw->adap;
	int ret;

	csio_spin_unlock_irq(hw, &hw->lock);
	ret = t4_config_glbl_rss(adap, adap->mbox,
			FW_RSS_GLB_CONFIG_CMD_MODE_BASICVIRTUAL,
			F_FW_RSS_GLB_CONFIG_CMD_TNLMAPEN |
			F_FW_RSS_GLB_CONFIG_CMD_HASHTOEPLITZ |
			F_FW_RSS_GLB_CONFIG_CMD_TNLALLLKP);
	csio_spin_lock_irq(hw, &hw->lock);

	return (ret < 0) ? CSIO_INVAL : CSIO_SUCCESS;
}

/**
 * csio_config_pfvf - Configure Physical/Virtual functions settings.
 * @hw: HW module
 *
 */
static csio_retval_t
csio_config_pfvf(struct csio_hw *hw)
{
	struct adapter *adap = &hw->adap;
	int ret;

	csio_spin_unlock_irq(hw, &hw->lock);
	ret = t4_cfg_pfvf(adap, adap->mbox, adap->pf, 0,
			CSIO_NEQ, CSIO_NETH_CTRL, CSIO_NIQ_FLINT, 0,
			0, CSIO_NVI, CSIO_CMASK, CSIO_PMASK,
			CSIO_NEXACTF, CSIO_R_CAPS, CSIO_WX_CAPS);
	csio_spin_lock_irq(hw, &hw->lock);

	return (ret < 0) ? CSIO_INVAL : CSIO_SUCCESS;
}

/*
 * csio_enable_ports - Bring up all available ports.
 * @hw: HW module.
 *
 */
static csio_retval_t
csio_enable_ports(struct csio_hw *hw)
{
	struct adapter *adap = &hw->adap;
	struct fw_port_cmd c;
	int ret;
	uint8_t portid;
	int i;

	for (i = 0; i < hw->num_t4ports; i++) {
		portid = hw->t4port[i].portid;
		
		/* Read PORT information */
		csio_mb_port(&c, portid, CSIO_FALSE, 0, 0);

		csio_spin_unlock_irq(hw, &hw->lock);
		ret = t4_wr_mbox(adap, adap->mbox, &c, sizeof(c), &c);
		if (ret) {
			csio_err(hw, "PORT cmd(read) on port[%d] failed with "
				"ret 0x%x\n", portid, ret);
			csio_spin_lock_irq(hw, &hw->lock);
			return CSIO_INVAL;
		}
		csio_spin_lock_irq(hw, &hw->lock);

		hw->t4port[i].pcap = csio_ntohs(c.u.info.pcap);

		/* Write back PORT information */
		csio_mb_port(&c, portid, CSIO_TRUE, (PAUSE_RX | PAUSE_TX),
				hw->t4port[i].pcap);

		csio_spin_unlock_irq(hw, &hw->lock);
		ret = t4_wr_mbox(adap, adap->mbox, &c, sizeof(c), NULL);
		if (ret) {
			csio_err(hw, "PORT cmd(write) on port[%d] failed with "
				"ret:0x%x\n", portid, ret);
			csio_spin_lock_irq(hw, &hw->lock);
			return CSIO_INVAL;
		}
		csio_spin_lock_irq(hw, &hw->lock);
		
	} /* For all ports */

	return CSIO_SUCCESS;
}

/**
 * csio_get_fcoe_resinfo - Read fcoe fw resource info.
 * @hw: HW module
 * Issued with lock held.
 */
static csio_retval_t
csio_get_fcoe_resinfo(struct csio_hw *hw)
{
	struct adapter *adap = &hw->adap;
	struct csio_fcoe_res_info *res_info = &hw->un.fres_info;
	struct fw_fcoe_res_info_cmd c, *rsp;
	int ret;

	/* Get FCoE FW resource information */
	csio_fcoe_read_res_info_init_mb(&c);

	csio_spin_unlock_irq(hw, &hw->lock);
	ret = t4_wr_mbox(adap, adap->mbox, &c, sizeof(c), &c);
	if (ret) {
		csio_err(hw, "FCOE RESINFO cmd failed with ret x%x\n", ret);
		csio_spin_lock_irq(hw, &hw->lock);
		return CSIO_INVAL;
	}
	csio_spin_lock_irq(hw, &hw->lock);

	rsp = &c;

	res_info->e_d_tov = csio_ntohs(rsp->e_d_tov);
	res_info->r_a_tov_seq = csio_ntohs(rsp->r_a_tov_seq);
	res_info->r_a_tov_els = csio_ntohs(rsp->r_a_tov_els);
	res_info->r_r_tov = csio_ntohs(rsp->r_r_tov);
	res_info->max_xchgs = csio_ntohl(rsp->max_xchgs);
	res_info->max_ssns = csio_ntohl(rsp->max_ssns);
	res_info->used_xchgs = csio_ntohl(rsp->used_xchgs);
	res_info->used_ssns = csio_ntohl(rsp->used_ssns);
	res_info->max_fcfs = csio_ntohl(rsp->max_fcfs);
	res_info->max_vnps = csio_ntohl(rsp->max_vnps);
	res_info->used_fcfs = csio_ntohl(rsp->used_fcfs);
	res_info->used_vnps = csio_ntohl(rsp->used_vnps);

	return CSIO_SUCCESS;
}

#ifdef __CSIO_FOISCSI_ENABLED__
csio_retval_t
csio_enable_foiscsi_ipv6(struct csio_hw *hw)
{
	struct adapter *adap = &hw->adap;
	uint32_t param[1], val[1];
	int ret;

	param[0] = V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_CHNET) |
			    V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_CHNET_FLAGS);

	val[0] = FW_PARAMS_PARAM_CHNET_FLAGS_ENABLE_IPV6 |
		FW_PARAMS_PARAM_CHNET_FLAGS_ENABLE_DAD |
		FW_PARAMS_PARAM_CHNET_FLAGS_ENABLE_MLDV2;

	ret = t4_set_params(adap, adap->mbox, adap->pf, 0, 1,
					    param, val);
	if (ret) {
		csio_err(hw, "Foiscsi IPv6 not enabled, err 0x%x\n", ret);
		return CSIO_NOSUPP;
	}
	csio_info(hw, "Foiscsi IPv6 enabled\n");

	return CSIO_SUCCESS;
}
#endif

/*
 * HW initialization: contact FW, obtain config, perform basic init.
 *
 * If the firmware we're dealing with has Configuration File support, then
 * we use that to perform all configuration -- either using the configuration
 * file stored in flash on the adapter or using a filesystem-local file
 * if available.
 *
 * If we don't have configuration file support in the firmware, then we'll
 * have to set things up the old fashioned way with hard-coded register
 * writes and firmware commands ...
 */

/*
 * Attempt to initialize the HW via a Firmware Configuration File.
 */
static int
csio_hw_use_fwconfig(struct csio_hw *hw, int reset, u32 *fw_cfg_param)
{
	struct adapter *adap = &hw->adap;
	unsigned int mtype, maddr;
	enum csio_oss_error rv;
	uint32_t finiver = 0, finicsum = 0, cfcsum = 0;
	int using_flash;
	int ret;
	char path[64];

	/*
	 * Reset device if necessary
	 */
	if (reset) {
		ret = t4_fw_reset(adap, adap->mbox, F_PIORSTMODE | F_PIORST);
		if (ret < 0) {
			rv = CSIO_INVAL;
			goto bye;
		}	
	}	

	/* if this is a 10Gb/s-BT adapter, make sure the chip external
	 * 10GB/s-BT PHYs have up-to-date firmware. Note that this step needs
	 * to be performanced after any global adapter RESET above since some
	 * PHYs only have local RAM copies of the PHY firmware.
	 */
	if (csio_is_hw_10gbt_device(hw) && hw->os_ops->os_flash_hw_phy) {
		rv = hw->os_ops->os_flash_hw_phy(hw);
		if (rv != CSIO_SUCCESS)
			goto bye;
	}

	/*
	 * If we have a T4 configuration file in host ,
	 * then use that.  Otherwise, use the configuration file stored
	 * in the HW flash ...
	 */
	if (hw->os_ops->os_flash_config != NULL) {
		rv = hw->os_ops->os_flash_config(hw, fw_cfg_param, path);
		if (rv != CSIO_SUCCESS) {
			if (rv == CSIO_NOSUPP) {
				int cfg_addr = t4_flash_cfg_addr(adap);

				if (cfg_addr < 0) {
					rv = CSIO_INVAL;
					goto bye;
				}	

				using_flash = 1;
				mtype = FW_MEMTYPE_CF_FLASH;
				maddr = cfg_addr;
			}
			else
				goto bye;

		}
		else {
			mtype = G_FW_PARAMS_PARAM_Y(*fw_cfg_param);
			maddr = G_FW_PARAMS_PARAM_Z(*fw_cfg_param) << 16;
			using_flash = 0;
		}
	}
	else {
		int cfg_addr = t4_flash_cfg_addr(adap);

		if (cfg_addr < 0) {
			rv = CSIO_INVAL;
			goto bye;
		}	

		using_flash = 1;
		mtype = FW_MEMTYPE_CF_FLASH;
		maddr = cfg_addr;
	}

	hw->cfg_store = (uint8_t)mtype;
	csio_dbg(hw, "Flash Config Addr: mtype=%d, maddr=0x%x\n", mtype, maddr);

	/*
	 * Issue a Capability Configuration command to the firmware to get it
	 * to parse the Configuration File.
	 */
	rv = csio_hw_fw_config_file(hw, &using_flash, mtype, maddr, &finiver,
		&finicsum, &cfcsum);
	if (rv != CSIO_SUCCESS)
		goto bye;

	hw->cfg_finiver 	= finiver;
	hw->cfg_finicsum 	= finicsum;
	hw->cfg_cfcsum 		= cfcsum;
	hw->cfg_csum_status 	= CSIO_TRUE;

	if (finicsum != cfcsum) {
		csio_warn(hw, "Configuration File checksum mismatch: "
 	 		"[fini] csum=%#x, computed csum=%#x\n",
			finicsum, cfcsum);
		
		hw->cfg_csum_status = CSIO_FALSE;
	}

	/*
	 * Note that we're operating with parameters
	 * not supplied by the driver, rather than from hard-wired
	 * initialization constants buried in the driver.
	 */
	hw->flags |= CSIO_HWF_USING_SOFT_PARAMS;

	/* device parameters */
	csio_spin_lock_irq(hw, &hw->lock);
	rv = csio_get_device_params(hw);
	csio_spin_unlock_irq(hw, &hw->lock);
	if (rv != CSIO_SUCCESS)
		goto bye;

	/* Configure SGE */
	csio_wr_sge_init(hw);

	/*
	 * And finally tell the firmware to initialize itself using the
	 * parameters from the Configuration File.
	 */
	/* Post event to notify completion of configuration */
	csio_spin_lock_irq(hw, &hw->lock);
	csio_post_event(&hw->sm, CSIO_HWE_INIT);
	csio_spin_unlock_irq(hw, &hw->lock);

	csio_info(hw, "Successfully configured using Firmware "
		 "Configuration File %s, version %#x, computed checksum %#x\n",
		 (using_flash
		  ? (using_flash == 1 ? "On FLASH" : "Firmware Default")
		  : path),
		 finiver, cfcsum);
	return 0;

	/*
	 * Something bad happened.  Return the error ...
	 */
bye:
	hw->flags &= ~CSIO_HWF_USING_SOFT_PARAMS;
	csio_dbg(hw, "Configuration file error %d\n", rv);
	return rv;
}

static void
csio_hw_config_default_filter(struct csio_hw *hw)
{	
	u32 v = HW_TPL_FR_MT_PR_IV_P_FC;
	t4_write_indirect(&hw->adap, A_TP_PIO_ADDR, A_TP_PIO_DATA, &v, 1,
			  A_TP_VLAN_PRI_MAP);
	/*
	 * We need Five Tuple Lookup mode to be set in TP_GLOBAL_CONFIG order
	 * to support any of the compressed filter fields above.  Newer
	 * versions of the firmware do this automatically but it doesn't hurt
	 * to set it here.  Meanwhile, we do _not_ need to set Lookup Every
	 * Packet in TP_INGRESS_CONFIG to support matching non-TCP packets
	 * since the firmware automatically turns this on and off when we have
	 * a non-zero number of filters active (since it does have a
	 * performance impact).
	 */
	t4_set_reg_field(&hw->adap, A_TP_GLOBAL_CONFIG,
			 V_FIVETUPLELOOKUP(M_FIVETUPLELOOKUP),
			 V_FIVETUPLELOOKUP(M_FIVETUPLELOOKUP));

	/*
	 * Tweak some settings.
	 */
	t4_write_reg(&hw->adap, A_TP_SHIFT_CNT, V_SYNSHIFTMAX(6) |
		     V_RXTSHIFTMAXR1(4) | V_RXTSHIFTMAXR2(15) |
		     V_PERSHIFTBACKOFFMAX(8) | V_PERSHIFTMAX(8) |
		     V_KEEPALIVEMAXR1(4) | V_KEEPALIVEMAXR2(9));
}

/*
 * Attempt to initialize the adapter via hard-coded, driver supplied
 * parameters ...
 */
static int
csio_hw_no_fwconfig(struct csio_hw *hw, int reset)
{
	enum csio_oss_error rv;
	/*
	 * Reset device if necessary
	 */
	if (reset) {
		rv = csio_do_reset(hw, CSIO_TRUE);
		if (rv != CSIO_SUCCESS)
			goto out;
	}	

	/* if this is a 10Gb/s-BT adapter, make sure the chip external
	 * 10GB/s-BT PHYs have up-to-date firmware. Note that this step needs
	 * to be performanced after any global adapter RESET above since some
	 * PHYs only have local RAM copies of the PHY firmware.
	 */
	if (csio_is_hw_10gbt_device(hw) && hw->os_ops->os_flash_hw_phy) {
		rv = hw->os_ops->os_flash_hw_phy(hw);
		if (rv != CSIO_SUCCESS)
			goto out;
	}

	/* Get and set device capabilities */
	rv = csio_config_device_caps(hw);
	if (rv != CSIO_SUCCESS)
		goto out;

	/* Config Global RSS command */
	rv = csio_config_global_rss(hw);
	if (rv != CSIO_SUCCESS)
		goto out;

	/* Configure PF/VF capabilities of device */
	rv = csio_config_pfvf(hw);
	if (rv != CSIO_SUCCESS)
		goto out;

	/* device parameters */
	rv = csio_get_device_params(hw);
	if (rv != CSIO_SUCCESS)
		goto out;

	/* Configure SGE */
	csio_wr_sge_init(hw);

	/* Configure default filter */
	csio_hw_config_default_filter(hw);

	/* Post event to notify completion of configuration */
	csio_post_event(&hw->sm, CSIO_HWE_INIT);

out:
	return rv;
}

int
csio_hw_check_fwconfig(struct csio_hw *hw, u32 *param)
{
	struct adapter *adap = &hw->adap;
	u32 _param[1], val[1];
	int ret;


	/*
	 * Find out whether we're dealing with a version of
	 * the firmware which has configuration file support.
	 */
	_param[0] = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
		     V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_CF));

	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 1, _param, val);
	if (ret < 0) {
		csio_err(hw, "%s: Failed rv:%d\n", __func__, ret);
		return CSIO_INVAL;
	}

	*param = val[0];

	return CSIO_SUCCESS;
}

static void csio_setup_memwin(struct adapter *adap, uint32_t win)
{
	/* Note fw_attach values for csiostor & cxgb4 are opposites,
	 * hence we use compilment
	 */
	u32 csio_win_base = t4_get_util_window(adap, !csio_exit_no_mb);

	/* csiostor/foiscsi PCI-e memory window is already calculated for us */
	t4_setup_memwin(adap, csio_win_base, win);
}

/**
 * csio_hw_configure - Configure HW
 * @hw - HW module
 *
 */
static void
csio_hw_configure(struct csio_hw *hw)
{
	int reset = 1;
	enum csio_oss_error rv;
	u32 param[1];
	uint32_t win;
	u32 vers;

	rv = csio_hw_dev_ready(hw);
	if (rv != CSIO_SUCCESS) {
		CSIO_INC_STATS(hw, n_err_fatal);
		csio_post_event(&hw->sm, CSIO_HWE_FATAL);
		goto out;
	}

	/* Needed for FW download */
	rv = t4_get_flash_params(&hw->adap);
	if (rv != CSIO_SUCCESS) {
		csio_err(hw, "Failed to get serial flash params rv:%d\n", rv);
		csio_post_event(&hw->sm, CSIO_HWE_FATAL);
		goto out;
	}

	if (is_fpga(hw->adap.params.chip)) {
		/* FPGA */
		hw->adap.params.cim_la_size = 2 * CIMLA_SIZE;
	} else {
		/* ASIC */
		hw->adap.params.cim_la_size = CIMLA_SIZE;
	}

	/* Set pci completion timeout value to 4 seconds. */
	t4_os_find_pci_capability(&hw->adap, 0xd);

	win = csio_is_fcoe(hw) ? MEMWIN_CSIOSTOR : MEMWIN_FOISCSI;
	csio_spin_unlock_irq(hw, &hw->lock);
	csio_setup_memwin(&hw->adap, win);
	csio_spin_lock_irq(hw, &hw->lock);

	rv = csio_hw_get_fw_version(hw, &hw->fwrev);
	if (rv != CSIO_SUCCESS)
		goto out;

	csio_hw_print_fw_version(hw, "Firmware revision");

	if (csio_exit_no_mb) {
		csio_dbg(hw, "Exiting after issuing WHOAMI.\n");
		return;
	}

	csio_spin_unlock_irq(hw, &hw->lock);
	rv = csio_do_hello(hw, &hw->fw_state);
	csio_spin_lock_irq(hw, &hw->lock);
	if (rv != CSIO_SUCCESS) {
		CSIO_INC_STATS(hw, n_err_fatal);
		csio_post_event(&hw->sm, CSIO_HWE_FATAL);
		goto out;
	}

	/* Do firmware update */
	csio_spin_unlock_irq(hw, &hw->lock);
	if(hw->os_ops->os_flash_fw)
		rv = hw->os_ops->os_flash_fw(hw);
	else
		rv = CSIO_SUCCESS;
	csio_spin_lock_irq(hw, &hw->lock);

	if (rv != CSIO_SUCCESS)
		goto out;

	/* Read vpd */
	csio_spin_unlock_irq(hw, &hw->lock);
	rv = csio_hw_get_vpd_params(hw, &hw->adap.params.vpd);
	csio_spin_lock_irq(hw, &hw->lock);
	if (rv != CSIO_SUCCESS)
		goto out;

	csio_info(hw, "%s: S/N: %s, P/N: %s\n", hw->name,
		       hw->adap.params.vpd.sn, hw->adap.params.vpd.pn);

	if (!t4_get_exprom_version(&hw->adap, &vers)) {
		csio_info(hw, "OptionRom Version %u.%u.%u.%u.\n",
			G_FW_HDR_FW_VER_MAJOR(vers), G_FW_HDR_FW_VER_MINOR(vers),
			G_FW_HDR_FW_VER_MICRO(vers), G_FW_HDR_FW_VER_BUILD(vers));
		hw->optrom_ver = vers;
	}
	/*
	 * Read firmware device log parameters.  We really need to find a way
	 * to get these parameters initialized with some default values (which
	 * are likely to be correct) for the case where we either don't
	 * attache to the firmware or it's crashed when we probe the adapter.
	 * That way we'll still be able to perform early firmware startup
	 * debugging ...  If the request to get the Firmware's Device Log
	 * parameters fails, we'll live so we don't make that a fatal error.
	 */
	csio_spin_unlock_irq(hw, &hw->lock);
	csio_get_devlog(hw);
	csio_spin_lock_irq(hw, &hw->lock);

	if (hw->fw_state != DEV_STATE_INIT) {
		/*
		 * If the firmware doesn't support Configuration
		 * Files, use the old Driver-based, hard-wired
		 * initialization.  Otherwise, try using the
		 * Configuration File support and fall back to the
		 * Driver-based initialization if there's no
		 * Configuration File found.
		 */
		csio_spin_unlock_irq(hw, &hw->lock);
		if (csio_hw_check_fwconfig(hw, param) == CSIO_SUCCESS) {
			rv = csio_hw_use_fwconfig(hw, reset, param);
			if (rv != CSIO_SUCCESS) {
				csio_info(hw,
				    "No Configuration File present "
				    "on adapter.  Using hard-wired "
				    "configuration parameters.\n");
				csio_spin_lock_irq(hw, &hw->lock);
				rv = csio_hw_no_fwconfig(hw, reset);
				csio_spin_unlock_irq(hw, &hw->lock);
			}
		}
		else {
			csio_spin_lock_irq(hw, &hw->lock);
			rv = csio_hw_no_fwconfig(hw, reset);
			csio_spin_unlock_irq(hw, &hw->lock);
		}
		csio_spin_lock_irq(hw, &hw->lock);

		if (rv != CSIO_SUCCESS)
			goto out;

	} else {
		if (hw->fw_state == DEV_STATE_INIT) {

			hw->flags |= CSIO_HWF_USING_SOFT_PARAMS;

			/* device parameters */
			rv = csio_get_device_params(hw);
			if (rv != CSIO_SUCCESS)
				goto out;

			/* Get device capabilities */
			rv = csio_config_device_caps(hw);
			if (rv != CSIO_SUCCESS)
				goto out;

			/* Configure SGE */
			csio_wr_sge_init(hw);

			/* Post event to notify completion of configuration */
			csio_post_event(&hw->sm, CSIO_HWE_INIT);
		}
	} /* if not master */

out:
	return;
}

/**
 * csio_hw_initialize - Initialize HW
 * @hw - HW module
 *
 * For FCoE, provide a longer timeout (2s) to allow some time for FIP discovery
 * protocol to start in FW.
 */
static void
csio_hw_initialize(struct csio_hw *hw)
{
	struct adapter *adap = &hw->adap;
	enum csio_oss_error rv;
	int ret;
	int i;

	if (csio_is_hw_master(hw) && hw->fw_state != DEV_STATE_INIT) {
		/*
		 * And finally tell the firmware to initialize itself using the
		 * parameters from the Configuration File.
		 */
		csio_spin_unlock_irq(hw, &hw->lock);
		ret = t4_fw_initialize(adap, adap->mbox);
		csio_spin_lock_irq(hw, &hw->lock);
		if (ret < 0)
			goto out;
	}

	csio_spin_unlock_irq(hw, &hw->lock);
	t4_init_sge_params(&hw->adap);
	rv = csio_hw_to_ops(hw)->os_config_queues(hw);
	csio_spin_lock_irq(hw, &hw->lock);
	if (rv != CSIO_SUCCESS) {
		csio_err(hw, "Config of queues failed!: %d\n", rv);
		goto out;
	}

	for (i = 0; i < hw->num_t4ports; i++)
		hw->t4port[i].mod_type = FW_PORT_MOD_TYPE_NA;
	
	if (csio_is_hw_master(hw) && hw->fw_state != DEV_STATE_INIT) {
		rv = csio_enable_ports(hw);
		if (rv != CSIO_SUCCESS) {
			csio_err(hw, "Failed to enable ports: %d\n", rv);
			goto out;
		}
	}
	if (csio_is_fcoe(hw)) {
		rv = csio_get_fcoe_resinfo(hw);
		if (rv != CSIO_SUCCESS) {
			csio_err(hw, "Failed to read fcoe resource "
					"info: %d\n", rv);
			goto out;
		}
	} else {
#ifdef __CSIO_FOISCSI_ENABLED__
		csio_spin_unlock_irq(hw, &hw->lock);
		rv = csio_foiscsi_transport_init(hw);
		csio_spin_lock_irq(hw, &hw->lock);
		if (rv != CSIO_SUCCESS) {
			csio_err(hw, "Failed to initialize FOiSCSI "
					"transport: %d \n", rv);
			goto out;
		}
#endif
	}

	csio_post_event(&hw->sm, CSIO_HWE_INIT_DONE);
	return;

out:
	return;
}

/*****************************************************************************/
/* START: HW SM                                                              */
/*****************************************************************************/
/**
 * csio_hws_uninit - Uninit state
 * @hw - HW module
 * @evt - Event
 *
 */
static void
csio_hws_uninit(struct csio_hw *hw, csio_hw_ev_t evt)
{
	hw->prev_evt = hw->cur_evt;
	hw->cur_evt = evt;
	CSIO_INC_STATS(hw, n_evt_sm[evt]);

	switch(evt) {

	case CSIO_HWE_CFG:
		csio_set_state(&hw->sm, csio_hws_configuring);
		csio_hw_configure(hw);
		break;

	default:
		csio_warn(hw, "unexp hw event:%d received in "
			"hw state[uninit]\n", evt);
		CSIO_INC_STATS(hw, n_evt_unexp);
		break;
	}

	return;
}

/**
 * csio_hws_configuring - Configuring state
 * @hw - HW module
 * @evt - Event
 *
 */
static void
csio_hws_configuring(struct csio_hw *hw, csio_hw_ev_t evt)
{
	hw->prev_evt = hw->cur_evt;
	hw->cur_evt = evt;
	CSIO_INC_STATS(hw, n_evt_sm[evt]);

	switch(evt) {

	case CSIO_HWE_INIT:
		csio_set_state(&hw->sm, csio_hws_initializing);
		csio_hw_initialize(hw);
		break;

	case CSIO_HWE_INIT_DONE:
		csio_set_state(&hw->sm, csio_hws_ready);
		/* Fan out event to all lnode SMs */
		csio_notify_lnodes(hw, CSIO_LN_NOTIFY_HWREADY);
		break;

	case CSIO_HWE_FATAL:
		csio_set_state(&hw->sm, csio_hws_uninit);
		break;

	case CSIO_HWE_PCI_REMOVE:
		csio_do_bye(hw);
		break;
	default:
		csio_warn(hw, "unexp event:%d received in "
			"hw state[configuring]\n", evt);
		CSIO_INC_STATS(hw, n_evt_unexp);
		break;
	}

	return;
}

/**
 * csio_hws_initializing - Initialiazing state
 * @hw - HW module
 * @evt - Event
 *
 */
static void
csio_hws_initializing(struct csio_hw *hw, csio_hw_ev_t evt)
{
	hw->prev_evt = hw->cur_evt;
	hw->cur_evt = evt;
	CSIO_INC_STATS(hw, n_evt_sm[evt]);
	
	switch(evt) {

	case CSIO_HWE_INIT_DONE:
		csio_set_state(&hw->sm, csio_hws_ready);
		
		/* Fan out event to all lnode SMs */
		csio_notify_lnodes(hw, CSIO_LN_NOTIFY_HWREADY);

		/* Enable interrupts */
		csio_hw_intr_enable(hw);
		break;

	case CSIO_HWE_FATAL:
		csio_set_state(&hw->sm, csio_hws_uninit);
		break;

	case CSIO_HWE_PCI_REMOVE:
		csio_do_bye(hw);
		break;

	default:
		csio_warn(hw, "unexp event:%d received in "
			"hw state[initializing]\n", evt);
		CSIO_INC_STATS(hw, n_evt_unexp);
		break;
	}

	return;
}

/**
 * csio_hws_ready - Ready state
 * @hw - HW module
 * @evt - Event
 *
 */
static void
csio_hws_ready(struct csio_hw *hw, csio_hw_ev_t evt)
{
	/* Remember the event */
	hw->evtflag = evt;

	hw->prev_evt = hw->cur_evt;
	hw->cur_evt = evt;
	CSIO_INC_STATS(hw, n_evt_sm[evt]);
	
	switch(evt) {

	case CSIO_HWE_HBA_RESET:
	case CSIO_HWE_FW_DLOAD:
	case CSIO_HWE_SUSPEND:
	case CSIO_HWE_PCI_REMOVE:
	case CSIO_HWE_PCIERR_DETECTED:
		csio_set_state(&hw->sm, csio_hws_quiescing);
		/* cleanup all outstanding cmds */
		if (evt == CSIO_HWE_HBA_RESET ||
		    evt == CSIO_HWE_PCIERR_DETECTED)
			csio_scsim_cleanup_io(csio_hw_to_scsim(hw), CSIO_FALSE);
		else
			csio_scsim_cleanup_io(csio_hw_to_scsim(hw), CSIO_TRUE);

		csio_evtq_stop(hw);
		csio_notify_lnodes(hw, CSIO_LN_NOTIFY_HWSTOP);
		csio_evtq_flush(hw);
		csio_mgmtm_cleanup(csio_hw_to_mgmtm(hw));
		csio_post_event(&hw->sm, CSIO_HWE_QUIESCED);
		break;

	case CSIO_HWE_FATAL:
		csio_set_state(&hw->sm, csio_hws_uninit);
		break;

	default:
		csio_warn(hw, "unexp event:%d received in hw state[ready]\n",
			    evt);
		CSIO_INC_STATS(hw, n_evt_unexp);
		break;
	}

	return;
}

/**
 * csio_hws_quiescing - Quiescing state
 * @hw - HW module
 * @evt - Event
 *
 */
static void
csio_hws_quiescing(struct csio_hw *hw, csio_hw_ev_t evt)
{
	hw->prev_evt = hw->cur_evt;
	hw->cur_evt = evt;
	CSIO_INC_STATS(hw, n_evt_sm[evt]);
	
	switch(evt) {

	case CSIO_HWE_QUIESCED:
		switch (hw->evtflag) {

		case CSIO_HWE_FW_DLOAD:
			csio_set_state(&hw->sm, csio_hws_resetting);
			/* Download firmware */
			/* Fall through */

		case CSIO_HWE_HBA_RESET:
			csio_set_state(&hw->sm, csio_hws_resetting);
			/* Start reset of the HBA */
			csio_notify_lnodes(hw, CSIO_LN_NOTIFY_HWRESET);
			csio_spin_unlock_irq(hw, &hw->lock);
			csio_wr_destroy_queues(hw, CSIO_FALSE);
			csio_spin_lock_irq(hw, &hw->lock);
			csio_do_reset(hw, CSIO_FALSE);
			csio_post_event(&hw->sm, CSIO_HWE_HBA_RESET_DONE);
			break;

		case CSIO_HWE_PCI_REMOVE:
			csio_set_state(&hw->sm, csio_hws_removing);
			if (csio_exit_no_mb)
				break;
			csio_notify_lnodes(hw, CSIO_LN_NOTIFY_HWREMOVE);
			csio_spin_unlock_irq(hw, &hw->lock);
			csio_wr_destroy_queues(hw, CSIO_TRUE);
			csio_spin_lock_irq(hw, &hw->lock);
			/* Now send the bye command */
			csio_do_bye(hw);
			break;

		case CSIO_HWE_SUSPEND:
			csio_set_state(&hw->sm, csio_hws_quiesced);
			break;

		case CSIO_HWE_PCIERR_DETECTED:
			csio_set_state(&hw->sm, csio_hws_pcierr);
			csio_spin_unlock_irq(hw, &hw->lock);
			csio_wr_destroy_queues(hw, CSIO_FALSE);
			csio_spin_lock_irq(hw, &hw->lock);
			break;

		default:
			csio_warn(hw, "unexp event:%d received in hw "
				"state[quiescing]\n", evt);
			CSIO_INC_STATS(hw, n_evt_unexp);
			break;

		}
		break;

	default:
		csio_warn(hw, "unexp event:%d received in hw "
			"state[quiescing]\n", evt);
		CSIO_INC_STATS(hw, n_evt_unexp);
		break;
	}

	return;
}

/**
 * csio_hws_quiesced - Quiesced state
 * @hw - HW module
 * @evt - Event
 *
 */
static void
csio_hws_quiesced(struct csio_hw *hw, csio_hw_ev_t evt)
{
	hw->prev_evt = hw->cur_evt;
	hw->cur_evt = evt;
	CSIO_INC_STATS(hw, n_evt_sm[evt]);
	
	switch(evt) {

	case CSIO_HWE_RESUME:
		csio_set_state(&hw->sm, csio_hws_configuring);
		csio_hw_configure(hw);
		break;

	default:
		csio_warn(hw, "unexp event:%d received in hw state[quiesced]\n",
			evt);
		CSIO_INC_STATS(hw, n_evt_unexp);
		break;
	}

	return;
}

/**
 * csio_hws_resetting - HW Resetting state
 * @hw - HW module
 * @evt - Event
 *
 */
static void
csio_hws_resetting(struct csio_hw *hw, csio_hw_ev_t evt)
{
	hw->prev_evt = hw->cur_evt;
	hw->cur_evt = evt;
	CSIO_INC_STATS(hw, n_evt_sm[evt]);
	
	switch(evt) {

	case CSIO_HWE_HBA_RESET_DONE:
		csio_evtq_start(hw);
		csio_set_state(&hw->sm, csio_hws_configuring);
		csio_hw_configure(hw);
		break;

	default:
		csio_warn(hw, "unexp event:%d received in "
			"hw state[resetting]\n", evt);
		CSIO_INC_STATS(hw, n_evt_unexp);
		break;
	}

	return;
}

/**
 * csio_hws_removing - PCI Hotplug removing state
 * @hw - HW module
 * @evt - Event
 *
 */
static void
csio_hws_removing(struct csio_hw *hw, csio_hw_ev_t evt)
{
	hw->prev_evt = hw->cur_evt;
	hw->cur_evt = evt;
	CSIO_INC_STATS(hw, n_evt_sm[evt]);
	
	switch(evt) {
	case CSIO_HWE_HBA_RESET:
		if (!csio_is_hw_master(hw))
			break;
		/*
		 * The BYE should have alerady been issued, so we cant
		 * use the mailbox interface. Hence we use the PL_RST
		 * register directly.
		 */
		csio_err(hw, "Resetting hw via register"
			    " and waiting 2 sec...\n");
		t4_write_reg(&hw->adap, A_PL_RST, F_PIORSTMODE | F_PIORST);
		csio_mdelay(2000);
		break;

	/* Should never receive any new events */
	default:
		csio_warn(hw, "unexp event:%d received in "
			"hw state[removing]\n",	evt);
		CSIO_INC_STATS(hw, n_evt_unexp);
		break;

	}

	return;
}

/**
 * csio_hws_pcierr - PCI Error state
 * @hw - HW module
 * @evt - Event
 *
 */
static void
csio_hws_pcierr(struct csio_hw *hw, csio_hw_ev_t evt)
{
	hw->prev_evt = hw->cur_evt;
	hw->cur_evt = evt;
	CSIO_INC_STATS(hw, n_evt_sm[evt]);
	
	switch(evt) {

	case CSIO_HWE_PCIERR_SLOT_RESET:
		csio_evtq_start(hw);
		csio_set_state(&hw->sm, csio_hws_configuring);
		csio_hw_configure(hw);
		break;

	default:
		csio_warn(hw, "unexp event:%d received in"
			"hw state[pcierr]\n", evt);
		CSIO_INC_STATS(hw, n_evt_unexp);
		break;
	}

	return;
}

/**
 * csio_hws_offline - Offline state
 * @hw - HW module
 * @evt - Event
 *
 */
static void
csio_hws_offline(struct csio_hw *hw, csio_hw_ev_t evt)
{
	hw->prev_evt = hw->cur_evt;
	hw->cur_evt = evt;
	CSIO_INC_STATS(hw, n_evt_sm[evt]);
	
	switch(evt) {

	case CSIO_HWE_PCIERR_RESUME:
		csio_set_state(&hw->sm, csio_hws_configuring);
		csio_hw_configure(hw);
		break;

	default:
		csio_warn(hw, "unexp event:%d received in hw state[offline]\n",
			evt);
		CSIO_INC_STATS(hw, n_evt_unexp);
		break;
	}

	return;
}

/*****************************************************************************/
/* END: HW SM                                                                */
/*****************************************************************************/

/**
 * csio_hw_stateto_str -
 * @hw - HW module
 * @str - state of HW.
 *
 * This routines returns the current state of HW module.
 */
void csio_hw_stateto_str(struct csio_hw *hw, int8_t *str)
{
	if (csio_get_state(hw) == ((csio_sm_state_t)csio_hws_uninit)) {
		csio_strcpy(str, "UNINIT");
		return;
	}	
	if (csio_get_state(hw) == ((csio_sm_state_t)csio_hws_configuring)) {
		csio_strcpy(str, "CONFIGURING");
		return;
	}	
	if (csio_get_state(hw) == ((csio_sm_state_t)csio_hws_initializing)) {
		csio_strcpy(str, "INITIALIZING");
		return;
	}	
	if (csio_get_state(hw) == ((csio_sm_state_t)csio_hws_quiescing)) {
		csio_strcpy(str, "QUIESCING");
		return;
	}	
	if (csio_get_state(hw) == ((csio_sm_state_t)csio_hws_quiesced)) {
		csio_strcpy(str, "QUIESCED");
		return;
	}	
	if (csio_get_state(hw) == ((csio_sm_state_t)csio_hws_resetting)) {
		csio_strcpy(str, "RESETTING");
		return;
	}	
	if (csio_get_state(hw) == ((csio_sm_state_t)csio_hws_removing)) {
		csio_strcpy(str, "REMOVING");
		return;
	}	
	if (csio_get_state(hw) == ((csio_sm_state_t)csio_hws_pcierr)) {
		csio_strcpy(str, "PCIERROR");
		return;
	}	
	if (csio_get_state(hw) == ((csio_sm_state_t)csio_hws_ready)) {
		csio_strcpy(str, "READY");
		return;
	}	
	if (csio_get_state(hw) == ((csio_sm_state_t)csio_hws_offline)) {
		csio_strcpy(str, "OFFLINE");
		return;
	}	
	csio_strcpy(str, "UNKNOWN");
}

/**
 * csio_hw_evt_name
 * @evt - hw event.
 *
 * This routines returns the event name of given hw event.
 */
const char *csio_hw_evt_name(csio_hw_ev_t evt)
{
	const char *evt_name;
	evt_name = hw_evt_names[evt];
	return evt_name;
}

void t4_fatal_err(struct adapter *adap)
{
	t4_set_reg_field(adap, A_SGE_CONTROL, F_GLOBALENABLE, 0);
	t4_intr_disable(adap);
	CH_ERR(adap, "encountered fatal error, adapter stopped\n");
}

/**
 *	csio_hw_slow_intr_handler - control path interrupt handler
 *	@hw: HW module
 *
 *	T4 interrupt handler for non-data global interrupt events, e.g., errors.
 *	The designation 'slow' is because it involves register reads, while
 *	data interrupts typically don't involve any MMIOs.
 */
int
csio_hw_slow_intr_handler(struct csio_hw *hw)
{
	uint32_t cause = t4_read_reg(&hw->adap, A_PL_INT_CAUSE);

	if (!(cause & GLBL_INTR_MASK)) {
		CSIO_INC_STATS(hw, n_plint_unexp);
		return 0;
	}

	csio_dbg(hw, "Slow interrupt! cause: 0x%x\n", cause);

	CSIO_INC_STATS(hw, n_plint_cnt);

	t4_slow_intr_handler(&hw->adap);

	return 1;
}

/*****************************************************************************
 * Event handling
 ****************************************************************************/
csio_retval_t
csio_enqueue_evt(struct csio_hw *hw, csio_evt_t type, void *evt_msg,
			uint16_t len)
{
	struct csio_evt_msg *evt_entry = NULL;	

	if (type >= CSIO_EVT_MAX) {
		csio_warn(hw, "unexpected event type %#x\n", type);
		return CSIO_INVAL;
	}

	if (len > EVT_MSG_SIZE) {
		csio_warn(hw, "unexpected msg size\n");
		return CSIO_INVAL;
	}

	if (hw->flags & CSIO_HWF_FWEVT_STOP) {
		return CSIO_INVAL;
	}	

	csio_deq_from_head(&hw->evt_free_q, &evt_entry);
	if (!evt_entry) {
		csio_err(hw, "Failed to alloc Event entry. "
			"Dropping msg type %d len %d\n", type, len);
		return	CSIO_NOMEM;
	}
	
	csio_vdbg(hw, "Enquing msg type %d len %d into eventq\n", type, len);
	/* copy event msg and queue the event */
	evt_entry->type = type;
	csio_memcpy((void*) evt_entry->data, evt_msg, len);
	csio_enq_at_tail(&hw->evt_active_q, &evt_entry->list);
	CSIO_DEC_STATS(hw, n_evt_freeq);
	CSIO_INC_STATS(hw, n_evt_activeq);
	return CSIO_SUCCESS;
}

csio_retval_t
csio_enqueue_evt_lock(struct csio_hw *hw, csio_evt_t type, void *evt_msg,
			uint16_t len, bool msg_sg)
{
	struct csio_evt_msg *evt_entry = NULL;	
	struct csio_fl_dma_buf *fl_sg;
	uint32_t off = 0;
	unsigned long flags = 0;
	int n;

	if (type >= CSIO_EVT_MAX) {
		csio_warn(hw, "unexpected event type %#x\n", type);
		return CSIO_INVAL;
	}

	if (len > EVT_MSG_SIZE) {
		csio_warn(hw, "unexpected msg size\n");
		return CSIO_INVAL;
	}

	csio_spin_lock_irqsave(hw, &hw->lock, flags);
	if (hw->flags & CSIO_HWF_FWEVT_STOP) {
		csio_spin_unlock_irqrestore(hw, &hw->lock, flags);
		return CSIO_INVAL;
	}	
	csio_deq_from_head(&hw->evt_free_q, &evt_entry);
	if (!evt_entry) {
		csio_err(hw, "Failed to alloc Event entry."
			"Dropping msg type %d len %d\n", type, len);
		csio_spin_unlock_irqrestore(hw, &hw->lock, flags);
		return	CSIO_NOMEM;
	}
	
	csio_vdbg(hw, "Enquing msg type %d len %d into eventq\n", type, len);
	/* copy event msg and queue the event */
	evt_entry->type = type;

	/* If Payload in SG list*/
	if (msg_sg) {
		fl_sg = (struct csio_fl_dma_buf *) evt_msg;
		for (n = 0; (n < CSIO_MAX_FLBUF_PER_IQWR && off < len); n++) {
			csio_memcpy(
				(void*)((uintptr_t)evt_entry->data + off),
				fl_sg->flbufs[n].vaddr,
				fl_sg->flbufs[n].len);
			off += fl_sg->flbufs[n].len;
		}
	}
	else
		csio_memcpy((void*) evt_entry->data, evt_msg, len);
		
	csio_enq_at_tail(&hw->evt_active_q, &evt_entry->list);
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);
	CSIO_DEC_STATS(hw, n_evt_freeq);
	CSIO_INC_STATS(hw, n_evt_activeq);
	return CSIO_SUCCESS;
}

struct csio_evt_msg *
csio_dequeue_evt(struct csio_hw *hw)
{
	struct csio_evt_msg *evt_entry = NULL;	

	csio_spin_lock_irq(hw, &hw->lock);
	if (csio_list_empty(&hw->evt_active_q)) {
		csio_spin_unlock_irq(hw, &hw->lock);
		return NULL;
	}

	csio_deq_from_head(&hw->evt_active_q, &evt_entry);
	csio_spin_unlock_irq(hw, &hw->lock);
	if (evt_entry)
		CSIO_DEC_STATS(hw, n_evt_activeq);

	return evt_entry;
}

void
csio_free_evt(struct csio_hw *hw, struct csio_evt_msg *evt_entry)
{
	if (evt_entry) {
		csio_spin_lock_irq(hw, &hw->lock);
		csio_deq_elem(&evt_entry->list);
		csio_enq_at_tail(&hw->evt_free_q, &evt_entry->list);
		CSIO_DEC_STATS(hw, n_evt_activeq);
		CSIO_INC_STATS(hw, n_evt_freeq);
		csio_spin_unlock_irq(hw, &hw->lock);
	}
}

void
csio_evtq_flush(struct csio_hw *hw)
{
	uint32_t count;
	count = 30;
	while (hw->flags & CSIO_HWF_FWEVT_PENDING && count--) {
		csio_spin_unlock_irq(hw, &hw->lock);
		csio_msleep(2000);
		csio_spin_lock_irq(hw, &hw->lock);
	}

	CSIO_DB_ASSERT(!(hw->flags & CSIO_HWF_FWEVT_PENDING));
}

void
csio_evtq_stop(struct csio_hw *hw)
{
	hw->flags |= CSIO_HWF_FWEVT_STOP;
}

void
csio_evtq_start(struct csio_hw *hw)
{
	hw->flags &= ~CSIO_HWF_FWEVT_STOP;
}

void
csio_evtq_cleanup(struct csio_hw *hw)
{
	struct csio_list	*evt_entry, *next_entry;

	/* Release outstanding events from activeq to freeq*/
	if (!csio_list_empty(&hw->evt_active_q)) {
		csio_enq_list_at_tail(&hw->evt_free_q, &hw->evt_active_q);
	}

	hw->stats.n_evt_activeq = 0;
	hw->flags &= ~CSIO_HWF_FWEVT_PENDING;

	/* Freeup event entry */
	csio_list_for_each_safe(evt_entry, next_entry, &hw->evt_free_q) { 	
		csio_free(csio_md(hw, CSIO_EVTQ_MD), evt_entry);
		CSIO_DEC_STATS(hw, n_evt_freeq);
	}

	hw->stats.n_evt_freeq = 0;
}


static void
csio_process_fwevtq_entry(struct csio_hw *hw, void *wr, uint32_t len,
			  struct csio_fl_dma_buf *flb, void *priv)
{
	__u8 op;
	__be64 *data;
	void *msg = NULL;
	uint32_t msg_len = 0;
	bool msg_sg = 0;

	csio_vdbg(hw, "################ FW evtq WR len:%d ################\n",
		    len);
	CSIO_DUMP_BUF(wr, len);

	op = ((struct rss_header *) wr)->opcode;
	if (op == CPL_FW6_PLD) {
		CSIO_INC_STATS(hw, n_cpl_fw6_pld);
		if (!flb || !flb->totlen) {
			csio_warn(hw, "warn: CPL_FW6_PLD msg recv without"
				"flist\n");
			CSIO_INC_STATS(hw, n_cpl_unexp);
			return;
		}
		
		csio_vdbg(hw,
			"############### FL data len:%d ##################\n",
			flb->totlen);
		CSIO_DUMP_BUF(flb->flbufs[0].vaddr, flb->totlen);
		msg = (void *) flb;
		msg_len = flb->totlen;
		msg_sg = 1;

		data = (__be64 *) msg;
		CSIO_TRACE(hw, CSIO_HW_MOD, CSIO_DBG_LEV,
			   csio_be64_to_cpu(*data++),
			   csio_be64_to_cpu(*data++),
			   csio_be64_to_cpu(*data++),
			   csio_be64_to_cpu(*data++));
		
		csio_vdbg(hw,
		    "############### FL data dump ##################\n");
		CSIO_DUMP_BUF(flb->flbufs[0].vaddr, flb->totlen);
	}
	else if (op == CPL_FW6_MSG || op == CPL_FW4_MSG) {

		CSIO_INC_STATS(hw, n_cpl_fw6_msg);
		/* skip RSS header */
		msg = (void *)((uintptr_t)wr + sizeof(__be64));
		msg_len = (op == CPL_FW6_MSG) ? sizeof(struct cpl_fw6_msg) :
			   sizeof(struct cpl_fw4_msg);	

		data = (__be64 *) msg;
		CSIO_TRACE(hw, CSIO_HW_MOD, CSIO_DBG_LEV,
			   csio_be64_to_cpu(*data++),
			   csio_be64_to_cpu(*data++),
			   csio_be64_to_cpu(*data++),
			   csio_be64_to_cpu(*data++));
	} else {
		csio_warn(hw, "unexpected CPL %#x on FW event queue\n",
			  op);
		CSIO_INC_STATS(hw, n_cpl_unexp);
		return;
	}

	/* Enqueue event to EventQ. Events processing happens
	 * in Event worker thread context */
	if (csio_enqueue_evt_lock(hw, CSIO_EVT_FW, msg, (uint16_t)msg_len,
		msg_sg))
		CSIO_INC_STATS(hw, n_evt_drop);
	return;
}

void
csio_evtq_worker(void *data)
{
	struct csio_hw *hw = (struct csio_hw *)data;
	struct csio_list evt_q, *evt_entry, *next_entry;
	struct csio_evt_msg	*evt_msg;
	struct cpl_fw6_msg *msg;
	struct csio_rnode_fcoe *rnf;
	enum csio_oss_error rv = 0;
	uint8_t evtq_stop = 0;

	csio_dbg(hw, "event worker thread invoked! active evts#%d\n",
		hw->stats.n_evt_activeq);

	csio_spin_lock_irq(hw, &hw->lock);
	while (!csio_list_empty(&hw->evt_active_q)) {
		csio_head_init(&evt_q);
		csio_enq_list_at_tail(&evt_q, &hw->evt_active_q);
		csio_spin_unlock_irq(hw, &hw->lock);

		csio_list_for_each_safe(evt_entry, next_entry, &evt_q) {
			evt_msg = (struct csio_evt_msg *) evt_entry;	

			/* Drop events if queue is STOPPED */
			csio_spin_lock_irq(hw, &hw->lock);
			if (hw->flags & CSIO_HWF_FWEVT_STOP)
				evtq_stop = 1;		
			csio_spin_unlock_irq(hw, &hw->lock);
			if (evtq_stop) {
				csio_warn(hw, "event Q stopped.."
					"dropping evt %x\n", evt_msg->type);
				CSIO_INC_STATS(hw, n_evt_drop);
				goto free_evt;
			}

			switch(evt_msg->type) {
		
			case CSIO_EVT_FW:
				msg = (struct cpl_fw6_msg *)(evt_msg->data);
	
				if ((msg->opcode == CPL_FW6_MSG ||
				msg->opcode == CPL_FW4_MSG) && !msg->type) {

					if (csio_is_fcoe(hw)) {
						rv = csio_mb_fwevt_handler(hw,
								msg->data);
					} else {
#ifdef __CSIO_FOISCSI_ENABLED__
						rv = csio_foiscsi_mb_fwevt_handler
							(hw, msg->data);
#endif
					}			
				
					if(!rv)
						break;

					/* Handle any remaining fw events */
					if (csio_is_fcoe(hw))
						csio_fcoe_fwevt_handler(hw,
							msg->opcode, msg->data);
				}
				else if (msg->opcode == CPL_FW6_PLD) {
					
					/* Handle any remaining fw events */
					if (csio_is_fcoe(hw)) {
						csio_fcoe_fwevt_handler(hw,
							msg->opcode, msg->data);
					 } else {
#ifdef __CSIO_FOISCSI_ENABLED__
						csio_foiscsi_mb_fwevt_handler(hw,
							msg->data);
#endif
					}
				}
				else {
					csio_warn(hw, "Unhandled FW msg op %x"
						" type %x !\n",
						msg->opcode, msg->type);
					CSIO_INC_STATS(hw, n_evt_drop);
				}
				break;

			case CSIO_EVT_DEV_LOSS:
				csio_memcpy(&rnf, evt_msg->data, sizeof(rnf));
				csio_rnf_devloss_handler(rnf);
				break;

			default:
				csio_warn(hw, "Unhandled event %x on the"
					"event Q!\n", evt_msg->type);
				CSIO_INC_STATS(hw, n_evt_unexp);
				break;
			}
free_evt:			
			csio_free_evt(hw, evt_msg);
		}	

		csio_spin_lock_irq(hw, &hw->lock);
	}	
	hw->flags &= ~CSIO_HWF_FWEVT_PENDING;
	csio_spin_unlock_irq(hw, &hw->lock);
	csio_dbg(hw, "event worker thread exiting\n");
}

csio_retval_t
csio_fwevtq_handler(struct csio_hw *hw)
{
	enum csio_oss_error rv;

	if (csio_q_iqid(hw, hw->fwevt_iq_idx) == CSIO_MAX_QID) {
		CSIO_INC_STATS(hw, n_int_stray);
		return CSIO_INVAL;
	}

	rv = csio_wr_process_iq_idx(hw, hw->fwevt_iq_idx,
			   csio_process_fwevtq_entry, NULL);
	return rv;
}

/*****************************************************************************
 * Entry points
 ****************************************************************************/
#define PF_INTR_MASK (F_PFSW | F_PFCIM)

/**
 * csio_hw_intr_enable - Enable HW interrupts
 * @hw: Pointer to HW module.
 *
 * Enable interrupts in HW registers.
 */
void
csio_hw_intr_enable(struct csio_hw *hw)
{
	uint16_t vec =  (uint16_t)csio_get_nondata_intr_idx(hw);
	uint32_t whoami = t4_read_reg(&hw->adap, A_PL_WHOAMI);
	uint32_t pf = (CHELSIO_CHIP_VERSION(hw->adap.params.chip) <= CHELSIO_T5
		       ? G_SOURCEPF(whoami)
		       : G_T6_SOURCEPF(whoami));

	uint32_t pl = t4_read_reg(&hw->adap, A_PL_INT_ENABLE);

	/*
	 * Set aivec for MSI/MSIX. A_PCIE_PF_CFG.INTXType is set up
	 * by FW, so do nothing for INTX.
	 */
	if (hw->intr_mode == CSIO_IM_MSIX)
		t4_set_reg_field(&hw->adap, MYPF_REG(A_PCIE_PF_CFG),
				   V_AIVEC(M_AIVEC), vec);
	else if (hw->intr_mode == CSIO_IM_MSI)
		t4_set_reg_field(&hw->adap, MYPF_REG(A_PCIE_PF_CFG),
				   V_AIVEC(M_AIVEC), 0);

	t4_write_reg(&hw->adap, MYPF_REG(A_PL_PF_INT_ENABLE), PF_INTR_MASK);

	/* Turn on MB interrupts - this will internally flush PIO as well */

	/* These are common registers - only a master can modify them */
	if (csio_is_hw_master(hw)) {
		/*
		 * Disable the Serial FLASH interrupt, if enabled!
		 *
		 * REVISIT: Remove this once fw is fixed to disable the
		 *	    SF interrupt.
	 	 */
		pl &= (~F_SF);
		t4_write_reg(&hw->adap, A_PL_INT_ENABLE, pl);

		t4_write_reg(&hw->adap, A_SGE_INT_ENABLE3,
			      F_ERR_CPL_EXCEED_IQE_SIZE |
			      F_EGRESS_SIZE_ERR | F_ERR_INVALID_CIDX_INC |
			      F_ERR_CPL_OPCODE_0 | F_ERR_DROPPED_DB |
			      F_ERR_DATA_CPL_ON_HIGH_QID1 |
			      F_ERR_DATA_CPL_ON_HIGH_QID0 | F_ERR_BAD_DB_PIDX3 |
			      F_ERR_BAD_DB_PIDX2 | F_ERR_BAD_DB_PIDX1 |
			      F_ERR_BAD_DB_PIDX0 | F_ERR_ING_CTXT_PRIO |
			      F_ERR_EGR_CTXT_PRIO | F_INGRESS_SIZE_ERR);
		t4_set_reg_field(&hw->adap, A_PL_INT_MAP0, 0, 1 << pf);
	}

	hw->flags |= CSIO_HWF_INTR_ENABLED;

	return;
}

/**
 * csio_hw_intr_disable - Disable HW interrupts
 * @hw: Pointer to HW module.
 *
 * Turn off Mailbox and PCI_PF_CFG interrupts.
 */
void
csio_hw_intr_disable(struct csio_hw *hw)
{
	uint32_t whoami = t4_read_reg(&hw->adap, A_PL_WHOAMI);
	uint32_t pf = (CHELSIO_CHIP_VERSION(hw->adap.params.chip) <= CHELSIO_T5
		       ? G_SOURCEPF(whoami)
		       : G_T6_SOURCEPF(whoami));

	if (!(hw->flags & CSIO_HWF_INTR_ENABLED))
		return;

	hw->flags &= ~CSIO_HWF_INTR_ENABLED;

	t4_write_reg(&hw->adap, MYPF_REG(A_PL_PF_INT_ENABLE), 0);
	if (csio_is_hw_master(hw))
		t4_set_reg_field(&hw->adap, A_PL_INT_MAP0, 1 << pf, 0);

	/* Turn off MB interrupts */

	return;
}

/**
 * csio_hw_start -  Kicks off the HW State machine
 * @hw: Pointer to HW module.
 *
 * It is assumed that the initialization is a synchronous operation.
 * So when we return afer posting the event, the HW SM should be in
 * the ready state, if there were no errors during init.
 */
csio_retval_t
csio_hw_start(struct csio_hw *hw)
{
	csio_spin_lock_irq(hw, &hw->lock);
	csio_post_event(&hw->sm, CSIO_HWE_CFG);
	csio_spin_unlock_irq(hw, &hw->lock);

	if (csio_exit_no_mb)
		return CSIO_SUCCESS;

	if (csio_is_hw_ready(hw))
		return CSIO_SUCCESS;
	else if csio_match_state(hw, csio_hws_uninit)
		return CSIO_FATAL;
	else
		return CSIO_INVAL;
}

csio_retval_t
csio_hw_stop(struct csio_hw *hw)
{
	csio_post_event(&hw->sm, CSIO_HWE_PCI_REMOVE);

	if (csio_is_hw_removing(hw))	
		return CSIO_SUCCESS;
	else
		return CSIO_INVAL;
}

/**
 * csio_hw_reset - Reset the hardware
 * @hw: HW module.
 *
 * Caller should hold lock across this function.
 */
csio_retval_t
csio_hw_reset(struct csio_hw *hw)
{
	if (!csio_is_hw_master(hw))
		return CSIO_NOPERM;

	if (hw->rst_retries >= CSIO_MAX_RESET_RETRIES) {
		csio_err(hw, "Max hw reset reached..");
		return CSIO_INVAL;
	}

	hw->rst_retries++;
	csio_post_event(&hw->sm, CSIO_HWE_HBA_RESET);
	
	if (csio_is_hw_ready(hw)) {	
		hw->rst_retries = 0;
		hw->stats.n_reset_start = csio_os_msecs();
		return CSIO_SUCCESS;
	}	
	else {		
//		csio_post_event(&hw->sm, CSIO_HWE_FATAL);
		return CSIO_INVAL;
	}	
}

/**
 * csio_hw_get_device_id - Caches the Adapter's vendor & device id.
 * @hw: HW module.
 */
csio_retval_t
csio_hw_get_device_id(struct csio_hw *hw)
{
	int ver;
	u32 pl_rev;
	struct adapter *adap = &hw->adap;

	/* Is the adapter device id cached already ?*/
	if(csio_is_dev_id_cached(hw))
		return CSIO_SUCCESS;

	pl_rev = G_REV(t4_read_reg(&hw->adap, A_PL_REV));
	/* Get the PCI vendor & device id */

	t4_os_pci_read_cfg2(adap, PCI_VENDOR_ID, &adap->params.pci.vendor_id);
	t4_os_pci_read_cfg2(adap, PCI_DEVICE_ID, &adap->params.pci.device_id);

	csio_dev_id_cached(hw);
	ver = CHELSIO_PCI_ID_VER(adap->params.pci.device_id);
	adap->params.chip = 0;
	switch (ver) {
	case CHELSIO_T4_FPGA:
		adap->params.chip |= CHELSIO_CHIP_FPGA;
		/*FALLTHROUGH*/
	case CHELSIO_T4:
		adap->params.chip |= CHELSIO_CHIP_CODE(CHELSIO_T4, pl_rev);
		break;
	case CHELSIO_T5_FPGA:
		adap->params.chip |= CHELSIO_CHIP_FPGA;
		/*FALLTHROUGH*/
	case CHELSIO_T5:
		adap->params.chip |= CHELSIO_CHIP_CODE(CHELSIO_T5, pl_rev);
		break;
	case CHELSIO_T6_FPGA:
		adap->params.chip |= CHELSIO_CHIP_FPGA;
		/* FALLTHROUGH*/
	case CHELSIO_T6:
		adap->params.chip |= CHELSIO_CHIP_CODE(CHELSIO_T6, pl_rev);
		break;
	default:
		csio_err(hw, "Device 0x%x is not supported\n",
			 hw->adap.params.pci.device_id);
		return CSIO_INVAL;
	}

	/* T4A1 chip is no longer supported */
	if (is_t4(adap->params.chip) && (pl_rev == 1)) {
		csio_err(hw, "T4 rev 1 chip is no longer supported\n");
		return CSIO_INVAL;
	}

	adap->params.pci.vpd_cap_addr =
		t4_os_find_pci_capability(adap, PCI_CAP_ID_VPD);

	return CSIO_SUCCESS;
} /* csio_hw_get_device_id */

/**
 * csio_hw_init - Initialize HW module.
 * @hw: Pointer to HW module.
 * @os_ops: OS interface handlers.
 */
csio_retval_t
csio_hw_init(struct csio_hw *hw, struct csio_hw_os_ops *os_ops)
{
	enum csio_oss_error rv = CSIO_INVAL;
	uint32_t i;
	uint16_t ven_id, dev_id;
	struct csio_evt_msg	*evt_entry;

	csio_head_init(&hw->sm.sm_list);
	csio_init_state(&hw->sm, csio_hws_uninit, csio_hw_to_tbuf(hw));
	csio_spin_lock_init(&hw->lock);
	csio_head_init(&hw->sln_head);
	hw->os_ops = os_ops;
	hw->scsi_mode = CSIO_SCSI_MODE_INITIATOR;

	/* Get the PCI vendor & device id */
	if (csio_hw_get_device_id(hw))
		goto err;

	csio_strcpy(hw->name, CSIO_HW_NAME);

	/* Set the model & its description */

	ven_id = hw->adap.params.pci.vendor_id;
	dev_id = hw->adap.params.pci.device_id;

	
	/* Initialize default log level */
	hw->params.log_level = (uint32_t) csio_dbg_level;
	csio_trace_init(csio_hw_to_tbuf(hw), csio_dbg_level);	

	csio_set_fwevt_intr_idx(hw, -1);	
	csio_set_nondata_intr_idx(hw, -1);	

	/* Init all the modules: WorkRequest and Transport */
	rv = csio_wrm_init(csio_hw_to_wrm(hw), hw);
	if (rv)
		goto err;

	rv = csio_scsim_init(csio_hw_to_scsim(hw), hw);
	if (rv)
		goto err_wrm_exit;

	rv = csio_mgmtm_init(csio_hw_to_mgmtm(hw), hw);
	if (rv)
		goto err_scsim_exit;
	/* Pre-allocate evtq and initialize them */
	csio_head_init(&hw->evt_active_q);
	csio_head_init(&hw->evt_free_q);
	for (i = 0; i < csio_evtq_sz; i++) {

		evt_entry = csio_alloc(csio_md(hw, CSIO_EVTQ_MD),
				   sizeof(struct csio_evt_msg),
				   CSIO_MNOWAIT);
		if (!evt_entry) {
			csio_err(hw, "Failed to initialize eventq");
			goto err_evtq_cleanup;
		}

		csio_enq_at_tail(&hw->evt_free_q, &evt_entry->list);
		CSIO_INC_STATS(hw, n_evt_freeq);
	}
	
	hw->dev_num = dev_num;
	dev_num++;

#ifdef __CSIO_TARGET__
	rv = csio_tgtm_init(csio_hw_to_tgtm(hw), hw);
	if (rv)
		goto err_evtq_cleanup;
#endif /* __CSIO_TARGET */

	return CSIO_SUCCESS;

err_evtq_cleanup:
	csio_evtq_cleanup(hw);
	csio_mgmtm_exit(csio_hw_to_mgmtm(hw));
err_scsim_exit:
	csio_scsim_exit(csio_hw_to_scsim(hw));
err_wrm_exit:
	csio_wrm_exit(csio_hw_to_wrm(hw), hw);
err:
	return rv;
}

/**
 * csio_hw_exit - Un-initialize HW module.
 * @hw: Pointer to HW module.
 *
 */
void
csio_hw_exit(struct csio_hw *hw)
{
#ifdef __CSIO_FOISCSI_ENABLED__
	if (csio_is_iscsi(hw))
		csio_foiscsi_transport_uninit(hw);
#endif

#ifdef __CSIO_TARGET__
	csio_tgtm_exit(csio_hw_to_tgtm(hw));
#endif /* __CSIO_TARGET__ */
	csio_evtq_cleanup(hw);
	csio_mgmtm_exit(csio_hw_to_mgmtm(hw));
	csio_scsim_exit(csio_hw_to_scsim(hw));
	csio_wrm_exit(csio_hw_to_wrm(hw), hw);

	return;
}
