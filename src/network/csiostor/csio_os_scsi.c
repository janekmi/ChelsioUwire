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

#include <linux/moduleparam.h>
#include <linux/device.h>
#include <linux/ctype.h>
#include <linux/version.h>
#include <linux/module.h>
#include <asm/unaligned.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_transport_fc.h>
#ifdef __CSIO_FOISCSI_ENABLED__
#include <csio_os_foiscsi.h>
#endif

#include <csio_os_scsi.h>
#include <csio_os_init.h>
#include <csio_os_defs.h>
#include <csio_version.h>

/* REVISIT: HW state should be moved out of here */
static ssize_t
csio_show_hw_state(struct device *dev,
		   struct device_attribute *attr, char *buf)
{
	struct csio_os_lnode *osln = shost_priv(class_to_shost(dev));
	struct csio_hw *hw = csio_osln_to_hw(osln);

	/* REVISIT: THis should print all the states */
	if (csio_is_hw_ready(hw))
		return snprintf(buf, PAGE_SIZE, "READY\n");
	else
		return snprintf(buf, PAGE_SIZE, "NOT READY\n");
}

/* Device reset */
static ssize_t
csio_device_reset(struct device *dev,
		   struct device_attribute *attr, const char *buf, size_t count)
{
	struct csio_os_lnode *osln = shost_priv(class_to_shost(dev));
	struct csio_os_hw *oshw = csio_osln_to_oshw(osln);
	struct csio_hw *hw = csio_osln_to_hw(osln);
	
	if (*buf != '1')
		return -EINVAL;

	/* Delete NPIV lnodes */
	 csio_oslnodes_exit(oshw, 1);

	/* Block upper IOs */
	csio_oslnodes_block_request(oshw);

	csio_spin_lock_irq(hw, &hw->lock);
	csio_hw_reset(hw);
	csio_spin_unlock_irq(hw, &hw->lock);
	
	/* Unblock upper IOs */
	csio_oslnodes_unblock_request(oshw);
	return count;
}

/* disable port */
static ssize_t
csio_disable_port(struct device *dev,
		   struct device_attribute *attr, const char *buf, size_t count)
{
	struct csio_os_lnode *osln = shost_priv(class_to_shost(dev));
	struct csio_os_hw *oshw = csio_osln_to_oshw(osln);
	struct csio_hw *hw = csio_osln_to_hw(osln);
	struct csio_lnode *ln = csio_osln_to_ln(osln);
	bool disable;
	
	if (*buf == '1' || *buf == '0') {
		disable = (*buf == '1') ? CSIO_TRUE : CSIO_FALSE;
	}
	else
		return -EINVAL;
	
	/* Block upper IOs */
	csio_oslnodes_block_by_port(oshw, ln->portid);
	
	csio_spin_lock_irq(hw, &hw->lock);
	csio_disable_lnodes(hw, ln->portid, disable);
	csio_spin_unlock_irq(hw, &hw->lock);
#if 0	
	if (csio_is_fcoe(hw))
		csio_fcoe_disable_link(hw, ln, ln->portid, disable);
	else	{
		/* TODO for iSCSI */
	}	
#endif	
	/* Unblock upper IOs */
	csio_oslnodes_unblock_by_port(oshw, ln->portid);
	return count;
}

/* SCSI module statistics */
static ssize_t
csio_show_scsi_stats(struct device *dev,
		   struct device_attribute *attr, char *buf)
{
	struct csio_os_lnode *osln = shost_priv(class_to_shost(dev));
	struct csio_lnode *ln = csio_osln_to_ln(osln);
	struct csio_scsim *scsim = csio_hw_to_scsim(ln->hwp);
	size_t len=0;
	
	if (!scsim) {
		return 0;
	}

	len = snprintf(buf, PAGE_SIZE, "SCSI STATISTICS:\n");
	len += snprintf(buf + len, PAGE_SIZE - len, "\ttot_success:%lld\n",
			scsim->stats.n_tot_success);
	len += snprintf(buf + len, PAGE_SIZE - len, "\trn_nr_error:%d\n",
			scsim->stats.n_rn_nr_error);
	len += snprintf(buf + len, PAGE_SIZE - len, "\thw_nr_error:%d\n",
			scsim->stats.n_hw_nr_error);
	len += snprintf(buf + len, PAGE_SIZE - len, "\tdmamap_error:%d\n",
			scsim->stats.n_dmamap_error);
	len += snprintf(buf + len, PAGE_SIZE - len, "\tunsupp_sge_error:%d\n",
			scsim->stats.n_unsupp_sge_error);
	len += snprintf(buf + len, PAGE_SIZE - len, "\tno_req_error:%d\n",
			scsim->stats.n_no_req_error);
	len += snprintf(buf + len, PAGE_SIZE - len, "\tbusy_error:%d\n",
			scsim->stats.n_busy_error);
	len += snprintf(buf + len, PAGE_SIZE - len, "\thosterror:%d\n",
			scsim->stats.n_hosterror);
	len += snprintf(buf + len, PAGE_SIZE - len, "\trsperror:%d\n",
			scsim->stats.n_rsperror);
	len += snprintf(buf + len, PAGE_SIZE - len, "\tautosense:%d\n",
			scsim->stats.n_autosense);
	len += snprintf(buf + len, PAGE_SIZE - len, "\toverflow_error:%d\n",
			scsim->stats.n_ovflerror);
	len += snprintf(buf + len, PAGE_SIZE - len, "\tunderflow_error:%d\n",
			scsim->stats.n_unflerror);
	len += snprintf(buf + len, PAGE_SIZE - len, "\tn_rdev_nr_error:%d\n",
			scsim->stats.n_rdev_nr_error);
	len += snprintf(buf + len, PAGE_SIZE - len, "\tn_rdev_lost_error:%d\n",
			scsim->stats.n_rdev_lost_error);
	len += snprintf(buf + len, PAGE_SIZE - len, "\tn_rdev_logo_error:%d\n",
			scsim->stats.n_rdev_logo_error);
	len += snprintf(buf + len, PAGE_SIZE - len, "\tn_link_down_error:%d\n",
			scsim->stats.n_link_down_error);
	len += snprintf(buf + len, PAGE_SIZE - len, "\tn_unknown_error:%d\n",
			scsim->stats.n_unknown_error);
	len += snprintf(buf + len, PAGE_SIZE - len, "\taborted:%d\n",
			scsim->stats.n_aborted);
	len += snprintf(buf + len, PAGE_SIZE - len, "\tabrt_timedout:%d\n",
			scsim->stats.n_abrt_timedout);
	len += snprintf(buf + len, PAGE_SIZE - len, "\tabrt_fail:%d\n",
			scsim->stats.n_abrt_fail);
	len += snprintf(buf + len, PAGE_SIZE - len, "\tabrt_race_comp:%d\n",
			scsim->stats.n_abrt_race_comp);
	len += snprintf(buf + len, PAGE_SIZE - len, "\tabrt_busy_error:%d\n",
			scsim->stats.n_abrt_busy_error);
	len += snprintf(buf + len, PAGE_SIZE - len, "\tclosed:%d\n",
			scsim->stats.n_closed);
	len += snprintf(buf + len, PAGE_SIZE - len, "\tcls_busy_error:%d\n",
			scsim->stats.n_cls_busy_error);
	len += snprintf(buf + len, PAGE_SIZE - len, "\tactiveq_cnt:%d\n",
			scsim->stats.n_active);
	len += snprintf(buf + len, PAGE_SIZE - len, "\ttm_active:%d\n",
			scsim->stats.n_tm_active);
	len += snprintf(buf + len, PAGE_SIZE - len, "\twcbfnq_cnt:%d\n",
			scsim->stats.n_wcbfn);
	len += snprintf(buf + len, PAGE_SIZE - len, "\tfreeq_cnt:%d\n",
			scsim->stats.n_free_ioreq);
	len += snprintf(buf + len, PAGE_SIZE - len, "\tfree_ddps:%d\n",
			scsim->stats.n_free_ddp);
	len += snprintf(buf + len, PAGE_SIZE - len, "\tddp_miss:%d\n",
			scsim->stats.n_ddp_miss);
	len += snprintf(buf + len, PAGE_SIZE - len, "\tinval_cplop:%d\n",
			scsim->stats.n_inval_cplop);
	len += snprintf(buf + len, PAGE_SIZE - len, "\tinval_scsiop:%d\n",
			scsim->stats.n_inval_scsiop);
       	return len;
}

/* SCSI queue dump */
static ssize_t
csio_show_scsiq_dump(struct device *dev,
		   struct device_attribute *attr, char *buf)
{
	struct csio_os_lnode *osln = shost_priv(class_to_shost(dev));
	struct csio_lnode *ln = csio_osln_to_ln(osln);
	struct csio_hw *hw = csio_osln_to_hw(osln);
	struct csio_scsim *scsim = csio_hw_to_scsim(ln->hwp);
	struct csio_list *tmp;
	struct csio_ioreq *ioreq;
#ifndef __CSIO_DEBUG__
	struct scsi_cmnd *scmnd;
#else
	struct csio_fcp_cmnd *fcp_cmd;
#endif	
	unsigned long flags;
	size_t len=0;
	
	if (!scsim) {
		return 0;
	}

	len += snprintf(buf + len, PAGE_SIZE - len, "Activeq dump:\n");
	len += snprintf(buf + len, PAGE_SIZE - len,
		"iohndl\tlun\top\tlba\txferlen\n");
#ifndef __CSIO_DEBUG__
	csio_spin_lock_irqsave(hw, &hw->lock, flags);
	csio_list_for_each(tmp, &scsim->active_q) {
		ioreq = (struct csio_ioreq *)tmp;
		scmnd = (struct scsi_cmnd *) csio_scsi_osreq(ioreq);
		if (!scmnd)
			continue;
		len += snprintf(buf + len, PAGE_SIZE - len,
			"%08llx %4llu %08llx%08llx %4d",
			ioreq->fw_handle, (uint64_t)scmnd->device->lun,
			*((uint64_t *)scmnd->cmnd),
			*((uint64_t *) &scmnd->cmnd[8]),
			scsi_bufflen(scmnd));
	}
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);
#else
	csio_spin_lock_irqsave(hw, &hw->lock, flags);
	csio_list_for_each(tmp, &scsim->active_q) {
		ioreq = (struct csio_ioreq *)tmp;
		fcp_cmd = (struct csio_fcp_cmnd *) ioreq->data;
		len += snprintf(buf + len, PAGE_SIZE - len,
			"%p %2x %2x %x %d\n",
			ioreq, fcp_cmd->lun[7],
			fcp_cmd->cdb[0],
			htonl(*((uint32_t *) &fcp_cmd->cdb[2])),
			htonl(fcp_cmd->dl));
	}
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);
#endif
       	return len;
}

/* Show debug level */
static ssize_t
csio_show_dbg_level(struct device *dev,
		   struct device_attribute *attr, char *buf)
{
	struct csio_os_lnode *osln = shost_priv(class_to_shost(dev));
	struct csio_lnode *ln = csio_osln_to_ln(osln);
	
	return (snprintf(buf, PAGE_SIZE,"%x\n", ln->params.log_level));
}

/* Store debug level */
static ssize_t
csio_store_dbg_level(struct device *dev,
		   struct device_attribute *attr, const char *buf, size_t count)
{
	struct csio_os_lnode *osln = shost_priv(class_to_shost(dev));
	struct csio_hw *hw = csio_osln_to_hw(osln);
	struct csio_lnode *ln = csio_osln_to_ln(osln);
	uint32_t dbg_level = 0;
	
	if (!isdigit(buf[0]))
		return -EINVAL;
	
	if (sscanf(buf, "%i", &dbg_level))
		return -EINVAL;

	ln->params.log_level = dbg_level;
	hw->params.log_level = dbg_level;
	
	return 0;
}

#ifdef CSIO_DATA_CAPTURE
/* Show data cap enable */
static ssize_t
csio_show_dcap_enable(struct device *dev,
		   struct device_attribute *attr, char *buf)
{
	struct csio_os_lnode *osln = shost_priv(class_to_shost(dev));
	struct csio_hw *hw = csio_osln_to_hw(osln);
	
	return (snprintf(buf, PAGE_SIZE,"%x\n",
		(hw->trace_buf->level & CSIO_TRACE_DCAP_ENABLE) ? 1 : 0));
}

/* Store data capture enable/disable */
static ssize_t
csio_store_dcap_enable(struct device *dev,
		   struct device_attribute *attr, const char *buf, size_t count)
{
	struct csio_os_lnode *osln = shost_priv(class_to_shost(dev));
	struct csio_hw *hw = csio_osln_to_hw(osln);
	uint32_t enable = 0;
	
	if (!isdigit(buf[0])) {
		return -EINVAL;
	}
	sscanf(buf, "%d", &enable);
	if (enable)
		hw->trace_buf->level |= CSIO_TRACE_DCAP_ENABLE;
	else
		hw->trace_buf->level &= ~CSIO_TRACE_DCAP_ENABLE;
	return count;
}
#endif

static DEVICE_ATTR(hw_state, S_IRUGO, csio_show_hw_state, NULL);
static DEVICE_ATTR(device_reset, S_IWUSR, NULL, csio_device_reset);
static DEVICE_ATTR(disable_port, S_IWUSR, NULL, csio_disable_port);
static DEVICE_ATTR(scsi_stats, S_IRUGO, csio_show_scsi_stats, NULL);
static DEVICE_ATTR(scsi_queue, S_IRUGO, csio_show_scsiq_dump, NULL);
static DEVICE_ATTR(dbg_level, S_IRUGO | S_IWUSR, csio_show_dbg_level,
		  csio_store_dbg_level);
#ifdef CSIO_DATA_CAPTURE
static DEVICE_ATTR(dcap_enable, S_IRUGO | S_IWUSR, csio_show_dcap_enable,
		  csio_store_dcap_enable);
#endif

static struct device_attribute *csio_fcoe_lport_attrs[] = {
	&dev_attr_hw_state,
	&dev_attr_device_reset,
	&dev_attr_disable_port,
	&dev_attr_scsi_stats,
	&dev_attr_scsi_queue,
	&dev_attr_dbg_level,
#ifdef CSIO_DATA_CAPTURE
	&dev_attr_dcap_enable,
#endif
	NULL,
};

static ssize_t
csio_show_num_reg_rnodes(struct device *dev,
		     struct device_attribute *attr, char *buf)
{
	struct csio_os_lnode *osln = shost_priv(class_to_shost(dev));
	struct csio_lnode *ln = csio_osln_to_ln(osln);

	return snprintf(buf, PAGE_SIZE, "%d\n", ln->num_reg_rnodes);
}

static DEVICE_ATTR(num_reg_rnodes, S_IRUGO, csio_show_num_reg_rnodes, NULL);

static struct device_attribute *csio_fcoe_vport_attrs[] = {
	&dev_attr_num_reg_rnodes,
	&dev_attr_dbg_level,
#if 0
	&dev_attr_link_state,
#endif
	NULL,
};

static inline uint32_t
csio_scsi_copy_to_sgl(struct csio_hw *hw, struct csio_ioreq *req)
{
	struct scsi_cmnd *scmnd  = (struct scsi_cmnd *)csio_scsi_osreq(req);
	struct scatterlist *sg;
	uint32_t bytes_left;
	uint32_t bytes_copy;
	uint32_t buf_off = 0;
	uint32_t start_off = 0;
	uint32_t sg_off = 0;
	void *sg_addr;	
	void *buf_addr;	
	struct csio_dma_buf *dma_buf;
	
	bytes_left = scsi_bufflen(scmnd);
	sg = scsi_sglist(scmnd);
	dma_buf = (struct csio_dma_buf *) csio_list_next(&req->gen_list);

	/* Copy data from driver buffer to SGs of SCSI CMD */
	while (bytes_left > 0 && sg && dma_buf) {
		if (buf_off >= dma_buf->len) {
			buf_off = 0;
			dma_buf = (struct csio_dma_buf *)
					csio_list_next(dma_buf);
			continue;
		}
	
		if (start_off >= sg->length) {
			start_off -= sg->length;
			sg = sg_next(sg);
			continue;
		}

		buf_addr = dma_buf->vaddr + buf_off;
		sg_off = sg->offset + start_off;     	
		bytes_copy = min((dma_buf->len - buf_off),
				sg->length - start_off);
		bytes_copy = min((uint32_t)(PAGE_SIZE - (sg_off & ~PAGE_MASK)),
				bytes_copy);

		sg_addr = csio_kmap_atomic(sg_page(sg) + (sg_off >> PAGE_SHIFT));
		if (!sg_addr) {
			csio_err(hw, "failed to kmap sg:%p of ioreq:%p\n",
				sg, req);
			break;
		}

		/*csio_dbg(hw, "copy_to_sgl:sg_addr %p sg_off %d buf %p len %d\n",
				sg_addr, sg_off, buf_addr, bytes_copy);*/
		memcpy(sg_addr + (sg_off & ~PAGE_MASK), buf_addr, bytes_copy);
		csio_kunmap_atomic(sg_addr);

		start_off +=  bytes_copy;
		buf_off += bytes_copy;
		bytes_left -= bytes_copy;
	}

	if (bytes_left > 0)
		return DID_ERROR;
	else
		return DID_OK;
}

#ifdef CSIO_DATA_CAPTURE
void
csio_scsi_data_capture(struct csio_hw *hw, struct csio_ioreq *req)
{
	struct scsi_cmnd *scmnd  = (struct scsi_cmnd *)csio_scsi_osreq(req);
	struct csio_oss_sgel *sgel;
	struct csio_oss_dcap dcap;
	uint32_t i,ii,len;
	uint64_t *data;
	void *vaddr;	
	uint32_t blk_size = 1024;

	if (!(hw->trace_buf->level & CSIO_TRACE_DCAP_ENABLE))
		return;

	/* Return if no SG Entries */	
	if (!req->nsge)
		return;

	dcap.ioreq = (uintptr_t) req;
	dcap.flags = scmnd->cmnd[0];
	dcap.flags = (dcap.flags << 16 | csio_htons(*((uint16_t *) &scmnd->cmnd[7])));
	dcap.lba = csio_htonl(*((uint32_t *) &scmnd->cmnd[2]));

	csio_scsi_for_each_sg((hw)->os_dev, csio_scsi_osreq(req), sgel,
			      req->nsge,i)
	{
		BUG_ON(!sg_page(sgel));
		dcap.addr = csio_sgel_dma_addr(sgel);
		len = csio_sgel_len(sgel);
		for (ii=0; ii< len; ii+= blk_size) {
			vaddr = csio_kmap_atomic(sg_page(sgel) + ((sgel->offset + ii)
				>> PAGE_SHIFT),	KM_IRQ0);

			if (!vaddr) {
				csio_err(hw, "failed to map sg:%p\n",
					sg_page(sgel));
				break;
			}
	
			data = (uint64_t *) (vaddr);
			dcap.len  = ii;
			dcap.val1 = *data++;
			dcap.val2 = *data++;
			dcap.val3 = *data++;
			dcap.val4 = *data++;
			CSIO_DCAP_WRITE(hw->dcap_buf, &dcap, 1);
			csio_kunmap_atomic(vaddr);
		}
			
	}
}
#endif

/*
 * csio_fcoe_scsi_err_handler - FCoE SCSI error handler.
 * @hw: HW module.
 * @req: IO request.
 *
 */
static inline void
csio_fcoe_scsi_err_handler(struct csio_hw *hw, struct csio_ioreq *req)
{
	struct scsi_cmnd *cmnd  = (struct scsi_cmnd *)csio_scsi_osreq(req);
	struct csio_scsim *scm = csio_hw_to_scsim(hw);
	struct csio_fcp_resp *fcp_resp;
	struct csio_dma_buf *dma_buf;
	uint8_t flags, scsi_status = 0;
	uint32_t host_status = DID_OK;
	uint32_t rsp_len = 0, sns_len = 0;
	struct csio_os_rnode *osrn =
			(struct csio_os_rnode *)(cmnd->device->hostdata);

	if (req->wr_status) {
		csio_scsi_dbg(hw,
		    "cmpl req %p cmd:%p op:%x lun:%4llu wr:%x\n", req, cmnd,
		     cmnd->cmnd[0], (uint64_t)cmnd->device->lun,
		    req->wr_status);
	}	
	
	switch (req->wr_status) {
	case FW_HOSTERROR:
		/*
 		 * REVISIT: Do we need this check with the latest driver?
 		 *
		 * This can happen when we get here due to I/O aborts
		 * during a PCI remove. In such cases, the SCSI ML could
		 * have invalidated the scsi_cmnd and we should not be
		 * accessing it. Hence we just return.
		 */
		if (unlikely(!csio_is_hw_ready(hw)))
			return;
		/*
		 * REVISIT: Temporarily using FW_HOSTERROR to indicate driver
		 * internal error. Later we should use a value here that is
		 * not going to be used by firmware for any other error.
		 */
		host_status = DID_ERROR;
		CSIO_INC_STATS(scm, n_hosterror);

		break;
	case FW_SCSI_RSP_ERR:
		dma_buf = &req->dma_buf;
		fcp_resp = (struct csio_fcp_resp *)dma_buf->vaddr;
		flags = fcp_resp->flags;
		scsi_status = fcp_resp->scsi_status;

		if (flags & FCP_RSP_LEN_VAL) {
			rsp_len = be32_to_cpu(fcp_resp->rsp_len);
			if ((rsp_len != 0 && rsp_len != 4 && rsp_len != 8) ||
				(fcp_resp->rsp_code != FCP_TMF_CMPL)) {
				host_status = DID_ERROR;
				goto out;
			}
		}

		if ((flags & FCP_SNS_LEN_VAL) && fcp_resp->sns_len) {
			sns_len = be32_to_cpu(fcp_resp->sns_len);
			if (sns_len > SCSI_SENSE_BUFFERSIZE)
				sns_len = SCSI_SENSE_BUFFERSIZE;

			memcpy(cmnd->sense_buffer, &fcp_resp->rsvd1 + rsp_len,
			       sns_len);
			CSIO_INC_STATS(scm, n_autosense);
		}

		csio_scsi_vdbg(hw,
			    "SCSI CMD 0x%x failed: 0x%x\n"
			    "\tSNS: %02x %02x %02x %02x %02x %02x %02x %02x\n"
			    "\tflags: 0x%x resid:0x%x snslen:0x%x rsplen:0x%x"
			    " rspcode:0x%x\n",
			    cmnd->cmnd[0], scsi_status,
			    cmnd->sense_buffer[0], cmnd->sense_buffer[1],			
			    cmnd->sense_buffer[2], cmnd->sense_buffer[3],			
			    cmnd->sense_buffer[4], cmnd->sense_buffer[5],			
			    cmnd->sense_buffer[6], cmnd->sense_buffer[7],			
			    flags, be32_to_cpu(fcp_resp->resid),
			    be32_to_cpu(fcp_resp->sns_len),
			    be32_to_cpu(fcp_resp->rsp_len), fcp_resp->rsp_code);

		scsi_set_resid(cmnd, 0);

		/* Under run */
		if (flags & FCP_RESID_UNDER) {
			scsi_set_resid(cmnd, be32_to_cpu(fcp_resp->resid));

			csio_scsi_vdbg(hw,
			     "Under-run cmnd:0x%x expected len:0x%x"
			     " resid:0x%x underflow:0x%x\n",
			     cmnd->cmnd[0], scsi_bufflen(cmnd),
			     scsi_get_resid(cmnd), cmnd->underflow);

			if (!(flags & FCP_SNS_LEN_VAL) &&
			    (scsi_status == SAM_STAT_GOOD) &&
			    ((scsi_bufflen(cmnd) - scsi_get_resid(cmnd))
			      < cmnd->underflow)) {
				csio_scsi_vdbg(hw,
					    "Under-run error. Min bytes "
					    "expected: 0x%x\n",
					    cmnd->underflow);
				host_status = DID_ERROR;
			}
		} else if (flags & FCP_RESID_OVER) {
			/* Over run */
			csio_scsi_vdbg(hw,
			     "Over run error. cmnd:0x%x len:0x%x resid:0x%x\n",
			      cmnd->cmnd[0], scsi_bufflen(cmnd),
			      scsi_get_resid(cmnd));
			host_status = DID_ERROR;
		}
		CSIO_INC_STATS(scm, n_rsperror);
		break;

	case FW_SCSI_OVER_FLOW_ERR:
		csio_warn(hw, "Over-flow error,cmnd:0x%x expected len:0x%x"
			  " resid:0x%x\n", cmnd->cmnd[0],
			  scsi_bufflen(cmnd), scsi_get_resid(cmnd));
		host_status = DID_ERROR;
		CSIO_INC_STATS(scm, n_ovflerror);
		break;

	case FW_SCSI_UNDER_FLOW_ERR:
		csio_warn(hw, "Under-flow error,cmnd:0x%x expected"
			  " len:0x%x resid:0x%x lun:0x%llx ssn:0x%x\n",
			  cmnd->cmnd[0], scsi_bufflen(cmnd),
			  scsi_get_resid(cmnd), (uint64_t)cmnd->device->lun,
			  csio_osrn_to_rn(osrn)->flowid);
		host_status = DID_ERROR;
		CSIO_INC_STATS(scm, n_unflerror);
		break;

	case FW_SCSI_ABORT_REQUESTED:
	case FW_SCSI_ABORTED:
	case FW_SCSI_CLOSE_REQUESTED:
		csio_scsi_dbg(hw,
			    "Req %p cmd:%p op:%x %s\n", req, cmnd,
			     cmnd->cmnd[0],
			    (req->wr_status == FW_SCSI_CLOSE_REQUESTED) ?
			    "closed" : "aborted");
		/*
		 * csio_eh_abort_handler checks this value to
		 * succeed or fail the abort request.
		 */
		host_status = DID_REQUEUE;
		if (req->wr_status == FW_SCSI_CLOSE_REQUESTED)
			CSIO_INC_STATS(scm, n_closed);
		else
			CSIO_INC_STATS(scm, n_aborted);
		break;

	case FW_SCSI_ABORT_TIMEDOUT:
		/* FW timed out the abort itself */
		csio_scsi_dbg(hw,
			    "FW timed out abort req:%p cmnd:%p status:%x\n",
			    req, cmnd, req->wr_status);
		host_status = DID_ERROR;
		CSIO_INC_STATS(scm, n_abrt_timedout);
		break;

	case FW_RDEV_NOT_READY:
		/*
		 * In firmware, a RDEV can get into this state
		 * temporarily, before moving into dissapeared/lost
		 * state. So, the driver should complete the request equivalent
		 * to device-disappeared!
		 */
		CSIO_INC_STATS(scm, n_rdev_nr_error);
		host_status = DID_ERROR;
		break;

	case FW_ERR_RDEV_LOST:
		CSIO_INC_STATS(scm, n_rdev_lost_error);
		host_status = DID_ERROR;
		break;

	case FW_ERR_RDEV_LOGO:
		CSIO_INC_STATS(scm, n_rdev_logo_error);
		host_status = DID_ERROR;
		break;

	case FW_ERR_RDEV_IMPL_LOGO:
#if 0 /* TODO: add this stat */
		CSIO_INC_STATS(scm, n_rdev_impl_logo_error);
#endif
		host_status = DID_ERROR;
		break;

	case FW_ERR_LINK_DOWN:
		CSIO_INC_STATS(scm, n_link_down_error);
		host_status = DID_ERROR;
		break;

	case FW_FCOE_NO_XCHG:
		CSIO_INC_STATS(scm, n_no_xchg_error);
		host_status = DID_REQUEUE;
		break;

	default:
		csio_err(hw, "Unknown SCSI FW return:%d req:%p cmnd:%p\n",
			    req->wr_status, req, cmnd);
		/* Assert for now */
		CSIO_DB_ASSERT(0);

		/* Do this later */
		CSIO_INC_STATS(scm, n_unknown_error);
		host_status = DID_ERROR;
		break;
	}

out:
	if (req->nsge > 0) {
		scsi_dma_unmap(cmnd);
#ifdef CSIO_DATA_CAPTURE
		csio_scsi_data_capture(hw, req);
#endif
	}

	cmnd->result = (((host_status) << 16) | scsi_status);
	cmnd->scsi_done(cmnd);

	/* Wake up waiting threads */
	csio_scsi_osreq(req) = NULL;
	complete_all(&req->cmplobj.cmpl);

	return;
}

/* TO BE REMOVED LATER */
static inline void
csio_os_dump_buffer(uint8_t *buf, uint32_t buf_len)
{
	uint32_t ii = 0;

	for (ii = 0; ii < buf_len ; ii++) {
		if (!(ii & 0xF))
			printk("\n0x%p:", (buf + ii));
		if (!(ii & 0x7))
			printk(" 0x%02x", buf[ii]);
		else
			printk("%02x", buf[ii]);
	}

	printk("\n");
}

/*
 * csio_iscsi_scsi_err_handler - iSCSI SCSI error handler.
 * @hw: HW module.
 * @req: IO request.
 *
 */
static inline void
csio_iscsi_scsi_err_handler(struct csio_hw *hw, struct csio_ioreq *req)
{
#ifdef __CSIO_FOISCSI_ENABLED__
	struct scsi_cmnd *cmnd  = (struct scsi_cmnd *)csio_scsi_osreq(req);
	struct csio_scsim *scm = csio_hw_to_scsim(hw);
	struct fw_scsi_iscsi_rsp *iresp;
	struct csio_dma_buf *dma_buf;
	uint8_t sbit_to_uflow, scsi_status = 0;
	uint32_t host_status = DID_OK;
	uint32_t sns_len = 0;
	char *data;
	struct csio_os_rnode *osrn =
			(struct csio_os_rnode *)(cmnd->device->hostdata);
	struct csio_rnode_iscsi *rni = csio_rnode_to_iscsi(csio_osrn_to_rn(osrn));

	csio_dbg(hw, "%s: req->wr_status [0x%0x]\n", __FUNCTION__, req->wr_status);
	
	switch (req->wr_status) {
	case FW_HOSTERROR:
		/*
 		 * REVISIT: Do we need this check with the latest driver?
 		 *
		 * This can happen when we get here due to I/O aborts
		 * during a PCI remove. In such cases, the SCSI ML could
		 * have invalidated the scsi_cmnd and we should not be
		 * accessing it. Hence we just return.
		 */
		if (unlikely(!csio_is_hw_ready(hw)))
			return;
		/*
		 * REVISIT: Temporarily using FW_HOSTERROR to indicate driver
		 * internal error. Later we should use a value here that is
		 * not going to be used by firmware for any other error.
		 */
		host_status = DID_ERROR;
		CSIO_INC_STATS(scm, n_hosterror);

		break;
	case FW_SCSI_RSP_ERR:
		dma_buf = &req->dma_buf;
		iresp = (struct fw_scsi_iscsi_rsp *)dma_buf->vaddr;
		sbit_to_uflow = iresp->sbit_to_uflow;
		scsi_status = iresp->status;
		data = (char *)dma_buf->vaddr + 48;

		if (iresp->status == SAM_STAT_CHECK_CONDITION) {
			sns_len = get_unaligned_be16(data);

			if (sns_len > SCSI_SENSE_BUFFERSIZE)
				sns_len = SCSI_SENSE_BUFFERSIZE;

			memcpy(cmnd->sense_buffer, data + 2, sns_len);

			CSIO_INC_STATS(scm, n_autosense);
		}

#ifdef __CSIO_DEBUG__
		csio_dbg(hw,
			"%s: SCSI CMD [0x%x], status [0x%x], sbit_to_uflow [0x%x]\n", __FUNCTION__,
			cmnd->cmnd[0], scsi_status, sbit_to_uflow);
		csio_scsi_dbg(hw, "%s: sense data len [%u] bytes\n", __FUNCTION__, sns_len);
		csio_os_dump_buffer(cmnd->sense_buffer, sns_len);
#endif

		/* Under run */
		if (sbit_to_uflow & (F_FW_SCSI_ISCSI_RSP_BIDIR_UFLOW |
					F_FW_SCSI_ISCSI_RSP_BIDIR_OFLOW)) {

			int res_cnt = be32_to_cpu(iresp->bidir_res_cnt);


			csio_scsi_vdbg(hw,
			     "Under-run cmnd:0x%x expected len:0x%x"
			     " resid:0x%x underflow:0x%x\n",
			     cmnd->cmnd[0], scsi_bufflen(cmnd),
			     scsi_get_resid(cmnd), cmnd->underflow);
			
			if (scsi_bidi_cmnd(cmnd) && res_cnt > 0 &&
				(sbit_to_uflow & F_FW_SCSI_ISCSI_RSP_BIDIR_OFLOW ||
				 res_cnt <= scsi_in(cmnd)->length))
				scsi_in(cmnd)->resid = res_cnt;
			else
				host_status = DID_BAD_TARGET;
		}
		
		if (sbit_to_uflow & (F_FW_SCSI_ISCSI_RSP_UFLOW |
				   F_FW_SCSI_ISCSI_RSP_OFLOW)) {

			int res_cnt = be32_to_cpu(iresp->res_cnt);
			
			csio_scsi_vdbg(hw,
			     "Over run error. cmnd:0x%x len:0x%x resid:0x%x\n",
			      cmnd->cmnd[0], scsi_bufflen(cmnd),
			      scsi_get_resid(cmnd));

			if (res_cnt > 0 &&
				(iresp->sbit_to_uflow & F_FW_SCSI_ISCSI_RSP_OFLOW ||
				res_cnt <= scsi_bufflen(cmnd)))
				scsi_set_resid(cmnd, res_cnt);
			else
				host_status = DID_BAD_TARGET;
		}
		CSIO_INC_STATS(scm, n_rsperror);
		break;

	case FW_SCSI_DDP_ERR:
	case FW_SCSI_TASK_ERR:
		if (csio_rnism_in_ready(rni))
			host_status = DID_REQUEUE;
		else if (csio_rnism_in_recovery(rni))
			host_status = DID_TRANSPORT_DISRUPTED;
		else
			host_status = DID_NO_CONNECT;

		csio_dbg(hw, "%s: wr_status [%u], %s req [%p].\n",
				__FUNCTION__, req->wr_status,
				(csio_rnism_in_ready(rni) ||
				csio_rnism_in_recovery(rni)) ?
				"requeuing" : "failing",
				req);
		break;

	case FW_SCSI_ABORT_REQUESTED:
	case FW_SCSI_ABORTED:
	case FW_SCSI_CLOSE_REQUESTED:
		csio_scsi_dbg(hw,
				"Req %p cmd:%p op:%x %s\n", req, cmnd,
				cmnd->cmnd[0],
				(req->wr_status == FW_SCSI_CLOSE_REQUESTED) ?
				"closed" : "aborted");

		host_status = DID_REQUEUE;
		if (req->wr_status == FW_SCSI_CLOSE_REQUESTED)
			CSIO_INC_STATS(scm, n_closed);
		else
			CSIO_INC_STATS(scm, n_aborted);
		break;

	default:
		csio_err(hw, "Unknown SCSI FW return:%d req:%p cmnd:%p\n",
			    req->wr_status, req, cmnd);
		/* Assert for now */
		CSIO_DB_ASSERT(0);

		/* Do this later */
		CSIO_INC_STATS(scm, n_unknown_error);
		host_status = DID_ERROR;
		break;
	}

	if (req->nsge > 0) {
		scsi_dma_unmap(cmnd);
#ifdef CSIO_DATA_CAPTURE
		csio_scsi_data_capture(hw, req);
#endif
	}

	cmnd->result = (((host_status) << 16) | scsi_status);
	cmnd->scsi_done(cmnd);

#if 0
	/*
	 * If abort timed out, let the blocked abort handler time out as well.
	 * There is no way to pass a status otherwise. This is until we
	 * compeltely trust firmware to do the job and be alive, and hence
	 * not time the abort in the abort handler.
	 */
	if (req->wr_status != FW_SCSI_ABORT_TIMEDOUT)
#endif
	/* Wake up any threads waiting for the below to happen */
	csio_scsi_osreq(req) = NULL;
	complete_all(&req->cmplobj.cmpl);

	return;
#endif
}

/*
 * csio_os_scsi_cbfn - SCSI callback function.
 * @hw: HW module.
 * @req: IO request.
 *
 */
static void
csio_os_scsi_cbfn(struct csio_hw *hw, struct csio_ioreq *req)
{
	struct scsi_cmnd *cmnd  = (struct scsi_cmnd *)csio_scsi_osreq(req);
	uint8_t scsi_status = SAM_STAT_GOOD;
	uint32_t host_status = DID_OK;

#if 0
	{
		struct scatterlist *sgel;
		void *addr;
		int len;

		if (req->nsge > 0) {
			if (likely(csio_is_hw_ready(hw))) {
				sgel = scsi_sglist(cmnd);
				addr = sg_virt(sgel);
				len = sg_dma_len(sgel);
				csio_scsi_dbg(hw, "%s %d bytes:\n",
				csio_is_fcoe(hw) ? "FCP Data":"iSCSI Data", len);
				csio_os_dump_buffer(addr, (len > 16)? 16 : len);
			}
		}
	}
#endif

	if (likely(req->wr_status == FW_SUCCESS)) {
		if (likely(req->nsge > 0)) {
			scsi_dma_unmap(cmnd);
#ifdef __CSIO_DDP_SUPPORT__
			if (unlikely(req->dcopy))
				host_status = csio_scsi_copy_to_sgl(hw, req);
#endif
#ifdef CSIO_DATA_CAPTURE
			csio_scsi_data_capture(hw, req);
#endif
		}

		cmnd->result = (((host_status) << 16) | scsi_status);
		cmnd->scsi_done(cmnd);
		csio_scsi_osreq(req) = NULL;
		CSIO_INC_STATS(csio_hw_to_scsim(hw), n_tot_success);
	} else {
		/* Error handling */
		if (csio_is_fcoe(hw)) {
			csio_fcoe_scsi_err_handler(hw, req);	
		} else { /* iSCSI */
#ifdef __CSIO_FOISCSI_ENABLED__
			csio_iscsi_scsi_err_handler(hw, req);
#endif
		}
	}

#if 0
	{
		static int counter = 0;
		/* Print every csio_scsi_prt_freq'th I/O to console */
		if (!(counter++ % csio_scsi_prt_freq))
			csio_scsi_vdbg(hw, "ioreq:%p status:0x%x\n",
					req, req->wr_status);
	}

	CSIO_TRACE(hw, CSIO_HW_MOD, CSIO_DBG_LEV, req, cmnd, req->wr_status, 0);
#endif

	return;
}

static inline int
csio_os_rnode_chkrdy(struct csio_hw *hw, struct csio_os_rnode *osrn,
		     struct scsi_cmnd *cmnd)
{
	if (csio_is_fcoe(hw)) {
		struct fc_rport *rport = starget_to_rport(
					 scsi_target(cmnd->device));
		return fc_remote_port_chkready(rport);
	}
#ifdef __CSIO_FOISCSI_ENABLED__	
	else
		return csio_iscsi_session_chkready(csio_osrn_to_rn(osrn));
#else
	return 0;
#endif
}

/**
 * csio_queuecommand: The routine to start an SCSI IO.
 * @cmnd: The SCSI IO
 * @done: The ML routine to call once IO is done from our side.
 *
 * This routine does the following:
 * 	- checks if HW and Rnode SMs are in a ready state.
 * 	- gets a free ioreq structure (which is already initialized
 * 	  to uninit during its allocation) from the ioreq_freelist.
 * 	- If there are SG elements to be mapped (scsi_sg_count(cmnd) > 0),
 * 	  calls scsi_dma_map() to map them.
 * 	  If mapping fails, or we dont support that many mappings, error out.
 * 	- Else, initialize, ioreq->lnode, and save off the scsi_cmnd pointer
 * 	  in ioreq->scratch1.
 * 	- Kick off the SCSI SM for this IO. If a non-zero value is returned,
 * 	  it means we didnt get resources to do the IO. Return busy status
 * 	  to ML.
 */
static int
csio_queuecommand_lck(struct scsi_cmnd *cmnd, void (*done)(struct scsi_cmnd *))
{
	struct csio_os_lnode *osln = shost_priv(cmnd->device->host);
	struct csio_lnode *ln = csio_osln_to_ln(osln);
	struct csio_hw *hw = csio_osln_to_hw(osln);
	struct csio_os_hw *oshw = csio_hw_to_os(hw);
	struct csio_scsim *scsim = csio_hw_to_scsim(hw);
	struct csio_os_rnode *osrn =
			(struct csio_os_rnode *)(cmnd->device->hostdata);
	struct csio_ioreq *ioreq = NULL;
	unsigned long flags;
	uint32_t nsge = 0;
	int rv = SCSI_MLQUEUE_HOST_BUSY, nr;
	enum csio_oss_error retval;
	int cpu = cmnd->request->cpu;
	struct csio_scsi_qset *sqset;

	csio_scsi_vdbg(hw, "portid:%d req->cpu:%d curcpu:%d\n",
		    ln->portid, cpu, smp_processor_id());

	if (cpu < 0)
		cpu = smp_processor_id();

	sqset = &oshw->sqset[ln->portid][cpu];

	nr = csio_os_rnode_chkrdy(hw, osrn, cmnd);
	if (nr) {
		cmnd->result = nr;
		CSIO_INC_STATS(scsim, n_rn_nr_error);
		goto err_done;
	}

	if (unlikely(!csio_is_hw_ready(hw))) {
		csio_err(hw, "HW module is not ready.\n");
		cmnd->result = (DID_REQUEUE << 16);
		CSIO_INC_STATS(scsim, n_hw_nr_error);
		goto err_done;
	}

#if 0
	/* This is only for iSCSI internal debug usage
	 * and will get rid of it.
	 */
	if (unlikely(!csio_osrn_to_rn(osrn))) {
		csio_dbg(hw, "%s: Remote node don't exist, "
			"buggy lookup bailing command [%p]\n",
				__FUNCTION__, cmnd);
	       cmnd->result = (DID_TRANSPORT_DISRUPTED << 16);	
	       goto err_done;
	}

#endif

	/* Calculate req->nsge, if there are SG elements to be mapped  */
	nsge = scsi_dma_map(cmnd);
	if (unlikely(nsge < 0)) {
		csio_err(hw, "SCSI DMA mapping failed! (error val = %d)"
			    " SGE Count: %d\n", nsge, scsi_sg_count(cmnd));
		CSIO_INC_STATS(scsim, n_dmamap_error);
		rv = SCSI_MLQUEUE_HOST_BUSY;
		goto err;
	/* Do we support so many mappings? */
	} else if (unlikely(nsge > scsim->max_sge)) {
		csio_err(hw, "More SGEs than can be supported."
			    " SGEs: %d, Max SGEs: %d\n",
			    nsge, scsim->max_sge);
		CSIO_INC_STATS(scsim, n_unsupp_sge_error);
		rv = SCSI_MLQUEUE_HOST_BUSY;
		goto err_dma_unmap;
	}

	/* Get a free ioreq structure - SM is already set to uninit */
	ioreq = csio_get_scsi_ioreq_lock(hw, scsim);
	if (!ioreq) {
		csio_err(hw,
			    "Out of IO request elements. Num active ioreq:%d\n",
			    scsim->stats.n_active);
		CSIO_INC_STATS(scsim, n_no_req_error);
		goto err_dma_unmap;
	}

	ioreq->nsge		= nsge;
	ioreq->lnode 		= ln;
	ioreq->rnode 		= csio_osrn_to_rn(osrn);
	ioreq->iq_idx 		= sqset->iq_idx;
	ioreq->eq_idx 		= sqset->eq_idx;
	ioreq->wr_status	= 0;
	ioreq->drv_status	= CSIO_SUCCESS;
	csio_scsi_osreq(ioreq) 	= (void *)cmnd;
	/* SCSI mid-layer times us */
	ioreq->tmo     		= 0;
	
	switch (cmnd->sc_data_direction) {
		case DMA_BIDIRECTIONAL:
			ioreq->datadir = CSIO_IOREQF_DMA_BIDI;
			CSIO_INC_STATS(ln, n_control_requests);
			break;
		case DMA_TO_DEVICE:
			ioreq->datadir = CSIO_IOREQF_DMA_WRITE;
			CSIO_INC_STATS(ln, n_output_requests);
			ln->stats.n_output_bytes += scsi_bufflen(cmnd);
			break;
		case DMA_FROM_DEVICE:
			ioreq->datadir = CSIO_IOREQF_DMA_READ;
			CSIO_INC_STATS(ln, n_input_requests);
			ln->stats.n_input_bytes += scsi_bufflen(cmnd);
			break;
		case DMA_NONE:
			ioreq->datadir = CSIO_IOREQF_DMA_NONE;
			CSIO_INC_STATS(ln, n_control_requests);
			break;
		default:
			CSIO_DB_ASSERT(0);
			break;
	}

	/* Set cbfn */
	ioreq->io_cbfn = csio_os_scsi_cbfn;

	/* Needed during abort */
	cmnd->host_scribble = (unsigned char *)ioreq;
	cmnd->scsi_done = done;
	csio_scsi_tm_op(cmnd)	= 0;

	/* Kick off SCSI IO SM on the ioreq */
	csio_spin_lock_irqsave(hw, &hw->lock, flags);
	retval = csio_scsi_start_io(ioreq);
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

	if (retval != CSIO_SUCCESS) {
		csio_err(hw, "ioreq: %p couldnt be started, retval:%d\n",
			    ioreq, retval);
		CSIO_INC_STATS(scsim, n_busy_error);
		goto err_put_req;
	}

	return 0;

err_put_req:
	csio_put_scsi_ioreq_lock(hw, scsim, ioreq);
err_dma_unmap:
	if (nsge > 0)
		scsi_dma_unmap(cmnd);
err:
	return rv;

err_done:
	done(cmnd);
	return 0;
}

#ifdef DEF_SCSI_QCMD
static DEF_SCSI_QCMD(csio_queuecommand);
#else
#define csio_queuecommand csio_queuecommand_lck
#endif

/*
 * csio_wait_for_rport_unblock - Block SCSI eh thread for blocked rport
 * @cmnd: SCSI command that scsi_eh is trying to recover
 *
 * This routine blocks the scsi_eh thread until the fc_rport leaves the
 * FC_PORTSTATE_BLOCKED. This is necessary to avoid the scsi_eh
 * failing recovery actions for blocked rports which would lead to
 * offlined SCSI devices.
 */
static void
csio_wait_for_rport_unblock(struct scsi_cmnd *cmnd)
{
	struct Scsi_Host *shost = cmnd->device->host;
	struct fc_rport *rport = starget_to_rport(scsi_target(cmnd->device));

	spin_lock_irq(shost->host_lock);
	while (rport->port_state == FC_PORTSTATE_BLOCKED) {
		spin_unlock_irq(shost->host_lock);
		msleep(1000);
		spin_lock_irq(shost->host_lock);
	}
	spin_unlock_irq(shost->host_lock);
	return;
}

static csio_retval_t
csio_do_abrt_cls(struct csio_hw *hw, struct csio_ioreq *ioreq, bool abort)
{
	struct csio_os_hw *oshw = csio_hw_to_os(hw);
	enum csio_oss_error rv;
	int cpu = smp_processor_id();
	struct csio_lnode *ln = ioreq->lnode;
	struct csio_scsi_qset *sqset = &oshw->sqset[ln->portid][cpu];;

	ioreq->tmo = (csio_is_fcoe(hw) ? CSIO_SCSI_FCOE_ABRT_TMO_MS :
				   	 CSIO_SCSI_ISCSI_ABRT_TMO_MS);
	/*
	 * Use current processor queue for posting the abort/close, but retain
	 * the ingress queue ID of the original I/O being aborted/closed - we
	 * need the abort/close completion to be received on the same queue
	 * as the original I/O.
	 */
	ioreq->eq_idx = sqset->eq_idx;

	/*
	 * REVISIT: Handle the failure to abort/close more appropriately.
	 * Can we enqueue the ioreq in the res_wait_q, since we are reusing
	 * the original ioreq, which is already in the active_q?
	 * Return failure for now.
	 */
	if (abort == SCSI_ABORT)
		rv = csio_scsi_abort(ioreq);
	else /* close */
		rv = csio_scsi_close(ioreq);

	return rv;
}

static int
csio_eh_abort_handler(struct scsi_cmnd *cmnd)
{
	struct csio_ioreq *ioreq;
	struct csio_os_lnode *osln = shost_priv(cmnd->device->host);
	struct csio_hw *hw = csio_osln_to_hw(osln);
	struct csio_lnode *ln = csio_osln_to_ln(osln);
	struct csio_scsim *scsim = csio_hw_to_scsim(hw);
	int ready = 0;
	unsigned long tmo = 0;
	enum csio_oss_error rv;
#ifdef __CSIO_DEBUG__
	struct csio_os_rnode *osrn =
			(struct csio_os_rnode *)(cmnd->device->hostdata);
#endif /* __CSIO_DEBUG__ */

 	/* REVISIT: To be replaced by fc_block_scsi_eh() in newer kernels */
	if (csio_is_fcoe(ln->hwp))
		csio_wait_for_rport_unblock(cmnd);

	ioreq = (struct csio_ioreq *)cmnd->host_scribble;
	if (!ioreq)
		return SUCCESS;

#ifdef __CSIO_DEBUG__
	if (!osrn) {
		csio_err(hw, "Abort handler recv invalid rnode for ioreq:%p\n",
			ioreq);
		return FAILED;
	}

	csio_scsi_dbg(hw, "Request to abort "
		"ioreq:%p cmd:%p cdb:%08llx ssni:0x%x lun:%llu iq:0x%x\n",
		ioreq, cmnd, *((uint64_t *)cmnd->cmnd),
		(csio_osrn_to_rn(osrn))->flowid,
		(uint64_t)cmnd->device->lun, csio_q_physiqid(hw, ioreq->iq_idx));
#endif /* __CSIO_DEBUG__ */

	if (((struct scsi_cmnd *)csio_scsi_osreq(ioreq)) != cmnd) {
		csio_dbg(hw, "Possible race b/w cmpltn & EH thread,osreq:%p\n",
			    csio_scsi_osreq(ioreq));
		CSIO_INC_STATS(scsim, n_abrt_race_comp);
		return SUCCESS;
	}

	if (csio_is_fcoe(hw)) {
		ready = csio_is_lnf_ready(csio_lnode_to_fcoe(ln));
		tmo = CSIO_SCSI_FCOE_ABRT_TMO_MS;
	} else {
#ifdef __CSIO_FOISCSI_ENABLED__
		ready = csio_iscsi_get_session_state(ioreq->rnode);
		csio_scsi_tm_op(cmnd)   = FW_SCSI_ISCSI_ABORT_FUNC;
		tmo = CSIO_SCSI_ISCSI_ABRT_TMO_MS;
#endif
	}

	csio_spin_lock_irq(hw, &hw->lock);
	rv = csio_do_abrt_cls(hw, ioreq, (ready ? SCSI_ABORT : SCSI_CLOSE));
	csio_spin_unlock_irq(hw, &hw->lock);

	if (rv != CSIO_SUCCESS) {
		if (rv == CSIO_INVAL) {
			/*
			 * Return success, if abort/close request issued on
			 * already completed IO
			 */
			return SUCCESS;
		}

		if (ready)
			CSIO_INC_STATS(scsim, n_abrt_busy_error);
		else
			CSIO_INC_STATS(scsim, n_cls_busy_error);

		goto inval_osreq;
	}


#ifdef __CSIO_FOISCSI_ENABLED__
	if (csio_is_fcoe(hw) ||
			csio_iscsi_get_session_state(ioreq->rnode)) {
		init_completion(&ioreq->cmplobj.cmpl);
		wait_for_completion_timeout(&ioreq->cmplobj.cmpl,
				msecs_to_jiffies(tmo));
	}
#else
	/* Wait for completion */
	init_completion(&ioreq->cmplobj.cmpl);
	wait_for_completion_timeout(&ioreq->cmplobj.cmpl,
				    msecs_to_jiffies(tmo));
#endif	

	/* FW didnt respond to abort within our timeout */
	if (((struct scsi_cmnd *)csio_scsi_osreq(ioreq)) == cmnd) {
		csio_err(hw, "Abort timed out -- req: %p\n", ioreq);
		CSIO_INC_STATS(scsim, n_abrt_timedout);

inval_osreq:
		/*
		 * SCSI ML guanrantees on return of the EH thread that
		 * all scsi_cmnds in the EH queue will have scsi_finish_cmd
		 * called for them. So on return from here, there is no
		 * guarantee that our reference of the scsi_cmnd is valid.
		 * We however keep our ioreq around, until we hear back from
		 * FW, or until EOL. We therefore invalidate our reference
		 * of scsi_cmnd in the ioreq, so we dont access stale memory.
		 * We call scsi_done as well, although this has no effect
		 * for a command that has EH running on it.
		 */
		if (ioreq->nsge > 0) {
			scsi_dma_unmap(cmnd);
#ifdef CSIO_DATA_CAPTURE
			csio_scsi_data_capture(hw, ioreq);
#endif
		}

		csio_spin_lock_irq(hw, &hw->lock);
		csio_scsi_osreq(ioreq) = NULL;
		csio_spin_unlock_irq(hw, &hw->lock);

		cmnd->result = (DID_ERROR << 16);
		cmnd->scsi_done(cmnd);

		return FAILED;
	}

	/*
	 * We can safely use cmnd->result here, although we have already
	 * called scsi_done for this cmnd. SCSI-ML guarantees that the
	 * completion handler doesnt run for a command that has kicked
	 * off the error handler thread.
	 * NOTE: Expect iSCSI completion handler to return successfully
	 * aborted I/Os with DID_REQUEUE.
	 */
	/* FW successfully aborted the request */
	if (host_byte(cmnd->result) == DID_REQUEUE) {
		csio_info(hw,
		    	"Aborted SCSI req:%p cmnd:%p to LUN:%llu slnum:0x%lx\n",
		    	ioreq, cmnd, (uint64_t)cmnd->device->lun, cmnd->serial_number);
		return SUCCESS;
	} else {
		csio_info(hw,
		    	"Failed to abort SCSI req:%p to LUN:%llu slnum:0x%lx\n",
		    	ioreq, (uint64_t)cmnd->device->lun, cmnd->serial_number);
		return FAILED;
	}
}

/*
 * csio_os_tm_cbfn - TM callback function.
 * @hw: HW module.
 * @req: IO request.
 *
 * Cache the result in 'cmnd', since ioreq will be freed soon
 * after we return from here, and the waiting thread shouldnt trust
 * the ioreq contents.
 */
static void
csio_os_tm_cbfn(struct csio_hw *hw, struct csio_ioreq *req)
{
	struct scsi_cmnd *cmnd  = (struct scsi_cmnd *)csio_scsi_osreq(req);
	struct csio_dma_buf *dma_buf;
	uint8_t flags = 0;

	csio_scsi_dbg(hw, "req: %p in csio_os_tm_cbfn status: %d\n",
		      req, req->wr_status);
	csio_scsi_dbg(hw,
	    "cmpl req %p cmd:%p tm lun:%4llu wr:%x\n", req, cmnd,
	     (uint64_t)cmnd->device->lun,
	    req->wr_status);

	/* Cache FW return status */
	cmnd->SCp.Status = req->wr_status;

	/* Special handling based on FCP response */
	if (csio_is_fcoe(hw)) {
		struct csio_fcp_resp *fcp_resp;

		/*
		 * FW returns us this error, if flags were set. FCP4 says
		 * FCP_RSP_LEN_VAL in flags shall be set for TM completions.
		 * So if a target were to set this bit, we expect that the
		 * rsp_code is set to FCP_TMF_CMPL for a successful TM
		 * completion. Any other rsp_code means TM operation failed.
		 * If a target were to just ignore setting flags, we treat
		 * the TM operation as success, and FW returns FW_SUCCESS.
		 */
		if (req->wr_status == FW_SCSI_RSP_ERR) {
			dma_buf = &req->dma_buf;
			fcp_resp = (struct csio_fcp_resp *)dma_buf->vaddr;
			flags = fcp_resp->flags;

			/* Modify return status if flags indicate success */
			if (flags & FCP_RSP_LEN_VAL)
				if (fcp_resp->rsp_code == FCP_TMF_CMPL)
					cmnd->SCp.Status = FW_SUCCESS;

			csio_scsi_dbg(hw, "TM FCP rsp code: %d\n",
				      fcp_resp->rsp_code);
		}
	}

#if 0
	/* fw_wr is used by abort processing, hence clear out cached data */
	memset(req->fw_wr, 0, CSIO_STOR_MAX_WRSZ);
#endif
	/* Wake up the TM handler thread */
	csio_scsi_osreq(req) = NULL;

	return;
}

static int
csio_eh_lun_reset_handler(struct scsi_cmnd *cmnd)
{
	struct csio_os_lnode *osln = shost_priv(cmnd->device->host);
	struct csio_hw *hw = csio_osln_to_hw(osln);
	struct csio_os_hw *oshw = csio_hw_to_os(hw);
	struct csio_scsim *scsim = csio_hw_to_scsim(hw);
	struct csio_lnode *ln = csio_osln_to_ln(osln);
	struct csio_os_rnode *osrn =
			(struct csio_os_rnode *)(cmnd->device->hostdata);
	struct csio_ioreq *ioreq = NULL;
	struct csio_scsi_qset *sqset;
	unsigned long flags;
	enum csio_oss_error retval;
	int count;
	struct csio_list local_q;
	struct csio_scsi_level_data sld;

	if (!osrn) {
		csio_err(hw, "LUN reset recevied invalid rnode\n");
		goto fail;
	}

	csio_scsi_dbg(hw, "Request to reset LUN:%llu (ssni:0x%x tgtid:%d)\n",
		      (uint64_t)cmnd->device->lun, (csio_osrn_to_rn(osrn))->flowid,
		      osrn->scsi_id);

	if (!csio_is_lnf_ready(csio_lnode_to_fcoe(ln))) {
		csio_err(hw, "LUN reset cannot be issued on non-ready"
			     " local node vnpi:0x%x (LUN:%llu)\n",
			     (csio_lnode_to_fcoe(ln))->vnp_flowid,
			     (uint64_t)cmnd->device->lun);
		goto fail;
	}

	/* Lnode is ready, now wait on rport node readiness */
 	/* REVISIT: To be replaced by fc_block_scsi_eh()
	 * in newer kernels
	 */
	csio_wait_for_rport_unblock(cmnd);

	/*
	 * If we have blocked in the previous call, at this point, either the
	 * remote node has come back online, or device loss timer has fired
	 * and the remote node is destroyed. Allow the LUN reset only for
	 * the former case, since LUN reset is a TMF I/O on the wire, and we
	 * need a valid session to issue it.
	 */
	if (csio_os_rnode_chkrdy(hw, osrn, cmnd)) {
		csio_err(hw, "LUN reset cannot be issued on non-ready"
			     " remote node ssni:0x%x (LUN:%llu)\n",
			     (csio_osrn_to_rn(osrn))->flowid,
			     (uint64_t)cmnd->device->lun);
		goto fail;
	}

	/* Get a free ioreq structure - SM is already set to uninit */
	ioreq = csio_get_scsi_ioreq_lock(hw, scsim);

	if (!ioreq) {
		csio_err(hw,
			"Out of IO request elements. Num active ioreq:%d\n",
			 scsim->stats.n_active);
		goto fail;
	}

	sqset 			= &oshw->sqset[ln->portid][smp_processor_id()];
	ioreq->nsge		= 0;
	ioreq->lnode 		= ln;
	ioreq->rnode 		= csio_osrn_to_rn(osrn);
	ioreq->iq_idx 		= sqset->iq_idx;
	ioreq->eq_idx 		= sqset->eq_idx;

	csio_scsi_osreq(ioreq)	= cmnd;
	cmnd->host_scribble	= (unsigned char *)ioreq;
	cmnd->SCp.Status	= 0;

	csio_scsi_tm_op(cmnd)	= FCP_TMF_LUN_RESET;
	ioreq->tmo		= CSIO_SCSI_FCOE_LUNRST_TMO_MS / 1000;

	/*
	 * FW times the LUN reset for ioreq->tmo, so we got to wait a little
	 * longer (10s for now) than that to allow FW to return the timed
	 * out command.
	 */
	count = CSIO_ROUNDUP((ioreq->tmo + 10) * 1000, CSIO_SCSI_TM_POLL_MS);

	/* Set cbfn */
	ioreq->io_cbfn = csio_os_tm_cbfn;

	csio_head_init(&local_q);
	/* Save of the ioreq info for later use */
	sld.level = CSIO_LEV_LUN;
	sld.lnode = ioreq->lnode;
	sld.rnode = ioreq->rnode;
	sld.oslun = (uint64_t)cmnd->device->lun;

	csio_spin_lock_irqsave(hw, &hw->lock, flags);
	/* Kick off TM SM on the ioreq */
	retval = csio_scsi_start_tm(ioreq);
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

	if (retval != CSIO_SUCCESS) {
		csio_err(hw, "LUN reset failed to start req:%p, retval:%d\n",
			    ioreq, retval);
		goto fail_ret_ioreq;
	}

	csio_scsi_dbg(hw, "Waiting max %d secs for LUN reset completion\n",
		    count * (CSIO_SCSI_TM_POLL_MS / 1000));
	/* Wait for completion */
	while ((((struct scsi_cmnd *)csio_scsi_osreq(ioreq)) == cmnd)
								&& count--)
		msleep(CSIO_SCSI_TM_POLL_MS);

	/* LUN reset timed-out */
	if (((struct scsi_cmnd *)csio_scsi_osreq(ioreq)) == cmnd) {
		csio_err(hw, "LUN reset timed out -- req: %p\n", ioreq);

		csio_spin_lock_irq(hw, &hw->lock);
		csio_scsi_drvcleanup(ioreq);
		csio_deq_elem(ioreq);
		csio_spin_unlock_irq(hw, &hw->lock);

		goto fail_ret_ioreq;
	}

	/* LUN reset returned, check cached status */
	if (cmnd->SCp.Status != FW_SUCCESS) {
		csio_err(hw, "LUN:%llu reset failed. status: %d\n",
			    (uint64_t)cmnd->device->lun, cmnd->SCp.Status);
		goto fail;
	}

	/* LUN reset succeeded, Start aborting affected I/Os */
	/*
	 * Since the host guarantees during LUN reset that there
	 * will not be any more I/Os to that LUN, until the LUN reset
	 * completes, we gather pending I/Os after the LUN reset.
	 */
	csio_spin_lock_irq(hw, &hw->lock);
	csio_scsi_gather_active_ios(scsim, &sld, &local_q);

	retval = csio_scsi_abort_io_q(scsim, &local_q, 30000);
	csio_spin_unlock_irq(hw, &hw->lock);
		
	/* Aborts may have timed out */
	if (retval != CSIO_SUCCESS) {
		csio_err(hw, "Attempt to abort I/Os during LUN reset of %llu"
			    " returned %d\n", (uint64_t)cmnd->device->lun, retval);
		/* Return I/Os back to active_q */
		csio_spin_lock_irq(hw, &hw->lock);
		csio_enq_list_at_tail(&scsim->active_q, &local_q);
		csio_spin_unlock_irq(hw, &hw->lock);
		goto fail;
	}

	CSIO_INC_STATS(csio_osrn_to_rn(osrn), n_lun_rst);

	csio_info(hw, "LUN:%llu reset successful\n", (uint64_t)cmnd->device->lun);

	return SUCCESS;

fail_ret_ioreq:
	csio_put_scsi_ioreq_lock(hw, scsim, ioreq);
fail:
	CSIO_INC_STATS(csio_osrn_to_rn(osrn), n_lun_rst_fail);
	return FAILED;
}

static int
csio_eh_iscsi_lun_reset_handler(struct scsi_cmnd *cmnd)
{
	struct csio_os_lnode *osln = shost_priv(cmnd->device->host);
	struct csio_hw *hw = csio_osln_to_hw(osln);
	struct csio_os_hw *oshw = csio_hw_to_os(hw);
	struct csio_scsim *scsim = csio_hw_to_scsim(hw);
	struct csio_lnode *ln = csio_osln_to_ln(osln);
	struct csio_os_rnode *osrn =
			(struct csio_os_rnode *)(cmnd->device->hostdata);
	struct csio_ioreq *ioreq = NULL;
	struct csio_scsi_qset *sqset;
	unsigned long flags;
	enum csio_oss_error retval;
	int count;
	struct csio_list local_q;
	struct csio_scsi_level_data sld;

	if (!osrn) {
		csio_err(hw, "LUN reset recevied invalid rnode\n");
		goto fail;
	}

	csio_scsi_dbg(hw, "Request to reset LUN:%llu (ssni:0x%x tgtid:%d)\n",
		      (uint64_t)cmnd->device->lun, (csio_osrn_to_rn(osrn))->flowid,
		      osrn->scsi_id);

#ifdef __CSIO_FOISCSI_ENABLED__	
	if (csio_iscsi_session_chkready(&osrn->rnode)) {
		csio_err(hw, "LUN reset cannot be issued on non-ready"
			     " session :0x%x (LUN:%llu)\n",
			     osrn->rnode.flowid,
			     (uint64_t)cmnd->device->lun);
		goto fail;
	}
#endif

	/* Get a free ioreq structure - SM is already set to uninit */
	ioreq = csio_get_scsi_ioreq_lock(hw, scsim);

	if (!ioreq) {
		csio_err(hw,
			"Out of IO request elements. Num active ioreq:%d\n",
			 scsim->stats.n_active);
		goto fail;
	}

	sqset 			= &oshw->sqset[ln->portid][smp_processor_id()];
	ioreq->nsge		= 0;
	ioreq->lnode 		= ln;
	ioreq->rnode 		= csio_osrn_to_rn(osrn);
	ioreq->iq_idx 		= sqset->iq_idx;
	ioreq->eq_idx 		= sqset->eq_idx;

	csio_scsi_osreq(ioreq)	= cmnd;
	cmnd->host_scribble	= (unsigned char *)ioreq;
	cmnd->SCp.Status	= 0;

#ifdef __CSIO_FOISCSI_ENABLED__
	csio_scsi_tm_op(cmnd)	= FW_SCSI_ISCSI_LUN_RESET_FUNC;
	ioreq->tmo		= CSIO_SCSI_ISCSI_LUNRST_TMO_MS / 1000;
#endif

	/*
	 * FW times the LUN reset for ioreq->tmo, so we got to wait a little
	 * longer (10s for now) than that to allow FW to return the timed
	 * out command.
	 */
	count = CSIO_ROUNDUP((ioreq->tmo + 10) * 1000, CSIO_SCSI_TM_POLL_MS);

	/* Set cbfn */
	ioreq->io_cbfn = csio_os_tm_cbfn;

	csio_head_init(&local_q);
	/* Save of the ioreq info for later use */
	sld.level = CSIO_LEV_LUN;
	sld.lnode = ioreq->lnode;
	sld.rnode = ioreq->rnode;
	sld.oslun = (uint64_t)cmnd->device->lun;

	csio_spin_lock_irqsave(hw, &hw->lock, flags);
	/* Kick off TM SM on the ioreq */
	retval = csio_scsi_start_tm(ioreq);
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

	if (retval != CSIO_SUCCESS) {
		csio_err(hw, "LUN reset failed to start req:%p, retval:%d\n",
			    ioreq, retval);
		goto fail_ret_ioreq;
	}

	csio_scsi_dbg(hw, "Waiting max %d secs for LUN reset completion\n",
		    count * (CSIO_SCSI_TM_POLL_MS / 1000));
	/* Wait for completion */
	while ((((struct scsi_cmnd *)csio_scsi_osreq(ioreq)) == cmnd)
								&& count--)
		msleep(CSIO_SCSI_TM_POLL_MS);

	/* LUN reset timed-out */
	if (((struct scsi_cmnd *)csio_scsi_osreq(ioreq)) == cmnd) {
		csio_err(hw, "LUN reset timed out -- req: %p\n", ioreq);

		csio_spin_lock_irq(hw, &hw->lock);
		csio_scsi_drvcleanup(ioreq);
		csio_deq_elem(ioreq);
		csio_spin_unlock_irq(hw, &hw->lock);

		goto fail_ret_ioreq;
	}

	/* LUN reset returned, check cached status */
	if (cmnd->SCp.Status != FW_SUCCESS) {
		csio_err(hw, "LUN:%llu reset failed. status: %d\n",
			    (uint64_t)cmnd->device->lun, cmnd->SCp.Status);
		goto fail;
	}

	/* LUN reset succeeded, Start aborting affected I/Os */
	/*
	 * Since the host guarantees during LUN reset that there
	 * will not be any more I/Os to that LUN, until the LUN reset
	 * completes, we gather pending I/Os after the LUN reset.
	 */
	csio_spin_lock_irq(hw, &hw->lock);
	csio_scsi_gather_active_ios(scsim, &sld, &local_q);

	csio_scsi_cleanup_io_q(scsim, &local_q);

	csio_spin_unlock_irq(hw, &hw->lock);

	CSIO_INC_STATS(csio_osrn_to_rn(osrn), n_lun_rst);

	csio_info(hw, "LUN:%llu reset successful\n", (uint64_t)cmnd->device->lun);

	return SUCCESS;

fail_ret_ioreq:
	csio_put_scsi_ioreq_lock(hw, scsim, ioreq);
fail:
	CSIO_INC_STATS(csio_osrn_to_rn(osrn), n_lun_rst_fail);
	return FAILED;
}

static int
csio_eh_bus_reset_handler(struct scsi_cmnd *cmnd)
{
	int rv = SUCCESS;

	return rv;
}

static int
csio_slave_alloc(struct scsi_device *sdev)
{
	struct fc_rport *rport = starget_to_rport(scsi_target(sdev));

	if (!rport || fc_remote_port_chkready(rport)) {
		return -ENXIO;
	}
	sdev->hostdata = *((struct csio_os_lnode **)(rport->dd_data));

	return 0;
}

static int
csio_iscsi_slave_alloc(struct scsi_device *sdev)
{
	struct scsi_target *stgt = scsi_target(sdev);
	struct device *dev = stgt->dev.parent;
	struct csio_os_rnode *osrn = (struct csio_os_rnode *)dev->platform_data;

#if 0	
	struct csio_os_lnode *osln = shost_priv(sdev->host);
	struct csio_lnode *ln = csio_osln_to_ln(osln);
	struct csio_rnode *rn;
	struct csio_os_rnode *osrn;
	struct csio_rnode *rnhead = NULL;
	struct csio_list *tmp = NULL;
	struct csio_rnode_iscsi *rni = NULL;

	rnhead  = (struct csio_rnode *)&ln->rnhead;
	csio_list_for_each(tmp, &rnhead->rnlist) {
		rn  = (struct csio_rnode *)tmp;
		rni = csio_rnode_to_iscsi(rn);

		if (rni->sess_handle == sdev->id) {
			osrn = csio_rnode_to_os(rn);
			sdev->hostdata = (void *)osrn;
			break;
		}

	}
#endif	
	sdev->hostdata = (void *)osrn;
#ifdef __CSIO_FOISCSI_ENABLED__
	if (osrn)
		osrn->rsess->starget = stgt;
#endif
	return 0;
}

#if 1 /* REVISIT */
static int
csio_slave_configure(struct scsi_device *sdev)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
	scsi_change_queue_depth(sdev, CSIO_MAX_CMD_PER_LUN);
#else
	if (sdev->tagged_supported)
		scsi_activate_tcq(sdev, CSIO_MAX_CMD_PER_LUN);
	else
		scsi_deactivate_tcq(sdev, 1);
#endif
	return 0;
}

#endif

#if 0
/* Lets use it to play with q_depth changes on fly */
static int
csio_foiscsi_change_queue_depth(struct scsi_device *sdev, int depth, int reason)
{
	printk(KERN_DEBUG "%s: sdev %p, depth %d, reason %d\n", __FUNCTION__,
			sdev, depth, reason);
	switch (reason) {
	case SCSI_QDEPTH_DEFAULT:
		scsi_adjust_queue_depth(sdev, scsi_get_tag_type(sdev), depth);
		break;
	case SCSI_QDEPTH_QFULL:
		scsi_track_queue_full(sdev, depth);
		break;
	case SCSI_QDEPTH_RAMP_UP:
		scsi_adjust_queue_depth(sdev, scsi_get_tag_type(sdev), depth);
		break;
	default:
		return -EOPNOTSUPP;
	}
	return sdev->queue_depth;
}
#endif

static void
csio_slave_destroy(struct scsi_device *sdev)
{
	sdev->hostdata = NULL;
	return;
}

static int
csio_scan_finished(struct Scsi_Host *shost, unsigned long time)
{
	struct csio_os_lnode *osln = shost_priv(shost);
	struct csio_lnode *ln = csio_osln_to_ln(osln);
	int rv = 0;

	if (csio_exit_no_mb) {
		printk(KERN_INFO "csiostor: Returning scan_finished thread.\n");
		return 1;
	}

#ifdef __CSIO_TARGET__
	/* Nothing to scan in pure target mode */
	if (!csio_initiator_mode(ln->hwp))
		return 1;
#endif /* __CSIO_TARGET__ */ 	

	spin_lock_irq(shost->host_lock);
	/* Synchronize with PCI instance removal */
	if (!ln->hwp || csio_elem_dequeued(ln)) {
		spin_unlock_irq(shost->host_lock);
		return 1;
	}

	rv = csio_scan_done(ln, jiffies, time, csio_max_scan_tmo * HZ,
			    csio_delta_scan_tmo * HZ);

	spin_unlock_irq(shost->host_lock);

	return rv;
}

/*
 * A separate host template is allocated for iSCSI and FCoE
 * each. If most code can be shared later, they would be
 * combined.
 */
struct scsi_host_template csio_fcoe_shost_template = {
	.module 		= THIS_MODULE,
	.name			= CSIO_DRV_DESC,
	.queuecommand		= csio_queuecommand,
	.eh_abort_handler	= csio_eh_abort_handler,
	.eh_device_reset_handler = csio_eh_lun_reset_handler,
	.eh_bus_reset_handler	= csio_eh_bus_reset_handler,
	.slave_alloc		= csio_slave_alloc,
#if 0 /* REVISIT */
	.slave_configure	= csio_slave_configure,
#endif
	.slave_destroy		= csio_slave_destroy,
	.scan_finished		= csio_scan_finished,
	.this_id		= -1,
	.sg_tablesize		= CSIO_SCSI_FCOE_MAX_SGE,
	.cmd_per_lun		= CSIO_MAX_CMD_PER_LUN, /* REVISIT */
	.use_clustering		= ENABLE_CLUSTERING,
	.shost_attrs		= csio_fcoe_lport_attrs,
	.max_sectors		= CSIO_MAX_SECTOR_SIZE,	/* maxIO size */
};

struct scsi_host_template csio_fcoe_shost_vport_template = {
	.module 		= THIS_MODULE,
	.name			= CSIO_DRV_DESC,
	.queuecommand		= csio_queuecommand,
	.eh_abort_handler	= csio_eh_abort_handler,
	.eh_device_reset_handler = csio_eh_lun_reset_handler,
	.eh_bus_reset_handler	= csio_eh_bus_reset_handler,
	.slave_alloc		= csio_slave_alloc,
#if 0 /* REVISIT */
	.slave_configure	= csio_slave_configure,
#endif
	.slave_destroy		= csio_slave_destroy,
	.scan_finished		= csio_scan_finished,
	.this_id		= -1,
	.sg_tablesize		= CSIO_SCSI_FCOE_MAX_SGE,
	.cmd_per_lun		= CSIO_MAX_CMD_PER_LUN,	/* REVISIT */
	.use_clustering		= ENABLE_CLUSTERING,
	.shost_attrs		= csio_fcoe_vport_attrs,
	.max_sectors		= CSIO_MAX_SECTOR_SIZE,	/* maxIO size */
};

/* REVISIT: ISCSI */
struct scsi_host_template csio_iscsi_shost_template = {
	.module 		= THIS_MODULE,
	.name			= CSIO_DRV_DESC,
	.can_queue		= 2048,
	.queuecommand		= csio_queuecommand,
#if 0
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
	.change_queue_depth	= scsi_change_queue_depth,
#else
	.change_queue_depth	= csio_foiscsi_change_queue_depth,
#endif
#endif
	.eh_abort_handler	= csio_eh_abort_handler,
	.eh_device_reset_handler = csio_eh_iscsi_lun_reset_handler,
	.eh_bus_reset_handler	= csio_eh_bus_reset_handler,
	.slave_alloc		= csio_iscsi_slave_alloc,
#if 1 /* REVISIT */
	.slave_configure	= csio_slave_configure,
#endif
	.slave_destroy		= csio_slave_destroy,
#ifdef __CSIO_FOISCSI_ENABLED__	
	/*.scan_finished		= csio_iscsi_scan_finished,*/
#endif
	.this_id		= -1,
	.sg_tablesize		= CSIO_SCSI_ISCSI_MAX_SGE,
	.cmd_per_lun		= CSIO_MAX_CMD_PER_LUN,
	.use_clustering		= ENABLE_CLUSTERING,
/* REVISIT: ISCSI */
#if 0
	.shost_attrs		= csio_iscsi_attrs,
#endif
	.max_sectors		= CSIO_FOISCSI_MAX_SECTOR_SIZE,
};

void
csio_os_abort_cls(struct csio_ioreq *ioreq, void *osreq)
{
	struct csio_lnode *ln = ioreq->lnode;
	struct csio_hw *hw = ln->hwp;
	int ready = 0;
	struct csio_scsim *scsim = csio_hw_to_scsim(hw);
	enum csio_oss_error rv;

	/* REVISIT: This is called with lock held, not sure
	 * whether we need this check.
	 */
	if (csio_scsi_osreq(ioreq) != osreq) {
		csio_warn(hw, "Possible race b/w cmpltn & LUN reset cleanup "
			" osreq:%p\n", csio_scsi_osreq(ioreq));
		CSIO_INC_STATS(scsim, n_abrt_race_comp);
		return;
	}

	if (csio_is_fcoe(hw)) {
		ready = csio_is_lnf_ready(csio_lnode_to_fcoe(ln));
	} else {
#if 0 /* iSCSI */
		ready = csio_is_lni_ready(csio_lnode_to_fcoe(ln));
#endif
	}

	rv = csio_do_abrt_cls(hw, ioreq, (ready ? SCSI_ABORT : SCSI_CLOSE));
	if (rv != CSIO_SUCCESS) {
		if (ready)
			CSIO_INC_STATS(scsim, n_abrt_busy_error);
		else
			CSIO_INC_STATS(scsim, n_cls_busy_error);
	}
}
