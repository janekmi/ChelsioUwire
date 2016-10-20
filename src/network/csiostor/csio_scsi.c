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
#include <csio_scsi.h>

/*
 * For conditional verbose print use
 * csio_scsi_vdb_cnd(cond, hw, fmt..)
 * CSIO_SCSI_DUMP_BUF(cond, wr, len)
 */

int csio_scsi_eqsize = 65536;
int csio_scsi_iqlen = 128;
int csio_scsi_ioreqs = 2048;
uint32_t csio_max_scan_tmo = 0;
uint32_t csio_delta_scan_tmo = 5;
int csio_ddp_descs = 256;
int csio_ddp_descs_npages = 32;

static void csio_scsis_uninit(struct csio_ioreq *, csio_scsi_ev_t);
static void csio_scsis_io_active(struct csio_ioreq *, csio_scsi_ev_t);
static void csio_scsis_tm_active(struct csio_ioreq *, csio_scsi_ev_t);
static void csio_scsis_aborting(struct csio_ioreq *, csio_scsi_ev_t);
static void csio_scsis_closing(struct csio_ioreq *, csio_scsi_ev_t);
static void csio_scsis_os_cmpl_await(struct csio_ioreq *, csio_scsi_ev_t);

bool
csio_scsi_io_active(struct csio_ioreq *req)
{
	return (csio_get_state(req) == (csio_sm_state_t)csio_scsis_io_active);
}

/*
 * csio_scsi_match_io - Match an ioreq with the given SCSI level data.
 * @ioreq: The I/O request
 * @sld: Level information
 *
 * Should be called with lock held.
 *
 */
static bool
csio_scsi_match_io(struct csio_ioreq *ioreq, struct csio_scsi_level_data *sld)
{
	switch (sld->level) {
	case CSIO_LEV_LUN:
		if (csio_scsi_osreq(ioreq) == NULL)
			return CSIO_FALSE;

		return (
			(ioreq->lnode == sld->lnode) &&
			(ioreq->rnode == sld->rnode) &&
			((uint64_t)(csio_scsi_oslun(csio_scsi_osreq(ioreq)))
							== sld->oslun)
			);
			
	case CSIO_LEV_RNODE:
		return ((ioreq->lnode == sld->lnode) &&
				(ioreq->rnode == sld->rnode));
	case CSIO_LEV_LNODE:
		return (ioreq->lnode == sld->lnode);
	case CSIO_LEV_ALL:
		return CSIO_TRUE;
	default:
		return CSIO_FALSE;
	}
}

/*
 * csio_scsi_gather_active_ios - Gather active I/Os based on level
 * @scm: SCSI module
 * @sld: Level information
 * @dest: The queue where these I/Os have to be gathered.
 *
 * Should be called with lock held.
 */
void
csio_scsi_gather_active_ios(struct csio_scsim *scm,
			    struct csio_scsi_level_data *sld,
			    struct csio_list *dest)
{
	struct csio_list *tmp, *next;

	if (csio_list_empty(&scm->active_q)) {
		csio_scsi_dbg(scm->hw, "No active SCSI I/Os to gather.\n");
		return;
	}

	/* Just splice the entire active_q into dest */
	if (sld->level == CSIO_LEV_ALL) {
		csio_enq_list_at_tail(dest, &scm->active_q);
		return;
	}
		
	csio_list_for_each_safe(tmp, next, &scm->active_q) {
		if (csio_scsi_match_io((struct csio_ioreq *)tmp, sld)) {
			csio_scsi_dbg(scm->hw, "gathering req: %p\n", tmp);
			csio_deq_elem(tmp);
			csio_enq_at_tail(dest, tmp);
		}
	}

	return;
}

static inline bool
csio_scsi_itnexus_loss_error(uint16_t error)
{
	switch (error) {
		case FW_ERR_LINK_DOWN:
		case FW_RDEV_NOT_READY:
		case FW_ERR_RDEV_LOST:
		case FW_ERR_RDEV_LOGO:
		case FW_ERR_RDEV_IMPL_LOGO:
			return 1;
	}
	return 0;
}

/*
 * csio_scsi_fcp_cmnd - Frame the SCSI FCP command paylod.
 * @req: IO req structure.
 * @addr: DMA location to place the payload.
 *
 * This routine is shared between FCP_WRITE, FCP_READ and FCP_CMD requests.
 */
static inline void
csio_scsi_fcp_cmnd(struct csio_ioreq *req, void *addr)
{
	struct csio_fcp_cmnd *fcp_cmnd = (struct csio_fcp_cmnd *)addr;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
	struct scsi_cmnd *scmnd = (struct scsi_cmnd *) csio_scsi_osreq(req);
#endif
	
	/* Check for Task Management */
	if (csio_likely(csio_scsi_tm_op(csio_scsi_osreq(req)) == 0)) {
		csio_scsi_lun(csio_scsi_osreq(req), req->scratch2,
			      fcp_cmnd->lun);
		fcp_cmnd->tm_flags = 0;
		fcp_cmnd->cmdref = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
		fcp_cmnd->pri_ta = 0;
#endif

		csio_scsi_cdb(csio_scsi_osreq(req), fcp_cmnd->cdb);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
		if (scmnd->flags & SCMD_TAGGED)
			fcp_cmnd->pri_ta = FCP_PTA_SIMPLE;
		else
			fcp_cmnd->pri_ta = 0;
#else
		csio_scsi_tag(csio_scsi_osreq(req), &fcp_cmnd->pri_ta,
			      FCP_PTA_HEADQ, FCP_PTA_ORDERED, FCP_PTA_SIMPLE);
#endif
		fcp_cmnd->dl = csio_cpu_to_be32(csio_scsi_datalen(
							csio_scsi_osreq(req)));

		if (req->nsge)
			if (req->datadir == CSIO_IOREQF_DMA_WRITE)
				fcp_cmnd->flags = FCP_CFL_WRDATA;
			else
				fcp_cmnd->flags = FCP_CFL_RDDATA;
		else
			fcp_cmnd->flags = 0;
	} else {
		csio_memset(fcp_cmnd, 0, sizeof(*fcp_cmnd));
		csio_scsi_lun(csio_scsi_osreq(req), req->scratch2,
			      fcp_cmnd->lun);
		fcp_cmnd->tm_flags = (uint8_t)csio_scsi_tm_op(
							csio_scsi_osreq(req));
	}

#ifdef __CSIO_DEBUG__
	csio_memcpy(req->data, fcp_cmnd, sizeof(struct csio_fcp_cmnd));
#endif
	return;
}

static inline void
csio_scsi_iscsi_data(struct csio_ioreq *req, void *addr)
{
#ifdef __CSIO_FOISCSI_ENABLED__
	/* TODO: handle TM Requests.*/
	struct fw_scsi_iscsi_data *idata = (struct fw_scsi_iscsi_data *)addr;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
	struct scsi_cmnd *scmnd = (struct scsi_cmnd *) csio_scsi_osreq(req);
#endif

	csio_memset(idata, 0, sizeof(*idata));
	if (csio_likely(csio_scsi_tm_op(csio_scsi_osreq(req)) == 0)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
		if (scmnd->flags & SCMD_TAGGED)
			idata->fbit_to_tattr = FW_SCSI_ISCSI_DATA_TATTR_SIMPLE;
		else
			idata->fbit_to_tattr = 0;
#else
		csio_scsi_tag(csio_scsi_osreq(req), &idata->fbit_to_tattr,
				FW_SCSI_ISCSI_DATA_TATTR_HEADOQ,
				FW_SCSI_ISCSI_DATA_TATTR_ORDERED,
				FW_SCSI_ISCSI_DATA_TATTR_SIMPLE);
#endif
		csio_scsi_cdb(csio_scsi_osreq(req), idata->cdb);
		idata->dlen =
			csio_cpu_to_be32(csio_scsi_datalen(csio_scsi_osreq(req)));
		if (req->nsge) {
			if (req->datadir == CSIO_IOREQF_DMA_WRITE)
				idata->fbit_to_tattr |= F_FW_SCSI_ISCSI_DATA_WBIT;
			else
				idata->fbit_to_tattr |= F_FW_SCSI_ISCSI_DATA_RBIT;
		}
	} else {
		idata->r0 |= 0x40 | FW_SCSI_ISCSI_TMF_OP; /*  ibit | opcode */
		idata->fbit_to_tattr =
			((uint8_t)csio_scsi_tm_op(csio_scsi_osreq(req)) & 0x7f);
		idata->dlen = csio_cpu_to_be32(FW_SCSI_ISCSI_RESERVED_TAG);
	}
	idata->fbit_to_tattr |= F_FW_SCSI_ISCSI_DATA_FBIT;
	csio_scsi_lun(csio_scsi_osreq(req), req->scratch2, idata->lun);

 	return;
#endif
}

/*
 * csio_scsi_init_cmd_wr - Initialize the SCSI CMD WR.
 * @req: IO req structure.
 * @addr: DMA location to place the payload.
 * @size: Size of WR (including FW WR + immed data + rsp SG entry
 *
 * Wrapper for populating fw_scsi_cmd_wr.
 */
static inline void
csio_scsi_init_cmd_wr(struct csio_ioreq *req, void *addr, uint32_t size)
{
	struct csio_hw *hw = req->lnode->hwp;
	struct csio_rnode *rn = req->rnode;
	struct fw_scsi_cmd_wr *wr = (struct fw_scsi_cmd_wr *)addr;
	struct csio_dma_buf *dma_buf;
	uint8_t imm = csio_hw_to_scsim(hw)->proto_cmd_len;

	wr->op_immdlen = csio_cpu_to_be32(V_FW_WR_OP(FW_SCSI_CMD_WR) |
					  V_FW_SCSI_CMD_WR_IMMDLEN(imm));
	wr->flowid_len16 = csio_cpu_to_be32(V_FW_WR_FLOWID(rn->flowid) |
					    V_FW_WR_LEN16(
						CSIO_ROUNDUP(size, 16)));

	wr->cookie = (uintptr_t) req;
	wr->iqid = csio_cpu_to_be16(csio_q_physiqid(hw, req->iq_idx));
	wr->tmo_val = (uint8_t) req->tmo;
	wr->r3 = 0;
	csio_memset(&wr->r5, 0, 8);

	/* Get RSP DMA buffer */
	dma_buf = &req->dma_buf;

	/* Prepare RSP SGL */
	wr->rsp_dmalen = csio_cpu_to_be32(dma_buf->len);
	wr->rsp_dmaaddr = csio_cpu_to_be64(csio_phys_addr(dma_buf->paddr));

	wr->r6 = 0;

	if (csio_is_fcoe(hw)) {
		wr->u.fcoe.ctl_pri = 0;
		wr->u.fcoe.cp_en_class = 0;
		wr->u.fcoe.r4_lo[0] = 0;
		wr->u.fcoe.r4_lo[1] = 0;

		/* Frame a FCP command */
		csio_scsi_fcp_cmnd(req, (void *)((uintptr_t)addr +
				    sizeof(struct fw_scsi_cmd_wr)));		
	} else {
		csio_scsi_iscsi_data(req, (void *)((uintptr_t)addr +
					sizeof(struct fw_scsi_cmd_wr)));
	}

	return;
}

#define CSIO_SCSI_CMD_WR_SZ(_imm)					\
	(sizeof(struct fw_scsi_cmd_wr) +	      	/* WR size */	\
	 CSIO_ALIGN((_imm), 16)) 			/* Immed data */\

#define CSIO_SCSI_CMD_WR_SZ_16(_imm)					\
			(CSIO_ALIGN(CSIO_SCSI_CMD_WR_SZ((_imm)), 16))

/*
 * csio_scsi_cmd - Create a SCSI CMD WR.
 * @req: IO req structure.
 *
 * Gets a WR slot in the ingress queue and initializes it with SCSI CMD WR.
 *
 */
static inline void
csio_scsi_cmd(struct csio_ioreq *req)
{
	struct csio_wr_pair wrp;
	struct csio_hw *hw = req->lnode->hwp;
	struct csio_scsim *scsim = csio_hw_to_scsim(hw);
	uint32_t size = CSIO_SCSI_CMD_WR_SZ_16(scsim->proto_cmd_len);

	req->drv_status = csio_wr_get(hw, req->eq_idx, size, &wrp);
	if (csio_unlikely(req->drv_status != CSIO_SUCCESS))
		return;

	if (wrp.size1 >= size) {
		/* Initialize WR in one shot */
		csio_scsi_init_cmd_wr(req, wrp.addr1, size);
	} else {
		uint8_t tmpwr[512];
		/*
		 * Make a temporary copy of the WR and write back
		 * the copy into the WR pair.
		 */
		csio_scsi_init_cmd_wr(req, (void *)tmpwr, size);
		csio_memcpy(wrp.addr1, tmpwr, wrp.size1);
		csio_memcpy(wrp.addr2, tmpwr + wrp.size1, size - wrp.size1);
	}

	CSIO_DUMP_WR(hw, wrp);
}

static inline void
csio_dump_evil_sgl(struct csio_hw *hw, struct csio_ioreq *req,
		   struct ulptx_sgl *sgl, void *wr, uint32_t size)
{
	uint32_t xfer_len = csio_scsi_datalen(csio_scsi_osreq(req));
	uint32_t first_page_off = (sgl->addr0 & (CSIO_PAGE_SIZE - 1));
	uint32_t first_page_len = CSIO_PAGE_SIZE - first_page_off;
	uint32_t last_page_off = ((xfer_len - first_page_len) % CSIO_PAGE_SIZE);

	if (first_page_off && last_page_off) {
		csio_vdbg(hw,
		    "################ EVIL SGL WR #################\n");
		CSIO_DUMP_BUF((uint8_t *)wr, size);
	}
}

/*
 * The following is fast path code. Therefore it is inlined with multi-line
 * macros using name substitution, thus avoiding if-else switches for
 * operation (read/write), as well as serving the purpose of code re-use.
 */
/*
 * csio_scsi_init_ulptx_dsgl - Fill in a ULP_TX_SC_DSGL
 * @hw: HW module
 * @req: IO request
 * @sgl: ULP TX SGL pointer.
 *
 */
#define csio_scsi_init_ultptx_dsgl(hw, req, sgl)			       \
do {									       \
	struct ulptx_sge_pair *_sge_pair = NULL;			       \
	struct csio_sgel *_sgel;					       \
	uint32_t _i = 0;						       \
	uint32_t _xfer_len;						       \
	struct csio_list *_tmp;						       \
	struct csio_dma_buf *_dma_buf;					       \
									       \
	(sgl)->cmd_nsge = csio_htonl(V_ULPTX_CMD(ULP_TX_SC_DSGL) |	       \
				     F_ULP_TX_SC_MORE		 |	       \
				     V_ULPTX_NSGE((req)->nsge));	       \
	/* Now add the data SGLs */					       \
	if (csio_likely(!(req)->dcopy)) {				       \
		csio_scsi_for_each_sg((hw)->os_dev, csio_scsi_osreq((req)),    \
				       _sgel, (req)->nsge, _i) {	       \
			if (_i == 0) {					       \
				(sgl)->addr0 = csio_cpu_to_be64(	       \
						csio_sgel_dma_addr(_sgel));    \
				(sgl)->len0 = csio_cpu_to_be32(		       \
						csio_sgel_len(_sgel));	       \
				_sge_pair = 				       \
					(struct ulptx_sge_pair *)((sgl) + 1);  \
				continue;				       \
			}						       \
			if ((_i - 1) & 0x1) {				       \
				_sge_pair->addr[1] = csio_cpu_to_be64(	       \
						csio_sgel_dma_addr(_sgel));    \
				_sge_pair->len[1] = csio_cpu_to_be32(	       \
						csio_sgel_len(_sgel));	       \
				_sge_pair++;				       \
			} else 	{					       \
				_sge_pair->addr[0] = csio_cpu_to_be64(	       \
						csio_sgel_dma_addr(_sgel));    \
				_sge_pair->len[0] = csio_cpu_to_be32(	       \
						csio_sgel_len(_sgel));	       \
			}						       \
		}							       \
		csio_sg_reset(_sgel);					       \
	} else {							       \
		/* Program sg elements with driver's DDP buffer */	       \
		_xfer_len = csio_scsi_datalen(csio_scsi_osreq((req)));	       \
		csio_list_for_each(_tmp, &(req)->gen_list) {		       \
			_dma_buf = (struct csio_dma_buf *)_tmp;		       \
			if (_i == 0) {					       \
				(sgl)->addr0 = csio_cpu_to_be64(	       \
					csio_phys_addr(_dma_buf->paddr));      \
				(sgl)->len0 = csio_cpu_to_be32(		       \
					CSIO_MIN(_xfer_len, _dma_buf->len));   \
				_sge_pair = 				       \
					(struct ulptx_sge_pair *)((sgl) + 1);  \
			}						       \
			else if ((_i - 1) & 0x1) {			       \
				_sge_pair->addr[1] = csio_cpu_to_be64(	       \
					csio_phys_addr(_dma_buf->paddr));      \
				_sge_pair->len[1] = csio_cpu_to_be32(	       \
					CSIO_MIN(_xfer_len, _dma_buf->len));   \
				_sge_pair++;				       \
			} else 	{					       \
				_sge_pair->addr[0] = csio_cpu_to_be64(	       \
					csio_phys_addr(_dma_buf->paddr));      \
				_sge_pair->len[0] = csio_cpu_to_be32(	       \
					CSIO_MIN(_xfer_len, _dma_buf->len));   \
			}						       \
			_xfer_len -= CSIO_MIN(_xfer_len, _dma_buf->len);       \
			_i++;						       \
		}							       \
	}								       \
} while(0)

/*
 * csio_scsi_init_data_wr - Initialize the READ/WRITE SCSI WR.
 * @req: IO req structure.
 * @oper: read/write
 * @wrp: DMA location to place the payload.
 * @size: Size of WR (including FW WR + immed data + rsp SG entry + data SGL
 * @wrop:  _READ_/_WRITE_
 *
 * Wrapper for populating fw_scsi_read_wr/fw_scsi_write_wr.
 */
#define csio_scsi_init_data_wr(req, oper, wrp, size, wrop)	       	       \
do {									       \
	struct csio_hw *_hw = (req)->lnode->hwp;			       \
	struct csio_rnode *_rn = (req)->rnode;       			       \
	struct fw_scsi_##oper##_wr *__wr = (struct fw_scsi_##oper##_wr *)(wrp);\
	struct ulptx_sgl *_sgl;						       \
	struct csio_dma_buf *_dma_buf;					       \
	uint8_t _imm = csio_hw_to_scsim(_hw)->proto_cmd_len;		       \
									       \
	__wr->op_immdlen = csio_cpu_to_be32(V_FW_WR_OP(FW_SCSI##wrop##WR) |    \
					   V_FW_SCSI##wrop##WR_IMMDLEN(_imm)); \
	__wr->flowid_len16 = csio_cpu_to_be32(V_FW_WR_FLOWID(_rn->flowid) |    \
					     V_FW_WR_LEN16(		       \
						CSIO_ROUNDUP((size), 16)));    \
	__wr->cookie = (uintptr_t) (req);				       \
	__wr->iqid = csio_cpu_to_be16(csio_q_physiqid(_hw,		       \
							       (req)->iq_idx));\
	__wr->tmo_val = (uint8_t)((req)->tmo);				       \
	__wr->use_xfer_cnt = 1;						       \
	__wr->xfer_cnt = csio_cpu_to_be32(csio_scsi_datalen(		       \
						csio_scsi_osreq((req))));      \
	__wr->ini_xfer_cnt = csio_cpu_to_be32(csio_scsi_datalen(	       \
						csio_scsi_osreq((req))));      \
	/* Get RSP DMA buffer */					       \
	_dma_buf = &(req)->dma_buf;					       \
									       \
	/* Prepare RSP SGL */						       \
	__wr->rsp_dmalen = csio_cpu_to_be32(_dma_buf->len);		       \
	__wr->rsp_dmaaddr = csio_cpu_to_be64(csio_phys_addr(_dma_buf->paddr)); \
									       \
	__wr->r4 = 0;							       \
									       \
	/* Frame a FCP command if FCoE, SCSI command PDU if iSCSI */	       \
	if (csio_is_fcoe(hw)) {						       \
		__wr->u.fcoe.ctl_pri = 0;				       \
		__wr->u.fcoe.cp_en_class = 0;				       \
		__wr->u.fcoe.r3_lo[0] = 0;				       \
		__wr->u.fcoe.r3_lo[1] = 0;				       \
		csio_scsi_fcp_cmnd((req), (void *)((uintptr_t)(wrp) +	       \
				   sizeof(struct fw_scsi_##oper##_wr)));       \
	} else {							       \
		csio_scsi_iscsi_data((req), (void *)((uintptr_t)(wrp) +	       \
				   sizeof(struct fw_scsi_##oper##_wr)));       \
	}								       \
									       \
	/* Move WR pointer past command and immediate data */		       \
	_sgl = (struct ulptx_sgl *) ((uintptr_t)(wrp) +			       \
			      sizeof(struct fw_scsi_##oper##_wr) +	       \
			      CSIO_ALIGN(_imm, 16));			       \
									       \
	/* Fill in the DSGL */						       \
	csio_scsi_init_ultptx_dsgl(_hw, (req), _sgl);			       \
									       \
	/* csio_dump_evil_sgl(_hw, (req), _sgl, (wrp), (size)); */	       \
} while (0)

/* Calculate WR size needed for fw_scsi_read_wr/fw_scsi_write_wr */
#define csio_scsi_data_wrsz(req, oper, sz, imm)				       \
do {									       \
	(sz) = sizeof(struct fw_scsi_##oper##_wr) +	/* WR size */          \
	       CSIO_ALIGN((imm), 16) +			/* Immed data */       \
	       sizeof(struct ulptx_sgl);		/* ulptx_sgl */	       \
									       \
	if (csio_unlikely((req)->nsge > 1))				       \
	       (sz) += (sizeof(struct ulptx_sge_pair) * 		       \
				(CSIO_ALIGN(((req)->nsge - 1), 2) / 2));       \
							/* Data SGE */	       \
} while (0)

/*
 * csio_scsi_data - Create a SCSI WRITE/READ WR.
 * @req: IO req structure.
 * @oper: read/write
 * @wrop:  _READ_/_WRITE_ (string subsitutions to use with the FW bit field
 *         macros). NOTE: The underscores used in the strings are to make sure
 *         we are unique and we dont clash with the OS defined macros
 *         READ and WRITE.
 *
 * Gets a WR slot in the ingress queue and initializes it with
 * SCSI CMD READ/WRITE WR.
 *
 */
#define csio_scsi_data(req, oper, wrop)					       \
do {									       \
	struct csio_wr_pair _wrp;					       \
	uint32_t _size;							       \
	struct csio_hw *_hw = (req)->lnode->hwp;			       \
	struct csio_scsim *_scsim = csio_hw_to_scsim(_hw);		       \
									       \
	csio_scsi_data_wrsz((req), oper, _size, _scsim->proto_cmd_len);	       \
	_size = CSIO_ALIGN(_size, 16);					       \
									       \
	(req)->drv_status = csio_wr_get(_hw, (req)->eq_idx, _size, &_wrp);     \
	if (csio_likely((req)->drv_status == CSIO_SUCCESS)) {		       \
		if (csio_likely(_wrp.size1 >= _size)) {			       \
			/* Initialize WR in one shot */			       \
			csio_scsi_init_data_wr((req), oper, _wrp.addr1,        \
						    _size, wrop);	       \
		} else {						       \
			uint8_t tmpwr[512];				       \
			/* 						       \
			 * Make a temporary copy of the WR and write back      \
			 * the copy into the WR pair.			       \
			 */						       \
			csio_scsi_init_data_wr((req), oper, (void *)tmpwr,     \
						    _size, wrop);	       \
			csio_memcpy(_wrp.addr1, tmpwr, _wrp.size1);	       \
			csio_memcpy(_wrp.addr2, tmpwr + _wrp.size1,	       \
				    _size - _wrp.size1);		       \
		}							       \
	}								       \
} while (0)

/*
 * csio_setup_ddp - Setup DDP buffers for Read request.
 * @req: IO req structure.
 *
 * Checks SGLs/Data buffers are virtually contiguous required for DDP.
 * If contiguous,driver posts SGLs in the WR otherwise post internal
 * buffers for such request for DDP.
 */
static inline void
csio_setup_ddp(struct csio_scsim *scsim, struct csio_ioreq *req)
{
	struct csio_hw *hw = req->lnode->hwp;
	struct csio_sgel *sgel = NULL;
	uint64_t sg_addr = 0;
	uint32_t ddp_pagesz = 4096;
	uint32_t buf_off;
#ifdef __CSIO_DDP_SUPPORT__
	struct csio_dma_buf *dma_buf = NULL;
	uint32_t alloc_len = 0;
	uint32_t xfer_len = 0;
#endif /* __CSIO_DDP_SUPPORT__ */
	uint32_t sg_len = 0;
	uint32_t i;

	csio_scsi_for_each_sg(hw->os_dev, csio_scsi_osreq(req), sgel,
			      req->nsge, i) {
		sg_addr = csio_sgel_dma_addr(sgel);
		sg_len 	= csio_sgel_len(sgel);

		buf_off = sg_addr & (ddp_pagesz - 1);

		/* Except 1st buffer,all buffer addr have to be Page aligned */
		if (i != 0 && buf_off) {
			csio_dbg(hw, "SGL addr not DDP aligned "
				"(%llx:%d)\n", sg_addr, sg_len);
			csio_sg_reset(sgel);
			goto no_ddp;
		}

		/* Except last buffer,all buffer must end on page boundary */
		if ((i != (req->nsge - 1)) &&
			((buf_off + sg_len) & (ddp_pagesz - 1))) {
			csio_dbg(hw, "SGL addr not ending on page boundary"
					"(%llx:%d)\n", sg_addr, sg_len);
			csio_sg_reset(sgel);
			goto no_ddp;
		}
	}
	csio_sg_reset(sgel);
	req->dcopy = 0;
	/* SGL's are virtually contiguous. HW will DDP to SGLs */
	csio_scsi_data(req, read, _READ_);
	return;

no_ddp:
	CSIO_INC_STATS(scsim, n_ddp_miss);
#ifdef __CSIO_DDP_SUPPORT__
	/* For non-ddp SGLs, driver will allocate internal DDP buffer.
	 * Once command is completed data from DDP buffer copied
	 * to SGLs
	 */
	req->dcopy = 1;
	/* Use gen_list to store the DDP buffers */
	csio_head_init(&req->gen_list);
	xfer_len = csio_scsi_datalen(csio_scsi_osreq(req));

	i = 0;
	/* Allocate ddp buffers for this request */
	while (alloc_len < xfer_len) {
		dma_buf = csio_get_scsi_ddp(scsim);	
		if (dma_buf == NULL || i > scsim->max_sge) {
			req->drv_status = CSIO_BUSY;
			break;
		}
		alloc_len += dma_buf->len;
		/* Added to IO req */
		csio_enq_at_tail(&req->gen_list, dma_buf);
		i++;
	}

	if (!req->drv_status) {
		/* set number of ddp bufs used */
		req->nsge = i;
		csio_scsi_data(req, read, _READ_);
		return;
	}

	 /* release dma descs */
	if (i > 0)
		csio_put_scsi_ddp_list(scsim, &req->gen_list, i);	
#else
	csio_scsi_dump_evil_req(csio_scsi_osreq(req));

	csio_scsi_dbg(hw, "Dumping SGLs of req %p\n", req);
	csio_scsi_for_each_sg(hw->os_dev, csio_scsi_osreq(req),
			      sgel, req->nsge, i) {
		sg_addr = csio_sgel_dma_addr(sgel);
		sg_len 	= csio_sgel_len(sgel);
		csio_scsi_dbg(hw, "SGL addr:len (%llx:%d)\n",
			sg_addr, sg_len);
	}
	csio_sg_reset(sgel);
	CSIO_DB_ASSERT(0);
#endif /* __CSIO_DDP_SUPPORT__ */
}

/*
 * csio_scsi_init_abrt_cls_wr - Initialize an ABORT/CLOSE WR.
 * @req: IO req structure.
 * @addr: DMA location to place the payload.
 * @size: Size of WR
 * @abort: abort OR close
 *
 * Wrapper for populating fw_scsi_cmd_wr.
 */
static inline void
csio_scsi_init_abrt_cls_wr(struct csio_ioreq *req, void *addr, uint32_t size,
			   bool abort)
{
	struct csio_hw *hw = req->lnode->hwp;
	struct csio_rnode *rn = req->rnode;
	struct fw_scsi_abrt_cls_wr *wr = (struct fw_scsi_abrt_cls_wr *)addr;

	wr->op_immdlen = csio_cpu_to_be32(V_FW_WR_OP(FW_SCSI_ABRT_CLS_WR));
	wr->flowid_len16 = csio_cpu_to_be32(V_FW_WR_FLOWID(rn->flowid) |
					    V_FW_WR_LEN16(
						CSIO_ROUNDUP(size, 16)));

	wr->cookie = (uintptr_t) req;
	wr->iqid = csio_cpu_to_be16(csio_q_physiqid(hw, req->iq_idx));
	wr->tmo_val = (uint8_t) req->tmo;
	/* 0 for CHK_ALL_IO tells FW to look up t_cookie */
	wr->sub_opcode_to_chk_all_io =
				(V_FW_SCSI_ABRT_CLS_WR_SUB_OPCODE(abort) |
				 V_FW_SCSI_ABRT_CLS_WR_CHK_ALL_IO(0));
	wr->r3[0] = 0;
	wr->r3[1] = 0;
	wr->r3[2] = 0;
	wr->r3[3] = 0;
	/* Since we re-use the same ioreq for abort as well */
	wr->t_cookie = (uintptr_t) req;	

	if (csio_is_iscsi(hw)) {
		wr->op_immdlen |= V_FW_SCSI_CMD_WR_IMMDLEN(
				csio_hw_to_scsim(hw)->proto_cmd_len);
		csio_scsi_iscsi_data(req, (void *)((uintptr_t)addr +
					sizeof(struct fw_scsi_abrt_cls_wr)));
	}

	return;
}

static inline void
csio_scsi_abrt_cls(struct csio_ioreq *req, bool abort)
{
	struct csio_wr_pair wrp;
	struct csio_hw *hw = req->lnode->hwp;
	uint32_t size = CSIO_ALIGN(sizeof(struct fw_scsi_abrt_cls_wr), 16);

#ifdef __CSIO_FOISCSI_ENABLED__
	if (csio_is_iscsi(hw))
		size += CSIO_ALIGN(sizeof(struct fw_scsi_iscsi_data), 16);
#endif

	req->drv_status = csio_wr_get(hw, req->eq_idx, size, &wrp);
	if (req->drv_status != CSIO_SUCCESS)
		return;

	if (wrp.size1 >= size) {
		/* Initialize WR in one shot */
		csio_scsi_init_abrt_cls_wr(req, wrp.addr1, size, abort);
	} else {
		uint8_t tmpwr[512];
		/*
		 * Make a temporary copy of the WR and write back
		 * the copy into the WR pair.
		 */
		csio_scsi_init_abrt_cls_wr(req, (void *)tmpwr, size, abort);
		csio_memcpy(wrp.addr1, tmpwr, wrp.size1);
		csio_memcpy(wrp.addr2, tmpwr + wrp.size1, size - wrp.size1);
	}

	CSIO_DUMP_WR(hw, wrp);
}


/*****************************************************************************/
/* START: SCSI  SM                                                      */
/*****************************************************************************/
static void
csio_scsis_uninit(struct csio_ioreq *req, csio_scsi_ev_t evt)
{
	struct csio_hw *hw = req->lnode->hwp;
	struct csio_scsim *scsim = csio_hw_to_scsim(hw);

	switch (evt) {

	case CSIO_SCSIE_START_IO:

		/* There is data */
		if (req->nsge) {
			if (req->datadir == CSIO_IOREQF_DMA_WRITE) {
				req->dcopy = 0;	
				csio_scsi_data(req, write, _WRITE_);
			}
			else	{
				csio_setup_ddp(scsim, req);
			}
		} else {
			csio_scsi_cmd(req);
		}
		
		if (csio_likely(req->drv_status == CSIO_SUCCESS)) {
			/* change state and enqueue on active_q */
			csio_set_state(&req->sm, csio_scsis_io_active);
			csio_enq_at_tail(&scsim->active_q, &req->sm.sm_list);
			csio_wr_issue(hw, req->eq_idx, CSIO_FALSE);
			CSIO_INC_STATS(scsim, n_active);

			return;
		}
		break;

	case CSIO_SCSIE_START_TM:
		csio_scsi_cmd(req);
		if (req->drv_status == CSIO_SUCCESS) {
			/*
			 * NOTE: We collect the affected I/Os prior to issuing
			 * LUN reset, and not after it. This is to prevent
			 * aborting I/Os that get issued after the LUN reset,
			 * but prior to LUN reset completion (in the event that
			 * the host stack has not blocked I/Os to a LUN that is
			 * being reset.
			 */
			csio_scsi_dbg(hw,
				"req: %p revcd evt CSIO_SCSIE_START_TM\n", req);
			csio_set_state(&req->sm, csio_scsis_tm_active);
			csio_enq_at_tail(&scsim->active_q, &req->sm.sm_list);
			csio_wr_issue(hw, req->eq_idx, CSIO_FALSE);
			CSIO_INC_STATS(scsim, n_tm_active);
		}
		//CSIO_TRACE(hw, CSIO_SCSI_MOD, CSIO_DBG_LEV, req, 0, 0, 0);
		return;

	case CSIO_SCSIE_ABORT:
	case CSIO_SCSIE_CLOSE:
		/*
		 * NOTE:
		 * We could get here due to  :
		 * - a window in the cleanup path of the SCSI module
		 *   (csio_scsi_abort_io()). Please see NOTE in this function.
		 * - a window in the time we tried to issue an abort/close
		 *   of a request to FW, and the FW completed the request
		 *   itself.
		 *   Print a message for now, and return INVAL either way.
		 */
		req->drv_status = CSIO_INVAL;
		csio_warn(hw, "Trying to abort/close completed IO:%p!\n", req);
		break;

	default:
		csio_warn(hw, "%s: Unhandled event:%d sent to req:%p\n", __FUNCTION__, evt, req);
		CSIO_DB_ASSERT(0);
	}
	return;
}

static void
csio_scsis_io_active(struct csio_ioreq *req, csio_scsi_ev_t evt)
{
	struct csio_hw *hw = req->lnode->hwp;
	struct csio_rnode_fcoe *rnf;
	struct csio_scsim *scm = csio_hw_to_scsim(hw);

	switch (evt) {

	case CSIO_SCSIE_COMPLETED:
		CSIO_DEC_STATS(scm, n_active);
		csio_deq_elem(req);
		csio_set_state(&req->sm, csio_scsis_uninit);
		/*
		 * REVISIT: The fix below is FCoE-only for now. Dunno how
		 * iSCSI will handle IT-nexus loss. If the handling is
		 * found to be similar, the check for FCoE below can
		 * be removed. The os_cmpl_q then becomes part of the
		 * common rnode, instead of rnf.
		 */
		/*
		 * In MSIX mode, with multiple queues, the SCSI compeltions
		 * could reach us sooner than the FW events sent to indicate
		 * I-T nexus loss (link down, remote device logo etc). We
		 * dont want to be returning such I/Os to the upper layer
		 * immediately, since we wouldnt have reported the I-T nexus
		 * loss itself. This forces us to serialize such completions
		 * with the reporting of the I-T nexus loss. Therefore, we
		 * internally queue up such up such completions in the rnode.
		 * The reporting of I-T nexus loss to the upper layer is then
		 * followed by the returning of I/Os in this internal queue.
		 * Having another state alongwith another queue helps us take
		 * actions for events such as ABORT received while we are
		 * in this rnode queue.
		 */
		if ((csio_unlikely(req->wr_status != FW_SUCCESS)) &&
							csio_is_fcoe(hw)) {
			rnf = csio_rnode_to_fcoe(req->rnode);
			/*
			 * FW says remote device is lost, but rnode
			 * doesnt reflect it.
			 */
			if (csio_scsi_itnexus_loss_error(req->wr_status) &&
						csio_is_rnf_ready(rnf)) {
				csio_scsi_dbg(hw,
					"Holding req %p on return of %d\n",
					req, req->wr_status);
				csio_set_state(&req->sm,
						csio_scsis_os_cmpl_await);
				csio_enq_at_tail(&rnf->os_cmpl_q,
						 &req->sm.sm_list);
			}
		}
#ifdef __CSIO_SCSI_PERF__
		else {
			if (csio_likely(req->nsge)) {
				int64_t len = csio_scsi_datalen(
						csio_scsi_osreq(req));
				if (req->datadir == CSIO_IOREQF_DMA_WRITE) {
					scm->stats.writes++;
					scm->stats.wbytes += len;
				} else  {
					scm->stats.reads++;
					scm->stats.rbytes += len;
				}
			}
		}
#endif /* __CSIO_SCSI_PERF__ */

		break;

	case CSIO_SCSIE_ABORT:
		csio_scsi_abrt_cls(req, SCSI_ABORT);
		if (req->drv_status == CSIO_SUCCESS) {
			csio_wr_issue(hw, req->eq_idx, CSIO_FALSE);
			csio_scsi_dbg(hw,
			    	    "ioreq %p state change to aborting\n", req);
			csio_set_state(&req->sm, csio_scsis_aborting);
		}
		break;

	case CSIO_SCSIE_CLOSE:
		if (csio_is_fcoe(hw)) {
			csio_scsi_abrt_cls(req, SCSI_CLOSE);
			if (req->drv_status == CSIO_SUCCESS) {
				csio_wr_issue(hw, req->eq_idx, CSIO_FALSE);
				csio_scsi_dbg(hw,
						"ioreq %p state change to \
						closing\n", req);
				csio_set_state(&req->sm, csio_scsis_closing);
			}
		} else {
			csio_scsi_dbg(hw,
					"ioreq %p state change to closing\n",
					req);
			csio_set_state(&req->sm, csio_scsis_closing);
			req->wr_status = FW_SCSI_CLOSE_REQUESTED;
			req->io_cbfn(hw, req);
		}
		break;

	case CSIO_SCSIE_DRVCLEANUP:
		req->wr_status = FW_HOSTERROR;
		CSIO_DEC_STATS(scm, n_active);
		csio_set_state(&req->sm, csio_scsis_uninit);
		break;

	default:
		csio_warn(hw, "Unhandled event:%d sent to req:%p\n", evt, req);
		CSIO_DB_ASSERT(0);

	}
	return;
}

static void
csio_scsis_tm_active(struct csio_ioreq *req, csio_scsi_ev_t evt)
{
	struct csio_hw *hw = req->lnode->hwp;
	struct csio_scsim *scm = csio_hw_to_scsim(hw);

	switch (evt) {

	case CSIO_SCSIE_COMPLETED:
		csio_scsi_dbg(hw,
			    "req: %p recvd evt CSIO_SCSIE_COMPLETED\n", req);
		CSIO_DEC_STATS(scm, n_tm_active);
		csio_deq_elem(req);
		csio_set_state(&req->sm, csio_scsis_uninit);

		break;

	case CSIO_SCSIE_ABORT:
		csio_scsi_abrt_cls(req, SCSI_ABORT);
		if (req->drv_status == CSIO_SUCCESS) {
			csio_wr_issue(hw, req->eq_idx, CSIO_FALSE);
			csio_scsi_dbg(hw, "ioreq %p state change to aborting\n",
					req);
			csio_set_state(&req->sm, csio_scsis_aborting);
		}
		break;


	case CSIO_SCSIE_CLOSE:
		csio_scsi_abrt_cls(req, SCSI_CLOSE);
		if (req->drv_status == CSIO_SUCCESS) {
			csio_wr_issue(hw, req->eq_idx, CSIO_FALSE);
			csio_scsi_dbg(hw, "ioreq %p state change to closing\n",
					req);
			csio_set_state(&req->sm, csio_scsis_closing);
		}
		break;

	case CSIO_SCSIE_DRVCLEANUP:
		req->wr_status = FW_HOSTERROR;
		CSIO_DEC_STATS(scm, n_tm_active);
		csio_set_state(&req->sm, csio_scsis_uninit);
		break;

	default:
		csio_warn(hw, "Unhandled event:%d sent to req:%p\n",
				evt, req);
		CSIO_DB_ASSERT(0);
	}
	return;
}

static void
csio_scsis_aborting(struct csio_ioreq *req, csio_scsi_ev_t evt)
{
	struct csio_hw *hw = req->lnode->hwp;
	struct csio_scsim *scm = csio_hw_to_scsim(hw);

	switch (evt) {

	case CSIO_SCSIE_COMPLETED:
		csio_scsi_dbg(hw, "ioreq %p recvd cmpltd (wr_status:%d) "
				"in aborting st\n", req, req->wr_status);
		/*
		 * Use CSIO_CANCELLED to explicitly tell the ABORTED event that
		 * the original I/O was returned to driver by FW.
		 * We dont really care if the I/O was returned with success by
		 * FW (because the ABORT and completion of the I/O crossed each
		 * other), or any other return value. Once we are in aborting
		 * state, the success or failure of the I/O is unimportant to
		 * us.
		 */
		req->drv_status = CSIO_CANCELLED;
		break;

	case CSIO_SCSIE_ABORT:
		csio_scsi_dbg(hw, "Ignoring evt ABORT, req %p already"
			    " in aborting state\n", req);
		CSIO_INC_STATS(scm, n_abrt_dups);
		break;

	case CSIO_SCSIE_ABORTED:

		csio_scsi_dbg(hw, "abort of %p return status:0x%x "
			     "drv_status:%x\n", req, req->wr_status,
			     req->drv_status);
		/*
		 * Check if original I/O WR completed before the Abort
		 * completion.
		 * In case of iSCSI original I/O is not returned. Only
		 * one completion is received for abort.
		 */
		if (csio_is_fcoe(hw) && req->drv_status != CSIO_CANCELLED) {
			csio_fatal(hw, "Abort completed before original I/O,"
				    " req:%p\n", req);
			CSIO_DB_ASSERT(0);
		}

		/*
		 * There are the following possible scenarios:
		 * 1. The abort completed successfully, FW returned FW_SUCCESS.
		 * 2. The completion of an I/O and the receipt of
		 *    abort for that I/O by the FW crossed each other.
		 *    The FW returned FW_EINVAL. The original I/O would have
		 *    returned with FW_SUCCESS or any other SCSI error.
		 * 3. The FW couldnt sent the abort out on the wire, as there
		 *    was an I-T nexus loss (link down, remote device logged
		 *    out etc). FW sent back an appropriate IT nexus loss status
		 *    for the abort.
		 * 4. FW sent an abort, but abort timed out (remote device
		 *    didnt respond). FW replied back with
		 *    FW_SCSI_ABORT_TIMEDOUT.
		 * 5. FW couldnt genuinely abort the request for some reason,
		 *    and sent us an error.
		 *
		 * The first 3 scenarios are treated as  succesful abort
		 * operations by the host, while the last 2 are failed attempts
		 * to abort. Manipulate the return value of the request
		 * appropriately, so that host can convey these results
		 * back to the upper layer.
		 */
		if ((req->wr_status == FW_SUCCESS) ||
		    (req->wr_status == FW_EINVAL) ||
		     csio_scsi_itnexus_loss_error(req->wr_status))
			req->wr_status = FW_SCSI_ABORT_REQUESTED;

		CSIO_DEC_STATS(scm, n_active);
		csio_deq_elem(req);
		csio_set_state(&req->sm, csio_scsis_uninit);
		break;

	case CSIO_SCSIE_DRVCLEANUP:
		req->wr_status = FW_HOSTERROR;
		CSIO_DEC_STATS(scm, n_active);
		csio_set_state(&req->sm, csio_scsis_uninit);
		break;

	case CSIO_SCSIE_CLOSE:
		/*
		 * We can receive this event from the module
		 * cleanup paths, if the FW forgot to reply to the ABORT WR
		 * and left this ioreq in this state. For now, just ignore
		 * the event. The CLOSE event is sent to this state, as
		 * the LINK may have already gone down.
		 */
		csio_scsi_dbg(hw, "Ignoring evt CLOSE, req %p already"
			      " in aborting state\n", req);
		break;

	default:
		csio_warn(hw, "Unhandled event:%d sent to req:%p\n", evt, req);
		CSIO_DB_ASSERT(0);
	}
	return;
}

static void
csio_scsis_closing(struct csio_ioreq *req, csio_scsi_ev_t evt)
{
	struct csio_hw *hw = req->lnode->hwp;
	struct csio_scsim *scm = csio_hw_to_scsim(hw);

	switch (evt) {

	case CSIO_SCSIE_COMPLETED:
		csio_scsi_dbg(hw, "ioreq %p recvd cmpltd (wr_status:%d) "
				"in closing st\n", req, req->wr_status);
		/*
		 * Use CSIO_CANCELLED to explicitly tell the CLOSED event that
		 * the original I/O was returned to driver by FW.
		 * We dont really care if the I/O was returned with success by
		 * FW (because the CLOSE and completion of the I/O crossed each
		 * other), or any other return value. Once we are in aborting
		 * state, the success or failure of the I/O is unimportant to
		 * us.
		 */
		req->drv_status = CSIO_CANCELLED;
		break;

	case CSIO_SCSIE_CLOSED:
		csio_scsi_dbg(hw, "close of %p return status:0x%x "
			     "drv_status:%x\n", req, req->wr_status,
			     req->drv_status);
		/*
		 * Check if original I/O WR completed before the Close
		 * completion.
		 */
		if (req->drv_status != CSIO_CANCELLED) {
			csio_fatal(hw, "Close completed before original I/O,"
				    " req:%p\n", req);
			CSIO_DB_ASSERT(0);
		}

		/*
		 * Either close succeeded, or we issued close to FW at the
		 * same time FW compelted it to us. Either way, the I/O
		 * is closed.
		 */
		CSIO_DB_ASSERT((req->wr_status == FW_SUCCESS) ||
					(req->wr_status == FW_EINVAL));
#ifndef __CSIO_DEBUG__
		if ((req->wr_status == FW_SUCCESS) ||
					(req->wr_status == FW_EINVAL))
#endif /* __CSIO_DEBUG__ */
			req->wr_status = FW_SCSI_CLOSE_REQUESTED;

		CSIO_DEC_STATS(scm, n_active);
		csio_deq_elem(req);
		csio_set_state(&req->sm, csio_scsis_uninit);
		break;

	case CSIO_SCSIE_CLOSE:
		csio_scsi_dbg(hw, "Ignoring evt CLOSE, req %p already"
			    " in closing state\n", req);
		break;

	case CSIO_SCSIE_DRVCLEANUP:
		req->wr_status = FW_HOSTERROR;
		CSIO_DEC_STATS(scm, n_active);
		csio_set_state(&req->sm, csio_scsis_uninit);
		break;

	default:
		csio_warn(hw, "Unhandled event:%d sent to req:%p\n",
			      evt, req);
		CSIO_DB_ASSERT(0);
	}
	return;
}

static void
csio_scsis_os_cmpl_await(struct csio_ioreq *req, csio_scsi_ev_t evt)
{
	struct csio_hw *hw = req->lnode->hwp;

	switch (evt) {
	case CSIO_SCSIE_ABORT:
	case CSIO_SCSIE_CLOSE:
		/*
		 * Just succeed the abort request, and hope that
		 * the remote device unregister path will cleanup
		 * this I/O to the upper layer within a sane
		 * amount of time.
		 */
		/*
		 * A close can come in during a LINK DOWN. The FW would have
		 * returned us the I/O back, but not the remote device lost
		 * FW event. In this interval, if the I/O times out at the upper
		 * layer, a close can come in. Take the same action as abort:
		 * return success, and hope that the remote device unregister
		 * path will cleanup this I/O. If the FW still doesnt send
		 * the msg, the close times out, and the upper layer resorts
		 * to the next level of error recovery.
		 */
		req->drv_status = CSIO_SUCCESS;
		break;
	case CSIO_SCSIE_DRVCLEANUP:
		csio_set_state(&req->sm, csio_scsis_uninit);
		break;
	default:
		csio_warn(hw, "Unhandled event:%d sent to req:%p\n",
				evt, req);
		CSIO_DB_ASSERT(0);
	}
}

/*
 * csio_scsi_cmpl_handler - WR completion handler for SCSI.
 * @hw: HW module.
 * @wr: The completed WR from the ingress queue.
 * @len: Length of the WR.
 * @flb: Freelist buffer array.
 * @priv: Private object
 * @scsiwr: Pointer to SCSI WR.
 *
 * This is the WR completion handler called per completion from the
 * ISR. It is called with lock held. It walks past the RSS and CPL message
 * header where the actual WR is present.
 * It then gets the status, WR handle (ioreq pointer) and the len of
 * the WR, based on WR opcode. Only on a non-good status is the entire
 * WR copied into the WR cache (ioreq->fw_wr).
 * The ioreq corresponding to the WR is returned to the caller.
 * NOTE: The SCSI queue doesnt allocate a freelist today, hence
 * no freelist buffer is expected.
 */
struct csio_ioreq *
csio_scsi_cmpl_handler(struct csio_hw *hw, void *wr, uint32_t len,
		     struct csio_fl_dma_buf *flb, void *priv, uint8_t **scsiwr)
{
	struct csio_ioreq *ioreq = NULL;
	struct cpl_fw6_msg *cpl;
	uint8_t *tempwr;
	uint8_t	status;
	struct csio_scsim *scm = csio_hw_to_scsim(hw);

	/*Check if WR Length is in unit of 16bytes  */
	CSIO_DB_ASSERT(!(len & 0xF));

#ifdef __CSIO_TARGET__
	/*
	 * If the target driver is interested in the WR, it should return
	 * 1, so that the initiator mode handler doesnt have to look into
	 * the same WR again.
	 */
	if (csio_tgt_isr(hw, wr, len, flb, priv))
		return NULL;
#else
	if (csio_unlikely(flb))
		csio_warn(hw, "Unexpected freelist buffer on SCSI cmpl\n");
#endif /* __CSIO_TARGET__ */

	/* skip RSS header */
	cpl = (struct cpl_fw6_msg *)((uintptr_t)wr + sizeof(__be64));

	if (csio_unlikely(cpl->opcode != CPL_FW6_MSG)) {
		csio_err(hw, "Error: Invalid CPL msg recvd on SCSI q\n");
		CSIO_INC_STATS(scm, n_inval_cplop);
		return NULL;
	}
	
	tempwr = (uint8_t *)(cpl->data);
	status = csio_wr_status(tempwr);
	*scsiwr = tempwr;

	if (csio_likely((*tempwr == FW_SCSI_READ_WR) ||
			(*tempwr == FW_SCSI_WRITE_WR) ||
			(*tempwr == FW_SCSI_CMD_WR))) {
		ioreq = (struct csio_ioreq *)((uintptr_t)
				 (((struct fw_scsi_read_wr *)tempwr)->cookie));
		CSIO_DB_ASSERT(csio_virt_addr_valid(ioreq));

		ioreq->wr_status = status;

		return ioreq;
	}

	if (*tempwr == FW_SCSI_ABRT_CLS_WR) {
		ioreq = (struct csio_ioreq *)((uintptr_t)
			 (((struct fw_scsi_abrt_cls_wr *)tempwr)->cookie));
		CSIO_DB_ASSERT(csio_virt_addr_valid(ioreq));

		ioreq->wr_status = status;
		CSIO_TRACE(hw, CSIO_SCSI_MOD, CSIO_DBG_LEV, ioreq,
			   ((struct fw_scsi_abrt_cls_wr *)tempwr)->cookie,
			   status, 0);

		return ioreq;
	}
		
	csio_warn(hw, "WR with invalid opcode in SCSI IQ: %x\n", *tempwr);
	CSIO_INC_STATS(scm, n_inval_scsiop);
	return NULL;
}

/*
 * csio_scsi_cleanup_io_q - Cleanup the given queue.
 * @scm: SCSI module.
 * @q: Queue to be cleaned up.
 *
 * Called with lock held. Has to exit with lock held.
 */
void
csio_scsi_cleanup_io_q(struct csio_scsim *scm, struct csio_list *q)
{
	struct csio_hw *hw = scm->hw;
	struct csio_ioreq *ioreq;
	struct csio_list *tmp, *next;
	void *osreq;

	/* Call back the completion routines of the active_q */
	csio_list_for_each_safe(tmp, next, q) {
		ioreq = (struct csio_ioreq *)tmp;
		csio_scsi_dbg(hw, "cleaning up req: %p\n", ioreq);
		/*
		 * REVISIT: Temporarily using FW_HOSTERROR to indicate driver
		 * internal error. Later we should use a value here that is
		 * not going to be used by firmware for any other error.
		 */
		csio_scsi_drvcleanup(ioreq);
		csio_deq_elem(ioreq);
		osreq = csio_scsi_osreq(ioreq);
		csio_spin_unlock_irq(hw, &hw->lock);

		/*
		 * Upper layers may have cleared this command, hence this
		 * check to avoid accessing stale references.
		 */
		if (osreq != NULL)
			ioreq->io_cbfn(hw, ioreq);

		csio_spin_lock_irq(hw, &scm->freelist_lock);
		csio_put_scsi_ioreq(scm, ioreq);
		csio_spin_unlock_irq(hw, &scm->freelist_lock);

		csio_spin_lock_irq(hw, &hw->lock);
	}

	return;
}

#define CSIO_SCSI_ABORT_Q_POLL_MS		2000

/*
 * csio_scsi_abort_io_q - Abort all I/Os on given queue
 * @scm: SCSI module.
 * @q: Queue to abort.
 * @tmo: Timeout in ms
 *
 * Attempt to abort all I/Os on given queue, and wait for a max
 * of tmo milliseconds for them to complete. Returns success
 * if all I/Os are aborted. Else returns CSIO_TIMEOUT.
 * Should be entered with lock held. Exits with lock held.
 * NOTE:
 * Lock has to be held across the loop that aborts I/Os, since dropping the lock
 * in between can cause the list to be corrupted. As a result, the caller
 * of this function has to ensure that the number of I/os to be aborted
 * is finite enough to not cause lock-held-for-too-long issues.
 */
csio_retval_t
csio_scsi_abort_io_q(struct csio_scsim *scm, struct csio_list *q, uint32_t tmo)
{
	struct csio_hw *hw = scm->hw;
	struct csio_list *tmp, *next;
	int count = CSIO_ROUNDUP(tmo, CSIO_SCSI_ABORT_Q_POLL_MS);
	void *osreq;

	if (csio_list_empty(q))
		return CSIO_SUCCESS;

	csio_scsi_dbg(hw, "Aborting SCSI I/Os\n");
	
	/* Now abort/close I/Os in the queue passed */
	csio_list_for_each_safe(tmp, next, q) {
		csio_scsi_dbg(hw, "aborting req: %p\n", tmp);
		osreq = csio_scsi_osreq((struct csio_ioreq *)tmp);
		csio_hw_to_ops(hw)->os_abrt_cls((struct csio_ioreq *)tmp,
						 osreq);
	}
	
	/* Wait till all active I/Os are completed/aborted/closed */
	csio_scsi_dbg(hw, "Waiting for aborts to complete max %d secs.\n",
		    count * (CSIO_SCSI_ABORT_Q_POLL_MS / 1000));
	while (!csio_list_empty(q) && count--) {
		csio_spin_unlock_irq(hw, &hw->lock);
		csio_msleep(CSIO_SCSI_ABORT_Q_POLL_MS);
		csio_spin_lock_irq(hw, &hw->lock);
	}

	/* all aborts completed */
	if (csio_list_empty(q))
		return CSIO_SUCCESS;

	return CSIO_TIMEOUT;
}

/*
 * csio_scsim_cleanup_io - Cleanup all I/Os in SCSI module.
 * @scm: SCSI module.
 * @abort: abort required.
 * Called with lock held, should exit with lock held.
 * Can sleep when waiting for I/Os to complete.
 */
csio_retval_t
csio_scsim_cleanup_io(struct csio_scsim *scm, bool abort)
{
	struct csio_hw *hw = scm->hw;
	enum csio_oss_error rv = CSIO_SUCCESS;
	int count = CSIO_ROUNDUP(60 * 1000, CSIO_SCSI_ABORT_Q_POLL_MS);

	/* No I/Os pending */
	if (csio_list_empty(&scm->active_q))
		return CSIO_SUCCESS;

	/* Wait until all active I/Os are completed */
	csio_scsi_dbg(hw, "Waiting max %d secs for all I/Os to complete\n",
		      count * (CSIO_SCSI_ABORT_Q_POLL_MS / 1000));
	while (!csio_list_empty(&scm->active_q) && count--) {
		csio_spin_unlock_irq(hw, &hw->lock);
		csio_msleep(CSIO_SCSI_ABORT_Q_POLL_MS);
		csio_spin_lock_irq(hw, &hw->lock);
	}

	/* all I/Os completed */
	if (csio_list_empty(&scm->active_q))
		return CSIO_SUCCESS;

	/* Else abort */
	csio_scsi_dbg(hw, "Some I/Os pending, aborting them...\n");

	if (abort) {
		rv = csio_scsi_abort_io_q(scm, &scm->active_q, 30000);
		if (rv == CSIO_SUCCESS)
			return rv;
		csio_scsi_dbg(hw, "Some I/O aborts timed out, cleaning up..\n");
	}

	csio_scsi_cleanup_io_q(scm, &scm->active_q);

	CSIO_DB_ASSERT(csio_list_empty(&scm->active_q));

	return rv;
}

/*
 * csio_scsim_cleanup_io_lnode - Cleanup all I/Os of given lnode.
 * @scm: SCSI module.
 * @lnode: lnode
 *
 * Called with lock held, should exit with lock held.
 * Can sleep (with dropped lock) when waiting for I/Os to complete.
 */
csio_retval_t
csio_scsim_cleanup_io_lnode(struct csio_scsim *scm, struct csio_lnode *ln)
{
	struct csio_hw *hw = scm->hw;
	struct csio_scsi_level_data sld;
	enum csio_oss_error rv;
	int count = CSIO_ROUNDUP(60 * 1000, CSIO_SCSI_ABORT_Q_POLL_MS);

	csio_scsi_dbg(hw, "Gathering all SCSI I/Os on lnode %p\n", ln);

	sld.level = CSIO_LEV_LNODE;
	sld.lnode = ln;
	csio_head_init(&ln->cmpl_q);
	csio_scsi_gather_active_ios(scm, &sld, &ln->cmpl_q);

	/* No I/Os pending on this lnode  */
	if (csio_list_empty(&ln->cmpl_q))
		return CSIO_SUCCESS;

	/* Wait until all active I/Os on this lnode are completed */
	csio_scsi_dbg(hw, "Waiting max %d secs for I/Os on ln:%p to complete\n",
		      count * (CSIO_SCSI_ABORT_Q_POLL_MS / 1000), ln);
	while (!csio_list_empty(&ln->cmpl_q) && count--) {
		csio_spin_unlock_irq(hw, &hw->lock);
		csio_msleep(CSIO_SCSI_ABORT_Q_POLL_MS);
		csio_spin_lock_irq(hw, &hw->lock);
	}

	/* all I/Os completed */
	if (csio_list_empty(&ln->cmpl_q))
		return CSIO_SUCCESS;

	csio_scsi_dbg(hw, "Some I/Os pending on ln:%p, aborting them..\n", ln);

	/* I/Os are pending, abort them */
	rv = csio_scsi_abort_io_q(scm, &ln->cmpl_q, 30000);
	if (rv != CSIO_SUCCESS) {
		csio_scsi_dbg(hw, "Some I/O aborts timed out, cleaning up..\n");
		csio_scsi_cleanup_io_q(scm, &ln->cmpl_q);
	}

	CSIO_DB_ASSERT(csio_list_empty(&ln->cmpl_q));
	
	return rv;
}

#ifdef __CSIO_DDP_SUPPORT__
/**
 * csio_scsi_alloc_ddp_bufs - Allocate memory for direct data placement.
 * @scm: SCSI Module
 * @hw: HW device.
 * @buf_size: buffer size
 * @num_buf : Number of buffers.
 *
 * This routine alloc DMA' buffer required for SCSI Data xfer, if
 * each SGL buffer for a SCSI Read request posted by SCSI midlayer are
 * not virtually contiguous.
 * T4 HW supports DDP only if for virtually contiguous buffer. For non-virtual
 * contiguous buffer intermediate copy will be done from DDP buffers to
 * SCSI Request SGLs.
 */	
static csio_retval_t
csio_scsi_alloc_ddp_bufs(struct csio_scsim *scm, struct csio_hw *hw,
		int buf_size, int num_buf)
{
	int n = 0;
	struct csio_list *tmp;
	struct csio_dma_buf *ddp_desc = NULL;
	uint32_t unit_size = 0;

	if (!num_buf) {
		return CSIO_SUCCESS;
	}

	if (!buf_size) {
		return CSIO_INVAL;
	}
	csio_head_init(&scm->ddp_freelist);

	/* Align buf size to page size */
	buf_size = (buf_size + CSIO_PAGE_SIZE - 1) & CSIO_PAGE_MASK;
	/* Initialize dma descriptors */
	for (n = 0; n < num_buf; n++) {
		/* Set unit size to request size */	
		unit_size = buf_size;
		ddp_desc = csio_alloc(csio_md(hw, CSIO_DDP_MD),
				   sizeof(struct csio_dma_buf),
				   CSIO_MNOWAIT);
		if (!ddp_desc) {
			csio_err(hw, "ddp desc alloc failed for SCSI"
				    " module, Num allocated = %d.\n",
				     scm->stats.n_free_ddp);
			goto no_mem;
		}

		/* Allocate Dma buffers for DDP */
		ddp_desc->vaddr = csio_dma_alloc(&ddp_desc->dmahdl, hw->os_dev,
						unit_size, 8,
						&ddp_desc->paddr, CSIO_MNOWAIT);

	      	if (!ddp_desc->vaddr) {
			csio_err(hw, "SCSI resp DMA alloc failed!\n");
			csio_free(csio_md(hw, CSIO_DDP_MD), ddp_desc);
			goto no_mem;
	       	}
		ddp_desc->len = unit_size;
		/* Added it to scsi ddp freelist */
		csio_enq_at_tail(&scm->ddp_freelist, &ddp_desc->list);
		CSIO_INC_STATS(scm, n_free_ddp);
	}

	return CSIO_SUCCESS;	

no_mem:
	 /* release dma descs back to freelist and free dma memory */
	csio_list_for_each(tmp, &scm->ddp_freelist) {
		ddp_desc = (struct csio_dma_buf *) tmp;
		tmp = csio_list_prev(tmp);
		csio_dma_free(&ddp_desc->dmahdl, ddp_desc->vaddr);
		csio_deq_elem(ddp_desc);
		csio_free(csio_md(hw, CSIO_DDP_MD), ddp_desc);
		CSIO_DEC_STATS(scm, n_free_ddp);
	}

#ifdef __CSIO_DEBUG__
	if (scm->stats.n_free_ddp != 0)
		csio_dbg(hw, "Mismatch in allocation & free of DDP buffers, "
			 "No. of DDP buffers left = %d\n",
				scm->stats.n_free_ddp);
#endif /* __CSIO_DEBUG__ */

	return CSIO_NOMEM;
}	

/**
 * csio_scsi_free_ddp_bufs - free memory for direct data placement.
 * @scm: SCSI Module
 * @hw: HW device.
 *
 * This routine frees ddp buffers.
 */	
static csio_retval_t
csio_scsi_free_ddp_bufs(struct csio_scsim *scm, struct csio_hw *hw)
{
	struct csio_list *tmp;
	struct csio_dma_buf *ddp_desc;

	 /* release dma descs back to freelist and free dma memory */
	csio_list_for_each(tmp, &scm->ddp_freelist) {
		ddp_desc = (struct csio_dma_buf *) tmp;
		tmp = csio_list_prev(tmp);
		csio_dma_free(&ddp_desc->dmahdl, ddp_desc->vaddr);
		csio_deq_elem(ddp_desc);
		csio_free(csio_md(hw, CSIO_DDP_MD), ddp_desc);
		CSIO_DEC_STATS(scm, n_free_ddp);
	}

#ifdef __CSIO_DEBUG__
	if (scm->stats.n_free_ddp != 0)
		csio_dbg(hw, "DDP Buffers NOT freed completely, "
			 "No. of DDP buffers left = %d\n",
				scm->stats.n_free_ddp);
#endif /* __CSIO_DEBUG__ */

	return CSIO_NOMEM;
}	

#endif /* __CSIO_DDP_SUPPORT__ */

/**
 * csio_scsim_init: Initialize SCSI Module
 * @scm: SCSI Module
 * @hw: HW module
 *
 * Initialize SCSI timers, resource wait queue, active queue,
 * resource wait q, completion q. Allocate Egress and Ingress
 * WR queues and save off the queue index returned by the WR
 * module for future use. Allocate and save off ioreqs in the
 * ioreq_freelist for future use. Make sure their SM is initialized
 * to uninit state.
 */
csio_retval_t
csio_scsim_init(struct csio_scsim *scm, struct csio_hw *hw)
{
	int i;
	struct csio_ioreq *ioreq;
	struct csio_dma_buf *dma_buf;

	csio_head_init(&scm->active_q);
	scm->hw = hw;
	
	/*
	 * Setting this up here will save us a conditional statement
	 * in the fast path.
	 */
	if (csio_is_fcoe(hw)) {
		scm->proto_cmd_len = sizeof(struct csio_fcp_cmnd);
		scm->proto_rsp_len = sizeof(struct csio_fcp_resp);
		scm->max_sge = CSIO_SCSI_FCOE_MAX_SGE;
	} else { /* iSCSI */
#ifdef __CSIO_FOISCSI_ENABLED__
		scm->proto_cmd_len = sizeof(struct fw_scsi_iscsi_data);
		scm->proto_rsp_len = sizeof(struct fw_scsi_iscsi_rsp);
		scm->max_sge = CSIO_SCSI_ISCSI_MAX_SGE;
#endif
	}

	csio_spin_lock_init(&scm->freelist_lock);

	/* Pre-allocate ioreqs and initialize them */
	csio_head_init(&scm->ioreq_freelist);
	for (i = 0; i < csio_scsi_ioreqs; i++) {

		ioreq = csio_alloc(csio_md(hw, CSIO_SCSIREQ_MD),
				   sizeof(struct csio_ioreq),
				   CSIO_MNOWAIT);
		if (!ioreq) {
			csio_err(hw, "IO req alloc failed for SCSI"
				    " module, Num allocated = %d.\n",
				     scm->stats.n_free_ioreq);

			goto free_ioreq;
		}

		/* Allocate Dma buffers for Response Payload */
		dma_buf = &ioreq->dma_buf;
		dma_buf->vaddr = csio_dma_alloc(&dma_buf->dmahdl, hw->os_dev,
						scm->proto_rsp_len, 8,
						&dma_buf->paddr, CSIO_MNOWAIT);

		if (!dma_buf->vaddr) {
			csio_err(hw, "SCSI resp DMA alloc failed!\n");
			csio_free(csio_md(hw, CSIO_SCSIREQ_MD), ioreq);
			goto free_ioreq;
		}

		dma_buf->len = scm->proto_rsp_len;

		/* Set state to uninit */
		csio_init_state(&ioreq->sm, csio_scsis_uninit,
						csio_hw_to_tbuf(hw));
		csio_head_init(&ioreq->gen_list);
		csio_cmpl_init(&ioreq->cmplobj);

		csio_enq_at_tail(&scm->ioreq_freelist, &ioreq->sm.sm_list);
		CSIO_INC_STATS(scm, n_free_ioreq);
	}
	
#ifdef __CSIO_DDP_SUPPORT__
	if (csio_scsi_alloc_ddp_bufs(scm, hw, csio_ddp_descs_npages *
				CSIO_PAGE_SIZE, csio_ddp_descs)) {
		goto free_ioreq;	
	}		
#endif
	return CSIO_SUCCESS;

free_ioreq:
	/*
	 * Free up existing allocations, since an error
	 * from here means we are returning for good
	 */
	while (!csio_list_empty(&scm->ioreq_freelist)) {
		csio_deq_from_head(&scm->ioreq_freelist, &ioreq);

		dma_buf = &ioreq->dma_buf;
		csio_dma_free(&dma_buf->dmahdl, dma_buf->vaddr);

		csio_free(csio_md(hw, CSIO_SCSIREQ_MD), ioreq);
	}

	scm->stats.n_free_ioreq = 0;

	return CSIO_NOMEM;
}

/**
 * csio_scsim_exit: Uninitialize SCSI Module
 * @scm: SCSI Module
 *
 * Stop timers, free allocations.
 */
void
csio_scsim_exit(struct csio_scsim *scm)
{
	struct csio_ioreq *ioreq;
	struct csio_dma_buf *dma_buf;

	while (!csio_list_empty(&scm->ioreq_freelist)) {
		csio_deq_from_head(&scm->ioreq_freelist, &ioreq);

		dma_buf = &ioreq->dma_buf;
		csio_dma_free(&dma_buf->dmahdl, dma_buf->vaddr);

		csio_free(csio_md(scm->hw, CSIO_SCSIREQ_MD), ioreq);
	}

	scm->stats.n_free_ioreq = 0;

#ifdef __CSIO_DDP_SUPPORT__
	csio_scsi_free_ddp_bufs(scm, scm->hw);
#endif	

	return;
}
