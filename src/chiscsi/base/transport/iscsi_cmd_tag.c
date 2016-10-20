#include <linux/version.h>
#include <linux/kernel.h>

#include <common/os_export.h>
#include <common/iscsi_defs.h>
#include <common/cxgb_dev.h>
#include <kernel/os_socket.h>
#include <kernel/cxgbi_ippm.h>

static inline unsigned int iscsi_tag_make_sw_tag(unsigned int idx,
						 unsigned int r2tsn)
{
	/* assume idx and r2tsn both are < 0x7FFF (32767) */
	return idx | (r2tsn << 16);
}

void iscsi_tag_decode_sw_tag(unsigned int sw_tag, unsigned int *idx,
				unsigned int *r2tsn)
{
	/* assume idx and r2tsn both are < 0x7FFF (32767) */
	if (idx)
		*idx = sw_tag & 0x7FFF;
	if (r2tsn)
		*r2tsn = (sw_tag >> 16) & 0x7FFF;
}

/* 
 * this is temp. function for target multi-phase data support
 * once it is verified working, will merge it with other tag generation func.
 */

//static void iscsi_task_tag_release_ddp(void *odevp, unsigned int ddp_tag);
void iscsi_target_task_tag_release_woff(void *odevp, unsigned int ddp_tag)
{
	//iscsi_task_tag_release_ddp(odevp, ddp_tag);
	return;
}

int iscsi_target_task_tag_get_woff(void *isock, unsigned int idx, unsigned int r2t,
			unsigned int sgcnt, chiscsi_sgvec *sgl, unsigned int total_xferlen,
			unsigned int xferoff, unsigned int buflen,
			unsigned int *sw_tag, unsigned int *ddp_tag,
			void *pi_info, struct chiscsi_tag_ppod *ppod_info)
{
	offload_device	*odev = ((iscsi_socket *)isock)->s_odev;
	struct cxgbi_ppm *ppm = NULL;
	unsigned int base_tag;
	int err = -EINVAL;

	r2t %= ISCSI_SESSION_MAX_OUTSTANDING_R2T;
	base_tag = iscsi_tag_make_sw_tag(idx, r2t);

	*sw_tag = *ddp_tag = base_tag;

	/* no ddp set up */
	if (!sgcnt)
		goto done;
 
	if (!(((iscsi_socket *)isock)->s_mode & ISCSI_OFFLOAD_MODE_DDP))
		goto done;

	if (!odev || !(odev->d_flag & ODEV_FLAG_ULP_DDP_ENABLED))
		goto done;

	ppm = odev->odev2ppm(odev);
	if (!ppm)
		goto done;

done:
	if (err < 0) {
		if (ppm)
			err = cxgbi_ppm_make_non_ddp_tag(ppm, base_tag,
							ddp_tag);
		return err;
	} else
		return 1;
}

static inline struct cxgbi_ppm *isock_to_ppm(iscsi_socket *isock)
{
	offload_device *odev = isock ? isock->s_odev : NULL;
	struct cxgbi_ppm *ppm = NULL;

	if (odev && (odev->d_flag & ODEV_FLAG_ULP_DDP_ENABLED))
		ppm = odev->odev2ppm(odev);
	return ppm;
}

unsigned int iscsi_tag_get_sw_tag(iscsi_socket *isock, unsigned int tag)
{
	struct cxgbi_ppm *ppm = isock_to_ppm(isock);

	if (!ppm) 
		return tag;

 	if (cxgbi_ppm_is_ddp_tag(ppm, tag))
		return (unsigned int)(cxgbi_ppm_get_tag_caller_data(ppm, tag));
	else 
		return cxgbi_ppm_decode_non_ddp_tag(ppm, tag);	
}

int iscsi_tag_update_r2tsn(chiscsi_scsi_command *sc, unsigned int r2tsn,					unsigned int *new_tag)
{
	struct cxgbi_ppm *ppm = isock_to_ppm(sc->sc_sock);
	int err = 0;
	
 	if (ppm && cxgbi_ppm_is_ddp_tag(ppm, sc->sc_ddp_tag))
		return cxgbi_ppm_ddp_tag_update_sw_bits(ppm, r2tsn,
						 sc->sc_ddp_tag, new_tag);
	
	*new_tag = iscsi_tag_make_sw_tag(sc->sc_idx, r2tsn);
	if (ppm)
		err = cxgbi_ppm_make_non_ddp_tag(ppm, *new_tag, new_tag);
	return err;
}

static void ddp_dma_unmap_sgl(struct pci_dev *pdev, chiscsi_sgvec *sgl,
			 unsigned int sgcnt, unsigned int pgsz)
{
	chiscsi_sgvec *sg = sgl;
	int i;

	if (!sgl->sg_dma_addr)
		return;

	for (i = 0; i < sgcnt; i++, sg++) {
		dma_unmap_page(&pdev->dev, sg->sg_dma_addr, pgsz,
				PCI_DMA_FROMDEVICE);
		sg->sg_dma_addr = 0ULL;
	}
}

static int ddp_dma_map_sgl(struct pci_dev *pdev, chiscsi_sgvec *sgl,
			 unsigned int sgcnt, unsigned int pgsz)
{
	chiscsi_sgvec *sg = sgl;
	int i;

	if (sgl->sg_dma_addr)
		return 0;

	for (i = 0; i < sgcnt; i++, sg++) {
		sg->sg_dma_addr = dma_map_page(&pdev->dev, sg->sg_page, 0,
						pgsz, PCI_DMA_FROMDEVICE);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
                if (unlikely(dma_mapping_error(&pdev->dev, sg->sg_dma_addr)))
#else
                if (unlikely(pci_dma_mapping_error(sg->sg_dma_addr)))
#endif
                {
                        os_log_info("%s: pg %d,0x%p, dma mapping err.\n",
                                __func__, i, sg->sg_page);
                        goto unmap;
                }
        }
	return i;

unmap:
	 if (i)
		ddp_dma_unmap_sgl(pdev, sgl, i, pgsz);
        return -EINVAL;

}

int iscsi_tag_reserve(chiscsi_scsi_command *sc)
{
	iscsi_socket *isock = sc->sc_sock;
	struct cxgbi_pdu_pi_info *pi_info = NULL;
	offload_device	*odev = isock->s_odev;
	struct cxgbi_ppm *ppm = odev ? isock_to_ppm(isock) : NULL;
	chiscsi_scsi_write_cb *wcb = &sc->sc_cb.wcb;
	chiscsi_sgvec *sgl = (chiscsi_sgvec *)sc->sc_sgl.sgl_vecs;
	struct cxgbi_task_tag_info ttinfo;
	unsigned int pg_shift;
	int err = 0;

	sc->sc_sw_tag = iscsi_tag_make_sw_tag(sc->sc_idx,
			wcb->w_r2tsn % ISCSI_SESSION_MAX_OUTSTANDING_R2T);

	if (sc->sc_xfer_len < 512 ||
	    !(isock->s_mode & ISCSI_OFFLOAD_MODE_DDP) || !ppm) {
		/* no ddp */
		goto no_ddp;
	}

	ttinfo.flags = 0;
	ttinfo.cid = isock->s_port_id;
	ttinfo.pg_shift = pg_shift =
				 ppm->tformat.pgsz_order[isock->s_ddp_pgidx] +
				 DDP_PGSZ_BASE_SHIFT;

	if (sc->pi_info.prot_op)
		pi_info = &sc->pi_info;

	/* make sure the buffers are suitable for ddp */

	ttinfo.nr_pages = (sc->sc_xfer_len + sgl->sg_offset +
			   (1 << pg_shift) - 1) >> pg_shift;

	err = odev->ppm_ppods_reserve(ppm, ttinfo.nr_pages, 0, &ttinfo.idx,
					&sc->sc_ddp_tag,
					(unsigned long)sc->sc_sw_tag);
	if (err < 0)
		goto no_ddp;
	ttinfo.tag = sc->sc_ddp_tag;
	ttinfo.npods = err;

	if (!sgl->sg_dma_addr) {
		err = ddp_dma_map_sgl(ppm->pdev, sgl, sc->sc_sgl.sgl_vecs_nr,
				1 << pg_shift);
		if (err <= 0)
			goto rel_ppods;
		scmd_fpriv_set_bit(sc, CH_SFP_BUF_DDP_MAPPED_BIT);
		ttinfo.flags |= CXGBI_PPOD_INFO_FLAG_MAPPED;
	}

	odev->ppm_make_ppod_hdr(ppm, sc->sc_ddp_tag, isock->s_tid,
				sgl->sg_offset, sc->sc_xfer_len, pi_info,
				&ttinfo.hdr);
	
	ttinfo.sgl = (struct scatterlist *)sc->sc_sgl.sgl_vecs;
	ttinfo.nents = sc->sc_sgl.sgl_vecs_nr;

	err = odev->ddp_set_map(isock, (void *)&ttinfo, &sc->ppod_info);
	if (err < 0)
		goto unmap_sgl;

	/* save the related info for release time */
	sc->sc_odev = odev;
	return 0;

unmap_sgl:
	if (scmd_fpriv_test_bit(sc, CH_SFP_BUF_DDP_MAPPED_BIT)) {
		scmd_fpriv_clear_bit(sc, CH_SFP_BUF_DDP_MAPPED_BIT);
		ddp_dma_unmap_sgl(ppm->pdev, sgl, sc->sc_sgl.sgl_vecs_nr,
				1 << pg_shift);
	}

rel_ppods:
	odev->ppm_ppod_release(ppm, ttinfo.idx);

no_ddp:
	os_log_debug(ISCSI_DBG_DDP,
			"no ddp, itt 0x%x, f 0x%x, xfer %u, ppm 0x%p.\n", 
			sc->sc_itt, sc->sc_fpriv, sc->sc_xfer_len, ppm);
	if (ppm)
		err = cxgbi_ppm_make_non_ddp_tag(ppm, sc->sc_sw_tag,
			&sc->sc_ddp_tag);
	else
		sc->sc_ddp_tag = sc->sc_sw_tag;

	return err;
}

void iscsi_tag_release(chiscsi_scsi_command *sc)
{
	offload_device	*odev = sc->sc_odev;
	struct cxgbi_ppm *ppm = odev ? odev->odev2ppm(odev) : NULL;
	unsigned int idx;

	if ((sc->sc_ddp_tag == ISCSI_INVALID_TAG) ||
	    !ppm || !cxgbi_ppm_is_ddp_tag(ppm, sc->sc_ddp_tag)) {
		return;
	}

	idx = cxgbi_ppm_ddp_tag_get_idx(ppm, sc->sc_ddp_tag);
	odev->ppm_ppod_release(ppm, idx);

	if (scmd_fpriv_test_bit(sc, CH_SFP_BUF_DDP_MAPPED_BIT)) {
		iscsi_socket *isock = sc->sc_sock;
		unsigned int pg_shift =
				ppm->tformat.pgsz_order[isock->s_ddp_pgidx] +
					DDP_PGSZ_BASE_SHIFT;

		scmd_fpriv_clear_bit(sc, CH_SFP_BUF_DDP_MAPPED_BIT);
		ddp_dma_unmap_sgl(ppm->pdev,
				(chiscsi_sgvec *)sc->sc_sgl.sgl_vecs,
				sc->sc_sgl.sgl_vecs_nr, 1 << pg_shift);
	}

	if (odev->ddp_clear_map) 
		odev->ddp_clear_map(sc->sc_odev, idx, &sc->ppod_info);

	sc->sc_odev = NULL;
	sc->sc_ddp_tag = ISCSI_INVALID_TAG;
}
