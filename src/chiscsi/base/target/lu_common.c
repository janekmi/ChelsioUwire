#include <linux/version.h>
#include <linux/kernel.h>
#ifdef KERNEL_HAS_EXPORT_H
#include <linux/export.h>
#endif
#include <linux/mm.h>
#include <linux/pci.h>
#include <common/iscsi_socket.h>
#include <common/cxgb_dev.h>

#include <common/iscsi_common.h>
#include <common/iscsi_target_device.h>
#include <common/os_export.h>

extern struct page *rsvd_pages[];
extern unsigned char *rsvd_pages_addr[];
extern unsigned int lu_sect_shift;

/*
 * scsi command memory buffer allocation & release
 */
static void free_kernel_pages(chiscsi_sgvec *sgl, unsigned int cnt)
{
	int i;

	for (i = 0; i < cnt; i++)
		if (!(sgl[i].sg_flag & CHISCSI_SG_SBUF_SHARE))
			os_free_one_page(sgl[i].sg_page);
}

static void free_kernel_pages_dma(chiscsi_sgvec *sgl, unsigned int cnt)
{
	int i;
	chiscsi_sgvec *sg = sgl;

	for (i = 0; i < cnt; i++, sg++) {
		if (!sg->sg_page)
			break;
		if (sg->sg_dma_addr)
			pci_unmap_page((struct pci_dev *)sg->sg_private[0],
				sg->sg_dma_addr - sg->sg_offset,
				PAGE_SIZE,
				(sg->sg_flag & CHISCSI_SG_SBUF_DMA_READ) ?
					PCI_DMA_TODEVICE : PCI_DMA_FROMDEVICE);

		os_free_one_page(sg->sg_page);
	}
	memset(sgl, 0, sizeof(chiscsi_sgvec) * cnt);
}

void os_lun_scmd_memory_free_by_page(chiscsi_sgl *sc_sgl)
{
	chiscsi_sgvec *sgl = (chiscsi_sgvec *)sc_sgl->sgl_vecs;
	unsigned int sgcnt = sc_sgl->sgl_vecs_nr;

	if (!sgcnt) {
		os_free(sgl);
	} else if (sgl) {
		if (sgl->sg_flag & CHISCSI_SG_SBUF_DMABLE)
			free_kernel_pages_dma(sgl, sgcnt);
		else
			free_kernel_pages(sgl, sgcnt);
		os_free(sgl);
	}
	sc_sgl->sgl_vecs_nr = 0;
	sc_sgl->sgl_vecs = NULL;
	sc_sgl->sgl_vec_last = NULL;
}

static int alloc_kernel_pages(chiscsi_sgvec *sgl, unsigned int nr_pages,
				 int shared)
{
	int i;
	chiscsi_sgvec *sg = sgl;

	if (shared) {
		for (i = 0; i < nr_pages; i++, sg++) {
			sg->sg_page = rsvd_pages[1];
			sg->sg_addr = rsvd_pages_addr[1];
			sg->sg_offset = 0;
			sg->sg_length = PAGE_SIZE;
			sg->sg_next = sg + 1;
			sg->sg_flag = CHISCSI_SG_SBUF_SHARE;
		}
	} else {
		for (i = 0; i < nr_pages; i++, sg++) {
			sg->sg_page = os_alloc_one_page(1, &sg->sg_addr);
			if (!sg->sg_page)
				/* yield() */
				return i;
			sg->sg_offset = 0;
			sg->sg_length = PAGE_SIZE;
			sg->sg_next = sg + 1;
		}
	}
	sgl[nr_pages -1].sg_next = NULL;

	return i;
}

#ifdef __TEST_PREMAPPED_SKB__
static int alloc_kernel_pages_dma(offload_device *odev, chiscsi_sgvec *sgl,
				unsigned int nr_pages, int read)
{
	int i;
	chiscsi_sgvec *sg = sgl;
	struct pci_dev *pdev = (struct pci_dev *)odev->d_pdev;

	for (i = 0; i < nr_pages; i++, sg++) {
		struct page *pg = os_alloc_one_page(1, &sg->sg_addr);

		if (!pg)
			return i;

		sg->sg_dma_addr = pci_map_page(pdev, pg, 0, PAGE_SIZE,
					read ? PCI_DMA_TODEVICE :
						PCI_DMA_FROMDEVICE);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
                if (unlikely(pci_dma_mapping_error(pdev, sg->sg_dma_addr)))
#else
                if (unlikely(pci_dma_mapping_error(sg->sg_dma_addr)))
#endif
			goto err_out;

		sg->sg_page = pg;
		sg->sg_flag = CHISCSI_SG_SBUF_DMABLE | CHISCSI_SG_SBUF_DMA_ONLY;
		if (read)
			sg->sg_flag |= CHISCSI_SG_SBUF_DMA_READ;
		sg->sg_offset = 0;
		sg->sg_length = PAGE_SIZE;
		sg->sg_next = sg + 1;
		sg->sg_private[0] = (unsigned long)pdev;
	}

	sgl[nr_pages -1].sg_next = NULL;

	return i;

err_out:
	free_kernel_pages_dma(sgl, nr_pages);
	return 0;
}
#endif

int os_lun_scmd_memory_alloc_by_page(chiscsi_scsi_command *sc, chiscsi_sgl *sc_sgl)
{
#ifdef __TEST_PREMAPPED_SKB__
	iscsi_socket *isock = (iscsi_socket *)sc->sc_sock;
	struct offload_device *odev = isock->s_odev;
#endif
	unsigned int len, off = 0, nr_pages;
	unsigned long sglen = 0UL;
	chiscsi_sgvec *sgl;
	int shared = scmd_fpriv_test_bit(sc, CH_SFP_CHLU_SINK_BIT) ? 1:0;
	int err;

	/* allocation in one-shot */
	if ((sc->sc_flag & SC_FLAG_PASSTHRU) ||
            (scmd_fpriv_test_bit(sc, CH_SFP_LU_PASSTHRU_BIT)))
		len = sc->sc_xfer_len;
	else
		len = sc->sc_blk_cnt << lu_sect_shift;

#ifdef __TEST_PREMAPPED_SKB__
	if ((sc->sc_flag & SC_FLAG_READ) && odev && odev->d_pdev) {
		len = sc->sc_xfer_len;
		nr_pages = (len + PAGE_SIZE - 1) >> PAGE_SHIFT;
		sglen = nr_pages << PAGE_SHIFT;
	} else
#endif
	{
		if (!(sc->sc_flag & SC_FLAG_PASSTHRU) &&
            	    !(scmd_fpriv_test_bit(sc, CH_SFP_LU_PASSTHRU_BIT))) {
			loff_t ppos = sc->sc_lba << lu_sect_shift;
			off = ppos & (~PAGE_MASK);
		}
		nr_pages = (len + off + PAGE_SIZE - 1) >> PAGE_SHIFT;
		sglen = nr_pages << PAGE_SHIFT;
	}

	/* No need to allocate if nr_pages is zero */	
	if (nr_pages == 0)
		return 0;

	sgl = os_alloc(sizeof(chiscsi_sgvec) * nr_pages, 1, 1);
	if (!sgl)
		return -ISCSI_ENOMEM;
	sc_sgl->sgl_vecs = (void *)sgl;
	sc_sgl->sgl_vec_last = sgl + nr_pages - 1;
	sc_sgl->sgl_vecs_nr = nr_pages;

#ifdef __TEST_PREMAPPED_SKB__
	if (odev && odev->d_pdev) {
		err = alloc_kernel_pages_dma(odev, sgl, nr_pages,
					sc->sc_flag & SC_FLAG_READ);
	} else
#endif
		err = alloc_kernel_pages(sgl, nr_pages, shared);

	if (err < nr_pages) {
		if (err) {
			sc_sgl->sgl_vecs_nr = err - 1;
			os_lun_scmd_memory_free_by_page(sc_sgl);
		}
		return -ISCSI_ENOMEM;
	}

	if (off) {
		sgl->sg_offset = off;
		sgl->sg_length -= off;
		sgl->sg_addr += off;
		sglen -= off;

		if (sgl->sg_dma_addr)
			sgl->sg_dma_addr += off;
	}
        if (sglen > len)
		sgl[nr_pages - 1].sg_length -= sglen - len;

	sc_sgl->sgl_length = len;

	return 0;
}

int os_lun_pi_memory_alloc_by_pages(chiscsi_scsi_command *sc, chiscsi_sgl *pi_sgl)
{
#ifdef __TEST_PREMAPPED_SKB__
	iscsi_socket *isock = (iscsi_socket *)sc->sc_sock;
	struct offload_device *odev = isock->s_odev;
#endif
	chiscsi_sgvec *sgl;
	unsigned int dlen, pi_len, nr_pages;
	unsigned long sglen = 0UL;
	int shared = scmd_fpriv_test_bit(sc, CH_SFP_CHLU_SINK_BIT) ? 1:0;
	int err, off = 0;

	if ((sc->sc_flag & SC_FLAG_PASSTHRU) ||
            (scmd_fpriv_test_bit(sc, CH_SFP_LU_PASSTHRU_BIT))) 
		dlen = sc->sc_xfer_len;
	else 
		dlen = sc->sc_blk_cnt << lu_sect_shift;

	pi_len = (dlen >> lu_sect_shift) << 3;

#ifdef __TEST_PREMAPPED_SKB__
	if ((sc->sc_flag & SC_FLAG_READ) && odev && odev->d_pdev) {
		dlen = sc->sc_xfer_len;
		nr_pages = (pi_len + PAGE_SIZE - 1) >> PAGE_SHIFT;
		sglen = nr_pages << PAGE_SHIFT;
	} else
#endif
	{
		if (!(sc->sc_flag & SC_FLAG_PASSTHRU) &&
            	    !(scmd_fpriv_test_bit(sc, CH_SFP_LU_PASSTHRU_BIT))) {
			off = pi_len & (~PAGE_MASK);
		}
		nr_pages = (pi_len + PAGE_SIZE - 1) >> PAGE_SHIFT;
		sglen = nr_pages << PAGE_SHIFT;
	}

	os_log_debug(ISCSI_DBG_SCSI, "%s: sc 0x%p,  sc->sc_lba 0x%x, "
		"pi_len %u, nr_pages %u, "
		"sglen %u, off %u, dlen %u, sc_blk_cnt %u\n",
		__func__, sc,  sc->sc_lba, pi_len, nr_pages, sglen, off,
		dlen, sc->sc_blk_cnt);

	if (nr_pages == 0)
		return 0;

	sgl = os_alloc(sizeof(chiscsi_sgvec) * nr_pages, 1, 1);
	if (!sgl)
		return -ISCSI_ENOMEM;

	pi_sgl->sgl_vecs = (void *) sgl;
	pi_sgl->sgl_vec_last = sgl + nr_pages - 1;
	pi_sgl->sgl_vecs_nr = nr_pages;

#ifdef __TEST_PREMAPPED_SKB__
	if (odev && odev->d_pdev) {
		os_log_warn("%s: f 0x%x, itt 0x%x, xfer %u, pi pages %u.\n",
			__func__, sc->sc_flag, sc->sc_itt, sc->sc_xfer_len, nr_pages);
		err = alloc_kernel_pages_dma(odev, sgl, nr_pages,
					sc->sc_flag & SC_FLAG_READ);
	} else
#endif
		err = alloc_kernel_pages(sgl, nr_pages, shared);

	if (err < nr_pages) {
		if (err) {
			pi_sgl->sgl_vecs_nr = err - 1;
			os_lun_scmd_memory_free_by_page(pi_sgl);
		}
		return -ISCSI_ENOMEM;
	}
	if (off) {
		sgl->sg_offset = PAGE_SIZE - off;
		sgl->sg_length = off;
		sgl->sg_addr += sgl->sg_offset;
		sglen -= off;

		if (sgl->sg_dma_addr)
			sgl->sg_dma_addr += sgl->sg_offset;
	}
#if 0
	/* Only for debugging. */
	memset(sgl->sg_addr, 0x2, sgl->sg_length);
#endif
	pi_sgl->sgl_length = pi_len;
	return 0;
}

void os_lun_pi_memory_release(chiscsi_scsi_command *sc)
{
	if (sc->lsc_sc_protsgl.sgl_vecs_nr || sc->lsc_sc_protsgl.sgl_vecs)
		os_lun_scmd_memory_free_by_page(&sc->lsc_sc_protsgl);

	memset(&sc->lsc_sc_protsgl, 0, sizeof(struct chiscsi_sgl));
}

void os_lun_scsi_cmd_memory_release(chiscsi_scsi_command *sc)
{
	if (sc->lsc_sc_sgl.sgl_vecs_nr || sc->lsc_sc_sgl.sgl_vecs)
		os_lun_scmd_memory_free_by_page(&sc->lsc_sc_sgl);

	os_lun_pi_memory_release(sc);
}

EXPORT_SYMBOL(chiscsi_target_class_register);
EXPORT_SYMBOL(chiscsi_target_class_deregister);
EXPORT_SYMBOL(chiscsi_target_session_abort);
EXPORT_SYMBOL(chiscsi_target_first_login_check_done);
EXPORT_SYMBOL(chiscsi_target_login_stage_check_done);
EXPORT_SYMBOL(chiscsi_target_lun_class_register);
EXPORT_SYMBOL(chiscsi_target_lun_class_deregister);
EXPORT_SYMBOL(chiscsi_scsi_cmd_buffer_ready);
EXPORT_SYMBOL(chiscsi_scsi_cmd_execution_status);
EXPORT_SYMBOL(chiscsi_scsi_cmd_ready_to_release);
EXPORT_SYMBOL(chiscsi_tmf_execution_done);
EXPORT_SYMBOL(chiscsi_scsi_cmd_abort);
EXPORT_SYMBOL(chiscsi_scsi_cmd_abort_status);
EXPORT_SYMBOL(chiscsi_target_add);
EXPORT_SYMBOL(chiscsi_target_remove);
EXPORT_SYMBOL(chiscsi_target_reconfig);
EXPORT_SYMBOL(chiscsi_get_session_info);
EXPORT_SYMBOL(chiscsi_get_one_session_info);
EXPORT_SYMBOL(chiscsi_get_perf_info);
EXPORT_SYMBOL(chiscsi_get_connection_info);
EXPORT_SYMBOL(chiscsi_get_target_info);
EXPORT_SYMBOL(chiscsi_iscsi_command_dump);
EXPORT_SYMBOL(chiscsi_session_settings_sprintf);
EXPORT_SYMBOL(chiscsi_conn_settings_sprintf);
EXPORT_SYMBOL(chiscsi_chap_settings_sprintf);
EXPORT_SYMBOL(chiscsi_target_config_settings_sprintf);
EXPORT_SYMBOL(chiscsi_target_info_sprintf);
EXPORT_SYMBOL(chiscsi_perf_info_sprintf);
EXPORT_SYMBOL(chiscsi_session_info_sprintf);
EXPORT_SYMBOL(chiscsi_connection_info_sprintf);
EXPORT_SYMBOL(chiscsi_portal_info_sprintf);
