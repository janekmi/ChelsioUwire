/*
 * iscsi target device -- ramdisk io
 */

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/mm.h>

#include <common/iscsi_common.h>
#include <common/iscsi_target_device.h>
#include <common/os_export.h>

#define MEM_TYPE	"MEM"

extern unsigned int lu_sect_shift;

struct pi_blk_t {
	unsigned short guard;
	unsigned short app_tag;
	unsigned int ref_tag;
};

/*
 * built-in ramdisk support (for measuring network/iscsi protocol performance)
 * - NULLRW mode discard all read/write data
 * - ramdisk memory is organized as a list of kernel pages
 */

#define RAMDISK_SIZE_DFLT_IN_MB		16	/* 16MB */

typedef struct ramdisk ramdisk;
typedef struct rd_pagemap rd_pagemap;

struct rd_pagemap {
	/* os-dependent */
	void   *p_lock;

	/* os-independent */
	unsigned int p_flag;
#define PAGE_FLAG_LOCKED	0x1
	void   *p_page;
	unsigned char *p_addr;
};
#define	RD_PAGEMAP_SIZE		(sizeof(rd_pagemap))

#define rd_pagemap_index(head,i) \
		(rd_pagemap *)( ((unsigned char *)(head)) + (i * (RD_PAGEMAP_SIZE)) )

struct ramdisk {
	unsigned long long d_pgcnt;
	unsigned long long d_size;
	struct ramdisk *rd_pi;
	unsigned char d_pmap[0];
};

static inline void rd_free(ramdisk * rd, int ispi)
{
	int i;

	if (!rd)
		return;

	if (!ispi)
		os_decrement_ramdisk_stats((rd->d_size>>20)*1024);

	for (i = 0; i < rd->d_pgcnt; i++) {
		rd_pagemap *pmap = rd_pagemap_index(rd->d_pmap, i);
		if (pmap->p_lock)
			os_lock(pmap->p_lock);
		if (pmap->p_page)
			os_free_one_page(pmap->p_page);
		if (pmap->p_lock)
			os_unlock(pmap->p_lock);
		if (pmap->p_lock) /* may be called on p_lock alloc failure */
			os_free(pmap->p_lock);
	}
	os_vfree(rd);
}

static inline ramdisk *rd_alloc(unsigned long long size, int alloc, int ispi)
{
	ramdisk *rd;
	unsigned long long i, npages =
		(size + os_page_size - 1) >> os_page_shift;
	unsigned long long alloc_size =
		sizeof(ramdisk) + npages * RD_PAGEMAP_SIZE;
	/* app_tag value 0xffff disables pi check during first read */
	struct pi_blk_t pi_blk = {0, 0xffff, 0};

	if(alloc && !ispi && !os_can_allocate_ramdisk((size>>20)*1024)) {
		return NULL;
	}

	rd = os_vmalloc(alloc_size);
	if (!rd)
		return NULL;

	if (!ispi)
		os_update_ramdisk_stats((size>>20)*1024);

	/* os_alloc and os_alloc_big does memset() */
	rd->d_size = size;

	for (i = 0; i < npages; i++) {
		rd_pagemap *pmap = rd_pagemap_index(rd->d_pmap, i);
		if (!pmap) {
			rd_free(rd, ispi);
			return NULL;
		}
		pmap->p_lock = os_alloc(os_lock_size, 1, 1);
		if (!pmap->p_lock) {
			rd_free(rd, ispi);
			return NULL;
		}
		os_lock_init(pmap->p_lock);
		if (alloc) {
			pmap->p_page = os_alloc_one_page(1, &pmap->p_addr);
			if (!pmap->p_page) {
				rd->d_pgcnt = i;
				rd_free(rd, ispi);
				return NULL;
			}
#if 0
			/* Initialize page with 0xff to prevent
 			 * initial pi check by the adapter. */
			if (ispi) {
				memset(pmap->p_addr, 0xff, os_page_size);
			} else /* for test */
				memset(pmap->p_addr, 0xbb, os_page_size);
#endif
			if (ispi) {
				unsigned int j = 0;
				unsigned int num_pi_in_page =
						(os_page_size >> 3);
				while (j < num_pi_in_page) {
					memcpy((void *)((
					  (struct pi_blk_t *)pmap->p_addr) + j),
					    (void *)&pi_blk, sizeof(pi_blk));
					j++;
					pi_blk.ref_tag++;
				}
			}
		}
	}
	rd->d_pgcnt = i;

	return rd;
}

static void mem_detach(chiscsi_target_lun *lu)
{
	ramdisk *rd = (ramdisk *) lu->priv_data;

	lu->priv_data = NULL;

	if (rd) {
		if (rd->rd_pi) {
			rd_free(rd->rd_pi, 1);
			rd->rd_pi = NULL;
		}
		rd_free(rd, 0);
	}
}

static int mem_config_parse(chiscsi_target_lun *lu, char *buf, int buflen, 
			    char *ebuf)
{
	/* options:
	 * 	- size=xxxMB/GB]
	 * 	- type=1/2/3
	 */
	unsigned int size = 0;
	char *ch = NULL;
	int gb = 0;
	int i;
	unsigned int dif_type = ISCSI_PI_DIF_TYPE_1;

	for (i = 0; i < buflen; ) {
		char *s = buf + i;
		int slen = strlen(s);

		i += slen + 1;
		if (!slen) continue;

		if (!strncmp(s, "size=", 5)) {
			char *unit = s + strlen(s) - 2;
			if (!strcmp(unit, "MB"))
				gb = 0;
			else if (!strcmp(unit, "GB"))
				gb = 1;
			else {
				if (ebuf)
					sprintf(ebuf, "ERR! %s: %s size %s not in MB/GB.\n", MEM_TYPE, lu->path, s);
				os_log_error("%s: %s size %s not in MB/GB.\n", MEM_TYPE, lu->path, s);
				return -ISCSI_EFORMAT;
			}

			*unit = '\0';
			s += 5;
			size = (unsigned int)simple_strtoul(s, &ch, 10);
			if (!size) {
				if (ebuf)
					sprintf(ebuf, "ERR! %s: %s size invalid.\n", MEM_TYPE, lu->path);
				os_log_error("ERR! %s: %s size invalid.\n", MEM_TYPE, lu->path);
				return -ISCSI_EFORMAT;
			}
			if (*ch) {
				if (ebuf)
					sprintf(ebuf, "ERR! %s: invalid decimal digits.\n",
							buf);
				os_log_info("ERR! %s: invalid decimal digits.\n", buf);
				return -ISCSI_EFORMAT;
			}
		} else if (!strncmp(s, "type=", 5)) {
			ch = NULL;
			s += 5;
			dif_type = (unsigned int)simple_strtoul(s, &ch, 10);
			if (dif_type != ISCSI_PI_DIF_TYPE_1 &&
			    dif_type != ISCSI_PI_DIF_TYPE_2 &&
			    dif_type != ISCSI_PI_DIF_TYPE_3) {
				if (ebuf)
					sprintf(ebuf, "ERR! invalid dif type %u.\n",
							dif_type);
				os_log_error("%s: Invalid dif type %d, "
					"must be betw 1-3\n", __func__,
					dif_type);
				return -ISCSI_EFORMAT;
			}
		} else {

			if (ebuf)
				sprintf(ebuf, "%s: Unknown option %s.\n", MEM_TYPE, s);
			os_log_error("%s: Unknown option %s.\n", MEM_TYPE, s);
			return -ISCSI_EFORMAT;
		}
		/* add option for crc or ip checksum? TODO */
	}

	if (chiscsi_target_lun_flag_test(lu, LUN_T10DIX_BIT)) {
		lu->dif_type = dif_type;
		os_log_info("T10-DIF/DIX type %u set on lun %s\n",
			dif_type, lu->path);
	}
	lu->size = size;
	if (gb)
		lu->size <<= 10; /* GB -> MB */

	return 0;
}

static inline void mem_size_mb_to_byte(chiscsi_target_lun *lu)
{
	if (!lu->size)
		lu->size = RAMDISK_SIZE_DFLT_IN_MB;
	lu->size <<= 20; /* MB -> byte */
}

static inline int mem_scsi_cmd_t10dix_enabled(struct chiscsi_target_lun *lu,
			chiscsi_scsi_command *sc)
{
	return (sc->sc_flag & SC_FLAG_T10DIX);
}

static int mem_scsi_fill_pi_info(struct chiscsi_target_lun *lu,
			chiscsi_scsi_command *sc)
{
	if (sc->sc_flag & SC_FLAG_READ) {
		if (sc->sc_flag & SC_FLAG_T10DIF)
			sc->pi_info.prot_op = ISCSI_PI_OP_SCSI_PROT_WRITE_PASS;
		else
			sc->pi_info.prot_op = ISCSI_PI_OP_SCSI_PROT_WRITE_STRIP;
	} else if (sc->sc_flag & SC_FLAG_WRITE) {
		if (sc->sc_flag & SC_FLAG_T10DIF)
			sc->pi_info.prot_op = ISCSI_PI_OP_SCSI_PROT_READ_PASS;
		else
			sc->pi_info.prot_op = ISCSI_PI_OP_SCSI_PROT_READ_INSERT;
	}

	sc->pi_info.dif_type = lu->dif_type;
	sc->pi_info.guard = lu->prot_guard;
	sc->pi_info.interval = (lu_sect_shift==12)?\
		ISCSI_SCSI_PI_INTERVAL_4K:ISCSI_SCSI_PI_INTERVAL_512;

 	/* sc->pi_info.pi_len = pi_sgl->sgl_length? */

	return 0;
}

static int mem_attach(chiscsi_target_lun *lu, char *ebuf, int ebuflen)
{
	ramdisk *rd = (ramdisk *)lu->priv_data;

	mem_size_mb_to_byte(lu);
	rd = rd_alloc(lu->size, 1, 0);
	if (!rd) {
		if (ebuf)
			sprintf(ebuf + strlen(ebuf),
				"%s %s, Out of memory.\n", MEM_TYPE, lu->path);
		return -ISCSI_ENOMEM;
	}
	rd->rd_pi = NULL;
	lu->priv_data = (void *) rd;
	if (chiscsi_target_lun_flag_test(lu, LUN_T10DIX_BIT)) {
		unsigned long long pi_mem_size = (lu->size >> lu_sect_shift) << 3;
		rd->rd_pi = rd_alloc(pi_mem_size, 1, 1);
		if (!rd->rd_pi) {
			os_log_error(
			   "%s: pi pages allocation failed, size %llu.\n",
			 	MEM_TYPE, pi_mem_size);
			if (ebuf)
				sprintf(ebuf + strlen(ebuf),
				  "%s %s, pi alloc out of memory.\n",
				  MEM_TYPE, lu->path);
			lu->dif_type = ISCSI_PI_DIF_TYPE_0;
			goto out;
		}
		/* integrity type is set from config file. */
		lu->prot_guard = ISCSI_PI_GUARD_TYPE_CRC;
	}
out:
	return 0;
}

static int mem_reattach(chiscsi_target_lun *lu, chiscsi_target_lun *new_lu,
			char *ebuf, int ebuflen)
{
	unsigned long long i, npages_reuse;
	ramdisk *rd_old = (ramdisk *)lu->priv_data;
	ramdisk *rd;

	mem_size_mb_to_byte(new_lu);

	rd = rd_alloc(new_lu->size, 0, 0);
	if (!rd) {
		if (ebuf)
			sprintf(ebuf + strlen(ebuf),
				"%s %s, Out of memory.\n", MEM_TYPE, lu->path);
		return -ISCSI_ENOMEM;
	}
	rd->rd_pi = NULL;
	/* T10DIF TODO move following in a function */
	/* reuse the pages */
	npages_reuse = (rd->d_pgcnt < rd_old->d_pgcnt) ? 
			rd->d_pgcnt : rd_old->d_pgcnt;

	for (i = 0; i < npages_reuse; i++) {
		rd_pagemap *pmap_old = rd_pagemap_index(rd_old->d_pmap, i);
		rd_pagemap *pmap = rd_pagemap_index(rd->d_pmap, i);

		pmap->p_page = pmap_old->p_page;
		pmap->p_addr = pmap_old->p_addr;
		get_page(pmap->p_page);
	}

	for (; i < rd->d_pgcnt; i++) {
		rd_pagemap *pmap = rd_pagemap_index(rd->d_pmap, i);
		pmap->p_page = os_alloc_one_page(1, &pmap->p_addr);
		if (!pmap->p_page) {
			rd->d_pgcnt = i;
			rd_free(rd, 0);
			return -ISCSI_ENOMEM;
		}
	}

	new_lu->priv_data = (void *)rd;

	if (chiscsi_target_lun_flag_test(lu, LUN_T10DIX_BIT)) {
		unsigned long long old_pi_mem_size = (lu->size >> lu_sect_shift) << 3;
		unsigned long long new_pi_mem_size = (new_lu->size >> lu_sect_shift) << 3;
		ramdisk *lu_rd = rd;

		os_log_info("%s: realloc pi memory old_pi_mem_size %u, "
			"new_pi_mem_size %u\n", __func__, old_pi_mem_size,
			new_pi_mem_size);

		rd = rd->rd_pi;
		rd_old = rd_old->rd_pi;

		rd = rd_alloc(new_pi_mem_size, 0, 1);
		if (!rd) {
			os_log_error(
			   "%s: pi pages allocation failed, size %llu.\n",
			 	MEM_TYPE, new_pi_mem_size);
			goto out;
		}
		/* T10DIF TODO move following in a function */
		/* reuse the pi pages */
		npages_reuse = (rd->d_pgcnt < rd_old->d_pgcnt) ?
			rd->d_pgcnt : rd_old->d_pgcnt;

		for (i = 0; i < npages_reuse; i++) {
			rd_pagemap *pmap_old = rd_pagemap_index(rd_old->d_pmap, i);
			rd_pagemap *pmap = rd_pagemap_index(rd->d_pmap, i);

			pmap->p_page = pmap_old->p_page;
			pmap->p_addr = pmap_old->p_addr;
			get_page(pmap->p_page);
		}

		for (; i < rd->d_pgcnt; i++) {
			rd_pagemap *pmap = rd_pagemap_index(rd->d_pmap, i);
			pmap->p_page = os_alloc_one_page(1, &pmap->p_addr);
			if (!pmap->p_page) {
				rd->d_pgcnt = i;
				rd_free(rd, 1);
				lu_rd->rd_pi = NULL;
				lu->dif_type = ISCSI_PI_DIF_TYPE_0;
				goto out;
			}
		}
	}
out:
	return 0;
}

#if 0
int iscsi_display_byte_string(char *caption, unsigned char *bytes, int start,
			      int maxlen, char *obuf, int obuflen);
#endif

static void mem_scmd_execute(chiscsi_scsi_command *sc)
{
	chiscsi_target_lun *lu = iscsi_target_session_lun_get(sc->sc_sess,
							sc->sc_lun_acl);
	ramdisk *rd;
	chiscsi_sgl *sc_sgl = &sc->lsc_sc_sgl;
	chiscsi_sgvec *sgl = (chiscsi_sgvec *)sc_sgl->sgl_vecs;
	chiscsi_sgvec *pi_sgl = (chiscsi_sgvec *)sc->lsc_sc_protsgl.sgl_vecs;
	unsigned int sgcnt = sc_sgl->sgl_vecs_nr;
	unsigned int pi_sgcnt = sc->lsc_sc_protsgl.sgl_vecs_nr;
	unsigned long long pos;
	unsigned long long pidx;
	unsigned long poffset;
	unsigned long long pi_pos, pi_pidx;
	unsigned long pi_poffset;
	int read = (sc->sc_flag & SC_FLAG_READ) ? 1 : 0;
	int i;
	int data_len = 0, pi_len = 0;

	os_log_debug(ISCSI_DBG_SCSI, "%s: is read %u, sgcnt %u, sc_xfer_len %u, sc_lba 0x%x\n",
		__func__, read, sgcnt, sc->sc_xfer_len, sc->sc_lba);

	if (!lu || !lu->priv_data) {
		os_log_error("MEM, bad lun %d, lu 0x%p, fp 0x%p, sess 0x%p, itt 0x%x.\n", sc->sc_lun, lu, lu ? lu->priv_data : NULL, sc->sc_sess, sc->sc_itt);
		chiscsi_scsi_command_target_failure(sc);
		goto done;
	}

	if (!(rd = (ramdisk *)lu->priv_data)) {
		chiscsi_scsi_command_target_failure(sc);
		goto done;
	}

        /* Check Condition  Already Set - We wont process this */
        if (sc->sc_status == 0x02)
                goto done;

	pos = sc->sc_lba << lu_sect_shift;
	pidx = pos >> os_page_shift;
	poffset = pos & (~os_page_mask);

	pi_pos = (pos >> lu_sect_shift) << 3;
	pi_pidx = pi_pos >> os_page_shift;
	pi_poffset = pi_pos & (~os_page_mask);

#if 0
	os_log_info("%s: pos %llu, pidx %llu, poffset %u, "
		"pi_pos %llu, pi_pidx %llu, pi_poffset %u, "
		"pi_sgcnt %u\n",
		__func__, pos, pidx, poffset, pi_pos,
		pi_pidx, pi_poffset, pi_sgcnt);
#endif

	if (pidx >= rd->d_pgcnt ||
	    (pidx + sgcnt) > rd->d_pgcnt) {
		os_log_warn("%s, %s, rw beyond limit, pos %llu, pgidx %llu + %u >= %llu.\n",
			    MEM_TYPE, lu->path, pos, pidx, sgcnt, rd->d_pgcnt);
		if (read)
			chiscsi_scsi_command_read_error(sc);
		else
			chiscsi_scsi_command_write_error(sc);
		goto done;
        }

	if (!sc->sc_xfer_len || 
	    chiscsi_target_lun_flag_test(lu, LUN_NULLRW_BIT))
		goto done;

	if (sc->sc_flag & SC_FLAG_ABORT) {
		os_log_info("%s: sc 0x%p, itt 0x%x, f 0x%x, abort.\n",
			__func__, sc, sc->sc_itt, sc->sc_flag);
		goto done;
	}

	for (i = 0; i < sgcnt; i++, pidx++, sgl++) {
		rd_pagemap *pmap = rd_pagemap_index(rd->d_pmap, pidx);

		os_lock(pmap->p_lock);
		if (read)
			memcpy(sgl->sg_addr, pmap->p_addr + poffset,
			       sgl->sg_length);
		else 
			memcpy(pmap->p_addr + poffset, sgl->sg_addr,
			       sgl->sg_length);
#if 0
		if (!read) {
			iscsi_display_byte_string("copied data",
				pmap->p_addr + poffset,
				0, sgl->sg_length, NULL, 0);
		}
#endif

		data_len += sgl->sg_length;
		if (poffset) poffset = 0;
		os_unlock(pmap->p_lock);
	}

	/* Copy corresponding pi bytes */
	if (chiscsi_target_lun_flag_test(lu, LUN_T10DIX_BIT) &&
	    mem_scsi_cmd_t10dix_enabled(lu, sc)) {
		unsigned int pmap_pglen, pmap_pgoff;
		unsigned int pi_sgllen, pi_sgloff, copy;

		rd = rd->rd_pi;

		if (pi_pidx >= rd->d_pgcnt ||
		    (pi_pidx + pi_sgcnt) > rd->d_pgcnt) {
			os_log_error("%s %s, pi rw beyond limit, pos %llu, "
			  "pi_pos %llu, pi_pidx %llu + %u >= %llu.\n",
				MEM_TYPE, lu->path, pos, pi_pos, pi_pidx,
				pi_sgcnt, rd->d_pgcnt);
			/* Should not happen. Debug code */
			goto done;
		}

		pmap_pglen = os_page_size - pi_poffset;
		pmap_pgoff = pi_poffset;
		pi_sgllen = pi_sgl->sg_length;
		pi_sgloff = 0;

		for (i = 0; i < pi_sgcnt;) {
			rd_pagemap *pmap = rd_pagemap_index(rd->d_pmap, pi_pidx);
			copy = MINIMUM(pmap_pglen, pi_sgllen);

#if 0
			os_log_info("%s: i %u, pi_pidx %u, pi_poffset %u, "
			  "pmap_pglen %u, pmap_pgoff %u, pi_sgllen %u, "
			  "pi_sgcnt %u, copy %u, pi_sgl->sg_addr 0x%p, "
			  "read %u\n",
			  __func__,
			  i, pi_pidx, pi_poffset, pmap_pglen, pmap_pgoff,
			  pi_sgllen, pi_sgcnt, copy, pi_sgl->sg_addr, read);
#endif

			os_lock(pmap->p_lock);
			if (read)
				memcpy(pi_sgl->sg_addr + pi_sgloff,
					pmap->p_addr + pmap_pgoff, copy);
			else
				memcpy(pmap->p_addr + pmap_pgoff,
					pi_sgl->sg_addr + pi_sgloff, copy);
			pmap_pglen -= copy;
			if (!pmap_pglen) {
				pi_pidx++;
				pmap_pglen = os_page_size;
				pmap_pgoff = 0;
			} else
				pmap_pgoff += copy;

			pi_sgllen -= copy;
			if (!pi_sgllen) {
				pi_sgl++;
				pi_sgllen = pi_sgl->sg_length;
				pi_sgloff = 0;
				i++;
			} else
				pi_sgloff += copy;

			pi_len += copy;
			os_unlock(pmap->p_lock);
		}
	}
	os_log_debug(ISCSI_DBG_SCSI, "%s: sc_lba 0x%x, data_len %u, pi_len %u\n",
		__func__, sc->sc_lba, data_len, pi_len);
done:
	if (lu)
		iscsi_target_session_lun_put(lu);
	if (sc->sc_flag & SC_FLAG_WRITE) {
		os_lun_scmd_memory_free_by_page(sc_sgl);
		os_lun_pi_memory_release(sc);
	}
	if (!sc->sc_xfer_len && sc_sgl->sgl_vecs) {
                os_lun_scmd_memory_free_by_page(sc_sgl);
		os_lun_pi_memory_release(sc);
	}
	chiscsi_scsi_cmd_execution_status(sc, sc_sgl->sgl_vecs,
					sc_sgl->sgl_vecs_nr,
					sc_sgl->sgl_boff, sc_sgl->sgl_length);
}

static int mem_scsi_cmd_cdb_rcved(chiscsi_scsi_command *sc)
{
	chiscsi_sgl *sc_sgl = &sc->lsc_sc_sgl;
	int rv;

	/* one-shot allocation, just save it in lsc->sc_sgl */
	rv = os_lun_scmd_memory_alloc_by_page(sc, sc_sgl);
	if (rv < 0)
		return rv;

	if ((sc->sc_flag & SC_FLAG_READ) || (sc->sc_flag & SC_FLAG_WRITE)) {
		chiscsi_target_lun *lu = iscsi_target_session_lun_get(sc->sc_sess,
							sc->sc_lun_acl);
		if (lu && chiscsi_target_lun_flag_test(lu, LUN_T10DIX_BIT) &&
	    	    mem_scsi_cmd_t10dix_enabled(lu, sc)) {
			chiscsi_sgl *pi_sgl = &sc->lsc_sc_protsgl;

			rv = os_lun_pi_memory_alloc_by_pages(sc, pi_sgl);
			if (rv < 0) {
				os_log_info("%s: sc 0x%p itt 0x%x, f 0x%x, "
					"xfer %u, PI ENOMEM %d.\n",
					__func__, sc, sc->sc_itt, sc->sc_flag,
					sc->sc_xfer_len, rv);
			}
			mem_scsi_fill_pi_info(lu, sc);
		}
		iscsi_target_session_lun_put(lu);
	}

	if (sc->sc_flag & SC_FLAG_READ) {
		mem_scmd_execute(sc);
	} else {
		chiscsi_scsi_cmd_buffer_ready(sc, sc_sgl->sgl_vecs,
					sc_sgl->sgl_vecs_nr, sc_sgl->sgl_boff,
					sc_sgl->sgl_length);
	}
	return 0;
}

static void mem_scsi_cmd_data_xfer_status(chiscsi_scsi_command *sc,
				unsigned char *xfer_sreq_buf,
				unsigned int xfer_sgcnt,
				unsigned int xfer_offset,
				unsigned int xfer_buflen)
{
	chiscsi_sgl *sc_sgl = &sc->lsc_sc_sgl;

#if 0
	os_log_info("%s: sc 0x%p, xfer_sgcnt %u, xfer_offset %u, "
		"xfer_buflen %u, sc->sc_flag 0x%x, sc_sgl->sgl_vecs %u, "
		"sc_sgl->sgl_vecs_nr %u, sc->sc_lba 0x%x\n",
		__func__, sc, xfer_sgcnt, xfer_offset, xfer_buflen,
		sc->sc_flag, sc_sgl->sgl_vecs, sc_sgl->sgl_vecs_nr,
		sc->sc_lba);
#endif

	if (sc_sgl->sgl_vecs != xfer_sreq_buf ||
	    sc_sgl->sgl_vecs_nr != xfer_sgcnt ||
	    sc_sgl->sgl_boff != xfer_offset ||
	    sc_sgl->sgl_length != xfer_buflen) {
		os_log_warn("%s: itt 0x%x, SGL mismatch: 0x%p/0x%p, %u/%u, %u/%u+%u/%u.\n",
			__func__, sc->sc_itt, sc_sgl->sgl_vecs, xfer_sreq_buf,
			sc_sgl->sgl_vecs_nr, xfer_sgcnt, sc_sgl->sgl_boff,
			xfer_offset, sc_sgl->sgl_length, xfer_buflen);
	}

	if (sc->sc_flag & SC_FLAG_ABORT) {
		os_log_info("%s: sc 0x%p, itt 0x%x, f 0x%x, abort.\n",
			__func__, sc, sc->sc_itt, sc->sc_flag);
		os_lun_scmd_memory_free_by_page(sc_sgl);
		scmd_fscsi_clear_bit(sc, CH_SFSCSI_HOLD_BIT);
		return;
	}

	if (sc->sc_flag & SC_FLAG_READ) {
		os_lun_scmd_memory_free_by_page(sc_sgl);
		os_lun_pi_memory_release(sc);
	} else
		/* write: all data received */
		mem_scmd_execute(sc);
}

static int mem_scsi_cmd_abort(chiscsi_scsi_command *sc)
{
	scmd_fscsi_clear_bit(sc, CH_SFSCSI_HOLD_BIT);
	return 0;
}

static int mem_tmf_execute(unsigned long sess_hndl, unsigned long tmf_hndl,
			 unsigned char immediate_cmd, unsigned char tmf_func,
			 unsigned int lun, chiscsi_scsi_command *sc)
{
	return 0;
}

chiscsi_target_lun_class lun_class_mem = {
	.property = 1 << LUN_CLASS_DUP_PATH_ALLOWED_BIT,
	.class_name = MEM_TYPE,
	.fp_config_parse_options = mem_config_parse,
	.fp_attach = mem_attach,
	.fp_reattach = mem_reattach,
	.fp_detach = mem_detach,
	.fp_scsi_cmd_cdb_rcved = mem_scsi_cmd_cdb_rcved,
	.fp_scsi_cmd_data_xfer_status = mem_scsi_cmd_data_xfer_status,
	.fp_scsi_cmd_cleanup = os_lun_scsi_cmd_memory_release,
	.fp_scsi_cmd_abort = mem_scsi_cmd_abort,
	.fp_tmf_execute = mem_tmf_execute
};
