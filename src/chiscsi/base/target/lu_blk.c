/*
 * iscsi target device -- block io 
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/uio.h>
#include <scsi/scsi.h>
#include <linux/blkdev.h>
#include <linux/writeback.h>
#include <linux/buffer_head.h>

#include <common/iscsi_common.h>
#include <common/iscsi_target_device.h>
#include <common/os_export.h>
#include <kernel/linux_compat.h>

#define BLK_TYPE	"BLK"

extern unsigned int lu_sect_shift;

struct blk_io_context {
	unsigned int flags;
#define BIOC_FLAG_WAIT_COMPL	0x1
#define BIOC_FLAG_COMPL		0x2
#define BIOC_FLAG_TMF		0x4
	spinlock_t lock;
	chiscsi_scsi_command *sc;
	chiscsi_sgl sc_sgl;
	chiscsi_sgl sc_pi_sgl;
	unsigned int itt;
	atomic_t err;	
	atomic_t count;
	struct completion tio_complete;
};

void vfs_detach(chiscsi_target_lun *lu);
int vfs_attach(chiscsi_target_lun *lu, char *ebuf, int ebuflen);
int vfs_reattach(chiscsi_target_lun *old, chiscsi_target_lun *new,
                        char *ebuf, int ebuflen);

static inline struct block_device *lu_get_bdev(chiscsi_target_lun *lu)
{
	struct file *fp = (struct file *)lu->priv_data;
	return ((struct inode *)fp->f_mapping->host)->i_bdev;
}

#if defined(CONFIG_BLK_DEV_INTEGRITY)
static inline int blk_set_integrity_type(chiscsi_target_lun *lu)
{
	unsigned int dif_type = ISCSI_PI_DIF_TYPE_0;
	unsigned int guard = ISCSI_PI_GUARD_TYPE_IP;
	struct block_device *bdev;
	struct blk_integrity *bi;

	if (lu && chiscsi_target_lun_flag_test(lu, LUN_T10DIX_BIT)) {
		bdev = lu_get_bdev(lu);

		if (bdev && (bi = bdev_get_integrity(bdev))) {
			if (!strcmp(bi->name, "T10-DIF-TYPE1-IP")) {
				dif_type = ISCSI_PI_DIF_TYPE_1;
				guard = ISCSI_PI_GUARD_TYPE_IP;
			} else if (!strcmp(bi->name, "T10-DIF-TYPE2-IP")) {
				dif_type = ISCSI_PI_DIF_TYPE_2;
				guard = ISCSI_PI_GUARD_TYPE_IP;
			} else if (!strcmp(bi->name, "T10-DIF-TYPE3-IP")) {
				dif_type = ISCSI_PI_DIF_TYPE_3;
				guard = ISCSI_PI_GUARD_TYPE_IP;
			} else if (!strcmp(bi->name, "T10-DIF-TYPE1-CRC")) {
				dif_type = ISCSI_PI_DIF_TYPE_1;
				guard = ISCSI_PI_GUARD_TYPE_CRC;
			} else if (!strcmp(bi->name, "T10-DIF-TYPE2-CRC")) {
				dif_type = ISCSI_PI_DIF_TYPE_2;
				guard = ISCSI_PI_GUARD_TYPE_CRC;
			} else if (!strcmp(bi->name, "T10-DIF-TYPE3-CRC")) {
				dif_type = ISCSI_PI_DIF_TYPE_3;
				guard = ISCSI_PI_GUARD_TYPE_CRC;
			}
		}
		os_log_info("%s, DIX enabled, dif_type %u, guard %u\n",
			lu->path, dif_type, guard);

		lu->dif_type = dif_type;
		lu->prot_guard = guard;
	}

	return 0;
}
#endif

static int blk_attach(chiscsi_target_lun *lu, char *ebuf, int ebuflen)
{
	int rv = vfs_attach(lu, ebuf, ebuflen);

	if (rv < 0)
		return rv;

	if (!chiscsi_target_lun_flag_test(lu, LUN_BLKDEV_BIT)) {
		sprintf(ebuf,
			"%s NOT BLK device.\n", lu->path);
		os_log_error("%s NOT BLK device, 0x%x.\n", lu->path);
		vfs_detach(lu);
		return -ISCSI_EINVAL;	
	}
#if defined(CONFIG_BLK_DEV_INTEGRITY)
	blk_set_integrity_type(lu);
#endif
	return 0;
}

#if 0
int iscsi_display_byte_string(char *, unsigned char *, int,
			      int, char *, int);
#endif

static void blk_cmd_exe_complete(chiscsi_scsi_command *sc, int err)
{
 	chiscsi_sgl *sc_sgl = &sc->lsc_sc_sgl;

	sc->sc_sdev_hndl = NULL;

	if (err) {
		os_log_error("%s: sc 0x%p, itt 0x%x, flag 0x%x, err %d.\n",
			__func__, sc, sc->sc_itt, sc->sc_flag, err);
		if (sc->sc_flag & SC_FLAG_WRITE)
			chiscsi_scsi_command_write_error(sc);
		else
			chiscsi_scsi_command_read_error(sc);
	}

	if (sc->sc_flag & SC_FLAG_WRITE) {
		os_lun_scsi_cmd_memory_release(sc);
	}
	if (!sc->sc_xfer_len && sc_sgl->sgl_vecs) {
		os_lun_scsi_cmd_memory_release(sc);
	}

#if 0
	/* Print pi buffer content */
	{
		chiscsi_sgl *pi_sgl = &sc->lsc_sc_protsgl;
		chiscsi_sgvec *sg = (chiscsi_sgvec *)pi_sgl->sgl_vecs;

		if (pi_sgl->sgl_vecs && pi_sgl->sgl_vecs_nr) {
			os_log_info("%s: pi buffer sg_addr 0x%p, sg_page %p\n",
				__func__, sg->sg_addr, sg->sg_page);
			iscsi_display_byte_string("sglist data", sg->sg_addr, 0,
						  sg->sg_length, NULL, 0);

		}
	}
#endif

	chiscsi_scsi_cmd_execution_status(sc, sc_sgl->sgl_vecs,
					sc_sgl->sgl_vecs_nr,
					sc_sgl->sgl_boff, sc_sgl->sgl_length);
}

#if 0
/*
 * passthrough via blk_execute_rq()
 * blk_execute_rq_nowait
 *	insert a fully prepared request at the back of the I/O scheduler queue
 *	for execution and wait for completion.
 */

#ifdef BLK_RQ_NO_RESID
#define resid_len 	data_len
#endif
static void blk_rq_end_io(struct request *rq, int error)
{
	chiscsi_scsi_command *sc = rq->end_io_data;
	chiscsi_target_lun *lu = sc->lu;
	chiscsi_sgl *sc_sgl = &sc->lsc_sc_sgl;

	os_log_debug(ISCSI_DBG_SCSI,
		"%s: sc 0x%p, itt 0x%x, error 0x%x, 0x%x, resid %u, sense %u.\n",
		__func__, sc, sc->sc_itt, error, rq->errors, rq->resid_len, rq->sense_len);

 	sc->sc_response = ISCSI_RESPONSE_COMPLETED;
        sc->sc_status = rq->errors & 0xff;
	sc->sc_sense_key = sc->sc_sense_buf[2];	

	if (rq->errors) {
		os_log_warn("BLK %s itt 0x%x, xfer %u, op 0x%x, error 0x%x, 0x%x, resid %u, sense %u.\n",
			lu->path, sc->sc_itt, sc->sc_xfer_len, sc->sc_cmd[0],
			error, rq->errors, rq->resid_len, rq->sense_len);
#if 0
		os_log_error("%s: status 0x%x, masked_status 0x%x, msg_status 0x%x, host_status 0x%x, driver_status 0x%x.\n"
			__func__, rq->errors & 0xff, msg_byte(rq->errors),
			host_byte(rq->errors), driver_byte(rq->errors));
		if (rq->sense_len)
			iscsi_display_byte_string("sense", sc->sc_sense_buf, 0,
					 SCSI_SENSE_BUFFERSIZE, NULL, 0);
#endif
	}

	rq->end_io_data = NULL;
        __blk_put_request(rq->q, rq);

	blk_cmd_exe_complete(sc, 0);
	sc->lu = NULL;
	iscsi_target_session_lun_put(lu);
}


static int blk_cmd_passthru(chiscsi_scsi_command *sc)
{
	chiscsi_target_lun *lu = NULL;
	struct block_device *bdev;
	struct request_queue *q;
	chiscsi_sgl *sc_sgl = &sc->lsc_sc_sgl;
	chiscsi_sgvec *sg = (chiscsi_sgvec *)sc_sgl->sgl_vecs;
	unsigned int sgcnt = sc_sgl->sgl_vecs_nr;
	unsigned int sgidx = 0;
	int rw = (sc->sc_flag & SC_FLAG_WRITE) ? WRITE : READ;
	int err = 0;
	struct request *rq;
	char b[BDEVNAME_SIZE];
	unsigned int len = 0;

	os_log_debug(ISCSI_DBG_SCSI,
		"%s: sc 0x%p itt 0x%x, f 0x%x, xfer %u, status 0x%x.\n",
		__func__, sc, sc->sc_itt, sc->sc_flag, sc->sc_xfer_len, sc->sc_status);

	/* Check Condition  Already Set - We wont process this */
	if (sc->sc_status == 0x02)
		return 0;

	lu = sc->lu = iscsi_target_session_lun_get(sc->sc_sess, sc->sc_lun_acl);
	if (!lu || !lu->priv_data) {
		os_log_error("BLK, bad lun %d, lu 0x%p, fp 0x%p, sess 0x%p, itt 0x%x.\n",
			sc->sc_lun, lu, lu ? lu->priv_data : NULL, sc->sc_sess, sc->sc_itt);
		err = -EINVAL;
		goto err_done;
	}

	bdev = lu_get_bdev(lu);
	if (!bdev) {
		os_log_error("BLK, lu %s, not attached.\n", lu->path);
		err = -EINVAL;
		goto release_lun;
	}

	q = bdev_get_queue(bdev);
	if (!q) {
		os_log_error("trying to access nonexisting block-device %s.\n",
				bdevname(bdev, b));
		err = -EINVAL;
		goto release_lun;
	}

	rq = blk_get_request(q, rw, GFP_KERNEL);
	if (!rq) {
		os_log_error("blk_get_request failed, %s, %s, rw %d.\n",
				bdevname(bdev, b), lu->path, rw);
		err = -EINVAL;
		goto release_lun;
	}

	/*
	 * fill in request structure
	 */
	rq->cmd_len = sc->sc_cmdlen;
#ifdef BLK_RQ_HAS_CMD_TYPE
        rq->cmd_type = REQ_TYPE_BLOCK_PC;
#else
	rq->flags |= REQ_BLOCK_PC;
#endif

	memcpy(rq->cmd, sc->sc_cmd, 16);
	rq->timeout = q->sg_timeout;
        if (!rq->timeout)
#ifdef BLK_RQ_HAS_TIMEOUT
                rq->timeout = BLK_DEFAULT_SG_TIMEOUT;
#else
		rq->timeout = 60 * HZ;
#endif
	rq->sense = sc->sc_sense_buf;
	rq->sense_len = 0;
	rq->retries = 0;

	rq->end_io_data = sc;
	
	len = sc->sc_xfer_len;
	for (sgidx = 0; sgidx < sgcnt; sgidx++, sg++) {
		int rv;
		unsigned int l = min(len, sg->sg_length);

		rv  = blk_rq_map_kern(rq->q, rq, sg->sg_addr, sg->sg_length, __GFP_WAIT);
		os_log_debug(ISCSI_DBG_SCSI,
			"%s: %s,%s sc itt 0x%x, xfer %u, blk_map sg %u/%u,%u,%u, %d.\n",
			__func__, bdevname(bdev, b), lu->path,
			sc->sc_itt, sc->sc_xfer_len, sgidx, sgcnt, sg->sg_length, l, rv);
		if (rv) {
			os_log_error("blk %s,%s sc itt 0x%x, xfer %u, blk_map sg %u/%u,%u, %d.\n",
				bdevname(bdev, b), lu->path,
				sc->sc_itt, sc->sc_xfer_len, sgidx, sgcnt, sg->sg_length, rv);
			err = -EIO;
			goto release_rq;
		}
		len -= l;
	}

	os_log_debug(ISCSI_DBG_SCSI,
		"%s: %s,%s, sc itt 0x%x, xfer %u, sg %u submitted q 0x%p/0x%p.\n",
		__func__, bdevname(bdev, b), lu->path, sc->sc_itt, sc->sc_xfer_len, sgcnt, q, rq->q);
        blk_execute_rq_nowait(q, NULL, rq, 0, blk_rq_end_io);
        return 0;

release_rq:
	blk_put_request(rq);

release_lun:
	if (lu)
		iscsi_target_session_lun_put(lu);

err_done:
	os_log_debug(ISCSI_DBG_SCSI,
		"%s: sc 0x%p itt 0x%x, f 0x%x, xfer %u, err %d.\n",
		__func__, sc, sc->sc_itt, sc->sc_flag, sc->sc_xfer_len, err);
	blk_cmd_exe_complete(sc, err);
	return err;
}
#endif

/*
 * bio execution
 */

static void bioc_free_sgl(struct blk_io_context *bioc)
{
	/*
	 * this is only called, when a TMF is issued on a scsi task, but 
 	 * the io has already been submitted but not yet completed
 	 * so we clean it up after the io has returned
 	 */
	 os_lun_scmd_memory_free_by_page(&bioc->sc_sgl);
	 os_lun_scmd_memory_free_by_page(&bioc->sc_pi_sgl);
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0))
static void blk_bi_endio(struct bio *bio)
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24))
static void blk_bi_endio(struct bio *bio, int err)
#else
static int blk_bi_endio(struct bio *bio, unsigned int bytes_done, int err)
#endif
{
	struct blk_io_context *bioc = bio->bi_private;

	os_log_debug(ISCSI_DBG_SCSI,
		"%s: sc itt 0x%x, err %d, count %d.\n",
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0))
		__func__, bioc->itt, bio->bi_error, atomic_read(&bioc->count));
#else
		__func__, bioc->itt, err, atomic_read(&bioc->count));
#endif

	//scmd_set_timestamp(sc, CH_SCMD_TM_EXE_DONE_N);
	
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
	/* Ignore partials */
	if (bio->bi_size)
		return 1;
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0))
	if (bio->bi_error || !test_bit(BIO_UPTODATE, (unsigned long *)&bio->bi_flags))
#else
	if (err || !test_bit(BIO_UPTODATE, &bio->bi_flags))
#endif
		atomic_inc(&bioc->err);

	bio->bi_private = NULL;
	bio_put(bio);

	if (atomic_dec_and_test(&bioc->count)) {
		unsigned long flags; 

		spin_lock_irqsave(&bioc->lock, flags);
		bioc->flags |= BIOC_FLAG_COMPL;

		if (bioc->flags & BIOC_FLAG_WAIT_COMPL) {
			complete(&bioc->tio_complete);
			spin_unlock_irqrestore(&bioc->lock, flags);
		} else {
			chiscsi_scsi_command *sc = bioc->sc;

			if (sc && !(bioc->flags & BIOC_FLAG_TMF)) {
				spin_unlock_irqrestore(&bioc->lock, flags);

				scmd_set_timestamp(sc, CH_SCMD_TM_EXE_COMPLETE);
				blk_cmd_exe_complete(sc, atomic_read(&bioc->err));
			} else {
				spin_unlock_irqrestore(&bioc->lock, flags);
			}
			os_free(bioc);
		}
	}

	
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24))
	return;
#else
	return 0;
#endif
}

#if defined(CONFIG_BLK_DEV_INTEGRITY)
static int blk_scsi_cmd_alloc_bip(chiscsi_scsi_command *sc, struct bio *bio,
				int dlen, int *sgoffset)
{
	struct blk_integrity *bi;
	struct bio_integrity_payload *bip;
	chiscsi_sgl *pi_sgl = &sc->lsc_sc_protsgl;
	chiscsi_sgvec *sgl;
	unsigned int sectors = bio_sectors(bio), pi_len;
	unsigned int i, offset, sg_len, bytes, newsgoffset, ret;

	if (!pi_sgl || !pi_sgl->sgl_vecs_nr) {
		os_log_error("blk sc itt 0x%x, pi sgl missing. pi_sgl %p, %u\n",
			sc->sc_itt, pi_sgl, (pi_sgl?pi_sgl->sgl_vecs_nr:0));
		return -EINVAL;
	}

	/* For dlen bytes of data in bio, how many bytes of pi to
	   pass in bip */
	bi = bdev_get_integrity(bio->bi_bdev);
	/* sectors =  (bi->sector_size == 4096)?(sectors>>3):sectors; */
	pi_len = sectors *  bi->tuple_size;

	/* allocate bip */
	bip = bio_integrity_alloc(bio, GFP_KERNEL, pi_sgl->sgl_vecs_nr);
	if (unlikely(!bip)) {
		os_log_error("blk sc itt 0x%x, alloc bip OOM.\n",
				sc->sc_itt);
		return -ENOMEM;
	}
	os_log_debug(ISCSI_DBG_SCSI, "%s: bio 0x%p, bip 0x%p: pi nr_pages %u, "
		    "sectors %d, pi_len %d, dlen %u, sgoffset %u\n",
		    __func__, bio, bip, pi_sgl->sgl_vecs_nr, sectors,
		    pi_len, dlen, *sgoffset);

	newsgoffset = *sgoffset;

	/* pass pi_len of pi to bio */
	sgl = (chiscsi_sgvec *)pi_sgl->sgl_vecs;
	for (i = 0; (pi_len && (i < pi_sgl->sgl_vecs_nr)); i++, sgl++) {
		/* seek offset */
#if 0
		os_log_info("%s: bio 0x%p, bip 0x%p, sg_length %u, "
			"sg_offset %u, *sgoffset %u, offset %u, sg_len %u\n",
			__func__, bio, bip, sgl->sg_length, sgl->sg_offset,
			*sgoffset, offset, sg_len);
#endif
		if (*sgoffset >= sgl->sg_length) {
			*sgoffset -= sgl->sg_length;
			continue;
		}
		offset = sgl->sg_offset + *sgoffset;
		sg_len = sgl->sg_length - *sgoffset;
		*sgoffset = 0;

		bytes = (pi_len > sg_len)?sg_len:pi_len;
		newsgoffset += bytes;

#if 0
		os_log_info("%s: bio 0x%p, bip 0x%p: bytes %u, offset %u, "
			    "newsgoffset %u, sg_len %u, pi_len %u\n",
			    __func__, bio, bip, bytes, offset, newsgoffset,
			    sg_len, pi_len);

		/* Only for debugging. Remove it later */
		if (sc->sc_flag & SC_FLAG_WRITE) {
			unsigned char str[128];
			unsigned char const_buf[16];
			int print_buf = 0, xx;
			void *tmp_addr = kmap(sgl->sg_page);

			tmp_addr += offset;
			memset(const_buf, 0x02, 16);
			for (xx = 0; xx < bytes; xx+= 16) {
				if (!memcmp((tmp_addr + xx), const_buf, 16)) {
					print_buf = 1;
					break;
				}
			}
			if (print_buf) {
				sprintf(str, "pi data 0x%llx", sc->sc_lba); 
				iscsi_display_byte_string(str, tmp_addr,
							0, bytes, NULL, 0);
			}
			kunmap(tmp_addr);
		}
#endif

		ret = bio_integrity_add_page(bio, sgl->sg_page,
					bytes, offset);
		if ((ret == 0) || (ret < bytes)) {
			os_log_error("%s: err %d, add page in bio failed\n",
				__func__, ret);
			return -EINVAL;
		}
		pi_len -= bytes;
	}
	*sgoffset = newsgoffset;
	return 0;
}

static int blk_scsi_cmd_t10dix_enabled(struct chiscsi_target_lun *lu,
			chiscsi_scsi_command *sc)
{
	struct block_device *bdev;
	struct blk_integrity *bi;
	int rv = 0;

	if (!(sc->sc_flag & SC_FLAG_T10DIX))
		return 0;

	bdev = lu_get_bdev(lu);
	if (!bdev) {
		os_log_error("BLK, lu %s, not attached.\n", lu->path);
		return rv;
	}

	bi = bdev_get_integrity(bdev);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
	if (bi && bi->verify_fn && (bi->flags & BLK_INTEGRITY_VERIFY))
	
#else
	if (bi && bi->verify_fn && (bi->flags & INTEGRITY_FLAG_READ))
#endif
		rv = 1;

	return rv;
}

static int blk_scsi_fill_pi_info(struct chiscsi_target_lun *lu,
			chiscsi_scsi_command *sc)
{
	struct block_device *bdev = lu_get_bdev(lu);
	struct blk_integrity *bi = bdev_get_integrity(bdev);

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

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,0))
	sc->pi_info.interval = (bi->interval == 4096)?\
		ISCSI_SCSI_PI_INTERVAL_4K:ISCSI_SCSI_PI_INTERVAL_512;
#else
	sc->pi_info.interval = (bi->sector_size==4096)?\
		ISCSI_SCSI_PI_INTERVAL_4K:ISCSI_SCSI_PI_INTERVAL_512;
#endif
	sc->pi_info.dif_type =  lu->dif_type;
	sc->pi_info.guard =  lu->prot_guard;

	return 0;
}
#endif

static int blk_scmd_execute(chiscsi_scsi_command *sc)
{
	chiscsi_target_lun *lu;
	struct block_device *bdev;
	struct request_queue *q;
	chiscsi_sgl *sc_sgl = &sc->lsc_sc_sgl;
	chiscsi_sgvec *sgl = (chiscsi_sgvec *)sc_sgl->sgl_vecs;
	struct bio *bio = NULL, *bio_head = NULL, *bio_tail = NULL;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39))
	struct blk_plug plug;
#endif
	struct blk_io_context *bioc;
	loff_t	pos;
	sector_t sector = sc->sc_lba;
	unsigned int sgcnt = sc_sgl->sgl_vecs_nr;
	unsigned int max_vecs = BIO_MAX_PAGES;
	unsigned int sgidx = 0;
	int rw = (sc->sc_flag & SC_FLAG_WRITE) ? WRITE : READ;
	int err = 0;
	int dlen = 0;
	int wait = 0;
#if defined(CONFIG_BLK_DEV_INTEGRITY)
	int sgoffset = 0;
#endif
	os_log_debug(ISCSI_DBG_SCSI,
		"%s: sc 0x%p itt 0x%x, f 0x%x, xfer %u, status 0x%x, "
		"sc_lba 0x%x.\n",
		__func__, sc, sc->sc_itt, sc->sc_flag, sc->sc_xfer_len,
		sc->sc_status, sc->sc_lba);

	/* Check Condition  Already Set - We wont process this */
	if (sc->sc_status == 0x02) {
		blk_cmd_exe_complete(sc, 0);
		return 0;
	}

#if 0
	if ((sc->sc_flag & SC_FLAG_PASSTHRU) ||
	    (scmd_fpriv_test_bit(sc, CH_SFP_LU_PASSTHRU_BIT)))
		return blk_cmd_passthru(sc);
#endif

        if (!sc->sc_xfer_len) {
		os_log_debug(ISCSI_DBG_SCSI,"%s: itt 0x%x, xfer %u, pass.\n",
			 __FUNCTION__, sc->sc_itt, sc->sc_xfer_len);
		blk_cmd_exe_complete(sc, 0);
		return 0;
	}

	lu = iscsi_target_session_lun_get(sc->sc_sess, sc->sc_lun_acl);
	if (!lu || !lu->priv_data) {
		os_log_error("BLK, bad lun %d, lu 0x%p, fp 0x%p, sess 0x%p, itt 0x%x.\n",
			sc->sc_lun, lu, lu ? lu->priv_data : NULL, sc->sc_sess, sc->sc_itt);
		err = -EINVAL;
		goto err_done;
	}

	bdev = lu_get_bdev(lu);
	if (!bdev) {
		os_log_error("BLK, lu %s, not attached.\n", lu->path);
		err = -EINVAL;
		goto release_lun;
	}
	q = bdev_get_queue(bdev);
	if (!q) {
		char b[BDEVNAME_SIZE];
		os_log_error("trying to access nonexisting block-device %s.\n",
			bdevname(bdev, b));
		err = -EINVAL;
		goto release_lun;
	}

	max_vecs = bio_get_nr_vecs(bdev);
	if (max_vecs > BIO_MAX_PAGES)
		max_vecs = BIO_MAX_PAGES;
	if (!max_vecs) {
		os_log_warn("BLK, lu %s, itt 0x%x, %u, f 0x%lx, max vecs 0.\n",
			lu->path, sc->sc_itt, sc->sc_xfer_len, sc->sc_flag);
		err = -EINVAL;
		goto release_lun;
	}

	if (chiscsi_target_lun_flag_test(lu, LUN_NULLRW_BIT)) {
		goto release_lun;
	}

	os_lock_irq(sc->sc_lock);
	if (sc->sc_flag & (SC_FLAG_TMF_ABORT | SC_FLAG_CMD_ABORT)) {
		os_log_info("%s: sc 0x%p, itt 0x%x, f 0x%x, abort.\n",
			__func__, sc, sc->sc_itt, sc->sc_flag);
		os_unlock_irq(sc->sc_lock);
		err = -EIO;
		goto release_lun;
	}
	os_unlock_irq(sc->sc_lock);

        bioc = os_alloc(sizeof(struct blk_io_context), 1,1);
        if (!bioc) {
		os_log_error("blk sc itt 0x%x, alloc bio context OOM.\n",
				sc->sc_itt);
		err = -ENOMEM;
		goto release_lun;
	}
	spin_lock_init(&bioc->lock);
        atomic_set(&bioc->err, 0);
        atomic_set(&bioc->count, 0);
	if (chiscsi_target_lun_flag_test(lu, LUN_SYNC_BIT)) {
		init_completion(&bioc->tio_complete);
		bioc->flags = BIOC_FLAG_WAIT_COMPL;
		wait = 1;
	}

	bioc->sc = sc;

	pos = sc->sc_lba << lu_sect_shift;
        while (sgidx < sgcnt) {
		unsigned int nr_vecs = min_t(unsigned int,
					(sgcnt - sgidx), max_vecs);
		int i;

               	bio = bio_alloc(GFP_KERNEL, nr_vecs);
                if (!bio) {
			os_log_error("blk sc itt 0x%x, alloc bio OOM, sg %u/%u.\n",
					sc->sc_itt, sgidx, sgcnt);
                        err = -ENOMEM;
			goto free_bio;
                }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
                bio->bi_iter.bi_sector = sector;
#else
                bio->bi_sector = sector;
#endif
                bio->bi_bdev = bdev;
                bio->bi_end_io = blk_bi_endio;
                bio->bi_private = bioc;

		if (bio_head) { 
			bio_tail->bi_next = bio;
			bio_tail = bio;
		} else
			bio_head = bio_tail = bio;

		atomic_inc(&bioc->count);

		for (i = 0; i < nr_vecs && sgidx < sgcnt; i++) {
			int rv = bio_add_page(bio, sgl->sg_page,
					sgl->sg_length, sgl->sg_offset);
			if (rv != sgl->sg_length) {
				if (!rv && i == 0) {
			 		os_log_error("blk sc itt 0x%x, xfer %u,"
						" bio_add sg %d,%u/%u,%u, %u/%u, %d.\n",
						sc->sc_itt, sc->sc_xfer_len, i,
						sgidx, sgcnt, sgl->sg_length,
						nr_vecs, max_vecs, rv);
					err = -EIO;
					goto free_bio;
				}
				break;
			}
			pos += sgl->sg_length;
			dlen +=  sgl->sg_length;
			sgidx++;
			sgl++;
                }

#if defined(CONFIG_BLK_DEV_INTEGRITY)
		if (chiscsi_target_lun_flag_test(lu, LUN_T10DIX_BIT) &&
			(blk_scsi_cmd_t10dix_enabled(lu, sc))) {
			/* Attach integrity data to bio */
			if ((err = blk_scsi_cmd_alloc_bip(sc, bio, dlen,
							&sgoffset)) < 0) {
				os_log_warn("BLK, lu %s, itt 0x%x, xfer_len %u, "
					"pi alloc failed err %d",
					lu->path, sc->sc_itt, sc->sc_xfer_len,
					err);
				goto free_bio;
			}
		}
#endif

		sector += bio_sectors(bio);
        } 

	os_log_debug(ISCSI_DBG_SCSI,
		"%s, %s, itt 0x%x, submitting bios.\n",
		__func__, lu->path, sc->sc_itt);

	os_lock_irq(sc->sc_lock);
	if (sc->sc_flag & (SC_FLAG_TMF_ABORT | SC_FLAG_CMD_ABORT)) {
		os_log_info("%s: sc 0x%p, itt 0x%x, f 0x%x, abort.\n",
			__func__, sc, sc->sc_itt, sc->sc_flag);
		os_unlock_irq(sc->sc_lock);
		err = -EIO;
		goto free_bio;
	}

	sc->sc_sdev_hndl = (void *)bioc;
	os_unlock_irq(sc->sc_lock);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39))
	/* once start_plug, make sure finish_plug is always called */
	blk_start_plug(&plug);
#endif

	while (bio_head) {
                bio = bio_head;
                bio_head = bio->bi_next;
		bio->bi_next = NULL;
                submit_bio(rw, bio);
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39))
	blk_finish_plug(&plug);
#else
	if (q && q->unplug_fn)
		q->unplug_fn(q);
#endif
	scmd_set_timestamp(sc, CH_SCMD_TM_EXE_SUBMIT);

	iscsi_target_session_lun_put(lu);

	if (wait) {
		unsigned long flags; 

		wait_for_completion(&bioc->tio_complete);
		err = atomic_read(&bioc->err);

		spin_lock_irqsave(&bioc->lock, flags);
		sc = bioc->sc;
		if (sc) {
			spin_unlock_irqrestore(&bioc->lock, flags);
			blk_cmd_exe_complete(sc, err);
		} else {
			spin_unlock_irqrestore(&bioc->lock, flags);
			bioc_free_sgl(bioc);
		}

		os_free(bioc);
	}

	/* blk_bi_endio() will call blk_cmd_exe_complete() */
	return 0;

free_bio:
	while (bio_head) {
		bio = bio_head;
		bio_head = bio->bi_next;
		bio_put(bio);
	}
	os_free(bioc);

release_lun:
	iscsi_target_session_lun_put(lu);

err_done:
	blk_cmd_exe_complete(sc, err);
	return err;
}

static int blk_scsi_cmd_cdb_rcved(chiscsi_scsi_command *sc)
{
	chiscsi_sgl *sc_sgl = &sc->lsc_sc_sgl;
	chiscsi_target_lun *lu = NULL;
	int rv;

	os_log_debug(ISCSI_DBG_SCSI,
		"%s: alloc len %u, sc_lba 0x%x, sc_flag 0x%x\n",
		__func__, (sc->sc_blk_cnt << lu_sect_shift),
		sc->sc_lba, sc->sc_flag);

	/* one-shot allocation, just save it in lsc->sc_sgl */
	rv = os_lun_scmd_memory_alloc_by_page(sc, sc_sgl);
	if (rv < 0) {
		os_log_info("%s: sc 0x%p itt 0x%x, f 0x%x, xfer %u, %u+%u, ENOMEM %d.\n",
			__func__, sc, sc->sc_itt, sc->sc_flag, sc->sc_xfer_len,
			sc_sgl->sgl_boff, sc_sgl->sgl_length, rv);
		return rv;
	}

	lu = iscsi_target_session_lun_get(sc->sc_sess, sc->sc_lun_acl);

	if ((sc->sc_flag & SC_FLAG_READ) || (sc->sc_flag & SC_FLAG_WRITE)) {

#if defined(CONFIG_BLK_DEV_INTEGRITY)
		if (lu && chiscsi_target_lun_flag_test(lu, LUN_T10DIX_BIT) &&
			(blk_scsi_cmd_t10dix_enabled(lu, sc))) {
			chiscsi_sgl *pi_sgl = &sc->lsc_sc_protsgl;

			rv = os_lun_pi_memory_alloc_by_pages(sc, pi_sgl);
			if (rv < 0) {
				os_log_info("%s: sc 0x%p itt 0x%x, f 0x%x, "
					"xfer %u, PI ENOMEM %d.\n",
				__func__, sc, sc->sc_itt, sc->sc_flag,
				sc->sc_xfer_len, rv);
			}
			blk_scsi_fill_pi_info(lu, sc);
		}
#endif
	}

	if (sc->sc_flag & SC_FLAG_READ) {
		if (lu && chiscsi_target_lun_flag_test(lu, LUN_SYNC_BIT))
			iscsi_target_scmd_assign_lu_worker(sc);
		else
			blk_scmd_execute(sc);
	} else 
		chiscsi_scsi_cmd_buffer_ready(sc, sc_sgl->sgl_vecs,
					sc_sgl->sgl_vecs_nr, sc_sgl->sgl_boff,
					sc_sgl->sgl_length);
	iscsi_target_session_lun_put(lu);
	return 0;
}

static void blk_scsi_cmd_data_xfer_status(chiscsi_scsi_command *sc,
				unsigned char *xfer_sreq_buf,
				unsigned int xfer_sgcnt,
				unsigned int xfer_offset,
				unsigned int xfer_buflen)
{
	chiscsi_sgl *sc_sgl = &sc->lsc_sc_sgl;

	if (sc_sgl->sgl_vecs != xfer_sreq_buf ||
	    sc_sgl->sgl_vecs_nr != xfer_sgcnt ||
	    sc_sgl->sgl_boff != xfer_offset ||
	    sc_sgl->sgl_length != xfer_buflen) {
		os_log_warn("%s: itt 0x%x, SGL mismatch: 0x%p/0x%p, %u/%u, %u/%u+%u/%u.\n",
			__func__, sc->sc_itt, sc_sgl->sgl_vecs, xfer_sreq_buf,
			sc_sgl->sgl_vecs_nr, xfer_sgcnt, sc_sgl->sgl_boff,
			xfer_offset, sc_sgl->sgl_length, xfer_buflen);
	}

	if (sc->sc_flag & (SC_FLAG_TMF_ABORT | SC_FLAG_CMD_ABORT)) {
		os_log_info("%s: sc 0x%p, itt 0x%x, f 0x%x, abort.\n",
			__func__, sc, sc->sc_itt, sc->sc_flag);

		os_lun_scsi_cmd_memory_release(sc);
		scmd_fscsi_clear_bit(sc, CH_SFSCSI_HOLD_BIT);
		return;
	}

	if (sc->sc_flag & SC_FLAG_READ) {
		os_lun_scsi_cmd_memory_release(sc);
	} else {
		chiscsi_target_lun *lu = iscsi_target_session_lun_get(sc->sc_sess,
					sc->sc_lun_acl);
		/* write: all data received */

		if (lu && chiscsi_target_lun_flag_test(lu, LUN_SYNC_BIT))
			iscsi_target_scmd_assign_lu_worker(sc);
		else	
			blk_scmd_execute(sc);
		if (lu)
			iscsi_target_session_lun_put(lu);
	}
}

static int blk_scsi_cmd_abort(chiscsi_scsi_command *sc)
{
	struct blk_io_context *bioc;

	return 0;

	if (scmd_fpriv_test_bit(sc, CH_SFP_TLU_THREAD_BIT)) {
		iscsi_target_scmd_remove_from_lu_worker(sc);
	}

	os_lock_irq(sc->sc_lock);

	bioc = (struct blk_io_context *)sc->sc_sdev_hndl;

	sc->sc_sdev_hndl = NULL;
	if (!bioc) {
		os_log_info("%s: sc 0x%p, itt 0x%x, no bioc.\n",
			 __func__, sc, sc->sc_itt);
		/* release allocated memory */
		os_lun_scsi_cmd_memory_release(sc);
        	scmd_fscsi_clear_bit(sc, CH_SFSCSI_BUF_READY_BIT);
		chiscsi_scsi_command_aborted(sc);
		scmd_fscsi_clear_bit(sc, CH_SFSCSI_HOLD_BIT);

		os_unlock_irq(sc->sc_lock);

		chiscsi_scsi_cmd_execution_status(sc, NULL, 0, 0, 0);
	} else {
		unsigned long flags; 

		scmd_fscsi_clear_bit(sc, CH_SFSCSI_HOLD_BIT);

		memcpy(&bioc->sc_sgl, &sc->lsc_sc_sgl, sizeof(chiscsi_sgl));
		memcpy(&bioc->sc_pi_sgl, &sc->lsc_sc_protsgl,
			sizeof(chiscsi_sgl));

        	scmd_fscsi_clear_bit(sc, CH_SFSCSI_BUF_READY_BIT);
		memset(&sc->lsc_sc_sgl, 0, sizeof(struct chiscsi_sgl));
		memset(&sc->lsc_sc_protsgl, 0, sizeof(struct chiscsi_sgl));

		os_unlock_irq(sc->sc_lock);

		/* being executed */
		spin_lock_irqsave(&bioc->lock, flags);
		bioc->flags |= BIOC_FLAG_TMF;
		bioc->sc = NULL;

		if (bioc->flags & BIOC_FLAG_COMPL) {
			/* just completed */
			os_log_info("%s: sc 0x%p, itt 0x%x, bioc, completed.\n",
			 __func__, sc, sc->sc_itt);
			spin_unlock_irqrestore(&bioc->lock, flags);
		} else if (bioc->flags & BIOC_FLAG_WAIT_COMPL) {
		//	bioc->flags &= ~BIOC_FLAG_WAIT_COMPL;
		//	complete(&bioc->tio_complete);
			spin_unlock_irqrestore(&bioc->lock, flags);

			os_log_info("%s: sc 0x%p, itt 0x%x, bioc, waiting compl.\n",
				 __func__, sc, sc->sc_itt);
			chiscsi_scsi_command_aborted(sc);
			chiscsi_scsi_cmd_execution_status(sc, NULL, 0, 0, 0);

		} else {
			spin_unlock_irqrestore(&bioc->lock, flags);

			os_log_info("%s: sc 0x%p, itt 0x%x, bioc, abort.\n",
				 __func__, sc, sc->sc_itt);
			chiscsi_scsi_command_aborted(sc);
			chiscsi_scsi_cmd_execution_status(sc, NULL, 0, 0, 0);
		}
	}

	return 0;
}

static int blk_tmf_execute(unsigned long sess_hndl, unsigned long tmf_hndl,
			unsigned char immediate_cmd, unsigned char tmf_func,
			unsigned int lun, chiscsi_scsi_command *sc)
{
	return 0;
}

chiscsi_target_lun_class lun_class_blk = {
	.property = 1 << LUN_CLASS_HAS_CMD_QUEUE_BIT,
	.lun_extra_size = 0,
	//.scmd_extra_size = sizeof(struct blk_io_context),
	.class_name = BLK_TYPE,
	.fp_attach = blk_attach,
	.fp_reattach = vfs_reattach,
	.fp_detach = vfs_detach,
	.fp_queued_scsi_cmd_exe = blk_scmd_execute,
	.fp_scsi_cmd_cdb_rcved = blk_scsi_cmd_cdb_rcved,
	.fp_scsi_cmd_data_xfer_status = blk_scsi_cmd_data_xfer_status,
	.fp_scsi_cmd_cleanup = os_lun_scsi_cmd_memory_release,
	.fp_scsi_cmd_abort = blk_scsi_cmd_abort,
	.fp_tmf_execute = blk_tmf_execute
};
