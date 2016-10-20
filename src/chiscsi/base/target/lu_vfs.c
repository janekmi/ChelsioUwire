/*
 * iscsi target device -- file io
 */
#ifdef __ISCSI_VFS__

#include <linux/version.h>
#include <linux/kernel.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/uio.h>

#include <common/iscsi_common.h>
#include <common/iscsi_target_device.h>
#include <common/os_export.h>

#define VFS_TYPE	"FILE"

extern unsigned int lu_sect_shift;

void vfs_detach(chiscsi_target_lun *lu)
{
	int err;

	if (!lu->priv_data)
		return;

	if (lu->lun_tmp && lu->lun_tmp->priv_data == lu->priv_data)
		return;

	err = filp_close(lu->priv_data, NULL);
	if (err)
		os_log_error("%s: close failed %d.\n", lu->path, err);
	lu->priv_data = NULL;
}

int vfs_attach(chiscsi_target_lun *lu, char *ebuf, int ebuflen)
{
	mm_segment_t fs;
	struct file *fp;
	struct inode *inode;
	int oflag = O_LARGEFILE;

	fs = get_fs();
	set_fs(get_ds());

        if (chiscsi_target_lun_flag_test(lu, LUN_RO_BIT))
                oflag |= O_RDONLY;
        else
                oflag |= O_RDWR;
        if (!chiscsi_target_lun_flag_test(lu, LUN_NONEXCL_BIT))
                oflag |= O_EXCL;

	fp = filp_open(lu->path, oflag, 0);
	set_fs(fs);

	if (IS_ERR(fp)) {
		if (ebuf && ebuflen)
			sprintf(ebuf, "attach %s failed %ld.\n",
				lu->path, PTR_ERR(fp));
		os_log_error("attach %s FAILED, %ld.\n",
				lu->path, PTR_ERR(fp));
		return -ISCSI_EINVAL;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	inode = fp->f_dentry->d_inode;
#else
	inode = file_inode(fp);
#endif
	if (S_ISBLK(inode->i_mode)) {
        	chiscsi_target_lun_flag_set(lu, LUN_BLKDEV_BIT);
		inode = inode->i_bdev->bd_inode;
	} else if (!(S_ISREG(inode->i_mode))) {
		if (ebuf && ebuflen)
			sprintf(ebuf,
				"%s device type 0x%x NOT supported.\n",
				lu->path, inode->i_mode);
		os_log_error("%s device type 0x%x NOT supported.\n",
				lu->path, inode->i_mode);
		filp_close(fp, NULL);
                return -ISCSI_EINVAL;
        }

	if (inode->i_size == 0) {
		if (ebuf && ebuflen)
			sprintf(ebuf, "%s size is ZERO.\n", lu->path);
		os_log_error("%s size is ZERO.\n", lu->path);
		vfs_detach(lu);
                return -ISCSI_EINVAL;
	}

	lu->priv_data = (void *)fp;
	lu->size = inode->i_size;

	os_log_info("%s, mode 0x%x, SYNC %s.\n",
		lu->path, inode->i_mode, 
		chiscsi_target_lun_flag_test(lu, LUN_SYNC_BIT) ? "on" : "off");
	return 0;
}

int vfs_reattach(chiscsi_target_lun *old, chiscsi_target_lun *new,
			char *ebuf, int ebuflen)
{
	struct file *fp = (struct file *)old->priv_data;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	struct inode *inode = fp->f_dentry->d_inode;
#else
	struct inode *inode = file_inode(fp);
#endif


	if (S_ISBLK(inode->i_mode))
		inode = inode->i_bdev->bd_inode;

	new->priv_data = (void *)fp;
	new->size = inode->i_size;
	return 0;
}

static int vfs_flush(chiscsi_target_lun *lu)
{
	struct file *fp;
	int rv;

	if (!(fp =  (struct file *)lu->priv_data)) {
		os_log_info("%s, %s hndl NULL.\n", lu->path, VFS_TYPE);
		return -ISCSI_ENULL;
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35))
	rv = vfs_fsync_range(fp, 0, LLONG_MAX, 1);
#else
	rv = vfs_fsync_range(fp, fp->f_dentry, 0, LLONG_MAX, 1);
#endif
        if (rv < 0)
                 os_log_error("%s: vfs_fsync_range failed: %d.\n",
			 	__func__, rv);

	return rv;
}

static int vfs_scmd_execute(chiscsi_scsi_command *sc)
{
	chiscsi_target_lun *lu = iscsi_target_session_lun_get(sc->sc_sess,
							sc->sc_lun_acl);
	struct file *fhndl;
	chiscsi_sgl *sc_sgl = &sc->lsc_sc_sgl;
	chiscsi_sgvec *sgl = (chiscsi_sgvec *)sc_sgl->sgl_vecs;
	unsigned int sgcnt = sc_sgl->sgl_vecs_nr;
	loff_t pos, pos_sav;
	mm_segment_t fs;
	int i, rv = 0;
	int flush = 0;
	struct iovec *iov;
	int is_write = (sc->sc_flag & SC_FLAG_WRITE) ? 1 : 0;

	if (!lu || !lu->priv_data) {
		os_log_error("VFS, bad lun %d, lu 0x%p, fp 0x%p, sess 0x%p, itt 0x%x.\n",
			sc->sc_lun, lu, lu ? lu->priv_data : NULL, sc->sc_sess, sc->sc_itt);
		chiscsi_scsi_command_target_failure(sc);
		goto done;
	}

	if (!(fhndl = (struct file *)lu->priv_data)) {
		os_log_info("%s, %s not attached.\n", lu->path, VFS_TYPE);
		/* mark as internal failure */
		chiscsi_scsi_command_target_failure(sc);
		goto done;
	}

	/* Check Condition  Already Set - We wont process this */
	if (sc->sc_status == 0x02)
		goto done;
	
	if (!sc->sc_xfer_len) {
		goto done;
        }

	if (chiscsi_target_lun_flag_test(lu, LUN_NULLRW_BIT))
		goto done;
	if (chiscsi_target_lun_flag_test(lu, LUN_SYNC_BIT))
		flush = 1;

	pos_sav = pos = sc->sc_lba << lu_sect_shift;

	iscsi_target_session_lun_put(lu);
	lu = NULL;

	os_lock_irq(sc->sc_lock);
	if (sc->sc_flag & SC_FLAG_ABORT) {
		os_log_info("%s: sc 0x%p, itt 0x%x, f 0x%x, abort.\n",
			__func__, sc, sc->sc_itt, sc->sc_flag);
		os_unlock_irq(sc->sc_lock);
                goto done;
	}
	os_unlock_irq(sc->sc_lock);

	iov = kmalloc(sizeof(struct iovec)*sgcnt, GFP_KERNEL);
	if (!iov) {
		os_log_info("%s: sc 0x%p, itt 0x%x, f 0x%x, oom.\n",
			__func__, sc, sc->sc_itt, sc->sc_flag);
		rv = -ENOMEM;
		goto done;
	}

	for (i = 0; i < sgcnt; i++, sgl++) {
		iov[i].iov_len = sgl->sg_length;		
		iov[i].iov_base = sgl->sg_addr;		
	}

	fs = get_fs();
	set_fs(get_ds());
	if (is_write)
		rv = vfs_writev(fhndl, &iov[0], sgcnt, &pos);
	else
		rv = vfs_readv(fhndl, &iov[0], sgcnt, &pos);
	set_fs(fs);

	kfree(iov);

	if (rv < 0) {
		os_log_error("%s: %c failed %d, exp. %d.\n",
			VFS_TYPE, is_write ? 'W' : 'R', rv, sc->sc_xfer_len);
		goto done;
	}

	if (rv != sc->sc_xfer_len) {
		os_log_error("%s: %c, returns %d, exp. %d.\n",
			VFS_TYPE, is_write ? 'W' : 'R', rv, sc->sc_xfer_len);
	}

	if (flush) {
		lu = iscsi_target_session_lun_get(sc->sc_sess, sc->sc_lun_acl);
		if (lu) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35))
			rv =  vfs_fsync_range(fhndl, pos_sav, pos, 1);
#else
			rv =  vfs_fsync_range(fhndl, fhndl->f_dentry,
						 pos_sav, pos, 1);
#endif
			if (rv < 0)
				os_log_error("%s: sync returns %d.\n",
					__func__, rv);
		}
	}

done:
	if (rv < 0) {
		if (sc->sc_flag & SC_FLAG_READ)
			chiscsi_scsi_command_read_error(sc);
		else
			chiscsi_scsi_command_write_error(sc);
	}

	if (lu)
		iscsi_target_session_lun_put(lu);
	if (sc->sc_flag & SC_FLAG_WRITE)
		os_lun_scsi_cmd_memory_release(sc);
	if (!sc->sc_xfer_len && sc_sgl->sgl_vecs)
		os_lun_scsi_cmd_memory_release(sc);
	chiscsi_scsi_cmd_execution_status(sc, sc_sgl->sgl_vecs,
					sc_sgl->sgl_vecs_nr,
					sc_sgl->sgl_boff, sc_sgl->sgl_length);
	return 0;
}

static int vfs_scsi_cmd_cdb_rcved(chiscsi_scsi_command *sc)
{
	chiscsi_sgl *sc_sgl = &sc->lsc_sc_sgl;
	int rv;

	rv = os_lun_scmd_memory_alloc_by_page(sc, sc_sgl);
	if (rv < 0)
		return rv;
	if (sc->sc_flag & SC_FLAG_READ)
		/* pick a thread to execute this */
		iscsi_target_scmd_assign_lu_worker(sc);
        else
		chiscsi_scsi_cmd_buffer_ready(sc, sc_sgl->sgl_vecs,
					sc_sgl->sgl_vecs_nr, sc_sgl->sgl_boff,
					sc_sgl->sgl_length);
	return 0;
}

static void vfs_scsi_cmd_data_xfer_status(chiscsi_scsi_command *sc,
				unsigned char *xfer_sreq_buf,
				unsigned int xfer_sgcnt,
				unsigned int xfer_offset,
				unsigned int xfer_buflen)
{
	chiscsi_sgl *sc_sgl = &sc->lsc_sc_sgl;

	/* should match what we had allocated */
	if (sc_sgl->sgl_vecs != xfer_sreq_buf || 
	    sc_sgl->sgl_vecs_nr != xfer_sgcnt ||
	    sc_sgl->sgl_boff != xfer_offset  ||
	    sc_sgl->sgl_length != xfer_buflen)
		os_log_warn("%s: SGL mismatch: 0x%p/0x%p, %u/%u, %u/%u+%u/%u\n",
			__func__, sc_sgl->sgl_vecs, xfer_sreq_buf,
			sc_sgl->sgl_vecs_nr, xfer_sgcnt, sc_sgl->sgl_boff,
			xfer_offset, sc_sgl->sgl_length, xfer_buflen);

	if (sc->sc_flag & SC_FLAG_ABORT) {
		os_log_info("%s: sc 0x%p, itt 0x%x, f 0x%x, abort.\n",
			__func__, sc, sc->sc_itt, sc->sc_flag);
		os_lun_scsi_cmd_memory_release(sc);
		scmd_fscsi_clear_bit(sc, CH_SFSCSI_HOLD_BIT);
                return;
        }


	if (sc->sc_flag & SC_FLAG_READ)
		os_lun_scsi_cmd_memory_release(sc);
	else {
		if (sc->sc_state >= CH_SC_STATE_STATUS) {
			os_lun_scsi_cmd_memory_release(sc);
		} else
			iscsi_target_scmd_assign_lu_worker(sc);
	}
}

static int vfs_scsi_cmd_abort(chiscsi_scsi_command *sc)
{
	return 0;
}

static int vfs_tmf_execute(unsigned long sess_hndl, unsigned long tmf_hndl,
			 unsigned char immediate_cmd, unsigned char tmf_func,
			 unsigned int lun, chiscsi_scsi_command *sc)
{
	return 0;
}


chiscsi_target_lun_class lun_class_vfs = {
	.property = 1 << LUN_CLASS_HAS_CMD_QUEUE_BIT,
	.lun_extra_size = 0,
	.class_name = VFS_TYPE,
	.fp_attach = vfs_attach,
	.fp_reattach = vfs_reattach,
	.fp_detach = vfs_detach,
	.fp_flush = vfs_flush,
	.fp_queued_scsi_cmd_exe = vfs_scmd_execute,
	.fp_scsi_cmd_cdb_rcved = vfs_scsi_cmd_cdb_rcved,
	.fp_scsi_cmd_data_xfer_status = vfs_scsi_cmd_data_xfer_status,
	.fp_scsi_cmd_cleanup = os_lun_scsi_cmd_memory_release,
	.fp_scsi_cmd_abort = vfs_scsi_cmd_abort,
	.fp_tmf_execute = vfs_tmf_execute
};
#endif /* ifdef __ISCSI_VFS__ */
