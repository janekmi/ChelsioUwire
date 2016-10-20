#include <common/iscsi_error.h>
#include <common/iscsi_debug.h>
#include <common/iscsi_target_device.h>
#include <common/iscsi_scsi_command.h>

#ifdef __ISCSI_SCST__
extern chiscsi_target_lun_class lun_class_scst;
#endif
extern chiscsi_target_lun_class lun_class_blk;
extern chiscsi_target_lun_class lun_class_vfs;
extern chiscsi_target_lun_class lun_class_mem;

int os_target_init(void)
{
	int rv;

	rv = chiscsi_target_lun_class_register(&lun_class_blk,
						CHELSIO_TARGET_CLASS);
	if (rv < 0) 
		return rv;

#ifdef __ISCSI_VFS__
	rv = chiscsi_target_lun_class_register(&lun_class_vfs,
						CHELSIO_TARGET_CLASS);
	if (rv < 0) 
		return rv;
#endif

#ifdef __ISCSI_SCST__
	rv = chiscsi_target_lun_class_register(&lun_class_scst,
						CHELSIO_TARGET_CLASS);
	if (rv < 0)
		return rv;
#endif

	rv = chiscsi_target_lun_class_register(&lun_class_mem,
						CHELSIO_TARGET_CLASS);
	if (rv < 0) 
		return rv;

#ifdef __TEST_PREMAPPED_SKB__
	os_log_info("%s: premap buffer testing enabled.\n", __func__);
#endif
	return 0;
}

void os_target_cleanup(void)
{
	chiscsi_target_lun_class_deregister(lun_class_blk.class_name,
						CHELSIO_TARGET_CLASS);
#ifdef __ISCSI_VFS__
	chiscsi_target_lun_class_deregister(lun_class_vfs.class_name,
						CHELSIO_TARGET_CLASS);
#endif
	chiscsi_target_lun_class_deregister(lun_class_mem.class_name,
						CHELSIO_TARGET_CLASS);
#ifdef __ISCSI_SCST__
	chiscsi_target_lun_class_deregister(lun_class_scst.class_name,
						CHELSIO_TARGET_CLASS);
#endif
}
