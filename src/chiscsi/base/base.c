/*
 *   iscsi_mod.c
 *	module entry/exit point
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/smp.h>

#include <common/version.h>
#include <common/iscsi_common.h>
#include <common/iscsi_control.h>
#include <common/iscsi_lib_export.h>

#ifdef __ISCSI_SCST__
#include <scst.h>
extern struct scst_tgt_template chiscsi_scst_tgt_template;
#endif

void    iscsi_ioctl_cleanup(void);
int     iscsi_ioctl_init(void);
void    iscsi_os_cleanup(void);
int     iscsi_os_init(void);
#ifdef __CONFIG_DEBUGFS__
int     iscsi_debugfs_init(void);
void    iscsi_debugfs_cleanup(void);
#else
#define iscsi_debugfs_init()		0
#define iscsi_debugfs_cleanup()
#endif
int os_target_init(void);
void os_target_cleanup(void);


/* iscsi module info */
MODULE_AUTHOR(MOD_AUTHOR);
MODULE_LICENSE(MOD_LICENSE);
#ifdef __ACL_LM__
MODULE_DESCRIPTION(DRIVER_STRING " v" DRIVER_VERSION "+");
#else
MODULE_DESCRIPTION(DRIVER_STRING " v" DRIVER_VERSION);
#endif

/* Module parameters */
unsigned int cxgb3_mpool_kb = 0;
module_param(cxgb3_mpool_kb, uint, 0644);
MODULE_PARM_DESC(cxgb3_mpool_kb, "cxgb3 memory pool size in KB (default=0KB)");

unsigned int node_max_lun_count = 512;
module_param(node_max_lun_count, uint, 0644);
MODULE_PARM_DESC(node_max_lun_count, "Maximum LUN count per iSCSI Target Node (default=512)");

unsigned int iscsi_lu_worker_thread = 0;
module_param(iscsi_lu_worker_thread, uint, 0644);
MODULE_PARM_DESC(iscsi_lu_worker_thread,
		"# of target lun worker thread for FILE and BLK,SYNC mode");

unsigned int lu_sect_shift = DEFAULT_SECT_SIZE_SHIFT;
module_param(lu_sect_shift, uint, 0644);
MODULE_PARM_DESC(lu_sect_shift, "LUN sector size shift, default=9 (512 sector size)");

/* iSCSI cleanup function */
static void iscsi_main_exit(void)
{
	char    buffer[256];

	iscsi_common_cleanup();
	os_target_cleanup();
#ifdef __ISCSI_SCST__
	scst_unregister_target_template(&chiscsi_scst_tgt_template);
#endif
	iscsi_ioctl_cleanup();
	iscsi_debugfs_cleanup();
	iscsi_os_cleanup();

	memset(buffer, 0, 256);
	iscsi_stats_display(buffer, 256);
	os_log_info("%s.\n", buffer);

	os_log_info("%s v%s-%s unloaded.\n",
		    DRIVER_STRING, DRIVER_VERSION, BUILD_VERSION);
}

static int __init iscsi_main_init(void)
{
	int     rv = 0;
	char    buffer[256];

	if (node_max_lun_count > ISCSI_TARGET_LUN_MAX) {
		os_log_info("resize node_max_lun_count %u -> %u.\n",
			node_max_lun_count, ISCSI_TARGET_LUN_MAX);
		node_max_lun_count = ISCSI_TARGET_LUN_MAX;
	}

	rv = iscsi_os_init();
	if (rv < 0)
		goto err_out;

	rv = iscsi_ioctl_init();
	if (rv < 0)
		goto err_out;

	rv = iscsi_common_init(num_possible_cpus());
	if (rv < 0)
		goto err_out;

	rv = iscsi_debugfs_init();
	if (rv < 0)
		goto err_out;

#ifdef __ISCSI_SCST__
	rv = scst_register_target_template(&chiscsi_scst_tgt_template);
	if (rv < 0) 
		goto err_out;
#endif

	rv = os_target_init();
	if (rv < 0)
		goto err_out;
	
	memset(buffer, 0, 256);
	iscsi_stats_display(buffer, 256);
	os_log_info("%s.\n", buffer);

	os_log_info("%s v%s-%s loaded.\n", DRIVER_STRING, DRIVER_VERSION,
		    BUILD_VERSION);

	return 0;

      err_out:
	iscsi_main_exit();
	return rv;
}

module_init(iscsi_main_init);
module_exit(iscsi_main_exit);
