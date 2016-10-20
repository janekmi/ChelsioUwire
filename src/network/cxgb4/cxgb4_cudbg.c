#include <linux/version.h>
#include <linux/types.h>
#include <linux/time.h>
#include "t4_hw.h"
#include "common.h"
#include "t4_regs.h"
#include "t4_msg.h"
#include "platdef.h"
#include "cudbg_if.h"

void do_collect(struct adapter *adap, void *buf, unsigned long size)
{
	struct cudbg_init cudbg = {{0}};
	struct timespec ts;
	void *handle = NULL;
	int ret;

	init_cudbg_hdr(&cudbg.header);
	set_dbg_bitmap(cudbg.dbg_bitmap, CUDBG_ALL);
	cudbg.adap = adap;
	cudbg.print = (cudbg_print_cb) printk;
	cudbg.sw_state_buf = NULL;
	cudbg.sw_state_buflen = 0;
	cudbg.use_flash = 1;

	getnstimeofday(&ts);
	cudbg.dbg_params[CUDBG_TIMESTAMP_PARAM].u.time = ts.tv_sec;
	cudbg.dbg_params[CUDBG_TIMESTAMP_PARAM].param_type =
			CUDBG_TIMESTAMP_PARAM;

#ifdef T4_OS_LOG_MBOX_CMDS
	cudbg.dbg_params[CUDBG_MBOX_LOG_PARAM].param_type =
			CUDBG_MBOX_LOG_PARAM;
	cudbg.dbg_params[CUDBG_MBOX_LOG_PARAM].u.mboxlog_param.log =
			adap->mbox_log;
	cudbg.dbg_params[CUDBG_MBOX_LOG_PARAM].u.mboxlog_param.mbox_cmds =
			T4_OS_LOG_MBOX_CMDS;
	cudbg.dbg_params_cnt++;
#endif

	ret = cudbg_hello(&cudbg, &handle);
	if (ret) {
		dev_err(adap->pdev_dev,
			"cudbg failed to initialize, hello cmd failed, ret=%d",
			 ret);
		goto out;
	}

	ret = cudbg_collect(handle, buf, (u32 *)&size);
	if (ret) {
		dev_err(adap->pdev_dev,
			"cudbg collect failed, ret=%d", ret);
		goto out;
	} else {
		dev_info(adap->pdev_dev,
			"cudbg collect success, size=%lu", size);
		dev_info(adap->pdev_dev, "Dumping debug data to flash.");
	}

out:
	if (handle)
		cudbg_bye(handle);
}
