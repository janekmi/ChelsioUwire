
/* 
 * iscsi_control_linux.c - iSCSI ioctl handling on Linux
 */

#include <common/os_builtin.h>
#include <common/iscsi_common.h>
#include <common/iscsi_control.h>
#include <common/iscsi_lib_export.h>
#include <iscsi_control_defs.h>
#include <iscsi_common_api.h>
#include <iscsi_control_api.h>
#include <iscsi_target_api.h>

int iscsi_control_request(int opcode, unsigned long data, unsigned long thour)
{
	int     rv = -ISCSI_ECMD;
	int     rv_tmp = -ISCSI_ECMD;
	iscsi_control_args *arg;
	char   *ebuf = NULL, *kbuf = NULL, *dbuf = NULL;
	int     kbuflen = 0, dbuflen = 0;

	arg = os_vmalloc(sizeof(iscsi_control_args));
	if (!arg) {
		rv = -ISCSI_ENOMEM;
		goto cleanup;
	}

	ebuf = os_vmalloc(sizeof(char) * ISCSI_CONTROL_REQ_MAX_BUFLEN);
	if (!ebuf) {
		rv = -ISCSI_ENOMEM;
		goto cleanup;
	}		
	ebuf[0] = 0;

	rv = os_copy_from_user(arg, (void *) data, sizeof(iscsi_control_args));
	if (rv)
		return -ISCSI_EUSER;

	/* key file buffer */
	kbuflen = arg->len[0];
	if (kbuflen) {
		kbuf = os_vmalloc(kbuflen);
		if (!kbuf) {
			rv = sprintf(ebuf, "chiscsi: out of memory.\n");
			ebuf[rv] = 0;
			rv = -ISCSI_ENOMEM;
			goto cleanup;
		}
		rv = os_copy_from_user(kbuf, (void *) (arg->addr[0]), kbuflen);
		if (rv) {
			rv = -ISCSI_EUSER;
			goto cleanup;
		}
	}

	/* command buffer */
	dbuflen = arg->len[1];
	if (dbuflen) {
		dbuf = os_vmalloc(dbuflen);
		if (!dbuf) {
			rv = sprintf(ebuf, "chiscsi: out of memory.\n");
			ebuf[rv] = 0;
			rv = -ISCSI_ENOMEM;
			goto cleanup;
		}
		dbuf[0] = 0;
		if (arg->flag & ISCSI_CONTROL_FLAG_EXTRA_DATA) {
			rv = os_copy_from_user(dbuf, (void *) (arg->addr[1]),
					       dbuflen);
			if (rv) {
				rv = -ISCSI_EUSER;
				goto cleanup;
			}
		}
	}

	ebuf[0] = 0;		/* clean out the ebuf */
	rv_tmp = iscsi_control_process_request(opcode, arg->buf, ebuf,
					       ISCSI_CONTROL_REQ_MAX_BUFLEN,
					       dbuf, dbuflen, arg->flag);

	if (!rv_tmp && dbuflen) {
		rv = os_copy_to_user((void *) arg->addr[1], dbuf, dbuflen);
		if (rv) {
			rv = -ISCSI_EUSER;
			goto cleanup;
		}
	}

      cleanup:
	arg->buf[0] = ebuf[0];
	if (ebuf[0])
		os_strcpy(arg->buf, ebuf);

	rv = os_copy_to_user((void *) data, arg, sizeof(iscsi_control_args));
	if (rv)
		rv = -ISCSI_EUSER;

	if (arg)
		os_vfree(arg);
	if (ebuf)
		os_vfree(ebuf);
	if (kbuf)
		os_vfree(kbuf);
	if (dbuf)
		os_vfree(dbuf);

	if (!rv)
		rv = rv_tmp;
	return (rv < 0 ? rv : 0);
}
