#ifndef	CXGBTOOL_FOISCSI_STOR_H
#define	CXGBTOOL_FOISCSI_STOR_H

#include <csio_services.h>
#include <csio_foiscsi_persistent.h>
#include <csio_foiscsi_ioctl.h>

#define DEFAULT_ISCSI_TARGET_PORT 3260

enum {
	CSIO_EINVAL	= 22,
	CSIO_ENOMEM	= 12,
	CSIO_ENODEV	= 19,
	CSIO_ENOSYS	= 38,

} csio_foiscsi_err;


extern int run_foiscsi_stor(int, char **);


#endif	/* CXGBTOOL_FOISCSI_STOR_H */
