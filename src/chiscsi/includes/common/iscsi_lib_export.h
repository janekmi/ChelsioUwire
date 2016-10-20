#ifndef __ISCSI_EXPORT_H__
#define __ISCSI_EXPORT_H__

#include <common/iscsi_common.h>
#include <common/os_export.h>
#include <common/iscsi_error.h>
#include <common/iscsi_sgvec.h>
#include <common/iscsi_scsi_command.h>
#include <common/iscsi_pdu.h>
#include <common/iscsi_socket.h>
#include <common/iscsi_offload.h>

/* 
 * exported library function proto-types
 */

/* init & cleanup */
int     iscsi_common_init(int);
int     iscsi_common_cleanup(void);

/* ioctl */
int     iscsi_control_request(int, unsigned long, unsigned long);

int	iscsi_display_byte_string(
char *caption, 
unsigned char *bytes,
			int start, 
int maxlen,
 char *obuf,
 int obuflen);

/*
 *  * copy data (may not be page-aligned) from fsg to page-aligned tsg at offset.
 *   * calling routine should make sure the data is mapped, if needed.
 *    */
int chiscsi_sglist_copy_sgdata(unsigned int offset,
                                chiscsi_sgvec * fsg, unsigned int fsgcnt,
                                chiscsi_sgvec * tsg, unsigned int tsgcnt);


#endif /* ifdef __ISCSI_EXPORT_H__ */
