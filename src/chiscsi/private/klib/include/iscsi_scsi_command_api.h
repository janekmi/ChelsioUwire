#ifndef __ISCSI_SCSI_COMMAND_API_H__
#define __ISCSI_SCSI_COMMAND_API_H__

#include <common/iscsi_scsi_command.h>

void __chiscsi_scsi_command_put(const char *, chiscsi_scsi_command *);
void __chiscsi_scsi_command_get(const char *, chiscsi_scsi_command *);
#define chiscsi_scsi_command_get(sc) __chiscsi_scsi_command_get(__func__, sc)
#define chiscsi_scsi_command_put(sc) __chiscsi_scsi_command_put(__func__, sc)

void chiscsi_scsi_command_display(chiscsi_scsi_command *sc, int detail);
chiscsi_scsi_command *iscsi_session_find_scmd_by_itt(iscsi_session *sess,
			iscsi_connection *conn, unsigned int itt,
			int check_doneq);
void chiscsi_scsi_command_release_ddp_tag(chiscsi_scsi_command *);
void chiscsi_scsi_command_release(chiscsi_scsi_command *, chiscsi_queue *);
int chiscsi_scsi_command_pool_init(chiscsi_queue *scq, int max);
chiscsi_scsi_command *chiscsi_scsi_command_alloc(iscsi_connection *, unsigned int);
int chiscsi_scsi_command_allocate_local_data(chiscsi_scsi_command *);

/* alloc & free */

/* scsi_command queue free */
void    iscsi_scmdq_free_by_conn(chiscsi_queue *, iscsi_connection *);
void    iscsi_scmdq_free_all(chiscsi_queue *);

/* burst data */
int     chiscsi_scsi_command_burst_send_pdus(chiscsi_scsi_command *, int);
int     chiscsi_scsi_command_burst_build_data_pdus(chiscsi_scsi_command *,
			unsigned int, unsigned int, unsigned int);

int	chiscsi_scsi_command_check_data_pattern(chiscsi_scsi_command *sc,
						unsigned int offset,
						unsigned int dlen,
						unsigned char pattern,
						int check_before_offset);

#endif /* ifndef __ISCSI_SCSI_COMMAND_API_H__ */
