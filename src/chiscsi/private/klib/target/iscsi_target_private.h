#ifndef __ISCSI_TARGET_PRIVATE_H__
#define __ISCSI_TARGET_PRIVATE_H__

/*
 * iscsi target data structs
 */

#include <common/os_builtin.h>
#include <common/iscsi_common.h>
#include <common/iscsi_control.h>
#include <common/iscsi_target_device.h>
#include <iscsi_control_defs.h>
#include <iscsi_structs.h>
#include <iscsi_global.h>
#include <iscsi_text.h>
#include <iscsi_portal.h>
#include <iscsi_config_keys.h>
#include <iscsi_session_keys.h>
#include <iscsi_connection_keys.h>
#include <iscsi_socket_api.h>
#include <iscsi_auth_api.h>
#include <iscsi_sgvec_api.h>
#include "iscsi_target_scsi.h"

/* TMF */
#define IT_TMF_ABORT_COMPARE_CMDSN      0x1
#define IT_TMF_ABORT_COMPARE_LUN        0x2
#define IT_TMF_ABORT_NEED_SEND_SENSE    0x10

void target_scsi_command_release(chiscsi_scsi_command *);
void target_session_tmf_reset(iscsi_session *);
int it_rcv_login_request(iscsi_pdu *);
int target_login_respond(iscsi_connection *);
int target_rcv_text_request(iscsi_pdu *);
int it_rcv_tmf_request(iscsi_pdu *);
int it_send_tmf_response(iscsi_connection *, unsigned int, unsigned char);
int it_xmt_asyncmsg(iscsi_connection * conn, unsigned char event,
			unsigned long long lun, unsigned int len,
			unsigned char *buf);

int iscsi_target_session_close(iscsi_session *);
int iscsi_target_connection_close(iscsi_connection *);

/*
 * iscsi target
 */
int     iscsi_target_display_short(iscsi_node *, unsigned char *, int);
int     iscsi_target_display_long(iscsi_node *, unsigned char *, int);


int     iscsi_target_portal_find(iscsi_node *, iscsi_portal *,
				  unsigned int *, unsigned int *);
int iscsi_target_portals_update(iscsi_node *node, char *ebuf);
int iscsi_target_portals_remove(iscsi_node *node);

void    iscsi_target_scsi_command_done(chiscsi_scsi_command *, int err);

/* target thread */
int     iscsi_target_main_thread_start(iscsi_thread *, int);
int     iscsi_target_main_thread_stop(iscsi_thread *, int);
int     iscsi_target_worker_thread_start(iscsi_thread *, int);
int     iscsi_target_worker_thread_stop(iscsi_thread *, int);
int     iscsi_target_lu_thread_start(iscsi_thread *, int);
int     iscsi_target_lu_thread_stop(iscsi_thread *, int);

/*
 * lun
 */
void chiscsi_target_lun_class_cleanup(void);
int chiscsi_target_lun_class_init(void);

void    iscsi_target_lu_cleanup(void);

//int     iscsi_target_lu_config_start(iscsi_node *, iscsi_keyval *, char *, int);
//int     iscsi_target_lu_config_finish(iscsi_node *);
//int     iscsi_target_lu_config_abort(iscsi_node *);
//int     iscsi_target_lu_config_release(iscsi_node *);
int     iscsi_target_lu_flush(iscsi_node *, int, int);

int	chiscsi_target_luns_has_property(iscsi_node *node, int property_bit);

int     iscsi_target_reserve_clear(iscsi_node *);
int     iscsi_target_lu_reserve_clear(iscsi_node *, unsigned int);
int iscsi_target_lu_reserve_clear_by_session(iscsi_session *); 

int stm_persistent_reserve_check(chiscsi_scsi_command *,chiscsi_target_lun *);
chiscsi_target_lun *iscsi_target_lu_find_by_lun(iscsi_node *, unsigned int);
int is_chelsio_lun_class(chiscsi_target_lun_class *sc);

/* 
 * data xfer
 */
int it_scmd_write_init(chiscsi_scsi_command *sc, iscsi_pdu *pdu);
int it_scmd_read_init(chiscsi_scsi_command *sc);
int iscsi_target_write_burst_complete(chiscsi_scsi_command *sc);
int it_scmd_read_continue(chiscsi_scsi_command *);
int it_scmd_write_continue(chiscsi_scsi_command *);
void it_scmd_read_buffer_acked(chiscsi_scsi_command *sc, unsigned int ttt);
int it_scmd_send_sense_status(chiscsi_scsi_command *sc);
void it_scmd_lun_check_error(chiscsi_scsi_command *sc, int first_time);
void it_scmd_exe_check_error(chiscsi_scsi_command *sc);
void it_scmd_release_backend_buffers(chiscsi_scsi_command *, unsigned int max);
int it_scmd_exe_check_acl_error(chiscsi_scsi_command *sc);
int it_scmd_state_abortable(chiscsi_scsi_command *sc);
void it_scmd_acked(chiscsi_scsi_command *sc);

int iscsi_target_rcv_scsi_command(iscsi_pdu *);
int iscsi_target_rcv_data_out(iscsi_pdu *);
int iscsi_target_scsi_command_execute(chiscsi_scsi_command *);
int iscsi_target_scsi_command_respond(chiscsi_scsi_command *);
void iscsi_target_scsi_command_check_execution_status(chiscsi_scsi_command *sc);
void iscsi_target_scsi_command_check_tmf_condition(chiscsi_scsi_command *sc);

iscsi_node *target_create_default_keys(char *name, char *alias, int enq);
int it_xmt_nop_in(iscsi_connection *conn, int reply, int priority,
                        unsigned int len, unsigned int offset, void *scmd,
                        unsigned int *ttt);
int target_rcv_text_request(iscsi_pdu *pdu);


int iscsi_target_lu_scsi_non_rwio_cmd_respond(chiscsi_scsi_command *);
int it_chelsio_target_check_opcode(chiscsi_scsi_command *);

#endif
