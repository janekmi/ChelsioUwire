#ifndef __ISCSI_TARGET_DEVICE_H__
#define __ISCSI_TARGET_DEVICE_H__

#include <common/version.h>
#include <common/iscsi_sgvec.h>
#include <common/iscsi_scsi_command.h>
#include <common/iscsi_pdu.h>
#include <common/iscsi_target_class.h>

chiscsi_target_lun *iscsi_target_session_lun_get(void *sessp, int lun);
#define iscsi_target_session_lun_put(lu)

#define LUN_PERSISTENT_PATH		"/etc/chelsio-iscsi/prdb"
#define CHELSIO_TARGET_CLASS		"CHELSIO"

typedef struct chiscsi_target_lun_scmd	chiscsi_target_lun_scmd;

/* Type Definitions */
/* ================ */

#define STM_SA_READ_KEYS		0x00
#define STM_SA_READ_RESERVATIONS   0x01
#define STM_SA_REPORT_CAPABILITIES 0x02

#define STM_SA_REGISTER            0x00
#define STM_SA_RESERVE             0x01
#define STM_SA_RELEASE             0x02
#define STM_SA_CLEAR               0x03
#define STM_SA_PREEMPT             0x04
#define STM_SA_PREEMPT_ABORT       0x05
#define STM_SA_REGISTER_IGNORE     0x06
#define STM_SA_REGISTER_MOVE       0x07

#define STM_TYP_NONE               0x00
#define STM_TYP_WRITE_EXCLUSIVE    0x01
#define STM_TYP_EXCLUSIVE_ACCESS   0x03
#define STM_TYP_WRITE_REGISTRANTS  0x05
#define STM_TYP_ACCESS_REGISTRANTS 0x06
#define STM_TYP_WRITE_ALL          0x07
#define STM_TYP_ACCESS_ALL         0x08



/**
 * pr_type -- Indicates type of active reservations.
 * - NONE              no reservations
 * - STANDARD          standard reservations
 * - PERSISTENT        persistent reservations
 */
typedef enum stm_pr_type {
	STM_RES_NONE,		/* 0: no reservations */
	STM_RES_STANDARD,	/* 1: standard reservations */
	STM_RES_PERSISTENT,	/* 2: persistent reservations */
} stm_pr_type_t;

#define SPC_APTPL_UNSUPPORTED	-1
#define SPC_APTPL_OFF		0
#define SPC_APTPL_ON		1
#define SPC_APTPL_NEED_TO_ERASE 2

void os_lun_scmd_memory_free_by_page(chiscsi_sgl *);
int os_lun_scmd_memory_alloc_by_page(chiscsi_scsi_command *, chiscsi_sgl *);
int os_lun_pi_memory_alloc_by_pages(chiscsi_scsi_command *, chiscsi_sgl *);
void os_lun_scsi_cmd_memory_release(chiscsi_scsi_command *);
void os_lun_pi_memory_release(chiscsi_scsi_command *);

 /**
 * Persisten Reservation/Registration Database
 *
 * This structure stores information on registrations/reservations
 * - valid:  validity flag
 * - initiator_id:  initiator identifier
 * - key:  reservation key
 * - type: reservation type
 * - port: port identifier (I_T_Nexus)
 */
typedef struct stm_pr_entry{
  int valid;
  char initiator_id[256];
  unsigned long long key;
  //uint64_t key;
  int type;
  int port;
} stm_pr_entry;

#define EXTERN  extern

#define	ISCSI_TARGET_LUN_SIZE	(sizeof(chiscsi_target_lun))

#define chiscsi_target_lun_enqueue(L,Q,P) \
	do { \
		ch_enqueue_tail(L,chiscsi_target_lun,next,Q,P); \
		chiscsi_target_lun_flag_set(P, LUN_QUEUED_BIT); \
	} while (0);
#define chiscsi_target_lun_dequeue(L,Q,P) \
		ch_dequeue_head(L,chiscsi_target_lun,next,Q,P)
#define chiscsi_target_lun_ch_qremove(L,Q,P) \
	do { \
		if (chiscsi_target_lun_flag_test(P, LUN_QUEUED_BIT)) \
                	ch_qremove(L,chiscsi_target_lun,next,Q,P); \
	} while (0)
#define chiscsi_target_lun_find_by_lunnum(L,Q,P,V) \
		ch_qsearch_by_field_value(L,chiscsi_target_lun,next,Q,P,lun,V)
#define chiscsi_target_lun_find_by_path(L,Q,P,S) \
		ch_qsearch_by_field_string(L,chiscsi_target_lun,next,Q,P,path,S)

#define chiscsi_target_lun_scmd_enqueue(L,Q,P) \
		ch_enqueue_tail(L,chiscsi_scsi_command,lsc_next,Q,P)
#define chiscsi_target_lun_scmd_dequeue(L,Q,P) \
		ch_dequeue_head(L,chiscsi_scsi_command,lsc_next,Q,P)
#define chiscsi_target_lun_scmd_ch_qremove(L,Q,P) \
                ch_qremove(L,chiscsi_scsi_command,lsc_next,Q,P)

void iscsi_target_scmd_assign_lu_worker(chiscsi_scsi_command *);
void iscsi_target_scmd_remove_from_lu_worker(chiscsi_scsi_command *);

#endif /* ifndef __ISCSI_TARGET_DEVICE_H__ */
