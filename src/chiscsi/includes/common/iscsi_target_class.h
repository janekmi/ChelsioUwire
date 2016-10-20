#ifndef __CHISCSI_TARGET_EXPORT_H__
#define __CHISCSI_TARGET_EXPORT_H__

#include "iscsi_tcp.h"
#include "iscsi_sgvec.h"
#include "iscsi_scsi_command.h"
#include "iscsi_chap.h"
#include "iscsi_info.h"

typedef struct chiscsi_target_class	chiscsi_target_class;
typedef struct chiscsi_target_lun_class	chiscsi_target_lun_class;
typedef struct chiscsi_target_lun		chiscsi_target_lun;

/*
 * target class
 */
struct chiscsi_target_class {
	/* public */
	char *class_name;
	unsigned int property;
	int (*fp_config_parse_luns)(chiscsi_target_lun *lu,
				    char *buf,
				    int buflen,
				    char *ebuf);
	void (*fp_first_login_check)(unsigned long hndl,
				     char *initiator_name,
				     char *target_name,
				     chiscsi_tcp_endpoints *eps);
	void (*fp_login_stage_check)(unsigned long hndl,
				     unsigned char login_stage,
				     char *initiator_name,
				     char *target_name,
				     chiscsi_tcp_endpoints *eps);
	void (*fp_chap_info_get)(char *initiator_name,
				 char *target_name,
				 chap_info *chap);
	unsigned long (*fp_session_added)(unsigned long sess_hndl,
				 unsigned char isid[6],
				 char *initiator_name,
				 char *target_name);
	void (*fp_session_removed)(unsigned long sess_hndl,
				 char *initiator_name,
				 char *target_name);
	int (*fp_discovery_target_accessible)(unsigned long hndl,
					      char *initiator_name,
					      char *target_name,
				     	      chiscsi_tcp_endpoints *eps);
	int (*fp_select_redirection_portal)(char *target_name,
					char *initiator_name,
					chiscsi_tcp_endpoints *eps);
					    
	/* private */
	chiscsi_target_class *next;	
	chiscsi_target_lun_class *lclass_list;
};
#define chiscsi_target_class_property_set(classp,bit) \
		(classp)->property |= 1 << bit
#define chiscsi_target_class_property_clear(classp,bit) \
		(classp)->property &= ~(1 << bit)
#define chiscsi_target_class_property_test(classp,bit) \
		((classp)->property & (1 << bit))

void chiscsi_target_first_login_check_done(unsigned long hndl,
					   unsigned char login_status_class,
					   unsigned char login_status_detail,
					   unsigned int max_cmd);
void chiscsi_target_login_stage_check_done(unsigned long hndl,
					   unsigned char login_status_class,
					   unsigned char login_status_detail);
int chiscsi_target_session_abort(unsigned long sess_hndl);

int chiscsi_target_class_register(chiscsi_target_class *target_class);
int chiscsi_target_class_deregister(char *class_name);

/*
 * target lun class
 */
enum chlun_class_property_bits {
        LUN_CLASS_SCSI_PASS_THRU_BIT,
        LUN_CLASS_MULTI_PHASE_DATA_BIT,
        LUN_CLASS_HAS_CMD_QUEUE_BIT,	/* LU maintains its own queue, this
					 should be the default mode, so it
					 won't exe. in the iscsi target stack
					 context */
	LUN_CLASS_CMD_RELEASE_WAIT_BIT, /* for completed chiscsi_iscsi_command  
					   do not release until instructed
					   by the backend (i.e.
					   chiscsi_scsi_cmd_ready_to_release
					   is called.
					 */
        LUN_CLASS_DUP_PATH_ALLOWED_BIT,

	LUN_CLASS_TYPE_SCST_BIT,        /* Aborted commands follow a different
					   path for SCST. */
	LUN_CLASS_CHELSIO_BIT,		/* Chelsio lun class */
};

struct chiscsi_target_lun_class {
	/*
	 * public
	 */
	char *class_name;
	unsigned int property;
	unsigned int lun_extra_size;
	/*
	 * mandatory only for chelsio target/lun
	 */
	int (*fp_config_parse_options)(chiscsi_target_lun *lu, char *buf,
				int buflen, char *ebuf);
	int (*fp_attach)(chiscsi_target_lun *lu, char *ebuf, int ebuflen);
	void (*fp_detach)(chiscsi_target_lun *lu);
	int (*fp_reattach)(chiscsi_target_lun *old_lu, chiscsi_target_lun *new_lu,
				char *ebuf, int ebuflen);
	int (*fp_flush)(chiscsi_target_lun *lu);
	int (*fp_queued_scsi_cmd_exe)(chiscsi_scsi_command *scmd);

	/*
	 * mandatory: any backend target/lun 
	 */
	int (*fp_scsi_cmd_cdb_rcved)(chiscsi_scsi_command *scmd);
	void (*fp_scsi_cmd_data_xfer_status)(chiscsi_scsi_command *scmd,
				unsigned char *xfer_sreq_buf,
				unsigned int xfer_sgcnt,
				unsigned int xfer_offset,
				unsigned int xfer_buflen);
	void (*fp_scsi_cmd_cleanup)(chiscsi_scsi_command *scmd);
	int (*fp_scsi_cmd_abort)(chiscsi_scsi_command *scmd);
	void (*fp_scsi_cmd_abort_status) (unsigned int	sc_lun, 
				unsigned int sc_cmdsn, 
				unsigned int sc_itt,
				unsigned int sc_xfer_sgcnt,
				unsigned char *sc_xfer_sreq_buf,
				void 	*sc_sdev_hndl);
	int (*fp_tmf_execute)(unsigned long sess_tclass,
				unsigned long hndl,
				unsigned char immediate_cmd,
				unsigned char tmf_func, unsigned int lun,
				chiscsi_scsi_command *scmd);

	/*
	 * private field, used by iscsi stack only
	 */
	chiscsi_target_lun_class *next;
	chiscsi_target_class *tclass;
};

int chiscsi_target_lun_class_register(chiscsi_target_lun_class *lun_class,
				      char *class_name);
int chiscsi_target_lun_class_deregister(char *lun_class_name,
				      	char *target_class_name);

int chiscsi_scsi_cmd_execution_status(chiscsi_scsi_command *scmd,
				unsigned char *xfer_sreq_buf,
				unsigned int xfer_sgcnt,
				unsigned int xfer_offset,
				unsigned int xfer_buflen);
int chiscsi_scsi_cmd_buffer_ready(chiscsi_scsi_command *scmd,
				unsigned char *xfer_sreq_buf,
				unsigned int xfer_sgcnt,
				unsigned int xfer_offset,
				unsigned int xfer_buflen);
int chiscsi_tmf_execution_done(unsigned long hndl,
				unsigned char tmf_response,
				chiscsi_scsi_command *scmd);
int chiscsi_scsi_cmd_abort(chiscsi_scsi_command *scmd);
int chiscsi_scsi_cmd_abort_status(chiscsi_scsi_command *scmd);
void chiscsi_iscsi_command_dump(chiscsi_scsi_command *scmd);
void chiscsi_scsi_cmd_ready_to_release(chiscsi_scsi_command *scmd);

/* target configuration APIs */
int chiscsi_target_add(void *sdev_priv, char *target_name, char *target_class_str,
			char *config_buffer, int config_buflen);
int chiscsi_target_remove(void *sdev_priv, char *target_name);
int chiscsi_target_reconfig(void *sdev_priv, char *target_name, char *target_class_str,
			char *config_buffer, int config_buflen);

/*
 * lun 
 */

#define IT_PRODUCT_REV_MAX	4
#define IT_PRODUCT_REV		DRIVER_VERSION
#define IT_PRODUCT_ID_MAX	16
#define IT_PRODUCT_ID		"CHISCSI Target"
#define IT_VENDOR_ID_MAX	8
#define IT_SCSI_ID_MAX		24
#define IT_SCSI_SN_MAX		16
#define IT_SCSI_WWN_MAX		16

/* sector size defaults to 512 */
#define SECT_SIZE_SHIFT		9
#define SECT_SIZE		(1 << SECT_SIZE_SHIFT)


/*
 * Persisten Reservation/Registration Database Entry
 *
 * This structure stores information on registrations/reservations
 * - valid:  validity flag
 * - initiator_id:  initiator identifier
 * - key:  reservation key
 * - type: reservation type
 * - port: port identifier (I_T_Nexus)
 */

typedef struct pr_entry{
	int valid;
	char initiator_id[256];
	unsigned long long key;
	int type;
	int port;
} pr_entry;

#define STM_PRESERVE_REGISTRATION_MAX	16 /* maximum registrations */
struct reservation {
	/* for reserve-release */
	unsigned long rsvd_sess_hndl;

	/* for persisten reservation */
	int pr_type;
	int pr_generation;
	pr_entry pr_registrations[STM_PRESERVE_REGISTRATION_MAX];
	pr_entry pr_reservation;
};

enum lun_flag_common_bits {
	LUN_BLKDEV_BIT,
	LUN_QUEUED_BIT,
	LUN_OFFLINE_BIT,
	LUN_UPDATING_BIT,

	LUN_RESERVED_BIT,

	/* property modifier */
	LUN_RO_BIT,
	LUN_FLAG_MODIFIER_BIT_START = LUN_RO_BIT,
	LUN_NULLRW_BIT,
	LUN_SYNC_BIT,
	LUN_NONEXCL_BIT,
	LUN_NOWCACHE_BIT,
	LUN_PASSTHRU_UNKNOWN_ONLY_BIT,
	LUN_PASSTHRU_ALL_BIT,
	
	LUN_FLAG_MODIFIER_BIT_END = LUN_PASSTHRU_ALL_BIT,

	LUN_T10DIX_BIT,
	LUN_T10DIF_BIT,

	LUN_FLAG_COMMON_BIT_MAX
};

struct chiscsi_target_lun {
	/* private */
	chiscsi_target_lun *next;
	chiscsi_target_lun *lun_tmp;
	void *os_data;
	unsigned long tnode_hndl;

	struct reservation rsv; /* reservation */
	int aptpl;	/* APTPL support for this LUN */
	unsigned long aptpl_fhndl;

	/* public */
	chiscsi_target_lun_class *class;	
	char *path;
	unsigned long flags;
	unsigned int lun;	/* lun # */	
	unsigned long long size;
	unsigned int sect_shift;
	unsigned int dif_type;
	unsigned int prot_guard;
	char prod_id[IT_PRODUCT_ID_MAX + 1];
	char scsi_id[IT_SCSI_ID_MAX + 1];
	char scsi_sn[IT_SCSI_SN_MAX + 1];
	char scsi_wwn[IT_SCSI_WWN_MAX + 1];
	unsigned int workers;
	void *priv_data;
};

#define chiscsi_target_lun_flag_test(lun,bit) ((lun)->flags & (1 << bit))
#define chiscsi_target_lun_flag_set(lun,bit) ((lun)->flags |= 1 << (bit))
#define chiscsi_target_lun_flag_clear(lun,bit) ((lun)->flags &= ~(1 << (bit)))

#endif
