/* iface.h */
#include <linux/version.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <common/iscsi_target_class.h>
#include <common/iscsi_scsi_command.h>
#include <common/iscsi_info.h>
#include "iface_util.h"

/* first login check status class and detail */
#define ISCSI_LOGIN_STATUS_CLASS_INITIATOR_ERROR 2
#define ISCSI_LOGIN_STATUS_CLASS_TARGET_ERROR   3

/* initiator error*/
#define ISCSI_LOGIN_STATUS_CLASS_INITIATOR_ERROR 2
#define ISCSI_LOGIN_STATUS_DETAIL_INIT_ERROR    0
#define ISCSI_LOGIN_STATUS_DETAIL_TARGET_NOT_FOUND 3
#define ISCSI_LOGIN_STATUS_DETAIL_TARGET_REMOVED 4
#define ISCSI_LOGIN_STATUS_DETAIL_INVALID_REQUEST 11

/* Target error*/
#define ISCSI_LOGIN_STATUS_CLASS_TARGET_ERROR   3
#define ISCSI_LOGIN_STATUS_DETAIL_TARG_ERROR    0
#define ISCSI_LOGIN_STATUS_DETAIL_SERVICE_UNAVAIL 1
#define ISCSI_LOGIN_STATUS_DETAIL_NO_RESOURCES  2

/* Storage Driver/Product ID version information */
#define DR_VERSION              "2.0"
#define PRODUCT_REV_MAX         4
#define PRODUCT_REV             DR_VERSION
#define VENDOR_ID_MAX           8
#define VENDOR_ID               "APITEST"       /* 8 bytes */
#define PRODUCT_ID_MAX          16
#define PRODUCT_ID              "API Test Target"
#define SCSI_ID_MAX             24
#define SCSI_ID_STR             "CHELSIO_API20"
#define SCSI_SN_MAX             16
#define SCSI_SN_STR             "0743003082011"

/* sector size defaults to 512 */
#define SECT_SIZE_SHIFT         9
#define SECT_SIZE               (1 << SECT_SIZE_SHIFT)
#define MAX_LUNS		4

#define MAX_Q_TYPES		1

#define ALLOC_SIZE              16384
#define ALLOC_SHIFT             14

#if 0
#define BUFFER_PAGE_SIZE        ALLOC_SIZE
#define BUFFER_PAGE_SHIFT       ALLOC_SHIFT
#endif

#define BUFFER_PAGE_SIZE        PAGE_SIZE
#define BUFFER_PAGE_SHIFT       PAGE_SHIFT

/* session information buffer */
#define MAX_DATA_BUFLEN         65536

/* Config_buffer */
#define MAX_CONFIG_BUFLEN       1024    

enum work_flag {
	MARK_DO_WORK = 1,
	MARK_FOR_WORK,
	MARK_ABORT_SCMD,
	MARK_TMF_SCMD
};

/* typedefs for structures */
typedef struct  storage_sglist  storage_sglist;
typedef struct  scmd_sgl        scmd_sgl;
typedef struct  iface_scmd_info iface_scmd_info;
typedef struct  luninfo         luninfo;

/* wrapper for chiscsi_sgvec */
struct storage_sglist {
	unsigned int sglist_boff;
	chiscsi_sgvec *sgvec;
	struct storage_sglist *sglist_next;
};

/* struct to keep track of allocated buffers */
struct scmd_sgl {
        unsigned int sgl_flag;
        unsigned int sgl_boff;
        unsigned int sgl_length;
        unsigned int sgl_vecs_nr;
	unsigned int sgl_boff_exp;
        chiscsi_sgvec *sgl_vec_last;
        unsigned char *sgl_vecs;
};

/* scsi command information */
struct iface_scmd_info {
        void                    *lock;
        unsigned int            flag;
        unsigned int            sip;
        unsigned int            sport;
        iface_scmd_info         *snext;
        chiscsi_scsi_command      *sc;
        scmd_sgl                sc_sgl;
        dma_addr_t              mapping;        /* for testing purpose */
};

#define qsearch_by_field(L,T,NP,Q,P,F,V)  \
        do { \
                lockq_##L(Q); \
                for (P = (T*)(Q)->q_head; (P) && (P)->F != (V); P = (P)->NP) \
                unlockq_##L(Q); \
        } while(0)


#define scmd_info_enqueue(L,Q,P) \
                ch_enqueue_tail(L,iface_scmd_info, snext,Q,P)
#define scmd_info_dequeue(L,Q,P) \
                ch_dequeue_head(L,iface_scmd_info, snext,Q,P)
#define scmd_info_ch_qremove(L,Q,P) \
                ch_qremove(L,iface_scmd_info, snext,Q,P)
#define scmd_info_qsearch_by_sc(L,Q,P,V) \
                qsearch_by_field(L,iface_scmd_info, snext,Q,P,sc,V)
#define scmd_info_qsearch_by_flag(L,Q,P,V) \
                qsearch_by_field(L,iface_scmd_info, snext,Q,P,flag,V)

#define scmd_set_bit(sc,bit) (sc)->sc_fpriv |= 1 << (bit)
#define scmd_test_bit(sc,bit) ((sc)->sc_fpriv & (1 << bit))

void *get_scmd_info_ptr(chiscsi_scsi_command *sc, int);

/*non-rwio functions*/
int     parse_cdb_rw_info(chiscsi_scsi_command *);
int     iscsi_target_lu_scsi_non_rwio_cmd_respond(chiscsi_scsi_command *);

int     read_command_execute(iface_scmd_info *, unsigned long long);
int     write_command_execute(iface_scmd_info *, unsigned long long);

/* function for config_buffer construction */
int     construct_config_buffer(void);
int     construct_reconfig_buffer(void);

/* Utility functions for portal */
int     addr_is_ipv6(char *);
int     convert_portal_to_ipv4(char *, unsigned int *);
int     convert_portal_to_ipv6(char *, unsigned int *, int);
int     decode_portal(char *, tcp_endpoint *);
int     decode_shadow_mode(char *);

/* Various Info api-call functions */
int     get_target_info(char *);
int     get_target_perf_info(tcp_endpoint *);
int     display_session_info(int, char *, void *);
int     get_session_information(unsigned long, char *, char *);
int 	get_one_session_info(void *);

/*lun infomtaiton */
struct luninfo {
        unsigned long                   flags;
        unsigned int                    lun;                    /* lun # */
        unsigned long long              size;
        unsigned int                    sect_shift;
        chiscsi_target_lun_class        *lclass;                /*registred target lun class*/
        struct kthread_info_struct      *kthinfo;               /* thread info to handle scmd work */
        chiscsi_queue                     *scinfoq[MAX_Q_TYPES];  /*q to keep info about the scmd and buffers(chiscsi_sgl)*/
};

extern luninfo lun[MAX_LUNS];
extern int num_luns;
