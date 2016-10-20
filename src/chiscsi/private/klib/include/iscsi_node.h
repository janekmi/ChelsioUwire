#ifndef __ISCSI_NODE_H__
#define __ISCSI_NODE_H__

#include <common/iscsi_info.h>
#include <common/iscsi_target_class.h>

/*
 * iscsi node: target or initiator
 */

enum iscsi_node_flag_bits {
	NODE_FLAG_OFFLINE_BIT,	/* being removed */
	NODE_FLAG_ONLINE_BIT,	/* online */
	NODE_FLAG_UPDATING_BIT,	/* being updated */
};

enum iscsi_node_common_qtype {
	NODE_SESSQ,

	NODE_TARGET_Q_MAX
};

typedef struct iscsi_target_portal	iscsi_target_portal;
struct iscsi_target_portal {
	unsigned int flag;
	unsigned int grouptag;
	unsigned int redirect_to_ntags;
	unsigned int redirect_last_select;

	unsigned int timeout;
	/* when shadow mode is on, we won't have a portal ptr, so keep a copy
	 * of ip and port here */
	struct tcp_endpoint ep;
	iscsi_portal *portal;
	char *redirect_str;

	unsigned int *redirect_to_list;
};

#define ACL_FLAG_ALLR	0x1
#define ACL_FLAG_ALLW	0x2
#define ACL_FLAG_ALLRW	(ACL_FLAG_ALLR | ACL_FLAG_ALLW)	
#define ACL_FLAG_ISNS	0x20

typedef struct iscsi_target_acl iscsi_target_acl;
struct iscsi_target_acl {
	iscsi_target_acl *next;
	unsigned long isns_pid;		/* for acls from isns client only */
	unsigned int pos;		/* for acls from config only */
	unsigned int flag;
	unsigned int iaddr_cnt;
	unsigned int taddr_cnt;
	unsigned int iname_cnt;
	struct tcp_endpoint *iaddr_list;
	struct tcp_endpoint *taddr_list;
	char *iname;
	unsigned char *rmask;		/* for acls from config file only */
	unsigned char *wmask;		/* for acls from config file only */
};

struct iscsi_node {
	/* os-dependent struct */

	/* counter is the # of conns currently in login phase */
	void   *os_data;
	chiscsi_queue *n_queue[NODE_TARGET_Q_MAX];

	/* os-independent fields */
	iscsi_node *n_next;

	/* automic bit operations, iscsi_node_flag_bits */
	unsigned long n_fbits;

	/* normal bit operations */
	unsigned int n_flag;
#define F_TARGET_PORTAL_REMOVED	0x1
#define F_TARGET_LUN_CHANGED	0x2

	unsigned int n_id;	/* an unique id for this node */
	char   n_name[256];
	char   n_alias[256];
	struct iscsi_session_settings sess_keys;
	struct iscsi_conn_settings conn_keys;
	struct iscsi_chap_settings chap;

	int     n_keys_max[NODE_KEYS_TYPE_MAX];
	iscsi_keyval *n_keys[NODE_KEYS_TYPE_MAX];

	void   *n_auth;

	/* used during configuration update */
	//iscsi_keyval *n_keys_save[NODE_KEYS_TYPE_MAX];
	//void   *n_auth_save;
	
	/* redirect portal information - initiator only */
//	char *n_redirect_str;

	/* Shadow Mode on or off - Target Only*/
	//int n_shadow_mode;

	/* Whether redirection is enabled on this Node - Target only*/
	int n_redirect_on;

	chiscsi_target_class *tclass;
	unsigned short t_tsih_next;
	unsigned char filler[2];
	void *scst_target;
	
	struct iscsi_target_config_settings config_keys;
        unsigned int lu_cnt;
        chiscsi_target_lun **lu_list;

        unsigned int portal_active;     /* # listening server started */
        unsigned int portal_cnt;
        iscsi_target_portal *portal_list;

	/* ACL */
	unsigned int acl_mask_len;
	iscsi_target_acl *acl_list;
	iscsi_target_acl *acl_isns_list;
};

#define ISCSI_NODE_SIZE (sizeof(iscsi_node))

#define iscsi_node_flag_set(n,bit)   \
                os_set_bit_atomic(&((n)->n_fbits),bit)
#define iscsi_node_flag_clear(n,bit) \
                os_clear_bit_atomic(&((n)->n_fbits),bit)
#define iscsi_node_flag_test(n,bit)  \
                os_test_bit_atomic(&((n)->n_fbits),bit)
#define iscsi_node_flag_testnset(n,bit)  \
                os_test_and_set_bit_atomic(&((n)->n_fbits),bit)
#define iscsi_node_flag_testnclear(n,bit) \
                os_test_and_clear_bit_atomic(&((n)->n_fbits),bit)

#define iscsi_node_enqueue(L,Q,P)   ch_enqueue_tail(L,iscsi_node,n_next,Q,P)
#define iscsi_node_dequeue(L,Q,P)   ch_dequeue_head(L,iscsi_node,n_next,Q,P)
#define iscsi_node_ch_qremove(L,Q,P)   ch_qremove(L,iscsi_node,n_next,Q,P)


void    iscsi_node_free(iscsi_node *);
iscsi_node *iscsi_node_alloc(void);

iscsi_node *iscsi_node_find_by_name(char *);
iscsi_node *iscsi_node_find_by_alias(char *);

int     iscsi_node_remove(iscsi_node *, int, char *, unsigned int);
int     iscsi_node_add(char *, unsigned int, char *, unsigned int, 
			chiscsi_target_class *);
int 	iscsi_node_handle_redirect(iscsi_node *, int, char *, unsigned int, int);
int     iscsi_node_reconfig(iscsi_node *, char *, unsigned int, char *,
			    unsigned int, chiscsi_target_class *);

int     iscsi_node_get_target_names(char *, int);
int     iscsi_node_retrieve_config(void *, char *, int, int);

int	iscsi_node_drop_session(unsigned long sess_hndl);
int     iscsi_node_get_session(iscsi_node *, char *, char *, int);

/* ACL */
#define iscsi_node_acl_enable(n) (n)->config_keys.acl_en

int iscsi_acl_config(iscsi_node *node, char *ebuf);
int iscsi_acl_config_display(iscsi_node *node, char *buf, int buflen);
int iscsi_acl_isns_config(unsigned long pid, iscsi_node *node, char *buf,
			int buflen, char *ebuf);
void iscsi_acl_list_free(iscsi_target_acl *list);

int iscsi_acl_session_true_lun(iscsi_session *sess, int lun);
int iscsi_acl_target_accessible(iscsi_node *node, char *iname,
			struct chiscsi_tcp_endpoints *eps);
/* return 0 if pass acl, < 0 otherwise */
int iscsi_acl_session_check(iscsi_session *sess);
int iscsi_acl_connection_check(iscsi_connection *conn);
int iscsi_acl_scsi_command_check(chiscsi_scsi_command *sc);
int iscsi_acl_permission_check(iscsi_node *, iscsi_node *);

int iscsi_node_has_dif_dix_enabled_lun(iscsi_node *, unsigned int);

int chiscsi_target_is_chelsio(chiscsi_target_class *);

#endif /* ifndef __ISCSI_NODE_H__ */
