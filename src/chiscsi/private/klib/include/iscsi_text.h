#ifndef ISCSI_KEYS_H
#define ISCSI_KEYS_H

/*
 * iscsi key value pair handling
 */

#include <common/iscsi_queue.h>

#define ISCSI_NAME_LEN_MAX		223
#define ISCSI_ALIAS_LEN_MAX		255
#define ISCSI_KEY_NAME_MAX_LEN		63
#define ISCSI_TEXT_VALUE_MAX_LEN	255

#define ISCSI_KV_WRITE_NO_SEPERATOR	'Z'	/* for iscsi_kvp_write_text */

#define ISCSI_CONFIG_KEY_SEPERATOR      ':'

/*
 * key-value pair data structures
 */

typedef struct iscsi_string iscsi_string;
typedef struct iscsi_string_pair iscsi_string_pair;
typedef struct iscsi_keydef iscsi_keydef;
typedef struct iscsi_value iscsi_value;
typedef struct iscsi_keyval iscsi_keyval;

/* text key-value string pairs */
struct iscsi_string {
	iscsi_string *s_next;
	char   *s_str;
};

struct iscsi_string_pair {
	struct iscsi_string_pair *p_next;
	unsigned int p_seq;
	unsigned int p_flag;
	unsigned int p_keylen;
	char   *p_key;
	iscsi_string p_val;
};

#define string_pair_enqueue(L,Q,P) \
			ch_enqueue_tail(L,iscsi_string_pair,p_next,Q,P)
#define string_pair_dequeue(L,Q,P) \
			ch_dequeue_head(L,iscsi_string_pair,p_next,Q,P)
#define string_pair_ch_qremove(L,Q,P)	ch_qremove(L,iscsi_string_pair,p_next,Q,P)

/* text key definition */
struct iscsi_keydef {
	char    name[ISCSI_KEY_NAME_MAX_LEN + 1];
	int     vtype;
	unsigned int property;
	unsigned int val_dflt;
	unsigned int val_min;
	unsigned int val_max;
	int     (*fp_decode) (int mode, char *, iscsi_value *, char *);
	int     (*fp_post_decode) (iscsi_keyval *, iscsi_value *, char *);
	int     (*fp_encode) (char *, iscsi_value *);
	int     (*fp_size) (iscsi_value *);
	int     (*fp_compute) (iscsi_keyval *, iscsi_keyval *);
	int     (*fp_compute_check) (iscsi_keyval *, iscsi_keyval *);
	/* fp_value_add and fp_value_remove is used for key-value add and remove
	 * fp_value_remove is mandatory for keys that can be declared multiple 
	 * times (i.e, ISCSI_KEY_DECLARE_MULTIPLE is set)
	 */
	int     (*fp_value_add) (iscsi_value *, iscsi_keyval *, char *);
	int     (*fp_value_remove) (iscsi_value *, iscsi_keyval *, char *);
};

/* ISCSI_VALUE_NUM_COUNT_MAX is 7 = 
 *
 *  for PortalGroup (7)
 * 	1 x IPv6 address (4) + 
 * 	1 x portal port (1) +
 * 	1 x portal group tag (1) +
 * 	1 x portal timeout (1)
 * the redirect groups are kept in string format and parsed at
 * 	portal starting time
 *
 * for ACL (5)
 *      1 x # of initiator names
 *      1 x # of src ip addresses
 * 	1 x # of dst ip addresses
 *      1 x # lun mask (<= 1)
 *      1 x # ALL R/W flag
 */ 
#define ISCSI_VALUE_NUM_COUNT_MAX	7	

/* ISCSI_VALUE_STR_COUNT_MAX is 4 = 
 *
 *  for ACL (4)
 *     1 x initiator name list
 *     1 x saddr list
 *     1 x daddr list
 *     1 x lun mask list
*/ 
#define ISCSI_VALUE_STR_COUNT_MAX	4

/* ISCSI_VALUE_DATA_COUNT_MAX is 1 */
#define ISCSI_VALUE_DATA_COUNT_MAX	1

/* for PortalGroup */
#define ISCSI_VALUE_NUM_IDX_PG_IP	0
#define ISCSI_VALUE_NUM_IDX_PG_PORT	(ISCSI_IPADDR_LEN / sizeof(unsigned int))
#define ISCSI_VALUE_NUM_IDX_PG_TAG	(ISCSI_VALUE_NUM_IDX_PG_PORT + 1)
#define ISCSI_VALUE_NUM_IDX_PG_TIMEOUT	(ISCSI_VALUE_NUM_IDX_PG_TAG + 1)

/* for ACL */
#define ISCSI_VALUE_NUM_ACL_INAME_IDX	0
#define ISCSI_VALUE_NUM_ACL_SADDR_IDX	1
#define ISCSI_VALUE_NUM_ACL_DADDR_IDX	2
#define ISCSI_VALUE_NUM_ACL_LUN_IDX	3
#define ISCSI_VALUE_NUM_ACL_LUNALL_IDX	4

#define ISCSI_VALUE_STR_ACL_INAME_IDX	0
#define ISCSI_VALUE_STR_ACL_SADDR_IDX	1
#define ISCSI_VALUE_STR_ACL_DADDR_IDX	2
#define ISCSI_VALUE_STR_ACL_LUN_IDX	3

/* iscsi_value v_flag */
#define ISCSI_VALUE_FLAG_LOCKED		0x80	/* do not free the value */

struct iscsi_value {
	struct iscsi_value *v_next;	/* next value in list */
	unsigned int v_pos;		/* for multiple declarations */
	unsigned int v_type;
	unsigned char v_flag;
	unsigned char v_num_used;
	unsigned char v_str_used;
	unsigned char v_data_used;
	unsigned int v_num[ISCSI_VALUE_NUM_COUNT_MAX];
	void   *v_data[ISCSI_VALUE_DATA_COUNT_MAX];
	char   *v_str[ISCSI_VALUE_STR_COUNT_MAX];
};

/* key-value pair struct */
struct iscsi_keyval {
	iscsi_keyval *kv_next;
	iscsi_keydef *kv_def;
	char   *kv_name;
	unsigned int kv_flags;
	unsigned int kv_vtype;
	unsigned int kv_rcvcnt;
	unsigned int kv_rcvseq;	/* sequence in the receive buffer */
	iscsi_value *kv_valp;
};

#define keyval_enqueue(L,Q,P)	ch_enqueue_tail(L,iscsi_keyval,kv_next,Q,P)
#define keyval_dequeue(L,Q,P)	ch_dequeue_head(L,iscsi_keyval,kv_next,Q,P)
#define keyval_ch_qremove(L,Q,P)	ch_qremove(L,iscsi_keyval,kv_next,Q,P)

/*
 * iscsi_value types
 */
enum value_type {
	ISCSI_VALUE_TYPE_RESPONSE,
	ISCSI_VALUE_TYPE_TEXT,
	ISCSI_VALUE_TYPE_BOOLEAN,
	ISCSI_VALUE_TYPE_LIST,
	ISCSI_VALUE_TYPE_NUMERIC,
	ISCSI_VALUE_TYPE_NUMERIC_RANGE,
	ISCSI_VALUE_TYPE_NUMERIC_ENCODE,
	ISCSI_VALUE_TYPE_NUMERIC_ENCODE_HEX,
	ISCSI_VALUE_TYPE_NUMERIC_ENCODE_BASE64
};

/*
 * key-value pair flags 
 */

#define ISCSI_KV_FLAG_DECLARED			0x1
#define ISCSI_KV_FLAG_COMPUTED			0x2
#define ISCSI_KV_FLAG_REJECT			0x4
#define ISCSI_KV_FLAG_NOTUNDERSTOOD		0x8
#define ISCSI_KV_FLAG_IRRELEVANT		0x10
#define ISCSI_KV_FLAG_DUPLICATE			0x20
#define ISCSI_KV_FLAG_RESPONSE \
	(ISCSI_KV_FLAG_NOTUNDERSTOOD | ISCSI_KV_FLAG_IRRELEVANT | \
 	 ISCSI_KV_FLAG_REJECT )

#define ISCSI_KV_FLAG_SEND			0x40
#define ISCSI_KV_FLAG_SENT			0x80
#define ISCSI_KV_FLAG_DROP_AFTER_SEND		0x100
#define ISCSI_KV_FLAG_DISPLAY			0x200
#define ISCSI_KV_FLAG_DISPLAY_DETAIL		0x400

#define ISCSI_KV_FLAG_NO_VALUE			0x800

/*
 * iscsi key properties
 */
#define ISCSI_KEY_SENDER_TARGET			0x1	/* sent by target */
#define ISCSI_KEY_SENDER_INITIATOR		0x2	/* sent by initiator */
#define ISCSI_KEY_SENDER_TARGET_LOGIN		0x4	/* sent by target during login */
#define ISCSI_KEY_SENDER_INITIATOR_LOGIN	0x8	/* sent by initiator during login */
#define ISCSI_KEY_SENDER_TARGET_FFP		0x10	/* sent by target during FFP */
#define ISCSI_KEY_SENDER_INITIATOR_FFP		0x20	/* sent by initiator during FFP */
#define ISCSI_KEY_SENDER_TARGET_CONFIG		0x40	/* target config key */
#define ISCSI_KEY_SENDER_INITIATOR_CONFIG	0x80	/* initiator config key */

#define ISCSI_KEY_SENDER_ALL_CONFIG	\
		(ISCSI_KEY_SENDER_TARGET_CONFIG | \
		ISCSI_KEY_SENDER_INITIATOR_CONFIG)

#define ISCSI_KEY_SENDER_TARGET_ALL	\
		(ISCSI_KEY_SENDER_TARGET | \
		 ISCSI_KEY_SENDER_TARGET_LOGIN | \
	 	 ISCSI_KEY_SENDER_TARGET_FFP | \
		 ISCSI_KEY_SENDER_TARGET_CONFIG)

#define ISCSI_KEY_SENDER_INITIATOR_ALL	\
		(ISCSI_KEY_SENDER_INITIATOR | \
		 ISCSI_KEY_SENDER_INITIATOR_LOGIN | \
		 ISCSI_KEY_SENDER_INITIATOR_FFP | \
		 ISCSI_KEY_SENDER_INITIATOR_CONFIG)

#define ISCSI_KEY_CHANGABLE			0x100	/* value can be changed */
#define ISCSI_KEY_DECLARATIVE			0x200

#define ISCSI_KEY_DECLARE_MULTIPLE		0x1000	/* can be declared multiple times */
#define ISCSI_KEY_HAS_DEFAULT			0x2000
#define ISCSI_KEY_HAS_MIN			0x4000
#define ISCSI_KEY_HAS_MAX			0x8000
#define ISCSI_KEY_ALLOW_EMPTY_VALUE		0x10000
#define ISCSI_KEY_IRRELEVANT_IN_DISCOVERY	0x20000

#define ISCSI_KEY_STAGE_LOGIN_SECURITY		0x100000
#define ISCSI_KEY_STAGE_LOGIN_OPERATIONAL	0x200000
#define ISCSI_KEY_STAGE_FFP			0x400000

#define ISCSI_KEY_STAGE_LOGIN	\
		(ISCSI_KEY_STAGE_LOGIN_SECURITY | \
		 ISCSI_KEY_STAGE_LOGIN_OPERATIONAL)

#define ISCSI_KEY_STAGE_ALL	\
		(ISCSI_KEY_STAGE_LOGIN | ISCSI_KEY_STAGE_FFP)

/* display the key in summary or detail mode */
#define ISCSI_KEY_DISPLAY_MODE_SUMMARY		0x1000000
#define ISCSI_KEY_DISPLAY_MODE_DETAIL		0x2000000

/*
 *  key types and defines
 */

enum iscsi_node_key_types {
	NODE_KEYS_CONNECTION,
	NODE_KEYS_SESSION,
	NODE_KEYS_CONFIG,

	NODE_KEYS_TYPE_MAX
};

enum iscsi_decode_mode {
	ISCSI_KV_DECODE_OP_ADD = 1, /* decode for adding */
	ISCSI_KV_DECODE_OP_REMOVE = 2, /* decode for remove */
	ISCSI_KV_DECODE_OP_REPLACE = 3, /* decode for replacement */
};

/* flags for target device */
#define ISCSI_KEY_TARGET_DEVICE_LUTYPE_FILE	0x1
#define ISCSI_KEY_TARGET_DEVICE_LUTYPE_MEM	0x2
#define ISCSI_KEY_TARGET_DEVICE_LUTYPE_RAW	0x4

#define ISCSI_KEY_TARGET_DEVICE_LUMODE_NULLRW	0x10
#define ISCSI_KEY_TARGET_DEVICE_LUMODE_SYNC	0x20
#define ISCSI_KEY_TARGET_DEVICE_LUMODE_RO	0x40

#define ISCSI_KEY_TARGET_DEVICE_LUSIZE_MB	0x100
#define ISCSI_KEY_TARGET_DEVICE_LUSIZE_GB	0x200

#define ISCSI_KEY_TARGET_DEVICE_LUTYPE_MASK 	\
		(ISCSI_KEY_TARGET_DEVICE_LUTYPE_FILE | \
		 ISCSI_KEY_TARGET_DEVICE_LUTYPE_MEM | \
		 ISCSI_KEY_TARGET_DEVICE_LUTYPE_RAW)

/* flags for target ACL */
#define ISCSI_KEY_ACL_R			0x1
#define ISCSI_KEY_ACL_W			0x2
#define ISCSI_KEY_ACL_NONE		0x4
#define ISCSI_KEY_ACL_ALLR		0x10
#define ISCSI_KEY_ACL_ALLW		0x20
#define ISCSI_KEY_ACL_ALL_NONE		0x40

#define ISCSI_KEY_ACL_RW	(ISCSI_KEY_ACL_R | ISCSI_KEY_ACL_W)
#define ISCSI_KEY_ACL_ALLRW	(ISCSI_KEY_ACL_ALLR | ISCSI_KEY_ACL_ALLW)

/*
 * key-value APIs
 */

/* iscsi value */
iscsi_value *iscsi_value_alloc(void);
void    iscsi_value_free(iscsi_value *, char *);
void    iscsi_value_list_append(iscsi_value **, iscsi_value *);
iscsi_value *iscsi_value_duplicate_list(iscsi_value *);

/* value decode */
int	kv_decode_numeric(int, char *, unsigned int *, char *);
int     kv_decode_number_range(int, char *, iscsi_value *, char *);
int     kv_decode_addr_n_port(int, char *, iscsi_value *, char *);
int     kv_size_addr_n_port(iscsi_value *);
int     kv_encode_addr_n_port(char *, iscsi_value *);
int	kv_decode_acl(int mode, char *buf, iscsi_value *vp, char *ebuf);


/* single key-value pair */
#define iscsi_kvp_alloc() \
	(iscsi_keyval *)(os_alloc(sizeof(iscsi_keyval), 1, 1))

void    iscsi_kvp_free(iscsi_keyval * kvp);
int     iscsi_kvp_display(iscsi_keyval *);
int     iscsi_kvp_fill_default(iscsi_keyval *);
int     iscsi_kvp_value_add(iscsi_keyval *, iscsi_value *, char *);
int     iscsi_kvp_value_delete(iscsi_keyval *, iscsi_value *, char *);
int     iscsi_kvp_size_text(iscsi_keyval *);
int     iscsi_kvp_decode_buffer(int, int, int, iscsi_keyval *, char *, char *, int);
int     iscsi_kvp_write_text(int, char *, iscsi_keyval *, char, char, int);

/* key-value pair list */
iscsi_keyval *iscsi_kvlist_alloc(int, iscsi_keydef *);
void    iscsi_kvlist_free(int, iscsi_keyval *);
int     iscsi_kvlist_display(int, iscsi_keyval *);
int     iscsi_kvlist_fill_default(int, iscsi_keyval *);
int     iscsi_kvlist_check_key_property_in_discovery(int, iscsi_keyval *);
int     iscsi_kvlist_compute_value(int, iscsi_keyval *, iscsi_keyval *);
int     iscsi_kvlist_check_compute_value(int, iscsi_keyval *, iscsi_keyval *);
int     iscsi_kvlist_duplicate_value(int, iscsi_keyval *, iscsi_keyval *);
int     iscsi_kvlist_merge_value(int, int, iscsi_keyval *, iscsi_keyval *);
int     iscsi_kvlist_size_text(int, iscsi_keyval *);
int     iscsi_kvlist_write_text(int, iscsi_keyval *, int, unsigned int, char,
				char, char *, int, int);
int     iscsi_kvlist_match_key(char *, int, iscsi_keyval *);

/* decode */
int     iscsi_kvlist_decode_pairq_discovery(int, int, int, iscsi_keyval *,
				chiscsi_queue *, char *, int);
int     iscsi_kvlist_decode_pairq(int, int, int, iscsi_keyval *, chiscsi_queue *,
				  char *, int);
void    iscsi_empty_string_pairq(chiscsi_queue *);
int     iscsi_kv_text_to_string_pairq(unsigned int, char *, chiscsi_queue *,
				      char *, int);
int     iscsi_get_keyval_string(int, char *, char **, char **, char *);
int     iscsi_match_key_string(char *, int, iscsi_keydef *);


int     iscsi_string_pairq_size_response(chiscsi_queue *, unsigned int);
int     iscsi_string_pairq_write_text(chiscsi_queue *, char *, unsigned int);

int 	iscsi_kvlist_get_value_by_index(int, iscsi_keyval *, iscsi_keydef *,
				unsigned int *);
#endif
