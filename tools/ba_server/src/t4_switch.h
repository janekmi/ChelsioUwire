#ifndef	__T4_SWITCH_
#define	__T4_SWITCH_

struct filter_entry {
	TAILQ_ENTRY(filter_entry)		fe;
	u_int					rule;
	u_int					cond;
	struct ch_filter			filter;
};

struct table_entry {
	int					inuse;
	int					active;
	TAILQ_HEAD(, filter_entry)		filter_head;
};

extern char devname[];

#define	BA_MAX_TABLES			5

#define ACL_MATCH_ETHERTYPE		0x0000000001
#define ACL_MATCH_VLAN 			0x0000000002	
#define ACL_MATCH_SRC_IP 		0x0000000004	
#define ACL_MATCH_DST_IP		0x0000000008	
#define ACL_MATCH_PROTOCOL		0x0000000010
#define ACL_MATCH_SRC_PORT		0x0000000020
#define ACL_MATCH_DST_PORT		0x0000000040
#define ACL_MATCH_SRC_IP6 		0x0000000080	
#define ACL_MATCH_DST_IP6 		0x0000000100	
#define ACL_MATCH_IPV6			0x0000000200	

#define	ACL_ACTION_DROP			FILTER_DROP
#define	ACL_ACTION_INPUT		FILTER_PASS
#define	ACL_ACTION_REDIRECT		FILTER_SWITCH

int	sw_create_table(int table_id);
int	sw_delete_table(int table_id);
int	sw_activate_table(int table_id);
int	sw_deactivate_table(int table_id);
int	sw_get_table(int table_id);

int	sw_list_rules();
int	sw_add_rule(u_int options_set, char *options_val[]);
int	sw_update_rule(int rule, int table, u_int opts_set, char *options_val[]);
int	sw_delete_rule(int table, int rule);
int	sw_purge_rules(int table);
int	sw_move_rule(int table, int old_rule, int new_rule);
int	sw_match_rule(int table, u_int opts_set, char *options_val[]);
int	sw_count_rule(int rule, int table);
int	sw_dump_tables(void);

int	sw_get_first_table(int *table);
int	sw_get_next_table(int table, int *nexttable);

int	sw_get_rule(int table, int rule, struct filter_entry ** ent);
int	sw_get_first_rule(int table, int *rule, struct filter_entry ** ent);
int	sw_get_next_rule(int table, int rule, int *next,
			 struct filter_entry ** ent);
int	sw_get_last_rule(int table);
int	sw_activate_rule(int table_id, int rule);
int	sw_deactivate_rule(int table_id, int rule);

struct filter_entry * sw_get_filter(int table_id, int rule);
int 	sw_add_filter(int table_id, int rule, struct filter_entry *filter);
int	sw_activate_filter(struct filter_entry *filter);
int	sw_deactivate_filter(struct filter_entry *filter);
int	sw_get_filter_id(int table, int rule);

int	sw_get_count(int table, int rule, long long *c);
int	sw_get_filter_count(int table, int filter, long long *c);
int	sw_get_port_state(int port);

void	set_devname(char * name);
int	get_devname(void);


#define	BA_DEFAULT_ACTION	FM_ACL_ACTIONEXT_DENY

#endif	/* __T4_SWITCH_ */
