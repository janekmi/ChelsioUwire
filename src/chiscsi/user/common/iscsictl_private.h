#ifndef __ISCSICTL_H__
#define __ISCSICTL_H__

#include <ctype.h>
#include <string.h>

#define LINE_BUFFER_LENGTH		1024
#define ISCSI_CONTROL_DATA_MAX_BUFLEN	131072
#define ISCSICTL_CONFIG_FILE_DFLT	"/etc/chelsio-iscsi/chiscsi.conf"

#define IS_CMD_OPTION(arg)	((strlen(arg)) == 2 && (arg[0] == '-'))

/* convert string to upper case letters */
#define str_to_upper(str) \
		do { \
			char	*c = s;	\
			for(; *c; c++) *c = toupper(*c); \
		} while(0)

/* convert string to lower case letters */
#define str_to_lower(s) 	\
		do { \
			char	*c = s;	\
			for(; *c; c++) *c = tolower(*c); \
		} while(0)

/* count the number of occurances of "c" in str */
#define str_count_char(s,ch) ({	\
		int 	cnt = 0; \
		char	*c = s;	\
		for(; *c; c++) if ((*c) == ch) cnt++; \
		cnt; })

/* replace the "fc" with "tc" in str */
#define str_replace_char(s,fc,tc) ({	\
		int 	cnt = 0; \
		char	*c = s;	\
		for(; *c; c++) if ((*c) == fc) {*c = tc; cnt++;}\
		cnt; })

#define str_trim_leading_spaces(s) 	\
		do {	\
			char	*c; \
			for (c = s; *c && isspace(*c); c++) ; \
			str = c; \
		} while(0)	\

#define str_trim_trailing_spaces(s) 	\
		do {	\
			char	*c; \
			int	l = strlen(s); \
			if (l) {	\
				l--; \
				for (c = s + l; l && isspace(*c); c--, l--) \
					*c = 0; \
			} \
		} while(0)	\

/* for iSNS */
enum iscsictl_isns_request {
	ISNS_REQ_INITIATORS,
	ISNS_REQ_TARGET_PORTALS,
	ISNS_REQ_TARGETS,
	ISNS_REQ_TARGET_ACL,

	ISNS_REQ_MAX
};

/* function proto-types */

/* string */
int     str_buffer_insert_time(char *);

/* open/close control device */
int     iscsictl_open_device(void);
void    iscsictl_close_device(int);
int     iscsictl_send_control_cmd(int, int, void *);
/* isns client signalling */
int     iscsictl_update_isns_client(void);

/* file */
int     os_file_size(char *, unsigned long *);

/* lib functions */
int     iscsictl_parse_cmd_option(int *, int, char **);
int     iscsictl_cmd_execute(int, int *);
int     iscsictl_need_open_device(void);

int     iscsictl_isns_get_portals(int, char *, int);
int     iscsictl_isns_get_targets(int, char *, int);
int     iscsictl_isns_cmd(int, char *, int, char *, int, int);

#endif /* ifndef __ISCSICTL_PRIVATE_H__ */
