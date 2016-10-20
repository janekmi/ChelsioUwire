/* 
 * iscsictl_cmd.c -- user space functions to gather user request, 
 * 	forward it to the iscsi module, and receive the response from
 *	iscsi module
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>
#include <errno.h>

#include "../../user/common/iscsictl_private.h"
#include "../include/iscsi_control_defs.h"

/* 
 * key file locations
 */
#define ISCSICTL_PATH 			"/etc/chelsio-iscsi"
#define ISCSICTL_LICENSE_FILE 		"/etc/chelsio-iscsi/chiscsi.key"
#define ISCSICTL_TIMESTAMP_FILE 	"/etc/.chiscsi.cache"

/*
 * key-value pair -- for <key>=<val> pair, where <val> can be a list
 */
typedef struct kv_pair kv_pair;
struct kv_pair {
	kv_pair *next;
	unsigned char flag;	/* key value flag for "ALL" or "NULL" value */
	unsigned char type;	/* key type */
	char   *key;
	char   *val;
};

#define kv_pair_free(kvlist) \
                do { \
                        kv_pair *__kv; \
                        for (__kv = kvlist; __kv; ) { \
                                kv_pair *__next = __kv->next; \
                                free(__kv); \
                                __kv = __next; \
                        } \
                } while(0)

/* 
 * key types
 */
enum {
	KEY_TYPE_INITIATOR,
	KEY_TYPE_TARGET,
	KEY_TYPE_PORTAL,
	KEY_TYPE_LUN,

	KEY_TYPE_MAX
};

static char key_type_str[][16] = {
	"initiator",
	"target",
	"portal",
	"lun"
};

/* key value special types */
#define VALUE_TYPE_NULL		0x1
#define VALUE_TYPE_ALL		0x2
#define VALUE_TYPE_LIST		0x4

/* 
 * config file entries 
 */
enum {
	CONF_TYPE_GLOBAL,
	CONF_TYPE_TARGET,
	CONF_TYPE_DEFAULTS,
	CONF_TYPE_MAX
};

static char config_type_str[][16] = {
	"global",
	"target",
	"default",
};

typedef struct config_entry config_entry;
struct config_entry {
	config_entry *next;
	int     type;
	int     buflen;
	char   *name;
	char   *alias;
	char   *buf;
};

#define config_entry_free(conf) \
		do { \
			while (conf) { \
				config_entry    *next = conf->next; \
				if (conf->alias) free(conf->alias); \
				if (conf->name) free(conf->name); \
				if (conf->buf) free(conf->buf); \
				free(conf); \
				conf = next; \
			} \
			conf = NULL; \
		} while(0)

#define ISCSICTL_ARGS_MAX			32

/* Globals */
static char debug = 0;
static unsigned long tmstamp = 0;

static int isns_update = 0;
static int iscsictl_fd = -1;
static int cmd = ISCSI_CONTROL_OPCODE_UNKNOWN;
static char *config_file = NULL;
static char *sess_hndl = NULL;

static int entity_cnt = 0;
static int key_cnt = 0;
static char *entity_list[ISCSICTL_ARGS_MAX];
static char *key_list[ISCSICTL_ARGS_MAX];

static int kbuflen = 0;
static char *keybuf = NULL;

#define iscsictl_send_request(fd,cmd,arg) ({\
		int	__rv; \
 		if (debug) printf("send ctl cmd %u.\n", cmd); \
		arg.timestamp = tmstamp;	\
		arg.addr[0] = (unsigned long)keybuf; \
		arg.len[0] = (unsigned int)kbuflen; \
		__rv = iscsictl_send_control_cmd(fd, cmd, &arg); \
 		if (debug) printf("send ctl cmd %u, rv %d.\n", cmd,  __rv); \
		__rv; })

/**
 * str_list_parse_kv_pair -- parse an array of string buffers in the format of <key>=<value>
 */
static kv_pair *str_to_kv_pair(char *str)
{
	kv_pair *kv_head = NULL;
	kv_pair *kv_tail = NULL;
	char   *dup = NULL;
	char   *val = NULL;
	char   *ch;
	int     val_cnt = 0;
	int     i, type;

	if (!str || !strlen(str))
		return NULL;

	dup = strdup(str);
	if (!dup) {
		fprintf(stderr, "ERROR: %s strdup() out of memory.\n", str);
		goto out;
	}

	/* find the "=" */
	for (ch = dup; *ch && (*ch) != '='; ch++) ;
	if (*ch == '=') {
		/* <value> portion present */
		*ch = '\0';
		/* dup points to <key>, *val points to <value> */
		val = str + strlen(dup) + 1;
	} else {
		fprintf(stderr, "ERROR: key-value %s \"=\" missing\n",dup);
		goto out;
	}

	/* check for key type */
	str_to_lower(dup);
	for (type = 0; type < KEY_TYPE_MAX; type++) {
		if (!strcmp(dup, key_type_str[type]))
			break;
	}

	if (type == KEY_TYPE_MAX) {
		fprintf(stderr, "ERROR: unknown key %s.\n", str);
		goto out;
	}

	/* split <val> if it is a list */
	if (val)
		val_cnt = str_replace_char(val, ',', '\0');

	for (val_cnt++, i = 0; i < val_cnt; i++) {
		kv_pair *kv;

		kv = malloc(sizeof(kv_pair));
		if (!kv) {
			fprintf(stderr, "ERROR: malloc(%lu) out of memory.\n",
				(unsigned long)sizeof(kv_pair));
			goto out;
		}
		memset(kv, 0, sizeof(kv_pair));

		kv->type = type;
		kv->key = str;
		if (!strlen(val))
			kv->flag = VALUE_TYPE_NULL;
		else if (!(strcmp(val, "ALL")))
			kv->flag = VALUE_TYPE_ALL;
		else
			kv->val = val;

		/* add to the kv_pair list */
		if (!kv_head)
			kv_head = kv;
		else
			kv_tail->next = kv;
		kv_tail = kv;

		if (val)
			val += strlen(val) + 1;
	}

      out:
	if (dup)
		free(dup);
	return kv_head;
}

static int str_list_parse_kv_pair(char **str_list, int str_cnt,
				  unsigned int key_flag, unsigned int val_flag,
				  kv_pair ** kv_list)
{
	int     i, error = 0;
	kv_pair *head = NULL, *tail = NULL;

	if (!str_cnt)
		return 0;

	for (i = 0; i < str_cnt; i++) {
		kv_pair *kv = str_to_kv_pair(str_list[i]);
		kv_pair *kv_tmp;
		int     all = 0;

		if (!kv) {
			fprintf(stderr, "%s INVALID.\n", str_list[i]);
			continue;
		}

		/* key-value check */
		if (!(key_flag & (1 << kv->type))) {
			fprintf(stderr, "ERROR: %s unknown keys.\n", kv->key);
			goto kv_error;
		}

		if (kv->next) {
			kv_pair *prev = NULL;
			/* list not allowed */
			if (!(val_flag & VALUE_TYPE_LIST)) {
				fprintf(stderr,
					"ERROR: %s list value not supported.\n",
					kv->key);
				goto kv_error;
			}
			/* > 1 elements in the list, release the NULL element */
			for (kv_tmp = kv; kv_tmp;) {
				kv_pair *next = kv_tmp->next;

				if (kv_tmp->flag & VALUE_TYPE_NULL) {
					if (prev)
						prev->next = kv_tmp->next;
					else
						kv = kv_tmp->next;
					kv_tmp->next = NULL;
					kv_pair_free(kv->next);
				} else
					prev = kv_tmp;

				kv_tmp = next;
			}
		}

		/* check if ALL is specified, if it is, release all the kv
		 * except the 1st 
		 * if both ALL and NULL are present in the list, ALL takes
		 * the precedence */
		for (kv_tmp = kv; kv_tmp && !all; kv_tmp = kv_tmp->next) {
			if (kv_tmp->flag & VALUE_TYPE_ALL)
				all = 1;
		}
		if (all) {
			kv->flag = VALUE_TYPE_ALL;
			if (kv->next) {
				kv_pair_free(kv->next);
				kv->next = NULL;
			}
		}

		/* individual value check */
		for (kv_tmp = kv; kv_tmp; kv_tmp = kv_tmp->next) {
			if ((kv_tmp->flag & VALUE_TYPE_NULL)
			    && !(val_flag & VALUE_TYPE_NULL)) {
				fprintf(stderr, "WARN: %s has no value.\n",
					kv_tmp->key);
				goto kv_error;
			}

			if ((kv->flag & VALUE_TYPE_ALL)
			    && !(val_flag & VALUE_TYPE_ALL)) {
				fprintf(stderr,
					"ERROR: %s not supported.\n",
					kv_tmp->key);
				goto kv_error;
			}
		}

		/* no error, add to the list */
		if (!head)
			head = kv;
		else
			tail->next = kv;
		for (kv_tmp = kv; kv_tmp->next; kv_tmp = kv_tmp->next) ;
		tail = kv_tmp;

		continue;
	      kv_error:
		kv_pair_free(kv);
		error++;
	}

	*kv_list = head;

	/* return error, if none of the string yield any result */
	if (!head && error)
		return -1;

	return 0;
}

/**
 * iscsictl_read_timestamp -- read timestamp file
 */
static int iscsictl_read_timestamp(char *fname)
{
	FILE   *fhndl;

	/* if no timestamp time, create it */
	fhndl = fopen(fname, "r");
	if (!fhndl) {
		struct timeval tm;

		if (gettimeofday(&tm, NULL) < 0) {
			fprintf(stderr, "Error: unable to read system time.\n");
			return -1;
		}
		tmstamp = ((unsigned long) tm.tv_sec) / 3600;

		fhndl = fopen(fname, "w");
		if (!fhndl) {
			fprintf(stderr, "Error: unable to write file.\n");
			return -1;
		}
		fprintf(fhndl, "%lu", tmstamp);
		fclose(fhndl);

	} else {
		fscanf(fhndl, "%lu", &tmstamp);
		fclose(fhndl);
	}

	return 0;
}

static int iscsictl_file_read_to_buf(char *fname, char **buf_pp)
{
	unsigned long fsize;
	int     rv;
	char   *buf;
	FILE   *fhndl;

	fhndl = fopen(fname, "r");
	if (!fhndl)
		return -1;

	rv = os_file_size(fname, &fsize);
	if (rv < 0)
		fsize = 4096;
	fsize++;
	buf = malloc(fsize);
	if (!buf) {
		fprintf(stderr, "out of memory %lu.\n", fsize);
		fclose(fhndl);
		return -1;
	}
	memset(buf, 0, fsize);
	fgets(buf, fsize, fhndl);
	fclose(fhndl);

	*buf_pp = buf;
	return (strlen(buf));
}

static void iscsictl_keyfile_cleanup(void)
{
	if (kbuflen && keybuf) {
		free(keybuf);
		keybuf = NULL;
		kbuflen = 0;
	}
}

static int iscsictl_read_keyfile(void)
{
	kbuflen = iscsictl_file_read_to_buf(ISCSICTL_LICENSE_FILE, &keybuf);
	if (kbuflen < 0) {
		kbuflen = 0;
		keybuf = NULL;
	}
	return 0;
}

/*
 * config. file handling
 */

/* Dump a given buffer */
static void iscsictl_dump_buffer(char *buffer, int len, char *str)
{
	int     i;

	if (str)
		printf("%s, ", str);
	printf("len=%d:\n", len);
	for (i = 0; i < len; i++) {
		if (buffer[i]) {
			printf("%c", buffer[i]);
		} else {
			printf("##");
		}
	}
	printf("\n");
}

/* Dump a config entry */
void iscsictl_dump_config(config_entry * cfg, char *str)
{
	if (str)
		printf("\n%s: \n", str);
	while (cfg) {
		printf("%s:", config_type_str[cfg->type]);
		if (cfg->name)
			printf("name=%s", cfg->name);
		if (cfg->alias)
			printf(", alias=%s", cfg->alias);
		printf("\n");
		iscsictl_dump_buffer(cfg->buf, cfg->buflen, NULL);
		printf("\n");
		cfg = cfg->next;
	}
	printf("\n");
}


/* find a config entry with "name"                                    */
static config_entry *iscsictl_config_entry_find(config_entry *head, char *name)
{
	config_entry *conf;
	for (conf = head; conf; conf = conf->next) {
		if (name && conf->name && !strcmp(conf->name, name))
			return conf;
	}
	fprintf(stderr, "ERROR: target name %s NOT found.\n", name);
	return NULL;
}


static int iscsictl_config_file_read(char *fname, config_entry ** conf_pp)
{
	FILE   *fhndl;
	int     line = 0;
	int     cbuf_cnt = 0, buflen;
	char   *cbuf;
	config_entry *conf_head = NULL;
	config_entry *conf = NULL, *prevcfg = NULL;
	int     block_start = 0;
	int     type = CONF_TYPE_MAX;
	char    line_buf[LINE_BUFFER_LENGTH];
	char    config_buffer[ISCSI_CONTROL_DATA_MAX_BUFLEN];
	int     rc = 0;

	if (!fname) {
		printf("Error: Input source config file name is null!\n");
		return -1;
	}
	if (!conf_pp) {
		printf("Error: Input config list is null!\n");
		return -1;
	}
	*conf_pp = NULL;

	fhndl = fopen(fname, "r");
	if (!fhndl) {
		fprintf(stderr, "Error: File \"%s\" cannot be opened!\n",
			fname);
		return -1;
	}

	cbuf = config_buffer;
	cbuf_cnt = 0;
	while (fgets(line_buf, LINE_BUFFER_LENGTH, fhndl)) {
		char   *ch, *str, *key, *val;
		line++;

		/* remove leading space */
		str = line_buf;
		str_trim_leading_spaces(str);

		/* remove any comment at the end */
		buflen = strlen(str);
		if (buflen) {
			buflen--;
			for (ch = str + buflen; buflen && (*ch != '#');
			     ch--, buflen--) ;
			if (*ch == '#')
				*ch = 0;

			/* remove trailing space */
			str_trim_trailing_spaces(str);
		}
		/* skip comment or empty line */
		if (!(*str) || *str == '#') {
			continue;
		}

		/*
		 * look for 
		 * - target: or
		 * - global:
		 */
		buflen = strlen(str);
		if (str[buflen - 1] == ':') {
			block_start = 1;
			str[buflen - 1] = 0;
			str_to_lower(str);
			for (type = 0; type < CONF_TYPE_MAX; type++) {
				if (!strcmp(str, config_type_str[type])) {
					ch = str + buflen + 1;
					break;
				}
			}
		} else {
			block_start = 0;
		}

		if (type == CONF_TYPE_MAX) {
			fprintf(stderr, "%s, line %d, invalid format.\n",
				fname, line);
			fflush(stderr);
			rc = -1;
			break;
		}

		/* starts a new block */
		if (block_start) {
			if (conf) {
				/* make sure we have a name for the target */
				if (!conf->name &&
				    conf->type == CONF_TYPE_TARGET) {
					fprintf(stderr,
						"%s line %d, missing TargetName.\n",
						fname, line);
					fflush(stderr);
					rc = -1;
					break;
				}
				conf->buf = malloc(cbuf_cnt);
				if (!conf->buf) {
					fprintf(stderr,
						"%s: out of memory %d.\n",
						fname, cbuf_cnt);
					rc = -1;
					break;
				}
				conf->buflen = cbuf_cnt;
				memcpy(conf->buf, config_buffer, cbuf_cnt);

				prevcfg = conf;
			}
			cbuf = config_buffer;
			cbuf_cnt = 0;

			conf = malloc(sizeof(config_entry));
			if (!conf) {
				fprintf(stderr, "%s out of memory %lu.\n",
					fname, (unsigned long )sizeof(config_entry));
				rc = -1;
				break;
			}
			memset(conf,0,sizeof(config_entry));

			if (prevcfg)
				prevcfg->next = conf;
			else
				conf_head = conf;

			conf->type = type;

			continue;
		}

		/* normal <key>=<value> pairs, split to key and value part */
		key = str;
		for (ch = str; *ch && (*ch != '='); ch++) ;
		if (!*ch) {
			fprintf(stderr, "%s, line %d: \"%s\" invalid format!\n",
				fname, line, str);
			fflush(stderr);
			rc = -1;
			break;
		}
		val = ch + 1;
		*ch = 0;
		/* remove trailing space after the key */
		str_trim_trailing_spaces(key);
		/* remove leading space before the value */
		str_trim_leading_spaces(val);

		/* save <key> and <value> */
		buflen = sprintf(cbuf, "%s=%s", key, val);
		cbuf[buflen] = 0;
		buflen++;
		cbuf += buflen;
		cbuf_cnt += buflen;

		if (conf->type == CONF_TYPE_TARGET) {
			if (!strcmp(key, "TargetName")) {
				if (conf->name) {
					fprintf(stderr,
						"line %d: duplicate declaration.\n",
						line);
					rc = -1;
					break;
				}
				conf->name = strdup(val);
				/* RFC 3722, section 1
				 * iSCSI names are generalized using a 
				 * normalized character set (converted to lower
				 * case or equivalent), with no white space
				 * allowed, and very limited punctuation. 
				 *  ....
				 * In addition, any upper-case characters input
				 * via a user interface MUST be mapped to their
				 * lower-case equivalents.
				 */
				ch = conf->name;
				while (*ch) {
					*ch = tolower(*ch);
					ch++;
				}
			}
			if (!strcmp(key, "TargetAlias")) {
				if (conf->alias) {
					fprintf(stderr,
						"line %d: duplicate declaration.\n",
						line);
					rc = -1;
					break;
				}
				conf->alias = strdup(val);
			}
		}
	}

	if (conf) {
		conf->buf = malloc(cbuf_cnt);
		if (!conf->buf) {
			fprintf(stderr, "read %s: out of memory %d.\n", fname,
				cbuf_cnt);
			rc = -1;
		} else {
			conf->buflen = cbuf_cnt;
			memcpy(conf->buf, config_buffer, cbuf_cnt);
		}
	}

	fclose(fhndl);

	if (debug)
		iscsictl_dump_config(conf_head, fname);

	if (conf_head == NULL) {
		fprintf(stderr, "ERROR: %s, no valid block is found.\n", fname);
	}


	if ((rc < 0) && conf_head) {
		config_entry_free(conf_head);
		conf_head = NULL;
	}

	*conf_pp = conf_head;

	return rc;
}

/*
 * Individual Cmd Execution
 */

/**
 * add iSNS:
 *	iscsictl -I client=<name> server=<ip>[:<port>]
 */
/* handled in iscsictl.c */


/**
 * iscsictl_drv_get --  Get Chelsio Global Settings
 *	iscsictl -g
 */
static int iscsictl_drv_get(FILE * outhndl)
{
	int     rv;
	iscsi_control_args arg;

	if (!outhndl)
		outhndl = stdout;

	memset(&arg, 0, sizeof(iscsi_control_args));
	rv = iscsictl_send_request(iscsictl_fd, ISCSI_CONTROL_OPCODE_DRV_GET,
				   arg);

	if (arg.buf[0]) {
		if (!rv) {
			fprintf(outhndl, "%s\n", arg.buf);
		} else
			fprintf(stderr, "%s\n", arg.buf);
	}

	return rv;
}

/**
 * iscsictl_drv_set --  set Chelsio Global Settings
 *	iscsictl -G var=<const>
 */
static int iscsictl_drv_set(int entity_cnt, char **entity_list)
{
	int     rv;
	int     i;
	iscsi_control_args arg;

	memset(&arg, 0, sizeof(iscsi_control_args));

	for (i = 0; i < entity_cnt; i++) {
		strcpy(arg.buf, entity_list[i]);
		rv = iscsictl_send_request(iscsictl_fd,
					   ISCSI_CONTROL_OPCODE_DRV_SET, arg);
		if (strlen(arg.buf))
			fprintf(stderr, "%s", arg.buf);
		if (rv < 0)
			fprintf(stderr, "ERROR: Failed to set %s!\n",
				entity_list[i]);
	}
	return 0;
}

/**
 * iscsictl_target_flush -- Flush iSCSI targets' data
 *      iscsictl -F [target=<name>] [-k lun=<val>]
 *      - <name>=ALL allowed
 *      - lun=ALL allowed
 */
static int iscsictl_target_flush(int entity_cnt, char **entity_list,
				 int key_cnt, char **key_list)
{
	int     rv;
	iscsi_control_args arg;
	kv_pair *name_list = NULL;
	kv_pair *lun_list = NULL;
	kv_pair *kv_name, *kv_lun;

	rv = str_list_parse_kv_pair(entity_list, entity_cnt,
				    (1 << KEY_TYPE_TARGET),
				    (VALUE_TYPE_NULL | VALUE_TYPE_ALL |
				     VALUE_TYPE_LIST), &name_list);
	if (rv < 0)
		return rv;
	rv = str_list_parse_kv_pair(key_list, key_cnt,
				    (1 << KEY_TYPE_LUN),
				    (VALUE_TYPE_NULL | VALUE_TYPE_ALL |
				     VALUE_TYPE_LIST), &lun_list);
	if (rv < 0)
		return rv;

	/* if the name list is empty or "ALL", release the lun list */
	if (name_list && (name_list->flag & (VALUE_TYPE_NULL | VALUE_TYPE_ALL))) {
		kv_pair_free(name_list);
		name_list = NULL;
	}

	/* if lun list is empty or "ALL", release the lun list */
	if (lun_list && (lun_list->flag & (VALUE_TYPE_NULL | VALUE_TYPE_ALL))) {
		kv_pair_free(lun_list);
		lun_list = NULL;
	}

	memset(&arg, 0, sizeof(iscsi_control_args));

	if (!name_list && !lun_list) {
		arg.buf[0] = '\0'; 	/* name */
		arg.buf[1] = '\0';	/* lun */
		rv = iscsictl_send_request(iscsictl_fd, cmd, arg);
		if (arg.buf[0])
			printf("%s\n", arg.buf);
		if (rv < 0)
			fprintf(stderr, "ERROR: target flush failed.\n");
	} else if (!name_list) {
		for (kv_lun = lun_list; kv_lun; kv_lun = kv_lun->next) {
			int len = sprintf(arg.buf + 1, "%s", kv_lun->val);
			arg.buf[0] = '\0'; /* name */
			arg.buf[++len] = '\0';
			rv = iscsictl_send_request(iscsictl_fd, cmd, arg);
			if (arg.buf[0])
				printf("%s\n", arg.buf);
			if (rv < 0)
				fprintf(stderr,
					"ERROR: target flush lun %s failed.\n",
					kv_lun->val);
		}
	} else if (!lun_list) {
		for (kv_name = name_list; kv_name; kv_name = kv_name->next) {
			int len = sprintf(arg.buf, "%s", kv_name->val);
			arg.buf[++len] = '\0'; /* name */
			arg.buf[++len] = '\0'; /* lun */
			rv = iscsictl_send_request(iscsictl_fd, cmd, arg);
			if (arg.buf[0])
				printf("%s\n", arg.buf);
			if (rv < 0)
				fprintf(stderr,
					"ERROR: target %s flush lun failed.\n",
					kv_name->val);
		}
	} else {
		for (kv_name = name_list; kv_name; kv_name = kv_name->next) {
			for (kv_lun = lun_list; kv_lun; kv_lun = kv_lun->next) {
				int     len =
					sprintf(arg.buf, "%s", kv_name->val);
				arg.buf[++len] = '\0';
				len += sprintf(arg.buf + len, "%s",
					       kv_lun->val);
				arg.buf[++len] = '\0';
				rv = iscsictl_send_request(iscsictl_fd, cmd,
							   arg);
				if (arg.buf[0])
					printf("%s\n", arg.buf);
				if (rv < 0)
					fprintf(stderr,
						"ERROR: %s flush lun %s failed.\n",
						kv_name->val, kv_lun->val);
			}
		}
	}

	if (name_list)
		kv_pair_free(name_list);
	if (lun_list)
		kv_pair_free(lun_list);

	return rv;
}

/*
 * add Target:
 *	iscsictl -S target=<name>
 * reload active target:
 *	iscsictl -S
 */

static void iscsictl_reload_globals(config_entry * conf_list)
{
	config_entry *conf;

	/* reload the global settings from the config file */
	for (conf = conf_list; conf; conf = conf->next) {
		if (conf->type == CONF_TYPE_GLOBAL) {
			char   *val;

			val = conf->buf;
			while ((val - conf->buf) < conf->buflen) {
				int     rv;
				rv = iscsictl_drv_set(1, &val);
				val += strlen(val) + 1;
			}
		}
	}
}

static int iscsictl_add_one_node(config_entry * conf)
{
	iscsi_control_args arg;
	int rv;

	/* buffer format: <node name><null> */
	if (conf->name)
		strcpy(arg.buf, conf->name);
	else {
		fprintf(stderr, "ERROR: Missing target name\n");
		return -1;	
	}
	arg.addr[1] = (unsigned long) (conf->buf);
	arg.len[1] = conf->buflen;
	arg.flag = ISCSI_CONTROL_FLAG_EXTRA_DATA;
	rv = iscsictl_send_request(iscsictl_fd, cmd, arg);
	if (arg.buf[0])
		fprintf(stderr, "%s", arg.buf);
	if (rv < 0)
		fprintf(stderr, "ERROR: Failed to start target %s!\n",
			conf->name);

	return rv;
}

static int iscsictl_add_node(config_entry * conf_list)
{
	kv_pair *node_list = NULL;
	kv_pair *kv_node;
	int     rv = 0;

	iscsictl_reload_globals(conf_list);

	rv = str_list_parse_kv_pair(entity_list, entity_cnt,
				    1 << KEY_TYPE_TARGET,
				    (VALUE_TYPE_ALL | VALUE_TYPE_LIST),
				    &node_list);
	if (rv < 0)
		return rv;

	/* entity_list cannot be NULL */
	for (kv_node = node_list; kv_node; kv_node = kv_node->next) {
		config_entry *conf;

		if (kv_node->flag & VALUE_TYPE_ALL) {
			for (conf = conf_list; conf; conf = conf->next) {
				if (conf->type == CONF_TYPE_TARGET) {
					rv = iscsictl_add_one_node(conf);
					if (!rv)
						isns_update++;
				}
			}
		} else {
			conf = iscsictl_config_entry_find(conf_list,
							  kv_node->val);
			if (conf) {
				rv = iscsictl_add_one_node(conf);
				if (!rv)
					isns_update++;
			} else {
				fprintf(stderr,
					"ERROR: Failed to find target %s!\n",
					kv_node->val);
				rv = -ENODEV;
			}
		}
	}

	if (node_list)
		kv_pair_free(node_list);
	return rv;
}

/*
 * remove target:
 * 	iscsictl -s <target>=<name>
 */
static int iscsictl_remove_node(void)
{
	int     rv;
	kv_pair *node_list = NULL;
	kv_pair *kv_node;

	rv = str_list_parse_kv_pair(entity_list, entity_cnt,
				    1 << KEY_TYPE_TARGET,
				    (VALUE_TYPE_ALL | VALUE_TYPE_LIST),
				    &node_list);
	if (rv < 0)
		return rv;

	/* entity_list cannot be NULL */
	for (kv_node = node_list; kv_node; kv_node = kv_node->next) {
		iscsi_control_args arg;
		memset(&arg, 0, sizeof(iscsi_control_args));

		if (kv_node->flag & VALUE_TYPE_ALL) {
			rv = sprintf(arg.buf, "ALL");
			arg.buf[rv++] = '\0';
		} else
			strcpy(arg.buf, kv_node->val);

		rv = iscsictl_send_request(iscsictl_fd, cmd, arg);

		if (arg.buf[0])
			fprintf(stderr, "%s", arg.buf);
		if (!rv)
			isns_update++;
		if (rv < 0)
			fprintf(stderr, "ERROR: Failed to remove target %s!\n",
				kv_node->val);
	}

	kv_pair_free(node_list);

	return rv;
}

/*
 * get iSCSI configuration:
 *	iscsictl -c [<target>=<name>]
 */
static int iscsictl_get_entity_names(int ktype, char *buf, int buflen)
{
	int     rv;
	iscsi_control_args arg;

	memset(&arg, 0, sizeof(iscsi_control_args));

	buf[0] = 0;
	arg.buf[0] = 0;
	arg.addr[1] = (unsigned long) buf;
	arg.len[1] = buflen;

	rv = iscsictl_send_request(iscsictl_fd,
				ISCSI_CONTROL_OPCODE_TARGET_GET_NAMES, arg);
	if (arg.buf[0])
		fprintf(stderr, "%s", arg.buf);

	return rv;
}

static int iscsictl_config_get_one_target(FILE *outhndl, char *tname,
					int detail)
{
	int     rv;
	char    databuf[ISCSI_CONTROL_DATA_MAX_BUFLEN];
	iscsi_control_args arg;
	int     len;

	if (detail)
		arg.flag = ISCSI_CONTROL_FLAG_DETAIL;
	/* node name */
	len = sprintf(arg.buf, "%s", tname);
	arg.buf[len++] = 0;
	/* key name */
	arg.buf[len++] = 0;
	/* data buffer */
	databuf[0] = 0;
	arg.addr[1] = (unsigned long) databuf;
	arg.len[1] = ISCSI_CONTROL_DATA_MAX_BUFLEN;

	rv = iscsictl_send_request(iscsictl_fd, 
		outhndl ? ISCSI_CONTROL_OPCODE_TARGET_GET_WRITE :
			ISCSI_CONTROL_OPCODE_TARGET_GET,	
		arg);

	if (!rv && outhndl && (databuf[0])) {
		char   *c;
		/* skip first line */
		for (c = databuf; *c && *c != '\n'; c++) ;
			if (*c)
				c++;
		fprintf(outhndl,
			"#\n#iSCSI Target Configurations\n#\n");
		fprintf(outhndl, "\n%s\n", c);
	} else {
		if (arg.buf[0])
			printf("%s\n", arg.buf);
		if (databuf[0])
			printf("%s\n", databuf);
	}

	return rv;
}

static int iscsictl_config_get(FILE *outhndl, int entity_cnt,
				char **entity_list)
{
	int     rv;
	char    databuf[ISCSI_CONTROL_DATA_MAX_BUFLEN];
	kv_pair *node_list = NULL;
	kv_pair *kv_node;

	rv = str_list_parse_kv_pair(entity_list, entity_cnt,
				    1 << KEY_TYPE_TARGET,
				    (VALUE_TYPE_ALL | VALUE_TYPE_LIST),
				    &node_list);
	if (rv < 0)
		return rv;

	kv_node = node_list;
	if (kv_node->flag & VALUE_TYPE_ALL) {
		int i, len;
		char *tname;

		/* databuf:<target>=<name>,... */
        	rv = iscsictl_get_entity_names(KEY_TYPE_TARGET, databuf,
                                       ISCSI_CONTROL_DATA_MAX_BUFLEN);
        	if (rv < 0)
                	goto out;
        	len = strlen(databuf);
		/* skip "target=" */
		len -= 7;	
		tname = databuf + 7;
        	/* no target active */
        	if (!len)
                	goto out;
		
		for (i = 0; i < len; i++) {
			if (databuf[i] != ',')
				continue;

			databuf[i] = 0;
			rv = iscsictl_config_get_one_target(outhndl, tname,
						outhndl ? 1 : 0);
			tname = databuf + i + 1;
		}
		rv = iscsictl_config_get_one_target(outhndl, tname,
						outhndl ? 1 : 0);

	} else {
		for (kv_node = node_list; kv_node; kv_node = kv_node->next)
			rv = iscsictl_config_get_one_target(outhndl,
							kv_node->val, 1);
	}

out:
	kv_pair_free(node_list);
	return rv;
}

static int iscsictl_drop_session(char *sess_hndl)
{
	int	rv;
	iscsi_control_args arg;

	memset(&arg, 0, sizeof(iscsi_control_args));
	strcpy(arg.buf, sess_hndl);

	rv = iscsictl_send_request(iscsictl_fd, cmd, arg);

	return rv;
}

/* 
 * retrieve runtime iSCSI sessions:
 *	iscsictl -r <target>=<name> [-k <initiator>=<name>]
 */
static int iscsictl_get_sessions(void)
{
	int     rv;
	char    databuf[ISCSI_CONTROL_DATA_MAX_BUFLEN];
	kv_pair *node_list = NULL;
	kv_pair *peer_list = NULL;
	kv_pair *kv_node;
	kv_pair *kv_peer;

	rv = str_list_parse_kv_pair(entity_list, entity_cnt,
					1 << KEY_TYPE_TARGET,
					VALUE_TYPE_LIST, &node_list);
	if (rv < 0)
		return rv;

	if (!node_list) {
		fprintf(stderr, "Missing initiator/target name.\n");
		return -EINVAL;
	}

	if (key_cnt) {
		rv = str_list_parse_kv_pair(key_list, key_cnt,
					1 << KEY_TYPE_INITIATOR,
					VALUE_TYPE_LIST, &peer_list);
		if (rv < 0)
			goto out;
	}

	for (kv_node = node_list; kv_node; kv_node = kv_node->next) {
		iscsi_control_args arg;

		if (!peer_list) {
			int     len;
			memset(&arg, 0, sizeof(iscsi_control_args));
			/* node name */
			len = sprintf(arg.buf, "%s", kv_node->val);
			arg.buf[len++] = 0;
			/* peer name */
			arg.buf[len++] = 0;
			databuf[0] = 0;
			arg.addr[1] = (unsigned long) databuf;
			arg.len[1] = ISCSI_CONTROL_DATA_MAX_BUFLEN;
			rv = iscsictl_send_request(iscsictl_fd, cmd, arg);
			if (arg.buf[0])
				fprintf(stderr, "%s\n", arg.buf);
			if (databuf[0])
				printf("%s\n", databuf);
			continue;
		}

		for (kv_peer = peer_list; kv_peer; kv_peer = kv_peer->next) {
			int     len;

			if (kv_peer->type != KEY_TYPE_INITIATOR) {
				fprintf(stderr,
					"ERR: expect -k initiator=<value>.\n");
				continue;
			}

			memset(&arg, 0, sizeof(iscsi_control_args));
			/* node name */
			len = sprintf(arg.buf, "%s", kv_node->val);
			arg.buf[len++] = 0;
			/* peer name */
			len += sprintf(arg.buf + len, "%s", kv_peer->val);
			arg.buf[len++] = 0;

			databuf[0] = 0;
			arg.addr[1] = (unsigned long) databuf;
			arg.len[1] = ISCSI_CONTROL_DATA_MAX_BUFLEN;
			rv = iscsictl_send_request(iscsictl_fd, cmd, arg);
			if (arg.buf[0])
				fprintf(stderr, "%s\n", arg.buf);
			if (databuf[0])
				printf("%s\n", databuf);
		}
	}

out:
	kv_pair_free(node_list);
	if (peer_list)
		kv_pair_free(peer_list);
	return rv;
}

/* 
 * Update or Write Config File:
 *	Update: iscsictl -f <filename> -U 
 *		NOTE: the config of inactive initiators/targets are retained
 *	Write: iscsictl -f <filename> -W 
 *		NOTE: the config of inactive initiators/targets are deleted
 */

static int iscsictl_config_file_write(char *fname)
{
	char    tmp_fname[256];
	int     len;
	FILE   *fhndl = NULL, *thndl;
	config_entry *conf_list = NULL;
	char    databuf[ISCSI_CONTROL_DATA_MAX_BUFLEN];
	int     buflen;
	char   *tmpbuf = databuf;
	int     rv;

	/* generate a unique tmp. file name */
	len = sprintf(tmp_fname, "/tmp/chiscsi-wrt");
	tmp_fname[len++] = '\0';

	fhndl = fopen(tmp_fname, "w");
	if (!fhndl) {
		fprintf(stderr, "ERROR: unable to write %s.\n", tmp_fname);
		return -1;
	}

	/* write globals */
	fprintf(fhndl, "%s:\n", config_type_str[CONF_TYPE_GLOBAL]);
	rv = iscsictl_drv_get(fhndl);
	if (rv < 0)
		goto out;

	/* write targets */

	/* databuf:<target>=<name>,... */
	rv = iscsictl_get_entity_names(KEY_TYPE_TARGET, databuf,
				       ISCSI_CONTROL_DATA_MAX_BUFLEN);
	if (rv < 0)
		goto out;
	buflen = strlen(databuf);
	/* no target active */
	if (!buflen)
		goto done;

	rv = iscsictl_config_get(fhndl, 1, &tmpbuf);
	if (rv < 0)
		goto done;

done:
	fflush(fhndl);
	fclose(fhndl);
	fhndl = NULL;

	/* copy the tmp file */
	fhndl = fopen(tmp_fname, "r");
	if (!fhndl) {
		fprintf(stderr, "ERROR: unable to read tmp file.\n");
		rv = -1;
		goto out;
	}
	thndl = fopen(fname, "w");
	if (!thndl) {
		fprintf(stderr, "ERROR: unable to write %s.\n", fname);
		rv = -1;
		goto out;
	}

	while (fgets(databuf, LINE_BUFFER_LENGTH, fhndl)) {
		fprintf(thndl, "%s", databuf);
	}
	fflush(thndl);
	fclose(thndl);
	fclose(fhndl);

	fhndl = NULL;
	thndl = NULL;

out:
	if (fhndl) {
		fflush(fhndl);
		fclose(fhndl);
	}
	if (conf_list)
		config_entry_free(conf_list);

	remove(tmp_fname);
	return rv;
}

/*
 * APIs for isns client
 */

int iscsictl_isns_cmd(int fd, char *rbuf, int rbuflen, char *dbuf, int dbuflen,
		      int cmd)
{
	int     rv;
	iscsi_control_args arg;

	if (cmd < 0 || cmd >= ISNS_REQ_MAX) {
		fprintf(stderr, "ERROR: isns cmd invalid %d.\n", cmd);
		return -1;
	}

	cmd += ISCSI_CONTROL_OPCODE_ISNS_BASE;

	rv = iscsictl_read_timestamp(ISCSICTL_TIMESTAMP_FILE);
	if (rv < 0)
		return rv;

	rv = iscsictl_read_keyfile();
	if (rv < 0)
		return rv;

	memset(&arg, 0, sizeof(iscsi_control_args));
	if (rbuf && rbuflen) {
		memcpy(arg.buf, rbuf, rbuflen);
	}
	if (dbuf && dbuflen) {
		arg.addr[1] = (unsigned long) dbuf;
		arg.len[1] = dbuflen;
		if (dbuf[0])
			arg.flag = ISCSI_CONTROL_FLAG_EXTRA_DATA;
	}

	rv = iscsictl_send_request(fd, cmd, arg);
	iscsictl_keyfile_cleanup();
	return rv;
}

/**
 * iscsictl_isns_get_portals -- get the target portal info for the isns client
 * 	NOTE: buflen should be ISCSI_CONTROL_DATA_MAX_BUFLEN 
 */
int iscsictl_isns_get_portals(int fd, char *buf, int buflen)
{
	int     rv;
	iscsi_control_args arg;

	rv = iscsictl_read_timestamp(ISCSICTL_TIMESTAMP_FILE);
	if (rv < 0)
		return rv;
	rv = iscsictl_read_keyfile();
	if (rv < 0)
		return rv;

	memset(&arg, 0, sizeof(iscsi_control_args));
	buf[0] = 0;
	arg.addr[1] = (unsigned long) buf;
	arg.len[1] = buflen;
	rv = iscsictl_send_request(fd,
				   ISCSI_CONTROL_OPCODE_ISNS_GET_TARGET_PORTALS,
				   arg);

	iscsictl_keyfile_cleanup();

	return rv;
}

/**
 * iscsictl_isns_get_targets -- get all the target info for the isns client
 * 	NOTE: buflen should be ISCSI_CONTROL_DATA_MAX_BUFLEN 
 */
int iscsictl_isns_get_targets(int fd, char *buf, int buflen)
{
	int     rv;
	iscsi_control_args arg;

	rv = iscsictl_read_timestamp(ISCSICTL_TIMESTAMP_FILE);
	if (rv < 0)
		return rv;
	rv = iscsictl_read_keyfile();
	if (rv < 0)
		return rv;

	memset(&arg, 0, sizeof(iscsi_control_args));
	buf[0] = 0;
	arg.addr[1] = (unsigned long) buf;
	arg.len[1] = buflen;
	rv = iscsictl_send_request(fd, ISCSI_CONTROL_OPCODE_ISNS_GET_TARGETS,
				   arg);
	iscsictl_keyfile_cleanup();
	return rv;
}

/*
 * APIs to iscsictl (user/cli/iscsictl.c)
 */

/* if cmd need to send to kernel */
int iscsictl_need_open_device(void)
{
#if 0
	if (cmd == ISCSI_CONTROL_OPCODE_ISNS_ADD)
		return 0;
#endif
	return 1;
}

int iscsictl_parse_cmd_option(int *idx_p, int argc, char **argv)
{
/* grab as much argument as possible */
#define GRAB_ARGS_TO_LIST(min,list_idx,list)	\
		do { \
			int		cnt = 0;	\
			char	*op = argv[idx]; \
			for (idx++; idx < argc; idx++) { \
				if (IS_CMD_OPTION(argv[idx])) { \
					idx--;	\
					break;	\
				} else { \
					list[list_idx++] = argv[idx]; \
					cnt++; \
				} \
			} \
			if (cnt < min) { \
				fprintf(stderr, "%s: missing operand.\n", op); \
				rv = -1; \
			} \
		} while(0)

	int     rv = 0;
	int     idx = *idx_p;
	int     cmd_save = cmd;
	char    option = argv[idx][1];

	rv = iscsictl_read_timestamp(ISCSICTL_TIMESTAMP_FILE);
	if (rv < 0)
		return rv;

	switch (option) {
		case 'd':
			debug = 1;
			break;
		case 'f':
			config_file = argv[++idx];
			break;
		case 'k':
			GRAB_ARGS_TO_LIST(1, key_cnt, key_list);
			break;
		case 'c':
			cmd = ISCSI_CONTROL_OPCODE_CONFIG_GET;
			GRAB_ARGS_TO_LIST(0, entity_cnt, entity_list);
			break;
		case 'F':
			cmd = ISCSI_CONTROL_OPCODE_TARGET_FLUSH;
			GRAB_ARGS_TO_LIST(0, entity_cnt, entity_list);
			break;
		case 'g':
			cmd = ISCSI_CONTROL_OPCODE_DRV_GET;
			break;
		case 'G':
			cmd = ISCSI_CONTROL_OPCODE_DRV_SET;
			GRAB_ARGS_TO_LIST(1, entity_cnt, entity_list);
			break;
		case 's':
			cmd = ISCSI_CONTROL_OPCODE_TARGET_REMOVE;
			GRAB_ARGS_TO_LIST(1, entity_cnt, entity_list);
			break;
		case 'S':
			cmd = ISCSI_CONTROL_OPCODE_TARGET_ADD;
			GRAB_ARGS_TO_LIST(0, entity_cnt, entity_list);
			break;
		case 'W':
			cmd = ISCSI_CONTROL_OPCODE_CONFIG_FILE_WRITE;
			break;
		case 'r':
			cmd = ISCSI_CONTROL_OPCODE_DBGDUMP;
			GRAB_ARGS_TO_LIST(1, entity_cnt, entity_list);
			break;
		case 'D':
			cmd = ISCSI_CONTROL_OPCODE_DROP_SESSION;
			sess_hndl = argv[++idx];
			break;
		case 'x':
			/* Global default params file argv[++idx], currently unimplemented */
			++idx;
			break;

		default:
			fprintf(stderr, "ERROR: Unrecognized option -%c.\n",
				option);
			rv = -1;
	}

	*idx_p = ++idx;

	if (!rv && (cmd_save != ISCSI_CONTROL_OPCODE_UNKNOWN) &&
	    (cmd_save != cmd)) {
		fprintf(stderr, "ERROR: too many command -%c.\n", option);
		rv = -1;
	}

	return rv;
}

/* command execution -- send to kernel */
int iscsictl_cmd_execute(int fd, int *isnsflag)
{
	int     rv = -1;
	config_entry *conf_list = NULL;

	if (debug) {
		int     i;
		printf("cmd = %d.\n", cmd);
		for (i = 0; i < entity_cnt; i++)
			printf("entity_list[%d]: %s.\n", i, entity_list[i]);
		for (i = 0; i < key_cnt; i++)
			printf("key_list[%d]: %s.\n", i, key_list[i]);
	}

	rv = iscsictl_read_keyfile();
	if (rv < 0)
		return rv;

	if (fd < 0) {
		fprintf(stderr, "iscsictl_execute: invalid descriptor: %d.\n",
			fd);
		return fd;
	}

	iscsictl_fd = fd;

	switch (cmd) {
		case ISCSI_CONTROL_OPCODE_TARGET_FLUSH:
			rv = iscsictl_target_flush(entity_cnt, entity_list,
						   key_cnt, key_list);
			break;

		case ISCSI_CONTROL_OPCODE_CONFIG_GET:
			if (!entity_cnt) {	/* get everything */
				/* get stats */
				iscsi_control_args arg;
				memset(&arg, 0, sizeof(iscsi_control_args));
				rv = iscsictl_send_request(iscsictl_fd,
							   ISCSI_CONTROL_OPCODE_STAT_GET,
							   arg);
				printf("%s\n", arg.buf);

				/* get all the node information */
				entity_list[entity_cnt++] = "target=ALL";
			}
			rv = iscsictl_config_get(NULL, entity_cnt, entity_list);
			break;

		case ISCSI_CONTROL_OPCODE_DRV_GET:
			rv = iscsictl_drv_get(NULL);
			break;

		case ISCSI_CONTROL_OPCODE_DRV_SET:
			rv = iscsictl_drv_set(entity_cnt, entity_list);
			break;

		case ISCSI_CONTROL_OPCODE_TARGET_ADD:
			if (!entity_cnt) {	/* reload */
				entity_list[entity_cnt++] = "target=ALL";
				cmd = ISCSI_CONTROL_OPCODE_TARGET_RELOAD;
			}
			if (key_cnt) {
				fprintf(stderr,
					"-k option can not be used with -S option\n");
				rv = -1;
				break;
			}
			rv = iscsictl_config_file_read(config_file ? config_file
						       :
						       ISCSICTL_CONFIG_FILE_DFLT,
						       &conf_list);
			if (rv < 0)
				break;

			rv = iscsictl_add_node(conf_list);
			break;

		case ISCSI_CONTROL_OPCODE_TARGET_REMOVE:
			if (key_cnt) {
				fprintf(stderr,
					"-k option can not be used with -s option\n");
				rv = -1;
				break;
			}
			rv = iscsictl_remove_node();
			break;

		case ISCSI_CONTROL_OPCODE_DBGDUMP:
			rv = iscsictl_get_sessions();
			break;

		case ISCSI_CONTROL_OPCODE_CONFIG_FILE_WRITE:
			if (!config_file) {
				fprintf(stderr,
					"ERROR: No configuration file is specified.\n");
				break;
			}
			rv = iscsictl_config_file_write(config_file);
			break;

		case ISCSI_CONTROL_OPCODE_DROP_SESSION:
			rv = iscsictl_drop_session(sess_hndl);
			break;

		default:
			fprintf(stderr, "ERROR: UNKNOWN command %d.\n", cmd);
			break;
	}			/* Endswitch (cmd) */

	if (conf_list)
		config_entry_free(conf_list);
	*isnsflag = isns_update;

	iscsictl_keyfile_cleanup();
	return rv;
}
