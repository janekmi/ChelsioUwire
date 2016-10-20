#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <platdef.h>
#include <t4_regs.h>
#include <adap_util.h>
#include <common.h>
#include <t4_regs.h>
#include <t4_hw.h>
#include <cudbg_if.h>
#include <adapter.h>
#include <time.h>
#include <errno.h>
#include <inttypes.h>

#define CUDBG_DEFAULT_RETRY_COUNT 1
#define CUDBG_DEFAULT_RETRY_DELAY 0

#define INITIAL_OUTBUF_SIZE (5 * 1024 * 1024) /* 5MB */
#define NEXT_SIZE 1000000
#define ADP_NUM_LEN 10
#define MAX_BUFF_SIZE (32 * 1024 * 1024) /* 32MB */
#define MAX_SF_SIZE (2 * 1024 * 1024) /* 2MB */
#define ENTITY_LEN 20
#define IND_REG_FILE "all_regs"
#define FILE_WRITE_MODE "w"
#define FILE_APPEND_MODE "a+"
#define FILE_BIN_MODE "wb"
#define MAX_PARAM_LEN 256

void *global_buf;
u32 *global_buf_size;
FILE *global_file;
char *global_file_name;
extern int errno;

char *option_list[] = {
				"--collect",
				"--view",
				"--version",
				"--debug",
				"--info",
				"--readflash",
				"--extract",
				"--loadfw",
			};

typedef struct optional_flags {
	char *name;
	char *value;
	int val_check;	  /* Is check required on the value received  */
	int min_val;	  /* Minimum value expected */
	int val_expected;
} optional_flags_t;

enum {
	CUDBG_OPT_COLLECT,
	CUDBG_OPT_VIEW,
	CUDBG_OPT_VERSION,
	CUDBG_OPT_DEBUG,
	CUDBG_OPT_INFO,
	CUDBG_OPT_RD_FLASH,
	CUDBG_OPT_EXTRACT,
	CUDBG_OPT_FW
};

enum optional_flag_index {
	SKIP_LIST,
	RETRIES,
	DELAY,
	FLASH_FLAG,
	FLAG_FW_NO_ATTACH,
	MAX_OPT_FLAGS
};

optional_flags_t optional_flag_list[] = {
			{"--skip", NULL, 0, 0, 1},
			{"--retries", NULL, 1, 1, 1},
			{"--delay", NULL, 1, 1, 1},
			{"--flash", NULL, 0, 0, 0},
			{"--fwnoattach", NULL, 0, 0, 0},
		};

void usage()
{
	int i;

	printf("\n\n\t\tUsage:\n");
	printf("\t\tcudbg_app --collect <debug entity1, debug entity2, ...>"\
			" <ifname1, ifname2, ...> <outfilename> [--fwnoattach]"\
			" [--flash] [--skip debug entity1, debug entity2]"\
			"\n\t\t\t\t\t--retries <number of retires> --delay"\
			" <delay in seconds>\n");
	printf("\t\tcudbg_app --debug <debug entity1, debug entity2, ...>"\
			" <ifname1, ifname2, ...>" \
			" --retries <number of retires> --delay <delay in"\
			" seconds>\n\n");
	printf("\t\teg: cudbg_app --collect all eth16 outfilename\n");
	printf("\t\teg: cudbg_app --collect all eth16,eth17 outfilenam"\
			" --flash\n");
	printf("\t\teg: cudbg_app --collect all eth16 outfilename"\
			" --fwnoattach\n");
	printf("\t\teg: cudbg_app --collect all eth16,eth17 outfilename --skip"\
			" mc0\n");
	printf("\t\teg: cudbg_app --collect all eth16,eth17 outfilename --skip"\
			" mc0 --retries 3 --delay 1\n");
	printf("\t\teg: cudbg_app --debug devlog eth16,eth17\n");
	printf("\t\teg: cudbg_app --debug wtp eth16,eth17 --skip mc0"\
			" --retries 3 --delay 1\n");
	printf("\t\t\t\tOR\n\n");
	printf("\t\tcudbg_app --collect <debug entity> <pci device1, pci"\
			" device2, ...> <outfilename>\n\n");
	printf("\t\teg: cudbg_app --collect  all"\
			" \"/sys/bus/pci/devices/0000:01:00.4\" outfilename\n\n\n");
	printf("\t\tcudbg_app --extract <debug entity> --path <directory path"\
			" to dump debug files> <infilename>\n\n\n");
	printf("\t\tcudbg_app --view <debug entity> <infilename>\n\n\n");
	printf("\t\tcudbg_app --info <infilename>\n\n\n");
	printf("\t\tcudbg_app --readflash <ifname1, ifname2, ...>"\
			" <outfilename>\n\n\n");
	printf("\t\tcudbg_app --loadfw <ifname> <fw_binary_path>\n\n");
	printf("\t\teg: cudbg_app --loadfw eth16 /root/t5fw-1.15.22.0.bin\n");
	printf("\t\teg: cudbg_app --loadfw \"/sys/bus/pci/devices/0000:01:00.4\" "\
			"/root/t5fw-1.15.22.0.bin\n\n\n");
	printf("\t\tcudbg_app --version\n\n\n");
	printf("\t\t<debug entities>\n\n");
	printf("\t\t\t");
	for (i = 0; i < ARRAY_SIZE(entity_list); i++) {
		if (entity_list[i].bit == CUDBG_EXT_ENTITY)
			continue;

		if (!(i % 5))
			printf("\n\t\t\t");
		printf("%-13s\t", entity_list[i].name);
	}
	printf("\n\n");
}

int check_dbg_entity(char *entity)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(entity_list); i++) {
		if (!strcmp(entity, entity_list[i].name))
			return entity_list[i].bit;
	}
	return -1;
}

int validate_entity_list(char *dbg_entity_list)
{
	char *dbg_entity;
	int rc;
	char tmp_dbg_entity_list[MAX_PARAM_LEN];

	strcpy(tmp_dbg_entity_list, dbg_entity_list);
	dbg_entity = strtok(tmp_dbg_entity_list, ",");
	while (dbg_entity != NULL) {
		rc = check_dbg_entity(dbg_entity);
		if (rc < 0) {
			printf("\n\tInvalid debug entity: %s\n", dbg_entity);
			usage();
			return rc;
		}
		dbg_entity = strtok(NULL, ",");
	}
	return 0;
}

int  set_dbg_entity(u8 *dbg_bitmap, char *dbg_entity_list)
{
	int i, dbg_entity_bit, rc = 0;
	char *dbg_entity;
	dbg_entity = strtok(dbg_entity_list, ",");
	while (dbg_entity != NULL) {
		rc = check_dbg_entity(dbg_entity);
		if (rc < 0) {
			printf("\n\tInvalid debug entity: %s\n", dbg_entity);
			usage();
			return rc;
		}

		dbg_entity_bit = rc;

		if (dbg_entity_bit == CUDBG_ALL) {
			for (i = 1; i < CUDBG_MAX_ENTITY; i++)
				set_dbg_bitmap(dbg_bitmap, i);
			set_dbg_bitmap(dbg_bitmap, CUDBG_ALL);
			break;
		} else {
			set_dbg_bitmap(dbg_bitmap, dbg_entity_bit);
		}

		dbg_entity = strtok(NULL, ",");
	}

	return 0;
}

int modify_dbg_bitmap(u8 *dbg_bitmap, char *skip_list)
{
	int rc, skip_bit;
	char *skip_entity;

	skip_entity = strtok(skip_list, ",");
	while (skip_entity != NULL) {
		rc = check_dbg_entity(skip_entity);
		if (rc < 0) {
			printf("\n\tInvalid debug entity: %s\n", skip_entity);
			usage();
			return rc;
		}

		skip_bit = rc;
		reset_dbg_bitmap(dbg_bitmap, skip_bit);
		reset_dbg_bitmap(dbg_bitmap, CUDBG_ALL);
		skip_entity = strtok(NULL, ",");
	}
	return 0;
}

static int init_cudbg(struct cudbg_init *dbg_init, char *dbg_entity_list, char *skip_list)
{
	int rc = 0;

	init_cudbg_hdr(&(dbg_init->header));
	dbg_init->verbose = 0;
	dbg_init->full_mode = 0;
	dbg_init->no_compress = 1;
	rc = set_dbg_entity(dbg_init->dbg_bitmap,  dbg_entity_list);
	if (skip_list != NULL)
		rc = modify_dbg_bitmap(dbg_init->dbg_bitmap, skip_list);

	dbg_init->print = (cudbg_print_cb) printf;
	dbg_init->sw_state_buf = NULL;
	dbg_init->sw_state_buflen = 0;

	return rc;
}

/* index is the zero based position of --skip in the command line */
int check_optional_flags(char *argv[], int argc, int index,
		optional_flags_t (*optional_flag_list)[])
{
	int i, j;

	for (j = index; j < argc; j++) {
		for (i = 0; i < MAX_OPT_FLAGS; i++) {
			if (!strcmp(argv[j], (*optional_flag_list)[i].name)) {

				if (j+1 < argc &&
					(*optional_flag_list)[i].val_expected) {
					(*optional_flag_list)[i].value =
					argv[++j];

				} else if ((*optional_flag_list)[i].val_expected) {
					printf("\n\tMissing %s argument list\n",
						(*optional_flag_list)[i].name);
					return -1;
				} else {
					(*optional_flag_list)[i].value = "1"; /* Set default value */
				}

				if ((*optional_flag_list)[i].val_check
						&& (atoi(
						(*optional_flag_list)[i].value)
						< (*optional_flag_list)[i].min_val)) {
					printf("\n\tInvalid option %s for %s\n"
							, (*optional_flag_list)[i].value,
							(*optional_flag_list)[i].name);
					return -1;
				}
			}
		}
	}
	return 0;
}

int check_option(char *opt)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(option_list); i++) {
		if (!strcmp(opt, option_list[i]))
			return i;
	}
	return -1;
}

int read_from_flash(char *iff_list, char *out_file)
{
	struct cudbg_flash_hdr flash_hdr;
	void *handle = NULL;
	void *buf = NULL;
	u32 buf_size = 0;
	struct cudbg_init *dbg_init = NULL;
	int rc = 0;
	int count;
	char *iff;
	FILE *out_fp;

	out_fp = fopen(out_file, "wb");
	if (!out_fp) {
		perror("error in opening file ");
		rc = -1;
		goto out;
	}

	dbg_init = (struct cudbg_init *) malloc(sizeof(struct cudbg_init));
	if (dbg_init == NULL) {
		rc = CUDBG_STATUS_NOSPACE;
		goto out;
	}

	memset(dbg_init, 0, sizeof(struct cudbg_init));
	rc = init_cudbg(dbg_init, NULL, NULL);
	if (rc != 0) {
		printf("init_cudbg failed :%s\n", err_msg[-rc]);
		goto out;
	}

	iff = strtok(iff_list, ",");
	while (iff != NULL) {

		rc = set_adapter_fields(&(dbg_init->adap), iff);

		if (rc != 0) {
			printf("Adapter init failed :%s\n", err_msg[-rc]);
			goto out;
		}

		rc = cudbg_hello(dbg_init, &handle);
		if (rc != 0) {
			printf("cudbg_hello failed :%s\n", err_msg[-rc]);
			goto out;
		}

		rc = cudbg_read_flash_details(handle, &flash_hdr);
		if (rc != 0)
			goto out;

		buf_size = flash_hdr.data_len + sizeof(struct cudbg_flash_hdr);

		buf = malloc(buf_size);
		if (buf == NULL) {
			rc = CUDBG_STATUS_NOSPACE;
			goto out;
		}

		rc = cudbg_read_flash_data(handle, buf, buf_size);

		printf("Writing %u bytes to %s.\n", buf_size, out_file);
		count = fwrite(buf, 1, buf_size, out_fp);
		if (count <= 0) {
			perror("error in writing to file ");
			rc = -1;
			rc = CUDBG_STATUS_FILE_WRITE_FAILED;
			goto out;
		}

		cudbg_bye(handle);

		put_adapter_fields(&dbg_init->adap);

		iff = strtok(NULL, ",");
		free(buf);
		buf = NULL;
	}

out:

	if (dbg_init && dbg_init->adap)
		put_adapter_fields(&dbg_init->adap);
	if (dbg_init)
		free(dbg_init);
	if (out_fp)
		fclose(out_fp);
	if (buf)
		free(buf);
	if (handle)
		cudbg_bye(handle);
	return 0;

}

static int lockfd;

void cudbg_exit(int sig)
{
	int count;

	lockf(lockfd, F_ULOCK, 0);
	close(lockfd);

	if (!global_buf)
		exit(-1);

	count = fwrite(global_buf, 1, *global_buf_size, global_file);
	if (count <= 0) {
		perror("error in writing to file ");
	} else {
		printf("\n\tCollected %u bytes Debug Information to file"\
				" \"%s\"\n\n", *global_buf_size,
				global_file_name);
	}

	if (global_file)
		fclose(global_file);
	if (global_buf)
		free(global_buf);
	exit(sig);
}

int cudbg_init()
{
	char file[CUDBG_FILE_NAME_LEN];
	int rc;

	sprintf(file, "%s", "lock_file");
	lockfd = open(file, O_WRONLY | O_CREAT, 644);
	if (lockfd < 0)
		return 0;

	if (lockf(lockfd, F_TLOCK, 0) < 0) {
		close(lockfd);
		return 0;
	} else {
		char buf[10];

		rc = ftruncate(lockfd, 0);
		if (rc) {
			perror("error in file truncate ");
			return 0;
		}

		sprintf(buf, "%d\n", getpid());
		rc = write(lockfd, buf, strlen(buf));
		if (rc <= 0) {
			perror("error in writing to file ");
			return 0;
		}
	}
	signal(SIGINT, cudbg_exit); /* Handle signals */
	signal(SIGTERM, cudbg_exit);
	signal(SIGQUIT, cudbg_exit);
	signal(SIGHUP, cudbg_exit);
	signal(SIGSEGV, cudbg_exit);
	signal(SIGABRT, cudbg_exit);
	signal(SIGTSTP, cudbg_exit);

	return 1;
}

int do_loadfw(char *iff, char *fw_file)
{
	struct cudbg_init *dbg_init = NULL;
	void *handle = NULL;
	uint8_t *buf = NULL;
	struct stat sb;
	int fd = 0, rc = 0;
	size_t len;

	dbg_init = (struct cudbg_init *) malloc(sizeof(struct cudbg_init));
	if (dbg_init == NULL) {
		rc = CUDBG_STATUS_NOSPACE;
		goto out;
	}

	memset(dbg_init, 0, sizeof(struct cudbg_init));

	rc = init_cudbg(dbg_init, NULL, NULL);
	if (rc != 0) {
		printf("init_cudbg failed %s\n", err_msg[-rc]);
		goto out;
	}
	if (iff != NULL) {
		printf("\nInterface %s :\n", iff);
		rc = set_adapter_fields(&dbg_init->adap, iff);
		if (rc) {
			printf("Set adapter fields failed %s : %s [Maybe"\
					" invalid interface]\n", iff,
					err_msg[-rc]);
			goto out;
		}

		rc = cudbg_hello(dbg_init, &handle);
		if (rc != 0) {
			printf("cudbg_hello failed :%s\n", err_msg[rc]);
			goto out;
		}

		fd = open(fw_file, O_RDONLY);
		if (fd < 0) {
			printf("Cannot open %s\n", fw_file);
			goto out;
		}
		if (fstat(fd, &sb) < 0) {
			printf(" File stats error for %s\n", fw_file);
			goto out;
		}

		len = (size_t)sb.st_size;
		buf = malloc(sizeof(uint8_t) * len);
		if (!buf) {
			printf("Failed to allocate %ld bytes for fw_file-%s", (long)len, fw_file);
			goto out;
		}
		if (read(fd, buf, len) < len) {
			printf(" Buffer read failed for file %s", fw_file);
			goto out;
		}

		rc = cudbg_loadfw(dbg_init, buf, len);
		if (rc) {
			printf("cudbg_loadfw failed :%d\n", rc);
			goto out;
		}
	}

out:
	if (dbg_init && dbg_init->adap)
		put_adapter_fields(&dbg_init->adap);
	if (dbg_init)
		free(dbg_init);
	if (fd)
		close(fd);
	if (buf)
		free(buf);
	if (handle)
		cudbg_bye(handle);
	return rc;
}

int is_valid_dbg_entity(char *dbg_entity_list)
{
	int dbg_entity_bit, rc = 0;
	char *dbg_entity;
	char tmp_dbg_entity_list[MAX_PARAM_LEN];
 
	strcpy(tmp_dbg_entity_list, dbg_entity_list);
	dbg_entity = strtok(tmp_dbg_entity_list, ",");
	while (dbg_entity != NULL) {

		rc = check_dbg_entity(dbg_entity);
		if (rc < 0) {
			printf("\n\tInvalid debug entity: %s\n", dbg_entity);
			return rc;
		}

		dbg_entity_bit = rc;
		if (dbg_entity_bit == CUDBG_ALL) {
			printf("\n\t\"%s\" is not supported in debug command\n\n",
			       dbg_entity);
			return CUDBG_STATUS_NOT_SUPPORTED;
		}

		if (entity_list[dbg_entity_bit].flag & 1 << ENTITY_FLAG_BINARY) {
			printf("\n\t %s entity is not supported for debug "\
			       "command. Please use extract command\n\n",
			       dbg_entity);
			return CUDBG_STATUS_NOT_SUPPORTED;
		}

		dbg_entity = strtok(NULL, ",");
	}

	return 0;
}

int do_collect(char *dbg_entity_list, char *iff_list, char *out_file,
		optional_flags_t optional_flag_list[], int option)
{
	void *handle = NULL;
	void *buf = NULL;
	FILE *out = NULL;
	struct cudbg_init *dbg_init = NULL;
	u32 buf_size = 0;
	u32 tmp_buff_size;
	int rc = 0, retries, delay, count;
	int flash = 0;
	int fw_no_attach = 0;
	char *iff;

	

	dbg_init = (struct cudbg_init *) malloc(sizeof(struct cudbg_init));
	if (dbg_init == NULL) {
		rc = CUDBG_STATUS_NOSPACE;
		goto out;
	}
	memset(dbg_init, 0, sizeof(struct cudbg_init));

	rc = init_cudbg(dbg_init, dbg_entity_list, optional_flag_list[0].value);
	if (rc != 0) {
		printf("init_cudbg failed %s\n", err_msg[-rc]);
		goto out;
	}

	if (optional_flag_list[FLAG_FW_NO_ATTACH].value)
		fw_no_attach =
			atoi(optional_flag_list[FLAG_FW_NO_ATTACH].value);

	if (fw_no_attach) {
		dbg_init->dbg_params[CUDBG_FW_ATTACH_PARAM].param_type =
				CUDBG_FW_ATTACH_PARAM;
		dbg_init->dbg_params_cnt++;
	}

	if (optional_flag_list[FLASH_FLAG].value)
		flash = atoi(optional_flag_list[FLASH_FLAG].value);

	if (flash) {
		dbg_init->use_flash = 1;
		dbg_init->dbg_params[CUDBG_TIMESTAMP_PARAM].u.time = time(NULL);
		dbg_init->dbg_params[CUDBG_TIMESTAMP_PARAM].param_type =
				CUDBG_TIMESTAMP_PARAM;
		dbg_init->dbg_params_cnt++;
	}

	buf_size = MAX_BUFF_SIZE;

	buf = (void *)malloc(buf_size);
	if (buf == NULL) {
		rc = CUDBG_STATUS_NOSPACE;
		goto out;
	}
	memset(buf, 0, buf_size);

	if (option != CUDBG_OPT_DEBUG) {
		out = fopen(out_file, "wb");
		if (!out) {
			perror("error in opening file ");
			rc = -1;
			goto out;
		}
		global_file_name = out_file;
		global_file = out;
	}

	iff = strtok(iff_list, ",");
	while (iff != NULL) {
		printf("\nInterface %s :\n", iff);
		rc = set_adapter_fields(&dbg_init->adap, iff);
		if (rc) {
			printf("Set adapter fields failed %s : %s [Maybe"\
					" invalid interface]\n", iff,
					err_msg[-rc]);
			goto out;
		}

		rc = cudbg_hello(dbg_init, &handle);
		if (rc != 0) {
			printf("cudbg_hello failed :%s\n", err_msg[rc]);
			goto out;
		}

		if (optional_flag_list[1].value)
			retries = atoi(optional_flag_list[1].value);
		else
			retries = CUDBG_DEFAULT_RETRY_COUNT;
		if (optional_flag_list[1].value && optional_flag_list[2].value)
			delay = atoi(optional_flag_list[2].value);
		else
			delay = CUDBG_DEFAULT_RETRY_DELAY;

		while (retries--) {
			tmp_buff_size = buf_size;
			global_buf_size = &tmp_buff_size;
			if (option != CUDBG_OPT_DEBUG)
				global_buf = buf;
			rc = cudbg_collect(handle, buf, &tmp_buff_size);

			if (option == CUDBG_OPT_DEBUG) {
				cudbg_view(handle, buf, tmp_buff_size, NULL, 0);
				printf("\n\t\t<========================END===="\
						"==================>\t\t\n\n\n");
			}

			sleep(delay);

			if (option != CUDBG_OPT_DEBUG) {
				count = fwrite(buf, 1, tmp_buff_size, out);
				if (count <= 0) {
					perror("error in writing to file ");
					rc = CUDBG_STATUS_FILE_WRITE_FAILED;
					goto out;
				} else {
					printf("\n\tCollected %u bytes Debug"\
							" Information to file"\
							" \"%s\"\n\n",
							*global_buf_size,
							 global_file_name);
				}
			}

			memset(buf, 0, buf_size);
		}
		if (rc) {

			printf("cudbg_collect failed with err :%s\n",
					err_msg[-rc]);
			goto out;
		}

		iff = strtok(NULL, ",");

		cudbg_bye(handle);

		put_adapter_fields(&dbg_init->adap);
	}

out:
	if (dbg_init && dbg_init->adap)
		put_adapter_fields(&dbg_init->adap);
	if (dbg_init)
		free(dbg_init);
	if (out)
		fclose(out);
	if (buf)
		free(buf);
	if (handle)
		cudbg_bye(handle);
	return rc;
}

int read_input_file(char *in_file, void **buf, u32 *buf_size)
{
	FILE *fptr = NULL;
	int rc = 0;

	fptr = fopen(in_file, "rb");
	if (!fptr) {
		perror("error in opening file ");
		rc = -1;
		goto out;
	}
	rc = fseek(fptr, 0, SEEK_END);
	if (rc < 0) {
		perror("error in seeking file ");
		rc = -1;
		goto out;
	}
	*buf_size = ftell(fptr);
	rc = fseek(fptr, 0, SEEK_SET);
	if (rc < 0) {
		perror("error in seeking file ");
		rc = -1;
		goto out;
	}
	*buf = (void *) malloc(*buf_size);
	if (*buf == NULL) {
		rc = CUDBG_STATUS_NOSPACE;
		goto out;
	}
	memset(*buf, 0, *buf_size);

	rc = fread(*buf, 1, *buf_size, fptr);
	if (rc <= 0) {
		perror("error in reading from file ");
		goto out;
	}

out:
	if (fptr)
		fclose(fptr);

	return rc;
}

void do_bye(void *handle)
{
	cudbg_bye(handle);
}

int do_hello(void **handle, int info, char *dbg_entity_list, optional_flags_t
		optional_flag_list[])
{
	struct cudbg_init *dbg_init = NULL;
	int rc = 0;

	dbg_init = (struct cudbg_init *) malloc(sizeof(struct cudbg_init));
	if (dbg_init == NULL) {
		rc = CUDBG_STATUS_NOSPACE;
		goto out;
	}
	memset(dbg_init, 0, sizeof(struct cudbg_init));

	rc = init_cudbg(dbg_init, dbg_entity_list, optional_flag_list[0].value);
	if (rc != 0) {
		printf("init_cudbg failed :%s\n", err_msg[-rc]);
		goto out;
	}

	if (info)
		dbg_init->info = 1;

	rc = cudbg_hello(dbg_init, handle);
	if (rc != 0) {
		printf("cudbg_hello failed :%s\n", err_msg[-rc]);
		goto out;
	}

out:
	if (dbg_init)
		free(dbg_init);
	return rc;
}

int write_to_file(char *poutbuf, u32 poutbuf_size, char *entity_name,
		char *dir_name, char *f_flags)
{
	int dir_length, rc = 0;
	FILE *fptr;
	char filepath[CUDBG_FILE_NAME_LEN];
	char tmp[ADP_NUM_LEN];

	if (poutbuf_size <= 0)
		goto out;

	dir_length = strlen(dir_name);
	/*255 because we will add '/' */
	if (dir_length + strlen(entity_name) > 255) {
		printf("\n\tfile path should not be greater than 256 bytes\n");
		exit(1);
	}

	strcpy(filepath, dir_name);
	filepath[dir_length] = '/';
	filepath[dir_length+1] = '\0';
	strcat(filepath, entity_name);

	if (strcmp(f_flags, FILE_BIN_MODE))
		sprintf(tmp, ".txt");
	else
		tmp[0] = '\0';

	strcat(filepath, tmp);

	fptr = fopen(filepath, f_flags);
	if (fptr == NULL) {
		perror("\n\tCan not create file\n");
		exit(1);
	}

	if (strcmp(f_flags, FILE_BIN_MODE))
		rc = fprintf(fptr, "%s" , poutbuf);
	else
		fwrite(poutbuf, poutbuf_size, 1, fptr);

	if (rc < 0)
		rc = CUDBG_STATUS_FILE_WRITE_FAILED;

	fclose(fptr);
out:
	return rc;
}

int process_debug_buffer(void *handle, void *buf, u32 buf_size,
		u32 entity_num, char *dir_name)
{
	char *poutbuf = NULL;
	u32 poutbuf_size = 0;
	u32 next_offset = 0;
	u32 size_factor = 1;
	int adp_num = 1;
	int data_len = 0;
	int rc = 0;
	static int count;
	char tmp_dir_name[CUDBG_DIR_NAME_LEN];

	do {
		if (buf_size-next_offset <= 0)
			break;

		do {
			/* extract option */
			if (dir_name != NULL) {
				free(poutbuf);
				if (!((int)poutbuf_size > 0 &&
					data_len ==
					CUDBG_STATUS_OUTBUFF_OVERFLOW))
					poutbuf_size = INITIAL_OUTBUF_SIZE +
						size_factor * NEXT_SIZE;

				if (data_len == CUDBG_STATUS_OUTBUFF_OVERFLOW)
					printf("Entity extraction failed,"\
							" retrying with next"\
							" size %u\n",
							poutbuf_size);

				poutbuf = (char *)malloc(poutbuf_size);
			}

			data_len = cudbg_view(handle, buf+next_offset,
					buf_size-next_offset, poutbuf,
					&poutbuf_size);
			count++;
			size_factor = size_factor * 2;
			/* Next iteration will allocate size_factor *
			 * NEXT_SIZE bytes if poutbuf_size -ve */
		} while (data_len == CUDBG_STATUS_OUTBUFF_OVERFLOW);

		if (data_len < 0) {
			rc = data_len;
			goto out;
		}

		/* extract option */
		if ((dir_name != NULL) && poutbuf_size) {
			sprintf(tmp_dir_name, "%s/debug_%d", dir_name, adp_num);
			rc = mkdir(tmp_dir_name, S_IRWXU | S_IRWXG | S_IROTH
					| S_IXOTH);
			if (rc && errno != EEXIST) {
				perror(" directory can not be created...");
				goto out;
			}

			if (entity_list[entity_num].flag & 1 <<
					ENTITY_FLAG_REGISTER)
				rc = write_to_file(poutbuf, poutbuf_size,
						IND_REG_FILE, tmp_dir_name,
						FILE_APPEND_MODE);

			if (entity_list[entity_num].flag & 1 <<
					ENTITY_FLAG_BINARY)
				rc = write_to_file(poutbuf, poutbuf_size,
						entity_list[entity_num].name,
						tmp_dir_name, FILE_BIN_MODE);
			else
				rc = write_to_file(poutbuf, poutbuf_size,
						entity_list[entity_num].name,
						tmp_dir_name, FILE_WRITE_MODE);

			free(poutbuf);
			poutbuf = NULL;

			if (rc < 0)
				goto out;

			adp_num++;
		}

		next_offset += data_len;

	} while (data_len > 0);

	return count;
out:
	return rc;
}

int do_extract_view(char *dbg_entity_list, char *in_file, int info,
				optional_flags_t optional_flag_list[],
				char *dir_name)
{
	char entity_name[ENTITY_LEN];
	void *handle = NULL;
	void *buf = NULL;
	u32 buf_size = 0;
	int rc = 0, i, all = 0;
	int cnt = 0;
	int extract = 0;

	rc = validate_entity_list(dbg_entity_list);
	if (rc != 0)
		goto out;

	if (dir_name != NULL)
		extract = 1;

	if (extract) {
		rc = mkdir(dir_name, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
		if (errno == EEXIST) {
			printf("\n\"%s\" directory already exist, first remove"\
					" it\n", dir_name);
			goto out;
		} else if (rc) {
			perror("directory can not be created...");
			goto out;
		}
	}

	rc = read_input_file(in_file, &buf, &buf_size);
	if (rc < 0)
		goto out;


	if (!strcmp(dbg_entity_list, "all"))
		all = 1;

	for (i = 1; i < CUDBG_MAX_ENTITY; i++) {
		if (all || (strstr(dbg_entity_list, entity_list[i].name) !=
					NULL)) {
			if (!info && !extract  && (entity_list[i].flag & 1 <<
						ENTITY_FLAG_BINARY)) {
				printf("\nPlease use --extract option to dump"\
						" binary entity %s\n\n",
						entity_list[i].name);
				continue;
			}

			if (all && !extract)
				strcpy(entity_name, entity_list[0].name);
			else
				strcpy(entity_name, entity_list[i].name);

			rc = do_hello(&handle, info, entity_name,
					optional_flag_list);
			if (rc)
				goto out;

			rc = process_debug_buffer(handle, buf, buf_size, i,
					dir_name);
			if (rc == CUDBG_STATUS_NO_SIGNATURE ||
			    rc == CUDBG_METADATA_VERSION_MISMATCH)
				goto out;

			do_bye(handle);
			if (all && !extract)
				break;
		}
	}

	if (extract)
		printf("\nDebug logs extracted to %s\n", dir_name);
	else if (cnt && !all)
		printf("\nTotal debug entities %d\n\n", cnt);

out:
	if (buf)
		free(buf);
	if (handle)
		cudbg_bye(handle);

	return rc;
}

#if 0
int do_view(char *dbg_entity_list, char *in_file, int info,
		optional_flags_t optional_flag_list[])
{
	void *handle = NULL;
	void *buf = NULL;
	u32 buf_size = 32 * 1024 * 1024;
	u32  next_offset = 0;
	int data_len;
	int rc = 0;

	rc = do_hello(&handle, info, dbg_entity_list, optional_flag_list);
	if (rc)
		goto out;
	/* rcad from file */
	rc = read_input_file(in_file, &buf, &buf_size);
	if (rc < 0)
		goto out;

	do {
		if (buf_size-next_offset <= 0)
			break;

		data_len = cudbg_view(handle, buf+next_offset,
				buf_size-next_offset, NULL, 0);
		next_offset += data_len;
		if (data_len > 0)
			printf("\n\t\t<========================END============="\
					"===========>\t\t\n\n\n");
	} while (data_len > 0);

out:
	if (buf)
		free(buf);
	if (handle)
		cudbg_bye(handle);
	return rc;
}
#endif

int main(int argc, char *argv[])
{
	char *out_file;
	int rc = 0, option;

	while (!cudbg_init()) {
		perror("Another instance of CUDBG is already running....");
		sleep(2);
	}

	if (geteuid() != 0) {
		printf("Please run %s as root\n", argv[0]);
		return -EPERM;
	}

	if (argc < 2) {
		printf("\n\tInvalid number of arguments %d\n", argc);
		usage();
		rc = -1;
		goto err;
	}

	rc = check_option(argv[1]);
	if (rc < 0) {
		printf("\n\tInvalid option: %s\n", argv[1]);
		usage();
		goto err;
	}
	option = rc;

	if (option == CUDBG_OPT_VERSION) {
		printf("Version %d.%d.%d\n", CUDBG_MAJOR_VERSION,
				CUDBG_MINOR_VERSION, CUDBG_BUILD_VERSION);
		return 0;
	}

	if (argc < 3) {
		printf("\n\tInvalid number of arguments %d\n", argc);
		usage();
		rc = -1;
		goto err;
	}

	if (option == CUDBG_OPT_INFO) {
		char tmp[4];

		out_file = argv[2];
		rc = check_optional_flags(argv, argc, 3, &optional_flag_list);
		if (rc)
			goto err;
		strcpy(tmp, "all");
		rc = do_extract_view(tmp, out_file, 1, optional_flag_list,
				NULL);

	} else if (option == CUDBG_OPT_COLLECT) {

		if (argc < 5) {
			printf("\n\tInvalid number of arguments %d\n", argc);
			usage();
			rc = -1;
			goto err;
		}

		rc = check_optional_flags(argv, argc, 5, &optional_flag_list);
		if (rc)
			goto err;

		out_file = argv[4];
		if (out_file[0] == '-') {
			printf("\n\tFile name \"%s\" beginning with '-' is not"\
					" supported\n", out_file);
			usage();
			rc = -1;
			goto err;
		}

		rc = do_collect(argv[2], argv[3], out_file, optional_flag_list,
				option);

	} else if (option == CUDBG_OPT_VIEW) {

		if (argc < 4) {
			printf("\n\tInvalid number of arguments %d\n", argc);
			usage();
			rc = -1;
			goto err;
		}

		rc = check_optional_flags(argv, argc, 4, &optional_flag_list);
		if (rc)
			goto err;

		out_file = argv[3];
		if (out_file[0] == '-') {
			printf("\n\tFile name \"%s\" beginning with '-' is not"\
					" supported\n", out_file);
			usage();
			rc = -1;
			goto err;
		}

		rc = do_extract_view(argv[2], out_file, 0, optional_flag_list,
				NULL);
	} else if (option == CUDBG_OPT_DEBUG) {
		rc = is_valid_dbg_entity(argv[2]);
		if (rc)
			goto err;

		rc = check_optional_flags(argv, argc, 4, &optional_flag_list);
		if (rc)
			goto err;

		rc = do_collect(argv[2], argv[3], argv[4], optional_flag_list,
				option);
	} else if (option == CUDBG_OPT_RD_FLASH) {
		rc = read_from_flash(argv[2], argv[3]);
	} else if (option == CUDBG_OPT_EXTRACT) {
		if (argc < 6 && strcmp(argv[3], "--path")) {
			printf("\n\tInvalid number of arguments %d\n", argc);
			usage();
			rc = -1;
			goto err;
		}
		rc = do_extract_view(argv[2], argv[5], 0, optional_flag_list,
				argv[4]);
	} else if (option == CUDBG_OPT_FW) {
		if (argc < 4) {
			printf("\n\tInvalid number of arguments %d\n", argc);
			usage();
			rc = -1;
			goto err;
		}
		rc = do_loadfw(argv[2], argv[3]);
	}

err:
	return rc;
}
