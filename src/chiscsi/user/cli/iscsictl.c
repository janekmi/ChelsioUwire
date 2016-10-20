/* 
 * Chelsio iSCSI module Command Line Interface software (iscsictl)
 *
 * This implementations used Linux ioctl interface to communicate with 
 * the Chelsio's Linux iscsi kernel module.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/time.h>

/* grab the iscsi release version */
#include "../../includes/common/version.h"
#include "../common/iscsictl_private.h"

/**
 * str_buffer_insert_time -- add timestamp to a character buffer
 * @buf: the buf should at least be able to hold 20 chars.
 *
 * could be used to add a timestamp or generate a unique file name 
 **/
int str_buffer_insert_time(char *buf)
{
	struct tm *tm_p;
	struct timeval time;
	int     len;

	gettimeofday(&time, NULL);
	tm_p = localtime((time_t *) & (time.tv_sec));
	len = sprintf(buf, "-%04d.%02d.%02d.%02d.%02d.%02d",
		      tm_p->tm_year + 1900, tm_p->tm_mon, tm_p->tm_mday,
		      tm_p->tm_hour, tm_p->tm_min, tm_p->tm_sec);
	printf("buf_append_time: %s.\n", buf);
	return len;
}

/**
 * iscsictl_show_usage -- display help message for iscsictl
 * @name: iscsictl name
 * @detail_usage: detailed or not
 *
 **/
void iscsictl_show_usage(char *name, int detail_usage)
{
	printf(" Usage: %s <option> [parameters]\n", name);
	printf("\n\
\
    -f <filename>                       Specify iSCSI configuration file,\n\
                                        default to /etc/chelsio-iscsi/chiscsi.conf.\n\
    -S [var=const]*                     Start and/or Reload iSCSI target(s)\n\
    -s <var=const>*                     Stop iSCSI target(s)\n\
    -c [var=const]*			Get iSCSI configuration\n\
    -g                                  Get iSCSI driver global settings\n\
    -G <var=const>**                    Set iSCSI driver global settings\n\
    -F [<var=const>* -k lun=<val>]      Flush data to the backend storage.\n\
    -r <var=const>* [-k key=<val>]      Retrieve session information\n\
    -D <Session handle in hex>		Drop active session\n\
    -W                                  Write only current iSCSI configuration to config file\n\
    -h                                  Display detailed usage messages\n\
    -v                                  Display version information\n\
    -x                                  Use global defaults from configuration file\n\
\n\
 Note: everything within square-brakets [] is optional, \n\
       everything angle-brackets <> is mandatory.\n\n");

	if (!detail_usage)
		return;

	printf("\
\n\
    key=value:\n\
          RFC3270 specified or Chelsio specific key=value pairs\n\
\n\
          If no key=value is specified,\n\
          command will be completed with no changes\n\
\n\
    *var=const:\n\
          target=<name1[,name2,...,nameN] | ALL>\n\
\n\
          For MANDATORY var=const parameter(s):\n\
          If no var=const is specified, command will be denied\n\
\n\
          For OPTIONAL var=const parameter(s):\n\
          If no target=<> is specified, default to ALL\n\
\n\
    **var=const:\n\
           iscsi_auth_order=<ACL | CHAP>\n\
	   iscsi_acl_order=<CONFIG | ISNS>\n\
           iscsi_login_complete_time=<N seconds>\n\
           iscsi_chelsio_ini_idstr=<chelsio initiator id substring>\n\
\n\
        discovery session chap control:\n\
           DISC_AuthMethod=<None | CHAP>\n\
           DISC_Auth_CHAP_Policy=<Oneway | Mutual>\n\
           DISC_Auth_CHAP_Target=\"<user id>\":\"<secret>\"\n\
           DISC_Auth_CHAP_Initiator=\"<user id>\":\"<secret>\"\n\
\n\
           If no var=const is specified,\n\
           command will be completed with no changes\n");
}

/**
 * iscsictl_parse_cmdline -- parse the cmd input line for options and parameters
 * @argc:
 * @argv
 **/
int iscsictl_parse_cmdline(int argc, char **argv)
{
	int     i, rv = 0;

	for (i = 1; i < argc;) {
		if (IS_CMD_OPTION(argv[i])) {
			if ((argv[i][1] == 'h') || (argv[i][1] == '?')) {
				iscsictl_show_usage(argv[0], 1);
				return 1;
			} else if (argv[i][1] == 'v') {
				printf("%s v%s-%s\n%s\n",
				       argv[0], DRIVER_VERSION, BUILD_VERSION,
				       COPYRIGHT);
				return 1;
			} else {
				rv = iscsictl_parse_cmd_option(&i, argc, argv);
				if (rv < 0 || rv > 0)
					return rv;
			}
		} else if (!strcmp(argv[i], "?")) {
			iscsictl_show_usage(argv[0], 0);
			return 1;
		} else {
			fprintf(stderr, "Invalid argument: %s.\n", argv[i]);
			return -1;
		}
	}

	return 0;
}

/**
 * main -- this is main function of iscsictl CLI
 * @argc:
 * @argv
 **/
int main(int argc, char **argv)
{
	int     rv;
	int     fd = -1;
	int     update_isns = 0;
	int     lockfd = -1;

	if (argc == 1) {
		iscsictl_show_usage(argv[0], 1);
		return 0;
	}

	rv = iscsictl_parse_cmdline(argc, argv);
	if (rv < 0)
		return rv;

	/* we are done */
	if (rv > 0)
		return 0;

	if (iscsictl_need_open_device()) {
		rv = iscsictl_open_device();
		if (rv < 0) {
			fprintf(stderr, "ERROR: cannot find iscsi device!\n");
			return rv;
		}
		fd = rv;
	}

	/* make sure only one instance of iscsictl is running at any given time */
	lockfd = open("/etc/chelsio-iscsi/iscsictl.pid", O_WRONLY | O_CREAT,
		      0644);
	if (lockfd < 0) {
		fprintf(stderr, "ERROR: unable to create iscsictl pid file\n");
		goto out;
	}
	if (lockf(lockfd, F_TLOCK, 0) < 0) {
		fprintf(stderr,
			"ERROR: unable to obtain exclusive lock, iscsictl already running?\n");
		close(lockfd);
		lockfd = -1;
		goto out;
	} else {
		char    buf[36];
		ftruncate(lockfd, 0);
		sprintf(buf, "%d\n", getpid());
		write(lockfd, buf, strlen(buf));
	}

	rv = iscsictl_cmd_execute(fd, &update_isns);

      out:
	if (lockfd >= 0) {
		lockf(lockfd, F_ULOCK, 0);
		close(lockfd);
	}
	if (fd >= 0)
		iscsictl_close_device(fd);

	if (update_isns)
		iscsictl_update_isns_client();

	return rv;
}
