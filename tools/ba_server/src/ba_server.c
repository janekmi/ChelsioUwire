#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/signal.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#define	MULTI_DATA_PORTS
#define SYS_FILE		"/sys/class/net"

#include "cxgbtool.h"
#include "ba_server.h"
#include "t4_switch.h"
#include "hw_bypass.h"
#include "t4fw_interface.h"

struct ba_adapters		ba_adapters[MAX_BA_IFS];
int				ba_adapter_index;

extern u_int	sw_init(int ipv6);
void		ba_shell(void);
void		ba_recv(void);
int		ba_main(int argc, char *argv[], int sock);
void		bypass_help(void);
void		redirect_help(void);
int		ba_get_adapters();
int		ba_setup_socket(void);
int		ba_get_devname(void);
int		ba_verify_devname(char *devname);

/*
 * sub-command handlers
 */
int	ba_redirect_list(void);
int	ba_redirect_add(void);
int	ba_redirect_update(void);
int	ba_redirect_delete(void);
int	ba_redirect_purge(void);
int	ba_redirect_move(void);
int	ba_redirect_match(void);
int	ba_redirect_create_table(void);
int	ba_redirect_activate_table(void);
int	ba_redirect_deactivate_table(void);
int	ba_redirect_delete_table(void);
int	ba_redirect_count(void);
int	ba_bypass_get(void);
int	ba_bypass_set(void);
int	ba_redirect_dump(void);

int  	ba_set_state(int which, char * param);
int  	ba_set_watchdog(char * param);
int  	ba_set_watchdog_timeout(char * param);

int  	ba_get_watchdog(void);
int  	ba_get_watchdog_timeout(void);
int  	ba_get_debug(void);

int		server_sock;
char		lockfile[64];
char		sockpath[64];
int		ipv6 = 0;

/* global state variables */
int	ba_current_state = BA_STATE_DEFAULT;
int	ba_default_state = BA_STATE_DEFAULT;
int	ba_watchdog_state = BA_WATCHDOG_STATE_DEFAULT;
int	ba_watchdog_timeout = 0;

void
sigusr(int sig)
{
	return;
}

int
main(int argc, char * argv[])
{
	int ch;
	int fd;
	int rc;
	sigset_t mask;
	int dontfork = 0;

	while ((ch = getopt(argc, argv, "i:n6")) != -1) {
		switch(ch) {
		case 'i':
			set_devname(optarg);
			break;
		case 'n':
			dontfork = 1;
			break;
		case '6':
			ipv6 = 1;
			break;
		default:
			break;
		}
	}

	rc = ba_get_adapters();
	if (rc != 0) {
		printf("couldn't find bypass adapter(s)\n");
		exit(-1);
	}

	if (devname[0] == 0) {
		ba_get_devname();
	} else {
		rc = ba_verify_devname(devname);
		if (rc != 0) {
			printf("%s: driver and/or adapter do not have Bypass "
			       "Support\n", devname);
			exit(-1);
		}
	}

	printf("Using %s as the management interface\n", devname);

	/*
	 * file semaphore for startup
	 */
	snprintf(lockfile, sizeof(lockfile), "%s.%s",
			BA_PATH_PIDFILE, devname);
	fd = open(lockfile, O_CREAT);
	if (fd < 0) {
		printf("can't create pidfile\n");
		exit(-1);
	}

	rc = flock(fd, LOCK_EX|LOCK_NB);
	if (rc < 0) {
		printf("another instance of ba_server is already running\n");
		exit(-1);
	}

	/*
	 * parent waits for child to finish initialization before exiting
	 */
	signal(SIGUSR1, sigusr);
	sigemptyset(&mask);
	if (dontfork == 0) {
		if (fork() != 0) {
			sigsuspend(&mask);
			exit(0);
		}
	}

	/*
	 * initialize in the child process
	 */

	signal(SIGPIPE, SIG_IGN);

	/* initialize the switch */
	rc = sw_init(ipv6);
	if (rc < 0) {
		printf("unable to initialize hardware\n");
		exit(-1);
	}

	ba_watchdog_timeout = hw_get_watchdog_timeout();

	printf("Adapter Initialized.\n");

	if (ba_setup_socket() < 0)
		exit(-1);

	/*
	 * tell parents that initialization is complete
	 */
	kill(getppid(), SIGUSR1);

	/*
	 * handle client requests
	 */
	ba_recv();

	exit(0);
}

int
ba_get_adapters()
{
	DIR *net;
	struct dirent *dev;
	int i;

	net = opendir("/sys/class/net");
	if (net == NULL) {
		printf("Can't open /sys/class/net\n");
		return -1;
	}

	i = 0;
	while ((dev = readdir(net))) {
		char bypass[1024];
		struct stat sb;

		snprintf(bypass, sizeof bypass, "/sys/class/net/%s/bypass",
			 dev->d_name);
		if (stat(bypass, &sb) || !S_ISDIR(sb.st_mode))
			continue;

		strncpy(ba_adapters[i].name, dev->d_name, IFNAMSIZ);
		i++;
		if (i == MAX_BA_IFS) {
			printf("Too many bypass adapters\n");
			closedir(net);
			return -1;
		}
	}

	closedir(net);

	/*
	 * If there are no bypass adapters on the system, return error.
	 */
	if (i == 0)
		return -1;

	return 0;
}

/*
 * get the default bypass adapter
 */
int
ba_get_devname(void)
{
	/* use the first discovered as the default */
	set_devname(ba_adapters[0].name);
	ba_adapter_index = 0;

	return 0;
}

int
ba_verify_devname(char *devname)
{
	int			i = 0;

	while (ba_adapters[i].name[0] != '\0') {
		if (0 == strcmp(ba_adapters[i].name, devname)) {
			ba_adapter_index = i;
			return 0;
		}
	
		i++;
	}

	return -1;
}

int
ba_get_port(char * port)
{
	int		num_ports;
	int		portval;

	num_ports = ba_adapters[ba_adapter_index].num_ports;

	portval = ba_convert_to_int(port, "port");
	if (portval == -1)
		return -1;

	if ( (portval < 0) || (portval >= num_ports) )
		return -1;

	return portval;
}

/*
 * process cli requests
 */
int
ba_setup_socket(void)
{
	int			retry = 10;
	struct sockaddr_un	sun;
	u_int			sunlen;
	int			rc = -1;

	server_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (server_sock < 0) {
		printf("couldn't create cli socket\n");
		return -1;
	}

	snprintf(sockpath, sizeof(sockpath), "%s.%s", BA_PATH_NAME, devname);

	unlink(sockpath);

	/*
	 * bind to the BA server address
	 */
	bzero(&sun, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, sockpath, sizeof(sun.sun_path));
	sunlen = sizeof(sun);

	while ( (rc == -1) && (retry-- > 0) ) {
		usleep(200);
		rc = bind(server_sock, (struct sockaddr *)&sun, sunlen);
	}
	if (rc < 0) {
		printf("couldn't bind cli socket, errno = %d\n", errno);
		return -1;
	}

	listen(server_sock, 10);

	return 0;
}

/*
 * process cli requests
 */
void
ba_recv(void)
{
	char			*argv[32];
	char			*ptr;
	char			readbuf[2048];
	int			count;
	int			i;
	int			rc = -1;
	int			cli;
	int			__attribute__((unused)) fin;
	int			__attribute__((unused)) ferr;
	char			exitrc;
	struct sockaddr_un	sun;
	u_int			sunlen;

	bzero(&sun, sizeof(sun));
	sun.sun_family = AF_UNIX;

	printf("Accepting client requests (pid %d).\n", getpid());

	/*
	 * accept connections from the CLI and process one at a time
	 */
	while (1) {
		sunlen = sizeof(sun);
		cli = accept(server_sock, (struct sockaddr *)&sun, &sunlen);
		if (cli < 0)
			continue;

		count = read(cli, readbuf, sizeof(readbuf));
		if (count == 0) {
			continue;
		}
		readbuf[count] = '\0';

		/*
		 * parse command line into argv
		 */
		bzero(argv, sizeof(argv));
		i = 0;
		ptr = readbuf;
		while ((argv[i] = strtok(ptr, " 	\n"))) {
			if (argv[i] == NULL)
				break;
			ptr = NULL;
			i++;
		}

		optind = 0;
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
		fin = dup2(cli, STDOUT_FILENO);
		ferr = dup2(cli, STDERR_FILENO);
		if (strcmp(argv[0], "dbg")) {
			rc = ba_main(i, argv, cli);
		} else {
			rc = -1;
		}
		exitrc = rc;
		fflush(stdout);
		fflush(stderr);
		write(cli, &exitrc, sizeof(exitrc));
		close(cli);
		fin = dup2(server_sock, STDOUT_FILENO);
		ferr = dup2(server_sock, STDERR_FILENO);
	}
}

/****************************************************************************
 *
 * option structure for getopt_long parsing of command line
 *
 ****************************************************************************/

struct option bypass_get_options[] = {
	{"default_state",	0,	0, 0},	// BA_OPT_GET_DEFAULT_STATE
	{"current_state",	0,	0, 0},	// BA_OPT_GET_CURRENT_STATE
	{"watchdog",		0,	0, 0},	// BA_OPT_GET_WATCHDOG
	{"watchdog_timeout",	0,	0, 0},	// BA_OPT_GET_WATCHDOG_TIMEOUT
	{"debug",		0,	0, 0},	// BA_OPT_GET_DEBUG
	{0, 0, 0, 0}
};

struct option bypass_set_options[] = {
	{"default_state",	1,	0, 0},	// BA_OPT_SET_DEFAULT_STATE
	{"current_state",	1,	0, 0},	// BA_OPT_SET_CURRENT_STATE
	{"watchdog",		1,	0, 0},	// BA_OPT_SET_WATCHDOG
	{"watchdog_timeout",	1,	0, 0},	// BA_OPT_SET_WATCHDOG_TIMEOUT
	{0, 0, 0, 0}
};

struct option redirect_add_and_update_options[] = {
	{"table",		1,	0, 0},	// BA_OPT_ADDUPD_TABLE
	{"index",		1,	0, 0},	// BA_OPT_ADDUPD_INDEX
	{"proto",		1,	0, 0},	// BA_OPT_ADDUPD_PROTO
	{"srcaddr",		1,	0, 0},	// BA_OPT_ADDUPD_SRCADDR
	{"srcmask",		1,	0, 0},	// BA_OPT_ADDUPD_SRCMASK
	{"srcport_min",		1,	0, 0},	// BA_OPT_ADDUPD_SRCPORT_MIN
	{"srcport_max",		1,	0, 0},	// BA_OPT_ADDUPD_SRCPORT_MAX
	{"dstaddr",		1,	0, 0},	// BA_OPT_ADDUPD_DSTADDR
	{"dstmask",		1,	0, 0},	// BA_OPT_ADDUPD_DSTMASK
	{"dstport_min",		1,	0, 0},	// BA_OPT_ADDUPD_DSTPORT_MIN
	{"dstport_max",		1,	0, 0},	// BA_OPT_ADDUPD_DSTPORT_MAX
	{"vlan",		1,	0, 0},	// BA_OPT_ADDUPD_VLAN
	{"action",		1,	0, 0},	// BA_OPT_ADDUPD_ACTION
	{"port",		1,	0, 0},	// BA_OPT_ADDUPD_PORT
	{"ethertype",		1,	0, 0},	// BA_OPT_ADDUPD_ETYPE
	{"srcport",		1,	0, 0},	// BA_OPT_ADDUPD_SRCPORT
	{"srcportmask",		1,	0, 0},	// BA_OPT_ADDUPD_SRCPORTMASK
	{"dstport",		1,	0, 0},	// BA_OPT_ADDUPD_DSTPORT
	{"dstportmask",		1,	0, 0},	// BA_OPT_ADDUPD_DSTPORTMASK
	{"srcaddr6",		1,	0, 0},	// BA_OPT_ADDUPD_SRCADDR6
	{"srcmask6",		1,	0, 0},	// BA_OPT_ADDUPD_SRCMASK6
	{"dstaddr6",		1,	0, 0},	// BA_OPT_ADDUPD_DSTADDR6
	{"dstmask6",		1,	0, 0},	// BA_OPT_ADDUPD_DSTMASK6
	{"ipv6",		0,	0, 0},	// BA_OPT_ADDUPD_IPV6
	{0, 0, 0, 0}
};

struct option redirect_delete_options[] = {
	{"table",		1,	0, 0},	// BA_OPT_DELETE_TABLE
	{"index",		1,	0, 0},	// BA_OPT_DELETE_INDEX
	{0, 0, 0, 0}
};

struct option redirect_purge_options[] = {
	{"table",		1,	0, 0},	// BA_OPT_PURGE_TABLE
	{"action",		1,	0, 0},	// BA_OPT_PURGE_ACTION
	{0, 0, 0, 0}
};

struct option redirect_move_options[] = {
	{"table",		1,	0, 0},	// BA_OPT_MOVE_TABLE
	{"old_id",		1,	0, 0},	// BA_OPT_MOVE_OLD_ID
	{"new_id",		1,	0, 0},	// BA_OPT_MOVE_NEW_ID
	{0, 0, 0, 0}
};

struct option redirect_create_table_options[] = {
	{"table",		1,	0, 0},	// BA_OPT_CREATE_TABLE
	{0, 0, 0, 0}
};

struct option redirect_activate_table_options[] = {
	{"table",		1,	0, 0},	// BA_OPT_ACTIVATE_TABLE
	{0, 0, 0, 0}
};

struct option redirect_deactivate_table_options[] = {
	{"table",		1,	0, 0},	// BA_OPT_DEACTIVATE_TABLE
	{0, 0, 0, 0}
};

struct option redirect_delete_table_options[] = {
	{"table",		1,	0, 0},	// BA_OPT_DELETE_TABLE
	{0, 0, 0, 0}
};

struct option redirect_count_options[] = {
	{"table",		1,	0, 0},	// BA_OPT_COUNT_TABLE
	{"index",		1,	0, 0},	// BA_OPT_COUNT_INDEX
	{0, 0, 0, 0}
};

struct option redirect_dump_options[] = {
	{"table",		1,	0, 0},	// BA_OPT_DUMP_TABLE
	{0, 0, 0, 0}
};

struct ba_cmd_table cmd_table[BA_CMD_MAX+1] = {
	{NULL},	
	{ba_redirect_list},		// BA_REDIRECT_LIST_CMD
	{ba_redirect_add},		// BA_REDIRECT_ADD_CMD
	{ba_redirect_update},		// BA_REDIRECT_UPDATE_CMD
	{ba_redirect_delete},		// BA_REDIRECT_DELETE_CMD
	{ba_redirect_purge},		// BA_REDIRECT_PURGE_CMD
	{ba_redirect_move},		// BA_REDIRECT_MOVE_CMD
	{ba_redirect_match},		// BA_REDIRECT_MATCH_CMD
	{ba_redirect_create_table},	// BA_REDIRECT_CREATE_TABLE_CMD
	{ba_redirect_activate_table},	// BA_REDIRECT_ACTIVATE_TABLE_CMD
	{ba_redirect_delete_table},	// BA_REDIRECT_DELETE_TABLE_CMD
	{ba_redirect_count},		// BA_REDIRECT_COUNT_CMD
	{ba_bypass_get},		// BA_BYPASS_GET_CMD
	{ba_bypass_set},		// BA_BYPASS_SET_CMD
	{ba_redirect_dump},		// BA_REDIRECT_DUMP_CMD
	{ba_redirect_deactivate_table}	// BA_REDIRECT_DEACTIVATE_TABLE_CMD
};

u_int		options_set;
char		*options_val[BA_MAX_OPTIONS];
u_int		options_count;

int
ba_main(int argc, char *argv[], int sock)
{
	int		rc;
	char		*command = NULL;
	int		c;
	int		opt_index;
	struct option 	*options;
	int		subcommand;
	char		*cmd;

	options = NULL;
	options_set = 0;
	options_count = 0;
	bzero(options_val, sizeof(options_val));

	if (argc < 3) {
		printf("interface and sub-command must be specified\n");
		return -1;
	}

	cmd = basename(argv[0]);

	if (strcmp(cmd, BA_BYPASS_CMD) == 0) {
		command = BA_BYPASS_CMD;
		if (strcmp(argv[2], "set") == 0) {
			subcommand = BA_BYPASS_SET_CMD;
			options = bypass_set_options;
		} else if (strcmp(argv[2], "get") == 0) {
			subcommand = BA_BYPASS_GET_CMD;
			options = bypass_get_options;
		} else if (strcmp(argv[2], "help") == 0) {
			bypass_help();
			return 0;
		} else {
			printf("invalid bypass command\n");
			bypass_help();
			return -1;
		}
	} else if (strcmp(cmd, BA_REDIRECT_CMD) == 0) {
		command = BA_REDIRECT_CMD;
		if (strcmp(argv[2], "list") == 0)
			subcommand = BA_REDIRECT_LIST_CMD;
		else if (strcmp(argv[2], "add") == 0) {
			subcommand = BA_REDIRECT_ADD_CMD;
			options = redirect_add_and_update_options;
		} else if (strcmp(argv[2], "update") == 0) {
			subcommand = BA_REDIRECT_UPDATE_CMD;
			options = redirect_add_and_update_options;
		} else if (strcmp(argv[2], "delete") == 0) {
			subcommand = BA_REDIRECT_DELETE_CMD;
			options = redirect_delete_options;
		} else if (strcmp(argv[2], "purge") == 0) {
			subcommand = BA_REDIRECT_PURGE_CMD;
			options = redirect_purge_options;
		} else if (strcmp(argv[2], "move") == 0) {
			subcommand = BA_REDIRECT_MOVE_CMD;
			options = redirect_move_options;
		} else if (strcmp(argv[2], "match") == 0) {
			subcommand = BA_REDIRECT_MATCH_CMD;
			/* use same options as add and update */
			options = redirect_add_and_update_options;
		} else if (strcmp(argv[2], "create_table") == 0) {
			subcommand = BA_REDIRECT_CREATE_TABLE_CMD;
			options = redirect_create_table_options;
		} else if (strcmp(argv[2], "activate_table") == 0) {
			subcommand = BA_REDIRECT_ACTIVATE_TABLE_CMD;
			options = redirect_activate_table_options;
		} else if (strcmp(argv[2], "deactivate_table") == 0) {
			subcommand = BA_REDIRECT_DEACTIVATE_TABLE_CMD;
			options = redirect_deactivate_table_options;
		} else if (strcmp(argv[2], "delete_table") == 0) {
			subcommand = BA_REDIRECT_DELETE_TABLE_CMD;
			options = redirect_delete_table_options;
		} else if (strcmp(argv[2], "count") == 0) {
			subcommand = BA_REDIRECT_COUNT_CMD;
			options = redirect_count_options;
		} else if (strcmp(argv[2], "dump") == 0) {
			subcommand = BA_REDIRECT_DUMP_CMD;
			options = redirect_dump_options;
		} else if (strcmp(argv[2], "help") == 0) {
			redirect_help();
			return 0;
		} else {
			printf("invalid redirect command\n");
			redirect_help();
			return -1;
		}
	}

	if (command == NULL) {
		printf("Invalid command\n\n");
		return -1;
	}

	/*
	 * get all the options for the selected command
	 */
	while (1) {
		c = getopt_long(argc, argv, "", options, &opt_index);
		if (c == -1)
			break;

		switch (c) {
		case 0:
			options_set |= 1 << opt_index;
			options_val[opt_index] = optarg;
			options_count++;
#ifdef DEBUG
			printf("option %s with arg %s\n", 
				options[opt_index].name, optarg);
#endif
			break;
		default:
			return -1;
		}
	}

	/*
	 * execute command handler
	 */
	rc = (*cmd_table[subcommand].ba_cmd_handler)();

	return rc;
}

/*
 * convert a number string to decimal
 */
int
ba_convert_to_int(char * str, char * name)
{
	int		num;
	char		*end;

	num = strtol(str, &end, 0);
	if (*end != '\0') {
		printf("%s (%s) is not a valid number\n", name, str);
		return -1;
	}
	
	return num;
}

int
ba_redirect_list(void)
{
	int	rc;

	rc = sw_list_rules();

	return rc;
}

int
ba_redirect_add(void)
{
	int			rc;

	rc = sw_add_rule(options_set, options_val);
	if (rc != 0) {
		printf("failed adding rule\n");
		return -1;
	}

	return rc;
}

int
ba_redirect_update(void)
{
	int	rc = 0;
	int	table;
	int	rule;

	if ((options_set & (1 << BA_OPT_ADDUPD_INDEX)) == 0) {
		printf("rule index must be specified\n");
		return -1;
	}

	rule = ba_convert_to_int(options_val[BA_OPT_ADDUPD_INDEX], "index");
	if (rule == -1)
		return -1;

	if ((options_set & (1 << BA_OPT_ADDUPD_TABLE)) == 0) {
		table = BA_DEFAULT_TABLE;
	} else {
		table = ba_convert_to_int(options_val[BA_OPT_ADDUPD_TABLE],
					  "table");
		if (table == -1)
			return -1;
	}

	rc = sw_update_rule(rule, table, options_set, options_val);

	return rc;
}

int
ba_redirect_delete(void)
{
	int	rc = 0;
	int	table;
	int	rule;

	if ((options_set & (1 << BA_OPT_DELETE_INDEX)) == 0) {
		printf("rule index must be specified\n");
		return -1;
	}

	rule = ba_convert_to_int(options_val[BA_OPT_DELETE_INDEX], "index");
	if (rule == -1)
		return -1;

	if ((options_set & (1 << BA_OPT_DELETE_TABLE)) == 0) {
		table = BA_DEFAULT_TABLE;
	} else {
		table = ba_convert_to_int(options_val[BA_OPT_DELETE_TABLE],
					  "table");
		if (table == -1)
			return -1;
	}

	rc = sw_delete_rule(table, rule);
	if (rc != 0) {
		printf("failed deleting rule\n");
		return -1;
	}

	return rc;
}

int
ba_redirect_purge(void)
{
	int	rc;
	int	table;

	if ((options_set & (1 << BA_OPT_PURGE_TABLE)) == 0) {
		table = BA_DEFAULT_TABLE;
	} else {
		table = ba_convert_to_int(options_val[BA_OPT_PURGE_TABLE],
					  "table");
		if (table == -1)
			return -1;
	}

	rc = sw_purge_rules(table);

	return rc;
}

int
ba_redirect_move(void)
{
	int	rc;
	int	old_rule;
	int	new_rule;
	int	table;

	if ((options_set & (1 << BA_OPT_MOVE_TABLE)) == 0) {
		table = BA_DEFAULT_TABLE;
	} else {
		table = ba_convert_to_int(options_val[BA_OPT_MOVE_TABLE],
					  "table");
		if (table == -1)
			return -1;
	}

	if ((options_set & (1 << BA_OPT_MOVE_OLD_ID)) == 0) {
		printf("old index must be specified\n");
		return -1;
	} else {
		old_rule = ba_convert_to_int(options_val[BA_OPT_MOVE_OLD_ID],
					  "old rule");
		if (old_rule == -1)
			return -1;
	}

	if ((options_set & (1 << BA_OPT_MOVE_NEW_ID)) == 0) {
		printf("new index must be specified\n");
		return -1;
	} else {
		new_rule = ba_convert_to_int(options_val[BA_OPT_MOVE_NEW_ID],
					  "new rule");
		if (new_rule == -1)
			return -1;
	}

	rc = sw_move_rule(table, old_rule, new_rule);

	return rc;
}

int
ba_redirect_match(void)
{
	int	rc = 0;
	int	table;

	if ((options_set & (1 << BA_OPT_ADDUPD_TABLE)) == 0) {
		table = BA_DEFAULT_TABLE;
	} else {
		table = ba_convert_to_int(options_val[BA_OPT_ADDUPD_TABLE],
					  "table");
		if (table == -1)
			return -1;
	}

	rc = sw_match_rule(table, options_set, options_val);
	if (rc == -1)
		printf("No matching rule was found\n");
	else
		printf("%d\n", rc);

	return rc;
}

int
ba_redirect_create_table(void)
{
	int	rc = 0;
	long	table;

	if ((options_set & (1 << BA_OPT_CREATE_TABLE)) == 0) {
		printf("table id must be specified\n");
		return -1;
	}

	table = ba_convert_to_int(options_val[BA_OPT_CREATE_TABLE], "table id");
	if (table == -1)
		return -1;

	rc = sw_create_table(table);
	if (rc != 0) {
		printf("failed creating table\n");
		return -1;
	}

	return rc;
}

int
ba_redirect_activate_table(void)
{
	int	rc = 0;
	long	table;

	if ((options_set & (1 << BA_OPT_ACTIVATE_TABLE)) == 0) {
		printf("table id must be specified\n");
		return -1;
	}

	table = ba_convert_to_int(options_val[BA_OPT_ACTIVATE_TABLE], "table");
	if (table == -1)
		return -1;

	rc = sw_get_table(table);
	if (rc != 0) {
		printf("invalid table id\n");
		return -1;
	}

	rc = sw_activate_table(table);
	if (rc != 0) {
		printf("failed activating table\n");
		return -1;
	}

	return rc;
}

int
ba_redirect_deactivate_table(void)
{
	int	rc = 0;
	long	table;

	if ((options_set & (1 << BA_OPT_DEACTIVATE_TABLE)) == 0) {
		printf("table id must be specified\n");
		return -1;
	}

	table = ba_convert_to_int(options_val[BA_OPT_DEACTIVATE_TABLE], "table");
	if (table == -1)
		return -1;

	rc = sw_get_table(table);
	if (rc != 0) {
		printf("invalid table id\n");
		return -1;
	}

	rc = sw_deactivate_table(table);
	if (rc != 0) {
		printf("failed deactivating table\n");
		return -1;
	}

	return rc;
}

int
ba_redirect_delete_table(void)
{
	int	rc = 0;
	long	table;

	if ((options_set & (1 << BA_OPT_DELETE_TABLE)) == 0) {
		printf("table id must be specified\n");
		return -1;
	}

	table = ba_convert_to_int(options_val[BA_OPT_DELETE_TABLE], "table");
	if (table == -1)
		return -1;

	rc = sw_delete_table(table);
	if (rc != 0) {
		printf("failed deleting table\n");
		return -1;
	}

	return rc;
}

int
ba_redirect_count(void)
{
	int	rc = 0;
	int	table;
	int	rule;

	if ((options_set & (1 << BA_OPT_COUNT_INDEX)) == 0) {
		printf("rule index must be specified\n");
		return -1;
	}

	rule = ba_convert_to_int(options_val[BA_OPT_COUNT_INDEX], "index");
	if (rule == -1)
		return -1;

	if ((options_set & (1 << BA_OPT_COUNT_TABLE)) == 0) {
		table = BA_DEFAULT_TABLE;
	} else {
		table = ba_convert_to_int(options_val[BA_OPT_COUNT_TABLE],
					  "table");
		if (table == -1)
			return -1;
	}

	rc = sw_count_rule(rule, table);
	if (rc != 0) {
		printf("failed getting rule counts\n");
		return -1;
	}

	return rc;
}

int
ba_redirect_dump(void)
{
	int	rc = 0;
	int	table;

	if ((options_set & (1 << BA_OPT_DUMP_TABLE)) == 0) {
		table = BA_TABLE_ALL;
	} else {
		table = ba_convert_to_int(options_val[BA_OPT_DUMP_TABLE],
					  "table");
		if (table == -1)
			return -1;
	}

	rc = sw_dump_tables();
	if (rc != 0) {
		printf("failed dumping tables\n");
		return -1;
	}

	return rc;
}

int
ba_bypass_get(void)
{
	int	rc = 0;

	if (options_count == 0) {
		printf("get key must be supplied\n");
		return -1;
	}

	if (options_count > 1) {
		printf("only one get key should be supplied\n");
		return -1;
	}

	if ((options_set & (1 << BA_OPT_GET_DEFAULT_STATE)) != 0) {
		rc = hw_get_bypass_state(DEFAULT_STATE);
	}

	if ((options_set & (1 << BA_OPT_GET_CURRENT_STATE)) != 0) {
		rc = hw_get_bypass_state(CURRENT_STATE);
	}

	if ((options_set & (1 << BA_OPT_GET_WATCHDOG)) != 0) {
		rc = ba_get_watchdog();
	}

	if ((options_set & (1 << BA_OPT_GET_WATCHDOG_TIMEOUT)) != 0) {
		rc = ba_get_watchdog_timeout();
	}

	if ((options_set & (1 << BA_OPT_GET_DEBUG)) != 0) {
		rc = ba_get_debug();
	}

	return rc;
}

int
ba_bypass_set(void)
{
	int	rc = 0;
	char	*param;

	if (options_count == 0) {
		printf("set key must be supplied\n");
		return -1;
	}

	if (options_count > 1) {
		printf("only one set key should be supplied\n");
		return -1;
	}

	if ((options_set & (1 << BA_OPT_SET_DEFAULT_STATE)) != 0) {
		param = options_val[BA_OPT_SET_DEFAULT_STATE];
		rc = ba_set_state(DEFAULT_STATE, param);
	}

	if ((options_set & (1 << BA_OPT_SET_CURRENT_STATE)) != 0) {
		param = options_val[BA_OPT_SET_CURRENT_STATE];
		rc = ba_set_state(CURRENT_STATE, param);
	}

	if ((options_set & (1 << BA_OPT_SET_WATCHDOG)) != 0) {
		param = options_val[BA_OPT_SET_WATCHDOG];
		rc = ba_set_watchdog(param);
	}

	if ((options_set & (1 << BA_OPT_SET_WATCHDOG_TIMEOUT)) != 0) {
		param = options_val[BA_OPT_SET_WATCHDOG_TIMEOUT];
		rc = ba_set_watchdog_timeout(param);
	}

	return rc;
}

int 
ba_set_state(int which, char * param)
{
	int		rc = 0;
	int		state;

	if (strcmp(param, BA_BYPASS_STATE) == 0)
		state = BA_STATE_BYPASS;
	else if (strcmp(param, BA_DISCONNECT_STATE) == 0)
		state = BA_STATE_DISCONNECT;
	else if ( (strcmp(param, BA_NORMAL_STATE) == 0) &&
			 (which == CURRENT_STATE))
		state = BA_STATE_NORMAL;
	else {
		printf("invalid bypass state (%s)\n", param);
		return -1;
	}

	if (which == CURRENT_STATE) {
		ba_current_state = state;
	} else {
		ba_default_state = state;
	}

	rc = hw_set_bypass_state(which, state);

	return rc;
}

int  
ba_set_watchdog(char * param)
{
	int		rc = 0;
	int		state = -1;

	if (strcmp(param, BA_WATCHDOG_ENABLE) == 0)
		state = BA_WATCHDOG_STATE_ENABLED;
	else if (strcmp(param, BA_WATCHDOG_DISABLE) == 0)
		state = BA_WATCHDOG_STATE_DISABLED;
	else if (strcmp(param, BA_WATCHDOG_PING) == 0) {
		rc = hw_ping_bypass();
		return rc;
	} else if (strcmp(param, BA_WATCHDOG_LOCK) == 0) {
		rc = hw_lock_bypass();
		return rc;
	} else {
		printf("invalid watchdog state (%s)\n", param);
		return -1;
	}

	rc = hw_set_watchdog_state(state);
	if ( (rc == 0) && (state != -1) )
		ba_watchdog_state = state;
	else if (rc == EPERM)
		printf("watchdog is locked, no changes allowed\n");
	else
		printf("error %d setting watchdog\n", rc);

	return rc;
}

int  
ba_set_watchdog_timeout(char * param)
{
	int		rc = 0;
	int		tmo;

	tmo = ba_convert_to_int(options_val[BA_OPT_SET_WATCHDOG_TIMEOUT],
				"timeout");
	if (tmo == -1)
		return -1;

	if (tmo < 0) {
		printf("timeout must be greater than zero\n");
		return -1;
	}

	if (tmo > (FW_WATCHDOG_MAX_TIMEOUT_SECS * 1000)) {
		printf("Maximum watchdog timeout is %d seconds\n",
			FW_WATCHDOG_MAX_TIMEOUT_SECS);
		return -1;
	}

	if (ba_watchdog_state == BA_WATCHDOG_STATE_ENABLED)
		rc = hw_set_watchdog_timeout(param);

	if (rc != 0) {
		if (rc == EPERM)
			printf("watchdog is locked, no changes allowed\n");
		else
			printf("error %d setting watchdog timeout\n", rc);
	} else {
		ba_watchdog_timeout = atoi(param);
	}

	return rc;
}

int  
ba_get_watchdog(void)
{
	int		rc = 0;
	char		*state;

	switch (ba_watchdog_state) {
		case BA_WATCHDOG_STATE_DISABLED:
			state = BA_WATCHDOG_STRING_DISABLED;
			break;

		case BA_WATCHDOG_STATE_ENABLED:
			state = BA_WATCHDOG_STRING_ENABLED;
			break;

		default:
			state = "unknown state";
			break;
	}

	printf("%s\n", state);

	return rc;
}

int  
ba_get_watchdog_timeout(void)
{
	int		rc = 0;
	int		tmo;

	tmo = ba_watchdog_timeout;

	if (tmo == 0) {
		tmo = hw_get_watchdog_timeout();
		if (tmo == -1) {
			printf("failed to get watchdog timeout\n");
			rc = -1;
		}
	}

	if (rc == 0)
		printf("%d\n", tmo);

	return rc;
}

int  
ba_get_debug(void)
{
	int		rc = 0;

	return rc;
}

void
bypass_help(void)
{
	printf("\n");
	printf("bypass interface_name get|set --key [value]\n\n");
	printf("where key is one of:\n");
	printf("\tdefault_state\n");
	printf("\tcurrent_state\n");
	printf("\twatchdog\n");
	printf("\twatchdog_timeout\n");

	printf("\n");

	printf("For set operations the key values can be:\n");
	printf("\tdefault_state           - bypass|disconnect\n");
	printf("\tcurrent_state           - bypass|disconnect|normal\n");
	printf("\twatchdog                - enable|disable|lock|ping\n");
	printf("\twatchdog_timeout        - timeout in milliseconds\n");

	printf("\n");

	return;
}

void
redirect_help(void)
{
	printf("redirect interface_name command --key [value]\n\n");
	printf("where command is one of:\n");
	printf("\tlist\n");
	printf("\tadd\n");
	printf("\tupdate\n");
	printf("\tmatch\n");
	printf("\tdelete\n");
	printf("\tpurge\n");
	printf("\tmove\n");
	printf("\tcount\n");
	printf("\tcreate_table\n");
	printf("\tdelete_table\n");
	printf("\tactivate_table\n");
	printf("\tdeactivate_table\n");
	printf("\tdump\n");
	printf("\n");

	printf("The add, update, and match commands accept the following keys:\n");
	printf("\t--table\n");
	printf("\t--index\n");
	printf("\t--proto\n");
	printf("\t--srcaddr\n");
	printf("\t--srcmask\n");
	printf("\t--srcaddr6\n");
	printf("\t--srcmask6\n");
#ifdef	PORT_RANGE
	printf("\t--srcport_min\n");
	printf("\t--srcport_max\n");
#endif
	printf("\t--srcport\n");
	printf("\t--srcportmask\n");
	printf("\t--dstaddr\n");
	printf("\t--dstmask\n");
	printf("\t--dstaddr6\n");
	printf("\t--dstmask6\n");
#ifdef	PORT_RANGE
	printf("\t--dstport_min\n");
	printf("\t--dstport_max\n");
#endif
	printf("\t--dstport\n");
	printf("\t--dstportmask\n");
	printf("\t--vlan\n");
	printf("\t--ipv6\n");
	printf("\t--action\n");
	printf("\t--port\n");

	printf("\n");

	printf("redirect interface_name\n");
	printf("redirect interface_name --table table_id --index rule_num\n");
	printf("redirect interface_name --table table_id --index rule_num\n");
	printf("redirect interface_name --table table_id\n");
	printf("redirect interface_name --table table_id --old_id old_id --new_id new_id\n");
	printf("redirect interface_name --table table_id\n");
	printf("redirect interface_name --table table_id\n");
	printf("redirect interface_name --table table_id\n");
	printf("redirect interface_name --table table_id\n");
	printf("redirect interface_name dump\n");

	printf("\n");

	return;
}
