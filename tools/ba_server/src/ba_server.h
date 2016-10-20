#ifndef	__BA_SERVER_
#define	__BA_SERVER_

#include <net/if.h>

#define	BA_PATH_NAME	"/var/run/ba_server_sock"
#define	BA_PATH_PIDFILE	"/var/run/ba_server.pid"

#define	BA_BYPASS_CMD	"bypass"
#define	BA_REDIRECT_CMD	"redirect"

extern int ba_watchdog_timeout;
extern char *ifname;

struct ba_cmd_table {
	int (*ba_cmd_handler)(void);
};

struct ba_adapters {
	char		name[IFNAMSIZ];
	int		num_ports;
};

extern struct ba_adapters ba_adapters[MAX_BA_IFS];
extern int ba_adapter_index;

#define BA_REDIRECT_LIST_CMD			1
#define BA_REDIRECT_ADD_CMD			2
#define BA_REDIRECT_UPDATE_CMD			3
#define BA_REDIRECT_DELETE_CMD			4
#define BA_REDIRECT_PURGE_CMD			5
#define BA_REDIRECT_MOVE_CMD			6
#define BA_REDIRECT_MATCH_CMD			7
#define BA_REDIRECT_CREATE_TABLE_CMD		8
#define BA_REDIRECT_ACTIVATE_TABLE_CMD		9
#define BA_REDIRECT_DELETE_TABLE_CMD		10
#define BA_REDIRECT_COUNT_CMD			11
#define BA_BYPASS_GET_CMD			12
#define BA_BYPASS_SET_CMD			13
#define BA_REDIRECT_DUMP_CMD			14
#define BA_REDIRECT_DEACTIVATE_TABLE_CMD	15

#define BA_CMD_MAX				15

/*
 * index for options. These must match the static initialization of the
 * getopt option arrays.
 */
#define	BA_MAX_OPTIONS				32

#define BA_OPT_GET_DEFAULT_STATE		0
#define BA_OPT_GET_CURRENT_STATE		1
#define BA_OPT_GET_WATCHDOG			2
#define BA_OPT_GET_WATCHDOG_TIMEOUT		3
#define BA_OPT_GET_DEBUG			4
#define BA_OPT_GET_PORT_STATE			5

#define BA_OPT_SET_DEFAULT_STATE		0
#define BA_OPT_SET_CURRENT_STATE		1
#define BA_OPT_SET_WATCHDOG			2
#define BA_OPT_SET_WATCHDOG_TIMEOUT		3

#define BA_OPT_ADDUPD_TABLE			0
#define BA_OPT_ADDUPD_INDEX			1
#define BA_OPT_ADDUPD_PROTO			2
#define BA_OPT_ADDUPD_SRCADDR			3
#define BA_OPT_ADDUPD_SRCMASK			4
#define BA_OPT_ADDUPD_SRCPORT_MIN		5
#define BA_OPT_ADDUPD_SRCPORT_MAX		6
#define BA_OPT_ADDUPD_DSTADDR			7
#define BA_OPT_ADDUPD_DSTMASK			8
#define BA_OPT_ADDUPD_DSTPORT_MIN		9
#define BA_OPT_ADDUPD_DSTPORT_MAX		10
#define BA_OPT_ADDUPD_VLAN			11
#define BA_OPT_ADDUPD_ACTION			12
#define BA_OPT_ADDUPD_PORT			13
#define BA_OPT_ADDUPD_ETYPE			14
#define BA_OPT_ADDUPD_SRCPORT			15
#define BA_OPT_ADDUPD_SRCPORTMASK		16
#define BA_OPT_ADDUPD_DSTPORT			17
#define BA_OPT_ADDUPD_DSTPORTMASK		18
#define BA_OPT_ADDUPD_SRCADDR6			19
#define BA_OPT_ADDUPD_SRCMASK6			20
#define BA_OPT_ADDUPD_DSTADDR6			21
#define BA_OPT_ADDUPD_DSTMASK6			22
#define BA_OPT_ADDUPD_IPV6			23

#define BA_OPT_DELETE_TABLE			0
#define BA_OPT_DELETE_INDEX			1

#define BA_OPT_PURGE_TABLE			0
#define BA_OPT_PURGE_ACTION			1

#define BA_OPT_MOVE_TABLE			0
#define BA_OPT_MOVE_OLD_ID			1
#define BA_OPT_MOVE_NEW_ID			2

#define BA_OPT_CREATE_TABLE			0

#define BA_OPT_ACTIVATE_TABLE			0

#define BA_OPT_DEACTIVATE_TABLE			0

#define BA_OPT_DELETE_TABLE			0

#define BA_OPT_COUNT_TABLE			0
#define BA_OPT_COUNT_INDEX			1

#define BA_OPT_DUMP_TABLE			0

/* protocols */
#define PROTO_TCP				"tcp"
#define PROTO_UDP				"udp"
#define PROTO_ICMP				"icmp"
#define PROTO_ICMP6				"icmp6"
#define PROTO_ANY				"any"

/* actions */
#define ACTION_DROP				"drop"
#define ACTION_INPUT				"input"
#define ACTION_FORWARD				"forward"
#define ACTION_MIRROR				"mirror"

/* bypass modes */
#define	BA_STATE_BYPASS				1
#define	BA_STATE_DISCONNECT			2
#define	BA_STATE_NORMAL				3
#define	BA_STATE_DEFAULT			BA_STATE_BYPASS

#define	CURRENT_STATE				1
#define	DEFAULT_STATE				2

#define BA_BYPASS_STATE				"bypass"
#define BA_DISCONNECT_STATE			"disconnect"
#define BA_NORMAL_STATE				"normal"

#define BA_WATCHDOG_ENABLE			"enable"
#define BA_WATCHDOG_DISABLE			"disable"
#define BA_WATCHDOG_LOCK			"lock"
#define BA_WATCHDOG_PING			"ping"

#define BA_WATCHDOG_STATE_DISABLED		1
#define BA_WATCHDOG_STATE_ENABLED		2
#define BA_WATCHDOG_STATE_DEFAULT		BA_WATCHDOG_STATE_DISABLED

#define BA_WATCHDOG_STRING_DISABLED		"disabled"
#define BA_WATCHDOG_STRING_ENABLED		"enabled"

#define BA_WATCHDOG_TIMEOUT_DEFAULT		5
#define BA_WATCHDOG_TIMEOUT_MAX			1000000

#define BA_DEFAULT_TABLE			1
#define BA_DEFAULT_RULE				1

#define BA_TABLE_ALL				-1

#define BA_SW					0
#define BA_RULE_INCREMENT			5

/*
 * adapter external ports
 */
#define BA_PORT0				5
#define BA_PORT1				7

/*
 * host ports
 */
#define BA_HOST_PORT0				0
#define BA_HOST_PORT1				1
#define BA_DEFAULT_HOST_PORT			BA_HOST_PORT0

int ba_convert_to_int(char * str, char * name);
int ba_get_port(char * port);

#endif	/* BA_SERVER_ */ 
