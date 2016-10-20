#include <csio_hw.h>
#include <csio_foiscsi.h>
#include <cxgbtool_stor.h>
#include <cxgbtool_foiscsi_stor.h>
#include <csio_services.h>
#include <csio_foiscsi_persistent.h>
#include <csio_foiscsi_ioctl.h>
#include <getopt.h>
#include <arpa/inet.h>

/*#define CSIO_FOISCSI_BRINGUP*/
#ifdef CSIO_FOISCSI_BRINGUP
#define csio_foiscsi_log_devel_debug(fmt, args...)\
	fprintf(stderr, fmt, ##args)
#else
#define csio_foiscsi_log_devel_debug(fmt, args...)\
	do {} while (0)
#endif

#define csio_foiscsi_log_info(file, fmt, arg...)\
	fprintf(file, fmt, ##arg)

#define CSIO_FOISCSI_VLAN_NONE	0xFFF

static const char *foiscsi_name = "cxgbtool stor --foiscsi ";
static const char *foiscsi_base_opt = "--foiscsi";
/* move these to related headers */

/* ======================================= */

static struct option const long_options[] = 
{
	{"mode", required_argument, NULL, 'm'},
	{"dev", required_argument, NULL, 'd'},
	{"portal", required_argument, NULL, 'P'},
	{"persistent", no_argument, NULL, 'B'},
	{"idx", required_argument, NULL, 'x'},
	{"targetname", required_argument, NULL, 'T'},
	{"sid", required_argument, NULL, 's'},
	{"nodeid", required_argument, NULL, 'e'},
	{"saddr", required_argument, NULL, 'r'},
	{"mask", required_argument, NULL, 'k'},
#if 0
	{"bcaddr", required_argument, NULL, 'b'},
#endif
	{"gw", required_argument, NULL, 'g'},
	{"type", required_argument, NULL, 't'},
	{"loopback", required_argument, NULL, 'O'},
	{"op", required_argument, NULL, 'o'},
	{"ifid", required_argument, NULL, 'i'},
	{"vlanid", required_argument, NULL, 'l'},
	{"vlanprio", required_argument, NULL, 'y'},
	{"name", required_argument, NULL, 'n' },
	{"alias", required_argument, NULL, 'a' },
	{"port", required_argument, NULL, 'p'},
	{"mtu", required_argument, NULL, 'u'},
	{"ini_user", required_argument, NULL, 'I'},
	{"ini_sec", required_argument, NULL, 'S'},
	{"tgt_user", required_argument, NULL, 'R'},
	{"tgt_sec", required_argument, NULL, 'C'},
	{"auth", required_argument, NULL, 'A'},
	{"policy", required_argument, NULL, 'L'},
	{"help", no_argument, NULL, 'h'},
	{"prefix", required_argument, NULL, 'f'},
	{NULL, 0, NULL, 0},
};

static char *short_options = "hm:P:T:o:i:n:a:p:s:d:t:I:r:u:I:S:R:C:A:L:";

static int str_to_mode(char *str)
{
	int mode;

	if (!strcmp("init-instance", str))
		mode = MODE_INIT_INSTANCE;
	else if (!strcmp("session", str))
		mode = MODE_SESSION;
	else if (!strcmp("iface", str))
		mode = MODE_IFACE;
	else if (!strcmp("ifconf", str))
		mode = MODE_IFCONF;
	else if (!strcmp("discovery", str))
		mode = MODE_DISCOVERY;
	else if (!strcmp("persistent", str))
		mode = MODE_PERSISTENT;
	else if (!strcmp("hw", str))
		mode = MODE_HW;
	else
		mode = CXGBTOOL_FOISCSI_MODE_NONE;

	return mode;
}

static int str_to_op(char *str)
{
	int op;

	if (!strcmp("assign", str))
		op = OP_ASSIGN;
	else if (!strcmp("clear", str))
		op = OP_CLEAR;
	else if (!strcmp("show", str))
		op = OP_SHOW;
	else if (!strcmp("login", str))
		op = OP_LOGIN;
	else if (!strcmp("logout", str))
		op = OP_LOGOUT;
	else if (!strcmp("up", str))
		op = OP_UP;
	else if (!strcmp("down", str))
		op = OP_DOWN;
	else if (!strcmp("mtu", str))
		op = OP_MTU;
	else if (!strcmp("vlan", str))
		op = OP_VLAN;
	else if (!strcmp("dcbx", str))
		op = OP_DCBX;
	else
		op = OP_NOOP;

	return op;
}

#if 0
static char *op_to_str(int op)
{
	char *str;

	if (op == OP_ASSIGN)
		str = "assign";
	else if (op == OP_CLEAR)
		str = "clear";
	else if (op == OP_SHOW)
		str = "show";
	else if (op == OP_LOGIN)
		str = "login";
	else if (op == OP_LOGOUT)
		str = "logout";
	else if (op == OP_UP)
		str = "up";
	else if (op == OP_DOWN)
		str = "down";
	else if (op == OP_MTU)
		str = "mtu";
	else if (op == OP_VLAN)
		str = "vlan";
	else
		str = "unknown";

	return str;
}
#endif

static int str_to_ifconf_type(char *str)
{
	int type;

	if (!strcasecmp("ipv4", str))
		type = TYPE_IPV4;
	else if (!strcasecmp("vlan_ipv4", str))
		type = TYPE_VLAN_IPV4;
	else if (!strcasecmp("ipv6", str))
		type = TYPE_IPV6;
	else if (!strcasecmp("dhcp", str))
		type = TYPE_DHCP;
	else if (!strcasecmp("dhcpv6", str))
		type = TYPE_DHCPV6;
	else
		type = TYPE_NONE;

	return type;
}

static const char *const foiscsi_err_msgs[FOISCSI_ERR_LAST] = {
	"",
	"Invalid parameter",
	"Out of memory",
	"Function not implemented",
	"No such device",
	"Invalid index",
	"Instance already exists",
	"Exceeded Max Instances supported",
	"Insufficient resources",
	"Invalid instance name",
	"Invalid operation",
	"Instance not found",
	"Cannot continue: one or more active sessions exist",
	"Zero objects to display",
	"Inteface not provisioned",
	"Session already exists",
	"iSCSI Parameters mismatch",
	"Invalid Request",
	"iSCSI login Timedout",
	"Invalid port",
	"Interface busy",
	"Interface LINK down",
};

static void usage(int status)
{

	if (status)
		fprintf(stderr, "Try cxgbtool stor --foiscsi --help for more information\n");
	else {
		printf("Usage: cxgbtool stor --foiscsi [OPTION]\n");
		printf("\
cxgbtool stor --foiscsi --mode init-instance --dev device --op assign --nodeid 1...n --name node_name --alias alias --ini_user ini_username --ini_sec ini_chap_secret\n\
cxgbtool stor --foiscsi --mode init-instance --dev device --op clear --nodeid 1...n \n\
cxgbtool stor --foiscsi --mode init-instance --dev device --op show \n\
cxgbtool stor --foiscsi --mode init-instance --dev device --op show -nodeid 1...n \n\
\n\
cxgbtool stor --foiscsi --mode discovery --dev device --nodeid 1...n --saddr saddr --portal portal\n\
\n\
cxgbtool stor --foiscsi --mode session --dev device --op login --nodeid 1...n --saddr saddr --target target_name --portal portal --auth auth_method --policy auth_policy --tgt_user tgt_username --tgt_sec tgt_chap_secret --persistent\n\
cxgbtool stor --foiscsi --mode session --dev device --op logout --nodeid 1...n --sid 1...n \n\
cxgbtool stor --foiscsi --mode session --dev device --op logout --nodeid 1...n \n\
cxgbtool stor --foiscsi --mode session --dev device --op show \n\
cxgbtool stor --foiscsi --mode session --dev device --op show --nodeid 1...n \n\
cxgbtool stor --foiscsi --mode session --dev device --op show --nodeid 1...n --sid 1...n\n\
\n\
cxgbtool stor --foiscsi --mode iface --dev device --op up --ifid 0...n --loopback\n\
cxgbtool stor --foiscsi --mode iface --dev device --op down --ifid 0...n --loopback\n\
cxgbtool stor --foiscsi --mode iface --dev device --op vlan --ifid 0...n --vlanid 2...4094 --vlanprio 0...7 --loopback\n\
cxgbtool stor --foiscsi --mode iface --dev device --op mtu --ifid 0...n --mtu 1500...9000 --loopback\n\
cxgbtool stor --foiscsi --mode iface --dev device --op show --ifid 0...n --loopback\n\
\n\
cxgbtool stor --foiscsi --mode ifconf --dev device --op assign --type IPV4 --saddr xxx.xxx.xxx.xxx --mask xxx.xxx.xxx.xxx --gw xxx.xxx.xxx.xxx --ifid 0...n --vlanid 2...4094 --vlanprio 0...7\n\
cxgbtool stor --foiscsi --mode ifconf --dev device --op assign --type IPV6 --saddr xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx --prefix n --gw xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx --ifid 0...n --vlanid 2...4094 --vlanprio 0...7\n\
\n\
cxgbtool stor --foiscsi --mode ifconf --dev device --op assign --type DHCP --ifid 0...n --vlanid 2...4094 --vlanprio 0...7\n\
cxgbtool stor --foiscsi --mode ifconf --dev device --op assign --type DHCPV6 --ifid 0...n --vlanid 2...4094 --vlanprio 0...7\n\
cxgbtool stor --foiscsi --mode ifconf --dev device --op show --type IPV4 --ifid 0...n --vlanid 2...4094 --vlanprio 0...7\n\
cxgbtool stor --foiscsi --mode ifconf --dev device --op show --type IPV6 --ifid 0...n --vlanid 2...4094 --vlanprio 0...7\n\
cxgbtool stor --foiscsi --mode ifconf --dev device --op show --type DHCP --ifid 0...n --vlanid 2...4094 --vlanprio 0...7\n\
cxgbtool stor --foiscsi --mode ifconf --dev device --op clear --type IPV4 --ifid 0...n --vlanid 2...4094 --vlanprio 0...7\n\
cxgbtool stor --foiscsi --mode ifconf --dev device --op clear --type IPV6 --ifid 0...n --vlanid 2...4094 --vlanprio 0...7\n\
cxgbtool stor --foiscsi --mode ifconf --dev device --op clear --type DHCP --ifid 0...n --vlanid 2...4094 --vlanprio 0...7\n\
cxgbtool stor --foiscsi --mode ifconf --dev device --op clear --type DHCPV6 --ifid 0...n --vlanid 2...4094 --vlanprio 0...7\n\
\n\
cxgbtool stor --foiscsi --mode persistent --dev device --op show\n\
cxgbtool stor --foiscsi --mode persistent --dev device --op clear\n\
cxgbtool stor --foiscsi --mode persistent --dev device --op clear --idx 0...n\n\n\
cxgbtool stor --foiscsi --mode hw --dev device --op show\n\
cxgbtool stor --foiscsi --mode hw --dev device --op dcbx\n");
	}

	exit(status == 0 ? 0 : FOISCSI_ERR_INVALID_PARAM);
}

static int
verify_short_mode_params(int argc, char **argv, char *short_allowed, int skip_m)
{
	int ch, longindex;
	int ret = 0;

	optind = 2;

	while ((ch = getopt_long(argc, argv, short_options,
					long_options, &longindex)) >= 0) {
		if (!strchr(short_allowed, ch)) {
			if (ch == 'm' && skip_m)
				continue;
			ret = ch;
			break;
		}
	}

	return ret;
}

#if 0
static int
verify_long_mode_params(int argc, char **argv, char *long_allowed)
{
	int ch, longindex;
	int ret = 0;

	optind = 2;

	while ((ch = getopt_long(argc, argv, short_options,
					long_options, &longindex)) >= 0) {
		if (!strstr(long_allowed, long_options[longindex].name)) {
			ret = longindex;
			break;
		}
	}

	return ret;
}
#endif

char*           
str_to_ipport(char *str, int *port, int *tpgt)
{                       
	char *stpgt, *sport = str, *ip = str;

	if (!strchr(ip, '.')) {
		if (*ip == '[') {
			if (!(sport = strchr(ip, ']')))
				return NULL;
			*sport++ = '\0';
			ip++;
			str = sport;
		} else
			sport = NULL;
	}               

	if (sport && (sport = strchr(str, ':'))) {
		*sport++ = '\0';        
		*port = strtoul(sport, NULL, 10);
		str = sport;
	}                       

	if ((stpgt = strchr(str, ','))) {
		*stpgt++ = '\0';
		*tpgt = strtoul(stpgt, NULL, 10);
	} else          
		*tpgt = -1;

	csio_foiscsi_log_devel_debug("ip %s, port %d, tgpt %d\n", ip, *port, *tpgt);
	return ip;      
}

static adap_handle_t open_adapter_handle(char *dev)
{
	if (!dev)
		return -1;

	return open_adapter_str(dev);
}

static inline int csio_chnet_is_valid_vlan(uint16_t vlan)
{
	uint16_t vlanid = vlan & 0x0fff;
	return (vlanid >= 2 && vlanid < 4095);
}


static int csio_foiscsi_iface_do_link_op(adap_handle_t hw, int op, int8_t port, uint8_t flags)
{
	void *buffer = NULL;
	struct csio_foiscsi_iface_ioctl *req = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(*req));
	uint32_t cmd;
	int rc = 0;

	if (hw < 0) {
		fprintf(stderr, "%s: No chelsio T4 CNA available\n", foiscsi_name);
		rc = FOISCSI_ERR_IFACE_INVALID_PORT;
		goto out;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", foiscsi_name);
		rc = FOISCSI_ERR_OOM;
		goto out;
	}

	cmd = CSIO_STOR_FOISCSI_OPCODE(op == OP_UP ?
			CSIO_FOISCSI_IFACE_LINK_UP_IOCTL:
			CSIO_FOISCSI_IFACE_LINK_DOWN_IOCTL);
	
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
	req = (struct csio_foiscsi_iface_ioctl*)get_payload(buffer);
	memset(req, 0, sizeof(*req));
	req->ifid = port;
	req->flags = flags;

	rc = issue_ioctl(hw, buffer, len);

	req = (struct csio_foiscsi_iface_ioctl*)get_payload(buffer);
	rc = req->retval;
	ioctl_buffer_free(buffer);
out:
	return rc;
}

static int32_t
csio_foiscsi_iface_do_vlan(adap_handle_t hw, uint16_t vlanid, int8_t port)
{
	void *buffer = NULL;
	struct csio_foiscsi_ifconf_ioctl *req = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(*req));
	uint32_t cmd = CSIO_STOR_FOISCSI_OPCODE(CSIO_FOISCSI_IFCONF_VLAN_SET_IOCTL);
	int rc = 0;

	if (hw < 0) {
		fprintf(stderr, "%s: No chelsio T4 CNA available\n", foiscsi_name);
		rc = FOISCSI_ERR_INVALID_PARAM;
		goto out;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", foiscsi_name);
		rc = FOISCSI_ERR_OOM;
		goto out;
	}

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
	req = (struct csio_foiscsi_ifconf_ioctl*)get_payload(buffer);
	memset(req, 0, sizeof(*req));
	
	req->ifid = port;
	req->vlanid = vlanid;

	rc = issue_ioctl(hw, buffer, len);

	req = (struct csio_foiscsi_ifconf_ioctl*)get_payload(buffer);
	
	csio_foiscsi_log_devel_debug("%s: status %d, req->retval %d\n",
						foiscsi_name, rc, req->retval);

	req = (struct csio_foiscsi_ifconf_ioctl*)get_payload(buffer);

	rc = req->retval;

	if (rc == 0) {
		fprintf(stderr, "ifid[%d]: vlan-id %u, vlan-prio %u provisioned successfully\n",
				port, vlanid & 0x0fff, (vlanid >> 13) & 0x7);
	} else if (rc == 2) {
		fprintf(stderr, "ifid[%d]: vlan in use\n", port);
	} else {
		fprintf(stderr, "ifid[%d]: error provisioning vlan-id %u, vlan-prio %u\n",
				port, vlanid & 0x0fff, (vlanid >> 13) & 0x7);
	}

	ioctl_buffer_free(buffer);

out:
	return rc;
}

static int csio_foiscsi_iface_do_mtu(adap_handle_t hw, int16_t mtu, int8_t port)
{
	void *buffer = NULL;
	struct csio_foiscsi_ifconf_ioctl *req = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(*req));
	uint32_t cmd = CSIO_STOR_FOISCSI_OPCODE(CSIO_FOISCSI_IFCONF_MTU_SET_IOCTL);
	int rc = 0;

	if (hw < 0) {
		fprintf(stderr, "%s: No chelsio T4 CNA available\n", foiscsi_name);
		rc = FOISCSI_ERR_INVALID_PARAM;
		goto out;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", foiscsi_name);
		rc = FOISCSI_ERR_OOM;
		goto out;
	}

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
	req = (struct csio_foiscsi_ifconf_ioctl*)get_payload(buffer);
	memset(req, 0, sizeof(*req));
	
	req->ifid = port;
	req->mtu = mtu;
	
	rc = issue_ioctl(hw, buffer, len);

	req = (struct csio_foiscsi_ifconf_ioctl*)get_payload(buffer);
	rc = req->retval;

	if (rc == 0) {
		fprintf(stderr, "\nifid : %d\n", port);
		fprintf(stderr, "----------------------------------\n");
		fprintf(stderr, "mtu changed to  : %u\n", req->mtu);
		fprintf(stderr, "----------------------------------\n");
	} else 
		fprintf(stderr, "\nInvalid parameter\n");

	csio_foiscsi_log_devel_debug("%s: status %d\n", foiscsi_name, rc);
	ioctl_buffer_free(buffer);

out:
	return rc;
}

static int32_t
csio_foiscsi_iface_do_show(adap_handle_t hw, uint8_t ifid, struct csio_foiscsi_ifconf_ioctl *um_iface)
{

	void *buffer = NULL;
	struct csio_foiscsi_ifconf_ioctl *req = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(*req));
	uint32_t cmd = CSIO_STOR_FOISCSI_OPCODE(CSIO_FOISCSI_IFACE_GET_IOCTL);
	int rc = 0;

	if (hw < 0) {
		fprintf(stderr, "%s: No chelsio T4 CNA available\n", foiscsi_name);
		rc = FOISCSI_ERR_INVALID_PARAM;
		goto out;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", foiscsi_name);
		rc = FOISCSI_ERR_OOM;
		goto out;
	}

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
	req = (struct csio_foiscsi_ifconf_ioctl*)get_payload(buffer);
	memset(req, 0, sizeof(*req));

	req->ifid = ifid;

	rc = issue_ioctl(hw, buffer, len);

	req = (struct csio_foiscsi_ifconf_ioctl*)get_payload(buffer);

	if (rc == 0) { 
		if(!um_iface) {
			fprintf(stderr, "\nifid : %d\n", ifid);
			fprintf(stderr, "----------------------------------\n");
			fprintf(stderr, "mtu   : %u\n", req->mtu);
			fprintf(stderr, "vlan-id: %u\n",
				csio_chnet_is_valid_vlan(req->vlanid) ? (req->vlanid & 0x0fff) : 0);
			fprintf(stderr, "vlan-prio: %u\n",
				csio_chnet_is_valid_vlan(req->vlanid) ? ((req->vlanid >> 13) & 0xf) : 0);
			fprintf(stderr, "----------------------------------\n");
			fprintf(stderr, "Address Type Mask : 0x%x\n", req->address_state);
		} else {
			memcpy(um_iface, req, sizeof(struct csio_foiscsi_ifconf_ioctl));
		}
	} else 
		fprintf(stderr, "\nInvalid parameter\n");

	csio_foiscsi_log_devel_debug("%s: status %d\n", foiscsi_name, rc);

	ioctl_buffer_free(buffer);

out:
	return rc;
}


void csio_foiscsi_ifconf_do_dhcp_show(adap_handle_t hw, uint16_t type,
				uint16_t vlanid, uint8_t ifid)
{
	return;
}

int32_t csio_foiscsi_ifconf_do_ipv6_show(adap_handle_t hw, uint16_t type,
				uint16_t vlanid, uint8_t ifid)
{
	void *buffer = NULL;
	struct csio_foiscsi_ifconf_ioctl *req = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(*req));
	uint32_t cmd =
		CSIO_STOR_FOISCSI_OPCODE(CSIO_FOISCSI_IFCONF_IPV6_GET_IOCTL);
	int rc = 0;
	char ipv6_addr[64];

	if (hw < 0) {
		fprintf(stderr, "%s: No chelsio T4 CNA available\n",
			foiscsi_name);
		rc = CSIO_EINVAL;
		goto out;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", foiscsi_name);
		rc = CSIO_ENOMEM;
		goto out;
	}

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
	req = (struct csio_foiscsi_ifconf_ioctl*)get_payload(buffer);
	memset(req, 0, sizeof(*req));

	req->ifid = ifid;
	req->vlanid = vlanid;
	req->type = type;
	
	rc = issue_ioctl(hw, buffer, len);
	if (rc == 0) {
		fprintf(stderr, "\nifid : %d\n", ifid);
		fprintf(stderr, "----------------------------------\n");
		if (inet_ntop(AF_INET6, req->v6.ipv6_addr, ipv6_addr, 64)){
			fprintf(stderr, "ip:\t %s/%u\n",
				ipv6_addr, req->v6.prefix_len);
			
		}
		inet_ntop(AF_INET6, req->v6.ipv6_gw, ipv6_addr, 64);
		fprintf(stderr, "gw:\t %s\n", ipv6_addr);
		fprintf(stderr, "----------------------------------\n");
	} else
		fprintf(stderr, "\nInvalid parameter\n");

	req->subop = OP_LLOCAL;
	rc = issue_ioctl(hw, buffer, len);
        if (rc == 0) {
                fprintf(stderr, "\nLink-local\n");
                fprintf(stderr, "----------------------------------\n");
                if (inet_ntop(AF_INET6, req->v6.ipv6_addr, ipv6_addr, 64)){
                        fprintf(stderr, "ip:\t %s/%u\n",
                                ipv6_addr, req->v6.prefix_len);

                }
                fprintf(stderr, "----------------------------------\n");
        } else
                fprintf(stderr, "\nInvalid parameter\n");

	csio_foiscsi_log_devel_debug("%s: status %d\n", foiscsi_name, rc);

	ioctl_buffer_free(buffer);

out:
	return rc;
}

int32_t csio_foiscsi_ifconf_do_ipv4_show(adap_handle_t hw, uint16_t type,
				uint16_t vlanid, uint8_t ifid, struct csio_foiscsi_ifconf_ioctl *um_req)
{
	void *buffer = NULL;
	struct csio_foiscsi_ifconf_ioctl *req = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(*req));
	uint32_t cmd = CSIO_STOR_FOISCSI_OPCODE(CSIO_FOISCSI_IFCONF_IPV4_GET_IOCTL);
	struct in_addr iaddr;
	struct in_addr mask;
	struct in_addr gw;
	int rc = 0;

	if (hw < 0) {
		fprintf(stderr, "%s: No chelsio T4 CNA available\n", foiscsi_name);
		rc = FOISCSI_ERR_INVALID_PARAM;
		goto out;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", foiscsi_name);
		rc = FOISCSI_ERR_OOM;
		goto out;
	}

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
	req = (struct csio_foiscsi_ifconf_ioctl*)get_payload(buffer);
	memset(req, 0, sizeof(*req));

	req->ifid = ifid;
	req->vlanid = vlanid;
	req->type = type;
	
	rc = issue_ioctl(hw, buffer, len);

	/*req = get_payload(buffer);*/
	iaddr.s_addr = ntohl(req->v4.ipv4_addr);
	mask.s_addr = ntohl(req->v4.ipv4_mask);
	gw.s_addr = ntohl(req->v4.ipv4_gw);


	if (rc == 0) {
		if(!um_req) {
			fprintf(stderr, "\nifid : %d\n", ifid);
			fprintf(stderr, "----------------------------------\n");
			fprintf(stderr, "ip:\t %s\n", inet_ntoa(iaddr));
			fprintf(stderr, "mask:\t %s\n", inet_ntoa(mask));
			fprintf(stderr, "gw:\t %s\n", inet_ntoa(gw));
			fprintf(stderr, "----------------------------------\n");
		} else {
			memcpy(um_req, req, sizeof(struct csio_foiscsi_ifconf_ioctl));
		}
	} else 
		fprintf(stderr, "\nInvalid parameter\n");

	csio_foiscsi_log_devel_debug("%s: status %d\n", foiscsi_name, rc);

	ioctl_buffer_free(buffer);

out:
	return rc;
}

static int32_t
csio_foiscsi_ifconf_do_dhcp_assign(adap_handle_t hw, uint16_t type,
					uint16_t vlanid, uint8_t ifid)
{
	void *buffer = NULL;
	struct csio_foiscsi_ifconf_ioctl *req = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(*req));
	uint32_t cmd;
	struct in_addr iaddr, mask, gw;
	char ipv6_addr[64];
	int rc = 0;

	if (hw < 0) {
		fprintf(stderr, "%s: No chelsio T4 CNA available\n", foiscsi_name);
		rc = FOISCSI_ERR_INVALID_PARAM;
		goto out;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", foiscsi_name);
		rc = FOISCSI_ERR_OOM;
		goto out;
	}

	if (type == TYPE_DHCP)
		cmd =CSIO_STOR_FOISCSI_OPCODE(
			CSIO_FOISCSI_IFCONF_IPV4_DHCP_SET_IOCTL);
	else /* (type == TYPE_DHCPV6) */
		cmd = CSIO_STOR_FOISCSI_OPCODE(
			CSIO_FOISCSI_IFCONF_IPV6_DHCP_SET_IOCTL);

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
	req = (struct csio_foiscsi_ifconf_ioctl*)get_payload(buffer);
	memset(req, 0, sizeof(*req));

	req->ifid = ifid;
	req->type = type;
	req->subop = OP_ASSIGN;
	
	if (csio_chnet_is_valid_vlan(vlanid))
		req->vlanid = vlanid;

	rc = issue_ioctl(hw, buffer, len);

	req = get_payload(buffer);

	rc = req->retval;

	csio_foiscsi_log_devel_debug("%s: rc %d\n", __FUNCTION__, rc);
	if (type == TYPE_DHCP) {
		iaddr.s_addr = ntohl(req->v4.ipv4_addr);
		mask.s_addr = ntohl(req->v4.ipv4_mask);
		gw.s_addr = ntohl(req->v4.ipv4_gw);
	
		if (rc == 0) {
			fprintf(stderr, "\nip\t%s\n\n"
			"mask\t%s\n\n"
			"gw\t%s\n\n"
			"[%s on iface %d successfully]\n",
 			req->v4.ipv4_addr == 0 ?\
				 "xxx.xxx.xxx.xxx" : inet_ntoa(iaddr),
			req->v4.ipv4_mask == 0 ?\
				 "xxx.xxx.xxx.xxx" : inet_ntoa(mask),
			req->v4.ipv4_gw == 0 ?\
				 "xxx.xxx.xxx.xxx" : inet_ntoa(gw),
 			"provisioned", ifid);
		}
	} else {
		if ((rc == 0) &&
		     inet_ntop(AF_INET6, req->v6.ipv6_addr, ipv6_addr, 64))
			fprintf(stderr, "\nip\t%s\n\n"
				"[provisioned on iface %d successfully\n",
				ipv6_addr, ifid);

	}

	ioctl_buffer_free(buffer);

out:
	return rc;
}

static int32_t
csio_foiscsi_ifconf_do_ipv6_assign(adap_handle_t hw, uint16_t type, char *saddr,
				unsigned int prefix_len, char *gw,
				uint16_t vlanid, uint8_t ifid)
{
	void *buffer = NULL;
	struct csio_foiscsi_ifconf_ioctl *req = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(*req));
	uint32_t cmd = CSIO_STOR_FOISCSI_OPCODE(
			CSIO_FOISCSI_IFCONF_IPV6_SET_IOCTL);
	uint8_t addr6[16], gw6[16];

	int rc = 0;

	if (hw < 0) {
		fprintf(stderr, "%s: No chelsio T4 CNA available\n",
			foiscsi_name);
		rc = CSIO_EINVAL;
		goto out;
	}

	if (saddr && (inet_pton(AF_INET6, saddr, addr6) != 1)) {
		fprintf(stderr, "%s: Invalid saddr\n", foiscsi_name);
		rc = CSIO_EINVAL;
		goto out;
	}
	if (gw && (inet_pton(AF_INET6, gw, gw6) !=  1)) {
		fprintf(stderr, "%s: Invalid router address\n", foiscsi_name);
		rc = CSIO_EINVAL;
		goto out;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", foiscsi_name);
		rc = CSIO_ENOMEM;
		goto out;
	}

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
	req = (struct csio_foiscsi_ifconf_ioctl*)get_payload(buffer);
	memset(req, 0, sizeof(*req));

	req->ifid = ifid;
	req->type = type;
	req->subop = OP_ASSIGN;
	
	if (saddr)
		memcpy(req->v6.ipv6_addr, addr6, 16);
	if (gw)
		memcpy(req->v6.ipv6_gw, gw6, 16);

	req->v6.prefix_len = prefix_len;

	req->vlanid = vlanid;

	rc = issue_ioctl(hw, buffer, len);

	req = get_payload(buffer);

	csio_foiscsi_log_devel_debug("%s: rc %d\n", __FUNCTION__, rc);
	
	if (rc == 99 || rc == 2) {
		fprintf(stderr, "\naddress %s already in use.\n",
			saddr);
	} else if (rc == EADDRINUSE)
		fprintf(stderr, "\naddress %s have conflict on the network.\n",
				saddr);
	
	if (rc == 0) {
		fprintf(stderr, "\nip\t%s/%d\n\ngw\t%s \n\n"
			"[%s on iface %d successfully]\n\n",
			saddr == NULL ? "xxx.xxx.xxx.xxx" : saddr,
			prefix_len,
			gw == NULL ? "xxx.xxx.xxx.xxx" : gw,
			"provisioned", ifid);
	}

	csio_foiscsi_log_devel_debug("%s: status %d\n", foiscsi_name, rc);

	ioctl_buffer_free(buffer);

out:
	return rc;
}

static int32_t
csio_foiscsi_ifconf_do_ipv4_assign(adap_handle_t hw, uint16_t type, char *saddr,
				char *mask, char *bcaddr, char *gw,
				uint16_t vlanid, uint8_t ifid)
{
	void *buffer = NULL;
	struct csio_foiscsi_ifconf_ioctl *req = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(*req));
	uint32_t cmd = CSIO_STOR_FOISCSI_OPCODE(CSIO_FOISCSI_IFCONF_IPV4_SET_IOCTL);
	int rc = 0;

	if (hw < 0) {
		fprintf(stderr, "%s: No chelsio T4 CNA available\n", foiscsi_name);
		rc = FOISCSI_ERR_INVALID_PARAM;
		goto out;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", foiscsi_name);
		rc = FOISCSI_ERR_OOM;
		goto out;
	}

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
	req = (struct csio_foiscsi_ifconf_ioctl*)get_payload(buffer);
	memset(req, 0, sizeof(*req));

	req->ifid = ifid;
	req->type = type;
	req->subop = OP_ASSIGN;
	
	if(saddr)
		req->v4.ipv4_addr = inet_network(saddr);
	
	if (mask)
		req->v4.ipv4_mask = inet_network(mask);
	
#if 0
	if(bcaddr)
		req->u.ipv4.bcaddr = inet_network(bcaddr);
#endif
	if(gw)
		req->v4.ipv4_gw = inet_network(gw);

	req->vlanid = vlanid;

	rc = issue_ioctl(hw, buffer, len);

	req = get_payload(buffer);

	rc = req->retval;

	csio_foiscsi_log_devel_debug("%s: rc %d\n", __FUNCTION__, rc);
	
	if (rc == 99 || rc == 2) {
		fprintf(stderr, "\naddress %s already in use.\n",
			saddr);
	} else if (rc == EADDRINUSE)
		fprintf(stderr, "\naddress %s have conflict on the network.\n",
				saddr);
	
	if (rc == 0) {
		fprintf(stderr, "\nip\t%s\nmask\t%s\ngw\t%s \n\n"
			"[%s on iface %d successfully]\n\n",
			saddr == NULL ? "xxx.xxx.xxx.xxx" : saddr,
			mask == NULL ? "xxx.xxx.xxx.xxx" : mask,
			gw == NULL ? "xxx.xxx.xxx.xxx" : gw,
			"provisioned", ifid);
	}

	csio_foiscsi_log_devel_debug("%s: status %d\n", foiscsi_name, rc);

	ioctl_buffer_free(buffer);

out:
	return rc;
}

int32_t
csio_foiscsi_persistent_do_op_clear(adap_handle_t hw, int32_t op, uint8_t idx)
{
	void *buffer = NULL;
	struct iscsi_persistent_target_db  *req = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(*req));
	uint32_t cmd = CSIO_STOR_FOISCSI_OPCODE(CSIO_FOISCSI_PERSISTENT_CLEAR_IOCTL);
	uint32_t rc = 0;
	
	if (hw < 0) {
		fprintf(stderr, "%s: No chelsio T4 CNA available\n", foiscsi_name);
		rc = FOISCSI_ERR_INVALID_PARAM;
		goto out;
        }

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", foiscsi_name);
		rc = FOISCSI_ERR_OOM;
		goto out;
	}

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
	req = (struct iscsi_persistent_target_db *)get_payload(buffer);
	memset(req, 0, sizeof(*req));
	req->num_persistent_targets = idx;

	rc = issue_ioctl(hw, buffer, len);
	if (rc == 0) {
		fprintf(stderr, "ioctl successful\n");
	} else
		fprintf(stderr, "invalid parameter\n");

	ioctl_buffer_free(buffer);

out:
        return rc;
}

int32_t
csio_foiscsi_persistent_do_op_show(adap_handle_t hw, int32_t op)
{
	void *buffer = NULL;
	struct iscsi_persistent_target_db  *req = NULL;
	struct in_addr saddr, taddr;
	char ip6[INET6_ADDRSTRLEN];
	size_t len = os_agnostic_buffer_len(sizeof(*req));
	uint32_t cmd = CSIO_STOR_FOISCSI_OPCODE(CSIO_FOISCSI_PERSISTENT_GET_IOCTL);
	int rc = 0, j = 0;

	if (hw < 0) {
		fprintf(stderr, "%s: No chelsio T4 CNA available\n", foiscsi_name);
		rc = FOISCSI_ERR_INVALID_PARAM;
		goto out;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", foiscsi_name);
		rc = FOISCSI_ERR_OOM;
		goto out;
	}

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
	req = (struct iscsi_persistent_target_db *)get_payload(buffer);
	memset(req, 0, sizeof(*req));

	rc = issue_ioctl(hw, buffer, len);
	if (rc == 0)
		fprintf(stderr, "ioctl successful\n");
	else
		fprintf(stderr, "\nInvalid parameter\n");

	for (j=0; j< req->num_persistent_targets; j++) {
		if (req->target[j].valid == VALID_REC) {
			printf("========Target Record idx %d ========\n",j);
			printf("target iqn = %s\n",req->target[j].targname);
			if (!req->target[j].flag) {
				taddr.s_addr = ntohl(
					req->target[j].portal.taddr.ipv4_address);
				printf("Target Portal  = %s:%u\n",
				       inet_ntoa(taddr),req->target[j].portal.tcpport);
				saddr.s_addr = ntohl(req->target[j].saddr);
                        	printf("Source Address = %s\n",inet_ntoa(saddr));
			} else {
				inet_ntop(AF_INET6, req->target[j].portal.taddr.ipv6_address, ip6, INET6_ADDRSTRLEN);
				printf("Target Portal  = [%s]:%u\n", ip6, req->target[j].portal.tcpport);
				inet_ntop(AF_INET6, req->target[j].saddr6, ip6, INET6_ADDRSTRLEN);
				printf("Source Address = %s\n", ip6);
			}
			printf("node Id = %u\n",req->target[j].node_id);
			printf("max conn = %u\n",req->target[j].attr.max_conn);
			printf("maxR2t = %u\n",req->target[j].attr.max_r2t);
			printf("time2wait = %u\n",req->target[j].attr.time2wait);
			printf("time2retain = %u\n",req->target[j].attr.time2retain);
			printf("max_burst = %u\n",req->target[j].attr.max_burst);
			printf("first_burst = %u\n",req->target[j].attr.first_burst);
			printf("max_rcv_dsl = %u\n",req->target[j].attr.max_rcv_dsl);
			printf("ping timeout = %u\n\n",req->target[j].attr.ping_tmo);
		}
	}	

	csio_foiscsi_log_devel_debug("%s: status %d\n", foiscsi_name, rc);
	ioctl_buffer_free(buffer);
out:
        return rc;
}


int32_t
csio_foiscsi_ifconf_do_ip_clear(adap_handle_t hw, uint16_t type,
				uint8_t ifid, uint16_t vlanid)
{
	void *buffer = NULL;
	struct csio_foiscsi_ifconf_ioctl *req = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(*req));
	uint32_t cmd;

	int rc = 0;

	if (hw < 0) {
		fprintf(stderr, "%s: No chelsio T4 CNA available\n", foiscsi_name);
		rc = FOISCSI_ERR_INVALID_PARAM;
		goto out;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", foiscsi_name);
		rc = FOISCSI_ERR_OOM;
		goto out;
	}
	if (type == TYPE_IPV6 || type == TYPE_VLAN_IPV6 || type == TYPE_DHCPV6)
		cmd = CSIO_STOR_FOISCSI_OPCODE(
			CSIO_FOISCSI_IFCONF_IPV6_SET_IOCTL);
	else
		cmd = CSIO_STOR_FOISCSI_OPCODE(
			CSIO_FOISCSI_IFCONF_IPV4_SET_IOCTL);

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
	req = (struct csio_foiscsi_ifconf_ioctl*)get_payload(buffer);
	memset(req, 0, sizeof(*req));

	req->ifid = ifid;
	req->type = type;
	req->subop = OP_CLEAR;
	
	if (csio_chnet_is_valid_vlan(vlanid))
		req->vlanid = vlanid;
	else
		req->vlanid = CSIO_FOISCSI_VLAN_NONE;
	
	rc = issue_ioctl(hw, buffer, len);

	req = get_payload(buffer);

	csio_foiscsi_log_devel_debug("%s: rc %d\n", __FUNCTION__, rc);
	
	if (rc == -1) {
		fprintf(stderr, "error clearing resources.\n");
	}
	if (rc == 0) {
		fprintf(stderr, "ifid[%d]: IP deleted\n", ifid);
	}

	csio_foiscsi_log_devel_debug("%s: status %d\n", foiscsi_name, rc);


	ioctl_buffer_free(buffer);

out:
	return rc;

}

int32_t
csio_foiscsi_persistent_do_op(adap_handle_t hw, int32_t op, uint8_t idx)
{
	int32_t rc = 0;
        
	switch (op) {
	case OP_SHOW:
		rc = csio_foiscsi_persistent_do_op_show(hw, op);
		break;
	case OP_CLEAR:
		rc = csio_foiscsi_persistent_do_op_clear(hw, op, idx);
		break;
	default:
		fprintf(stderr, "Invalid options\n");
		break;
	}
	return rc;
}

int32_t
csio_foiscsi_ifconf_do_op(adap_handle_t hw, int32_t op, uint16_t type,
			char *sip, char *mask, char *bcaddr, char *gw,
			uint16_t vlanid, uint8_t ifid, unsigned int prefix_len)
{
	int32_t rc = 0;

	switch (op) {
	case OP_ASSIGN:
		if (type == TYPE_IPV4 || type == TYPE_VLAN_IPV4)
			rc = csio_foiscsi_ifconf_do_ipv4_assign(hw, type, sip,
					mask, bcaddr, gw, vlanid, ifid);
		else if ((type == TYPE_IPV6) || (type == TYPE_VLAN_IPV6))
			rc = csio_foiscsi_ifconf_do_ipv6_assign(hw, type, sip,
					prefix_len, gw, vlanid, ifid);
		else if ((type == TYPE_DHCP) || (type == TYPE_DHCPV6))
			rc = csio_foiscsi_ifconf_do_dhcp_assign(hw, type,
								vlanid, ifid);
		break;

	case OP_SHOW:
		if (type == TYPE_IPV4)
			csio_foiscsi_ifconf_do_ipv4_show(hw, type,
							vlanid, ifid, NULL);
		else if ((type == TYPE_IPV6) || (type == TYPE_DHCPV6))
			csio_foiscsi_ifconf_do_ipv6_show(hw, type,
							vlanid, ifid);
		else if (type == TYPE_DHCP)
			csio_foiscsi_ifconf_do_ipv4_show(hw, type,
							vlanid, ifid, NULL);
		break;
	
	case OP_CLEAR:
		csio_foiscsi_ifconf_do_ip_clear(hw, type, ifid,
							vlanid);
		break;

	default:
		break;
	}

	return rc;
}

int32_t
csio_foiscsi_iface_do_op(adap_handle_t hw, int32_t op, int16_t mtu, uint16_t vlanid, uint8_t ifid, uint8_t flags)
{
	int32_t rc = 0;

	switch(op) {
	case OP_UP:
	case OP_DOWN:
		rc = csio_foiscsi_iface_do_link_op(hw, op, ifid, flags);
		break;

	case OP_MTU:
		if (mtu < 1500 || mtu > 9000) {
			fprintf(stderr, "invalid mtu %d specified\n", mtu);
			rc = FOISCSI_ERR_INVALID_PARAM;
			goto out;
		}
		rc = csio_foiscsi_iface_do_mtu(hw, mtu, ifid);
		break;
	
	case OP_VLAN:
		if (!csio_chnet_is_valid_vlan(vlanid)) {
			fprintf(stderr, "invalid vlanid %u specified\n", vlanid);
			rc = FOISCSI_ERR_INVALID_PARAM;
			goto out;
		}
		rc = csio_foiscsi_iface_do_vlan(hw, vlanid, ifid);
		break;
		
	case OP_SHOW:
		rc = csio_foiscsi_iface_do_show(hw, ifid, NULL);
		break;
		
	default:
		break;
	}

out:
	return rc;
}

int32_t
um_csio_foiscsi_ifconf_do_op(adap_handle_t hw, int32_t op, struct csio_foiscsi_ifconf_ioctl *um_req)
{                       
        int32_t rc = 0;
        
        switch (op) {
        case OP_ASSIGN: {
                if (um_req->type == TYPE_IPV4 ||
		    um_req->type == TYPE_VLAN_IPV4) {
			char ip[16], gw[16], nm[16];

			convert_decimal_ip(ip, um_req->v4.ipv4_addr);
        		convert_decimal_ip(gw, um_req->v4.ipv4_gw);
			convert_decimal_ip(nm, um_req->v4.ipv4_mask);

                        rc = csio_foiscsi_ifconf_do_ipv4_assign(hw,
					um_req->type, ip, nm, NULL, gw,
					um_req->vlanid, um_req->ifid);
		} else if (um_req->type == TYPE_IPV6)
                        rc = csio_foiscsi_ifconf_do_ipv6_assign(hw,
				um_req->type, (char *) um_req->v6.ipv6_addr,
				um_req->v6.prefix_len,
				(char *)um_req->v6.ipv6_gw,
				um_req->vlanid, um_req->ifid);

                else if ((um_req->type == TYPE_DHCP) ||
			 (um_req->type == TYPE_DHCPV6))
                        rc = csio_foiscsi_ifconf_do_dhcp_assign(hw,
				um_req->type, um_req->vlanid, um_req->ifid);
                break;
	}

        case OP_SHOW:
                if (um_req->type == TYPE_IPV4)
                        csio_foiscsi_ifconf_do_ipv4_show(hw, um_req->type,
                                                        um_req->vlanid, um_req->ifid, um_req);
                else if ((um_req->type == TYPE_IPV6) ||
			 (um_req->type == TYPE_DHCPV6))
                        csio_foiscsi_ifconf_do_ipv6_show(hw, um_req->type,
                                                        um_req->vlanid, um_req->ifid);
                else if (um_req->type == TYPE_DHCP)
                        csio_foiscsi_ifconf_do_ipv4_show(hw, um_req->type,
                                                        um_req->vlanid, um_req->ifid, um_req);
                break;

        case OP_CLEAR:
		csio_foiscsi_ifconf_do_ip_clear(hw, um_req->type,
					um_req->ifid, um_req->vlanid);
                break;

        default:
                break;
        }

        return rc;
}

int32_t
um_csio_foiscsi_iface_do_op(adap_handle_t hw, struct csio_foiscsi_iface_ioctl *um_ioc, struct csio_foiscsi_ifconf_ioctl *um_req)
{
        int32_t rc = 0;

        switch(um_ioc->op) {
        case OP_UP:
        case OP_DOWN:
                rc = csio_foiscsi_iface_do_link_op(hw, um_ioc->op, um_ioc->ifid, um_ioc->flags);
                break;

        case OP_MTU:
                if (um_req->mtu < 1500 || um_req->mtu > 9000) {
                        rc = FOISCSI_ERR_INVALID_PARAM;
                        goto out;
                }
                rc = csio_foiscsi_iface_do_mtu(hw, um_req->mtu, um_ioc->ifid);
                break;

        case OP_VLAN:
                if (!csio_chnet_is_valid_vlan(um_req->vlanid)) {
                        rc = FOISCSI_ERR_INVALID_PARAM;
                        goto out;
                }
                rc = csio_foiscsi_iface_do_vlan(hw, um_req->vlanid, um_ioc->ifid);
                break;

        case OP_SHOW:
                rc = csio_foiscsi_iface_do_show(hw, um_ioc->ifid, um_req);
                break;

        default:
                break;
        }

out:
        return rc;
}

void shift_argv(int *argc, char *argv[], int pos)
{
	int i;

	for (i = 1 ; i <= *argc; i++)
		argv[i - 1] = argv[i];

	(*argc)--;
}

int run_foiscsi_stor(int argc, char *argv[])
{
	int ch, longindex, mode=-1;
	int rc=0, op=OP_NOOP;
	unsigned long sid = -1;
	char *targetname = NULL, *ip = NULL, *sip = NULL;
	char *mask = NULL, *bcaddr = NULL, *gw = NULL;
	int tpgt, tcp_port = DEFAULT_ISCSI_TARGET_PORT;
	int nodeid = -1, persistent = 0;
	char *nodename = NULL, *alias = NULL;
	char *ini_user = NULL, *ini_sec = NULL;
        char *tgt_user = NULL, *tgt_sec = NULL;\
	char *auth_method = NULL, *policy = NULL;
	char *device = NULL;
	adap_handle_t hw = -1;
	short mtu = -1;
	uint16_t type = TYPE_NONE;
	int oport_cnt = 0;
	int oup_cnt = 0;
	int odown_cnt = 0;
	int oassign_cnt = 0;
	int oshow_cnt = 0;
	unsigned int prefix_len = 64;
	uint8_t ifid = -1;
	uint8_t idx = -1;
	uint16_t vlanid = CSIO_FOISCSI_VLAN_NONE;
	uint8_t vlanprio = 0;
	uint8_t maxnodenamelen = FW_FOISCSI_NAME_MAX_LEN - 1;
	uint8_t maxaliaslen = FW_FOISCSI_ALIAS_MAX_LEN - 1;
	uint8_t flags = 0;

	csio_foiscsi_log_devel_debug("%s: entering\n", foiscsi_name);
	csio_foiscsi_log_devel_debug("optind %d, argc %d\n", optind, argc);
	
	optopt = 0;
	optind = 3;

	if (!strncmp(argv[2], foiscsi_base_opt, strlen(foiscsi_base_opt))) {
		memset(argv[2], 0, strlen(foiscsi_base_opt));
		strncpy(argv[2], "foiscsi", strlen(foiscsi_base_opt));
	}

	csio_foiscsi_log_devel_debug("%s: argv[0] %s, argv[1] %s\n",
					foiscsi_name, argv[0], argv[1]);


	while ((ch = getopt_long(argc, argv, short_options, long_options, &longindex)) >= 0) {

		csio_foiscsi_log_devel_debug("%s: ch : %c, longindex %d\n",
						foiscsi_name, ch, longindex);

		switch (ch) {
		case 'd':
			device = optarg;
			csio_foiscsi_log_devel_debug("%s: device %s\n",
							foiscsi_name, device);
			break;
		case 'o':
			op = str_to_op(optarg);
			if (op == OP_UP)
				oup_cnt++;
			else if (op == OP_DOWN)
				odown_cnt++;
			else if (op == OP_ASSIGN)
				oassign_cnt++;
			else if (op == OP_SHOW)
				oshow_cnt++;
			
			csio_foiscsi_log_devel_debug("%s: opcode %d\n", foiscsi_name, op);
			break;
		case 'm':
			mode = str_to_mode(optarg);
			csio_foiscsi_log_devel_debug("%s: mode %d\n", foiscsi_name, mode);
			break;
		case 'i':
			ifid = atoi(optarg);
			csio_foiscsi_log_devel_debug("%s: index %d\n", foiscsi_name, ifid);
			break;
		case 'a':
			alias = optarg;
			csio_foiscsi_log_devel_debug("%s: alias %s\n", foiscsi_name, alias);
			break;
		case 'n':
			nodename = optarg;
			csio_foiscsi_log_devel_debug("%s: nodename %s\n", foiscsi_name, nodename);
			break;
		case 'p':
			csio_foiscsi_log_devel_debug("%s: optarg %s\n", foiscsi_name, optarg);
			break;
		case 'T':
			targetname = optarg;
			csio_foiscsi_log_devel_debug("%s: targetname %s\n", foiscsi_name, targetname);
			break;
		case 'P':
			ip = str_to_ipport(optarg, &tcp_port, &tpgt);
			break;
		case 's':
			sid = strtoull(optarg, NULL, 10);
			break;
		case 'r':
			sip = optarg;
			csio_foiscsi_log_devel_debug("%s: saddr %s\n", foiscsi_name, optarg);
			break;
		case 'k':
			mask = optarg;
			csio_foiscsi_log_devel_debug("%s: mask %s\n", foiscsi_name, optarg);
			break;
#if 0
		case 'b':
			bcaddr = optarg;
			csio_foiscsi_log_devel_debug("%s: bcaddr %s\n", foiscsi_name, optarg);
			break;
#endif
		case 'g':
			gw = optarg;
			csio_foiscsi_log_devel_debug("%s: gw %s\n", foiscsi_name, optarg);
			break;
		case 'l':
			vlanid = atoi(optarg);
			csio_foiscsi_log_devel_debug("%s: vlanid %u\n", foiscsi_name, vlanid);
			break;
		case 'y':
			vlanprio = atoi(optarg);
			csio_foiscsi_log_devel_debug("%s: vlanprio %u\n", foiscsi_name, vlanprio);
			break;
		case 'B':
			persistent = 1;
			break;
		case 'x':
			idx = atoi(optarg);
			csio_foiscsi_log_devel_debug("%s: index %d\n", foiscsi_name, idx);
			break;
		case 't':
			type = str_to_ifconf_type(optarg);
			csio_foiscsi_log_devel_debug("%s: type %d : %s\n", foiscsi_name, type, optarg);
			break;
		case 'u':
			mtu = atoi(optarg);
			csio_foiscsi_log_devel_debug("%s: mtu %d\n", foiscsi_name, mtu);
			break;
		case 'e':
			nodeid = strtoull(optarg, NULL, 10);
			break;
		case 'I':
			ini_user = optarg;
			break;
		case 'S':
			ini_sec = optarg;
			break;
		case 'R':
			tgt_user = optarg;
			break;
		case 'C':
			tgt_sec = optarg;
			break;
		case 'A':
			auth_method = optarg;
			break;
		case 'L':
			policy = optarg;
			break;
		case 'O':
			flags = atoi(optarg);
			break;
		case 'h':
			usage(0);
			break;
		case 'f':
			prefix_len = atoi(optarg);
			csio_foiscsi_log_devel_debug("%s: ipv6 prefix len %d\n",
					foiscsi_name, prefix_len);
			break;
		case '?':
		default:
			usage(1);
			csio_foiscsi_log_devel_debug("in default\n");
			csio_foiscsi_log_devel_debug("%s: Invalid character %c\n", foiscsi_name, optopt);
			rc = FOISCSI_ERR_INVALID_PARAM;
			goto out;

			break;
		}
	}

	if (argc == 3)
		usage(0);
	
	csio_foiscsi_log_devel_debug("optind %d, argc %d\n", optind, argc);
	
	if (optind < argc) {
		fprintf(stderr, "%s: unrecognised option %s\n", foiscsi_name, argv[optind]);
		rc = FOISCSI_ERR_INVALID_PARAM;
		goto out;
	}

	if (optopt) {
		fprintf(stderr, "%s: Invalid character %c\n", foiscsi_name, optopt);
		rc = FOISCSI_ERR_INVALID_PARAM;
		goto out;
	}

	if (!device) {
		fprintf(stderr, "%s: Please specify Chelsio device node\n", foiscsi_name);
		rc = FOISCSI_ERR_INVALID_PARAM;
		goto out;
	}

	if (mode < 0) {
		fprintf(stderr, "Mode is a required parameter\n");
		usage(1);
	}

#if 0
	if (op == OP_NOOP) {
		fprintf(stderr, "please specify a valid operations\n");
		usage(1);
	}
#endif

	if (device) {
		hw = open_adapter_handle(device);

		if (hw == -1 || (csio_probe_adapter(hw) != 0)) {
			fprintf(stderr, "%s: error opening device %s, %s\n", foiscsi_name, device, strerror(errno));
			rc = errno;
			goto out;
		}
	}

	switch (mode) {
	case MODE_INIT_INSTANCE:

		if ((rc = verify_short_mode_params(argc, argv, "moineadIS", 0))) {
			fprintf(stderr, "%s: init-instance option '-%c' is not "
					"supported\n", foiscsi_name, rc);
			rc = FOISCSI_ERR_INVALID_PARAM;
			goto out;
		}

		if (nodename && strlen(nodename) > maxnodenamelen) {
			fprintf(stderr, "Invalid nodename length %d\n", (int)strlen(nodename));
			rc = FOISCSI_ERR_INVALID_PARAM;
			goto out;
		}

		if (alias && strlen(alias) > maxaliaslen) {
			fprintf(stderr, "Invalid alias length %d\n", (int)strlen(alias));
			rc = FOISCSI_ERR_INVALID_PARAM;
			goto out;
		}

		rc = foiscsi_manage_instance(hw, op, nodeid, nodename, alias,
				ini_user, ini_sec);
		break;

	case MODE_DISCOVERY:
		
		if ((rc = verify_short_mode_params(argc, argv, "mirePdl", 0))) {
			fprintf(stderr, "%s: discovery option '-%c' is not "
					"supported\n", foiscsi_name, rc);
			rc = FOISCSI_ERR_INVALID_PARAM;
			goto out;
		}

		rc = foiscsi_do_discovery(hw, op, nodeid, sip, ip, tcp_port,
					vlanid, NULL);
		break;

	case MODE_SESSION:
		
		if ((rc = verify_short_mode_params(argc, argv,
					"moiseSrTPdALRCBl", 0))) {
			fprintf(stderr, "%s: session option '-%c' is not "
					"supported\n", foiscsi_name, rc);
			rc = FOISCSI_ERR_INVALID_PARAM;
			goto out;
		}

		if (op == OP_LOGIN) {
			if (nodeid == -1 ||
				sip == NULL || targetname == NULL ||
				ip == NULL || !tcp_port) {
				fprintf(stderr,
					"required parameter missing\n\n");
				rc = FOISCSI_ERR_INVALID_PARAM;
				goto out;
			}

			csio_foiscsi_log_devel_debug("\tnodeid: %d\n"
						"\tsource ip: %s\n"
						"\tTargetName: %s\n"
						"\tdestinatip ip: %s\n"
						"\tport: %d\n"
						"\tpersistent: %d\n",
						nodeid, sip, targetname, 
						ip, tcp_port, persistent);
#if 0
		} else if (op == OP_LOGOUT || op == OP_SHOW) {
#endif
		} else if (op == OP_LOGOUT) {
			if (nodeid == -1) {
				fprintf(stderr, "required parameter missing\n\n");
				rc = FOISCSI_ERR_INVALID_PARAM;
				goto out;
			}
#if 0
			if (sid == -1)
				sid = 0;
#endif

			csio_foiscsi_log_devel_debug("\tnodeid %d\n"
							"\tsid %ld\n",
							nodeid, sid);
		}
		
		rc = foiscsi_manage_session(hw, op, nodeid, sip, targetname,
				ip, tcp_port, sid, auth_method, policy, 
				tgt_user, tgt_sec, persistent, vlanid);
		break;

	case MODE_IFACE:

		if (op == OP_NOOP) {
			fprintf(stderr, "please specify an operation you want to perform.\n");
			rc = FOISCSI_ERR_INVALID_PARAM;
			goto out;
		}

		if (ifid == (uint8_t)-1) {
			fprintf(stderr, "please specify a valid --ifid\n");
			rc = FOISCSI_ERR_INVALID_PARAM;
			goto out;
		}

		if (mtu != -1 && vlanid != CSIO_FOISCSI_VLAN_NONE) {
			fprintf(stderr, "invalid option combination\n");
			rc = FOISCSI_ERR_INVALID_PARAM;
			goto out;
		}

		if (op == OP_UP || op == OP_DOWN) {
			if ((rc = verify_short_mode_params(argc, argv, "mdoiO", 0))) {
				fprintf(stderr, "iface, option '-%c' is not "
						"supported\n",rc);
				rc = FOISCSI_ERR_INVALID_PARAM;
				goto out;
			}

			if (oport_cnt > 1) {
				fprintf(stderr, "iface, multiple --ifid option is invalid\n");
				rc = FOISCSI_ERR_INVALID_PARAM;
				goto out;
			}
		} else if (op == OP_MTU) {
			if ((rc = verify_short_mode_params(argc, argv, "mdoiuO", 0))) {
				fprintf(stderr, "iface, option '-%c' is not "
						"supported\n",rc);
				rc = FOISCSI_ERR_INVALID_PARAM;
				goto out;
			}
		} else if (op == OP_VLAN) {
			if ((rc = verify_short_mode_params(argc, argv, "mdoilyO", 0))) {
				fprintf(stderr, "iface, option '-%c' is not "
						"supported\n",rc);
				rc = FOISCSI_ERR_INVALID_PARAM;
				goto out;
			}
		} else if (op == OP_ASSIGN || op == OP_SHOW) {
			if ((rc = verify_short_mode_params(argc, argv, "mdoiO", 0))) {
				fprintf(stderr, "iface, option '-%c' is not "
						"supported\n",rc);
				rc = FOISCSI_ERR_INVALID_PARAM;
				goto out;
			}
		}

		vlanid = (vlanid & 0x0fff) | (vlanprio << 13);
		fprintf(stderr, "flags %u\n", flags);
		rc = csio_foiscsi_iface_do_op(hw, op, mtu, vlanid, ifid, flags);
		break;

	case MODE_IFCONF:
		
		if (op == OP_NOOP) {
			fprintf(stderr, "ifconf, please specify an operation you want to perform.\n");
			rc = FOISCSI_ERR_INVALID_PARAM;
			goto out;
		}

		if (type == TYPE_NONE) {
			fprintf(stderr, "ifconf, required option --type is missing\n");
			rc = FOISCSI_ERR_INVALID_PARAM;
			goto out;
		}

		if (ifid == (uint8_t)-1) {
			fprintf(stderr, "ifconf, required option --ifid is missing\n");
			rc = FOISCSI_ERR_INVALID_PARAM;
			goto out;
		}

		if (op == OP_ASSIGN) {
			
			if (type == TYPE_IPV4 || type == TYPE_IPV6) {
				if ((rc = verify_short_mode_params(argc, argv, "mdoitrkglyf", 0))) {
					fprintf(stderr, "ifconf, option '-%c' is not "
							"supported\n", rc);
					rc = FOISCSI_ERR_INVALID_PARAM;
					goto out;
				}
				
				if (!sip) {
					fprintf(stderr, "ifconf: please specify --saddr\n");
					rc = FOISCSI_ERR_INVALID_PARAM;
					goto out;
				}

			/*} else if (type == TYPE_VLAN_IPV4 || type == TYPE_VLAN_IPV6) {
				if ((rc = verify_short_mode_params(argc, argv, "mdoitrkgl", 0))) {
					fprintf(stderr, "ifconf, option '-%c' is not "
							"supported\n", rc);
					rc = FOISCSI_ERR_INVALID_PARAM;
					goto out;
				}
				
				if (!sip) {
					fprintf(stderr, "ifconf: please specify --saddr\n");
					rc = FOISCSI_ERR_INVALID_PARAM;
					goto out;
				}*/

			} else if (type == TYPE_DHCP) {
				if ((rc = verify_short_mode_params(argc, argv, "mdoitly", 0))) {
					fprintf(stderr, "ifconf, option '-%c' is not "
							"supported\n", rc);
					rc = FOISCSI_ERR_INVALID_PARAM;
					goto out;

				}
			}
		} else if (op == OP_SHOW || op == OP_CLEAR) {
			if ((rc = verify_short_mode_params(argc, argv, "mdoitly", 0))) {
				fprintf(stderr, "ifconf, option '-%c' is not "
						"supported\n", rc);
				rc = FOISCSI_ERR_INVALID_PARAM;
				goto out;
			}
		}
		vlanid = (vlanid & 0x0fff) | (vlanprio << 13);
		rc = csio_foiscsi_ifconf_do_op(hw, op, type, sip, mask,
				bcaddr, gw, vlanid, ifid, prefix_len);
		break;

	case MODE_PERSISTENT:
		if (op == OP_CLEAR || op == OP_SHOW ) {
			rc = csio_foiscsi_persistent_do_op(hw, op, idx);
		}			
		break;

	case MODE_HW:
		if ((rc = verify_short_mode_params(argc, argv, "mdo", 0))) {
			fprintf(stderr, "ifconf, option '-%c' is not "
					"supported\n", rc);
			rc = FOISCSI_ERR_INVALID_PARAM;
			goto out;
		}
		if (op == OP_DCBX)
			rc = csio_print_all_dcbx_info(hw);
		else
			rc = csio_print_hw_info(hw);

		break;
	
	default:
		fprintf(stderr, "%s: Unsupported Mode\n", foiscsi_name);
		usage(0);
	}

out:
	if (rc > 0 && rc <= FOISCSI_ERR_LAST)
		fprintf(stderr, "%s\n", foiscsi_err_msgs[rc]);
	else if (rc > FOISCSI_ERR_LAST)
		fprintf(stderr, "Invalid parameter, retval %d\n", rc);
	
	if (hw != -1)
		close_adapter(hw);
	
	csio_foiscsi_log_devel_debug("%s: %d: %s\n", foiscsi_name, rc, retval_to_str(rc));
	
	return 0;
}
