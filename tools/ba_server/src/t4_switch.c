#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <netdb.h>
#include <assert.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

#include "cxgbtool.h"
#include "ba_server.h"
#include "t4_switch.h"

int			adap_fd;
struct table_entry	tables[BA_MAX_TABLES+1];
char			devname[32];
int			num_filters;
int			ba_filter_size = 1;
int			max_acl_rules;
int			ba_rule_increment = BA_RULE_INCREMENT;
int			ba_ipv6 = 0;
long long		in6_all_bits[2];

#define DEBUG_FILE		"/sys/kernel/debug/cxgb4/*/tids"

void	sw_print_rule(struct filter_entry *fe);
int	ba_port_config();
int	sw_table_active(int table);
int	validate_rule_table(int rule, int table);
int	sw_ioctl(int adap_fd, int cmd, struct ifreq *ifr);


/*
 * Initialize the switch 
 */
int
sw_init(int ipv6)
{
	int			i;
	char			buf[64];
	FILE			*f;
	int			rc;
	int			start, end;
	struct ifreq		ifr;
	struct ch_filter	filter;
	struct ch_bypass_ports	cbp;
	char			*cp;
	struct ethtool_drvinfo	drvinfo;
	char			debug_file[PATH_MAX];
	int			reserved_filter_index;
	int			num_reserved_filters;

	/*
	 * Set up control socket and prepare for sending commands to the
	 * driver.
	 */
	adap_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (adap_fd < 0) {
		printf("can't get control socket to device driver for %s\n",
		       devname);
		return -1;
	}
	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, devname, sizeof(ifr.ifr_name));

	/*
	 * Figure out the /sys/kernel/debug/cxgb4/{PCI Bus:Slot.Function}/tids file
	 * name for our device.
	 */
	drvinfo.cmd = ETHTOOL_GDRVINFO;
	ifr.ifr_data = (void *)&drvinfo;
	rc = ioctl(adap_fd, SIOCETHTOOL, &ifr);
	if (rc != 0) {
		printf("unable to retrieve %s ethtool Driver Information: %s\n",
		       devname, strerror(errno));
		return -1;
	}
	sprintf(debug_file, "/sys/kernel/debug/cxgb4/%s/tids", drvinfo.bus_info);

	/*
	 * Figure out how many filters we have.
	 */
	snprintf(buf, sizeof(buf), "/bin/cat %s | grep FTID", debug_file);
	f = popen(buf, "r");
	if (f == NULL) {
		printf("Unable to open %s to determine number of filters\n",
		       debug_file);
		return -1;
	}
	cp = fgets(buf, sizeof(buf), f);
	pclose(f);
	if (cp == NULL) {
		printf("Unable to find FTID in %s\n", debug_file);
		return -1;
	}
	if (sscanf(buf, "FTID range: %d..%d", &start, &end) != 2) {
		printf("Unable to scan FTID start/end from %s\n", debug_file);
		return -1;
	}
	num_filters = end - start + 1;
	if (num_filters <= 0) {
		printf("Illegal FTID start=%d/end=%d in %s\n",
		       start, end, debug_file);
		return -1;
	}

	/*
	 * Reserve space for special filters below.
	 *
	 * We set up four special filters at the end of the filter range.
	 * there are three IPv4 filters and one IPv6 filter.  IPv6 filters
	 * occupy four filter slots and need to be on a multiple of four
	 * boundary.  Since the number of filters we have is _probably a
	 * multiple of four to begin with, we'll place the IPv6 filter last
	 * (but round down to be sure) and have the three IPv4 filters proceed
	 * it.
	 */
	reserved_filter_index = (num_filters & ~0x3) - 4 - 3;
	num_reserved_filters = num_filters - reserved_filter_index;
	if (reserved_filter_index <= 0) {
		printf("Insufficient FTID start=%d, end=%d in %s;"
		       " can't allocate special filters\n",
		       start, end, debug_file);
		return -1;
	}

	/*
	 * Figure out how many filters/table, etc. we'll have.
	 */
	max_acl_rules = (num_filters - num_reserved_filters)/BA_MAX_TABLES;
	if (ipv6) {
		memset(&in6_all_bits, 0xff, 16);
		ba_ipv6 = 1;
		max_acl_rules /= 4;
		ba_filter_size = 4;
		ba_rule_increment = 2;
	}
	if (max_acl_rules == 0) {
		printf("Insufficient FTID start=%d, end=%d in %s; need %d\n",
		       start, end, debug_file,
		       BA_MAX_TABLES * (ipv6 ? 4 : 1));
		return -1;
	}
	if (max_acl_rules < (16 *  ba_filter_size)) {
		printf("Warning: very few filters available;"
		       " FTID start=%d, end=%d in %s\n",
		       start, end, debug_file);
	}

	bzero(&filter, sizeof(filter));

	/*
	 * get a list of all ports on the adapter
	 */
	ifr.ifr_data = (void *)&cbp;
	cbp.cmd = CHELSIO_GET_BYPASS_PORTS;
	rc = sw_ioctl(adap_fd, SIOCCHIOCTL, &ifr);
	if (rc != 0) {
		printf("failed to get list of bypass ports\n");
		return -1;
	}

	ba_adapters[ba_adapter_index].num_ports = cbp.port_count;

	for (i = 0; i < cbp.port_count; i++) {
		/*
		 * put interface in promiscuous mode and bring it up
		 */
		strncpy(ifr.ifr_name, cbp.ba_if[i].if_name,
			sizeof(ifr.ifr_name));
		rc = ioctl(adap_fd, SIOCGIFFLAGS, &ifr);
		ifr.ifr_flags |= IFF_PROMISC|IFF_UP;
		rc = ioctl(adap_fd, SIOCSIFFLAGS, &ifr);

	}

	filter.cmd = CHELSIO_DEL_FILTER;
	filter.filter_ver = CH_FILTER_SPECIFICATION_ID;
	ifr.ifr_data = (void *)&filter;
	strncpy(ifr.ifr_name, devname, sizeof(ifr.ifr_name));

	/*
	 * delete any existing filters so that we start from scratch
	 */
	for (i = 0; i < num_filters; i++) {
		filter.filter_id = i;
		rc = sw_ioctl(adap_fd, SIOCCHIOCTL, &ifr);
		if (rc != 0) {
			printf("Can't delete filter at %d\n", i);
			return -1;
		}
	}

	/*
	 * Install secial filters noted above.
	 *
	 * If these change, then we'll need to change the code which
	 * calculates the Reserved Filter Index.
	 */

	/*
	 * Add an IPv4 filter to accept our own MAC addresses (UNICAST
	 * which matches in the MPS TCAM).
	 */
	bzero(&filter, sizeof(filter));
	ifr.ifr_data = (void *)&filter;
	strncpy(ifr.ifr_name, devname, sizeof(ifr.ifr_name));
	filter.cmd = CHELSIO_SET_FILTER;
	filter.filter_ver = CH_FILTER_SPECIFICATION_ID;
	filter.filter_id = reserved_filter_index;
	filter.fs.action = FILTER_PASS;
	filter.fs.val.matchtype = UCAST_EXACT;
	filter.fs.mask.matchtype = 0x7;
	rc = sw_ioctl(adap_fd, SIOCCHIOCTL, &ifr);
	if (rc != 0) {
		printf("Can't set up UCAST_EXACT filter at filter index %d\n",
		       filter.filter_id);
		return -1;
	}

	/*
	 * Add a filter to accept broadcast MAC addresses
	 */
	filter.filter_id++;
	filter.fs.val.matchtype = BCAST;
	rc = sw_ioctl(adap_fd, SIOCCHIOCTL, &ifr);
	if (rc != 0) {
		printf("Can't set up BCAST filter at filter index %d\n",
		       filter.filter_id);
		return -1;
	}

	/*
	 * add lowest priority filters to drop everything
	 */
	filter.filter_id++;
	filter.fs.action = FILTER_DROP;
	filter.fs.val.matchtype = PROMISC;
	rc = sw_ioctl(adap_fd, SIOCCHIOCTL, &ifr);
	if (rc != 0) {
		printf("Can't set up IPv4 PROMISC filter at filter index %d\n",
		       filter.filter_id);
		return -1;
	}

	filter.filter_id++;
	filter.fs.type = 1; /* IPv6 */
	if (filter.filter_id & 0x3) {
		printf("IPv6 PROMISC filter not on multiple of four;"
		       " someone changed things inconsistently ...\n");
		return -1;
	}
	rc = sw_ioctl(adap_fd, SIOCCHIOCTL, &ifr);
	if (rc != 0) {
		printf("Can't set up IPv6 PROMISC filter at filter index %d\n",
		       filter.filter_id);
		return -1;
	}

	/*
	 * init the filter table
	 */
	for (i = 1; i <= BA_MAX_TABLES; i++) {
		TAILQ_INIT(&tables[i].filter_head);
	}

	return 0;

}


void
set_devname(char * name)
{
	strncpy(devname, name, sizeof(devname));

	return;
}

struct filter_entry *
sw_alloc_filter(void)
{
	struct filter_entry		*fe;

	fe = malloc(sizeof(*fe));

	if (fe == NULL)
		return NULL;

	bzero(fe, sizeof(*fe));

	return fe;
}

/*
 * Add a filter entry to the given table
 */
int
sw_add_filter(int table, int rule, struct filter_entry *filter)
{
	struct filter_entry		*fe;

	fe = sw_get_filter(table, rule);
	if (fe != NULL)
		return EEXIST;

	filter->rule = rule;
	filter->filter.filter_id = sw_get_filter_id(table, rule);

	TAILQ_FOREACH(fe, &tables[table].filter_head, fe) {
		if (fe->rule > rule) {
			TAILQ_INSERT_BEFORE(fe, filter, fe);
			return 0;
		}
	}

	TAILQ_INSERT_TAIL(&tables[table].filter_head, filter, fe);

	return 0;
}

int
sw_delete_filter(int table, struct filter_entry *filter)
{
	if (sw_table_active(table))  {
		sw_deactivate_rule(table, filter->rule);
	}
	TAILQ_REMOVE(&tables[table].filter_head, filter, fe);
	free(filter);

	return 0;
}

struct filter_entry *
sw_get_filter(int table_id, int rule)
{
	struct filter_entry		*fe;

	TAILQ_FOREACH(fe, &tables[table_id].filter_head, fe) {
		if (fe->rule == rule)
			break;
	}

	return fe;
}

int
sw_get_filter_id(int table, int rule)
{

	return (((table - 1) * max_acl_rules) + (rule - 1)) * ba_filter_size;
}

int
sw_create_table(int table_id)
{
	int		rc = 0;

	if ((table_id) < 1 || (table_id > BA_MAX_TABLES))
		return EINVAL;

	if (tables[table_id].inuse != 0)
		return EEXIST;

	tables[table_id].inuse = 1;
	tables[table_id].active = 0;

	return rc;
}

int
sw_get_table(int table_id)
{
	if ((table_id) < 1 || (table_id > BA_MAX_TABLES))
		return EINVAL;

	if (tables[table_id].inuse != 1)
		return ENOENT;

	return 0;
}

int
sw_get_first_table(int *table)
{
	int			i;

	for (i = 1; i <= BA_MAX_TABLES; i++) {
		if (tables[i].inuse) {
			*table = i;
			return 0;
		}
	}

	return ENOENT;
}

int
sw_get_next_table(int table, int *nexttable)
{
	int			i;

	for (i = table+1; i <= BA_MAX_TABLES; i++) {
		if (tables[i].inuse) {
			*nexttable = i;
			return 0;
		}
	}

	return ENOENT;

}

int
sw_delete_table(int table_id)
{
	int			rc = 0;
	struct filter_entry	*filter;
	int			rule;

	if ((table_id) < 1 || (table_id > BA_MAX_TABLES))
		return EINVAL;

	sw_deactivate_table(table_id);

	/* avoid info messages from sw_delete_rule */
	tables[table_id].active = 1;

	rc = sw_get_first_rule(table_id, &rule, &filter);
	while (rc == 0) {
		rc = sw_delete_rule(table_id, rule);
		if (rc != 0)
			printf("sw_delete_table: failed to delete rule\n");
		rc = sw_get_first_rule(table_id, &rule, &filter);
	}
	tables[table_id].inuse = 0;
	tables[table_id].active = 0;

	return 0;
}

int
sw_activate_table(int table_id)
{
	int			rc;
	int			rule;
	struct filter_entry	*filter;

	if ((table_id) < 1 || (table_id > BA_MAX_TABLES))
		return EINVAL;

	tables[table_id].active = 1;
	rc = sw_get_first_rule(table_id, &rule, &filter);
	while (rc == 0) {
		rc = sw_activate_rule(table_id, rule);
		if (!rc)
			rc = sw_get_next_rule(table_id, rule, &rule, &filter);
	}

	if (rc == ENOENT)
		rc = 0;

	return rc;
}

int
sw_deactivate_table(int table_id)
{
	int			rc;
	int			rule;
	struct filter_entry	*filter;

	if ((table_id) < 1 || (table_id > BA_MAX_TABLES))
		return EINVAL;

	tables[table_id].active = 0;
	rc = sw_get_first_rule(table_id, &rule, &filter);
	while (rc == 0) {
		rc = sw_deactivate_rule(table_id, rule);
		if (rc != 0)
			printf("sw_deactivate_table: failed to deactivate rule\n");
		rc = sw_get_next_rule(table_id, rule, &rule, &filter);
	}

	if (rc == ENOENT)
		rc = 0;

	return rc;
}

int
sw_get_rule(int table, int rule, struct filter_entry ** ent)
{
	struct filter_entry	*fe;

	if ((table) < 1 || (table > BA_MAX_TABLES))
		return EINVAL;

	TAILQ_FOREACH(fe, &tables[table].filter_head, fe) {
		if (fe->rule == rule) {
			*ent = fe;
			return 0;
		}
	}

	return ENOENT;
}

int
sw_get_first_rule(int table, int *rule, struct filter_entry ** ent)
{
	struct filter_entry	*fe;

	if ((table) < 1 || (table > BA_MAX_TABLES))
		return EINVAL;

	fe = TAILQ_FIRST(&tables[table].filter_head);
	if (fe == NULL)
		return ENOENT;

	*ent = fe;
	*rule = fe->rule;

	return 0;
}

int
sw_get_next_rule(int table, int rule, int *next, struct filter_entry ** ent)
{
	struct filter_entry	*fe;

	if ((table) < 1 || (table > BA_MAX_TABLES))
		return EINVAL;

	TAILQ_FOREACH(fe, &tables[table].filter_head, fe) {
		if (fe->rule > rule) {
			*next = fe->rule;
			*ent = fe;
			return 0;
		}
	}

	return ENOENT;
}

int
sw_deactivate_rule(int table_id, int rule)
{
	int			rc = 0;
	struct filter_entry	*fe;
	struct ch_filter	*filter;
	struct ifreq		ifr;

	fe = sw_get_filter(table_id, rule);
	if (fe == NULL)
		return ENOENT;

	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, devname, sizeof(ifr.ifr_name));

	filter = &fe->filter;
	ifr.ifr_data = (void *)filter;
	filter->cmd = CHELSIO_DEL_FILTER;
	filter->filter_ver = CH_FILTER_SPECIFICATION_ID;

	rc = sw_ioctl(adap_fd, SIOCCHIOCTL, &ifr);
	if (rc != 0)
		printf("Failed to deactivate rule: %s\n", strerror(rc));

	return rc;
}

int
sw_activate_rule(int table_id, int rule)
{
	int			rc = 0;
	struct filter_entry	*fe;
	struct ch_filter	*filter;
	struct ifreq		ifr;

	fe = sw_get_filter(table_id, rule);
	if (fe == NULL)
		return ENOENT;

	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, devname, sizeof(ifr.ifr_name));

	filter = &fe->filter;
	ifr.ifr_data = (void *)filter;
	filter->cmd = CHELSIO_SET_FILTER;
	filter->filter_ver = CH_FILTER_SPECIFICATION_ID;

	rc = sw_ioctl(adap_fd, SIOCCHIOCTL, &ifr);
	if (rc != 0)
		printf("Failed to activate rule: %s\n", strerror(rc));

	return rc;
}

int
sw_ioctl(int adap_fd, int cmd, struct ifreq *ifr)
{
	int			rc;
	int			sleep_dur = 100;

	rc = ioctl(adap_fd, SIOCCHIOCTL, ifr);

	while ( (rc == -1) && (errno == EBUSY) && sleep_dur < 102400) {
		usleep(sleep_dur);
		rc = ioctl(adap_fd, SIOCCHIOCTL, ifr);
		sleep_dur *= 2;
	}

	return rc == -1 ? errno : 0;
}

char *
sw_get_iport(struct filter_entry *fe)
{
	static char		iport[10];

	if (fe->filter.fs.mask.iport != 0) 
		sprintf(iport, "%d", fe->filter.fs.val.iport);	
	else
		sprintf(iport, "*");	

	return iport;
}

void
sw_print_rule(struct filter_entry *fe)
{
	struct in_addr		in;
	char			*protostr = "any";
	struct ch_filter	*filter;
	int			rule;
	struct ch_filter_tuple	*val;
	struct ch_filter_tuple	*mask;
	int			cond;
	char			in6addr[128];

	cond = fe->cond;
	rule = fe->rule;
	filter = &fe->filter;
	val = &filter->fs.val;
	mask = &filter->fs.mask;

	printf("\t%d\t", rule);

	switch (filter->fs.action) {
		case ACL_ACTION_DROP:
			printf("DROP(%s) ", sw_get_iport(fe));
			break;
		case ACL_ACTION_REDIRECT:
			printf("FORWARD(%d) ", filter->fs.eport);
	
			break;
		case ACL_ACTION_INPUT:
			printf("INPUT(%s) ", sw_get_iport(fe));
			break;
	}
	printf("\t");

	if (cond & ACL_MATCH_IPV6) {
		printf("ipv6 ");
	}

	if (cond & ACL_MATCH_VLAN) {
		printf("vlan %d ", val->ivlan);
	}

	if (cond & ACL_MATCH_ETHERTYPE) {
		printf("etype 0x%4.4x ", val->ethtype);
	}

	if (cond & ACL_MATCH_SRC_IP) {
		in.s_addr = *(int *)val->fip;
		printf("srcaddr %s", inet_ntoa(in));
		in.s_addr = *(int*)mask->fip;
		printf("/%s ", inet_ntoa(in));
	}

	if (cond & ACL_MATCH_DST_IP) {
		in.s_addr = *(int *)val->lip;
		printf("dstaddr %s", inet_ntoa(in));
		in.s_addr = *(int *)mask->lip;
		printf("/%s ", inet_ntoa(in));
	}

	if (cond & ACL_MATCH_SRC_IP6) {
		inet_ntop(AF_INET6, val->fip, in6addr, sizeof(in6addr));
		printf("srcaddr %s", in6addr);
		if (inet_ntop(AF_INET6, mask->fip, in6addr, sizeof(in6addr)) == NULL)
printf("inet_ntop failed, errno = %d\n", errno);
		printf("/%s ", in6addr);
	}

	if (cond & ACL_MATCH_DST_IP6) {
		inet_ntop(AF_INET6, val->lip, in6addr, sizeof(in6addr));
		printf("dstaddr %s", in6addr);
		inet_ntop(AF_INET6, mask->lip, in6addr, sizeof(in6addr));
		printf("/%s ", in6addr);
	}

	if (cond & ACL_MATCH_SRC_PORT) {
		printf("srcport %d", val->fport);
		printf("/%x ", mask->fport);
	}

	if (cond & ACL_MATCH_DST_PORT) {
		printf("dstport %d", val->lport);
		printf("/%x ", mask->lport);
	}

	if (cond & ACL_MATCH_PROTOCOL) {
		if (val->proto == 1)
			protostr = PROTO_ICMP;
		else if (val->proto == 17)
			protostr = PROTO_UDP;
		else if (val->proto == 6)
			protostr = PROTO_TCP;
		else if (val->proto == 58)
			protostr = PROTO_ICMP6;
		else
			protostr = PROTO_ANY;
		printf("proto %s ", protostr);
	}

	printf("\n");

	return;
}

int
sw_list_rules()
{
	int   			rc;
	int      		table;
	int      		rule;
	struct filter_entry	*filter;

	printf("table\t\tindex\taction     \tkeys\n");
	printf("----------\t-----\t--------\t----------\n");

	rc = sw_get_first_table(&table);
	while (rc == 0) {
		if (sw_table_active(table)) 
			printf("%d (active):", table);
		else
			printf("%d (inactive):", table);

		if (rc != 0)
			printf("\n");

		rc = sw_get_first_rule(table, &rule, &filter);
		while (rc == 0) {
			sw_print_rule(filter);
			printf("\t");
			rc = sw_get_next_rule(table, rule, &rule, &filter);
		}
		printf("\n");

		rc = sw_get_next_table(table, &table);
	}

	return 0;
}

/*
 * parse the options entered on the command line into a filter
 */
int
sw_parse_opts(u_int options_set, char *options_val[],
	      struct filter_entry *filter)
{
	int			redirect_port = -1;
	struct ch_filter	new_filter;
	struct ch_filter_tuple	*val;
	struct ch_filter_tuple	*mask;
	u_int			*cond;
	int 			iport = 0;
	int 			imask = 0;
	int			rc;
	int			ipv6 = 0;

	new_filter = filter->filter;
	val = &new_filter.fs.val;
	mask = &new_filter.fs.mask;
	cond = &filter->cond;

	if (options_set & (1 << BA_OPT_ADDUPD_IPV6)) {
		if (!ba_ipv6) {
			printf("bypass server not started with IPv6 option\n");
			return -1;
		}

		if ( (options_set & (1 << BA_OPT_ADDUPD_SRCADDR)) ||
				(options_set & (1 << BA_OPT_ADDUPD_SRCMASK)) ||
				(options_set & (1 << BA_OPT_ADDUPD_DSTADDR)) ||
				(options_set & (1 << BA_OPT_ADDUPD_DSTMASK)) ) {
			printf("cannot specify IPv4 options with IPv6 set\n");
			return -1;
		}

		ipv6 = 1;
		*cond |= ACL_MATCH_IPV6;
	} else {
		if ( (options_set & (1 << BA_OPT_ADDUPD_SRCADDR6)) ||
				(options_set & (1 << BA_OPT_ADDUPD_SRCMASK6)) ||
				(options_set & (1 << BA_OPT_ADDUPD_DSTADDR6)) ||
				(options_set & (1 << BA_OPT_ADDUPD_DSTMASK6)) ){
			printf("cannot specify IPv6 options without IPv6 set\n");
			return -1;
		}

	}

	if (options_set & (1 << BA_OPT_ADDUPD_PROTO)) {
		char * proto = options_val[BA_OPT_ADDUPD_PROTO];

		*cond |= ACL_MATCH_PROTOCOL;
		mask->proto = 0xff;
		if (strcmp(proto, PROTO_ICMP) == 0 || strcmp(proto, "1") == 0)
			val->proto = 1;
		else if (strcmp(proto, PROTO_UDP) == 0 || strcmp(proto, "17") == 0)
			val->proto = 17;
		else if (strcmp(proto, PROTO_TCP) == 0 || strcmp(proto, "6") == 0)
			val->proto = 6;
		else if (strcmp(proto, PROTO_ICMP6) == 0 || strcmp(proto, "58") == 0){
			if (!ba_ipv6) {
				printf("icmp6 protocol specified, but bypass server not started with IPv6 option\n");
                        	return -1;
                	}
			val->proto = 58;
		}
		else if (strcmp(proto, PROTO_ANY) == 0) {
			val->proto = 0x00;
			mask->proto = 0x00;
		} else {
			printf("invalid protocol (%s) specified\n", proto);
			return -1;
		}
	}

	if (options_set & (1 << BA_OPT_ADDUPD_SRCADDR)) {
		struct hostent *h;
		char * src = options_val[BA_OPT_ADDUPD_SRCADDR];

		h = gethostbyname(src);
		if (h == NULL) {
			printf("invalid srcaddr (%s) specified\n", src);
			return -1;
		}

		*cond |= ACL_MATCH_SRC_IP;
		bcopy(h->h_addr, &val->fip[0], 4);
		*(u_int *)&mask->fip = INADDR_BROADCAST;
	}

	if (options_set & (1 << BA_OPT_ADDUPD_SRCMASK)) {
		struct hostent *h;
		char * srcmask = options_val[BA_OPT_ADDUPD_SRCMASK];

		h = gethostbyname(srcmask);
		if (h == NULL) {
			printf("invalid srcmask (%s) specified\n", srcmask);
			return -1;
		}

		*cond |= ACL_MATCH_SRC_IP;
		bcopy(h->h_addr, &mask->fip[0], 4);
	}

	if (options_set & (1 << BA_OPT_ADDUPD_SRCPORT)) {
		int	port;

		port = strtol(options_val[BA_OPT_ADDUPD_SRCPORT], NULL, 10);

		*cond |= ACL_MATCH_SRC_PORT;
		val->fport = port;
		mask->fport = 0xffff;
	}

	if (options_set & (1 << BA_OPT_ADDUPD_SRCPORTMASK)) {
		int	sm;

		sm = strtol(options_val[BA_OPT_ADDUPD_SRCPORTMASK], NULL, 0);

		mask->fport = sm;
	}

	if (options_set & (1 << BA_OPT_ADDUPD_DSTADDR)) {
		struct hostent *h;
		char * dst = options_val[BA_OPT_ADDUPD_DSTADDR];

		h = gethostbyname(dst);
		if (h == NULL) {
			printf("invalid dstaddr (%s) specified\n", dst);
			return -1;
		}

		*cond |= ACL_MATCH_DST_IP;
		bcopy(h->h_addr, &val->lip[0], 4);
		*(u_int *)(&mask->lip[0]) = INADDR_BROADCAST;
	}


	if (options_set & (1 << BA_OPT_ADDUPD_DSTMASK)) {
		struct hostent *h;
		char * dstmask = options_val[BA_OPT_ADDUPD_DSTMASK];

		h = gethostbyname(dstmask);
		if (h == NULL) {
			printf("invalid dstmask (%s) specified\n", dstmask);
			return -1;
		}

		*cond |= ACL_MATCH_DST_IP;
		bcopy(h->h_addr, &mask->lip[0], 4);
	}

	if (options_set & (1 << BA_OPT_ADDUPD_DSTPORT)) {
		int	port;

		port = strtol(options_val[BA_OPT_ADDUPD_DSTPORT], NULL, 10);

		*cond |= ACL_MATCH_DST_PORT;
		val->lport = port;
		mask->lport = 0xffff;
	}

	if (options_set & (1 << BA_OPT_ADDUPD_DSTPORTMASK)) {
		int	dm;

		dm = strtol(options_val[BA_OPT_ADDUPD_DSTPORTMASK], NULL, 0);

		mask->lport = dm;
	}


	if (options_set & (1 << BA_OPT_ADDUPD_VLAN)) {
		int vlan;

		vlan = strtol(options_val[BA_OPT_ADDUPD_VLAN], NULL, 10);
		if ( (vlan < 0) || (vlan > 4095) ) {
			printf("vlan must be in the range 0-4095\n");
			return -1;
		}

		*cond |= ACL_MATCH_VLAN;
		val->ivlan = vlan;
		mask->ivlan = 0xfff;
		val->ivlan_vld = 1;
		mask->ivlan_vld = 1;
	}

	if (options_set & (1 << BA_OPT_ADDUPD_PORT)) {
		char * port = options_val[BA_OPT_ADDUPD_PORT];

		redirect_port = ba_get_port(port);
		if (redirect_port == -1) {
			printf("invalid port (%s) specified\n", port);
			return -1;
		}
	}
	
	if (options_set & (1 << BA_OPT_ADDUPD_ETYPE)) {
		int	ethertype;

		ethertype = ba_convert_to_int(options_val[BA_OPT_ADDUPD_ETYPE],
					      "ethertype");
		if (ethertype == -1)
			return -1;

		*cond |= ACL_MATCH_ETHERTYPE;
		val->ethtype = ethertype & 0xffff;
		mask->ethtype = 0xffff;
	}

	if (options_set & (1 << BA_OPT_ADDUPD_SRCADDR6)) {
		char * src = options_val[BA_OPT_ADDUPD_SRCADDR6];

		if (!ba_ipv6) {
			printf("bypass server not started with IPv6 option\n");
			return -1;
		}

		rc = inet_pton(AF_INET6, src, &val->fip);
		if (rc <= 0) {
			printf("invalid srcaddr6 (%s) specified\n", src);
			return -1;
		}

		*cond |= ACL_MATCH_SRC_IP6;
		bcopy(&in6_all_bits, &mask->fip, 16);
	}

	if (options_set & (1 << BA_OPT_ADDUPD_SRCMASK6)) {
		char * srcmask = options_val[BA_OPT_ADDUPD_SRCMASK6];

		if (!ba_ipv6) {
			printf("bypass server not started with IPv6 option\n");
			return -1;
		}

		rc = inet_pton(AF_INET6, srcmask, &mask->fip[0]);
		if (rc <= 0) {
			printf("invalid srcmask6 (%s) specified\n", srcmask);
			return -1;
		}

		*cond |= ACL_MATCH_SRC_IP6;
	}

	if (options_set & (1 << BA_OPT_ADDUPD_DSTADDR6)) {
		char * dst = options_val[BA_OPT_ADDUPD_DSTADDR6];

		if (!ba_ipv6) {
			printf("bypass server not started with IPv6 option\n");
			return -1;
		}

		rc = inet_pton(AF_INET6, dst, &val->lip);
		if (rc <= 0) {
			printf("invalid dstaddr6 (%s) specified\n", dst);
			return -1;
		}

		*cond |= ACL_MATCH_DST_IP6;
		bcopy(&in6_all_bits, &mask->lip, 16);
	}

	if (options_set & (1 << BA_OPT_ADDUPD_DSTMASK6)) {
		char * dstmask = options_val[BA_OPT_ADDUPD_DSTMASK6];

		if (!ba_ipv6) {
			printf("bypass server not started with IPv6 option\n");
			return -1;
		}

		rc = inet_pton(AF_INET6, dstmask, &mask->lip[0]);
		if (rc <= 0) {
			printf("invalid dstmask6 (%s) specified\n", dstmask);
			return -1;
		}

		*cond |= ACL_MATCH_DST_IP6;
	}

	if (options_set & (1 << BA_OPT_ADDUPD_ACTION)) {
		char * act;

		act = options_val[BA_OPT_ADDUPD_ACTION];
		if (strcmp(act, ACTION_DROP) == 0) {
			new_filter.fs.action = ACL_ACTION_DROP;
			if (redirect_port != -1) {
				iport = redirect_port;
				imask = 0x7;
			}
		} else if (strcmp(act, ACTION_INPUT) == 0) {
			new_filter.fs.action = ACL_ACTION_INPUT;
			if (redirect_port != -1) {
				iport = redirect_port;
				imask = 0x7;
			}
		} else if (strcmp(act, ACTION_FORWARD) == 0) {
			if (redirect_port == -1) {
				printf("Error: redirect port not specified\n");
				return -1;
			}
			new_filter.fs.action = ACL_ACTION_REDIRECT;
			new_filter.fs.eport = redirect_port;
		} else {
			printf("invalid action (%s) specified\n", act);
			return -1;
		}
	}

	new_filter.fs.val.iport = iport;
	new_filter.fs.mask.iport = imask;
	new_filter.fs.type = ipv6;

	/* count the filter hits */
	new_filter.fs.hitcnts = 1;

	filter->filter = new_filter;

	return 0;
}

/*
 * add a filter rule to the specified table.
 */
int
sw_add_rule(u_int options_set, char *options_val[])
{
	int			rc = 0;
	struct filter_entry	*filter;
	int			table = BA_DEFAULT_TABLE;
	int			rule = BA_DEFAULT_RULE;

	if (options_set & (1 << BA_OPT_ADDUPD_TABLE)) {
		table = strtol(options_val[BA_OPT_ADDUPD_TABLE], NULL, 10);
	}

	if (sw_get_table(table) != 0) {
		printf("Invalid table id\n");
		return EINVAL;
	}

	if (options_set & (1 << BA_OPT_ADDUPD_INDEX)) {
		rule = strtol(options_val[BA_OPT_ADDUPD_INDEX], NULL, 10);
		if ( (rule <= 0) || (rule > max_acl_rules) ) {
			printf("Invalid rule id\n");
			return EINVAL;
		}
	} else {
		rule = sw_get_last_rule(table) + ba_rule_increment;
	}

	if (rule <= 0) {
		printf("Error: rule id must be positive\n");
		return EINVAL;
	}

	if (rule > max_acl_rules) {
		printf("Error: rule index %d is greater than maximum (%d)\n",
			rule, max_acl_rules);
		return EINVAL;
	}

	if (sw_get_filter(table, rule) != NULL) {
		printf("Rule %d in table %d already exists.\n", rule, table);
		return EEXIST;
	}

	filter = sw_alloc_filter();
	filter->rule = rule;

	rc = sw_parse_opts(options_set, options_val, filter);
	if (rc != 0)
		return rc;

	rc = sw_add_filter(table, rule, filter);

	if (rc == 0) {
		if (!sw_table_active(table)) 
			printf("info: table must be activated for this rule to be active\n");
		else {
			rc = sw_activate_rule(table, rule);
			if (rc == 0)
				printf("Rule applied to active table\n");
			else
				sw_delete_filter(table, filter);
		}
	}

	return rc;
}

int
sw_update_rule(int rule, int table, u_int options_set, char *options_val[])
{
	int			rc = 0;
	struct filter_entry	*fe;
	struct filter_entry	*fe_new;

	/* get the existing rule */
	fe = sw_get_filter(table, rule);
	if (fe == NULL) {
		printf("Rule %d does not exist in table %d\n", rule, table);
		return ENOENT;
	}

	/* allocate new filter */
	fe_new = sw_alloc_filter();
	if (fe_new == NULL)
		return ENOMEM;

	/* add in the update */
	rc = sw_parse_opts(options_set, options_val, fe_new);
	if (rc != 0)
		return rc;

	/* remove the existing rule */
	sw_delete_filter(table, fe);

	/* add the new updated rule */
	rc = sw_add_filter(table, rule, fe_new);

	if (rc == 0) {
		if (!sw_table_active(table)) 
			printf("info: table must be activated for this updated rule to be active\n");
		else {
			rc = sw_activate_rule(table, rule);
			if (rc == 0)
				printf("Rule updated to active table\n");
			else
				sw_delete_filter(table,fe);
		}
	}

	return rc;
}

int
sw_delete_rule(int table, int rule)
{
	int			rc;
	struct filter_entry	*filter;

	/* get the existing rule */
	filter = sw_get_filter(table, rule);
	if (filter == NULL)
		return ENOENT;

	rc = sw_delete_filter(table, filter);
	if (rc != 0)
		return rc;

	if (sw_table_active(table))  {
		printf("Rule deleted from active table\n");
	} else
		printf("info: Rule deleted from inactive table\n");

	return rc;
}

int
sw_purge_rules(int table)
{
	int			rc;
	int			rule;
	struct filter_entry 	*filter;

	rc = sw_get_first_rule(table, &rule, &filter);

	while (rc == 0) {
		rc = sw_delete_rule(table, rule);
	
		rc = sw_get_first_rule(table, &rule, &filter);
	}

	return 0;
}

int
sw_move_rule(int table, int old_rule, int new_rule)
{
	int			rc = 0;
	struct filter_entry 	*filter;
	struct filter_entry 	*new_filter;

	if ( (new_rule <= 0) || (new_rule > max_acl_rules) ) {
		printf("Invalid new rule id\n");
		return EINVAL;
	}
	
	/* get the new rule */
	rc = sw_get_rule(table, new_rule, &filter);
	if (rc == 0) {
		printf("Error: New rule id %d exists\n", new_rule);
		return -1;
	}

	/* get the old rule */
	rc = sw_get_rule(table, old_rule, &filter);
	if (rc != 0) {
		printf("Error: Old rule id %d does not exist\n", old_rule);
		return rc;
	}

	new_filter = sw_alloc_filter();
	if (new_filter == NULL)
		return ENOMEM;

	*new_filter = *filter;

	/* add the new rule */
	rc = sw_add_filter(table, new_rule, new_filter);
	if (rc != 0) {
		printf("unable to add rule id %d\n", new_rule);
		return rc;
	}

	/* remove the existing rule */
	rc = sw_delete_filter(table, filter);
	if (rc != 0) {
		printf("Old rule id %d could not be removed\n", old_rule);
		return rc;
	}

	if (!sw_table_active(table)) 
		printf("info: table must be activated for this moved rule to take effect\n");
	else {
		rc = sw_activate_rule(table, new_rule);
		if (rc == 0)
			printf("Rule moved in active table\n");
	}

	return rc;
}

int
sw_match_rule(int table, u_int options_set, char *options_val[])
{
	int			rc = 0;
	struct filter_entry	*filter;
	struct filter_entry	tgt_filter;
	int			rule;

	bzero(&tgt_filter, sizeof(tgt_filter));

	bzero(&filter, sizeof(filter));

	/* parse the rule into a filter */
	rc = sw_parse_opts(options_set, options_val, &tgt_filter);
	if (rc != 0)
		return rc;

	rc = sw_get_first_rule(table, &rule, &filter);

	/* look through all the rules for a match */
	while (rc == 0) {
		tgt_filter.filter.filter_id = sw_get_filter_id(table, rule);
		tgt_filter.filter.cmd = filter->filter.cmd;
		if (bcmp(&tgt_filter.filter, &filter->filter,
		      sizeof(tgt_filter.filter)) == 0) {
			return(rule);
		}

		rc = sw_get_next_rule(table, rule, &rule, &filter);
	}
	
	return -1;
}

int
validate_rule_table(int rule, int table)
{
	int			rc;
	struct filter_entry 	*filter;

	rc = sw_get_table(table);
	if (rc != 0) {
		printf("Table id %d is not a valid table\n", table);
		return rc;
	}

	rc = sw_get_rule(table, rule, &filter);
	if (rc != 0) {
		printf("Index %d is not a valid rule\n", rule);
		return rc;
	}

	return 0;
}

int
sw_count_rule(int rule, int table)
{
	int			rc;
	long long		cnt;

	rc = validate_rule_table(rule, table);
	if (rc != 0)
		return rc;

	if (!sw_table_active(table)) {
		printf("Table must be active to retrieve count\n");
		return -1;
	}

	rc = sw_get_count(table, rule, &cnt);
	if (rc == 0)
		printf("%lld packets\n", cnt);
	else
		printf("table could not get rule count - error %d\n", rc);

// #define DEBUG
#ifdef DEBUG
	cnt = 0;
	rc = sw_get_filter_count(table, 501, &cnt);
	printf("filter 501 count %lld\n", cnt);
	rc = sw_get_filter_count(table, 502, &cnt);
	printf("filter 502 count %lld\n", cnt);
	rc = sw_get_filter_count(table, 503, &cnt);
	printf("filter 503 count %lld\n", cnt);
	rc = sw_get_filter_count(table, 504, &cnt);
	printf("filter 504 count %lld\n", cnt);
#endif

	return rc;
}

int
getmasklen(u_int mask)
{
	int		len = 0;
	int		i;

	for  (i = 0; (mask & (1 << (31-i))) && (i < 32); i++) {
		len++;
	} 
		
	return len;
}

/*
 * Dump the current state in command format that is suitable for replaying.
 */
void
sw_dump_cmd(int table, int rule, struct filter_entry *fe)
{
	struct in_addr		in;
	char			*protostr = "any";
	struct ch_filter	*filter;
	struct ch_filter_tuple	*val;
	struct ch_filter_tuple	*mask;
	u_int			cond;
	char			in6addr[128];

	cond = fe->cond;
	filter = &fe->filter;
	val = &filter->fs.val;
	mask = &filter->fs.mask;

	printf("redirect %s add --table %d --index %d ", devname, table, rule);

	if (cond & ACL_MATCH_IPV6) {
		printf("--ipv6 ");
	}

	if (cond & ACL_MATCH_VLAN) {
		printf("--vlan %d ", val->ivlan);
	}

	if (cond & ACL_MATCH_ETHERTYPE) {
		printf("--ethertype 0x%4.4x ", val->ethtype);
	}

	if (cond & ACL_MATCH_SRC_IP) {
		in.s_addr = *(int *)val->fip;
		printf("--srcaddr %s ", inet_ntoa(in));
		in.s_addr = *(int *)mask->fip;
		printf("--srcmask %s ", inet_ntoa(in));
	}

	if (cond & ACL_MATCH_DST_IP) {
		in.s_addr = *(int *)val->lip;
		printf("--dstaddr %s ", inet_ntoa(in));
		in.s_addr = *(int *)mask->lip;
		printf("--dstmask %s ", inet_ntoa(in));
	}

	if (cond & ACL_MATCH_SRC_IP6) {
		inet_ntop(AF_INET6, val->fip, in6addr, sizeof(in6addr));
		printf("--srcaddr6 %s ", in6addr);
		inet_ntop(AF_INET6, mask->fip, in6addr, sizeof(in6addr));
		printf("--srcmask6 %s ", in6addr);
	}

	if (cond & ACL_MATCH_DST_IP6) {
		inet_ntop(AF_INET6, val->lip, in6addr, sizeof(in6addr));
		printf("--dstaddr6 %s ", in6addr);
		inet_ntop(AF_INET6, mask->lip, in6addr, sizeof(in6addr));
		printf("--dstmask6 %s ", in6addr);
	}

	if (cond & ACL_MATCH_SRC_PORT) {
		printf("--srcport %d ", val->fport);
		printf("--srcportmask %x ", mask->fport);
	}

	if (cond & ACL_MATCH_DST_PORT) {
		printf("--dstport %d ", val->lport);
		printf("--dstportmask %x ", mask->lport);
	}

	if (cond & ACL_MATCH_PROTOCOL) {
		if (val->proto == 1)
			protostr = PROTO_ICMP;
		else if (val->proto == 17)
			protostr = PROTO_UDP;
		else if (val->proto == 6)
			protostr = PROTO_TCP;
		else if (val->proto == 58)
			protostr = PROTO_ICMP6;
		else
			protostr = PROTO_ANY;
		printf("--proto %s ", protostr);
	}

	switch (filter->fs.action) {
		case ACL_ACTION_DROP:
			printf("--action drop ");
			if (mask->iport != 0) 
				printf("--port %d ", val->iport);	
			break;
		case ACL_ACTION_INPUT:
			printf("--action input ");
			if (mask->iport != 0) 
				printf("--port %d ", val->iport);	
			break;
		case ACL_ACTION_REDIRECT:
			printf("--action forward --port %d ", filter->fs.eport);
			break;
	}
	printf("\n");

	return;
}

int
sw_dump_tables(void)
{
	int			rc = 0;
	int      		table;
	int      		rule;
	struct filter_entry	*filter;
	int			active;

	rc = sw_get_first_table(&table);
	while (rc == 0) {

		printf("############ Table Number %d  #############\n", table);
		printf("redirect %s create_table --table %d\n", devname, table);

		if (sw_table_active(table)) 
			active = 1;
		else
			active = 0;

		rc = sw_get_first_rule(table, &rule, &filter);

		while (rc == 0) {
			sw_dump_cmd(table, rule, filter);
			rc = sw_get_next_rule(table, rule, &rule, &filter);
		}

		if (active == 1)
			printf("redirect %s activate_table --table %d\n",
				devname, table);

		printf("\n");
		rc = sw_get_next_table(table, &table);
	}

	return 0;
}

int
sw_get_last_rule(int table)
{
	int			rc;
	int			ret_rule = 0;
	int			rule;
	struct filter_entry	*filter;

	if ((table) < 1 || (table > BA_MAX_TABLES))
		return -1;

	rc = sw_get_first_rule(table, &rule, &filter);

	while (rc == 0) {
		if (rule > ret_rule)
			ret_rule = rule;
		rc = sw_get_next_rule(table, rule, &rule, &filter);
	}

	return ret_rule;
}

int
sw_table_active(int table)
{
	if ((table) < 1 || (table > BA_MAX_TABLES))
		return 0;

	if (tables[table].inuse != 1)
		return 0;

	if (tables[table].active != 1)
		return 0;

	return 1;
}

	
int
sw_get_count(int table, int rule, long long *cnt)
{
	int			rc;
	struct ifreq		ifr;
	struct ch_filter_count	count;

	bzero(&ifr, sizeof(ifr));
	ifr.ifr_data = (void *)&count;
	strncpy(ifr.ifr_name, devname, sizeof(ifr.ifr_name));

	count.filter_id = sw_get_filter_id(table, rule);
	count.cmd = CHELSIO_GET_FILTER_COUNT;
	rc = sw_ioctl(adap_fd, SIOCCHIOCTL, &ifr);
	if (rc != 0)
		return rc;

	*cnt = count.pkt_count;

	return 0;
}

int
sw_get_filter_count(int table, int filter, long long *cnt)
{
	int			rc;
	struct ifreq		ifr;
	struct ch_filter_count	count;

	bzero(&ifr, sizeof(ifr));
	ifr.ifr_data = (void *)&count;
	strncpy(ifr.ifr_name, devname, sizeof(ifr.ifr_name));

	count.filter_id = filter;
	count.cmd = CHELSIO_GET_FILTER_COUNT;
	rc = sw_ioctl(adap_fd, SIOCCHIOCTL, &ifr);
	if (rc != 0)
		return rc;

	*cnt = count.pkt_count;

	return 0;
}
