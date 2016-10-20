#ifndef __ISCSI_TCP_H__
#define __ISCSI_TCP_H__

#ifndef memcmp
extern int memcmp(const void *s1, const void *s2, unsigned long n);
#endif
extern int sprintf(char *str, const char *format, ...);

/**
 * tcp 4tuples
 **/
/* ipv6 string[xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx] */
#define ISCSI_IPV6_ADDR_STR_MAXLEN	41
/* ipv4 string xxx.xxx.xxx.xxx				*/
#define ISCSI_IPV4_ADDR_STR_MAXLEN	15

#define ISCSI_IPADDR_LEN		16
#define ISCSI_IPADDR_IPV4_OFFSET	12

typedef struct tcp_endpoint	tcp_endpoint;
struct tcp_endpoint {
	unsigned char ip[ISCSI_IPADDR_LEN];
	unsigned int port;
};

#define ipaddr_mark_as_ipv4(ip)	\
	do { \
		memset(ip, 0, sizeof(char) * 16); \
		*(((unsigned char *)ip) + 10) = 0xFF; \
		*(((unsigned char *)ip) + 11) = 0xFF; \
	} while (0)


typedef struct chiscsi_tcp_endpoints	chiscsi_tcp_endpoints;
struct chiscsi_tcp_endpoints {
	unsigned int f_ipv6:1;
	unsigned int f_filler:31;
	struct tcp_endpoint iaddr;	/* initiator tcp address */
	struct tcp_endpoint taddr;	/* target tcp address */
	unsigned int port_id;	/* for Chelsio HBA only */
};

static inline int tcp_endpoint_is_ipv6(struct tcp_endpoint *ep)
{
	/* ipv4 addresses are stored as ipv4-mapped ipv6 addresses ::ffff:0:0/96 */
	static char zero[ISCSI_IPADDR_IPV4_OFFSET] = { 0 };
	zero[10] = 0xFF; zero[11] = 0xFF;
	return !!memcmp(ep->ip, zero, ISCSI_IPADDR_IPV4_OFFSET);
}

static inline int tcp_endpoint_sprintf(struct tcp_endpoint *ep, char *buf)
{
	int len;

	if (tcp_endpoint_is_ipv6(ep))
		len = sprintf(buf,
			"[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
			"%02x%02x:%02x%02x:%02x%02x]",
			ep->ip[0], ep->ip[1], ep->ip[2], ep->ip[3],
			ep->ip[4], ep->ip[5], ep->ip[6], ep->ip[7],
			ep->ip[8], ep->ip[9], ep->ip[10], ep->ip[11],
			ep->ip[12], ep->ip[13], ep->ip[14], ep->ip[15]);
	else
		len = sprintf(buf, "%u.%u.%u.%u",
			ep->ip[12], ep->ip[13], ep->ip[14], ep->ip[15]);
	if (ep->port)
		len += sprintf(buf + len, ":%u", ep->port);
	buf[len] = '\0';

	return len;
}

static inline int chiscsi_tcp_endpoints_sprintf(struct chiscsi_tcp_endpoints *iep,
					char *buf)
{
	int len;

	len = tcp_endpoint_sprintf(&iep->iaddr, buf);
	len += sprintf(buf + len, " - ");
	len += tcp_endpoint_sprintf(&iep->taddr, buf + len);

	return len;
}
#endif
