#ifndef __IFACE_STRUTIL_H__
#define __IFACE_STRUTIL_H__

#ifndef NULL
#define NULL    ((void *)0)
#endif

#define api_isdigit(c)		((c) >= '0' && (c) <= '9')
#define api_isspace(c)		((c) == ' ')
#define api_isxdigit(c)		((((c) >= '0') && ((c) <= '9')) || \
                          	(((c) >= 'A') && ((c) <= 'F')) || \
                          	(((c) >= 'a') && ((c) <= 'f')))

static inline void tcp_endpoint_print(struct tcp_endpoint *ep)
{
	if(tcp_endpoint_is_ipv6(ep))
		printk("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
			"%02x%02x:%02x%02x:%02x%02x",
			ep->ip[0], ep->ip[1], ep->ip[2], ep->ip[3],
			ep->ip[4], ep->ip[5], ep->ip[6], ep->ip[7],
			ep->ip[8], ep->ip[9], ep->ip[10], ep->ip[11],
			ep->ip[12], ep->ip[13], ep->ip[14], ep->ip[15]);
	else
		printk("%u.%u.%u.%u", ep->ip[12], ep->ip[13], ep->ip[14], ep->ip[15]);

	if (ep->port)
		printk(":%u", ep->port);
}

static inline void chiscsi_tcp_endpoints_print(struct chiscsi_tcp_endpoints *iep)
{
        tcp_endpoint_print(&iep->iaddr);
        printk( " - ");
        tcp_endpoint_print(&iep->taddr);
}

static inline unsigned int api_strlen(const char *s)
{
        const char *sc;
        if (!s)
                return 0;
        for (sc = s; *sc; ++sc) ;
        return sc - s;
}

static inline char *api_strstr(const char *s1, const char *s2)
{
        int     l1, l2;

        if (!s1)
                return NULL;
        if (!s2)
                return (char *) s1;

        l2 = api_strlen(s2);
        if (!l2)
                return (char *) s1;

        l1 = api_strlen(s1);
        while (l1 >= l2) {
                l1--;
                if (!memcmp(s1, s2, l2))
                        return (char *) s1;
                s1++;
        }
        return NULL;
}

static inline char *api_strchr(const char *s, int c)
{
        if (!s)
                return NULL;
        for (; *s != (char) c; ++s)
                if (*s == '\0')
                        return NULL;
        return (char *) s;
}
#endif /*ifndef __IFACE_STRUTIL_H__ */
