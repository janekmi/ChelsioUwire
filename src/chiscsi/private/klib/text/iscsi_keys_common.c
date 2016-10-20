/*
 * iscsi_keys_common.c
 * common decode/encode/size/compute functions for iscsi key-values
 */
#include <linux/version.h>
#include <linux/inet.h>
#include <iscsi_structs.h>
#include "iscsi_text_private.h"

/* 
 * common iscsi text strings
 */
#define ISCSI_KEY_REJECT_STR		"Reject"
#define ISCSI_KEY_NOTUNDERSTOOD_STR	"NotUnderstood"
#define ISCSI_KEY_IRRELEVANT_STR	"Irrelevant"

#define ISCSI_KEY_YES_STR		"Yes"
#define ISCSI_KEY_NO_STR		"No"

/*
 * utility function
 * NOTE: input string should be terminated with a NULL character
 */

/* IPV4 only */
int iscsi_string_to_ipv4(char *str, unsigned int *ip, char *ebuf)
{
	int     i = 2;
	unsigned int val[4], addr = 0;
	char   *ipstr;
	int found_char = 0;

	/* make sure the ip str is in xxx.xxx.xxx.xxx format */
	i = 0;
	for (ipstr = str; *ipstr; ipstr++) {
		/*make sure that each non dot char is a digit*/
		if (*ipstr == '.') {
			i++;
			/* we should not have double dots either*/
			if (*(ipstr+1) == '.')
				found_char++;
		} else if (!os_isdigit(*ipstr) && (*ipstr != ',') && (*ipstr != ';'))
			found_char++;
	}
		
	//os_log_info("ERR! %d: Found Char is %d  i is %d.\n", str,found_char,i);
	if (i != 3 || found_char) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"ERR! %s: invalid IP address format.\n", str);
		os_log_info("ERR! %s: invalid IP address format.\n", str);
		return -ISCSI_EFORMAT;
	}

	val[0] = os_strtoul(str, NULL, 0);
	ipstr = str;
	i = 1;
	while ((ipstr = os_strchr(ipstr, '.')) && *(++ipstr) != '\0') {
		val[i] = os_strtoul(ipstr, NULL, 0);
		i++;
	}
	/* here, we set the ip address in little-endia order */
	for (i = 0; i < 4; i++)
		addr |= val[i] << (i * 8);

	if (!addr) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"ERR! %s: all zero IP address.\n", str);
		os_log_info("ERR! %s: all zero IP address.\n", str);
		return -ISCSI_EZERO;
	}
	/* convert the ip address to host order */
	*ip = os_le32_to_host(addr);
	return 0;
}


int iscsi_string_is_address_ipv6(char * str) {

        int count=0;
	char *addr;

        for (addr = str; *addr; addr++) {
                if (*addr == ':')
                        count++;
                else if (*addr == ']' || *addr == ',')
                        break;
        }
        return (count ? count-1 : count);
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19))
int iscsi_string_to_ipv6(char *str,
	    unsigned int *ip, char *ebuf, int ipv6_expand) {

	int i = 0, j = 0;
	unsigned int val[16];//,ip[4];
	char *ipstr;
	int found_char = 0;
	int expand_char = 0;

        /* make sure the ip str is in xxxx:xx..xx:xxxx, [xxxx:x...x:xxxx]:xxxx or xxxx::xxxx format */
        
        for (ipstr = str; *ipstr; ipstr++) {
                /*make sure that each non colon or bracket char is a digit*/
                if (*ipstr == ':') {
			if (!j)	
	                        i++;
			else	j++;
			if (*(ipstr+1) == ':')
				expand_char++;
		} else if (!os_isxdigit(*ipstr) && (*ipstr != ',') && (*ipstr != '[') && (*ipstr != ']'))
                        found_char++;
		if (*ipstr == ']')
			j = 1;
        }

        if (i > 7 || j > 2 || found_char || expand_char > 1) {
                if (ebuf)
                        sprintf(ebuf + os_strlen(ebuf),
                                "ERR! %s: invalid IPv6 address format.\n", str);
                os_log_info("ERR! %s : invalid IPv6 address format.\n", str);
                return -ISCSI_EFORMAT;
        }
	
	ipstr = str;
	i = 0;
	j = 1;
        if( *ipstr == '[')                        //expect a port
                ipstr++;
        if( *ipstr == ':') {                      //for loopback
                val[i] = val[i+1] = 0;
                i += 2;
        }

        for(; *ipstr && *ipstr != ']'; ipstr++) {
                if(j) {
                        val[i] = os_strtoul(ipstr, NULL, 16);
                        val[i+1] = val[i] & 0xFF;
                        val[i] = val[i] >> 8;
                        i += 2;
                        j = 0;
                }

                if( *ipstr == ':') {
                        if( *(ipstr+1) == ':') {
                                while ( ipv6_expand--) {
                                        val[i] = val[i+1] = 0;
                                        i += 2;
                                }
                                ipstr++;
                        }
                        j=1;
                }
        }

        for(i = 0; i < 4; i++)
                for(j = 0; j < 4; j++) {
                        ip[i] |= val[i * 4 + j] << (j * 8);
                }
	
        if (!(ip[0] | ip[1] | ip[2] | ip[3])) {
                if (ebuf)
                        sprintf(ebuf + os_strlen(ebuf),
                                "ERR! %s: all zero IP address.\n", str);
                os_log_info("ERR! %s: all zero IP address.\n", str);
                return -ISCSI_EZERO;
        }

	for(i = 0; i < 4; i++)
		ip[i] = os_le32_to_host(ip[i]);
	return 0;
}
#else
int iscsi_string_to_ipv6(char *str,
		unsigned int *ip, char *ebuf, int rsvd) {
	int ret;

	/* in6_pton won't take '[' so let's handle it here */
	if (*str == '[')
		ret = in6_pton(str+1, -1, (char*)ip,']', NULL);
	else
		ret = in6_pton(str, -1, (char*)ip, -1 , NULL);
	/*
	 * in6_pton returns 1 on success whereas
	 * iscsi_string_to_ip expects 0, so inverse it.
	 */
	ret = !ret;
	if (ret) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"ERR! %s: invalid IP address format.\n", str);
		os_log_info("ERR! %s : invalid IPv6 address format.\n", str);
		ret = -ISCSI_EFORMAT;
	} else if (!(ip[0] | ip[1] | ip[2] | ip[3])) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"ERR! %s: all zero IP address.\n", str);
		os_log_info("ERR! %s: all zero IP address.\n", str);
		ret = -ISCSI_EZERO;
        }

	return ret;
}
#endif

/* Handles IPv4 & IPv6 */
int iscsi_string_to_ip(char *str,
        unsigned int *ip, char *ebuf, int ipv6_expand) {

	if(!ipv6_expand) {

		/* it's an ipv4 address, map it as ipv4-mapped-ipv6
		 * this lets us use ipv6 socket for ipvN in the future
		 * with no changes required here
		 */
		ipaddr_mark_as_ipv4(ip);
		return iscsi_string_to_ipv4(str, &ip[3], ebuf);
	}
	else	ipv6_expand = 7 - ipv6_expand;

	return iscsi_string_to_ipv6(str, ip, ebuf, ipv6_expand);
}

STATIC int string_to_number_range(char *str, unsigned int *n1, unsigned int *n2,
				  char *ebuf)
{
	char   *ch, *v1, *v2 = NULL;
	int     rv;

	ch = str;
	v1 = ch;
	while (*ch && (*ch != '~'))
		ch++;
	/* indeed, it is a range */
	if (*ch == '~') {
		if ((ch - v1) == 0) {
			if (ebuf)
				sprintf(ebuf + os_strlen(ebuf),
					"ERR! %s: range missing 1st part.\n",
					str);
			os_log_info("ERR! %s: range missing 1st part.\n", str);
			return -ISCSI_EFORMAT;
		}
		/* terminate v1 string */
		*ch = '\0';
		v2 = ch + 1;
		if (!(*v2)) {
			if (ebuf)
				sprintf(ebuf + os_strlen(ebuf),
					"ERR! %s: range missing 2nd part.\n",
					str);
			os_log_info("ERR! %s: range missing 2nd part.\n", str);
			return -ISCSI_EFORMAT;
		}
	}

	rv = kv_decode_numeric(ISCSI_KV_DECODE_OP_ADD, v1, n1, ebuf);
	if (rv < 0)
		return rv;

	if (v2) {
		rv = kv_decode_numeric(ISCSI_KV_DECODE_OP_ADD, v2, n2, ebuf);
	} else {
		*n2 = *n1;
	}
	return rv;
}

/*
 * common decode functions
 * NOTE: vp should not be NULL
 *	 input buf should be terminated with a NULL character
 */

/* @buf -- <ip>[:<port>] 
 *	v_num[0] -- ip
 *	v_num[1] -- port
 */

static int check_duplicate_address(iscsi_value *vp1, iscsi_value *vp2,
				char *ebuf)
{
	char tbuf[80];

	if ((vp2->v_num[ISCSI_VALUE_NUM_IDX_PG_PORT] ==
	     vp1->v_num[ISCSI_VALUE_NUM_IDX_PG_PORT]) &&
	     !memcmp(vp2->v_num, vp1->v_num, ISCSI_IPADDR_LEN)) {
		tcp_endpoint_sprintf((struct tcp_endpoint *)vp1->v_num, tbuf);
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf), "duplicate IP %s.\n",
				tbuf);
		os_log_info("duplicate IP %s.\n", tbuf);

		return -ISCSI_EDUP;
	}
	return 0;
}

int kv_decode_addr_n_port(int mode, char *buf, iscsi_value * vp_head, char *ebuf)
{
	char   *ch;
	iscsi_value *vp = vp_head;

	if (!(*buf)) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"ERR! missing IP address.\n");
		os_log_info("ERR! missing IP address %s.\n", buf);
		return -ISCSI_EINVAL;
	}

	/* the ip address and port could be a list */
	ch = buf;
	while (*ch) {
		char   *ip_str, *port_str;
		unsigned int ip[4];
		unsigned int port = ISCSI_PORT_DEFAULT;
		int rv;
		int is_ipv6 = iscsi_string_is_address_ipv6(ch);

#ifndef CHISCSI_IPV6_SUPPORT
		if(is_ipv6) {
	                if (ebuf)
                      	  sprintf(ebuf + os_strlen(ebuf),
                                "ERR! IPV6 support is not enabled !\n");
	                os_log_info("ERR! IPV6 support is not enabled !\n", buf);
			return -ISCSI_ENOTSUPP;
		}
#endif
		memset(ip, 0, ISCSI_IPADDR_LEN);

		/* Redirection */
                if(os_strlen(ch) == 3)
                        if(*ch == '[' && *(ch + 2) == ']')
	                        break;

		/* find and terminate ip address portion */
		ip_str = ch;
		if(!is_ipv6) {
			while (*ch && ((*ch != ':') && (*ch != ',')))
				ch++;
			if (*ch == ':') {
				*ch = 0;
				ch++;
				port_str = ch;
			} else {
				if (*ch == ',') {
					*ch = 0;
					ch++;
				}
				port_str = NULL;
			}

			rv = iscsi_string_to_ip(ip_str, ip, ebuf, 0);

		} else {
			while (*ch && ((*ch != ']') && (*ch != ',')))
				ch++;
			if (*ch == ']' && *(ch + 1) == ':') {
                                ch+=2;
                                port_str = ch;
			} else {
				if (*ch == ',') {
					ch++;
				}
				port_str = NULL;
			}
			rv = iscsi_string_to_ip(ip_str, ip, ebuf, is_ipv6);
		}

		if (rv < 0)
			return rv;

		if (port_str) {
			port = (unsigned int) os_strtoul(ch, &ch, 0);
			if (*ch)
				ch++;
		}

		/* save everything */
		if (!vp) {
			vp = iscsi_value_alloc();
			if (!vp) {
				if (ebuf)
					sprintf(ebuf + os_strlen(ebuf),
						"ERR! out of memory.\n");
				return -ISCSI_ENOMEM;
			}
			iscsi_value_list_append(&vp_head, vp);
		}

		memcpy(vp->v_num, ip, ISCSI_IPADDR_LEN);

		vp->v_num[ISCSI_VALUE_NUM_IDX_PG_PORT] = port;
		vp->v_num_used = 5;
		vp = vp->v_next;
	}

	/* check if there is any duplicate address */
	if (vp_head->v_next) {
		iscsi_value *vp1, *vp2;
		for (vp1 = vp; vp1; vp1 = vp1->v_next) {
			for (vp2 = vp; vp2; vp2 = vp2->v_next) {
				if (vp2 == vp1)
					continue;
				if (check_duplicate_address(vp1, vp2, ebuf) < 0)
					return -ISCSI_EDUP;
			}
		}
	}
	return 0;
}

int kv_decode_text(int mode, char *buf, iscsi_value * vp, char *ebuf)
{
	if (os_strlen(buf)) {
		vp->v_str[0] = os_strdup(buf);
		if (!vp->v_str[0])
			return -ISCSI_ENOMEM;
		vp->v_str_used = 1;
	}
	return 0;
}

int kv_decode_number(int mode, char *buf, iscsi_value * vp, char *ebuf)
{
	int     rv;

	if (!vp)
		return -ISCSI_ENULL;

	rv = kv_decode_numeric(mode, buf, &vp->v_num[0], ebuf);
	if (rv < 0)
		return rv;
	vp->v_num_used = 1;
	if (vp->v_str[0])
		vp->v_str_used = 1;
	return 0;
}

int kv_decode_number_range(int mode, char *buf, iscsi_value * vp, char *ebuf)
{
	int     rv;

	if (!vp)
		return -ISCSI_ENULL;

	rv = string_to_number_range(buf, &vp->v_num[0], &vp->v_num[1], ebuf);
	if (rv < 0)
		return rv;

	vp->v_num_used = 2;

	if (vp->v_num[1] < vp->v_num[0]) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"INVALID Range %u < %u.\n",
				vp->v_num[1], vp->v_num[0]);
		os_log_info("INVALID Range %u < %u.\n", vp->v_num[1],
			    vp->v_num[0]);
		return -ISCSI_EINVAL;
	}

	return 0;
}

int kv_decode_boolean(int mode, char *buf, iscsi_value * vp, char *ebuf)
{
	if (!vp)
		return -ISCSI_ENULL;

	if (os_strcmp(buf, ISCSI_KEY_YES_STR) == 0) {
		vp->v_num[0] = 1;
	} else if (os_strcmp(buf, ISCSI_KEY_NO_STR) == 0) {
		vp->v_num[0] = 0;
	} else {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"ERR! UNKNOWN boolean %s.\n", buf);
		os_log_info("ERR! UNKNOWN boolean %s.\n", buf);
		return -ISCSI_EINVAL;
	}
	vp->v_num_used = 1;
	return 0;
}

int kv_post_decode_check_str(iscsi_keyval * kvp, iscsi_value * valp, char *ebuf)
{
	iscsi_value *vp;
	if (!kvp || !valp) {
		return -ISCSI_ENULL;
	}

	/* check if the same str has been declared already */
	for (vp = kvp->kv_valp; vp && vp != valp; vp = vp->v_next) {
		if (vp->v_str[0] && !os_strcmp(vp->v_str[0], valp->v_str[0])) {
			if (ebuf)
				sprintf(ebuf + os_strlen(ebuf),
					"ERR! duplicate %s.\n", valp->v_str[0]);
			os_log_info("ERR! duplicate %s.\n", valp->v_str[0]);
			return -ISCSI_EDUP;
		}
	}

	return 0;
}

/* check for Reject/NotUnderstood/Irrelevant */
int kv_decode_response(int mode, char *buf, unsigned int *flag)
{
	if (os_strcmp(buf, ISCSI_KEY_NOTUNDERSTOOD_STR) == 0) {
		*flag |= ISCSI_KV_FLAG_NOTUNDERSTOOD;
	} else if (os_strcmp(buf, ISCSI_KEY_IRRELEVANT_STR) == 0) {
		*flag |= ISCSI_KV_FLAG_IRRELEVANT;
	} else if (os_strcmp(buf, ISCSI_KEY_REJECT_STR) == 0) {
		*flag |= ISCSI_KV_FLAG_REJECT;
	} else {
		return -ISCSI_EINVAL;
	}
	return 0;
}

/*
 * common encode functions
 * NOTE: vp should not be NULL
 *	 input buf should be large enough to hold the encoded string (call 
 *	 kv_size_xxx first).
 */

int kv_encode_number(char *buf, iscsi_value * vp)
{
	int     rv;
	rv = sprintf(buf, "%u", vp->v_num[0]);
	return (rv);
}

int kv_encode_number_range(char *buf, iscsi_value * vp)
{
	int     rv;
	rv = sprintf(buf, "%u", vp->v_num[0]);
	if (vp->v_num[1] != vp->v_num[0]) {
		rv += sprintf(buf, "~%u", vp->v_num[1]);
	}
	return (rv);
}

int kv_encode_boolean(char *buf, iscsi_value * vp)
{
	int     rv;
	rv = sprintf(buf, "%s",
		     vp->v_num[0] ? ISCSI_KEY_YES_STR : ISCSI_KEY_NO_STR);
	return (rv);
}

int kv_encode_text(char *buf, iscsi_value * vp)
{
	int     rv = 0;
	if (vp->v_str[0])
		rv = sprintf(buf, "%s", vp->v_str[0]);
	return (rv);
}

/* check for Reject/NotUnderstood/Irrelevant */
int kv_encode_response(char *buf, unsigned int flag)
{
	if (flag & ISCSI_KV_FLAG_NOTUNDERSTOOD) {
		sprintf(buf, ISCSI_KEY_NOTUNDERSTOOD_STR);
	} else if (flag & ISCSI_KV_FLAG_REJECT) {
		sprintf(buf, ISCSI_KEY_REJECT_STR);
	} else if (flag & ISCSI_KV_FLAG_IRRELEVANT) {
		sprintf(buf, ISCSI_KEY_IRRELEVANT_STR);
	} else {
		return -ISCSI_EINVAL;
	}
	return (os_strlen(buf));
}

int kv_encode_addr_n_port(char *buf, iscsi_value * vp)
{
	/* xxx.xxx.xxx.xxx:<port>, port default to 3260 */
	int     len;

	len = tcp_endpoint_sprintf((struct tcp_endpoint *)vp->v_num, buf);
	return len;
}

/*
 * common size functions -- returns # spaces needed for encoding
 */

int kv_size_number(iscsi_value * vp)
{
	return (kv_calc_numeric_size(vp->v_num[0]));
}

int kv_size_number_range(iscsi_value * vp)
{
	int     len = kv_calc_numeric_size(vp->v_num[0]);
	if (vp->v_num[1] != vp->v_num[0])
		len += kv_calc_numeric_size(vp->v_num[1]);
	return len;
}

int kv_size_boolean(iscsi_value * vp)
{
	if (vp->v_num[0])
		return (os_strlen(ISCSI_KEY_YES_STR));
	else
		return (os_strlen(ISCSI_KEY_NO_STR));
}

int kv_size_text(iscsi_value * vp)
{
	if (vp->v_str[0])
		return (os_strlen(vp->v_str[0]));
	return 0;
}

int kv_size_response(unsigned int flags)
{
	if (flags & ISCSI_KV_FLAG_NOTUNDERSTOOD)
		return (os_strlen(ISCSI_KEY_NOTUNDERSTOOD_STR));
	else if (flags & ISCSI_KV_FLAG_REJECT)
		return (os_strlen(ISCSI_KEY_REJECT_STR));
	else if (flags & ISCSI_KV_FLAG_IRRELEVANT)
		return (os_strlen(ISCSI_KEY_IRRELEVANT_STR));
	return 0;
}

int kv_size_addr_n_port(iscsi_value * vp)
{
	/* xxx.xxx.xxx.xxx:<port>, port default to 3260 */
	return (16 + kv_calc_numeric_size(vp->v_num[1]));
}

/*
 * compute: compute kvp1 and kvp2, and save the result in kvp2
 */
int kv_compute_number_min(iscsi_keyval * kvp1, iscsi_keyval * kvp2)
{
	if (!kvp1 || !kvp1->kv_valp || !kvp2 || !kvp2->kv_valp) {
		os_log_info("%s: compute failed (NULL).\n",
			    kvp1 ? kvp1->kv_name : NULL);
		return -ISCSI_ENULL;
	}
	if (kvp2->kv_valp->v_num[0] > kvp1->kv_valp->v_num[0])
		kvp2->kv_valp->v_num[0] = kvp1->kv_valp->v_num[0];
	return 0;
}

int kv_compute_number_max(iscsi_keyval * kvp1, iscsi_keyval * kvp2)
{
	if (!kvp1 || !kvp1->kv_valp || !kvp2 || !kvp2->kv_valp) {
		os_log_info("%s: compute failed (NULL).\n",
			    kvp1 ? kvp1->kv_name : NULL);
		return -ISCSI_ENULL;
	}
	if (kvp2->kv_valp->v_num[0] < kvp1->kv_valp->v_num[0])
		kvp2->kv_valp->v_num[0] = kvp1->kv_valp->v_num[0];
	return 0;
}

int kv_compute_boolean_and(iscsi_keyval * kvp1, iscsi_keyval * kvp2)
{
	if (!kvp1 || !kvp1->kv_valp || !kvp2 || !kvp2->kv_valp) {
		os_log_info("%s: compute failed (NULL).\n",
			    kvp1 ? kvp1->kv_name : NULL);
		return -ISCSI_ENULL;
	}
	kvp2->kv_valp->v_num[0] = (kvp1->kv_valp->v_num[0] &&
				   kvp2->kv_valp->v_num[0]);

	return 0;
}

int kv_compute_boolean_or(iscsi_keyval * kvp1, iscsi_keyval * kvp2)
{
	if (!kvp1 || !kvp1->kv_valp || !kvp2 || !kvp2->kv_valp) {
		os_log_info("%s: compute failed (NULL).\n",
			    kvp1 ? kvp1->kv_name : NULL);
		return -ISCSI_ENULL;
	}
	kvp2->kv_valp->v_num[0] = (kvp1->kv_valp->v_num[0] ||
				   kvp2->kv_valp->v_num[0]);
	return 0;
}

/*
 * computation check functions
 *  -- kvp1 is what we sent, kvp2 is what we receive
 */

int kv_check_compute_list_selection(iscsi_keyval * kvp1, iscsi_keyval * kvp2)
{
	iscsi_value *vp1, *vp2;
	//iscsi_keydef *kdefp = kvp1->kv_def;

	if (!kvp1 || !kvp2 || !kvp1->kv_valp || !kvp2->kv_valp) 
		return 0;

	vp1 = kvp1->kv_valp;
	vp2 = kvp2->kv_valp;
	/* should only select at most one value out of the list */
	if (vp2->v_next) {
		os_log_info("%s: list select too many.\n", kvp1->kv_name);
		return -ISCSI_EINVAL;
	}

	for (; vp1; vp1 = vp1->v_next) {
		/* only support value in v_num[0] for now */
		if (vp2->v_num[0] == vp1->v_num[0])
			break;
	}

	if (vp1) return 0;
	os_log_info("%s: LIST selection %u not in original list.\n", 
		kvp1->kv_name, vp2->v_num[0]);
	return -ISCSI_EINVAL;
}

int kv_check_compute_number_min(iscsi_keyval * kvp1, iscsi_keyval * kvp2)
{
	iscsi_value *vp1, *vp2;

	if (!kvp1 || !kvp2 || !kvp1->kv_valp || !kvp2->kv_valp) 
		return 0;

	vp1 = kvp1->kv_valp;
	vp2 = kvp2->kv_valp;

	if (vp2->v_num[0] <= vp1->v_num[0])
		return 0;
	os_log_info("%s: MIN 0x%x > 0x%x.\n", 
		kvp1->kv_name, vp2->v_num[0], vp1->v_num[0]);
	return -ISCSI_EINVAL;
}

int kv_check_compute_number_max(iscsi_keyval * kvp1, iscsi_keyval * kvp2)
{
	iscsi_value *vp1, *vp2;

	if (!kvp1 || !kvp2 || !kvp1->kv_valp || !kvp2->kv_valp) 
		return 0;

	vp1 = kvp1->kv_valp;
	vp2 = kvp2->kv_valp;

	if (vp2->v_num[0] >= vp1->v_num[0])
		return 0;
	os_log_info("%s: MAX 0x%x < 0x%x.\n", 
		kvp1->kv_name, vp2->v_num[0], vp1->v_num[0]);
	return -ISCSI_EINVAL;
}

int kv_check_compute_boolean_and(iscsi_keyval * kvp1, iscsi_keyval * kvp2)
{
	iscsi_value *vp1, *vp2;

	if (!kvp1 || !kvp2 || !kvp1->kv_valp || !kvp2->kv_valp) 
		return 0;

	vp1 = kvp1->kv_valp;
	vp2 = kvp2->kv_valp;

	/* if we send false, there is no way we can get true back */
	if (vp2->v_num[0] && !vp1->v_num[0]) {
		os_log_info("%s: AND %u -> %u.\n", 
			kvp1->kv_name, vp1->v_num[0], vp2->v_num[0]);
		return -ISCSI_EINVAL;
	}
	return 0;
}

int kv_check_compute_boolean_or(iscsi_keyval * kvp1, iscsi_keyval * kvp2)
{
	iscsi_value *vp1, *vp2;

	if (!kvp1 || !kvp2 || !kvp1->kv_valp || !kvp2->kv_valp) 
		return 0;

	vp1 = kvp1->kv_valp;
	vp2 = kvp2->kv_valp;

	/* if we send true, there is no way we can get false back */
	if (!vp2->v_num[0] && vp1->v_num[0]) {
		os_log_info("%s: OR %u -> %u.\n", 
			kvp1->kv_name, vp1->v_num[0], vp2->v_num[0]);
		return -ISCSI_EINVAL;
	}
	return 0;
}
