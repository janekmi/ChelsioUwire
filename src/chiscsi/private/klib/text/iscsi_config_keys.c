#include <common/iscsi_common.h>
#include <iscsi_structs.h>
#include <iscsi_global.h>
#include <iscsi_config_keys.h>
#include <iscsi_target_api.h>
#include "iscsi_text_private.h"

/* returns int value if in range '0'..'9' else returns -1 if not a number 

static int isnum( char c )
{
    if ( c < '0' || c > '9' ) return -1; 
    return c - '0';
} */

/*
 * iscsi configuration keys (Chelsio specific)
 */

/* 
 * target only: "PortalGroup" = <portalgroup tag>@<ip>:<port>
 * [,...timeout=xx][,[redirect groups]]  
 * 	v_num[0]-[3] -- ip
 * 	v_num[4] -- port
 * 	v_num[5] -- tag
 * 	v_num[6] -- timeout
 * 	v_str[0] -- string of redirect groups
 */
STATIC int kv_decode_portalgroup(int mode, char *buf, iscsi_value *vp, char *ebuf)
{
	unsigned int tag;
	unsigned int timeout = 0;
	int rv;
	char *ch, *tmstr;
	char *redirect_str_start, *redirect_str_end;
	iscsi_value *orig_vp = NULL;

	/* search for the optional parameters at the end:
 	 * - timeout=xxx 
	 * - redirect portalgroups: [x,y,...]
 	 */
	tmstr = os_strstr(buf, "timeout=");
        redirect_str_start = os_strchr(buf, '[');
        redirect_str_end = os_strchr(buf, ']');

	/* make sure we don't pick up the ipv6 address as a redirect portal */
	while(redirect_str_start && redirect_str_end)
		if(os_strstrbet(redirect_str_start, redirect_str_end, ":")) {
			redirect_str_start = os_strchr(redirect_str_end++, '[');
			redirect_str_end = os_strchr(redirect_str_end, ']');
		} else break;

	if (tmstr == buf || redirect_str_start == buf) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
			"ERR! %s missing portal info. at the beginning.\n",
			buf);
		os_log_info("ERR! %s missing portal info. at the beginning.\n",
				buf);
		return -ISCSI_EFORMAT;
	}
	if ((redirect_str_start && !redirect_str_end) ||
	    (!redirect_str_start && redirect_str_end)) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
					"ERR! %s redirect un-terminated.\n",
					buf);
		os_log_info("ERR! %s redirect un-terminated.\n", buf);
		return -ISCSI_EFORMAT;
	}

	if (redirect_str_start && redirect_str_end) {
		/* should always be preceded by ',' */
		ch = redirect_str_start - 1;
		if (*ch != ',') {
			if (ebuf)
				sprintf(ebuf + os_strlen(ebuf),
					"ERR! %s bad redirect config.\n",
					buf);
			os_log_info("ERR! %s bad redirect config.\n", buf);
			return -ISCSI_EFORMAT;
		}
		if (redirect_str_end - redirect_str_start == 1) {
			if (ebuf)
				sprintf(ebuf + os_strlen(ebuf),
					"ERR! %s empty redirect config.\n",
					buf);
			os_log_info("ERR! %s empty redirect config.\n", buf);
			return -ISCSI_EFORMAT;
		}

		*redirect_str_end = 0;
		for (ch = redirect_str_start + 1; *ch; ch++) {
			if (*ch < '0' && *ch > '9' && *ch != ',') {
				if (ebuf)
					sprintf(ebuf + os_strlen(ebuf),
					"ERR! %s invalid redirect config %s.\n",
					buf, ch);
				os_log_info("ERR! %s invalid redirect config %s.\n", buf, ch);
				return -ISCSI_EFORMAT;
			}
		}
	}
	     
	if (tmstr) {
		ch = tmstr - 1;
		if (*ch != ',') {
			if (ebuf)
				sprintf(ebuf + os_strlen(ebuf),
					"ERR! %s bad timeout format.\n", buf);
			os_log_info("ERR! %s bad timeout format.\n", buf);
			return -ISCSI_EFORMAT;
		}
		ch = os_strchr(tmstr, '=');
		ch++;
		timeout = os_strtoul(ch, &ch, 10);
		if (*ch) {
			if (ebuf)
				sprintf(ebuf + os_strlen(ebuf),
					"ERR! %s invalid timeout value.\n",
					buf);
			os_log_info("ERR! %s invalid timeout value.\n", buf);
			return -ISCSI_EFORMAT;
		}
	} else
		timeout = ISCSI_HEARTBEAT_DEFAULT;

	/* remove the timeout and redirect substrings
	 * since they are at the end, just null them */
	if (tmstr)
		*(tmstr - 1) = 0;
	if (redirect_str_start)
		*(redirect_str_start - 1) = 0;

	/* get the portal group tag first */
	ch = buf;
	tag = os_strtoul(buf, &ch, 10);
	if (*ch != '@') {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"ERR! %s missing portal group tag.\n",
				buf);
		os_log_info("ERR! %s missing portal group tag.\n", buf);
		return -ISCSI_EFORMAT;
	}
	ch++;

	if (!(*ch)) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"ERR! %s missing ip address.\n", buf);
		os_log_info("ERR! %s missing ip address.\n", buf);
		return -ISCSI_EFORMAT;
	}

	rv = kv_decode_addr_n_port(mode, ch, vp, ebuf);
	if (rv < 0){
		return rv;
	}
	orig_vp = vp;
	/* the same tag applies to all ip's */
	for (; vp; vp = vp->v_next) {
		vp->v_num[ISCSI_VALUE_NUM_IDX_PG_TAG] = tag;
		vp->v_num[ISCSI_VALUE_NUM_IDX_PG_TIMEOUT] = timeout;
		vp->v_num_used += 2;
	}
	vp = orig_vp;
	if (redirect_str_start) {
        	vp->v_str[0] = os_strdup(redirect_str_start + 1);
		if (!vp->v_str[0]) {
			if (ebuf)
				sprintf(ebuf + os_strlen(ebuf),
				"ERR! %s decode, OOM.\n", buf);
			os_log_info("ERR! %s decode OOM.\n", buf);
			return -ISCSI_ENOMEM;
		}
		vp->v_str_used = 1;	
	}
	return 0;
}

/* 
	check if 
	1). same portal group tag has been declared or
	2). same ip being declared multiple time
*/
STATIC int kv_post_decode_portalgroup(iscsi_keyval * kvp, iscsi_value * vp,
				      char *ebuf)
{
	iscsi_value *dup;

	/* check for same portal group tag */
	for (dup = kvp->kv_valp; dup; dup = dup->v_next) {
		if ((vp->v_num[ISCSI_VALUE_NUM_IDX_PG_TAG] ==
			dup->v_num[ISCSI_VALUE_NUM_IDX_PG_TAG]))
			break;
	}
	if (dup) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"%s, duplicate tag %u.\n",
				kvp->kv_name,
				vp->v_num[ISCSI_VALUE_NUM_IDX_PG_TAG]);
		os_log_info("%s, duplicate tag %u.\n", kvp->kv_name,
			    vp->v_num[ISCSI_VALUE_NUM_IDX_PG_TAG]);
		return -ISCSI_EDUP;
	}

	/* check for same ip address and port */
	for (dup = kvp->kv_valp; dup; dup = dup->v_next) {
		if(vp->v_flag == dup->v_flag)
			if(!memcmp(vp->v_num, dup->v_num,
				sizeof(unsigned int) * 5))
			break;
	}

	if (dup) {
		char tbuf[80];

		tcp_endpoint_sprintf((tcp_endpoint *)vp->v_num, tbuf);
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"%s, duplicate ip %s.\n", kvp->kv_name, tbuf);
		os_log_info("%s, duplicate ip %s.\n", kvp->kv_name, tbuf);
		return -ISCSI_EDUP;
	}
	return 0;
}

/* target only: "TargetClass" = <target class name> 
 *                 v_str[0] -- class name
 *                 */
static int kv_decode_targetclass(int mode, char *buf, iscsi_value * vp, char *ebuf)
{
        chiscsi_target_class *tclass = iscsi_target_class_find_by_name(buf);
        if (!tclass) {
                os_log_error("%s, Unknown target class.\n", buf);
                if (ebuf)
                        sprintf(ebuf, "%s, Unknown target class.\n", buf);
                return -ISCSI_EFORMAT;
        }
        vp->v_data[0] = (void *)tclass;
	vp->v_data_used = 1;
	return (kv_decode_text(mode, buf, vp, ebuf));
}

/* target only: ACL Format
     ACL=[<iname=initiator name>][;<sip=src ip>][;<dip=dst ip>]
	 [;<lun=N:R/RW,0~N:R/RW,ALL:R/RW>]
		v_str[0]  -- initiator name list
		v_str[1]  -- saddr list
		v_str[2]  -- daddr list
		v_str[3]  -- lun mask list
*/
static inline int break_list_by_comma(char *start, char *end, char *keyname,
				char *buf, char **listpp)
{
	char sav = *end;
	char *c;
	char *list;
	int l = end - start; 
	int i;
	int cnt = 0;

	*end = '\0';

	if (!l) {
		os_log_info("ERR! ACL %s empty: %s.\n", keyname, buf);
		goto done;
	}

	list = os_alloc(l + 1, 1, 1);
	if (!list) {
		os_log_info("ERR! ACL %s OOM %d.\n", keyname, l);
		goto done;
	}
	*listpp = list;

	for (i = 0, c = start; i < l; i++, c++) {
		if (*c == ',')
			*c = '\0';
	}

	for (cnt = 0, c = start; c <= end; ) {
		if (*c == '\0')
			c++;
		else {	
			int len = os_strlen(c);

			os_strcpy(list, c);
			list += len + 1;
			c += len;
			cnt++;
		}
	}
	if (!cnt) {
		os_log_info("ERR! ACL %s empty: %s.\n", keyname, buf);
		os_free(*listpp);
		*listpp = NULL;
		return 0;
	}
		
done:
	for (i = 0, c = start; i < l; i++, c++) {
		if (*c == '\0')
			*c = ',';
	}
	*end = sav;

	return cnt;
}

static int acl_check_iname(char *buf, char *ebuf, int cnt)
{
	int i, j;
	char *c;

	for (i = 0, c = buf; i < cnt; i++) {
		int l = os_strlen(c);

		if (l > ISCSI_NAME_LEN_MAX) {
			if (ebuf)
				sprintf(ebuf,
				"ERR! ACL iname too long %d > %d: %s.\n",
					l, ISCSI_NAME_LEN_MAX, c);
			os_log_info("ERR! ACL iname too long %d > %d: %s.\n",
				l, ISCSI_NAME_LEN_MAX, c);
			return -ISCSI_EFORMAT;
		}

		if (os_strncmp(c, "iqn.", 4) && os_strncmp(c, "eui.", 4)) {
			if (ebuf)
				sprintf(ebuf,
					"ERR! ACL iname invalid: %s.\n", c);
			os_log_info("ERR! ACL iname invalid: %s.\n", c);
			return -ISCSI_EFORMAT;
		}

		c += l + 1;
	}

	for (i = 0, c = buf; i < cnt; i++) {
		int l = os_strlen(c);
		char *c2 = c + l + 1;

		for (j = i + 1; j < cnt; j++) {
			int l2 = os_strlen(c2);	

			if (!os_strcmp(c, c2)) {
				if (ebuf)
					sprintf(ebuf,
					"ERR! ACL dup iname: %s.\n", c);
				os_log_info("ERR! ACL duplicate iname: %s.\n",
						c);
				return -ISCSI_EFORMAT;
			}

			c2 += l2 + 1;
		}

		c += l + 1;
	}

	return 0;
}

static int acl_check_ipaddr(char *buf, char *ebuf, int cnt)
{
	int i, token = 0;
	char *ip;

	for (i = 0, ip = buf; i < cnt; i++) {
		int j, l = os_strlen(ip);

		/* IPV4: 0-9 and ".", IPV6: 0-9,a-f, and ":" */
		for (j = 0; j < l; j++) {
			char c = ip[j];

			if(c == '[' || c == ']') {
				if( c == '[')
					token++;
				else	token--;
				continue;
			}

			if (!os_isxdigit(c) && c != '.' && c != ':') {
				goto err_out;
			}
		}
		if(token)
                	goto err_out;

		ip += l + 1;
	}

	return 0;

err_out:
	if (ebuf)
		sprintf(ebuf, "ERR! ACL ip invalid: %s.\n",
			ip);
	os_log_info("ERR! ACL ip invalid: %s.\n", ip);
	return -ISCSI_EFORMAT;

}


static int acl_check_lunmask_list(char *buf, char *ebuf, unsigned int *all_flag)
{
	/* <lun numbers or ALL>:<R|RW> */
	int len = os_strlen(buf);
	int r = 0, w = 0;
	char *rw = NULL;
	char *lun = buf;
	char *c = buf;
	unsigned int f = 0;

	while (*c) {
		char sav;
		char *all = NULL;

		for (c = lun; *c && *c != ':'; c++)
			;

		sav = *c;
		*c = '\0';
		all = os_strstr(lun, "ALL");

		if (all && (c - lun) != os_strlen("ALL")) {
			/* must contain something other than ALL */
			if (ebuf)
				sprintf(ebuf, "ERR! ACL, bad lun list %s.\n",
					lun);
			os_log_info("ERR! ACL, bad lun list %s.\n", lun);
			*c = sav;
			return -ISCSI_EFORMAT;
		}

		if (!all) {
#ifdef __ACL_LM__
			char *_c;

			/* the lu list contains numbers seperated by comma */
			for (_c = lun; *_c; _c++) {
				if (!os_isdigit(*_c) && *_c != ',' &&
					*_c != '~') {
					if (ebuf)
						sprintf(ebuf,
						"ERR! ACL, bad lun %s.\n",
						lun);
					os_log_info("ERR! ACL, bad lun %s, %c.\n",
						lun, *_c);
					*c = sav;
					return -ISCSI_EFORMAT;
				}
			}
#else
			if (ebuf)
				sprintf(ebuf, "ERR! ACL lun %s must be ALL.\n",
					lun);
			os_log_info("ERR! ACL lun %s must be ALL.\n", lun);
			return -ISCSI_EFORMAT;
#endif
		}

		*c = sav;
		rw = c + 1;

		for (c = rw; *c && *c != ','; c++)
			;
		sav = *c;
		*c = '\0';

		if (!os_strcmp(rw, "RW") || !os_strcmp(rw, "WR"))
			r = w = 1;	
		else if (!os_strcmp(rw, "R"))
			r = 1;
		else if (!os_strcmp(rw, "W"))
			w = 1;
		else {
			if (ebuf)
				sprintf(ebuf, "ERR! ACL, bad rw permission %s.\n",
					rw);
			os_log_info("ERR! ACL, bad rw permission %s.\n", rw);
			*c = sav;
			return -ISCSI_EFORMAT;
		}
		*c = sav;
		if (*c)
			c++;

		if ((r && (f & ACL_FLAG_ALLR)) ||
		    (w && (f & ACL_FLAG_ALLW))) {
			if (ebuf)
				sprintf(ebuf,
					"ERR! ACL, overlapping lun rw %s.\n",
					buf);
			os_log_info("ERR! ACL, overlapping lun rw %s.\n", buf);
			return -ISCSI_EFORMAT;
		}

		if (all) {
			if (r)
				f |= ACL_FLAG_ALLR;
			if (w)
				f |= ACL_FLAG_ALLW;
			
			/* zero-out as it is reflected in the flag now */
			memset(lun, '\0', c - lun);
		}

		lun = c;
	}

	if (f) {
		/* remove the zeroed-out part */
		int i;
		int null_found = 0;

		for (i = 0, c = buf; i < len; i++) {
			if (buf[i] != '\0') {
				if (null_found)
					*c = buf[i];
				c++;
			} else
				null_found = 1;
		}
		*c = '\0';
	}

	*all_flag = f;
	return 0;
}

int kv_decode_acl(int mode, char *buf, iscsi_value *vp, char *ebuf)
{
	char *iname1 = NULL, *iname2 = NULL;
	char *sip1 = NULL, *sip2 = NULL;
	char *dip1 = NULL, *dip2 = NULL;
	char *lun1 = NULL, *lun2 = NULL;
	char *iname_list = NULL;
	char *sip_list = NULL;
	char *dip_list = NULL;
	char *lun_list = NULL;
	char *c1 = buf;
	char *c2 = buf;
	char *c3;
	int iname_cnt = 0;
	int sip_cnt = 0;
	int dip_cnt = 0;
	unsigned int lun_flag = 0;
	int rv = 0;

	while (*c2 != '\0') {
		char sav;

		if (*c2 != '=') {
			c2++;
			continue;
		}

		for (c3 = c2 + 1; *c3 && *c3 != ';'; c3++)
			;
		sav = *c3;
		*c3 = '\0';
		*c2 = '\0';

		if (!os_strcmp(c1, "iname")) {
			iname1 = c2 + 1;
			iname2 = c3;
		} else if (!os_strcmp(c1, "sip")) {
			sip1 = c2 + 1;
			sip2 = c3;
		} else if (!os_strcmp(c1, "dip")) {
			dip1 = c2 + 1;
			dip2 = c3;
		} else if (!os_strcmp(c1, "lun")) {
			lun1 = c2 + 1;
			lun2 = c3;
		} else {
			*c2 = '=';
			os_log_info("ERR! Bad ACL key %s in %s.\n", c1, buf);
			return -ISCSI_EFORMAT;
		}

		*c2 = '=';
		*c3 = sav;

		c2 = c3;
		while (*c2 && *c2 == ';')
			c2++;
		c1 = c2;
	}

	if (!iname1 && !sip1 && !dip1) {
		os_log_info("ERR! ACL missing iname, sip, dip: %s.\n", buf);
		return -ISCSI_EFORMAT;
	}

	if (iname1) {
		iname_cnt = break_list_by_comma(iname1, iname2, "iname", buf,
					&iname_list);
		if (!iname_cnt) {
			rv = -ISCSI_EFORMAT;
			goto err_out;
		}
		rv = acl_check_iname(iname_list, ebuf, iname_cnt);
		if (rv < 0)
			goto err_out;
	}

	if (sip1) {
		sip_cnt = break_list_by_comma(sip1, sip2, "sip", buf,
					&sip_list);
		if (!sip_cnt) {
			rv = -ISCSI_EFORMAT;
			goto err_out;
		}
		rv = acl_check_ipaddr(sip_list, ebuf, sip_cnt);
		if (rv < 0)
			goto err_out;
	}

	if (dip1) {
		dip_cnt = break_list_by_comma(dip1, dip2, "dip", buf,
					&dip_list);
		if (!dip_cnt) {
			rv = -ISCSI_EFORMAT;
			goto err_out;
		}
		rv = acl_check_ipaddr(dip_list, ebuf, dip_cnt);
		if (rv < 0)
			goto err_out;
	}

	if (lun1) {
		char sav;

		sav = *(lun2 + 1);
		*(lun2 + 1) = '\0';
		lun_list = os_strdup(lun1);
		if (!lun_list) {
			os_log_info("ACL lun OOM: %s.\n", lun1);
			*(lun2 + 1) = sav;
			rv = -ISCSI_EFORMAT;
			goto err_out;
		}
		*(lun2 + 1) = sav;

		rv = acl_check_lunmask_list(lun_list, ebuf, &lun_flag);
		if (rv < 0)
			goto err_out;

		if ((*lun_list == '\0') ||
		    ((lun_flag & ACL_FLAG_ALLR) && 
		     (lun_flag & ACL_FLAG_ALLW))) {
			os_free(lun_list);
			lun_list = NULL;
		} 
	} else
		lun_flag = ACL_FLAG_ALLRW;

	vp->v_num[ISCSI_VALUE_NUM_ACL_INAME_IDX] = iname_cnt;
	vp->v_num[ISCSI_VALUE_NUM_ACL_SADDR_IDX] = sip_cnt;
	vp->v_num[ISCSI_VALUE_NUM_ACL_DADDR_IDX] = dip_cnt;
	vp->v_num[ISCSI_VALUE_NUM_ACL_LUN_IDX] = lun_list ? 1 : 0;
	vp->v_num[ISCSI_VALUE_NUM_ACL_LUNALL_IDX] = lun_flag;
	vp->v_num_used = 5;	

	vp->v_str[ISCSI_VALUE_STR_ACL_INAME_IDX] = iname_list;
	vp->v_str[ISCSI_VALUE_STR_ACL_SADDR_IDX] = sip_list;
	vp->v_str[ISCSI_VALUE_STR_ACL_DADDR_IDX] = dip_list;
	vp->v_str[ISCSI_VALUE_STR_ACL_LUN_IDX] = lun_list;

	vp->v_str_used = 4;	
	return 0;

err_out:
	if (iname_list)
		os_free(iname_list);
	if (sip_list)
		os_free(sip_list);
	if (dip_list)
		os_free(dip_list);
	if (lun_list)
		os_free(lun_list);
	return rv;
}

/*
 * Chelsio Configuration Key Definition Table
 */
iscsi_keydef iscsi_keydef_config_tbl[ISCSI_KEY_CONFIG_COUNT] = {
	/* ISCSI_KEY_CONF_PORTALGROUP */
	{
	 .name = "PortalGroup",
	 .vtype = ISCSI_VALUE_TYPE_TEXT,
	 .property = (ISCSI_KEY_SENDER_TARGET_CONFIG |
		      ISCSI_KEY_CHANGABLE | ISCSI_KEY_DECLARE_MULTIPLE |
		      ISCSI_KEY_DISPLAY_MODE_SUMMARY),
	 .fp_decode = kv_decode_portalgroup,
	 .fp_post_decode = kv_post_decode_portalgroup}
	,
	/* ISCSI_KEY_CONF_TARGET_SESSION_MAXCMD */
	{
	 .name = "TargetSessionMaxCmd",
	 .vtype = ISCSI_VALUE_TYPE_NUMERIC,
	 .property = (ISCSI_KEY_SENDER_TARGET_CONFIG |
		      ISCSI_KEY_HAS_DEFAULT |
		      ISCSI_KEY_HAS_MIN | ISCSI_KEY_HAS_MAX |
		      ISCSI_KEY_DISPLAY_MODE_DETAIL),
	 .val_dflt = ISCSI_SESSION_SCMDQ_DEFAULT,
	 .val_min = 1,
	 .val_max = 2048,
	 .fp_decode = kv_decode_number,
	 .fp_encode = kv_encode_number,
	 .fp_size = kv_size_number}
	,
	 /* ISCSI_KEY_CONF_TARGET_CLASS */
        {
	 .name = "TargetClass",
	 .vtype = ISCSI_VALUE_TYPE_TEXT,
	 .property = (ISCSI_KEY_SENDER_TARGET_CONFIG |
			ISCSI_KEY_DISPLAY_MODE_SUMMARY),
	 .fp_decode = kv_decode_targetclass,
	 .fp_encode = kv_encode_text,
	 .fp_size = kv_size_text}
        ,
	/* ISCSI_KEY_CONF_TARGET_DEVICE */
	{
	 .name = "TargetDevice",
	 .vtype = ISCSI_VALUE_TYPE_TEXT,
	 .property = (ISCSI_KEY_SENDER_TARGET_CONFIG |
		      ISCSI_KEY_DECLARE_MULTIPLE |
		      ISCSI_KEY_DISPLAY_MODE_SUMMARY),
	 .fp_decode = kv_decode_text,
	 .fp_post_decode = kv_post_decode_check_str,
	 .fp_encode = kv_encode_text,
	 .fp_size = kv_size_text}
	,
	/* ISCSI_KEY_CONF_ACL_ENABLE */
	{
	 .name = "ACL_Enable",
	 .vtype = ISCSI_VALUE_TYPE_TEXT,
	 .property = (ISCSI_KEY_SENDER_TARGET_CONFIG |
		      ISCSI_KEY_CHANGABLE | ISCSI_KEY_HAS_DEFAULT |
		      ISCSI_KEY_DISPLAY_MODE_SUMMARY),
	 .fp_decode = kv_decode_boolean,
	 .fp_encode = kv_encode_boolean,
	 .fp_size = kv_size_boolean}
	,
	/* ISCSI_KEY_CONF_ACL */
	{
	 .name = "ACL",
	 .vtype = ISCSI_VALUE_TYPE_TEXT,
	 .property = (ISCSI_KEY_SENDER_TARGET_CONFIG |
		      ISCSI_KEY_CHANGABLE | ISCSI_KEY_DECLARE_MULTIPLE |
		      ISCSI_KEY_DISPLAY_MODE_DETAIL),
	 .fp_decode = kv_decode_acl}
	,
        /* ISCSI_KEY_CONF_SHADOW_MODE */
        {
         .name = "ShadowMode",
         .vtype = ISCSI_VALUE_TYPE_TEXT,
         .property = (ISCSI_KEY_SENDER_TARGET_CONFIG |
                      ISCSI_KEY_CHANGABLE | ISCSI_KEY_HAS_DEFAULT |
                      ISCSI_KEY_DISPLAY_MODE_SUMMARY),
         .fp_decode = kv_decode_boolean,
         .fp_encode = kv_encode_boolean,
         .fp_size = kv_size_boolean}
        ,
        /* ISCSI_KEY_CONF_REGISTER_ISNS */
	{
         .name = "RegisteriSNS",
         .vtype = ISCSI_VALUE_TYPE_BOOLEAN,
         .property = (ISCSI_KEY_SENDER_ALL_CONFIG |
                      ISCSI_KEY_CHANGABLE | ISCSI_KEY_HAS_DEFAULT |
                      ISCSI_KEY_DISPLAY_MODE_SUMMARY),
         .val_dflt = 1,
         .fp_decode = kv_decode_boolean,
         .fp_encode = kv_encode_boolean,
         .fp_size = kv_size_boolean}

};

/*
 * check if in ShadowMode, there is a portal that neither redirected to, nor redirects
 */
int iscsi_config_keys_check_for_standalone_portal(iscsi_keyval * kvlist)
{
        unsigned short i=0,j;
	unsigned long bmap;
        iscsi_value * vp;
        vp = kvlist->kv_valp;

        bmap = ~0;
        while(vp){
                if(vp->v_num_used >= 5) {
			bmap &= ~(1 << i);
			for(j = 4; j < vp->v_num_used; j++)
				bmap &= ~( 1 << (vp->v_num[j] - 1));
                }
                i++;
                vp = vp->v_next;
        };

	return( i ? bmap & ((1 << i) - 1) : 1);
}

/*
 * config keys API
 */
int iscsi_config_keys_validate_value(iscsi_keyval * kvlist,
				     char *ebuf, int ebuflen, 
				     int is_chelsio_class)
{
	iscsi_keyval *kvp;
	
	if (((kvlist + ISCSI_KEY_CONF_SHADOW_MODE)->kv_valp == NULL) 
		|| ((kvlist + ISCSI_KEY_CONF_PORTALGROUP)->kv_valp == NULL)
		|| ((kvlist + ISCSI_KEY_CONF_ACL_ENABLE)->kv_valp == NULL))
	{
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"Invalid config: check portal and/or acl settings\n");
		os_log_info(
			"Invalid config: check portal and/or acl settings.\n", 1);
		return -ISCSI_EINVAL;
	}
	
	if (is_chelsio_class &&
	    !(kvlist + ISCSI_KEY_CONF_TARGET_DEVICE)->kv_valp) {
	/* we may not need a TargetDevice if in Shadow Mode */
		if((kvlist + ISCSI_KEY_CONF_SHADOW_MODE)->kv_valp->v_num[0])
                	if(!iscsi_config_keys_check_for_standalone_portal(kvlist + ISCSI_KEY_CONF_PORTALGROUP))
                        	goto fall_through;

			if (ebuf)
				sprintf(ebuf + os_strlen(ebuf),
					"%s missing.\n", (kvlist + ISCSI_KEY_CONF_TARGET_DEVICE)->kv_name);
			os_log_info("%s missing.\n", (kvlist + ISCSI_KEY_CONF_TARGET_DEVICE)->kv_name);
			return -ISCSI_EINVAL;

	} else if(((kvlist + ISCSI_KEY_CONF_TARGET_DEVICE)->kv_valp) && 
		  ((kvlist + ISCSI_KEY_CONF_SHADOW_MODE)->kv_valp->v_num[0])) {
		if(!iscsi_config_keys_check_for_standalone_portal(kvlist + ISCSI_KEY_CONF_PORTALGROUP)) {
			if (ebuf)
                               	sprintf(ebuf + os_strlen(ebuf),
                                       	"Unnecessary %s defined.\n", (kvlist + ISCSI_KEY_CONF_TARGET_DEVICE)->kv_name);
			os_log_info("Unnecessary %s defined.\n", (kvlist + ISCSI_KEY_CONF_TARGET_DEVICE)->kv_name);
		}
	}
	
fall_through:
	if (is_chelsio_class) {
		kvp = (kvlist + ISCSI_KEY_CONF_TARGET_DEVICE);	
		if (kvp->kv_rcvcnt > ISCSI_TARGET_LUN_MAX) {
			if (ebuf)
				sprintf(ebuf + os_strlen(ebuf),
					"%s too many luns > %u.\n",
					kvp->kv_name, ISCSI_TARGET_LUN_MAX);
			os_log_info("%s too many luns > %u.\n",
				    kvp->kv_name, ISCSI_TARGET_LUN_MAX);
			return -ISCSI_EINVAL;
		}
	}

	kvp = kvlist + ISCSI_KEY_CONF_PORTALGROUP;
	if (!kvp->kv_valp) {
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"%s missing.\n", kvp->kv_name);
		os_log_info("%s missing.\n", kvp->kv_name);
		return -ISCSI_EINVAL;
	}

	return 0;
}

int iscsi_get_target_config_key_settings(
				struct iscsi_target_config_settings *setting,
				iscsi_keyval *kvlist)
{
	int rv;
	unsigned int val;

	rv = iscsi_kvlist_get_value_by_index(ISCSI_KEY_CONF_ACL_ENABLE,
				kvlist, iscsi_keydef_config_tbl, &val);
	if (rv < 0)
		return rv;
	setting->acl_en = val ? 1 : 0;

	rv = iscsi_kvlist_get_value_by_index(ISCSI_KEY_CONF_REGISTER_ISNS,
				kvlist, iscsi_keydef_config_tbl, &val);
	if (rv < 0)
		return rv;
	setting->isns_register = val ? 1 : 0;

	rv = iscsi_kvlist_get_value_by_index(ISCSI_KEY_CONF_SHADOW_MODE,
				kvlist, iscsi_keydef_config_tbl, &val);
	if (rv < 0)
		return rv;
	setting->shadow_mode = val ? 1 : 0;

	rv = iscsi_kvlist_get_value_by_index(
				ISCSI_KEY_CONF_TARGET_SESSION_MAXCMD,
				kvlist, iscsi_keydef_config_tbl,
				&setting->sess_max_cmds);
	if (rv < 0)
		return rv;

	return 0;	
}
