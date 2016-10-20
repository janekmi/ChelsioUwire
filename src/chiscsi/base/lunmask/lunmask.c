#ifdef __ACL_LM__

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/string.h>
#include <common/iscsi_debug.h>

#define ACCESS_MASK_BITS	8	/* byte mask */
#define ACCESS_R		0x1
#define ACCESS_W		0x2

static inline int lm_bit_test(unsigned char *rwmask, int lun)
{
	int i = lun / ACCESS_MASK_BITS;
	int j = lun % ACCESS_MASK_BITS;
	unsigned char mask = 1 << j;

	return (rwmask[i] & mask);
}

static inline void lm_bit_set(unsigned char *rwmask, int lun)
{
	int i = lun / ACCESS_MASK_BITS;
	int j = lun % ACCESS_MASK_BITS;
	unsigned char mask = 1 << j;

	rwmask[i] |= mask;
}

static int string_to_number_range(char *str, unsigned int *n1,
				unsigned int *n2, char *ebuf)
{
	char *ch, *v1, *v2 = NULL;
	char *endp;

	ch = str;
	v1 = ch;
	while (*ch && (*ch != '~'))
		ch++;
	/* indeed, it is a range */
	if (*ch == '~') {
		if ((ch - v1) == 0) {
			if (ebuf)
				sprintf(ebuf,
					"ERR! %s: range missing 1st part.\n",
					str);
			os_log_info("ERR! %s: range missing 1st part.\n",
				str);
			return -EINVAL;
		}
		/* terminate v1 string */
		*ch = '\0';
		v2 = ch + 1;
		if (!(*v2)) {
			*ch = '~';
			if (ebuf)
				sprintf(ebuf,
					"ERR! %s: range missing 2nd part.\n",
					str);
			os_log_info("ERR! %s: range missing 2nd part.\n",
				str);
			return -EINVAL;
		}
	}

	*n1 = (unsigned int)simple_strtoul(v1, &endp, 0);
	if (v1 == endp) {
		if (v2)
			*ch = '~';
		if (ebuf)
			sprintf(ebuf, "ERR! %s: bad lun numbers.\n", v1);
		os_log_info("ERR! %s: bad lun numbers.\n", v1);
		return -EINVAL;
	}
	if (v2) {
		*n2 = (unsigned int)simple_strtoul(v2, &endp, 0);
		*ch = '~';
		if (v2 == endp) {
			if (ebuf)
			sprintf(ebuf, "ERR! %s: bad lun numbers.\n", v2);
			os_log_info("ERR! %s: bad lun numbers.\n", v2);
			return -EINVAL;
		}
	} else
		*n2 = *n1;

	return 0;
}

int lm_config_parse(unsigned char *rmask, unsigned char *wmask, int lunmax,
		char *buf, char *ebuf, int ebuflen)
{
	char *ch = buf;
	int allr = 0;
	int allw = 0;
	int rv = 0;

	while (*ch) {
		char   *lunstr, *rwstr;
		unsigned int rw = 0;

		lunstr = ch;
		/* look for permission string */
		while (*ch && *ch != ':')
			ch++;
		if (*ch != ':') {
			if (ebuf)
				sprintf(ebuf, "ERR! %s missing lun number.\n",
					buf);
			os_log_info("ERR! %s missing lun number.\n", buf);
			return -EINVAL;
		}
		*ch = '\0';
		ch++;

		rwstr = ch;
		while (*ch && *ch != ',' && *ch != '~')
			ch++;
		if (*ch && *ch != ',' && *ch != '~') {
			rwstr--;
			*rwstr = ':';
			if (ebuf)
				sprintf(ebuf, "ERR! %s missing permission.\n",
					buf);
			os_log_info("ERR! %s missing permission.\n", buf);
			return -EINVAL;
		}
		if (*ch) {
			*ch = '\0';
			ch++;
		}

		/* get both lun string and permission string */
		if (!strcmp(rwstr, "RW") || !strcmp(rwstr, "WR"))
			rw = ACCESS_R | ACCESS_W;
		else if (!strcmp(rwstr, "R"))
			rw = ACCESS_R;
		else if (!strcmp(rwstr, "W"))
			rw = ACCESS_W;
		else {
			if (ebuf)
				sprintf(ebuf,
					"ERR! %s invalid lun permission.\n",
					buf);
			os_log_info("ERR! %s invalid lun permission.\n", buf);
			return -EINVAL;
		}

		if (!strcmp(lunstr, "ALL")) {
			if ((allr && (rw & ACCESS_R)) ||
			    (allw && (rw & ACCESS_W))) {
				if (ebuf)
					sprintf(ebuf,
						"ERR! %s lun overlaps ALL.\n",
						buf);
				os_log_info("ERR! %s lun overlaps ALL.\n", buf);
				return -EINVAL;
			}
			if (rw & ACCESS_R)
				allr = 1;
			if (rw & ACCESS_W)
				allw = 1;
		} else { /* lu number lists */
			/* luns could be a number, a range, or a list */
			while (*lunstr) {
				char *vstr;
				unsigned int i;
				unsigned int v1, v2;

				/* skip leading "," */
				while (*lunstr && *lunstr == ',')
					lunstr++;
				vstr = lunstr;
				/* terminate the vstr */
				while (*lunstr && *lunstr != ',')
					lunstr++;
				if (*lunstr == ',') {
					*lunstr = '\0';
					lunstr++;
				}
				rv = string_to_number_range(vstr, &v1, &v2,
							ebuf);
				if (rv < 0)
					return rv;

				/* lunmax is 1-based, v1/2 is 0-based */
				if (v1 >= lunmax || v2 >= lunmax) {
					if (ebuf)
						sprintf(ebuf,
						"ERR! lun %s too big > "
						"max %d.\n",
						buf, lunmax - 1);
					os_log_info("ERR! lun %s does not exist, max %u.\n",
						buf, lunmax - 1);
					return -EINVAL;
				}

				for (i = v1; i <= v2; i++) {
					if (rw & ACCESS_R)
						lm_bit_set(rmask, i);
					if (rw & ACCESS_W)
						lm_bit_set(wmask, i);
				}
			}
		}
	}

	return 0;
}

int lm_config_display(unsigned char *rmask, unsigned char *wmask, int lunmax,
			char *buf, int buflen)
{
	int mmax = (lunmax + ACCESS_MASK_BITS - 1) / ACCESS_MASK_BITS;
	int i, j;
	int begin = 0;
	int bflag = 0;
	unsigned int rw = 0, rw_save = 0;
	int len = 0;

	for (i = 0; i <= mmax && begin < lunmax; i++) {
		unsigned char mask = 1;

		for (j = 0; j < ACCESS_MASK_BITS && begin < lunmax;
			j++, mask <<= 1) {
			int end;

			rw_save = rw;
			rw = 0;
			if (rmask && (rmask[i] & mask))
				rw |= ACCESS_R;
			if (wmask && (wmask[i] & mask))
				rw |= ACCESS_W;

			if (rw_save == rw)
				continue;

			end = i * ACCESS_MASK_BITS + (j - 1);
			if (end > lunmax)
				end = lunmax - 1;

			if (!bflag) {
				bflag = 1;
				goto move_begin;
			}

			if (!rw)
				bflag = 0;
			if (!rw_save)
				goto move_begin;

			if (begin == end)
				len += sprintf(buf + len, "%d:", begin);
			else
				len += sprintf(buf + len, "%d~%d:", begin, end);
			if (rw_save & ACCESS_R)
				buf[len++] = 'R';
			if (rw_save & ACCESS_W)
				buf[len++] = 'W';
			buf[len++] = ',';
move_begin:
			begin = end;
			begin++;
		}
	}

	if (bflag && begin < lunmax) {
		len += sprintf(buf + len, "%d~%d:", begin, lunmax - 1);
		if (rw_save & ACCESS_R)
			buf[len++] = 'R';
		if (rw_save & ACCESS_W)
			buf[len++] = 'W';
		buf[len++] = ',';
	}

	return len;
}

int lm_lun_readable(unsigned char *rmask, unsigned char *wmask, int lun)
{
	if (!wmask || !rmask)
		return 0;

	return lm_bit_test(rmask, lun) || lm_bit_test(wmask, lun);
}

int lm_lun_writable(unsigned char *rmask, unsigned char *wmask, int lun)
{
	if (!wmask)
		return 0;
	return lm_bit_test(wmask, lun);
}

int lm_make_lun_list(unsigned char *rmask, unsigned int *lun_list, int lunmax)
{
	int mmax = (lunmax + ACCESS_MASK_BITS - 1) / ACCESS_MASK_BITS;
	int i, j, k;
	int cnt = 0;

	if (!rmask)
		return 0;

	for (i = 0; i <= mmax; i++) {
		unsigned char mask = 1;

		k = i * ACCESS_MASK_BITS;
		for (j = 0; j < ACCESS_MASK_BITS && k < lunmax;
			j++, mask <<= 1, k++) {
			if (rmask[i] & mask) {
				lun_list[cnt] = k;
				cnt++;
			}
		}
	}

	return cnt;
}

#endif /* ifdef __ACL_LM__ */
