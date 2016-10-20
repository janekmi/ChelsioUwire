#include <iscsi_structs.h>
#include "iscsi_text_private.h"

/* 
 * string buffer <-> value 
 */

/* Hex Array <-> string */
STATIC int encode_hex_string(unsigned char *from, unsigned int flen, char *to)
{
	int     i, j;
	int     len = 0;

	for (i = 0, j = 0; i < flen; i++, j += 2)
		len += sprintf(to + j, "%02x", from[i]);
	return len;
}

#define hex_char_to_number(c)	\
		if ((c) >= '0' && (c) <= '9') \
			c -= '0'; \
		else if ((c) >= 'A' && (c) <= 'F') \
			c = (c) - 'A' + 10; \
		else if ((c) >= 'a' && (c) <= 'f') \
			c = (c) - 'a' + 10; \
		else { \
			os_log_info("bad hex char %c.\n", c); \
			return -ISCSI_EINVAL; \
		}

STATIC int decode_hex_string(char *from, unsigned char *to, unsigned long tolen)
{
	int     tidx, fidx, flen = os_strlen(from);
	int     tlen;
	char    c1, c2;

	if (!from || !flen || !to) {
		os_log_info("hex string 0x%p (%d), 0x%p (%lu).\n", from, flen,
			    to, tolen);
		return -ISCSI_ENULL;
	}

	tlen = (flen + 1) / 2;
	if (tlen > tolen) {
		os_log_info("hex string tlen %d < tolen %lu.\n", tlen, tolen);
		//      return -ISCSI_ENOMEM;
	}

	/* odd number of characters */
	if (flen & 1) {
		os_log_info("hex string length odd %d.\n", flen);
		c1 = from[0];
		hex_char_to_number(c1);
		to[0] = c1;
		tidx = 1;
		fidx = 1;
	} else {
		tidx = 0;
		fidx = 0;
	}

	for (; fidx < flen; fidx += 2, tidx++) {
		c1 = from[fidx];
		c2 = from[fidx + 1];

		hex_char_to_number(c1);
		hex_char_to_number(c2);

		to[tidx] = (c1 << 4) | c2;
	}

	return tlen;
}

/* Base64 Array <-> string */
static char base64code[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

STATIC int encode_base64_string(unsigned char *from, unsigned int flen,
				char *to)
{
	unsigned int fidx, tidx, fleft;

	if (!from || !flen || !to)
		return -ISCSI_ENULL;

	/* is the length multiple of 3 ? */
	fleft = flen % 3;
	flen -= fleft;

	for (fidx = 0, tidx = 0; fidx < flen; fidx += 3) {
		to[tidx++] = base64code[(from[fidx] >> 2) & 0x3F];
		to[tidx++] = base64code[((from[fidx] << 4) & 0x30) |
					((from[fidx + 1] >> 4) & 0x0F)];
		to[tidx++] = base64code[((from[fidx + 1] << 2) & 0x3C) |
					((from[fidx + 2] >> 6) & 0x03)];
		to[tidx++] = base64code[from[fidx + 2] & 0x3F];
	}

	if (fleft == 1) {
		/* two characters followed by two "=" padding characters */
		int     byte = from[fidx];
		to[tidx++] = base64code[(byte >> 2) & 0x3F];
		to[tidx++] = base64code[(byte << 4) & 0x30];
		to[tidx++] = base64code[64];
		to[tidx++] = base64code[64];

	} else if (fleft == 2) {
		/* three characters followed by one "=" padding characters */
		int     byte1 = from[fidx];
		int     byte2 = from[fidx + 1];
		to[tidx++] = base64code[(byte1 >> 2) & 0x3F];
		to[tidx++] = base64code[((byte1 << 4) & 0x30) |
					((byte2 >> 4) & 0x0F)];
		to[tidx++] = base64code[(byte2 << 2) & 0x3C];
		to[tidx++] = base64code[64];
	}
	return tidx;
}

#define base64_char_to_number(c)	\
	if ((c) == '=') c = 64;	\
	else if ((c) == '/') c = 63; \
	else if ((c) == '+') c = 62; \
	else if ((c) >= 'A' && (c) <= 'Z') \
		c -= 'A'; \
	else if ((c) >= 'a' && (c) <= 'z') \
		c = (c) - 'a' + 26; \
	else if ((c) >= '0' && (c) <= '9') \
		c = (c) - '0' + 52; \
	else  \
		c = -1;

STATIC int decode_base64_string(char *from, unsigned char *to,
				unsigned int tolen)
{
	unsigned int flen = os_strlen(from);
	unsigned int i, fidx, tidx, fleft = 0;
	unsigned char byte[4];

	if (!from || !flen || !to)
		return -ISCSI_ENULL;
	/* not multiple of 4 */
	if (flen & 0x3)
		return -ISCSI_EINVAL;

	/* remove padding at the end */
	if (from[flen - 1] == '=') {
		int     pad = 1;
		if (from[flen - 2] == '=')
			pad++;

		flen -= pad;
		fleft = flen & 3;
		if (fleft == 2) {
			/* 1 byte: 2 characters followed by 2 "=" */
			if (pad != 2) {
				os_log_info
					("base64 ERR, %d left, with %d pad.\n",
					 fleft, pad);
				return -ISCSI_EFORMAT;
			}
		} else if (fleft == 3) {
			/* 2 bytes: 3 characters followed by 1 "=" */
			if (pad != 1) {
				os_log_info
					("base64 ERR, %d left, with %d pad.\n",
					 fleft, pad);
				return -ISCSI_EFORMAT;
			}
		} else {
			os_log_info("base64 ERR, %d left, with %d pad.\n",
				    fleft, pad);
			return -ISCSI_EFORMAT;
		}

		flen -= fleft;
	}

	for (fidx = 0, tidx = 0; fidx < flen;) {
		for (i = 0; i < 4; i++, fidx++) {
			signed char    c = from[fidx];
			base64_char_to_number(c);
			if (c < 0 || c == 64) {
				return -ISCSI_EINVAL;
			}
			byte[i] = c;
		}

		to[tidx++] = ((byte[0] << 2) & 0xFC) | ((byte[1] >> 4) & 0x3);
		to[tidx++] = ((byte[1] << 4) & 0xF0) | ((byte[2] >> 2) & 0xF);
		to[tidx++] = ((byte[2] << 6) & 0xC0) | (byte[3] & 0x3F);
	}

	if (fleft) {
		for (i = 0; i < fleft; i++, fidx++) {
			signed char    c = from[fidx];
			base64_char_to_number(c);
			if (c < 0 || c == 64) {
				return -ISCSI_EINVAL;
			}
			byte[i] = c;
		}

		to[tidx++] = ((byte[0] << 2) & 0xFC) | ((byte[1] >> 4) & 0x3);
		if (fleft == 3) {
			/* 2 bytes */
			to[tidx++] =
				((byte[1] << 4) & 0xF0) | ((byte[2] >> 2) &
							   0xF);
		}
	}

	return tidx;
}

/* Encoded number <-> string */

/* v_data[0] -- the decoded number 
 * v_num[0] --	the decoded number length in bytes */

int kv_size_encoded_numeric(iscsi_value * vp)
{
	int     rv = -ISCSI_EINVAL;
	if (vp->v_type == ISCSI_VALUE_TYPE_NUMERIC_ENCODE_HEX) {
		/* every 4 bits per byte + "0x" + ending NULL */
		rv = vp->v_num[0] * 2 + 3;
	} else if (vp->v_type == ISCSI_VALUE_TYPE_NUMERIC_ENCODE_BASE64) {
		/* every 6 bits per byte + "0xb" + ending NULL */
		rv = ((vp->v_num[0] + 2) / 3) * 4 + 3;
	}
	return rv;
}

int kv_decode_encoded_numeric(int mode, char *buf, iscsi_value * vp, char *ebuf)
{
	int     blen = os_strlen(buf) - 2;
	unsigned char *dp;

	if (buf[0] != '0')
		goto format_err;

	if (buf[1] == 'x' || buf[1] == 'X') {
		int     rv, len;
		vp->v_type = ISCSI_VALUE_TYPE_NUMERIC_ENCODE_HEX;
		/* "0x" or "0b" not counted */
		buf += 2;
		/* how many bytes the decoded number needs */
		len = (blen - 1) / 2 + 1;
		dp = os_alloc(len, 1, 1);
		if (!dp)
			return -ISCSI_ENOMEM;

		rv = decode_hex_string(buf, dp, len);
		if (rv < 0) {
			os_free(dp);
			return rv;
		}
		vp->v_num[0] = len;
		vp->v_data[0] = dp;
		vp->v_num_used = 1;
		vp->v_data_used = 1;
		return 0;

	} else if (buf[1] == 'b' || buf[1] == 'B') {
		int     rv, len;
		vp->v_type = ISCSI_VALUE_TYPE_NUMERIC_ENCODE_BASE64;
		buf += 2;
		/* how many bytes the decoded number needs */
		/* 6 bits for every bytes in the string */
		if ((blen & 3))
			goto format_err;
		/* if last 2 char are "==" then last 16 bits not used */
		len = blen / 4 * 3;
		dp = os_alloc(len, 1, 1);
		if (!dp)
			return -ISCSI_ENOMEM;

		rv = decode_base64_string(buf, dp, len);
		if (rv < 0) {
			os_free(dp);
			return rv;
		}
		dp[rv] = 0;
		vp->v_num[0] = rv;
		vp->v_data[0] = dp;
		vp->v_num_used = 1;
		vp->v_data_used = 1;
		return 0;
	}

      format_err:
	if (ebuf)
		sprintf(ebuf + os_strlen(ebuf),
			"%s: invalid encoding format.\n", buf);
	os_log_info("%s: invalid encoding format.\n", buf);
	return -ISCSI_EFORMAT;
}

int kv_encode_encoded_numeric(char *buf, iscsi_value * vp)
{
	int     len = 2;

	buf[0] = '0';
	if (vp->v_type == ISCSI_VALUE_TYPE_NUMERIC_ENCODE_HEX) {
		buf[1] = 'x';
		len += encode_hex_string(vp->v_data[0], vp->v_num[0], buf + 2);
	} else if (vp->v_type == ISCSI_VALUE_TYPE_NUMERIC_ENCODE_BASE64) {
		buf[1] = 'b';
		len += encode_base64_string(vp->v_data[0], vp->v_num[0],
					    buf + 2);
	} else {
		return -ISCSI_EINVAL;
	}

	return len;
}

/* return 0, if the same, 1 otherwise */
int kv_number_array_compare(unsigned char *v1, unsigned int len1,
			    unsigned char *v2, unsigned int len2)
{
	int     i;

	if (!v1 && !v2)
		return 0;
	if (len1 != len2)
		return 1;
	for (i = 0; i < len1; i++) {
		if (v1[i] != v2[i])
			return 1;
	}

	return 0;
}

/* Number <-> string */

/* the decoded number is saved in v_num[0] */
int kv_calc_numeric_size(unsigned int v)
{
	int     len = 0;
	int	test = 1;
	while (v / test) {
		len++;
		test *= 10;
	}
	return (len);
}

int kv_decode_numeric(int mode, char *buf, unsigned int *v, char *ebuf)
{
	unsigned long val;

	/* Empty value is an error */
	if(buf == NULL)
	{
		//	sprintf(ebuf + os_strlen(ebuf),
		//		": NULL digits.\n");
		return -ISCSI_EFORMAT;
	}
	/* hex */
	if ((buf[0] == '0') && (buf[1] == 'x' || buf[1] == 'X')) {
		char   *ch;
		val = os_strtoul(buf, &ch, 16);
		if (*ch) {
			if (ebuf)
				sprintf(ebuf + os_strlen(ebuf),
					"%s: invalid hex digits.\n", buf);
			os_log_info("%s: invalid hex digits.\n", buf);
			return -ISCSI_EFORMAT;
		}

	} else {		/* decimal */
		char   *ch;
		val = os_strtoul(buf, &ch, 10);
		if (*ch) {
			if (ebuf)
				sprintf(ebuf + os_strlen(ebuf),
					"%s: invalid decimal digits.\n",
					buf);
			os_log_info("%s: invalid decimal digits.\n", buf);
			return -ISCSI_EFORMAT;
		}
	}
	*v = val;

	return 0;
}

int kv_encode_numeric(char *buf, unsigned int v)
{
	int     len;
	len = sprintf(buf, "%u", v);
	return len;
}
