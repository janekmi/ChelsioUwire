/*
 * isns pdu related functions
 */

#include "isns.h"
#include "isns_pdu.h"
#include "isns_pdu_defs.h"
#include "isns_globals.h"

/**
 * isns_pdu_write_hdr -- construct pdu header
 * @pdu: pdu buffer
 * @fid: function id
 * @dlen: pdu data length
 * @flag: pdu flag
 * @tid: transaction id
 */
void isns_pdu_write_hdr(char *pdu, u_int16_t fid, u_int16_t dlen,
			u_int16_t flag, u_int16_t tid)
{
	flag |= ISNS_PDU_FLAG_SENDER_CLIENT | ISNS_PDU_FLAG_LAST_PDU |
		ISNS_PDU_FLAG_FIRST_PDU;

	SET_ISNS_PDU_VERSION(pdu, ISNSP_VERSION);
	SET_ISNS_PDU_FUNCTIONID(pdu, fid);
	SET_ISNS_PDU_LENGTH(pdu, dlen);
	SET_ISNS_PDU_FLAGS(pdu, flag);
	SET_ISNS_PDU_TRANSACTIONID(pdu, tid);
	SET_ISNS_PDU_SEQUENCEID(pdu, 0);
}

/**
 * isns_pdu_write_attr -- write an attribute to a pdu
 * @pdu: pdu buffer
 * @tag: attribute tag
 * @len: attribute length (do not need to be 4-byte aligned)
 * @str: attribute string value if available
 * @val: attribute integer value if available
 *
 * !either a string value or an integer value but not both.
 */
void isns_pdu_write_attr(char *pdu, u_int32_t tag, u_int32_t len, char *str,
			 u_int32_t val)
{
	u_int32_t dlen = GET_ISNS_PDU_LENGTH(pdu);
	u_int8_t pad = (len & 0x3) ? 4 - (len & 0x3) : 0;
	char   *buf = pdu + ISNS_PDU_HDR_LEN + dlen;

	SET_ISNS_ATTR_TAG(buf, tag);
	buf += ISNS_ATTR_TAG_LENGTH;
	/* pad to 4 byte alignment */
	SET_ISNS_ATTR_LENGTH(buf, len + pad);
	buf += ISNS_ATTR_TAGLEN_LENGTH;
	memset(buf, 0, len + pad);
	if (str) {
		memcpy(buf, str, len);
	} else if (len) {
		*((u_int32_t *) buf) = htonl(val);
	}
	dlen += len + pad + ISNS_ATTR_TAG_LENGTH + ISNS_ATTR_TAGLEN_LENGTH;
	SET_ISNS_PDU_LENGTH(pdu, dlen);
}

/**
 * isns_pdu_write_attr_ip -- write an ip address attribute to a pdu
 * @pdu: pdu buffer
 * @ip: ip address in an integer form
 * @tag: attribute tag
 * @iplen: attribute length
 */
void isns_pdu_write_attr_ip(char *pdu, u_int32_t *ip, u_int32_t tag,
			    u_int32_t iplen)
{
	char    ipbuf[ISNS_ATTR_PORTALIP_LENGTH + 4];	/* max. length */

	memset(ipbuf, 0, ISNS_ATTR_PORTALIP_LENGTH + 4);
	if(!ip)
		memset(ipbuf + 10, 0xff, 2);
	else
		memcpy(ipbuf, ip, sizeof(u_int32_t) * 4);
	isns_pdu_write_attr(pdu, tag, iplen, ipbuf, 0);
}

int isns_pdu_send(isns_sock * sock, char *pdu, int mlen)
{
	int     rv = 0;
	int     len = 0;
	unsigned int total_len = GET_ISNS_PDU_LENGTH(pdu) + ISNS_PDU_HDR_LEN;

	if (total_len > mlen) {
		isns_log_msg("pdu_send: pdu len %u > max %d.\n", total_len,
			     mlen);
	}

	if (sock->fd < 0) {
		rv = isns_sock_connect(sock);
		if (rv < 0)
			return rv;
	}

	while (len < total_len) {
		rv = write(sock->fd, pdu + len, total_len - len);
		if (rv < 0)
			goto out;
		len += rv;
	}

      out:
	if (rv < 0) {
		isns_log_error("faile to send pdu: %d, close sock %d.\n", rv,
			       sock->fd);
		isns_sock_close(sock);
	}

	return rv;
}

int isns_pdu_recv(isns_sock * sock, char *buf, int buflen)
{
	int     rv;
	int     len = 0;
	unsigned int dlen;

	if (sock->fd < 0) {
		rv = isns_sock_connect(sock);
		if (rv < 0)
			return rv;
	}

	if (buflen < ISNS_PDU_HDR_LEN) {
		isns_log_error("pdu recv buffer too small: %d < %d.\n", buflen,
			       ISNS_PDU_HDR_LEN);
		return -1;
	}

	memset(buf, 0, buflen);

	while (len < ISNS_PDU_HDR_LEN) {
		rv = read(sock->fd, buf + len, ISNS_PDU_HDR_LEN - len);
		if (rv < 0)
			goto out;
		len += rv;
	}

	dlen = GET_ISNS_PDU_LENGTH(buf);
	if ((dlen + ISNS_PDU_HDR_LEN) > ISNS_PDU_MAX_LENGTH) {
		isns_log_error("rcv'd pdu too big: %d < %d.\n",
			       dlen + ISNS_PDU_HDR_LEN, ISNS_PDU_MAX_LENGTH);
		return -EIO;
	}

	buf += len;

	len = 0;
	while (len < dlen) {
		rv = read(sock->fd, buf + len, dlen - len);
		if (rv < 0)
			goto out;
		len += rv;
	}

      out:
	if (rv < 0) {
		isns_log_error("faile to recv pdu: %d, close sock %d.\n", rv,
			       sock->fd);
		isns_sock_close(sock);
	}

	return rv;
}

int isns_pdu_send_n_recv(isns_sock * sock, char *buf, int buflen)
{
	int     rv;
	unsigned int fid = GET_ISNS_PDU_FUNCTIONID(buf);
	unsigned int err;

	fid |= 0x8000;		/* the response opcode */

	rv = isns_pdu_send(sock, buf, buflen);
	if (rv < 0)
		return rv;

	rv = isns_pdu_recv(sock, buf, buflen);
	if (rv < 0)
		return rv;

	if (GET_ISNS_PDU_FUNCTIONID(buf) != fid) {
		isns_log_error("exp. resp 0x%x, rcv 0x%x.\n", fid,
			       GET_ISNS_PDU_FUNCTIONID(buf));
		return -EINVAL;
	}

	err = GET_ISNS_ERRORCODE(buf);
	if (err) {
		isns_log_error("rcv resp 0x%x, error code %d.\n", fid, err);
		return -EINVAL;
	}

	return 0;
}
