/*
 * iSNS client utility functions
 *		- register/de-register iSNS client 
 *		- register/de-register target
 *		- SCN register/de-register target
 *		- register/de-register initiator
 *		- SCN register/de-register initiator
 *		- query for initiators in the same DD
 *		- query for targets in the same DD
 */

#include "isns.h"
#include "isns_pdu_defs.h"
#include "isns_pdu.h"
#include "isns_globals.h"

u_int16_t transaction_id = 0;

int isns_entity_deregister(isns_sock * sock, char *name)
{
	char    pdu[ISNS_PDU_MAX_LENGTH];
	int     rv;

	memset(pdu, 0, ISNS_PDU_MAX_LENGTH);

	isns_pdu_write_hdr(pdu, ISNS_DEV_DEREG_REQ, 0, 0, ++transaction_id);

	isns_pdu_write_attr(pdu, ISNS_ATTR_ISCSINAME_TAG, strlen(name) + 1,
			    name, 0);
	isns_pdu_write_attr(pdu, ISNS_ATTR_DELIMITER_TAG,
			    ISNS_ATTR_DELIMITER_LENGTH, NULL, 0);
	isns_pdu_write_attr(pdu, ISNS_ATTR_ISCSINAME_TAG, strlen(name) + 1,
			    name, 0);

	rv = isns_pdu_send_n_recv(sock, pdu, ISNS_PDU_MAX_LENGTH);
	if (rv < 0)
		return rv;

	return 0;
}

int isns_query_peers(isns_sock * sock, char *name, u_int32_t node_type,
		     char *buf, int maxlen)
{
	char   *pdu = buf;
	int     rv;

	memset(pdu, 0, maxlen);

	isns_pdu_write_hdr(pdu, ISNS_DEV_ATTR_QUERY_REQ, 0, 0,
			   ++transaction_id);
	isns_pdu_write_attr(pdu, ISNS_ATTR_ISCSINAME_TAG, strlen(name) + 1,
			    name, 0);
	isns_pdu_write_attr(pdu, ISNS_ATTR_ISCSINODETYPE_TAG,
			    ISNS_ATTR_ISCSINODETYPE_LENGTH, NULL, node_type);
	isns_pdu_write_attr(pdu, ISNS_ATTR_DELIMITER_TAG,
			    ISNS_ATTR_DELIMITER_LENGTH, NULL, 0);

	isns_pdu_write_attr(pdu, ISNS_ATTR_ISCSINAME_TAG, 0, NULL, 0);
	isns_pdu_write_attr(pdu, ISNS_ATTR_ISCSINODETYPE_TAG, 0, NULL, 0);
	isns_pdu_write_attr_ip(pdu, 0, ISNS_ATTR_PORTALIP_TAG, 0);
	/*required for isns initiator*/
	isns_pdu_write_attr_ip(pdu, 0, ISNS_ATTR_PORTALPORT_TAG, 0);
	isns_pdu_write_attr(pdu, ISNS_ATTR_PGTAG_TAG, 0, NULL, 0);

	rv = isns_pdu_send_n_recv(sock, pdu, maxlen);
	if (rv < 0)
		return rv;

	return 0;
}

int isns_scn_deregister(isns_sock * sock, char *name)
{
	char    pdu[ISNS_PDU_MAX_LENGTH];
	int     rv;

	memset(pdu, 0, ISNS_PDU_MAX_LENGTH);

	isns_pdu_write_hdr(pdu, ISNS_SCN_DEREG_REQ, 0, 0, ++transaction_id);
	isns_pdu_write_attr(pdu, ISNS_ATTR_ISCSINAME_TAG, strlen(name) + 1,
			    name, 0);
	isns_pdu_write_attr(pdu, ISNS_ATTR_ISCSINAME_TAG, strlen(name) + 1,
			    name, 0);

	rv = isns_pdu_send_n_recv(sock, pdu, ISNS_PDU_MAX_LENGTH);
	if (rv < 0)
		return rv;

	return 0;
}

int isns_scn_register(isns_sock * sock, char *name)
{
	char    pdu[ISNS_PDU_MAX_LENGTH];
	int     rv;
	unsigned int isns_scnbit_node;

	memset(pdu, 0, ISNS_PDU_MAX_LENGTH);

	isns_scnbit_node = ISNS_SCNBIT_INITIATOR;

	isns_pdu_write_hdr(pdu, ISNS_SCN_REG_REQ, 0, 0, ++transaction_id);

	isns_pdu_write_attr(pdu, ISNS_ATTR_ISCSINAME_TAG, strlen(name) + 1,
			    name, 0);
	isns_pdu_write_attr(pdu, ISNS_ATTR_ISCSINAME_TAG, strlen(name) + 1,
			    name, 0);
	isns_pdu_write_attr(pdu, ISNS_ATTR_DELIMITER_TAG,
			    ISNS_ATTR_DELIMITER_LENGTH, NULL, 0);
	isns_pdu_write_attr(pdu, ISNS_ATTR_SCNBITMAP_TAG,
			    ISNS_ATTR_SCNBITMAP_LENGTH, NULL,
			    (isns_scnbit_node | ISNS_SCNBIT_OBJ_REMOVED |
			     ISNS_SCNBIT_OBJ_ADDED | ISNS_SCNBIT_OBJ_UPDATED));

	rv = isns_pdu_send_n_recv(sock, pdu, ISNS_PDU_MAX_LENGTH);
	if (rv < 0)
		return rv;

	return 0;
}
