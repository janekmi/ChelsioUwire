#include <iscsi_structs.h>
#include "iscsi_text_private.h"

void iscsi_string_pair_display(iscsi_string_pair * pair)
{
	iscsi_string *svalp = &(pair->p_val);

	os_log_info("%s(%d): seq %u, flag 0x%x.\n",
		    pair->p_key, pair->p_keylen, pair->p_seq, pair->p_flag);

	for (; svalp; svalp = svalp->s_next) {
		os_log_info("\t%s.\n", svalp->s_str);
	}
}

void iscsi_pairq_display(char *caption, chiscsi_queue * pairq)
{
	iscsi_string_pair *pair;

	os_log_info("%s:\n", caption);
	for (pair = pairq->q_head; pair; pair = pair->p_next) {
		iscsi_string_pair_display(pair);
	}
}

int iscsi_match_key_string(char *buf, int kmax, iscsi_keydef * kdef)
{
	int     i = kmax;
	int     len = os_strlen(buf);

	if (len) {
		for (i = 0; i < kmax; i++, kdef++) {
			if (len == os_strlen(kdef->name)
			    && !os_strcmp(buf, kdef->name))
				break;
		}
	}

	if (i == kmax)
		return -ISCSI_ENOMATCH;
	return i;
}

/*
 * APIs for iscsi_string_pair
 */
int iscsi_string_pair_find_key_type(iscsi_string_pair * pair, int kmax,
				    iscsi_keydef * kdef)
{
	return (iscsi_match_key_string(pair->p_key, kmax, kdef));
}

iscsi_string_pair *iscsi_string_pair_find_by_key(chiscsi_queue * pairq, char *key)
{
	iscsi_string_pair *pair;
	int     len = os_strlen(key);
	for (pair = pairq->q_head; pair; pair = pair->p_next) {
		if ((pair->p_keylen == len) && !os_strcmp(pair->p_key, key))
			break;
	}
	return pair;
}

void iscsi_string_pair_free(iscsi_string_pair * pair)
{
	iscsi_string *strp;

	if (!pair)
		return;

	strp = pair->p_val.s_next;
	while (strp) {
		iscsi_string *next = strp->s_next;
//              if (strp->s_str) os_free(strp->s_str);
		os_free(strp);
		strp = next;
	}
//      if (pair->p_val.s_str) os_free(pair->p_val.s_str);
	os_free(pair);
}

void iscsi_empty_string_pairq(chiscsi_queue * pairq)
{
	iscsi_string_pair *spair;

	if (!pairq)
		return;

	string_pair_dequeue(nolock, pairq, spair);
	while (spair) {
		iscsi_string_pair_free(spair);
		string_pair_dequeue(nolock, pairq, spair);
	}
}

int iscsi_string_pairq_write_text(chiscsi_queue * pairq, char *buf,
				  unsigned int resp_flag)
{
	char    resp_buf[20];
	int     resp_len = kv_encode_response(resp_buf, resp_flag);
	int     len = 0;
	iscsi_string_pair *pair;

	resp_buf[resp_len] = '\0';
	for (pair = pairq->q_head; pair; pair = pair->p_next) {
		/* key = <response><NULL> */
		len += sprintf(buf + len, "%s=%s", pair->p_key, resp_buf);
		buf[len++] = '\0';
	}
	return len;
}

int iscsi_string_pairq_size_response(chiscsi_queue * pairq,
				     unsigned int resp_flag)
{
	unsigned int resp_len = kv_size_response(resp_flag);
	int     len = 0;
	iscsi_string_pair *pair;
	for (pair = pairq->q_head; pair; pair = pair->p_next) {
		/* key = <response><NULL> */
		len += pair->p_keylen + resp_len + 2;
	}
	return len;
}
