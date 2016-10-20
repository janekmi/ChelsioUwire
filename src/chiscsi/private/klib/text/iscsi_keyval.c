#include <iscsi_structs.h>
#include "iscsi_text_private.h"

/*
 * APIs for iscsi_keyval struct
 */

int iscsi_kvp_display(iscsi_keyval * kvp)
{
	iscsi_value *vp;

	os_log_info("kvp 0x%p, %s, flags=0x%x, vtype=%u, rcv=%u, seq=%u.\n",
		    kvp, kvp->kv_name, kvp->kv_flags, kvp->kv_vtype,
		    kvp->kv_rcvcnt, kvp->kv_rcvseq);
	for (vp = kvp->kv_valp; vp; vp = vp->v_next) {
		int     i;
		os_log_info
			("\tvp 0x%p, pos=%u, type=%u, flag=0x%x, num=%u, str=%u, data=%u.\n",
			 vp, vp->v_pos, vp->v_type, vp->v_flag, vp->v_num_used,
			 vp->v_str_used, vp->v_data_used);
		for (i = 0; i < vp->v_num_used; i++)
			os_log_info("\t\tnum %d = 0x%x(%u).\n", i, vp->v_num[i],
				    vp->v_num[i]);
		for (i = 0; i < vp->v_str_used; i++)
			os_log_info("\t\tstr %d = %s.\n", i, vp->v_str[i]);
		for (i = 0; i < vp->v_data_used; i++)
			os_log_info("\t\tdata %d = 0x%p.\n", i, vp->v_data[i]);
	}
	return 0;
}

void iscsi_kvp_free(iscsi_keyval * kvp)
{
	if (kvp) {
		if (kvp->kv_valp) {
			iscsi_value_free(kvp->kv_valp, kvp->kv_name);
		}
		os_free(kvp);
	}
}

/* compute buffer size needed for the key value pair */
int iscsi_kvp_size_text(iscsi_keyval * kvp)
{
	int     rv;
	int     len = 0;
	unsigned int pos;
	iscsi_keydef *kdefp = kvp->kv_def;
	iscsi_value *vp = kvp->kv_valp;

	if (!kvp)
		return -ISCSI_ENULL;

	/* keyname= */
	if (kvp->kv_flags & ISCSI_KV_FLAG_RESPONSE) {
		len = os_strlen(kvp->kv_name) + 1;
		len += kv_size_response(kvp->kv_flags);
		len++;
		return len;
	}

	if (!kvp->kv_valp)
		return 0;

	if (!kdefp || !kdefp->fp_size) {
		os_log_info("%s: no size function, kdef 0x%p.\n", kvp->kv_name,
			    kdefp);
		return 0;
	}

	len = os_strlen(kvp->kv_name) + 1;
	pos = vp->v_pos;
	while (vp) {
		if (kdefp->vtype == ISCSI_VALUE_TYPE_LIST) {
			rv = kdefp->fp_size(vp);
			if (rv < 0)
				return rv;
			len += rv + 1;
		} else {
			rv = kdefp->fp_size(vp);
			if (rv < 0)
				return rv;
			len += rv;
		}
		if (kdefp->property & ISCSI_KEY_DECLARE_MULTIPLE) {
			/* values with same v_pos will be on the same line */
			/* the size function should already finished this line */
			/* find the value for the next line */
			for (; vp && vp->v_pos == pos; vp = vp->v_next) ;
			if (vp) {
				len += os_strlen(kvp->kv_name) + 1;
				pos = vp->v_pos;
			}
		} else
			vp = vp->v_next;
	}
	/* null at then end */
	len++;

	return len;
}


int iscsi_kvp_fill_default(iscsi_keyval * kvp)
{
	iscsi_keydef *kdefp = kvp->kv_def;

	if (!kvp->kv_valp && kdefp && (kdefp->property & ISCSI_KEY_HAS_DEFAULT)) {
		kvp->kv_valp = iscsi_value_alloc();
		if (!kvp->kv_valp)
			return -ISCSI_ENOMEM;
		kvp->kv_valp->v_num[0] = kdefp->val_dflt;
		kvp->kv_valp->v_num_used = 1;
	}
	return 0;
}

int iscsi_kvp_value_delete(iscsi_keyval * kvp, iscsi_value * vp, char *ebuf)
{
	int     rv;
	char    buf[ISCSI_TEXT_VALUE_MAX_LEN + 1];
	iscsi_value *vp_orig;
	iscsi_keydef *kdefp = kvp->kv_def;

	vp_orig = iscsi_value_list_find_value(kvp->kv_valp, vp);

	if (!vp_orig) {
		*buf = '\0';
		rv = kdefp->fp_encode(buf, vp);
		if (ebuf)
			sprintf(ebuf + os_strlen(ebuf),
				"%s: already deleted.\n", buf);
		os_log_info("%s: already added.\n", buf);
		return 0;
	}

	rv = iscsi_value_list_remove_by_ptr(&kvp->kv_valp, vp_orig);
	if (rv < 0)
		return rv;

	vp_orig->v_next = NULL;
	iscsi_value_free(vp_orig, kvp->kv_name);
	return 0;
}

/* write the key-value pair to buffer, seperated by 1 byte "seperator" */
#define WRITE_SEPERATOR(ch, seperator, len) \
        if ((seperator) != ISCSI_KV_WRITE_NO_SEPERATOR) {	\
            ch = seperator; \
            len += 1; \
        }

int iscsi_kvp_write_text(int buflen, char *buf, iscsi_keyval * kvp, char prefix,
			 char postfix, int mark_as_sent)
{
	int     rv;
	int     baselen, len;
	unsigned int pos;
	iscsi_keydef *kdefp;
	iscsi_value *vp;

	if (!buflen || !buf || !kvp) {
		return -ISCSI_ENULL;
	}

	baselen = len = os_strlen(buf);

	if (kvp->kv_flags & ISCSI_KV_FLAG_RESPONSE) {
		WRITE_SEPERATOR(buf[len], prefix, len);
		len += sprintf(buf + len, "%s=", kvp->kv_name);

		rv = kv_encode_response(buf + len, kvp->kv_flags);
		if (rv < 0)
			return rv;
		len += rv;
		goto done;
	}

	if (!(kvp->kv_valp))
		return 0;

	kdefp = kvp->kv_def;
	if (!kdefp)
		return 0;

	if (!kdefp->fp_encode) {
		os_log_info("%s: no encode function.\n", kvp->kv_name);
		return 0;
	}

	WRITE_SEPERATOR(buf[len], prefix, len);
	len += sprintf(buf + len, "%s=", kvp->kv_name);

	vp = kvp->kv_valp;
	pos = vp->v_pos;

	while (vp) {
		if (kdefp->vtype == ISCSI_VALUE_TYPE_LIST) {
			if (buf[len - 1] != '=') {
				buf[len] = ',';
				len++;
			}
			rv = kdefp->fp_encode(buf + len, vp);
			if (rv < 0)
				return rv;
			len += rv;
		} else {
			rv = kdefp->fp_encode(buf + len, vp);
			if (rv < 0)
				return rv;
			len += rv;
		}

		if (kdefp->property & ISCSI_KEY_DECLARE_MULTIPLE) {
			/* values with same v_pos will be on the same line */
			/* the encode function should already finished this line */
			/* find the value for the next line */
			for (; vp && vp->v_pos == pos; vp = vp->v_next) ;
			if (vp) {
				WRITE_SEPERATOR(buf[len], postfix, len);
				WRITE_SEPERATOR(buf[len], prefix, len);
				len += sprintf(buf + len, "%s=", kvp->kv_name);
				pos = vp->v_pos;
			}
		} else {
			vp = vp->v_next;
		}
	}

      done:
	WRITE_SEPERATOR(buf[len], postfix, len);
	if (mark_as_sent) {
		kvp->kv_flags &= ~ISCSI_KV_FLAG_SEND;
		if (kvp->kv_flags & ISCSI_KV_FLAG_RESPONSE) {
			kvp->kv_flags &= ~ISCSI_KV_FLAG_RESPONSE;
			kvp->kv_rcvcnt--;
		} else
			kvp->kv_flags |= ISCSI_KV_FLAG_SENT;
	}

	if (kvp->kv_flags & ISCSI_KV_FLAG_DROP_AFTER_SEND) {
		kvp->kv_flags &= ~ISCSI_KV_FLAG_DROP_AFTER_SEND;
		iscsi_value_free(kvp->kv_valp, kvp->kv_name);
		kvp->kv_valp = NULL;
	}

	return (len - baselen);
}

/* move kvp_f's value to kvp_t */
int iscsi_kvp_merge_value(iscsi_keyval * kvp_f, iscsi_keyval * kvp_t)
{
	iscsi_keydef *kdefp = kvp_t->kv_def;
	iscsi_value *vp_f = kvp_f->kv_valp;
	iscsi_value *vp_t = kvp_t->kv_valp;

	if (!kvp_f->kv_valp)
		return 0;
	if (kvp_f->kv_flags & ISCSI_KV_FLAG_RESPONSE)
		return 0;

	/* If the key does not allow multiple declaration, error */
	if (vp_t && !kvp_t->kv_rcvcnt) {
		iscsi_value_free(vp_t, kvp_t->kv_name);
		kvp_t->kv_valp = NULL;
		vp_t = NULL;
	}

	if (vp_t && !(kdefp->property & ISCSI_KEY_DECLARE_MULTIPLE)) {
		os_log_info("%s: rcv'd/declared too many times.\n",
			    kdefp->name);
		return -ISCSI_EINVAL;
	}

	iscsi_value_list_append(&kvp_t->kv_valp, vp_f);
	kvp_t->kv_rcvcnt += kvp_f->kv_rcvcnt;

	kvp_f->kv_valp = NULL;
	kvp_f->kv_rcvcnt = 0;

	return 0;
}

/*
 * APIs for kvlist (list of iscsi_keyval)
 */
int iscsi_kvlist_display(int kmax, iscsi_keyval * kvlist)
{
	int     i;
	iscsi_keyval *kvp;
	for (kvp = kvlist, i = 0; i < kmax; i++, kvp++) {
		iscsi_kvp_display(kvp);
	}
	return 0;
}

iscsi_keyval *iscsi_kvlist_alloc(int max, iscsi_keydef * kdef)
{
	int     i;
	iscsi_keydef *kdefp = kdef;
	iscsi_keyval *kvlist, *kvp;

	kvlist = os_alloc(max * sizeof(iscsi_keyval), 1, 1);
	if (!kvlist)
		return NULL;
	/* os_alloc does memset() */

	if (!kdef)
		return kvlist;

	for (kvp = kvlist, i = 0; i < max; i++, kvp++, kdefp++) {
		kvp->kv_def = kdefp;
		kvp->kv_name = kdefp->name;
	}

	return kvlist;
}

void iscsi_kvlist_free(int max, iscsi_keyval * kvlist)
{
	int     i;
	iscsi_keyval *kvp;

	if (!kvlist)
		return;

	kvp = kvlist;
	for (kvp = kvlist, i = 0; i < max; i++, kvp++) {
		iscsi_value_free(kvp->kv_valp, kvp->kv_name);
	}

	os_free(kvlist);
}

int iscsi_kvlist_fill_default(int kmax, iscsi_keyval * kvlist)
{
	int     i;
	iscsi_keyval *kvp;

	for (kvp = kvlist, i = 0; i < kmax; i++, kvp++) {
		int     rv;
		rv = iscsi_kvp_fill_default(kvp);
		if (rv < 0)
			return rv;
	}

	return 0;
}

int iscsi_kvlist_get_value_by_index(int idx, iscsi_keyval *kvlist,
				iscsi_keydef *def_tbl, unsigned int *val)
{
	iscsi_keyval *kvp = kvlist ? kvlist + idx : NULL;
	iscsi_keydef *kdef = def_tbl + idx;

	if (!kvp || !kvp->kv_valp) {
		if (!def_tbl) {
			os_log_info("kvlist idx %d NULL, no default found.\n",
				idx);
			return -ISCSI_EINVAL;
		}
		*val = kdef->val_dflt;
	} else
		*val = kvp->kv_valp->v_num[0];

	return 0;
}

/* check if the key is irrelevant in discovery */
int iscsi_kvlist_check_key_property_in_discovery(int max, iscsi_keyval * kvlist)
{
	int     i;

	if (!kvlist) {
		os_log_info("list (%d) discovery check ailed (0x%p).\n", max,
			    kvlist);
		return -ISCSI_ENULL;
	}

	for (i = 0; i < max; i++, kvlist++) {
		if (kvlist->kv_valp) {
			iscsi_keydef *kdefp = kvlist->kv_def;
			if (!kdefp)
				return -ISCSI_ENULL;
			if (kdefp->property & ISCSI_KEY_IRRELEVANT_IN_DISCOVERY) {
				kvlist->kv_flags |= ISCSI_KV_FLAG_IRRELEVANT;
				iscsi_value_free(kvlist->kv_valp,
						 kvlist->kv_name);
				kvlist->kv_valp = NULL;
			}
		}
	}
	return 0;
}

/* compute kv1 and kv2, and save the result in kv2 */
int iscsi_kvlist_compute_value(int max, iscsi_keyval * kv1, iscsi_keyval * kv2)
{
	int     i;

	if (!kv1 || !kv2) {
		os_log_info("list (%d) compute failed (0x%p, 0x%p).\n", max,
			    kv1, kv2);
		return -ISCSI_ENULL;
	}

	for (i = 0; i < max; i++, kv1++, kv2++) {
		iscsi_keydef *kdefp = kv2->kv_def;
		if (kdefp->fp_compute && kv1->kv_valp && kv2->kv_valp) {
			int     rv;
			rv = kdefp->fp_compute(kv1, kv2);
			if (rv < 0)
				return rv;
			kv2->kv_flags |= ISCSI_KV_FLAG_COMPUTED;
		}
	}

	return 0;
}

/* check for computed value kv2 from kv1 */
int iscsi_kvlist_check_compute_value(int max, iscsi_keyval * kv1, iscsi_keyval * kv2)
{
	int     i;

	if (!kv1 || !kv2) {
		os_log_info("list (%d) compute failed (0x%p, 0x%p).\n", max,
			    kv1, kv2);
		return -ISCSI_ENULL;
	}

	for (i = 0; i < max; i++, kv1++, kv2++) {
		iscsi_keydef *kdefp = kv2->kv_def;
		if (kdefp->fp_compute_check && kv1->kv_valp && kv2->kv_valp) {
			int     rv;
			rv = kdefp->fp_compute_check(kv1, kv2);
			if (rv < 0) {
				return rv;
			}
		}
	}

	return 0;
}

/* copy all the values of kvp_fr and add to kvp_t */
int iscsi_kvlist_duplicate_value(int max, iscsi_keyval * kvp_f,
				 iscsi_keyval * kvp_t)
{
	int     i;

	if (!kvp_f || !kvp_t) {
		os_log_info("list (%d) dup failed (0x%p, 0x%p).\n", max, kvp_f,
			    kvp_t);
		return -ISCSI_ENULL;
	}

	for (i = 0; i < max; i++, kvp_f++, kvp_t++) {
		iscsi_value *vp;
		if (!kvp_f->kv_valp)
			continue;
		if (kvp_f->kv_flags & ISCSI_KV_FLAG_RESPONSE)
			continue;

		vp = iscsi_value_duplicate_list(kvp_f->kv_valp);
		if (!vp)
			return -ISCSI_ENOMEM;

		iscsi_value_list_append(&kvp_t->kv_valp, vp);
	}
	return 0;
}

/* merge value and flag */
int iscsi_kvlist_merge_value(int merge_flag, int max, iscsi_keyval * kvp_f,
		     iscsi_keyval * kvp_t)
{
	int     i;

	if (!kvp_f || !kvp_t) {
		os_log_info("list (%d) merge failed (0x%p, 0x%p).\n", max,
			    kvp_f, kvp_t);
		return -ISCSI_ENULL;
	}

	for (i = 0; i < max; i++, kvp_f++, kvp_t++) {
		int     rv;
		if (merge_flag) {
			kvp_t->kv_flags |= kvp_f->kv_flags;
		}
		if (kvp_f->kv_flags & ISCSI_KV_FLAG_RESPONSE)
			continue;
		if (!kvp_f->kv_valp)
			continue;
		kvp_t->kv_flags |= kvp_f->kv_flags;

		rv = iscsi_kvp_merge_value(kvp_f, kvp_t);
		if (rv < 0)
			return rv;
	}
	return 0;
}

/* compute buffer size needed for all the key value pairs,
   only the ones with ISCSI_KV_FLAG_SEND set will be included */
int iscsi_kvlist_size_text(int max, iscsi_keyval * kvlist)
{
	int     i;
	int     len = 0;
	iscsi_keyval *kvp = kvlist;

	if (!kvlist) {
		os_log_info("list (%d) size failed (0x%p).\n", max, kvlist);
		return -ISCSI_ENULL;
	}

	for (i = 0; i < max; i++, kvp++) {
		if (kvp->kv_flags & ISCSI_KV_FLAG_SEND) {
			int     rv;
			rv = iscsi_kvp_size_text(kvp);
			if (rv < 0)
				return rv;
			len += rv;
		}
	}

	return len;
}

/* write all key-value pairs to buffer, only the ones with "flag" set
   will be included */
int iscsi_kvlist_write_text(int max, iscsi_keyval * kvlist, int use_kdef,
			    unsigned int match_flag, char prefix, char postfix,
			    char *buf, int buflen, int mark_as_sent)
{
	int     i;
	int     baselen, len;
	iscsi_keyval *kvp = kvlist;

	if (!buf || !kvlist) {
		return -ISCSI_ENULL;
	}

	len = baselen = os_strlen(buf);

	for (i = 0; i < max; i++, kvp++) {
		if ((use_kdef && (kvp->kv_def->property & match_flag)) ||
		    (!use_kdef && (kvp->kv_flags & match_flag))) {
			int     rv;
			buf[len] = 0;
			rv = iscsi_kvp_write_text(buflen - len, buf + len, kvp,
						  prefix, postfix,
						  mark_as_sent);
			if (rv < 0)
				return rv;
			len += rv;
		}
	}

	return (len - baselen);
}


int iscsi_kvlist_match_key(char *keystr, int kmax, iscsi_keyval * kvlist)
{
	int     i;
	iscsi_keydef *kdef;
	iscsi_keyval *kvp;

	for (i = 0, kvp = kvlist; i < kmax; i++, kvp++) {
		kdef = kvp->kv_def;
		/* match is found */
		if (!os_strcmp(kdef->name, keystr))
			break;
	}
	if (i == kmax)
		return -ISCSI_ENOMATCH;

	return i;
}
