/*
 * iscsi_struct.c -- iscsi structures
 */

#include <common/os_builtin.h>
#include <common/iscsi_control.h>
#include <iscsi_control_defs.h>
#include <iscsi_structs.h>
#include <iscsi_global.h>
#include <iscsi_config_keys.h>
#include <iscsi_session_keys.h>
#include <iscsi_connection_keys.h>
#include <iscsi_socket_api.h>
#include <iscsi_auth_api.h>
#include <iscsi_target_api.h>

/*
 * ulong mask array 
 */
INLINE int iscsi_ulong_mask_set(unsigned long *maskp, int start, int end)
{
	int     i;
	int     bit = start & ((1 << iscsi_ulong_mask_shift) - 1);
	int     idx = start >> iscsi_ulong_mask_shift;

	for (i = start; i <= end; i++, bit++) {
		if (bit == iscsi_ulong_mask_bits) {
			idx++;
			bit = 0;
		}
		maskp[idx] |= 1 << bit;
	}

	return idx;
}

/*
 * memory utility
 */
void   *iscsi_enlarge_memory(void *dp, unsigned int old_size,
			     unsigned int new_size, int free)
{
	unsigned char *oldp = (unsigned char *) dp;
	unsigned char *newp = NULL;

	if (old_size >= new_size) {
		os_log_warn("enlarge, size %u <= old size %u.\n", new_size,
			    old_size);
		return NULL;
	}

	newp = os_alloc(new_size, 1, 1);
	if (!newp)
		return NULL;
	/* os_alloc does memset() */
	if (old_size)
		memcpy(newp, oldp, old_size);
	if (free && oldp)
		os_free(oldp);

	return ((void *) newp);
}

/*
 * iscsi table
 */
void iscsi_table_free(iscsi_table * tbl, void (*fp_free_elem) (void *))
{
	if (!tbl || !tbl->tbl_entry) {
		return;
	}
	os_lock(tbl->tbl_lock);
	if (fp_free_elem) {
		int     i;
		void   *dp;
		for (i = 0, dp = tbl->tbl_entry; i < tbl->tbl_size; i++, dp++) {
			if (dp) {
				fp_free_elem(dp);
				dp = NULL;
			}
		}
	}
	os_free(tbl->tbl_entry);
	tbl->tbl_entry = NULL;
	os_unlock(tbl->tbl_lock);
	os_free(tbl);
}

iscsi_table *iscsi_table_alloc(unsigned int table_size)
{
	iscsi_table *tbl;
	void  **list;
	int     offset = sizeof(iscsi_table);

	tbl = os_alloc(ISCSI_TABLE_SIZE, 1, 1);
	if (!tbl)
		return NULL;
	/* os_alloc does memset() */

	tbl->tbl_lock = (void *) (PTR_OFFSET(tbl, offset));
	os_lock_init(tbl->tbl_lock);
	offset += os_lock_size;

	list = os_alloc((table_size * sizeof(void *)), 1, 1);
	if (!list) {
		os_free(tbl);
		return NULL;
	}
	/* os_alloc does memset() */

	tbl->tbl_size = table_size;
	tbl->tbl_entry = list;
	return tbl;
}

/* caller should hold the lock */
STATIC INLINE int iscsi_table_expand(iscsi_table * tbl,
				     unsigned int new_table_size)
{
	void   *list_old = tbl->tbl_entry;
	void   *list;

	if (new_table_size <= tbl->tbl_size)
		return 0;
	list = (unsigned char *) iscsi_enlarge_memory((void *) list_old,
						      (tbl->tbl_size *
						       sizeof(void *)),
						      (new_table_size *
						       sizeof(void *)), 0);
	if (!list)
		return -ISCSI_ENOMEM;

	os_lock(tbl->tbl_lock);
	tbl->tbl_size = new_table_size;
	tbl->tbl_entry = list;
	os_unlock(tbl->tbl_lock);

	os_free(list_old);
	return 0;
}

int iscsi_table_remove_element_by_ptr(iscsi_table * tbl, void *elemp)
{
	int     i;
	void  **list;

	if (!tbl || !elemp) {
		os_log_error("tbl 0x%p, remove elemp 0x%p.\n", tbl, elemp);
		return -ISCSI_ENULL;
	}

	os_lock(tbl->tbl_lock);
	list = tbl->tbl_entry;
	if ((tbl->tbl_size && !list) || (tbl->tbl_used > tbl->tbl_size)) {
		os_unlock(tbl->tbl_lock);
		os_log_error("remove, tbl size %u/%u, list 0x%p.\n",
			     tbl->tbl_used, tbl->tbl_size, list);
		return -ISCSI_EINVAL;
	}
	for_each_table_entry(tbl, i) {
		if (list[i] && list[i] == elemp) {
			list[i] = NULL;
			tbl->tbl_used--;
			os_unlock(tbl->tbl_lock);
			return 0;
		}
	}
	os_unlock(tbl->tbl_lock);
	return -ISCSI_ENOTFOUND;
}

void   *iscsi_table_find_element_by_idx(iscsi_table * tbl, int idx)
{
	void   *elemp;

	if (!tbl || idx < 0 || idx >= tbl->tbl_size) {
		os_log_error("tbl find 0x%p, %u, idx %d.\n",
			     tbl, tbl ? tbl->tbl_size : 0, idx);
		return NULL;
	}
	os_lock(tbl->tbl_lock);
	elemp = tbl->tbl_entry[idx];
	os_unlock(tbl->tbl_lock);

	return (elemp);
}

int iscsi_table_remove_element_by_idx(iscsi_table * tbl, void *elemp, int idx)
{
	void  **list;

	if (!tbl || !elemp || idx < 0 || idx >= tbl->tbl_size) {
		os_log_error("tbl 0x%p, elemp 0x%p, %u, remove idx %d.\n",
			     tbl, elemp, tbl ? tbl->tbl_size : 0, idx);
		return -ISCSI_EINVAL;
	}
	os_lock(tbl->tbl_lock);
	list = tbl->tbl_entry;
	if (list[idx] && list[idx] == elemp) {
		list[idx] = NULL;
		tbl->tbl_used--;
		os_unlock(tbl->tbl_lock);
		return 0;
	}
	os_unlock(tbl->tbl_lock);

	return -ISCSI_ENOMATCH;
}

int iscsi_table_add_element_by_idx(iscsi_table * tbl, void *elemp, int idx,
				   int lock)
{
	if (lock)
		os_lock(tbl->tbl_lock);
	if (idx >= tbl->tbl_size) {
		if (lock)
			os_unlock(tbl->tbl_lock);
		os_log_error("tbl 0x%p, add idx %d >= %u.\n", tbl, idx,
			     tbl->tbl_size);
		return -ISCSI_EINVAL;
	}

	if (!(tbl->tbl_entry[idx]))
		tbl->tbl_used++;
	tbl->tbl_entry[idx] = elemp;

	if (lock)
		os_unlock(tbl->tbl_lock);

	return 0;
}

int iscsi_table_add_element(iscsi_table * tbl, void *elemp, unsigned int incr)
{
	int     idx = -1;
	void  **list;
	int     i;

	if (!tbl || !elemp) {
		return -ISCSI_ENULL;
	}

	if (!incr)
		incr = ISCSI_TABLE_DEFAULT_INCR;

	/* need to expand list */

	os_lock(tbl->tbl_lock);
	if (tbl->tbl_used == tbl->tbl_size) {
		int     rv;
		os_unlock(tbl->tbl_lock);

		rv = iscsi_table_expand(tbl, tbl->tbl_size + incr);
		if (rv < 0)
			return rv;

		os_lock(tbl->tbl_lock);
	}

	list = tbl->tbl_entry;
	for_each_table_entry(tbl, i) {
		if (!list[i])
			break;
	}

	idx = i;
	list[i] = elemp;

	tbl->tbl_used++;

	os_unlock(tbl->tbl_lock);

	return idx;
}

/*
 * misc.
 */

/* dump out bytes in hex */
int iscsi_display_byte_string(char *caption, unsigned char *bytes, int start,
			      int maxlen, char *obuf, int obuflen)
{
	char   *buf = obuf;
	int     buflen = obuflen;
	unsigned char *dp;
	char    buffer[256];
	unsigned int i;
	int     len = 0;

	if (!bytes)
		return 0;
	if (!buf)
		buf = buffer;

	if (caption)
		len = sprintf(buf, "%s: ", caption);
	len += sprintf(buf + len, "%u -- %u:\n", start, (start + maxlen - 1));
	if (!obuf) {
		buf[len] = 0;
		os_log_info("%s", buf);
		len = 0;
	} else {
		if (len >= buflen) {
			buflen = 0;
			goto out;
		}
		buflen -= len;
		buf += len;
		len = 0;
	}

	dp = bytes + start;
	for (i = 0; i < maxlen; i++, dp++) {
		/* dump 16 bytes a time */
		if (i && (i % 16 == 0)) {
			buf[len++] = '\n';
			if (!obuf) {
				buf[len] = 0;
				os_log_info("%s", buf);
				len = 0;
			}
		}
		len += sprintf(buf + len, "%02x ", *dp);
		if (obuf) {
			if (len >= buflen) {
				buflen = 0;
				break;
			}
			buflen -= len;
			buf += len;
		}
	}

	if (len) {
		if (obuf)
			buf[len++] = '\n';
		else {
			buf[len] = 0;
			os_log_info("%s\n", buf);
			len = 0;
		}
	}

      out:
	return (obuf ? (obuflen - buflen) : 0);
}
