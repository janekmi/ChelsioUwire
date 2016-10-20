#include <iscsi_structs.h>
#include "iscsi_text_private.h"

/*
 * APIs for iscsi_value struct
 */

/* allocate a single value struct */
iscsi_value *iscsi_value_alloc(void)
{
	iscsi_value *vp;

	vp = os_alloc(sizeof(iscsi_value), 1, 1);
	if (vp)
		/* os_alloc does memset() */
		vp->v_next = NULL;
	return vp;
}

void iscsi_value_free(iscsi_value * vp, char *name)
{
	int     i;

	if (!vp)
		return;
	
	while (vp) {
		iscsi_value *next = vp->v_next;
		if (vp->v_flag & ISCSI_VALUE_FLAG_LOCKED) {
			vp = next;
			continue;
		}
		for (i = 0; i < ISCSI_VALUE_STR_COUNT_MAX; i++) {
			if (vp->v_str_used && vp->v_str[i]) {
				if (i < vp->v_str_used) {
					if (vp->v_str[i])
						os_free(vp->v_str[i]);
					vp->v_str[i] = NULL;
				} else {
					os_log_info
						("%s: v_str %d, used %d, 0x%p.\n",
						 name, i, vp->v_str_used,
						 vp->v_str[i]);
				}
			}
		}
		for (i = 0; i < ISCSI_VALUE_DATA_COUNT_MAX; i++) {
			if (vp->v_data_used && vp->v_data[i]) {
				if (i < vp->v_data_used) {
					if (vp->v_data[i])
						os_free(vp->v_data[i]);
					vp->v_data[i] = NULL;
				} else {
					os_log_info
						("%s: v_data %d, used %d, 0x%p.\n",
						 name, i, vp->v_data_used,
						 vp->v_data[i]);
				}
			}
		}
		os_free(vp);

		vp = next;
	}
}

iscsi_value *iscsi_value_list_find_value(iscsi_value * vlist, iscsi_value * vp)
{
	for (; vlist; vlist = vlist->v_next) {
		int     num_match = 1, str_match = 1;

		if (vp->v_num_used) {
			int     i;
			if (vlist->v_num_used != vp->v_num_used)
				continue;
			for (i = 0; i < vlist->v_num_used; i++) {
				if (vlist->v_num[i] != vp->v_num[i]) {
					num_match = 0;
					break;
				}
			}
			if (!num_match)
				continue;
		}

		if (vp->v_str_used) {
			int     i;
			if (vlist->v_str_used != vp->v_str_used)
				continue;
			for (i = 0; i < vlist->v_num_used; i++) {
				if (os_strcmp(vlist->v_str[i], vp->v_str[i])) {
					str_match = 0;
					break;
				}
			}
			if (!str_match)
				continue;
		}

		return vlist;
	}

	return NULL;
}

/* NOTE: vp could be a list */
void iscsi_value_list_append(iscsi_value ** vlistpp, iscsi_value * vp)
{
	if (!(*vlistpp)) {
		*vlistpp = vp;
	} else {
		iscsi_value *vlist = *vlistpp;
		for (; vlist->v_next; vlist = vlist->v_next) ;
		vlist->v_next = vp;
	}
}

int iscsi_value_list_remove_by_ptr(iscsi_value ** vlistpp, iscsi_value * valp)
{
	iscsi_value *vp, *prev;
	if (!vlistpp || !(*vlistpp) || !valp) {
		return -ISCSI_ENULL;
	}

	for (prev = NULL, vp = *vlistpp; vp && vp != valp;
	     prev = vp, vp = vp->v_next) ;
	if (vp != valp)
		return -ISCSI_EINVAL;

	if (prev)
		prev->v_next = vp->v_next;
	else
		*vlistpp = vp->v_next;

	vp->v_next = NULL;
	return 0;
}

/* duplicate a list of value structs */
iscsi_value *iscsi_value_duplicate_list(iscsi_value * valp)
{
	iscsi_value *head = NULL, *tail = NULL;

	while (valp) {
		iscsi_value *vp;
		int     i;
		vp = iscsi_value_alloc();
		if (!vp) {
			goto err_out;
		}
		memcpy(vp, valp, sizeof(iscsi_value));

		/* append at end of head */
		if (head) {
			tail->v_next = vp;
			tail = vp;
		} else {
			head = tail = vp;
		}

		/* duplicate the values */
		for (i = 0; i < valp->v_num_used; i++) {
			vp->v_num[i] = valp->v_num[i];
		}

		for (i = 0; i < valp->v_str_used; i++) {
			vp->v_str[i] = os_strdup(valp->v_str[i]);
			if (!vp->v_str[i]) {
				goto err_out;
			}
		}

		/* do NOT copy the data */
		vp->v_data_used = 0;
		for (i = 0; i < valp->v_data_used; i++) {
			vp->v_data[i] = NULL;
		}

		vp->v_next = NULL;
		valp = valp->v_next;
	}

	return head;

      err_out:
	if (head) {
		iscsi_value_free(head, NULL);
	}
	return NULL;
}
