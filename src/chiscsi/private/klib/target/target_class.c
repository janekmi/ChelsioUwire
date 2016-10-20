#include <common/os_export.h>
#include <common/os_builtin.h>
#include <common/iscsi_debug.h>
#include <common/iscsi_error.h>
#include <common/iscsi_queue.h>
#include <common/iscsi_target_class.h>
#include <common/iscsi_target_device.h>

/* target class queue */
static chiscsi_queue *tclassq = NULL;
extern chiscsi_target_class tclass_chelsio;

int chiscsi_target_is_chelsio(chiscsi_target_class *tclass)
{
	return tclass && !os_strcmp(tclass->class_name, CHELSIO_TARGET_CLASS);
}
/*
 * chiscsi_target_class
 */
#define chiscsi_target_class_enqueue(L,Q,P) \
	ch_enqueue_tail(L,chiscsi_target_class,next,Q,P)
#define chiscsi_target_class_dequeue(L,Q,P) \
	ch_dequeue_head(L,chiscsi_target_class,next,Q,P)
#define chiscsi_target_class_ch_qremove(L,Q,P) \
	ch_qremove(L,chiscsi_target_class,next,Q,P)
#define chiscsi_target_class_qsearch_by_name(L,Q,P,S) \
	ch_qsearch_by_field_string(L,chiscsi_target_class,next,Q,P,class_name,S)

static void target_class_destroy(chiscsi_target_class *tclass)
{
	chiscsi_target_lun_class *lclass, *lnext;

	lclass = tclass->lclass_list;
	while(lclass) {
		lnext = lclass->next;
		os_free(lclass);
		lclass = lnext;
	}
	os_free(tclass);
}

chiscsi_target_class *iscsi_target_class_default(void)
{
	return (tclassq ? tclassq->q_head : NULL);
}

chiscsi_target_class *iscsi_target_class_find_by_name(char *name)
{
	chiscsi_target_class *tclass;	
	if (!tclassq)
		return NULL;
	chiscsi_target_class_qsearch_by_name(lock, tclassq, tclass, name);
	return tclass;
}

int chiscsi_target_class_register(chiscsi_target_class *tclass)
{
	chiscsi_target_class *dup;

	if (!tclassq)
		return -ISCSI_EINVAL;

	if (!tclass->class_name) {
		os_log_error("Target class, missing class_name.\n", 0);
		return -ISCSI_EINVAL;
	}

	chiscsi_target_class_qsearch_by_name(lock, tclassq, dup, 
					     tclass->class_name);
	if (dup) {
		os_log_error("Target class %s, already existed.\n",
			     tclass->class_name);
		return -ISCSI_EINVAL;
	}

	dup = os_alloc(sizeof(chiscsi_target_class)+
		       os_strlen(tclass->class_name) + 1, 1, 1);
	if (!dup) {
		os_log_error("Target class %s, OOM.\n", tclass->class_name);
		return -ISCSI_ENOMEM;
	}
	memcpy(dup, tclass, sizeof(chiscsi_target_class));
	dup->class_name = (char *)(dup + 1);
	os_strcpy(dup->class_name, tclass->class_name);
	dup->next = NULL;
	dup->lclass_list = NULL;

	os_log_info("Target class %s, added.\n", tclass->class_name);
	chiscsi_target_class_enqueue(lock, tclassq, dup);
	return 0;
}

int chiscsi_target_class_deregister(char *tname)
{
	chiscsi_target_class *tclass;

	if (!tclassq)
		return 0;

	chiscsi_target_class_qsearch_by_name(lock, tclassq, tclass, tname);
	if (!tclass) {
		os_log_warn("Target class %s not found.\n", tname);
		return -ISCSI_EINVAL;
	}

	os_log_info("Target class %s removed.\n", tclass->class_name);

	chiscsi_target_class_ch_qremove(lock, tclassq, tclass);
	target_class_destroy(tclass);
	/* remove all the targets? */	

	return 0;
}

/*
 * chiscsi_target_lun_class
 */
chiscsi_target_lun_class *chiscsi_target_lun_class_find_by_name(int lock,
				chiscsi_target_class *tclass, char *lname)
{
	chiscsi_target_lun_class *lclass = tclass->lclass_list;

	if (!tclassq)
		return NULL;

	if (lock)
		os_lock(tclassq->q_lock);
	for (; lclass; lclass = lclass->next) {
		if (!os_strcmp(lclass->class_name, lname))
			break;
	}
	if (lock)
		os_unlock(tclassq->q_lock);
	return lclass;
}

static inline void lun_class_add(chiscsi_target_class *tclass,
			 chiscsi_target_lun_class *lclass)
{
	chiscsi_target_lun_class *last = tclass->lclass_list;
	for (; last && last->next; last = last->next)
		;

	/* insert at the end */
	if (!last)
		tclass->lclass_list = lclass;
	else
		last->next = lclass;

	/* 
	 * check for property:
	 * if either LUN_CLASS_SCSI_PASS_THRU_BIT or
	 * 	LUN_CLASS_MULTI_PHASE_DATA_BIT is set, 
	 * then set LUN_CLASS_HAS_CMD_QUEUE_BIT.
	 * We don't want those lun class execute in the context of chelsio
	 * stack.
	 */
	if (lclass->property & 
	    ((1 << LUN_CLASS_SCSI_PASS_THRU_BIT) | 
	     (1 << LUN_CLASS_MULTI_PHASE_DATA_BIT))) {
		lclass->property |= 1 << LUN_CLASS_HAS_CMD_QUEUE_BIT;
		os_log_info("TARGET Class %s, LUN class %s, property 0x%x.\n",
				tclass->class_name, lclass->class_name,
				lclass->property);
	}

	lclass->next = NULL;
}

static inline chiscsi_target_lun_class *lun_class_remove_by_name(
				chiscsi_target_class *tclass, char *lname)
{
	chiscsi_target_lun_class *prev = NULL;
	chiscsi_target_lun_class *curr = tclass->lclass_list;

	for (; curr; prev = curr, curr = curr->next) {
		if (!os_strcmp(curr->class_name, lname))
			break;
	}

	/* a match is found */
	if (curr) {
		if (prev)
			prev->next = curr->next;
		else
			tclass->lclass_list = curr->next;
	}

	return curr;
}

chiscsi_target_lun_class *chiscsi_target_lun_class_default(chiscsi_target_class *tclass)
{
	return (tclass ? tclass->lclass_list : NULL);
}

int chiscsi_target_lun_class_register(chiscsi_target_lun_class *lclass,
				      char *tname)
{
	chiscsi_target_class *tclass;
	chiscsi_target_lun_class *dup, *tmp;
	int rv = 0;

	if (!tclassq)
		return -ISCSI_EINVAL;

	if (!lclass->class_name) {
		os_log_error("LUN class, missing class_name.\n", rv);
		return -ISCSI_EINVAL;
	}

	if (!lclass->fp_scsi_cmd_cdb_rcved ||
	    !lclass->fp_scsi_cmd_data_xfer_status ||
	    !lclass->fp_scsi_cmd_abort ||
	    !lclass->fp_tmf_execute) {
		os_log_error("LUN class %s, missing fp_scsi_cmd_xxx or fp_tmf_xx.\n",
			     lclass->class_name);
		return -ISCSI_EINVAL;
	}

	dup = os_alloc(sizeof(chiscsi_target_lun_class)+
		       os_strlen(lclass->class_name) + 1, 1, 1);
	if (!dup) {
		os_log_error("LUN class %s, OOM.\n", lclass->class_name);
		return -ISCSI_ENOMEM;
	}
	memcpy(dup, lclass, sizeof(chiscsi_target_lun_class));
	dup->class_name = (char *)(dup + 1);
	os_strcpy(dup->class_name, lclass->class_name);
	dup->next = NULL;

	os_lock(tclassq->q_lock);
	chiscsi_target_class_qsearch_by_name(nolock, tclassq, tclass, tname);
	if (!tclass) {
		os_unlock(tclassq->q_lock);
		os_log_error("Target class %s missing.\n", tname);
		rv = -ISCSI_EINVAL;
		goto err_out;
	}

	tmp = chiscsi_target_lun_class_find_by_name(0, tclass, lclass->class_name);
	if (tmp) {
		os_unlock(tclassq->q_lock);
		os_log_error("LUN class %s, already existed.\n",
			     lclass->class_name);
		rv = -ISCSI_EINVAL;
		goto err_out;
	}

	dup->tclass = tclass;
	if (!os_strcmp(tclass->class_name, CHELSIO_TARGET_CLASS))
		dup->property |= 1 << LUN_CLASS_CHELSIO_BIT;


	lun_class_add(tclass, dup);
	os_unlock(tclassq->q_lock);

	os_log_info("LUN class %s, added to %s.\n", dup->class_name, tname);
	return 0;

err_out:
	os_free(dup);
	return rv;
}

int chiscsi_target_lun_class_deregister(char *lname, char *tname)
{
	chiscsi_target_class *tclass;
	chiscsi_target_lun_class *lclass;
	int rv = 0;

	if (!tclassq)
		return -ISCSI_EINVAL;

	os_lock(tclassq->q_lock);
	chiscsi_target_class_qsearch_by_name(nolock, tclassq, tclass, tname); 
	if (!tclass) {
		os_log_warn("Target class %s missing.\n", tname);
		rv = -ISCSI_EINVAL;
		goto out;
	}

	lclass = lun_class_remove_by_name(tclass, lname);
	if (lclass) {
		os_log_info("LUN class %s removed from %s.\n", lname, tname);
		os_free(lclass);
	} else {
		os_log_warn("class %s, %s, missing.\n", tname, lname);
		rv = -ISCSI_EINVAL;
		goto out;
	}

out:
	os_unlock(tclassq->q_lock);
	return rv;
}

int iscsi_target_class_luns_has_property(int lock, int property_bit,
					 chiscsi_target_class *tclass)
{
	chiscsi_target_lun_class *lclass = tclass->lclass_list;
	int match = 0;

	if (!tclassq)
		return 0;

	if (lock)
		os_lock(tclassq->q_lock);
	for (; lclass && !match; lclass = lclass->next) {
		if (lclass->property & (1 << property_bit))
			match = 1;
	}
	if (lock)
		os_unlock(tclassq->q_lock);
	return match;
}

void target_class_cleanup(void)
{
	if (tclassq) {
		chiscsi_target_class *tclass;

		os_lock(tclassq->q_lock);
		chiscsi_target_class_dequeue(nolock, tclassq, tclass);
		while(tclass) {
			target_class_destroy(tclass);
			chiscsi_target_class_dequeue(nolock, tclassq, tclass);
		}
		os_unlock(tclassq->q_lock);
		ch_queue_free(tclassq);
		tclassq = NULL;
	}
}

int target_class_init(void)
{
	if (!tclassq) {
		ch_queue_alloc(tclassq);
		if (!tclassq)
			return -ISCSI_ENOMEM;
	}
        return 0;

q_lock_fail:
	ch_queue_free(tclassq);
	return -ISCSI_ENOMEM;
}

int is_chelsio_lun_class(chiscsi_target_lun_class *lclass) 
{
	char *tname = tclass_chelsio.class_name;
	chiscsi_target_lun_class *lc = NULL;
	chiscsi_target_class *tclass = NULL;

	if (!tclassq) 
		return -ISCSI_EINVAL;

	chiscsi_target_class_qsearch_by_name(nolock, tclassq, tclass, tname);
        if (!tclass) {
		return 0;
        }

	/* Given lclass IS chelsio lun class */
	if (lclass) 
	        lc = chiscsi_target_lun_class_find_by_name(0, tclass, lclass->class_name);
	
        if (lc) {
		return 1;
        }

        return 0;
}
