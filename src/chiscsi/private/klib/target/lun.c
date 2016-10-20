#include <common/version.h>
#include <common/iscsi_target_device.h>
#include <common/iscsi_scst.h>
#include <iscsi_target_api.h>
#include "iscsi_target_private.h"
#include <common/os_export.h>
#ifdef __KERNEL__
#include <linux/kernel.h>
#endif

extern chiscsi_queue *it_lu_q;

/*
 * chiscsi_target_lun struct allocation & release
 */
static chiscsi_target_lun *lu_alloc(void)
{
	chiscsi_target_lun *lu = os_alloc(ISCSI_TARGET_LUN_SIZE, 1, 1);

	if (!lu)
		return NULL;
	if (!(lu->os_data = os_data_init(lu)))
		goto os_data_fail;
	os_data_counter_set(lu->os_data, 0);

	return lu;

os_data_fail:
	os_free(lu);
	return NULL;
}

int chiscsi_target_luns_has_property(iscsi_node *node, int property_bit)
{
	int i;

	for (i = 0; i < node->lu_cnt; i++) {
		chiscsi_target_lun *lu = node->lu_list[i];
                if (lu->class->property & (1 << property_bit))
			break;
        }

        return (i < node->lu_cnt);
}

/* 
 * lun flush
 */
int iscsi_target_lu_flush(iscsi_node * node, int lun, int all)
{
	chiscsi_target_lun *lu;
	chiscsi_target_lun_class *class;
	int i;

	if (all) {
		for (i = 0; i < node->lu_cnt; i++) {
			lu = node->lu_list[i];
			class = lu->class;
			if (!class->fp_flush) 
				continue;
			class->fp_flush(lu);
		}

		os_log_info("%s: all the luns manually flushed.\n",
			    node->n_name);
	} else {
		lu = iscsi_target_lu_find(node, lun);
		if (lu && lu->class && lu->class->fp_flush) {
			lu->class->fp_flush(lu);
			os_log_info("%s: lun %u manually flushed.\n",
			    	node->n_name, lun);
		}
	}
	return 0;
}

/*
 * target lun configuration
 */
#ifndef O_RDONLY
#define O_RDONLY             00
#endif

chiscsi_target_lun *iscsi_target_session_lun_get_ref(void *sessp, int lun)
{
	iscsi_session *sess = (iscsi_session *)sessp;

	if (sess) {
		iscsi_node *node = (iscsi_node *)sess->s_node;
		int true_lun = lun;
		chiscsi_target_lun *lu;

		lu = iscsi_target_lu_find(node, true_lun);
		if (lu) {
			if (chiscsi_target_lun_flag_test(lu, LUN_OFFLINE_BIT))
				lu = NULL;
			else
				os_data_counter_inc(lu->os_data);
			return lu;
		}

		os_log_error("%s: sess 0x%p, lun %d NOT found, node 0x%p, %u.\n",
				__func__, sess, lun, node,
				node ? node->lu_cnt: 0);
	}
	return NULL;
}


chiscsi_target_lun *iscsi_target_session_lun_get(void *sessp, int lun)
{
	iscsi_session *sess = (iscsi_session *)sessp;

	if (sess) {
		iscsi_node *node = (iscsi_node *)sess->s_node;
		int true_lun = lun;
		chiscsi_target_lun *lu;

		lu = iscsi_target_lu_find(node, true_lun);
		if (lu) {
			if (chiscsi_target_lun_flag_test(lu, LUN_OFFLINE_BIT))
				lu = NULL;
			return lu;
		}

		os_log_error("%s: sess 0x%p, lun %d NOT found, node 0x%p, %u.\n",
				__func__, sess, lun, node,
				node ? node->lu_cnt: 0);
	}
	return NULL;
}

void iscsi_target_session_lun_put_ref(chiscsi_target_lun *lu)
{
	if (!lu)
		return;

	os_data_counter_dec(lu->os_data);

	os_lock_irq_os_data(lu->os_data);
	if (chiscsi_target_lun_flag_test(lu, LUN_OFFLINE_BIT)) {
		if (os_data_counter_read(lu->os_data) == 0) {
			os_unlock_irq_os_data(lu->os_data);
			if (lu->path)
				os_free(lu->path);
			os_data_free(lu->os_data);
			os_free(lu);
			return;
		}
	}
	os_unlock_irq_os_data(lu->os_data);
}

static void generate_string(char *base1, char *base2, char *buf, int buflen)
{
        static char chelsio_oem_id[] = "0743";        /* 00:07:43 */
	int len = os_strlen(chelsio_oem_id);
	int blen1 = os_strlen(base1);
	int blen2 = os_strlen(base2);
	int i = 0, j = 0;
	char val;

	if (buflen < len)
		len = buflen;
	memcpy(buf, chelsio_oem_id, len);
	
	while ((len + 2) < buflen) {
		if (base2) {
			val = base1[blen1 - i - 1] ^ base2[blen2 - j - 1];
			j++;
			if (j > blen2)
				j = 0;
		} else {
	 		val = base1[blen1 - i - 1] ^ base1[i];
		}
		len += sprintf(buf + len, "%02x", val);
		i++;
		if (i >= blen1)
			i = 0;
	}
	/* only 1 char left */
	if (len < buflen) {
 		val = base1[blen1 - i] ^ base1[i];
		val &= 0xF;
		len += sprintf(buf + len, "%01x", val);
	}
	
}

static void generate_wwn(iscsi_node *node, chiscsi_target_lun *lu)
{
	int len;
	char *name = node->n_alias ? node->n_alias : node->n_name;
	char *id = os_strlen(lu->prod_id) ? lu->prod_id : NULL;

	len = sprintf(lu->scsi_wwn, ":W%u", lu->lun);
	generate_string(name, id, lu->scsi_wwn + len, IT_SCSI_WWN_MAX - len);
}

static void generate_scsi_id(iscsi_node *node, chiscsi_target_lun *lu)
{
	int len;
	char *name = node->n_alias ? node->n_alias : node->n_name;
	char *id = os_strlen(lu->prod_id) ? lu->prod_id : NULL;

	len = sprintf(lu->scsi_id, "%uD", lu->lun);
	generate_string(name, id, lu->scsi_id + len, IT_SCSI_ID_MAX - len);
}

static void generate_scsi_sn(iscsi_node *node, chiscsi_target_lun *lu)
{
	int len;
	char *name = node->n_alias ? node->n_alias : node->n_name;
	char *id = os_strlen(lu->prod_id) ? lu->prod_id : NULL;

	len = sprintf(lu->scsi_sn, "%uN", lu->lun);	
	generate_string(name, id, lu->scsi_sn + len, IT_SCSI_SN_MAX - len);
}

int iscsi_target_lu_read_config(iscsi_node *node, char *ebuf, int ebuflen)
{
	chiscsi_target_class *tclass = node->tclass;
	iscsi_keyval *kvp = node->n_keys[NODE_KEYS_CONFIG] +
				ISCSI_KEY_CONF_TARGET_DEVICE;
	iscsi_value *vp;
	chiscsi_target_lun *lu, *dup;
	int i;
	int rv;

	if (!node->n_redirect_on && !kvp->kv_rcvcnt) {
		if(!os_strcmp(tclass->class_name, CHELSIO_TARGET_CLASS))
			os_log_info("0x%p, %s, no target device.\n",
					node, node->n_name);
		return 0;
	}

	for (vp = kvp->kv_valp, i = 0; vp; vp = vp->v_next, i++) {
		lu = lu_alloc();

		if (!lu) {
			if (ebuf && ebuflen)	
				sprintf(ebuf, "%s: lun %d, %s OOM.\n",
					node->n_name, i, vp->v_str[0]);
			os_log_error("%s, lun %d, %s OOM.\n",
				node->n_name, i, vp->v_str[0]);
			rv = -ISCSI_ENOMEM;
			goto err_out;
		}

		node->lu_list[i] = lu;
		lu->sect_shift = lu_sect_shift;
		lu->lun = i;
		lu->tnode_hndl = (unsigned long)node;

		rv = tclass->fp_config_parse_luns(lu, vp->v_str[0],
					os_strlen(vp->v_str[0]), ebuf);
		if (rv < 0)
			goto err_out;

		if (lu->scsi_id[0] == 0)	
			generate_scsi_id(node, lu);
		if (lu->scsi_sn[0] == 0)	
			generate_scsi_sn(node, lu);
		if (lu->scsi_wwn[0] == 0)	
			generate_wwn(node, lu);
		if (lu->prod_id[0] == 0)	
			memcpy(lu->prod_id, IT_PRODUCT_ID, IT_PRODUCT_ID_MAX);
	}

	for (i = 0; i < node->lu_cnt; i++) {
		iscsi_node *n;

		lu = node->lu_list[i];
		os_lock(it_lu_q->q_lock);
		for (dup = it_lu_q->q_head; dup; dup = dup->next) {
			if (lu->class->property &
				(1 << LUN_CLASS_DUP_PATH_ALLOWED_BIT)) {
				iscsi_node *t = (iscsi_node *)dup->tnode_hndl;

				if (!os_strcmp(node->n_name, t->n_name) &&
				    !os_strcmp(lu->path, dup->path))
					break;
			} else if (!os_strcmp(lu->path, dup->path))
				break;
		}
		os_unlock(it_lu_q->q_lock);

		if (!dup)
			continue;

		/* different target */
		n = (iscsi_node *)dup->tnode_hndl;
		if (lu->class != dup->class) {
			if (ebuf)
				sprintf(ebuf, "dev %s already with class %s.\n",
					lu->path, dup->class->class_name);
			os_log_info("dev %s already with class %s.\n",
					lu->path, dup->class->class_name);
			rv = -ISCSI_EDUP;
			goto err_out;
		}
		if (os_strcmp(n->n_name, node->n_name) && 
		    !(lu->class->property & 
				(1 << LUN_CLASS_DUP_PATH_ALLOWED_BIT))) {
			if (ebuf)
				sprintf(ebuf, "%s already has device %s.\n",
					n->n_name, dup->path);
			os_log_info("%s already has device %s.\n",
					n->n_name, dup->path);
			rv = -ISCSI_EDUP;
			goto err_out;
		}

		dup->lun_tmp = lu;
		lu->lun_tmp = dup;
	}
	return 0;

err_out:
	for (i = 0; i < node->lu_cnt; i++) {
		chiscsi_target_lun *lu = node->lu_list[i];
		if (!lu)
			break;
		node->lu_list[i] = NULL;
		if (lu->lun_tmp)
			lu->lun_tmp->lun_tmp = NULL;
		if (lu->path)
			os_free(lu->path);
		os_data_free(lu->os_data);
		os_free(lu);
	}
	return rv;
}

int iscsi_target_lu_duplicate_validate(int reconfig, iscsi_node *node,
				char *ebuf, int ebuflen)
{
	int i;
	chiscsi_target_lun *lu, *dup;

	for (i = 0; i < node->lu_cnt; i++) {
		lu = node->lu_list[i];
		dup = lu->lun_tmp;
		if (!dup)
			continue;

		if (reconfig) {
			if (lu->class != dup->class) {
				if (ebuf)
					sprintf(ebuf,
						"%s class change prohibited.\n",
						dup->path);
				os_log_info("LU %s class change prohibited.\n",
						dup->path);
				return -ISCSI_EINVAL;
			}
			if (chiscsi_target_lun_flag_test(lu, LUN_NONEXCL_BIT) !=
			    chiscsi_target_lun_flag_test(dup, LUN_NONEXCL_BIT)) {
				if (ebuf)
					sprintf(ebuf,
					"%s NONEXCL change prohibited.\n",
					dup->path);
				os_log_info("%s NONEXCL change prohibited.\n",
					dup->path);
				return -ISCSI_EINVAL;
			}
			if (chiscsi_target_lun_flag_test(lu, LUN_RO_BIT) !=
			    chiscsi_target_lun_flag_test(dup, LUN_RO_BIT)) {
				if (ebuf)
					sprintf(ebuf,
					"%s RO change prohibited.\n",
					dup->path);
				os_log_info("%s RO change prohibited.\n",
					dup->path);
				return -ISCSI_EINVAL;
			}

		} else if (!(lu->class->property &
			     (1 << LUN_CLASS_DUP_PATH_ALLOWED_BIT))) {
			iscsi_node *n = (iscsi_node *)dup->tnode_hndl;
			if (ebuf)
				sprintf(ebuf, "dup lu %s, %s.\n",
					dup->path, n->n_name);
			os_log_info("Duplicate LU %s, %s.\n",
					dup->path, n->n_name, dup->path);
			return -ISCSI_EDUP;
		}
	}

	return 0;
}


int iscsi_target_lu_init_reservation(chiscsi_target_lun *lu)
{
	char path[256];
	void *pfd = NULL;
	unsigned long long pos = 0;

	/* Persistent Reservation APTPL support */
	memset(path, '\0', 256);
	snprintf(path, 256, "%s/%d", LUN_PERSISTENT_PATH, lu->lun);
	pfd = os_file_open(path, O_RDONLY, 0);
	if (pfd != NULL) {
		int rv = os_file_read(pfd, &lu->rsv, sizeof(lu->rsv), &pos);
		os_file_close(pfd);
		if (rv == sizeof(lu->rsv))
			lu->aptpl = SPC_APTPL_ON;
		else
			lu->aptpl = SPC_APTPL_OFF;
	} else
		lu->aptpl = SPC_APTPL_UNSUPPORTED;
	return 0;
}

void luq_dump(void)
{
	chiscsi_target_lun *lu;
	int i = 0;
	iscsi_node *node = NULL;

	os_lock(it_lu_q->q_lock);
	for (lu = it_lu_q->q_head; lu; lu = lu->next, i++) {
		if (i >= it_lu_q->q_cnt) {
			os_log_info("LUQ 0x%p, %d > %u.\n", lu, i, it_lu_q->q_cnt);
			break;
		}
		node = (iscsi_node *)lu->tnode_hndl;
		os_log_info("LU 0x%p: %s,%s, ref %u, f 0x%lx, node 0x%p, %s,#%u, 0x%p, 0x%p.\n",
			lu, lu->path, lu->class->class_name,
			os_data_counter_read(lu->os_data), lu->flags, node, 
			node->n_name, lu->lun, lu->lun_tmp, lu->next);
	}
	os_unlock(it_lu_q->q_lock);
}

void iscsi_target_lu_offline(iscsi_node *node)
{
	chiscsi_target_lun *lu;
	int cnt = node->lu_cnt;
	int i;

	node->lu_cnt = 0;
	for (i = 0; i < cnt; i++) {
		lu = node->lu_list[i];
		node->lu_list[i] = NULL;
		/* lu may not be set up yet */
		if (lu) {
			lu->tnode_hndl = 0UL;

			os_lock_irq_os_data(lu->os_data);
			os_data_counter_inc(lu->os_data);
			chiscsi_target_lun_flag_set(lu, LUN_OFFLINE_BIT);
			os_unlock_irq_os_data(lu->os_data);
			chiscsi_target_lun_ch_qremove(lock, it_lu_q, lu);

			lu->class->fp_detach(lu);

			os_lock_irq_os_data(lu->os_data);
			os_data_counter_dec(lu->os_data);
			if (os_data_counter_read(lu->os_data) == 0) {
				if (lu->path)
					os_free(lu->path);
				os_unlock_irq_os_data(lu->os_data);
				os_data_free(lu->os_data);
				os_free(lu);
			} else {
				os_log_info("%d, lu 0x%p, busy %d.\n",
					i, lu, os_data_counter_read(lu->os_data));
				os_unlock_irq_os_data(lu->os_data);
			}
		}
	}
}

/*
 * lu scsi reserve & release
 */
static inline void it_lu_reserve_clear(chiscsi_target_lun *lu)
{
	os_lock_irq_os_data(lu->os_data);
	lu->rsv.rsvd_sess_hndl = 0UL;
	chiscsi_target_lun_flag_clear(lu, LUN_RESERVED_BIT);
	if(lu->rsv.pr_type == STM_RES_STANDARD)
		lu->rsv.pr_type = STM_RES_NONE;
	os_unlock_irq_os_data(lu->os_data);
}

int iscsi_target_lu_reserve_clear(iscsi_node *node, unsigned int lun)
{
	chiscsi_target_lun *lu = iscsi_target_lu_find(node, lun);

	if (!lu)
		return -ISCSI_EINVAL;

	it_lu_reserve_clear(lu);
	return 0;
}

int iscsi_target_lu_reserve_clear_by_session(iscsi_session * sess)
{
	iscsi_node *node = sess->s_node;
	chiscsi_target_lun *lu = NULL;
	int i;

	for (i = 0; i < node->lu_cnt; i++) {
		lu = node->lu_list[i];
		if (lu->rsv.rsvd_sess_hndl == (unsigned long)sess)
			break;
	}

	if (i < node->lu_cnt)
		it_lu_reserve_clear(lu);
	return 0;
}

int iscsi_target_reserve_clear(iscsi_node * node)
{
	int     i;

	for (i = 0; i < node->lu_cnt; i++) {
		chiscsi_target_lun *lu = node->lu_list[i];
		it_lu_reserve_clear(lu);
	}
	return 0;
}
