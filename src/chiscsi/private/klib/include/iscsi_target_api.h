#ifndef __ISCSI_TARGET_API_H__
#define __ISCSI_TARGET_API_H__

#include <common/iscsi_target_device.h>
#include <iscsi_structs.h>

void	iscsi_target_cleanup(void);
int	iscsi_target_init(void);

/*
 * target/lun class
 */
chiscsi_target_class		*iscsi_target_class_default(void);
chiscsi_target_lun_class	*chiscsi_target_lun_class_default(chiscsi_target_class *);
chiscsi_target_class		*iscsi_target_class_find_by_name(char *);
chiscsi_target_lun_class	*chiscsi_target_lun_class_find_by_name(int lock,
						chiscsi_target_class *, char *);

int	iscsi_target_class_luns_has_property(int lock, int property_bit,
			chiscsi_target_class *tclass);

/* initialization & cleanup */
void	target_class_cleanup(void);
int	target_class_init(void);

int     iscsi_target_write_all_target_portal_config(char *, unsigned int);
int     iscsi_target_write_all_target_config(char *, unsigned int);

//int     iscsi_target_need_timeout_monitor(void);

/* target node */
void	iscsi_node_target_free(iscsi_node *);
iscsi_node *iscsi_node_target_alloc(iscsi_keyval *kv_conf);
int	iscsi_node_target_scst_configured(iscsi_node *);

int iscsi_node_target_read_config(iscsi_node *node, char *ebuf, int ebuflen);
int iscsi_target_lu_duplicate_validate(int reconfig, iscsi_node *node,
				char *ebuf, int ebuflen);
int	iscsi_target_lu_init_reservation(chiscsi_target_lun *lu);
void iscsi_target_lu_offline(iscsi_node *node);
void luq_dump(void);
int iscsi_target_lu_read_config(iscsi_node *node, char *ebuf, int ebuflen);

/* node display */
int     iscsi_node_portal_display(iscsi_node *, char *, int);
int     iscsi_node_target_display_stats(iscsi_node *, char *, int, int);

/* for iscsi control */
int     iscsi_node_target_add(int, iscsi_node *, char *, unsigned int);
int     iscsi_node_target_reconfig_prepare(iscsi_node *, char *, unsigned int);
int     iscsi_node_target_reconfig_finish(iscsi_node *, char *, unsigned int);
void    iscsi_node_target_reconfig_revert(iscsi_node *, char *, unsigned int);

int     iscsi_target_flush(iscsi_node *, char *, char *, int);
int     iscsi_target_display_all_portals(char *, int);

/* lun */
//chiscsi_target_lun * iscsi_target_lu_alloc(char *, int);
//void iscsi_target_lu_init(chiscsi_target_lun *);

int	iscsi_target_lu_flush(iscsi_node *, int, int);

static inline chiscsi_target_lun *iscsi_target_lu_find(iscsi_node *node,
						unsigned int lun)
{
	if (node && lun < node->lu_cnt)
		return node->lu_list[lun];
	return NULL;
}

/* data xfer */
int	iscsi_target_xmt_reject(iscsi_pdu *, int);
int	iscsi_target_pdu_scsi_command_bhs_rcv(iscsi_pdu *);
int	iscsi_target_pdu_data_out_bhs_rcv(iscsi_pdu *);

#endif /* #ifndef __ISCSI_TARGET_API_H__ */
