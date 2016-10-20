#ifndef __ISCSI_SCST_H__
#define __ISCSI_SCST_H__

/* scst target wrappers */
void *iscsi_scst_register(const char *);

void iscsi_scst_unregister(void *iscsi_scst_tgt);

/* scst session wrappers */

void *iscsi_scst_reg_session(void *, char *initiator_name);

void iscsi_scst_unreg_session(void *session);
#endif
