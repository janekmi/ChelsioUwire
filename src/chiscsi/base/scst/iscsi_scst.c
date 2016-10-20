
#include <common/iscsi_target_class.h>
#include <common/iscsi_scst.h>

#ifdef __ISCSI_SCST__
#include <scst.h>

extern struct scst_tgt_template chiscsi_scst_tgt_template;

/* scst target wrappers */
void *iscsi_scst_register(const char *target_name)
{
	return scst_register_target(&chiscsi_scst_tgt_template, target_name);
}

void iscsi_scst_unregister(void *iscsi_scst_tgt)
{
	return scst_unregister_target((struct scst_tgt *)iscsi_scst_tgt);
}

/* scst session wrappers */

void *iscsi_scst_reg_session(void *scst_target, char *initiator_name)
{
	return scst_register_session((struct scst_tgt *)scst_target, SCST_NON_ATOMIC, 
			initiator_name, NULL, NULL, NULL);
}

void iscsi_scst_unreg_session(void *session)
{
	scst_unregister_session((struct scst_session *)session, 0, NULL);
}

#else

void *iscsi_scst_register(const char *target_name)
{
	return (void *)0; 
}

void iscsi_scst_unregister(void *iscsi_scst_tgt)
{
	return; 
}

void *iscsi_scst_reg_session(void *scst_target, char *initiator_name)
{
	return (void *)0;
}

void iscsi_scst_unreg_session(void *session)
{
	return;
}

#endif
