
#ifndef __ISCSI_TARGET_NOTIF_H__
#define __ISCSI_TARGET_NOTIF_H__


#define CHISCSI_LOGIN_SUCCESS	1
#define CHISCSI_LOGOUT_SUCCESS	2
#define CHISCSI_AUTH_FAILURE	3	
#define CHISCSI_LOGIN_FAILURE	4
#define CHISCSI_LOGOUT_FAILURE	5
#define CHISCSI_ACL_DENY	6
#define CHISCSI_NODE_ADD	7
#define CHISCSI_NODE_REMOVE	8

#define CHISCSI_EVENT_BUFFER_MAX 512
int os_chiscsi_notify_event(unsigned long, char*, ...);

#ifndef __KLIB__ 
#include <linux/notifier.h>
int chiscsi_register_notifier(struct notifier_block*);
int chiscsi_unregister_notifier(struct notifier_block*);
#endif /* __KLIB__ */

#endif /* __ISCSI_TARGET_NOTIF_H__ */
