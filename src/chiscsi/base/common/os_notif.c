/* Notifiers for Unified Storage */
#ifdef __ISCSI_NOTIFIER__
#include <linux/module.h> 
#include <linux/version.h>
#ifdef KERNEL_HAS_EXPORT_H
#include <linux/export.h>
#endif
#include <linux/notifier.h>
#include <common/iscsi_target_notif.h>

#if defined(RHEL_RELEASE_CODE)
#	define NOTIF_DIST_VERSION_CODE		RHEL_RELEASE_CODE
#	define NOTIF_DIST_VERSION		RHEL_RELEASE_VERSION(5,0)
#elif defined(SLE_VERSION_CODE)
#	define NOTIF_DIST_VERSION_CODE		SLE_VERSION_CODE
#	define NOTIF_DIST_VERSION		SLE_VERSION(11,0,0)
#else
#	define NOTIF_DIST_VERSION_CODE		LINUX_VERSION_CODE	
#	define NOTIF_DIST_VERSION		KERNEL_VERSION(2,6,17)
#endif

#if NOTIF_DIST_VERSION_CODE < NOTIF_DIST_VERSION 
#  define atomic_notifier_chain_register notifier_chain_register
#  define atomic_notifier_chain_unregister notifier_chain_unregister
#  define atomic_notifier_call_chain notifier_call_chain
#  define ATOMIC_NOTIFIER_HEAD(name) struct notifier_block* name=NULL
#endif

ATOMIC_NOTIFIER_HEAD(chiscsi_notif);

int chiscsi_register_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_register(&chiscsi_notif, nb);
}
EXPORT_SYMBOL(chiscsi_register_notifier);

int chiscsi_unregister_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_unregister(&chiscsi_notif, nb);
}
EXPORT_SYMBOL(chiscsi_unregister_notifier);

int os_chiscsi_notify_event(unsigned long event, char* fmt, ...)
{
	char buffer[CHISCSI_EVENT_BUFFER_MAX];
	va_list args;
	va_start(args, fmt);
	vsnprintf(buffer, CHISCSI_EVENT_BUFFER_MAX, fmt, args);
	va_end(args);

	return atomic_notifier_call_chain(&chiscsi_notif, event, buffer);
}
#else
int os_chiscsi_notify_event(unsigned long event, char* fmt, ...)
{
	return 1;
}
#endif
