#include <linux/kernel.h>
#include <linux/module.h>
#ifdef KERNEL_HAS_EXPORT_H
#include <linux/export.h>
#endif
#include <linux/jiffies.h>
#include <common/iscsi_common.h>
#include <common/iscsi_debug.h>

extern unsigned int iscsi_msg_level;
extern unsigned long iscsi_msg_debug_level;

#define ISCSI_LOG_HEADER	"chiscsi: "
#define STR_ERR			"ERR! "
#define STR_WARNING		"WARN! "
#define STR_INFO		""
#define STR_DEBUG		""

#define LOG_BUFFER(LEVEL,buf) \
	printk(KERN_##LEVEL ISCSI_LOG_HEADER STR_##LEVEL "%lu %s", jiffies, buf)

#define va_list_sprintf(buf,bl,fmt)	({\
       	va_list __args; \
	int	__l; \
	va_start(__args, fmt); \
       	__l = vsnprintf(buf, bl, fmt, __args); \
	va_end(__args); \
	__l; })

int iscsi_msg_debug_level_on(int dbglevel)
{
	return  iscsi_msg_level && iscsi_msg_debug_level &&
		 ((1 << ISCSI_MSG_DEBUG) & iscsi_msg_level) &&
		 ((1UL << dbglevel) & iscsi_msg_debug_level);
}
EXPORT_SYMBOL(iscsi_msg_debug_level_on);

void __os_debug_msg(const char *fname, const char *fmt, ...)
{
	char    buffer[512];

	va_list_sprintf(buffer, 512, fmt);
	printk(KERN_INFO ISCSI_LOG_HEADER "%s, %s", fname, buffer);
}
EXPORT_SYMBOL(__os_debug_msg);

void __os_log_msg(const char *fname, int level, const char *fmt, ...)
{
	char    buffer[512];

	va_list_sprintf(buffer, 512, fmt);

	switch (level) {
		case ISCSI_MSG_DEBUG:
			printk(KERN_INFO ISCSI_LOG_HEADER "%s, %s",
				fname, buffer);
			break;
		case ISCSI_MSG_INFO:
			if (iscsi_msg_level &&
			    (1 << ISCSI_MSG_INFO) & iscsi_msg_level) {
				LOG_BUFFER(INFO, buffer);
			}
			break;
		case ISCSI_MSG_WARN:
			LOG_BUFFER(WARNING, buffer);
			break;
		case ISCSI_MSG_ERR:
			LOG_BUFFER(ERR, buffer);
			break;
	}
}
EXPORT_SYMBOL(__os_log_msg);

static char iscsi_error_code_msg[][36] = {
	/*
	   01234567890123456789012345678901234
	 */
	" ",			/* no error */
	"out of memory",	/* ISCSI_ENOMEM */
	"null value",		/* ISCSI_ENULL */
	"invalid value",	/* ISCSI_EINVAL */
	"operation failed",	/* ISCSI_EFAIL */
	"I/O failure",		/* ISCSI_EIO */
	"invalid state",	/* ISCSI_ESTATE */
	"data overflow",	/* ISCSI_EOVERFLOW */
	"data underflow",	/* ISCSI_EUNDERFLOW */
	"no match found",	/* ISCSI_ENOMATCH */
	"not ready",		/* ISCSI_ENOTREADY */
};

int buffer_log_error_code(int err, char *buf, int buflen, char *fmt, ...)
{
	int     len = 0;
	if (err > 0) {
		len = sprintf(buf, "%s!", iscsi_error_code_msg[err]);
		if (fmt) {
			len += va_list_sprintf(buf + len, buflen - len, fmt);
		}
		buf[len++] = '\n';
		buf[len++] = '\0';
	}
	return len;
}

void os_log_error_code(int err, const char *fmt, ...)
{
	if (err > 0) {
		char    buffer[512];
		va_list_sprintf(buffer, 512, fmt);
		printk(KERN_WARNING ISCSI_LOG_HEADER STR_WARNING "%s, %s.\n",
		       iscsi_error_code_msg[err], buffer);
	}
}

int os_printf(const char *fmt, ...)
{
	char buffer[512];
	int rv;

	rv = va_list_sprintf(buffer, 512, fmt);
	LOG_BUFFER(INFO, buffer);
	return rv;
}
