#ifndef __LIBWDTOE_DEBUG_H__
#define __LIBWDTOE_DEBUG_H__

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/syslog.h>

enum dbg_levels {
	DBG_INIT	= (1 << 0),	/* lib init-related stuff */
	DBG_CONN	= (1 << 1),	/* connection management stuff */
	DBG_RES_ALLOC	= (1 << 2),	/* resource allocation stuff (RxQ, TxQ, SW-FL, etc.) */
	DBG_CHAR_DEV	= (1 << 3),
	DBG_RECV	= (1 << 4),
	DBG_SELECT	= (1 << 5),
	DBG_SEND	= (1 << 6),
	DBG_CREDITS	= (1 << 7),
	DBG_LOOKUP	= (1 << 8),	/* active/passive shared lookup table(s) */
	DBG_STATS	= (1 << 9),
};

extern unsigned dbg_flags;

#ifndef NDEBUG
#define DBG(l, fmt, args...) if ((l) & dbg_flags) syslog(LOG_DEBUG, "%s {thread %d}: " fmt, __func__, \
							(int) syscall(SYS_gettid), ## args)
#else
#define DBG(l, fmt, args...)
#endif

#endif
