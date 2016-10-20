#ifndef __LIBWDTOE_STATS_H__
#define __LIBWDTOE_STATS_H__

#include "debug.h"

#define INC_STAT(c, a) do {			\
				(c)->stats.a++;	\
			  } while (0)

struct conn_stats {
	unsigned long long fast_sends;
	unsigned long long fast_recvs;
	unsigned long long waits;
};

void *stats_thread_routine(void *arg);
#endif
