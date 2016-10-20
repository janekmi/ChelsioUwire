#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <signal.h>

#include "isns_globals.h"

/**
 * isns_timer -- a periodic timer pops every poll_period (in seconds)
 *
 */
void   *isns_timer(void *arg)
{
	while (keep_running) {
		sleep(poll_period);
		kill(self_pid, SIGUSR1);
	}
	return NULL;
}
