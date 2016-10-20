/*
 * VERY IMPORTANT INFORMATION:
 *
 * This file is used by the WD-TOE User Space library as well t4_tom (when
 * compiled with WD-TOE support).
 *
 * If you need certain structures to be accessible from User Space and Kernel
 * Space, this is the right file for your structure definitions.
 *
 * Note that so far the name of the file is 'ntuples.h' because it is dealing
 * with connection tuple structures exclusively. Should you need to add new
 * definitions that are not related to connection tuples, you may have to
 * rename the file accordingly.
 *
 * However, you should always double check the sizes of your structure
 * member types for both Kernel and User Space. For example, you want to make
 * sure that type 'long' has the same size in Kernel and User Space. Failure
 * to do so may result in the application crashing and hanging unexpectedly as
 * a given structure definition may be interpreted differently in Kernel and in
 * User Space.
 */

#ifndef _CHELSIO_WDTOE_NTUPLES_H
#define _CHELSIO_WDTOE_NTUPLES_H

#define WDTOE_COOKIE 0xfa11dead


#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <asm/types.h>
#endif

/* Number of simultaneous connections supported by WD-TOE */
#define NWDTOECONN 64

struct conn_tuple {
	unsigned int atid;
	unsigned int lport;
	unsigned short in_use;
};

struct passive_tuple {
	unsigned int stid;
	int tid;
	__u16 pport;
	__u32 pip;
	unsigned short in_use;
};
#endif

