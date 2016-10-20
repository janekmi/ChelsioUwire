/*
 * Copyright (c) 2007-2009 Chelsio, Inc. All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */
#ifndef __TOE_COMPAT_2_4_H
#define __TOE_COMPAT_2_4_H

#include <linux/version.h>

/* XXX Only built against 2.4.21 */
#if LINUX_VERSION_CODE != KERNEL_VERSION(2,4,21)
#endif

/******************************************************************************
 * socket compatibility
 * map 2.6 field names to 2.4 names
 ******************************************************************************/
#define sk_family		family
#define sk_protocol		protocol
#define sk_route_caps		route_caps
#define sk_backlog_rcv		backlog_rcv

/******************************************************************************
 * module compatibility
 ******************************************************************************/
#define	MODULE_VERSION(x)
#define subsys_initcall	module_init

/******************************************************************************
 * lock compatibility
 ******************************************************************************/
#define	DEFINE_MUTEX(l)			DECLARE_MUTEX((l))
#define mutex_lock(l)			down((l))
#define mutex_unlock(l)			up((l))
#define mutex_init(l)			sema_init((l), 1)
#define	DEFINE_RWLOCK(l)		rwlock_t (l) = RW_LOCK_UNLOCKED

#define spin_trylock_irq(lock) \
({ \
        local_irq_disable(); \
        spin_trylock(lock) ? \
        1 : ({ local_irq_enable(); 0;  }); \
})
#endif /* __TOE_COMPAT_2_4_H */
