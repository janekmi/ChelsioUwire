/*
 * Copyright (C) 2003-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __CSIO_OS_TRANSUTIL_FOISCSI_H__
#define  __CSIO_OS_TRANSUTIL_FOISCSI_H__

#include <csio_defs.h>
#include <linux/kthread.h>
#include <csio_oss.h>

/* Mutex wrapper */
static inline csio_retval_t csio_mutex_init(csio_mutex_t *mutex)
{
	mutex_init(&mutex->lock);
	return CSIO_SUCCESS;
}

static inline csio_retval_t csio_mutex_lock(csio_mutex_t *mutex)
{
	mutex_lock(&mutex->lock);
	return CSIO_SUCCESS;
}

static inline csio_retval_t csio_mutex_unlock(csio_mutex_t *mutex)
{
	mutex_unlock(&mutex->lock);
	return CSIO_SUCCESS;
}

static inline void* foiscsi_alloc(unsigned int size)
{
	return (kzalloc(size, GFP_ATOMIC));
}

static inline void foiscsi_free(void *ptr)
{
	if (ptr)
		kfree(ptr);
}

typedef	struct task_struct  csio_task_struct_t;

static inline void* csio_kthread_create(int (*thread_fun)(void *data),
						 void *data, const char name[])
{
	return (kthread_create(thread_fun, (void *)data, name));
}

static inline void csio_wake_up(csio_task_struct_t *p)
{
	wake_up_process(p);
}

static inline int csio_kthread_stop(csio_task_struct_t *p)
{
        return (kthread_stop(p));
}
#endif
