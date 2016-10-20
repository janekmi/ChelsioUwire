/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <linux/spinlock.h>
#include <linux/rwlock.h>
#include <linux/mutex.h>

const unsigned long os_spinlock_size = sizeof(spinlock_t);
const unsigned long os_rwlock_size = sizeof(rwlock_t);
const unsigned long os_mutex_size = sizeof(struct mutex);

/*Spin lock*/
void chfcoe_spin_lock_init(void *lock)
{
	spin_lock_init((spinlock_t *)lock);
}

void chfcoe_spin_lock(void *lock)
{
	spin_lock((spinlock_t *)lock);
}

void chfcoe_spin_unlock(void *lock)
{
	spin_unlock((spinlock_t *)lock);
}

void chfcoe_spin_lock_bh(void *lock)
{
	spin_lock_bh((spinlock_t *)lock);
}

void chfcoe_spin_unlock_bh(void *lock)
{
	spin_unlock_bh((spinlock_t *)lock);
}

/* rw lock */
void chfcoe_rwlock_init(void *lock)
{
	rwlock_init((rwlock_t *)lock);
}

void chfcoe_read_lock(void *lock)
{
	read_lock((rwlock_t *)lock);
}

void chfcoe_read_unlock(void *lock)
{
	read_unlock((rwlock_t *)lock);
}

void chfcoe_read_lock_bh(void *lock)
{
	read_lock_bh((rwlock_t *)lock);
}

void chfcoe_read_unlock_bh(void *lock)
{
	read_unlock_bh((rwlock_t *)lock);
}

void chfcoe_write_lock_bh(void *lock)
{
	write_lock_bh((rwlock_t *)lock);
}

void chfcoe_write_unlock_bh(void *lock)
{
	write_unlock_bh((rwlock_t *)lock);
}

/*Mutex lock*/
void chfcoe_mutex_init(void *lock)
{
	mutex_init((struct mutex *)lock);
}

void chfcoe_mutex_lock(void *lock)
{
	mutex_lock((struct mutex *)lock);
}

void chfcoe_mutex_unlock(void *lock)
{
	mutex_unlock((struct mutex *)lock);
}
