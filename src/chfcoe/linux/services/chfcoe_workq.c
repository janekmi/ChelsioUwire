/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <linux/workqueue.h>
#include <linux/kernel.h>
#include "chfcoe_os.h"

const unsigned long os_work_size = sizeof(struct work_struct);
const unsigned long os_dwork_size = sizeof(struct delayed_work);


/*Workqueue*/
void *chfcoe_alloc_workqueue(const char *name)
{
	struct workqueue_struct *wq = NULL;

	wq = alloc_workqueue(name, WQ_UNBOUND | WQ_MEM_RECLAIM, WQ_MAX_ACTIVE);

	return (void *)wq;
} 

int chfcoe_queue_work(void *workq, chfcoe_work_t *workp)
{
	return queue_work((struct workqueue_struct *)workq, (struct work_struct *)workp->work);	
} 

int chfcoe_queue_delayed_work(void *workq, chfcoe_dwork_t *dworkp, unsigned long delay_msecs)
{
	return queue_delayed_work((struct workqueue_struct *)workq,
			(struct delayed_work *)dworkp->work, msecs_to_jiffies(delay_msecs));
}

int chfcoe_cancel_delayed_work(chfcoe_dwork_t *dworkp)
{
	return cancel_delayed_work((struct delayed_work *)dworkp->work);		
} 

int chfcoe_cancel_delayed_work_sync(chfcoe_dwork_t *dworkp)
{
	return cancel_delayed_work_sync((struct delayed_work *)dworkp->work);		
} 

int chfcoe_flush_delayed_work(chfcoe_dwork_t *dworkp)
{
	return flush_delayed_work((struct delayed_work *)dworkp->work);		
} 

void chfcoe_flush_workqueue(void *workq)
{
	flush_workqueue((struct workqueue_struct *)workq);
}

void chfcoe_destroy_workqueue(void *workq)
{
	destroy_workqueue((struct workqueue_struct *)workq);
}

int chfcoe_cancel_work_sync(chfcoe_work_t *workp)
{
	return cancel_work_sync((struct work_struct *)workp->work);
}

/*Kernel Workqueue*/
int chfcoe_schedule_work(chfcoe_work_t *workp)
{
	return schedule_work((struct work_struct *)workp->work);
}

int chfcoe_schedule_delayed_work(chfcoe_dwork_t *dworkp, unsigned long delay)
{
	return schedule_delayed_work((struct delayed_work *)dworkp->work, delay);
}

/* Work function */
void chfcoe_wfn(struct work_struct *w)
{
	chfcoe_work_t *workp = (chfcoe_work_t *)((unsigned char *)w
		- sizeof(chfcoe_work_t));

	(*(workp->wfn))(workp->data);
}

void chfcoe_delayed_wfn(struct work_struct *w)
{
	struct delayed_work *d_work = container_of(w, struct delayed_work, work);
	
	chfcoe_dwork_t *dworkp = (chfcoe_dwork_t *)((unsigned char *)d_work
		- sizeof(chfcoe_dwork_t));

	(*(dworkp->wfn))(dworkp->data);
}

void chfcoe_init_work(chfcoe_work_t *workp, void (*wfn)(void *), void *data)
{
	workp->wfn = wfn;
	workp->data = data;
	INIT_WORK((struct work_struct *)workp->work, chfcoe_wfn);
}

void chfcoe_init_delayed_work(chfcoe_dwork_t *dworkp, void (*wfn)(void *),
		void *data)
{
	dworkp->wfn = wfn;
	dworkp->data = data;
	INIT_DELAYED_WORK(((struct delayed_work *)dworkp->work), chfcoe_delayed_wfn);
}
