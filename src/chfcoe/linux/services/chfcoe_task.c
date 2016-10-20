/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <linux/kthread.h>

void chfcoe_schedule(void)
{
	schedule();
}

void chfcoe_task_state_interruptible(void)
{
	set_current_state(TASK_INTERRUPTIBLE);
}

void chfcoe_task_state_running(void)
{
	set_current_state(TASK_RUNNING);
}

void *chfcoe_kthread_create_on_node(int (*threadfn)(void *), void *data,
		int node, const char *fmt, ...)
{
	char buf[50];
	struct task_struct *task = NULL;
	va_list args;

	va_start(args, fmt);
	vsnprintf(buf, 50, fmt, args);
	va_end(args);

	task = kthread_create_on_node(threadfn, data, node, buf);

	if(IS_ERR(task))
		return NULL;

	return (void *)task;

}

void chfcoe_wake_up_process(void *task)
{
	wake_up_process((struct task_struct *)task);
}

int chfcoe_kthread_should_stop(void)
{
	return kthread_should_stop();
}

int chfcoe_kthread_stop(void *task)
{
	return kthread_stop((struct task_struct *)task);
}

void chfcoe_set_user_nice(void *task, long nice)
{
	chfcoe_set_user_nice((struct task_struct *)task, nice);
}
