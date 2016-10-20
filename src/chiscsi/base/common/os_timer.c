/*
 * kernel timer function wrappers
 */
#include <linux/version.h>
#include <linux/jiffies.h>
#include <linux/timer.h>
#include <linux/sched.h>
#include <linux/param.h>
#include <common/iscsi_common.h>
#include <common/os_export.h>

unsigned long os_get_timestamp(void)
{
        return jiffies;
}

void   *os_timer_alloc(char wait)
{
	struct timer_list *timer;

	timer = os_alloc(sizeof(struct timer_list), wait, 1);
	return (void *) timer;
}

void os_timer_free(void *tp)
{
	os_free(tp);
}

int os_timer_init(void *tp, void *privdata)
{
	struct timer_list *timer = (struct timer_list *) tp;

	init_timer(timer);
	timer->data = (ulong) privdata;
	del_timer(timer);
	return 0;
}

void os_timer_start(void *tp, int tm_sec, void (*fp) (unsigned long))
{
	struct timer_list *timer = (struct timer_list *) tp;

	del_timer(timer);
	timer->function = fp;
	timer->expires = 0;
	if (tm_sec)
		timer->expires += tm_sec * HZ;
	timer->expires += jiffies;
	add_timer(timer);
}

void os_timer_stop(void *tp)
{
	struct timer_list *timer = (struct timer_list *) tp;
	del_timer(timer);
}
