/*
 * kernel thread function wrappers
 */
#include <linux/version.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/cpuset.h>

#include <common/iscsi_common.h>
#include <common/os_export.h>
#include <common/os_data.h>

enum thread_bit {
	THREAD_UP_BIT,
	THREAD_STOP_BIT
};

const unsigned int os_kthread_size = sizeof(os_kthread);

//#undef __USE_KTHREAD__
#define __USE_KTHREAD__

#ifdef __USE_KTHREAD__		/* use kthread struct */
static int kthread_bind_to_cpu(os_kthread *thinfo)
{
	int rv = 0;
#ifdef __THREAD_BIND2CPU__
	iscsi_thread_common *th_comm = thinfo->t_common;
	struct task_struct *task = thinfo->t_task;

	if (th_comm->id < num_possible_cpus()) {
		cpumask_t new_mask;
		unsigned long mask = 1 << th_comm->id;

		/* set the affinity mask */
		memcpy(&new_mask, &mask, sizeof(cpumask_t));
		cpus_and(new_mask, new_mask, task->cpus_allowed);
		/* requires GPL license */
		rv = set_cpus_allowed_ptr(task, &new_mask);
		/* read the affinity mask */
		memset(&new_mask, 0, sizeof(cpumask_t));
		cpus_and(new_mask, task->cpus_allowed, cpu_possible_map);
		memcpy(&mask, &new_mask, sizeof(cpumask_t));

		os_log_info("%s, bind to cpu %u (0x%x).\n", 
		     th_comm->name, th_comm->id, mask);
	}
#endif
	return rv;
}

static int os_thread_body(void *arg)
{
	os_kthread *thinfo = (os_kthread *) arg;
	iscsi_thread_common *th_comm = thinfo->t_common;
	void   *farg = th_comm->farg;
	unsigned int timeout = th_comm->timeout;
	DECLARE_WAITQUEUE(wait, current);

	os_log_debug(ISCSI_DBG_THREAD,
		     "%s UP, waitq 0x%p, data 0x%p.\n",
		     th_comm->name, thinfo->t_waitq, farg);

	disallow_signal(SIGPIPE);

	kthread_bind_to_cpu(thinfo);

	th_comm->finit(farg);

	add_wait_queue(thinfo->t_waitq, &wait);
	__set_current_state(TASK_RUNNING);
	do {
		os_log_debug(ISCSI_DBG_THREAD, "%s, awake.\n", th_comm->name);

		th_comm->fproc(farg);

		__set_current_state(TASK_INTERRUPTIBLE);

		if (!(th_comm->ftest(farg))) {
			os_log_debug(ISCSI_DBG_THREAD,
				     "%s, goes to sleep %d.\n", th_comm->name,
				     timeout);
			schedule();
		}
		__set_current_state(TASK_RUNNING);

	} while (!kthread_should_stop());

	os_log_debug(ISCSI_DBG_THREAD, "%s, work done.\n", th_comm->name);

	remove_wait_queue(thinfo->t_waitq, &wait);

	th_comm->fdone(farg);

	os_log_debug(ISCSI_DBG_THREAD, "%s, exit.\n", th_comm->name);
	return 0;
}

int os_kthread_create(void *dp, iscsi_thread_common * th_comm)
{
	iscsi_os_data *tmp = (iscsi_os_data *)dp;
	os_kthread *thinfo = &tmp->priv.th_kinfo;
	void *waitq = &tmp->waitq;
	struct task_struct *task;

	if (!dp || !waitq || !th_comm) {
		os_log_error("kthread create, 0x%p, 0x%p, 0x%p.\n", dp, waitq, th_comm);
		return -ISCSI_ENULL;
	}

	if (thinfo->t_task) {
		os_log_error("kthread %s task already running?\n",
			  thinfo->t_common ? thinfo->t_common->name : "?");
		return -ISCSI_EINVAL;
	}

	thinfo->t_waitq = waitq;
	thinfo->t_common = th_comm;
	task = kthread_create(os_thread_body, thinfo, "%s", th_comm->name);
	if (IS_ERR(task)) {
		os_log_error("kthread %s, create task 0x%lx\n", th_comm->name, IS_ERR(task));
		return -ISCSI_EFAIL;
	}
	thinfo->t_task = task;

	os_log_debug(ISCSI_DBG_THREAD,
		     "kthread %s, 0x%p, waitq 0x%p, data 0x%p created.\n",
		     th_comm->name, thinfo->t_task, thinfo->t_waitq,
		     th_comm->farg);
	return 0;
}

int os_kthread_start(void *arg)
{
	iscsi_os_data *tmp = (iscsi_os_data *)arg;
	os_kthread *thinfo = &tmp->priv.th_kinfo;

	if (!thinfo->t_task) {
		os_log_error("kthread %s, start.\n", thinfo->t_common->name);
		return -ISCSI_ENULL;
	}

	os_log_debug(ISCSI_DBG_THREAD,
		     "kthread %s, 0x%p, started.\n",
		     thinfo->t_common->name, thinfo->t_task);

	wake_up_process(thinfo->t_task);

	return 0;
}

int os_kthread_stop(void *arg)
{
	os_kthread *thinfo = &(((iscsi_os_data *)arg)->priv.th_kinfo);
	int     rv;

	if (!thinfo->t_task) {
		os_log_warn("kthread %s, already stopped.\n",
			    thinfo->t_common->name);
		return 0;
	}
	rv = kthread_stop(thinfo->t_task);
	if (rv < 0) {
		os_log_error("kthread %s, stop %d.\n", thinfo->t_common->name, rv);
		return rv;
	}

	os_log_debug(ISCSI_DBG_THREAD,
		     "kthread %s, 0x%p, stopped.\n",
		     thinfo->t_common->name, thinfo->t_task);
	thinfo->t_task = NULL;

	return 0;
}

#else /* uses kernel_thread struct */
static int os_thread_body(void *arg)
{
	os_kthread *thinfo = (os_kthread *) arg;
	iscsi_thread_common *th_comm = thinfo->t_common;
	void   *farg = th_comm->farg;
	unsigned int timeout = th_comm->timeout;

	DECLARE_WAITQUEUE(wait, current);

	set_bit(THREAD_UP_BIT, &thinfo->t_flag);

	os_log_debug(ISCSI_DBG_THREAD,
		     "thread %s UP, waitq 0x%p, data 0x%p.\n",
		     th_comm->name, thinfo->t_waitq, farg);

	allow_signal(SIGKILL);
	disallow_signal(SIGPIPE);
	current->exit_signal = 0;
	daemonize(th_comm->name);

	th_comm->finit(farg);

	add_wait_queue(thinfo->t_waitq, &wait);
	__set_current_state(TASK_RUNNING);
	while (!(test_bit(THREAD_STOP_BIT, &thinfo->t_flag))) {

		os_log_debug(ISCSI_DBG_THREAD,
			     "thread %s, awake.\n", th_comm->name);

		th_comm->fproc(farg);

		if (signal_pending(current)) {
			os_log_info("thread %s: caught signal.\n",
				    th_comm->name);
			break;
		}
		__set_current_state(TASK_INTERRUPTIBLE);

		if (!(th_comm->ftest(farg))) {
			os_log_debug(ISCSI_DBG_THREAD,
				     "%s, goes to sleep %d.\n", th_comm->name,
				     timeout);
			schedule();
			//schedule_timeout(timeout*HZ); 
		}

		__set_current_state(TASK_RUNNING);
	}

	os_log_debug(ISCSI_DBG_THREAD, "%s: work done.\n", th_comm->name);

	remove_wait_queue(thinfo->t_waitq, &wait);

	th_comm->fdone(farg);

	clear_bit(THREAD_UP_BIT, &thinfo->t_flag);

	os_log_debug(ISCSI_DBG_THREAD, "%s: exit.\n", th_comm->name);

	wake_up(&thinfo->t_waitq_ack);

	return 0;
}

int os_kthread_create(void *dp, iscsi_thread_common * th_comm)
{
        iscsi_os_data *tmp = (iscsi_os_data *)dp;
        os_kthread *thinfo = &tmp->priv.th_kinfo;
        void *waitq = &tmp->waitq;

	if (!dp || !waitq || !th_comm) {
		os_log_error("kthread create, 0x%p, 0x%p, 0x%p.\n", dp, waitq, th_comm);
		return -ISCSI_ENULL;
	}

	memset(thinfo, 0, sizeof(os_kthread));
	init_waitqueue_head(&thinfo->t_waitq_ack);
	thinfo->t_waitq = waitq;
	thinfo->t_common = th_comm;
	clear_bit(THREAD_UP_BIT, &thinfo->t_flag);

	os_log_debug(ISCSI_DBG_THREAD,
		     "thread %s, waitq 0x%p, data 0x%p created.\n",
		     th_comm->name, thinfo->t_waitq, th_comm->farg);
	return 0;
}

int os_kthread_start(void *arg)
{
	os_kthread *thinfo = &((iscsi_os_data *)arg->priv.th_kinfo);
	iscsi_thread_common *th_comm = thinfo->t_common;

	clear_bit(THREAD_STOP_BIT, &thinfo->t_flag);

	if (test_bit(THREAD_UP_BIT, &thinfo->t_flag)) {
		os_log_debug(ISCSI_DBG_THREAD,
			     "thread %s, already started 0x%lx.\n",
			     th_comm->name, thinfo->t_flag);
	} else {
		os_log_debug(ISCSI_DBG_THREAD,
			     "thread %s, started.\n", th_comm->name);
		kernel_thread(os_thread_body, thinfo, 0);
	}

	return 0;
}

static int os_kthread_stopped(void *arg)
{
	os_kthread *thinfo = (os_kthread *) arg;
	return ((test_bit(THREAD_UP_BIT, &thinfo->t_flag)) == 0);
}

int os_kthread_stop(void *arg)
{
	os_kthread *thinfo = &((iscsi_os_data *)arg->priv.th_kinfo);
	iscsi_thread_common *th_comm = thinfo->t_common;

	if (test_bit(THREAD_UP_BIT, &thinfo->t_flag)) {
		set_bit(THREAD_STOP_BIT, &thinfo->t_flag);

		os_wake_up(thinfo->t_waitq);

		os_log_debug(ISCSI_DBG_THREAD,
			     "thread %s, stopping.\n", th_comm->name);

		os_wait_on(&thinfo->t_waitq_ack, os_kthread_stopped, thinfo, 5);

		if (test_bit(THREAD_UP_BIT, &thinfo->t_flag)) {
			os_log_error("kthread stil up 0x%lx.\n", thinfo->t_flag);
			return -ISCSI_EFAIL;
		}
		clear_bit(THREAD_STOP_BIT, &thinfo->t_flag);
		os_log_debug(ISCSI_DBG_THREAD,
			     "thread %s, stopped.\n", th_comm->name);
	} else {
		os_log_debug(ISCSI_DBG_THREAD,
			     "thread %s, already stopped.\n", th_comm->name);
	}
	return 0;
}
#endif
