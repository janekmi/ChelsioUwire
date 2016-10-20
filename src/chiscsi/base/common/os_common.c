/*
 * common linux kernel wrappers
 */

#include <linux/version.h>
#include <linux/kernel.h>
#ifdef KERNEL_HAS_EXPORT_H
#include <linux/export.h>
#endif
#include <linux/sched.h>
#include <linux/smp.h>
#ifdef CONFIG_BKL
#include <linux/smp_lock.h>
#endif
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/random.h>
#include <asm/atomic.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <common/iscsi_common.h>
#include <common/os_export.h>
#include <common/os_data.h>

/* iscsi uses "unsigned long" for bit masks */
const unsigned long iscsi_ulong_mask_max = ULONG_MAX;
const unsigned int iscsi_ulong_mask_bits = (sizeof(unsigned long)) << 3;
unsigned int iscsi_ulong_mask_shift = 0;
char sw_tag_idx_bits;
char sw_tag_r2t_bits;

/* os-specific data structures */
const unsigned int os_lock_size = sizeof(iscsi_os_lock);
const unsigned int os_waitq_size = sizeof(wait_queue_head_t);
const unsigned int os_counter_size = sizeof(atomic_t);
DEFINE_PER_CPU(u32[ISCSI_STAT_MAX], iscsi_stats);

/**
 * iscsi_os_init - os dependent initialization 
 */

/* count how many bits needed for a given unsigned value */
static inline int uint_bits_needed(unsigned long v)
{
	int i = 0;

	for (v >>= 1; v > 0; v >>= 1, i++)
		;
	return i;
}

void os_transport_cleanup(void);
int os_transport_init(void);
int iscsi_os_init(void)
{
	/* # bits needed for the length of ulong */
	iscsi_ulong_mask_shift = uint_bits_needed(iscsi_ulong_mask_bits);
	sw_tag_idx_bits = uint_bits_needed(ISCSI_SESSION_SCMDQ_MAX - 1) + 1;
	sw_tag_r2t_bits = uint_bits_needed(ISCSI_SESSION_MAX_OUTSTANDING_R2T-1)
				 + 1;

	return (os_transport_init());
}

void iscsi_os_cleanup(void)
{
	os_transport_cleanup();
}

/*
 * os specific function wrappers 
 */
unsigned long os_strtoul(const char *cp, char **endp, int base)
{
	return (simple_strtoul(cp, endp, base));
}

void os_get_random_bytes(void *buf, int nbytes)
{
	return (get_random_bytes(buf, nbytes));
}

void os_counter_inc(void *p)
{
	atomic_inc((atomic_t *) p);
}

void os_counter_dec(void *p)
{
	atomic_dec((atomic_t *) p);
}

void os_counter_set(void *p, int v)
{
	atomic_set((atomic_t *) p, v);
}

int os_counter_read(void *p)
{
	return (atomic_read((atomic_t *) p));
}

void os_counter_add(void *p, int v)
{
	atomic_add(v, (atomic_t *)p);
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0))
void iscsi_stats_inc(int type)
{
	raw_cpu_inc(iscsi_stats[type]);
}

void iscsi_stats_dec(int type)
{
	raw_cpu_dec(iscsi_stats[type]);
}

void iscsi_stats_set(int type, int val)
{
	raw_cpu_write(iscsi_stats[type], val);
}

int iscsi_stats_read(int type)
{
	return raw_cpu_read(iscsi_stats[type]);
}


#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33))
void iscsi_stats_inc(int type)
{
	__this_cpu_inc(iscsi_stats[type]);
}

void iscsi_stats_dec(int type)
{
	__this_cpu_dec(iscsi_stats[type]);
}

void iscsi_stats_set(int type, int val)
{
	__this_cpu_write(iscsi_stats[type], val);
}

int iscsi_stats_read(int type)
{
	return __this_cpu_read(iscsi_stats[type]);
}

#else

void iscsi_stats_inc(int type)
{
	__get_cpu_var(iscsi_stats[type])++;
}

void iscsi_stats_dec(int type)
{
	__get_cpu_var(iscsi_stats[type])--;
}

void iscsi_stats_set(int type, int val)
{
	__get_cpu_var(iscsi_stats[type]) = val;
}
 
int iscsi_stats_read(int type)
{
	return __get_cpu_var(iscsi_stats[type]);
}
#endif
EXPORT_SYMBOL(iscsi_stats_inc);
EXPORT_SYMBOL(iscsi_stats_dec);
EXPORT_SYMBOL(iscsi_stats_read);

int iscsi_stats_display(char *buf, int buflen)
{
	/* make sure the name is matched to the iscsi_stats_type
	   defined in iscsi_common.h */
	static char iscsi_stat_name[ISCSI_STAT_MAX][10] = {
		"sess",
		"conn",
		"sbuf_rx",
		"sbuf_tx",
		"mem",
		"mempg",
		"gl"
	};
	int     i = 0, len = strlen(buf);
	unsigned int cpu;
	unsigned int count;

	for (; i < ISCSI_STAT_MAX; i++) {
		count = 0;
		for_each_possible_cpu(cpu) {
			count += per_cpu(iscsi_stats[i], cpu);
		}	
		len += sprintf(buf + len, "%s=%d ", iscsi_stat_name[i],
			       count);
		if (len >= buflen)
			break;
	}

	return len;
}

void os_set_bit_atomic(void *p, int pos)
{
	set_bit(pos, p);
}

int os_test_bit_atomic(void *p, int pos)
{
	return (test_bit(pos, p));
}

void os_clear_bit_atomic(void *p, int pos)
{
	clear_bit(pos, p);
}

int os_test_and_set_bit_atomic(void *p, int pos)
{
	return (test_and_set_bit(pos, p));
}

int os_test_and_clear_bit_atomic(void *p, int pos)
{
	return (test_and_clear_bit(pos, p));
}

unsigned short os_ntohs(unsigned short v)
{
	return (ntohs(v));
}
unsigned short os_htons(unsigned short v)
{
	return (htons(v));
}

unsigned int os_ntohl(unsigned int v)
{
	return (ntohl(v));
}

unsigned int os_htonl(unsigned int v)
{
	return (htonl(v));
}

unsigned long long os_ntohll(unsigned long long v)
{
	return (be64_to_cpu(v));
}

unsigned long long os_htonll(unsigned long long v)
{
	return (cpu_to_be64(v));
}

unsigned int os_le32_to_host(unsigned int v)
{
	return (le32_to_cpu(v));
}

void __os_lock_init(const char *fname, void *l)
{
	iscsi_os_lock *lock = (iscsi_os_lock *)l;

	os_log_debug(ISCSI_DBG_LOCK, "%s: init lock 0x%p.\n", fname, l);
	spin_lock_init(&lock->splock);
	lock->flag = 0UL;
}

void __os_lock(const char *fname, void *l)
{
	iscsi_os_lock *lock = (iscsi_os_lock *)l;

	os_log_debug(ISCSI_DBG_LOCK, "%s: locking 0x%p.\n", fname, l);
	spin_lock(&lock->splock);
	os_log_debug(ISCSI_DBG_LOCK, "%s: locked 0x%p.\n", fname, l);
}

void __os_unlock(const char *fname, void *l)
{
	iscsi_os_lock *lock = (iscsi_os_lock *)l;

	os_log_debug(ISCSI_DBG_LOCK, "%s: unlock 0x%p.\n", fname, l);
	spin_unlock(&lock->splock);
}

void __os_lock_irq(const char *fname, void *l)
{
	iscsi_os_lock *lock = (iscsi_os_lock *)l;

	os_log_debug(ISCSI_DBG_LOCK, "%s: irq locking 0x%p.\n", fname, l);
	spin_lock_irqsave(&lock->splock, lock->flag);
	os_log_debug(ISCSI_DBG_LOCK, "%s: irq locked 0x%p.\n", fname, l);
}

void __os_unlock_irq(const char *fname, void *l)
{
	iscsi_os_lock *lock = (iscsi_os_lock *)l;

	os_log_debug(ISCSI_DBG_LOCK, "%s: irq unlock 0x%p.\n", fname, l);
	spin_unlock_irqrestore(&lock->splock, lock->flag);
}

void __os_module_get(const char *fname, void *arg)
{
	try_module_get(THIS_MODULE);

	os_log_debug(ISCSI_DBG_MODULE, "%s: 0x%p, get mod %d.\n",
		fname, arg, module_refcount(THIS_MODULE));
}
EXPORT_SYMBOL(__os_module_get);

void __os_module_put(const char *fname, void *arg)
{
	module_put(THIS_MODULE);

	os_log_debug(ISCSI_DBG_MODULE, "%s: 0x%p put mod %d.\n",
		fname, arg, module_refcount(THIS_MODULE));
}
EXPORT_SYMBOL(__os_module_put);

void __os_waitq_init(const char *fname, void *arg)
{
	wait_queue_head_t *waitq = arg;
	init_waitqueue_head(waitq);
	os_log_debug(ISCSI_DBG_WAIT, "%s: init waitq 0x%p.\n", fname, waitq);
}

void __os_wake_up(const char *fname, void *arg)
{
	wait_queue_head_t *waitq = arg;
	os_log_debug(ISCSI_DBG_WAIT, "%s: wake up waitq 0x%p.\n", fname, waitq);
	wake_up(waitq);
}

/**
 * __os_wait_on - wait on a condition to happen or timeout
 * returns 0 if condition is existing (no wait has happened)
 * otherwise returns 1 if waited.
 */
int __os_wait_on(const char *fname, void *arg, int (*fp) (void *), void *farg,
		 int timeout)
{
	int     waited = 0;
	wait_queue_head_t *waitq = arg;
	DECLARE_WAITQUEUE(wait, current);

	os_log_debug(ISCSI_DBG_WAIT,
		     "%s: wake on waitq 0x%p, arg 0x%p.\n", fname, waitq, farg);

	add_wait_queue(waitq, &wait);
	if (fp && (fp(farg)))
		goto done;

	os_log_debug(ISCSI_DBG_WAIT,
		     "%s: wake on waitq 0x%p, sleep %d.\n", fname, waitq,
		     timeout);

	set_current_state(TASK_INTERRUPTIBLE);
	/* 0 : waited timeout, 1 : no wait */
	waited = 1;
	if (timeout)
		schedule_timeout(timeout * HZ);
	else
		schedule();
	set_current_state(TASK_RUNNING);

      done:
	os_log_debug(ISCSI_DBG_WAIT,
		     "%s: wake on waitq 0x%p, done.\n", fname, waitq);
	remove_wait_queue(waitq, &wait);
	return waited;
}

int __os_wait_interruptible(void * arg,int event)
{
	wait_queue_head_t *waitq = arg;
	wait_event_interruptible(*waitq,event);
	return 1;	
}

int os_waitq_active(void *arg)
{
	wait_queue_head_t *waitq = arg;
	return (waitqueue_active(waitq));
}

void *os_data_init(void *parent)
{
	iscsi_os_data *p;

	p = os_alloc(sizeof(iscsi_os_data), 1, 1);
	if (!p)
		return NULL;

	p->parent = parent;	/* provide handle to parent */
	os_lock_init(&p->lock);
	os_waitq_init(&p->waitq);
	os_waitq_init(&p->ackq);

	return p;
}

void os_data_kthread_wakeup(void *arg)
{
	os_kthread_wakeup(&((iscsi_os_data *)arg)->waitq);
}

void os_data_counter_inc(void *p)
{
	iscsi_os_data *os_data = p;
        atomic_inc(&os_data->counter);
}

void os_data_counter_dec(void *p)
{
	iscsi_os_data *os_data = p;
        atomic_dec(&os_data->counter);
}

void os_data_counter_set(void *p, int v)
{
	iscsi_os_data *os_data = p;
        atomic_set(&os_data->counter, v);
}

int os_data_counter_read(void *p)
{
	iscsi_os_data *os_data = p;
	return (atomic_read(&os_data->counter));
}

void portal_counter_set(void *p, int v, int type)
{
	iscsi_os_data *os_data = p;
	if (type < MAX_PORTAL_STATS)
		atomic_set(&os_data->priv.stats[type], v);
}

int portal_counter_read(void *p, int type)
{
	iscsi_os_data *os_data = p;
	if (type >= MAX_PORTAL_STATS)
		return -EINVAL;
	return (atomic_read(&os_data->priv.stats[type]));
}

void portal_counter_add(void *p, int v, int type)
{
	iscsi_os_data *os_data = p;
	if (type < MAX_PORTAL_STATS)
		atomic_add(v, &os_data->priv.stats[type]);
}

void portal_counter_inc(void *p, int type)
{
	iscsi_os_data *os_data = p;
	if (type < MAX_PORTAL_STATS)
		atomic_inc(&os_data->priv.stats[type]);
}

int os_data_wait_on_waitq(void *arg, int (*fp) (void *), void *farg, int tmout)
{
	return os_wait_on(&((iscsi_os_data *)arg)->waitq, fp, farg, tmout); 
}

void os_data_wait_on_ackq(void *arg, int (*fp) (void *), void *farg, int tmout)
{
	os_wait_on(&((iscsi_os_data *)arg)->ackq, fp, farg, tmout);
}

void os_data_wake_up_waitq(void *arg)
{
	os_wake_up(&((iscsi_os_data *)arg)->waitq);
}

void os_data_wake_up_ackq(void *arg)
{
	os_wake_up(&((iscsi_os_data *)arg)->ackq);
}

int os_data_waitq_active(void *arg)
{
	return os_waitq_active(&((iscsi_os_data *)arg)->waitq);
}

int os_data_ackq_active(void *arg)
{
	return os_waitq_active(&((iscsi_os_data *)arg)->ackq);
}

void os_lock_os_data(void *l)
{
	os_lock(&((iscsi_os_data *)l)->lock);
}

void os_unlock_os_data(void *l)
{
	os_unlock(&((iscsi_os_data *)l)->lock);
}

void os_lock_irq_os_data(void *l)
{
	os_lock_irq(&((iscsi_os_data *)l)->lock);
}

void os_unlock_irq_os_data(void *l)
{
	os_unlock_irq(&((iscsi_os_data *)l)->lock);
}
