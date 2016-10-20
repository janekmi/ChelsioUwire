/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __CHFCOE_OS__
#define __CHFCOE_OS__

extern const unsigned long os_spinlock_size;
extern const unsigned long os_rwlock_size;
extern const unsigned long os_mutex_size;
extern const unsigned long os_atomic_size;
extern const unsigned long os_skbcb_offset;
extern const unsigned long os_work_size;
extern const unsigned long os_dwork_size;
extern const unsigned long os_sk_buff_head_size;
extern const unsigned long os_completion_size;
extern const unsigned long os_structpage_size;
extern const unsigned long os_hz;
extern const unsigned long os_page_size;
extern const unsigned long os_page_mask;
extern const unsigned long os_page_shift;

#ifdef __CHFCOE_PRIVATE__
typedef __signed__ int int32_t;
#ifdef __GNUC__
__extension__ typedef __signed__ long long int64_t;
__extension__ typedef unsigned long long __u64;
#else
typedef __signed__ long long int64_t;
typedef unsigned long long __u64;
#endif

typedef unsigned char uint8_t;
typedef signed char int8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

typedef _Bool bool;
typedef unsigned long size_t;

typedef unsigned long uintptr_t;

#ifdef __CHECKER__
#define __bitwise__ __attribute__((bitwise))
#else
#define __bitwise__
#endif
#ifdef __CHECK_ENDIAN__
#define __bitwise __bitwise__
#else
#define __bitwise
#endif

typedef __u64 __bitwise __be64;
typedef u32 __bitwise __be32;
typedef u16 __bitwise __be16;

typedef u8	__u8;
typedef u16	__u16;
typedef u32	__u32;

#define NULL ((void *)0)

#endif

enum chfcoe_log_level {
	CHFCOE_LOG_ERR,
	CHFCOE_LOG_WARN,
	CHFCOE_LOG_INFO,
	CHFCOE_LOG_DBG,
};

/* maps to linux errno */
typedef enum {
	CHFCOE_PERM = 1,
	CHFCOE_EIO = 5,
	CHFCOE_NOMEM = 12,
	CHFCOE_BUSY = 16,
	CHFCOE_INVAL = 22,
	CHFCOE_NOSUPP = 95,
	CHFCOE_OS_EMAX = CHFCOE_NOSUPP + 1,
} os_err_t;

struct chfcoe_work {
	void (*wfn)(void *);
	void *data;
	void *work;
};

typedef struct chfcoe_work chfcoe_work_t;
typedef struct chfcoe_work chfcoe_dwork_t;

#define chfcoe_work_size	(sizeof(chfcoe_work_t) + os_work_size)
#define chfcoe_dwork_size	(sizeof(chfcoe_dwork_t) + os_dwork_size)

/* spin lock */
void chfcoe_spin_lock_init(void *lock);
void chfcoe_spin_lock(void *lock);
void chfcoe_spin_unlock(void *lock);
void chfcoe_spin_lock_bh(void *lock);
void chfcoe_spin_unlock_bh(void *lock);

/* rw lock */
void chfcoe_rwlock_init(void *lock);
void chfcoe_read_lock(void *lock);
void chfcoe_read_unlock(void *lock);
void chfcoe_read_lock_bh(void *lock);
void chfcoe_read_unlock_bh(void *lock);
void chfcoe_write_lock_bh(void *lock);
void chfcoe_write_unlock_bh(void *lock);

/*Mutex lock*/
void chfcoe_mutex_init(void *lock);
void chfcoe_mutex_lock(void *lock);
void chfcoe_mutex_unlock(void *lock);

/*Memory Allocation*/
void *chfcoe_mem_alloc(unsigned long size);
void *chfcoe_mem_alloc_atomic(unsigned long size);
void *chfcoe_mem_alloc_node(unsigned long size, int node);
void chfcoe_mem_free(void *p);

/*Slab*/
void *chfcoe_cache_create(const char *name, unsigned long size);
void chfcoe_cache_destroy(void *cache);
void *chfcoe_cache_zalloc_atomic(void *cache);
void chfcoe_cache_free(void *cache, void *p);

/*Atomic variables*/
void chfcoe_atomic_set(void *p, int v);
int chfcoe_atomic_read(void *p);
void chfcoe_atomic_inc(void *p);
void chfcoe_atomic_dec(void *p);
int chfcoe_atomic_dec_and_test(void *p);

/*Bit operations*/
int chfcoe_test_bit(unsigned long pos, const void *p);
void chfcoe_set_bit(unsigned long pos, void *p);
void __chfcoe_set_bit(unsigned long pos, void *p);
void chfcoe_clear_bit(unsigned long pos, void *p);
void __chfcoe_clear_bit(unsigned long pos, void *p);
int chfcoe_test_and_clear_bit(unsigned long pos, void *p);
int chfcoe_test_and_set_bit(unsigned long pos, void *p);
unsigned long chfcoe_find_next_zero_bit(const unsigned long *p, unsigned long size,
		unsigned long off);
unsigned long chfcoe_find_next_bit(const unsigned long *p, unsigned long size,
		unsigned long off);
/* Byte order */
unsigned short chfcoe_ntohs(unsigned short v);
unsigned int chfcoe_ntohl(unsigned int v);
unsigned short chfcoe_htons(unsigned short v);
unsigned int chfcoe_htonl(unsigned int v);
unsigned int chfcoe_le32_to_cpu(unsigned int v);
unsigned long long chfcoe_le64_to_cpu(unsigned long long v);
unsigned short chfcoe_cpu_to_be16(unsigned short v);
unsigned int chfcoe_cpu_to_be32(unsigned int v);
unsigned long long chfcoe_cpu_to_be64(unsigned long long v);
unsigned long long chfcoe_be64_to_cpu(unsigned long long v);
unsigned short chfcoe_be16_to_cpu(unsigned short v);
unsigned int chfcoe_be32_to_cpu(unsigned int v);

/* Task */
void chfcoe_schedule(void);
void chfcoe_task_state_interruptible(void);
void chfcoe_task_state_running(void);
void *chfcoe_kthread_create_on_node(int (*threadfn)(void *), void *data,
		int node, const char *fmt, ...);
void chfcoe_wake_up_process(void *task);
int chfcoe_kthread_should_stop(void);
int chfcoe_kthread_stop(void *task);
void chfcoe_set_user_nice(void *task, long nice);

/*sk_buff operations*/
void *chfcoe_fcb_alloc(unsigned int len);
void *chfcoe_fcb_alloc_atomic(unsigned int len);
void chfcoe_fcb_reserve(void *skb, int len);
unsigned char *chfcoe_fcb_put(void *skb, unsigned int len);
void chfcoe_fcb_trim(void *skb, unsigned int len);
void chfcoe_fcb_free(void *skb);
unsigned char *chfcoe_fcb_push(void *skb, unsigned int len);
unsigned char *chfcoe_fcb_pull(void *skb, unsigned int len);
unsigned char *chfcoe_skb_data(void *skb);
unsigned int chfcoe_skb_len(void *skb);
void chfcoe_skb_dtr(void *skb, void *dtr);

/* skb queue */
void chfcoe_skb_queue_head_init(void *skb_list);
unsigned int chfcoe_skb_queue_len(void *skb_list);
void chfcoe_skb_queue_purge(void *skb_list);
void chfcoe_skb_queue_splice_init(void *skb_list, void *head);
void *chfcoe_sk_buff_head_lock(void *skb_list);
void chfcoe_skb_queue_tail(void *skb_list, void *skb);
void __chfcoe_skb_queue_tail(void *skb_list, void *skb);
void *chfcoe_skb_dequeue(void *skb_list);
void *__chfcoe_skb_dequeue(void *skb_list);


/*Workqueue*/
void *chfcoe_alloc_workqueue(const char *name);
int chfcoe_queue_work(void *workq, chfcoe_work_t *workp);
int chfcoe_queue_delayed_work(void *workq, chfcoe_dwork_t *dworkp, unsigned long delay_msecs);
int chfcoe_cancel_delayed_work(chfcoe_dwork_t *dworkp);
int chfcoe_cancel_delayed_work_sync(chfcoe_dwork_t *dworkp);
int chfcoe_flush_delayed_work(chfcoe_dwork_t *dworkp);
void chfcoe_flush_workqueue(void *workq);
void chfcoe_destroy_workqueue(void *workq);
int chfcoe_cancel_work_sync(chfcoe_work_t *workp);


/*Kernel Workqueue*/
int chfcoe_schedule_work(chfcoe_work_t *workp);
int chfcoe_schedule_delayed_work(chfcoe_dwork_t *dworkp, unsigned long delay);

void chfcoe_init_work(chfcoe_work_t *workp, void (*wfn)(void *), void *data);
void chfcoe_init_delayed_work(chfcoe_dwork_t *dworkp, void (*wfn)(void *),
		void *data);

/* lib */
char *os_strcpy(char *, const char *);
unsigned long os_strlen(const char *);
unsigned long os_strtoul(const char *, char **, int);
int os_time_after(unsigned long a, unsigned long b);
int os_isprint(int);
int os_sprintf(char *, const char *, ...);
int os_snprintf(char *, int, const char *, ...);
//void os_snprintf(char *, int, unsigned long);
void *chfcoe_memset(void *m, int c, unsigned long count);
void *chfcoe_memcpy(void *dst, const void *src, unsigned long count);
int chfcoe_memcmp(const void *m1, const void *m2, unsigned long count);

unsigned int chfcoe_smp_id(void);
unsigned int chfcoe_num_online_cpus(void);
void chfcoe_smp_mb(void);
void chfcoe_bug(void);
void chfcoe_log(unsigned int level, const char *fmt, ...);
uint64_t chfcoe_get_lun(const uint8_t *);

long long os_gettimeinsecs(void);

/* scatter list */
unsigned long long chfcoe_sg_dma_addr(void *sg);
unsigned int chfcoe_sg_dma_len(void *sg);
unsigned int chfcoe_sg_len(void *sg);
unsigned int chfcoe_sg_offset(void *sg);
void *chfcoe_sg_next(void *sg);
void *chfcoe_sg_page(void *sg);
unsigned int chfcoe_pci_map_page(void *pdev, void *sg_ptr, uint64_t *dma_addr);
void chfcoe_pci_unmap_page(void *pdev, void *page,
		uint64_t dma_addr, unsigned int len);
void *chfcoe_kmap(void *p);
void chfcoe_kunmap(void *p);

/* Completion */
void chfcoe_init_completion(void *cmpl);
void chfcoe_reinit_completion(void *cmpl);
void chfcoe_wait_for_completion(void *cmpl);
void chfcoe_complete(void *cmpl);

/* Delay */
void chfcoe_msleep(unsigned int msecs);
unsigned long os_jiffies(void);

/* netdev */
#ifndef SPEED_40000
#define SPEED_40000 40000
#endif

/* !!! NETDEV events defined in netdevice.h should match this array */
enum netdev_events {
	OS_NETDEV_UP = 1,
	OS_NETDEV_DOWN,
	OS_NETDEV_REBOOT,
	OS_NETDEV_CHANGE,
	OS_NETDEV_REGISTER,
	OS_NETDEV_UNREGISTER,
	OS_NETDEV_CHANGEMTU,
	OS_NETDEV_CHANGEADDR,
	OS_NETDEV_GOING_DOWN,
	OS_NETDEV_CHANGENAME,
	OS_NETDEV_FEAT_CHANGE,

	OS_NETDEV_EVENT_MAX
};

int os_dcb_get_prio(void *);
bool os_netif_running(void *ndev);
bool os_netif_carrier_ok(void *);
unsigned short os_pdev_vendor(void *);
unsigned short os_pdev_device(void *);
const char *os_netdev_name(void *);
void os_netdev_mac(void *, void *);
int os_netdev_mtu(void *ndev);
int os_netdev_speed(void *);

//void chfcoe_netdev_event(void *, void *, int);

//void os_netdev_event_subscribe(chfcoe_netdev_notifier_t);
//void os_netdev_event_unsubscribe(void);

/* file ops */
int os_read_file(const char *, char *, int);
int os_write_file(const char *, char *, int);
int os_stat_atime(const char *);

#endif
