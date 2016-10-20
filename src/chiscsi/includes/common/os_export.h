#ifndef __ISCSI_OS_H__
#define __ISCSI_OS_H__

#include <common/iscsi_common.h>
#include <common/iscsi_sgvec.h>
#include <common/iscsi_socket.h>
#include <common/iscsi_lunmask.h>

/*
 * os-dependent declarations
 */

#ifndef NULL
#define NULL 	((void *)0)
#endif

extern const unsigned long os_page_mask;	/* for PAGE_MASK */
extern const unsigned long os_page_size;	/* for PAGE_SIZE */
extern const unsigned int os_page_shift;	/* for PAGE_SHIFT */
extern const unsigned int os_lock_size;	/* for spinlock */
extern const unsigned int os_waitq_size;	/* for waitq */
extern const unsigned int os_counter_size;	/* for atomic counter */
extern const unsigned int os_kthread_size;	/* for kthread info */

/*
 * wrapper functions
 */

void *os_data_init(void *);
#define os_data_free(p)		os_free(p)

extern unsigned long os_strtoul(const char *, char **, int);
extern void os_get_random_bytes(void *, int);

/* byte order */
unsigned short os_ntohs(unsigned short);
unsigned short os_htons(unsigned short);
unsigned int os_ntohl(unsigned int);
unsigned int os_htonl(unsigned int);
unsigned long long os_ntohll(unsigned long long);
unsigned long long os_htonll(unsigned long long);
unsigned int os_le32_to_host(unsigned int);

/* atomic counter */
void    os_counter_inc(void *);
void    os_counter_dec(void *);
void    os_counter_set(void *, int);
int     os_counter_read(void *);
void    os_counter_add(void *, int);

void	os_data_counter_inc(void *);
void	os_data_counter_dec(void *);
void	os_data_counter_set(void *, int);
int	os_data_counter_read(void *);
void	portal_counter_set(void *, int, int);
int	portal_counter_read(void *, int);
void	portal_counter_add(void *, int, int);
void	portal_counter_inc(void *, int);

void    iscsi_stats_inc(int);
void    iscsi_stats_dec(int);
void    iscsi_stats_set(int, int);
int     iscsi_stats_read(int);
int     iscsi_stats_display(char *, int);

/* atomic bit operation */
int     os_test_bit_atomic(void *, int);
void    os_set_bit_atomic(void *, int);
void    os_clear_bit_atomic(void *, int);
int     os_test_and_set_bit_atomic(void *, int);
int     os_test_and_clear_bit_atomic(void *, int);

/* spin_lock operation */
void    __os_lock_init(const char *, void *);
void    __os_lock(const char *, void *);
void    __os_unlock(const char *, void *);
void    __os_lock_irq(const char *, void *);
void    __os_unlock_irq(const char *, void *);

#define os_lock_init(l)		__os_lock_init(__FUNCTION__,l)
#define os_lock(l)		__os_lock(__FUNCTION__,l)
#define os_unlock(l)		__os_unlock(__FUNCTION__,l)
#define os_lock_irq(l)		__os_lock_irq(__FUNCTION__,l)
#define os_unlock_irq(l)	__os_unlock_irq(__FUNCTION__,l)

void	__os_module_get(const char *, void *);
void    __os_module_put(const char *, void *);
int     __os_module_refcnt(const char *, void *);

#define os_module_get(p)	__os_module_get(__FUNCTION__, (void *)p)
#define os_module_put(p)	__os_module_put(__FUNCTION__, (void *)p)

void	os_lock_os_data(void *);
void	os_unlock_os_data(void *);
void	os_lock_irq_os_data(void *);
void	os_unlock_irq_os_data(void *);

/* waitq operation */
void    __os_waitq_init(const char *, void *);
int     __os_wait_on(const char *, void *, int (*fp) (void *), void *, int);
int     __os_wait_interruptible(void *, int);
void    __os_wake_up(const char *, void *);
#define os_waitq_init(q)	__os_waitq_init(__FUNCTION__, q)
#define os_wait_on(arg,fp,farg,tmout)	\
		__os_wait_on(__FUNCTION__, arg, fp, farg, tmout)
#define os_wait_interruptible(arg, event) __os_wait_interruptible(arg,event)
#define os_wake_up(q)		__os_wake_up(__FUNCTION__, q)
int     os_waitq_active(void *);

int	os_data_wait_on_waitq(void *, int (*fp) (void *), void *, int);
void	os_data_wait_on_ackq(void *, int (*fp) (void *), void *, int);
void	os_data_wake_up_waitq(void *);
void	os_data_wake_up_ackq(void *);
int	os_data_waitq_active(void *);
int	os_data_ackq_active(void *);

/* memory allocation/free */

#define OS_MEM_WAIT	0x1     /* can wait */
#define OS_MEM_DMA	0x2     /* should be DMA-able */
#define OS_MEM_VIRT	0x4     /* don't need to physically contiguous */

void   *__os_alloc(const char *, unsigned int, char, char);
void   *__os_vmalloc(const char *, unsigned int);
void   __os_update_ramdisk_stats(unsigned long long);
void   __os_decrement_ramdisk_stats(unsigned long long);
int    __os_can_allocate_ramdisk(unsigned long long);
void    __os_free(const char *, void *);
void    __os_vfree(const char *, void *);
void   *__os_alloc_one_page(const char *, char, unsigned char **);
void    __os_free_one_page(const char *, void *);
void * __os_file_open(const char *, int, int);
void * __os_phys_to_virt(unsigned long);
int  __os_file_read(void *, void *, int, unsigned long long *);
int __os_file_write(void *, void *, int, unsigned long long *);
void __os_file_close(void *);
int __os_file_unlink(void *);

#define os_alloc(s,w,c)		__os_alloc(__FUNCTION__, s, w, c)
#define os_vmalloc(s)           __os_vmalloc(__FUNCTION__, s)
#define os_can_allocate_ramdisk(s) __os_can_allocate_ramdisk(s)
#define os_update_ramdisk_stats(s) __os_update_ramdisk_stats(s)
#define os_decrement_ramdisk_stats(s) __os_decrement_ramdisk_stats(s)
#define os_free(p) 		__os_free(__FUNCTION__, p)
#define os_vfree(p) 		__os_vfree(__FUNCTION__, p)
#define os_phys_to_virt(p)      __os_phys_to_virt(p)

#define os_file_read(a,b,c,d)		__os_file_read(a,b,c,d)
#define os_file_write(a,b,c,d)		__os_file_write(a,b,c,d)
#define os_file_open(a,b,c)		__os_file_open(a,b,c)
#define os_file_close(a)		__os_file_close(a)
#define os_file_unlink(a)		__os_file_unlink(a)

#define os_alloc_one_page(w,a)	__os_alloc_one_page(__FUNCTION__, w, a)
#define os_free_one_page(p) 	__os_free_one_page(__FUNCTION__, p)

/* user <-> kernel copy */
unsigned long os_copy_from_user(void *, const void *, unsigned long);
unsigned long os_copy_to_user(void *, const void *, unsigned long);

/* memory mapping */
int     os_chiscsi_sglist_page_map(chiscsi_sgvec *, int);
void    os_chiscsi_sglist_page_unmap(chiscsi_sgvec *, int);

/* kernel thread */
#define os_kthread_wakeup(q)	__os_wake_up(__FUNCTION__, q)

void	os_data_kthread_wakeup(void *);
int	os_kthread_create(void *, iscsi_thread_common *);
int     os_kthread_start(void *);
int     os_kthread_stop(void *);

/* timer */
void   *os_timer_alloc(char);
void    os_timer_free(void *);
int     os_timer_init(void *, void *);
void    os_timer_start(void *, int, void (*)(unsigned long));
void    os_timer_stop(void *);

unsigned long os_get_timestamp(void);

#endif /* ifndef __ISCSI_OS_H__ */
