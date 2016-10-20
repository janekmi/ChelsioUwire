/*
 *  Copyright (C) 2008-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description:
 *
 */

#ifndef __CSIO_DEFS_H__
#define __CSIO_DEFS_H__

#include <csio_oss.h>

/*****************************************************************************/
/* Standard function returns */
/*****************************************************************************/
typedef enum csio_oss_error csio_retval_t;

enum {
	CSIO_FALSE = 0,
	CSIO_TRUE = 1,
};

/*****************************************************************************/
/* Wait flags for allocation routines */
/*****************************************************************************/
enum {
	CSIO_MNOWAIT = 0,
	CSIO_MWAIT   = 1
};

/*****************************************************************************/
/* Linked list services */
/*****************************************************************************/
struct csio_list {
	struct csio_list *next;
	struct csio_list *prev;
};

#define csio_list_next(elem)	((struct csio_list *)(elem))->next
#define csio_list_prev(elem)	((struct csio_list *)(elem))->prev

#define csio_list_empty(head)						\
	(csio_list_next((head)) == ((struct csio_list *)(head)))

#define csio_head_init(head)						\
do {									\
	csio_list_next((head)) = (struct csio_list *)(head);		\
	csio_list_prev((head)) = (struct csio_list *)(head);		\
} while(0)

#define csio_elem_init(elem)						\
do {									\
	csio_list_next((elem)) = (struct csio_list *)NULL;		\
	csio_list_prev((elem)) = (struct csio_list *)NULL;		\
} while(0)

#define csio_enq_at_head(head, elem)					\
do {									\
	csio_list_next((elem)) = csio_list_next((head));		\
	csio_list_prev((elem)) = (struct csio_list *)(head);		\
	csio_list_prev(csio_list_next((head))) =			\
				(struct csio_list *)(elem);		\
	csio_list_next((head)) = (struct csio_list *)(elem);		\
} while(0)

#define csio_enq_at_tail(head, elem)					\
do {									\
	csio_list_prev((elem)) = csio_list_prev((head));		\
	csio_list_next((elem)) = (struct csio_list *)(head);		\
	csio_list_next(csio_list_prev((head)))				\
				= (struct csio_list *)(elem);		\
	csio_list_prev((head)) = (struct csio_list *)(elem);		\
} while(0)

#define csio_enq_list_at_head(dest, src)				\
do {									\
	csio_list_next(csio_list_prev((src))) = csio_list_next((dest));	\
	csio_list_prev(csio_list_next((src))) =				\
				(struct csio_list *)(dest);		\
	csio_list_prev(csio_list_next((dest))) = csio_list_prev((src));	\
	csio_list_next((dest)) = csio_list_next((src));			\
	csio_head_init((src));						\
} while(0)

#define csio_enq_list_at_tail(dest, src)				\
do {									\
	csio_list_next(csio_list_prev((dest))) = csio_list_next((src));	\
	csio_list_prev(csio_list_next((src))) = csio_list_prev((dest));	\
	csio_list_next(csio_list_prev((src))) = 			\
				(struct csio_list *)(dest);		\
	csio_list_prev((dest)) = csio_list_prev((src));			\
	csio_head_init((src));						\
} while(0)

#define csio_deq_elem(elem)						\
do {									\
	csio_list_next(csio_list_prev((elem))) = csio_list_next((elem));\
	csio_list_prev(csio_list_next((elem))) = csio_list_prev((elem));\
	csio_head_init(elem);						\
} while (0)

#define csio_elem_dequeued(elem)					 \
	((csio_list_next((elem)) == (struct csio_list *)(elem)) && 	 \
		(csio_list_prev((elem)) == (struct csio_list *)(elem)))

#define csio_deq_from_head(head, elem)					  \
do {									  \
	if (csio_list_empty(head)) {					  \
		*((struct csio_list **)(elem)) = (struct csio_list *)NULL;\
	}								  \
	else {								  \
		*((struct csio_list **)(elem)) = csio_list_next((head));  \
		csio_list_next((head)) = 				  \
				csio_list_next(csio_list_next((head)));   \
		csio_list_prev(csio_list_next((head))) = (head);	  \
		csio_elem_init(*((struct csio_list **)(elem)));	          \
	}								  \
} while(0)

#define csio_deq_from_tail(head, elem)      		        	  \
do {									  \
	if (csio_list_empty(head)) {					  \
		*((struct csio_list **)(elem)) = (struct csio_list *)NULL;\
	}								  \
	else {								  \
		*((struct csio_list **)(elem)) = csio_list_prev((head));  \
		csio_list_prev((head)) = 				  \
				csio_list_prev(csio_list_prev((head)));   \
		csio_list_next(csio_list_prev((head))) = (head);	  \
		csio_elem_init(*((struct csio_list **)(elem)));	      	  \
	}							      	  \
} while(0)

#define csio_list_for_each(elem, head)					  \
	for (elem = (head)->next; elem != head; elem = elem->next)

#define csio_list_for_each_safe(elem, n, head)				  \
	for (elem = (head)->next, n = elem->next; elem != head; elem = n, \
		n = elem->next)

/*****************************************************************************/
/* Debug logging */
/*****************************************************************************/
/* Module support for debugging */
#define CSIO_SCSI_MOD		0x01
#define CSIO_DISC_MOD		0x02	
#define CSIO_LNODE_MOD		0x04
#define CSIO_RNODE_MOD		0x08
#define CSIO_HW_MOD		0x10
#define CSIO_ALL_MOD		0xFF

/* Log Levels for debugging */
#define CSIO_INIT_LEV		0x01
#define CSIO_FATAL_LEV		0x02
#define CSIO_ERR_LEV		0x04
#define CSIO_INFO_LEV		0x08
#define CSIO_WARN_LEV		0x10	
#define CSIO_DBG_LEV		0x20
#define CSIO_STOP_ON_FATAL_LEV	0x40
#define CSIO_ALL_LEV		0xFF

#ifdef __CSIO_DEBUG_VERBOSE__
#define CSIO_VDBG_LEV		CSIO_DBG_LEV	/* Verbose debug */
#else
#define CSIO_VDBG_LEV		0
#endif

/* SET/GET macros for Module & Level */
#define S_DBG_MOD		8
#define M_DBG_MOD		0xFF
#define V_DBG_MOD(x)   		((x) << S_DBG_MOD)
#define G_DBG_MOD(x)   		(((x) >> S_DBG_MOD) & M_DBG_MOD)
#define V_DBG_DFT_MOD  		V_DBG_MOD(CSIO_ALL_MOD)

#define S_DBG_LEV		0
#define M_DBG_LEV		0xFF
#define V_DBG_LEV(x)   		((x) << S_DBG_LEV)
#define G_DBG_LEV(x)   		(((x) >> S_DBG_LEV) & M_DBG_LEV)
#define V_DBG_DFT_LEV 		\
			V_DBG_LEV(CSIO_INIT_LEV | CSIO_FATAL_LEV | CSIO_ERR_LEV)

#define CSIO_DEVID(__dev)	 __dev->dev_num
#define CSIO_DEVID_LO(__dev)	 CSIO_DEVID(__dev) & 0xFFFF
#define CSIO_DEVID_HI(__dev)	 (CSIO_DEVID(__dev) >> 16) & 0xFFFF

#define CSIO_PARAM(x, y)	 (x)->params.y
#define DB_CFG_LEV(x)		 (x ? CSIO_PARAM(x, log_level) : 0)

#define CSIO_DB_LOG(__hndl, __mod, __lev, __fmt, ...)	\
do {	\
	if((DB_CFG_LEV(__hndl) & V_DBG_MOD(__mod)) && 	\
	(DB_CFG_LEV(__hndl) & V_DBG_LEV(__lev))) { \
		csio_oss_db_log("CSIO_DBG:%x:%x "__fmt,	CSIO_DEVID_HI(__hndl), \
			CSIO_DEVID_LO(__hndl), ##__VA_ARGS__);	\
	}	\
} while(0)

#define csio_info(__hw, __fmt, ...)	\
do {	\
	csio_oss_info((__hw)->os_dev, __fmt, ##__VA_ARGS__);	\
} while(0)
								 
#define csio_fatal(__hw, __fmt, ...)	\
do {	\
	csio_oss_fatal((__hw)->os_dev, __fmt, ##__VA_ARGS__);	\
} while(0)

#define csio_err(__hw, __fmt, ...)	\
do {	\
	csio_oss_err((__hw)->os_dev, __fmt, ##__VA_ARGS__);	\
} while(0)

#define csio_warn(__hw, __fmt, ...)	\
do {	\
	csio_oss_warn((__hw)->os_dev, __fmt, ##__VA_ARGS__);	\
} while(0)

#define csio_dbg(__hw, __fmt, ...)	\
do {	\
	csio_oss_dbg((__hw)->os_dev, __fmt, ##__VA_ARGS__);	\
} while(0)

#define csio_vdbg(__hw, __fmt, ...)	\
do {	\
	csio_oss_vdbg((__hw)->os_dev, __fmt, ##__VA_ARGS__);	\
} while(0)

#define csio_scsi_dbg(__hw, __fmt, ...)	\
do {	\
	csio_oss_scsi_dbg((__hw)->os_dev, __fmt, ##__VA_ARGS__);	\
} while(0)

#define csio_scsi_vdbg(__hw, __fmt, ...)	\
do {	\
	csio_oss_scsi_vdbg((__hw)->os_dev, __fmt, ##__VA_ARGS__); \
} while(0)

#define csio_scsi_vdbg_cnd(__cnd, __hw, __fmt, ...)	\
do {	\
	csio_oss_scsi_vdbg((__cnd), (__hw)->os_dev, __fmt, ##__VA_ARGS__); \
} while(0)
#define CSIO_DB_BEGIN	csio_oss_db_func("CSIO_DBG: Enter ");
#define CSIO_DB_END	csio_oss_db_func("CSIO_DBG: Leave ");

#ifdef __CSIO_TRACE_SUPPORT__
#define CSIO_TRACE(_t, _mod, _lev, _a1, _a2, _a3, _a4)	\
	csio_oss_trace(((_t) ? (_t->trace_buf) : NULL), \
			(V_DBG_MOD(_mod) | V_DBG_LEV(_lev)), \
			CSIO_TRACE_IO, (_a1), (_a2), (_a3), (_a4)) 
#define CSIO_TRACE_SM(_t, _mod, _lev, _type, _a1, _a2, _a3, _a4)	\
	csio_oss_trace(_t, (V_DBG_MOD(_mod) | V_DBG_LEV(_lev)), \
			_type, (_a1), (_a2), (_a3), (_a4)) 
#else	/* __CSIO_TRACE_SUPPORT__ */
#define CSIO_TRACE(_t, _mod, _lev, _a1, _a2, _a3, _a4)
#define CSIO_TRACE_SM(_t, _mod, _lev, _type, _a1, _a2, _a3, _a4)
#endif  /* __CSIO_TRACE_SUPPORT__ */

/*****************************************************************************/
/* State machine defines */
/*****************************************************************************/
typedef void (*csio_sm_state_t)(void *, uint32_t);

struct csio_subsm {
	csio_sm_state_t		sm_state;
};

/*
 * This structure should be placed at the beginning of the
 * module that uses state machine services. That way, users
 * can invoke the state passing the module as the parameter.
 */
struct csio_sm {
	struct csio_list	sm_list;
	csio_sm_state_t		sm_state;
#ifdef __CSIO_TRACE_SUPPORT__
	void *			trace_ctx;	/* Trace context */
#endif
};

/* State machine defines */

#define	csio_set_state(__smp, __state)					    \
do {									    \
	csio_vprintk("CSIO_DBG: Set module [%p] to State"	    	    \
			"["#__state"]\n", __smp);		    	    \
	CSIO_TRACE_SM(((struct csio_sm *) (__smp))->trace_ctx,		    \
			CSIO_HW_MOD, CSIO_DBG_LEV, CSIO_TRACE_SMS,	    \
			(__smp), (__state), 0, 0);		      	    \
	((struct csio_sm *)(__smp))->sm_state = (csio_sm_state_t)(__state); \
} while(0)


#define csio_post_event(__smp, __evt)					    \
do {									    \
	csio_vprintk("CSIO_DBG: Post module [%p] an "	    	    \
			"Event[%d]\n", __smp, __evt);		    	    \
	CSIO_TRACE_SM(((struct csio_sm *) __smp)->trace_ctx, 		    \
			CSIO_HW_MOD, CSIO_DBG_LEV, CSIO_TRACE_SME,	    \
			__smp, __evt, 0, 0);		    	            \
	((struct csio_sm *) (__smp))->sm_state((__smp), (uint32_t)(__evt)); \
} while(0)

#define	csio_get_state(__smp)	((struct csio_sm *)(__smp))->sm_state

#define	csio_match_state(__smp, __state)				    \
	(csio_get_state((__smp)) == (csio_sm_state_t)(__state))

#ifdef __CSIO_TRACE_SUPPORT__
#define csio_init_state(__smp, __state, __trace_ctx)			    \
do {									    \
	((struct csio_sm *)(__smp))->sm_state = (csio_sm_state_t)(__state); \
	((struct csio_sm *)(__smp))->trace_ctx = (void *) (__trace_ctx); \
} while(0)
#else
#define csio_init_state(__smp, __state, __trace_ctx)			    \
do {									    \
	((struct csio_sm *)(__smp))->sm_state = (csio_sm_state_t)(__state); \
} while(0)
#endif


/*****************************************************************************
 * General non-OS specific services                                          *
 *****************************************************************************/

#define CSIO_ROUNDUP(__v, __r)		(((__v) + (__r) - 1) / (__r))
#define CSIO_DIV_ROUND_UP(__n, __d)	CSIO_ROUNDUP((__n), (__d))
#define CSIO_ALIGN(__val, __align)	CSIO_OSS_ALIGN((__val), (__align))
#define CSIO_PTR_ALIGN(__ptr, __align)	(((uintptr_t)(__ptr) + 		\
					 (__align) - 1) / (__align) * (__align))

#define CSIO_MIN(__x, __y)		((__x) < (__y) ? (__x) : (__y))
#define CSIO_ABS(__x)			((__x) < 0 ? -(__x) : (__x))
#define CSIO_ARRAY_SIZE(x) 		(sizeof(x) / sizeof((x)[0]))
#define CSIO_OFFSETOF(TYPE, MEMBER) 	((size_t) &((TYPE *)0)->MEMBER)
#define CSIO_INVALID_IDX		0xFFFFFFFF
#define CSIO_INC_STATS(elem, val)	(elem)->stats.val++
#define CSIO_DEC_STATS(elem, val)	(elem)->stats.val--
#define CSIO_VALID_WWN(__n)		((*__n >> 4) == 0x5 ? CSIO_TRUE: \
						CSIO_FALSE)
/* Memory allocation/free */
static inline void *
csio_alloc(struct csio_list *desc, size_t size, int flag)
{
	void *addr;

	/* TODO: need locks for these. */
	csio_deq_from_head(desc, &addr);

	return addr;
}

static inline void
csio_free(struct csio_list *desc, void *addr)
{
	csio_enq_at_tail(desc, addr);
	return;
}

#define csio_virt_addr_valid(__addr)	csio_oss_virt_add_valid((__addr))

static inline uint64_t
csio_wwn_to_u64(uint8_t *wwn)
{
	return 	(uint64_t)wwn[0] << 56 | (uint64_t)wwn[1] << 48 |
		(uint64_t)wwn[2] << 40 | (uint64_t)wwn[3] << 32 |
		(uint64_t)wwn[4] << 24 | (uint64_t)wwn[5] << 16 |
		(uint64_t)wwn[6] <<  8 | (uint64_t)wwn[7];
}

static inline void
csio_u64_to_wwn(uint64_t inm, u8 *wwn)
{
	wwn[0] = (inm >> 56) & 0xff;
	wwn[1] = (inm >> 48) & 0xff;
	wwn[2] = (inm >> 40) & 0xff;
	wwn[3] = (inm >> 32) & 0xff;
	wwn[4] = (inm >> 24) & 0xff;
	wwn[5] = (inm >> 16) & 0xff;
	wwn[6] = (inm >> 8) & 0xff;
	wwn[7] = inm & 0xff;
}

/*****************************************************************************
 * Short definitions for OS specific services                                *
 *****************************************************************************/

/* Cache/page related defiens */
#define csio_cacheline_sz(_dev)		csio_oss_cacheline_sz(_dev)
#define CSIO_PAGE_SIZE			CSIO_OSS_PAGE_SIZE
#define CSIO_PAGE_MASK			CSIO_OSS_PAGE_MASK
#define CSIO_INT_MAX			CSIO_OSS_INT_MAX

#define __csio_cacheline_aligned	__csio_oss_cacheline_aligned

/* Locking */
typedef struct csio_oss_spinlock csio_spinlock_t;
typedef struct csio_oss_mutex	csio_mutex_t;

#define csio_spin_lock_init(__l)	csio_oss_spin_lock_init((__l))
#define csio_spin_lock(_hw, __l)			\
			csio_oss_spin_lock((_hw)->os_dev, (__l))
#define csio_spin_lock_irq(_hw, __l)			\
			csio_oss_spin_lock_irq((_hw)->os_dev, (__l))
#define csio_spin_lock_irqsave(_hw, __l, __f) 		\
			csio_oss_spin_lock_irqsave((_hw)->os_dev, (__l), (__f))
#define csio_spin_unlock(_hw, __l)			\
			csio_oss_spin_unlock((_hw)->os_dev, (__l))
#define csio_spin_unlock_irq(_hw, __l)			\
			csio_oss_spin_unlock_irq((_hw)->os_dev, (__l))
#define csio_spin_unlock_irqrestore(_hw, __l, __f)	\
		csio_oss_spin_unlock_irqrestore((_hw)->os_dev, (__l), (__f))

/* Timers */
typedef struct csio_oss_timer		csio_timer_t;
#define csio_timer_init(__t, __f, __d)	csio_oss_timer_init((__t), (__f), (__d))
#define csio_timer_start(__t, __o)	csio_oss_timer_start(__t, (__o))
#define csio_timer_stop(__t)		csio_oss_timer_stop((__t))

/* Trace support */
typedef struct csio_oss_trace_buf	csio_trace_buf_t;

/* Data capture support */
#ifdef CSIO_DATA_CAPTURE
typedef struct csio_oss_dcap_buf       csio_dcap_buf_t;
typedef struct csio_oss_dcap           csio_dcap_t;

#define CSIO_DCAP_WRITE(_t, _d, _l)    \
	csio_oss_dcap_write((_t), (_d), (_l))

#define CSIO_DCAP_READ(_t, _d, _l)     \
	csio_oss_dcap_read((_t), (_d), (_l))
#endif


#ifdef __CSIO_TRACE_SUPPORT__
#define csio_trace_init(__t, __l)	csio_oss_trace_init((__t), (__l))
#define csio_trace_start(__t, __l)	csio_oss_trace_start((__t), (__l))
#define csio_trace_stop(__t)		csio_oss_trace_stop((__t))
#define csio_trace_readmsg(__t, __a, __l)	\
	csio_oss_trace_readmsg((__t), (__a), (__l))
#else
#define csio_trace_init(__t, __l)
#define csio_trace_start(__t, __l)
#define csio_trace_stop(__t)	
#define csio_trace_readmsg(__t, __a, __l)
#endif

/* Memory fence/barriers */
#define csio_mb() 			csio_oss_mb()
#define csio_rmb() 			csio_oss_rmb()
#define csio_wmb() 			csio_oss_wmb()

/* Debug assertions */
#define	CSIO_ASSERT(__c)		csio_oss_assert((__c))
#define CSIO_DB_ASSERT(__c)		csio_oss_db_assert((__c))

/* Print/logging */
#define csio_printk( ... )		csio_oss_printk(__VA_ARGS__)
#define csio_vprintk( ... )		csio_oss_vprintk(__VA_ARGS__)
#ifdef __CSIO_DEBUG_VERBOSE__
#define CSIO_DUMP_BUF(__buf, __len)	csio_oss_dump_buffer((__buf), (__len))
#define CSIO_SCSI_DUMP_BUF(__cnd, __buf, __len)	\
			csio_oss_scsi_dump_buffer((__cnd), (__buf), (__len))
#else
#define CSIO_DUMP_BUF(__buf, __len)
#define CSIO_SCSI_DUMP_BUF(__cnd, __buf, __len)
#endif /* CSIO_DEBUG_VERBOSE */

/* DMA memory allocations */
typedef struct csio_oss_dma_obj		csio_dma_obj_t;
#define csio_dma_alloc(__dobj, __dev, __sz, __aln, __phys, __fl)	     \
					csio_oss_dma_alloc((__dobj), (__dev),\
					(__sz), (__aln), (__phys), (__fl))
#define csio_dma_free(__d, __v)		csio_oss_dma_free((__d), (__v))
#define csio_dma_pool_alloc(__dobj, __dev, __sz, __aln, __phys, __fl)	     \
					csio_oss_dma_pool_alloc((__dobj),    \
					(__dev), (__sz), (__aln),	     \
					(__phys), (__fl))
#define csio_dma_pool_free(__d, __v)	csio_oss_dma_pool_free((__d), (__v))

/* PCI */
#define csio_pci_vpd_capability(__adap, __p)	\
			csio_oss_pci_vpd_capability((__adap)->pdev, (__p))
#define csio_pci_capability(__hw, __cap, __p)	\
			csio_oss_pci_capability((__hw)->os_dev, (__cap), (__p))

/* ISR Workers/DPC */
typedef struct csio_oss_workq		csio_workq_t;
typedef	struct csio_oss_work		csio_work_t;
#define csio_workq_create(__wq, __d1, __d2)	\
					csio_oss_workq_create((__wq),	\
							(__d1), (__d2))
#define csio_queue_work(__wq, __w)	\
					csio_oss_queue_work((__wq),	\
							(__w))
#define csio_workq_flush(__wq)		\
					csio_oss_workq_flush((__wq))
#define csio_workq_destroy(__wq)	\
					csio_oss_workq_destroy((__wq))
#define csio_work_init(__w, __f, __d1, __d2, __os_func)			\
					csio_oss_work_init((__w), (__f),\
					(__d1), (__d2), (__os_func))
#define csio_work_schedule(__w)		csio_oss_work_schedule((__w))
#define csio_work_cleanup(__w)		csio_oss_work_cleanup((__w))

/* Busy waiter in milli-secs */
#define csio_mdelay(__m)		csio_oss_mdelay((__m))
/* Busy waiter in micro-secs */
#define csio_udelay(__u)		csio_oss_udelay((__u))
/* Busy waiter in nano-secs */
#define csio_ndelay(__n)		csio_oss_ndelay((__n))

/* Timed sleep in mill-secs */
#define csio_msleep(__m)		csio_oss_msleep((__m))

/* Sleep/wakeup */
typedef struct csio_oss_cmpl		csio_cmpl_t;
#define csio_cmpl_init(__c)		csio_oss_cmpl_init((__c))
#define csio_sleep(__c)			csio_oss_sleep((__c))
#define csio_wakeup(__c)		csio_oss_wakeup((__c))

/* Os specific time variable */
typedef	csio_oss_osticks_t		csio_osticks_t;
#define csio_os_msecs()			csio_oss_os_msecs()
#define csio_os_usecs()			csio_oss_os_usecs()

/* OS bar mapping */
typedef csio_oss_iomem_t		csio_iomem_t;
typedef	csio_oss_physaddr_t		csio_physaddr_t;
#define csio_phys_addr(__p)		csio_oss_phys_addr((__p))
#define csio_reg_valid(__d, __r)	csio_oss_reg_valid((__d), (__r))

/* Byte setting */
#define csio_memset(__p, __v, __l)	csio_oss_memset((__p), (__v), (__l))
#define csio_memcpy(__d, __s, __l)	csio_oss_memcpy((__d), (__s), (__l))
#define csio_memcmp(__d, __s, __l)	csio_oss_memcmp((__d), (__s), (__l))
#define csio_strcpy(__d, __s)		csio_oss_strcpy((__d), (__s))
#define csio_strncpy(__d, __s, __l)	csio_oss_strncpy((__d), (__s), (__l))
#define csio_strstrip(__s)		csio_oss_strstrip((__s))
#define csio_strlen(__s)		csio_oss_strlen((__s))

/* Os name and version */
#define csio_osname(__hw, __buf, __sz)		\
		csio_oss_osname((__hw)->os_dev, (__buf), (__sz))
/* Os hostname */
#define csio_hostname(__hw, __buf, __sz)	\
		csio_oss_hostname((__hw)->os_dev, (__buf), (__sz))


/* Byte order */
#define csio_ntohs(_x)			csio_oss_ntohs(_x)
#define csio_ntohl(_x)			csio_oss_ntohl(_x)
#define csio_htons(_x)			csio_oss_htons(_x)
#define csio_htonl(_x)			csio_oss_htonl(_x)
#define csio_cpu_to_le16(_x)		csio_oss_cpu_to_le16(_x)
#define csio_cpu_to_le32(_x)		csio_oss_cpu_to_le32(_x)
#define csio_cpu_to_le64(_x)		csio_oss_cpu_to_le64(_x)
#define csio_le16_to_cpu(_x)		csio_oss_le16_to_cpu(_x)
#define csio_le32_to_cpu(_x)		csio_oss_le32_to_cpu(_x)
#define csio_le64_to_cpu(_x)		csio_oss_le64_to_cpu(_x)
#define csio_cpu_to_be16(_x)		csio_oss_cpu_to_be16(_x)
#define csio_cpu_to_be32(_x)		csio_oss_cpu_to_be32(_x)
#define csio_cpu_to_be64(_x)		csio_oss_cpu_to_be64(_x)
#define csio_be16_to_cpu(_x)		csio_oss_be16_to_cpu(_x)
#define csio_be32_to_cpu(_x)		csio_oss_be32_to_cpu(_x)
#define csio_be64_to_cpu(_x)		csio_oss_be64_to_cpu(_x)
#define csio_swab32(_x)			csio_oss_swab32(_x)

/* Reference counting */
typedef	struct csio_oss_kref		csio_kref_t;
#define csio_kref_init(__r, __p, __f)	csio_oss_kref_init((__r), (__p), (__f))
#define csio_kref_get(__r)		csio_oss_kref_get((__r))
#define csio_kref_put(__r)		csio_oss_kref_put((__r))

/* optimizations */
#define csio_likely(_cond)		csio_oss_likely((_cond))
#define csio_unlikely(_cond)		csio_oss_unlikely((_cond))

/* SCSI */

#define CSIO_SAM_STAT_GOOD		CSIO_OSS_SAM_STAT_GOOD
#define CSIO_SAM_STAT_CHECK_CONDITION 	CSIO_OSS_SAM_STAT_CHECK_CONDITION
#define CSIO_SAM_STAT_CONDITION_MET	CSIO_OSS_SAM_STAT_CONDITION_MET
#define CSIO_SAM_STAT_BUSY		CSIO_OSS_SAM_STAT_BUSY
#define CSIO_SAM_STAT_INTERMEDIATE 	CSIO_OSS_SAM_STAT_INTERMEDIATE
#define CSIO_SAM_STAT_INTERMEDIATE_CONDITION_MET			\
	CSIO_OSS_SAM_STAT_INTERMEDIATE_CONDITION_MET
#define CSIO_SAM_STAT_RESERVATION_CONFLICT				\
	CSIO_OSS_SAM_STAT_RESERVATION_CONFLICT
#define CSIO_SAM_STAT_COMMAND_TERMINATED				\
	CSIO_OSS_SAM_STAT_COMMAND_TERMINATED
#define CSIO_SAM_STAT_TASK_SET_FULL	CSIO_OSS_SAM_STAT_TASK_SET_FULL
#define CSIO_SAM_STAT_ACA_ACTIVE	CSIO_OSS_SAM_STAT_ACA_ACTIVE
#define CSIO_SAM_STAT_TASK_ABORTED	CSIO_OSS_SAM_STAT_TASK_ABORTED

#define csio_sgel			csio_oss_sgel
#define csio_scsi_for_each_sg(_dev, _req, _sgel, _n, _i)		\
	csio_oss_scsi_for_each_sg((_dev), (_req), (_sgel), (_n), (_i))
#define csio_sg_reset(_sgel) 		csio_oss_sg_reset((_sgel))
#define csio_sgel_dma_addr(_sgel)	csio_oss_sgel_dma_addr((_sgel))
#define csio_sgel_virt(_sgel)		csio_oss_sgel_virt((_sgel))
#define csio_sgel_len(_sgel)		csio_oss_sgel_len((_sgel))
#define csio_sgel_next(_sgel)		csio_oss_sgel_next((_sgel))
#define csio_copy_to_sgel(__sgel, __from, __len)			\
	csio_oss_copy_to_sgel((__sgel), (__from), (__len))

#define csio_scsi_lun(_req, _sc2, _lu)	csio_oss_scsi_lun((_req), (_sc2), (_lu))
#define csio_scsi_oslun(_req)		csio_oss_scsi_oslun((_req))
#define csio_scsi_cdb(_req, _cdb)	csio_oss_scsi_cdb((_req), (_cdb))
#define csio_scsi_tag(_req, _tag, _hq, _oq, _sq)			\
	csio_oss_scsi_tag((_req), (_tag), (_hq), (_oq), (_sq))
#define csio_scsi_datalen(_req)		csio_oss_scsi_datalen((_req))
#define csio_scsi_tm_op(_req)		csio_oss_scsi_tm_op((_req))

/* Generic */

#define CSIO_PCI_BASE_ADDRESS_0		CSIO_OSS_PCI_BASE_ADDRESS_0
#define CSIO_PCI_BASE_ADDRESS_MEM_MASK	CSIO_OSS_PCI_BASE_ADDRESS_MEM_MASK

#define csio_ilog2(_x)			csio_oss_ilog2((_x))
#define csio_hweight32(__w)		csio_oss_hweight32((__w))

#endif /* ifndef __CSIO_DEFS_H__ */
