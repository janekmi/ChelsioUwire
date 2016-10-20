/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*
 * Description:
 * 	The chfcoe_defs header file contains general purpose routine definitions
 */

#ifndef __CHFCOE_DEFS_H__
#define __CHFCOE_DEFS_H__

#include <chfcoe_os.h>

/*****************************************************************************/
/* Standard function returns */
/*****************************************************************************/
typedef enum {
	CHFCOE_SUCCESS,
	CHFCOE_EPROTO = CHFCOE_OS_EMAX,
	CHFCOE_RETRY,
	CHFCOE_TIMEOUT,
	CHFCOE_CANCELLED,
	CHFCOE_FATAL,
	CHFCOE_SCSI_ABORT_REQUESTED,
	CHFCOE_SCSI_ABORT_TIMEDOUT,
	CHFCOE_SCSI_ABORTED,	
	CHFCOE_SCSI_CLOSE_REQUESTED,
	CHFCOE_ERR_LINK_DOWN,
	CHFCOE_RDEV_NOT_READY,
	CHFCOE_ERR_RDEV_LOST,
	CHFCOE_ERR_RDEV_LOGO,
	CHFCOE_FCOE_NO_XCHG,
	CHFCOE_SCSI_RSP_ERR,
	CHFCOE_ERR_RDEV_IMPL_LOGO,
	CHFCOE_SCSI_UNDER_FLOW_ERR,
	CHFCOE_SCSI_OVER_FLOW_ERR,
	CHFCOE_SCSI_DDP_ERR,
	CHFCOE_SCSI_TASK_ERR,
} chfcoe_retval_t;

enum {
	CHFCOE_FALSE,
	CHFCOE_TRUE,
};

/*****************************************************************************/
/* Wait flags for allocation routines */
/*****************************************************************************/
enum {
	CHFCOE_NOATOMIC,
	CHFCOE_ATOMIC,
};

/*****************************************************************************/
/* Linked list services */
/*****************************************************************************/
struct chfcoe_list {
	struct chfcoe_list *next;
	struct chfcoe_list *prev;
};

#define chfcoe_list_next(elem)	((struct chfcoe_list *)(elem))->next
#define chfcoe_list_prev(elem)	((struct chfcoe_list *)(elem))->prev

#define chfcoe_list_empty(head)						\
	(chfcoe_list_next((head)) == ((struct chfcoe_list *)(head)))

#define chfcoe_head_init(head)						\
do {									\
	chfcoe_list_next((head)) = (struct chfcoe_list *)(head);	\
	chfcoe_list_prev((head)) = (struct chfcoe_list *)(head);	\
} while(0)

#define chfcoe_elem_init(elem)						\
do {									\
	chfcoe_list_next((elem)) = (struct chfcoe_list *)NULL;		\
	chfcoe_list_prev((elem)) = (struct chfcoe_list *)NULL;		\
} while(0)

#define chfcoe_enq_at_head(head, elem)					\
do {									\
	chfcoe_list_next((elem)) = chfcoe_list_next((head));		\
	chfcoe_list_prev((elem)) = (struct chfcoe_list *)(head);	\
	chfcoe_list_prev(chfcoe_list_next((head))) =			\
				(struct chfcoe_list *)(elem);		\
	chfcoe_list_next((head)) = (struct chfcoe_list *)(elem);	\
} while(0)

#define chfcoe_enq_at_tail(head, elem)					\
do {									\
	chfcoe_list_prev((elem)) = chfcoe_list_prev((head));		\
	chfcoe_list_next((elem)) = (struct chfcoe_list *)(head);	\
	chfcoe_list_next(chfcoe_list_prev((head)))			\
				 = (struct chfcoe_list *)(elem);	\
	chfcoe_list_prev((head)) = (struct chfcoe_list *)(elem);	\
} while(0)

#define chfcoe_enq_list_at_head(dest, src)				\
do {									\
	chfcoe_list_next(chfcoe_list_prev((src))) 			\
				 = chfcoe_list_next((dest));		\
	chfcoe_list_prev(chfcoe_list_next((src))) 			\
				 = (struct chfcoe_list *)(dest);	\
	chfcoe_list_prev(chfcoe_list_next((dest)))			\
				 = chfcoe_list_prev((src));		\
	chfcoe_list_next((dest)) = chfcoe_list_next((src));		\
	chfcoe_head_init((src));					\
} while(0)

#define chfcoe_enq_list_at_tail(dest, src)				\
do {									\
	chfcoe_list_next(chfcoe_list_prev((dest))) 			\
				= chfcoe_list_next((src));		\
	chfcoe_list_prev(chfcoe_list_next((src)))			\
				= chfcoe_list_prev((dest));		\
	chfcoe_list_next(chfcoe_list_prev((src))) = 			\
				(struct chfcoe_list *)(dest);		\
	chfcoe_list_prev((dest)) = chfcoe_list_prev((src));		\
	chfcoe_head_init((src));					\
} while(0)

#define chfcoe_deq_elem(elem)						\
do {									\
	chfcoe_list_next(chfcoe_list_prev((elem))) 			\
				= chfcoe_list_next((elem));		\
	chfcoe_list_prev(chfcoe_list_next((elem)))			\
				 = chfcoe_list_prev((elem));		\
	chfcoe_elem_init(elem);						\
} while (0)

#define chfcoe_elem_dequeued(elem)					\
	((chfcoe_list_next((elem)) == (struct chfcoe_list *)(elem)) && 	\
		(chfcoe_list_prev((elem)) 				\
				== (struct chfcoe_list *)(elem)))

#define chfcoe_deq_from_head(head, elem)				\
do {									\
	if (chfcoe_list_empty(head)) {					\
		*((struct chfcoe_list **)(elem))			\
				= (struct chfcoe_list *)NULL;		\
	}								\
	else {								\
		*((struct chfcoe_list **)(elem)) 			\
				= chfcoe_list_next((head));  		\
		chfcoe_list_next((head)) = 				\
			chfcoe_list_next(chfcoe_list_next((head)));   	\
		chfcoe_list_prev(chfcoe_list_next((head))) = (head);	\
		chfcoe_elem_init(*((struct chfcoe_list **)(elem)));	\
	}								\
} while(0)

#define chfcoe_deq_from_tail(head, elem)      		        	\
do {									\
	if (chfcoe_list_empty(head)) {					\
		*((struct chfcoe_list **)(elem)) 			\
			= (struct chfcoe_list *)NULL;			\
	}								\
	else {								\
		*((struct chfcoe_list **)(elem)) 			\
			= chfcoe_list_prev((head));  			\
		chfcoe_list_prev((head)) = 				\
			chfcoe_list_prev(chfcoe_list_prev((head)));   	\
		chfcoe_list_next(chfcoe_list_prev((head))) = (head);	\
		chfcoe_elem_init(*((struct chfcoe_list **)(elem)));	\
	}							      	\
} while(0)

#define chfcoe_list_for_each(elem, head)				\
	for (elem = (head)->next; elem != head; elem = elem->next)

#define chfcoe_list_for_each_safe(elem, n, head)			\
	for (elem = (head)->next, n = elem->next; elem != head; 	\
		elem = n, n = elem->next)

/* Global definitions */
#define	CHFCOE_MAX_XID			(4095)
#define CHFCOE_MAX_PORTS		0x4
#define	CHFCOE_TARGET			(0x1)

#define chfcoe_info(__port, __fmt, ...)					\
do {									\
	chfcoe_log(CHFCOE_LOG_INFO, __fmt, ##__VA_ARGS__);		\
} while(0)
#define chfcoe_err(__port, __fmt, ...)					\
do {									\
	chfcoe_log(CHFCOE_LOG_ERR, __fmt, ##__VA_ARGS__);		\
} while(0)

#define chfcoe_warn(__port, __fmt, ...)					\
do {									\
	chfcoe_log(CHFCOE_LOG_WARN, __fmt, ##__VA_ARGS__);		\
} while(0)
#ifdef __CHFCOE_DEBUG__
#define chfcoe_dbg(__port, __fmt, ...)					\
do {									\
	chfcoe_log(CHFCOE_LOG_DBG, __fmt, ##__VA_ARGS__);		\
} while(0)
#else
#define chfcoe_dbg(__port, __fmt, ...)					
#endif

/*****************************************************************************/
/* State machine defines */
/*****************************************************************************/
#define	chfcoe_set_state(__mod, __state)				\
do {									\
	chfcoe_dbg(CHFCOE_LOG_DBG, "Set module [%p] to State[%d]\n", __mod, __state);		    	\
	((__mod))->state = (__state); 					\
} while(0)

#define	chfcoe_get_state(__mod)	((__mod))->state

#define	chfcoe_match_state(__mod, __state)				\
	(chfcoe_get_state((__mod)) == (__state))

/* General defines */
#define chfcoe_for_each_port(adapter, iter) 				\
        for (iter = 0; iter < (adapter)->nports; ++iter)

/*****************************************************************************
 * General non-OS specific services                                          *
 *****************************************************************************/

#define CHFCOE_ROUNDUP(__v, __r)	(((__v) + (__r) - 1) / (__r))
#define CHFCOE_DIV_ROUND_UP(__n, __d)	CHFCOE_ROUNDUP((__n), (__d))
#define CHFCOE_ALIGN(__val, __align)					\
	CHFCOE_OSS_ALIGN((__val), (__align))
#define CHFCOE_PTR_ALIGN(__ptr, __align)				\
	(((uintptr_t)(__ptr) + (__align) - 1) / (__align) * (__align))

#define CHFCOE_MIN(__x, __y)		((__x) < (__y) ? (__x) : (__y))
#define CHFCOE_ABS(__x)			((__x) < 0 ? -(__x) : (__x))
#define CHFCOE_ARRAY_SIZE(x) 		(sizeof(x) / sizeof((x)[0]))
#define CHFCOE_OFFSETOF(TYPE, MEMBER) 	((size_t) &((TYPE *)0)->MEMBER)
#define CHFCOE_INVALID_IDX		0xFFFFFFFF
#define CHFCOE_INC_STATS(elem, val)	(elem)->stats.val++
#define CHFCOE_DEC_STATS(elem, val)	(elem)->stats.val--
#define CHFCOE_VALID_WWN(__n)						\
	((*__n >> 4) == 0x5 ? CHFCOE_TRUE: CHFCOE_FALSE)

#define CHFCOE_PTR_OFFSET(p, off) ((void *)((unsigned char *)(p) + (off)))
#define CHFCOE_CONTAINER_OF(ptr, type, mem)				\
	((void *)((unsigned char *)(ptr) - CHFCOE_OFFSETOF(type, mem)))
#define CHFCOE_BITS_TO_LONGS(bits) CHFCOE_DIV_ROUND_UP(bits, 8 * sizeof(unsigned long))
#define min(x, y) ({                            \
	typeof(x) _min1 = (x);                  \
	typeof(y) _min2 = (y);                  \
	(void) (&_min1 == &_min2);              \
	_min1 < _min2 ? _min1 : _min2; })

#define ETH_ALEN	6

/* Memory allocation/free */
static inline void *
chfcoe_alloc(struct chfcoe_list *desc)
{
	void *addr;

	chfcoe_deq_from_head(desc, &addr);

	return addr;
} /* chfcoe_alloc */

static inline void
chfcoe_free(struct chfcoe_list *desc, void *addr)
{
	chfcoe_enq_at_tail(desc, addr);
	return;
} /* chfcoe_free */

static inline uint64_t
chfcoe_wwn_to_u64(uint8_t *wwn)
{
	return 	(uint64_t)wwn[0] << 56 | (uint64_t)wwn[1] << 48 |
		(uint64_t)wwn[2] << 40 | (uint64_t)wwn[3] << 32 |
		(uint64_t)wwn[4] << 24 | (uint64_t)wwn[5] << 16 |
		(uint64_t)wwn[6] <<  8 | (uint64_t)wwn[7];
} /* chfcoe_wwn_to_u64 */

static inline void
chfcoe_u64_to_wwn(uint64_t inm, u8 *wwn)
{
	wwn[0] = (inm >> 56) & 0xff;
	wwn[1] = (inm >> 48) & 0xff;
	wwn[2] = (inm >> 40) & 0xff;
	wwn[3] = (inm >> 32) & 0xff;
	wwn[4] = (inm >> 24) & 0xff;
	wwn[5] = (inm >> 16) & 0xff;
	wwn[6] = (inm >> 8) & 0xff;
	wwn[7] = inm & 0xff;
} /* chfcoe_u64_to_wwn */

static inline void
chfcoe_get_wwnn(unsigned char *wwnn, uint8_t *mac, u32 portid, u8 tag)
{
	u64 *wwn;
	        /* World Wide Node Name */
	chfcoe_memcpy(wwnn, mac, 6);

        wwn = (u64 *) wwnn;
        (*wwn) = chfcoe_cpu_to_be64(chfcoe_be64_to_cpu(*wwn) >> 4);
	
        wwnn[0] = 0x50;
        wwnn[6] |= (u8) portid;
        wwnn[7] = tag;
} /* chfcoe_get_wwnn */

static inline void
chfcoe_get_wwpn(unsigned char *wwpn, unsigned char *wwnn, u8 tag)
{
	chfcoe_memcpy(wwpn, wwnn, 8);
	/* World Wide Port Name */
	wwpn[7] |= (1 << 7);
        wwpn[7] |= tag;
} /* fcoe_get_wwpn */

/*****************************************************************************
 * Short definitions for OS specific services                                *
 *****************************************************************************/

/* optimizations */
#define chfcoe_likely(_cond)		__builtin_expect(!!(_cond), 1)
#define chfcoe_unlikely(_cond)		__builtin_expect(!!(_cond), 0)

/* Debug assertions */
#define	CHFCOE_ASSERT(cond)						\
do {									\
	if (chfcoe_unlikely(!((cond))))					\
	{								\
		chfcoe_bug();						\
	}								\
} while(0)

#ifdef __CHFCOE_DEBUG__
#define CHFCOE_DB_ASSERT(cond)		CHFCOE_ASSERT(cond)
#else
#define CHFCOE_DB_ASSERT(cond)
#endif

static inline u32 chfcoe_ntoh24(const u8 *p)
{
        return (p[0] << 16) | (p[1] << 8) | p[2];
}

static inline void chfcoe_hton24(u8 *p, u32 v)
{
	p[0] = (v >> 16) & 0xff;
	p[1] = (v >> 8) & 0xff;
	p[2] = v & 0xff;
}

typedef uint64_t chfcoe_dma_addr_t;
typedef void chfcoe_fc_buffer_t;

#endif /* __CHFCOE_DEFS_H__ */
