#ifndef __ISCSI_QUEUE_H__
#define __ISCSI_QUEUE_H__

/*
 * queue.h
 * generic queue head/tail structure and macros to manipulate
 * arbitrary "queued" data structures.
 */

/* generic queue head/tail structure */
typedef struct queue chiscsi_queue;
struct queue {
	void   *q_lock;
	unsigned int q_cnt;
	void   *q_head, *q_tail;
};
#define ISCSI_QUEUE_SIZE	(sizeof(chiscsi_queue))

#define chiscsi_queue_index(head,i)	\
	(chiscsi_queue *)(((unsigned char *)(head)) + i * ISCSI_QUEUE_SIZE)

/* lock flavors */
#define lockq_nolock(Q)		{}
#define unlockq_nolock(Q)	{}
#define lockq_lock(Q)		os_lock((Q)->q_lock)
#define unlockq_lock(Q)		os_unlock((Q)->q_lock)
#define lockq_lockirq(Q)	os_lock_irq((Q)->q_lock)
#define unlockq_lockirq(Q)	os_unlock_irq((Q)->q_lock)

#define ch_queue_free(Q) \
	do {						\
		if (Q) {				\
			if ((Q)->q_lock)		\
				os_free((Q)->q_lock);	\
			os_free(Q);			\
		}					\
	} while(0)

#define ch_queue_init(Q) \
	do {						\
		memset((Q)->q_lock, 0, os_lock_size);	\
		os_lock_init((Q)->q_lock);		\
		(Q)->q_cnt = 0;				\
		(Q)->q_head = NULL;			\
		(Q)->q_tail = NULL;			\
	} while(0)

/* ch_queue_alloc explicitly assumes a q_lock_fail label to handle allocation
 * failures
 */
#define ch_queue_alloc(Q) \
	do { \
		Q = os_alloc(ISCSI_QUEUE_SIZE, 1, 1);	\
		if (Q) {				\
			(Q)->q_lock = os_alloc(os_lock_size, 1, 1);	\
			if ((Q)->q_lock)		\
				ch_queue_init(Q);		\
			else {				\
				os_free(Q);		\
				Q = NULL;		\
				goto q_lock_fail;	\
			}				\
		}					\
	} while(0)

/* move the content of FQ to TQ */
#define ch_queue_move_content(FL,FQ,TL,TQ)	\
	do { \
		lockq_##TL(TQ); \
		(TQ)->q_cnt = (FQ)->q_cnt; \
		(TQ)->q_head = (FQ)->q_head; \
		(TQ)->q_tail = (FQ)->q_tail; \
		unlockq_##TL(TQ); \
		lockq_##FL(FQ); \
		(FQ)->q_cnt = 0; \
		(FQ)->q_head = NULL; \
		(FQ)->q_tail = NULL; \
		unlockq_##FL(FQ); \
	} while(0)

/* enqueue at the head */
#define ch_enqueue_head(L,T,NP,Q,P) \
	do { \
		lockq_##L(Q); \
		((T*)(P))->NP = (Q)->q_head; \
		(Q)->q_head = P; \
		if (!(Q)->q_tail) \
			(Q)->q_tail = P; \
		((Q)->q_cnt)++; \
		unlockq_##L(Q); \
	} while(0)

/* enqueue at the tail */
#define ch_enqueue_tail(L,T,NP,Q,P) \
	do { \
		lockq_##L(Q); \
		(P)->NP = NULL; \
		if (!(Q)->q_head) \
			(Q)->q_head = P; \
		else \
			((T*)((Q)->q_tail))->NP = P; \
		(Q)->q_tail = P; \
		((Q)->q_cnt)++; \
		unlockq_##L(Q); \
	} while(0)

/* insert between PREV and NEXT */
#define ch_enqueue_between(L,T,NP,Q,P,PREV,NEXT) \
	do { \
		lockq_##L(Q); \
		P->NP = NULL; \
		if (PREV) \
			(PREV)->NP = P; \
		else \
			(Q)->q_head = P; \
		if (NEXT) \
			P->NP = NEXT; \
		else \
			(Q)->q_tail = P; \
		((Q)->q_cnt)++; \
		unlockq_##L(Q); \
	} while(0)

/* insert by field value in incrementing order */
#define ch_enqueue_by_field_incr(L,T,NP,Q,P,F)	\
	do { \
		T	*__p = NULL, *__n; \
		lockq_##L(Q); \
		for (__n = (Q)->q_head; __n; __p = __n, __n = __n->NP) \
			if (__n->F > (P)->F) break; \
		ch_enqueue_between(nolock,T,NP,Q,P,__p,__n); \
		unlockq_##L(Q); \
	} while(0)

/* dequeue from the head */
#define ch_dequeue_head(L,T,NP,Q,P) \
	do { \
		lockq_##L(Q); \
		if ( ((P) = (Q)->q_head) ) { \
			(Q)->q_head = (P)->NP; \
			(P)->NP = NULL; \
			if ((Q)->q_head == NULL) {\
				(Q)->q_tail = NULL; \
			} \
			((Q)->q_cnt)--; \
		} \
		unlockq_##L(Q); \
	} while(0)

/* remove an arbitrary element from the queue */
#define ch_qremove(L,T,NP,Q,P) \
	do { \
		T *curr, *prev = NULL; \
		lockq_##L(Q); \
		for (curr = (T*)(Q)->q_head; curr && curr != (P); \
		     prev = curr, curr = curr->NP) \
			 ; \
		if (curr == (P)) { \
			if (prev) prev->NP = curr->NP; \
			if ((Q)->q_tail == (P)) \
				(Q)->q_tail = prev; \
			if ((Q)->q_head == (P)) \
				(Q)->q_head = curr->NP; \
			((Q)->q_cnt)--; \
			(P)->NP = NULL; \
		} \
		unlockq_##L(Q); \
	} while(0)

/* search an element by one of its field value, the value should be unique */
#define ch_qsearch_by_field_value(L,T,NP,Q,P,F,V)	\
	do { \
		lockq_##L(Q); \
		for (P = (T*)(Q)->q_head; (P) && (P)->F != (V); P = (P)->NP) \
			; \
		unlockq_##L(Q); \
	} while(0)

/* search an element by one of its string field, the string should be unique */
#define ch_qsearch_by_field_string(L,T,NP,Q,P,F,S)	\
	do { \
		lockq_##L(Q); \
		for (P = (T*)(Q)->q_head; (P);  P = (P)->NP) \
			if (!os_strcmp((P)->F, S)) \
				break; \
		unlockq_##L(Q); \
	} while(0)

#endif /* __QUEUE_H__ */
