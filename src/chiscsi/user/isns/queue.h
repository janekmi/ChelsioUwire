/*
 * queue.h
 *
 * generic queue head/tail structure and macros to manipulate
 * arbitrary "queued" data structures.
 *
 */
#ifndef __QUEUE_H__
#define __QUEUE_H__

/* generic queue head/tail structure */
typedef struct queue queue;
struct queue {
	unsigned int q_cnt;
	void   *q_head, *q_tail;
};

/* free an chiscsi_queue struct */
#define ch_queue_free(Q)	free(Q)

/* allocate and initialize an chiscsi_queue struct */
#define ch_queue_alloc(Q)	\
	do {	\
		Q = malloc(sizeof(queue)); \
		if (Q) memset(Q, 0, sizeof(queue));	\
	} while(0)

/* initialize an chiscsi_queue struct */
#define ch_queue_init(Q) \
	do { \
		if (Q) memset(Q, 0, sizeof(queue));	\
	} while(0)

/* empty queue */
#define queue_remove_all(T,NP,Q,FP) \
	do { \
		T *__curr, *__next = NULL; \
		for (__curr = (Q)->q_head; __curr; __curr = __next) { \
			__next = __curr->NP; \
			FP(__curr); \
		} \
		ch_queue_init(Q); \
	} while(0)

/* move the content of FQ to TQ */
#define ch_queue_move_content(TQ,FQ)	\
	do { \
		(TQ)->q_cnt = (FQ)->q_cnt; \
		(TQ)->q_head = (FQ)->q_head; \
		(TQ)->q_tail = (FQ)->q_tail; \
		(FQ)->q_cnt = 0; \
		(FQ)->q_head = NULL; \
		(FQ)->q_tail = NULL; \
	} while(0)

/* enqueue at the head */
#define ch_enqueue_head(T,NP,Q,P) \
	do { \
		((T*)(P))->NP = (Q)->q_head; \
		(Q)->q_head = (P); \
		((Q)->q_cnt)++; \
	} while(0)

/* enqueue at the tail */
#define ch_enqueue_tail(T,NP,Q,P) \
	do { \
		(P)->NP = NULL; \
		if (!(Q)->q_head) \
			(Q)->q_head = P; \
		else { \
			T *__tail = (T*)(Q)->q_tail; \
			__tail->NP = P; \
		} \
		(Q)->q_tail = P; \
		((Q)->q_cnt)++; \
	} while(0)

/* dequeue from the head */
#define ch_dequeue_head(T,NP,Q,P) \
	do { \
		if ( ((P) = (Q)->q_head) ) { \
			(Q)->q_head = (P)->NP; \
			(P)->NP = NULL; \
			if ((Q)->q_head == NULL) {\
				(Q)->q_tail = NULL; \
			} \
			((Q)->q_cnt)--; \
		} \
	} while(0)

/* dequeue from the tail */
#define ch_dequeue_tail(T,NP,Q,P) \
	do { \
		T	*prev = NULL, *curr; \
		for (curr = (Q)->q_head; curr && curr != (Q)->q_tail; \
			 prev = curr, curr = curr->NP) \
			 ; \
		(P) = curr; \
		if (curr) {	\
			if (prev) { \
				prev->NP = NULL; \
				(Q)->q_tail = prev; \
			} else {\
				(Q)->q_head = NULL;	\
				(Q)->q_tail = NULL; \
			} \
			((Q)->q_cnt)--; \
		} \
	} while(0)

/* remove an arbitrary element from the queue */
#define ch_qremove(T,NP,Q,P) \
	do { \
		T *curr, *prev = NULL; \
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
	} while(0)

/* remove an element by its field value from the queue, the value 
   should be unique */
#define ch_qremove_by_field(T,NP,Q,P,F,V) \
	do { \
		T *curr, *prev = NULL; \
		for (curr = (T*)(Q)->q_head; curr && curr->F != (V); \
		     prev = curr, curr = curr->NP) \
			 ; \
		P = curr; \
		if (curr) { \
			if (prev) prev->NP = curr->NP; \
			if ((Q)->q_tail == (P)) \
				(Q)->q_tail = prev; \
			if ((Q)->q_head == (P)) \
				(Q)->q_head = curr->NP; \
			((Q)->q_cnt)--; \
			(P)->NP = NULL; \
		} \
	} while(0)

/* search an element by one of its field value, the value should be unique */
#define ch_qsearch_by_field_value(T,NP,Q,P,F,V)	\
	do { \
		for (P = (T*)(Q)->q_head; (P) && (P)->F != (V); P = (P)->NP) \
			; \
	} while(0)

#endif /* __QUEUE_H__ */
