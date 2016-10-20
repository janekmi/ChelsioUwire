#ifndef __ISCSI_THREAD_H__
#define __ISCSI_THREAD_H__

/*
 * iscsi thread struct
 */

typedef struct iscsi_masked_list iscsi_masked_list;
typedef struct iscsi_thread iscsi_thread;
typedef struct iscsi_thread_entry iscsi_thread_entry;

struct iscsi_thread_entry {
	iscsi_thread *thp;
	iscsi_masked_list *mlist;
	int mpos;
};

struct iscsi_masked_list {
	/* os dependent part */
	void   *l_lock;
	/* os independent part */
	iscsi_masked_list *l_next;
	unsigned long l_mask_valid;	/* valid mask */
	unsigned long l_mask_work;	/* work mask */
	unsigned long l_mask_idle;	/* rx idle mask */
	void   *l_list[ISCSI_BITMASK_BIT_MAX];	/* list of pointers */
};
#define	ISCSI_MASKED_LIST_SIZE	(sizeof(iscsi_masked_list))

#define masked_list_enqueue(L,Q,P) \
			ch_enqueue_tail(L,iscsi_masked_list,l_next,Q,P)
#define masked_list_dequeue(L,Q,P) \
			ch_dequeue_head(L,iscsi_masked_list,l_next,Q,P)
#define masked_list_ch_qremove(L,Q,P) \
			ch_qremove(L,iscsi_masked_list,l_next,Q,P)

#define mask_list_set_bit(mlist,bit) \
			os_set_bit_atomic(&mlist->l_mask_work, bit)

enum thread_flag_bits {
	THREAD_FLAG_UP_BIT,
	THREAD_FLAG_STOP_BIT,
	THREAD_FLAG_DATA_SESS_BIT,
	THREAD_FLAG_TIMEOUT_CHECK_BIT,
	THREAD_FLAG_TIMEOUT_UPDATE_BIT,
	THREAD_FLAG_VALIDATE_BIT,	/* validate all connections */
	THREAD_FLAG_WORK_BIT
};

struct iscsi_thread {
	/* os dependent part */
	void   *os_data;
	chiscsi_queue *th_dataq;	/* queue of iscsi_masked_list */
	/* os independent part */
	unsigned long th_flag;
	void   *th_private;
	iscsi_thread_common th_common;
};


/* define these macros to use the new os_data struct */
#define ISCSI_THREAD_SIZE	(sizeof(iscsi_thread))

#define iscsi_thread_index(head,i) \
	(iscsi_thread *)(((unsigned char *)(head)) + i * ISCSI_THREAD_SIZE)

#define iscsi_thread_flag_set(thp,bit)	\
			os_set_bit_atomic(&((thp)->th_flag),bit)
#define iscsi_thread_flag_clear(thp,bit) \
			os_clear_bit_atomic(&((thp)->th_flag),bit)
#define iscsi_thread_flag_test(thp,bit)	\
			os_test_bit_atomic(&((thp)->th_flag),bit)
#define iscsi_thread_flag_testnset(thp,bit)	\
			os_test_and_set_bit_atomic(&((thp)->th_flag),bit)
#define iscsi_thread_flag_testnclear(thp,bit) \
			os_test_and_clear_bit_atomic(&((thp)->th_flag),bit)

/* if the thread has work to do */
#define iscsi_thread_has_work(thp)	\
		((iscsi_thread_flag_test(thp, THREAD_FLAG_WORK_BIT)) || \
		 (iscsi_thread_flag_test(thp, THREAD_FLAG_TIMEOUT_CHECK_BIT)) || \
		 (iscsi_thread_flag_test(thp, THREAD_FLAG_TIMEOUT_UPDATE_BIT)) || \
		 (iscsi_thread_flag_test(thp, THREAD_FLAG_VALIDATE_BIT)) )

/* process all the entities */
#define thread_process_all(FP,work) \
	do { \
		iscsi_masked_list	*mlist; \
		int					i;  \
		for (mlist = mlq->q_head; mlist; mlist = mlist->l_next) { \
			if (!mlist->l_mask_valid) continue; \
			for (i = 0; i < ISCSI_BITMASK_BIT_MAX; i++) { \
				if (os_test_bit_atomic(&mlist->l_mask_valid, i)) { \
					if (FP(mlist->l_list[i])) work++; \
				} \
			} \
		}   \
	} while(0)

/* process the entity whose mask is set */
#define thread_process_mask(FMASK,FP,work,empty) \
	do { \
		iscsi_masked_list	*mlist; \
		int					i;  \
		for (mlist = mlq->q_head; mlist; mlist = mlist->l_next) { \
			if (!mlist->l_mask_valid) { \
				empty++; \
				continue; \
			} \
			for (i = 0; i < ISCSI_BITMASK_BIT_MAX && mlist->FMASK; i++) { \
				if (os_test_and_clear_bit_atomic(&mlist->FMASK, i) && \
					os_test_bit_atomic(&mlist->l_mask_valid, i) ) { \
					if (FP(mlist->l_list[i])) work++; \
				} \
			} \
		}   \
	} while(0)

/*
 * thread_process_mlistq --
 * this is the main processing loop for the target/initiator main/worker thread
 * the fp_xxx() should takes a void ptr as input, and returns 1 if futher
 * processing is needed, 0 otherwise.
 */

#define thread_process_mlistq(thp,mlq,fp_wrk,fp_tm_update,fp_tm_chk) \
	do { \
		int	empty_mask = 0; \
		int	check_timeout = 0; \
		/* need to update connection timeout */ \
		if (iscsi_thread_flag_testnclear(thp, THREAD_FLAG_TIMEOUT_UPDATE_BIT)) { \
			int	work = 0; \
			thread_process_all(fp_tm_update, work); \
			if (work) iscsi_thread_flag_set(thp, THREAD_FLAG_WORK_BIT); \
		} \
		/* need to check connection timeout -- prepare */ \
		if (iscsi_thread_flag_testnclear(thp, THREAD_FLAG_TIMEOUT_CHECK_BIT)) { \
			iscsi_masked_list   *mlist; \
			check_timeout = 1; \
			/* save the connection masks */ \
			for (mlist = mlq->q_head; mlist; mlist = mlist->l_next) { \
				mlist->l_mask_idle = mlist->l_mask_valid; \
			} \
		} \
		/* process iscsi activitity */ \
		if (iscsi_thread_flag_testnclear(thp, THREAD_FLAG_WORK_BIT)) {  \
			int	work = 0; \
			thread_process_mask(l_mask_work,fp_wrk,work,empty_mask); \
		} \
		/* now check for connection timeout */ \
		if (check_timeout) { \
			int	work = 0; \
			thread_process_mask(l_mask_idle,fp_tm_chk,work,empty_mask); \
			if (work) iscsi_thread_flag_set(thp, THREAD_FLAG_WORK_BIT); \
		} \
		/* we have closed connections, prune mlistq */ \
		if (empty_mask) { \
			iscsi_masked_list_queue_cleanup(mlq, 0); \
		} \
	} while(0)

#endif /* ifndef __ISCSI_THREAD_H__ */
