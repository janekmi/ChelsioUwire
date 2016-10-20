#include <assert.h>
#include <pthread.h>
#include "atomic.h"
#include "device.h"
#include "buffer.h"

extern struct wdtoe_device *wd_dev;

inline void *next_buffer(struct sw_t4_txq *q)
{
	assert(q && q->queue && q->sw_queue);

	/* init the copied field */
	q->queue[q->pidx].copied = 0;

	return (void *)q->sw_queue[q->pidx];
}

inline int sw_txq_next_pidx(struct sw_t4_txq *q, int cur_pidx)
{
	assert(q);

	if (++cur_pidx == q->size)
		return 0;

	return cur_pidx;

}

static inline void sw_txq_produce(struct sw_t4_txq *q)
{
	atomic_incr(&q->in_use);
	if (++q->pidx == q->size)
		q->pidx = 0;
	DBG(DBG_SEND, "pidx is now %u, %d Tx buffers in use\n",
	    q->pidx, atomic_read(&q->in_use));
}

static inline void sw_txq_consume(struct sw_t4_txq *q)
{
	assert(q);

	atomic_decr(&q->in_use);

	if (++q->cidx == q->size)
		q->cidx = 0;
}

static inline void release_tx_buf(struct sw_t4_txq *sw_txq, int n_bufs)
{
	int n = n_bufs;

	while (n--) {
		sw_txq_consume(sw_txq);
	}

	DBG(DBG_SEND, "released %d Tx buffers, %d still in use\n",
	    n_bufs, atomic_read(&sw_txq->in_use));

	assert(atomic_read(&sw_txq->in_use) >= 0);
}

inline void finish_buffer(struct sw_t4_txq *q, size_t copied)
{
	assert(q && q->queue);

	q->queue[q->pidx].copied = copied;
	sw_txq_produce(q);
}

inline void credit_enqueue(int idx, struct sw_cred_q_entry cdqe)
{
	struct sw_cred_q *credq = NULL;
	int buf_idx;
	buf_idx = wd_dev->stack_info->conn_info[idx].buf_idx;
	/* error check on buf_idx */
	if (buf_idx < 0 || buf_idx >= NWDTOECONN) {
		DBG(DBG_SEND, "wrong buf_idx [%d], "
				"can not continue Tx\n",
				buf_idx);
		return;
	}
	credq = &wd_dev->stack_info->buf.credq[buf_idx];
	if (!credq) {
		DBG(DBG_SEND, "wrong cred queue for buf_idx [%d], "
				"can not continue Tx\n", buf_idx);
		return;
	}

	credq->queue[credq->pidx] = cdqe;

	DBG(DBG_SEND, "credq->queue[%u]'s n_bufs [%d], credit [%d]\n",
					credq->pidx,
					credq->queue[credq->pidx].n_bufs,
					credq->queue[credq->pidx].cred);

	/* increase the pidx, wrap around if we reach the end */
	if (++credq->pidx == credq->size)
		credq->pidx = 0;
}

inline void credit_dequeue(int idx, int credits)
{
	int n_bufs = 0;
	struct sw_cred_q_entry *credq_entry = NULL;
	struct sw_cred_q *credq = NULL;
	struct sw_t4_txq *sw_txq = NULL;
	int remain = credits;
	int buf_idx = wd_dev->stack_info->conn_info[idx].buf_idx;

	/* error check on buf_idx */
	if (buf_idx < 0 || buf_idx >= NWDTOECONN) {
		DBG(DBG_CONN, "wrong buf_idx [%d], "
				"can not continue Tx\n",
				buf_idx);
		return;
	}
	credq = &wd_dev->stack_info->buf.credq[buf_idx];
	if (!credq) {
		DBG(DBG_CONN, "wrong cred queue for buf_idx [%d], "
				"can not continue.\n", buf_idx);
		return;
	}
	sw_txq = &wd_dev->stack_info->buf.sw_txq[buf_idx];
	if (!sw_txq) {
		DBG(DBG_CONN, "wrong sw_txq for buf_idx [%d], "
				"can not continue.\n", buf_idx);
		return;
	}

	while (remain > 0) {
		credq_entry = &credq->queue[credq->cidx];
		if (!credq_entry) {
			DBG(DBG_LOOKUP | DBG_CREDITS, "could not access "
			    "credit queue entry for cidx %d\n", credq->cidx);
			return;
		}

		if (!credq_entry->cred) {
			/*
			 * If the credit value is 0 under the cidx
			 * it means that we received credits for
			 * something we didn't consume in user space.
			 * Therefore we won't find anything in the
			 * credit queue. We should return, then.
			 */
			DBG(DBG_CREDITS, "received %d credits for something "
			    " never consumed in user space (don't panic)\n",
			    remain);
			return;
		} else if (credq_entry->cred <= remain) {
			remain -= credq_entry->cred;
			credq_entry->cred = 0;
			n_bufs = credq_entry->n_bufs;
			DBG(DBG_CREDITS, "credits in credq->queue[%d]: %d, "
			    "remain %d\n", credq->cidx, credq_entry->cred,
			     remain);
			/*
			 * Release Tx bufs if there is any associated with
			*  this credit entry.
			*/
			if (n_bufs) {
				DBG(DBG_CREDITS, "releasing %d Tx buffers\n",
				    n_bufs);
				release_tx_buf(sw_txq, n_bufs);
			}
			credq_entry->n_bufs = 0;
			/* Consume the queue entry, update cidx */
			if (++credq->cidx == credq->size)
				credq->cidx = 0;
		} else {
			credq_entry->cred -= remain;
			remain = 0;
		}
	}
}

/*
 * returns the index to an entry of new Tx and Rx buf,
 * returns -1 if no new entry available.
 */
int get_new_buf(struct wdtoe_device *dev)
{
	int i;
	pthread_spin_lock(&dev->stack_info->buf.lock);
	for (i = 0; i < NWDTOECONN; i++) {
		if (dev->stack_info->buf.flags[i] == 0) {
			dev->stack_info->buf.flags[i] = 1;
			pthread_spin_unlock(&dev->stack_info->buf.lock);
			return i;
		}
	}
	pthread_spin_unlock(&dev->stack_info->buf.lock);
	return -1;
}
