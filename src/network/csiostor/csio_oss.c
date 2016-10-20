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

#include <csio_oss.h>

static void
csio_oss_freeobj(struct kref *kref)
{
	struct csio_oss_kref *oss_kref = container_of(kref, struct csio_oss_kref,
	     					      kref);
	return oss_kref->freeobj(oss_kref->obj);
}

void
csio_oss_kref_init(struct csio_oss_kref *oss_kref, void *obj,
		   void (*freeobj)(void *))
{
	oss_kref->obj		= obj;
	oss_kref->freeobj	= freeobj;
	kref_init(&oss_kref->kref);

	return;
}

void
csio_oss_kref_get(struct csio_oss_kref *oss_kref)
{
	kref_get(&oss_kref->kref);
	return;
}

int
csio_oss_kref_put(struct csio_oss_kref *oss_kref)
{
	return kref_put(&oss_kref->kref, csio_oss_freeobj);
}

int
csio_oss_osname(void *os_dev, uint8_t *buf, size_t buf_len)
{
	uint8_t *ptr = buf;
	
	if (snprintf(ptr, buf_len, "%s %s %s",
			init_utsname()->sysname,
			init_utsname()->release,
			init_utsname()->version) > 0) {
		return 0;
	}
	return -1;
}	

#if 0

/**
 * csio_oss_alloc - Allocates kernel memory.
 * @mem_handle:    Pointer to pool, if memory pools were created
 * @size:	   Size of the request in bytes
 * @flag:	   Can this call wait or return immediately?
 *
 * This call doubles up as a wrapper for regular memory allocation,
 * as well as pool based allocation.
 */
void *
csio_oss_alloc(void *mem_handle, size_t size, int flag)
{
	/* This is a fixed size pool allocation */
	if (mem_handle)
		return mempool_alloc((mempool_t *)mem_handle,
				     ((flag == 1)? GFP_KERNEL : GFP_ATOMIC));
	
	return kzalloc(size, ((flag == 1)? GFP_KERNEL : GFP_ATOMIC));
}

/**
 * csio_oss_free - Frees memory.
 * @mem_handle:    Pointer to pool, if memory pools were created
 * @ptr:	   Memory to be freed.
 *
 */
void
csio_oss_free(void *mem_handle, void *ptr)
{
	if (mem_handle)
		return mempool_free(ptr, (mempool_t *)mem_handle);

	return kfree(ptr);
}

#endif /* if 0 */

/**
 * csio_oss_dma_alloc - Allocates DMA'able memory
 * @dobj: OSS DMA object
 * @dev: The OS representation of the device
 * @size: Size of allocation
 * @align: Alignment for start address
 * @paddr: Physical address of allocated memory
 * @flag: Can this call wait or return immediately?
 *
 * This call returns a DMA memory area of the passed in size
 * meeting the alignment restrictions passed in. Since this
 * is a single allocation, we could have used a single call like
 * pci_alloc_consistent. But since we have an alignment
 * requirement as well, we have to take this route of having
 * to create a PCI pool, and then allocating from it -
 * pci_alloc_consistent/dma_alloc_coherent doesnt provide an
 * alignment parameter.
 */
void *
csio_oss_dma_alloc(struct csio_oss_dma_obj *dobj, void *dev, size_t size,
			size_t align, dma_addr_t *paddr, int flag)
{
	void *vaddr;

#if 0
	dobj->pool = pci_pool_create("csio_generic_dma_pool",
				      dobj->dev, size, align, 0);
	if (!dobj->pool)
		return NULL;

	vaddr = pci_pool_alloc(dobj->pool,
			       ((flag == 1)? GFP_KERNEL : GFP_ATOMIC), paddr);
#endif
	/* Note: this call returns a paddr/vaddr in order of PAGE_SIZE */
	vaddr = pci_alloc_consistent((struct pci_dev *)dev, size, paddr);
	if (vaddr) {
		dobj->paddr	= *paddr;
		dobj->dev  	= (struct pci_dev *)dev;
		dobj->size	= size;
	}

	return vaddr;
}

/**
 * csio_oss_dma_free - Free DMA'able memory
 * @dobj: OSS DMA object
 * @vaddr: DMA address to free.
 *
 */
void
csio_oss_dma_free(struct csio_oss_dma_obj *dobj, void *vaddr)
{
#if 0
	pci_pool_free(dobj->pool, vaddr, dobj->paddr);
	pci_pool_destroy(dobj->pool);
#endif
	pci_free_consistent(dobj->dev, dobj->size, vaddr, dobj->paddr);

	return;
}

void
csio_oss_log(struct csio_oss_log_buf *log, uint32_t level, char *str,
		    uint64_t arg1, uint64_t arg2,
		    uint64_t arg3, uint64_t arg4)
{
	int32_t nbytes;
	char tbuf[128]; /* Temporary buffer */
	char *ch;
	
	/* Check Log level is enabled */
	if (!(log->level & CSIO_LOG_LEVEL_ENABLE) ||
	   !(log->level & level))
	   return;	

	nbytes = snprintf(tbuf, sizeof(tbuf),
			  "File %s:line %d:%s:%llx:%llx:%llx:%llx\n",
			   __FILE__, __LINE__, str, arg1, arg2, arg3, arg4);
	
	if (nbytes < 0)
		return;
	
	/* Write the message into log buffer */
	for (ch = tbuf; ch < tbuf + nbytes; ch++) {
		log->buf[log->wr_idx] = *ch;	
		log->wr_idx = (log->wr_idx + 1) & CSIO_LOG_BUF_MASK;	

		/* Circular log buffer full. Allow over writing */		
		if (log->buf_cnt >= CSIO_LOG_BUF_SIZE) {
			log->rd_idx = (log->rd_idx + 1) & CSIO_LOG_BUF_MASK;
		}
		else
			log->buf_cnt++;	
	}
}

/**
 * Name: csio_oss_log_init
 *
 * Description: Initializes log buffer.
 *
 * Arugments :
 * 	IN log - Log buffer.
 *
 * Return : None
 */
void
csio_oss_log_init(struct csio_oss_log_buf *log)
{
   	
}

/**
 * Name: csio_oss_log_start
 *
 * Description: Starts log buffer .
 *
 * Arugments :
 * 	IN log - Log buffer.
 *	IN level - log level.
 *
 * Return : None
 */
void
csio_oss_log_start(struct csio_oss_log_buf *log, uint32_t level)
{
	log->level = (level | CSIO_LOG_LEVEL_ENABLE);	
}

/**
 * Name: csio_oss_log_stop
 *
 * Description: Stops log buffer.
 *
 * Arugments :
 * 	IN log - log buffer.
 *
 * Return : None
 */
void
csio_oss_log_stop(struct csio_oss_log_buf *log)
{
	log->level &= ~CSIO_LOG_LEVEL_ENABLE; 	
}


/**
 * Name: csio_oss_log_load
 *
 * Description: Loads the contents of log buffer into the buffer request
 * by caller.
 *
 * Arugments :
 * 	IN log   - log buffer.
 * 	IN buf   - Buffer address specified by caller.
 * 	IN len   - Length of log buffer to be transfered.
 *
 * Return : Number of bytes transfered to caller's buffer.
 */
int
csio_oss_log_load(struct csio_oss_log_buf *log, char *buf, uint32_t len)
{
	uint32_t ii;
	uint32_t nbytes = 0;
  	
	nbytes = (len <  log->buf_cnt) ? len : log->buf_cnt;
	for (ii = 0; ii < nbytes; ii++) {
		buf[ii] = log->buf[log->rd_idx];
		log->rd_idx = (log->rd_idx + 1) & CSIO_LOG_BUF_MASK;
	}
	return  nbytes;
}

/**
 * Name: csio_oss_trace_init
 *
 * Description: Initializes trace buffer.
 *
 * Arugments :
 * 	IN trace_buf - trace buffer.
 *
 * Return : None
 */
void
csio_oss_trace_init(struct csio_oss_trace_buf *trace_buf, uint32_t level)
{
	memset(trace_buf, 0, sizeof(struct csio_oss_trace_buf));
	trace_buf->level = (level | CSIO_TRACE_LEVEL_ENABLE);	
}

/**
 * Name: csio_oss_trace_start
 *
 * Description: Starts trace buffer .
 *
 * Arugments :
 * 	IN trace_buf - trace buffer.
 *	IN level - trace level.
 *
 * Return : None
 */
void
csio_oss_trace_start(struct csio_oss_trace_buf *trace_buf, uint32_t level)
{
	trace_buf->level = (level | CSIO_TRACE_LEVEL_ENABLE);	
}

/**
 * Name: csio_oss_trace_stop
 *
 * Description: Stops trace buffer.
 *
 * Arugments :
 * 	IN trace_buf - trace buffer.
 *
 * Return : None
 */
void
csio_oss_trace_stop(struct csio_oss_trace_buf *trace_buf)
{
	trace_buf->level &= ~CSIO_TRACE_LEVEL_ENABLE; 	
}


/**
 * Name: csio_oss_trace_readmsg
 *
 * Description: Reads msgs from traces buffer and copies into buffer
 * request by caller.
 *
 * Arugments :
 * 	IN trace_buf - trace buffer.
 * 	IN msg_buf   - Buffer address specified by caller.
 * 	IN msg_num   - Number of msg to be transfered.
 *
 * Return : Number of msgs transfered to caller's buffer.
 */
int
csio_oss_trace_readmsg(struct csio_oss_trace_buf *trace_buf,
		       struct csio_oss_trace_msg *msg_buf, uint32_t msg_num)
{
	uint32_t ii;
	uint32_t nmsg = 0;
  	
	nmsg = (msg_num <  trace_buf->msg_cnt) ? msg_num : trace_buf->msg_cnt;
	for (ii = 0; ii < nmsg; ii++) {
		memcpy(msg_buf + ii, trace_buf->msg_addr + trace_buf->rd_idx,
			sizeof(struct csio_oss_trace_msg));
		trace_buf->rd_idx = ((trace_buf->rd_idx + 1) &
				     CSIO_TRACE_BUF_MASK);
	}
	return  nmsg;
}

/*
 *
 * Name: csio_oss_dcap_read
 *
 * Description: Reads from data capture buffer and copies into buffer
 * request by caller.
 *
 * Arugments :
 * 	IN dcap_buf -  data capture buffer.
 * 	IN msg_buf   - Buffer address specified by caller.
 * 	IN msg_num   - Number of entires to be transfered.
 *
 * Return : Number of msgs transfered to caller's buffer.
 */
int
csio_oss_dcap_read(struct csio_oss_dcap_buf *dcap_buf,
		   struct csio_oss_dcap *msg_buf, uint32_t msg_num)
{
	uint32_t ii;
	uint32_t nmsg = 0;
  	
	nmsg = (msg_num <  dcap_buf->msg_cnt) ? msg_num : dcap_buf->msg_cnt;
	for (ii = 0; ii < nmsg; ii++) {
		memcpy(msg_buf + ii, dcap_buf->msg_addr + dcap_buf->rd_idx,
			sizeof(struct csio_oss_dcap));
		dcap_buf->rd_idx = ((dcap_buf->rd_idx + 1) &
				     CSIO_DCAP_BUF_MASK);
	}
	return  nmsg;
}

/**
 * Name: csio_oss_dcap_write
 *
 * Description: Captures Data buffer,cdb, transfer length for the given
 * 		request.
 *
 * Arugments :
 * 	IN dcap_buf -  data capture buffer.
 * 	IN msg_buf   - Buffer address specified by caller.
 * 	IN msg_num   - Number of entires to be transfered.
 *
 * Return : Number of msgs transfered to caller's buffer.
 */
int
csio_oss_dcap_write(struct csio_oss_dcap_buf *dcap_buf,
		   struct csio_oss_dcap *msg_buf, uint32_t msg_num)
{
	struct csio_oss_dcap *msg;
	
	/* Copy the data capture into data capture buffer */
	msg = (dcap_buf->msg_addr + dcap_buf->wr_idx);
	memcpy(msg, msg_buf, sizeof(struct csio_oss_dcap));

	/* Update Write index and msg count */
	dcap_buf->wr_idx = (dcap_buf->wr_idx + 1) & CSIO_DCAP_BUF_MASK;
	/* Circular trace buffer full. Allow over writing */		
	if (dcap_buf->msg_cnt >= CSIO_DCAP_BUF_SIZE) {
		dcap_buf->rd_idx = ((dcap_buf->rd_idx + 1) &
				     CSIO_DCAP_BUF_MASK);
	}
	else {
		dcap_buf->msg_cnt++;
	}
	return  dcap_buf->msg_cnt;
}

/* Timers */
void
csio_oss_timer_init(struct csio_oss_timer *timerp,
		    void (*tmo_fn)(uintptr_t),
		    void *data)
{
	struct timer_list *tm = &timerp->oss_timer;

	init_timer(tm);
	tm->function 	= tmo_fn;
	tm->data	= (unsigned long)data;

	return;
}

void
csio_oss_timer_start(struct csio_oss_timer *timerp, uint32_t tmo)
{
	struct timer_list *tm = &timerp->oss_timer;

	mod_timer(tm, (jiffies + (msecs_to_jiffies(tmo))));

	return;	
}

void
csio_oss_timer_stop(struct csio_oss_timer *timerp)
{
	struct timer_list *tm = &timerp->oss_timer;

	del_timer_sync(tm);

	return;
}

void
csio_oss_cmpl_init(struct csio_oss_cmpl *cmplp)
{
	init_completion(&cmplp->cmpl);
	return;
}

/* Sleep/wakeup */
void
csio_oss_sleep(struct csio_oss_cmpl *cmplp)
{
	wait_for_completion(&cmplp->cmpl);
	return;
}

void
csio_oss_wakeup(struct csio_oss_cmpl *cmplp)
{
	/* REVISIT: should we used complete() here? */
	complete_all(&cmplp->cmpl);
	return;
}

int workq_thread = 0;
void
csio_oss_workq_create(struct csio_oss_workq *workq, void *data1, void *data2)
{
	uint8_t wq_name[16];
	int n;
	n = snprintf(wq_name,16, "csio_kthread:%d\n", workq_thread++);
	if(n)
		n--;
	wq_name[n] = '\0';
	workq->wq = create_singlethread_workqueue(wq_name);
	return;
}

int
csio_oss_queue_work(struct csio_oss_workq *workq, struct csio_oss_work *workp)
{
	return queue_work(workq->wq, &workp->work);
}

void
csio_oss_workq_flush(struct csio_oss_workq *workq)
{
	flush_workqueue(workq->wq);
	return;
}

void
csio_oss_workq_destroy(struct csio_oss_workq *workq)
{
	destroy_workqueue(workq->wq);
	return;
}

/* ISR Workers */
static void
csio_oss_wfn(struct work_struct *work)
{
	struct csio_oss_work *workp =
			container_of(work, struct csio_oss_work, work);

	(*(workp->wfn))(workp->data);
	return;
}

void
csio_oss_work_init(struct csio_oss_work *workp, void (*wfn)(void *),
		   void *data1, void *data2, void *os_func)
{
	workp->wfn = wfn;
	workp->data = data1;
	INIT_WORK(&workp->work, csio_oss_wfn);
	return;
}

int
csio_oss_work_schedule(struct csio_oss_work *workp)
{
	return schedule_work(&workp->work);
}

int
csio_oss_work_cleanup(struct csio_oss_work *workp)
{
//	return flush_work(&workp->work);
	return cancel_work_sync(&workp->work);
}
