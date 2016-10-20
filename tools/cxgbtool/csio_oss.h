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

#ifndef __CSIO_OSS_H__
#define __CSIO_OSS_H__

#if defined(__KERNEL__)

#include <linux/kernel.h>
#include <linux/kref.h>
#include <asm/io.h>
#include <asm/bug.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <scsi/scsi.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_eh.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_tcq.h>
#include <scsi/scsi_cmnd.h>
#include <asm/scatterlist.h>
#include <linux/mempool.h>
#include <linux/mm.h>
#include <linux/pci.h>
#include <asm/page.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/completion.h>
#include <linux/workqueue.h>
#include <linux/utsname.h>
#include <linux/version.h>

#ifdef __CSIO_DEBUG__ /* For dump the evil request */
#include <linux/blkdev.h>
#include <linux/bio.h>
#endif

/* Time related macros */
/* data Type of jiffies */
typedef unsigned long 	csio_oss_osticks_t;

enum csio_oss_error {
	CSIO_SUCCESS 	= 0,
	CSIO_NOPERM 	= EPERM,
	CSIO_NOENT 	= ENOENT,
	CSIO_EIO 	= EIO,
	CSIO_RETRY 	= EAGAIN,
	CSIO_NOMEM 	= ENOMEM,
	CSIO_BUSY 	= EBUSY,
	CSIO_INVAL 	= EINVAL,
	CSIO_EPROTO 	= EPROTO,
	CSIO_NOSUPP 	= EOPNOTSUPP,
	CSIO_TIMEOUT 	= ETIMEDOUT,
	CSIO_CANCELLED 	= ECANCELED,
	CSIO_OS_MAX_ERR,
	CSIO_FATAL
};

#define csio_oss_os_msecs()		jiffies_to_msecs(jiffies)
#define csio_oss_os_usecs()		jiffies_to_usecs(jiffies)

#define	csio_oss_mdelay(__m)		mdelay((__m))
#define	csio_oss_udelay(__u)		udelay((__u))
#define	csio_oss_ndelay(__n)		ndelay((__n))
#define csio_oss_msleep(__m)		msleep((__m))

/* use of volatile not recommended in Linux */
#define __VOLATILE

/* PCI related macros */

#define CSIO_OSS_PCI_BASE_ADDRESS_0		PCI_BASE_ADDRESS_0
#define CSIO_OSS_PCI_BASE_ADDRESS_MEM_MASK	PCI_BASE_ADDRESS_MEM_MASK

#define CSIO_REG(b, r)                  ((b) + (r))

static inline bool
csio_oss_reg_valid(void *dev, uint32_t reg)
{
	return (reg >= pci_resource_len((struct pci_dev *)dev, 0)? 0 : 1);
}

#define csio_oss_mb()			mb()
#define csio_oss_rmb()			rmb()
#define csio_oss_wmb()			wmb()

#define csio_oss_assert(cond)						\
do {									\
	if (unlikely(!((cond))))					\
	{								\
		BUG();							\
		panic("CSIO assertion %s:%d, cond: %s\n",		\
					__FILE__, __LINE__, #cond);	\
	}								\
} while(0)

#ifdef __CSIO_DEBUG__

#define csio_oss_db_assert(__c)		csio_oss_assert((__c))

#else /* __CSIO_DEBUG __ */

#define csio_oss_db_assert(__c)

#endif /* __CSIO_DEBUG __ */

#define csio_oss_memset(__p, __v, __l)	memset((__p), (__v), (__l))
#define csio_oss_memcpy(__d, __s, __l)	memcpy((__d), (__s), (__l))
#define csio_oss_memcmp(__d, __s, __l)	memcmp((__d), (__s), (__l))
#define csio_oss_strcpy(__d, __s)	strcpy((__d), (__s))
#define csio_oss_strncpy(__d, __s, __l)	strncpy((__d), (__s), (__l))
#define csio_oss_strstrip(__s)		strstrip((__s))
#define csio_oss_strlen(__s)		strlen((__s))

/* Byte swappers */
#define csio_oss_ntohs(_x)		ntohs(_x)
#define csio_oss_ntohl(_x)		ntohl(_x)
#define csio_oss_htons(_x)		htons(_x)
#define csio_oss_htonl(_x)		htonl(_x)
#define csio_oss_cpu_to_le16(_x)	cpu_to_le16(_x)
#define csio_oss_cpu_to_le32(_x)	cpu_to_le32(_x)
#define csio_oss_cpu_to_le64(_x)	cpu_to_le64(_x)
#define csio_oss_le16_to_cpu(_x)	le16_to_cpu(_x)
#define csio_oss_le32_to_cpu(_x)	le32_to_cpu(_x)
#define csio_oss_le64_to_cpu(_x)	le64_to_cpu(_x)
#define csio_oss_cpu_to_be16(_x)	cpu_to_be16(_x)
#define csio_oss_cpu_to_be32(_x)	cpu_to_be32(_x)
#define csio_oss_cpu_to_be64(_x)	cpu_to_be64(_x)
#define csio_oss_be16_to_cpu(_x)	be16_to_cpu(_x)
#define csio_oss_be32_to_cpu(_x)	be32_to_cpu(_x)
#define csio_oss_be64_to_cpu(_x)	be64_to_cpu(_x)
#define csio_oss_swab32(_x)		swab32(_x)

/* Number of 1s in a 32-bit word */
#define csio_oss_hweight32(__w)		hweight32((__w))

/* ilog2 */
#define csio_oss_ilog2(_x)		ilog2((_x))

#define CSIO_OSS_INT_MAX		INT_MAX

/* Align macros */
#define CSIO_OSS_ALIGN(_v, _a)		ALIGN((_v), (_a))

/* SCSI */
#define CSIO_OSS_SAM_STAT_GOOD			SAM_STAT_GOOD
#define CSIO_OSS_SAM_STAT_CHECK_CONDITION	SAM_STAT_CHECK_CONDITION
#define CSIO_OSS_SAM_STAT_CONDITION_MET		SAM_STAT_CONDITION_MET
#define CSIO_OSS_SAM_STAT_BUSY			SAM_STAT_BUSY
#define CSIO_OSS_SAM_STAT_INTERMEDIATE		SAM_STAT_INTERMEDIATE
#define CSIO_OSS_SAM_STAT_INTERMEDIATE_CONDITION_MET			\
	SAM_STAT_INTERMEDIATE_CONDITION_MET
#define CSIO_OSS_SAM_STAT_RESERVATION_CONFLICT	SAM_STAT_RESERVATION_CONFLICT
#define CSIO_OSS_SAM_STAT_COMMAND_TERMINATED	SAM_STAT_COMMAND_TERMINATED
#define CSIO_OSS_SAM_STAT_TASK_SET_FULL		SAM_STAT_TASK_SET_FULL
#define CSIO_OSS_SAM_STAT_ACA_ACTIVE		SAM_STAT_ACA_ACTIVE
#define CSIO_OSS_SAM_STAT_TASK_ABORTED		SAM_STAT_TASK_ABORTED

#define csio_oss_sgel 			scatterlist
#define csio_oss_scsi_for_each_sg(__dev, _osreq, _sgel, _n, _i)		\
	scsi_for_each_sg((struct scsi_cmnd *)(_osreq), (_sgel), (_n), (_i))
#define csio_oss_sgel_dma_addr(_sgel)	sg_dma_address((_sgel))
#define csio_oss_sgel_virt(_sgel)	sg_virt((_sgel))
#define csio_oss_sgel_len(_sgel)	sg_dma_len((_sgel))
#define csio_oss_sg_reset(_sgel)

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)
#define csio_kmap_atomic(_sgel)		kmap_atomic((_sgel), KM_IRQ0)
#define csio_kunmap_atomic(_sgel)	kunmap_atomic((_sgel), KM_IRQ0)
#else
#define csio_kmap_atomic(_sgel)		kmap_atomic((_sgel))
#define csio_kunmap_atomic(_sgel)      	kunmap_atomic((_sgel))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
#define csio_scsi_target_unblock(_dev, _state)	scsi_target_unblock((_dev))
#else
#define csio_scsi_target_unblock(_dev, _state)	scsi_target_unblock((_dev), (_state))
#endif

static inline int
csio_oss_copy_to_sgel(struct scatterlist *sgel, void *from, uint32_t len)
{
	uint32_t sg_off = sgel->offset;
	void *sg_addr;

	sg_addr = csio_kmap_atomic(sg_page(sgel) + (sg_off >> PAGE_SHIFT));
	if (!sg_addr)
		return -1;

	printk("copy_to_sgel:sg_addr %p sg_off %d from %p len %d\n",
		sg_addr, sg_off, from, len);

	memcpy(sg_addr + (sg_off & ~PAGE_MASK), from, len);
	csio_kunmap_atomic(sg_addr);

	return 0;
}

#ifdef __CSIO_USE_SG_NEXT__

#define csio_oss_sgel_next(_sgel)	sg_next((_sgel))

#else

static inline struct csio_oss_sgel *
csio_oss_sgel_next(struct csio_oss_sgel *sg)
{
        sg++;
        return sg;
}

#endif /* __CSIO_USE_SG_NEXT__ */

#define csio_oss_scsi_datalen(_osreq)					\
	(scsi_bufflen((struct scsi_cmnd *)(_osreq)))
#define csio_oss_scsi_oslun(_osreq)					\
	(((struct scsi_cmnd *)(_osreq))->device->lun)
#define csio_oss_scsi_tm_op(_osreq)					\
	(((struct scsi_cmnd *)(_osreq))->SCp.Message)

static inline void
csio_oss_scsi_lun(void *osreq, void *scratch2, uint8_t *lun)
{
	struct scsi_cmnd *scmnd = (struct scsi_cmnd *)osreq;
	struct scsi_lun *slun = (struct scsi_lun *)lun;

	int_to_scsilun(scmnd->device->lun, slun);

	return;
}

static inline void
csio_oss_scsi_cdb(void *osreq, uint8_t *cdb)
{
	struct scsi_cmnd *scmnd = (struct scsi_cmnd *)osreq;

	memcpy(cdb, scmnd->cmnd, 16);

	return;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
static inline void
csio_oss_scsi_tag(void *osreq, uint8_t *tag, uint8_t hq,
		  uint8_t oq, uint8_t sq)
{
	struct scsi_cmnd *scmnd = (struct scsi_cmnd *)osreq;
	char stag[2];

	if (scsi_populate_tag_msg(scmnd, stag)) {
		switch (stag[0]) {
		case HEAD_OF_QUEUE_TAG:
			*tag = hq;
			break;
		case ORDERED_QUEUE_TAG:
			*tag = oq;
			break;
		default:
			*tag = sq;
			break;
		}
	} else {
		*tag = 0;
	}

	return;
}
#endif

#ifdef __CSIO_DEBUG__
static inline void
csio_scsi_dump_evil_req(void *osreq)
{
	struct scsi_cmnd *scmnd = (struct scsi_cmnd *)osreq;
	struct request *rq = scmnd->request;
	struct bio *bio;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
	struct bio_vec bvec;
	struct bvec_iter iter;
#else
	struct bio_vec *bvec;
	int iter = 0;
#endif
	int i = 0;

	printk("csiostor: Evil request\n");
	__rq_for_each_bio(bio, rq) {
		printk("\tbio[%d]:\n", i++);
		printk("\t\tbi_sector: 0x%llx\n",
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
			(uint64_t)bio->bi_iter.bi_sector);
#else
			(uint64_t)bio->bi_sector);
#endif
		printk("\t\tbi_flags: 0x%lx\n", bio->bi_flags);
		printk("\t\tbi_rw: 0x%lx\n", bio->bi_rw);
		printk("\t\tbi_vcnt: %d\n", bio->bi_vcnt);
		printk("\t\tbi_phys_segments: %d\n", bio->bi_phys_segments);
		printk("\t\tbi_size: %d\n",
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
			bio->bi_iter.bi_size);
#else
			bio->bi_size);
#endif
		printk("\t\tbi_seg_front_size: %d\n", bio->bi_seg_front_size);
		printk("\t\tbi_seg_back_size: %d\n", bio->bi_seg_back_size);
		printk("\t\tbi_max_vecs: %d\n", bio->bi_max_vecs);
			
		bio_for_each_segment(bvec, bio, iter)
			printk("\t\tbvec[%d]=> addr:%llx len:%d off:%d\n",
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
					iter.bi_idx, (u64)page_to_phys(bvec.bv_page),
					bvec.bv_len, bvec.bv_offset);
#else
					iter, (u64)page_to_phys(bvec->bv_page),
					bvec->bv_len, bvec->bv_offset);
#endif
	}
}
#else
#define csio_scsi_dump_evil_req(req)
#endif /* __CSIO_DEBUG__ */

static inline int
csio_oss_pci_vpd_capability(void *dev, int *pos)
{
	*pos = pci_find_capability((struct pci_dev *)dev, PCI_CAP_ID_VPD);
	if (*pos)
		return 0;

	return -1;
}

static inline int
csio_oss_pci_capability(void *dev, int cap, int *pos)
{
	*pos = pci_find_capability((struct pci_dev *)dev, cap);
	if (*pos)
		return 0;

	return -1;
}

/* Reference counting */
struct csio_oss_kref {
	struct kref     kref;
	void 		*obj;
	void 		(*freeobj)(void *);
};
	
void csio_oss_kref_init(struct csio_oss_kref *, void *, void (*)(void *));
void csio_oss_kref_get(struct csio_oss_kref *);
int csio_oss_kref_put(struct csio_oss_kref *);

/* Compiler Optimizations */
#define csio_oss_likely(_cond)			likely((_cond))		
#define csio_oss_unlikely(_cond)		unlikely((_cond))		


/* Memory allocation macros */
#define csio_oss_cacheline_sz(_dev)	L1_CACHE_BYTES
#define CSIO_OSS_PAGE_SIZE		PAGE_SIZE
#define CSIO_OSS_PAGE_MASK		PAGE_MASK

#define __csio_oss_cacheline_aligned	____cacheline_aligned_in_smp

#define csio_oss_virt_add_valid(__addr)	virt_addr_valid((void *)(__addr))

/* DMA */
typedef	void __iomem			*csio_oss_iomem_t;
typedef	dma_addr_t			csio_oss_physaddr_t;

#define csio_oss_phys_addr(__p)		((__p))

struct csio_oss_dma_obj {
	struct pci_dev *dev;
	dma_addr_t paddr;
	size_t size;
};

void *csio_oss_dma_alloc(struct csio_oss_dma_obj *, void *,
				size_t, size_t, dma_addr_t *, int);
void csio_oss_dma_free(struct csio_oss_dma_obj *, void *);

/*
 * For now, use page sized dma allocations. For smaller sizes later,
 * we will need to create pools of DMA memory, and allocate off them.
 */
#define csio_oss_dma_pool_alloc(__dobj, __dev, __sz, __aln, __phys, __fl)    \
					csio_oss_dma_alloc((__dobj), (__dev),\
					(__sz), (__aln), (__phys), (__fl))
#define csio_oss_dma_pool_free(__d, __v)	csio_oss_dma_free((__d), (__v))

/* Locking */
struct csio_oss_spinlock {
	spinlock_t	oss_lock;
};

struct csio_oss_mutex {
	struct mutex lock;
};

#define csio_oss_spin_lock_init(l)	spin_lock_init(&(l)->oss_lock)
#define csio_oss_spin_lock(_osdev, l)	spin_lock(&(l)->oss_lock)
#define csio_oss_spin_lock_irq(_osdev, l)		\
					spin_lock_irq(&(l)->oss_lock)
#define csio_oss_spin_lock_irqsave(_osdev, l, f)	\
				spin_lock_irqsave(&(l)->oss_lock, (f))
#define csio_oss_spin_unlock(_osdev, l)	spin_unlock(&(l)->oss_lock)
#define csio_oss_spin_unlock_irq(_osdev, l)		\
				spin_unlock_irq(&(l)->oss_lock)
#define csio_oss_spin_unlock_irqrestore(_osdev, l, f)	\
				spin_unlock_irqrestore(&(l)->oss_lock, (f))

/* Logging */
#define csio_oss_printk(fmt, arg...)		printk(fmt, ##arg)
#define csio_oss_sprintf(__fmt, arg...)         sprintf(__fmt, ##arg)
#define csio_oss_info(pdev, fmt, arg...) 	\
	dev_info(&((struct pci_dev *)pdev)->dev, fmt, ##arg)
#define csio_oss_fatal(pdev, fmt, arg...) 	\
	dev_crit(&((struct pci_dev *)pdev)->dev, fmt, ##arg)
#define csio_oss_err(pdev, fmt, arg...) 	\
	dev_err(&((struct pci_dev *)pdev)->dev, fmt, ##arg)
#define csio_oss_warn(pdev, fmt, arg...) 	\
	dev_warn(&((struct pci_dev *)pdev)->dev, fmt, ##arg)
#ifdef __CSIO_DEBUG__
#define csio_oss_dbg(pdev, fmt, arg...) 	\
	dev_printk(KERN_INFO, &((struct pci_dev *)pdev)->dev, fmt, ##arg)
#else
#define csio_oss_dbg(pdev, fmt, arg...) 
#endif

#ifdef __CSIO_DEBUG__
#define csio_oss_db_log(__fmt, __arg...)	printk(__fmt, ##__arg)
#define csio_oss_scsi_dbg(pdev, fmt, arg...)	\
	dev_printk(KERN_INFO, &((struct pci_dev *)pdev)->dev, fmt, ##arg)
#else /* __CSIO_DEBUG __ */

#define csio_oss_scsi_dbg(pdev, fmt, arg...)
#define csio_oss_db_log(__fmt, __arg...)

#endif /* __CSIO_DEBUG __ */

#ifdef __CSIO_DEBUG_VERBOSE__

#define csio_oss_vdbg(pdev,__fmt, __arg...)	\
	dev_printk(KERN_DEBUG, &((struct pci_dev *)pdev)->dev, fmt, ##arg)
#define csio_oss_scsi_vdbg(pdev, fmt, arg...)	\
	dev_printk(KERN_DEBUG, &((struct pci_dev *)pdev)->dev, fmt, ##arg)
#define csio_oss_vprintk(__fmt, __arg...)	\
	printk(fmt, ##arg)
#define csio_oss_db_func(__fmt)		\
	printk(__fmt"Func %s: Line %d\n", __FUNCTION__, __LINE__)

#define csio_oss_scsi_vdbg_cnd(cnd, pdev, fmt, arg...)	\
	/* Modify here for conditional vdbg */		\
	if (cnd)					\
		dev_printk(KERN_DEBUG, &((struct pci_dev *)pdev)->dev, \
		    fmt, ##arg)	
#else	/* __CSIO_DEBUG_VERBOSE__ */  

#define csio_oss_vdbg(__fmt, __arg...)
#define csio_oss_scsi_vdbg(pdev, fmt, arg...)
#define csio_oss_vprintk(__fmt, __arg...)
#define csio_oss_db_func(__fmt)	
#define csio_oss_scsi_vdbg_cnd(cnd, pdev, fmt, arg...)

#endif /* __CSIO_DEBUG_VERBOSE__  */

/* Log buffer size */
#define CSIO_LOG_BUF_SHIFT	10	/* 1K */	
#define CSIO_LOG_BUF_SIZE	(1 << CSIO_LOG_BUF_SHIFT)
#define CSIO_LOG_BUF_MASK	(CSIO_LOG_BUF_SIZE - 1)

/* Log levels */
#define CSIO_LOG_LEVEL_ENABLE  0x10000000

/* Log buffer  */
struct csio_oss_log_buf {
	char buf[CSIO_LOG_BUF_SIZE];    /* Log buffer */
	uint32_t  rd_idx;		/* Read index */
	uint32_t  wr_idx;		/* Write index */
	uint32_t  buf_cnt;		/* Total bytes in Trace buffer */
	uint32_t  level;		/* Trace level */	
};

/* Trace buffer size */
#define CSIO_TRACE_BUF_SHIFT	10	/* 1K */	
#define CSIO_TRACE_BUF_SIZE	(1 << CSIO_TRACE_BUF_SHIFT)
#define CSIO_TRACE_BUF_MASK	(CSIO_TRACE_BUF_SIZE - 1)

/* Data buffer cap size */
#define CSIO_DCAP_BUF_SHIFT	10	/* 1K */	
#define CSIO_DCAP_BUF_SIZE	(1 << CSIO_DCAP_BUF_SHIFT)
#define CSIO_DCAP_BUF_MASK	(CSIO_DCAP_BUF_SIZE - 1)

/* Trace levels */
#define CSIO_TRACE_LEVEL_ENABLE  0x10000000
#define CSIO_TRACE_DCAP_ENABLE   0x20000000

/* Trace type */
#define CSIO_TRACE_IO		0	/* Trace IO path */
#define CSIO_TRACE_SMS		1	/* Trace SM events */
#define CSIO_TRACE_SME		2	/* Trace SM events */

#define _FILE_ strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__ 
/* Trace message */
struct csio_oss_trace_msg {
	char      file_name[32];	/* File name */
	uint32_t  line_no;		/* Line number */
	uint8_t	  type;			/* msg type */
	uint64_t  val[4];		/* Values to be stored as hex(64bit) */
	uint32_t  ts;			/* Time stamp */	
};
/* Trace buffer  */
struct csio_oss_trace_buf {
	/* Message buffer address */
	struct csio_oss_trace_msg msg_addr[CSIO_TRACE_BUF_SIZE]; 
	uint32_t  		  msg_size;	/* Message size */
	uint32_t  		  rd_idx;	/* Read index */
	uint32_t  		  wr_idx;	/* Write index */
	uint32_t  		  msg_cnt;	/* Total no of msg */
	uint32_t  		  level;	/* Trace level */	
};

/* Data capture */
struct csio_oss_dcap {
	uint64_t  ioreq;		/* Req handle */
	uint32_t  flags;		/* CDB opcode */ 
	uint32_t  lba;			/* lba */
	uint64_t  addr;			/* Address */
	uint32_t  len;			/* len */
	uint32_t  rsvd;			/* len */
	uint64_t  val1;			/* Value #1 */
	uint64_t  val2;			/* Value #2 */
	uint64_t  val3;			/* Value #3 */
	uint64_t  val4;			/* Value #4 */
};

/* Data capture buffer  */
struct csio_oss_dcap_buf {
	/* Message buffer address */
	struct csio_oss_dcap     msg_addr[CSIO_DCAP_BUF_SIZE]; 
	uint32_t  		 msg_size;	/* Message size */
	uint32_t  		 rd_idx;	/* Read index */
	uint32_t  		 wr_idx;	/* Write index */
	uint32_t  		 msg_cnt;	/* Total no of msg */
	uint32_t  		 level;		/* Trace level */	
};

#define _FILE_ strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__
#define csio_oss_trace(_tbuf, _l, _type, _v1, _v2, _v3, _v4)        \
do      \
{       \
	struct csio_oss_trace_buf *t = _tbuf;       \
        struct csio_oss_trace_msg *msg; \
					\
        /* Check Trace level is enabled */	\
        if (!(t->level & CSIO_TRACE_LEVEL_ENABLE) ||	\
           !(t->level & _l))                         \
           break;                                      \
        /* Frame trace msg */				\
        msg = (t->msg_addr + t->wr_idx);                \
        strncpy(msg->file_name, _FILE_, 32);            \
        msg->line_no = __LINE__;                        \
        msg->type = _type;                        \
 	msg->val[0] = (uintptr_t) _v1;            \
        msg->val[1] = (uintptr_t) _v2;            \
        msg->val[2] = (uintptr_t) _v3;            \
        msg->val[3] = _v4;                        \
        msg->ts = jiffies;                              \
	/* Update Write index and msg count */		\
	t->wr_idx = (t->wr_idx + 1) & CSIO_TRACE_BUF_MASK;	\
        /* Circular trace buffer full. Allow over writing */	\
        if (t->msg_cnt >= CSIO_TRACE_BUF_SIZE) {                \
                t->rd_idx = ((t->rd_idx + 1) &          \
                                     CSIO_TRACE_BUF_MASK);      \
        }                       \
        else {                  \
                t->msg_cnt++;   \
        }               \
}while(0);

static inline void
csio_oss_dump_buffer(uint8_t *buf, uint32_t buf_len)
{
	uint32_t ii = 0;

	for (ii = 0; ii < buf_len ; ii++) {
		if(!(ii & 0xF))
			printk("\n0x%p:", (buf + ii));
		if(!(ii & 0x7))
			printk(" 0x%02x", buf[ii]);
		else
			printk("%02x", buf[ii]);
	}

	printk("\n");
}

static inline void
csio_oss_scsi_dump_buffer(uint32_t cnd, uint8_t *buf, uint32_t buf_len)
{
	uint32_t ii = 0;

	/* Modify here for conditional dump */
	if (!cnd)
		return;

	for (ii = 0; ii < buf_len ; ii++) {
		if(!(ii & 0xF))
			printk("\n0x%p:", (buf + ii));
		if(!(ii & 0x7))
			printk(" 0x%02x", buf[ii]);
		else
			printk("%02x", buf[ii]);
        }

        printk("\n");
}

static inline int
csio_oss_hostname(void *os_dev, uint8_t *buf, size_t buf_len)
{
	if (snprintf(buf, buf_len, "%s",
		init_utsname()->nodename) > 0) {
		return 0;
	}
	return -1;
}

void csio_oss_trace_init(struct csio_oss_trace_buf *, uint32_t);
void csio_oss_trace_start(struct csio_oss_trace_buf *, uint32_t);
void csio_oss_trace_stop(struct csio_oss_trace_buf *);
int csio_oss_trace_readmsg(struct csio_oss_trace_buf *,
                           struct csio_oss_trace_msg *, uint32_t);
int csio_oss_dcap_read(struct csio_oss_dcap_buf *dcap_buf, 
		   struct csio_oss_dcap *msg_buf, uint32_t msg_num);
int csio_oss_dcap_write(struct csio_oss_dcap_buf *dcap_buf, 
		   struct csio_oss_dcap *msg_buf, uint32_t msg_num);


/* Scheduling and timers */

/* Timers */
struct csio_oss_timer {
	struct timer_list oss_timer;
};

void csio_oss_timer_init(struct csio_oss_timer *,
				void (*)(uintptr_t), void *);
void csio_oss_timer_start(struct csio_oss_timer *, uint32_t);
void csio_oss_timer_stop(struct csio_oss_timer *);

/* Sleep/wakeup */
struct csio_oss_cmpl {
	struct completion cmpl;
	int flags;
};

void csio_oss_cmpl_init(struct csio_oss_cmpl *);
void csio_oss_sleep(struct csio_oss_cmpl *);
void csio_oss_wakeup(struct csio_oss_cmpl *);

/* Worker queue */
struct csio_oss_workq {
	struct workqueue_struct *wq;
};

/* ISR Worker */
struct csio_oss_work {
	struct work_struct work;
	void (*wfn)(void *);
	void *data;
};

void csio_oss_workq_create(struct csio_oss_workq *, void *, void *);
int
csio_oss_queue_work(struct csio_oss_workq *workq, struct csio_oss_work *workp);
void csio_oss_workq_destroy(struct csio_oss_workq *);

void csio_oss_work_init(struct csio_oss_work *,
				void (*)(void *), void *, void *, void *);
int csio_oss_work_schedule(struct csio_oss_work *);
int csio_oss_work_cleanup(struct csio_oss_work *);
int csio_oss_osname(void *os_dev, uint8_t *buf, size_t buf_len);

#endif /* __KERNEL__ */

/* This is shared between user and kernel space */
typedef struct csio_ioctl_hdr {
	uint32_t cmd;
	uint32_t len;
	uint32_t dir;
} ioctl_hdr_t;

/* some kernels do not have these definitions, though we should be moving to %pI4 */
#ifndef NIPQUAD
#define NIPQUAD(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]
#endif

#define NIPQUAD_REV(addr) \
        ((unsigned char *)&addr)[3], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[0]

#ifndef NIPQUAD_FMT
#define NIPQUAD_FMT "%u.%u.%u.%u"
#endif

#endif /* __CSIO_OSS_H__ */
