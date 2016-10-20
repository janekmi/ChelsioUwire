/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <linux/sched.h>
#include <linux/scatterlist.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/highmem.h>
#include <linux/ctype.h>
#include <linux/version.h>
#include <linux/jiffies.h>
#include <linux/pci.h>
#include <asm/atomic.h>
#include "chfcoe_os.h"

const unsigned long os_completion_size = sizeof(struct completion);
const unsigned long os_atomic_size = sizeof(atomic_t);
const unsigned long os_structpage_size = sizeof(struct page);
const unsigned long os_hz = HZ;
const unsigned long os_page_size = PAGE_SIZE;
const unsigned long os_page_mask = PAGE_MASK;
const unsigned long os_page_shift = PAGE_SHIFT;

void *chfcoe_memset(void *m, int c, unsigned long count)
{
	return memset(m, c, count);
}

void *chfcoe_memcpy(void *dst, const void *src, unsigned long count)
{
	return memcpy(dst, src, count);
}

int chfcoe_memcmp(const void *m1, const void *m2, unsigned long count)
{
	return memcmp(m1, m2, count);
}

unsigned int chfcoe_smp_id(void)
{
	return smp_processor_id();
}

unsigned int chfcoe_num_online_cpus(void)
{
	return num_online_cpus();
}

void chfcoe_smp_mb(void)
{
	smp_mb();
}

void chfcoe_bug(void)
{
	BUG();
}

void chfcoe_log(unsigned int level, const char *fmt, ...)
{
	char buf[512];
	va_list args;

	va_start(args, fmt);
	vsnprintf(buf, 512, fmt, args); 
	va_end(args);

	switch (level) {
	case CHFCOE_LOG_ERR:
		printk(KERN_ERR "chfcoe:%s", buf);
		break;

	case CHFCOE_LOG_WARN:
		printk(KERN_WARNING "chfcoe:%s", buf);
		break;

	case CHFCOE_LOG_INFO:
		printk(KERN_INFO "chfcoe:%s", buf);
		break;

	case CHFCOE_LOG_DBG:
		printk(KERN_DEBUG "chfcoe:%s", buf);
		break;
	}

}

uint64_t chfcoe_get_lun(const uint8_t *lun)
{
	return (*((__be64 *)lun));
}

/* scatter list */
unsigned long long chfcoe_sg_dma_addr(void *sg)
{
	return sg_dma_address((struct scatterlist *)sg);
}

unsigned int chfcoe_sg_dma_len(void *sg)
{
	return sg_dma_len((struct scatterlist *)sg);
}

unsigned int chfcoe_sg_len(void *sg)
{
	return (((struct scatterlist *)sg)->length);
}

unsigned int chfcoe_sg_offset(void *sg)
{
	return (((struct scatterlist *)sg)->offset);
}

void *chfcoe_sg_page(void *sg)
{
	return sg_page((struct scatterlist *)sg);
}

void *chfcoe_sg_next(void *sg)
{
	return ((void *)sg_next(sg));
}

unsigned int chfcoe_pci_map_page(void *pdev, void *sg_ptr, uint64_t *dma_addr)
{
	struct scatterlist *sg = sg_ptr;

	*dma_addr = pci_map_page(pdev, sg_page(sg), sg->offset, sg->length, PCI_DMA_TODEVICE);

	if (unlikely(pci_dma_mapping_error(pdev, *dma_addr)))
		return 1;

	get_page(sg_page(sg));

	return 0;
}

void chfcoe_pci_unmap_page(void *pdev, void *page,
		uint64_t dma_addr, unsigned int len)
{
	pci_unmap_page(pdev, dma_addr, len, PCI_DMA_TODEVICE);
	put_page(page);
}

void *chfcoe_kmap(void *p)
{
	return kmap((struct page *)p);
}

void chfcoe_kunmap(void *p)
{
	kunmap((struct page *)p);
}

/* Completion */
void chfcoe_init_completion(void *cmpl)
{
	init_completion((struct completion *)cmpl);
}

void chfcoe_reinit_completion(void *cmpl)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
	INIT_COMPLETION(*(struct completion *)cmpl);
#else
	reinit_completion((struct completion *)cmpl);
#endif
}

void chfcoe_wait_for_completion(void *cmpl)
{
	wait_for_completion((struct completion *)cmpl);
}

void chfcoe_complete(void *cmpl)
{
	complete((struct completion *)cmpl);
}

/* Delay */
void chfcoe_msleep(unsigned int msecs)
{
	msleep(msecs);
}

unsigned long os_jiffies(void)
{
	return jiffies;
}

/*Atomic variables*/
void chfcoe_atomic_set(void *p, int v)
{
	atomic_set((atomic_t *)p, v);
}	

int chfcoe_atomic_read(void *p)
{
	return atomic_read((atomic_t *)p);
}	

void chfcoe_atomic_inc(void *p)
{
	atomic_inc((atomic_t *)p);
}	

void chfcoe_atomic_dec(void *p)
{
	atomic_dec((atomic_t *)p);
}	

int chfcoe_atomic_dec_and_test(void *p)
{
	return atomic_dec_and_test((atomic_t *)p);
}


/*Bit operations*/
int chfcoe_test_bit(unsigned long pos, const void *p)
{
	return test_bit(pos, p);
}

void chfcoe_set_bit(unsigned long pos, void *p)
{
	set_bit(pos, p);
}

void __chfcoe_set_bit(unsigned long pos, void *p)
{
	__set_bit(pos, p);
}

void chfcoe_clear_bit(unsigned long pos, void *p)
{
	clear_bit(pos, p);
}

void __chfcoe_clear_bit(unsigned long pos, void *p)
{
	__clear_bit(pos, p);
}

int chfcoe_test_and_clear_bit(unsigned long pos, void *p)
{
	return test_and_clear_bit(pos, p);
}

int chfcoe_test_and_set_bit(unsigned long pos, void *p)
{
	return test_and_set_bit(pos, p);
}


unsigned long chfcoe_find_next_zero_bit(const unsigned long *p, unsigned long size,
		unsigned long off)
{
	return find_next_zero_bit(p, size, off);
}

unsigned long chfcoe_find_next_bit(const unsigned long *p, unsigned long size,
		unsigned long off)
{
	return find_next_bit(p, size, off);
}

long long os_gettimeinsecs(void)
{
	struct timeval tm;

	do_gettimeofday(&tm);

	return tm.tv_sec;
}

int os_isprint(int c)
{
	return isprint(c);
}

int os_snprintf(char *buffer, int buflen, const char *fmt, ...)
{
	char buf[512];
	va_list args;

	va_start(args, fmt);
	vsnprintf(buf, 512, fmt, args); 
	va_end(args);

	return snprintf(buffer, buflen, buf);
}

int os_sprintf(char *buffer, const char *fmt, ...)
{
	char buf[512];
	va_list args;

	va_start(args, fmt);
	vsnprintf(buf, 512, fmt, args); 
	va_end(args);

	return sprintf(buffer, buf);
}

unsigned long os_strtoul(const char *cp, char **endp, int base)
{       
	return (simple_strtoul(cp, endp, base));
}

unsigned long os_strlen(const char *str)
{
	return strlen(str);
}

char *os_strcpy(char *dest, const char *src)
{
	return strcpy(dest, src);
}

int os_time_after(unsigned long a, unsigned long b)
{
	return time_after(a, b);
}

