/*
 * Function wrappers for handling kernel memory
 */
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/skbuff.h>
#include <linux/smp.h>
#ifdef CONFIG_BKL
#include <linux/smp_lock.h>
#endif
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/quotaops.h>
#include <linux/pagemap.h>
#include <linux/personality.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/mount.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/backing-dev.h>
#include <linux/vfs.h>
#include <asm/uaccess.h>
#include <linux/rcupdate.h>
#include <asm/io.h>

#include <common/iscsi_common.h>
#include <common/os_export.h>
#include <kernel/linux_compat.h>
/*
 * memory allocation
 *	returns < 0 if out of memory, 0 otherwise
 */
void   *__os_alloc(const char *fname, unsigned int size, char wait,
		   char contiguous)
{
	void   *p = NULL;

	if (unlikely(size > (PAGE_SIZE << MAX_ORDER)
#ifdef HAS_KMALLOC_MAX_SIZE
		|| size > KMALLOC_MAX_SIZE
#endif
	   )) {
		if (wait && !contiguous)
			p = vmalloc(size);
		else
			os_log_error("%s: alloc size %u > %u << %u, %d,%d.\n",
					fname, size, PAGE_SIZE, MAX_ORDER,
					wait, contiguous);
	} else
		p = kmalloc(size, (wait ? GFP_KERNEL : GFP_ATOMIC));

	if (!p && wait && !contiguous)
		p = vmalloc(size);

	if (!p) {
		os_log_error("%s, failed to alloc %u.\n", fname, size);
		return NULL;
	}

	memset(p, 0, size);
	iscsi_stats_inc(ISCSI_STAT_MEM);
	os_log_debug(ISCSI_DBG_MEM,
		     "%s: malloc 0x%p (%u,%d), total %d.\n",
		     fname, p, size, wait, iscsi_stats_read(ISCSI_STAT_MEM));

	return p;
}

#define KK(x) ((x) << (PAGE_SHIFT-10))
unsigned long long total_size_of_ramdisks = 0;

/* Make sure that the total size of all ramdisks is at most half of system memory */
int __os_can_allocate_ramdisk(unsigned long long alloc_size)
{

	struct sysinfo i;
	si_meminfo(&i);

#ifdef CONFIG_HIGHMEM
	if((alloc_size + total_size_of_ramdisks) > (256*1024)) {
		os_log_info("The total size of all ramdisks cannot excede %ld KB for a PAE system\n",(256*1024));
#else
	if((alloc_size + total_size_of_ramdisks) > (KK(i.totalram)/2)) {
			os_log_info("The total size of all ramdisks cannot excede half of system memory, or %ld KB\n",KK(i.totalram));
#endif
		return 0;
	}
	else
		return 1;

}

void __os_update_ramdisk_stats(unsigned long long alloc_size)
{
	total_size_of_ramdisks += alloc_size;
}

void __os_decrement_ramdisk_stats(unsigned long long alloc_size)
{
	total_size_of_ramdisks -= alloc_size;
}


void __os_vfree(const char *fname, void *p)
{
	if (p) {
		iscsi_stats_dec(ISCSI_STAT_MEM);
		os_log_debug(ISCSI_DBG_MEM,
				"%s: vfree 0x%p, total %d.\n",
				fname, p, iscsi_stats_read(ISCSI_STAT_MEM));
		vfree(p);
	}
}

void   *__os_vmalloc(const char *fname, unsigned int size)
{
	void *p = NULL;

	p = vmalloc(size);

	if (!p) {
		os_log_error("%s, failed to alloc %u.\n", fname, size);
		return NULL;
	}
	iscsi_stats_inc(ISCSI_STAT_MEM);
	os_log_debug(ISCSI_DBG_MEM,
			"%s: vmalloc 0x%p, total %d.\n",
			fname, p,  iscsi_stats_read(ISCSI_STAT_MEM));

	return p;
}


void * __os_phys_to_virt( unsigned long pos)
{
	return phys_to_virt(pos);
}

void __os_free(const char *fname, void *p)
{
	if (p) {
		iscsi_stats_dec(ISCSI_STAT_MEM);
		os_log_debug(ISCSI_DBG_MEM,
				"%s: kfree 0x%p total %d.\n",
				fname, p, iscsi_stats_read(ISCSI_STAT_MEM));

		if (((unsigned long) p) >= VMALLOC_START &&
				((unsigned long) p) < VMALLOC_END)
			vfree(p);
		else
			kfree(p);
	}
}

/* 
 * page mapping of a scattergather list
 */
int os_chiscsi_sglist_page_map(chiscsi_sgvec * sg, int sgcnt)
{
	int     i;
	for (i = 0; i < sgcnt; i++, sg++) {
		if ((sg->sg_flag & CHISCSI_SG_SBUF_MAP_NEEDED) &&
				!(sg->sg_flag & CHISCSI_SG_SBUF_MAPPED)) {
			sg->sg_addr = (unsigned char *) kmap(sg->sg_page);
			sg->sg_addr += sg->sg_offset;
			sg->sg_flag |= CHISCSI_SG_SBUF_MAPPED;
		}
	}
	return 0;
}

void os_chiscsi_sglist_page_unmap(chiscsi_sgvec * sg, int sgcnt)
{
	int     i;
	for (i = 0; i < sgcnt; i++, sg++) {
		if (sg->sg_flag & CHISCSI_SG_SBUF_MAPPED) {
			sg->sg_flag &= ~CHISCSI_SG_SBUF_MAPPED;
			sg->sg_addr = NULL;
			kunmap(sg->sg_page);
		}
	}
}

/*
 * user <-> kernel copy
 */
unsigned long os_copy_from_user(void *to, const void *from, unsigned long n)
{
	return (copy_from_user(to, from, n));
}

unsigned long os_copy_to_user(void *to, const void *from, unsigned long n)
{
	return (copy_to_user(to, from, n));
}

void * __os_file_open(const char __user *filename,int flags, int mode)
{
	struct file *fp;
	mm_segment_t fs;
	fs = get_fs();
        set_fs(get_ds());
	fp = filp_open(filename,flags, mode);
	set_fs(fs);
	if (IS_ERR(fp))
		return NULL;
        else
		return fp;
}

void __os_file_close(void* fp)
{
	mm_segment_t fs;
	fs = get_fs();
        set_fs(get_ds());
	(void)filp_close(fp, NULL);
	set_fs(fs);
	return;
}

int __os_file_unlink(void* fp_api)
{
	int status = 0;
	struct file* fp = (struct file*)fp_api;
	mm_segment_t fs;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	struct inode *inode = fp->f_dentry->d_inode;
#else
	struct inode *inode = file_inode(fp);
#endif

	fs = get_fs();
        set_fs(get_ds());

#ifdef VFS_UNLINK_3PAR
	status = vfs_unlink(inode,fp->f_path.dentry, 0);
#else
	status = vfs_unlink(inode,fp->f_path.dentry);
#endif

	set_fs(fs);
	return status;
}

int __os_file_read(void *fp_api, void *buf_api, int count,
			unsigned long long *pos)
{
	size_t rv = 0;
	struct file* fp = (struct file*)fp_api;
	char __user *buf = (char __user *)buf_api;
	mm_segment_t fs;

	fs = get_fs();
        set_fs(get_ds());

	rv = vfs_read(fp, buf, count, pos);

	set_fs(fs);

	return (int)rv;
}

int __os_file_write(void* fp_api, void *buf_api, int count,
			unsigned long long *pos)
{
	size_t rv = 0;
	struct file* fp = (struct file*)fp_api;
	char __user *buf = (char __user *)buf_api;

	mm_segment_t fs;
	fs = get_fs();
        set_fs(get_ds());
	rv = vfs_write(fp, buf, count, pos);
	set_fs(fs);
	return (int)rv;
}
