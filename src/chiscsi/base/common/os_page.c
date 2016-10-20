#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#ifdef KERNEL_HAS_EXPORT_H
#include <linux/export.h>
#endif
#include <linux/mm.h>
#include <common/iscsi_common.h>
#include <common/os_export.h>

const unsigned long os_page_mask = PAGE_MASK;
const unsigned long os_page_size = PAGE_SIZE;
const unsigned int os_page_shift = PAGE_SHIFT;

/*
 * kernel pages
 *      returns < 0 if out of memory, 0 otherwise
 */
void   *__os_alloc_one_page(const char *fname, char wait, unsigned char **addrp)
{
	struct page *p = alloc_page(wait ? GFP_KERNEL : GFP_ATOMIC);
	if (!p) {
		os_log_error("%s failed to alloc one page.\n", fname);
		return NULL;
	} 

	iscsi_stats_inc(ISCSI_STAT_MEMPAGE);
	*addrp = (unsigned char *) (page_address(p));
	os_log_debug(ISCSI_DBG_MEM_PAGE,
		     "%s: alloc page 0x%p (%d), total %d.\n",
		     fname, p, wait, iscsi_stats_read(ISCSI_STAT_MEMPAGE));
	return (void *) p;
}
EXPORT_SYMBOL(__os_alloc_one_page);

void __os_free_one_page(const char *fname, void *p)
{
	if (p) {
		iscsi_stats_dec(ISCSI_STAT_MEMPAGE);
		os_log_debug(ISCSI_DBG_MEM_PAGE,
			     "%s: free page 0x%p, total %d.\n",
			     fname, p, iscsi_stats_read(ISCSI_STAT_MEMPAGE));
		__free_page((struct page *) p);
	}
}
EXPORT_SYMBOL(__os_free_one_page);
