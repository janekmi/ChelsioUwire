#ifndef __CXGBI_COMPAT_H__
#define __CXGBI_COMPAT_H__

#include "cxgbi_compat_libiscsi2.h"

#if !defined (ISVMALLOC)
#ifdef CONFIG_MMU
static inline int is_vmalloc_addr(const void *x)
{
	unsigned long addr = (unsigned long)x;
	return addr >= VMALLOC_START && addr < VMALLOC_END;
}
#else
#define is_vmalloc_addr(x)	0
#endif
#endif

#if !defined (NIPQUAD)
#define NIPQUAD_FMT	"%pI4"
#define NIPQUAD(addr)	(&(addr))
#endif

#if !defined (PRFMT)
#ifndef pr_warning
#define pr_warning(fmt, ...)	printk(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#endif
//#undef pr_err
#ifndef pr_err
#define pr_err(fmt, ...)	printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#endif
//#undef pr_info
#ifndef pr_info
#define pr_info(fmt, ...)	printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
#endif

#endif

#ifndef pr_warn
#define pr_warn pr_warning
#endif

#if !defined(_VLAN_N_VID_) && defined(CXGBI_IPV6_SUPPORT)
#define VLAN_N_VID VLAN_GROUP_ARRAY_LEN
#endif

#endif /* ifndef __CXGBI_COMPAT_H__ */
