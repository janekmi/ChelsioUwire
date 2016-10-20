/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver.
 *
 * Copyright (C) 2005-2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __T4_LINUX_FS__
#define __T4_LINUX_FS__

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
#include <linux/module.h>
#else
#include <linux/export.h>
#endif

#define DMABUF 1
#define DMABUF_SZ (64 * 1024)

struct t4_linux_debugfs_entry {
	const char *name;
	const struct file_operations *ops;
	umode_t mode;
	unsigned char data;
	unsigned int req;	/* adapter requirements to create this file */
};

struct seq_tab {
	int (*show)(struct seq_file *seq, void *v, int idx);
	unsigned int rows;		/* # of entries */
	unsigned char width;		/* size in bytes of each entry */
	unsigned char skip_first;	/* whether the first line is a header */
	char data[0];			/* the table data */
};

enum {  
	ADAP_NEED_L2T  = 1 << 0,
	ADAP_NEED_OFLD = 1 << 1,
	ADAP_NEED_FILT = 1 << 2,
	ADAP_NEED_SMT  = 1 << 3,
	ADAP_NEED_SRQ  = 1 << 4,
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static inline void *PDE_DATA(const struct inode *inode)
{
	return PDE(inode)->data;
}
#endif

#ifdef f_dentry
#define FILE_DATA(_file) ((_file)->f_path.dentry->d_inode)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
#define FILE_DATA(_file) file_inode(_file)
#else
#define FILE_DATA(_file) ((_file)->f_dentry->d_inode)
#endif

#define DEFINE_SIMPLE_DEBUGFS_FILE(name) \
static int name##_open(struct inode *inode, struct file *file) \
{ \
	return single_open(file, name##_show, inode->i_private); \
} \
static const struct file_operations name##_debugfs_fops = { \
	.owner   = THIS_MODULE, \
	.open    = name##_open, \
	.read    = seq_read, \
	.llseek  = seq_lseek, \
	.release = single_release \
}

char *unit_conv(char *buf, size_t len, unsigned int val,
		       unsigned int factor);

static inline unsigned int hex2val(char c)
{
	return isdigit(c) ? c - '0' : tolower(c) - 'a' + 10;
}

int setup_debugfs(struct adapter *adap);
void add_debugfs_files(struct adapter *adap, 
					struct t4_linux_debugfs_entry *files,
					unsigned int nfiles);

#ifdef T4_TRACE
void alloc_trace_bufs(struct adapter *adap);
void free_trace_bufs(struct adapter *adap);
#else
# define alloc_trace_bufs(adapter)
# define free_trace_bufs(adapter)
#endif

struct seq_tab *seq_open_tab(struct file *f, unsigned int rows,
			     unsigned int width, unsigned int have_header,
			     int (*show)(struct seq_file *seq, void *v, int i));
int mem_open(struct inode *inode, struct file *file);

#endif /* __T4_LINUX_FS__ */
