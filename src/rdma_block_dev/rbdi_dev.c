/*
 * Copyright (c) 2005-2006 Intel Corporation.  All rights reserved.
 * Copyright (c) 2015 Chelsio Corporation.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *	copyright notice, this list of conditions and the following
 *	disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *	copyright notice, this list of conditions and the following
 *	disclaimer in the documentation and/or other materials
 *	provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/completion.h>
#include <linux/file.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/idr.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <linux/module.h>
#include <linux/string.h>

#include <rdma/rdma_user_cm.h>
#include <rdma/ib_marshall.h>
#include <rdma/rdma_cm.h>
#include <rdma/rdma_cm_ib.h>

#include "rbdi_dev.h"

MODULE_AUTHOR("Steve Wise");
MODULE_DESCRIPTION("RDMA Test Driver");
MODULE_LICENSE("Dual BSD/GPL");

#define PFX "rbdi_dev: "

struct rbdi_dev_file {
	struct file		*filp;
};

/**
 * rbdi_dev_hello() - HELLO command to verify ABI version
 * @file:	rbdi_dev device file pointer
 * @inbuf:	user pointer of the request buffer
 * @in_len:	length of user request buffer
 * @out_len:	length of the user's reply buffer
 *
 * Copy in the user request, and return RBDI_DEV_VERSION in the reply
 *
 * Return: 0 or negative errno if the operation could not be attempted
 */
static ssize_t rbdi_dev_hello(struct rbdi_dev_file *file,
			      const char __user *inbuf, int in_len, int out_len)
{
	struct rbdi_dev_hello_req req;
	struct rbdi_dev_hello_rep rep;
	int ret = 0;
	
	if (out_len < sizeof(rep))
		return -ENOSPC;

	if (copy_from_user(&req, inbuf, sizeof(req)))
		return -EFAULT;

	rep.version = RBDI_DEV_VERSION;
	sprintf(rep.output, "Hello pid %d\n", req.pid);

	if (copy_to_user((void __user *)(uintptr_t)req.response,
			 &rep, sizeof(rep)))
		ret = -EFAULT;

	return ret;
}

/**
 * rbdi_dev_add() - ADD command to add a target device
 * @file:	rbdi_dev device file pointer
 * @inbuf:	user pointer of the request buffer
 * @in_len:	length of user request buffer
 * @out_len:	length of the user's reply buffer
 *
 * Copy in the user request which contains the IPv4 address string, the
 * IP port number, and the target block device name, and call
 * rbdi_add_target() to add the target.  The resulting errno is returned
 * in the reply structure.
 *
 * Return: 0 or negative errno if the operation could not be attempted
 */
static ssize_t rbdi_dev_add(struct rbdi_dev_file *file,
			    const char __user *inbuf, int in_len, int out_len)
{
	struct rbdi_dev_add_req req;
	struct rbdi_dev_add_rep rep = {0};
	int ret;

	if (out_len < sizeof(rep))
		return -ENOSPC;

	if (copy_from_user(&req, inbuf, sizeof(req)))
		return -EFAULT;
	ret = rbdi_add_target(req.addr, req.port, req.device);
	rep.error_num = ret;
	if (copy_to_user((void __user *)(uintptr_t)req.response,
			 &rep, sizeof(rep)))
		ret = -EFAULT;
	return ret;
}

/**
 * rbdi_dev_rem() - REM command to remove a target device
 * @file:	rbdi_dev device file pointer
 * @inbuf:	user pointer of the request buffer
 * @in_len:	length of user request buffer
 * @out_len:	length of the user's reply buffer
 *
 * Copy in the user request which contains rbdi device name to be removed,
 * and call rbdi_remove_device() to remove the target.  The resulting errno
 * is returned in the reply structure.
 *
 * Return: 0 or negative errno if the operation could not be attempted
 */
static ssize_t rbdi_dev_rem(struct rbdi_dev_file *file,
			    const char __user *inbuf, int in_len, int out_len)
{
	struct rbdi_dev_rem_req req;
	struct rbdi_dev_rem_rep rep = {0};
	int ret;

	if (out_len < sizeof(rep))
		return -ENOSPC;

	if (copy_from_user(&req, inbuf, sizeof(req)))
		return -EFAULT;
	ret = rbdi_remove_device(req.device);
	rep.error_num = ret;
	if (copy_to_user((void __user *)(uintptr_t)req.response,
			 &rep, sizeof(rep)))
		ret = -EFAULT;
	return ret;
}

/**
 * rbdi_dev_list() - LIST command to list the attached targets
 * @file:	rbdi_dev device file pointer
 * @inbuf:	user pointer of the request buffer
 * @in_len:	length of user request buffer
 * @out_len:	length of the user's reply buffer
 *
 * This command should be called twice by the user: First with
 * req.response_size == 0.  The command handler rbdi_list_targets() will
 * return the number of bytes needed to contain the output of the LIST command
 * in rep.response_size.  The user can then malloc the memory based on this
 * and call the second time with req.response_size set to the amount of memory 
 * allocated.  rbdi_list_targets() will then copy the human-readable
 * output string to the users response output buffer.
 *
 * Return: 0 or negative errno if the operation could not be attempted
 */
static ssize_t rbdi_dev_list(struct rbdi_dev_file *file,
			     const char __user *inbuf, int in_len, int out_len)
{
	struct rbdi_dev_list_req req;
	struct rbdi_dev_list_rep rep = {0};
	int ret = 0;

	if (out_len < sizeof(rep))
		return -ENOSPC;

	if (copy_from_user(&req, inbuf, sizeof(req)))
		return -EFAULT;

	rep.response_size = rbdi_list_targets(req.response + sizeof rep,
					      req.response_size);
	if (copy_to_user((void __user *)(uintptr_t)req.response,
			 &rep, sizeof(rep)))
		ret = -EFAULT;
	return ret;
}

/**
 * rbdi_dev_cmd_table - The array of command handler functions.
 */
static ssize_t (*rbdi_dev_cmd_table[])(struct rbdi_dev_file *file,
				       const char __user *inbuf,
				       int in_len, int out_len) = {
	[RBDI_DEV_HELLO] = rbdi_dev_hello,
	[RBDI_DEV_ADD] = rbdi_dev_add,
	[RBDI_DEV_REM] = rbdi_dev_rem,
	[RBDI_DEV_LIST] = rbdi_dev_list,
};

/**
 * rbdi_dev_write() - the rbdi_dev character device driver write function
 * @file:	The file pointer for this device instance
 * @buf:	The user buffer containing the command request and response
 * @len:	The length of the user buffer
 * @pos:	File position (not used)
 *
 * Copy in the rbdi_dev_cmd_hdr and validate it.  If it looks good, then
 * call the appropriate command handler function.
 *
 * Return: @len or a negative errno upon error
 */
static ssize_t rbdi_dev_write(struct file *filp, const char __user *buf,
			      size_t len, loff_t *pos)
{
	struct rbdi_dev_file *file = filp->private_data;
	struct rbdi_dev_cmd_hdr hdr;
	ssize_t ret;

	if (len < sizeof(hdr))
		return -EINVAL;

	if (copy_from_user(&hdr, buf, sizeof(hdr)))
		return -EFAULT;

	if (hdr.cmd >= ARRAY_SIZE(rbdi_dev_cmd_table))
		return -EINVAL;

	if (hdr.in + sizeof(hdr) > len)
		return -EINVAL;

	if (!rbdi_dev_cmd_table[hdr.cmd])
		return -ENOSYS;

	ret = rbdi_dev_cmd_table[hdr.cmd](file, buf + sizeof(hdr), hdr.in,
					  hdr.out);
	if (!ret)
		ret = len;

	return ret;
}

/**
 * rbdi_dev_open() - rbdi_dev device open function
 * @inode:	The inode associated with this device
 * @filp:	The file pointer to be associated with this open instance
 *
 * Allocate the file and hang it off @filp.
 * 
 * Return: 0 or negative errno upon failure.
 */
static int rbdi_dev_open(struct inode *inode, struct file *filp)
{
	struct rbdi_dev_file *file;

	file = kmalloc(sizeof *file, GFP_KERNEL);
	if (!file)
		return -ENOMEM;

	filp->private_data = file;
	file->filp = filp;

	return nonseekable_open(inode, filp);
}

/**
 * rbdi_dev_close() - rbdi_dev device close function
 * @inode:	The inode associated with this device
 * @filp:	The file pointer to be associated with this open instance
 *
 * Free up the file pointer and return.
 * 
 * Return: 0
 */
static int rbdi_dev_close(struct inode *inode, struct file *filp)
{
	struct rbdi_dev_file *file = filp->private_data;
	kfree(file);
	return 0;
}

static const struct file_operations rbdi_dev_fops = {
	.owner 	 = THIS_MODULE,
	.open 	 = rbdi_dev_open,
	.release = rbdi_dev_close,
	.write	 = rbdi_dev_write,
	.llseek	 = no_llseek,
};

static struct miscdevice rbdi_dev_misc = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= "rbdi_dev",
	.nodename	= "rbdi_dev",
	.mode		= 0666,
	.fops		= &rbdi_dev_fops,
};

/**
 * rbdi_dev_init() - rbdi_dev initialization function
 *
 * Called when rbdi loads, this will register the character device.
 * 
 * Return: 0 or negative errno if the registration fails
 */
int rbdi_dev_init(void)
{
	int ret;

	ret = misc_register(&rbdi_dev_misc);
	return ret;
}

/**
 * rbdi_dev_cleanup() - rbdi_dev cleanup function
 *
 * Called when rbdi unloads, this will deregister the character device.
 * 
 */
void rbdi_dev_cleanup(void)
{
	misc_deregister(&rbdi_dev_misc);
}
