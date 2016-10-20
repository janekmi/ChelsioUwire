/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/fs.h>

int os_read_file(const char *filename, char *buffer, int buffer_len)
{
	int ret = 0;
	struct file* filp;
	mm_segment_t old_fs;

	old_fs = get_fs();
	filp = filp_open(filename, O_RDONLY, 0);
	if (IS_ERR(filp))
		return -1;

	set_fs(KERNEL_DS);
	ret = vfs_read(filp, buffer, buffer_len, &filp->f_pos);
	set_fs(old_fs);
	filp_close(filp, NULL);

	return ret;
}

int os_write_file(const char *filename, char *data, int len)
{
	struct file *filp;
	int ret = 0;
	mm_segment_t old_fs;

	filp = filp_open(filename, O_WRONLY|O_CREAT|O_TRUNC|O_LARGEFILE, 0644);
	if (IS_ERR(filp))
		return -1;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = vfs_write(filp, data, len, &filp->f_pos);
	set_fs(old_fs);
	filp_close(filp, NULL);

	return 0;
}

int os_stat_atime(const char* path)
{
	struct file *filp;
	time_t atime;

	filp = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(filp))
		return -1;

	atime = filp->f_dentry->d_inode->i_atime.tv_sec;
	filp_close(filp, NULL);

	return atime;
}

