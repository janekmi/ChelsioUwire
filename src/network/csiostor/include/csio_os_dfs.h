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

#ifndef __CIOS_OS_DFS_H__
#define __CIOS_OS_DFS_H__

int __devinit csio_osdfs_create(struct csio_os_hw *oshw);
int csio_osdfs_destroy(struct csio_os_hw *oshw);
int csio_osdfs_init(void);
int csio_osdfs_exit(void);

#endif /* ifndef __CIOS_OS_DFS_H__ */
