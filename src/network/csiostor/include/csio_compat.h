/*
 * Copyright (C) 2003-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/*
 * This file is used to allow the driver to be compiled under multiple
 * versions of Linux with as few obtrusive in-line #ifdef's as possible.
 */

#ifndef __CSIO_COMPAT_H
#define __CSIO_COMPAT_H

#include "distro_compat.h"

#ifndef __devinit
/* these disappeared in Linux 3.8 ... */
#define __devinit
#define __devexit
#define __devexit_p(x) x
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
#define kstrtoul strict_strtoul
#endif

#endif /* __CSIO_COMPAT_H */
