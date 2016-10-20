/******************************************************************************
 *
 * Copyright (c) Chelsio Communications.  All rights reserved.
 *
 *   THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
 *   KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 *   IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
 *   PURPOSE.
 *
 * Module Name:
 *
 *    csio_defs.h
 *
 * Abstract:
 *
 *    csio_defs.h -  contains the common definitions & headers.
 *
 * Environment:
 *
 *    User mode
 *
 * Revision History:
 *
 *	Gokul TV - 08-Jun-10 -	Creation
 *
 *****************************************************************************/

#ifndef __CSIO_APP_DEFS_H__
#define __CSIO_APP_DEFS_H__

#include <csio_services.h>

#ifdef __cplusplus
extern "C" {
#endif

#define csio_printf( ... )		csio_oss_printf(__VA_ARGS__)

#define csio_memset(__p, __v, __l)	csio_oss_memset((__p), (__v), (__l))
#define csio_memcpy(__d, __s, __l)	csio_oss_memcpy((__d), (__s), (__l))

#define csio_malloc(__sz)		csio_oss_malloc((__sz))
#define csio_memfree(__ptr)		csio_oss_memfree((__ptr))

#define csio_sprintf( ... ) 		csio_oss_sprintf(__VA_ARGS__)
#define csio_snprintf( ... ) 		csio_oss_snprintf(__VA_ARGS__)
#if 0
#define csio_snprintf(__str, __sz, __fmt, ... )
		csio_oss_snprintf((__str),( __sz1), (__sz2), (__fmt), ...)
#define csio_snprintf( ... )		csio_oss_snprintf(__VA_ARGS__)
#endif

/*
 *  64-bit format specificers.
 *
 */

#define FS_S64		CSIO_OSS_FS_S64
#define FS_S64x		CSIO_OSS_FS_S64x
#define FS_U64		CSIO_OSS_FS_U64
#define FS_U64x		CSIO_OSS_FS_U64x
			

#ifdef __cplusplus
}
#endif

#endif /* __CSIO_APP_DEFS_H__ */
