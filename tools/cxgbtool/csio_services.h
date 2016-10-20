/******************************************************************************
 *
 * Copyright (c) Chelsio Communications.  All rights reserved.
 *
 *   THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
 *   KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 *   IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
 *   PURPOSE.
 *
 *
 *****************************************************************************/

#ifndef __CSIO_SERVICES_H__
#define __CSIO_SERVICES_H__

#include <endian.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <byteswap.h>
#include <inttypes.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <asm-generic/ioctl.h>
#include <asm/byteorder.h>
#include <inttypes.h>

#include <csio_oss.h>
#include <t4fw_interface.h>

#ifdef __cplusplus
extern "C" {
#endif


#if defined(__KERNEL__)
#undef USER_MODE
#else
#define USER_MODE
#endif

#define TRUE	1
#define FALSE	0

#define IS_STR_EQUAL(_str1, _str2) (!strcmp((_str1), (_str2)))
#define IS_BUF_EQUAL(_buf1, _buf2, _count) (!memcmp((_buf1), (_buf2), (_count)))

#define csio_strcmp(_str1, _str2)	strcmp((_str1), (_str2))
//#define csio_stricmp(_str1, _str2)	_stricmp((_str1), (_str2))
//have to fix this soon
#define csio_stricmp(_str1, _str2)	strcmp((_str1), (_str2))
#define csio_min(__x, __y)		((__x) < (__y) ? (__x) : (__y))
#define csio_max(__x, __y)		((__x) > (__y) ? (__x) : (__y))

#ifndef CSIO_IOCTL_SIGNATURE
#define CSIO_IOCTL_SIGNATURE			"csiodev"
#endif

#define CSIO_CDEVFILE				"csiostor"
#define CHFCOE_CDEVFILE				"chfcoe"

#ifndef CSIO_DEFAULT_IOCTL_TIMEOUT_PERIOD
#define CSIO_DEFAULT_IOCTL_TIMEOUT_PERIOD	10000 /* 10 seconds */
#endif

#define inline __inline
#define INLINE __inline

#ifdef FCOE_LIB
#	define __csio_export
#else	
#	define __csio_export	static
#endif


#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(x)
#endif

#if !defined (CSIO_ASSERT)
#	if defined (DBG)
#		define CSIO_ASSERT(_x)	do { if (!(_x)) __debugbreak(); } while(0)
#	else
#		define CSIO_ASSERT(_x)
#	endif
#endif

#ifndef CSIO_ARRAY_SIZE
#define CSIO_ARRAY_SIZE(_x)	(sizeof(_x) / sizeof((_x)[0]))
#endif

/*
 *  64-bit OS specific format specificers.
 *
 */
#define CSIO_OSS_FS_S64		PRId64
#define CSIO_OSS_FS_S64x	PRIx64
#define CSIO_OSS_FS_U64		PRIu64
#define CSIO_OSS_FS_U64x	PRIx64

#define cpu_to_le64(x)				__cpu_to_le64(x)
#define le64_to_cpu(x)				__le64_to_cpu(x)
#define cpu_to_le32(x)				__cpu_to_le32(x)
#define le32_to_cpu(x)				__le32_to_cpu(x)
#define cpu_to_le16(x)				__cpu_to_le16(x)
#define le16_to_cpu(x)				__le16_to_cpu(x)
#define cpu_to_be64(x)				__cpu_to_be64(x)
#define be64_to_cpu(x)				__be64_to_cpu(x)
#define cpu_to_be32(x)				__cpu_to_be32(x)
#define be32_to_cpu(x)				__be32_to_cpu(x)
#define cpu_to_be16(x)				__cpu_to_be16(x)
#define be16_to_cpu(x)				__be16_to_cpu(x)

#define csio_oss_printf(__fmt, ...)		printf(__fmt, ##__VA_ARGS__)
#define csio_oss_memcpy(__dst, __src, __sz)	memcpy((__dst), (__src), (__sz))
#define csio_oss_memset(__dst, __val, __sz)	memset((__dst), (__val), (__sz))
#define csio_oss_malloc(__sz)			malloc((__sz))
#define csio_oss_memfree(__ptr)			free((__ptr))
#define csio_oss_sprintf(__fmt, ...)		sprintf(__fmt, ##__VA_ARGS__)
#define csio_oss_snprintf(__fmt, ...)		snprintf(__fmt, ##__VA_ARGS__)
#if 0
#define csio_oss_snprintf(__str, __sz1, __sz2, __fmt, __arg...)
				snprintf((__str), (__sz1), (__fmt), ##__arg)
#endif

typedef int adap_handle_t;
typedef int file_handle_t;

/* IOCTL services */
#define CSIO_IOCD_NONE				_IOC_NONE
#define CSIO_IOCD_WRITE				_IOC_WRITE
#define CSIO_IOCD_READ				_IOC_READ
#define CSIO_IOCD_RW			(CSIO_IOCD_WRITE | CSIO_IOCD_READ)

static void inline
csio_oss_init_header(void *header, uint32_t cmd, char magic[8],
		     size_t len, uint32_t dir)
{
	ioctl_hdr_t *hdr = (ioctl_hdr_t *)header;

	hdr->cmd = cmd;
	hdr->len = len - sizeof(ioctl_hdr_t);
	hdr->dir = dir;
	return;
}

#define os_agnostic_buffer_len(_plen)		((_plen) + sizeof(ioctl_hdr_t))

#define get_payload(_buf)	\
			(void *)((uintptr_t)(_buf) + sizeof(ioctl_hdr_t))


/* Function definitions */
adap_handle_t open_adapter(int8_t);
adap_handle_t open_adapter_str(char *);
void close_adapter(adap_handle_t);
file_handle_t open_file(char *);
int write_file(file_handle_t, void *, size_t, uint32_t *);
void close_file(file_handle_t);
void *ioctl_buffer_alloc(size_t, char signature[8]);
void ioctl_buffer_free(void *);
int issue_ioctl(adap_handle_t, void *, size_t);
const char *csio_ipv6_ntop(void *, char *, int);
int csio_ipv6_pton(char *, void *);
void csio_heap_sort(void *, size_t, size_t,int (*)(const void *, const void *),
		    void (*)(void *, void *,int));

#ifdef __cplusplus
}
#endif

#endif /* __CSIO_SERVICES_H__ */
