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
 *    csio_services.c -  contains the Linux OS specific User-level service
 *			 calls/APIs.
 *
 * Environment:
 *
 *
 *****************************************************************************/

#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <csio_services.h>

adap_handle_t
open_adapter(int8_t adapter_no)
{
	adap_handle_t handle ;
	char devfile[32];

	sprintf(devfile, "/dev/%s%u", CSIO_CDEVFILE, adapter_no);

	handle = open(devfile, O_RDWR);
	if (handle < 0)
		return (adap_handle_t)-1;

	return handle;
} 

adap_handle_t
open_adapter_str(char *adapter_str)
{
	adap_handle_t handle;

	handle = open(adapter_str, O_RDWR);
	if (handle < 0)
		return (adap_handle_t)-1;

	return handle;
} 

void
close_adapter (adap_handle_t adapter)
{
	close(adapter);
} 

file_handle_t
open_file(char *file_name)
{
	file_handle_t fd = open(file_name, O_RDWR);
	if (fd < 0)
		return (file_handle_t)-1;

	return fd;
}

int
write_file(file_handle_t file, void *buffer, size_t size, uint32_t *offset)
{
	int count = write(file, buffer, size);
	if (count < 0)
		return -1;

	*offset += (uint32_t)count;

	return 0;
}

void
close_file(file_handle_t file)
{
	close(file);
}

void
ioctl_buffer_free(void *buffer)
{
	free(buffer);
} 

int
issue_ioctl(adap_handle_t fd, void *buffer, size_t len)
{
	int status = 0;
	ioctl_hdr_t *hdr = (ioctl_hdr_t *)buffer;

	errno = 0;
	status = ioctl(fd, hdr->cmd, buffer);
	if (status < 0)
		return -errno;

	return 0;
} 

void *
ioctl_buffer_alloc(size_t len, char signature[8])
{
	void *buf = malloc(len);
	if (buf != NULL)
		memset(buf, 0, len);

	return buf;
} 

const char *
csio_ipv6_ntop(void *src, char *dst, int size)
{
	return inet_ntop(AF_INET6, src, dst, size);
}

int
csio_ipv6_pton(char *src, void *dst)
{
	return inet_pton(AF_INET6, src, dst);
}

static void
u32_swap(void *a, void *b, int size)
{
        uint32_t t	= *(uint32_t *)a;
        *(uint32_t *)a	= *(uint32_t *)b;
        *(uint32_t *)b	= t;

	UNREFERENCED_PARAMETER(size);

        return;

} 

static void
generic_swap(void *a1, void *b1, int size)
{
        uint8_t temp = 0;
        uint8_t *a = a1, *b = b1;

        do {
		temp = *a;
		*(a++) = *b;
		*(b++) = temp;

        } while (--size > 0);

        return;
} 

void
csio_heap_sort(void *base, size_t num, size_t size,
		int (*cmp_func)(const void *, const void *),
		void (*swap_func)(void *, void *, int size))
{
	// pre-scale counters for performance //
	int i = (int)((num/2 - 1) * size);
	int n = (int)(num * size);
	int c = 0, r = 0;
	uintptr_t base_val = (uintptr_t)base;

	if (!swap_func) {
		swap_func = (size == 4 ? u32_swap : generic_swap);
	}

	for ( ; i >= 0; i -= (int)size) {
		for (r = i; (r * 2 + (int)size) < n; r  = c) {
			c = r * 2 + (int)size;

			if (c < n - (int)size &&
				cmp_func((void *)(base_val + c), 
					(void *)(base_val + c + (int)size)) < 0)
				c += (int)size;

			if (cmp_func((void *)(base_val + r),
						(void *)(base_val + c)) >= 0)
				break;

			swap_func((void *)(base_val + r),
					(void *)(base_val + c), (int)size);
		}
	}

	for (i = n - (int)size; i > 0; i -= (int)size) {
		swap_func((void *)(base_val), 
				(void *)(base_val + i), (int)size);

		for (r = 0; r * 2 + (int)size < i; r = c) {
			c = r * 2 + (int)size;

			if (c < (i - (int)size) &&
				cmp_func((void *)(base_val + c), 
					(void *)(base_val + c + (int)size)) < 0)
				c += (int)size;

			if (cmp_func((void *)(base_val + r), 
						(void *)(base_val + c)) >= 0)
				break;

			swap_func((void *)(base_val + r),
					(void *)(base_val + c), (int)size);
		}
	}

	return;
}
