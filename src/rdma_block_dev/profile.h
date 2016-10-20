/*
 * Copyright (c) 2015 Chelsio Communications, Inc. All rights reserved.
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
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
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
#ifndef __PROFILE_H__
#define __PROFILE_H__

#include <linux/time.h>
#include <linux/debugfs.h>

#define SAMPLES 16384
#define SKIP 8192

enum {
	TGT_POLL_RCQ,
	TGT_REQUEST,
	TGT_BACKEND,
	TGT_WRITE,
	TGT_REPLY,
	INI_REQUEST,
	INI_MAP,
	INI_SEND,
	INI_POLL_RCQ,
	INI_REPLY,
	LAST,
};

extern void myprofile_init(struct dentry *root);

#ifdef PROFILE

extern unsigned int prof_calls[LAST];
extern unsigned int prof_sample_idx[LAST];
extern struct timespec ts_func_enter[LAST][SAMPLES+1];
extern struct timespec ts_func_exit[LAST][SAMPLES+1];

#define PENTER(_x) \
do { \
	prof_calls[_x]++; \
	if (prof_sample_idx[_x] < SAMPLES) { \
		prof_sample_idx[_x]++; \
		getnstimeofday(&ts_func_enter[_x][prof_sample_idx[_x]]); \
	} \
} while(0)

#define PRESET(_x) \
do { \
	prof_calls[_x]--; \
	prof_sample_idx[_x]--; \
} while(0)

#define PEXIT(_x) \
do { \
	if (prof_sample_idx[_x] <= SAMPLES) { \
		getnstimeofday(&ts_func_exit[_x][prof_sample_idx[_x]]); \
	} \
} while(0)

#define PINIT(X) myprofile_init(X)

#else
#define PENTER(x)
#define PEXIT(x)
#define PRESET(X)
#define PINIT(X)
#endif

#endif /* __PROFILE_H__ */
