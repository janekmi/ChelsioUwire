/*
 * Copyright (C) 2003-2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __IW_CXGB4_COMPAT_H
#define __IW_CXGB4_COMPAT_H

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
static inline void t4_tcp_parse_options(struct sk_buff *skb,
					struct tcp_options_received *opt_rx,
					u8 **hvpp, int estab)
{
	tcp_parse_options(skb, opt_rx, estab);
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
static inline void t4_tcp_parse_options(const struct sk_buff *skb,
					struct tcp_options_received *opt_rx,
					u8 **hvpp, int estab)
{
	tcp_parse_options(skb, opt_rx, (const u8 **)hvpp, estab);
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static inline void t4_tcp_parse_options(const struct sk_buff *skb,
					struct tcp_options_received *opt_rx,
					u8 **hvpp, int estab)
{
	tcp_parse_options(skb, opt_rx, (const u8 **)hvpp, estab, NULL);
}
#else
static inline void t4_tcp_parse_options(const struct sk_buff *skb,
					struct tcp_options_received *opt_rx,
					u8 **hvpp, int estab)
{
	tcp_parse_options(skb, opt_rx, estab, NULL);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
extern const __u8 ip_tos2prio[16];
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
#define net_random()            prandom_u32()
#endif

#endif /* __IW__CXGB4_COMPAT_H */
