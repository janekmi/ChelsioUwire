/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <linux/skbuff.h>

const unsigned long os_skbcb_offset = offsetof(struct sk_buff, cb);
const unsigned long os_sk_buff_head_size = sizeof(struct sk_buff_head);

/*sk_buff operations*/
void *chfcoe_fcb_alloc(unsigned int len)
{
	struct sk_buff *skb = NULL;

	skb = alloc_skb_fclone(len + NET_SKB_PAD, GFP_KERNEL);
	return (void *)skb;
}

void *chfcoe_fcb_alloc_atomic(unsigned int len)
{
	struct sk_buff *skb = NULL;

	skb = alloc_skb_fclone(len + NET_SKB_PAD, GFP_ATOMIC);
	return (void *)skb;
}

void chfcoe_fcb_reserve(void *skb, int len)
{
	skb_reserve((struct sk_buff *)skb, NET_SKB_PAD + len);
}

unsigned char *chfcoe_fcb_put(void *skb, unsigned int len)
{
	return skb_put((struct sk_buff *)skb, len);
}

void chfcoe_fcb_trim(void *skb, unsigned int len)
{
	skb_trim((struct sk_buff *)skb, len);
}

void chfcoe_fcb_free(void *skb)
{
	kfree_skb((struct sk_buff *)skb);
}

unsigned char *chfcoe_fcb_push(void *skb, unsigned int len)
{
	return skb_push((struct sk_buff *)skb, len);
}

unsigned char *chfcoe_fcb_pull(void *skb, unsigned int len)
{
	return skb_pull((struct sk_buff *)skb, len);
}

unsigned char *chfcoe_skb_data(void *skb)
{
	return ((struct sk_buff *)skb)->data;
}

unsigned int chfcoe_skb_len(void *skb)
{
	return ((struct sk_buff *)skb)->len;
}

void chfcoe_skb_dtr(void *skb, void *dtr)
{
	((struct sk_buff *)skb)->destructor = dtr;
}

/* skb queue */
void chfcoe_skb_queue_head_init(void *skb_list)
{
	skb_queue_head_init((struct sk_buff_head *)skb_list);
}

unsigned int chfcoe_skb_queue_len(void *skb_list)
{
	return skb_queue_len((struct sk_buff_head *)skb_list); 
}

void chfcoe_skb_queue_purge(void *skb_list)
{
	skb_queue_purge((struct sk_buff_head *)skb_list);
}

void chfcoe_skb_queue_splice_init(void *skb_list, void *head)
{
	skb_queue_splice_init((struct sk_buff_head *)skb_list,
			((struct sk_buff_head *)head));
}

void *chfcoe_sk_buff_head_lock(void *skb_list)
{
	return ((void *)&(((struct sk_buff_head *)skb_list)->lock));
}

void chfcoe_skb_queue_tail(void *skb_list, void *skb)
{
	skb_queue_tail((struct sk_buff_head *)skb_list, (struct sk_buff *)skb);
}

void __chfcoe_skb_queue_tail(void *skb_list, void *skb)
{
	__skb_queue_tail((struct sk_buff_head *)skb_list, (struct sk_buff *)skb);
}

void *chfcoe_skb_dequeue(void *skb_list)
{
	struct sk_buff *skb = NULL;

	skb = skb_dequeue((struct sk_buff_head *)skb_list);
	return (void *)skb;
}

void *__chfcoe_skb_dequeue(void *skb_list)
{
	struct sk_buff *skb = NULL;

	skb = __skb_dequeue((struct sk_buff_head *)skb_list);
	return (void *)skb;
}
