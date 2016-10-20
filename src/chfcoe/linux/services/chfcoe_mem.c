/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <linux/slab.h>

/*Memory Allocation*/
void *chfcoe_mem_alloc(unsigned long size)
{
	return kzalloc(size, GFP_KERNEL);
}

void *chfcoe_mem_alloc_atomic(unsigned long size)
{
	return kzalloc(size, GFP_ATOMIC);
}

void *chfcoe_mem_alloc_node(unsigned long size, int node)
{
	return kzalloc_node(size, GFP_KERNEL, node);
}

void chfcoe_mem_free(void *p)
{
	kfree(p);
}


/*Slab*/
void *chfcoe_cache_create(const char *name, unsigned long size)
{
#if defined(__CHFCOE_DEBUG_SLAB__) && defined(CONFIG_DEBUG_SLAB)
	printk(KERN_INFO "chfcoe: DEBUG SLAB enabled\n");
	return kmem_cache_create(name, size, 0, SLAB_RED_ZONE|SLAB_POISON, NULL);
#else
	return kmem_cache_create(name, size, 0, 0, NULL);
#endif
}

void chfcoe_cache_destroy(void *cache)
{
	kmem_cache_destroy((struct kmem_cache *)cache);
}

void *chfcoe_cache_zalloc_atomic(void *cache)
{
	return kmem_cache_zalloc((struct kmem_cache *)cache, GFP_ATOMIC);
}

void chfcoe_cache_free(void *cache, void *p)
{
	kmem_cache_free((struct kmem_cache *)cache, p);
}
