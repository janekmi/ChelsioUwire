#include <linux/spinlock.h>	/* required by genalloc */
#ifdef GEN_ALLOC
#include <linux/genalloc.h>
#else
#include "cxgb4_genalloc.h"
#endif
#include <linux/module.h>
#include "ocqp.h"

#define MIN_OCQP_SHIFT 12	/* 4KB == min ocqp size */

u32 cxgb4_ocqp_pool_alloc(struct net_device *dev, int size)
{
	unsigned long addr = 0;
	struct adapter *adap = netdev2adap(dev);
	if (adap->ocqp_pool)
		addr = gen_pool_alloc(adap->ocqp_pool, size);

	return (u32)addr;
}
EXPORT_SYMBOL(cxgb4_ocqp_pool_alloc);

int ocqp_pool_create(struct adapter *adap)
{
	unsigned start, chunk, top;

	adap->ocqp_pool = gen_pool_create(MIN_OCQP_SHIFT, -1);
	if (!adap->ocqp_pool)
		return -ENOMEM;

	start = adap->vres.ocq.start;
	chunk = adap->vres.ocq.size;
	top = start + chunk;

	while (start < top) {
		chunk = min(top - start + 1, chunk);
		if (gen_pool_add(adap->ocqp_pool, start, chunk, -1)) {
			if (chunk <= 1024 << MIN_OCQP_SHIFT) {
				return 0;
			}
			chunk >>= 1;
		} else {
			start += chunk;
		}
	}

	return 0;
}

void ocqp_pool_destroy(struct adapter *adap)
{
	if (adap->ocqp_pool)
		gen_pool_destroy(adap->ocqp_pool);
}

void cxgb4_ocqp_pool_free(struct net_device *dev, u32 addr, int size)
{
	struct adapter *adap = netdev2adap(dev);
	if (adap->ocqp_pool)
		gen_pool_free(adap->ocqp_pool, (unsigned long)addr, size);
}
EXPORT_SYMBOL(cxgb4_ocqp_pool_free);
