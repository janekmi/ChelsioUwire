#include <sys/mman.h>
#include "debug.h"
#include "mmap.h"

void *wdtoe_mmap(int len, int fd, int offset)
{
	return mmap(0, len, PROT_WRITE, MAP_SHARED, fd, offset);
}

void wdtoe_munmap(void *addr, size_t length)
{
	int ret;

	ret = munmap(addr, length);
	if (ret == -1)
		DBG(DBG_RES_ALLOC, "munmap failed for addr %p\n", addr);
}
