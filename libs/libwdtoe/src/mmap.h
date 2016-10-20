#ifndef __LIBWDTOE_MMAP_H__
#define __LIBWDTOE_MMAP_H__

void *wdtoe_mmap(int len, int fd, int offset);
void wdtoe_munmap(void *addr, size_t length);
#endif
