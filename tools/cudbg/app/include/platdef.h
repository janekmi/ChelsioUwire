#ifndef _PLATDEF_H_
#define _PLATDEF_H_
#define true 1
#define false 0

typedef unsigned int u32, __be32, uint32_t, __u32;
#ifdef _ASM_GENERIC_INT_L64_H
typedef unsigned long long  u64;
#else
typedef unsigned long long u64, __be64, __u64;
#endif
typedef unsigned char u8, uint8_t, __u8, s8;
typedef unsigned short u16, __be16, uint16_t, bool, __u16, s16;

#endif /* _PLATDEF_H_ */

