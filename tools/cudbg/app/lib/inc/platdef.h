#ifndef _PLATDEF_H_
#define _PLATDEF_H_
#define true 1
#define false 0

#define __force

#ifdef __CHECKER__
#define __bitwise__ __attribute__((bitwise))
#else
#define __bitwise__
#endif
#ifdef __CHECK_ENDIAN__
#define __bitwise __bitwise__
#else
#define __bitwise
#endif

typedef unsigned int u32, uint32_t, __u32;
typedef unsigned long long  u64, __u64;
typedef unsigned char u8, uint8_t, __u8;
typedef unsigned short u16, uint16_t, __u16;

#if defined(WIN32) || defined(__NT__) || defined(_WIN32) || defined(__WIN32__)
#if defined(_MSC_VER) || defined(__GNUC__)

#endif
#define __func__ __FUNCTION__
#else
typedef unsigned char s8;
typedef unsigned short bool, s16;
typedef unsigned long   uintptr_t;

#endif

typedef __u16 __bitwise __le16;
typedef __u16 __bitwise __be16;
typedef __u32 __bitwise __le32;
typedef __u32 __bitwise __be32;
#if defined(__GNUC__)
typedef __u64 __bitwise __le64;
typedef __u64 __bitwise __be64;
#endif

#endif /* _PLATDEF_H_ */

