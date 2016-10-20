#ifndef __OS_BUILTIN_H__
#define __OS_BUILTIN_H__

#include <common/iscsi_common.h>
#include <common/os_export.h>
#include <linux/string.h>
/*
 * basic functions defines/declarations
 */

#ifndef NULL
#define NULL	((void *)0)
#endif

#define os_isdigit(c)	((c) >= '0' && (c) <= '9')
#define os_isxdigit(c)  ((((c) >= '0') && ((c) <= '9')) || (((c) >= 'A') && ((c) <= 'F')) || (((c) >= 'a') && ((c) <= 'f')))
#define os_isspace(c)	((c) == ' ')

#define os_isupper(c)	((c) >= 'A' && (c) <= 'Z')
#define os_islower(c)	((c) >= 'a' && (c) <= 'z')

#ifndef __KERNEL__
extern int sprintf(char *str, const char *format, ...)
	__attribute__ ((format (printf, 2, 3)));
extern int snprintf(char * buf, int size, const char * fmt, ...)
        __attribute__ ((format (printf, 3, 4)));
#endif

static inline void os_str2upper(char *s)
{
	for(; *s; s++)
		if(('a' <= *s) && (*s <= 'z'))
			*s = 'A' + (*s - 'a');
}
 
static inline void os_str2lower(char *s)
{
	for(; *s; s++)
		if(('A' <= *s) && (*s <= 'Z'))
			*s = 'a' + (*s - 'A');
}

static inline unsigned int os_strlen(const char *s)
{
	const char *sc;
	if (!s)
		return 0;
	for (sc = s; *sc; ++sc) ;
	return sc - s;
}

static inline char *os_strcpy(char *dest, const char *src)
{
	char   *tmp = dest;
	while ((*dest++ = *src++) != '\0') ;
	return tmp;
}

static inline char *os_strncpy(char *dest, const char *src, unsigned int count)
{
	char   *tmp = dest;
	while (count) {
		if ((*tmp = *src) != '\0')
			src++;
		tmp++;
		count--;
	}
	return dest;
}

static inline char *os_strdup(const char *src)
{
	int     len = os_strlen(src);
	char   *dest, *tmp;

	if (!len)
		return NULL;
	len++;
	dest = os_alloc(len, 1, 1);
	if (!dest)
		return NULL;

	tmp = dest;
	while ((*tmp++ = *src++) != '\0') ;
	return dest;
}

static inline int os_strcmp(const char *cs, const char *ct)
{
	signed char __res;

	if (!cs & !ct)
		return 0;
	if (!cs)
		return -1;
	if (!ct)
		return 1;

	while (1) {
		if ((__res = *cs - *ct++) != 0 || !*cs++)
			break;
	}
	return __res;
}

static inline int os_strncmp(const char *cs, const char *ct, unsigned int count)
{
	signed char __res = 0;

	if (!cs & !ct)
		return 0;
	if (!cs)
		return -1;
	if (!ct)
		return 1;

	while (count) {
		if ((__res = *cs - *ct++) != 0 || !*cs++)
			break;
		count--;
	}
	return __res;
}

static inline int os_strcasecmp(const char *s1, const char *s2)
{
	os_str2lower((char *)s1);
	os_str2lower((char *)s2);
	return os_strcmp(s1, s2);
}

static inline char *os_strchr(const char *s, int c)
{
	if (!s)
		return NULL;
	for (; *s != (char) c; ++s)
		if (*s == '\0')
			return NULL;
	return (char *) s;
}

static inline char *os_strstr(const char *s1, const char *s2)
{
	int     l1, l2;

	if (!s1)
		return NULL;
	if (!s2)
		return (char *) s1;

	l2 = os_strlen(s2);
	if (!l2)
		return (char *) s1;

	l1 = os_strlen(s1);
	while (l1 >= l2) {
		l1--;
		if (!memcmp(s1, s2, l2))
			return (char *) s1;
		s1++;
	}
	return NULL;
}

static inline char *os_strstrbet(const char *s1, const char *s2,const char *s3)
{
        int     l1, l2, l3;

        if (!s1)
                return NULL;
        if (!s2)
                return os_strstr(s1,s3);
        if (!s3)
                return (char *) s1;

        l3 = os_strlen(s3);
        if (!l3)
                return (char *) s1;

	l2 = os_strlen(s2);
	l1 = os_strlen(s1);
	if(l2 >= l1)
		return NULL;

        l1 -= l2;
        while (l1 >= l3) {
                l1--;
                if (!memcmp(s1, s3, l3))
                        return (char *) s1;
                s1++;
        }
        return NULL;
}

static inline char *os_strcat(char *dest, const char *src)
{
    os_strcpy(dest + os_strlen(dest), src);
    return dest;
}
#endif /* ifndef __OS_BUILTIN_H__ */
