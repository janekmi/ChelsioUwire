#ifndef __ISNS_TARGET_H__
#define __ISNS_TARGET_H__

#include "isns_sock.h"

int     isns_target_init(void);
int     isns_target_cleanup(isns_sock *);
int     isns_target_client(isns_sock *, int, int);

#endif /* ifndef __ISNS_TARGET_H__ */
