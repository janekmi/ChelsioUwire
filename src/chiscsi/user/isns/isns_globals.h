#ifndef __ISNS_GLOBAL_H__
#define __ISNS_GLOBAL_H__

#include "isns_sock.h"

extern char i_eid[];
extern char t_eid[];
extern pid_t self_pid;
extern int poll_period;
extern int keep_running;

extern isns_sock main_sock;
extern isns_sock main_lsock;

extern u_int16_t transaction_id;

extern char iscsictl_buffer[];	/* for iscsictl */

#endif /* ifndef __ISNS_GLOBAL_H__ */
