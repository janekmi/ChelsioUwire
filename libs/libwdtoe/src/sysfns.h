#ifndef __LIBWDTOE_SYSFNS_H__
#define __LIBWDTOE_SYSFNS_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <stddef.h>
#include <unistd.h>
#include <poll.h>

int (*sys_socket)(int, int, int);
int (*sys_listen)(int, int);
int (*sys_connect)(int, const struct sockaddr *, socklen_t);
int (*sys_accept)(int, struct sockaddr *, socklen_t *);
ssize_t (*sys_write)(int, const void *, size_t);
ssize_t (*sys_writev)(int, const struct iovec *, int);
ssize_t (*sys_send)(int, const void *, size_t, int);
ssize_t (*sys_sendto)(int, const void *, size_t, int,
		      const struct sockaddr *, socklen_t);
ssize_t (*sys_sendmsg)(int, const struct msghdr *, int);
ssize_t (*sys_read)(int, void *, size_t);
ssize_t (*sys_readv)(int, const struct iovec *, int);
ssize_t (*sys_recv)(int, void *, size_t, int);
ssize_t (*sys_recvfrom)(int, void *, size_t, int,
			struct sockaddr *, socklen_t *);
ssize_t (*sys_recvmsg)(int, struct msghdr *, int);
int (*sys_select)(int, fd_set *, fd_set *, fd_set *, struct timeval *);
int (*sys_poll)(struct pollfd *, nfds_t, int);
int (*sys_close)(int);
int (*sys_shutdown)(int, int);
int (*sys_fcntl)(int fd, int cmd, ... /* arg */ );
#endif
