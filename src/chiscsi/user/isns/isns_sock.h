#ifndef __ISNS_SOCK_H__
#define __ISNS_SOCK_H__

#include <pthread.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef struct isns_sock isns_sock;
struct isns_sock {
	pthread_t thread;
	int     fd;
	unsigned int sip[4];
	unsigned int sport;
	unsigned int dip[4];
	unsigned int dport;
};

#define isns_sock_init(p)	\
		do { \
			memset(p, 0, sizeof(isns_sock));	\
			(p)->fd = -1; \
		} while (0)

int     isns_sock_listen(isns_sock *);
int     isns_sock_accept(isns_sock *, isns_sock *);
int     isns_sock_connect(isns_sock *);
int     isns_sock_close(isns_sock *);

#endif /* ifndef __ISNS_SOCK_H__ */
