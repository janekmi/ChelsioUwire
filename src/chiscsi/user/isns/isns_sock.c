/* 
 * isns socket functions
 */

#include "isns.h"
#include "isns_sock.h"
#include "isns_globals.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

int isns_sock_connect(isns_sock * sock)
{
	int     rv;
	struct sockaddr_in6 addr;
	unsigned int addr_len = sizeof(addr);
	int     val = 1;
	int 	i;
	char 	*ip6;

	sock->fd = -1;

	rv = socket(AF_INET6, SOCK_STREAM, 0);
	if (rv < 0) {
		perror("socket");
		return rv;
	}
	sock->fd = rv;

	addr.sin6_family = AF_INET6;
	for (i=0;i<4;i++)
		addr.sin6_addr.s6_addr32[i] = sock->dip[i];
//	addr.sin_addr.s_addr = sock->dip;
	addr.sin6_port = htons(sock->dport);

	rv = connect(sock->fd, (struct sockaddr *) &addr, addr_len);
	if (rv < 0) {
		perror("connect");
		goto err_out;
	}

	rv = getsockname(sock->fd, (struct sockaddr *) &addr, &addr_len);
	if (rv < 0) {
		perror("getsockname");
		goto err_out;
	}

	rv = setsockopt(sock->fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
	if (rv) {
		perror("setsockopt");
		goto err_out;
	}

	sock->sport = ntohs(addr.sin6_port);
	ip6 = malloc(sizeof(char) * INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &(addr.sin6_addr), ip6, INET6_ADDRSTRLEN);
	inet_pton(AF_INET6, ip6, sock->sip);
	free(ip6);

	if(addr.sin6_addr.s6_addr32[0])
	        isns_log_msg("connect " FORMAT_IPV6_PORT " -- " FORMAT_IPV6_PORT ".\n",
	                     ADDR_IPV6(sock->sip), sock->sport,
        	             ADDR_IPV6(sock->dip), sock->dport);
	else	isns_log_msg("connect " FORMAT_IPV4_PORT " -- " FORMAT_IPV4_PORT ".\n",
			     ADDR_IPV4(sock->sip[3]), sock->sport,
			     ADDR_IPV4(sock->dip[3]), sock->dport);

      err_out:
	if ((rv < 0) && (sock->fd >= 0)) {
		close(sock->fd);
		sock->fd = -1;
	}
	return rv;
}

int isns_sock_listen(isns_sock * sock)
{
	int     rv;
	struct sockaddr_in6 addr;
	unsigned int addr_len = sizeof(addr);

	sock->fd = -1;

	rv = socket(AF_INET6, SOCK_STREAM, 0);
	if (rv < 0) {
		perror("socket");
		return rv;
	}
	sock->fd = rv;

	addr.sin6_family = AF_INET6;
	addr.sin6_addr = in6addr_any;
	addr.sin6_port = htons(0);

	rv = bind(sock->fd, (struct sockaddr *) &addr, addr_len);
	if (rv < 0) {
		perror("bind");
		goto err_out;
	}

	rv = getsockname(sock->fd, (struct sockaddr *) &addr, &addr_len);
	if (rv < 0) {
		perror("getsockname");
		goto err_out;
	}

	sock->sport = ntohs(addr.sin6_port);
	rv = listen(sock->fd, 1);

	if(!addr.sin6_addr.s6_addr32[0])
		isns_log_msg("listen at " FORMAT_IPV4_PORT ".\n",
			     ADDR_IPV4(sock->sip[3]), sock->sport);
	else	isns_log_msg("listen at " FORMAT_IPV6_PORT ".\n",
                             ADDR_IPV6(sock->sip), sock->sport);

      err_out:
	if ((rv < 0) && (sock->fd >= 0)) {
		close(sock->fd);
		sock->fd = -1;
	}
	return rv;
}

int isns_sock_accept(isns_sock * lsock, isns_sock * sock)
{
	int     rv;
	struct sockaddr_in6 from;
	unsigned int fromlen = sizeof(from);
	int     val = 1;

	sock->fd = -1;

	rv = accept(lsock->fd, (struct sockaddr *) &from, &fromlen);
	if (rv < 0) {
		perror("accept");
		return rv;
	}
	sock->fd = rv;

	rv = setsockopt(sock->fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
	if (rv) {
		perror("setsockopt");
		goto err_out;
	}

	rv = getpeername(sock->fd, (struct sockaddr *) &from, &fromlen);
	if (rv < 0) {
		perror("getpeername");
		goto err_out;
	}
	memcpy(sock->sip, &from.sin6_addr, sizeof(unsigned int) * 4);
	sock->sport = ntohs(from.sin6_port);

	if(!sock->sip[0])
		isns_log_msg("accepted from " FORMAT_IPV4_PORT ".\n",
			     ADDR_IPV4(sock->sip[3]), sock->sport);
	else	isns_log_msg("accepted from " FORMAT_IPV6_PORT ".\n",
                             ADDR_IPV6(sock->sip), sock->sport);

      err_out:
	if ((rv < 0) && (sock->fd >= 0)) {
		close(sock->fd);
		sock->fd = -1;
	}
	return rv;
}

int isns_sock_close(isns_sock * sock)
{
	if (sock->fd >= 0) {
		close(sock->fd);
		sock->fd = -1;
	}
	return 0;
}
