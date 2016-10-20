#ifndef __ISCSI_SOCKET_API_H__
#define __ISCSI_SOCKET_API_H__

/*
 * iscsi connection socket-based operation
 */

#include <iscsi_structs.h>

iscsi_connection *iscsi_connection_listen(struct tcp_endpoint *);
int	iscsi_connection_accept(iscsi_connection *, iscsi_connection **);
void	iscsi_socket_close(iscsi_socket *, int rst);
void	iscsi_socket_destroy(iscsi_socket *);

int     iscsi_connection_write_pdu(iscsi_connection *);
int     iscsi_connection_adjust_offload_mode(iscsi_connection *);

#endif /* ifndef __ISCSI_SOCKET_API_H__ */
