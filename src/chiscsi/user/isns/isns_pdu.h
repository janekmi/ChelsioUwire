#ifndef __ISNS_PDU_H__
#define __ISNS_PDU_H__

#include "isns_pdu_defs.h"
#include "isns_sock.h"

void    isns_pdu_write_hdr(char *, u_int16_t, u_int16_t, u_int16_t, u_int16_t);
void    isns_pdu_write_attr(char *, u_int32_t, u_int32_t, char *, u_int32_t);
void    isns_pdu_write_attr_ip(char *, u_int32_t *, u_int32_t, u_int32_t);

int     isns_pdu_send(isns_sock *, char *, int);
int     isns_pdu_recv(isns_sock *, char *, int);
int     isns_pdu_send_n_recv(isns_sock *, char *, int);

#endif /* ifndef __ISNS_PDU_H__ */
