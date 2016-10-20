#ifndef __ISNS_UTILS_H__
#define __ISNS_UTILS_H__

int     isns_entity_deregister(isns_sock *, char *);
int     isns_scn_register(isns_sock *, char *);
int     isns_scn_deregister(isns_sock *, char *);
int     isns_query_peers(isns_sock *, char *, u_int32_t, char *, int);

#endif /* ifndef __ISNS_UTILS_H__ */
