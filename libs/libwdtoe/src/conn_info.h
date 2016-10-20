#ifndef __LIBWDTOE_CONN_INFO_H__
#define __LIBWDTOE_CONN_INFO_H__

#include <sys/types.h>
#include "common.h"
#include "ntuples.h"
#include "device.h"

inline int passive_tuple_get_peer_info(struct passive_tuple *, unsigned int,
				       unsigned int, __u32 *, __u16 *);
inline int conn_tuple_get_lport(struct conn_tuple *, unsigned int);
inline int conn_info_get_free_ntuple(struct wdtoe_conn_info *);
inline int conn_info_remove_sockfd_entry(struct wdtoe_conn_info *, int);
inline void conn_info_free_entry(struct wdtoe_conn_info *, int tid);
inline int conn_info_insert_cpl_tuple(struct wdtoe_conn_info *, unsigned int,
				      unsigned int, unsigned int, unsigned int,
				      __u32, __u16, int);
inline int conn_info_insert_sockfd_passive(struct wdtoe_conn_info *, __u32,
					   __u16, unsigned int, int *, int *);
inline int get_free_entry_from_priv_conn_info(struct wdtoe_conn_info *, int *);
inline int conn_info_insert_sockfd_active(struct wdtoe_conn_info *,
					  unsigned int, unsigned int, int *, int *);
inline int conn_info_copy_entry(struct wdtoe_conn_info *,
				struct wdtoe_conn_info *, int);
inline int conn_info_insert_info(struct wdtoe_conn_info *, unsigned int, int,
				 int, unsigned int);
void debug_k_passive_tuples(void);
void debug_print_conn_info(struct wdtoe_conn_info *);
inline int set_tid_state(struct wdtoe_conn_info *, unsigned int,
			 enum wdtoe_tcp_states);
inline int set_tid_state(struct wdtoe_conn_info *, unsigned int,
			 enum wdtoe_tcp_states);
inline int get_tid_tcp_state(struct wdtoe_conn_info *, int);
inline void conn_info_remove_tid_entry(struct wdtoe_conn_info *, int);
inline int get_idx_from_tid(struct wdtoe_conn_info *, int);
inline int get_idx_from_sockfd(struct wdtoe_conn_info *, int);
inline int conn_info_get_tid(struct wdtoe_conn_info *, int, int *, int *);
inline int conn_info_get_idx(struct wdtoe_conn_info *, int, int *);
inline int conn_info_get_idx_from_tid(struct wdtoe_conn_info *, unsigned int,
				      int *);
inline int check_sockfd_peer_closed(struct wdtoe_conn_info *, int);
inline int check_tid_peer_closed(struct wdtoe_conn_info *, int);
void insert_listen_svr(struct wdtoe_listsvr *, int, __u16);
int remove_listen_svr(struct wdtoe_listsvr *, int , __u16 *);
int decre_listen_svr(struct wdtoe_listsvr *, int fd, __u16);
struct wdtoe_conn_info *alloc_conn_info(size_t entries);
int init_conn_info(struct wdtoe_conn_info *wci, size_t entries);
struct wdtoe_listsvr *alloc_listsvr(size_t entries);
int init_listsvr(struct wdtoe_listsvr *lsvr, size_t entries);
#endif
