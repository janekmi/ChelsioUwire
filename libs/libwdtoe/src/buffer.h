#ifndef __LIBWDTOE_CREDITS_H__
#define __LIBWDTOE_CREDITS_H__

#include "device.h"

inline void *next_buffer(struct sw_t4_txq *q);
inline int sw_txq_next_pidx(struct sw_t4_txq *q, int cur_pidx);
inline void finish_buffer(struct sw_t4_txq *q, size_t copied);
inline void credit_enqueue(int idx, struct sw_cred_q_entry cdqe);
inline void credit_dequeue(int idx, int credits);
int get_new_buf(struct wdtoe_device *dev);
#endif
