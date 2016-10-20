#ifndef __ISCSI_MASK_H__
#define __ISCSI_MASK_H__

/*
 * unsigned long bit mask
 */

#define iscsi_mask_bit_set(dp,pos)	\
	do { \
		if ((pos) < iscsi_ulong_mask_bits) { \
			*dp |= 1UL << (pos); \
		} else { \
			dp[(pos)>>iscsi_ulong_mask_shift] |= 1 << ((pos)&iscsi_ulong_mask_max); \
		} \
	} while (0);

#define iscsi_mask_bit_clear(dp,pos)	\
	do { \
		if ((pos) < iscsi_ulong_mask_bits) { \
			*dp &= ~(1UL << (pos)); \
		} else { \
			dp[(pos)>>iscsi_ulong_mask_shift] &= ~(1UL << ((pos)&iscsi_ulong_mask_max)); \
		} \
	} while (0);

static inline int iscsi_mask_bit_test(unsigned long *dp, unsigned int pos)
{
	return (dp[pos >> iscsi_ulong_mask_shift] & (1UL << (pos & iscsi_ulong_mask_max)));
}

#endif /* ifndef __ISCSI_MASK_H__ */
