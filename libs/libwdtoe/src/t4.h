#ifndef __LIBWDTOE_T4_H__
#define __LIBWDTOE_T4_H__

#include <assert.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <stdint.h>
#include <endian.h>
#include <byteswap.h>
#include <errno.h>
#include "atomic.h"

#include "t4fw_interface.h"

#define __u8 uint8_t
#define u8 uint8_t
#define __u16 uint16_t
#define __be16 uint16_t
#define u16 uint16_t
#define __u32 uint32_t
#define __be32 uint32_t
#define u32 uint32_t
#define __u64 uint64_t
#define __be64 uint64_t
#define u64 uint64_t

#if defined(RSS_HDR_VLD) || defined(CHELSIO_FW)
# define RSS_HDR struct rss_header rss_hdr;
#else
# define RSS_HDR
#endif

#define cpu_to_be16 htons
#define cpu_to_be32 htonl
#define cpu_to_be64 htonll
#define be16_to_cpu ntohs
#define be32_to_cpu ntohl
#define be64_to_cpu ntohll

#if __BYTE_ORDER == __LITTLE_ENDIAN
#  define cpu_to_pci32(val) ((val))
#elif __BYTE_ORDER == __BIG_ENDIAN
#  define cpu_to_pci32(val) (__bswap_32((val)))
#else
#  error __BYTE_ORDER not defined
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t htonll(uint64_t x) { return bswap_64(x); }
static inline uint64_t ntohll(uint64_t x) { return bswap_64(x); }
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline uint64_t htonll(uint64_t x) { return x; }
static inline uint64_t ntohll(uint64_t x) { return x; }
#else
#error __BYTE_ORDER is neither __LITTLE_ENDIAN nor __BIG_ENDIAN
#endif


#include "t4_regs.h"
#include "t4_msg.h"


/* macros for flit 6 of the iqe */
#define S_IQE_HDRNEW	63
#define M_IQE_HDRNEW	0x1
#define G_IQE_HDRNEW(x) (((x) >> S_IQE_HDRNEW) & M_IQE_HDRNEW)

#define S_IQE_HDRDMALEN		32
#define M_IQE_HDRDMALEN 	0x7fffffff
#define G_IQE_HDRDMALEN(x)	(((x) >> S_IQE_HDRDMALEN) & M_IQE_HDRDMALEN)

#define S_IQE_DATANEW		31
#define M_IQE_DATANEW		0x1
#define G_IQE_DATANEW(x)	(((x) >> S_IQE_DATANEW) & M_IQE_DATANEW)

#define S_IQE_DATADMALEN	0
#define M_IQE_DATADMALEN	0x7fffffff
#define G_IQE_DATADMALEN(x)	(((x) >> S_IQE_DATADMALEN) & M_IQE_DATADMALEN)

#define IQE_HDRNEW(x)		((unsigned)G_IQE_HDRNEW(be64_to_cpu((x)->newbuf_dma_len)))
#define IQE_HDRDMALEN(x)	((unsigned)G_IQE_HDRDMALEN(be64_to_cpu((x)->newbuf_dma_len)))
#define IQE_DATANEW(x)		((unsigned)G_IQE_DATANEW(be64_to_cpu((x)->newbuf_dma_len)))
#define IQE_DATADMALEN(x)	((unsigned)G_IQE_DATADMALEN(be64_to_cpu((x)->newbuf_dma_len)))

/* macros for flit 7 of the iqe */
#define S_IQE_GENBIT	63
#define M_IQE_GENBIT	0x1
#define G_IQE_GENBIT(x)	(((x) >> S_IQE_GENBIT) & M_IQE_GENBIT)
#define V_IQE_GENBIT(x) ((x)<<S_IQE_GENBIT)

#define S_IQE_OVFBIT	62
#define M_IQE_OVFBIT	0x1
#define G_IQE_OVFBIT(x)	((((x) >> S_IQE_OVFBIT)) & M_IQE_OVFBIT)

#define S_IQE_IQTYPE	60
#define M_IQE_IQTYPE	0x3
#define G_IQE_IQTYPE(x)	((((x) >> S_IQE_IQTYPE)) & M_IQE_IQTYPE)

#define M_IQE_TS	0x0fffffffffffffffULL
#define G_IQE_TS(x)	((x) & M_IQE_TS)

#define IQE_OVFBIT(x)	((unsigned)G_IQE_OVFBIT(be64_to_cpu((x)->bits_type_ts)))
#define IQE_GENBIT(x)	((unsigned)G_IQE_GENBIT(be64_to_cpu((x)->bits_type_ts)))
#define IQE_IQTYPE(x)	((unsigned)G_IQE_IQTYPE(be64_to_cpu((x)->bits_type_ts)))
#define IQE_TS(x)	(G_IQE_TS(be64_to_cpu((x)->bits_type_ts)))

// the following is for wmb() only, from infiniband/arch.h:
//
/*
 * Architecture-specific defines.  Currently, an architecture is
 * required to implement the following operations:
 *
 * mb() - memory barrier.  No loads or stores may be reordered across
 *     this macro by either the compiler or the CPU.
 * rmb() - read memory barrier.  No loads may be reordered across this
 *     macro by either the compiler or the CPU.
 * wmb() - write memory barrier.  No stores may be reordered across
 *     this macro by either the compiler or the CPU.
 * wc_wmb() - flush write combine buffers.  No write-combined writes
 *     will be reordered across this macro by either the compiler or
 *     the CPU.
 */

#if defined(__i386__)

#define mb()	 asm volatile("lock; addl $0,0(%%esp) " ::: "memory")
#define rmb()	 mb()
#define wmb()	 asm volatile("" ::: "memory")
#define wc_wmb() mb()

#elif defined(__x86_64__)

/*
 *  * Only use lfence for mb() and rmb() because we don't care about
 *   * ordering against non-temporal stores (for now at least).
 *    */
#define mb()	 asm volatile("lfence" ::: "memory")
#define rmb()	 mb()
#define wmb()	 asm volatile("" ::: "memory")
#define wc_wmb() asm volatile("sfence" ::: "memory")

#else

#warning No architecture specific defines found.  Using generic implementation.

#define mb()	 asm volatile("" ::: "memory")
#define rmb()	 mb()
#define wmb()	 mb()
#define wc_wmb() wmb()

#endif


#define writel(v, a) do { *((volatile u32 *)(a)) = cpu_to_pci32(v); } while (0)

extern int ma_wr;

enum {
	T4_TX_ONCHIP = (1 << 0),
};

struct t4_fl_shared_params_entry {
	u16 cidx;
	u16 pidx;
	u16 in_use;
	u16 pend_cred;
};

struct t4_sw_fl_shared_params_entry {
	u16 cidx;
	u16 pidx;
	atomic_t in_use;
	u16 pend_cred;
};

struct t4_raw_fl {
	u64 *queue;
	struct t4_fl_shared_params_entry *fl_shared_params;
	u64 *sw_queue;
	void *db;
	size_t memsize;
	u32 qid;
	u16 size;
};

#define NRXBUF 16
struct sw_t4_raw_fl {
	u64 sw_queue[NRXBUF];
	u16 size;
	u16 cidx;
	u16 pidx;
	atomic_t in_use;
};

struct t4_iq_shared_params_entry {
	u16 cidx;
	u16 cidx_inc;
	u8 gen;
};

struct t4_iq {
	struct t4_iqe *queue;
	struct t4_iq_shared_params_entry *iq_shared_params;
	void *gts;
	size_t memsize;
	u64 bits_type_ts;
	u16 size;
	u16 qid;
	u8 error;
};

struct t4_desc {
	__be64 flit[8];
};

struct t4_txq_shared_params_entry {
	u16 cidx;
	u16 pidx;
	u16 flags;
};

#define MAX_INLINE_OFLD_TX_DESC 4
union tx_desc {
	struct t4_desc desc[MAX_INLINE_OFLD_TX_DESC];
	struct fw_ofld_tx_data_wr req;
	struct fw_flowc_wr flowc;
};

struct t4_txq {
	u16 size;
	size_t memsize;
	void *db;
	u16 qid;
	struct t4_desc *desc;
	struct t4_txq_shared_params_entry *txq_params;
	volatile u32 *udb;
};

/*
struct cpl_rx_pkt {
	RSS_HDR
	__u8 opcode;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 iff:4;
	__u8 csum_calc:1;
	__u8 ipmi_pkt:1;
	__u8 vlan_ex:1;
	__u8 ip_frag:1;
#else
	__u8 ip_frag:1;
	__u8 vlan_ex:1;
	__u8 ipmi_pkt:1;
	__u8 csum_calc:1;
	__u8 iff:4;
#endif
	__be16 csum;
	__be16 vlan;
	__be16 len;
	__be32 l2info;
	__be16 hdr_len;
	__be16 err_vec;
};
*/

/*
 * IQE defs
 */
struct t4_iqe {
	__be64 rss_hdr;			/* flit 0 */
	struct cpl_rx_pkt rx_pkt;	/* flits 1..2 */
	__be64 reserved1;		/* flit 3 */
	__be64 reserved2;		/* flit 4 */
	__be64 reserved3;		/* flit 5 */
	__be64 newbuf_dma_len;		/* flit 6 */
	__be64 bits_type_ts;		/* flit 7 */
};

static inline void t4_raw_fl_produce(struct t4_raw_fl *f)
{
	f->fl_shared_params->in_use++;
	if (++f->fl_shared_params->pidx == f->size) {
		f->fl_shared_params->pidx = 0;
	}
}

static inline void t4_ring_fl_db(struct t4_raw_fl *f)
{
	if (f->fl_shared_params->pend_cred >= 8) {
		wmb();
		writel(F_DBPRIO | 
			V_QID(f->qid) | 
			V_PIDX(f->fl_shared_params->pend_cred / 8),
			f->db);
		f->fl_shared_params->pend_cred &= 7;
	}
}

static inline int t4_txq_onchip(struct t4_txq *txq)
{
	return txq->txq_params->flags & T4_TX_ONCHIP;
}

static inline void copy_wqe_to_udb(volatile u32 *udb_offset, void *wr)
{
	u64 *src, *dst;
	int len16 = 4;

	src = (u64 *)wr;
	dst = (u64 *)udb_offset;

	while (len16) {
		*dst++ = *src++;
		*dst++ = *src++;
		len16--;
	}
}

static inline void t4_ring_txq_db(struct t4_txq *t, int n, int t5)
{
	wmb();
	if (t5) {
		if (n == 1) {
			int index = t->txq_params->pidx ?
				(t->txq_params->pidx - 1) : (t->size - 1);
			void *wr = (void *)&t->desc[index];
			copy_wqe_to_udb(t->udb + 14, wr);
		} else {
			writel(V_PIDX_T5(n), t->udb);
		}
		wc_wmb();
		return;
	}
	if (ma_wr) {
		if (t4_txq_onchip(t)) {
			int i;
			for (i = 0; i < 16; i++)
			    *(volatile u32 *)&t->desc[t->size].flit[2+i] = i;
		}
	}
	writel(V_QID(t->qid) | V_PIDX(n), t->db);
}

static inline int t4_valid_iqe(struct t4_iq *iq, struct t4_iqe *iqe)
{
	return (IQE_GENBIT(iqe) == iq->iq_shared_params->gen);
}

#if 0
#include <stdio.h>
/*
 * t4_dump_iqe - Dumps an RespQ entry by blocks of 32 bits.
 * For the sake of clarity, the function also prints the
 * 64-bit flit number of each 32-bit block.
 *
 * The byte order is little endian.
 */
static inline void t4_dump_iqe(struct t4_iqe *iqe)
{
	int len = sizeof(*iqe);
	int flit = -1;
	int *value = (int *)iqe;

	printf("size of IQE: %d\n", len);

	while (len > 0) {
		if (len % 8 == 0)
			flit++;

		printf("IQE [flit %d]: %#010x\n", flit, ntohl(*value));
		value++;
		len -= 4;
	}
}
#endif

static inline int t4_next_iqe(struct t4_iq *iq, struct t4_iqe **iqe)
{
	int ret;
 
	if (iq->error)
		return -ENODATA;

	if (t4_valid_iqe(iq, &iq->queue[iq->iq_shared_params->cidx])) {
		*iqe = &iq->queue[iq->iq_shared_params->cidx];
		ret = 0;
	} else {
		ret = -ENODATA;
	}
	
	return ret;
}

static inline void t4_iq_consume(struct t4_iq *iq)
{
	/*
	 * write to GTS reg to update the
	 * cidx that has already been processed
	 */
	if (++iq->iq_shared_params->cidx_inc == (iq->size >> 4)) {
		uint32_t val;

		val = V_CIDXINC(iq->iq_shared_params->cidx_inc) | 
				V_TIMERREG(7) |
				V_INGRESSQID(iq->qid);
		writel(val, iq->gts);
		iq->iq_shared_params->cidx_inc = 0;
	}
	if (++iq->iq_shared_params->cidx == iq->size) {
		iq->iq_shared_params->cidx = 0;
		iq->iq_shared_params->gen ^= 1;
	}
}

static inline void t4_raw_fl_consume(struct t4_raw_fl *f)
{
	f->fl_shared_params->in_use--;
	if (++f->fl_shared_params->cidx == f->size)
		f->fl_shared_params->cidx = 0;
	assert((f->fl_shared_params->cidx != f->fl_shared_params->pidx)
			|| f->fl_shared_params->in_use == 0);
}

static inline void sw_t4_raw_fl_consume(struct sw_t4_raw_fl *f)
{
	atomic_decr(&f->in_use);
	if (++f->cidx == f->size)
		f->cidx = 0;
	/* XXX what is this assert for?? */
	//assert((f->cidx != f->pidx)
	//		|| atomic_read(&f->in_use) == 0);
}

static inline void sw_t4_raw_fl_produce(struct sw_t4_raw_fl *f)
{
	atomic_incr(&f->in_use);
	assert(atomic_read(&f->in_use) < f->size);
	if (++f->pidx == f->size) {
		f->pidx = 0;
	}
}

/*
 * borrowed from cxgb4/sge.c;
 * @frags: number of fl buffers we want to restore
 */
static inline void t4_raw_fl_restore(struct t4_raw_fl *f, int frags)
{
	while (frags--) {
		if (f->fl_shared_params->cidx == 0)
			f->fl_shared_params->cidx = f->size - 1;
		else
			f->fl_shared_params->cidx--;
		f->fl_shared_params->in_use++;
	}
}

static inline void t4_txq_produce(struct t4_txq *t, unsigned int n)
{
	int i;
	for (i = 0; i < n; i++) {
		if (++t->txq_params->pidx == t->size)
			t->txq_params->pidx = 0;
	}
}
#endif
