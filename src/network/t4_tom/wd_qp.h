#ifndef _CHELSIO_TOM_T4_WD_QP_H
#define _CHELSIO_TOM_T4_WD_QP_H

#include <linux/vmalloc.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/toedev.h>
#include <linux/cdev.h>
#include <net/tcp.h>
#include <net/offload.h>
#include <net/route.h>
#include <asm/atomic.h>
#include "common.h"
#include "defs.h"
#include "tom.h"
#include "cpl_io_state.h"
#include "t4_tcb.h"
#include "t4_regs.h"
#include "cxgb4_ofld.h"
#include "t4fw_interface.h"
#include "offload.h"
#include "ntuples.h"

#define WDTOE_TXQ_SIZE 512
#define WDTOE_FLSIZE 16
#define WDTOE_MMAPNUM_RXQ (WDTOE_FLSIZE * 16 + 5)
/* we map txq->queue, txq->shared_param, and txq->udb */
#define WDTOE_MMAPNUM_TXQ 3
/* As dev0 is reserved, so we support 64 stacks in total */
#define WDTOE_DEV_TABLE_ENTRY 65

/* stolen from iw_cxgb4/t4.h, */
/* we probably should include it someday */
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

/* Flags for wdtoe_raw_[r|t]xq */
enum {
	T4_TX_ONCHIP = (1 << 0),
};

enum wdtoe_hca_type {
	T4_WDTOE = 0,
	T5_WDTOE = 1,
};

#if defined(RSS_HDR_VLD) || defined(CHELSIO_FW)
# define RSS_HDR struct rss_header rss_hdr;
#else
# define RSS_HDR
#endif

/*
 * IQE defs
 *
 * Note that the data structure in Kernel is different
 * from the one in User Space. In User Space the first
 * flit is '__be64 rss_hdr' but here we don't need it
 * because 'RSS_HDR' is defined to a real structure
 * in 'struct cpl_rx_pkt', as TOM defines 'RSS_HDR_VLD'
 * to 1 in t4_tom/defs.h. In User Space, 'RSS_HDR' is
 * replaced by zilch by the preprocessor.
 */
struct t4_iqe {
	struct cpl_rx_pkt rx_pkt;	/* flits 0..2 */
	__be64 reserved1;		/* flit 3 */
	__be64 reserved2;		/* flit 4 */
	__be64 reserved3;		/* flit 5 */
	__be64 newbuf_dma_len;		/* flit 6 */
	__be64 bits_type_ts;		/* flit 7 */
};

/* keep this structure same as the one in user space */
struct t4_iq_shared_params_entry {
	u16 cidx;
	u16 cidx_inc;
	u8 gen;
};

struct t4_iq_shared_params {
	__be64 *desc;
	size_t memsize;
	unsigned long phys_addr;
	dma_addr_t dma_addr;
};

struct t4_desc {
	__be64 flit[8];
};

struct t4_txq {
	unsigned int size;
	unsigned int memsize;
	unsigned int cntxt_id;
	struct t4_desc *desc;
	unsigned long phys_addr;
	dma_addr_t dma_addr;
	u64 udb;	/* address of udb page, to be mmaped to user */
	u64 kudb;	/* address of udb, to be saved in kernel */
};

/* XXX not sure what we need to maintain yet, */
/* XXX assuming we need to store cidx, pidx.. */
struct t4_txq_shared_params_entry {
	u16 cidx;
	u16 pidx;
	u16 flags;
};

struct t4_txq_shared_params {
	__be64 *desc;
	size_t memsize;
	unsigned long phys_addr;
	dma_addr_t dma_addr;
};

struct wdtoe_raw_txq {
	struct net_device *netdev;
	struct t4_txq txq;
	struct t4_txq_shared_params txq_params;
	u16 flags;
};

/* 
 * lifted from "struct c4iw_raw_qp" in iw_cxgb4.h 
 */
struct t4_iq {
	unsigned int cntxt_id;
	__be64 *desc;
	unsigned long phys_addr;
	dma_addr_t dma_addr;
	unsigned int size;
	unsigned int memsize;
	/* make the t4_iq look the same as in user space */
	struct t4_iqe *queue;
	struct t4_iq_shared_params_entry *iq_shared_params;
	struct adapter *adapter;
};

struct fl_sw_desc {
	void *buf;
	dma_addr_t dma_addr;
};

/* keep this structure same as the one in user space */
struct t4_fl_shared_params_entry {
	u16 cidx;
	u16 pidx;
	u16 in_use;
	u16 pend_cred;
};

struct t4_fl_shared_params {
	__be64 *desc;
	size_t memsize;
	unsigned long phys_addr;
	dma_addr_t dma_addr;
};

struct t4_fl {
	unsigned int avail;
	unsigned int pend_cred;
	unsigned int cidx;
	unsigned int pidx;
	unsigned int cntxt_id;
	unsigned int size;
	unsigned int memsize;
	struct fl_sw_desc *sdesc;
	size_t sdesc_memsize;
	dma_addr_t sdesc_dma_addr;
	unsigned long sdesc_phys_addr;
	__be64 *desc;
	dma_addr_t dma_addr;
	unsigned long phys_addr;
	void __iomem *db;
};

struct sw_t4_fl {
	unsigned int avail;
	unsigned int pend_cred;
	unsigned int cidx;
	unsigned int pidx;

	unsigned int size;
	unsigned int memsize;
	__be64 *desc;
	dma_addr_t dma_addr;
	unsigned long phys_addr;
	/* for the software desc */
	struct fl_sw_desc *sdesc;
	size_t sdesc_memsize;
	dma_addr_t sdesc_dma_addr;
	unsigned long sdesc_phys_addr;

	struct t4_fl_shared_params sw_fl_params;
};

enum wdtoe_conn_info_state {
	AVAILABLE,
	IN_USE,
	INCOMPLETE,
};

enum wdtoe_tcp_states {
	TCP_CONN_IDLE = 0,
	TCP_CONN_ESTABLISHED = 1,
	TCP_CONN_CLOSE_WAIT = 2,
};

enum wdtoe_device_flag {
	WD_DEV_FREE = 0,
	WD_DEV_ENGAGED = 1,
	WD_DEV_CREATED = 2,
};

/*
 * This structure is not used from Kernel Space
 * but is needed for padding reasons
 */
struct conn_stats {
	unsigned long long fast_sends;
	unsigned long long fast_recvs;
	unsigned long long waits;
};

/* keep this structure same as the one in user space */
struct wdtoe_conn_info_entry {
	unsigned int atid;
	unsigned int stid;
	unsigned int lport;
	__u32 pip;
	__u16 pport;
	int tid;
	unsigned int sockfd;
	enum wdtoe_conn_info_state state;
	enum wdtoe_tcp_states tcp_state;
	int port_num;
	/* unacked RX credits */
	__u32 copied;
	__u32 buf_len;
	int buf_idx;			 /* index for Tx and Rx buffers */
	int wd_flags;
	int sk_flags;
	unsigned int max_credits;
	atomic_t cur_credits;
	unsigned int pend_credits;
	struct conn_stats stats;
};

struct wdtoe_conn_info {
	__be64 *desc;
	size_t memsize;
	unsigned long phys_addr;
	dma_addr_t dma_addr;
};

struct sw_txq_entry {
	u64 dma_addr;
	int copied;
};

#define NTXBUF 48
struct sw_t4_txq {
	struct sw_txq_entry queue[NTXBUF];
	u64 sw_queue[NTXBUF];

	u16 size;

	u16 cidx;
	u16 pidx;
	atomic_t in_use;
	u16 pend_cred;
};

#define NRXBUF 16
struct sw_t4_raw_fl {
	u64 sw_queue[NRXBUF];
	u16 size;
	u16 cidx;
	u16 pidx;
	atomic_t in_use;
};

struct sw_cred_q_entry {
	int cred;
	int n_bufs;
};

#define NCRED 64
struct sw_cred_q {
	struct sw_cred_q_entry queue[NCRED];
	u16 size;
	u16 cidx;
	u16 pidx;
};

#define NWDTOECONN 64
struct rx_tx_buffer {
	struct sw_t4_txq sw_txq[NWDTOECONN];
	struct sw_t4_raw_fl sw_fl[NWDTOECONN];
	struct sw_cred_q credq[NWDTOECONN];
	int flags[NWDTOECONN];
	spinlock_t lock;
};

struct wdtoe_listsvr {
	int sockfd;
	int idx;
	u16 listen_port;
	atomic_t ref_cnt;
};

struct wdtoe_stack_info_entry {
	struct wdtoe_conn_info_entry conn_info[NWDTOECONN];
	struct rx_tx_buffer buf;
	struct wdtoe_listsvr svr_info[NWDTOECONN];
};

struct wdtoe_stack_info {
	__be64 *desc;
	size_t memsize;
	unsigned long phys_addr;
	dma_addr_t dma_addr;
};

#define T4_IQE_LEN 64

struct wd_raw_rxq {
	//struct ib_qp ibqp;
	//struct c4iw_dev *dev;
	struct net_device *netdev;
	//struct c4iw_cq *scq;
	//struct c4iw_cq *rcq;
	struct t4_iq iq;
	struct t4_fl fl;
	//struct t4_eth_txq txq;
	//int txq_idx;
	//u32 state;
	//struct mutex mutex;
	//atomic_t refcnt;
	//wait_queue_head_t wait;
	//u16 vlan_pri;
	//int fid;
	struct t4_iq_shared_params iq_params;
	struct t4_fl_shared_params fl_params;
};

enum {
	WDTOE_CMD_CREATE_RXQ,
	WDTOE_CMD_PASS_PID,
	WDTOE_CMD_CPL_TO_TOM,
	WDTOE_CMD_CONN_TUPLES,
	WDTOE_CMD_PASS_TUPLES,
	WDTOE_CMD_UPDATE_RX_CREDITS,
	WDTOE_CMD_COPY_RXQ,
	WDTOE_CMD_GET_PORT_NUM,
	WDTOE_CMD_CREATE_DEV,
	WDTOE_CMD_REG_LISTEN,
	WDTOE_CMD_REMOVE_LISTEN,
	WDTOE_CMD_CREATE_MEMPOOL,
	WDTOE_CMD_COPY_TXQ,
	WDTOE_CMD_REG_STACK,
	WDTOE_CMD_SEND_FLOWC,
};

struct wdtoe_cmd_hdr {
	__u32 command;
	__u16 in_words;
	__u16 out_words;
};

struct wdtoe_conn_tuples_cmd {
	__u64 response;
};

struct wdtoe_passive_tuples_cmd {
	__u64 response;
};

struct create_rxq_resp {
	__u32 nports;
	__u32 stack_info_memsize;
	__u32 hca_type;
	__u32 qid_mask;
};

struct create_mempool {
	__u64 response;
	__u32 page_num;
};

struct create_mempool_resp {
};

struct copy_rxq_resp {
	//struct ibv_create_qp_resp ibv_resp;
	//__u64 ma_sync_key;
	__u64 db_key;
	//__u64 txq_key;
	__u64 fl_key;
	__u64 iq_key;
	//__u64 txq_memsize;
	__u64 fl_memsize;
	__u64 iq_memsize;
	//__u32 txq_id;
	__u32 fl_id;
	__u32 iq_id;
	//__u32 txq_size;
	__u32 fl_size;
	__u32 iq_size;
	//__u32 tx_chan;
	//__u32 pf;
	//__u32 flags;
	//__u32 fid;
	__u32 fl_pidx;
	__u32 fl_pend_cred;
	__u32 fl_avail;
};

struct wdtoe_create_qp_cmd {
	__u64 response;
	__u32 tx_hold_thres;
};

struct wdtoe_pass_pid_cmd {
	__u32 pid;
};

struct wdtoe_update_rx_credits_cmd {
	__u64 response;
	__u32 tid;
	__u32 buf_len;
	__u32 copied;
};

struct wdtoe_pass_cpl_to_tom_cmd {
	__u64 response;
	struct t4_iqe full_iqe;
};

struct wdtoe_copy_rxq_cmd {
	__u64 response;
	__u32 port_num;
};


struct wdtoe_copy_txq_cmd {
	__u64 response;
	__u32 port_num;
};

struct wdtoe_copy_txq_resp {
	//__u64 db_key;
	//__u64 txq_key;
	__u64 txq_memsize;
	__u32 txq_id;
	__u32 txq_size;
	__u16 flags;
	//__u32 tx_chan;
	//__u32 pf;
	//__u32 flags;
	//__u32 fid;
};

struct wdtoe_flowc_cmd {
	__u64 response;
	__u32 tid;
};

struct wdtoe_flowc_resp {
	__u32 rcv_nxt;		/* from tp->rcv_nxt */
	__u32 snd_nxt;
	__u16 advmss;
	__u32 sndbuf;
	__u32 tx_c_chan;	/* type unsigned int in TOM */
	__u32 pfvf;		/* type unsigned int in TOM */
	__u32 txplen_max;	/* type unsigned int in TOM */
};


struct wdtoe_get_port_num_cmd {
	__u64 response;
	__u32 tid;
};

struct wdtoe_get_port_num_resp {
	__u32 port_num;
	__u32 max_cred;
};

struct wdtoe_create_dev_cmd {
	__u64 response;
};

struct wdtoe_reg_listen_cmd {
	__u64 response;
	__u16 dev_idx;
	__u16 listen_port;
};

struct wdtoe_reg_listen_resp {

};

struct wdtoe_remove_listen_cmd {
	__u64 response;
	__u16 listen_port;
};

struct wdtoe_remove_listen_resp {

};

struct wdtoe_create_dev_resp {
	__u16 dev_idx;
};

struct wdtoe_mm {
	u64 paddr;
	u64 vaddr;
	dma_addr_t daddr;
	unsigned len;
};

struct wdtoe_device {
	struct cdev cdev;
	struct device *pdev;
	struct wd_raw_rxq **rxq_list;
	struct wdtoe_raw_txq **txq_list;
	struct wdtoe_mm *address_list;
	struct wdtoe_mm *address_list_mempool;
	int mempool_size;
	struct wdtoe_conn_info conn_info;
	struct wdtoe_stack_info stack_info;
	struct wdtoe_stack_info_entry *k_stack_info;
	int devno;
	int index;
	int mmap_element_offset;
	spinlock_t lock;
	/* counter for connection number associated with this device */
	int conn_num;
	int in_use;
	enum wdtoe_hca_type hca_type;
	unsigned long qpshift;
	u32 qpmask;
};

struct pid_node {
	pid_t pid;
	struct pid_node *next;
};

struct wdtoe_device_table {
	int index;
	struct wdtoe_device *wd_dev;
	struct pid_node *pid_list;
	enum wdtoe_device_flag in_use;
	spinlock_t lock;
};

struct wdtoe_listen_device {
	int listen_port;
	/* index to the device table */
	int idx_dev;
	int in_use;
};

static inline int t4_txq_onchip(struct wdtoe_raw_txq *txq)
{
	return txq->flags & T4_TX_ONCHIP;
}

/* XXX this one can be static now */
struct wd_raw_rxq *wd_create_raw_rxq(struct cxgb4_lld_info *, 
					struct net_device *);
extern struct cxgb4_lld_info *cached_lldi;
extern struct tom_data *cached_td;

int wdtoe_mmap(struct file *filp, struct vm_area_struct *vma);

int wdtoe_insert_conn_tuple(struct conn_tuple *c, unsigned int atid,
			    unsigned int lport);

unsigned int wdtoe_calc_opt2(const struct sock *sk,
			     const struct offload_settings *s,
			     struct wdtoe_device *wd_dev);

/* XXX need to push lldi into wd_qp.c, 
 * and them remove the lldi from the arg list
 */
ssize_t wdtoe_create_rxq(struct cxgb4_lld_info *, 
			struct wdtoe_device *wd_dev,
			const char __user *buf, 
			int, int);
ssize_t wdtoe_create_mempool(struct cxgb4_lld_info *, 
			struct wdtoe_device *wd_dev,
			const char __user *buf, 
			int, int);
ssize_t wdtoe_create_txq(struct cxgb4_lld_info *,
			struct wdtoe_device *wd_dev,
			const char __user *buf,
			int, int);
ssize_t wdtoe_pass_pid(struct cxgb4_lld_info *, 
			const char __user *buf, 
			int, int);
ssize_t wdtoe_pass_cpl_to_tom(struct cxgb4_lld_info *, 
				struct wdtoe_device *wd_dev,
				const char __user *buf, 
				int, int);
ssize_t wdtoe_update_rx_credits(struct cxgb4_lld_info *, 
				struct wdtoe_device *wd_dev,
				const char __user *buf, 
				int, int);
ssize_t wdtoe_copy_rxq(struct cxgb4_lld_info *, 
			struct wdtoe_device *wd_dev,
			const char __user *buf, 
			int, int);
ssize_t wdtoe_copy_txq(struct cxgb4_lld_info *, 
			struct wdtoe_device *wd_dev,
			const char __user *buf, 
			int, int);
ssize_t wdtoe_reg_stack(struct cxgb4_lld_info *,
			struct wdtoe_device *wd_dev,
			const char __user *buf,
			int, int);
ssize_t wdtoe_send_tx_flowc_wr(struct cxgb4_lld_info *,
			struct wdtoe_device *wd_dev,
			const char __user *buf,
			int, int);
ssize_t wdtoe_reg_listen(struct cxgb4_lld_info *,
			struct wdtoe_device *wd_dev,
			const char __user *buf,
			int, int);
ssize_t wdtoe_remove_listen(struct cxgb4_lld_info *,
			struct wdtoe_device *wd_dev,
			const char __user *buf,
			int, int);
ssize_t wdtoe_get_port_num(struct cxgb4_lld_info *, 
			const char __user *buf,
			int, int);
ssize_t wdtoe_create_dev(struct cxgb4_lld_info *,
			const char __user *buf,
			int, int);
int wdtoe_open(struct inode *inode, struct file *filp);
int wdtoe_close(struct inode *inode, struct file *filp);

int wdtoe_find_dev_by_pid(struct wdtoe_device_table *, int*, int);
int wdtoe_find_dev_by_tid(struct wdtoe_device_table *, int*, int*, int);

int wdtoe_act_open_req(struct sock *sk, unsigned int atid, __be16 lport,
		       const struct offload_settings *s, __be32 *opt2);

void t4_dump_iqe(const char *, struct t4_iqe *);

int is_wdtoe(struct sock *);

/* Onchip queues */
extern u32 cxgb4_ocqp_pool_alloc(struct net_device *dev, int size);
extern void cxgb4_ocqp_pool_free(struct net_device *dev, u32 addr, int size);
#endif
