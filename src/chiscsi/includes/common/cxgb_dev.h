#ifndef __CXGB_DEVICE_H__
#define __CXGB_DEVICE_H__

#include <linux/version.h>
#include <linux/skbuff.h>

#include <common/iscsi_common.h>
#include <common/iscsi_sgvec.h>
#include <common/iscsi_offload.h>
#include <common/iscsi_socket.h>
#include <common/iscsi_pdu.h>
#include <common/iscsi_tag.h>

/*
 * Chelsio's offload support
 */
enum offload_device_version {
	ULP_VERSION_T3 = 3,
	ULP_VERSION_T4,
	ULP_VERSION_T5,
	ULP_VERSION_T6,
};

/*
 * T2/3 device
 */
struct offload_device_template {
	unsigned int ttid_min;
	unsigned int ttid_max;
	int (*isock_get_ttid)(iscsi_socket *, void **);
	void (*isock_offload_info)(iscsi_socket *, void *tdev);
};
struct offload_device_template * odev_template_get(int);

typedef struct offload_device offload_device;

#define ODEV_FLAG_ULP_CRC_ENABLED	0x1
#define ODEV_FLAG_ULP_DDP_ENABLED	0x2
#define ODEV_FLAG_ULP_TX_ALLOC_DIGEST   0x4
#define ODEV_FLAG_ULP_RX_PAD_INCLUDED   0x8

#define ODEV_FLAG_TX_ZCOPY_DMA_ADDR	0x10

#define ODEV_FLAG_ULP_T10DIF_ENABLED	0x20
#define ODEV_FLAG_ULP_ISO_ENABLED	0x40
#define ODEV_FLAG_ULP_COMPL_ENABLED	0x80

#define ODEV_FLAG_ULP_ENABLED	\
	(ODEV_FLAG_ULP_CRC_ENABLED | ODEV_FLAG_ULP_DDP_ENABLED)

struct offload_device {
	offload_device *d_next;

	unsigned char d_version;
	unsigned char d_tx_hdrlen;	/* CPL_TX_DATA, < 256 */
	unsigned char d_ulp_rx_datagap; /* for coalesced iscsi msg */
	unsigned char d_force;
	unsigned int d_pi_hdrlen;	/* fw_tx_pi_header */
	unsigned int d_iso_hdrlen;	/* cpl_tx_data_iso */

	unsigned int d_flag;
	unsigned int d_payload_tmax;
	unsigned int d_payload_rmax;
	chiscsi_sgvec d_pad_pg;

	void	*d_lldev;	/* lld device */
	void	*d_tdev;	/* toedev */
	void	*d_pdev;	/* pci device */
	void	*d_ndev;	/* net device */
	//void	*d_pptable;
	void	*d_extra;	/* extra for ddp */

	void    (*dev_release) (offload_device *);
	void    (*dev_put) (offload_device *);
	void    (*dev_get) (offload_device *);

	void *  (*odev2ppm)(offload_device *odev);
	/* bind an offload connection to a particular cpu */
	int	(*sk_bind_to_cpu)(iscsi_socket *, unsigned int);
	
	int	(*sk_display)(struct iscsi_socket *, char *, int);
	/* offloaded sk -> ulp mode */
	int     (*sk_set_ulp_mode)(struct iscsi_socket *, 
				   unsigned char, unsigned char, unsigned char);

	/* offloaded sk tx/rx */
	void	(*sk_rx_tcp_consumed)(iscsi_socket *, unsigned int);
	int	(*sk_rx_ulp_skb)(void *);
	int	(*sk_rx_ulp_skb_ready)(void *);
	int	(*sk_rx_ulp_ddpinfo)(void *, iscsi_pdu *, void *);
	void	(*sk_tx_skb_setmode)(void *, unsigned char,
				     unsigned char, unsigned char);
	void	(*sk_tx_skb_setforce)(void *, unsigned char,
				     unsigned char);
	int	(*sk_tx_skb_push)(struct sock *, struct sk_buff *, int);
	void	(*sk_tx_skb_setmode_pi)(void *, unsigned char,
					unsigned char);
	int	(*sk_tx_make_pi_hdr)(void *, iscsi_pdu *);
	int	(*sk_tx_make_iso_cpl)(void *, iscsi_pdu *);
	void	(*sk_tx_skb_setmode_iso)(void *, unsigned char,
					unsigned char);

	void    (*sk_ddp_off)(struct sock *);
	int	(*isock_read_pdu_header_toe)(iscsi_socket *, iscsi_pdu *);
	int	(*isock_read_pdu_data_toe)(iscsi_socket *, iscsi_pdu *);
	int	(*isock_read_pdu_header_ulp)(iscsi_socket *, iscsi_pdu *);
	int	(*isock_read_pdu_data_ulp)(iscsi_socket *, iscsi_pdu *);
	int	(*isock_read_pdu_pi_ulp)(iscsi_socket *, iscsi_pdu *);
	int	(*isock_write_pdus_toe)(iscsi_socket *, chiscsi_queue *,
					chiscsi_queue *);
	int	(*isock_write_pdus_ulp)(iscsi_socket *, chiscsi_queue *,
					chiscsi_queue *);

	/* ppm */
	void	(*ppm_make_ppod_hdr)(void *ppm, u32 tag, unsigned int tid,
                        unsigned int offset, unsigned int length,
                        void *pi, void *hdr);
	void	(*ppm_ppod_release)(void *, u32 idx);
	int	(*ppm_ppods_reserve)(void *, unsigned short nr_pages,
                        u32 per_tag_pg_idx, u32 *ppod_idx, u32 *ddp_tag,
                        unsigned long caller_data);

	/* ddp */
	void	(*ddp_clear_map)(offload_device *, unsigned int idx,
			struct chiscsi_tag_ppod *);
	int 	(*ddp_set_map)(iscsi_socket *, void *ttinfo_p,
			struct chiscsi_tag_ppod *);

	/* premap buffer handling */
	int	(*skb_set_premapped_sgl)(struct sk_buff *,
					chiscsi_sgvec *sgl, unsigned int sgcnt);
	void	(*skb_reset_premapped_sgl)(struct sk_buff *);
};

#define offload_device_enqueue(L,Q,P) \
		ch_enqueue_tail(L,offload_device,d_next,Q,P)
#define offload_device_dequeue(L,Q,P) \
                ch_dequeue_head(L,offload_device,d_next,Q,P)
#define offload_device_ch_qremove(L,Q,P) \
		ch_qremove(L,offload_device,d_next,Q,P)
#define offload_device_qsearch_by_tdev(L,Q,P,V) \
                ch_qsearch_by_field_value(L,offload_device,d_next,Q,P,d_tdev,V)

int offload_device_init(void);
void offload_device_cleanup(void);
void os_sock_offload_info(iscsi_socket *);
void offload_device_remove_by_version(int);

unsigned int sock_rx_pdu_max(iscsi_socket *);
unsigned int sock_tx_pdu_max(iscsi_socket *);

/*
 * ULP defines
 */

#define SBUF_ULP_FLAG_HDR_RCVD          0x1
#define SBUF_ULP_FLAG_DATA_RCVD         0x2
#define SBUF_ULP_FLAG_STATUS_RCVD       0x4
#define SBUF_ULP_FLAG_COALESCE_OFF      0x8
#define SBUF_ULP_FLAG_HCRC_ERROR        0x10
#define SBUF_ULP_FLAG_DCRC_ERROR        0x20
#define SBUF_ULP_FLAG_PAD_ERROR         0x40
#define SBUF_ULP_FLAG_DATA_DDPED        0x80
#define SBUF_ULP_FLAG_CMPL_RCVD		0x100
#define SBUF_ULP_FLAG_LRO		0x200

#define SBUF_ULP_ISCSI_FLAGS_PI_RCVD		0x1 /* pi cpl rcvd */
#define SBUF_ULP_ISCSI_FLAGS_PI_DDPD		0x2 /* pi ddp'd */
#define SBUF_ULP_ISCSI_FLAGS_PI_ERR		0x4 /* pi verify error */

#define ISCSI_PDU_NONPAYLOAD_LEN        312 /* bhs(48) + ahs(256) + digest(8) */
#define ULP2_MAX_PKT_SIZE       16224
#define ULP2_MAX_PDU_PAYLOAD    (ULP2_MAX_PKT_SIZE - ISCSI_PDU_NONPAYLOAD_LEN)


#endif /* ifndef __CXGB_DEVICE_H__ */
