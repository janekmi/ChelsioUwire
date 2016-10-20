#ifndef __ISCSI_SOCKET_H__
#define __ISCSI_SOCKET_H__

#include <common/iscsi_tcp.h>
#include <common/iscsi_queue.h>
#include <common/iscsi_offload.h>
#include <common/iscsi_sgvec.h>
#include <common/iscsi_pdu.h>

/*
 * iscsi socket
 */

typedef struct iscsi_socket iscsi_socket;

#define ISCSI_SOCKET_ACTIVE_OPEN	0x1
#define ISCSI_SOCKET_OFFLOADED		0x2
#define ISCSI_SOCKET_ULP2TOE		0x4
#define ISCSI_SOCKET_BIND2CPU		0x8

#define ISCSI_SOCKET_RST		0x10
#define ISCSI_SOCKET_NO_TX		0x20
#define ISCSI_SOCKET_TX_CLOSED		0x40
#define ISCSI_SOCKET_QUICKACK		0x80

struct iscsi_socket {
	/* the 4-tuple */
	struct chiscsi_tcp_endpoints	s_tcp;

	/* iscsi private */
	unsigned char	s_flag;		
	unsigned char	s_cpuno;	/* bind to cpuno */
	unsigned char	s_mode;		/* offload mode */
	unsigned char	s_txhold;

	unsigned char	s_ddp_pgidx;	/* ddp page selection */
	unsigned char	s_hcrc_len;
	unsigned char	s_dcrc_len;
	unsigned char	filler[1];

	/* offload only */
	unsigned int 	s_tid;
	unsigned int 	s_port_id;
	unsigned int 	s_sndnxt;
	void		*s_egress_dev;
	void		*s_tx_page;
	char		*s_tx_addr;
	void		*s_pdu_data;

	unsigned int	s_tmax;
	unsigned int	s_rmax;
	unsigned int	s_mss;
	unsigned int 	s_snd_nxt;
	unsigned int	s_isomax;	/* max data in iso */
	void 		*s_odev;	/* offload device, if any */
	void   		*s_appdata;	/* upperlayer data pointer */
	void   		*s_private;	/* underlying socket related info. */

	int     (*sk_write_pdus) (iscsi_socket *, chiscsi_queue *, chiscsi_queue *);
	int	(*sk_read_pdu_header) (iscsi_socket *, struct iscsi_pdu *);
	int	(*sk_read_pdu_data) (iscsi_socket *, struct iscsi_pdu *);
	int	(*sk_read_pdu_pi) (iscsi_socket *, struct iscsi_pdu *);
};

/* exported by the iscsi core library */
void 		iscsi_socket_state_change(iscsi_socket *);
void 		iscsi_socket_data_ready(iscsi_socket *);
void 		iscsi_socket_write_space(iscsi_socket *, int);


/* exported by the platform dependent layer */
void		os_socket_bind_to_cpu(iscsi_socket *, unsigned int);
void *		os_socket_netdev(iscsi_socket *);
int		os_socket_set_offload_mode(iscsi_socket *, unsigned char,
					   unsigned char, unsigned char,
					   unsigned int);
void *		os_socket_get_offload_pci_device(iscsi_socket *);

iscsi_socket *	os_socket_listen(struct tcp_endpoint *ep, int);
int 		os_socket_accept(iscsi_socket *, void *, iscsi_socket **);
void 		os_socket_release(iscsi_socket *);
void 		os_socket_destroy(iscsi_socket *);
int		os_socket_display(iscsi_socket *, char *, int);

#endif /* ifndef __ISCSI_SOCKET_H__ */
