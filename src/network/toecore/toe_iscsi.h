/*
 * Modified version of iscsi_tcp.h 
 */

#ifndef ISCSI_TCP_H
#define ISCSI_TCP_H

struct crypto_hash;
struct socket;
struct iscsi_tcp_conn;
struct iscsi_segment;


/*
 * iSCSI Template Message Header
 */
struct iscsi_hdr {
	uint8_t		opcode;
	uint8_t		flags;		/* Final bit */
	uint8_t		rsvd2[2];
	uint8_t		hlength;	/* AHSs total length */
	uint8_t		dlength[3];	/* Data length */
	uint8_t		lun[8];
	__be32		itt;		/* Initiator Task Tag */
	__be32		ttt;		/* Target Task Tag */
	__be32		statsn;
	__be32		exp_statsn;
	__be32		max_statsn;
	uint8_t		other[12];
};

/* Extended CDB AHS */
struct iscsi_ecdb_ahdr {
	__be16 ahslength;	/* CDB length - 15, including reserved byte */
	uint8_t ahstype;
	uint8_t reserved;
	uint8_t ecdb[260 - 16];	/* 4-byte aligned extended CDB spillover */
};

struct iscsi_rlength_ahdr {
	__be16 ahslength;
	uint8_t ahstype;
	uint8_t reserved;
	__be32 read_length;
};

enum {
	/* this is the maximum possible storage for AHSs */
	ISCSI_MAX_AHS_SIZE = sizeof(struct iscsi_ecdb_ahdr) +
				sizeof(struct iscsi_rlength_ahdr),
	ISCSI_DIGEST_SIZE = sizeof(__u32),
};

struct iscsi_segment {
	unsigned char		*data;
	unsigned int		size;
	unsigned int		copied;
	unsigned int		total_size;
	unsigned int		total_copied;

	//struct hash_desc	*hash;
	void			*hash;
	unsigned char		recv_digest[ISCSI_DIGEST_SIZE];
	unsigned char		digest[ISCSI_DIGEST_SIZE];
	unsigned int		digest_len;

	//struct scatterlist	*sg;
	void			*sg;
	void			*sg_mapped;
	unsigned int		sg_offset;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
	bool			atomic_mapped;
#endif

	// Not worth pulling in the definition of iscsi_segment_done_fn_t ...
	//iscsi_segment_done_fn_t	*done;
};

/* Socket connection recieve helper */
struct iscsi_tcp_recv {
	struct iscsi_hdr	*hdr;
	struct iscsi_segment	segment;

	/* Allocate buffer for BHS + AHS */
	uint32_t		hdr_buf[64];

	/* copied and flipped values */
	int			datalen;
};

struct iscsi_conn {
	//struct iscsi_cls_conn	*cls_conn;	/* ptr to class connection */
	void			*cls_conn;
	void			*dd_data;	/* iscsi_transport data */
};

/* Socket connection send helper */
struct iscsi_tcp_send {
	struct iscsi_hdr	*hdr;
	struct iscsi_segment	segment;
	struct iscsi_segment	data_segment;
};

struct iscsi_tcp_conn {
	struct iscsi_conn	*iscsi_conn;
	struct socket		*sock;
	int			stop_stage;	/* conn_stop() flag: *
						 * stop to recover,  *
						 * stop to terminate */
	/* control data */
	struct iscsi_tcp_recv	in;		/* TCP receive context */
	struct iscsi_tcp_send	out;		/* TCP send context */

	/* old values for socket callbacks */
	void			(*old_data_ready)(struct sock *, int);
	void			(*old_state_change)(struct sock *);
	void			(*old_write_space)(struct sock *);

	/* data and header digests */
	//struct hash_desc	tx_hash;	/* CRC32C (Tx) */
	//struct hash_desc	rx_hash;	/* CRC32C (Rx) */

	/* MIB custom statistics */
	//uint32_t		sendpage_failures_cnt;
	//uint32_t		discontiguous_hdr_cnt;

	//int			error;

	//ssize_t (*sendpage)(struct socket *, struct page *, int, size_t, int);
};

#endif /* ISCSI_H */
