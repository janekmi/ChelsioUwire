/*
 * This file is part of the Chelsio T4/T5/T6 Virtual Function (VF) Ethernet
 * driver support code.
 *
 * Copyright (C) 2003-2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __T4VF_COMMON_H__
#define __T4VF_COMMON_H__

#include "t4_hw.h"
#include "t4_chip_type.h"
#include "osdep.h"
#include "t4fw_interface.h"

/*
 * Per-VF statistics.
 */
struct t4vf_port_stats {
	/*
	 * TX statistics.
	 */
	u64 tx_bcast_bytes;		/* broadcast */
	u64 tx_bcast_frames;
	u64 tx_mcast_bytes;		/* multicast */
	u64 tx_mcast_frames;
	u64 tx_ucast_bytes;		/* unicast */
	u64 tx_ucast_frames;
	u64 tx_drop_frames;		/* TX dropped frames */
	u64 tx_offload_bytes;		/* offload */
	u64 tx_offload_frames;

	/*
	 * RX statistics.
	 */
	u64 rx_bcast_bytes;		/* broadcast */
	u64 rx_bcast_frames;
	u64 rx_mcast_bytes;		/* multicast */
	u64 rx_mcast_frames;
	u64 rx_ucast_bytes;
	u64 rx_ucast_frames;		/* unicast */

	u64 rx_err_frames;		/* RX error frames */
};

/*
 * Per-"port" (Virtual Interface) link configuration ...
 */
struct link_config {
	unsigned short supported;        /* link capabilities */
	unsigned short advertising;      /* advertised capabilities */
	unsigned short requested_speed;  /* speed user has requested */
	unsigned short speed;            /* actual link speed */
	unsigned char  requested_fc;     /* flow control user has requested */
	unsigned char  fc;               /* actual link flow control */
	unsigned char  autoneg;          /* autonegotiating? */
	unsigned char  link_ok;          /* link up? */
};

enum {
	PAUSE_RX      = 1 << 0,
	PAUSE_TX      = 1 << 1,
	PAUSE_AUTONEG = 1 << 2
};

/*
 * General device parameters ...
 */
struct dev_params {
	u32 fwrev;			/* firmware version */
	u32 tprev;			/* TP Microcode Version */
};

/*
 * Scatter Gather Engine parameters.  These are almost all determined by the
 * Physical Function Driver.  We just need to grab them to see within which
 * environment we're playing ...
 */
struct sge_params {
	u32 sge_control;		/* padding, boundaries, lengths, etc. */
	u32 sge_control2;		/* T5: more of the same */
	u32 sge_host_page_size;		/* PF0-7 page sizes */
	u32 sge_egress_queues_per_page;	/* PF0-7 egress queues/page */
	u32 sge_ingress_queues_per_page;/* PF0-7 ingress queues/page */
	u32 sge_vf_hps;			/* host page size for our vf */
	u32 sge_vf_eq_qpp;		/* egress queues/page for our VF */
	u32 sge_vf_iq_qpp;		/* ingress queues/page for our VF */
	u32 sge_fl_buffer_size[16];	/* free list buffer sizes */
	u32 sge_ingress_rx_threshold;	/* RX counter interrupt threshold[4] */
	u32 sge_congestion_control;	/* congestion thresholds, etc. */
	u32 sge_timer_value_0_and_1;	/* interrupt coalescing timer values */
	u32 sge_timer_value_2_and_3;
	u32 sge_timer_value_4_and_5;
};

/*
 * Vital Product Data parameters.
 */
struct vpd_params {
	u32 cclk;			/* Core Clock (KHz) */
};

/* Stores chip specific parameters */
struct arch_specific_params {
	u32 sge_fl_db;
	u16 mps_tcam_size;
};

/*
 * Global Receive Side Scaling (RSS) parameters in host-native format.
 */
struct rss_params {
	unsigned int mode;		/* RSS mode */
	union {
	    struct {
		uint synmapen:1;	/* SYN Map Enable */
		uint syn4tupenipv6:1;	/* enable hashing 4-tuple IPv6 SYNs */
		uint syn2tupenipv6:1;	/* enable hashing 2-tuple IPv6 SYNs */
		uint syn4tupenipv4:1;	/* enable hashing 4-tuple IPv4 SYNs */
		uint syn2tupenipv4:1;	/* enable hashing 2-tuple IPv4 SYNs */
		uint ofdmapen:1;	/* Offload Map Enable */
		uint tnlmapen:1;	/* Tunnel Map Enable */
		uint tnlalllookup:1;	/* Tunnel All Lookup */
		uint hashtoeplitz:1;	/* use Toeplitz hash */
	    } basicvirtual;
	} u;
};

/*
 * Virtual Interface RSS Configuration in host-native format.
 */
union rss_vi_config {
    struct {
	u16 defaultq;			/* Ingress Queue ID for !tnlalllookup */
	uint ip6fourtupen:1;		/* hash 4-tuple IPv6 ingress packets */
	uint ip6twotupen:1;		/* hash 2-tuple IPv6 ingress packets */
	uint ip4fourtupen:1;		/* hash 4-tuple IPv4 ingress packets */
	uint ip4twotupen:1;		/* hash 2-tuple IPv4 ingress packets */
	uint udpen:1;			/* hash 4-tuple UDP ingress packets */
    } basicvirtual;
};

/*
 * Maximum resources provisioned for a PCI VF.
 */
struct vf_resources {
	unsigned int nvi;		/* N virtual interfaces */
	unsigned int neq;		/* N egress Qs */
	unsigned int nethctrl;		/* N egress ETH or CTRL Qs */
	unsigned int niqflint;		/* N ingress Qs/w free list(s) & intr */
	unsigned int niq;		/* N ingress Qs */
	unsigned int tc;		/* PCI-E traffic class */
	unsigned int pmask;		/* port access rights mask */
	unsigned int nexactf;		/* N exact MPS filters */
	unsigned int r_caps;		/* read capabilities */
	unsigned int wx_caps;		/* write/execute capabilities */
};

/*
 * Per-"adapter" (Virtual Function) parameters.
 */
struct adapter_params {
	struct dev_params dev;		/* general device parameters */
	struct sge_params sge;		/* Scatter Gather Engine */
	struct vpd_params vpd;		/* Vital Product Data */
	struct rss_params rss;		/* Receive Side Scaling */
	struct vf_resources vfres;	/* Virtual Function Resource limits */
	struct arch_specific_params arch; /* chip specific params */
	enum chip_type chip;		/* chip code */
	u8 nports;			/* # of Ethernet "ports" */
};

/*
 * Firmware Mailbox Command/Reply log.  All values are in Host-Endian format.
 * The access and execute times are signed in order to accommodate negative
 * error returns.
 */
struct mbox_cmd {
	u64 cmd[MBOX_LEN/8];		/* a Firmware Mailbox Command/Reply */
	u64 timestamp;			/* OS-dependent timestamp */
	u32 seqno;			/* sequence number */
	s16 access;			/* time (ms) to access mailbox */
	s16 execute;			/* time (ms) to execute */
};

struct mbox_cmd_log {
	unsigned int size;		/* number of entries in the log */
	unsigned int cursor;		/* next position in the log to write */
	u32 seqno;			/* next sequence number */
	/* variable length mailbox command log starts here */
};

/*
 * Given a pointer to a Firmware Mailbox Command Log and a log entry index,
 * return a pointer to the specified entry.
 */
static inline struct mbox_cmd *mbox_cmd_log_entry(struct mbox_cmd_log *log,
						  unsigned int entry_idx)
{
	return &((struct mbox_cmd *)&(log)[1])[entry_idx];
}

#include "adapter.h"

#ifndef PCI_VENDOR_ID_CHELSIO
# define PCI_VENDOR_ID_CHELSIO 0x1425
#endif

#define for_each_port(adapter, iter) \
	for (iter = 0; iter < (adapter)->params.nports; iter++)

static inline bool is_10g_port(const struct link_config *lc)
{
	return (lc->supported & FW_PORT_CAP_SPEED_10G) != 0;
}

static inline bool is_x_10g_port(const struct link_config *lc)
{
	return ((lc->supported & FW_PORT_CAP_SPEED_10G) != 0 ||
		(lc->supported & FW_PORT_CAP_SPEED_40G) != 0 ||
		(lc->supported & FW_PORT_CAP_SPEED_100G) != 0);
}


static inline unsigned int core_ticks_per_usec(const struct adapter *adapter)
{
	return adapter->params.vpd.cclk / 1000;
}

static inline unsigned int us_to_core_ticks(const struct adapter *adapter,
					    unsigned int us)
{
	return (us * adapter->params.vpd.cclk) / 1000;
}

static inline unsigned int core_ticks_to_us(const struct adapter *adapter,
					    unsigned int ticks)
{
	/* add Core Clock / 2 to round ticks to nearest uS */
	return ((ticks * 1000 + adapter->params.vpd.cclk/2) /
		adapter->params.vpd.cclk);
}

void t4vf_record_mbox_marker(struct adapter *adapter,
			     const void *marker, unsigned int size);
int t4vf_wr_mbox_core(struct adapter *, const void *, int, void *, bool);

static inline int t4vf_wr_mbox(struct adapter *adapter, const void *cmd,
			       int size, void *rpl)
{
	return t4vf_wr_mbox_core(adapter, cmd, size, rpl, true);
}

static inline int t4vf_wr_mbox_ns(struct adapter *adapter, const void *cmd,
				  int size, void *rpl)
{
	return t4vf_wr_mbox_core(adapter, cmd, size, rpl, false);
}

/**
 *	hash_mac_addr - return the hash value of a MAC address
 *	@addr: the 48-bit Ethernet MAC address
 *
 *	Hashes a MAC address according to the hash function used by hardware
 *	inexact (hash) address matching.  The description in the hardware
 *	documentation for the MPS says this:
 *
 *	    The hash function takes the 48 bit MAC address and hashes
 *	    it down to six bits.  Bit zero of the hash is the XOR of
 *	    bits 0, 6 ... 42 of the MAC address.  The other hash bits
 *	    are computed in a similar fashion ending with bit five of
 *	    the hash as the XOR of bits 5, 11 ... 47 of the MAC address.
 */
static inline int hash_mac_addr(const u8 *addr)
{
	u32 a = ((u32)addr[0] << 16) | ((u32)addr[1] << 8) | addr[2];
	u32 b = ((u32)addr[3] << 16) | ((u32)addr[4] << 8) | addr[5];

	a ^= b;
	a ^= (a >> 12);
	a ^= (a >> 6);
	return a & 0x3f;
}

int t4vf_wait_dev_ready(struct adapter *);
int t4vf_port_init(struct adapter *, int);

int t4vf_fw_reset(struct adapter *);
int t4vf_set_params(struct adapter *, unsigned int, const u32 *, const u32 *);

enum t4_bar2_qtype { T4_BAR2_QTYPE_EGRESS, T4_BAR2_QTYPE_INGRESS };
int t4vf_bar2_sge_qregs(struct adapter *adapter,
		      unsigned int qid,
		      enum t4_bar2_qtype qtype,
		      u64 *pbar2_qoffset,
		      unsigned int *pbar2_qid);

int t4vf_get_sge_params(struct adapter *);
int t4vf_get_vpd_params(struct adapter *);
int t4vf_get_dev_params(struct adapter *);
int t4vf_get_rss_glb_config(struct adapter *);
int t4vf_get_vfres(struct adapter *);

int t4vf_read_rss_vi_config(struct adapter *, unsigned int,
			    union rss_vi_config *);
int t4vf_write_rss_vi_config(struct adapter *, unsigned int,
			     union rss_vi_config *);
int t4vf_config_rss_range(struct adapter *, unsigned int, int, int,
			  const u16 *, int);

int t4vf_alloc_vi(struct adapter *, int);
int t4vf_free_vi(struct adapter *, int);
int t4vf_enable_vi(struct adapter *, unsigned int, bool, bool);
int t4vf_identify_port(struct adapter *, unsigned int, unsigned int);

int t4vf_set_rxmode(struct adapter *, unsigned int, int, int, int, int, int,
		    bool);
int t4vf_alloc_mac_filt(struct adapter *, unsigned int, bool, unsigned int,
			const u8 **, u16 *, u64 *, bool);
int t4vf_free_mac_filt(struct adapter *, unsigned int, unsigned int naddr,
		       const u8 **, bool);
int t4vf_change_mac(struct adapter *, unsigned int, int, const u8 *, bool);
int t4vf_set_addr_hash(struct adapter *, unsigned int, bool, u64, bool);
int t4vf_get_port_stats(struct adapter *, int, struct t4vf_port_stats *);

int t4vf_iq_free(struct adapter *, unsigned int, unsigned int, unsigned int,
		 unsigned int);
int t4vf_eth_eq_free(struct adapter *, unsigned int);

int t4vf_handle_fw_rpl(struct adapter *, const __be64 *);
int t4vf_prep_adapter(struct adapter *, u32);

#endif /* __T4VF_COMMON_H__ */
