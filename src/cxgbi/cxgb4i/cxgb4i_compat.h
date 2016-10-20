#ifndef __CXGB4I_COMPAT_H__
#define __CXGB4I_COMPAT_H__

#ifdef __CXGB4TOE__

#ifdef DEL_WORK
struct delayed_work_compat {
	struct work_struct work;
};
#define delayed_work delayed_work_compat
#endif

#include "common.h"
#include "cxgb4_ofld.h"
#include "t4fw_interface.h"

#define KEEP_ALIVE	V_KEEP_ALIVE
#define WND_SCALE	V_WND_SCALE
#define MSS_IDX		V_MSS_IDX
#define L2T_IDX		V_L2T_IDX
#define TX_CHAN		V_TX_CHAN
#define SMAC_SEL	V_SMAC_SEL
#define ULP_MODE	V_ULP_MODE
#define RCV_BUFSIZ	V_RCV_BUFSIZ
#define RX_CHANNEL	V_RX_CHANNEL
#define RSS_QUEUE	V_RSS_QUEUE
#define NO_REPLY	V_NO_REPLY
#define REPLY_CHAN	V_REPLY_CHAN
#define QUEUENO		V_QUEUENO
#define RSS_QUEUE_VALID	F_RSS_QUEUE_VALID

#define RX_CREDITS	V_RX_CREDITS
#define RX_FORCE_ACK	V_RX_FORCE_ACK

#define FW_WR_OP	V_FW_WR_OP
#define FW_FLOWC_WR_NPARAMS	V_FW_FLOWC_WR_NPARAMS
#define FW_WR_LEN16	V_FW_WR_LEN16
#define FW_WR_FLOWID	V_FW_WR_FLOWID
#define FW_WR_COMPL	V_FW_WR_COMPL
#define FW_WR_IMMDLEN	V_FW_WR_IMMDLEN

#define FW_OFLD_TX_DATA_WR_ULPMODE	V_TX_ULP_MODE
#define FW_OFLD_TX_DATA_WR_ULPSUBMODE	V_TX_ULP_SUBMODE
#define FW_OFLD_TX_DATA_WR_SHOVE	V_TX_SHOVE

#define GET_FW_WR_FLOWID  G_FW_WR_FLOWID
#define GET_TID_TID	G_TID_TID
#define GET_AOPEN_ATID	G_AOPEN_ATID
#define GET_AOPEN_STATUS	G_AOPEN_STATUS
#define ISCSI_PDU_LEN	G_ISCSI_PDU_LEN
#define GET_TCPOPT_MSS	G_TCPOPT_MSS
#define GET_TCPOPT_TSTAMP G_TCPOPT_TSTAMP
#define FW_VIID_PFN_GET G_FW_VIID_PFN  

#define ULPTX_CMD	V_ULPTX_CMD
#define ULP_MEMIO_DATA_LEN	V_ULP_MEMIO_DATA_LEN
#define ULP_MEMIO_DATA_ADDR	V_ULP_MEMIO_DATA_ADDR
#define ULP_MEMIO_ADDR	V_ULP_MEMIO_ADDR
#define ULPTX_NSGE	V_ULPTX_NSGE
#define ULP_TX_MORE F_ULP_TX_SC_MORE

#ifdef CXGBI_T10DIF_SUPPORT
#define FW_OFLD_TX_DATA_WR_T10DIF		V_FW_OFLD_TX_DATA_WR_T10DIF

#define FW_TX_PI_HEADER_PI_OP			V_FW_TX_PI_HEADER_OP
#define FW_TX_PI_HEADER_PI_ULPTXMORE		F_FW_TX_PI_HEADER_ULPTXMORE
#define FW_TX_PI_HEADER_PI_CONTROL		V_FW_TX_PI_HEADER_PI_CONTROL
#define FW_TX_PI_HEADER_GUARD_TYPE		V_FW_TX_PI_HEADER_GUARD_TYPE
#define FW_TX_PI_HEADER_VALIDATE		V_FW_TX_PI_HEADER_VALIDATE
#define FW_TX_PI_HEADER_INLINE			V_FW_TX_PI_HEADER_INLINE
#define FW_TX_PI_HEADER_PI_INTERVAL		V_FW_TX_PI_HEADER_PI_INTERVAL
#define FW_TX_PI_HEADER_TAG_TYPE		V_FW_TX_PI_HEADER_TAG_TYPE
#define FW_TX_PI_HEADER_PI_START4		V_FW_TX_PI_HEADER_PI_START4
#define FW_TX_PI_HEADER_PI_END4			V_FW_TX_PI_HEADER_PI_END4
#define FW_TX_PI_HEADER_TAG_GEN_ENABLED		V_FW_TX_PI_HEADER_TAG_GEN_ENABLED
#endif
#ifndef DELACK
#define DELACK V_DELACK
#define RX_DACK_CHANGE V_RX_DACK_CHANGE
#define RX_DACK_MODE V_RX_DACK_MODE
#endif

#ifndef CXGB4_PORT_IDX
static unsigned int cxgb4_port_idx(const struct net_device *dev)
{
        return netdev2pinfo(dev)->port_id;
}
#endif

#endif /* #ifdef __CXGB4TOE__ */

#ifndef roundup
#define roundup(x, y)	((((x) + ((y) - 1)) / (y)) * (y))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0)
#define prandom_u32 net_random
#endif

#endif /* __CXGB4I_COMPAT_H__ */
