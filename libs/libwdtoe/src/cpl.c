#include <string.h>
#include "debug.h"
#include "kernelcom.h"
#include "conn_info.h"
#include "buffer.h"
#include "cpl.h"

extern int global_devfd;
extern struct conn_tuple *k_conn_tuples;
extern struct passive_tuple *k_passive_tuples;
extern struct wdtoe_device *wd_dev;

static int do_cpl_act_establish(const __be64 *rsp, const __be64 *rsp_end,
				u8 opcode)
{
	int lport;
	int buf_idx;
	unsigned int atid;
	unsigned int tid;
	const struct cpl_act_establish *rpl;
	struct wdtoe_get_conn_tuples cmd;
	int ret = 0;

	rpl = (struct cpl_act_establish *)rsp;

	atid = G_TID_TID(ntohl(rpl->tos_atid));
	tid = GET_TID(rpl);

	DBG(DBG_CONN, "received CPL_ACT_ESTABLISH (%#x) for atid %u, tid %u\n",
	    opcode, atid, tid);

	assert(k_conn_tuples);

	get_kernel_conn_tuples(global_devfd, &cmd ,sizeof(cmd), k_conn_tuples,
			       sizeof(*k_conn_tuples));


	lport = conn_tuple_get_lport(k_conn_tuples, atid);
	if (lport == -1) {
		DBG(DBG_LOOKUP, "could not retrieve local port for active "
		    "connection with atid %u\n", atid);
		ret = -1;
		goto out;
	}

	/*
	 * Here we're asking for a SW-FL (a cache) for this new active
	 * connection. Remember, each connection needs its own chache for
	 * demultiplexing purposes.
	 *
	 * If we can't get a cache for this new connection there is nothing
	 * we can do. We're then in serious troubles.
	 */
	buf_idx = get_new_buf(wd_dev);
	if (buf_idx < 0) {
		DBG(DBG_CONN, "no tx_buf available, can not continue.\n");
		ret = -1;
		goto out;
	}

	ret = conn_info_insert_cpl_tuple(wd_dev->stack_info->conn_info,
					 atid, 0, tid, lport, 0, 0,
					 buf_idx);
	if (ret == -1) {
		DBG(DBG_LOOKUP, "could not insert tuple for active "
		    "connection with atid %u tid %u and local port %d\n",
		    atid, tid, lport);
		ret = -1;
		goto out;
	}

out:
	return ret;
}

static int do_cpl_pass_establish(const __be64 *rsp, const __be64 *rsp_end,
				 u8 opcode)
{
	int ret;
	__u32 pip;
	__u16 pport;
	int buf_idx;
	unsigned int stid;
	unsigned int tid;
	struct wdtoe_get_passive_tuples cmd_p_tpl;
	const struct cpl_pass_establish *rpl_passive;

	pip = 0;
	pport = 0;

	rpl_passive = (struct cpl_pass_establish *)rsp;
	stid = G_PASS_OPEN_TID(ntohl(rpl_passive->tos_stid));
	tid = GET_TID(rpl_passive);

	DBG(DBG_CONN, "received CPL_PASS_ESTABLISH (%#x) for stid %u, tid %u\n",
	    opcode, stid, tid);

	// XXX do we need error check on the return value?
	get_kernel_passive_tuples(global_devfd, &cmd_p_tpl, sizeof(cmd_p_tpl),
				  k_passive_tuples, sizeof(*k_passive_tuples)
				  * NWDTOECONN);

	ret = passive_tuple_get_peer_info(k_passive_tuples, stid, tid, &pip,
					  &pport);
	if (ret == -1) {
		DBG(DBG_LOOKUP, "could not get peer ip and port for passive "
		    "connection with stid %d, tid %d\n", stid, tid);
		return -1;
	}

	buf_idx = get_new_buf(wd_dev);
	if (buf_idx < 0) {
		DBG(DBG_CONN, "no buffer available for a new connection, "
		    "cannot continue.\n");
		return -1;
	}

	ret = conn_info_insert_cpl_tuple(wd_dev->stack_info->conn_info,
					 0, stid, tid, 0, pip, pport,
					 buf_idx);
	if (ret == -1) {
		DBG(DBG_LOOKUP, "could not insert tuple for active connection "
		    "with stid %u, tid %u, ip %#x, port %u\n", stid, tid, pip,
		    pport);
	}

	return ret;
}

static int do_cpl_peer_close(const __be64 *rsp, const __be64 *rsp_end,
			     u8 opcode)
{
	int tcpst;
	unsigned int tid;
	const struct cpl_peer_close *rplpc;

	/* change the tcp_state to CLOSE_WAIT */
	rplpc = (struct cpl_peer_close *)rsp;
	tid = GET_TID(rplpc);

	DBG(DBG_CONN, "received CPL_PEER_CLOSE (%#x) for tid %u\n", opcode, tid);

	tcpst = get_tid_tcp_state(wd_dev->stack_info->conn_info, tid);

	if (tcpst == -1) {
		return -1;
	} else if (tcpst == TCP_CLOSE_WAIT) {	// active close
		conn_info_remove_tid_entry(wd_dev->stack_info->conn_info, tid);

	} else {
		set_tid_state(wd_dev->stack_info->conn_info, tid,
			      TCP_CLOSE_WAIT);
	}

	return 0;
}

static int do_cpl_close_con_rpl(const __be64 *rsp, const __be64 *rsp_end,
				u8 opcode)
{
	int tcpst;
	unsigned int tid;
	const struct cpl_close_con_rpl *rplccr;

	rplccr = (struct cpl_close_con_rpl *)rsp;
	tid = GET_TID(rplccr);

	DBG(DBG_CONN, "received CPL_CLOSE_CON_RPL (%#x) for tid %d\n", opcode,
	    tid);

	tcpst = get_tid_tcp_state(wd_dev->stack_info->conn_info, tid);

	if (tcpst == -1) {
		return -1;
	} else if (tcpst == TCP_CLOSE_WAIT) {	// passive close
		conn_info_remove_tid_entry(wd_dev->stack_info->conn_info, tid);
	} else {
		set_tid_state(wd_dev->stack_info->conn_info, tid,
			      TCP_CLOSE_WAIT);
	}

	return 0;
}

static int do_cpl_abort_rpl_rss(const __be64 *rsp, const __be64 *rsp_end,
				u8 opcode)
{
	unsigned int tid;
	const struct cpl_abort_rpl_rss *rplarr;

	rplarr = (struct cpl_abort_rpl_rss *)rsp;
	tid = GET_TID(rplarr);

	DBG(DBG_CONN, "received CPL_ABORT_RPL_RSS (%#x) for tid %d, "
	    "status %d\n", opcode, tid, rplarr->status);

	conn_info_remove_tid_entry(wd_dev->stack_info->conn_info, tid);

	return 0;
}

static int do_cpl_fw4_ack(const __be64 *rsp, const __be64 *rsp_end, u8 opcode)
{
	int idx;
	unsigned int tid;
	const struct cpl_fw4_ack *rplack;

	rplack = (struct cpl_fw4_ack *)rsp;
	tid = GET_TID(rplack);

	DBG(DBG_CREDITS, "received CPL_FW4_ACK (%#x) for tid %d, credits %d\n",
	    opcode, tid, rplack->credits);

	idx = get_idx_from_tid(wd_dev->stack_info->conn_info, tid);
	if (idx < 0) {
		DBG(DBG_CONN, "could not get the index for tid %u\n", tid);
		goto skip_credit_dequeue;
	}

	credit_dequeue(idx, rplack->credits);

skip_credit_dequeue:
	return 0;
}

static int (*cpl_handler[])(const __be64 *rsp, const __be64 *rsp_end,
			    u8 opcode) = {
	[CPL_ACT_ESTABLISH]	= do_cpl_act_establish,
	[CPL_PASS_ESTABLISH]	= do_cpl_pass_establish,
	[CPL_PEER_CLOSE]	= do_cpl_peer_close,
	[CPL_CLOSE_CON_RPL]	= do_cpl_close_con_rpl,
	[CPL_ABORT_RPL_RSS]	= do_cpl_abort_rpl_rss,
	[CPL_FW4_ACK]		= do_cpl_fw4_ack,
};

void process_cpl(const __be64 *rsp, const __be64 *rsp_end, u8 opcode)
{
	int ret;
	size_t cmd_size;
	size_t resp_size;
	size_t rsp_size;

	/*
	 * The following structs are being used for their very simple
	 * properties. There is actually nothing specific to act establish.
	 */
	struct wdtoe_cpl_act_establish cmd;
	struct wdtoe_cpl_act_establish_resp resp;

	/* skip the RSS header */
	rsp++;

	if (!cpl_handler[opcode]) {
		DBG(DBG_CONN, "received unexpected CPL (%#x)\n", opcode);
		goto reinject;
	}

	ret = cpl_handler[opcode](rsp, rsp_end, opcode);
	if (ret < 0) {
		DBG(DBG_CONN, "CPL handler for opcode %#x failed\n", opcode);
	}

reinject:
	/*
	 * The following code takes care of reinjecting CPL messages back to
	 * the Kernel. We are decrementing the @rsp pointer because we need to
	 * hand CPLs with their RSS headers to TOM.
	 */
	rsp--;

	cmd_size = sizeof(cmd);
	resp_size = sizeof(resp);

	/*
	 * Here we are making sure we are not copying data that is farther than
	 * the boundaries of the IQE we are currently dealing with.
	 */
	rsp_size = (__u64)rsp_end - (__u64)rsp;

	memcpy(&cmd.iqe_cpl, rsp, rsp_size);

	(void)wdtoe_cmd_pass_cpl_to_tom(wd_dev->devfd, &cmd, cmd_size, &resp,
					resp_size);
}
