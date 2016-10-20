/*
 *  Copyright (C) 2008-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description:
 *
 */
#define NTSTRSAFE_NO_DEPRECATE 1

#include <csio_lnode_foiscsi.h>
#include <csio_lnode.h>
#include <csio_rnode.h>
#include <csio_defs.h>
#include <csio_os_defs.h>
#include <csio_stor_ioctl.h>
#include <csio_foiscsi_ioctl.h>
#include <csio_foiscsi_persistent.h>
#include <csio_foiscsi.h>


/*
 *
 * CRC LOOKUP TABLE
 * ================
 * The following CRC lookup table was generated automatically
 * by the Rocksoft^tm Model CRC Algorithm Table Generation
 * Program V1.0 using the following model parameters:
 *
 * 	Width	: 4 bytes.
 *	Poly	: 0x1EDC6F41L
 *	Reverse	: TRUE
 *
 * For more information on the Rocksoft^tm Model CRC Algorithm,
 * see the document titled "A Painless Guide to CRC Error
 * Detection Algorithms" by Ross Williams (ross@guest.adelaide.edu.au.).
 * This document is likely to be in the FTP archive
 * "ftp.adelaide.edu.au/pub/rocksoft".
 */

static unsigned int crc32Table[256] = {
	0x00000000L, 0xF26B8303L, 0xE13B70F7L, 0x1350F3F4L,
	0xC79A971FL, 0x35F1141CL, 0x26A1E7E8L, 0xD4CA64EBL,
	0x8AD958CFL, 0x78B2DBCCL, 0x6BE22838L, 0x9989AB3BL,
	0x4D43CFD0L, 0xBF284CD3L, 0xAC78BF27L, 0x5E133C24L,
	0x105EC76FL, 0xE235446CL, 0xF165B798L, 0x030E349BL,
	0xD7C45070L, 0x25AFD373L, 0x36FF2087L, 0xC494A384L,
	0x9A879FA0L, 0x68EC1CA3L, 0x7BBCEF57L, 0x89D76C54L,
	0x5D1D08BFL, 0xAF768BBCL, 0xBC267848L, 0x4E4DFB4BL,
	0x20BD8EDEL, 0xD2D60DDDL, 0xC186FE29L, 0x33ED7D2AL,
	0xE72719C1L, 0x154C9AC2L, 0x061C6936L, 0xF477EA35L,
	0xAA64D611L, 0x580F5512L, 0x4B5FA6E6L, 0xB93425E5L,
	0x6DFE410EL, 0x9F95C20DL, 0x8CC531F9L, 0x7EAEB2FAL,
	0x30E349B1L, 0xC288CAB2L, 0xD1D83946L, 0x23B3BA45L,
	0xF779DEAEL, 0x05125DADL, 0x1642AE59L, 0xE4292D5AL,
	0xBA3A117EL, 0x4851927DL, 0x5B016189L, 0xA96AE28AL,
	0x7DA08661L, 0x8FCB0562L, 0x9C9BF696L, 0x6EF07595L,
	0x417B1DBCL, 0xB3109EBFL, 0xA0406D4BL, 0x522BEE48L,
	0x86E18AA3L, 0x748A09A0L, 0x67DAFA54L, 0x95B17957L,
	0xCBA24573L, 0x39C9C670L, 0x2A993584L, 0xD8F2B687L,
	0x0C38D26CL, 0xFE53516FL, 0xED03A29BL, 0x1F682198L,
	0x5125DAD3L, 0xA34E59D0L, 0xB01EAA24L, 0x42752927L,
	0x96BF4DCCL, 0x64D4CECFL, 0x77843D3BL, 0x85EFBE38L,
	0xDBFC821CL, 0x2997011FL, 0x3AC7F2EBL, 0xC8AC71E8L,
	0x1C661503L, 0xEE0D9600L, 0xFD5D65F4L, 0x0F36E6F7L,
	0x61C69362L, 0x93AD1061L, 0x80FDE395L, 0x72966096L,
	0xA65C047DL, 0x5437877EL, 0x4767748AL, 0xB50CF789L,
	0xEB1FCBADL, 0x197448AEL, 0x0A24BB5AL, 0xF84F3859L,
	0x2C855CB2L, 0xDEEEDFB1L, 0xCDBE2C45L, 0x3FD5AF46L,
	0x7198540DL, 0x83F3D70EL, 0x90A324FAL, 0x62C8A7F9L,
	0xB602C312L, 0x44694011L, 0x5739B3E5L, 0xA55230E6L,
	0xFB410CC2L, 0x092A8FC1L, 0x1A7A7C35L, 0xE811FF36L,
	0x3CDB9BDDL, 0xCEB018DEL, 0xDDE0EB2AL, 0x2F8B6829L,
	0x82F63B78L, 0x709DB87BL, 0x63CD4B8FL, 0x91A6C88CL,
	0x456CAC67L, 0xB7072F64L, 0xA457DC90L, 0x563C5F93L,
	0x082F63B7L, 0xFA44E0B4L, 0xE9141340L, 0x1B7F9043L,
	0xCFB5F4A8L, 0x3DDE77ABL, 0x2E8E845FL, 0xDCE5075CL,
	0x92A8FC17L, 0x60C37F14L, 0x73938CE0L, 0x81F80FE3L,
	0x55326B08L, 0xA759E80BL, 0xB4091BFFL, 0x466298FCL,
	0x1871A4D8L, 0xEA1A27DBL, 0xF94AD42FL, 0x0B21572CL,
	0xDFEB33C7L, 0x2D80B0C4L, 0x3ED04330L, 0xCCBBC033L,
	0xA24BB5A6L, 0x502036A5L, 0x4370C551L, 0xB11B4652L,
	0x65D122B9L, 0x97BAA1BAL, 0x84EA524EL, 0x7681D14DL,
	0x2892ED69L, 0xDAF96E6AL, 0xC9A99D9EL, 0x3BC21E9DL,
	0xEF087A76L, 0x1D63F975L, 0x0E330A81L, 0xFC588982L,
	0xB21572C9L, 0x407EF1CAL, 0x532E023EL, 0xA145813DL,
	0x758FE5D6L, 0x87E466D5L, 0x94B49521L, 0x66DF1622L,
	0x38CC2A06L, 0xCAA7A905L, 0xD9F75AF1L, 0x2B9CD9F2L,
	0xFF56BD19L, 0x0D3D3E1AL, 0x1E6DCDEEL, 0xEC064EEDL,
	0xC38D26C4L, 0x31E6A5C7L, 0x22B65633L, 0xD0DDD530L,
	0x0417B1DBL, 0xF67C32D8L, 0xE52CC12CL, 0x1747422FL,
	0x49547E0BL, 0xBB3FFD08L, 0xA86F0EFCL, 0x5A048DFFL,
	0x8ECEE914L, 0x7CA56A17L, 0x6FF599E3L, 0x9D9E1AE0L,
	0xD3D3E1ABL, 0x21B862A8L, 0x32E8915CL, 0xC083125FL,
	0x144976B4L, 0xE622F5B7L, 0xF5720643L, 0x07198540L,
	0x590AB964L, 0xAB613A67L, 0xB831C993L, 0x4A5A4A90L,
	0x9E902E7BL, 0x6CFBAD78L, 0x7FAB5E8CL, 0x8DC0DD8FL,
	0xE330A81AL, 0x115B2B19L, 0x020BD8EDL, 0xF0605BEEL,
	0x24AA3F05L, 0xD6C1BC06L, 0xC5914FF2L, 0x37FACCF1L,
	0x69E9F0D5L, 0x9B8273D6L, 0x88D28022L, 0x7AB90321L,
	0xAE7367CAL, 0x5C18E4C9L, 0x4F48173DL, 0xBD23943EL,
	0xF36E6F75L, 0x0105EC76L, 0x12551F82L, 0xE03E9C81L,
	0x34F4F86AL, 0xC69F7B69L, 0xD5CF889DL, 0x27A40B9EL,
	0x79B737BAL, 0x8BDCB4B9L, 0x988C474DL, 0x6AE7C44EL,
	0xBE2DA0A5L, 0x4C4623A6L, 0x5F16D052L, 0xAD7D5351L
};
#define CRC32C_PRELOAD 0xffffffff

unsigned int csio_calculate_crc32c(const void *buf, int len, unsigned int crc)
{
	unsigned char *p = (unsigned char *) buf;
	if (!len)
		return crc;
	while (len-- > 0)
		crc = crc32Table[(crc ^ *p++) & 0xff] ^ (crc >> 8);
	return crc;
}

void process_rnism_events(void *data)
{

	return;
}

static int nlni = 0;

csio_retval_t
csio_lni_init(struct csio_lnode_iscsi *lni)
{
	int rc = CSIO_SUCCESS;

	csio_dbg(csio_lnode_to_hw(lni->ln), "%s: nlni [%d].\n", __FUNCTION__, nlni);

	csio_workq_create(&lni->workq, NULL, NULL);
	if (!lni->workq.wq)
		rc = CSIO_NOMEM;

	nlni++;

	csio_mutex_init(&lni->lni_mtx);
#ifdef __CSIO_DEBUG__
	atomic_set(&lni->mtx_cnt, 0);
#endif

	return rc;
}

void
csio_lni_exit(struct csio_lnode_iscsi *lni)
{
	csio_close_lni(lni);
	csio_workq_destroy(&lni->workq);
	return;
}

void
csio_lni_down(struct csio_lnode_iscsi *lni)
{
	struct csio_hw *hw = csio_lnode_to_hw(lni->ln);
	struct csio_list *tmp = NULL, *next = NULL;
	struct csio_list *rnhead = &lni->ln->rnhead;

	csio_list_for_each_safe(tmp, next, rnhead)
	{
		if (csio_hw_to_ops(hw)->os_rn_unreg_rnode) {
			csio_hw_to_ops(hw)->
				os_rn_unreg_rnode((struct csio_rnode *)tmp);
		}
	}

	csio_dbg(hw, "iSCSI lnode %p down\n", lni);
}

void
csio_close_lni(struct csio_lnode_iscsi *lni)
{
	struct csio_hw *hw = csio_lnode_to_hw(lni->ln);
	struct csio_list *tmp = NULL, *next = NULL;
	struct csio_list *rnhead = &lni->ln->rnhead;

	csio_list_for_each_safe(tmp, next, rnhead)
	{
		csio_spin_lock_irq(hw, &hw->lock);
		if (csio_hw_to_ops(hw)->os_free_rnode) {
			csio_hw_to_ops(hw)->
				os_free_rnode((struct csio_rnode *)tmp);
		}
		csio_spin_unlock_irq(hw, &hw->lock);
	}
	csio_dbg(hw, "iSCSI lnode %p close\n", lni);
}

/**
 * csio_lni_start - Kick off lnode State machine.
 * @lni: iSCSI lnode
 *
 * Initializes iSCSI lnodes.
 */

enum csio_oss_error
csio_lni_start(struct csio_lnode_iscsi *lni)
{
	csio_retval_t rc = CSIO_SUCCESS;
	struct csio_hw *hw = csio_lnode_to_hw(lni->ln);

	lni->inode_id = hw->num_lns;
	csio_dbg(hw, "inode id = %d\n", lni->inode_id);	

	return rc;
}

int csio_issue_foiscsi_chap_wr(struct csio_hw *hw,
		struct csio_lnode_iscsi *inode,
		struct csio_rnode_iscsi *rni,
		short inode_id, unsigned int flowid, u8 node_type)
{
	struct fw_foiscsi_chap_wr chap_wr;
	struct csio_wr_pair wrp;
	int rc = CSIO_SUCCESS;
	int size;
	u8 id_len = 0, sec_len = 0;
	unsigned long flags;

	csio_dbg(hw, "Sizeof fw_foiscsi_chap_wr %lu bytes\n",
			sizeof(struct fw_foiscsi_chap_wr));

	csio_spin_lock_irqsave(hw, &hw->lock, flags);

	size = CSIO_ALIGN(sizeof(struct fw_foiscsi_chap_wr), 16);

	rc = csio_wr_get(hw, hw->mgmtm.eq_idx, size, &wrp);
	if (csio_unlikely(rc != CSIO_SUCCESS))
		goto out;
	
	memset(&chap_wr, 0, sizeof(struct fw_foiscsi_chap_wr));

	chap_wr.op_compl = csio_cpu_to_be32 (
			V_FW_WR_OP(FW_FOISCSI_CHAP_WR));

	chap_wr.flowid_len16 = csio_cpu_to_be32 (
			V_FW_WR_FLOWID(flowid) |
			V_FW_WR_LEN16(CSIO_ROUNDUP(size, 16)));

	chap_wr.node_type = node_type;

	if (node_type == FW_FOISCSI_NODE_TYPE_TARGET) {

		id_len = csio_strlen(rni->login_info.tgt_id);
		sec_len = csio_strlen(rni->login_info.tgt_sec);

		csio_memcpy(chap_wr.chap_id, rni->login_info.tgt_id, id_len);
		csio_memcpy(chap_wr.chap_sec, rni->login_info.tgt_sec, sec_len);

	} else if (node_type == FW_FOISCSI_NODE_TYPE_INITIATOR) {

		chap_wr.node_id = csio_cpu_to_be16(inode_id);
		chap_wr.cookie = (u64)(uintptr_t)inode;

		id_len = csio_strlen(inode->inst.chap_id);
		sec_len = csio_strlen(inode->inst.chap_sec);

		csio_memcpy(chap_wr.chap_id, inode->inst.chap_id, id_len);
		csio_memcpy(chap_wr.chap_sec, inode->inst.chap_sec, sec_len);
	}
	chap_wr.id_len = id_len;
	chap_wr.sec_len = sec_len;

	csio_wr_copy_to_wrp(&chap_wr, &wrp, 0, sizeof(struct fw_foiscsi_chap_wr));
	csio_wr_issue(hw, hw->mgmtm.eq_idx, CSIO_FALSE);

out:
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

#ifdef __CSIO_DEBUG__
	if (rc)
		csio_dbg(hw, "%s: Out of credits, cannot allocate wr\n", __FUNCTION__);
	else
		csio_dump_wr_buffer((uint8_t *)&chap_wr, sizeof(struct fw_foiscsi_chap_wr));
#endif
	return rc;
}	

int csio_issue_foiscsi_node_wr(struct csio_hw *hw,
		struct csio_lnode_iscsi *inode,
		struct foiscsi_instance *ini_inst,
		short inode_id, unsigned int flowid, u8 subop)
{
	struct fw_foiscsi_node_wr node_wr;
	struct csio_wr_pair wrp;
	int rc = CSIO_SUCCESS;
	int size;
	u8 alias_len = 0, iqn_len = 0;
	unsigned long flags;

	csio_dbg(hw, "Sizeof fw_foiscsi_node_wr %lu bytes\n",
			sizeof(struct fw_foiscsi_node_wr));

	csio_spin_lock_irqsave(hw, &hw->lock, flags);

	size = CSIO_ALIGN(sizeof(struct fw_foiscsi_node_wr), 16);

	rc = csio_wr_get(hw, hw->mgmtm.eq_idx, size, &wrp);
	if (csio_unlikely(rc != CSIO_SUCCESS))
		goto out;

	memset(&node_wr, 0, sizeof(struct fw_foiscsi_node_wr));

	node_wr.op_to_immdlen = csio_cpu_to_be32 (
			V_FW_WR_OP(FW_FOISCSI_NODE_WR));

	node_wr.flowid_len16 = csio_cpu_to_be32 (
			V_FW_WR_FLOWID(flowid) |
			V_FW_WR_LEN16(CSIO_ROUNDUP(size, 16)));

	node_wr.subop = subop;
	node_wr.nodeid = csio_cpu_to_be16(inode_id);

	node_wr.cookie = (u64)(uintptr_t)inode;

	if (node_wr.subop ==  FW_FOISCSI_WR_SUBOP_DEL)
		goto send_wr;


	alias_len = (u8)csio_strlen(ini_inst->alias);
	iqn_len = (u8)csio_strlen(ini_inst->name);

	node_wr.alias_len = ++alias_len;
	node_wr.iqn_len = ++iqn_len;

	csio_memcpy(node_wr.alias, ini_inst->alias, alias_len);
	csio_memcpy(node_wr.iqn, ini_inst->name, iqn_len);

	node_wr.login_retry = csio_cpu_to_be16(ini_inst->login_retry_cnt);
	node_wr.retry_timeout = csio_cpu_to_be16(ini_inst->recovery_timeout);
	
	csio_dbg(hw, "%s: login_retry [%u], retry_timeout [%u]\n",
			__FUNCTION__, ini_inst->login_retry_cnt, ini_inst->recovery_timeout);
#if 0
	node_wr->login_retry = ini_inst->login_retry;
	node_wr->retry_timeout = ini_inst->retry_timeout;
#endif
send_wr:
	csio_wr_copy_to_wrp(&node_wr, &wrp, 0, sizeof(struct fw_foiscsi_node_wr));
	csio_wr_issue(hw, hw->mgmtm.eq_idx, CSIO_FALSE);

out:
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

#ifdef __CSIO_DEBUG__
	if (rc)
		csio_dbg(hw, "%s: Out of credits, cannot allocate wr\n", __FUNCTION__);
	else
		csio_dump_wr_buffer((uint8_t *)&node_wr, sizeof(struct fw_foiscsi_node_wr));
#endif
	return rc;
}

int csio_issue_foiscsi_ctrl_wr(struct csio_hw *hw,
		struct foiscsi_login_info *tlogin, struct csio_rnode *rn,
		u8 subop, unsigned int flowid,
		unsigned int node_id, unsigned int sess_id)
{
	struct fw_foiscsi_ctrl_wr ctrl_wr;
	struct csio_wr_pair wrp;
	struct fw_foiscsi_conn_attr *ca;
	struct csio_os_hw *oshw;
	struct csio_rnode_iscsi *rni;
	int rc = 0, name_len = 0;
	int size;
	int *iq_idx;
	unsigned long flags;

	csio_dbg(hw, "Size of fw_foiscsi_ctrl_wr %lu bytes\n",
			sizeof(struct fw_foiscsi_ctrl_wr));

	csio_spin_lock_irqsave(hw, &hw->lock, flags);
	
	oshw = csio_hw_to_os(hw);
	rni = csio_rnode_to_iscsi(rn);
	
	/*Align the size on 16 byte boundary*/
	size = CSIO_ALIGN(sizeof(struct fw_foiscsi_ctrl_wr), 16);

	rc = csio_wr_get(hw, hw->mgmtm.eq_idx, size, &wrp);

	if (csio_unlikely(rc != CSIO_SUCCESS))
		goto out;

	memset(&ctrl_wr, 0, sizeof(struct fw_foiscsi_ctrl_wr));

	ctrl_wr.op_compl = csio_cpu_to_be32(V_FW_WR_OP(FW_FOISCSI_CTRL_WR));
	ctrl_wr.flowid_len16 = csio_cpu_to_be32(
			V_FW_WR_FLOWID(flowid) |
			V_FW_WR_LEN16(CSIO_ROUNDUP(size, 16)));
	ctrl_wr.subop = subop;
	ctrl_wr.node_id = csio_cpu_to_be32(node_id);
	ctrl_wr.cookie = (u64)(uintptr_t)rn;
#if 0
	csio_dbg(hw, "cookie %0llx rn %p\n", ctrl_wr->cookie, rn);
#endif
	if (subop == FW_FOISCSI_WR_SUBOP_MOD &&
	    rni->io_state == FW_FOISCSI_CTRL_IO_STATE_BLOCK) {
		ctrl_wr.flowid_len16 = csio_cpu_to_be32(
				V_FW_WR_FLOWID(sess_id) |
				V_FW_WR_LEN16(CSIO_ROUNDUP(size, 16)));
		ctrl_wr.ctrl_id = csio_cpu_to_be32(sess_id);

		ctrl_wr.io_state = FW_FOISCSI_CTRL_IO_STATE_BLOCKED;
		goto send_wr;
	} else if (subop == FW_FOISCSI_WR_SUBOP_DEL) {
		ctrl_wr.flowid_len16 = csio_cpu_to_be32(
				V_FW_WR_FLOWID(sess_id) |
				V_FW_WR_LEN16(CSIO_ROUNDUP(size, 16)));
		ctrl_wr.ctrl_id = csio_cpu_to_be32(sess_id);
		goto send_wr;
	}

	ctrl_wr.sess_attr.sess_type_to_erl =
		csio_cpu_to_be32(tlogin->sess_attr.sess_type_to_erl);
	ctrl_wr.sess_attr.max_conn =
		csio_cpu_to_be16(tlogin->sess_attr.max_conn);
	ctrl_wr.sess_attr.max_r2t =
		csio_cpu_to_be16(tlogin->sess_attr.max_r2t);
	ctrl_wr.sess_attr.time2wait =
		csio_cpu_to_be16(tlogin->sess_attr.time2wait);
	ctrl_wr.sess_attr.time2retain =
		csio_cpu_to_be16(tlogin->sess_attr.time2retain);
	ctrl_wr.sess_attr.max_burst =
		csio_cpu_to_be32(tlogin->sess_attr.max_burst);
	ctrl_wr.sess_attr.first_burst =
		csio_cpu_to_be32(tlogin->sess_attr.first_burst);

	ca = &ctrl_wr.conn_attr;

	if (tlogin->ip_type == TYPE_IPV6)
		tlogin->conn_attr.hdigest_to_ddp_pgsz |=
					F_FW_FOISCSI_CTRL_WR_IPV6;
	ctrl_wr.conn_attr.hdigest_to_ddp_pgsz =
		csio_cpu_to_be32(tlogin->conn_attr.hdigest_to_ddp_pgsz);

	ctrl_wr.conn_attr.max_rcv_dsl = csio_cpu_to_be32(tlogin->conn_attr.max_rcv_dsl);
	ctrl_wr.conn_attr.ping_tmo = csio_cpu_to_be32(tlogin->conn_attr.ping_tmo);
	ctrl_wr.conn_attr.dst_port = csio_cpu_to_be16(tlogin->tgt_port);

	if (tlogin->ip_type == TYPE_IPV4) {
		ctrl_wr.conn_attr.u.ipv4_addr.dst_addr =
				csio_cpu_to_be32(tlogin->tgt_ip.ip4);
		ctrl_wr.conn_attr.u.ipv4_addr.src_addr =
				csio_cpu_to_be32(tlogin->src_ip.ip4);
	} else { /* IPv6 */
		ctrl_wr.conn_attr.u.ipv6_addr.dst_addr[0] =
					*(__be64 *)(tlogin->tgt_ip.ip6);
		ctrl_wr.conn_attr.u.ipv6_addr.dst_addr[1] =
					*(__be64 *)(tlogin->tgt_ip.ip6 + 8);

		ctrl_wr.conn_attr.u.ipv6_addr.src_addr[0] =
					*(__be64 *)(tlogin->src_ip.ip6);
		ctrl_wr.conn_attr.u.ipv6_addr.src_addr[1] =
					*(__be64 *)(tlogin->src_ip.ip6 + 8);
	}

	name_len = csio_strlen(tlogin->tgt_name);

	if (name_len && (name_len < FW_FOISCSI_NAME_MAX_LEN)) {
		ctrl_wr.tgt_name_len = ++name_len;
		csio_memcpy(ctrl_wr.tgt_name, tlogin->tgt_name, name_len);
	}

	iq_idx = (int *)ctrl_wr.r3;
	*iq_idx = csio_cpu_to_be32(csio_q_physiqid(hw,
				oshw->sqset[rn->lnp->portid][smp_processor_id()].iq_idx));

send_wr:
	csio_wr_copy_to_wrp(&ctrl_wr, &wrp, 0, sizeof(struct fw_foiscsi_ctrl_wr));
	csio_wr_issue(hw, hw->mgmtm.eq_idx, CSIO_FALSE);

out:
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

#ifdef __CSIO_DEBUG__
	csio_dbg(hw, "iq_idx [0x%x]\n",
			csio_q_physiqid(hw,
				oshw->sqset[rn->lnp->portid][smp_processor_id()].iq_idx));
	if (rc)
		csio_dbg(hw, "%s: Out of credits, cannot allocate wr\n", __FUNCTION__);
	else
		csio_dump_wr_buffer((uint8_t *)&ctrl_wr, sizeof(struct fw_foiscsi_ctrl_wr));
#endif
	return rc;
}
