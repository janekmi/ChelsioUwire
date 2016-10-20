#ifndef __CUDBG_VIEW_H__
#define __CUDBG_VIEW_H__

#include <cudbg_lib_common.h>
#if defined(WIN32) || defined(__NT__) || defined(_WIN32) || defined(__WIN32__)
typedef boolean_t bool;
#endif

static int view_cim_q(char *, u32, struct cudbg_buffer *);
static int view_cim_la(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_reg_dump(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_cim_qcfg(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_mc0_data(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_mc1_data(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_fw_devlog(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_cim_ma_la(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_edc0_data(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_edc1_data(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_cim_obq_sge(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_cim_ibq_tp0(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_cim_obq_ulp0(char *, u32, struct cudbg_buffer *,
			     enum chip_type);
static int view_cim_obq_ulp1(char *, u32, struct cudbg_buffer *,
			     enum chip_type);
static int view_cim_obq_ulp2(char *, u32, struct cudbg_buffer *,
			     enum chip_type);
static int view_cim_obq_ulp3(char *, u32, struct cudbg_buffer *,
			     enum chip_type);
static int view_cim_obq_ncsi(char *, u32, struct cudbg_buffer *,
			     enum chip_type);
static int view_rss(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_rss_pf_config(char *, u32, struct cudbg_buffer *,
			      enum chip_type);
static int view_rss_key(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_rss_vf_config(char *, u32, struct cudbg_buffer *,
			      enum chip_type);
static int view_rss_config(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_path_mtu(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_sw_state(char *, u32, struct cudbg_buffer *, enum chip_type);
int view_wtp(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_pm_stats(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_tcp_stats(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_hw_sched(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_tp_err_stats_show(char *, u32, struct cudbg_buffer *,
				  enum chip_type);
static int view_fcoe_stats(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_rdma_stats(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_tp_indirect(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_sge_indirect(char *, u32, struct cudbg_buffer *,
			     enum chip_type);
static int view_cpl_stats(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_ddp_stats(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_wc_stats(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_ulprx_la(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_lb_stats(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_tp_la(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_meminfo(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_cim_pif_la(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_clk_info(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_cim_obq_sge_rx_q0(char *, u32, struct cudbg_buffer *,
				  enum chip_type);
static int view_cim_obq_sge_rx_q1(char *, u32, struct cudbg_buffer *,
				  enum chip_type);
static int view_macstats(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_pcie_indirect(char *, u32, struct cudbg_buffer *,
			      enum chip_type);
static int view_pm_indirect(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_full(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_tx_rate(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_tid(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_pcie_config(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_dump_context(char *, u32, struct cudbg_buffer *,
			     enum chip_type);
static int view_mps_tcam(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_vpd_data(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_le_tcam(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_cctrl(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_ma_indirect(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_ulptx_la(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_ext_entity(char *, u32, struct cudbg_buffer *, enum chip_type);
static int view_up_cim_indirect(char *, u32, struct cudbg_buffer *,
				enum chip_type);
static int view_pbt_tables(char *, u32, struct cudbg_buffer *,
			   enum chip_type);
static int view_mbox_log(char *, u32, struct cudbg_buffer *,
			 enum chip_type);

static int (*view_entity[]) (char *, u32, struct cudbg_buffer *,
			     enum chip_type) = {
	view_reg_dump,
	view_fw_devlog,
	view_cim_la,
	view_cim_ma_la,
	view_cim_qcfg,
	view_cim_ibq_tp0,
	view_cim_ibq_tp0,
	view_cim_ibq_tp0,
	view_cim_ibq_tp0,
	view_cim_ibq_tp0,
	view_cim_ibq_tp0,
	view_cim_obq_ulp0,
	view_cim_obq_ulp1,
	view_cim_obq_ulp2,
	view_cim_obq_ulp3,
	view_cim_obq_sge,
	view_cim_obq_ncsi,
	view_edc0_data,
	view_edc1_data,
	view_mc0_data,
	view_mc1_data,
	view_rss,	    /*22*/
	view_rss_pf_config, /*23*/
	view_rss_key,	    /*24*/
	view_rss_vf_config,
	view_rss_config,
	view_path_mtu,
	view_sw_state,
	view_wtp,
	view_pm_stats,
	view_hw_sched,
	view_tcp_stats,
	view_tp_err_stats_show,
	view_fcoe_stats,
	view_rdma_stats,
	view_tp_indirect,
	view_sge_indirect,
	view_cpl_stats,
	view_ddp_stats,
	view_wc_stats,
	view_ulprx_la,
	view_lb_stats,
	view_tp_la,
	view_meminfo,
	view_cim_pif_la,
	view_clk_info,
	view_cim_obq_sge_rx_q0,
	view_cim_obq_sge_rx_q1,
	view_macstats,
	view_pcie_indirect,
	view_pm_indirect,
	view_full,
	view_tx_rate,
	view_tid,
	view_pcie_config,
	view_dump_context,
	view_mps_tcam,
	view_vpd_data,
	view_le_tcam,
	view_cctrl,
	view_ma_indirect,
	view_ulptx_la,
	view_ext_entity,
	view_up_cim_indirect,
	view_pbt_tables,
	view_mbox_log,
};

struct reg_info {
	const char *name;
	uint32_t addr;
	uint32_t len;
};

struct mod_regs {
	const char *name;
	const struct reg_info *ri;
	unsigned int offset;
};

static const char *yesno(int);
void translate_fw_devlog(void *, u32, u32 *, u32 *);
#define BIT(n)	(1U << n)

#endif

