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

#ifndef __CSIO_MB_H__
#define __CSIO_MB_H__

#include <csio_defs.h>

#define CSIO_MB_MAX_REGS		8
#define CSIO_MAX_MB_SIZE		64
extern uint8_t csio_os_stage;

#define FW_PARAM_DEV(param) \
	V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) | \
	V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_##param)

#define FW_PARAM_PFVF(param) \
	V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_PFVF) | \
	V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_PFVF_##param)|  \
	V_FW_PARAMS_PARAM_Y(0) | \
	V_FW_PARAMS_PARAM_Z(0)

struct csio_iq_params;
struct csio_eq_params;

/*****************************************************************************/
/* Entry points                                                              */
/*****************************************************************************/
enum dev_state;
enum dev_master;

/* MB Generic Command/Response Helpers */
void
csio_mb_dump_fw_dbg(struct csio_hw *hw, __be64 *cmd);

void csio_mb_ldst(struct fw_ldst_cmd *cmdp, struct csio_hw *, int reg);

void csio_mb_caps_config(struct csio_hw *, struct fw_caps_config_cmd*,
			    bool, int, bool, bool, bool, bool);

void csio_rss_glb_config(struct csio_hw *, struct csio_mb *,
			 uint32_t, uint8_t, unsigned int,
			 void (*)(struct csio_hw *, struct csio_mb *));

void csio_mb_pfvf(struct csio_hw *, struct csio_mb *, uint32_t, 
		  unsigned int, unsigned int, unsigned int, 
		  unsigned int, unsigned int, unsigned int, 
		  unsigned int, unsigned int, unsigned int,
		  unsigned int, unsigned int, unsigned int,
		  unsigned int, void (*) (struct csio_hw *, struct csio_mb *));

void csio_mb_port(struct fw_port_cmd*, uint8_t, bool, uint32_t, uint16_t);

void csio_mb_process_read_port_rsp(struct csio_hw *, struct csio_mb *,
                         enum fw_retval *, uint16_t *);

void csio_mb_initialize(struct csio_hw *, struct csio_mb *, uint32_t,
			void (*)(struct csio_hw *, struct csio_mb *));

void csio_mb_iq_alloc(struct fw_iq_cmd *, struct csio_iq_params *);

void csio_mb_iq_write(struct fw_iq_cmd *, bool, struct csio_iq_params *);

void csio_mb_iq_alloc_write(struct fw_iq_cmd *,	struct csio_iq_params *);

void csio_mb_iq_alloc_write_rsp(struct fw_iq_cmd *, struct csio_iq_params *);

void csio_mb_iq_start_stop(struct fw_iq_cmd *, struct csio_iq_params *);

void csio_mb_iq_free(struct fw_iq_cmd *, struct csio_iq_params *);

void csio_mb_eq_ofld_alloc(struct fw_eq_ofld_cmd *, struct csio_eq_params *);

void csio_mb_eq_ofld_alloc_rsp(struct csio_hw *, struct csio_mb *,
			       enum fw_retval *, struct csio_eq_params *);

void csio_mb_eq_ofld_write(struct fw_eq_ofld_cmd *, bool, 
		struct csio_eq_params *);

void csio_mb_eq_ofld_alloc_write(struct fw_eq_ofld_cmd *, 
		struct csio_eq_params *);

void csio_mb_eq_ofld_alloc_write_rsp(struct fw_eq_ofld_cmd *,
		struct csio_eq_params *);

void csio_mb_eq_ofld_start_stop(struct fw_eq_ofld_cmd *,
		struct csio_eq_params *);

void csio_mb_eq_ofld_free(struct fw_eq_ofld_cmd *, struct csio_eq_params *);

void csio_mb_rdev_read(struct csio_hw *, struct csio_mb *, void *,
		       uint32_t, uint32_t, int,
		       void (*) (struct csio_hw *, struct csio_mb *));

void csio_mb_rdev_read_rsp(struct csio_hw *, struct csio_mb *,
			   enum fw_retval *, void **);

void csio_mb_dcbx_read_port_init_mb(struct fw_port_cmd *, uint8_t, 
		enum fw_port_action, enum fw_port_dcb_type);

/* MB module functions */
csio_retval_t csio_mb_fwevt_handler(struct csio_hw *, __be64 *);
#endif /* ifndef __CSIO_MB_H__ */
