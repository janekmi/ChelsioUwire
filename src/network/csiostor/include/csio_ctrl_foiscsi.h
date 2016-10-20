/*
 * Copyright (C) 2003-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __CSIO_CTRL_FOISCSI_H__
#define __CSIO_CTRL_FOISCSI_H__

#include <csio_trans_foiscsi.h>
#include <csio_os_transutil_foiscsi.h>
#include <csio_foiscsi.h>

#define FOISCSI_IFACE_INVALID_IFID	0
#define MAX_IFACE_SUPPORTED	4

#define CSIO_ISCSI_NUM_LNODES		CSIO_MAX_T4PORTS
#define CSIO_ISCSI_NUM_RNODES		2048
#define CSIO_MAX_TARGETS_PER_BUS	ISCSI_MAX_TARGETS_PER_BUS


struct csio_foiscsi_iface;

struct csio_foiscsi_iface_ipv4 {
    struct csio_foiscsi_iface       *iface;
    unsigned int                    addr;
    unsigned int                    mask;
    unsigned int                    refcnt;
};

struct csio_foiscsi_iface_ipv6 {
    struct csio_foiscsi_iface       *iface;
    unsigned int                    addr[4];
    unsigned int                    prefix_len;
    unsigned int                    refcnt;
};

struct csio_foiscsi_iface_vlan {
    struct csio_foiscsi_iface       *iface;
    unsigned short                  vlan_id;
    struct csio_foiscsi_iface_ipv4  ipv4;
    struct csio_foiscsi_iface_ipv6  ipv6;
};

enum foiscsi_iface_state {
	FOISCSI_IFACE_STATE_LINK_DOWN = 0,
	FOISCSI_IFACE_STATE_LINK_UP = 1,
	FOISCSI_IFACE_STATE_ENABLED = 3,
};

struct csio_foiscsi_iface_linkl {
	struct csio_foiscsi_iface       *iface;
	unsigned short                  vlan_id;
	struct csio_foiscsi_iface_ipv6  ipv6;
	struct csio_foiscsi_iface_ipv6  ipv6_vlan;
};

enum csio_foiscsi_tclient {
	CSIO_FOISCSI_TCLIENT_CLI = 1,
	CSIO_FOISCSI_TCLIENT_BOOT = 2,
	CSIO_FOISCSI_TCLIENT_PERSISTENT = 3,
	CSIO_FOISCSI_TCLIENT_IMA = 4,
};

struct csio_foiscsi_iface {
	unsigned int                    if_id;
	unsigned int                    if_state;
	unsigned int			tclient;
	unsigned short                  mtu;
	unsigned short			old_mtu;
	unsigned int                    gw;
    	unsigned int                    gw6[4];
	unsigned int                    address_state;
	struct csio_hw                  *hw;
	struct csio_t4port              *tport;
	struct csio_lnode               *ln;
	struct csio_foiscsi_iface       *vif;
	struct csio_foiscsi_iface_ipv4  ipv4;
	struct csio_foiscsi_iface_ipv6  ipv6;
	struct csio_foiscsi_iface_vlan  vlan_info;
	struct csio_foiscsi_iface_linkl	link_local;
	/* iface lock TODO replace it with wrapper */
	csio_mutex_t			mlock;	/* lock for iface operation */
	csio_spinlock_t			hlock; /* lock for transport_handle */
	unsigned int op_pending;
	void *transport_handle;
};

struct csio_foiscsi_sess_table {
	struct csio_list	rni_list;
	unsigned int		start;
	unsigned int		last;
	unsigned int		max;
	csio_spinlock_t		tlock;
	unsigned long		*bitmap;
};

struct csio_ctrl_instance {
	/* instance lock TODO replace it with wrapper. */
	csio_mutex_t	inode_lock; /* lock for instance related operation */
	//csio_spinlock_t		hlock; /* lock for transport_handle */
	unsigned int portid;
	unsigned int op_pending;
	void *transport_handle;
};

struct csio_ctrl_foiscsi {
	/* session_map TODO */
	unsigned int			max_init_instances;
	/* following 3 fields are not getting used as of now. */
	unsigned int			max_sessions;
	unsigned int			max_conn_per_sess;
	unsigned int			max_ifaces;
	struct csio_foiscsi_iface	ifaces[MAX_IFACE_SUPPORTED];
	/* TODO Instance structure array [max_instances supported] */
	struct csio_ctrl_instance	instance[FW_FOISCSI_INIT_NODE_MAX];
	struct csio_foiscsi_sess_table	sess_table;
};

struct csio_bootlogin {
	csio_task_struct_t *bootlogin_ts;
	csio_timer_t bootlogin_timer;
	int attempt;
        union {
               struct csio_foiscsi_iface_ioctl iface_req;
               struct csio_foiscsi_ifconf_ioctl ifconf_req;
        } request;
	struct foiscsi_instance ini_inst;
	struct foiscsi_login_info linfo;
};

struct csio_foiscsi_devinst {
	struct csio_list	hlist;
	struct csio_hw 		*hw;
	struct csio_ctrl_foiscsi foiscsi_cdev;
	struct csio_bootlogin  bootlogin;
};

struct csio_foiscsi_devinst* get_foiscsi_inst(struct csio_hw *);


static inline struct csio_ctrl_foiscsi* get_foiscsi_cdev(struct csio_hw *hw)
{
	struct csio_foiscsi_devinst *inst = NULL;

	return ((inst = get_foiscsi_inst(hw)) ? &inst->foiscsi_cdev : NULL);
}

enum csio_oss_error
csio_foiscsi_iface_init(struct csio_hw *hw, int ifid,
				struct csio_foiscsi_iface *iface);

int csio_foiscsi_persistent_login(struct csio_foiscsi_devinst *foiscsi_inst);
int csio_foiscsi_persistent_init(void);

int csio_persistent_check(struct csio_hw *hw, struct iscsi_persistent_target_db *target_db);
int csio_add_persistent_iface(struct csio_hw *hw, struct csio_foiscsi_iface *iface, struct iscsi_persistent_target_db *targetdb);
int csio_add_persistent_instance(struct csio_hw *hw, struct csio_lnode_iscsi *lni, int inode_id, struct iscsi_persistent_target_db *targetdb);
int csio_add_persistent_target_info(struct csio_hw *hw, struct foiscsi_login_info *login, struct iscsi_persistent_target_db *targetdb);
int csio_add_persistent_target(struct csio_hw *hw,
                               struct foiscsi_login_info *login,
                               struct csio_lnode_iscsi *lni,
                               struct csio_foiscsi_iface *iface);

int csio_foiscsi_persistent_show_handler(struct csio_hw *hw,
                                struct iscsi_persistent_target_db *target_db);

int csio_foiscsi_persistent_clear_handler(struct csio_hw *hw, uint8_t idx);

#endif /* END __CSIO_CTRL_FOISCSI_H__ */
