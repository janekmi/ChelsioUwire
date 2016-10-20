/*
 * This file is part of the Chelsio T4 Ethernet driver for Linux.
 *
 * Copyright (C) 2003-2010 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/* This file should not be included directly.  Include common.h instead. */

#ifndef __T4_ADAPTER_H__
#define __T4_ADAPTER_H__
#include <sys/mman.h>
#include <cudbg_if.h>

#define PCIE_BAR0_LENGTH        0x513FF
/*
 * OS Lock/List primitives for those interfaces in the Common Code which
 * need this.
 */
typedef int t4_os_lock_t;
typedef struct t4_os_list {
	int list;
} t4_os_list_t;

enum {                                 /* adapter flags */
   FULL_INIT_DONE   = (1 << 0),
   DEV_ENABLED      = (1 << 1),
   USING_MSI        = (1 << 2),
   USING_MSIX       = (1 << 3),
   FW_OK            = (1 << 4),
   RSS_TNLALLLOOKUP = (1 << 5),
   MASTER_PF        = (1 << 6),
   BYPASS_DROP      = (1 << 7),
   FW_OFLD_CONN     = (1 << 8),
   USING_SRAM       = (1 << 9),
   ADAPTER_ERROR    = (1 << 10),
};

typedef struct adapter adapter_t;

struct adapter {
    void  *regs;
    u32 t4_bar0;
    const char *iff_name;
    unsigned int use_bd;
    unsigned int flags;
    unsigned int mbox;
    unsigned int pf;
    unsigned int vpd_busy;
    uint32_t *bar0;
    unsigned int vpd_flag;

    struct adapter_params params;
    struct port_info *port[MAX_NPORTS];
    

    /* support for single-threading access to adapter mailbox registers */
    t4_os_lock_t mbox_lock;
    t4_os_list_t mbox_list;
};

struct port_info {
    struct adapter *adapter;
    u16    viid;
    s16    xact_addr_filt;		/* index of exact MAC address filter */
    u16    rss_size;		/* size of VI's RSS table slice */
    s8     mdio_addr;		/* address of the PHY */
    u8     port_type;		/* firmware port type */
    u8     mod_type;		/* firmware module type */
    u8     port_id;			/* physical port ID */
    u8     tx_chan;
    u8     lport;			/* associated offload logical port */
    u8     rss_mode;
    u8     dev_port;

    struct link_config link_cfg;
};


#if 0
/**
 * t4_read_reg - read a HW register
 * @adapter: the adapter
 * @reg_addr: the register address
 *
 * Returns the 32-bit value of the given HW register.
 */
static inline u32 t4_read_reg(adapter_t *adapter, u32 reg_addr)
{
    /* consumer has to fill this */
    return 0;

}

/**
 * t4_write_reg - write a HW register
 * @adapter: the adapter
 * @reg_addr: the register address
 * @val: the value to write
 *
 * Write a 32-bit value into the given HW register.
 */
static inline void t4_write_reg(adapter_t *adapter, u32 reg_addr, u32 val)
{
    /* consumer has to fill this */
}


/**
 * t4_read_reg64 - read a 64-bit HW register
 * @adapter: the adapter
 * @reg_addr: the register address
 *
 * Returns the 64-bit value of the given HW register.
 */
static inline u64 t4_read_reg64(adapter_t *adapter, u32 reg_addr)
{
    /* consumer has to fill this */
    return 0;
}

/**
 * t4_write_reg64 - write a 64-bit HW register
 * @adapter: the adapter
 * @reg_addr: the register address
 * @val: the value to write
 *
 * Write a 64-bit value into the given HW register.
 */
static inline void t4_write_reg64(adapter_t *adapter, u32 reg_addr, u64 val)
{
     /* consumer has to fill this */
}

#endif

/**
 * t4_os_pci_write_cfg4 - 32-bit write to PCI config space
 * @adapter: the adapter
 * @reg: the register address
 * @val: the value to write
 *
 * Write a 32-bit value into the given register in PCI config space.
 */
static inline void t4_os_pci_write_cfg4(adapter_t *adapter, int reg, u32 val)
{
    /* consumer has to fill this */
}

/**
 * t4_os_pci_read_cfg4 - read a 32-bit value from PCI config space
 * @adapter: the adapter
 * @reg: the register address
 * @val: where to store the value read
 *
 * Read a 32-bit value from the given register in PCI config space.
 */
static inline void t4_os_pci_read_cfg4(adapter_t *adapter, int reg, u32 *val)
{
    /* consumer has to fill this */
}

/**
 * t4_os_pci_write_cfg2 - 16-bit write to PCI config space
 * @adapter: the adapter
 * @reg: the register address
 * @val: the value to write
 *
 * Write a 16-bit value into the given register in PCI config space.
 */
static inline void t4_os_pci_write_cfg2(adapter_t *adapter, int reg, u16 val)
{
    /* consumer has to fill this */
}

/**
 * t4_os_pci_read_cfg2 - read a 16-bit value from PCI config space
 * @adapter: the adapter
 * @reg: the register address
 * @val: where to store the value read
 *
 * Read a 16-bit value from the given register in PCI config space.
 */
static inline void t4_os_pci_read_cfg2(adapter_t *adapter, int reg, u16 *val)
{
    /* consumer has to fill this */
}

/**
 * t4_os_find_pci_capability - lookup a capability in the PCI capability list
 * @adapter: the adapter
 * @cap: the capability
 *
 * Return the address of the given capability within the PCI capability list.
 */
static inline int t4_os_find_pci_capability(adapter_t *adapter, int cap)
{
    /* consumer has to fill this */
    return 0;
}

/**
 * t4_os_pci_read_seeprom - read four bytes of SEEPROM/VPD contents
 * @adapter: the adapter
 * @addr: SEEPROM/VPD Address to read
 * @valp: where to store the value read
 *
 * Read a 32-bit value from the given address in the SEEPROM/VPD.  The address
 * must be four-byte aligned.  Returns 0 on success, a negative erro number
 * on failure.
 */
static inline int t4_os_pci_read_seeprom(adapter_t *adapter,
        int addr, u32 *valp)
{
    /* consumer has to fill this */
    return 0;
}

/**
 * t4_os_pci_write_seeprom - write four bytes of SEEPROM/VPD contents
 * @adapter: the adapter
 * @addr: SEEPROM/VPD Address to write
 * @val: the value write
 *
 * Write a 32-bit value to the given address in the SEEPROM/VPD.  The address
 * must be four-byte aligned.  Returns 0 on success, a negative erro number
 * on failure.
 */
static inline int t4_os_pci_write_seeprom(adapter_t *adapter,
        int addr, u32 val)
{
    /* consumer has to fill this */
    return 0;
}

/**
 * adap2pinfo - return the port_info of a port
 * @adap: the adapter
 * @idx: the port index
 *
 * Return the port_info structure for the port of the given index.
 */
static inline struct port_info *adap2pinfo(struct adapter *adap, int idx)
{
    /* consumer has to fill this */
    return (adap->port[idx]);
}

static inline void t4_os_lock(t4_os_lock_t *lock)
{
    /* consumer has to fill this */
}

/**
 * t4_os_unlock - unlock a spinlock
 * @lock: the spinlock
 */
static inline void t4_os_unlock(t4_os_lock_t *lock)
{
    /* consumer has to fill this */
}

/**
 * t4_os_init_list_head - initialize
 * @head: head of list to initialize [to empty]
 */

static inline struct t4_os_list *t4_os_list_first_entry(t4_os_list_t *head)
{
    /* consumer has to fill this */
    return 0;
}

/**
 * t4_os_atomic_add_tail - Enqueue list element atomically onto list
 * @new: the entry to be addded to the queue
 * @head: current head of the linked list
 * @lock: lock to use to guarantee atomicity
 */
static inline void t4_os_atomic_add_tail(t4_os_list_t *new,
    t4_os_list_t *head, t4_os_lock_t *lock)
{
    t4_os_lock(lock);
    /* consumer has to fill this */
    t4_os_unlock(lock);
}

/**
 * t4_os_atomic_list_del - Dequeue list element atomically from list
 * @entry: the entry to be remove/dequeued from the list.
 * @lock: the spinlock
 */
static inline void t4_os_atomic_list_del(t4_os_list_t *entry,
        t4_os_lock_t *lock)
{
    t4_os_lock(lock);
    /* consumer has to fill this */
    t4_os_unlock(lock);
}


static inline void *t4_alloc_mem(size_t size)
{
    /* consumer has to fill this */
    return NULL;
}

static void t4_free_mem(void *addr)
{
    /* consumer has to fill this */
}

static inline void msleep( u32 _msecs )
{
    usleep(_msecs * 1000);
}

#if 0
static inline void usleep(u32  _msecs )
{
    /* consumer has to fill this */
}
#endif
static inline void udelay(u32  _msecs )
{
    /* consumer has to fill this */
}

static inline void mdelay(u32  _msecs )
{
    /* consumer has to fill this */
}

static inline unsigned int t4_use_ldst(adapter_t *adap)
{
        return (adap->flags & FW_OK) || (!adap->use_bd);
}

/* commuser defined functions */

extern void err (int __status, __const char *__format, ...)
    __attribute__ ((__noreturn__, __format__ (__printf__, 2, 3)));
    /*
     *  * Determines whether the entity a command is to be run on is a device name or
     *   * a file path.  The distinction is simplistic: it's a file path if it contains
     *    * '/'.
     *     */
static int is_file(const char *s)
{
    return strchr(s, '/') != NULL;
}

static uint32_t *mmap_bar0(adapter_t *adap, size_t len, int prot)
{
    int fd;
    char fname[256];

    if (strchr(adap->iff_name, ':') != NULL)
        /*
         ** iff_name == /sys/devices/pci0000\:00/0000:00:04.0/0000:08:00.0
         **/
        snprintf(fname, sizeof(fname), "%s/resource0", adap->iff_name);
    else if (strchr(adap->iff_name, '/') != NULL)
        /*
         ** iff_name == /sys/class/net/ethX
         **/
        snprintf(fname, sizeof(fname), "%s/device/resource0", adap->iff_name);
    else
        /*
         ** iff_name = ethX
         **/
        snprintf(fname, sizeof(fname),
                "/sys/class/net/%s/device/resource0", adap->iff_name);

    fd = open(fname, (prot & PROT_WRITE) ? O_RDWR : O_RDONLY);
    if (fd < 0)
        return NULL;
    adap->bar0 = mmap(NULL, len, prot, MAP_SHARED, fd, 0);
    close(fd);

    adap->bar0 = (adap->bar0 == MAP_FAILED) ? NULL : adap->bar0;
    return adap->bar0;
}

static void write_reg_mmap(adapter_t *adap, u32 addr, u64 val, int s)
{
    u64 *bar0_64;

    if(!s)
    {
        val = (u32) val;
        adap->bar0[addr / 4] = htole32(val);
    } else {
        bar0_64 = (u64 *)adap->bar0;
        bar0_64[addr / 8] = htole64(val);
    }
}

static u64 read_reg_mmap(adapter_t *adap, uint32_t addr, int s)
{
    u32 val;
    u64 val64, *bar0_64;

    if (!s)
    {
        val = adap->bar0[addr / 4];
        return le32toh(val);
    } else {
        bar0_64 = (u64 *)adap->bar0;
        val64 = bar0_64[addr / 8];
        return le64toh(val64);

    }
}

static u64 t4_read_reg64(struct adapter *adap, uint32_t addr)
{
    const char * iff_name = adap->iff_name;

    if (is_file(iff_name))
        return read_reg_mmap(adap, addr, 1);
    else
        return read_reg_mmap(adap, addr, 1);
}

static uint32_t t4_read_reg(struct adapter *adap, uint32_t addr)
{
    const char * iff_name = adap->iff_name;

    if (is_file(iff_name))
        return read_reg_mmap(adap, addr, 0);
    else
        return read_reg_mmap(adap, addr, 0);
}

static void t4_write_reg64(struct adapter *adap, uint32_t addr, u64 val)
{
    const char * iff_name = adap->iff_name;

    if (is_file(iff_name))
        write_reg_mmap(adap, addr, val, 1);
    else
        write_reg_mmap(adap, addr, val, 1);
}

static void t4_write_reg(struct adapter *adap, u32 addr, u32 val)
{
    const char * iff_name = adap->iff_name;

    if (is_file(iff_name))
        write_reg_mmap(adap, addr, val, 0);
    else
        write_reg_mmap(adap, addr, val, 0);
}

static int set_mbox(struct adapter  *adap)
{
    adap->mbox = 4;
    adap->pf = 4;
    return 0;
}

int t4_query_params(struct adapter *adap, unsigned int mbox, unsigned int pf,
                    unsigned int vf, unsigned int nparams, const u32 *params,
                    u32 *val);
static int set_adapter_fields(adapter_t **adapter, const char *iff_name)
{
    adapter_t *padap;
    u32 pl_rev, cclk_param, cclk_val;
    int rc = 0;

    *adapter = (adapter_t *) malloc(sizeof(adapter_t));

    if (*adapter == NULL)
    {
        rc = -2 /* CUDBG_STATUS_NOSPACE */;
        goto err;
    }

    padap = *adapter;
    memset(padap, 0, sizeof(adapter_t));

    padap->iff_name = iff_name;

    mmap_bar0(padap, PCIE_BAR0_LENGTH, PROT_READ | PROT_WRITE);
    if (padap->bar0 == NULL)
        return CUDBG_STATUS_MMAP_FAILED;

    pl_rev = G_REV(t4_read_reg((*adapter), A_PL_REV));
    padap->params.chip |=  CHELSIO_CHIP_CODE(CHELSIO_T5, pl_rev);

    if (is_fpga((*adapter)->params.chip)) {
        /* FPGA */
        (*adapter)->params.cim_la_size = 2 * CIMLA_SIZE;
    } else {
        /* ASIC */
        (*adapter)->params.cim_la_size = CIMLA_SIZE;
    }

    padap->use_bd = 1; /* enable back door access*/
    padap->params.arch.vfcount = 128;
    padap->params.arch.nchan = NCHAN;
    padap->params.arch.mps_tcam_size =
                            NUM_MPS_T5_CLS_SRAM_L_INSTANCES;
    padap->params.arch.mps_rplc_size = 128; 
    padap->params.arch.pm_stats_cnt = PM_NSTATS;

    cclk_param = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
            V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_CCLK));
    rc = t4_query_params(padap, padap->mbox, padap->pf, 0, 1,
            &cclk_param, &cclk_val);
    padap->params.vpd.cclk = cclk_val;
    if(rc) {
        printf("Failed to collect t4_query_params() rc %d\n", rc);
    }
    rc = set_mbox(*adapter);
err:
    return rc;
}

static void put_adapter_fields(adapter_t **adapter)
{
    if ((*adapter) && (*adapter)->bar0)
    {
        munmap((*adapter)->bar0, PCIE_BAR0_LENGTH);
        (*adapter)->bar0 = NULL;
    }
    if(*adapter)
    {
        free(*adapter);
        *adapter = NULL;
    }
}

static inline void t4_db_full(struct adapter *adap) {}
static inline void t4_db_dropped(struct adapter *adap) {}
static void t4_fatal_err( adapter_t * _pAdapter ) {}
#define t4_os_alloc(_size)	t4_alloc_mem((_size))
static void t4_os_portmod_changed(const struct adapter *adap, int port_id){}
static void t4_os_link_changed(struct adapter *adap, int port_id, int link_stat){}
#define t4_os_free(_ptr)	t4_free_mem((_ptr))
static inline void t4_os_set_hw_addr(adapter_t *adapter, int port_idx,
        u8 hw_addr[]){}
#endif /* __T4_ADAPTER_H__ */
