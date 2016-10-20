#include <endian.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <byteswap.h>
#include <inttypes.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/sockios.h>
#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <dirent.h>

#include "cxgbtool.h"
#ifdef STORAGE
#include "cxgbtool_stor.h"
#ifdef __CSIO_FOISCSI_ENABLED__
#include "cxgbtool_foiscsi_stor.h"
#endif
#endif

/* Define types for <linux/mii.h> and ethtool-copy.h */
/* Hack so we may include the kernel's ethtool.h */
typedef __uint8_t	u8;
typedef __uint16_t	u16;
typedef __uint32_t	u32;
typedef unsigned long long u64;

/*
 * Some <linux/mii.h> headers will include <linux/if.h> which redefines
 * ifmap, ifreq, and ifconf structures from <net/if.h>.
 * Work around for this nuisance.
 */
#define _LINUX_IF_H

#include <linux/mii.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ethtool-copy.h"
#include "version.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define in_range(val, lo, hi) ( val < 0 || (val <= hi && val >= lo))

#ifndef htole32                        /* old glibc || !_BSD_SOURCE */
# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define htole32(x) (x)
#  define le32toh(x) (x)
#  define htole64(x) (x)
#  define le64toh(x) (x)
# else
#  define htole32(x) __bswap_32 (x)
#  define le32toh(x) __bswap_32 (x)
#  define htole64(x) __bswap_64 (x)
#  define le64toh(x) __bswap_64 (x)
# endif
#endif

#define PROTO_SRAM_LINES 128
#define PROTO_SRAM_LINE_BITS 132
#define PROTO_SRAM_LINE_NIBBLES (132 / 4)
#define PROTO_SRAM_SIZE (PROTO_SRAM_LINE_NIBBLES * PROTO_SRAM_LINES / 2)
#define PROTO_SRAM_EEPROM_ADDR 4096

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

struct field_desc {
	const char *name;     /* field name */
	unsigned short start; /* start bit position */
	unsigned short end;   /* end bit position */
	unsigned char shift;  /* # of low-order bits omitted and implicitly 0 */
	unsigned char hex;    /* print field in hex instead of decimal */
	unsigned char islog2; /* field contains the base-2 log of the value */
};

struct toetool_proto {
	uint32_t cmd;
	uint32_t data[5 * 128];
};

#include "reg_defs.c"
#include "reg_defs_t3.c"
#include "reg_defs_t3b.c"
#include "reg_defs_t3c.c"
#include "reg_defs_t4.c"
#include "reg_defs_t5.c"
#include "reg_defs_t6.c"
#include "reg_defs_t4vf.c"

static const char *progname;

static int fd = -1;   /* control socket file descriptor */

static void __attribute__((noreturn)) usage(FILE *fp)
{
	fprintf(fp, "Usage: %s <interface> [operation]\n", progname);
	fprintf(fp,
#ifdef CHELSIO_T4_DIAGS
		"\tclearflash                          clear all flash sectors\n"
#endif
		"\tclearstats [port|queue [<N>]]       clear selected statistics\n"
		"\tcontext <type> <id>                 show an SGE context\n"
		"\tdesc <qset> <queue> <idx> [<cnt>]   dump SGE descriptors\n"
		"\tdriver-file [<file>]                dump contents of driver files\n"
		"\tfilter <idx> [<param> <val>] ...    set a filter\n"
		"\tfilter <idx> delete|clear           delete a filter\n"
		"\tfilter show                         display set filters\n"
		"\teeprom <offset> <EEPROM image>      write to EEPROM\n"
		"\tloadfw <FW image>                   download firmware\n"
		"\tloadcfg <FW CFG text file>          download firmware config file\n"
		"\tloadphy <PHY FW image>              download phy firmware\n"
		"\tloadboot <boot image> \n"
		"\t     [pf|offset <val>]              download boot image\n"
		"\tloadboot-cfg <BOOT CFG binary file> download boot config file\n"
		"\tlro on|off                          enable/disable lro for all queues\n"
		"\tmdio <phy_addr> <mmd_addr>\n"
		"\t     <reg_addr> [<val>]             read/write MDIO register\n"
		"\ti2c <port> <devid> <offset> <len>\n"
		"\t     [<byte(s)>]                    read/write I2C device\n"
		"\tmemdump cm|tx|rx|flash <addr> <len> dump a mem range\n"
		"\tmeminfo                             show memory info\n"
		"\tmtus [<mtu0>...<mtuN>]              read/write MTU table\n"
		"\tnapi on|off                         enable/disable napi for all queues\n"
		"\tpktsched port <idx> <min> <max>     set TX port scheduler params\n"
		"\tpktsched tunnelq <idx> <max>        set TX tunnelq scheduler params\n"
		"\tpktsched tx <idx>\n"
		"\t         [<param> <val>] ...        set Tx HW scheduler\n"
		"\tsched-class [<param> <val>]         configure TX scheduler class\n"
		"\tsched-queue <queue> <class>         bind NIC queues to TX Scheduling class\n"
		"\tsched-pfvf <pf> <vf> <class>        bind PF/VF NIC queues to TX Scheduling class\n"
		"\tpm [<TX page spec> <RX page spec>]  read/write PM config\n"
		"\tpolicy <offload policy>             set offload policy\n"
		"\tproto                               dump proto SRAM\n"
		"\tqdesc <type> <qid> <idx> [<cnt>]    dump SGE descriptors\n"
		"\tqset [<index> [<param> <val>] ...]  read/write qset parameters\n"
		"\tqintr <qid> [[<param> <val>] ...]   read/write response queue interrupt coalescing parameters\n"
		"\tqsets [<# of qsets>]                read/write # of qsets\n"
		"\tqtype-num <type> [<# of qsets>]     read/write # of offload qsets\n"
		"\treg <address>[=<val>]               read/write register\n"
		"\tregdump [<module>]                  dump registers\n"
		"\ttcamdump <address> <count>          show TCAM entry\n"
		"\ttcb <index>                         read TCB\n"
		"\ttrace tx|rx|all on|off [not]\n"
		"\t      [<param> <val>[:<mask>]] ...  write trace parameters\n"
		"\ttrace tx|rx|all                     read trace parameters\n"
		"\tioqs                                dump uP ioqs\n"
		"\tla                                  dump uP logic analyzer info\n"
		"\tup                                  activate TOE\n"
		"\twdtoe stats [pid]                   dump WireDirect TCP statistics\n"
		"\twdudp stats [pid]                   dump WireDirect UDP statistics\n"
/* Unsupported
		"\ttcam [<#serv> <#routes> <#filters>] read/write TCAM config\n"
		"\ttpi <address>[=<val>]               read/write TPI register\n"
*/
#ifdef STORAGE
		"\n[ Storage ]\n\n"
#ifdef __CSIO_FOISCSI_ENABLED__
		"\tstor --foiscsi                      access iSCSI subcommands\n"
#endif
#endif
		);
	exit(fp == stderr ? 1 : 0);
}

/*
 * Extract the card version from a version word.
 */
static inline unsigned int get_card_vers(unsigned int version)
{
	return version & 0x3ff;
}

static inline unsigned int max(unsigned int a, unsigned int b)
{
	return a >= b ? a : b;
}

/*
 * Make an ethtool ioctl call.
 */
static int ethtool_call(const char *iff_name, void *data)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iff_name, sizeof(ifr.ifr_name) - 1);
	ifr.ifr_data = data;
	return ioctl(fd, SIOCETHTOOL, &ifr) < 0 ? -1 : 0;
}

static int get_drv_info(const char *iff_name,
		   struct ethtool_drvinfo *drvinfo)
{
	drvinfo->cmd = ETHTOOL_GDRVINFO;
	return ethtool_call(iff_name, drvinfo);
}

static int get_adapter_ver(const char *iff_name)
{
	struct ethtool_regs regs = {0};

	regs.cmd = ETHTOOL_GREGS;
	if (ethtool_call(iff_name, &regs))
		err(1, "can't read registers");

	return get_card_vers(regs.version);
}

static void get_pci_bus_slot_func(const char *iff_name, char *buf, int len)
{
	struct ethtool_drvinfo drvinfo;

	if (get_drv_info(iff_name, &drvinfo))
		err(1, "can't get driver info");
	strncpy(buf, drvinfo.bus_info, len);
	return;
}

/*
 * Make a TOETOOL ioctl call.
 */
static int doit(const char *iff_name, void *data)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iff_name, sizeof(ifr.ifr_name) - 1);
	ifr.ifr_data = data;
	return ioctl(fd, SIOCCHIOCTL, &ifr) < 0 ? -1 : 0;
}

static int get_int_arg(const char *s, uint32_t *valp)
{
	char *p;

	*valp = strtoul(s, &p, 0);
	if (*p) {
		warnx("bad parameter \"%s\", integer expected", s);
		return -1;
	}
	return 0;
}

/*
 * Determines whether the entity a command is to be run on is a device name or
 * a file path.  The distinction is simplistic: it's a file path if it contains
 * '/'.
 */
static int is_file(const char *s)
{
	return strchr(s, '/') != NULL;
}

/*
 * Register I/O through mmap of BAR0.
 */
static uint32_t *mmap_bar0(const char *iff_name, size_t len, int prot)
{
	int fd;
	uint32_t *bar0;
	char fname[256];

	if (strchr(iff_name, ':') != NULL)
		/*
		 * iff_name == /sys/devices/pci0000\:00/0000:00:04.0/0000:08:00.0
		 */
		snprintf(fname, sizeof(fname), "%s/resource0", iff_name);
	else if (strchr(iff_name, '/') != NULL)
		/*
		 * iff_name == /sys/class/net/ethX
		 */
		snprintf(fname, sizeof(fname), "%s/device/resource0", iff_name);
	else
		/*
		 * iff_name = ethX
		 */
		snprintf(fname, sizeof(fname),
				"/sys/class/net/%s/device/resource0", iff_name);

	fd = open(fname, (prot & PROT_WRITE) ? O_RDWR : O_RDONLY);
	if (fd < 0)
		return NULL;

	bar0 = mmap(NULL, len, prot, MAP_SHARED, fd, 0);
	close(fd);
	return bar0 == MAP_FAILED ? NULL : bar0;
}

static uint32_t read_reg_mmap(const char *iff_name, uint32_t addr)
{
	uint32_t val, *bar0;

	bar0 = mmap_bar0(iff_name, addr + 4, PROT_READ);
	if (!bar0)
		err(1, "register read");

	val = bar0[addr / 4];
	munmap(bar0, addr + 4);
	return le32toh(val);
}

static void write_reg_mmap(const char *iff_name, uint32_t addr, uint32_t val)
{
	uint32_t *bar0 = mmap_bar0(iff_name, addr + 4, PROT_WRITE);

	if (!bar0)
		err(1, "register write");

	bar0[addr / 4] = htole32(val);
	munmap(bar0, addr + 4);
}

static uint32_t read_reg(const char *iff_name, uint32_t addr)
{
	struct ch_reg op = {
		.cmd = CHELSIO_GETREG,
		.addr = addr
	};

	if (is_file(iff_name))
		return read_reg_mmap(iff_name, addr);
	if (doit(iff_name, &op) == 0)
		return op.val;
	if (errno == EOPNOTSUPP)
		return read_reg_mmap(iff_name, addr);
	err(1, "register read");
}

static void write_reg(const char *iff_name, uint32_t addr, uint32_t val)
{
	struct ch_reg op = {
		.cmd = CHELSIO_SETREG,
		.addr = addr,
		.val = val
	};

	if (is_file(iff_name))
		write_reg_mmap(iff_name, addr, val);
	else if (doit(iff_name, &op) < 0) {
		if (errno != EOPNOTSUPP)
			err(1, "register write");
		write_reg_mmap(iff_name, addr, val);
	}
}

static int register_io(int argc, char *argv[], int start_arg,
		       const char *iff_name)
{
	char *p;
	uint32_t addr, val = 0, write = 0;

	if (argc != start_arg + 1) return -1;

	addr = strtoul(argv[start_arg], &p, 0);
	if (p == argv[start_arg]) return -1;
	if (*p == '=' && p[1]) {
		val = strtoul(p + 1, &p, 0);
		write = 1;
	}
	if (*p) {
		warnx("bad parameter \"%s\"", argv[start_arg]);
		return -1;
	}

	if (write)
		write_reg(iff_name, addr, val);
	else {
		val = read_reg(iff_name, addr);
		printf("%#x [%u]\n", val, val);
	}
	return 0;
}

#if 0 /* Unsupported */
static int tpi_io(int argc, char *argv[], int start_arg, const char *iff_name)
{
	char *p;
	struct ch_reg op;

	if (argc != start_arg + 1) return -1;

	op.cmd = CHELSIO_GETTPI;
	op.addr = strtoul(argv[start_arg], &p, 0);
	if (p == argv[start_arg]) return -1;
	if (*p == '=' && p[1]) {
		op.val = strtoul(p + 1, &p, 0);
		op.cmd = CHELSIO_SETTPI;
	}
	if (*p) {
		warnx("bad parameter \"%s\"", argv[start_arg]);
		return -1;
	}

	if (doit(iff_name, &op) < 0)
		err(1, "TPI register %s",
		    op.cmd == CHELSIO_GETTPI ? "read" : "write");
	if (op.cmd == CHELSIO_GETTPI)
		printf("%#x [%u]\n", op.val, op.val);
	return 0;
}
#endif

static int mdio_io(int argc, char *argv[], int start_arg, const char *iff_name)
{
	/*
	 * Use char buf to avoid annoying compiler "does break
	 * strict-aliasing" warnings.  We know what we're doing here.
	 */
	char buf[sizeof(struct ifreq)];
	struct ifreq *ifr = (struct ifreq *)buf;
	struct mii_ioctl_data *p =
		(void *)(buf + offsetof(struct ifreq, ifr_ifru));
	unsigned int cmd, phy_addr, reg, mmd, val = 0;

	if (argc == start_arg + 3)
		cmd = SIOCGMIIREG;
	else if (argc == start_arg + 4)
		cmd = SIOCSMIIREG;
	else
		return -1;

	if (get_int_arg(argv[start_arg], &phy_addr) ||
	    get_int_arg(argv[start_arg + 1], &mmd) ||
	    get_int_arg(argv[start_arg + 2], &reg) ||
	    (cmd == SIOCSMIIREG && get_int_arg(argv[start_arg + 3], &val)))
		return -1;

	memset(ifr, 0, sizeof(struct ifreq));
	strncpy(ifr->ifr_name, iff_name, sizeof(ifr->ifr_name) - 1);
	p->phy_id  = phy_addr | (mmd << 8);
	p->reg_num = reg;
	p->val_in  = val;

	if (ioctl(fd, cmd, ifr) < 0)
		err(1, "MDIO %s", cmd == SIOCGMIIREG ? "read" : "write");
	if (cmd == SIOCGMIIREG)
		printf("%#x [%u]\n", p->val_out, p->val_out);
	return 0;
}

static int i2c_io(int argc, char *argv[], int start_arg, const char *iff_name)
{
	struct ch_i2c_data *op;
	size_t oplen;
	unsigned int cmd, port, devid, offset, len, bytes, i;

	/*
	 * We need at least: port, device ID, offset and len ...
	 */
	if (argc - start_arg < 4)
		errx(1, "too few arguments");
	bytes = argc - start_arg - 4;
	cmd = (bytes == 0
	       ? CHELSIO_GET_I2C_DATA
	       : CHELSIO_SET_I2C_DATA);

	
	/*
	 * Parse base parameters.
	 */
	if (strcmp(argv[start_arg], "none") == 0 ||
	    strcmp(argv[start_arg], "-") == 0)
		port = ~0;
	else if (get_int_arg(argv[start_arg], &port))
			errx(1, "invalid port specification");

	if (get_int_arg(argv[start_arg + 1], &devid) ||
	    get_int_arg(argv[start_arg + 2], &offset) ||
	    get_int_arg(argv[start_arg + 3], &len) ||
	    len == 0)
		errx(1, "invalid device/offset/len specification");;
	if (bytes && bytes != len)
		errx(1, "must provide all bytes being written");

	/*
	 * Now that we know the amount of data that we're transfering, we can
	 * allocate our command and initialize it
	 */
	oplen = sizeof (struct ch_i2c_data) + len;
	op = (struct ch_i2c_data *)malloc(oplen);
	if (op == NULL)
		errx(1, "can't allocate %lu bytes", (unsigned long)oplen);
	memset(op, 0, oplen);
	op->cmd = cmd;
	op->port = port;
	op->devid = devid;
	op->offset = offset;
	op->len = len;

	/*
	 * If this is a write command, collect the I2C data bytes.
	 */
	for (i = 0; i < bytes; i++) {
		const char *arg = argv[start_arg + 4 + i];
		unsigned int byte;

		if (get_int_arg(arg, &byte))
			errx(1, "invalid byte specification: %s", arg);
		if (byte >= 256)
			errx(1, "byte value out of range: %s", arg);
		op->data[i] = byte;
			    
	}

	if (doit(iff_name, op) < 0)
		err(1, "i2c %s", bytes ? "write" : "read");

	/*
	 * If this is a read command, display the requested bytes.
	 */
	if (bytes == 0)
		for (i = 0; i < len; i++)
			printf("I2C data[%d] = %#x [%u]\n", i,
			       op->data[i], op->data[i]);

	free(op);
	return 0;
}

static inline uint32_t xtract(uint32_t val, int shift, int len)
{
	return (val >> shift) & ((1 << len) - 1);
}

static int dump_block_regs(const struct reg_info *reg_array, const u32 *regs)
{
	uint32_t reg_val = 0; // silence compiler warning

	for ( ; reg_array->name; ++reg_array)
		if (!reg_array->len) {
			reg_val = regs[reg_array->addr / 4];
			printf("[%#7x] %-47s %#-10x %u\n", reg_array->addr,
			       reg_array->name, reg_val, reg_val);
		} else {
			uint32_t v = xtract(reg_val, reg_array->addr,
					    reg_array->len);

			printf("    %*u:%u %-47s %#-10x %u\n",
			       reg_array->addr < 10 ? 3 : 2,
			       reg_array->addr + reg_array->len - 1,
			       reg_array->addr, reg_array->name, v, v);
		}
	return 1;
}

static int dump_regs_table(int argc, char *argv[], int start_arg,
			   const u32 *regs, const struct mod_regs *modtab,
			   int nmodules, const char *modnames)
{
	int match = 0;
	const char *block_name = NULL;

	if (argc == start_arg + 1)
		block_name = argv[start_arg];
	else if (argc != start_arg)
		return -1;

	for ( ; nmodules; nmodules--, modtab++)
		if (!block_name || !strcmp(block_name, modtab->name))
			match += dump_block_regs(modtab->ri,
						 regs + modtab->offset);
	if (!match)
		errx(1, "unknown block \"%s\"\navailable: %s", block_name,
		     modnames);
	return 0;
}


static int dump_regs_t2(int argc, char *argv[], int start_arg, const u32 *regs)
{
	int match = 0;
	char *block_name = NULL;

	if (argc == start_arg + 1)
		block_name = argv[start_arg];
	else if (argc != start_arg)
		return -1;

	if (!block_name || !strcmp(block_name, "sge"))
		match += dump_block_regs(sge_regs, regs);
	if (!block_name || !strcmp(block_name, "mc3"))
		match += dump_block_regs(mc3_regs, regs);
	if (!block_name || !strcmp(block_name, "mc4"))
		match += dump_block_regs(mc4_regs, regs);
	if (!block_name || !strcmp(block_name, "tpi"))
		match += dump_block_regs(tpi_regs, regs);
	if (!block_name || !strcmp(block_name, "tp"))
		match += dump_block_regs(tp_regs, regs);
	if (!block_name || !strcmp(block_name, "rat"))
		match += dump_block_regs(rat_regs, regs);
	if (!block_name || !strcmp(block_name, "cspi"))
		match += dump_block_regs(cspi_regs, regs);
	if (!block_name || !strcmp(block_name, "espi"))
		match += dump_block_regs(espi_regs, regs);
	if (!block_name || !strcmp(block_name, "ulp"))
		match += dump_block_regs(ulp_regs, regs);
	if (!block_name || !strcmp(block_name, "pl"))
		match += dump_block_regs(pl_regs, regs);
	if (!block_name || !strcmp(block_name, "mc5"))
		match += dump_block_regs(mc5_regs, regs);
	if (!match)
		errx(1, "unknown block \"%s\"", block_name);
	return 0;
}

static int dump_regs_t3(int argc, char *argv[], int start_arg, const u32 *regs,
			int is_pcie)
{
	int match = 0;
	char *block_name = NULL;

	if (argc == start_arg + 1)
		block_name = argv[start_arg];
	else if (argc != start_arg)
		return -1;

	if (!block_name || !strcmp(block_name, "sge"))
		match += dump_block_regs(sge3_regs, regs);
	if (!block_name || !strcmp(block_name, "pci"))
		match += dump_block_regs(is_pcie ? pcie0_regs : pcix1_regs,
					 regs);
	if (!block_name || !strcmp(block_name, "t3dbg"))
		match += dump_block_regs(t3dbg_regs, regs);
	if (!block_name || !strcmp(block_name, "pmrx"))
		match += dump_block_regs(mc7_pmrx_regs, regs);
	if (!block_name || !strcmp(block_name, "pmtx"))
		match += dump_block_regs(mc7_pmtx_regs, regs);
	if (!block_name || !strcmp(block_name, "cm"))
		match += dump_block_regs(mc7_cm_regs, regs);
	if (!block_name || !strcmp(block_name, "cim"))
		match += dump_block_regs(cim_regs, regs);
	if (!block_name || !strcmp(block_name, "tp"))
		match += dump_block_regs(tp1_regs, regs);
	if (!block_name || !strcmp(block_name, "ulp_rx"))
		match += dump_block_regs(ulp2_rx_regs, regs);
	if (!block_name || !strcmp(block_name, "ulp_tx"))
		match += dump_block_regs(ulp2_tx_regs, regs);
	if (!block_name || !strcmp(block_name, "pmrx"))
		match += dump_block_regs(pm1_rx_regs, regs);
	if (!block_name || !strcmp(block_name, "pmtx"))
		match += dump_block_regs(pm1_tx_regs, regs);
	if (!block_name || !strcmp(block_name, "mps"))
		match += dump_block_regs(mps0_regs, regs);
	if (!block_name || !strcmp(block_name, "cplsw"))
		match += dump_block_regs(cpl_switch_regs, regs);
	if (!block_name || !strcmp(block_name, "smb"))
		match += dump_block_regs(smb0_regs, regs);
	if (!block_name || !strcmp(block_name, "i2c"))
		match += dump_block_regs(i2cm0_regs, regs);
	if (!block_name || !strcmp(block_name, "mi1"))
		match += dump_block_regs(mi1_regs, regs);
	if (!block_name || !strcmp(block_name, "sf"))
		match += dump_block_regs(sf1_regs, regs);
	if (!block_name || !strcmp(block_name, "pl"))
		match += dump_block_regs(pl3_regs, regs);
	if (!block_name || !strcmp(block_name, "mc5"))
		match += dump_block_regs(mc5a_regs, regs);
	if (!block_name || !strcmp(block_name, "xgmac0"))
		match += dump_block_regs(xgmac0_0_regs, regs);
	if (!block_name || !strcmp(block_name, "xgmac1"))
		match += dump_block_regs(xgmac0_1_regs, regs);
	if (!match)
		errx(1, "unknown block \"%s\"", block_name);
	return 0;
}

static int dump_regs_t3b(int argc, char *argv[], int start_arg, const u32 *regs,
			 int is_pcie)
{
	int match = 0;
	char *block_name = NULL;

	if (argc == start_arg + 1)
		block_name = argv[start_arg];
	else if (argc != start_arg)
		return -1;

	if (!block_name || !strcmp(block_name, "sge"))
		match += dump_block_regs(t3b_sge3_regs, regs);
	if (!block_name || !strcmp(block_name, "pci"))
		match += dump_block_regs(is_pcie ? t3b_pcie0_regs :
						   t3b_pcix1_regs, regs);
	if (!block_name || !strcmp(block_name, "t3dbg"))
		match += dump_block_regs(t3b_t3dbg_regs, regs);
	if (!block_name || !strcmp(block_name, "pmrx"))
		match += dump_block_regs(t3b_mc7_pmrx_regs, regs);
	if (!block_name || !strcmp(block_name, "pmtx"))
		match += dump_block_regs(t3b_mc7_pmtx_regs, regs);
	if (!block_name || !strcmp(block_name, "cm"))
		match += dump_block_regs(t3b_mc7_cm_regs, regs);
	if (!block_name || !strcmp(block_name, "cim"))
		match += dump_block_regs(t3b_cim_regs, regs);
	if (!block_name || !strcmp(block_name, "tp"))
		match += dump_block_regs(t3b_tp1_regs, regs);
	if (!block_name || !strcmp(block_name, "ulp_rx"))
		match += dump_block_regs(t3b_ulp2_rx_regs, regs);
	if (!block_name || !strcmp(block_name, "ulp_tx"))
		match += dump_block_regs(t3b_ulp2_tx_regs, regs);
	if (!block_name || !strcmp(block_name, "pmrx"))
		match += dump_block_regs(t3b_pm1_rx_regs, regs);
	if (!block_name || !strcmp(block_name, "pmtx"))
		match += dump_block_regs(t3b_pm1_tx_regs, regs);
	if (!block_name || !strcmp(block_name, "mps"))
		match += dump_block_regs(t3b_mps0_regs, regs);
	if (!block_name || !strcmp(block_name, "cplsw"))
		match += dump_block_regs(t3b_cpl_switch_regs, regs);
	if (!block_name || !strcmp(block_name, "smb"))
		match += dump_block_regs(t3b_smb0_regs, regs);
	if (!block_name || !strcmp(block_name, "i2c"))
		match += dump_block_regs(t3b_i2cm0_regs, regs);
	if (!block_name || !strcmp(block_name, "mi1"))
		match += dump_block_regs(t3b_mi1_regs, regs);
	if (!block_name || !strcmp(block_name, "sf"))
		match += dump_block_regs(t3b_sf1_regs, regs);
	if (!block_name || !strcmp(block_name, "pl"))
		match += dump_block_regs(t3b_pl3_regs, regs);
	if (!block_name || !strcmp(block_name, "mc5"))
		match += dump_block_regs(t3b_mc5a_regs, regs);
	if (!block_name || !strcmp(block_name, "xgmac0"))
		match += dump_block_regs(t3b_xgmac0_0_regs, regs);
	if (!block_name || !strcmp(block_name, "xgmac1"))
		match += dump_block_regs(t3b_xgmac0_1_regs, regs);
	if (!match)
		errx(1, "unknown block \"%s\"", block_name);
	return 0;
}

static int dump_regs_t3c(int argc, char *argv[], int start_arg, const u32 *regs,
			 int is_pcie)
{
	int match = 0;
	char *block_name = NULL;

	if (argc == start_arg + 1)
		block_name = argv[start_arg];
	else if (argc != start_arg)
		return -1;

	if (!block_name || !strcmp(block_name, "sge"))
		match += dump_block_regs(t3c_sge3_regs, regs);
	if (!block_name || !strcmp(block_name, "pci"))
		match += dump_block_regs(is_pcie ? t3c_pcie0_regs :
						   t3c_pcix1_regs, regs);
	if (!block_name || !strcmp(block_name, "t3dbg"))
		match += dump_block_regs(t3c_t3dbg_regs, regs);
	if (!block_name || !strcmp(block_name, "pmrx"))
		match += dump_block_regs(t3c_mc7_pmrx_regs, regs);
	if (!block_name || !strcmp(block_name, "pmtx"))
		match += dump_block_regs(t3c_mc7_pmtx_regs, regs);
	if (!block_name || !strcmp(block_name, "cm"))
		match += dump_block_regs(t3c_mc7_cm_regs, regs);
	if (!block_name || !strcmp(block_name, "cim"))
		match += dump_block_regs(t3c_cim_regs, regs);
	if (!block_name || !strcmp(block_name, "tp"))
		match += dump_block_regs(t3c_tp1_regs, regs);
	if (!block_name || !strcmp(block_name, "ulp_rx"))
		match += dump_block_regs(t3c_ulp2_rx_regs, regs);
	if (!block_name || !strcmp(block_name, "ulp_tx"))
		match += dump_block_regs(t3c_ulp2_tx_regs, regs);
	if (!block_name || !strcmp(block_name, "pmrx"))
		match += dump_block_regs(t3c_pm1_rx_regs, regs);
	if (!block_name || !strcmp(block_name, "pmtx"))
		match += dump_block_regs(t3c_pm1_tx_regs, regs);
	if (!block_name || !strcmp(block_name, "mps"))
		match += dump_block_regs(t3c_mps0_regs, regs);
	if (!block_name || !strcmp(block_name, "cplsw"))
		match += dump_block_regs(t3c_cpl_switch_regs, regs);
	if (!block_name || !strcmp(block_name, "smb"))
		match += dump_block_regs(t3c_smb0_regs, regs);
	if (!block_name || !strcmp(block_name, "i2c"))
		match += dump_block_regs(t3c_i2cm0_regs, regs);
	if (!block_name || !strcmp(block_name, "mi1"))
		match += dump_block_regs(t3c_mi1_regs, regs);
	if (!block_name || !strcmp(block_name, "sf"))
		match += dump_block_regs(t3c_sf1_regs, regs);
	if (!block_name || !strcmp(block_name, "pl"))
		match += dump_block_regs(t3c_pl3_regs, regs);
	if (!block_name || !strcmp(block_name, "mc5"))
		match += dump_block_regs(t3c_mc5a_regs, regs);
	if (!block_name || !strcmp(block_name, "xgmac0"))
		match += dump_block_regs(t3c_xgmac0_0_regs, regs);
	if (!block_name || !strcmp(block_name, "xgmac1"))
		match += dump_block_regs(t3c_xgmac0_1_regs, regs);
	if (!match)
		errx(1, "unknown block \"%s\"", block_name);
	return 0;
}

#define T4_MODREGS(name) { #name, t4_##name##_regs }

static int dump_regs_t4(int argc, char *argv[], int start_arg, const u32 *regs)
{
	static struct mod_regs t4_mod[] = {
		T4_MODREGS(sge),
		{ "pci", t4_pcie_regs },
		T4_MODREGS(dbg),
		T4_MODREGS(mc),
		T4_MODREGS(ma),
		{ "edc0", t4_edc_0_regs },
		{ "edc1", t4_edc_1_regs },
		T4_MODREGS(cim), 
		T4_MODREGS(tp),
		T4_MODREGS(ulp_rx),
		T4_MODREGS(ulp_tx),
		{ "pmrx", t4_pm_rx_regs },
		{ "pmtx", t4_pm_tx_regs },
		T4_MODREGS(mps),
		{ "cplsw", t4_cpl_switch_regs },
		T4_MODREGS(smb),
		{ "i2c", t4_i2cm_regs },
		T4_MODREGS(mi),
		T4_MODREGS(uart),
		T4_MODREGS(pmu), 
		T4_MODREGS(sf),
		T4_MODREGS(pl),
		T4_MODREGS(le),
		T4_MODREGS(ncsi),
		T4_MODREGS(xgmac)
	};

	return dump_regs_table(argc, argv, start_arg, regs, t4_mod,
			       ARRAY_SIZE(t4_mod),
			       "sge, pci, dbg, mc, ma, edc0, edc1, cim, tp, "
			       "ulprx, ulptx, pmrx, pmtx, mps, cplsw, smb, "
			       "i2c, mi, uart, pmu, sf, pl, le, ncsi, xgmac");
}

#undef T4_MODREGS

#define T5_MODREGS(name) { #name, t5_##name##_regs }

static int dump_regs_t5(int argc, char *argv[], int start_arg, const u32 *regs)
{
	static struct mod_regs t5_mod[] = {
		T5_MODREGS(sge),
		{ "pci", t5_pcie_regs },
		T5_MODREGS(dbg),
		{ "mc0", t5_mc_0_regs },
		{ "mc1", t5_mc_1_regs },
		T5_MODREGS(ma),
		{ "edc0", t5_edc_t50_regs },
		{ "edc1", t5_edc_t51_regs },
		T5_MODREGS(cim),
		T5_MODREGS(tp),
		{ "ulprx", t5_ulp_rx_regs },
		{ "ulptx", t5_ulp_tx_regs },
		{ "pmrx", t5_pm_rx_regs },
		{ "pmtx", t5_pm_tx_regs },
		T5_MODREGS(mps),
		{ "cplsw", t5_cpl_switch_regs },
		T5_MODREGS(smb),
		{ "i2c", t5_i2cm_regs },
		T5_MODREGS(mi),
		T5_MODREGS(uart),
		T5_MODREGS(pmu),
		T5_MODREGS(sf),
		T5_MODREGS(pl),
		T5_MODREGS(le),
		T5_MODREGS(ncsi),
		T5_MODREGS(mac),
		{ "hma", t5_hma_t5_regs }
	};

	return dump_regs_table(argc, argv, start_arg, regs, t5_mod,
			       ARRAY_SIZE(t5_mod),
			       "sge, pci, dbg, mc0, mc1, ma, edc0, edc1, cim, "
			       "tp, ulprx, ulptx, pmrx, pmtx, mps, cplsw, smb, "
			       "i2c, mi, uart, pmu, sf, pl, le, ncsi, "
			       "mac, hma");
}

#undef T5_MODREGS

#define T6_MODREGS(name) { #name, t6_##name##_regs }
static int dump_regs_t6(int argc, char *argv[], int start_arg, const u32 *regs)
{
	static struct mod_regs t6_mod[] = {
		T6_MODREGS(sge),
		{ "pci", t6_pcie_regs },
		T6_MODREGS(dbg),
		{ "mc0", t6_mc_0_regs },
		T6_MODREGS(ma),
		{ "edc0", t6_edc_t60_regs },
		{ "edc1", t6_edc_t61_regs },
		T6_MODREGS(cim),
		T6_MODREGS(tp),
		{ "ulprx", t6_ulp_rx_regs },
		{ "ulptx", t6_ulp_tx_regs },
		{ "pmrx", t6_pm_rx_regs },
		{ "pmtx", t6_pm_tx_regs },
		T6_MODREGS(mps),
		{ "cplsw", t6_cpl_switch_regs },
		T6_MODREGS(smb),
		{ "i2c", t6_i2cm_regs },
		T6_MODREGS(mi),
		T6_MODREGS(uart),
		T6_MODREGS(pmu),
		T6_MODREGS(sf),
		T6_MODREGS(pl),
		T6_MODREGS(le),
		T6_MODREGS(ncsi),
		T6_MODREGS(mac),
		{ "hma", t6_hma_t6_regs }
	};

	return dump_regs_table(argc, argv, start_arg, regs, t6_mod,
			       ARRAY_SIZE(t6_mod),
			       "sge, pci, dbg, mc0, ma, edc0, edc1, cim, "
			       "tp, ulprx, ulptx, pmrx, pmtx, mps, cplsw, smb, "
			       "i2c, mi, uart, pmu, sf, pl, le, ncsi, "
			       "mac, hma");
}
#undef T6_MODREGS

static int dump_regs_t4vf(int argc, char *argv[], int start_arg,
			  const u32 *regs)
{
	static struct mod_regs t4vf_mod[] = {
		{ "sge", t4vf_sge_regs },
		{ "mps", t4vf_mps_regs },
		{ "pl", t4vf_pl_regs },
		{ "mbdata", t4vf_mbdata_regs },
		{ "cim", t4vf_cim_regs },
	};

	return dump_regs_table(argc, argv, start_arg, regs, t4vf_mod,
			       ARRAY_SIZE(t4vf_mod),
			       "sge, mps, pl, mbdata, cim");
}

static int dump_regs_t5vf(int argc, char *argv[], int start_arg,
			  const u32 *regs)
{
	static struct mod_regs t5vf_mod[] = {
		{ "sge", t5vf_sge_regs },
		{ "mps", t4vf_mps_regs },
		{ "pl", t5vf_pl_regs },
		{ "mbdata", t4vf_mbdata_regs },
		{ "cim", t4vf_cim_regs },
	};

	return dump_regs_table(argc, argv, start_arg, regs, t5vf_mod,
			       ARRAY_SIZE(t5vf_mod),
			       "sge, mps, pl, mbdata, cim");
}

static int dump_regs_t6vf(int argc, char *argv[], int start_arg,
			  const u32 *regs)
{
	static struct mod_regs t6vf_mod[] = {
		{ "sge", t5vf_sge_regs },
		{ "mps", t4vf_mps_regs },
		{ "pl", t6vf_pl_regs },
		{ "mbdata", t4vf_mbdata_regs },
		{ "cim", t4vf_cim_regs },
	};

	return dump_regs_table(argc, argv, start_arg, regs, t6vf_mod,
			       ARRAY_SIZE(t6vf_mod),
			       "sge, mps, pl, mbdata, cim");
}

/*
 * Read a register dump from a binary file.  The file must start with an
 * ethtool_regs header with the version field properly set.
 */
static void read_regs_from_file(const char *fname, struct ethtool_regs *regs)
{
	int fd = open(fname, O_RDONLY);

	if (fd < 0 || read(fd, regs, regs->len + sizeof(*regs)) < 0)
		err(1, "%s", fname);
	close(fd);
}

static int dump_regs(int argc, char *argv[], int start_arg,
		     const char *iff_name, struct ethtool_drvinfo *drvinfo)
{
	int vers, revision, is_pcie, ret = 0;
	char *buf = NULL;
	struct ethtool_regs *regs;

	buf = (char *)malloc(sizeof(struct ethtool_regs) +
			     drvinfo->regdump_len);
	if (buf == NULL)
		return -1;
	regs = (struct ethtool_regs *)buf;
	regs->cmd = ETHTOOL_GREGS;
	regs->len = drvinfo->regdump_len;
	if (is_file(iff_name))
		read_regs_from_file(iff_name, regs);
	else if (ethtool_call(iff_name, regs))
		err(1, "can't read registers");

	vers = get_card_vers(regs->version);
	revision = (regs->version >> 10) & 0x3f;
	is_pcie = (regs->version & 0x80000000) != 0;

	if (vers <= 2) {
		ret = dump_regs_t2(argc, argv, start_arg, (u32 *)regs->data);
	} else if (vers == 3) {
		if (revision == 0)
			ret = dump_regs_t3(argc, argv, start_arg,
					    (u32 *)regs->data, is_pcie);
		else if (revision == 2 || revision == 3)
			ret = dump_regs_t3b(argc, argv, start_arg,
					     (u32 *)regs->data, is_pcie);
		else if (revision == 4)
			ret = dump_regs_t3c(argc, argv, start_arg,
					     (u32 *)regs->data, is_pcie);
	} else if (vers == 4) {
		if (revision == 0x3f)
			ret = dump_regs_t4vf(argc, argv, start_arg,
					      (u32 *)regs->data);
		else
			ret = dump_regs_t4(argc, argv, start_arg,
					    (u32 *)regs->data);
	} else if (vers == 5) {
		if (revision == 0x3f)
			ret =  dump_regs_t5vf(argc, argv, start_arg,
						(u32 *)regs->data);
		else
			ret =  dump_regs_t5(argc, argv, start_arg,
						(u32 *)regs->data);
	} else if (vers == 6) {
		if (revision == 0x3f)
			ret =  dump_regs_t6vf(argc, argv, start_arg,
						(u32 *)regs->data);
		else
			ret =  dump_regs_t6(argc, argv, start_arg,
						(u32 *)regs->data);
	} else {
		err(1, "unknown card type %d, rev %d", vers, revision);
	}

	free(buf);
	return ret;
}

#define PROC_PATH "/proc/driver/cxgb4/"
#define DRIVER_PATH "/sys/kernel/debug/cxgb4/"

static int dump_file(const char *filename, const char *iff_name)
{
	char driver_file[PATH_MAX];
	char driver_cmd[sizeof(driver_file) + 4];
	int e;
	struct stat s;
	char bus_slot_func[ETHTOOL_BUSINFO_LEN];

	if (get_adapter_ver(iff_name) < 4)
		errx(1, "%s is not a Chelsio T4 or later interface", iff_name);

	get_pci_bus_slot_func(iff_name, bus_slot_func, sizeof(bus_slot_func));
	snprintf(driver_file, sizeof(driver_file), PROC_PATH"%s/%s",
		 bus_slot_func, filename);

	e = stat(driver_file, &s);
	if (e) {
		snprintf(driver_file, sizeof(driver_file), DRIVER_PATH"%s/%s",
			 bus_slot_func, filename);
		e = stat(driver_file, &s);
		if (e)
			err(1, "%s", filename);
	}

	if (s.st_mode & S_IFDIR)	/* Handle . & .. & other dirs */
		errx(1, "%s: Is a directory", filename);

	e = access(driver_file, R_OK);
	if (e)
		err(1, "%s", filename);

	snprintf(driver_cmd, sizeof(driver_cmd), "cat %s", driver_file);

	if (system(driver_cmd) < 0)
		return errno;

	return 0;
}

static int t3_meminfo(const u32 *regs)
{
	enum {
		SG_EGR_CNTX_BADDR = 0x58,
		SG_CQ_CONTEXT_BADDR = 0x6c,
		CIM_SDRAM_BASE_ADDR = 0x28c,
		CIM_SDRAM_ADDR_SIZE = 0x290,
		TP_CMM_MM_BASE = 0x314,
		TP_CMM_TIMER_BASE = 0x318,
		TP_CMM_MM_RX_FLST_BASE = 0x460,
		TP_CMM_MM_TX_FLST_BASE = 0x464,
		TP_CMM_MM_PS_FLST_BASE = 0x468,
		ULPRX_ISCSI_LLIMIT = 0x50c,
		ULPRX_ISCSI_ULIMIT = 0x510,
		ULPRX_TDDP_LLIMIT = 0x51c,
		ULPRX_TDDP_ULIMIT = 0x520,
		ULPRX_STAG_LLIMIT = 0x52c,
		ULPRX_STAG_ULIMIT = 0x530,
		ULPRX_RQ_LLIMIT = 0x534,
		ULPRX_RQ_ULIMIT = 0x538,
		ULPRX_PBL_LLIMIT = 0x53c,
		ULPRX_PBL_ULIMIT = 0x540,
	};

	unsigned int egr_cntxt = regs[SG_EGR_CNTX_BADDR / 4],
		     cq_cntxt = regs[SG_CQ_CONTEXT_BADDR / 4],
		     timers = regs[TP_CMM_TIMER_BASE / 4] & 0xfffffff,
		     pstructs = regs[TP_CMM_MM_BASE / 4],
		     pstruct_fl = regs[TP_CMM_MM_PS_FLST_BASE / 4],
		     rx_fl = regs[TP_CMM_MM_RX_FLST_BASE / 4],
		     tx_fl = regs[TP_CMM_MM_TX_FLST_BASE / 4],
		     cim_base = regs[CIM_SDRAM_BASE_ADDR / 4],
		     cim_size = regs[CIM_SDRAM_ADDR_SIZE / 4];
	unsigned int iscsi_ll = regs[ULPRX_ISCSI_LLIMIT / 4],
		     iscsi_ul = regs[ULPRX_ISCSI_ULIMIT / 4],
		     tddp_ll = regs[ULPRX_TDDP_LLIMIT / 4],
		     tddp_ul = regs[ULPRX_TDDP_ULIMIT / 4],
		     stag_ll = regs[ULPRX_STAG_LLIMIT / 4],
		     stag_ul = regs[ULPRX_STAG_ULIMIT / 4],
		     rq_ll = regs[ULPRX_RQ_LLIMIT / 4],
		     rq_ul = regs[ULPRX_RQ_ULIMIT / 4],
		     pbl_ll = regs[ULPRX_PBL_LLIMIT / 4],
		     pbl_ul = regs[ULPRX_PBL_ULIMIT / 4];

	printf("CM memory map:\n");
	printf("  TCB region:      0x%08x - 0x%08x [%u]\n", 0, egr_cntxt - 1,
	       egr_cntxt);
	printf("  Egress contexts: 0x%08x - 0x%08x [%u]\n", egr_cntxt,
	       cq_cntxt - 1, cq_cntxt - egr_cntxt);
	printf("  CQ contexts:     0x%08x - 0x%08x [%u]\n", cq_cntxt,
	       timers - 1, timers - cq_cntxt);
	printf("  Timers:          0x%08x - 0x%08x [%u]\n", timers,
	       pstructs - 1, pstructs - timers);
	printf("  Pstructs:        0x%08x - 0x%08x [%u]\n", pstructs,
	       pstruct_fl - 1, pstruct_fl - pstructs);
	printf("  Pstruct FL:      0x%08x - 0x%08x [%u]\n", pstruct_fl,
	       rx_fl - 1, rx_fl - pstruct_fl);
	printf("  Rx FL:           0x%08x - 0x%08x [%u]\n", rx_fl, tx_fl - 1,
	       tx_fl - rx_fl);
	printf("  Tx FL:           0x%08x - 0x%08x [%u]\n", tx_fl, cim_base - 1,
	       cim_base - tx_fl);
	printf("  uP RAM:          0x%08x - 0x%08x [%u]\n", cim_base,
	       cim_base + cim_size - 1, cim_size);

	printf("\nPMRX memory map:\n");
	printf("  iSCSI region:    0x%08x - 0x%08x [%u]\n", iscsi_ll, iscsi_ul,
	       iscsi_ul - iscsi_ll + 1);
	printf("  TCP DDP region:  0x%08x - 0x%08x [%u]\n", tddp_ll, tddp_ul,
	       tddp_ul - tddp_ll + 1);
	printf("  TPT region:      0x%08x - 0x%08x [%u]\n", stag_ll, stag_ul,
	       stag_ul - stag_ll + 1);
	printf("  RQ region:       0x%08x - 0x%08x [%u]\n", rq_ll, rq_ul,
	       rq_ul - rq_ll + 1);
	printf("  PBL region:      0x%08x - 0x%08x [%u]\n", pbl_ll, pbl_ul,
	       pbl_ul - pbl_ll + 1);
	return 0;
}

static int meminfo(int argc, char *argv[], int start_arg, const char *iff_name)
{
	const int REGDUMP_SIZE = 4 * 1024;

	int vers;
	char buf[sizeof(struct ethtool_regs) + REGDUMP_SIZE];
	struct ethtool_regs *regs = (struct ethtool_regs *)buf;

	regs->cmd = ETHTOOL_GREGS;
	regs->len = REGDUMP_SIZE;
	if (ethtool_call(iff_name, regs))
		err(1, "can't read registers");

	vers = get_card_vers(regs->version);
	if (vers == 3)
		return t3_meminfo((u32 *)regs->data);

	else
		return dump_file("meminfo", iff_name);
}

static int device_up(int argc, char *argv[], int start_arg,
		     const char *iff_name)
{
	uint32_t op = CHELSIO_DEVUP;

	if (argc != start_arg) return -1;
	if (doit(iff_name, &op) < 0)
		err(1, "up");
	return 0;
}

static int mtu_tab_op(int argc, char *argv[], int start_arg,
		      const char *iff_name)
{
	struct ch_mtus op;
	int i;

	if (argc == start_arg) {
		op.cmd = CHELSIO_GETMTUTAB;
		op.nmtus = MAX_NMTUS;

		if (doit(iff_name, &op) < 0)
			err(1, "get MTU table");
		for (i = 0; i < op.nmtus; ++i)
			printf("%u ", op.mtus[i]);
		printf("\n");
	} else if (argc <= start_arg + MAX_NMTUS) {
		op.cmd = CHELSIO_SETMTUTAB;
		op.nmtus = argc - start_arg;

		for (i = 0; i < op.nmtus; ++i) {
			char *p;
			unsigned long m = strtoul(argv[start_arg + i], &p, 0);

			if (*p || m > 9600) {
				warnx("bad parameter \"%s\"",
				      argv[start_arg + i]);
				return -1;
			}
			if (i && m < op.mtus[i - 1])
				errx(1, "MTUs must be in ascending order");
			op.mtus[i] = m;
		}
		if (doit(iff_name, &op) < 0)
			err(1, "set MTU table");
	} else
		return -1;

	return 0;
}

/*
 * Shows the fields of a multi-word structure.  The structure is considered to
 * consist of @nwords 32-bit words (i.e, it's an (@nwords * 32)-bit structure)
 * whose fields are described by @fd.  The 32-bit words are given in @words
 * starting with the least significant 32-bit word.
 */
static void show_struct(const u32 *words, int nwords,
			const struct field_desc *fd)
{
	unsigned int w = 0;
	const struct field_desc *p;

	for (p = fd; p->name; p++)
		w = max(w, strlen(p->name));

	while (fd->name) {
		unsigned long long data;
		int first_word = fd->start / 32;
		int shift = fd->start % 32;
		int width = fd->end - fd->start + 1;
		unsigned long long mask = (1ULL << width) - 1;

		data = (words[first_word] >> shift) |
		       ((u64)words[first_word + 1] << (32 - shift));
		if (shift)
		       data |= ((u64)words[first_word + 2] << (64 - shift));
		data &= mask;
		if (fd->islog2)
			data = 1 << data;
		printf("%-*s ", w, fd->name);
		printf(fd->hex ? "%#llx\n" : "%llu\n", data << fd->shift);
		fd++;
	}
}

#define FIELD(name, start, end) { name, start, end, 0, 0, 0 }
#define FIELD1(name, start) FIELD(name, start, start)

static void show_t5t6_ctxt(const struct ch_mem_range *p, int vers)
{
	static struct field_desc egress_t5[] = {
		FIELD("DCA_ST:", 181, 191),
		FIELD1("StatusPgNS:", 180),
		FIELD1("StatusPgRO:", 179),
		FIELD1("FetchNS:", 178),
		FIELD1("FetchRO:", 177),
		FIELD1("Valid:", 176),
		FIELD("PCIeDataChannel:", 174, 175),
		FIELD1("StatusPgTPHintEn:", 173),
		FIELD("StatusPgTPHint:", 171, 172),
		FIELD1("FetchTPHintEn:", 170),
		FIELD("FetchTPHint:", 168, 169),
		FIELD1("FCThreshOverride:", 167),
		{ "WRLength:", 162, 166, 9, 0, 1 },
		FIELD1("WRLengthKnown:", 161),
		FIELD1("ReschedulePending:", 160),
		FIELD1("OnChipQueue:", 159),
		FIELD1("FetchSizeMode:", 158),
		{ "FetchBurstMin:", 156, 157, 4, 0, 1 },
		FIELD1("FLMPacking:", 155),
		FIELD("FetchBurstMax:", 153, 154),
		FIELD("uPToken:", 133, 152),
		FIELD1("uPTokenEn:", 132),
		FIELD1("UserModeIO:", 131),
		FIELD("uPFLCredits:", 123, 130),
		FIELD1("uPFLCreditEn:", 122),
		FIELD("FID:", 111, 121),
		FIELD("HostFCMode:", 109, 110),
		FIELD1("HostFCOwner:", 108),
		{ "CIDXFlushThresh:", 105, 107, 0, 0, 1 },
		FIELD("CIDX:", 89, 104),
		FIELD("PIDX:", 73, 88),
		{ "BaseAddress:", 18, 72, 9, 1 },
		FIELD("QueueSize:", 2, 17),
		FIELD1("QueueType:", 1),
		FIELD1("CachePriority:", 0),
		{ NULL }
	};
	static struct field_desc egress_t6[] = {
		FIELD("DCA_ST:", 181, 191),
		FIELD1("StatusPgNS:", 180),
		FIELD1("StatusPgRO:", 179),
		FIELD1("FetchNS:", 178),
		FIELD1("FetchRO:", 177),
		FIELD1("Valid:", 176),
		FIELD1("ReschedulePending_1:", 175),
		FIELD1("PCIeDataChannel:", 174),
		FIELD1("StatusPgTPHintEn:", 173),
		FIELD("StatusPgTPHint:", 171, 172),
		FIELD1("FetchTPHintEn:", 170),
		FIELD("FetchTPHint:", 168, 169),
		FIELD1("FCThreshOverride:", 167),
		{ "WRLength:", 162, 166, 9, 0, 1 },
		FIELD1("WRLengthKnown:", 161),
		FIELD1("ReschedulePending:", 160),
		FIELD("TimerIx:", 157, 159),
		FIELD1("FetchBurstMin:", 156),
		FIELD1("FLMPacking:", 155),
		FIELD("FetchBurstMax:", 153, 154),
		FIELD("uPToken:", 133, 152),
		FIELD1("uPTokenEn:", 132),
		FIELD1("UserModeIO:", 131),
		FIELD("uPFLCredits:", 123, 130),
		FIELD1("uPFLCreditEn:", 122),
		FIELD("FID:", 111, 121),
		FIELD("HostFCMode:", 109, 110),
		FIELD1("HostFCOwner:", 108),
		{ "CIDXFlushThresh:", 105, 107, 0, 0, 1 },
		FIELD("CIDX:", 89, 104),
		FIELD("PIDX:", 73, 88),
		{ "BaseAddress:", 18, 72, 9, 1 },
		FIELD("QueueSize:", 2, 17),
		FIELD1("QueueType:", 1),
		FIELD1("FetchSizeMode:", 0),
		{ NULL }
	};
	static struct field_desc fl_t5[] = {
		FIELD("DCA_ST:", 181, 191),
		FIELD1("StatusPgNS:", 180),
		FIELD1("StatusPgRO:", 179),
		FIELD1("FetchNS:", 178),
		FIELD1("FetchRO:", 177),
		FIELD1("Valid:", 176),
		FIELD("PCIeDataChannel:", 174, 175),
		FIELD1("StatusPgTPHintEn:", 173),
		FIELD("StatusPgTPHint:", 171, 172),
		FIELD1("FetchTPHintEn:", 170),
		FIELD("FetchTPHint:", 168, 169),
		FIELD1("FCThreshOverride:", 167),
		FIELD1("ReschedulePending:", 160),
		FIELD1("OnChipQueue:", 159),
		FIELD1("FetchSizeMode:", 158),
		{ "FetchBurstMin:", 156, 157, 4, 0, 1 },
		FIELD1("FLMPacking:", 155),
		FIELD("FetchBurstMax:", 153, 154),
		FIELD1("FLMcongMode:", 152),
		FIELD("MaxuPFLCredits:", 144, 151),
		FIELD("FLMcontextID:", 133, 143),
		FIELD1("uPTokenEn:", 132),
		FIELD1("UserModeIO:", 131),
		FIELD("uPFLCredits:", 123, 130),
		FIELD1("uPFLCreditEn:", 122),
		FIELD("FID:", 111, 121),
		FIELD("HostFCMode:", 109, 110),
		FIELD1("HostFCOwner:", 108),
		{ "CIDXFlushThresh:", 105, 107, 0, 0, 1 },
		FIELD("CIDX:", 89, 104),
		FIELD("PIDX:", 73, 88),
		{ "BaseAddress:", 18, 72, 9, 1 },
		FIELD("QueueSize:", 2, 17),
		FIELD1("QueueType:", 1),
		FIELD1("CachePriority:", 0),
		{ NULL }
	};
	static struct field_desc ingress_t5[] = {
		FIELD("DCA_ST:", 143, 153),
		FIELD1("ISCSICoalescing:", 142),
		FIELD1("Queue_Valid:", 141),
		FIELD1("TimerPending:", 140),
		FIELD1("DropRSS:", 139),
		FIELD("PCIeChannel:", 137, 138),
		FIELD1("SEInterruptArmed:", 136),
		FIELD1("CongestionMgtEnable:", 135),
		FIELD1("NoSnoop:", 134),
		FIELD1("RelaxedOrdering:", 133),
		FIELD1("GTSmode:", 132),
		FIELD1("TPHintEn:", 131),
		FIELD("TPHint:", 129, 130),
		FIELD1("UpdateScheduling:", 128),
		FIELD("UpdateDelivery:", 126, 127),
		FIELD1("InterruptSent:", 125),
		FIELD("InterruptIDX:", 114, 124),
		FIELD1("InterruptDestination:", 113),
		FIELD1("InterruptArmed:", 112),
		FIELD("RxIntCounter:", 106, 111),
		FIELD("RxIntCounterThreshold:", 104, 105),
		FIELD1("Generation:", 103),
		{ "BaseAddress:", 48, 102, 9, 1 },
		FIELD("PIDX:", 32, 47),
		FIELD("CIDX:", 16, 31),
		{ "QueueSize:", 4, 15, 4, 0 },
		{ "QueueEntrySize:", 2, 3, 4, 0, 1 },
		FIELD1("QueueEntryOverride:", 1),
		FIELD1("CachePriority:", 0),
		{ NULL }
	};
	static struct field_desc ingress_t6[] = {
		FIELD1("SP_NS:", 158),
		FIELD1("SP_RO:", 157),
		FIELD1("SP_TPHintEn:", 156),
		FIELD("SP_TPHint:", 154, 155),
		FIELD("DCA_ST:", 143, 153),
		FIELD1("ISCSICoalescing:", 142),
		FIELD1("Queue_Valid:", 141),
		FIELD1("TimerPending:", 140),
		FIELD1("DropRSS:", 139),
		FIELD("PCIeChannel:", 137, 138),
		FIELD1("SEInterruptArmed:", 136),
		FIELD1("CongestionMgtEnable:", 135),
		FIELD1("NoSnoop:", 134),
		FIELD1("RelaxedOrdering:", 133),
		FIELD1("GTSmode:", 132),
		FIELD1("TPHintEn:", 131),
		FIELD("TPHint:", 129, 130),
		FIELD1("UpdateScheduling:", 128),
		FIELD("UpdateDelivery:", 126, 127),
		FIELD1("InterruptSent:", 125),
		FIELD("InterruptIDX:", 114, 124),
		FIELD1("InterruptDestination:", 113),
		FIELD1("InterruptArmed:", 112),
		FIELD("RxIntCounter:", 106, 111),
		FIELD("RxIntCounterThreshold:", 104, 105),
		FIELD1("Generation:", 103),
		{ "BaseAddress:", 48, 102, 9, 1 },
		FIELD("PIDX:", 32, 47),
		FIELD("CIDX:", 16, 31),
		{ "QueueSize:", 4, 15, 4, 0 },
		{ "QueueEntrySize:", 2, 3, 4, 0, 1 },
		FIELD1("QueueEntryOverride:", 1),
		FIELD1("CachePriority:", 0),
		{ NULL }
	};
	static struct field_desc flm_t5[] = {
		FIELD1("Valid:", 89),
		FIELD("SplitLenMode:", 87, 88),
		FIELD1("TPHintEn:", 86),
		FIELD("TPHint:", 84, 85),
		FIELD1("NoSnoop:", 83),
		FIELD1("RelaxedOrdering:", 82),
		FIELD("DCA_ST:", 71, 81),
		FIELD("EQid:", 54, 70),
		FIELD("SplitEn:", 52, 53),
		FIELD1("PadEn:", 51),
		FIELD1("PackEn:", 50),
		FIELD1("Cache_Lock :", 49),
		FIELD1("CongDrop:", 48),
		FIELD("PackOffset:", 16, 47),
		FIELD("CIDX:", 8, 15),
		FIELD("PIDX:", 0, 7),
		{ NULL }
	};
	static struct field_desc flm_t6[] = {
		FIELD1("Valid:", 89),
		FIELD("SplitLenMode:", 87, 88),
		FIELD1("TPHintEn:", 86),
		FIELD("TPHint:", 84, 85),
		FIELD1("NoSnoop:", 83),
		FIELD1("RelaxedOrdering:", 82),
		FIELD("DCA_ST:", 71, 81),
		FIELD("EQid:", 54, 70),
		FIELD("SplitEn:", 52, 53),
		FIELD1("PadEn:", 51),
		FIELD1("PackEn:", 50),
		FIELD1("Cache_Lock :", 49),
		FIELD1("CongDrop:", 48),
		FIELD1("Inflifght:", 47),
		FIELD1("CongEn:", 46),
		FIELD1("CongMode:", 45),
		FIELD("PackOffset:", 20, 39),
		FIELD("CIDX:", 8, 15),
		FIELD("PIDX:", 0, 7),
		{ NULL }
	};
	static struct field_desc conm_t5[] = {
		FIELD1("CngMPSEnable:", 21),
		FIELD("CngTPMode:", 19, 20),
		FIELD1("CngDBPHdr:", 18),
		FIELD1("CngDBPData:", 17),
		FIELD1("CngIMSG:", 16),
		{ "CngChMap:", 0, 15, 0, 1, 0 },
		{ NULL }
	};

	const u32 *data = (u32 *)p->buf;
	if (p->mem_id == CNTXT_TYPE_EGRESS) {
		if (data[0] & 2)
			show_struct(data, 6, fl_t5);
		else if (vers == 5)
			show_struct(data, 6,  egress_t5);
		else
			show_struct(data, 6,  egress_t6);
	} else if (p->mem_id == CNTXT_TYPE_FL)
		show_struct(data, 3, (vers == 5) ? flm_t5 : flm_t6);
	else if (p->mem_id == CNTXT_TYPE_RSP || p->mem_id == CNTXT_TYPE_CQ)
		show_struct(data, 5, (vers == 5) ? ingress_t5 : ingress_t6);
	else if (p->mem_id == CNTXT_TYPE_CONG)
		show_struct(data, 1, conm_t5);
}
static void show_t4_ctxt(const struct ch_mem_range *p)
{
	static struct field_desc egress_t4[] = {
		FIELD1("StatusPgNS:", 180),
		FIELD1("StatusPgRO:", 179),
		FIELD1("FetchNS:", 178),
		FIELD1("FetchRO:", 177),
		FIELD1("Valid:", 176),
		FIELD("PCIeDataChannel:", 174, 175),
		FIELD1("DCAEgrQEn:", 173),
		FIELD("DCACPUID:", 168, 172),
		FIELD1("FCThreshOverride:", 167),
		FIELD("WRLength:", 162, 166),
		FIELD1("WRLengthKnown:", 161),
		FIELD1("ReschedulePending:", 160),
		FIELD1("OnChipQueue:", 159),
		FIELD1("FetchSizeMode", 158),
		{ "FetchBurstMin:", 156, 157, 4, 0, 1 },
		{ "FetchBurstMax:", 153, 154, 6, 0, 1 },
		FIELD("uPToken:", 133, 152),
		FIELD1("uPTokenEn:", 132),
		FIELD1("UserModeIO:", 131),
		FIELD("uPFLCredits:", 123, 130),
		FIELD1("uPFLCreditEn:", 122),
		FIELD("FID:", 111, 121),
		FIELD("HostFCMode:", 109, 110),
		FIELD1("HostFCOwner:", 108),
		{ "CIDXFlushThresh:", 105, 107, 0, 0, 1 },
		FIELD("CIDX:", 89, 104),
		FIELD("PIDX:", 73, 88),
		{ "BaseAddress:", 18, 72, 9, 1 },
		FIELD("QueueSize:", 2, 17),
		FIELD1("QueueType:", 1),
		FIELD1("CachePriority:", 0),
		{ NULL }
	};
	static struct field_desc fl_t4[] = {
		FIELD1("StatusPgNS:", 180),
		FIELD1("StatusPgRO:", 179),
		FIELD1("FetchNS:", 178),
		FIELD1("FetchRO:", 177),
		FIELD1("Valid:", 176),
		FIELD("PCIeDataChannel:", 174, 175),
		FIELD1("DCAEgrQEn:", 173),
		FIELD("DCACPUID:", 168, 172),
		FIELD1("FCThreshOverride:", 167),
		FIELD1("ReschedulePending:", 160),
		FIELD1("OnChipQueue:", 159),
		FIELD1("FetchSizeMode", 158),
		{ "FetchBurstMin:", 156, 157, 4, 0, 1 },
		{ "FetchBurstMax:", 153, 154, 6, 0, 1 },
		FIELD1("FLMcongMode:", 152),
		FIELD("MaxuPFLCredits:", 144, 151),
		FIELD("FLMcontextID:", 133, 143),
		FIELD1("uPTokenEn:", 132),
		FIELD1("UserModeIO:", 131),
		FIELD("uPFLCredits:", 123, 130),
		FIELD1("uPFLCreditEn:", 122),
		FIELD("FID:", 111, 121),
		FIELD("HostFCMode:", 109, 110),
		FIELD1("HostFCOwner:", 108),
		{ "CIDXFlushThresh:", 105, 107, 0, 0, 1 },
		FIELD("CIDX:", 89, 104),
		FIELD("PIDX:", 73, 88),
		{ "BaseAddress:", 18, 72, 9, 1 },
		FIELD("QueueSize:", 2, 17),
		FIELD1("QueueType:", 1),
		FIELD1("CachePriority:", 0),
		{ NULL }
	};
	static struct field_desc ingress_t4[] = {
		FIELD1("NoSnoop:", 145),
		FIELD1("RelaxedOrdering:", 144),
		FIELD1("GTSmode:", 143),
		FIELD1("ISCSICoalescing:", 142),
		FIELD1("Valid:", 141),
		FIELD1("TimerPending:", 140),
		FIELD1("DropRSS:", 139),
		FIELD("PCIeChannel:", 137, 138),
		FIELD1("SEInterruptArmed:", 136),
		FIELD1("CongestionMgtEnable:", 135),
		FIELD1("DCAIngQEnable:", 134),
		FIELD("DCACPUID:", 129, 133),
		FIELD1("UpdateScheduling:", 128),
		FIELD("UpdateDelivery:", 126, 127),
		FIELD1("InterruptSent:", 125),
		FIELD("InterruptIDX:", 114, 124),
		FIELD1("InterruptDestination:", 113),
		FIELD1("InterruptArmed:", 112),
		FIELD("RxIntCounter:", 106, 111),
		FIELD("RxIntCounterThreshold:", 104, 105),
		FIELD1("Generation:", 103),
		{ "BaseAddress:", 48, 102, 9, 1 },
		FIELD("PIDX:", 32, 47),
		FIELD("CIDX:", 16, 31),
		{ "QueueSize:", 4, 15, 4, 0 },
		{ "QueueEntrySize:", 2, 3, 4, 0, 1 },
		FIELD1("QueueEntryOverride:", 1),
		FIELD1("CachePriority:", 0),
		{ NULL }
	};
	static struct field_desc flm_t4[] = {
		FIELD1("NoSnoop:", 79),
		FIELD1("RelaxedOrdering:", 78),
		FIELD1("Valid:", 77),
		FIELD("DCACPUID:", 72, 76),
		FIELD1("DCAFLEn:", 71),
		FIELD("EQid:", 54, 70),
		FIELD("SplitEn:", 52, 53),
		FIELD1("PadEn:", 51),
		FIELD1("PackEn:", 50),
		FIELD1("DBpriority:", 48),
		FIELD("PackOffset:", 16, 47),
		FIELD("CIDX:", 8, 15),
		FIELD("PIDX:", 0, 7),
		{ NULL }
	};
	static struct field_desc conm_t4[] = {
		FIELD1("CngDBPHdr:", 6),
		FIELD1("CngDBPData:", 5),
		FIELD1("CngIMSG:", 4),
		{ "CngChMap:", 0, 3, 0, 1, 0},
		{ NULL }
	};

	const u32 *data = (u32 *)p->buf;
	if (p->mem_id == CNTXT_TYPE_EGRESS)
		show_struct(data, 6, (data[0] & 2) ? fl_t4 : egress_t4);
	else if (p->mem_id == CNTXT_TYPE_FL)
		show_struct(data, 3, flm_t4);
	else if (p->mem_id == CNTXT_TYPE_RSP || p->mem_id == CNTXT_TYPE_CQ)
		show_struct(data, 5, ingress_t4);
	else if (p->mem_id == CNTXT_TYPE_CONG)
		show_struct(data, 1, conm_t4);
}

#undef FIELD
#undef FIELD1

static void show_egress_cntxt(u32 data[])
{
	printf("credits:      %u\n", data[0] & 0x7fff);
	printf("GTS:          %u\n", (data[0] >> 15) & 1);
	printf("index:        %u\n", data[0] >> 16);
	printf("queue size:   %u\n", data[1] & 0xffff);
	printf("base address: 0x%llx\n",
	       ((data[1] >> 16) | ((u64)data[2] << 16) |
	       (((u64)data[3] & 0xf) << 48)) << 12);
	printf("rsp queue #:  %u\n", (data[3] >> 4) & 7);
	printf("cmd queue #:  %u\n", (data[3] >> 7) & 1);
	printf("TUN:          %u\n", (data[3] >> 8) & 1);
	printf("TOE:          %u\n", (data[3] >> 9) & 1);
	printf("generation:   %u\n", (data[3] >> 10) & 1);
	printf("uP token:     %u\n", (data[3] >> 11) & 0xfffff);
	printf("valid:        %u\n", (data[3] >> 31) & 1);
}

static void show_fl_cntxt(u32 data[])
{
	printf("base address: 0x%llx\n",
	       ((u64)data[0] | ((u64)data[1] & 0xfffff) << 32) << 12);
	printf("index:        %u\n", (data[1] >> 20) | ((data[2] & 0xf) << 12));
	printf("queue size:   %u\n", (data[2] >> 4) & 0xffff);
	printf("generation:   %u\n", (data[2] >> 20) & 1);
	printf("entry size:   %u\n",
	       (data[2] >> 21) | (data[3] & 0x1fffff) << 11);
	printf("congest thr:  %u\n", (data[3] >> 21) & 0x3ff);
	printf("GTS:          %u\n", (data[3] >> 31) & 1);
}

static void show_response_cntxt(u32 data[])
{
	printf("index:        %u\n", data[0] & 0xffff);
	printf("size:         %u\n", data[0] >> 16);
	printf("base address: 0x%llx\n",
	       ((u64)data[1] | ((u64)data[2] & 0xfffff) << 32) << 12);
	printf("MSI-X/RspQ:   %u\n", (data[2] >> 20) & 0x3f);
	printf("intr enable:  %u\n", (data[2] >> 26) & 1);
	printf("intr armed:   %u\n", (data[2] >> 27) & 1);
	printf("generation:   %u\n", (data[2] >> 28) & 1);
	printf("CQ mode:      %u\n", (data[2] >> 31) & 1);
	printf("FL threshold: %u\n", data[3]);
}

static void show_cq_cntxt(u32 data[])
{
	printf("index:            %u\n", data[0] & 0xffff);
	printf("size:             %u\n", data[0] >> 16);
	printf("base address:     0x%llx\n",
	       ((u64)data[1] | ((u64)data[2] & 0xfffff) << 32) << 12);
	printf("rsp queue #:      %u\n", (data[2] >> 20) & 0x3f);
	printf("AN:               %u\n", (data[2] >> 26) & 1);
	printf("armed:            %u\n", (data[2] >> 27) & 1);
	printf("ANS:              %u\n", (data[2] >> 28) & 1);
	printf("generation:       %u\n", (data[2] >> 29) & 1);
	printf("overflow mode:    %u\n", (data[2] >> 31) & 1);
	printf("credits:          %u\n", data[3] & 0xffff);
	printf("credit threshold: %u\n", data[3] >> 16);
}

static int get_sge_context(int argc, char *argv[], int start_arg,
			   const char *iff_name)
{
	int vers;
	struct ch_cntxt op;
	struct ch_mem_range *op2;

	if (argc != start_arg + 2) return -1;

	if (!strcmp(argv[start_arg], "egress"))
		op.cntxt_type = CNTXT_TYPE_EGRESS;
	else if (!strcmp(argv[start_arg], "fl"))
		op.cntxt_type = CNTXT_TYPE_FL;
	else if (!strcmp(argv[start_arg], "response") ||
		 !strcmp(argv[start_arg], "ingress"))
		op.cntxt_type = CNTXT_TYPE_RSP;
	else if (!strcmp(argv[start_arg], "cq"))
		op.cntxt_type = CNTXT_TYPE_CQ;
	else if (!strcmp(argv[start_arg], "cong"))
		op.cntxt_type = CNTXT_TYPE_CONG;
	else {
		warnx("unknown context type \"%s\"; known types are egress, "
		      "ingress, fl, cq, cong, and response", argv[start_arg]);
		return -1;
	}

	if (get_int_arg(argv[start_arg + 1], &op.cntxt_id))
		return -1;

	op.cmd = CHELSIO_GET_SGE_CONTEXT;
	if (doit(iff_name, &op) == 0) {
		if (op.cntxt_type == CNTXT_TYPE_EGRESS)
			show_egress_cntxt(op.data);
		else if (op.cntxt_type == CNTXT_TYPE_FL)
			show_fl_cntxt(op.data);
		else if (op.cntxt_type == CNTXT_TYPE_RSP)
			show_response_cntxt(op.data);
		else if (op.cntxt_type == CNTXT_TYPE_CQ)
			show_cq_cntxt(op.data);
		return 0;
	} else if (errno != EOPNOTSUPP)
		err(1, "get SGE context");

#define CTXT_SIZE (4 * 8)

	/* try newer interface */
	op2 = malloc(sizeof(*op2) + CTXT_SIZE);
	if (!op2)
		err(1, "get SGE context");
	op2->cmd = CHELSIO_GET_SGE_CTXT;
	op2->mem_id = op.cntxt_type;
	op2->addr = op.cntxt_id;
	op2->len = CTXT_SIZE;
	if (doit(iff_name, op2) < 0)
		err(1, "get SGE context");

	vers = get_card_vers(op2->version);
	if (vers == 4)
		show_t4_ctxt(op2);
	else if ((vers == 5) || (vers == 6))
		show_t5t6_ctxt(op2, vers);
	else
		errx(1, "unknown card type %d", vers);
	free(op2);
	return 0;
}

#if __BYTE_ORDER == __BIG_ENDIAN
# define ntohll(n) ((u64)(n))
#else
# define ntohll(n) ((u64)bswap_64(n))
#endif

static int get_sge_desc(int argc, char *argv[], int start_arg,
			const char *iff_name)
{
	u64 *p, wr_hdr;
	unsigned int n = 1, qset, qnum;

	/*
	 * Use char buf to avoid annoying compiler "does break
	 * strict-aliasing" warnings.  We know what we're doing here.
	 */
	char buf[sizeof(struct ch_desc)];
	struct ch_desc *op = (void *)buf;;

	if (argc != start_arg + 3 && argc != start_arg + 4)
		return -1;

	if (get_int_arg(argv[start_arg], &qset) ||
	    get_int_arg(argv[start_arg + 1], &qnum) ||
	    get_int_arg(argv[start_arg + 2], &op->idx))
		return -1;

	if (argc == start_arg + 4 && get_int_arg(argv[start_arg + 3], &n))
		return -1;

	if (qnum > 5)
		errx(1, "invalid queue number %d, range is 0..5", qnum);

	op->cmd = CHELSIO_GET_SGE_DESC;
	op->queue_num = qset * 6 + qnum;

	for (; n--; op->idx++) {
		if (doit(iff_name, op) < 0)
			err(1, "get SGE descriptor");

		p = (u64 *)op->data;
		wr_hdr = ntohll(*p);
		printf("Descriptor %u: cmd %u, TID %u, %s%s%s%s%u flits\n",
		       op->idx, (unsigned int)(wr_hdr >> 56),
		       ((unsigned int)wr_hdr >> 8) & 0xfffff,
		       ((wr_hdr >> 55) & 1) ? "SOP, " : "",
		       ((wr_hdr >> 54) & 1) ? "EOP, " : "",
		       ((wr_hdr >> 53) & 1) ? "COMPL, " : "",
		       ((wr_hdr >> 52) & 1) ? "SGL, " : "",
		       (unsigned int)wr_hdr & 0xff);

		for (; op->size; p++, op->size -= sizeof(u64))
			printf("%016llx%c", ntohll(*p),
			       op->size % 32 == 8 ? '\n' : ' ');
	}
	return 0;
}

static int get_sge_desc2(int argc, char *argv[], int start_arg,
			 const char *iff_name)
{
	uint64_t *p;
	struct ch_mem_range *op;
	unsigned int n = 1, type, qid, idx;

	if (argc != start_arg + 3 && argc != start_arg + 4)
		return -1;

	if (!strcmp(argv[start_arg], "eth") ||
	    !strcmp(argv[start_arg], "tx") ||
	    !strcmp(argv[start_arg], "xmit"))
		type = SGE_QTYPE_TX_ETH;
	else if (!strcmp(argv[start_arg], "ofld") ||
		 !strcmp(argv[start_arg], "offload"))
		type = SGE_QTYPE_TX_OFLD;
	else if (!strcmp(argv[start_arg], "ctrl") ||
		 !strcmp(argv[start_arg], "control"))
		type = SGE_QTYPE_TX_CTRL;
	else if (!strcmp(argv[start_arg], "fl") ||
		 !strcmp(argv[start_arg], "freelist"))
		type = SGE_QTYPE_FL;
	else if (!strcmp(argv[start_arg], "rsp") ||
		 !strcmp(argv[start_arg], "rspq") ||
		 !strcmp(argv[start_arg], "response") ||
		 !strcmp(argv[start_arg], "responseq"))
		type = SGE_QTYPE_RSP;
	else {
		/*
		 * We used to force users to use the actual enumeration
		 * values.  So we allow them to be used here in order to
		 * support legacy scripts.
		 */
		if (!isdigit(*argv[start_arg]) ||
		    get_int_arg(argv[start_arg], &type)) {
			warnx("Possible Queue Types are: "
			      "eth, ofld, ctrl, fl and rsp\n");
			return -1;
		}
	}

	if (get_int_arg(argv[start_arg + 1], &qid) ||
	    get_int_arg(argv[start_arg + 2], &idx))
		return -1;

	if (argc == start_arg + 4 && get_int_arg(argv[start_arg + 3], &n))
		return -1;

	op = malloc(sizeof(*op) + 128);
	if (!op)
		err(1, "get SGE descriptor");

	op->cmd = CHELSIO_GET_SGE_DESC2;
	op->mem_id = (type << 24) | qid;
	op->addr = idx;

	for ( ; n--; op->addr++) {
		op->len = 128;
		if (doit(iff_name, op) < 0)
			err(1, "get SGE descriptor");

		printf("Descriptor %u\n", op->addr);

		for (p = (uint64_t *)op->buf; op->len; p++, op->len -= 8)
			printf("%016llx%c", ntohll(*p),
			       op->len % 32 == 8 ? '\n' : ' ');
	}
	free(op);
	return 0;
}

static int get_tcb_t3(int argc, char *argv[], int start_arg,
		      const char *iff_name)
{
	uint64_t *d;
	unsigned int i;
	unsigned int tcb_idx;
	struct ch_mem_range *op;

	if (argc != start_arg + 1)
		return -1;

	if (get_int_arg(argv[start_arg], &tcb_idx))
		return -1;

	op = malloc(sizeof(*op) + TCB_SIZE);
	if (!op)
		err(1, "get TCB");

	op->cmd    = CHELSIO_GET_MEM;
	op->mem_id = MEM_CM;
	op->addr   = tcb_idx * TCB_SIZE;
	op->len    = TCB_SIZE;

	if (doit(iff_name, op) < 0)
		err(1, "get TCB");

	for (d = (uint64_t *)op->buf, i = 0; i < TCB_SIZE / 32; i++) {
		printf("%2u:", i);
		printf(" %08x %08x %08x %08x", (uint32_t)d[1],
		       (uint32_t)(d[1] >> 32), (uint32_t)d[0],
		       (uint32_t)(d[0] >> 32));
		d += 2;
		printf(" %08x %08x %08x %08x\n", (uint32_t)d[1],
		       (uint32_t)(d[1] >> 32), (uint32_t)d[0],
		       (uint32_t)(d[0] >> 32));
		d += 2;
	}
	free(op);
	return 0;
}

static int get_tcb(int argc, char *argv[], int start_arg, const char *iff_name)
{
	int i;
	uint32_t *d;
	struct ch_tcb op;
	int vers;

	vers = get_adapter_ver(iff_name);
	if (vers == 3)
		return get_tcb_t3(argc, argv,start_arg, iff_name);
	if (vers < 4)
		errx(1, "%s is not a Chelsio T4 or later interface", iff_name);

	if (argc != start_arg + 1)
		errx(1, "usage: tcb <tcb index>");

	op.cmd = CHELSIO_GET_TCB;
	if (get_int_arg(argv[start_arg], &op.tcb_index))
		errx(1, "tcb: bad interger argument");

	if (doit(iff_name, &op) < 0)
		err(1, "tcb");

	for (d = op.tcb_data, i = 0; i < TCB_WORDS; i += 8) {
		int j;

		printf("%2u:", 4 * i);
		for (j = 0; j < 8; ++j)
			printf(" %08x", *d++);
		printf("\n");
	}
	return 0;
}

#ifdef WRC
/*
 * The following defines, typedefs and structures are defined in the FW and
 * should be exported instead of being redefined here (and kept up in sync).
 * We'll fix this in the next round of FW cleanup.
 */
#define CM_WRCONTEXT_BASE       0x20300000
#define CM_WRCONTEXT_OFFSET	0x300000
#define WRC_SIZE                (FW_WR_SIZE * (2 + FW_WR_NUM) + 32 + 4 * 128)
#define FW_WR_SIZE	128
#define FW_WR_NUM	16
#define FBUF_SIZE	(FW_WR_SIZE * FW_WR_NUM)
#define FBUF_WRAP_SIZE	128
#define FBUF_WRAP_FSZ	(FBUF_WRAP_SZ >> 3)
#define MEM_CM_WRC_SIZE  WRC_SIZE

typedef char 			_s8;
typedef short 			_s16;
typedef int 			_s32;
typedef long long 		_s64;
typedef unsigned char           _u8;
typedef unsigned short          _u16;
typedef unsigned int            _u32;
typedef unsigned long long      _u64;

enum fw_ri_mpa_attrs {
	FW_RI_MPA_RX_MARKER_ENABLE = 0x1,
	FW_RI_MPA_TX_MARKER_ENABLE = 0x2,
	FW_RI_MPA_CRC_ENABLE	= 0x4,
	FW_RI_MPA_IETF_ENABLE	= 0x8
} __attribute__ ((packed));

enum fw_ri_qp_caps {
	FW_RI_QP_RDMA_READ_ENABLE = 0x01,
	FW_RI_QP_RDMA_WRITE_ENABLE = 0x02,
	FW_RI_QP_BIND_ENABLE	= 0x04,
	FW_RI_QP_FAST_REGISTER_ENABLE = 0x08,
	FW_RI_QP_STAG0_ENABLE	= 0x10
} __attribute__ ((packed));

enum wrc_state {
	WRC_STATE_CLOSED,
	WRC_STATE_ABORTED,
	WRC_STATE_HALFCLOSED,
	WRC_STATE_TOE_ESTABLISHED,
	WRC_STATE_RDMA_TX_DATA_PEND,
	WRC_STATE_RDMA_PEND,
	WRC_STATE_RDMA_ESTABLISHED,
};

enum ack_mode {
	ACK_MODE_TIMER,
	ACK_MODE_TIMER_PENDING,
	ACK_MODE_IMMEDIATE
} __attribute__ ((packed));

enum timer_state {
	TIMER_IDLE,			/* No Timer pending */
	TIMER_DELETED,			/* Timer has been deleted, but is still
					 * in the TOETIMERF
					 */
	TIMER_ADDED,			/* Timer added and in the TOETIMERF */
} __attribute__ ((packed));

struct _wr {
	_u32 a;
	_u32 b;
};

struct fbuf {
	_u32 	pp;			/* fifo producer pointer */
	_u32	cp;			/* fifo consumer pointer */
	_s32	num_bytes;		/* num bytes stored in the fbuf */
	char	bufferb[FBUF_SIZE]; 	/* buffer space in bytes */
	char	_wrap[FBUF_WRAP_SIZE];	/* wrap buffer size*/
};
struct wrc {
	_u32	wrc_tid;
	_u16	wrc_flags;
	_u8	wrc_state;
	_u8	wrc_credits;

	/* IO */
	_u16	wrc_sge_ec;
	_u8	wrc_sge_respQ;
	_u8	wrc_port;
	_u8	wrc_ulp;

	_u8	wrc_coherency_counter;

	/* REASSEMBLY */
	_u8	wrc_frag_len;
	_u8	wrc_frag_credits;
	_u32	wrc_frag;

	union {
		struct {

			/* TOE */
			_u8	aborted;			/*  2  0 */
			_u8	wrc_num_tx_pages;		/*  2  0 */
			_u8	wrc_max_tx_pages;		/*  2  0 */
			_u8	wrc_trace_idx;			/*  2  0 */
			_u32 	wrc_snd_nxt;			/*  3  1 */
			_u32 	wrc_snd_max;			/*  3  2 */
			_u32 	wrc_snd_una;			/*  4  3 */
			_u32	wrc_snd_iss;			/*  4  4 */

			/* RI */
			_u32	wrc_pdid;			/*  5  5 */
			_u32	wrc_scqid;			/*  5  6 */
			_u32	wrc_rcqid;			/*  6  7 */
			_u32	wrc_rq_addr_32a;		/*  6  8 */
			_u16	wrc_rq_size;			/*  6  9 */
			_u16	wrc_rq_wr_idx;			/*  6  9 */
			enum fw_ri_mpa_attrs wrc_mpaattrs;	/*  7 10 */
			enum fw_ri_qp_caps wrc_qpcaps;		/*  7 10 */
			_u16	wrc_mulpdu_tagged;		/*  7 10 */
			_u16	wrc_mulpdu_untagged;		/*  7 11 */
			_u16	wrc_ord_max;			/*  7 11 */
			_u16	wrc_ird_max;			/*  8 12 */
			_u16	wrc_ord;			/*  8 12 */
			_u16	wrc_ird;			/*  8 13 */
			_u16	wrc_markeroffset;		/*  8 13 */
			_u32	wrc_msn_send;			/*  9 14 */
			_u32	wrc_msn_rdma_read;		/*  9 15 */
			_u32	wrc_msn_rdma_read_req;		/* 10 16 */
			_u16	wrc_rdma_read_req_err;		/* 10 17 */
			_u8	wrc_ack_mode;			/* 10 17 */
			_u8	wrc_sge_ec_credits;		/* 10 17 */
			_u16	wrc_maxiolen_tagged;		/* 11 18 */
			_u16	wrc_maxiolen_untagged;		/* 11 18 */
			_u32	wrc_mo;				/* 11 19 */
			
			_u8	wrc_ack_tx_pages; 		/* 12 20 */ // move me up
			enum timer_state wrc_timer; 		/* 12 20 */ // move me up
			_u8	wrc_sge_credits; 		/* 12 20 */ // move me up
			_u8	wrc_ri_error;			/* 12 20 */
			_u8	wrc_ri_error_op;		/* 12 21 */
			_u8	wrc_ri_priv;			/* 12 21 */
			_u8	wrc_ri_init;			/* 12 21 */
			_u8	wrc_rdma_read_inv_idx;		/* 12 21 */
			_u32	wrc_rdma_read_inv_mask;		/* 13 22 */
			_u16	wrc_ri_nrqe;			/* 13 23 */
			_u8	wrc_memread_count;		/* 13 23 */

		} toe_ri;

		struct {

		} ipmi;

		struct {
			_u32	wrc_pad2[24];
		} pad;
	} u __attribute__ ((packed));

	/* BUFFERING */
	struct fbuf wrc_fbuf __attribute__ ((packed));
};
#define wrc_aborted u.toe_ri.aborted
#define wrc_num_tx_pages u.toe_ri.wrc_num_tx_pages
#define wrc_max_tx_pages u.toe_ri.wrc_max_tx_pages
#define wrc_trace_idx u.toe_ri.wrc_trace_idx
#define wrc_snd_nxt u.toe_ri.wrc_snd_nxt
#define wrc_snd_max u.toe_ri.wrc_snd_max
#define wrc_snd_una u.toe_ri.wrc_snd_una
#define wrc_snd_iss u.toe_ri.wrc_snd_iss
#define wrc_pdid u.toe_ri.wrc_pdid
#define wrc_scqid u.toe_ri.wrc_scqid
#define wrc_rcqid u.toe_ri.wrc_rcqid
#define wrc_rq_addr_32a u.toe_ri.wrc_rq_addr_32a
#define wrc_rq_size u.toe_ri.wrc_rq_size
#define wrc_rq_wr_idx u.toe_ri.wrc_rq_wr_idx
#define wrc_mpaattrs u.toe_ri.wrc_mpaattrs
#define wrc_qpcaps u.toe_ri.wrc_qpcaps
#define wrc_mulpdu_tagged u.toe_ri.wrc_mulpdu_tagged
#define wrc_mulpdu_untagged u.toe_ri.wrc_mulpdu_untagged
#define wrc_ord_max u.toe_ri.wrc_ord_max
#define wrc_ird_max u.toe_ri.wrc_ird_max
#define wrc_ord u.toe_ri.wrc_ord
#define wrc_ird u.toe_ri.wrc_ird
#define wrc_markeroffset u.toe_ri.wrc_markeroffset
#define wrc_msn_send u.toe_ri.wrc_msn_send
#define wrc_msn_rdma_read u.toe_ri.wrc_msn_rdma_read
#define wrc_msn_rdma_read_req u.toe_ri.wrc_msn_rdma_read_req
#define wrc_rdma_read_req_err u.toe_ri.wrc_rdma_read_req_err
#define wrc_ack_mode u.toe_ri.wrc_ack_mode
#define wrc_sge_ec_credits u.toe_ri.wrc_sge_ec_credits
#define wrc_maxiolen_tagged u.toe_ri.wrc_maxiolen_tagged
#define wrc_maxiolen_untagged u.toe_ri.wrc_maxiolen_untagged
#define wrc_mo u.toe_ri.wrc_mo
#define wrc_ack_tx_pages u.toe_ri.wrc_ack_tx_pages
#define wrc_timer u.toe_ri.wrc_timer
#define wrc_sge_credits u.toe_ri.wrc_sge_credits
#define wrc_ri_error u.toe_ri.wrc_ri_error
#define wrc_ri_error_op u.toe_ri.wrc_ri_error_op
#define wrc_ri_priv u.toe_ri.wrc_ri_priv
#define wrc_ri_init u.toe_ri.wrc_ri_init
#define wrc_rdma_read_inv_idx u.toe_ri.wrc_rdma_read_inv_idx
#define wrc_rdma_read_inv_mask u.toe_ri.wrc_rdma_read_inv_mask
#define wrc_memread_count u.toe_ri.wrc_memread_count
#define wrc_ri_nrqe u.toe_ri.wrc_ri_nrqe

static void print_wrc_field(char *field, unsigned int value, unsigned int size)
{
	switch(size) {
	case 1:
		printf("  1 %s: 0x%02x (%u)\n", field, value, value);
		break;
	case 2: {
		unsigned short host_value = ntohs(value);
		printf("  2 %s: 0x%04x (%u)\n", field, host_value, host_value);
		break;
	}
	case 4: {
		unsigned int host_value = ntohl(value);
		printf("  4 %s: 0x%08x (%u)\n", field, host_value, host_value);
		break;
	}
	default:
		printf("  unknown size %u for field %s\n", size, field);
	}
}

#define P(field)  print_wrc_field(#field, p->wrc_ ## field, sizeof (p->wrc_ ## field))

static void print_wrc(unsigned int wrc_idx, struct wrc *p)
{
	u32 *buf = (u32 *)p;
	unsigned int i, j;

	printf("WRC STATE (raw)\n");
	for (i = 0; i < 32;) {
		printf("[%08x]:", 0x20300000 + wrc_idx * MEM_CM_WRC_SIZE + i * 4);
		for (j = 0; j < 8; j++) {
			printf(" %08x ", htonl(buf[i++]));
		}
		printf("\n");
	}
	printf("WRC BASIC\n");
	P(tid); P(flags); P(state); P(credits);
	printf("WRC IO\n");
	P(sge_ec); P(sge_respQ); P(port); P(ulp); P(coherency_counter);
	printf("WRC REASSEMBLY\n");
	P(frag_len); P(frag_credits); P(frag);
	printf("WRC TOE\n");
	P(aborted); P(num_tx_pages); P(max_tx_pages); P(ack_tx_pages); P(timer); P(trace_idx); P(snd_nxt);
	P(snd_max); P(snd_una); P(snd_iss);
	printf("WRC RI\n");
	P(pdid); P(scqid); P(rcqid); P(rq_addr_32a); P(rq_size); P(rq_wr_idx);
	P(mpaattrs); P(qpcaps); P(mulpdu_tagged); P(mulpdu_untagged); P(ord_max);
	P(ird_max); P(ord); P(ird); P(markeroffset); P(msn_send); P(msn_rdma_read);
	P(msn_rdma_read_req); P(rdma_read_req_err); P(ack_mode);
	P(sge_ec_credits); P(maxiolen_tagged); P(maxiolen_untagged); P(mo);
	P(ack_tx_pages); P(timer); P(sge_credits); P(ri_error); P(ri_error_op);
	P(ri_priv); P(ri_init); P(rdma_read_inv_idx); P(rdma_read_inv_mask);
	P(ri_nrqe); P(memread_count);
	printf("WRC BUFFERING\n");
	printf("  4 fbuf.pp: 0x%08x (%u)\n", htonl(p->wrc_fbuf.pp),  htonl(p->wrc_fbuf.pp));
	printf("  4 fbuf.cp: 0x%08x (%u)\n",  htonl(p->wrc_fbuf.cp),  htonl(p->wrc_fbuf.cp));
	printf("  4 fbuf.num_bytes: 0x%08x (%d)\n",  htonl(p->wrc_fbuf.num_bytes),  htonl(p->wrc_fbuf.num_bytes));
	printf("WRC BUFFER (raw)\n");
	for (i = 32; i < (FBUF_SIZE + FBUF_WRAP_SIZE) / 4;) {
		printf("[%08x]:", 0x20300000 + wrc_idx * MEM_CM_WRC_SIZE + i * 4);
		for (j = 0; j < 4; j++) {
			printf(" %016lx", ((unsigned long)htonl(buf[i++]) << 32) | htonl(buf[i++]) );
		}
		printf("\n");
	}
}

#undef P

#define P(field)  print_sizeof(#field, ##field, sizeof (p->##field))

struct history_e {
	_u32 wr_addr;
	_u32 debug;
	_u64 wr_flit0;
	_u64 wr_flit1;
	_u64 wr_flit2;
};

static void print_wrc_zero(unsigned int wrc_idx, struct wrc *p)
{
	uint32_t *buf =
	   (uint32_t *)((unsigned long)p + FW_WR_SIZE * (2 + FW_WR_NUM));
	unsigned int i;

	printf("WRC ZERO\n");
	printf("[%08x]:", CM_WRCONTEXT_BASE + wrc_idx * MEM_CM_WRC_SIZE +
	       FW_WR_SIZE * (2 + FW_WR_NUM));
	for (i = 0; i < 4;)
		printf(" %08x%08x", htonl(buf[i]), htonl(buf[i++]));
	printf("\n");
}

static void print_wrc_history(struct wrc *p)
{
	unsigned int i, idx;
	struct history_e *e =
	    (struct history_e *)((unsigned long)p + FW_WR_SIZE *
				 (2 + FW_WR_NUM) + 32);
	printf("WRC WR HISTORY, idx %u\n", p->wrc_trace_idx);
	idx = p->wrc_trace_idx;
	for (i = 0; i < 16; i++) {
		printf("%02u: %08x %08x %08x%08x %08x%08x %08x%08x\n", idx,
		       htonl(e[idx].wr_addr), htonl(e[idx].debug),
		       htonl(e[idx].wr_flit0 & 0xFFFFFFFF),
		       htonl(e[idx].wr_flit0 >> 32),
		       htonl(e[idx].wr_flit1 & 0xFFFFFFFF),
		       htonl(e[idx].wr_flit1 >> 32),
		       htonl(e[idx].wr_flit2 & 0xFFFFFFFF),
		       htonl(e[idx].wr_flit2 >> 32));
		idx = (idx - 1) & 0xF;
	}
}

static int get_wrc(int argc, char *argv[], int start_arg, const char *iff_name)
{
	struct ch_mem_range *op;
	uint64_t *p;
	uint32_t *buf;
	unsigned int idx, i = 0;

	if (argc != start_arg + 1)
		return -1;

	if (get_int_arg(argv[start_arg], &idx))
		return -1;

	op = malloc(sizeof(*op) + MEM_CM_WRC_SIZE);
	if (!op)
		err(1, "get_wrc: malloc failed");

	op->cmd    = CHELSIO_GET_MEM;
	op->mem_id = MEM_CM;
	op->addr   = read_reg(iff_name, 0x28c) + CM_WRCONTEXT_OFFSET +
			      idx * MEM_CM_WRC_SIZE;
	op->len    = MEM_CM_WRC_SIZE;
	buf = (uint32_t *)op->buf;

	if (doit(iff_name, op) < 0)
		err(1, "get_wrc");

	/* driver manges with the data... put it back into the the FW's view
	 */
	for (p = (uint64_t *)op->buf;
	     p < (uint64_t *)(op->buf + MEM_CM_WRC_SIZE); p++) {
		uint64_t flit = *p;
		buf[i++] = htonl((uint32_t)(flit >> 32));
		buf[i++] = htonl((uint32_t)flit);
	}

	print_wrc(idx, (struct wrc *)op->buf);
	print_wrc_zero(idx, (struct wrc *)op->buf);
	print_wrc_history((struct wrc *)op->buf);

	free(op);
	return 0;
}
#endif

static int get_pm_page_spec(const char *s, unsigned int *page_size,
			    unsigned int *num_pages)
{
	char *p;
	unsigned long val;

	val = strtoul(s, &p, 0);
	if (p == s) return -1;
	if (*p == 'x' && p[1]) {
		*num_pages = val;
		*page_size = strtoul(p + 1, &p, 0);
	} else {
		*num_pages = -1;
		*page_size = val;
	}
	*page_size <<= 10;     // KB -> bytes
	return *p;
}

static int conf_pm(int argc, char *argv[], int start_arg, const char *iff_name)
{
	struct ch_pm op;

	if (argc == start_arg) {
	 	op.cmd = CHELSIO_GET_PM;
		if (doit(iff_name, &op) < 0)
			err(1, "read pm config");
		printf("%ux%uKB TX pages, %ux%uKB RX pages, %uKB total memory\n",
		       op.tx_num_pg, op.tx_pg_sz >> 10, op.rx_num_pg,
		       op.rx_pg_sz >> 10, op.pm_total >> 10);
		return 0;
	}

	if (argc != start_arg + 2) return -1;

	if (get_pm_page_spec(argv[start_arg], &op.tx_pg_sz, &op.tx_num_pg)) {
		warnx("bad parameter \"%s\"", argv[start_arg]);
		return -1;
	}
	if (get_pm_page_spec(argv[start_arg + 1], &op.rx_pg_sz,
			     &op.rx_num_pg)) {
		warnx("bad parameter \"%s\"", argv[start_arg + 1]);
		return -1;
	}
	op.cmd = CHELSIO_SET_PM;
	if (doit(iff_name, &op) < 0)
		err(1, "pm config");
	return 0;
}

#if 0 /* Unsupported */
static int conf_tcam(int argc, char *argv[], int start_arg,
		     const char *iff_name)
{
	struct ch_tcam op;

	if (argc == start_arg) {
		op.cmd = CHELSIO_GET_TCAM;
		op.nfilters = 0;
		if (doit(iff_name, &op) < 0)
			err(1, "read tcam config");
		printf("%u total entries, %u servers, %u filters, %u routes\n",
		       op.tcam_size, op.nservers, op.nfilters, op.nroutes);
		return 0;
	}

	if (argc != start_arg + 3) return -1;

	if (get_int_arg(argv[start_arg], &op.nservers) ||
	    get_int_arg(argv[start_arg + 1], &op.nroutes) ||
	    get_int_arg(argv[start_arg + 2], &op.nfilters))
		return -1;
	op.cmd = CHELSIO_SET_TCAM;
	if (doit(iff_name, &op) < 0)
		err(1, "tcam config");
	return 0;
}
#endif

static int dump_tcam(int argc, char *argv[], int start_arg,
		     const char *iff_name)
{
	unsigned int nwords;
	struct ch_tcam_word op;

	if (argc != start_arg + 2) return -1;

	if (get_int_arg(argv[start_arg], &op.addr) ||
	    get_int_arg(argv[start_arg + 1], &nwords))
		return -1;
	op.cmd = CHELSIO_READ_TCAM_WORD;

	while (nwords--) {
		if (doit(iff_name, &op) < 0)
			err(1, "tcam dump");

		printf("0x%08x: 0x%02x 0x%08x 0x%08x\n", op.addr,
		       op.buf[0] & 0xff, op.buf[1], op.buf[2]);
		op.addr++;
	}
	return 0;
}

static void hexdump_8b(unsigned int start, uint64_t *data, unsigned int len)
{
	int i;

	while (len) {
		printf("0x%08x:", start);
		for (i = 0; i < 4 && len; ++i, --len)
			printf(" %016llx", (unsigned long long)*data++);
		printf("\n");
		start += 32;
	}
}

static void hexdump_4b(unsigned int start, uint32_t *data, unsigned int len)
{
	int i;

	while (len) {
		printf("0x%08x:", start);
		for (i = 0; i < 8 && len; ++i, --len)
			printf(" %08x", *data++);
		printf("\n");
		start += 32;
	}
}

static int dump_mem(int argc, char *argv[], int start_arg,
		    const char *iff_name)
{
	struct ch_mem_range *op;
	unsigned int mem_id, addr, len;

	if (argc != start_arg + 3) return -1;

	if (!strcmp(argv[start_arg], "cm"))
		mem_id = MEM_CM;
	else if (!strcmp(argv[start_arg], "rx"))
		mem_id = MEM_PMRX;
	else if (!strcmp(argv[start_arg], "tx"))
		mem_id = MEM_PMTX;
	else if (!strcmp(argv[start_arg], "flash"))
		mem_id = MEM_FLASH;
	else
		errx(1, "unknown memory \"%s\"; must be one of \"cm\", \"tx\","
			" \"rx\", or \"flash\"", argv[start_arg]);

	if (get_int_arg(argv[start_arg + 1], &addr) ||
	    get_int_arg(argv[start_arg + 2], &len))
		return -1;

	op = malloc(sizeof(*op) + len);
	if (!op)
		err(1, "memory dump");

	op->cmd    = CHELSIO_GET_MEM;
	op->mem_id = mem_id;
	op->addr   = addr;
	op->len    = len;

	if (doit(iff_name, op) < 0)
		err(1, "memory dump");

	if (mem_id == MEM_FLASH)
		hexdump_4b(op->addr, (uint32_t *)op->buf, op->len / 4);
	else
		hexdump_8b(op->addr, (uint64_t *)op->buf, op->len / 8);
	free(op);
	return 0;
}

/**
 *      load_cfg -  this function can be used to load a configuration file (text format) in to the flash
 *      @*iffname: the interface name, ex eth2
 *
 *      this function will load a configuration file specified by user 
 *      to the flash.
 */
static uint32_t load_cfg(int argc, char *argv[], int start_arg, const char *iff_name)
{
        
        int fd;
	size_t cfg_file_size, len, i;
        struct struct_load_cfg *op;
	const char *fname = argv[start_arg];
        struct stat stbuf;

        if (argc != start_arg + 1)
		return -1;

	/*
	 * If we're given the special "clear" filename, pass that on as a
	 * zero-length file to the driver as an indication that the FLASH area
	 * reserved for a Firmware Configuration File should be cleared.
	 */
	if (strcmp(fname, "clear") == 0) {
		struct struct_load_cfg clear_op;

		clear_op.cmd = CHELSIO_LOAD_CFG;
		clear_op.len = 0;
		if (doit(iff_name, &clear_op) < 0)
			err(1, "loadcfg %s clear", iff_name);
		return 0;
	}

	/*
	 * Open the Firmware Configuration File and grab its size.
	 */
	fd = open(fname, O_RDONLY);
	if (fd < 0)
		errx(1, "loadcfg %s - open %s", iff_name, fname);

        if (fstat(fd, &stbuf) == -1) {
		errx(1, "loadcfg %s - fstat %s", iff_name, fname);
        }
        cfg_file_size = stbuf.st_size;
        if (cfg_file_size == 0) {
		errx(1, "loadcfg %s - %s file size is zero", iff_name, fname);
        }

	/*
	 * The Firmware Configuration File which we pass to the driver must
	 * have a length of a multiple of 4.  If the file isn't, then we'll
	 * pad it up with 0's.
	 */
	len = (cfg_file_size + 4-1) & ~3;
	op = malloc(sizeof(*op) + len);
	if (!op)
		err(1, "loadcfg %s - malloc %s buffer", iff_name, fname);
        if (read(fd, op->buf, cfg_file_size) < 0)
		err(1, "loadcfg %s - read %s", iff_name, fname);
	for (i = cfg_file_size; i < len; i++)
		op->buf[i] = 0;
        close(fd);

	/*
	 * Send the load cponfiguration file command down to the driver.
	 */
        op->cmd   = CHELSIO_LOAD_CFG;
        op->len   = len;
	if (doit(iff_name, op) < 0)
		errx(1, "loadcfg %s", fname);
	return 0;        
}

/**
 *	load_phy_fw -  this function can be used to load PHY file in to the flash
 *	@*iffname: the interface name, ex eth2
 *
 *	this function will load a PHY file specified by user
 *	to the flash at location defined by firmware
 */
static uint32_t load_phy_fw(int argc, char *argv[], int start_arg,
			    const char *iff_name)
{
	int        fd, len, i;
	struct     ch_mem_range *op;
	uint32_t   phy_file_size;
	const char *fname = argv[start_arg];
	struct     stat stbuf;
	unsigned int val2add = 0;

	if (argc != start_arg + 1) return -1;

	fd = open(fname, O_RDONLY);
	if (fd < 0)
		err(1, "%s", fname);

	if (fstat(fd, &stbuf) == -1) {
		err(1, "load phy - size");
	}
	phy_file_size = stbuf.st_size;

	if (phy_file_size == 0) {
		err(1, "load phy - file size is zero");
	}

	if ( (phy_file_size % 4) != 0) {
		val2add = 4 - (phy_file_size % 4);
	}

	op = malloc(sizeof(*op) + phy_file_size + val2add + 1);
	if (!op)
		err(1, "load phy - op malloc");

	len = read(fd, op->buf, phy_file_size + 1);

	len += val2add;
	for (i=0; i < val2add; i++) {
		op->buf[phy_file_size+i] = 0; // insert null character
	}

	if (len < 0)
		err(1, "load phy - read to buffer");

	close(fd);

	op->cmd   = CHELSIO_LOAD_PHY_FW;
	op->len   = len;

	if (doit(iff_name, op) < 0)
		err(1, "load phy - doit");
	return 0;
}

static int load_fw(int argc, char *argv[], int start_arg, const char *iff_name)
{
        int fd;
	struct stat sb;
	size_t len;
	struct ch_mem_range *op;
	const char *fname = argv[start_arg];

	if (argc != start_arg + 1) return -1;

	fd = open(fname, O_RDONLY);
	if (fd < 0)
		err(1, "loadfw open %s", fname);
	if (fstat(fd, &sb) < 0)
		err(1, "loadfw fstat %s", fname);
	len = (size_t)sb.st_size;

	op = malloc(sizeof *op + len);
	if (!op)
		err(1, "loadfw %s, allocate %ld bytes", fname, (long)len);
	if (read(fd, op->buf, len) < len)
		err(1, "loadfw %s", fname);
	close(fd);

	memset(op, 0, sizeof *op);
	op->cmd = CHELSIO_LOAD_FW;
	op->len = len;

	if (doit(iff_name, op) < 0)
		err(1, "load firmware");
	return 0;
}

/* Max BOOT size is 255*512 bytes including the BIOS boot ROM basic header */
#define MAX_BOOT_IMAGE_SIZE (1024 * 512)

static int load_boot(int argc, char *argv[],
		     int start_arg, const char *iff_name)
{
	int fd, len;
	unsigned int type, addr;
	struct ch_mem_range *op;
	const char *fname = argv[start_arg];

	if (argc == start_arg + 1) {
		type = 0;
		addr = 0;
	} else if (argc == start_arg + 3) {

		if (!strcmp(argv[start_arg + 1], "pf"))
			type = 0;
		else if (!strcmp(argv[start_arg + 1], "offset"))
			type = 1;
		else
			return -1;

		if (get_int_arg(argv[start_arg + 2], &addr))
			return -1;
	} else
		return -1;

	/*
	 * If we're given the special "clear" filename, pass that on as
	 * a zero-length file to the driver as an indication that the
	 * FLASH area reserved for option ROM should be cleared.
	 */
	if (strcmp(fname, "clear") == 0) {
		op = malloc(sizeof(*op));
		if (!op)
			err(1, "load boot image");

		len = 0;
		goto send_ioctl;
	}

	fd = open(fname, O_RDONLY);
	if (fd < 0)
		err(1, "load boot image");

	op = malloc(sizeof(*op) + MAX_BOOT_IMAGE_SIZE + 1);
	if (!op)
		err(1, "load boot image");

	len = read(fd, op->buf, MAX_BOOT_IMAGE_SIZE + 1);
	if (len < 0)
		err(1, "load boot image");
 	if (len > MAX_BOOT_IMAGE_SIZE)
		errx(1, "boot image too large");

send_ioctl:
	op->cmd = CHELSIO_LOAD_BOOT;
	op->mem_id = type;
	op->addr = addr;
	op->len = len;

	if (doit(iff_name, op) < 0)
		err(1, "load boot image");
	return 0;
}



#define MAX_EEPROM_SIZE (17 * 1024)

static int wr_eeprom(int argc, char *argv[], int start_arg,
		     const char *iff_name)
{
	int fd, len;
	const char *fname;
	unsigned int offset;
	struct ethtool_eeprom *op;

	if (argc != start_arg + 2) return -1;

	if (get_int_arg(argv[start_arg], &offset))
		return -1;

	fname = argv[start_arg + 1];
	fd = open(fname, O_RDONLY);
	if (fd < 0)
		err(1, "%s", fname);

	op = malloc(sizeof(*op) + MAX_EEPROM_SIZE + 1);
	if (!op)
		err(1, "write EEPROM");

	len = read(fd, op->data, MAX_EEPROM_SIZE + 1);
	if (len < 0)
		err(1, "write EEPROM");
 	if (len > MAX_EEPROM_SIZE)
		errx(1, "EEPROM image too large");
	close(fd);

	op->cmd = ETHTOOL_SEEPROM;
	op->magic = 0x38E2F10C;
	op->offset = offset;
	op->len = len;

	if (ethtool_call(iff_name, op) < 0)
		err(1, "write EEPROM");
	return 0;
}

static int clear_ofld_policy(const char *iff_name)
{
	struct ch_mem_range op;

	op.cmd = CHELSIO_SET_OFLD_POLICY;
	op.len = 0;
	if (doit(iff_name, &op) < 0)
		err(1, "load offload policy");
	return 0;
}

static int load_ofld_policy(int argc, char *argv[], int start_arg,
			    const char *iff_name)
{
	int fd, len;
	struct stat st;
	struct ch_mem_range *op;
	const char *fname = argv[start_arg];

	// license_expiration_check(LICENSE_EXPIRATION_DATE, "traffic management");

	if (argc != start_arg + 1) return -1;

	if (!strcmp(fname, "none"))
		return clear_ofld_policy(iff_name);

	fd = open(fname, O_RDONLY);
	if (fd < 0)
		err(1, "%s", fname);

	if (fstat(fd, &st) < 0)
		err(1, "%s", fname);

	op = malloc(sizeof(*op) + st.st_size);
	if (!op)
		err(1, "load offload policy");

	len = read(fd, op->buf, st.st_size);
	if (len < 0)
		err(1, "%s", fname);
 	if (len != st.st_size)
		errx(1, "could not read %s", fname);

	op->cmd = CHELSIO_SET_OFLD_POLICY;
	op->len = len;

	if (doit(iff_name, op) < 0)
		err(1, "load offload policy");
	return 0;
}

#if 0 /* Unsupported */
static int write_proto_sram(const char *fname, const char *iff_name)
{
	int i;
	char c;
	struct toetool_proto op = { .cmd = CHELSIO_SET_PROTO };
	uint32_t *p = op.data;
	FILE *fp = fopen(fname, "r");

	if (!fp)
		err(1, "load protocol sram");

	for (i = 0; i < 128; i++, p += 5) {
		int n = fscanf(fp, "%1x%8x%8x%8x%8x",
			       &p[0], &p[1], &p[2], &p[3], &p[4]);
		if (n != 5)
			errx(1, "%s: bad line %d", fname, i);
	}
	if (fscanf(fp, "%1s", &c) != EOF)
		errx(1, "%s: protocol sram image has too many lines", fname);
	fclose(fp);

	if (doit(iff_name, &op) < 0)
		err(1, "load protocol sram");
	return 0;
}
#endif

/*
 * This dumps the protocol SRAM section of the EEPROM.  In general this is the
 * same as what is loaded in TP's protocol SRAM, though not necessarily.
 */
static int dump_proto_sram(const char *iff_name)
{
	int i, j;
	u8 buf[sizeof(struct ethtool_eeprom) + PROTO_SRAM_SIZE];
	struct ethtool_eeprom *ee = (struct ethtool_eeprom *)buf;
	u8 *p = buf + sizeof(struct ethtool_eeprom);

	ee->cmd = ETHTOOL_GEEPROM;
	ee->len = PROTO_SRAM_SIZE;
	ee->offset = PROTO_SRAM_EEPROM_ADDR;
	if (ethtool_call(iff_name, ee))
		err(1, "show protocol sram");

	for (i = 0; i < PROTO_SRAM_LINES; i++) {
		for (j = PROTO_SRAM_LINE_NIBBLES - 1; j >= 0; j--) {
			int nibble_idx = i * PROTO_SRAM_LINE_NIBBLES + j;
			u8 nibble = p[nibble_idx / 2];

			if (nibble_idx & 1)
				nibble >>= 4;
			else
				nibble &= 0xf;
			printf("%x", nibble);
		}
		putchar('\n');
	}
	return 0;
}

static int proto_sram_op(int argc, char *argv[], int start_arg,
			 const char *iff_name)
{
#if 0 /* Unsupported */
	if (argc == start_arg + 1)
		return write_proto_sram(argv[start_arg], iff_name);
#endif
	if (argc == start_arg)
		return dump_proto_sram(iff_name);
	return -1;
}

static int dump_qset_params(const char *iff_name)
{
	struct ch_qset_params op;

	op.cmd = CHELSIO_GET_QSET_PARAMS;
	op.qset_idx = 0;

	while (doit(iff_name, &op) == 0) {
		if (!op.qset_idx)
			printf("%4s  %3s  %5s  %5s  %4s  %5s  %5s  %5s"
			       "  %4s  %4s  %-4s  %3s\n",
			       "QNUM", "IRQ", "TXQ0", "TXQ1", "TXQ2", "RSPQ",
			       "FL0", "FL1", "CONG", "LAT", "MODE", "LRO");
		if (op.qnum < 0 || op.qnum > 8)
			op.qnum = 0;
		if (op.vector < 0)
			op.vector = 0;
		printf("%4u  %3u  %5u  %5u  %4u  %5u  %5u  %5u  %4u  %4u"
		       "  %-4s  %3u\n",
		       op.qnum + op.qset_idx,
		       op.vector,
		       op.txq_size[0], op.txq_size[1], op.txq_size[2],
		       op.rspq_size, op.fl_size[0], op.fl_size[1],
		       op.cong_thres, op.intr_lat,
		       op.polling ? "napi" : "irq",
		       op.lro);
		op.qset_idx++;
	}
	if (!op.qset_idx || (errno && errno != EINVAL))
		err(1, "get qset parameters");
	return 0;
}

static int qset_config(int argc, char *argv[], int start_arg,
		       const char *iff_name)
{
	struct ch_qset_params op;

	if (argc == start_arg)
		return dump_qset_params(iff_name);

	if (argc == 4)
		errx(1, "missing qset parameter \n"
			"allowed parameters are \"txq0\", \"txq1\", "
			"\"txq2\", \"rspq\", \"fl0\", \"fl1\", \"lat\", "
			"\"cong\", \"mode\' and \"lro\"");

	if (argc > 4)
		if (argc % 2)
			errx(1, "missing value for qset parameter \"%s\"",
				argv[argc - 1]);

	if (get_int_arg(argv[start_arg++], &op.qset_idx))
		return -1;

	op.txq_size[0] = op.txq_size[1] = op.txq_size[2] = -1;
	op.fl_size[0] = op.fl_size[1] = op.rspq_size = -1;
	op.polling = op.lro = op.intr_lat = op.cong_thres = -1;

	while (start_arg + 2 <= argc) {
		int32_t *param = NULL;

		if (!strcmp(argv[start_arg], "txq0"))
			param = &op.txq_size[0];
		else if (!strcmp(argv[start_arg], "txq1"))
			param = &op.txq_size[1];
		else if (!strcmp(argv[start_arg], "txq2"))
			param = &op.txq_size[2];
		else if (!strcmp(argv[start_arg], "rspq"))
			param = &op.rspq_size;
		else if (!strcmp(argv[start_arg], "fl0"))
			param = &op.fl_size[0];
		else if (!strcmp(argv[start_arg], "fl1"))
			param = &op.fl_size[1];
		else if (!strcmp(argv[start_arg], "lat"))
			param = &op.intr_lat;
		else if (!strcmp(argv[start_arg], "cong"))
			param = &op.cong_thres;
		else if (!strcmp(argv[start_arg], "mode"))
			param = &op.polling;
		else if (!strcmp(argv[start_arg], "lro"))
			param = &op.lro;
		else
			errx(1, "unknown qset parameter \"%s\"\n"
			     "allowed parameters are \"txq0\", \"txq1\", "
			     "\"txq2\", \"rspq\", \"fl0\", \"fl1\", \"lat\", "
			     "\"cong\", \"mode\' and \"lro\"", argv[start_arg]);

		start_arg++;

		if (param == &op.polling) {
			if (!strcmp(argv[start_arg], "irq"))
				op.polling = 0;
			else if (!strcmp(argv[start_arg], "napi"))
				op.polling = 1;
			else
				errx(1, "illegal qset mode \"%s\"\n"
				     "known modes are \"irq\" and \"napi\"",
				     argv[start_arg]);
		} else if (get_int_arg(argv[start_arg], (uint32_t *)param))
			return -1;
		start_arg++;
	}
	if (start_arg != argc)
		errx(1, "unknown parameter %s", argv[start_arg]);

#if 0
	printf("%4u %6d %6d %6d %6d %6d %6d %5d %9d   %d\n", op.qset_idx,
	       op.txq_size[0], op.txq_size[1], op.txq_size[2],
	       op.rspq_size, op.fl_size[0], op.fl_size[1], op.cong_thres,
	       op.intr_lat, op.polling);
#endif
	op.cmd = CHELSIO_SET_QSET_PARAMS;
	if (doit(iff_name, &op) < 0)
		err(1, "set qset parameters");

	return 0;
}

/*
 * Set/get Response Queue Interrupt Coalescing parameters.
 */
static int qintr_config(int argc, char *argv[], int start_arg,
			     const char *iff_name)
{
	struct ch_queue_intr_params op;

	if (argc == start_arg)
		errx(1, "missing Response Queue ID");
	if (argc > 4)
		if (argc % 2)
			errx(1, "missing value for interrupt parameter \"%s\"",
			     argv[argc - 1]);

	if (get_int_arg(argv[start_arg++], &op.qid))
		return -1;

	if (argc == start_arg) {
		op.cmd = CHELSIO_GET_QUEUE_INTR_PARAMS;
		if (doit(iff_name, &op))
			err(1, "getting Response Queue Interrupt Coalescing"
			    " parameters");
		printf("timer = %d us, count = %d packets\n",
		       op.timer, op.count);
		return 0;
	}

	op.timer = -1;
	op.count = -1;
	while (start_arg + 2 <= argc) {
		int32_t *param = NULL;

		if (!strcmp(argv[start_arg], "timer"))
			param = &op.timer;
		else if  (!strcmp(argv[start_arg], "count"))
			param = &op.count;
		else
			errx(1,
			     "unknown interrupt coalescing parameter \"%s\"\n"
			     "allowed parameters are \"timer\" and \"count\"",
			     argv[start_arg]);
		start_arg++;

		if (get_int_arg(argv[start_arg], (uint32_t *)param))
			return -1;
		start_arg++;
	}

	op.cmd = CHELSIO_SET_QUEUE_INTR_PARAMS;
	if (doit(iff_name, &op))
		err(1, "setting Response Queue Interrupt Coalescing parameters");

	return 0;
}

static int qset_num_config(int argc, char *argv[], int start_arg,
			   const char *iff_name)
{
	struct ch_reg op;

	if (argc == start_arg) {
		op.cmd = CHELSIO_GET_QSET_NUM;
		if (doit(iff_name, &op) < 0)
			err(1, "get qsets");
		printf("%u\n", op.val);
		return 0;
	}

	if (argc != start_arg + 1)
		return -1;
	if (get_int_arg(argv[start_arg], &op.val))
		return -1;

	op.cmd = CHELSIO_SET_QSET_NUM;
	if (doit(iff_name, &op) < 0)
		err(1, "set qsets");
	return 0;
}

static int qtype_num_config(int argc, char *argv[], int start_arg,
			   const char *iff_name, uint32_t type)
{
	struct ch_qtype_num op;

	op.qtype = type;
	if (argc == start_arg) {
		op.cmd = CHELSIO_GET_QTYPE_NUM;
		if (doit(iff_name, &op) < 0)
			err(1, "get qtype-num");
		printf("%u\n", op.val);
		return 0;
	}

	if (argc != start_arg + 1)
		return -1;
	if (get_int_arg(argv[start_arg], &op.val))
		return -1;

	op.cmd = CHELSIO_SET_QTYPE_NUM;
	if (doit(iff_name, &op) < 0)
		err(1, "set qtype-num");
	return 0;
}

static int qtype_config(int argc, char *argv[], int start_arg,
			   const char *iff_name)
{
	int r = -1;

	if (argc < start_arg+1)
		return -1;

	if (!strcmp(argv[start_arg], "eth"))
		r = qtype_num_config(argc, argv,
				start_arg+1, iff_name, QTYPE_ETH);
	else if (!strcmp(argv[start_arg], "ofld"))
		r = qtype_num_config(argc, argv,
				start_arg+1, iff_name, QTYPE_OFLD);
	else if (!strcmp(argv[start_arg], "rdma"))
		r = qtype_num_config(argc, argv,
				start_arg+1, iff_name, QTYPE_RDMA);
	else if (!strcmp(argv[start_arg], "rciq"))
		r = qtype_num_config(argc, argv,
				start_arg+1, iff_name, QTYPE_RCIQ);
	else if (!strcmp(argv[start_arg], "iscsi"))
		r = qtype_num_config(argc, argv,
				start_arg+1, iff_name, QTYPE_ISCSI);
	else
		warnx("Invalid type \"%s\": Valid types are "
			"\"eth|ofld|rdma|rciq|iscsi\"\n", argv[start_arg]);

	return r;
}


/*
 * Parse an argument sub-vector as a { <parameter name> <addr>[/<mask>] }
 * ordered tuple.  If the parameter name in the argument sub-vector does not
 * match the passed in parameter name, then a zero is returned for the
 * function and no parsing is performed.  If there is a match, then the value
 * and optional mask are parsed and returned in the provided return value
 * pointers.  If no optional mask is specified, then a default mask of all 1s
 * will be returned.
 *
 * The value return parameter "afp" is used to specify the expected address
 * family -- IPv4 or IPv6 -- of the address[/mask] and return its actual
 * format.  A passed in value of AF_UNSPEC indicates that either IPv4 or IPv6
 * is acceptable; AF_INET means that only IPv4 addresses are acceptable; and
 * AF_INET6 means that only IPv6 are acceptable.  AF_INET is returned for IPv4
 * and AF_INET6 for IPv6 addresses, respectively.  IPv4 address/mask pairs are
 * returned in the first four bytes of the address and mask return values with
 * the address A.B.C.D returned with { A, B, C, D } returned in addresses { 0,
 * 1, 2, 3}, respectively.
 *
 * An error in parsing the value[:mask] will result in an error message and
 * program termination.
 */
static int parse_ipaddr(const char *param, char *args[],
			int *afp, uint8_t addr[], uint8_t mask[], int maskless)
{
	const char *colon, *afn;
	char *slash;
	uint8_t *m;
	int af, ret, masksize;

	/*
	 * Is this our parameter?
	 */
	if (strcmp(param, args[0]) != 0)
		return 0;

	/*
	 * Fundamental IPv4 versus IPv6 selection.
	 */
	colon = strchr(args[1], ':');
	if (!colon) {
		afn = "IPv4";
		af = AF_INET;
		masksize = 32;
	} else {
		afn = "IPv6";
		af = AF_INET6;
		masksize = 128;
	}
	if (*afp == AF_UNSPEC)
		*afp = af;
	else if (*afp != af)
		errx(1, "address %s is not of expected family %s", args[1],
		     *afp == AF_INET ? "IP" : "IPv6");

	/*
	 * Parse address (temporarily stripping off any "/mask"
	 * specification).
	 */
	slash = strchr(args[1], '/');
	if (slash)
		*slash = 0;
	ret = inet_pton(af, args[1], addr);
	if (slash)
		*slash = '/';
	if (ret <= 0)
		errx(1, "Cannot parse %s %s address %s", param, afn, args[1]);

	/*
	 * Parse optional mask specification.
	 */
	if (slash) {
		char *p;
		unsigned int prefix = strtoul(slash + 1, &p, 10);

		if (p == slash + 1)
			errx(1, "missing address prefix for %s", param);
		if (*p)
			errx(1, "%s is not a valid address prefix", slash + 1);
		if (prefix > masksize)
			errx(1, "prefix %u is too long for an %s address",
			     prefix, afn);
		memset(mask, 0, masksize / 8);
		masksize = prefix;

		if (maskless)
			errx(1, "mask cannot be provided for maskless specification");
	}

	/*
	 * Fill in mask.
	 */
	for (m = mask; masksize >= 8; m++, masksize -= 8)
		*m = ~0;
	if (masksize)
		*m = ~0 << (8 - masksize);

	return 1;
}

/*
 * Parse an argument sub-vector as a { <parameter name> <value> } ordered
 * tuple.  If the parameter name in the argument sub-vector does not match the
 * passed in parameter name, then a zero is returned for the function and no
 * parsing is performed.  If there is a match, then the value is parsed and
 * returned in the provided return value pointer.
 */
static int parse_val(const char *param, char *args[], uint32_t *val)
{
	char *p;

	if (strcmp(param, args[0]) != 0)
		return 0;

	*val = strtoul(args[1], &p, 0);
	if (p > args[1] && p[0] == 0)
		return 1;

	errx(1, "parameter \"%s\" has bad \"value\" %s", args[0], args[1]);
	/*NOTREACHED*/
}

/*
 * Parse an argument sub-vector as a { <parameter name> <value>[:<mask>] }
 * ordered tuple.  If the parameter name in the argument sub-vector does not
 * match the passed in parameter name, then a zero is returned for the
 * function and no parsing is performed.  If there is a match, then the value
 * and optional mask are parsed and returned in the provided return value
 * pointers.  If no optional mask is specified, then a default mask of all 1s
 * will be returned. If bitwidth parameter is non-zero an error will be flagged
 * if the parsed value/mask bit width is greater than the it's value.
 *
 * An error in parsing the value[:mask] will result in an error message and
 * program termination.
 */
static int parse_val_mask(const char *param, char *args[],
			  uint32_t *val, uint32_t *mask, int bitwidth, int maskless)
{
	char *p;

	if (strcmp(param, args[0]) != 0)
		return 0;

	*val = strtoul(args[1], &p, 0);

	if (bitwidth && (*val & ~((1 << bitwidth) - 1)))
		errx(1, "parameter \"%s\" value should be no greater than %d "
		     "bits\n", args[0], bitwidth);

	if (p > args[1]) {
		if (p[0] == 0) {
			*mask = ~0;
			return 1;
		}

		if (p[0] == ':' && p[1] != 0) {
			*mask = strtoul(p+1, &p, 0);

			if (bitwidth && (*mask & ~((1 << bitwidth) - 1)))
				errx(1, "parameter \"%s\" mask should be no "
				     "greater than %d bits\n",
				     args[0], bitwidth);

			if (maskless)
				errx(1, "mask cannot be provided for maskless specification");

			if (p[0] == 0)
				return 1;
		} else
			if (maskless)
				errx(1, "mask cannot be provided for maskless specification");
	}

	errx(1, "parameter \"%s\" has bad \"value[:mask]\" %s",
	     args[0], args[1]);
	/*NOTREACHED*/
}

static int trace_config(int argc, char *argv[], int start_arg,
			const char *iff_name)
{
	struct ch_trace op;

	if (argc == start_arg)
		return -1;

	memset(&op, 0, sizeof(op));
	if (!strcmp(argv[start_arg], "tx"))
		op.config_tx = 1;
	else if (!strcmp(argv[start_arg], "rx"))
		op.config_rx = 1;
	else if (!strcmp(argv[start_arg], "all"))
		op.config_tx = op.config_rx = 1;
	else
		errx(1, "bad trace filter \"%s\"; must be one of \"rx\", "
		     "\"tx\" or \"all\"", argv[start_arg]);

	if (argc == ++start_arg) {
		op.cmd = CHELSIO_GET_TRACE_FILTER;
		if (doit(iff_name, &op) < 0)
			err(1, "trace");
		printf("sip: %x:%x, dip: %x:%x, sport: %x:%x, dport: %x:%x, "
	        "interface: %x:%x, vlan: %x:%x, proto: %x:%x, "
	        "invert: %u, tx_enable: %u, rx_enable: %u\n", op.sip,
	        op.sip_mask, op.dip, op.dip_mask, op.sport, op.sport_mask,
	        op.dport, op.dport_mask, op.intf, op.intf_mask, op.vlan,
	        op.vlan_mask, op.proto, op.proto_mask, op.invert_match,
	        op.trace_tx, op.trace_rx);
		return 0;
	}
	if (!strcmp(argv[start_arg], "on")) {
		op.trace_tx = op.config_tx;
		op.trace_rx = op.config_rx;
	} else if (strcmp(argv[start_arg], "off"))
		errx(1, "bad argument \"%s\"; must be \"on\" or \"off\"",
		     argv[start_arg]);

	start_arg++;
	if (start_arg < argc && !strcmp(argv[start_arg], "not")) {
		op.invert_match = 1;
		start_arg++;
	}

	while (start_arg + 2 <= argc) {
		int af = AF_INET;
		char **args = &argv[start_arg];
		uint32_t val, mask;

		if (parse_val_mask("interface", args, &val, &mask, 0, 0)) {
			op.intf = val;
			op.intf_mask = mask;
		} else if (parse_ipaddr("sip", args, &af,
					(uint8_t *)&val, (uint8_t *)&mask, 0)) {
			op.sip = ntohl(val);
			op.sip_mask = ntohl(mask);
		} else if (parse_ipaddr("dip", args, &af,
					(uint8_t *)&val, (uint8_t *)&mask, 0)) {
			op.dip = ntohl(val);
			op.dip_mask = ntohl(mask);
		} else if (parse_val_mask("sport", args, &val, &mask, 0, 0)) {
			op.sport = val;
			op.sport_mask = mask;
		} else if (parse_val_mask("dport", args, &val, &mask, 0, 0)) {
			op.dport = val;
			op.dport_mask = mask;
		} else if (parse_val_mask("vlan", args, &val, &mask, 0, 0)) {
			op.vlan = val;
			op.vlan_mask = mask;
		} else if (parse_val_mask("proto", args, &val, &mask, 0, 0)) {
			op.proto = val;
			op.proto_mask = mask;
		} else
			errx(1, "unknown trace parameter \"%s\"\n"
			     "known parameters are \"interface\", \"sip\", "
			     "\"dip\", \"sport\", \"dport\", \"vlan\", "
			     "\"proto\"", argv[start_arg]);

		start_arg += 2;
	}
	if (start_arg != argc)
		errx(1, "unknown parameter \"%s\"", argv[start_arg]);

#if 0
	printf("sip: %x:%x, dip: %x:%x, sport: %x:%x, dport: %x:%x, "
	       "interface: %x:%x, vlan: %x:%x, tx_config: %u, rx_config: %u, "
	       "invert: %u, tx_enable: %u, rx_enable: %u\n", op.sip,
	       op.sip_mask, op.dip, op.dip_mask, op.sport, op.sport_mask,
	       op.dport, op.dport_mask, op.intf, op.intf_mask, op.vlan,
	       op.vlan_mask, op.config_tx, op.config_rx, op.invert_match,
	       op.trace_tx, op.trace_rx);
#endif
	op.cmd = CHELSIO_SET_TRACE_FILTER;
	if (doit(iff_name, &op) < 0)
		err(1, "trace");
	return 0;
}

static int read_nqsets(const char *iff_name, int *sq, int *nq)
{
	struct ch_qset_params op;

	op.cmd = CHELSIO_GET_QSET_PARAMS;
	op.qset_idx = 0;

	while (doit(iff_name, &op) == 0) {
		if (!op.qset_idx)
			*sq = op.qnum;
		op.qset_idx++;
	}

	*nq = op.qset_idx;

	return 0;
}


static int setup_lro(int argc, char *argv[], int start_arg,
		const char *iff_name)
{
	int sq = 0, nq, lq;
	char sbuf0[32];

	if (argc == start_arg)
		errx(1, "missing argument to enable/disable lro");

	if (argc > 4)
		errx(1, "too many arguments");

	read_nqsets(iff_name, &sq, &nq);

	argv[4] = "lro";
	if (!strcmp(argv[3], "on") || !strcmp(argv[3], "1"))
		argv[5] = "1";
	else if (!strcmp(argv[3], "off") || !strcmp(argv[3], "0"))
		argv[5] = "0";
	else
		errx(1, "bad argument \"%s\"; must be \"on\" or \"off\"",
			argv[3]);

	lq = sq + nq;
	while (sq < lq) {
		sprintf(sbuf0, "%i", sq);
		argv[3] = sbuf0;
		qset_config(6, argv, 3, iff_name);
		sq++;
	}

	printf("%s LRO for all Queues on %s\n",
		!strcmp(argv[5], "1") ? "Enabled" : "Disabled", iff_name);

	return 0;
}

static int setup_napi(int argc, char *argv[], int start_arg,
		const char *iff_name)
{
	int sq = 0, nq, lq;
	char sbuf0[32];

	if (argc == start_arg)
		errx(1, "missing argument to enable/disable napi");

	if (argc > 4)
		errx(1, "too many arguments");

	read_nqsets(iff_name, &sq, &nq);

	argv[4] = "mode";
	if (!strcmp(argv[3], "on") || !strcmp(argv[3], "1"))
		argv[5] = "napi";
	else if (!strcmp(argv[3], "off") || !strcmp(argv[3], "0"))
		argv[5] = "irq";
	else
		errx(1, "bad argument \"%s\"; must be \"on\" or \"off\"",
			argv[3]);

	lq = sq + nq;
	while (sq < lq) {
		sprintf(sbuf0, "%i", sq);
		argv[3] = sbuf0;
		qset_config(6, argv, 3, iff_name);
		sq++;
	}

	printf("%s NAPI for all Queues on %s\n",
		!strcmp(argv[5], "napi") ? "Enabled" : "Disabled", iff_name);

	return 0;
}

static int is_chelsio_iface(const char *iff_name)
{
	struct ethtool_drvinfo drvinfo = {0};
	char *iface;
	FILE *fp;
	char iface_device[256] = {0};
	char vendor_id[8] = {0};

	if (is_file(iff_name)) {
		if (strchr(iff_name, ':') != NULL) {
			/*
			 * Interface is a sysfs device path like
			 * /sys/devices/pci0000\:00/0000:00:04.0/0000:08:00.0
			 */
			snprintf(iface_device, sizeof(iface_device),
					"%s/vendor", iff_name);
			fp = fopen(iface_device, "r");
			if (fp == NULL)
				return 0;
			/*
			 * vendor_id is a string of length 6 (0x1425)
			 */
			if (fread(vendor_id, 1, 6, fp) != 6) {
				fclose(fp);
				return 0;
			}
			fclose(fp);
			if (!strcmp(vendor_id, "0x1425"))
				return 1;
			else
				return 0;
		} else {
			/*
			 * Interface is a sysfs interface path like
			 * /sys/class/net/eth2
			 */
			iface = strrchr(iff_name, '/');
			if (iface == NULL)
				return 0;
			iface += 1;
		}
	} else
		iface = (char *)iff_name;

	drvinfo.cmd = ETHTOOL_GDRVINFO;
	if (ethtool_call(iface, &drvinfo))
		return 0;
	if (!strncmp("cxgb", drvinfo.driver, 4))
		return 1;

	return 0;
}

static int
driver_file(int argc, char *argv[], int start_arg, const char *iff_name)
{
	char bus_slot_func[ETHTOOL_BUSINFO_LEN];
	char proc_cmd[PATH_MAX + 4];
	char debug_cmd[PATH_MAX + 4];

	if (get_adapter_ver(iff_name) < 4)
		errx(1, "%s is not a Chelsio T4 or T5 interface", iff_name);

	get_pci_bus_slot_func(iff_name, bus_slot_func, sizeof(bus_slot_func));

	if (argc < 4) {
		snprintf(proc_cmd, sizeof(proc_cmd),
			 "ls "PROC_PATH"%s/",
			 bus_slot_func);
		snprintf(debug_cmd, sizeof(debug_cmd),
			 "ls "DRIVER_PATH"%s/",
			 bus_slot_func);

		if ((system(proc_cmd) < 0) || (system(debug_cmd) < 0))
			errx(1, "Can't access driver files");
	} else if (argc > 4)
		usage(stderr);
	else
		if (dump_file(argv[start_arg], iff_name) < 0)
			errx(1, "Can't access driver files");
	printf("\n");
	return 0;
}

static int filter_show(const char *iff_name)
{
	printf("\nLE-TCAM Filters:\n\n");
	if (dump_file("filters", iff_name) < 0)
		err(1, "can't access filters");
	printf("\n");

	printf("\nHash Filters:\n\n");
	if (dump_file("hash_filters", iff_name) < 0)
		err(1, "can't access hash filters");
	printf("\n");

	return 0;
}

static int filter_config(int argc, char *argv[], int start_arg,
			 const char *iff_name)
{
	int af = AF_UNSPEC;
	struct ch_filter op;
	uint32_t filter_id;
	int temp_arg;

	if (argc < start_arg + 1)
		return -1;

	memset(&op, 0, sizeof(op));
        
	if (!strcmp(argv[start_arg], "show")) {
		filter_show(iff_name);
		return 0;
	}else if (get_int_arg(argv[start_arg++], &filter_id))
		return -1;
	op.filter_id = filter_id;
	op.filter_ver = CH_FILTER_SPECIFICATION_ID;

	if (argc == start_arg + 1 && (!strcmp(argv[start_arg], "delete") ||
				      !strcmp(argv[start_arg], "clear"))) {
		op.cmd = CHELSIO_DEL_FILTER;
		if (doit(iff_name, &op) < 0)
			err(1, "delete filter");
		return 0;
	} else if (argc == start_arg + 3 && (!strcmp(argv[start_arg], "delete") ||
				      !strcmp(argv[start_arg], "clear"))) {
		op.cmd = CHELSIO_DEL_FILTER;
		start_arg++;

		if (!strcmp(argv[start_arg], "cap")) {
	        	if (!strcmp(argv[start_arg + 1], "maskless"))
				op.fs.cap = 1;
			else if (!strcmp(argv[start_arg + 1], "maskfull"))
				op.fs.cap = 0;
			else
				errx(1, "unknown cap \"%s\"; must be one of"
						" \"maskless\"  or \"maskfull\"",
						argv[start_arg + 1]);
		}

		if (doit(iff_name, &op) < 0) {
			if (errno == EBUSY)
				err(1, "no filter support when offload in use");
			err(1, "delete filter");
		}
		return 0;
	}

	temp_arg = start_arg;
	while (temp_arg + 2 <= argc) {
		if (!strcmp(argv[temp_arg], "cap")) {
			if (!strcmp(argv[temp_arg + 1], "maskless"))
				op.fs.cap = 1;
			else if (!strcmp(argv[temp_arg + 1], "maskfull"))
				op.fs.cap = 0;
			else
				errx(1, "unknown cap \"%s\"; must be one of"
					" \"maskless\"  or \"maskfull\"",
					argv[temp_arg + 1]);
		}
		temp_arg += 2;
	}

	while (start_arg + 2 <= argc) {
		char **args = &argv[start_arg];
		uint32_t val, mask;

		if (!strcmp(argv[start_arg], "type")) {
			int newaf;
			if (!strcasecmp(argv[start_arg + 1], "ipv4"))
				newaf = AF_INET;
			else if (!strcasecmp(argv[start_arg + 1], "ipv6"))
				newaf = AF_INET6;
			else
				errx(1, "unknown ipv parameter; must be one of"
				     " \"ipv4\" or \"ipv6\"");
			if (af != AF_UNSPEC && af != newaf)
				errx(1, "conflicting IPv4 and IPv6"
				     " specifications.\n");
			af = newaf;
		} else if (parse_val_mask("fcoe", args, &val, &mask,
					  FCOE_BITWIDTH, op.fs.cap)) {
			op.fs.val.fcoe = val;
			op.fs.mask.fcoe = mask;
		} else if (parse_val_mask("iport", args, &val, &mask,
					  IPORT_BITWIDTH, op.fs.cap)) {
			op.fs.val.iport = val;
			op.fs.mask.iport = mask;
		} else if (parse_val_mask("ovlan", args, &val, &mask,
					  OVLAN_BITWIDTH, op.fs.cap)) {
			op.fs.val.ovlan = val;
			op.fs.mask.ovlan = mask;
			op.fs.val.ovlan_vld = 1;
			op.fs.mask.ovlan_vld = 1;
		} else if (parse_val_mask("ivlan", args, &val, &mask,
					  IVLAN_BITWIDTH, op.fs.cap)) {
			op.fs.val.ivlan = val;
			op.fs.mask.ivlan = mask;
			op.fs.val.ivlan_vld = 1;
			op.fs.mask.ivlan_vld = 1;
		} else if (parse_val_mask("pf", args, & val, &mask,
					  PF_BITWIDTH, op.fs.cap)) {
			op.fs.val.pf = val;
			op.fs.mask.pf = mask;
			op.fs.val.pfvf_vld = 1;
			op.fs.mask.pfvf_vld = 1;
		} else if (parse_val_mask("vf", args, & val, &mask,
					  VF_BITWIDTH, op.fs.cap)) {
			op.fs.val.vf = val;
			op.fs.mask.vf = mask;
			op.fs.val.pfvf_vld = 1;
			op.fs.mask.pfvf_vld = 1;
		} else if (parse_val_mask("tos", args, &val, &mask,
					  TOS_BITWIDTH, op.fs.cap)) {
			op.fs.val.tos = val;
			op.fs.mask.tos = mask;
		} else if (parse_val_mask("proto", args, &val, &mask,
					  PROTO_BITWIDTH, op.fs.cap)) {
			op.fs.val.proto = val;
			op.fs.mask.proto = mask;
		} else if (parse_val_mask("ethtype", args, &val, &mask,
					  ETHTYPE_BITWIDTH, op.fs.cap)) {
			op.fs.val.ethtype = val;
			op.fs.mask.ethtype = mask;
		} else if (parse_val_mask("macidx", args, &val, &mask,
			   MACIDX_BITWIDTH, op.fs.cap)) {
			op.fs.val.macidx = val;
			op.fs.mask.macidx = mask;
		} else if (parse_val_mask("matchtype", args, &val, &mask,
					  MATCHTYPE_BITWIDTH, op.fs.cap)) {
			op.fs.val.matchtype = val;
			op.fs.mask.matchtype = mask;
		} else if (parse_val_mask("frag", args, &val, &mask,
					  FRAG_BITWIDTH, op.fs.cap)) {
			op.fs.val.frag = val;
			op.fs.mask.frag = mask;
		} else if (parse_val_mask("lport", args, &val, &mask, 0, op.fs.cap)) {
			op.fs.val.lport = val;
			op.fs.mask.lport = mask;
		} else if (parse_val_mask("fport", args, &val, &mask, 0, op.fs.cap)) {
			op.fs.val.fport = val;
			op.fs.mask.fport = mask;
		} else if (parse_ipaddr("lip", args, &af, op.fs.val.lip, op.fs.mask.lip,
			   op.fs.cap)) {
			/*nada*/;
		} else if (parse_ipaddr("fip", args, &af, op.fs.val.fip, op.fs.mask.fip,
			   op.fs.cap)) {
			/*nada*/;
		} else if (!strcmp(argv[start_arg], "action")) {
			if (!strcmp(argv[start_arg + 1], "pass"))
				op.fs.action = FILTER_PASS;
			else if (!strcmp(argv[start_arg + 1], "drop"))
				op.fs.action = FILTER_DROP;
			else if (!strcmp(argv[start_arg + 1], "switch"))
				op.fs.action = FILTER_SWITCH;
			else
				errx(1, "unknown action \"%s\"; must be one of"
				     " \"pass\", \"drop\" or \"switch\"",
				     argv[start_arg + 1]);
		} else if (parse_val("hitcnts", args, &val)) {
			op.fs.hitcnts = val;
		} else if (parse_val("prio", args, &val)) {
			op.fs.prio = val;
		} else if (parse_val("rpttid", args, &val)) {
			op.fs.rpttid = 1;
		} else if (parse_val("queue", args, &val)) {
			op.fs.dirsteer = 1;
			op.fs.iq = val;
		} else if (parse_val("tcbhash", args, &val)) {
			op.fs.maskhash = 1;
			op.fs.dirsteerhash = 1;
		} else if (parse_val("eport", args, &val)) {
			op.fs.eport = val;
		} else if (parse_val("swapmac", args, &val)) {
			op.fs.swapmac = 1;
		} else if (!strcmp(argv[start_arg], "dmac")) {
			struct ether_addr *daddr = ether_aton(argv[start_arg + 1]);
			if (daddr == NULL)
				errx(1, "invalid dmac address \"%s\"",
				     argv[start_arg + 1]);
			memcpy(op.fs.dmac, daddr, ETH_ALEN);
			op.fs.newdmac = 1;
		} else if (!strcmp(argv[start_arg], "smac")) {
			struct ether_addr *saddr = ether_aton(argv[start_arg + 1]);
			if (saddr == NULL)
				errx(1, "invalid smac address \"%s\"",
				     argv[start_arg + 1]);
			memcpy(op.fs.smac, saddr, ETH_ALEN);
			op.fs.newsmac = 1;
		} else if (!strcmp(argv[start_arg], "vlan")) {
			char *p;
			if (!strcmp(argv[start_arg + 1], "none")) {
				op.fs.newvlan = VLAN_REMOVE;
			} else if (argv[start_arg + 1][0] == '=') {
				op.fs.newvlan = VLAN_REWRITE;
			} else if (argv[start_arg + 1][0] == '+') {
				op.fs.newvlan = VLAN_INSERT;
			} else
				errx(1, "unknown vlan parameter \"%s\"; must"
				     " be one of \"none\", \"=<vlan>\" or"
				     " \"+<vlan>\"", argv[start_arg + 1]);
			if (op.fs.newvlan == VLAN_REWRITE ||
			    op.fs.newvlan == VLAN_INSERT) {
				op.fs.vlan = strtoul(argv[start_arg + 1] + 1,
				    &p, 0);
				if (p == argv[start_arg + 1] + 1 || p[0] != 0)
					errx(1, "bad vlan value \"%s\"",
					     argv[start_arg + 1]);
			}
		} else if (!strcmp(argv[start_arg], "cap")) {
			/* do nothing since we already parsed it before.. */
		} else
 			errx(1, "unknown filter parameter \"%s\"",
			     argv[start_arg]);

		start_arg += 2;
	}
	if (start_arg != argc)
		errx(1, "no value for \"%s\"", argv[start_arg]);

	/*
	 * Check basic sanity of option combinations.
	 */
	if (op.fs.action != FILTER_SWITCH &&
	    (op.fs.eport || op.fs.newdmac || op.fs.newsmac || op.fs.newvlan ||
	     op.fs.swapmac))
		errx(1, "prio, port dmac, smac, swapmac and vlan only make"
		     " sense with \"action switch\"");
	if (op.fs.action != FILTER_PASS &&
	    (op.fs.rpttid || op.fs.dirsteer || op.fs.maskhash))
		errx(1, "rpttid, queue and tcbhash don't make sense with"
		     " action \"drop\" or \"switch\"");

	op.cmd = CHELSIO_SET_FILTER;
	op.fs.type = (af == AF_INET6 ? 1 : 0); /* default IPv4 */
	if (doit(iff_name, &op) < 0)
		err(1, "set filter");

	if (op.fs.cap)
		printf("Hash-Filter Index = %u\n", op.filter_id);

	return 0;
}

static int get_sched_param(int argc, char *argv[], int pos, unsigned int *valp)
{
	if (pos + 1 >= argc)
		errx(1, "missing value for %s", argv[pos]);
	if (get_int_arg(argv[pos + 1], valp))
		exit(1);
	return 0;
}

static int tx_sched(int argc, char *argv[], int start_arg, const char *iff_name)
{
	struct ch_hw_sched op;
	unsigned int idx, val;

	if (argc < 5 || get_int_arg(argv[start_arg++], &idx))
		return -1;

	op.cmd = CHELSIO_SET_HW_SCHED;
	op.sched = idx;
	op.mode = op.channel = op.weight = -1;
	op.kbps = op.class_ipg = op.flow_ipg = -1;

	while (argc > start_arg) {
		if (!strcmp(argv[start_arg], "mode")) {
			if (start_arg + 1 >= argc)
				errx(1, "missing value for mode");
			if (!strcmp(argv[start_arg + 1], "class"))
				op.mode = 0;
			else if (!strcmp(argv[start_arg + 1], "flow"))
				op.mode = 1;
			else
				errx(1, "bad mode \"%s\"", argv[start_arg + 1]);
		} else if (!strcmp(argv[start_arg], "channel") &&
			 !get_sched_param(argc, argv, start_arg, &val))
			op.channel = val;
		else if (!strcmp(argv[start_arg], "weight") &&
			!get_sched_param(argc, argv, start_arg, &val))
			op.weight = val;
		else if (!strcmp(argv[start_arg], "rate") &&
			 !get_sched_param(argc, argv, start_arg, &val))
			op.kbps = val;
		else if (!strcmp(argv[start_arg], "ipg") &&
			 !get_sched_param(argc, argv, start_arg, &val))
			op.class_ipg = val;
		else if (!strcmp(argv[start_arg], "flowipg") &&
			 !get_sched_param(argc, argv, start_arg, &val))
			op.flow_ipg = val;
		else
			errx(1, "unknown scheduler parameter \"%s\"",
			     argv[start_arg]);
		start_arg += 2;
	}

	if (doit(iff_name, &op) < 0)
		 err(1, "pktsched");

	return 0;
}

static int pktsched(int argc, char *argv[], int start_arg, const char *iff_name)
{
	struct ch_pktsched_params op;
	unsigned int idx, min = -1, max;

	if (argc < 4)
		errx(1, "no scheduler specified");

	if (!strcmp(argv[start_arg], "port")) {
		if (argc <= start_arg + 1)
			return -1;

		op.sched = PKTSCHED_PORT;

		/* no min and max provided, do a get */
		if (argc == start_arg + 2) {
			op.cmd = CHELSIO_GET_PKTSCHED;
			if (get_int_arg(argv[start_arg + 1], &idx))
				return -1;
			goto doit;
		}

		if (argc != start_arg + 4)
			return -1;

		if (get_int_arg(argv[start_arg + 1], &idx) ||
		    get_int_arg(argv[start_arg + 2], &min) ||
		    get_int_arg(argv[start_arg + 3], &max))
			return -1;

		if ((int)min > (int)max)
			errx(-1, "error min value (%d) is greater"
			     "than max value (%d)", min, max);
		if ((int)min < 0 || (int)max < 0 || (int)min > 100 || (int)max > 100)
			errx(-1, "error min and max values should be"
			     " between 0 and 100");

	} else if (!strcmp(argv[start_arg], "tunnelq")) {
		if (argc <= start_arg + 1)
			return -1;

		op.sched = PKTSCHED_TUNNELQ;

		/* no max value provided, do a get */
		if (argc == start_arg + 2) {
			op.cmd = CHELSIO_GET_PKTSCHED;
			get_int_arg(argv[start_arg + 1], &idx);
			goto doit;
		}

		if (argc != start_arg + 3)
			return -1;

		if (get_int_arg(argv[start_arg + 1], &idx) ||
		    get_int_arg(argv[start_arg + 2], &max))
			return -1;

		if ((int)max > 100 || (int)max < 0)
			errx(-1, "error max value should be between 0 and 100");

	} else if (!strcmp(argv[start_arg], "tx"))
		return tx_sched(argc, argv, start_arg + 1, iff_name);
	else
		errx(1, "unknown scheduler \"%s\"; must be one of \"port\", "
			"\"tunnelq\" or \"tx\"", argv[start_arg]);

	op.min = min;
	op.max = max;
	op.binding = -1;
	op.cmd = CHELSIO_SET_PKTSCHED;
doit:	op.idx = idx;
	if (doit(iff_name, &op) < 0)
		 err(1, "pktsched");

	if (op.cmd == CHELSIO_GET_PKTSCHED) {
		if (op.sched == PKTSCHED_PORT)
			printf("Port Min %d \tPort Max %d\n", op.min, op.max);
		else if (op.sched == PKTSCHED_TUNNELQ)
			printf("Tunnelq Max %d\n", op.max);
	}

	return 0;
}


static int sched_class(int argc, char *argv[], int start_arg, const char *iff_name)
{
	struct ch_sched_params op;
	unsigned int val;
	int errs;

	/*
	 * Initialize message to all unset/invalid values so the driver can
	 * tell what's being specifically requested.  We initialize the entire
	 * message to 0xff to indicate uninitialized values.  Since virtually
	 * all CPUs [now] use 2's Complement representation to store signed
	 * integers this causes them all to take on a value 0f -1 -- including
	 * the reserved fields at the end of the message.  This will make it
	 * easier for us to add new fields later on while maintaining binary
	 * compatibility.  But for the sake of correctness, we explicitly
	 * initialize the currently defined fields with -1 ...
	 */
	memset(&op, ~0, sizeof op);
	op.subcmd = -1;
	op.type = -1;
	if (start_arg == argc)
		errx(1, "missing scheduling sub-command");
	if (!strcmp(argv[start_arg], "config")) {
		op.subcmd = SCHED_CLASS_SUBCMD_CONFIG;
		op.u.config.minmax = -1;
	} else if (!strcmp(argv[start_arg], "params")) {
		op.subcmd = SCHED_CLASS_SUBCMD_PARAMS;
		op.u.params.level
		= op.u.params.mode
		= op.u.params.rateunit
		= op.u.params.ratemode
		= op.u.params.channel
		= op.u.params.class
		= op.u.params.minrate
		= op.u.params.maxrate
		= op.u.params.weight
		= op.u.params.pktsize
		= -1;
	} else
		errx(1, "invalid scheduling sub-command \"%s\"",
		     argv[start_arg]);
	start_arg++;

	/*
	 * Decode remaining arguments ...
	 */
	for (errs = 0; argc > start_arg; start_arg += 2) {
		if (start_arg+1 == argc) {
			warnx("missing argument for \"%s\"",
			      argv[start_arg]);
			errs++;
			break;
		}

		if (!strcmp(argv[start_arg], "type")) {
			if (!strcmp(argv[start_arg+1], "packet"))
				op.type = SCHED_CLASS_TYPE_PACKET;
			else if (!strcmp(argv[start_arg+1], "stream"))
				op.type = SCHED_CLASS_TYPE_STREAM;
			else {
				warnx("invalid type parameter \"%s\"",
				      argv[start_arg+1]);
				errs++;
			}

			continue;
		}

		if (op.subcmd == SCHED_CLASS_SUBCMD_CONFIG) {
			if (!strcmp(argv[start_arg], "minmax") &&
			    !get_sched_param(argc, argv, start_arg, &val))
				op.u.config.minmax = val;
			else {
				warnx("unknown scheduler config parameter "
				      "\"%s\"", argv[start_arg]);
				errs++;
			}

			continue;
		}

		if (op.subcmd == SCHED_CLASS_SUBCMD_PARAMS) {
			if (!strcmp(argv[start_arg], "level")) {
			    if (!strcmp(argv[start_arg+1], "cl-rl"))
				op.u.params.level = SCHED_CLASS_LEVEL_CL_RL;
			    else if (!strcmp(argv[start_arg+1], "cl-wrr"))
				op.u.params.level = SCHED_CLASS_LEVEL_CL_WRR;
			    else if (!strcmp(argv[start_arg+1], "ch-rl"))
				op.u.params.level = SCHED_CLASS_LEVEL_CH_RL;
			    else {
				warnx("invalid level parameter \"%s\"",
				      argv[start_arg+1]);
				errs++;
			    }
			} else if (!strcmp(argv[start_arg], "mode")) {
			    if (!strcmp(argv[start_arg+1], "class"))
				op.u.params.mode = SCHED_CLASS_MODE_CLASS;
			    else if (!strcmp(argv[start_arg+1], "flow"))
				op.u.params.mode = SCHED_CLASS_MODE_FLOW;
			    else {
				warnx("invalid mode parameter \"%s\"",
				      argv[start_arg+1]);
				errs++;
			    }
			} else if (!strcmp(argv[start_arg], "rate-unit")) {
			    if (!strcmp(argv[start_arg+1], "bits"))
				op.u.params.rateunit = SCHED_CLASS_RATEUNIT_BITS;
			    else if (!strcmp(argv[start_arg+1], "pkts"))
				op.u.params.rateunit = SCHED_CLASS_RATEUNIT_PKTS;
			    else {
				warnx("invalid rate-unit parameter \"%s\"",
				      argv[start_arg+1]);
				errs++;
			    }
			} else if (!strcmp(argv[start_arg], "rate-mode")) {
			    if (!strcmp(argv[start_arg+1], "relative"))
				op.u.params.ratemode = SCHED_CLASS_RATEMODE_REL;
			    else if (!strcmp(argv[start_arg+1], "absolute"))
				op.u.params.ratemode = SCHED_CLASS_RATEMODE_ABS;
			    else {
				warnx("invalid rate-mode parameter \"%s\"",
				      argv[start_arg+1]);
				errs++;
			    }
			} else if (!strcmp(argv[start_arg], "channel") &&
			    !get_sched_param(argc, argv, start_arg, &val))
				op.u.params.channel = val;
			else if (!strcmp(argv[start_arg], "class") &&
				 !get_sched_param(argc, argv, start_arg, &val))
				op.u.params.class = val;
			else if (!strcmp(argv[start_arg], "min-rate") &&
				 !get_sched_param(argc, argv, start_arg, &val))
				op.u.params.minrate = val;
			else if (!strcmp(argv[start_arg], "max-rate") &&
				 !get_sched_param(argc, argv, start_arg, &val))
				op.u.params.maxrate = val;
			else if (!strcmp(argv[start_arg], "weight") &&
				 !get_sched_param(argc, argv, start_arg, &val))
				op.u.params.weight = val;
			else if (!strcmp(argv[start_arg], "pkt-size") &&
				 !get_sched_param(argc, argv, start_arg, &val))
				op.u.params.pktsize = val;
			else {
				warnx("unknown scheduler parameter \"%s\"",
				      argv[start_arg]);
				errs++;
			}

			continue;
		}
	}

	/*
	 * Catch some logical falacies in terms of argument combinations here
	 * so we can offer more than just the EINVAL return from the driver.
	 * The driver will be able to catch a lot more issues since it knows
	 * the specifics of the device hardware capabilities like how many
	 * channels, classes, etc. the device supports.
	 */
	if (op.type < 0) {
		warnx("sched \"type\" parameter missing");
		errs++;
	}
	if (op.subcmd == SCHED_CLASS_SUBCMD_CONFIG) {
		if (op.u.config.minmax < 0) {
			errx(1, "sched config \"minmax\" parameter missing");
			errs++;
		}
	}
	if (op.subcmd == SCHED_CLASS_SUBCMD_PARAMS) {
		if (op.u.params.level < 0) {
			warnx("sched params \"level\" parameter missing");
			errs++;
		}
		if (op.u.params.mode < 0 &&
		    op.u.params.level == SCHED_CLASS_LEVEL_CL_RL) {
			warnx("sched params \"mode\" parameter missing");
			errs++;
		}
		if (op.u.params.rateunit < 0 &&
                    (op.u.params.level == SCHED_CLASS_LEVEL_CL_RL ||
                     op.u.params.level == SCHED_CLASS_LEVEL_CH_RL)) {
			warnx("sched params \"rate-unit\" parameter missing");
			errs++;
		}
		if (op.u.params.ratemode < 0 &&
		    (op.u.params.level == SCHED_CLASS_LEVEL_CL_RL ||
		     op.u.params.level == SCHED_CLASS_LEVEL_CH_RL)) {
			warnx("sched params \"rate-mode\" parameter missing");
			errs++;
		}
		if (op.u.params.channel < 0) {
			warnx("sched params \"channel\" missing");
			errs++;
		}
		if (op.u.params.class < 0 &&
		    (op.u.params.level == SCHED_CLASS_LEVEL_CL_RL ||
		     op.u.params.level == SCHED_CLASS_LEVEL_CL_WRR)) {
			warnx("sched params \"class\" missing");
			errs++;
		}
		if (op.u.params.maxrate < 0 &&
		    (op.u.params.level == SCHED_CLASS_LEVEL_CL_RL ||
		     op.u.params.level == SCHED_CLASS_LEVEL_CH_RL)) {
			warnx("sched params \"max-rate\" missing for "
			      "rate-limit level");
			errs++;
		}
		if (op.u.params.weight < 0 &&
		    op.u.params.level == SCHED_CLASS_LEVEL_CL_WRR) {
			warnx("sched params \"weight\" missing for "
			      "weighted-round-robin level");
			errs++;
		}
		else if (op.u.params.level == SCHED_CLASS_LEVEL_CL_WRR &&
			 !in_range(op.u.params.weight, 1, 99)) {
				warnx("sched params \"weight\" takes "
				      "value(1-99)");
				errs++;
		}
		if (op.u.params.pktsize < 0 &&
		    op.u.params.level == SCHED_CLASS_LEVEL_CL_RL) {
			warnx("sched params \"pkt-size\" missing for "
			      "rate-limit level");
			errs++;
		}
		if (op.u.params.mode == SCHED_CLASS_MODE_FLOW &&
		    op.u.params.ratemode != SCHED_CLASS_RATEMODE_ABS) {
			warnx("sched params mode flow needs rate-mode absolute");
			errs++;
		}
		if (op.u.params.ratemode == SCHED_CLASS_RATEMODE_REL &&
		    !in_range(op.u.params.maxrate, 1, 100)) {
			warnx("sched params \"max-rate\" takes "
			      "percentage value(1-100) for rate-mode relative");
			errs++;
		}
		if (op.u.params.ratemode == SCHED_CLASS_RATEMODE_ABS &&
		    !in_range(op.u.params.maxrate, 1, 10000000)) {
			warnx("sched params \"max-rate\" takes "
			      "value(1-10000000) for rate-mode absolute");
			errs++;
		}
		if (op.u.params.maxrate > 0 &&
		    op.u.params.maxrate < op.u.params.minrate) {
			warnx("sched params \"max-rate\" is less than "
			      "\"min-rate\"");
			errs++;
		}
	}

	if (errs > 0)
		errx(1, "%d error%s in sched-class command",
		     errs, errs == 1 ? "" : "s");

	/*
	 * 
	 */
	op.cmd = CHELSIO_SET_SCHED_CLASS;
	if (doit(iff_name, &op) < 0)
		 err(1, "sched-class");
	return 0;

}

static int sched_queue(int argc, char *argv[], int start_arg, const char *iff_name)
{
	struct ch_sched_queue op;
	uint32_t val;

	memset(&op, 0, sizeof op);

	if (argc != start_arg + 2)
		errx(1, "need TX Queue Index and Class Index");

	if (!strcmp(argv[start_arg], "all") ||
	    !strcmp(argv[start_arg], "*"))
		op.queue = -1;
	else {
		if (get_int_arg(argv[start_arg], &val))
			return -1;
		op.queue = val;
	}

	if (!strcmp(argv[start_arg+1], "unbind") ||
	    !strcmp(argv[start_arg+1], "clear"))
		op.class = -1;
	else {
		if (get_int_arg(argv[start_arg+1], &val))
			return -1;
		op.class = val;
	}

	op.cmd = CHELSIO_SET_SCHED_QUEUE;
	if (doit(iff_name, &op) < 0)
		err(1, "sched-queue");

	return 0;
}

static int sched_pfvf(int argc, char *argv[], int start_arg, const char *iff_name)
{
	struct ch_sched_pfvf op;
	uint32_t pf, vf, class;

	memset(&op, 0, sizeof op);

	if (argc != start_arg + 3)
		errx(1, "need PF, VF and TX Class Index");

	if (get_int_arg(argv[start_arg+0], &pf) ||
	    get_int_arg(argv[start_arg+1], &vf))
		return -1;
	op.pf = pf;
	op.vf = vf;

	/*
	 * We know the legitimate PF values are in the range [0..7] but legal
	 * VF values depend on the card and how it's programmed.  So we'll let
	 * the firmware complain if the VF value is out of range ...  Note
	 * that op.pf is unsigned so the compiler gets pissy if we use
	 * in_range(op.pf, 0, 7) ...
	 */
	if (op.pf > 7)
		errx(1, "scehd-pfvf pf must be in [0..7]");

	if (!strcmp(argv[start_arg+2], "unbind") ||
	    !strcmp(argv[start_arg+2], "clear"))
		op.class = -1;
	else {
		if (get_int_arg(argv[start_arg+2], &class))
			return -1;
		op.class = class;
	}

	op.cmd = CHELSIO_SET_SCHED_PFVF;
	if (doit(iff_name, &op) < 0)
		err(1, "sched-pfvf");

	return 0;
}

#ifdef CHELSIO_T4_DIAGS
static int clear_flash(int argc, char *argv[], int start_arg,
		       const char *iff_name)
{
	struct ch_reg op;

	op.cmd = CHELSIO_CLEAR_FLASH;

	if (doit(iff_name, &op) < 0)
		err(1, "clearflash");

	return 0;
}
#endif

/*
 *	load_boot_cfg -  this function can be used to load optionrom configuration data to the flash
 *	@*iffname: the interface name, ex eth2
 *
 *	this function will load default configuration data  
 *	to the flash.
 */
static uint32_t load_boot_cfg(int argc, char *argv[], int start_arg, const char *iff_name)
{
	int fd;
	size_t bootcfg_file_size, len, i;
	struct struct_load_cfg *op;
	const char *fname = argv[start_arg];
	struct stat stbuf;

	if (argc != start_arg + 1)
		return -1;

	/*
	 * If we're given the special "clear" filename, pass that on as a
	 * zero-length file to the driver as an indication that the FLASH area
	 * reserved for a OptionROM Config should be cleared 
	 */ 
	if (strcmp(fname, "clear") == 0) {
		struct struct_load_cfg clear_op;

		clear_op.cmd = CHELSIO_LOAD_BOOTCFG;
		clear_op.len = 0;
		if (doit(iff_name, &clear_op) < 0)
			err(1, "loadboot-cfg %s clear", iff_name);
		return 0;
	} 

	/*
	 * Open the Boot Configuration File and grab its size.
  	 */
	fd = open(fname, O_RDONLY);
	if (fd < 0)
		errx(1, "loadboot-cfg %s - open %s", iff_name, fname);

	if (fstat(fd, &stbuf) == -1) {
		errx(1, "loadboot-cfg %s - fstat %s", iff_name, fname);
	}
	bootcfg_file_size = stbuf.st_size;
	if (bootcfg_file_size == 0) {
		errx(1, "loadboot-cfg %s - %s file size is zero", iff_name, fname);
	}

	/*
 	 * The Boot Configuration File which we pass to the driver must
 	 * have a length of a multiple of 4.  If the file isn't, then we'll
 	 * pad it up with 0's.
 	 */ 
	len = (bootcfg_file_size + 4-1) & ~3;
	op = malloc(sizeof(*op) + len);
	if (!op)
		err(1, "loadboot-cfg %s - malloc %s buffer", iff_name, fname);
	if (read(fd, op->buf, bootcfg_file_size) < 0)
		err(1, "loadboot-cfg %s - read %s", iff_name, fname);
	for (i = bootcfg_file_size; i < len; i++)
		op->buf[i] = 0;
	close(fd);

	/* 
 	 * Send the load cponfiguration file command down to the driver.
 	 */
	op->cmd   = CHELSIO_LOAD_BOOTCFG;
	op->len   = len;
	if (doit(iff_name, op) < 0)
		errx(1, "loadcfg %s", fname);
	return 0;
}


static int clear_stats(int argc, char *argv[], int start_arg,
		       const char *iff_name)
{
	struct ch_reg op;

	op.cmd = CHELSIO_CLEAR_STATS;
	op.addr = -1;

	if (argc == start_arg)
		op.val = STATS_PORT | STATS_QUEUE;
	else if (argc == start_arg + 1) {
		if (!strcmp(argv[start_arg], "port"))
			op.val = STATS_PORT;
		else if (!strcmp(argv[start_arg], "queue"))
			op.val = STATS_QUEUE;
		else
			return -1;
	} else if (argc == start_arg + 2 && !strcmp(argv[start_arg], "queue")) {
		if (get_int_arg(argv[start_arg + 1], &op.addr))
			return -1;
		op.val = STATS_QUEUE;
	} else
		return -1;

	if (doit(iff_name, &op) < 0)
		 err(1, "clearstats");
	return 0;
}

static int get_up_la(int argc, char *argv[], int start_arg, const char *iff_name)
{
	struct ch_up_la *op;
	int i, idx, max_idx, entries;
	const int la_entries = 2048; /* expected to cover both T3 and T4 */
	const size_t la_bufsize = la_entries * sizeof(op->la[0]);

	op = malloc(sizeof(*op) + la_bufsize);
	if (op == NULL)
		err(1, "up_la");

	op->cmd = CHELSIO_GET_UP_LA;
	op->bufsize = la_bufsize;
	op->idx = -1;

	if (doit(iff_name, op) < 0) {
		free(op);
		err(1, "up_la");
	}

	if (op->stopped)
		printf("LA is not running\n");

	entries = op->bufsize / sizeof(op->la[0]);
	idx = (int)op->idx;
	max_idx = (entries / 4) - 1;
	for (i = 0; i < max_idx; i++) {
		printf("%04x %08x %08x\n",
		       op->la[idx], op->la[idx+2], op->la[idx+1]);
		idx = (idx + 4) & (entries - 1);
	}

	free(op);
	return 0;
}

static int get_up_ioqs(int argc, char *argv[], int start_arg, const char *iff_name)
{
	struct ch_up_ioqs *op;
	int i, entries;
	const int ioq_entries = 24; /* expected to cover both T3 and T4 */
	const size_t ioq_bufsize = ioq_entries * sizeof(op->ioqs[0]);

	op = malloc(sizeof(*op) + ioq_bufsize);
	if (op == NULL)
		err(1, "up_ioqs");

	op->cmd = CHELSIO_GET_UP_IOQS;
	op->bufsize = ioq_bufsize;

	if (doit(iff_name, op) < 0) {
		free(op);
		err(1, "up_ioqs");
	}

	printf("ioq_rx_enable   : 0x%08x\n", op->ioq_rx_enable);
	printf("ioq_tx_enable   : 0x%08x\n", op->ioq_tx_enable);
	printf("ioq_rx_status   : 0x%08x\n", op->ioq_rx_status);
	printf("ioq_tx_status   : 0x%08x\n", op->ioq_tx_status);
	
	entries = op->bufsize / sizeof(op->ioqs[0]);
	for (i = 0; i < entries; i++) {
		printf("\nioq[%d].cp       : 0x%08x\n", i,
		       op->ioqs[i].ioq_cp);
		printf("ioq[%d].pp       : 0x%08x\n", i,
		       op->ioqs[i].ioq_pp);
		printf("ioq[%d].alen     : 0x%08x\n", i,
		       op->ioqs[i].ioq_alen);
		printf("ioq[%d].stats    : 0x%08x\n", i,
		       op->ioqs[i].ioq_stats);
		printf("  sop %u\n", op->ioqs[i].ioq_stats >> 16);
		printf("  eop %u\n", op->ioqs[i].ioq_stats  & 0xFFFF);
	}

	free(op);
	return 0;
}

#define WDUDP_STATS 0
#define WDTOE_STATS 1

static void
dump_wd_stats(int s, int pid, int prot)
{
	struct sockaddr_un sun;
	char buf[512];
	int cc;
	socklen_t fromlen = sizeof sun;

	sun.sun_family = AF_UNIX;
	memset(sun.sun_path, 0, sizeof sun.sun_path);

	if (prot == WDUDP_STATS)
		sprintf(sun.sun_path, "/var/run/chelsio/WD/libcxgb4_sock-%d", pid);
	else if (prot == WDTOE_STATS)
		sprintf(sun.sun_path, "/var/run/chelsio/WD/libwdtoe-%d", pid);
	else {
		fprintf(stderr, "Could not determine which stats to request for process %d.\n", pid);
		return;
	}

	strncpy(buf, "stats", sizeof ("stats"));
	cc = sendto(s, (void *)buf, strlen(buf) + 1, 0, (const struct sockaddr *)&sun, sizeof sun);
	if (cc == -1) {
		perror("sendto");
		fprintf(stderr, "Process %d appears to not be using the WD libraries.  Unlinking %s\n",
			pid, sun.sun_path);
		unlink(sun.sun_path);
		return;
	}

	while ((cc = recvfrom(s, buf, sizeof buf, 0, (struct sockaddr *)&sun, &fromlen)) > 0) {
		if (!strncmp(buf, "@@DONE@@", strlen("@@DONE@@")))
			break;
		printf("pid %d %s", pid, buf);
	}
}

static int
wdtoe_stats(int pid)
{
	int s;
	struct dirent *dent;
	DIR *dir; 
	int ret = -1;
	struct sockaddr_un mysun;

	s = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (s == -1) {
		perror("socket");
		goto out;
	}

	mysun.sun_family = AF_UNIX;
	memset(mysun.sun_path, 0, sizeof mysun.sun_path);
	sprintf(mysun.sun_path, "/var/run/chelsio/WD/wdtest-%d", getpid());
	unlink(mysun.sun_path);
	if (bind(s, (const struct sockaddr *)&mysun, sizeof mysun) == -1) {
		perror("bind");
		goto out1;
	}
	if (pid) {
		dump_wd_stats(s, pid, WDTOE_STATS);
		goto out1;
	}
	dir = opendir("/var/run/chelsio/WD");
	if (!dir) {
		printf("No WD-TOE procs found in /var/run/chelsio/WD\n");
		goto out1;
	}
	while ((dent = readdir(dir))) {
		int pid;

		if (dent->d_name[0] == '.') {
			continue;
		}
		if (dent->d_reclen < strlen("libwdtoe-") ||
		    strncmp(dent->d_name, "libwdtoe-", strlen("libwdtoe-"))) {
			continue;
		}
		pid = atoi(dent->d_name + strlen("libwdtoe-"));
		if (pid)
			dump_wd_stats(s, pid, WDTOE_STATS);
	}
	ret = 0;
 out1:
 	close(s);
	unlink(mysun.sun_path);
 out:
	return ret;
}

static int
wdudp_stats(int pid)
{
	int s;
	struct dirent *dent;
	DIR *dir; 
	int ret = -1;
	struct sockaddr_un mysun;

	s = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (s == -1) {
		perror("socket");
		goto out;
	}

	mysun.sun_family = AF_UNIX;
	memset(mysun.sun_path, 0, sizeof mysun.sun_path);
	sprintf(mysun.sun_path, "/var/run/chelsio/WD/wdtest-%d", getpid());
	unlink(mysun.sun_path);
	if (bind(s, (const struct sockaddr *)&mysun, sizeof mysun) == -1) {
		perror("bind");
		goto out1;
	}
	if (pid) {
		dump_wd_stats(s, pid, WDUDP_STATS);
		goto out1;
	}
	dir = opendir("/var/run/chelsio/WD");
	if (!dir) {
		printf("No WDUDP procs found in /var/run/chelsio/WD\n");
		goto out1;
	}
	while ((dent = readdir(dir))) {
		int pid;

		if (dent->d_name[0] == '.') {
			continue;
		}
		if (dent->d_reclen < strlen("libcxgb4_sock-") ||
		    strncmp(dent->d_name, "libcxgb4_sock-", strlen("libcxgb4_sock-"))) {
			continue;
		}
		pid = atoi(dent->d_name + strlen("libcxgb4_sock-"));
		if (pid)
			dump_wd_stats(s, pid, WDUDP_STATS);
	}
	ret = 0;
 out1:
 	close(s);
	unlink(mysun.sun_path);
 out:
	return ret;
}

static int
wdudp_cmd(int argc, char *argv[], int start_arg, const char *iff_name)
{
	if (argc < 4) usage(stderr);

	if (!strcmp(argv[start_arg], "stats"))
		wdudp_stats(argc == 5 ? atoi(argv[4]) : 0);
	else
		errx(1, "Unknown wdudp command %s\n", argv[start_arg]);

	return 0;
}

static int
wdtoe_cmd(int argc, char *argv[], int start_arg, const char *iff_name)
{
	if (argc < 4) usage(stderr);

	if (!strcmp(argv[start_arg], "stats"))
		wdtoe_stats(argc == 5 ? atoi(argv[4]) : 0);
	else
		errx(1, "Unknown wdtoe command %s\n", argv[start_arg]);

	return 0;
}

static int
run_cmd(int argc, char *argv[], const char *iff_name,
	struct ethtool_drvinfo *drvinfo)
{
	int r = -1;

	if (!is_chelsio_iface(iff_name)) {
#ifdef STORAGE
#ifdef __CSIO_FOISCSI_ENABLED__		
		if (!strcmp(iff_name, "stor") &&
				!strcmp(argv[2], "--foiscsi")) {
			r = run_foiscsi_stor(argc, argv);
			goto done;
		}
#endif
#endif
			errx(1, "%s is not a Chelsio interface", iff_name);
	}

	if (!strcmp(argv[2], "reg"))
		r = register_io(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "mdio"))
		r = mdio_io(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "i2c"))
		r = i2c_io(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "loadcfg"))
		r = load_cfg(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "loadphy"))
		r = load_phy_fw(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "up"))
		r = device_up(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "mtus"))
		r = mtu_tab_op(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "pm"))
		r = conf_pm(argc, argv, 3, iff_name);
#ifdef WRC
	else if (!strcmp(argv[2], "wrc"))
		r = get_wrc(argc, argv, 3, iff_name);
#endif
	else if (!strcmp(argv[2], "regdump"))
		r = dump_regs(argc, argv, 3, iff_name, drvinfo);
	else if (!strcmp(argv[2], "tcamdump"))
		r = dump_tcam(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "memdump"))
		r = dump_mem(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "meminfo"))
		r = meminfo(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "context"))
		r = get_sge_context(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "desc"))
		r = get_sge_desc(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "qdesc"))
		r = get_sge_desc2(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "eeprom"))
		r = wr_eeprom(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "loadfw"))
		r = load_fw(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "loadboot"))
		r = load_boot(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "loadboot-cfg"))
		r = load_boot_cfg(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "policy"))
		r = load_ofld_policy(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "proto"))
		r = proto_sram_op(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "qset"))
		r = qset_config(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "qintr"))
		r = qintr_config(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "qsets"))
		r = qset_num_config(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "qtype-num"))
		r = qtype_config(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "trace"))
		r = trace_config(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "pktsched"))
		r = pktsched(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "sched-class"))
		r = sched_class(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "sched-queue"))
		r = sched_queue(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "sched-pfvf"))
		r = sched_pfvf(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "napi"))
		r = setup_napi(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "lro"))
		r = setup_lro(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "tcb"))
		r = get_tcb(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "filter"))
		r = filter_config(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "clearstats"))
		r = clear_stats(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "la"))
		r = get_up_la(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "ioqs"))
		r = get_up_ioqs(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "wdudp"))
		r = wdudp_cmd(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "wdtoe"))
		r = wdtoe_cmd(argc, argv, 3, iff_name);
#ifdef CHELSIO_T4_DIAGS
	else if (!strcmp(argv[2], "clearflash"))
		r = clear_flash(argc, argv, 3, iff_name);
#endif
	else if (!strcmp(argv[2], "driver-file"))
		r = driver_file(argc, argv, 3, iff_name);
#if 0 /* Unsupported */
	else if (!strcmp(argv[2], "tpi"))
		r = tpi_io(argc, argv, 3, iff_name);
	else if (!strcmp(argv[2], "tcam"))
		r = conf_tcam(argc, argv, 3, iff_name);
#endif
#ifdef STORAGE
done:
#endif

	if (r == -1)
		usage(stderr);
	return 0;
}

static int
run_cmd_loop(int argc, char *argv[], const char *iff_name,
	     struct ethtool_drvinfo *drvinfo)
{
	int n, i;
	char buf[64];
	char *args[8], *s;

	args[0] = argv[0];
	args[1] = argv[1];

	/*
	 * Fairly simplistic loop.  Displays a "> " prompt and processes any
	 * input as a cxgbtool command.  You're supposed to enter only the part
	 * after "cxgbtool cxgbX".  Use "quit" or "exit" to exit.  Any error in
	 * the command will also terminate cxgbtool.
	 */
	do {
		fprintf(stdout, "> ");
		fflush(stdout);
		n = read(STDIN_FILENO, buf, sizeof(buf));
		if (n > sizeof(buf) - 1) {
			fprintf(stdout, "too much input.\n");
			return (0);
		} else if (n <= 0)
			return (0);

		if (buf[--n] != '\n')
			continue;
		else
			buf[n] = 0;

		s = &buf[0];
		for (i = 2; i < sizeof(args)/sizeof(args[0]) - 1; i++) {
			while (s && (*s == ' ' || *s == '\t'))
				s++;
			if ((args[i] = strsep(&s, " \t")) == NULL)
				break;
		}
		args[sizeof(args)/sizeof(args[0]) - 1] = 0;

		if (!strcmp(args[2], "quit") || !strcmp(args[2], "exit"))
			return (0);

		(void) run_cmd(i, args, iff_name, drvinfo);
	} while (1);

	/* Can't really get here */
	return (0);
}

int
main(int argc, char *argv[])
{
	int r = -1;
	const char *iff_name;
	struct ethtool_drvinfo drvinfo = {0};
	progname = argv[0];

	if (argc == 2) {
		if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))
			usage(stdout);
		if (!strcmp(argv[1], "-v") || !strcmp(argv[1], "--version")) {
			printf("%s version %s\n", PROGNAME, VERSION);
			printf("%s\n", COPYRIGHT);
			exit(0);
		}
	}

	if (argc < 3) usage(stderr);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		err(1, "Cannot get control socket");

	iff_name = argv[1];

	get_drv_info(iff_name, &drvinfo);

	if (argc == 3 && !strcmp(argv[2], "stdio"))
		r = run_cmd_loop(argc, argv, iff_name, &drvinfo);
	else
		r = run_cmd(argc, argv, iff_name, &drvinfo);

	return (r);
}
