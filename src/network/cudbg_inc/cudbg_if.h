/*
 * Chelsio Unified Debug Interface header file.
 * Version 1.1
 */
#ifndef _CUDBG_IF_H_
#define _CUDBG_IF_H_
/*
 * Use inlined functions for supported systems.
 */
#if defined(__GNUC__) || defined(__DMC__) || defined(__POCC__) || \
	defined(__WATCOMC__) || defined(__SUNPRO_C)

#elif defined(__BORLANDC__) || defined(_MSC_VER) || defined(__LCC__)
#define inline __inline
#else
#define inline
#endif

#ifdef __GNUC__
#define ATTRIBUTE_UNUSED __attribute__ ((unused))
#else
#define ATTRIBUTE_UNUSED
#endif

#define OUT
#define IN
#define INOUT

/* Error codes */

#define CUDBG_STATUS_SUCCESS		     0
#define CUDBG_STATUS_NOSPACE		    -2
#define CUDBG_STATUS_FLASH_WRITE_FAIL	    -3
#define CUDBG_STATUS_FLASH_READ_FAIL	    -4
#define CUDBG_STATUS_UNDEFINED_OUT_BUF	    -5
#define CUDBG_STATUS_UNDEFINED_CBFN	    -6
#define CUDBG_STATUS_UNDEFINED_PRINTF_CBFN  -7
#define CUDBG_STATUS_ADAP_INVALID	    -8
#define CUDBG_STATUS_FLASH_EMPTY	    -9
#define CUDBG_STATUS_NO_ADAPTER		    -10
#define CUDBG_STATUS_NO_SIGNATURE	    -11
#define CUDBG_STATUS_MULTIPLE_REG	    -12
#define CUDBG_STATUS_UNREGISTERED	    -13
#define CUDBG_STATUS_UNDEFINED_ENTITY	    -14
#define CUDBG_STATUS_REG_FAIlED		    -15
#define CUDBG_STATUS_DEVLOG_FAILED	    -16
#define CUDBG_STATUS_SMALL_BUFF		    -17
#define CUDBG_STATUS_CHKSUM_MISSMATCH	    -18
#define CUDBG_STATUS_NO_SCRATCH_MEM	    -19
#define CUDBG_STATUS_OUTBUFF_OVERFLOW	    -20
#define CUDBG_STATUS_INVALID_BUFF	    -21  /* Invalid magic */
#define CUDBG_STATUS_FILE_OPEN_FAIL	    -22
#define CUDBG_STATUS_DEVLOG_INT_FAIL	    -23
#define CUDBG_STATUS_ENTITY_NOT_FOUND	    -24
#define CUDBG_STATUS_DECOMPRESS_FAIL	    -25
#define CUDBG_STATUS_BUFFER_SHORT	    -26
#define CUDBG_METADATA_VERSION_MISMATCH     -27
#define CUDBG_STATUS_NOT_IMPLEMENTED	    -28
#define CUDBG_SYSTEM_ERROR		    -29
#define CUDBG_STATUS_MMAP_FAILED	    -30
#define CUDBG_STATUS_FILE_WRITE_FAILED	    -31
#define CUDBG_STATUS_CCLK_NOT_DEFINED	    -32
#define CUDBG_STATUS_FLASH_FULL            -33
#define CUDBG_STATUS_SECTOR_EMPTY          -34
#define CUDBG_STATUS_ENTITY_NOT_REQUESTED  -35
#define CUDBG_STATUS_NOT_SUPPORTED         -36

#define CUDBG_MAJOR_VERSION		    1
#define CUDBG_MINOR_VERSION		    9
#define CUDBG_BUILD_VERSION		    0

#define CUDBG_MAX_PARAMS		    16

#define CUDBG_FILE_NAME_LEN 256
#define CUDBG_DIR_NAME_LEN  256
#define CUDBG_MAX_BITMAP_LEN 16

static char ATTRIBUTE_UNUSED * err_msg[] = {
	"Success",
	"Unknown",
	"No space",
	"Flash write fail",
	"Flash read fail",
	"Undefined out buf",
	"Callback function undefined",
	"Print callback function undefined",
	"ADAP invalid",
	"Flash empty",
	"No adapter",
	"No signature",
	"Multiple registration",
	"Unregistered",
	"Undefined entity",
	"Reg failed",
	"Devlog failed",
	"Small buff",
	"Checksum mismatch",
	"No scratch memory",
	"Outbuff overflow",
	"Invalid buffer",
	"File open fail",
	"Devlog int fail",
	"Entity not found",
	"Decompress fail",
	"Buffer short",
	"Version mismatch",
	"Not implemented",
	"System error",
	"Mmap failed",
	"File write failed",
	"cclk not defined",
	"Flash full",
	"Sector empty",
	"Entity not requested",
	"Not supported"
};

enum CUDBG_DBG_ENTITY_TYPE {
	CUDBG_ALL	   = 0,
	CUDBG_REG_DUMP	   = 1,
	CUDBG_DEV_LOG	   = 2,
	CUDBG_CIM_LA	   = 3,
	CUDBG_CIM_MA_LA    = 4,
	CUDBG_CIM_QCFG	   = 5,
	CUDBG_CIM_IBQ_TP0  = 6,
	CUDBG_CIM_IBQ_TP1  = 7,
	CUDBG_CIM_IBQ_ULP  = 8,
	CUDBG_CIM_IBQ_SGE0 = 9,
	CUDBG_CIM_IBQ_SGE1 = 10,
	CUDBG_CIM_IBQ_NCSI = 11,
	CUDBG_CIM_OBQ_ULP0 = 12,
	CUDBG_CIM_OBQ_ULP1 = 13,
	CUDBG_CIM_OBQ_ULP2 = 14,
	CUDBG_CIM_OBQ_ULP3 = 15,
	CUDBG_CIM_OBQ_SGE  = 16,
	CUDBG_CIM_OBQ_NCSI = 17,
	CUDBG_EDC0	   = 18,
	CUDBG_EDC1	   = 19,
	CUDBG_MC0	   = 20,
	CUDBG_MC1	   = 21,
	CUDBG_RSS	   = 22,
	CUDBG_RSS_PF_CONF  = 23,
	CUDBG_RSS_KEY	   = 24,
	CUDBG_RSS_VF_CONF  = 25,
	CUDBG_RSS_CONF	   = 26,
	CUDBG_PATH_MTU	   = 27,
	CUDBG_SW_STATE	   = 28,
	CUDBG_WTP	   = 29,
	CUDBG_PM_STATS	   = 30,
	CUDBG_HW_SCHED	   = 31,
	CUDBG_TCP_STATS    = 32,
	CUDBG_TP_ERR_STATS = 33,
	CUDBG_FCOE_STATS   = 34,
	CUDBG_RDMA_STATS   = 35,
	CUDBG_TP_INDIRECT  = 36,
	CUDBG_SGE_INDIRECT = 37,
	CUDBG_CPL_STATS    = 38,
	CUDBG_DDP_STATS    = 39,
	CUDBG_WC_STATS	   = 40,
	CUDBG_ULPRX_LA	   = 41,
	CUDBG_LB_STATS	   = 42,
	CUDBG_TP_LA	   = 43,
	CUDBG_MEMINFO	   = 44,
	CUDBG_CIM_PIF_LA   = 45,
	CUDBG_CLK	   = 46,
	CUDBG_CIM_OBQ_RXQ0 = 47,
	CUDBG_CIM_OBQ_RXQ1 = 48,
	CUDBG_MAC_STATS    = 49,
	CUDBG_PCIE_INDIRECT = 50,
	CUDBG_PM_INDIRECT  = 51,
	CUDBG_FULL	   = 52,
	CUDBG_TX_RATE	   = 53,
	CUDBG_TID_INFO	   = 54,
	CUDBG_PCIE_CONFIG  = 55,
	CUDBG_DUMP_CONTEXT = 56,
	CUDBG_MPS_TCAM	   = 57,
	CUDBG_VPD_DATA	   = 58,
	CUDBG_LE_TCAM	   = 59,
	CUDBG_CCTRL	   = 60,
	CUDBG_MA_INDIRECT  = 61,
	CUDBG_ULPTX_LA	   = 62,
	CUDBG_EXT_ENTITY   = 63,
	CUDBG_UP_CIM_INDIRECT = 64,
	CUDBG_PBT_TABLE    = 65,
	CUDBG_MBOX_LOG     = 66,
	CUDBG_MAX_ENTITY   = 67,
};

#define ENTITY_FLAG_NULL 0
#define ENTITY_FLAG_REGISTER 1
#define ENTITY_FLAG_BINARY 2
#define ENTITY_FLAG_FW_NO_ATTACH    3

struct el {char *name; int bit; u32 flag; };
static struct el ATTRIBUTE_UNUSED entity_list[] = {
	{"all", CUDBG_ALL, ENTITY_FLAG_NULL},
	{"regdump", CUDBG_REG_DUMP, 1 << ENTITY_FLAG_REGISTER},
	/* {"reg", CUDBG_REG_DUMP},*/
	{"devlog", CUDBG_DEV_LOG, ENTITY_FLAG_NULL |
			(1 << ENTITY_FLAG_FW_NO_ATTACH)},
	{"cimla", CUDBG_CIM_LA, ENTITY_FLAG_NULL},
	{"cimmala", CUDBG_CIM_MA_LA, ENTITY_FLAG_NULL},
	{"cimqcfg", CUDBG_CIM_QCFG, ENTITY_FLAG_NULL},
	{"ibqtp0", CUDBG_CIM_IBQ_TP0, ENTITY_FLAG_NULL},
	{"ibqtp1", CUDBG_CIM_IBQ_TP1, ENTITY_FLAG_NULL},
	{"ibqulp", CUDBG_CIM_IBQ_ULP, ENTITY_FLAG_NULL},
	{"ibqsge0", CUDBG_CIM_IBQ_SGE0, ENTITY_FLAG_NULL},
	{"ibqsge1", CUDBG_CIM_IBQ_SGE1, ENTITY_FLAG_NULL},
	{"obqncsi", CUDBG_CIM_OBQ_NCSI, ENTITY_FLAG_NULL},
	{"obqulp0", CUDBG_CIM_OBQ_ULP0, ENTITY_FLAG_NULL},
	/* {"cimobqulp1", CUDBG_CIM_OBQ_ULP1},*/
	{"obqulp1", CUDBG_CIM_OBQ_ULP1, ENTITY_FLAG_NULL},
	{"obqulp2", CUDBG_CIM_OBQ_ULP2, ENTITY_FLAG_NULL},
	{"obqulp3", CUDBG_CIM_OBQ_ULP3, ENTITY_FLAG_NULL},
	{"obqsge", CUDBG_CIM_OBQ_SGE, ENTITY_FLAG_NULL},
	{"ibqncsi", CUDBG_CIM_IBQ_NCSI, ENTITY_FLAG_NULL},
	{"edc0", CUDBG_EDC0, (1 << ENTITY_FLAG_BINARY) |
			(1 << ENTITY_FLAG_FW_NO_ATTACH)},
	{"edc1", CUDBG_EDC1, (1 << ENTITY_FLAG_BINARY) |
			(1 << ENTITY_FLAG_FW_NO_ATTACH)},
	{"mc0", CUDBG_MC0, (1 << ENTITY_FLAG_BINARY) |
			(1 << ENTITY_FLAG_FW_NO_ATTACH)},
	{"mc1", CUDBG_MC1, (1 << ENTITY_FLAG_BINARY) |
			(1 << ENTITY_FLAG_FW_NO_ATTACH)},
	{"rss", CUDBG_RSS, ENTITY_FLAG_NULL},
	{"rss_pf_config", CUDBG_RSS_PF_CONF, ENTITY_FLAG_NULL},
	{"rss_key", CUDBG_RSS_KEY, ENTITY_FLAG_NULL},
	{"rss_vf_config", CUDBG_RSS_VF_CONF, ENTITY_FLAG_NULL},
	{"rss_config", CUDBG_RSS_CONF, ENTITY_FLAG_NULL},
	{"pathmtu", CUDBG_PATH_MTU, ENTITY_FLAG_NULL},
	{"swstate", CUDBG_SW_STATE, ENTITY_FLAG_NULL},
	{"wtp", CUDBG_WTP, ENTITY_FLAG_NULL},
	{"pmstats", CUDBG_PM_STATS, ENTITY_FLAG_NULL},
	{"hwsched", CUDBG_HW_SCHED, ENTITY_FLAG_NULL},
	{"tcpstats", CUDBG_TCP_STATS, ENTITY_FLAG_NULL},
	{"tperrstats", CUDBG_TP_ERR_STATS, ENTITY_FLAG_NULL},
	{"fcoestats", CUDBG_FCOE_STATS, ENTITY_FLAG_NULL},
	{"rdmastats", CUDBG_RDMA_STATS, ENTITY_FLAG_NULL},
	{"tpindirect", CUDBG_TP_INDIRECT, 1 << ENTITY_FLAG_REGISTER},
	{"sgeindirect", CUDBG_SGE_INDIRECT, 1 << ENTITY_FLAG_REGISTER},
	{"cplstats", CUDBG_CPL_STATS, ENTITY_FLAG_NULL},
	{"ddpstats", CUDBG_DDP_STATS, ENTITY_FLAG_NULL},
	{"wcstats", CUDBG_WC_STATS, ENTITY_FLAG_NULL},
	{"ulprxla", CUDBG_ULPRX_LA, ENTITY_FLAG_NULL},
	{"lbstats", CUDBG_LB_STATS, ENTITY_FLAG_NULL},
	{"tpla", CUDBG_TP_LA, ENTITY_FLAG_NULL},
	{"meminfo", CUDBG_MEMINFO, ENTITY_FLAG_NULL},
	{"cimpifla", CUDBG_CIM_PIF_LA, ENTITY_FLAG_NULL},
	{"clk", CUDBG_CLK, ENTITY_FLAG_NULL},
	{"obq_sge_rx_q0", CUDBG_CIM_OBQ_RXQ0, ENTITY_FLAG_NULL},
	{"obq_sge_rx_q1", CUDBG_CIM_OBQ_RXQ1, ENTITY_FLAG_NULL},
	{"macstats", CUDBG_MAC_STATS, ENTITY_FLAG_NULL |
				(1 << ENTITY_FLAG_FW_NO_ATTACH)},
	{"pcieindirect", CUDBG_PCIE_INDIRECT, 1 << ENTITY_FLAG_REGISTER},
	{"pmindirect", CUDBG_PM_INDIRECT, 1 << ENTITY_FLAG_REGISTER},
	{"full", CUDBG_FULL, ENTITY_FLAG_NULL},
	{"txrate", CUDBG_TX_RATE, ENTITY_FLAG_NULL},
	{"tidinfo", CUDBG_TID_INFO, ENTITY_FLAG_NULL |
			(1 << ENTITY_FLAG_FW_NO_ATTACH)},
	{"pcieconfig", CUDBG_PCIE_CONFIG, ENTITY_FLAG_NULL},
	{"dumpcontext", CUDBG_DUMP_CONTEXT, ENTITY_FLAG_NULL},
	{"mpstcam", CUDBG_MPS_TCAM, ENTITY_FLAG_NULL |
			(1 << ENTITY_FLAG_FW_NO_ATTACH)},
	{"vpddata", CUDBG_VPD_DATA, ENTITY_FLAG_NULL},
	{"letcam", CUDBG_LE_TCAM, ENTITY_FLAG_NULL},
	{"cctrl", CUDBG_CCTRL, ENTITY_FLAG_NULL},
	{"maindirect", CUDBG_MA_INDIRECT, 1 << ENTITY_FLAG_REGISTER},
	{"ulptxla", CUDBG_ULPTX_LA, ENTITY_FLAG_NULL},
	{"extentity", CUDBG_EXT_ENTITY, ENTITY_FLAG_NULL},
	{"upcimindirect", CUDBG_UP_CIM_INDIRECT, 1 << ENTITY_FLAG_REGISTER},
	{"pbttables", CUDBG_PBT_TABLE, ENTITY_FLAG_NULL},
	{"mboxlog", CUDBG_MBOX_LOG, ENTITY_FLAG_NULL},
};

typedef int (*cudbg_print_cb) (char *str, ...);

struct cudbg_init_hdr {
	u8   major_ver;
	u8   minor_ver;
	u8   build_ver;
	u8   res;
	u16  init_struct_size;
};

struct cudbg_flash_hdr {
	u32 signature;
	u8 major_ver;
	u8 minor_ver;
	u8 build_ver;
	u8 res;
	u64 timestamp;
	u64 time_res;
	u32 hdr_len;
	u32 data_len;
	u32 hdr_flags;
	u32 sec_seq_no;
	u32 reserved[22];
};

struct cudbg_param {
	u16			 param_type;
	u16			 reserved;
	union {
		struct {
			u32 memtype;	/* which memory (EDC0, EDC1, MC) */
			u32 start;	/* start of log in firmware memory */
			u32 size;	/* size of log */
		} devlog_param;
		struct {
			struct mbox_cmd_log *log;
			u16 mbox_cmds;
		} mboxlog_param;
		u64 time;
	} u;
};

/*
 * * What is OFFLINE_VIEW_ONLY mode?
 *
 * cudbg frame work will be used only to interpret previously collected
 * data store in a file (i.e NOT hw flash)
 */

struct cudbg_init {
	struct cudbg_init_hdr	 header;
	cudbg_print_cb		 print;		 /* Platform dependent print
						    function */
	u32			 verbose:1;	 /* Turn on verbose print */
	u32			 use_flash:1;	 /* Use flash to collect or view
						    debug */
	u32			 full_mode:1;	 /* If set, cudbg will pull in
						    common code */
	u32			 no_compress:1;  /* Dont compress will storing
						    the collected debug */
	u32			 info:1;	 /* Show just the info, Dont
						    interpret */
	u32			 reserved:27;
	u8			 dbg_bitmap[CUDBG_MAX_BITMAP_LEN];
						/* Bit map to select the dbg
						    data type to be collect
						    or viewed */
	void			 *sw_state_buf;		/* */
	u32			 sw_state_buflen;	  /* */

	/* Optional for OFFLINE_VIEW_ONLY mode. Set to NULL for
	 * OFFLINE_VIEW_ONLY mode */
	struct adapter		 *adap;		 /* Pointer to adapter structure
						    with filled fields */
	u16		   dbg_params_cnt;
	u16		   dbg_reserved;
	struct cudbg_param dbg_params[CUDBG_MAX_PARAMS];
};

enum {
	CUDBG_DEVLOG_PARAM = 1,
	CUDBG_TIMESTAMP_PARAM = 2,
	CUDBG_FW_ATTACH_PARAM = 3,
	CUDBG_MBOX_LOG_PARAM = 4
};

/********************************* Helper functions *************************/
static inline void set_dbg_bitmap(u8 *bitmap, enum CUDBG_DBG_ENTITY_TYPE type)
{
	int index = type / 8;
	int bit = type % 8;

	bitmap[index] |= (1 << bit);
}

static inline void reset_dbg_bitmap(u8 *bitmap, enum CUDBG_DBG_ENTITY_TYPE type)
{
	int index = type / 8;
	int bit = type % 8;

	bitmap[index] &= ~(1 << bit);
}

static inline void init_cudbg_hdr(struct cudbg_init_hdr *hdr)
{
	hdr->major_ver = CUDBG_MAJOR_VERSION;
	hdr->minor_ver = CUDBG_MINOR_VERSION;
	hdr->build_ver = CUDBG_BUILD_VERSION;
	hdr->init_struct_size = sizeof(struct cudbg_init);
}

/********************************* End of Helper functions
 * *************************/

/* API Prototypes */

/**
 *  cudbg_hello - To initialize cudbg framework. Needs to called
 *  first before calling anyother function
 *  ## Parameters ##
 *  @dbg_init : A pointer to cudbg_init structure.
 *  @handle : A pointer to void
 *  ##	Return ##
 *  If the function succeeds, returns 0 and a handle will be copied to @handle.
 *  -ve value represent error.
 */

int cudbg_hello(IN struct cudbg_init *dbg_init, OUT void **handle);

/**
 *  cudbg_params - To pass parameters to cudbg framework, if any.
 *  ## Parameters ##
 *  @handle : A pointer returned by cudbg_init.
 *  @dbg_params : A pointer to first cudbg_param in the array of
 *		  cudbg_param structures.
 *  @param_count : Number of cudbg_param structures in the array.
 *  ##	Return ##
 *  If the function succeeds, returns 0.
 *  -ve value represent error.
 */

int cudbg_params(IN void *handle, IN struct cudbg_param *dbg_params,
		IN u16 param_count);
int cudbg_loadfw(IN void *handle, IN uint8_t *buf, size_t len);
int cudbg_get_eeprom(void *handle, u8 *data, int addr, int len);
int cudbg_set_eeprom(void *handle, u8 *data, int offset, int len);

/**
 *  cudbg_collect - To collect and store debug information.
 *  ## Parameters ##
 *  @handle : A pointer returned by cudbg_init.
 *  @outbuf : pointer to output buffer, to store the collected information
 *	      or to use it as a scratch buffer in case HW flash is used to
 *	      store the debug information.
 *  @outbuf_size : Size of output buffer.
 *  ##	Return ##
 *  If the function succeeds, the return value will be size of debug information
 *  collected and stored.
 *  -ve value represent error.
 */
int cudbg_collect(IN void *handle, OUT void *outbuf, INOUT u32 *outbuf_size);

/**
 *  cudbg_view - To Display debug information passed in o_inbuf or read from
 *  flash .
 *  ## Parameters ##
 *  @adap : A pointer to Adapter information.
 *  @o_inbuf : Input data buffer that has collected debug information. Optional
 *  and
 *	       set to NULL in case of viewing info from the HW flash.
 *  @o_inbuf_size : Size of Input data buffer. 0 if @o_inbuf is set to NULL.
 *  @o_outbuf : pointer to output buffer. Optional and set to NULL if the output
 *		has to be printed to standard output.
 *  @o_outbuf_size : Set to 0, @o_outbuf is NULL.
 *  ##	Return ##
 *  If the function succeeds, the return value will be zero.
 *  -ve value represent error
 *  @outbuf_size set to required size of Output buffer if failed with error
 *  CUDBG_STATUS_NOSPACE.
 */

int cudbg_view(IN void *handle, IN void *o_inbuf, IN u32 o_inbuf_size, OUT void
		*o_outbuf, INOUT u32 *o_outbuf_size);

/**
 *  cudbg_bye - To exit cudbg framework.
 *  ## Parameters ##
 *  @handle : A pointer returned by cudbg_hello.
 */

int cudbg_bye(IN void *handle);

/**
 *  cudbg_read_flash_data - Read cudbg “flash” header from adapter flash.
 *  			    This will be used by the consumer mainly to
 *  			    know the size of the data in flash.
 *  ## Parameters ##
 *  @handle : A pointer returned by cudbg_hello.
 *  @data : A pointer to data/header buffer
 */

int cudbg_read_flash_details(void *handle, struct cudbg_flash_hdr *data);

/**
 *  cudbg_read_flash_data - Read cudbg dump contents stored in flash.
 *  ## Parameters ##
 *  @handle : A pointer returned by cudbg_hello.
 *  @data_buf : A pointer to data buffer.
 *  @data_buf_size : Data buffer size.
 */

int cudbg_read_flash_data(void *handle, void *data_buf, u32 data_buf_size);

/**
 *  cudbg_reset_bitmap - Set new debug entities overriding already
 *  			 registered debug entities during cudbg_hello.
 *  ## Parameters ##
 *  @handle : A pointer returned by cudbg_hello.
 *  @bitmap : A pointer to new debug entities list.
 *  @bitmap_count: New debug entities count.
 */

int cudbg_reset_bitmap(void *handle, unsigned long *bitmap, int bitmap_count);

#endif /* _CUDBG_IF_H_ */
