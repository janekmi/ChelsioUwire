#ifndef __OFFLOAD_REQ__
#define __OFFLOAD_REQ__

#include <stdint.h>

/*
 * Header at the beginning of an offload policy file.
 */
struct ClassifierFileHeader {
    unsigned int vers;           // version of file format
    int output_everything;       // value of Classifier::_output_everything
    unsigned int nrules;         // value of noutputs()
    unsigned int prog_size;      // Classifier::_exprs.size()
    unsigned int opt_prog_size;  // IPFilter::_prog.size()
    unsigned int nsettings;      // IPFilter::_settings.size()
};

/*
 * Structure holding the values that will be matched against the criteria of
 * offload policy rules.
 */
struct OffloadReq {
    uint32_t sip[4];
    uint32_t dip[4];
    uint16_t sport;
    uint16_t dport;
    uint8_t  ipvers_opentype;  /* bits 0-3: IP version, bits 4-7: open type */
    uint8_t  tos;
    uint16_t vlan;
    uint32_t mark;
};

/*
 * <FIELD>_WORD is the starting 32-bit word within OffloadReq of <FIELD>
 * <FIELD>_OFFSET is the starting offset within <FIELD>_WORD of <FIELD>
 */
enum {
    SIP_WORD = 0,               SIP_OFFSET = 0,
    SIPV6_1_WORD = 1,           SIPV6_1_OFFSET = 0,
    SIPV6_2_WORD = 2,           SIPV6_2_OFFSET = 0,
    SIPV6_3_WORD = 3,           SIPV6_3_OFFSET = 0,
    DIP_WORD = 4,               DIP_OFFSET = 0,
    DIPV6_1_WORD = 5,           DIPV6_1_OFFSET = 0,
    DIPV6_2_WORD = 6,           DIPV6_2_OFFSET = 0,
    DIPV6_3_WORD = 7,           DIPV6_3_OFFSET = 0,
    SPORT_WORD = 8,             SPORT_OFFSET = 16,
    DPORT_WORD = 8,             DPORT_OFFSET = 0,
    OPENTYPE_WORD = 9,          OPENTYPE_OFFSET = 28,
    VERS_WORD = 9,              VERS_OFFSET = 24,
    TOS_WORD = 9,               TOS_OFFSET = 16,
    VLAN_WORD = 9,              VLAN_OFFSET = 0,
    MARK_WORD = 10,             MARK_OFFSET = 0,
};

/*
 * Structure holding the offload settings specified by an offload policy rule.
 */
struct OffloadSettings {
    uint8_t offload;
    int8_t  ddp;
    int8_t  rx_coalesce;
    int8_t  cong_algo;
    int32_t bind_q;
    int16_t sched_class;
    int8_t  tstamp;
    int8_t  sack;

#ifdef __cplusplus
    OffloadSettings()
	: offload(0), ddp(-1), rx_coalesce(-1), cong_algo(-1), bind_q(-1),
	  sched_class(-1), tstamp(-1), sack(-1)
    {}
#endif
};

/*
 * Special values for OffloadSettings.bind_q
 */
enum {
	QUEUE_RANDOM = -2,  /* bind to a random queue */
	QUEUE_CPU = -3,     /* bind to a queue detemined by CPU id */
};

static inline uint8_t mk_ipvers_opentype(uint8_t ipvers, uint8_t open_type)
{
	return (open_type << 4) | ipvers;
}
#endif
