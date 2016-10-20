/*
 */

#ifndef __IBFT_H__
#define __IBFT_H__

/* #include <sys/types.h> */
#include <stdint.h>

/*
 * 'iBFT' Signature for the iSCSI Boot Firmware Table
 */
#define IBFT_SIGNATURE	"iBFT"

/*
 * 3.2 iBFT Standard Structure Header
 */
typedef struct ibft_hdr {
	uint8_t id;
	uint8_t version;
	uint16_t length;
	uint8_t index;
	uint8_t flags;
} ibft_hdr;

/*
 * 3.3 IBF Table Header
 */
#define IBFT_REVISION		1
typedef struct ibft_table_hdr {
	uint8_t signature[4];
	uint32_t length;
	uint8_t revision;
	uint8_t checksum;
	uint8_t oemid[6];
	uint8_t oem_table_id[8];
	uint8_t reserved[24];
} __attribute__((__packed__)) ibft_table_hdr;

/*
 * 3.4 Control Structure
 */
#define IBFT_VERSION_CONTROL	1
#define IBFT_LENGTH_CONTROL	18
#define IBFT_STRING_CONTROL	"CONTROL"
typedef struct ibft_control {
	ibft_hdr hdr;
	uint16_t extensions;
	uint16_t initiator_offset;
	uint16_t nic0_offset;
	uint16_t target0_offset;
	uint16_t nic1_offset;
	uint16_t target1_offset;
} __attribute__((__packed__)) ibft_control;

/*
 * 3.4.1 Structure Type/ID
 */
enum ibft_struct_id {
	IBFT_ID_RESERVED,
	IBFT_ID_CONTROL,
	IBFT_ID_INITIATOR,
	IBFT_ID_NIC,
	IBFT_ID_TARGET,
	IBFT_ID_EXTENSIONS
};

#define IBFT_BLOCK_FLAG_VALID			0x1
#define IBFT_BLOCK_FLAG_FW_BOOT_SEL		0x2
/*
 * 3.5 Initiator Structure
 */
#define IBFT_VERSION_INITIATOR 	1
#define IBFT_LENGTH_INITIATOR	74
#define IBFT_STRING_INITIATOR	"INITIATOR"

#define IBFT_INITIATOR_INDEX	0
#define IBFT_INITIATOR_FLAG_BLOCK_VALID 	IBFT_BLOCK_FLAG_VALID
#define IBFT_INITIATOR_FLAG_FW_BOOT_SEL 	IBFT_BLOCK_FLAG_FW_BOOT_SEL
typedef struct ibft_initiator {
	ibft_hdr hdr;
	uint8_t isns_server[16];
	uint8_t slp_server[16];
	uint8_t primary_radius_server[16];
	uint8_t secondary_radius_server[16];
	uint16_t initiator_name_length;
	uint16_t initiator_name_offset;
} __attribute__((__packed__)) ibft_initiator;

/*
 * 3.6 NIC Structure
 */
#define IBFT_VERSION_NIC		1
#define IBFT_LENGTH_NIC			102
#define IBFT_STRING_NIC			"NIC"

#define IBFT_NIC_FLAG_BLOCK_VALID 	IBFT_BLOCK_FLAG_VALID
#define IBFT_NIC_FLAG_FW_BOOT_SEL 	IBFT_BLOCK_FLAG_FW_BOOT_SEL
#define IBFT_NIC_FLAG_LINK_GLOBAL 	0x4
typedef struct ibft_nic {
	ibft_hdr hdr;
	uint8_t ip_addr[16];
	uint8_t subnet_mask_prefix;
	uint8_t origin;
	uint8_t gateway[16];
	uint8_t primary_dns[16];
	uint8_t secondary_dns[16];
	uint8_t dhcp[16];
	uint16_t vlan;
	uint8_t mac[6];
	uint16_t pci_info;	/* bus:8, device:5, function:3 */
	uint16_t hostname_length;
	uint16_t hostname_offset;
} __attribute__((__packed__)) ibft_nic;

/*
 * 3.7 Target Structure
 */
#define IBFT_VERSION_TARGET	1
#define IBFT_LENGTH_TARGET	54
#define IBFT_STRING_TARGET	"target"

#define IBFT_TARGET_FLAG_BLOCK_VALID 	IBFT_BLOCK_FLAG_VALID
#define IBFT_TARGET_FLAG_FW_BOOT_SEL 	IBFT_BLOCK_FLAG_FW_BOOT_SEL
#define IBFT_TARGET_FLAG_RADIUS_CHAP 	0x4
#define IBFT_TARGET_FLAG_RADIUS_RCHAP 	0x8
typedef struct ibft_target {
	ibft_hdr hdr;
	uint8_t ip_addr[16];
	uint16_t port;
	uint8_t boot_lun[8];
	uint8_t chap_type;
#define IBFT_TARGET_NO_CHAP	0
#define IBFT_TARGET_CHAP	1
#define IBFT_TARGET_MUTUAL_CHAP	2
	uint8_t nic_association;
	uint16_t target_name_length;
	uint16_t target_name_offset;
	uint16_t chap_name_length;
	uint16_t chap_name_offset;
	uint16_t chap_secret_length;
	uint16_t chap_secret_offset;
	uint16_t rchap_name_length;
	uint16_t rchap_name_offset;
	uint16_t rchap_secret_length;
	uint16_t rchap_secret_offset;
} __attribute__((__packed__)) ibft_target;

#endif /* define __IBFT_H__ */
