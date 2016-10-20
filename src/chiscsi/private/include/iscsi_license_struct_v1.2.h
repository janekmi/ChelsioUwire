#ifndef __ISCSI_LICENSE_STRUCT_V1_2_H__
#define __ISCSI_LICENSE_STRUCT_V1_2_H__
#include <iscsi_license_struct.h>

/* current version 1.2 */
#define L_VERSION_MAJOR_V1_2		1
#define L_VERSION_MINOR_V1_2		2
#define VERSION_STR_LENGTH_V1_2		8 /* 4 digits each for ver major and minor */

/*
 * license key file format:
 *
 * fields:
 *	@version-major:		4 bytes
 *	@version-minor:		4 bytes
 *	@eths:			# of eth in the license, 2 bytes
 *	@eth information:
 *		- mac address,	6 * 2 bytes, hex
 *		- vendor id,	4 bytes, hex
 *		- device id,	4 bytes, hex
 *		- speed,	4 bytes, hex
 *		- VPD,		8 * 2 bytes, hex
 *	@flag[PRODUCT_MAX]:
 *		product flag,	4 bytes each, hex
 *	@license duration[PRODUCT_MAX]:
 *		- day,		2 bytes
 *		- month,	2 bytes
 *		- year,		4 bytes
 *	@customer name:		32 bytes, padded with NULL
 *
 * fields at the tail end:
 *	@length:	length of the actual license key, 4 bytes
 *
 * fields at the end of the file:
 *	@version:	
 *		- major,	4 bytes
 *		- minor,	4 bytes
 */

/* for license key file */
#define MATRIX_ORDER_V1_2		64
#define MATRIX_SIZE_V1_2		(MATRIX_ORDER_V1_2 * MATRIX_ORDER_V1_2)
#define MATRIX_ORDER_HALF_V1_2		(MATRIX_ORDER_V1_2 >> 1)
#define KEYFILE_LENGTH_V1_2		(MATRIX_SIZE_V1_2 + VERSION_STR_LENGTH_V1_2) 

#define KEYFILE_ETH_MAX_V1_2		1

#define LICENSE_CUSTOMER_NAME_MAX_LEN_V1_2	31

/*
 *			!!!WARNING!!!

 * if you are adding, removing, or changing the order of enum prodcuts
 * please
 *	1. increase the version number. And
 *	2. update license_version_product_max()
 */
enum products_v1_2  {
        PROD_ISCSI_TARGET_V1_2,
        PROD_ISCSI_INITIATOR_V1_2,
        PROD_UNIFIED_STORAGE_V1_2,
        PROD_UNIFIED_GATEWAY_V1_2,
        PROD_CHIMNEY_V1_2,
        PROD_UNIFIED_MANAGER_V1_2,
        PROD_USS_NFSORDMA_V1_2,
        PROD_USS_LUSTRE_V1_2,

        PRODUCT_MAX_V1_2,
        PROCUCT_MAX_VERSION_1_1_V1_2 = PROD_CHIMNEY_V1_2,
        PROCUCT_MAX_VERSION_1_2_V1_2 = PRODUCT_MAX_V1_2
};

static inline int license_version_product_max_v1_2(int ver_major, int ver_minor)
{
	if (ver_major == 1 && ver_minor == 1)
		return PROCUCT_MAX_VERSION_1_1_V1_2;
	if (ver_major == 1 && ver_minor == 2)
		return PROCUCT_MAX_VERSION_1_2_V1_2;
	return -1;
}

struct license_v1_2 {
	unsigned int		version[2];	/* version major, minor */
	char			customer[LICENSE_CUSTOMER_NAME_MAX_LEN_V1_2 + 1];
	unsigned int		flag[PRODUCT_MAX_V1_2];
	struct key_duration	duration[PRODUCT_MAX_V1_2];
        unsigned int		ethmax;
        struct eth_info 	eth[0];
};

static inline void license_set_flag_v1_2(struct license_v1_2 *license, int prod, int bit)
{
	license->flag[prod] |= 1 << bit;
}

static inline void license_clear_flag_v1_2(struct license_v1_2 *license, int prod, int bit)
{
	license->flag[prod] &= ~(1 << bit);
}
static inline unsigned int license_flag_set_v1_2(struct license_v1_2 *license, int prod,
					    int bit)
{
	return license->flag[prod] & (1 << bit);
}

static inline void license_set_duration_v1_2(struct license_v1_2 *license, int prod,
					int day, int mon, int yr)
{
	license->duration[prod].day = day;
	license->duration[prod].mon = mon;
	license->duration[prod].year = yr;
}
#endif
