#ifndef __LICENSE_LIB_V1_2_C__
#define __LICENSE_LIB_V1_2_C__


/*
 * this file contains all the functions related to the customer info. file
 * and the license key file
 * the user-space only functions are enclosed with #ifndef __KLIB__
 */

/*
 * translate between total # hours and # year + # mon + # day
 * to simplify the logic, we don't take leap year and days in month
 * variations, (i.e.)
 * 	1 year = 365 days
 *	1 month = 31 days
 *	1 day = 24 hours
 */



#ifdef __cplusplus
extern "C" {
#endif

#include "iscsi_license_struct_v1.2.h"

#ifdef __LICENSE_DEBUG__
static void license_display_v1_2(struct license_v1_2 *license,
				unsigned char *vpd,
				int (*fp_print)(const char *fmt, ...))
{
	int i, max;
	char buffer[80];

	fp_print("version: v%u.%u\n",
		license->version[0], license->version[1]);	
	fp_print("customer: %s\n", license->customer);
	
	eth_info_display(license->version[0], license->version[1],
			 &license->eth[0], vpd, license->ethmax, fp_print);

	max = license_version_product_max_v1_2(license->version[0],
					  license->version[1]);
	for (i = 0; i < max; i++) {
		int j;
		int len;

		fp_print("%s:\n", product_string(i));

		len = sprintf(buffer, "\tflag: 0x%x ", license->flag[i]);
		for (j = 0; j < FLAG_COMMON_BITS; j++)
			if (license->flag[i] & (1 << j))
			{
				len += sprintf(buffer + len, "%s ",
						license_flag_bit_string(j));
				if (j==FLAG_EVAL_BIT)
				{
					len += sprintf(buffer + len,
						"\n\tre-eval request=%d ",
						license->eth[0].reeval);
				}
			}
		fp_print("%s\n", buffer);
		fp_print("\tvalid: %u year, %u month, %u day.\n",
			license->duration[i].year, license->duration[i].mon, 
			license->duration[i].day); 
	}
}
#endif

static int license_validate_fields_v1_2(struct license_v1_2 *license)
{
	int i, j, max;

	if (!license->ethmax)
		return -1;

	for (i = 0; i < license->ethmax; i++) {
		for (j = 0; j < ETH_MAC_ADDR_MAX_LEN; j++)
			if (license->eth[i].mac[j])
				break;
		/* mac is all zero */
		if (j == ETH_MAC_ADDR_MAX_LEN)
			return -1;
		if (!license->eth[i].vendor_id)
			return -1;
		if (!license->eth[i].device_id)
			return -1;
		if (!license->eth[i].linkspeed > 10000)
			return -1;
	}

	max = license_version_product_max_v1_2(license->version[0],
					  license->version[1]);
	for (i = 0; i < max; i++) {
		if (license->flag[i])
			break;
	}
	/* no product is selected */
	if (i == max)
		return -1;

	for (i = 0; i < max; i++) {
		if (!license->flag[i] &&
		    (license->duration[i].day || license->duration[i].mon ||
		     license->duration[i].year))
			return -1;
		if (license->flag[i] &&
		    key_duration_invalid(&license->duration[i]))
			return -1;
		/* eval duation invalid */
		if (license_flag_set_v1_2(license, i, FLAG_EVAL_BIT) &&
		    days_from_duration(&license->duration[i]) > EVAL_DAYS_MAX)
			return -1;
	}

	/* customer string will not be checked here */
	return 0;
}

static void buf_read_version_v1_2(char *buf, unsigned int *version,
			     unsigned long (*fp_strtoul)(const char *,
							char **, int))
{
	char temp[5];
	int i;
	
	for (i = 0; i < 2; i++) {
		buf_copy_bytes(temp, buf, 0, 4);
		version[i] = (unsigned int)fp_strtoul(temp, NULL, 10);
		buf+= sizeof(unsigned int);
	}
}

static int license_from_key_buffer_v1_2(char *buf, int buflen, char *err_buf,
				   struct license_v1_2 *license,
				   unsigned long (*fp_strtoul)(const char *,
							       char **, int))
{
	int i, max;
	int pos = 8;
	char temp[5];
	unsigned int datalen;
	unsigned int version[2];

	/* data length */
	buf_copy_bytes(temp, buf, buflen - 4, 4);
	datalen = (unsigned int)fp_strtoul(temp, NULL, 10);
	buf[datalen] = '\0';

        if(license->version[0] != L_VERSION_MINOR_V1_2 ||
                        license->version[1] != L_VERSION_MAJOR_V1_2){
                if(err_buf)
                        sprintf(err_buf, "version %d.%d NOT supported", license->version[0], license->version[1]);
        }
	/* version */
	buf_read_version_v1_2(buf, &version[0], fp_strtoul);
	if ((version[0] != license->version[0]) || 
	    (version[1] != license->version[1])) {
		if (err_buf)
			sprintf(err_buf, "version mismatch: %u.%u != %u.%u.\n",
				version[0], version[1],
				license->version[0], license->version[1]);
		return -1;
	}

	/* # of macs */
	pos = 8;
	buf_copy_bytes(temp, buf, pos, 2);
	license->ethmax = (unsigned int)fp_strtoul(temp, NULL, 10);
	pos += 2;

	if (license->ethmax > KEYFILE_ETH_MAX_V1_2) {
		if (err_buf)
			sprintf(err_buf, "too many eths: %u > %d.\n",
				license->ethmax, KEYFILE_ETH_MAX_V1_2);
		return -1;
	}

	pos += buf_read_ethinfo(license->version[0], license->version[1],
				buf + pos, &license->eth[0], license->ethmax,
				NULL, fp_strtoul);

	max = license_version_product_max_v1_2(license->version[0],
					  license->version[1]);
	for (i = 0; i < max; i++) {
		buf_copy_bytes(temp, buf, pos, 4);
		pos += 4;
		license->flag[i] = (unsigned int)fp_strtoul(temp, NULL, 16);
	}

	for (i = 0; i < max; i++) {
		buf_copy_bytes(temp, buf, pos, 2);
		pos += 2;
		license->duration[i].day =
				(unsigned int)fp_strtoul(temp, NULL, 10);

		buf_copy_bytes(temp, buf, pos, 2);
		pos += 2;
		license->duration[i].mon =
				(unsigned int)fp_strtoul(temp, NULL, 10);

		buf_copy_bytes(temp, buf, pos, 4);
		pos += 4;
		license->duration[i].year =
				(unsigned int)fp_strtoul(temp, NULL, 10);
        }

	i = datalen - pos;
	if (i == 0 || i > LICENSE_CUSTOMER_NAME_MAX_LEN_V1_2) {
		if (err_buf)
			sprintf(err_buf, "name invalid %d > %d (%d - %d).\n",
				i, LICENSE_CUSTOMER_NAME_MAX_LEN_V1_2, datalen, pos);
		return -1;
	}

	memcpy(license->customer, buf + pos, i);
	license->customer[i] = '\0';

	if (license_validate_fields_v1_2(license) < 0) {
		if (err_buf)
			sprintf(err_buf, "fields validation failed.\n");
		return -1;
	}

	return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* ifndef __LICENSE_LIB_C__ */
