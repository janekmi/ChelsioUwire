#ifndef __LICENSE_LIB_C__
#define __LICENSE_LIB_C__

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
static inline unsigned long days_from_duration(struct key_duration *duration)
{
	unsigned long days = duration->year * 365 +
				duration->mon * 31 +
				duration->day;
	return days;
}

static inline unsigned long hours_from_duration(struct key_duration *duration)
{
	unsigned long hours = duration->year  * 8760 +
				duration->mon * 744 +
				duration->day * 24;
	return hours;
}

typedef unsigned int uint32_t;	
unsigned int calc_crc(const void *buf, uint32_t size)
{
	int initial = 0xc1118510;
	static const uint32_t crctab[] = {
		0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
		0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
		0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
		0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c
	};
	uint32_t i, crc = initial;
	const unsigned char *data = (const unsigned char*) buf;

	for (i = 0; i < size; i++) {
		crc ^= *data++;
		crc = (crc >> 4) ^ crctab[crc & 0xf];
		crc = (crc >> 4) ^ crctab[crc & 0xf];
	}
	return crc;
}

/*
 * license structure
 */

static inline void license_init_uss_maint_default(struct license *license,
                                            int product)
{
        /* defaults to 1 year maintenance  license */
        license->product[product].flag = 1 << FLAG_USS_MAINT_BIT;
        license->product[product].duration.year = USS_MAINT_KEY_DURATION_YRS_DFLT;
        license->product[product].duration.mon = 0;
        license->product[product].duration.day = 0;
}

static inline void license_init_production_default(struct license *license,
					    int product)
{
	/* defaults to 31 day eval license */
	license->product[product].flag = 1 << FLAG_PROD_BIT;
	license->product[product].duration.year = PROD_KEY_DURATION_YRS_DFLT;
	license->product[product].duration.mon = 0;
	license->product[product].duration.day = 0;
}

static inline void license_init_eval_default(struct license *license, int prod)
{
	/* defaults to 31 day eval license */
	license->product[prod].flag = 1 << FLAG_EVAL_BIT;
	license->product[prod].duration.year = 0;
	license->product[prod].duration.mon = 0;
	license->product[prod].duration.day = EVAL_KEY_DURATION_DAY_DFLT;
}

#ifdef __KLIB__
#define strcasecmp os_strcasecmp
#define isprint(c) (c)
#endif
static inline int find_uss_subtype(char* name)
{
	int i;

	for(i=0; i < USS_SUBTYPE_MAX; i++){
		if(!strcasecmp(name, uss_subtype_str(i)))
			return i;
	}

	return -1;
}

static inline int is_chelsio_nic(unsigned short vendor_id)
{
	/* should we also check for mac? */
	return vendor_id == 0x1425;
}

static inline int is_chelsio_adapter(unsigned short device_id)
{
	/* not silicon, but chelsio-sold adapters */
	return !(device_id & 0x80);
}

static char *vendor_id_to_string(unsigned short vendor_id)
{
        switch (vendor_id) {
	case 0x1425:	return "CHELSIO";
	case 0x8086:	return "INTEL";
	case 0x14c1:	return "MYRICOM";
	case 0x14e4:	return "BROADCOM";
	case 0x17d5:	return "S2IO";
	case 0x10de:	return "NVIDIA";
	case 0x10ec:	return "REALTEK";
	case 0x1186:	return "DLINK";
	case 0x12ae:	return "ALTEON";
	case 0x1011:	return "DEC";
	}
        return NULL;
}

static void eth_info_display(int ver_major, int ver_minor,
			    struct eth_info *ethlist, unsigned char *vpd,
			    int ethmax, int (*fp_print)(const char *fmt, ...))
{
        int i,j;
	char buffer[80];

        for (i = 0; i < ethmax; i++) {
		char *vendor = vendor_id_to_string(ethlist[i].vendor_id);
		int len;

		if (ethmax > 1)
			fp_print("\nInterface %d:\n", i+1);
		else
			fp_print("\nInterface:\n", i+1);

		fp_print("MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
			ethlist[i].mac[0], ethlist[i].mac[1],
			ethlist[i].mac[2], ethlist[i].mac[3],
			ethlist[i].mac[4], ethlist[i].mac[5]);

		len = sprintf(buffer, "Vendor ID: 0x%x", ethlist[i].vendor_id);
		if (vendor)
			len += sprintf(buffer + len, " (%s)", vendor);
		fp_print("%s\n", buffer);
		fp_print("Device ID: 0x%x\n", ethlist[i].device_id);
		if (ethlist[i].linkspeed)
			fp_print("Link speed: %u Mbps\n", ethlist[i].linkspeed);
		else
			fp_print("Link speed: UNKNOWN\n");

		if (ver_major == 1 && ver_minor >= 2) {
			fp_print("Device Type: ");
			for (j=0;j<sizeof(ethlist[i].deviceType) && 
					isprint(ethlist[i].deviceType[j]);j++)
				fp_print("%c",ethlist[i].deviceType[j]);
			fp_print("\n");

			fp_print("Serial Num : ");
			for (j=0;j<sizeof(ethlist[i].deviceType) &&
					isprint(ethlist[i].serialNum[j]);j++)
				fp_print("%c",ethlist[i].serialNum[j]);
			fp_print("\n");
		}

		if (vpd) {
			if (is_chelsio_nic(ethlist[i].vendor_id))
				fp_print("VPD: %02X%02X %02X%02X %02X%02X %02X%02X\n",
					 vpd[0], vpd[1], vpd[2], vpd[3],
					 vpd[4], vpd[5], vpd[6], vpd[7]);
			vpd += 8;
		}
	}
}

void display_uss_subtypes(struct license *license, int (*fp_print)(const char *fmt, ...))
{
	int i;
	
	fp_print("\tsize: %u TB\n", license_get_size(license, PROD_UNIFIED_STORAGE)?:USS_SIZE_DFLT);
	fp_print("\tSub-types: ");
	for(i=0; i<USS_SUBTYPE_MAX; i++){
		if(license_get_uss_subtype(license, i))
			fp_print("%s ", uss_subtype_str(i));
	}
	fp_print("\n");
}

void display_usr_subtypes(struct license *license, int (*fp_print)(const char *fmt, ...))
{
	int i;

	fp_print("\tSub-types: ");
	for(i=0; i<USS_SUBTYPE_MAX; i++){
		if(license_is_usr_subtype(i) && license_get_uss_subtype(license, i))
			fp_print("%s ", uss_subtype_str(i));
	}
	fp_print("\n");
}

void display_amsterdam_subtypes(struct license *license, int (*fp_print)(const char *fmt, ...))
{
	int i;
	
	fp_print("\tsize: %u TB\n", license_get_size(license, PROD_UNIFIED_STORAGE)?:USS_SIZE_DFLT);
	fp_print("\tSub-types: ");
	for(i=0; i<USS_SUBTYPE_MAX; i++){
		if(license_get_amsterdam_subtype(license, i))
			fp_print("%s ", uss_subtype_str(i));
	}
	fp_print("\n");
}

void license_display(struct license *license, unsigned char *vpd,
			    int (*fp_print)(const char *fmt, ...))
{
	int i, max;
	char buffer[80];
	void (*product_spec_display[PRODUCT_MAX])(struct license*, 
			int (*fp_print)(const char *fmt, ...)) = {NULL};

	product_spec_display[PROD_UNIFIED_STORAGE] = display_uss_subtypes;
	product_spec_display[PROD_UNIFIED_GATEWAY] = display_usr_subtypes;
	product_spec_display[PROD_AMSTERDAM] = display_amsterdam_subtypes;

	fp_print("version: v%u.%u\n",
		license->version[0], license->version[1]);	
	fp_print("customer: %s\n", license->customer);
	
	eth_info_display(license->version[0], license->version[1],
			 &license->eth[0], vpd, license->ethmax, fp_print);

	max = license_print_product_max(license->version[0],
					  license->version[1]);
	for (i = 0; i < max; i++) {
		int j;
		int len;

		char *prod = product_string(i);
		if(!prod)
			continue;

		fp_print("%s:\n", prod);

		len = sprintf(buffer, "\tflag: 0x%x ", license->product[i].flag);
		for (j = 0; j < FLAG_COMMON_BITS; j++)
			if (license->product[i].flag & (1 << j))
			{
				len += sprintf(buffer + len, "%s ",
						license_flag_bit_string(j));
				if (j==FLAG_EVAL_BIT && license->ethmax)
				{
					len += sprintf(buffer + len, "\n\tre-eval request=%d ",
							license->eth[0].reeval);
				}
			}
		fp_print("%s\n", buffer);
		if(license->product[i].flag && product_spec_display[i])
			product_spec_display[i](license, fp_print);
		fp_print("\tvalid: %u year, %u month, %u day.\n",
			license->product[i].duration.year, license->product[i].duration.mon, 
			license->product[i].duration.day); 
	}
}

static int license_validate_fields(struct license *license)
{
	int i, j, max;

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

	max = license_print_product_max(license->version[0],
					  license->version[1]);
	for (i = 0; i < max; i++) {
		if (license->product[i].flag)
			break;
	}
	/* no product is selected */
	if (i == max)
		return -1;

	for (i = 0; i < max; i++) {
		if (!license->product[i].flag &&
		    (license->product[i].duration.day || license->product[i].duration.mon ||
		     license->product[i].duration.year))
			return -1;
		if (license->product[i].flag &&
		    key_duration_invalid(&license->product[i].duration))
			return -1;
		/* eval duation invalid */
		if (license_flag_set(license, i, FLAG_EVAL_BIT) &&
		    days_from_duration(&license->product[i].duration) > EVAL_DAYS_MAX)
			return -1;
	}

	/* customer string will not be checked here */
	return 0;
}

static inline void buf_copy_bytes(char *to, char *from, int pos, int count)
{
	memcpy(to, from + pos, count);
	to[count] = '\0';
}

int buf_check_crc(char* buf, int len, 
		unsigned long (*fp_strtoul)(const char *, char**, int))
{
	char temp[9];
	unsigned int crc;

	buf_copy_bytes(temp, buf, len, 8); /* last 8 bytes */
	crc = (unsigned int)fp_strtoul(temp, NULL, 16);
	if(crc != calc_crc(buf, len))
		return -1;
	buf[len] = '\0';

	return 0;
}

static void buf_read_version(char *buf, unsigned short *version,
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



#define MAX_REEVAL 8

void get_next_reeval(unsigned short* reeval)
{
	/*
	if (*reeval>MAX_REEVAL)
	{
		*reeval=MAX_REEVAL;
		return 0;
	}
	*/

	if (*reeval==MAX_REEVAL)
	{
//		printf("User has exceeded his maximum re-evaluation\n");
//		exit(0);
		return ;
	}

	(*reeval)++;

}

/*
 * buf_read_ethinfo() is used for reading both infofile and key file
 * for infofile, vpd must NOT be NULL.
 * for key file, vpd must be NULL
 */
static int buf_read_ethinfo(int ver_major, int ver_minor,
			    char *buf, struct eth_info *ethlist, int ethmax,
			    unsigned char *vpd,
			    unsigned long (*fp_strtoul)(const char *,
							char **, int))
{
	int i, j,len=0;
	int pos = 0;
	char temp[5];

	for (i = 0; i < ethmax; i++) {
		for (j = 0; j < ETH_MAC_ADDR_MAX_LEN; j++) {
			buf_copy_bytes(temp, buf, pos, 2);
			pos += 2;
			ethlist[i].mac[j] = 
				(unsigned char)fp_strtoul(temp, NULL, 16);
		}

		buf_copy_bytes(temp, buf, pos, 4);
		pos += 4;
		ethlist[i].vendor_id =
				(unsigned short)fp_strtoul(temp, NULL, 16);

		buf_copy_bytes(temp, buf, pos, 4);
		pos += 4;
		ethlist[i].device_id =
				(unsigned short)fp_strtoul(temp, NULL, 16);

		buf_copy_bytes(temp, buf, pos, 4);
		pos += 4;
		ethlist[i].linkspeed = 
				(unsigned short)fp_strtoul(temp, NULL, 16);

		if (ver_major == 1 && ver_minor >= 2) {
			buf_copy_bytes(temp, buf, pos, 4);
			pos += 4;
			ethlist[i].reeval =
				(unsigned short)fp_strtoul(temp, NULL, 16);

			len = sizeof(ethlist[i].deviceType);
			for (j = 0; j < len; j++) {
				buf_copy_bytes(temp, buf, pos, 2);
				pos += 2;
				ethlist[i].deviceType[j] =
				(unsigned char)fp_strtoul(temp, NULL, 16);
			}

			len = sizeof(ethlist[i].serialNum);
			for (j = 0; j < len; j++) {
				buf_copy_bytes(temp, buf, pos, 2);
				pos += 2;
				ethlist[i].serialNum[j] =
				(unsigned char)fp_strtoul(temp, NULL, 16);
			}
		}

		if (vpd) {
			for (j = 0; j < ETH_VPD_BYTES; j++, vpd++) {
				buf_copy_bytes(temp, buf, pos, 2);
				pos += 2;
				*vpd = (unsigned char)fp_strtoul(temp, NULL, 16);
			}
		}
	}

	return pos;
}

static inline int license_from_key_buffer(char *buf, int buflen, char *err_buf,
				   struct license *license,
				   unsigned long (*fp_strtoul)(const char *,
							       char **, int))
{
	int i, max;
	int pos = 8;
	char temp[10];
	unsigned int datalen;
	unsigned short version[2];

	/* data length */
	buf_copy_bytes(temp, buf, buflen - 4, 4);
	datalen = (unsigned int)fp_strtoul(temp, NULL, 10);
	buf[datalen] = '\0';

	if (license->version[0] > L_VERSION_MAJOR || 
	    license->version[0] < L_VERSION_MAJOR_MIN ||
	    license->version[1] > L_VERSION_MINOR ||
	    license->version[1] < L_VERSION_MINOR_MIN) {
		if(err_buf)
			sprintf(err_buf, "version %d.%d NOT supported",
				license->version[0], license->version[1]);
	}

	/* version */
	buf_read_version(buf, &version[0], fp_strtoul);
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

	if (license->ethmax > KEYFILE_ETH_MAX) {
		if (err_buf)
			sprintf(err_buf, "too many eths: %u > %d.\n",
				license->ethmax, KEYFILE_ETH_MAX);
		return -1;
	}

	pos += buf_read_ethinfo(license->version[0], license->version[1],
				buf + pos, &license->eth[0], license->ethmax,
				NULL, fp_strtoul);

	max = license_version_product_max(license->version[0],
					  license->version[1]);
	for (i = 0; i < max; i++) {
		buf_copy_bytes(temp, buf, pos, 4);
		pos += 4;
		license->product[i].flag = (unsigned int)fp_strtoul(temp, NULL, 16);

		buf_copy_bytes(temp, buf, pos, 2);
		pos += 2;
		license->product[i].duration.day =
				(unsigned int)fp_strtoul(temp, NULL, 10);

		buf_copy_bytes(temp, buf, pos, 2);
		pos += 2;
		license->product[i].duration.mon =
				(unsigned int)fp_strtoul(temp, NULL, 10);

		buf_copy_bytes(temp, buf, pos, 4);
		pos += 4;
		license->product[i].duration.year =
				(unsigned int)fp_strtoul(temp, NULL, 10);

		buf_copy_bytes(temp, buf, pos, 8);
		pos += 8;
		license->product[i].spec1 =
				(unsigned int)fp_strtoul(temp, NULL, 16);

		buf_copy_bytes(temp, buf, pos, 8);
		pos += 8;
		license->product[i].spec2 =
				(unsigned int)fp_strtoul(temp, NULL, 16);
        }

	i = datalen - pos;
	if (i == 0 || i > LICENSE_CUSTOMER_NAME_MAX_LEN) {
		if (err_buf)
			sprintf(err_buf, "name invalid %d > %d (%d - %d).\n",
				i, LICENSE_CUSTOMER_NAME_MAX_LEN, datalen, pos);
		return -1;
	}

	memcpy(license->customer, buf + pos, i);
	license->customer[i] = '\0';

	if (license_validate_fields(license) < 0) {
		if (err_buf)
			sprintf(err_buf, "fields validation failed.\n");
		return -1;
	}

	return 0;
}

#ifndef __KLIB__
static void printf_character_line(char c, int repeat)
{
	int i;

	for (i = 0; i < repeat; i++)
		printf("%c", c);
	printf("\n");
}

/*
 * utility functions
 */
static int read_one_line_file(char *fname, char *buf, int buflen)
{
	FILE *fhndl;

	memset(buf, 0, buflen);
	fhndl = fopen(fname, "r");
	if (!fhndl) {
		fprintf(stderr, "Unable to open %s for read.\n", fname);
		return -1;
	}

	if (fgets(buf, buflen, fhndl) == NULL) {
		fprintf(stderr, "Input file %s is empty \n", fname);
		fclose(fhndl);
		return -1;
	}
	fclose(fhndl);

	return (strlen(buf));
}

static inline int write_one_line_file(char *buffer, char *fname)
{
	FILE *fhndl;

	fhndl = fopen(fname, "wb+");
	if (!fhndl) {
		fprintf(stderr, "Unable to open %s for write.\n", fname);
		return -1;
	}
	fprintf(fhndl, "%s", buffer);
	fclose(fhndl);
	return 0;
}

static void seed_random_number(void)
{
	time_t currenttime;

	/*create a random seed for random function */
	time(&currenttime);
	srandom((unsigned int) currenttime);
}

static void buffer_fill_random_alphanumeric(char *buffer, int buflen)
{
	char *alphanumeric[3] = {
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"abcdefghijklmnopqrstuvwxyz",
		"01234567890123456789012345",
	};
	int i, j, k;

	/* generate a random l,u, or n option and generate random letters
	   from them */
	for (i = 0; i < buflen; i++) {
		j = random() % 3;
		k = random() % 26;
		buffer[i] = alphanumeric[j][k];
	}
}


/*
 * info. file
 */


static void infobuf_mask_zeroes(char *buf, int len)
{
	char *nonhexalpha = "GgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz";
	int cnt = strlen(nonhexalpha);
	int i;

	for (i = 0; i < len; i++)
		if (buf[i] == '0')
			buf[i] = nonhexalpha[random() % cnt];
}

static void infobuf_unmask_zeroes(char *buf, int len)
{
	int i;
	for (i = 0; i < len; i++)
		if ((buf[i] >= 'G' && buf[i] <= 'Z') ||
		    (buf[i] >= 'g' && buf[i] <= 'z')) 
			buf[i] = '0';
}

#define infobuf_sprintf_wo_null(buf, idx, bytes, fmt, arg) \
	do { \
		char __c = buf[idx + bytes]; \
		sprintf(buf + idx, fmt, arg); \
		buf[idx + bytes] = __c; \
		infobuf_mask_zeroes(buf + idx, bytes); \
	} while(0)

static void infobuf_write_ushort(char *buf, int *pos, unsigned short val,
				int step)
{
	char tbuf[5];
	int i, max;

	sprintf(tbuf, "%04x", val);
	max = strlen(tbuf) - 1;
	infobuf_mask_zeroes(tbuf, 4);
	for (i = 0; i < max; i += 2, *pos += step) {
		buf[*pos] = tbuf[i];
		buf[*pos + 1] = tbuf[i + 1];
	}
}

static void infobuf_read_unsigned(char *to, char *from, int pos, int count)
{
	memcpy(to, from + pos, count);
	to[count] = '\0';
	infobuf_unmask_zeroes(to, count);
}

static inline int write_info_file(struct eth_info *ethinfo, unsigned char *vpd,
			   int ethmax, int sel, char *fname,
			   unsigned int fsize, char *buffer)
{
	FILE *fhndl;
	int pos = INFOFILE_DATA_START(fsize);
	int step = INFOFILE_DATA_STEP(fsize);
	int i, j, len;

	/*
	 * NOTE:
         * fsize: fsize == infofile_size(),
         * buffer: length >= fsize + VERSION_STR_LENGTH + 1 
         */
	seed_random_number();

	buffer_fill_random_alphanumeric(buffer, fsize);
	sprintf(buffer + fsize, "%04d%04d", L_VERSION_MAJOR, L_VERSION_MINOR);

	infobuf_write_ushort(buffer, &pos, ethmax, step);
	infobuf_write_ushort(buffer, &pos, sel, step);

	for (i = 0; i < ethmax; i++) {
		for (j = 0; j < ETH_MAC_ADDR_MAX_LEN; j++, pos += step)
			infobuf_sprintf_wo_null(buffer, pos, 2, "%02x",
					    ethinfo[i].mac[j]);

		infobuf_write_ushort(buffer, &pos, ethinfo[i].vendor_id, step);
		infobuf_write_ushort(buffer, &pos, ethinfo[i].device_id, step);
		infobuf_write_ushort(buffer, &pos, ethinfo[i].linkspeed, step);
		infobuf_write_ushort(buffer, &pos, ethinfo[i].reeval, step);

		len = sizeof(ethinfo[i].deviceType);
		for (j = 0; j < len; j++, pos += step)
			infobuf_sprintf_wo_null(buffer, pos, 2, "%02x",
						ethinfo[i].deviceType[j]);

		len = sizeof(ethinfo[i].serialNum);
		for (j = 0; j < len; j++, pos += step)
			infobuf_sprintf_wo_null(buffer, pos, 2, "%02x",
						ethinfo[i].serialNum[j]);

		for (j = 0; j < ETH_VPD_BYTES; j++, pos += step, vpd++)
			infobuf_sprintf_wo_null(buffer, pos, 2, "%02x", *vpd);
	}

	/* Fill next DELIMIT positions with FF to indicate that data is over */
	for (i = 0; i < INFOFILE_DELIMIT_MAX; i++, pos += step)
		infobuf_sprintf_wo_null(buffer, pos, 2, "%02x", INFOFILE_DELIMITER);

	fhndl = fopen(fname, "w");
	if (!fhndl) {
		fprintf(stderr, "Unable to open %s for write.\n", fname);
		return -1;
	}
	fprintf(fhndl, "%s", buffer);
	fclose(fhndl);

	return 0;
}

static inline int read_info_file(char *fname, struct license *license,
			  unsigned char *vpd, int *sel, unsigned int fsize,
			  char *file_buf, char *info_buf)
{
	char temp[5];
	int pos = INFOFILE_DATA_START(fsize);
	int step = INFOFILE_DATA_STEP(fsize);
	int i, max, blen;
	int info_len = 0, info_max;
	int v12 = 0;

	/*
	 *NOTE:
         * fsize: fsize == infofile_size(),
         * file_buf: length >= fsize + VERSION_STR_LENGTH + 1
         * info_buf: length >= fsize  + 1
         */

	if (!vpd) {
		fprintf(stderr, "NO vpd data allocated for info file.\n");
		return -1;
	}

	if (!file_buf || !info_buf) {
		fprintf(stderr, "NO data buffer allocated for info file.\n");
		return -1;
	}

	blen = read_one_line_file(fname, file_buf, fsize+VERSION_STR_LENGTH+1);
	if (blen < 0)
		return blen;

	if (blen != (fsize + VERSION_STR_LENGTH)) {
		fprintf(stderr,
			"File %s is not a valid customer info file %d != %d.\n",
			fname, blen, fsize + VERSION_STR_LENGTH);
		return -1;
	}
	
	buf_read_version(file_buf + fsize, &license->version[0], strtoul);
	if (license->version[0] > L_VERSION_MAJOR || 
	    license->version[0] < L_VERSION_MAJOR_MIN ||
	    (license->version[1] > L_VERSION_MINOR &&
	    license->version[1] < L_VERSION_MINOR_MIN)) {
		/* special case for 1.2 */
		if (license->version[0] == 1 && license->version[1] == 2)
			v12 = 1;
		else {
			fprintf(stderr,
				"File %s version %u.%u NOT supported.\n",
				fname, license->version[0],
				license->version[1]);
			return -1;
		}
	}

	if (v12) {
		fprintf(stdout,
		"\n\t################### !!WARNING!! ######################\n"
		"\t# Generating v%d.%d license key from v1.2 info file    #\n"
		"\t# Applicable only for USS software upgrade customers.#\n"
		"\t######################################################\n\n",
			L_VERSION_MAJOR_MIN, L_VERSION_MINOR_MIN);
	}

	/* read ethmax and user selection */
	for (; info_len < 8 && pos < blen; pos += step) {
		infobuf_read_unsigned(temp, file_buf, pos, 2);
		info_len += sprintf(info_buf + info_len, "%s", temp);
	}
	if (info_len != 8) {
		fprintf(stderr, "file corrupted! Unable to read eth max/sel.\n");
		return -1;
	}

	buf_copy_bytes(temp, info_buf, 0, 4);
	license->ethmax = (unsigned int)strtoul(temp, NULL, 16);
	buf_copy_bytes(temp, info_buf, 4, 4);
	*sel = (int)strtoul(temp, NULL, 16);

	if (license->ethmax > INFOFILE_ETH_MAX) {
		fprintf(stderr, "file corrupted! Too many eth %u > %d.\n",
			license->ethmax, INFOFILE_ETH_MAX);
		return -1;
	}
	if (*sel >= license->ethmax) {
		fprintf(stderr, "file corrupted! eth selection %d/%u.\n",
			*sel, license->ethmax);
		return -1;
	}

	/* read eth info */
	info_max = license->ethmax * (sizeof(struct eth_info) + ETH_VPD_BYTES);
	info_max <<= 1; /* bytes to string */
	for (info_len = 0; info_len < info_max && pos < blen; pos += step) {
		infobuf_read_unsigned(temp, file_buf, pos, 2);
		info_len += sprintf(info_buf + info_len, "%s", temp);
	}
	if (info_len != info_max) {
		fprintf(stderr, "file corrupted! read eth info %d exp. %d.\n",
			info_len, info_max);
		return -1;
	}

	/* read delimits */
	for (i = 0; i < INFOFILE_DELIMIT_MAX && pos < blen; pos += step, i++) {
		infobuf_read_unsigned(temp, file_buf, pos, 2);
		if (strtoul(temp, NULL, 16) != INFOFILE_DELIMITER) {
			printf("expect delimit %d at %d, got %s.\n",
				i, pos, temp);
		}
	}
	if (i < INFOFILE_DELIMIT_MAX) {
		fprintf(stderr, "file corrupted! Read delimit %d.\n", i);
		return -1;
	}

	pos += buf_read_ethinfo(license->version[0], license->version[1],
				info_buf, &license->eth[0],
				license->ethmax, vpd, strtoul);

	/* Update reeval request number */
	max = license_version_product_max(license->version[0],
					  license->version[1]);
	for (i = 0; i < max; i++) {
		if (license->product[i].flag & (1 << FLAG_EVAL_BIT)) {
            		for (i = 0; i < license->ethmax; i++)
                		get_next_reeval(&license->eth[i].reeval);
            		break;
		}
	}

	return 0;
}

static inline int read_config_file(char *fname, struct license *license,
				char *buf)
{
	FILE *fhndl;
	int i;
	int line = 0;
	int rv = -1;
	int eth_cnt = 0;

	/*
 	 * NOTE:
 	 * buf: length >= fsize
 	 */

	fhndl = fopen(fname, "r");
	if (!fhndl) {
		fprintf(stderr, "ERROR opening %s for read.\n", fname);
		return -1;
	}

	while (fgets(buf, sizeof(buf), fhndl)) {
		char *ch, *key, *val;
		int len;

		line++;	
		/* remove leading space */
		for (ch = buf; *ch && isspace(*ch); ch++)
			;
		/* skip comment line */
		if (!*ch || *ch == '#')
			continue;

		key = ch;
		/* remove tailing comment */
		for (; *ch && (*ch != '#'); ch++)
			;
		if (*ch)
			*ch = '\0';
		/* remove carriage-return */
		len = strlen(key);	
		if (key[len - 1] == '\n')
			key[--len] = '\0';
		
		if (!strcmp(key, "CUSTOMERNAME=")) {
			val = key + 13;
			if (strlen(val) >= LICENSE_CUSTOMER_NAME_MAX_LEN) {
				fprintf(stderr, "line %d, customer %s: length > %d.\n",
					line, val, LICENSE_CUSTOMER_NAME_MAX_LEN);
				goto out;
			}
			if (license->customer[0]) {
				fprintf(stderr, "line %d, customer already defined %s.\n",
					line, license->customer);
				goto out;
			}
			strcpy(license->customer, val);
		} else if (!strcmp(key, "HWADDR=")) {
			val = key + 7;
			if (eth_cnt >= KEYFILE_ETH_MAX) {
				fprintf(stderr, "Too many MAC: %d > %d.\n",
					eth_cnt, KEYFILE_ETH_MAX);
				goto out;
			}
			/* We are possibly introducing some endianness issues here */
			if (sscanf(val, "%02x:%02x:%02x:%02x:%02x:%02x",
				   (int *)&license->eth[eth_cnt].mac[0],
				   (int *)&license->eth[eth_cnt].mac[1],
				   (int *)&license->eth[eth_cnt].mac[2],
				   (int *)&license->eth[eth_cnt].mac[3],
				   (int *)&license->eth[eth_cnt].mac[4],
				   (int *)&license->eth[eth_cnt].mac[5]) != 6) {
				fprintf(stderr, "line %d, INVALID MAC: %s.\n", line, key);
				goto out;
			}
			eth_cnt++;
		} else if (!strcmp(key, "DEVICEID=")) {
                        val = key + 9;
			license->eth[eth_cnt].device_id =
				(unsigned short)strtoul(val, NULL, 16);
		} else if (!strcmp(key, "VENDORID=")) {
                        val = key + 9;
			license->eth[eth_cnt].vendor_id =
				(unsigned short)strtoul(val, NULL, 16);
		} else if (!strcmp(key, "LINKSPEED=")) {
			val = key + 10;
                        license->eth[eth_cnt].linkspeed = (unsigned short)atoi(val);
		}
	}

	license->ethmax = eth_cnt;
	if (!eth_cnt) {
		fprintf(stderr, "%s: Missing HWADDR.\n", fname);
		goto out;
	}

	if (!strlen(license->customer)) {
		fprintf(stderr, "%s: Missing CUSTOMERNAME.\n", fname);
		goto out;
	}

	for (i = 0; i < eth_cnt; i++) {
		int j;
		for (j = 0; j < ETH_MAC_ADDR_MAX_LEN; j++)
			if (license->eth[i].mac[j])
				break;
		if (j == ETH_MAC_ADDR_MAX_LEN) {
			fprintf(stderr, "%s: interface %d, HWADDR all zeroes.\n", fname, i);
			goto out;
		}
		if (!license->eth[i].vendor_id) {
			fprintf(stderr, "%s: interface %d, Missing VENDORID.\n", fname, i);
			goto out;
		}
		if (!license->eth[i].device_id) {
			fprintf(stderr, "%s: interface %d, Missing DEVICEID.\n", fname, i);
			goto out;
		}
		if (!license->eth[i].linkspeed) {
			fprintf(stderr, "%s: interface %d, LINKSPEED default to 100Mbps\n",
				fname, i);
			license->eth[i].linkspeed = 100;
		}
	}

	rv = 0;
out:
	fclose(fhndl);	
	return rv;
}

/*
 * key files
 */
static inline int license_to_key_buffer(char *buf, struct license *license)
{
	int i;
	int len = 0;

	/* version */
	sprintf(buf + len, "%04d%04d", license->version[0], license->version[1]);
	len += 8;

	/* # of macs */
	sprintf(buf + len, "%02d", license->ethmax);
	len += 2;

	/* mac info */
	for (i = 0; i < license->ethmax; i++) {
		sprintf(buf + len, "%02X%02X%02X%02X%02X%02X",
			license->eth[i].mac[0], license->eth[i].mac[1],
			license->eth[i].mac[2], license->eth[i].mac[3],
			license->eth[i].mac[4], license->eth[i].mac[5]);
		len += 12;
		sprintf(buf + len, "%04x", license->eth[i].vendor_id);
		len += 4;
		sprintf(buf + len, "%04x", license->eth[i].device_id);
		len += 4;
		sprintf(buf + len, "%04x", license->eth[i].linkspeed);
		len += 4;
		sprintf(buf + len, "%04x", license->eth[i].reeval);
		len += 4;

		sprintf(buf + len, "%02X%02X%02X%02X%02X%02X%02X%02X",
			license->eth[i].deviceType[0], license->eth[i].deviceType[1],
			license->eth[i].deviceType[2], license->eth[i].deviceType[3],
			license->eth[i].deviceType[4], license->eth[i].deviceType[5],
			license->eth[i].deviceType[6], license->eth[i].deviceType[7]);
		len += 16;
		sprintf(buf + len, "%02X%02X%02X%02X%02X%02X%02X%02X",
			license->eth[i].deviceType[8],  license->eth[i].deviceType[9],
			license->eth[i].deviceType[10], license->eth[i].deviceType[11],
			license->eth[i].deviceType[12], license->eth[i].deviceType[13],
			license->eth[i].deviceType[14], license->eth[i].deviceType[15]);
		len += 16;
		sprintf(buf + len, "%02X%02X%02X%02X%02X%02X%02X%02X",
			license->eth[i].serialNum[0], license->eth[i].serialNum[1],
			license->eth[i].serialNum[2], license->eth[i].serialNum[3],
			license->eth[i].serialNum[4], license->eth[i].serialNum[5],
			license->eth[i].serialNum[6], license->eth[i].serialNum[7]);
		len += 16;
		sprintf(buf + len, "%02X%02X%02X%02X%02X%02X%02X%02X",
			license->eth[i].serialNum[8],  license->eth[i].serialNum[9],
			license->eth[i].serialNum[10], license->eth[i].serialNum[11],
			license->eth[i].serialNum[12], license->eth[i].serialNum[13],
			license->eth[i].serialNum[14], license->eth[i].serialNum[15]);
		len += 16;
	}

	/* product flag */
	for (i = 0; i < PRODUCT_MAX; i++){
		len += sprintf(buf + len, "%04x", license->product[i].flag);

	/* product duration */
		len += sprintf(buf + len, "%02d%02d%04d",
			license->product[i].duration.day, license->product[i].duration.mon,
			license->product[i].duration.year);

	/* product specific fields */	
		len += sprintf(buf + len, "%08x", license->product[i].spec1);
		len += sprintf(buf + len, "%08x", license->product[i].spec2);
	}
	/* customer name */
	len += sprintf(buf + len, "%s", license->customer);

	return len;
}
#endif /* ifndef __KERNEL__ */

#ifdef __cplusplus
}
#endif

#endif /* ifndef __LICENSE_LIB_C__ */
