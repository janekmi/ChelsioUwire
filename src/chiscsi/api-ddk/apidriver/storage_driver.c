/***************************************************************************
 *	Driver handling SCSI commands
 *	For any execution errors driver should set following fields in 
 * 	iscsi_scis_command
 *		sc_status
 *		sc_response
 *		sc_semse_key
 *		sc_sense_asc
 *		sc_sense_ascq
 *		sc_sense_buf
 *		sc_xfer_residualcount
 *	see function sc_unsupported_cmd below for example. 
 *
***************************************************************************/

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/errno.h>
#include <common/iscsi_target_class.h>
#include <common/iscsi_scsi_command.h>

#include "storage_driver.h"
#include "iface.h"

#define ALIAS	"apitest_target"

#define VENDOR_ID_MAXLEN   8
#define VENDOR_ID_DFLT     "CHISCSI"       /* 8 bytes */

char    itarget_vendor_id[VENDOR_ID_MAXLEN + 1] =
        VENDOR_ID_DFLT;

int debug = 0;

/* iscsi target sense data  */
void sc_unsupported_cmd(chiscsi_scsi_command *sc, int op)      
{
	printk("it sess 0x%p, sc itt 0x%x, opcode 0x%x not supported.\n", 
                        sc->sc_sess, sc->sc_itt, op); 
	sc->sc_response = ISCSI_RESPONSE_COMPLETED; 
	sc->sc_status = SCSI_STATUS_CHECK_CONDITION; 
	sc->sc_sense_key = SCSI_SENSE_ILLEGAL_REQUEST; 
	sc->sc_sense_asc = 0x20; /* invalid cmd opcode */ 
	sc->sc_sense_ascq = 0; 
}

#if 0
static void sc_internal_failure(chiscsi_scsi_command *sc) 
{
	printk("it sess 0x%p, sc itt 0x%x, target internal failure.\n", 
                        sc->sc_sess, sc->sc_itt); 
	sc->sc_response = ISCSI_RESPONSE_TARGET_FAILURE; 
	sc->sc_status = SCSI_STATUS_CHECK_CONDITION; 
	sc->sc_sense_key = SCSI_SENSE_ABORTED_COMMAND; 
	sc->sc_sense_asc = 0x44; /* internal target failure */ 
	sc->sc_sense_ascq = 0; 
}
#endif
       	
/* For debug */
int display_byte_string(char *caption, unsigned char *bytes, int maxlen)
{
	char *obuf = NULL;
        char   *buf = obuf;
	int start = 0;
	int obuflen = 0;
        int     buflen = obuflen;
        unsigned char *dp;
        char    buffer[256];
        unsigned int i;
        int     len = 0;

        if (!bytes)
                return 0;
        if (!buf)
                buf = buffer;

        if (caption)
                len = sprintf(buf, "%s: ", caption);
        len += sprintf(buf + len, "%u -- %u:\n", start, (start + maxlen - 1));
        if (!obuf) {
                buf[len] = 0;
                printk("%s", buf);
                len = 0;
        } else {
                if (len >= buflen) {
                        buflen = 0;
                        goto out;
                }
                buflen -= len;
                buf += len;
                len = 0;
        }

        dp = bytes + start;
        for (i = 0; i < maxlen; i++, dp++) {
                /* dump 16 bytes a time */
                if (i && (i % 16 == 0)) {
                        buf[len++] = '\n';
                        if (!obuf) {
                                buf[len] = 0;
                                printk("%s", buf);
                                len = 0;
                        }
                }
                len += sprintf(buf + len, "%02x ", *dp);
                if (obuf) {
                        if (len >= buflen) {
                                buflen = 0;
                                break;
                        }
                        buflen -= len;
                        buf += len;
                }
        }

        if (len) {
                if (obuf)
                        buf[len++] = '\n';
                else {
                        buf[len] = 0;
                        printk("%s\n", buf);
                        len = 0;
                }
        }

      out:
        return (obuf ? (obuflen - buflen) : 0);
}

int find_lun_num(int sc_lun) 
{
	int i;

	for (i = 0; i < num_luns; i++) {
		if (lun[i].lun == sc_lun) {
			break; return -1;
		}
	}
	return i;
}

int set_scsi_id(unsigned char *buf, int buflen, char *name,
			      unsigned int lun)
{
	char    tmp_buf[10];	/* large enough to hold lun number */
	int     len = sprintf(tmp_buf, "%u", lun);
	int     pos = buflen - len;

	memcpy(buf + pos, tmp_buf, len);
	buf[--pos] = '-';
	len = MINIMUM(pos, (strlen(name)));
	pos -= len;
	memcpy(buf + pos, name + strlen(name) - len, len);

	return (buflen - pos);
}

unsigned char *scmd_get_data_buffer(chiscsi_scsi_command *sc)
{
	iface_scmd_info *scmd_info = get_scmd_info_ptr(sc, 0);
        scmd_sgl *sc_sgl = &scmd_info->sc_sgl;
	chiscsi_sgvec *sgl = (chiscsi_sgvec *)sc_sgl->sgl_vecs;

	if (sc_sgl->sgl_vecs_nr) {
		memset(sgl->sg_addr, 0, sgl->sg_length);
		return (sgl->sg_addr);
	}  else 
		return ((unsigned char *)sc_sgl->sgl_vecs);
}

int scmd_buffer_copy_data(chiscsi_scsi_command *sc,
					 unsigned char *data, int dlen)
{
	iface_scmd_info *scmd_info = get_scmd_info_ptr(sc, 0);
        scmd_sgl *sc_sgl = &scmd_info->sc_sgl;
	chiscsi_sgvec *sgl = (chiscsi_sgvec *)sc_sgl->sgl_vecs;
	
	if (sc->sc_xfer_len < dlen) 
		dlen = sc->sc_xfer_len;
	
	if (sc_sgl->sgl_vecs_nr) {
		int i, off = 0;

		for (i = 0; i < sc_sgl->sgl_vecs_nr; i++, sgl++) {
			int copy = MINIMUM(dlen, sgl->sg_length);
			memcpy(sgl->sg_addr, data + off, copy);
			off += copy;
		}
			printk("scmd buffer copy %d/%u != %d.\n", 
				dlen, sc->sc_xfer_len, off);
		if (off != dlen) {
			printk("scmd buffer copy %d/%u != %d.\n", 
				dlen, sc->sc_xfer_len, off);
		}
		if (debug) 
			display_byte_string("SCSI COMMAND", sgl->sg_addr, dlen);
        } else {
                memcpy(&sgl, data, dlen);
	}

	return dlen;
}

/******************************************************************
 * scsi command implementation
******************************************************************/

int read_command_execute(iface_scmd_info *scmd_info, unsigned long long pos) 
{
	/* pass the scsi command to the backend from here*/
	/* copy data into the buffers */
	if (0) {
		printk("itt 0x%x, Backend read %u data from pos %llu \n",
			scmd_info->sc->sc_itt, scmd_info->sc->sc_xfer_len, pos);
	}
	return 0;
}


int write_command_execute(iface_scmd_info *scmd_info, unsigned long long pos) 
{
	/* pass the scsi command to the backend from here*/
	/* write data from sglist to the disk */
	if (0) {
		printk("itt 0x%x, Backend wrote %u data to %llu \n",
			scmd_info->sc->sc_itt, scmd_info->sc->sc_xfer_len, pos);
	}
	return 0;
}

#define CHECK_SCSI_RESP_BUFLEN(buflen,min)	\
	if (buflen < min) {	\
	    printk("%s: buflen %u < %u.\n", __FUNCTION__, buflen, min); \
	    return -SPC_ERR_DATA_PHASE;	\
	}

#define INQUIRY_RESP_MAX_LEN 128
int lun_inquiry(chiscsi_scsi_command * sc, unsigned char *cdb)
{
	int     rv = -1;
	int     len = 0;
	unsigned char buf[INQUIRY_RESP_MAX_LEN];

	if (((cdb[1] & 0x3) == 0x3) || (!(cdb[1] & 0x3) && cdb[2])) {
		return -1;
	}
	memset(buf, 0, INQUIRY_RESP_MAX_LEN);

	if (cdb[1] & 0x2) {	/* CMDDT bit set */
		buf[1] = 0x1;
		len = 6;
		rv = 0;
	} else if (cdb[1] & 0x1) {	/* EVPD bit set */
		if (cdb[2] == 0) {	/* supported vital product data pages */
			buf[1] = 0x0;
			buf[3] = 3;
			buf[4] = 0x0;
			buf[5] = 0x80;
			buf[6] = 0x83;
			len = 7;
			rv = 0;
		} else if (cdb[2] == 0x80) {	/* unit serial number */

			buf[1] = 0x80;
			buf[3] = SCSI_SN_MAX;

			memset(buf + 4, 0x20, SCSI_SN_MAX);
			set_scsi_id(buf + 4, SCSI_SN_MAX, ALIAS, sc->sc_lun);
			len = SCSI_SN_MAX + 4;
			rv = 0;
		} else if (cdb[2] == 0x83) {	/* device identification */
			int     tmp_len, idx;

			buf[1] = 0x83;
			buf[3] = SCSI_ID_MAX + 4 + 20;

			buf[4] = 0x2;
			buf[5] = 0x8;
			buf[7] = SCSI_ID_MAX;
			memset(buf + 8, 0x20, SCSI_ID_MAX);

			tmp_len = MINIMUM(strlen(itarget_vendor_id),
					  VENDOR_ID_MAX);
			memcpy(buf + 8, itarget_vendor_id, tmp_len);
			idx = 8 + tmp_len;
			buf[++idx] = '-';
			set_scsi_id(buf + idx, SCSI_ID_MAX - idx + 8,
				    ALIAS, sc->sc_lun);
			buf[32] = 0x51;
			buf[33] = 0x2;/* contains EUI-64 */
			buf[34] = 0xff;
			buf[35] = 0x10;
			buf[36] = 0x0;
			buf[37] = 0x7;
			buf[38] = 0x43;
			
			memcpy(buf+39,ALIAS,12);
			buf[51] = sc->sc_lun;			
	
			//len = 32;
			len = 52;
			rv = 0;
		}
	} else if (!(cdb[1] & 0x3)) {
		buf[2] = 4;
		buf[3] = 0xD2;
		buf[4] = 59;
		buf[7] = 0x02;
		memset(buf + 8, 0x20, 28);
		memcpy(buf + 8, itarget_vendor_id,
		       MINIMUM(strlen(itarget_vendor_id),
			       VENDOR_ID_MAX));
		memcpy(buf + 16, PRODUCT_ID,
		       MINIMUM(strlen(PRODUCT_ID), PRODUCT_ID_MAX));
		memcpy(buf + 32, PRODUCT_REV,
		       MINIMUM(strlen(PRODUCT_REV), PRODUCT_REV_MAX));
		buf[58] = 0x03;
		buf[59] = 0x20;
		buf[60] = 0x09;
		buf[61] = 0x60;
		buf[62] = 0x03;
		buf[63] = 0x00;
		len = 64;
		rv = 0;
	}

	if (rv < 0)
		return rv;

	/*If lun is not found in the lun array then NO_LUN*/
	if (find_lun_num(sc->sc_lun) < 0)
		buf[0] = SCSI_DEVICE_TYPE_NO_LUN;

	/* copy the data, do not enlarge */
	if (len > cdb[4])
		len = cdb[4];
	if (len > sc->sc_xfer_len)
		len = sc->sc_xfer_len;
	
	if (debug)
		display_byte_string("SCSI COMMAND", buf, len);
	
	rv = scmd_buffer_copy_data(sc, buf, len);
	return (rv < 0 ? rv : len);
}

int lun_report_luns(chiscsi_scsi_command *sc, unsigned char *cdb)
{
	unsigned int *word = (unsigned int *) (cdb + 6);
	unsigned char *buf = scmd_get_data_buffer(sc);
	int 	buflen = sc->sc_xfer_len;
	int     cnt, lun_cnt;
	int i;

	if ((ntohl(*word)) < 16 || (cdb[2] > 2) || (buf == NULL) || (buflen == 0)) {
		return -1;
	}

	lun_cnt = (buflen - 8) / 8;
		word = (unsigned int *) buf;

		cnt = 0;

		word[0] = htonl(num_luns << 3);	/* Lun List Length*/
		word[1] = 0;
		word = (unsigned int *) (buf + 8);

		for (i =0; i < num_luns; i++) {
			*word = htonl((0x3ff & lun[i].lun) << 16 |
					 ((lun[i].lun >
					   0xff) ? (0x1 << 30) : 0));
			word += 2;
			cnt++;
			if (cnt >= lun_cnt)
				break;
		}

	return buflen;
}


int lun_read_capacity(chiscsi_scsi_command *sc, unsigned char *cdb)
{
	unsigned int buflen = sc->sc_xfer_len;
	unsigned char *buf = scmd_get_data_buffer(sc);
	unsigned int *word;
	int i = sc->sc_lun;
	unsigned long long sectors = lun[i].size >> lun[i].sect_shift;
	
	CHECK_SCSI_RESP_BUFLEN(buflen, 8);

	word = (unsigned int *) buf;
	word[0] = (sectors >> 32) ?
		htonl(0xffffffff) : htonl(sectors - 1);
	word[1] = htonl(1U << lun[i].sect_shift);

	return 8;
}

static unsigned char page_01[] = { 
        0x01, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00,
};

/* Disconnect-Reconnect page for mode_sense */
static unsigned char disconnect_pg[] = {
	0x2, 0xe, 0x80, 0x80, 0x0, 0xa, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
};

/* Caching page for mode_sense */
/* for write-through, it should be 0x8, 0x12 0x10, ... */
/* for write-back, it should be 0x8, 0x12 0x14, ... */
static unsigned char caching_pg[] = {
	0x8, 0x12, 0x0, 0x0, 0xff, 0xff, 0x0, 0x0,
	0xff, 0xff, 0xff, 0xff, 0x80, 0x14, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0
};

/* Control mode page for mode_sense */
static unsigned char ctrl_m_pg[] = {
	0xa, 0xa, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x2, 0x4b
};

/* Informational Exceptions control mode page for mode_sense */
static unsigned char iec_m_pg[] = {
	0x1c, 0xa, 0x8, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0
};

/* Format device page for mode_sense */
static unsigned char format_pg[] = {
	0x3, 0x16, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x1, 0x0, 0x2, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0
};

static unsigned char geo_m_pg[] = {
	0x4, 0x16, 0x0, 0x0, 0x0, 0x40, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x3a, 0x98, 0x0, 0x0
};

static int copy_geo_m_pg(unsigned char *buf, unsigned long long sector)
{
	int     size = sizeof(geo_m_pg);
	unsigned int ncyl, *p;

	/* assume 0xff heads, 15krpm. */
	memcpy(buf, geo_m_pg, size);
	ncyl = sector >> 14;	/* 256 * 64 */
	p = (unsigned int *) (buf + 1);
	*p = *p | htonl(ncyl);
	return size;
}

static int copy_mode_sense_pg(unsigned char *buf, unsigned char *pg,
			      unsigned char pg_size)
{
	memcpy(buf, pg, pg_size);
	return pg_size;
}

#define MODE_SENSE_RESP_MAX_LEN 256
static int lun_mode_sense(chiscsi_scsi_command *sc, unsigned char *cdb, int opc)
{
	unsigned char pcode = cdb[2] & 0x3f;
	unsigned char buf[MODE_SENSE_RESP_MAX_LEN];
	int i = sc->sc_lun;
	unsigned long long sectors = lun[i].size >> lun[i].sect_shift;
	int     len;

	memset(buf, 0, MODE_SENSE_RESP_MAX_LEN);

	if (opc==6) {
		if (lun[i].flags & (1 << LUN_RO_BIT))
			buf[2] = 0x80;
	}
	else {
		if (lun[i].flags & (1 << LUN_RO_BIT))
			buf[3] = 0x80;
	}

	if (cdb[1] & 0x8) {
		len = 4;
	} else {
		if(cdb[1] & 0x10)
		{
			unsigned int *word;
			len =24;
			buf[7] = 16; /*Descriptor length*/
			word = (unsigned int *) (buf + 8);
			word[0] = htonl(sectors >>32);
			word[1] = htonl(sectors);
			word[2] = 0;
			word[3] = htonl(1U << lun[i].sect_shift);
		} else {
			unsigned int *word;
			len = 12;
			buf[3] = 8;
			word = (unsigned int *) (buf + 4);
			word[0] = (sectors >> 32) ?
				htonl(0xffffffff) : htonl(sectors);
			word[1] = htonl(1U << lun[i].sect_shift);
		}
	}

	switch (pcode) {
	
		case 0x1: /* Read/Write Error Recovery Page */
			len += copy_mode_sense_pg(buf + len, page_01,
						  sizeof(page_01));
			break;
		case 0x2:	/* Disconnect-Reconnect page, all devices */
			len += copy_mode_sense_pg(buf + len, disconnect_pg,
						  sizeof(disconnect_pg));
			break;
		case 0x3:	/* Format device page, direct access */
			len += copy_mode_sense_pg(buf + len, format_pg,
						  sizeof(format_pg));
			break;
		case 0x4:
			len += copy_geo_m_pg(buf + len, sectors);
			break;
		case 0x8:	/* Caching page, direct access */
			caching_pg[2] = 0x14;
			len += copy_mode_sense_pg(buf + len, caching_pg,
						  sizeof(caching_pg));
			break;
		case 0xa:	/* Control Mode page, all devices */
			len += copy_mode_sense_pg(buf + len, ctrl_m_pg,
						  sizeof(ctrl_m_pg));
			break;
		case 0x1c:	/* Informational Exceptions Mode page, all devices */
			len += copy_mode_sense_pg(buf + len, iec_m_pg,
						  sizeof(iec_m_pg));
			break;
		case 0x3f:
			caching_pg[2] = 0x14;
			len += copy_mode_sense_pg(buf + len, page_01,
						  sizeof(page_01));
			len += copy_mode_sense_pg(buf + len, disconnect_pg,
						  sizeof(disconnect_pg));
			len += copy_mode_sense_pg(buf + len, format_pg,
						  sizeof(format_pg));
			len += copy_geo_m_pg(buf + len, sectors);
			len += copy_mode_sense_pg(buf + len, caching_pg,
						  sizeof(caching_pg));
			len += copy_mode_sense_pg(buf + len, ctrl_m_pg,
						  sizeof(ctrl_m_pg));
			len += copy_mode_sense_pg(buf + len, iec_m_pg,
						  sizeof(iec_m_pg));
			break;
		default:
			return -1;
	}
	if (opc==6) {
		buf[0] = len - 1;
	}
	else {
		buf[0] = ((len -1) >> 16);
		buf[1] = (len -1 );
	}

	if (len > sc->sc_xfer_len)
		len = sc->sc_xfer_len;

	return (scmd_buffer_copy_data(sc, buf, len));
}

static int lun_request_sense(chiscsi_scsi_command *sc, unsigned char *cdb)
{
	unsigned char *buf = scmd_get_data_buffer(sc);

	CHECK_SCSI_RESP_BUFLEN(sc->sc_xfer_len, 18);

	buf[0] = 0xf0;
	buf[1] = 0;
	buf[2] = SCSI_SENSE_NO_SENSE;
	buf[7] = 0xa;

	return 18;
}

#define READ_CAPACITY_16_MAX_LEN 32
static int lun_service_action_in(chiscsi_scsi_command *sc, unsigned char *cdb) 
{
	int i = sc->sc_lun;
	unsigned long long sectors = lun[i].size >> lun[i].sect_shift;	
	unsigned char buf[READ_CAPACITY_16_MAX_LEN];
	unsigned int len;

	if ((cdb[1] & 0x1f)!= SCSI_READ_CAPACITY_16) {
		sc_unsupported_cmd(sc, cdb[0]);
		return 0;
	}

	len = cdb[13] + (cdb[12] << 8) + (cdb[11] << 16) + (cdb[10] << 24);

	if (len > READ_CAPACITY_16_MAX_LEN)
		len = READ_CAPACITY_16_MAX_LEN;
	CHECK_SCSI_RESP_BUFLEN(sc->sc_xfer_len, len);

	memset(buf, 0, READ_CAPACITY_16_MAX_LEN);

	*((uint64_t *) buf) = (uint64_t)cpu_to_be64(sectors - 1);
	*((uint32_t *)(buf + 8)) = (uint32_t)htonl(1UL << lun[i].sect_shift);

	return (scmd_buffer_copy_data(sc, buf, len));
}

/*Function to determine non rwio commands*/
int parse_cdb_rw_info(chiscsi_scsi_command *sc) 
{
        int opcode = sc->sc_cmd[0];
        if (SCSI_RWIO_6_CMD(opcode)) {
		scmd_set_bit(sc, CH_SFP_RWIO_BIT);
                cdb_6_decode(sc->sc_cmd, sc->sc_lba, sc->sc_blk_cnt);
        } else if (SCSI_RWIO_10_CMD(opcode)) {
		scmd_set_bit(sc, CH_SFP_RWIO_BIT);
                cdb_10_decode(sc->sc_cmd, sc->sc_lba, sc->sc_blk_cnt);
        } else if (SCSI_RWIO_12_CMD(opcode)) {
		scmd_set_bit(sc, CH_SFP_RWIO_BIT);
                cdb_12_decode(sc->sc_cmd, sc->sc_lba, sc->sc_blk_cnt);
        } else if (SCSI_RWIO_16_CMD(opcode)) {
		scmd_set_bit(sc, CH_SFP_RWIO_BIT);
                cdb_16_decode(sc->sc_cmd, sc->sc_lba, sc->sc_blk_cnt);
        }

        return 0;
}

/* SCSI primary command handling */
int iscsi_target_lu_scsi_non_rwio_cmd_respond(chiscsi_scsi_command *sc)
{
	unsigned char opcode = sc->sc_cmd[0];
	int rv = 0;
	
	if (sc->sc_sgl.sgl_vecs_nr > 1) {
		printk("rcv sc non rwio cmd, itt 0x%x, xfer %u, num sgl vecs %u > 1.\n",
				sc->sc_itt, sc->sc_xfer_len, sc->sc_sgl.sgl_vecs_nr);
		chiscsi_target_session_abort((unsigned long)sc->sc_sess); 
		/* Instead of calling chiscsi_target_session_abort it is also 
		 * possible to send check condition as shown below */ 
		/* sc_internal_failure(sc); */
		return 0;
	}

	switch (opcode) {
		case SCSI_OPCODE_INQUIRY:
			/* mandatory, ignore unit attention */
			rv = lun_inquiry(sc, sc->sc_cmd);
			printk("lun inquiry \n");
			break;
		case SCSI_OPCODE_REPORT_LUNS:
			rv = lun_report_luns(sc, sc->sc_cmd);
			break;
		case SCSI_OPCODE_READ_CAPACITY_10:
			rv = lun_read_capacity(sc, sc->sc_cmd);
			break;
		case SCSI_OPCODE_MODE_SENSE_6:
			rv = lun_mode_sense(sc, sc->sc_cmd, 6);
			break;
		case SCSI_OPCODE_REQUEST_SENSE:	/* mandatory, ignore unit attention */
			rv = lun_request_sense(sc, sc->sc_cmd);
			break;
		case SCSI_OPCODE_SERVICE_ACTION_IN_16:
			rv = lun_service_action_in(sc, sc->sc_cmd);
			break;
		case SCSI_OPCODE_START_STOP_UNIT:
		case SCSI_OPCODE_TEST_UNIT_READY:
			break;
		default:
			sc_unsupported_cmd(sc, opcode);
			rv = 0;
			break;
	}

	return 0;
}
