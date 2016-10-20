#include <common/version.h>
#include <common/os_builtin.h>
#include <common/os_export.h>
#include <iscsi_target_api.h>
#include "iscsi_target_private.h"
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <strings.h>
#include <arpa/inet.h>
#include <sys/types.h>
#endif

/* Function declarations */
int stm_command_reservation_check(chiscsi_scsi_command *, chiscsi_target_lun *);
static int stm_preserve_check_registration(chiscsi_target_lun *, char *);

/*Preprocessor macros*/
#ifndef O_WRONLY
#define O_WRONLY             01
#endif
#ifndef O_RDWR
#define O_RDWR               02
#endif
#ifndef O_CREAT
#define O_CREAT            0100 /* not fcntl */
#endif
#define MAXPATHLEN          256
/*
 * Information obtained from:
 *	SPC-3, Revision 23
 *	Section 6.12.1 PERSISTENCE RESERVE OUT
 *	Table 112 - PERSISTENCE RESERVE OUT command
 */
typedef struct scsi_cdb_prout {
	uint8_t			cmd;
	uint8_t			action : 5,
				resbits : 3;
	uint8_t			type : 4,
				scope : 4;
	uint8_t			resbytes[2];
	uint8_t			param_len[4];
	uint8_t			control;
} scsi_cdb_prout_t;

typedef struct scsi_cdb_prin {
	uint8_t			cmd;
	uint8_t			action : 5,
				resbits : 3;
	uint8_t			resbytes[5];
	uint8_t			alloc_len[2];
	uint8_t			control;
} scsi_cdb_prin_t;

#define	PR_LU_SCOPE		0x0	/* Persistent reservation applies to full logical unit*/
#define	PR_OUT_REGISTER_MOVE	0x7

 /*	Table 114 - PERSISTENCE RESERVE OUT parameter list
 */
typedef struct scsi_prout_plist {
	uint8_t			reservation_key[8];
	uint8_t			service_key[8];
	uint8_t			obsolete1[4];
	uint8_t			resbits1 : 4,
				spec_i_pt : 1,
				all_tg_pt : 1,
				resbits2 : 1,
				aptpl : 1;
	uint8_t			resbytes1;
	uint8_t			obsolete2[2];
	uint8_t			apd[1];
} scsi_prout_plist_t;

#define STM_ALIAS_PAD_SIZE(nx)          if (nx % 4) nx=nx+(4-(nx % 4));

struct  StmAliasEntry{
    uint64_t        alias;
    uint8_t         protocol_id;
    uint8_t         reserved1;
    uint8_t         reserved2;
    uint8_t         format_code;
    uint16_t        reserved3;
    uint16_t        designation_length;
    uint8_t         designation[4];
};


static void scmd_calc_residualcount(chiscsi_scsi_command *sc, unsigned int len)
{
	if (len != sc->sc_xfer_len) {
		if (len >  sc->sc_xfer_len) {
			sc->sc_xfer_residualcount = len - sc->sc_xfer_len;
			sc->sc_flag |= SC_FLAG_XFER_OVERFLOW;
		} else {
			sc->sc_xfer_residualcount = sc->sc_xfer_len - len;
			sc->sc_flag |= SC_FLAG_XFER_UNDERFLOW;
		}
		sc->sc_xfer_len = sc->sc_xfer_left = len;
	}
}

static inline unsigned char *scmd_get_data_buffer(chiscsi_scsi_command *sc)
{
	if (sc->sc_sgl.sgl_vecs_nr) {
		chiscsi_sgvec *sgl = (chiscsi_sgvec *)sc->sc_sgl.sgl_vecs;
		memset(sgl->sg_addr, 0, sgl->sg_length);
		return (sgl->sg_addr);
	} else 
		return (sc->sc_sgl.sgl_vecs);
	
}

static inline int scmd_buffer_copy_data(chiscsi_scsi_command *sc,
					 unsigned char *data, int dlen)
{
	if (sc->sc_xfer_len < dlen) 
		dlen = sc->sc_xfer_len;
	if (sc->sc_sgl.sgl_vecs_nr) {
		chiscsi_sgvec *sgl = (chiscsi_sgvec *)sc->sc_sgl.sgl_vecs;
		int i = 0, off = 0, copy = 0;
		for (i = 0; i < sc->sc_sgl.sgl_vecs_nr; i++, sgl++) {
			copy = MINIMUM(dlen, sgl->sg_length);
			memcpy(sgl->sg_addr, data + off, copy);
			off += copy;
		}
		if (off != dlen) {
os_log_info("scmd buffer copy %d/%u != %d.\n", dlen, sc->sc_xfer_len, off);
		}
		if (sc->sc_xfer_len > dlen) {
			for (; i < sc->sc_sgl.sgl_vecs_nr; i++, sgl++) {
				memset(sgl->sg_addr + copy, 0,
					sgl->sg_length - copy);	
				copy = 0;
			}
		}
	} else {
		memcpy(sc->sc_sgl.sgl_vecs, data, dlen);	
		if (sc->sc_xfer_len > dlen)
			memset(sc->sc_sgl.sgl_vecs + dlen, 0,
				sc->sc_xfer_len - dlen);
	}
	return dlen;
}

/*
 * scsi cdb processing
 */

#define CHECK_SCSI_RESP_BUFLEN(buflen,min)	\
	if (buflen < min) {	\
	    os_log_info("%s: buflen %u < %u.\n", __FUNCTION__, buflen, min); \
	    return -SPC_ERR_DATA_PHASE;	\
	}

#define INQUIRY_RESP_MAX_LEN 128
static int lun_inquiry(chiscsi_scsi_command * sc, unsigned char *cdb)
{
	iscsi_session *sess = sc->sc_sess;
	iscsi_node *node = sess->s_node;
	chiscsi_target_lun *lu = NULL;
	unsigned char buf[INQUIRY_RESP_MAX_LEN];
	unsigned int lun = sc->sc_lun_acl;
	int len = 0;
	int no_lun = 0;
	int rv;

	if (!node) {
		os_log_info("scsi inquiry, itt 0x%x, node NULL.\n", sc->sc_itt);
		return -ISCSI_EINVAL;
	}
	if (sc->sc_flag & SC_FLAG_LUN_OOR)
		no_lun = 1;

	lu = iscsi_target_session_lun_get(sc->sc_sess, lun);
	if (!lu) {
		os_log_info("inquiry, itt 0x%x, lun %d/%d NULL.\n",
			sc->sc_itt, lun, sc->sc_lun);
		/* set to NO_LUN */
		no_lun = 1;
	}

	if (((cdb[1] & 0x3) == 0x3) || (!(cdb[1] & 0x3) && cdb[2])) {
		rv = -ISCSI_EINVAL;
		goto done;
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
		} else if (!no_lun && cdb[2] == 0x80) {
			/* unit serial number */
			buf[1] = 0x80;
			buf[3] = IT_SCSI_SN_MAX;

			memset(buf + 4, 0x20, IT_SCSI_SN_MAX);
			memcpy(buf + 4, lu->scsi_sn,
			   MINIMUM(os_strlen(lu->scsi_sn), IT_SCSI_SN_MAX));
			len = IT_SCSI_SN_MAX + 4;
			rv = 0;
		} else if (!no_lun && cdb[2] == 0x83) {
			/* device identification */
			buf[1] = 0x83;
			buf[3] = IT_SCSI_ID_MAX + 4 + 20;

			buf[4] = 0x2;
			buf[5] = 0x8;
			buf[7] = IT_SCSI_ID_MAX;

			memset(buf + 8, 0x20, IT_SCSI_ID_MAX);
			memcpy(buf + 8, lu->scsi_id,
			   MINIMUM(os_strlen(lu->scsi_id), IT_SCSI_ID_MAX));
			buf[32] = 0x51;
			buf[33] = 0x2;/* contains EUI-64 */
			buf[34] = 0xff;
			buf[35] = 0x10;

			memcpy(buf+36, lu->scsi_wwn, IT_SCSI_WWN_MAX);
			len = 52;
			rv = 0;
		}
	} else if (!no_lun && !(cdb[1] & 0x3)) {
		buf[2] = 4;
		buf[3] = 0xD2;
		buf[4] = 59;
		/* Setting PROTECT bit if DIF is enabled */
		if (chiscsi_target_lun_flag_test(lu, LUN_T10DIF_BIT))
 		 	buf[5] = 0x01;

		buf[7] = 0x02;
		memset(buf + 8, 0x20, 28);
		memcpy(buf + 8, iscsi_target_vendor_id,
		       MINIMUM(os_strlen(iscsi_target_vendor_id),
			       IT_VENDOR_ID_MAX));
		memcpy(buf + 16, lu->prod_id, 
			MINIMUM(os_strlen(lu->prod_id), IT_PRODUCT_ID_MAX));
		memcpy(buf + 32, IT_PRODUCT_REV,
		       MINIMUM(os_strlen(IT_PRODUCT_REV), IT_PRODUCT_REV_MAX));
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
		goto done;

	if (no_lun)
		buf[0] = SCSI_DEVICE_TYPE_NO_LUN;

	/* copy the data, do not enlarge */
	if (len > cdb[4])
		len = cdb[4];
	if (len > sc->sc_xfer_len)
		len = sc->sc_xfer_len;

	rv = scmd_buffer_copy_data(sc, buf, len);
	//return (rv < 0 ? rv : len);
done:
	if (lu)
		iscsi_target_session_lun_put(lu);

	return (rv < 0 ? rv : sc->sc_xfer_len);
}

static int lun_report_luns(chiscsi_scsi_command *sc, unsigned char *cdb)
{
	iscsi_session *sess = sc->sc_sess;
	iscsi_node *node = sess->s_node;
	unsigned int *word = (unsigned int *) (cdb + 6);
	int acl_on = iscsi_node_acl_enable(node);
	int cnt = (sc->sc_xfer_len - 8) / 8;
	unsigned int lu_cnt = node->lu_cnt;
	unsigned int sg_i = 0; 
	unsigned int sgcnt = sc->sc_sgl.sgl_vecs_nr;
	unsigned int sglen;
	chiscsi_sgvec *sg;
	unsigned int tlen = 0;

	if ((os_ntohl(*word)) < 16 || (cdb[2] > 2))
		return -ISCSI_EINVAL;

	if (acl_on) {
		if (!sess->acl) {
			iscsi_connection *conn = sc->sc_conn;
			int rv = iscsi_acl_connection_check(conn);

			if (rv < 0)
				return rv;
		}
		lu_cnt = sess->acl_lu_cnt;
	}

	if (sgcnt) {
		sg = (chiscsi_sgvec *)sc->sc_sgl.sgl_vecs;
		memset(sg->sg_addr, 0, sg->sg_length);

		sglen = sg->sg_length;
		word = (unsigned int *)sg->sg_addr;
	} else {
		sg = NULL;
		sglen = sc->sc_xfer_len;
		word = (unsigned int *)sc->sc_sgl.sgl_vecs;
	}

	if (!sglen || !word)
		return -ISCSI_ENOMEM;

	if (cnt < lu_cnt) {
		/* not enough space for all the luns */
		word[0] = os_htonl(lu_cnt << 3);
		tlen = 4;
	} else {
		chiscsi_target_lun *lu;
		unsigned int i;
		unsigned int used = 8;

		/* enough space for all the luns */
		word[0] = os_htonl(lu_cnt << 3);
		word[1] = 0;
		word += 2;

		for (i = 0; i < lu_cnt; i++, used += 8, word += 2) {
			if (acl_on && sess->acl_lu_cnt < node->lu_cnt)
				lu = node->lu_list[sess->acl_lun_list[i]];
			else
				lu = node->lu_list[i];

			if (used >= sglen) {
				tlen += used;
				if (sg_i >= sgcnt) {
					os_log_info("report_luns: used %u > "
						"xfer %u, sg %u/%u.\n",
						used, tlen, sg_i, sgcnt);
					return tlen;
				}
				sg_i++;
				sg = sg->sg_next;
				memset(sg->sg_addr, 0, sg->sg_length);

				sglen = sg->sg_length;
				word = (unsigned int *)sg->sg_addr;
				used = 0;
			}

			*word = os_htonl((0x3fff & i) << 16);
		}
		tlen += used;
	}

	return sc->sc_xfer_len;
}

static int lun_read_capacity(chiscsi_scsi_command *sc, unsigned char *cdb)
{
	unsigned int buflen = sc->sc_xfer_len;
	unsigned char *buf = scmd_get_data_buffer(sc);
	unsigned int *word;
	chiscsi_target_lun *lu;
	unsigned long long sectors;

	CHECK_SCSI_RESP_BUFLEN(buflen, 8);

	lu = iscsi_target_session_lun_get(sc->sc_sess, sc->sc_lun_acl);
	if (!lu)
		return -ISCSI_EINVAL;
	sectors = lu->size >> lu_sect_shift;

	word = (unsigned int *) buf;
	word[0] = (sectors >> 32) ?
		os_htonl(0xffffffff) : os_htonl(sectors - 1);
	word[1] = os_htonl(1U << lu_sect_shift);

	iscsi_target_session_lun_put(lu);
	return 8;
}

static unsigned char page_01[] = { 
        0x01, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00,
};

#if 0
static unsigned char page_07[] = {
    0x07, 0x0a,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
#endif

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
	*p = *p | os_htonl(ncyl);
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
	unsigned long long sectors;
	chiscsi_target_lun *lu;
	int rv = 0;
	int     len;

	memset(buf, 0, MODE_SENSE_RESP_MAX_LEN);

	lu = iscsi_target_session_lun_get(sc->sc_sess, sc->sc_lun_acl);
	if (!lu)
		return -ISCSI_EINVAL;
	sectors = lu->size >> lu_sect_shift;

	/* read only */
	if (chiscsi_target_lun_flag_test(lu, LUN_RO_BIT) ||
	    !(sc->sc_flag & SC_FLAG_LUN_ACL_W)) {
		if (opc == 6)
			buf[2] = 0x80;
		else
			buf[3] = 0x80;
	}

	if (cdb[1] & 0x8) {
		len = 4;
	} else {
		if(cdb[1] & 0x10)
		{
			unsigned int *word;
			len =24;
			buf[7] = 16; //Descriptor length
			word = (unsigned int *) (buf + 8);
			word[0] = os_htonl(sectors >>32);
			word[1] = os_htonl(sectors);
			word[2] = 0;
			word[3] = os_htonl(1U << lu_sect_shift);
		} else {
			unsigned int *word;
			len = 12;
			buf[3] = 8;
			word = (unsigned int *) (buf + 4);
			word[0] = (sectors >> 32) ?
				os_htonl(0xffffffff) : os_htonl(sectors);
			word[1] = os_htonl(1U << lu_sect_shift);
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
	/*
		case 0x7:
			len += copy_mode_sense_pg(buf + len, page_07,
						  sizeof(page_07));
			break;
	*/
		case 0x8:	/* Caching page, direct access */
			caching_pg[2] = chiscsi_target_lun_flag_test(lu,
						LUN_NOWCACHE_BIT) ? 0x10 : 0x14;
			len += copy_mode_sense_pg(buf + len, caching_pg,
						  sizeof(caching_pg));
			break;
		case 0xa:	/* Control Mode page, all devices */
			len += copy_mode_sense_pg(buf + len, ctrl_m_pg,
						  sizeof(ctrl_m_pg));
			break;
		case 0x2c:     /* RDAC page */
			/* We don't support RDAC Redundant Controller neither does Microsoft Target, 
				send empty response to silence sg_utils. */
			break;
		case 0x1c:	/* Informational Exceptions Mode page, all devices */
			len += copy_mode_sense_pg(buf + len, iec_m_pg,
						  sizeof(iec_m_pg));
			break;
		case 0x3f:
			caching_pg[2] = 0x14;
#if 0
			caching_pg[2] =
				chiscsi_target_lun_flag_test(lun,
						LU_FLAG_CACHE_BIT) ? 0x14 :
				0x10;
#endif
			len += copy_mode_sense_pg(buf + len, page_01,
						  sizeof(page_01));
			len += copy_mode_sense_pg(buf + len, disconnect_pg,
						  sizeof(disconnect_pg));
			len += copy_mode_sense_pg(buf + len, format_pg,
						  sizeof(format_pg));
			len += copy_geo_m_pg(buf + len, sectors);
	//		len += copy_mode_sense_pg(buf + len, page_07,
	//					  sizeof(page_07));
			len += copy_mode_sense_pg(buf + len, caching_pg,
						  sizeof(caching_pg));
			len += copy_mode_sense_pg(buf + len, ctrl_m_pg,
						  sizeof(ctrl_m_pg));
			len += copy_mode_sense_pg(buf + len, iec_m_pg,
						  sizeof(iec_m_pg));
			break;
		default:
			rv = -ISCSI_EINVAL;
			goto done;
	}
	if (opc==6) {
		buf[0] = len - 1;
	}
	else {
		//buf[1] = (uint8_t)(len - 2);
		buf[0] = ((len -1) >> 16);
		buf[1] = (len -1 );
	}

	if (len > sc->sc_xfer_len)
		len = sc->sc_xfer_len;

#ifndef __TARGET_LU_NO_UNDER_FLOW__
	/* copy the data */
	scmd_calc_residualcount(sc, len);
#endif
done:
	iscsi_target_session_lun_put(lu);
	if (rv < 0) return rv;
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
	chiscsi_target_lun *lu;
	unsigned long long sectors;
	unsigned char buf[READ_CAPACITY_16_MAX_LEN];
	unsigned int len;

#if 0
	/* T10DIF test */
	os_log_info("%s: scsi cmd 0x%x rcvd\n", __FUNCTION__, cdb[1]);
#endif

	if ((cdb[1] & 0x1f)!= SCSI_READ_CAPACITY_16) {
		os_log_info("%s: cmd 0x%x not supported.\n", __FUNCTION__, cdb[1]);
		sc_unsupported_cmd(sc, cdb[0]);
		return 0;
	}

	len = cdb[13] + (cdb[12] << 8) + (cdb[11] << 16) + (cdb[10] << 24);

	if (len > READ_CAPACITY_16_MAX_LEN)
		len = READ_CAPACITY_16_MAX_LEN;
	CHECK_SCSI_RESP_BUFLEN(sc->sc_xfer_len, len);

	memset(buf, 0, READ_CAPACITY_16_MAX_LEN);

	lu = iscsi_target_session_lun_get(sc->sc_sess, sc->sc_lun_acl);
	if (!lu)
		return -ISCSI_EINVAL;
	sectors = lu->size >> lu_sect_shift;	

	*((uint64_t *) buf) = (uint64_t)os_htonll(sectors - 1);
	*((uint32_t *)(buf + 8)) = (uint32_t)os_htonl(1UL << lu_sect_shift);

	/* Set P_TYPE and PROT_EN */
	if (chiscsi_target_lun_flag_test(lu, LUN_T10DIF_BIT))
		buf[12] = 0x01;	/* type 1 and protection enable */

	iscsi_target_session_lun_put(lu);

	return (scmd_buffer_copy_data(sc, buf, len));
}

/* Global Constants */
/* ================ */

/* Global Type Definitions */
/* ======================= */
struct  StmPreserveParameters{
  uint64_t reservation_key;
  uint64_t sa_key;
  uint32_t scope_address;
  uint8_t  flags;
  uint8_t  reserved;
  uint16_t obsolete;
}__attribute__((packed));
//};

#define os_ntohl64(x)	(os_ntohl((uint32_t) (x>>32)) + \
			((uint64_t) os_ntohl((uint32_t) x) << 32))

/* Global Variables */
/* ================ */

static unsigned char  stm_persistent_reserve_in_mask[] =
    { 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x3f };

static unsigned char  stm_persistent_reserve_out_mask[] =
    { 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x3f };

static uint8_t  stm_report_alias_mask[] =
    { 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff,
    0x3f };

#if 0
static uint8_t  stm_report_target_port_groups_mask[] =
    { 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff,
    0x3f };
#endif

/*
 * Function: stm_command_syntax_check
 *
 * Description:
 * - Checks for SCSI command syntax conformity
 * - Returns 0 if okay; returns 1 if error has been detected.
 * - Errors will set sense data, scsi status and general status and will
 * - terminate command.  Calling procedure should simply finish on return.
 * - mask:  command syntax mask
 * - ret:  return value
 *
 * - SCSI notes:
 *	- # Each SCSI command is defined by a syntax bit mask of reserved or
 *	  unused bits.
 *	- # These bits must be 0 in command block. Errors are detected using a
 *	   logical AND between the command block and the mask.
 */
int stm_command_syntax_check(chiscsi_scsi_command *sc, unsigned char * mask)
{
	int j;
	int ret = 0;

	for (j = 0; j < sc->sc_cmdlen; j++)
		if (sc->sc_cmd[j] & mask[j])
			ret = 1;
	return ret;
}


/*
 * Function: stm_preserve_find_registration
 * Description:
 * - finds active registration
 * - -1 is used as no-care parameter
 * - returns index or returns -1 if fails
 */
static int stm_preserve_find_registration(chiscsi_target_lun *lu, char *id,
					uint64_t key)
{
	int dne = 0;
	int idx = 0;

	while (!dne && (idx<STM_PRESERVE_REGISTRATION_MAX)) {
		if (lu->rsv.pr_registrations[idx].valid &&
		    ((os_strcmp(lu->rsv.pr_registrations[idx].initiator_id,id)
			== 0) ||
		     (id==NULL)) &&
		    ((lu->rsv.pr_registrations[idx].key==key) || (key==-1)))
			dne = 1;
		else
			idx++;
	}
	if (idx == STM_PRESERVE_REGISTRATION_MAX)
		idx=-1;
	return idx;
}

/*
 * Function: stm_preserve_find_registration_free
 * Description:
 * - finds free registration entry
 * - returns index or returns -1 if fails
 */
static int stm_preserve_find_registration_free(chiscsi_target_lun *lu)

{
	int idx = 0;

	while ((idx < STM_PRESERVE_REGISTRATION_MAX) &&
	       (lu->rsv.pr_registrations[idx].valid))
		idx++;
	if (idx == STM_PRESERVE_REGISTRATION_MAX)
		idx=-1;

	return idx;
}

/*
 *      Persistent Reserve In
 */

/*
 * Function: stm_preserve_read_keys
 * Description:
 * - Service Action: Read keys
 */
static int stm_preserve_read_keys(chiscsi_target_lun *lu,
				 chiscsi_scsi_command *sc, int alen)
{
	int j,nx;
	uint32_t *buf;
	int len = 0;

	if ((buf = os_alloc(alen,1,1)) == NULL)
		/* Lack of memory is not fatal, just too busy */
		return -1;

	nx = 0;
	for (j = 0; j < STM_PRESERVE_REGISTRATION_MAX; j++) {
		if (lu->rsv.pr_registrations[j].valid) {
			buf[nx*2 + 2] = os_ntohl(
				(int)(lu->rsv.pr_registrations[j].key>>32));
             		buf[nx*2 + 3] = os_ntohl(
				(int) lu->rsv.pr_registrations[j].key);
			nx++;
		}
	}

	len = nx*8;
	buf[0] = os_ntohl(lu->rsv.pr_generation);
	buf[1] = os_ntohl(len);

	len+=8;
	scmd_buffer_copy_data(sc, (unsigned char *)buf, len);
	os_free(buf);
	return 0;
}

/*
 * Function: stm_preserve_read_reservations
 * Description:
 * - Service Action: Read reservations
 */
static int stm_preserve_read_reservations(chiscsi_target_lun *lu,
					 chiscsi_scsi_command *sc)
{
	uint32_t *buf;
	int len = 0;

	if ((buf = os_alloc(24,1,1)) == NULL)
		/* Lack of memory is not fatal, just too busy */
		return -1;

	if (lu->rsv.pr_reservation.valid) {
		buf[2] = os_ntohl((uint32_t) (lu->rsv.pr_reservation.key>>32));
		buf[3] = os_ntohl((uint32_t) lu->rsv.pr_reservation.key);
		buf[5] = os_ntohl((int) (lu->rsv.pr_reservation.type<<16));
		len = 24;
		buf[1]=os_ntohl(16);
	} else {
		len = 8;
		buf[1]=0x00; //No PR held
	}
	buf[0] = os_ntohl(lu->rsv.pr_generation);

	scmd_buffer_copy_data(sc, (uint8_t *)buf, len);
	os_free(buf);
	return 0;
}

/*
 * Function: stm_preserve_read_capabilities
 * Description:
 * - Service Action: Read capabilities
 */
static int stm_preserve_read_capabilities(chiscsi_target_lun *lu,
					 chiscsi_scsi_command *sc, int len)
{
	uint8_t *buf;

	if ((buf = os_alloc(8,1,1)) == NULL)
		return -1;

	buf[1] = 8;
	buf[2] = 0x11; // We support the PTPL_C and CRH 
	buf[3] = 0x1; //We support PTPL_A

	scmd_buffer_copy_data(sc, buf, 8);
	os_free(buf);
	return 0;
}

/*
 * Function: stm_persistent_reserve_in
 * Description:
 *      - Handles Persistent Reserve In
 */
static int stm_persistent_reserve_in(chiscsi_scsi_command *sc)
{
	int len;
	int rv = 0;
	scsi_cdb_prin_t	*p_prin = (scsi_cdb_prin_t *)sc->sc_cmd;
	chiscsi_target_lun *lu;

	len = (sc->sc_cmd[7] << 8) + sc->sc_cmd[8];

	/* Need to generate a CHECK CONDITION with ILLEGAL REQUEST
	 * and INVALID FIELD IN CDB (0x24/0x00) if any of the following is
	 * true.
	 *	(1) The SERVICE ACTION field is 004h - 01fh,
	 *	(2) The reserved area in byte 1 is set,
	 *	(3) The reserved area in bytes 2 thru 6 are set,
	 *	(4) If any of the reserved bits in the CONTROL byte are set.
	 */
	if ((p_prin->action >= 0x4) || p_prin->resbits || p_prin->resbytes[0] ||
	    p_prin->resbytes[1] || p_prin->resbytes[2] || p_prin->resbytes[3] ||
	    p_prin->resbytes[4] || p_prin->control)
		return -SCSI_INVALID_CDB;
	/*
	 * Information obtained from:
	 *	SPC-3, Revision 23
	 *	Section 6.11 PERSISTENCE RESERVE IN
	 * Acquire ALLOCATION LENGTH from bytes 7, 8
	 * A zero(0) length allocation is not an error and we should just
	 * acknowledge the operation.
	 */
	if ( len == 0)
		return 0;

	lu = iscsi_target_session_lun_get(sc->sc_sess, sc->sc_lun_acl);
	if (!lu)
		return -ISCSI_EINVAL;

	if (!stm_command_syntax_check(sc, stm_persistent_reserve_in_mask)) {
		switch (sc->sc_cmd[1] & 0x1f) { // service action
			case STM_SA_READ_KEYS:
				rv = stm_preserve_read_keys(lu, sc, len);
				break;
			case STM_SA_READ_RESERVATIONS:
				rv = stm_preserve_read_reservations(lu, sc);
				break;
			case STM_SA_REPORT_CAPABILITIES:
				rv = stm_preserve_read_capabilities(lu, sc, len);
				break;
			default:  // others are errors
				rv = -ISCSI_EINVAL;
				break;
		}
	}
	iscsi_target_session_lun_put(lu);
	return rv;
}

/*
 *      Persistent Reserve Out
 */

/*
 * Function: stm_preserve_register
 * Description:
 *      - Service Action: Register
 */
static int stm_preserve_register(chiscsi_target_lun *lu,
				 chiscsi_scsi_command *sc, int len, int ign)
{
	int idx,fidx;
	iscsi_session *sc_sess = sc->sc_sess;
	char *id = sc_sess->s_peer_name;
	struct  StmPreserveParameters *prm = (struct StmPreserveParameters *)
						sc->sc_sgl.sgl_vecs;
	uint64_t key = os_ntohl64(prm->reservation_key);
	uint64_t skey = os_ntohl64(prm->sa_key);
	uint32_t prt = sc_sess->s_isid[0] << 6 & 0xC0;

	/* Find active registration */
	if (key)
		idx = stm_preserve_find_registration(lu, id, key);
	else
		idx = stm_preserve_find_registration(lu, id, -1);

	if (idx == -1) {
		/* No active registration */
		fidx = stm_preserve_find_registration_free(lu);

		if (fidx == -1)
            		return 0;
		if ((!key || ign) && skey) {
			lu->rsv.pr_type=STM_RES_PERSISTENT;
			lu->rsv.pr_registrations[fidx].valid=1;
			os_strcpy(
				lu->rsv.pr_registrations[fidx].initiator_id,
				sc_sess->s_peer_name);
			lu->rsv.pr_registrations[fidx].key=skey;
			lu->rsv.pr_registrations[fidx].port=prt;

			lu->rsv.pr_generation++;
			return 0;
		} else {
			/* No more resources */
			return -SPC_ERR_REGISTRATION_RESOURCES;
		}
	} else {
		/* Registration active, change if ignore or key is correct */
		if (ign || (key == lu->rsv.pr_registrations[idx].key)) {
			 if (skey) {
			 	/* change value */
				lu->rsv.pr_registrations[idx].key = skey;
				lu->rsv.pr_registrations[idx].port = prt;
			} else {
				/* unregister */
				lu->rsv.pr_registrations[idx].valid = 0;
			}

			lu->rsv.pr_generation++;
            		return 0;
		} 
		/* What do we do here?
		 * ambiguous: second registration?
		 *  MS Cluster:  who cares - just do it
		 */
		return 0;
	} 
}

/*
 * Function: stm_preserve_reserve
 * Description:
 * - Service Action: Reserve
 */
static int stm_preserve_reserve(chiscsi_target_lun *lu,
				chiscsi_scsi_command *sc,int len)
{
	struct StmPreserveParameters *prm;
	int typ;
	uint64_t key,rkey;
	int err;
	iscsi_session *sc_sess = sc->sc_sess;

	prm =(struct StmPreserveParameters *)sc->sc_sgl.sgl_vecs;
	err = -1;

	/* Check type */
	typ = sc->sc_cmd[2] & 0x0f;
	key = os_ntohl64(prm->reservation_key);
	rkey = key;

	switch(typ) {
		case STM_TYP_WRITE_EXCLUSIVE:
		case STM_TYP_EXCLUSIVE_ACCESS:
		case STM_TYP_WRITE_REGISTRANTS:
		case STM_TYP_ACCESS_REGISTRANTS:
			break;
		case STM_TYP_WRITE_ALL:
		case STM_TYP_ACCESS_ALL:
			rkey = 0;
			break;
		default:  // others are errors
			return -1;
	}
	/* Check registration key - The key should exist here */
	if (stm_preserve_find_registration(lu, sc_sess->s_peer_name,key) == -1)
		return -SCSI_STATUS_RESERVATION_CONFLICT;
   	/* Check active reservation */
	if (lu->rsv.pr_reservation.valid) {
		/* identical reservation is okay */
		if ((os_strcmp(lu->rsv.pr_reservation.initiator_id,
				sc_sess->s_peer_name) != 0) ||
		    (key && (lu->rsv.pr_reservation.key!=key)) ||
		    (lu->rsv.pr_reservation.type!=typ))
		    	return -SCSI_STATUS_RESERVATION_CONFLICT;
	} else {
		lu->rsv.pr_reservation.valid = 1;
		os_strcpy(lu->rsv.pr_reservation.initiator_id,
			sc_sess->s_peer_name);
		lu->rsv.pr_reservation.key = rkey;
		lu->rsv.pr_reservation.type = typ;
		lu->rsv.pr_reservation.port = sc_sess->s_isid[0] & 0xC0;
		return 0;
	}
	return err;
}

/*
 * Function: stm_preserve_release
 * Description:
 * - Service Action: Release
 */
int stm_preserve_release(chiscsi_target_lun *lu, chiscsi_scsi_command *sc,
			int len)
{
	iscsi_session *sc_sess = sc->sc_sess;
	int typ;
	unsigned long long key;
	int err = 0;
	struct StmPreserveParameters *prm =(struct StmPreserveParameters *)
						sc->sc_sgl.sgl_vecs;

	/* Check type */
	typ=sc->sc_cmd[2] & 0x0f;
	switch(typ) {
		case STM_TYP_WRITE_EXCLUSIVE:
		case STM_TYP_EXCLUSIVE_ACCESS:
		case STM_TYP_WRITE_REGISTRANTS:
		case STM_TYP_ACCESS_REGISTRANTS:
		case STM_TYP_WRITE_ALL:
		case STM_TYP_ACCESS_ALL:
			break;
		default:
			return -1;
	}

	if (!err) {
		key = os_ntohl64(prm->reservation_key);
		if (stm_preserve_find_registration(lu,
					sc_sess->s_peer_name,key) == -1) {
			/* Conflict if not registered */
			return -SCSI_STATUS_RESERVATION_CONFLICT;
       		} else {
			/* Known to be registered */
			if (!lu->rsv.pr_reservation.valid) {
				 /* no reservation is not an error */
				return 0;
			} else {
				if (((!lu->rsv.pr_reservation.key) ||
		   		     (lu->rsv.pr_reservation.key==key)) &&
				    (lu->rsv.pr_reservation.type==typ)) {
					lu->rsv.pr_reservation.valid=0;
					return 0;
				} else {
					return -SCSI_RELEASE_INVALID;
				}
			}
		}
	}
	return -1;
}

/*
 * Function: stm_preserve_clear
 * Description:
 * - Service Action: Clear
 */
int stm_preserve_clear(chiscsi_target_lun *lu, chiscsi_scsi_command *sc,
			int len)
{
	struct StmPreserveParameters *prm;
	iscsi_session *sc_sess = sc->sc_sess;
	uint64_t key;
	int j;

	prm = (struct StmPreserveParameters *)sc->sc_sgl.sgl_vecs;
	/* Check registration key */
	key = os_ntohl64(prm->reservation_key);
	if (stm_preserve_find_registration(lu,sc_sess->s_peer_name,key)==-1)
		return -SCSI_STATUS_RESERVATION_CONFLICT;

	for (j = 0; j < STM_PRESERVE_REGISTRATION_MAX; j++)
		lu->rsv.pr_registrations[j].valid = 0;

	lu->rsv.pr_reservation.valid = 0;
	lu->rsv.pr_generation++;
	return 0; 
}

/*
 * Function: stm_preserve_preempt
 * Description:
 * - Service Action: preempt
 */
static int stm_preserve_preempt(chiscsi_target_lun *lu,
				chiscsi_scsi_command *sc,int len, int abt)
{
	iscsi_session *sc_sess = sc->sc_sess;
	int typ;
	unsigned long long key,skey,rkey;
	int err = 0;
	int idx;
	struct StmPreserveParameters *prm =
			(struct StmPreserveParameters *)sc->sc_sgl.sgl_vecs;

	/* Check type */
	typ = sc->sc_cmd[2] & 0x0f;
	key = os_ntohl64(prm->reservation_key);
	skey = os_ntohl64(prm->sa_key);
	rkey = key;

	switch(typ) {
		case STM_TYP_WRITE_EXCLUSIVE:
		case STM_TYP_EXCLUSIVE_ACCESS:
		case STM_TYP_WRITE_REGISTRANTS:
		case STM_TYP_ACCESS_REGISTRANTS:
			break;
		case STM_TYP_WRITE_ALL:
		case STM_TYP_ACCESS_ALL:
			rkey = 0;
			break;
		default:
			return -1;
			break;
	}

	if (!err) {
		if ((stm_preserve_find_registration(lu, sc_sess->s_peer_name,
						key)==-1) || !skey) {
			/*  Conflict if not registered */
			return -SCSI_STATUS_RESERVATION_CONFLICT;

		} else {
			/*  Known to be registered */
			if (!lu->rsv.pr_reservation.valid ||
			    (lu->rsv.pr_reservation.key &&
			     lu->rsv.pr_reservation.key!=skey)) {

				/* No reservation or not key
				 * registrations preempted */
				for (idx = 0;
				     idx < STM_PRESERVE_REGISTRATION_MAX;
				     idx++) {
					if (lu->rsv.pr_registrations[idx].key
						== skey)
						lu->rsv.pr_registrations[idx].valid = 0;
				}

			} else {
				/* Preempt reservation and registrations */
				for (idx = 0;
				     idx < STM_PRESERVE_REGISTRATION_MAX;
				     idx++) {
					if (lu->rsv.pr_registrations[idx].key
						== skey) {
						lu->rsv.pr_registrations[idx].valid=0;
						/* Abort tasks if necessary */
						if (abt)
							scmd_fscsi_set_bit(sc, CH_SFSCSI_EXECUTED_BIT);
					}
				}

				lu->rsv.pr_reservation.valid=1;
				lu->rsv.pr_reservation.key=rkey;
				lu->rsv.pr_reservation.type=typ;
				os_strcpy(lu->rsv.pr_reservation.initiator_id,
					sc_sess->s_peer_name);
				lu->rsv.pr_reservation.port= sc_sess->s_isid[0] & 0xC0;
			}
			return 0;
		}
	}
	return 0;
}

/*
 * Function: stm_persistent_reserve_check
 * Description:
 * - Verifies persistent reservations
 * - returns -1 if reservation conflict
 * - returns 0 if okay
 */
int stm_persistent_reserve_check(chiscsi_scsi_command *sc,
				chiscsi_target_lun *lu)
{
	int cft = 0;
	int reg;
	int typ;
	iscsi_session *sc_sess = sc->sc_sess;

	if (!lu->rsv.pr_reservation.valid)
		return 0;

	typ=lu->rsv.pr_reservation.type;
	reg = stm_preserve_check_registration(lu,sc_sess->s_peer_name);

	switch (sc->sc_cmd[0]) {
		case SCSI_OPCODE_WRITE_6:
		case SCSI_OPCODE_WRITE_10:
		case SCSI_OPCODE_WRITE_N_VERIFY_10:
		switch (typ) {
               		case STM_TYP_WRITE_EXCLUSIVE:
               		case STM_TYP_EXCLUSIVE_ACCESS  :
                  		/* Conflict on exclusive reservation if request
				 * is not from holder */
				if (os_strcmp(lu->rsv.pr_reservation.initiator_id,
						sc_sess->s_peer_name) != 0)
					cft=1;
				break;
			case STM_TYP_WRITE_REGISTRANTS:
			case STM_TYP_ACCESS_REGISTRANTS:
			case STM_TYP_WRITE_ALL:
			case STM_TYP_ACCESS_ALL:
				/* Conflict on other reservations if initiator
				 * is not registered */
				if (!reg)
					cft=1;
				break;
			default:
				break;
			}
			break;
		case SCSI_OPCODE_FORMAT_UNIT:
		case SCSI_OPCODE_READ_6:
		case SCSI_OPCODE_READ_10:
		case SCSI_OPCODE_READ_CAPACITY_10:
		case SCSI_OPCODE_SEEK_10:
		case SCSI_OPCODE_START_STOP_UNIT:
		case SCSI_OPCODE_SYNCHRONIZE_CACHE_10:
		case SCSI_OPCODE_TEST_UNIT_READY:
		case SCSI_OPCODE_VERIFY_10:
		switch (typ) {
			case STM_TYP_EXCLUSIVE_ACCESS:
				if (os_strcmp(lu->rsv.pr_reservation.initiator_id,
						sc_sess->s_peer_name) != 0)
					cft=1;
				break;
			case STM_TYP_ACCESS_REGISTRANTS:
			case STM_TYP_ACCESS_ALL:
				 /* Always conflict if not registered. */
				if (!reg)
					cft=1;
				break;
			default:
				break;
			}
			break;
		default:
			break;
	}
	return cft;
}

int stm_command_reservation_check(chiscsi_scsi_command *sc,
				chiscsi_target_lun *lu)
{
	int ret = 0;
	int cft = 0;

	switch (lu->rsv.pr_type) {
		case STM_RES_NONE:
			break;
		case STM_RES_STANDARD:
			switch (sc->sc_cmd[0]) {
				case SCSI_OPCODE_PERSISTENT_RESERVE_IN:
				case SCSI_OPCODE_PERSISTENT_RESERVE_OUT:
				case SCSI_OPCODE_RESERVE_6:
				case SCSI_OPCODE_RESERVE_10:
					cft = 1;
					break;
				case SCSI_OPCODE_RELEASE_6:
				case SCSI_OPCODE_RELEASE_10:
					cft = 0;  // good status
					break;
				default:
					cft = 1;
					break;
			}
			break;
		case STM_RES_PERSISTENT:
			switch (sc->sc_cmd[0]) {
				case SCSI_OPCODE_RESERVE_6:
				case SCSI_OPCODE_RESERVE_10:
				case SCSI_OPCODE_RELEASE_6:
				case SCSI_OPCODE_RELEASE_10:
					cft = 1;
					break;
				default:
					cft = stm_persistent_reserve_check(sc,
									lu);
					break;
			}
			break;
		default:
			break;
	}

	if (cft == 0) // good status
		ret = 0;
	if (cft == 1) // reservation conflict
		ret = 1;
	return ret;
}

static void spc_pr_erase(chiscsi_target_lun *lu)
{
        if (lu->aptpl_fhndl)
                os_file_unlink((void *)lu->aptpl_fhndl);
}

/*
 * []----
 * | spc_pr_write -
 * |    Write keys and reservations for this device to backend storage.
 * []----
 */
static int spc_pr_write(chiscsi_target_lun *lu)
{
        int length;
        char path[MAXPATHLEN];
        int status = -1;

        /*
         * Verify space requirements and allocate buffer memory.
         */
        memset(path, '\0', MAXPATHLEN);
        sprintf(path, "%s/%d","/etc/chelsio-iscsi/prdb", lu->lun);
	lu->aptpl_fhndl = (unsigned long)os_file_open(path, O_WRONLY|O_CREAT, 0600);
        if (lu->aptpl_fhndl) {
                length = os_file_write((void *)lu->aptpl_fhndl,
					(char *)&lu->rsv,
					sizeof(struct reservation), 0);
                os_file_close((void *)lu->aptpl_fhndl);
		if (length == sizeof(struct reservation))
			status = 0;
        }

        return status;
}

/*
 * Function: stm_persistent_reserve_out
 * Description:
 *      - Handles Persistent Reserve Out
 */
static int stm_persistent_reserve_out(chiscsi_scsi_command *sc)
{
	int len;
	int rv = -1;
	int status = 0;
	scsi_cdb_prout_t *p_prout = (scsi_cdb_prout_t *)sc->sc_cmd;
	scsi_prout_plist_t *plist = (scsi_prout_plist_t *)sc->sc_sgl.sgl_vecs; 
	chiscsi_target_lun *lu;

	len = (sc->sc_cmd[7] << 8) + sc->sc_cmd[8];

	/* Need to generate a CHECK CONDITION with ILLEGAL REQUEST and INVALID
	 * FIELD IN CDB (0x24/0x00) if any of the following is true.
	 * (1) The SERVICE ACTION field is 008h - 01fh,
	 * (2) The reserved area in byte 1 is set,
	 * (3) The TYPE and SCOPE fields are invalid,
	 * (4) The reserved area in bytes 3 and 4 are set,
	 * (5) If any of the reserved bits in the CONTROL byte are set.
	 */

	if ((p_prout->action >= 0x8) || p_prout->resbits ||
	    (p_prout->type >= 0x9) || (p_prout->scope >= 0x3) ||
	    p_prout->control)
		return -SCSI_INVALID_CDB;

	/* Parameter list length shall contain 24 (0x18), the SPEC_I_PIT is
	 * zero (it is because we don't support SIP_C)) the service action is
	 * not REGISTER AND MOVE
	 */
	if ((p_prout->action != STM_SA_REGISTER_MOVE) && (len != 24))
		return -SCSI_PARAM_LIST_ERROR;

	/* SCOPE field shall always be set to LU_SCOPE */
	if (p_prout->scope != PR_LU_SCOPE)
		return -SCSI_INVALID_CDB;

	if (stm_command_syntax_check(sc, stm_persistent_reserve_out_mask))
		return -SCSI_INVALID_CDB;
	
	rv = -ISCSI_EINVAL;
	lu = iscsi_target_session_lun_get(sc->sc_sess, sc->sc_lun_acl);
	if (!lu)
		return rv;
	switch(sc->sc_cmd[1] & 0x1f) { // service action
		case STM_SA_REGISTER:
			rv = stm_preserve_register(lu,sc,len,0);
			break;
		case STM_SA_RESERVE:
			rv = stm_preserve_reserve(lu,sc,len);
			break;
		case STM_SA_RELEASE:
			rv = stm_preserve_release(lu,sc,len);
			break;
		case STM_SA_CLEAR:
			rv = stm_preserve_clear(lu,sc,len);
			break;
		case STM_SA_PREEMPT:
			rv = stm_preserve_preempt(lu,sc,len,0);
			break;
		case STM_SA_PREEMPT_ABORT:
			rv = stm_preserve_preempt(lu,sc,len,1);
			break;
		case STM_SA_REGISTER_IGNORE:
			rv = stm_preserve_register(lu,sc,len,1);
			break;
		case STM_SA_REGISTER_MOVE: //Not yet implemented
			rv = 0;
			break;
		default:  // others are errors
			rv = -ISCSI_EINVAL;
			break;
	}
	if (rv < 0)
		goto done;

	/* If Activate Persist Through Power Loss (APTPL) is set, persist
	 * this PGR data on disk
	 */
	if ((lu->aptpl == SPC_APTPL_UNSUPPORTED) && 
	    (((sc->sc_cmd[1] & 0x1f) == STM_SA_REGISTER) ||
	     ((sc->sc_cmd[1] & 0x1f) == STM_SA_REGISTER_IGNORE))) {
		goto done;
	} else if ((((sc->sc_cmd[1] & 0x1f) == STM_SA_REGISTER) ||
		 ((sc->sc_cmd[1] & 0x1f) == STM_SA_REGISTER_IGNORE)) &&
		 plist->aptpl) {
		os_log_info("%s \n","Persisting Writes to Disk");
		lu->aptpl = SPC_APTPL_ON;
	} else if (((sc->sc_cmd[1] & 0x1f) == STM_SA_REGISTER) ||
		   ((sc->sc_cmd[1] & 0x1f) == STM_SA_REGISTER_IGNORE)) {
		os_log_info("%s\n","Next power cycle will erase PR");
		lu->aptpl = SPC_APTPL_NEED_TO_ERASE; // Need to erase
	}

	switch(lu->aptpl) {
		case SPC_APTPL_OFF:
			break;
		case SPC_APTPL_NEED_TO_ERASE:
			spc_pr_erase(lu);
			break;
		case SPC_APTPL_ON:
			 status = spc_pr_write(lu);
			break;
		default:
			break;
	}

	if( status < 0)
		lu->aptpl = SPC_APTPL_UNSUPPORTED;

done:
	iscsi_target_session_lun_put(lu);
	return rv;
}


/*
 *      Persistent Reservation checks
 */
static int stm_preserve_check_registration(chiscsi_target_lun *lu, char *iid)
{
	int fnd = 0;
	int idx = 0;

	while (!fnd && (idx<STM_PRESERVE_REGISTRATION_MAX)) {
		if (lu->rsv.pr_registrations[idx].valid &&
		    !os_strcmp(lu->rsv.pr_registrations[idx].initiator_id,iid))
			fnd=1;
		else
			idx++;
	}

	return fnd;
}

int stm_report_alias(chiscsi_scsi_command *sc)
{

	uint32_t len, total_len,ent,nx,siz=0;
	uint8_t        *bfr;	
	struct StmAliasEntry  *entry;
	iscsi_session *sess = sc->sc_sess;
	iscsi_node *node = sess->s_node;

	if (stm_command_syntax_check(sc, stm_report_alias_mask))
		return -SCSI_INVALID_CDB;

	len = sc->sc_cmd[6];
	len = (len << 8) + sc->sc_cmd[6];
	len = (len << 8) + sc->sc_cmd[7];
	len = (len << 8) + sc->sc_cmd[8];
	len = (len << 8) + sc->sc_cmd[9];

	nx = os_strlen(node->n_alias);

	total_len = 8+16+nx;
	
	if ((bfr = os_alloc(total_len,1,1)) == NULL) {
		/*
		 * Lack of memory is not fatal, just too busy
		 */
		return -1;
	}
	
	siz = 8;
	ent = 0;
	
	entry = (struct StmAliasEntry *) & bfr[siz];
	
	entry->alias = (uint64_t)((uint64_t)1<<32) + *(node->n_alias);
	entry->protocol_id = 5;
	entry->format_code = 0;

	os_strcpy((char *)entry->designation, node->n_alias);

	STM_ALIAS_PAD_SIZE(nx);
	entry->designation_length = os_ntohs(nx);

	siz += 16 + nx;
	ent++;

	bfr[0] = (uint8_t) ((siz - 4) >> 24);
	bfr[1] = (uint8_t) ((siz - 4) >> 16);
	bfr[2] = (uint8_t) ((siz - 4) >> 8);
	bfr[3] = (uint8_t) (siz - 4);

	bfr[6] = (uint8_t) (ent << 8);
	bfr[7] = (uint8_t) ent;

	scmd_buffer_copy_data(sc,bfr,siz);
	os_free(bfr);

	return 0;
}

int it_chelsio_target_check_opcode(chiscsi_scsi_command *sc)
{
	unsigned char opcode = sc->sc_cmd[0];
	iscsi_session *sess = sc->sc_sess;
	iscsi_node *node = sess->s_node;

	if (node->lu_list[sc->sc_lun_acl] == NULL)
		return 0;
	if (chiscsi_target_lun_flag_test(node->lu_list[sc->sc_lun_acl],
				 LUN_PASSTHRU_ALL_BIT)) {
		sc->sc_flag |= SC_FLAG_PASSTHRU;
		return 0;
	}

	if (SCSI_RWIO_6_CMD(opcode)) {
		scmd_fpriv_set_bit(sc, CH_SFP_RWIO_BIT);
		cdb_6_decode(sc->sc_cmd, sc->sc_lba, sc->sc_blk_cnt);
	} else if (SCSI_RWIO_10_CMD(opcode)) {
		scmd_fpriv_set_bit(sc, CH_SFP_RWIO_BIT);
		cdb_10_decode(sc->sc_cmd, sc->sc_lba, sc->sc_blk_cnt);
	} else if (SCSI_RWIO_12_CMD(opcode)) {
		scmd_fpriv_set_bit(sc, CH_SFP_RWIO_BIT);
		cdb_12_decode(sc->sc_cmd, sc->sc_lba, sc->sc_blk_cnt);
	} else if (SCSI_RWIO_16_CMD(opcode)) {
		scmd_fpriv_set_bit(sc, CH_SFP_RWIO_BIT);
		cdb_16_decode(sc->sc_cmd, sc->sc_lba, sc->sc_blk_cnt);
	} else if (opcode != SCSI_OPCODE_INQUIRY &&
		opcode != SCSI_OPCODE_REPORT_LUNS &&
		opcode != SCSI_OPCODE_READ_CAPACITY_10 &&
		opcode != SCSI_OPCODE_MODE_SENSE_6 &&
		opcode != SCSI_OPCODE_REQUEST_SENSE &&
		opcode != SCSI_OPCODE_SERVICE_ACTION_IN_16 &&
		opcode != SCSI_OPCODE_START_STOP_UNIT &&
		opcode != SCSI_OPCODE_TEST_UNIT_READY &&
		opcode != SCSI_OPCODE_RESERVE_6 &&
		opcode != SCSI_OPCODE_RESERVE_10 &&
		opcode != SCSI_OPCODE_RELEASE_6 &&
		opcode != SCSI_OPCODE_RELEASE_10 &&
		opcode != SCSI_OPCODE_PERSISTENT_RESERVE_IN &&
		opcode != SCSI_OPCODE_PERSISTENT_RESERVE_OUT &&
		opcode != SCSI_OPCODE_MAINTENANCE_IN) {
		/* unsupported opcode */

		if (sc->sc_flag & SC_FLAG_LUN_OOR) {
			os_log_info("itt 0x%x: op 0x%x, lun %d/%d OOR.\n",
				sc->sc_itt, opcode, sc->sc_lun, sc->sc_lun_acl);
			sc_unsupported_cmd(sc, opcode);
		}

		if (chiscsi_target_lun_flag_test(node->lu_list[sc->sc_lun_acl],
					 LUN_PASSTHRU_UNKNOWN_ONLY_BIT)) {
			os_log_info("itt 0x%x: op 0x%x, lun %d/%d, passthru.\n",

				sc->sc_itt, opcode, sc->sc_lun, sc->sc_lun_acl);
			sc->sc_flag |= SC_FLAG_PASSTHRU;
		} else {
			os_log_info("itt 0x%x: op 0x%x unsupported, lun %d/%d.\n",
				sc->sc_itt, opcode, sc->sc_lun, sc->sc_lun_acl);
			sc_unsupported_cmd(sc, opcode);
		}
	}
	if (scmd_fpriv_test_bit(sc, CH_SFP_RWIO_BIT) &&
	    SCSI_RWIO_PROTECT_EN(sc->sc_cmd))
		scmd_fpriv_set_bit(sc, CH_SFP_PROT_BIT);
	return 0;
}

int iscsi_target_lu_scsi_non_rwio_cmd_respond(chiscsi_scsi_command *sc)
{
	iscsi_session *sess = sc->sc_sess;
	unsigned char opcode = sc->sc_cmd[0];
	int rv = 0;

	/* no need to wait for backend in this case */
	chiscsi_scsi_cmd_ready_to_release(sc);

	switch (opcode) {
		case SCSI_OPCODE_INQUIRY:
			/* mandatory, ignore unit attention */
			rv = lun_inquiry(sc, sc->sc_cmd);
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
	       //case SCSI_OPCODE_MODE_SENSE_10:
		//	rv = lun_mode_sense(lu, sc, sc->sc_cmd, 0, 10);
		//	break;
			//case SCSI_OPCODE_MODE_SELECT_6:
			//case SCSI_OPCODE_MODE_SELECT_10:
		case SCSI_OPCODE_REQUEST_SENSE:	/* mandatory, ignore unit attention */
			rv = lun_request_sense(sc, sc->sc_cmd);
			break;
		case SCSI_OPCODE_SERVICE_ACTION_IN_16:
			rv = lun_service_action_in(sc, sc->sc_cmd);
			break;
		case SCSI_OPCODE_START_STOP_UNIT:
		case SCSI_OPCODE_TEST_UNIT_READY:
			//case SCSI_OPCODE_SEND_DIAGNOSTIC:
			break;
		case SCSI_OPCODE_RESERVE_6:
		case SCSI_OPCODE_RESERVE_10:
		{
			chiscsi_target_lun *lu = iscsi_target_session_lun_get(
				sc->sc_sess, sc->sc_lun_acl);
			if (lu) {
				os_lock_irq_os_data(lu->os_data);
				lu->rsv.pr_type = STM_RES_STANDARD;
				chiscsi_target_lun_flag_set(lu, LUN_RESERVED_BIT);
				lu->rsv.rsvd_sess_hndl = (unsigned long)sess;
				os_unlock_irq_os_data(lu->os_data);
				iscsi_target_session_lun_put(lu);
				sc->sc_state = CH_SC_STATE_STATUS;
			} else {
				rv = -ISCSI_EINVAL;
			}
			break;
		}
		case SCSI_OPCODE_RELEASE_6:
		case SCSI_OPCODE_RELEASE_10:
			iscsi_target_lu_reserve_clear_by_session(sess);
			sc->sc_state = CH_SC_STATE_STATUS;
			break;

		case SCSI_OPCODE_PERSISTENT_RESERVE_IN :
			rv = stm_persistent_reserve_in(sc);
			sc->sc_state = CH_SC_STATE_STATUS;
			break;
		case SCSI_OPCODE_PERSISTENT_RESERVE_OUT:
			rv = stm_persistent_reserve_out(sc);
			sc->sc_state = CH_SC_STATE_STATUS;
			break;

		case SCSI_OPCODE_MAINTENANCE_IN:
			switch (sc->sc_cmd[1] & 0x1f)
			{
				case SCSI_REPORT_ALIAS:
					rv = stm_report_alias(sc);
					break;
				case SCSI_REPORT_TARGET_PORT_GROUPS:
					//stm_report_target_port_groups(cmd);
					break;
				default:
					break;
			}
			break;

		default:
			sc_unsupported_cmd(sc, opcode);
			rv = 0;
			break;
	}

#ifndef __TARGET_LU_NO_UNDER_FLOW__
	if (rv > 0) 
		scmd_calc_residualcount(sc, rv);
#endif
	if(rv == 0)
		return 0;

 	if(rv == -SPC_ASC_INVALID_FIELD_IN_PARAMETER_LIST)
		sc_invalid_field_in_param_list(sc);		
	else if(rv == -SPC_ERR_REGISTRATION_RESOURCES)
		sc_err_registration_resources(sc);
	else if(rv == -SPC_ERR_DATA_PHASE)
		sc_err_data_phase(sc);
	else if(rv == -SCSI_PARAM_LIST_ERROR)
		sc_param_list_error(sc);
	else if(rv == -SCSI_STATUS_RESERVATION_CONFLICT)
		sc_reservation_conflict(sc);
	else if(rv == -SCSI_RELEASE_INVALID)
		sc_release_invalid(sc);
	else if (rv < 0)// SPC_ASC_INVALID_CDB
		sc_invalid_cdb_field(sc);

	return 0;
}
