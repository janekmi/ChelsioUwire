#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <platdef.h>
#include <t4_regs.h>
#include <t4_chip_type.h>
#include <cudbg_if.h>
#include <cudbg_view.h>
#include <t4fw_interface.h>
#include <common.h>
#include <t4_hw.h>
#include <cudbg_view_entity.h>

extern struct reg_info t6_sge_regs[];
extern struct reg_info t6_pcie_regs[];
extern struct reg_info t6_dbg_regs[];
extern struct reg_info t6_ma_regs[];
extern struct reg_info t6_cim_regs[];
extern struct reg_info t6_tp_regs[];
extern struct reg_info t6_ulp_tx_regs[];
extern struct reg_info t6_pm_rx_regs[];
extern struct reg_info t6_pm_tx_regs[];
extern struct reg_info t6_mps_regs[];
extern struct reg_info t6_cpl_switch_regs[];
extern struct reg_info t6_smb_regs[];
extern struct reg_info t6_i2cm_regs[];
extern struct reg_info t6_mi_regs[];
extern struct reg_info t6_uart_regs[];
extern struct reg_info t6_pmu_regs[];
extern struct reg_info t6_ulp_rx_regs[];
extern struct reg_info t6_sf_regs[];
extern struct reg_info t6_pl_regs[];
extern struct reg_info t6_le_regs[];
extern struct reg_info t6_ncsi_regs[];
extern struct reg_info t6_mac_regs[];
extern struct reg_info t6_mc_0_regs[];
extern struct reg_info t6_edc_t60_regs[];
extern struct reg_info t6_edc_t61_regs[];
extern struct reg_info t6_hma_t6_regs[];

extern struct reg_info t5_sge_regs[];
extern struct reg_info t5_pcie_regs[];
extern struct reg_info t5_dbg_regs[];
extern struct reg_info t5_ma_regs[];
extern struct reg_info t5_cim_regs[];
extern struct reg_info t5_tp_regs[];
extern struct reg_info t5_ulp_tx_regs[];
extern struct reg_info t5_pm_rx_regs[];
extern struct reg_info t5_pm_tx_regs[];
extern struct reg_info t5_mps_regs[];
extern struct reg_info t5_cpl_switch_regs[];
extern struct reg_info t5_smb_regs[];
extern struct reg_info t5_i2cm_regs[];
extern struct reg_info t5_mi_regs[];
extern struct reg_info t5_uart_regs[];
extern struct reg_info t5_pmu_regs[];
extern struct reg_info t5_ulp_rx_regs[];
extern struct reg_info t5_sf_regs[];
extern struct reg_info t5_pl_regs[];
extern struct reg_info t5_le_regs[];
extern struct reg_info t5_ncsi_regs[];
extern struct reg_info t5_mac_regs[];
extern struct reg_info t5_mc_0_regs[];
extern struct reg_info t5_mc_1_regs[];
extern struct reg_info t5_edc_t50_regs[];
extern struct reg_info t5_edc_t51_regs[];
extern struct reg_info t5_hma_t5_regs[];

#if defined(WIN32) || defined(__NT__) || defined(_WIN32) || defined(__WIN32__)
#else
#include <adap_util.h>
#include <reg_defs_t5.c>
#include <reg_defs_t6.c>
#endif 

#include <time.h>
#include <stdarg.h>
#include <cudbg_entity.h>
#include <cudbg_lib_common.h>

#define  cudbg_printf(cudbg_poutbuf, err_label, format, ...) \
	do { \
		if (cudbg_poutbuf->data) {\
			rc = snprintf(cudbg_poutbuf->data + \
				      cudbg_poutbuf->offset,\
				      cudbg_poutbuf->size -\
				      cudbg_poutbuf->offset, format, \
				      ##__VA_ARGS__);\
			if (cudbg_poutbuf->offset + rc >= \
			    cudbg_poutbuf->size - 1) {\
				cudbg_poutbuf->size = rc = \
				CUDBG_STATUS_OUTBUFF_OVERFLOW;\
				goto err_label; \
			} \
		cudbg_poutbuf->offset += rc;\
		} else {\
			rc = printf(format, ##__VA_ARGS__);\
		} \
	} while (0)

/* Format a value in a unit that differs from the
 * value's native unit by the
 * given factor.
 */
static void unit_conv(char *buf, size_t len, unsigned int val,
		      unsigned int factor)
{
	unsigned int rem = val % factor;

	if (rem == 0)
		snprintf(buf, len, "%u", val / factor);
	else {
		while (rem % 10 == 0)
			rem /= 10;
		snprintf(buf, len, "%u.%u", val / factor, rem);
	}
}

int validate_next_rec_offset(void *pinbuf, u32 inbuf_size, u32
			     next_rec_offset)
{
	struct cudbg_hdr *cudbg_hdr;

	if (inbuf_size <= next_rec_offset)
		return 0;

	cudbg_hdr = (struct cudbg_hdr *)((char *)pinbuf + next_rec_offset);
	if ((cudbg_hdr->signature != CUDBG_SIGNATURE) &&
	    (cudbg_hdr->signature != CUDBG_LEGACY_SIGNATURE))
		return 0; /* no next rec */

	return next_rec_offset;
}

int view_ext_entity(char *pinbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		    enum chip_type chip)
{
	struct cudbg_entity_hdr *entity_hdr = NULL;
	u32 next_ext_offset = 0;
	u32 entity_type;
	u32 total_size = 0;
	int rc = 0;

	entity_hdr = (struct cudbg_entity_hdr *)pinbuf;

	while ((entity_hdr->flag & CUDBG_EXT_DATA_VALID)
		&& (total_size < size)) {
		entity_type = entity_hdr->entity_type;
		if (entity_hdr->sys_warn)
			printf("Entity warning: Type %s , %d\n",
			       entity_list[entity_type].name,
			       entity_hdr->sys_warn);

		if (entity_hdr->hdr_flags) {
			printf("Entity error: Type %s, %s\n",
			       entity_list[entity_type].name,
			       err_msg[-entity_hdr->hdr_flags]);
			if (entity_hdr->sys_err)
				printf("System error  %d\n",
				       entity_hdr->sys_err);

			next_ext_offset = entity_hdr->next_ext_offset;
			continue;
		}
		if (entity_hdr->size > 0) {
			total_size += entity_hdr->size +
					sizeof(struct cudbg_entity_hdr);

			/* Remove padding bytes, if any */
			if (entity_hdr->num_pad)
				entity_hdr->size =
					entity_hdr->size -
					entity_hdr->num_pad;

			rc = view_entity[entity_type - 1]
				(pinbuf +
				 entity_hdr->start_offset,
				 entity_hdr->size,
				 cudbg_poutbuf,
				 chip);

			if (rc < 0)
				goto out;
		}
		next_ext_offset = entity_hdr->next_ext_offset;
		entity_hdr = (struct cudbg_entity_hdr *)(pinbuf
			      + next_ext_offset);
	}

	if (total_size != size)
		printf("Entity warning: Extended entity size mismatch\n");

out:
	return rc;
}

int cudbg_view(void *handle, void *pinbuf, u32 inbuf_size,
	       void *poutbuf, u32 *poutbuf_size)
{

	struct cudbg_flash_hdr *cudbg_flash_hdr;
	struct cudbg_entity_hdr *entity_hdr;
	struct cudbg_hdr *tmp_hdr;
	u32 next_rec_offset = 0;
	int rc = 0;
	int index, bit, all;
	int count = 0;
	u32 offset, max_entities, i;
	struct cudbg_buffer cudbg_poutbuf = {0};
	static int flash_info_banner;

	u8 *dbg_bitmap = ((struct cudbg_private	*)handle)->dbg_init.dbg_bitmap;
	u32 info = ((struct cudbg_private *)handle)->dbg_init.info;

	if (inbuf_size < (sizeof(struct cudbg_entity_hdr) +
			  sizeof(struct cudbg_hdr))) {
		printf("\n\tInvalid cudbg dump file\n");
		return CUDBG_STATUS_NO_SIGNATURE;
	}

	/* check for optional flash header */
	cudbg_flash_hdr = (struct cudbg_flash_hdr *)pinbuf;

	if ((cudbg_flash_hdr->signature == CUDBG_FL_SIGNATURE)) {
		if (!flash_info_banner) {
			printf("/***************Flash Header information***************/\n");
			printf("Flash signature: %c%c%c%c\n",
			       (cudbg_flash_hdr->signature  >> 24) & 0xFF,
			       (cudbg_flash_hdr->signature  >> 16) & 0xFF,
			       (cudbg_flash_hdr->signature  >> 8) & 0xFF,
			       cudbg_flash_hdr->signature & 0xFF);

			printf("Flash payload timestamp (GMT): %s",
			       asctime(gmtime((time_t *) &
				       cudbg_flash_hdr->timestamp)));
			printf("Flash payload size: %u bytes\n",
			       cudbg_flash_hdr->data_len);
			printf("/******************************************************/\n\n");
		}

		/* skip flash header */
		pinbuf = (u8 *)pinbuf + cudbg_flash_hdr->hdr_len;
		next_rec_offset += cudbg_flash_hdr->hdr_len;
		flash_info_banner = 1;
	}

	tmp_hdr  = (struct cudbg_hdr *)pinbuf;
	if ((tmp_hdr->signature != CUDBG_SIGNATURE) &&
	    (tmp_hdr->signature != CUDBG_LEGACY_SIGNATURE)) {
		printf("\n\tInvalid cudbg dump file\n");
		return CUDBG_STATUS_NO_SIGNATURE;
	}

	if ((tmp_hdr->major_ver != CUDBG_MAJOR_VERSION) ||
	    (tmp_hdr->minor_ver != CUDBG_MINOR_VERSION)) {
		printf("\n\tMeta data version mismatch\n");
		printf("\tMeta data version expected %d.%d\n",
		       CUDBG_MAJOR_VERSION, CUDBG_MINOR_VERSION);
		printf("\tMeta data version in dump %d.%d\n",
		       tmp_hdr->major_ver, tmp_hdr->minor_ver);
		return CUDBG_METADATA_VERSION_MISMATCH;
	}

	next_rec_offset += tmp_hdr->data_len;
	offset = tmp_hdr->hdr_len;
	all = dbg_bitmap[0] & (1 << CUDBG_ALL);
	max_entities = min(tmp_hdr->max_entities, CUDBG_MAX_ENTITY);

	for (i = 1; i < max_entities; i++) {
		index = i / 8;
		bit = i % 8;

		if (all || (dbg_bitmap[index] & (1 << bit))) {
			entity_hdr =
				(struct cudbg_entity_hdr *)((char *)pinbuf + offset);

			if (entity_hdr->sys_warn)
				printf("Entity warning: Type %s , %d\n",
				       entity_list[i].name,
				       entity_hdr->sys_warn);

			if (entity_hdr->hdr_flags) {
				offset += sizeof(struct cudbg_entity_hdr);
				printf("Entity error: Type %s, %s\n",
				       entity_list[i].name,
				       err_msg[-entity_hdr->hdr_flags]);
				if (entity_hdr->sys_err)
					printf("System error  %d\n",
					       entity_hdr->sys_err);

				if (poutbuf)
					*poutbuf_size = 0;

				continue;
			}
			memset(&cudbg_poutbuf, 0, sizeof(cudbg_poutbuf));
			if (entity_hdr->size > 0) {
				if (poutbuf) {
					cudbg_poutbuf.data = poutbuf;
					cudbg_poutbuf.size = *poutbuf_size;
					cudbg_poutbuf.offset = 0;
				}

				if (info)
					printf("%-20s compressed size %u\n",
					       entity_list[i].name,
					       entity_hdr->size);
				else {
					if (entity_hdr->entity_type !=
					    CUDBG_EXT_ENTITY)
						printf("%s() dbg entity : %s\n",
						       __func__,
						       entity_list[i].name);
					/* Remove padding bytes, if any */
					if (entity_hdr->num_pad)
						entity_hdr->size =
							entity_hdr->size -
							entity_hdr->num_pad;

					rc = view_entity[i-1]
						((char *)pinbuf +
						 entity_hdr->start_offset,
						 entity_hdr->size,
						 &cudbg_poutbuf,
						 tmp_hdr->chip_ver);

					count++;
				}
			} else if (!all && i !=
				   CUDBG_EXT_ENTITY) {
				printf("%s() dbg entity : %s\n",
				       __func__, entity_list[i].name);
				printf("\t%s not available\n",
				       entity_list[i].name);
			}
			if (rc < 0)
				goto out;
		}
		offset += sizeof(struct cudbg_entity_hdr);
	}

	if (poutbuf) {
		if (!count)
			*poutbuf_size = 0;
		else
			*poutbuf_size = cudbg_poutbuf.size;
	}

	return validate_next_rec_offset(pinbuf, inbuf_size, next_rec_offset);

out:
	if (poutbuf)
		*poutbuf_size = cudbg_poutbuf.size;
	return rc;
}

int view_cim_q(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	u32 *pdata = NULL;
	int rc;
	u32 i;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	pdata = (u32 *)dc_buff.data;

	for (i = 0; i < dc_buff.offset / 4; i += 4) {
		cudbg_printf(cudbg_poutbuf, err1, "%#06x: %08x %08x %08x "\
			     "%08x\n", i * 4,
			     pdata[i + 0], pdata[i + 1],
			     pdata[i + 2], pdata[i + 3]);
	}

err1:
	free(dc_buff.data);
err:
	return rc;
}

int view_cim_obq_ulp0(char *pbuf, u32 size,
		      struct cudbg_buffer *cudbg_poutbuf,
		      enum chip_type chip)
{
	int rc;

	rc = view_cim_q(pbuf, size, cudbg_poutbuf);
	return rc;
}

int view_cim_obq_ulp1(char *pbuf, u32 size,
		      struct cudbg_buffer *cudbg_poutbuf,
		      enum chip_type chip)
{
	int rc;

	rc = view_cim_q(pbuf, size, cudbg_poutbuf);
	return rc;
}

int view_cim_obq_ulp2(char *pbuf, u32 size, struct cudbg_buffer
		      *cudbg_poutbuf, enum chip_type chip)
{
	int rc;

	rc = view_cim_q(pbuf, size, cudbg_poutbuf);
	return rc;
}

int view_cim_obq_ulp3(char *pbuf, u32 size, struct cudbg_buffer
		      *cudbg_poutbuf, enum chip_type chip)
{
	int rc;
	rc = view_cim_q(pbuf, size, cudbg_poutbuf);
	return rc;
}

int view_cim_obq_sge(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		     enum chip_type chip)
{
	int rc;
	rc = view_cim_q(pbuf, size, cudbg_poutbuf);
	return rc;
}

int view_cim_obq_ncsi(char *pbuf, u32 size, struct cudbg_buffer
		      *cudbg_poutbuf, enum chip_type chip)
{
	int rc;
	rc = view_cim_q(pbuf, size, cudbg_poutbuf);
	return rc;
}

int view_cim_obq_sge_rx_q0(char *pbuf, u32 size, struct cudbg_buffer
			   *cudbg_poutbuf, enum chip_type chip)
{
	int rc;
	rc = view_cim_q(pbuf, size, cudbg_poutbuf);
	return rc;
}

int view_cim_obq_sge_rx_q1(char *pbuf, u32 size, struct cudbg_buffer
			   *cudbg_poutbuf, enum chip_type chip)
{
	int rc;
	rc = view_cim_q(pbuf, size, cudbg_poutbuf);
	return rc;
}

int view_cim_ibq_tp0(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		     enum chip_type chip)
{
	int rc;
	rc = view_cim_q(pbuf, size, cudbg_poutbuf);
	return rc;
}

static int view_cim_la_t6(char *pbuf, u32 size, struct cudbg_buffer
			  *cudbg_poutbuf)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	u32 *p, cfg, dc_size;
	int rc;
	u32 i;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);

	if (rc)
		goto err1;

	dc_size = dc_buff.offset;

	p = (u32 *)((char *)dc_buff.data + sizeof(cfg));
	cfg = *((u32 *)dc_buff.data);
	dc_size -= sizeof(cfg);

	if (cfg & F_UPDBGLACAPTPCONLY) {
		cudbg_printf(cudbg_poutbuf, err1, "Status   Inst    Data      "\
			     "PC\r\n");

		for (i = 0; i < dc_size; i += 32, p += 8) {
			cudbg_printf(cudbg_poutbuf, err1,
				     "  %02x   %08x %08x %08x\n",
				     p[3] & 0xff, p[2], p[1], p[0]);

			cudbg_printf(cudbg_poutbuf, err1,
				     "  %02x   %02x%06x %02x%06x %02x%06x\n",
				     (p[6] >> 8) & 0xff, p[6] & 0xff, p[5] >> 8,
				     p[5] & 0xff, p[4] >> 8, p[4] & 0xff,
				     p[3] >> 8);

			cudbg_printf(cudbg_poutbuf, err1,
				     "  %02x   %04x%04x %04x%04x %04x%04x\n",
				     (p[9] >> 16) & 0xff, p[9] & 0xffff,
				     p[8] >> 16, p[8] & 0xffff, p[7] >> 16,
				     p[7] & 0xffff, p[6] >> 16);
		}
		goto err1;
	}

	cudbg_printf(cudbg_poutbuf, err1, "Status   Inst    Data      PC     "\
		     "LS0Stat  LS0Addr  LS0Data  LS1Stat  LS1Addr  LS1Data\n");

	for (i = 0; i < dc_size; i += 32, p += 8) {
		cudbg_printf(cudbg_poutbuf, err1, "  %02x   %04x%04x %04x%04x "\
			     "%04x%04x %08x %08x %08x %08x %08x %08x\n",
			     (p[9] >> 16) & 0xff,       /* Status */
			     p[9] & 0xffff, p[8] >> 16, /* Inst */
			     p[8] & 0xffff, p[7] >> 16, /* Data */
			     p[7] & 0xffff, p[6] >> 16, /* PC */
			     p[2], p[1], p[0],          /* LS0 Stat, Addr
							   and Data */
			     p[5], p[4], p[3]);         /* LS1 Stat, Addr
							   and Data */
	}

err1:
	free(dc_buff.data);
err:
	return rc;
}

static int view_cim_la_t5(char *pbuf, u32 size, struct cudbg_buffer
			  *cudbg_poutbuf)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	u32 *p, cfg, dc_size;
	int rc;
	u32 i;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);

	if (rc)
		goto err1;

	dc_size = dc_buff.offset;

	p = (u32 *)((char *)dc_buff.data + sizeof(cfg));
	cfg = *((u32 *)dc_buff.data);
	dc_size -= sizeof(cfg);

	if (cfg & F_UPDBGLACAPTPCONLY) {
		/* as per cim_la_show_3in1() (in
		 * sw\dev\linux\drv\cxgb4_main.c)*/
		cudbg_printf(cudbg_poutbuf, err1, "Status   Data      PC\r\n");

		for (i = 0; i < dc_size; i += 32, p += 8) {
			cudbg_printf(cudbg_poutbuf, err1,
				     "  %02X   %08X %08X\r\n",
				     (p[5] & 0xFF), p[6], p[7]);

			cudbg_printf(cudbg_poutbuf, err1,
				     "  %02X   %02X%06X %02X%06X\n",
				     ((p[3] >> 8) & 0xFF), (p[3] & 0xFF),
				     (p[4] >> 8), (p[4] & 0xFF), (p[5] >> 8));

			cudbg_printf(cudbg_poutbuf, err1,
				     "  %02X   %X%07X %X%07X\r\n",
				     ((p[0] >> 4) & 0xFF), (p[0] & 0xF),
				     (p[1] >> 4), (p[1] & 0xF), (p[2] >> 4));
		}
		goto err1;
	}

	cudbg_printf(cudbg_poutbuf, err1, "Status   Data      PC     LS0Stat  "\
		     "LS0Addr             LS0Data\n");

	for (i = 0; i < dc_size; i += 32, p += 8) {
		cudbg_printf(cudbg_poutbuf, err1, "%02x   %x%07x %x%07x %08x "\
			     "%08x %08x%08x%08x%08x\n",
			     ((p[0] >> 4) & 0xFF), (p[0] & 0xF), (p[1] >> 4),
			     (p[1] & 0xF), (p[2] >> 4), (p[2] & 0xF), p[3],
			     p[4], p[5], p[6], p[7]);
	}

err1:
	free(dc_buff.data);
err:
	return rc;
}

int view_cim_la(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		enum chip_type chip)
{
	int rc = -1;

	if (is_t5(chip))
		rc = view_cim_la_t5(pbuf, size, cudbg_poutbuf);
	else if (is_t6(chip))
		rc = view_cim_la_t6(pbuf, size, cudbg_poutbuf);

	return rc;
}

int view_cim_ma_la(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		   enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	int rc, i, j;
	u32 *p;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);

	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);

	if (rc)
		goto err1;

	p = (u32 *)dc_buff.data;

	for (i = 0; i <= CIM_MALA_SIZE; i++, p += 4) {
		if (i < CIM_MALA_SIZE) {
			cudbg_printf(cudbg_poutbuf, err1,
				     "%02x%08x%08x%08x%08x\n",
				     p[4], p[3], p[2], p[1], p[0]);
		} else {
			cudbg_printf(cudbg_poutbuf, err1, "\nCnt ID Tag UE   "\
				     "   Data       RDY VLD\n");
			for (j = 0; j < CIM_MALA_SIZE ; j++, p += 3) {
				cudbg_printf(cudbg_poutbuf, err1,
					     "%3u %2u  %x  %u %08x%08x  %u   "\
					     "%u\n",
					     (p[2] >> 10) & 0xff,
					     (p[2] >> 7) & 7, (p[2] >> 3) & 0xf,
					     (p[2] >> 2) & 1,
					     (p[1] >> 2) | ((p[2] & 3) << 30),
					     (p[0] >> 2) | ((p[1] & 3) << 30),
					     (p[0] >> 1) & 1, p[0] & 1);
			}
		}
	}

err1:
	free(dc_buff.data);
err:
	return rc;
}

int view_cim_qcfg(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		  enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	int rc, i;
	u32 *p, *wr;
	struct struct_cim_qcfg *QcfgData;
	static const char * const pQname[] = {
		"TP0", "TP1", "ULP", "SGE0", "SGE1", "NC-SI",
		"ULP0", "ULP1", "ULP2", "ULP3", "SGE", "NC-SI"
	};

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);

	if (rc)
		goto err1;

	QcfgData = (struct struct_cim_qcfg *) (dc_buff.data);
	p = QcfgData->stat;
	wr = QcfgData->obq_wr;

	cudbg_printf(cudbg_poutbuf, err1, "  Queue Base Size Thres  RdPtr "\
		     "WrPtr  SOP  EOP Avail\n");
	for (i = 0; i < CIM_NUM_IBQ; i++, p += 4) {
		cudbg_printf(cudbg_poutbuf, err1, "%5s %5x %5u %4u %6x  %4x "\
			     "%4u %4u %5u\n",
			     pQname[i], QcfgData->base[i], QcfgData->size[i],
			     QcfgData->thres[i], G_IBQRDADDR(p[0]),
			     G_IBQWRADDR(p[1]), G_QUESOPCNT(p[3]),
			     G_QUEEOPCNT(p[3]), G_QUEREMFLITS(p[2]) * 16);
	}

	for (; i < CIM_NUM_IBQ + CIM_NUM_OBQ; i++, p += 4, wr += 2) {
		cudbg_printf(cudbg_poutbuf, err1, "%5s %5x %5u %11x  %4x %4u "\
			     "%4u %5u\n",
			     pQname[i], QcfgData->base[i], QcfgData->size[i],
			     G_QUERDADDR(p[0]) & 0x3fff,
			     wr[0] - QcfgData->base[i], G_QUESOPCNT(p[3]),
			     G_QUEEOPCNT(p[3]), G_QUEREMFLITS(p[2]) * 16);
	}

err1:
	free(dc_buff.data);

err:
	return rc;
}

int decompress_buffer_wrapper(struct cudbg_buffer *pc_buff,
			      struct cudbg_buffer *pdc_buff)
{
	int rc = 0;
	pdc_buff->data =  malloc(2 * CUDBG_CHUNK_SIZE);

	if (pdc_buff->data == NULL) {
		rc = CUDBG_STATUS_NOSPACE;
		goto err;
	}
	pdc_buff->size = 2 * CUDBG_CHUNK_SIZE;

	rc = decompress_buffer(pc_buff, pdc_buff);

	if (rc == CUDBG_STATUS_SMALL_BUFF) {
		free(pdc_buff->data);
		pdc_buff->data =  malloc(pdc_buff->size);

		if (pdc_buff->data == NULL) {
			rc = CUDBG_STATUS_NOSPACE;
			goto err;
		}
		rc = decompress_buffer(pc_buff, pdc_buff);
	}

err:
	return rc;
}

int copy_bin_data(char *pbuf, u32 size, const char *fname, struct
		  cudbg_buffer * cudbg_poutbuf)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	int rc = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	if (cudbg_poutbuf->data == NULL)
		goto err;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	if (dc_buff.size > cudbg_poutbuf->size) {
		rc = CUDBG_STATUS_OUTBUFF_OVERFLOW;
		cudbg_poutbuf->size = dc_buff.size;
		goto err1;
	}

	memcpy(cudbg_poutbuf->data, dc_buff.data, dc_buff.size);
	cudbg_poutbuf->size = dc_buff.size;

err1:
	free(dc_buff.data);
err:
	return rc;
}

int view_edc0_data(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		   enum chip_type chip)
{
	const char *file_name = "_cudbg_edc0.bin";
	int rc;

	rc = copy_bin_data(pbuf, size, file_name, cudbg_poutbuf);

	return rc;
}

int view_edc1_data(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		   enum chip_type chip)
{
	const char *file_name = "_cudbg_edc1.bin";
	int rc;

	rc = copy_bin_data(pbuf, size, file_name, cudbg_poutbuf);

	return rc;
}

int view_mc0_data(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		  enum chip_type chip)
{
	const char *file_name = "_cudbg_mc0.bin";
	int rc;
	rc = copy_bin_data(pbuf, size, file_name, cudbg_poutbuf);

	return rc;
}

int view_mc1_data(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		  enum chip_type chip)
{
	const char *file_name = "_cudbg_mc1.bin";
	int rc;
	rc = copy_bin_data(pbuf, size, file_name, cudbg_poutbuf);

	return rc;
}

int view_sw_state(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		  enum chip_type chip)
{
	return CUDBG_STATUS_NOT_IMPLEMENTED;
}

int view_cpl_stats(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		   enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct struct_tp_cpl_stats *tp_cpl_stats_buff;
	struct tp_cpl_stats stats;
	int rc = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	tp_cpl_stats_buff = (struct struct_tp_cpl_stats *) dc_buff.data;

	stats =  tp_cpl_stats_buff->stats;

	if (tp_cpl_stats_buff->nchan == NCHAN) {
		cudbg_printf(cudbg_poutbuf, err1, "                 channel 0"\
			     "  channel 1  channel 2  channel 3\n");
		cudbg_printf(cudbg_poutbuf, err1, "CPL requests:   %10u %10u "\
			     "%10u %10u\n",
			     stats.req[0], stats.req[1], stats.req[2],
			     stats.req[3]);
		cudbg_printf(cudbg_poutbuf, err1, "CPL responses:  %10u %10u "\
			     "%10u %10u\n",
			     stats.rsp[0], stats.rsp[1], stats.rsp[2],
			     stats.rsp[3]);
	} else {
		cudbg_printf(cudbg_poutbuf, err1, "                 channel 0"\
			     "  channel 1\n");
		cudbg_printf(cudbg_poutbuf, err1, "CPL requests:   %10u %10u\n",
			     stats.req[0], stats.req[1]);
		cudbg_printf(cudbg_poutbuf, err1, "CPL responses:  %10u %10u\n",
			     stats.rsp[0], stats.rsp[1]);
	}

err1:
	free(dc_buff.data);
err:
	return rc;
}

int view_ddp_stats(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		   enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct tp_usm_stats *tp_usm_stats_buff;
	int rc = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	tp_usm_stats_buff = (struct tp_usm_stats *) dc_buff.data;

	cudbg_printf(cudbg_poutbuf, err1, "Frames: %u\n",
		     tp_usm_stats_buff->frames);
	cudbg_printf(cudbg_poutbuf, err1, "Octets: %llu\n",
		     (unsigned long long)tp_usm_stats_buff->octets);
	cudbg_printf(cudbg_poutbuf, err1, "Drops:  %u\n",
		     tp_usm_stats_buff->drops);

err1:
	free(dc_buff.data);
err:
	return rc;
}

int view_macstats(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		  enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct struct_mac_stats *mac_stats_buff;
	int rc = 0;
	u32 i;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	mac_stats_buff = (struct struct_mac_stats *) dc_buff.data;
	for (i = 0; i < mac_stats_buff->port_count; i++) {
		cudbg_printf(cudbg_poutbuf, err1, "\nMac %d Stats:\n", i);
		cudbg_printf(cudbg_poutbuf, err1, "tx_octets              "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].tx_octets);
		cudbg_printf(cudbg_poutbuf, err1, "tx_frames              "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].tx_frames);
		cudbg_printf(cudbg_poutbuf, err1, "tx_bcast_frames        "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].tx_bcast_frames);
		cudbg_printf(cudbg_poutbuf, err1, "tx_mcast_frames        "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].tx_mcast_frames);
		cudbg_printf(cudbg_poutbuf, err1, "tx_ucast_frames        "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].tx_ucast_frames);
		cudbg_printf(cudbg_poutbuf, err1, "tx_error_frames        "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].tx_error_frames);
		cudbg_printf(cudbg_poutbuf, err1, "tx_frames_64           "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].tx_frames_64);
		cudbg_printf(cudbg_poutbuf, err1, "tx_frames_65_127       "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].tx_frames_65_127);
		cudbg_printf(cudbg_poutbuf, err1, "tx_frames_128_255      "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].tx_frames_128_255);
		cudbg_printf(cudbg_poutbuf, err1, "tx_frames_256_511      "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].tx_frames_256_511);
		cudbg_printf(cudbg_poutbuf, err1, "tx_frames_512_1023     "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].tx_frames_512_1023);
		cudbg_printf(cudbg_poutbuf, err1, "tx_frames_1024_1518    "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].tx_frames_1024_1518);
		cudbg_printf(cudbg_poutbuf, err1, "tx_frames_1519_max     "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].tx_frames_1519_max);
		cudbg_printf(cudbg_poutbuf, err1, "tx_drop                "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].tx_drop);
		cudbg_printf(cudbg_poutbuf, err1, "tx_pause               "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].tx_pause);
		cudbg_printf(cudbg_poutbuf, err1, "tx_ppp0                "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].tx_ppp0);
		cudbg_printf(cudbg_poutbuf, err1, "tx_ppp1                "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].tx_ppp1);
		cudbg_printf(cudbg_poutbuf, err1, "tx_ppp2                "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].tx_ppp2);
		cudbg_printf(cudbg_poutbuf, err1, "tx_ppp3                "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].tx_ppp3);
		cudbg_printf(cudbg_poutbuf, err1, "tx_ppp4                "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].tx_ppp4);
		cudbg_printf(cudbg_poutbuf, err1, "tx_ppp5                "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].tx_ppp5);
		cudbg_printf(cudbg_poutbuf, err1, "tx_ppp6                "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].tx_ppp6);
		cudbg_printf(cudbg_poutbuf, err1, "tx_ppp7                "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].tx_ppp7);
		cudbg_printf(cudbg_poutbuf, err1, "rx_octets              "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_octets);
		cudbg_printf(cudbg_poutbuf, err1, "rx_frames              "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_frames);
		cudbg_printf(cudbg_poutbuf, err1, "rx_bcast_frames        "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_bcast_frames);
		cudbg_printf(cudbg_poutbuf, err1, "rx_mcast_frames        "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_mcast_frames);
		cudbg_printf(cudbg_poutbuf, err1, "rx_ucast_frames        "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_ucast_frames);
		cudbg_printf(cudbg_poutbuf, err1, "rx_too_long            "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_too_long);
		cudbg_printf(cudbg_poutbuf, err1, "rx_jabber              "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_jabber);
		cudbg_printf(cudbg_poutbuf, err1, "rx_fcs_err             "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_fcs_err);
		cudbg_printf(cudbg_poutbuf, err1, "rx_len_err             "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_len_err);
		cudbg_printf(cudbg_poutbuf, err1, "rx_symbol_err          "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_symbol_err);
		cudbg_printf(cudbg_poutbuf, err1, "rx_runt                "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_runt);
		cudbg_printf(cudbg_poutbuf, err1, "rx_frames_64           "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_frames_64);
		cudbg_printf(cudbg_poutbuf, err1, "rx_frames_65_127       "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_frames_65_127);
		cudbg_printf(cudbg_poutbuf, err1, "rx_frames_128_255      "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_frames_128_255);
		cudbg_printf(cudbg_poutbuf, err1, "rx_frames_256_511      "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_frames_256_511);
		cudbg_printf(cudbg_poutbuf, err1, "rx_frames_512_1023     "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_frames_512_1023);
		cudbg_printf(cudbg_poutbuf, err1, "rx_frames_1024_1518    "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_frames_1024_1518);
		cudbg_printf(cudbg_poutbuf, err1, "rx_frames_1519_max     "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_frames_1519_max);
		cudbg_printf(cudbg_poutbuf, err1, "rx_pause               "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_pause);
		cudbg_printf(cudbg_poutbuf, err1, "rx_ppp0                "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_ppp0);
		cudbg_printf(cudbg_poutbuf, err1, "rx_ppp1                "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_ppp1);
		cudbg_printf(cudbg_poutbuf, err1, "rx_ppp2                "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_ppp2);
		cudbg_printf(cudbg_poutbuf, err1, "rx_ppp3                "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_ppp3);
		cudbg_printf(cudbg_poutbuf, err1, "rx_ppp4                "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_ppp4);
		cudbg_printf(cudbg_poutbuf, err1, "rx_ppp5                "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_ppp5);
		cudbg_printf(cudbg_poutbuf, err1, "rx_ppp6                "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_ppp6);
		cudbg_printf(cudbg_poutbuf, err1, "rx_ppp7                "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_ppp7);
		cudbg_printf(cudbg_poutbuf, err1, "rx_ovflow0             "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_ovflow0);
		cudbg_printf(cudbg_poutbuf, err1, "rx_ovflow1             "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_ovflow1);
		cudbg_printf(cudbg_poutbuf, err1, "rx_ovflow2             "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_ovflow2);
		cudbg_printf(cudbg_poutbuf, err1, "rx_ovflow3             "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_ovflow3);
		cudbg_printf(cudbg_poutbuf, err1, "rx_trunc0              "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_trunc0);
		cudbg_printf(cudbg_poutbuf, err1, "rx_trunc1              "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_trunc1);
		cudbg_printf(cudbg_poutbuf, err1, "rx_trunc2              "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_trunc2);
		cudbg_printf(cudbg_poutbuf, err1, "rx_trunc3              "\
			     "%64llu\n",
			     mac_stats_buff->stats[i].rx_trunc3);
	}

err1:
	free(dc_buff.data);
err:
	return rc;
}

int view_ulptx_la(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		  enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct struct_ulptx_la *ulptx_la_buff;
	int i, j, rc = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	ulptx_la_buff = (struct struct_ulptx_la *) dc_buff.data;

	for (i = 0; i < CUDBG_NUM_ULPTX; i++) {
		cudbg_printf(cudbg_poutbuf, err1,
			     "==============================\n");
		cudbg_printf(cudbg_poutbuf, err1, "DUMPING ULP_TX_LA_%d\n", i);
		cudbg_printf(cudbg_poutbuf, err1,
			     "==============================\n");

		cudbg_printf(cudbg_poutbuf, err1, "[0x%x] %-24s %#x\n",
			     (A_ULP_TX_LA_RDPTR_0 + 0x10 * i),
			     cudbg_ulptx_rdptr[i], ulptx_la_buff->rdptr[i]);
		cudbg_printf(cudbg_poutbuf, err1, "[0x%x] %-24s %#x\n",
			     (A_ULP_TX_LA_WRPTR_0 + 0x10 * i),
			     cudbg_ulptx_wrptr[i], ulptx_la_buff->wrptr[i]);
		cudbg_printf(cudbg_poutbuf, err1, "[0x%x] %-24s %#-13x\n",
			     (A_ULP_TX_LA_RDDATA_0 + 0x10 * i),
			     cudbg_ulptx_rddata[i], ulptx_la_buff->rddata[i]);

		for (j = 0; j < CUDBG_NUM_ULPTX_READ; j++) {
			cudbg_printf(cudbg_poutbuf, err1,
				     "[%#x]   %#-16x [%u]\n",
				     j, ulptx_la_buff->rd_data[i][j],
				     ulptx_la_buff->rd_data[i][j]);
		}
	}
err1:
	free(dc_buff.data);
err:
	return rc;

}

int view_ulprx_la(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		  enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct struct_ulprx_la *ulprx_la_buff;
	u32 *p;
	int rc = 0;
	u32 i;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	ulprx_la_buff = (struct struct_ulprx_la *) dc_buff.data;
	p = ulprx_la_buff->data;

	cudbg_printf(cudbg_poutbuf, err1,
		     "      Pcmd        Type   Message                Data\n");
	for (i = 0; i <  ulprx_la_buff->size; i++, p += 8)
		cudbg_printf(cudbg_poutbuf, err1,
			     "%08x%08x  %4x  %08x  %08x%08x%08x%08x\n",
			     p[1], p[0], p[2], p[3], p[7], p[6], p[5], p[4]);

err1:
	free(dc_buff.data);
err:
	return rc;
}

int view_wc_stats(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		  enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct struct_wc_stats *wc_stats_buff;
	int rc = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	wc_stats_buff = (struct struct_wc_stats *) dc_buff.data;

	cudbg_printf(cudbg_poutbuf, err1, "WriteCoalSuccess: %u\n",
		     wc_stats_buff->wr_cl_success);
	cudbg_printf(cudbg_poutbuf, err1, "WriteCoalFail:    %u\n",
		     wc_stats_buff->wr_cl_fail);

err1:
	free(dc_buff.data);
err:
	return rc;
}

static int field_desc_show(u64 v, const struct field_desc *p,
			   struct cudbg_buffer *cudbg_poutbuf)
{
	char buf[32];
	int line_size = 0;
	int rc = 0;

	while (p->name) {
		u64 mask = (1ULL << p->width) - 1;
		int len = snprintf(buf, sizeof(buf), "%s: %llu", p->name,
				   ((unsigned long long)v >> p->start) & mask);

		if (line_size + len >= 79) {
			line_size = 8;
			cudbg_printf(cudbg_poutbuf, err1, "\n        ");
		}
		cudbg_printf(cudbg_poutbuf, err1, "%s ", buf);
		line_size += len + 1;
		p++;
	}
	cudbg_printf(cudbg_poutbuf, err1, "\n");
err1:
	return rc;
}

static int tp_la_show(void *v, int idx, struct cudbg_buffer *cudbg_poutbuf)
{
	const u64 *p = v;
	int rc;

	rc = field_desc_show(*p, tp_la0, cudbg_poutbuf);
	return rc;
}

static int tp_la_show2(void *v, int idx, struct cudbg_buffer *cudbg_poutbuf)
{
	const u64 *p = v;
	int rc;

	if (idx)
		cudbg_printf(cudbg_poutbuf, err1, "'\n");
	rc = field_desc_show(p[0], tp_la0, cudbg_poutbuf);
	if (rc < 0)
		goto err1;
	if (idx < (TPLA_SIZE / 2 - 1) || p[1] != ~0ULL)
		rc = field_desc_show(p[1], tp_la0, cudbg_poutbuf);
err1:
	return rc;
}

static int tp_la_show3(void *v, int idx, struct cudbg_buffer *cudbg_poutbuf)
{
	const u64 *p = v;
	int rc;

	if (idx)
		cudbg_printf(cudbg_poutbuf, err1, "\n");
	rc = field_desc_show(p[0], tp_la0, cudbg_poutbuf);
	if (rc < 0)
		goto err1;
	if (idx < (TPLA_SIZE / 2 - 1) || p[1] != ~0ULL)
		rc = field_desc_show(p[1], (p[0] & BIT(17)) ? tp_la2 : tp_la1,
				     cudbg_poutbuf);
err1:
	return rc;
}

int view_tp_la(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
	       enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct struct_tp_la *tp_la_buff;
	int rc = 0;
	int i;

	static int (*la_show) (void *v, int idx,
			       struct cudbg_buffer *cudbg_poutbuf);

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	tp_la_buff = (struct struct_tp_la *) dc_buff.data;

	switch (tp_la_buff->mode) {

	case 2:
		la_show = tp_la_show2;
		break;
	case 3:
		la_show = tp_la_show3;
		break;
	default:
		la_show = tp_la_show;
	}

	for (i = 0; i < TPLA_SIZE/2; i++) {
		rc = la_show((u64 *)tp_la_buff->data + i*2, i, cudbg_poutbuf);
		if (rc < 0)
			goto err1;
	}

err1:
	free(dc_buff.data);
err:
	return rc;
}

static unsigned long do_div(unsigned long *number, u32 divisor)
{
	unsigned long remainder = *number % divisor;

	(*number) /= divisor;
	return remainder;
}

static int string_get_size(unsigned long size,
			   const enum string_size_units units, char *buf,
			   int len)
{
	const char *units_10[] = {
		"B", "kB", "MB", "GB", "TB", "PB",
		"EB", "ZB", "YB", NULL
	};
	const char *units_2[] = {
		"B", "KiB", "MiB", "GiB", "TiB", "PiB",
		"EiB", "ZiB", "YiB", NULL
	};
	const char **units_str[2];/* = {units_10, units_2};*/
	const u32 divisor[] = {1000, 1024};
	int i = 0;
	int j = 0;
	unsigned long remainder = 0;
	unsigned long sf_cap = 0;
	char tmp[8] = {0};

	tmp[0] = '\0';
	i = 0;

	units_str[STRING_UNITS_10] = units_10;
	units_str[STRING_UNITS_2] = units_2;

	if (size >= divisor[units]) {
		while (size >= divisor[units] && units_str[units][i]) {
			remainder = do_div(&size, divisor[units]);
			i++;
		}

		sf_cap = size;

		for (j = 0; sf_cap*10 < 1000; j++)
			sf_cap *= 10;

		if (j) {
			remainder *= 1000;
			do_div(&remainder, divisor[units]);

			snprintf(tmp, sizeof(tmp), ".%03lu",
				 (unsigned long)remainder);
			tmp[j + 1] = '\0';
		}
	}

	snprintf(buf, len, "%lu%s %s", (unsigned long)size, tmp,
		 units_str[units][i]);

	return 0;
}

static int mem_region_show(const char *name, u32 from, u32 to,
			   struct cudbg_buffer *cudbg_poutbuf)
{
	int rc = 0;
	char buf[40] = {0};
	string_get_size((u64)to - from + 1, STRING_UNITS_2,
			buf, sizeof(buf));
	cudbg_printf(cudbg_poutbuf, err1, "%-14s %#x-%#x [%s]\n", name, from,
		     to, buf);
err1:
	return rc;
} /* mem_region_show */

int view_meminfo(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		 enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct struct_meminfo *meminfo_buff;
	u32 i, lo, idx;
	int rc = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	meminfo_buff = (struct struct_meminfo *) dc_buff.data;

	for (lo = 0; lo < meminfo_buff->avail_c; lo++) {
		idx = meminfo_buff->avail[lo].idx;
		rc = mem_region_show(memory[idx], meminfo_buff->avail[lo].base,
				     meminfo_buff->avail[lo].limit - 1,
				     cudbg_poutbuf);
		if (rc < 0)
			goto err1;
	}

	for (i = 0; i < meminfo_buff->mem_c; i++) {
		if (meminfo_buff->mem[i].idx >= ARRAY_SIZE(region))
			continue;                        /* skip holes */
		if (!(meminfo_buff->mem[i].limit))
			meminfo_buff->mem[i].limit =
				i < meminfo_buff->mem_c - 1 ?
				meminfo_buff->mem[i + 1].base - 1 : ~0;

		idx = meminfo_buff->mem[i].idx;
		rc = mem_region_show(region[idx], meminfo_buff->mem[i].base,
				     meminfo_buff->mem[i].limit, cudbg_poutbuf);
		if (rc < 0)
			goto err1;
	}

	rc = mem_region_show("uP RAM:", meminfo_buff->up_ram_lo,
			     meminfo_buff->up_ram_hi, cudbg_poutbuf);
	if (rc < 0)
		goto err1;
	rc = mem_region_show("uP Extmem2:", meminfo_buff->up_extmem2_lo,
			     meminfo_buff->up_extmem2_hi, cudbg_poutbuf);
	if (rc < 0)
		goto err1;
	cudbg_printf(cudbg_poutbuf, err1, "\n%u Rx pages of size %uKiB for %u "\
		     "channels\n",
		     meminfo_buff->rx_pages_data[0],
		     meminfo_buff->rx_pages_data[1],
		     meminfo_buff->rx_pages_data[2]);

	cudbg_printf(cudbg_poutbuf, err1, "%u Tx pages of size %u%ciB for %u "\
		     "channels\n\n",
		     meminfo_buff->tx_pages_data[0],
		     meminfo_buff->tx_pages_data[1],
		     meminfo_buff->tx_pages_data[2],
		     meminfo_buff->tx_pages_data[3]);

	for (i = 0; i < 4; i++) {
		cudbg_printf(cudbg_poutbuf, err1, "Port %d using %u pages out "\
			     "of %u allocated\n",
			     i, meminfo_buff->port_used[i],
			     meminfo_buff->port_alloc[i]);
	}

	for (i = 0; i < NCHAN; i++) {
		cudbg_printf(cudbg_poutbuf, err1, "Loopback %d using %u pages "\
			     "out of %u allocated\n",
			     i, meminfo_buff->loopback_used[i],
			     meminfo_buff->loopback_alloc[i]);
	}

err1:
	free(dc_buff.data);
err:
	return rc;
}

int view_lb_stats(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		  enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct lb_port_stats *tmp_stats;
	struct struct_lb_stats *lb_stats_buff;
	int i, j, rc = 0;
	u64 *p0, *p1;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	lb_stats_buff = (struct struct_lb_stats *) dc_buff.data;

	tmp_stats  = lb_stats_buff->s;

	for (i = 0; i < lb_stats_buff->nchan; i += 2, tmp_stats += 2) {

		p0 = &(tmp_stats[0].octets);
		p1 = &(tmp_stats[1].octets);
		cudbg_printf(cudbg_poutbuf, err1, "%s                       "\
			     "Loopback %u           Loopback %u\n",
			     i == 0 ? "" : "\n", i, i + 1);

		for (j = 0; j < ARRAY_SIZE(lb_stat_name); j++)
			cudbg_printf(cudbg_poutbuf, err1, "%-17s %20llu "\
				     "%20llu\n", lb_stat_name[j],
				     (unsigned long long)*p0++,
				     (unsigned long long)*p1++);
	}

err1:
	free(dc_buff.data);
err:
	return rc;
}

int view_rdma_stats(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		    enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct tp_rdma_stats *rdma_stats_buff;
	int rc = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	rdma_stats_buff = (struct tp_rdma_stats *) dc_buff.data;

	cudbg_printf(cudbg_poutbuf, err1, "NoRQEModDefferals: %u\n",
		     rdma_stats_buff->rqe_dfr_mod);
	cudbg_printf(cudbg_poutbuf, err1, "NoRQEPktDefferals: %u\n",
		     rdma_stats_buff->rqe_dfr_pkt);

err1:
	free(dc_buff.data);
err:
	return rc;
}

int view_clk_info(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		  enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct struct_clk_info *clk_info_buff;
	int rc = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	clk_info_buff = (struct struct_clk_info *) dc_buff.data;

	unit_conv(clk_info_buff->core_clk_period,
			sizeof(clk_info_buff->core_clk_period),
			clk_info_buff->cclk_ps, 1000);
	unit_conv(clk_info_buff->tp_timer_tick,
			sizeof(clk_info_buff->tp_timer_tick),
			(clk_info_buff->cclk_ps << clk_info_buff->tre),
			1000000);
	unit_conv(clk_info_buff->tcp_tstamp_tick,
			sizeof(clk_info_buff->tcp_tstamp_tick),
			(clk_info_buff->cclk_ps <<
			 G_TIMESTAMPRESOLUTION(clk_info_buff->res)), 1000000);
	unit_conv(clk_info_buff->dack_tick,
			sizeof(clk_info_buff->dack_tick),
			(clk_info_buff->cclk_ps << clk_info_buff->dack_re),
			1000000);

	cudbg_printf(cudbg_poutbuf, err1, "Core clock period: %s ns\n",
		     clk_info_buff->core_clk_period);
	cudbg_printf(cudbg_poutbuf, err1, "TP timer tick: %s us\n",
		     clk_info_buff->tp_timer_tick);
	cudbg_printf(cudbg_poutbuf, err1, "TCP timestamp tick: %s us\n",
		     clk_info_buff->tcp_tstamp_tick);
	cudbg_printf(cudbg_poutbuf, err1, "DACK tick: %s us\n",
		     clk_info_buff->dack_tick);
	cudbg_printf(cudbg_poutbuf, err1, "DACK timer: %u us\n",
		     clk_info_buff->dack_timer);
	cudbg_printf(cudbg_poutbuf, err1, "Retransmit min: %llu us\n",
		     clk_info_buff->retransmit_min);
	cudbg_printf(cudbg_poutbuf, err1, "Retransmit max: %llu us\n",
		     clk_info_buff->retransmit_max);
	cudbg_printf(cudbg_poutbuf, err1, "Persist timer min: %llu us\n",
		     clk_info_buff->persist_timer_min);
	cudbg_printf(cudbg_poutbuf, err1, "Persist timer max: %llu us\n",
		     clk_info_buff->persist_timer_max);
	cudbg_printf(cudbg_poutbuf, err1, "Keepalive idle timer: %llu us\n",
		     clk_info_buff->keepalive_idle_timer);
	cudbg_printf(cudbg_poutbuf, err1, "Keepalive interval: %llu us\n",
		     clk_info_buff->keepalive_interval);
	cudbg_printf(cudbg_poutbuf, err1, "Initial SRTT: %llu us\n",
		     clk_info_buff->initial_srtt);

	cudbg_printf(cudbg_poutbuf, err1, "FINWAIT2 timer: %llu us\n",
		     clk_info_buff->finwait2_timer);

err1:
	free(dc_buff.data);
err:
	return rc;

}

int view_cim_pif_la(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		    enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct cim_pif_la *cim_pif_la_buff;
	int i, rc = 0;
	u32 *p;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	cim_pif_la_buff = (struct cim_pif_la *) dc_buff.data;

	p = (u32 *)cim_pif_la_buff->data;

	cudbg_printf(cudbg_poutbuf, err1, "Cntl ID DataBE   Addr            "\
		     "     Data\n");
	for (i = 0; i < cim_pif_la_buff->size; i++, p = p + 6)
		cudbg_printf(cudbg_poutbuf, err1, " %02x  %02x  %04x  %08x "\
			     "%08x%08x%08x%08x\n",
			     (p[5] >> 22) & 0xff, (p[5] >> 16) & 0x3f,
			     p[5] & 0xffff, p[4], p[3], p[2], p[1], p[0]);

	p = (u32 *) cim_pif_la_buff->data +  6 * CIM_PIFLA_SIZE;

	cudbg_printf(cudbg_poutbuf, err1, "\nCntl ID               Data\n");
	for (i = 0; i < cim_pif_la_buff->size; i++, p = p + 6)
		cudbg_printf(cudbg_poutbuf, err1, " %02x  %02x "\
			     "%08x%08x%08x%08x\n",
			     (p[4] >> 6) & 0xff, p[4] & 0x3f, p[3], p[2], p[1],
			     p[0]);

err1:
	free(dc_buff.data);
err:
	return rc;
}

int view_fcoe_stats(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		    enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct tp_fcoe_stats stats[4];
	struct struct_tp_fcoe_stats *tp_fcoe_stats_buff;
	int rc = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	tp_fcoe_stats_buff = (struct struct_tp_fcoe_stats *) dc_buff.data;
	memcpy(stats, tp_fcoe_stats_buff->stats, sizeof(stats));

	if (tp_fcoe_stats_buff->nchan == NCHAN) {
		cudbg_printf(cudbg_poutbuf, err1, "                   channel "\
			     "0        channel 1        channel 2        "\
			     "channel 3\n");
		cudbg_printf(cudbg_poutbuf, err1, "octetsDDP:  %16llu %16llu "\
			     "%16llu %16llu\n",
			     stats[0].octets_ddp, stats[1].octets_ddp,
			     stats[2].octets_ddp, stats[3].octets_ddp);
		cudbg_printf(cudbg_poutbuf, err1, "framesDDP:  %16u %16u %16u "\
			     "%16u\n",
			     stats[0].frames_ddp, stats[1].frames_ddp,
			     stats[2].frames_ddp, stats[3].frames_ddp);
		cudbg_printf(cudbg_poutbuf, err1, "framesDrop: %16u %16u %16u "\
			     "%16u\n",
			     stats[0].frames_drop, stats[1].frames_drop,
			     stats[2].frames_drop, stats[3].frames_drop);
	} else {
		cudbg_printf(cudbg_poutbuf, err1, "                   channel "\
			     "0        channel 1\n");
		cudbg_printf(cudbg_poutbuf, err1, "octetsDDP:  %16llu "\
			     "%16llu\n",
			     stats[0].octets_ddp, stats[1].octets_ddp);
		cudbg_printf(cudbg_poutbuf, err1, "framesDDP:  %16u %16u\n",
			     stats[0].frames_ddp, stats[1].frames_ddp);
		cudbg_printf(cudbg_poutbuf, err1, "framesDrop: %16u %16u\n",
			     stats[0].frames_drop, stats[1].frames_drop);
	}

err1:
	free(dc_buff.data);
err:
	return rc;
}

int view_tp_err_stats_show(char *pbuf, u32 size,
			   struct cudbg_buffer *cudbg_poutbuf,
			   enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct tp_err_stats stats;
	struct struct_tp_err_stats *tp_err_stats_buff;
	int rc = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	tp_err_stats_buff = (struct struct_tp_err_stats *) dc_buff.data;
	stats = tp_err_stats_buff->stats;

	if (tp_err_stats_buff->nchan == NCHAN) {
		cudbg_printf(cudbg_poutbuf, err1, "                 channel 0"\
			     "  channel 1  channel 2  channel 3\n");
		cudbg_printf(cudbg_poutbuf, err1, "macInErrs:      %10u %10u "\
			     "%10u %10u\n",
			     stats.mac_in_errs[0], stats.mac_in_errs[1],
			     stats.mac_in_errs[2], stats.mac_in_errs[3]);
		cudbg_printf(cudbg_poutbuf, err1, "hdrInErrs:      %10u %10u "\
			     "%10u %10u\n",
			     stats.hdr_in_errs[0], stats.hdr_in_errs[1],
			     stats.hdr_in_errs[2], stats.hdr_in_errs[3]);
		cudbg_printf(cudbg_poutbuf, err1, "tcpInErrs:      %10u %10u "\
			     "%10u %10u\n",
			     stats.tcp_in_errs[0], stats.tcp_in_errs[1],
			     stats.tcp_in_errs[2], stats.tcp_in_errs[3]);
		cudbg_printf(cudbg_poutbuf, err1, "tcp6InErrs:     %10u %10u "\
			     "%10u %10u\n",
			     stats.tcp6_in_errs[0], stats.tcp6_in_errs[1],
			     stats.tcp6_in_errs[2], stats.tcp6_in_errs[3]);
		cudbg_printf(cudbg_poutbuf, err1, "tnlCongDrops:   %10u %10u "\
			     "%10u %10u\n",
			     stats.tnl_cong_drops[0], stats.tnl_cong_drops[1],
			     stats.tnl_cong_drops[2], stats.tnl_cong_drops[3]);
		cudbg_printf(cudbg_poutbuf, err1, "tnlTxDrops:     %10u %10u "\
			     "%10u %10u\n",
			     stats.tnl_tx_drops[0], stats.tnl_tx_drops[1],
			     stats.tnl_tx_drops[2], stats.tnl_tx_drops[3]);
		cudbg_printf(cudbg_poutbuf, err1, "ofldVlanDrops:  %10u %10u "\
			     "%10u %10u\n",
			     stats.ofld_vlan_drops[0], stats.ofld_vlan_drops[1],
			     stats.ofld_vlan_drops[2],
			     stats.ofld_vlan_drops[3]);
		cudbg_printf(cudbg_poutbuf, err1, "ofldChanDrops:  %10u %10u "\
			     "%10u %10u\n\n",
			     stats.ofld_chan_drops[0], stats.ofld_chan_drops[1],
			     stats.ofld_chan_drops[2],
			     stats.ofld_chan_drops[3]);
	} else {
		cudbg_printf(cudbg_poutbuf, err1, "                 channel 0"\
			     "  channel 1\n");
		cudbg_printf(cudbg_poutbuf, err1, "macInErrs:      %10u %10u\n",
			     stats.mac_in_errs[0], stats.mac_in_errs[1]);
		cudbg_printf(cudbg_poutbuf, err1, "hdrInErrs:      %10u %10u\n",
			     stats.hdr_in_errs[0], stats.hdr_in_errs[1]);
		cudbg_printf(cudbg_poutbuf, err1, "tcpInErrs:      %10u %10u\n",
			     stats.tcp_in_errs[0], stats.tcp_in_errs[1]);
		cudbg_printf(cudbg_poutbuf, err1, "tcp6InErrs:     %10u %10u\n",
			     stats.tcp6_in_errs[0], stats.tcp6_in_errs[1]);
		cudbg_printf(cudbg_poutbuf, err1, "tnlCongDrops:   %10u %10u\n",
			     stats.tnl_cong_drops[0], stats.tnl_cong_drops[1]);
		cudbg_printf(cudbg_poutbuf, err1, "tnlTxDrops:     %10u %10u\n",
			     stats.tnl_tx_drops[0], stats.tnl_tx_drops[1]);
		cudbg_printf(cudbg_poutbuf, err1, "ofldVlanDrops:  %10u %10u\n",
			     stats.ofld_vlan_drops[0],
			     stats.ofld_vlan_drops[1]);
		cudbg_printf(cudbg_poutbuf, err1, "ofldChanDrops:  %10u %10u"\
			     "\n\n", stats.ofld_chan_drops[0],
			     stats.ofld_chan_drops[1]);
	}

	cudbg_printf(cudbg_poutbuf, err1, "ofldNoNeigh:    %u\nofldCongDefer: "\
		     " %u\n", stats.ofld_no_neigh, stats.ofld_cong_defer);

err1:
	free(dc_buff.data);
err:
	return rc;
}

int view_tcp_stats(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		   enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct struct_tcp_stats *tcp_stats_buff;
	int rc = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	tcp_stats_buff = (struct struct_tcp_stats *) dc_buff.data;

	cudbg_printf(cudbg_poutbuf, err1, "                                IP"\
		     "                 IPv6\n");
	cudbg_printf(cudbg_poutbuf, err1, "OutRsts:      %20u %20u\n",
		     tcp_stats_buff->v4.tcp_out_rsts,
		     tcp_stats_buff->v6.tcp_out_rsts);
	cudbg_printf(cudbg_poutbuf, err1, "InSegs:       %20llu %20llu\n",
		     (unsigned long long)(tcp_stats_buff->v4.tcp_in_segs),
		     (unsigned long long)(tcp_stats_buff->v6.tcp_in_segs));
	cudbg_printf(cudbg_poutbuf, err1, "OutSegs:      %20llu %20llu\n",
		     (unsigned long long)(tcp_stats_buff->v4.tcp_out_segs),
		     (unsigned long long)(tcp_stats_buff->v6.tcp_out_segs));
	cudbg_printf(cudbg_poutbuf, err1, "RetransSegs:  %20llu %20llu\n",
		     (unsigned long long)(tcp_stats_buff->v4.tcp_retrans_segs),
		     (unsigned long long)(tcp_stats_buff->v6.tcp_retrans_segs));

err1:
	free(dc_buff.data);
err:
	return rc;
}

int view_hw_sched(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		  enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	int rc = 0;
	int i;
	struct struct_hw_sched *hw_sched_buff;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	hw_sched_buff = (struct struct_hw_sched *)dc_buff.data;

	cudbg_printf(cudbg_poutbuf, err1, "Scheduler  Mode   Channel  Rate "\
		     "(Kbps)   Class IPG (0.1 ns)   Flow IPG (us)\n");

	for (i = 0; i < NTX_SCHED; ++i, hw_sched_buff->map >>= 2) {
		cudbg_printf(cudbg_poutbuf, err1, "    %u      %-5s     %u"\
			     "     ", i,
			     (hw_sched_buff->mode & (1 << i)) ?
			     "flow" : "class",
			     hw_sched_buff->map & 3);
		if (hw_sched_buff->kbps[i]) {
			cudbg_printf(cudbg_poutbuf, err1, "%9u     ",
				     hw_sched_buff->kbps[i]);
		} else {
			cudbg_printf(cudbg_poutbuf, err1, " disabled     ");
		}

		if (hw_sched_buff->ipg[i]) {
			cudbg_printf(cudbg_poutbuf, err1, "%13u        ",
				     hw_sched_buff->ipg[i]);
		} else {
			cudbg_printf(cudbg_poutbuf, err1, "     disabled    "\
				     "    ");
		}

		if (hw_sched_buff->pace_tab[i]) {
			cudbg_printf(cudbg_poutbuf, err1, "%10u\n",
				     hw_sched_buff->pace_tab[i]);
		} else {
			cudbg_printf(cudbg_poutbuf, err1, "  disabled\n");
		}
	}

err1:
	free(dc_buff.data);
err:
	return rc;
}

int view_pm_stats(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		  enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct struct_pm_stats *pm_stats_buff;
	int i, rc = 0;

	static const char * const tx_pm_stats[] = {
		"Read:", "Write bypass:", "Write mem:", "Bypass + mem:"
	};
	static const char * const rx_pm_stats[] = {
		"Read:", "Write bypass:", "Write mem:", "Flush:"
	};

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	pm_stats_buff = (struct struct_pm_stats *)dc_buff.data;

	cudbg_printf(cudbg_poutbuf, err1, "%13s %10s  %20s\n", " ", "Tx pcmds",
		     "Tx bytes");
	for (i = 0; i < PM_NSTATS - 1; i++)
		cudbg_printf(cudbg_poutbuf, err1, "%-13s %10u  %20llu\n",
			     tx_pm_stats[i], pm_stats_buff->tx_cnt[i],
			     pm_stats_buff->tx_cyc[i]);

	cudbg_printf(cudbg_poutbuf, err1, "%13s %10s  %20s\n", " ", "Rx pcmds",
		     "Rx bytes");
	for (i = 0; i < PM_NSTATS - 1; i++)
		cudbg_printf(cudbg_poutbuf, err1, "%-13s %10u  %20llu\n",
			     rx_pm_stats[i], pm_stats_buff->rx_cnt[i],
			     pm_stats_buff->rx_cyc[i]);

	if (CHELSIO_CHIP_VERSION(chip) > CHELSIO_T5) {
		/* In T5 the granularity of the total wait is too fine.
		 * It is not useful as it reaches the max value too fast.
		 * Hence display this Input FIFO wait for T6 onwards.
		 */
		cudbg_printf(cudbg_poutbuf, err1, "%13s %10s  %20s\n",
			   " ", "Total wait", "Total Occupancy");
		cudbg_printf(cudbg_poutbuf, err1, "Tx FIFO wait  "
			     "%10u  %20llu\n", pm_stats_buff->tx_cnt[i],
			     pm_stats_buff->tx_cyc[i]);
		cudbg_printf(cudbg_poutbuf, err1, "Rx FIFO wait  %10u  "
			     "%20llu\n", pm_stats_buff->rx_cnt[i],
			     pm_stats_buff->rx_cyc[i]);

		/* Skip index 6 as there is nothing useful here */
		i += 2;

		/* At index 7, a new stat for read latency (count, total wait)
		 * is added.
		 */
		cudbg_printf(cudbg_poutbuf, err1, "%13s %10s  %20s\n",
			     " ", "Reads", "Total wait");
		cudbg_printf(cudbg_poutbuf, err1, "Tx latency    "
			     "%10u  %20llu\n", pm_stats_buff->tx_cnt[i],
			     pm_stats_buff->tx_cyc[i]);
		cudbg_printf(cudbg_poutbuf, err1, "Rx latency    "
			     "%10u  %20llu\n", pm_stats_buff->rx_cnt[i],
			     pm_stats_buff->rx_cyc[i]);
	}

err1:
	free(dc_buff.data);
err:
	return rc;
}

int view_path_mtu(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		  enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	int rc = 0;
	u16 *mtus;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	mtus = (u16 *)dc_buff.data;
	cudbg_printf(cudbg_poutbuf, err1, "%u %u %u %u %u %u %u %u %u %u %u %u"\
		     " %u %u %u %u\n",
		     mtus[0], mtus[1], mtus[2], mtus[3], mtus[4], mtus[5],
		     mtus[6], mtus[7], mtus[8], mtus[9], mtus[10], mtus[11],
		     mtus[12], mtus[13], mtus[14], mtus[15]);
err1:
	free(dc_buff.data);
err:
	return rc;
}

int view_rss_config(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		    enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct rss_config *struct_rss_conf;
	u32 rssconf;
	int rc = 0;

	static const char * const keymode[] = {
		"global",
		"global and per-VF scramble",
		"per-PF and per-VF scramble",
		"per-VF and per-VF scramble",
	};

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	struct_rss_conf = (struct rss_config *)dc_buff.data;

	rssconf = struct_rss_conf->tp_rssconf;

	cudbg_printf(cudbg_poutbuf, err1, "TP_RSS_CONFIG: %#x\n", rssconf);
	cudbg_printf(cudbg_poutbuf, err1, "  Tnl4TupEnIpv6: %3s\n",
		     yesno(rssconf & F_TNL4TUPENIPV6));
	cudbg_printf(cudbg_poutbuf, err1, "  Tnl2TupEnIpv6: %3s\n",
		     yesno(rssconf & F_TNL2TUPENIPV6));
	cudbg_printf(cudbg_poutbuf, err1, "  Tnl4TupEnIpv4: %3s\n",
		     yesno(rssconf & F_TNL4TUPENIPV4));
	cudbg_printf(cudbg_poutbuf, err1, "  Tnl2TupEnIpv4: %3s\n",
		     yesno(rssconf & F_TNL2TUPENIPV4));
	cudbg_printf(cudbg_poutbuf, err1, "  TnlTcpSel:     %3s\n",
		     yesno(rssconf & F_TNLTCPSEL));
	cudbg_printf(cudbg_poutbuf, err1, "  TnlIp6Sel:     %3s\n",
		     yesno(rssconf & F_TNLIP6SEL));
	cudbg_printf(cudbg_poutbuf, err1, "  TnlVrtSel:     %3s\n",
		     yesno(rssconf & F_TNLVRTSEL));
	cudbg_printf(cudbg_poutbuf, err1, "  TnlMapEn:      %3s\n",
		     yesno(rssconf & F_TNLMAPEN));
	cudbg_printf(cudbg_poutbuf, err1, "  OfdHashSave:   %3s\n",
		     yesno(rssconf & F_OFDHASHSAVE));
	cudbg_printf(cudbg_poutbuf, err1, "  OfdVrtSel:     %3s\n",
		     yesno(rssconf & F_OFDVRTSEL));
	cudbg_printf(cudbg_poutbuf, err1, "  OfdMapEn:      %3s\n",
		     yesno(rssconf & F_OFDMAPEN));
	cudbg_printf(cudbg_poutbuf, err1, "  OfdLkpEn:      %3s\n",
		     yesno(rssconf & F_OFDLKPEN));
	cudbg_printf(cudbg_poutbuf, err1, "  Syn4TupEnIpv6: %3s\n",
		     yesno(rssconf & F_SYN4TUPENIPV6));
	cudbg_printf(cudbg_poutbuf, err1, "  Syn2TupEnIpv6: %3s\n",
		     yesno(rssconf & F_SYN2TUPENIPV6));
	cudbg_printf(cudbg_poutbuf, err1, "  Syn4TupEnIpv4: %3s\n",
		     yesno(rssconf & F_SYN4TUPENIPV4));
	cudbg_printf(cudbg_poutbuf, err1, "  Syn2TupEnIpv4: %3s\n",
		     yesno(rssconf & F_SYN2TUPENIPV4));
	cudbg_printf(cudbg_poutbuf, err1, "  Syn4TupEnIpv6: %3s\n",
		     yesno(rssconf & F_SYN4TUPENIPV6));
	cudbg_printf(cudbg_poutbuf, err1, "  SynIp6Sel:     %3s\n",
		     yesno(rssconf & F_SYNIP6SEL));
	cudbg_printf(cudbg_poutbuf, err1, "  SynVrt6Sel:    %3s\n",
		     yesno(rssconf & F_SYNVRTSEL));
	cudbg_printf(cudbg_poutbuf, err1, "  SynMapEn:      %3s\n",
		     yesno(rssconf & F_SYNMAPEN));
	cudbg_printf(cudbg_poutbuf, err1, "  SynLkpEn:      %3s\n",
		     yesno(rssconf & F_SYNLKPEN));
	cudbg_printf(cudbg_poutbuf, err1, "  ChnEn:         %3s\n",
		     yesno(rssconf & F_CHANNELENABLE));
	cudbg_printf(cudbg_poutbuf, err1, "  PrtEn:         %3s\n",
		     yesno(rssconf & F_PORTENABLE));
	cudbg_printf(cudbg_poutbuf, err1, "  TnlAllLkp:     %3s\n",
		     yesno(rssconf & F_TNLALLLOOKUP));
	cudbg_printf(cudbg_poutbuf, err1, "  VrtEn:         %3s\n",
		     yesno(rssconf & F_VIRTENABLE));
	cudbg_printf(cudbg_poutbuf, err1, "  CngEn:         %3s\n",
		     yesno(rssconf & F_CONGESTIONENABLE));
	cudbg_printf(cudbg_poutbuf, err1, "  HashToeplitz:  %3s\n",
		     yesno(rssconf & F_HASHTOEPLITZ));
	cudbg_printf(cudbg_poutbuf, err1, "  Udp4En:        %3s\n",
		     yesno(rssconf & F_UDPENABLE));
	cudbg_printf(cudbg_poutbuf, err1, "  Disable:       %3s\n",
		     yesno(rssconf & F_DISABLE));

	rssconf = struct_rss_conf->tp_rssconf_tnl;

	cudbg_printf(cudbg_poutbuf, err1, "TP_RSS_CONFIG_TNL: %#x\n",
		     rssconf);
	cudbg_printf(cudbg_poutbuf, err1, "  MaskSize:      %3d\n",
		     G_MASKSIZE(rssconf));
	cudbg_printf(cudbg_poutbuf, err1, "  MaskFilter:    %3d\n",
		     G_MASKFILTER(rssconf));
	if (CHELSIO_CHIP_VERSION(struct_rss_conf->chip) > CHELSIO_T5) {
		cudbg_printf(cudbg_poutbuf, err1, "  HashAll:     %3s\n",
			     yesno(rssconf & F_HASHALL));
		cudbg_printf(cudbg_poutbuf, err1, "  HashEth:     %3s\n",
			     yesno(rssconf & F_HASHETH));
	}
	cudbg_printf(cudbg_poutbuf, err1, "  UseWireCh:     %3s\n",
		     yesno(rssconf & F_USEWIRECH));

	rssconf = struct_rss_conf->tp_rssconf_ofd;

	cudbg_printf(cudbg_poutbuf, err1, "TP_RSS_CONFIG_OFD: %#x\n",
		     rssconf);
	cudbg_printf(cudbg_poutbuf, err1, "  MaskSize:      %3d\n",
		     G_MASKSIZE(rssconf));
	cudbg_printf(cudbg_poutbuf, err1, "  RRCplMapEn:    %3s\n",
		     yesno(rssconf & F_RRCPLMAPEN));
	cudbg_printf(cudbg_poutbuf, err1, "  RRCplQueWidth: %3d\n",
		     G_RRCPLQUEWIDTH(rssconf));

	rssconf = struct_rss_conf->tp_rssconf_syn;

	cudbg_printf(cudbg_poutbuf, err1, "TP_RSS_CONFIG_SYN: %#x\n",
		     rssconf);
	cudbg_printf(cudbg_poutbuf, err1, "  MaskSize:      %3d\n",
		     G_MASKSIZE(rssconf));
	cudbg_printf(cudbg_poutbuf, err1, "  UseWireCh:     %3s\n",
		     yesno(rssconf & F_USEWIRECH));

	rssconf = struct_rss_conf->tp_rssconf_vrt;

	cudbg_printf(cudbg_poutbuf, err1, "TP_RSS_CONFIG_VRT: %#x\n",
		     rssconf);
	if (CHELSIO_CHIP_VERSION(struct_rss_conf->chip) > CHELSIO_T5) {
		cudbg_printf(cudbg_poutbuf, err1, "  KeyWrAddrX:     %3d\n",
			     G_KEYWRADDRX(rssconf));
		cudbg_printf(cudbg_poutbuf, err1, "  KeyExtend:      %3s\n",
			     yesno(rssconf & F_KEYEXTEND));
	}
	cudbg_printf(cudbg_poutbuf, err1, "  VfRdRg:        %3s\n",
		     yesno(rssconf & F_VFRDRG));
	cudbg_printf(cudbg_poutbuf, err1, "  VfRdEn:        %3s\n",
		     yesno(rssconf & F_VFRDEN));
	cudbg_printf(cudbg_poutbuf, err1, "  VfPerrEn:      %3s\n",
		     yesno(rssconf & F_VFPERREN));
	cudbg_printf(cudbg_poutbuf, err1, "  KeyPerrEn:     %3s\n",
		     yesno(rssconf & F_KEYPERREN));
	cudbg_printf(cudbg_poutbuf, err1, "  DisVfVlan:     %3s\n",
		     yesno(rssconf & F_DISABLEVLAN));
	cudbg_printf(cudbg_poutbuf, err1, "  EnUpSwt:       %3s\n",
		     yesno(rssconf & F_ENABLEUP0));
	cudbg_printf(cudbg_poutbuf, err1, "  HashDelay:     %3d\n",
		     G_HASHDELAY(rssconf));
	if (CHELSIO_CHIP_VERSION(struct_rss_conf->chip) <= CHELSIO_T5) {
		cudbg_printf(cudbg_poutbuf, err1, "  VfWrAddr:      %3d\n",
			     G_VFWRADDR(rssconf));
	} else {
		cudbg_printf(cudbg_poutbuf, err1, "  VfWrAddr:      %3d\n",
			     G_T6_VFWRADDR(rssconf));
	}
	cudbg_printf(cudbg_poutbuf, err1, "  KeyMode:       %s\n",
		     keymode[G_KEYMODE(rssconf)]);
	cudbg_printf(cudbg_poutbuf, err1, "  VfWrEn:        %3s\n",
		     yesno(rssconf & F_VFWREN));
	cudbg_printf(cudbg_poutbuf, err1, "  KeyWrEn:       %3s\n",
		     yesno(rssconf & F_KEYWREN));
	cudbg_printf(cudbg_poutbuf, err1, "  KeyWrAddr:     %3d\n",
		     G_KEYWRADDR(rssconf));

	rssconf = struct_rss_conf->tp_rssconf_cng;

	cudbg_printf(cudbg_poutbuf, err1, "TP_RSS_CONFIG_CNG: %#x\n",
		     rssconf);
	cudbg_printf(cudbg_poutbuf, err1, "  ChnCount3:     %3s\n",
		     yesno(rssconf & F_CHNCOUNT3));
	cudbg_printf(cudbg_poutbuf, err1, "  ChnCount2:     %3s\n",
		     yesno(rssconf & F_CHNCOUNT2));
	cudbg_printf(cudbg_poutbuf, err1, "  ChnCount1:     %3s\n",
		     yesno(rssconf & F_CHNCOUNT1));
	cudbg_printf(cudbg_poutbuf, err1, "  ChnCount0:     %3s\n",
		     yesno(rssconf & F_CHNCOUNT0));
	cudbg_printf(cudbg_poutbuf, err1, "  ChnUndFlow3:   %3s\n",
		     yesno(rssconf & F_CHNUNDFLOW3));
	cudbg_printf(cudbg_poutbuf, err1, "  ChnUndFlow2:   %3s\n",
		     yesno(rssconf & F_CHNUNDFLOW2));
	cudbg_printf(cudbg_poutbuf, err1, "  ChnUndFlow1:   %3s\n",
		     yesno(rssconf & F_CHNUNDFLOW1));
	cudbg_printf(cudbg_poutbuf, err1, "  ChnUndFlow0:   %3s\n",
		     yesno(rssconf & F_CHNUNDFLOW0));
	cudbg_printf(cudbg_poutbuf, err1, "  RstChn3:       %3s\n",
		     yesno(rssconf & F_RSTCHN3));
	cudbg_printf(cudbg_poutbuf, err1, "  RstChn2:       %3s\n",
		     yesno(rssconf & F_RSTCHN2));
	cudbg_printf(cudbg_poutbuf, err1, "  RstChn1:       %3s\n",
		     yesno(rssconf & F_RSTCHN1));
	cudbg_printf(cudbg_poutbuf, err1, "  RstChn0:       %3s\n",
		     yesno(rssconf & F_RSTCHN0));
	cudbg_printf(cudbg_poutbuf, err1, "  UpdVld:        %3s\n",
		     yesno(rssconf & F_UPDVLD));
	cudbg_printf(cudbg_poutbuf, err1, "  Xoff:          %3s\n",
		     yesno(rssconf & F_XOFF));
	cudbg_printf(cudbg_poutbuf, err1, "  UpdChn3:       %3s\n",
		     yesno(rssconf & F_UPDCHN3));
	cudbg_printf(cudbg_poutbuf, err1, "  UpdChn2:       %3s\n",
		     yesno(rssconf & F_UPDCHN2));
	cudbg_printf(cudbg_poutbuf, err1, "  UpdChn1:       %3s\n",
		     yesno(rssconf & F_UPDCHN1));
	cudbg_printf(cudbg_poutbuf, err1, "  UpdChn0:       %3s\n",
		     yesno(rssconf & F_UPDCHN0));
	cudbg_printf(cudbg_poutbuf, err1, "  Queue:         %3d\n",
		     G_QUEUE(rssconf));

err1:
	free(dc_buff.data);
err:
	return rc;
}

int view_rss_key(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		 enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	u32 *key;
	int rc = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	key = (u32 *)dc_buff.data;
	cudbg_printf(cudbg_poutbuf, err1,
		     "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x\n",
		     key[9], key[8], key[7], key[6], key[5], key[4],
		     key[3], key[2], key[1], key[0]);

err1:
	free(dc_buff.data);
err:
	return rc;
}

int view_rss_vf_config(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		       enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct rss_vf_conf *vfconf;
	int i, rc = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	vfconf = (struct rss_vf_conf *) dc_buff.data;

	cudbg_printf(cudbg_poutbuf, err1, "     RSS                     Hash "\
		     "Tuple Enable\n");
	cudbg_printf(cudbg_poutbuf, err1, "     Enable   IVF  Dis  Enb  IPv6 "\
		     "     IPv4      UDP    Def  Secret Key\n");
	cudbg_printf(cudbg_poutbuf, err1, " VF  Chn Prt  Map  VLAN  uP  Four "\
		     "Two  Four Two  Four   Que  Idx       Hash\n");

	for (i = 0; i < dc_buff.offset/sizeof(*vfconf); i += 1) {
		cudbg_printf(cudbg_poutbuf, err1, "%3d  %3s %3s  %3d   %3s %3s"\
			     "   %3s %3s   %3s %3s   %3s  %4d  %3d %#10x\n",
			     i, yesno(vfconf->rss_vf_vfh & F_VFCHNEN),
			     yesno(vfconf->rss_vf_vfh & F_VFPRTEN),
			     G_VFLKPIDX(vfconf->rss_vf_vfh),
			     yesno(vfconf->rss_vf_vfh & F_VFVLNEX),
			     yesno(vfconf->rss_vf_vfh & F_VFUPEN),
			     yesno(vfconf->rss_vf_vfh & F_VFIP4FOURTUPEN),
			     yesno(vfconf->rss_vf_vfh & F_VFIP6TWOTUPEN),
			     yesno(vfconf->rss_vf_vfh & F_VFIP4FOURTUPEN),
			     yesno(vfconf->rss_vf_vfh & F_VFIP4TWOTUPEN),
			     yesno(vfconf->rss_vf_vfh & F_ENABLEUDPHASH),
			     G_DEFAULTQUEUE(vfconf->rss_vf_vfh),
			     G_KEYINDEX(vfconf->rss_vf_vfh),
			     vfconf->rss_vf_vfl);

		vfconf++;
	}

err1:
	free(dc_buff.data);
err:
	return rc;
}

int view_rss_pf_config(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		       enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct rss_pf_conf *pfconf;
	int i, rc = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	pfconf = (struct rss_pf_conf *) dc_buff.data;

	cudbg_printf(cudbg_poutbuf, err1, "PF Map Index Size = %d\n\n",
		     G_LKPIDXSIZE(pfconf->rss_pf_map));

	cudbg_printf(cudbg_poutbuf, err1, "     RSS              PF   VF    "\
		     "Hash Tuple Enable         Default\n");
	cudbg_printf(cudbg_poutbuf, err1, "     Enable       IPF Mask Mask  "\
		     "IPv6      IPv4      UDP   Queue\n");
	cudbg_printf(cudbg_poutbuf, err1, " PF  Map Chn Prt  Map Size Size  "\
		     "Four Two  Four Two  Four  Ch1  Ch0\n");

#define G_PFnLKPIDX(map, n) \
	(((map) >> S_PF1LKPIDX*(n)) & M_PF0LKPIDX)
#define G_PFnMSKSIZE(mask, n) \
	(((mask) >> S_PF1MSKSIZE*(n)) & M_PF1MSKSIZE)

	for (i = 0; i < dc_buff.offset/sizeof(*pfconf); i += 1) {

		cudbg_printf(cudbg_poutbuf, err1, "%3d  %3s %3s %3s  %3d  %3d"\
			     "  %3d   %3s %3s   %3s %3s   %3s  %3d  %3d\n",
			     i, yesno(pfconf->rss_pf_config & F_MAPENABLE),
			     yesno(pfconf->rss_pf_config & F_CHNENABLE),
			     yesno(pfconf->rss_pf_config & F_PRTENABLE),
			     G_PFnLKPIDX(pfconf->rss_pf_map, i),
			     G_PFnMSKSIZE(pfconf->rss_pf_mask, i),
			     G_IVFWIDTH(pfconf->rss_pf_config),
			     yesno(pfconf->rss_pf_config & F_IP6FOURTUPEN),
			     yesno(pfconf->rss_pf_config & F_IP6TWOTUPEN),
			     yesno(pfconf->rss_pf_config & F_IP4FOURTUPEN),
			     yesno(pfconf->rss_pf_config & F_IP4TWOTUPEN),
			     yesno(pfconf->rss_pf_config & F_UDPFOURTUPEN),
			     G_CH1DEFAULTQUEUE(pfconf->rss_pf_config),
			     G_CH0DEFAULTQUEUE(pfconf->rss_pf_config));

		pfconf++;

	}
#undef G_PFnLKPIDX
#undef G_PFnMSKSIZE
err1:
	free(dc_buff.data);
err:
	return rc;
}

int view_rss(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
	     enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	u16 *pdata = NULL;
	int rc = 0;
	u32 i;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	pdata = (u16 *) dc_buff.data;

	for (i = 0; i < dc_buff.offset / 2; i += 8) {
		cudbg_printf(cudbg_poutbuf, err1, "%4d:  %4u  %4u  %4u  %4u  "\
			     "%4u  %4u  %4u  %4u\n",
			     i, pdata[i + 0], pdata[i + 1], pdata[i + 2],
			     pdata[i + 3], pdata[i + 4], pdata[i + 5],
			     pdata[i + 6], pdata[i + 7]);
	}

err1:
	free(dc_buff.data);
err:
	return rc;
}

int view_fw_devlog(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		   enum chip_type chip)
{
	struct fw_devlog_e *e;
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct fw_devlog_e *devlog;
	unsigned long index;
	u32 num_entries = 0;
	u32 first_entry = 0;
	int rc = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	translate_fw_devlog(dc_buff.data, dc_buff.offset,
			&num_entries, &first_entry);

	devlog = (struct fw_devlog_e *)(dc_buff.data);
	cudbg_printf(cudbg_poutbuf, err1, "%10s  %15s  %8s  %8s  %s\n",
		     "Seq#", "Tstamp", "Level", "Facility", "Message");
	for (index = first_entry; ;) {
		if (index >= num_entries)
			index -= num_entries;

		e = &devlog[index++];
		if ((e->timestamp == 0) || (index == first_entry))
			break;
		cudbg_printf(cudbg_poutbuf, err1, "%10d  %15llu  %8s  %8s  ",
			     e->seqno, e->timestamp,
			     (e->level < ARRAY_SIZE(devlog_level_strings)
			      ? devlog_level_strings[e->level] : "UNKNOWN"),
			     (e->facility < ARRAY_SIZE(devlog_facility_strings)
			      ? devlog_facility_strings[e->facility]
			      : "UNKNOWN"));
		cudbg_printf(cudbg_poutbuf, err1, (const char *)e->fmt,
			     e->params[0], e->params[1], e->params[2],
			     e->params[3], e->params[4], e->params[5],
			     e->params[6], e->params[7]);
	}

err1:
	free(dc_buff.data);
err:
	return rc;
}

void translate_fw_devlog(void *pbuf, u32 io_size,
		u32 *num_entries, u32 *first_entry)
{
	struct fw_devlog_e  *e = NULL;
	u64 ftstamp;
	u32 index;

	*num_entries = (io_size / sizeof(struct fw_devlog_e));

	*first_entry = 0;

	e = (struct fw_devlog_e *)pbuf;
	for (ftstamp = ~0ULL, index = 0; index < *num_entries; index++) {
		int i;

		if (e->timestamp == 0)
			continue;

		e->timestamp = NTOHLL(e->timestamp);
		e->seqno = ntohl(e->seqno);

		for (i = 0; i < 8; i++)
			e->params[i] = ntohl(e->params[i]);

		if (e->timestamp < ftstamp) {
			ftstamp = e->timestamp;
			*first_entry = index;
		}

		e++;
	}
}

/* Regdump function */

static inline uint32_t xtract(uint32_t val, int shift, int len)
{
	return (val >> shift) & ((1L << len) - 1);
}

static int dump_block_regs(const struct reg_info *reg_array, const u32 *regs,
			   struct cudbg_buffer *cudbg_poutbuf)
{
	uint32_t reg_val = 0; /* silence compiler warning*/
	int rc = 0;
	for (; reg_array->name; ++reg_array) {
		if (!reg_array->len) {
			reg_val = regs[reg_array->addr / 4];
			cudbg_printf(cudbg_poutbuf, err1, "[%#7x] %-47s %#-10x"\
				     " %u\n", reg_array->addr, reg_array->name,
				     reg_val, reg_val);
		} else {
			uint32_t v = xtract(reg_val, reg_array->addr,
					reg_array->len);
			cudbg_printf(cudbg_poutbuf, err1, "    %*u:%u %-47s "\
				     "%#-10x %u\n",
				     reg_array->addr < 10 ? 3 : 2,
				     reg_array->addr + reg_array->len - 1,
				     reg_array->addr, reg_array->name, v, v);
		}
	}

	return 1;
err1:
	return rc;
}

static int dump_regs_table(const u32 *regs, const struct mod_regs *modtab,
			   int nmodules, const char *modnames,
			   struct cudbg_buffer *cudbg_poutbuf)
{
	int match = 0;
	int rc = 0;
	for (; nmodules; nmodules--, modtab++) {
		rc = dump_block_regs(modtab->ri,
				regs + modtab->offset, cudbg_poutbuf);
		if (rc < 0)
			goto err1;
		match += rc;
	}

err1:
	return rc;
}

#define T6_MODREGS(name) { #name, t6_##name##_regs }
static int dump_regs_t6(const u32 *regs, struct cudbg_buffer *cudbg_poutbuf)
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

	return dump_regs_table(regs, t6_mod,
			ARRAY_SIZE(t6_mod),
			"sge, pci, dbg, mc0, ma, edc0, edc1, cim, "\
			"tp, ulprx, ulptx, pmrx, pmtx, mps, cplsw, smb, "\
			"i2c, mi, uart, pmu, sf, pl, le, ncsi, "\
			"mac, hma", cudbg_poutbuf);
}
#undef T6_MODREGS

#define T5_MODREGS(name) { #name, t5_##name##_regs }

static int dump_regs_t5(const u32 *regs, struct cudbg_buffer *cudbg_poutbuf)
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
	return dump_regs_table(regs, t5_mod,
			ARRAY_SIZE(t5_mod),
			"sge, pci, dbg, mc0, mc1, ma, edc0, edc1, cim, "\
			"tp, ulprx, ulptx, pmrx, pmtx, mps, cplsw, smb, "\
			"i2c, mi, uart, pmu, sf, pl, le, ncsi, "\
			"mac, hma", cudbg_poutbuf);
}
#undef T5_MODREGS

int view_reg_dump(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		  enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	int rc = 0;
	u32 *regs;
	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;
	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;
	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	regs = (u32 *) ((unsigned int *)dc_buff.data);
	if (CHELSIO_CHIP_VERSION(chip) <= CHELSIO_T5)
		rc =  dump_regs_t5((u32 *)regs, cudbg_poutbuf);
	else if (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T6)
		rc = dump_regs_t6((u32 *)regs, cudbg_poutbuf);
err1:
	free(dc_buff.data);
err:
	return rc;
}

static int t6_view_wtp(char *pbuf, u32 size,
		       struct cudbg_buffer *cudbg_poutbuf)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct wtp_data *wtp = NULL;
	int rc = 0;
	int i = 0;
	/****Rx****/
	u32 pcie_core_dmaw_sop = 0;
	u32 sge_pcie_sop = 0;
	u32 csw_sge_sop = 0;
	u32 tp_csw_sop = 0;
	u32 tpcside_csw_sop = 0;
	u32 ulprx_tpcside_sop = 0;
	u32 pmrx_ulprx_sop = 0;
	u32 mps_tpeside_sop = 0;
	u32 mps_tp_sop = 0;
	u32 xgm_mps_sop = 0;
	u32 rx_xgm_xgm_sop = 0;
	u32 wire_xgm_sop = 0;
	u32 rx_wire_macok_sop = 0;

	u32 pcie_core_dmaw_eop = 0;
	u32 sge_pcie_eop = 0;
	u32 csw_sge_eop = 0;
	u32 tp_csw_eop = 0;
	u32 tpcside_csw_eop = 0;
	u32 ulprx_tpcside_eop = 0;
	u32 pmrx_ulprx_eop = 0;
	u32 mps_tpeside_eop = 0;
	u32 mps_tp_eop = 0;
	u32 xgm_mps_eop = 0;
	u32 rx_xgm_xgm_eop = 0;
	u32 wire_xgm_eop = 0;
	u32 rx_wire_macok_eop = 0;

	/****Tx****/
	u32 core_pcie_dma_rsp_sop = 0;
	u32 pcie_sge_dma_rsp_sop = 0;
	u32 sge_debug_index6_sop = 0;
	u32 sge_utx_sop = 0;
	u32 utx_tp_sop = 0;
	u32 sge_work_req_sop = 0;
	u32 utx_tpcside_sop = 0;
	u32 tpcside_rxarb_sop = 0;
	u32 tpeside_mps_sop = 0;
	u32 tp_mps_sop = 0;
	u32 mps_xgm_sop = 0;
	u32 tx_xgm_xgm_sop = 0;
	u32 xgm_wire_sop = 0;
	u32 tx_macok_wire_sop = 0;

	u32 core_pcie_dma_rsp_eop = 0;
	u32 pcie_sge_dma_rsp_eop = 0;
	u32 sge_debug_index6_eop = 0;
	u32 sge_utx_eop = 0;
	u32 utx_tp_eop = 0;
	u32 utx_tpcside_eop = 0;
	u32 tpcside_rxarb_eop = 0;
	u32 tpeside_mps_eop = 0;
	u32 tp_mps_eop = 0;
	u32 mps_xgm_eop = 0;
	u32 tx_xgm_xgm_eop = 0;
	u32 xgm_wire_eop = 0;
	u32 tx_macok_wire_eop = 0;

	u32 pcie_core_cmd_req_sop = 0;
	u32 sge_pcie_cmd_req_sop = 0;
	u32 core_pcie_cmd_rsp_sop = 0;
	u32 pcie_sge_cmd_rsp_sop = 0;
	u32 sge_cim_sop = 0;
	u32 pcie_core_dma_req_sop = 0;
	u32 sge_pcie_dma_req_sop = 0;
	u32 utx_sge_dma_req_sop = 0;

	u32 sge_pcie_cmd_req_eop = 0;
	u32 pcie_core_cmd_req_eop = 0;
	u32 core_pcie_cmd_rsp_eop = 0;
	u32 pcie_sge_cmd_rsp_eop = 0;
	u32 sge_cim_eop = 0;
	u32 pcie_core_dma_req_eop = 0;
	u32 sge_pcie_dma_req_eop = 0;
	u32 utx_sge_dma_req_eop = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);

	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	wtp = (struct wtp_data *) dc_buff.data;

	/*Add up the sop/eop of all channels.*/
	for (i = 0; i < 8; i++) {
		if (i < 2) {
			/*Rx Path*/
			csw_sge_sop           +=
				(wtp->sge_debug_data_high_indx1.sop[i]);
			tp_csw_sop            +=
				(wtp->sge_debug_data_high_indx9.sop[i]);

			csw_sge_eop           += (wtp->csw_sge.eop[i]);
			tp_csw_eop            += (wtp->tp_csw.eop[i]);
			rx_wire_macok_sop     +=
				wtp->mac_porrx_etherstatspkts.sop[i];
			rx_wire_macok_eop     +=
				wtp->mac_porrx_etherstatspkts.eop[i];

			/*Tx Path*/
			sge_pcie_cmd_req_sop  += wtp->sge_pcie_cmd_req.sop[i];
			pcie_sge_cmd_rsp_sop  += wtp->pcie_sge_cmd_rsp.sop[i];
			sge_cim_sop           += wtp->sge_cim.sop[i];
			tpcside_csw_sop       += (wtp->utx_tpcside_tx.sop[i]);
			sge_work_req_sop      += wtp->sge_work_req_pkt.sop[i];
			tx_macok_wire_sop     +=
				wtp->mac_portx_etherstatspkts.sop[i];
			tx_macok_wire_eop     +=
				wtp->mac_portx_etherstatspkts.eop[i];

			sge_pcie_cmd_req_eop  += wtp->sge_pcie_cmd_req.eop[i];
			pcie_sge_cmd_rsp_eop  += wtp->pcie_sge_cmd_rsp.eop[i];
			sge_cim_eop           += wtp->sge_cim.eop[i];

		}

		if (i < 3) {
			pcie_core_cmd_req_sop += wtp->pcie_cmd_stat2.sop[i];
			core_pcie_cmd_rsp_sop += wtp->pcie_cmd_stat3.sop[i];

			core_pcie_cmd_rsp_eop += wtp->pcie_cmd_stat3.eop[i];
			pcie_core_cmd_req_eop += wtp->pcie_cmd_stat2.eop[i];
		}

		if (i < 4) {
			/*Rx Path*/
			pcie_core_dmaw_sop    +=
				(wtp->pcie_dma1_stat2.sop[i]);
			sge_pcie_sop          +=
				(wtp->sge_debug_data_high_indx7.sop[i]);
			ulprx_tpcside_sop     += (wtp->ulprx_tpcside.sop[i]);
			pmrx_ulprx_sop        += (wtp->pmrx_ulprx.sop[i]);
			mps_tpeside_sop       +=
				(wtp->tp_dbg_eside_pktx.sop[i]);
			rx_xgm_xgm_sop        +=
				(wtp->mac_porrx_pkt_count.sop[i]);
			wire_xgm_sop          +=
				(wtp->mac_porrx_aframestra_ok.sop[i]);

			pcie_core_dmaw_eop    +=
				(wtp->pcie_dma1_stat2.eop[i]);
			sge_pcie_eop          += (wtp->sge_pcie.eop[i]);
			tpcside_csw_eop       += (wtp->tpcside_csw.eop[i]);
			ulprx_tpcside_eop     += (wtp->ulprx_tpcside.eop[i]);
			pmrx_ulprx_eop        += (wtp->pmrx_ulprx.eop[i]);
			mps_tpeside_eop       += (wtp->mps_tpeside.eop[i]);
			rx_xgm_xgm_eop        +=
				(wtp->mac_porrx_pkt_count.eop[i]);
			wire_xgm_eop          +=
				(wtp->mac_porrx_aframestra_ok.eop[i]);

			/*special case type 3:*/
			mps_tp_sop            += (wtp->mps_tp.sop[i]);
			mps_tp_eop            += (wtp->mps_tp.eop[i]);

			/*Tx Path*/
			core_pcie_dma_rsp_sop +=
				wtp->pcie_t5_dma_stat3.sop[i];
			pcie_sge_dma_rsp_sop  += wtp->pcie_sge_dma_rsp.sop[i];
			sge_debug_index6_sop  +=
				wtp->sge_debug_data_high_index_6.sop[i];
			sge_utx_sop           += wtp->ulp_se_cnt_chx.sop[i];
			utx_tp_sop            += wtp->utx_tp.sop[i];
			utx_tpcside_sop       += wtp->utx_tpcside.sop[i];
			tpcside_rxarb_sop     += wtp->tpcside_rxarb.sop[i];
			tpeside_mps_sop       += wtp->tpeside_mps.sop[i];
			tx_xgm_xgm_sop        +=
				wtp->mac_portx_pkt_count.sop[i];
			xgm_wire_sop          +=
				wtp->mac_portx_aframestra_ok.sop[i];

			core_pcie_dma_rsp_eop +=
				wtp->pcie_t5_dma_stat3.eop[i];
			pcie_sge_dma_rsp_eop  += wtp->pcie_sge_dma_rsp.eop[i];
			sge_debug_index6_eop  +=
				wtp->sge_debug_data_high_index_6.eop[i];
			sge_utx_eop           += wtp->sge_utx.eop[i];
			utx_tp_eop            += wtp->utx_tp.eop[i];
			utx_tpcside_eop       += wtp->utx_tpcside.eop[i];
			tpcside_rxarb_eop     += wtp->tpcside_rxarb.eop[i];
			tpeside_mps_eop       += wtp->tpeside_mps.eop[i];
			tx_xgm_xgm_eop        +=
				wtp->mac_portx_pkt_count.eop[i];
			xgm_wire_eop          +=
				wtp->mac_portx_aframestra_ok.eop[i];

			/*special case type 3:*/
			tp_mps_sop            += wtp->tp_mps.sop[i];
			mps_xgm_sop           += wtp->mps_xgm.sop[i];

			tp_mps_eop            += wtp->tp_mps.eop[i];
			mps_xgm_eop           += wtp->mps_xgm.eop[i];

			pcie_core_dma_req_sop +=
				wtp->pcie_dma1_stat2_core.sop[i];
			sge_pcie_dma_req_sop  +=
				wtp->sge_debug_data_high_indx5.sop[i];
			utx_sge_dma_req_sop   += wtp->utx_sge_dma_req.sop[i];

			pcie_core_dma_req_eop +=
				wtp->pcie_dma1_stat2_core.eop[i];
			sge_pcie_dma_req_eop  +=
				wtp->sge_debug_data_high_indx5.eop[i];
			utx_sge_dma_req_eop   += wtp->utx_sge_dma_req.eop[i];
		}

		if (i < 5) {
			xgm_mps_sop               += (wtp->xgm_mps.sop[i]);
			xgm_mps_eop               += (wtp->xgm_mps.eop[i]);
		}
	}
	cudbg_printf(cudbg_poutbuf, err1, "ifaces = nic0 nic1\n");
	cudbg_printf(cudbg_poutbuf, err1, "*************************EGGRESS (TX) PATH **********************************\n");
	cudbg_printf(cudbg_poutbuf, err1, "MOD :  core---->PCIE---->SGE<-|    #Ring Doorbell\n");
	cudbg_printf(cudbg_poutbuf, err1, "SOP        ?      ???         |\n");
	cudbg_printf(cudbg_poutbuf, err1, "EOP        ?      ???         |\n");
	cudbg_printf(cudbg_poutbuf, err1, "MOD |<-core<----PCIE<----SGE<-|    #Request Work Request\n");
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH0  %02X       %02x\n",
		     wtp->pcie_cmd_stat2.sop[0], wtp->sge_pcie_cmd_req.sop[0]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP |    %02X       %02X\n",
		     pcie_core_cmd_req_sop, sge_pcie_cmd_req_sop);
	cudbg_printf(cudbg_poutbuf, err1, "EOP |    %2X       %2X\n",
		     pcie_core_cmd_req_eop, sge_pcie_cmd_req_eop);
	cudbg_printf(cudbg_poutbuf, err1, "MOD |->core---->PCIE---->SGE------>CIM/uP->| uP<-CIM<-CSW #->Work req. <-Pkts\n");
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH0  %02X       %02X      %02X"\
		     "               |      %2X\n",
		     wtp->pcie_cmd_stat3.sop[0], wtp->pcie_sge_cmd_rsp.sop[1],
		     wtp->sge_cim.sop[0], wtp->sge_work_req_pkt.sop[0]);

	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH1                   %02X"\
		     "               |\n", wtp->pcie_sge_cmd_rsp.sop[1]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP      %02X       %02X      %2X"\
		     "               |      %2X\n", core_pcie_cmd_rsp_sop,
		     pcie_sge_cmd_rsp_sop, sge_cim_sop, sge_work_req_sop);
	cudbg_printf(cudbg_poutbuf, err1, "EOP      %2X       %2X      %2X"\
		     "               |\n", core_pcie_cmd_rsp_eop,
		     pcie_sge_cmd_rsp_eop, sge_cim_eop);
	cudbg_printf(cudbg_poutbuf, err1, "MOD |<-core<----PCIE<----SGE<------UTX<--------|#data dma requests\n");
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH0  %02X\n",
		     wtp->pcie_dma1_stat2_core.sop[0]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH1  %02X\n",
		     wtp->pcie_dma1_stat2_core.sop[1]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP |    %2X\n",
		     pcie_core_dma_req_sop);
	cudbg_printf(cudbg_poutbuf, err1, "EOP |    %2X\n",
		     pcie_core_dma_req_eop);

	cudbg_printf(cudbg_poutbuf, err1, "MOD |->core-->PCIE-->SGE-->UTX---->TPC------->TPE---->MPS--->MAC--->MACOK->wire\n");
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH0        %02X         %2X   "\
		     "   %2X       %2X    %2X   %02X  %02X  %02X      %02X   "\
		     " %02X\n",
		     wtp->pcie_t5_dma_stat3.sop[0], wtp->ulp_se_cnt_chx.sop[0],
		     wtp->utx_tpcside.sop[0], wtp->tpcside_rxarb.sop[0],
		     wtp->tpeside_mps.sop[0], wtp->tp_mps.sop[0],
		     wtp->mps_xgm.sop[0], wtp->mac_portx_pkt_count.sop[0],
		     wtp->mac_portx_aframestra_ok.sop[0],
		     wtp->mac_portx_etherstatspkts.sop[0]);

	cudbg_printf(cudbg_poutbuf, err1, "EOP_CH0        %02X         %2X  "\
		     "    %2X       %2X    %2X   %02X  %02X  %02X      %02X"\
		     "    %02X\n",
		     wtp->pcie_t5_dma_stat3.eop[0], wtp->ulp_se_cnt_chx.eop[0],
		     wtp->utx_tpcside.eop[0], wtp->tpcside_rxarb.eop[0],
		     wtp->tpeside_mps.eop[0], wtp->tp_mps.eop[0],
		     wtp->mps_xgm.eop[0], wtp->mac_portx_pkt_count.eop[0],
		     wtp->mac_portx_aframestra_ok.eop[0],
		     wtp->mac_portx_etherstatspkts.eop[0]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH1        %02X         %2X   "\
		     "   %2X       %2X    %2X   %02X  %02X  %02X      %02X  "\
		     "%02X\n",
		     wtp->pcie_t5_dma_stat3.sop[1], wtp->ulp_se_cnt_chx.sop[1],
		     wtp->utx_tpcside.sop[1], wtp->tpcside_rxarb.sop[1],
		     wtp->tpeside_mps.sop[1], wtp->tp_mps.sop[1],
		     wtp->mps_xgm.sop[1], wtp->mac_portx_pkt_count.sop[1],
		     wtp->mac_portx_aframestra_ok.sop[1],
		     wtp->mac_portx_etherstatspkts.sop[1]);

	cudbg_printf(cudbg_poutbuf, err1, "EOP_CH1        %02X         %2X   "\
		     "   %2X       %2X    %2X   %02X  %02X  %02X      %02X"\
		     "    %02X\n",
		     wtp->pcie_t5_dma_stat3.eop[1], wtp->ulp_se_cnt_chx.eop[1],
		     wtp->utx_tpcside.eop[1], wtp->tpcside_rxarb.eop[1],
		     wtp->tpeside_mps.eop[1], wtp->tp_mps.eop[1],
		     wtp->mps_xgm.eop[1], wtp->mac_portx_pkt_count.eop[1],
		     wtp->mac_portx_aframestra_ok.eop[1],
		     wtp->mac_portx_etherstatspkts.eop[1]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH2        %02X         %2X   "\
		     "   %2X       %2X    %2X   %02X  %02X\n",
		     wtp->pcie_t5_dma_stat3.sop[2], wtp->ulp_se_cnt_chx.sop[2],
		     wtp->utx_tpcside.sop[2], wtp->tpcside_rxarb.sop[2],
		     wtp->tpeside_mps.sop[2], wtp->tp_mps.sop[2],
		     wtp->mps_xgm.sop[2]);

	cudbg_printf(cudbg_poutbuf, err1, "EOP_CH2        %02X         %2X   "\
		     "   %2X       %2X    %2X   %02X  %02X\n",
		     wtp->pcie_t5_dma_stat3.eop[2], wtp->ulp_se_cnt_chx.eop[2],
		     wtp->utx_tpcside.eop[2], wtp->tpcside_rxarb.eop[2],
		     wtp->tpeside_mps.eop[2], wtp->tp_mps.eop[2],
		     wtp->mps_xgm.eop[2]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH3        %02X         %2X  "\
		     "    %2X       %2X    %2X   %02X  %02X\n",
		     wtp->pcie_t5_dma_stat3.sop[3], wtp->ulp_se_cnt_chx.sop[3],
		     wtp->utx_tpcside.sop[3], wtp->tpcside_rxarb.sop[3],
		     wtp->tpeside_mps.sop[3], wtp->tp_mps.sop[3],
		     wtp->mps_xgm.sop[3]);

	cudbg_printf(cudbg_poutbuf, err1, "EOP_CH3        %02X         %2X   "\
		     "   %2X       %2X    %2X   %02X  %02X\n",
		     wtp->pcie_t5_dma_stat3.eop[3], wtp->ulp_se_cnt_chx.eop[3],
		     wtp->utx_tpcside.eop[3], wtp->tpcside_rxarb.eop[3],
		     wtp->tpeside_mps.eop[3], wtp->tp_mps.eop[3],
		     wtp->mps_xgm.eop[3]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP            %2X         %2X    "\
		     "  %2X       %2X    %2X   %2X  %2X  %2X      %2X    %2X\n",
		     core_pcie_dma_rsp_sop, sge_utx_sop, utx_tp_sop,
		     tpcside_rxarb_sop, tpeside_mps_sop, tp_mps_sop,
		     mps_xgm_sop, tx_xgm_xgm_sop, xgm_wire_sop,
		     tx_macok_wire_sop);
	cudbg_printf(cudbg_poutbuf, err1, "EOP            %2X         %2X   "\
			"   %2X       %2X    %2X   %2X  %2X  %2X      %2X  "\
			"  %2X\n",
			core_pcie_dma_rsp_eop, sge_utx_eop, utx_tp_eop,
			tpcside_rxarb_eop, tpeside_mps_eop, tp_mps_eop,
			mps_xgm_eop, tx_xgm_xgm_eop, xgm_wire_eop,
			tx_macok_wire_eop);
	cudbg_printf(cudbg_poutbuf, err1, "*************************INGRESS (RX) PATH **********************************\n");

	cudbg_printf(cudbg_poutbuf, err1, "MOD   core<-PCIE<---SGE<--CSW<-----TPC<-URX<-LE-TPE<-----MPS<--MAC<-MACOK<--wire\n");

	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH0      %2X  %2X    %2X    %2X"\
		     "   %2X  %2X  %2X %2X  %2X    %2X   %02X  %02X     "\
		     " %02X    %02X\n",
		     wtp->pcie_dma1_stat2.sop[0],
		     wtp->sge_debug_data_high_indx7.sop[0],
		     wtp->sge_debug_data_high_indx1.sop[0],
		     wtp->sge_debug_data_high_indx9.sop[0],
		     wtp->utx_tpcside_tx.sop[0], wtp->ulprx_tpcside.sop[0],
		     wtp->pmrx_ulprx.sop[0], wtp->le_db_rsp_cnt.sop,
		     wtp->tp_dbg_eside_pktx.sop[0], wtp->mps_tp.sop[0],
		     wtp->xgm_mps.sop[0], wtp->mac_porrx_pkt_count.sop[0],
		     wtp->mac_porrx_aframestra_ok.sop[0],
		     wtp->mac_porrx_etherstatspkts.sop[0]);

	cudbg_printf(cudbg_poutbuf, err1, "EOP_CH0      %2X  %2X    %2X    "\
		     "%2X   %2X  %2X  %2X %2X  %2X    %2X   %02X  %02X   "\
		     "   %02X    %02X\n",
		     wtp->pcie_dma1_stat2.eop[0],
		     wtp->sge_debug_data_high_indx7.eop[0],
		     wtp->sge_debug_data_high_indx1.eop[0],
		     wtp->sge_debug_data_high_indx9.eop[0],
		     wtp->utx_tpcside_tx.eop[0], wtp->ulprx_tpcside.eop[0],
		     wtp->pmrx_ulprx.eop[0], wtp->le_db_rsp_cnt.eop,
		     wtp->tp_dbg_eside_pktx.eop[0], wtp->mps_tp.eop[0],
		     wtp->xgm_mps.eop[0], wtp->mac_porrx_pkt_count.eop[0],
		     wtp->mac_porrx_aframestra_ok.eop[0],
		     wtp->mac_porrx_etherstatspkts.eop[0]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH1      %2X  %2X    %2X   "\
		     " %2X   %2X  %2X  %2X     %2X    %2X   %02X  %02X  "\
		     "    %02X    %02X\n",
		     wtp->pcie_dma1_stat2.sop[1],
		     wtp->sge_debug_data_high_indx7.sop[1],
		     wtp->sge_debug_data_high_indx1.sop[1],
		     wtp->sge_debug_data_high_indx9.sop[1],
		     wtp->utx_tpcside_tx.sop[1], wtp->ulprx_tpcside.sop[1],
		     wtp->pmrx_ulprx.sop[1], wtp->tp_dbg_eside_pktx.sop[1],
		     wtp->mps_tp.sop[1], wtp->xgm_mps.sop[1],
		     wtp->mac_porrx_pkt_count.sop[1],
		     wtp->mac_porrx_aframestra_ok.sop[1],
		     wtp->mac_porrx_etherstatspkts.sop[1]);

	cudbg_printf(cudbg_poutbuf, err1, "EOP_CH1      %2X  %2X    %2X    %2X"\
		     "   %2X  %2X  %2X     %2X    %2X   %02X  %02X      "\
		     "%02X    %02X\n",
		     wtp->pcie_dma1_stat2.eop[1],
		     wtp->sge_debug_data_high_indx7.eop[1],
		     wtp->sge_debug_data_high_indx1.eop[1],
		     wtp->sge_debug_data_high_indx9.eop[1],
		     wtp->utx_tpcside_tx.eop[1], wtp->ulprx_tpcside.eop[1],
		     wtp->pmrx_ulprx.eop[1], wtp->tp_dbg_eside_pktx.eop[1],
		     wtp->mps_tp.eop[1], wtp->xgm_mps.eop[1],
		     wtp->mac_porrx_pkt_count.eop[1],
		     wtp->mac_porrx_aframestra_ok.eop[1],
		     wtp->mac_porrx_etherstatspkts.eop[1]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH2                           "\
		     "               %2X         %02X\n",
		     wtp->tp_dbg_eside_pktx.sop[2], wtp->xgm_mps.sop[2]);

	cudbg_printf(cudbg_poutbuf, err1, "EOP_CH2                           "\
		     "               %2X         %02X\n",
		     wtp->tp_dbg_eside_pktx.eop[2], wtp->xgm_mps.eop[2]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH3                           "\
		     "               %2X         %02X\n",
		     wtp->tp_dbg_eside_pktx.sop[3],
		     wtp->xgm_mps.sop[3]);

	cudbg_printf(cudbg_poutbuf, err1, "EOP_CH3                           "\
		     "               %2X         %02X\n",
		     wtp->tp_dbg_eside_pktx.eop[3], wtp->xgm_mps.eop[3]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH4                           "\
		     "                          %02X\n",
		     wtp->xgm_mps.sop[4]);
	cudbg_printf(cudbg_poutbuf, err1, "EOP_CH4                           "\
		     "                          %02X\n",
		     wtp->xgm_mps.eop[4]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH5                           "\
		     "                          %02X\n",
		     wtp->xgm_mps.sop[5]);
	cudbg_printf(cudbg_poutbuf, err1, "EOP_CH5                           "\
		     "                          %02X\n",
		     wtp->xgm_mps.eop[5]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH6\n");
	cudbg_printf(cudbg_poutbuf, err1, "EOP_CH6\n");
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH7\n");
	cudbg_printf(cudbg_poutbuf, err1, "EOP_CH7\n");

	cudbg_printf(cudbg_poutbuf, err1, "SOP          %2X  %2X    %2X    %2X"\
		     "   %2X  %2X   %2X    %2X    %2X   %2X  %2X      %2X "\
		     "  %2X\n",
		     pcie_core_dmaw_sop, sge_pcie_sop, csw_sge_sop,
		     tp_csw_sop, tpcside_csw_sop, ulprx_tpcside_sop,
		     pmrx_ulprx_sop, mps_tpeside_sop,
		     mps_tp_sop, xgm_mps_sop, rx_xgm_xgm_sop,
		     wire_xgm_sop, rx_wire_macok_sop);
	cudbg_printf(cudbg_poutbuf, err1, "EOP          %2X  %2X    %2X    "\
		     "%2X   %2X  %2X   %2X    %2X    %2X   %2X  %2X     "\
		     " %2X   %2X\n",
		     pcie_core_dmaw_eop, sge_pcie_eop, csw_sge_eop,
		     tp_csw_eop, tpcside_csw_eop, ulprx_tpcside_eop,
		     pmrx_ulprx_eop, mps_tpeside_eop, mps_tp_eop,
		     xgm_mps_eop, rx_xgm_xgm_eop, wire_xgm_eop,
		     rx_wire_macok_eop);
	cudbg_printf(cudbg_poutbuf, err1, "DROP: ???      ???      ???       "\
		     "%2X(mib)  %2X(err) %2X(oflow) %X(cls)\n",
		     (wtp->mps_tp.drops & 0xFF), (wtp->xgm_mps.err & 0xFF),
		     (wtp->xgm_mps.drop & 0xFF),
		     (wtp->xgm_mps.cls_drop & 0xFF));
	cudbg_printf(cudbg_poutbuf, err1, "INTS:  ");
	for (i = 0; i < 2; i++) {
		cudbg_printf(cudbg_poutbuf, err1, "%2X<- %2X    ",
			     (wtp->pcie_core_dmai.sop[i] & 0xF),
			     (wtp->sge_pcie_ints.sop[i] & 0xF));
	}
	cudbg_printf(cudbg_poutbuf, err1, "(PCIE<-SGE, channels 0 to 1)\n");

err1:
	free(dc_buff.data);

err:
	return rc;
}

static int t5_view_wtp(char *pbuf, u32 size,
		       struct cudbg_buffer *cudbg_poutbuf)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct wtp_data *wtp = NULL;
	int rc = 0;
	int i = 0;
	/****Rx****/
	u32 pcie_core_dmaw_sop = 0;
	u32 sge_pcie_sop = 0;
	u32 csw_sge_sop = 0;
	u32 tp_csw_sop = 0;
	u32 tpcside_csw_sop = 0;
	u32 ulprx_tpcside_sop = 0;
	u32 pmrx_ulprx_sop = 0;
	u32 mps_tpeside_sop = 0;
	u32 mps_tp_sop = 0;
	u32 xgm_mps_sop = 0;
	u32 rx_xgm_xgm_sop = 0;
	u32 wire_xgm_sop = 0;

	u32 pcie_core_dmaw_eop = 0;
	u32 sge_pcie_eop = 0;
	u32 csw_sge_eop = 0;
	u32 tp_csw_eop = 0;
	u32 tpcside_csw_eop = 0;
	u32 ulprx_tpcside_eop = 0;
	u32 pmrx_ulprx_eop = 0;
	u32 mps_tpeside_eop = 0;
	u32 mps_tp_eop = 0;
	u32 xgm_mps_eop = 0;
	u32 rx_xgm_xgm_eop = 0;
	u32 wire_xgm_eop = 0;

	/****Tx****/
	u32 core_pcie_dma_rsp_sop = 0;
	u32 pcie_sge_dma_rsp_sop = 0;
	u32 sge_debug_index6_sop = 0;
	u32 sge_utx_sop = 0;
	u32 utx_tp_sop = 0;
	u32 sge_work_req_sop = 0;
	u32 utx_tpcside_sop = 0;
	u32 tpcside_rxarb_sop = 0;
	u32 tpeside_mps_sop = 0;
	u32 tp_mps_sop = 0;
	u32 mps_xgm_sop = 0;
	u32 tx_xgm_xgm_sop = 0;
	u32 xgm_wire_sop = 0;

	u32 core_pcie_dma_rsp_eop = 0;
	u32 pcie_sge_dma_rsp_eop = 0;
	u32 sge_debug_index6_eop = 0;
	u32 sge_utx_eop = 0;
	u32 utx_tp_eop = 0;
	u32 utx_tpcside_eop = 0;
	u32 tpcside_rxarb_eop = 0;
	u32 tpeside_mps_eop = 0;
	u32 tp_mps_eop = 0;
	u32 mps_xgm_eop = 0;
	u32 tx_xgm_xgm_eop = 0;
	u32 xgm_wire_eop = 0;

	u32 pcie_core_cmd_req_sop = 0;
	u32 sge_pcie_cmd_req_sop = 0;
	u32 core_pcie_cmd_rsp_sop = 0;
	u32 pcie_sge_cmd_rsp_sop = 0;
	u32 sge_cim_sop = 0;
	u32 pcie_core_dma_req_sop = 0;
	u32 sge_pcie_dma_req_sop = 0;
	u32 utx_sge_dma_req_sop = 0;

	u32 sge_pcie_cmd_req_eop = 0;
	u32 pcie_core_cmd_req_eop = 0;
	u32 core_pcie_cmd_rsp_eop = 0;
	u32 pcie_sge_cmd_rsp_eop = 0;
	u32 sge_cim_eop = 0;
	u32 pcie_core_dma_req_eop = 0;
	u32 sge_pcie_dma_req_eop = 0;
	u32 utx_sge_dma_req_eop = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	wtp = (struct wtp_data *) dc_buff.data;

	/*Add up the sop/eop of all channels.*/
	for (i = 0; i < 8; i++) {
		if (i < 2) {
			/*Rx Path*/
			csw_sge_sop           +=
				(wtp->sge_debug_data_high_indx1.sop[i]);
			tp_csw_sop            +=
				(wtp->sge_debug_data_high_indx9.sop[i]);

			csw_sge_eop           += (wtp->csw_sge.eop[i]);
			tp_csw_eop            += (wtp->tp_csw.eop[i]);

			/*Tx Path*/
			sge_pcie_cmd_req_sop  += wtp->sge_pcie_cmd_req.sop[i];
			pcie_sge_cmd_rsp_sop  += wtp->pcie_sge_cmd_rsp.sop[i];
			sge_cim_sop           += wtp->sge_cim.sop[i];
			tpcside_csw_sop       += (wtp->utx_tpcside_tx.sop[i]);
			sge_work_req_sop      += wtp->sge_work_req_pkt.sop[i];

			sge_pcie_cmd_req_eop  += wtp->sge_pcie_cmd_req.eop[i];
			pcie_sge_cmd_rsp_eop  += wtp->pcie_sge_cmd_rsp.eop[i];
			sge_cim_eop           += wtp->sge_cim.eop[i];

		}

		if (i < 3) {
			pcie_core_cmd_req_sop += wtp->pcie_cmd_stat2.sop[i];
			core_pcie_cmd_rsp_sop += wtp->pcie_cmd_stat3.sop[i];

			core_pcie_cmd_rsp_eop += wtp->pcie_cmd_stat3.eop[i];
			pcie_core_cmd_req_eop += wtp->pcie_cmd_stat2.eop[i];
		}

		if (i < 4) {
			/*Rx Path*/
			pcie_core_dmaw_sop    +=
				(wtp->pcie_dma1_stat2.sop[i]);
			sge_pcie_sop          +=
				(wtp->sge_debug_data_high_indx7.sop[i]);
			ulprx_tpcside_sop     += (wtp->ulprx_tpcside.sop[i]);
			pmrx_ulprx_sop        += (wtp->pmrx_ulprx.sop[i]);
			mps_tpeside_sop       +=
				(wtp->tp_dbg_eside_pktx.sop[i]);
			rx_xgm_xgm_sop        +=
				(wtp->mac_porrx_pkt_count.sop[i]);
			wire_xgm_sop          +=
				(wtp->mac_porrx_aframestra_ok.sop[i]);

			pcie_core_dmaw_eop    +=
				(wtp->pcie_dma1_stat2.eop[i]);
			sge_pcie_eop          += (wtp->sge_pcie.eop[i]);
			tpcside_csw_eop       += (wtp->tpcside_csw.eop[i]);
			ulprx_tpcside_eop     += (wtp->ulprx_tpcside.eop[i]);
			pmrx_ulprx_eop        += (wtp->pmrx_ulprx.eop[i]);
			mps_tpeside_eop       += (wtp->mps_tpeside.eop[i]);
			rx_xgm_xgm_eop        +=
				(wtp->mac_porrx_pkt_count.eop[i]);
			wire_xgm_eop          += (wtp->xgm_mps.eop[i]);

			/*special case type 3:*/
			mps_tp_sop            += (wtp->mps_tp.sop[i]);
			mps_tp_eop            += (wtp->mps_tp.eop[i]);

			/*Tx Path*/
			core_pcie_dma_rsp_sop +=
				wtp->pcie_t5_dma_stat3.sop[i];
			pcie_sge_dma_rsp_sop  += wtp->pcie_sge_dma_rsp.sop[i];
			sge_debug_index6_sop  +=
				wtp->sge_debug_data_high_index_6.sop[i];
			sge_utx_sop           += wtp->ulp_se_cnt_chx.sop[i];
			utx_tp_sop            += wtp->utx_tp.sop[i];
			utx_tpcside_sop       += wtp->utx_tpcside.sop[i];
			tpcside_rxarb_sop     += wtp->tpcside_rxarb.sop[i];
			tpeside_mps_sop       += wtp->tpeside_mps.sop[i];
			tx_xgm_xgm_sop        +=
				wtp->mac_portx_pkt_count.sop[i];
			xgm_wire_sop          +=
				wtp->mac_portx_aframestra_ok.sop[i];

			core_pcie_dma_rsp_eop +=
				wtp->pcie_t5_dma_stat3.eop[i];
			pcie_sge_dma_rsp_eop  += wtp->pcie_sge_dma_rsp.eop[i];
			sge_debug_index6_eop  +=
				wtp->sge_debug_data_high_index_6.eop[i];
			sge_utx_eop           += wtp->sge_utx.eop[i];
			utx_tp_eop            += wtp->utx_tp.eop[i];
			utx_tpcside_eop       += wtp->utx_tpcside.eop[i];
			tpcside_rxarb_eop     += wtp->tpcside_rxarb.eop[i];
			tpeside_mps_eop       += wtp->tpeside_mps.eop[i];
			tx_xgm_xgm_eop        +=
				wtp->mac_portx_pkt_count.eop[i];
			xgm_wire_eop          +=
				wtp->mac_portx_aframestra_ok.eop[i];

			/*special case type 3:*/
			tp_mps_sop            += wtp->tp_mps.sop[i];
			mps_xgm_sop           += wtp->mps_xgm.sop[i];

			tp_mps_eop            += wtp->tp_mps.eop[i];
			mps_xgm_eop           += wtp->mps_xgm.eop[i];

			pcie_core_dma_req_sop +=
				wtp->pcie_dma1_stat2_core.sop[i];
			sge_pcie_dma_req_sop  +=
				wtp->sge_debug_data_high_indx5.sop[i];
			utx_sge_dma_req_sop   += wtp->utx_sge_dma_req.sop[i];

			pcie_core_dma_req_eop +=
				wtp->pcie_dma1_stat2_core.eop[i];
			sge_pcie_dma_req_eop  +=
				wtp->sge_debug_data_high_indx5.eop[i];
			utx_sge_dma_req_eop   += wtp->utx_sge_dma_req.eop[i];
		}

		xgm_mps_sop               += (wtp->xgm_mps.sop[i]);
		xgm_mps_eop               += (wtp->xgm_mps.eop[i]);
	}
	cudbg_printf(cudbg_poutbuf, err1, "ifaces = nic0 nic1\n");
	cudbg_printf(cudbg_poutbuf, err1, "*************************EGGRESS (TX) PATH **********************************\n");
	cudbg_printf(cudbg_poutbuf, err1, "MOD :  core---->PCIE---->SGE<-|    #Ring Doorbell\n");
		cudbg_printf(cudbg_poutbuf, err1, "SOP        ?      ???         |\n");
	cudbg_printf(cudbg_poutbuf, err1, "EOP        ?      ???         |\n");
	cudbg_printf(cudbg_poutbuf, err1, "MOD |<-core<----PCIE<----SGE<-|    #Request Work Request\n");
		cudbg_printf(cudbg_poutbuf, err1, "SOP_CH0  %02X       %02x\n",
			     wtp->pcie_cmd_stat2.sop[0],
			     wtp->sge_pcie_cmd_req.sop[0]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH1  %02X       %02X\n",
		     wtp->pcie_cmd_stat2.sop[1], wtp->sge_pcie_cmd_req.sop[1]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH2  %02X\n",
		     wtp->pcie_cmd_stat2.sop[2]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP |    %02X       %02X\n",
		     pcie_core_cmd_req_sop, sge_pcie_cmd_req_sop);
	cudbg_printf(cudbg_poutbuf, err1, "EOP |   %2X       %2X\n",
		     pcie_core_cmd_req_eop, sge_pcie_cmd_req_eop);
	cudbg_printf(cudbg_poutbuf, err1, "MOD |->core---->PCIE---->SGE------>CIM/uP->| uP<-CIM<-CSW #->Work req. <-Pkts\n");
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH0  %02X       %02X      %02X"\
		     "               |      %2X\n",
		     wtp->pcie_cmd_stat3.sop[0], wtp->pcie_sge_cmd_rsp.sop[0],
		     wtp->sge_cim.sop[0], wtp->sge_work_req_pkt.sop[0]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH1  %02X       %02X      %02X"\
		     "               |      %2X\n",
		     wtp->pcie_cmd_stat3.sop[1], wtp->pcie_sge_cmd_rsp.sop[1],
		     wtp->sge_cim.sop[1], wtp->sge_work_req_pkt.sop[1]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH2  %02X                     "\
		     "           |\n", wtp->pcie_cmd_stat3.sop[2]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP      %02X       %02X      %2X "\
		     "              |      %2X\n",
		     core_pcie_cmd_rsp_sop, pcie_sge_cmd_rsp_sop,
		     sge_cim_sop, sge_work_req_sop);
	cudbg_printf(cudbg_poutbuf, err1, "EOP      %2X       %2X      %2X   "\
		     "            |\n",
		     core_pcie_cmd_rsp_eop,
		     pcie_sge_cmd_rsp_eop, sge_cim_eop);
	cudbg_printf(cudbg_poutbuf, err1, "MOD |<-core<----PCIE<----SGE<------UTX<--------|#data dma requests\n");
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH0  %02X       %02X      "\
		     "%02X\n", wtp->pcie_dma1_stat2_core.sop[0],
		     wtp->sge_debug_data_high_indx5.sop[0],
		     wtp->utx_sge_dma_req.sop[0]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH1  %02X       %02X      "\
		     "%02X\n", wtp->pcie_dma1_stat2_core.sop[1],
		     wtp->sge_debug_data_high_indx5.sop[1],
		     wtp->utx_sge_dma_req.sop[1]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH2  %02X       %02X      "\
		     "%02X\n", wtp->pcie_dma1_stat2_core.sop[2],
		     wtp->sge_debug_data_high_indx5.sop[2],
		     wtp->utx_sge_dma_req.sop[2]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH3  %02X       %02X      "\
		     "%02X\n", wtp->pcie_dma1_stat2_core.sop[3],
		     wtp->sge_debug_data_high_indx5.sop[3],
		     wtp->utx_sge_dma_req.sop[3]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP |    %2X       %2X      %2X\n",
		     pcie_core_dma_req_sop/*eop in perl??*/,
		     sge_pcie_dma_req_sop, utx_sge_dma_req_sop);
	cudbg_printf(cudbg_poutbuf, err1, "EOP |    %2X       %2X      %2X\n",
		     pcie_core_dma_req_eop,
		     sge_pcie_dma_req_eop, utx_sge_dma_req_eop);
	cudbg_printf(cudbg_poutbuf, err1, "MOD |->core-->PCIE-->SGE-->UTX---->TPC------->TPE---->MPS--->MAC--->wire\n");
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH0        %02X %2X   %2X  %2X"\
		     "    %2X       %2X    %2X   %02X  %02X   %02X      %02X\n",
		     wtp->pcie_t5_dma_stat3.sop[0],
		     wtp->sge_debug_data_high_index_6.sop[0],
		     wtp->sge_debug_data_high_index_3.sop[0],
		     wtp->ulp_se_cnt_chx.sop[0], wtp->utx_tpcside.sop[0],
		     wtp->tpcside_rxarb.sop[0], wtp->tpeside_mps.sop[0],
		     wtp->tp_mps.sop[0], wtp->mps_xgm.sop[0],
		     wtp->mac_portx_pkt_count.sop[0],
		     wtp->mac_portx_aframestra_ok.sop[0]);

	cudbg_printf(cudbg_poutbuf, err1, "EOP_CH0        %02X %2X   %2X  %2X"\
		     "    %2X       %2X    %2X   %02X  %02X   %02X      %02X\n",
		     wtp->pcie_t5_dma_stat3.eop[0],
		     wtp->sge_debug_data_high_index_6.eop[0],
		     wtp->sge_debug_data_high_index_3.eop[0],
		     wtp->ulp_se_cnt_chx.eop[0], wtp->utx_tpcside.eop[0],
		     wtp->tpcside_rxarb.eop[0], wtp->tpeside_mps.eop[0],
		     wtp->tp_mps.eop[0], wtp->mps_xgm.eop[0],
		     wtp->mac_portx_pkt_count.eop[0],
		     wtp->mac_portx_aframestra_ok.eop[0]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH1        %02X %2X   %2X  %2X"\
		     "    %2X       %2X    %2X   %02X  %02X   %02X      %02X\n",
		     wtp->pcie_t5_dma_stat3.sop[1],
		     wtp->sge_debug_data_high_index_6.sop[1],
		     wtp->sge_debug_data_high_index_3.sop[1],
		     wtp->ulp_se_cnt_chx.sop[1], wtp->utx_tpcside.sop[1],
		     wtp->tpcside_rxarb.sop[1], wtp->tpeside_mps.sop[1],
		     wtp->tp_mps.sop[1], wtp->mps_xgm.sop[1],
		     wtp->mac_portx_pkt_count.sop[1],
		     wtp->mac_portx_aframestra_ok.sop[1]);

	cudbg_printf(cudbg_poutbuf, err1, "EOP_CH1        %02X %2X   %2X  %2X"\
		     "    %2X       %2X    %2X   %02X  %02X   %02X      %02X\n",
		     wtp->pcie_t5_dma_stat3.eop[1],
		     wtp->sge_debug_data_high_index_6.eop[1],
		     wtp->sge_debug_data_high_index_3.eop[1],
		     wtp->ulp_se_cnt_chx.eop[1], wtp->utx_tpcside.eop[1],
		     wtp->tpcside_rxarb.eop[1], wtp->tpeside_mps.eop[1],
		     wtp->tp_mps.eop[1], wtp->mps_xgm.eop[1],
		     wtp->mac_portx_pkt_count.eop[1],
		     wtp->mac_portx_aframestra_ok.eop[1]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH2        %02X %2X   %2X  %2X"\
		     "    %2X       %2X    %2X   %02X  %02X   %02X      %02X\n",
		     wtp->pcie_t5_dma_stat3.sop[2],
		     wtp->sge_debug_data_high_index_6.sop[2],
		     wtp->sge_debug_data_high_index_3.sop[2],
		     wtp->ulp_se_cnt_chx.sop[2], wtp->utx_tpcside.sop[2],
		     wtp->tpcside_rxarb.sop[2], wtp->tpeside_mps.sop[2],
		     wtp->tp_mps.sop[2], wtp->mps_xgm.sop[2],
		     wtp->mac_portx_pkt_count.sop[2],
		     wtp->mac_portx_aframestra_ok.sop[2]);

	cudbg_printf(cudbg_poutbuf, err1, "EOP_CH2        %02X %2X   %2X  %2X"\
		     "    %2X       %2X    %2X   %02X  %02X   %02X      %02X\n",
		     wtp->pcie_t5_dma_stat3.eop[2],
		     wtp->sge_debug_data_high_index_6.eop[2],
		     wtp->sge_debug_data_high_index_3.eop[2],
		     wtp->ulp_se_cnt_chx.eop[2], wtp->utx_tpcside.eop[2],
		     wtp->tpcside_rxarb.eop[2], wtp->tpeside_mps.eop[2],
		     wtp->tp_mps.eop[2], wtp->mps_xgm.eop[2],
		     wtp->mac_portx_pkt_count.eop[2],
		     wtp->mac_portx_aframestra_ok.eop[2]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH3        %02X %2X   %2X  %2X"\
		     "    %2X       %2X    %2X   %02X  %02X   %02X      %02X\n",
		     wtp->pcie_t5_dma_stat3.sop[3],
		     wtp->sge_debug_data_high_index_6.sop[3],
		     wtp->sge_debug_data_high_index_3.sop[3],
		     wtp->ulp_se_cnt_chx.sop[3], wtp->utx_tpcside.sop[3],
		     wtp->tpcside_rxarb.sop[3], wtp->tpeside_mps.sop[3],
		     wtp->tp_mps.sop[3], wtp->mps_xgm.sop[3],
		     wtp->mac_portx_pkt_count.sop[3],
		     wtp->mac_portx_aframestra_ok.sop[3]);

	cudbg_printf(cudbg_poutbuf, err1, "EOP_CH3        %02X %2X   %2X  %2X"\
		     "    %2X       %2X    %2X   %02X  %02X   %02X      %02X\n",
		     wtp->pcie_t5_dma_stat3.eop[3],
		     wtp->sge_debug_data_high_index_6.eop[3],
		     wtp->sge_debug_data_high_index_3.eop[3],
		     wtp->ulp_se_cnt_chx.eop[3], wtp->utx_tpcside.eop[3],
		     wtp->tpcside_rxarb.eop[3], wtp->tpeside_mps.eop[3],
		     wtp->tp_mps.eop[3], wtp->mps_xgm.eop[3],
		     wtp->mac_portx_pkt_count.eop[3],
		     wtp->mac_portx_aframestra_ok.eop[3]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP            %2X %2X   %2X  %2X "\
		     "   %2X       %2X    %2X   %2X  %2X   %2X      %2X\n",
		     core_pcie_dma_rsp_sop, sge_debug_index6_sop,
		     pcie_sge_dma_rsp_sop, sge_utx_sop, utx_tp_sop,
		     tpcside_rxarb_sop, tpeside_mps_sop, tp_mps_sop,
		     mps_xgm_sop, tx_xgm_xgm_sop, xgm_wire_sop);
	cudbg_printf(cudbg_poutbuf, err1, "EOP            %2X %2X   %2X  %2X "\
		     "   %2X       %2X    %2X   %2X  %2X   %2X      %2X\n",
		     core_pcie_dma_rsp_eop, sge_debug_index6_eop,
		     pcie_sge_dma_rsp_eop, sge_utx_eop, utx_tp_eop,
		     tpcside_rxarb_eop, tpeside_mps_eop, tp_mps_eop,
		     mps_xgm_eop, tx_xgm_xgm_eop, xgm_wire_eop);
	cudbg_printf(cudbg_poutbuf, err1, "*************************INGRESS (RX) PATH **********************************\n");

	cudbg_printf(cudbg_poutbuf, err1, "MOD   core<-PCIE<---SGE<--CSW<-----TPC<-URX<-LE-TPE<-----MPS<--MAC<---wire\n");

	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH0      %2X  %2X    %2X    %2X"\
		     "   %2X  %2X  %2X %2X  %2X    %2X   %02X  %02X      "\
		     "%02X\n",
		     wtp->pcie_dma1_stat2.sop[0],
		     wtp->sge_debug_data_high_indx7.sop[0],
		     wtp->sge_debug_data_high_indx1.sop[0],
		     wtp->sge_debug_data_high_indx9.sop[0],
		     wtp->utx_tpcside_tx.sop[0], wtp->ulprx_tpcside.sop[0],
		     wtp->pmrx_ulprx.sop[0], wtp->le_db_rsp_cnt.sop,
		     wtp->tp_dbg_eside_pktx.sop[0], wtp->mps_tp.sop[0],
		     wtp->xgm_mps.sop[0], wtp->mac_porrx_pkt_count.sop[0],
		     wtp->mac_porrx_aframestra_ok.sop[0]);

	cudbg_printf(cudbg_poutbuf, err1, "EOP_CH0      %2X  %2X    %2X    "\
		     "%2X   %2X  %2X  %2X %2X  %2X    %2X   %02X  %02X  "\
		     "    %02X\n",
		     wtp->pcie_dma1_stat2.eop[0],
		     wtp->sge_debug_data_high_indx7.eop[0],
		     wtp->sge_debug_data_high_indx1.eop[0],
		     wtp->sge_debug_data_high_indx9.eop[0],
		     wtp->utx_tpcside_tx.eop[0], wtp->ulprx_tpcside.eop[0],
		     wtp->pmrx_ulprx.eop[0], wtp->le_db_rsp_cnt.eop,
		     wtp->tp_dbg_eside_pktx.eop[0], wtp->mps_tp.eop[0],
		     wtp->xgm_mps.eop[0], wtp->mac_porrx_pkt_count.eop[0],
		     wtp->mac_porrx_aframestra_ok.eop[0]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH1      %2X  %2X    %2X    "\
		     "%2X   %2X  %2X  %2X     %2X    %2X   %02X  %02X   "\
		     "   %02X\n",
		     wtp->pcie_dma1_stat2.sop[1],
		     wtp->sge_debug_data_high_indx7.sop[1],
		     wtp->sge_debug_data_high_indx1.sop[1],
		     wtp->sge_debug_data_high_indx9.sop[1],
		     wtp->utx_tpcside_tx.sop[1], wtp->ulprx_tpcside.sop[1],
		     wtp->pmrx_ulprx.sop[1], wtp->tp_dbg_eside_pktx.sop[1],
		     wtp->mps_tp.sop[1], wtp->xgm_mps.sop[1],
		     wtp->mac_porrx_pkt_count.sop[1],
		     wtp->mac_porrx_aframestra_ok.sop[1]);

	cudbg_printf(cudbg_poutbuf, err1, "EOP_CH1      %2X  %2X    %2X    "\
		     "%2X   %2X  %2X  %2X     %2X    %2X   %02X  %02X   "\
		     "   %02X\n",
		     wtp->pcie_dma1_stat2.eop[1],
		     wtp->sge_debug_data_high_indx7.eop[1],
		     wtp->sge_debug_data_high_indx1.eop[1],
		     wtp->sge_debug_data_high_indx9.eop[1],
		     wtp->utx_tpcside_tx.eop[1], wtp->ulprx_tpcside.eop[1],
		     wtp->pmrx_ulprx.eop[1], wtp->tp_dbg_eside_pktx.eop[1],
		     wtp->mps_tp.eop[1], wtp->xgm_mps.eop[1],
		     wtp->mac_porrx_pkt_count.eop[1],
		     wtp->mac_porrx_aframestra_ok.eop[1]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH2      %2X  %2X             "\
		     "                 %2X    %2X   %02X  %02X      %02X\n",
		     wtp->pcie_dma1_stat2.sop[2],
		     wtp->sge_debug_data_high_indx7.sop[2],
		     wtp->tp_dbg_eside_pktx.sop[2], wtp->mps_tp.sop[2],
		     wtp->xgm_mps.sop[2], wtp->mac_porrx_pkt_count.sop[2],
		     wtp->mac_porrx_aframestra_ok.sop[2]);

	cudbg_printf(cudbg_poutbuf, err1, "EOP_CH2      %2X  %2X             "\
		     "                 %2X    %2X   %02X  %02X      %02X\n",
		     wtp->pcie_dma1_stat2.eop[2],
		     wtp->sge_debug_data_high_indx7.eop[2],
		     wtp->tp_dbg_eside_pktx.eop[2], wtp->mps_tp.eop[2],
		     wtp->xgm_mps.eop[2], wtp->mac_porrx_pkt_count.eop[2],
		     wtp->mac_porrx_aframestra_ok.eop[2]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH3      %2X  %2X             "\
		     "                 %2X    %2X   %02X  %02X      %02X\n",
		     wtp->pcie_dma1_stat2.sop[3],
		     wtp->sge_debug_data_high_indx7.sop[3],
		     wtp->tp_dbg_eside_pktx.sop[3], wtp->mps_tp.sop[3],
		     wtp->xgm_mps.sop[3], wtp->mac_porrx_pkt_count.sop[3],
		     wtp->mac_porrx_aframestra_ok.sop[3]);

	cudbg_printf(cudbg_poutbuf, err1, "EOP_CH3      %2X  %2X             "\
		     "                 %2X    %2X   %02X  %02X      %02X\n",
		     wtp->pcie_dma1_stat2.eop[3],
		     wtp->sge_debug_data_high_indx7.eop[3],
		     wtp->tp_dbg_eside_pktx.eop[3], wtp->mps_tp.eop[3],
		     wtp->xgm_mps.eop[3], wtp->mac_porrx_pkt_count.eop[3],
		     wtp->mac_porrx_aframestra_ok.eop[3]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH4                           "\
		     "                          %02X\n",
		     wtp->xgm_mps.sop[4]);
	cudbg_printf(cudbg_poutbuf, err1, "EOP_CH4                           "\
		     "                          %02X\n",
		     wtp->xgm_mps.eop[4]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH5                           "\
		     "                          %02X\n",
		     wtp->xgm_mps.sop[5]);
	cudbg_printf(cudbg_poutbuf, err1, "EOP_CH5                           "\
		     "                          %02X\n",
		     wtp->xgm_mps.eop[5]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH6                           "\
		     "                          %02X\n",
		     wtp->xgm_mps.sop[6]);
	cudbg_printf(cudbg_poutbuf, err1, "EOP_CH6                           "\
		     "                          %02X\n",
		     wtp->xgm_mps.eop[6]);
	cudbg_printf(cudbg_poutbuf, err1, "SOP_CH7                           "\
		     "                          %02X\n",
		     wtp->xgm_mps.sop[7]);
	cudbg_printf(cudbg_poutbuf, err1, "EOP_CH7                           "\
		     "                          %02X\n",
		     wtp->xgm_mps.eop[7]);

	cudbg_printf(cudbg_poutbuf, err1, "SOP          %2X  %2X    %2X    "\
		     "%2X   %2X  %2X   %2X    %2X    %2X   %2X  %2X     %2X\n",
		     pcie_core_dmaw_sop, sge_pcie_sop, csw_sge_sop,
		     tp_csw_sop, tpcside_csw_sop, ulprx_tpcside_sop,
		     pmrx_ulprx_sop, mps_tpeside_sop, mps_tp_sop,
		     xgm_mps_sop, rx_xgm_xgm_sop, wire_xgm_sop);
	cudbg_printf(cudbg_poutbuf, err1, "EOP          %2X  %2X    %2X    "\
		     "%2X   %2X  %2X   %2X    %2X    %2X   %2X  %2X     %2X\n",
		     pcie_core_dmaw_eop, sge_pcie_eop,
		     csw_sge_eop, tp_csw_eop,
		     tpcside_csw_eop, ulprx_tpcside_eop,
		     pmrx_ulprx_eop, mps_tpeside_eop,
		     mps_tp_eop, xgm_mps_eop, rx_xgm_xgm_eop,
		     wire_xgm_eop);
	cudbg_printf(cudbg_poutbuf, err1, "DROP: ???      ???      ???       "\
		     "%2X(mib)  %2X(err) %2X(oflow) %X(cls)\n",
		     (wtp->mps_tp.drops & 0xFF),
		     (wtp->xgm_mps.err & 0xFF),
		     (wtp->xgm_mps.drop & 0xFF),
		     (wtp->xgm_mps.cls_drop & 0xFF));
	cudbg_printf(cudbg_poutbuf, err1, "INTS:  ");
	for (i = 0; i < 4; i++) {
		cudbg_printf(cudbg_poutbuf, err1, "%2X<- %2X    ",
			     (wtp->pcie_core_dmai.sop[i] & 0xF),
			     (wtp->sge_pcie_ints.sop[i] & 0xF));
	}
	cudbg_printf(cudbg_poutbuf, err1, "(PCIE<-SGE, channels 0 to 3)\n");

err1:
	free(dc_buff.data);

err:
	return rc;
}

int view_wtp(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
	     enum chip_type chip)
{
	int rc = -1;

	if (is_t5(chip))
		rc = t5_view_wtp(pbuf, size, cudbg_poutbuf);
	else if (is_t6(chip))
		rc = t6_view_wtp(pbuf, size, cudbg_poutbuf);

	return rc;
}

/*
 *  * Small utility function to return the strings "yes" or "no" if the
 *  supplied
 *   * argument is non-zero.
 *    */
static const char *yesno(int x)
{
	static const char *yes = "yes";
	static const char *no = "no";
	return x ? yes : no;
}

static int dump_indirect_regs(const struct cudbg_reg_info *reg_array,
			      u32 indirect_addr, const u32 *regs,
			      struct cudbg_buffer *cudbg_poutbuf)
{
	uint32_t reg_val = 0; /* silence compiler warning*/
	int i, rc;

	for (i = 0 ; reg_array->name; ++reg_array)
		if (!reg_array->len) {
			reg_val = regs[i];
			i++;
			cudbg_printf(cudbg_poutbuf, err1, "[0x%05x:0x%05x] "\
				     "%-47s %#-14x %u\n",
				     indirect_addr, reg_array->addr,
				     reg_array->name, reg_val, reg_val);
		} else {
			uint32_t v = xtract(reg_val, reg_array->addr,
					reg_array->len);
			cudbg_printf(cudbg_poutbuf, err1, "    %*u:%u %-55s "\
				     "%#-14x %u\n",
				     reg_array->addr < 10 ? 3 : 2,
				     reg_array->addr + reg_array->len - 1,
				     reg_array->addr, reg_array->name, v, v);
		}
	return 1;
err1:
	return rc;
}

int view_cctrl(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
	       enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	u16 (*incr)[NCCTRL_WIN];
	int rc = 0;
	u32 i = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);

	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	incr = (void *)dc_buff.data;
	for (i = 0; i < NCCTRL_WIN; i++) {
		cudbg_printf(cudbg_poutbuf, err1, "%2d: %4u %4u %4u %4u %4u "\
			     "%4u %4u %4u\n", i,
			     incr[0][i], incr[1][i], incr[2][i], incr[3][i],
			     incr[4][i], incr[5][i], incr[6][i], incr[7][i]);
		cudbg_printf(cudbg_poutbuf, err1, "%8u %4u %4u %4u %4u %4u %4u"\
			     " %4u\n", incr[8][i], incr[9][i], incr[10][i],
			     incr[11][i], incr[12][i], incr[13][i],
			     incr[14][i], incr[15][i]);
	}

err1:
	free(dc_buff.data);

err:
	return rc;
}

int view_up_cim_indirect(char *pbuf, u32 size,
			 struct cudbg_buffer *cudbg_poutbuf,
			 enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct ireg_buf *up_cim_indr;
	u32 indirect_addr;
	int rc = 0;
	int i = 0;
	int n = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);

	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	indirect_addr = A_CIM_HOST_ACC_CTRL;

	up_cim_indr = (struct ireg_buf *)dc_buff.data;

	if (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T5)
		n = sizeof(t5_up_cim_reg_array) / (4 * sizeof(u32));
	else if (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T6)
		n = sizeof(t6_up_cim_reg_array) / (4 * sizeof(u32));

	for (i = 0; i < n; i++) {
		u32 *buff = up_cim_indr->outbuf;

		if (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T5)
			rc = dump_indirect_regs(t5_up_cim_reg_ptr[i],
						indirect_addr,
						(const u32 *)buff,
						cudbg_poutbuf);
		else if (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T6)
			rc = dump_indirect_regs(t6_up_cim_reg_ptr[i],
						indirect_addr,
						(const u32 *)buff,
						cudbg_poutbuf);

		if (rc < 0)
			goto err1;
		up_cim_indr++;
	}

err1:
	free(dc_buff.data);

err:
	return rc;
}

static int print_pbt_addr_entry(struct cudbg_buffer *cudbg_poutbuf, u32 val)
{
	u32 vld, alloc, pending, address;
	int rc = 0;
	char *fmts = "\n    [%2u:%2u]  %-10s  ";

	vld = (val >> 28) & 1;
	cudbg_printf(cudbg_poutbuf, err1, fmts, 28, 28, "vld");
	cudbg_printf(cudbg_poutbuf, err1, "%d", vld);

	alloc = (val >> 27) & 1;
	cudbg_printf(cudbg_poutbuf, err1, fmts, 27, 27, "alloc");
	cudbg_printf(cudbg_poutbuf, err1, "%d", alloc);

	pending = (val >> 26) & 1;
	cudbg_printf(cudbg_poutbuf, err1, fmts, 26, 26, "pending");
	cudbg_printf(cudbg_poutbuf, err1, "%d", pending);

	address = val & 0x1FFFFFF;
	cudbg_printf(cudbg_poutbuf, err1, fmts, 25, 0, "address<<6");
	cudbg_printf(cudbg_poutbuf, err1, "0x%08x", address<<6);
	cudbg_printf(cudbg_poutbuf, err1, "\n");

err1:
	return rc;
}

int view_mbox_log(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		  enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct cudbg_mbox_log *mboxlog = NULL;
	int rc, i, k;
	u16 mbox_cmds;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);
	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	mbox_cmds = (u16)dc_buff.size / sizeof(struct cudbg_mbox_log);
	mboxlog = (struct cudbg_mbox_log *)dc_buff.data;

	cudbg_printf(cudbg_poutbuf, err1,
		     "%10s  %15s  %5s  %5s  %s\n", "Seq", "Tstamp", "Atime",
		     "Etime", "Command/Reply");

	for (i = 0; i < mbox_cmds && mboxlog->entry.timestamp; i++) {
		cudbg_printf(cudbg_poutbuf, err1, "%10u  %15llu  %5d  %5d",
			     mboxlog->entry.seqno, mboxlog->entry.timestamp,
			     mboxlog->entry.access, mboxlog->entry.execute);
		for (k = 0; k < MBOX_LEN / 8; k++)
			cudbg_printf(cudbg_poutbuf, err1, "  %08x %08x",
				     mboxlog->hi[k], mboxlog->lo[k]);

		cudbg_printf(cudbg_poutbuf, err1, "\n");
		mboxlog++;
	}

err1:
	free(dc_buff.data);

err:
	return rc;
}

int view_pbt_tables(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		    enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct cudbg_pbt_tables *pbt;
	u32 addr;
	int rc = 0;
	int i = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);

	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	pbt = (struct cudbg_pbt_tables *)dc_buff.data;

	/* PBT dynamic entries */
	addr = CUDBG_CHAC_PBT_ADDR;
	for (i = 0; i < CUDBG_PBT_DYNAMIC_ENTRIES; i++) {
		cudbg_printf(cudbg_poutbuf, err1, "Dynamic ");
		cudbg_printf(cudbg_poutbuf, err1, "Addr Table [0x%03x]: 0x%08x",
			     (addr + (i * 4) - CUDBG_CHAC_PBT_ADDR),
			     pbt->pbt_dynamic[i]);
		rc = print_pbt_addr_entry(cudbg_poutbuf, pbt->pbt_dynamic[i]);
		if (rc < 0)
			goto err1;
	}

	/* PBT static entries */
	addr = CUDBG_CHAC_PBT_ADDR + (1 << 6);
	for (i = 0; i < CUDBG_PBT_STATIC_ENTRIES; i++) {
		cudbg_printf(cudbg_poutbuf, err1, "Static ");
		cudbg_printf(cudbg_poutbuf, err1, "Addr Table [0x%03x]: 0x%08x",
			     (addr + (i * 4) - CUDBG_CHAC_PBT_ADDR),
			     pbt->pbt_static[i]);
		rc = print_pbt_addr_entry(cudbg_poutbuf, pbt->pbt_static[i]);
		if (rc < 0)
			goto err1;
	}

	/* PBT lrf entries */
	addr = CUDBG_CHAC_PBT_LRF;
	for (i = 0; i < CUDBG_LRF_ENTRIES; i++) {
		cudbg_printf(cudbg_poutbuf, err1,
			     "LRF Table [0x%03x]: 0x%08x\n",
			     (addr + (i * 4) - CUDBG_CHAC_PBT_LRF),
			     pbt->lrf_table[i]);
	}

	/* PBT data entries */
	addr = CUDBG_CHAC_PBT_DATA;
	for (i = 0; i < CUDBG_PBT_DATA_ENTRIES; i++) {
		cudbg_printf(cudbg_poutbuf, err1,
			     "DATA Table [0x%03x]: 0x%08x\n",
			     (addr + (i * 4) - CUDBG_CHAC_PBT_DATA),
			     pbt->pbt_data[i]);
	}

err1:
	free(dc_buff.data);

err:
	return rc;
}

int view_ma_indirect(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		     enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct ireg_buf *ma_indr;
	u32 indirect_addr;
	int rc = 0;
	int i = 0;
	int n;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);

	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	indirect_addr = A_MA_LOCAL_DEBUG_CFG;

	ma_indr = (struct ireg_buf *)dc_buff.data;
	n = sizeof(t6_ma_ireg_array) / (4 * sizeof(u32));
	n += sizeof(t6_ma_ireg_array2) / (4 * sizeof(u32));

	for (i = 0; i < n; i++) {
		u32 *buff = ma_indr->outbuf;

		rc = dump_indirect_regs(t6_ma_ptr[i], indirect_addr,
					(const u32 *) buff, cudbg_poutbuf);
		if (rc < 0)
			goto err1;
		ma_indr++;
	}

err1:
	free(dc_buff.data);

err:
	return rc;
}

int view_pm_indirect(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		     enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	u32 indirect_addr;
	struct ireg_buf *ch_pm;
	int rc = 0;
	int i = 0;
	int n;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);

	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	ch_pm = (struct ireg_buf *)dc_buff.data;

	if (!cudbg_poutbuf->data)
		cudbg_printf(cudbg_poutbuf, err1, "\n\nPM_RX\n\n");

	indirect_addr = PM_RX_INDIRECT;

	n = sizeof(t5_pm_rx_array)/(4 * sizeof(u32));
	for (i = 0; i < n; i++) {
		u32 *buff = ch_pm->outbuf;

		rc = dump_indirect_regs(t5_pm_rx_ptr[i], indirect_addr,
					(const u32 *) buff, cudbg_poutbuf);
		if (rc < 0)
			goto err1;

		ch_pm++;
	}

	if (!cudbg_poutbuf->data)
		cudbg_printf(cudbg_poutbuf, err1, "\n\nPM_TX\n\n");

	indirect_addr = PM_TX_INDIRECT;

	n = sizeof(t5_pm_tx_array)/(4 * sizeof(u32));
	for (i = 0; i < n; i++) {
		u32 *buff = ch_pm->outbuf;

		rc = dump_indirect_regs(t5_pm_tx_ptr[i], indirect_addr,
					(const u32 *) buff, cudbg_poutbuf);
		if (rc < 0)
			goto err1;
		ch_pm++;
	}

err1:
	free(dc_buff.data);

err:
	return rc;

}

int view_tx_rate(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		 enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct tx_rate *tx_rate;
	int rc = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);

	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	tx_rate = (struct tx_rate *)dc_buff.data;

	cudbg_printf(cudbg_poutbuf, err1, "\n\n\t\tTX_RATE\n\n");
	if (tx_rate->nchan == NCHAN) {
		cudbg_printf(cudbg_poutbuf, err1, "              channel 0   channel 1   channel 2   channel 3\n");
		cudbg_printf(cudbg_poutbuf, err1, "NIC B/s:     %10llu  %10llu"\
			     "  %10llu  %10llu\n",
			     (unsigned long long)tx_rate->nrate[0],
			     (unsigned long long)tx_rate->nrate[1],
			     (unsigned long long)tx_rate->nrate[2],
			     (unsigned long long)tx_rate->nrate[3]);
		cudbg_printf(cudbg_poutbuf, err1, "Offload B/s: %10llu  %10llu"\
			     "  %10llu  %10llu\n",
			     (unsigned long long)tx_rate->orate[0],
			     (unsigned long long)tx_rate->orate[1],
			     (unsigned long long)tx_rate->orate[2],
			     (unsigned long long)tx_rate->orate[3]);
	} else {
		cudbg_printf(cudbg_poutbuf, err1, "              channel 0   "\
			     "channel 1\n");
		cudbg_printf(cudbg_poutbuf, err1, "NIC B/s:     %10llu  "\
			     "%10llu\n",
			     (unsigned long long)tx_rate->nrate[0],
			     (unsigned long long)tx_rate->nrate[1]);
		cudbg_printf(cudbg_poutbuf, err1, "Offload B/s: %10llu  "\
			     "%10llu\n",
			     (unsigned long long)tx_rate->orate[0],
			     (unsigned long long)tx_rate->orate[1]);
	}

err1:
	free(dc_buff.data);

err:
	return rc;
}

int view_tid(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
	     enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct tid_info_region *tid;
	int rc = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);

	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	tid = (struct tid_info_region *)dc_buff.data;
	cudbg_printf(cudbg_poutbuf, err1, "\n\n\tTID INFO\n\n");
	if (tid->le_db_conf & F_HASHEN) {
		if (tid->sb) {
			cudbg_printf(cudbg_poutbuf, err1, "TID range: "\
				     "0..%u/%u..%u\n", tid->sb - 1,
				     tid->hash_base, tid->ntids - 1);
		} else if (tid->flags & FW_OFLD_CONN) {
			cudbg_printf(cudbg_poutbuf, err1, "TID range: "\
				     "%u..%u/%u..%u\n", tid->aftid_base,
				     tid->aftid_end, tid->hash_base,
				     tid->ntids - 1);

		} else {
			cudbg_printf(cudbg_poutbuf, err1, "TID range: "\
				     "%u..%u\n", tid->hash_base,
				     tid->ntids - 1);
		}
	} else if (tid->ntids) {
		cudbg_printf(cudbg_poutbuf, err1, "TID range: %u..%u\n",
			     tid->hash_base, tid->ntids - 1);
	}

	if (tid->nstids)
		cudbg_printf(cudbg_poutbuf, err1, "STID range: %u..%u\n",
			     tid->stid_base, tid->stid_base + tid->nstids - 1);
	if (tid->natids)
		cudbg_printf(cudbg_poutbuf, err1, "ATID range: 0..%u\n",
			     tid->natids - 1);

#if 0    /*For T4 cards*/
	if (tid->nsftids)
		cudbg_printf(cudbg_poutbuf, err1, "SFTID range: %u..%u\n",
			     tid->sftid_base,
			     tid->sftid_base + tid->nsftids - 2);
#endif

	if (tid->nuotids)
		cudbg_printf(cudbg_poutbuf, err1, "UOTID range: %u..%u\n",
			     tid->uotid_base,
			     tid->uotid_base + tid->nuotids - 1);

	if (tid->nhpftids && is_t6(chip))
		cudbg_printf(cudbg_poutbuf, err1, "HPFTID range: %u..%u\n",
			     tid->hpftid_base,
			     tid->hpftid_base + tid->nhpftids - 1);
	if (tid->ntids)
		cudbg_printf(cudbg_poutbuf, err1, "HW TID usage: %u IP users, "\
			     "%u IPv6 users\n",
			     tid->IP_users, tid->IPv6_users);

err1:
	free(dc_buff.data);

err:
	return rc;
}

static int show_cntxt(struct cudbg_ch_cntxt *context,
		      struct cudbg_cntxt_field *field,
		      struct cudbg_buffer *cudbg_poutbuf)
{
	char str[8];
	int rc;

	if (context->cntxt_type == CTXT_EGRESS)
		strcpy(str, "egress");
	if (context->cntxt_type == CTXT_INGRESS)
		strcpy(str, "ingress");
	if (context->cntxt_type == CTXT_FLM)
		strcpy(str, "fl");
	if (context->cntxt_type == CTXT_CNM)
		strcpy(str, "cong");
	cudbg_printf(cudbg_poutbuf, err1, "\n\nContext type: %-47s\nQueue ID: "\
			"%-10d\n", str, context->cntxt_id);

	while (field->name) {
		unsigned long long data;

		u32 index = field->start_bit / 32;
		u32 bits = field->start_bit % 32;
		u32 width = field->end_bit - field->start_bit + 1;
		u32 mask = (1ULL << width) - 1;

		data = (unsigned long long)((context->data[index] >> bits) |
		       ((u64)context->data[index + 1] << (32 - bits)));
		if (bits)
			data |= ((u64)context->data[index + 2] << (64 - bits));
		data &= mask;

		if (field->islog2)
			data = (unsigned long long)(1 << data);

		cudbg_printf(cudbg_poutbuf, err1, "%-47s %#-10llx\n",
			     field->name, data << field->shift);
		field++;
	}
err1:
	return rc;
}

int view_mps_tcam(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		  enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct cudbg_mps_tcam *tcam;
	int rc = 0;
	int n;
	int i;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);

	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;
	n = dc_buff.size / sizeof(struct cudbg_mps_tcam);

	tcam = (struct cudbg_mps_tcam *)dc_buff.data;

	if (is_t6(chip)) {
		cudbg_printf(cudbg_poutbuf, err1, "Idx  Ethernet address     "\
			     "Mask       VNI   Mask   IVLAN Vld DIP_Hit   "\
			     "Lookup  Port Vld Ports PF  VF                  "\
			     "         Replication                           "\
			     "         P0 P1 P2 P3  ML\n");
	} else if (is_t5(chip)) {
		if (tcam->rplc_size > CUDBG_MAX_RPLC_SIZE) {
			cudbg_printf(cudbg_poutbuf, err1, "Idx  Ethernet "\
				     "address     Mask     Vld Ports PF  VF  "\
				     "                         Replication   "\
				     "                                 P0 P1 "\
				     "P2 P3  ML\n");
		} else {
			cudbg_printf(cudbg_poutbuf, err1, "Idx  Ethernet "\
				     "address     Mask     Vld Ports PF  VF  "\
				     "            Replication               P0"\
				     " P1 P2 P3  ML\n");
		}
	}

	for (i = 0; i < n; i++) {
		if (is_t6(chip)) {
			/* Inner header lookup */
			if (tcam->lookup_type && (tcam->lookup_type !=
						  M_DATALKPTYPE)) {
				cudbg_printf(cudbg_poutbuf, err1, "%3u "\
					     "%02x:%02x:%02x:%02x:%02x:%02x "\
					     "%012llx %06x %06x    -    -   "\
					     "%3c      %3c  %4x   %3c   "\
					     "%#x%4u%4d",
					     tcam->idx, tcam->addr[0],
					     tcam->addr[1], tcam->addr[2],
					     tcam->addr[3], tcam->addr[4],
					     tcam->addr[5],
					     (unsigned long long)tcam->mask,
					     tcam->vniy, tcam->vnix,
					     tcam->dip_hit ? 'Y' : 'N',
					     tcam->lookup_type ? 'I' : 'O',
					     tcam->port_num,
					     (tcam->cls_lo & F_T6_SRAM_VLD)
					     ? 'Y' : 'N',
					     G_PORTMAP(tcam->cls_hi),
					     G_T6_PF(tcam->cls_lo),
					     (tcam->cls_lo & F_T6_VF_VALID)
					     ?
					     G_T6_VF(tcam->cls_lo) : -1);
			} else {
				cudbg_printf(cudbg_poutbuf, err1, "%3u "\
					     "%02x:%02x:%02x:%02x:%02x:%02x"\
					     " %012llx    -       -   ",
					     tcam->idx, tcam->addr[0],
					     tcam->addr[1], tcam->addr[2],
					     tcam->addr[3], tcam->addr[4],
					     tcam->addr[5],
					     (unsigned long long)tcam->mask);

				if (tcam->vlan_vld) {
					cudbg_printf(cudbg_poutbuf, err1,
						     "%4u  Y     ",
						     tcam->ivlan);
				} else {
					cudbg_printf(cudbg_poutbuf, err1,
						     "  -    N     ");
				}

				cudbg_printf(cudbg_poutbuf, err1,
					     "-      %3c  %4x   %3c   "\
					     "%#x%4u%4d",
					     tcam->lookup_type ? 'I' : 'O',
					     tcam->port_num,
					     (tcam->cls_lo & F_T6_SRAM_VLD)
					     ? 'Y' : 'N',
					     G_PORTMAP(tcam->cls_hi),
					     G_T6_PF(tcam->cls_lo),
					     (tcam->cls_lo & F_T6_VF_VALID)
					     ?
					     G_T6_VF(tcam->cls_lo) : -1);
			}
		} else if (is_t5(chip)) {
			cudbg_printf(cudbg_poutbuf, err1, "%3u "\
				     "%02x:%02x:%02x:%02x:%02x:%02x %012llx%3c"\
				     "   %#x%4u%4d",
				     tcam->idx, tcam->addr[0], tcam->addr[1],
				     tcam->addr[2], tcam->addr[3],
				     tcam->addr[4], tcam->addr[5],
				     (unsigned long long)tcam->mask,
				     (tcam->cls_lo & F_SRAM_VLD) ? 'Y' : 'N',
				     G_PORTMAP(tcam->cls_hi),
				     G_PF(tcam->cls_lo),
				     (tcam->cls_lo & F_VF_VALID) ?
				     G_VF(tcam->cls_lo) : -1);
		}

		if (tcam->repli) {
			if (tcam->rplc_size > CUDBG_MAX_RPLC_SIZE) {
				cudbg_printf(cudbg_poutbuf, err1, " %08x %08x "\
					     "%08x %08x %08x %08x %08x %08x",
					     tcam->rplc[7], tcam->rplc[6],
					     tcam->rplc[5], tcam->rplc[4],
					     tcam->rplc[3], tcam->rplc[2],
					     tcam->rplc[1], tcam->rplc[0]);
			} else {
				cudbg_printf(cudbg_poutbuf, err1, " %08x %08x "\
					     "%08x %08x", tcam->rplc[3],
					     tcam->rplc[2], tcam->rplc[1],
					     tcam->rplc[0]);
			}
		} else {
			if (tcam->rplc_size > CUDBG_MAX_RPLC_SIZE)
				cudbg_printf(cudbg_poutbuf, err1, "%72c", ' ');
			else
				cudbg_printf(cudbg_poutbuf, err1, "%36c", ' ');
		}
		if (is_t6(chip)) {
			cudbg_printf(cudbg_poutbuf, err1,  "%4u%3u%3u%3u %#x\n",
				     G_T6_SRAM_PRIO0(tcam->cls_lo),
				     G_T6_SRAM_PRIO1(tcam->cls_lo),
				     G_T6_SRAM_PRIO2(tcam->cls_lo),
				     G_T6_SRAM_PRIO3(tcam->cls_lo),
				     (tcam->cls_lo >> S_T6_MULTILISTEN0) & 0xf);
		} else if (is_t5(chip)) {
			cudbg_printf(cudbg_poutbuf, err1, "%4u%3u%3u%3u %#x\n",
				     G_SRAM_PRIO0(tcam->cls_lo),
				     G_SRAM_PRIO1(tcam->cls_lo),
				     G_SRAM_PRIO2(tcam->cls_lo),
				     G_SRAM_PRIO3(tcam->cls_lo),
				     (tcam->cls_lo >> S_MULTILISTEN0) & 0xf);
		}
		tcam++;
	}

err1:
	free(dc_buff.data);

err:
	return rc;
}

int view_dump_context(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		      enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct cudbg_ch_cntxt *context;
	int rc = 0;
	int n;
	int i;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);

	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;
	n = dc_buff.size / sizeof(struct cudbg_ch_cntxt);

	context = (struct cudbg_ch_cntxt *)dc_buff.data;

	for (i = 0; i < n; i++) {
		if (context->cntxt_type == CTXT_EGRESS) {
			if (is_t5(chip))
				rc = show_cntxt(context, t5_egress_cntxt,
						cudbg_poutbuf);
			else if (is_t6(chip))
				rc = show_cntxt(context, t6_egress_cntxt,
						cudbg_poutbuf);
		} else if (context->cntxt_type == CTXT_INGRESS) {
			if (is_t5(chip))
				rc = show_cntxt(context, t5_ingress_cntxt,
						cudbg_poutbuf);
			else if (is_t6(chip))
				rc = show_cntxt(context, t6_ingress_cntxt,
						cudbg_poutbuf);
		} else if (context->cntxt_type == CTXT_CNM)
			rc = show_cntxt(context, t5_cnm_cntxt, cudbg_poutbuf);
		else if (context->cntxt_type == CTXT_FLM) {
			if (is_t5(chip))
				rc = show_cntxt(context, t5_flm_cntxt,
						cudbg_poutbuf);
			else if (is_t6(chip))
				rc = show_cntxt(context, t6_flm_cntxt,
						cudbg_poutbuf);
		}

		if (rc < 0)
			goto err1;

		context++;
	}

err1:
	free(dc_buff.data);

err:
	return rc;
}

int view_le_tcam(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		 enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct cudbg_tid_data *tid_data = NULL;
	struct cudbg_tcam *tcam_region = NULL;
	char *le_region[] = {
		"active", "server", "filter", "clip", "routing"
	};
	int rc = 0, j;
	u32 i;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);

	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	tcam_region = (struct cudbg_tcam *)dc_buff.data;
	tid_data = (struct cudbg_tid_data *)(tcam_region + 1);

	cudbg_printf(cudbg_poutbuf, err1, "\n\nRouting table index: 0x%X\n",
		     tcam_region->routing_start);
	cudbg_printf(cudbg_poutbuf, err1, "Lip comp table index: 0x%X\n",
		     tcam_region->clip_start);
	cudbg_printf(cudbg_poutbuf, err1, "Filter table index: 0x%X\n",
		     tcam_region->filter_start);
	cudbg_printf(cudbg_poutbuf, err1, "Server index: 0x%X\n\n",
		     tcam_region->server_start);

	cudbg_printf(cudbg_poutbuf, err1, "tid start: %d\n\n", 0);
	cudbg_printf(cudbg_poutbuf, err1, "tid end: %d\n\n",
		     tcam_region->max_tid);

	for (i = 0; i < tcam_region->max_tid; i++) {
		cudbg_printf(cudbg_poutbuf, err1,
			     "======================================================================================\n");
		cudbg_printf(cudbg_poutbuf, err1, "This is a LE_DB_DATA_READ "\
			     "command: on TID %d at index %d\n", i, i * 4);
		if (i < tcam_region->server_start / 4) {
			cudbg_printf(cudbg_poutbuf, err1, "Region: %s\n\n",
				     le_region[0]);
		} else if ((i >= tcam_region->server_start / 4) &&
			   (i < tcam_region->filter_start / 4)) {
			cudbg_printf(cudbg_poutbuf, err1, "Region: %s\n\n",
				     le_region[1]);
		} else if ((i >= tcam_region->filter_start / 4) &&
			   (i < tcam_region->clip_start / 4)) {
			cudbg_printf(cudbg_poutbuf, err1, "Region: %s\n\n",
				     le_region[2]);
		} else if ((i >= tcam_region->clip_start / 4) &&
			   (i < tcam_region->routing_start / 4)) {
			cudbg_printf(cudbg_poutbuf, err1, "Region: %s\n\n",
				     le_region[3]);
		} else if (i >= tcam_region->routing_start / 4) {
			cudbg_printf(cudbg_poutbuf, err1, "Region: %s\n\n",
				     le_region[4]);
		}

		cudbg_printf(cudbg_poutbuf, err1, "READ:\n");
		cudbg_printf(cudbg_poutbuf, err1, "DBGICMDMODE: %s\n",
			     (tid_data->dbig_conf & 1) ? "LE" : "TCAM");
		cudbg_printf(cudbg_poutbuf, err1, "READING TID: 0x%X\n",
			     tid_data->tid);
		cudbg_printf(cudbg_poutbuf, err1, "Write: "\
			     "LE_DB_DBGI_REQ_TCAM_CMD: 0x%X\n",
			     tid_data->dbig_cmd);
		cudbg_printf(cudbg_poutbuf, err1, "Write: LE_DB_DBGI_CONFIG "\
			     "0x%X\n", tid_data->dbig_conf);
		cudbg_printf(cudbg_poutbuf, err1, "Polling: LE_DB_DBGI_CONFIG:"\
			     " busy bit\n");
		cudbg_printf(cudbg_poutbuf, err1, "Read: "\
			     "LE_DB_DBGI_RSP_STATUS: 0x%X [%d]\n",
			     tid_data->dbig_rsp_stat & 1,
			     tid_data->dbig_rsp_stat & 1);
		cudbg_printf(cudbg_poutbuf, err1, "Read: "\
			     "LE_DB_DBGI_RSP_DATA:\n");
		cudbg_printf(cudbg_poutbuf, err1, "Response data for TID "\
			     "0x%X:\n", i);

		for (j = 0; j < CUDBG_NUM_REQ_REGS; j++) {
			cudbg_printf(cudbg_poutbuf, err1, "\t0x%X: 0x%08X\n",
				     A_LE_DB_DBGI_RSP_DATA + (j << 2),
				     tid_data->data[j]);
		}

		cudbg_printf(cudbg_poutbuf, err1, "DATA READ: ");
		for (j = CUDBG_NUM_REQ_REGS - 1; j >= 0; j--) {
			cudbg_printf(cudbg_poutbuf, err1, "%08X",
				     tid_data->data[j]);
		}
		cudbg_printf(cudbg_poutbuf, err1, "\n\n");

		tid_data++;
	}

err1:
	free(dc_buff.data);
err:
	return rc;
}

int view_pcie_config(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		     enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	u32 *pcie_config;
	int rc = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);

	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	if (!cudbg_poutbuf->data)
		cudbg_printf(cudbg_poutbuf, err1, "\n\t\t\tPCIE CONFIG\n\n");

	pcie_config = (u32 *)dc_buff.data;
	rc = dump_indirect_regs(t5_pcie_config_ptr[0], 0,
				(const u32 *)pcie_config, cudbg_poutbuf);

err1:
	free(dc_buff.data);

err:
	return rc;
}

int view_pcie_indirect(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		       enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct ireg_buf *ch_pcie;
	u32 indirect_addr;
	int rc = 0;
	int i = 0;
	int n;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);

	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	if (!cudbg_poutbuf->data)
		cudbg_printf(cudbg_poutbuf, err1, "\n\nPCIE_PDBG\n\n");

	indirect_addr = PCIE_PDEBUG_INDIRECT;

	ch_pcie = (struct ireg_buf *)dc_buff.data;
	n = sizeof(t5_pcie_pdbg_array)/(4 * sizeof(u32));
	for (i = 0; i < n; i++) {
		u32 *buff = ch_pcie->outbuf;

		rc = dump_indirect_regs(t5_pcie_pdbg_ptr[i], indirect_addr,
					(const u32 *) buff, cudbg_poutbuf);
		if (rc < 0)
			goto err1;
		ch_pcie++;
	}

	if (!cudbg_poutbuf->data)
		cudbg_printf(cudbg_poutbuf, err1, "\n\nPCIE_CDBG\n\n");

	indirect_addr = PCIE_CDEBUG_INDIRECT;

	n = sizeof(t5_pcie_cdbg_array)/(4 * sizeof(u32));
	for (i = 0; i < n; i++) {
		u32 *buff = ch_pcie->outbuf;

		rc = dump_indirect_regs(t5_pcie_cdbg_ptr[i], indirect_addr,
					(const u32 *) buff, cudbg_poutbuf);
		if (rc < 0)
			goto err1;
		ch_pcie++;
	}

err1:
	free(dc_buff.data);

err:
	return rc;

}

int view_tp_indirect(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		     enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct ireg_buf *ch_tp_pio;
	u32 *pkey = NULL;
	u32 indirect_addr;
	int rc = 0;
	int i = 0;
	int j = 0, k, l, len, n = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);

	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	ch_tp_pio = (struct ireg_buf *)dc_buff.data;
	l = 0;

	indirect_addr = TP_PIO;
	if (!cudbg_poutbuf->data)
		cudbg_printf(cudbg_poutbuf, err1, "\n\nTP_PIO\n\n");

	if (CHELSIO_CHIP_VERSION(chip) <= CHELSIO_T5)
		n = sizeof(t5_tp_pio_array)/(4 * sizeof(u32));
	else if (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T6)
		n = sizeof(t6_tp_pio_array)/(4 * sizeof(u32));

	for (i = 0; i < n; i++) {
		u32 *buff = ch_tp_pio->outbuf;

		if (CHELSIO_CHIP_VERSION(chip) <= CHELSIO_T5)
			rc = dump_indirect_regs(t5_tp_pio_ptr[i], indirect_addr,
						(const u32 *) buff,
						cudbg_poutbuf);
		else if (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T6)
			rc = dump_indirect_regs(t6_tp_pio_ptr[i], indirect_addr,
						(const u32 *) buff,
						cudbg_poutbuf);

		if (rc < 0)
			goto err1;

		ch_tp_pio++;
	}

	indirect_addr = TP_TM_PIO_ADDR;
	if (!cudbg_poutbuf->data)
		cudbg_printf(cudbg_poutbuf, err1, "\n\nTP_TM_PIO\n\n");
	l = 0;

	if (CHELSIO_CHIP_VERSION(chip) <= CHELSIO_T5)
		n = sizeof(t5_tp_tm_pio_array)/(4 * sizeof(u32));
	else if (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T6)
		n = sizeof(t6_tp_tm_pio_array)/(4 * sizeof(u32));

	for (i = 0; i < n; i++) {
		u32 *buff = ch_tp_pio->outbuf;

		if (CHELSIO_CHIP_VERSION(chip) <= CHELSIO_T5)
			rc = dump_indirect_regs(t5_tp_tm_regs, indirect_addr,
						(const u32 *)buff,
						cudbg_poutbuf);
		else if (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T6)
			rc = dump_indirect_regs(t6_tp_tm_regs, indirect_addr,
						(const u32 *)buff,
						cudbg_poutbuf);

		if (rc < 0)
			goto err1;

		ch_tp_pio++;
	}
	indirect_addr = TP_MIB_INDEX;
	if (!cudbg_poutbuf->data)
		cudbg_printf(cudbg_poutbuf, err1, "\n\nTP_MIB_INDEX\n\n");

	l = 0;
	if (CHELSIO_CHIP_VERSION(chip) <= CHELSIO_T5)
		n = sizeof(t5_tp_mib_index_array)/(4 * sizeof(u32));
	else if (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T6)
		n = sizeof(t6_tp_mib_index_array)/(4 * sizeof(u32));
	for (i = 0; i < n ; i++) {
		u32 *buff = ch_tp_pio->outbuf;

		pkey = (u32 *) buff;
		if (CHELSIO_CHIP_VERSION(chip) <= CHELSIO_T5)
			j = l + t5_tp_mib_index_array[i][3];
		else if (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T6)
			j = l + t6_tp_mib_index_array[i][3];

		len = 0;
		for (k = l; k < j; k++) {
			if (CHELSIO_CHIP_VERSION(chip) <= CHELSIO_T5) {
				cudbg_printf(cudbg_poutbuf, err1, "[0x%x:%2s]"\
					     " %-47s %#-10x %u\n",
					     indirect_addr,
					     t5_tp_mib_index_reg_array[k].addr,
					     t5_tp_mib_index_reg_array[k].name,
					     pkey[len], pkey[len]);
			} else if (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T6) {
				cudbg_printf(cudbg_poutbuf, err1, "[0x%x:%2s]"\
					     " %-47s %#-10x %u\n",
					     indirect_addr,
					     t6_tp_mib_index_reg_array[k].addr,
					     t6_tp_mib_index_reg_array[k].name,
					     pkey[len], pkey[len]);
			}

			len++;

		}
		l = k;
		ch_tp_pio++;
	}

err1:
	free(dc_buff.data);

err:
	return rc;
}

int view_sge_indirect(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		      enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	u32 *pkey = NULL;
	u32 indirect_addr;
	int rc = 0;
	int i = 0;
	int j, k;
	int l = 0;
	int len;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);

	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	pkey = (u32 *) dc_buff.data;

	indirect_addr = SGE_DEBUG_DATA_INDIRECT;

	for (i = 0; i < 2; i++) {
		cudbg_printf(cudbg_poutbuf, err1, "\n");
		j = l + t5_sge_dbg_index_array[i][3];
		len = 0;
		for (k = l; k < j; k++) {
			if (i == 0) {
				cudbg_printf(cudbg_poutbuf, err1, "[0x%x:0x%x]"\
					     "  %-47s %#-10x %u\n",
					     indirect_addr,
					     sge_debug_data_high[k].addr,
					     sge_debug_data_high[k].name,
					     pkey[len], pkey[len]);
			} else {
				cudbg_printf(cudbg_poutbuf, err1, "[0x%x:0x%x]"\
					     " %-47s %#-10x %u\n",
					     indirect_addr,
					     sge_debug_data_low[k].addr,
					     sge_debug_data_low[k].name,
					     pkey[len], pkey[len]);
			}
			len++;
		}
		pkey = (u32 *)((char *)pkey + sizeof(struct ireg_buf));
	}

err1:
	free(dc_buff.data);

err:
	return rc;
}

static int view_full_t6(char *pbuf, u32 size, struct cudbg_buffer
			*cudbg_poutbuf)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	u32 *sp;
	u32 tx, rx, cs, es, pcie, pcie1, sge;
	u32 pcie_c0rd_full, pcie_c0wr_full, pcie_c0rsp_full;
	u32 pcie_c1rd_full, pcie_c1wr_full, pcie_c1rsp_full;
	u32 sge_req_full = 0, sge_rx_full;
	u32 rx_fifo_cng, rx_pcmd_cng, rx_hdr_cng;
	u32 cng0, cng1;
	int rc = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);

	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	sp = (u32 *)dc_buff.data;

	/* Collect Registers:
	 * TP_DBG_SCHED_TX (0x7e40 + 0x6a),
	 * TP_DBG_SCHED_RX (0x7e40 + 0x6b),
	 * TP_DBG_CSIDE_INT (0x7e40 + 0x23f),
	 * TP_DBG_ESIDE_INT (0x7e40 + 0x148),
	 * PCIE_CDEBUG_INDEX[AppData0] (0x5a10 + 2),
	 * PCIE_CDEBUG_INDEX[AppData1] (0x5a10 + 3),
	 * SGE_DEBUG_DATA_HIGH_INDEX_10 (0x12a8)
	 **/
	tx = *sp;
	rx = *(sp + 1);
	cs = *(sp + 2);
	es = *(sp + 3);
	pcie = *(sp + 4);
	pcie1 = *(sp + 5);
	sge = *(sp + 6);

	pcie_c0wr_full = pcie & 1;
	pcie_c0rd_full = (pcie >> 2) & 1;
	pcie_c0rsp_full = (pcie >> 4) & 1;

	pcie_c1wr_full = pcie1 & 1;
	pcie_c1rd_full = (pcie1 >> 2) & 1;
	pcie_c1rsp_full = (pcie1 >> 4) & 1;

	/* sge debug_PD_RdRspAFull_d for each channel */
	sge_rx_full = (sge >> 30) & 0x3;

	rx_fifo_cng = (rx >> 20) & 0xf;
	rx_pcmd_cng = (rx >> 14) & 0x3;
	rx_hdr_cng = (rx >> 8) & 0xf;
	cng0 = (rx_fifo_cng & 1) | (rx_pcmd_cng & 1) | (rx_hdr_cng & 1);
	cng1 = ((rx_fifo_cng & 2) >> 1) | ((rx_pcmd_cng & 2) >> 1) |
		((rx_hdr_cng & 2) >> 1);

	cudbg_printf(cudbg_poutbuf, err1, "\n");
	/* TP resource reservation */
	cudbg_printf(cudbg_poutbuf, err1, "Tx0 ==%1u=>  T  <=%1u= Rx0\n",
		     ((tx >> 28) & 1), ((rx >> 28) & 1));
	cudbg_printf(cudbg_poutbuf, err1, "Tx1 ==%1u=>  P  <=%1u= Rx1\n",
		     ((tx >> 29) & 1), ((rx >> 29) & 1));
	cudbg_printf(cudbg_poutbuf, err1, "\n");

	/* TX path */
	/* pcie bits 19:16 are D_RspAFull for each channel */
	/* Tx is blocked when Responses from system cannot flow toward TP. */
	cudbg_printf(cudbg_poutbuf, err1, "Tx0 P =%1u=> S ? U =>%1u=>  T\n",
		     pcie_c0rsp_full, ((cs >> 24) & 1));
	cudbg_printf(cudbg_poutbuf, err1, "Tx1 C =%1u=> G ? T =>%1u=>  P\n",
		     pcie_c1rsp_full, ((cs >> 25) & 1));

	/* RX path */
	/* Rx is blocked when sge and/or pcie cannot send requests to system.
	 * */
	cudbg_printf(cudbg_poutbuf, err1, "       Rd Wr\n");
	cudbg_printf(cudbg_poutbuf, err1, "RX0 P <=%1u=%1u=%1u S <=%1u= C "\
		     "<=%1u= T <=T <=%1u=  T <=%1u= M\n",
		     ((pcie_c0rd_full >> 0) & 1), ((pcie_c0wr_full >> 0) & 1),
		     ((sge_req_full >> 0) & 1), ((sge_rx_full >> 0) & 1),
		     cng0, ((cs >> 20) & 1), ((es >> 16) & 1));
	cudbg_printf(cudbg_poutbuf, err1, "RX1 C <=%1u=%1u=%1u G <=%1u= X "\
		     "<=%1u= C <=P <=%1u=  E <=%1u= P\n",
		     ((pcie_c1rd_full >> 1) & 1), ((pcie_c1wr_full >> 1) & 1),
		     ((sge_req_full >> 1) & 1), ((sge_rx_full >> 1) & 1),
		     cng1, ((cs >> 21) & 1), ((es >> 17) & 1));
	cudbg_printf(cudbg_poutbuf, err1, "\n");

err1:
	free(dc_buff.data);

err:
	return rc;
}

static int view_full_t5(char *pbuf, u32 size, struct cudbg_buffer
			*cudbg_poutbuf)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	u32 *sp;
	u32 tx, rx, cs, es, pcie, sge;
	u32 pcie_rd_full, pcie_wr_full; //, pcie_full;
	u32 sge_rsp_full, sge_req_full, sge_rx_full;
	u32 rx_fifo_cng, rx_pcmd_cng, rx_hdr_cng;
	u32 cng0, cng1;
	int rc = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);

	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	sp = (u32 *)dc_buff.data;

	/* Collect Registers:
	 * TP_DBG_SCHED_TX (0x7e40 + 0x6a),
	 * TP_DBG_SCHED_RX (0x7e40 + 0x6b),
	 * TP_DBG_CSIDE_INT (0x7e40 + 0x23f),
	 * TP_DBG_ESIDE_INT (0x7e40 + 0x148),
	 * PCIE_CDEBUG_INDEX[AppData0] (0x5a10 + 2),
	 * SGE_DEBUG_DATA_HIGH_INDEX_10 (0x12a8)
	 **/
	tx = *sp;
	rx = *(sp + 1);
	cs = *(sp + 2);
	es = *(sp + 3);
	pcie = *(sp + 4);
	sge = *(sp + 5);

	pcie_rd_full = (pcie >> 8) & 0xf;
	pcie_wr_full = pcie & 0xf;

	/* OR together D_RdReqAFull and D_WrReqAFull for pcie */

	/* sge debug_PD_RdRspAFull_d for each channel */
	sge_rsp_full = ((sge >> 26) & 0xf);
	/* OR together sge debug_PD_RdReqAFull_d and debug PD_WrReqAFull_d */
	sge_req_full = ((sge >> 22) & 0xf) | ((sge >> 18) & 0xf);
	sge_rx_full = (sge >> 30) & 0x3;

	rx_fifo_cng = (rx >> 20) & 0xf;
	rx_pcmd_cng = (rx >> 14) & 0x3;
	rx_hdr_cng = (rx >> 8) & 0xf;
	cng0 = (rx_fifo_cng & 1) | (rx_pcmd_cng & 1) | (rx_hdr_cng & 1);
	cng1 = ((rx_fifo_cng & 2) >> 1) | ((rx_pcmd_cng & 2) >> 1) |
		((rx_hdr_cng & 2) >> 1);

	cudbg_printf(cudbg_poutbuf, err1, "\n");
	/* TP resource reservation */
	cudbg_printf(cudbg_poutbuf, err1, "Tx0 ==%1u=\\     /=%1u= Rx0\n",
		     ((tx >> 28) & 1), ((rx >> 28) & 1));
	cudbg_printf(cudbg_poutbuf, err1, "Tx1 ==%1u= | T | =%1u= Rx1\n",
		     ((tx >> 29) & 1), ((rx >> 29) & 1));
	cudbg_printf(cudbg_poutbuf, err1, "Tx2 ==%1u= | P | =%1u= Rx2\n",
		     ((tx >> 30) & 1), ((rx >> 30) & 1));
	cudbg_printf(cudbg_poutbuf, err1, "Tx3 ==%1u=/     \\=%1u= Rx3\n",
		     ((tx >> 31) & 1), ((rx >> 31) & 1));
	cudbg_printf(cudbg_poutbuf, err1, "\n");

	/* TX path */
	/* pcie bits 19:16 are D_RspAFull for each channel */
	/* Tx is blocked when Responses from system cannot flow toward TP. */
	cudbg_printf(cudbg_poutbuf, err1, "Tx0 P =%1u=%1u=\\ S ? U ==%1u=\\\n",
		     ((pcie >> 16) & 1), (sge_rsp_full & 1), ((cs >> 24) & 1));
	cudbg_printf(cudbg_poutbuf, err1, "Tx1 C =%1u=%1u= |G ? T ==%1u= | T\n",
		     ((pcie >> 17) & 1), ((sge_rsp_full >> 1) & 1),
		     ((cs >> 25) & 1));
	cudbg_printf(cudbg_poutbuf, err1, "Tx2 I =%1u=%1u= |E ? X ==%1u= | P\n",
		     ((pcie >> 18) & 1), ((sge_rsp_full >> 2) & 1),
		     ((cs >> 26) & 1));
	cudbg_printf(cudbg_poutbuf, err1, "Tx3 E =%1u=%1u=/   ?   ==%1u=/\n",
		     ((pcie >> 19) & 1), ((sge_rsp_full >> 3) & 1),
		     ((cs >> 27) & 1));
	cudbg_printf(cudbg_poutbuf, err1, "\n");

	/* RX path */
	/* Rx is blocked when sge and/or pcie cannot send requests to system.
	 * */
	cudbg_printf(cudbg_poutbuf, err1, "       Rd Wr\n");
	cudbg_printf(cudbg_poutbuf, err1, "RX0 P /=%1u=%1u=%1u S <=%1u= C "\
		     "<=%1u= T <=T <=%1u=  T /=%1u= M\n",
		     ((pcie_rd_full >> 0) & 1), ((pcie_wr_full >> 0) & 1),
		     ((sge_req_full >> 0) & 1), ((sge_rx_full >> 0) & 1),
		     cng0, ((cs >> 20) & 1), ((es >> 16) & 1));
	cudbg_printf(cudbg_poutbuf, err1, "RX1 C| =%1u=%1u=%1u G <=%1u= X "\
		     "<=%1u= C <=P <=%1u=  E| =%1u= P\n",
		     ((pcie_rd_full >> 1) & 1), ((pcie_wr_full >> 1) & 1),
		     ((sge_req_full >> 1) & 1), ((sge_rx_full >> 1) & 1),
		     cng1, ((cs >> 21) & 1), ((es >> 17) & 1));
	cudbg_printf(cudbg_poutbuf, err1, "RX2 I| =%1u=%1u=%1u E             "\
		     "             | =%1u= S\n",
		     ((pcie_rd_full >> 2) & 1), ((pcie_wr_full >> 2) & 1),
		     ((sge_req_full >> 2) & 1), ((es >> 18) & 1));
	cudbg_printf(cudbg_poutbuf, err1, "RX3 E \\=%1u=%1u=%1u               "\
		     "              \\=%1u=\n",
		     ((pcie_rd_full >> 3) & 1), ((pcie_wr_full >> 3) & 1),
		     ((sge_req_full >> 3) & 1), ((es >> 19) & 1));
	cudbg_printf(cudbg_poutbuf, err1, "\n");

err1:
	free(dc_buff.data);

err:
	return rc;
}

int view_full(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
	      enum chip_type chip)
{
	int rc = -1;

	if (is_t5(chip))
		rc = view_full_t5(pbuf, size, cudbg_poutbuf);
	else if (is_t6(chip))
		rc = view_full_t6(pbuf, size, cudbg_poutbuf);

	return rc;
}

int view_vpd_data(char *pbuf, u32 size, struct cudbg_buffer *cudbg_poutbuf,
		  enum chip_type chip)
{
	struct cudbg_buffer c_buff;
	struct cudbg_buffer dc_buff;
	struct struct_vpd_data *vpd_data;
	int rc = 0;

	c_buff.data = pbuf;
	c_buff.size = size;
	c_buff.offset = 0;
	dc_buff.data = NULL;
	dc_buff.size = 0;
	dc_buff.offset = 0;

	rc = validate_buffer(&c_buff);

	if (rc)
		goto err;

	rc = decompress_buffer_wrapper(&c_buff, &dc_buff);
	if (rc)
		goto err1;

	vpd_data = (struct struct_vpd_data *) dc_buff.data;
	cudbg_printf(cudbg_poutbuf, err1, "MN %s\n", vpd_data->mn);
	cudbg_printf(cudbg_poutbuf, err1, "SN %s\n", vpd_data->sn);
	cudbg_printf(cudbg_poutbuf, err1, "BN %s\n", vpd_data->bn);
	cudbg_printf(cudbg_poutbuf, err1, "NA %s\n", vpd_data->na);

err1:
	free(dc_buff.data);

err:
	return rc;
}
