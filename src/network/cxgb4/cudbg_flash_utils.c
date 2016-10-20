#ifdef __KERNEL__
#include <platdef.h>
#else
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#endif
#include <t4_regs.h>
#ifndef CUDBG_LITE
#include <fcntl.h>
#include <unistd.h>
#include <adap_util.h>
#include <common.h>
#include <t4_hw.h>
#include <t4_chip_type.h>
#include <adapter.h>
#endif
#include <cudbg_if.h>
#include <cudbg_lib_common.h>

enum {
	SF_ATTEMPTS = 10,		/* max retries for SF operations */

	/* flash command opcodes */
	SF_PROG_PAGE	= 2,	/* program page */
	SF_WR_DISABLE	= 4,	/* disable writes */
	SF_RD_STATUS	= 5,	/* read status register */
	SF_WR_ENABLE	= 6,	/* enable writes */
	SF_RD_DATA_FAST = 0xb,	/* read flash */
	SF_RD_ID	= 0x9f, /* read ID */
	SF_ERASE_SECTOR = 0xd8, /* erase sector */
};

#if 0
/*** Flash Layout	***/

	OPROM_START_SEC			0  /* First flash sector for
					      Option-ROM */
	NUM_OPROM_SEC			7  /* Number of flash sectors
					      for Option-ROM */
	FW_START_SEC			8  /* First flash sector for Firmware */

	NUM_FW_SEC			16 /* Number of flash sectors
					      for Firmware */
	BOOT_CONFIG_START_SEC		7  /* First flash sector for config
					      utility i params */
	NUM_BOOT_CONFIG_SEC		1  /* Number of flash sectors for config
					      utility params */
	HW_CONFIG_START_SEC		31 /* First flash sector for hardware
					      config file */
	NUM_HW_CONFIG_SEC		1  /* Number of flash sectors for
					      hardware config file */
	UTIL_START_SEC			7  /* First flash sector for Config
					      Utility */
	FCOE_BOOT_INFO_SEC		30 /* First flash sector for FCOE BOOT
					      INFO to OS */
	NUM_FCOE_BOOT_INFO_SEC		1  /* Number of flash sectors for FCOE
					      BOOT INFO to OS */
	ISCSI_BOOT_INFO_SEC		29 /* First flash sector for ISCSI BOOT
					      INFO to OS */
	NUM_ISCSI_BOOT_INFO_SEC		1  /* Number of flash sectors for ISCSI
					      BOOT INFO to OS */
	VPDINIT_BOOT_INFO_SEC		26 /* First flash sector for VPD INIT */

	NUM_VPDINIT_BOOT_SEC		1  /* Number of flash sectors for VPD
					      INIT */
#endif

/* cudbg is writing to second half of the flash 2 MB to 4 MB */


extern struct cudbg_flash_sec_info sec_info;

int write_flash(struct adapter *adap, u32 start_sec, void *data, u32 size);
int read_flash(struct adapter *adap, u32 start_sec , void *data, u32 size,
		u32 start_address);

void update_skip_size(u32 size)
{
	sec_info.skip_size += size;
}

void set_sector_availability(int sector_nu, int avail)
{
	sector_nu -= CUDBG_START_SEC;
	if (avail)
		set_dbg_bitmap(sec_info.sec_bitmap, sector_nu);
	else
		reset_dbg_bitmap(sec_info.sec_bitmap, sector_nu);
}

/* This function will return empty sector available for filling */
int find_empty_sec(void)
{
	int i, index, bit;

	for (i = CUDBG_START_SEC; i < CUDBG_SF_MAX_SECTOR; i++) {
		index = (i - CUDBG_START_SEC) / 8;
		bit = (i - CUDBG_START_SEC) % 8;
		if (!(sec_info.sec_bitmap[index] & (1 << bit)))
			return i;
	}

	return CUDBG_STATUS_FLASH_FULL;
}

/* This function will get header initially. If header is already there
 * then it will update that header */
void update_headers(void *handle, struct cudbg_buffer *dbg_buff,
		    u64 timestamp, u32 cur_entity_hdr_offset,
		    u32 start_offset, u32 ext_size)
{
	void *sec_hdr;
	struct cudbg_hdr *cudbg_hdr;
	struct cudbg_flash_hdr *flash_hdr;
	struct cudbg_entity_hdr *entity_hdr;
	u32 hdr_offset;
	u32 data_hdr_size;
	u32 total_hdr_size;
	u32 sec_hdr_start_addr;

	data_hdr_size = CUDBG_MAX_ENTITY * sizeof(struct cudbg_entity_hdr) +
				sizeof(struct cudbg_hdr);
	total_hdr_size = data_hdr_size + sizeof(struct cudbg_flash_hdr);
	sec_hdr_start_addr = CUDBG_SF_SECTOR_SIZE - total_hdr_size;
	sec_hdr  = sec_info.sec_data + sec_hdr_start_addr;

	flash_hdr = (struct cudbg_flash_hdr *)(sec_hdr);
	cudbg_hdr = (struct cudbg_hdr *)dbg_buff->data;

	/* initially initialize flash hdr and copy all data headers and
	 * in next calling (else part) copy only current entity header
	 */
	if ((start_offset - sec_info.skip_size) == data_hdr_size) {
		flash_hdr->signature = CUDBG_FL_SIGNATURE;
		flash_hdr->major_ver = CUDBG_FL_MAJOR_VERSION;
		flash_hdr->minor_ver = CUDBG_FL_MINOR_VERSION;
		flash_hdr->build_ver = CUDBG_FL_BUILD_VERSION;
		flash_hdr->hdr_len = sizeof(struct cudbg_flash_hdr);
		hdr_offset =  sizeof(struct cudbg_flash_hdr);

		memcpy((void *)((char *)sec_hdr + hdr_offset),
		       (void *)((char *)dbg_buff->data), data_hdr_size);
	} else
		memcpy((void *)((char *)sec_hdr +
			sizeof(struct cudbg_flash_hdr) +
			cur_entity_hdr_offset),
			(void *)((char *)dbg_buff->data +
			cur_entity_hdr_offset),
			sizeof(struct cudbg_entity_hdr));

	hdr_offset = data_hdr_size + sizeof(struct cudbg_flash_hdr);
	flash_hdr->data_len = cudbg_hdr->data_len - sec_info.skip_size;
	flash_hdr->timestamp = timestamp;

	entity_hdr = (struct cudbg_entity_hdr *)((char *)sec_hdr +
		      sizeof(struct cudbg_flash_hdr) +
		      cur_entity_hdr_offset);
	/* big entity like mc need to be skipped */
	entity_hdr->start_offset -= sec_info.skip_size;

	cudbg_hdr = (struct cudbg_hdr *)((char *)sec_hdr +
			sizeof(struct cudbg_flash_hdr));
	cudbg_hdr->data_len = flash_hdr->data_len;
	flash_hdr->data_len += ext_size;
}

/* Write CUDBG data into serial flash */
int cudbg_write_flash(void *handle, u64 timestamp, void *data,
		      u32 start_offset, u32 cur_entity_hdr_offset,
		      u32 cur_entity_size,
		      u32 ext_size)
{
	struct cudbg_init *cudbg_init = NULL;
	struct adapter *adap = NULL;
	struct cudbg_flash_hdr *flash_hdr = NULL;
	struct cudbg_buffer *dbg_buff = (struct cudbg_buffer *)data;
	u32 data_hdr_size;
	u32 total_hdr_size;
	u32 tmp_size;
	u32 sec_data_offset;
	u32 sec_hdr_start_addr;
	u32 sec_data_size;
	u32 space_left;
	int rc = 0;
	int sec;

	cudbg_init = &(((struct cudbg_private *)handle)->dbg_init);
	adap = cudbg_init->adap;

	data_hdr_size = CUDBG_MAX_ENTITY * sizeof(struct cudbg_entity_hdr) +
			sizeof(struct cudbg_hdr);
	total_hdr_size = data_hdr_size + sizeof(struct cudbg_flash_hdr);
	sec_hdr_start_addr = CUDBG_SF_SECTOR_SIZE - total_hdr_size;
	sec_data_size = sec_hdr_start_addr;

	cudbg_init->print("\tWriting %u bytes to flash\n",
			  cur_entity_size);

	/* this function will get header if sec_info.sec_data does not
	 * have any header and
	 * will update the header if it has header
	 */
	update_headers(handle, dbg_buff, timestamp,
		       cur_entity_hdr_offset,
		       start_offset, ext_size);

	if (ext_size) {
		cur_entity_size += sizeof(struct cudbg_entity_hdr);
		start_offset = dbg_buff->offset - cur_entity_size;
	}

	flash_hdr = (struct cudbg_flash_hdr *)(sec_info.sec_data +
			sec_hdr_start_addr);

	space_left = CUDBG_FLASH_SIZE - flash_hdr->data_len;
	if (cur_entity_size > space_left) {
		rc = CUDBG_STATUS_FLASH_FULL;
		goto out;
	}

	while (cur_entity_size > 0) {
		sec = find_empty_sec();
		if (sec_info.par_sec) {
			sec_data_offset = sec_info.par_sec_offset;
			set_sector_availability(sec_info.par_sec, 0);
			sec_info.par_sec = 0;
			sec_info.par_sec_offset = 0;

		} else {
			sec_info.cur_seq_no++;
			flash_hdr->sec_seq_no = sec_info.cur_seq_no;
			sec_data_offset = 0;
		}

		if (cur_entity_size + sec_data_offset > sec_data_size) {
			tmp_size = sec_data_size - sec_data_offset;
		} else {
			tmp_size = cur_entity_size;
			sec_info.par_sec = sec;
			sec_info.par_sec_offset = cur_entity_size +
						  sec_data_offset;
		}

		memcpy((void *)((char *)sec_info.sec_data + sec_data_offset),
		       (void *)((char *)dbg_buff->data + start_offset),
		       tmp_size);

		rc = write_flash(adap, sec, sec_info.sec_data,
				CUDBG_SF_SECTOR_SIZE);
		if (rc)
			goto out;

		cur_entity_size -= tmp_size;
		set_sector_availability(sec, 1);
		start_offset += tmp_size;
	}
out:
	return rc;
}

int write_flash(struct adapter *adap, u32 start_sec, void *data, u32 size)
{
	unsigned int addr;
	unsigned int i, n;
	unsigned int sf_sec_size;
	int rc = 0;

	u8 *ptr = (u8 *)data;

	sf_sec_size = adap->params.sf_size/adap->params.sf_nsec;

	addr =  start_sec * CUDBG_SF_SECTOR_SIZE;
	i = DIV_ROUND_UP(size,/* # of sectors spanned */
			sf_sec_size);

	rc = t4_flash_erase_sectors(adap, start_sec,
		   start_sec + i - 1);
	/*
	 * If size == 0 then we're simply erasing the FLASH sectors associated
	 * with the on-adapter OptionROM Configuration File.
	 */

	if (rc || size == 0)
		goto out;

	/* this will write to the flash up to SF_PAGE_SIZE at a time */
	for (i = 0; i < size; i += SF_PAGE_SIZE) {
		if ((size - i) <  SF_PAGE_SIZE)
			n = size - i;
		else
			n = SF_PAGE_SIZE;
		rc = t4_write_flash(adap, addr, n, ptr, 0);
		if (rc)
			goto out;

		addr += n;
		ptr += n;
	}

	return 0;
out:
	return rc;
}

int cudbg_read_flash_details(void *handle, struct cudbg_flash_hdr *data)
{
	int rc;
	rc = cudbg_read_flash(handle, (void *)data,
			      sizeof(struct cudbg_flash_hdr), 0);

	return rc;
}

int cudbg_read_flash_data(void *handle, void *buf, u32 buf_size)
{
	int rc;
	u32 total_hdr_size, data_header_size;
	void *payload = NULL;
	u32 payload_size = 0;

	data_header_size = CUDBG_MAX_ENTITY * sizeof(struct cudbg_entity_hdr) +
		sizeof(struct cudbg_hdr);
	total_hdr_size = data_header_size + sizeof(struct cudbg_flash_hdr);

	/* Copy flash header to buffer */
	rc = cudbg_read_flash(handle, buf, total_hdr_size, 0);
	if (rc != 0)
		goto out;
	payload = (char *)buf + total_hdr_size;
	payload_size  = buf_size - total_hdr_size;

	/* Reading flash data to buf */
	rc = cudbg_read_flash(handle, payload, payload_size, 1);
	if (rc != 0)
		goto out;

out:
	return rc;
}

int cudbg_read_flash(void *handle, void *data, u32 size, int data_flag)
{
	struct cudbg_init *cudbg_init = NULL;
	struct cudbg_flash_hdr flash_hdr;
	struct adapter *adap = NULL;
	u32 total_hdr_size;
	u32 data_hdr_size;
	u32 sec_hdr_start_addr;
	u32 tmp_size;
	u32 data_offset = 0;
	u32 i, j;
	int rc;

	cudbg_init = &(((struct cudbg_private *)handle)->dbg_init);
	adap = cudbg_init->adap;

	rc = t4_get_flash_params(adap);
	if (rc) {
		cudbg_init->print("\nGet flash params failed."
			"Try Again...readflash\n\n");
		return rc;
	}

	data_hdr_size = CUDBG_MAX_ENTITY * sizeof(struct cudbg_entity_hdr) +
			sizeof(struct cudbg_hdr);
	total_hdr_size = data_hdr_size + sizeof(struct cudbg_flash_hdr);
	sec_hdr_start_addr = CUDBG_SF_SECTOR_SIZE - total_hdr_size;

	if (!data_flag) {
		/* fill header */
		if (!sec_info.max_timestamp) {
			/* finding max time stamp because it may
			 * have older filled sector also
			 */
			memset(&flash_hdr, 0, sizeof(struct cudbg_flash_hdr));
			rc = read_flash(adap, CUDBG_START_SEC, &flash_hdr,
				sizeof(struct cudbg_flash_hdr),
				sec_hdr_start_addr);
			if (flash_hdr.signature == CUDBG_FL_SIGNATURE) {
				sec_info.max_timestamp = flash_hdr.timestamp;
			} else {
				rc = read_flash(adap, CUDBG_START_SEC + 1,
					&flash_hdr,
					sizeof(struct cudbg_flash_hdr),
					sec_hdr_start_addr);
				if (flash_hdr.signature == CUDBG_FL_SIGNATURE)
					sec_info.max_timestamp =
							flash_hdr.timestamp;
			}

			/* finding max sequence number because max sequenced
			 * sector has updated header
			 */
			for (i = CUDBG_START_SEC; i <
					CUDBG_SF_MAX_SECTOR; i++) {
				memset(&flash_hdr, 0,
				       sizeof(struct cudbg_flash_hdr));
				rc = read_flash(adap, i, &flash_hdr,
						sizeof(struct cudbg_flash_hdr),
						sec_hdr_start_addr);

				if (flash_hdr.signature == CUDBG_FL_SIGNATURE &&
				    sec_info.max_timestamp ==
				    flash_hdr.timestamp &&
				    sec_info.max_seq_no <=
				    flash_hdr.sec_seq_no) {
					if (sec_info.max_seq_no ==
					    flash_hdr.sec_seq_no) {
						if (sec_info.hdr_data_len <
						    flash_hdr.data_len)
							sec_info.max_seq_sec = i;
					} else {
						sec_info.max_seq_sec = i;
						sec_info.hdr_data_len =
							flash_hdr.data_len;
					}
					sec_info.max_seq_no = flash_hdr.sec_seq_no;
				}
			}
		}
		rc = read_flash(adap, sec_info.max_seq_sec,
				(struct cudbg_flash_hdr *)data,
				size, sec_hdr_start_addr);

		if (rc)
			cudbg_init->print("Read flash header failed, rc %d\n",
					rc);

		return rc;
	}

	/* finding sector sequence sorted */
	for (i = 1; i <= sec_info.max_seq_no; i++) {
		for (j = CUDBG_START_SEC; j < CUDBG_SF_MAX_SECTOR; j++) {
			memset(&flash_hdr, 0, sizeof(struct cudbg_flash_hdr));
			rc = read_flash(adap, j, &flash_hdr,
				sizeof(struct cudbg_flash_hdr),
				sec_hdr_start_addr);

			if (flash_hdr.signature ==
					CUDBG_FL_SIGNATURE &&
					sec_info.max_timestamp ==
					flash_hdr.timestamp &&
					flash_hdr.sec_seq_no == i) {
				if (size + total_hdr_size >
						CUDBG_SF_SECTOR_SIZE)
					tmp_size = CUDBG_SF_SECTOR_SIZE -
						total_hdr_size;
				else
					tmp_size =  size;

				if ((i != sec_info.max_seq_no) ||
				    (i == sec_info.max_seq_no &&
				    j == sec_info.max_seq_sec)){
					/* filling data buffer with sector data
					 * except sector header
					 */
					rc = read_flash(adap, j,
							(void *)((char *)data +
							data_offset),
							tmp_size, 0);
					data_offset += (tmp_size);
					size -= (tmp_size);
					break;
				}
			}
		}
	}

	return rc;
}

int read_flash(struct adapter *adap, u32 start_sec , void *data, u32 size,
		u32 start_address)
{
	unsigned int addr, i, n;
	int rc;
	u32 *ptr = (u32 *)data;
	addr = start_sec * CUDBG_SF_SECTOR_SIZE + start_address;
	size = size / 4;
	for (i = 0; i < size; i += SF_PAGE_SIZE) {
		if ((size - i) <  SF_PAGE_SIZE)
			n = size - i;
		else
			n = SF_PAGE_SIZE;
		rc = t4_read_flash(adap, addr, n, ptr, 0);
		if (rc)
			goto out;

		addr = addr + (n*4);
		ptr += n;
	}

	return 0;
out:
	return rc;
}

#ifdef CUDBG_UTILS
int cudbg_loadfw(void *handle, uint8_t *buf, size_t len)
{
	struct cudbg_init *cudbg_init =
		&(((struct cudbg_private *)handle)->dbg_init);
	struct adapter *adap = cudbg_init->adap;
	unsigned int mbox = M_PCIE_FW_MASTER + 1;
	u8 *fw_data;
	int rc;

	rc = t4_get_flash_params(adap);
	if (rc < 0) {
		cudbg_init->print("\nGet flash params failed.\n\n");
		return -EINVAL;
	}

	if ((adap->flags & FULL_INIT_DONE)) {
		cudbg_init->print("Full init done for adap");
		mbox = adap->mbox;
	}

	fw_data = buf;
	rc = t4_fw_upgrade(adap, mbox, fw_data, len, true);

	if (rc)
		cudbg_init->print("FW flash  failed, rc %d\n", rc);
	return rc;
}

/**
 * The following routines will implement eeprom read/write
 */

#define VPD_DIAGSRESULT_START   0x1ae0
#define VPD_DIAGSRESULT_END     0x1bb9
#define EEPROM_STAT_ADDR        0x7bfc

static int eeprom_ptov(unsigned int phys_addr, unsigned int fn, unsigned int sz)
{
	fn *= sz;
	if (phys_addr < 1024)
		return phys_addr + (31 << 10);
	if (phys_addr < 1024 + fn)
		return fn + phys_addr - 1024;
	if (phys_addr < EEPROMSIZE)
		return phys_addr - 1024 - fn;
	if (phys_addr < EEPROMVSIZE)
		return phys_addr - 1024;
	return -EINVAL;
}

static int eeprom_rd_phys(struct adapter *adap, unsigned int phys_addr, u32 *v)
{
	int vaddr = eeprom_ptov(phys_addr, adap->pf, EEPROMPFSIZE);

	if (vaddr >= 0)
		vaddr = t4_seeprom_read(adap, vaddr, v);
	return vaddr < 0 ? vaddr : 0;
}

static int eeprom_wr_phys(struct adapter *adap, unsigned int phys_addr, u32 v)
{
	int vaddr = 0;

	if ((phys_addr >= VPD_DIAGSRESULT_START) &&
		(phys_addr <= VPD_DIAGSRESULT_END))
		return 0;

	vaddr = eeprom_ptov(phys_addr, adap->pf, EEPROMPFSIZE);

	if (vaddr == EEPROM_STAT_ADDR)
		return 0;

	if (vaddr >= 0)
		vaddr = t4_seeprom_write(adap, vaddr, v);

	return vaddr < 0 ? vaddr : 0;
}

int cudbg_get_eeprom(void *handle, u8 *data, int addr, int len)
{
	struct cudbg_init *cudbg_init =
		&(((struct cudbg_private *)handle)->dbg_init);
	struct adapter *adapter = cudbg_init->adap;
	u8 *buf = t4_os_alloc(EEPROMSIZE);
	int i, err = 0;

	if (!buf)
		return -ENOMEM;

	for (i = addr & ~3; !err && i < addr + len; i += 4)
		err = eeprom_rd_phys(adapter, i, (u32 *)&buf[i]);

	if (!err)
		memcpy(data, buf + addr, len);
	t4_os_free(buf);
	return err;
}

int cudbg_set_eeprom(void *handle, u8 *data, int offset, int len)
{
	struct cudbg_init *cudbg_init =
		&(((struct cudbg_private *)handle)->dbg_init);
	struct adapter *adapter = cudbg_init->adap;
	u32 aligned_offset, aligned_len, *p;
	int err = 0;
	u8 *buf;

	aligned_offset = offset & ~3;
	aligned_len = (len + (offset & 3) + 3) & ~3;

	if (aligned_offset != offset || aligned_len != len) {
		/* RMW possibly needed for first or last words.
		 */
		buf = t4_os_alloc(aligned_len);
		if (!buf) {
			err = -ENOMEM;
			goto out;
		}
		memset(buf, 0, aligned_len);
		err = eeprom_rd_phys(adapter, aligned_offset, (u32 *)buf);
		if (!err && aligned_len > 4)
			err = eeprom_rd_phys(adapter,
					     aligned_offset + aligned_len - 4,
					     (u32 *)&buf[aligned_len - 4]);
		if (err)
			goto out;
		memcpy(buf + (offset & 3), data, len);
	} else
		buf = data;

	cudbg_init->print("Writing to adapter with start_addr=%d, len=%d\n",
					  offset, len);

	err = t4_seeprom_wp(adapter, false);
	if (err)
		goto out;

	for (p = (u32 *)buf; !err && aligned_len; aligned_len -= 4, p++) {
		err = eeprom_wr_phys(adapter, aligned_offset, *p);
		aligned_offset += 4;
	}

	if (!err)
		err = t4_seeprom_wp(adapter, true);

out:
	if (buf != NULL && buf != data)
		t4_os_free(buf);
	return err;
}

#endif
