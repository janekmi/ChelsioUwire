/*
 *      SCSI Opcode Constants
 */

#define SCSI_OPCODE_TEST_UNIT_READY			0x00
#define SCSI_OPCODE_REQUEST_SENSE			0x03
#define SCSI_OPCODE_READ_6                              0x08
#define SCSI_OPCODE_WRITE_6                             0x0a
#define SCSI_OPCODE_INQUIRY                             0x12
#define SCSI_OPCODE_VERIFY_6                            0x13
#define SCSI_OPCODE_MODE_SELECT_6			0x15
#define SCSI_OPCODE_MODE_SENSE_6			0x1a
#define SCSI_OPCODE_START_STOP_UNIT			0x1b

#define SCSI_OPCODE_READ_CAPACITY_10			0x25

#define SCSI_OPCODE_READ_10				0x28
#define SCSI_OPCODE_WRITE_10				0x2a
#define SCSI_OPCODE_WRITE_N_VERIFY_10			0x2e
#define SCSI_OPCODE_VERIFY_10				0x2f

#define SCSI_OPCODE_SYNCHRONIZE_CACHE_10                0x35
#define SCSI_OPCODE_MODE_SELECT_10			0x55
#define SCSI_OPCODE_MODE_SENSE_10			0x5a

#define SCSI_OPCODE_READ_16				0x88
#define SCSI_OPCODE_WRITE_16				0x8a
#define SCSI_OPCODE_WRITE_N_VERIFY_16			0x8e
#define SCSI_OPCODE_VERIFY_16				0x8f

#define SCSI_OPCODE_SERVICE_ACTION_IN_16		0x9e
#define SCSI_OPCODE_REPORT_LUNS				0xa0

#define SCSI_OPCODE_READ_12				0xa8
#define SCSI_OPCODE_WRITE_12				0xaa
#define SCSI_OPCODE_WRITE_N_VERIFY_12                   0xae
#define SCSI_OPCODE_VERIFY_12				0xaf

#define SCSI_OPCODE_READ_ELEMENT_STATUS_ATTACHED        0xb4
#define SCSI_OPCODE_REQUEST_VOLUME_ELEMENT_ADDRESS      0xb5
#define SCSI_OPCODE_SEND_VOLUME_TAG                     0xb6
#define SCSI_OPCODE_READ_DEFECT_DATA_12                 0xb7
#define SCSI_OPCODE_READ_ELEMENT_STATUS                 0xb8

/* Constants:  SCSI Service Service Action codes */

#define SCSI_READ_CAPACITY_16                          0x10



/*  Status codes */

#define SCSI_STATUS_GOOD				0x00
#define SCSI_STATUS_CHECK_CONDITION 	                0x02
#define SCSI_STATUS_RESERVATION_CONFLICT	        0x18
#define SCSI_RELEASE_INVALID		            	0x0c

/*
 *  SENSE KEYS
 */

#define SCSI_SENSE_NO_SENSE				0x00
#define SCSI_SENSE_RECOVERED_ERROR			0x01

#define SCSI_SENSE_NOT_READY				0x02
#define SCSI_SENSE_MEDIUM_ERROR				0x03
#define SCSI_SENSE_HARDWARE_ERROR			0x04
#define SCSI_SENSE_ILLEGAL_REQUEST			0x05
#define SCSI_SENSE_UNIT_ATTENTION			0x06
#define SCSI_SENSE_WRITE_PROTECT			0x07
#define SCSI_SENSE_ABORTED_COMMAND			0x0b

/* ASC/ASCQ values */
#define SCSI_PARAM_LIST_ERROR                           0x1a
#define SCSI_INVALID_CDB                                0x24
#define SPC_ASC_INVALID_FIELD_IN_PARAMETER_LIST         0x26
#define SPC_ERR_REGISTRATION_RESOURCES                  0x55
#define SPC_ERR_DATA_PHASE                              0x4b



/*  DEVICE TYPES  */

#define SCSI_DEVICE_TYPE_NO_LUN      	   0x7f

#define SCSI_RWIO_6_CMD(op) \
	((op) == SCSI_OPCODE_READ_6 || \
	 (op) == SCSI_OPCODE_WRITE_6 || \
	 (op) == SCSI_OPCODE_VERIFY_6)

#define SCSI_RWIO_10_CMD(op) \
	((op) == SCSI_OPCODE_READ_10 || \
	 (op) == SCSI_OPCODE_WRITE_10 || \
	 (op) == SCSI_OPCODE_VERIFY_10 || \
	 (op) == SCSI_OPCODE_WRITE_N_VERIFY_10 || \
	 (op) == SCSI_OPCODE_SYNCHRONIZE_CACHE_10)

#define SCSI_RWIO_12_CMD(op) \
	((op) == SCSI_OPCODE_READ_12 || \
	 (op) == SCSI_OPCODE_WRITE_12 || \
	 (op) == SCSI_OPCODE_VERIFY_12 || \
	 (op) == SCSI_OPCODE_WRITE_N_VERIFY_12)

#define SCSI_RWIO_16_CMD(op) \
	((op) == SCSI_OPCODE_READ_16 || \
	 (op) == SCSI_OPCODE_WRITE_16 || \
	 (op) == SCSI_OPCODE_VERIFY_16 || \
	 (op) == SCSI_OPCODE_WRITE_N_VERIFY_16)

#define SCSI_RWIO_CMD(op)	\
	((SCSI_RWIO_6_CMD(op)) || \
	 (SCSI_RWIO_10_CMD(op)) || \
	 (SCSI_RWIO_12_CMD(op)) || \
	 (SCSI_RWIO_16_CMD(op)))


/*  cdb decode  */
#define cdb_fua_set(cdb)		(cdb[1] & 0x8)

#define cdb_6_decode(cdb,lba,len) \
do { \
	lba = (cdb[3] + (cdb[2] << 8) + ((cdb[1] & 0x1f) << 16)) & 0xFFFFFF; \
	len = (0 == cdb[4]) ? 256 : cdb[4]; \
} while(0)

#define cdb_10_decode(cdb,lba,len) \
do { \
	lba = (cdb[5] + (cdb[4] << 8) + (cdb[3] << 16) + (cdb[2] << 24)) & 0xFFFFFFFF; \
	len = cdb[8] + (cdb[7] << 8); \
} while(0)

#define cdb_12_decode(cdb,lba,len) \
do { \
	lba = (cdb[5] + (cdb[4] << 8) + (cdb[3] << 16) + (cdb[2] << 24)) & 0xFFFFFFFF; \
	len = (cdb[9] + (cdb[8] << 8) + (cdb[7] << 16) + (cdb[6] << 24)) & 0xFFFFFFFF; \
} while(0)

#define cdb_16_decode(cdb,lba,len) \
do { \
	int __i; \
	for (lba = 0UL, __i = 0; __i < 8; ++__i) { \
		if (__i > 0) lba <<= 8; \
		lba += cdb[2 + __i]; \
	} \
	len = (cdb[13] + (cdb[12] << 8) + (cdb[11] << 16) + (cdb[10] << 24)) & 0xFFFFFFFF; \
} while(0)

extern int display_byte_string(char *, unsigned char *, int );
