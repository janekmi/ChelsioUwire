#ifndef __ISCSI_TARGET_SCSI_H__
#define __ISCSI_TARGET_SCSI_H__

/*
 *      SCSI Opcode Constants
 */

#define SCSI_OPCODE_TEST_UNIT_READY			0x00
#define SCSI_OPCODE_REWIND                              0x01
#define SCSI_OPCODE_REQUEST_SENSE			0x03
#define SCSI_OPCODE_FORMAT_UNIT                         0x04
#define SCSI_OPCODE_FORMAT_MEDIUM                       0x04
#define SCSI_OPCODE_READ_BLOCK_LIMITS               	0x05
#define SCSI_OPCODE_INITIALIZE_ELEMENT_STATUS           0x07
#define SCSI_OPCODE_REASSIGN_BLOCKS                     0x07
#define SCSI_OPCODE_READ_6				0x08
#define SCSI_OPCODE_WRITE_6				0x0a
#define SCSI_OPCODE_READ_REVERSE                        0x0f

#define SCSI_OPCODE_WRITE_FILEMARKS                     0x10
#define SCSI_OPCODE_SPACE                               0x11
#define SCSI_OPCODE_INQUIRY                             0x12
#define SCSI_OPCODE_VERIFY_6                            0x13
#define SCSI_OPCODE_RECOVER_BUFFER_DATA                 0x14
#define SCSI_OPCODE_MODE_SELECT_6			0x15
#define SCSI_OPCODE_RESERVE_6				0x16
#define SCSI_OPCODE_RELEASE_6				0x17
#define SCSI_OPCODE_ERASE                               0x19
#define SCSI_OPCODE_MODE_SENSE_6			0x1a
#define SCSI_OPCODE_START_STOP_UNIT			0x1b

#define SCSI_OPCODE_READ_CAPACITY_10			0x25
#define SCSI_OPCODE_READ_10				0x28
#define SCSI_OPCODE_READ_GENERATION                     0x29
#define SCSI_OPCODE_WRITE_10				0x2a
#define SCSI_OPCODE_SEEK_10               		0x2b
#define SCSI_OPCODE_ERASE_10                            0x2c
#define SCSI_OPCODE_READ_UPDATED_BLOCK                  0x2d
#define SCSI_OPCODE_WRITE_N_VERIFY_10			0x2e
#define SCSI_OPCODE_VERIFY_10				0x2f

#define SCSI_OPCODE_SET_LIMITS_10                       0x33
#define SCSI_OPCODE_PRE_FETCH                           0x34
#define SCSI_OPCODE_READ_POSITION                       0x34
#define SCSI_OPCODE_SYNCHRONIZE_CACHE_10		0x35
#define SCSI_OPCODE_LOCK_UNLOCK_CACHE                   0x36
#define SCSI_OPCODE_READ_DEFECT_DATA_10                 0x37
#define SCSI_OPCODE_MEDIUM_SCAN                         0x38
#define SCSI_OPCODE_WRITE_BUFFER                        0x3b
#define SCSI_OPCODE_READ_BUFFER                         0x3c
#define SCSI_OPCODE_UPDATE_BLOCK                        0x3d
#define SCSI_OPCODE_READ_LONG                           0x3e
#define SCSI_OPCODE_WRITE_LONG                          0x3f


#define SCSI_OPCODE_WRITE_SAME                          0x41
#define SCSI_OPCODE_REPORT_DENSITY_SUPPORT              0x44
#define SCSI_OPCODE_LOG_SELECT                          0x4c
#define SCSI_OPCODE_LOG_SENSE                           0x4d

#define SCSI_OPCODE_XDWRITE                             0x50
#define SCSI_OPCODE_XPWRITE                             0x51
#define SCSI_OPCODE_XDREAD                              0x52
#define SCSI_OPCODE_MODE_SELECT_10			0x55
#define SCSI_OPCODE_RESERVE_10				0x56
#define SCSI_OPCODE_RELEASE_10				0x57
#define SCSI_OPCODE_MODE_SENSE_10			0x5a
#define SCSI_OPCODE_PERSISTENT_RESERVE_IN           	0x5e
#define SCSI_OPCODE_PERSISTENT_RESERVE_OUT    		0x5f

#define SCSI_OPCODE_XDWRITE_EXTENDED                    0x80
#define SCSI_OPCODE_EXTENDED_COPY                       0x83
#define SCSI_OPCODE_RECEIVE_COPY_RESULTS                0x84
#define SCSI_OPCODE_READ_16				0x88
#define SCSI_OPCODE_WRITE_16				0x8a
#define SCSI_OPCODE_WRITE_N_VERIFY_16			0x8e
#define SCSI_OPCODE_VERIFY_16				0x8f

#define SCSI_OPCODE_SERVICE_ACTION_IN_16		0x9e

#define SCSI_OPCODE_REPORT_LUNS				0xa0
#define SCSI_OPCODE_MAINTENANCE_IN                      0xa3
#define SCSI_OPCODE_MAINTENANCE_OUT                     0xa4
#define SCSI_OPCODE_MOVE_MEDIUM	                       	0xa5
#define SCSI_OPCODE_EXCHANGE_MEDIUM                     0xa6
#define SCSI_OPCODE_MOVE_MEDIUM_ATTACHED                0xa7 	
#define SCSI_OPCODE_READ_12				0xa8
#define SCSI_OPCODE_WRITE_12				0xaa
#define SCSI_OPCODE_ERASE_12                            0xac
#define SCSI_OPCODE_WRITE_N_VERIFY_12			0xae
#define SCSI_OPCODE_VERIFY_12				0xaf

#define SCSI_OPCODE_SET_LIMITS_12                       0xb3
#define SCSI_OPCODE_READ_ELEMENT_STATUS_ATTACHED        0xb4
#define SCSI_OPCODE_REQUEST_VOLUME_ELEMENT_ADDRESS      0xb5
#define SCSI_OPCODE_SEND_VOLUME_TAG                     0xb6
#define SCSI_OPCODE_READ_DEFECT_DATA_12                 0xb7
#define SCSI_OPCODE_READ_ELEMENT_STATUS                 0xb8

/*
 * Constants:  SCSI Maintenance In / Maintenance Out Service Action codes
*/

#define SCSI_REPORT_TARGET_PORT_GROUPS                  0x0a
#define SCSI_SET_TARGET_PORT_GROUP                      0x0a
#define SCSI_REPORT_ALIAS                               0x0b
#define SCSI_CHANGE_ALIAS                               0x0b
#define SCSI_MIRROR_IN                                  0x18
#define SCSI_MIRROR_OUT                                 0x18

/*
 * Constants:  SCSI Service Service Action codes
*/

#define SCSI_READ_CAPACITY_16                          0x10
#define SCSI_READ_LONG_16                              0x11


/*
 *  Status codes
*/

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
#define SCSI_PARAM_LIST_ERROR				0x1a
#define SCSI_INVALID_CDB				0x24
#define SPC_ASC_INVALID_FIELD_IN_PARAMETER_LIST		0x26
#define SPC_ERR_REGISTRATION_RESOURCES			0x55
#define SPC_ERR_DATA_PHASE				0x4b

/*
 *  DEVICE TYPES
 */

#define SCSI_DEVICE_TYPE_NO_LUN      	   0x7f

#define SCSI_RESCAN_CMD(op)	\
	((op) == SCSI_OPCODE_INQUIRY || \
	 (op) == SCSI_OPCODE_REPORT_LUNS)

#define SCSI_NOLUN_CMD(op)	\
	((op) == SCSI_OPCODE_REQUEST_SENSE || \
	 (op) == SCSI_OPCODE_REPORT_LUNS)

#define SCSI_MODESENSE_CMD(op) \
	((op) == SCSI_OPCODE_MODE_SENSE_6 || \
	 (op) == SCSI_OPCODE_MODE_SENSE_10)

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

#define SCSI_RWIO_PROTECT_EN(cdb)	(cdb[1] & 0x20)
/*
 * check if the scsi command is allowed if the LU is reserved by another
 * initiator
 */
#define SCSI_CMD_ALLOWED_IN_RESERVATION(cdb)	\
 		( (cdb[0] == SCSI_OPCODE_INQUIRY) || \
		  (cdb[0] == SCSI_OPCODE_REPORT_LUNS) || \
		  (cdb[0] == SCSI_OPCODE_REQUEST_SENSE) || \
		  (cdb[0] == SCSI_OPCODE_READ_CAPACITY_10) || \
		  ((cdb[0] == SCSI_OPCODE_START_STOP_UNIT) &&  \
		   (((cdb[4]) & 0xF1) == 1)) || \
		  (cdb[0] == SCSI_OPCODE_RELEASE_6) || \
		  (cdb[0] == SCSI_OPCODE_RELEASE_10) )

/*
 * cdb decode
 */
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

/*
 * iscsi target sense data
 */
#define sc_unsupported_cmd(sc, op)	\
	do {	\
		os_log_debug(ISCSI_DBG_SCSI_COMMAND, 	\
			"it sess 0x%p, sc itt 0x%x, opcode 0x%x not supported.\n", \
			sc->sc_sess, sc->sc_itt, op); \
	    (sc)->sc_response = ISCSI_RESPONSE_COMPLETED; \
	    (sc)->sc_status = SCSI_STATUS_CHECK_CONDITION; \
	    (sc)->sc_sense_key = SCSI_SENSE_ILLEGAL_REQUEST; \
	    (sc)->sc_sense_asc = 0x20; /* invalid cmd opcode */ \
	    (sc)->sc_sense_ascq = 0; \
	} while(0)

#define sc_read_error(sc)	\
	do {	\
	    os_log_debug(ISCSI_DBG_SCSI_COMMAND, 	\
			"it sess 0x%p, sc itt 0x%x, read error.\n", \
			sc->sc_sess, sc->sc_itt); \
	    (sc)->sc_response = ISCSI_RESPONSE_COMPLETED; \
	    (sc)->sc_status = SCSI_STATUS_CHECK_CONDITION; \
	    (sc)->sc_sense_key = SCSI_SENSE_MEDIUM_ERROR; \
	    (sc)->sc_sense_asc = 0x11; /* read error */\
	    (sc)->sc_sense_ascq = 0x0; \
	} while(0)

#define sc_write_error(sc)	\
	do {	\
	    os_log_debug(ISCSI_DBG_SCSI_COMMAND, 	\
			"it sess 0x%p, sc itt 0x%x, write error.\n", \
			sc->sc_sess, sc->sc_itt); \
	    (sc)->sc_response = ISCSI_RESPONSE_COMPLETED; \
	    (sc)->sc_status = SCSI_STATUS_CHECK_CONDITION; \
	    (sc)->sc_sense_key = SCSI_SENSE_MEDIUM_ERROR; \
	    (sc)->sc_sense_asc = 0xC; /* write error */\
	    (sc)->sc_sense_ascq = 0x0; \
	} while(0)

#define sc_rw_error(sc) \
	do { \
		if (sc->sc_flag & SC_FLAG_WRITE) \
			sc_write_error(sc); \
		else \
			sc_read_error(sc); \
	} while(0)

/* RFC 3720 10.4.7.2 */
#define sc_unexpected_unsolicited_data(sc)	\
	do {	\
	    os_log_debug(ISCSI_DBG_SCSI_COMMAND, 	\
			"it sess 0x%p, sc itt 0x%x, unexp. unsolicited data.\n", \
			sc->sc_sess, sc->sc_itt); \
	    (sc)->sc_response = ISCSI_RESPONSE_COMPLETED; \
	    (sc)->sc_status = SCSI_STATUS_CHECK_CONDITION; \
	    (sc)->sc_sense_key = SCSI_SENSE_ABORTED_COMMAND; \
	    (sc)->sc_sense_asc = 0xC; /* write error */\
	    (sc)->sc_sense_ascq = 0xC; /* unexpected unsolicited data */ \
	} while(0)

#define sc_incorrect_amount_of_data(sc)	\
	do {	\
	    os_log_debug(ISCSI_DBG_SCSI_COMMAND, 	\
			"it sess 0x%p, sc itt 0x%x, incorrect amount of data.\n", \
			 sc->sc_sess, sc->sc_itt); \
	    (sc)->sc_response = ISCSI_RESPONSE_COMPLETED; \
	    (sc)->sc_status = SCSI_STATUS_CHECK_CONDITION; \
	    (sc)->sc_sense_key = SCSI_SENSE_ABORTED_COMMAND; \
	    (sc)->sc_sense_asc = 0xC; /* write error */\
	    (sc)->sc_sense_ascq = 0xD; /* not enough unsolicited data */ \
	} while(0)

#define sc_data_digest_error(sc)	\
	do {	\
	    os_log_debug(ISCSI_DBG_SCSI_COMMAND, 	\
			"it sess 0x%p, sc itt 0x%x, data digest error.\n", \
			 sc->sc_sess, sc->sc_itt); \
	    (sc)->sc_response = ISCSI_RESPONSE_COMPLETED; \
	    (sc)->sc_status = SCSI_STATUS_CHECK_CONDITION; \
	    (sc)->sc_sense_key = SCSI_SENSE_ABORTED_COMMAND; \
	    (sc)->sc_sense_asc = 0x47; /* scsi parity error */ \
	    (sc)->sc_sense_ascq = 0x5; /* protocol service crc error */ \
	} while(0)

#define sc_snack_rejected(sc)	\
	do {	\
	    os_log_debug(ISCSI_DBG_SCSI_COMMAND, 	\
			"it sess 0x%p, sc itt 0x%x, snack rejected.\n", \
			sc->sc_sess, sc->sc_itt); \
	    (sc)->sc_response = ISCSI_RESPONSE_COMPLETED; \
	    (sc)->sc_status = SCSI_STATUS_CHECK_CONDITION; \
	    (sc)->sc_sense_key = SCSI_SENSE_ABORTED_COMMAND; \
	    (sc)->sc_sense_asc = 0x11; /* read error */ \
	    (sc)->sc_sense_ascq = 0x13; /* failed retransmission request */ \
	} while(0)

/* RFC 3720 6.5 */
#define sc_connection_failed(sc)	\
	do {	\
	    os_log_debug(ISCSI_DBG_SCSI_COMMAND, 	\
			"it sess 0x%p, sc itt 0x%x, conn. failed.\n", \
			 sc->sc_sess, sc->sc_itt); \
	    (sc)->sc_response = ISCSI_RESPONSE_COMPLETED; \
	    (sc)->sc_status = SCSI_STATUS_CHECK_CONDITION; \
	    (sc)->sc_sense_key = SCSI_SENSE_UNIT_ATTENTION; \
	    (sc)->sc_sense_asc = 0x47;  \
	    (sc)->sc_sense_ascq = 0x7F; /* some commands cleared by iscsi protocol event */ \
	} while(0)

#define sc_invalid_address(sc)	\
	do {	\
		os_log_debug(ISCSI_DBG_SCSI_COMMAND, 	\
			"it sess 0x%p, sc itt 0x%x, invalid addr.\n", \
			sc->sc_sess, sc->sc_itt); \
	    (sc)->sc_response = ISCSI_RESPONSE_COMPLETED; \
	    (sc)->sc_status = SCSI_STATUS_CHECK_CONDITION; \
	    (sc)->sc_sense_key = SCSI_SENSE_ILLEGAL_REQUEST; \
	    (sc)->sc_sense_asc = 0x21; /* logical addr out of range */ \
	    (sc)->sc_sense_ascq = 0; \
	} while(0)

#define sc_invalid_cdb_field(sc)	\
	do {	\
		os_log_debug(ISCSI_DBG_SCSI_COMMAND, 	\
			"it sess 0x%p, sc itt 0x%x, invalid cdb field.\n", \
			sc->sc_sess, sc->sc_itt); \
	    (sc)->sc_response = ISCSI_RESPONSE_COMPLETED; \
	    (sc)->sc_status = SCSI_STATUS_CHECK_CONDITION; \
	    (sc)->sc_sense_key = SCSI_SENSE_ILLEGAL_REQUEST; \
	    (sc)->sc_sense_asc = 0x24; /* invalid field in cdb */ \
	    (sc)->sc_sense_ascq = 0; \
	} while(0)

#define sc_param_list_error(sc)	\
	do {	\
		os_log_debug(ISCSI_DBG_SCSI_COMMAND, 	\
			"it sess 0x%p, sc itt 0x%x, invalid cdb field.\n", \
			sc->sc_sess, sc->sc_itt); \
	    (sc)->sc_response = ISCSI_RESPONSE_COMPLETED; \
	    (sc)->sc_status = SCSI_STATUS_CHECK_CONDITION; \
	    (sc)->sc_sense_key = SCSI_SENSE_ILLEGAL_REQUEST; \
	    (sc)->sc_sense_asc = 0x1a; /* param list length error */ \
	    (sc)->sc_sense_ascq = 0; \
	} while(0)

#define sc_invalid_field_in_param_list(sc)	\
	do {	\
		os_log_debug(ISCSI_DBG_SCSI_COMMAND, 	\
			"it sess 0x%p, sc itt 0x%x, invalid cdb field.\n", \
			sc->sc_sess, sc->sc_itt); \
	    (sc)->sc_response = ISCSI_RESPONSE_COMPLETED; \
	    (sc)->sc_status = SCSI_STATUS_CHECK_CONDITION; \
	    (sc)->sc_sense_key = SCSI_SENSE_ILLEGAL_REQUEST; \
	    (sc)->sc_sense_asc = 0x1a; /* Invalid field in param list */ \
	    (sc)->sc_sense_ascq = 1; \
	} while(0)

#define sc_err_registration_resources(sc)	\
	do {	\
		os_log_debug(ISCSI_DBG_SCSI_COMMAND, 	\
			"it sess 0x%p, sc itt 0x%x, invalid cdb field.\n", \
			sc->sc_sess, sc->sc_itt); \
	    (sc)->sc_response = ISCSI_RESPONSE_COMPLETED; \
	    (sc)->sc_status = SCSI_STATUS_CHECK_CONDITION; \
	    (sc)->sc_sense_key = SCSI_SENSE_ILLEGAL_REQUEST; \
	    (sc)->sc_sense_asc = 0x55; /* Invalid field in param list */ \
	    (sc)->sc_sense_ascq = 4; \
	} while(0)

#define sc_err_data_phase(sc)	\
	do {	\
		os_log_debug(ISCSI_DBG_SCSI_COMMAND, 	\
			"it sess 0x%p, sc itt 0x%x, invalid cdb field.\n", \
			sc->sc_sess, sc->sc_itt); \
	    (sc)->sc_response = ISCSI_RESPONSE_COMPLETED; \
	    (sc)->sc_status = SCSI_STATUS_CHECK_CONDITION; \
	    (sc)->sc_sense_key = SCSI_SENSE_ILLEGAL_REQUEST; \
	    (sc)->sc_sense_asc = 0x4b; /* Err Data Phase */ \
	    (sc)->sc_sense_ascq = 0; \
	} while(0)

#define sc_reservation_conflict(sc)	\
	do {	\
		os_log_debug(ISCSI_DBG_SCSI_COMMAND, 	\
			"it sess 0x%p, sc itt 0x%x, invalid cdb field.\n", \
			sc->sc_sess, sc->sc_itt); \
	    (sc)->sc_response = ISCSI_RESPONSE_COMPLETED; \
	    (sc)->sc_status = SCSI_STATUS_RESERVATION_CONFLICT; \
	    (sc)->sc_sense_key = 0x0; \
	    (sc)->sc_sense_asc = 0x0; /* persistent reservation conflict */ \
	    (sc)->sc_sense_ascq = 0; \
	} while(0)

#define sc_release_invalid(sc)	\
	do {	\
		os_log_debug(ISCSI_DBG_SCSI_COMMAND, 	\
			"it sess 0x%p, sc itt 0x%x, invalid cdb field.\n", \
			sc->sc_sess, sc->sc_itt); \
	    (sc)->sc_response = ISCSI_RESPONSE_COMPLETED; \
	    (sc)->sc_status = SCSI_STATUS_CHECK_CONDITION; \
	    (sc)->sc_sense_key = 0x05; \
	    (sc)->sc_sense_asc = 0x26; /* Invalid Release */ \
	    (sc)->sc_sense_ascq = 0x04; \
	} while(0)

#define sc_device_reset(sc)	\
	do {	\
		os_log_debug(ISCSI_DBG_SCSI_COMMAND, 	\
			"it sess 0x%p, sc itt 0x%x, device reset.\n", \
			sc->sc_sess, sc->sc_itt); \
	    (sc)->sc_response = ISCSI_RESPONSE_COMPLETED; \
	    (sc)->sc_status = SCSI_STATUS_CHECK_CONDITION; \
	    (sc)->sc_sense_key = SCSI_SENSE_UNIT_ATTENTION; \
	    (sc)->sc_sense_asc = 0x29; /* power on or reset occured */ \
	} while(0)

#define sc_target_cold_reset(sc)	\
	do {	\
		os_log_debug(ISCSI_DBG_SCSI_COMMAND, 	\
			"it sess 0x%p, sc itt 0x%x, cold reset.\n", \
			sc->sc_sess, sc->sc_itt); \
	    (sc)->sc_response = ISCSI_RESPONSE_COMPLETED; \
	    (sc)->sc_status = SCSI_STATUS_CHECK_CONDITION; \
	    (sc)->sc_sense_key = SCSI_SENSE_UNIT_ATTENTION; \
	    (sc)->sc_sense_asc = 0x29; /* power on or reset occured */ \
	    (sc)->sc_sense_ascq = 0x2; /* bus reset */ \
	} while(0)

#define sc_target_warm_reset(sc)	\
	do {	\
		os_log_debug(ISCSI_DBG_SCSI_COMMAND, 	\
			"it sess 0x%p, sc itt 0x%x, warm reset.\n", \
			sc->sc_sess, sc->sc_itt); \
	    (sc)->sc_response = ISCSI_RESPONSE_COMPLETED; \
	    (sc)->sc_status = SCSI_STATUS_CHECK_CONDITION; \
	    (sc)->sc_sense_key = SCSI_SENSE_UNIT_ATTENTION; \
	    (sc)->sc_sense_asc = 0x29; /* power on or reset occured */ \
	    (sc)->sc_sense_ascq = 0x3; /* bus device reset */ \
	} while(0)

#define sc_lun_reset(sc)	\
	do {	\
		os_log_debug(ISCSI_DBG_SCSI_COMMAND, 	\
			"it sess 0x%p, sc itt 0x%x, lun reset.\n", \
			sc->sc_sess, sc->sc_itt); \
	    (sc)->sc_response = ISCSI_RESPONSE_COMPLETED; \
	    (sc)->sc_status = SCSI_STATUS_CHECK_CONDITION; \
	    (sc)->sc_sense_key = SCSI_SENSE_UNIT_ATTENTION; \
	    (sc)->sc_sense_asc = 0x29; /* power on or reset occured */ \
	    (sc)->sc_sense_ascq = 0x4; /* device internal reset */ \
	} while(0)

#define sc_luns_changed(sc)	\
	do {	\
		os_log_debug(ISCSI_DBG_SCSI_COMMAND, 	\
			"it sess 0x%p, sc itt 0x%x, lun changed.\n", \
			sc->sc_sess, sc->sc_itt); \
	    (sc)->sc_response = ISCSI_RESPONSE_COMPLETED; \
	    (sc)->sc_status = SCSI_STATUS_CHECK_CONDITION; \
	    (sc)->sc_sense_key = SCSI_SENSE_UNIT_ATTENTION; \
	    (sc)->sc_sense_asc = 0x3F; /* target operation conditions changed */ \
	    (sc)->sc_sense_ascq = 0xE; /* report luns data changed */ \
	} while(0)

#define sc_lun_size_changed(sc)	\
	do {	\
		os_log_debug(ISCSI_DBG_SCSI_COMMAND, 	\
			"it sess 0x%p, sc itt 0x%x, lun size changed.\n", \
			sc->sc_sess, sc->sc_itt); \
	    (sc)->sc_response = ISCSI_RESPONSE_COMPLETED; \
	    (sc)->sc_status = SCSI_STATUS_CHECK_CONDITION; \
	    (sc)->sc_sense_key = SCSI_SENSE_UNIT_ATTENTION; \
	    (sc)->sc_sense_asc = 0x3F; /* target operation conditions changed */ \
	    (sc)->sc_sense_ascq = 0xA; /* volume set created or modified */ \
	} while(0)

#define sc_read_only(sc)	\
	do {	\
		os_log_debug(ISCSI_DBG_SCSI_COMMAND, 	\
			"it sess 0x%p, sc itt 0x%x, read only.\n", \
			sc->sc_sess, sc->sc_itt); \
	    (sc)->sc_response = ISCSI_RESPONSE_COMPLETED; \
	    (sc)->sc_status = SCSI_STATUS_CHECK_CONDITION; \
	    /* Fix for PR 8108 interop with ESX */ \
	    /* (sc)->sc_sense_key = SCSI_SENSE_WRITE_PROTECT; */ \
	    /* (sc)->sc_sense_asc = 0x27;  write protected */ \
	    /* (sc)->sc_sense_ascq = 0x2;  lun s/w write protect */ \
	    (sc)->sc_sense_key = SCSI_SENSE_MEDIUM_ERROR; \
	    (sc)->sc_sense_asc = 0x03; /* peripheral device write fault */ \
	    (sc)->sc_sense_ascq = 0x0; \
	} while(0)

#define sc_write_only(sc)	\
	do {	\
		os_log_debug(ISCSI_DBG_SCSI_COMMAND, 	\
			"it sess 0x%p, sc itt 0x%x, write only.\n", \
			sc->sc_sess, sc->sc_itt); \
	    (sc)->sc_response = ISCSI_RESPONSE_COMPLETED; \
	    (sc)->sc_status = SCSI_STATUS_CHECK_CONDITION; \
	    (sc)->sc_sense_key = SCSI_SENSE_ILLEGAL_REQUEST; \
	    (sc)->sc_sense_asc = 0x20; /* invalid command opeartion code */ \
	    (sc)->sc_sense_ascq = 0x2; /* access denied */ \
	} while(0)

#define sc_lun_reservation_conflict(sc)	\
	do {	\
		os_log_debug(ISCSI_DBG_SCSI_COMMAND, 	\
			"it sess 0x%p, sc itt 0x%x, reserv. conflict.\n", \
			sc->sc_sess, sc->sc_itt); \
	    (sc)->sc_response = ISCSI_RESPONSE_COMPLETED; \
	    (sc)->sc_status = SCSI_STATUS_RESERVATION_CONFLICT; \
	    (sc)->sc_sense_key = SCSI_SENSE_ILLEGAL_REQUEST; \
	    (sc)->sc_sense_asc = 0x20; /* invalid command opeartion code */ \
	    (sc)->sc_sense_ascq = 0x2; /* access denied */ \
	} while(0)

#define sc_internal_failure(sc)	\
	do {	\
		os_log_debug(ISCSI_DBG_SCSI_COMMAND, 	\
			"it sess 0x%p, sc itt 0x%x, target internal failure.\n", \
			sc->sc_sess, sc->sc_itt); \
	    (sc)->sc_response = ISCSI_RESPONSE_TARGET_FAILURE; \
	    (sc)->sc_status = SCSI_STATUS_CHECK_CONDITION; \
	    (sc)->sc_sense_key = SCSI_SENSE_ABORTED_COMMAND; \
	    (sc)->sc_sense_asc = 0x44; /* internal target failure */ \
	    (sc)->sc_sense_ascq = 0; \
	} while(0)

#endif /* ifndef __ISCSI_TARGET_SCSI_H__ */
