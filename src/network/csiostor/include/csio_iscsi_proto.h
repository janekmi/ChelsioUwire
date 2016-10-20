/*
 *  Copyright (C) 2008-2014 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 * 
 * Description:
 * 
 */

#ifndef __CSIO_PROTO_FOISCSI_H__
#define __CSIO_PROTO_FOISCSI_H__

/* Response Flags */
#define ISCSI_BIDI_RSP            0x80            /* bidirectional read rsp */
#define ISCSI_BIDI_READ_UNDER     0x40            /* bidi read underrun */
#define ISCSI_BIDI_READ_OVER      0x20            /* bidi read overrun */
#define ISCSI_CONF_REQ            0x10            /* confirmation requested */
#define ISCSI_RESID_UNDER         0x08            /* transfer shorter than
                                                 * expected
                                                 */
#define ISCSI_RESID_OVER          0x04            /* DL insufficient for
                                                 * full transfer                                                 */
#define ISCSI_SNS_LEN_VAL         0x02            /* SNS_LEN field is valid */
#define ISCSI_RSP_LEN_VAL         0x01            /* RSP_LEN field is valid */

/* Response codes */
#define ISCSI_TMF_CMPL            0x00
#define ISCSI_DATA_LEN_INVALID    0x01
#define ISCSI_CMND_FIELDS_INVALID 0x02
#define ISCSI_DATA_PARAM_MISMATCH 0x03
#define ISCSI_TMF_REJECTED        0x04
#define ISCSI_TMF_FAILED          0x05
#define ISCSI_TMF_SUCCEEDED       0x05
#define ISCSI_TMF_INVALID_LUN     0x09

struct csio_foiscsi_resp {
        uint8_t         flags;                  /* flags */
        uint8_t         scsi_status;            /* SCSI status code */
        uint16_t 	rsvd;
	uint32_t        resid;                  /* Residual bytes */
        uint32_t        sns_len;                /* Length of sense data */
        uint32_t        rsp_len;                /* Length of response */
        uint8_t         rsp_code;               /* Response code */
        uint8_t         sns_data[128];
};

#endif
