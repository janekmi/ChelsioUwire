#ifndef __ISCSI_PDU_DEFS_H__
#define __ISCSI_PDU_DEFS_H__

/*
 * iscsi_pdu_defs.h
 *
 * iscsi pdu format definitions
 */

#include <common/os_builtin.h>
#include <common/iscsi_pdu.h>

#define iscsi_tmf_enqueue(L,Q,P) ch_enqueue_tail(L,iscsi_tmf,p_next,Q,P)
#define iscsi_tmf_dequeue(L,Q,P) ch_dequeue_head(L,iscsi_tmf,p_next,Q,P)
#define iscsi_tmf_ch_qremove(L,Q,P) ch_qremove(L,iscsi_tmf,p_next,Q,P)

void iscsi_tmf_free(iscsi_tmf *);

/*
 * serial arithmetic functions per RFC1982 -- 
 * The following macros supports the cases where the unsigned int is
 * more than 4 bytes in size.
 */

#define U32_SERIAL_MAX		0xFFFFFFFFU	/* 2 ^ 32 - 1 */
#define uint_serial_inc(u)	\
	{ \
		if ((u) >= U32_SERIAL_MAX)	u = 0U; \
		else	(u) ++; \
	}

#define uint_serial_dec(u) \
	{ \
		if ((u) == 0)	u = U32_SERIAL_MAX; \
		else			(u)--; \
	}

/* u is unsigned, a could be signed and < 0 */
#define uint_serial_add(u,a)	({\
		int __a = a; \
		if ((u) >= U32_SERIAL_MAX)	__a--;	\
		((u) + (__a)); })

#define uint_serial_diff(u1,u2) ({ \
	int __diff = (u2) - (u1); \
	unsigned int __v = __diff; \
	if (__diff < 0) __v *= -1; \
	__v; })


#define uint_serial_compare(u1,u2) ({ \
	int __rv = 0; \
	if ((u1) == (u2)) __rv = 0; \
	else if ((u1) < (u2)) { \
		__rv = ( ((u2) - (u1)) < (1 << 31) ) ? -1 : 1; \
	} else { \
		__rv = ( ((u1) - (u2)) > (1 << 31) ) ? -1 : 1; \
	} \
	__rv; })

/* u1 >= u >= u2 */
#define uint_serial_in_between(u,u1,u2) \
	(uint_serial_compare(u, u1) >= 0 && uint_serial_compare(u, u2) <= 0)

/*
 * search flag, used when searching a pduq
 */
#define ISCSI_PDU_MATCH_OPCODE	0x1
#define ISCSI_PDU_MATCH_ITT 	0x2
#define ISCSI_PDU_MATCH_TTT 	0x4

/*
 * iscsi pdu 
 */
/* default to hold 16K data in pages */
#define ISCSI_PDU_SGCNT_DFLT	\
		((unsigned int)((16384 + os_page_size - 1) >> os_page_shift))

#define ISCSI_PDU_CACHE_SIZE	\
		(ISCSI_PDU_SIZE + ISCSI_PDU_SGCNT_DFLT * sizeof(chiscsi_sgvec))

#define iscsi_pdu_flag_set(pdu,bit) \
		os_set_bit_atomic(&((pdu)->p_flag),bit)
#define iscsi_pdu_flag_clear(pdu,bit) \
		os_clear_bit_atomic(&((pdu)->p_flag),bit)
#define iscsi_pdu_flag_test(pdu,bit)    \
		os_test_bit_atomic(&((pdu)->p_flag),bit)
#define iscsi_pdu_flag_testnset(pdu,bit)    \
		os_test_and_set_bit_atomic(&((pdu)->p_flag),bit)
#define iscsi_pdu_flag_testnclear(pdu,bit) \
		os_test_and_clear_bit_atomic(&((pdu)->p_flag),bit)

static inline unsigned int get_pdu_lun(unsigned char *lun_p)
{
	unsigned char val = (*lun_p) >> 6;
	unsigned int i, lun = 0;

	switch (val) {
		case 0:
			for (i = 0; i < sizeof(lun); i += 2)
				lun = lun | (((lun_p[i] << 8) |
					lun_p[i + 1]) << (i * 8));
			break;
		case 1:
			lun = ((lun_p[0] & 0x3F) << 8) | lun_p[1];
			break;
		default:
			lun = 0xFFFFFFFF;
			break;
	}

	return lun;
}

static inline void set_pdu_lun(unsigned char *lun_p, unsigned int lun)
{
	unsigned int i;
	memset((void *)lun_p, 0, 8);

	for (i = 0; i < sizeof(lun); i += 2) {
                lun_p[i] = (lun >> 8) & 0xFF;
                lun_p[i+1] = lun & 0xFF;
                lun = lun >> 16;
        }

}

/*
 * read from a byte stream
 */
#define GET_1BYTE(PTR,BYTE) 		(*(unsigned char *)(((unsigned char *)(PTR))+(BYTE)))
#define SET_1BYTE(PTR,BYTE,VAL) 	(*(unsigned char *)(((unsigned char *)((PTR)))+(BYTE)) = VAL)

/* 2 bytes */
#define GET_2BYTE(PTR,BYTE)		\
		(os_ntohs(*(unsigned short *)(((unsigned char *)(PTR))+(BYTE))))
#define SET_2BYTE(PTR,BYTE,VAL) \
		((*(unsigned short *)(((unsigned char *)(PTR))+(BYTE)))=os_htons(VAL))

/* 4 bytes */
#define GET_4BYTE(PTR,BYTE)		\
		(os_ntohl(*(unsigned int *)(((unsigned char *)(PTR))+(BYTE))))
#define SET_4BYTE(PTR,BYTE,VAL) \
		((*(unsigned int *)(((unsigned char *)(PTR))+(BYTE)))=os_htonl(VAL))

/* msb -- bit 0, lsb -- bit 7 */
#define GET_BIT(PTR,BYTE,BIT)	\
			(((*(unsigned char *)(((unsigned char *)((PTR)))+(BYTE))) & (0x80>>(BIT)))>>(7-BIT))
#define SET_BIT(PTR,BYTE,BIT)	\
			((*(unsigned char *)(((unsigned char *)((PTR)))+(BYTE))) |= (0x80>>(BIT)))
#define CLR_BIT(PTR,BYTE,BIT)	\
			((*(unsigned char *)(((unsigned char *)((PTR)))+(BYTE))) &= ~(0x80>>(BIT)))

/*
 * iscsi pdu header field
 */

/* AHS : additional header segment */
#define GET_AHS_LENGTH(AHS)		GET_2BYTE(AHS,0)
#define SET_AHS_LENGTH(AHS,VAL)		SET_2BYTE(AHS,0,VAL)
#define GET_AHS_TYPE(AHS)		GET_1BYTE(AHS,2)
#define SET_AHS_TYPE(AHS,VAL)		SET_1BYTE(AHS,2,VAL)
#define		ISCSI_AHS_TYPE_CODE_EXTENDED_CDB	1
#define		ISCSI_AHS_TYPE_CODE_EXP_BI_READ_LENGTH	2
#define GET_AHS_SPECIFIC(AHS)		GET_1BYTE(AHS,3)
#define SET_AHS_SPECIFIC(AHS,VAL) 	SET_1BYTE(AHS,3,VAL)

/* BHS : basic header segment */
#define GET_PDU_I(PDU) 			GET_BIT((PDU)->p_bhs,0,1)
#define SET_PDU_I(PDU)			SET_BIT((PDU)->p_bhs,0,1)
#define CLR_PDU_I(PDU)			CLR_BIT((PDU)->p_bhs,0,1)

#define GET_PDU_OPCODE(PDU) 		(GET_1BYTE((PDU)->p_bhs,0) & 0x3F)
#define SET_PDU_OPCODE(PDU,VAL)	\
		(*(unsigned char *)(((unsigned char *)((PDU)->p_bhs))) = \
		( (*(unsigned char *)(((unsigned char *)((PDU)->p_bhs))) & 0xc0) | \
		  ((VAL)&0x3F)))

#define GET_PDU_F(PDU) 			GET_BIT((PDU)->p_bhs,1,0)
#define SET_PDU_F(PDU)			SET_BIT((PDU)->p_bhs,1,0)
#define CLR_PDU_F(PDU)			CLR_BIT((PDU)->p_bhs,1,0)

#define GET_PDU_C(PDU)      		GET_BIT((PDU)->p_bhs,1,1)
#define SET_PDU_C(PDU)      		SET_BIT((PDU)->p_bhs,1,1)
#define CLR_PDU_C(PDU)      		CLR_BIT((PDU)->p_bhs,1,1)


#define GET_PDU_TOTAL_AHS_LENGTH(PDU) GET_1BYTE((PDU)->p_bhs,4)
#define SET_PDU_TOTAL_AHS_LENGTH(PDU,VAL) \
				SET_1BYTE((PDU)->p_bhs,4,VAL)

#define GET_PDU_DATA_SEGMENT_LENGTH(PDU) (GET_4BYTE((PDU)->p_bhs,4) & 0xFFFFFF)
#define SET_PDU_DATA_SEGMENT_LENGTH(PDU,VAL) \
		((*(unsigned int *)(((unsigned char *)((PDU)->p_bhs))+4)) = \
		os_htonl( \
			((*(unsigned int *)(((unsigned char *)((PDU)->p_bhs))+4))&0xFF000000) | \
			((VAL)&0xFFFFFF)))

#define SET_PDU_AHS_AND_DATA_LENGTH(PDU,VAL) SET_4BYTE((PDU)->p_bhs,4,VAL)

#define GET_PDU_LUN(PDU)		get_pdu_lun( ((unsigned char *)((PDU)->p_bhs))+8 )
#define SET_PDU_LUN(PDU,VAL)	set_pdu_lun( ((unsigned char *)((PDU)->p_bhs)+8),(VAL) )

#define GET_PDU_ITT(PDU)		GET_4BYTE((PDU)->p_bhs,16)
#define SET_PDU_ITT(PDU,VAL)	SET_4BYTE((PDU)->p_bhs,16,VAL)

/* common field */
#define GET_PDU_RESPONSE(PDU) 		GET_1BYTE((PDU)->p_bhs,2)
#define SET_PDU_RESPONSE(PDU,VAL)	SET_1BYTE((PDU)->p_bhs,2,VAL)

#define GET_PDU_STATUS(PDU)		GET_1BYTE((PDU)->p_bhs,3)
#define SET_PDU_STATUS(PDU,VAL) 	SET_1BYTE((PDU)->p_bhs,3,VAL)
/* tmf PDU */
#define GET_PDU_TASK_TAG(PDU)		GET_4BYTE((PDU)->p_bhs,20)
#define SET_PDU_TASK_TAG(PDU,VAL) 	SET_4BYTE((PDU)->p_bhs,20,VAL)

#define GET_PDU_TTT(PDU)		GET_4BYTE((PDU)->p_bhs,20)
#define SET_PDU_TTT(PDU,VAL)		SET_4BYTE((PDU)->p_bhs,20,VAL)

#define GET_PDU_SNACK_TAG(PDU)		GET_4BYTE((PDU)->p_bhs,20)
#define SET_PDU_SNACK_TAG(PDU,VAL) 	SET_4BYTE((PDU)->p_bhs,20,VAL)

/* data in/out PDU */
#define GET_PDU_DATA_XFER_LENGTH(PDU) 	GET_4BYTE((PDU)->p_bhs,20)
#define SET_PDU_DATA_XFER_LENGTH(PDU,VAL) SET_4BYTE((PDU)->p_bhs,20,VAL)

/* login/logout PDU */
#define GET_PDU_CID(PDU)		GET_2BYTE((PDU)->p_bhs,20)
#define SET_PDU_CID(PDU,VAL)		SET_2BYTE((PDU)->p_bhs,20,VAL)


#define GET_PDU_CMDSN(PDU)		GET_4BYTE((PDU)->p_bhs,24)
#define SET_PDU_CMDSN(PDU,VAL)		SET_4BYTE((PDU)->p_bhs,24,VAL)

#define GET_PDU_STATSN(PDU)		GET_4BYTE((PDU)->p_bhs,24)
#define SET_PDU_STATSN(PDU,VAL)		SET_4BYTE((PDU)->p_bhs,24,VAL)

#define GET_PDU_EXPSTATSN(PDU)		GET_4BYTE((PDU)->p_bhs,28)
#define SET_PDU_EXPSTATSN(PDU,VAL)	SET_4BYTE((PDU)->p_bhs,28,VAL)

#define GET_PDU_EXPCMDSN(PDU)		GET_4BYTE((PDU)->p_bhs,28)
#define SET_PDU_EXPCMDSN(PDU,VAL)	SET_4BYTE((PDU)->p_bhs,28,VAL)

#define GET_PDU_MAXCMDSN(PDU)		GET_4BYTE((PDU)->p_bhs,32)
#define SET_PDU_MAXCMDSN(PDU,VAL)	SET_4BYTE((PDU)->p_bhs,32,VAL)

#define GET_PDU_DATASN(PDU)		GET_4BYTE((PDU)->p_bhs,36)
#define SET_PDU_DATASN(PDU,VAL) 	SET_4BYTE((PDU)->p_bhs,36,VAL)

#define GET_PDU_R2TSN(PDU)		GET_4BYTE((PDU)->p_bhs,36)
#define SET_PDU_R2TSN(PDU,VAL) 		SET_4BYTE((PDU)->p_bhs,36,VAL)

#define GET_PDU_EXPDATASN(PDU)		GET_4BYTE((PDU)->p_bhs,36)
#define SET_PDU_EXPDATASN(PDU,VAL)	SET_4BYTE((PDU)->p_bhs,36,VAL)

#define GET_PDU_BUFFER_OFFSET(PDU)	GET_4BYTE((PDU)->p_bhs,40)
#define SET_PDU_BUFFER_OFFSET(PDU,VAL) 	SET_4BYTE((PDU)->p_bhs,40,VAL)

/*
 * SCSI command PDU
 */
#define GET_PDU_R(PDU) 			GET_BIT((PDU)->p_bhs,1,1)
#define SET_PDU_R(PDU)			SET_BIT((PDU)->p_bhs,1,1)
#define CLR_PDU_R(PDU)			CLR_BIT((PDU)->p_bhs,1,1)

#define GET_PDU_W(PDU) 			GET_BIT((PDU)->p_bhs,1,2)
#define SET_PDU_W(PDU)			SET_BIT((PDU)->p_bhs,1,2)
#define CLR_PDU_W(PDU)			CLR_BIT((PDU)->p_bhs,1,2)

#define GET_PDU_TASK_ATTRIBUTES(PDU)	(GET_1BYTE((PDU)->p_bhs,1) & 0x7)
#define SET_PDU_TASK_ATTRIBUTES(PDU,VAL)	((*(unsigned char *)(((unsigned char *)((PDU)->p_bhs))+1)) = \
		((*(unsigned char *)(((unsigned char *)((PDU)->p_bhs))+1) & 0xF8) | ((VAL) & 0x7)))

#define GET_PDU_CDB_DATA_PTR(PDU)	(((unsigned char *)((PDU)->p_bhs))+32)

/*
 * SCSI response PDU
 */
#define GET_PDU_o(PDU) 			GET_BIT((PDU)->p_bhs,1,3)
#define SET_PDU_o(PDU)			SET_BIT((PDU)->p_bhs,1,3)
#define CLR_PDU_o(PDU)			CLR_BIT((PDU)->p_bhs,1,3)

#define GET_PDU_u(PDU) 			GET_BIT((PDU)->p_bhs,1,4)
#define SET_PDU_u(PDU)			SET_BIT((PDU)->p_bhs,1,4)
#define CLR_PDU_u(PDU)			CLR_BIT((PDU)->p_bhs,1,4)

#define GET_PDU_O(PDU) 			GET_BIT((PDU)->p_bhs,1,5)
#define SET_PDU_O(PDU)			SET_BIT((PDU)->p_bhs,1,5)
#define CLR_PDU_O(PDU)			CLR_BIT((PDU)->p_bhs,1,5)

#define GET_PDU_U(PDU) 			GET_BIT((PDU)->p_bhs,1,6)
#define SET_PDU_U(PDU)			SET_BIT((PDU)->p_bhs,1,6)
#define CLR_PDU_U(PDU)			CLR_BIT((PDU)->p_bhs,1,6)

#define GET_PDU_BI_READ_RESIDUAL_COUNT(PDU)	GET_4BYTE((PDU)->p_bhs,40)
#define SET_PDU_BI_READ_RESIDUAL_COUNT(PDU,VAL) SET_4BYTE((PDU)->p_bhs,40,VAL)

#define GET_PDU_RESIDUAL_COUNT(PDU)		GET_4BYTE((PDU)->p_bhs,44)
#define SET_PDU_RESIDUAL_COUNT(PDU,VAL)		SET_4BYTE((PDU)->p_bhs,44,VAL)

/*
 * Task Management Function Response PDU
 */
#define GET_PDU_TMF_FUNCTION(PDU) 	(GET_1BYTE((PDU)->p_bhs,1) & 0x7F)
#define SET_PDU_TMF_FUNCTION(PDU,VAL) 	(*(unsigned char *)(((unsigned char *)((PDU)->p_bhs))+1) = \
		((*(unsigned char *)(((unsigned char *)((PDU)->p_bhs))+1)) & 0x80) | ((VAL) & 0x7F) )

#define GET_PDU_TMF_REF_TASK_TAG(PDU)		GET_4BYTE((PDU)->p_bhs,20)
#define SET_PDU_TMF_REF_TASK_TAG(PDU,VAL) 	SET_4BYTE((PDU)->p_bhs,20,VAL)

#define GET_PDU_TMF_REFCMDSN(PDU)		GET_4BYTE((PDU)->p_bhs,32)
#define SET_PDU_TMF_REFCMDSN(PDU,VAL) 		SET_4BYTE((PDU)->p_bhs,32,VAL)

/*
 * SCSI Data-out PDU
 */
/*
 * SCSI Data_in PDU
 */
#define GET_PDU_A(PDU) 			GET_BIT((PDU)->p_bhs,1,1)
#define SET_PDU_A(PDU)			SET_BIT((PDU)->p_bhs,1,1)
#define CLR_PDU_A(PDU)			CLR_BIT((PDU)->p_bhs,1,1)

#define GET_PDU_O(PDU) 			GET_BIT((PDU)->p_bhs,1,5)
#define SET_PDU_O(PDU)			SET_BIT((PDU)->p_bhs,1,5)
#define CLR_PDU_O(PDU)			CLR_BIT((PDU)->p_bhs,1,5)

#define GET_PDU_U(PDU) 			GET_BIT((PDU)->p_bhs,1,6)
#define SET_PDU_U(PDU)			SET_BIT((PDU)->p_bhs,1,6)
#define CLR_PDU_U(PDU)			CLR_BIT((PDU)->p_bhs,1,6)

#define GET_PDU_S(PDU) 			GET_BIT((PDU)->p_bhs,1,7)
#define SET_PDU_S(PDU)			SET_BIT((PDU)->p_bhs,1,7)
#define CLR_PDU_S(PDU)			CLR_BIT((PDU)->p_bhs,1,7)

/*
 * Ready to Transfer (R2T) PDU
 */
#define GET_PDU_DESIRED_DATA_XFER_LENGTH(PDU)	GET_4BYTE((PDU)->p_bhs,44)
#define SET_PDU_DESIRED_DATA_XFER_LENGTH(PDU,VAL)	SET_4BYTE((PDU)->p_bhs,44,VAL)

/*
 * Asynchronous Message PDU
 */
#define GET_PDU_ASYNC_EVENT(PDU)		GET_1BYTE((PDU)->p_bhs,36)
#define SET_PDU_ASYNC_EVENT(PDU,VAL)	SET_1BYTE((PDU)->p_bhs,36,VAL)

#define GET_PDU_ASYNC_VCODE(PDU)	GET_1BYTE((PDU)->p_bhs,37)
#define SET_PDU_ASYNC_VCODE(PDU,VAL)	SET_1BYTE((PDU)->p_bhs,37,VAL)

#define GET_PDU_ASYNC_PARM1(PDU)	GET_2BYTE((PDU)->p_bhs,38)
#define SET_PDU_ASYNC_PARM1(PDU,VAL)	SET_2BYTE((PDU)->p_bhs,38,VAL)

#define GET_PDU_ASYNC_PARM2(PDU)	GET_2BYTE((PDU)->p_bhs,40)
#define SET_PDU_ASYNC_PARM2(PDU,VAL)	SET_2BYTE((PDU)->p_bhs,40,VAL)

#define GET_PDU_ASYNC_PARM3(PDU)	GET_2BYTE((PDU)->p_bhs,42)
#define SET_PDU_ASYNC_PARM3(PDU,VAL)	SET_2BYTE((PDU)->p_bhs,42,VAL)

/*
 * Text Response PDU
 */

/*
 * Login Request PDU
 */
#define GET_PDU_LOGIN_T(PDU)      	GET_BIT((PDU)->p_bhs,1,0)
#define SET_PDU_LOGIN_T(PDU)      	SET_BIT((PDU)->p_bhs,1,0)
#define CLR_PDU_LOGIN_T(PDU)      	CLR_BIT((PDU)->p_bhs,1,0)

#define GET_PDU_LOGIN_CSG(PDU)		((*(unsigned char *)(((unsigned char *)((PDU)->p_bhs))+1) & 0xC) >> 2)
#define SET_PDU_LOGIN_CSG(PDU,VAL)	((*(unsigned char *)(((unsigned char *)((PDU)->p_bhs))+1)) = \
		((*(unsigned char *)(((unsigned char *)((PDU)->p_bhs))+1)) & 0xF3)|((VAL<<2)&0xC))

#define GET_PDU_LOGIN_NSG(PDU)		(*(unsigned char *)(((unsigned char *)((PDU)->p_bhs))+1) & 0x3)
#define SET_PDU_LOGIN_NSG(PDU,VAL)	((*(unsigned char *)(((unsigned char *)((PDU)->p_bhs))+1)) = \
			((*(unsigned char *)(((unsigned char *)((PDU)->p_bhs))+1)) & 0xFC)|((VAL)&0x3))

#define GET_PDU_LOGIN_VERSION_MAX(PDU)		GET_1BYTE((PDU)->p_bhs,2)
#define SET_PDU_LOGIN_VERSION_MAX(PDU,VAL)	SET_1BYTE((PDU)->p_bhs,2,VAL)

#define GET_PDU_LOGIN_VERSION_MIN(PDU)		GET_1BYTE((PDU)->p_bhs,3)
#define SET_PDU_LOGIN_VERSION_MIN(PDU,VAL)	SET_1BYTE((PDU)->p_bhs,3,VAL)

#define GET_PDU_LOGIN_VERSION_ACTIVE(PDU)	GET_1BYTE((PDU)->p_bhs,3)
#define SET_PDU_LOGIN_VERSION_ACTIVE(PDU,VAL)	SET_1BYTE((PDU)->p_bhs,3,VAL)

#define GET_PDU_LOGIN_ISID(PDU,ISID)	(memcpy(ISID, (PDU)->p_bhs + 8, 6))
#define SET_PDU_LOGIN_ISID(PDU,ISID)	(memcpy((PDU)->p_bhs + 8, ISID, 6))

#define GET_PDU_LOGIN_TSIH(PDU)			GET_2BYTE((PDU)->p_bhs,14)
#define SET_PDU_LOGIN_TSIH(PDU,VAL)		SET_2BYTE((PDU)->p_bhs,14,VAL)

/* 
 * login response PDU
 */
#define GET_PDU_LOGIN_STATUS_CLASS(PDU)		GET_1BYTE((PDU)->p_bhs,36)
#define SET_PDU_LOGIN_STATUS_CLASS(PDU,VAL)	SET_1BYTE((PDU)->p_bhs,36,VAL)

#define GET_PDU_LOGIN_STATUS_DETAIL(PDU)	GET_1BYTE((PDU)->p_bhs,37)
#define SET_PDU_LOGIN_STATUS_DETAIL(PDU,VAL)	SET_1BYTE((PDU)->p_bhs,37,VAL)

/* 
 * Logout Request PDU
 */
#define GET_PDU_LOGOUT_REASON(PDU)	(GET_1BYTE((PDU)->p_bhs,1) & 0x7F)
#define SET_PDU_LOGOUT_REASON(PDU,VAL)	(SET_1BYTE((PDU)->p_bhs,1,(((VAL)&0x7F)|0x80)))

/* 
 * Logout Response PDU
 */
#define GET_PDU_LOGOUT_RESPONSE(PDU)		GET_1BYTE((PDU)->p_bhs,2)
#define SET_PDU_LOGOUT_RESPONSE(PDU,VAL)	SET_1BYTE((PDU)->p_bhs,2,VAL)

#define GET_PDU_LOGOUT_TIME2WAIT(PDU)		GET_2BYTE((PDU)->p_bhs,40)
#define SET_PDU_LOGOUT_TIME2WAIT(PDU,VAL)	SET_2BYTE((PDU)->p_bhs,40,VAL)

#define GET_PDU_LOGOUT_TIME2RETAIN(PDU)		GET_2BYTE((PDU)->p_bhs,42)
#define SET_PDU_LOGOUT_TIME2RETAIN(PDU,VAL)	SET_2BYTE((PDU)->p_bhs,42,VAL)

/*
 * SNACK request PDU
 */
#define GET_PDU_SNACK_TYPE(PDU)		(GET_1BYTE((PDU)->p_bhs,1)&0xF)
#define SET_PDU_SNACK_TYPE(PDU,VAL)	(SET_1BYTE((PDU)->p_bhs,1,((VAL&0xF)|0x80)))

#define GET_PDU_SNACK_BEGRUN(PDU)		GET_4BYTE((PDU)->p_bhs,40)
#define SET_PDU_SNACK_BEGRUN(PDU,VAL)		SET_4BYTE((PDU)->p_bhs,40,VAL)

#define GET_PDU_SNACK_RUNLENGTH(PDU)		GET_4BYTE((PDU)->p_bhs,44)
#define SET_PDU_SNACK_RUNLENGTH(PDU,VAL)	SET_4BYTE((PDU)->p_bhs,44,VAL)

/*
 * Reject PDU
 */
#define GET_PDU_REJECT_REASON(PDU)		GET_1BYTE((PDU)->p_bhs,2)
#define SET_PDU_REJECT_REASON(PDU,VAL)		SET_1BYTE((PDU)->p_bhs,2,VAL)


/*
 * NOP-Out PDU
 */

/*
 * NOP_In PDU
 */


/*
 * Sense Data, <2 bytes of length><followed by data> 
 */
#define PDU_SENSE_DATA_LENGTH_FIELD_SIZE	2

#define GET_SENSE_DATA_LENGTH(PTR)		GET_2BYTE(PTR,0)
#define SET_SENSE_DATA_LENGTH(PTR,VAL)		SET_2BYTE(PTR,0,VAL)

#define GET_SENSE_DATA_PTR(PTR)		(((unsigned char *)(PTR))+2)

/* display */
int     iscsi_pdu_display(iscsi_pdu *, char *, int, int);

/* pdu allocation & free */
void iscsi_connection_pdu_pool_fill(iscsi_connection *);
void iscsi_connection_pdu_pool_release(iscsi_connection *);
iscsi_pdu *iscsi_pdu_get(iscsi_connection *, unsigned int, unsigned int,
			   unsigned int);
void    iscsi_pdu_done(iscsi_pdu *);
int     iscsi_pdu_enlarge_sglist(iscsi_pdu *, unsigned int);
int	iscsi_pdu_alloc_data_buffer(iscsi_pdu *, unsigned int);
int iscsi_pdu_sglist_setup_by_offset(iscsi_pdu *, unsigned int,
				chiscsi_sgvec *, unsigned int);
int iscsi_pdu_pi_sglist_setup_by_offset(iscsi_pdu *, unsigned int,
				chiscsi_sgvec *, unsigned int);

void    iscsi_pduq_free_all(chiscsi_queue *, iscsi_pdu *);
void    iscsi_pduq_free_by_conn(chiscsi_queue *, iscsi_connection *);

/* search */
iscsi_pdu *iscsi_pduq_search(chiscsi_queue *, unsigned char, unsigned int,
			     unsigned int, unsigned int);

/* pdu data copy */
int     iscsi_pduq_data_to_one_buffer(chiscsi_queue *, char **);
int     iscsi_pdu_data_to_one_buffer(iscsi_pdu *, char **);
int     iscsi_pdu_data_to_sglist(iscsi_pdu *, chiscsi_sgvec *, unsigned int,
				 unsigned int);
int     iscsi_pduq_data_to_sglist(chiscsi_queue *, chiscsi_sgvec *,
				  unsigned int, unsigned int);

/* iscsi digest */
int     iscsi_header_digest_set(iscsi_pdu *);
int     iscsi_data_digest_set(iscsi_pdu *);
int     iscsi_header_digest_check(iscsi_pdu *);
int     iscsi_data_digest_check(iscsi_pdu *);

/* send prepare */
int     iscsi_pdu_prepare_to_send(iscsi_pdu *);
#endif /* __PDU_PDU_DEFS_H__ */
