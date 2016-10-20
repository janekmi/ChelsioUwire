/*
 *  Copyright (C) 2015 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: This file defines unified sal api required for SCSI Target 
 * stack to interface with Chelsio fcoe/iscsi interface driver.
 */

#ifndef __CSIO_SAL_API_H__
#define __CSIO_SAL_API_H__

/* All compatible SAL versions */
#define CHTGT_SAL_VERSION 0x100
#define CHTGT_SAL_VERSION_STR  "1.0.0"

#define FBSD_SAL_VERSION 0x100
#define FBSD_SAL_VERSION_STR "1.0.0"
/* return values b/w TGT driver <---> SAL */
typedef enum { 
	CSIO_TSUCCESS = 0,
	CSIO_TINVAL = 1,
	CSIO_TBUSY = 2,
	CSIO_TNOSUPP = 3,
	CSIO_TTIMEOUT = 4,
	CSIO_TNOMEM = 5,
	CSIO_TNOPERM = 6,
	CSIO_TRETRY = 7,
	CSIO_TEPROTO = 8,
	CSIO_TEIO = 9,
	CSIO_TCANCELLED = 10,
	CSIO_TDUP = 11,
} csio_tret_t;

typedef void	*csio_sal_handle_t;
typedef void    *csio_tgt_handle_t;
typedef void    *csio_ssn_handle_t;
typedef void    *csio_cmd_handle_t;
typedef void    *csio_conn_handle_t;
typedef void    *csio_sess_handle_t;
typedef void 	*csio_dev_handle_t;
typedef void 	*csio_lport_handle_t;


/* control op codes*/
typedef enum {
	CSIO_INITIAL_LOGIN  = 1,	/* Initial login */
	CSIO_STAGE_LOGIN,		/* Current login stage */
	CSIO_CHAP_AUTH,			/* Chap authentication  */
	CSIO_DISC_TARGET_ACL,		/* Controls targets accessible during 
					 *  discovery 
					 */
	CSIO_REDIRECT_TARGET,		/* Target Redirection */
	CSIO_SESSION_ADD,		/* Session added */
	CSIO_SESSION_REM,		/* Session removed */
} csio_sal_control_op_t;

/* Type of protocol*/
typedef enum {
	CSIO_SAL_PROT_FCOE  = 0,
	CSIO_SAL_PROT_ISCSI,
	CSIO_SAL_PROT_MAX,
} csio_sal_prot_t;



#define PROTO_FCP_PTA_SIMPLE			0x0 /* simple queue tag */
#define PROTO_FCP_PTA_HEADQ			0x1 /* head of queue tag */
#define PROTO_FCP_PTA_ORDERED			0x2 /* ordered task attribute */
#define PROTO_FCP_PTA_ACA			0x4 /* auto. contigent allegiance */
#define PROTO_FCP_PTA_UNTAGGED			0x5 
#define PROTO_FCP_PTA_MASK			0x7 

/*
 * tcp 4tuples
 */
#define ISCSI_IPADDR_LEN                16
#define ISCSI_IPADDR_IPV4_OFFSET        12

struct tcp_endpoint {
	unsigned char	ip[ISCSI_IPADDR_LEN];
	unsigned int  	port;
};

typedef struct iscsi_tcp_endpoints {
	unsigned int f_ipv6:1;
	unsigned int f_filler:31;
	struct tcp_endpoint iaddr;      /* initiator tcp address */
	struct tcp_endpoint taddr;      /* target tcp address */
	unsigned int port_id;   	/* for Chelsio HBA only */
} iscsi_tcp_endpoints_t;

#define CHAP_NAME_LEN_MIN       1
#define CHAP_NAME_LEN_MAX       256
#define CHAP_SECRET_LEN_MIN     12
#define CHAP_SECRET_LEN_MAX     16

#define CHAP_FLAG_LOCAL_NAME_VALID      0x1
#define CHAP_FLAG_LOCAL_SECRET_VALID    0x2
#define CHAP_FLAG_REMOTE_NAME_VALID     0x4
#define CHAP_FLAG_REMOTE_SECRET_VALID   0x8
#define CHAP_FLAG_MUTUAL_REQUIRED       0x10

typedef struct chap_info {
	unsigned char   flag;
	unsigned char   local_secret_length;
	unsigned char   remote_secret_length;
	unsigned char   filler;

	char    local_name[CHAP_NAME_LEN_MAX];
	char    local_secret[CHAP_SECRET_LEN_MAX];
	char    remote_name[CHAP_NAME_LEN_MAX];
	char    remote_secret[CHAP_SECRET_LEN_MAX];
} chap_info_t;

/* Control command */
typedef struct csio_sal_control_cmd {
	csio_sal_control_op_t	op;	/* control opcode */
	csio_sal_prot_t		proto;	/* Protocol */
	csio_ssn_handle_t	ssn_hndl; /* session handle */
	csio_conn_handle_t	conn_hndl; /* connection handle */
	csio_tgt_handle_t	tgt_hndl; /* Target handle */
	union {
		struct {
		} fcoe;
	        struct {	
			unsigned char login_stage;	/* login stage */
			unsigned char login_status_class; /* login status */
			unsigned char login_status_detail; /* login status 
							    * detail 
							    */
	 		unsigned int  max_cmd;		   /* max command 
							    * supported 
							    */
			unsigned char isid[6];		 /* isid */
			char          *initiator_name;   /* initiator name */
			char   	      *target_name;	 /* target name */
			iscsi_tcp_endpoints_t  *eps;	 /* local and remote 
							  * tcp endpoint 
							  */
			chap_info_t 	       *chap; 	 /* chap information */
                } iscsi; 
	} u;
} csio_sal_control_cmd_t;

/* Type of role */
typedef enum {
	CSIO_SAL_ROLE_NONE  = 0,
	CSIO_SAL_ROLE_INITIATOR,
	CSIO_SAL_ROLE_TARGET,
	CSIO_SAL_ROLE_BOTH
} csio_sal_role_t;

/* TGT Commands from SAL to driver */
typedef enum {
	CSIO_SAL_LPORT_PARAM  = 1,		/* lport parameter */
	CSIO_SAL_SESSION_PARAM  = 2,		/* session parameter */
	CSIO_SAL_CONN_PARAM = 3,		/* connection parameter */ 
	CSIO_SAL_CONFIG_PARAM  = 4,		/* config parameter */
} csio_sal_param_type_t;

typedef struct csio_sal_tgt_cmdhdr {
	csio_dev_handle_t 	dev_handle;
	csio_lport_handle_t	lport_handle;
        csio_sal_prot_t         prot; /* Type of protocol */
} csio_sal_tgt_cmdhdr_t;

struct csio_sal_fcoe_port_params {
	uint8_t 		wwpn[8];
	uint8_t 		wwnn[8];
	uint32_t 		nport_id;
};

struct csio_sal_iscsi_port_params {
	char			*node_name;
	uint16_t 		grouptag;
	unsigned char		isid[6];
	struct tcp_endpoint 	tcp_endpoint;
	iscsi_tcp_endpoints_t  eps;
}; 

typedef struct csio_sal_lport_params {
	uint8_t			port;	/* Port number */
	csio_sal_role_t		role;
	union {            	      /* Params */
		struct csio_sal_fcoe_port_params fcoe_params;
		struct csio_sal_iscsi_port_params iscsi_params;
	} un;
} csio_sal_lport_params_t;

#define sal_fcoe_parm(P) 	(P)->un.fcoe_params
#define sal_iscsi_parm(P) 	(P)->un.iscsi_params

/* Registration params between driver and SAL */
typedef struct csio_sal_reg_params {
        csio_sal_prot_t         prot;         /* Type of protocol */
	union {            	      /* Params */
		struct csio_sal_fcoe_port_params fcoe_params;
		struct csio_sal_iscsi_port_params iscsi_params;
	} un;
        void                    *priv;   /* Driver private
                                          * object
                                          */
} csio_sal_reg_params_t;

/* Key value parameter */
typedef struct csio_sal_keyval {
	char *key;		/* key name */
	char *val;		/* value */
	uint8_t keylen;		/* key length */	
	uint8_t vallen;		/* value length */
} csio_sal_keyval_t;

/* Key value pairs */
typedef struct csio_sal_kv_params {
	uint16_t		kv_count; 
	csio_sal_keyval_t	kv_entry[0];
} csio_sal_kv_params_t;

/* sal parameters */
typedef struct csio_sal_params {
	csio_sal_tgt_cmdhdr_t	cmdhdr;
        csio_sal_prot_t         prot;         /* Type of protocol */
	union {
		struct csio_sal_fcoe_port_params	fcoe_params;
		csio_sal_kv_params_t			kv_params;
	} un;	
} csio_sal_params_t;

/* Defines for req_status */
#define CSIO_DRV_ST_SUCCESS		0
#define CSIO_DRV_ST_FAILED		-1
#define CSIO_DRV_ST_ABORTED		-2

/* Task management opcodes */
typedef enum {
	CSIO_SAL_TM_ABORT_TASK		= 1,
	CSIO_SAL_TM_ABORT_TASK_SET	= 2,
	CSIO_SAL_TM_CLEAR_ACA		= 3,
	CSIO_SAL_TM_CLEAR_TASK_SET	= 4,
	CSIO_SAL_TM_LUN_RESET		= 5,
	CSIO_SAL_TM_TARGET_RESET	= 6,
} csio_tm_op_t;

/* Task management status codes */
typedef enum {
	CSIO_SAL_TM_ST_SUCCESS		= 0,
	CSIO_SAL_TM_ST_INVALID_TASK	= 1,
	CSIO_SAL_TM_ST_INVALID_LUN	= 2,
	CSIO_SAL_TM_ST_UNSUPP_FN	= 3,
	CSIO_SAL_TM_ST_REJECTED		= 4,
	CSIO_SAL_TM_ST_FAILED		= 5,
} csio_tm_st_t;

/* Command structure from driver to SAL */
typedef struct csio_sal_cmd {	
	uint8_t			*cdb;			/* scsi cdb */
	uint8_t			*lun;			/* LUN */
	uint16_t		scdb;			/* scsi cdb size */
	uint16_t		slun;			/* Size of LUN */
	uint64_t		tag;			/* IO Tag */
	uint32_t		init_tag;		/* Initiator Tag */

	/* Chelsio Target needs xfer_len bcoz it didn't rely on cdb info 
	 for length */
	uint32_t		xfer_len;		/* xfer len */
	csio_tgt_handle_t	tgt_handle;		/* Target handle */
	csio_ssn_handle_t	ssn_handle;		/* session handle */
	void 			*priv;			/* Private command 
							 * object of target 
							 * driver. Will be
							 * passed to SCSI 
							 * server. When called
							 * from SCSI server,
							 * this object will
							 * be extracted and
							 * passed to the
							 * target driver.
							 */
	int			atomic;
	void 			*scratch1;
	void 			*scratch2;
	void			*scratch3;
	csio_tm_op_t		tm_op;			/* Task mgmt opcode */
} csio_sal_cmd_t;

#define csio_sreq_set_flag(__s, __f)		((__s)->flags |= (__f))
#define csio_sreq_clear_flag(__s, __f)		((__s)->flags &= ~(__f))
#define csio_sreq_is_flag_set(__s, __f)		((__s)->flags & (__f))

struct csio_sal_ops;
/* The I/O element between driver and SAL */
typedef struct csio_sal_req {
	void			*drv_req;	/* Driver's request object */
	void			*os_dev;	/* The OS HW device object */
	struct csio_sal_ops	*sops;		/* Sal ops */
	csio_sal_prot_t  	prot;		/* Type of protocol */
	int			nsge;		/* Number SG elements
						 */
	int			nsge_map;	/* Number of Mapped SG 
						 * elements
						 */
	void			*os_sge;	/* The OS Scatter-Gather 
						 * element.
						 */
	int64_t			write_data_len;
	uint32_t		rel_off;
	uint32_t		buff_len;
	int			data_len;	/* Data length */
	uint16_t		data_direction;	/* Data direction */
	uint16_t		send_status;	/* send status or not */
	uint16_t		scsi_status;	/* status set by scsi server*/
	int8_t			req_status;	/* Status from driver */
	uint8_t			*sense_buffer;	/* Sense buffer */
	int			sense_buffer_len; /* Sense buffer len */
	uint8_t			pri;		/* Priority - from cmd,
						 * protocol specific
						 */
	uint8_t			ta;		/* Task attribute - from cmd,
						 * protocol specific
						 */
	csio_tm_op_t            tm_op;
} csio_sal_req_t;

typedef struct csio_sgl {
	int	sg_flag;
	void    *sg_addr;
	void 	*sg_dma_addr;
	size_t	sg_offset;
	size_t	sg_length;
} csio_sgl_t;

#define csio_scsi_for_each_sg(_sgl, _sgel, _n, _i)	\
        for (_i = 0, _sgel = (csio_sgl_t *) (_sgl); _i < _n; _i++, \
			_sgel++)
#define sg_dma_addr(_sgel)	_sgel->sg_dma_addr
#define sg_virt(_sgel)		_sgel->sg_addr
#define sg_len(_sgel)		_sgel->sg_length
#define sg_off(_sgel)		_sgel->sg_offset
#define sg_next(_sgel)		_sgel + 1

/* SAL proto ops */
typedef struct csio_proto_ops {
	csio_lport_handle_t (*sal_target_add)(csio_sal_lport_params_t *,
					csio_tgt_handle_t);
	csio_tret_t (*sal_target_remove)(csio_lport_handle_t);
	csio_tret_t (*sal_target_enable)(csio_lport_handle_t, int);
	csio_lport_handle_t (*sal_set_param)(csio_sal_param_type_t, csio_sal_params_t *);
	csio_tret_t (*sal_get_param)(csio_sal_param_type_t, csio_sal_params_t *);
	csio_tret_t (*sal_control_send)(csio_sal_control_cmd_t *);
	csio_tret_t (*sal_xmit)(csio_sal_req_t *);
	csio_tret_t (*sal_acc)(csio_sal_req_t *);
	csio_tret_t (*sal_rsp)(csio_sal_req_t *);
	csio_tret_t (*sal_abort)(csio_sal_req_t *);
	csio_tret_t (*sal_abort_status)(csio_sal_req_t *);
	void 	    (*sal_tm_done)(csio_sal_req_t *, csio_tm_st_t, csio_cmd_handle_t);
	void 	    (*sal_free)(csio_sal_req_t *);
	void        (*sal_sess_unreg_done)(void *);

} csio_proto_ops_t;

/* SAL ops */
typedef struct csio_sal_ops {
	uint32_t 		sal_version;
	int 			max_sge;
	csio_sal_prot_t		proto;
	csio_proto_ops_t	*proto_ops;
	csio_cmd_handle_t	(*sal_rcv_cmd)(csio_ssn_handle_t ssn, csio_sal_cmd_t *);
	void			(*sal_start_cmd)(csio_cmd_handle_t);
	int			(*sal_async_mode)(csio_sal_cmd_t *);
	void			(*sal_control_rcv)(csio_sal_control_cmd_t *);
	void			(*sal_cmd_abort)(csio_cmd_handle_t);
	void			(*sal_cmd_abort_status)(csio_sal_cmd_t *);
	void 			(*sal_rcv_data)(csio_cmd_handle_t, int);
	void 			(*sal_xmit_done)(csio_cmd_handle_t, int);
	void 			(*sal_cmd_done)(csio_cmd_handle_t, 
						csio_sal_req_t *);
	void			(*sal_cmd_cleanup)(csio_sal_cmd_t *);
	csio_tret_t 		(*sal_rcv_tm)(csio_ssn_handle_t,
					      csio_sal_cmd_t *,
					      csio_cmd_handle_t *);
	csio_ssn_handle_t 	(*sal_reg_ssn) (csio_tgt_handle_t tgt, 
					csio_sal_reg_params_t *);
	void	    		(*sal_unreg_ssn) (csio_ssn_handle_t);
	csio_tgt_handle_t	(*sal_reg_tgt)(csio_sal_lport_params_t *);
	void			(*sal_unreg_tgt)(csio_tgt_handle_t);
} csio_sal_ops_t;

static inline
void csio_sal_sess_unreg_done(csio_sal_ops_t *sops, void *rn)
{
	if (sops->proto_ops && sops->proto_ops->sal_sess_unreg_done)
		sops->proto_ops->sal_sess_unreg_done(rn);

}
csio_sal_ops_t *csio_sal_get_sops(csio_sal_prot_t proto);

static inline
csio_tret_t csio_sal_xmit(csio_sal_req_t *sreq) 
{
	csio_sal_ops_t *sops = sreq->sops;
	if (sops->proto_ops && sops->proto_ops->sal_xmit)
		return sops->proto_ops->sal_xmit(sreq);

	return  CSIO_TNOSUPP;
}

static inline
csio_tret_t csio_sal_acc(csio_sal_req_t *sreq) 
{

	csio_sal_ops_t *sops = sreq->sops;
	if (sops->proto_ops && sops->proto_ops->sal_acc)
		return sops->proto_ops->sal_acc(sreq);

	return  CSIO_TNOSUPP;
}

static inline
csio_tret_t csio_sal_rsp(csio_sal_req_t *sreq) 
{

	csio_sal_ops_t *sops = sreq->sops;
	if (sops->proto_ops && sops->proto_ops->sal_rsp)
		return sops->proto_ops->sal_rsp(sreq);

	return  CSIO_TNOSUPP;
}

static inline
csio_tret_t csio_sal_free(csio_sal_req_t *sreq) 
{

	csio_sal_ops_t *sops = sreq->sops;
	if (sops->proto_ops && sops->proto_ops->sal_free)
		sops->proto_ops->sal_free(sreq);

	return  CSIO_TNOSUPP;
}

static inline
csio_tret_t csio_sal_abort_status(csio_sal_req_t *sreq)
{
	csio_sal_ops_t *sops = sreq->sops;
	if (sops->proto_ops && sops->proto_ops->sal_abort_status)
		sops->proto_ops->sal_abort_status(sreq);
	
	return CSIO_TNOSUPP;
}
static inline
csio_tret_t csio_sal_tm_done(csio_sal_req_t *sreq, 
		csio_tm_st_t tm_status, csio_cmd_handle_t cmd)
{
	csio_sal_ops_t *sops = sreq->sops;
	if (sops->proto_ops && sops->proto_ops->sal_tm_done)
		sops->proto_ops->sal_tm_done(sreq, tm_status, cmd);
	
	return CSIO_TNOSUPP;
}	

static inline
csio_tret_t csio_sal_control_send(csio_sal_ops_t *sops, 
				  csio_sal_control_cmd_t *ctrl_req)
{
	if (sops->proto_ops && sops->proto_ops->sal_control_send)
		return sops->proto_ops->sal_control_send(ctrl_req);

	return  CSIO_TNOSUPP;
}
 
static inline
csio_lport_handle_t csio_sal_target_add(csio_sal_ops_t *sops, 
				csio_sal_lport_params_t *lparam,
				csio_tgt_handle_t tgt_hndl)
{
	if (sops->proto_ops && sops->proto_ops->sal_target_add)
		return sops->proto_ops->sal_target_add(lparam, tgt_hndl);

	return  NULL;
}

static inline
csio_tret_t csio_sal_target_remove(csio_sal_ops_t *sops, 
				csio_tgt_handle_t tgt_hndl)
{
	if (sops->proto_ops && sops->proto_ops->sal_target_remove)
		return sops->proto_ops->sal_target_remove(tgt_hndl);

	return  CSIO_TNOSUPP;
}

static inline
csio_lport_handle_t csio_sal_set_param(csio_sal_ops_t *sops,
			csio_sal_param_type_t	ptype,
			csio_sal_params_t *param)
{
	if (sops->proto_ops && sops->proto_ops->sal_set_param)
		return sops->proto_ops->sal_set_param(ptype, param);

	return  NULL;
}

static inline
csio_tret_t csio_sal_get_param(csio_sal_ops_t *sops,
			csio_sal_param_type_t	ptype,
			csio_sal_params_t *param)
{
	if (sops->proto_ops && sops->proto_ops->sal_get_param)
		return sops->proto_ops->sal_get_param(ptype, param);

	return  CSIO_TNOSUPP;
}
csio_sal_ops_t *csio_sal_register_proto(csio_proto_ops_t *proto_ops, 
		csio_sal_prot_t proto);
void csio_sal_unregister_proto(csio_sal_prot_t proto);
csio_tret_t csio_sal_init(csio_sal_ops_t *);
void csio_sal_exit(csio_sal_ops_t *);
int csio_scst_sal_init(void);
void csio_scst_sal_exit(void);
#endif /* __CSIO_SAL_API_H__ */
