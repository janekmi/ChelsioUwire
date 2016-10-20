/******************************************************************************
 *
 * Copyright (c) Chelsio Communications.  All rights reserved.
 *
 *   THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
 *   KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 *   IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
 *   PURPOSE.
 *
 * Module Name:
 *
 *    csio_iscsi.c
 *
 * Abstract:
 *
 *    csio_iscsi.c -  contains the common Chelsio iSCSI specific handlers. 
 *
 * Environment:
 *
 *    User mode
 *
 * Revision History:
 *
 *	Vijay S J - 8-March-11 -	Creation
 *
 *****************************************************************************/
#define _GNU_SOURCE
#define CHSTORUTIL_INCLUDE_ISCSI_INITIALIZATIONS
#include <csio_foiscsi.h>
#include <csio_foiscsi_persistent.h>
#include <cxgbtool_stor.h>
#include <cxgbtool_stor_params.h>

#if !defined __GNUC__
#pragma warning(disable : 4995)
#endif

#define ISCSI_PARAM_FILE	"/etc/csio_iscsi_param.conf"
#define FILE_BUF_SIZE		400

//returns -1 on failure or ip on success
uint32_t convert_dotted_ip(char *ip)
{
	int a,b,c,d;
	uint32_t ipadr = 0;
	
	sscanf(ip,"%d.%d.%d.%d",&a,&b,&c,&d);
	//csio_printf("a=%d b=%d c=%d d=%d\n",a,b,c,d);
	//TODO: validate abcd
	ipadr = (a<<24)|(b<<16)|(c<<8)|d;
	//csio_printf("ip=0x%x\n",ipadr);
	return ipadr;
}


int csio_os_read_init_inst_param(struct foiscsi_instance *ini_inst,
		int ini_chap)
{
	char *line = NULL, *pch = NULL, *pch1 = NULL, str[25];
	int count = 0, param = 0, i = 0, ret = 0;
	unsigned long val = 0;
	char val_s[25];
	char *file_buf[FILE_BUF_SIZE];
	size_t len = FILE_BUF_SIZE;
	FILE *fp = NULL;
	int buf_last_line = 0 ;

	if(!(fp = fopen(ISCSI_PARAM_FILE, "r"))) {
		csio_printf("Unable to open Config file\n");
		return -1;
	} else {
		memset(&file_buf,0,FILE_BUF_SIZE);
		file_buf[buf_last_line] = malloc(FILE_BUF_SIZE);
		if(NULL == file_buf[buf_last_line]) {
			fclose(fp);
			return -1;
		}
		while((ret = getline(&file_buf[buf_last_line], &len, fp)) != -1) {
			buf_last_line++;
			file_buf[buf_last_line] = malloc(len);
			if(NULL == file_buf[buf_last_line])
				return -1;
		}
		fclose(fp);
	}

	if(buf_last_line == 0)
		return -1;

	line = malloc(FILE_BUF_SIZE);
	if(NULL == line) {
		goto  free_buff;
		return -ENOMEM;
	}
	for(i=0; i < buf_last_line; i++) {
		count = 0;
		strcpy(line ,file_buf[i]);
		pch = strtok(line, " \t,.\r\n");
		while (NULL != pch) {
			pch1 = strchr(pch, '#');
			if (NULL != pch1) {
				if(i == buf_last_line - 1 && param < 20) {
					free(line);
					goto  free_buff;
				}
				break;
			}
			count++;
			if (2 == count) {
				memset(&val_s,0,sizeof(val_s));
				if (!strcmp (str, "UserName")
					|| !strcmp (str, "UserNameIN")
					|| !strcmp (str, "Password")
					|| !strcmp (str, "PasswordIN"))	{
					strcpy(val_s,pch);
				} else {
					val = atol(pch);
				}
			} else if(1 == count) {
				strcpy(str,pch);
			}
			pch = strtok (NULL, " \t,.\r\n");
		}
		if(count == 0)
		{} else if (count == 2) {
			if ((!strcmp(str, "UserNameIN")) && ini_chap) {
				memcpy(ini_inst->chap_id, val_s, strlen(val_s));
			} else if ((!strcmp(str, "PasswordIN")) && ini_chap) {
					memcpy(ini_inst->chap_sec, val_s, strlen(val_s));
			} else if (!strcmp(str, "LoginRetryCount")) {
				if (!val)
					val = 10;
				ini_inst->login_retry_cnt = val;
			} else if (!strcmp(str, "RecoveryTimeout")) {
				ini_inst->recovery_timeout = val;
			}
		}
	}
free_buff:
	return 0;		

}

int csio_os_read_iscsi_param(struct foiscsi_login_info *linfo, int method)
{
	char *line = NULL, *pch = NULL, *pch1 = NULL, str[25];
	int count = 0, param = 0, i = 0, ret = 0;
	unsigned long val = 0;
	char val_s[25];
	char *file_buf[FILE_BUF_SIZE];
	size_t len = FILE_BUF_SIZE;
	FILE *fp = NULL;
	int buf_last_line = 0 ;

	if(!(fp = fopen(ISCSI_PARAM_FILE, "r"))) {
		csio_printf("Unable to open Config file\n");
	       	return -1;
	} else {
		memset(&file_buf,0,FILE_BUF_SIZE);
		file_buf[buf_last_line] = malloc(FILE_BUF_SIZE);
		if(NULL == file_buf[buf_last_line]) {
			fclose(fp);
			return -1;
		}
		while((ret = getline(&file_buf[buf_last_line], &len, fp)) != -1) {
			buf_last_line++;
			file_buf[buf_last_line] = malloc(len);
			if(NULL == file_buf[buf_last_line])
				return -1;
		}
		fclose(fp);
	}

	if(buf_last_line == 0)
		return -1;

	line = malloc(FILE_BUF_SIZE);
	if(NULL == line) {
		goto  free_buff;
		return -ENOMEM;
	}

	for(i=0; i < buf_last_line; i++) {
		count = 0;
		strcpy(line ,file_buf[i]);

		switch(param) {
			case 0:
			case 1:
			case 2:
			case 3:
			case 4:
			case 5:
			case 6:
			case 7:
			case 8:
			case 9:
			case 10:
			case 11:
			case 12:
			case 13:
			case 14:
			case 15:
			case 16:
			case 17:
			case 18:
			case 19:
			case 20:
			case 21:
			case 22:
			case 23:
			case 24:
			case 25:
			case 26:
			case 27:
			case 28:
			case 29:
			case 30:
			pch = strtok(line, " \t,.\r\n");
			while (NULL != pch) {
				pch1 = strchr(pch, '#');
				if (NULL != pch1) {
					if(i == buf_last_line - 1 && param < 20) {
						free(line);
						goto  free_buff;
					}
					break;
				}
				count++;
				if (2 == count) {
					memset(&val_s,0,sizeof(val_s));
					if (!strcmp(pch, val_string[YES]) 
						|| !strcmp (pch, val_string[NO]) 
						|| !strcmp (pch, "CRC32C") 
						|| !strcmp (pch, "None")
						|| !strcmp (str, "UserName")
						|| !strcmp (str, "UserNameIN")
						|| !strcmp (str, "Password")
						|| !strcmp (str, "PasswordIN")
						|| !strcmp (str, "AuthPolicy")
						|| !strcmp (pch, "Mutual")
						|| !strcmp (pch, "Oneway")
						|| !strcmp (pch, "CHAP")) {
						strcpy(val_s,pch);
					} else {
						val = atol(pch);
					}
				} else if(1 == count) {
					strcpy(str,pch);
				} else {
                                        if (!strcmp(str, "HeaderDigest") ||
					    	!strcmp(str, "DataDigest") ||
					    	!strcmp(str, "AuthMethod") ||
						!strcmp(str, "AuthPolicy")) {
						if (!strcmp(val_s, "CRC32C") || !strcmp(val_s, "None")) {
							if(!strcmp(pch, "CRC32C") || !strcmp(pch, "None")) {
								strcat(val_s,",");
								strcat(val_s,pch);
								count = 2;
							}
						}
					}
				}
				pch = strtok (NULL, " \t,.\r\n");
			}
			if(count == 0)
			{} else if (count == 2) {
                                if (!strcmp(str, "DataSequenceInOrder")) {
                                        if (strcmp(val_s, val_string[YES]) &&  strcmp (val_s, val_string[NO])) {
                                                csio_printf("DataSequenceInOrder should be %s or %s\n", val_string[param_set[V_DSIO][val_max]], val_string[param_set[V_DSIO][val_min]]);
                                                free(line);
                                                goto  free_buff;
                                        }
                                        if (!strcmp(val_s, val_string[YES]))
                                                linfo->sess_attr.sess_type_to_erl |=
							V_FW_FOISCSI_CTRL_WR_SEQ_INORDER(1);
                                        else
                                                linfo->sess_attr.sess_type_to_erl |=
							V_FW_FOISCSI_CTRL_WR_SEQ_INORDER(0);
				} else if (!strcmp(str, "DataPDUInOrder")) {
					if (strcmp(val_s, val_string[YES]) &&  strcmp (val_s, val_string[NO])) {
						csio_printf("DataPDUInOrder should be %s or %s\n", val_string[param_set[V_DPIO][val_max]], val_string[param_set[V_DPIO][val_min]]);
						free(line);
						goto  free_buff;
					}
					if (!strcmp(val_s, val_string[YES]))
						linfo->sess_attr.sess_type_to_erl |=
							V_FW_FOISCSI_CTRL_WR_PDU_INORDER(1);
					else
						linfo->sess_attr.sess_type_to_erl |=
							V_FW_FOISCSI_CTRL_WR_PDU_INORDER(0);
				} else if (!strcmp (str, "ImmediateData")) {
					if (strcmp (val_s, val_string[YES]) && strcmp (val_s, val_string[NO])) {
						csio_printf("ImmediateData should be %s or %s\n", val_string[param_set[V_IDATA][val_min]], val_string[param_set[V_IDATA][val_min]]);
						free(line);
						goto  free_buff;
					}
					if (!strcmp(val_s, val_string[YES]))
						linfo->sess_attr.sess_type_to_erl |=
							V_FW_FOISCSI_CTRL_WR_IMMD_DATA_EN(1);
					else 
						linfo->sess_attr.sess_type_to_erl |=
							V_FW_FOISCSI_CTRL_WR_IMMD_DATA_EN(0);
				} else if (!strcmp(str, "InitialR2T")) {
					if (strcmp(val_s, val_string[YES]) &&  strcmp (val_s, val_string[NO])) {
						csio_printf("InitialR2T should be %s or %s\n", val_string[param_set[V_INITR2T][val_max]], val_string[param_set[V_INITR2T][val_min]]);
						free(line);
						goto  free_buff;
					}
					if (!strcmp(val_s, val_string[YES]))
						linfo->sess_attr.sess_type_to_erl |=
							V_FW_FOISCSI_CTRL_WR_INIT_R2T_EN(1);
					else
						linfo->sess_attr.sess_type_to_erl |=
							V_FW_FOISCSI_CTRL_WR_INIT_R2T_EN(0);
				} else if (!strcmp(str, "ErrorRecoveryLevel")) {
					if (val >= param_set[V_ERL][val_min] && val <= param_set[V_ERL][val_max])
						linfo->sess_attr.sess_type_to_erl |=
							V_FW_FOISCSI_CTRL_WR_ERL(val);
					else {
						csio_printf("ErrorRecoveryLevel should be %d to %d\n", param_set[V_ERL][val_min], param_set[V_ERL][val_max]);
						free(line);
						goto  free_buff;
					}
				} else if (!strcmp(str, "MaxConnections")) {
					if (val >= param_set[V_MAXCONN][val_min] && val <= param_set[V_MAXCONN][val_max])
						linfo->sess_attr.max_conn = val;
					else {
						csio_printf("MaxConnections should be %d to %d\n", param_set[V_MAXCONN][val_min], param_set[V_MAXCONN][val_max]);
						free(line);
						goto  free_buff;
					}
				} else if (!strcmp(str, "MaxOutstandingR2T")) {
					if (val >= param_set[V_MAXR2T][val_min] && val <= param_set[V_MAXR2T][val_max])
						linfo->sess_attr.max_r2t = val;
					else {
						csio_printf("MaxOutstandingR2T should be %d to %d\n", param_set[V_MAXR2T][val_min], param_set[V_MAXR2T][val_max]);
						free(line);
						goto  free_buff;
					}
				} else if (!strcmp(str, "DefaultTime2Wait")) {
					if (val >= param_set[V_T2W][val_min] && val <= param_set[V_T2W][val_max])
						linfo->sess_attr.time2wait = val;
					else {
						csio_printf("DefaultTime2Wait should be %d to %d\n", param_set[V_T2W][val_min], param_set[V_T2W][val_max]);
						free(line);
						goto  free_buff;
					}
				} else if (!strcmp(str, "DefaultTime2Retain")) {
					if (val >= param_set[V_T2R][val_min] && val <= param_set[V_T2R][val_max])
						linfo->sess_attr.time2retain = val;
					else {
						csio_printf("DefaultTime2Retain should be %d to %d\n", param_set[V_T2R][val_min], param_set[V_T2R][val_max]);
						free(line);
						goto  free_buff;
					}
				} else if (!strcmp(str, "MaxBurstLength")) {
					if (val >= param_set[V_MAXBL][val_min] && val <= param_set[V_MAXBL][val_max])
						linfo->sess_attr.max_burst = val;
					else {
						csio_printf("MaxBurstLength should be %d to %d(2**24-1)\n", param_set[V_MAXBL][val_min], param_set[V_MAXBL][val_max]);
						free(line);
						goto  free_buff;
					}
				} else if (!strcmp(str, "FirstBurstLength")) {
					if (val >= param_set[V_FSTBL][val_min] && val <= param_set[V_FSTBL][val_max])
						linfo->sess_attr.first_burst = val;
					else {
						csio_printf("FirstBurstLength should be %d to %d(2**24-1)\n", param_set[V_FSTBL][val_min], param_set[V_FSTBL][val_max]);
						free(line);
						goto  free_buff;
					}
				} else if (!strcmp(str, "HeaderDigest")) {
					if (strcmp(val_s, "CRC32C") && strcmp (val_s, "None")  
						&& strcmp(val_s, "CRC32C,None")
						&& strcmp(val_s, "None,CRC32C"))  {
						csio_printf("HeaderDigest should be CRC32C OR None\n");
						free(line);
						goto  free_buff;
					}
					if (!strcmp(val_s, "CRC32C"))
						linfo->conn_attr.hdigest_to_ddp_pgsz |=
							V_FW_FOISCSI_CTRL_WR_HDIGEST(FW_FOISCSI_DIGEST_TYPE_CRC32);
					else if (!strcmp(val_s, "None"))
						linfo->conn_attr.hdigest_to_ddp_pgsz |=
							V_FW_FOISCSI_CTRL_WR_HDIGEST(FW_FOISCSI_DIGEST_TYPE_NONE);
					else if (!strcmp(val_s, "CRC32C,None")) {
						linfo->conn_attr.hdigest_to_ddp_pgsz |=
							V_FW_FOISCSI_CTRL_WR_HDIGEST(FW_FOISCSI_DIGEST_TYPE_CRC32_FST);
					}
					else if (!strcmp(val_s, "None,CRC32C")) {
						linfo->conn_attr.hdigest_to_ddp_pgsz |=
							V_FW_FOISCSI_CTRL_WR_HDIGEST(FW_FOISCSI_DIGEST_TYPE_CRC32_SEC);
					}
				} else if (!strcmp(str, "DataDigest")) {
					if (strcmp(val_s, "CRC32C") && strcmp (val_s, "None")
						&& strcmp(val_s, "CRC32C,None")
						&& strcmp(val_s, "None,CRC32C"))  {
						csio_printf("DataDigest should be CRC32C OR None\n");
						free(line);
						goto  free_buff;
					}
					if (!strcmp(val_s, "CRC32C"))
						linfo->conn_attr.hdigest_to_ddp_pgsz |=
							V_FW_FOISCSI_CTRL_WR_DDIGEST(FW_FOISCSI_DIGEST_TYPE_CRC32);
					else if (!strcmp(val_s, "None"))
						linfo->conn_attr.hdigest_to_ddp_pgsz |=
							V_FW_FOISCSI_CTRL_WR_DDIGEST(FW_FOISCSI_DIGEST_TYPE_NONE);
					else if (!strcmp(val_s, "CRC32C,None"))
						linfo->conn_attr.hdigest_to_ddp_pgsz |=
							V_FW_FOISCSI_CTRL_WR_DDIGEST(FW_FOISCSI_DIGEST_TYPE_CRC32_FST);
					else if (!strcmp(val_s, "None,CRC32C"))
						linfo->conn_attr.hdigest_to_ddp_pgsz |=
							V_FW_FOISCSI_CTRL_WR_DDIGEST(FW_FOISCSI_DIGEST_TYPE_CRC32_SEC);

				} else if (!strcmp(str, "MaxRecvDataSegmentLength")) {
					if (val >= param_set[V_MAXRDSL][val_min] && val <= param_set[V_MAXRDSL][val_max])
						linfo->conn_attr.max_rcv_dsl = val;
					else {
						csio_printf("MaxRecvDataSegmentLength should be %d to %d\n", param_set[V_MAXRDSL][val_min], param_set[V_MAXRDSL][val_max]);
						free(line);
						goto  free_buff;
					}
				} else if (!strcmp(str, "PingTimeout")) {
					if (val >= param_set[V_PINGTMO][val_min] && val <= param_set[V_PINGTMO][val_max])
						linfo->conn_attr.ping_tmo = val;
					else {
						csio_printf("PingTimeout should be %d to %d\n", param_set[V_PINGTMO][val_min], param_set[V_PINGTMO][val_max]);
						free(line);
						goto  free_buff;
					}
				} else if (!strcmp(str, "AbortTimeout")) {
					linfo->abort_timeout = val;
				} else if (!strcmp(str, "LurTimeout")) {
					linfo->lur_timeout = val;
 				}
				param++;
				break;
			} else {
				free(line);
				goto  free_buff;
			}
				break;
			
			default:
				pch = strtok (line, " \t,.\r\n");
				while(NULL != pch) {
					pch1 = strchr(pch,'#');
					if (pch1 != NULL)
						break;
					free(line);
					goto  free_buff;
				}
				break;
		}
	}
	free(line);
	return 0;

free_buff:
	for(i = 0; i <= buf_last_line; i++) {
		free(file_buf[i]);
	}
	return -1;
}


int foiscsi_get_obj_count(adap_handle_t hw, int obj_type, int dbindex)
{
	struct foiscsi_count *cnt = NULL;
	unsigned int cmd, count = 0;
	char *buf = NULL;
	int len, rc = 0;

	len = os_agnostic_buffer_len(sizeof(struct foiscsi_count));
	cmd = CSIO_STOR_FOISCSI_OPCODE(CSIO_FOISCSI_GET_COUNT_IOCTL);
	buf = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	csio_init_header(buf, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);

	cnt = (struct foiscsi_count *)get_payload(buf);

	cnt->type = obj_type;
	cnt->inode_idx = dbindex;

	rc = issue_ioctl(hw, buf, len);
	if (rc) {
		goto out;
	}

	cnt = (struct foiscsi_count *)get_payload(buf);
	count = cnt->count;

out:
	ioctl_buffer_free(buf);

	return count;
	

}

int foiscsi_assign_instance(adap_handle_t hw,int dbindex,
		char *nodename, char *alias,
		char *ini_user, char *ini_sec)
{

	struct foiscsi_instance *ini_inst = NULL;
	void *buf = NULL;
	unsigned int cmd = CSIO_STOR_FOISCSI_OPCODE(CSIO_FOISCSI_ASSIGN_INSTANCE_IOCTL);
	int len = os_agnostic_buffer_len(sizeof(struct foiscsi_instance));
	int rc = 0;
	int ini_chap = 0;
	int ini_passlen = 0;

	buf = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (!buf)
		return FOISCSI_ERR_OOM;

	csio_init_header(buf, cmd, CSIO_IOCTL_SIGNATURE, len,
			 CSIO_IOCD_WRITE);

	ini_inst = (struct foiscsi_instance *)get_payload(buf);

	if (!nodename) {
		fprintf(stderr, "Invalid nodename length\n");
		ioctl_buffer_free(buf);
		rc = FOISCSI_ERR_INVALID_INST_NAME;
		goto out;
	}
	if ((ini_user && !ini_sec) || (!ini_user && ini_sec)) {
		fprintf(stderr, "Initiator chap details missing\n");
		rc = -1;
		goto out;
	} else if (ini_user && ini_sec){
		memcpy(ini_inst->chap_id, ini_user, strlen(ini_user));
		memcpy(ini_inst->chap_sec, ini_sec, strlen(ini_sec));
	} else {
		ini_chap = 1;
	}

	memcpy(ini_inst->name, nodename, strlen(nodename));

	if (alias)
		memcpy(ini_inst->alias, alias, strlen(alias));

	csio_os_read_init_inst_param(ini_inst, ini_chap);

	csio_printf("login_retry_cnt [%u], recovery_timeout [%u]\n",
			ini_inst->login_retry_cnt, ini_inst->recovery_timeout);

	ini_passlen = strlen(ini_inst->chap_sec);
	if (ini_passlen) {
		if (ini_passlen < 12 || ini_passlen > 128) {
			csio_printf("\nInitiator secret should be 12-128 characters long\n\n");
			rc = -1;
			goto out;
		}
	}

	ini_inst->id = dbindex;

	rc = issue_ioctl(hw, buf, len);

	ini_inst = (struct foiscsi_instance *)get_payload(buf);

	if (rc)
		goto out;

	csio_printf("\nInstance %s successfully assigned at index %d \n\n",
			ini_inst->name, ini_inst->id);
out:
	rc = ini_inst->retval;	
	ioctl_buffer_free(buf);
	return rc;
}

int foiscsi_clear_instance(adap_handle_t hw, int dbindex)
{
	struct foiscsi_instance *ini_inst = NULL;
	void *buf = NULL;
	unsigned int cmd = CSIO_STOR_FOISCSI_OPCODE(CSIO_FOISCSI_CLEAR_INSTANCE_IOCTL);
	int len = os_agnostic_buffer_len(sizeof(struct foiscsi_instance));
	int rc = 0;

	buf = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (!buf)
		return FOISCSI_ERR_OOM;

	csio_init_header(buf, cmd, CSIO_IOCTL_SIGNATURE, len,
			 CSIO_IOCD_WRITE);

	ini_inst = (struct foiscsi_instance *)get_payload(buf);

	ini_inst->id = dbindex;

	rc = issue_ioctl(hw, buf, len);

	ini_inst = (struct foiscsi_instance *)get_payload(buf);

	if (rc)
		goto out;

	csio_printf("\nInstance at index %d cleared successfully\n\n",
			ini_inst->id);
out:
	rc = ini_inst->retval;	
	ioctl_buffer_free(buf);
	return rc;
}

int foiscsi_show_instance (adap_handle_t hw, int idx, struct foiscsi_instance *um_inst)
{
	struct foiscsi_instance *ini_inst = NULL;
	void *buf = NULL;
	unsigned int cmd = CSIO_STOR_FOISCSI_OPCODE(CSIO_FOISCSI_SHOW_INSTANCE_IOCTL);
	int len = os_agnostic_buffer_len(sizeof(struct foiscsi_instance));
	int rc = 0, count = 0, i, dbindex = -1;
	

	if (idx == 0 || idx > FW_FOISCSI_INIT_NODE_MAX) {
		rc = FOISCSI_ERR_INVALID_INDEX;
		goto out;
	} else {
		dbindex = idx;
	}

	count = foiscsi_get_obj_count(hw, FOISCSI_INSTANCE_COUNT, dbindex);

	if (!count) {
		return FOISCSI_ERR_ZERO_OBJ_FOUND;
		
	}

	len = os_agnostic_buffer_len(
			sizeof(struct foiscsi_instance) * count);

	buf = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (!buf) {
		rc = FOISCSI_ERR_OOM;
		goto out;
	}

	csio_init_header(buf, cmd, CSIO_IOCTL_SIGNATURE, len,
			CSIO_IOCD_RW);

	ini_inst = (struct foiscsi_instance *)get_payload(buf);

	ini_inst->id = dbindex;

	rc = issue_ioctl(hw, buf, len);
	if (rc)
		goto out;

	ini_inst = (struct foiscsi_instance *)get_payload(buf);

	if(!um_inst) {
		for (i = 0; i < count; i++) {
			csio_printf("Node Id: [%d]\n\tNodename: [%s]\n\tAlias: [%s] \
					\n\tInitiator User Name: [%s]\n\tInitiator Chap Secret: [%s] \n",
					(ini_inst + i)->id, (ini_inst + i)->name, (ini_inst + i)->alias,
					(ini_inst + i)->chap_id, (ini_inst + i)->chap_sec);
		}
	} else {
		memcpy(um_inst, ini_inst, sizeof(struct foiscsi_instance) * count);
	}

out:
	ioctl_buffer_free(buf);

	return rc;
}
int foiscsi_manage_instance(adap_handle_t hw, int op,
		int dbindex, char *nodename, char *alias,
		char *ini_user, char *ini_sec)
{
	unsigned int rc = 0;

	if ((dbindex <= 0 ||
		dbindex > (FW_FOISCSI_INIT_NODE_MAX)) && op != OP_SHOW) {
		csio_printf("Invalid idx %d. idx should be ( > 0 and <= %d)\n",
				dbindex, FW_FOISCSI_INIT_NODE_MAX);
		rc = FOISCSI_ERR_INVALID_INDEX;
		goto out;
	}

	if (op == OP_ASSIGN) {
		if(nodename == NULL) {
			fprintf(stderr, "required parameter missing\n\n");
			rc = -1;
			goto out;
		}
		rc = foiscsi_assign_instance(hw, dbindex, nodename, alias,
				ini_user, ini_sec);
	}
	if (op == OP_CLEAR)
		rc = foiscsi_clear_instance(hw, dbindex);
	if (op == OP_SHOW)
		rc = foiscsi_show_instance(hw, dbindex, NULL);

out:
	return rc;
}

static int
foiscsi_session_login(adap_handle_t hw, int dbindex,
		char *sip, char *targetname, char *dip,
		int tcp_port, char *auth_method, char *policy,
		char *tgt_user, char *tgt_sec, int persistent,
		unsigned int vlanid)
{
	struct foiscsi_login_info *linfo = NULL;
	unsigned int saddr = 0, daddr = 0, retry_cnt = 0;
	void *buf = NULL;
	int len = os_agnostic_buffer_len(sizeof(struct foiscsi_login_info));
	int rc = 0, method = -1, tgt_passlen = 0, mutual_chap = 0;
	/* GLUE CHANGE */
	unsigned int cmd = CSIO_STOR_FOISCSI_OPCODE(CSIO_FOISCSI_LOGIN_TO_TARGET);
	int ip_type;
	int8_t saddr6[16], daddr6[16];

	if (!targetname) {
		csio_printf("Invalid target name\n");
		return -EINVAL;
	}

	if (!sip || !dip) {
		csio_printf("Invalid ip\n");
		return -EINVAL;
	}

	if (dbindex < 0 || dbindex > FW_FOISCSI_INIT_NODE_MAX) {
		csio_printf("Invalid Instance index\n");
		return FOISCSI_ERR_INVALID_INDEX;
	}

	buf = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buf == NULL) {
		return FOISCSI_ERR_OOM;
	}

	if (strchr(sip, ':')) {
		ip_type = TYPE_IPV6;
		if (csio_ipv6_pton(sip, saddr6) != 1) {
			csio_printf("Invalid ipv6 address %s\n", sip);
			return -EINVAL;
		}
		if (csio_ipv6_pton(dip, daddr6) != 1) {
			csio_printf("Invalid ipv6 address %s\n", dip);
			return -EINVAL;
		}
	} else {
		ip_type = TYPE_IPV4;
		saddr = convert_dotted_ip(sip);
		daddr = convert_dotted_ip(dip);
	}

retry:
	memset(buf, 0, len);
	csio_init_header(buf, cmd, CSIO_IOCTL_SIGNATURE, len,
			CSIO_IOCD_RW);

	linfo = (struct foiscsi_login_info *)get_payload(buf);
	
	memset(&linfo->sess_attr, 0, sizeof(linfo->sess_attr));
	memset(&linfo->conn_attr, 0, sizeof(linfo->conn_attr));

	linfo->op = OP_LOGIN;
	linfo->ip_type = ip_type;
	if (ip_type == TYPE_IPV4) {
		linfo->tgt_ip.ip4 = daddr;
		linfo->src_ip.ip4 = saddr;
	} else {
		memcpy(linfo->tgt_ip.ip6, daddr6, 16);
		memcpy(linfo->src_ip.ip6, saddr6, 16);
	}
	linfo->tgt_port = tcp_port;
	linfo->sess_attr.sess_type_to_erl |=
		V_FW_FOISCSI_CTRL_WR_SESS_TYPE(FW_FOISCSI_SESSION_TYPE_NORMAL);
	linfo->inode_id = dbindex;
	linfo->persistent = persistent;
	memcpy(linfo->tgt_name, targetname, strlen(targetname));

	if (auth_method) {
		if (!policy) {
			csio_printf("\nPlease specify Auth Policy\n");
			ioctl_buffer_free(buf);
			rc = -1;
			goto out;
		}

		if (strcmp(auth_method, "CHAP") && strcmp (auth_method, "None")
				&& strcmp(auth_method, "CHAP,None")
				&& strcmp(auth_method, "None,CHAP"))  {
			csio_printf("\nAuthMethod should be CHAP OR None\n");
			rc = -1;
			ioctl_buffer_free(buf);
			goto  out;
		}

		if (!strcmp(auth_method, "CHAP"))
			method = FW_FOISCSI_AUTH_METHOD_CHAP;
		else if (!strcmp(auth_method, "None"))
			method = FW_FOISCSI_AUTH_METHOD_NONE;
		else if (!strcmp(auth_method, "CHAP,None"))
			method = FW_FOISCSI_AUTH_METHOD_CHAP_FST;
		else if (!strcmp(auth_method, "None,CHAP"))
			method = FW_FOISCSI_AUTH_METHOD_CHAP_SEC;
		else {
			csio_printf("\nPlease specify a valid Auth Method\n");
			ioctl_buffer_free(buf);
			return -1;
		}


		if (method >= 0)
			linfo->conn_attr.hdigest_to_ddp_pgsz |=
				V_FW_FOISCSI_CTRL_WR_AUTH_METHOD(method);

		if (!strcmp(policy, "Mutual")) {
			linfo->conn_attr.hdigest_to_ddp_pgsz |=
				V_FW_FOISCSI_CTRL_WR_AUTH_POLICY
				(FW_FOISCSI_AUTH_POLICY_MUTUAL);
			mutual_chap = 1;
		} else if (!strcmp(policy, "Oneway"))
			linfo->conn_attr.hdigest_to_ddp_pgsz |=
				V_FW_FOISCSI_CTRL_WR_AUTH_POLICY
				(FW_FOISCSI_AUTH_POLICY_ONEWAY);
		else {
			csio_printf("\nPlease specify a valid Auth Policy\n");
			ioctl_buffer_free(buf);
			return -1;

		}

		if ((!tgt_user || !tgt_sec) && mutual_chap) {
			csio_printf("\nTarget chap details missing\n");
			ioctl_buffer_free(buf);
			rc = -1;
			goto out;
		} else if (tgt_user && tgt_sec){
			memcpy(linfo->tgt_id, tgt_user, strlen(tgt_user));
			memcpy(linfo->tgt_sec, tgt_sec, strlen(tgt_sec));
			tgt_passlen = strlen(linfo->tgt_sec);
			if (tgt_passlen) {
				if (tgt_passlen < 12 || tgt_passlen > 128) {
					csio_printf("\nTarget secret should be 12-128 characters long\n\n");
					ioctl_buffer_free(buf);
					rc = -1;
					goto out;
				}
			}
		}

	} else if (policy || tgt_user || tgt_sec) {
		csio_printf("\nPlease specify a valid Auth Method\n");
		ioctl_buffer_free(buf);
		return -1;
	}

	if(csio_os_read_iscsi_param(linfo, method)) {
		csio_printf("Error reading configuration parameters\n");
		ioctl_buffer_free(buf);
		return -1;
	}

	if (!linfo->login_retry_cnt)
		linfo->login_retry_cnt = 10;

	rc = issue_ioctl(hw, buf, len);

	linfo = (struct foiscsi_login_info *)get_payload(buf);

	if (linfo->status == FOISCSI_ERR_LOGIN_TIMEDOUT) {
		retry_cnt++;
		/*csio_printf("Login failed : status [0x%x], retry [0x%x]\n",
				linfo->status, retry_cnt);*/
		if (retry_cnt < linfo->login_retry_cnt) {
			sleep(1);
			goto retry;
		}
	}

	if(rc) {
		csio_printf("iSCSI login failed.\n");
		goto out;
	}

	csio_printf("\nSession id [%d] logged in to target %s\n",
			linfo->sess_idx, linfo->tgt_name);

out:
	return rc;
}

static int
foiscsi_session_logout(adap_handle_t hw, int op, int dbindex, int sid)
{
	struct foiscsi_logout_info *linfo;
	void *buf = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(struct foiscsi_logout_info));
	int rc = 0;
	/* GLUE CHANGE */
	uint32_t cmd = CSIO_STOR_FOISCSI_OPCODE(CSIO_FOISCSI_LOGOUT_FROM_TARGET);

	if (dbindex < 0 || dbindex == 0 || 
			dbindex > FW_FOISCSI_INIT_NODE_MAX || sid == 0)
		return FOISCSI_ERR_INVALID_INDEX;

	buf = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buf == NULL) {
		csio_printf("Insufficient resources..!\n");
		return FOISCSI_ERR_OOM;
	}

	csio_init_header(buf, cmd, CSIO_IOCTL_SIGNATURE, len,
			CSIO_IOCD_RW);

	linfo = (struct foiscsi_logout_info *)get_payload(buf);

	linfo->op = OP_LOGOUT;
	linfo->inode_id = dbindex;
	linfo->sess_id = sid;

	rc = issue_ioctl(hw, buf, len);

	linfo = (struct foiscsi_logout_info *)get_payload(buf);

	if(rc) {
		if ((rc == FOISCSI_ERR_INVALID_REQUEST) && sid < 0) {
			csio_printf("Inactive sessions exist on node [%d]\n",
					linfo->inode_id);
			rc = 0;
		} else {
			csio_printf("logout command failed\n");
		}
		goto out;
	}

	if (sid < 0)
		csio_printf("Logged out of all sessions of Node [%d]\n",
				linfo->inode_id);
	else
		csio_printf("Logged out:Node [%d] Session [%d]\n",
				linfo->inode_id, linfo->sess_id);

out:
	return rc;
}

static int
foiscsi_session_show(adap_handle_t hw, int op, int dbindex, int sid, struct foiscsi_sess_info *um_sess)
{
	struct foiscsi_sess_info *sess_info = NULL;
	unsigned int cmd, count = 0;
	char *buf = NULL;
	int len, rc = 0, i = 0, j = 1;
	char init_ip[64], targ_ip[64];
	int show_all = 0;	

	if (dbindex == 0 || dbindex > FW_FOISCSI_INIT_NODE_MAX
			|| sid == 0)
		return FOISCSI_ERR_INVALID_INDEX;

	if (dbindex < 0) {
		show_all = 1;
		sid = 0;
		//return FOISCSI_ERR_INVALID_INDEX;
	}

	do {
		if (show_all)
			dbindex = j;

		count = foiscsi_get_obj_count(hw, FOISCSI_SESSION_COUNT, dbindex);

		if (!count && !show_all)
			return FOISCSI_ERR_ZERO_OBJ_FOUND;

		if (!count && show_all)
			goto loop_inc;

		len = os_agnostic_buffer_len(
				sizeof(struct foiscsi_sess_info) * count);
		cmd = CSIO_STOR_FOISCSI_OPCODE(CSIO_FOISCSI_SESSION_INFO_IOCTL);
		buf = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
		csio_init_header(buf, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);

		sess_info = (struct foiscsi_sess_info *)get_payload(buf);

		sess_info->inode_idx = dbindex;
		sess_info->sess_idx = sid;

		rc = issue_ioctl(hw, buf, len);

		if (rc) {
			ioctl_buffer_free(buf);
			return rc;
		}

		sess_info = (struct foiscsi_sess_info *)get_payload(buf);

		if(!um_sess) {
			csio_printf("Initiator Id: %d\n", dbindex);
			for (i = 0; i < count; i++) {
				if (sess_info->ip_type == TYPE_IPV4) {
					convert_decimal_ip(init_ip,
						sess_info->init_ip.ip4);
					convert_decimal_ip(targ_ip,
						sess_info->targ_ip.ip4);
				} else {
					csio_ipv6_ntop(
						sess_info->init_ip.ip6,
						init_ip, 64);
                                	csio_ipv6_ntop(
						sess_info->targ_ip.ip6,
						targ_ip, 64);
				}

				csio_printf("\tSession id: [%u]\n\tSession State: %s\n\tInitiator portal: [%s]\n\tTarget Name: %s\n\tTarget portal: [%s:%u] \n",
						sess_info->sess_idx, (sess_info->state)?"ACTIVE":"INACTIVE", init_ip, sess_info->targ_name,
						targ_ip, sess_info->targ_port);
				fprintf(stderr, "\n------------------------------------------------------------------------------------\n");
			
				if (sid > 0)
					break;

				sess_info++;
			}
		} else {
			memcpy(um_sess, sess_info, sizeof(struct foiscsi_sess_info)* count);
			um_sess += count;
		}

		ioctl_buffer_free(buf);
		if (!show_all)
			break;

loop_inc:
		j++;	
	} while (j <= FW_FOISCSI_INIT_NODE_MAX); 

	return rc;
}

int foiscsi_manage_session(adap_handle_t hw, int op, int dbindex,
		char *sip, char *targetname, char *dip, int tcp_port,
		int sid, char *auth_method, char *policy,
		char *tgt_user, char *tgt_sec, int persistent,
		unsigned int vlanid)
{
	int rc = 0;
	if (op == OP_LOGIN)
		rc = foiscsi_session_login(hw, dbindex, sip, targetname, dip,
				tcp_port, auth_method, policy, tgt_user,
				tgt_sec, persistent, vlanid);

	if (op == OP_LOGOUT)
		rc = foiscsi_session_logout(hw, op, dbindex, sid);

	if (op == OP_SHOW)
		rc = foiscsi_session_show(hw, op, dbindex, sid, NULL);

	return rc;	
}

int foiscsi_do_discovery(adap_handle_t hw, int op, int dbindex,
		char *sip, char *dip, int tcp_port,
		unsigned int vlanid,
		struct foiscsi_login_info *um_linfo)
{
	struct foiscsi_login_info *linfo = NULL;
	unsigned int saddr = 0, daddr = 0, retry_cnt = 0;;
	void *buf = NULL;
	char *disc_buf=NULL, *buf1=NULL, *pch=NULL;
	uint32_t i=0,len1=0;
	uint32_t buf_len = ISCSI_SEND_TARGETS_BUF_LEN;
	int len = os_agnostic_buffer_len(sizeof(struct foiscsi_login_info) +
			buf_len);
	/* GLUE CHANGE */
	uint32_t cmd = CSIO_STOR_FOISCSI_OPCODE(CSIO_FOISCSI_DISC_TARGS);
	int rc = 0, method = -1;
	int ip_type;
	int8_t saddr6[16], daddr6[16];

	if (!sip || !dip) {
		csio_printf("Invalid ip\n");
		return -EINVAL;
	}

	if (dbindex < 0 || dbindex > FW_FOISCSI_INIT_NODE_MAX)
		return FOISCSI_ERR_INVALID_INDEX;

	buf = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buf == NULL) {
		return FOISCSI_ERR_OOM;
	}

	if (strchr(sip, ':')) {
		ip_type = TYPE_IPV6;
		if (csio_ipv6_pton(sip, saddr6) != 1) {
			csio_printf("Invalid ipv6 address %s\n", sip);
			return -EINVAL;
		}
		if (csio_ipv6_pton(dip, daddr6) != 1) {
			csio_printf("Invalid ipv6 address %s\n", dip);
			return -EINVAL;
		}
	} else {
		ip_type = TYPE_IPV4;
		saddr = convert_dotted_ip(sip);
		daddr = convert_dotted_ip(dip);
	}
retry:
	memset(buf, 0, len);
	csio_init_header(buf, cmd, CSIO_IOCTL_SIGNATURE, len,
			CSIO_IOCD_RW);

	linfo = (struct foiscsi_login_info *)get_payload(buf);
	linfo->op = OP_LOGIN;
	linfo->ip_type = ip_type;
	linfo->vlanid = vlanid;
	if (ip_type == TYPE_IPV4) {
		linfo->tgt_ip.ip4 = daddr;
		linfo->src_ip.ip4 = saddr;
	} else {
		memcpy(linfo->tgt_ip.ip6, daddr6, 16);
		memcpy(linfo->src_ip.ip6, saddr6, 16);

	}
	linfo->tgt_port = tcp_port;
	strncpy((char *)linfo->tgt_name, "Discovery", 9);
	linfo->sess_attr.sess_type_to_erl |=
		V_FW_FOISCSI_CTRL_WR_SESS_TYPE(FW_FOISCSI_SESSION_TYPE_DISCOVERY);
	linfo->inode_id = dbindex;
	linfo->disc_buf = (buf + (sizeof(struct foiscsi_login_info)));

	if(csio_os_read_iscsi_param(linfo, method)) {
		csio_printf("Error reading configuration parameters\n");
		ioctl_buffer_free(buf);
		return -1;
	}

	if (!linfo->login_retry_cnt)
		linfo->login_retry_cnt = 10;

	rc = issue_ioctl(hw, buf, len);

	if (linfo->status == FOISCSI_ERR_LOGIN_TIMEDOUT) {
		retry_cnt++;
		/*csio_printf("Discovery failed : status [0x%x], retry [0x%x]\n",
				linfo->status, retry_cnt);*/
		if (retry_cnt < linfo->login_retry_cnt) {
			sleep(1);
			goto retry;
		}
	}
	
	if(rc) {
		csio_printf("Discovery failed.\n");
		goto out;
	}

	disc_buf = (char *)get_payload(buf) + 
			sizeof(struct foiscsi_login_info);

	if(!um_linfo) {
		while(i < linfo->buf_len) {
			buf1 = &disc_buf[i];
			pch = strstr(buf1,"TargetName");
			if(pch)
				csio_printf("\n\n%s\n",buf1);
			else
				csio_printf("%s\n",buf1);
			len1 = (uint32_t)(strlen(buf1) + 1);
			i+=len1;
		}
		csio_printf("\n");
	} else {
		um_linfo->disc_buf = malloc(linfo->buf_len);
		um_linfo->buf_len = linfo->buf_len;
		memcpy(um_linfo->disc_buf, disc_buf, linfo->buf_len);
	}
out:
	ioctl_buffer_free(buf);
	return rc;
}

int um_foiscsi_get_count(adap_handle_t hw, struct foiscsi_count *obj_count)
{
/*
        FOISCSI_INSTANCE_COUNT,
        FOISCSI_SESSION_COUNT,
        FOISCSI_IFACE_COUNT,
*/
	int rc = 0;

        rc = foiscsi_get_obj_count(hw, obj_count->type, obj_count->inode_idx);
	if(!rc)
		rc = FOISCSI_ERR_ZERO_OBJ_FOUND;
	else {
		obj_count->count = rc;
		rc = 0;
	}

	return rc;
}

int um_foiscsi_manage_instance(adap_handle_t hw, struct foiscsi_instance *ini_inst)
{
        unsigned int rc = 0;

	if(!ini_inst)
		return FOISCSI_ERR_INVALID_REQUEST;

        if ((ini_inst->id <= 0 ||
                ini_inst->id > (FW_FOISCSI_INIT_NODE_MAX)) && ini_inst->op != OP_SHOW) {
                csio_printf("Invalid idx %d. idx should be ( > 0 and <= %d)\n",
                                ini_inst->id, FW_FOISCSI_INIT_NODE_MAX);
                rc = FOISCSI_ERR_INVALID_INDEX;
                goto out;
        }

        if (ini_inst->op == OP_ASSIGN) {
                if(ini_inst->name == NULL) {
                        fprintf(stderr, "required parameter missing\n\n");
                        rc = -1;
                        goto out;
                }
                rc = foiscsi_assign_instance(hw, ini_inst->id, ini_inst->name, ini_inst->alias,
                                ini_inst->chap_id, ini_inst->chap_sec);
        }
        if (ini_inst->op == OP_CLEAR)
                rc = foiscsi_clear_instance(hw, ini_inst->id);
        if (ini_inst->op == OP_SHOW)
                rc = foiscsi_show_instance(hw, ini_inst->id, ini_inst);

out:
        return rc;

}

int um_foiscsi_manage_session(int hw, int op, char *auth_method, char *policy, void *sess_buf)
{
        int rc = 0;

        if(!sess_buf)
                return FOISCSI_ERR_INVALID_REQUEST;

        if (op == OP_LOGIN) {
		struct foiscsi_login_info *linfo = sess_buf;
	        char init_ip[16], targ_ip[16];

		/* TODO Handle ipv6 case */
        	convert_decimal_ip(init_ip, linfo->src_ip.ip4);
        	convert_decimal_ip(targ_ip, linfo->tgt_ip.ip4);

                rc = foiscsi_session_login(hw, linfo->inode_id, init_ip, (char *)linfo->tgt_name, targ_ip,
                                linfo->tgt_port, auth_method, policy, linfo->tgt_id,
                                linfo->tgt_sec, linfo->persistent,
				linfo->vlanid);
	}

        if (op == OP_LOGOUT) {
		struct foiscsi_logout_info *linfo = sess_buf;
                rc = foiscsi_session_logout(hw, op, linfo->inode_id, linfo->sess_id);
	}

        if (op == OP_SHOW) {
		struct foiscsi_sess_info *sess_info = sess_buf;
                rc = foiscsi_session_show(hw, op, sess_info->inode_idx, sess_info->sess_idx, (struct foiscsi_sess_info *)sess_buf);
	}

        return rc;
}

int um_foiscsi_do_discovery(int hw, struct foiscsi_login_info *um_disc) 
{
	char init_ip[16], targ_ip[16];

	if(!um_disc)
		return FOISCSI_ERR_INVALID_REQUEST;

	convert_decimal_ip(init_ip, um_disc->src_ip.ip4);
	convert_decimal_ip(targ_ip, um_disc->tgt_ip.ip4);

	return foiscsi_do_discovery(hw, OP_LOGIN, um_disc->inode_id, init_ip, targ_ip, um_disc->tgt_port, um_disc->vlanid, um_disc);
}

void csio_show_instances(adap_handle_t hw, int all)
{
	iscsi_ops.os_show_inst(all);
}

#if 0
int edit_instance(adap_handle_t hw,
		  int id, 
		  int oper,
		  char *name,
		  char *alias,
		  char *uname,
		  char *pwd)
{
	void *buffer = NULL;
	struct iscsi_inst *payload = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(struct iscsi_inst));
	int status = 0;
	uint32_t cmd = CSIO_STOR_ISCSI_OPCODE(CSIO_ISCSI_EDIT_INSTANCE);
	
	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len,
			 CSIO_IOCD_WRITE);

	payload = (struct iscsi_inst *)get_payload(buffer);

	if(DEL == oper) {
		memset(payload, 0, sizeof(struct iscsi_inst));
	} else {
		memcpy(payload->name, name, FW_FOISCSI_NAME_MAX_LEN);
		memcpy(payload->alias, alias, FW_FOISCSI_NAME_MAX_LEN);
		if(uname)
			memcpy(payload->uname, uname, FW_FOISCSI_NAME_MAX_LEN);

		if(pwd)
			memcpy(payload->pwd, pwd, FW_FOISCSI_NAME_MAX_LEN);
	}
	payload->id = id;

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status != 0) {
		csio_printf("ioctl failed with status %u\n",status);
		ioctl_buffer_free(buffer);
		return status;
	} else {
		if(ADD == oper)
			csio_printf("iscsi instance created successfully\n");
		else if (MOD == oper)
			csio_printf("iscsi instance modified successfully\n");
		else
			csio_printf("iscsi instance deleted successfully\n");
			
	}

	ioctl_buffer_free(buffer);

	return status;
} /* set_iscsi_name */
#endif

#if 0
void csio_edit_instance(adap_handle_t hw,
			char *adap_name, 
			int oper,
			int id,
			char *name,
			char *alias,
			char *auth,
			char *uname,
			char *pwd)
{
	int idx = 0;
	
	if((id > MAX_INITIATOR_INSTANCES -1) || (id < 0)) {
		csio_printf("invalid index\n");
		return;
	}

	if(DEL != oper) {

		if (!name || !alias) {
			csio_printf("invalid parameter\n");
			return;
		}

		if (strncmp(name, "iqn.", 4)) {
			csio_printf("invalid iscsi name format\n");
			return;
		}
			
		if (auth) {
			if(strcmp(auth, "chap")) {
				csio_printf("invalid authentication method\n");
				return;
			}

			if(!strcmp(auth, "chap")) {
				if(!uname || !pwd) {
					csio_printf("invalid parameter\n");
					return;
				}
			}
		} else {
			if(uname || pwd) {
				csio_printf("invalid parameter\n");
				return;
			}
		}
	}

	/* os_edit_inst returns new idx or the same id for modification.
	 * id will not be valid for creation.
	 */
	idx = iscsi_ops.os_edit_inst(adap_name, oper, id, name, alias, auth, uname, pwd);
	/* send an ioctl to the driver, to update the driver database */
	if(-1 != idx) {
		edit_instance(hw, idx, oper, name, alias, uname, pwd);
	}
}
#endif

void convert_decimal_ip(char ip[], uint32_t ipaddr)
{
	sprintf(ip,"%d.%d.%d.%d", 
	(ipaddr>>24)&0xFF, 
	(ipaddr>>16)&0xFF, 
	(ipaddr>>8)&0xFF, 
	ipaddr&0xFF);
}

int validate_ip(char *str, int len)
{
	int noOfDots = 0;
	int count = 0;
	unsigned char prv = '.';

	while (len--) {
		if (*str == '.') {
			if (prv == '.')
				return -1;
			count = 0;
			noOfDots++;
			prv = *str;
			str++;
			continue;
		}
		if ((*str >= '0') && (*str <= '9')) {
			count = (count * 10) + (*str - '0');
			if (count > 255)
				return -1;
			prv = *str;
			str++;
			continue;
		}
		//
		// IP address cannot contain character other than dot and numerals
		//
		return -1;
	}
	//
	// IP address must contain 3 dots and last character cannot be dot
	//
	if ((noOfDots != 3) || (prv == '.'))
		return -1;
	return 0;
}
int validate_ip_class(uint32_t ipadr)
{
    uint32_t class_id = 0;

    class_id = ipadr & 0xF0000000;
    class_id >>= 28;

    //NO broadcast, No Class D(leading bits 1110)(host ip cant be multicast addr) 
    //and No Class E(leading bits 1111)(reserved set of addresses)

    if((0xF == class_id) 
       || (0xE == class_id)
       || (0xFFFFFFFF == ipadr))
        return -1;

    return 0;
}

int validate_netmask(uint32_t mask)
{
	uint32_t dword = (~mask) + 1;

	/* for a valid netmask, 2s compliment be a power of 2*/
	if(dword && !(dword & (dword-1))) {
		/* The condition checks if the 2s compliment
		 * is not 0 and is a power of 2.
		 */

		/* 253(11111101) is invalid.(because of 1 after 0) 
		* if 254, then 0 and 1 would be 
		* reserved hostids leaving behind 
		* 0 hostids which is invalid.
		* So, lsbyte has to be <= 252
		*/
		if((mask & 0xFF) <= 0xFC)
			return 0;
		else
			return -1;
	} else {
		return -1;
	}
	
}

#if 0
int csio_show_sess_info(adap_handle_t hw)
{
	void *buffer = NULL;
	struct num_target *num_targ = NULL;
	struct sess_info *sinfo = NULL;
	size_t len;
	int i, num_reg_target = 0, status = 0;
	uint32_t cmd;
	char ip[16];

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	len = os_agnostic_buffer_len(sizeof(struct num_target));
	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	cmd = CSIO_STOR_FOISCSI_OPCODE(CSIO_ISCSI_GET_NUM_TARGET);

	if (buffer == NULL) {
		csio_printf("Insufficient resources..!\n");

		return -1;
	}        

	/*  Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len,
			CSIO_IOCD_RW);

	num_targ = (struct num_target *)get_payload(buffer);

	/*  Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);
	num_reg_target = num_targ->num_reg_target;
	if(0 == num_reg_target) {
		csio_printf("No active sessions.\n");
		ioctl_buffer_free(buffer);
		return status;
	}       
	ioctl_buffer_free(buffer);

	len = os_agnostic_buffer_len(sizeof(struct sess_info) * num_reg_target);
	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	cmd = CSIO_STOR_FOISCSI_OPCODE(CSIO_ISCSI_GET_SESS_INFO);

	if (buffer == NULL) {
		csio_printf("Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len,
			CSIO_IOCD_RW);

	sinfo = (struct sess_info *)get_payload(buffer);

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);
	csio_printf("Port\tSession-handle\tInitiator-name(ip)\tTarget-name(ip:port)\n");
	for(i=0; i<num_reg_target; i++) {
		convert_decimal_ip(ip, sinfo->init_ip);
		csio_printf("%u\t%u\t\t%s(%s)",sinfo->port,
				sinfo->shdl,
				sinfo->init_name,
				ip);

		convert_decimal_ip(ip, sinfo->targ_ip);
		csio_printf("\t%s(%s:%u)\n",sinfo->targ_name,
				ip,
				sinfo->targ_port);
		sinfo++;
	}
	ioctl_buffer_free(buffer);

	if (status != 0)
		csio_printf("Failed to issue ioctl\n");

	return status;
}
#endif
#if 0
int target_discover(adap_handle_t hw, 
		uint32_t dip,
		uint16_t dport,
		int vlan,
		uint32_t ip)
{
	return status;
}

int csio_discover_targets(adap_handle_t hw,
			   char *discip,
			   int dport,
			   int vlan,
			   char *hostip)
{
	return 0;
}

int target_login(adap_handle_t hw, 
		 char *name,	
		 uint32_t tgt_ip,
		 uint16_t tgt_port,
		 uint32_t hostip,
		 char *initname,
		 char *initalias,
		 int vlan,
		 uint8_t  persistent)
{
	return status;
}
#endif
int csio_del_target(adap_handle_t hw,
		    char *tgt_name,
		    char *tgt_ip,
		    int tgt_port)
{
	uint32_t tip = 0;
	void *buffer = NULL;
	struct targ_del *del;
	size_t len = os_agnostic_buffer_len(sizeof(struct targ_del));
	int status = 0;
	uint32_t cmd = CSIO_OS_OPCODE(CSIO_OS_ISCSI_DEL_TARGET);

	//TODO: validate the iqn
	if(!tgt_name || !tgt_ip || !tgt_port) {
		csio_printf("invalid parameter\n");
		return -1;
	}

	if(tgt_ip) {
		tip = convert_dotted_ip(tgt_ip);
		if(validate_ip(tgt_ip, (int)strlen(tgt_ip)) < 0 || 
			validate_ip_class(tip) < 0) {
			csio_printf("invalid target ip\n");
			return -1;
		}
	}

	if (hw == (adap_handle_t)-1) {
		CSIO_ASSERT(FALSE);
		return -1;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);

	if (buffer == NULL) {
		csio_printf("Insufficient resources..!\n");

		return -1;
	}

	/* Initialize common ioctl header. */
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len,
			 CSIO_IOCD_WRITE);

	del = (struct targ_del *)get_payload(buffer);
	memcpy(del->name, tgt_name, FW_FOISCSI_NAME_MAX_LEN);
	del->ip.ip4 = tip;
	del->port = (uint16_t)tgt_port;

	/* Issue the IOCTL. */
	status = issue_ioctl(hw, buffer, len);

	if (status != 0) {
		csio_printf("Failed to issue ioctl1\n");
		ioctl_buffer_free(buffer);
		return -1;
	}

	ioctl_buffer_free(buffer);

	return status;

}

#if 0
int csio_login_to_target(adap_handle_t hw,
			 char *adapname,
			 char *tgt_name,
			 char *tgt_ip,
			 int tgt_port,
			 char *hostip,
			 char *initname,
			 char *initalias,
			 int vlan,
			 int persistent)
{
	return 0;
}

int target_logout(adap_handle_t hw, 
		  uint32_t sess_hdl
		  )
{
	return status;
}

int csio_logout_from_target(adap_handle_t hw, uint32_t sess_hdl)
{
	if(target_logout(hw, sess_hdl) < 0)
		return -1;

	csio_printf("Logged out from session %d\n", sess_hdl);
	return 0;

}
#endif
