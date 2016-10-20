//#include <linux/version.h>
#include "iface.h"

/* Global Variable */
struct tcp_endpoint ep;
struct tcp_endpoint redirect_ep;

/* utilty functions for the Ifacedriver*/
int addr_is_ipv6 (char *str)
{
        int count=0;
        char *ipv6_addr;

        for (ipv6_addr = str; *ipv6_addr; ipv6_addr++) {
                if (*ipv6_addr == ':')
                        count++;
                else if (*ipv6_addr == ']' || *ipv6_addr == ',')
                        break;
        }
        return (count ? count-1 : count);
}

int convert_portal_to_ipv4(char *str, unsigned int *ip)
{
        int i = 0;
        unsigned int val[4], ipv4_addr = 0;
        char   *ipstr;
        int found_char = 0;

	/* make sure the ip str is in xxx.xxx.xxx.xxx format */
        for (ipstr = str; *ipstr; ipstr++) {
                if (*ipstr == '.')
                        i++;
                else if (!api_isdigit(*ipstr) && (*ipstr != ','))
                        found_char++;
        }

        if ((i != 3) || found_char) {
                printk("ERR! %s: invalid IP address format.\n", str);
                return -EINVAL;
        }

        val[0] = simple_strtoul (str, NULL, 0);
        ipstr = str;
        i = 1;

        while ((ipstr = api_strchr(ipstr, '.')) && *(++ipstr) != '\0') {
                val[i] = simple_strtoul(ipstr, NULL, 0);
                i++;
        }

        /* set ip addr in little-endian order */
        for (i = 0; i < 4; i++)
                ipv4_addr |= val[i] << (i * 8);

        if (!ipv4_addr) {
                printk("ERR! %s: all zero IP address.\n", str);
                return -EINVAL;
        }

        /* convert ip addr to host order */
        *ip = le32_to_cpu(ipv4_addr);

        return 0;
}

int convert_portal_to_ipv6(char *str, unsigned int *ip, int ipv6_expand)
{
        int i = 0, j = 0;
        unsigned int val[16];
        char *ipstr;
        int found_char = 0;

        ipstr=str;
        ipv6_expand = 7 - ipv6_expand;

        /* ip str must be in xxxx:xx..xx:xxxx, [xxxx:x...x:xxxx]:xxxx or xxxx::xxxx format */
        for (ipstr = str; *ipstr; ipstr++) {
                if (*ipstr == ':')
                        if (!j) i++;
                        else    j++;
                else if (!api_isxdigit(*ipstr) &&
                         (*ipstr != ',') &&
                         (*ipstr != '[') &&
                         (*ipstr != ']'))
                        found_char++;
                if (*ipstr == ']')
                        j = 1;
        }

        if (i > 7 || j > 2 || found_char) {
                printk ("ERR! %s : invalid IPv6 address format.\n", str);
                return -EINVAL;
        }

        ipstr = str;
        i = 0;
        j = 1;
        if (*ipstr == '[')
                ipstr++;
        if (*ipstr == ':') {    /* for loopback */
                val[i] = val[i+1] = 0;
                i += 2;
        }

        for (; *ipstr && *ipstr != ']'; ipstr++) {
                if (j) {
                        val[i] = simple_strtoul(ipstr, NULL, 16);
                        val[i+1] = val[i] & 0xFF;
                        val[i] = val[i] >> 8;
                        i += 2;
                        j = 0;
                }
                if (*ipstr == ':') {
                        if (*(ipstr+1) == ':') {
                                while (ipv6_expand--) {
                                        val[i] = val[i+1] = 0;
                                        i += 2;
                                }
                                ipstr++;
                        }
                        j=1;
                }
       }

       for (i = 0; i < 4; i++)
                for (j = 0; j < 4; j++) {
                        ip[i] |= val[i * 4 + j] << (j * 8);
                }

        if (!(ip[0] | ip[1] | ip[2] | ip[3])) {
                printk ("ERR! %s: all zero IP address.\n", str);
                return -EINVAL;
        }

        for (i = 0; i < 4; i++)
                ip[i] = le32_to_cpu(ip[i]);

        return 0;
}


/* portal input will be in format of ProtalGroup=1@xxx.xxx.xxx.xxx:3260 */
int decode_portal (char *portal, tcp_endpoint *ep)
{
        char *ch, *tch;
	char *tmpstr, *tportal;
        unsigned int tag;
        int is_ipv6 = 0;

        if(!(*portal) ) {
                printk("ERR!! empty portal input %s.\n", portal);
                return -EINVAL;
        }

        tportal = portal;
        tmpstr = api_strchr(tportal, '=');
        if (tmpstr) {
                if( tmpstr == tportal) {
                        printk("ERR!! Portal %s shoud not be empty.\n",portal);
                        return -EINVAL;
                }
        }

//      printk("portal %s tmpstr %s\n", portal, tmpstr );
        tmpstr++;
        ch = tmpstr;
        tag = simple_strtoul(tmpstr, &ch, 10 );
//      printk("tag %u tmpstr %s ch %s \n", tag, tmpstr, ch);
        tmpstr++;

	/* No need to parse redirection tag, so terminate it before [ */
	tch = tmpstr;
	while (*tch && (*tch != '['))
		tch++;
	
	if (*tch == '[')
		*tch = 0;

        ch = tmpstr;
        ch++;

//      printk("portal %s tag %u tmpstr %s ch %s\n", portal, tag, tmpstr, ch);  

        while (*ch) {
                char *ip_str, *port_str = NULL;
                unsigned int ip[4];
                unsigned int port = ISCSI_PORT_DEFAULT;
                int rv;

                memset (ip, 0, 4 * sizeof(unsigned int));

                /* find IP from string */
                ip_str = ch;
                while (*ch && ((*ch != ':') && (*ch != ',')))
                        ch++;
                if (*ch == ':') {
                        *ch = 0;
                        ch++;
                        port_str = ch;
               }

                //printk("tmpstr %s ip_str %s\n", tmpstr, ip_str);

                is_ipv6 = addr_is_ipv6(ip_str);

                if (!is_ipv6)
                        rv = convert_portal_to_ipv4 (ip_str, &ip[3]);
                else
                        rv = convert_portal_to_ipv6 (ip_str, ip, is_ipv6);

                if (rv < 0)
                        return rv;

		//printk("ip_str %s, port_str %s \n", ip_str, port_str);

                if (port_str) {
                        port = (unsigned int) simple_strtoul(ch, &ch, 0);
                        if(*ch)
                                ch++;
                }

                /* copy ip and port address into global varaible */
		memcpy (ep->ip, ip, ISCSI_IPADDR_LEN);
                ep->port = port;
        }

        return 0;
}

int decode_shadow_mode(char *buffer)
{
        char *temp_buf, *resp_str;

        if (!buffer) {
                printk( "ERR! buffer empty %s\n", buffer);
                return -EINVAL;
        }

        temp_buf = buffer;
        resp_str = api_strchr( temp_buf, '=');

        if (resp_str) {
                if (resp_str == temp_buf) {
                        printk( "ERR! value missing\n");
                        return -EINVAL;
                }
        }

        resp_str++;
        printk( "buffer %s, resp %s\n", buffer, resp_str);

        if (strncmp(resp_str, "Yes", 3) == 0) 
                return 1;
        else
                return 0;
}

int get_target_info(char *tname)
{
        int rv=0;
        struct chiscsi_target_info *target_info = NULL;

        if (!tname) {
                printk( "ERR! target name empty \n" );
                return -EINVAL;
        }

        target_info = kmalloc(sizeof(struct chiscsi_target_info), GFP_KERNEL);

        if (!target_info)
                return -EINVAL;

        rv = chiscsi_get_target_info(tname, target_info);

        if (rv < 0) {
                printk( "ERR! chiscsi_get_target_info returned %d\n", rv );
                if (target_info)
                        kfree (target_info);
                return rv;
        }

        printk( "\tTARGET: %s\n", target_info->name);
	if (target_info->alias[0] != 0)
	        printk( "\tTargetAlias: %s\n", target_info->alias);
        
	
	if( target_info->chap.chap_en == 1) {
		
		printk( "\tAuthMethod=");

		if (target_info->chap.chap_required == 1) 
			printk( "%s\n", "CHAP");
		else
			printk( "%s\n", "None,CHAP");
	
		printk( "\tAuth_CHAP_Policy=%s\n", 
			(target_info->chap.mutual_chap_forced == 1) ? "Mutual": "OneWay");

		printk( "\tAuth_CHAP_ChallengeLength=%u\n", 
			target_info->chap.challenge_length);
	
	} else
		printk( "\tAuthMethod=%s\n", "None" );


        printk( "\tACLEnable=%x\n", target_info->config_keys.acl_en);
        printk( "\tMaxConnections=%x\n", target_info->sess_keys.max_conns);
        printk( "\tInitialR2T=%x\n", target_info->sess_keys.initial_r2t);
        printk( "\tMaxOutstandingR2T=%x\n", target_info->sess_keys.max_r2t);
        printk( "\tImmediateData=%x\n", target_info->sess_keys.immediate_data);
        printk( "\tFirstBurstLength=%u\n", target_info->sess_keys.first_burst);
        printk( "\tMaxBurstLength=%u\n", target_info->sess_keys.max_burst);
        printk( "\tDefaultTime2Wait=%u\n", target_info->sess_keys.time2wait);
        printk( "\tDefaultTime2Retain=%u\n", target_info->sess_keys.time2retain);
        printk( "\tErrorRecoveryLevel=%x\n", target_info->sess_keys.erl);
        printk( "\tTargetSessionMaxCmd=%d\n", target_info->config_keys.sess_max_cmds);
        printk( "\tShadowMode=%x\n", target_info->config_keys.shadow_mode);
        printk( "\tRegisteriSNS=%x\n", target_info->config_keys.isns_register);
        printk( "\tMaxRecvDataSegmentLength=%u\n",
                target_info->conn_keys.max_recv_data_segment);
        printk( "\tMaxTransmitDataSegmentLength=%u\n",
                target_info->conn_keys.max_xmit_data_segment);
        printk( "\tHeaderDigest=%x,%x\n",
                target_info->conn_keys.header_digest[0],
		target_info->conn_keys.header_digest[1]);
        printk( "\tDataDigest=%x,%x\n",
                target_info->conn_keys.data_digest[0],
		target_info->conn_keys.data_digest[1]);
	printk( "\tAuth_Order=%s\n", (target_info->auth_order == 1) ? "CHAP" : "ACL" );
	printk( "\n");

        if (target_info)
                kfree (target_info);
        return rv;
}

int get_target_perf_info (tcp_endpoint *endpoint)
{
       int rv;
       struct chiscsi_perf_info *pdata = NULL;
       pdata = kmalloc (sizeof(struct chiscsi_perf_info), GFP_KERNEL);

        if (!pdata)
                return -EINVAL;

	rv = chiscsi_get_perf_info (endpoint, pdata);

        if (rv ==  0) {
                printk ( "Target Performance Data for " );
                printk ( "Portal: " );
		tcp_endpoint_print (endpoint);
		printk( "\n");

                printk ( "\tRead Bytes -- %lu \n\tWrite bytes -- %lu \n"
                         "\tWrite commands -- %lu \n\tRead commands -- %lu\n",
                         pdata->read_bytes, pdata->write_bytes,
                         pdata->write_cmd_cnt, pdata->read_cmd_cnt );
		printk( "\n");
        } else
                printk ( "ERR!! chiscsi_get_perf_info failed %d\n", rv );

        if (pdata)
                kfree (pdata);

        return rv;
}

void display_one_session (void *sess_info_p)
{
        struct chiscsi_session_info *sess_info = (struct chiscsi_session_info *)sess_info_p;

        printk( "\tsession_info_ptr 0x%p\n", sess_info);
        printk( "\tConnection=%u\n",    sess_info->conn_cnt);
        printk( "\tInitiatorName=%s\n", sess_info->peer_name );
        if (sess_info->peer_alias)
                printk( "\tAlias=%s\n", sess_info->peer_alias );

        printk( "\tISID=0x%02x%02x%02x%02x%02x%02x\n",
                sess_info->isid[0], sess_info->isid[1], sess_info->isid[2],
                sess_info->isid[3], sess_info->isid[4], sess_info->isid[5]);

        printk( "\tSessionType=%x\n", sess_info->type );
        printk( "\tTSIH=0x%x\n", sess_info->tsih );
        printk( "\tCmdSeqNum=0x%x\n", sess_info->cmdsn );
        printk( "\tMaxCmdSeqNum=0x%x\n", sess_info->maxcmdsn );
        printk( "\tExpCmdSeqNum=0x%x\n", sess_info->expcmdsn );
        printk( "\tInitialR2T=%x\n", sess_info->sess_keys.initial_r2t);
        printk( "\tImmediateData=%x\n", sess_info->sess_keys.immediate_data);
        printk( "\tErrorRecoveryLevel=%x\n", sess_info->sess_keys.erl );
        printk( "\tDataPDUInOrder=%x\n",sess_info->sess_keys.data_pdu_in_order);
        printk( "\tDataSeqInOrder=%x\n",sess_info->sess_keys.data_sequence_in_order);
        printk( "\tMaxConnections=%u\n", sess_info->sess_keys.max_conns);
        printk( "\tMaxR2T=%u\n", sess_info->sess_keys.max_r2t);
        printk( "\tFirstBurstLength=%u\n", sess_info->sess_keys.first_burst);
        printk( "\tMaxBurstLength=%u\n", sess_info->sess_keys.max_burst);
        printk( "\tDefaultTime2Wait=%u\n", sess_info->sess_keys.time2wait );
        printk( "\tDefaultTime2Retain%u\n", sess_info->sess_keys.time2retain );
        printk( "\n");
        printk( "\tRead=%lu Bytes\n", sess_info->perf.read_bytes);
        printk( "\tWrite=%lu Bytes \n", sess_info->perf.write_bytes);
        printk( "\tRead Command=%lu\n", sess_info->perf.read_cmd_cnt );
        printk( "\tWrite Command=%lu\n", sess_info->perf.write_cmd_cnt );
        printk( "\n");
}

int display_session_info (int sess_num, char *iname, void *sess_info_p)
{
	int rv = 0, i = 0, j = 0;
        struct chiscsi_session_info *sess_info = (struct chiscsi_session_info *)sess_info_p;
        struct chiscsi_connection_info *conn_info = NULL;
 
        for (j = 0; sess_info && (j < sess_num); j++, sess_info++) {
                if (!iname || !strcmp(iname, sess_info->peer_name)) {
			printk( "\tsession_info_ptr 0x%p\n", sess_info);
                        printk( "\tConnection=%u\n",    sess_info->conn_cnt);
                        printk( "\tInitiatorName=%s\n", sess_info->peer_name );
                        if (sess_info->peer_alias)
				printk( "\tAlias=%s\n", sess_info->peer_alias );
                        printk( "\tISID=0x%02x%02x%02x%02x%02x%02x\n",
				sess_info->isid[0], sess_info->isid[1], sess_info->isid[2],
				sess_info->isid[3], sess_info->isid[4], sess_info->isid[5]); 
			printk( "\tSessionType=%x\n", sess_info->type );
                        printk( "\tTSIH=0x%x\n", sess_info->tsih );
                        printk( "\tCmdSeqNum=0x%x\n", sess_info->cmdsn );
                        printk( "\tMaxCmdSeqNum=0x%x\n", sess_info->maxcmdsn );
                        printk( "\tExpCmdSeqNum=0x%x\n", sess_info->expcmdsn );
                        printk( "\tInitialR2T=%x\n", sess_info->sess_keys.initial_r2t);
                        printk( "\tImmediateData=%x\n", sess_info->sess_keys.immediate_data);
                        printk( "\tErrorRecoveryLevel=%x\n", sess_info->sess_keys.erl );
                        printk( "\tDataPDUInOrder=%x\n",sess_info->sess_keys.data_pdu_in_order);
                        printk( "\tDataSeqInOrder=%x\n",sess_info->sess_keys.data_sequence_in_order);
                        printk( "\tMaxConnections=%u\n", sess_info->sess_keys.max_conns);
                        printk( "\tMaxR2T=%u\n", sess_info->sess_keys.max_r2t);
                        printk( "\tFirstBurstLength=%u\n", sess_info->sess_keys.first_burst);
                        printk( "\tMaxBurstLength=%u\n", sess_info->sess_keys.max_burst);
                        printk( "\tDefaultTime2Wait=%u\n", sess_info->sess_keys.time2wait );
                        printk( "\tDefaultTime2Retain%u\n", sess_info->sess_keys.time2retain );
                        printk( "\n");
                        printk( "\tRead=%lu Bytes\n", sess_info->perf.read_bytes);
                        printk( "\tWrite=%lu Bytes \n", sess_info->perf.write_bytes);
                        printk( "\tRead Command=%lu\n", sess_info->perf.read_cmd_cnt );
                        printk( "\tWrite Command=%lu\n", sess_info->perf.write_cmd_cnt );
                        printk( "\n");

                        if (strcmp(sess_info->peer_name, iname) == 0) {
                                for (i=0; i < sess_info->conn_cnt; i++) {
                                        conn_info = kmalloc( sizeof(struct chiscsi_session_info), GFP_KERNEL);
                                        
                                        memset (conn_info, 0, sizeof(struct chiscsi_session_info));

                                        if (!conn_info) 
                                                return -EINVAL;

                                        rv = chiscsi_get_connection_info(sess_info->hndl, i, conn_info);
                                        if ( rv < 0 ) {
                                               printk( "ERR! chiscsi_get_connection Info for cnt %d returned %d\n",
                                                        i, rv );
                                                break;
                                        }
                                        printk( "\tconn_info_ptr=0x%p\n", conn_info);
                                        printk( "\tCID=0x%x,\n", conn_info->cid);
                                        printk( "\tPortalGroupTag=%u\n", conn_info->conn_keys.portal_group_tag);
					printk( "\t" );
					tcp_endpoint_print (&conn_info->tcp_endpoints.iaddr);
					printk( ", -- " );
					tcp_endpoint_print (&conn_info->tcp_endpoints.taddr);
					printk( "\n" );
                                        printk( "\tExpStatSN=0x%u\n",conn_info->expstatsn);
                                        printk( "\tStatSN=0x%u\n", conn_info->statsn);
                                        printk( "\tMaxRecvDataSegment=%u\n", conn_info->conn_keys.max_recv_data_segment);
                                        printk( "\tMaxXmitDataSegment=%u\n", conn_info->conn_keys.max_xmit_data_segment);
                                        printk( "\tHeaderDigest=%d\n", (int)conn_info->conn_keys.header_digest[0]);
                                        printk( "\tDataDigest=%d\n", (int)conn_info->conn_keys.data_digest[0]);
                                        printk( "\tOffloaded=0x%x\n", conn_info->offloaded);
                        		printk( "\n");
                                }
                        }
                }
        }

        if (conn_info)
                kfree(conn_info);

        return rv;
}

int get_one_session_info(void * s_hndl)
{
	int rv = 0;
	struct chiscsi_session_info *sess_info = NULL;
	
	if (!s_hndl)
		return -EINVAL;
	
	sess_info = kmalloc(sizeof(struct chiscsi_session_info), GFP_KERNEL);

	if (!sess_info)
		return -EINVAL;

	memset (sess_info, 0, sizeof(struct chiscsi_session_info) );

	rv = chiscsi_get_one_session_info (s_hndl, sess_info);
	
	if (rv == 0)
		display_one_session(sess_info);
	else
		printk ("ERR! chiscsi_get_session_info returned %d\n", rv );

        if (sess_info)
                kfree(sess_info);

        return rv;
}
	
int get_session_information (unsigned long s_hndl, char *tname, char *iname )
{
        int rv=0;
        struct chiscsi_session_info *sess_info = NULL;
        int sess_num = 0;

        if (!tname) {
                printk( "ERR! target name empty \n");
                return -EINVAL;
        }               

        sess_num = 10;
        sess_info = kmalloc( sess_num * sizeof(struct chiscsi_session_info), GFP_KERNEL );

        if (!sess_info)
                return -EINVAL;

        memset (sess_info, 0, sess_num * sizeof(struct chiscsi_session_info) );
                
        rv = chiscsi_get_session_info (tname, iname, sess_num, sess_info);

        if (rv == 0)
                rv = display_session_info(sess_num, iname, (void *)sess_info);
        else
                printk( "ERR! chiscsi_get_session_info returned %d\n", rv );

        if (sess_info)
                kfree(sess_info);
        
        return rv;
}
