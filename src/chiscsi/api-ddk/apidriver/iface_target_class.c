/***************************************************************
 * 	iface_lun_class.c
 *	-setup the chiscsi_target_lun_class struct
 *	-Allocate memory and setup chiscsi_sgvec list and 
 *	 populate fields below
 *		sgl->sg_page
 *		sgl->sg_addr
 *		sgl->sg_offset
 *		sgl->sg_length
 *	-populate following fields in chiscsi_scsi_command
 *	        sc->sc_sgl.sgl_vecs
 *       	sc->sc_sgl.sgl_vecs_nr
 *	        sc->sc_sgl.sgl_length
***************************************************************/

#include <common/iscsi_chap.h>
#include "iface.h"

#define TARGET_CLASS_NAME       "API_TEST"

extern char                     *target_name;
extern char                     *init_name;
extern struct   tcp_endpoint    ep;
extern struct   tcp_endpoint    redirect_ep;
extern int                      shadow_mode;

char    *target_alias           = "target_id1";
char    *chap_init_secret       = "initiator_sec1";  /*secret for verifying an initiator, in oneway+mutual*/
char    *chap_target_secret     = "target_secret1";   /*secret for verifying a target, in mutual*/

void testdisk_first_login_check(unsigned long c_hndl, char * iname, char *tname,
				chiscsi_tcp_endpoints *endpoints)
{

	/*Storage driver may want to setup and verify Access Control Lists*/
        chiscsi_tcp_endpoints eps;

        memcpy (eps.iaddr.ip, endpoints->iaddr.ip, ISCSI_IPADDR_LEN);
        eps.iaddr.port = endpoints->iaddr.port;

        memcpy (eps.taddr.ip, endpoints->taddr.ip, ISCSI_IPADDR_LEN);
        eps.taddr.port = endpoints->taddr.port;

        printk("First login: (I) ");
        chiscsi_tcp_endpoints_print(&eps);
        printk(" (T) Check done.\n");

	/*example of initiator error */
#if 0
	if (strcmp(tname, target_name)) {
		chiscsi_target_first_login_check_done(c_hndl, 
				ISCSI_LOGIN_STATUS_CLASS_INITIATOR_ERROR,
				ISCSI_LOGIN_STATUS_DETAIL_TARGET_NOT_FOUND, 0);
	} else 
#endif	
	
	/*Staus class 0 detail 0 - no errors, max_cmd = 0 means default (128) num of 
	  outstnding scsi commands */
	chiscsi_target_first_login_check_done(c_hndl, 0 ,0 ,0);
}

void testdisk_login_stage_check(unsigned long c_hndl, unsigned char login_stage,
				char *iname, char *tname, chiscsi_tcp_endpoints *endpoints)
{
	/*Storage driver may want to add code to setup and verify Access Control Lists*/
	//if (0) {
                chiscsi_tcp_endpoints eps;

                memcpy (eps.iaddr.ip, endpoints->iaddr.ip, ISCSI_IPADDR_LEN);
                eps.iaddr.port = endpoints->iaddr.port;

                memcpy (eps.taddr.ip, endpoints->taddr.ip, ISCSI_IPADDR_LEN);
                eps.taddr.port = endpoints->taddr.port;

                printk("Login Stage: (I) ");
                chiscsi_tcp_endpoints_print(&eps);
                printk(" (T) Check done.\n");
	//}

	/*Staus class 0 detail 0 - no errors */
	chiscsi_target_login_stage_check_done(c_hndl, 0, 0);
}


/* Function to configure CHAP information*/
void testdisk_chap_info_get(char *iname, char *tname, chap_info *chap)
{
	/* chap->remote_name sent by initiator*/
	if (chap->remote_name != NULL) {
		printk("chap->remote_name = %s init_name = %s\n",
				chap->remote_name, init_name);

		/* remote name matches with our init_name */	
		if (!strcmp(chap->remote_name, init_name)) {
			/*set VALID flag*/
			chap->flag |= CHAP_FLAG_REMOTE_SECRET_VALID;
			strncpy(chap->remote_secret, chap_init_secret, strlen(chap_init_secret));
		       	chap->remote_secret_length = strlen(chap->remote_secret);
		} else {
			/*not setting the VALID flag, causes auth failure*/
			printk("No chap information found \n");
		}
	}

	/*For mutual chap*/
	if(chap->local_name != NULL) {
		strncpy(chap->local_name, target_alias, strlen(target_alias));
		chap->flag |= CHAP_FLAG_LOCAL_SECRET_VALID;
		chap->flag |= CHAP_FLAG_LOCAL_NAME_VALID;
		strncpy(chap->local_secret, chap_target_secret, strlen(chap_target_secret));
        	chap->local_secret_length = strlen(chap->local_secret);
		/* ONLY if mutual is forced */
		/* chap->flag |= CHAP_FLAG_MUTUAL_REQUIRED; */
	}

}

unsigned long testdisk_session_added(unsigned long s_hndl, unsigned char isid[6], 
				char *iname, char *tname)
{
        int rv;
        
	printk("\tGet one session info\n");
	rv = get_one_session_info((void *)s_hndl);
	if (rv < 0)
		printk("ERR!! get_one_session_info returned %d\n", rv);

#if 0
        printk("\t Getting Session Information\n\n" );
        rv = get_session_information (s_hndl, tname, iname );
        if (rv < 0) 
                printk("ERR! get_session_info returned %d\n", rv);
        
        printk("\t Getting Target Information\n\n" );
        rv = get_target_info (tname);
        if (rv < 0) 
                printk("ERR! get_target_information returned %d\n", rv);
#endif

	/*Add code if any session information needs to be stored*/
	printk("Session Add: isid 0x%02x%02x%02x%02x%02x%02x \n",
		isid[0], isid[1], isid[2], isid[3], isid[4], isid[5]);

	return 0UL;
}

void testdisk_session_removed(unsigned long s_hndl, char *iname, char *tname)
{
	/*Add code for any session information needs to be removed*/
	printk("iscsi session between Initiator %s --> Target %s is removed\n",
			iname, tname);
}

/* To check whether certain target is discoverable by certain initiator*/
int testdisk_discovery_target_accessible(unsigned long c_hndl, char * iname, char *tname,
	                                chiscsi_tcp_endpoints *endpoints)
{
	/*Storage driver may maintain its own database of access control list*/ 
#if 0
	if (!(strcmp(iname, init_name))) {
		if(!(strcmp(tname, target_name)))
			return 1;
		else {
			printk("Discovery by Initiator %s of Target %s is denied\n",
				iname, tname);
			return 0;
		}
	} else {
		printk("Initiator %s is not allowed to discover target %s \n",
				iname, tname);
		return 0;
	}
#endif
		return 1;
}

int testdisk_select_redirection_portal (char *tname, char *iname,
                                chiscsi_tcp_endpoints *eps)
{
        if (redirect_ep.port) {
	        memcpy (&eps->taddr, &redirect_ep, sizeof(struct tcp_endpoint));
	        printk("Initiator %s has redirection-to portal ", iname);
        	tcp_endpoint_print(&eps->taddr);
	        printk( "\n");
	} else {
		printk ("%s: no matching portal found.\n", iname);
		return -EINVAL;
        }
	
        return 0;
}

chiscsi_target_class tclass_apitest = {
        .class_name = TARGET_CLASS_NAME,
        .property = 0,
        .fp_config_parse_luns = NULL,	/*can be used to parse a lun config*/
        .fp_first_login_check = testdisk_first_login_check,
        .fp_login_stage_check = testdisk_login_stage_check,
        .fp_chap_info_get = testdisk_chap_info_get,
        .fp_session_added = testdisk_session_added,
        .fp_session_removed = testdisk_session_removed,
        .fp_discovery_target_accessible = testdisk_discovery_target_accessible,
	.fp_select_redirection_portal = testdisk_select_redirection_portal
};

