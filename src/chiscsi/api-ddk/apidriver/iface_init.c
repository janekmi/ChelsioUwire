/***************************************************************
 * iface_init.c - initialize interface driver
 *	-Register/Deregister iSCSI Target class
 *	-Register/Deregister iSCSI Target Lun class
 *	-Initialize the LUNs
 *	-Add/remove iSCSI target and target parameters
 *	-initialize a thread per lun for handling scsi command
 *
 *	-Various iSCSI parameters can be set in following key=value format
 *	 Refer user guide for complete parameter list
 *		For example:
 *		PortalGroup=1@203.0.113.144:3260
 *		MaxRecvDataSegmentLength=8192
 *	        HeaderDigest=None,CRC32C
 *	       	DataDigest=None,CRC32C
 *       	ImmediateData=Yes
 *	        InitialR2T=No
 *       	MaxOutstandingR2T=1
 *	        MaxConnections=4
 *		......
 ***************************************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include "iface.h"
#include "storage_kthread.h"

MODULE_LICENSE("GPL");

/*Module Parameters to configure the target*/
/*char    *target_name = "iqn.2004-05.com.chelsio.iscsi-sw4";
char    *init_name = "iqn.1991-05.com.microsoft:buzz1";
char    *tgt_name = "TargetName=iqn.2004-05.com.chelsio.iscsi-sw4";
*/
 
char    *target_name = "iqn.2004-05.com.chelsio.iscsi-sw3";
char    *init_name = "iqn.1994-05.com.iscsi-sw3:openinitiator";
char    *tgt_name = "TargetName=iqn.2004-05.com.chelsio.iscsi-sw4";

#ifdef __REDIRECTION_TEST__
//char    *shadow_mode = "ShadowMode=Yes";
char    *shadow_mode = "ShadowMode=No";
char    *portal = "PortalGroup=1@102.50.50.22:3260,[2]";
char    *redirection_portal= "PortalGroup=2@102.50.50.22:3961";
#else
char    *portal = "PortalGroup=1@102.50.50.22:3260";
//char    *portal = "PortalGroup=1@102.50.50.20:3260";
#endif

#ifdef __RECONFIG_TEST__
char    *acl_enable = "ACL_Enable=Yes";
char    *acl = "ACL=iname=iqn.1994-05.com.iscsi-sw3:openinitiator;sip=102.50.50.22;dip=102.50.50.22";
#endif

char    *config_buffer;
char    *lun_sizes_mb = "2048";
char    *immediate = "ImmediateData=No";
char    *initialr2t = "InitialR2T=Yes";

#ifdef __CHAP_TEST__
char *auth_method = "AuthMethod=CHAP";
char *auth_policy = "Auth_CHAP_Policy=Mutual";
char *auth_chap_initiator = "Auth_CHAP_Initiator=\"initiator_id1\":\"initiator_sec1\"";
char *auth_chap_target = "Auth_CHAP_Target=\"target_id1\":\"target_secret1\"";
#endif

/* Global variables */
extern		chiscsi_target_lun_class lun_class_storage;
extern		chiscsi_target_class tclass_apitest;
struct 		luninfo lun[MAX_LUNS];
int		num_luns = 0;
void 		*page_addr;
void            *addr;
extern struct tcp_endpoint      ep;

#ifdef __REDIRECTION_TEST__
extern struct tcp_endpoint      redirect_ep;
#endif


/*initialize the queue */
void init_queue(chiscsi_queue *q)
{
	q->q_lock = q + 1;  
	spin_lock_init((spinlock_t *)q->q_lock);      
       	q->q_cnt = 0; 
       	q->q_head = NULL; 
       	q->q_tail = NULL; 
}

/* using chiscsi's generic queue structure */
chiscsi_queue *alloc_queue(void) 
{
	unsigned int size = sizeof(spinlock_t) + sizeof(chiscsi_queue);
	chiscsi_queue *q = kmalloc(size, GFP_KERNEL);
	memset(q, 0, size);

	/*initialize the queue */
        if (q)  
		init_queue(q);
	
	return q;
}

int construct_config_buffer(void)
{
        int len = 0;

        /* setup config buffer for node add */
        config_buffer = kmalloc(MAX_CONFIG_BUFLEN, GFP_KERNEL);
        memset(config_buffer, 0, MAX_CONFIG_BUFLEN);

        /* TargetName */
        len += sprintf(config_buffer, "%s", tgt_name);
        config_buffer[len++] = '\0';

#ifdef __REDIRECTION_TEST__
        /* Portal */
        len += sprintf(config_buffer + len, "%s", shadow_mode);
        config_buffer[len++] = '\0';

        /* PortalGroup */
        len += sprintf(config_buffer + len, "%s", portal);
        config_buffer[len++] = '\0';

        /* redirection */
        len += sprintf(config_buffer + len, "%s", redirection_portal);
        config_buffer[len++] = '\0';
#else
        /* PortalGroup */
        len += sprintf(config_buffer + len, "%s", portal);
        config_buffer[len++] = '\0';
#endif

        /* InitialR2T */
        len += sprintf(config_buffer + len, "%s", initialr2t);
        config_buffer[len++] = '\0';

        /* ImmeddiateData */
        len += sprintf(config_buffer + len, "%s", immediate);
        config_buffer[len++] = '\0';

#ifdef __CHAP_TEST__
        /* Chap */
        len += sprintf(config_buffer + len, "%s", auth_method);
        config_buffer[len++] = '\0';

        len += sprintf(config_buffer + len, "%s", auth_policy);
        config_buffer[len++] = '\0';

        len += sprintf(config_buffer + len, "%s",  auth_chap_initiator);
        config_buffer[len++] = '\0';

        len += sprintf(config_buffer + len, "%s", auth_chap_target);
        config_buffer[len++] = '\0';
#endif

        return len;
}

#ifdef __RECONFIG_TEST__
int construct_reconfig_buffer(void)
{
         int len = 0;

        /* setup config buffer for node add */
        config_buffer = kmalloc(MAX_CONFIG_BUFLEN, GFP_KERNEL);
        memset(config_buffer, 0, MAX_CONFIG_BUFLEN);

        /* TargetName */
        len += sprintf(config_buffer, "%s", tgt_name);
        config_buffer[len++] = '\0';

        /* PortalGroup */
        len += sprintf(config_buffer + len, "%s", portal);
        config_buffer[len++] = '\0';

        /* InitialR2T */
        len += sprintf(config_buffer + len, "%s", initialr2t);
        config_buffer[len++] = '\0';

        /* ImmeddiateData */
        len += sprintf(config_buffer + len, "%s", immediate);
        config_buffer[len++] = '\0';

        /* ACL_Enable */
        len += sprintf(config_buffer + len, "%s", acl_enable);
        config_buffer[len++] = '\0';

        /* ACL Rule*/
        len += sprintf(config_buffer + len, "%s", acl);
        config_buffer[len++] = '\0';

        return len;
}
#endif


/* initilize the luninfo array */
int init_all_luns(chiscsi_target_lun_class *lun_class_storage)
{
	char *ch, *c;
	int i = 0;
	chiscsi_queue *q;

	ch = c = lun_sizes_mb;
	while (*ch) {
		while (*ch && (*ch != ','))
			ch++;
		if (*ch) {
			*ch = 0; 
			ch++;
		}

		lun[i].size = (simple_strtoul(c, NULL, 10) << 20);
		lun[i].lun = i; 
		lun[i].sect_shift = SECT_SIZE_SHIFT;
        	lun[i].lclass = lun_class_storage;
		lun[i].flags = 0;

		q = alloc_queue();

		if (!q)
			return -ENOMEM;

		lun[i].scinfoq[0] = q;
		lun[i].kthinfo = NULL;

		c = ch;
		i++;
		if (i >= MAX_LUNS) {
                        printk(KERN_INFO "max. # luns %d already reached.\n", MAX_LUNS);
                        break;
                }

	}
	num_luns = i + 1;

	return 0;
}

static int __init storagedriver_init(void)
{
	int rv = 0;
	int i;
	int buf_len = 0;
        char temp_portal[50];

#ifdef __REDIRECTION_TEST__
        int sh_mode;

        char temp_shmode[20]; 
        char temp_redirect_portal[50];
#endif
        /* save Portal for decoding purpose */
        memset(temp_portal, 0, 50);
        strncpy(temp_portal, portal, strlen(portal)+1);

#ifdef __REDIRECTION_TEST__
        /* save shadow mode for decoding purpose */
        memset(temp_shmode, 0, 20);
        strncpy(temp_shmode, shadow_mode, strlen(shadow_mode)+1);

        /* Save Temp Redirect portal String */
        memset(temp_redirect_portal, 0, 50);
        strncpy(temp_redirect_portal, redirection_portal, strlen(redirection_portal)+1);
#endif

        buf_len = construct_config_buffer();
        if (buf_len < 0)
                return -EINVAL;

        /*register the targetclass and start a target*/
        rv  = chiscsi_target_class_register(&tclass_apitest);
        if (rv < 0) {
                printk("Unable to register Target Class %s \n",
                                tclass_apitest.class_name);
                return -EINVAL;
        }

        /*Add a lun class to target class*/
        rv = chiscsi_target_lun_class_register(&lun_class_storage,
                                               tclass_apitest.class_name);
        if (rv < 0) {
                printk("Unable to register LUN class %s\n",
                                lun_class_storage.class_name);
                goto out;
        }
        printk("LUN class %s, added to %s.\n", lun_class_storage.class_name,
                tclass_apitest.class_name);

        /*setup luns associated with the lun class*/
        rv  = init_all_luns(&lun_class_storage);
        if (rv < 0) {
                printk("Unable to setup LUNs %s\n",
                                lun_class_storage.class_name);
                goto out;
        }

        /*initialize and start the threads for each lun*/
        for (i = 0; i < num_luns; i++) {
                init_and_run_storage_thread(i);
        }

        /* Add target */
        rv = chiscsi_target_add(NULL, target_name, tclass_apitest.class_name,
                                config_buffer, buf_len);
        if (rv < 0) {
                printk("Unable to add target %s to target class %s\n",
                                target_name, tclass_apitest.class_name);
                goto out;
        }

	/* allocate a page so that we can make it avaialble in multiphase*/
        page_addr = alloc_page(GFP_KERNEL);
        if (!page_addr) {
                printk("Failed to allocate page \n");
                return -ENOMEM;
        }
        printk("page addr 0x%p\n", page_addr);

        addr = kmalloc(ALLOC_SIZE, GFP_KERNEL);
        if (!addr) {
                printk("Failed to allocate memory \n");
                return -ENOMEM;
        }
        printk("addr 0x%p\n", addr);

#ifdef __REDIRECTION_TEST__ 
        /* check for ShadowMode for redirection */
        sh_mode = decode_shadow_mode(temp_shmode);
        rv = sh_mode;

        if (rv < 0) {
                printk("unable to decode shadow_mode, default will be NO.\n");
                rv = 0;
        }

        printk("Shadow Mode is set to %d\n", sh_mode);

        /* extract and save portal info */
        rv = decode_portal (temp_portal, &ep);
        if (rv < 0 ) {
                printk("unable to save portal information for target %s\n", target_name);
                rv = 0;
        } else {
                printk ("Portal information for IP ");
                tcp_endpoint_print(&ep);
                printk (" saved.\n");
        }

        rv = decode_portal (temp_redirect_portal, &redirect_ep);
        if (rv < 0) {
                printk("unable to save portal information for target %s\n", target_name);
                rv = 0;
        } else {
                printk ("Portal information for Redirect IP ");
                tcp_endpoint_print(&redirect_ep);
                printk (" saved.\n");
        }
#else
        /* extract and save portal info */
        rv = decode_portal (temp_portal, &ep);
        if (rv < 0 ) {
                printk("unable to save portal information for target %s\n", target_name);
                rv = 0;
        } else {
                printk ("Portal information for IP ");
                tcp_endpoint_print(&ep);
                printk (" saved.\n");
        }
#endif

#ifdef __RECONFIG_TEST__
        /* Test for reconfig API call */
        buf_len = construct_reconfig_buffer();
        if (buf_len >  0) {
                rv = chiscsi_target_reconfig(NULL, target_name, tclass_apitest.class_name,
                                        config_buffer, buf_len);
                if (rv < 0) {
                        printk( "target_reconfig_failed.. no need to fail driver start.\n");
                        rv = 0;
                }
        }
#endif

        printk(KERN_ALERT "Chelsio storage driver 2.0 loaded.\n");
        return rv;

out:
        /* deregister and remove node */
        chiscsi_target_lun_class_deregister(lun_class_storage.class_name,
                                tclass_apitest.class_name);
        chiscsi_target_remove(NULL, target_name);
        chiscsi_target_class_deregister(tclass_apitest.class_name);
        return rv;

}

static void __exit storagedriver_exit(void)
{
	int i;
        //int rv=0;

        /*free the page */
        if (page_addr)
                __free_page(page_addr);

        if (addr)
                kfree(addr);

#if 0
        /* test for Target Info API */ 
        rv = get_target_info (target_name);
        if (rv < 0)
                printk("get_target_information returned %d\n", rv);

        /* test for Perf Info API */
        rv = get_target_perf_info(&ep);
        if (rv < 0)
                printk("target_get_performance returned %d.\n", rv);
#endif

        /*Stop all the threads*/
        for (i = 0; i < num_luns; i++) {
                if (lun[i].kthinfo)
                        stop_storage_thread(lun[i].kthinfo);
        }

        /*Deregister LUN class*/
        chiscsi_target_lun_class_deregister(lun_class_storage.class_name,
                                tclass_apitest.class_name);

        /*remove target and deregister targetclass*/
        chiscsi_target_remove(NULL, target_name);
        chiscsi_target_class_deregister(tclass_apitest.class_name);

        printk(KERN_ALERT "Chelsio storage driver 2.0 unloaded.\n");
}

module_init(storagedriver_init);
module_exit(storagedriver_exit);
