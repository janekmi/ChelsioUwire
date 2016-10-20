/*****************************************************************************/
/* "NetPIPE" -- Network Protocol Independent Performance Evaluator.          */
/* Copyright 1997, 1998 Iowa State University Research Foundation, Inc.      */
/*                                                                           */
/* This program is free software; you can redistribute it and/or modify      */
/* it under the terms of the GNU General Public License as published by      */
/* the Free Software Foundation.  You should have received a copy of the     */
/* GNU General Public License along with this program; if not, write to the  */
/* Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.   */
/*                                                                           */
/*       ibv.c             ---- Infiniband module for OpenFabrics verbs      */
/*                                                                           */
/* Contributions Copyright (c) 2007 Cisco, Inc.                              */
/*****************************************************************************/

#define USE_VOLATILE_RPTR /* needed for polling on last byte of recv buffer */
#include    "netpipe.h"
#include    <stdio.h>
#include    <getopt.h>
#include    <pthread.h>
#include    <stdarg.h>

#define WANT_DEBUG 0

FILE* logfile = NULL;

/* If we're not debugging, make the logprintf() an inline function
   that the compiler will optimize away. */
#if WANT_DEBUG
#define LOGPRINTF(args)                                           \
  do {                                                            \
    va_list arglist;                                              \
    fprintf(logfile, "%s:%d:%s: ", __FILE__, __LINE__, __func__); \
    logprintf args;                                               \
    fprintf(logfile, "\n");                                       \
  } while (0)
#else
#define LOGPRINTF(a)
#endif

/* Pre-release versions of libiberbs do not have ibv_device_list() */
#define HAVE_IBV_DEVICE_LIST 1

/* Header files needed for Infiniband */

#include    <infiniband/verbs.h>

/* Global vars */

static struct ibv_device      *hca;	/* Infiniband Adapter */
static struct ibv_context     *ctx;	/* Context for Connections */
static struct ibv_port_attr    hca_port;/* Attributes of the HCA */
static int                     port_num;/* IB port to use */
static uint16_t                lid;	/* Local ID of Adapter */
static uint16_t                d_lid;	/* Destination ID */
static struct ibv_pd          *pd_hndl;	/* Protection Domain handle */
static int                     num_cqe;	/* # Command Queue Entries */
static int                     act_num_cqe; /* Actual # CQE */
static struct ibv_cq          *s_cq_hndl; /* Send Command Queue */
static struct ibv_cq          *r_cq_hndl; /* Recv Command Queue */
static struct ibv_mr          *s_mr_hndl; /* Send Mem. Region */
static struct ibv_mr          *r_mr_hndl; /* Recv Mem. Region */
static struct ibv_qp_init_attr qp_init_attr; /* Initial QP attributes */
static struct ibv_qp          *qp_hndl;	/* Handle to QP */
static uint32_t                d_qp_num; /* Dest. QP Number */
static struct ibv_qp_attr      qp_attr; /* QP Attribute */
static struct ibv_wc           wc;		/* Work Completion Queue */
static int                     max_wq=50000;	/* max write queue entries */	
static void*                   remote_address;	/* remote address */
static uint32_t                remote_key;	/* Remote Key */
static volatile int            receive_complete; /* initialization variable */
static pthread_t               thread;		/* thread to handle events */

static int initIB(ArgStruct *p);
static void logprintf(const char *format,  ...);

/* Function definitions */

void Init(ArgStruct *p, int* pargc, char*** pargv)
{
   /* Setup Infiniband specific defaults
    */
   p->prot.ib_mtu = IBV_MTU_1024;        /* 1024 Byte MTU                    */
   p->prot.commtype = NP_COMM_RDMAWRITE; /* Use RDMA write communications    */
   p->prot.comptype = NP_COMP_LOCALPOLL; /* Use local polling for completion */
   p->prot.device_and_port = NULL;       /* Use first available port         */
   p->tr = 0;                            /* I am not the transmitter         */
   p->rcv = 1;                           /* I am the receiver                */
}
/* Setup(..) function is simply used to 'setup' the standard features of 
 * the netpipe modules.  tcp,netpipe-related stuff.  This does no actual
 * 'setup' of any InfiniBand stuff, other than passing/storing
 * the parameters from the command line.... the 'initIB' function
 * is called from here though to do IB initialization.
 */
void Setup(ArgStruct *p)
{

 int one = 1;
 int sockfd;
 struct sockaddr_in *lsin1, *lsin2;      /* ptr to sockaddr_in in ArgStruct */
 char *host;
 struct hostent *addr;
 struct protoent *proto;		/* protocol entry */
 int send_size, recv_size, sizeofint = sizeof(int);
 struct sigaction sigact1;
#if WANT_DEBUG
 char logfilename[80];
#endif

 /* Sanity check */
 if( p->prot.commtype == NP_COMM_RDMAWRITE && 
     p->prot.comptype != NP_COMP_LOCALPOLL ) {
   fprintf(stderr, "Error, RDMA Write may only be used with local polling.\n");
   fprintf(stderr, "Try using RDMA Write With Immediate Data with vapi polling\n");	/* vapi polling? */
   fprintf(stderr, "or event completion\n");
   exit(-1);
 }
 
 if( p->prot.commtype != NP_COMM_RDMAWRITE && 
     p->prot.comptype == NP_COMP_LOCALPOLL ) {
   fprintf(stderr, "Error, local polling may only be used with RDMA Write.\n");
   fprintf(stderr, "Try using vapi polling or event completion\n");
   exit(-1);
 }

#if WANT_DEBUG
 /* Open log file */
 sprintf(logfilename, ".iblog%d", 1 - p->tr);
 logfile = fopen(logfilename, "w");
#endif

 host = p->host;                           /* copy ptr to hostname */ 

 lsin1 = &(p->prot.sin1);		  /* setup the socket structure #1 */
 lsin2 = &(p->prot.sin2);		 /* setup socket structure #2 */
					/* more setup stuff */
 bzero((char *) lsin1, sizeof(*lsin1));
 bzero((char *) lsin2, sizeof(*lsin2));
					/* tcp checks */
 if ( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
   printf("NetPIPE: can't open stream socket! errno=%d\n", errno);
   exit(-4);
 }

					/* another tcp check */
 if(!(proto = getprotobyname("tcp"))){
   printf("NetPIPE: protocol 'tcp' unknown!\n");
   exit(555);
 }

 if (p->tr){                                  /* if client i.e., Sender */


   if (atoi(host) > 0) {                   /* Numerical IP address */
     lsin1->sin_family = AF_INET;
     lsin1->sin_addr.s_addr = inet_addr(host);

   } else {
      
     if ((addr = gethostbyname(host)) == NULL){		/* get the hostname */
       printf("NetPIPE: invalid hostname '%s'\n", host);
       exit(-5);
     }

     lsin1->sin_family = addr->h_addrtype;
     bcopy(addr->h_addr, (char*) &(lsin1->sin_addr.s_addr), addr->h_length);
   }

   lsin1->sin_port = htons(p->port);

 } else {                                 /* we are the receiver (server) */

   bzero((char *) lsin1, sizeof(*lsin1));
   lsin1->sin_family      = AF_INET;
   lsin1->sin_addr.s_addr = htonl(INADDR_ANY);
   lsin1->sin_port        = htons(p->port);
  		 
   /* re-use socket, common if netpipe aborts due to busted networks */
   one = 1;
   if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int))) {
       printf("NetPIPE: server: unable to setsockopt -- errno %d\n", errno);
       exit(-7);
   }

   if (bind(sockfd, (struct sockaddr *) lsin1, sizeof(*lsin1)) < 0){
     printf("NetPIPE: server: bind on local address failed! errno=%d\n", errno);
     exit(-6);
   }

 }

 if(p->tr)
   p->commfd = sockfd;
 else
   p->servicefd = sockfd;
/* ********** This is where the IB specific stuff begins ******** */
 

 /* Establish tcp connections */
 /* Connection management for IB is handled over tcp/ip connection */
 establish(p);

 /* Initialize OpenIB -> Mellanox Infiniband */

 if(initIB(p) == -1) {
   CleanUp(p);
   exit(-1);
 }
}   
/* Event Handler:
 * Receives events from the EventThread, and notifies other functions
 * of their arrivals.
 */
void event_handler(struct ibv_cq *cq);


/* EventThread:
 * Continuously polls the Command Queue for events, and registers them with
 * the event_handler(..) function.
 */
void *EventThread(void *unused)
{
  struct ibv_cq *cq;
  void *ev_ctx;

  while (1) {
    if (ibv_get_cq_event(0, &cq, &ev_ctx)) {
      fprintf(stderr, "Failed to get CQ event\n");
      return NULL;
    }
    event_handler(cq);
  }
}
/* Initialize the actual IB device */
int initIB(ArgStruct *p)
{
  int i, j, ret;
  char *tmp;
  int num_devices = 0;
  struct ibv_device **hca_list, **filtered_hca_list;
  struct ibv_device_attr hca_attr;
#if !HAVE_IBV_DEVICE_LIST
  struct dlist *hca_dlist; 
  struct ibv_device* hca_device; 
#endif

  /* Find all the devices on this host */
#if HAVE_IBV_DEVICE_LIST
  hca_list = ibv_get_device_list(&num_devices);
#else
  hca_dlist = ibv_get_devices();
  dlist_start(hca_dlist); 
  dlist_for_each_data(hca_dlist, hca_device, struct ibv_device)
    ++num_devices;
#endif

  /* If we didn't find any, return an error */
  if (0 == num_devices) {
      fprintf(stderr, "Couldn't find any IBV devices\n");
      return -1;
  }
  
#if !HAVE_IBV_DEVICE_LIST
  /* If we have the old version (ibv_get_devices()), convert it to
     the new form */
  hca_list = (struct ibv_device**) malloc(num_devices * 
                                          sizeof(struct ibv_device*));
  if (NULL == hca_list) {
      fprintf(stderr, "%s:%s:%d: malloc failed\n", __FILE__,
              __func__, __LINE__);
      return -1;
  }
  
  i = 0; 
  dlist_start(hca_dlist); 
  dlist_for_each_data(hca_dlist, hca_device, struct ibv_device)
      hca_list[i++] = hca_device;
#endif    

  /* Possible values for p->prot.device_and_port:

     1. <device>:<port> -- use only this device and only this port
     2. <device> -- use the first active port on this device
     3. :<port> -- use only this port, but on any device

     <device> names are matched exactly.
  */

  /* If a device name was specified on the command line, see if we can
     find it */
  tmp = NULL;
  port_num = -1;
  filtered_hca_list = hca_list;
  if (NULL != p->prot.device_and_port) {
      /* If there's a : in the string, then we have a port */
      tmp = strchr(p->prot.device_and_port, ':');
      if (NULL != tmp) {
          *tmp = '\0';
          ++tmp;
          port_num = atoi(tmp);
      }
      LOGPRINTF(("Pre-filter: looking for target device \"%s\", port %d",
                 p->prot.device_and_port, port_num));

      /* If the length of the device string left is >0, then there's a
         device specification */
      if (strlen(p->prot.device_and_port) > 0) {
          int found = 0;

          /* Loop through all the devices and find a matching
             name */
          for (i = 0; i < num_devices; ++i) {
              LOGPRINTF(("Pre-filter: found device: %s",
                         ibv_get_device_name(hca_list[i])));
              if (0 == strcmp(p->prot.device_and_port, 
                              ibv_get_device_name(hca_list[i]))) {
                  LOGPRINTF(("Pre-filter: found target device: %s (%d of %d)",
                             p->prot.device_and_port, i, num_devices));
                  filtered_hca_list = &(hca_list[i]);
                  num_devices = 1;
                  found = 1;
                  break;
              }
          }

          /* If we didn't find it, abort */
          if (!found) {
              fprintf(stderr, "Unable to find device \"%s\", aborting\n",
                      p->prot.device_and_port);
              return -1;
          }
      }
  }

  /* Traverse the filtered HCA list and find a good port */
  for (hca = NULL, i = 0; NULL == hca && i < num_devices; ++i) {

      /* Get a ibv_context from the ibv_device  */
      ctx = ibv_open_device(filtered_hca_list[i]);
      if (!ctx) {
          fprintf(stderr, "Couldn't create IBV context\n");
          return -1;
      } else {
          LOGPRINTF(("Found HCA %s",
                     ibv_get_device_name(filtered_hca_list[i])));
      }
      
      /* Get the device attributes */
      if (0 != ibv_query_device(ctx, &hca_attr)) {
          fprintf(stderr, "Could not get device context for %s, aborting\n",
                  ibv_get_device_name(hca));
          return -1;
      }

      for (j = 1; j <= hca_attr.phys_port_cnt; ++j) {
          /* If a specific port was asked for, *only* look at that port */
          if (port_num >= 0 && port_num != j) {
              continue;
          }
          LOGPRINTF(("Checking %s:%d...", 
                     ibv_get_device_name(filtered_hca_list[i]), j));

          /* Query this port and see if it's active */
          if (0 != ibv_query_port(ctx, j, &hca_port)) {
              fprintf(stderr, "Unable to query port %s:%d, aborting\n",
                      ibv_get_device_name(filtered_hca_list[i]), j);
              return -1;
          }

          /* If this port is active, we have a winner! */
          if (IBV_PORT_ACTIVE == hca_port.state) {
              LOGPRINTF(("%s:%d is ACTIVE", 
                         ibv_get_device_name(filtered_hca_list[i]), j));
              port_num = j;
              hca = filtered_hca_list[i];
              break;
          }
      }

      /* If we found one, we're done */
      if (hca) {
          break;
      }

      /* Otherwise, close the device (ignore any errors) */
      ibv_close_device(ctx);
      ctx = NULL;
  }

  /* If we didn't find a good device/port combo, abort */
  if (NULL == hca) {
      fprintf(stderr, "Could not find an active device and port, aborting\n");
      return -1;
  }

  /* free up the other devices in the event we would have multiple ib
     devices. if this isnt done, the device pointers will still be
     around in space somewhere -> bad */

#if HAVE_IBV_DEVICE_LIST
  ibv_free_device_list(hca_list); 
#endif
  
  /* Get HCA properties */
  
  lid = hca_port.lid;		/* local id, used to ref back to the device */
  LOGPRINTF(("  lid = %d", lid));


  /* Allocate Protection Domain */
	/* need a Protection domain to handle/register memory over the card */
  pd_hndl = ibv_alloc_pd(ctx);	
  if(!pd_hndl) {
    fprintf(stderr, "Error allocating PD\n");
    return -1;
  } else {
    LOGPRINTF(("Allocated Protection Domain"));
  }


  /* Create send completion queue */
  
  num_cqe = 30000; /* Requested number of completion q elements */
  s_cq_hndl = ibv_create_cq(ctx, num_cqe, NULL, NULL, 0);
  if(!s_cq_hndl) {
    fprintf(stderr, "Error creating send CQ\n");
    return -1;
  } else {
    act_num_cqe = s_cq_hndl->cqe;
    LOGPRINTF(("Created Send Completion Queue with %d elements", act_num_cqe));
  }


  /* Create recv completion queue */
  
  num_cqe = 20000; /* Requested number of completion q elements */
  r_cq_hndl = ibv_create_cq(ctx, num_cqe, NULL, NULL, 0);
  if(!r_cq_hndl) {
    fprintf(stderr, "Error creating send CQ\n");
    return -1;
  } else {
    act_num_cqe = r_cq_hndl->cqe;
    LOGPRINTF(("Created Recv Completion Queue with %d elements", act_num_cqe));
  }


  /* Placeholder for MR */
	/* We dont actually setup the Memory Regions here, instead
	 * this is done in the 'MyMalloc(..)' helper function.
	 * You could however, set them up here.
	 */

  /* Create Queue Pair */
    /* To setup a Queue Pair, the following qp initial attributes must be
     * specified and passed to the create_qp(..) function:
     * max send/recv write requests.  (max_recv/send_wr)
     * max scatter/gather entries. (max_recv/send_sge)
     * Command queues to associate the qp with.  (recv/send_cq)
     * Signalling type:  1-> signal all events.  0-> dont, event handler will
     *   deal with this.
     * QP type.  (RC=reliable connection, UC=unreliable.. etc.) defined 
     *   in the verbs header.
     */
  memset(&qp_init_attr, 0, sizeof(struct ibv_qp_init_attr)); 
  qp_init_attr.cap.max_recv_wr    = max_wq; /* Max outstanding WR on RQ      */
  qp_init_attr.cap.max_send_wr    = max_wq; /* Max outstanding WR on SQ      */
  qp_init_attr.cap.max_recv_sge   = 1; /* Max scatter/gather entries on RQ */
  qp_init_attr.cap.max_send_sge   = 1; /* Max scatter/gather entries on SQ */
  qp_init_attr.recv_cq            = r_cq_hndl; /* CQ handle for RQ         */
  qp_init_attr.send_cq            = s_cq_hndl; /* CQ handle for SQ         */
  qp_init_attr.sq_sig_all         = 0; /* Signalling type */
  qp_init_attr.qp_type            = IBV_QPT_RC; /* Transmission type         */

  /* ibv_create_qp( ibv_pd *pd, ibv_qp_init_attr * attr) */  
  qp_hndl = ibv_create_qp(pd_hndl, &qp_init_attr);
  if(!qp_hndl) {
    fprintf(stderr, "Error creating Queue Pair: %s\n", strerror(errno));
    return -1;
  } else {
    LOGPRINTF(("Created Queue Pair"));
  }

    /* Using the tcp connection, exchange necesary data needed to map
     *  the remote memory:
     *  (local: lid, qp_hndl->qp_num ), (remote: d_lid, d_qp_num)
     */

  /* Exchange lid and qp_num with other node */
  
  if( write(p->commfd, &lid, sizeof(lid) ) != sizeof(lid) ) {
    fprintf(stderr, "Failed to send lid over socket\n");
    return -1;
  }
  if( write(p->commfd, &qp_hndl->qp_num, sizeof(qp_hndl->qp_num) ) != sizeof(qp_hndl->qp_num) ) {
    fprintf(stderr, "Failed to send qpnum over socket\n");
    return -1;
  }
  if( read(p->commfd, &d_lid, sizeof(d_lid) ) != sizeof(d_lid) ) {
    fprintf(stderr, "Failed to read lid from socket\n");
    return -1;
  }
  if( read(p->commfd, &d_qp_num, sizeof(d_qp_num) ) != sizeof(d_qp_num) ) {
    fprintf(stderr, "Failed to read qpnum from socket\n");
    return -1;
  }
  
  LOGPRINTF(("Local: lid=%d qp_num=%d Remote: lid=%d qp_num=%d",
             lid, qp_hndl->qp_num, d_lid, d_qp_num));
    /* Further setup must be done to finalize the QP 'connection'.
     * First set the State of the qp to initialization by making a seperate
     * ibv_qp_attr* variable, giving it the initial values, and calling
     * ibv_qp_modify(..) to merge these settings into the QP.
     */
/* NOTE: According to openIB, ib_mthca's QP modify does not set alternate path
 *  fields in QP context, so you'll have to do this manually if necessary
 */

    /* Bring up Queue Pair */
  
  /******* INIT state ******/

  /* qp_attr is seperately allocated per qp/connection */
  qp_attr.qp_state = IBV_QPS_INIT;
  qp_attr.pkey_index = 0;
  qp_attr.port_num = port_num;
  qp_attr.qp_access_flags = IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ;
  /* merge the qp_attributes into the queue pair */
  ret = ibv_modify_qp(qp_hndl, &qp_attr,
		      IBV_QP_STATE              |
		      IBV_QP_PKEY_INDEX         |
		      IBV_QP_PORT               |
		      IBV_QP_ACCESS_FLAGS);
  if(ret) {
    fprintf(stderr, "Error modifying QP to INIT\n");
    return -1;
  }

  LOGPRINTF(("Modified QP to INIT"));

/* To enable the Queue Pair to finally receive data, it must be 
 * put into the 'RTR' (Ready-To-Receive) state.  The Queue Pair will NOT
 * function properly until it has been setup, and manually put through
 * the init and rtr states.
 */
  
  /******* RTR (Ready-To-Receive) state *******/

  qp_attr.qp_state = IBV_QPS_RTR;
  qp_attr.max_dest_rd_atomic = 1;
  qp_attr.dest_qp_num = d_qp_num;
  qp_attr.ah_attr.sl = 0;
  qp_attr.ah_attr.is_global = 0;
  qp_attr.ah_attr.dlid = d_lid;
  qp_attr.ah_attr.static_rate = 0;
  qp_attr.ah_attr.src_path_bits = 0;
  qp_attr.ah_attr.port_num = port_num;
  qp_attr.path_mtu = p->prot.ib_mtu;
  qp_attr.rq_psn = 0;
  qp_attr.pkey_index = 0;
  qp_attr.min_rnr_timer = 5;
  /* merge these settings into the qp */
  ret = ibv_modify_qp(qp_hndl, &qp_attr,
		      IBV_QP_STATE              |
		      IBV_QP_AV                 |
		      IBV_QP_PATH_MTU           |
		      IBV_QP_DEST_QPN           |
		      IBV_QP_RQ_PSN             |
		      IBV_QP_MAX_DEST_RD_ATOMIC |
		      IBV_QP_MIN_RNR_TIMER);

  if(ret) {
    fprintf(stderr, "Error modifying QP to RTR\n");
    return -1;
  }

  LOGPRINTF(("Modified QP to RTR"));

  /* Sync before going to RTS state */
  Sync(p);

  /* In the same manner, 'enable' sending on the queue pair */
  
  /******* RTS (Ready-to-Send) state *******/

  qp_attr.qp_state = IBV_QPS_RTS;
  qp_attr.sq_psn = 0;
  qp_attr.timeout = 31;
  qp_attr.retry_cnt = 1;
  qp_attr.rnr_retry = 1;
  qp_attr.max_rd_atomic = 1;

  ret = ibv_modify_qp(qp_hndl, &qp_attr,
		      IBV_QP_STATE              |
		      IBV_QP_TIMEOUT            |
		      IBV_QP_RETRY_CNT          |
		      IBV_QP_RNR_RETRY          |
		      IBV_QP_SQ_PSN             |
		      IBV_QP_MAX_QP_RD_ATOMIC);

  if(ret) {
    fprintf(stderr, "Error modifying QP to RTS\n");
    return -1;
  }
  
  LOGPRINTF(("Modified QP to RTS"));

  /* If using event completion, request the initial notification */
  /* This spawns a seperate thread to do the event handling and
   * notification.
   * NOTE:  This may have problems in systems with Weak Memory Consistency
   * since there are no mutex(*) calls to preserve coherancy??
   */ 
  if( p->prot.comptype == NP_COMP_EVENT ) {
    if (pthread_create(&thread, NULL, EventThread, NULL)) {
      fprintf(stderr, "Couldn't start event thread\n");
      return -1;
    }
    ibv_req_notify_cq(r_cq_hndl, 0);	/* request completion notification  */
  }					/* for the receive cq.  2nd argument 
					   specifies if ONLY 'solicited'
					   completions will be 'noticed' */
  
 
  return 0; /* if we get here, the connection is setup correctly */
}


/* Deallocate everything properly */
int finalizeIB(ArgStruct *p)
{
  int ret;

  LOGPRINTF(("Finalizing IB stuff"));
    /* NOTE: This implementation only has created one of each type of queue.
     * In other implementations it may be necessary to create arrays of 
     * these queues.  If this is the case, you need to loop and get them all */
  if(qp_hndl) {	    
    LOGPRINTF(("Destroying QP"));
    ret = ibv_destroy_qp(qp_hndl);
    if(ret) {
      fprintf(stderr, "Error destroying Queue Pair\n");
    }
  }

  if(r_cq_hndl) {
    LOGPRINTF(("Destroying Recv CQ"));
    ret = ibv_destroy_cq(r_cq_hndl);
    if(ret) {
      fprintf(stderr, "Error destroying recv CQ\n");
    }
  }

  if(s_cq_hndl) {
    LOGPRINTF(("Destroying Send CQ"));
    ret = ibv_destroy_cq(s_cq_hndl);
    if(ret) {
      fprintf(stderr, "Error destroying send CQ\n");
    }
  }

  /* Check memory registrations just in case user bailed out */
  if(s_mr_hndl) {
    LOGPRINTF(("Deregistering send buffer"));
    ret = ibv_dereg_mr(s_mr_hndl);
    if(ret) {
      fprintf(stderr, "Error deregistering send mr\n");
    }
  }

  if(r_mr_hndl) {
    LOGPRINTF(("Deregistering recv buffer"));
    ret = ibv_dereg_mr(r_mr_hndl);
    if(ret) {
      fprintf(stderr, "Error deregistering recv mr\n");
    }
  }

  if(pd_hndl) {
    LOGPRINTF(("Deallocating PD"));
    ret = ibv_dealloc_pd(pd_hndl);
    if(ret) {
      fprintf(stderr, "Error deallocating PD\n");
    }
  }

  /* Application code should not close HCA, just release handle */

  if(ctx) {
    LOGPRINTF(("Releasing HCA"));
    ret = ibv_close_device(ctx);
    if(ret) {
      fprintf(stderr, "Error releasing HCA\n");
    }
  }

  return 0;
}

void event_handler(struct ibv_cq *cq)
{
  int ret;
 
  while(1) {
     /* int ibv_poll_cq(a,b,c):
      *	    a: command queue to poll
      *	    b: max number of completions to return
      *	    c: array of at least (b) entries of ibv_wc where these
      *		completion events will be returned.
      */
    ret = ibv_poll_cq(cq, 1, &wc);

     if(ret == 0) {
        LOGPRINTF(("Empty completion queue, requesting next notification"));
        ibv_req_notify_cq(r_cq_hndl, 0);  /* ... explained in prev line.. */
        return;
     } else if(ret < 0) {
        fprintf(stderr, "Error in event_handler (polling cq)\n");
        exit(-1);
     } else if(wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "Error in event_handler, on returned work completion "
		"status: %d\n", wc.status);
        exit(-1);
     }
     
     LOGPRINTF(("Retrieved work completion"));

     /* For ping-pong mode at least, this check shouldn't be needed for
      * normal operation, but it will help catch any bugs with multiple
      * sends coming through when we're only expecting one.
      */
     if(receive_complete == 1) {

        while(receive_complete != 0) sched_yield();

     }

     receive_complete = 1;

  }
  
}

/* read the data from the tcp connection */
static int
readFully(int fd, void *obuf, int len)
{
  int bytesLeft = len;
  char *buf = (char *) obuf;
  int bytesRead = 0;

  while (bytesLeft > 0 &&
        (bytesRead = read(fd, (void *) buf, bytesLeft)) > 0)
    {
      bytesLeft -= bytesRead;
      buf += bytesRead;
    }
  if (bytesRead <= 0)
    return bytesRead;
  return len;
}


/* sync up the tcp connection */
void Sync(ArgStruct *p)
{
    char s[] = "SyncMe";
    char response[7];

    if (write(p->commfd, s, strlen(s)) < 0 ||
        readFully(p->commfd, response, strlen(s)) < 0)
      {
        perror("NetPIPE: error writing or reading synchronization string");
        exit(3);
      }
    if (strncmp(s, response, strlen(s)))
      {
        fprintf(stderr, "NetPIPE: Synchronization string incorrect!\n");
        exit(3);
      }
}




void PrepareToReceive(ArgStruct *p)
{
  int                ret;       /* Return code */
  struct ibv_recv_wr rr;        /* Receive request */
  struct ibv_recv_wr *bad_wr;	/* Handle to any incomplete requests */
  struct ibv_sge     sg_entry;  /* Scatter/Gather list - holds buff addr */

  /* We don't need to post a receive if doing RDMA write with local polling */

  if( p->prot.commtype == NP_COMM_RDMAWRITE &&
      p->prot.comptype == NP_COMP_LOCALPOLL )
     return;
  /* setup the receive request, specify which list to use and # entries */
  rr.num_sge = 1;		    /* # of entries in this list */	
  rr.sg_list = &sg_entry;	    /* the list of entries */
  rr.next = NULL;		    /* the next entry (if more than one */

  sg_entry.lkey = r_mr_hndl->lkey;  /* link the entries lkey to our remote mr */
  sg_entry.length = p->bufflen;	    /* provide a buffer length */
  sg_entry.addr = (uintptr_t)p->r_ptr; /* address/context of sg_entry */

  /* technically if we have problems, the return is < 0,
   * but this works as well
   */

  /* if we get a change in bad_wr value, it is because the Receive request
   * couldnt be posted to the command queue for some reason.  
   * (This may be because the queue is full) 
   * You should probably do something with the bad_wr if your request 
   * needs to actuall get posted.
   */
  ret = ibv_post_recv(qp_hndl, &rr, &bad_wr);
  if(ret) {
    fprintf(stderr, "Error posting recv request\n");
    CleanUp(p);
    exit(-1);
  } else {
    LOGPRINTF(("Posted recv request"));
  }

  /* Set receive flag to zero and request event completion 
   * notification for this receive so the event handler will 
   * be triggered when the receive completes.
   */
  if( p->prot.comptype == NP_COMP_EVENT ) {
    receive_complete = 0;
  }
}

/* SendData == Post a 'send' request to the (send)command queue */
void SendData(ArgStruct *p)
{
  int                ret;       /* Return code */
  struct ibv_send_wr sr;        /* Send request */
  struct ibv_send_wr *bad_wr;	/* Handle to any incomplete wr returned by ibv*/
  struct ibv_sge     sg_entry;  /* Scatter/Gather list - holds buff addr */

  /* Fill in send request struct */
    /* Set the send request's opcode based on run-time options */
  if(p->prot.commtype == NP_COMM_SENDRECV) {
     sr.opcode = IBV_WR_SEND;
     LOGPRINTF(("Doing regular send"));
  } else if(p->prot.commtype == NP_COMM_SENDRECV_WITH_IMM) {
     sr.opcode = IBV_WR_SEND_WITH_IMM;
     LOGPRINTF(("Doing regular send with imm"));
  } else if(p->prot.commtype == NP_COMM_RDMAWRITE) {
     sr.opcode = IBV_WR_RDMA_WRITE;	/* if RDMA, need to give more info */
     sr.wr.rdma.remote_addr = (uintptr_t)(((char *)remote_address) + (p->s_ptr - p->s_buff));
     sr.wr.rdma.rkey = remote_key;
     LOGPRINTF(("Doing RDMA write (raddr=%p)", sr.wr.rdma.remote_addr));
  } else if(p->prot.commtype == NP_COMM_RDMAWRITE_WITH_IMM) {
     sr.opcode = IBV_WR_RDMA_WRITE_WITH_IMM;	/* more info if RDMA */
     sr.wr.rdma.remote_addr = (uintptr_t)(((char *)remote_address) + (p->s_ptr - p->s_buff));
     sr.wr.rdma.rkey = remote_key;
     LOGPRINTF(("Doing RDMA write with imm (raddr=%p)", sr.wr.rdma.remote_addr));
  } else {
     fprintf(stderr, "Error, invalid communication type in SendData\n");
     exit(-1);
  }
  
  sr.send_flags = 0;	/* This needed due to a bug in Mellanox HW rel a-0 */

  sr.num_sge = 1;		    /* # entries in this request */
  sr.sg_list = &sg_entry;	    /* the list of other requests */
  sr.next = NULL;		    /* the next request in the list */

  sg_entry.lkey = s_mr_hndl->lkey;  /* Local memory region key */
  sg_entry.length = p->bufflen;	   /* buffer's size */
  sg_entry.addr = (uintptr_t)p->s_ptr;	/* buffer's location */


  
  /* Post the send request to the (send)command queue */

  /* ibv_post_send(...) is handled in same fashion ibv_post_recv(..) */
  ret = ibv_post_send(qp_hndl, &sr, &bad_wr);
  if(ret) {
    fprintf(stderr, "Error posting send request\n");
  } else {
    LOGPRINTF(("Posted send request"));
  }

}

/* Post a receive request to the (receive)command queue */
void RecvData(ArgStruct *p)
{
  int ret;

  /* Busy wait for incoming data */

  LOGPRINTF(("Receiving at buffer address %p", p->r_ptr));

  /*
   * Unsignaled receives are not supported, so we must always poll the
   * CQ, except when using RDMA writes.
   */
  if( p->prot.commtype == NP_COMM_RDMAWRITE ) {
       
    /* Poll for receive completion locally on the receive data */

    LOGPRINTF(("Waiting for last byte of data to arrive"));
     
    while(p->r_ptr[p->bufflen-1] != 'a' + (p->cache ? 1 - p->tr : 1) ) 
    {
       /* BUSY WAIT -- this should be fine since we 
        * declared r_ptr with volatile qualifier */ 
    }

    /* Reset last byte */
    p->r_ptr[p->bufflen-1] = 'a' + (p->cache ? p->tr : 0);

    LOGPRINTF(("Received all of data"));

  } else if( p->prot.comptype != NP_COMP_EVENT ) {
     
     /* Poll for receive completion using poll function */

     LOGPRINTF(("Polling completion queue for work completion"));
     
     ret = 0;
     while(ret == 0)
        ret = ibv_poll_cq(r_cq_hndl, 1, &wc);	/* poll & grab 1 completion */
     /* ret = # of completions polled by the function */

     if(ret < 0) {
        fprintf(stderr, "Error in RecvData, polling for completion\n");
        exit(-1);
     }

     if(wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "Error in status of returned completion: %d\n",
                wc.status);
        exit(-1);
     }

     LOGPRINTF(("Retrieved successful completion"));
     
  } else if( p->prot.comptype == NP_COMP_EVENT ) {

     /* Instead of polling directly on data or the completion queue,
      * let the event completion handler set a flag when the receive
      * completes, and poll on that instead. Could try using semaphore here
      * as well to eliminate busy polling
      */

     LOGPRINTF(("Polling receive flag"));
     
     while( receive_complete == 0 )	/* this is set by the event hanlr */
     {
        /* BUSY WAIT */
     }

     /* If in prepost-burst mode, we won't be calling PrepareToReceive
      * between ping-pongs, so we need to reset the receive_complete
      * flag here.
      */
     if( p->preburst ) receive_complete = 0;

     LOGPRINTF(("Receive completed"));
  }
}

/* Reset is used after a trial to empty the work request queues so we
   have enough room for the next trial to run */
void Reset(ArgStruct *p)
{

  int                ret;       /* Return code */
  struct ibv_send_wr sr;        /* Send request */
  struct ibv_send_wr *bad_sr;	/* handle to your reqeust if it fails */
  struct ibv_recv_wr rr;        /* Recv request */
  struct ibv_recv_wr *bad_rr;  /* handle to your request if it fails */

  /* If comptype is event, then we'll use event handler to detect receive,
   * so initialize receive_complete flag
   */
  if(p->prot.comptype == NP_COMP_EVENT) receive_complete = 0;

  /* Prepost receive */
  rr.num_sge = 0;	/* there are no entries in this request */
  rr.next = NULL;

  LOGPRINTF(("Posting recv request in Reset"));
  ret = ibv_post_recv(qp_hndl, &rr, &bad_rr);
  if(ret) {
    fprintf(stderr, "  Error posting recv request\n");
    CleanUp(p);
    exit(-1);
  }

  /* Make sure both nodes have preposted receives */
  Sync(p);

  /* Post Send */
  sr.opcode = IBV_WR_SEND;
  sr.send_flags = IBV_SEND_SIGNALED;
  sr.num_sge = 0;	    /* no entires in this request */
  sr.next = NULL;

  LOGPRINTF(("Posting send request "));
  ret = ibv_post_send(qp_hndl, &sr, &bad_sr);
  if(ret) {
    fprintf(stderr, "  Error posting send request in Reset\n");
    exit(-1);
  }
  if(wc.status != IBV_WC_SUCCESS) {
     fprintf(stderr, "  Error in completion status: %d\n",
             wc.status);
     exit(-1);
  }

  LOGPRINTF(("Polling for completion of send request"));
  ret = 0;
  while(ret == 0)
    ret = ibv_poll_cq(s_cq_hndl, 1, &wc);   /* grab the request */

  if(ret < 0) {
    fprintf(stderr, "Error polling CQ for send in Reset\n");
    exit(-1);
  }
  if(wc.status != IBV_WC_SUCCESS) {
     fprintf(stderr, "  Error in completion status: %d\n",
             wc.status);
     exit(-1);
  }          
  
  LOGPRINTF(("Status of send completion: %d", wc.status));

  if(p->prot.comptype == NP_COMP_EVENT) { 
     /* If using event completion, the event handler will set receive_complete
      * when it gets the completion event.
      */
     LOGPRINTF(("Waiting for receive_complete flag"));
     while(receive_complete == 0) { /* BUSY WAIT */ }
  } else {
     LOGPRINTF(("Polling for completion of recv request"));
     ret = 0;
     while(ret == 0)
       ret = ibv_poll_cq(r_cq_hndl, 1, &wc);
     
     if(ret < 0) {
       fprintf(stderr, "Error polling CQ for recv in Reset");
       exit(-1);
     }
     if(wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "  Error in completion status: %d\n",
                wc.status);
        exit(-1);
     }

     LOGPRINTF(("Status of recv completion: %d", wc.status));
  }
  LOGPRINTF(("Done with reset"));
}


/* ********** NetPipe stuff ********* */
void SendTime(ArgStruct *p, double *t)
{
    uint32_t ltime, ntime;

    /*
      Multiply the number of seconds by 1e6 to get time in microseconds
      and convert value to an unsigned 32-bit integer.
      */
    ltime = (uint32_t)(*t * 1.e6);

    /* Send time in network order */
    ntime = htonl(ltime);
    if (write(p->commfd, (char *)&ntime, sizeof(uint32_t)) < 0)
      {
        printf("NetPIPE: write failed in SendTime: errno=%d\n", errno);
        exit(301);
      }
}

void RecvTime(ArgStruct *p, double *t)
{
    uint32_t ltime, ntime;
    int bytesRead;

    bytesRead = readFully(p->commfd, (void *)&ntime, sizeof(uint32_t));
    if (bytesRead < 0)
      {
        printf("NetPIPE: read failed in RecvTime: errno=%d\n", errno);
        exit(302);
      }
    else if (bytesRead != sizeof(uint32_t))
      {
        fprintf(stderr, "NetPIPE: partial read in RecvTime of %d bytes\n",
                bytesRead);
        exit(303);
      }
    ltime = ntohl(ntime);

    /* Result is ltime (in microseconds) divided by 1.0e6 to get seconds */
    *t = (double)ltime / 1.0e6;
}

/* in the event of a send failure, re-send (tcp)*/
void SendRepeat(ArgStruct *p, int rpt)
{
  uint32_t lrpt, nrpt;

  lrpt = rpt;
  /* Send repeat count as a long in network order */
  nrpt = htonl(lrpt);
  if (write(p->commfd, (void *) &nrpt, sizeof(uint32_t)) < 0)
    {
      printf("NetPIPE: write failed in SendRepeat: errno=%d\n", errno);
      exit(304);
    }
}


/* in the event of a recv failure, resend (tcp)*/
void RecvRepeat(ArgStruct *p, int *rpt)
{
  uint32_t lrpt, nrpt;
  int bytesRead;

  bytesRead = readFully(p->commfd, (void *)&nrpt, sizeof(uint32_t));
  if (bytesRead < 0)
    {
      printf("NetPIPE: read failed in RecvRepeat: errno=%d\n", errno);
      exit(305);
    }
  else if (bytesRead != sizeof(uint32_t))
    {
      fprintf(stderr, "NetPIPE: partial read in RecvRepeat of %d bytes\n",
              bytesRead);
      exit(306);
    }
  lrpt = ntohl(nrpt);

  *rpt = lrpt;
}


/* establish the tcp connection */
void establish(ArgStruct *p)
{
 unsigned int clen;
 int one = 1;
 struct protoent;

 clen = sizeof(p->prot.sin2);
 if(p->tr){
   if(connect(p->commfd, (struct sockaddr *) &(p->prot.sin1),
              sizeof(p->prot.sin1)) < 0){
     printf("Client: Cannot Connect! errno=%d\n",errno);
     exit(-10);
   }
  }
  else {
    /* SERVER */
    listen(p->servicefd, 5);
    p->commfd = accept(p->servicefd, (struct sockaddr *) &(p->prot.sin2),
                       &clen);

    if(p->commfd < 0){
      printf("Server: Accept Failed! errno=%d\n",errno);
      exit(-12);
    }
  }
}

void CleanUp(ArgStruct *p)
{
   char *quit="QUIT";
   if (p->tr)
   {
      write(p->commfd,quit, 5);
      read(p->commfd, quit, 5);
      close(p->commfd);
   }
   else
   {
      read(p->commfd,quit, 5);
      write(p->commfd,quit,5);
      close(p->commfd);
      close(p->servicefd);
   }

   finalizeIB(p);	/* finally, deallocate all the IB stuff */
}


/* Exchange IB connection info via the tcp connection */
void AfterAlignmentInit(ArgStruct *p)
{
  int bytesRead;

  /* Exchange buffer pointers and remote infiniband keys if doing rdma. Do
   * the exchange in this function because this will happen after any
   * memory alignment is done, which is important for getting the 
   * correct remote address.
  */
  if( p->prot.commtype == NP_COMM_RDMAWRITE || 
      p->prot.commtype == NP_COMM_RDMAWRITE_WITH_IMM ) {
     
     /* Send my receive buffer address
      */
     if(write(p->commfd, (void *)&p->r_buff, sizeof(void*)) < 0) {
        perror("NetPIPE: write of buffer address failed in AfterAlignmentInit");
        exit(-1);
     }
     
     LOGPRINTF(("Sent buffer address: %p", p->r_buff));
     
     /* Send my remote key for accessing
      * my remote buffer via IB RDMA
      */
     if(write(p->commfd, (void *)&r_mr_hndl->rkey, sizeof(uint32_t)) < 0) {
        perror("NetPIPE: write of remote key failed in AfterAlignmentInit");
        exit(-1);
     }
  
     LOGPRINTF(("Sent remote key: %d", r_mr_hndl->rkey));
     
     /* Read the sent data
      */
     bytesRead = readFully(p->commfd, (void *)&remote_address, sizeof(void*));
     if (bytesRead < 0) {
        perror("NetPIPE: read of buffer address failed in AfterAlignmentInit");
        exit(-1);
     } else if (bytesRead != sizeof(void*)) {
        perror("NetPIPE: partial read of buffer address in AfterAlignmentInit");
        exit(-1);
     }
     
     LOGPRINTF(("Received remote address from other node: %p", remote_address));
     
     bytesRead = readFully(p->commfd, (void *)&remote_key, sizeof(uint32_t));
     if (bytesRead < 0) {
        perror("NetPIPE: read of remote key failed in AfterAlignmentInit");
        exit(-1);
     } else if (bytesRead != sizeof(uint32_t)) {
        perror("NetPIPE: partial read of remote key in AfterAlignmentInit");
        exit(-1);
     }
     
     LOGPRINTF(("Received remote key from other node: %d", remote_key));

  }
}


void MyMalloc(ArgStruct *p, int bufflen, int soffset, int roffset)
{
  /* Allocate buffers */

  p->r_buff = malloc(bufflen+MAX(soffset,roffset));
  if(p->r_buff == NULL) {
    fprintf(stderr, "Error malloc'ing buffer\n");
    exit(-1);
  }

  if(p->cache) { /* run-time option ? */

    /* Infiniband spec says we can register same memory region
     * more than once, so just copy buffer address. We will register
     * the same buffer twice with Infiniband.
     */
    p->s_buff = p->r_buff;

  } else {
    
    p->s_buff = malloc(bufflen+soffset);
    if(p->s_buff == NULL) {
      fprintf(stderr, "Error malloc'ing buffer\n");
      exit(-1);
    }

  }

  /* Register buffers with Infiniband */

  /* Associate our newly allocated buffers with an IB memory region
   *   If the reg fails, the function will return NULL for your region ptr
   *   Else it will return a ptr to an allocated mem region 
   */

  /* Register the local recv mem region handle:
   * ibv_mem_register( 
   *	    local protection domain,
   *	    remote buffer address,
   *	    size of the remote buffer,
   *	    access rights to this memory
   *	    )
   */
  r_mr_hndl = ibv_reg_mr(pd_hndl, p->r_buff, bufflen + MAX(soffset, roffset),
			 IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);

  if(!r_mr_hndl)
        {
    fprintf(stderr, "Error registering recv buffer\n");
    exit(-1);
        }
        else
        {
         LOGPRINTF(("Registered Recv Buffer"));
        }

    /* Register the send mem region handle */
  s_mr_hndl = ibv_reg_mr(pd_hndl, p->s_buff, bufflen+soffset, IBV_ACCESS_LOCAL_WRITE);
  if(!s_mr_hndl) {
    fprintf(stderr, "Error registering send buffer\n");
    exit(-1);
  } else {
    LOGPRINTF(("Registered Send Buffer"));
  }

}


/* De_register the allocated memory regions before exiting */
void FreeBuff(char *buff1, char *buff2)
{
  int ret;

  if(s_mr_hndl) {
    LOGPRINTF(("Deregistering send buffer"));
    ret = ibv_dereg_mr(s_mr_hndl);
    if(ret) {
      fprintf(stderr, "Error deregistering send mr\n");
    } else {
      s_mr_hndl = NULL;
    }
  }

  if(r_mr_hndl) {
    LOGPRINTF(("Deregistering recv buffer"));
    ret = ibv_dereg_mr(r_mr_hndl);
    if(ret) {
      fprintf(stderr, "Error deregistering recv mr\n");
    } else {
      r_mr_hndl = NULL;
    }
  }

  if(buff1 != NULL)
    free(buff1);

  if(buff2 != NULL)
    free(buff2);
}


static void logprintf(const char *format, ...)
{
    va_list arglist;
    va_start(arglist, format);
    vfprintf(logfile, format, arglist);
    va_end(arglist);
}
