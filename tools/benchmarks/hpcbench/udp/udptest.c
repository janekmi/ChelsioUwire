
/***************************************************************************/
/**                                                                       **/
/**     UDP communication benchmark                                       **/
/**     By Ben Huang, huang@csd.uwo.ca, April 2004                        **/
/**     UDP latency and throughput test between two processes             **/
/**                                                                       **/
/**     "udptest.c"                                                       **/
/**                                                                       **/
/***************************************************************************/ 

#include "udplib.h"
#include "util.h"


/****************************** Function prototype *************************/

static void init_data();                              // Variable initialization
static void parse_command(int, char **, int *);       // Parse command line
static void udp_ping();                               // RTT latency test
static void print_ping_result();                      // Print out the RTT test results
static void sig_handler(int);                         // Interrupt handler
static void qos_type(struct UDPconnection *, char *); // Get the IP TOS information
static status_t client_shutdown();                    // Close the socket connections
static status_t write_plot();                         // Write plot file for gnuplot

/****************************** Global variables ***************************/

static char hostname[BUFLEN];                     // Server 
static char localhost[BUFLEN];                    // Local host
static char filename[BUFLEN];                     // Output file
static char curtime[BUFLEN];                      // Time of testing
static char plotname[BUFLEN];                     // Plot file for gnuplot
static FILE * output;                             // Output file

static struct Parameter setting;                  // UDP test settings
static struct UDPconnection udpsock;              // UDP connection and its parameters
static struct UDPconnection server;               // Server's UDP configuration
static struct TCPconnection tcpsock;              // TCP connection and its parameters
static struct Throughput localTP;                 // Local(client) side throughputs 
static struct Throughput networkTP;               // Remote(Server) side throughputs
static struct RTT rtt;                            // Round Trip Time results


/*************************** Mian function *********************************/

int main(int argc, char *argv[]) 
{
    char buff[BUFLEN], sysbuff[2*BUFLEN];         
    short * ptr;                                  
    int i;                                        
    int testMode;                                 // Test mode (RTT/througput)
    int lossPackets;                              // Lost packet number
    long_int * s_rtime_usec;                      // Server process wall clock time 
    long_int * s_utime_usec;                      // Server process time in user mode
    long_int * s_stime_usec;                      // Server process time in system mode
    double clientTP, serverTP;                    // client/server throughputs
    double lossRate;                              // Packet loss rate
    struct SYSInfo * sysinfo = NULL;              // System (CPU/Interrupts) information
    struct SYSInfo * serverinfo = NULL;           // Server's system information
    struct PROInfo * proinfo;                     // Process information

    /**************** At least given server name ***************************/

    if ( argc > 1 && strcmp(argv[1], "--help")==0 ) {
	fprintf(stderr, help_description);
	fprintf(stderr, help_usage,  DEFAULTPORT, DEFAULTDATAGRAM, DEFAULTSIZE, 
		DEFAULTPORT, DEFAULTREPEAT, DEFAULTTIME);
	fprintf(stderr, help_example);
	return 0;
    } else if ( argc < 3 ) {
	print_usage();
	return 1;
    }

    /********* Data initialization and parse the command line **************/
    
    init_data();
    parse_command(argc, argv, &testMode);

    /********* Just send data in case of UDP traffic generator *************/
    
    if ( setting.udpGen ) {
	udp_traffic_generator(hostname, tcpsock.port, udpsock.sendBuf,
			      setting.testTime, setting.throughput);
	return 0;
    }

    /******************** Check the write file option **********************/

    if ( setting.writeOption ) {
	if ( (output = fopen(filename, "w")) == NULL ) {
	    fprintf(stderr, "%s: Unable to write the file!\n", filename);
	    setting.writeOption = 0;
	}
    } 

    /*************** Allocate memory to hold CPU information ***************/
    
    if ( setting.CPUoption ) { 

	/** Two more items to hold the syslog of pre/post states of test ***/

	if ( (sysinfo = (struct SYSInfo *)malloc((setting.repeat + 2) 
			* sizeof(struct SYSInfo))) == NULL ) {
	    perror("Failed to malloc.");
	    exit(1);
	}

	if ( start_trace_system( &sysinfo[0]) == NOTOK ) {
	    fprintf(stderr, "Failed to monitor system information.\n");
	    setting.CPUoption = 0;
	} else {
	    sleep(1);
	    stop_trace_system( &sysinfo[0] );
	}
    }
 
    /***********************  TCP connection to server *********************/

    if (client_tcp_connect(hostname, &tcpsock) == NOTOK) {
	fprintf(stderr, "%s : %d ", hostname, tcpsock.port);
	perror("Unable to establish TCP connection.");
	return 1;
    }

    /*************** Send parameters to server *****************************/
    
    sprintf(buff, test_init_str, testMode, udpsock.tos, setting.CPUoption, 
	    server.sendBuf, server.recvBuf, udpsock.packetSize, udpsock.dataSize);
    if ( tcp_send_request(buff, strlen(buff), &tcpsock) == NOTOK ) {
	perror("TCP send parameters error.");
	return 1;
    }
 
    /************  Get server's UDP connection setting *********************/

    if ( tcp_get_request(buff, &tcpsock) == NOTOK || 
	 sscanf(buff, server_setting_str, &udpsock.port, &server.tos, 
		&setting.sCPUoption, &server.sendBuf, &server.recvBuf, 
		&server.packetSize, &server.dataSize) != 7) {
	perror("Failed to get UDP connection information.");
	return 1;
    }    

    /************ Initialization of UDP communication  *********************/

    if (client_udp_init(hostname, &udpsock) == NOTOK) {
	fprintf(stderr, "%s : %d ", hostname, udpsock.port);
	perror("Failed to establish the UDP connection.");
	return 1;
    }

    if ( gethostname(localhost, BUFLEN) < 0 ) {
	perror("gethostname.");
	strcpy(localhost, "Localhost");
    }

    /************************* Allocate memory *****************************/

    if ( (buffer = (char *) malloc ( udpsock.packetSize)) == NULL ){
	fprintf(stderr, "Malloc error : %d\n", udpsock.packetSize);
        return 1;
    }

    /******* Randomize the buffer to prevent the possible compression ******/
    
    srand(time(NULL));
    for(ptr = (short *)buffer; ptr < (short *)(buffer+udpsock.packetSize); ptr += 2 )
	*ptr = (short)rand();

    /*** Allocate memory to store the client/server process information ****/
	
    if ( (proinfo = (struct PROInfo *)malloc((setting.repeat)*sizeof(struct PROInfo))) == NULL ||
	 (s_rtime_usec = (long_int *)malloc((setting.repeat)*sizeof(long_int))) == NULL ||
	 (s_utime_usec = (long_int *)malloc((setting.repeat)*sizeof(long_int))) == NULL ||
	 (s_stime_usec = (long_int *)malloc((setting.repeat)*sizeof(long_int))) == NULL ) {
	perror("Failed to malloc.");
	exit(1);
    }
    
#ifdef DEBUG
    fprintf(stderr, " DEBUG: Client connected to server on port: %d\n", udpsock.port);
#endif

    /********************** Handle the interruption ************************/

    signal(SIGINT, sig_handler);
    signal(SIGTSTP, sig_handler);

    /********************** RTT (latency test) *****************************/

    if ( testMode == LATENCY ) {
	udp_ping();
	print_ping_result();
	return 0;
    }

    /************************ UDP throughput test **************************/

    /** We need another container to hold server's system info if defined **/

    if ( setting.sCPUoption ) { // Server also monitor the system resource
	if ( (serverinfo = (struct SYSInfo *)malloc((setting.repeat + 2) 
			   * sizeof(struct SYSInfo))) == NULL ) {
	    perror("Failed to malloc.");
	    exit(1);
	}
	bzero(buff, BUFLEN);
	if ( tcp_get_request(sysbuff, &tcpsock) == NOTOK ||
	     string_to_sysinfo( &serverinfo[0], sysbuff, 2*BUFLEN) == NOTOK ) {
	    perror("Failed to get server's initial system information.");
	    exit (1);
	}
    }

    /******************** Print out the connection message *****************/

    if ( setting.verbose ) {
	fprintf(stderr, "UDP throughput %s test\n%s (client) <--> %s (server)\n", 
		setting.exponential ? "exponential" : "fixed packet size", localhost, hostname);
	fprintf(stderr, "UDP-port: %d UDP-send-buffer: %d UDP-recv-buffer: %d\n",
		udpsock.port, udpsock.sendBuf, udpsock.recvBuf);
    }

    /******************* Write test parameters to a file *******************/

    if ( setting.writeOption ) {

	get_local_time(curtime, BUFLEN);
	fprintf(output, "# UDP communication test -- %s\n", curtime);
	fprintf(output, "# %s size %s stream test\n", setting.exponential ? 
		"Exponential":"Fixed packet", setting.bidirection ? "bidirectional":"unidirectional");
	fprintf(output, "# Hosts: %s (client) <--> %s (server)\n\n", localhost, hostname);
	fprintf(output, "# Client UDP socket buffer size (Bytes) -- SNDBUF: %d RCVBUF: %d\n", 
		udpsock.sendBuf, udpsock.recvBuf );
	fprintf(output, "# Server UDP socket buffer size (Bytes) -- SNDBUF: %d RCVBUF: %d\n", 
		server.sendBuf, server.recvBuf);
	qos_type(&udpsock, buff);
	fprintf(output, "# Client IP TOS type: %s\n", buff);
	qos_type(&server, buff);
	fprintf(output, "# Server IP TOS type: %s\n", buff);
	fprintf(output, "# UDP datagram (packet) size (Bytes) -- Client: %d Server: %d\n", udpsock.packetSize, server.packetSize);

	if ( setting.exponential ) {  // Exponential test
	    fprintf(output, "# Test time (second): %f\n\n", setting.testTime);
	    if ( !setting.bidirection ) { 
		fprintf(output, "#   Size    Network     Local    Client      Client    Server      Server    Server  ServerRecv\n");
		fprintf(output, "#  (Byte)    (Mbps)    (Mbps)   SentPkg    SentByte   RecvPkg    RecvByte   LostPkg    LossRate\n");
	    } else {
		fprintf(output, "#   Size    Network     Local    Client      Client    Server      Server    Client      Client    Server      Server  ServerRecv\n");
		fprintf(output, "#  (Byte)    (Mbps)    (Mbps)   SentPkg    SentByte   RecvPkg    RecvByte   RecvPkg    RecvByte   SentPkg    SentByte    LossRate\n");
	    }
	}
	else { // Fixed packet size test
	    fprintf(output, "# Data size of each read/write (Bytes) -- Client: %d Server: %d\n", udpsock.dataSize, server.dataSize); 
	    fprintf(output, "# Message size (Bytes): %lld\n", setting.messageSize);
	    fprintf(output, "# Test time (Second): %f\n# Test repeat: %d\n\n", setting.testTime, setting.repeat); 

	    if ( ! setting.bidirection ) // One way unidirectional test
		fprintf(output, "#   Network(Mbps) Local(Mbps) SentPkg(C) SentByte(C) RecvPkg(S) RecvByte(S)  LostPkg  LossRate\n");
	    else { // bidirection test 
		fprintf(output, "#     Network     Local    Client     Client    Server     Server    Client     Client    Server     Server   Server\n");
		fprintf(output, "#   throughput throughput   sent       sent      recv       recv      recv       recv      sent       sent     recv\n");
		fprintf(output, "#     (Mbps)     (Mbps)    packet      byte     packet      byte     packet      byte     packet      byte   loss-rate\n");
	    } // bidriection test
	} // Fixed packet size test

    } // If write option

    /********************** Start UDP throughput test **********************/ 

    for ( i = 0; i < setting.repeat; i++ ) {                   

	if ( setting.exponential ) {
		udpsock.dataSize = (1<<i);  // Increase the packet size doubly
		if ( udpsock.dataSize > udpsock.packetSize ) // The last one
		    udpsock.dataSize = udpsock.packetSize;
	}

	/**************** Inform server to start UDP test ******************/ 

	sprintf(buff, test_start_str, udpsock.dataSize, 0);
	if ( tcp_send_request(buff, strlen(buff), &tcpsock) == NOTOK ) {
	    perror("Failed to send request.");
	    client_shutdown();
	    exit (1);
	}

	/*************** Start monitoring system information ***************/

	if ( setting.CPUoption ) 
	    start_trace_system(&sysinfo[i+1]);
	start_trace_process(&proinfo[i]);

	/***************** Start UPD throughput test ***********************/

	if ( setting.bidirection ) {
	    if ( client_udp_bi_test (setting.messageSize, setting.testTime, &udpsock) 
		 == NOTOK && error != TIMEOUT && error != DISORDER ) {
		perror("UDP test error.");
		client_shutdown();
		exit (1);
	    }
	} else if ( client_udp_test (setting.messageSize, setting.testTime, &udpsock, 
		    setting.throughput) == NOTOK && error != TIMEOUT && error != DISORDER ) {
	    perror("UDP test error.");
	    client_shutdown();
	    exit (1);
	}

	stop_trace_process(&proinfo[i]);

	if ( setting.CPUoption ) {
	    usleep(1000);
	    stop_trace_system(&sysinfo[i+1]);
	}
	
#ifdef DEBUG 
	fprintf(stderr, " DEBUG: One trip test done, sent Bytes: %lld sent packets: %d\n",
		udpsock.sentBytes, udpsock.sentPackets);
	fprintf(stderr, " DEBUG: Waiting server's test result ...\n");
#endif 
	
	/************* Get server's test result by TCP channel *************/
	
	if ( tcp_get_request(buff, &tcpsock) == NOTOK ) {
	    fprintf(stderr, "Get result error (TCP data channel).\n");
	    client_shutdown();
	    exit(1);
	} else if ( strncmp(buff, test_time_out_str, strlen(test_time_out_str)) == 0 ) {
	    if ( setting.sCPUoption ) {
		if ( tcp_get_request(sysbuff, &tcpsock) == NOTOK ||
		     string_to_sysinfo( &serverinfo[i+1], sysbuff, 2*BUFLEN) == NOTOK ) {
		    perror("Failed to get server's system information.");
		    exit (1);
		}
	    }

	    fprintf(stderr, "UDP key packets lost. Igore the result.\n");
	    if ( setting.writeOption )
		fprintf (output, "#%d UDP key packets lost. Igore the result.\n", i+1);

	    s_rtime_usec[i] = s_utime_usec[i] = s_stime_usec[i] = 0;
	    continue;

	} else if ( sscanf(buff, server_result_str, &server.recvBytes, 
		    &server.recvPackets, &server.sentBytes, &server.sentPackets, 
		    &server.elapsedTime, &s_utime_usec[i], &s_stime_usec[i]) != 7 ) {
		fprintf(stderr, "Failed to parse server's result: %s\n", buff);
		client_shutdown();
		exit(1);
	}
	s_rtime_usec[i] = server.elapsedTime;

	if ( setting.sCPUoption ) {
	    if ( tcp_get_request(sysbuff, &tcpsock) == NOTOK ||
		 string_to_sysinfo( &serverinfo[i+1], sysbuff, 2*BUFLEN) == NOTOK ) {
		perror("Failed to get server's system information.");
		exit (1);
	    }
	}	

	localTP.trial++;
	networkTP.trial++;

	if ( server.elapsedTime <= 0 ) {
	    fprintf(stderr, "Wrong of server's elapsed time! Ignore the result: %s\n", buff);
	    continue;
	}
	
	serverTP = (server.recvBytes+udpsock.recvBytes) * 8.0 / server.elapsedTime; // Network count
	
	if ( networkTP.min > serverTP )
	    networkTP.min = serverTP;
	if ( networkTP.max < serverTP )
	    networkTP.max = serverTP;
	networkTP.sum += serverTP;
	
	clientTP = (server.sentBytes+udpsock.sentBytes) * 8.0 / udpsock.elapsedTime; // local count
	proinfo[i].rtime_sec = udpsock.elapsedTime / 1000000;
	proinfo[i].rtime_usec = udpsock.elapsedTime % 1000000;
	
	/************* Keep the minimum and maximum throughputs ************/	    
	
	if ( localTP.min > clientTP )
	    localTP.min = clientTP;
	if ( localTP.max < clientTP )
	    localTP.max = clientTP;
	localTP.sum += clientTP;

	/****** Compute the packet loss rate of client sending *************/
	
	lossPackets = udpsock.sentPackets - server.recvPackets;
	lossRate = lossPackets * 1.0 / udpsock.sentPackets;
	
	/*********************** Print out test results ********************/ 
	    
	if ( setting.verbose ) {
	    if ( setting.exponential )	
		fprintf(stderr, "Message size: %d\n", udpsock.dataSize);
	    fprintf(stderr, "\n[Client] Sent-bytes: %lld Sent-packets: %d ", 
		    udpsock.sentBytes, udpsock.sentPackets);
	    fprintf(stderr, "Recv-bytes: %lld Recv-Packets: %d\n", 
		    udpsock.recvBytes, udpsock.recvPackets);
	    fprintf(stderr, "[Server] Recv-bytes: %lld Recv-Packets: %d ", 
		    server.recvBytes, server.recvPackets);
	    fprintf(stderr, "Sent-bytes: %lld Sent-Packets: %d\n", 
		    server.sentBytes, server.sentPackets);
	    fprintf(stderr, "Client-time(Sec.): %f  Server-time(Sec.): %f\n", 
		    udpsock.elapsedTime/1000000.0, server.elapsedTime/1000000.0);
	    fprintf(stderr, "Network-throughput(Mbps): %f Local-throughput: %f\n", 
		    serverTP, clientTP);
	    fprintf(stderr, "Lost-packets (c->s): %d  Loss-rate(c->s): %f\n\n", 
		    lossPackets, lossRate);
	} else
	    fprintf(stderr, " (%d) Throughput: %f  Loss-rate: %f\n", 
		    i+1, serverTP, lossRate);
	    
	/*************** Store test results in the file ********************/

	if ( setting.writeOption ) {
	    if ( setting.exponential ) {     // exponential throughput test
		if ( !setting.bidirection )
		    fprintf (output, "%-3d%6d%10.3f%10.3f%10d%12lld%10d%12lld%10d%10.3f\n", 
			 i+1, udpsock.dataSize, serverTP, clientTP, udpsock.sentPackets, 
			 udpsock.sentBytes, server.recvPackets, server.recvBytes, 
			 lossPackets, lossRate);
		else
		    fprintf (output, "%-3d%6d%10.3f%10.3f%10d%12lld%10d%12lld%10d%12lld%10d%12lld%12.3f\n", 
			 i+1, udpsock.dataSize, serverTP, clientTP, udpsock.sentPackets, 
			 udpsock.sentBytes, server.recvPackets, server.recvBytes, udpsock.recvPackets, 
			     udpsock.recvBytes, server.sentPackets, server.sentBytes, lossRate);
	    }
	    else if ( !setting.bidirection )   // unidirectional throughput test 
		fprintf (output, "%-3d%13.4f%12.4f%11d%12lld%11d%12lld%10d%10.3f\n", 
			 i+1, serverTP, clientTP, udpsock.sentPackets, udpsock.sentBytes, 
			 server.recvPackets, server.recvBytes, lossPackets, lossRate);
	    else {                             // bidirectional throughput test 
		fprintf(output, "%-3d%10.3f%11.3f%9d", i+1, serverTP, clientTP, udpsock.sentPackets);
		fprintf(output, "%12lld%9d%12lld", udpsock.sentBytes, server.recvPackets, server.recvBytes);
		fprintf(output, "%9d%12lld%9d", udpsock.recvPackets, udpsock.recvBytes, server.sentPackets);
		fprintf(output, "%12lld%9.3f\n", server.sentBytes, lossRate);
	    } // bidriection test
	} // if write option

    } // for loop of repeat


    /********************** Inform server the end of the session ***********/

    sprintf(buff, test_end_str);
    if ( tcp_send_request (buff, strlen(buff), &tcpsock) == NOTOK )
	fprintf(stderr, "Close session error.");

    if ( setting.CPUoption ) { // record the post-test system info
	if ( start_trace_system( &sysinfo[setting.repeat+1] ) == NOTOK ) {
	    perror("Failed to trace system in final state.");
	    exit (1);
	}
	sleep(1);
	if ( stop_trace_system( &sysinfo[setting.repeat+1] ) == NOTOK ) {
	    perror("Failed to trace system in final state.");
	    exit (1);
	}
	if ( setting.sCPUoption ) {
	    if ( tcp_get_request(sysbuff, &tcpsock) == NOTOK ||
		 string_to_sysinfo( &serverinfo[setting.repeat+1],
				    sysbuff, 2*BUFLEN) == NOTOK ) {
		perror("Failed to get server's last syslog.");
		exit (1);
	    }
	}
    }

    /***** Compute the average throughput for fixed-size message tests *****/

    if ( !setting.exponential && setting.writeOption && localTP.trial > 2 ) {
	
	localTP.avg = localTP.sum/localTP.trial; 
	networkTP.avg = networkTP.sum/localTP.trial; 

	fprintf(output, "\n# Local Average: %10f  Minimum: %10f  Maximum: %10f\n", 
		localTP.avg, localTP.min, localTP.max);
	fprintf(output, "# Network Average: %10f  Minimum: %10f  Maximum: %10f\n", 
		networkTP.avg, networkTP.min, networkTP.max);
    } 

    if ( setting.writeOption ) {
	fprintf(output, "\n# Process information for each test: \n\n");
	fprintf(output, "#         Client     C-process   C-process      Server     S-process   S-process\n");
	fprintf(output, "#      Elapsed-time  User-mode  System-mode  Elapsed-time  User-mode  System-mode\n");
	fprintf(output, "#       (Seconds)    (Seconds)   (Seconds)    (Seconds)    (Seconds)   (Seconds)\n");
	for ( i = 0; i < setting.repeat; i++ ) {
	    fprintf(output, "#%-4d%11.2f%13.2f%12.2f%13.2f%13.2f%12.2f\n", i+1, 
		    (double)proinfo[i].rtime_sec + proinfo[i].rtime_usec/1000000.0,
		    (double)proinfo[i].utime_sec + proinfo[i].utime_usec/1000000.0,
		    (double)proinfo[i].stime_sec + proinfo[i].stime_usec/1000000.0,
		    s_rtime_usec[i]/1000000.0, s_utime_usec[i]/1000000.0, s_stime_usec[i]/1000000.0);
	}
	fprintf(output, "\n");
	fclose(output); 

	fprintf(stderr, "Test done! The results are stored in file \"%s\"\n", filename);
	if ( setting.CPUoption ) {
	    strcpy(buff, filename);
	    strcat(buff, ".c_log");
	    if ( write_sys_info(sysinfo, setting.repeat+2, buff, curtime, localhost) == OK )
		fprintf(stderr, "Local-syslog: \"%s\"  ", buff); 
	    strcpy(buff, filename);
	    strcat(buff, ".s_log");
	    if ( setting.sCPUoption && 
		 write_sys_info(serverinfo, setting.repeat+2, buff, curtime, hostname) == OK )
		fprintf(stderr, "server-syslog: \"%s\"", buff); 
	    fprintf(stderr, "\n");
	}	
	if ( setting.plotOption && write_plot() == OK ) { 
	    fprintf(stderr, "Plot-file: \"%s\". ", plotname);
	    fprintf(stderr, "Use \"gnuplot %s\" to plot the data\n", plotname);
	}
	fclose(output);
    } else 
	fprintf(stderr, "Test done!\n");

    /*************************** Close the connection **********************/

    client_shutdown();   
    return 0;

}  // end of main function 


/************************** Variables initialization ***********************/

static void init_data() 
{
    /************************ Clean the char arrays ************************/

    bzero(hostname, BUFLEN);
    bzero(filename, BUFLEN);
    bzero(plotname, BUFLEN);
    bzero(localhost, BUFLEN);

    /****************** Default test mode  setting *************************/

    setting.verbose = 0;                   
    setting.latency = 0;
    setting.bidirection = 0;
    setting.exponential = 0;
    setting.writeOption = 0;
    setting.plotOption = 0;
    setting.udpGen = 0;
    setting.CPUoption = 0;
    setting.sCPUoption = 0;
    setting.throughput = 0;

    setting.repeat = DEFAULTREPEAT;    
    setting.messageSize = DEFAULTSIZE;    
    setting.testTime = DEFAULTTIME; 
    
    
    /******************* Connection  initialization ************************/

    tcpsock.port = DEFAULTPORT;            // TCP communication port

    udpsock.packetSize = DEFAULTDATAGRAM;  // UPD packet (datagram) size 
    udpsock.dataSize = DEFAULTDATAGRAM;    // Data size of each sending  
    udpsock.tos = 0;                       // IP TOS setting   
    udpsock.sendBuf = -1;                  // Using system default setting
    udpsock.recvBuf = -1;                  // Using system default setting

    server.packetSize = DEFAULTDATAGRAM; 
    server.dataSize = DEFAULTDATAGRAM;    
    server.tos = 0;    
    server.sendBuf = -1;                 
    server.recvBuf = -1;                

    /****************** RTTs and Throughputs initialization ****************/

    rtt.mode = 0;
    rtt.trial = 0;
    rtt.loss = 0;
    rtt.size = 64;
    rtt.min = MAXNUMBER;
    rtt.max = 0;
    rtt.sum = 0;
    rtt.avg = 0;

    localTP.min = MAXNUMBER;
    localTP.max = 0;
    localTP.sum = 0;
    localTP.avg = 0;
    localTP.trial = 0; 

    networkTP.min = MAXNUMBER;
    networkTP.max = 0;
    networkTP.sum = 0;
    networkTP.avg = 0;
    networkTP.trial = 0; 

    return;
}


/*************************** Parse command line ****************************/

static void parse_command(int argc, char *argv[], int *testMode)
{
    char buff[BUFLEN];
    int i, option;
    long_int size;

    while ( (option = getopt (argc, argv, ":viacgePh:p:A:b:B:d:l:o:q:l:t:T:m:r:")) != -1) {
	switch ( option ) {
	case 'a' :  /* RTT (latency) test (UDP ping) */
	    setting.latency = 1;
	    break;
	case 'A':   /* message size for RTT (latency) test */
	    setting.latency = 1;
	    if ( (size = parse_size(optarg)) > 0 )
		rtt.size = (int)size;
            if ( rtt.size > MAXDATAGRAM ) 
                rtt.size = MAXDATAGRAM;
	    break;
	case 'b':  /* client UDP buffer size */
	    if ( (size = parse_size(optarg)) >= 0 ) {
		udpsock.recvBuf = (int)size;
		udpsock.sendBuf = (int)size;
	    }
	    break;
	case 'B':  /* server UDP buffer size */
	    if ( (size = parse_size(optarg)) >=0 ) {
		server.recvBuf = (int)size;
		server.sendBuf = (int)size;
	    }
	    break;
	case 'c':   /* monitor CPU and system information */
	    setting.CPUoption = 1;
	    break;
	case 'd':  /* data size of each sending/receiving */
	    if ( (size = parse_size(optarg)) > 0)
		udpsock.dataSize = (int)size;
	    break;
	case 'e' :  /* exponential test */
	    setting.exponential = 1;
	    break;
	case 'g' :  /* UDP traffic generator */
	    setting.udpGen = 1;
	    break;
	case 'h' :  /* server host name or IP address */
	    strcpy (hostname, optarg);
	    break;
	case 'i' :  /* bidirectional test mode */
	    setting.bidirection = 1;
	    break;
	case 'l':  /* UDP datagram length (packet size) */
	    if ( (size = parse_size(optarg)) > 0)
		udpsock.packetSize = (int)size;
	    break;
	case 'm':  /* message size */
	    if ( (size = parse_size(optarg)) > 0)
		setting.messageSize = size;
	    break;
	case 'o':   /* write test results to a file */
	    strcpy(filename, optarg);
	    setting.writeOption = 1;
	    break;
	case 'p':   /* connection port number */
	    if ( (size = parse_size(optarg)) > 0 )
		tcpsock.port = (int)size;
	    break;
	case 'P':   /* write plot file */
	    setting.plotOption = 1;
	    break;
	case 'q':  /* Qos (TOS) setting */
	    if ( (size = parse_size(optarg)) > 0) {
		switch (size) {
		case 1:  /* Minimize delay */
		    udpsock.tos = TOS_LOWDELAY;
		    break;
		case 2:  /* Maximize throughput */
		    udpsock.tos = TOS_MAXTP;
		    break;
		case 3:  /* DiffServ Class1 with low drop probability */
		    udpsock.tos = DSCP_C1_DL;
		    break;
		case 4:  /* DiffServ Class1 with high drop probability */
		    udpsock.tos = DSCP_C1_DH;
		    break;
		case 5:  /* DiffServ Class4 with low drop probability */
		    udpsock.tos = DSCP_C4_DL;
		    break;
		case 6:  /* DiffServ Class4 with high drop probability */
		    udpsock.tos = DSCP_C4_DH;
		    break;
		default:
		    fprintf(stderr, "Warning: QoS(-q) should be number 1-6. Igore the QoS setting\n");
		    break;
		}
	    }
	    break;
	case 'r':  /* repetition of tests */
	    if ( (size = parse_size(optarg)) > 0)
		setting.repeat = (int)size;
	    break;
	case 't':  /* test time in second */
	    if ( atof(optarg) > 0 )
		setting.testTime = atof(optarg);
	    break;
	case 'T' :  /* UDP traffic generator */
	    strcpy(buff, optarg);
	    if ( atol(buff) > 0 ) { 
		if ( buff[strlen(buff)-1] == 'M' || buff[strlen(buff)-1] == 'm')
		    setting.throughput = atol(buff)*1000LL*1000;
		else if (buff[strlen(buff)-1] == 'K' || buff[strlen(buff) -1] == 'k')
		    setting.throughput = atol(buff)*1000LL;
		else 
		    setting.throughput = atol(buff);
	    }
	    break;
	case 'v' :  /* print out detail message */
	    setting.verbose = 1;
	    break;
	case ':':
	    fprintf(stderr,"Error: -%c without argument\n", optopt);
	    print_usage();
	    exit(1);
	case '?':
	    fprintf(stderr,"Error: Unknown argument %c\n", optopt);
	    print_usage();
	    exit(1);
	default:
	    print_usage();
	    exit(1);
	}
    }

    /* The datasize of each read/write is the same as packetsize by default */
    
    if ( udpsock.dataSize != udpsock.packetSize && 
	 udpsock.dataSize == DEFAULTDATAGRAM )
	udpsock.dataSize = udpsock.packetSize;

    /* The datasize of each read/write should not be greater than packetsize */
    
    if ( udpsock.dataSize > udpsock.packetSize )
	udpsock.dataSize = udpsock.packetSize;

    /************* Initialization for exponential test *********************/

    if ( setting.exponential ) {
	udpsock.dataSize = 0;      // Exponential tests start from 2^0=1 Byte
	setting.messageSize = 0;   // Only rely on test time (no message size requirement)
	for ( i = 0; (1<<i) < udpsock.packetSize; i++);  // Datasize from 2^0 to 2^i (size of eaching sending)
	setting.repeat = 1 + i++;  // The last test is the package size 
    }

    /****************** Syslog is only written to files ********************/
    
    if ( !setting.writeOption )
	setting.CPUoption = 0;

    /* Server has the the same buffer size with client if they are not defined */

    if ( server.recvBuf < 0 && udpsock.recvBuf > 0 ) { 
	server.recvBuf = udpsock.recvBuf;
	server.sendBuf = udpsock.sendBuf;
    }

    /********************** Set the test mode *****************************/

    if ( setting.latency ) {
	*testMode = LATENCY;
	setting.exponential = 0;
	setting.bidirection = 0;
	setting.CPUoption = 0;
	udpsock.dataSize = udpsock.packetSize = rtt.size;
    } else if ( setting.bidirection )
	*testMode = TPBIDIRECT;
    else 
	*testMode = TPSTREAM;

    return;

}


/************** Show the QoS type setting in IP TOS fields *****************/

static void qos_type(struct UDPconnection * sock, char * buff ) 
{
    if ( sock->tos == 0 )
	strcpy(buff, "Default");
    if ( sock->tos == TOS_LOWDELAY )
	strcpy(buff, "IPTOS_Minimize_Delay");
    else if ( sock->tos == TOS_MAXTP ) 
	strcpy(buff, "IPTOS_Maximize_Throughput");
    else if ( sock->tos == DSCP_C1_DL )
	strcpy(buff, "DiffServ_Class1_Low_Drop");
    else if ( sock->tos == DSCP_C1_DH )
	strcpy(buff, "DiffServ_Class1_High_Drop");
    else if ( sock->tos == DSCP_C4_DL )
	strcpy(buff, "DiffServ_Class4_Low_Drop");
    else if ( sock->tos == DSCP_C4_DH )
	strcpy(buff, "DiffServ_Class4_High_Drop");
    return;
}


/******************* RTT (latency) test is kind of UDP ping ****************/

static void udp_ping() 
{
    char buff[BUFLEN];
    int i, iteration; 
    double rttTime;
 
    iteration = 2; // start from a small size
    rtt.mode = 1;

    udpsock.elapsedTime = 0;
    
    /******** Obtain the iteration number for a minimum test time **********/
    /******** Double the iteration for at most 20 times (2^20=2M) **********/
    
    for ( i = 1; udpsock.elapsedTime < MINITIME && i < 20; i++ ) {
	
	/* There is a synchronization step for UDP-ping, so the iteration for
	 * server is one more than local's (iteration+1)
	 */
	
	sprintf(buff, test_start_str, udpsock.dataSize, iteration+1);	
	if ( tcp_send_request(buff, strlen(buff), &tcpsock) == NOTOK ) {
	    perror("Failed to send request to server.");
	    client_shutdown();
	    exit (1);
	}
	
	/********************* Start estimation test  *********************/
	
	if ( client_udp_ping (iteration, &udpsock) == OK ) {
	    iteration *= 2;
	} else if ( error == TIMEOUT || error == DISORDER ) {

	    fprintf(stderr, "Ping error: %s\n", (error == TIMEOUT) ? 
		    "Packet lost":"Packet disorder");
	  
	    /************ An estra synchronization step ********************/ 
	    sprintf(buff, test_sync_str);	
	    if ( tcp_send_request(buff, strlen(buff), &tcpsock) == NOTOK ) {
		perror("Failed to send request to server.");
		client_shutdown();
		exit (1);
	    } else if ( tcp_get_request(buff, &tcpsock) == NOTOK || 
		 strncmp(buff, test_sync_str, 20) != 0 ) {
		perror("Failed to synchronize.");
		exit (1);
	    }    
	    continue;

	} else {
	    perror("UDP communication error.");
	    exit (1);
	}
    } 

    if ( i == 20 ) { // Too many trials and 
	perror("UDP ping pre-test error.");
	exit (1);
    }
    
    if ( setting.verbose ) {
	fprintf(stderr, "RTT (latency) test\n%s <--> %s\n", localhost, hostname);
	fprintf(stderr, "UDP-port: %d UDP-buffer: %d\nMessage-size: %d Iteration: %d\n", 
		udpsock.port, udpsock.sendBuf, rtt.size, iteration);
    }

    if ( setting.writeOption ) {
	get_local_time(buff, BUFLEN);
	fprintf(output, "# UDP roundtrip time test %s\n", buff);
	fprintf(output, "# %s <--> %s\n", localhost, hostname);
	fprintf(output, "# UDP-send-buffer: %d UDP-recv-buffer: %d\n", 
		udpsock.sendBuf, udpsock.recvBuf);
	fprintf(output, "# Message-size: %d Iteration: %d\n", rtt.size, iteration);
    }
    
    /***************** Endless loop of RTT (latency) test **************/
    
    for( i = 1; i <= setting.repeat; i++) {
	
	/* There is a synchronization step for UDP-ping, so the iteration for
	 * server is one more than local's (iteration+1)
	 */

	sprintf(buff, test_start_str, udpsock.dataSize, iteration+1);
	if ( tcp_send_request(buff, strlen(buff), &tcpsock) == NOTOK ) { 
	    perror("Failed to send request to server.");
	    client_shutdown();
	    exit (1);
	}

	if ( client_udp_ping (iteration, &udpsock) == NOTOK ) {
	    if ( error == TIMEOUT ) {
		fprintf(stderr, "UDP Round Trip Time (%d) : Packet lost\n", i);
		if ( setting.writeOption ) 
		    fprintf(output, "UDP Round Trip Time (%d) : Packet lost\n", i);
	    } else if ( error == DISORDER ) {
		fprintf(stderr, "UDP Round Trip Time (%d) : Packet disordered\n", i);
		if ( setting.writeOption ) 
		    fprintf(output, "UDP Round Trip Time (%d) : Packet disordered\n", i);
	    } else {
		perror("UDP communication error.");
		exit(1);
	    }
	    rtt.trial++;
	    rtt.loss++;

	    /************ Need a synchronization for this case *************/

	    sprintf(buff, test_sync_str);	
	    if ( tcp_send_request(buff, strlen(buff), &tcpsock) == NOTOK ) {
		perror("Failed to send request to server(sync).");
		client_shutdown();
		exit (1);
	    } else if ( tcp_get_request(buff, &tcpsock) == NOTOK || 
		 strncmp(buff, test_sync_str, 20) != 0 ) {
		perror("Failed to synchronize.");
		exit (1);
	    } 
   
	} else {  // UDP ping OK

	    /******** Compute the RTT times and their statistics *******/
	    
	    rttTime = udpsock.elapsedTime*1.0/iteration;
	    rtt.trial++;
	    rtt.sum += rttTime;
	    rtt.avg = rtt.sum/rtt.trial;
	    if ( rtt.min > rttTime)
		rtt.min = rttTime;
	    if ( rtt.max < rttTime)
		rtt.max = rttTime;
	    if ( rttTime > 1000 ) {
		fprintf(stderr, "UDP Round Trip Time (%d) : %6.3f msec\n", i, rttTime/1000);
		if ( setting.writeOption ) 
		    fprintf(output, "UDP Round Trip Time (%d) : %6.3f msec\n", i, rttTime/1000);
	    } else {
		fprintf(stderr, "UDP Round Trip Time (%d) : %6.3f usec\n", i, rttTime);
		if ( setting.writeOption ) 
		    fprintf(output, "UDP Round Trip Time (%d) : %6.3f usec\n", i, rttTime);
	    }
	}	    
	sleep (1);
    }
    
    return;
}


/***************** Print out the RTT latency (UDP Ping) results ************/

static void print_ping_result()
{
    if ( rtt.mode ) {

	if ( rtt.loss > 0 ) {
	    fprintf(stderr, "%d trials (%d failed) with message size %d Bytes.\n", 
		    rtt.trial, rtt.loss, rtt.size);
	    if ( setting.writeOption) 
		fprintf(output, "%d trials (%d failed) with message size %d Bytes.\n", 
			rtt.trial, rtt.loss, rtt.size);
	} else {
	    fprintf(stderr, "%d trials with message size %d Bytes.\n",  
		    rtt.trial, rtt.size);
	    if ( setting.writeOption) 
		fprintf(output, "%d trials with message size %d Bytes.\n",  
			rtt.trial, rtt.size);
	}

	if ( rtt.avg > 1000 ) {
	    fprintf(stderr, "UDP RTT (%d-byte) min/avg/max = %6.3f/%6.3f/%6.3f msec\n", 
		    rtt.size, rtt.min/1000, rtt.avg/1000, rtt.max/1000);
	    if ( setting.writeOption) 
		fprintf(output, "UDP RTT (%d-byte) min/avg/max = %6.3f/%6.3f/%6.3f msec\n", 
			rtt.size, rtt.min/1000, rtt.avg/1000, rtt.max/1000);
	} else {
	    fprintf(stderr, "UDP RTT (%d-byte) min/avg/max = %6.3f/%6.3f/%6.3f usec\n", 
		    rtt.size, rtt.min, rtt.avg, rtt.max);
	    if ( setting.writeOption) 
		fprintf(output, "UDP RTT (%d-byte) min/avg/max = %6.3f/%6.3f/%6.3f usec\n", 
			rtt.size, rtt.min, rtt.avg, rtt.max);
	}
    }
    return;
}


/************************** Interrupt handler ******************************/

static void sig_handler(int sig_num) 
{
    // fprintf(stderr, "Captured interruption, quit..\n");
    if ( rtt.mode )
	print_ping_result();
    client_shutdown();
    exit(sig_num);
}

/*************** Client close the connections ******************************/

static status_t client_shutdown() 
{
    close(tcpsock.socket);
    close(udpsock.socket); 
    free(buffer);
    return OK;
}

/****** Write a configuration file for gnuplot to plot the data  ***********/

static status_t write_plot() 
{ 
    int i = 0, j = 0;
    char buff[BUFLEN];
    FILE * plot;
    
    int exp_mode = setting.exponential;
    int buffsize = udpsock.sendBuf;
    int packetsize = udpsock.packetSize;

    /***************** Get the relative path name **************************/

    while ( filename[i] != '\0' && i < strlen(filename) ) {
        buff[j++] = filename[i++];
        if ( buff[j-1] == '/' ) {   // "/home/user/result" -> "result"
            j = 0;
            buff[j] = filename[i];
        }
    }
    buff[j] = '\0';

    strcpy(plotname, filename);
    strcat(plotname, ".plot");
    
    if ( (plot = fopen(plotname, "w")) == NULL ) {
	fprintf(stderr, "%s: Unable to write the plot file!\n", plotname);
	return NOTOK;
    } 
    strcpy(filename, buff);
 
    fprintf(plot, "# The configuration file for plotting the data of file %s \n", filename);
    fprintf(plot, "# Usage: gnuplot %s.plot\n\n", filename);
    fprintf(plot, "set key left \n");

    if ( exp_mode ) {
	fprintf(plot, "set xlabel \"Message size (Bytes)\"\n");
	fprintf(plot, "set logscale x\n"); 
    } else 
	fprintf(plot, "set xlabel \"Trials\"\n");

    fprintf(plot, "set ylabel \"Throughput (Mbps)\"\n");

    fprintf(plot, "set title \"UDP communication \\n ");
    fprintf(plot, "Buffer size: %d   Datagram (packet) size: %d\\n Hosts: %s <--> %s\"\n", 
	    buffsize, packetsize, localhost, hostname);
    if ( exp_mode )
        fprintf(plot, "plot \'%s\' us 2:3 ti \'Network\' w lp, \'%s\' us 2:4 ti \'Localhost\' w lp\n",
	        filename, filename);
    else 
        fprintf(plot, "plot \'%s\' us 1:2 ti \'Network\' w lp, \'%s\' us 1:3 ti \'Localhost\' w lp\n",
	        filename, filename);
    fprintf(plot, "pause -1 \"\\n Ctrl^c to exit.\\n ");
    fprintf(plot, "Push return to create postscript (ps, eps) files.\\n\\n\"\n");

    /****  for postscript (ps) and encapsulated postscript (eps) format  ***/

    fprintf(plot, "set output \"%s.ps\"\n", filename);
    fprintf(plot, "set term post color\n");
    fprintf(plot, "replot\n");
    fprintf(plot, "set output \"%s.eps\"\n", filename);
    fprintf(plot, "set term post eps\n");
    fprintf(plot, "replot\n");
    fprintf(plot, "clear\n");

    fclose(plot);
    return OK;
}
