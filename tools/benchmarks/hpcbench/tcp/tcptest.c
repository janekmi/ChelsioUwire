
/***************************************************************************/
/**                                                                       **/
/**         TCP communication benchmark                                   **/
/**         By Ben Huang, hben@users.sf.net March 2004                    **/
/**         TCP latency/throughput test between two processes             **/
/**                                                                       **/
/**         "tcptest.c"                                                   **/
/**                                                                       **/
/***************************************************************************/ 


#include "tcplib.h"
#include "util.h"

/************************** Function prototypes ****************************/

static void init_data();                             // Variable initialization
static void parse_command(int, char **, int *);      // Parse command line
static void sig_handler(int);                        // Signals handler     
static status_t client_shutdown();                   // Close the socket connections
static int tcp_pretest();                            // Estimation test 
static void tcp_ping();                              // RTT latency test
static void print_ping_result();                     // Print out the RTT test results
static void qos_type(struct TCPconnection *, char *);// Get the IP TOS information
static int read_file( const char *, int *);          // Read a file for sendfile() test
static status_t write_plot();                        // Write plot file for gnuplot

/************************** Global variables *******************************/

static char hostname[BUFLEN];              // Server  
static char localhost[BUFLEN];             // Local host
static char filename[BUFLEN];              // Output file
static char sfilename[BUFLEN];             // File name to read for sendfile() test
static char curtime[BUFLEN];               // Time of testing
static char plotname[BUFLEN];              // Plot file for gnuplot
static FILE *output;                       // Output file

static struct Parameter setting;           // TCP test settings
static struct TCPconnection controlSock;   // TCP control(data) channel
static struct TCPconnection testSock;      // TCP test channel
static struct TCPconnection server;        // Hold the server's configuration
static struct Throughput throughput;       // Network throughputs
static struct RTT rtt;                     // Round Trip Time results


/*************************** Mian function *********************************/

int main(int argc, char *argv[]) 
{      
    char buff[BUFLEN], sysbuff[2*BUFLEN];               
    short *ptr;    
    int i, testMode, fileSize, iteration, stream_mode;   
    double bandwidth;                      // Network throughput
    int preIteration = 1;                  // The preious interation (exponential test)
    long_int preSize = 1;                  // The previous data size (exponential test)
    long_int messageSize = 0;              // Message size               
    long_int time_usec = 0;                // Elapsed time in microsecond
    long_int s_rtime_usec = 0;             // Server's elapsed time
    long_int s_utime_usec = 0;             // Server's process time in user mode
    long_int s_stime_usec = 0;             // Server's process time in system mode
    long_int totalBytes;                   // Total sent bytes
    struct SYSInfo * sysinfo = NULL;       // System (CPU/Interrupts) information
    struct SYSInfo * serverinfo = NULL;    // Server's system information
    struct PROInfo proinfo;                // Process information
 
    /**************** At least given server name ***************************/

    if ( argc > 1 && strcmp(argv[1], "--help")==0 ) {
	fprintf(stderr, help_description);
	fprintf(stderr, help_usage, DEFAULTPORT, DEFAULTSIZE, DEFAULTPORT,  
		DEFAULTREPEAT, DEFAULTTIME);
	fprintf(stderr, help_example);
	return 1;
    } else if ( argc < 3 ) {
	print_usage();
	return 1;
    }
    
    /************** Initialization of controlSock, testSock and rtt ********/

    init_data();

   /********************** Parsing the command line ************************/

    parse_command(argc, argv, &testMode);

    iteration = setting.iteration;
    messageSize = setting.messageSize;
    stream_mode = setting.stream_mode;
	
    if ( setting.sendfile_test ) { 
	
	/***************** Read the file for sendfile() test ***************/
	
	if ( (testSock.fd = read_file(sfilename, &fileSize)) < 0 ) {
	    fprintf(stderr, "Read file error.\n");
	    exit(1);
	}
	if ( fileSize < testSock.dataSize ) // send size should be less than file size 
	    testSock.dataSize = fileSize;

    } 

    /******************* Check the write file option  **********************/
	
    if ( setting.writeOption ) {
	if ( (output = fopen(filename, "w")) == NULL ) {
	    fprintf(stderr, "%s: Unable to write the file!\n", filename);
	    setting.writeOption = 0; 
	} 
    }

    /*************************** Handle the interruption *******************/
    
    signal(SIGINT, sig_handler);  
    
    /******** Client initialize communication and connect to server ********/

    if ( client_connect(hostname, &controlSock) == NOTOK) {
	fprintf(stderr, "%s : %d\n", hostname, controlSock.port);
	perror("Unable to establish data connection.");
	exit(1);
    }

    /*************** Allocate memory to hold system information ************/
    
    if ( setting.CPUoption ) { 

	/***** Two more items to record the syslog of pre/post states ******/

	if ( (sysinfo = (struct SYSInfo *)malloc((setting.repeat+2) 
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

    /******************* Inform server the test options ********************/

    sprintf(buff, client_request_str, testMode, testSock.blocking, testSock.delay, 
	    testSock.cork, stream_mode, server.recvBuf, server.sendBuf, 
	    testSock.mss, testSock.tos, testSock.dataSize, setting.CPUoption);
    if ( send_request(controlSock.socket, buff, strlen(buff)) == NOTOK ) {
	fprintf(stderr, "Send TCP options error: %s...exiting!\n", buff);
	exit (1);
    }

    if ( gethostname(localhost, BUFLEN) < 0 ) {
	perror("gethostname.");
	strcpy(localhost, "Localhost");
    }

    /*************** Print out the connection message **********************/

    if ( setting.verbose ) {
	if ( setting.sendfile_test )
	    strcpy(buff, "Throughput test with sendfile");
	else 
	    strcpy(buff, setting.latency_test ? "Latency(RTT) test":"Throughput test");
	fprintf(stderr, "[%s]  %s[local] <--> %s[server] \n", buff, localhost, hostname);
    }

    /*********** Get server's test channel's port number *******************/

    bzero(buff, BUFLEN);
    if ( get_request(&controlSock, buff) == NOTOK || 
	 sscanf(buff, server_port_str, &testSock.port) != 1 ) {
	perror("Failed to get server's test channel port number.");
	fprintf(stderr," %s\n", buff);
	exit (1);
    }

    /**************** Establish test channel connection ********************/

    if ( client_connect(hostname, &testSock) == NOTOK ) {
	perror("Unable to establish connection.");
	fprintf(stderr, "%s : %d\n", hostname, testSock.port);
	exit(1);
    }
    
    /************** Receive server test channel configurations *************/

    bzero(buff, BUFLEN);
    if ( get_request(&controlSock, buff) == NOTOK || 
	 sscanf(buff, server_parameter_str, &server.blocking, &server.delay, 
		&server.cork, &server.recvBuf, &server.sendBuf, 
		&server.mss, &server.tos, &setting.sCPUoption) != 8 ) {
	perror("Failed to receive server's response.");
	fprintf(stderr," %s\n", buff);
	exit (1);
    }

    /********** Print out the test channel connection details **************/

    if ( setting.verbose  ) {
	fprintf(stderr, "Control-port[%d] Test-port[%d] Recv-buffer[%d] Send-buffer[%d] MSS[%d]\n", 
		controlSock.port, testSock.port, testSock.recvBuf, testSock.sendBuf, testSock.mss);
	fprintf(stderr, "%s  %s  %s  %s\n", stream_mode ? 
		"Stream-test[Unidirectional]":"Pingpong-test[Bidirectional]",
		testSock.blocking ? "Blocking[ON]":"Blocking[OFF]", 
		testSock.delay ? "TCP_NODELAY[OFF]":"TCP_NODELAY[ON]",
		testSock.cork ? "TCP_CORK[ON]":"TCP_CORK[OFF]");
    }

    /*********** Allocate memory for sending/receiving data ****************/

    if ( (rbuffer = (char *)malloc(testSock.dataSize)) == NULL ||
	 (sbuffer = (char *)malloc(testSock.dataSize)) == NULL ) {
	fprintf(stderr, "Could not malloc memory! buffer size: %lld\n", testSock.dataSize);
	client_shutdown();
	exit(1);
    }    

    /****** Randomize the buffer to prevent possible data compression ******/
    
    srand(time(NULL));
    for ( ptr = (short *)sbuffer; ptr < (short *)(sbuffer+testSock.dataSize); ptr +=2 )
	*ptr = (short)rand();   

    /**************************** RTT(latency) test ************************/

    if ( setting.latency_test ) {
	tcp_ping();
	print_ping_result();
	client_shutdown();
	return 0;
    } 

    /**************************** Throughput test **************************/


    /** We need another container to hold server's system info if defined **/

    if ( setting.sCPUoption ) { // Server also monitor the system resource
	if ( (serverinfo = (struct SYSInfo *)malloc((setting.repeat+2) 
			    * sizeof(struct SYSInfo))) == NULL ) {
	    perror("Failed to malloc.");
	    exit(1);
	}
	bzero(buff, BUFLEN);
	if ( get_request(&controlSock, sysbuff) == NOTOK ||
	     string_to_sysinfo( &serverinfo[0], sysbuff, 2*BUFLEN) == NOTOK ) {
	    perror("Failed to get server's initial system information.");
	    exit (1);
	}
    }

    /********** Determine the iteration for fixed size throughput test *****/

    if ( !setting.exp_mode && iteration <= 0 ) {
	if ( setting.verbose )
	    fprintf(stderr, "Estimating network throughput...\n");

	if ( tcp_pretest(messageSize, stream_mode, &iteration, &time_usec) == NOTOK ) {
	    fprintf(stderr, "Pre-test error.\n");
	    return 1;
	}

	/* Compute the iteration for throughput test by the defined test time */
	else {  // Throughput test
	    if ( setting.testTime < 1 ) {   // We don't accept a very small test time.
		setting.testTime = DEFAULTTIME;
		iteration = (int) 1000000LL * iteration * setting.testTime / time_usec;
		if ( setting.verbose ) {
		    fprintf(stderr, "Input time interval for each testing is too small! ");
		    fprintf(stderr, "Using default test time instead: %2.3f seconds\n", 
			    setting.testTime);
		}
	    } else 
		iteration = (int) 1000000LL * iteration * setting.testTime / time_usec;
	    if ( iteration < MINITRIALS ) // Minimum iteration
		iteration = MINITRIALS; 
	} 
	if ( setting.verbose )
	    fprintf(stderr, "Iteration for the defined time: %d\n", iteration);
    } 

    /**** write test information to the file for throughput test ***********/	

    if ( setting.writeOption) {
	
	/************* Printout the host and time information **************/ 

	get_local_time(curtime, BUFLEN);

	fprintf(output, "# TCP communication test -- %s\n", curtime);
	fprintf(output, "# Hosts: %s (client) <----> %s (server)\n", localhost, hostname);
	if ( setting.sendfile_test )
	    fprintf(output, "# TCP sendfile() (unidirectional) test.\n");
	else 
	    fprintf(output, "# TCP test mode: %s %s test\n", 
		    stream_mode ? "stream(unidirectional)":"ping-pong(bidirectional)", 
		    setting.exp_mode ? "exponential throughput" : "throughput");
	fprintf(output, "# Socket Recv-buffer (Bytes) -- client: %d  server: %d\n", 
		testSock.recvBuf, server.recvBuf);
	fprintf(output, "# Socket Send-buffer (Bytes) -- client: %d  server: %d\n", 
		testSock.sendBuf, server.sendBuf);
	fprintf(output, "# Socket blocking option -- client: %s  server: %s\n", 
		testSock.blocking ? "ON":"OFF", server.blocking ? "ON":"OFF");
	fprintf(output, "# TCP_NODELAY option -- client: %s  server: %s\n", 
		testSock.delay ? "OFF":"ON", server.delay ? "OFF":"ON");
	fprintf(output, "# TCP_CORK option -- client: %s  server: %s\n", 
		testSock.cork ? "ON":"OFF", server.cork ? "ON":"OFF");
	fprintf(output, "# TCP Maximum-segment-size(MSS) (Bytes) -- client: %d  server: %d\n", 
		testSock.mss, server.mss); 
	qos_type(&testSock, buff);
	fprintf(output, "# IP TOS type -- client: %s ", buff);
	qos_type(&server, buff);
	fprintf(output, "server: %s\n", buff);
	if ( setting.exp_mode ) {
	    fprintf(output, "\n# Data-size  Network-hroughput   Elapsed-time   Iteration\n");
	    fprintf(output, "#  (Bytes)        (Mbps)           (Seconds)    \n");
	} else {
	    fprintf(output, "# Data size of each read/write (Bytes): %lld\n", testSock.dataSize);
	    fprintf(output, "# Total data size sent of each test (Bytes): %lld\n", messageSize*iteration);
	    fprintf(output, "# Message size (Bytes): %lld\n", messageSize);
	    fprintf(output, "# Iteration: %d\n# Test Repetition: %d\n\n", iteration, setting.repeat);
	    fprintf(output, "#        Network      Client     C-process   C-process      Server     S-process   S-process\n");
	    fprintf(output, "#      Throughput  Elapsed-time  User-mode  System-mode  Elapsed-time  User-mode  System-mode\n");
	    fprintf(output, "#         (Mbps)    (Seconds)    (Seconds)   (Seconds)    (Seconds)    (Seconds)   (Seconds)\n");
      	}
    }

    /*********************** Start throughput test *************************/
	    
    for ( i = 0; i < setting.repeat; i++ ) {

	if ( setting.exp_mode ) {   // Initialization for exponential test
	    messageSize = (1<<i);
	    if ( i == 0 )
		iteration = MAXTRIALS;
	    else            // Compute the iteration by the previous test
		iteration = preSize*preIteration*1000000.0*setting.testTime
		            /time_usec/messageSize;
	    if ( iteration < MINITRIALS )
		iteration = MINITRIALS; 
	    if ( iteration > MAXTRIALS )
		iteration  = MAXTRIALS;

	} // end of exp_mode setting

	/********** Inform server the test size and iteration **************/
	    
	sprintf(buff, test_start_str, messageSize, iteration);
	if ( send_request(controlSock.socket, buff, strlen(buff)) == NOTOK ) {
	    perror("Error of sending request to server.");
	    client_shutdown();
	    exit(1);
	}
	
	/************** Monitor system information if defined **************/

	if ( setting.CPUoption )
	    start_trace_system( &sysinfo[i+1] );

	/******* We trace process information before and after test ********/
	/** After test we will get a "test done" confirmation from server **/

	start_trace_process( &proinfo );
	if ( client_tcp_test ( messageSize, iteration, stream_mode, &time_usec, &testSock) 
	     == NOTOK || get_request(&controlSock, buff) == NOTOK || 
	     strncmp(buff, test_done_str, 9) != 0 ) { 
	    fprintf(stderr, " TCP communication Error. %s\n", buff);
	    client_shutdown();
	    exit (1);
	}
	stop_trace_process( &proinfo );

	if ( setting.CPUoption ) {
	    usleep(1000); // wait a while for the data to be updated
	    stop_trace_system( &sysinfo[i+1] );
	}

	/******* Receive server's process information of the test **********/

	if ( get_request(&controlSock, buff) == NOTOK || 
	     sscanf(buff, server_proinfo_str, &s_rtime_usec, &s_utime_usec,
		    &s_stime_usec) != 3 ) {
	    perror("Failed to get server's process information.");
	    exit (1);
	}

	if ( setting.sCPUoption ) { // Receive server's system information if defined
	    bzero(buff, BUFLEN);
	    if ( get_request(&controlSock, sysbuff) == NOTOK ||
		 string_to_sysinfo( &serverinfo[i+1], sysbuff, 2*BUFLEN) == NOTOK ) {
		perror("Failed to get server's system information.");
		exit (1);
	    }
	}
	
	/********************* Compute the throughput **********************/
	
	if ( time_usec < 10 ) {
	    time_usec = 1;
	    preIteration = iteration * 10;
	    if ( setting.verbose )
		fprintf(stderr, "Test time too short. Ignore the results.\n");
	    continue;
	}
	
	throughput.trial++;        
	totalBytes = stream_mode ? messageSize*iteration : messageSize*2*iteration; 
	bandwidth =  totalBytes * 8.0  / time_usec;  //Mbps

	if (setting.verbose)
	    fprintf(stderr, "%s test. Message-size: %lld  Iteration: %d (Total: %lld Bytes)\n", 
		    stream_mode ? "Stream":"Ping-pong", messageSize, iteration, totalBytes);
	
	/************ Record the minimum and maximum throughputs ***********/
	
	if ( throughput.min > bandwidth )
	    throughput.min = bandwidth;
	if ( throughput.max < bandwidth )
	    throughput.max = bandwidth;
	throughput.sum += bandwidth;

	if ( setting.verbose ) { 
	    fprintf(stderr, "Elapsed-time : %f Seconds   Network-throughput : %f Mbps\n", 
		    time_usec/1000000.0, bandwidth);
	} else 
	    fprintf(stderr, " (%d) : %f Mbps\n", i+1, bandwidth);
	
	/***************** Write down the results to a file  ***************/
	
	if ( setting.exp_mode) {
	    preSize = messageSize;
	    preIteration = iteration;
	    if ( setting.writeOption )
		fprintf(output, "%10lld%15.4f%18.5f%11d\n",
			messageSize, bandwidth, time_usec/1000000.0, iteration);
	} else if ( setting.writeOption )
	    fprintf(output, "%-4d%12.3f%12.2f%13.2f%12.2f%13.2f%13.2f%12.2f\n", i+1, bandwidth, 
		    time_usec/1000000.0, (double)proinfo.utime_sec + proinfo.utime_usec/1000000.0,
		    (double)proinfo.stime_sec + proinfo.stime_usec/1000000.0, s_rtime_usec/1000000.0,
		     s_utime_usec/1000000.0,  s_stime_usec/1000000.0);

    } // end of for loop of setting.repeat 

    /******************** All tests have finished **************************/
    /******** Inform server that current session will be ended *************/

    strcpy(buff, test_done_str);
    if ( send_request(controlSock.socket, buff, strlen(buff)) == NOTOK ) {
	perror("Failed to send end-of-session to server.");
	client_shutdown();
	exit(1);
    }
    if ( setting.CPUoption ) { // record the post-test system info for comparison
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
	    bzero(buff, BUFLEN);
	    if ( get_request(&controlSock, sysbuff) == NOTOK ||
		 string_to_sysinfo( &serverinfo[setting.repeat+1], sysbuff, 2*BUFLEN) == NOTOK ) {
		perror("Failed to get server's last syslog.");
		exit (1);
	    }
	}
    }

    if ( !setting.exp_mode && setting.writeOption && throughput.trial > 3 ) {

	/****** We eliminate the maximum and the minimum results ***********/

	throughput.sum = throughput.sum - throughput.min - throughput.max; 
	fprintf(output, "\n# Throughput statistics : Average %8.4f   Minimum %8.4f   Maximum %8.4f\n", 
		throughput.sum/(throughput.trial-2), throughput.min, throughput.max);
    }

    if ( setting.writeOption ) {
	fprintf(stderr, "Test done!\nTest-result: \"%s\" %s", 
		filename, setting.CPUoption? " ":"\n");
	if ( setting.CPUoption ) {
	    strcpy(buff, filename);
	    strcat(buff, ".c_log");
	    if ( write_sys_info(sysinfo, setting.repeat+2, buff, curtime, localhost)== OK )
		fprintf(stderr, "Local-syslog: \"%s\"  ", buff); 
	    strcpy(buff, filename);
	    strcat(buff, ".s_log");
	    if ( write_sys_info(serverinfo, setting.repeat+2, buff, curtime, hostname) == OK )
		fprintf(stderr, "server-syslog: \"%s\"\n", buff); 
	}	
	if ( setting.plotOption && write_plot() == OK ) { 
	    fprintf(stderr, "Plot-file: \"%s\". ", plotname);
	    fprintf(stderr, "Use \"gnuplot %s\" to plot the data\n", plotname);
	}
	fclose(output);
    } else 
	fprintf(stderr, "Test done!\n");

    client_shutdown();
    return 0;

}  // end of main function


/*************************** Structures initialization *********************/

static void init_data() 
{
    /************************ Clean the char arrays ************************/

    bzero(hostname, BUFLEN);
    bzero(filename, BUFLEN);
    bzero(sfilename, BUFLEN);
    bzero(plotname, BUFLEN);
    bzero(localhost, BUFLEN);

    /****************** Default test mode  setting *************************/

    setting.verbose = 0;            // Disable printing out detail message   
    setting.latency_test = 0;       // Throughput test by default
    setting.stream_mode = 1;        // One-way stream test by default
    setting.exp_mode = 0;           // Not an esponential test
    setting.writeOption = 0;        // Don't write results to a file
    setting.CPUoption = 0;          // Don't monitor local system information 
    setting.sCPUoption = 0;         // Don't monitor server system information

    setting.repeat = DEFAULTREPEAT;    // 10 times (defined in tcplib.h)
    setting.messageSize = DEFAULTSIZE; // 64k (defined in tcplib.h)
    setting.testTime = DEFAULTTIME;    // 5 seconds (defined in tcplib.h)

    /**************** TCP connections' variables initialization ************/

    /**************** TCP control channel default setting ******************/

    controlSock.port = DEFAULTPORT;  // Control channel TCP port number 
    controlSock.dataSize = 8192;     // Default sending/receiving size
    controlSock.blocking = 1;        // Blocking communication
    controlSock.delay = 0;           // Set TCP_NODELAY
    controlSock.tos = 0;             // No TOS setting
    controlSock.cork = 0;            // No TCP_CORK setting
    controlSock.mss = -1;            // Use default 
    controlSock.recvBuf = -1;        // Use default
    controlSock.sendBuf = -1;        // Use default

    /**************** TCP test channel default setting *********************/

    testSock.fd = -1;                // No file descriptor for sendfile() test
    testSock.port = 0;               // Pick by system
    testSock.blocking = 1;           // Blocking communicaiton by default
    testSock.delay = 1;              // Don't set TCP_NODELAY by default
    testSock.cork = 0;               // Don't set TCP_CORK by default
    testSock.tos = 0;                // Use system default TOS setting (0)
    testSock.mss = -1;               // Don't set MTU size
    testSock.dataSize = 8192;        // Default read/write size 
    testSock.recvBuf = -1;           // Use system default socket buffer size
    testSock.sendBuf = -1;           // Use system default socket buffer size

    /************ Server test channel TCP socket buffer size setting *******/

    server.recvBuf = -1;             // Use system default socket buffer size
    server.sendBuf = -1;             // Use system default socket buffer size
 
     
    /****************** RTTs and Throughputs initialization ****************/

    rtt.mode = 0, rtt.size = DEFAULTRTT, rtt.trial= 0;
    rtt.min = MAXNUMBER, rtt.max = 0, rtt.sum = 0, rtt.avg = 0;
    throughput.min = MAXNUMBER, throughput.max = 0;
    throughput.sum = 0, throughput.avg = 0, throughput.trial = 0; 
    
    return;
}


/************************ Parse the command line ***************************/

static void parse_command(int argc, char *argv[], int *testMode) 
{
    int option;
    long_int size;

    while ( (option = getopt (argc, argv, ":acinvCNPe:h:f:p:q:A:b:B:m:M:d:r:t:I:o:")) != -1) {
	switch ( option ) {
	case 'a':  /* RTT (latency) test (TCP ping) */
	    setting.latency_test = rtt.mode = 1;
	    break;
	case 'A':  /* message size for RTT test */
	    setting.latency_test = rtt.mode = 1;
	    rtt.size = (int) parse_size(optarg);
	    if ( rtt.size < 1 )
		rtt.size = 2;
	    break;
	case 'b':  /* client TCP buffer size */
	    if ( (size = parse_size(optarg)) >= 0 ) {
		testSock.recvBuf = (int) size;
		testSock.sendBuf = testSock.recvBuf;
	    }
	    break;
	case 'B':  /* Server TCP buffer size */
	    if ( (size = (int)parse_size(optarg)) >=0 ) {
		server.recvBuf = size;
		server.sendBuf = size;
	    }
	    break;
	case 'c':  /* Monitor CPU and system loads */
	    setting.CPUoption = 1;
	    break;
	case 'C':  /* TCP_CORK option */
	    testSock.cork = 1;
	    break;
	case 'd':  /* dataSize of each read/write */
	    if ( (size = parse_size(optarg)) > 0)
		testSock.dataSize = size;
	    break;
	case 'e':  /* exponential test */
	    setting.exponent = atoi(optarg);
	    if ( setting.exponent < 2 || setting.exponent > 30 )
		setting.exponent = MAXLEN;
	    setting.exp_mode = 1;
	    break;
	case 'f':  /* Linux sendfile() test */
	    setting.sendfile_test = 1;
	    strcpy(sfilename, optarg);
	    break;
	case 'h':  /* server host name or IP address */
	    strcpy (hostname, optarg);
	    break;
	case 'i':  /* Ping-pong (bidirectional) test */
	    setting.stream_mode = 0;
	    break;
	case 'I':  /* iteration of sending/receiving */
	    if ( (size = parse_size(optarg)) > 0)
		setting.iteration = (int)size;
	    break;
	case 'm':  /* message size */
	    setting.messageSize = parse_size(optarg);
	    break;
	case 'M':  /* MSS(Maximum Segment Size) */
	    testSock.mss = (int)parse_size(optarg);
	    break;
	case 'n':  /* non-blocking communication */
	    testSock.blocking = 0;
	    break;
	case 'N':  /* turn off Negle algorithm (turn on TCP_NODELAY option) */
	    testSock.delay = 0;
	    break;
	case 'o':  /* write test results to a file */
	    strcpy(filename, optarg);
	    setting.writeOption = 1;
	    break;
	case 'p':  /* port number */
	    controlSock.port = atoi(optarg);
	    break;
	case 'P':  /* write plot file */
	    setting.plotOption = 1;
	    break;
	case 'q':  /* Qos (TOS) setting */
	    if ( (size = parse_size(optarg)) > 0) {
		switch (size) {
		case 1:  /* Minimize delay */
		    testSock.tos = TOS_LOWDELAY;
		    break;
		case 2:  /* Maximize throughput */
		    testSock.tos = TOS_MAXTP;
		    break;
		case 3:  /* DiffServ Class1 with low drop probability */
		    testSock.tos = DSCP_C1_DL;
		    break;
		case 4:  /* DiffServ Class1 with high drop probability */
		    testSock.tos = DSCP_C1_DH;
		    break;
		case 5:  /* DiffServ Class4 with low drop probability */
		    testSock.tos = DSCP_C4_DL;
		    break;
		case 6:  /* DiffServ Class4 with high drop probability */
		    testSock.tos = DSCP_C4_DH;
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
	case 't':  /* test time */
	    if ( (size = parse_size(optarg)) > 0)
		setting.testTime = atof(optarg);
	    break;
	case 'v':  /* print out connection message */
	    setting.verbose = 1;
	    break;
	case ':':  
	    fprintf(stderr,"Error: -%c without argument\n", optopt);
	    print_usage();
	    exit (1);
	case '?':
	    fprintf(stderr,"Error: Unknown argument %c\n", optopt);
	    print_usage();
	    exit(1);
	default: 
	    print_usage();
	    exit(1);
	}
    }
    
    /****** Make sure all test parameters (modes) are consistant ************/

    if ( setting.latency_test ) { // RTT(latency) test 
	*testMode = LATENCY;
	setting.CPUoption = 0;    // Don't monitor system loads
	setting.stream_mode = 0;  // latency test is always bidirectional 
	testSock.blocking = 1;    // blocking communication
	testSock.cork = 0;        // send paritial frame
	testSock.delay = 0;       // send immediately
	testSock.dataSize = rtt.size;
	setting.messageSize = rtt.size;
    } else if ( setting.sendfile_test ) { // sendfile test is unidirectional and blocking 
	*testMode = SENDFILE;
	setting.stream_mode = 1;
	testSock.blocking = 1;
    } else { // throuhgput test 
	*testMode = THROUGHPUT;
	if ( testSock.dataSize > setting.messageSize )
	    testSock.dataSize = setting.messageSize;
    }

    if ( setting.exp_mode ) // message size from 1, 2, 4...2^exponent
	setting.repeat = setting.exponent + 1;
    
    if ( !testSock.delay && testSock.cork ) { // TCP_CORK is anti-TCP_NODELAY
	testSock.cork = 0;
	if ( setting.verbose ) {
	    fprintf(stderr, "Couldn't combine both TCP_NODELAY and TCP_CORK option.\n");
	    fprintf(stderr, "Ignore TCP_CORK option");
	}
    }

    /* Server has the the same buffer size with client if they are not defined */

    if ( server.recvBuf < 0 && testSock.recvBuf > 0 ) { 
	server.recvBuf = testSock.recvBuf;
	server.sendBuf = testSock.sendBuf;
    }

    return;
}


/************** Show the QoS type setting in IP TOS fields *****************/

static void qos_type(struct TCPconnection * sock, char * buff ) 
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


/************************** Interrupt handler ******************************/

static void sig_handler(int sig_num) 
{
    if ( rtt.mode)
	print_ping_result();
    client_shutdown();
    exit(sig_num);
}


/********************** Clean up client's connection ***********************/

static status_t client_shutdown() 
{
    close(controlSock.socket);
    close(testSock.socket); 
    free(sbuffer);
    free(rbuffer);
    return OK;
}


/*** TCP pretest is to evaluate the iteration for a desired test time ******/
/*** A minimum test time should be achieved to avoid the timing effect *****/

static status_t tcp_pretest(long_int messageSize, int stream_mode, 
			    int *iteration, long_int *usec)
{
    char buff[BUFLEN], sysbuff[2*BUFLEN];
    long_int time_usec;
    int trial;
    struct SYSInfo sysinfo;
    long_int s_rtime_usec, s_utime_usec, s_stime_usec;
   
    if ( messageSize > 10000000 ) { 
	trial = MINITRIALS;
    } else if ( messageSize > 500000 ) {
	trial = 2 * MINITRIALS;
    } else if ( messageSize > 50000 ) {
	trial = 4 * MINITRIALS;
    } else if ( messageSize < 100 ) {
	trial = MAXTRIALS;
    } else { //100-50k
	trial = 20 * MINITRIALS;
    }
  
    /*************************** Warm up ***********************************/
    
    sprintf(buff, test_start_str, messageSize, trial);
    if ( send_request(controlSock.socket, buff, strlen(buff)) == NOTOK ) {
	perror("Error of sending request to server.");
	return NOTOK;
    }

    bzero(buff, BUFLEN);
    if ( client_tcp_test(messageSize, trial, stream_mode, &time_usec, &testSock) == NOTOK 
	 || get_request(&controlSock, buff) == NOTOK || strncmp(buff, test_done_str, 9) != 0 ) { 
	perror("TCP communication error.\n");
	client_shutdown();
	return NOTOK;
    }
    if ( get_request(&controlSock, buff) == NOTOK || 
	 sscanf(buff, server_proinfo_str, &s_rtime_usec, &s_utime_usec, &s_stime_usec) != 3 ) {
	perror("Failed to get server's process information.");
	return NOTOK;
    }
    if ( setting.sCPUoption ) {  // We need to get server's syslog as well if defined
	bzero(buff, BUFLEN);
	if ( get_request(&controlSock, sysbuff) == NOTOK ||
	     string_to_sysinfo( &sysinfo, sysbuff, 2*BUFLEN) == NOTOK ) {
	    perror("Failed to get server's system information.");
	    return NOTOK;
	}
    }
    time_usec = 0;
    
    /*************** Make sure the elapsed time is long enough *************/
    
    while ( time_usec < MINITIME ) { // 0.1 second

	sprintf(buff, test_start_str, messageSize, trial);
	if ( send_request(controlSock.socket, buff, strlen(buff)) == NOTOK ) {
	    perror("Error of sending request to server.");
	    return NOTOK;
	}
	
	bzero(buff, BUFLEN);
	if ( client_tcp_test(messageSize, trial, stream_mode, &time_usec, &testSock) == NOTOK 
	     || get_request(&controlSock, buff) == NOTOK || strncmp(buff, test_done_str, 9) != 0 ) { 
	    perror("TCP communication error.\n");
	    client_shutdown();
	    return NOTOK;
	} 
	if ( get_request(&controlSock, buff) == NOTOK || 
	     sscanf(buff, server_proinfo_str, &s_rtime_usec, &s_utime_usec,
		    &s_stime_usec) != 3 ) {
	    perror("Failed to get server's process information.");
	    return NOTOK;
	}
	if ( setting.sCPUoption ) {  // We need to get server's syslog as well if defined
	    bzero(buff, BUFLEN);
	    if ( get_request(&controlSock, sysbuff) == NOTOK ||
		 string_to_sysinfo( &sysinfo, sysbuff, 2*BUFLEN) == NOTOK ) {
		perror("Failed to get server's system information.");
		return NOTOK;
	    }
	}
	if ( time_usec > MINITIME ) // Make sure the test time is long enough
	    break;
	else 
	    trial *= 10;
	usleep(1000);
    
    } // end of while loop

    *iteration = trial;
    *usec = time_usec;

    return OK;
}


/***************** TCP ping (RTT latency test) *****************************/
/* The network latency in HPC environtments is too little to be measured, so
 * we repeat the RTT test for many times (the value of iteration) and compute
 * the mean as results.
 */

static void tcp_ping() 
{
    char buff[BUFLEN];
    int i, trial, iteration;
    long_int time_usec = 0;
    double latency;
    int verbose = setting.verbose;
    int repeat = setting.repeat;
    long_int messageSize = rtt.size;
    int stream_mode = 0;

    /******** Obtain the iteration number for a minimum test time **********/
    /******** Double the iteration for at most 20 times (2^20=2M) **********/
    
    trial = 2; // start from a small size
    for ( i = 1; time_usec < MINITIME && i < 20; i++ ) {
	sprintf(buff, test_start_str, messageSize, trial);	
	if ( send_request(controlSock.socket, buff, strlen(buff)) == NOTOK ) { 
	    perror("Failed to send a request to server.");
	    client_shutdown();
	    exit (1);
	}
	if ( client_tcp_test( messageSize, trial, stream_mode, &time_usec, &testSock) == NOTOK
	     || get_request(&controlSock, buff) == NOTOK 
	     || strncmp(buff, test_done_str, 9) != 0 ) {
	    perror("TCP communication Error (pretest).");
	    printf("buff: %s\n", buff);
	    exit (1);
	}
	if ( time_usec >= MINITIME )
	    break;
	trial *=2;
    } 
    if ( i == 20 ) { // Too many trials and 
	perror("TCP ping pre-test error (Too many trials).");
	exit (1);
    }
    iteration = trial;

    if ( verbose )
	fprintf(stderr, "Iteration for RTT test: %d\n", iteration);

    if ( setting.writeOption ) {
	get_local_time(curtime, BUFLEN);
	fprintf(output, "# TCP roundtrip time test %s\n", curtime);
	fprintf(output, "# %s <--> %s\n", localhost, hostname);
	fprintf(output, "# TCP-send-buffer: %d TCP-recv-buffer: %d\n", 
		testSock.sendBuf, testSock.recvBuf);
	fprintf(output, "# Message-size: %d Iteration: %d\n", rtt.size, iteration);
    }
    
    /******************** Start latency test (TCP ping) ********************/

    for ( i = 1; i <= repeat; i++ ) { // Keep testing
	sprintf(buff, test_start_str, messageSize, iteration);
	if ( send_request(controlSock.socket, buff, strlen(buff)) == NOTOK ) {
	    perror("Error of sending request to server");
	    exit (1);
	}
	bzero(buff, BUFLEN);
	if ( client_tcp_test(messageSize, iteration, stream_mode, &time_usec, &testSock) == NOTOK
	     || get_request(&controlSock, buff) == NOTOK 
	     || strncmp(buff, test_done_str, 9) != 0 ) {
	    perror("TCP communication Error");
	    exit (1);
	} else
	    latency = time_usec * 1.0 / iteration;
	
	rtt.trial++;
	rtt.sum += latency;
	rtt.avg = rtt.sum/rtt.trial;
	if ( rtt.min > latency) // Minimum
	    rtt.min = latency;
	if ( rtt.max < latency) // Maximum
	    rtt.max = latency;
	if ( latency > 1000 ) {
	    fprintf(stderr, "TCP Round Trip Time (%d) : %6.3f msec\n", i, latency/1000);
	    if ( setting.writeOption )
		fprintf(output, "TCP Round Trip Time (%d) : %6.3f msec\n", i, latency/1000);
	} else {
	    fprintf(stderr, "TCP Round Trip Time (%d) : %6.3f usec\n", i, latency);
	    if ( setting.writeOption )
		fprintf(output, "TCP Round Trip Time (%d) : %6.3f usec\n", i, latency);
	}
	sleep (1);
    }
    
    return;
}


/********************* Print out the RTT(latency) test results *************/

static void print_ping_result()
{
    fprintf(stderr, "%d trials with message size %d Bytes.\n", rtt.trial, rtt.size);
    if ( setting.writeOption )
	fprintf(output, "%d trials with message size %d Bytes.\n", rtt.trial, rtt.size);

    if ( rtt.avg > 1000 ) {
	fprintf(stderr, "TCP RTT min/avg/max = %6.3f/%6.3f/%6.3f msec\n", 
		rtt.min/1000, rtt.avg/1000, rtt.max/1000);
	if ( setting.writeOption )
	    fprintf(output, "TCP RTT (%d-byte) min/avg/max = %6.3f/%6.3f/%6.3f msec\n", 
		    rtt.size, rtt.min/1000, rtt.avg/1000, rtt.max/1000);
    } else {
	fprintf(stderr, "TCP RTT min/avg/max = %6.3f/%6.3f/%6.3f usec\n", 
		rtt.min, rtt.avg, rtt.max);
	if ( setting.writeOption )
	    fprintf(output, "TCP RTT (%d-byte) min/avg/max = %6.3f/%6.3f/%6.3f usec\n", 
		    rtt.size, rtt.min, rtt.avg, rtt.max);
    }
    return;
}


/******************* Read a file for sendfile() test ***********************/
/** Some systems cache the data in memory when file is currently accessed **/

static int read_file( const char * fileName, int *fileSize)
{
	int rval, fileFd;
	char buff[BUFLEN*8];
	struct stat fileStat;

	if ( (fileFd = open(fileName, O_RDONLY)) < 0 ) {
	    perror("Open file");
	    return -1;
	}

	if ( (rval = fstat(fileFd, &fileStat )) != 0 ) {
	    perror("error of fstat.\n");
	    return -1;
	}

	if ( (*fileSize = fileStat.st_size) == 0 ) {
	    fprintf(stderr, "file size is zero.\n");
	    return -1;
	}
	
        while ( (rval= read(fileFd, buff, BUFLEN*8)) > 0 );
	if ( lseek(fileFd, 0, SEEK_SET) !=0 ) {
	    fprintf(stderr, "lseek error.\n");
	    return -1;
	}
                       
	return fileFd;
}


/****** Write a configuration file for gnuplot to plot the data  ***********/

static status_t write_plot()
{
    int i = 0, j = 0;
    int blocking = testSock.blocking;
    int recvBuf = testSock.recvBuf;
    int sendBuf = testSock.sendBuf;
    int exp_mode = setting.exp_mode;
    
    char buff[BUFLEN];
    FILE * plot;


    /***************** Get the relative path name **************************/

    while ( filename[i] != '\0' && i < strlen(filename) ) {
        buff[j++] = filename[i++];
        if ( buff[j-1] == '/' ) {  // "/home/user/result" -> "result"
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

    fprintf(plot, "# Configuration file for plotting \"%s\"\n", filename);
    fprintf(plot, "# Usage: gnuplot %s.txt\n\n", filename);
    fprintf(plot, "set key left \n");

    if ( exp_mode ) {
        fprintf(plot, "set xlabel \"Message size (Bytes)\"\n");
        fprintf(plot, "set logscale x\n");
    } else
        fprintf(plot, "set xlabel \"Trial\"\n");

    fprintf(plot, "set ylabel \"Throughput (Mbps)\"\n");
    fprintf(plot, "set title \"TCP %s communication \\n",
            blocking ? "blocking":"non-blocking");
    fprintf(plot, "Recv-buffer: %d Send-Buffer: %d\\nHosts: %s <--> %s\"\n",
            recvBuf, sendBuf, localhost, hostname);
    fprintf(plot, "plot \'%s\' us 1:2 notitle with linespoints\n", filename);
    fprintf(plot, "pause -1 \"\\nCtrl^c to exit.\\n");
    fprintf(plot, "Push return to create postscript (ps, eps) files.\\n\\n\"\n");

    /** Output postscript (ps) and encapsulated postscript (eps) format  ***/

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
