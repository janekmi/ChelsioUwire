
/***************************************************************************/
/**                                                                       **/
/**         TCP communication benchmark                                   **/
/**         By Ben Huang, hben@users.sf.net March 2004                    **/
/**         TCP latency and throughput test between two processes         **/
/**                                                                       **/
/**         "tcpserver.c"                                                 **/
/**                                                                       **/
/***************************************************************************/ 


#include "tcplib.h"
#include "util.h"

static void server_shutdown();             // Server close TCP connections 
static void close_session();               // Close child process's connections
static void int_sig_handler(int);          // Interrupt signal handler
static void pipe_sig_handler(int);         // SIGPIPE signal handler
static void child_sig_handler(int);        // Child process signal handler
static void time_out_handler();            // Time out handler

static struct TCPconnection controlSock;   // TCP control channel
static struct TCPconnection testSock;      // TCP test channel
static jmp_buf alarm_env;                  // Time out environment

/*************************** Mian function *********************************/

int main(int argc, char *argv[])
{
    char buff[BUFLEN], sysbuff[2*BUFLEN];  
    short *ptr;                            
    int rval, option;                      
    int verbose = 0;                       // Disable printing message
    int iteration;                         // Iteration of receiving/sending
    int test_mode;                         // Test mode (RTT/Throughput)
    int stream_mode;                       // Stream or ping-pong mode
    int CPUoption;                         // Monitor system information?
    long_int size;                         // Message size
    long_int elapsedTime;                  // Elapsed time
    struct SYSInfo sysinfo;                // Structure for system information
    struct PROInfo proinfo;                // Structure for process information
    struct hostent *hp;                    // Hostent structure
    struct in_addr sin_addr;               // Hold client's address

    /**************** Variable initialization ******************************/
    /******* 0 means using default value in the socket option setting ******/

    controlSock.port = DEFAULTPORT;        // TCP connection port number
    controlSock.recvBuf = 0;               // TCP socket (recv) buffer size 
    controlSock.sendBuf = 0;               // TCP socket (send) buffer size
    controlSock.blocking = 1;              // Blocking communication mode
    controlSock.delay = 0;                 // Enable Nagel algorithm 
    controlSock.mss = 0;                   // TCP MSS (Maximum Segment Size)
    controlSock.cork = 0;                  // TCP_CORK option 
    controlSock.tos =0;                    // TOS (Type of Service)
    controlSock.dataSize = 8192;           // Data size of each sending/receiving
    testSock.port = 0;                     // Test port is selected by system
  
    /*********************** Print help message ****************************/

    if ( argc > 1 && strcmp(argv[1], "--help") == 0 ) {
	fprintf(stderr, help_description);
	fprintf(stderr, help_usage, DEFAULTPORT, DEFAULTSIZE, DEFAULTPORT,  
		DEFAULTREPEAT, DEFAULTTIME);
	fprintf(stderr, help_example);
	return 0;
    } 

    /**************** Parse the command line *******************************/
      
    if ( argc > 1 ) {
	while ( (option = getopt (argc, argv, ":vp:")) != -1) {
	    switch ( option ) {
	    case 'v':  
		verbose = 1;
		break;
	    case 'p':
		if ( atoi(optarg) >= 0 )
		    controlSock.port = atoi(optarg);
		break;
	    case ':':
		fprintf(stderr,"Error: -%c without filename.\n", optopt);
		print_usage();
		return 1;
	    case '?':
		fprintf(stderr,"Error: Unknown argument %c\n", optopt);
		print_usage();
		return 1;
	    default: 
		print_usage();
		return 1;
	    }
	}
    }

    /******************** Handle the interruption **************************/
 
    signal(SIGINT, int_sig_handler);
    signal(SIGTSTP, int_sig_handler);
    signal(SIGPIPE, pipe_sig_handler);
    signal(SIGCHLD, child_sig_handler);
 
    /************ Initialize communications for the server *****************/

    if ( server_init(&controlSock) == NOTOK) {
	perror("Unable to initialize communications.");
	exit(1);
    }
    fprintf(stderr, "TCP socket listening on port [%d]\n", controlSock.port);

    /**************** TCP data channel waiting a connection ****************/

    while ( server_get_connection(&controlSock, &sin_addr) == OK ) {
 
	/********** Create a new process to handle the UDP test ************/

	if ( (rval=fork()) > 0 ) { // Parent
	    close (controlSock.socket);
	    continue;
	} else                   // Child
	    close (controlSock.welcomeSocket);

	/*** Receive the TCP communication options from client *************/

	bzero(buff, BUFLEN);
	if ( get_request(&controlSock, buff) == NOTOK || 
	     sscanf(buff, client_request_str, &test_mode, &testSock.blocking, 
		    &testSock.delay, &testSock.cork, &stream_mode, 
		    &testSock.recvBuf, &testSock.sendBuf, &testSock.mss, 
		    &testSock.tos, &testSock.dataSize, &CPUoption) != 11 ) {
	    if ( verbose ) {
		fprintf(stderr, "Receive TCP options error [%s]\n", buff);
		fprintf(stderr, "Quit this session.\n");
	    }
	    close (controlSock.socket);
	    exit (1);
	}

	if ( CPUoption ) {
	    if ( start_trace_system( &sysinfo ) == OK ) {
		sleep (1);
		if ( stop_trace_system ( &sysinfo ) == OK )
		    CPUoption = 1;
	    } else 
		CPUoption = 0;
	}

	/************************ Check the test mode **********************/

	if ( test_mode != LATENCY && test_mode != SENDFILE && 
	     test_mode != THROUGHPUT ) { 
	    if ( verbose )
		fprintf(stderr, "Wrong test mode request: %d\n", test_mode);
	    close (controlSock.socket);
	    exit (1);
	}

	/********** Create another TCP connection (test channel)  **********/

	if ( server_init(&testSock) == NOTOK ) {
	    if ( verbose )
		fprintf(stderr, "Server test channel initialization error. \n");
	    close (controlSock.socket);
	    exit(1);
	}

	/********* Allocate the memory for sending/receiving data **********/
	    
	if ( (rbuffer = (char *)malloc(testSock.dataSize)) == NULL ||
	     (sbuffer = (char *)malloc(testSock.dataSize)) == NULL ) {
	    if ( verbose )
		fprintf(stderr, "Could not malloc memory! buffer size: %lld\n", size);
	    close (controlSock.socket);
	    exit(1);
	}    
	    
	/**** Randomize the buffer to prevent possible data compression ****/
	    
	srand(time(NULL));
	for ( ptr = (short *)sbuffer; ptr < (short *)(sbuffer+testSock.dataSize); 
	      ptr +=2 )
	    *ptr = (short)rand();   

	
	/******** Inform client the test channel's port number *************/
	
	sprintf(buff, server_port_str, testSock.port);
	if ( send_request(controlSock.socket, buff, strlen(buff)) == NOTOK ) {
	    if ( verbose )
		fprintf(stderr, "Send TCP test port number error.\n");
	    close_session();
	}

	/************ Accept (establish) the test connection ***************/
	
	if ( server_get_connection(&testSock, &sin_addr) == NOTOK ) {
	    fprintf(stderr, "Server test channel getting connection error.\n");
	    close_session();
	}
	close(testSock.welcomeSocket); // Close test channel's welcome socket


	/*********** Inform client the server's network settings ***********/

	sprintf(buff, server_parameter_str, testSock.blocking, testSock.delay,
		testSock.cork, testSock.recvBuf, testSock.sendBuf, testSock.mss, 
		testSock.tos, CPUoption);
	if ( send_request(controlSock.socket, buff, strlen(buff)) == NOTOK ) {
	    if ( verbose )
		fprintf(stderr, "Failed to send server's configuration.\n");
	    close_session();
	}

	/********** Send syslog to client if the option is defined *********/

	if ( CPUoption ) {
	    bzero(sysbuff, 2*BUFLEN);
	    if ( sysinfo_to_string(&sysinfo, sysbuff, 2*BUFLEN) == NOTOK ||
		 send_request(controlSock.socket, sysbuff, strlen(sysbuff)) == NOTOK ) {
		if ( verbose )
		    fprintf(stderr, "Failed to send system initial information.\n");
		close_session();
	    }
	}		
	
	/*********** Print out the connection message **********************/

	if ( verbose ) {
	    get_local_time(buff, BUFLEN);
	    fprintf(stderr, "Session[%d] started at [%s]:\n", (int)getpid(), buff);
	    if ( (hp=gethostbyaddr((char *)&sin_addr, sizeof(sin_addr), AF_INET)) )
		fprintf(stderr, "Connection from %s [%s] ", 
			hp->h_name, inet_ntoa(sin_addr));
	    else        // Host not in the host tables or DNS
		fprintf(stderr, "Connection from [%s] ", inet_ntoa(sin_addr));

	    if ( test_mode == SENDFILE )
		strcpy(buff, "Throughput test with sendfile");
	    else 
		strcpy(buff, test_mode == LATENCY ? "Latency(RTT) test":"Throughput test");
	    fprintf(stderr, "[%s] [%s]\n", buff, stream_mode ? "Unidirectional":"Bidirectional");

	    fprintf(stderr, "%s %s %s ", testSock.blocking ? "Blocking[ON]":"Blocking[OFF]", 
		    testSock.delay ? "TCP_NODELAY[OFF]":"TCP_NODELAY[ON]",
		    testSock.cork ? "TCP_CORK[ON]":"TCP_CORK[OFF]");
	    fprintf(stderr, "Recv-buff[%d] Send-buff[%d] MSS[%d]\n", 
		    testSock.recvBuf, testSock.sendBuf, testSock.mss);
	}
	
	/** Set a timer in case of communication abnormally disconnected ***/
	
	if ( signal(SIGALRM, time_out_handler) == SIG_ERR ) {
	    if ( verbose )
		perror("Signal alarm.");
	    close_session();
	}
	
	if ( setjmp(alarm_env) != 0 ) {
	    if ( verbose )
		fprintf(stderr, "Connection lost.\n");
	    close_session();
	}
	
	alarm (5);
	
	/********** TCP test channel waiting for  a request ****************/
	
	while ( get_request(&controlSock, buff) == OK ) {
	    
	    alarm(0);  // Cancel timer
	    
	    /********************** parse client's request *****************/

	    if ( sscanf(buff, test_start_str, &size, &iteration) != 2) {
		
		/************************* Session ends ********************/
		
		if ( strncmp(buff, test_done_str, strlen(test_done_str)) == 0 ) {
		    if ( test_mode != LATENCY && CPUoption ) {
			if ( start_trace_system(&sysinfo) == OK ) {
			    sleep(1);
			    bzero(buff, BUFLEN);
			    if ( stop_trace_system(&sysinfo) == OK &&
				 sysinfo_to_string( &sysinfo, sysbuff, 2*BUFLEN ) == OK &&
				 send_request(controlSock.socket, sysbuff, strlen(sysbuff)) == OK ) {
				if ( verbose ) {
				    get_local_time(buff, BUFLEN);
				    fprintf(stderr, "Session[%d] ended at [%s].\n", (int)getpid(), buff);
				}
				close_session();
			    }
			}
			if ( verbose )
			    fprintf(stderr, "Failed to send the last syslog.\n");
		    }
		    if ( verbose ) {
			get_local_time(buff, BUFLEN);
			fprintf(stderr, "Session[%d] ended at [%s].\n", (int)getpid(), buff);
		    }
		    close_session();
		} else if ( verbose ) 
		    fprintf(stderr, "Wrong format. Unable to parse request: %s", buff);
		close_session();
	    }
	    
	    /************** Are request number acceptable? *****************/
	    
	    if ( size < 1 || iteration < 1 ) {
		if ( verbose )
		    fprintf(stderr, "Client's request is not acceptable...\n");
		close_session();
	    }
  
	    if ( CPUoption ) {
		if( start_trace_system( &sysinfo ) == NOTOK ) {
		    if ( verbose )
			fprintf(stderr, "Trace system information error.\n");
		    close_session();
		}
	    }

	    if ( test_mode != LATENCY )
		start_trace_process( &proinfo );

	    if ( (server_tcp_test(size, iteration, stream_mode, &elapsedTime, 
				  &testSock)) == NOTOK ) {
		if ( verbose )
		    fprintf(stderr, "TCP test error. Quit the session.\n");
		close_session();
	    } else {  
		if ( test_mode != LATENCY )
		    stop_trace_process( &proinfo ); // Stop tracing process info

		if ( CPUoption ) { // Stop tracing system info
		    usleep(1000);  // Wait for a while for the data to be updated
		    if ( stop_trace_system ( &sysinfo ) == NOTOK ) {
			if ( verbose )
			    fprintf(stderr, "Failed to get system information.\n");
		    }
		}
		    
		strcpy(buff, test_done_str); // Send a confirmation to client
		if ( send_request(controlSock.socket, buff, strlen(buff)) == NOTOK ) {
		    if ( verbose )
			fprintf(stderr, "Failed to send confirmation error\n");
		    close_session();
		}
		
		if ( test_mode != LATENCY ) { // Send the process inforamtion
		    sprintf(buff, server_proinfo_str, elapsedTime, 
			    proinfo.utime_sec*1000000LL + proinfo.utime_usec,
			    proinfo.stime_sec*1000000LL + proinfo.stime_usec);

		    if ( send_request(controlSock.socket, buff, strlen(buff)) == NOTOK ) {
			if ( verbose )
			    fprintf(stderr, "Failed to send process info error\n");
			close_session();
		    }		       
		}

		if ( CPUoption ) { // Send client the system information if defined
		    if ( sysinfo_to_string( &sysinfo, sysbuff, 2*BUFLEN) == NOTOK ||
			 send_request(controlSock.socket, sysbuff, strlen(sysbuff)) == NOTOK ) {
			if ( verbose )
			    fprintf(stderr, "Failed to send system information.\n");
			close_session();
		    }
		}
	    }
	    
#ifdef DEBUG
	    fprintf(stderr, " DEBUG: Test done in %s mode. Message size: %lld  Repeats: %d \n", 
		    stream_mode ? "stream":"ping-pong", size, iteration);
	    if ( elapsedTime > 0 ) 
		fprintf(stderr, " DEBUG: Total transimitted %lld bytes in %f seconds. Network throughput : %f Mbps\n\n",
			stream_mode? size*iteration : size*2*iteration, elapsedTime/1000000.0, stream_mode ? 
			size*iteration*8.0/elapsedTime : size*iteration*2*8.0/elapsedTime ); 
#endif

	} // while loop of get_request
	close_session();
	     
    } // while loop of get_connection

    /*********************** clean up the connections. *********************/

    server_shutdown();
    return 0;

}

/******************************** Interrupt handler ************************/

static void int_sig_handler( int sig_num) 
{
    server_shutdown();
    exit(sig_num);
}

/******************************** Interrupt handler ************************/

static void pipe_sig_handler( int sig_num) 
{

#ifdef DEBUG
    fprintf(stderr, " DEBUG: Connection reset. Wrote socket error.\n");
#endif
    close_session();
}

/**************************** Alarm time out handler ***********************/

static void time_out_handler() 
{
#ifdef DEBUG
    fprintf(stderr," DEBUG: (Child) Get request time out. Quit this session.\n");
#endif
    longjmp(alarm_env, 1);
}

/************** Server (main process) close the TCP connections ************/

static void server_shutdown() 
{
    close(controlSock.welcomeSocket);
    return;
}

/*********** Server (child process) close the TCP connections **************/

static void close_session() 
{
    close(controlSock.socket);
    close(testSock.socket);
    free(rbuffer);
    free(sbuffer);
#ifdef DEBUG
    fprintf(stderr," DEBUG: Quit the session.\n");
#endif
    exit(0);
}

/***************************** Child process handler ***********************/

static void child_sig_handler (int sig_num)
{
    pid_t pid;
    int stat;
    while ( (pid = waitpid(-1, &stat, WNOHANG)) > 0 ) {
#ifdef DEBUG
	fprintf(stderr, " DEBUG: (S) Child %d terminated.\n", pid);
#endif
    }
    return;
}
