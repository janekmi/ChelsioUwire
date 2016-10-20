
/****************************************************************************/
/**                                                                        **/
/**  UDP communication benchmark                                           **/
/**  By Ben Huang, huang@csd.uwo.ca, April 2004                            **/
/**  UDP latency and throughput test between two processes                 **/
/**                                                                        **/
/**  "udpserver.c"                                                         **/
/**                                                                        **/
/****************************************************************************/ 

#include "udplib.h"
#include "util.h"

void signal_handler(int);                    // Interrupt handler 
void signal_child (int);                     // Child process handler
status_t close_session();                    // Close a session
status_t server_shutdown();                  // Close connections 

struct TCPconnection tcpsock;                // TCP data channel
struct UDPconnection udpsock;                // UDP test channel

/******************************* Main function *****************************/

int main(int argc, char *argv[]) 
{
    char buff[BUFLEN], sysbuff[2*BUFLEN];    
    short *ptr;                              
    int option;                              // Parsing otpion
    int testMode;                            // Test mode (latency/throughput)
    int verbose = 0;                         // Disable printing message
    int CPUoption = 0;                       // Monitor system information?
    int port = DEFAULTPORT;                  // TCP port number
    int iteration;                           // Iteration of receiving/sending
    int failure = 0;                         // Failure number for RTT test
    struct SYSInfo sysinfo;                  // System information
    struct PROInfo proinfo;                  // Process information
    struct hostent *hp;                      // Hostent structure
    struct in_addr client_addr;              // structure for client address

    /*********************** Print help message ****************************/

    if ( argc > 1 && strcmp(argv[1], "--help") == 0 ) {
	fprintf(stderr, help_description);
	fprintf(stderr, help_usage,  DEFAULTPORT, DEFAULTDATAGRAM, DEFAULTSIZE, 
		DEFAULTPORT, DEFAULTREPEAT, DEFAULTTIME);
	fprintf(stderr, help_example);
	return 0;
    } 

    /********************** Parsing the command line ***********************/

    if ( argc > 1 ) {
	while ( (option = getopt (argc, argv, ":vp:")) != -1) {
	    switch ( option ) {
	    case 'v':
		verbose = 1;
		break;
	    case 'p':
		if ( atoi(optarg) >= 0 )
		    port = atoi(optarg);
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

    /********************** Handle the interruption ************************/

    signal(SIGINT, signal_handler);
    signal(SIGTSTP, signal_handler);
    signal(SIGCHLD, signal_child);

    /********************** TCP server initialization **********************/

    if ( server_tcp_init(port, &tcpsock) == NOTOK) {
	perror("Unable to initialize tcp communication.");
	return 1;
    }
    fprintf(stderr, "TCP socket listening on port [%d]\n", tcpsock.port);

    /*********************** TCP channel got a connection ******************/

    while ( server_tcp_get_connection(&tcpsock, &client_addr) == OK ) {

	/********** Create a new process to handle the UDP test ************/

	if ( fork() > 0 ) { // Parent
	    close (tcpsock.socket);
	    continue;
	} else              // Child
	    close (tcpsock.welcomeSocket);

	/********************** Parse client's request *********************/

	if ( tcp_get_request(buff, &tcpsock) == NOTOK || 
	     sscanf(buff, test_init_str, &testMode, &udpsock.tos, &CPUoption, 
		    &udpsock.sendBuf, &udpsock.recvBuf, &udpsock.packetSize, 
		    &udpsock.dataSize) != 7 ) {
	    if ( verbose ) {
		fprintf(stderr, ":%s\n", buff);
		perror("TCP get request error.");
	    }
	    exit(1);
	}

	if ( testMode != LATENCY            // RTT (latency) test (UDP ping)
	     && testMode != TPSTREAM        // Unidirectional throughput test
	     && testMode != TPBIDIRECT ) {  // Bidirectional throughput test
	    if ( verbose ) 
		fprintf(stderr, "Not a valid test mode: %d\n", testMode);
	    close_session();
	    exit(1);
	}    

	/********************** Syslog of idle state ***********************/
	
	if ( CPUoption ) {
	    if ( start_trace_system( &sysinfo ) == OK ) {
		sleep (1);
		if ( stop_trace_system ( &sysinfo ) == OK )
		    CPUoption = 1;
	    } else 
		CPUoption = 0;
	}

	/********************** UDP server initialization ******************/
	
	udpsock.port = 0;        // Let system pick a UPD communication port 
	if ( server_udp_init(&udpsock) == NOTOK ) {
	    perror("Failed to create UDP socket.");
	    exit(1);
	}
	if ( ( buffer = (char *)malloc(udpsock.packetSize)) == NULL ) {
	    perror("Malloc memory.");
	    exit(1);
	}

	/***** Randomize the buffer to prevent the possible compression ****/

	srand(time(NULL));
	for ( ptr=(short *)buffer; ptr<(short *)(buffer+udpsock.packetSize); ptr += 2 )
	    *ptr = (short)rand();


#ifdef DEBUG
	fprintf(stderr, " DEBUG: Server's UDP RCVBUF: %d SNDBUF: %d Packet-size: %d\n", 
		udpsock.recvBuf, udpsock.sendBuf, udpsock.packetSize);
#endif
	
	/********** Inform client the UDP communication parameters *********/
   
	sprintf(buff, server_setting_str, udpsock.port, udpsock.tos, 
		CPUoption, udpsock.sendBuf, udpsock.recvBuf, 
		udpsock.packetSize, udpsock.dataSize);      
	if ( tcp_send_request(buff, strlen(buff), &tcpsock) == NOTOK ) {
	    perror("Failed to send UDP configuration.");
	    free(buffer);
	    exit(1);
	}

	/********** Send syslog to client if the option is defined *********/

	if ( CPUoption ) {
	    if ( sysinfo_to_string(&sysinfo, sysbuff, 2*BUFLEN) == NOTOK ||
		 tcp_send_request(sysbuff, strlen(sysbuff), &tcpsock) == NOTOK ) {
		if ( verbose )
		    fprintf(stderr, "Failed to send system initial information.\n");
		exit (1);
	    }
	}

	/*********** Print out the connection message **********************/

	if ( verbose ) {
	    get_local_time(buff, BUFLEN);
	    fprintf(stderr, "Session[%d] started at [%s]:\n", (int)getpid(), buff);
	    if ( (hp=gethostbyaddr((char *)&client_addr, sizeof(client_addr), AF_INET)) )
		fprintf(stderr, "-- Connection from %s [%s]\n", hp->h_name, inet_ntoa(client_addr));
	    else // Host not in the host tables or DNS
		fprintf(stderr, "-- Connection from [%s]\n", inet_ntoa(client_addr));
	    fprintf(stderr, "-- UDP port: %d Buffer size: %d Packet size: %d\n", 
		    udpsock.port, udpsock.recvBuf, udpsock.packetSize);
	}

	/********** TCP channel got a request from client ******************/

	while ( tcp_get_request(buff, &tcpsock) == OK ) {	    
	     
	    /**************** Parse client's request ***********************/
	    if (sscanf(buff, test_start_str, &udpsock.dataSize, &iteration ) != 2) {
		
		/******* For UDP RTT (latency) test synchronization ********/
		if ( strncmp(buff, test_sync_str, strlen(test_sync_str)) == 0 ) {
		    sprintf(buff, test_sync_str);
		    if ( tcp_send_request(buff, strlen(buff), &tcpsock) == NOTOK ) {
			perror("Failed to synchronize.");
			exit (1);
		    }
		}
		/***** Session ends, send the post-test syslog to client ***/
		else if ( strncmp(buff, test_end_str, strlen(test_end_str)) == 0 ) {
		    if ( CPUoption ) {
			if (start_trace_system( &sysinfo ) == OK ) {
			    sleep (1);
			    if ( stop_trace_system (&sysinfo ) == OK &&
				 sysinfo_to_string (&sysinfo, sysbuff, 2*BUFLEN) == OK &&
				 tcp_send_request(sysbuff, strlen(sysbuff), &tcpsock) == OK ) {
				if ( verbose ) {
				    get_local_time(buff, BUFLEN);
				    fprintf(stderr, "Session[%d] ended at [%s].\n", 
					    (int)getpid(), buff);
				}
				exit (1);
			    }
			}
			if ( verbose )
			    fprintf(stderr, "Failed to send the last syslog.\n");
			exit (1);
		    } else {
			if ( verbose ) {
			    get_local_time(buff, BUFLEN);
			    fprintf(stderr, "Session[%d] ended at [%s].\n", (int)getpid(), buff);
			}
			exit (1);
		    }
		}
		/************ Wrong request. Quit the session **************/
		else if ( verbose ) {
		    fprintf(stderr, "Wrong format of request: %s\n", buff);
		    exit (1);
		}
	    }

#ifdef DEBUG 
	fprintf(stderr, " DEBUG: C->S (TCP) Server got a request: %s", buff);
	fprintf(stderr, " DEBUG: Parse result: DataSize %d Iteration %d\n", 
		udpsock.dataSize, iteration);
#endif 

	    /***************************** Start test **********************/

	    if ( testMode == LATENCY ) {  // UDP RTT (latency) test 
	        if ( server_udp_ping(iteration, &udpsock) == OK ) {
		    failure = 0;
		    continue;
	        } else if ( error == TIMEOUT || error == DISORDER ) {
		    if ( verbose )
			fprintf(stderr, "Too many packets lost. Quit RTT test session.\n");
		    continue;
		}
		close_session();
		exit(1);
	    } 
	    
	    /********************* UDP throughput test *********************/

	    else {  

		if ( CPUoption)
		    start_trace_system(&sysinfo);
		start_trace_process(&proinfo);  // Start monitoring process info
		    
		if ( testMode == TPBIDIRECT ) { 
		    if ( server_udp_bi_test(&udpsock) == NOTOK ) { // Bidirectinal test
			if ( error != TIMEOUT && error != DISORDER ) {  // Test error
			    perror("UDP throughput test error.");
			    close_session();
			    exit(1);
			} else {  // Test time out or packet disordered
			    sprintf(buff, test_time_out_str);
			    if ( tcp_send_request (buff, strlen(buff), &tcpsock ) == NOTOK ) {
				perror("Failed to send test results.");
				close_session();
				exit(1);
			    }
			    if ( CPUoption ) {
				stop_trace_system(&sysinfo);
				if ( sysinfo_to_string(&sysinfo, sysbuff, 2*BUFLEN) == NOTOK ||
				     tcp_send_request(sysbuff, strlen(sysbuff), &tcpsock) == NOTOK ) {
				    close_session();
				    perror("Failed to send syslog.");
				    exit(1);
				}
			    }
			}
			continue;
		    }
		} else if ( server_udp_test(&udpsock) == NOTOK ) { // Unidirectinal test
		    if ( error != TIMEOUT && error != DISORDER ) {  // Test error
			perror("UDP throughput test error.");
			close_session();
			exit(1);
		    } else {  // Test time out or packet disordered
			sprintf(buff, test_time_out_str);
			if ( tcp_send_request (buff, strlen(buff), &tcpsock ) == NOTOK ) {
			    perror("Failed to send test results.");
			    close_session();
			    exit(1);
			}
			if ( CPUoption ) {
			    stop_trace_system(&sysinfo);
			    if ( sysinfo_to_string(&sysinfo, sysbuff, 2*BUFLEN) == NOTOK ||
				 tcp_send_request(sysbuff, strlen(sysbuff), &tcpsock) == NOTOK ) {
				close_session();
				perror("Failed to send syslog.");
				exit(1);
			    }
			}
		    }
		    continue;
		}
		
		/** Test OK, stop tracing system info and send result to client **/

		stop_trace_process(&proinfo);  // Stop monitoring process info
		if ( CPUoption ) {
		    usleep(1000);
		    stop_trace_system(&sysinfo);
		}
		
		/**************** Send test results to client **************/

		sprintf(buff, server_result_str, udpsock.recvBytes, udpsock.recvPackets, 
			udpsock.sentBytes, udpsock.sentPackets, udpsock.elapsedTime,
			proinfo.utime_sec*1000000LL + proinfo.utime_usec,
			proinfo.stime_sec*1000000LL + proinfo.stime_usec);

		if ( tcp_send_request (buff, strlen(buff), &tcpsock ) == NOTOK ) {
		    perror("Failed to send test results.");
		    close_session();
		    exit(1);
		}

		if ( CPUoption ) {  // Send syslog to client
		    if ( sysinfo_to_string(&sysinfo, sysbuff, 2*BUFLEN) == NOTOK ||
			 tcp_send_request(sysbuff, strlen(sysbuff), &tcpsock) == NOTOK ) {
			close_session();
			perror("Failed to send syslog.");
			exit(1);
		    }
		}

#ifdef DEBUG
    fprintf(stderr, " DEBUG: Recv-byte: %lld Recv-packet: %d Test-time(Sec.): %f\n",
	    udpsock.recvBytes, udpsock.recvPackets, udpsock.elapsedTime/1000000.0);
#endif

	    } // end of UDP throughput test
	       
	} // while loop of get_request 
	close_session();
	exit(1);

    } // while loop of get_connection

    server_shutdown();

    return 0;
}

/**************** Server close the TCP and UDP connections *****************/

status_t server_shutdown() 
{
    close(tcpsock.welcomeSocket);
    return OK;
}

/**************** Server close the TCP and UDP connections *****************/

status_t close_session() 
{
    close(tcpsock.socket);
    close(udpsock.socket);
    free(buffer);
    return OK;
}

/******************************** Interrupt handler ************************/

void signal_handler( int sig_num) 
{
    server_shutdown();
    exit(sig_num);
}

/***************************** Child process handler ***********************/

void signal_child (int sig_num)
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
