
/****************************************************************************/
/**                                                                        **/
/**  UDP communication benchmark                                           **/
/**  By Ben Huang, huang@csd.uwo.ca, April 2004                            **/
/**  UDP latency and throughput test between two processes                 **/
/**                                                                        **/
/**  "udplib.c"                                                            **/
/**                                                                        **/
/****************************************************************************/ 

#ifndef _UDPLIB_DOT_C
#define _UDPLIB_DOT_C
#include "udplib.h"
#endif

static sigjmp_buf alarm_env;                  // Time out environment


/**************************** Brief description ****************************/
/* 
 * void print_usage()                   // Print out help message
 *
 * static void timeOutHandler()         // Time out handler
 * static int set_alarm()               // Set a timer
 * static void delay_usec()             // Pause for microseconds
 *
 * status_t tcp_send_request()          // (server/client) Send a request by TCP
 * status_t tcp_get_request()           // (server/client) Get a request by TCP
 *
 * status_t server_tcp_init()           // Server TCP channel initialization 
 * status_t server_tcp_get_connection() // Server accepts a TCP connection
 * status_t server_udp_init()           // Server UDP channel initialization
 * inline status_t server_udp_ping()    // Server UDP RTT latency test (UDP ping)
 * inline status_t server_udp_test()    // Server unidirectional throughput test 
 * inline status_t server_udp_bi_test() // Server bidirectional throughput test
 *
 * status_t client_tcp_connect()        // Client establishs TCP connection
 * status_t client_udp_init()           // Client UDP initialization
 * inline status_t client_udp_ping()    // Client UDP RTT latency test (UDP ping)
 * inline status_t client_udp_test()    // Client UDP unidirectional throughput test
 * inline status_t client_udp_bi_test() // Client UPD bidirectional throughput test
 *
 */

/*********************** Help message (short version) **********************/

void print_usage() {  
    fprintf(stderr, "Usage: [server] %% udpserver [options]\n");
    fprintf(stderr, "       [client] %% udptest -h host [options]\n");
    fprintf(stderr, "Try \"udpserver --help\" or \"udptest --help\" for more information.\n");
    return;
}

/****************** Signal handler for time out alarm **********************/

static void timeOutHandler() 
{

#ifdef DEBUG
    fprintf(stderr," DEBUG: Catch time out alarm!\n");
#endif

    siglongjmp(alarm_env, 1);

    return;
}


/***************************** Pause for microseconds **********************/
/****** gettimeofday() has microsecond resolution in most systems **********/
/** BUG: In Linux SMP (Alapha arch.) systems, this resolution is only 1ms **/ 

void delay_usec(int time_usec)
{
    struct timeval startTime, endTime; 
    int delay = 0;

    if ( time_usec <= 0 )
	return;

    gettimeofday(&startTime, NULL);

    while ( delay < time_usec) {
	gettimeofday(&endTime, NULL);
	delay = (endTime.tv_sec - startTime.tv_sec) * 1000000
	    + endTime.tv_usec - startTime.tv_usec;
    }

    return;
}


/******************************** Set timer ********************************/
/*
static int set_alarm(int sec, int usec)
{
  struct itimerval old, new;

  new.it_interval.tv_usec = 0;
  new.it_interval.tv_sec = 0;
  new.it_value.tv_usec = usec;
  new.it_value.tv_sec = sec;

  if (setitimer (ITIMER_REAL, &new, &old) < 0)
    return 0;
  else
    return old.it_value.tv_sec;
}
*/

/**************** Send a message by TCP control channel ********************/

status_t tcp_send_request (char * str, int length, struct TCPconnection *sock) 
{ 
    int rval, left = length;
    char *buff = str; 
    
    while ( left > 0 ) {
	if ( (rval=write(sock->socket, buff, left)) < 0  ) {
	    perror("Sending request.");
	    return NOTOK;
	}
	left -=rval ;
	buff +=rval;
    }

#ifdef DEBUG
    fprintf(stderr, " DEBUG: TCP send out request (size %d): %s\n", length, str);
#endif

    return OK;
}

/********* Get a messages(request) from TCP control channel ****************/

status_t tcp_get_request(char *request, struct TCPconnection *tcpsock) 
{
    char buff1[BUFLEN], * buff = buff1;
    int rval=0, got_r=0;
  
    while ( rval < (BUFLEN - 1)) {
	if  ( read(tcpsock->socket, buff, 1) != 1)  {
	    return NOTOK;
	} else {
	    
	    /***** Look for the \r\n combination on the end of a line ******/
	    
	    if ((got_r) && ( *buff == '\n')) {
		rval++;
		break;
	    } else if ( *buff == '\r') {
		    got_r = 1;
	    } else {
		got_r = 0;
	    }
	    buff++;
	    rval++;
	}
    }
    if ( rval == BUFLEN -1 ) {
	fprintf(stderr, "Buffer overflowing...\n");
	return NOTOK;
    }

    strcpy (request, buff1);

#ifdef DEBUG
    fprintf(stderr, "\n DEBUG: Got a request(parse size %d): %s\n", rval, request);
#endif

    return OK;
}

/**************************** Initialize server's TCP connection ***********/

status_t server_tcp_init (int port, struct TCPconnection *sock) 
{
    struct sockaddr_in serverAddress;
    int wsocket;
    int value = 1, length = sizeof(value);

    if ( port < 0 ) {
	fprintf(stderr, " Port number must be a positive integer : %d\n", port); 
	return NOTOK;
    }

    /********************* Create the socket *******************************/

    if ( (sock->welcomeSocket=socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
 	perror("Creating server socket");
	return NOTOK;
    }
    wsocket = sock->welcomeSocket;

    signal(SIGPIPE, SIG_IGN); 


    /************** Let the socket rebindable in TIME_WAIT state ***********/

    if ( setsockopt(wsocket, SOL_SOCKET, SO_REUSEADDR, &value, length) < 0 ) {
	perror("Setting socket rebindable");
	return NOTOK;
    }

    /************************* Disable Nagle algorithm *********************/

#ifdef TCP_NODELAY
    value = 1;
    if ( setsockopt(wsocket, IPPROTO_TCP, TCP_NODELAY, &value, 
		    sizeof(value)) < 0) {
	perror("Setting TCP_NODELAY option.");
	return NOTOK;
    }
#endif

    /********************* Bind the socket *********************************/

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(port);
    if (bind(wsocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress))<0) {
	perror("Binding server socket");
	return NOTOK;
    }

    length = sizeof(serverAddress);
    if (getsockname(wsocket, (struct sockaddr *) &serverAddress, &length)) {
	perror("Getting socket name");
	return NOTOK;
    }
    sock->port = ntohs(serverAddress.sin_port);

#ifdef DEBUG
    fprintf(stderr, "TCP connection on port %d\n", sock->port);
#endif

    /***************** Set the listening queue length **********************/

    if ( listen(wsocket, 5) < 0 ) {
	perror("TCP socket listen");
	return NOTOK;
    }
    return OK;
}

/**************** Server accepts a client connection ***********************/

status_t server_tcp_get_connection(struct TCPconnection *sock, struct in_addr *sin_addr) 
{
    struct sockaddr_in clientAddress;
    int length = sizeof(clientAddress);

    do {
	sock->socket = accept(sock->welcomeSocket, 
			      (struct sockaddr *) &clientAddress, &length);
    } while ( sock->socket < 0 && errno == EINTR );
    
    if (sock->socket < 0) {
	perror("TCP accept error.");
	return NOTOK;
    }

    *sin_addr = clientAddress.sin_addr;

    return OK;
}

/****************** Server Initialize the UDP socket ***********************/

status_t server_udp_init (struct UDPconnection *sock) 
{
    int serverUdpSocket, bufferSize;
    int value, length;
    struct sockaddr_in udpServerAddress;
  
    /********************** create the socket ******************************/

    if ( (sock->socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
	perror("Creating server udp socket");
	return NOTOK;
    }
    serverUdpSocket = sock->socket;
 
    /****************** Set server's UDP buffer size ***********************/

    bufferSize = sock->recvBuf;
    if ( bufferSize >=0  ) {

#ifdef linux
	bufferSize = bufferSize / 2; // Get 20K when setting 10K in Linux
#endif

	if(  setsockopt(serverUdpSocket, SOL_SOCKET, SO_RCVBUF, 
			(char *) &bufferSize, sizeof(bufferSize)) ) {
	    perror("Setting socket UDP RCVBUF buffer size.");
	    return NOTOK;
	}
	if(  setsockopt(serverUdpSocket, SOL_SOCKET, SO_SNDBUF, 
			(char *) &bufferSize, sizeof(bufferSize)) ) {
	    perror("Setting socket UDP SNDBUF buffer size.");
	    return NOTOK;
	}
    }
 
    /************* Verify the UDP buffer size ******************************/

    length = sizeof(value);
    if( getsockopt(serverUdpSocket, SOL_SOCKET, SO_RCVBUF, &value, &length) ) {
	perror("Getting socket UDP RCVBUG buffer size.");
	return NOTOK;
    }
    sock->recvBuf = value;

    length = sizeof(value);
    if( getsockopt(serverUdpSocket, SOL_SOCKET, SO_SNDBUF, &value, &length) ) {
	perror("Getting socket UDP SNDBUG buffer size");
	return NOTOK;
    }
    sock->sendBuf = value;

    /********* Packet size should not be greater than buffer size **********/

    if ( sock->packetSize > value ) {
	sock->packetSize = value;
    }	

    /************************** Set IP's "QoS" *****************************/
    /* Six possible values for our tests:
       1: IPTOS_LOWDELAY (Minimize delay)
       2: IPTOS_THROUGHPUT (Maximize throughput)
       3: AF11 (DiffServ Class1 with low drop probabiltiy)
       4: AF13 (DiffServ Class1 with high drop probabiltiy)
       5: AF41 (DiffServ Class4 with low drop probabiltiy)
       6: AF43 (DiffServ Class4 with high drop probabiltiy)

       (EF-DiffServ with highest IP precedence needs root's privilege to set)
    */

    if ( sock->tos > 0 ) {
	value = sock->tos;
	length = sizeof(value);
	if ( setsockopt(serverUdpSocket, IPPROTO_IP, IP_TOS, &value, length) < 0 ) {
	    perror("Setting TOS bits.");
	    return NOTOK;
	}
    }

    /************************** Verify TOS value ***************************/

    length = sizeof(value);
    if ( getsockopt(serverUdpSocket, IPPROTO_IP, IP_TOS, &value, &length) < 0 ) {
	perror("Getting TOS bits.");
	return NOTOK;
    }
    sock->tos = value;

    /********************** Bind the socket ********************************/

    udpServerAddress.sin_family = AF_INET;
    udpServerAddress.sin_addr.s_addr = INADDR_ANY;
    udpServerAddress.sin_port = htons(sock->port);
    if ( bind( serverUdpSocket, (struct sockaddr *) &udpServerAddress, 
	       sizeof(udpServerAddress))) {
	perror("Binding server udp socket");
	return NOTOK;
    }

    length = sizeof(udpServerAddress);
    if  ( getsockname(serverUdpSocket, (struct sockaddr *) &udpServerAddress, 
		      &length) ) {
	perror("Getting socket name");
	return NOTOK;
    }
    sock->port = ntohs(udpServerAddress.sin_port);

    return OK;
}

/********************* UDP RTT (latency) test ******************************/
/** iteration: Iteration of receiving/sending                             **/
/** precise_mode: Less overhead and more accurate test                    **/
/** sock: UDP connection                                                  **/
/***************************************************************************/

inline status_t server_udp_ping ( int iteration, struct UDPconnection *sock)
{
    int i, rval, sequence, addrSize, serverUdpSocket, packetSize;
    struct sockaddr_in clientAddress;    
    char buff[MAXDATAGRAM];
    struct UDPHeader *header = (struct UDPHeader *)buff;     

    bzero(buff, MAXDATAGRAM);
    addrSize = sizeof(clientAddress);
    serverUdpSocket = sock->socket;
    packetSize = sock->packetSize;
    sequence = 0;
    
    /********* Set a timer to handle the time out situation ****************/
    
    if ( signal(SIGALRM, timeOutHandler) == SIG_ERR ) {
	perror("Set alarm signal.");
	return NOTOK;
    }
    
    error = 0;
    if ( sigsetjmp(alarm_env, 1) != 0 ) {
	error = TIMEOUT;
	return NOTOK;
    }
    
#ifdef DEBUG
    fprintf(stderr, "\n DEBUG: Start UDP RTT latency test (iteration %d).\n", iteration);
#endif
	    
    /************************** Start RTT test *****************************/

    alarm (5);   // 5 seconds
    for ( i = 0; i < iteration; i++ ) {

#ifdef DEBUG
	// fprintf(stderr, ".");
#endif
	if ( (rval=recvfrom(serverUdpSocket, buff, packetSize, 0, 
		      (struct sockaddr*)&clientAddress, &addrSize)) < 0 ) {
	    alarm(0);
	    perror("Recvfrom error (UDP ping).");
	    return NOTOK;
	}
	
	if ( rval > 4 ) {
	    if ( ntohl(header->seq_number) != (sequence + 1) ) {
		fprintf(stderr, "Disordered packet [seq: %d pre_seq: %d]\n",  
			(int)ntohl(header->seq_number), sequence);
		error = DISORDER;
		alarm(0);
		return NOTOK;
	    } else 
		sequence = ntohl(header->seq_number);
	}

#ifdef DEBUG
	// fprintf(stderr, "*");
#endif
	if ( sendto (serverUdpSocket, buff, rval, 0, 
		     (struct sockaddr*)&clientAddress, addrSize) < 0 ) {
	    perror("Sendto error (UDP ping).");
	    alarm(0);
	    return NOTOK;
	}
    }
    alarm(0); // Cancel timer

    return OK;

    /* Using select() is a little more expensive than above implementation */
    /* 
       {
    int i, msg, rval, sequence, addrSize, serverUdpSocket, packetSize;
    struct timeval timeOut;
    fd_set readSet; 
    struct UDPHeader * udpHeader = (struct UDPHeader *) buffer; 
    FD_ZERO(&readSet);
    for ( i = 0; i < iteration; i++ ) {
	FD_SET( serverUdpSocket, &readSet );
	timeOut.tv_sec  = 2;   // 2 seconds
	timeOut.tv_usec = 0;
	rval = select(serverUdpSocket+1, &readSet, NULL, NULL, &timeOut );
	if ( (rval > 0) && (FD_ISSET(serverUdpSocket, &readSet)) ) {
	    alarm(0); // Cancel the timer
	    msg = recvfrom (serverUdpSocket, buffer, packetSize, 0, 
				(struct sockaddr*)&clientAddress, &addrSize);
	    if ( msg < 0 && errno != EINTR ) {
		perror("UDP ping receive.");
		return NOTOK;
	    }
	    if ( (sequence=ntohl( udpHeader->seq_number )) != i ) {
		    fprintf(stderr, "UDP packet disorder.\n");
		    *error = DISORDER;
		    return NOTOK;
	    }
	    if( sendto (serverUdpSocket, buffer, msg, 0, 
			(struct sockaddr*)&clientAddress, addrSize) < 0 ) {
		    perror ("UDP ping send.");
		    return NOTOK;
	    } 
	} else if ( rval == 0 ) {  // Timeout
	    *error = TIMEOUT;
	    return NOTOK;
	}
    }
    */
}
    
/********************* UDP throughput test *********************************/

inline status_t server_udp_test (struct UDPconnection * sock) 
{
    int rval, msg, recvPackets = 0;
    long_int recvBytes = 0;  
    struct UDPHeader *udpHeader = (struct UDPHeader *) buffer; 
    struct sockaddr_in clientAddress;        
    int addrSize = sizeof(clientAddress);    
    struct timeval startTime, endTime, waitTime; 
    fd_set readSet;
    int serverUdpSocket = sock->socket;      
    int packetSize = sock->packetSize;  
     
    /****************** Set the time out signal handler ********************/

    if ( signal(SIGALRM, timeOutHandler) == SIG_ERR ) {
	perror("Set alarm signal.");
	return NOTOK;
    }

    error = 0; 
    if ( sigsetjmp(alarm_env, 1) != 0 ) {
	error = TIMEOUT;
	return NOTOK;
    }

    /**************** Warm up and timing synchronization *******************/

#ifdef DEBUG
    fprintf(stderr, " DEBUG: Start to synchronize.\n");
#endif  

    alarm(2); // 2 seconds
    if ( (msg=recvfrom(serverUdpSocket, buffer, packetSize, 0, 
		       (struct sockaddr*)&clientAddress, &addrSize)) < 0 ) {
	alarm(0);
	perror("Recvfrom error (UDP throughput test warm up).");
	return NOTOK;
    } else if ( msg != HEADERSIZE || ntohl(udpHeader->seq_number) != 0
		|| ntohl(udpHeader->cmd) != SYNC) {
	alarm(0);
	fprintf(stderr, "Sync error! size: %d seq: %d\n", 
		msg, (int)ntohl(udpHeader->seq_number));
	error = DISORDER;

	/******************** Clean up the socket **************************/

	waitTime.tv_sec  = 1;   // 1 second
	waitTime.tv_usec = 0;
	FD_ZERO(&readSet);
	for (;;) {
	    FD_SET(serverUdpSocket, &readSet );
	    rval = select(serverUdpSocket+1, &readSet, NULL, NULL, &waitTime);
	    if ( (rval > 0) && (FD_ISSET(serverUdpSocket, &readSet)) ) {
		if ( recvfrom(serverUdpSocket, buffer, packetSize, 0, 
				   (struct sockaddr*)&clientAddress, &addrSize) < 0 ) {
		    perror ("Server receiving last packet error...\n");
		    break;
		}
	    } else if ( rval < 0 ) {
		perror("UDP select.");
		break;
	    } else if ( rval == 0 )
		break;
	}
	
	return NOTOK;
    }
    
    udpHeader->seq_number = htonl(0);
    udpHeader->cmd = htonl(ACKSYNC);
    if ( sendto(serverUdpSocket, buffer, msg, 0, 
		   (struct sockaddr*)&clientAddress, addrSize) < 0
	 || recvfrom(serverUdpSocket, buffer, packetSize, 0, 
		     (struct sockaddr*)&clientAddress, &addrSize) < 0) {
	alarm(0);
	perror("Sync error (UDP throughput test sync).");
	return NOTOK;
    }
    alarm(0);

#ifdef DEBUG
    fprintf(stderr, " DEBUG: Start UDP througput test.\n");
#endif  

    /********************** Start UDP throughput test **********************/

    alarm(MAXTESTTIME);
    gettimeofday(&startTime, NULL);  // start timing
    for (;;) {   
	msg = recvfrom(serverUdpSocket, buffer, packetSize, 0, 
		       (struct sockaddr*)&clientAddress, &addrSize); 
 	if ( msg < 0 ) {
	    perror("Recvfrom error (UDP throughput test).");
	    alarm(0);
	    return NOTOK;
	} else if ( msg == 0 )
	    continue;
	recvBytes += msg;
	recvPackets++;

	if ( msg > 8 ) {
	    if ( ntohl(udpHeader->cmd) == FIN ) {
		gettimeofday(&endTime, NULL);   // stop timing
		alarm(0);  // Cancel timer
		sock->recvLoss = ntohl(udpHeader->seq_number) - recvPackets;
		break;
	    } 
	} 

    } // end of for loop

    sock->recvBytes = recvBytes;
    sock->recvPackets = recvPackets;
    sock->sentBytes = 0;
    sock->sentPackets = 0;
    sock->elapsedTime = (endTime.tv_sec - startTime.tv_sec) * 1000000LL +
	endTime.tv_usec - startTime.tv_usec;
    
    /********** Clean up possible arriving (FIN) packets *******************/
    /**** We use signal-droven implementation instead of using select() ***/

    if ( sigsetjmp(alarm_env, 1) != 0 ) {
#ifdef DEBUG
	fprintf(stderr, " DEBUG: Time over for cleaning up the UDP socket.\n");
#endif
	return OK;
    }
    alarm(SERVERWAITTIME);
    
    for (;;) {
	if ( (msg=recvfrom(serverUdpSocket, buffer, packetSize, 0, 
			   (struct sockaddr*)&clientAddress, &addrSize)) < 0 ) {
	    perror ("Recvfrom error (clean up last packets).");
	    alarm(0);
	    return NOTOK;
	}
    }

#ifdef DEBUG
    fprintf (stderr, " DEBUG: (S) Test done. Elapsed Time: %lld\n", sock->elapsedTime);
#endif
    
    return OK;
}

/*************** UDP bidirectional throughput test *************************/

inline status_t server_udp_bi_test (struct UDPconnection * sock ) 
{
    int msg, sig, rval;                       // Common variables
    int send_seq = 0;                         // SendPacket's sequence number
    int sentACK = 0;                          // The number of ACKFIN packets sent
    int gotFIN = 0;                           // Received the FIN packet?
    int recvPackets = 0;                      // Received packet number
    int serverUdpSocket = sock->socket;       // UDP socket
    int packetSize = sock->packetSize;        // Packet size
    long_int recvBytes = 0;                   // Total received bytes
    long_int sentBytes = 0;                   // Total sent bytes
    char sendBuff[sock->packetSize+1];        // A buffer for sending
    struct sockaddr_in clientAddress;         // Sockaddr_in structure
    int addrSize = sizeof(clientAddress);     // Size of sockaddr_in 
    struct UDPHeader * sendHeader = (struct UDPHeader *) sendBuff;
    struct UDPHeader * udpHeader = (struct UDPHeader *) buffer; 
    struct timeval startTime, endTime, waitTime; 
    fd_set readSet, writeSet;           

    error = 0;
    FD_ZERO(&readSet);
    FD_ZERO(&writeSet);

    /********************** Set time out signal handler ********************/

    if ( signal(SIGALRM, timeOutHandler) == SIG_ERR ) {
	perror("Set alarm signal.");
	return NOTOK;
    }

    error = 0; 
    if ( sigsetjmp(alarm_env, 1) != 0 ) {
	error = TIMEOUT;
	return NOTOK;
    }

#ifdef DEBUG
    fprintf(stderr, " DEBUG: Start to synchronize (UDP bidirectional throughput test).\n");
#endif

    alarm(2); 

    /**************** Warm up and timing synchronization *******************/

    if ( (msg=recvfrom(serverUdpSocket, buffer, packetSize, 0, 
		       (struct sockaddr*)&clientAddress, &addrSize)) < 0 ) {
	alarm(0);
	perror("Recvfrom error (UDP bidirectional throughput test warm up).");
	return NOTOK;
    } else if ( msg != HEADERSIZE || ntohl(udpHeader->seq_number) != 0
		|| ntohl(udpHeader->cmd) != SYNC ) {
	alarm(0);
	error = DISORDER;

	/******************** Clean up the socket **************************/

	waitTime.tv_sec  = 1;   // 1 second
	waitTime.tv_usec = 0;
	FD_ZERO(&readSet);
	for (;;) {
	    FD_SET(serverUdpSocket, &readSet );
	    rval = select(serverUdpSocket+1, &readSet, NULL, NULL, &waitTime);
	    if ( (rval > 0) && (FD_ISSET(serverUdpSocket, &readSet)) ) {
		if ( recvfrom(serverUdpSocket, buffer, packetSize, 0, 
				   (struct sockaddr*)&clientAddress, &addrSize) < 0 ) {
		    perror ("Server receiving last packet error...\n");
		    break;
		}
	    } else if ( rval < 0 ) {
		perror("UDP select.");
		break;
	    } else if ( rval == 0 )
		break;
	}

	return NOTOK;
    }

    sendHeader->seq_number = htonl(0);
    sendHeader->cmd = htonl(ACKSYNC);
    if ( sendto(serverUdpSocket, sendBuff, msg, 0, 
		(struct sockaddr*)&clientAddress, addrSize) < 0
	 || recvfrom(serverUdpSocket, buffer, packetSize, 0, 
		     (struct sockaddr*)&clientAddress, &addrSize) < 0) {
	alarm(0);
	perror("UDP throughput test (bidirectional) sync error.");
	return NOTOK;
    }
    alarm(0);

#ifdef DEBUG
    fprintf(stderr, " DEBUG: Start to UDP throughput test (bidirectional).\n");
#endif

    /************** Start UDP bidirectional throughput test ****************/

    alarm(MAXTESTTIME); // We shouldn't use select() here since writeSet is always take priority

    gettimeofday(&startTime, NULL);  // start timing
    while ( sentACK < MAXFIN ) {  

	FD_SET(serverUdpSocket, &readSet);
	FD_SET(serverUdpSocket, &writeSet);
	sig = select(serverUdpSocket+1, &readSet, &writeSet, NULL, NULL);

	if ( sig > 0 && FD_ISSET(serverUdpSocket, &readSet) ) { // Socket readable

	    msg = recvfrom(serverUdpSocket, buffer, packetSize, 0, 
			   (struct sockaddr*)&clientAddress, &addrSize);
	    if ( msg < 0 ) {
		perror("Recvfrom error (UDP throughput test).");
		alarm(0);
		return NOTOK;
	    } else if ( msg == 0 )
		continue;

	    recvBytes += msg;
	    recvPackets++;

	    if ( msg > 8 && ntohl(udpHeader->cmd) == FIN ) {
		if ( !gotFIN ) {
		    gettimeofday(&endTime, NULL);  // Stop timing
		    
		    /********** Record the test statistics *****************/
		    
		    sock->recvBytes = recvBytes;
		    sock->sentBytes = sentBytes;
		    sock->recvPackets = recvPackets;
		    sock->sentPackets = send_seq;
		    sock->recvLoss = ntohl(udpHeader->seq_number) - recvPackets;
		    sock->sentLoss = 0;
		    sock->elapsedTime = (endTime.tv_sec - startTime.tv_sec) * 1000000LL +
			endTime.tv_usec - startTime.tv_usec;
		}
		gotFIN = 1;
	    }
	} 
	
	if ( sig > 0 && FD_ISSET(serverUdpSocket, &writeSet) ) { // Socket writable

	    sendHeader->seq_number = htonl(++send_seq);
	    
	    if ( gotFIN ) { // Send ACKFIN to client (as many as MAXFIN times) if received FIN 
		sendHeader->cmd = htonl(ACKFIN);
		if ( (msg = sendto(serverUdpSocket, sendBuff, HEADERSIZE, 0, 
			       (struct sockaddr*)&clientAddress, sizeof(clientAddress))) < 0 ) {
		    perror("Sendto (ACKFIN) error (UDP bidirectional throughput test).");
		    alarm(0);
		    return NOTOK;
		}
		sentACK++;
	    } 
	    else { // Send data to client until receive FIN signal from client
		sendHeader->cmd = htonl(DATA);
		if ( (msg = sendto(serverUdpSocket, sendBuff, sock->dataSize, 0, 
				   (struct sockaddr*)&clientAddress, sizeof(clientAddress))) < 0 ) {
		    perror("Sendto (data) error (UDP bidirectional throughput test).");
		    alarm(0);
		    return NOTOK;
		}
	    }
	    if ( msg > 0)
		sentBytes += msg;
	} 
	    
	if ( sig < 0 ) {  // Something wrong
	    perror("Select (UDP bidirectinal throughput test).");
	    alarm(0);
	    return NOTOK;
	}
    } 
    alarm(0);

    /************* Clean up possible arriving (FIN) packets ****************/
     
    waitTime.tv_sec  = SERVERWAITTIME;   
    waitTime.tv_usec = 0;
    FD_ZERO(&readSet);

    for (;;) {
	FD_SET(serverUdpSocket, &readSet );
	rval = select(serverUdpSocket+1, &readSet, NULL, NULL, &waitTime);
	if ( (rval > 0) && (FD_ISSET(serverUdpSocket, &readSet)) ) {
	    if ( (msg=recvfrom(serverUdpSocket, buffer, packetSize, 0, 
			       (struct sockaddr*)&clientAddress, &addrSize)) < 0 ) {
		perror ("Recvfrom error (clean up FIN packets).");
		return NOTOK;
	    }
	} else if ( rval < 0 && errno != EINTR ) {
	    perror("Select error (clean up FINs).");
	    return NOTOK;
	} else if ( rval == 0 )
	    break;
    }
    
#ifdef DEBUG
    fprintf (stderr, " DEBUG: (S) Test done. Elapsed Time: %lld\n", sock->elapsedTime);
#endif
    
    return OK;

}


/********** Client TCP connection (reliable control channel) ***************/
/** The cases that this TCP connection is used:                           **/  
/** Client gets the server's UDP port (could be different with TCP port)  **/
/** Client informs server to start the UDP test                           **/
/** Client gets the test results from server                              **/
/***************************************************************************/

status_t client_tcp_connect(char *hostname, struct TCPconnection *sock) 
{
    struct hostent *hp;
    struct sockaddr_in serverAddress; 
    int clientTcpSocket;

    if ( sock->port <= 0  ) {  
	fprintf(stderr, "Port number should be a positive integer \n");
	return NOTOK;
    }

    /******************** Create the TCP socket ****************************/

    if ( (sock->socket = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
 	perror("Creating socket"); 
	return NOTOK;
    }
    clientTcpSocket = sock->socket;

    /********************* Create the server address ***********************/

    if ( atoi(hostname) > 0 ) { // Check if the hostname is numerical type
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_addr.s_addr = inet_addr(hostname);
    } else {  // Check if the hostname is domainname type
	if ((hp = gethostbyname(hostname)) == NULL) {
	    fprintf(stderr, "Unable to resolve server name %s!\n", hostname);
	    return NOTOK;
	}
	serverAddress.sin_family = AF_INET;
	bcopy(hp->h_addr, &serverAddress.sin_addr, hp->h_length);
    }
    serverAddress.sin_port = htons(sock->port);

    if (connect(clientTcpSocket, (struct sockaddr *) &serverAddress, 
		sizeof(serverAddress)) < 0) {
	perror("Connecting socket"); 
	return NOTOK;
    }

    return OK;
}


/************* Initialzatioon of client's UDP communcation *****************/
/** hostname: server's host name or IP address                            **/
/** sock: UDP socket struct                                               **/
/***************************************************************************/
 
status_t client_udp_init(char *hostname, struct UDPconnection *sock) 
{
    struct hostent *hp;
    int value, length, bufferSize, clientUdpSocket;
    int packetSize = sock->packetSize;     
    struct sockaddr_in clientAddress;
    struct sockaddr_in serverAddress;
  
    /************************* Create the socket ***************************/
  
    sock->socket = socket(AF_INET, SOCK_DGRAM, 0);
    if ( sock->socket < 0) {
	perror("Creating client udp socket"); 
	return NOTOK;
    }
    clientUdpSocket = sock->socket;
    
    /*************************** Set UDP buffer ****************************/

    bufferSize = sock->sendBuf;
    if ( bufferSize > 0 ) {     

#ifdef linux	
	bufferSize = bufferSize / 2; // Get 20K when setting 10K in Linux
#endif
	if ( setsockopt(clientUdpSocket, SOL_SOCKET, SO_SNDBUF, 
			(char *) &bufferSize, sizeof(bufferSize)) < 0 ) {
	    perror("Setting UDP SNDBUF size");
	    return NOTOK;
	}
	if ( setsockopt(clientUdpSocket, SOL_SOCKET, SO_RCVBUF, 
			(char *) &bufferSize, sizeof(bufferSize)) < 0 ) {
	    perror("Setting UDP RCVBUF size");
	    return NOTOK;
	}
    }

    /************************** Verify UDP buffer **************************/

    length = sizeof(value);
    if (getsockopt(clientUdpSocket, SOL_SOCKET, SO_SNDBUF, &value, &length)<0) {
	perror("Getting UDP socket SNDBUF size");
	return NOTOK;
    }
    sock->sendBuf = value;
    if (getsockopt(clientUdpSocket, SOL_SOCKET, SO_RCVBUF, &value, &length)<0) {
	perror("Getting UDP socket RCVBUF size");
	return NOTOK;
    }
    sock->recvBuf = value;

    /************ Set UDP datagram length (Packet size) ********************/

    if ( packetSize >= value || packetSize <= 0 ) {
        sock->packetSize = value;
    } else if ( packetSize > MAXDATAGRAM )
	sock->packetSize = DEFAULTDATAGRAM;

    /************************** Set IP's "QoS" *****************************/
    /* Six possible values for our tests:
       1: IPTOS_LOWDELAY (Minimize delay)
       2: IPTOS_THROUGHPUT (Maximize throughput)
       3: AF11 (DiffServ Class1 with low drop probabiltiy)
       4: AF13 (DiffServ Class1 with high drop probabiltiy)
       5: AF41 (DiffServ Class4 with low drop probabiltiy)
       6: AF43 (DiffServ Class4 with high drop probabiltiy)
       (EF-DiffServ with highest IP precedence needs root's privilege to set)
    */

    if ( sock->tos > 0 ) {
	value = sock->tos;
	length = sizeof(value);
	if ( setsockopt(clientUdpSocket, IPPROTO_IP, IP_TOS, &value, length) < 0 ) {
	    perror("Setting TOS bits.");
	    return NOTOK;
	}
    }

    /************************** Verify TOS value ***************************/
 
    length = sizeof(value);
    if ( getsockopt(clientUdpSocket, IPPROTO_IP, IP_TOS, &value, &length) < 0 ) {
	perror("Getting TOS bits.");
	return NOTOK;
    }
    sock->tos = value;
    
    /************************ Bind the socket ******************************/
  
    clientAddress.sin_family = AF_INET;
    clientAddress.sin_addr.s_addr = INADDR_ANY;
    clientAddress.sin_port = 0;
    length = sizeof(clientAddress);
    if (bind(clientUdpSocket, (struct sockaddr *)&clientAddress, length)) {
	perror("Binding client udp socket"); 
	return NOTOK;
    }
  
    /*********************** Create the address for the server. ************/

    if ( atoi(hostname) > 0 ) {  // Numerical format
	serverAddress.sin_family = AF_INET;
	(serverAddress.sin_addr).s_addr = inet_addr(hostname);
    } else { // Domainname format
	if ((hp = gethostbyname(hostname)) == NULL) {
	    fprintf(stderr, "Unable to resolve server name %s!\n", hostname);
	    return NOTOK;
	}
	serverAddress.sin_family = AF_INET;
	bcopy(hp->h_addr, &serverAddress.sin_addr, hp->h_length);
    }

    serverAddress.sin_port = htons(sock->port);
  
    /**** UDP connect! then we could use "write" instead of "sendto" *******/
  
    if (connect(clientUdpSocket, (struct sockaddr *)&serverAddress, length)<0) {
	perror("Connecting udp socket"); 
	return NOTOK;
    }

    return OK;
}

/************************** UDP RTT (latency) test *************************/
/** iteration: Iteration of round trips (send/receive)                    **/
/** udpsock: UDP connection                                               **/
/***************************************************************************/

inline status_t client_udp_ping(int iteration, struct UDPconnection *udpsock) 
{
    char rbuff[MAXDATAGRAM], wbuff[MAXDATAGRAM];
    int i, rval, sig, msg, dataSize, sequence, clientUdpSocket;
    struct timeval startTime, endTime, timeOut; 
    struct UDPHeader *wHeader = (struct UDPHeader *) wbuff;
    struct UDPHeader *rHeader = (struct UDPHeader *) rbuff; 
    fd_set readSet;

    FD_ZERO (&readSet);
    bzero(rbuff, MAXDATAGRAM);
    bzero(wbuff, MAXDATAGRAM);
    clientUdpSocket = udpsock->socket; 
    dataSize = udpsock->dataSize;
    sequence = 1;
 
    /**********  The maximum size of each sending/receiving ****************/

    if ( dataSize > MAXDATAGRAM )
	dataSize = MAXDATAGRAM;
    else if ( dataSize > udpsock->packetSize )
	dataSize = udpsock->packetSize;

    if ( dataSize > 4 )
	wHeader->seq_number = htonl(sequence);
 
    /********* Set a timer to handle the time out situation ****************/

    if ( signal(SIGALRM, timeOutHandler) == SIG_ERR ) {
	perror("Set alarm signal alarm.");
	return NOTOK;
    }

    error = 0;
    if ( sigsetjmp(alarm_env, 1) != 0 ) {
	    error = TIMEOUT;
	return NOTOK;
    }
    
    /************ Clean up the socket before we start UPD RTT test *********/

    FD_SET (clientUdpSocket, &readSet);
    timeOut.tv_sec = 0;                   
    timeOut.tv_usec = 1;  // 1 microsecond
    sig = select (clientUdpSocket+1, &readSet, NULL, NULL, &timeOut);
    if ( sig > 0 ) {      // Socket is readable
	rval=read(clientUdpSocket, rbuff, dataSize);
	if ( rval < 0 ) {
	    perror("Read socket error (UDP ping initialization).");
	    return NOTOK;
	}
    } else if ( sig < 0 ) { 
	perror("Select error (UDP ping initialization).");
	return NOTOK;
    } 

#ifdef DEBUG
    fprintf(stderr, " DEBUG: Start UDP RTT latency test (iteration %d).\n", iteration);
#endif

    /**************** Warm up and timing synchronization *******************/

    if ( write(clientUdpSocket, wbuff, dataSize) < 0 ) {
	perror("Write socket error (UDP ping warm up).");
	return NOTOK;
    }

    alarm (1);      // 1 second
    if ( read(clientUdpSocket, rbuff, dataSize) < 0 ) {
	alarm(0);
	perror("Read socket error (UDP ping sync).");
	return NOTOK;
    } else 
	alarm (0);  // Cancel timer
    
    if ( dataSize > 4 ) {
	if ( ntohl(rHeader->seq_number) != sequence ) {
	    fprintf(stderr, "Disorder [s:%d r:%d].\n", 
		    sequence, (int)ntohl(rHeader->seq_number));
	    error = DISORDER;
	    return NOTOK;
	}
    }

#ifdef DEBUG
    fprintf(stderr, " DEBUG: After warm up.\n");
#endif  
    
    /*************** Start timing and RTT (latency) test *******************/
    

    alarm(5);    // 5 second
    gettimeofday(&startTime, NULL);
    for ( i = 0; i < iteration; i++ ) {
	if ( dataSize > 4 ) {
	    sequence++;
	    wHeader->seq_number = htonl(sequence);
	}

#ifdef DEBUG
	// fprintf(stderr, ".");
#endif
	if ( write(clientUdpSocket, wbuff, dataSize) < 0 ) {
	    perror("Write socket error (UDP ping).");
	    alarm(0);
	    return NOTOK;
	} 

#ifdef DEBUG
	// fprintf(stderr, "*");
#endif
	
	if ( (msg=read(clientUdpSocket, rbuff, dataSize)) < 0 ) {
	    alarm(0);
	    perror("Read socket error (UDP ping).");
	    return NOTOK;
	} 

	if ( dataSize > 4 ) {
	    if ( ntohl(rHeader->seq_number) != sequence ) {
		fprintf(stderr, "Disorder [send_seq:%d read_seq:%d].\n", 
			sequence, (int)ntohl(rHeader->seq_number));
		error = DISORDER;
		alarm(0);
		return NOTOK;
	    } 
	}

    }   // end of for loop   
    gettimeofday(&endTime, NULL);
    alarm(0);

    udpsock->elapsedTime = (endTime.tv_sec-startTime.tv_sec) * 1000000LL 
 	                  + endTime.tv_usec -startTime.tv_usec;
    return OK;
    
    /* Using select() has slightly more overhead than above implementation */
    /*

    gettimeofday(&startTime, NULL);
    for ( i = 0; i < iteration; i++) {
	udpHeader->seq_number = htonl(i);
	if ( (rval = write (clientUdpSocket, buff, dataSize)) < 0 ) {
	    perror("UDP ping (send).");
	    return NOTOK;
	}
	
	FD_SET (clientUdpSocket, &readSet);
	timeOut.tv_sec = 2;  // 2 seconds                     
	timeOut.tv_usec = 0;
	sig = select (clientUdpSocket+1, &readSet, NULL, NULL, &timeOut);
	if ( sig > 0 ) {  // Socket is readable
	    rval=read(clientUdpSocket, buff, dataSize);
	    if ( rval < 0 ) {
		perror("UDP ping (read).");
		return NOTOK;
	    } else if ( rval != dataSize ) {
		fprintf(stderr, "UDP received data with wrong size: %d\n", rval);
	    }
	} else if ( sig == 0 ) { // Time out
		*error = TIMEOUT;  
		return NOTOK;
	} else if ( errno != EINTR ){
	    perror("UDP ping (select).");
	    return NOTOK;
	}
    }
    gettimeofday(&endTime, NULL);
     
    */
}

/*************************** UDP throughput test ***************************/
/** message: Total message to send                                        **/
/** precise_mode: Precise_mode has less overhead and is more accurate     **/
/** timeTime: Test time in seconds                                        **/
/** udpsock: UDP connection                                               **/
/** sendRate: Throughput constraint for testing (0 means unlimited)       **/
/***************************************************************************/

inline status_t client_udp_test ( long_int message, double testTime, 
		        struct UDPconnection *udpsock, long_int sendRate ) 
{
    int i, rval; 
    struct timeval startTime, endTime;                
    struct UDPHeader * udpHeader = (struct UDPHeader *) buffer;
    int clientUdpSocket = udpsock->socket;      // UDP socket
    int dataSize = udpsock->dataSize;           // Send size
    int sequence = 0;                           // Sequence of send packets
    int delay = 0;                              // Delay time between each sending
    long_int sentBytes = 0;                     // Data sent in bytes
    long_int elapsedTime = 0;                   // Elapsed time in microsecond
    long_int targetTime = 1000000LL*testTime;   // Test time in microsecond
    long_int throughput = 0;                    // throughput in bps

    if ( dataSize > udpsock->packetSize)
	dataSize = udpsock->packetSize;

    /****************** Initial delay time in microseconds *****************/
    /* If sendRate (throughput limit) is defined, We have a small interval
     * between each sending. This delay time is in microseconds level. To 
     * avoid a long period of sending if a small sendRate defined, we only 
     * consider the elapsed time in the test, and the data size sent may 
     * smaller than the massage size that user specifies.
     */

    if ( sendRate > 0 ) {
	delay = (8 * 1000000LL * dataSize / sendRate);
	if ( delay < 1 )
	    delay = 1;
	else  // No message size constraint for the test
	    message = 0;
    }

    /********* Set a timer to handle the time out situation ****************/

    if ( signal(SIGALRM, timeOutHandler) == SIG_ERR ) {
	perror("Set alarm signal (UDP throughput test).");
	return NOTOK;
    }

    error = 0;
    if ( sigsetjmp(alarm_env, 1) != 0 ) {
	error = TIMEOUT;
	return NOTOK;
    }

#ifdef DEBUG
    fprintf(stderr, " DEBUG: Start to synchronize (UDP oneway throughput test).\n");
#endif

    /**************** Warm up and timing synchronization *******************/

    alarm(2);  // 2 seconds
    udpHeader->seq_number = htonl(0);
    udpHeader->cmd = htonl(SYNC);
    if ( write(clientUdpSocket, buffer, HEADERSIZE) < 0 ||
	 (rval=read (clientUdpSocket, buffer, udpsock->packetSize)) < 0 ) { 
	alarm(0);
	perror("UDP throughput test warm up (sync) error.");
	return NOTOK;
    }

    if ( ntohl(udpHeader->seq_number) != 0 || ntohl(udpHeader->cmd) != ACKSYNC ||
	 rval != HEADERSIZE) {
    	alarm(0);
	fprintf(stderr, "UDP test sync error (packet disorder).\n");
	error = DISORDER;	
	return NOTOK;
    }  

    if ( write(clientUdpSocket, buffer, HEADERSIZE) < 0 ) {
	alarm(0);
	perror("UDP throughput test warm up (sync) error.");
	return NOTOK;
    }

    alarm(0);  // Cancel timer

#ifdef DEBUG
    fprintf(stderr, " DEBUG: Start to UDP oneway throughput test.\n");
#endif

    /****************** Start UDP throughput test **************************/

    gettimeofday(&startTime, NULL);
    do {
	udpHeader->seq_number = htonl(++sequence);
	udpHeader->cmd = htonl(DATA);

	if ( (rval=write(clientUdpSocket, buffer, dataSize)) < 0 ) {
	    perror("Write socket error (UDP throughput test).");
	    return NOTOK;
	}
	sentBytes += rval;
	gettimeofday(&endTime, NULL);
	elapsedTime = (endTime.tv_sec - startTime.tv_sec) * 1000000LL 
 	    + endTime.tv_usec - startTime.tv_usec;

	if ( sendRate > 0 ) {      // Adjust the throughput if defined
	    if ( elapsedTime > 0 )
		throughput = sentBytes * 8 * 1000000 / elapsedTime;

	    if ( throughput > sendRate ) // reduce throughput (increase delay)
	    	delay++;
	    else if ( delay > 0 )  // reduce the delay time
		delay--;
	    
	    delay_usec(delay);
	}

    } while ( sentBytes < message || elapsedTime < targetTime ); 
   
    /* Data was sent out and the test time is satisfied at this point. 
     * Send the last packet (FIN) many times (defined by MAXFIN) informing 
     * server the end of this trip of test. Assume at least one can reach 
     * the other end. 
     */

    for ( i = 0; i < MAXFIN; i++ ) {
	udpHeader->seq_number = htonl(++sequence);
	udpHeader->cmd = htonl(FIN);
	if ( ( rval=write(clientUdpSocket, buffer, HEADERSIZE)) < 0 ) {
	    perror("Write socket error (UDP throughput test sending FINs).");
	    return NOTOK;
	}

	/******** Stop timing and record the test statistics ***************/
	
	if ( i == 0 ) {
	    gettimeofday(&endTime, NULL);
	    udpsock->sentBytes = sentBytes + rval;
	    udpsock->sentPackets = sequence;
	    udpsock->recvBytes = 0;
	    udpsock->recvPackets = 0;
	    udpsock->elapsedTime = (endTime.tv_sec - startTime.tv_sec)*1000000LL 
		+ endTime.tv_usec - startTime.tv_usec;
	}
    }
	
#ifdef DEBUG
    fprintf(stderr, " DEBUG: C->S (UDP) UDP data were sent out! Resend the last packet 100 times\n");
    fprintf(stderr, " DEBUG: Client's Throughput: %f Mbps\n", sentBytes*8.0/elapsedTime); 
#endif 

    sleep(SERVERWAITTIME);  // Wait for while 

    return OK;
}

/**************** UDP bidirectional throughput test ************************/
/** message: Total message to send                                        **/
/** testTime: test time in seconds                                        **/
/** udpsock: UDP connection                                               **/
/***************************************************************************/

inline status_t client_udp_bi_test ( long_int message, double testTime, 
				  struct UDPconnection *udpsock ) 
{
    char recvBuff[udpsock->packetSize+1];
    int rval = 0, sig = 0; 
    struct timeval startTime, endTime, waitTime;                
    struct UDPHeader * udpHeader = (struct UDPHeader *) buffer;
    struct UDPHeader * recvHeader = (struct UDPHeader *) recvBuff;
    int clientUdpSocket = udpsock->socket;          // UDP socket
    int dataSize = udpsock->dataSize;               // Send size
    int sequence = 0;                               // Sequence of send packets
    int recvPackets = 0;                            // Received packet number
    int gotACKFIN = 0;                              // Got a ACKFIN from server?
    long_int sentBytes = 0;                         // Data sent in bytes
    long_int recvBytes = 0;                         // Data received in bytes
    long_int elapsedTime = 0;                       // Elapsed time in microsecond
    long_int targetTime = 1000000LL * testTime;     // Test time in microsecond
    fd_set readSet, writeSet;

    /****************** Clean up the fd_set structure **********************/    

    FD_ZERO(&readSet);
    FD_ZERO(&writeSet);

    /****************** dataSize must be less than packet size *************/

    if ( dataSize > udpsock->packetSize)
	dataSize = udpsock->packetSize;

    /************************ Set a time out handler  **********************/

    if ( signal(SIGALRM, timeOutHandler) == SIG_ERR ) {
	perror("Set alarm signal (UDP bidrectional throughput test).");
	return NOTOK;
    }

    error = 0;
    if ( sigsetjmp(alarm_env, 1) != 0 ) {
	error = TIMEOUT;
	return NOTOK;
    }

    /**************** Warm up and timing synchronization *******************/

    alarm(2);  // 2 seconds
    udpHeader->seq_number = htonl(0);
    udpHeader->cmd = htonl(SYNC);

    if ( write(clientUdpSocket, buffer, HEADERSIZE) < 0 ||
	 (rval=read (clientUdpSocket, buffer, udpsock->packetSize)) < 0 ) { 
	alarm(0);
	perror("UDP throughput test warm up (sync) error.");
	return NOTOK;
    }

    if ( ntohl(udpHeader->seq_number) != 0 || rval != HEADERSIZE || 
	 ntohl(udpHeader->cmd) != ACKSYNC ) {
    	alarm(0);
	fprintf(stderr, "UDP test sync error (packet disorder).\n");
	fprintf(stderr, "Sequence: %d Command: %d headersize: %d\n", 
		(int)ntohl(udpHeader->seq_number),  (int)ntohl(udpHeader->cmd), rval);
	error = DISORDER;

	/******************* Clear up the socket **************************/

	waitTime.tv_sec  = 1;   // 1 second
	waitTime.tv_usec = 0;
	FD_ZERO(&readSet);
	for (;;) {
	    FD_SET(clientUdpSocket, &readSet );
	    sig = select(clientUdpSocket+1, &readSet, NULL, NULL, &waitTime);
	    if ( (sig > 0) && (FD_ISSET(clientUdpSocket, &readSet)) ) {
		if ( read(clientUdpSocket, buffer, udpsock->packetSize) < 0 ) {
		    perror ("Read socket error (UDP bidirectional throughput test clean up).");
		    return NOTOK;
		}
	    } else if ( sig < 0 && errno != EINTR ) {
		perror("Select error (UDP bidirectional throughput test clean up).");
		return NOTOK;
	    } else if ( sig == 0 ) // Time out, quit.
		break;
	}

	return NOTOK;
    } 
 
    if ( write (clientUdpSocket, buffer, HEADERSIZE) < 0 ) {
	alarm(0);
	perror("UDP bidirectional throughput test warm up (sync) error.");
	return NOTOK;
    }

    if ( ntohl(udpHeader->seq_number) != 0 || ntohl(udpHeader->cmd) != ACKSYNC ) {
    	alarm(0);
	fprintf(stderr, "UDP bidirectional test sync error (packet disorder).\n");
	error = DISORDER;
	return NOTOK;
    }
    alarm(0);  // Cancel timer   

#ifdef DEBUG
    fprintf(stderr, " DEBUG: After sync, start timing.\n");
#endif

    /************* Start UDP bidirectional throughput test *****************/

    alarm(MAXTESTTIME);

    gettimeofday(&startTime, NULL);
    do {
	FD_SET(clientUdpSocket, &readSet);
	FD_SET(clientUdpSocket, &writeSet);

	sig = select(clientUdpSocket+1, &readSet, &writeSet, NULL, NULL);

	if ( sig > 0 && FD_ISSET(clientUdpSocket, &readSet) ) { // Ready to read

	    rval = read(clientUdpSocket, recvBuff, udpsock->packetSize);

	    if ( rval < 0 ) {
		perror("Read socket error (UDP bidirectional throughput test).");
		alarm(0);
		return NOTOK;
	    } else if ( rval == 0 )
		continue;
	    
	    recvBytes += rval;
	    recvPackets++;

	    /************ Test done if receive an ACKFIN message ***********/

	    if ( rval > 8 ) {
		if ( ntohl(recvHeader->cmd) == ACKFIN ) {
		    gettimeofday(&endTime, NULL);
		    sentBytes += rval;
		    udpsock->elapsedTime = (endTime.tv_sec - startTime.tv_sec) * 1000000LL 
			+ endTime.tv_usec - startTime.tv_usec;
		    udpsock->sentBytes = sentBytes;
		    udpsock->recvBytes = recvBytes;
		    udpsock->sentPackets = sequence;
		    udpsock->recvPackets = recvPackets;
		    gotACKFIN = 1;
		    break;
		} else if ( ntohl(recvHeader->cmd) != DATA ) 
		    fprintf(stderr, "Wrong data! : %d\n",  (int)ntohl(recvHeader->cmd));
	    }
	}

	if ( sig > 0 && FD_ISSET(clientUdpSocket, &writeSet) ) { // Ready to send

	    /********************** Fill packet's header *******************/

	    udpHeader->seq_number = htonl(++sequence);
	    // udpHeader->time_sec = htonl(endTime.tv_sec);    
	    // udpHeader->time_usec = htonl(endTime.tv_usec); 

	    /*********************** Send data *****************************/

	    if ( sentBytes < message || elapsedTime < targetTime ) {
		udpHeader->cmd = htonl(DATA);
		rval=write(clientUdpSocket, buffer, dataSize);
	    } 
	    else { // Send FIN packets if message is sent out and test time is satisfied
		udpHeader->cmd = htonl(FIN);
		rval=write(clientUdpSocket, buffer, HEADERSIZE);
	    }

	    sentBytes += rval;
	    if ( rval < 0 ) {
		perror("Write socket error (UDP bidirectional throughput test).");
		alarm(0);
		return NOTOK;
	    }
	} 

	if ( sig < 0 ) { 
	    perror("Select error (UDP bidirectional test).");
	    alarm(0);
	    return NOTOK;
	}

	gettimeofday(&endTime, NULL);
	elapsedTime = (endTime.tv_sec - startTime.tv_sec) * 1000000LL 
	    + endTime.tv_usec - startTime.tv_usec;

    } while ( sentBytes < message || elapsedTime < targetTime || !gotACKFIN );
    alarm(0);  

    /************ Clean up possible arriving (ACKFIN) packets **************/
    
    waitTime.tv_sec  = SERVERWAITTIME;   // 2 seconds
    waitTime.tv_usec = 0;
    FD_ZERO(&readSet);
    for (;;) {
	FD_SET(clientUdpSocket, &readSet );
	sig = select(clientUdpSocket+1, &readSet, NULL, NULL, &waitTime);
	if ( (sig > 0) && (FD_ISSET(clientUdpSocket, &readSet)) ) {
	    if ( read(clientUdpSocket, recvBuff, udpsock->packetSize) < 0 ) {
		perror ("Read socket error (UDP bidirectional throughput test clean up).");
		return NOTOK;
	    }
	} else if ( sig < 0 && errno != EINTR ) {
	    perror("Select error (UDP bidirectional throughput test clean up).");
	    return NOTOK;
	} else if ( sig == 0 ) // Time out, quit.
	    break;
    }

#ifdef DEBUG
    fprintf(stderr, " DEBUG: Client UDP bidirectional test sent out data.\n");
#endif

    return OK;
 
}


/********************* UDP traffic generator *******************************/

/* UDP is connectionless, we can send packets to a target host with desired
 * data rate without server(target host)'s support. This is OK for most Unix 
 * systems, which just ignore the ICMP errors sent from target host.
 */

status_t  udp_traffic_generator(char *hostName, int port, int bufferSize,
				double testTime, long_int targetThroughput)
{
    char buff[BUFLEN];
    struct hostent *hp;
    int rval, udpSocket;
    struct sockaddr_in clientAddress, serverAddress;
    struct timeval startTime, endTime;                
    int dataSize = DEFAULTDATAGRAM;
    int sentPackets = 0;
    int delayTime = 0;
    long_int sentBytes = 0;                 
    long_int elapsedTime = 0; 
    long_int targetTime = 1000000LL * testTime;   
    long_int throughput = 0;

    /************************* Create the socket ***************************/
  
    udpSocket  = socket(AF_INET, SOCK_DGRAM, 0);
    if ( udpSocket < 0) {
	perror("Creating client udp socket"); 
	return NOTOK;
    }

    if ( bufferSize >=0  ) {

#ifdef linux
	bufferSize = bufferSize / 2; // Get 20K when setting 10K in Linux
#endif
	if(  setsockopt(udpSocket, SOL_SOCKET, SO_SNDBUF, 
			(char *) &bufferSize, sizeof(bufferSize)) ) {
	    perror("Setting socket UDP SNDBUF buffer size.");
	    return NOTOK;
	}
    }
     
    /************************ Bind the socket ******************************/
  
    clientAddress.sin_family = AF_INET;
    clientAddress.sin_addr.s_addr = INADDR_ANY;
    clientAddress.sin_port = 0;
    if (bind(udpSocket, (struct sockaddr *)&clientAddress, sizeof(clientAddress))) {
	perror("Binding client udp socket"); 
	return NOTOK;
    }
  
    /*********************** Create the address for the server. ************/

    if ( atoi(hostName) > 0 ) {  // Numerical format
	serverAddress.sin_family = AF_INET;
	(serverAddress.sin_addr).s_addr = inet_addr(hostName);
    } else { // Domainname format
	if ((hp = gethostbyname(hostName)) == NULL) {
	    fprintf(stderr, "Unable to resolve server name %s!\n", hostName);
	    return NOTOK;
	}
	serverAddress.sin_family = AF_INET;
	bcopy(hp->h_addr, &serverAddress.sin_addr, hp->h_length);
    }
    serverAddress.sin_port = htons(port);

    fprintf(stderr, "Try to send UDP packets to %s on port %d\n", hostName, port);
    if ( targetThroughput == 0 )
	fprintf(stderr, "Send-time(Seconds): %.2f  Target-througput(Mbps): Unlimited\n", 
		testTime);
    else 
	fprintf(stderr, "Send-time(Seconds): %.2f  Target-througput(Mbps): %.2f\n", 
		testTime, targetThroughput/1000000.0);

    /****************** Initial delay time in microseconds *****************/

    if ( targetThroughput > 0 ) {
	delayTime = (8 * 1000000LL * dataSize / targetThroughput); 
	if ( delayTime < 1 )
	    delayTime = 1;
    }
    
    gettimeofday(&startTime, NULL); // Start timing
    do {
	
	if ( (rval=sendto(udpSocket, buff, dataSize, 0, (struct sockaddr *)&serverAddress, 
			  sizeof(serverAddress))) < 0 ) {
	    perror("UDP test (send).");
	    return NOTOK;
	}
	sentBytes += rval;
	sentPackets ++;

	gettimeofday(&endTime, NULL);
	elapsedTime = (endTime.tv_sec - startTime.tv_sec) * 1000000LL 
	    + endTime.tv_usec - startTime.tv_usec;

	if ( targetThroughput > 0 ) {   // Adjust the delay time between each sending
	    if ( elapsedTime > 0 )
		throughput = sentBytes * 8 * 1000000 / elapsedTime;

	    if ( throughput > targetThroughput ) // reduce throughput (increase delay)
	    	delayTime++;
	    else if ( delayTime > 0 ) // reduce the delay time
		delayTime--;
	    
	    delay_usec(delayTime);
	}
	    
    } while ( elapsedTime < targetTime );

    throughput = sentBytes * 8 * 1000000 / elapsedTime;
    fprintf(stderr, "Done! Elapsed-time(Seconds): %.2f\n", elapsedTime/1000000.0);
    fprintf(stderr, "Sent-packets: %d  Sent-bytes: %lld  Throughput(Mbps): %f\n", 
	    sentPackets, sentBytes, throughput/1000000.0);

    return OK;
}
