
/***************************************************************************/
/**                                                                       **/
/**         TCP communication benchmark                                   **/
/**         By Ben Huang, hben@users.sf.net March 2004                    **/
/**         TCP latency/throughput test between two processes             **/
/**                                                                       **/
/**         "tcplib.c"                                                    **/
/**                                                                       **/
/***************************************************************************/ 

#ifndef _TCP_LIB_
#define _TCP_LIB_
#include "tcplib.h"
#endif

/************************* Brief routine description ***********************/
/* 
 * void print_usage()                   // Print help message
 *
 * status_t send_request()              // (server/client) Send a small buffer
 * status_t get_request()               // (server/client) Get a text message 
 * 
 * status_t server_init()               // Serve init
 * status_t server_get_connection()     // Server accepts a connection
 * status_t server_tcp_test()           // Server starts to test
 *
 * status_t client_connect()            // Client connects to a server 
 * status_t client_tcp_test ()          // Client starts to test
 *
 */

/*********************** Help message (short version) **********************/

void print_usage() {  
    fprintf(stderr, "Usage: [server] %% tcpserver [options]\n");
    fprintf(stderr, "       [client] %% tcptest -h host [options]\n");
    fprintf(stderr, "Try \"tcpserver --help\" or \"tcptest --help\" for more information.\n");
    return;
}

/************ Sending data to the connected socket *************************/

status_t send_request(int sock, char *request, int size) 
{
    int rval;
    int left = size;
    char *buff = request;

    while ( left > 0 ) {
	if ( (rval = write ( sock, buff, left)) <= 0 ) {
	    perror("Sending request.");
	    return NOTOK;
	}
	left -= rval; 
	buff += rval;
    }

#ifdef DEBUG
    fprintf(stderr, " DEBUG: Send out request (size %d): %s\n", size, request);
#endif

    return OK;
}

/************* Getting a message from a connected socket ******************/

status_t get_request(struct TCPconnection *sock, char *request) 
{
    char buff1[BUFLEN], *buff = buff1;
    int rval = 0, got_r = 0;
    bzero(buff1, BUFLEN);

    while ( rval < (BUFLEN - 1)) {
	if  ( read(sock->socket, buff, 1) != 1)  {
	    return NOTOK;
	} else { 

	    /*****  Look for the \r\n combination on the end of a line *****/

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

/************************ TCP server initialization ************************/

status_t server_init(struct TCPconnection *sock) 
{
    struct sockaddr_in serverAddress;
    int value, length;
    int welcomeSocket;
    int delay = sock->delay;
    int MSSsize = sock->mss;
    int recvBuf = sock->recvBuf;
    int sendBuf = sock->sendBuf;

    /*************************** Create the socket  ************************/
  
    if ( (sock->welcomeSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
	perror("Creating server socket");
	return NOTOK;
    }
    welcomeSocket = sock->welcomeSocket;
    //   signal(SIGPIPE, SIG_IGN);

    /************** Let the socket rebindable in TIME_WAIT state ***********/

    value = 1;
    if ( setsockopt(welcomeSocket, SOL_SOCKET, SO_REUSEADDR, &value, 
		    sizeof(value)) < 0 ) {
	perror("Setting socket rebindable");
	return NOTOK;
    }
  
    /*********************** Set TCP buffer (window) size ******************/

    if ( recvBuf >= 0 ) {

#ifdef linux
	recvBuf = recvBuf / 2;  // Get 20k when setting 10k buffer in Linux
#endif
	if ( setsockopt(welcomeSocket, SOL_SOCKET, SO_RCVBUF, &recvBuf,  
			sizeof(recvBuf)) < 0) {
	    perror("Setting TCP socket RCVBUF");
	    return NOTOK;
	}
    } 

    length = sizeof(value);
    if ( getsockopt(welcomeSocket, SOL_SOCKET, SO_RCVBUF, &value, &length) < 0 ) {
	perror("Getting TCP socket RCVBUF");
	return NOTOK;
    }
    sock->recvBuf = value;

    if ( sendBuf >= 0 ) {
#ifdef linux
	sendBuf = sendBuf / 2;  // Get 20k when setting 10k buffer in Linux
#endif
	if ( setsockopt(welcomeSocket, SOL_SOCKET, SO_SNDBUF, &sendBuf,  
			sizeof(sendBuf)) < 0) {
	    perror("Setting TCP socket SNDBUF");
	    return NOTOK;
	} 
    }

    length = sizeof(value);
    if ( getsockopt(welcomeSocket, SOL_SOCKET, SO_SNDBUF, &value, &length) < 0 ) {
	perror("Getting TCP socket SNDBUF");
	return NOTOK;
    }
    sock->sendBuf = value;

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
	if ( setsockopt(welcomeSocket, IPPROTO_IP, IP_TOS, &value, length) < 0 ) {
	    perror("Setting TOS bits.");
	    return NOTOK;
	}
    }

    /************************** Verify TOS value ***************************/

    length = sizeof(value);
    if ( getsockopt(welcomeSocket, IPPROTO_IP, IP_TOS, &value, &length) < 0 ) {
	perror("Getting TOS bits.");
	return NOTOK;
    }
    sock->tos = value;

#ifdef TCP_MAXSEG

    /************************ Set TCP MTU/MSS size *************************/

    if ( MSSsize > 0 ) { 
#ifdef linux
	MSSsize = MSSsize + 12; // Most Linux systems use 12 bytes for timestamp
#endif
         if ( setsockopt( welcomeSocket, IPPROTO_TCP, TCP_MAXSEG, (char*) &MSSsize, 
			 sizeof(MSSsize)) < 0 ) {
            perror("Setting MTU(MSS)");
            return NOTOK;
        }
    }

#endif
    
    /************************* Disable Nagle algorithm *********************/

#ifdef TCP_NODELAY
    if ( !delay  ) {
	value = 1;
	if ( setsockopt(welcomeSocket, IPPROTO_TCP, TCP_NODELAY, &value, 
			sizeof(value)) < 0) {
	    perror("Setting the TCP_NODELAY option.");
	    return NOTOK;
	}
    }
#endif

    /************************ Set TCP_CORK option  *************************/
    /*** TCP_CORK option is new in Linux to avoid sending partial frames ***/

#ifdef TCP_CORK  
    if ( sock->cork == 1 && delay ) { // TCP_CORK and TCP_NODELAY are conflictive
	value = 1;
    	if ( setsockopt(welcomeSocket, SOL_TCP, TCP_CORK, &value, sizeof(value)) < 0 ) {
	    perror("Setting TCP_CORK.");
	    return NOTOK;
	} 
	sock->cork = 1;
    } else 
	sock->cork = 0;
#else 
    sock->cork = 0;
#endif

    /********** Bind the socket and set the port number. *******************/

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(sock->port);

    if (bind(welcomeSocket, (struct sockaddr *) &serverAddress, sizeof(serverAddress))) {
	perror("Binding server socket");
	return NOTOK;
    }

    length = sizeof(serverAddress);
    if (getsockname(welcomeSocket, (struct sockaddr *) &serverAddress, &length)) {
	perror("Getting socket name");
	return NOTOK;
    }
    sock->port = ntohs(serverAddress.sin_port);

    if ( listen(welcomeSocket, 5) < 0 ) {
	perror("TCP socket listen");
	return NOTOK;
    }

#ifdef DEBUG
    fprintf(stderr, " DEBUG: TCP channel [%d] ready to accept connections!\n", sock->port);
#endif

    return OK;
}

/***************** TCP server accepts a connection *************************/

status_t server_get_connection(struct TCPconnection *sock, struct in_addr *sin_addr) 
{
    struct sockaddr_in clientAddress;
    int value, length;

    do {
	length = sizeof(clientAddress);
	sock->socket = accept(sock->welcomeSocket, 
			      (struct sockaddr *) &clientAddress, &length);
    } while ( sock->socket < 0 && errno == EINTR );
    
    if (sock->socket < 0) {
	perror("Accetpting socket error."); 
	return NOTOK;
    }

    /******************** Setting non-blocking communication **************/
    
    if ( !sock->blocking ) {
	if ( (value = fcntl(sock->socket, F_GETFL, 0)) < 0 ||
	     fcntl(sock->socket, F_SETFL, value | O_NONBLOCK) < 0 ) {
	    perror("Setting non-blocking socket.");
	    return NOTOK;
	}
    }

#ifdef TCP_MAXSEG
    length = sizeof(value);
    if ( getsockopt(sock->socket, IPPROTO_TCP, TCP_MAXSEG, (char*)&value, &length) < 0 ) {
	perror("Getting MTU(MSS) size \n");
	return NOTOK;
    }
    sock->mss = value;
#endif
 
#ifdef DEBUG
    fprintf(stderr, " DEBUG: C->S (TCP) Server accepted a connection!\n");
#endif

    *sin_addr = clientAddress.sin_addr;

    return OK;
}

/************************** Client start TCP test **************************/
/** msgSize: message size                                                 **/
/** iteraion: iteration of sending/receiving                              **/
/** stream_mode: one direction test (pingpong mode is bidirection) test   **/
/** elapsedTime: elapsed time of the test                                 **/
/** sock: The TCP conneciton                                              **/
/***************************************************************************/  

status_t server_tcp_test( long_int msgSize, int iteration, int stream_mode, 
			  long_int *elapsedTime, struct TCPconnection *sock) 
{   
    int i, rval, slength = 0, rlength = 0; 
    long_int sleft = 0, rleft = 0, totalBytes = 0;
    struct timeval start, end;
    fd_set readSet, writeSet;

    int dataSize = sock->dataSize;
    int serverSocket = sock->socket;

    /********** Initialization for non-blocking communication **************/

    FD_ZERO(&readSet);
    FD_ZERO(&writeSet);
    totalBytes = msgSize * iteration;   
    sleft = totalBytes; 
    rleft = totalBytes;
	    
#ifdef DEBUG
    fprintf(stderr, " DEBUG: Start synchronization of the test.\n");
#endif

    /***************************** Warm up (Sync)  *************************/
    /************** ( No warm up step for TCP_CORK test ) ******************/

    if ( sock->blocking && !sock->cork) { // blocking communication
	if ( read(serverSocket, rbuffer, 1) == NOTOK ||
	     write(serverSocket, sbuffer, 1) == NOTOK ) {
	    perror("Warm up error");
	    return NOTOK;
	} 
    } else if ( !sock->cork ) { // non-blocking communication
	while ( slength != 1 || rlength != 1 ) {
	    if ( rlength != 1 && (rlength=read(serverSocket, rbuffer, 1)) < 0
		 && errno != EWOULDBLOCK ) {
		perror("Sycn read error.");
		return NOTOK;
	    }
	    if ( slength != 1 && (slength=write(serverSocket, sbuffer, 1)) < 0 
		 && errno != EWOULDBLOCK ) {
		perror("Sync send error.");
		return NOTOK;
	    }
	}
    }
    
#ifdef DEBUG
    fprintf(stderr, " DEBUG: Start to test.\n");
#endif

    /*********** Start regular (blocking) TCP communication test ************/
    /***** Sendfile test uses the same code of blocking stream test *********/
    /* 
     * Linux sendfile() uses zero copy mechanism, which eliminates the cost
     * of data transmission between user space and kernel space. Client sends
     * data with sendfile() function call and server read the data as usual 
     * socket communication procedure. Be aware that sendfile() test is always 
     * a unidirectional stream test
     */
    
    if ( sock->blocking ) {   // Blocking TCP test 
	gettimeofday(&start, NULL);      
	for ( i = 0; i < iteration; i++ ) { 
	    rleft = msgSize;
	    while ( rleft > 0 ) {
		if ( (rlength=read(serverSocket, rbuffer, dataSize < rleft ?
				   dataSize:rleft)) < 0 ) {
		    perror("Read socket error.");
		    return NOTOK;
		} else if ( rlength == 0 ) {
		    perror("Connection terminated.");
		    return NOTOK; 
		} else
		    rleft -= rlength;
	    }
	    sleft = msgSize; 
	    
	    if ( !stream_mode ) { // Ping-pong test
		while ( sleft > 0 ) {
		    if ( (slength=write(serverSocket, sbuffer, dataSize < sleft ? 
					dataSize:sleft)) < 0 ) {
			perror("Write socket error.");
			return NOTOK;
		    } else 
			sleft -= slength;
		} // end of while loop
	    } // end of ping-pong condition

	} // end of for loop

	if ( stream_mode && !sock->cork ) { // Finalize for stream test
	    if ( write(serverSocket, rbuffer, 1) == NOTOK ) {
		perror("Write socket error (finalizing for stream test).");
		return NOTOK;
	    }
	}
	gettimeofday(&end, NULL);

    } // end of blocking communication test
    
    /****************** Non-blocking TCP communication test ****************/
    
    else if ( stream_mode ) {  // Non-blocking TCP stream (unidirectional) test

	gettimeofday(&start, NULL);      
	while( rleft > 0 ) {
	    FD_SET(serverSocket, &readSet);
	    rval = select(serverSocket+1, &readSet, NULL, NULL, NULL );
	    if ( rval > 0 && (FD_ISSET(serverSocket, &readSet)) ) {
		if ( (rlength=read(serverSocket, rbuffer, 
				   dataSize<rleft ? dataSize:rleft)) < 0 ) {
		    if ( errno != EWOULDBLOCK  ) {
			perror("Read socket error.");
			return NOTOK;
		    }
		} else if ( rlength > 0 ) {
		    rleft -= rlength;
		} else if ( rlength == 0 ) {
		    perror("Connection terminated.");
		    return NOTOK;
		}
	    } else if ( rval < 0 && errno != EINTR ) {
		perror("Select error.");
		return NOTOK;
	   }
	}
	while ( !sock->cork && (slength=write(serverSocket, sbuffer, 1))
		!= 1 ) { // Finalization for stream test
	    if ( slength < 0 && errno != EWOULDBLOCK )
		perror("Finalizing error.");
	    return NOTOK;
	}
	gettimeofday(&end, NULL);
	
    } else { // Non-blocking TCP bidirectional test
	
 	gettimeofday(&start, NULL);      
	while( sleft > 0 || rleft > 0 ) {
	    if ( sleft > 0 )
		FD_SET(serverSocket, &writeSet);
	    if ( rleft > 0  )
		FD_SET(serverSocket, &readSet);
	    rval = select(serverSocket+1, &readSet, &writeSet, NULL, NULL );
	    if ( rleft > 0 && (FD_ISSET(serverSocket, &readSet)) ) {
		if ( (rlength = read(serverSocket, rbuffer, 
				     dataSize < rleft ? dataSize:rleft)) < 0 ) {
		    if ( errno != EWOULDBLOCK ) {
			perror("Read socket error.");
			return NOTOK;
		    } 
		} else if ( rlength == 0 ) {
		    perror("Connection terminated.");
		    return NOTOK;
		} else
		    rleft -= rlength;
	    }
	    if ( sleft > 0 && (FD_ISSET(serverSocket, &writeSet)) ) {
		if ( (slength = write(serverSocket, sbuffer, 
				      dataSize < sleft ? dataSize:sleft)) < 0 ) {
		    if ( errno != EWOULDBLOCK ) {
			perror("Write socket error.");
		       return NOTOK;
		    }
		} else
		    sleft -= slength;
	    }
	    if ( rval < 0 && errno != EINTR ) {
		perror("Select error.");
		return NOTOK;
	   }
	}
	gettimeofday(&end, NULL);

    } // End of non-blocking TCP pingpong test 

    *elapsedTime = 1000000LL * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;  
  
#ifdef DEBUG
    fprintf(stderr, " DEBUG: One trip of client test done. Elapsed time: %lld\n\n", *elapsedTime);
#endif
  
    return OK;

}


/***************** Client initialize and connect to server *******************/

status_t client_connect(char *hostname, struct TCPconnection *sock)
{
    int value, length;
    int clientSocket;
    int port = sock->port;
    int delay = sock->delay;
    int recvBuf = sock->recvBuf;
    int sendBuf = sock->sendBuf;
    int MSSsize = sock->mss;
    struct hostent *hp;
    struct sockaddr_in serverAddress; 

    if ( sock->port <= 0  ) {  
	fprintf(stderr, "Port number should be an integer \n");
	return NOTOK;
    }

    /**************************** Create the socket ************************/

    if ( (sock->socket = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
	perror("Creating socket"); 
	return NOTOK;
    }
    clientSocket = sock->socket;

    //signal(SIGPIPE, SIG_IGN);

    /********************* Setting buffer size  ****************************/

    if ( recvBuf >= 0 ) {
#ifdef linux
	recvBuf = recvBuf / 2; // Get 20k when setting 10k buffer in Linux
#endif
	if ( setsockopt(clientSocket, SOL_SOCKET, SO_RCVBUF, &recvBuf, sizeof(recvBuf)) < 0) {
	    fprintf(stderr, "Setting TCP RCVBUF buffer size error...\n");
	    return NOTOK;
	} 
    }

    length = sizeof(value);
    if ( getsockopt(clientSocket, SOL_SOCKET, SO_RCVBUF, &value, &length) < 0 ) {
	perror("Getting TCP socket RCVBUF size");
	return NOTOK;
    }

    sock->recvBuf = value;
    if ( sendBuf >= 0 ) {
#ifdef linux
	sendBuf = sendBuf / 2; // Get 20k when setting 10k buffer in Linux
#endif
	if ( setsockopt(clientSocket, SOL_SOCKET, SO_SNDBUF, &sendBuf,  sizeof(sendBuf)) < 0) {
	    fprintf(stderr, "Setting TCP SNDBUF buffer size error...\n");
	    return NOTOK;
	} 
    }

    length = sizeof(value);
    if ( getsockopt(clientSocket, SOL_SOCKET, SO_SNDBUF, &value, &length) < 0 ) {
	perror("Getting TCP socket SNDBUF size");
	return NOTOK;
    }
    sock->sendBuf = value;

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
	if ( setsockopt(clientSocket, IPPROTO_IP, IP_TOS, &value, length) < 0 ) {
	    perror("Setting TOS bits.");
	    return NOTOK;
	}
    }

    /************************** Verify TOS value ***************************/

    length = sizeof(value);
    if ( getsockopt(clientSocket, IPPROTO_IP, IP_TOS, &value, &length) < 0 ) {
	perror("Getting TOS bits.");
	return NOTOK;
    }
    sock->tos = value;

    /************************ Set TCP MTU(MSS) size ************************/

#ifdef TCP_MAXSEG

    if ( MSSsize > 0 ) {
#ifdef linux
	MSSsize = MSSsize + 12; // Most Linux systems use 12 bytes for timestamps
#endif
	if ( setsockopt( clientSocket, IPPROTO_TCP, TCP_MAXSEG, (char*) &MSSsize, 
			 sizeof(MSSsize)) < 0 ) {
            perror("Setting MTU(MSS)");
            return NOTOK;
        }
    }
#endif

    /********* Setting NODELAY option (disable Nagle algorithm) ************/

#ifdef TCP_NODELAY
    if ( !delay  ) {
	value = 1;
	if ( setsockopt(clientSocket, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value)) < 0) {
	    perror("Setting TCP_NODELAY option.");
	    return NOTOK;
	}
    }
#endif

    /************************ Set TCP_CORK option  *************************/
    /*** TCP_CORK option is new in Linux to avoid sending partial frames ***/

#ifdef TCP_CORK    
    if ( sock->cork == 1 && delay ) { // Shouldn't combine TCP_CORK and TCP_NODELAY together
	value = 1;
	if ( setsockopt(clientSocket, SOL_TCP, TCP_CORK, &value, sizeof(value)) < 0 ) {
	    perror("Setting TCP_CORK.");
	    return NOTOK;
	} 
	sock->cork = 1;
	//printf("work in TCP_CORK mode\n");
    } else 
	sock->cork = 0;
#else 
    sock->cork = 0;
#endif

    /******************* Convert server address  ***************************/

    if ( atoi(hostname) > 0 ) {       // Numerical type
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_addr.s_addr = inet_addr(hostname);
    } else {                          // Domain name type
	if ((hp = gethostbyname(hostname)) == NULL) {
	    fprintf(stderr, "Unable to resolve server name %s!\n", hostname);
	    return NOTOK;
	}
	serverAddress.sin_family = AF_INET;
	bcopy(hp->h_addr, &serverAddress.sin_addr, hp->h_length);
    }
    serverAddress.sin_port = htons(port);

    /******************** Connect to the server  ***************************/

    if ( connect(clientSocket, (struct sockaddr *) &serverAddress, 
		 sizeof(serverAddress)) < 0) {
	perror("Connecting socket"); 
	return NOTOK;
    }

#ifdef TCP_MAXSEG
    /********************** Print out MTU(MSS) value ***********************/
    length = sizeof(value);
    if ( getsockopt( clientSocket, IPPROTO_TCP, TCP_MAXSEG, (char*) &value, 
			 &length ) < 0 ) {
	perror("Getting MTU(MSS) size.");
	return NOTOK;
    }
    sock->mss = value;
#endif

    /******************** Setting non-blocking communication **************/
    
    if ( !sock->blocking ) {
	if ( (value = fcntl(clientSocket, F_GETFL, 0)) < 0 ||
	     fcntl(clientSocket, F_SETFL, value | O_NONBLOCK) < 0 ) {
	    perror("Setting non-blocking socket.");
	    return NOTOK;
	}
    }

    return OK;
}

/************************** Client start TCP test **************************/
/** msgSize: message size                                                 **/
/** iteraion: iteration of sending/receiving                              **/
/** stream_mode: one direction test (pingpong mode is bidirection) test   **/
/** elapsedTime: elapsed time of the test                                 **/
/** sock: The TCP test conneciton                                         **/
/***************************************************************************/  

status_t client_tcp_test(long_int msgSize, int iteration, int stream_mode, 
			 long_int *elapsedTime, struct TCPconnection *sock) 
{   
    int i, rval, slength = 0, rlength = 0;
    long_int sleft = 0, rleft = 0, totalBytes = 0;
    struct timeval start, end;
    off_t offset;
    fd_set readSet, writeSet;

    int dataSize = sock->dataSize;
    int clientSocket = sock->socket; 

	
    /********** Initialization for non-blocking communication **************/

    FD_ZERO(&readSet);
    FD_ZERO(&writeSet);
    totalBytes = msgSize * iteration;    
    sleft = totalBytes;
    rleft = totalBytes;

#ifdef DEBUG
    fprintf(stderr, " DEBUG: Start synchronization of the test.\n");
#endif

    /***************************** Warm up (Sync)  *************************/
    /******************** NOT included for TCP_CORK test *******************/

    if ( sock->blocking && !sock->cork ) {  // blocking communication
	if ( write(clientSocket, sbuffer, 1) == NOTOK ||
	     read(clientSocket, rbuffer, 1) == NOTOK ) {
	    perror("Warm up error.");
	    return NOTOK;
	} 
    } else if ( !sock->cork ) {  // non-blocking communication
	while ( slength != 1 || rlength != 1 ) {
	    if ( slength != 1 && (slength=write(clientSocket, sbuffer, 1)) < 0 
		 && errno != EWOULDBLOCK ) {
		perror("Sync send error.");
		return NOTOK;
	    }
	    if ( rlength != 1 && (rlength=read(clientSocket, rbuffer, 1)) < 0
		 && errno != EWOULDBLOCK ) {
		perror("Sycn read error.");
	    }
	}
    }

#ifdef DEBUG
    fprintf(stderr, " DEBUG: Start to test.\n");
#endif

    /************************** sendfile() test ****************************/
    /* 
     * Linux sendfile() uses zero copy mechanism, which eliminates the cost
     * of data transmission between user space and kernel space. Client sends
     * data with sendfile() function call and server read the data as usual 
     * socket communication procedure. Be aware that sendfile() test is always 
     * a unidirectional stream test
     */

    if ( sock->fd > 0 ) {    // file descriptor for sendfile
	gettimeofday(&start, NULL);      
	for ( i = 0; i < iteration; i++ ) { 
	    sleft = msgSize; 
	    while ( sleft > 0 ) { 
		offset = 0;
#ifdef linux
		if ( (slength=sendfile(clientSocket, sock->fd, &offset, dataSize < sleft ? 
				       dataSize:sleft)) < 0 ) {
		    perror("Sendfile error.");
		    return NOTOK;
		} else 
		    sleft -= slength;
#else
		fprintf(stderr, "Sendfile() tests not supported.\n");
		return NOTOK;
#endif
	    }
	}

	if (!sock->cork ) { // Finalization
	    if ( read(clientSocket, rbuffer, 1) < 0 ) {
		perror("Read socket (finalizing for stream test).\n");
		return NOTOK;
	    }
	}

	gettimeofday(&end, NULL);
    }

    /*********** Regular (blocking) TCP communication test ******************/
    
    else if ( sock->blocking ) { // blocking test

	gettimeofday(&start, NULL);      
	for ( i = 0; i < iteration; i++ ) { 
	    sleft = msgSize; 
	    while ( sleft > 0 ) { 
		if ( (slength=write(clientSocket, sbuffer, dataSize < sleft ? 
				    dataSize:sleft)) < 0 ) {
		    perror("Write socket.");
		    return NOTOK;
		} else 
		    sleft -= slength;
	    }
	    rleft = msgSize;

	    if ( !stream_mode ) { // Ping-pong mode
		while (rleft > 0 ) { 
		    if ( (rlength=read(clientSocket, rbuffer, dataSize < rleft ?
				       dataSize:rleft)) < 0 ) {
			perror("Read socket.");
			return NOTOK;
		    } else if ( rlength == 0 ) {
			perror("Connection terminated.");
			return NOTOK;
		    } else
			rleft -= rlength;

		} // end of while loop
	    } // end of ping-pong test condition

	} // end of for loop 

	if ( stream_mode && !sock->cork ) { // Finalize for stream test
	    if ( read(clientSocket, rbuffer, 1) < 0 ) {
		fprintf(stderr, "Read error (finalizing for stream test).\n");
		return NOTOK;
	    }
	}
	gettimeofday(&end, NULL);
    }
    
    /************* Start non-blocking TCP communication test ***************/

    else if ( stream_mode ) { // Non-blocking stream (unidirectional) test

	gettimeofday(&start, NULL);      
	while( sleft > 0 ) {
	    if ( (slength=write(clientSocket, sbuffer, 
				dataSize < sleft ? dataSize:sleft)) < 0 ) {
		if ( errno != EWOULDBLOCK ) {
		    perror("Write socket.");
		    return NOTOK;
		}
	    } else
		sleft -= slength;
	}
	while ( !sock->cork && (rlength=read(clientSocket, rbuffer, 1)) != 1 ) {
	    if ( rlength < 0 && errno != EWOULDBLOCK )
		perror("Read error (finalization for stream test).");
	}
	gettimeofday(&end, NULL);

	
    } // end of non-blocking stream test
    
    else { // Non-blocking bidirectional test
	
	gettimeofday(&start, NULL);      
	while( sleft > 0 || rleft > 0 ) {
	    if ( sleft > 0 )
		FD_SET(clientSocket, &writeSet);
	    if ( rleft > 0  )
		FD_SET(clientSocket, &readSet);
	    rval = select(clientSocket+1, &readSet, &writeSet, NULL, NULL);
	    if ( rleft > 0 && (FD_ISSET(clientSocket, &readSet)) ) {
		if ( (rlength = read(clientSocket, rbuffer, 
				     dataSize < rleft ? dataSize:rleft)) < 0 ) {
		    if ( errno != EWOULDBLOCK ) {
			perror("Read socket.");
			return NOTOK;
		    }
		} else if ( rlength == 0 ) {
		    perror("Connection terminated.");
		    return NOTOK;
		} else
		    rleft -= rlength;
	    }
	    if ( sleft > 0 && (FD_ISSET(clientSocket, &writeSet)) ) {
		if ( (slength = write(clientSocket, sbuffer, 
				      dataSize < sleft ? dataSize:sleft)) < 0 ) {
		    if ( errno != EWOULDBLOCK ) {
			perror("Write socket.");
			return NOTOK;
		    }
		} else
		    sleft -= slength;
	    }
	    if ( rval < 0 ) {
		perror("Select.");
		return NOTOK;
	    }
	}
	gettimeofday(&end, NULL);

    }   // end of non-blocking pingpong test
    
    *elapsedTime = 1000000LL * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;  
    
#ifdef DEBUG
    fprintf(stderr, " DEBUG: One trip of client test done [%lld usec].\n", *elapsedTime);
#endif
  
    return OK;

}


