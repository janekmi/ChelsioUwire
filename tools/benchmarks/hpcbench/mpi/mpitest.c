/****************************************************************************************/
/**                                                                                    **/
/**              MPI communication benchmark                                           **/
/**              By Ben Huang, huang@csd.uwo.ca, March 2004                            **/
/**   Throughput test between two processes with specific size message                 **/
/**   or exponentially increasing size of messages                                     **/ 
/**   Communication functions: MPI_Send/MPI_Recv, MPI_Isend/MPI_Irecv                  **/
/**   Timing function: MPI_Wtime (slightly different with gettimeofday)                **/
/**                                                                                    **/
/****************************************************************************************/ 


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include "mpi.h"
#include "util.h"

/*********************** Define some constants  ****************************/


#define BUFLEN    1024 
#define EVALUATION 100        // Iteration for evaluation test
#define MINITRIALS 5          // The minimum of iteration 
#define MAXTRIALS 10000       // The maximum of iteration 
#define MAXNUMBER (1<<28)     // A large number
#define MAXLEN 30             // In Exponential test mode, maximum message size 2^30 (1000 Mbps)
#define DEFAULTREPEAT 10      // Repetition of tests (invalid for exponential test)
#define DEFAULTSIZE (1<<20)   // Message size (1MBytes)                     
#define DEFAULTTIME 5         // Test time

/************************ Global variables *********************************/                 

static char *sbuffer;                // Data (send) buffer
static char *rbuffer;                // Data (receive) buffer
static char localhost[BUFLEN];       // Host name of master node
static char curtime[BUFLEN];         // Time of testing
static char remotehost[BUFLEN];      // Host name of secondary node 
static char plotname[BUFLEN];        // Plot file name
static int stream_mode = 1;          // Stream or ping-pong test?
static int block_option = 1;         // Blocking or non-blocking communicaiton?
static int cpu_option = 0;           // Monitor system info?

/************************* Function prototype ******************************/

static status_t mpi_test(int, long_int, int, double *, struct SYSInfo *, struct PROInfo *, int);
static status_t write_plot(char *, int, int, int, long_int);


/****************************** Help message *******************************/

void print_usage() {
    fprintf(stderr, "\n mpitest -- A benchmark to test MPI communication between two processes (nodes).\n\n");
    fprintf(stderr, " Usage(MPICH): mpirun -np 2 mpitest [options]\n");
    fprintf(stderr, " %% mpirun -np 2 mpitest [-acinP] [-A size] [-e exponent] [-m message] [-o output] [-r repeat] [-t time]\n");

    fprintf(stderr, " [-a] Round Trip Time (latency) test. Disable by default.\n");
    fprintf(stderr, " [-A RTT-size] Specify the message size in bytes for RTT (latency) test.\n");
    fprintf(stderr, " [-c] CPU log option. Tracing system information during the test. Only available for Linux systems.\n");
    fprintf(stderr, " [-e n] Exponential tests with message size increasing exponentially from 1 to 2^n. Disable by default.\n");
    fprintf(stderr, " [-i] Ping-pong (bidirectional) test. Stream (unidirectional) test by default.\n");
    fprintf(stderr, " [-m message-size] Message size by bytes (1M by default). Disable in exponential tests.\n");
    fprintf(stderr, " [-n] Non-blocking communication. Blocking communication by default.\n");
    fprintf(stderr, " [-o output] Write test results to a file. Disable by default.\n");
    fprintf(stderr, " [-P] Plot file for gnuplot. Only enable when the output is specified. Disable by default.\n");
    fprintf(stderr, " [-r repeat] Repeat tests many times. Disable in exponential tests. 10 times by default.\n");
    fprintf(stderr, " [-t test-time] Specify test time by seconds. 5 seconds by default.\n");
    fprintf(stderr, " Note: Input supports the postfix of \"kKmM\". 1K=1024, 1M=1024x1024.\n\n"); 

    fprintf(stderr, " Example1: %% mpirun -np 2 mpitest\n");
    fprintf(stderr, "           Throughput stream test with default parameters.\n");
    fprintf(stderr, " Example2: %% mpirun -np 2 mpitest -e 20\n");
    fprintf(stderr, "           Exponential stream (unidirectional) test, message size from 1 byte to 2^20 (1M) bytes.\n"); 
    fprintf(stderr, " Example3: %% mpirun -np 2 mpitest -c -m 10m -Po output.txt\n");
    fprintf(stderr, "           Throughput stream test with 10MBytes message size, write result/plot files, log system info. \n"); 
    fprintf(stderr, " Example4: %% mpirun -np 2 mpitest -ni -m 100k -t 3 -r 10\n");
    fprintf(stderr, "           Nonblocking ping-pong test. Message-size: 100KBytes; test-ime: 3 seconds; repeat 10 times.\n");
    fprintf(stderr, " Example5: %% mpirun -np 2 mpitest -a -o rtt.txt\n");
    fprintf(stderr, "           MPI Round Trip Time (latency) test. Write the result to file \"rtt.txt\".\n\n"); 
    fprintf(stderr, " To use own machine file: mpirun -np 2 -machinefile <machine file> mpitest [options]\n");
    fprintf(stderr, "                      or: mpirun -p4pg <configuration file> mpitest [options]\n\n");

    fflush(stderr); 
    return;
}

/***************************** Main function *******************************/

int main(int argc, char **argv) 
{
    char buff[BUFLEN];
    char filename[BUFLEN];        
    short *ptr;
    int i, j, n, option, data, maxsize, trial;
    int process_number, rank;              // Node's number and idenfifier
    int latency_test=0;                    // MPI ping (RTT test)?
    int exp_mode=0;                        // Exponential test?
    int plot_option=0, write_file=0;       // Write results to files?
    int iteration;                         // Iteration of sending/receiving
    int pre_iteration;                     // The previous iteration (exponential test)
    int repeat=DEFAULTREPEAT;              // Repetition of tests
    double test_time = DEFAULTTIME;        // Test time in seconds
    double start_time, end_time;           // Timing variables
    double m_rtime, m_utime, m_stime;      // Master node's elapsed time and process time
    double s_rtime, s_utime, s_stime;      // Secondary node's times (real/user/system mode)
    double elapsed_time;                   // Elapsed time
    double throughput;                     // Throughput
    double rtt, rttMini, rttMax, rttSum;   // Round Trip Time for latency test
    struct SYSInfo *sysinfo=NULL, sysinfo1;// System (CPU/Interrupts) information
    struct PROInfo proinfo;                // Process information
    long_int message_size=DEFAULTSIZE;     // Message size
    long_int pre_message;                  // The previous message size (exponential test)
    FILE * output;                         // Output file 
    MPI_Status status;                     // MPI status
    MPI_Request r_request, s_request;      // MPI non-blocking flags

    /***************************** MPI initialization **********************/

    MPI_Init(&argc,&argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &process_number);

    /**************************** Only test two processes ******************/
  
    if ( process_number != 2 ) {
	if ( rank == 0 )
	    print_usage();
	MPI_Finalize();
	return 1;
    }  
    
    /********************** Parsing the command line ***********************/

    while ( (option = getopt (argc, argv, "acinPA:c:e:m:o:r:t:")) != -1) {
	switch ( option ) {
	case 'a':  /* RTT (latency) test (MPI ping) */
	    latency_test = 1;
	    message_size=64;
	    break;
	case 'A':  /* Message size for RTT test */
	    latency_test = 1;
	    strcpy(buff, optarg);
	    if ( (message_size = parse_size(buff)) < 1 )
		message_size = 1;
	    break;
	case 'c':  /* Monitor CPU and system loads */
	    cpu_option = 1;
	    break;
	case 'e':  /* Exponential test */
	    exp_mode = 1;
	    strcpy(buff, optarg);
	    n=atoi(buff);
	    if ( n < 2 || n > 30 )
		n = MAXLEN;
	    maxsize = (1<<n); // 2^n
	    break;
	case 'i':  /* Ping-pong (bidrectional) test */
	    stream_mode = 0;
	    break;
	case 'm':  /* Message size */
	    strcpy(buff, optarg);
	    message_size = parse_size(buff);
	    break;
	case 'n':  /* Non-blocking communication */
	    block_option = 0;
	    break;
	case 'o':  /* write test results to a file */
	    write_file = 1;
	    strcpy(filename, optarg);
	    break;
	case 'P':  /* write plot file for gnuplot*/
	    plot_option = 1;
	    break;
	case 'r':  /* test repetition */
	    strcpy(buff,optarg);
	    repeat = atoi(buff);
	    break;
	case 't':  /* test time */
	    strcpy(buff, optarg);
	    test_time = atof(buff);
	    break;
	default: 
	    if ( rank == 0 ) 
		print_usage();
	    MPI_Finalize();
	    return 1;
	}
    } 

    /**************** Initialization for latency test **********************/

    if ( latency_test ) {
        exp_mode = 0; 
	cpu_option = 0;
	stream_mode = 0;
	if ( test_time == DEFAULTTIME ) 
	    test_time = 0.2;  // 0.2 second if not defined
	rttMini = MAXNUMBER;
	rttMax = 0;
	rttSum = 0;
    }

    /******************** Allocate the memory ******************************/

    if ( exp_mode ) {  // exponential test
	repeat = n+1;
	if ( (sbuffer=(char *)malloc(maxsize+1))==NULL || 
	     (rbuffer=(char *)malloc(maxsize+1))==NULL )  {
	    fprintf(stderr, "Memory malloc error! Exitting...\n"); 
	    MPI_Finalize();
	    return 1;
	}	 

	/*** Randomize the buffer to prevent possible data compression *****/

 	srand(time(NULL));
	for ( ptr = (short *)sbuffer; ptr < (short *)(sbuffer+maxsize); ptr +=2 )
	    *ptr = (short)rand();  
	memset(rbuffer, 0, maxsize);
    } 
    else { // Not exponential tests

	if ( (sbuffer=(char*)malloc(message_size+1))==NULL 
	     || (rbuffer=(char*)malloc(message_size+1))==NULL ) {
	    fprintf(stderr, "Memory malloc error! Exitting...\n"); 
	    MPI_Finalize();
	    return 1;
	}

	/*** Randomize the buffer to prevent possible data compression *****/

 	srand(time(NULL));
	for ( ptr = (short *)sbuffer; ptr < (short *)(sbuffer+message_size); ptr +=2 )
	    *ptr = (short)rand();  
	memset(rbuffer, 1, message_size);
    }
    
    /******************** Write results to a file ? ************************/
    
    if ( write_file && filename != NULL && (output = fopen(filename, "w")) != NULL )
	write_file = 1;
 
    if ( !write_file ) // We only store system information in files
	cpu_option = 0;

    get_local_time(curtime, BUFLEN);


    /********************************************** Master node  ****************************************/ 
  
    if ( rank == 0 ) {      
	
	if ( cpu_option ) {  // Should we monitor the system information?

	    if ( start_trace_system( &sysinfo1) == NOTOK ) {
		fprintf(stderr, "Failed to monitor system information.");
		cpu_option = 0;
	    } 
	    /** Two more items to record the syslog of pre/post states */

	    else if ( (sysinfo = (struct SYSInfo *)malloc((repeat+2) 
			        * sizeof(struct SYSInfo))) == NULL ) {
		fprintf(stderr, "Master node failed to malloc for syslog.");
		cpu_option = 0;
	    }
	    
	    if ( cpu_option ) { // Record the pre-test syslog
		start_trace_system( &sysinfo[0]);
		sleep(1);
		stop_trace_system( &sysinfo[0] );
	    }
	} // end of cpu_option
	
	/******************* Record test environment ***********************/

	gethostname(localhost, BUFLEN);
	MPI_Recv(remotehost, BUFLEN, MPI_CHAR, 1, 0, MPI_COMM_WORLD, &status); 

	fprintf(stderr, "%s(Master-node) <--> %s(Secondary-node)\n", localhost, remotehost);
 
	if ( latency_test ) 
	    fprintf(stderr, "MPI communicaiton latency (roundtrip time) test\n\n");
	else 
	    fprintf(stderr, "%s %s %s test\n\n", exp_mode ? "Exponential":"Fixed-size", 
	            block_option? "blocking":"non-blocking", 
		    stream_mode ? "stream (unidirectional)":"ping-pong (bidirectional)");

	if ( write_file ) {
	    if ( latency_test ) {
		fprintf(output, "# MPI communication latency (roundtrip time) test -- %s\n", curtime);
		fprintf(output, "# Hosts: %s <----> %s\n", localhost, remotehost);
		fprintf(output, "# %s Communication (%s)\n", block_option ? "Blocking":"Non-blocking",
			block_option ? "MPI_Send/MPI_Recv":"MPI_Isend/MPI_Irecv");
		fprintf(output, "# Message size (Bytes) : %lld\n", message_size);
	    } else {
		fprintf(output, "# MPI communication test -- %s\n", curtime);
		fprintf(output, "# Test mode: %s %s\n", exp_mode ? "Exponential":"Fixed-size", 
			stream_mode ? "stream (unidirectional) test":"ping-pong (bidirectional) test");
		fprintf(output, "# Hosts: %s <----> %s\n", localhost, remotehost);
	    }
	}

	if ( exp_mode ) {  // exponential testing
	    
	    /******************* Write down the test information ***********/

	    if ( write_file) {
		if ( block_option ) 
		    fprintf(output, "# Blocking communication (MPI_Send/MPI_Recv)\n#\n");
		else 
		    fprintf(output, "# Non-blocking communication (MPI_Isend/MPI_Irecv)\n#\n");

		fprintf(output, "#   Message    Overall             Master-node  M-process  M-process   Slave-node   S-process  S-process\n");
		fprintf(output, "#     Size   Throughput Iteration Elapsed-time  User-mode   Sys-mode  Elapsed-time  User-mode   Sys-mode\n");
		fprintf(output, "#    Bytes       Mbps                 Seconds     Seconds    Seconds     Seconds     Seconds     Seconds\n");
	    }

	    /******************** Estimate the iteration *******************/

	    MPI_Barrier(MPI_COMM_WORLD);  // Synchronization
	    start_time = MPI_Wtime();
	    for ( i = 0; i < EVALUATION; i++ ) {
		MPI_Send(sbuffer, 1, MPI_BYTE, 1, 0, MPI_COMM_WORLD);
		if ( !stream_mode )
		    MPI_Recv(rbuffer, 1, MPI_BYTE, 1, 0, MPI_COMM_WORLD, &status);
	    }
	    end_time = MPI_Wtime();

	    elapsed_time = end_time - start_time;
	    pre_message = 1;
	    pre_iteration = EVALUATION;

	    /*********** Message size exponentially increases **************/

	    for ( i = 0; i < repeat; i++ ) {

		message_size = (1<<i);

		/****************** Compute the iteration ******************/

	        iteration = (pre_message * 1.0 / message_size) * pre_iteration 
		    * test_time / elapsed_time;

		if ( iteration < MINITRIALS ) // minimum iteration
		    iteration = MINITRIALS;
		else if ( iteration > MAXTRIALS ) // maximum iteration
		    iteration = MAXTRIALS;

		/*************** Inform secondary node the iteration *******/

		MPI_Send(&iteration, 1, MPI_INT, 1, 0, MPI_COMM_WORLD);
		
		/*************** Start mpi test ***************************/

		mpi_test(rank+1, message_size, iteration, &elapsed_time, &sysinfo[i+1], &proinfo, 1);

		m_utime = proinfo.utime_sec + proinfo.utime_usec/1000000.0;
		m_stime = proinfo.stime_sec + proinfo.stime_usec/1000000.0;
		MPI_Recv(&s_rtime, 1, MPI_DOUBLE, 1, 0, MPI_COMM_WORLD, &status);
		MPI_Recv(&s_utime, 1, MPI_DOUBLE, 1, 0, MPI_COMM_WORLD, &status);
		MPI_Recv(&s_stime, 1, MPI_DOUBLE, 1, 0, MPI_COMM_WORLD, &status);


		if ( stream_mode )  // stream mode
		    throughput = (message_size * iteration + 2) * 8.0 / elapsed_time / 1000000; 
		else               // ping-pong mode
		    throughput = message_size * 2 * iteration * 8.0 / elapsed_time / 1000000;  

		/*  Store current message size and iteration number for
		 *  next computation of iteration with different message size 
		 */

		pre_message = message_size;
		pre_iteration = iteration;
	  		  
		fprintf(stderr, "(%d) Message-size:%lld  Iteration:%d  Throughput:%.4f Mbps\n", 
			    i+1, message_size, iteration, throughput);

		/****************** Write results to a file ****************/
		
		if ( write_file ) 
		    fprintf(output, "%10lld%12.4f%10d%12.2f%12.2f%11.2f%12.2f%12.2f%12.2f\n",
			    message_size, throughput, iteration, elapsed_time, m_utime, m_stime, 
			    s_rtime, s_utime, s_stime);      
	    }
	    
	    /************************  NOT an exponential test  ************************/
	    /******************  Examine only one specific message size ****************/

	} else {

	    /********************* warm up *********************************/

	    MPI_Send(sbuffer, message_size, MPI_BYTE, 1, 0, MPI_COMM_WORLD);
	    MPI_Recv(rbuffer, message_size, MPI_BYTE, 1, 0, MPI_COMM_WORLD, &status);

	    /************************ Determine the iteration **************/

	    trial = MINITRIALS;
	    for (;;) {  // Ensure the test time is long enough
		MPI_Send(&trial, 1, MPI_INT, 1, 0, MPI_COMM_WORLD);
		MPI_Barrier(MPI_COMM_WORLD);
		start_time = MPI_Wtime();
		for ( i = 0; i < trial; i++ ) {
		    MPI_Send(sbuffer, message_size, MPI_BYTE, 1, 0, MPI_COMM_WORLD);
		    if ( !stream_mode )
			MPI_Recv(rbuffer, message_size, MPI_BYTE, 1, 0, MPI_COMM_WORLD, &status);
		}
		end_time = MPI_Wtime();
		if ( (end_time-start_time) > 0.2 )  // 0.2 second
		    break;
		trial *= 2;
	    }
	    	
	    /*********************** Final estimation test *****************/

	    MPI_Send(&trial, 1, MPI_INT, 1, 0, MPI_COMM_WORLD);
	    MPI_Barrier(MPI_COMM_WORLD);
	    start_time = MPI_Wtime();
	    for ( i = 0; i < trial; i++ ) {
		MPI_Send(sbuffer, message_size, MPI_BYTE, 1, 0, MPI_COMM_WORLD);
		if ( !stream_mode )
		    MPI_Recv(rbuffer, message_size, MPI_BYTE, 1, 0, MPI_COMM_WORLD, &status);
	    }
	    end_time = MPI_Wtime();
	    
	    /***** Compute the iteration and send it to secondary node *****/

	    iteration = trial * test_time / (end_time - start_time);
	    if ( iteration < MINITRIALS )
		iteration = MINITRIALS;
	    trial = -1; // Sigal tells secondary node the end of trial(estimation) test.
	    MPI_Send(&trial, 1, MPI_INT, 1, 0, MPI_COMM_WORLD);
	    MPI_Send(&iteration, 1, MPI_INT, 1, 0, MPI_COMM_WORLD);
		
	    /*************** Write down test information *******************/

	    if ( !latency_test ) // Throughput test
		fprintf(stderr, "Message-size: %lld Bytes   iteration: %d   test-time: %4f Seconds\n\n", 
			message_size, iteration, test_time);

	    if ( write_file) {
		if ( latency_test ) {
		    fprintf(output, "# Iteration: %d\n", iteration);
		    fprintf(output, "# Test time (Seconds): %.2f\n\n", test_time);
		    fprintf(output, "#             RTT-time \n");
		    fprintf(output, "#           Microseconds\n");
		} else {
		    if ( block_option ) 
			fprintf(output, "# Blocking communication (MPI_Send/MPI_Recv)\n");
		    else 
			fprintf(output, "# Non-blocking communication (MPI_Isend/MPI_Irecv)\n");
		    fprintf(output, "# Total data size of each test (Bytes): %lld\n", message_size*iteration); 
		    fprintf(output, "# Message size (Bytes): %lld\n# Iteration : %d\n", message_size, iteration);
		    fprintf(output, "# Test time: %3f\n# Test repetition: %d\n#\n", test_time, repeat);
		    fprintf(output, "#      Overall    Master-node  M-process  M-process   Slave-node   S-process  S-process\n");
		    fprintf(output, "#    Throughput  Elapsed-time  User-mode   Sys-mode  Elapsed-time  User-mode   Sys-mode\n");
		    fprintf(output, "#        Mbps        Seconds     Seconds    Seconds     Seconds     Seconds     Seconds\n");
		}
	    }

	    /******************* Start to fixed-szie communication test ****************/

	    for ( i = 0; i < repeat; i++) {

		/*************** Start mpi test ***************************/
		mpi_test(rank+1, message_size, iteration, &elapsed_time, &sysinfo[i+1], &proinfo, 1);

		m_utime = proinfo.utime_sec + proinfo.utime_usec/1000000.0;
		m_stime = proinfo.stime_sec + proinfo.stime_usec/1000000.0;
		MPI_Recv(&s_rtime, 1, MPI_DOUBLE, 1, 0, MPI_COMM_WORLD, &status);
		MPI_Recv(&s_utime, 1, MPI_DOUBLE, 1, 0, MPI_COMM_WORLD, &status);
		MPI_Recv(&s_stime, 1, MPI_DOUBLE, 1, 0, MPI_COMM_WORLD, &status);


		if ( stream_mode )  // stream mode
		    throughput = (message_size*iteration+2)* 8.0/elapsed_time/1000000; // Mbps
		else               // ping-pong mode
		    throughput = message_size*2*iteration*8.0/elapsed_time/1000000;    // Mbps

		/********************* Latency test ************************/
		
		if ( latency_test ) {  // Compute the RTTs 
		    rtt = elapsed_time * 1000000 / iteration;
		    if ( rttMini > rtt )
			rttMini = rtt;
		    if ( rttMax < rtt )
			rttMax = rtt;
		    rttSum += rtt;
	
		    if ( rtt > 1000 ) 
			fprintf(stderr, "MPI Round Trip Time (%d) : %6.3f msec\n", i+1, rtt/1000);
		    else 
			fprintf(stderr, "MPI Round Trip Time (%d) : %6.3f usec\n", i+1, rtt);
		    sleep (1);
		} 
		/*********************** Throughput test *******************/

		else {        
		    fprintf(stderr, "(%d) Throughput(Mbps): %.4f  Message-size(Bytes): %lld  Test-time: %.2f\n", 
			    i+1, throughput, message_size, elapsed_time);
		}

		/*************** Write results to the file *****************/
		
		if ( write_file ) {
		    if ( latency_test ) 
			fprintf(output, "%-4d%18.3f\n", i+1, rtt);   
		    else 
			fprintf(output, "%-4d%10.4f%13.2f%12.2f%11.2f%12.2f%12.2f%12.2f\n", i+1,
				throughput, elapsed_time, m_utime, m_stime, s_rtime, s_utime, s_stime);
		}

	    } // end of for loop 

	} // end of throughput/latency test

	/**** Test done. Printout the summary of mpi ping (latency test) ***/

	if ( latency_test ) { 
	    fprintf(stderr, "Message size (Bytes) : %lld\n", message_size);

	    if ( (rttSum/repeat) > 1000 )
		fprintf(stderr, "MPI RTT min/avg/max = %.3f/%.3f/%.3f msec\n", 
			rttMini/1000, rttSum/repeat/1000, rttMax/1000);
	    else
		fprintf(stderr, "MPI RTT min/avg/max = %.3f/%.3f/%.3f usec\n", 
			rttMini, rttSum/repeat, rttMax);
	    
	    if ( write_file )
		fprintf(output, "\n# MPI RTT (%lld-byte) min/avg/max = %.3f/%.3f/%.3f usec\n\n", 
			message_size, rttMini, rttSum/repeat, rttMax);
	}

	if ( write_file ) {
	    fprintf(stderr, "Test result: \"%s\"\n", filename);
	    fclose(output);
	}

	/**** Record post-test state syslog and write results to a file ****/

	if ( cpu_option ) {
	    start_trace_system( &sysinfo[repeat+1] );
	    sleep(1);
	    stop_trace_system( &sysinfo[repeat+1] );
	    strcpy(buff, filename);
	    strcat(buff, ".m_log");
	    if ( write_sys_info(sysinfo, repeat+2, buff, curtime, localhost) == OK )
		fprintf(stderr, "Master node's syslog: \"%s\"\n", buff); 
	}

	/********************* Write the plot configuration file ***********/

	if ( write_file && plot_option ) { 
	    if ( write_plot(filename, latency_test, exp_mode, stream_mode, message_size) == OK )
		fprintf(stderr, "Plot file: \"%s\". Use \"gnuplot %s\" to plot the data\n", 
			plotname, plotname);
	}

	fprintf(stderr, "Test done!\n");

    
	/*************************************** Secondary node ********************************/
    
    }  else if ( rank == 1 )  {  

	if ( cpu_option ) {  // Should we monitor the system information?

	    if ( start_trace_system( &sysinfo1) == NOTOK ) {
		fprintf(stderr, "Slave node failed to monitor syslog.");
		cpu_option = 0;
	    } else if ( (sysinfo = (struct SYSInfo *)malloc((repeat+2) 
				   * sizeof(struct SYSInfo))) == NULL ) {
		fprintf(stderr, "Slave node failed to malloc for syslog.");
		cpu_option = 0;
	    }
	    
	    if ( cpu_option ) {  // Record pre-test state syslog
		start_trace_system( &sysinfo[0] );
		sleep(1);
		stop_trace_system( &sysinfo[0] );
	    }
	} // end of cpu_option

	/************ Get host information and send to master node *********/

	gethostname(remotehost, BUFLEN);
	MPI_Send(remotehost, BUFLEN, MPI_CHAR, 0, 0, MPI_COMM_WORLD);

	if (exp_mode) {  // exponential test

	    /************************ Estimation test **********************/

	    MPI_Barrier(MPI_COMM_WORLD);  // Synchronization
	    for ( i = 0; i < EVALUATION; i++ ) {
		MPI_Recv(rbuffer, 1, MPI_BYTE, 0, 0, MPI_COMM_WORLD, &status);
		if ( !stream_mode)
		    MPI_Send(sbuffer, 1, MPI_BYTE, 0, 0, MPI_COMM_WORLD);	    
	    }	    
		
	    for ( i = 0; i < repeat; i++ ) { 
		message_size = 1<<i;      
		MPI_Recv(&iteration, 1, MPI_INT, 0, 0, MPI_COMM_WORLD, &status);  

		mpi_test(rank-1, message_size, iteration, &s_rtime, &sysinfo[i+1], &proinfo, 0);
		s_utime = proinfo.utime_sec + proinfo.utime_usec/1000000.0;
		s_stime = proinfo.stime_sec + proinfo.stime_usec/1000000.0;
		MPI_Send(&s_rtime, 1, MPI_DOUBLE, 0, 0, MPI_COMM_WORLD);
		MPI_Send(&s_utime, 1, MPI_DOUBLE, 0, 0, MPI_COMM_WORLD);
		MPI_Send(&s_stime, 1, MPI_DOUBLE, 0, 0, MPI_COMM_WORLD);
	    } 
	    
	    /*********************** NOT an exponential test ***************************/

	} else {  // tests for a specific message size

	    /*************************** warm up ***************************/

	    MPI_Recv(rbuffer, message_size, MPI_BYTE, 0, 0, MPI_COMM_WORLD, &status);
	    MPI_Send(sbuffer, message_size, MPI_BYTE, 0, 0, MPI_COMM_WORLD);
	    
	    /************************ Estimation test **********************/

	    trial = 0;
	    while ( trial != -1 ) { 
		MPI_Recv(&trial, 1, MPI_INT, 0, 0, MPI_COMM_WORLD, &status);
		if ( trial == -1 ) 
		    break;
		MPI_Barrier(MPI_COMM_WORLD);  // Synchronization
		for ( i = 0; i < trial; i++ ) {
		    MPI_Recv(rbuffer, message_size, MPI_BYTE, 0, 0, MPI_COMM_WORLD, &status);
		    if ( !stream_mode )
			MPI_Send(sbuffer, message_size, MPI_BYTE, 0, 0, MPI_COMM_WORLD);	    
		}
	    }
	    
	    /*********** Get the iteration for testing from master node ****/

	    MPI_Recv(&iteration, 1, MPI_INT, 0, 0, MPI_COMM_WORLD, &status); 

	    for ( i = 0; i < repeat; i++ ) {  // Start to test
		mpi_test(rank-1, message_size, iteration, &s_rtime, &sysinfo[i+1], &proinfo, 0);
		s_utime = proinfo.utime_sec + proinfo.utime_usec/1000000.0;
		s_stime = proinfo.stime_sec + proinfo.stime_usec/1000000.0;
		MPI_Send(&s_rtime, 1, MPI_DOUBLE, 0, 0, MPI_COMM_WORLD);
		MPI_Send(&s_utime, 1, MPI_DOUBLE, 0, 0, MPI_COMM_WORLD);
		MPI_Send(&s_stime, 1, MPI_DOUBLE, 0, 0, MPI_COMM_WORLD);
	    }
	}

	/**** Record post-test state syslog and write results to a file ****/

	if ( cpu_option ) { 
	    start_trace_system( &sysinfo[repeat+1] );
	    sleep(1);
	    stop_trace_system( &sysinfo[repeat+1] );
	    strcpy(buff, filename);
	    strcat(buff, ".s_log");
	    if ( write_sys_info(sysinfo, repeat+2, buff, curtime, remotehost) == OK )
		fprintf(stderr, "Secondary node's syslog: \"%s\"\n", buff); 
	}
	
    }
 
    /***************************  clean up things **************************/

    free(rbuffer);
    free(sbuffer);
    MPI_Finalize();
    return 0;
}


/****************************** Start MPI test *****************************/

static status_t mpi_test(int dest, long long message, int iteration, double *rtime, 
		struct SYSInfo *sysinfo, struct PROInfo *proinfo, int master_node)
{
    int i;
    double start_time, end_time;  
    MPI_Status status;                    
    MPI_Request r_request, s_request; 

    if ( cpu_option )  // Monitor system's information
	start_trace_system(sysinfo);

    start_trace_process(proinfo); // Monitor process's information

    MPI_Barrier(MPI_COMM_WORLD);  // Synchronization
    start_time = MPI_Wtime();     // Start timing

    if ( master_node ) { // Master node 
	if ( block_option) { // Blocking communication
	    for ( i = 0; i < iteration; i++ ) { 
		MPI_Send(sbuffer, message, MPI_BYTE, dest, 0, MPI_COMM_WORLD);
		if ( !stream_mode ) {  // ping-pong mode
		    MPI_Recv(rbuffer, message, MPI_BYTE, dest, 0, MPI_COMM_WORLD, &status);
		}
	    }   
	    if ( stream_mode ) // Finalizing for stream test 
		MPI_Recv(rbuffer, 2, MPI_BYTE, dest, 0, MPI_COMM_WORLD, &status); 
	}
	else {   // Non-blocking communication
	    for ( i = 0; i < iteration; i++ ) {
		MPI_Isend(sbuffer, message, MPI_BYTE, dest, 0, MPI_COMM_WORLD, &s_request);
		if ( !stream_mode ) // ping-pong mode
		    MPI_Irecv(rbuffer, message, MPI_BYTE, dest, 0, MPI_COMM_WORLD, &r_request);
		MPI_Wait(&s_request, &status);
		if ( !stream_mode )
		    MPI_Wait(&r_request, &status);
	    }
	}      
    }
    else {  // Secondary node 
	if ( block_option) { // Blocking communication
	    for ( i = 0; i < iteration; i++ ) { 
		MPI_Recv(rbuffer, message, MPI_BYTE, dest, 0, MPI_COMM_WORLD, &status);
		if ( !stream_mode ) {  // ping-pong mode
		    MPI_Send(sbuffer, message, MPI_BYTE, dest, 0, MPI_COMM_WORLD);
		}
	    }   
	    if ( stream_mode )  // Finalizing for stream test 
		MPI_Send(sbuffer, 2, MPI_BYTE, dest, 0, MPI_COMM_WORLD);
	}
	else {  // Non-blocking communication
	    for ( i = 0; i < iteration; i++ ) {
		MPI_Irecv(rbuffer, message, MPI_BYTE, dest, 0, MPI_COMM_WORLD, &r_request);
		if ( !stream_mode )  // ping-pong mode
		    MPI_Isend(sbuffer, message, MPI_BYTE, dest, 0, MPI_COMM_WORLD, &s_request);
		MPI_Wait(&r_request, &status);
		if ( !stream_mode )
		    MPI_Wait(&s_request, &status);
	    }
	}   
    }  
    end_time = MPI_Wtime();
    stop_trace_process(proinfo);

    if ( cpu_option ) {
	usleep(1000); // Wait a bit for data to be updated
	stop_trace_system(sysinfo);
    }
	
    *rtime = end_time - start_time;

    return OK;
}


/****** Write a configuration file for gnuplot to plot the data  ***********/

status_t write_plot(char *file_name, int latency_test, int exp_mode, 
		    int stream_mode, long_int size) 
{ 
    int i = 0, j = 0;
    char buff[BUFLEN];
    FILE * plot;

    /***************** Get the relative path name **************************/

    while ( file_name[i] != '\0' && i < strlen(file_name) ) {
        buff[j++] = file_name[i++];
        if ( buff[j-1] == '/' ) {   // "/home/user/result" -> "result"
            j = 0;
            buff[j] = file_name[i];
        }
    }
    buff[j] = '\0';

    strcpy(plotname, file_name);
    strcat(plotname, ".plot");
    
    if ( (plot = fopen(plotname, "w")) == NULL ) {
	fprintf(stderr, "%s: Unable to write the plot file!\n", plotname);
	return NOTOK;
    } 
    strcpy(file_name, buff);

    fprintf(plot, "# The configuration file for plotting the data of file %s \n", file_name);
    fprintf(plot, "# Usage: gnuplot %s.txt\n\n", file_name);
    fprintf(plot, "set key left\n");

    if ( latency_test ) 
	fprintf(plot, "set ylabel \"Round Trip Time (usec)\"\n");
    else 
	fprintf(plot, "set ylabel \"Throughput (Mbps)\"\n");

    if ( exp_mode ) {
	fprintf(plot, "set xlabel \"Message size (Bytes)\"\n");
	fprintf(plot, "set logscale x\n");
	fprintf(plot, "set title \"MPI %s Communication\\n", block_option ? "Blocking":"Non-blocking");
	fprintf(plot, "Exponential %s test\\n", stream_mode ? "stream (uidirectional)":"ping-pong (bidirectional)");
	fprintf(plot, "%s <--> %s\"\n", localhost, remotehost);
    } else {
	fprintf(plot, "set xlabel \"Trials\"\n");
	fprintf(plot, "set title \"MPI %s Communication\\n", block_option ? "Blocking":"Non-blocking");
	if ( latency_test ) 
	    fprintf(plot, "RTT (Ping-pong) test  Message-size (Bytes): %lld\\n", size);
	else 
	    fprintf(plot, "%s test  Message-size (Bytes): %lld\\n", stream_mode ? 
		    "Stream (unidirectional)":"Ping-pong (bidirectional)", size);
	fprintf(plot, "%s <--> %s\"\n", localhost, remotehost);
    }
    fprintf(plot, "plot \'%s\'using 1:2 notitle with lp\n", file_name);

    fprintf(plot, "pause -1 \"\\nCtrl^c to exit.\\nPush return to create postscript (ps, eps) files.\\n\"\n");

    /*** Output postscript (ps) and encapsulated postscript (eps) format ***/

    fprintf(plot, "set output \"%s.ps\"\n", file_name);
    fprintf(plot, "set term post color\n");
    fprintf(plot, "replot\n");
    fprintf(plot, "set output \"%s.eps\"\n", file_name);
    fprintf(plot, "set term post eps\n");
    fprintf(plot, "replot\n");
    fprintf(plot, "clear\n");

    fclose(plot);
    return OK;
}
