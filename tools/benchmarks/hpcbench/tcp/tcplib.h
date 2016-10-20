/***********************************************************************************/
/**                                                                               **/
/**         TCP communication benchmark                                           **/
/**         By Ben Huang, hben@users.sf.net March 2004                            **/
/**         TCP latency and throughput test between two processes                 **/
/**                                                                               **/
/**         "tcplib.h"                                                            **/
/**                                                                               **/
/***********************************************************************************/ 

#ifndef _TCP_LIB_HEADER_
#define _TCP_LIB_HEADER_

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <malloc.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/socket.h> 
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#ifdef linux
#include <sys/sendfile.h>
#endif
#include <sys/resource.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

/************************ External variable used by getopt *****************/

extern char *optarg;
extern int optopt;
   
/**************************** Define some constants ************************/
     
#define BUFLEN 1024
#define MAXNUMBER ( 1<<28 )   // Maximum number for tests
#define MINITRIALS 5          // The minimum of iteration 
#define MAXTRIALS 5000        // The maximum of iteration 
#define MAXLEN 29             // In Exponential test mode, maximum message size 2^29 (256 Mbps)
#define DEFAULTPORT 5677      // TCP conncection port number 
#define DEFAULTREPEAT 10      // Repetition of tests (invalid for exponential test)
#define DEFAULTSIZE (1<<16)   // Message size (64KB)    
#define DEFAULTRTT 64         // Message size for TCP RTT (latency) test                
#define DEFAULTTIME 5         // Test time  
#define PRETESTTIME  100000   // Iteration for this minimum time (usec)
#define MINITIME  100000      // Minimum test time in microseconds

/************************ Set IP packet's TOS ******************************/
/************ Traditional IP TOS is defined by RFC791 **********************/
/******* RFC2474 redefines this field as DSCP(DiffServ Code Point) *********/
/** We couldn't set highest IP precedence (EF) without root's privilege ****/

#define TOS_LOWDELAY   16     // 0x10 (Minimize delay)
#define TOS_MAXTP      8      // 0x08 (Maximize throughput)
#define DSCP_C1_DL     40     // 0x28 (AF11, DiffServ Class1 with low drop probabiltiy)
#define DSCP_C1_DH     56     // 0x38 (AF13, DiffServ Class1 with high drop probabiltiy)
#define DSCP_C4_DL     136    // 0x88 (AF41, DiffServ Class4 with low drop probabiltiy)
#define DSCP_C4_DH     152    // 0x98 (AF43, DiffServ Class4 with high drop probabiltiy)

/************************ Define some types ********************************/

#ifndef _BASIC_TYPES_
#define _BASIC_TYPES_
typedef long long long_int;   // 64-bit integer
typedef enum status_t { NOTOK = -1, OK = 0 } status_t;
enum test_info { LATENCY = 10, THROUGHPUT, SENDFILE };
#endif

/*********** Define structure for parameter settings ***********************/

struct Parameter
{
    int verbose;                 // Print out connection message?
    int latency_test;            // TCP RTT (latency) test (TCP ping)?  
    int sendfile_test;           // Sendfile() test?
    int stream_mode;             // Unidirectional throughput test?
    int exp_mode;                // Exponential test?    
    int exponent;                // Exponential test?
    int writeOption;             // Writing results to a file?
    int plotOption;              // Writing a plot file?
    int CPUoption;               // Monitor CPU and system information?
    int sCPUoption;              // Server also monitor system info?
    int iteration;               // Iteration for each test
    int repeat;                  // Repetition of tests
    long_int messageSize;        // Message size to be transmitted
    double testTime;             // Test time
};

/****************** Define TCP  connection structure ***********************/

struct TCPconnection
{
    int welcomeSocket;             // TCP server socket
    int socket;                    // TCP connection socket
    int fd;                        // File descriptor to send of sendfile() test
    int port;                      // TCP port number
    int blocking;                  // Blocking communication?
    int delay;                     // Enable Nagle algorithm?
    int recvBuf;                   // TCP socket (recv) buffer size
    int sendBuf;                   // TCP socket (send) buffer size
    int tos;                       // TOS (Type of Service) setting
    int mss;                       // MSS (Maximum Segment Size)
    int cork;                      // TCP_CORK option (avoid sending partial frames)
    long_int dataSize;             // Data size of each sending/receiving
};

/********* Define RTT structure for Round Trip Time (latency) test *********/

struct RTT                         // Round Trip Time (latency) test
{                                  // Just a UDP version of ping
    int mode;                      // 1: RTT-test 0: Thhroughput-test
    int size;                      // Message size for test
    int trial;                     // Test repetition
    double min;                    // Minimum of RTTs
    double max;                    // Maximum of RTTs
    double sum;                    // Sum of RTTs
    double avg;                    // Avarage of RTTs            
};

/********* Define Throughput structure for network throughput test *********/

struct Throughput                  // Network throughput test
{                              
    int trial;                     // Test repetition
    double min;                    // Minimum of throughputs
    double max;                    // Maximum of throughputs
    double sum;                    // Sum of throughputs
    double avg;                    // Avarage of throughputs
};
   
/*****************************  Global variables ***************************/

char * rbuffer;                          // Data (recv) buffer 
char * sbuffer;                          // Data (send) buffer

/**************** Some communication in the TCP data channel ***************/

#ifndef _TCP_LIB_
const char client_request_str[] = 
"TESTMODE %d BLOCKING %d DELAY %d TCPCORK %d STREAM %d RECVBUF %d SENDBUF %d MTU %d TOS %d DATASIZE %lld SYSINFO %d \r\n";
const char server_port_str[] = "TEST PORT %d \r\n";
const char server_parameter_str[] = 
"BLOCKING %d DELAY %d TCPCORK %d RECVBUF %d SENDBUF %d MTU %d TOS %d SYSINFO %d \r\n";
const char server_proinfo_str[] = "REALTIME %lld USERTIME %lld SYSTIME %lld \r\n";
const char test_start_str[] = "MESSAGESIZE %lld ITERATION %d \r\n";
const char test_done_str[] = "TEST DONE \r\n";
#endif

/*************** Routines for client/server in net.c ***********************/

void print_usage();
status_t send_request(int socket, char *request, int size);
status_t get_request(struct TCPconnection *sock, char *request);

/******************* Routines for server in net.c **************************/

status_t server_init(struct TCPconnection *sock);
status_t server_get_connection(struct TCPconnection *sock, struct in_addr *addr);
status_t server_tcp_test(long_int size, int iteration, int stream_mode, 
			 long_int *elapsedTime, struct TCPconnection *sock);

/******************* Routines for client in net.c **************************/

status_t client_connect(char *host, struct TCPconnection *sock);
status_t client_tcp_test (long_int size, int iteration, int stream_mode, 
			  long_int *elapsedTime, struct TCPconnection *sock);

#ifndef _TCP_LIB_

const char help_description[] =
"tcpserver/tcptest -- A TCP communication benchmark\n\n\
The TCP RTT (latency) test is just a TCP version of \"ping\". RTT is too short to be \n\
measured in HPC environments, so we repeat RTT test many times and get the average of RTTs.\n\n\
In the TCP tests, message size (-m option) specifies the amount of data to be sent each time. \n\
The iteration of sending/receiving for a test time (-t option) is determined by an evaluation \n\
test, so the actually test time could vary slightly. In exponential test, message size \n\
increases expontenally from 1 byte to a large number (-e option). Be aware that there is a \n\
minimum number of iteration, and the test time might be much greater than what you specify if \n\
the message size is very large.\n\n\
If CPU and system monitoring option (-c) is defined, both client and server's CPU usages \n\
(Maximum 8 CPUs supported for SMP systems), network interface statistics and its interrupts \n\
to each CPU will be recorded. Currently this option is only available for Linux system.\n\n";

const char help_usage[] =
"tcpserver usage: tcpserver [options]\n\
 %% tcpserver [-v] [-p port]\n\
 [-p port-number] Port number for TCP communication (0 picked by system). %d by default.\n\
 [-v] Verbose mode. Disable by default.\n\n\
tcptest usage: tcptest -h host [options]\n\
 %% tcptest -h host [-vanicCNP] [-p port] [-A rtt-size] [-e exponent] [-b buffer] [-B buffer] [-q qos]\n\
           [-M MSS] [-d data] [-m message] [-r repeat] [-t time] [-f sendfile] [-I iteration] [-o output]\n\
 [-a] Test the TCP Round Trip Time (RTT). Ignore all other options if defined.\n\
 [-A test-size] TCP RTT test with specified message size.\n\
 [-b buffer-size] TCP buffer (windows) size in bytes. System default if not defined.\n\
 [-B buffer] Server UDP buffer size in bytes. The same as cleint's by default.\n\
 [-c] CPU log option. Tracing system information during the test. Only availabe when output is defined.\n\
 [-C] Turn on socket's TCP_CORK option (avoid sending partial frames). Disable by default.\n\
 [-d data-size] Data size of each read/write in bytes. The same as packet size by default.\n\
 [-e n] Exponential tests with message size increasing exponentially from 1 to 2^n.\n\
 [-f sendfile] Sendfile test. Memory mapping is used to reduce the workload. Disable by default.\n\
 [-h host-name] Hostname or IP address of server. Must be specified.\n\
 [-i] Bidirectional UDP throuhgput test. Default is unidirection stream test.\n\
 [-I iteration] Iteration of sending/receiving for each test. Auto-determined by default.\n\
 [-m message-size] Message size in bytes. %d by default.\n\
 [-M MSS-size] Maximum Segent Size in bytes (MTU-40 for TCP). System default if not defined.\n\
 [-n] Non-blocking communication. Blocking communication by default.\n\
 [-N] Turn on socket's TCP_NODELAY option (disable Nagel algorithm). Disable by default.\n\
 [-o output] Output file name.\n\
 [-p port-number] Server's port number. %d by default.\n\
 [-P] Write the plot file for gnuplot. Only enable when the output is specified.\n\
 [-q qos] Define the TOS field of IP packets. Six value can be used for this setting:\n\
     1:(IPTOS)-Minimize delay 2:(IPTOS)-Maximize throughput \n\
     3:(DiffServ)-Class1 with low drop probability 4:(DiffServ)-class1 with high drop probability\n\
     5:(DiffServ)-Class4 with low drop probabiltiy 6:(DiffServ)-Class4 with high drop probabiltiy\n\
 [-r repeat] Repetition of tests. %d by default.\n\
 [-t test-time] Test time in seconds. Disable if iteration is sepcified. %d by default.\n\
 [-v] Verbose mode. Disable by default.\n\
 Note: Input supports the postfix of \"kKmM\". 1k=1024, 1M=1024x1024.\n\n";

const char help_example[] =
"Examples\n\n\
 1. Start server process\n\
 [server] %% tcpserver\n\n\
 2. Start client process\n\
 [client] %% tcptest -h server\n\
 TCP blocking stream test with default set of parameters, verbose off, no result writing.\n\
 Default buffer size, message-size: 65536, test-time: 5.00, test-repeat: 10\n\n\
 [server] %% tcpserver -p 3000\n\
 [client] %% tcptest -vn -h server -p 3000 -b 100k -m 10m -t 2 -r 20 -o output.txt\n\
 Repeat non-blocking stream tests by 20 times with communication port of 3000.\n\
 Buffer size: 100K, message size: 10M, test time: 2 Seconds, store results in \"output.txt\".\n\n\
 [client] %% tcptest -e 20 -vh server -b 100k -o output.txt\n\
 Exponential stream test for buffer size of 100 KB with verbose mode with message size \n\
 increasing exponentially from 1 Byte to 1 MByte (2^20).\n\n\
 [client] %% tcptest -ah server\n\
 TCP Round Trip Time (RTT) test. A TCP version of ping.\n\n\
 With plot option (-P), when an \"output\" file is specified, an \"output.plot\" file will also be \n\
 created for plotting. Use \"gnuplot ouput.plot\" to plot the data.\n\
 With CPU option (-c), when an  \"output\" file is specified, \"output.c_log\" and  \"output.s_log\"\n\
 files store the system information of client and server, respectively.\n\n";
 
#endif  // end of ifnedf _TCP_LIB_

#endif
