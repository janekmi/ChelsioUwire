
/***************************************************************************/
/**                                                                       **/
/**     UDP communication benchmark                                       **/
/**     By Ben Huang, huang@csd.uwo.ca, April 2004                        **/
/**     UDP latency and throughput test between two processes             **/
/**                                                                       **/
/**     "udplib.h"                                                        **/
/**                                                                       **/
/***************************************************************************/ 

#ifndef _UDPLIB_HEADER_
#define _UDPLIB_HEADER_

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
#include <sys/resource.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

/************************ External variable used by getopt *****************/

extern char *optarg;
extern int optopt;

/*********************** Define some constants  ****************************/

#define BUFLEN    1024 
#define MAXNUMBER (1<<28)       // A large number 
#define DEFAULTSIZE (1<<20)     // 1M Message size
#define DEFAULTTIME 5           // 5 second test time
#define DEFAULTREPEAT 10        // Repetition of tests
#define DEFAULTDATAGRAM 1460    // UDP datagram size
#define MAXDATAGRAM 65000       // Maximum datagram size
#define DEFAULTPORT 5678        // Communication port number
#define HEADERSIZE 32           // Our self-defined UDP header size
#define MAXTESTTIME 60          // Maximum test time in seconds for UDP server
#define SERVERWAITTIME 2        // Pause time in second for UDP server
#define MINITIME 200000         // The minimum test time in microseconds
#define MAXFIN 1000             // The maximum number of sending FIN signal

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

enum test_info { 
    LATENCY = 1000,              // RTT (latency) test (UDP ping)
    TPSTREAM,                    // Throughput test
    TPBIDIRECT,                  // Bidirectional TP testf
    TIMEOUT,                     // Time out error
    DISORDER,                    // Packets in disorder
    END                          // End sign
};

enum cmd_info {
    SYNC = 2000,                 // Synchronization
    ACKSYNC,                     // ACK of SYNC
    DATA,                        // Data
    ACKDATA,                     // ACK of Data
    FIN,                         // FIN 
    ACKFIN                       // ACK of FIN
};

#ifndef _BASIC_TYPES_
#define _BASIC_TYPES_
typedef long long long_int;   // 64-bit integer
typedef enum status_t { NOTOK = -1, OK = 0 } status_t;
#endif


/*********** Define structure for parameter settings ***********************/

struct Parameter
{
    int verbose;                 // Print out connection message?
    int latency;                 // UDP RTT (latency) test?     
    int bidirection;             // Bidirectional throughput test?
    int exponential;             // Exponential test?
    int writeOption;             // Writing results to a file?
    int plotOption;              // Writing a plot file?
    int CPUoption;               // Monitor CPU and system information?
    int sCPUoption;              // Server also monitor system info?
    int port;                    // TCP connection port number
    int repeat;                  // Repetition of tests
    int udpGen;                  // UDP traffic generator?
    double testTime;             // Test time
    long_int messageSize;        // Message size to be transmitted
    long_int throughput;         // Throughput constraint setting 
};

/*********** Define TCP and UDP connection structure ***********************/

struct TCPconnection
{
    int welcomeSocket;                  // TCP server socket
    int socket;                         // TCP connection socket
    int port;                           // TCP port number
};

struct UDPconnection
{
    int socket;                         // File descriptor for socket
    int port;                           // Port number
    int tos;                            // IP TOS (Type of service) setting
    int recvBuf;                        // Receiving buffer size
    int sendBuf;                        // Sending buffer size
    int packetSize;                     // Packet (datagram) size
    int dataSize;                       // Data size for each sending/receiving

    int sentPackets;                    // Total UDP packets sent
    int recvPackets;                    // Total UDP packets received
    int sentLoss;                       // Loss packets (send)
    int recvLoss;                       // Loss packets (recv)
    long_int sentBytes;                 // Total UDP data sent in bytes
    long_int recvBytes;                 // Total UPD data received in bytes
    long_int elapsedTime;               // Elapse time in microsecond
};

/******************* Define UDP data header structure **********************/

struct UDPHeader 
{
    long seq_number;                    // Sequence number
    long cmd;                           // Purpose of the packet
    long time_sec;                      // Time stamp in second
    long time_usec;                     // Time stamp in microsecond
    long offset;                        // Time offset
    long size;                          // Data size
    long checksum;                      // Packet checksum
};

/********* Define RTT structure for Round Trip Time (latency) test *********/
    
struct RTT                               
{                                        // Just a UDP version of ping
    int mode;                            // 1: RTT test 0: UDP throughput test
    int size;                            // Message size for test
    int trial;                           // Total times of RTT test
    int loss;                            // Unsuccessful tests
    double min;                          // Minimum of RTTs
    double max;                          // Maximum of RTTs
    double sum;                          // Sum of RTTs
    double avg;                          // Avarage of RTTs            
};

/********* Define Throughput structure for network throughput test *********/

struct Throughput                        // Network throughput test
{                                
    int trial;                           // Repetition
    double min;                          // Minimum of throughputs
    double max;                          // Maximum of throughputs
    double sum;                          // Sum of throughputs
    double avg;                          // Avarage of throughputs
};
    
/********************* Global variables for client/server ******************/

int error;                               // Error information of the test
char * buffer;                           // Data buffer

/**************** Some communication in the TCP data channel ***************/

#ifndef _UDPLIB_DOT_C
const char test_init_str[] = 
"TESTMODE %d TOS %d CPUOPTION %d SENDBUF %d RECVBUF %d PACKETSIZE %d SENDSIZE %d \r\n";
const char server_setting_str[] = 
"UDPPORT %d TOS %d CPUOPTION %d SENDBUF %d RECVBUF %d PACKETSIZE %d SENDSIZE %d \r\n";
const char test_start_str[] = "SIZE %d REPEAT %d \r\n";
const char test_end_str[] = "UDP TEST DONE \r\n";
const char test_sync_str[] = "UDP RTT(PING) SYNCHRONIZATION \r\n";
const char test_time_out_str[] = "RECEIVE TIME OUT \r\n";
const char server_result_str[] = 
"RECEBYTES %lld RECVPACKETS %d SENTBYTES %lld SENTPACKETS %d REALTIME %lld USERTIME %lld SYSTIME %lld \r\n";
#endif


/**************** Routines for client and server in udplib.c ***************/

void print_usage();
status_t tcp_get_request(char *request, struct TCPconnection *tcpsock);
status_t tcp_send_request(char *request, int length, struct TCPconnection *tcpsock);

/******************** Routines for server in udplib.c **********************/

status_t server_tcp_init (int port, struct TCPconnection *tcpsock);
status_t server_tcp_get_connection(struct TCPconnection *tcpsock, 
				   struct in_addr *sin_addr);
status_t server_udp_init(struct UDPconnection *udpsock);
inline status_t server_udp_ping(int iteration, struct UDPconnection *udpsock);
inline status_t server_udp_test (struct UDPconnection * udpsock ); 
inline status_t server_udp_bi_test (struct UDPconnection * udpsock ); 

/******************** Routines for client in udplib.c **********************/

status_t client_tcp_connect(char *host, struct TCPconnection *tcpsock);
status_t client_udp_init(char *host, struct UDPconnection *udpsock);
inline status_t client_udp_ping(int iteration, struct UDPconnection *sock);
inline status_t client_udp_test(long_int message, double testTime, 
				struct UDPconnection *udpsock, long_int sendRate);
inline status_t client_udp_bi_test(long_int message, double testTime, 
				   struct UDPconnection *udpsock);
status_t udp_traffic_generator(char *host, int port, int buffer, double time, 
			       long_int throughput);


/*********************** Help information **********************************/

#ifndef _UDPLIB_DOT_C

const char help_description[] = 
"udpserver/udptest -- A UDP communication benchmark\n\n\
UDP Round Trip Time (latency) test is just a UDP version of \"ping\". RTT is too short to be\n\
measured in HPC environments, so we repeat RTT test many times and get the average of RTTs.\n\n\
A UPD throughput test is done when both of the conditions are satisfied: message size AND \n\
test time. So the actual size of sent message could be greater than the message size you \n\
specify if the test time is large.\n\n\
In UPD througput tests, message size (-m option) specifies the total amount of data to be \n\
sent. Messages are actually sent by small pieces (defined by -d option) that must be smaller \n\
than datagram (packet) size. In exponential tests, the sending size increases exponentially \n\
from 1 byte to the datagram (packet) size; while in the fixed-size tests, the size of each \n\
sending is always the same as datagram (packet) size. Most systems have a 64KB maximum size \n\
limit of UDP datagram (packet).\n\n\
UDP traffic generator keeps sending UDP packets to a remote host that is unnecessary running\n\
as server. Better to pick an unused port for this test. You can specify the througput to be \n\
sent (-T option). Be aware that this test may affect target host's performance.\n\n\
If CPU and system monitoring option (-c) is defined, both client and server's CPU usages \n\
(Maximum 8 CPUs supported for SMP systems), network interface statistics and its interrupts \n\
to each CPU will be recorded. Currently this option is only available for Linux system.\n\n";

const char help_usage[] =
"udpserver usage: udpserver [options]\n\
 %% udpserver [-v] [-p port]\n\
 [-p] Port number for TCP listening (0 picked by system), %d by default.\n\
 [-v] Verbose mode. Disable by default.\n\n\
udptest usage: udptest -h host [options]\n\
 %% udptest -h host [-vacdeiP] [-p port] [-A rtt] [-b buffer] [-B buffer] [-m msssage] [-q qos]\n\
                   [-l datagram] [-d data] [-t time] [-r repeat] [-o output] [-T throughput]\n\
 [-a] UDP Round Trip Time (RTT or latency) test.\n\
 [-A rtt-size] UDP RTT (latency) test with specified message size.\n\
 [-b buffer] Client UDP buffer size in bytes. Using system default value if not defined.\n\
 [-B buffer] Server UDP buffer size in bytes. The same as cleint's by default.\n\
 [-c] CPU log option. Tracing system info during the test. Only available when output is defined.\n\
 [-d data-size] Data size of each read/write in bytes. The same as packet size by default.\n\
 [-e] Exponential test (data size of each sending increasing from 1 byte to packet size).\n\
 [-g] UDP traffic generator (Keep sending data to a host). Work without server's support.\n\
 [-h host] Hostname or IP address of UDP server. Must be specified.\n\
 [-i] Bidirectional UDP throuhgput test. Default is unidirection stream test.\n\
 [-l datagram] UDP datagram (packet) size in bytes ( < udp-buffer-szie ). %d by default.\n\
 [-m message] Total message size in bytes. %d by default.\n\
 [-o output] Output file name.\n\
 [-p port] Port number of UDP server. %d by default.\n\
 [-P] Write the plot file for gnuplot. Only enable when the output is specified. \n\
 [-q qos] Define the TOS field of IP packets. Six values can be used for this setting:\n\
     1:(IPTOS)-Minimize delay 2:(IPTOS)-Maximize throughput \n\
     3:(DiffServ)-Class1 with low drop probability 4:(DiffServ)-class1 with high drop probability\n\
     5:(DiffServ)-Class4 with low drop probabiltiy 6:(DiffServ)-Class4 with high drop probabiltiy\n\
 [-r repeat] Repetition of tests. %d by default.\n\
 [-t time] Test time constraint in seconds. %d by default.\n\
 [-T throughput] Throughput constraint for UDP generator or throughput test. Unlimited by default.\n\
 [-v] Verbose mode. Disable by default.\n\
 Note: Input (except -T) supports the postfix of \"kKmM\". 1K=1024, 1M=1024x1024.\n\
 Throughput constraint option (-T): 1K=1000, 1M=1000000.\n\n";

const char help_example[] = 
"Examples\n\n\
 1. Start server process\n\
 [server] %% udpserver\n\n\
 2. Start client process\n\
 [client] %% udptest -ah server\n\
 UDP Round Trip Time (latency) test.\n\n\
 [client] %% udptest -h server\n\
 UDP throughput test with default set of parameters\n\
 Port-number: 5678, test-time: 5, test-repeat: 10.\n\
 Message-size: 1048576, packet-size: 1460, send-size: 1460\n\n\
 [server] %% udpserver -p 3000\n\
 [client] %% udptest -vh server -p 3000 -b 1M -m 10m -l 20k -t 2 -r 20 -o output.txt\n\
 Repeat throughput tests by 20 times with communication port of 3000; \n\
 store results in \"output.txt\".\n\
 Buffer-size: 1MB, message-size: 10MB, test-time: 2 Seconds, packet-size: 20KB\n\n\
 [client] %% udptest -eP -h server -b 100k -o output.txt\n\
 Exponential throughput test for buffer size of 100KB, writing output and plot files.\n\n\
 When an \"output\" file is specified, an \"output.plot\" file will also be created for\n\
 plotting. Use \"gnuplot ouput.plot\" to plot the data.\n\n";

#endif  // end of ifnedf _UDPLIB_DOT_C

#endif
