/***********************************************************************************/
/**                                                                               **/
/**         Utility measure system and process information                        **/
/**         By Ben Huang, hben@users.sf.net April 2004                            **/
/**         August 2006 update: support Linux 2.6 kernel                          **/
/**         "util.h"                                                              **/
/**                                                                               **/
/***********************************************************************************/ 

#ifndef _UTIL_HEADER_FILE
#define _UTIL_HEADER_FILE

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <malloc.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

/************************ External variable used by getopt *****************/

extern char *optarg;
extern int optopt;

/************************ Define some types ********************************/

#define BUFFLEN  2048 

#ifndef _BASIC_TYPES_
#define _BASIC_TYPES_
typedef long long long_int;   // 64-bit integer
typedef enum status_t { NOTOK = -1, OK = 0 } status_t;
#endif

#define NETNAMELEN 10
#ifndef UINT_MAX 
#define UINT_MAX 4294967295U
#endif

/* We assume the system has maximum cpu number of 8 and has 4 maximum network 
 * cards. This assumption is true in most HPC cases since we could build more 
 * nodes in a cluster instead of buying expensice SMP with more CPUs if we 
 * need more computational power.
 */

#define MAXCPU 8       // Maximum CPU number in one machine
#define MAXNETWORK 4   // Maximum network interface number in one machine

/******** Define the network interface name (examined by ifconfig ) ********/
/******** The loopback interface must be defined as "loop" *****************/

#ifdef _UTIL_DOT_C
#define NETTYPE 4  // Number of network device name, must match the following line
const char CONSTNETNAME[NETTYPE][NETNAMELEN] = {"eth", "loop", "elan", "wlan"};
#endif

/*********** Define PRO structure to hold process information  *************/

struct PROInfo {                   // structure holds the Process information 
    int pid;                       // process's pid
    long rtime_sec;                // Real (wall-clock) time spent on behalf of process in second
    long rtime_usec;               // Real time in microsecond
    long utime_sec;                // User time in second (spent executing user instructions)
    long utime_usec;               // User time in microsecond
    long stime_sec;                // System time in second (spent in operating system code) 
    long stime_usec;               // System time in microsecond
    long mem;                      // The maximum resident set size used in kilobytes (physical memory used)
    long swap;                     // The number of times the processe was swapped entirely out of main memory
    long read_times;               // The number of times the file system had to read from the disk
    long write_times;              // The number of times the file system had to write to the disk
    long signals;                  // Number of signals received
};


/********** Define some structures to hold the system information **********/

/* SYSInfo holds the CPU usage and interrupts of network cards 
 * We assume the maximum number of CPUs in SMPs is 8 and the maximum number
 * of network interfaces is 3. This is a fair assumption in most cases for HPCs.
 * net_irq_num[0-2]: the IRQ number of network interface(s) (at most 3)
 * net_interruput[1-8][0]: the first network card's interrupts for each CPU
 * net_interrupt[0][0]: all interrupts to all CPUs of first network interrace
 * cpu_user[1-8]: each cpu's jiffies in user mode. If there are only 
 * 4 CPUs, cpu_user[5-8] will not be used. 
 * cpu_user[0] always holds the summary of all CPU usage in user mode.
 */
    
typedef struct SINGLECPU {         // Structure holds CPU information
    long net_int[MAXNETWORK];      // Interrupts from network interface
    long_int user_mode;            // CPU usage in user mode
    long_int nice_mode;            // CPU usage in nice (low priority) mode
    long_int system_mode;          // CPU usage in system mode
    long_int idle_mode;            // CPU in idle state
    long_int total_usage;          // Total CPU usage
} CPU;

typedef struct NETWORKInterface {  // Structure for network interfaces
    int irq;                       // IRQ number
    long interrupt;                // Interrupts from this interface
    long_int recv_packet;          // Received packets
    long_int recv_byte;            // Received bytes
    long_int send_packet;          // Sent packets
    long_int send_byte;            // Sent bytes
    char name[NETNAMELEN];         // Interface name (e.g. eth0, wlan1, etc.)
} Network;

struct SYSInfo {                   // structure holds the CPU information 
    int clock_rate;                // HZ of kernel
    int cpu_num;                   // number of CPUs
    int net_num;                   // number of network interface (NIC)
    long_int cpu_total;
    long_int cpu_user;             // CPU usage in user mode
    long_int cpu_nice;             // CPU usage in low priority (nice) mode
    long_int cpu_system;           // CPU usage in system mode
    long_int cpu_idle;             // CPU idle state
    long_int mem_used;             // How much memory is used in bytes?
    long_int mem_total;            // How big is the phsical memeory in bytes?
    long_int interrupts;           // Overall system interrupts received
    long_int page_in;              // Number of pages in to disk
    long_int page_out;             // Number of pages out to disk
    long_int swap_in;              // Pages swapped in
    long_int swap_out;             // Pages swapped out
    long_int context_switch;       // Context switches
    Network net[MAXNETWORK]; 
    CPU cpu[MAXCPU];
};

/**************************** Function prototype ***************************/

long_int parse_size(char *str);
status_t get_local_time(char * str, int length);
status_t define_nic_name( char * netname );
status_t start_trace_system(struct SYSInfo * sysinfo);
status_t stop_trace_system(struct SYSInfo * sysinfo);
status_t start_trace_process(struct PROInfo * proinfo);
status_t stop_trace_process(struct PROInfo * proinfo);
status_t sysinfo_to_string( struct SYSInfo * sysinfo, char *str, int len );
status_t string_to_sysinfo( struct SYSInfo * sysinfo, char * str, int len );
status_t read_from_vmstat(struct SYSInfo * sysinfo);
status_t read_memory_info(struct SYSInfo * sysinfo);
status_t write_sys_info(struct SYSInfo * sysinfo, int length, char * filename, 
			char *time, char * hostname);

#endif
