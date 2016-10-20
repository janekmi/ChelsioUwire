/***************************************************************************/
/**                                                                       **/
/**          sysmon - Linux system information monitor tool               **/
/**          Report the CPU, Memory and Network statistcs                 **/
/**          Network statistics includes:                                 **/
/**          Each NIC's sent/received info and it's interrupts CPU        **/
/**                                                                       **/
/**          Ben Huang, hben@users.sf.net                                 **/
/**                                                                       **/
/***************************************************************************/       
		
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include "util.h"

#define TIMEINTERVAL 2    // Time interval in seconds
#define REPETITION   10   // Times of tracing 
#define MAXNETDEVICE 5    // Maximum network devices in one machine
#define TEMPNAMELEN  20   // Length of temporary file name

const char usage[] = 
" sysmon: A Linux tool to monitor system's CPU/Memory/Network information.\n\
 Usage: sysmon [-bhkswW] [-i interface-name] [-r repeat] [-t test-interval] [-T test-time]\n\
        [-b] Background (daemon) mode. Only valid when write option is defined.\n\
        [-h] Printout help messages.\n\
        [-k] Kill the sysmon background process (daemon). Disable by default.\n\
        [-s] Suppress CPU and memory info, only print out network statistics.\n\
        [-w] Write results to a file. Disable by default.\n\
        [-W] Write statistics of each network device to separate files. Disable by default.\n\
        [-i interface-name] Define the network device name (e.g. eth0). Monitor all if no interface defined.\n\
        [-r repeat] Repetition of monitoring. 10 times by default.\n\
        [-t test-interval] The interval (sample time) between each tracing in seconds. 2 seconds by default.\n\
        [-T test-time] The duration of system monitoring in minutes. Valid only write option defined.\n\
        [-o output] Specify the output (log) filename. Implies the write option.\n\
        Note: Default logfile has format of host-start-time.log if write option (-w) is defined.\n\n\
 Use \"ifconfig\" to check the name of network devices in your computer.\n\
 Possible names: eth0, wlan0, ppp0, etc (defined by NETNAME in util.h). loop is for loopback address.\n\n\
 Example1 (Monitor all network devices, very long format): %% sysmon \n\
 Example2 (Monitor eth0 and eth1, interval:5 Sec. repeat: 10 times): %% sysmon -i eth0,eth1 -t 10\n\
 Example3 (Log every 10 minutes for one week, run as daemon): %% sysmon -bw -i eth0 -t 600 -T 10080 \n\
 Output format: <CPU and memory info> <Network information>\n\
 Network information for each NIC: [interrupts] [recv-packets] [recv-bytes] [sent-packets] [sent-bytes]\n\n";

static void make_daemon();   // Run in background
static void kill_daemon();   // Kill sysmon background process
static void copy_file();     // Periodically copy temporary logfiles to target files 

int main(int argc, char *argv[]) 
{
    char buff[BUFFLEN], buff1[BUFFLEN], filename[BUFFLEN];
    char tmpfile[] = "/tmp/sm.XXXXXX";        // Temporary file holding all results
    char stmpfile[MAXNETDEVICE][TEMPNAMELEN]; // Temporary file holding each NIC's results 
    int i, j, fd, size, opt, option;
    double cpuload, userload, sysload, memload, mem_used, mem_total;
    long_int recv_packet[MAXNETWORK], send_packet[MAXNETWORK];
    long_int recv_byte[MAXNETWORK], send_byte[MAXNETWORK];
    struct SYSInfo sysinfo;
    time_t current_time;
    struct tm *time_tm;
    FILE *output, *s_out[MAXNETDEVICE];
    int write_option = 0;         // Store results to a file?
    int write_separate = 0;       // Write separate logfile for each NIC?
    int output_suppress = 0;      // Only print out the network statistics
    int daemon_option = 0;        // Run process in background?
    int output_defined = 0;       // Output filename defined?
    int kill_process = 0;         // Kill sysmon background process?
    int time_duration = 0;        // Only valid for write option
    int nic_defined = 0;          // Network device name defined?
    int repeat = REPETITION;      // Repeat tracing system by 10 times
    int time_val = TIMEINTERVAL;  // 2 seconds between each report

    /************************* Parse command line **************************/

    if ( argc > 1 ) {
	opt = 0;
	while ( (option = getopt (argc, argv, "hbswWkr:i:t:T:o:")) != -1) {
	    opt++;
	    switch ( option ) {
	    case 'h':  /* Print out help message */
		printf(usage);
		return 0;
	    case 'b':  /* Write result to a file */
		daemon_option = 1;
		break;
	    case 's':  /* Suppress CPU and other system info and only printout the network statistics */
		output_suppress = 1;
		break;
	    case 'w':  /* Write results to a file */
		write_option = 1;
		break;
	    case 'W':  /* Write results to files */
		write_option = 1;
		write_separate = 1;
		break;
	    case 'k':  /* Kill the sysmon background process */
		kill_process = 1;
		break;
	    case 'i':  /* Only monitor one network interface */
		strcpy(buff, optarg);
		define_nic_name(buff);
		nic_defined = 1;
		break;
	    case 'r':  /* Repetition of system tracing */
		if ( (size = atoi(optarg)) > 0)
		    repeat = size;
		break;
	    case 't':  /* Interval between each tracing in seconds */
		if ( (size = atoi(optarg)) > 0)
		    time_val = size;
		break;
	    case 'T':  /* System monitoring duration in minutes */
		if ( (size = atoi(optarg)) > 0)
		    time_duration = size;
		break;
	    case 'o':  /* Output file name */
		write_option = 1;
		strncpy(filename, optarg, BUFFLEN);
		if ( filename != NULL )
		    output_defined = 1;
		break;
	    default:   /* argurments invalid */
		printf(usage);
		return 1;
	    }
	}
	if ( argc == 2 && opt == 0 ) { /* A lazy use: "% sysmon eth1" */
	    strcpy(buff, argv[1]);
	    define_nic_name(buff);
	    nic_defined = 1;
	}
    }

    /***************** Kill background sysmon process ? ********************/

    if ( kill_process ) {  
	kill_daemon();
	return 0;
    }

    /******************* Is it ok to trace the system info ? ***************/

    if ( start_trace_system(&sysinfo) == NOTOK ) {
	fprintf(stderr, "Failed to monitor the system.\n");
	exit (1);
    }
    
    if ( sysinfo.net_num == 0 ) {
	if ( nic_defined )
	    fprintf(stderr, "Warning: Couldn't find the network device: %s\n\n", buff);
	else 
	    fprintf(stderr, "Warning: No network device found.\n\n");
    }

    /*********************** Initialization for write option ***************/
	
    if ( write_option) {

	if ( !output_defined ) {
	    time(&current_time);
	    time_tm = localtime(&current_time);
	    strftime(buff, BUFFLEN, "-%Y%m%d.log", time_tm);
	    
	    gethostname(filename, BUFFLEN);
	    for ( i = 0; filename[i] != '.' && filename[i] != '\0'; i++ );
	    filename[i] = '\0';
	    strncat(filename, buff, BUFFLEN);
	}

	/* Use local file system (/tmp) to temporarily store the results.
	 * Copy the data to output (may be NFS or other file systems) regularly.
	 */

	if ( (fd = mkstemp(tmpfile)) < 0  || ( output = fdopen(fd, "w")) == NULL ) {
	    perror("Failed to create temporary file");
	    write_option = 0;
	}

	if ( write_option ) {
	
	    /* The overall logfile may have long lines of each record if there exist 
	     * several network devices, which is hard to read. That is the reason 
	     * we separate them for each network interface. e.g., log.eth0, log.eth1, etc.
	     */
	    
	    if ( write_separate) {
		for ( i = 0; i < MAXNETDEVICE; i++ )
		    strcpy(stmpfile[i], "/tmp/sm.XXXXXX");
		for ( i = 0; i < sysinfo.net_num; i++ ) {
		    if ( (fd = mkstemp(stmpfile[i])) < 0  || 
			 ( s_out[i] = fdopen(fd, "w")) == NULL ) {
			perror("Failed to create temporary file for separate interfaces");
			write_separate = 0;
			break;
		    } else 
			write_separate = 1;
		}
	    }
	    
	    if ( daemon_option )  // Run in background
		make_daemon();

	    gethostname(buff, BUFFLEN);    
	    get_local_time(buff1, BUFFLEN);
	    fprintf(output, "# Syslog <%s> started at %s\n", buff, buff1);

	    if ( write_separate ) {
		for ( i = 0; i < sysinfo.net_num; i++)
		    fprintf(s_out[i], "# Syslog <%s> started at %s\n", buff, buff1);
	    }

	    if (time_duration > 0 ) {
		repeat = time_duration * 60 / time_val;
		if ( repeat < REPETITION )
		    repeat = REPETITION;
	    }
	}
    }

    if ( ! write_option) {
	printf("sysmon -- a network system monitor tool for Linux.\n");
	printf("Try \"sysmon -h\" for more information\n\n");
    }	    
 
    for ( i = 0; i < repeat; i++ ) {

	if ( start_trace_system(&sysinfo) == NOTOK ) {
	    fprintf(stderr, "Failed to monitor the system.\n");
	    exit (1);
	}

	sleep(time_val);

	if ( stop_trace_system(&sysinfo) == NOTOK ) {
	    fprintf(stderr, "Failed to monitor the system.\n");
	    exit (1);
	}

	/**************** printout the overall system information **********/

	if ( i == 0 ) {
	    printf("# CPU number: %d\n# Network device <%d>: %s %s %s %s\n", 
		   sysinfo.cpu_num, sysinfo.net_num, sysinfo.net[0].name, 
		   sysinfo.net[1].name, sysinfo.net[2].name, sysinfo.net[3].name);
	    printf("# Sample time: %d seconds\n# Metrics: # per %d %s\n\n", 
		   time_val, time_val, time_val > 1 ?  "seconds":"second");
	    if ( !output_suppress )
		printf("#  |     CPU    |  Mem  | IntRpt | Page | Swap | Context |");
	    else 
		printf("#    ");
	    for ( j = 0; j < sysinfo.net_num; j++ )
		printf( "|               Interface %s             | ", sysinfo.net[j].name);
	    if ( !output_suppress )
		printf("\n#  Load  User Sys Usage     All   In/out In/out   Switch");
	    else 
		printf("\n#   ");
	    for ( j = 0; j < sysinfo.net_num; j++ )
		printf( "   IntRpt RecvPkg  RecvByte SentPkg  SentByte");
	    printf("\n");

	    if ( write_option) {
		fprintf(output, "# CPU number: %d\n# Network device <%d>: %s %s %s %s\n", 
		       sysinfo.cpu_num, sysinfo.net_num, sysinfo.net[0].name, 
		       sysinfo.net[1].name, sysinfo.net[2].name, sysinfo.net[3].name);
		fprintf(output, "# Tracing interval: %d seconds \n# Metric: # per second\n\n", time_val);

		if ( write_separate ) {
		    for ( j = 0; j < sysinfo.net_num; j++ ) {
			fprintf(s_out[j], "# CPU number: %d\n# Network device <%d>: %s %s %s %s\n", 
				sysinfo.cpu_num, sysinfo.net_num, sysinfo.net[0].name, 
				sysinfo.net[1].name, sysinfo.net[2].name, sysinfo.net[3].name);
			fprintf(s_out[j], "# Sample time: %d seconds\n", time_val);
			fprintf(s_out[j], "# Metrics: # per %d seconds\n\n", time_val);
		    }
		}

		fprintf(output, "# Log-time  |     CPU(%%)      | Mem(%%) | IntRpt |   Page   |  Swap  | Context |");

		if ( write_separate ) {
		    for ( j = 0; j < sysinfo.net_num; j++ ) 
			fprintf(s_out[j], "# Log-time  |     CPU(%%)      | Mem(%%) | Interrupt |  Page  |  Swap  | Context |");

		}

		for ( j = 0; j < sysinfo.net_num; j++ ) {
		    fprintf(output, "              Interface %s              | ", 
			    sysinfo.net[j].name);
		    if ( write_separate )
			fprintf(s_out[j], "                   Interface %s                    |",  sysinfo.net[j].name);
		}

	       	fprintf(output,"\n#DateHr.Min  Load  User   Sys   Usage      All    In   Out   In  Out   Switch");

		if ( write_separate ) {
		    for ( j = 0; j < sysinfo.net_num; j++ ) 
			fprintf(s_out[j],"\n#Date Hr.Min  Load  User   Sys   Usage    Overall    In/out   In/out    Switch");
		}

		for ( j = 0; j < sysinfo.net_num; j++ ) {
		    fprintf(output, "  IntRpt RecvPkg  RecvByte SentPkg  SentByte");
		    if ( write_separate )
			fprintf(s_out[j], "    IntRpt   RecvPkg    RecvByte   SentPkg    SentByte\n");
		}
		fprintf(output, "\n");
	    }
	}
	if ( sysinfo.cpu_total <= 0 ) {
	    fprintf(stderr, "No message!\n");
	    continue;
	}

	cpuload = (sysinfo.cpu_total - sysinfo.cpu_idle)*100.0 / sysinfo.cpu_total;  
	userload = sysinfo.cpu_user*100.0 / sysinfo.cpu_total;
	sysload = sysinfo.cpu_system*100.0/ sysinfo.cpu_total;
	
	mem_used = sysinfo.mem_used*1.0 / (1024*1024);     // Memory used by system in Mbytes
	mem_total = sysinfo.mem_total*1.0 / (1024*1024);   // Physical memory in Mbytes
	memload = sysinfo.mem_used * 100.0 / sysinfo.mem_total;

	if ( !output_suppress )
	    printf("%-3d%3.0f%% %3.0f%% %3.0f%%%4.0f%%%10lld%8lld%7lld%9lld", 
		   i, cpuload, userload, sysload, memload, sysinfo.interrupts,
		   sysinfo.page_in+sysinfo.page_out, sysinfo.swap_in+sysinfo.swap_out, sysinfo.context_switch);
	else 
	    printf("%-3d ", i);

	if ( write_option ) {
	    bzero(buff, BUFFLEN);
	    time(&current_time);
	    time_tm = localtime(&current_time);
	    strftime(buff, BUFFLEN, "%d%H.%M ", time_tm);
	    fprintf(output, "%11s%6.1f%6.1f%6.1f%8.1f%9d%6d%6d%5d%5d%9d", buff, cpuload, userload, sysload, memload,
		    (int)sysinfo.interrupts/time_val, (int)sysinfo.page_in/time_val, (int)sysinfo.page_out/time_val, 
		    (int)sysinfo.swap_in/time_val, (int)sysinfo.swap_out/time_val, (int)sysinfo.context_switch/time_val); 
	    if ( write_separate ) {
		strftime(buff, BUFFLEN, "%d  %H.%M ", time_tm);
		for ( j = 0; j < sysinfo.net_num; j++ ) 
		    fprintf(s_out[j], "%12s%6.1f%6.1f%6.1f%8.1f%11lld%10lld%9lld%10lld", 
			    buff, cpuload,  userload, sysload, memload, sysinfo.interrupts,
			    sysinfo.page_in+sysinfo.page_out, sysinfo.swap_in+sysinfo.swap_out, sysinfo.context_switch); 
	    }
	}

	/**************** Printout the network statistics ******************/
	
	for ( j = 0; j < sysinfo.net_num; j++ ) {
	    recv_packet[j] = sysinfo.net[j].recv_packet;
	    recv_byte[j] = sysinfo.net[j].recv_byte;
	    send_packet[j] = sysinfo.net[j].send_packet;
	    send_byte[j] = sysinfo.net[j].send_byte;
	}

	for ( j = 0; j < sysinfo.net_num; j++ ) { 
	    printf( "%9ld%8lld%10lld%8lld%10lld", sysinfo.net[j].interrupt, 
		    recv_packet[j], recv_byte[j], send_packet[j], send_byte[j]);
	    if ( write_option ) {
		fprintf(output, "%8d%8d%10d%8d%10d", (int)(sysinfo.net[j].interrupt/time_val+0.5), 
			(int)(recv_packet[j]/time_val+0.5), (int)(recv_byte[j]/time_val+0.5), 
			(int)(send_packet[j]/time_val+0.5), (int)(send_byte[j]/time_val+0.5));
		if ( write_separate )
		    fprintf(s_out[j], "%10ld%10lld%12lld%10lld%12lld\n", sysinfo.net[j].interrupt, 
		    recv_packet[j], recv_byte[j], send_packet[j], send_byte[j]);
	    }
	}
	printf("\n");
	if ( write_option ) {
	    fprintf(output, "\n");
	    if ( fflush(output) < 0 )
		perror("Failed to write the file.");
	    if ( (i%10) == 0 ) // Copy temporary file to target regulary
		copy_file(tmpfile, filename);
	}

    } // Repeat done

    if ( write_option ) {
	get_local_time(buff, BUFFLEN);
	fprintf(output, "\n# Ended at %s Total records: %d\n", buff, repeat);
	fclose(output);
	copy_file(tmpfile, filename);
	unlink(tmpfile);
	if ( write_separate ) {  // Copy all separate files 
	    for ( i = 0; i < sysinfo.net_num; i++ ) {
		fprintf(s_out[i], "\n# Ended at %s Total records: %d\n", buff, repeat);
		fclose(s_out[i]);
		strncpy(buff1, filename, BUFFLEN);
		strncat(buff1, ".", BUFFLEN);
		strncat(buff1, sysinfo.net[i].name, BUFFLEN);
		copy_file(stmpfile[i], buff1);
		unlink(stmpfile[i]);
	    } // end of for loop
	} // end of write_separate
    } // end of write_option

    return 0;
}

/******************* Run program as daemon in background *******************/

static void make_daemon() 
{
    pid_t pid;

    if ( (pid = fork()) < 0 ) {   // Error in fork
        perror("Failed to fork first process.");
        exit(1);
    } else if  ( pid > 0 )  // Parent exits
        exit(0);

    if ( setsid() < 0  ) {  // Child changes session group
        perror("Failed to change the session group.");
    }

    signal(SIGINT, SIG_IGN); // Ignore interrupt signal
    signal(SIGHUP, SIG_IGN); // Ignore kill -HUP signal
 
    if ( (pid = fork()) < 0 ) { // Fork again to get released from terminal
        printf("Failed to fork second process. ");
        exit(1);
    } else if ( pid > 0 )
        exit(0);

    close(1);     // Close stdout
    if ( open("/dev/null", O_WRONLY) < 0 ) { // Redirect stdout to /dev/null
        perror("Failed to redirect stdout.");
        exit(1);
    }
    close(0);     // Close stdin
    dup(1);       // Redirect stdin to stdout (/dev/null)
    close(2);     // Close stderr
    dup(1);       // Redirect stderr to /dev/null
    
    return;

}

/*********************** Kill the background sysmon process ****************/

static void kill_daemon()
{
    int pid;
    char buff[BUFFLEN];
    FILE * in;

    if ( (in=popen("/bin/ps -ef | grep sysmon | grep -v grep | cut -c10-15", "r")) == NULL )
	exit (1);
	    
    while ( fgets(buff, BUFFLEN, in) != NULL ) {
	pid = atoi(buff);
	if ( pid > 0 && pid != (int)getpid()) {
	    printf("Killing process %d\n", pid);
	    kill(pid, SIGKILL);
	}
    }
    pclose(in);

    return;
}

/**************** Copy the temporary file to target (output) file **********/

static void copy_file(char *source, char *dest) 
{
    char buff[BUFFLEN];
    int rval, s_fd, d_fd;

    if ( (s_fd = open(source, O_RDONLY)) < 0 ) {
	perror("Failed to open temporary file.");
	return;
    }

    if ( (d_fd = creat(dest, 0644)) < 0 ) {
	perror("Failed to create output file for copy.");
	close(s_fd);
	return;
    }

    while ( (rval = read(s_fd, buff, BUFFLEN)) > 0 )
	if ( write(d_fd, buff, rval) != rval )
	    perror("Error in copying temporary file to output.");

    close(s_fd);
    close(d_fd);

    return;
    	
}
