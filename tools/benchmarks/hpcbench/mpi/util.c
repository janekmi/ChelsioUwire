/***********************************************************************************/
/**                                                                               **/
/**         Utility measure system and process information                        **/
/**         By Ben Huang, hben@users.sf.net, April 2004                           **/
/**         August 2006 update: support Linux 2.6 kernel                          **/
/**                                                                               **/
/**         "util.c"                                                              **/
/**                                                                               **/
/***********************************************************************************/ 

#ifndef _UTIL_DOT_C
#define _UTIL_DOT_C
#include "util.h"
#endif

/****** Parse the input value. support the postfix of "kKmM" ***************/

long_int parse_size(char *str)
{
    long_int size;
    char buff[BUFFLEN];

    switch (sscanf(str, "%lld%1[mMkK]", &size, buff)) {
        case 1:
            return size;
        case 2:
            switch (*buff) {
	    case 'k':
            case 'K':
                return (size<<10);
            case 'm':
            case 'M':
                return (size<<20);
	    default:
                return size;
            }
        default:
            return 0;
    }
}

/************************************** Old version ************************/
/*
long_int parse_size(char * str) 
{
    long_int  base = 1, value = 0;
    if ( atol(str) > 0 ) { 
	if ( str[strlen(str)-1] == 'M' || str[strlen(str)-1] == 'm' )
	    base = 1024 * 1024;
	else if ( str[strlen(str)-1] == 'K' || str[strlen(str) -1] == 'k' )
	    base = 1024;
	value = base * atol(str);
    }
    return value;
}
*/

/************************** Get the local time *****************************/

status_t  get_local_time(char * str, int length) 
{
    int i;
    char buff[length];
    time_t currentTime;

    bzero(buff, length);
    time(&currentTime);
    strncpy(buff, (char *)ctime(&currentTime), length-1);

    /**** Get rid of the character of '\n' returning by ctime function *****/

    for ( i = 0; buff[i] != '\n' && buff [i] != '\0'; i++);
    buff[i] = '\0';

    strcpy(str, buff);

    return OK;
}


/********** Subtraction with integer uper bound consideration **************/

static long_int safe_subtract(long_int a, long_int b) 
{
    if ( (a - b) >= 0 )
	return (a - b);
    /* A linux bug in SMP systems! Idle jiffies may decrease a little in some busy cases */
    else if ( (a-b) > -1000 )
	return 0;
    else   
	return ( a + UINT_MAX - b);
}


/***** Global variable indicating user specifies network interface name ****/

static int Defined_Nic_Name = 0; 
static char NETNAME[NETTYPE][NETNAMELEN];


/************ User define a network interface name (such as eth0) **********/
/************ Search NIC names from the /proc/interrupts by default ********/

status_t define_nic_name( char * netname ) 
{
    char * buff;
    int i = 0;

    Defined_Nic_Name = 1; // A global variable

    if ( strstr(netname, ",") == NULL ) { // Only define one device
	strncpy(NETNAME[0], netname, NETNAMELEN-1);
	NETNAME[0][NETNAMELEN-1] = '\0';
	i++; 
    } else {  // More than one devices are defined
	strncpy(NETNAME[0], strtok(netname, ","), NETNAMELEN-1);
	for ( i = 1;  (buff = strtok(NULL, ",")) != NULL; i++ ) {
	    strncpy(NETNAME[i], buff, NETNAMELEN-1);
	    NETNAME[i][NETNAMELEN-1] = '\0';
	}
    }

    for ( ; i < NETTYPE; i++ )
	strcpy(NETNAME[i], "\r\r\r"); // Just copy dummy characters 

    return OK;
}



/****************** Initialization for SYSInfo data ************************/

static void init_sysinfo_data( struct SYSInfo *sysinfo )
{
    int i, j;

    sysinfo->clock_rate = 0;
    sysinfo->cpu_num = 0;
    sysinfo->net_num = 0;
    sysinfo->cpu_user = 0;
    sysinfo->cpu_nice = 0;
    sysinfo->cpu_system = 0;
    sysinfo->cpu_idle = 0;
    sysinfo->cpu_total = 0;
    sysinfo->interrupts = 0;
    sysinfo->mem_used = 0;
    sysinfo->mem_total = 0;
    sysinfo->page_in = 0;
    sysinfo->page_out = 0;
    sysinfo->swap_in = 0;
    sysinfo->swap_out = 0;
    sysinfo->context_switch = 0;
    
    for ( i = 0 ; i < MAXNETWORK; i++ ) {
	sysinfo->net[i].irq = 0;
	sysinfo->net[i].interrupt = 0;
	sysinfo->net[i].recv_packet = 0;
	sysinfo->net[i].recv_byte = 0;
	sysinfo->net[i].send_packet = 0;
	sysinfo->net[i].send_byte = 0;
	bzero(sysinfo->net[i].name, NETNAMELEN);
    }
    for ( i = 0; i < MAXCPU; i++ ) {
	for ( j = 0; j < MAXNETWORK; j++ )
	    sysinfo->cpu[i].net_int[j] = 0;
	sysinfo->cpu[i].user_mode = 0;
	sysinfo->cpu[i].nice_mode = 0;
	sysinfo->cpu[i].system_mode = 0;
	sysinfo->cpu[i].idle_mode = 0;
	sysinfo->cpu[i].total_usage = 0;
    }

    return;
}


/************** Read CPU and interrupt information from /proc **************/
/************** Store results in SYSInfo struct ****************************/

/* All active interfaces have an entry in /proc/interrupts file. we parse 
 * this file to find out the active network interfaces. We also take the 
 * loopback interface into account, which doesn't have a record in the file.
 */

static status_t read_sys_info( struct SYSInfo * sysinfo )
{
    char buff[BUFFLEN], buff1[BUFFLEN], str[BUFFLEN];
    char *new_line, *find_str;
    int i, j, k, net_num, rval, fd;
    int kernel_26 = 0;

    /*************************** Initialization ****************************/

    bzero(buff, BUFFLEN);
    bzero(buff1, BUFFLEN);
    bzero(str, BUFFLEN);

    init_sysinfo_data(sysinfo);

    /* Copy the network interface names from predefined CONSTNETNAME in 
     * util.h if user has not specified a nic name
     */

    if ( ! Defined_Nic_Name )
	for ( i = 0; i < NETTYPE; i++ )
	    strcpy(NETNAME[i], CONSTNETNAME[i]);

    /************** Fill in loopback "interface" as the first NIC **********/
    /* Loopback "interface" has no records in /proc/interrupts. We are still
     * interested in some statistics about this "interface", whose info be
     * found in /proc/net/dev.
     */
	
    for ( i = 0; i < NETTYPE; i++ ) {
	if ( strncmp(NETNAME[i], "loop", strlen(NETNAME[i])) == 0 ) {
	    sysinfo->net_num = 1;
	    strcpy(sysinfo->net[0].name, "loop");
	}
    }

    /*** Interrupt information is stored in /proc/interrupts in Linux ******/

    if ( (fd = open("/proc/interrupts", O_RDONLY)) < 0 || 
	 (rval=read(fd, buff, BUFFLEN-1)) <= 0) {
        perror("Fail to get interrupt information from /proc/interrupts");
	return NOTOK;
    }
    close(fd); 

    /**** Frist line of /proc/interrupts indicates the number of CPUs ******/

    for ( i = 0; buff[i] != '\n' && i < BUFFLEN-1; i++) // copy the first line to buff1
           buff1[i] = buff[i];
    if ( strlen(buff) == 0 || ( sysinfo->cpu_num = sscanf(buff1, 
	 "%s %s %s %s %s %s %s %s", str, str, str, str, str, str, str, str)) < 1 ) {
 	perror("Failed to parse /proc/interrupts");
	return NOTOK;
    }
    if ( sysinfo->cpu_num > 8 ) {
	fprintf(stderr, "Exceed the maximum CPU number: %d.\n",sysinfo->cpu_num);
	return NOTOK;
    }
 
    /********** Parse the interrupt information line by line ***************/

    new_line = buff;
    net_num = sysinfo->net_num;
    while ( net_num < MAXNETWORK ) {
	
	/******************* Copy next line to buff1 for parsing ***********/
	
        if ( (new_line = strstr(new_line, "\n")) == NULL )
	    break;
	new_line++;
	if ( strlen(new_line) == 0 )
	    break;
	strncpy(buff1, new_line, BUFFLEN-1);
	for ( i = 0; buff1[i] != '\n' && i < BUFFLEN-1; i++ );
	buff1[i] = '\0';
	
	/****************** Search the network interface entry *************/

	for ( i = 0; i < NETTYPE; i++ ) {
	    if ( (find_str = strstr(buff1, NETNAME[i])) != NULL ) { // got one
		
		/******************* First number is IRQ *******************/
		
		sysinfo->net[net_num].irq = atoi(strtok(buff1, " :\t().,"));  

		/******** Following are interrupts for each CPU ************/
	
		for ( j = 0; j < sysinfo->cpu_num; j++ ) {
		    sysinfo->cpu[j].net_int[net_num] = atol(strtok(NULL, " :\t()."));
		    sysinfo->net[net_num].interrupt += sysinfo->cpu[j].net_int[net_num];
		}

		/** The last part is device name such as keyboard and eth0 */
 
		while ( (find_str = (char *)strtok(NULL, " :\t().,")) != NULL ) {
		    if ( (find_str = strstr(find_str, NETNAME[i])) != NULL ) { 
			strncpy(sysinfo->net[net_num].name, find_str, NETNAMELEN-1);
			break;
		    }
		}
		net_num++;
		break;

	    } // end of if find_str
	} // end of for loop 
    } // end of while loop 

    sysinfo->net_num = net_num;

#ifdef DEBUG
    fprintf(stderr, " DEBUG: Parse /proc/interrupts (%d bytes read). CPU: %d  Network-card: %d (%s %s %s)\n",
	   rval, sysinfo->cpu_num, net_num, sysinfo->net[0].name, sysinfo->net[1].name, sysinfo->net[2].name);
#endif        

    /*
    FILE  *fd1;
    if ( (fd1 = open("/proc/stat", "r")) == NULLf || 
	 fscanf(fp1, "%s %d %d %d %d", &str, &sysinfo->cpu_user, &sysinfo->cpu_nice, 
		    &sysinfo->cpu_system, &sysinfo->cpu_idle) != 5 ) {
        perror("Failed to get cpu information from /proc/stat.");
	return NOTOK;
    }
    fclose(fp1); 
    */

    /************************* Read CPU usage ******************************/

    /* CPU information is stored in /proc/stat in Linux. Format:
     * cpu-name user-jiffies nice-jiffies system-jiffies idle-jiffies. For example,
     * cpu  123456 123 12345 1234567
     * The number of jiffies that the system spent in user/nice/system/idle mode are
     * 123456, 123, 12345, and 1234567, respectively. Jiffy is defined by kernel (HZ).
     */ 

    bzero(buff, BUFFLEN);
    if ( (fd = open("/proc/stat", O_RDONLY)) < 0 || 
	 (rval=read(fd, buff, BUFFLEN-1)) <= 0) {
        perror("Failed to get cpu information from /proc/stat.");
	return NOTOK;
    }
    close(fd);

    /************* First line shows the summary of CPU statistics **********/

    if ( strlen(buff) == 0 || sscanf(buff, "%s %lld %lld %lld %lld", str, &sysinfo->cpu_user, 
		&sysinfo->cpu_nice, &sysinfo->cpu_system, &sysinfo->cpu_idle) != 5 ) {
	perror("Failed to get cpu information from /proc/stat.");
	return NOTOK;
    }
   
#ifdef DEBUG
    fprintf(stderr, " DEBUG: Parse /proc/stat (%d byt read): %lld[user] %lld[nice] %lld[system] %lld[idle]\n", rval, 
	   sysinfo->cpu_user, sysinfo->cpu_nice, sysinfo->cpu_system, sysinfo->cpu_idle);
#endif        

    /************************ Get each CPU's usage *************************/
    
    new_line = buff;
    for( i = 0; i < sysinfo->cpu_num; i++){
        if ( (new_line = strstr(new_line, "\n")) == NULL )
	    break;
	new_line++;
	if ( strlen(new_line) == 0 || sscanf(new_line, "%s %lld %lld %lld %lld", 
	     str, &sysinfo->cpu[i].user_mode, &sysinfo->cpu[i].nice_mode, 
             &sysinfo->cpu[i].system_mode, &sysinfo->cpu[i].idle_mode) != 5 ) {
	    perror("Failed to get cpu information from /proc/stat.");
	    return NOTOK;
	}
    }

    if ( (new_line = strstr(buff, "page")) == NULL ) {
      kernel_26 = 1;	    
    } else {
      if ( sscanf(new_line, "%s %lld %lld", str, &sysinfo->page_in, &sysinfo->page_out) != 3 ) {
	    perror("Fail to parse page info from /proc/stat.");
	    return NOTOK;
      }

      if ( (new_line = strstr(buff, "swap")) == NULL || sscanf(new_line, 
	    "%s %lld %lld", str, &sysinfo->swap_in, &sysinfo->swap_out) != 3 ) {
	    perror("Fail to parse swap info.");
	    return NOTOK;
      }
    }

    if ( (new_line = strstr(buff, "intr")) == NULL || sscanf(new_line, 
	  "%s %lld", str, &sysinfo->interrupts) != 2 ) {
	    perror("Fail to parse interrupt info from /proc/stat.");
	    return NOTOK;
    }

    if ( (new_line = strstr(buff, "ctxt")) == NULL || sscanf(new_line, 
	  "%s %lld", str, &sysinfo->context_switch) != 2 ) {
	    perror("Fail to parse context switch info from /proc/stat.");
	    return NOTOK;
    }

    if ( kernel_26 ) {
      read_from_vmstat(sysinfo);
      read_memory_info(sysinfo);
    } else {

      /*************** Read memory information  Kernel 2.4 ****************/

      bzero(buff, BUFFLEN);
      if ( (fd = open("/proc/meminfo", O_RDONLY)) < 0 || 
	   (rval=read(fd, buff, BUFFLEN-1)) <= 0) {
        perror("Failed to open /proc/meminfo.");
	return NOTOK;
      }
      close(fd);

      /********* Ignore the first comment line of /proc/meminfo ************/
      if ( (new_line = strstr(buff, "\n")) == NULL ) {
	perror("Fail to parse /proc/meminfo (No newline?).");
	return NOTOK;
      }
      new_line++;
      
      /************* Parse the second line of /proc/meminfo ****************/
      
      if ( strlen(new_line) == 0 || sscanf(new_line, "%s %lld %lld", str, 
					   &sysinfo->mem_total, &sysinfo->mem_used) != 3 ) {
	perror("Fail to parse /proc/meminfo (Wrong format).");
	return NOTOK;
      }
    }
   
#ifdef DEBUG
    fprintf(stderr, " DEBUG: Parse /proc/meminfo (%d byt read): %lld[mem-total] %lld[mem-used]\n", 
	   rval, sysinfo->mem_total, sysinfo->mem_used);
#endif        

    /*************** Read network device information ***********************/

    bzero(buff, BUFFLEN);
    if ( (fd = open("/proc/net/dev", O_RDONLY)) < 0 || 
	 (rval=read(fd, buff, BUFFLEN-1)) <= 0) {
        perror("Failed to open /proc/net/dev.");
	return NOTOK;
    }
    close(fd);

    /******* Ignore the first two comment lines of /proc/net/dev ***********/
    
    if ( (new_line = strstr(buff, "\n")) == NULL ) {
	perror("Fail to parse /proc/net/dev (No newline?).");
	return NOTOK;
    }
    new_line++;

    for ( i = 0; i < MAXNETWORK;  ) {
	
	/******************* Copy next line to buff1 for parsing ***********/

        if ( (new_line = strstr(new_line, "\n")) == NULL )
	    break;
	new_line++;
	if ( strlen(new_line) == 0 ) 
	    break;
	strncpy(buff1, new_line, BUFFLEN-1);
	for ( j = 0; buff1[j] != '\n' && j < BUFFLEN-1; j++);
	buff1[j] = '\0';

	strcpy(str, strtok(buff1, " :\t()."));
	for ( j = 0; j < sysinfo->net_num; j++ ) {
	    if ( strncmp(str, sysinfo->net[j].name, strlen(str)) == 0 ) {
		sysinfo->net[j].recv_byte = parse_size( strtok(NULL, " :\t()."));
		sysinfo->net[j].recv_packet = parse_size(strtok(NULL, " :\t()."));
		for ( k = 0; k < 6; k++) // We don't use those middle six fields
		    strtok(NULL, " :\t().");
		sysinfo->net[j].send_byte = parse_size(strtok(NULL, " :\t()."));
		sysinfo->net[j].send_packet = parse_size(strtok(NULL, " :\t()."));
#ifdef DEBUG
		fprintf(stderr, " DEBUG: %s: recv-bytes: %lld recv-packets: %lld send-bytes: %lld send-packets: %lld\n",
		   sysinfo->net[j].name, sysinfo->net[j].recv_byte, sysinfo->net[j].recv_packet, 
		   sysinfo->net[j].send_byte, sysinfo->net[j].send_packet);
#endif
		i++; 
		break;

	    } // end of if strncmp
	} // end of for loop of j
    } // end of for loop of i
 
    return OK;
}

/****************** Read paging and swapping info from /proc/vmstat file  ****************/
/****************** Work for Linux Kernel 2.6                             ****************/

status_t read_from_vmstat( struct SYSInfo * sysinfo )
{
    char buff[BUFFLEN], str[BUFFLEN];
    char *new_line;
    int fd, rval;

    bzero(buff, BUFFLEN);
    if ( (fd = open("/proc/vmstat", O_RDONLY)) < 0 ||
         (rval=read(fd, buff, BUFFLEN-1)) <= 0) {
        perror("Failed to get cpu information from /proc/stat.");
        return NOTOK;
    }
    close(fd);

    if ( (new_line = strstr(buff, "pgpgin")) == NULL || sscanf(new_line,
          "%s %lld", str, &sysinfo->page_in) != 2 ) {
            perror("Fail to parse page info from /proc/vmstat.");
            return NOTOK;
    }

    if ( (new_line = strstr(buff, "pgpgout")) == NULL || sscanf(new_line,
          "%s %lld", str, &sysinfo->page_out) != 2 ) {
            perror("Fail to parse page info from /proc/vmstat.");
            return NOTOK;
    }

    if ( (new_line = strstr(buff, "pswpin")) == NULL || sscanf(new_line,
          "%s %lld", str, &sysinfo->swap_in) != 2) {
            perror("Fail to parse swap info from /proc/vmstat.");
            return NOTOK;
    }

    if ( (new_line = strstr(buff, "pswpout")) == NULL || sscanf(new_line,
          "%s %lld", str, &sysinfo->swap_out) != 2) {
            perror("Fail to parse swap info from /proc/vmstat.");
            return NOTOK;
    } 

    return OK;
}


/****************** Read memory information from /proc/meminfo      ****************/
/****************** Work for Linux Kernel 2.6                       ****************/

status_t read_memory_info( struct SYSInfo * sysinfo )
{
    char buff[BUFFLEN], str[BUFFLEN];
    char *new_line;
    int fd, rval;
    long_int mem_free, mem_cache, mem_buffer;    
    bzero(buff, BUFFLEN);
    if ( (fd = open("/proc/meminfo", O_RDONLY)) < 0 ||
	 (rval=read(fd, buff, BUFFLEN-1)) <= 0) {
                perror("Failed to open /proc/meminfo.");
                return NOTOK;
    }
    close(fd);
    
    if ( sscanf(buff, "%s %lld ", str, &sysinfo->mem_total) != 2 ) {
      perror("Fail to parse /proc/meminfo (Memtotal Wrong format).");
                return NOTOK;
    }
    
    if ( (new_line = strstr(buff, "\n")) == NULL ) {
      perror("Fail to parse /proc/meminfo (No newline?).");
      return NOTOK;
    }
    new_line++;
    
    if ( sscanf(new_line, "%s %lld ", str, &mem_free) != 2 ) {
      perror("Fail to parse /proc/meminfo (MemFree Wrong format).");
      return NOTOK;
    }
    
    if ( (new_line = strstr(new_line, "\n")) == NULL ) {
      perror("Fail to parse /proc/meminfo (No newline?).");
      return NOTOK;
    }
    new_line++;
    if ( sscanf(new_line, "%s %lld ", str, &mem_buffer) != 2 ) {
      perror("Fail to parse /proc/meminfo (MemBuffer Wrong format).");
      return NOTOK;
    }
    
    if ( (new_line = strstr(new_line, "\n")) == NULL ) {
      perror("Fail to parse /proc/meminfo (No newline?).");
      return NOTOK;
    }
    new_line++;
    
    if ( sscanf(new_line, "%s %lld ", str, &mem_cache) != 2 ) {
      perror("Fail to parse /proc/meminfo (MemCache Wrong format).");
      return NOTOK;
    }
    sysinfo->mem_used = sysinfo->mem_total - mem_free - mem_cache - mem_buffer;

    return OK;
}

/****************** Start to monitor the system information ****************/

status_t start_trace_system( struct SYSInfo * sysinfo )
{

#ifndef linux
    return NOTOK; 
#endif

    if ( read_sys_info(sysinfo) == NOTOK )
	return NOTOK;
    return OK;
}

/******** Stop monitoring and compute the system resource usage ************/ 

status_t stop_trace_system( struct SYSInfo * sysinfo )
{    

#ifndef linux
    return NOTOK;
#endif

    int i, j;
    long clock_ticks;
    struct SYSInfo preInfo;

    /******************* Copy the original structure ***********************/

    preInfo = *sysinfo;

    /******************* Read fresh system information *********************/

    if ( read_sys_info(sysinfo) == NOTOK )
	return NOTOK;

    /*************** System's clock-per-second (HZ) value ******************/

    if ((clock_ticks = sysconf(_SC_CLK_TCK)) == -1) {
        perror("Failed to determine clock ticks per second.");
        return NOTOK;
    } else if ( clock_ticks == 0 ) {
        fprintf(stderr, "Invalid number of ticks per second\n");
        return NOTOK;
    }
    sysinfo->clock_rate = clock_ticks;
    
    /*** Record the system resource usage between start and stop tracing ***/

    sysinfo->cpu_user = safe_subtract(sysinfo->cpu_user, preInfo.cpu_user);
    sysinfo->cpu_nice = safe_subtract(sysinfo->cpu_nice, preInfo.cpu_nice);
    sysinfo->cpu_system = safe_subtract(sysinfo->cpu_system, preInfo.cpu_system);
    sysinfo->cpu_idle = safe_subtract(sysinfo->cpu_idle, preInfo.cpu_idle);
    sysinfo->cpu_total = sysinfo->cpu_user + sysinfo->cpu_nice 
	                 + sysinfo->cpu_system + sysinfo->cpu_idle;
    sysinfo->interrupts = safe_subtract(sysinfo->interrupts, preInfo.interrupts);
    sysinfo->page_in = safe_subtract(sysinfo->page_in, preInfo.page_in);
    sysinfo->page_out = safe_subtract(sysinfo->page_out, preInfo.page_out);
    sysinfo->swap_in = safe_subtract(sysinfo->swap_in, preInfo.swap_in);
    sysinfo->swap_out = safe_subtract(sysinfo->swap_out, preInfo.swap_out);
    sysinfo->context_switch = safe_subtract(sysinfo->context_switch, preInfo.context_switch);

    for ( i = 0; i < sysinfo->cpu_num; i++ ) {
	for ( j = 0; j < sysinfo->net_num; j++ )
	    sysinfo->cpu[i].net_int[j] = 
		(long)safe_subtract(sysinfo->cpu[i].net_int[j], preInfo.cpu[i].net_int[j]);
	sysinfo->cpu[i].user_mode = 
	    safe_subtract(sysinfo->cpu[i].user_mode, preInfo.cpu[i].user_mode);
	sysinfo->cpu[i].nice_mode = 
	    safe_subtract(sysinfo->cpu[i].nice_mode, preInfo.cpu[i].nice_mode);
	sysinfo->cpu[i].system_mode = 
	    safe_subtract(sysinfo->cpu[i].system_mode, preInfo.cpu[i].system_mode);
	sysinfo->cpu[i].idle_mode = 
	    safe_subtract(sysinfo->cpu[i].idle_mode, preInfo.cpu[i].idle_mode);
	sysinfo->cpu[i].total_usage = sysinfo->cpu[i].user_mode + sysinfo->cpu[i].nice_mode 
	    + sysinfo->cpu[i].system_mode + sysinfo->cpu[i].idle_mode;
    }
    for ( i = 0; i < sysinfo->net_num; i++ ) {
	sysinfo->net[i].interrupt = 
	    safe_subtract(sysinfo->net[i].interrupt, preInfo.net[i].interrupt);
	sysinfo->net[i].recv_byte = 
	    safe_subtract(sysinfo->net[i].recv_byte, preInfo.net[i].recv_byte);
	sysinfo->net[i].recv_packet = 
	    safe_subtract(sysinfo->net[i].recv_packet, preInfo.net[i].recv_packet);
	sysinfo->net[i].send_byte = 
	    safe_subtract(sysinfo->net[i].send_byte, preInfo.net[i].send_byte);
	sysinfo->net[i].send_packet = 
	    safe_subtract(sysinfo->net[i].send_packet, preInfo.net[i].send_packet);
    }	

    return OK;
}


/************ Start to monitor process's resource **************************/

status_t start_trace_process(struct PROInfo * usage) 
{
    struct rusage start;
    struct timeval tv;

    if ( getrusage(RUSAGE_SELF, &start) < 0 ) {
	perror("Fail to get process resource.");
	return NOTOK;
    }

    gettimeofday(&tv, NULL);
    usage->pid = getpid();
    usage->rtime_sec = tv.tv_sec;
    usage->rtime_usec = tv.tv_usec;
    usage->utime_sec = start.ru_utime.tv_sec;
    usage->utime_usec = start.ru_utime.tv_usec;
    usage->stime_sec = start.ru_stime.tv_sec;
    usage->stime_usec = start.ru_stime.tv_usec;
    usage->mem = start.ru_maxrss;
    usage->swap = start.ru_nswap;
    usage->read_times = start.ru_inblock;
    usage->write_times = start.ru_oublock;
    usage->signals = start.ru_nsignals;
    
    return OK;
}

/********** Stop monitoring and compute the process's resource usage *******/
    
status_t stop_trace_process(struct PROInfo * usage) 
{
    struct rusage end;
    struct timeval tv;

    if ( getpid() != usage->pid) {
	fprintf(stderr, "Not the same process!\n");
	return NOTOK;
    }
    if ( getrusage(RUSAGE_SELF, &end) < 0 ) {
	perror("Fail to get process resource.");
	return NOTOK;
    }
    gettimeofday(&tv, NULL);
    usage->rtime_sec = tv.tv_sec - usage->rtime_sec;
    usage->rtime_usec = tv.tv_usec - usage->rtime_usec;
    if (  usage->rtime_usec < 0 ) {
	usage->rtime_usec += 1000000;
	usage->rtime_sec  -= 1;
    }

    usage->utime_sec  = end.ru_utime.tv_sec - usage->utime_sec;
    usage->utime_usec = end.ru_utime.tv_usec - usage->utime_usec;

    if (  usage->utime_usec < 0 ) {
	usage->utime_usec += 1000000;
	usage->utime_sec  -= 1;
    }

    usage->stime_sec  = end.ru_stime.tv_sec - usage->stime_sec;
    usage->stime_usec = end.ru_stime.tv_usec - usage->stime_usec;

    if (  usage->stime_usec < 0 ) {
	usage->stime_usec += 1000000;
	usage->stime_sec  -= 1;
    }

    usage->swap = end.ru_nswap - usage->swap;
    usage->read_times = end.ru_inblock - usage->read_times;
    usage->write_times = end.ru_oublock - usage->write_times;
    usage->signals  = end.ru_nsignals - usage->signals;

    return OK;
}

/************ This function is just for object's serialization *************/
/* Another approach is to check system's byte order (little/big endian), 
 * then we could just directly send a block of data. 
 */

status_t sysinfo_to_string( struct SYSInfo * sysinfo, char *str, int len )
{
    char buff[len], temp[BUFFLEN];
    int i, j;

    bzero(buff, len);

    sprintf(buff, "%d %d %d %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld ", 
	    sysinfo->clock_rate, sysinfo->cpu_num, sysinfo->net_num, sysinfo->cpu_total, 
	    sysinfo->cpu_user, sysinfo->cpu_nice, sysinfo->cpu_system, sysinfo->cpu_idle, 
	    sysinfo->mem_used, sysinfo->mem_total, sysinfo->interrupts, sysinfo->page_in, 
	    sysinfo->page_out, sysinfo->swap_in, sysinfo->swap_out, sysinfo->context_switch);

    for ( i = 0; i < sysinfo->net_num; i++ ) {
	sprintf(temp, "%d %ld %lld %lld %lld %lld %s ", sysinfo->net[i].irq, 
		sysinfo->net[i].interrupt, sysinfo->net[i].recv_packet, 
		sysinfo->net[i].recv_byte, sysinfo->net[i].send_packet, 
		sysinfo->net[i].send_byte, sysinfo->net[i].name);
	if ( (strlen(buff)+strlen(temp)) > len ) {
	    fprintf(stderr, "Buffer overflowing.\n");
	    return NOTOK;
	}
	strcat(buff, temp);
    }

    for ( i = 0; i < sysinfo->cpu_num; i++ ) {
	for ( j = 0; j < sysinfo->net_num; j++ ) {
	    sprintf(temp, "%ld ", sysinfo->cpu[i].net_int[j]);
	    if ( (strlen(buff)+strlen(temp)) > len ) {
		fprintf(stderr, "Buffer overflowing.\n");
		return NOTOK;
	    }
	    strcat(buff, temp);
	}
	sprintf(temp, "%lld %lld %lld %lld %lld ", sysinfo->cpu[i].user_mode, 
		 sysinfo->cpu[i].nice_mode, sysinfo->cpu[i].system_mode, 
		 sysinfo->cpu[i].idle_mode, sysinfo->cpu[i].total_usage);
	if ( (strlen(buff)+strlen(temp)) > len ) {
	    fprintf(stderr, "Buffer overflowing.\n");
	    return NOTOK;
	}
	strcat(buff, temp);
    }

    if ( (strlen(buff)+3) > len ) {
	fprintf(stderr, "Buffer overflowing.\n");
	return NOTOK;
    }
    strcat(buff, "\r\n");
    strcpy(str, buff);

    return OK;

}

/*********************** Systen information de-serialization ***************/

status_t string_to_sysinfo( struct SYSInfo *sysinfo, char * str, int len )
{
    char buff[len+1], temp[BUFFLEN], *ptr = str;
    int i, j, num;
    
    if ( (num=sscanf(str, "%d %d %d %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld", 
		     &sysinfo->clock_rate, &sysinfo->cpu_num, &sysinfo->net_num, 
		     &sysinfo->cpu_total, &sysinfo->cpu_user, &sysinfo->cpu_nice, 
		     &sysinfo->cpu_system, &sysinfo->cpu_idle, &sysinfo->mem_used, 
		     &sysinfo->mem_total, &sysinfo->interrupts, &sysinfo->page_in,
		     &sysinfo->page_out, &sysinfo->swap_in, &sysinfo->swap_out, 
		     &sysinfo->context_switch)) != 16 ) {
	fprintf(stderr, "Parse wrong(%d): %s\n", num, ptr);
	return NOTOK;
    }
    sprintf(buff, "%d %d %d %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld", 
	    sysinfo->clock_rate, sysinfo->cpu_num, sysinfo->net_num, sysinfo->cpu_total, 
	    sysinfo->cpu_user, sysinfo->cpu_nice, sysinfo->cpu_system, sysinfo->cpu_idle, 
	    sysinfo->mem_used, sysinfo->mem_total, sysinfo->interrupts, sysinfo->page_in, 
	    sysinfo->page_out, sysinfo->swap_in, sysinfo->swap_out, sysinfo->context_switch);

    ptr = str+strlen(buff);

    for ( i = 0; i < sysinfo->net_num; i++ ) {
	if ( (num=sscanf(ptr, "%d %ld %lld %lld %lld %lld %s ", &sysinfo->net[i].irq, 
			 &sysinfo->net[i].interrupt, &sysinfo->net[i].recv_packet, 
			 &sysinfo->net[i].recv_byte, &sysinfo->net[i].send_packet, 
			 &sysinfo->net[i].send_byte, sysinfo->net[i].name)) != 7 ) {
	    fprintf(stderr, "Parse wrong(%d): %s\n", num, ptr);
	    return NOTOK;
	}
	
	sprintf(temp, "%d %ld %lld %lld %lld %lld %s ", sysinfo->net[i].irq, 
		sysinfo->net[i].interrupt, sysinfo->net[i].recv_packet, 
		sysinfo->net[i].recv_byte, sysinfo->net[i].send_packet, 
		sysinfo->net[i].send_byte, sysinfo->net[i].name);

	if ( (ptr+strlen(temp)) >= (str+len) ) {
	    fprintf(stderr, "Buffer overflowing.\n");
	    return NOTOK;
	}	  
	strcat(buff, temp);
	ptr = str+strlen(buff);
    }

    for ( i = 0; i < sysinfo->cpu_num; i++ ) {
	for ( j = 0; j < sysinfo->net_num; j++ ) {
	    if ( (num=sscanf(ptr, "%ld ", &sysinfo->cpu[i].net_int[j])) != 1) {
		fprintf(stderr, "Parse wrong(%d): %s\n", num, ptr);
		return NOTOK;
	    }
	    sprintf(temp, "%ld ", sysinfo->cpu[i].net_int[j]);
	    if ( (ptr+strlen(temp)) >= (str+len) ) {
		fprintf(stderr, "Buffer overflowing.\n");
		return NOTOK;
	    }	  
	    strcat(buff, temp);
	    ptr = str+strlen(buff);
	}
	if ( (num=sscanf(ptr, "%lld %lld %lld %lld %lld ", &sysinfo->cpu[i].user_mode, 
			 &sysinfo->cpu[i].nice_mode, &sysinfo->cpu[i].system_mode, 
			 &sysinfo->cpu[i].idle_mode, &sysinfo->cpu[i].total_usage)) != 5 ) {
	    fprintf(stderr, "Parse wrong(%d): %s\n", num, ptr);
	    return NOTOK; 
	}
	
	sprintf(temp, "%lld %lld %lld %lld %lld ", sysinfo->cpu[i].user_mode, 
		sysinfo->cpu[i].nice_mode, sysinfo->cpu[i].system_mode, 
		sysinfo->cpu[i].idle_mode, sysinfo->cpu[i].total_usage);
	if ( (ptr+strlen(temp)) >= (str+len) ) {
	    fprintf(stderr, "Buffer overflowing.\n");
	    return NOTOK;
	}	  
	strcat(buff, temp);
	ptr = str+strlen(buff);
    }

    return OK;
    
}

/********************** Write results to a file ****************************/

status_t write_sys_info(struct SYSInfo *sysinfo, int repeat, char *filename, 
			char *testtime, char *hostname) 
{
    FILE *output;
    char buff[BUFFLEN];
    int i, j, k, cpu_num, net_num; 
    int cpuload, userload, sysload, mem_used, mem_total;
    double cpu_all, user_all, sys_all, idle_all;
    double cpu1, user1, sys1, idle1;
    long_int recv_packet, sent_packet, recv_byte, sent_byte;

    cpu_num = sysinfo[0].cpu_num;
    net_num = sysinfo[0].net_num;
     
    strcpy(buff, filename);
    if ( (output = fopen(buff, "w")) == NULL ) {
        fprintf(stderr, "%s: Unable to write the file!\n", buff);
        return NOTOK;
    }

    fprintf(output, "# %s syslog -- %s\n", hostname, testtime);
    fprintf(output, "# Watch times: %d\n", repeat);
    fprintf(output, "# Network devices (interface): %d ( ", net_num);
    for ( i = 0; i < net_num; i++ )
	fprintf(output, "%s ", sysinfo[0].net[i].name);
    fprintf(output, ")\n# CPU number: %d\n\n",  cpu_num);

   /********** Write the each network interface's information **************/

    for ( i = 0; i < net_num; i++ ) {

	fprintf(output, "##### System info, statistics of network interface <%s> and its interrupts to each CPU #####\n", 
		sysinfo[0].net[i].name);
	fprintf(output, "#       CPU(%%)     Mem(%%)  Interrupt  Page   Swap   Context           <%s> information\n", 
		sysinfo[0].net[i].name);
	fprintf(output, "#   Load User  Sys  Usage   Overall  In/out In/out   Swtich   RecvPkg    RecvByte   SentPkg    SentByte  ");
	for ( j = 0; j < cpu_num; j++ )
	    fprintf(output, "Int-CPU%d ", j); 
	fprintf(output, "\n");
	for ( j = 0; j < repeat; j++ ) {
	    if ( sysinfo[j].cpu_total <= 0 ) {
		fprintf(stderr, "No message!\n");
		continue;
	    }
	    cpuload = (sysinfo[j].cpu_total - sysinfo[j].cpu_idle)*100 / sysinfo[j].cpu_total;  
	    userload = sysinfo[j].cpu_user*100 / sysinfo[j].cpu_total;
	    sysload = sysinfo[j].cpu_system*100/ sysinfo[j].cpu_total;
	    mem_used = sysinfo[j].mem_used / (1024*1024);       // Memory used by system in Mbytes
	    mem_total = sysinfo[j].mem_total / (1024*1024);     // Physical memory in Mbytes
	    recv_packet = sysinfo[j].net[i].recv_packet;
	    recv_byte = sysinfo[j].net[i].recv_byte;
	    sent_packet = sysinfo[j].net[i].send_packet;
	    sent_byte = sysinfo[j].net[i].send_byte;
	    fprintf(output, "%-3d %4d %4d %4d %6.0f%10lld%8lld%7lld%9lld", 
		    j, cpuload, userload, sysload, mem_used*100.0/mem_total, sysinfo[j].interrupts, 
		    sysinfo[j].page_in+sysinfo[j].page_out, sysinfo[j].swap_in+sysinfo[j].swap_out, 
		    sysinfo[j].context_switch);
	    fprintf(output, "%10lld%12lld%10lld%12lld ",
		    recv_packet, recv_byte, sent_packet, sent_byte);
	    for ( k = 0; k < cpu_num; k++ )
		fprintf(output, "%9ld", sysinfo[j].cpu[k].net_int[i]);
	    fprintf(output, "\n");
	}
	fprintf(output, "\n");
    }

    /*********************** Write each CPU's information ******************/

    if ( cpu_num > 1 ) {
	fprintf(output, "## CPU workload distribution: \n##");
	for ( i = 0; i < cpu_num; i++ ) {
	    fprintf(output, "\n##         CPU%d workload (%%)           Overall CPU workload (%%)\n", i);
	    fprintf(output, "#   < load   user  system   idle >  < load   user  system   idle >\n");
                                 
	    for ( j = 0; j < repeat; j++ ) {
		if ( sysinfo[j].cpu[i].total_usage <= 0 ) {
		    fprintf(stderr, "No message!\n");
		    continue;
		}
		cpu1 = (sysinfo[j].cpu[i].total_usage - sysinfo[j].cpu[i].idle_mode) 
		    * 100.0 / sysinfo[j].cpu[i].total_usage;  
		user1 = sysinfo[j].cpu[i].user_mode * 100.0 / sysinfo[j].cpu[i].total_usage;
		sys1 = sysinfo[j].cpu[i].system_mode * 100.0 / sysinfo[j].cpu[i].total_usage;
		idle1 = sysinfo[j].cpu[i].idle_mode * 100.0 / sysinfo[j].cpu[i].total_usage;
		cpu_all = (sysinfo[j].cpu_total - sysinfo[j].cpu_idle) 
		    * 100.0 / sysinfo[j].cpu_total;  
		user_all = sysinfo[j].cpu_user * 100.0 / sysinfo[j].cpu_total;
		sys_all = sysinfo[j].cpu_system * 100.0 / sysinfo[j].cpu_total;
		idle_all = sysinfo[j].cpu_idle * 100.0 / sysinfo[j].cpu_total;
		//fprintf(output, "%-2d %6.1f%%%6.1f%%%7.1f%%%6.1f%%  %7.1f%%%6.1f%%%6.1f%%%7.1f%%\n", 
		fprintf(output, "%-2d %7.1f%7.1f%7.1f%8.1f  %8.1f%7.1f%7.1f%8.1f\n", 
			j, cpu1, user1, sys1, idle1, cpu_all, user_all, sys_all, idle_all);
	    }
	}
    }

    fclose(output);
    
    return OK;
}
