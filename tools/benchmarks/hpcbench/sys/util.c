/***********************************************************************************/
/**                                                                               **/
/**         Sysmon: a Linux resource tracing tool                                 **/
/**         Ben Huang hben@users.sf.net                                           **/
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

static long_int parse_size(char *str)
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
