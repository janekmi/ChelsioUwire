/*
 * isns client
 */

#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include "../common/iscsictl_private.h"
#include "isns.h"
#include "isns_utils.h"
#include "isns_sock.h"
#include "isns_pdu_defs.h"
#include "isns_pdu.h"
#include "isns_target.h"

// grab the version number
#include "../../includes/common/version.h"

isns_sock main_tsock;		/* main isns target socket */
isns_sock main_lsock;		/* esi/scn listening socket */

pid_t   self_pid;
unsigned int poll_period = ISNS_POLL_PERIOD_DEFAULT;
char    t_eid[ISNS_EID_LENGTH];
char    eid[ISNS_EID_LENGTH];
int     keep_running = 1;
int     poll = 0;
int     update = 1;
int 	iscsi_node_all = 0;
int     isns_log = 0;
FILE*   fp = NULL;

char    iscsictl_buffer[ISCSI_CONTROL_DATA_MAX_BUFLEN];

/**
 * sig_catcher - isns client's signal catcher 
 * @signum - signal number
 */
static void sig_catcher(int signum)
{
	switch (signum) {
		case SIGTERM:
		case SIGINT:
		case SIGQUIT:
			isns_log_msg("need to exit.\n");
			keep_running = 0;
			break;
		case SIGUSR2:
			update = 1;
			isns_log_msg("iscsi update needed.\n");
			break;
		case SIGUSR1:
			poll = 1;
			isns_log_msg("polling needed.\n");
			break;
		default:
			break;
	}
}

static int isns_trap_signals(sigset_t * sigmask)
{
	sigset_t sigset;
	struct sigaction action;
	int     rv;

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	sigaddset(&sigset, SIGQUIT);
	sigaddset(&sigset, SIGTERM);
	sigaddset(&sigset, SIGUSR1);
	sigaddset(&sigset, SIGUSR2);

	sigemptyset(&action.sa_mask);
	action.sa_flags = 0;
	action.sa_handler = sig_catcher;

	/* setup no mask */
	rv = sigaction(SIGINT, &action, NULL);
	rv |= sigaction(SIGQUIT, &action, NULL);
	rv |= sigaction(SIGTERM, &action, NULL);
	rv |= sigaction(SIGUSR1, &action, NULL);
	rv |= sigaction(SIGUSR2, &action, NULL);
	if (rv < 0) {
		perror("sigaction");
		return rv;
	}

	sigprocmask(SIG_BLOCK, &sigset, sigmask);

	return 0;
}

/**
 * isns_main_server - iSNS esi/scn thread
 * @arg: NULL
 */
static void *isns_main_server(void *arg)
{
	int     rv;
	sigset_t sigmask;
	isns_sock sock;		/* accepted socket */
	char    rbuf[ISNS_PDU_MAX_LENGTH];
	char    tbuf[ISNS_PDU_MAX_LENGTH];

	rv = isns_trap_signals(&sigmask);
	if (rv < 0)
		return NULL;

	isns_sock_init(&sock);

	while (keep_running) {
		u_int16_t fid, tid, dlen;
		if (sock.fd < 0) {
			rv = isns_sock_accept(&main_lsock, &sock);
			if (rv < 0)
				goto reconn;
			if(!sock.sip[0])
				isns_log_msg
					("esi/scn server accept from " FORMAT_IPV4 ",%u.\n",
					 ADDR_IPV4(sock.sip[3]), sock.sport);
			else	isns_log_msg
                                        ("esi/scn server accept from " FORMAT_IPV6 ",%u.\n",
                                         ADDR_IPV6(sock.sip), sock.sport);
		}

		memset(tbuf, 0, ISNS_PDU_MAX_LENGTH);
		memset(rbuf, 0, ISNS_PDU_MAX_LENGTH);

		rv = isns_pdu_recv(&sock, rbuf, ISNS_PDU_MAX_LENGTH);
		if (rv < 0)
			goto reconn;

		/* parse the pdu */
		fid = GET_ISNS_PDU_FUNCTIONID(rbuf);
		tid = GET_ISNS_PDU_TRANSACTIONID(rbuf);
		dlen = GET_ISNS_PDU_LENGTH(rbuf);

		isns_log_msg("esi/scn: rcv pdu fid 0x%x, tid 0x%x, dlen %u.\n",
			     fid, tid, dlen);

		if (fid == ISNS_ESI) {
			isns_log_msg("esi/scn: rcv ESI.\n");
			isns_pdu_write_hdr(tbuf, ISNS_ESI_RESP, dlen + 4, 0,
					   tid);
			*(u_int32_t *) (tbuf + ISNS_PDU_HDR_LEN + 4) = 0;
			memcpy(tbuf + ISNS_PDU_HDR_LEN + 4,
			       rbuf + ISNS_PDU_HDR_LEN, dlen);
			rv = isns_pdu_send(&sock, tbuf, ISNS_PDU_MAX_LENGTH);
			isns_log_msg("esi/scn: send ESI %d.\n", rv);

		} else if (fid == ISNS_SCN) {
			u_int16_t tag, tlen;
			isns_log_msg("esi/scn: rcv SCN.\n");
			tag = htonl(*((u_int32_t *) rbuf));
			tlen = htonl(*
				     ((u_int32_t *) (rbuf +
						     ISNS_ATTR_TAG_LENGTH)));
			isns_pdu_write_hdr(tbuf, ISNS_SCN_RESP, 4, 0, tid);
			isns_pdu_write_attr(tbuf, tag, tlen,
					    rbuf + ISNS_PDU_HDR_LEN, 0);
			rv = isns_pdu_send(&sock, tbuf, ISNS_PDU_MAX_LENGTH);
			isns_log_msg("esi/scn: send SCN %d.\n", rv);
		}

reconn:
		isns_sock_close(&sock);
		sleep(1);
	}

	isns_sock_close(&sock);
	isns_sock_close(&main_lsock);
	isns_log_msg("esi/scn server exit.\n");

	return NULL;
}

static void *isns_file_logger(void * arg)
{
	char fname[ISNS_LOG_PATH_MAX+1];  

	snprintf(fname, sizeof(fname), "%s%ld", ISNS_LOG_PATH, (long)getpid());	
	fp = fopen(fname, "w");
	if(fp == NULL) {
		isns_log_error("could not open log file %s",fname);
		isns_log = 0;
		return NULL;
	}
	while(keep_running) {
		if(isns_log == 2) {
			fp = freopen(fname, "w",fp);
			if(fp == NULL) {
				isns_log_error("could not open log file %s",fname);
				isns_log = 0;
				return NULL;
			} else {
				if(!main_tsock.dip[0]) {
		                        isns_log_msg_to_file("chisns utility v%s-%s\nisnsserver \t: " FORMAT_IPV4 "\n",
        		                                DRIVER_VERSION, BUILD_VERSION ,ADDR_IPV4(main_tsock.dip[3]));
				} else { 
					isns_log_msg_to_file("chisns utility v%s-%s\nisnsserver \t: " FORMAT_IPV6 "\n",
							DRIVER_VERSION, BUILD_VERSION ,ADDR_IPV6(main_tsock.dip));
				}
				isns_log = 1;
			}
		}
	}

	fclose(fp);
	return NULL;
}

/**
 * isns_client - iSNS main thread
 * @arg: NULL
 */
void   *isns_timer(void *arg);
static int isns_client(void)
{
	int     rv;
	int     fail = 0;
	pthread_t timer_thread;
	pthread_t logger_thread;
	sigset_t sigmask;
	isns_sock_init(&main_lsock);

	isns_target_init();

	sleep(1);

	rv = isns_trap_signals(&sigmask);
	if (rv < 0)
		return rv;

	/* open the esi/scn listening server */
	rv = isns_sock_listen(&main_lsock);
	if (rv < 0)
		goto done;

	/* start the polling timer thread */
	rv = pthread_create(&timer_thread, NULL, &isns_timer, NULL);
	if (rv != 0) {
		isns_log_error("start timer thread failed.\n");
		goto done;
	}

	/* start the esi monitor thread */
	rv = pthread_create(&(main_lsock.thread), NULL, &isns_main_server,
			    NULL);
	if (rv != 0) {
		isns_log_error("start esi/scn thread failed.\n");
		goto done;
	}

	if(isns_log) {
		rv = pthread_create(&logger_thread, NULL, &isns_file_logger,
				    NULL);
		if (rv != 0) {
			isns_log_error("could not create log file. logging disabled\n");
			isns_log = 0;
		}
	}

	update = 1;		/* start with an iscsi update */
		
	while (keep_running) {

		if (fail) {
			isns_target_cleanup(&main_tsock);
			isns_entity_deregister(&main_tsock, t_eid);
			update = 1;
		}
			
		rv = isns_target_client(&main_tsock, update, poll);
		if (rv < 0)
			isns_target_cleanup(&main_tsock);
		isns_sock_close(&main_tsock);

		if (!rv) {
			fail = 0;
			update = 0;
			poll = 0;
		} else
			fail = 1;

		/* wait for request to come in, indicated by SIGUSR2 */
		sigsuspend(&sigmask);
	}
done:
	isns_target_cleanup(&main_tsock);

	isns_entity_deregister(&main_tsock, t_eid);

	isns_sock_close(&main_tsock);
	isns_sock_close(&main_lsock);

	isns_log_msg("exit.\n");

	return 0;
}

static void isns_display_usage(char *name)
{
	printf("Usage: %s server=<ip>[:<port>] [id=<id>] [query=<query interval>]\n",
		 name);
	printf("\tserver -- iSNS server address\n");
	printf("\tid     -- iSNS entity ID, default to <hostname>\n");
	printf("\tquery  -- initiator query interval (in seconds), default to %d sec.\n",
		 ISNS_POLL_PERIOD_DEFAULT);
	printf("\t-l     -- Log to file, defaults to %s<pid>\n",ISNS_LOG_PATH);
        printf("\t-h     -- Display this help message\n");
        printf("\t-v     -- Display version information\n");
}

static int iscsi_is_address_ipv6(char * str) {

        int count=0;
        char *addr;

        for (addr = str; *addr; addr++) {
                if (*addr == ':')
                        count++;
                else if (*addr == ']' || *addr == ',')
                        break;
        }
        return (count ? count-1 : count);
}

static int isns_parse_cmdline(int argc, char **argv)
{
	int     i, is_ipv6, ret = 0;
	char   *client_str = NULL, *server_str = NULL, *poll_str = NULL;
	char   *ip_str, *port_str;

	t_eid[0] = 0;

	/* parse the command line */
	for (i = 1; i < argc; i++) {
		char   *key, *val;

		if (!strncmp(argv[i], "-h", 2) || !strcmp(argv[i], "help")) {
			isns_display_usage(argv[0]);
			exit(0);
		}

                if (!strncmp(argv[i],  "-v", 2) || !strcmp(argv[i], "version")) {
                        printf("%s v%s-%s\n%s\n",
                        argv[0], DRIVER_VERSION, BUILD_VERSION,
                                       COPYRIGHT);
                        exit(0);
                }	

                if (!strncmp(argv[i],  "-l", 2)) {
			isns_log = 1;
			continue;
                }	

		key = strtok(argv[i], "=");
		val = strtok(NULL, "=");
		if (!strcmp(key, "server")) {
			if (server_str) {
				isns_log_error("duplicate %s.\n", key);
				return -1;
			}
			server_str = val;

		} else if (!strcmp(key, "id")) {
			if (client_str) {
				isns_log_error("duplicate %s.\n", key);
				return -1;
			}
			client_str = val;

		} else if (!strcmp(key, "query")) {
			if (poll_str) {
				isns_log_error("duplicate %s.\n", key);
				return -1;
			}
			poll_str = val;

		} else {
			isns_log_error("Un-recognized %s.\n", key);
			return -1;
		}
	}

	if (!server_str) {
		isns_log_error("Missing server info..\n");
		isns_display_usage(argv[0]);
		return -1;
	} 
	
	is_ipv6 = iscsi_is_address_ipv6(server_str);

	if(is_ipv6) {
		ip_str = server_str;
		if (*ip_str == '[') 
			ip_str++;
		ip_str = strtok(ip_str, "]");
		port_str = strtok(NULL, ":");
	} else {
		ip_str = malloc(sizeof(char) * INET6_ADDRSTRLEN);
		strcat(ip_str, IPV6_PREFIX);
		strcat(ip_str, strtok(server_str, ":"));
		port_str = strtok(NULL, ":");
	}

	if (ip_str) {
		inet_pton(AF_INET6, ip_str, main_tsock.dip);
	} else {
		struct hostent *addr;
		if ((addr = gethostbyname(ip_str)) == NULL) {
			isns_log_error("bad hostname %s.\n", ip_str);
			return -1;
		}
		bcopy(addr->h_addr, (char *) &main_tsock.dip, addr->h_length);
	}

	if (port_str) {
		main_tsock.dport = atoi(port_str);
	} else {
		main_tsock.dport = ISNS_SERVER_PORT_DEFAULT;
	}

	if (client_str) {
		strcpy(eid, client_str);
	} else if (gethostname(eid, 256) < 0) {
		perror("gethostname");	/* <unistd.h> */
		ret = -1;
		goto out;
	}
	
	strcpy(t_eid, eid);
	strcat(t_eid, ".target");
		
	if (poll_str) {
		poll_period = atoi(poll_str);
	}
	isns_log_msg("query interval = %u sec.\n", poll_period);

	ret = 0;
out:
	if(!is_ipv6)
		free(ip_str);
	return ret;
}

int main(int argc, char **argv)
{
	int     rv;

	self_pid = getpid();
	isns_sock_init(&main_tsock);

	rv = isns_parse_cmdline(argc, argv);
	if (rv < 0)
		exit(0);

	isns_client();

	return 0;
}
