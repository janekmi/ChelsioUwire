#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include "cxgbtool.h"
#include "ba_server.h"

int cli_sock;
char *devname;
char sockname[64];

int init_ba_client(void);

int main(int argc, char * argv[])
{
	int	rc;
	int	i;
	int	len;
	int	total_len = 0;
	char *	buf;
	char *	ptr;
	char	exitrc;

	if (0 != getuid()) {
		printf("ba_client: root privileges are required to run this command\n");
		exit(-1);
	}

	/*
	 * first arg is the interface
	 */
	devname = argv[1];

	/*
	 * connect to ba_server
	 */
	rc = init_ba_client();
	if (rc < 0) {
		printf("cli initialization failed, exiting\n");
		exit(rc);
	}

	/*
	 * get total length of all arguments
	 */
	for (i=0; i < argc; i++) {
		total_len += strlen(argv[i]) + 1;
	}

	/*
	 * allocate buffer to hold arguments
	 */
	buf = malloc(total_len);
	if (buf == NULL) {
		printf("command buf allocation failed, exiting\n");
		exit(rc);
	}

	/*
	 * copy args into buffer
	 */
	ptr = buf;
	for (i=0; i < argc; i++) {
		len = strlen(argv[i]) + 1;
		bcopy(argv[i], ptr, len);
		ptr[len-1] = ' ';
		ptr += len;
	}


	/*
	 * write the request to the server
	 */
	write(cli_sock, buf, total_len);

	/*
	 * read the response
	 */
	while ((rc = read(cli_sock, buf, total_len)) > 0) {
		exitrc = buf[rc-1];
		buf[rc] = '\0';
		printf("%s", buf);
	}
	if (exitrc != 0)
		printf("\b");

	free(buf);
	close(cli_sock);

	exit((int)exitrc);
}


/*
 * connect to ba_server socket allowing for retries
 */
int
init_ba_client(void)
{
	int			rc;
	int			retry = 10;
	struct sockaddr_un 	cli_sun;

	if ( (cli_sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0 ) {
		perror("socket");
		return -1;
	}

	bzero(&cli_sun, sizeof(cli_sun));
	cli_sun.sun_family = AF_UNIX;
	snprintf(cli_sun.sun_path, sizeof(cli_sun.sun_path), 
			"%s.%s", BA_PATH_NAME, devname);

	rc = connect(cli_sock, (struct sockaddr *)&cli_sun, sizeof(cli_sun));
	if (rc == 0)
		return rc;

	while ( (rc != 0) && (retry-- > 0) ) {
		sleep(1);
		rc = connect(cli_sock, (struct sockaddr *)&cli_sun,
					sizeof(cli_sun));
	}

	if (rc != 0) {
		printf("Can't connect to Bypass Adapter Server.\n");
		printf("Please check that the ba_server process is running.\n");
		close(cli_sock);
	}

	return rc;
}
