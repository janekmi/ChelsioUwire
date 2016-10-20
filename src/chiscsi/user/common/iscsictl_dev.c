/*
 * This implementations is Linux specific.
 * iscsi uses ioctl via a character device to communicate between user
 * and kernel space.
 *
 * This file contains character device functions that can be shared by 
 * the user space cli programs.
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include "../../includes/common/iscsi_control.h"

int iscsictl_open_device(void)
{
#define LINE_BUFFER_LENGTH	512
	FILE   *hndl;
	char    buffer[LINE_BUFFER_LENGTH];
	char    name[256];
	int     major;
	int     found = 0;
	int     rv;

	/* find the major number */
	hndl = fopen("/proc/devices", "r");
	if (!hndl) {
		fprintf(stderr,
			"ERR! Unable to open device file /proc/devices.\n");
		return -1;
	}

	while (fgets(buffer, LINE_BUFFER_LENGTH, hndl)) {
		/* <number><space><device name> */
		if (sscanf(buffer, "%d %s", &major, name) == 2) {
			if (!strcmp(name, ISCSI_CONTROL_DEVICE_NAME)) {
				found = 1;
				break;
			}
		}
	}

	fclose(hndl);

	if (!found) {
		fprintf(stderr, "ERR! Unable to find %s, is module loaded?\n",
			ISCSI_CONTROL_DEVICE_NAME);
		return -1;
	}

	/* do mknod */
	unlink(ISCSI_CONTROL_DEVICE);
	if (mknod(ISCSI_CONTROL_DEVICE, (S_IFCHR | 0644), (major << 8))) {
		fprintf(stderr, "ERR! Unable to create %s.\n",
			ISCSI_CONTROL_DEVICE);
		perror(ISCSI_CONTROL_DEVICE);
		return -1;
	}

	rv = open(ISCSI_CONTROL_DEVICE, 0);
	if (rv < 0) {
		fprintf(stderr, "ERR! Unable to open %s.\n",
			ISCSI_CONTROL_DEVICE);
		perror(ISCSI_CONTROL_DEVICE);
		return -1;
	}

	return rv;
}

void iscsictl_close_device(int fd)
{
	if (fd >= 0)
		close(fd);
}

int iscsictl_send_control_cmd(int fd, int cmd, void *arg)
{
	return (ioctl(fd, cmd, arg));
}
