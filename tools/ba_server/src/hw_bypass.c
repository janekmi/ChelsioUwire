#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/queue.h>
#include <net/ethernet.h>

#include "cxgbtool.h"
#include "ba_server.h"
#include "t4_switch.h"
#include "hw_bypass.h"

int
hw_write_sys(char * syspath, void * val, int len) 
{
	int		fd;
	int		rc = 0;

	fd = open(syspath, O_RDWR);
	if (fd == -1) {
		return ENOENT;
	}

	rc = write(fd, val, len);
	if (rc != len) {
		close(fd);
		return errno;
	}

	close(fd);

	return 0;
}

int
hw_read_sys(char * syspath, char * buf, int len) 
{
	int		fd;
	int		rc = 0;

	fd = open(syspath, O_RDWR);
	if (fd == -1) {
		return ENOENT;
	}

	rc = read(fd, buf, len);
	if (rc == -1) {
		close(fd);
		return errno;
	}

	close(fd);

	return 0;
}

int
hw_set_bypass_state(int which, int state)
{
	int		rc = 0;
	char		syspath[128];
	char		*mode_type;
	char		*mode_which;

	switch (state) {
		case BA_STATE_BYPASS:
			mode_type = BA_HW_MODE_BYPASS;
			break;
		case BA_STATE_DISCONNECT:
			mode_type = BA_HW_MODE_DROP;
			break;
		case BA_STATE_NORMAL:
			mode_type = BA_HW_MODE_NORMAL;
			break;
		default:
			printf("unknown mode\n");
			return -1;
			break;
	}

	switch (which) {
		case CURRENT_STATE:
			mode_which = BA_CURRENT_MODE_PATH;
			break;
		case DEFAULT_STATE:
			mode_which = BA_DEFAULT_MODE_PATH;
			break;
		default:
			printf("unknown type of mode\n");
			return -1;
			break;
	}

	snprintf(syspath, sizeof(syspath), "%s/%s/%s", BA_BASE_PATH, 
		 devname, mode_which);

	rc = hw_write_sys(syspath, (void *)mode_type, strlen(mode_type));

	return rc;
}

int
hw_get_bypass_state(int which)
{
	int		rc = 0;
	char		syspath[128];
	char		mode_type[128];
	char		*mode_which;

	switch (which) {
		case CURRENT_STATE:
			mode_which = BA_CURRENT_MODE_PATH;
			break;
		case DEFAULT_STATE:
			mode_which = BA_DEFAULT_MODE_PATH;
			break;
		default:
			printf("unknown type of mode\n");
			return -1;
			break;
	}

	snprintf(syspath, sizeof(syspath), "%s/%s/%s", BA_BASE_PATH, 
		 devname, mode_which);

	rc = hw_read_sys(syspath, mode_type, sizeof(mode_type));
	if (rc != 0)
		return rc;

	if (strncmp(mode_type, BA_HW_MODE_BYPASS, strlen(BA_HW_MODE_BYPASS)) == 0)
		printf("bypass\n");
	else if (strncmp(mode_type, BA_HW_MODE_DROP, strlen(BA_HW_MODE_DROP)) == 0)
		printf("disconnect\n");
	else if (strncmp(mode_type, BA_HW_MODE_NORMAL, strlen(BA_HW_MODE_NORMAL)) == 0)
		printf("normal\n");
	else {
		printf("invalid bypass state (%s)\n", mode_type);
		return -1;
	}

	return rc;
}

int
hw_ping_bypass(void)
{
	int		rc = 0;
	char		syspath[128];
	int		val = 1;

	snprintf(syspath, sizeof(syspath), "%s/%s/%s", BA_BASE_PATH, 
		 devname, BA_PING_PATH);

	rc = hw_write_sys(syspath, (void *)&val, sizeof(val));

	return rc;
}

int
hw_lock_bypass(void)
{
	int		rc = 0;
	char		syspath[128];
	int		val = 1;

	snprintf(syspath, sizeof(syspath), "%s/%s/%s", BA_BASE_PATH, 
		 devname, BA_LOCK_PATH);

	rc = hw_write_sys(syspath, (void *)&val, sizeof(val));

	return rc;
}

int
hw_set_watchdog_state(int state)
{
	int		rc = 0;
	char		syspath[128];
	int		val;
	char		tmo[32];

	switch (state) {
		case BA_WATCHDOG_STATE_ENABLED:
			val = ba_watchdog_timeout;
			if (val == -1) {
				printf("failed to enable watchdog\n");
				return val;
			}
			if (val == 0) {
				printf("timeout must be set before"
					" enabling watchdog\n");
				return -1;
			}
			break;
		case BA_WATCHDOG_STATE_DISABLED:
			val = 0;
			break;
		default:
			printf("unknown watchdog state\n");
			return -1;
			break;
	}

	snprintf(syspath, sizeof(syspath), "%s/%s/%s", BA_BASE_PATH, 
		 devname, BA_WATCHDOG_PATH);

	snprintf(tmo, sizeof(tmo), "%d", val);

	rc = hw_write_sys(syspath, (void *)tmo, strlen(tmo));

	return rc;
}

int
hw_get_watchdog_timeout(void)
{
	int		rc = 0;
	char		syspath[128];
	char		tmo[32];

	snprintf(syspath, sizeof(syspath), "%s/%s/%s", BA_BASE_PATH, 
		 devname, BA_WATCHDOG_PATH);

	rc = hw_read_sys(syspath, (void *)tmo, sizeof(tmo));
	if (rc == 0)
		rc = atoi(tmo);
	else 
		rc = -1;

	return rc;
}

int
hw_set_watchdog_timeout(char * tmo)
{
	int		rc = 0;
	char		syspath[128];

	snprintf(syspath, sizeof(syspath), "%s/%s/%s", BA_BASE_PATH, 
		 devname, BA_WATCHDOG_PATH);

	rc = hw_write_sys(syspath, (void *)tmo, strlen(tmo));
	if (rc != 0)
		rc = errno;

	return rc;
}

