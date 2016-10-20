/*
 * iscsi_common.c -- entry point for iscsi library initialization and cleanup.
 */

#include <common/iscsi_common.h>
#include <common/iscsi_control.h>
#include <iscsi_target_api.h>

void    iscsi_heartbeat_stop(void);
int     iscsi_heartbeat_start(void);
void    iscsi_socket_cleanup(void);
int     iscsi_socket_init(void);
void    iscsi_control_cleanup(void);
int     iscsi_control_init(void);
void    iscsi_globals_cleanup(void);
int     iscsi_globals_init(int);

void iscsi_shutdown(void)
{
	iscsi_node_remove(NULL, 0, NULL, 0);
}

int iscsi_common_cleanup(void)
{
	iscsi_shutdown();
	iscsi_heartbeat_stop();
	iscsi_target_cleanup();
	iscsi_socket_cleanup();
	iscsi_control_cleanup();
	iscsi_globals_cleanup();
	return 0;
}

int iscsi_common_init(int cpus)
{
	int     rv;

	/* default to non-smp */
	if (!cpus)
		cpus = 1;

	rv = iscsi_globals_init(cpus);
	if (rv < 0)
		goto err_out;

	rv = iscsi_control_init();
	if (rv < 0)
		goto err_out;

	rv = iscsi_socket_init();
	if (rv < 0)
		goto err_out;

	rv = iscsi_target_init();
	if (rv < 0)
		goto err_out;

	rv = iscsi_heartbeat_start();
	if (rv < 0)
		goto err_out;

	return 0;

err_out:
	iscsi_common_cleanup();
	return rv;
}
