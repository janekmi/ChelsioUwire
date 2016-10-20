#include <stddef.h>
#include <errno.h>
#include "kernelcom.h"
#include "sysfns.h"

int wdtoe_cmd_create_dev(int fd, struct wdtoe_create_dev *cmd,
			 size_t cmd_size,
			 struct wdtoe_create_dev_resp *resp,
			 size_t resp_size)
{
	WDTOE_BUILD_CMD(cmd, cmd_size, CREATE_DEV, resp, resp_size);

	if (sys_write(fd, cmd, cmd_size) != sizeof(*cmd))
		return errno;

	return 0;
}

int wdtoe_cmd_create_rxq(int fd, struct wdtoe_create_rxq *cmd,
			 size_t cmd_size,
			 struct wdtoe_create_rxq_resp *resp,
			 size_t resp_size, int tx_hold_thres)
{
	WDTOE_BUILD_CMD(cmd, cmd_size, CREATE_RXQ, resp, resp_size);

	cmd->tx_hold_thres = tx_hold_thres;

	if (sys_write(fd, cmd, cmd_size) != sizeof(*cmd))
		return errno;

	return 0;
}

int wdtoe_cmd_copy_rxq(int fd, struct wdtoe_copy_rxq *cmd,
		       size_t cmd_size,
		       struct wdtoe_copy_rxq_resp *resp,
		       size_t resp_size)
{
	WDTOE_BUILD_CMD(cmd, cmd_size, COPY_RXQ, resp, resp_size);

	if (sys_write(fd, cmd, cmd_size) != sizeof(*cmd))
		return errno;

	return 0;
}

int wdtoe_cmd_copy_txq(int fd, struct wdtoe_copy_txq *cmd,
		       size_t cmd_size,
		       struct wdtoe_copy_txq_resp *resp,
		       size_t resp_size)
{
	WDTOE_BUILD_CMD(cmd, cmd_size, COPY_TXQ, resp, resp_size);

	if (sys_write(fd, cmd, cmd_size) != sizeof(*cmd))
		return errno;

	return 0;
}

int wdtoe_cmd_create_mempool(int fd, struct wdtoe_create_mempool *cmd,
			     size_t cmd_size,
			     struct wdtoe_create_mempool_resp *resp,
			     size_t resp_size)
{
	WDTOE_BUILD_CMD(cmd, cmd_size, CREATE_MEMPOOL, resp, resp_size);

	if (sys_write(fd, cmd, cmd_size) != sizeof(*cmd))
		return errno;

	return 0;
}

int wdtoe_cmd_register_stack(int fd, struct wdtoe_reg_stack *cmd,
			     size_t cmd_size,
			     struct wdtoe_reg_stack_resp *resp,
			     size_t resp_size)
{
	WDTOE_BUILD_CMD(cmd, cmd_size, REG_STACK, resp, resp_size);

	if (sys_write(fd, cmd, cmd_size) != sizeof(*cmd))
		return errno;

	return 0;
}

int wdtoe_cmd_update_rx_credits(int fd, struct wdtoe_update_rx_credits *cmd,
				size_t cmd_size,
				struct wdtoe_update_rx_credits *resp,
				size_t resp_size)
{
	WDTOE_BUILD_CMD(cmd, cmd_size, UPDATE_RX_CREDITS, resp, resp_size);

	if (sys_write(fd, cmd, cmd_size) != sizeof(*cmd))
		return errno;

	return 0;
}

int wdtoe_cmd_send_tx_flowc(int fd, struct wdtoe_send_tx_flowc *cmd,
			    size_t cmd_size,
			    struct wdtoe_send_tx_flowc_resp *resp,
			    size_t resp_size)
{
	WDTOE_BUILD_CMD(cmd, cmd_size, SEND_FLOWC, resp, resp_size);

	if (sys_write(fd, cmd, cmd_size) != sizeof(*cmd))
		return errno;

	return 0;
}

int get_kernel_passive_tuples(int fd, struct wdtoe_get_passive_tuples *cmd,
			      size_t cmd_size, struct passive_tuple *resp,
			      size_t resp_size)
{
	WDTOE_BUILD_CMD(cmd, cmd_size, PASS_TUPLES, resp, resp_size);

	if (sys_write(fd, cmd, cmd_size) != sizeof(*cmd))
		return errno;

	return 0;
}

int get_kernel_conn_tuples(int fd, struct wdtoe_get_conn_tuples *cmd,
			   size_t cmd_size, struct conn_tuple *resp,
			   size_t resp_size)
{
	WDTOE_BUILD_CMD(cmd, cmd_size, CONN_TUPLES, resp, resp_size);

	if (sys_write(fd, cmd, cmd_size) != sizeof(*cmd))
		return errno;

	return 0;
}

int wdtoe_cmd_pass_cpl_to_tom(int fd, struct wdtoe_cpl_act_establish *cmd,
			      size_t cmd_size,
			      struct wdtoe_cpl_act_establish_resp *resp,
			      size_t resp_size)
{
	WDTOE_BUILD_CMD(cmd, cmd_size, CPL_TO_TOM, &resp, resp_size);

	if (sys_write(fd, cmd, cmd_size) != sizeof (*cmd))
		return errno;

	return 0;
}

int wdtoe_cmd_get_port_num(int fd, struct wdtoe_get_port_num *cmd,
			   size_t cmd_size,
			   struct wdtoe_get_port_num_resp *resp,
			   size_t resp_size)
{
	WDTOE_BUILD_CMD(cmd, cmd_size, GET_PORT_NUM, resp, resp_size);

	if (sys_write(fd, cmd, cmd_size) != sizeof(*cmd))
		return errno;

	return 0;
}

int wdtoe_cmd_reg_listen(int fd, struct wdtoe_reg_listen *cmd,
			 size_t cmd_size,
			 struct wdtoe_reg_listen_resp *resp,
			 size_t resp_size)
{
	WDTOE_BUILD_CMD(cmd, cmd_size, REG_LISTEN, resp, resp_size);

	if (sys_write(fd, cmd, cmd_size) != sizeof (*cmd))
		return errno;

	return 0;
}

int wdtoe_cmd_remove_listen(int fd, struct wdtoe_remove_listen *cmd,
			    size_t cmd_size,
			    struct wdtoe_remove_listen_resp *resp,
			    size_t resp_size)
{
	WDTOE_BUILD_CMD(cmd, cmd_size, REMOVE_LISTEN, resp, resp_size);

	if (sys_write(fd, cmd, cmd_size) != sizeof (*cmd))
		return errno;

	return 0;
}
