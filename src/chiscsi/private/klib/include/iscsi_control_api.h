#ifndef __ISCSI_CONTROL_API_H__
#define __ISCSI_CONTROL_API_H__

/*
 * for iscsi control
 */

#include <common/os_builtin.h>
#include <common/iscsi_control.h>
#include <iscsi_control_defs.h>

/*
 * driver control values <-> strings	
 */

/* offload mode */
static inline char *iscsi_offload_mode_val2str(unsigned int mode)
{
	switch (mode) {
		case ISCSI_OFFLOAD_MODE_AUTO:
			return "AUTO";
		case ISCSI_OFFLOAD_MODE_TOE:
			return "TOE";
		case ISCSI_OFFLOAD_MODE_CRC:
			return "CRC";
		case ISCSI_OFFLOAD_MODE_DDP:
			return "DDP";
		case ISCSI_OFFLOAD_MODE_ULP:
			return "ULP";
	}
	return "UNKNOWN";
}

static inline int iscsi_offload_mode_str2val(char *str)
{
	if (!os_strcmp(str, "AUTO"))
		return ISCSI_OFFLOAD_MODE_AUTO;
#if 0
	if (!os_strcmp(str, "TOE"))
		return ISCSI_OFFLOAD_MODE_TOE;
#endif
	if (!os_strcmp(str, "ULP"))
		return ISCSI_OFFLOAD_MODE_ULP;
	if (!os_strcmp(str, "CRC"))
		return ISCSI_OFFLOAD_MODE_CRC;
	return -ISCSI_EINVAL;
}

/* target worker distribution policy */
static inline char *iscsi_worker_policy_val2str(unsigned int order)
{
	switch (order) {
		case ISCSI_WORKER_POLICY_QSET:
			return "QSET";
		case ISCSI_WORKER_POLICY_RR:
			return "RR";
	}
	return "UNKNOWN";
}

static inline int iscsi_worker_policy_str2val(char *str)
{
	if (!os_strcmp(str, "QSET"))
		return ISCSI_WORKER_POLICY_QSET;
	if (!os_strcmp(str, "RR"))
		return ISCSI_WORKER_POLICY_RR;
	return -ISCSI_EINVAL;
}

/* target authentication order */
static inline char *iscsi_auth_order_val2str(unsigned int order)
{
	switch (order) {
		case ISCSI_AUTH_ORDER_ACL_FIRST:
			return "ACL";
		case ISCSI_AUTH_ORDER_CHAP_FIRST:
			return "CHAP";
	}
	return "UNKNOWN";
}

static inline int iscsi_auth_order_str2val(char *str)
{
	if (!os_strcmp(str, "ACL"))
		return ISCSI_AUTH_ORDER_ACL_FIRST;
	if (!os_strcmp(str, "CHAP"))
		return ISCSI_AUTH_ORDER_CHAP_FIRST;
	return -ISCSI_EINVAL;
}

/*target acl configuration order */
static inline char *iscsi_acl_order_val2str(unsigned int order)
{
        switch (order) {
                case ISCSI_ACL_ORDER_CONFIG_FIRST:
                        return "CONFIG";
                case ISCSI_ACL_ORDER_ISNS_FIRST:
                        return "ISNS";
        }
        return "UNKNOWN";
}

static inline int iscsi_acl_order_str2val(char *str)
{
        if (!os_strcmp(str, "CONFIG"))
                return ISCSI_ACL_ORDER_CONFIG_FIRST;
        if (!os_strcmp(str, "ISNS"))
                return ISCSI_ACL_ORDER_ISNS_FIRST;
        return -ISCSI_EINVAL;
}

static inline char *iscsi_disc_auth_val2str(unsigned int auth)
{
        switch (auth) {
		case ISCSI_DISC_AUTH_METHOD_NONE:
			return "None";
		case ISCSI_DISC_AUTH_METHOD_CHAP:
			return "CHAP";
	}
        return "UNKNOWN";
}

static inline int iscsi_disc_auth_str2val(char *str)
{
	if (!os_strcmp(str, "None"))
		return ISCSI_DISC_AUTH_METHOD_NONE;

	if (!os_strcmp(str, "CHAP"))
		return ISCSI_DISC_AUTH_METHOD_CHAP;

	return -ISCSI_EINVAL;
}

static inline char *iscsi_disc_auth_policy_val2str(unsigned int policy)
{
        switch (policy) {
		case ISCSI_DISC_AUTH_POLICY_ONEWAY:
			return "Oneway";
		case ISCSI_DISC_AUTH_POLICY_MUTUAL:
			return "Mutual";
	}
	return "UNKNOWN";
}

static inline int iscsi_disc_auth_policy_str2val(char *str)
{
	if (!os_strcmp(str, "Oneway"))
		return ISCSI_DISC_AUTH_POLICY_ONEWAY;

	if (!os_strcmp(str, "Mutual"))
		return ISCSI_DISC_AUTH_POLICY_MUTUAL;

	return -ISCSI_EINVAL;
}

static inline char *iscsi_onoff_val2str(unsigned char val)
{
	switch (val) {
		case 0:
			return "OFF";
		case 1:
			return "ON";
	}
	return "UNKNOWN";
}

static inline int iscsi_onoff_str2val(char *str)
{
	if (!os_strcmp(str, "ON"))
		return 1;
	if (!os_strcmp(str, "OFF"))
		return 0;
	return -ISCSI_EINVAL;
}

static inline char *iscsi_boolean_val2str(unsigned char val)
{
	switch (val) {
		case 0:
			return "No";
		case 1:
			return "Yes";
	}
	return "UNKNOWN";
}

static inline int iscsi_boolean_str2val(char *str)
{
	os_str2lower(str);
	if (!os_strcmp(str, "yes"))
		return 1;
	if (!os_strcmp(str, "no"))
		return 0;
	return -ISCSI_EINVAL;
}
int     iscsi_control_init(void);
void    iscsi_control_cleanup(void);
int     iscsi_control_process_request(int, char *, char *, int, char *, int, unsigned int);

#endif /* ifndef __ISCSI_CONTROL_API_H__ */
