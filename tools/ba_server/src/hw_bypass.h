#ifndef	__HW_BYPASS_H__
#define	__HW_BYPASS_H__

int	hw_ping_bypass(void);
int	hw_lock_bypass(void);
int	hw_set_bypass_state(int which, int state);
int	hw_set_watchdog_state(int state);
int	hw_set_watchdog_timeout(char * tmo);
int	hw_get_bypass_state(int which);
int	hw_get_watchdog_state(void);
int	hw_get_watchdog_timeout(void);

#define	BA_HW_MODE_NORMAL	"normal"
#define	BA_HW_MODE_BYPASS	"bypass"
#define	BA_HW_MODE_DROP		"drop"

#define	BA_BASE_PATH		"/sys/class/net"
#define	BA_DEFAULT_MODE_PATH	"bypass/failover_mode"
#define	BA_CURRENT_MODE_PATH	"bypass/current_mode"
#define	BA_WATCHDOG_PATH	"bypass/watchdog"
#define	BA_PING_PATH		"bypass/watchdog_ping"
#define	BA_LOCK_PATH		"bypass/watchdog_lock"

#endif	/* __HW_BYPASS_H__ */
