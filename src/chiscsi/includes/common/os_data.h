/* duplicate enum, do not modify */
enum iscsi_portal_counters {
	RD_B_CTR=0,
	WR_B_CTR,
	RD_CMD_CTR,
	WR_CMD_CTR,
	MAX_PORTAL_STATS,
};

typedef struct os_kthread os_kthread;
struct os_kthread {
	unsigned long t_flag;
	wait_queue_head_t t_waitq_ack;
	wait_queue_head_t *t_waitq;
	struct task_struct *t_task;
	iscsi_thread_common *t_common;
};

typedef union _iscsi_priv_os_data {
	struct os_kthread       th_kinfo;
	atomic_t		stats[MAX_PORTAL_STATS];
} iscsi_priv_os_data;

typedef union _iscsi_counter {
	atomic_t	th_counter;
	atomic_t	n_counter_login;
	atomic_t	c_r2t_credit;
} iscsi_counter;

/* aggregate all common OS dependent vars into this struct */
typedef struct iscsi_os_lock {
	spinlock_t		splock;
	unsigned long		flag;
} iscsi_os_lock;

typedef struct iscsi_os_data iscsi_os_data;
struct iscsi_os_data {
	void			*parent;
	iscsi_os_lock		lock;
	atomic_t		counter;
	wait_queue_head_t	waitq;
	wait_queue_head_t	ackq;
	iscsi_priv_os_data	priv;
};
