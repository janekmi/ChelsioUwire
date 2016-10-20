/* Kthread.h */

enum th_flag_bits {
	KTHREAD_WAKEUP,
	KTHREAD_EXIT,
};

typedef struct kthread_info_struct kthread_info_struct;
struct kthread_info_struct {
	char name[32];
        unsigned long t_flag;
	unsigned long timeout;
	int id;

        wait_queue_head_t t_waitq; 			/*q thread is waiting on */
        struct task_struct *t_task;
	chiscsi_queue *th_scq;
	void (*fproc)(void *); 			/*Func to be launched as thread*/
	void *farg;
};

void init_and_run_storage_thread(int);
void run_storage_thread(void *, void *, int);
int stop_storage_thread(void *);
void pass_scmd_to_storage_thread(void *);

