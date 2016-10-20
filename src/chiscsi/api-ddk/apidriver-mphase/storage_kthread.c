#include <linux/version.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/errno.h>
#include <linux/kthread.h>
#include <asm/atomic.h>

#include "iface.h"
#include "storage_kthread.h"

unsigned int marked_q_cnt = 0;

/*Alloc kthread info struct */
kthread_info_struct *alloc_kthread(void)
{
	kthread_info_struct *kthinfo;
	
	kthinfo = kmalloc(sizeof(kthread_info_struct), GFP_KERNEL);
	if (!kthinfo)
                return NULL;	
	memset(kthinfo, 0, sizeof(kthread_info_struct));
	
	return kthinfo;
}

/*Alloc kthread info struct */
void free_kthread(kthread_info_struct *kthinfo) 
{
	kfree(kthinfo);
}


/*Wakeup the thread */
void wakeup_storage_thread(kthread_info_struct *kthinfo)
{
        if (kthinfo) {
                set_bit(KTHREAD_WAKEUP, &kthinfo->t_flag);
                wake_up(&kthinfo->t_waitq);
        }
}

/* Hand over scmd to the storage thread */
void pass_scmd_to_storage_thread(void *sc)
{
	chiscsi_scsi_command *s  = sc;
	kthread_info_struct *kthinfo;
	chiscsi_queue *q;
	iface_scmd_info *scmd_info;

	if (!sc) {
		printk("sc NULL, No command execution\n");
		return;
	}

	kthinfo = lun[s->sc_lun].kthinfo;
	q = lun[s->sc_lun].scinfoq[0];

	spin_lock((spinlock_t *)q->q_lock);
	scmd_info_qsearch_by_sc(nolock, q, scmd_info, s);
	if(!scmd_info) {
		spin_unlock((spinlock_t *)q->q_lock);
		return;
	}
	scmd_info->flag = MARK_FOR_WORK;
	spin_unlock((spinlock_t *)q->q_lock);

	wakeup_storage_thread(kthinfo);
	return;
}

/* send marked scmd to execute work */
void storage_thread_proc(void *arg)
{
	kthread_info_struct *kthinfo = arg;
	chiscsi_queue *q = lun[kthinfo->id].scinfoq[0];
	iface_scmd_info *scmd_info = NULL; 

	/*traverse the q to find all scmds marked for work*/
	spin_lock((spinlock_t *)q->q_lock);	
	scmd_info = q->q_head;
	while (scmd_info) {
		if (scmd_info->flag == MARK_FOR_WORK) {
			scmd_info->flag = MARK_DO_WORK;
		}
		scmd_info = scmd_info->snext;
	}
	spin_unlock((spinlock_t *)q->q_lock);


	scmd_info = q->q_head;	
        while (scmd_info) {
		if (scmd_info->flag == MARK_DO_WORK) {
			scmd_info->flag = 0;
                	if (!scmd_test_bit(scmd_info->sc, CH_SFSCSI_FORCE_RELEASE_BIT))
                        	lun[scmd_info->sc->sc_lun].lclass->fp_queued_scsi_cmd_exe(scmd_info->sc);
		}
		scmd_info = scmd_info->snext;
	}
}


/* Condition to schedule the thread */
int storage_thread_has_work(kthread_info_struct *kthinfo)
{
	/*Thread id corresponds to lun num*/
	chiscsi_queue *q = lun[kthinfo->id].scinfoq[0];
	iface_scmd_info *scmd_info;
	int i = 0;
	
	spin_lock((spinlock_t *)q->q_lock);	
	/*go thru the q to see if there are still scmd to be processed*/
	scmd_info = q->q_head;
	while (scmd_info) {
		if (scmd_info->flag == MARK_FOR_WORK)
			i++;
		scmd_info = scmd_info->snext;
	}
	spin_unlock((spinlock_t *)q->q_lock);
	
	/*if more scmd_info in q means more work  
	 else no work*/
	if (i > 0)
		return 1;
	else 	
		return 0;
	
}

void  storage_thread_work_function(void *arg) {
	
	kthread_info_struct *kthinfo = (kthread_info_struct *)arg;

	DECLARE_WAITQUEUE(wait, current);
	allow_signal(SIGKILL);
	disallow_signal(SIGPIPE);

	add_wait_queue(&kthinfo->t_waitq, &wait);
	__set_current_state(TASK_RUNNING);
        do {
		/*Proc executing the threads work*/
		kthinfo->fproc(kthinfo);
		
                __set_current_state(TASK_INTERRUPTIBLE);
		
		/*Schedule if there is no more work to do*/
                if (!(storage_thread_has_work(kthinfo))) {
			//printk("%s, goes to sleep \n", kthinfo->name);
                        schedule();
                }

		//printk("thread woken up \n");

		/* wakeup call has set the flag, clear it */
		clear_bit(KTHREAD_WAKEUP, &kthinfo->t_flag);
                __set_current_state(TASK_RUNNING);

	} while (!kthread_should_stop());

	remove_wait_queue(&kthinfo->t_waitq, &wait);
	clear_bit(KTHREAD_WAKEUP, &kthinfo->t_flag);
}


/*************************************
 * Thread initiation and creation code 
 *************************************/

static int create_storage_thread( void *arg, void *func, int id) 
{
	kthread_info_struct *kthinfo = (kthread_info_struct *)arg;
	char *name = "iface_th";


	if (kthinfo->t_task) {
                printk("kthread %s task already running?\n", kthinfo->name);
                return -1;
        }
	
	init_waitqueue_head(&kthinfo->t_waitq);
	kthinfo->fproc = storage_thread_proc;
	kthinfo->timeout = MAX_SCHEDULE_TIMEOUT;
	kthinfo->id = id;
	kthinfo->th_scq = lun[id].scinfoq[0];
	sprintf(kthinfo->name, "%s%d", name, id);

	kthinfo->t_task = kthread_create((void *)func, kthinfo, "%s", kthinfo->name);
	if (IS_ERR(kthinfo->t_task)) {
                printk("kthread %s, create task 0x%lx\n", kthinfo->name, IS_ERR(kthinfo->t_task));
		free_kthread(kthinfo);
                return -1;
        }

	return 0;
}

/* wake_up_process*/
static int start_storage_thread(void *arg) 
{
	kthread_info_struct *kthinfo = arg;

	if (!kthinfo->t_task) {
		printk("Kthread %s already stopped\n", kthinfo->name); 
		return -1;
	}

	/*wake_up_process starts the created thread*/
	wake_up_process(kthinfo->t_task);

	return 0;
}

/*create and start */
void run_storage_thread(void *arg, void *func, int id) 
{
	kthread_info_struct *kthinfo = arg;
	int rv = 0;

	rv = create_storage_thread(kthinfo, func, id);
	if (rv < 0) {
		printk("ERR! Cant create kthread %d\n", rv);
	}

	rv = start_storage_thread(kthinfo);
	if (rv < 0) {
		printk("ERR! Cant start kthread %d\n", rv);
	}

}

/* Stop the thread */
int stop_storage_thread(void *arg) 
{
	kthread_info_struct *kthinfo = arg;
	int rv; 
	
	if (!kthinfo->t_task) {
		printk("Kthread %s already stopped\n", kthinfo->name); 
		return 0;
	}

	rv = kthread_stop(kthinfo->t_task);
	if (rv < 0) {
		printk("Kthread %s already stopped\n", kthinfo->name); 
		return -1;

	}

	kthinfo->t_task = NULL;
	free_kthread(kthinfo);
	return 0;
}

/*Initiate the kthread sleep until awakened */
void init_and_run_storage_thread(int num)
{
	kthread_info_struct *kthinfo;
	int i;

	for (i = 0; i < num; i ++) {
		kthinfo = alloc_kthread();
		memset(kthinfo, 0, sizeof(kthread_info_struct));
		lun[i].kthinfo = kthinfo;

		run_storage_thread(kthinfo, &storage_thread_work_function, i);
	}
}

