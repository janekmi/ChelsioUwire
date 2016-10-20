/*
 * Linux ioctl interface (via a character device)
 */

#include <linux/signal.h>
#include <asm/uaccess.h>
#ifdef CONFIG_COMPAT
#include <asm/compat.h>
#endif
#include <linux/blkdev.h>
#include <linux/time.h>
#include <common/iscsi_control.h>
#include <common/iscsi_lib_export.h>

static int iscsi_control_open(struct inode *inode, struct file *file)
{
	/* implement any access restrictions? */
	return 0;
}

static int iscsi_control_release(struct inode *inode, struct file *file)
{
	return 0;
}

#ifdef HAVE_UNLOCKED_IOCTL
struct mutex	iscsi_ioctl_mutex;
/* we no longer hold BKL if this is used */
static long iscsi_control_ioctl(struct file *file, unsigned int cmd,
                               unsigned long arg)
#else
static int iscsi_control_ioctl(struct inode *inode, struct file *file,
			       unsigned int cmd, unsigned long arg)
#endif
{
	struct timeval tm;
	int rv;

	do_gettimeofday(&tm);
#ifdef HAVE_UNLOCKED_IOCTL
	mutex_lock(&iscsi_ioctl_mutex);
#endif
	rv = iscsi_control_request
		(cmd, arg, (unsigned long) (tm.tv_sec / 3600));
#ifdef HAVE_UNLOCKED_IOCTL
	mutex_unlock(&iscsi_ioctl_mutex);
#endif
	return rv;
}

#ifndef CONFIG_COMPAT
typedef u32		compat_uptr_t;
/*
 * A pointer passed in from user mode. This should not
 * be used for syscall parameters, just declare them
 * as pointers because the syscall entry code will have
 * appropriately converted them already.
 */
static inline void __user *compat_ptr(compat_uptr_t uptr)
{
	return (void __user *)(unsigned long)uptr;
}
#endif

#ifdef HAVE_COMPAT_IOCTL
static long compat_iscsi_control_ioctl(struct file *file, unsigned int cmd,
					unsigned long arg)
{
	return iscsi_control_ioctl(file, cmd, (unsigned long)compat_ptr(arg));
}
#endif

/* the iSCSI control device's file operations */
static struct file_operations iscsi_control_fops = {
#ifdef HAVE_UNLOCKED_IOCTL
      unlocked_ioctl:iscsi_control_ioctl,
#else
      ioctl:iscsi_control_ioctl,
#endif
#ifdef HAVE_COMPAT_IOCTL
	compat_ioctl:compat_iscsi_control_ioctl,
#endif
      open:iscsi_control_open,
      release:iscsi_control_release,
};

int     ctldev_major = -1;
int iscsi_ioctl_init(void)
{
	/* register the the iSCSI control device */
	ctldev_major = register_chrdev(0, ISCSI_CONTROL_DEVICE_NAME,
				       &iscsi_control_fops);
	if (ctldev_major < 0) {
		os_log_error("register char dev %s, %d.\n",
			  ISCSI_CONTROL_DEVICE_NAME, ctldev_major);
		return -ISCSI_EFAIL;
	}
#ifdef HAVE_UNLOCKED_IOCTL
	mutex_init(&iscsi_ioctl_mutex);
#endif
	return 0;
}

void iscsi_ioctl_cleanup(void)
{
	if (ctldev_major >= 0) {
		/* unregister device */
		unregister_chrdev(ctldev_major, ISCSI_CONTROL_DEVICE);
		ctldev_major = -1;
	}
#ifdef HAVE_UNLOCKED_IOCTL
	mutex_destroy(&iscsi_ioctl_mutex);
#endif
}
