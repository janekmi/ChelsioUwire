#ifndef __CHISCSI_BASE_EXPORT_H__
#define __CHISCSI_BASE_EXPORT_H__

void offload_device_delete(offload_device *);
offload_device * offload_device_find_by_tdev(void *);
offload_device * offload_device_find_by_ndev(void *);
offload_device * offload_device_new_by_tdev(void *);
offload_device * offload_device_new_by_ndev(void *);

#endif /* __CHISCSI_BASE_EXPORT_H__ */
