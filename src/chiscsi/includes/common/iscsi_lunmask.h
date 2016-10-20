#ifdef __ACL_LM__

#ifndef __ISCSI_LUNMASK_H__
#define __ISCSI_LUNMASK_H__

int lm_config_parse(unsigned char *rmask, unsigned char *wmask, int lunmax,
			char *buf, char *ebuf);
int lm_config_display(unsigned char *rmask, unsigned char *wmask, int lunmax,
			char *buf, int buflen);
int lm_lun_readable(unsigned char *rmask, unsigned char *wmask, int lun);
int lm_lun_writable(unsigned char *rmask, unsigned char *wmask, int lun);
int lm_make_lun_list(unsigned char *rmask, unsigned int *lun_list, int lunmax);

#endif

#endif /* ifdef __ACL_LM__ */
