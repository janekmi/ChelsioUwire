#ifndef __ISCSI_CHAP_H__
#define __ISCSI_CHAP_H__

#define CHAP_NAME_LEN_MIN	1
#define CHAP_NAME_LEN_MAX	256
#define CHAP_SECRET_LEN_MIN	12
#define CHAP_SECRET_LEN_MAX	16

typedef struct chap_info	chap_info;

#define CHAP_FLAG_LOCAL_NAME_VALID	0x1
#define CHAP_FLAG_LOCAL_SECRET_VALID	0x2
#define CHAP_FLAG_REMOTE_NAME_VALID	0x4
#define CHAP_FLAG_REMOTE_SECRET_VALID	0x8
#define CHAP_FLAG_MUTUAL_REQUIRED	0x10

struct chap_info {
	unsigned char 	flag;
	unsigned char 	local_secret_length;
	unsigned char 	remote_secret_length;
	unsigned char	filler;

	char	local_name[CHAP_NAME_LEN_MAX];
	char	local_secret[CHAP_SECRET_LEN_MAX];
	char	remote_name[CHAP_NAME_LEN_MAX];
	char	remote_secret[CHAP_SECRET_LEN_MAX];
};

#endif
