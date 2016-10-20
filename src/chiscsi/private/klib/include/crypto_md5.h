#ifndef __CRYPTO_MD5_H__
#define __CRYPTO_MD5_H__

typedef struct crypto_md5_context crypto_md5_context;

struct crypto_md5_context {
	unsigned int length[2];	/* support 64bit length */
	unsigned int hash[4];
	unsigned char buffer[64];
};

void    crypto_md5_init(crypto_md5_context *);
void    crypto_md5_update(crypto_md5_context *, unsigned char *, unsigned int);
void    crypto_md5_finish(crypto_md5_context *, unsigned char *);

#endif /* ifndef __CRYPTO_MD5_H__ */
