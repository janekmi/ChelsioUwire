#ifndef __CRYPTO_SHA1_H__
#define __CRYPTO_SHA1_H__

typedef struct sha1_ctx crypto_sha1_context;
struct sha1_ctx {
	unsigned int length;
	unsigned int hash[5];
	unsigned char buffer[64];
};
void    crypto_sha1_init(crypto_sha1_context *);
void    crypto_sha1_update(crypto_sha1_context *, unsigned char *,
			   unsigned int);
void    crypto_sha1_finish(crypto_sha1_context *, unsigned char *);

#endif /* ifndef __CRYPTO_SHA1_H__ */
