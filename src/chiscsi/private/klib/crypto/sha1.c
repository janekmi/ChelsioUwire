/*
 * sha1.c -- the sha1 secure hash algorithm
 */

#include <common/os_builtin.h>
#include <crypto_sha1.h>

static void sha1_transform(unsigned int *, unsigned char *, unsigned int *);

void crypto_sha1_init(crypto_sha1_context * sctx)
{
	memset(sctx, 0, sizeof(crypto_sha1_context));
	sctx->hash[0] = 0x67452301;
	sctx->hash[1] = 0xEFCDAB89;
	sctx->hash[2] = 0x98BADCFE;
	sctx->hash[3] = 0x10325476;
	sctx->hash[4] = 0xC3D2E1F0;
}

void crypto_sha1_update(crypto_sha1_context * sctx, unsigned char *data,
			unsigned int len)
{
	unsigned int i, j;
	unsigned int temp[80];

	/* Update length */
	j = (sctx->length >> 3) & 0x3f;
	sctx->length += len << 3;

	if ((j + len) > 63) {
		memcpy(&sctx->buffer[j], data, (i = 64 - j));
		sha1_transform(sctx->hash, sctx->buffer, temp);
		for (; i + 63 < len; i += 64) {
			sha1_transform(sctx->hash, &data[i], temp);
		}
		j = 0;
	} else
		i = 0;
	memset(temp, 0, sizeof(temp));
	memcpy(&sctx->buffer[j], &data[i], len - i);
}

/* Add padding and return the message hash. */
void crypto_sha1_finish(crypto_sha1_context * sctx, unsigned char *resp)
{
	unsigned int i, j, index, padlen;
	unsigned long long val = sctx->length;
	unsigned char byte[8];
	static unsigned char padding[64] = { 0x80, };

	for (i = 0; i < 8; i++, val >>= 8) {
		byte[7 - i] = (unsigned char) (val & 0xFF);
	}

	/* pad resp to 56 mod 64 */
	index = (sctx->length >> 3) & 0x3f;
	padlen = (index < 56) ? (56 - index) : ((64 + 56) - index);
	crypto_sha1_update(sctx, padding, padlen);

	/* append length */
	crypto_sha1_update(sctx, byte, 8);

	for (i = j = 0; i < 5; i++, j += 4) {
		int     k;
		unsigned int tmp = sctx->hash[i];
		for (k = j + 3; k >= j; k--, tmp >>= 8)
			resp[k] = (unsigned char) (tmp & 0xFF);
	}
}


/* shift must be between 0 ~ 32 */
#define CircularShiftLeft_32(word,shift) \
	(((word) << (shift)) | ((word) >> (32 - (shift))))

#define f1(x,y,z)	((z) ^ ((x) & ((y) ^ (z))))	/* x ? y : z */
#define f2(x,y,z)	((x) ^ (y) ^ (z))	/* xor */
#define f3(x,y,z)	(((x) & (y)) + ((z) & ((x) ^ (y))))	/* majority */

static void sha1_transform(unsigned int *digest, unsigned char *in,
			   unsigned int *buf)
{
	static unsigned int K[4] = {
		0x5A827999,
		0x6ED9EBA1,
		0x8F1BBCDC,
		0xCA62C1D6
	};

	unsigned int a, b, c, d, e, tmp;
	unsigned int i;
	unsigned int *in_u32 = (unsigned int *) in;

	a = digest[0];
	b = digest[1];
	c = digest[2];
	d = digest[3];
	e = digest[4];

	for (i = 0; i < 16; i++)
		buf[i] = os_ntohl(in_u32[i]);

	for (i = 16; i < 80; i++) {
		tmp = (buf[i - 3] ^ buf[i - 8] ^ buf[i - 14] ^ buf[i - 16]);
		buf[i] = CircularShiftLeft_32(tmp, 1);
	}

	for (i = 0; i < 20; i++) {
		tmp = f1(b, c, d) + K[0] + CircularShiftLeft_32(a,
								5) + e + buf[i];
		e = d;
		d = c;
		c = CircularShiftLeft_32(b, 30);
		b = a;
		a = tmp;
	}

	for (; i < 40; i++) {
		tmp = f2(b, c, d) + K[1] + CircularShiftLeft_32(a,
								5) + e + buf[i];
		e = d;
		d = c;
		c = CircularShiftLeft_32(b, 30);
		b = a;
		a = tmp;
	}
	for (; i < 60; i++) {
		tmp = f3(b, c, d) + K[2] + CircularShiftLeft_32(a,
								5) + e + buf[i];
		e = d;
		d = c;
		c = CircularShiftLeft_32(b, 30);
		b = a;
		a = tmp;
	}
	for (; i < 80; i++) {
		tmp = f2(b, c, d) + K[3] + CircularShiftLeft_32(a,
								5) + e + buf[i];
		e = d;
		d = c;
		c = CircularShiftLeft_32(b, 30);
		b = a;
		a = tmp;
	}

	digest[0] += a;
	digest[1] += b;
	digest[2] += c;
	digest[3] += d;
	digest[4] += e;
}
