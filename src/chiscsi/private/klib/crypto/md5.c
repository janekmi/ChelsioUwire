/*
 * md5.c -- the md5 functions are based on the public domain code 
 * 	written by Colin Plumb in 1993. 
 */

#include <common/os_builtin.h>
#include <crypto_md5.h>

static void crypto_md5_transform(unsigned int *, unsigned int *);

/*
 * Note: this code is harmless on little-endian machines.
 */
static inline void reverse_byte(unsigned char *buf, unsigned int len)
{
	unsigned int val;
	do {
		val = (unsigned int) ((unsigned) buf[3] << 8 | buf[2]) << 16 |
			((unsigned) buf[1] << 8 | buf[0]);
		*(unsigned int *) buf = val;
		buf += 4;
	} while (--len);
}

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
void crypto_md5_init(crypto_md5_context * mctx)
{
	memset(mctx, 0, sizeof(crypto_md5_context));

	mctx->hash[0] = 0x67452301;
	mctx->hash[1] = 0xefcdab89;
	mctx->hash[2] = 0x98badcfe;
	mctx->hash[3] = 0x10325476;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
void crypto_md5_update(crypto_md5_context * mctx, unsigned char *data,
		       unsigned len)
{
	unsigned int l;

	/* Update length */
	l = mctx->length[0];
	mctx->length[0] = l + ((unsigned int) len << 3);
	if (mctx->length[0] < l)
		mctx->length[1]++;
	mctx->length[1] += len >> 29;

	l = (l >> 3) & 0x3F;

	/* Handle any leading odd-sized chunks */
	if (l) {
		unsigned char *dp = mctx->buffer + l;

		l = 64 - l;
		if (len < l) {
			memcpy(dp, data, len);
			return;
		}
		memcpy(dp, data, l);
		reverse_byte(mctx->buffer, 16);
		crypto_md5_transform(mctx->hash, (unsigned int *) mctx->buffer);
		data += l;
		len -= l;
	}
	/* Process data in 64-byte chunks */

	while (len >= 64) {
		memcpy(mctx->buffer, data, 64);
		reverse_byte(mctx->buffer, 16);
		crypto_md5_transform(mctx->hash, (unsigned int *) mctx->buffer);
		data += 64;
		len -= 64;
	}

	/* Handle any remaining bytes of data. */
	memcpy(mctx->buffer, data, len);
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern 
 * 1 0* (64-bit count of length processed, MSB-first)
 */
void crypto_md5_finish(crypto_md5_context * mctx, unsigned char *digest)
{
	unsigned int len;
	unsigned char *dp;

	/* compute number of bytes mod 64 */
	len = (mctx->length[0] >> 3) & 0x3F;

	/* set the first char of padding to 0x80.  This is safe since there is
	   always at least one byte free */
	dp = mctx->buffer + len;
	*dp++ = 0x80;

	/* bytes of padding needed to make 64 bytes */
	len = 63 - len;

	/* pad out to 56 mod 64 */
	if (len < 8) {
		/* pad the first block to 64 bytes */
		memset(dp, 0, len);
		reverse_byte(mctx->buffer, 16);
		crypto_md5_transform(mctx->hash, (unsigned int *) mctx->buffer);

		/* fill the next block with 56 bytes */
		memset(mctx->buffer, 0, 56);
	} else {
		/* pad block to 56 bytes */
		memset(dp, 0, len - 8);
	}
	reverse_byte(mctx->buffer, 14);

	/* Append length in length and transform */
	((unsigned int *) mctx->buffer)[14] = mctx->length[0];
	((unsigned int *) mctx->buffer)[15] = mctx->length[1];

	crypto_md5_transform(mctx->hash, (unsigned int *) mctx->buffer);
	reverse_byte((unsigned char *) mctx->hash, 4);
	memcpy(digest, mctx->hash, 16);
}

/* The four core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the md5 algorithm. */
#define MD5_STEP(f, w, x, y, z, data, s) \
	( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )

/*
 * The core of the md5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  blocks
 * the data and converts bytes into longwords for this routine.
 */
static void crypto_md5_transform(unsigned int *buf, unsigned int *in)
{
	unsigned int a, b, c, d;

	a = buf[0];
	b = buf[1];
	c = buf[2];
	d = buf[3];

	MD5_STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
	MD5_STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
	MD5_STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
	MD5_STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
	MD5_STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
	MD5_STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
	MD5_STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
	MD5_STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
	MD5_STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
	MD5_STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
	MD5_STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
	MD5_STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
	MD5_STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
	MD5_STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
	MD5_STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
	MD5_STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

	MD5_STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
	MD5_STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
	MD5_STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
	MD5_STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
	MD5_STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
	MD5_STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
	MD5_STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
	MD5_STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
	MD5_STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
	MD5_STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
	MD5_STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
	MD5_STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
	MD5_STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
	MD5_STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
	MD5_STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
	MD5_STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

	MD5_STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
	MD5_STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
	MD5_STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
	MD5_STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
	MD5_STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
	MD5_STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
	MD5_STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
	MD5_STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
	MD5_STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
	MD5_STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
	MD5_STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
	MD5_STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
	MD5_STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
	MD5_STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
	MD5_STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
	MD5_STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

	MD5_STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
	MD5_STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
	MD5_STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
	MD5_STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
	MD5_STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
	MD5_STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
	MD5_STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
	MD5_STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
	MD5_STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
	MD5_STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
	MD5_STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
	MD5_STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
	MD5_STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
	MD5_STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
	MD5_STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
	MD5_STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

	buf[0] += a;
	buf[1] += b;
	buf[2] += c;
	buf[3] += d;
}
