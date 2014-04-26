/*
* crypto_stream/try.c version 20090118
* D. J. Bernstein
* Public domain.
*/
#include <stddef.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#include "crypto_stream_chacha20.h"

unsigned char
*alignedcalloc (unsigned long long len)
{
	unsigned char *aligned;
	unsigned char *unaligned;
	size_t         i;

	if (SIZE_MAX - (size_t) 256U < len ||
			(unaligned = (unsigned char *) malloc(len + (size_t) 256U)) == NULL) {
		return NULL;
	}
#ifdef HAVE_ARC4RANDOM_BUF
	(void) i;
	arc4random_buf(unaligned, len + (size_t) 256U);
#else
	for (i = (size_t) 0U; i < len + (size_t) 256U; ++i) {
		unaligned[i] = (unsigned char) rand();
	}
#endif
	aligned = unaligned + 64;
	aligned += (ptrdiff_t) 63 & (-(ptrdiff_t) aligned);
	memset(aligned, 0, len);

	return aligned;
}

#define crypto_stream crypto_stream_chacha20
#define crypto_stream_xor crypto_stream_chacha20_xor
#define crypto_stream_KEYBYTES crypto_stream_chacha20_KEYBYTES
#define crypto_stream_NONCEBYTES crypto_stream_chacha20_NONCEBYTES


#define MAXTEST_BYTES 10000
#define CHECKSUM_BYTES 4096
#define TUNE_BYTES 1536

static unsigned char *k;
static unsigned char *n;
static unsigned char *m;
static unsigned char *c;
static unsigned char *s;
static unsigned char *k2;
static unsigned char *n2;
static unsigned char *m2;
static unsigned char *c2;
static unsigned char *s2;

void chacha20_preallocate (void)
{
}

void chacha20_allocate (void)
{
	k = alignedcalloc (crypto_stream_KEYBYTES);
	n = alignedcalloc (crypto_stream_NONCEBYTES);
	m = alignedcalloc (MAXTEST_BYTES);
	c = alignedcalloc (MAXTEST_BYTES);
	s = alignedcalloc (MAXTEST_BYTES);
	k2 = alignedcalloc (crypto_stream_KEYBYTES);
	n2 = alignedcalloc (crypto_stream_NONCEBYTES);
	m2 = alignedcalloc (MAXTEST_BYTES);
	c2 = alignedcalloc (MAXTEST_BYTES);
	s2 = alignedcalloc (MAXTEST_BYTES);
}

void chacha20_predoit (void)
{
}

void chacha20_doit (void)
{
	crypto_stream_xor (c, m, TUNE_BYTES, n, k);
}

char checksum[crypto_stream_KEYBYTES * 2 + 1];

const char *chacha20_checksum_compute (void)
{
	long long i;
	long long j;

	for (i = 0; i < CHECKSUM_BYTES; ++i) {
		long long mlen = i;
		long long clen = i;
		long long slen = i;
		long long klen = crypto_stream_KEYBYTES;
		long long nlen = crypto_stream_NONCEBYTES;
		for (j = -16; j < 0; ++j)
			m[j] = rand ();
		for (j = -16; j < 0; ++j)
			c[j] = rand ();
		for (j = -16; j < 0; ++j)
			s[j] = rand ();
		for (j = -16; j < 0; ++j)
			n[j] = rand ();
		for (j = -16; j < 0; ++j)
			k[j] = rand ();
		for (j = mlen; j < mlen + 16; ++j)
			m[j] = rand ();
		for (j = clen; j < clen + 16; ++j)
			c[j] = rand ();
		for (j = slen; j < slen + 16; ++j)
			s[j] = rand ();
		for (j = nlen; j < nlen + 16; ++j)
			n[j] = rand ();
		for (j = klen; j < klen + 16; ++j)
			k[j] = rand ();
		for (j = -16; j < mlen + 16; ++j)
			m2[j] = m[j];
		for (j = -16; j < clen + 16; ++j)
			c2[j] = c[j];
		for (j = -16; j < slen + 16; ++j)
			s2[j] = s[j];
		for (j = -16; j < nlen + 16; ++j)
			n2[j] = n[j];
		for (j = -16; j < klen + 16; ++j)
			k2[j] = k[j];

		crypto_stream_xor (c, m, mlen, n, k);

		for (j = -16; j < mlen + 16; ++j)
			if (m[j] != m2[j])
				return "crypto_stream_xor overwrites m";
		for (j = -16; j < slen + 16; ++j)
			if (s[j] != s2[j])
				return "crypto_stream_xor overwrites s";
		for (j = -16; j < nlen + 16; ++j)
			if (n[j] != n2[j])
				return "crypto_stream_xor overwrites n";
		for (j = -16; j < klen + 16; ++j)
			if (k[j] != k2[j])
				return "crypto_stream_xor overwrites k";
		for (j = -16; j < 0; ++j)
			if (c[j] != c2[j])
				return "crypto_stream_xor writes before output";
		for (j = clen; j < clen + 16; ++j)
			if (c[j] != c2[j])
				return "crypto_stream_xor writes after output";

		for (j = -16; j < clen + 16; ++j)
			c2[j] = c[j];

		crypto_stream (s, slen, n, k);

		for (j = -16; j < mlen + 16; ++j)
			if (m[j] != m2[j])
				return "crypto_stream overwrites m";
		for (j = -16; j < clen + 16; ++j)
			if (c[j] != c2[j])
				return "crypto_stream overwrites c";
		for (j = -16; j < nlen + 16; ++j)
			if (n[j] != n2[j])
				return "crypto_stream overwrites n";
		for (j = -16; j < klen + 16; ++j)
			if (k[j] != k2[j])
				return "crypto_stream overwrites k";
		for (j = -16; j < 0; ++j)
			if (s[j] != s2[j])
				return "crypto_stream writes before output";
		for (j = slen; j < slen + 16; ++j)
			if (s[j] != s2[j])
				return "crypto_stream writes after output";

		for (j = 0; j < mlen; ++j)
			if ((s[j] ^ m[j]) != c[j])
				return "crypto_stream_xor does not match crypto_stream";

		for (j = 0; j < clen; ++j)
			k[j % klen] ^= c[j];
		crypto_stream_xor (m, c, clen, n, k);
		crypto_stream (s, slen, n, k);
		for (j = 0; j < mlen; ++j)
			if ((s[j] ^ m[j]) != c[j])
				return "crypto_stream_xor does not match crypto_stream";
		for (j = 0; j < mlen; ++j)
			n[j % nlen] ^= m[j];
		m[mlen] = 0;
	}

	sodium_bin2hex (checksum, sizeof checksum, k, crypto_stream_KEYBYTES);

	return 0;
}
