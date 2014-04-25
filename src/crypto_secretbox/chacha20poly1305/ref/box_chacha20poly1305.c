/* Copyright (c) 2014, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sodium/crypto_onetimeauth_poly1305.h>
#include <sodium.h>
#include "crypto_stream_chacha20.h"

int crypto_secretbox_chacha20poly1305 (unsigned char *c, const unsigned char *m,
		unsigned long long mlen, const unsigned char *n, const unsigned char *k)
{
	int i;
	unsigned char subkey[32];
	if (mlen < 16)
		return -1;
	/* Km = E({0}, n, k) */
	sodium_memzero (subkey, 32);
	crypto_stream_chacha20 (subkey, 32, n, k);

	crypto_stream_chacha20_xor (c + 16, m + 16, mlen - 16, n, k);
	crypto_onetimeauth_poly1305 (c, c + 16, mlen - 16, subkey);

	return 0;
}

int crypto_secretbox_chacha20poly1305_open (unsigned char *m,
		const unsigned char *c, unsigned long long clen, const unsigned char *n,
		const unsigned char *k)
{
	int i;
	unsigned char subkey[32];
	if (clen < 16)
		return -1;

	sodium_memzero (subkey, 32);
	crypto_stream_chacha20 (subkey, 32, n, k);

	if (crypto_onetimeauth_poly1305_verify (c, c + 16, clen - 16, subkey)
			!= 0)
		return -1;

	crypto_stream_chacha20_xor (m + 16, c + 16, clen - 16, n, k);
	for (i = 0; i < 16; ++i)
		m[i] = 0;
	return 0;
}
