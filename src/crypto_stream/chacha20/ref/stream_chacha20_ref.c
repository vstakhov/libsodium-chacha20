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

#include "chacha.h"
#include "crypto_stream_chacha20.h"

int
crypto_stream_chacha20 (
		unsigned char *c,unsigned long long clen,
		const unsigned char *n,
		const unsigned char *k
)
{
	struct chacha_ctx ctx;

	if (!clen) {
		return 0;
	}

	chacha_keysetup (&ctx, k, crypto_stream_chacha20_KEYBYTES * 8);
	chacha_ivsetup (&ctx, n, n + 8);

	chacha_encrypt_bytes (&ctx, c, c, clen);

	return 0;
}

int
crypto_stream_chacha20_xor (
		unsigned char *c,
		const unsigned char *m,
		unsigned long long mlen,
		const unsigned char *n,
		const unsigned char *k
)
{
	struct chacha_ctx ctx;

	if (!mlen) {
		return 0;
	}

	chacha_keysetup (&ctx, k, crypto_stream_chacha20_KEYBYTES * 8);
	chacha_ivsetup (&ctx, n, n + 8);

	chacha_encrypt_bytes (&ctx, m, c, mlen);

	return 0;
}
