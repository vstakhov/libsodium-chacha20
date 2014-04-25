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
#ifndef CRYPTO_SECRETBOX_CHACHA20POLY1305_H_
#define CRYPTO_SECRETBOX_CHACHA20POLY1305_H_

#include <stddef.h>

#ifdef __cplusplus
# if __GNUC__
# pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C"
{
#endif

#define crypto_secretbox_chacha20poly1305_KEYBYTES 32U
#define crypto_secretbox_chacha20poly1305_NONCEBYTES 16U
#define crypto_secretbox_chacha20poly1305_ZEROBYTES 16U
#define crypto_secretbox_chacha20poly1305_BOXZEROBYTES 0U
#define crypto_secretbox_chacha20poly1305_MACBYTES (crypto_secretbox_chacha20poly1305_ZEROBYTES - crypto_secretbox_chacha20poly1305_BOXZEROBYTES)

size_t crypto_secretbox_chacha20poly1305_keybytes (void);
size_t crypto_secretbox_chacha20poly1305_noncebytes (void);
size_t crypto_secretbox_chacha20poly1305_zerobytes (void);
size_t crypto_secretbox_chacha20poly1305_boxzerobytes (void);
size_t crypto_secretbox_chacha20poly1305_macbytes (void);

#define crypto_secretbox_chacha20poly1305_PRIMITIVE "chacha20poly1305"

const char *crypto_secretbox_chacha20poly1305_primitive (void);


int crypto_secretbox_chacha20poly1305 (unsigned char *c, const unsigned char *m,
		unsigned long long mlen, const unsigned char *n,
		const unsigned char *k);


int crypto_secretbox_chacha20poly1305_open (unsigned char *m, const unsigned char *c,
		unsigned long long clen, const unsigned char *n,
		const unsigned char *k);

#ifdef __cplusplus
}
#endif


#endif /* CRYPTO_SECRETBOX_CHACHA20POLY1305_H_ */
