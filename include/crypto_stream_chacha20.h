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
#ifndef CRYPTO_STREAM_CHACHA20_H_
#define CRYPTO_STREAM_CHACHA20_H_

/*
* WARNING: This is just a stream cipher. It is NOT authenticated encryption.
* While it provides some protection against eavesdropping, it does NOT
* provide any security against active attacks.
* Unless you know what you're doing, what you are looking for is probably
* the crypto_box functions.
*/

#include <stddef.h>

#define crypto_stream_chacha20_KEYBYTES 32U
#define crypto_stream_chacha20_NONCEBYTES 16U

#ifdef __cplusplus
# if __GNUC__
# pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

size_t crypto_stream_chacha20_keybytes(void);

size_t crypto_stream_chacha20_noncebytes(void);

const char * crypto_stream_chacha20_primitive(void);

int crypto_stream_chacha20(unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);

int crypto_stream_chacha20_xor(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *,const unsigned char *);
#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_STREAM_CHACHA20_H_ */
