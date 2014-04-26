/*
 * Copyright (c) 2014, Vsevolod Stakhov
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
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

#include <sys/types.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sodium.h>

#include "crypto_stream_chacha20.h"
#include "crypto_secretbox_chacha20poly1305.h"

static void
test_crypto_stream (void)
{
	unsigned char k[crypto_stream_chacha20_KEYBYTES];
	unsigned char n[crypto_stream_chacha20_NONCEBYTES];
	unsigned char m[128], c[128];
	char out[256];
	const char test_str[] = "test chacha20";

	/* Simple encrypt/decrypt test */
	memcpy (m, test_str, sizeof (test_str));

	randombytes_buf (k, sizeof (k));
	randombytes_buf (n, sizeof (n));

	crypto_stream_chacha20_xor (c, m, sizeof (test_str), n, k);
	sodium_bin2hex (out, sizeof (out), c, sizeof (test_str));

	printf ("Got chacha20 encryption: %s\n", out);

	crypto_stream_chacha20_xor (m, c, sizeof (test_str), n, k);

	sodium_bin2hex (out, sizeof (out), m, sizeof (test_str));
	printf ("Got chacha20 decryption: %s (%s)\n", m, out);
}

static int
test_crypto_secretbox (void)
{
	unsigned char k[crypto_stream_chacha20_KEYBYTES];
	unsigned char n[crypto_stream_chacha20_NONCEBYTES];
	unsigned char m[128], c[128];
	char out[256];
	const char test_str[] = "test chacha20";
	size_t clen = sizeof (test_str) + crypto_secretbox_chacha20poly1305_ZEROBYTES;

	memset (m, 0, crypto_secretbox_chacha20poly1305_ZEROBYTES);
	memcpy (m + crypto_secretbox_chacha20poly1305_ZEROBYTES,
			test_str, sizeof (test_str));

	randombytes_buf (k, sizeof (k));
	randombytes_buf (n, sizeof (n));

	crypto_secretbox_chacha20poly1305 (c, m, clen, n, k);

	sodium_bin2hex (out, sizeof (out), c, clen);

	printf ("Got secretbox encryption: %s\n", out);

	if (crypto_secretbox_chacha20poly1305_open (m, c, clen, n, k) == -1) {
		return -1;
	}

	sodium_bin2hex (out, sizeof (out),
			m + crypto_secretbox_chacha20poly1305_ZEROBYTES, sizeof (test_str));
	printf ("Got secretbox decryption: %s (%s)\n",
			m + crypto_secretbox_chacha20poly1305_ZEROBYTES, out);
}

int
main (int argc, char **argv)
{
	test_crypto_stream ();
	if (test_crypto_secretbox () == -1) {
		return EXIT_FAILURE;
	}
	return 0;
}
