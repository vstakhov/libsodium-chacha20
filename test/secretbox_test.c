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

sig_atomic_t got_alarm;

static void
alrm_handler (int signo)
{
	got_alarm = 1;
}

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

	return 0;
}

static long
test_crypto_secretbox_time (int blen, int seconds)
{
	unsigned char k[crypto_stream_chacha20_KEYBYTES];
	unsigned char n[crypto_stream_chacha20_NONCEBYTES];
	unsigned char *c, *m;
	long cycles = 0;

	blen += crypto_secretbox_chacha20poly1305_ZEROBYTES;
	posix_memalign ((void **)&c, 16, blen);
	posix_memalign ((void **)&m, 16, blen);
	randombytes_buf (m, blen);
	memset (m, 0, crypto_secretbox_chacha20poly1305_ZEROBYTES);

	randombytes_buf (k, sizeof (k));
	randombytes_buf (n, sizeof (n));

	alarm (seconds);

	while (!got_alarm) {
		crypto_secretbox_chacha20poly1305 (c, m, blen, n, k);
		if (crypto_secretbox_chacha20poly1305_open (m, c, blen, n, k) == -1) {
			return -1;
		}
		cycles ++;
	}

	got_alarm = 0;
	return cycles;
}

static long
test_crypto_secretbox_salsa_time (int blen, int seconds)
{
	unsigned char k[crypto_secretbox_KEYBYTES];
	unsigned char n[crypto_secretbox_NONCEBYTES];
	unsigned char *c, *m;
	long cycles = 0;

	blen += crypto_secretbox_ZEROBYTES;
	posix_memalign ((void **)&c, 16, blen);
	posix_memalign ((void **)&m, 16, blen);
	randombytes_buf (m, blen);
	memset (m, 0, crypto_secretbox_ZEROBYTES);

	randombytes_buf (k, sizeof (k));
	randombytes_buf (n, sizeof (n));

	alarm (seconds);

	while (!got_alarm) {
		crypto_secretbox (c, m, blen, n, k);
		if (crypto_secretbox_open (m, c, blen, n, k) == -1) {
			return -1;
		}
		cycles ++;
	}

	got_alarm = 0;
	return cycles;
}

struct tres {
	int bsize;
	long cycles_box_chacha;
	long cycles_box_salsa;
};

int
main (int argc, char **argv)
{
	int i, seconds = 3;
	struct tres tr[] = {
		{32, 0, 0},
		{64, 0, 0},
		{128, 0, 0},
		{512, 0, 0},
		{1024, 0, 0},
		{4096, 0, 0},
		{8192, 0, 0},
		{32768, 0, 0},
		{65536, 0, 0}
	};

	if (argc > 1) {
		seconds = strtoul (argv[1], NULL, 10);
	}

	test_crypto_stream ();
	if (test_crypto_secretbox () == -1) {
		return EXIT_FAILURE;
	}

	for (i = 0; i < sizeof(tr) / sizeof (tr[0]); i ++) {
		signal (SIGALRM, alrm_handler);
		printf ("Testing chacha20 cryptobox for %d bytes for %d seconds: ",
				tr[i].bsize, seconds);
		tr[i].cycles_box_chacha = test_crypto_secretbox_time (tr[i].bsize, seconds);
		printf ("%ld operations\n", tr[i].cycles_box_chacha);
	}
	printf ("\n");
	for (i = 0; i < sizeof(tr) / sizeof (tr[0]); i ++) {
		signal (SIGALRM, alrm_handler);
		printf ("Testing salsa20 cryptobox for %d bytes for %d seconds: ",
				tr[i].bsize, seconds);
		tr[i].cycles_box_salsa = test_crypto_secretbox_salsa_time (tr[i].bsize, seconds);
		printf ("%ld operations\n", tr[i].cycles_box_salsa);
	}

	printf ("\nSummary:\n");
	printf ("%15s | %20s | %20s\n", "Block size", "Chacha20", "Salsa20");
	printf ("\n");

	for (i = 0; i < sizeof(tr) / sizeof (tr[0]); i ++) {
		printf ("%15d | %20ld | %20ld\n", tr[i].bsize,
				tr[i].cycles_box_chacha * tr[i].bsize / seconds,
				tr[i].cycles_box_salsa * tr[i].bsize / seconds);
	}

	return 0;
}
