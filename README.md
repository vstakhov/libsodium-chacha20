libsodium-chacha20
==================

This is a secretbox extension for using inside libsodium providing ChaCha20-Poly1305 cipher suite. It requires [libsodium](https://github.com/jedisct1/libsodium/) to build and link.
It does not replace the default cryptobox of libsodium providing the alternative (and sometimes faster) implementation of secretbox.

## Usage

~~~C
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <crypto_secretbox_chacha20poly1305.h>

int chacha20_test (unsigned char *m, unsigned mlen)
{
	unsigned char k[crypto_stream_chacha20_KEYBYTES];
	unsigned char n[crypto_stream_chacha20_NONCEBYTES];

	memset (m, 0, crypto_secretbox_chacha20poly1305_ZEROBYTES);
	memcpy (m + crypto_secretbox_chacha20poly1305_ZEROBYTES,
					test_str, sizeof (test_str));

	randombytes_buf (k, sizeof (k));
	randombytes_buf (n, sizeof (n));

	crypto_secretbox_chacha20poly1305 (m, m, clen, n, k);
	
	if (crypto_secretbox_chacha20poly1305_open (m, m, clen, n, k) == -1) {
		return -1;
	}

	return 0;
}
~~~

For this specific primitive the sizes are the following:

* `keybytes`: 32
* `noncebytes`: 16
* `zerobytes`: 16
* `boxzerobytes`: 0

## Security model

This implementation uses the reference and optimized version of D. J. Bernstein [ChaCha20 algorithm](http://cr.yp.to/chacha.html).
Optimized version is written by Ted Krovetz and uses sse3/altivec/neon to speed up operation.

For MAC this secretbox uses fast [Poly1305](http://cr.yp.to/mac.html).

To create secretbox, libsodium-chacha20 initially encrypt a block of 64 zero bytes using the specified key and nonce to create 2 subkeys. One subkey is used for encryption and another - for MAC.

Therefore the overall procedure can be described as following:

~~~
subkeys[64] = E({0}[64], n, k)
c = E(m + zerobytes, n, subkeys)
MAC = M(m + zerobytes, n, subkeys + 32)

C = MAC || c
~~~

This introduces some weak keys that, in particular, maps to themselves, so `E({0}[64], n, k)` is equal to `k`. However, probability of such keys is negligible for a specific nonce.

## Performance comparision
Salsa20 is a standard `libsodium` crypto\_secretbox implementation.

~~~
     Block size |             Chacha20 |              Salsa20

             32 |             16945363 |              7728051
             64 |             30913945 |             11210937
            128 |             40789145 |             17243673
            512 |             53664307 |             28753612
           1024 |             56867635 |             32382873
           4096 |             59557888 |             35932160
           8192 |             59878604 |             36436377
          32768 |             59847475 |             36932812
          65536 |             59716403 |             37086822
~~~

Hardware used:
Intel(R) Core(TM) i7-3630QM CPU @ 2.40GHz

Chacha implementation: reference (without optimizations).

Here is another benchmark result provided by Roman Timofeev:

~~~
     Block size |             Chacha20 |              Salsa20

             32 |             57646240 |             25184192
             64 |            110266794 |             41375125
            128 |            150549760 |             69475370
            512 |            259458389 |            177806677
           1024 |            301762560 |            228260181
           4096 |            330050218 |            289914880
           8192 |            334618624 |            303658325
          32768 |            339487402 |            313786368
          65536 |            340830890 |            315555840
~~~

Hardware used: 
Intel Core™ i7-3770

Chacha implementation: krovetz (sse3 vectorizing).
