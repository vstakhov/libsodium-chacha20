libsodium-chacha20
==================

This is a secretbox extension for using inside libsodium providing ChaCha20-Poly1305 cipher suite

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
