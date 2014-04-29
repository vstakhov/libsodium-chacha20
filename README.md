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

Hardware used: Intel Core™ i7-3770
Chacha implementation: krovetz (sse3 vectorizing).
