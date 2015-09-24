hilabliss
=========

24-Sep-15  Markku-Juhani O. Saarinen <m.saarinen@qub.ac.uk>

# Introduction

This is a simple educational implementation of **BLISS-B**, the Bimodal 
Lattice Signature Scheme, based on BLISS originally published in Crypto '13:

*Léo Ducas, Alain Durmus, Tancrède Lepoint, Vadim Lyubashevsky:*
Lattice Signatures and Bimodal Gaussians

Extended version of this paper is available as 
[IACR ePrint 2013/383](https://eprint.iacr.org/2013/383). This code implements
the BLISS-B variant of Léo Ducas, which is available as
[IACR ePrint 2014/874](https://eprint.iacr.org/2014/874).

As such, this is pretty much state of the art in Lattice based signature
schemes, apart from the couple of caveats I will tell you about.

# Features

* 100% written by me (albeit I admit peeking at reference code occasionally).
* A self-contained (only requires standard libmath!), portable, clean.
* SHA3 for hashing and random oracle stuff. 
* Number Theoretic Transforms for the negacyclic rings.
* A binary-search Discrete Gaussian Gaussian sampler, which only has 64 bits
of precision however. This is basically a demonstrator.
* A semi-secure PRNG called "notrand" for completeness, also using SHA3.
* A test driver.

# Compiling and running

Assuming that you get the tarball open:
```
$ make
gcc -Wall -Ofast   -c ntt32.c -o ntt32.o
gcc -Wall -Ofast   -c bliss.c -o bliss.o
gcc -Wall -Ofast   -c bliss_param.c -o bliss_param.o
gcc -Wall -Ofast   -c sha3.c -o sha3.o
gcc -Wall -Ofast   -c main.c -o main.o
gcc -Wall -Ofast   -c distribution.c -o distribution.o
gcc -Wall -Ofast   -c notrandom.c -o notrandom.o
gcc  -o hila ntt32.o bliss.o bliss_param.o sha3.o main.o distribution.o notrandom.o -lm
$ ./hila 
CLASS 1 x 1000
CLASS 2 x 1000
CLASS 3 x 1000
CLASS 4 x 1000
$ yes "POST QUANTUM LATTICE RING-LWE SUCCESS"
```
You may omit the last line.

