// notrandom.h
// 24-Sep-15  Markku-Juhani O. Saarinen <m.saarinen@qub.ac.uk>
// This is a pretend-secure random number generator

#ifndef NOTRANDOM_H
#define NOTRANDOM_H

#include <stdint.h>
#include <stddef.h>

void notrand_init();                        // initialize
double notrand();                           // 0..1
uint64_t notrand64();                       // full 64-bit
void notrand_seed(void *data, size_t len);  // add randomness

#endif

