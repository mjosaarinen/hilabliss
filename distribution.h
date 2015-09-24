// distribution.h
// 22-Sep-15  Markku-Juhani O. Saarinen <mjos@iki.fi>

#ifndef DISTRIBUTION_H
#define DISTRIBUTION_H

#include <stdint.h>

// initialize parameter sets 0..4
void gauss_init();

// sample from the given set
int32_t gauss_sample(int set);

//void gaussian_vecs(int32_t x[], int32_t y[], int n, double sigma);

#endif
