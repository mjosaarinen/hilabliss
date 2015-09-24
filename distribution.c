// distribution.c
// 22-Sep-15  Markku-Juhani O. Saarinen <mjos@iki.fi>

#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "distribution.h"
#include "notrandom.h"
#include "bliss.h"
#include "sha3.h"

// global tables for binary search

#define GAUSS_CDF_SIZE 0x1000
#define GAUSS_CDF_STEP 0x0800

uint64_t gauss_cdf[5][GAUSS_CDF_SIZE];

// Build CDF's for given sigma

void gauss_gen_cdf(uint64_t cdf[], long double sigma, int n)
{
    int i;
    long double s, d, e;

    // 2/sqrt(2*Pi)  * (1 << 64) / sigma
    d = 0.7978845608028653558798L * (18446744073709551616.0L) / sigma;

    e = -0.5L / (sigma * sigma);
    s = 0.5L * d;
    cdf[0] = 0;
    for (i = 1; i < n; i++) {
        cdf[i] = s;
        s += d * expl(e * ((long double) (i*i)));
    }
}

void gauss_init()
{
    int i;

    notrand_init();

    for (i = 0; i <= 4; i++)
        gauss_gen_cdf(gauss_cdf[i], bliss_param[i].sig, GAUSS_CDF_SIZE);
}

// binary search on a list

static int binsearch(uint64_t x, const uint64_t l[], int n, int st)
{
    int a, b;

    a = 0;
    while (st > 0) {
        b = a + st;
        if (b < n && x >= l[b])
            a = b;
        st >>= 1;
    }
    return a;
}

// sample from the distribution with binary search

int32_t gauss_sample(int set)
{
    int a;
    uint64_t x;

    x = notrand64();
    a = binsearch(x, gauss_cdf[set], GAUSS_CDF_SIZE, GAUSS_CDF_STEP);

    return x & 1 ? a : -a;
}

// gaussian Sampling old skool

void gaussian_vecs(int32_t x[], int32_t y[], int n, double sigma)
{
    int i;
    double t, u, s;

    sigma /= sqrt(2.0);
    for (i = 0; i < n; i++) {
        do {
            t = notrand() - 0.5;
            u = notrand() - 0.5;
            s = t * t + u * u;
        } while (s >= 0.25 || s == 0.0);
        s *= 4.0;
        s = sigma * sqrt(-log(s) / s);
        x[i] = (int) round(s * t);
        y[i] = (int) round(s * u);
    }
}

