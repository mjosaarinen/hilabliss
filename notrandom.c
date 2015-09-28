// notrandom.c
// 24-Sep-15  Markku-Juhani O. Saarinen <m.saarinen@qub.ac.uk>
// This is a pretend-secure random number generator

#include "notrandom.h"
#include "sha3.h"

// data comes out of pools 0 and 1 -- 2 is pretend-secret

static uint64_t nrpool[3][8];
static int nrpt = 0, nrsel = 0;

// 64 - bit

uint64_t notrand64()
{
    if (nrpt >= 8) {
        nrpt = 0;
        sha3(nrpool, 3 * 64, nrpool[nrsel], 64);
        nrsel ^= 1;
    }
    return nrpool[nrsel][nrpt++];
}

double notrand()
{
    return ((double) notrand64()) / 18446744073709551615.0;
}

void notrand_init()
{
    uint64_t i;

    for (i = 0; i < 3; i++)
        sha3(&i, sizeof(i), nrpool[i], 64);

    nrpt = 0;
    nrsel = 0;
}

void notrand_seed(void *data, size_t len)
{
    sha3_ctx_t ctx;

    sha3_init(&ctx, 64);
    sha3_update(&ctx, nrpool, 3 * 64);
    sha3_update(&ctx, data, len);
    sha3_final(nrpool[2], &ctx);
}

