// bliss.c
// 18-Jun-15  Markku-Juhani O. Saarinen <m.saarinen@qub.ac.uk>

#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "bliss.h"
#include "distribution.h"
#include "ntt32.h"
#include "sha3.h"
#include "notrandom.h"

// local utility functions

// absolute maximinum of a vector

int vecabsmax(const int32_t v[], int n)
{
    int i, max;

    max = 0;
    for (i = 0; i < n; i++) {
        if (v[i] > max)
            max = v[i];
        if (-v[i] > max)
            max = -v[i];
    }

    return max;
}

// scalar product (or norm if t=u)

int vecscalar(const int32_t t[], const int32_t u[], int n)
{
    int i, sum;

    sum = 0;
    for (i = 0; i < n; i++)
        sum += t[i] * u[i];

    return sum;
}

// Uniform Polynomials.

void uniform_poly(int32_t v[], int n, int nz1, int nz2)
{
    int i, j;
    uint64_t x;

    for (i = 0; i < n; i++)
        v[i] = 0;

    i = 0;
    while (i < nz1) {
        x = notrand64();
        j = (x >> 1) % n;
        if (v[j] != 0)
            continue;
        v[j] = x & 1 ? 1 : -1;
        i++;
    }

    i = 0;
    while (i < nz2) {
        x = notrand64();
        j = (x >> 1) % n;
        if (v[j] != 0)
            continue;
        v[j] = x & 1 ? 2 : -2;
        i++;
    }
}

// random oracle

int bliss_c_oracle(int32_t c_idx[], int kappa,
                    const void *hash, size_t hash_len,
                    const int32_t w[], int n)
{
    int i, idx, r, idx_i;
    sha3_ctx_t sha;
    uint8_t md[64], t[2], *fl;

    if ((fl = malloc(n)) == NULL)
        return -1;

    memset(fl, 0, n);
    idx_i = 0;

    for (r = 0; r < 65536; r++) {

        sha3_init(&sha, 64);
        sha3_update(&sha, hash, hash_len);

        for (i = 0; i < n; i++) {
            t[0] = w[i] >> 8;              // big endian 16-bit
            t[1] = w[i] & 0xFF;
            sha3_update(&sha, t, 2);
        }
        t[0] = r >> 8;                      // same with round
        t[1] = r & 0xFF;

        sha3_update(&sha, t, 2);
        sha3_final(md, &sha);

        for (i = 0; i < 64; i += 2) {

            idx = ((((uint16_t) md[i]) << 8) + ((uint16_t) md[i + 1])) % n;

            if (fl[idx] == 0) {
                c_idx[idx_i++] = idx;
                if (idx_i == kappa) {
                    free(fl);
                    return 0;
                }
                fl[idx] = 1;
            }
        }
    }

    return -2;
}

// == PRIVKEY ==

// Free a private key

void bliss_privkey_free(bliss_privkey_t *priv)
{
    const bliss_param_t *p;

    p = &bliss_param[priv->set];
    memset(priv, 0x00, sizeof(bliss_privkey_t) + 3 * p->n * sizeof(int32_t));
    free(priv);
}

// Create an empty private key.

bliss_privkey_t *bliss_privkey_new(int set)
{
    bliss_privkey_t *priv;
    const bliss_param_t *p;
    size_t siz;

    p = &bliss_param[set];
    siz = sizeof(bliss_privkey_t) + 3 * p->n * sizeof(int32_t);
    priv = malloc(siz);

    memset(priv, 0x00, siz);
    priv->set = set;
    priv->f = ((void *) priv) + sizeof(bliss_privkey_t);
    priv->g = &priv->f[p->n];
    priv->a = &priv->g[p->n];

    return priv;
}

// Key generation. Return NULL on failure.

bliss_privkey_t *bliss_privkey_gen(int set)
{
    int i, r;
    bliss_privkey_t *priv;
    const bliss_param_t *p;
    int32_t *t, *u, x;

    p = &bliss_param[set];
    if ((priv = bliss_privkey_new(set)) == NULL ||
        (t = calloc(2 * p->n, sizeof(int32_t))) == NULL)
        return NULL;
    u = &t[p->n];

    // randomize g
    uniform_poly(priv->g, p->n, p->nz1, p->nz2);
    for (i = 0; i < p->n; i++)      // 2g - 1 ?
        priv->g[i] *= 2;
    priv->g[0]--;
    for (i = 0; i < p->n; i++)
        t[i] = priv->g[i];
    ntt32_xmu(t, p->n, p->q, t, p->w);
    ntt32_fft(t, p->n, p->q, p->w);

    // find an invertible f
    for (r = 0; r < 99999; i++) {

        // randomize f
        uniform_poly(priv->f, p->n, p->nz1, p->nz2);

        // a = g/f. try again if "f" not invertible.
        for (i = 0; i < p->n; i++)
            u[i] = priv->f[i];
        ntt32_xmu(u, p->n, p->q, u, p->w);
        ntt32_fft(u, p->n, p->q, p->w);

        for (i = 0; i < p->n; i++) {
            x = u[i] % p->q;
            if (x == 0)
                break;
            x = ntt32_pwr(x, p->q - 2, p->q);
            u[i] = x;
        }
        if (i < p->n)
            continue;

        // success!
        ntt32_xmu(priv->a, p->n, p->q, t, u);
        ntt32_fft(priv->a, p->n, p->q, p->w);
        ntt32_xmu(priv->a, p->n, p->q, priv->a, p->r);

        // retransform (can we optimize this ?)
        ntt32_cmu(priv->a, p->n, p->q, priv->a, -1);    // flip sign
        ntt32_flp(priv->a, p->n, p->q);
        ntt32_xmu(priv->a, p->n, p->q, priv->a, p->w);
        ntt32_fft(priv->a, p->n, p->q, p->w);

        // normalize a
        for (i = 0; i < p->n; i++) {
            x = priv->a[i] % p->q;
            if (x < 0)
                x += p->q;
            priv->a[i] = x;
        }

        free(t);
        return priv;
    }

    // too many iterations, fail
    free(t);
    bliss_privkey_free(priv);

    return NULL;
}

