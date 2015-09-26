// bliss.c
// 18-Jun-15  Markku-Juhani O. Saarinen <mjos@iki.fi>

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

static int vecabsmax(const int32_t v[], int n)
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

static int vecscalar(const int32_t t[], const int32_t u[], int n)
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
                    const int32_t ud[], int n)
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
            t[0] = ud[i] >> 8;              // big endian 16-bit
            t[1] = ud[i] & 0xFF;
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

// == PUBKEY ==

// Free a public key.

void bliss_pubkey_free(bliss_pubkey_t *pub)
{
    const bliss_param_t *p;

    p = &bliss_param[pub->set];
    memset(pub, 0x00,
        sizeof(bliss_privkey_t) + p->n * sizeof(int32_t));
    free(pub);
}

// Create an empty public key.

bliss_pubkey_t *bliss_pubkey_new(int set)
{
    bliss_pubkey_t *pub;
    const bliss_param_t *p;
    size_t siz;

    p = &bliss_param[set];
    siz = sizeof(bliss_privkey_t) + p->n * sizeof(int32_t);
    pub = malloc(siz);

    memset(pub, 0x00, siz);
    pub->set = set;
    pub->a = ((void *) pub) + sizeof(bliss_pubkey_t);

    return pub;
}

// Derive a public key from a private key.

bliss_pubkey_t *bliss_pubkey_frompriv(const bliss_privkey_t *priv)
{
    int i;
    bliss_pubkey_t *pub;
    const bliss_param_t *p;

    p = &bliss_param[priv->set];

    if ((pub = bliss_pubkey_new(priv->set)) == NULL)
        return NULL;

    // copy a = g/f
    for (i = 0; i < p->n; i++)
        pub->a[i] = priv->a[i];

    return pub;
}

// == SIGNATURE ==

// GreedySC

static void greedy_sc(const int32_t f[], const int32_t g[], int n,
    const int c_idx[], int kappa, int32_t v1[], int32_t v2[])
{
    int i, j, idx, sgn;

    for (i = 0; i < n; i++) {
        v1[i] = 0;
        v2[i] = 0;
    }

    for (j = 0; j < kappa; j++) {

        idx = c_idx[j];
        sgn = 0;

        for (i = 0; i < n - idx; i++) {
            sgn += f[i] * v1[i + idx] + g[i] * v2[i + idx];
        }
        for (i = n - idx; i < n; i++) {
            sgn -= f[i] * v1[i + idx - n] + g[i] * v2[i + idx - n];
        }

        if (sgn > 0) {
            for (i = 0; i < n - idx; i++) {
                v1[i + idx] -= f[i];
                v2[i + idx] -= g[i];
            }
            for (i = n - idx; i < n; i++) {
                v1[i + idx - n] += f[i];
                v2[i + idx - n] += g[i];
            }
        } else {
            for (i = 0; i < n - idx; i++) {
                v1[i + idx] += f[i];
                v2[i + idx] += g[i];
            }
            for (i = n - idx; i < n; i++) {
                v1[i + idx - n] -= f[i];
                v2[i + idx - n] -= g[i];
            }
        }
    }
}

// Free a signature.

void bliss_sign_free(bliss_signature_t *sign)
{
    const bliss_param_t *p;

    p = &bliss_param[sign->set];
    memset(sign, 0x00, sizeof(bliss_signature_t) +
            (2 * p->n + p->kappa) * sizeof(int32_t));
    free(sign);
}

// Create an empty signature with given parameters.

bliss_signature_t *bliss_sign_new(int set)
{
    bliss_signature_t *sign;
    size_t siz;
    const bliss_param_t *p;

    p = &bliss_param[set];
    siz = sizeof(bliss_signature_t) +
        (2 * p->n + p->kappa) * sizeof(int32_t);
    sign = malloc(siz);

    memset(sign, 0x00, siz);
    sign->set = set;
    sign->z1 = ((void *) sign) + sizeof(bliss_signature_t);
    sign->z2d = &sign->z1[p->n];
    sign->c_idx = &sign->z2d[p->n];

    return sign;
}

// Sign a message.

bliss_signature_t *bliss_sign(const bliss_privkey_t *priv,
    const uint8_t *hash, size_t hash_len)
{
    int i, r;
    double d;
    int32_t *t, *u, *v, *ud, *s1c, *s2c, x;
    const bliss_param_t *p;
    bliss_signature_t *sign;

    p = &bliss_param[priv->set];

    if ((sign = bliss_sign_new(priv->set)) == NULL ||
        (t = calloc(6 * p->n, sizeof(int32_t))) == NULL)
        return NULL;
    u = &t[p->n];
    v = &u[p->n];
    ud = &v[p->n];
    s1c = &ud[p->n];
    s2c = &s1c[p->n];

    for (r = 0; r < 99999; r++) {

        // normal distributed random
        for (i = 0; i < p->n; i++) {
            t[i] = gauss_sample(priv->set);
            u[i] = gauss_sample(priv->set);
        }

        // v = t * a
        for (i = 0; i < p->n; i++)
            v[i] = t[i];
        ntt32_xmu(v, p->n, p->q, v, p->w);
        ntt32_fft(v, p->n, p->q, p->w);
        ntt32_xmu(v, p->n, p->q, v, priv->a);
        ntt32_fft(v, p->n, p->q, p->w);
        ntt32_xmu(v, p->n, p->q, v, p->r);
        ntt32_flp(v, p->n, p->q);

        // round and drop
        for (i = 0; i < p->n; i++) {
            x = ((p->q + 1) * v[i] + u[i]) % (p->q * 2);
            if (x < 0)
                x += (p->q * 2);
            v[i] = x;
            ud[i] = ((x + (1 << (p->d - 1))) >> p->d) % p->p;
        }

        // create the c index set
        bliss_c_oracle(sign->c_idx, p->kappa, hash, hash_len, ud, p->n);
        greedy_sc(priv->f, priv->g, p->n, sign->c_idx, p->kappa, s1c, s2c);

        // add or subtract
        if (notrand64() & 1) {
            for (i = 0; i < p->n; i++) {
                t[i] -= s1c[i];
                u[i] -= s2c[i];
            }
        } else {
            for (i = 0; i < p->n; i++) {
                t[i] += s1c[i];
                u[i] += s2c[i];
            }
        }

        // rejection math
        d = 1.0 / ((double) p->sig * p->sig);
        d = 1.0 / (p->m  *
            exp(-0.5 * d * (vecscalar(s1c, s1c, p->n) +
                vecscalar(s2c, s2c, p->n))) *
            cosh(d * (vecscalar(t, s1c, p->n) + vecscalar(u, s2c, p->n))));

        // must be HIGHER than the continue probability to redo generation
        if (notrand() > d)
            continue;

        // generate signature
        for (i = 0; i < p->n; i++) {
            x = v[i] - u[i];

            if (x < 0)
                x += 2 * p->q;
            if (x >= 2 * p->q)
                x -= 2 * p->q;

            x = ((x + (1 << (p->d - 1))) >> p->d) % p->p; // uz2d

            // normalize in range
            x = ud[i] - x;
            if (x < -p->p / 2)
                x += p->p;
            if (x > p->p / 2)
                x -= p->p;
            v[i] = x;
        }

        // return it
        for (i = 0; i < p->n; i++) {
            sign->z1[i] = t[i];
            sign->z2d[i] = v[i];
        }

        free(t);
        return sign;
    }

    // too many iterations, fail
    bliss_sign_free(sign);
    free(t);

    return NULL;
}

// Verify a signature. Return 0 if signature OK.

int bliss_verify(const bliss_signature_t *sign,
    const uint8_t *hash, size_t hash_len,
    const bliss_pubkey_t *pub)
{
    int i;
    int32_t *v, *my_idx, x;
    const bliss_param_t *p;

    // check that signature and public key use the same parameters set
    if (sign->set != pub->set)
        return -1;

    p = &bliss_param[pub->set];

    // compute norms
    if (vecabsmax(sign->z1, p->n) > p->b_inf ||
        (vecabsmax(sign->z2d, p->n) << p->d) > p->b_inf)
        return -2;

    if (vecscalar(sign->z1, sign->z1, p->n) +
        (vecscalar(sign->z2d, sign->z2d, p->n) << (2 * p->d)) > p->b_l2)
        return -3;

    // check the signature
    v = calloc(p->n + p->kappa, sizeof(int));
    if (v == NULL)
        return -4;
    my_idx = &v[p->n];

    // v = z1 * a (mod x^n + 1)
    for (i = 0; i < p->n; i++)
        v[i] = sign->z1[i];

    ntt32_xmu(v, p->n, p->q, v, p->w);
    ntt32_fft(v, p->n, p->q, p->w);
    ntt32_xmu(v, p->n, p->q, v, pub->a);
    ntt32_fft(v, p->n, p->q, p->w);
    ntt32_xmu(v, p->n, p->q, v, p->r);
    ntt32_flp(v, p->n, p->q);

    // verification magic
    for (i = 0; i < p->n; i++)
        v[i] = ((p->q + 1) * v[i]) % (2 * p->q);

    // v = v + C * q
    for (i = 0; i < p->kappa; i++)
        v[sign->c_idx[i]] = (v[sign->c_idx[i]] + p->q) % (2 * p->q);

    // drop bits
    for (i = 0; i < p->n; i++) {
        x = v[i];
        x = (((x + (1 << (p->d - 1))) >> p->d) + sign->z2d[i]) % p->p;
        if (x < 0)
            x += p->p;
        v[i] = x;
    }

    // run the oracle
    bliss_c_oracle(my_idx, p->kappa, hash, hash_len, v, p->n);

    // check it
    for (i = 0; i < p->kappa; i++) {
        if (my_idx[i] != sign->c_idx[i]) {
            free(v);
            return -5;
        }
    }
    free(v);

    return 0;
}

