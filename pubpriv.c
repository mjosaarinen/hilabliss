// pubpriv.c
// 04-Nov-15  Markku-Juhani O. Saarinen <m.saarinen@qub.ac.uk>

#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "bliss.h"
#include "distribution.h"
#include "ntt32.h"
#include "sha3.h"
#include "notrandom.h"

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
    const int c_idx[], int kappa, int32_t x[], int32_t y[])
{
    int i, j, k, sgn;

    for (j = 0; j < n; j++) {
        x[j] = 0;
        y[j] = 0;
    }

    for (k = 0; k < kappa; k++) {

        i = c_idx[k];
        sgn = 0;

        for (j = 0; j < n - i; j++) {
            sgn += f[j] * x[i + j] + g[j] * y[i + j];
        }
        for (j = n - i; j < n; j++) {
            sgn -= f[j] * x[i + j - n] + g[j] * y[i + j - n];
        }

        if (sgn > 0) {
            for (j = 0; j < n - i; j++) {
                x[i + j] -= f[j];
                y[i + j] -= g[j];
            }
            for (j = n - i; j < n; j++) {
                x[i + j - n] += f[j];
                y[i + j - n] += g[j];
            }
        } else {
            for (j = 0; j < n - i; j++) {
                x[i + j] += f[j];
                y[i + j] += g[j];
            }
            for (j = n - i; j < n; j++) {
                x[i + j - n] -= f[j];
                y[i + j - n] -= g[j];
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
    sign->t = ((void *) sign) + sizeof(bliss_signature_t);
    sign->z = &sign->t[p->n];
    sign->c_idx = &sign->z[p->n];

    return sign;
}

// Sign a message.

bliss_signature_t *bliss_sign(const bliss_privkey_t *priv,
    const uint8_t *hash, size_t hash_len)
{
    int i, r;
    double d;
    int32_t *t, *u, *v, *z, *x, *y, tmp;
    const bliss_param_t *p;
    bliss_signature_t *sign;

    p = &bliss_param[priv->set];

    if ((sign = bliss_sign_new(priv->set)) == NULL ||
        (t = calloc(6 * p->n, sizeof(int32_t))) == NULL)
        return NULL;
    u = &t[p->n];
    v = &u[p->n];
    z = &v[p->n];
    x = &z[p->n];
    y = &x[p->n];

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

            tmp = v[i]; // old: tmp = ((p->q + 1) * v[i] + u[i]) % (p->q * 2);
            if (tmp & 1)
                tmp += p->q;
            tmp = (tmp + u[i]) % (2 * p->q);
            if (tmp < 0)
                tmp += (2 * p->q);
            v[i] = tmp;
            z[i] = ((tmp + (1 << (p->d - 1))) >> p->d) % p->p;
        }

        // create the c index set
        bliss_c_oracle(sign->c_idx, p->kappa, hash, hash_len, z, p->n);
        greedy_sc(priv->f, priv->g, p->n, sign->c_idx, p->kappa, x, y);

        // add or subtract
        if (notrand64() & 1) {
            for (i = 0; i < p->n; i++) {
                t[i] -= x[i];
                u[i] -= y[i];
            }
        } else {
            for (i = 0; i < p->n; i++) {
                t[i] += x[i];
                u[i] += y[i];
            }
        }

        // rejection math
        d = 1.0 / ((double) p->sig * p->sig);
        d = 1.0 / (p->m  *
            exp(-0.5 * d * (vecscalar(x, x, p->n) +
                vecscalar(y, y, p->n))) *
            cosh(d * (vecscalar(t, x, p->n) + vecscalar(u, y, p->n))));

        // must be HIGHER than the continue probability to redo generation
        if (notrand() > d)
            continue;

        // generate signature
        for (i = 0; i < p->n; i++) {
            tmp = v[i] - u[i];

            // normalize
            if (tmp < 0)
                tmp += 2 * p->q;
            if (tmp >= 2 * p->q)
                tmp -= 2 * p->q;

            tmp = ((tmp + (1 << (p->d - 1))) >> p->d) % p->p; // uz

            // normalize in range
            tmp = z[i] - tmp;
            if (tmp < -p->p / 2)
                tmp += p->p;
            if (tmp > p->p / 2)
                tmp -= p->p;
            z[i] = tmp;
        }

        // return it
        for (i = 0; i < p->n; i++) {
            sign->t[i] = t[i];
            sign->z[i] = z[i];
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
    int32_t *v, *my_idx, tmp;
    const bliss_param_t *p;

    // check that signature and public key use the same parameters set
    if (sign->set != pub->set)
        return -1;

    p = &bliss_param[pub->set];

    // compute norms
    if (vecabsmax(sign->t, p->n) > p->b_inf ||
        (vecabsmax(sign->z, p->n) << p->d) > p->b_inf)
        return -2;

    if (vecscalar(sign->t, sign->t, p->n) +
        (vecscalar(sign->z, sign->z, p->n) << (2 * p->d)) > p->b_l2)
        return -3;

    // check the signature
    v = calloc(p->n + p->kappa, sizeof(int));
    if (v == NULL)
        return -4;
    my_idx = &v[p->n];

    // v = t * a (mod x^n + 1)
    for (i = 0; i < p->n; i++)
        v[i] = sign->t[i];

    ntt32_xmu(v, p->n, p->q, v, p->w);
    ntt32_fft(v, p->n, p->q, p->w);
    ntt32_xmu(v, p->n, p->q, v, pub->a);
    ntt32_fft(v, p->n, p->q, p->w);
    ntt32_xmu(v, p->n, p->q, v, p->r);
    ntt32_flp(v, p->n, p->q);

    // verification magic
    for (i = 0; i < p->n; i++) {
        if (v[i] & 1)       // old: v[i] = ((p->q + 1) * v[i]) % (2 * p->q);
            v[i] += p->q;
    }

    // v = v + C * q
    for (i = 0; i < p->kappa; i++)
        v[sign->c_idx[i]] = (v[sign->c_idx[i]] + p->q) % (2 * p->q);

    // drop bits and add z
    for (i = 0; i < p->n; i++) {
        tmp = (((v[i] + (1 << (p->d - 1))) >> p->d) + sign->z[i]) % p->p;
        if (tmp < 0)
            tmp += p->p;
        v[i] = tmp;
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

