// bliss.h
// 18-Jun-15  Markku-Juhani O. Saarinen <m.saarinen@qub.ac.uk>

#ifndef BLISS_H
#define BLISS_H

#include <stdint.h>
#include <stddef.h>

// parameter set

typedef struct {
    int q;                                  // field modulus
    int n;                                  // ring size (x^n+1)
    int d;                                  // bit drop shift
    int p;                                  // magic modulus
    int kappa;                              // index vector size
    int b_inf;                              // infinite norm
    int b_l2;                               // L2 norm
    int nz1;                                // nonzero +-1
    int nz2;                                // nonzero +-2
    int pmax;                               // derived from nt, nz2, n, kappa
    long double sig;                        // standard deviation
    long double m;                          // repetition rate
    const int *w;                           // n roots of unity (mod q)
    const int *r;                           // w[i]/n (mod q)
} bliss_param_t;

// parameter set constants
extern const bliss_param_t bliss_param[];   // standard types

// signature

typedef struct {
    int set;                                // parameter set
    int *t;                                 // signature t
    int *z;                                 // signature z
    int *c_idx;                             // signature oracle indeces for c
} bliss_signature_t;

// private key

typedef struct {
    int set;                                // parameter set
    int *f;                                 // sparse polynomial f
    int *g;                                 // sparse polynomial g
    int *a;                                 // NTT of f/g
} bliss_privkey_t;

// public key

typedef struct {
    int set;                                // parameter set
    int *a;                                 // NTT of f/g
} bliss_pubkey_t;

// prototypes; helper functions

int vecabsmax(const int32_t v[], int n);
int vecscalar(const int32_t t[], const int32_t u[], int n);


// Random oracle.
int bliss_c_oracle(int *c_idx, int kappa,
    const void *hash, size_t hash_len, const int *ud, int n);

// == PRIVKEY ==

// Free a private key.
void bliss_privkey_free(bliss_privkey_t *priv);

// Create an empty private key.
bliss_privkey_t *bliss_privkey_new(int set);

// Key generation. Return NULL on failure.
bliss_privkey_t *bliss_privkey_gen(int set);

// == PUBKEY ==

// Free a public key.
void bliss_pubkey_free(bliss_pubkey_t *pub);

// Create an empty public key.
bliss_pubkey_t *bliss_pubkey_new(int set);

// Derive a public key from a private key
bliss_pubkey_t *bliss_pubkey_frompriv(const bliss_privkey_t *priv);


// == SIGNATURE ==

// Free a signature.
void bliss_sign_free(bliss_signature_t *sign);

// Create an empty signature with given parameters.
bliss_signature_t *bliss_sign_new(int set);

// Sign a message.
bliss_signature_t *bliss_sign(const bliss_privkey_t *priv,
    const uint8_t *hash, size_t hash_len);

// Verify a signature. Return 0 if signature OK.
int bliss_verify(const bliss_signature_t *sign,
    const uint8_t *hash, size_t hash_len,
    const bliss_pubkey_t *pub);

#endif

