// sha3.h
// 19-Nov-11  Markku-Juhani O. Saarinen <m.saarinen@qub.ac.uk>

#ifndef SHA3_H
#define SHA3_H

#include <stddef.h>
#include <stdint.h>

#ifndef SHA3_ROUNDS
#define SHA3_ROUNDS 24
#endif

#ifndef ROTL64
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))
#endif

// State
typedef struct {
    union {
        uint8_t b[200];                     // 8-bit bytes
        uint64_t q[25];                     // 64-bit words
    } st;
    int pt, rsiz, mdlen;
} sha3_ctx_t;

// update the state
void keccakf(uint64_t st[25], int norounds);

// OpenSSL - like interfece
int sha3_init(sha3_ctx_t *c, int mdlen);
int sha3_update(sha3_ctx_t *c, const void *data, size_t len);
int sha3_final(void *md, sha3_ctx_t *c);

// compute a keccak hash (md) of given byte length from "in"
void *sha3(const void *in, size_t inlen, void *md, int mdlen);

#endif

