// main.c
// 06-May-15  Markku-Juhani O. Saarinen <m.saarinen@qub.ac.uk>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "sha3.h"
#include "ntt32.h"
#include "bliss.h"
#include "notrandom.h"
#include "distribution.h"

// test it

int main(int argc, char **argv)
{
    int i, set;
    bliss_privkey_t *priv;
    bliss_pubkey_t *pub;
    bliss_signature_t *sign;

    // data to be signed
    uint8_t data[] = "Lorem Ipsuxm.";
    uint8_t data_hash[64];

    // not a secure random
    gauss_init();

    // hash it
    sha3(data, sizeof(data), data_hash, 64);

    // loop over parameter sets
    for (set = 1; set <= 4; set++) {

        printf("CLASS %d x 1000\n", set);

        for (i = 0; i < 1000; i++) {

            // create a private key
            if ((priv = bliss_privkey_gen(set)) == NULL) {
                fprintf(stderr, "%04d/%d  bliss_privkey_gen()" , i, set);
                exit(1);
            }

            // derive public key from private key
            if ((pub = bliss_pubkey_frompriv(priv)) == NULL) {
                fprintf(stderr, "%04d/%d  bliss_pubkey_frompriv()" , i, set);
                exit(1);
            }

            // sign
            if ((sign = bliss_sign(priv, data_hash,
                64)) == NULL) {
                fprintf(stderr, "%04d/%d  bliss_sign()" , i, set);
                exit(1);
            }

            // verify
            if (bliss_verify(sign, data_hash, 64, pub)) {
                fprintf(stderr, "%04d/%d bliss_verify() FAIL.\n", i, set);
                exit(1);
            } else {
    //          printf("%d Signature OK.\n", i);
            }

            bliss_sign_free(sign);
            bliss_pubkey_free(pub);
            bliss_privkey_free(priv);
        }
    }

    return 0;
}

