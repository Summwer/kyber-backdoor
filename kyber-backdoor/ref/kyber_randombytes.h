#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>
#include "polyvec.h"

void kyber_randombytes(uint8_t *out, size_t outlen);
void implant_ss_to_seed(uint8_t *x, size_t xlen);
void implant_ct_to_t(polyvec *pkpv, polyvec *e,const uint8_t seed[32]);

void pack_sk(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk);

void unpack_pk(polyvec *pk, uint8_t seed[KYBER_SYMBYTES],
 const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES]);

#endif
