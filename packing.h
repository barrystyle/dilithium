#ifndef MLDSA65_PACKING_H
#define MLDSA65_PACKING_H
#include "params.h"
#include "polyvec.h"
#include <stdint.h>

void MLDSA65_pack_pk(uint8_t pk[MLDSA65_CRYPTO_PUBLICKEYBYTES], const uint8_t rho[SEEDBYTES], const polyveck *t1);

void MLDSA65_pack_sk(uint8_t sk[MLDSA65_CRYPTO_SECRETKEYBYTES],
                                   const uint8_t rho[SEEDBYTES],
                                   const uint8_t tr[TRBYTES],
                                   const uint8_t key[SEEDBYTES],
                                   const polyveck *t0,
                                   const polyvecl *s1,
                                   const polyveck *s2);

void MLDSA65_pack_sig(uint8_t sig[MLDSA65_CRYPTO_BYTES], const uint8_t c[CTILDEBYTES], const polyvecl *z, const polyveck *h);

void MLDSA65_unpack_pk(uint8_t rho[SEEDBYTES], polyveck *t1, const uint8_t pk[MLDSA65_CRYPTO_PUBLICKEYBYTES]);

void MLDSA65_unpack_sk(uint8_t rho[SEEDBYTES],
                                     uint8_t tr[TRBYTES],
                                     uint8_t key[SEEDBYTES],
                                     polyveck *t0,
                                     polyvecl *s1,
                                     polyveck *s2,
                                     const uint8_t sk[MLDSA65_CRYPTO_SECRETKEYBYTES]);

int MLDSA65_unpack_sig(uint8_t c[CTILDEBYTES], polyvecl *z, polyveck *h, const uint8_t sig[MLDSA65_CRYPTO_BYTES]);

#endif
