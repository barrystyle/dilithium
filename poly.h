#ifndef MLDSA65_POLY_H
#define MLDSA65_POLY_H
#include "params.h"
#include <stdint.h>

typedef struct {
    int32_t coeffs[N];
} poly;

void MLDSA65_poly_reduce(poly *a);
void MLDSA65_poly_caddq(poly *a);

void MLDSA65_poly_add(poly *c, const poly *a, const poly *b);
void MLDSA65_poly_sub(poly *c, const poly *a, const poly *b);
void MLDSA65_poly_shiftl(poly *a);

void MLDSA65_poly_ntt(poly *a);
void MLDSA65_poly_invntt_tomont(poly *a);
void MLDSA65_poly_pointwise_montgomery(poly *c, const poly *a, const poly *b);

void MLDSA65_poly_power2round(poly *a1, poly *a0, const poly *a);
void MLDSA65_poly_decompose(poly *a1, poly *a0, const poly *a);
unsigned int MLDSA65_poly_make_hint(poly *h, const poly *a0, const poly *a1);
void MLDSA65_poly_use_hint(poly *b, const poly *a, const poly *h);

int MLDSA65_poly_chknorm(const poly *a, int32_t B);
void MLDSA65_poly_uniform(poly *a,
                                        const uint8_t seed[SEEDBYTES],
                                        uint16_t nonce);
void MLDSA65_poly_uniform_eta(poly *a,
        const uint8_t seed[CRHBYTES],
        uint16_t nonce);
void MLDSA65_poly_uniform_gamma1(poly *a,
        const uint8_t seed[CRHBYTES],
        uint16_t nonce);
void MLDSA65_poly_challenge(poly *c, const uint8_t seed[CTILDEBYTES]);

void MLDSA65_polyeta_pack(uint8_t *r, const poly *a);
void MLDSA65_polyeta_unpack(poly *r, const uint8_t *a);

void MLDSA65_polyt1_pack(uint8_t *r, const poly *a);
void MLDSA65_polyt1_unpack(poly *r, const uint8_t *a);

void MLDSA65_polyt0_pack(uint8_t *r, const poly *a);
void MLDSA65_polyt0_unpack(poly *r, const uint8_t *a);

void MLDSA65_polyz_pack(uint8_t *r, const poly *a);
void MLDSA65_polyz_unpack(poly *r, const uint8_t *a);

void MLDSA65_polyw1_pack(uint8_t *r, const poly *a);

#endif
