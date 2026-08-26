#ifndef MLDSA65_POLYVEC_H
#define MLDSA65_POLYVEC_H
#include "params.h"
#include "poly.h"
#include <stdint.h>

/* Vectors of polynomials of length L */
typedef struct {
    poly vec[L];
} polyvecl;

void MLDSA65_polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce);

void MLDSA65_polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce);

void MLDSA65_polyvecl_reduce(polyvecl *v);

void MLDSA65_polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v);

void MLDSA65_polyvecl_ntt(polyvecl *v);
void MLDSA65_polyvecl_invntt_tomont(polyvecl *v);
void MLDSA65_polyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a, const polyvecl *v);
void MLDSA65_polyvecl_pointwise_acc_montgomery(poly *w,
        const polyvecl *u,
        const polyvecl *v);


int MLDSA65_polyvecl_chknorm(const polyvecl *v, int32_t B);



/* Vectors of polynomials of length K */
typedef struct {
    poly vec[K];
} polyveck;

void MLDSA65_polyveck_uniform_eta(polyveck *v, const uint8_t seed[CRHBYTES], uint16_t nonce);

void MLDSA65_polyveck_reduce(polyveck *v);
void MLDSA65_polyveck_caddq(polyveck *v);

void MLDSA65_polyveck_add(polyveck *w, const polyveck *u, const polyveck *v);
void MLDSA65_polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v);
void MLDSA65_polyveck_shiftl(polyveck *v);

void MLDSA65_polyveck_ntt(polyveck *v);
void MLDSA65_polyveck_invntt_tomont(polyveck *v);
void MLDSA65_polyveck_pointwise_poly_montgomery(polyveck *r, const poly *a, const polyveck *v);

int MLDSA65_polyveck_chknorm(const polyveck *v, int32_t B);

void MLDSA65_polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v);
void MLDSA65_polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v);
unsigned int MLDSA65_polyveck_make_hint(polyveck *h,
        const polyveck *v0,
        const polyveck *v1);
void MLDSA65_polyveck_use_hint(polyveck *w, const polyveck *v, const polyveck *h);

void MLDSA65_polyveck_pack_w1(uint8_t r[K * POLYW1_PACKEDBYTES], const polyveck *w1);

void MLDSA65_polyvec_matrix_expand(polyvecl mat[K], const uint8_t rho[SEEDBYTES]);

void MLDSA65_polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[K], const polyvecl *v);

#endif
