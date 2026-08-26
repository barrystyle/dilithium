#include "fips202.h"
#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "randombytes.h"
#include "sign.h"
#include "symmetric.h"
#include <stdint.h>

// the crypto_sign_keypair_deterministic/crypto_derive_pk routines were written by barrystyle
// and covered by copyright, but can be used freely as long as this header remains intact.

/*************************************************
* Name:        MLDSA65_crypto_sign_keypair
*
* Description: Generates public and private key.
*
* Arguments:   - uint8_t *pk: pointer to output public key (allocated
*                             array of MLDSA65_CRYPTO_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key (allocated
*                             array of MLDSA65_CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int MLDSA65_crypto_sign_keypair(uint8_t *pk, uint8_t *sk) {
    uint8_t seedbuf[2 * SEEDBYTES + CRHBYTES];
    uint8_t tr[TRBYTES];
    const uint8_t *rho, *rhoprime, *key;
    polyvecl mat[K];
    polyvecl s1, s1hat;
    polyveck s2, t1, t0;

    /* Get randomness for rho, rhoprime and key */
    randombytes(seedbuf, SEEDBYTES);
    seedbuf[SEEDBYTES + 0] = K;
    seedbuf[SEEDBYTES + 1] = L;
    shake256(seedbuf, 2 * SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES + 2);
    rho = seedbuf;
    rhoprime = rho + SEEDBYTES;
    key = rhoprime + CRHBYTES;

    /* Expand matrix */
    MLDSA65_polyvec_matrix_expand(mat, rho);

    /* Sample short vectors s1 and s2 */
    MLDSA65_polyvecl_uniform_eta(&s1, rhoprime, 0);
    MLDSA65_polyveck_uniform_eta(&s2, rhoprime, L);

    /* Matrix-vector multiplication */
    s1hat = s1;
    MLDSA65_polyvecl_ntt(&s1hat);
    MLDSA65_polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
    MLDSA65_polyveck_reduce(&t1);
    MLDSA65_polyveck_invntt_tomont(&t1);

    /* Add error vector s2 */
    MLDSA65_polyveck_add(&t1, &t1, &s2);

    /* Extract t1 and write public key */
    MLDSA65_polyveck_caddq(&t1);
    MLDSA65_polyveck_power2round(&t1, &t0, &t1);
    MLDSA65_pack_pk(pk, rho, &t1);

    /* Compute H(rho, t1) and write secret key */
    shake256(tr, TRBYTES, pk, MLDSA65_CRYPTO_PUBLICKEYBYTES);
    MLDSA65_pack_sk(sk, rho, tr, key, &t0, &s1, &s2);

    return 0;
}

/*************************************************
* Name:        crypto_sign_signature
*
* Description: Computes signature.
*
* Arguments:   - uint8_t *sig:   pointer to output signature (of length MLDSA65_CRYPTO_BYTES)
*              - size_t *siglen: pointer to output length of signature
*              - uint8_t *m:     pointer to message to be signed
*              - size_t mlen:    length of message
*              - uint8_t *ctx:   pointer to context string
*              - size_t ctxlen:  length of context string
*              - uint8_t *sk:    pointer to bit-packed secret key
*
* Returns 0 (success) or -1 (context string too long)
**************************************************/
int MLDSA65_crypto_sign_signature_ctx(uint8_t *sig,
        size_t *siglen,
        const uint8_t *m,
        size_t mlen,
        const uint8_t *ctx,
        size_t ctxlen,
        const uint8_t *sk) {
    unsigned int n;
    uint8_t seedbuf[2 * SEEDBYTES + TRBYTES + RNDBYTES + 2 * CRHBYTES];
    uint8_t *rho, *tr, *key, *mu, *rhoprime, *rnd;
    uint16_t nonce = 0;
    polyvecl mat[K], s1, y, z;
    polyveck t0, s2, w1, w0, h;
    poly cp;
    shake256incctx state;

    if (ctxlen > 255) {
        return -1;
    }

    rho = seedbuf;
    tr = rho + SEEDBYTES;
    key = tr + TRBYTES;
    rnd = key + SEEDBYTES;
    mu = rnd + RNDBYTES;
    rhoprime = mu + CRHBYTES;
    MLDSA65_unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

    /* Compute mu = CRH(tr, 0, ctxlen, ctx, msg) */
    mu[0] = 0;
    mu[1] = (uint8_t)ctxlen;
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, tr, TRBYTES);
    shake256_inc_absorb(&state, mu, 2);
    shake256_inc_absorb(&state, ctx, ctxlen);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    randombytes(rnd, RNDBYTES);
    shake256(rhoprime, CRHBYTES, key, SEEDBYTES + RNDBYTES + CRHBYTES);

    /* Expand matrix and transform vectors */
    MLDSA65_polyvec_matrix_expand(mat, rho);
    MLDSA65_polyvecl_ntt(&s1);
    MLDSA65_polyveck_ntt(&s2);
    MLDSA65_polyveck_ntt(&t0);

rej:
    /* Sample intermediate vector y */
    MLDSA65_polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

    /* Matrix-vector multiplication */
    z = y;
    MLDSA65_polyvecl_ntt(&z);
    MLDSA65_polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
    MLDSA65_polyveck_reduce(&w1);
    MLDSA65_polyveck_invntt_tomont(&w1);

    /* Decompose w and call the random oracle */
    MLDSA65_polyveck_caddq(&w1);
    MLDSA65_polyveck_decompose(&w1, &w0, &w1);
    MLDSA65_polyveck_pack_w1(sig, &w1);

    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, sig, K * POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(sig, CTILDEBYTES, &state);
    shake256_inc_ctx_release(&state);
    MLDSA65_poly_challenge(&cp, sig);
    MLDSA65_poly_ntt(&cp);

    /* Compute z, reject if it reveals secret */
    MLDSA65_polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
    MLDSA65_polyvecl_invntt_tomont(&z);
    MLDSA65_polyvecl_add(&z, &z, &y);
    MLDSA65_polyvecl_reduce(&z);
    if (MLDSA65_polyvecl_chknorm(&z, GAMMA1 - BETA)) {
        goto rej;
    }

    /* Check that subtracting cs2 does not change high bits of w and low bits
     * do not reveal secret information */
    MLDSA65_polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
    MLDSA65_polyveck_invntt_tomont(&h);
    MLDSA65_polyveck_sub(&w0, &w0, &h);
    MLDSA65_polyveck_reduce(&w0);
    if (MLDSA65_polyveck_chknorm(&w0, GAMMA2 - BETA)) {
        goto rej;
    }

    /* Compute hints for w1 */
    MLDSA65_polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
    MLDSA65_polyveck_invntt_tomont(&h);
    MLDSA65_polyveck_reduce(&h);
    if (MLDSA65_polyveck_chknorm(&h, GAMMA2)) {
        goto rej;
    }

    MLDSA65_polyveck_add(&w0, &w0, &h);
    n = MLDSA65_polyveck_make_hint(&h, &w0, &w1);
    if (n > OMEGA) {
        goto rej;
    }

    /* Write signature */
    MLDSA65_pack_sig(sig, sig, &z, &h);
    *siglen = MLDSA65_CRYPTO_BYTES;
    return 0;
}

/*************************************************
* Name:        crypto_sign
*
* Description: Compute signed message.
*
* Arguments:   - uint8_t *sm: pointer to output signed message (allocated
*                             array with MLDSA65_CRYPTO_BYTES + mlen bytes),
*                             can be equal to m
*              - size_t *smlen: pointer to output length of signed
*                               message
*              - const uint8_t *m: pointer to message to be signed
*              - size_t mlen: length of message
*              - const uint8_t *ctx: pointer to context string
*              - size_t ctxlen: length of context string
*              - const uint8_t *sk: pointer to bit-packed secret key
*
* Returns 0 (success) or -1 (context string too long)
**************************************************/
int MLDSA65_crypto_sign_ctx(uint8_t *sm,
        size_t *smlen,
        const uint8_t *m,
        size_t mlen,
        const uint8_t *ctx,
        size_t ctxlen,
        const uint8_t *sk) {
    int ret;
    size_t i;

    for (i = 0; i < mlen; ++i) {
        sm[MLDSA65_CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
    }
    ret = MLDSA65_crypto_sign_signature_ctx(sm, smlen, sm + MLDSA65_CRYPTO_BYTES, mlen, ctx, ctxlen, sk);
    *smlen += mlen;
    return ret;
}

/*************************************************
* Name:        crypto_sign_verify
*
* Description: Verifies signature.
*
* Arguments:   - uint8_t *m: pointer to input signature
*              - size_t siglen: length of signature
*              - const uint8_t *m: pointer to message
*              - size_t mlen: length of message
*              - const uint8_t *ctx: pointer to context string
*              - size_t ctxlen: length of context string
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signature could be verified correctly and -1 otherwise
**************************************************/
int MLDSA65_crypto_sign_verify_ctx(const uint8_t *sig,
        size_t siglen,
        const uint8_t *m,
        size_t mlen,
        const uint8_t *ctx,
        size_t ctxlen,
        const uint8_t *pk) {
    unsigned int i;
    uint8_t buf[K * POLYW1_PACKEDBYTES];
    uint8_t rho[SEEDBYTES];
    uint8_t mu[CRHBYTES];
    uint8_t c[CTILDEBYTES];
    uint8_t c2[CTILDEBYTES];
    poly cp;
    polyvecl mat[K], z;
    polyveck t1, w1, h;
    shake256incctx state;

    if (ctxlen > 255 || siglen != MLDSA65_CRYPTO_BYTES) {
        return -1;
    }

    MLDSA65_unpack_pk(rho, &t1, pk);
    if (MLDSA65_unpack_sig(c, &z, &h, sig)) {
        return -1;
    }
    if (MLDSA65_polyvecl_chknorm(&z, GAMMA1 - BETA)) {
        return -1;
    }

    /* Compute CRH(H(rho, t1), msg) */
    shake256(mu, TRBYTES, pk, MLDSA65_CRYPTO_PUBLICKEYBYTES);
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, TRBYTES);
    mu[0] = 0;
    mu[1] = (uint8_t)ctxlen;
    shake256_inc_absorb(&state, mu, 2);
    shake256_inc_absorb(&state, ctx, ctxlen);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    /* Matrix-vector multiplication; compute Az - c2^dt1 */
    MLDSA65_poly_challenge(&cp, c);
    MLDSA65_polyvec_matrix_expand(mat, rho);

    MLDSA65_polyvecl_ntt(&z);
    MLDSA65_polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

    MLDSA65_poly_ntt(&cp);
    MLDSA65_polyveck_shiftl(&t1);
    MLDSA65_polyveck_ntt(&t1);
    MLDSA65_polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

    MLDSA65_polyveck_sub(&w1, &w1, &t1);
    MLDSA65_polyveck_reduce(&w1);
    MLDSA65_polyveck_invntt_tomont(&w1);

    /* Reconstruct w1 */
    MLDSA65_polyveck_caddq(&w1);
    MLDSA65_polyveck_use_hint(&w1, &w1, &h);
    MLDSA65_polyveck_pack_w1(buf, &w1);

    /* Call random oracle and verify challenge */
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, buf, K * POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(c2, CTILDEBYTES, &state);
    shake256_inc_ctx_release(&state);
    for (i = 0; i < CTILDEBYTES; ++i) {
        if (c[i] != c2[i]) {
            return -1;
        }
    }

    return 0;
}

/*************************************************
* Name:        crypto_sign_open
*
* Description: Verify signed message.
*
* Arguments:   - uint8_t *m: pointer to output message (allocated
*                            array with smlen bytes), can be equal to sm
*              - size_t *mlen: pointer to output length of message
*              - const uint8_t *sm: pointer to signed message
*              - size_t smlen: length of signed message
*              - const uint8_t *ctx: pointer to context tring
*              - size_t ctxlen: length of context string
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signed message could be verified correctly and -1 otherwise
**************************************************/
int MLDSA65_crypto_sign_open_ctx(uint8_t *m,
        size_t *mlen,
        const uint8_t *sm,
        size_t smlen,
        const uint8_t *ctx,
        size_t ctxlen,
        const uint8_t *pk) {
    size_t i;

    if (smlen < MLDSA65_CRYPTO_BYTES) {
        goto badsig;
    }

    *mlen = smlen - MLDSA65_CRYPTO_BYTES;
    if (MLDSA65_crypto_sign_verify_ctx(sm, MLDSA65_CRYPTO_BYTES, sm + MLDSA65_CRYPTO_BYTES, *mlen, ctx, ctxlen, pk)) {
        goto badsig;
    } else {
        /* All good, copy msg, return 0 */
        for (i = 0; i < *mlen; ++i) {
            m[i] = sm[MLDSA65_CRYPTO_BYTES + i];
        }
        return 0;
    }

badsig:
    /* Signature verification failed */
    *mlen = 0;
    for (i = 0; i < smlen; ++i) {
        m[i] = 0;
    }

    return -1;
}

int MLDSA65_crypto_sign_signature(uint8_t *sig,
        size_t *siglen,
        const uint8_t *m,
        size_t mlen,
        const uint8_t *sk) {
    return MLDSA65_crypto_sign_signature_ctx(sig, siglen, m, mlen, NULL, 0, sk);
}

int MLDSA65_crypto_sign(uint8_t *sm,
                                      size_t *smlen,
                                      const uint8_t *m,
                                      size_t mlen,
                                      const uint8_t *sk) {
    return MLDSA65_crypto_sign_ctx(sm, smlen, m, mlen, NULL, 0, sk);
}

int MLDSA65_crypto_sign_verify(const uint8_t *sig,
        size_t siglen,
        const uint8_t *m,
        size_t mlen,
        const uint8_t *pk) {
    return MLDSA65_crypto_sign_verify_ctx(sig, siglen, m, mlen, NULL, 0, pk);
}

int MLDSA65_crypto_sign_open(uint8_t *m,
        size_t *mlen,
        const uint8_t *sm, size_t smlen,
        const uint8_t *pk) {
    return MLDSA65_crypto_sign_open_ctx(m, mlen, sm, smlen, NULL, 0, pk);
}

/*************************************************
* Name:        MLDSA65_crypto_sign_keypair_deterministic
*
* Description: Generates public and private key.
*
* Arguments:   - uint8_t *pk:    pointer to output public key (allocated
*                                array of MLDSA65_CRYPTO_PUBLICKEYBYTES bytes)
*              - uint8_t *sk:    pointer to output private key (allocated
*                                array of MLDSA65_CRYPTO_SECRETKEYBYTES bytes)
*              - uint8_t *seed:  pointer to array of uint8_t bytes for
*                                deterministic key generation (must be SEEDBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int MLDSA65_crypto_sign_keypair_deterministic(uint8_t *pk,
        uint8_t *sk, const uint8_t *seed) {
    uint8_t seedbuf[2 * SEEDBYTES + CRHBYTES];
    uint8_t tr[TRBYTES];
    const uint8_t *rho, *rhoprime, *key;
    polyvecl mat[K];
    polyvecl s1, s1hat;
    polyveck s2, t1, t0;

    /* Expand the user-supplied 32-byte seed deterministically */
    for (int i = 0; i < SEEDBYTES; i++)
         seedbuf[i] = seed[i];
    shake256(seedbuf, SEEDBYTES, seedbuf, SEEDBYTES);

    /* Get randomness for rho, rhoprime and key */
    seedbuf[SEEDBYTES + 0] = K;
    seedbuf[SEEDBYTES + 1] = L;
    shake256(seedbuf, 2 * SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES + 2);
    rho = seedbuf;
    rhoprime = rho + SEEDBYTES;
    key = rhoprime + CRHBYTES;

    /* Expand matrix */
    MLDSA65_polyvec_matrix_expand(mat, rho);

    /* Sample short vectors s1 and s2 */
    MLDSA65_polyvecl_uniform_eta(&s1, rhoprime, 0);
    MLDSA65_polyveck_uniform_eta(&s2, rhoprime, L);

    /* Matrix-vector multiplication */
    s1hat = s1;
    MLDSA65_polyvecl_ntt(&s1hat);
    MLDSA65_polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
    MLDSA65_polyveck_reduce(&t1);
    MLDSA65_polyveck_invntt_tomont(&t1);

    /* Add error vector s2 */
    MLDSA65_polyveck_add(&t1, &t1, &s2);

    /* Extract t1 and write public key */
    MLDSA65_polyveck_caddq(&t1);
    MLDSA65_polyveck_power2round(&t1, &t0, &t1);
    MLDSA65_pack_pk(pk, rho, &t1);

    /* Compute H(rho, t1) and write secret key */
    shake256(tr, TRBYTES, pk, MLDSA65_CRYPTO_PUBLICKEYBYTES);
    MLDSA65_pack_sk(sk, rho, tr, key, &t0, &s1, &s2);

    return 0;
}

/*************************************************
* Name:        MLDSA65_crypto_derive_pk
*
* Description: Derives public key from private key.
*
* Arguments:   - uint8_t *sk: pointer to input private key (allocated
*                             array of MLDSA65_CRYPTO_SECRETKEYBYTES bytes)
*              - uint8_t *pk: pointer to output public key (allocated
*                             array of MLDSA65_CRYPTO_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int MLDSA65_crypto_derive_pk(const uint8_t *sk, uint8_t *pk) {
    uint8_t seedbuf[2 * SEEDBYTES + TRBYTES + 2 * CRHBYTES];
    uint8_t *rho, *tr, *key;
    polyvecl mat[K], s1;
    polyveck t0, t1, s2;

    rho = seedbuf;
    tr = rho + SEEDBYTES;
    key = tr + TRBYTES;

    /* Unpack secret key */
    MLDSA65_unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

    /* Reconstruct t = s1*A + s2 (where A is derived from rho) */
    MLDSA65_polyvec_matrix_expand(mat, rho);
    MLDSA65_polyvecl_ntt(&s1);
    MLDSA65_polyvec_matrix_pointwise_montgomery(&t1, mat, &s1);
    MLDSA65_polyveck_reduce(&t1);
    MLDSA65_polyveck_invntt_tomont(&t1);
    MLDSA65_polyveck_add(&t1, &t1, &s2);

    /* Split t into t0 and t1 */
    MLDSA65_polyveck_caddq(&t1);
    MLDSA65_polyveck_power2round(&t1, &t0, &t1);

    /* Pack public key */
    MLDSA65_pack_pk(pk, rho, &t1);

    return 0;
}
