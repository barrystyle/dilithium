#ifndef MLDSA65_API_H
#define MLDSA65_API_H

#include <stddef.h>
#include <stdint.h>

#define MLDSA65_CRYPTO_SEEDBYTES 32
#define MLDSA65_CRYPTO_PUBLICKEYBYTES 1952
#define MLDSA65_CRYPTO_SECRETKEYBYTES 4032
#define MLDSA65_CRYPTO_BYTES 3309
#define MLDSA65_CRYPTO_ALGNAME "ML-DSA-65"

int MLDSA65_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

int MLDSA65_crypto_sign_signature_ctx(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *sk);

int MLDSA65_crypto_sign_ctx(uint8_t *sm, size_t *smlen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *sk);

int MLDSA65_crypto_sign_verify_ctx(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk);

int MLDSA65_crypto_sign_open_ctx(uint8_t *m, size_t *mlen,
        const uint8_t *sm, size_t smlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk);

int MLDSA65_crypto_sign_signature(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *sk);

int MLDSA65_crypto_sign(uint8_t *sm, size_t *smlen,
                                      const uint8_t *m, size_t mlen,
                                      const uint8_t *sk);

int MLDSA65_crypto_sign_verify(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *pk);

int MLDSA65_crypto_sign_open(uint8_t *m, size_t *mlen,
        const uint8_t *sm, size_t smlen,
        const uint8_t *pk);

int MLDSA65_crypto_sign_keypair_deterministic(uint8_t *pk, uint8_t *sk,
        const uint8_t* seed);

int MLDSA65_crypto_derive_pk(const uint8_t *sk, uint8_t *pk);

#endif
