/*
 * MLDSA_Levels.h - the public functions of the three ML-DSA builds in this library
 * (mldsa44_unit.c, mldsa65_unit.c, mldsa87_unit.c). Usable from C and C++.
 *
 * All functions return 0 on success. Pure ML-DSA (FIPS 204), as in mldsa-native:
 *   keypair_internal   : ML-DSA.KeyGen_internal (Alg. 6), key pair from a 32-byte seed
 *   keypair            : ML-DSA.KeyGen (Alg. 1), seed from the hardware random generator
 *   signature          : ML-DSA.Sign (Alg. 2), hedged (fresh randomness), context string ctx
 *   signature_internal : ML-DSA.Sign_internal (Alg. 7); with rnd = 32 zero bytes this is the
 *                        deterministic variant, used only for the known-answer test
 *   verify             : ML-DSA.Verify (Alg. 3)
 */
#ifndef DRONE_MLDSA_LEVELS_H
#define DRONE_MLDSA_LEVELS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Sizes in bytes (FIPS 204, Table 2) */
#define DRONE_MLDSA44_PK_BYTES 1312
#define DRONE_MLDSA44_SK_BYTES 2560
#define DRONE_MLDSA44_SIG_BYTES 2420
#define DRONE_MLDSA65_PK_BYTES 1952
#define DRONE_MLDSA65_SK_BYTES 4032
#define DRONE_MLDSA65_SIG_BYTES 3309
#define DRONE_MLDSA87_PK_BYTES 2592
#define DRONE_MLDSA87_SK_BYTES 4896
#define DRONE_MLDSA87_SIG_BYTES 4627

#define DRONE_MLDSA_DECLARE(L)                                                        \
  int DRONE_MLDSA##L##_keypair_internal(uint8_t *pk, uint8_t *sk, const uint8_t seed[32]); \
  int DRONE_MLDSA##L##_keypair(uint8_t *pk, uint8_t *sk);                             \
  int DRONE_MLDSA##L##_signature(uint8_t *sig, size_t *siglen, const uint8_t *m,      \
                                 size_t mlen, const uint8_t *ctx, size_t ctxlen,      \
                                 const uint8_t *sk);                                  \
  int DRONE_MLDSA##L##_signature_internal(uint8_t *sig, size_t *siglen,               \
                                          const uint8_t *m, size_t mlen,              \
                                          const uint8_t *pre, size_t prelen,          \
                                          const uint8_t rnd[32], const uint8_t *sk,   \
                                          int externalmu);                            \
  int DRONE_MLDSA##L##_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,    \
                              size_t mlen, const uint8_t *ctx, size_t ctxlen,         \
                              const uint8_t *pk);

DRONE_MLDSA_DECLARE(44)
DRONE_MLDSA_DECLARE(65)
DRONE_MLDSA_DECLARE(87)

#ifdef __cplusplus
}
#endif

#endif /* DRONE_MLDSA_LEVELS_H */
