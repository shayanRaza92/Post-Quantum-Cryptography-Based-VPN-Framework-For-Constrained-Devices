/*
 * host_check.c - runs the firmware's ML-DSA-44/65/87 builds on the laptop.
 *
 * For each level it prints (hex, one value per line):
 *   PK   key pair from the fixed seed 0x00..0x1F (KeyGen_internal)
 *   SIG  deterministic signature (rnd = 0) of the fixed message 0x60..0x7F, empty context
 * and checks that the signature verifies, that a hedged signature verifies, and that a
 * signature with one flipped bit is rejected. gen_mldsa_vectors.py compares PK and SIG
 * byte for byte with dilithium-py (an independent FIPS 204 implementation).
 */
#include <stdio.h>
#include <string.h>
#include "MLDSA_Levels.h"

static void hex(const char *tag, int level, const uint8_t *b, size_t n) {
  printf("%s%d ", tag, level);
  for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
  printf("\n");
}

#define CHECK_LEVEL(L)                                                                   \
  do {                                                                                   \
    static uint8_t pk[DRONE_MLDSA##L##_PK_BYTES], sk[DRONE_MLDSA##L##_SK_BYTES];         \
    static uint8_t sig[DRONE_MLDSA##L##_SIG_BYTES];                                      \
    size_t siglen = 0;                                                                   \
    const uint8_t pre[2] = {0, 0}; /* FIPS 204: M' = 0 || |ctx| || ctx || M, ctx empty */ \
    if (DRONE_MLDSA##L##_keypair_internal(pk, sk, seed)) return 10;                      \
    if (DRONE_MLDSA##L##_signature_internal(sig, &siglen, msg, sizeof msg, pre, 2, zero, sk, 0)) \
      return 11;                                                                         \
    if (siglen != DRONE_MLDSA##L##_SIG_BYTES) return 12;                                 \
    hex("PK", L, pk, sizeof pk);                                                         \
    hex("SIG", L, sig, siglen);                                                          \
    if (DRONE_MLDSA##L##_verify(sig, siglen, msg, sizeof msg, NULL, 0, pk)) return 13;   \
    sig[0] ^= 1;                                                                         \
    if (!DRONE_MLDSA##L##_verify(sig, siglen, msg, sizeof msg, NULL, 0, pk)) return 14;  \
    if (DRONE_MLDSA##L##_signature(sig, &siglen, msg, sizeof msg, NULL, 0, sk)) return 15; \
    if (DRONE_MLDSA##L##_verify(sig, siglen, msg, sizeof msg, NULL, 0, pk)) return 16;   \
    printf("OK%d\n", L);                                                                 \
  } while (0)

int main(void) {
  uint8_t seed[32], msg[32], zero[32];
  for (int i = 0; i < 32; i++) {
    seed[i] = (uint8_t)i;
    msg[i] = (uint8_t)(0x60 + i);
    zero[i] = 0;
  }
  CHECK_LEVEL(44);
  CHECK_LEVEL(65);
  CHECK_LEVEL(87);
  return 0;
}
