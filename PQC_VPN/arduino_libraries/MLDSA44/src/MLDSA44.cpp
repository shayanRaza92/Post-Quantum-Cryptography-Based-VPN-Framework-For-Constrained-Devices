#include "MLDSA44.h"

extern "C" {
#include "mldsa_native/mldsa_native.h"
}

static_assert(MLDSA44::PUBLIC_KEY_SIZE == MLDSA44_PUBLICKEYBYTES, "pk size mismatch");
static_assert(MLDSA44::SECRET_KEY_SIZE == MLDSA44_SECRETKEYBYTES, "sk size mismatch");
static_assert(MLDSA44::SIGNATURE_SIZE  == MLDSA44_BYTES,          "sig size mismatch");
static_assert(MLDSA44::SEED_SIZE       == MLDSA_SEEDBYTES,        "seed size mismatch");

int MLDSA44::generateKeypair(uint8_t* pk, uint8_t* sk) {
  return PQCP_MLDSA_NATIVE_MLDSA44_keypair(pk, sk);
}

int MLDSA44::generateKeypairFromSeed(uint8_t* pk, uint8_t* sk, const uint8_t* seed) {
  return PQCP_MLDSA_NATIVE_MLDSA44_keypair_internal(pk, sk, seed);
}

int MLDSA44::sign(uint8_t* sig, size_t* siglen, const uint8_t* msg, size_t msglen, const uint8_t* sk) {
  return PQCP_MLDSA_NATIVE_MLDSA44_signature(sig, siglen, msg, msglen, nullptr, 0, sk);
}

int MLDSA44::verify(const uint8_t* sig, size_t siglen, const uint8_t* msg, size_t msglen, const uint8_t* pk) {
  return PQCP_MLDSA_NATIVE_MLDSA44_verify(sig, siglen, msg, msglen, nullptr, 0, pk);
}
