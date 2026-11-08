#include "MLKEM512.h"

extern "C" {
#include "mlkem_native/mlkem_native.h"
}

static_assert(MLKEM512::PUBLIC_KEY_SIZE    == MLKEM512_PUBLICKEYBYTES,  "ek size mismatch");
static_assert(MLKEM512::SECRET_KEY_SIZE    == MLKEM512_SECRETKEYBYTES,  "dk size mismatch");
static_assert(MLKEM512::CIPHERTEXT_SIZE    == MLKEM512_CIPHERTEXTBYTES, "ct size mismatch");
static_assert(MLKEM512::SHARED_SECRET_SIZE == MLKEM512_BYTES,           "ss size mismatch");

int MLKEM512::generateKeypair(uint8_t* pk, uint8_t* sk) {
  return PQCP_MLKEM_NATIVE_MLKEM512_keypair(pk, sk);
}

int MLKEM512::generateKeypairFromSeed(uint8_t* pk, uint8_t* sk, const uint8_t* seed64) {
  return PQCP_MLKEM_NATIVE_MLKEM512_keypair_derand(pk, sk, seed64);
}

int MLKEM512::encapsulate(uint8_t* ct, uint8_t* ss, const uint8_t* pk) {
  return PQCP_MLKEM_NATIVE_MLKEM512_enc(ct, ss, pk);
}

int MLKEM512::decapsulate(uint8_t* ss, const uint8_t* ct, const uint8_t* sk) {
  return PQCP_MLKEM_NATIVE_MLKEM512_dec(ss, ct, sk);
}
