#ifndef MLDSA44_ARDUINO_H
#define MLDSA44_ARDUINO_H

// ============================================================================
// MLDSA44: Arduino/ESP32 wrapper for NIST FIPS 204 ML-DSA-44 (mldsa-native v1.0.0-beta2)
//   Public key : 1,312 bytes   Secret key : 2,560 bytes   Signature : 2,420 bytes
// Pure ML-DSA with an empty context string. All functions return 0 on success.
// Randomness (hedged signing, generateKeypair) comes from the ESP32 hardware TRNG.
// ============================================================================

#include <stddef.h>
#include <stdint.h>

class MLDSA44 {
public:
  static const size_t SEED_SIZE       = 32;
  static const size_t PUBLIC_KEY_SIZE = 1312;
  static const size_t SECRET_KEY_SIZE = 2560;
  static const size_t SIGNATURE_SIZE  = 2420;

  // ML-DSA.KeyGen (FIPS 204 Alg. 1) using the hardware TRNG
  static int generateKeypair(uint8_t* pk, uint8_t* sk);

  // ML-DSA.KeyGen_internal (FIPS 204 Alg. 6): deterministic keypair from a 32-byte seed
  static int generateKeypairFromSeed(uint8_t* pk, uint8_t* sk, const uint8_t* seed);

  // ML-DSA.Sign (FIPS 204 Alg. 2), hedged, ctx = ""
  static int sign(uint8_t* sig, size_t* siglen, const uint8_t* msg, size_t msglen, const uint8_t* sk);

  // ML-DSA.Verify (FIPS 204 Alg. 3), ctx = ""; returns 0 if valid
  static int verify(const uint8_t* sig, size_t siglen, const uint8_t* msg, size_t msglen, const uint8_t* pk);
};

#endif // MLDSA44_ARDUINO_H
