#ifndef MLKEM512_ARDUINO_H
#define MLKEM512_ARDUINO_H

// ============================================================================
// MLKEM512: Arduino/ESP32 wrapper for NIST FIPS 203 ML-KEM-512 (mlkem-native v2.0.0)
// Mirrors the static-class style of the MLDSA44 wrapper used by the PQC VPN.
//
//   Encapsulation key (ek) : 800 bytes   (ByteEncode12(t_hat) 768 B || rho 32 B)
//   Decapsulation key (dk) : 1,632 bytes (dk_pke 768 B || ek 800 B || H(ek) 32 B || z 32 B)
//   Ciphertext (ct)        : 768 bytes   (c1 = Compress_10(u) 640 B || c2 = Compress_4(v) 128 B)
//   Shared secret (ss)     : 32 bytes
//
// All functions return 0 on success and a negative MLK_ERR_* code on failure.
// Randomness comes from the ESP32 hardware TRNG (see mlkem_native_config.h).
// ============================================================================

#include <stddef.h>
#include <stdint.h>

class MLKEM512 {
public:
  static const size_t PUBLIC_KEY_SIZE    = 800;   // Encapsulation key ek
  static const size_t SECRET_KEY_SIZE    = 1632;  // Decapsulation key dk
  static const size_t CIPHERTEXT_SIZE    = 768;   // KEM ciphertext ct
  static const size_t SHARED_SECRET_SIZE = 32;    // Shared secret K
  static const size_t KEYGEN_SEED_SIZE   = 64;    // d || z for deterministic keygen
  static const size_t ENCAPS_SEED_SIZE   = 32;    // m for deterministic encapsulation

  // ML-KEM.KeyGen (FIPS 203 Alg. 19) using the hardware TRNG
  static int generateKeypair(uint8_t* pk, uint8_t* sk);

  // ML-KEM.KeyGen_internal (FIPS 203 Alg. 16) from a 64-byte seed (d || z), for KATs
  static int generateKeypairFromSeed(uint8_t* pk, uint8_t* sk, const uint8_t* seed64);

  // ML-KEM.Encaps (FIPS 203 Alg. 20): includes the ek modulus check
  static int encapsulate(uint8_t* ct, uint8_t* ss, const uint8_t* pk);

  // ML-KEM.Decaps (FIPS 203 Alg. 21): implicit rejection on a tampered ciphertext
  static int decapsulate(uint8_t* ss, const uint8_t* ct, const uint8_t* sk);
};

#endif // MLKEM512_ARDUINO_H
