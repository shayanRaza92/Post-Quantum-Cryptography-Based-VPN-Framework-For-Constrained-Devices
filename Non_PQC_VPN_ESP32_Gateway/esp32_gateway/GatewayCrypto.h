#ifndef GATEWAY_CRYPTO_H
#define GATEWAY_CRYPTO_H

#include <Arduino.h>
#include <sodium.h>   // libsodium (bundled with the ESP32 Arduino core)

// ============================================================================
// CLASS: GatewayCrypto
// Same cryptography as laptop_server/crypto_engine.py, in C++ with libsodium:
//   Ed25519 identity signatures, X25519 ephemeral key exchange,
//   HKDF-SHA256 key schedule, HMAC-SHA256 key confirmation, SHA-256 transcripts.
// The identity key is read-only after begin(), so all session tasks can share it.
// ============================================================================
class GatewayCrypto {
private:
  uint8_t _publicKey[crypto_sign_PUBLICKEYBYTES];  // 32-byte gateway Ed25519 public key
  uint8_t _secretKey[crypto_sign_SECRETKEYBYTES];  // 64-byte gateway Ed25519 secret key

public:
  void begin(const uint8_t seed[32]);              // Derives the identity keypair from the fixed seed
  const uint8_t* publicKey() const { return _publicKey; }

  // Signs a 32-byte transcript digest with the gateway identity key
  void sign(const uint8_t* digest, size_t len, uint8_t signatureOut[64]) const;

  // Verifies a client's Ed25519 signature against its registered public key
  static bool verify(const uint8_t* publicKey, const uint8_t* signature, const uint8_t* digest, size_t len);

  // Server Transcript: SHA-256("VPN-v1|SERVER|" || MSG1 (82B) || ServerNonce (32B) || ServerEphPk (32B))
  static void serverTranscript(const uint8_t* msg1, const uint8_t* serverNonce,
                               const uint8_t* serverEphPk, uint8_t out[32]);

  // Client Transcript: SHA-256("VPN-v1|CLIENT|" || MSG1 (82B) || MSG2 (128B))
  static void clientTranscript(const uint8_t* msg1, const uint8_t* msg2, uint8_t out[32]);

  // HKDF-SHA256 (RFC 5869): salt = SHA-256(N_cli || N_srv); outputs K_confirm (T1) and K_session (T2)
  static void deriveSessionKeys(const uint8_t sharedSecret[32], const uint8_t* clientNonce,
                                const uint8_t* serverNonce, uint8_t kConfirm[32], uint8_t kSession[32]);

  // HMAC-SHA256(K_confirm, roleLabel || transcriptDigest)
  static void confirmationTag(const uint8_t kConfirm[32], const char* roleLabel,
                              const uint8_t transcriptDigest[32], uint8_t out[32]);
};

#endif // GATEWAY_CRYPTO_H
