#ifndef SECURE_TUNNEL_H
#define SECURE_TUNNEL_H

#include <Arduino.h>
#include <WiFiClient.h>
#include "mbedtls/gcm.h"   // AES-GCM (ESP32 hardware AES accelerator via mbedtls)

// ============================================================================
// CLASS: SecureTunnel
// AES-256-GCM encrypted data tunnel keyed from the handshake's K_session.
//
// Directional keys (HKDF-Expand, RFC 5869, PRK = K_session):
//   K_c2s = HMAC-SHA256(K_session, "VPN-v1|TUNNEL|C2S" || 0x01)   ESP32 -> laptop
//   K_s2c = HMAC-SHA256(K_session, "VPN-v1|TUNNEL|S2C" || 0x01)   laptop -> ESP32
//
// Wire frame:  [2B LEN (BE)] [8B SEQ (BE)] [N B CIPHERTEXT] [16B GCM TAG]
//   LEN   = 8 + N + 16 (bytes following the length field)
//   Nonce = 4B direction ID (C2S=0x00000001, S2C=0x00000002) || 8B SEQ   (96-bit GCM IV)
//   AAD   = LEN || SEQ (10 B), so the header is authenticated too
//   SEQ starts at 0 and must increase by exactly 1 -> replayed / reordered / dropped
//   frames are rejected; per-direction keys + counters guarantee nonces never repeat.
// ============================================================================
class SecureTunnel {
public:
  static const size_t MAX_PLAINTEXT = 1024;
  static const size_t HEADER_SIZE   = 10;   // 2B LEN + 8B SEQ
  static const size_t TAG_SIZE      = 16;

  explicit SecureTunnel(WiFiClient& client);

  // Derives K_c2s / K_s2c from the 32-byte K_session and resets counters
  bool begin(const uint8_t* kSession);

  // Encrypts and sends one message (<= MAX_PLAINTEXT bytes)
  bool send(const uint8_t* plaintext, size_t len);

  // Non-blocking receive. Returns plaintext length (> 0) when a full frame was decrypted,
  // 0 if no complete frame yet, or -1 on authentication / framing / replay failure.
  int poll(uint8_t* out, size_t outMax);

  // Wipes keys and frees GCM contexts
  void end();

private:
  WiFiClient& _client;
  bool        _active;
  uint8_t     _kC2S[32];
  uint8_t     _kS2C[32];
  uint64_t    _txSeq;
  uint64_t    _rxSeq;
  mbedtls_gcm_context _txCtx;
  mbedtls_gcm_context _rxCtx;

  uint8_t _rxBuf[HEADER_SIZE + MAX_PLAINTEXT + TAG_SIZE];  // full incoming frame
  size_t  _rxHave;

  static void deriveKey(const uint8_t* kSession, const char* label, uint8_t* out);
  static void buildNonce(uint32_t dirId, uint64_t seq, uint8_t* nonce12);
};

#endif // SECURE_TUNNEL_H
