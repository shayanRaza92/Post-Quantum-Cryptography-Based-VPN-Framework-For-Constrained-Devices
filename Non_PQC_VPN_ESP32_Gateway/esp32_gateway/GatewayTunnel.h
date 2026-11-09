#ifndef GATEWAY_TUNNEL_H
#define GATEWAY_TUNNEL_H

#include <Arduino.h>
#include "mbedtls/gcm.h"   // AES-GCM (ESP32 hardware AES accelerator via mbedtls)

// ============================================================================
// CLASS: GatewayTunnel
// Gateway side of the AES-256-GCM data tunnel (mirror of esp32_client/SecureTunnel).
// One instance per client session; it never touches the socket itself, so the
// session decides how bytes are read and sent.
//
// Directional keys (HKDF-Expand, RFC 5869, PRK = K_session):
//   K_c2s = HMAC-SHA256(K_session, "VPN-v1|TUNNEL|C2S" || 0x01)   client -> gateway (we decrypt)
//   K_s2c = HMAC-SHA256(K_session, "VPN-v1|TUNNEL|S2C" || 0x01)   gateway -> client (we encrypt)
//
// Wire frame:  [2B LEN (BE)] [8B SEQ (BE)] [N B CIPHERTEXT] [16B GCM TAG]
//   LEN   = 8 + N + 16,   1 <= N <= MAX_PLAINTEXT
//   Nonce = 4B direction ID (C2S=1, S2C=2) || 8B SEQ
//   AAD   = LEN || SEQ, so the header is authenticated too
//   SEQ starts at 0 and must increase by exactly 1 (replay / reorder protection)
// ============================================================================
class GatewayTunnel {
public:
  static const size_t MAX_PLAINTEXT = 1024;
  static const size_t HEADER_SIZE   = 10;   // 2B LEN + 8B SEQ
  static const size_t TAG_SIZE      = 16;
  static const size_t MAX_FRAME     = HEADER_SIZE + MAX_PLAINTEXT + TAG_SIZE;

  GatewayTunnel();
  ~GatewayTunnel();

  bool begin(const uint8_t kSession[32]);   // Derives K_c2s / K_s2c, resets counters
  void end();                               // Wipes keys and frees GCM contexts

  // Encrypts one message into frameOut (MAX_FRAME bytes). Returns the frame length, or 0 on error.
  size_t seal(const uint8_t* plaintext, size_t len, uint8_t* frameOut);

  // Feeds received bytes. Consumes up to `len` bytes and reports how many in *used.
  // Returns 1 when one complete frame was authenticated and decrypted into `out`
  // (length *outLen, sequence *seqOut), 0 if more bytes are needed, -1 on
  // framing / replay / authentication failure (see lastError()).
  int consume(const uint8_t* data, size_t len, size_t* used,
              uint8_t* out, size_t* outLen, uint64_t* seqOut);

  const char* lastError() const { return _error; }
  uint64_t lastTxSeq() const { return _txSeq - 1; }
  const uint8_t* lastFrameCiphertext() const { return _rxBuf + HEADER_SIZE; }  // Valid right after consume()==1
  const uint8_t* keyC2S() const { return _kC2S; }
  const uint8_t* keyS2C() const { return _kS2C; }

private:
  bool        _active;
  uint8_t     _kC2S[32];
  uint8_t     _kS2C[32];
  uint64_t    _txSeq;
  uint64_t    _rxSeq;
  mbedtls_gcm_context _txCtx;
  mbedtls_gcm_context _rxCtx;
  uint8_t     _rxBuf[MAX_FRAME];
  size_t      _rxHave;
  const char* _error;

  int decryptFrame(uint8_t* out, size_t* outLen, uint64_t* seqOut);
};

#endif // GATEWAY_TUNNEL_H
