#ifndef SECURE_TUNNEL_H
#define SECURE_TUNNEL_H

#include <Arduino.h>
#include <WiFiClient.h>
#include "mbedtls/gcm.h"   // AES-GCM (ESP32 hardware AES accelerator via mbedtls)

// ============================================================================
// CLASS: SecureTunnel
// AES-256-GCM encrypted data tunnel, run as a SECURITY ASSOCIATION (SA) that is bound to the
// authenticated handshake, with in-tunnel REKEYING (fresh key exchange -> a new SA).
//
// SA binding. After MSG 4 both sides compute the handshake hash
//   TH = SHA-256("VPN-v1|SA-BIND|" || MSG1 || MSG2 || MSG3 || MSG4 || PK_client || PK_gateway)
// (all four messages exactly as sent, plus both long-term public keys). Every SA is derived from
// TH and the current session key K (K_session, or the rekeyed key), HKDF-SHA256 (RFC 5869):
//   PRK   = HMAC-SHA256(key = TH, K)                                  (Extract, salt = TH)
//   SPI   = first 4 B of HMAC-SHA256(PRK, "VPN-v1|SA|SPI" || epoch (4B BE) || 0x01)
//   K_c2s = HMAC-SHA256(PRK, "VPN-v1|SA|C2S" || epoch (4B BE) || 0x01)   ESP32 -> gateway
//   K_s2c = HMAC-SHA256(PRK, "VPN-v1|SA|S2C" || epoch (4B BE) || 0x01)   gateway -> ESP32
// So the keys only exist for THIS handshake between THESE two identities. The SPI names the SA
// (as in IPsec); it is not sent, it is authenticated in every frame instead (AAD below).
//
// Wire frame:  [2B LEN (BE)] [8B SEQ (BE)] [N B CIPHERTEXT] [16B GCM TAG]
//   LEN   = 8 + N + 16 (bytes following the length field)
//   Nonce = 4B direction ID (C2S=0x00000001, S2C=0x00000002) || 8B SEQ   (96-bit GCM IV)
//   AAD   = SPI (4) || epoch (4B BE) || LEN || SEQ  (18 B): a frame is only valid in its own SA
//   SEQ starts at 0 and must increase by exactly 1 -> replayed / reordered / dropped
//   frames are rejected; per-direction keys + counters guarantee nonces never repeat.
//
// Plaintext of every frame:  [1B TYPE] [payload]
//   TYPE 0x01 DATA        payload = application message
//   TYPE 0x02 REKEY_REQ   payload = [4B epoch (BE)] [client ephemeral public key]   (ESP32 -> gateway)
//   TYPE 0x03 REKEY_RESP  payload = [4B epoch (BE)] [gateway key share]            (gateway -> ESP32)
//
// Rekey: both sides derive from the fresh shared secret SS of that exchange
//   PRK       = HMAC-SHA256(key = K_session_old, SS)
//   K_session = HMAC-SHA256(PRK, "VPN-v1|REKEY" || epoch (4B BE) || 0x01)
// then a NEW SA (new SPI, new K_c2s / K_s2c, still bound to TH) is installed, SEQ = 0 in both
// directions, and the old SA is deleted (its keys wiped).
// The REKEY messages travel inside the authenticated tunnel, so nobody else can trigger one.
// ============================================================================
class SecureTunnel {
public:
  static const size_t  MAX_PLAINTEXT  = 1024;  // Including the 1-byte TYPE
  static const size_t  MAX_PAYLOAD    = MAX_PLAINTEXT - 1;
  static const size_t  HEADER_SIZE    = 10;    // 2B LEN + 8B SEQ
  static const size_t  AAD_SIZE       = 18;    // SPI (4) + epoch (4) + header (10)
  static const size_t  TAG_SIZE       = 16;
  static const uint8_t MSG_DATA       = 0x01;
  static const uint8_t MSG_REKEY_REQ  = 0x02;
  static const uint8_t MSG_REKEY_RESP = 0x03;

  explicit SecureTunnel(WiFiClient& client);

  // Installs the first SA (epoch 0) from the 32-byte K_session and the 32-byte handshake hash TH
  bool begin(const uint8_t* kSession, const uint8_t* handshakeHash);

  // Encrypts and sends one DATA message (<= MAX_PAYLOAD bytes)
  bool send(const uint8_t* payload, size_t len);

  // Encrypts and sends one message of any TYPE (used for REKEY_REQ)
  bool sendTyped(uint8_t type, const uint8_t* payload, size_t len);

  // Non-blocking receive. Returns the payload length (> 0) when a full frame was decrypted
  // (its TYPE is then in lastType()), 0 if no complete frame yet, or -1 on
  // authentication / framing / replay failure or an empty / unknown message.
  int poll(uint8_t* out, size_t outMax);
  uint8_t lastType() const { return _lastType; }

  // Installs a new SA from the rekey exchange's shared secret and deletes the old one
  bool rekey(const uint8_t sharedSecret[32], uint32_t newEpoch);

  uint32_t      epoch()          const { return _epoch; }
  uint32_t      spi()            const { return _spi; }      // ID of the current SA
  uint64_t      framesSent()     const { return _txSeq; }   // Frames sent with the current keys
  unsigned long keyAgeMs()       const { return millis() - _keyStartMs; }

  // Deletes the SA: wipes keys and the handshake hash, frees GCM contexts
  void end();

private:
  WiFiClient& _client;
  bool        _active;
  uint8_t     _kSession[32];   // Current session master key (needed for the next rekey)
  uint8_t     _handshakeHash[32];  // TH: binds every SA to the authenticated handshake
  uint32_t    _spi;            // Security Parameter Index of the current SA
  uint8_t     _kC2S[32];
  uint8_t     _kS2C[32];
  uint64_t    _txSeq;
  uint64_t    _rxSeq;
  uint32_t    _epoch;
  unsigned long _keyStartMs;
  uint8_t     _lastType;
  mbedtls_gcm_context _txCtx;
  mbedtls_gcm_context _rxCtx;

  uint8_t _rxBuf[HEADER_SIZE + MAX_PLAINTEXT + TAG_SIZE];  // full incoming frame
  uint8_t _plainBuf[MAX_PLAINTEXT];                        // decrypted TYPE || payload
  size_t  _rxHave;

  bool installSA(const uint8_t* kSession, uint32_t epoch);
  void deleteSA();
  void buildAad(const uint8_t* header, uint8_t* aad) const;
  static void deriveKey(const uint8_t* prk, const char* label, uint32_t epoch, uint8_t* out);
  static void buildNonce(uint32_t dirId, uint64_t seq, uint8_t* nonce12);
};

#endif // SECURE_TUNNEL_H
