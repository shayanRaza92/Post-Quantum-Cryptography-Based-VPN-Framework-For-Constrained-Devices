#ifndef SECURE_CHANNEL_H
#define SECURE_CHANNEL_H

#include <Arduino.h>
#include <WiFiClient.h>
#include <sodium.h>        // HMAC-SHA256 key derivation, sodium_memzero
#include <mbedtls/gcm.h>   // AES-256-GCM (uses the ESP32 hardware AES accelerator)
#include "config.h"

// ============================================================================
// CLASS: SecureChannel
// Encrypted record layer for the data tunnel, keyed from the handshake's K_session.
//
// Directional keys (a different key per direction, so nonces never collide):
//   K_c2s = HMAC-SHA256(K_session, "VPN-v1|DATA|C2S")   ESP32 -> Server   (AES-256 key)
//   K_s2c = HMAC-SHA256(K_session, "VPN-v1|DATA|S2C")   Server -> ESP32   (AES-256 key)
//
// Wire record:
//   [2B Length (big-endian)] [8B Sequence (big-endian)] [Ciphertext || 16B GCM Tag]
//   Length = number of bytes after the length field (8 + ciphertext + 16)
//
// Cipher : AES-256-GCM (NIST SP 800-38D), 96-bit IV, 128-bit tag
// IV     : 4 zero bytes || 8B Sequence   (unique per key: the sequence never repeats)
// AAD    : the 10-byte header (Length || Sequence), so neither can be altered
// Replay : the receiver only accepts the exact next sequence number
// ============================================================================
class SecureChannel {
public:
  static constexpr size_t LEN_FIELD       = 2;
  static constexpr size_t SEQ_FIELD       = 8;
  static constexpr size_t HEADER_LEN      = LEN_FIELD + SEQ_FIELD;
  static constexpr size_t KEY_LEN         = 32;  // AES-256
  static constexpr size_t NONCE_LEN       = 12;  // 96-bit GCM IV
  static constexpr size_t TAG_LEN         = 16;  // 128-bit GCM tag
  static constexpr size_t MAX_RECORD_BODY = SEQ_FIELD + MAX_RECORD_PLAINTEXT + TAG_LEN;
  static constexpr size_t MAX_RECORD_WIRE = LEN_FIELD + MAX_RECORD_BODY;

  explicit SecureChannel(WiFiClient& client);
  ~SecureChannel();

  // Derives the two directional AES-256 keys from K_session and resets both sequence counters.
  bool begin(const uint8_t* sessionKey);

  // Wipes the keys and any partially received record (call when the tunnel closes).
  void reset();

  // Encrypts and transmits one record. Returns false if not ready, too large, or the write failed.
  // If wireOut is given (MAX_RECORD_WIRE bytes), the exact bytes sent are copied there for printing.
  bool send(const uint8_t* data, size_t len, uint8_t* wireOut = nullptr, size_t* wireLenOut = nullptr);

  // Reads whatever is available from the socket.
  //   returns  1 : one record was authenticated and decrypted into out (null-terminated)
  //   returns  0 : no complete record yet
  //   returns -1 : fatal (bad length, wrong sequence / replay, or GCM tag mismatch)
  int poll(uint8_t* out, size_t outSize, size_t* outLen);

  // Raw wire bytes of the record most recently returned by poll() (valid until the next poll)
  const uint8_t* lastRxRecord() const    { return _rxBuf; }
  size_t         lastRxRecordLen() const { return _lastRxLen; }

  // Directional data keys (for the tunnel key printout)
  const uint8_t* txKey() const { return _txKey; }
  const uint8_t* rxKey() const { return _rxKey; }

private:
  WiFiClient&         _client;
  uint8_t             _txKey[KEY_LEN];
  uint8_t             _rxKey[KEY_LEN];
  mbedtls_gcm_context _txGcm;
  mbedtls_gcm_context _rxGcm;
  uint64_t            _txSeq;
  uint64_t            _rxSeq;
  uint8_t             _rxBuf[MAX_RECORD_WIRE];
  size_t              _rxLen;
  size_t              _lastRxLen;
  bool                _ready;

  static void deriveKey(const uint8_t* sessionKey, const char* label, uint8_t* outKey);
  static void buildNonce(uint64_t seq, uint8_t* nonce);
  static void putSeq(uint64_t seq, uint8_t* out);
  static uint64_t getSeq(const uint8_t* in);
};

#endif // SECURE_CHANNEL_H
