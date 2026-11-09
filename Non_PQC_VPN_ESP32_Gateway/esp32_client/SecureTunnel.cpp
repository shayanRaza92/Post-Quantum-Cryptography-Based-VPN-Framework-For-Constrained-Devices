#include "SecureTunnel.h"
#include <sodium.h>   // HMAC-SHA256 (HKDF-Expand) and sodium_memzero

static const uint32_t DIR_C2S = 0x00000001;  // ESP32 -> gateway
static const uint32_t DIR_S2C = 0x00000002;  // gateway -> ESP32

static void printHex(const uint8_t* d, size_t n) {
  for (size_t i = 0; i < n; i++) {
    if (d[i] < 0x10) Serial.print("0");
    Serial.print(d[i], HEX);
  }
}

static void printHexRow(const uint8_t* data, size_t len) {
  Serial.print("| ");
  printHex(data, len);
  for (size_t i = len * 2; i < 75; i++) Serial.print(" ");
  Serial.println(" |");
}

static void writeU64BE(uint8_t* p, uint64_t v) {
  for (int i = 7; i >= 0; i--) { p[i] = (uint8_t)(v & 0xFF); v >>= 8; }
}

static uint64_t readU64BE(const uint8_t* p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
  return v;
}

SecureTunnel::SecureTunnel(WiFiClient& client)
  : _client(client), _active(false), _txSeq(0), _rxSeq(0), _rxHave(0) {
  memset(_kC2S, 0, sizeof(_kC2S));
  memset(_kS2C, 0, sizeof(_kS2C));
  mbedtls_gcm_init(&_txCtx);
  mbedtls_gcm_init(&_rxCtx);
}

// HKDF-Expand (RFC 5869) single block: T1 = HMAC-SHA256(PRK = K_session, info || 0x01)
void SecureTunnel::deriveKey(const uint8_t* kSession, const char* label, uint8_t* out) {
  crypto_auth_hmacsha256_state st;
  crypto_auth_hmacsha256_init(&st, kSession, 32);
  crypto_auth_hmacsha256_update(&st, (const unsigned char*)label, strlen(label));
  const uint8_t one = 0x01;
  crypto_auth_hmacsha256_update(&st, &one, 1);
  crypto_auth_hmacsha256_final(&st, out);
}

void SecureTunnel::buildNonce(uint32_t dirId, uint64_t seq, uint8_t* nonce12) {
  nonce12[0] = (uint8_t)(dirId >> 24);
  nonce12[1] = (uint8_t)(dirId >> 16);
  nonce12[2] = (uint8_t)(dirId >> 8);
  nonce12[3] = (uint8_t)(dirId);
  writeU64BE(nonce12 + 4, seq);
}

bool SecureTunnel::begin(const uint8_t* kSession) {
  end();
  deriveKey(kSession, "VPN-v1|TUNNEL|C2S", _kC2S);
  deriveKey(kSession, "VPN-v1|TUNNEL|S2C", _kS2C);

  mbedtls_gcm_init(&_txCtx);
  mbedtls_gcm_init(&_rxCtx);
  if (mbedtls_gcm_setkey(&_txCtx, MBEDTLS_CIPHER_ID_AES, _kC2S, 256) != 0 ||
      mbedtls_gcm_setkey(&_rxCtx, MBEDTLS_CIPHER_ID_AES, _kS2C, 256) != 0) {
    Serial.println("[TUNNEL-ERROR] AES-256-GCM key setup failed.");
    end();
    return false;
  }
  _txSeq = 0;
  _rxSeq = 0;
  _rxHave = 0;
  _active = true;

  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| AES-256-GCM TUNNEL KEYS (HKDF-Expand from K_session)                        |");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| K_c2s = HMAC-SHA256(K_session, \"VPN-v1|TUNNEL|C2S\" || 0x01)  ESP32->Gateway  |");
  printHexRow(_kC2S, 32);
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| K_s2c = HMAC-SHA256(K_session, \"VPN-v1|TUNNEL|S2C\" || 0x01)  Gateway->ESP32  |");
  printHexRow(_kS2C, 32);
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Frame: [2B LEN][8B SEQ][CIPHERTEXT][16B TAG]  Nonce = DIR(4B) || SEQ(8B)    |");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("  >> In plain words:");
  Serial.println("     Every message is now encrypted with AES-256-GCM. 'ciphertext' is what");
  Serial.println("     actually travels over Wi-Fi and is unreadable without the key. 'tag");
  Serial.println("     VALID' means the message was not changed on the way. 'msg #' must go up");
  Serial.println("     by exactly one, so old messages cannot be replayed.");
  Serial.println();
  return true;
}

bool SecureTunnel::send(const uint8_t* plaintext, size_t len) {
  if (!_active || len == 0 || len > MAX_PLAINTEXT) return false;

  static uint8_t frame[HEADER_SIZE + MAX_PLAINTEXT + TAG_SIZE];
  const size_t bodyLen = 8 + len + TAG_SIZE;          // bytes after the LEN field
  frame[0] = (uint8_t)(bodyLen >> 8);
  frame[1] = (uint8_t)(bodyLen & 0xFF);
  writeU64BE(frame + 2, _txSeq);

  uint8_t nonce[12];
  buildNonce(DIR_C2S, _txSeq, nonce);

  uint8_t* ct  = frame + HEADER_SIZE;
  uint8_t* tag = ct + len;
  int rc = mbedtls_gcm_crypt_and_tag(&_txCtx, MBEDTLS_GCM_ENCRYPT, len,
                                     nonce, sizeof(nonce),
                                     frame, HEADER_SIZE,     // AAD = LEN || SEQ
                                     plaintext, ct, TAG_SIZE, tag);
  if (rc != 0) {
    Serial.printf("[TUNNEL-ERROR] AES-GCM encrypt failed (rc=%d)\n", rc);
    return false;
  }

  const size_t frameLen = HEADER_SIZE + len + TAG_SIZE;
  size_t written = _client.write(frame, frameLen);

  Serial.printf("-> SENT encrypted msg #%llu (%u bytes over Wi-Fi)\n", (unsigned long long)_txSeq, (unsigned)frameLen);
  Serial.printf("     message    : \"%.*s\"\n", (int)len, (const char*)plaintext);
  Serial.print ("     ciphertext : ");
  printHex(ct, len < 12 ? len : 12);
  Serial.print ("...  (nonce ");
  printHex(nonce, 12);
  Serial.println(")");

  _txSeq++;
  return written == frameLen;
}

int SecureTunnel::poll(uint8_t* out, size_t outMax) {
  if (!_active) return -1;

  // Accumulate bytes until a complete frame is buffered
  while (_client.available()) {
    size_t need;
    if (_rxHave < 2) {
      need = 2 - _rxHave;
    } else {
      size_t bodyLen = ((size_t)_rxBuf[0] << 8) | _rxBuf[1];
      if (bodyLen < 8 + 1 + TAG_SIZE || bodyLen > 8 + MAX_PLAINTEXT + TAG_SIZE) {
        Serial.printf("[TUNNEL-ERROR] Invalid frame length %u. Dropping session.\n", (unsigned)bodyLen);
        return -1;
      }
      need = 2 + bodyLen - _rxHave;
      if (need == 0) break;
    }
    int got = _client.read(_rxBuf + _rxHave, need);
    if (got <= 0) break;
    _rxHave += (size_t)got;
    if (_rxHave >= 2) {
      size_t bodyLen = ((size_t)_rxBuf[0] << 8) | _rxBuf[1];
      if (_rxHave == 2 + bodyLen) break;  // full frame ready
    }
  }

  if (_rxHave < 2) return 0;
  size_t bodyLen = ((size_t)_rxBuf[0] << 8) | _rxBuf[1];
  if (bodyLen < 8 + 1 + TAG_SIZE || bodyLen > 8 + MAX_PLAINTEXT + TAG_SIZE) return -1;
  if (_rxHave < 2 + bodyLen) return 0;

  // Full frame: [LEN][SEQ][CT][TAG]
  const uint64_t seq = readU64BE(_rxBuf + 2);
  const size_t ctLen = bodyLen - 8 - TAG_SIZE;
  const uint8_t* ct  = _rxBuf + HEADER_SIZE;
  const uint8_t* tag = ct + ctLen;
  _rxHave = 0;

  if (seq != _rxSeq) {
    Serial.printf("[TUNNEL-ERROR] Replay/reorder detected (got seq=%llu, expected %llu). Dropping session.\n",
                  (unsigned long long)seq, (unsigned long long)_rxSeq);
    return -1;
  }
  if (ctLen > outMax) return -1;

  uint8_t nonce[12];
  buildNonce(DIR_S2C, seq, nonce);
  int rc = mbedtls_gcm_auth_decrypt(&_rxCtx, ctLen, nonce, sizeof(nonce),
                                    _rxBuf, HEADER_SIZE, tag, TAG_SIZE, ct, out);
  if (rc != 0) {
    Serial.println("[TUNNEL-ERROR] AES-GCM authentication FAILED (tampered frame). Dropping session.");
    sodium_memzero(out, ctLen);
    return -1;
  }

  Serial.printf("<- RECEIVED encrypted msg #%llu (%u bytes over Wi-Fi)\n", (unsigned long long)seq, (unsigned)(HEADER_SIZE + ctLen + TAG_SIZE));
  Serial.print ("     ciphertext : ");
  printHex(ct, ctLen < 12 ? ctLen : 12);
  Serial.println("...  (unreadable without the key)");
  Serial.print ("     auth tag   : ");
  printHex(tag, TAG_SIZE);
  Serial.println("  -> VALID (not tampered)");
  Serial.printf("     decrypted  : \"%.*s\"\n\n", (int)ctLen, (const char*)out);

  _rxSeq++;
  return (int)ctLen;
}

void SecureTunnel::end() {
  if (_active) {
    mbedtls_gcm_free(&_txCtx);
    mbedtls_gcm_free(&_rxCtx);
  }
  sodium_memzero(_kC2S, sizeof(_kC2S));
  sodium_memzero(_kS2C, sizeof(_kS2C));
  _txSeq = _rxSeq = 0;
  _rxHave = 0;
  _active = false;
}
