#include "SecureTunnel.h"
#include <sodium.h>   // HMAC-SHA256 (HKDF) and sodium_memzero

static const uint32_t DIR_C2S = 0x00000001;  // ESP32 -> laptop
static const uint32_t DIR_S2C = 0x00000002;  // laptop -> ESP32

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

static const char* typeName(uint8_t t) {
  switch (t) {
    case SecureTunnel::MSG_DATA:       return "DATA";
    case SecureTunnel::MSG_REKEY_REQ:  return "REKEY_REQ";
    case SecureTunnel::MSG_REKEY_RESP: return "REKEY_RESP";
    default:                           return "UNKNOWN";
  }
}

SecureTunnel::SecureTunnel(WiFiClient& client)
  : _client(client), _active(false), _txSeq(0), _rxSeq(0), _epoch(0), _keyStartMs(0),
    _lastType(0), _rxHave(0) {
  memset(_kSession, 0, sizeof(_kSession));
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
  sodium_memzero(&st, sizeof(st));
}

void SecureTunnel::buildNonce(uint32_t dirId, uint64_t seq, uint8_t* nonce12) {
  nonce12[0] = (uint8_t)(dirId >> 24);
  nonce12[1] = (uint8_t)(dirId >> 16);
  nonce12[2] = (uint8_t)(dirId >> 8);
  nonce12[3] = (uint8_t)(dirId);
  writeU64BE(nonce12 + 4, seq);
}

// Derives both direction keys from kSession, loads the GCM contexts, resets counters
bool SecureTunnel::installKeys(const uint8_t* kSession) {
  uint8_t copy[32];
  memcpy(copy, kSession, 32);   // kSession may point into _kSession, which end() wipes
  end();
  memcpy(_kSession, copy, 32);
  sodium_memzero(copy, sizeof(copy));

  deriveKey(_kSession, "VPN-v1|TUNNEL|C2S", _kC2S);
  deriveKey(_kSession, "VPN-v1|TUNNEL|S2C", _kS2C);

  mbedtls_gcm_init(&_txCtx);
  mbedtls_gcm_init(&_rxCtx);
  _active = true;   // Contexts exist from here on, so end() must free them
  if (mbedtls_gcm_setkey(&_txCtx, MBEDTLS_CIPHER_ID_AES, _kC2S, 256) != 0 ||
      mbedtls_gcm_setkey(&_rxCtx, MBEDTLS_CIPHER_ID_AES, _kS2C, 256) != 0) {
    Serial.println("[TUNNEL-ERROR] AES-256-GCM key setup failed.");
    end();
    return false;
  }
  _txSeq = 0;
  _rxSeq = 0;
  _rxHave = 0;
  _keyStartMs = millis();
  return true;
}

bool SecureTunnel::begin(const uint8_t* kSession) {
  if (!installKeys(kSession)) return false;
  _epoch = 0;

  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| AES-256-GCM TUNNEL KEYS (HKDF-Expand from K_session)                        |");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| K_c2s = HMAC-SHA256(K_session, \"VPN-v1|TUNNEL|C2S\" || 0x01)  ESP32->Laptop  |");
  printHexRow(_kC2S, 32);
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| K_s2c = HMAC-SHA256(K_session, \"VPN-v1|TUNNEL|S2C\" || 0x01)  Laptop->ESP32  |");
  printHexRow(_kS2C, 32);
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Frame: [2B LEN][8B SEQ][CIPHERTEXT][16B TAG]  Nonce = DIR(4B) || SEQ(8B)    |");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("  >> In plain words:");
  Serial.println("     Every message is now encrypted with AES-256-GCM. 'ciphertext' is what");
  Serial.println("     actually travels over Wi-Fi and is unreadable without the key. 'tag");
  Serial.println("     VALID' means the message was not changed on the way. 'msg #' must go up");
  Serial.println("     by exactly one, so old messages cannot be replayed. The keys are");
  Serial.println("     replaced regularly (REKEY) by a fresh key exchange inside the tunnel.");
  Serial.println();
  return true;
}

bool SecureTunnel::rekey(const uint8_t sharedSecret[32], uint32_t newEpoch) {
  if (!_active) return false;

  // PRK = HMAC-SHA256(key = K_session_old, SS)
  uint8_t prk[32];
  crypto_auth_hmacsha256_state st;
  crypto_auth_hmacsha256_init(&st, _kSession, 32);
  crypto_auth_hmacsha256_update(&st, sharedSecret, 32);
  crypto_auth_hmacsha256_final(&st, prk);

  // K_session_new = HMAC-SHA256(PRK, "VPN-v1|REKEY" || epoch (4B BE) || 0x01)
  const char* info = "VPN-v1|REKEY";
  uint8_t epochBE[4] = { (uint8_t)(newEpoch >> 24), (uint8_t)(newEpoch >> 16), (uint8_t)(newEpoch >> 8), (uint8_t)newEpoch };
  const uint8_t one = 0x01;
  uint8_t kNew[32];
  crypto_auth_hmacsha256_init(&st, prk, 32);
  crypto_auth_hmacsha256_update(&st, (const unsigned char*)info, strlen(info));
  crypto_auth_hmacsha256_update(&st, epochBE, 4);
  crypto_auth_hmacsha256_update(&st, &one, 1);
  crypto_auth_hmacsha256_final(&st, kNew);
  sodium_memzero(prk, sizeof(prk));
  sodium_memzero(&st, sizeof(st));

  bool ok = installKeys(kNew);   // Wipes the old keys, resets SEQ to 0 in both directions
  sodium_memzero(kNew, sizeof(kNew));
  if (!ok) return false;
  _epoch = newEpoch;

  Serial.printf("[REKEY] Epoch %lu installed: new K_session, new K_c2s / K_s2c, msg # reset to 0.\n",
                (unsigned long)_epoch);
  Serial.print ("        K_c2s = ");
  printHex(_kC2S, 8);
  Serial.print("...   K_s2c = ");
  printHex(_kS2C, 8);
  Serial.println("...  (old keys wiped)\n");
  return true;
}

bool SecureTunnel::send(const uint8_t* payload, size_t len) {
  return sendTyped(MSG_DATA, payload, len);
}

bool SecureTunnel::sendTyped(uint8_t type, const uint8_t* payload, size_t len) {
  if (!_active || len == 0 || len > MAX_PAYLOAD) return false;

  static uint8_t plain[MAX_PLAINTEXT];
  static uint8_t frame[HEADER_SIZE + MAX_PLAINTEXT + TAG_SIZE];
  const size_t ptLen = 1 + len;
  plain[0] = type;
  memcpy(plain + 1, payload, len);

  const size_t bodyLen = 8 + ptLen + TAG_SIZE;          // bytes after the LEN field
  frame[0] = (uint8_t)(bodyLen >> 8);
  frame[1] = (uint8_t)(bodyLen & 0xFF);
  writeU64BE(frame + 2, _txSeq);

  uint8_t nonce[12];
  buildNonce(DIR_C2S, _txSeq, nonce);

  uint8_t* ct  = frame + HEADER_SIZE;
  uint8_t* tag = ct + ptLen;
  int rc = mbedtls_gcm_crypt_and_tag(&_txCtx, MBEDTLS_GCM_ENCRYPT, ptLen,
                                     nonce, sizeof(nonce),
                                     frame, HEADER_SIZE,     // AAD = LEN || SEQ
                                     plain, ct, TAG_SIZE, tag);
  sodium_memzero(plain, ptLen);
  if (rc != 0) {
    Serial.printf("[TUNNEL-ERROR] AES-GCM encrypt failed (rc=%d)\n", rc);
    return false;
  }

  const size_t frameLen = HEADER_SIZE + ptLen + TAG_SIZE;
  size_t written = _client.write(frame, frameLen);

  Serial.printf("-> SENT encrypted %s msg #%llu (%u bytes over Wi-Fi, key epoch %lu)\n", typeName(type),
                (unsigned long long)_txSeq, (unsigned)frameLen, (unsigned long)_epoch);
  if (type == MSG_DATA) {
    Serial.printf("     message    : \"%.*s\"\n", (int)len, (const char*)payload);
  }
  Serial.print ("     ciphertext : ");
  printHex(ct, ptLen < 12 ? ptLen : 12);
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
      if (bodyLen < 8 + 2 + TAG_SIZE || bodyLen > 8 + MAX_PLAINTEXT + TAG_SIZE) {
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
  if (bodyLen < 8 + 2 + TAG_SIZE || bodyLen > 8 + MAX_PLAINTEXT + TAG_SIZE) return -1;
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
  if (ctLen - 1 > outMax) return -1;

  uint8_t nonce[12];
  buildNonce(DIR_S2C, seq, nonce);
  int rc = mbedtls_gcm_auth_decrypt(&_rxCtx, ctLen, nonce, sizeof(nonce),
                                    _rxBuf, HEADER_SIZE, tag, TAG_SIZE, ct, _plainBuf);
  if (rc != 0) {
    Serial.println("[TUNNEL-ERROR] AES-GCM authentication FAILED (tampered frame). Dropping session.");
    sodium_memzero(_plainBuf, ctLen);
    return -1;
  }
  _rxSeq++;

  _lastType = _plainBuf[0];
  const size_t payloadLen = ctLen - 1;
  if (_lastType != MSG_DATA && _lastType != MSG_REKEY_RESP) {
    Serial.printf("[TUNNEL-ERROR] Unexpected message type 0x%02X. Dropping session.\n", _lastType);
    sodium_memzero(_plainBuf, ctLen);
    return -1;
  }
  memcpy(out, _plainBuf + 1, payloadLen);
  sodium_memzero(_plainBuf, ctLen);

  Serial.printf("<- RECEIVED encrypted %s msg #%llu (%u bytes over Wi-Fi, key epoch %lu)\n", typeName(_lastType),
                (unsigned long long)seq, (unsigned)(HEADER_SIZE + ctLen + TAG_SIZE), (unsigned long)_epoch);
  Serial.print ("     ciphertext : ");
  printHex(ct, ctLen < 12 ? ctLen : 12);
  Serial.println("...  (unreadable without the key)");
  Serial.print ("     auth tag   : ");
  printHex(tag, TAG_SIZE);
  Serial.println("  -> VALID (not tampered)");
  if (_lastType == MSG_DATA) {
    Serial.printf("     decrypted  : \"%.*s\"\n\n", (int)payloadLen, (const char*)out);
  } else {
    Serial.println();
  }
  return (int)payloadLen;
}

void SecureTunnel::end() {
  if (_active) {
    mbedtls_gcm_free(&_txCtx);
    mbedtls_gcm_free(&_rxCtx);
  }
  sodium_memzero(_kSession, sizeof(_kSession));
  sodium_memzero(_kC2S, sizeof(_kC2S));
  sodium_memzero(_kS2C, sizeof(_kS2C));
  _txSeq = _rxSeq = 0;
  _rxHave = 0;
  _active = false;
}
