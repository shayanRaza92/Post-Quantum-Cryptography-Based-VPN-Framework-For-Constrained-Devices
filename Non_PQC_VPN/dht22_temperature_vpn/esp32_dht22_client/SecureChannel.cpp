#include "SecureChannel.h"

static const char* const LABEL_C2S = "VPN-v1|DATA|C2S";  // ESP32 -> Server
static const char* const LABEL_S2C = "VPN-v1|DATA|S2C";  // Server -> ESP32

SecureChannel::SecureChannel(WiFiClient& client)
  : _client(client), _txSeq(0), _rxSeq(0), _rxLen(0), _lastRxLen(0), _ready(false) {
  memset(_txKey, 0, sizeof(_txKey));
  memset(_rxKey, 0, sizeof(_rxKey));
  mbedtls_gcm_init(&_txGcm);
  mbedtls_gcm_init(&_rxGcm);
}

SecureChannel::~SecureChannel() {
  reset();
  mbedtls_gcm_free(&_txGcm);
  mbedtls_gcm_free(&_rxGcm);
}

// K = HMAC-SHA256(K_session, label)  -> 32 bytes = one AES-256 key
void SecureChannel::deriveKey(const uint8_t* sessionKey, const char* label, uint8_t* outKey) {
  crypto_auth_hmacsha256(outKey, (const unsigned char*)label, strlen(label), sessionKey);
}

void SecureChannel::putSeq(uint64_t seq, uint8_t* out) {
  for (int i = 7; i >= 0; i--) {
    out[i] = (uint8_t)(seq & 0xFF);
    seq >>= 8;
  }
}

uint64_t SecureChannel::getSeq(const uint8_t* in) {
  uint64_t seq = 0;
  for (int i = 0; i < 8; i++) seq = (seq << 8) | in[i];
  return seq;
}

// IV = 0x00000000 || 8B big-endian sequence number
void SecureChannel::buildNonce(uint64_t seq, uint8_t* nonce) {
  memset(nonce, 0, NONCE_LEN);
  putSeq(seq, nonce + (NONCE_LEN - SEQ_FIELD));
}

bool SecureChannel::begin(const uint8_t* sessionKey) {
  reset();
  deriveKey(sessionKey, LABEL_C2S, _txKey);
  deriveKey(sessionKey, LABEL_S2C, _rxKey);
  if (mbedtls_gcm_setkey(&_txGcm, MBEDTLS_CIPHER_ID_AES, _txKey, KEY_LEN * 8) != 0 ||
      mbedtls_gcm_setkey(&_rxGcm, MBEDTLS_CIPHER_ID_AES, _rxKey, KEY_LEN * 8) != 0) {
    reset();
    return false;
  }
  _ready = true;
  return true;
}

void SecureChannel::reset() {
  sodium_memzero(_txKey, sizeof(_txKey));
  sodium_memzero(_rxKey, sizeof(_rxKey));
  sodium_memzero(_rxBuf, sizeof(_rxBuf));
  // Free and re-init the GCM contexts so the expanded AES key schedules are wiped too
  mbedtls_gcm_free(&_txGcm);
  mbedtls_gcm_free(&_rxGcm);
  mbedtls_gcm_init(&_txGcm);
  mbedtls_gcm_init(&_rxGcm);
  _txSeq = 0;
  _rxSeq = 0;
  _rxLen = 0;
  _lastRxLen = 0;
  _ready = false;
}

bool SecureChannel::send(const uint8_t* data, size_t len, uint8_t* wireOut, size_t* wireLenOut) {
  if (!_ready || len > MAX_RECORD_PLAINTEXT) return false;

  uint8_t record[MAX_RECORD_WIRE];
  const size_t body = SEQ_FIELD + len + TAG_LEN;

  record[0] = (uint8_t)(body >> 8);
  record[1] = (uint8_t)(body & 0xFF);
  putSeq(_txSeq, record + LEN_FIELD);

  uint8_t nonce[NONCE_LEN];
  buildNonce(_txSeq, nonce);

  // Ciphertext goes right after the header, the 16-byte tag right after the ciphertext
  int rc = mbedtls_gcm_crypt_and_tag(
    &_txGcm, MBEDTLS_GCM_ENCRYPT, len,
    nonce, NONCE_LEN,
    record, HEADER_LEN,                // AAD = Length || Sequence
    data, record + HEADER_LEN,         // plaintext -> ciphertext
    TAG_LEN, record + HEADER_LEN + len // GCM tag
  );
  if (rc != 0) return false;
  _txSeq++;

  const size_t total = HEADER_LEN + len + TAG_LEN;
  size_t written = _client.write(record, total);
  if (wireOut != nullptr) {
    memcpy(wireOut, record, total);
    if (wireLenOut != nullptr) *wireLenOut = total;
  }
  sodium_memzero(record, sizeof(record));
  return written == total;
}

int SecureChannel::poll(uint8_t* out, size_t outSize, size_t* outLen) {
  if (!_ready) return 0;

  // Pull in bytes, but never past the end of the current record
  while (_client.available()) {
    size_t need;
    if (_rxLen < LEN_FIELD) {
      need = LEN_FIELD - _rxLen;
    } else {
      size_t body = ((size_t)_rxBuf[0] << 8) | _rxBuf[1];
      if (body < SEQ_FIELD + TAG_LEN || body > MAX_RECORD_BODY) return -1;  // malformed length
      need = LEN_FIELD + body - _rxLen;
      if (need == 0) break;                                                  // record complete
    }
    int n = _client.read(_rxBuf + _rxLen, need);
    if (n <= 0) break;
    _rxLen += (size_t)n;
  }

  if (_rxLen < LEN_FIELD) return 0;
  size_t body = ((size_t)_rxBuf[0] << 8) | _rxBuf[1];
  if (body < SEQ_FIELD + TAG_LEN || body > MAX_RECORD_BODY) return -1;
  if (_rxLen < LEN_FIELD + body) return 0;

  // Strict ordering: anything other than the next expected record is a replay or a drop
  uint64_t seq = getSeq(_rxBuf + LEN_FIELD);
  if (seq != _rxSeq) return -1;

  size_t plainLen = body - SEQ_FIELD - TAG_LEN;
  if (plainLen + 1 > outSize) return -1;

  uint8_t nonce[NONCE_LEN];
  buildNonce(seq, nonce);

  // Verifies the tag in constant time BEFORE releasing any plaintext
  int rc = mbedtls_gcm_auth_decrypt(
    &_rxGcm, plainLen,
    nonce, NONCE_LEN,
    _rxBuf, HEADER_LEN,                          // AAD = Length || Sequence
    _rxBuf + HEADER_LEN + plainLen, TAG_LEN,     // GCM tag
    _rxBuf + HEADER_LEN, out                     // ciphertext -> plaintext
  );
  if (rc != 0) {                                 // MBEDTLS_ERR_GCM_AUTH_FAILED: tampered or wrong key
    sodium_memzero(out, outSize);
    return -1;
  }

  out[plainLen] = 0;
  *outLen = plainLen;
  _rxSeq++;
  _lastRxLen = LEN_FIELD + body;  // Raw record stays in _rxBuf until the next poll()
  _rxLen = 0;
  return 1;
}
