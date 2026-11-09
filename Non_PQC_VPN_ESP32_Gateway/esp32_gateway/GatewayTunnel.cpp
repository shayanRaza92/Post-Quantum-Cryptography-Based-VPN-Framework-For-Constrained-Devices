#include "GatewayTunnel.h"
#include <sodium.h>   // HMAC-SHA256 (HKDF-Expand) and sodium_memzero

static const uint32_t DIR_C2S = 0x00000001;  // client -> gateway
static const uint32_t DIR_S2C = 0x00000002;  // gateway -> client

static void writeU64BE(uint8_t* p, uint64_t v) {
  for (int i = 7; i >= 0; i--) { p[i] = (uint8_t)(v & 0xFF); v >>= 8; }
}

static uint64_t readU64BE(const uint8_t* p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
  return v;
}

static void buildNonce(uint32_t dirId, uint64_t seq, uint8_t nonce12[12]) {
  nonce12[0] = (uint8_t)(dirId >> 24);
  nonce12[1] = (uint8_t)(dirId >> 16);
  nonce12[2] = (uint8_t)(dirId >> 8);
  nonce12[3] = (uint8_t)(dirId);
  writeU64BE(nonce12 + 4, seq);
}

// HKDF-Expand (RFC 5869) single block: T1 = HMAC-SHA256(PRK = K_session, info || 0x01)
static void deriveKey(const uint8_t* kSession, const char* label, uint8_t out[32]) {
  crypto_auth_hmacsha256_state st;
  crypto_auth_hmacsha256_init(&st, kSession, 32);
  crypto_auth_hmacsha256_update(&st, (const unsigned char*)label, strlen(label));
  const uint8_t one = 0x01;
  crypto_auth_hmacsha256_update(&st, &one, 1);
  crypto_auth_hmacsha256_final(&st, out);
  sodium_memzero(&st, sizeof(st));
}

static bool validBodyLen(size_t bodyLen) {
  return bodyLen >= 8 + 1 + GatewayTunnel::TAG_SIZE &&
         bodyLen <= 8 + GatewayTunnel::MAX_PLAINTEXT + GatewayTunnel::TAG_SIZE;
}

GatewayTunnel::GatewayTunnel()
  : _active(false), _txSeq(0), _rxSeq(0), _rxHave(0), _error("") {
  memset(_kC2S, 0, sizeof(_kC2S));
  memset(_kS2C, 0, sizeof(_kS2C));
}

GatewayTunnel::~GatewayTunnel() {
  end();
}

bool GatewayTunnel::begin(const uint8_t kSession[32]) {
  end();
  deriveKey(kSession, "VPN-v1|TUNNEL|C2S", _kC2S);
  deriveKey(kSession, "VPN-v1|TUNNEL|S2C", _kS2C);

  mbedtls_gcm_init(&_txCtx);
  mbedtls_gcm_init(&_rxCtx);
  _active = true;  // Contexts exist from here on, so end() must free them
  if (mbedtls_gcm_setkey(&_txCtx, MBEDTLS_CIPHER_ID_AES, _kS2C, 256) != 0 ||   // we send S2C
      mbedtls_gcm_setkey(&_rxCtx, MBEDTLS_CIPHER_ID_AES, _kC2S, 256) != 0) {   // we receive C2S
    _error = "AES-256-GCM key setup failed";
    end();
    return false;
  }
  _txSeq = 0;
  _rxSeq = 0;
  _rxHave = 0;
  return true;
}

void GatewayTunnel::end() {
  if (_active) {
    mbedtls_gcm_free(&_txCtx);
    mbedtls_gcm_free(&_rxCtx);
  }
  sodium_memzero(_kC2S, sizeof(_kC2S));
  sodium_memzero(_kS2C, sizeof(_kS2C));
  sodium_memzero(_rxBuf, sizeof(_rxBuf));
  _txSeq = _rxSeq = 0;
  _rxHave = 0;
  _active = false;
}

size_t GatewayTunnel::seal(const uint8_t* plaintext, size_t len, uint8_t* frameOut) {
  if (!_active || len == 0 || len > MAX_PLAINTEXT) return 0;

  const size_t bodyLen = 8 + len + TAG_SIZE;          // bytes after the LEN field
  frameOut[0] = (uint8_t)(bodyLen >> 8);
  frameOut[1] = (uint8_t)(bodyLen & 0xFF);
  writeU64BE(frameOut + 2, _txSeq);

  uint8_t nonce[12];
  buildNonce(DIR_S2C, _txSeq, nonce);
  uint8_t* ct  = frameOut + HEADER_SIZE;
  uint8_t* tag = ct + len;
  if (mbedtls_gcm_crypt_and_tag(&_txCtx, MBEDTLS_GCM_ENCRYPT, len, nonce, sizeof(nonce),
                                frameOut, HEADER_SIZE,            // AAD = LEN || SEQ
                                plaintext, ct, TAG_SIZE, tag) != 0) {
    _error = "AES-GCM encrypt failed";
    return 0;
  }
  _txSeq++;
  return HEADER_SIZE + len + TAG_SIZE;
}

int GatewayTunnel::consume(const uint8_t* data, size_t len, size_t* used,
                           uint8_t* out, size_t* outLen, uint64_t* seqOut) {
  *used = 0;
  if (!_active) { _error = "tunnel not active"; return -1; }

  while (*used < len) {
    size_t need;
    if (_rxHave < 2) {
      need = 2 - _rxHave;
    } else {
      size_t bodyLen = ((size_t)_rxBuf[0] << 8) | _rxBuf[1];
      need = 2 + bodyLen - _rxHave;
    }
    size_t take = (len - *used < need) ? (len - *used) : need;
    memcpy(_rxBuf + _rxHave, data + *used, take);
    _rxHave += take;
    *used += take;

    if (_rxHave >= 2) {
      size_t bodyLen = ((size_t)_rxBuf[0] << 8) | _rxBuf[1];
      if (!validBodyLen(bodyLen)) {         // Memory / framing guard: closes only this session
        _error = "invalid frame length";
        return -1;
      }
      if (_rxHave == 2 + bodyLen) {
        return decryptFrame(out, outLen, seqOut);
      }
    }
  }
  return 0;
}

int GatewayTunnel::decryptFrame(uint8_t* out, size_t* outLen, uint64_t* seqOut) {
  const size_t bodyLen = ((size_t)_rxBuf[0] << 8) | _rxBuf[1];
  const uint64_t seq   = readU64BE(_rxBuf + 2);
  const size_t ctLen   = bodyLen - 8 - TAG_SIZE;
  const uint8_t* ct    = _rxBuf + HEADER_SIZE;
  const uint8_t* tag   = ct + ctLen;
  _rxHave = 0;   // The next consume() starts a new frame

  if (seq != _rxSeq) {
    _error = "replay/reorder detected (unexpected sequence number)";
    return -1;
  }
  uint8_t nonce[12];
  buildNonce(DIR_C2S, seq, nonce);
  if (mbedtls_gcm_auth_decrypt(&_rxCtx, ctLen, nonce, sizeof(nonce),
                               _rxBuf, HEADER_SIZE, tag, TAG_SIZE, ct, out) != 0) {
    sodium_memzero(out, ctLen);
    _error = "AES-GCM authentication FAILED (tampered frame)";
    return -1;
  }
  _rxSeq++;
  *outLen = ctLen;
  *seqOut = seq;
  return 1;
}
