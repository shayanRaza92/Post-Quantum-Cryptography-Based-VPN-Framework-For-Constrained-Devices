#include "GatewaySession.h"
#include "VpnGateway.h"
#include "GatewayCrypto.h"
#include <lwip/sockets.h>
#include <errno.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static bool isRetryableSocketError(int err) {
  return err == EAGAIN || err == EWOULDBLOCK || err == EINTR;
}

GatewaySession::GatewaySession(int sock, uint32_t ipAddr, const char* ipStr, uint16_t port, VpnGateway& gateway)
  : _sock(sock), _ipAddr(ipAddr), _gateway(gateway), _handshakeSlotHeld(true),
    _terminated(false), _terminateReason(nullptr), _clientPublicKey(nullptr), _deadline(0) {
  snprintf(_peer, sizeof(_peer), "%s:%u", ipStr, (unsigned)port);
  memset(_deviceId, 0, sizeof(_deviceId));
  memset(_msg1, 0, sizeof(_msg1));
  memset(_msg2, 0, sizeof(_msg2));
  memset(_clientTranscriptDigest, 0, sizeof(_clientTranscriptDigest));
  memset(_kConfirm, 0, sizeof(_kConfirm));
  memset(_kSession, 0, sizeof(_kSession));
}

GatewaySession::~GatewaySession() {
  sodium_memzero(_kConfirm, sizeof(_kConfirm));
  sodium_memzero(_kSession, sizeof(_kSession));
}

void GatewaySession::taskEntry(void* arg) {
  GatewaySession* session = static_cast<GatewaySession*>(arg);
  session->run();
  delete session;
  vTaskDelete(NULL);  // A FreeRTOS task must never return
}

void GatewaySession::terminate(const char* reason) {
  _terminateReason = reason;
  _terminated = true;
  shutdown(_sock, SHUT_RDWR);  // Wakes this session's blocked recv() in its own task
}

void GatewaySession::releaseHandshakeSlot() {
  if (_handshakeSlotHeld) {
    _handshakeSlotHeld = false;
    _gateway.releaseHandshake(_ipAddr);
  }
}

// ----------------------------------------------------------------------------
// LIFECYCLE
// ----------------------------------------------------------------------------
void GatewaySession::run() {
  bool authenticated = performHandshake();
  releaseHandshakeSlot();  // Free the slot as soon as the handshake ends (pass or fail)

  char header[64];
  snprintf(header, sizeof(header), "%s @ %s", _deviceId[0] ? _deviceId : "unknown-device", _peer);
  _log.flush(header);

  if (authenticated) {
    _gateway.registry().registerSession(_deviceId, this);
    runTunnel();
    // Unregister BEFORE closing the socket: once unregistered nobody can call terminate()
    // on us, so a recycled socket number can never be shut down by mistake.
    _gateway.registry().unregisterSession(_deviceId, this);
  }

  close(_sock);
  _gateway.releaseSession();
  logLine("[%s] Session closed.", header);
}

// ----------------------------------------------------------------------------
// SOCKET HELPERS
// ----------------------------------------------------------------------------
void GatewaySession::setRecvTimeout(unsigned long ms) {
  struct timeval tv;
  tv.tv_sec = ms / 1000;
  tv.tv_usec = (ms % 1000) * 1000;
  setsockopt(_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

bool GatewaySession::recvExact(uint8_t* buffer, size_t count) {
  size_t got = 0;
  while (got < count) {
    if (_terminated) return false;
    long remaining = (long)(_deadline - millis());
    if (remaining <= 0) return false;                       // Handshake deadline passed
    setRecvTimeout(remaining < 1000 ? (unsigned long)remaining : 1000);

    int r = recv(_sock, buffer + got, count - got, 0);
    if (r > 0) {
      got += r;
    } else if (r == 0) {
      return false;                                         // Client closed the connection
    } else if (!isRetryableSocketError(errno)) {
      return false;                                         // Reset / network error
    }
  }
  return true;
}

bool GatewaySession::sendAll(const void* data, size_t len) {
  const uint8_t* p = static_cast<const uint8_t*>(data);
  while (len > 0) {
    int w = send(_sock, p, len, MSG_NOSIGNAL);
    if (w > 0) {
      p += w;
      len -= w;
    } else if (w < 0 && isRetryableSocketError(errno) && !_terminated) {
      continue;
    } else {
      return false;
    }
  }
  return true;
}

// ----------------------------------------------------------------------------
// HANDSHAKE
// ----------------------------------------------------------------------------
bool GatewaySession::performHandshake() {
  _deadline = millis() + HANDSHAKE_TIMEOUT_MS;

  struct timeval sendTimeout = { 5, 0 };                    // A stuck client can't block send() forever
  setsockopt(_sock, SOL_SOCKET, SO_SNDTIMEO, &sendTimeout, sizeof(sendTimeout));

  _log.add("[TCP] Connection established with %s", _peer);

  if (!receiveClientHello()) return false;
  if (!sendServerProof())    return false;
  bool accepted = verifyClientProof();
  sendVerdict(accepted);
  sodium_memzero(_kConfirm, sizeof(_kConfirm));             // Only needed during the handshake
  return accepted;
}

// MESSAGE 1: CLIENT HELLO (82 bytes) + allowlist authorization
bool GatewaySession::receiveClientHello() {
  if (!recvExact(_msg1, MSG1_CLIENT_HELLO_SIZE)) {
    _log.add("[ERROR] Disconnected or timed out during MSG 1 (Client Hello).");
    return false;
  }

  uint8_t version = _msg1[0];
  uint8_t algId   = _msg1[1];
  if (version != PROTOCOL_VERSION || algId != ALGORITHM_ID) {
    _log.add("[AUTH-FAIL] Invalid Ver (0x%02X) or AlgID (0x%02X).", version, algId);
    return false;
  }

  // Device ID: 16 bytes, zero-padded. After removing the padding it must be 1..16
  // characters of [A-Za-z0-9_-] with no zero byte in the middle.
  const uint8_t* idField = _msg1 + 2;
  size_t idLen = DEVICE_ID_LENGTH;
  while (idLen > 0 && idField[idLen - 1] == 0) idLen--;
  bool idValid = idLen > 0;
  for (size_t i = 0; i < idLen && idValid; i++) {
    char c = (char)idField[i];
    idValid = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
  }
  if (!idValid) {
    _log.add("[AUTH-FAIL] Malformed Device ID field.");
    return false;
  }
  memcpy(_deviceId, idField, idLen);
  _deviceId[idLen] = '\0';

  _log.add("[Client -> Gateway] MSG 1: Client Hello (82 Bytes)");
  _log.add("    Version   : 0x%02X", version);
  _log.add("    Alg ID    : 0x%02X (Ed25519 + X25519 + HKDF-SHA256)", algId);
  _log.add("    Device ID : %s", _deviceId);
  _log.addHex("    Client Nonce [N_cli]", _msg1 + 18, CHALLENGE_NONCE_LENGTH);
  _log.addHex("    Client Ephemeral Public Key [PK_cli_eph]", _msg1 + 50, KEY_SHARE_LENGTH);

  _clientPublicKey = _gateway.allowlist().lookup(_deviceId);
  if (_clientPublicKey == nullptr) {
    _log.add("[AUTHORIZATION] '%s' DENIED (not in allowlist or revoked). Closing connection.", _deviceId);
    return false;
  }
  _log.add("[AUTHORIZATION] '%s' ALLOWED.", _deviceId);
  _log.addHex("    Registered Client Identity Public Key [PK_cli]", _clientPublicKey, 32);
  return true;
}

// MESSAGE 2: SERVER PROOF (128 bytes) + X25519 + HKDF
bool GatewaySession::sendServerProof() {
  const uint8_t* clientNonce = _msg1 + 18;
  const uint8_t* clientEphPk = _msg1 + 50;

  uint8_t serverNonce[CHALLENGE_NONCE_LENGTH];
  uint8_t serverEphSk[32];
  uint8_t serverEphPk[KEY_SHARE_LENGTH];
  randombytes_buf(serverNonce, sizeof(serverNonce));       // Hardware TRNG via ESP-IDF libsodium port
  randombytes_buf(serverEphSk, sizeof(serverEphSk));
  crypto_scalarmult_base(serverEphPk, serverEphSk);

  // X25519 shared secret. libsodium returns -1 for low-order points (all-zero secret).
  uint8_t sharedSecret[32];
  if (crypto_scalarmult(sharedSecret, serverEphSk, clientEphPk) != 0) {
    _log.add("[KEX-FAIL] Invalid client X25519 public key share. Closing connection.");
    sodium_memzero(serverEphSk, sizeof(serverEphSk));
    sodium_memzero(sharedSecret, sizeof(sharedSecret));
    return false;
  }
  GatewayCrypto::deriveSessionKeys(sharedSecret, clientNonce, serverNonce, _kConfirm, _kSession);
  sodium_memzero(serverEphSk, sizeof(serverEphSk));        // Forward secrecy: ephemeral key gone
  sodium_memzero(sharedSecret, sizeof(sharedSecret));

  // Sign H_srv = SHA-256(label || MSG1 || N_srv || PK_srv_eph)
  uint8_t serverDigest[32];
  GatewayCrypto::serverTranscript(_msg1, serverNonce, serverEphPk, serverDigest);
  uint8_t serverSig[SIGNATURE_LENGTH];
  _gateway.crypto().sign(serverDigest, sizeof(serverDigest), serverSig);

  memcpy(_msg2, serverNonce, CHALLENGE_NONCE_LENGTH);
  memcpy(_msg2 + CHALLENGE_NONCE_LENGTH, serverEphPk, KEY_SHARE_LENGTH);
  memcpy(_msg2 + CHALLENGE_NONCE_LENGTH + KEY_SHARE_LENGTH, serverSig, SIGNATURE_LENGTH);

  _log.add("[Gateway] Generated Server Nonce + Ephemeral X25519 keypair (Forward Secrecy).");
  _log.addHex("    SHA-256 Server Transcript Digest [H_srv]", serverDigest, 32);
  _log.add("[Gateway -> Client] MSG 2: Server Proof (128 Bytes)");
  _log.addHex("    Server Nonce [N_srv]", serverNonce, CHALLENGE_NONCE_LENGTH);
  _log.addHex("    Server Ephemeral Public Key [PK_srv_eph]", serverEphPk, KEY_SHARE_LENGTH);
  _log.addHex("    Server Ed25519 Signature [sigma_srv]", serverSig, SIGNATURE_LENGTH);
  _log.add("[Gateway] X25519 shared secret computed; K_confirm and K_session derived (HKDF-SHA256).");

  if (!sendAll(_msg2, sizeof(_msg2))) {
    _log.add("[ERROR] Failed to send MSG 2.");
    return false;
  }
  return true;
}

// MESSAGE 3: CLIENT PROOF (96 bytes): Ed25519 signature + HMAC key confirmation
bool GatewaySession::verifyClientProof() {
  uint8_t packet[MSG3_CLIENT_PROOF_SIZE];
  if (!recvExact(packet, sizeof(packet))) {
    _log.add("[AUTH-FAIL] Disconnected or timed out waiting for MSG 3 (Client Proof).");
    return false;
  }
  const uint8_t* clientSig        = packet;
  const uint8_t* clientConfirmTag = packet + SIGNATURE_LENGTH;

  _log.add("[Client -> Gateway] MSG 3: Client Proof (96 Bytes)");
  _log.addHex("    Client Ed25519 Signature [sigma_cli]", clientSig, SIGNATURE_LENGTH);
  _log.addHex("    Client Key Confirmation Tag", clientConfirmTag, KEY_CONFIRM_LENGTH);

  // H_cli = SHA-256(label || MSG1 || MSG2)
  GatewayCrypto::clientTranscript(_msg1, _msg2, _clientTranscriptDigest);
  _log.addHex("    SHA-256 Client Transcript Digest [H_cli]", _clientTranscriptDigest, 32);

  if (!GatewayCrypto::verify(_clientPublicKey, clientSig, _clientTranscriptDigest, 32)) {
    _log.add("[AUTH-FAIL] Ed25519 client signature INVALID. Rejecting.");
    return false;
  }
  _log.add("[Gateway] Ed25519 client signature VALID (client owns the registered key).");

  uint8_t expectedTag[KEY_CONFIRM_LENGTH];
  GatewayCrypto::confirmationTag(_kConfirm, CLIENT_CONFIRM_LABEL, _clientTranscriptDigest, expectedTag);
  if (crypto_verify_32(clientConfirmTag, expectedTag) != 0) {      // Constant-time compare
    _log.add("[KEY-CONFIRM-FAIL] Client key confirmation tag mismatch. Rejecting.");
    return false;
  }
  _log.add("[Gateway] Client key confirmation tag VALID (same X25519 secret on both sides).");
  return true;
}

// MESSAGE 4: SERVER VERDICT ("AUTH_OK\n" + 32B tag, or "AUTH_NO\n")
void GatewaySession::sendVerdict(bool accepted) {
  if (!accepted) {
    sendAll(AUTH_FAIL_TOKEN, MSG4_TOKEN_SIZE);
    _log.add("[Gateway -> Client] MSG 4: AUTH_NO (8 Bytes). [AUTHENTICATION REJECTED]");
    return;
  }
  uint8_t packet[MSG4_TOKEN_SIZE + KEY_CONFIRM_LENGTH];
  memcpy(packet, AUTH_OK_TOKEN, MSG4_TOKEN_SIZE);
  GatewayCrypto::confirmationTag(_kConfirm, SERVER_CONFIRM_LABEL, _clientTranscriptDigest, packet + MSG4_TOKEN_SIZE);

  _log.add("[Gateway -> Client] MSG 4: Server Verdict (40 Bytes)");
  _log.add("    Verdict Token : \"AUTH_OK\\n\"");
  _log.addHex("    Server Key Confirmation Tag", packet + MSG4_TOKEN_SIZE, KEY_CONFIRM_LENGTH);
  if (sendAll(packet, sizeof(packet))) {
    _log.add("[MUTUAL AUTHENTICATION & KEY EXCHANGE SUCCESS]");
  } else {
    _log.add("[ERROR] Failed to send MSG 4.");
  }
}

// ----------------------------------------------------------------------------
// DATA TUNNEL
// ----------------------------------------------------------------------------
static void hexPreview(const uint8_t* data, size_t len, char* out, size_t outSize) {
  size_t n = len < 12 ? len : 12;
  size_t pos = 0;
  for (size_t i = 0; i < n && pos + 3 < outSize; i++) pos += snprintf(out + pos, outSize - pos, "%02X", data[i]);
  out[pos] = '\0';
}

void GatewaySession::runTunnel() {
  if (!_tunnel.begin(_kSession)) {
    logLine("[%s] [TUNNEL-ERROR] %s. Closing session.", _deviceId, _tunnel.lastError());
    return;
  }
  sodium_memzero(_kSession, sizeof(_kSession));   // Only the derived tunnel keys are needed now

  char c2s[65], s2c[65];
  for (int i = 0; i < 32; i++) {
    snprintf(c2s + 2 * i, 3, "%02X", _tunnel.keyC2S()[i]);
    snprintf(s2c + 2 * i, 3, "%02X", _tunnel.keyS2C()[i]);
  }
  logLine("[%s] [TUNNEL ACTIVE] AES-256-GCM encrypted stream (PFS established).\n"
          "    K_c2s (client->gateway) = %s\n    K_s2c (gateway->client) = %s",
          _deviceId, c2s, s2c);

  setRecvTimeout(TUNNEL_POLL_MS);   // Short timeout so revocation / idle checks run while quiet
  uint8_t chunk[512];
  unsigned long lastRx = millis();

  while (true) {
    if (_terminated) {
      logLine("[%s] [SESSION CLOSED] %s.", _deviceId, _terminateReason ? _terminateReason : "terminated");
      return;
    }
    if (!_gateway.allowlist().isStillAuthorized(_deviceId, _clientPublicKey)) {
      logLine("[%s] [REVOKED] Device no longer authorized. Closing tunnel.", _deviceId);
      return;
    }
    if (millis() - lastRx >= TUNNEL_IDLE_TIMEOUT_MS) {
      logLine("[%s] [TUNNEL TIMEOUT] Idle for %lu s. Closing session.", _deviceId, TUNNEL_IDLE_TIMEOUT_MS / 1000);
      return;
    }

    int r = recv(_sock, chunk, sizeof(chunk), 0);
    if (r < 0) {
      if (_terminated) continue;                                    // Loop top prints the reason
      if (isRetryableSocketError(errno)) continue;                  // Poll timeout: run checks again
      logLine("[%s] Connection error (errno %d). Closing session.", _deviceId, errno);
      return;
    }
    if (r == 0) {
      if (_terminated) continue;                                    // Loop top prints the reason
      logLine("[%s] Client disconnected cleanly.", _deviceId);
      return;
    }
    lastRx = millis();

    // A chunk may hold part of a frame, one frame, or several frames
    size_t offset = 0;
    while (offset < (size_t)r) {
      size_t used = 0, msgLen = 0;
      uint64_t seq = 0;
      int status = _tunnel.consume(chunk + offset, r - offset, &used, _plain, &msgLen, &seq);
      offset += used;
      if (status < 0) {
        // Tampered, replayed, reordered or oversized frame: close ONLY this session
        logLine("[%s] [TUNNEL-ERROR] %s. Dropping session.", _deviceId, _tunnel.lastError());
        return;
      }
      if (status == 1 && !handleMessage(_plain, msgLen, seq)) {
        return;
      }
      if (status == 0) break;   // Need more bytes for the current frame
    }
  }
}

bool GatewaySession::handleMessage(const uint8_t* msg, size_t len, uint64_t seq) {
  char ctPreview[32];
  hexPreview(_tunnel.lastFrameCiphertext(), len, ctPreview, sizeof(ctPreview));
  logLine("[%s] <- RECEIVED encrypted msg #%llu (%u bytes over Wi-Fi)\n"
          "     ciphertext : %s...  (unreadable without the key)\n"
          "     decrypted  : \"%.*s\"  (GCM tag VALID)",
          _deviceId, (unsigned long long)seq, (unsigned)(GatewayTunnel::HEADER_SIZE + len + GatewayTunnel::TAG_SIZE),
          ctPreview, (int)(len < 120 ? len : 120), (const char*)msg);

  // Reply = "SERVER_ACK_FOR_<id>: <message>", cut to one frame
  int prefix = snprintf((char*)_reply, sizeof(_reply), "SERVER_ACK_FOR_%s: ", _deviceId);
  size_t replyLen = (size_t)prefix;
  size_t copy = len;
  if (replyLen + copy > sizeof(_reply)) copy = sizeof(_reply) - replyLen;
  memcpy(_reply + replyLen, msg, copy);
  replyLen += copy;

  size_t frameLen = _tunnel.seal(_reply, replyLen, _frame);
  if (frameLen == 0 || !sendAll(_frame, frameLen)) {
    logLine("[%s] [TUNNEL-ERROR] Could not send encrypted reply. Closing session.", _deviceId);
    return false;
  }
  hexPreview(_frame + GatewayTunnel::HEADER_SIZE, replyLen, ctPreview, sizeof(ctPreview));
  logLine("[%s] -> SENT encrypted reply msg #%llu (%u bytes over Wi-Fi)\n"
          "     ciphertext : %s...",
          _deviceId, (unsigned long long)_tunnel.lastTxSeq(), (unsigned)frameLen, ctPreview);
  return true;
}
