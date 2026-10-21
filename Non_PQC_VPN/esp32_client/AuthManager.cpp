#include "AuthManager.h"
#include "config.h"

// Constructor: Initializes references to network client, device identity, and pinned gateway key
AuthManager::AuthManager(WiFiClient& client, const DeviceIdentity& identity, const uint8_t* trustedGatewayKey)
  : _client(client), _identity(identity), _trustedGatewayKey(trustedGatewayKey) {}

// Helper: Reads exact number of bytes from TCP socket with timeout protection
bool AuthManager::readExact(uint8_t* buffer, size_t count, unsigned long timeoutMs) {
  size_t bytesRead = 0;                                        // Counter for bytes received so far
  unsigned long start = millis();                              // Record starting time

  while (bytesRead < count && (millis() - start < timeoutMs)) { // Loop until all bytes received or timed out
    while (_client.available() && bytesRead < count) {         // Check for incoming byte
      buffer[bytesRead++] = _client.read();                    // Save byte into buffer
    }
    delay(5);                                                  // Short delay to allow packets to arrive
  }
  return (bytesRead == count);                                 // Returns true only if all bytes arrived
}

// Helper: Builds domain-separated SHA-256 transcript hash
void AuthManager::buildTranscriptHash(const char* role, const uint8_t* serverNonce, const uint8_t* clientNonce, uint8_t* outDigest) {
  crypto_hash_sha256_state state;
  crypto_hash_sha256_init(&state);
  crypto_hash_sha256_update(&state, (const unsigned char*)"VPN-AUTH-v1|", 12);
  crypto_hash_sha256_update(&state, (const unsigned char*)role, strlen(role));
  crypto_hash_sha256_update(&state, (const unsigned char*)"|", 1);
  crypto_hash_sha256_update(&state, (const unsigned char*)_identity.getDeviceId(), strlen(_identity.getDeviceId()));
  crypto_hash_sha256_update(&state, (const unsigned char*)"|", 1);
  crypto_hash_sha256_update(&state, serverNonce, CHALLENGE_NONCE_LENGTH);
  crypto_hash_sha256_update(&state, (const unsigned char*)"|", 1);
  crypto_hash_sha256_update(&state, clientNonce, CHALLENGE_NONCE_LENGTH);
  crypto_hash_sha256_final(&state, outDigest);
}

// Executes two-stage handshake: Authorization check followed by challenge-response authentication
bool AuthManager::performMutualAuthentication() {
  Serial.println("[AUTH] Starting handshake...");

  // --- STAGE 1: Send Device ID for Allowlist Authorization ---
  char idPacket[DEVICE_ID_LENGTH] = {0};                       // 16-byte buffer padded with zeros
  strncpy(idPacket, _identity.getDeviceId(), sizeof(idPacket) - 1); // Copy device name
  _client.write((const uint8_t*)idPacket, sizeof(idPacket));    // Send 16-byte identification packet
  _client.flush();                                             // Push packet out over Wi-Fi

  // --- STAGE 2: Receive Server Challenge Nonce ---
  uint8_t serverChallenge[CHALLENGE_NONCE_LENGTH];             // 32-byte buffer for server challenge
  if (!readExact(serverChallenge, sizeof(serverChallenge))) {
    Serial.println("[AUTH] Server challenge timed out or device denied by allowlist.");
    return false;                                              // Handshake failed (not on allowlist or timeout)
  }

  // --- STAGE 3: Generate Client Challenge and Sign Domain-Separated Transcript ---
  uint8_t clientChallenge[CHALLENGE_NONCE_LENGTH];             // 32-byte buffer for client challenge
  esp_fill_random(clientChallenge, sizeof(clientChallenge));   // Generate fresh random numbers via TRNG

  // Build domain-separated transcript digest for CLIENT: SHA-256("VPN-AUTH-v1|CLIENT|<id>|<srv_nonce>|<cli_nonce>")
  uint8_t clientTranscriptDigest[crypto_hash_sha256_BYTES];
  buildTranscriptHash("CLIENT", serverChallenge, clientChallenge, clientTranscriptDigest);

  uint8_t clientSignature[SIGNATURE_LENGTH];                   // 64-byte buffer for client signature
  if (!_identity.sign(clientTranscriptDigest, sizeof(clientTranscriptDigest), clientSignature)) {
    Serial.println("[AUTH] Failed to sign client transcript.");
    return false;
  }

  // --- STAGE 4: Send Client Signature + Client Challenge (96 bytes total) ---
  _client.write(clientSignature, sizeof(clientSignature));     // Send 64-byte signature proof
  _client.write(clientChallenge, sizeof(clientChallenge));     // Send 32-byte client challenge nonce
  _client.flush();                                             // Push data out over Wi-Fi

  // --- STAGE 5: Receive and Verify Server's Signature Proof ---
  uint8_t serverSignature[SIGNATURE_LENGTH];                   // 64-byte buffer for server signature
  if (!readExact(serverSignature, sizeof(serverSignature))) {
    Serial.println("[AUTH] Timed out waiting for server proof.");
    return false;                                              // Stop if server takes too long
  }

  // Build domain-separated transcript digest for SERVER: SHA-256("VPN-AUTH-v1|SERVER|<id>|<srv_nonce>|<cli_nonce>")
  uint8_t serverTranscriptDigest[crypto_hash_sha256_BYTES];
  buildTranscriptHash("SERVER", serverChallenge, clientChallenge, serverTranscriptDigest);

  // Verify server signature against the pinned gateway public key and server transcript
  int verifyResult = crypto_sign_verify_detached(
    serverSignature,
    serverTranscriptDigest,
    sizeof(serverTranscriptDigest),
    _trustedGatewayKey
  );

  if (verifyResult != 0) {
    Serial.println("[AUTH] Server signature INVALID - untrusted gateway or transcript mismatch!");
    return false;                                              // Reject fake or untrusted server
  }

  // --- STAGE 6: Send Cryptographic CONFIRM Tag to Server ---
  uint8_t confirmTag[CONFIRMATION_TAG_LENGTH];
  buildTranscriptHash("CONFIRM", serverChallenge, clientChallenge, confirmTag);
  _client.write(confirmTag, sizeof(confirmTag));               // Send 32-byte cryptographic confirmation tag
  _client.flush();                                             // Push confirmation out over Wi-Fi
  Serial.println("[AUTH] Gateway signature verified. Sent cryptographic CONFIRM tag.");
  Serial.println("[AUTH] Mutual authentication successful.\n");
  return true;                                                 // Both parties authenticated successfully!
}
