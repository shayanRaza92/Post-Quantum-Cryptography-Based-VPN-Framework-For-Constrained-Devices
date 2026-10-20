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

  // --- STAGE 3: Sign Server Challenge and Create Client Challenge ---
  uint8_t clientSignature[SIGNATURE_LENGTH];                   // 64-byte buffer for client signature
  if (!_identity.sign(serverChallenge, sizeof(serverChallenge), clientSignature)) {
    Serial.println("[AUTH] Failed to sign server challenge.");
    return false;
  }

  uint8_t clientChallenge[CHALLENGE_NONCE_LENGTH];             // 32-byte buffer for client challenge
  esp_fill_random(clientChallenge, sizeof(clientChallenge));   // Generate fresh random numbers via TRNG

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

  // Verify server signature against the pinned gateway public key
  int verifyResult = crypto_sign_verify_detached(
    serverSignature,
    clientChallenge,
    sizeof(clientChallenge),
    _trustedGatewayKey
  );

  if (verifyResult != 0) {
    Serial.println("[AUTH] Server signature INVALID - untrusted gateway!");
    return false;                                              // Reject fake or untrusted server
  }

  // --- STAGE 6: Send AUTH_OK Confirmation to Server ---
  _client.write((const uint8_t*)AUTH_CONFIRM_TOKEN, strlen(AUTH_CONFIRM_TOKEN)); // Send confirmation token
  _client.flush();                                             // Push confirmation out over Wi-Fi
  Serial.println("[AUTH] Gateway signature verified. Sent AUTH_OK confirmation.");
  Serial.println("[AUTH] Mutual authentication successful.\n");
  return true;                                                 // Both parties authenticated successfully!
}
