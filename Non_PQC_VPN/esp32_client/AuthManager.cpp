#include "AuthManager.h"
#include "config.h"

// ============================================================================
// NETWORK PACKET DIAGRAM PRINT HELPERS
// Formats packet and transcript payloads cleanly without unnecessary decoration
// ============================================================================
static void printHexRow(const uint8_t* data, size_t len) {
  Serial.print("| ");
  for (size_t i = 0; i < len; i++) {
    if (data[i] < 0x10) Serial.print("0");
    Serial.print(data[i], HEX);
  }
  for (size_t i = len * 2; i < 75; i++) Serial.print(" ");
  Serial.println(" |");
}

static void printHex64Row(const uint8_t* data) {
  // Line 1: First 32 bytes (64 hex characters)
  Serial.print("| ");
  for (size_t i = 0; i < 32; i++) {
    if (data[i] < 0x10) Serial.print("0");
    Serial.print(data[i], HEX);
  }
  for (size_t i = 64; i < 75; i++) Serial.print(" ");
  Serial.println(" |");

  // Line 2: Second 32 bytes (64 hex characters)
  Serial.print("| ");
  for (size_t i = 32; i < 64; i++) {
    if (data[i] < 0x10) Serial.print("0");
    Serial.print(data[i], HEX);
  }
  for (size_t i = 64; i < 75; i++) Serial.print(" ");
  Serial.println(" |");
}

// ============================================================================
// CONSTRUCTOR
// Initializes references to active socket client, local identity, and pinned key
// ============================================================================
AuthManager::AuthManager(WiFiClient& client, const DeviceIdentity& identity, const uint8_t* trustedGatewayKey)
  : _client(client), _identity(identity), _trustedGatewayKey(trustedGatewayKey) {
  memset(_cachedMsg1, 0, sizeof(_cachedMsg1));
  memset(_cachedMsg2, 0, sizeof(_cachedMsg2));
}

// ============================================================================
// LOW-LEVEL STREAM UTILITY
// ============================================================================
bool AuthManager::readExact(uint8_t* buffer, size_t count, unsigned long timeoutMs) {
  size_t bytesRead = 0;
  unsigned long start = millis();

  while (bytesRead < count && (millis() - start < timeoutMs)) {
    while (_client.available() && bytesRead < count) {
      buffer[bytesRead++] = _client.read();
    }
    if (bytesRead < count) {
      delayMicroseconds(250); // Yield to TCP stack without introducing multi-millisecond delay
    }
  }
  return (bytesRead == count);
}

// ============================================================================
// TRANSCRIPT BUILDER: SERVER TRANSCRIPT (MSG 2)
// Running Transcript: SHA-256( "VPN-v1|SERVER|" (14B) || MSG1 (50B) || ServerNonce (32B) ) -> 96B input
// ============================================================================
void AuthManager::buildServerTranscript(const uint8_t* serverNonce, uint8_t* outDigest) {
  crypto_hash_sha256_state state;
  crypto_hash_sha256_init(&state);
  crypto_hash_sha256_update(&state, (const unsigned char*)"VPN-v1|SERVER|", 14);
  crypto_hash_sha256_update(&state, _cachedMsg1, MSG1_CLIENT_HELLO_SIZE);
  crypto_hash_sha256_update(&state, serverNonce, CHALLENGE_NONCE_LENGTH);
  crypto_hash_sha256_final(&state, outDigest);
}

// ============================================================================
// TRANSCRIPT BUILDER: CLIENT TRANSCRIPT (MSG 3)
// Running Transcript: SHA-256( "VPN-v1|CLIENT|" (14B) || MSG1 (50B) || MSG2 (96B) ) -> 160B input
// ============================================================================
void AuthManager::buildClientTranscript(const uint8_t* msg2, uint8_t* outDigest) {
  crypto_hash_sha256_state state;
  crypto_hash_sha256_init(&state);
  crypto_hash_sha256_update(&state, (const unsigned char*)"VPN-v1|CLIENT|", 14);
  crypto_hash_sha256_update(&state, _cachedMsg1, MSG1_CLIENT_HELLO_SIZE);
  crypto_hash_sha256_update(&state, msg2, MSG2_SERVER_PROOF_SIZE);
  crypto_hash_sha256_final(&state, outDigest);
}

// ============================================================================
// MESSAGE 1: CLIENT HELLO TRANSMITTER (50 BYTES)
// Transmits: [1B Version] [1B AlgID] [16B DeviceID] [32B Client Nonce]
// ============================================================================
bool AuthManager::sendClientHello(uint8_t* outClientNonce) {
  // 1. Generate 32B random nonce from ESP32 hardware TRNG
  esp_fill_random(outClientNonce, CHALLENGE_NONCE_LENGTH);

  // 2. Assemble 50-byte Client Hello packet
  uint8_t packet[MSG1_CLIENT_HELLO_SIZE];
  memset(packet, 0, sizeof(packet));

  packet[0] = PROTOCOL_VERSION;
  packet[1] = ALGORITHM_ID;

  const char* idStr = _identity.getDeviceId();
  size_t idLen = strlen(idStr);
  if (idLen > DEVICE_ID_LENGTH) idLen = DEVICE_ID_LENGTH;
  memcpy(packet + 2, idStr, idLen);

  memcpy(packet + 2 + DEVICE_ID_LENGTH, outClientNonce, CHALLENGE_NONCE_LENGTH);

  // Print structured wire packet diagram
  Serial.println("\n+-----------------------------------------------------------------------------+");
  Serial.println("| MSG 1: CLIENT HELLO WIRE PACKET (50 Bytes / 400-bits)                       |");
  Serial.println("+-------------------+--------------------+------------------------------------+");
  Serial.println("| Version (8-bits)  | Alg ID (8-bits)    | Device ID (128-bits / 16 Bytes)    |");
  Serial.printf ("| 0x%02X              | 0x%02X               | %-34s |\n", PROTOCOL_VERSION, ALGORITHM_ID, idStr);
  Serial.println("+-------------------+--------------------+------------------------------------+");
  Serial.println("| Client Nonce [N_cli] (32 Bytes / 256-bits)                                  |");
  printHexRow(outClientNonce, CHALLENGE_NONCE_LENGTH);
  Serial.println("+-----------------------------------------------------------------------------+");

  memcpy(_cachedMsg1, packet, sizeof(packet));

  size_t written = _client.write(packet, sizeof(packet));
  _client.flush();

  return (written == sizeof(packet));
}

// ============================================================================
// MESSAGE 2: SERVER PROOF RECEIVER & VERIFIER (96 BYTES)
// Receives: [32B Server Nonce] [64B Server Signature]
// Server authenticates FIRST! If verification fails, client aborts immediately.
// ============================================================================
bool AuthManager::receiveServerProof(const uint8_t* clientNonce, uint8_t* outServerNonce, uint8_t* outServerSig) {
  uint8_t packet[MSG2_SERVER_PROOF_SIZE];
  if (!readExact(packet, sizeof(packet))) {
    Serial.println("| [ERROR] Timed out waiting for MSG 2 (Server Proof).                         |");
    return false;
  }

  memcpy(_cachedMsg2, packet, sizeof(packet));
  memcpy(outServerNonce, packet, CHALLENGE_NONCE_LENGTH);
  memcpy(outServerSig, packet + CHALLENGE_NONCE_LENGTH, SIGNATURE_LENGTH);

  // 1. First, print MSG 2 Wire Packet received from server
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| MSG 2: SERVER PROOF WIRE PACKET (96 Bytes / 768-bits)                       |");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Server Nonce [N_srv] (32 Bytes / 256-bits)                                  |");
  printHexRow(outServerNonce, CHALLENGE_NONCE_LENGTH);
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Server Signature [sigma_srv] (64 Bytes / 512-bits)                          |");
  printHex64Row(outServerSig);
  Serial.println("+-----------------------------------------------------------------------------+");

  // 2. Client reconstructing Server Transcript
  Serial.println("\n[Client] Reconstructing Server Transcript (label || MSG1 || N_srv)...");
  const char* idStr = _identity.getDeviceId();
  size_t server_transcript_len = 14 + MSG1_CLIENT_HELLO_SIZE + CHALLENGE_NONCE_LENGTH; // 96 Bytes

  Serial.println("+-----------------------------------------------------------------------------+");
  char titleBuf[76];
  snprintf(titleBuf, sizeof(titleBuf), "SERVER TRANSCRIPT PAYLOAD (%u Bytes / %u-bits)",
           (unsigned int)server_transcript_len, (unsigned int)(server_transcript_len * 8));
  Serial.printf("| %-75s |\n", titleBuf);
  Serial.println("+----------------------------+---------------+-----------+--------------------+");
  Serial.println("| Field Name                 | Byte Offset   | Size      | Value / Encoding   |");
  Serial.println("+----------------------------+---------------+-----------+--------------------+");
  Serial.println("| Domain Prefix              | Byte 0..13    | 14 Bytes  | \"VPN-v1|SERVER|\"   |");
  Serial.printf ("| MSG1 Version               | Byte 14       | 1 Byte    | 0x%02X               |\n", PROTOCOL_VERSION);
  Serial.printf ("| MSG1 Algorithm ID          | Byte 15       | 1 Byte    | 0x%02X (Ed25519)     |\n", ALGORITHM_ID);
  char idVal[22];
  snprintf(idVal, sizeof(idVal), "\"%s\"", idStr);
  Serial.printf ("| %-26s | %-13s | %-9s | %-18s |\n", "MSG1 Device ID (0-padded)", "Byte 16..31", "16 Bytes", idVal);
  char cliBuf[22];
  snprintf(cliBuf, sizeof(cliBuf), "%02X%02X%02X%02X%02X%02X..%02X%02X",
           clientNonce[0], clientNonce[1], clientNonce[2], clientNonce[3], clientNonce[4], clientNonce[5], clientNonce[30], clientNonce[31]);
  Serial.printf ("| %-26s | %-13s | %-9s | %-18s |\n", "MSG1 Client Nonce [N_cli]", "Byte 32..63", "32 Bytes", cliBuf);
  char srvBuf[22];
  snprintf(srvBuf, sizeof(srvBuf), "%02X%02X%02X%02X%02X%02X..%02X%02X",
           outServerNonce[0], outServerNonce[1], outServerNonce[2], outServerNonce[3], outServerNonce[4], outServerNonce[5], outServerNonce[30], outServerNonce[31]);
  Serial.printf ("| %-26s | %-13s | %-9s | %-18s |\n", "Server Nonce [N_srv]", "Byte 64..95", "32 Bytes", srvBuf);
  Serial.println("+-----------------------------------------------------------------------------+");

  // 3. Client hashing Server Transcript
  Serial.println("\n[Client] Hashing Server Transcript (SHA-256)...");
  uint8_t serverTranscriptDigest[crypto_hash_sha256_BYTES];
  buildServerTranscript(outServerNonce, serverTranscriptDigest);

  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Expected SHA-256 Digest [H_srv] (32 Bytes / 256-bits)                       |");
  printHexRow(serverTranscriptDigest, sizeof(serverTranscriptDigest));
  Serial.println("+-----------------------------------------------------------------------------+");

  // 4. Verifying the server signature (REAL check on ESP32)
  Serial.println("\n[Client] Verifying Server Signature against Pinned Gateway Public Key...");
  int verifyResult = crypto_sign_verify_detached(
    outServerSig,
    serverTranscriptDigest,
    sizeof(serverTranscriptDigest),
    _trustedGatewayKey
  );

  char pkBuf[20], rBuf[20], sBuf[20], hBuf[20];
  snprintf(pkBuf, sizeof(pkBuf), "%02X%02X..%02X%02X",
           _trustedGatewayKey[0], _trustedGatewayKey[1], _trustedGatewayKey[30], _trustedGatewayKey[31]);
  snprintf(hBuf, sizeof(hBuf), "%02X%02X..%02X%02X",
           serverTranscriptDigest[0], serverTranscriptDigest[1], serverTranscriptDigest[30], serverTranscriptDigest[31]);
  snprintf(rBuf, sizeof(rBuf), "%02X%02X..%02X%02X",
           outServerSig[0], outServerSig[1], outServerSig[30], outServerSig[31]);
  snprintf(sBuf, sizeof(sBuf), "%02X%02X..%02X%02X",
           outServerSig[32], outServerSig[33], outServerSig[62], outServerSig[63]);

  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| ED25519 SIGNATURE VERIFICATION WORKING                                      |");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.printf ("| Input 1: Pinned Gateway PubKey [PK_srv] : %-34s|\n", pkBuf);
  Serial.printf ("| Input 2: Transcript Digest [H_srv]      : %-34s|\n", hBuf);
  Serial.printf ("| Input 3: Signature Point [R] (32 Bytes) : %-34s|\n", rBuf);
  Serial.printf ("| Input 4: Signature Scalar [s] (32 Bytes): %-34s|\n", sBuf);
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Step 1: Compute challenge scalar k = SHA-512(R || PK_srv || H_srv)          |");
  Serial.println("| Step 2: Evaluate Curve Equation   : [s]B == R + [k]PK_srv                   |");
  if (verifyResult == 0) {
    Serial.println("| Result : PASS -> Point identity matches! Signature mathematically valid.    |");
  } else {
    Serial.println("| Result : FAIL -> Point mismatch! Untrusted signature or forged packet.      |");
  }
  Serial.println("+-----------------------------------------------------------------------------+\n");

  return (verifyResult == 0);
}

// ============================================================================
// MESSAGE 3: CLIENT PROOF TRANSMITTER (64 BYTES)
// Signs Client Transcript (label || MSG1 || MSG2) and transmits 64B signature.
// ============================================================================
bool AuthManager::sendClientProof(const uint8_t* clientNonce, const uint8_t* serverNonce, const uint8_t* serverSig) {
  const char* idStr = _identity.getDeviceId();
  size_t client_transcript_len = 14 + MSG1_CLIENT_HELLO_SIZE + MSG2_SERVER_PROOF_SIZE; // 160 Bytes

  // 1. Client constructing Client Transcript
  Serial.println("[Client] Constructing Client Transcript (label || MSG1 || MSG2)...");
  Serial.println("+-----------------------------------------------------------------------------+");
  char titleBuf[76];
  snprintf(titleBuf, sizeof(titleBuf), "CLIENT TRANSCRIPT PAYLOAD (%u Bytes / %u-bits)",
           (unsigned int)client_transcript_len, (unsigned int)(client_transcript_len * 8));
  Serial.printf("| %-75s |\n", titleBuf);
  Serial.println("+----------------------------+---------------+-----------+--------------------+");
  Serial.println("| Field Name                 | Byte Offset   | Size      | Value / Encoding   |");
  Serial.println("+----------------------------+---------------+-----------+--------------------+");
  Serial.println("| Domain Prefix              | Byte 0..13    | 14 Bytes  | \"VPN-v1|CLIENT|\"   |");
  Serial.printf ("| MSG1 Version               | Byte 14       | 1 Byte    | 0x%02X               |\n", PROTOCOL_VERSION);
  Serial.printf ("| MSG1 Algorithm ID          | Byte 15       | 1 Byte    | 0x%02X (Ed25519)     |\n", ALGORITHM_ID);
  char idVal[22];
  snprintf(idVal, sizeof(idVal), "\"%s\"", idStr);
  Serial.printf ("| %-26s | %-13s | %-9s | %-18s |\n", "MSG1 Device ID (0-padded)", "Byte 16..31", "16 Bytes", idVal);
  char cliBuf[22];
  snprintf(cliBuf, sizeof(cliBuf), "%02X%02X%02X%02X%02X%02X..%02X%02X",
           clientNonce[0], clientNonce[1], clientNonce[2], clientNonce[3], clientNonce[4], clientNonce[5], clientNonce[30], clientNonce[31]);
  Serial.printf ("| %-26s | %-13s | %-9s | %-18s |\n", "MSG1 Client Nonce [N_cli]", "Byte 32..63", "32 Bytes", cliBuf);
  char srvBuf[22];
  snprintf(srvBuf, sizeof(srvBuf), "%02X%02X%02X%02X%02X%02X..%02X%02X",
           serverNonce[0], serverNonce[1], serverNonce[2], serverNonce[3], serverNonce[4], serverNonce[5], serverNonce[30], serverNonce[31]);
  Serial.printf ("| %-26s | %-13s | %-9s | %-18s |\n", "MSG2 Server Nonce [N_srv]", "Byte 64..95", "32 Bytes", srvBuf);
  char sigBuf[22];
  snprintf(sigBuf, sizeof(sigBuf), "%02X%02X%02X%02X%02X%02X..%02X%02X",
           serverSig[0], serverSig[1], serverSig[2], serverSig[3], serverSig[4], serverSig[5], serverSig[62], serverSig[63]);
  Serial.printf ("| %-26s | %-13s | %-9s | %-18s |\n", "MSG2 Server Sig [sig_srv]", "Byte 96..159", "64 Bytes", sigBuf);
  Serial.println("+-----------------------------------------------------------------------------+");

  // 2. Client hashing Client Transcript
  Serial.println("\n[Client] Hashing Client Transcript (SHA-256)...");
  uint8_t clientTranscriptDigest[crypto_hash_sha256_BYTES];
  buildClientTranscript(_cachedMsg2, clientTranscriptDigest);

  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| SHA-256 Digest [H_cli] (32 Bytes / 256-bits)                                |");
  printHexRow(clientTranscriptDigest, sizeof(clientTranscriptDigest));
  Serial.println("+-----------------------------------------------------------------------------+");

  // 3. Client signing digest with private key
  Serial.println("\n[Client] Signing digest with device private key...");
  uint8_t clientSignature[SIGNATURE_LENGTH];
  if (!_identity.sign(clientTranscriptDigest, sizeof(clientTranscriptDigest), clientSignature)) {
    Serial.println("| [ERROR] Failed to sign client transcript.                                   |");
    return false;
  }

  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Client Signature [sigma_cli] (64 Bytes / 512-bits)                          |");
  printHex64Row(clientSignature);
  Serial.println("+-----------------------------------------------------------------------------+");

  // 4. Send MSG 3 Wire Packet
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| MSG 3: CLIENT PROOF WIRE PACKET (64 Bytes / 512-bits)                       |");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Client Signature [sigma_cli] (64 Bytes / 512-bits)                          |");
  printHex64Row(clientSignature);
  Serial.println("+-----------------------------------------------------------------------------+");

  size_t written = _client.write(clientSignature, sizeof(clientSignature));
  _client.flush();

  return (written == sizeof(clientSignature));
}

// ============================================================================
// MESSAGE 4: SERVER VERDICT RECEIVER (8 BYTES)
// Receives "AUTH_OK\n" or "AUTH_NO\n" token confirming gateway verdict.
// ============================================================================
bool AuthManager::receiveServerVerdict() {
  uint8_t verdictBuf[MSG4_AUTH_OK_SIZE];
  if (!readExact(verdictBuf, sizeof(verdictBuf))) {
    Serial.println("| [ERROR] Timed out waiting for MSG 4 (Server Verdict).                       |");
    return false;
  }

  bool isOk = (memcmp(verdictBuf, "AUTH_OK\n", 8) == 0);

  // Print structured packet diagram
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| MSG 4: SERVER VERDICT WIRE PACKET (8 Bytes / 64-bits)                       |");
  Serial.println("+-----------------------------------------------------------------------------+");
  if (isOk) {
    Serial.println("| Verdict Token (8 Bytes / 64-bits) -> [MUTUAL AUTHENTICATION SUCCESS]        |");
    Serial.println("| \"AUTH_OK\\n\" (Hex: 415554485F4F4B0A)                                        |");
  } else {
    Serial.println("| Verdict Token (8 Bytes / 64-bits) -> [AUTHENTICATION REJECTED]              |");
    Serial.println("| \"AUTH_NO\\n\" (Hex: 415554485F4E4F0A)                                        |");
  }
  Serial.println("+-----------------------------------------------------------------------------+\n");

  return isOk;
}

// ============================================================================
// MASTER ORCHESTRATOR: OPTION A 4-MESSAGE MUTUAL AUTHENTICATION
// ============================================================================
bool AuthManager::performMutualAuthentication() {
  // --- MESSAGE 1: Client Hello (50 B) ---
  uint8_t clientNonce[CHALLENGE_NONCE_LENGTH];
  if (!sendClientHello(clientNonce)) {
    return false;
  }

  // --- MESSAGE 2: Server Proof (96 B) - Server Authenticates FIRST ---
  uint8_t serverNonce[CHALLENGE_NONCE_LENGTH];
  uint8_t serverSig[SIGNATURE_LENGTH];
  if (!receiveServerProof(clientNonce, serverNonce, serverSig)) {
    return false;
  }

  // --- MESSAGE 3: Client Proof (64 B) - Client binds Server Proof ---
  if (!sendClientProof(clientNonce, serverNonce, serverSig)) {
    return false;
  }

  // --- MESSAGE 4: Server Verdict (8 B) - Tunnel Open Confirmation ---
  if (!receiveServerVerdict()) {
    return false;
  }

  return true;
}
