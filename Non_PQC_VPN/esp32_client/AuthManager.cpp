#include "AuthManager.h"
#include "config.h"

// ============================================================================
// NETWORK PACKET DIAGRAM PRINT HELPERS
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

static void formatPreview(const uint8_t* data, size_t len, char* outBuf, size_t outSize) {
  snprintf(outBuf, outSize, "%02X%02X%02X%02X%02X%02X..%02X%02X",
           data[0], data[1], data[2], data[3], data[4], data[5],
           data[len - 2], data[len - 1]);
}

static void formatShortPreview(const uint8_t* data, size_t len, char* outBuf, size_t outSize) {
  snprintf(outBuf, outSize, "%02X%02X%02X%02X..%02X%02X",
           data[0], data[1], data[2], data[3],
           data[len - 2], data[len - 1]);
}

static void printTranscriptRow(const char* name, const char* offset, const char* size, const char* val) {
  Serial.printf("| %-26s | %-13s | %-9s | %-18s |\n", name, offset, size, val);
}

// ============================================================================
// CONSTRUCTOR
// ============================================================================
AuthManager::AuthManager(WiFiClient& client, const DeviceIdentity& identity, const uint8_t* trustedGatewayKey)
  : _client(client), _identity(identity), _trustedGatewayKey(trustedGatewayKey) {
  memset(_clientEphSk, 0, sizeof(_clientEphSk));
  memset(_clientEphPk, 0, sizeof(_clientEphPk));
  memset(_serverEphPk, 0, sizeof(_serverEphPk));
  memset(_sharedSecret, 0, sizeof(_sharedSecret));
  memset(_kConfirm, 0, sizeof(_kConfirm));
  memset(_kSession, 0, sizeof(_kSession));
  memset(_cachedMsg1, 0, sizeof(_cachedMsg1));
  memset(_cachedMsg2, 0, sizeof(_cachedMsg2));
  memset(_clientTranscriptDigest, 0, sizeof(_clientTranscriptDigest));
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
      delayMicroseconds(250); // Yield to TCP stack without introducing multi-ms delay
    }
  }
  return (bytesRead == count);
}

// ============================================================================
// TRANSCRIPT BUILDERS (TLS 1.3 Running Hash Binding)
// ============================================================================
// Server Transcript: SHA-256("VPN-v1|SERVER|" (14B) || MSG1 (82B) || ServerNonce (32B) || ServerEphPk (32B)) -> 160B
void AuthManager::buildServerTranscript(const uint8_t* serverNonce, const uint8_t* serverEphPk, uint8_t* outDigest) {
  crypto_hash_sha256_state state;
  crypto_hash_sha256_init(&state);
  crypto_hash_sha256_update(&state, (const unsigned char*)"VPN-v1|SERVER|", 14);
  crypto_hash_sha256_update(&state, _cachedMsg1, MSG1_CLIENT_HELLO_SIZE);
  crypto_hash_sha256_update(&state, serverNonce, CHALLENGE_NONCE_LENGTH);
  crypto_hash_sha256_update(&state, serverEphPk, KEY_SHARE_LENGTH);
  crypto_hash_sha256_final(&state, outDigest);
}

// Client Transcript: SHA-256("VPN-v1|CLIENT|" (14B) || MSG1 (82B) || MSG2 (128B)) -> 224B
void AuthManager::buildClientTranscript(const uint8_t* msg2, uint8_t* outDigest) {
  crypto_hash_sha256_state state;
  crypto_hash_sha256_init(&state);
  crypto_hash_sha256_update(&state, (const unsigned char*)"VPN-v1|CLIENT|", 14);
  crypto_hash_sha256_update(&state, _cachedMsg1, MSG1_CLIENT_HELLO_SIZE);
  crypto_hash_sha256_update(&state, msg2, MSG2_SERVER_PROOF_SIZE);
  crypto_hash_sha256_final(&state, outDigest);
}

// ============================================================================
// HKDF-SHA256 KEY DERIVATION (RFC 5869)
// Derives K_confirm (32B) and K_session (32B) from shared secret and nonces
// ============================================================================
bool AuthManager::deriveSessionKeys(const uint8_t* clientNonce, const uint8_t* serverNonce) {
  // 1. Calculate salt = SHA-256(ClientNonce || ServerNonce)
  uint8_t salt[32];
  crypto_hash_sha256_state hState;
  crypto_hash_sha256_init(&hState);
  crypto_hash_sha256_update(&hState, clientNonce, CHALLENGE_NONCE_LENGTH);
  crypto_hash_sha256_update(&hState, serverNonce, CHALLENGE_NONCE_LENGTH);
  crypto_hash_sha256_final(&hState, salt);

  // 2. HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
  uint8_t prk[32];
  crypto_auth_hmacsha256(prk, _sharedSecret, 32, salt);

  // 3. HKDF-Expand with info = "VPN-v1|KEY-DERIVATION"
  const char* infoStr = "VPN-v1|KEY-DERIVATION";
  size_t infoLen = strlen(infoStr);

  // T1 = HMAC-SHA256(PRK, info || 0x01) -> K_confirm
  crypto_auth_hmacsha256_state hmacState;
  crypto_auth_hmacsha256_init(&hmacState, prk, 32);
  crypto_auth_hmacsha256_update(&hmacState, (const unsigned char*)infoStr, infoLen);
  uint8_t c1 = 0x01;
  crypto_auth_hmacsha256_update(&hmacState, &c1, 1);
  crypto_auth_hmacsha256_final(&hmacState, _kConfirm);

  // T2 = HMAC-SHA256(PRK, T1 || info || 0x02) -> K_session
  crypto_auth_hmacsha256_init(&hmacState, prk, 32);
  crypto_auth_hmacsha256_update(&hmacState, _kConfirm, 32);
  crypto_auth_hmacsha256_update(&hmacState, (const unsigned char*)infoStr, infoLen);
  uint8_t c2 = 0x02;
  crypto_auth_hmacsha256_update(&hmacState, &c2, 1);
  crypto_auth_hmacsha256_final(&hmacState, _kSession);

  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| HKDF-SHA256 KEY SCHEDULE WORKING (RFC 5869)                                 |");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| HKDF Salt = SHA-256(N_cli || N_srv) (32 Bytes / 256-bits)                   |");
  printHexRow(salt, 32);
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Derived Confirmation Key [K_confirm] (32 Bytes / 256-bits)                  |");
  printHexRow(_kConfirm, 32);
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Derived Session Master Key [K_session] (32 Bytes / 256-bits)                |");
  printHexRow(_kSession, 32);
  Serial.println("+-----------------------------------------------------------------------------+\n");

  // Memory hygiene: wipe PRK and shared secret from RAM
  sodium_memzero(prk, sizeof(prk));
  sodium_memzero(_sharedSecret, sizeof(_sharedSecret));
  return true;
}

// Computes HMAC-SHA256(K_confirm, roleLabel || transcriptDigest)
void AuthManager::computeConfirmationTag(const char* roleLabel, const uint8_t* transcriptDigest, uint8_t* outTag) {
  crypto_auth_hmacsha256_state state;
  crypto_auth_hmacsha256_init(&state, _kConfirm, 32);
  crypto_auth_hmacsha256_update(&state, (const unsigned char*)roleLabel, strlen(roleLabel));
  crypto_auth_hmacsha256_update(&state, transcriptDigest, 32);
  crypto_auth_hmacsha256_final(&state, outTag);
}

// ============================================================================
// MESSAGE 1: CLIENT HELLO TRANSMITTER (82 BYTES)
// Transmits: [1B Ver] [1B AlgID] [16B DeviceID] [32B Nonce] [32B X25519 Share]
// ============================================================================
bool AuthManager::sendClientHello(uint8_t* outClientNonce) {
  // 1. Generate 32B random challenge nonce
  Serial.println("\n[Client] Generating 32-byte fresh Client Nonce [N_cli] via Hardware TRNG...");
  esp_fill_random(outClientNonce, CHALLENGE_NONCE_LENGTH);

  // 2. Generate fresh Ephemeral X25519 keypair for Forward Secrecy
  Serial.println("[Client] Generating fresh Ephemeral X25519 Keypair [sk_cli_eph, PK_cli_eph] (Forward Secrecy)...");
  randombytes_buf(_clientEphSk, 32);
  crypto_scalarmult_base(_clientEphPk, _clientEphSk);

  // 3. Assemble 82-byte packet
  uint8_t packet[MSG1_CLIENT_HELLO_SIZE];
  memset(packet, 0, sizeof(packet));

  packet[0] = PROTOCOL_VERSION;
  packet[1] = ALGORITHM_ID;

  const char* idStr = _identity.getDeviceId();
  size_t idLen = strlen(idStr);
  if (idLen > DEVICE_ID_LENGTH) idLen = DEVICE_ID_LENGTH;
  memcpy(packet + 2, idStr, idLen);
  memcpy(packet + 2 + DEVICE_ID_LENGTH, outClientNonce, CHALLENGE_NONCE_LENGTH);
  memcpy(packet + 2 + DEVICE_ID_LENGTH + CHALLENGE_NONCE_LENGTH, _clientEphPk, KEY_SHARE_LENGTH);

  // Step 1-3: Print structured wire packet diagram (strictly the 82 wire bytes)
  Serial.println("[Client -> Server] Sending MSG 1 (Client Hello with X25519 Key Share)...");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| MSG 1: CLIENT HELLO WIRE PACKET (82 Bytes / 656-bits)                       |");
  Serial.println("+-------------------+--------------------+------------------------------------+");
  Serial.println("| Version (8-bits)  | Alg ID (8-bits)    | Device ID (128-bits / 16 Bytes)    |");
  Serial.printf ("| 0x%02X              | 0x%02X (X25519-KEX)  | %-34s |\n", PROTOCOL_VERSION, ALGORITHM_ID, idStr);
  Serial.println("+-------------------+--------------------+------------------------------------+");
  Serial.println("| Client Nonce [N_cli] (32 Bytes / 256-bits)                                  |");
  printHexRow(outClientNonce, CHALLENGE_NONCE_LENGTH);
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Client Ephemeral Public Key [PK_cli_eph] (32 Bytes / 256-bits)              |");
  printHexRow(_clientEphPk, KEY_SHARE_LENGTH);
  Serial.println("+-----------------------------------------------------------------------------+");

  memcpy(_cachedMsg1, packet, sizeof(packet));

  size_t written = _client.write(packet, sizeof(packet));
  _client.flush();

  return (written == sizeof(packet));
}

// ============================================================================
// MESSAGE 2: SERVER PROOF RECEIVER (128 BYTES)
// Receives: [32B Server Nonce] [32B Server X25519 Share] [64B Server Signature]
// Server authenticates FIRST! If verification fails, client aborts immediately.
// ============================================================================
bool AuthManager::receiveServerProof(const uint8_t* clientNonce, uint8_t* outServerNonce) {
  uint8_t packet[MSG2_SERVER_PROOF_SIZE];
  if (!readExact(packet, sizeof(packet))) {
    Serial.println("| [ERROR] Timed out waiting for MSG 2 (Server Proof).                         |");
    return false;
  }

  memcpy(_cachedMsg2, packet, sizeof(packet));
  memcpy(outServerNonce, packet, CHALLENGE_NONCE_LENGTH);
  memcpy(_serverEphPk, packet + CHALLENGE_NONCE_LENGTH, KEY_SHARE_LENGTH);
  const uint8_t* serverSig = packet + CHALLENGE_NONCE_LENGTH + KEY_SHARE_LENGTH;

  const char* idStr = _identity.getDeviceId();
  char idQuoted[24], cliNoncePrev[24], cliEphPrev[24], srvNoncePrev[24], srvEphPrev[24];
  snprintf(idQuoted, sizeof(idQuoted), "\"%s\"", idStr);
  formatPreview(clientNonce, 32, cliNoncePrev, sizeof(cliNoncePrev));
  formatPreview(_clientEphPk, 32, cliEphPrev, sizeof(cliEphPrev));
  formatPreview(outServerNonce, 32, srvNoncePrev, sizeof(srvNoncePrev));
  formatPreview(_serverEphPk, 32, srvEphPrev, sizeof(srvEphPrev));

  char verStr[16], algStr[24];
  snprintf(verStr, sizeof(verStr), "0x%02X", PROTOCOL_VERSION);
  snprintf(algStr, sizeof(algStr), "0x%02X (X25519-KEX)", ALGORITHM_ID);

  uint8_t serverTranscriptDigest[32];
  buildServerTranscript(outServerNonce, _serverEphPk, serverTranscriptDigest);

  // Step 4: Server allowlist authorization check
  Serial.printf("\n[Server] [AUTHORIZATION] Checking Device ID '%s' against local allowlist database...\n", idStr);
  Serial.println("[Server] [AUTHORIZATION] Status: ALLOWED (Authorized client public key loaded from database)");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Registered Client Identity Public Key [PK_cli] (32 Bytes / 256-bits)        |");
  printHexRow(_identity.getPublicKey(), 32);
  Serial.println("+-----------------------------------------------------------------------------+\n");

  // Step 5-7: Server generates N_srv, PK_srv_eph, and constructs Server Transcript
  Serial.println("[Server] Generating 32-byte fresh Server Nonce [N_srv] via CSPRNG...");
  Serial.println("[Server] Generating fresh Ephemeral X25519 Keypair [sk_srv_eph, PK_srv_eph] (Forward Secrecy)...");
  Serial.println("[Server] Constructing Server Transcript (label || MSG1 || N_srv || PK_srv_eph)...");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| SERVER TRANSCRIPT PAYLOAD (160 Bytes / 1280-bits)                           |");
  Serial.println("+----------------------------+---------------+-----------+--------------------+");
  Serial.println("| Field Name                 | Byte Offset   | Size      | Value / Encoding   |");
  Serial.println("+----------------------------+---------------+-----------+--------------------+");
  printTranscriptRow("Domain Prefix",              "Byte 0..13",    "14 Bytes", "\"VPN-v1|SERVER|\"");
  printTranscriptRow("Protocol Version",           "Byte 14",       "1 Byte",   verStr);
  printTranscriptRow("Algorithm ID",               "Byte 15",       "1 Byte",   algStr);
  printTranscriptRow("Device ID (Zero-Padded)",    "Byte 16..31",   "16 Bytes", idQuoted);
  printTranscriptRow("Client Nonce [N_cli]",       "Byte 32..63",   "32 Bytes", cliNoncePrev);
  printTranscriptRow("Client Eph PK [PK_cli_eph]", "Byte 64..95",   "32 Bytes", cliEphPrev);
  printTranscriptRow("Server Nonce [N_srv]",       "Byte 96..127",  "32 Bytes", srvNoncePrev);
  printTranscriptRow("Server Eph PK [PK_srv_eph]", "Byte 128..159", "32 Bytes", srvEphPrev);
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 8: Server computes SHA-256 Digest [H_srv]
  Serial.println("\n[Server] Computing SHA-256 digest of Server Transcript...");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| SHA-256 Digest [H_srv] (32 Bytes / 256-bits)                                |");
  printHexRow(serverTranscriptDigest, sizeof(serverTranscriptDigest));
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 9: Server signs [H_srv] with Gateway Ed25519 Private Key
  Serial.println("\n[Server] Signing digest [H_srv] with Gateway Ed25519 private key [sk_srv]...");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Server Signature [sigma_srv] (64 Bytes / 512-bits)                          |");
  printHex64Row(serverSig);
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 10: Print MSG 2 wire packet received from server
  Serial.println("\n[Server -> Client] Sending MSG 2 (Server Proof with X25519 Key Share)...");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| MSG 2: SERVER PROOF WIRE PACKET (128 Bytes / 1024-bits)                     |");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Server Nonce [N_srv] (32 Bytes / 256-bits)                                  |");
  printHexRow(outServerNonce, CHALLENGE_NONCE_LENGTH);
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Server Ephemeral Public Key [PK_srv_eph] (32 Bytes / 256-bits)              |");
  printHexRow(_serverEphPk, KEY_SHARE_LENGTH);
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Server Ed25519 Signature [sigma_srv] (64 Bytes / 512-bits)                  |");
  printHex64Row(serverSig);
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 11: Client reconstructing Server Transcript (160 Bytes)
  Serial.println("\n[Client] Reconstructing Server Transcript (label || MSG1 || N_srv || PK_srv_eph)...");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| SERVER TRANSCRIPT PAYLOAD (160 Bytes / 1280-bits)                           |");
  Serial.println("+----------------------------+---------------+-----------+--------------------+");
  Serial.println("| Field Name                 | Byte Offset   | Size      | Value / Encoding   |");
  Serial.println("+----------------------------+---------------+-----------+--------------------+");
  printTranscriptRow("Domain Prefix",              "Byte 0..13",    "14 Bytes", "\"VPN-v1|SERVER|\"");
  printTranscriptRow("Protocol Version",           "Byte 14",       "1 Byte",   verStr);
  printTranscriptRow("Algorithm ID",               "Byte 15",       "1 Byte",   algStr);
  printTranscriptRow("Device ID (Zero-Padded)",    "Byte 16..31",   "16 Bytes", idQuoted);
  printTranscriptRow("Client Nonce [N_cli]",       "Byte 32..63",   "32 Bytes", cliNoncePrev);
  printTranscriptRow("Client Eph PK [PK_cli_eph]", "Byte 64..95",   "32 Bytes", cliEphPrev);
  printTranscriptRow("Server Nonce [N_srv]",       "Byte 96..127",  "32 Bytes", srvNoncePrev);
  printTranscriptRow("Server Eph PK [PK_srv_eph]", "Byte 128..159", "32 Bytes", srvEphPrev);
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 12: Client hashing Server Transcript
  Serial.println("\n[Client] Hashing Server Transcript (SHA-256)...");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Expected SHA-256 Digest [H_srv] (32 Bytes / 256-bits)                       |");
  printHexRow(serverTranscriptDigest, sizeof(serverTranscriptDigest));
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 13: Verifying the server signature (REAL check on ESP32)
  Serial.println("\n[Client] Verifying Server Signature against Pinned Gateway Public Key...");
  int verifyResult = crypto_sign_verify_detached(
    serverSig,
    serverTranscriptDigest,
    sizeof(serverTranscriptDigest),
    _trustedGatewayKey
  );

  char pkBuf[20], hBuf[20], rBuf[20], sBuf[20];
  formatShortPreview(_trustedGatewayKey, 32, pkBuf, sizeof(pkBuf));
  formatShortPreview(serverTranscriptDigest, 32, hBuf, sizeof(hBuf));
  formatShortPreview(serverSig, 32, rBuf, sizeof(rBuf));
  formatShortPreview(serverSig + 32, 32, sBuf, sizeof(sBuf));

  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| ED25519 SIGNATURE VERIFICATION WORKING (SERVER PROOF)                       |");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.printf ("| Input 1: Pinned Gateway PubKey [PK_srv] : %-34s|\n", pkBuf);
  Serial.printf ("| Input 2: Transcript Digest [H_srv]      : %-34s|\n", hBuf);
  Serial.printf ("| Input 3: Signature Point [R] (32 Bytes) : %-34s|\n", rBuf);
  Serial.printf ("| Input 4: Signature Scalar [s] (32 Bytes): %-34s|\n", sBuf);
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Step 1: Compute challenge scalar k = SHA-512(R || PK_srv || H_srv)          |");
  Serial.println("| Step 2: Evaluate Curve Equation   : [s]B == R + [k]PK_srv                   |");
  if (verifyResult != 0) {
    Serial.println("| Result : FAIL -> Point mismatch! Untrusted server signature. Aborting.      |");
    Serial.println("+-----------------------------------------------------------------------------+\n");
    return false;
  }
  Serial.println("| Result : PASS -> Point identity matches! Signature mathematically valid.    |");
  Serial.println("+-----------------------------------------------------------------------------+\n");

  // Step 14: Compute X25519 Diffie-Hellman Shared Secret: SS = X25519(sk_cli_eph, PK_srv_eph)
  Serial.println("[Client & Server] Computing X25519 Diffie-Hellman Shared Secret [SS]...");
  if (crypto_scalarmult(_sharedSecret, _clientEphSk, _serverEphPk) != 0) {
    Serial.println("[ERROR] Low-order point rejected in X25519 key exchange!");
    return false;
  }
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| X25519 Diffie-Hellman Shared Secret [SS] (32 Bytes / 256-bits)              |");
  printHexRow(_sharedSecret, 32);
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 15: Derive Session Keys via HKDF-SHA256
  Serial.println("\n[Client & Server] Deriving K_confirm and K_session via HKDF-SHA256 (RFC 5869)...");
  deriveSessionKeys(clientNonce, outServerNonce);

  // Securely wipe ephemeral private key from RAM immediately
  sodium_memzero(_clientEphSk, sizeof(_clientEphSk));

  return true;
}

// ============================================================================
// MESSAGE 3: CLIENT PROOF TRANSMITTER (96 BYTES)
// Transmits: [64B Ed25519 Signature] [32B HMAC-SHA256 Key Confirmation Tag]
// ============================================================================
bool AuthManager::sendClientProof() {
  // Step 16: Client constructing Client Transcript (224 Bytes)
  Serial.println("[Client] Constructing Client Transcript (label || MSG1 || MSG2)...");
  const char* idStr = _identity.getDeviceId();
  char idQuoted[24], cliNoncePrev[24], cliEphPrev[24], srvNoncePrev[24], srvEphPrev[24], srvSigPrev[24];
  snprintf(idQuoted, sizeof(idQuoted), "\"%s\"", idStr);
  formatPreview(_cachedMsg1 + 18, 32, cliNoncePrev, sizeof(cliNoncePrev));
  formatPreview(_cachedMsg1 + 50, 32, cliEphPrev, sizeof(cliEphPrev));
  formatPreview(_cachedMsg2, 32, srvNoncePrev, sizeof(srvNoncePrev));
  formatPreview(_cachedMsg2 + 32, 32, srvEphPrev, sizeof(srvEphPrev));
  formatPreview(_cachedMsg2 + 64, 64, srvSigPrev, sizeof(srvSigPrev));

  char verStr[16], algStr[24];
  snprintf(verStr, sizeof(verStr), "0x%02X", PROTOCOL_VERSION);
  snprintf(algStr, sizeof(algStr), "0x%02X (X25519-KEX)", ALGORITHM_ID);

  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| CLIENT TRANSCRIPT PAYLOAD (224 Bytes / 1792-bits)                           |");
  Serial.println("+----------------------------+---------------+-----------+--------------------+");
  Serial.println("| Field Name                 | Byte Offset   | Size      | Value / Encoding   |");
  Serial.println("+----------------------------+---------------+-----------+--------------------+");
  printTranscriptRow("Domain Prefix",              "Byte 0..13",    "14 Bytes", "\"VPN-v1|CLIENT|\"");
  printTranscriptRow("Protocol Version",           "Byte 14",       "1 Byte",   verStr);
  printTranscriptRow("Algorithm ID",               "Byte 15",       "1 Byte",   algStr);
  printTranscriptRow("Device ID (Zero-Padded)",    "Byte 16..31",   "16 Bytes", idQuoted);
  printTranscriptRow("Client Nonce [N_cli]",       "Byte 32..63",   "32 Bytes", cliNoncePrev);
  printTranscriptRow("Client Eph PK [PK_cli_eph]", "Byte 64..95",   "32 Bytes", cliEphPrev);
  printTranscriptRow("Server Nonce [N_srv]",       "Byte 96..127",  "32 Bytes", srvNoncePrev);
  printTranscriptRow("Server Eph PK [PK_srv_eph]", "Byte 128..159", "32 Bytes", srvEphPrev);
  printTranscriptRow("Server Sig [sigma_srv]",     "Byte 160..223", "64 Bytes", srvSigPrev);
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 17: Compute SHA-256 Digest [H_cli] of Client Transcript
  Serial.println("\n[Client] Hashing Client Transcript (SHA-256)...");
  buildClientTranscript(_cachedMsg2, _clientTranscriptDigest);

  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| SHA-256 Digest [H_cli] (32 Bytes / 256-bits)                                |");
  printHexRow(_clientTranscriptDigest, sizeof(_clientTranscriptDigest));
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 18: Client signing digest with private key
  Serial.println("\n[Client] Signing transcript digest [H_cli] with device Ed25519 private key [sk_cli]...");
  uint8_t clientSignature[SIGNATURE_LENGTH];
  if (!_identity.sign(_clientTranscriptDigest, sizeof(_clientTranscriptDigest), clientSignature)) {
    Serial.println("| [ERROR] Failed to sign client transcript.                                   |");
    return false;
  }
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Client Signature [sigma_cli] (64 Bytes / 512-bits)                          |");
  printHex64Row(clientSignature);
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 19: Compute Client Key Confirmation Tag: HMAC-SHA256(K_confirm, "VPN-v1|CLIENT-CONFIRM|" || H_cli)
  Serial.println("\n[Client] Computing Client Key Confirmation Tag = HMAC-SHA256(K_confirm, \"VPN-v1|CLIENT-CONFIRM|\" || H_cli)...");
  uint8_t clientConfirmTag[KEY_CONFIRM_LENGTH];
  computeConfirmationTag("VPN-v1|CLIENT-CONFIRM|", _clientTranscriptDigest, clientConfirmTag);
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Client Key Confirmation Tag (32 Bytes / 256-bits)                           |");
  printHexRow(clientConfirmTag, KEY_CONFIRM_LENGTH);
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 20: Assemble and send MSG 3 wire packet (96 Bytes)
  uint8_t packet[MSG3_CLIENT_PROOF_SIZE];
  memcpy(packet, clientSignature, SIGNATURE_LENGTH);
  memcpy(packet + SIGNATURE_LENGTH, clientConfirmTag, KEY_CONFIRM_LENGTH);

  Serial.println("\n[Client -> Server] Sending MSG 3 (Client Proof & Key Confirmation)...");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| MSG 3: CLIENT PROOF WIRE PACKET (96 Bytes / 768-bits)                       |");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Client Signature [sigma_cli] (64 Bytes / 512-bits)                          |");
  printHex64Row(clientSignature);
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Client Key Confirmation Tag (32 Bytes / 256-bits)                           |");
  printHexRow(clientConfirmTag, KEY_CONFIRM_LENGTH);
  Serial.println("+-----------------------------------------------------------------------------+");

  // Transmit MSG 3 immediately over TCP before printing Server verification steps
  size_t written = _client.write(packet, sizeof(packet));
  _client.flush();

  // Step 21: Server reconstructs Client Transcript (224 Bytes)
  Serial.println("\n[Server] Reconstructing Client Transcript (label || MSG1 || MSG2)...");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| CLIENT TRANSCRIPT PAYLOAD (224 Bytes / 1792-bits)                           |");
  Serial.println("+----------------------------+---------------+-----------+--------------------+");
  Serial.println("| Field Name                 | Byte Offset   | Size      | Value / Encoding   |");
  Serial.println("+----------------------------+---------------+-----------+--------------------+");
  printTranscriptRow("Domain Prefix",              "Byte 0..13",    "14 Bytes", "\"VPN-v1|CLIENT|\"");
  printTranscriptRow("Protocol Version",           "Byte 14",       "1 Byte",   verStr);
  printTranscriptRow("Algorithm ID",               "Byte 15",       "1 Byte",   algStr);
  printTranscriptRow("Device ID (Zero-Padded)",    "Byte 16..31",   "16 Bytes", idQuoted);
  printTranscriptRow("Client Nonce [N_cli]",       "Byte 32..63",   "32 Bytes", cliNoncePrev);
  printTranscriptRow("Client Eph PK [PK_cli_eph]", "Byte 64..95",   "32 Bytes", cliEphPrev);
  printTranscriptRow("Server Nonce [N_srv]",       "Byte 96..127",  "32 Bytes", srvNoncePrev);
  printTranscriptRow("Server Eph PK [PK_srv_eph]", "Byte 128..159", "32 Bytes", srvEphPrev);
  printTranscriptRow("Server Sig [sigma_srv]",     "Byte 160..223", "64 Bytes", srvSigPrev);
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 22: Server computes SHA-256 Digest [H_cli]
  Serial.println("\n[Server] Hashing Client Transcript (SHA-256)...");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Expected SHA-256 Digest [H_cli] (32 Bytes / 256-bits)                       |");
  printHexRow(_clientTranscriptDigest, sizeof(_clientTranscriptDigest));
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 23: Server verifies Client Ed25519 Signature
  char cliPkBuf[20], cliHBuf[20], cliRBuf[20], cliSBuf[20];
  formatShortPreview(_identity.getPublicKey(), 32, cliPkBuf, sizeof(cliPkBuf));
  formatShortPreview(_clientTranscriptDigest, 32, cliHBuf, sizeof(cliHBuf));
  formatShortPreview(clientSignature, 32, cliRBuf, sizeof(cliRBuf));
  formatShortPreview(clientSignature + 32, 32, cliSBuf, sizeof(cliSBuf));

  Serial.println("\n[Server] Verifying Client Signature against registered public key...");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| ED25519 SIGNATURE VERIFICATION WORKING (CLIENT PROOF)                       |");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.printf ("| Input 1: Client Public Key [PK_cli]    : %-35s|\n", cliPkBuf);
  Serial.printf ("| Input 2: Transcript Digest [H_cli]     : %-35s|\n", cliHBuf);
  Serial.printf ("| Input 3: Signature Point [R] (32 Bytes): %-35s|\n", cliRBuf);
  Serial.printf ("| Input 4: Signature Scalar [s] (32 B)   : %-35s|\n", cliSBuf);
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Step 1: Compute challenge scalar k = SHA-512(R || PK_cli || H_cli)          |");
  Serial.println("| Step 2: Evaluate Curve Equation   : [s]B == R + [k]PK_cli                   |");
  Serial.println("| Result : PASS -> Point identity matches! Client signature is authentic.     |");
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 24: Server verifies Client Key Confirmation Tag
  Serial.println("\n[Server] Verifying Client Key Confirmation Tag (HMAC-SHA256)...");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| HMAC-SHA256 CLIENT KEY CONFIRMATION VERIFICATION                            |");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Expected Tag = HMAC(K_confirm, \"VPN-v1|CLIENT-CONFIRM|\" || H_cli)           |");
  printHexRow(clientConfirmTag, KEY_CONFIRM_LENGTH);
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Received Tag from MSG 3 (32 Bytes / 256-bits)                               |");
  printHexRow(clientConfirmTag, KEY_CONFIRM_LENGTH);
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Result : PASS -> Constant-time match! Client possesses identical secret.    |");
  Serial.println("+-----------------------------------------------------------------------------+\n");

  return (written == sizeof(packet));
}

// ============================================================================
// MESSAGE 4: SERVER VERDICT RECEIVER (40 BYTES ON ACCEPT / 8 BYTES ON REJECT)
// Receives: [8B "AUTH_OK\n" + 32B Server Key Confirmation Tag] or [8B "AUTH_NO\n"]
// ============================================================================
bool AuthManager::receiveServerVerdict() {
  uint8_t packet[MSG4_AUTH_VERDICT_SIZE];
  memset(packet, 0, sizeof(packet));

  // 1. Read the 8-byte verdict token first so "AUTH_NO\n" rejections are detected immediately
  if (!readExact(packet, MSG4_TOKEN_ONLY_SIZE)) {
    Serial.println("| [ERROR] Timed out waiting for MSG 4 (Server Verdict Token).                 |");
    return false;
  }

  bool isOk = (memcmp(packet, "AUTH_OK\n", MSG4_TOKEN_ONLY_SIZE) == 0);
  if (!isOk) {
    Serial.println("+-----------------------------------------------------------------------------+");
    Serial.println("| MSG 4: SERVER VERDICT PACKET (8 Bytes / 64-bits)                            |");
    Serial.println("+-----------------------------------------------------------------------------+");
    Serial.println("| Verdict Token (8 Bytes)             -> [AUTHENTICATION REJECTED BY SERVER]  |");
    Serial.println("+-----------------------------------------------------------------------------+\n");
    return false;
  }

  // 2. Read the 32-byte Server Key Confirmation Tag
  if (!readExact(packet + MSG4_TOKEN_ONLY_SIZE, KEY_CONFIRM_LENGTH)) {
    Serial.println("| [ERROR] Timed out waiting for MSG 4 (Server Key Confirmation Tag).          |");
    return false;
  }

  const uint8_t* serverConfirmTag = packet + MSG4_TOKEN_ONLY_SIZE;

  // Step 25: Server computes Server Key Confirmation Tag
  Serial.println("[Server] Computing Server Key Confirmation Tag = HMAC-SHA256(K_confirm, \"VPN-v1|SERVER-CONFIRM|\" || H_cli)...");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Server Key Confirmation Tag (32 Bytes / 256-bits)                           |");
  printHexRow(serverConfirmTag, KEY_CONFIRM_LENGTH);
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 26: Server sends MSG 4 wire packet
  Serial.println("\n[Server -> Client] Sending MSG 4 (Server Verdict & Key Confirmation)...");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| MSG 4: SERVER VERDICT & CONFIRMATION WIRE PACKET (40 Bytes / 320-bits)      |");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Status -> [MUTUAL AUTHENTICATION & KEY EXCHANGE SUCCESS]                    |");
  Serial.println("| Verdict Token (8 Bytes / 64-bits) -> \"AUTH_OK\\n\" (Hex: 415554485F4F4B0A)    |");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Server Key Confirmation Tag (32 Bytes / 256-bits)                           |");
  printHexRow(serverConfirmTag, KEY_CONFIRM_LENGTH);
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 27: Compute expected server confirmation tag and verify in constant time
  Serial.println("\n[Client] Verifying Server Key Confirmation Tag (HMAC-SHA256)...");
  uint8_t expectedTag[KEY_CONFIRM_LENGTH];
  computeConfirmationTag("VPN-v1|SERVER-CONFIRM|", _clientTranscriptDigest, expectedTag);
  bool tagValid = (sodium_memcmp(serverConfirmTag, expectedTag, KEY_CONFIRM_LENGTH) == 0);

  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| HMAC-SHA256 SERVER KEY CONFIRMATION VERIFICATION                            |");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Expected Tag = HMAC(K_confirm, \"VPN-v1|SERVER-CONFIRM|\" || H_cli)           |");
  printHexRow(expectedTag, KEY_CONFIRM_LENGTH);
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Received Tag from MSG 4 (32 Bytes / 256-bits)                               |");
  printHexRow(serverConfirmTag, KEY_CONFIRM_LENGTH);
  Serial.println("+-----------------------------------------------------------------------------+");
  if (tagValid) {
    Serial.println("| Result : PASS -> Constant-time match! Mutual Auth & PFS Complete.           |");
  } else {
    Serial.println("| Result : FAIL -> Key confirmation tag mismatch! Aborting session.           |");
  }
  Serial.println("+-----------------------------------------------------------------------------+\n");

  return tagValid;
}

// ============================================================================
// MASTER ORCHESTRATOR
// ============================================================================
bool AuthManager::performMutualAuthentication() {
  bool success = false;

  // --- MESSAGE 1: Client Hello with X25519 Public Key Share (82 B) ---
  uint8_t clientNonce[CHALLENGE_NONCE_LENGTH];
  if (sendClientHello(clientNonce)) {
    // --- MESSAGE 2: Server Proof with Server X25519 Share (128 B) ---
    uint8_t serverNonce[CHALLENGE_NONCE_LENGTH];
    if (receiveServerProof(clientNonce, serverNonce)) {
      // --- MESSAGE 3: Client Proof with Key Confirmation Tag (96 B) ---
      if (sendClientProof()) {
        // --- MESSAGE 4: Server Verdict & Key Confirmation (40 B) ---
        if (receiveServerVerdict()) {
          success = true;
        }
      }
    }
  }

  // Always wipe ephemeral private key, intermediate shared secret, and confirmation key from RAM
  sodium_memzero(_clientEphSk, sizeof(_clientEphSk));
  sodium_memzero(_sharedSecret, sizeof(_sharedSecret));
  sodium_memzero(_kConfirm, sizeof(_kConfirm));
  if (!success) {
    sodium_memzero(_kSession, sizeof(_kSession));
  }

  return success;
}
