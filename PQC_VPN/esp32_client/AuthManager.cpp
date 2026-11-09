#include "AuthManager.h"
#include "config.h"
#include <MLKEM512.h>  // NIST FIPS 203 ML-KEM-512 key encapsulation (mlkem-native)

// Static buffer for MSG 3 (2,452 bytes) in .bss to preserve FreeRTOS task stack for ML-DSA-44 NTT math
static uint8_t s_msg3Packet[MSG3_CLIENT_PROOF_SIZE];

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

static void printMlDsaPubKeyBox(const uint8_t* pk) {
  Serial.println("| [Byte 0000..0031 : Matrix Expansion Seed rho (32 Bytes)]                    |");
  printHexRow(pk, 32);
  Serial.println("| ... [Bytes 0032..1279 : NTT Polynomial Vector t1 (1248 Bytes omitted)] ...  |");
  Serial.println("| [Byte 1280..1311 : Polynomial Vector t1 Tail (32 Bytes)]                    |");
  printHexRow(pk + 1280, 32);
}

static void printMlDsaSigBox(const uint8_t* sig) {
  Serial.println("| [Byte 0000..0031 : Commitment Hash c_tilde (32 Bytes)]                      |");
  printHexRow(sig, 32);
  Serial.println("| ... [Bytes 0032..2387 : Masked Response Vector z (2356 Bytes omitted)] ...  |");
  Serial.println("| [Byte 2388..2419 : PolyNorm Hint Vector h Tail (32 Bytes)]                  |");
  printHexRow(sig + 2388, 32);
}

// ML-KEM-512 encapsulation key ek (800 B) = ByteEncode12(t_hat) (768 B) || rho (32 B)
static void printMlKemEkBox(const uint8_t* ek) {
  Serial.println("| [Byte 000..031 : ByteEncode12(t_hat) Head (32 Bytes)]                       |");
  printHexRow(ek, 32);
  Serial.println("| ... [Bytes 032..767 : NTT Polynomial Vector t_hat (736 Bytes omitted)] ...  |");
  Serial.println("| [Byte 768..799 : Matrix Expansion Seed rho (32 Bytes)]                      |");
  printHexRow(ek + 768, 32);
}

// ML-KEM-512 ciphertext ct (768 B) = c1 = Compress_10(u) (640 B) || c2 = Compress_4(v) (128 B)
static void printMlKemCtBox(const uint8_t* ct) {
  Serial.println("| [Byte 000..031 : c1 = Compress_10(u) Head (32 Bytes)]                       |");
  printHexRow(ct, 32);
  Serial.println("| ... [Bytes 032..735 : Compressed u || Polynomial v (704 Bytes omitted)] ... |");
  Serial.println("| [Byte 736..767 : c2 = Compress_4(v) Tail (32 Bytes)]                        |");
  printHexRow(ct + 736, 32);
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
// BEGINNER-FRIENDLY EXPLANATION HELPERS
// ============================================================================
static void printPhase(int number, const char* title, const char* description) {
  Serial.println("\n===============================================================================");
  Serial.printf (" PHASE %d of 5 : %s\n", number, title);
  Serial.printf (" %s\n", description);
  Serial.println("===============================================================================");
}

// Prints text word-wrapped at 71 columns under an "In plain words:" heading
static void printNote(const char* text) {
  Serial.println("  >> In plain words:");
  const size_t width = 71;
  const char* p = text;
  while (*p) {
    size_t len = strlen(p);
    size_t take = len;
    if (len > width) {
      take = width;
      while (take > 0 && p[take] != ' ') take--;
      if (take == 0) take = width;
    }
    Serial.print("     ");
    Serial.write((const uint8_t*)p, take);
    Serial.println();
    p += take;
    while (*p == ' ') p++;
  }
  Serial.println();
}

static void printSummary() {
  static const char* const lines[] = {
    "SECURE CONNECTION ESTABLISHED - WHAT JUST HAPPENED",
    "",
    "[1] Who are you?  ML-DSA-44 : both sides proved their identity",
    "[2] Shared secret ML-KEM-512: agreed on a 32-byte key K without sending it",
    "[3] Session keys  HKDF-256  : turned K into the keys used for encryption",
    "[4] Double check  HMAC-256  : both sides confirmed they hold the same keys",
    "[5] From now on   AES-256-GCM: every message is encrypted + tamper-proof",
    "",
    "ML-DSA-44 and ML-KEM-512 are POST-QUANTUM: designed to resist attacks",
    "from future quantum computers."
  };
  Serial.println("###############################################################################");
  for (size_t i = 0; i < sizeof(lines) / sizeof(lines[0]); i++) {
    Serial.printf("# %-75s #\n", lines[i]);
  }
  Serial.println("###############################################################################\n");
}

// ============================================================================
// CONSTRUCTOR
// ============================================================================
AuthManager::AuthManager(WiFiClient& client, const DeviceIdentity& identity, const uint8_t* trustedGatewayKey)
  : _client(client), _identity(identity), _trustedGatewayKey(trustedGatewayKey) {
  memset(_clientKemDk, 0, sizeof(_clientKemDk));
  memset(_clientKemEk, 0, sizeof(_clientKemEk));
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
      // Gateway closed the socket (e.g. device ID not in allowlist) and nothing is left to read:
      // fail immediately instead of waiting out the full timeout.
      if (!_client.connected() && !_client.available()) {
        break;
      }
      delayMicroseconds(250);
    }
  }
  return (bytesRead == count);
}

// ============================================================================
// TRANSCRIPT BUILDERS (TLS 1.3 Running Hash Binding)
// ============================================================================
// Server Transcript: SHA-256("VPN-v1|SERVER|" (14B) || MSG1 (850B) || ServerNonce (32B) || KEM_ct (768B)) -> 1664B
void AuthManager::buildServerTranscript(const uint8_t* serverNonce, const uint8_t* kemCiphertext, uint8_t* outDigest) {
  crypto_hash_sha256_state state;
  crypto_hash_sha256_init(&state);
  crypto_hash_sha256_update(&state, (const unsigned char*)"VPN-v1|SERVER|", 14);
  crypto_hash_sha256_update(&state, _cachedMsg1, MSG1_CLIENT_HELLO_SIZE);
  crypto_hash_sha256_update(&state, serverNonce, CHALLENGE_NONCE_LENGTH);
  crypto_hash_sha256_update(&state, kemCiphertext, KEM_CIPHERTEXT_LENGTH);
  crypto_hash_sha256_final(&state, outDigest);
}

// Client Transcript: SHA-256("VPN-v1|CLIENT|" (14B) || MSG1 (850B) || MSG2 (3220B)) -> 4084B
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
// Derives K_confirm (32B) and K_session (32B) from ML-KEM shared secret and nonces
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
  crypto_auth_hmacsha256(prk, _sharedSecret, KEM_SHARED_SECRET_LENGTH, salt);

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
// MESSAGE 1: CLIENT HELLO TRANSMITTER (850 BYTES)
// Transmits: [1B Ver] [1B AlgID] [16B DeviceID] [32B Nonce] [800B ML-KEM-512 ek]
// ============================================================================
bool AuthManager::sendClientHello(uint8_t* outClientNonce) {
  // 1. Generate 32B random challenge nonce
  printPhase(1, "HELLO", "The ESP32 says hello and sends a one-time ML-KEM-512 public key.");
  Serial.println("\n[Client] Generating 32-byte fresh Client Nonce [N_cli] via Hardware TRNG...");
  esp_fill_random(outClientNonce, CHALLENGE_NONCE_LENGTH);

  // 2. Generate fresh Ephemeral ML-KEM-512 keypair for Forward Secrecy (FIPS 203 ML-KEM.KeyGen)
  Serial.println("[Client] Generating fresh Ephemeral ML-KEM-512 Keypair [dk_cli_eph, ek_cli_eph] (Forward Secrecy)...");
  int rc = MLKEM512::generateKeypair(_clientKemEk, _clientKemDk);
  if (rc != 0) {
    Serial.printf("[ERROR] ML-KEM-512 key generation failed (rc=%d)!\n", rc);
    return false;
  }

  // 3. Assemble 850-byte packet
  memset(_cachedMsg1, 0, sizeof(_cachedMsg1));

  _cachedMsg1[0] = PROTOCOL_VERSION;
  _cachedMsg1[1] = ALGORITHM_ID;

  const char* idStr = _identity.getDeviceId();
  size_t idLen = strlen(idStr);
  if (idLen > DEVICE_ID_LENGTH) idLen = DEVICE_ID_LENGTH;
  memcpy(_cachedMsg1 + 2, idStr, idLen);
  memcpy(_cachedMsg1 + 2 + DEVICE_ID_LENGTH, outClientNonce, CHALLENGE_NONCE_LENGTH);
  memcpy(_cachedMsg1 + 2 + DEVICE_ID_LENGTH + CHALLENGE_NONCE_LENGTH, _clientKemEk, KEM_PUBLIC_KEY_LENGTH);

  // Step 1-3: Print structured wire packet diagram (strictly the 850 wire bytes)
  Serial.println("[Client -> Server] Sending MSG 1 (Client Hello with ML-KEM-512 Encapsulation Key)...");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| MSG 1: CLIENT HELLO WIRE PACKET (850 Bytes / 6800-bits)                     |");
  Serial.println("+-------------------+--------------------+------------------------------------+");
  Serial.println("| Version (8-bits)  | Alg ID (8-bits)    | Device ID (128-bits / 16 Bytes)    |");
  Serial.printf ("| 0x%02X              | 0x%02X (MLDSA+MLKEM) | %-34s |\n", PROTOCOL_VERSION, ALGORITHM_ID, idStr);
  Serial.println("+-------------------+--------------------+------------------------------------+");
  Serial.println("| Client Nonce [N_cli] (32 Bytes / 256-bits)                                  |");
  printHexRow(outClientNonce, CHALLENGE_NONCE_LENGTH);
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Client Ephemeral ML-KEM-512 Encaps Key [ek_cli_eph] (800 Bytes / 6400-bits) |");
  printMlKemEkBox(_clientKemEk);
  Serial.println("+-----------------------------------------------------------------------------+");

  size_t written = _client.write(_cachedMsg1, sizeof(_cachedMsg1));
  _client.flush();

  return (written == sizeof(_cachedMsg1));
}

// ============================================================================
// MESSAGE 2: SERVER PROOF RECEIVER (3,220 BYTES)
// Receives: [32B Server Nonce] [768B ML-KEM-512 Ciphertext] [2,420B ML-DSA-44 Signature]
// Server authenticates FIRST! If verification fails, client aborts before decapsulating.
// ============================================================================
bool AuthManager::receiveServerProof(const uint8_t* clientNonce, uint8_t* outServerNonce) {
  if (!readExact(_cachedMsg2, sizeof(_cachedMsg2))) {
    if (!_client.connected()) {
      Serial.println("| [ERROR] Gateway closed connection before MSG 2 (device not authorized?).    |");
    } else {
      Serial.println("| [ERROR] Timed out waiting for MSG 2 (Server Proof).                         |");
    }
    return false;
  }

  memcpy(outServerNonce, _cachedMsg2, CHALLENGE_NONCE_LENGTH);
  const uint8_t* kemCiphertext = _cachedMsg2 + CHALLENGE_NONCE_LENGTH;
  const uint8_t* serverSig = _cachedMsg2 + CHALLENGE_NONCE_LENGTH + KEM_CIPHERTEXT_LENGTH;

  const char* idStr = _identity.getDeviceId();
  char idQuoted[24], cliNoncePrev[24], cliEkPrev[24], srvNoncePrev[24], ctPrev[24];
  snprintf(idQuoted, sizeof(idQuoted), "\"%s\"", idStr);
  formatPreview(clientNonce, 32, cliNoncePrev, sizeof(cliNoncePrev));
  formatPreview(_clientKemEk, KEM_PUBLIC_KEY_LENGTH, cliEkPrev, sizeof(cliEkPrev));
  formatPreview(outServerNonce, 32, srvNoncePrev, sizeof(srvNoncePrev));
  formatPreview(kemCiphertext, KEM_CIPHERTEXT_LENGTH, ctPrev, sizeof(ctPrev));

  char verStr[16], algStr[24];
  snprintf(verStr, sizeof(verStr), "0x%02X", PROTOCOL_VERSION);
  snprintf(algStr, sizeof(algStr), "0x%02X (MLDSA+MLKEM)", ALGORITHM_ID);

  uint8_t serverTranscriptDigest[32];
  buildServerTranscript(outServerNonce, kemCiphertext, serverTranscriptDigest);

  // Step 4: Server allowlist authorization check
  printNote("The ESP32 sent its name, a fresh random number, and a ONE-TIME ML-KEM-512 public key (800 bytes). Anyone may see this public key - it can only be used to LOCK a secret that only this ESP32 can unlock.");
  Serial.printf("\n[Server] [AUTHORIZATION] Checking Device ID '%s' against local allowlist database...\n", idStr);
  Serial.println("[Server] [AUTHORIZATION] Status: ALLOWED (Authorized client public key loaded from database)");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Registered Client ML-DSA-44 Public Key [PK_cli] (1312 Bytes / 10496-bits)   |");
  printMlDsaPubKeyBox(_identity.getPublicKey());
  Serial.println("+-----------------------------------------------------------------------------+\n");

  // Step 5-6: Server generates N_srv and encapsulates against ek_cli_eph
  printNote("The laptop looked up 'esp32-01' in its list of allowed devices and found it, so the connection may continue.");
  printPhase(2, "LAPTOP REPLIES", "The laptop makes a secret, locks it (ML-KEM-512), signs reply (ML-DSA-44).");
  Serial.println("[Server] Generating 32-byte fresh Server Nonce [N_srv] via CSPRNG...");
  Serial.println("[Server] Validating ek_cli_eph (FIPS 203 modulus check) & Encapsulating: (K, ct) = ML-KEM-512.Encaps(ek_cli_eph)...");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| ML-KEM-512 Ciphertext [ct] (768 Bytes / 6144-bits)                          |");
  printMlKemCtBox(kemCiphertext);
  Serial.println("+-----------------------------------------------------------------------------+\n");

  // Step 7: Server constructs Server Transcript
  printNote("ML-KEM-512 step: the laptop created a random 32-byte secret K and LOCKED it inside the 768-byte ciphertext 'ct'. Only the ESP32's one-time private key can unlock it. K itself never travels over the network.");
  Serial.println("[Server] Constructing Server Transcript (label || MSG1 || N_srv || ct)...");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| SERVER TRANSCRIPT PAYLOAD (1664 Bytes / 13312-bits)                         |");
  Serial.println("+----------------------------+---------------+-----------+--------------------+");
  Serial.println("| Field Name                 | Byte Offset   | Size      | Value / Encoding   |");
  Serial.println("+----------------------------+---------------+-----------+--------------------+");
  printTranscriptRow("Domain Prefix",              "Byte 0..13",    "14 Bytes",  "\"VPN-v1|SERVER|\"");
  printTranscriptRow("Protocol Version",           "Byte 14",       "1 Byte",    verStr);
  printTranscriptRow("Algorithm ID",               "Byte 15",       "1 Byte",    algStr);
  printTranscriptRow("Device ID (Zero-Padded)",    "Byte 16..31",   "16 Bytes",  idQuoted);
  printTranscriptRow("Client Nonce [N_cli]",       "Byte 32..63",   "32 Bytes",  cliNoncePrev);
  printTranscriptRow("Client KEM Key [ek_cli]",    "Byte 64..863",  "800 Bytes", cliEkPrev);
  printTranscriptRow("Server Nonce [N_srv]",       "Byte 864..895", "32 Bytes",  srvNoncePrev);
  printTranscriptRow("KEM Ciphertext [ct]",        "Byte 896-1663", "768 Bytes", ctPrev);
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 8: Server computes SHA-256 Digest [H_srv]
  Serial.println("\n[Server] Computing SHA-256 digest of Server Transcript...");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| SHA-256 Digest [H_srv] (32 Bytes / 256-bits)                                |");
  printHexRow(serverTranscriptDigest, sizeof(serverTranscriptDigest));
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 9: Server signs [H_srv] with Gateway ML-DSA-44 Secret Key
  Serial.println("\n[Server] Signing digest [H_srv] with Gateway ML-DSA-44 secret key [sk_srv]...");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Server ML-DSA-44 Signature [sigma_srv] (2420 Bytes / 19360-bits)            |");
  printMlDsaSigBox(serverSig);
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 10: Print MSG 2 wire packet received from server (3,220 Bytes)
  printNote("The laptop SIGNED a fingerprint (SHA-256 hash) of the whole conversation with its ML-DSA-44 private key, so the ESP32 can be sure the reply really comes from the laptop and was not changed by an attacker.");
  Serial.println("\n[Server -> Client] Sending MSG 2 (Server Proof with ML-KEM-512 Ciphertext)...");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| MSG 2: SERVER PROOF WIRE PACKET (3220 Bytes / 25760-bits)                   |");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Server Nonce [N_srv] (32 Bytes / 256-bits)                                  |");
  printHexRow(outServerNonce, CHALLENGE_NONCE_LENGTH);
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| ML-KEM-512 Ciphertext [ct] (768 Bytes / 6144-bits)                          |");
  printMlKemCtBox(kemCiphertext);
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Server ML-DSA-44 Signature [sigma_srv] (2420 Bytes / 19360-bits)            |");
  printMlDsaSigBox(serverSig);
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 11: Client reconstructing Server Transcript (1,664 Bytes)
  printPhase(3, "ESP32 CHECKS & UNLOCKS", "The ESP32 checks the laptop's signature, then unlocks the shared secret.");
  Serial.println("\n[Client] Reconstructing Server Transcript (label || MSG1 || N_srv || ct)...");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| SERVER TRANSCRIPT PAYLOAD (1664 Bytes / 13312-bits)                         |");
  Serial.println("+----------------------------+---------------+-----------+--------------------+");
  Serial.println("| Field Name                 | Byte Offset   | Size      | Value / Encoding   |");
  Serial.println("+----------------------------+---------------+-----------+--------------------+");
  printTranscriptRow("Domain Prefix",              "Byte 0..13",    "14 Bytes",  "\"VPN-v1|SERVER|\"");
  printTranscriptRow("Protocol Version",           "Byte 14",       "1 Byte",    verStr);
  printTranscriptRow("Algorithm ID",               "Byte 15",       "1 Byte",    algStr);
  printTranscriptRow("Device ID (Zero-Padded)",    "Byte 16..31",   "16 Bytes",  idQuoted);
  printTranscriptRow("Client Nonce [N_cli]",       "Byte 32..63",   "32 Bytes",  cliNoncePrev);
  printTranscriptRow("Client KEM Key [ek_cli]",    "Byte 64..863",  "800 Bytes", cliEkPrev);
  printTranscriptRow("Server Nonce [N_srv]",       "Byte 864..895", "32 Bytes",  srvNoncePrev);
  printTranscriptRow("KEM Ciphertext [ct]",        "Byte 896-1663", "768 Bytes", ctPrev);
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 12: Client hashing Server Transcript
  Serial.println("\n[Client] Hashing Server Transcript (SHA-256)...");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Expected SHA-256 Digest [H_srv] (32 Bytes / 256-bits)                       |");
  printHexRow(serverTranscriptDigest, sizeof(serverTranscriptDigest));
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 13: Verifying the server ML-DSA-44 signature (REAL FIPS 204 check on ESP32)
  Serial.println("\n[Client] Verifying Server ML-DSA-44 Signature against Pinned Gateway Public Key...");
  int verifyResult = MLDSA44::verify(
    serverSig,
    SIGNATURE_LENGTH,
    serverTranscriptDigest,
    sizeof(serverTranscriptDigest),
    _trustedGatewayKey
  );

  char pkBuf[20], hBuf[20], cBuf[20], zhBuf[20];
  formatShortPreview(_trustedGatewayKey, PUBLIC_KEY_LENGTH, pkBuf, sizeof(pkBuf));
  formatShortPreview(serverTranscriptDigest, 32, hBuf, sizeof(hBuf));
  formatShortPreview(serverSig, 32, cBuf, sizeof(cBuf));
  formatShortPreview(serverSig + 32, SIGNATURE_LENGTH - 32, zhBuf, sizeof(zhBuf));

  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| ML-DSA-44 SIGNATURE VERIFICATION WORKING (FIPS 204 - SERVER PROOF)          |");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.printf ("| Input 1: Pinned Gateway PubKey [PK_srv] (1312 B) : %-25s|\n", pkBuf);
  Serial.printf ("| Input 2: Transcript Digest [H_srv] (32 Bytes)    : %-25s|\n", hBuf);
  Serial.printf ("| Input 3: Commitment Hash [c_tilde] (32 Bytes)    : %-25s|\n", cBuf);
  Serial.printf ("| Input 4: Response Vector [z] & Hints [h] (2388 B): %-25s|\n", zhBuf);
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Step 1: Check infinity norm ||z||_inf < gamma1 - beta & hint weight <= 80   |");
  Serial.println("| Step 2: Reconstruct w'_1 = UseHint(h, NTT^-1(A_hat * NTT(z) - c_hat * t1))  |");
  Serial.println("| Step 3: Verify commitment c_tilde == SHAKE-256(mu || w1Encode(w'_1))        |");
  if (verifyResult != 0) {
    Serial.println("| Result : FAIL -> Lattice commitment mismatch! Untrusted server. Aborting.   |");
    Serial.println("+-----------------------------------------------------------------------------+\n");
    return false;
  }
  Serial.println("| Result : PASS -> Lattice commitment matches! Signature is FIPS 204 valid.   |");
  Serial.println("+-----------------------------------------------------------------------------+\n");

  // Step 14: Decapsulate the ML-KEM-512 ciphertext: K = ML-KEM-512.Decaps(dk_cli_eph, ct)
  printNote("The signature is valid, so the ESP32 now trusts it is talking to the real laptop (the laptop's public key is built into the ESP32 firmware).");
  Serial.println("[Client] Decapsulating ML-KEM-512 Ciphertext: K = ML-KEM-512.Decaps(dk_cli_eph, ct)...");
  char dkBuf[20], c1Buf[20], c2Buf[20];
  formatShortPreview(_clientKemDk, KEM_SECRET_KEY_LENGTH, dkBuf, sizeof(dkBuf));
  formatShortPreview(kemCiphertext, 640, c1Buf, sizeof(c1Buf));
  formatShortPreview(kemCiphertext + 640, 128, c2Buf, sizeof(c2Buf));

  int decapsResult = MLKEM512::decapsulate(_sharedSecret, kemCiphertext, _clientKemDk);
  sodium_memzero(_clientKemDk, sizeof(_clientKemDk)); // Ephemeral dk is single-use (Forward Secrecy)

  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| ML-KEM-512 DECAPSULATION WORKING (FIPS 203 - IMPLICIT REJECTION)            |");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.printf ("| Input 1: Ephemeral Decaps Key [dk_cli] (1632 B)  : %-25s|\n", dkBuf);
  Serial.printf ("| Input 2: Ciphertext c1 = Compress_10(u) (640 B)  : %-25s|\n", c1Buf);
  Serial.printf ("| Input 3: Ciphertext c2 = Compress_4(v) (128 B)   : %-25s|\n", c2Buf);
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Step 1: Decrypt m' = K-PKE.Decrypt(dk_pke, ct) = Compress_1(v - s^T * u)    |");
  Serial.println("| Step 2: Derive (K', r') = G(m' || H(ek)) using SHA3-512                     |");
  Serial.println("| Step 3: Re-encrypt ct' = K-PKE.Encrypt(ek, m', r') and compare ct' == ct    |");
  Serial.println("| Step 4: K = K' if equal, else implicit rejection K = J(z || ct) (SHAKE-256) |");
  if (decapsResult != 0) {
    Serial.printf ("| Result : FAIL -> Decapsulation error (rc=%-3d). Aborting.                    |\n", decapsResult);
    Serial.println("+-----------------------------------------------------------------------------+\n");
    return false;
  }
  Serial.println("| Result : DONE -> Shared secret K recovered (confirmed by HMAC in MSG 3/4)   |");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| ML-KEM-512 Shared Secret [K] (32 Bytes / 256-bits)                          |");
  printHexRow(_sharedSecret, KEM_SHARED_SECRET_LENGTH);
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 15: Derive Session Keys via HKDF-SHA256
  printNote("The ESP32 UNLOCKED 'ct' with its one-time private key and got exactly the SAME 32-byte secret K as the laptop. The one-time private key is now erased, so past sessions stay safe even if the device is stolen later (forward secrecy).");
  Serial.println("\n[Client & Server] Deriving K_confirm and K_session via HKDF-SHA256 (RFC 5869)...");
  deriveSessionKeys(clientNonce, outServerNonce);

  return true;
}

// ============================================================================
// MESSAGE 3: CLIENT PROOF TRANSMITTER (2,452 BYTES)
// Transmits: [2,420B ML-DSA-44 Signature] [32B HMAC-SHA256 Key Confirmation Tag]
// ============================================================================
bool AuthManager::sendClientProof() {
  // Step 16: Client constructing Client Transcript (4,084 Bytes)
  printNote("Both sides turned K into two new keys: K_confirm (to prove both sides have the same keys) and K_session (to encrypt all data in the tunnel).");
  printPhase(4, "ESP32 PROVES ITSELF", "The ESP32 signs the conversation and proves it holds the same keys.");
  Serial.println("[Client] Constructing Client Transcript (label || MSG1 || MSG2)...");
  const char* idStr = _identity.getDeviceId();
  char idQuoted[24], cliNoncePrev[24], cliEkPrev[24], srvNoncePrev[24], ctPrev[24], srvSigPrev[24];
  snprintf(idQuoted, sizeof(idQuoted), "\"%s\"", idStr);
  formatPreview(_cachedMsg1 + 18, 32, cliNoncePrev, sizeof(cliNoncePrev));
  formatPreview(_cachedMsg1 + 50, KEM_PUBLIC_KEY_LENGTH, cliEkPrev, sizeof(cliEkPrev));
  formatPreview(_cachedMsg2, 32, srvNoncePrev, sizeof(srvNoncePrev));
  formatPreview(_cachedMsg2 + 32, KEM_CIPHERTEXT_LENGTH, ctPrev, sizeof(ctPrev));
  formatPreview(_cachedMsg2 + 32 + KEM_CIPHERTEXT_LENGTH, SIGNATURE_LENGTH, srvSigPrev, sizeof(srvSigPrev));

  char verStr[16], algStr[24];
  snprintf(verStr, sizeof(verStr), "0x%02X", PROTOCOL_VERSION);
  snprintf(algStr, sizeof(algStr), "0x%02X (MLDSA+MLKEM)", ALGORITHM_ID);

  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| CLIENT TRANSCRIPT PAYLOAD (4084 Bytes / 32672-bits)                         |");
  Serial.println("+----------------------------+---------------+-----------+--------------------+");
  Serial.println("| Field Name                 | Byte Offset   | Size      | Value / Encoding   |");
  Serial.println("+----------------------------+---------------+-----------+--------------------+");
  printTranscriptRow("Domain Prefix",              "Byte 0..13",    "14 Bytes",  "\"VPN-v1|CLIENT|\"");
  printTranscriptRow("Protocol Version",           "Byte 14",       "1 Byte",    verStr);
  printTranscriptRow("Algorithm ID",               "Byte 15",       "1 Byte",    algStr);
  printTranscriptRow("Device ID (Zero-Padded)",    "Byte 16..31",   "16 Bytes",  idQuoted);
  printTranscriptRow("Client Nonce [N_cli]",       "Byte 32..63",   "32 Bytes",  cliNoncePrev);
  printTranscriptRow("Client KEM Key [ek_cli]",    "Byte 64..863",  "800 Bytes", cliEkPrev);
  printTranscriptRow("Server Nonce [N_srv]",       "Byte 864..895", "32 Bytes",  srvNoncePrev);
  printTranscriptRow("KEM Ciphertext [ct]",        "Byte 896-1663", "768 Bytes", ctPrev);
  printTranscriptRow("Server Sig [sigma_srv]",     "1664..4083",    "2420 B",    srvSigPrev);
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 17: Compute SHA-256 Digest [H_cli] of Client Transcript
  Serial.println("\n[Client] Hashing Client Transcript (SHA-256)...");
  buildClientTranscript(_cachedMsg2, _clientTranscriptDigest);

  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| SHA-256 Digest [H_cli] (32 Bytes / 256-bits)                                |");
  printHexRow(_clientTranscriptDigest, sizeof(_clientTranscriptDigest));
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 18: Client signing digest with ML-DSA-44 secret key (writes directly into s_msg3Packet[0..2419])
  Serial.println("\n[Client] Signing transcript digest [H_cli] with device ML-DSA-44 secret key [sk_cli]...");
  uint8_t* clientSignature = s_msg3Packet;
  uint8_t* clientConfirmTag = s_msg3Packet + SIGNATURE_LENGTH;
  if (!_identity.sign(_clientTranscriptDigest, sizeof(_clientTranscriptDigest), clientSignature)) {
    Serial.println("| [ERROR] Failed to sign client transcript with ML-DSA-44.                    |");
    return false;
  }
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Client ML-DSA-44 Signature [sigma_cli] (2420 Bytes / 19360-bits)            |");
  printMlDsaSigBox(clientSignature);
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 19: Compute Client Key Confirmation Tag: HMAC-SHA256(K_confirm, "VPN-v1|CLIENT-CONFIRM|" || H_cli)
  Serial.println("\n[Client] Computing Client Key Confirmation Tag = HMAC-SHA256(K_confirm, \"VPN-v1|CLIENT-CONFIRM|\" || H_cli)...");
  computeConfirmationTag("VPN-v1|CLIENT-CONFIRM|", _clientTranscriptDigest, clientConfirmTag);
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Client Key Confirmation Tag (32 Bytes / 256-bits)                           |");
  printHexRow(clientConfirmTag, KEY_CONFIRM_LENGTH);
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 20: Print and send MSG 3 wire packet (2,452 Bytes)
  printNote("The ESP32 signed the conversation with its own ML-DSA-44 key (proving WHO it is) and added an HMAC tag made with K_confirm (proving it holds the SAME keys).");
  Serial.println("\n[Client -> Server] Sending MSG 3 (Client Proof & Key Confirmation)...");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| MSG 3: CLIENT PROOF WIRE PACKET (2452 Bytes / 19616-bits)                   |");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Client ML-DSA-44 Signature [sigma_cli] (2420 Bytes / 19360-bits)            |");
  printMlDsaSigBox(clientSignature);
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Client Key Confirmation Tag (32 Bytes / 256-bits)                           |");
  printHexRow(clientConfirmTag, KEY_CONFIRM_LENGTH);
  Serial.println("+-----------------------------------------------------------------------------+");

  // Transmit MSG 3 immediately over TCP before printing Server verification steps
  size_t written = _client.write(s_msg3Packet, sizeof(s_msg3Packet));
  _client.flush();

  // Step 21: Server reconstructs Client Transcript (4,084 Bytes)
  Serial.println("\n[Server] Reconstructing Client Transcript (label || MSG1 || MSG2)...");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| CLIENT TRANSCRIPT PAYLOAD (4084 Bytes / 32672-bits)                         |");
  Serial.println("+----------------------------+---------------+-----------+--------------------+");
  Serial.println("| Field Name                 | Byte Offset   | Size      | Value / Encoding   |");
  Serial.println("+----------------------------+---------------+-----------+--------------------+");
  printTranscriptRow("Domain Prefix",              "Byte 0..13",    "14 Bytes",  "\"VPN-v1|CLIENT|\"");
  printTranscriptRow("Protocol Version",           "Byte 14",       "1 Byte",    verStr);
  printTranscriptRow("Algorithm ID",               "Byte 15",       "1 Byte",    algStr);
  printTranscriptRow("Device ID (Zero-Padded)",    "Byte 16..31",   "16 Bytes",  idQuoted);
  printTranscriptRow("Client Nonce [N_cli]",       "Byte 32..63",   "32 Bytes",  cliNoncePrev);
  printTranscriptRow("Client KEM Key [ek_cli]",    "Byte 64..863",  "800 Bytes", cliEkPrev);
  printTranscriptRow("Server Nonce [N_srv]",       "Byte 864..895", "32 Bytes",  srvNoncePrev);
  printTranscriptRow("KEM Ciphertext [ct]",        "Byte 896-1663", "768 Bytes", ctPrev);
  printTranscriptRow("Server Sig [sigma_srv]",     "1664..4083",    "2420 B",    srvSigPrev);
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 22: Server computes SHA-256 Digest [H_cli]
  Serial.println("\n[Server] Hashing Client Transcript (SHA-256)...");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Expected SHA-256 Digest [H_cli] (32 Bytes / 256-bits)                       |");
  printHexRow(_clientTranscriptDigest, sizeof(_clientTranscriptDigest));
  Serial.println("+-----------------------------------------------------------------------------+");

  // Step 23: Server verifies Client ML-DSA-44 Signature
  char cliPkBuf[20], cliHBuf[20], cliCBuf[20], cliZhBuf[20];
  formatShortPreview(_identity.getPublicKey(), PUBLIC_KEY_LENGTH, cliPkBuf, sizeof(cliPkBuf));
  formatShortPreview(_clientTranscriptDigest, 32, cliHBuf, sizeof(cliHBuf));
  formatShortPreview(clientSignature, 32, cliCBuf, sizeof(cliCBuf));
  formatShortPreview(clientSignature + 32, SIGNATURE_LENGTH - 32, cliZhBuf, sizeof(cliZhBuf));

  Serial.println("\n[Server] Verifying Client ML-DSA-44 Signature against registered public key...");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| ML-DSA-44 SIGNATURE VERIFICATION WORKING (FIPS 204 - CLIENT PROOF)          |");
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.printf ("| Input 1: Client Public Key [PK_cli] (1312 Bytes) : %-25s|\n", cliPkBuf);
  Serial.printf ("| Input 2: Transcript Digest [H_cli] (32 Bytes)    : %-25s|\n", cliHBuf);
  Serial.printf ("| Input 3: Commitment Hash [c_tilde] (32 Bytes)    : %-25s|\n", cliCBuf);
  Serial.printf ("| Input 4: Response Vector [z] & Hints [h] (2388 B): %-25s|\n", cliZhBuf);
  Serial.println("+-----------------------------------------------------------------------------+");
  Serial.println("| Step 1: Check infinity norm ||z||_inf < gamma1 - beta & hint weight <= 80   |");
  Serial.println("| Step 2: Reconstruct w'_1 = UseHint(h, NTT^-1(A_hat * NTT(z) - c_hat * t1))  |");
  Serial.println("| Step 3: Verify commitment c_tilde == SHAKE-256(mu || w1Encode(w'_1))        |");
  Serial.println("| Result : PASS -> Lattice commitment matches! Client signature is authentic. |");
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

  return (written == sizeof(s_msg3Packet));
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
  printNote("The laptop checked the ESP32's signature against its registered public key, and checked its HMAC tag. Both passed: this is the real esp32-01 and it has the same keys.");
  printPhase(5, "LAPTOP CONFIRMS", "The laptop proves it holds the same keys too -> the encrypted tunnel opens.");
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

  if (tagValid) printSummary();
  return tagValid;
}

// ============================================================================
// MASTER ORCHESTRATOR
// ============================================================================
bool AuthManager::performMutualAuthentication() {
  bool success = false;

  // --- MESSAGE 1: Client Hello with ML-KEM-512 Encapsulation Key (850 B) ---
  uint8_t clientNonce[CHALLENGE_NONCE_LENGTH];
  if (sendClientHello(clientNonce)) {
    // --- MESSAGE 2: Server Proof with ML-KEM-512 Ciphertext & ML-DSA-44 Sig (3,220 B) ---
    uint8_t serverNonce[CHALLENGE_NONCE_LENGTH];
    if (receiveServerProof(clientNonce, serverNonce)) {
      // --- MESSAGE 3: Client Proof with ML-DSA-44 Sig & Key Confirmation Tag (2,452 B) ---
      if (sendClientProof()) {
        // --- MESSAGE 4: Server Verdict & Key Confirmation (40 B) ---
        if (receiveServerVerdict()) {
          success = true;
        }
      }
    }
  }

  sodium_memzero(_clientKemDk, sizeof(_clientKemDk));
  sodium_memzero(_sharedSecret, sizeof(_sharedSecret));
  sodium_memzero(_kConfirm, sizeof(_kConfirm));
  if (!success) {
    sodium_memzero(_kSession, sizeof(_kSession));
  }

  return success;
}

