#ifndef AUTH_MANAGER_H
#define AUTH_MANAGER_H

#include <Arduino.h>
#include <WiFiClient.h>         // Network client socket library
#include "DeviceIdentity.h"     // DeviceIdentity class definition (ML-DSA-44)
#include "config.h"

// ============================================================================
// CLASS: AuthManager
// Implements 4-message mutual authentication with NIST FIPS 204 ML-DSA-44,
// Ephemeral NIST FIPS 203 ML-KEM-512 Key Encapsulation, and bidirectional
// HMAC-SHA256 Key Confirmation (fully post-quantum handshake):
//   MSG 1: Client Hello (850B)   -> Server [Ver | Alg | ID | Nonce | MLKEM512_ek (800B)]
//   MSG 2: Server Proof (3220B)  <- Server [Nonce | MLKEM512_ct (768B) | MLDSA44_sig (2420B)]
//   MSG 3: Client Proof (2452B)  -> Server [MLDSA44_sig (2420B) | Client_Confirm_Tag (32B)]
//   MSG 4: Server Verdict (40B)  <- Server ["AUTH_OK\n" | Server_Confirm_Tag (32B)]
// ============================================================================
class AuthManager {
private:
  WiFiClient&           _client;              // Active TCP socket connected to gateway
  const DeviceIdentity& _identity;            // Local device identity (ML-DSA-44 keys and signing)
  const uint8_t*        _trustedGatewayKey;   // 1,312-byte pinned gateway ML-DSA-44 public key

  // Ephemeral ML-KEM-512 keys and derived session secrets
  uint8_t _clientKemDk[KEM_SECRET_KEY_LENGTH];     // 1,632B fresh ML-KEM-512 decapsulation key (ephemeral)
  uint8_t _clientKemEk[KEM_PUBLIC_KEY_LENGTH];     // 800B fresh ML-KEM-512 encapsulation key (ephemeral)
  uint8_t _sharedSecret[KEM_SHARED_SECRET_LENGTH]; // 32-byte ML-KEM shared secret
  uint8_t _kConfirm[32];      // Derived key confirmation key
  uint8_t _kSession[32];      // Derived master session key (for tunnel encryption)

  // Cached wire packets for running transcript hashing (stored in .bss via global AuthManager instance)
  uint8_t _cachedMsg1[MSG1_CLIENT_HELLO_SIZE]; // 850B MSG 1 wire packet
  uint8_t _cachedMsg2[MSG2_SERVER_PROOF_SIZE]; // 3,220B MSG 2 wire packet
  uint8_t _clientTranscriptDigest[32];         // 32B Client transcript digest

  // --------------------------------------------------------------------------
  // LOW-LEVEL STREAM UTILITY
  // --------------------------------------------------------------------------
  bool readExact(uint8_t* buffer, size_t count, unsigned long timeoutMs = 10000);

  // --------------------------------------------------------------------------
  // TRANSCRIPT AND KEY DERIVATION MODULES
  // --------------------------------------------------------------------------
  // Server Transcript: SHA-256("VPN-v1|SERVER|" || MSG1 (850B) || ServerNonce (32B) || KEM_ct (768B)) -> 1664B
  void buildServerTranscript(const uint8_t* serverNonce, const uint8_t* kemCiphertext, uint8_t* outDigest);

  // Client Transcript: SHA-256("VPN-v1|CLIENT|" || MSG1 (850B) || MSG2 (3220B)) -> 4084B
  void buildClientTranscript(const uint8_t* msg2, uint8_t* outDigest);

  // Derives K_confirm and K_session via HKDF-SHA256 from shared secret and handshake nonces
  bool deriveSessionKeys(const uint8_t* clientNonce, const uint8_t* serverNonce);

  // Computes HMAC-SHA256 key confirmation tag over role label and transcript digest
  void computeConfirmationTag(const char* roleLabel, const uint8_t* transcriptDigest, uint8_t* outTag);

  // --------------------------------------------------------------------------
  // PROTOCOL HANDSHAKE STAGES
  // --------------------------------------------------------------------------
  bool sendClientHello(uint8_t* outClientNonce);
  bool receiveServerProof(const uint8_t* clientNonce, uint8_t* outServerNonce);
  bool sendClientProof();
  bool receiveServerVerdict();

public:
  AuthManager(WiFiClient& client, const DeviceIdentity& identity, const uint8_t* trustedGatewayKey);

  // Runs full post-quantum mutual authentication and key encapsulation handshake
  bool performMutualAuthentication();

  // Getter for derived 32-byte session master key
  const uint8_t* getSessionKey() const { return _kSession; }
};

#endif // AUTH_MANAGER_H

