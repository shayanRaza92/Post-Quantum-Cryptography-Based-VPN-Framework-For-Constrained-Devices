#ifndef AUTH_MANAGER_H
#define AUTH_MANAGER_H

#include <Arduino.h>
#include <WiFiClient.h>         // Network client socket library
#include "DeviceIdentity.h"     // DeviceIdentity class definition
#include "config.h"

// ============================================================================
// CLASS: AuthManager
// Implements 4-message mutual authentication with Ephemeral X25519 Key Exchange
// and bidirectional HMAC-SHA256 Key Confirmation:
//   MSG 1: Client Hello (82B)  -> Server [Ver | Alg | ID | Nonce | X25519_pk]
//   MSG 2: Server Proof (128B) <- Server [Nonce | X25519_pk | Ed25519_sig]
//   MSG 3: Client Proof (96B)  -> Server [Ed25519_sig | Client_Confirm_Tag]
//   MSG 4: Server Verdict (40B)<- Server ["AUTH_OK\n" | Server_Confirm_Tag]
// ============================================================================
class AuthManager {
private:
  WiFiClient&           _client;              // Active TCP socket connected to gateway
  const DeviceIdentity& _identity;            // Local device identity (Ed25519 keys and signing)
  const uint8_t*        _trustedGatewayKey;   // 32-byte pinned gateway public key

  // Ephemeral cryptographic keys and derived session secrets
  uint8_t _clientEphSk[32];   // Fresh X25519 private key (ephemeral)
  uint8_t _clientEphPk[32];   // Fresh X25519 public key share (ephemeral)
  uint8_t _serverEphPk[32];   // Gateway X25519 public key share received in MSG 2
  uint8_t _sharedSecret[32];  // 32-byte Diffie-Hellman shared secret
  uint8_t _kConfirm[32];      // Derived key confirmation key
  uint8_t _kSession[32];      // Derived master session key (for tunnel encryption)

  // Cached wire packets for running transcript hashing
  uint8_t _cachedMsg1[MSG1_CLIENT_HELLO_SIZE]; // 82B MSG 1 wire packet
  uint8_t _cachedMsg2[MSG2_SERVER_PROOF_SIZE]; // 128B MSG 2 wire packet
  uint8_t _clientTranscriptDigest[32];         // 32B Client transcript digest

  // --------------------------------------------------------------------------
  // LOW-LEVEL STREAM UTILITY
  // --------------------------------------------------------------------------
  bool readExact(uint8_t* buffer, size_t count, unsigned long timeoutMs = 7000);

  // --------------------------------------------------------------------------
  // TRANSCRIPT AND KEY DERIVATION MODULES
  // --------------------------------------------------------------------------
  // Server Transcript: SHA-256("VPN-v1|SERVER|" || MSG1 (82B) || ServerNonce (32B) || ServerEphPk (32B))
  void buildServerTranscript(const uint8_t* serverNonce, const uint8_t* serverEphPk, uint8_t* outDigest);

  // Client Transcript: SHA-256("VPN-v1|CLIENT|" || MSG1 (82B) || MSG2 (128B))
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

  // Runs full mutual authentication and key exchange handshake
  bool performMutualAuthentication();

  // Getter for derived 32-byte session master key
  const uint8_t* getSessionKey() const { return _kSession; }
};

#endif // AUTH_MANAGER_H
