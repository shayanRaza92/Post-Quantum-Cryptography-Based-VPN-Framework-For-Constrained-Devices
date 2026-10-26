#ifndef AUTH_MANAGER_H
#define AUTH_MANAGER_H

#include <Arduino.h>
#include <WiFiClient.h>         // Network client socket library
#include "DeviceIdentity.h"     // DeviceIdentity class definition

// ============================================================================
// CLASS: AuthManager (Option A: 4-Way Mutual Authentication)
// Purpose: Implements the clean 4-message mutual authentication handshake:
//          MSG 1: Client Hello (50B) -> Server
//          MSG 2: Server Proof (96B) <- Server (Server authenticates first!)
//          MSG 3: Client Proof (64B) -> Server (Binds Server Signature)
//          MSG 4: Server Verdict (8B) <- Server (AUTH_OK)
// ============================================================================
class AuthManager {
private:
  WiFiClient&           _client;              // Active TCP socket connected to gateway
  const DeviceIdentity& _identity;            // Local device identity (NVS keys and signing)
  const uint8_t*        _trustedGatewayKey;   // 32-byte pinned gateway public key

  // Cached wire packets for running transcript hashing (TLS 1.3 style)
  uint8_t _cachedMsg1[50]; // 50B MSG 1 wire packet
  uint8_t _cachedMsg2[96]; // 96B MSG 2 wire packet

  // --------------------------------------------------------------------------
  // LOW-LEVEL STREAM UTILITY MODULE
  // --------------------------------------------------------------------------
  bool readExact(uint8_t* buffer, size_t count, unsigned long timeoutMs = 7000);

  // --------------------------------------------------------------------------
  // TRANSCRIPT BUILDER MODULES (Running Transcript Hash)
  // --------------------------------------------------------------------------
  // Server Transcript: SHA-256( "VPN-v1|SERVER|" (14B) || MSG1 (50B) || ServerNonce (32B) ) -> 96B input
  void buildServerTranscript(const uint8_t* serverNonce, uint8_t* outDigest);

  // Client Transcript: SHA-256( "VPN-v1|CLIENT|" (14B) || MSG1 (50B) || MSG2 (96B) ) -> 160B input
  void buildClientTranscript(const uint8_t* msg2, uint8_t* outDigest);

  // --------------------------------------------------------------------------
  // PROTOCOL HANDSHAKE STAGE MODULES
  // --------------------------------------------------------------------------
  // Message 1: Transmits 50B Client Hello [Ver (1B) | Alg (1B) | ID (16B) | Nonce (32B)]
  bool sendClientHello(uint8_t* outClientNonce);

  // Message 2: Receives 96B Server Proof [Nonce (32B) | Sig (64B)] and verifies against pinned key
  bool receiveServerProof(const uint8_t* clientNonce, uint8_t* outServerNonce, uint8_t* outServerSig);

  // Message 3: Signs Client Transcript (label || MSG1 || MSG2) and transmits 64B signature
  bool sendClientProof(const uint8_t* clientNonce, const uint8_t* serverNonce, const uint8_t* serverSig);

  // Message 4: Receives 8B server verdict ("AUTH_OK\n" or "AUTH_NO\n")
  bool receiveServerVerdict();

public:
  // Constructor: Injects network client, device identity, and pinned gateway public key
  AuthManager(WiFiClient& client, const DeviceIdentity& identity, const uint8_t* trustedGatewayKey);

  // Master Orchestrator: Coordinates the 4-message handshake in sequence
  bool performMutualAuthentication();
};

#endif // AUTH_MANAGER_H
