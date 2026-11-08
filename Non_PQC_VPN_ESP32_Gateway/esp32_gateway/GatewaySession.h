#ifndef GATEWAY_SESSION_H
#define GATEWAY_SESSION_H

#include <Arduino.h>
#include "gateway_config.h"
#include "Log.h"

class VpnGateway;

// ============================================================================
// CLASS: GatewaySession
// One connected ESP32 client = one GatewaySession running in its OWN FreeRTOS task
// (same idea as laptop_server/tunnel_session.py running in its own Python thread).
//   MSG 1: Client Hello (82B)   <- [Ver | Alg | ID | Nonce | X25519_pk]
//   MSG 2: Server Proof (128B)  -> [Nonce | X25519_pk | Ed25519_sig]
//   MSG 3: Client Proof (96B)   <- [Ed25519_sig | Client_Confirm_Tag]
//   MSG 4: Server Verdict (40B) -> ["AUTH_OK\n" | Server_Confirm_Tag]  or "AUTH_NO\n"
// then the line-framed data tunnel.
// Any failure ends ONLY this task and closes ONLY this client's socket.
// ============================================================================
class GatewaySession {
public:
  GatewaySession(int sock, uint32_t ipAddr, const char* ipStr, uint16_t port, VpnGateway& gateway);
  ~GatewaySession();

  static void taskEntry(void* arg);       // FreeRTOS task function: runs and then deletes the session
  void terminate(const char* reason);     // Called from ANOTHER task (registry / Serial command)
  const char* peerLabel() const { return _peer; }

private:
  int           _sock;
  uint32_t      _ipAddr;                  // Client IP (network byte order), for the per-IP limit
  char          _peer[24];                // "192.168.4.2:51234"
  VpnGateway&   _gateway;
  bool          _handshakeSlotHeld;

  volatile bool        _terminated;
  const char* volatile _terminateReason;

  char           _deviceId[DEVICE_ID_LENGTH + 1];
  const uint8_t* _clientPublicKey;        // Registered key from the allowlist (points into flash)
  unsigned long  _deadline;               // millis() deadline for the whole handshake

  uint8_t _msg1[MSG1_CLIENT_HELLO_SIZE];
  uint8_t _msg2[MSG2_SERVER_PROOF_SIZE];
  uint8_t _clientTranscriptDigest[32];
  uint8_t _kConfirm[32];
  uint8_t _kSession[32];

  SessionLog _log;                        // Handshake log, printed as one block

  void run();
  bool performHandshake();
  bool receiveClientHello();
  bool sendServerProof();
  bool verifyClientProof();
  void sendVerdict(bool accepted);
  void runTunnel();
  void handleTunnelLine(const char* line, size_t len);

  bool recvExact(uint8_t* buffer, size_t count);   // Honors the handshake deadline
  bool sendAll(const void* data, size_t len);
  void setRecvTimeout(unsigned long ms);
  void releaseHandshakeSlot();
};

#endif // GATEWAY_SESSION_H
