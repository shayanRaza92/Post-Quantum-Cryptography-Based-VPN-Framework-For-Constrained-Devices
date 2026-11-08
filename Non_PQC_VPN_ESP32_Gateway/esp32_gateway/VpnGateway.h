#ifndef VPN_GATEWAY_H
#define VPN_GATEWAY_H

#include <Arduino.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include "gateway_config.h"
#include "GatewayCrypto.h"
#include "Allowlist.h"
#include "SessionRegistry.h"

// ============================================================================
// CLASS: VpnGateway
// Same job as laptop_server/server.py:
//   * Listens on TCP port 9000 and accepts ESP32 clients in a dedicated task.
//   * Gives every client its own GatewaySession task.
//   * Enforces DoS limits: total sessions, concurrent handshakes, handshakes per IP.
//   * A failure while accepting/dispatching one client never stops the accept loop.
//   * Serial Monitor commands: help, status, list, sessions, revoke/allow/kick <id>.
// ============================================================================
class VpnGateway {
public:
  bool begin(uint16_t port);                   // Loads keys + allowlist, starts the accept task
  void handleCommand(String line);             // One Serial Monitor command line

  GatewayCrypto&   crypto()    { return _crypto; }
  Allowlist&       allowlist() { return _allowlist; }
  SessionRegistry& registry()  { return _registry; }

  void releaseHandshake(uint32_t ipAddr);      // Called by a session when its handshake ends
  void releaseSession();                       // Called by a session after closing its socket

private:
  struct IpCounter { uint32_t ipAddr; uint8_t count; };

  GatewayCrypto     _crypto;
  Allowlist         _allowlist;
  SessionRegistry   _registry;
  int               _listenSock = -1;
  SemaphoreHandle_t _sessionSlots = nullptr;   // Counting semaphore: MAX_SESSIONS
  SemaphoreHandle_t _handshakeSlots = nullptr; // Counting semaphore: MAX_CONCURRENT_HANDSHAKES
  SemaphoreHandle_t _ipLock = nullptr;
  IpCounter         _ipCounters[MAX_CONCURRENT_HANDSHAKES];

  static void acceptTaskEntry(void* arg);
  void acceptLoop();
  void dispatch(int clientSock, uint32_t ipAddr, const char* ipStr, uint16_t port);
  const char* tryAcquireHandshake(uint32_t ipAddr);  // nullptr on success, else the reason
};

#endif // VPN_GATEWAY_H
