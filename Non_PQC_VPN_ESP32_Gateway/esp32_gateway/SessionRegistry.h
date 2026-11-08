#ifndef GATEWAY_SESSION_REGISTRY_H
#define GATEWAY_SESSION_REGISTRY_H

#include <Arduino.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include "gateway_config.h"

class GatewaySession;

// ============================================================================
// CLASS: SessionRegistry
// One live tunnel per device ID (same job as laptop_server/session_registry.py).
// If a device authenticates again (rebooted, Wi-Fi blip, half-open old socket),
// the old tunnel is closed so a device never has two tunnels at once.
// ============================================================================
class SessionRegistry {
private:
  struct Entry {
    char            deviceId[DEVICE_ID_LENGTH + 1];
    GatewaySession* session;                        // nullptr = free slot
  };
  SemaphoreHandle_t _lock = nullptr;
  Entry _entries[MAX_SESSIONS];

  void printActiveLocked();

public:
  void begin();
  void registerSession(const char* deviceId, GatewaySession* session);
  void unregisterSession(const char* deviceId, GatewaySession* session); // No-op if it was replaced
  bool terminate(const char* deviceId, const char* reason);              // Close a device's tunnel (Serial "kick")
  void printActive();
};

#endif // GATEWAY_SESSION_REGISTRY_H
