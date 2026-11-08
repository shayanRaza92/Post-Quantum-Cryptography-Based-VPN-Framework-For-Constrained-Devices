#ifndef GATEWAY_ALLOWLIST_H
#define GATEWAY_ALLOWLIST_H

#include <Arduino.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include "gateway_config.h"

// ============================================================================
// CLASS: Allowlist
// Replaces laptop_server/authorized_devices.json.
//   * The device list + public keys are compiled in (gateway_config.h).
//   * Any device can be revoked / re-allowed at runtime from the Serial Monitor.
//     Revocations are stored in NVS flash, so they survive a reboot.
//   * Thread-safe: session tasks check it while the Serial command task edits it.
// ============================================================================
class Allowlist {
private:
  SemaphoreHandle_t _lock = nullptr;
  bool _revoked[AUTHORIZED_DEVICE_COUNT];

  int indexOf(const char* deviceId) const;          // -1 if the ID is not in the compiled list
  void saveRevocations();                           // Persist revoked IDs to NVS (caller holds lock)

public:
  void begin();                                     // Creates the lock and loads revocations from NVS

  // Returns the registered public key, or nullptr if the ID is unknown or revoked
  const uint8_t* lookup(const char* deviceId);

  // True while deviceId is allowed AND still registered with exactly this key
  bool isStillAuthorized(const char* deviceId, const uint8_t* publicKey);

  // Runtime revocation. Returns false if the ID is not in the compiled list.
  bool setRevoked(const char* deviceId, bool revoked);

  void print();                                     // Lists every device with ALLOWED / REVOKED
};

#endif // GATEWAY_ALLOWLIST_H
