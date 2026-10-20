#ifndef AUTH_MANAGER_H
#define AUTH_MANAGER_H

#include <Arduino.h>
#include <WiFiClient.h>         // Network client socket library
#include "DeviceIdentity.h"     // DeviceIdentity class definition

class AuthManager {
private:
  WiFiClient&           _client;              // Reference to active TCP network client
  const DeviceIdentity& _identity;            // Reference to local device identity
  const uint8_t*        _trustedGatewayKey;   // Pointer to 32-byte trusted gateway public key

  // Helper method: Blocks until exact number of bytes arrive or timeout expires
  bool readExact(uint8_t* buffer, size_t count, unsigned long timeoutMs = 7000);

public:
  // Constructor: Takes network client, identity instance, and pinned gateway public key
  AuthManager(WiFiClient& client, const DeviceIdentity& identity, const uint8_t* trustedGatewayKey);

  // Executes two-stage authorization and mutual authentication handshake
  bool performMutualAuthentication();
};

#endif // AUTH_MANAGER_H
