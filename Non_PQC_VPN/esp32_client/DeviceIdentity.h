#ifndef DEVICE_IDENTITY_H
#define DEVICE_IDENTITY_H

#include <Arduino.h>
#include <sodium.h>       // Libsodium cryptographic library for Ed25519
#include <Preferences.h>  // ESP32 NVS flash storage library

class DeviceIdentity {
private:
  char    _deviceId[17];                                // Null-terminated device identifier string (max 16 chars + null)
  uint8_t _publicKey[crypto_sign_PUBLICKEYBYTES];       // 32-byte derived Ed25519 public key
  uint8_t _secretKey[crypto_sign_SECRETKEYBYTES];       // 64-byte derived Ed25519 secret signing key
  bool    _isInitialized;                               // Status flag indicating keys are ready

public:
  DeviceIdentity(const char* deviceId);                 // Constructor accepting the device name
  bool begin();                                         // Loads seed from NVS or generates new seed via TRNG
  const uint8_t* getPublicKey() const;                  // Getter for 32-byte public key
  const char* getDeviceId() const;                      // Getter for device ID name
  bool sign(const uint8_t* message, size_t messageLen, uint8_t* signatureOut) const; // Signs message
  void printPublicKeyHex() const;                       // Prints public key as two-digit hex to Serial
};

#endif // DEVICE_IDENTITY_H
