#ifndef DEVICE_IDENTITY_H
#define DEVICE_IDENTITY_H

#include <Arduino.h>
#define MLD_CONFIG_API_NO_SUPERCOP
#include <sodium.h>       // Libsodium for secure memory zeroization (sodium_memzero)
#include <MLDSA44.h>      // NIST FIPS 204 ML-DSA-44 post-quantum digital signature library (mldsa-native)
#include <Preferences.h>  // ESP32 NVS flash storage library

class DeviceIdentity {
private:
  char    _deviceId[17];                            // Null-terminated device identifier string (max 16 chars + null)
  uint8_t _publicKey[MLDSA44::PUBLIC_KEY_SIZE];     // 1,312-byte derived ML-DSA-44 public key
  uint8_t _secretKey[MLDSA44::SECRET_KEY_SIZE];     // 2,560-byte derived ML-DSA-44 secret signing key
  bool    _isInitialized;                           // Status flag indicating keys are ready

public:
  DeviceIdentity(const char* deviceId);             // Constructor accepting the device name
  bool begin();                                     // Loads 32B seed from NVS or generates new seed via TRNG
  const uint8_t* getPublicKey() const;              // Getter for 1,312-byte ML-DSA-44 public key
  const char* getDeviceId() const;                  // Getter for device ID name
  bool sign(const uint8_t* message, size_t messageLen, uint8_t* signatureOut) const; // Signs message with ML-DSA-44
  void printPublicKeyHex() const;                   // Prints 1,312-byte public key as two-digit uppercase hex to Serial
};

#endif // DEVICE_IDENTITY_H

