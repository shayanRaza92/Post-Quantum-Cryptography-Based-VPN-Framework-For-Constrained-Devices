#include "DeviceIdentity.h"

// Constructor: Initializes members and copies device name into buffer
DeviceIdentity::DeviceIdentity(const char* deviceId) : _isInitialized(false) {
  memset(_deviceId, 0, sizeof(_deviceId));                     // Zero out device ID buffer
  strncpy(_deviceId, deviceId, sizeof(_deviceId) - 1);         // Copy name safely
  memset(_seed, 0, sizeof(_seed));                             // Zero out seed buffer
  memset(_publicKey, 0, sizeof(_publicKey));                   // Zero out public key buffer
  memset(_secretKey, 0, sizeof(_secretKey));                   // Zero out secret key buffer
}

// Initializes identity: checks NVS flash for existing seed or generates new one via TRNG
bool DeviceIdentity::begin() {
  Preferences persistentStorage;                               // Preferences object for NVS flash
  persistentStorage.begin("vpn_identity", false);              // Open namespace in read/write mode

  bool keyExistsInFlash = persistentStorage.isKey("ed25519_seed"); // Check if key was saved previously

  if (keyExistsInFlash) {
    persistentStorage.getBytes("ed25519_seed", _seed, sizeof(_seed)); // Read seed from flash
    Serial.println("[KEY] Loaded existing key from NVS flash.");
  } else {
    Serial.println("[KEY] First boot! Generating unique key via Hardware TRNG...");
    esp_fill_random(_seed, sizeof(_seed));                     // Generate random bytes from chip hardware
    persistentStorage.putBytes("ed25519_seed", _seed, sizeof(_seed)); // Save seed permanently to flash
    Serial.println("[KEY] Saved seed permanently to NVS flash.");
  }
  persistentStorage.end();                                     // Close flash storage safely

  // Derive the 32-byte public key and 64-byte secret key from the 32-byte seed
  crypto_sign_seed_keypair(_publicKey, _secretKey, _seed);
  _isInitialized = true;                                       // Mark keys as ready for use

  // Print startup identity box to Serial Monitor
  Serial.println("========================================");
  Serial.printf ("Device ID  : %s\n", _deviceId);
  Serial.print  ("Public Key : ");
  printPublicKeyHex();
  Serial.println("========================================");

  return true;
}

// Getter for 32-byte public key
const uint8_t* DeviceIdentity::getPublicKey() const {
  return _publicKey;
}

// Getter for device ID string
const char* DeviceIdentity::getDeviceId() const {
  return _deviceId;
}

// Signs an incoming message using the device's private key, outputting 64-byte signature
bool DeviceIdentity::sign(const uint8_t* message, size_t messageLen, uint8_t* signatureOut) const {
  if (!_isInitialized) return false;                           // Fail if keys were not initialized
  unsigned long long sigLen = 0;                               // Output signature length
  crypto_sign_detached(signatureOut, &sigLen, message, messageLen, _secretKey); // Perform Ed25519 signing
  return true;
}

// Prints the public key bytes as readable uppercase hex
void DeviceIdentity::printPublicKeyHex() const {
  for (size_t i = 0; i < sizeof(_publicKey); i++) {
    if (_publicKey[i] < 0x10) Serial.print("0");               // Print leading zero for single digits
    Serial.print(_publicKey[i], HEX);                          // Print byte in hex format
  }
  Serial.println();
}