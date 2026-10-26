#include "DeviceIdentity.h"

// Constructor: Initializes members and copies device name into buffer (up to 16 chars)
DeviceIdentity::DeviceIdentity(const char* deviceId) : _isInitialized(false) {
  memset(_deviceId, 0, sizeof(_deviceId));                     // Zero out device ID buffer
  if (deviceId != nullptr) {
    strncpy(_deviceId, deviceId, sizeof(_deviceId) - 1);       // Copy name safely up to 16 chars
  }
  memset(_publicKey, 0, sizeof(_publicKey));                   // Zero out public key buffer
  memset(_secretKey, 0, sizeof(_secretKey));                   // Zero out secret key buffer
}

// Initializes identity: checks NVS flash for existing seed or generates new one via TRNG
// Hardened: validates 32-byte read length and wipes temporary seed from RAM using sodium_memzero
bool DeviceIdentity::begin() {
  Preferences persistentStorage;                               // Preferences object for NVS flash
  persistentStorage.begin("vpn_identity", false);              // Open namespace in read/write mode

  uint8_t tempSeed[32];
  memset(tempSeed, 0, sizeof(tempSeed));

  bool keyExistsInFlash = persistentStorage.isKey("ed25519_seed"); // Check if key was saved previously
  bool seedValid = false;

  if (keyExistsInFlash) {
    size_t readBytes = persistentStorage.getBytes("ed25519_seed", tempSeed, sizeof(tempSeed));
    if (readBytes == sizeof(tempSeed)) {
      seedValid = true;
      Serial.println("[KEY] Loaded valid 32-byte seed from NVS flash.");
    } else {
      Serial.println("[KEY-WARN] Corrupted seed length in NVS flash. Generating fresh keypair...");
    }
  }

  if (!seedValid) {
    Serial.println("[KEY] Generating unique key via Hardware TRNG...");
    esp_fill_random(tempSeed, sizeof(tempSeed));               // Generate random bytes from chip hardware
    persistentStorage.putBytes("ed25519_seed", tempSeed, sizeof(tempSeed)); // Save seed permanently to flash
    Serial.println("[KEY] Saved seed permanently to NVS flash.");
  }
  persistentStorage.end();                                     // Close flash storage safely

  // Derive the 32-byte public key and 64-byte secret key from the 32-byte seed
  crypto_sign_seed_keypair(_publicKey, _secretKey, tempSeed);

  // Securely wipe the temporary seed from RAM to prevent residual memory inspection
  sodium_memzero(tempSeed, sizeof(tempSeed));

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