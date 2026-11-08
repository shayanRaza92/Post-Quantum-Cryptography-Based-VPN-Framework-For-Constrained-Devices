#include "DeviceIdentity.h"

// Constructor: Initializes members and copies device name into buffer (up to 16 chars)
DeviceIdentity::DeviceIdentity(const char* deviceId) : _isInitialized(false) {
  memset(_deviceId, 0, sizeof(_deviceId));
  if (deviceId != nullptr) {
    strncpy(_deviceId, deviceId, sizeof(_deviceId) - 1);
  }
  memset(_publicKey, 0, sizeof(_publicKey));
  memset(_secretKey, 0, sizeof(_secretKey));
}

// Initializes identity: checks NVS flash for existing 32-byte ML-DSA-44 seed or generates a new one via TRNG.
// Note: Must be called inside a task with >= 64 KB stack (since MLDSA44::generateKeypairFromSeed uses ~33 KB stack).
bool DeviceIdentity::begin() {
  Preferences persistentStorage;
  persistentStorage.begin("vpn_pqc_id", false);

  uint8_t tempSeed[MLDSA44::SEED_SIZE];
  memset(tempSeed, 0, sizeof(tempSeed));

  bool keyExistsInFlash = persistentStorage.isKey("mldsa44_seed");
  bool seedValid = false;

  if (keyExistsInFlash) {
    size_t readBytes = persistentStorage.getBytes("mldsa44_seed", tempSeed, sizeof(tempSeed));
    if (readBytes == sizeof(tempSeed)) {
      seedValid = true;
      Serial.println("[KEY] Loaded valid 32-byte ML-DSA-44 seed from NVS flash.");
    } else {
      Serial.println("[KEY-WARN] Corrupted seed length in NVS flash. Generating fresh ML-DSA-44 seed...");
    }
  }

  if (!seedValid) {
    Serial.println("[KEY] Generating unique 32-byte ML-DSA-44 seed via Hardware TRNG...");
    esp_fill_random(tempSeed, sizeof(tempSeed));
    persistentStorage.putBytes("mldsa44_seed", tempSeed, sizeof(tempSeed));
    Serial.println("[KEY] Saved ML-DSA-44 seed permanently to NVS flash.");
  }
  persistentStorage.end();

  // Deterministically derive the 1,312-byte public key and 2,560-byte secret key from the 32-byte seed (FIPS 204)
  int rc = MLDSA44::generateKeypairFromSeed(_publicKey, _secretKey, tempSeed);
  sodium_memzero(tempSeed, sizeof(tempSeed));

  if (rc != 0) {
    Serial.println("[KEY-ERROR] ML-DSA-44 keypair derivation failed!");
    return false;
  }

  _isInitialized = true;

  // Print startup identity box to Serial Monitor
  Serial.println("========================================");
  Serial.printf ("Device ID  : %s\n", _deviceId);
  Serial.print  ("Public Key : ");
  printPublicKeyHex();
  Serial.println("========================================");

  return true;
}

// Getter for 1,312-byte ML-DSA-44 public key
const uint8_t* DeviceIdentity::getPublicKey() const {
  return _publicKey;
}

// Getter for device ID string
const char* DeviceIdentity::getDeviceId() const {
  return _deviceId;
}

// Signs an incoming message using the device's 2,560-byte ML-DSA-44 secret key, outputting 2,420-byte signature
bool DeviceIdentity::sign(const uint8_t* message, size_t messageLen, uint8_t* signatureOut) const {
  if (!_isInitialized) return false;
  size_t sigLen = 0;
  int rc = MLDSA44::sign(signatureOut, &sigLen, message, messageLen, _secretKey);
  return (rc == 0 && sigLen == MLDSA44::SIGNATURE_SIZE);
}

// Prints the 1,312-byte ML-DSA-44 public key as a continuous 2,624-character uppercase hex line
void DeviceIdentity::printPublicKeyHex() const {
  for (size_t i = 0; i < sizeof(_publicKey); i++) {
    if (_publicKey[i] < 0x10) Serial.print("0");
    Serial.print(_publicKey[i], HEX);
    if ((i & 0x3F) == 0x3F) {
      Serial.flush(); // Prevent UART TX FIFO overrun during long 2,624-char hex output
    }
  }
  Serial.println();
}

