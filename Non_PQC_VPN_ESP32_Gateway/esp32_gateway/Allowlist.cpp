#include "Allowlist.h"
#include "Log.h"
#include <Preferences.h>

static const char* NVS_NAMESPACE = "vpn_gw_allow";
static const char* NVS_KEY       = "revoked";      // Comma-separated list of revoked device IDs

void Allowlist::begin() {
  _lock = xSemaphoreCreateMutex();
  for (size_t i = 0; i < AUTHORIZED_DEVICE_COUNT; i++) _revoked[i] = false;

  Preferences prefs;
  prefs.begin(NVS_NAMESPACE, true);                // Read-only
  String stored = prefs.getString(NVS_KEY, "");
  prefs.end();

  // Parse "esp32-02,esp32-05"
  int start = 0;
  while (start < (int)stored.length()) {
    int comma = stored.indexOf(',', start);
    if (comma < 0) comma = stored.length();
    String id = stored.substring(start, comma);
    int idx = indexOf(id.c_str());
    if (idx >= 0) _revoked[idx] = true;
    start = comma + 1;
  }
}

int Allowlist::indexOf(const char* deviceId) const {
  for (size_t i = 0; i < AUTHORIZED_DEVICE_COUNT; i++) {
    if (strcmp(AUTHORIZED_DEVICES[i].deviceId, deviceId) == 0) return (int)i;
  }
  return -1;
}

const uint8_t* Allowlist::lookup(const char* deviceId) {
  xSemaphoreTake(_lock, portMAX_DELAY);
  int idx = indexOf(deviceId);
  const uint8_t* key = (idx >= 0 && !_revoked[idx]) ? AUTHORIZED_DEVICES[idx].publicKey : nullptr;
  xSemaphoreGive(_lock);
  return key;
}

bool Allowlist::isStillAuthorized(const char* deviceId, const uint8_t* publicKey) {
  const uint8_t* current = lookup(deviceId);
  return current != nullptr && memcmp(current, publicKey, 32) == 0;
}

void Allowlist::saveRevocations() {
  String list;
  for (size_t i = 0; i < AUTHORIZED_DEVICE_COUNT; i++) {
    if (!_revoked[i]) continue;
    if (list.length() > 0) list += ",";
    list += AUTHORIZED_DEVICES[i].deviceId;
  }
  Preferences prefs;
  prefs.begin(NVS_NAMESPACE, false);               // Read-write
  prefs.putString(NVS_KEY, list);
  prefs.end();
}

bool Allowlist::setRevoked(const char* deviceId, bool revoked) {
  xSemaphoreTake(_lock, portMAX_DELAY);
  int idx = indexOf(deviceId);
  if (idx >= 0) {
    _revoked[idx] = revoked;
    saveRevocations();
  }
  xSemaphoreGive(_lock);
  return idx >= 0;
}

void Allowlist::print() {
  xSemaphoreTake(_lock, portMAX_DELAY);
  logLine("Allowlist (%u device(s)):", (unsigned)AUTHORIZED_DEVICE_COUNT);
  for (size_t i = 0; i < AUTHORIZED_DEVICE_COUNT; i++) {
    const uint8_t* k = AUTHORIZED_DEVICES[i].publicKey;
    logLine("  - %-16s %s  key %02X%02X%02X%02X..%02X%02X", AUTHORIZED_DEVICES[i].deviceId,
            _revoked[i] ? "REVOKED" : "ALLOWED", k[0], k[1], k[2], k[3], k[30], k[31]);
  }
  xSemaphoreGive(_lock);
}
