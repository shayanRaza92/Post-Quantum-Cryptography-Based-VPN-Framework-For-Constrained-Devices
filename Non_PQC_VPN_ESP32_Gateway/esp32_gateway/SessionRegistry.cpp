#include "SessionRegistry.h"
#include "GatewaySession.h"
#include "Log.h"

// Lifetime note: a session object is deleted only by its own task, and only AFTER it
// has called unregisterSession() (which needs _lock). So while we hold _lock, every
// pointer stored in _entries is still alive and safe to call terminate() on.

void SessionRegistry::begin() {
  _lock = xSemaphoreCreateMutex();
  for (size_t i = 0; i < MAX_SESSIONS; i++) {
    _entries[i].deviceId[0] = '\0';
    _entries[i].session = nullptr;
  }
}

void SessionRegistry::registerSession(const char* deviceId, GatewaySession* session) {
  xSemaphoreTake(_lock, portMAX_DELAY);
  Entry* freeSlot = nullptr;
  for (size_t i = 0; i < MAX_SESSIONS; i++) {
    Entry& e = _entries[i];
    if (e.session != nullptr && strcmp(e.deviceId, deviceId) == 0) {
      // Same device already has a tunnel: close the old one and reuse its slot
      logLine("[%s] [SESSION] New authenticated session from %s replaces the old one from %s.",
              deviceId, session->peerLabel(), e.session->peerLabel());
      e.session->terminate("replaced by a newer session of the same device");
      e.session = session;
      printActiveLocked();
      xSemaphoreGive(_lock);
      return;
    }
    if (e.session == nullptr && freeSlot == nullptr) freeSlot = &e;
  }
  // A free slot always exists: there are at most MAX_SESSIONS sessions alive in total
  if (freeSlot != nullptr) {
    strncpy(freeSlot->deviceId, deviceId, DEVICE_ID_LENGTH);
    freeSlot->deviceId[DEVICE_ID_LENGTH] = '\0';
    freeSlot->session = session;
  }
  printActiveLocked();
  xSemaphoreGive(_lock);
}

void SessionRegistry::unregisterSession(const char* deviceId, GatewaySession* session) {
  xSemaphoreTake(_lock, portMAX_DELAY);
  for (size_t i = 0; i < MAX_SESSIONS; i++) {
    Entry& e = _entries[i];
    if (e.session == session && strcmp(e.deviceId, deviceId) == 0) {
      e.session = nullptr;
      e.deviceId[0] = '\0';
      printActiveLocked();
      break;
    }
  }
  xSemaphoreGive(_lock);
}

bool SessionRegistry::terminate(const char* deviceId, const char* reason) {
  bool found = false;
  xSemaphoreTake(_lock, portMAX_DELAY);
  for (size_t i = 0; i < MAX_SESSIONS; i++) {
    Entry& e = _entries[i];
    if (e.session != nullptr && strcmp(e.deviceId, deviceId) == 0) {
      e.session->terminate(reason);
      found = true;
    }
  }
  xSemaphoreGive(_lock);
  return found;
}

void SessionRegistry::printActive() {
  xSemaphoreTake(_lock, portMAX_DELAY);
  printActiveLocked();
  xSemaphoreGive(_lock);
}

void SessionRegistry::printActiveLocked() {
  char list[MAX_SESSIONS * (DEVICE_ID_LENGTH + 2) + 2] = "";
  unsigned count = 0;
  for (size_t i = 0; i < MAX_SESSIONS; i++) {
    if (_entries[i].session == nullptr) continue;
    if (count > 0) strcat(list, ", ");
    strcat(list, _entries[i].deviceId);
    count++;
  }
  logLine("[SESSIONS] Active tunnels (%u): %s", count, count ? list : "-");
}
