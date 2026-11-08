#include "VpnGateway.h"
#include "GatewaySession.h"
#include "Log.h"
#include <WiFi.h>
#include <lwip/sockets.h>
#include <errno.h>
#include <unistd.h>
#include <new>

bool VpnGateway::begin(uint16_t port) {
  _crypto.begin(GATEWAY_PRIVATE_SEED);
  _allowlist.begin();
  _registry.begin();

  _sessionSlots   = xSemaphoreCreateCounting(MAX_SESSIONS, MAX_SESSIONS);
  _handshakeSlots = xSemaphoreCreateCounting(MAX_CONCURRENT_HANDSHAKES, MAX_CONCURRENT_HANDSHAKES);
  _ipLock         = xSemaphoreCreateMutex();
  for (size_t i = 0; i < MAX_CONCURRENT_HANDSHAKES; i++) _ipCounters[i] = { 0, 0 };
  if (!_sessionSlots || !_handshakeSlots || !_ipLock) {
    logLine("[ERROR] Could not allocate gateway locks.");
    return false;
  }

  _listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
  if (_listenSock < 0) {
    logLine("[ERROR] socket() failed (errno %d).", errno);
    return false;
  }
  int reuse = 1;
  setsockopt(_listenSock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(port);
  if (bind(_listenSock, (struct sockaddr*)&addr, sizeof(addr)) != 0 || listen(_listenSock, MAX_SESSIONS) != 0) {
    logLine("[ERROR] bind/listen on port %u failed (errno %d).", (unsigned)port, errno);
    close(_listenSock);
    _listenSock = -1;
    return false;
  }

  if (xTaskCreate(acceptTaskEntry, "vpn-accept", 4096, this, 2, NULL) != pdPASS) {
    logLine("[ERROR] Could not start the accept task.");
    return false;
  }
  return true;
}

// ----------------------------------------------------------------------------
// ACCEPT LOOP (dedicated task)
// ----------------------------------------------------------------------------
void VpnGateway::acceptTaskEntry(void* arg) {
  static_cast<VpnGateway*>(arg)->acceptLoop();
  vTaskDelete(NULL);
}

void VpnGateway::acceptLoop() {
  logLine("Gateway listening for incoming ESP32 connections...");
  while (true) {
    struct sockaddr_in peer;
    socklen_t peerLen = sizeof(peer);
    int clientSock = accept(_listenSock, (struct sockaddr*)&peer, &peerLen);
    if (clientSock < 0) {
      // e.g. out of sockets / memory. Never leave the loop: that would stop serving every device.
      logLine("[ACCEPT-ERROR] accept() failed (errno %d). Continuing to serve other devices.", errno);
      vTaskDelay(pdMS_TO_TICKS(100));
      continue;
    }
    char ipStr[16];
    inet_ntop(AF_INET, &peer.sin_addr, ipStr, sizeof(ipStr));
    dispatch(clientSock, peer.sin_addr.s_addr, ipStr, ntohs(peer.sin_port));
  }
}

void VpnGateway::dispatch(int clientSock, uint32_t ipAddr, const char* ipStr, uint16_t port) {
  // DoS Defense 1: total live sessions (each costs a task stack + socket)
  if (xSemaphoreTake(_sessionSlots, 0) != pdTRUE) {
    logLine("[DOS-PROTECT] Session limit (%u) reached. Dropping %s:%u", (unsigned)MAX_SESSIONS, ipStr, (unsigned)port);
    close(clientSock);
    return;
  }

  // DoS Defense 2: global + per-IP concurrent handshake caps
  const char* busyReason = tryAcquireHandshake(ipAddr);
  if (busyReason != nullptr) {
    logLine("[DOS-PROTECT] Server busy: %s. Dropping %s:%u", busyReason, ipStr, (unsigned)port);
    close(clientSock);
    releaseSession();
    return;
  }

  logLine("[CONNECT] Incoming connection from %s:%u", ipStr, (unsigned)port);
  int noDelay = 1;
  setsockopt(clientSock, IPPROTO_TCP, TCP_NODELAY, &noDelay, sizeof(noDelay));

  GatewaySession* session = new (std::nothrow) GatewaySession(clientSock, ipAddr, ipStr, port, *this);
  if (session == nullptr ||
      xTaskCreate(GatewaySession::taskEntry, "vpn-session", SESSION_TASK_STACK_BYTES, session, 1, NULL) != pdPASS) {
    // Out of memory: refuse THIS client only, give back its slots, keep serving the rest
    logLine("[DISPATCH-ERROR] Not enough memory for a session (free heap %u B). Dropping %s:%u",
            (unsigned)ESP.getFreeHeap(), ipStr, (unsigned)port);
    delete session;
    close(clientSock);
    releaseHandshake(ipAddr);
    releaseSession();
  }
  // On success the session task owns the socket and both slots from here on
}

// ----------------------------------------------------------------------------
// SLOT ACCOUNTING
// ----------------------------------------------------------------------------
const char* VpnGateway::tryAcquireHandshake(uint32_t ipAddr) {
  const char* reason = nullptr;
  xSemaphoreTake(_ipLock, portMAX_DELAY);

  IpCounter* counter = nullptr;
  IpCounter* freeCounter = nullptr;
  for (size_t i = 0; i < MAX_CONCURRENT_HANDSHAKES; i++) {
    if (_ipCounters[i].count > 0 && _ipCounters[i].ipAddr == ipAddr) counter = &_ipCounters[i];
    if (_ipCounters[i].count == 0 && freeCounter == nullptr) freeCounter = &_ipCounters[i];
  }

  if (counter != nullptr && counter->count >= MAX_HANDSHAKES_PER_IP) {
    reason = "per-IP handshake limit reached";
  } else if (xSemaphoreTake(_handshakeSlots, 0) != pdTRUE) {
    reason = "global handshake capacity reached";
  } else {
    // A free counter always exists: at most MAX_CONCURRENT_HANDSHAKES handshakes run at once
    if (counter == nullptr) {
      counter = freeCounter;
      counter->ipAddr = ipAddr;
      counter->count = 0;
    }
    counter->count++;
  }

  xSemaphoreGive(_ipLock);
  return reason;
}

void VpnGateway::releaseHandshake(uint32_t ipAddr) {
  xSemaphoreTake(_ipLock, portMAX_DELAY);
  for (size_t i = 0; i < MAX_CONCURRENT_HANDSHAKES; i++) {
    if (_ipCounters[i].count > 0 && _ipCounters[i].ipAddr == ipAddr) {
      _ipCounters[i].count--;
      break;
    }
  }
  xSemaphoreGive(_handshakeSlots);
  xSemaphoreGive(_ipLock);
}

void VpnGateway::releaseSession() {
  xSemaphoreGive(_sessionSlots);
}

// ----------------------------------------------------------------------------
// SERIAL MONITOR COMMANDS
// ----------------------------------------------------------------------------
void VpnGateway::handleCommand(String line) {
  line.trim();
  if (line.length() == 0) return;

  int space = line.indexOf(' ');
  String cmd = (space < 0) ? line : line.substring(0, space);
  String arg = (space < 0) ? String("") : line.substring(space + 1);
  cmd.toLowerCase();
  arg.trim();

  if (cmd == "help") {
    logLine("Commands:");
    logLine("  status         - free memory, Wi-Fi clients, active tunnels");
    logLine("  list           - allowlist with ALLOWED / REVOKED state");
    logLine("  sessions       - devices with an active tunnel");
    logLine("  revoke <id>    - block a device now and disconnect it (saved in flash)");
    logLine("  allow <id>     - allow a revoked device again (saved in flash)");
    logLine("  kick <id>      - disconnect a device once (it may reconnect)");
  } else if (cmd == "status") {
    logLine("[STATUS] Free heap: %u B | Wi-Fi stations: %u | Gateway IP: %s",
            (unsigned)ESP.getFreeHeap(), (unsigned)WiFi.softAPgetStationNum(),
            WiFi.softAPIP().toString().c_str());
    _registry.printActive();
  } else if (cmd == "list") {
    _allowlist.print();
  } else if (cmd == "sessions") {
    _registry.printActive();
  } else if (cmd == "revoke" && arg.length() > 0) {
    if (_allowlist.setRevoked(arg.c_str(), true)) {
      logLine("[ALLOWLIST] %s REVOKED.", arg.c_str());
      _registry.terminate(arg.c_str(), "revoked by operator");
    } else {
      logLine("[ALLOWLIST] Unknown device ID '%s'. Type 'list'.", arg.c_str());
    }
  } else if (cmd == "allow" && arg.length() > 0) {
    if (_allowlist.setRevoked(arg.c_str(), false)) {
      logLine("[ALLOWLIST] %s ALLOWED.", arg.c_str());
    } else {
      logLine("[ALLOWLIST] Unknown device ID '%s'. Type 'list'.", arg.c_str());
    }
  } else if (cmd == "kick" && arg.length() > 0) {
    if (!_registry.terminate(arg.c_str(), "kicked by operator")) {
      logLine("[SESSIONS] '%s' has no active tunnel.", arg.c_str());
    }
  } else {
    logLine("Unknown command '%s'. Type 'help'.", line.c_str());
  }
}
