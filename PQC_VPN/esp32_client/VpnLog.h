#ifndef VPN_LOG_H
#define VPN_LOG_H

#include <Arduino.h>

// ============================================================================
// VpnSerial: the handshake and tunnel code print through this object instead of
// Serial (see the "#define Serial VpnSerial" lines in AuthManager.cpp and
// SecureTunnel.cpp). Normally it forwards everything to Serial. The system
// benchmark sets VpnSerial.quiet = true, because printing several KB of tables
// at 115200 baud would add hundreds of milliseconds to every measured handshake.
// ============================================================================
class QuietablePrint : public Print {
public:
  bool quiet = false;
  size_t write(uint8_t c) override { return quiet ? 1 : Serial.write(c); }
  size_t write(const uint8_t* buffer, size_t size) override { return quiet ? size : Serial.write(buffer, size); }
};

extern QuietablePrint VpnSerial;

#endif // VPN_LOG_H
