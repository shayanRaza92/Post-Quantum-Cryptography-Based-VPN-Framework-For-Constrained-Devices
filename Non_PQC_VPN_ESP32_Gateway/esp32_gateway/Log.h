#ifndef GATEWAY_LOG_H
#define GATEWAY_LOG_H

#include <Arduino.h>
#include <string>

// ============================================================================
// Thread-safe Serial logging for the multi-client gateway.
// Every client session runs in its own FreeRTOS task. Without a lock, two
// handshakes running at the same time would print mixed-up lines.
// ============================================================================

void logInit();                                   // Create the Serial lock (call once in setup)
void logLine(const char* fmt, ...);               // Print one formatted line atomically

// Collects one session's handshake output and prints it as ONE uninterrupted
// block (framed by BEGIN/END lines naming the device), like the laptop gateway.
class SessionLog {
private:
  std::string _text;

public:
  void add(const char* fmt, ...);                 // Append one formatted line
  void addHex(const char* label, const uint8_t* data, size_t len); // Append "label: HEX" (32 bytes per row)
  void flush(const char* header);                 // Print everything atomically, then clear
};

#endif // GATEWAY_LOG_H
