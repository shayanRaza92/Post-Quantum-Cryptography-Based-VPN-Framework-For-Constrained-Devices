#ifndef TUNNEL_LOG_H
#define TUNNEL_LOG_H

#include <Arduino.h>

// ============================================================================
// Boxed 79-column Serial printouts for the encrypted data tunnel, in the same
// style as the handshake log printed by AuthManager:
//   +-----------------------------------------------------------------------------+
//   | text (75 columns)                                                           |
// ============================================================================
namespace TunnelLog {
  void bar();                                         // +-----...-----+
  void row(const char* fmt, ...);                     // | text padded/truncated to 75 |
  void hexRows(const uint8_t* data, size_t len);      // hex, 32 bytes per row
  void textRows(const char* text, size_t len);        // text wrapped at 75 columns

  // Two-column "Field | Value" table
  void fieldTableHeader(const char* title);
  void field(const char* name, const char* fmt, ...);

  // Directional data keys derived from K_session
  void printDataKeys(const uint8_t* kC2s, const uint8_t* kS2c);

  // Breakdown of one wire record: Length, Sequence, Nonce, Ciphertext, GCM Tag
  void printRecord(const char* title, const uint8_t* record, size_t len, const char* keyName);

  // "title (N Bytes)" followed by the wrapped text, closed by a bar
  void printPayload(const char* title, const char* text, size_t len);
}

#endif // TUNNEL_LOG_H
