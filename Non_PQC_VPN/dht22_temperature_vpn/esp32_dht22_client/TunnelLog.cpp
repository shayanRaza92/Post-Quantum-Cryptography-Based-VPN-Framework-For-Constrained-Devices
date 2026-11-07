#include "TunnelLog.h"
#include <stdarg.h>

namespace TunnelLog {

static const size_t INNER       = 75;  // Text columns inside "| " ... " |"
static const size_t HEX_PER_ROW = 32;  // 32 bytes = 64 hex characters per row

static const char* const BAR_LINE =
  "+-----------------------------------------------------------------------------+";
static const char* const FIELD_BAR_LINE =
  "+----------------------------+------------------------------------------------+";

void bar() {
  Serial.println(BAR_LINE);
}

void row(const char* fmt, ...) {
  char buf[192];
  va_list args;
  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);
  Serial.printf("| %-75.75s |\n", buf);
}

void hexRows(const uint8_t* data, size_t len) {
  char hex[HEX_PER_ROW * 2 + 1];
  for (size_t offset = 0; offset < len; offset += HEX_PER_ROW) {
    size_t n = min(HEX_PER_ROW, len - offset);
    for (size_t i = 0; i < n; i++) {
      snprintf(hex + i * 2, 3, "%02X", data[offset + i]);
    }
    hex[n * 2] = '\0';
    row("%s", hex);
  }
}

// Wraps at 75 columns, breaking after a comma where possible (keeps JSON fields whole)
void textRows(const char* text, size_t len) {
  char chunk[INNER + 1];
  size_t offset = 0;
  while (offset < len) {
    size_t n = len - offset;
    if (n > INNER) {
      n = INNER;
      for (size_t i = INNER; i > 0; i--) {
        if (text[offset + i - 1] == ',') { n = i; break; }
      }
    }
    memcpy(chunk, text + offset, n);
    chunk[n] = '\0';
    row("%s", chunk);
    offset += n;
  }
}

void fieldTableHeader(const char* title) {
  bar();
  row("%s", title);
  Serial.println(FIELD_BAR_LINE);
  Serial.printf("| %-26s | %-46s |\n", "Field", "Value");
  Serial.println(FIELD_BAR_LINE);
}

void field(const char* name, const char* fmt, ...) {
  char buf[128];
  va_list args;
  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);
  Serial.printf("| %-26.26s | %-46.46s |\n", name, buf);
}

void printDataKeys(const uint8_t* kC2s, const uint8_t* kS2c) {
  bar();
  row("DATA TUNNEL KEYS (derived from K_session via HMAC-SHA256)");
  bar();
  row("K_c2s = HMAC-SHA256(K_session, \"VPN-v1|DATA|C2S\")   [ESP32 -> Server]");
  hexRows(kC2s, 32);
  bar();
  row("K_s2c = HMAC-SHA256(K_session, \"VPN-v1|DATA|S2C\")   [Server -> ESP32]");
  hexRows(kS2c, 32);
  bar();
}

void printRecord(const char* title, const uint8_t* record, size_t len, const char* keyName) {
  const size_t headerLen = 10, tagLen = 16;
  if (len < headerLen + tagLen) return;

  unsigned body = ((unsigned)record[0] << 8) | record[1];
  unsigned long seqHi = ((unsigned long)record[2] << 24) | ((unsigned long)record[3] << 16) |
                        ((unsigned long)record[4] << 8)  |  (unsigned long)record[5];
  unsigned long seqLo = ((unsigned long)record[6] << 24) | ((unsigned long)record[7] << 16) |
                        ((unsigned long)record[8] << 8)  |  (unsigned long)record[9];
  size_t cipherLen = len - headerLen - tagLen;

  bar();
  row("%s (%u Bytes / %u-bits on wire)", title, (unsigned)len, (unsigned)(len * 8));
  bar();
  row("Length Field   (2 Bytes)  : 0x%04X  (%u Bytes follow)", body, body);
  row("Sequence No.   (8 Bytes)  : 0x%08lX%08lX  (#%lu)", seqHi, seqLo, seqLo);
  row("GCM IV / Nonce (12 Bytes) : 00000000%08lX%08lX", seqHi, seqLo);
  row("AEAD Cipher / Key         : AES-256-GCM / %s", keyName);
  bar();
  row("Ciphertext (%u Bytes / %u-bits)", (unsigned)cipherLen, (unsigned)(cipherLen * 8));
  hexRows(record + headerLen, cipherLen);
  bar();
  row("GCM Authentication Tag (16 Bytes / 128-bits)");
  hexRows(record + len - tagLen, tagLen);
  bar();
}

void printPayload(const char* title, const char* text, size_t len) {
  row("%s (%u Bytes)", title, (unsigned)len);
  textRows(text, len);
  bar();
}

} // namespace TunnelLog
