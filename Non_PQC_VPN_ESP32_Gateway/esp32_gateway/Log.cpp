#include "Log.h"
#include <stdarg.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

static SemaphoreHandle_t gSerialLock = nullptr;

void logInit() {
  if (gSerialLock == nullptr) {
    gSerialLock = xSemaphoreCreateMutex();
  }
}

static void lockSerial()   { if (gSerialLock) xSemaphoreTake(gSerialLock, portMAX_DELAY); }
static void unlockSerial() { if (gSerialLock) xSemaphoreGive(gSerialLock); }

void logLine(const char* fmt, ...) {
  char buffer[256];
  va_list args;
  va_start(args, fmt);
  vsnprintf(buffer, sizeof(buffer), fmt, args);
  va_end(args);

  lockSerial();
  Serial.println(buffer);
  unlockSerial();
}

void SessionLog::add(const char* fmt, ...) {
  char buffer[256];
  va_list args;
  va_start(args, fmt);
  vsnprintf(buffer, sizeof(buffer), fmt, args);
  va_end(args);
  _text += buffer;
  _text += "\n";
}

void SessionLog::addHex(const char* label, const uint8_t* data, size_t len) {
  static const char HEX_DIGITS[] = "0123456789ABCDEF";
  _text += label;
  _text += ":\n";
  for (size_t row = 0; row < len; row += 32) {
    _text += "    ";
    for (size_t i = row; i < len && i < row + 32; i++) {
      _text += HEX_DIGITS[data[i] >> 4];
      _text += HEX_DIGITS[data[i] & 0x0F];
    }
    _text += "\n";
  }
}

void SessionLog::flush(const char* header) {
  lockSerial();
  Serial.println();
  Serial.println("###############################################################################");
  Serial.print  ("# BEGIN HANDSHAKE LOG : ");
  Serial.println(header);
  Serial.println("###############################################################################");
  Serial.print(_text.c_str());
  Serial.println("###############################################################################");
  Serial.print  ("# END HANDSHAKE LOG   : ");
  Serial.println(header);
  Serial.println("###############################################################################");
  unlockSerial();
  _text.clear();
}
