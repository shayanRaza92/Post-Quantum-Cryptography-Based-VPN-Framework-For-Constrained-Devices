/*
 * host_random.c - esp_fill_random() for the laptop build (Linux and macOS).
 *
 * Fills the buffer from the operating system's CSPRNG via getentropy(), which is
 * limited to 256 bytes per call. esp_fill_random() has no way to report an error,
 * so if the OS RNG ever fails we abort instead of returning predictable bytes.
 */
#define _DEFAULT_SOURCE  /* glibc: expose getentropy() under -std=c99 */
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <sys/random.h>
#endif
#include "esp_random.h"

void esp_fill_random(void *buf, size_t len) {
  uint8_t *out = (uint8_t *)buf;
  while (len > 0) {
    size_t n = len > 256 ? 256 : len;
    if (getentropy(out, n) != 0) {
      abort();
    }
    out += n;
    len -= n;
  }
}
