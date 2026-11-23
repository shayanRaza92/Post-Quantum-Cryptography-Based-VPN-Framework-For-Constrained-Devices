/* esp_fill_random() for the laptop build, using the operating system's random generator. */
#include <stdlib.h>
#include <sys/random.h>
#include "esp_random.h"

void esp_fill_random(void *buf, size_t len) {
  unsigned char *p = (unsigned char *)buf;
  while (len > 0) {
    size_t n = len > 256 ? 256 : len; /* getentropy() takes at most 256 bytes per call */
    if (getentropy(p, n) != 0) abort();
    p += n;
    len -= n;
  }
}
