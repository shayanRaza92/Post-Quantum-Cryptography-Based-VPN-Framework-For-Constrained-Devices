/*
 * linux_randombytes.c - laptop replacement for the ESP32 RNG in the mldsa-esp32 library.
 *
 * The ML-DSA-44 library (NeuraiProject/mldsa-esp32) gets randomness from
 * mldsa_esp32_randombytes(), which calls esp_fill_random() on the ESP32.
 * To compile the SAME C code for the laptop gateway, build_libmldsa44.sh
 * leaves out the library's randombytes.c and links this file instead, which
 * reads the Linux kernel CSPRNG (/dev/urandom).
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

int mldsa_esp32_randombytes(uint8_t *out, size_t outlen) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL) {
        return -1;
    }
    size_t got = fread(out, 1, outlen, f);
    fclose(f);
    return (got == outlen) ? 0 : -1;
}
