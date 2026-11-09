/*
 * esp_random.h - laptop stand-in for the ESP-IDF header of the same name.
 *
 * The bundled ML-KEM-512 / ML-DSA-44 configs (arduino_libraries/.../*_native_config.h)
 * route all randomness to esp_fill_random(). build_native_libs.sh puts this folder on
 * the include path so the SAME sources and SAME config compile on the laptop, with
 * esp_fill_random() implemented by host_random.c using the OS CSPRNG.
 */
#ifndef HOST_SHIM_ESP_RANDOM_H
#define HOST_SHIM_ESP_RANDOM_H

#include <stddef.h>

void esp_fill_random(void *buf, size_t len);

#endif
