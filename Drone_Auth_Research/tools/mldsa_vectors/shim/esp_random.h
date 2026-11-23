/* Laptop stand-in for the ESP-IDF header esp_random.h, so the firmware's ML-DSA
 * sources (whose config calls esp_fill_random) also build on the laptop. */
#ifndef DRONE_HOST_ESP_RANDOM_H
#define DRONE_HOST_ESP_RANDOM_H
#include <stddef.h>
void esp_fill_random(void *buf, size_t len);
#endif
