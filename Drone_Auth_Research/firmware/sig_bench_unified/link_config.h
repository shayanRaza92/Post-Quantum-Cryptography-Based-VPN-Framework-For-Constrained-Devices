// link_config.h - Wi-Fi settings for Step 3 (send W). Only used when ENABLE_LINK_TEST is 1
// in bench_config.h. The laptop running tools/gcs_link_test.py must be on the same network.
// Do not commit your real password.
#pragma once

#define LINK_WIFI_SSID     "YOUR_WIFI_SSID"
#define LINK_WIFI_PASSWORD "YOUR_WIFI_PASSWORD"
#define LINK_DRONE_ID      "drone-01"      // 16 bytes at most
