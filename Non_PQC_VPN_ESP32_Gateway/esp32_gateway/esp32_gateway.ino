#include <WiFi.h>              // ESP32 Wi-Fi (used here in Access Point mode)
#include <sodium.h>            // libsodium (bundled with the ESP32 Arduino core)
#include "gateway_config.h"    // Access point, allowlist, identity seed, limits
#include "Log.h"               // Thread-safe Serial logging
#include "VpnGateway.h"        // Accept loop + per-client session tasks

// ============================================================================
// ESP32 VPN GATEWAY (Classical: Ed25519 + X25519 + HKDF-SHA256)
// Replaces the laptop gateway. This board:
//   1. Creates its own Wi-Fi network (SoftAP) -> clients join it, no router needed.
//   2. Listens on TCP port 9000 at 192.168.4.1.
//   3. Authenticates every ESP32 client in its own task (one bad client never
//      affects the others) and keeps one tunnel per device.
// Type 'help' in the Serial Monitor (115200 baud, "Newline") for commands.
// ============================================================================

VpnGateway gateway;

static void printHex(const uint8_t* data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (data[i] < 0x10) Serial.print("0");
    Serial.print(data[i], HEX);
  }
  Serial.println();
}

// Wi-Fi events: shows when a client board joins / leaves the gateway network
static void onWiFiEvent(arduino_event_id_t event, arduino_event_info_t info) {
  if (event == ARDUINO_EVENT_WIFI_AP_STACONNECTED) {
    const uint8_t* m = info.wifi_ap_staconnected.mac;
    logLine("[WIFI] Station joined   (MAC %02X:%02X:%02X:%02X:%02X:%02X)", m[0], m[1], m[2], m[3], m[4], m[5]);
  } else if (event == ARDUINO_EVENT_WIFI_AP_STADISCONNECTED) {
    const uint8_t* m = info.wifi_ap_stadisconnected.mac;
    logLine("[WIFI] Station left     (MAC %02X:%02X:%02X:%02X:%02X:%02X)", m[0], m[1], m[2], m[3], m[4], m[5]);
  } else if (event == ARDUINO_EVENT_WIFI_AP_STAIPASSIGNED) {
    logLine("[WIFI] Station got IP   %s", IPAddress(info.wifi_ap_staipassigned.ip.addr).toString().c_str());
  }
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  logInit();

  Serial.println("\n================================================================");
  Serial.println("                  Classical VPN - ESP32 Gateway");
  Serial.println("================================================================");

  if (sodium_init() < 0) {
    Serial.println("[ERROR] Failed to initialize libsodium!");
    while (true) delay(1000);
  }

  // Start the Wi-Fi Access Point (also powers the RF circuitry the hardware TRNG needs)
  WiFi.onEvent(onWiFiEvent);
  WiFi.mode(WIFI_AP);
  if (!WiFi.softAP(AP_SSID, AP_PASSWORD, AP_CHANNEL, 0, AP_MAX_STATIONS)) {
    Serial.println("[ERROR] Could not start the Wi-Fi Access Point!");
    while (true) delay(1000);
  }
  WiFi.setSleep(false);  // No modem power-save: lower, steadier latency

  if (!gateway.begin(GATEWAY_PORT)) {
    Serial.println("[ERROR] Gateway failed to start!");
    while (true) delay(1000);
  }

  Serial.printf("Wi-Fi SSID        : %s\n", AP_SSID);
  Serial.printf("Gateway IP        : %s\n", WiFi.softAPIP().toString().c_str());
  Serial.printf("Port              : %u\n", (unsigned)GATEWAY_PORT);
  Serial.print ("Gateway Public Key: ");
  printHex(gateway.crypto().publicKey(), 32);
  Serial.println("================================================================");
  gateway.allowlist().print();
  Serial.println("Type 'help' for commands.\n");
}

void loop() {
  // Serial Monitor commands (revoke / allow / kick / status ...)
  if (Serial.available()) {
    String line = Serial.readStringUntil('\n');
    gateway.handleCommand(line);
  }
  delay(20);
}
