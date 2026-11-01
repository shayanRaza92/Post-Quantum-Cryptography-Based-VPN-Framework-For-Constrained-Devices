#include <WiFi.h>          // Library to connect the ESP32 to your local Wi-Fi router
#define MLD_CONFIG_API_NO_SUPERCOP
#include <sodium.h>        // Libsodium cryptography library for X25519 & SHA-256/HMAC-SHA256
#include <MLDSA44.h>       // NIST FIPS 204 ML-DSA-44 post-quantum digital signatures
#include "config.h"        // Wi-Fi credentials, server IP, port, and pinned 1,312B server key
#include "DeviceIdentity.h"// Device identity class (NVS flash storage and ML-DSA-44 key generation)
#include "AuthManager.h"   // Handshake manager class (allowlist check and ML-DSA-44 mutual authentication)

// Dedicated 64 KB FreeRTOS stack size required for ML-DSA-44 NTT polynomial arithmetic (~34 KB peak)
#define VPN_TASK_STACK_SIZE 65536

// --- OOP Object Instances (allocated in .bss to keep task stack free) ---
WiFiClient     networkClient;  // Network client socket for TCP communication
DeviceIdentity identity(DEVICE_ID); // Manages this ESP32's unique ML-DSA-44 identity keys
AuthManager    auth(networkClient, identity, TRUSTED_GATEWAY_PUBLIC_KEY); // Manages PQC mutual authentication

// --- VPN Tunnel State Variables ---
unsigned long lastTunnelMessageTime = 0; // Tracks the last timestamp a ping message was sent
int           pingSequenceNumber    = 0; // Incremental counter for sent ping messages
bool          isVpnAuthenticated    = false; // Set to true only when mutual authentication succeeds


// --- Connects to the laptop server over TCP and runs the PQC handshake ---
void connectToGatewayServer() {
  Serial.println("\n----------------------------------------");
  Serial.printf("Device ID         : %s\n", identity.getDeviceId());
  Serial.print ("Device Public Key : ");
  identity.printPublicKeyHex();
  Serial.println("----------------------------------------");
  Serial.printf("[TCP] Connecting to %s:%d ...\n", GATEWAY_IP, GATEWAY_PORT);

  if (networkClient.connect(GATEWAY_IP, GATEWAY_PORT)) {
    networkClient.setNoDelay(true); // Disable TCP Nagle buffering for low-latency handshakes
    Serial.println("[TCP] Connected.");

    if (auth.performMutualAuthentication()) {
      isVpnAuthenticated = true;
      Serial.println("[TUNNEL ACTIVE] Ready for data transmission.\n");
    } else {
      Serial.println("[AUTH] Handshake failed. Closing connection.");
      networkClient.stop();
      isVpnAuthenticated = false;
    }
  } else {
    Serial.println("[TCP] Connection failed. Retrying in 3 seconds...");
  }
}


// --- Dedicated 64 KB FreeRTOS Task for Post-Quantum VPN Handshake & Tunnel ---
void vpnClientTask(void* pvParameters) {
  (void)pvParameters;

  Serial.println("\n================================================================");
  Serial.println("            Post-Quantum VPN (ML-DSA-44 + X25519)");
  Serial.println("================================================================");

  if (sodium_init() < 0) {
    Serial.println("[ERROR] Failed to initialize libsodium!");
    vTaskDelete(NULL);
    return;
  }

  Serial.print("[WIFI] Connecting to ");
  Serial.println(WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  while (WiFi.status() != WL_CONNECTED) {
    vTaskDelay(pdMS_TO_TICKS(500));
    Serial.print(".");
  }

  Serial.println("\n[WIFI] Connected.");
  Serial.print  ("ESP32 IP : ");
  Serial.println(WiFi.localIP());

  // Disable Wi-Fi modem sleep to eliminate radio power-save latency jitter
  WiFi.setSleep(false);

  // Initialize ML-DSA-44 identity AFTER Wi-Fi is active so hardware TRNG has full RF entropy
  if (!identity.begin()) {
    Serial.println("[ERROR] Failed to initialize ML-DSA-44 DeviceIdentity!");
    vTaskDelete(NULL);
    return;
  }

  connectToGatewayServer();

  // Continuous VPN tunnel loop inside the 64 KB task
  for (;;) {
    if (!networkClient.connected() || !isVpnAuthenticated) {
      isVpnAuthenticated = false;
      vTaskDelay(pdMS_TO_TICKS(3000));
      connectToGatewayServer();
      continue;
    }

    if (millis() - lastTunnelMessageTime >= 1500) {
      lastTunnelMessageTime = millis();
      pingSequenceNumber++;

      String pingPayload = "[" + String(DEVICE_ID) + "] STATUS_PING #" + String(pingSequenceNumber) + "\n";
      networkClient.print(pingPayload);
      Serial.printf("[TX] %s", pingPayload.c_str());
    }

    while (networkClient.available()) {
      String incomingReply = networkClient.readStringUntil('\n');
      incomingReply.trim();
      if (incomingReply.length() > 0) {
        Serial.printf("[RX] %s\n", incomingReply.c_str());
      }
    }

    vTaskDelay(pdMS_TO_TICKS(10));
  }
}


// --- Runs once when the ESP32 turns on ---
void setup() {
  Serial.begin(115200);
  delay(1000);

  // Spawn dedicated 64 KB stack task on Core 1 (App CPU) for ML-DSA-44 PQC operations
  xTaskCreatePinnedToCore(
    vpnClientTask,
    "VPN_PQC_Task",
    VPN_TASK_STACK_SIZE,
    NULL,
    1,
    NULL,
    1
  );
}


// --- Default Arduino loopTask (8 KB stack) sleeps while VPN_PQC_Task (64 KB stack) handles all work ---
void loop() {
  vTaskDelay(portMAX_DELAY);
}

