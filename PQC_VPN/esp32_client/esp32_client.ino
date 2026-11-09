#include <WiFi.h>          // Library to connect the ESP32 to your local Wi-Fi router
#define MLD_CONFIG_API_NO_SUPERCOP
#include <sodium.h>        // Libsodium cryptography library for SHA-256/HMAC-SHA256 & memzero
#include <MLDSA44.h>       // NIST FIPS 204 ML-DSA-44 post-quantum digital signatures
#include <MLKEM512.h>      // NIST FIPS 203 ML-KEM-512 post-quantum key encapsulation (mlkem-native)
#include "config.h"        // Wi-Fi credentials, server IP, port, and pinned 1,312B server key
#include "DeviceIdentity.h"// Device identity class (NVS flash storage and ML-DSA-44 key generation)
#include "AuthManager.h"   // Handshake manager class (ML-DSA-44 mutual auth + ML-KEM-512 key exchange)
#include "SecureTunnel.h"  // AES-256-GCM encrypted data tunnel keyed from K_session

// Dedicated 64 KB FreeRTOS stack size required for ML-DSA-44 NTT polynomial arithmetic (~34 KB peak);
// ML-KEM-512 KeyGen/Decaps run in the same task and need far less stack than ML-DSA-44 signing
#define VPN_TASK_STACK_SIZE 65536

// --- OOP Object Instances (allocated in .bss to keep task stack free) ---
WiFiClient     networkClient;  // Network client socket for TCP communication
DeviceIdentity identity(DEVICE_ID); // Manages this ESP32's unique ML-DSA-44 identity keys
AuthManager    auth(networkClient, identity, TRUSTED_GATEWAY_PUBLIC_KEY); // Manages PQC mutual auth + ML-KEM KEX
SecureTunnel   tunnel(networkClient); // AES-256-GCM encryption of all post-handshake traffic

// --- VPN Tunnel State Variables ---
unsigned long lastTunnelMessageTime = 0; // Tracks the last timestamp a ping message was sent
int           pingSequenceNumber    = 0; // Incremental counter for sent ping messages
bool          isVpnAuthenticated    = false; // Set to true only when mutual authentication succeeds

// --- Reconnect Backoff ---
// After a failure (gateway down, device not in allowlist, auth rejected) the wait before the
// next attempt doubles: 3s, 6s, 12s, 24s, 30s, 30s ... It resets to 3s after a successful handshake.
// A rejected device therefore stops hammering the gateway that other ESP32s depend on.
const unsigned long RECONNECT_DELAY_MIN_MS = 3000;
const unsigned long RECONNECT_DELAY_MAX_MS = 30000;
unsigned long       reconnectDelayMs       = RECONNECT_DELAY_MIN_MS;

// --- In-Tunnel Rekeying State (fresh ML-KEM-512 exchange inside the encrypted tunnel) ---
bool           rekeyPending   = false;                   // REKEY_REQ sent, waiting for REKEY_RESP
unsigned long  rekeyStartedMs = 0;
static uint8_t rekeyEk[MLKEM512::PUBLIC_KEY_SIZE];       // Ephemeral encapsulation key (sent in REKEY_REQ)
static uint8_t rekeyDk[MLKEM512::SECRET_KEY_SIZE];       // Matching decapsulation key (wiped after use)

void cancelRekey() {
  rekeyPending = false;
  sodium_memzero(rekeyDk, sizeof(rekeyDk));
}

// Sends REKEY_REQ = [4B new epoch (BE)] [800B fresh ML-KEM-512 encapsulation key]
bool startRekey() {
  const uint32_t next = tunnel.epoch() + 1;
  Serial.printf("\n[REKEY] %llu messages / %lu s with the current keys -> rekey to epoch %lu (fresh ML-KEM-512 keypair)\n",
                (unsigned long long)tunnel.framesSent(), tunnel.keyAgeMs() / 1000, (unsigned long)next);
  if (MLKEM512::generateKeypair(rekeyEk, rekeyDk) != 0) {
    Serial.println("[REKEY] ML-KEM-512 key generation failed.");
    cancelRekey();
    return false;
  }
  static uint8_t payload[4 + MLKEM512::PUBLIC_KEY_SIZE];
  payload[0] = (uint8_t)(next >> 24); payload[1] = (uint8_t)(next >> 16);
  payload[2] = (uint8_t)(next >> 8);  payload[3] = (uint8_t)next;
  memcpy(payload + 4, rekeyEk, MLKEM512::PUBLIC_KEY_SIZE);
  if (!tunnel.sendTyped(SecureTunnel::MSG_REKEY_REQ, payload, sizeof(payload))) {
    cancelRekey();
    return false;
  }
  rekeyPending = true;
  rekeyStartedMs = millis();
  return true;
}

// Handles REKEY_RESP = [4B epoch (BE)] [768B ML-KEM-512 ciphertext]
bool finishRekey(const uint8_t* payload, size_t len) {
  if (!rekeyPending || len != 4 + MLKEM512::CIPHERTEXT_SIZE) {
    Serial.println("[REKEY] Unexpected REKEY_RESP.");
    cancelRekey();
    return false;
  }
  const uint32_t epoch = ((uint32_t)payload[0] << 24) | ((uint32_t)payload[1] << 16) |
                         ((uint32_t)payload[2] << 8) | payload[3];
  if (epoch != tunnel.epoch() + 1) {
    Serial.printf("[REKEY] Wrong epoch in REKEY_RESP (%lu).\n", (unsigned long)epoch);
    cancelRekey();
    return false;
  }
  uint8_t ss[MLKEM512::SHARED_SECRET_SIZE];
  bool ok = MLKEM512::decapsulate(ss, payload + 4, rekeyDk) == 0 && tunnel.rekey(ss, epoch);
  sodium_memzero(ss, sizeof(ss));
  cancelRekey();
  return ok;
}


// --- Connects to the laptop server over TCP and runs the PQC handshake. Returns true on success ---
bool connectToGatewayServer() {
  Serial.println("\n----------------------------------------");
  Serial.printf("Device ID         : %s\n", identity.getDeviceId());
  Serial.print ("Device Public Key : ");
  identity.printPublicKeyHex();
  Serial.println("----------------------------------------");
  Serial.printf("[TCP] Connecting to %s:%d ...\n", GATEWAY_IP, GATEWAY_PORT);
  networkClient.stop(); // Release any half-open socket left over from a previous session

  if (networkClient.connect(GATEWAY_IP, GATEWAY_PORT)) {
    networkClient.setNoDelay(true); // Disable TCP Nagle buffering for low-latency handshakes
    Serial.println("[TCP] Connected.");

    if (auth.performMutualAuthentication() && tunnel.begin(auth.getSessionKey())) {
      isVpnAuthenticated = true;
      lastTunnelMessageTime = millis(); // First ping 1.5s after the tunnel opens
      Serial.println("[TUNNEL ACTIVE] AES-256-GCM encrypted channel ready.\n");
      return true;
    }
    Serial.println("[AUTH] Handshake failed. Closing connection.");
    networkClient.stop();
    isVpnAuthenticated = false;
    return false;
  }
  Serial.println("[TCP] Connection failed.");
  return false;
}


// --- Dedicated 64 KB FreeRTOS Task for Post-Quantum VPN Handshake & Tunnel ---
void vpnClientTask(void* pvParameters) {
  (void)pvParameters;

  Serial.println("\n================================================================");
  Serial.println("    Post-Quantum VPN (ML-DSA-44 + ML-KEM-512 + AES-256-GCM)");
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

  if (!connectToGatewayServer()) {
    Serial.printf("[RETRY] Next attempt in %lu s.\n", reconnectDelayMs / 1000);
  }

  // Continuous VPN tunnel loop inside the 64 KB task
  for (;;) {
    // Wi-Fi dropped: wait for the (automatic) reconnect before trying TCP again
    if (WiFi.status() != WL_CONNECTED) {
      if (isVpnAuthenticated) {
        Serial.println("[WIFI] Wi-Fi connection lost. Waiting for it to come back...");
        networkClient.stop();
        tunnel.end();
        cancelRekey();
        isVpnAuthenticated = false;
        reconnectDelayMs = RECONNECT_DELAY_MIN_MS;
      }
      vTaskDelay(pdMS_TO_TICKS(500));
      continue;
    }

    if (!networkClient.connected() || !isVpnAuthenticated) {
      if (isVpnAuthenticated) {
        Serial.println("[TUNNEL] Connection to gateway lost (closed, revoked, or replaced).");
        reconnectDelayMs = RECONNECT_DELAY_MIN_MS; // Was working: retry quickly first
      }
      isVpnAuthenticated = false;
      tunnel.end();
      cancelRekey();
      vTaskDelay(pdMS_TO_TICKS(reconnectDelayMs)); // Back off before retrying
      if (connectToGatewayServer()) {
        reconnectDelayMs = RECONNECT_DELAY_MIN_MS;                                // Success: reset backoff
      } else {
        reconnectDelayMs = min(reconnectDelayMs * 2, RECONNECT_DELAY_MAX_MS);     // Failure: back off more
        Serial.printf("[RETRY] Next attempt in %lu s.\n", reconnectDelayMs / 1000);
      }
      continue;
    }

    // --- Rekey policy: fresh keys after REKEY_AFTER_MESSAGES messages or REKEY_AFTER_MS ---
    if (rekeyPending && millis() - rekeyStartedMs > REKEY_RESPONSE_TIMEOUT_MS) {
      Serial.println("[REKEY] Gateway did not answer the rekey in time. Closing connection.");
      cancelRekey();
      networkClient.stop();
      isVpnAuthenticated = false;
      continue;
    }
    if (!rekeyPending && (tunnel.framesSent() >= REKEY_AFTER_MESSAGES || tunnel.keyAgeMs() >= REKEY_AFTER_MS)) {
      if (!startRekey()) {
        Serial.println("[REKEY] Could not start rekey. Closing connection.");
        networkClient.stop();
        isVpnAuthenticated = false;
        continue;
      }
    }

    // Pings pause while a rekey is in progress, so no message is ever sent with keys about to change
    if (!rekeyPending && millis() - lastTunnelMessageTime >= 1500) {
      lastTunnelMessageTime = millis();
      pingSequenceNumber++;

      String pingPayload = "[" + String(DEVICE_ID) + "] STATUS_PING #" + String(pingSequenceNumber);
      if (!tunnel.send((const uint8_t*)pingPayload.c_str(), pingPayload.length())) {
        Serial.println("[TUNNEL] Send failed. Closing connection.");
        networkClient.stop();
        isVpnAuthenticated = false;
        continue;
      }
    }

    static uint8_t rxPlain[SecureTunnel::MAX_PLAINTEXT];
    int n;
    while ((n = tunnel.poll(rxPlain, sizeof(rxPlain))) > 0) {
      // DATA replies are already printed by SecureTunnel::poll; REKEY_RESP switches the keys
      if (tunnel.lastType() == SecureTunnel::MSG_REKEY_RESP && !finishRekey(rxPlain, n)) {
        n = -1;
        break;
      }
    }
    if (n < 0) {
      Serial.println("[TUNNEL] Integrity/replay check failed. Closing connection.");
      networkClient.stop();
      isVpnAuthenticated = false;
      continue;
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

