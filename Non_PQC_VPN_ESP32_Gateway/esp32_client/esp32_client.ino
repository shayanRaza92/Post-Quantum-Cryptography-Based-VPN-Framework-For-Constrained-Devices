#include <WiFi.h>          // Library to connect the ESP32 to your local Wi-Fi router
#include <sodium.h>        // Libsodium cryptography library for Ed25519
#include "config.h"        // Wi-Fi credentials, server IP, port, and pinned server key
#include "DeviceIdentity.h"// Device identity class (NVS flash storage and key generation)
#include "AuthManager.h"   // Handshake manager class (allowlist check and mutual authentication)
#include "SecureTunnel.h"  // AES-256-GCM encrypted data tunnel keyed from K_session

// --- OOP Object Instances ---
WiFiClient     networkClient;  // Network client socket for TCP communication
DeviceIdentity identity(DEVICE_ID); // Manages this ESP32's unique identity keys
AuthManager    auth(networkClient, identity, TRUSTED_GATEWAY_PUBLIC_KEY); // Manages mutual authentication
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

// --- In-Tunnel Rekeying State (fresh X25519 exchange inside the encrypted tunnel) ---
bool          rekeyPending   = false;   // REKEY_REQ sent, waiting for REKEY_RESP
unsigned long rekeyStartedMs = 0;
uint8_t       rekeySk[32];              // Ephemeral X25519 private key for this rekey (wiped after use)
uint8_t       rekeyPk[32];              // Matching public key (sent in REKEY_REQ)

void cancelRekey() {
  rekeyPending = false;
  sodium_memzero(rekeySk, sizeof(rekeySk));
}

// Sends REKEY_REQ = [4B new epoch (BE)] [32B fresh X25519 public key]
bool startRekey() {
  const uint32_t next = tunnel.epoch() + 1;
  Serial.printf("\n[REKEY] %llu messages / %lu s with the current keys -> rekey to epoch %lu (fresh X25519 keypair)\n",
                (unsigned long long)tunnel.framesSent(), tunnel.keyAgeMs() / 1000, (unsigned long)next);
  randombytes_buf(rekeySk, sizeof(rekeySk));
  crypto_scalarmult_base(rekeyPk, rekeySk);
  uint8_t payload[4 + 32];
  payload[0] = (uint8_t)(next >> 24); payload[1] = (uint8_t)(next >> 16);
  payload[2] = (uint8_t)(next >> 8);  payload[3] = (uint8_t)next;
  memcpy(payload + 4, rekeyPk, 32);
  if (!tunnel.sendTyped(SecureTunnel::MSG_REKEY_REQ, payload, sizeof(payload))) {
    cancelRekey();
    return false;
  }
  rekeyPending = true;
  rekeyStartedMs = millis();
  return true;
}

// Handles REKEY_RESP = [4B epoch (BE)] [32B gateway X25519 public key]
bool finishRekey(const uint8_t* payload, size_t len) {
  if (!rekeyPending || len != 4 + 32) {
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
  uint8_t ss[32];
  // crypto_scalarmult() returns -1 for a low-order (all-zero) result
  bool ok = crypto_scalarmult(ss, rekeySk, payload + 4) == 0 && tunnel.rekey(ss, epoch);
  sodium_memzero(ss, sizeof(ss));
  cancelRekey();
  return ok;
}


// --- Connects to the ESP32 gateway over TCP and runs the handshake. Returns true on success ---
bool connectToGatewayServer() {
  Serial.println("\n----------------------------------------");
  Serial.printf("Device ID         : %s\n", identity.getDeviceId());
  Serial.print ("Device Public Key : ");
  identity.printPublicKeyHex();
  Serial.println("----------------------------------------");
  Serial.printf("[TCP] Connecting to %s:%d ...\n", GATEWAY_IP, GATEWAY_PORT);
  networkClient.stop(); // Release any half-open socket left over from a previous session

  if (networkClient.connect(GATEWAY_IP, GATEWAY_PORT)) { // Try opening TCP socket to the ESP32 gateway
    networkClient.setNoDelay(true);                      // Disable TCP Nagle buffering for low-latency handshakes
    Serial.println("[TCP] Connected.");

    // Run the handshake, then key the AES-256-GCM tunnel from the derived K_session
    if (auth.performMutualAuthentication() && tunnel.begin(auth.getSessionKey())) {
      isVpnAuthenticated = true;              // Mark session as authenticated
      lastTunnelMessageTime = millis();       // First ping 1.5s after the tunnel opens
      Serial.println("[TUNNEL ACTIVE] AES-256-GCM encrypted channel ready.\n");
      return true;
    }
    Serial.println("[AUTH] Handshake failed. Closing connection.");
    networkClient.stop();                     // Disconnect if authentication failed
    isVpnAuthenticated = false;
    return false;
  }
  Serial.println("[TCP] Connection failed.");
  return false;
}


// --- Runs once when the ESP32 turns on ---
void setup() {
  Serial.begin(115200); // Start serial communication at 115200 baud rate for debug printing
  delay(1000);          // Wait 1 second for serial monitor to open

  Serial.println("\n================================================================");
  Serial.println("                         Classical VPN");
  Serial.println("================================================================");

  if (sodium_init() < 0) { // Start up the Libsodium cryptographic engine
    Serial.println("[ERROR] Failed to initialize libsodium!");
    while (true) delay(1000); // Halt here if crypto library fails to initialize
  }

  Serial.print("[WIFI] Connecting to ");
  Serial.println(WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD); // Start connecting to Wi-Fi network

  while (WiFi.status() != WL_CONNECTED) { // Keep waiting until Wi-Fi is connected
    delay(500);                           // Wait half a second
    Serial.print(".");                    // Print dot to show connection progress
  }

  Serial.println("\n[WIFI] Connected.");
  Serial.print  ("ESP32 IP : ");
  Serial.println(WiFi.localIP()); // Print the IP address assigned by your Wi-Fi router

  // Disable Wi-Fi modem sleep to eliminate radio power-save latency jitter
  WiFi.setSleep(false);

  // Initialize identity AFTER Wi-Fi is active.
  // Per Espressif TRM, the ESP32 hardware TRNG requires active RF circuitry for true cryptographic entropy.
  identity.begin();

  if (!connectToGatewayServer()) { // Connect to the ESP32 gateway and execute mutual authentication
    Serial.printf("[RETRY] Next attempt in %lu s.\n", reconnectDelayMs / 1000);
  }
}


// --- Runs continuously in a loop ---
void loop() {
  // The gateway is an ESP32 access point: if it reboots, its Wi-Fi disappears for a moment.
  // Wait for the (automatic) Wi-Fi reconnect before trying TCP again.
  if (WiFi.status() != WL_CONNECTED) {
    if (isVpnAuthenticated) {
      Serial.println("[WIFI] Lost connection to the gateway's Wi-Fi. Waiting for it to come back...");
      networkClient.stop();
      tunnel.end();
      cancelRekey();
      isVpnAuthenticated = false;
      reconnectDelayMs = RECONNECT_DELAY_MIN_MS;
    }
    delay(500);
    return;
  }

  // If connection dropped or authentication was lost, try to reconnect
  if (!networkClient.connected() || !isVpnAuthenticated) {
    if (isVpnAuthenticated) {
      Serial.println("[TUNNEL] Connection to gateway lost (closed, revoked, or replaced).");
      reconnectDelayMs = RECONNECT_DELAY_MIN_MS; // Was working: retry quickly first
    }
    isVpnAuthenticated = false; // Mark as unauthenticated
    tunnel.end();               // Wipe the old session's tunnel keys and counters
    cancelRekey();
    delay(reconnectDelayMs);    // Back off before retrying
    if (connectToGatewayServer()) {
      reconnectDelayMs = RECONNECT_DELAY_MIN_MS;            // Success: reset backoff
    } else {
      reconnectDelayMs = min(reconnectDelayMs * 2, RECONNECT_DELAY_MAX_MS); // Failure: back off more
      Serial.printf("[RETRY] Next attempt in %lu s.\n", reconnectDelayMs / 1000);
    }
    return;                     // Restart loop
  }

  // --- Rekey policy: fresh keys after REKEY_AFTER_MESSAGES messages or REKEY_AFTER_MS ---
  if (rekeyPending && millis() - rekeyStartedMs > REKEY_RESPONSE_TIMEOUT_MS) {
    Serial.println("[REKEY] Gateway did not answer the rekey in time. Closing connection.");
    cancelRekey();
    networkClient.stop();
    isVpnAuthenticated = false;
    return;
  }
  if (!rekeyPending && (tunnel.framesSent() >= REKEY_AFTER_MESSAGES || tunnel.keyAgeMs() >= REKEY_AFTER_MS)) {
    if (!startRekey()) {
      Serial.println("[REKEY] Could not start rekey. Closing connection.");
      networkClient.stop();
      isVpnAuthenticated = false;
      return;
    }
  }

  // Send an encrypted heartbeat ping every 1.5 seconds (paused while a rekey is in progress)
  if (!rekeyPending && millis() - lastTunnelMessageTime >= 1500) {
    lastTunnelMessageTime = millis(); // Record the current timestamp
    pingSequenceNumber++;             // Increment the ping sequence number

    String pingPayload = "[" + String(DEVICE_ID) + "] STATUS_PING #" + String(pingSequenceNumber);
    if (!tunnel.send((const uint8_t*)pingPayload.c_str(), pingPayload.length())) {  // Encrypt + send
      Serial.println("[TUNNEL] Send failed. Closing connection.");
      networkClient.stop();
      isVpnAuthenticated = false;
      return;
    }
  }

  // Receive, verify and decrypt the gateway's encrypted acknowledgements
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
  }
}
