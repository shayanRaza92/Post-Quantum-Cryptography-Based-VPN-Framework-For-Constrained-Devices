#include <WiFi.h>          // Library to connect the ESP32 to your local Wi-Fi router
#include <sodium.h>        // Libsodium cryptography library for Ed25519
#include "config.h"        // Wi-Fi credentials, server IP, port, and pinned server key
#include "DeviceIdentity.h"// Device identity class (NVS flash storage and key generation)
#include "AuthManager.h"   // Handshake manager class (allowlist check and mutual authentication)

// --- OOP Object Instances ---
WiFiClient     networkClient;  // Network client socket for TCP communication
DeviceIdentity identity(DEVICE_ID); // Manages this ESP32's unique identity keys
AuthManager    auth(networkClient, identity, TRUSTED_GATEWAY_PUBLIC_KEY); // Manages mutual authentication

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


// --- Connects to the laptop server over TCP and runs the handshake. Returns true on success ---
bool connectToGatewayServer() {
  Serial.println("\n----------------------------------------");
  Serial.printf("Device ID         : %s\n", identity.getDeviceId());
  Serial.print ("Device Public Key : ");
  identity.printPublicKeyHex();
  Serial.println("----------------------------------------");
  Serial.printf("[TCP] Connecting to %s:%d ...\n", GATEWAY_IP, GATEWAY_PORT);
  networkClient.stop(); // Release any half-open socket left over from a previous session

  if (networkClient.connect(GATEWAY_IP, GATEWAY_PORT)) { // Try opening TCP socket to laptop
    networkClient.setNoDelay(true);                      // Disable TCP Nagle buffering for low-latency handshakes
    Serial.println("[TCP] Connected.");

    if (auth.performMutualAuthentication()) { // Run the OOP security handshake
      isVpnAuthenticated = true;              // Mark session as authenticated
      lastTunnelMessageTime = millis();       // First ping 1.5s after the tunnel opens
      Serial.println("[TUNNEL ACTIVE] Ready for data transmission.\n");
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

  if (!connectToGatewayServer()) { // Connect to laptop server and execute mutual authentication
    Serial.printf("[RETRY] Next attempt in %lu s.\n", reconnectDelayMs / 1000);
  }
}


// --- Runs continuously in a loop ---
void loop() {
  // If connection dropped or authentication was lost, try to reconnect
  if (!networkClient.connected() || !isVpnAuthenticated) {
    if (isVpnAuthenticated) {
      Serial.println("[TUNNEL] Connection to gateway lost (closed, revoked, or replaced).");
      reconnectDelayMs = RECONNECT_DELAY_MIN_MS; // Was working: retry quickly first
    }
    isVpnAuthenticated = false; // Mark as unauthenticated
    delay(reconnectDelayMs);    // Back off before retrying
    if (connectToGatewayServer()) {
      reconnectDelayMs = RECONNECT_DELAY_MIN_MS;            // Success: reset backoff
    } else {
      reconnectDelayMs = min(reconnectDelayMs * 2, RECONNECT_DELAY_MAX_MS); // Failure: back off more
      Serial.printf("[RETRY] Next attempt in %lu s.\n", reconnectDelayMs / 1000);
    }
    return;                     // Restart loop
  }

  // Send a heartbeat ping message every 1.5 seconds (1500 milliseconds)
  if (millis() - lastTunnelMessageTime >= 1500) {
    lastTunnelMessageTime = millis(); // Record the current timestamp
    pingSequenceNumber++;             // Increment the ping sequence number

    // Build the status message string
    String pingPayload = "[" + String(DEVICE_ID) + "] STATUS_PING #" + String(pingSequenceNumber) + "\n";
    networkClient.print(pingPayload);              // Send the ping text over the TCP tunnel
    Serial.printf("[TX] %s", pingPayload.c_str()); // Print sent message to serial monitor
  }

  // Check if the laptop server sent back an acknowledgement reply
  while (networkClient.available()) {
    String incomingReply = networkClient.readStringUntil('\n'); // Read incoming reply until newline
    incomingReply.trim();                                      // Remove extra whitespace/newlines
    if (incomingReply.length() > 0) {
      Serial.printf("[RX] %s\n", incomingReply.c_str());       // Print received reply to serial monitor
    }
  }
}
