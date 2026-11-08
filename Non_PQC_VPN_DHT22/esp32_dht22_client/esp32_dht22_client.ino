#include <WiFi.h>           // Library to connect the ESP32 to your local Wi-Fi router
#include <sodium.h>         // Libsodium cryptography library (Ed25519, X25519, HMAC-SHA256)
#include <DHT.h>            // Adafruit "DHT sensor library" (install via Library Manager)
#include "config.h"         // Wi-Fi credentials, server IP, port, pinned server key, sensor pin
#include "DeviceIdentity.h" // Device identity class (NVS flash storage and key generation)
#include "AuthManager.h"    // Handshake manager class (allowlist check and mutual authentication)
#include "SecureChannel.h"  // Encrypted record layer keyed from K_session
#include "TunnelLog.h"      // Boxed Serial printouts of records and payloads

// --- OOP Object Instances ---
WiFiClient     networkClient;  // Network client socket for TCP communication
DeviceIdentity identity(DEVICE_ID); // Manages this ESP32's unique identity keys
AuthManager    auth(networkClient, identity, TRUSTED_GATEWAY_PUBLIC_KEY); // Manages mutual authentication
SecureChannel  channel(networkClient); // Encrypts sensor records with keys derived from K_session
DHT            dht(DHT_PIN, DHT22);    // DHT22 temperature / humidity sensor

// --- VPN Tunnel State Variables ---
unsigned long lastSensorSendTime = 0;     // Timestamp of the last reading sent
unsigned long readingNumber      = 0;     // Incremental counter for sent readings (across sessions)
bool          isVpnAuthenticated = false; // Set to true only when mutual authentication succeeds

// --- Reconnect Backoff ---
// After a failure (gateway down, device not in allowlist, auth rejected) the wait before the
// next attempt doubles: 3s, 6s, 12s, 24s, 30s, 30s ... It resets to 3s after a successful handshake.
const unsigned long RECONNECT_DELAY_MIN_MS = 3000;
const unsigned long RECONNECT_DELAY_MAX_MS = 30000;
unsigned long       reconnectDelayMs       = RECONNECT_DELAY_MIN_MS;


// --- Closes the tunnel and wipes the record-layer keys ---
void closeTunnel() {
  networkClient.stop();
  channel.reset();
  isVpnAuthenticated = false;
}


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
      if (!channel.begin(auth.getSessionKey())) { // Derive directional AES-256 keys from K_session
        Serial.println("[ERROR] Failed to load AES-256-GCM keys. Closing connection.");
        closeTunnel();
        return false;
      }
      isVpnAuthenticated = true;
      lastSensorSendTime = millis() - SENSOR_INTERVAL_MS; // Send the first reading right away
      Serial.println("[TUNNEL ACTIVE] Encrypted record layer ready (AES-256-GCM, keys from K_session).");
      Serial.println("[Client & Server] Deriving directional data keys from K_session...");
      TunnelLog::printDataKeys(channel.txKey(), channel.rxKey());
      Serial.printf ("[SENSOR] Sending DHT22 readings every %lu ms.\n", SENSOR_INTERVAL_MS);
      return true;
    }
    Serial.println("[AUTH] Handshake failed. Closing connection.");
    closeTunnel();
    return false;
  }
  Serial.println("[TCP] Connection failed.");
  return false;
}


// --- Reads the DHT22 and sends one encrypted JSON record through the tunnel ---
void sendTemperatureReading() {
  float humidity    = dht.readHumidity();
  float temperature = dht.readTemperature(); // Celsius
  unsigned long uptimeMs = millis();
  bool sensorOk = !(isnan(humidity) || isnan(temperature));
  float heatIndex = sensorOk ? dht.computeHeatIndex(temperature, humidity, false) : NAN;
  readingNumber++;

  char payload[MAX_RECORD_PLAINTEXT];
  if (sensorOk) {
    snprintf(payload, sizeof(payload),
             "{\"reading\":%lu,\"uptime_ms\":%lu,\"temperature_c\":%.2f,\"humidity_pct\":%.2f,\"heat_index_c\":%.2f}",
             readingNumber, uptimeMs, temperature, humidity, heatIndex);
  } else {
    // Still send a record so the server knows the device is alive but the sensor is failing
    snprintf(payload, sizeof(payload),
             "{\"reading\":%lu,\"uptime_ms\":%lu,\"error\":\"dht22_read_failed\"}",
             readingNumber, uptimeMs);
  }
  size_t plainLen = strlen(payload);

  // Encrypt and send first, then print (printing ~4 KB over Serial takes a few hundred ms)
  uint8_t wire[SecureChannel::MAX_RECORD_WIRE];
  size_t  wireLen = 0;
  bool sent = channel.send((const uint8_t*)payload, plainLen, wire, &wireLen);

  // 1. Sensor reading table
  Serial.printf("\n[SENSOR] Reading DHT22 on GPIO %u (reading #%lu)...\n", DHT_PIN, readingNumber);
  TunnelLog::fieldTableHeader("DHT22 SENSOR READING");
  TunnelLog::field("Device ID", "%s", DEVICE_ID);
  TunnelLog::field("Reading Number", "#%lu", readingNumber);
  TunnelLog::field("Device Uptime", "%.3f s", uptimeMs / 1000.0);
  if (sensorOk) {
    TunnelLog::field("Temperature", "%.2f C", temperature);
    TunnelLog::field("Relative Humidity", "%.2f %%RH", humidity);
    TunnelLog::field("Heat Index", "%.2f C", heatIndex);
    TunnelLog::field("Sensor Status", "OK");
  } else {
    TunnelLog::field("Temperature", "--");
    TunnelLog::field("Relative Humidity", "--");
    TunnelLog::field("Heat Index", "--");
    TunnelLog::field("Sensor Status", "READ FAILED (check wiring / pull-up)");
  }
  TunnelLog::bar();

  if (!sent) {
    Serial.println("[ERROR] Failed to send encrypted record. Closing tunnel.");
    closeTunnel();
    return;
  }

  // 2. Plaintext payload
  Serial.println("\n[Client] Building JSON payload and encrypting with AES-256-GCM (K_c2s)...");
  TunnelLog::bar();
  TunnelLog::printPayload("PLAINTEXT PAYLOAD (JSON)", payload, plainLen);

  // 3. Encrypted wire record
  Serial.println("\n[Client -> Server] Sending encrypted sensor record...");
  TunnelLog::printRecord("ENCRYPTED SENSOR RECORD", wire, wireLen, "K_c2s");
}


// --- Runs once when the ESP32 turns on ---
void setup() {
  Serial.begin(115200); // Start serial communication at 115200 baud rate for debug printing
  delay(1000);          // Wait 1 second for serial monitor to open

  Serial.println("\n================================================================");
  Serial.println("              Classical VPN - DHT22 Temperature Sensor");
  Serial.println("================================================================");

  if (sodium_init() < 0) { // Start up the Libsodium cryptographic engine
    Serial.println("[ERROR] Failed to initialize libsodium!");
    while (true) delay(1000); // Halt here if crypto library fails to initialize
  }

  dht.begin();
  Serial.printf("[SENSOR] DHT22 initialised on GPIO %u.\n", DHT_PIN);

  Serial.print("[WIFI] Connecting to ");
  Serial.println(WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD); // Start connecting to Wi-Fi network

  while (WiFi.status() != WL_CONNECTED) { // Keep waiting until Wi-Fi is connected
    delay(500);
    Serial.print(".");
  }

  Serial.println("\n[WIFI] Connected.");
  Serial.print  ("ESP32 IP : ");
  Serial.println(WiFi.localIP());

  // Disable Wi-Fi modem sleep to eliminate radio power-save latency jitter
  WiFi.setSleep(false);

  // Initialize identity AFTER Wi-Fi is active.
  // Per Espressif TRM, the ESP32 hardware TRNG requires active RF circuitry for true cryptographic entropy.
  identity.begin();

  if (!connectToGatewayServer()) {
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
    closeTunnel();
    delay(reconnectDelayMs);
    if (connectToGatewayServer()) {
      reconnectDelayMs = RECONNECT_DELAY_MIN_MS;
    } else {
      reconnectDelayMs = min(reconnectDelayMs * 2, RECONNECT_DELAY_MAX_MS);
      Serial.printf("[RETRY] Next attempt in %lu s.\n", reconnectDelayMs / 1000);
    }
    return;
  }

  // Send a sensor reading every SENSOR_INTERVAL_MS
  if (millis() - lastSensorSendTime >= SENSOR_INTERVAL_MS) {
    lastSensorSendTime = millis();
    sendTemperatureReading();
    if (!isVpnAuthenticated) return;
  }

  // Receive and decrypt acknowledgements from the server
  uint8_t reply[MAX_RECORD_PLAINTEXT + 1];
  size_t  replyLen = 0;
  int     result;
  while ((result = channel.poll(reply, sizeof(reply), &replyLen)) == 1) {
    Serial.println("\n[Server -> Client] Received encrypted ACK record...");
    TunnelLog::printRecord("ENCRYPTED ACK RECORD", channel.lastRxRecord(), channel.lastRxRecordLen(), "K_s2c");
    Serial.println("\n[Client] Verifying GCM tag and decrypting ACK with AES-256-GCM (K_s2c)...");
    TunnelLog::bar();
    TunnelLog::row("Result : PASS -> Tag valid, sequence number in order. Payload authentic.");
    TunnelLog::bar();
    TunnelLog::printPayload("DECRYPTED ACK PAYLOAD (JSON)", (const char*)reply, replyLen);
  }
  if (result < 0) {
    Serial.println("[TUNNEL] Received record failed authentication or sequence check. Closing tunnel.");
    closeTunnel();
  }
}
