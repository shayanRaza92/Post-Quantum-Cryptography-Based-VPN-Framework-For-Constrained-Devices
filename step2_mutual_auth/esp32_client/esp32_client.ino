#include <WiFi.h>
#include "mbedtls/md.h"

// Wi-Fi and Laptop settings
const char* WIFI_SSID     = "YOUR_WIFI_NAME";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";
const char* LAPTOP_IP     = "10.27.228.216"; // Set to your laptop IP
const uint16_t PORT       = 9000;

// Pre-Shared Key (must match server.py)
const char* PSK = "vpn_secret_key_123";

WiFiClient client;
unsigned long lastSendTime = 0;
int counter = 0;
bool isAuthenticated = false;

// Compute HMAC-SHA256
void compute_hmac(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, uint8_t* out) {
  const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_hmac(md_info, key, key_len, data, data_len, out);
}

// Read exact number of bytes with a timeout
bool read_exact(uint8_t* buffer, size_t len, unsigned long timeout_ms = 5000) {
  size_t bytes_read = 0;
  unsigned long start = millis();
  while (bytes_read < len && (millis() - start < timeout_ms)) {
    while (client.available() && bytes_read < len) {
      buffer[bytes_read++] = client.read();
    }
    delay(5);
  }
  return (bytes_read == len);
}

// Perform mutual challenge-response authentication
bool perform_mutual_auth() {
  Serial.println("Starting Mutual Authentication...");

  // Step 1: Receive 16-byte challenge from laptop
  uint8_t laptop_challenge[16];
  if (!read_exact(laptop_challenge, 16)) {
    Serial.println("Failed to receive challenge from laptop.");
    return false;
  }
  Serial.println("Received challenge from laptop.");

  // Step 2: Compute HMAC response to laptop's challenge
  uint8_t esp32_hmac[32];
  compute_hmac((const uint8_t*)PSK, strlen(PSK), laptop_challenge, 16, esp32_hmac);

  // Generate ESP32's own 16-byte random challenge
  uint8_t esp32_challenge[16];
  esp_fill_random(esp32_challenge, 16);

  // Send HMAC (32 bytes) + ESP32 challenge (16 bytes) = 48 bytes total
  client.write(esp32_hmac, 32);
  client.write(esp32_challenge, 16);
  client.flush();
  Serial.println("Sent HMAC proof and own challenge to laptop.");

  // Step 3: Receive 32-byte HMAC response from laptop
  uint8_t laptop_hmac[32];
  if (!read_exact(laptop_hmac, 32)) {
    Serial.println("Failed to receive HMAC proof from laptop.");
    return false;
  }

  // Verify laptop's HMAC response
  uint8_t expected_laptop_hmac[32];
  compute_hmac((const uint8_t*)PSK, strlen(PSK), esp32_challenge, 16, expected_laptop_hmac);

  if (memcmp(laptop_hmac, expected_laptop_hmac, 32) != 0) {
    Serial.println("FAILED: Laptop HMAC invalid! Untrusted server.");
    return false;
  }

  Serial.println(">>> Mutual Authentication Succeeded! <<<\n");
  return true;
}

void connectToServer() {
  Serial.print("Connecting to laptop on port ");
  Serial.println(PORT);

  if (client.connect(LAPTOP_IP, PORT)) {
    Serial.println("TCP Connected.");
    
    // Perform authentication handshake
    if (perform_mutual_auth()) {
      isAuthenticated = true;
    } else {
      Serial.println("Authentication failed. Closing connection.");
      client.stop();
      isAuthenticated = false;
    }
  } else {
    Serial.println("Connection failed, retrying in 2 seconds...");
  }
}

void setup() {
  Serial.begin(115200);
  delay(500);

  Serial.print("Connecting to Wi-Fi");
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWi-Fi connected!");
  Serial.print("ESP32 IP: ");
  Serial.println(WiFi.localIP());

  connectToServer();
}

void loop() {
  // If disconnected, try to reconnect
  if (!client.connected() || !isAuthenticated) {
    isAuthenticated = false;
    delay(2000);
    connectToServer();
    return;
  }

  // Send message every 1 second once authenticated
  if (millis() - lastSendTime >= 1000) {
    lastSendTime = millis();
    counter++;

    String msg = "PING #" + String(counter) + "\n";
    client.print(msg);
    Serial.print("[Send]: PING #" + String(counter));
  }

  // Read response from laptop
  while (client.available()) {
    String reply = client.readStringUntil('\n');
    Serial.print("  [Reply]: ");
    Serial.println(reply);
  }
}
