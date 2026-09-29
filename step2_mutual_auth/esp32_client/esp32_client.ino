#include <WiFi.h>
#include "mbedtls/md.h"

// Wi-Fi and Server settings
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

// Compute HMAC-SHA256 using ESP32 hardware engine
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
  Serial.println("\n[MUTUAL AUTHENTICATION]");

  // Step 1: Receive 16-byte challenge from server
  uint8_t laptop_challenge[16];
  if (!read_exact(laptop_challenge, 16)) {
    Serial.println("[FAIL] Server challenge timed out");
    return false;
  }
  Serial.println("[MSG1] Server Challenge");
  Serial.println("       Length         : 16 bytes");
  Serial.println("       Status         : RECEIVED");

  // Step 2: Compute HMAC proof and generate ESP32 challenge
  uint8_t esp32_hmac[32];
  compute_hmac((const uint8_t*)PSK, strlen(PSK), laptop_challenge, 16, esp32_hmac);

  uint8_t esp32_challenge[16];
  esp_fill_random(esp32_challenge, 16);

  // Send HMAC (32 bytes) + ESP32 challenge (16 bytes) = 48 bytes
  client.write(esp32_hmac, 32);
  client.write(esp32_challenge, 16);
  client.flush();

  Serial.println("\n[MSG2] ESP32 Authentication Proof");
  Serial.println("       Algorithm      : HMAC-SHA256");
  Serial.println("       Proof Length   : 32 bytes");
  Serial.println("       Challenge      : 16 bytes");
  Serial.println("       Status         : SENT");

  // Step 3: Receive 32-byte HMAC proof from server
  uint8_t laptop_hmac[32];
  if (!read_exact(laptop_hmac, 32)) {
    Serial.println("[FAIL] Server proof timed out");
    return false;
  }

  Serial.println("\n[MSG3] Server Authentication Proof");
  Serial.println("       Algorithm      : HMAC-SHA256");
  Serial.println("       Proof Length   : 32 bytes");
  Serial.println("       Status         : RECEIVED");

  // Verify server HMAC proof
  uint8_t expected_laptop_hmac[32];
  compute_hmac((const uint8_t*)PSK, strlen(PSK), esp32_challenge, 16, expected_laptop_hmac);

  if (memcmp(laptop_hmac, expected_laptop_hmac, 32) != 0) {
    Serial.println("\n[VERIFY] Server Authentication");
    Serial.println("         Result       : FAILED (Untrusted Server)");
    return false;
  }

  Serial.println("\n[VERIFY] Server Authentication");
  Serial.println("         Result       : SUCCESS");

  Serial.println("\n============================================================");
  Serial.println("        MUTUAL AUTHENTICATION SUCCESSFUL");
  Serial.println("============================================================\n");
  Serial.println("[DATA TUNNEL]");
  return true;
}

void connectToServer() {
  Serial.println("\n[TCP TRANSPORT]");
  Serial.print("Connecting to server ");
  Serial.print(LAPTOP_IP);
  Serial.print(":");
  Serial.print(PORT);
  Serial.println("...");

  if (client.connect(LAPTOP_IP, PORT)) {
    Serial.println("[OK] TCP connection established");

    if (perform_mutual_auth()) {
      isAuthenticated = true;
    } else {
      Serial.println("[ERROR] Authentication failed. Disconnecting.");
      client.stop();
      isAuthenticated = false;
    }
  } else {
    Serial.println("[FAIL] Connection failed. Retrying in 2 seconds...");
  }
}

void setup() {
  Serial.begin(115200);
  delay(500);

  Serial.println("\n============================================================");
  Serial.println("              PQC VPN - ESP32 CLIENT");
  Serial.println("============================================================");

  Serial.println("\n[NETWORK]");
  Serial.print("Connecting to Wi-Fi");
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("\n[OK] Wi-Fi connected");
  Serial.print("     ESP32 IP       : ");
  Serial.println(WiFi.localIP());
  Serial.print("     Server IP      : ");
  Serial.println(LAPTOP_IP);
  Serial.print("     Server Port    : ");
  Serial.println(PORT);

  connectToServer();
}

void loop() {
  if (!client.connected() || !isAuthenticated) {
    isAuthenticated = false;
    delay(2000);
    connectToServer();
    return;
  }

  // Send message every 1.5 seconds once authenticated
  if (millis() - lastSendTime >= 1500) {
    lastSendTime = millis();
    counter++;

    String msg = "PING #" + String(counter) + "\n";
    client.print(msg);
    Serial.print("[TX] PING #");
    Serial.println(counter);
  }

  // Read response from server
  while (client.available()) {
    String reply = client.readStringUntil('\n');
    reply.trim();
    if (reply.length() > 0) {
      Serial.print("[RX] ");
      Serial.println(reply);
    }
  }
}
