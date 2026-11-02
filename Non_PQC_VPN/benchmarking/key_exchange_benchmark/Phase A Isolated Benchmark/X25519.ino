
/*
  ESP32 X25519 over Wi-Fi
  -----------------------
  ESP32 acts as a Wi-Fi access point and TCP server.
  A laptop connects and exchanges X25519 public keys.

  Wi-Fi SSID:     ESP32-X25519-Demo
  Wi-Fi Password: X25519demo
  ESP32 IP:       192.168.4.1
  TCP Port:       5000

  LEARNING DEMO ONLY:
  - This is not a complete VPN.
  - Peers are not authenticated.
  - Shared secrets are printed only to verify the demo.
*/

#include <WiFi.h>
#include <sodium.h>

const char *AP_SSID = "ESP32-X25519-Demo";
const char *AP_PASSWORD = "X25519demo";
const uint16_t TCP_PORT = 5000;

WiFiServer server(TCP_PORT);

// Print a byte array as hexadecimal.
void printHex(const char *label, const unsigned char *data, size_t len) {
  Serial.print(label);

  for (size_t i = 0; i < len; i++) {
    if (data[i] < 0x10) {
      Serial.print('0');
    }

    Serial.print(data[i], HEX);
  }

  Serial.println();
}

// Receive exactly the requested number of bytes.
bool readExact(WiFiClient &client, unsigned char *buffer, size_t len,
               uint32_t timeoutMs = 15000) {
  size_t received = 0;
  uint32_t start = millis();

  while (received < len && (millis() - start) < timeoutMs) {

    if (!client.connected() && !client.available()) {
      return false;
    }

    while (client.available() && received < len) {
      int count = client.read(buffer + received, len - received);

      if (count > 0) {
        received += (size_t)count;
      }
    }

    delay(1);
  }

  return received == len;
}

// Send exactly the requested number of bytes.
bool writeExact(WiFiClient &client, const unsigned char *buffer, size_t len) {
  size_t sent = 0;
  uint32_t start = millis();

  while (sent < len && (millis() - start) < 5000) {

    size_t count = client.write(buffer + sent, len - sent);

    if (count > 0) {
      sent += count;
    } else {
      delay(1);
    }
  }

  return sent == len;
}

void setup() {
  Serial.begin(115200);
  delay(1200);

  Serial.println();
  Serial.println("====================================");
  Serial.println("ESP32 X25519 Wi-Fi Demo");
  Serial.println("====================================");

  // STEP 1: Initialize libsodium.
  Serial.println("\n[STEP 1] Initializing libsodium...");

  if (sodium_init() < 0) {
    Serial.println("[ERROR] libsodium initialization failed.");

    while (true) {
      delay(1000);
    }
  }

  Serial.println("[OK] libsodium initialized.");

  // STEP 2: Start the ESP32 Wi-Fi access point.
  Serial.println("\n[STEP 2] Starting Wi-Fi access point...");

  WiFi.mode(WIFI_AP);

  if (!WiFi.softAP(AP_SSID, AP_PASSWORD)) {
    Serial.println("[ERROR] Could not start Wi-Fi access point.");

    while (true) {
      delay(1000);
    }
  }

  Serial.print("[OK] Wi-Fi SSID: ");
  Serial.println(AP_SSID);

  Serial.print("[OK] Wi-Fi password: ");
  Serial.println(AP_PASSWORD);

  Serial.print("[OK] ESP32 IP address: ");
  Serial.println(WiFi.softAPIP());

  // STEP 3: Start the TCP server.
  server.begin();
  server.setNoDelay(true);

  Serial.print("\n[STEP 3] TCP server listening on port ");
  Serial.println(TCP_PORT);

  Serial.println("Connect your laptop to the ESP32 Wi-Fi.");
}

void loop() {
  WiFiClient client = server.available();

  if (!client) {
    delay(10);
    return;
  }

  Serial.println("\n[STEP 4] Laptop connected!");

  client.setNoDelay(true);

  unsigned char espPrivate[crypto_scalarmult_curve25519_SCALARBYTES];

  unsigned char espPublic[crypto_scalarmult_curve25519_BYTES];

  unsigned char laptopPublic[crypto_scalarmult_curve25519_BYTES];

  unsigned char sharedSecret[crypto_scalarmult_curve25519_BYTES];

  // STEP 5: Generate the ESP32 X25519 key pair.
  Serial.println("[STEP 5] Generating ESP32 X25519 key pair...");

  randombytes_buf(espPrivate, sizeof(espPrivate));

  if (crypto_scalarmult_curve25519_base(espPublic, espPrivate) != 0) {
    Serial.println("[ERROR] ESP32 public-key generation failed.");

    goto cleanup;
  }

  printHex("ESP32 public key: ", espPublic, sizeof(espPublic));

  // STEP 6: Send ESP32 public key to the laptop.
  Serial.println("\n[STEP 6] Sending ESP32 public key to laptop...");

  if (!writeExact(client, espPublic, sizeof(espPublic))) {
    Serial.println("[ERROR] Could not send ESP32 public key.");

    goto cleanup;
  }

  Serial.println("[OK] Public key sent.");

  // STEP 7: Receive laptop public key.
  Serial.println("\n[STEP 7] Waiting for laptop public key...");

  if (!readExact(client, laptopPublic, sizeof(laptopPublic))) {
    Serial.println("[ERROR] Did not receive complete laptop public key.");

    goto cleanup;
  }

  printHex("Laptop public key: ", laptopPublic, sizeof(laptopPublic));

  // STEP 8: Calculate the shared secret.
  Serial.println("\n[STEP 8] Calculating X25519 shared secret...");

  if (crypto_scalarmult_curve25519(sharedSecret, espPrivate, laptopPublic) !=
      0) {
    Serial.println("[ERROR] X25519 shared-secret calculation failed.");

    goto cleanup;
  }

  // Tell the laptop that calculation succeeded.
  {
    const unsigned char statusMessage[3] = {'O', 'K', '\n'};

    if (!writeExact(client, statusMessage, sizeof(statusMessage))) {
      Serial.println("[ERROR] Could not send status to laptop.");

      goto cleanup;
    }
  }

  Serial.println("\n[SUCCESS] ESP32 calculated the shared secret.");

  printHex("Shared secret (demo only): ", sharedSecret, sizeof(sharedSecret));

  Serial.println("Compare this with the laptop's shared secret.");

  Serial.println("Both values should match exactly.");

  Serial.println("WARNING: Never print shared secrets in production.");

cleanup:

  // Clear sensitive buffers before closing the connection.
  sodium_memzero(espPrivate, sizeof(espPrivate));
  sodium_memzero(sharedSecret, sizeof(sharedSecret));

  client.stop();

  Serial.println("\n[INFO] ESP32 private-key and secret buffers cleared.");

  Serial.println("[INFO] Connection closed. Waiting for another client.");

  delay(100);
}
