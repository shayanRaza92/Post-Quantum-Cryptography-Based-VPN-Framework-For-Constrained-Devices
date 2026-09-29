#include <WiFi.h>
#include <sodium.h>

// Wi-Fi and Server settings
const char* WIFI_SSID     = "YOUR_WIFI_NAME";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";
const char* LAPTOP_IP     = "10.27.228.216"; // Set to your laptop IP
const uint16_t PORT       = 9000;

// ESP32 Ed25519 Private Seed (32 bytes)
const uint8_t ESP32_PRIVATE_SEED[32] = {
  0x46, 0xc9, 0x61, 0x0f, 0xc5, 0x55, 0x0d, 0xbb,
  0x95, 0xaf, 0xd3, 0x13, 0x8e, 0x8d, 0x2b, 0x48,
  0x03, 0xff, 0xa3, 0x75, 0x5f, 0x5d, 0xdb, 0x42,
  0xa4, 0x47, 0x7b, 0xdf, 0x75, 0xec, 0xaf, 0x46
};

// Registered Laptop Gateway Ed25519 Public Key (32 bytes)
const uint8_t SERVER_PUBLIC_KEY[32] = {
  0x19, 0x1a, 0x24, 0x2d, 0xdd, 0x26, 0x7e, 0x20,
  0x58, 0x8d, 0x07, 0x6b, 0x12, 0xf4, 0x4c, 0x83,
  0x4f, 0xdd, 0xc7, 0xc5, 0x3d, 0x86, 0x78, 0x92,
  0x2e, 0xb1, 0x77, 0x59, 0xb1, 0x76, 0x73, 0xba
};

// Runtime keys
uint8_t esp32_pk[crypto_sign_PUBLICKEYBYTES]; // 32 bytes
uint8_t esp32_sk[crypto_sign_SECRETKEYBYTES]; // 64 bytes

WiFiClient client;
unsigned long lastSendTime = 0;
int counter = 0;
bool isAuthenticated = false;

// Helper to print bytes as hex string
void print_hex(const uint8_t* data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (data[i] < 0x10) Serial.print("0");
    Serial.print(data[i], HEX);
  }
  Serial.println();
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

// Perform mutual challenge-response authentication using Ed25519 signatures
bool perform_mutual_auth() {
  Serial.println("\n[MUTUAL AUTHENTICATION]");

  // Step 1: Receive 32-byte challenge from server
  uint8_t laptop_challenge[32];
  if (!read_exact(laptop_challenge, 32)) {
    Serial.println("[FAIL] Server challenge timed out");
    return false;
  }
  Serial.println("[MSG1] Server Challenge");
  Serial.println("       Length         : 32 bytes");
  Serial.print("       Nonce (Hex)    : ");
  print_hex(laptop_challenge, 32);
  Serial.println("       Status         : RECEIVED");

  // Step 2: Sign server's challenge with ESP32 private key
  uint8_t esp32_sig[crypto_sign_BYTES]; // 64 bytes
  unsigned long long sig_len = 0;
  crypto_sign_detached(esp32_sig, &sig_len, laptop_challenge, 32, esp32_sk);

  // Generate ESP32's own 32-byte random challenge
  uint8_t esp32_challenge[32];
  esp_fill_random(esp32_challenge, 32);

  // Send Signature (64 bytes) + ESP32 Challenge (32 bytes) = 96 bytes total
  client.write(esp32_sig, 64);
  client.write(esp32_challenge, 32);
  client.flush();

  Serial.println("\n[MSG2] ESP32 Authentication Proof");
  Serial.println("       Algorithm      : Ed25519 Digital Signature");
  Serial.print("       Signature (Hex): ");
  print_hex(esp32_sig, 64);
  Serial.print("       Client Nonce   : ");
  print_hex(esp32_challenge, 32);
  Serial.println("       Status         : SENT");

  // Step 3: Receive 64-byte Ed25519 signature from server
  uint8_t laptop_sig[crypto_sign_BYTES];
  if (!read_exact(laptop_sig, 64)) {
    Serial.println("[FAIL] Server proof timed out");
    return false;
  }

  Serial.println("\n[MSG3] Server Authentication Proof");
  Serial.println("       Algorithm      : Ed25519 Digital Signature");
  Serial.print("       Signature (Hex): ");
  print_hex(laptop_sig, 64);
  Serial.println("       Status         : RECEIVED");

  // Verify server's signature using SERVER_PUBLIC_KEY
  if (crypto_sign_verify_detached(laptop_sig, esp32_challenge, 32, SERVER_PUBLIC_KEY) != 0) {
    Serial.println("\n[VERIFY] Server Digital Signature");
    Serial.println("         Result       : FAILED (Untrusted Server / Forged Signature)");
    return false;
  }

  Serial.println("\n[VERIFY] Server Digital Signature");
  Serial.println("         Result       : SUCCESS (Valid Ed25519 Signature)");

  Serial.println("\n============================================================");
  Serial.println("        MUTUAL AUTHENTICATION SUCCESSFUL (Ed25519)");
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
  Serial.println("         PQC VPN - ESP32 CLIENT (Ed25519 AUTH)");
  Serial.println("============================================================");

  // Initialize Libsodium engine
  if (sodium_init() < 0) {
    Serial.println("[ERROR] Failed to initialize libsodium!");
    while (1) delay(1000);
  }

  // Derive Ed25519 public key and secret key from seed
  crypto_sign_seed_keypair(esp32_pk, esp32_sk, ESP32_PRIVATE_SEED);

  Serial.println("\n[CRYPTO]");
  Serial.print("     ESP32 PubKey   : ");
  print_hex(esp32_pk, 32);

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
