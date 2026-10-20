// ESP32 Phase B Network Benchmark — Ed25519 ONLY
// Extracted from the supplied Phase B sketch; ECDSA and RSA removed.
// Configure Wi-Fi credentials and laptop IP before uploading.

#include <WiFi.h>
#include <sodium.h>

const char *WIFI_SSID = "Tenda_401";
const char *WIFI_PASSWORD = "Tenda111";
const char *LAPTOP_IP = "192.168.0.200";
const uint16_t PORT = 9000;

#define ED25519_RUNS 20

WiFiClient client;

uint8_t ed_pk[crypto_sign_PUBLICKEYBYTES];
uint8_t ed_sk[crypto_sign_SECRETKEYBYTES];
uint8_t server_ed_pk[crypto_sign_PUBLICKEYBYTES];

struct BenchmarkResult {
  const char *name;
  int runs;
  float avg_handshake_ms;
  float avg_crypto_ms;
  float avg_network_ms;
  int wire_bytes;
};

BenchmarkResult res_ed25519;

bool read_exact(uint8_t *buf, size_t len, unsigned long timeout_ms = 10000) {
  size_t bytes_read = 0;
  unsigned long start = millis();
  while (bytes_read < len && (millis() - start < timeout_ms)) {
    while (client.available() && bytes_read < len) {
      buf[bytes_read++] = client.read();
    }
    delay(2);
  }
  return bytes_read == len;
}

int recv_msg(uint8_t *buf, size_t max_len, unsigned long timeout_ms = 10000) {
  uint8_t header[2];
  if (!read_exact(header, 2, timeout_ms))
    return -1;
  uint16_t len = ((uint16_t)header[0] << 8) | header[1];
  if (len > max_len)
    return -1;
  if (!read_exact(buf, len, timeout_ms))
    return -1;
  return (int)len;
}

void send_msg(const uint8_t *data, uint16_t len) {
  uint8_t header[2];
  header[0] = (len >> 8) & 0xFF;
  header[1] = len & 0xFF;
  client.write(header, 2);
  client.write(data, len);
  client.flush();
}

void test_ed25519_network() {
  Serial.println("\nBenchmarking Ed25519 handshake over Wi-Fi...");

  // Command 0x01 selects Ed25519; second byte is the number of runs.
  uint8_t cmd[2] = {0x01, ED25519_RUNS};
  client.write(cmd, 2);

  // Exchange Ed25519 public keys.
  send_msg(ed_pk, 32);
  uint8_t key_buf[64];
  int key_len = recv_msg(key_buf, sizeof(key_buf));
  if (key_len != 32) {
    Serial.println("Failed to exchange Ed25519 public keys!");
    return;
  }
  memcpy(server_ed_pk, key_buf, 32);

  float total_handshake_ms[ED25519_RUNS] = {0};
  float crypto_ms[ED25519_RUNS] = {0};
  bool run_success[ED25519_RUNS] = {false};

  for (int i = 0; i < ED25519_RUNS; i++) {
    uint8_t server_challenge[64];
    int chal_len = recv_msg(server_challenge, sizeof(server_challenge));
    if (chal_len != 32) {
      Serial.printf("Run %d failed receiving server challenge.\n", i + 1);
      continue;
    }

    unsigned long t_start = millis();
    unsigned long c_start = micros();

    uint8_t esp32_sig[crypto_sign_BYTES];
    unsigned long long sig_len = 0;
    if (crypto_sign_detached(esp32_sig, &sig_len, server_challenge, 32,
                             ed_sk) != 0 ||
        sig_len != crypto_sign_BYTES) {
      Serial.printf("Run %d failed signing challenge.\n", i + 1);
      continue;
    }

    uint8_t client_challenge[32];
    randombytes_buf(client_challenge, sizeof(client_challenge));
    unsigned long c_sign_time = micros() - c_start;

    // Message 2: 64-byte signature + 32-byte client challenge.
    uint8_t msg2[96];
    memcpy(msg2, esp32_sig, 64);
    memcpy(msg2 + 64, client_challenge, 32);
    send_msg(msg2, 96);

    uint8_t server_sig[128];
    int sig_in_len = recv_msg(server_sig, sizeof(server_sig));
    if (sig_in_len != 64) {
      Serial.printf("Run %d failed receiving server signature.\n", i + 1);
      continue;
    }

    unsigned long c_vstart = micros();
    int ok = crypto_sign_verify_detached(server_sig, client_challenge, 32,
                                         server_ed_pk);
    unsigned long c_verify_time = micros() - c_vstart;
    unsigned long t_end = millis();

    total_handshake_ms[i] = (float)(t_end - t_start);
    crypto_ms[i] = (float)(c_sign_time + c_verify_time) / 1000.0f;

    if (ok != 0) {
      Serial.printf("Run %d failed: invalid server signature.\n", i + 1);
    } else {
      run_success[i] = true;
      Serial.printf(
          "Handshake %2d/%d: %6.2f ms (Crypto: %.2f ms, Net: %.2f ms) | OK\n",
          i + 1, ED25519_RUNS, total_handshake_ms[i], crypto_ms[i],
          total_handshake_ms[i] - crypto_ms[i]);
    }
  }

  // Average successful handshakes only so failed runs don't distort the
  // results.
  float sum_h = 0.0f, sum_c = 0.0f;
  int successful_runs = 0;
  for (int i = 0; i < ED25519_RUNS; i++) {
    if (run_success[i]) {
      sum_h += total_handshake_ms[i];
      sum_c += crypto_ms[i];
      successful_runs++;
    }
  }

  res_ed25519.name = "Ed25519";
  res_ed25519.runs = successful_runs;
  res_ed25519.wire_bytes = 198; // Retained from the original benchmark.

  if (successful_runs > 0) {
    res_ed25519.avg_handshake_ms = sum_h / successful_runs;
    res_ed25519.avg_crypto_ms = sum_c / successful_runs;
    res_ed25519.avg_network_ms =
        res_ed25519.avg_handshake_ms - res_ed25519.avg_crypto_ms;
  } else {
    res_ed25519.avg_handshake_ms = 0;
    res_ed25519.avg_crypto_ms = 0;
    res_ed25519.avg_network_ms = 0;
  }

  Serial.println("\n========== Ed25519 Phase B Results ==========");
  Serial.printf("NET-1 Average Handshake Latency : %7.2f ms\n",
                res_ed25519.avg_handshake_ms);
  Serial.printf("NET-2 Reported Wire Payload     : %u bytes\n",
                res_ed25519.wire_bytes);
  Serial.printf("NET-3 Client Crypto Time        : %7.2f ms\n",
                res_ed25519.avg_crypto_ms);
  Serial.printf("NET-4 Estimated Network Time    : %7.2f ms\n",
                res_ed25519.avg_network_ms);
  Serial.printf("NET-5 Handshake Success Rate    : %7.1f %% (%d/%d)\n",
                100.0f * successful_runs / ED25519_RUNS, successful_runs,
                ED25519_RUNS);
  Serial.println("==============================================");
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println("\n==============================================");
  Serial.println("ESP32 Ed25519 Network Benchmark (Phase B)");
  Serial.printf("Gateway Server: %s:%u | Initial Free Heap: %u bytes\n",
                LAPTOP_IP, PORT, ESP.getFreeHeap());
  Serial.println("==============================================");

  if (sodium_init() < 0) {
    Serial.println("[ERROR] Failed to initialize libsodium!");
    while (true)
      delay(1000);
  }

  if (crypto_sign_keypair(ed_pk, ed_sk) != 0) {
    Serial.println("[ERROR] Failed to generate Ed25519 key pair!");
    while (true)
      delay(1000);
  }

  Serial.printf("\n[WIFI] Connecting to %s\n", WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\n[WIFI] Connected!");
  Serial.print("       ESP32 IP: ");
  Serial.println(WiFi.localIP());

  Serial.printf("[TCP] Connecting to server %s:%u ...\n", LAPTOP_IP, PORT);
  if (!client.connect(LAPTOP_IP, PORT)) {
    Serial.println("[FAIL] Could not connect to server. Check IP and port!");
    return;
  }

  Serial.println("[OK] Connected to server. Starting Ed25519 benchmark...\n");
  test_ed25519_network();

  // Tell the compatible Phase B server the benchmark is finished.
  uint8_t finish_cmd[2] = {0xFF, 0x00};
  client.write(finish_cmd, 2);
  client.flush();
  client.stop();

  Serial.println("\nEd25519 Phase B benchmark finished.");
}

void loop() { delay(1000); }
