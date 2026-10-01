// ESP32 Phase B Network Benchmark for Mutual Authentication Handshake
// Measures real-world Wi-Fi handshake latency for Ed25519, ECDSA P-256, and RSA-3072

#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include <WiFi.h>
#include <sodium.h>

// Built-in ESP32 cryptography libraries (mbedTLS)
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"

// Wi-Fi and Server settings (Update these for your local network)
const char* WIFI_SSID     = "Redmi 13C";
const char* WIFI_PASSWORD = "92144444";
const char* LAPTOP_IP     = "10.27.228.216"; // Set to your laptop IP
const uint16_t PORT       = 9000;

// Setup how many handshakes to run for each test
#define ED25519_RUNS 20
#define ECDSA_RUNS   20
#define RSA_RUNS     10

WiFiClient client;

// Entropy and random generator contexts
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context random_gen;

// Keys for Ed25519
uint8_t ed_pk[crypto_sign_PUBLICKEYBYTES];
uint8_t ed_sk[crypto_sign_SECRETKEYBYTES];
uint8_t server_ed_pk[crypto_sign_PUBLICKEYBYTES];

// Keys for ECDSA P-256
mbedtls_ecdsa_context ec_key;
mbedtls_ecdsa_context server_ec_key;

// Keys for RSA-3072
mbedtls_pk_context rsa_key;
mbedtls_pk_context server_rsa_key;

// Result storage
struct BenchmarkResult {
  const char* name;
  int runs;
  float avg_handshake_ms;
  float avg_crypto_ms;
  float avg_network_ms;
  int wire_bytes;
};

BenchmarkResult res_ed25519;
BenchmarkResult res_ecdsa;
BenchmarkResult res_rsa;

// ----------------------------------------------------
// Network Helpers (Length-Prefixed TCP Stream)
// ----------------------------------------------------

// Read exact number of bytes with a timeout
bool read_exact(uint8_t* buf, size_t len, unsigned long timeout_ms = 10000) {
  size_t bytes_read = 0;
  unsigned long start = millis();
  while (bytes_read < len && (millis() - start < timeout_ms)) {
    while (client.available() && bytes_read < len) {
      buf[bytes_read++] = client.read();
    }
    delay(2);
  }
  return (bytes_read == len);
}

// Receive length-prefixed packet
int recv_msg(uint8_t* buf, size_t max_len, unsigned long timeout_ms = 10000) {
  uint8_t header[2];
  if (!read_exact(header, 2, timeout_ms)) return -1;
  uint16_t len = ((uint16_t)header[0] << 8) | header[1];
  if (len > max_len) return -1;
  if (!read_exact(buf, len, timeout_ms)) return -1;
  return (int)len;
}

// Send length-prefixed packet
void send_msg(const uint8_t* data, uint16_t len) {
  uint8_t header[2];
  header[0] = (len >> 8) & 0xFF;
  header[1] = len & 0xFF;
  client.write(header, 2);
  client.write(data, len);
  client.flush();
}

// ----------------------------------------------------
// Test 1: Ed25519 Handshake Benchmark
// ----------------------------------------------------
void test_ed25519_network() {
  Serial.println("\n[1/3] Benchmarking Ed25519 Handshake over Wi-Fi...");

  // Send command: 0x01 (Ed25519), runs
  uint8_t cmd[2] = {0x01, ED25519_RUNS};
  client.write(cmd, 2);

  // Exchange public keys: Send ESP32 public key (32 bytes)
  send_msg(ed_pk, 32);

  // Receive server public key (32 bytes)
  uint8_t key_buf[64];
  int key_len = recv_msg(key_buf, sizeof(key_buf));
  if (key_len != 32) {
    Serial.println("  Failed to exchange Ed25519 public keys!");
    return;
  }
  memcpy(server_ed_pk, key_buf, 32);

  float total_handshake_ms[ED25519_RUNS];
  float crypto_ms[ED25519_RUNS];

  for (int i = 0; i < ED25519_RUNS; i++) {
    // Receive Message 1: Server Challenge (32 bytes)
    uint8_t server_challenge[64];
    int chal_len = recv_msg(server_challenge, sizeof(server_challenge));
    if (chal_len != 32) {
      Serial.printf("  Run %d failed on receiving server challenge\n", i + 1);
      continue;
    }

    // Start measuring handshake time
    unsigned long t_start = millis();
    unsigned long c_start = micros();

    // 1. Sign server challenge with Ed25519 private key
    uint8_t esp32_sig[crypto_sign_BYTES]; // 64 bytes
    unsigned long long sig_len = 0;
    crypto_sign_detached(esp32_sig, &sig_len, server_challenge, 32, ed_sk);

    // 2. Generate client challenge nonce (32 bytes)
    uint8_t client_challenge[32];
    esp_fill_random(client_challenge, 32);

    unsigned long c_sign_time = micros() - c_start;

    // Send Message 2: Signature (64 bytes) + Client Challenge (32 bytes) = 96 bytes
    uint8_t msg2[96];
    memcpy(msg2, esp32_sig, 64);
    memcpy(msg2 + 64, client_challenge, 32);
    send_msg(msg2, 96);

    // Receive Message 3: Server Signature (64 bytes)
    uint8_t server_sig[128];
    int sig_in_len = recv_msg(server_sig, sizeof(server_sig));
    if (sig_in_len != 64) {
      Serial.printf("  Run %d failed on receiving server signature\n", i + 1);
      continue;
    }

    // 3. Verify server signature
    unsigned long c_vstart = micros();
    int ok = crypto_sign_verify_detached(server_sig, client_challenge, 32, server_ed_pk);
    unsigned long c_verify_time = micros() - c_vstart;

    unsigned long t_end = millis();

    total_handshake_ms[i] = (float)(t_end - t_start);
    crypto_ms[i] = (float)(c_sign_time + c_verify_time) / 1000.0f;

    if (ok != 0) {
      Serial.printf("  Run %d failed: Invalid server signature\n", i + 1);
    } else {
      Serial.printf("  - Handshake %2d/%d: %6.2f ms (Crypto: %.2f ms, Net: %.2f ms) | OK\n",
                    i + 1, ED25519_RUNS, total_handshake_ms[i], crypto_ms[i],
                    total_handshake_ms[i] - crypto_ms[i]);
    }
  }

  // Calculate averages
  float sum_h = 0, sum_c = 0;
  for (int i = 0; i < ED25519_RUNS; i++) {
    sum_h += total_handshake_ms[i];
    sum_c += crypto_ms[i];
  }

  res_ed25519.name = "Ed25519";
  res_ed25519.runs = ED25519_RUNS;
  res_ed25519.avg_handshake_ms = sum_h / ED25519_RUNS;
  res_ed25519.avg_crypto_ms = sum_c / ED25519_RUNS;
  res_ed25519.avg_network_ms = res_ed25519.avg_handshake_ms - res_ed25519.avg_crypto_ms;
  res_ed25519.wire_bytes = 198; // 34 + 98 + 66
}

// ----------------------------------------------------
// Test 2: ECDSA P-256 Handshake Benchmark
// ----------------------------------------------------
void test_ecdsa_network() {
  Serial.println("\n[2/3] Benchmarking ECDSA P-256 Handshake over Wi-Fi...");

  // Send command: 0x02 (ECDSA), runs
  uint8_t cmd[2] = {0x02, ECDSA_RUNS};
  client.write(cmd, 2);

  // Export ESP32 ECDSA public key (65 bytes uncompressed point)
  uint8_t ec_pub_buf[70];
  size_t ec_pub_len = 0;
  mbedtls_ecp_point_write_binary(&ec_key.grp, &ec_key.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &ec_pub_len, ec_pub_buf, sizeof(ec_pub_buf));
  send_msg(ec_pub_buf, (uint16_t)ec_pub_len);

  // Receive server public key (65 bytes)
  uint8_t s_ec_buf[100];
  int s_ec_len = recv_msg(s_ec_buf, sizeof(s_ec_buf));
  if (s_ec_len != 65) {
    Serial.printf("  Failed to exchange ECDSA public keys (got %d bytes)!\n", s_ec_len);
    return;
  }

  // Load server public key into context
  mbedtls_ecdsa_init(&server_ec_key);
  mbedtls_ecp_group_load(&server_ec_key.grp, MBEDTLS_ECP_DP_SECP256R1);
  mbedtls_ecp_point_read_binary(&server_ec_key.grp, &server_ec_key.Q, s_ec_buf, s_ec_len);

  float total_handshake_ms[ECDSA_RUNS];
  float crypto_ms[ECDSA_RUNS];

  for (int i = 0; i < ECDSA_RUNS; i++) {
    // Receive Message 1: Server Challenge (32 bytes)
    uint8_t server_challenge[64];
    int chal_len = recv_msg(server_challenge, sizeof(server_challenge));
    if (chal_len != 32) continue;

    unsigned long t_start = millis();
    unsigned long c_start = micros();

    // 1. Hash challenge and sign with ECDSA private key
    uint8_t hash[32];
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), server_challenge, 32, hash);

    uint8_t signature[MBEDTLS_ECDSA_MAX_LEN];
    size_t sig_len = 0;
    mbedtls_ecdsa_write_signature(&ec_key, MBEDTLS_MD_SHA256, hash, 32, signature, sizeof(signature), &sig_len, mbedtls_ctr_drbg_random, &random_gen);

    // 2. Generate client challenge nonce (32 bytes)
    uint8_t client_challenge[32];
    esp_fill_random(client_challenge, 32);

    unsigned long c_sign_time = micros() - c_start;

    // Send Message 2: Signature + Client Challenge
    uint8_t msg2[150];
    memcpy(msg2, signature, sig_len);
    memcpy(msg2 + sig_len, client_challenge, 32);
    send_msg(msg2, sig_len + 32);

    // Receive Message 3: Server Signature
    uint8_t server_sig[150];
    int s_sig_len = recv_msg(server_sig, sizeof(server_sig));
    if (s_sig_len <= 0) continue;

    // 3. Hash client challenge and verify server signature
    unsigned long c_vstart = micros();
    uint8_t c_hash[32];
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), client_challenge, 32, c_hash);
    int ok = mbedtls_ecdsa_read_signature(&server_ec_key, c_hash, 32, server_sig, s_sig_len);
    unsigned long c_verify_time = micros() - c_vstart;

    unsigned long t_end = millis();

    total_handshake_ms[i] = (float)(t_end - t_start);
    crypto_ms[i] = (float)(c_sign_time + c_verify_time) / 1000.0f;

    if (ok != 0) {
      Serial.printf("  Run %d failed: Invalid server signature\n", i + 1);
    } else {
      Serial.printf("  - Handshake %2d/%d: %6.2f ms (Crypto: %.2f ms, Net: %.2f ms) | OK\n",
                    i + 1, ECDSA_RUNS, total_handshake_ms[i], crypto_ms[i],
                    total_handshake_ms[i] - crypto_ms[i]);
    }
  }

  float sum_h = 0, sum_c = 0;
  for (int i = 0; i < ECDSA_RUNS; i++) {
    sum_h += total_handshake_ms[i];
    sum_c += crypto_ms[i];
  }

  res_ecdsa.name = "ECDSA P-256";
  res_ecdsa.runs = ECDSA_RUNS;
  res_ecdsa.avg_handshake_ms = sum_h / ECDSA_RUNS;
  res_ecdsa.avg_crypto_ms = sum_c / ECDSA_RUNS;
  res_ecdsa.avg_network_ms = res_ecdsa.avg_handshake_ms - res_ecdsa.avg_crypto_ms;
  res_ecdsa.wire_bytes = 212; // Average wire bytes
}

// ----------------------------------------------------
// Test 3: RSA-3072 Handshake Benchmark
// ----------------------------------------------------
void test_rsa_network() {
  Serial.println("\n[3/3] Benchmarking RSA-3072 Handshake over Wi-Fi...");

  // Send command: 0x03 (RSA), runs
  uint8_t cmd[2] = {0x03, RSA_RUNS};
  client.write(cmd, 2);

  // Export ESP32 RSA public key (DER format)
  uint8_t rsa_pub_buf[512];
  int der_len = mbedtls_pk_write_pubkey_der(&rsa_key, rsa_pub_buf, sizeof(rsa_pub_buf));
  if (der_len <= 0) {
    Serial.println("  Failed to export RSA public key!");
    return;
  }
  uint8_t* der_start = rsa_pub_buf + sizeof(rsa_pub_buf) - der_len;
  send_msg(der_start, der_len);

  // Receive server RSA public key (DER format)
  uint8_t s_rsa_buf[512];
  int s_rsa_len = recv_msg(s_rsa_buf, sizeof(s_rsa_buf));
  if (s_rsa_len <= 0) {
    Serial.println("  Failed to receive server RSA public key!");
    return;
  }

  // Load server public key into context
  mbedtls_pk_init(&server_rsa_key);
  mbedtls_pk_parse_public_key(&server_rsa_key, s_rsa_buf, s_rsa_len);

  float total_handshake_ms[RSA_RUNS];
  float crypto_ms[RSA_RUNS];

  for (int i = 0; i < RSA_RUNS; i++) {
    // Receive Message 1: Server Challenge (32 bytes)
    uint8_t server_challenge[64];
    int chal_len = recv_msg(server_challenge, sizeof(server_challenge));
    if (chal_len != 32) continue;

    unsigned long t_start = millis();
    unsigned long c_start = micros();

    // 1. Hash challenge and sign with RSA-3072 private key
    uint8_t hash[32];
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), server_challenge, 32, hash);

    uint8_t signature[384];
    size_t sig_len = 0;
    mbedtls_pk_sign(&rsa_key, MBEDTLS_MD_SHA256, hash, 32, signature, sizeof(signature), &sig_len, mbedtls_ctr_drbg_random, &random_gen);

    // 2. Generate client challenge nonce (32 bytes)
    uint8_t client_challenge[32];
    esp_fill_random(client_challenge, 32);

    unsigned long c_sign_time = micros() - c_start;

    // Send Message 2: Signature (384 bytes) + Client Challenge (32 bytes) = 416 bytes
    uint8_t msg2[420];
    memcpy(msg2, signature, 384);
    memcpy(msg2 + 384, client_challenge, 32);
    send_msg(msg2, 416);

    // Receive Message 3: Server Signature (384 bytes)
    uint8_t server_sig[420];
    int s_sig_len = recv_msg(server_sig, sizeof(server_sig));
    if (s_sig_len != 384) continue;

    // 3. Hash client challenge and verify server signature
    unsigned long c_vstart = micros();
    uint8_t c_hash[32];
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), client_challenge, 32, c_hash);
    int ok = mbedtls_pk_verify(&server_rsa_key, MBEDTLS_MD_SHA256, c_hash, 32, server_sig, s_sig_len);
    unsigned long c_verify_time = micros() - c_vstart;

    unsigned long t_end = millis();

    total_handshake_ms[i] = (float)(t_end - t_start);
    crypto_ms[i] = (float)(c_sign_time + c_verify_time) / 1000.0f;

    if (ok != 0) {
      Serial.printf("  Run %d failed: Invalid server signature\n", i + 1);
    } else {
      Serial.printf("  - Handshake %2d/%d: %6.2f ms (Crypto: %.2f ms, Net: %.2f ms) | OK\n",
                    i + 1, RSA_RUNS, total_handshake_ms[i], crypto_ms[i],
                    total_handshake_ms[i] - crypto_ms[i]);
    }

    // Give ESP32 a tiny break between heavy RSA handshakes
    vTaskDelay(10);
  }

  float sum_h = 0, sum_c = 0;
  for (int i = 0; i < RSA_RUNS; i++) {
    sum_h += total_handshake_ms[i];
    sum_c += crypto_ms[i];
  }

  res_rsa.name = "RSA-3072";
  res_rsa.runs = RSA_RUNS;
  res_rsa.avg_handshake_ms = sum_h / RSA_RUNS;
  res_rsa.avg_crypto_ms = sum_c / RSA_RUNS;
  res_rsa.avg_network_ms = res_rsa.avg_handshake_ms - res_rsa.avg_crypto_ms;
  res_rsa.wire_bytes = 838; // 34 + 418 + 386
}

// ----------------------------------------------------
// Setup and Main Loop
// ----------------------------------------------------
void setup() {
  Serial.begin(115200);
  delay(500);

  Serial.println("\n============================================================");
  Serial.println("   PHASE B: MUTUAL AUTHENTICATION NETWORK BENCHMARK (ESP32)");
  Serial.println("============================================================");

  // 1. Initialize Libsodium engine for Ed25519
  if (sodium_init() < 0) {
    Serial.println("[ERROR] Failed to initialize libsodium!");
    while (1) delay(1000);
  }

  // 2. Initialize mbedTLS random number generator
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&random_gen);
  mbedtls_ctr_drbg_seed(&random_gen, mbedtls_entropy_func, &entropy, (const unsigned char*)"net_bench", 9);

  // 3. Generate Ed25519 keypair
  Serial.println("[INIT] Creating Ed25519 keypair...");
  crypto_sign_keypair(ed_pk, ed_sk);

  // 4. Generate ECDSA P-256 keypair
  Serial.println("[INIT] Creating ECDSA P-256 keypair...");
  mbedtls_ecdsa_init(&ec_key);
  mbedtls_ecdsa_genkey(&ec_key, MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random, &random_gen);

  // 5. Generate RSA-3072 keypair (this takes ~3.8 seconds once)
  Serial.println("[INIT] Creating RSA-3072 keypair (please wait ~4 seconds)...");
  mbedtls_pk_init(&rsa_key);
  mbedtls_pk_setup(&rsa_key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
  mbedtls_rsa_gen_key(mbedtls_pk_rsa(rsa_key), mbedtls_ctr_drbg_random, &random_gen, 3072, 65537);
  Serial.println("[INIT] All cryptographic keys generated successfully!");

  // 6. Connect to Wi-Fi
  Serial.print("\n[WIFI] Connecting to ");
  Serial.println(WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\n[WIFI] Connected!");
  Serial.print("       ESP32 IP: ");
  Serial.println(WiFi.localIP());

  // 7. Connect to Laptop Server
  Serial.printf("\n[TCP] Connecting to Server %s:%d ...\n", LAPTOP_IP, PORT);
  if (!client.connect(LAPTOP_IP, PORT)) {
    Serial.println("[FAIL] Could not connect to server. Check IP and port!");
    return;
  }
  Serial.println("[OK] Connected to server! Starting benchmark suite...\n");

  // Run the 3 benchmarks sequentially over Wi-Fi
  test_ed25519_network();
  test_ecdsa_network();
  test_rsa_network();

  // Notify server that all tests are done
  uint8_t finish_cmd[2] = {0xFF, 0x00};
  client.write(finish_cmd, 2);
  client.flush();
  client.stop();

  // Print Summary Comparison Table
  Serial.println("\n=========================================================================");
  Serial.println("           PHASE B: NETWORK BENCHMARK COMPARISON SUMMARY");
  Serial.println("=========================================================================");
  Serial.println("Algorithm       | Runs | Total Latency | Crypto Time | Net Latency | Wire Bytes");
  Serial.println("----------------+------+---------------+-------------+-------------+-----------");

  BenchmarkResult* all_results[3] = {&res_ed25519, &res_ecdsa, &res_rsa};
  for (int i = 0; i < 3; i++) {
    Serial.printf("%-15s | %4d | %10.2f ms | %8.2f ms | %8.2f ms | %6d B\n",
                  all_results[i]->name,
                  all_results[i]->runs,
                  all_results[i]->avg_handshake_ms,
                  all_results[i]->avg_crypto_ms,
                  all_results[i]->avg_network_ms,
                  all_results[i]->wire_bytes);
  }
  Serial.println("=========================================================================\n");
  Serial.println("[DONE] Benchmark completed! You can copy the table above into your report.");
}

void loop() {
  // Benchmark runs once in setup. Nothing to repeat in loop.
  delay(1000);
}
