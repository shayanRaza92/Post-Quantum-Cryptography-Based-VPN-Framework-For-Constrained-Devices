// ESP32 Phase B Network Benchmark for Mutual Authentication Handshake
// Rigorous Network Methodology:
// - Option A 4-Message Handshake Protocol (Production-Aligned):
//     MSG 1 (Client Hello, 50B) -> [Ver (1B) | AlgID (1B) | DeviceID (16B) | ClientNonce (32B)]
//     MSG 2 (Server Proof) <- [ServerNonce (32B) | ServerSig over Server Transcript]
//     MSG 3 (Client Proof) -> [ClientSig over Client Transcript (binds MSG1 || MSG2)]
//     MSG 4 (Server Verdict & Timing ACK, 8B) <- [Status (4B) | Server Crypto Time in us (4B)]
// - TLS 1.3-style Running Transcript Hashing:
//     Server Transcript: SHA-256("VPN-v1|SERVER|" || MSG1 || ServerNonce)
//     Client Transcript: SHA-256("VPN-v1|CLIENT|" || MSG1 || MSG2)
// - NULL-Crypto Control Baseline (Empirical physical Wi-Fi transit floor)
// - Unified 64-bit Microsecond Hardware Timing (esp_timer_get_time)
// - Single-Packet Buffer Writes (Zero Nagle / delayed-ACK packet splitting)
// - Desynchronization Resilience: explicit verdicts prevent stream stalls
// - Full Statistical Profile (Mean, Median, StdDev σ, Min, Max)

#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include <WiFi.h>
#include <sodium.h>
#include <esp_timer.h>
#include <math.h>

// Built-in ESP32 cryptography libraries (mbedTLS)
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"

// Wi-Fi and Server settings (Update for your local test environment)
const char* WIFI_SSID     = "Redmi 13C";
const char* WIFI_PASSWORD = "92144444";
const char* LAPTOP_IP     = "10.202.171.216";
const uint16_t PORT       = 9000;

// Benchmarking iteration counts
#define NULL_RUNS    50
#define ED25519_RUNS 50
#define ECDSA_RUNS   50
#define RSA_RUNS     20

#define DEVICE_ID    "esp32-01"

// Transcript labels matching production VPN protocol
const char* SERVER_TRANSCRIPT_LABEL = "VPN-v1|SERVER|";
const char* CLIENT_TRANSCRIPT_LABEL = "VPN-v1|CLIENT|";

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

// Statistical container for benchmark metrics
struct StatResult {
  float mean;
  float median;
  float min_val;
  float max_val;
  float stddev;
};

// Comprehensive KPI metrics per protocol configuration
struct BenchmarkResult {
  const char* name;
  int total_runs;
  int successful_runs;
  StatResult total_handshake_ms;
  StatResult client_crypto_ms;
  StatResult server_crypto_ms;
  StatResult non_crypto_ms;
  uint32_t avg_wire_bytes;
  float success_rate;
};

BenchmarkResult res_null;
BenchmarkResult res_ed25519;
BenchmarkResult res_ecdsa;
BenchmarkResult res_rsa;

// Live Wire Byte Counter
static uint32_t session_wire_bytes = 0;

// ----------------------------------------------------
// Statistical Analysis Helpers
// ----------------------------------------------------
static void sort_floats(float* arr, int n) {
  for (int i = 0; i < n - 1; i++) {
    for (int j = 0; j < n - i - 1; j++) {
      if (arr[j] > arr[j + 1]) {
        float temp = arr[j];
        arr[j] = arr[j + 1];
        arr[j + 1] = temp;
      }
    }
  }
}

StatResult calculate_stats(float* raw, int count) {
  StatResult s = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
  if (count <= 0) return s;

  float sum = 0.0f;
  for (int i = 0; i < count; i++) {
    sum += raw[i];
  }
  s.mean = sum / count;

  sort_floats(raw, count);
  s.min_val = raw[0];
  s.max_val = raw[count - 1];

  if (count % 2 == 0) {
    s.median = (raw[count / 2 - 1] + raw[count / 2]) / 2.0f;
  } else {
    s.median = raw[count / 2];
  }

  if (count > 1) {
    double sum_sq_diff = 0.0;
    for (int i = 0; i < count; i++) {
      double diff = raw[i] - s.mean;
      sum_sq_diff += diff * diff;
    }
    s.stddev = (float)sqrt(sum_sq_diff / (count - 1));
  } else {
    s.stddev = 0.0f;
  }
  return s;
}

// ----------------------------------------------------
// Network Helpers (Zero-Nagle Unified Framing)
// ----------------------------------------------------

// Read exact number of bytes with a microsecond yield to avoid polling lag
bool read_exact(uint8_t* buf, size_t len, unsigned long timeout_ms = 8000) {
  size_t bytes_read = 0;
  int64_t start_us = esp_timer_get_time();
  int64_t timeout_us = (int64_t)timeout_ms * 1000;

  while (bytes_read < len && (esp_timer_get_time() - start_us < timeout_us)) {
    while (client.available() && bytes_read < len) {
      buf[bytes_read++] = client.read();
    }
    if (bytes_read < len) {
      delayMicroseconds(250); // Yield to TCP stack without introducing multi-millisecond delay
    }
  }
  return (bytes_read == len);
}

// Receive length-prefixed packet
int recv_msg(uint8_t* buf, size_t max_len, unsigned long timeout_ms = 8000) {
  uint8_t header[2];
  if (!read_exact(header, 2, timeout_ms)) return -1;
  uint16_t len = ((uint16_t)header[0] << 8) | header[1];
  if (len > max_len) return -1;
  if (!read_exact(buf, len, timeout_ms)) return -1;
  session_wire_bytes += (2 + len);
  return (int)len;
}

// Send length-prefixed packet in a SINGLE write call to prevent TCP delayed-ACK packet splitting
void send_msg(const uint8_t* data, uint16_t len) {
  uint8_t packet[2 + len];
  packet[0] = (len >> 8) & 0xFF;
  packet[1] = len & 0xFF;
  if (len > 0 && data != NULL) {
    memcpy(packet + 2, data, len);
  }
  client.write(packet, 2 + len);
  client.flush();
  session_wire_bytes += (2 + len);
}

// ----------------------------------------------------
// Running Transcript Hashing (Production Aligned)
// ----------------------------------------------------

// Builds 50-byte Client Hello packet (MSG 1)
void build_msg1_client_hello(uint8_t alg_id, const uint8_t* client_nonce, uint8_t* out_msg1) {
  out_msg1[0] = 0x01; // Version
  out_msg1[1] = alg_id; // Algorithm ID (0x00=NULL, 0x01=Ed25519, 0x02=ECDSA, 0x03=RSA)
  memset(out_msg1 + 2, 0, 16);
  strncpy((char*)(out_msg1 + 2), DEVICE_ID, 15);
  memcpy(out_msg1 + 18, client_nonce, 32);
}

// Server Transcript: SHA-256("VPN-v1|SERVER|" (14B) || MSG1 (50B) || ServerNonce (32B)) -> 96B input
void build_server_transcript(const uint8_t* msg1, size_t msg1_len, const uint8_t* server_nonce, size_t nonce_len, uint8_t* out_digest) {
  crypto_hash_sha256_state state;
  crypto_hash_sha256_init(&state);
  crypto_hash_sha256_update(&state, (const unsigned char*)SERVER_TRANSCRIPT_LABEL, 14);
  crypto_hash_sha256_update(&state, msg1, msg1_len);
  crypto_hash_sha256_update(&state, server_nonce, nonce_len);
  crypto_hash_sha256_final(&state, out_digest);
}

// Client Transcript: SHA-256("VPN-v1|CLIENT|" (14B) || MSG1 (50B) || MSG2 (len bytes)) -> binds entire transcript
void build_client_transcript(const uint8_t* msg1, size_t msg1_len, const uint8_t* msg2, size_t msg2_len, uint8_t* out_digest) {
  crypto_hash_sha256_state state;
  crypto_hash_sha256_init(&state);
  crypto_hash_sha256_update(&state, (const unsigned char*)CLIENT_TRANSCRIPT_LABEL, 14);
  crypto_hash_sha256_update(&state, msg1, msg1_len);
  crypto_hash_sha256_update(&state, msg2, msg2_len);
  crypto_hash_sha256_final(&state, out_digest);
}

// ----------------------------------------------------
// [Test 0] NULL-Crypto Control Baseline
// Measures empirical Wi-Fi transport floor with 4-message exchange & zero crypto
// ----------------------------------------------------
void test_null_network() {
  Serial.println("\n[0/3] Benchmarking NULL-Crypto Control Baseline (Pure Wi-Fi Transport Floor)...");

  // Send command: 0x00 (NULL Baseline), runs
  uint8_t cmd[2] = {0x00, NULL_RUNS};
  client.write(cmd, 2);
  client.flush();

  float total_h_ms[NULL_RUNS];
  float client_c_ms[NULL_RUNS];
  float server_c_ms[NULL_RUNS];
  float non_crypto_ms[NULL_RUNS];
  int successful_runs = 0;
  uint32_t wire_start = session_wire_bytes;

  for (int i = 0; i < NULL_RUNS; i++) {
    int64_t t_start_us = esp_timer_get_time();

    // MSG 1: Send 50-byte Client Hello (Ver=0x01, Alg=0x00, DeviceID, Dummy Nonce)
    uint8_t dummy_nonce[32] = {0};
    uint8_t msg1[50];
    build_msg1_client_hello(0x00, dummy_nonce, msg1);
    send_msg(msg1, 50);

    // MSG 2: Receive 96-byte dummy Server Proof (32B dummy nonce + 64B dummy payload)
    uint8_t msg2[96];
    if (recv_msg(msg2, sizeof(msg2)) != 96) continue;

    // MSG 3: Send 64-byte dummy Client Proof
    uint8_t msg3[64] = {0};
    send_msg(msg3, 64);

    // MSG 4: Receive 8-byte Verdict ACK ([4B status] [4B server crypto time in us])
    uint8_t ack[8];
    if (recv_msg(ack, sizeof(ack)) != 8) continue;

    int64_t t_end_us = esp_timer_get_time();

    uint32_t status = ((uint32_t)ack[0] << 24) | ((uint32_t)ack[1] << 16) | ((uint32_t)ack[2] << 8) | ack[3];
    uint32_t s_crypto_us = ((uint32_t)ack[4] << 24) | ((uint32_t)ack[5] << 16) | ((uint32_t)ack[6] << 8) | ack[7];

    if (status != 1) continue;

    float total_ms = (float)(t_end_us - t_start_us) / 1000.0f;
    float s_ms = (float)s_crypto_us / 1000.0f;
    float c_ms = 0.0f; // Zero crypto in NULL baseline
    float transit_ms = total_ms - c_ms - s_ms;
    if (transit_ms < 0.0f) transit_ms = 0.0f;

    total_h_ms[successful_runs] = total_ms;
    client_c_ms[successful_runs] = c_ms;
    server_c_ms[successful_runs] = s_ms;
    non_crypto_ms[successful_runs] = transit_ms;
    successful_runs++;

    if ((i + 1) % 10 == 0 || (i + 1) == NULL_RUNS) {
      Serial.printf("  - Completed %2d/%d | Current Handshake: %5.2f ms (Transport: %5.2f ms)\n",
                    i + 1, NULL_RUNS, total_ms, transit_ms);
    }
  }

  uint32_t total_wire = session_wire_bytes - wire_start;
  res_null.name = "NULL Baseline";
  res_null.total_runs = NULL_RUNS;
  res_null.successful_runs = successful_runs;
  res_null.total_handshake_ms = calculate_stats(total_h_ms, successful_runs);
  res_null.client_crypto_ms   = calculate_stats(client_c_ms, successful_runs);
  res_null.server_crypto_ms   = calculate_stats(server_c_ms, successful_runs);
  res_null.non_crypto_ms      = calculate_stats(non_crypto_ms, successful_runs);
  res_null.avg_wire_bytes     = (successful_runs > 0) ? (total_wire / successful_runs) : 0;
  res_null.success_rate       = ((float)successful_runs / NULL_RUNS) * 100.0f;

  Serial.printf("  [RESULT] NULL Total Latency: Mean %5.2f ms | Median %5.2f ms | Net Floor %5.2f ms | %4u B\n",
                res_null.total_handshake_ms.mean, res_null.total_handshake_ms.median,
                res_null.non_crypto_ms.median, res_null.avg_wire_bytes);
}

// ----------------------------------------------------
// [Test 1] Ed25519 Mutual Authentication Network Benchmark
// Production 4-Message Handshake over Wi-Fi
// ----------------------------------------------------
void test_ed25519_network() {
  Serial.println("\n[1/3] Benchmarking Ed25519 Real Mutual Authentication over Wi-Fi...");

  // Send command: 0x01 (Ed25519), runs
  uint8_t cmd[2] = {0x01, ED25519_RUNS};
  client.write(cmd, 2);
  client.flush();

  // Initial Key Provisioning Exchange
  send_msg(ed_pk, 32);
  uint8_t key_buf[64];
  if (recv_msg(key_buf, sizeof(key_buf)) != 32) {
    Serial.println("  Failed to exchange Ed25519 public keys!");
    return;
  }
  memcpy(server_ed_pk, key_buf, 32);

  float total_h_ms[ED25519_RUNS];
  float client_c_ms[ED25519_RUNS];
  float server_c_ms[ED25519_RUNS];
  float non_crypto_ms[ED25519_RUNS];
  int successful_runs = 0;
  uint32_t wire_start = session_wire_bytes;

  for (int i = 0; i < ED25519_RUNS; i++) {
    int64_t t_start_us = esp_timer_get_time();

    // MSG 1: Generate 32B Client Nonce & Send 50-byte Client Hello
    uint8_t c_nonce[32];
    esp_fill_random(c_nonce, 32);
    uint8_t msg1[50];
    build_msg1_client_hello(0x01, c_nonce, msg1);
    send_msg(msg1, 50);

    // MSG 2: Receive 96-byte Server Proof (32B Server Nonce + 64B Server Sig)
    uint8_t msg2[96];
    if (recv_msg(msg2, sizeof(msg2)) != 96) continue;

    // Verify Server Signature over Server Transcript
    int64_t c_vstart_us = esp_timer_get_time();
    const uint8_t* server_nonce = msg2;
    const uint8_t* server_sig = msg2 + 32;

    uint8_t s_digest[32];
    build_server_transcript(msg1, 50, server_nonce, 32, s_digest);
    int ok = crypto_sign_verify_detached(server_sig, s_digest, 32, server_ed_pk);
    int64_t c_vend_us = esp_timer_get_time();
    int64_t c_verify_us = c_vend_us - c_vstart_us;

    if (ok != 0) {
      Serial.printf("  Run %d failed: Invalid server signature\n", i + 1);
      // Send zero signature to keep stream synchronized, then read rejection
      uint8_t zero_sig[64] = {0};
      send_msg(zero_sig, 64);
      uint8_t fail_ack[8];
      recv_msg(fail_ack, sizeof(fail_ack));
      continue;
    }

    // MSG 3: Sign Client Transcript (binds MSG1 || MSG2) and Send 64-byte Client Proof
    int64_t c_sstart_us = esp_timer_get_time();
    uint8_t c_digest[32];
    build_client_transcript(msg1, 50, msg2, 96, c_digest);

    uint8_t c_sig[crypto_sign_BYTES];
    unsigned long long sig_len = 0;
    crypto_sign_detached(c_sig, &sig_len, c_digest, 32, ed_sk);
    int64_t c_send_us = esp_timer_get_time();
    int64_t c_sign_us = c_send_us - c_sstart_us;

    send_msg(c_sig, 64);

    // MSG 4: Receive 8-byte Verdict ACK ([4B status] [4B server crypto time in us])
    uint8_t ack[8];
    if (recv_msg(ack, sizeof(ack)) != 8) continue;

    int64_t t_end_us = esp_timer_get_time();

    uint32_t status = ((uint32_t)ack[0] << 24) | ((uint32_t)ack[1] << 16) | ((uint32_t)ack[2] << 8) | ack[3];
    uint32_t s_crypto_us = ((uint32_t)ack[4] << 24) | ((uint32_t)ack[5] << 16) | ((uint32_t)ack[6] << 8) | ack[7];

    if (status != 1) {
      Serial.printf("  Run %d failed: Server rejected authentication\n", i + 1);
      continue;
    }

    float total_ms = (float)(t_end_us - t_start_us) / 1000.0f;
    float client_crypto = (float)(c_verify_us + c_sign_us) / 1000.0f;
    float server_crypto = (float)s_crypto_us / 1000.0f;
    float transit_ms = total_ms - client_crypto - server_crypto;
    if (transit_ms < 0.0f) transit_ms = 0.0f;

    total_h_ms[successful_runs] = total_ms;
    client_c_ms[successful_runs] = client_crypto;
    server_c_ms[successful_runs] = server_crypto;
    non_crypto_ms[successful_runs] = transit_ms;
    successful_runs++;

    if ((i + 1) % 10 == 0 || (i + 1) == ED25519_RUNS) {
      Serial.printf("  - Completed %2d/%d | Total: %5.2f ms (Client Crypto: %5.2f ms, Srv: %4.2f ms, Net: %5.2f ms)\n",
                    i + 1, ED25519_RUNS, total_ms, client_crypto, server_crypto, transit_ms);
    }
  }

  uint32_t total_wire = session_wire_bytes - wire_start;
  res_ed25519.name = "Ed25519";
  res_ed25519.total_runs = ED25519_RUNS;
  res_ed25519.successful_runs = successful_runs;
  res_ed25519.total_handshake_ms = calculate_stats(total_h_ms, successful_runs);
  res_ed25519.client_crypto_ms   = calculate_stats(client_c_ms, successful_runs);
  res_ed25519.server_crypto_ms   = calculate_stats(server_c_ms, successful_runs);
  res_ed25519.non_crypto_ms      = calculate_stats(non_crypto_ms, successful_runs);
  res_ed25519.avg_wire_bytes     = (successful_runs > 0) ? (total_wire / successful_runs) : 0;
  res_ed25519.success_rate       = ((float)successful_runs / ED25519_RUNS) * 100.0f;

  Serial.printf("  [RESULT] Ed25519 Latency: Mean %5.2f ms | Median %5.2f ms | Crypto: %5.2f ms | %4u B\n",
                res_ed25519.total_handshake_ms.mean, res_ed25519.total_handshake_ms.median,
                res_ed25519.client_crypto_ms.mean, res_ed25519.avg_wire_bytes);
}

// ----------------------------------------------------
// [Test 2] ECDSA P-256 Mutual Authentication Network Benchmark
// ----------------------------------------------------
void test_ecdsa_network() {
  Serial.println("\n[2/3] Benchmarking ECDSA P-256 Real Mutual Authentication over Wi-Fi...");

  // Send command: 0x02 (ECDSA), runs
  uint8_t cmd[2] = {0x02, ECDSA_RUNS};
  client.write(cmd, 2);
  client.flush();

  // Export and exchange 65-byte uncompressed public keys
  uint8_t ec_pub[70];
  size_t ec_pub_len = 0;
  mbedtls_ecp_point_write_binary(&ec_key.grp, &ec_key.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &ec_pub_len, ec_pub, sizeof(ec_pub));
  send_msg(ec_pub, (uint16_t)ec_pub_len);

  uint8_t s_ec_buf[100];
  int s_ec_len = recv_msg(s_ec_buf, sizeof(s_ec_buf));
  if (s_ec_len != 65) {
    Serial.println("  Failed to exchange ECDSA public keys!");
    return;
  }
  mbedtls_ecdsa_init(&server_ec_key);
  mbedtls_ecp_group_load(&server_ec_key.grp, MBEDTLS_ECP_DP_SECP256R1);
  mbedtls_ecp_point_read_binary(&server_ec_key.grp, &server_ec_key.Q, s_ec_buf, s_ec_len);

  float total_h_ms[ECDSA_RUNS];
  float client_c_ms[ECDSA_RUNS];
  float server_c_ms[ECDSA_RUNS];
  float non_crypto_ms[ECDSA_RUNS];
  int successful_runs = 0;
  uint32_t wire_start = session_wire_bytes;

  for (int i = 0; i < ECDSA_RUNS; i++) {
    int64_t t_start_us = esp_timer_get_time();

    // MSG 1: Generate 32B Client Nonce & Send 50-byte Client Hello
    uint8_t c_nonce[32];
    esp_fill_random(c_nonce, 32);
    uint8_t msg1[50];
    build_msg1_client_hello(0x02, c_nonce, msg1);
    send_msg(msg1, 50);

    // MSG 2: Receive Server Proof (32B Server Nonce + DER sig)
    uint8_t msg2[150];
    int msg2_len = recv_msg(msg2, sizeof(msg2));
    if (msg2_len <= 32) continue;

    // Verify Server Signature over Server Transcript
    int64_t c_vstart_us = esp_timer_get_time();
    const uint8_t* server_nonce = msg2;
    const uint8_t* server_sig = msg2 + 32;
    size_t server_sig_len = msg2_len - 32;

    uint8_t s_digest[32];
    build_server_transcript(msg1, 50, server_nonce, 32, s_digest);
    int ok = mbedtls_ecdsa_read_signature(&server_ec_key, s_digest, 32, server_sig, server_sig_len);
    int64_t c_vend_us = esp_timer_get_time();
    int64_t c_verify_us = c_vend_us - c_vstart_us;

    if (ok != 0) {
      Serial.printf("  Run %d failed: Invalid server ECDSA signature\n", i + 1);
      uint8_t zero_sig[64] = {0};
      send_msg(zero_sig, 64);
      uint8_t fail_ack[8];
      recv_msg(fail_ack, sizeof(fail_ack));
      continue;
    }

    // MSG 3: Sign Client Transcript (binds MSG1 || MSG2) and Send DER Signature
    int64_t c_sstart_us = esp_timer_get_time();
    uint8_t c_digest[32];
    build_client_transcript(msg1, 50, msg2, msg2_len, c_digest);

    uint8_t c_sig[MBEDTLS_ECDSA_MAX_LEN];
    size_t sig_len = 0;
    mbedtls_ecdsa_write_signature(&ec_key, MBEDTLS_MD_SHA256, c_digest, 32, c_sig, sizeof(c_sig), &sig_len, mbedtls_ctr_drbg_random, &random_gen);
    int64_t c_send_us = esp_timer_get_time();
    int64_t c_sign_us = c_send_us - c_sstart_us;

    send_msg(c_sig, sig_len);

    // MSG 4: Receive 8-byte Verdict ACK
    uint8_t ack[8];
    if (recv_msg(ack, sizeof(ack)) != 8) continue;

    int64_t t_end_us = esp_timer_get_time();

    uint32_t status = ((uint32_t)ack[0] << 24) | ((uint32_t)ack[1] << 16) | ((uint32_t)ack[2] << 8) | ack[3];
    uint32_t s_crypto_us = ((uint32_t)ack[4] << 24) | ((uint32_t)ack[5] << 16) | ((uint32_t)ack[6] << 8) | ack[7];

    if (status != 1) {
      Serial.printf("  Run %d failed: Server rejected authentication\n", i + 1);
      continue;
    }

    float total_ms = (float)(t_end_us - t_start_us) / 1000.0f;
    float client_crypto = (float)(c_verify_us + c_sign_us) / 1000.0f;
    float server_crypto = (float)s_crypto_us / 1000.0f;
    float transit_ms = total_ms - client_crypto - server_crypto;
    if (transit_ms < 0.0f) transit_ms = 0.0f;

    total_h_ms[successful_runs] = total_ms;
    client_c_ms[successful_runs] = client_crypto;
    server_c_ms[successful_runs] = server_crypto;
    non_crypto_ms[successful_runs] = transit_ms;
    successful_runs++;

    if ((i + 1) % 10 == 0 || (i + 1) == ECDSA_RUNS) {
      Serial.printf("  - Completed %2d/%d | Total: %5.2f ms (Client Crypto: %5.2f ms, Srv: %4.2f ms, Net: %5.2f ms)\n",
                    i + 1, ECDSA_RUNS, total_ms, client_crypto, server_crypto, transit_ms);
    }
  }

  uint32_t total_wire = session_wire_bytes - wire_start;
  res_ecdsa.name = "ECDSA P-256";
  res_ecdsa.total_runs = ECDSA_RUNS;
  res_ecdsa.successful_runs = successful_runs;
  res_ecdsa.total_handshake_ms = calculate_stats(total_h_ms, successful_runs);
  res_ecdsa.client_crypto_ms   = calculate_stats(client_c_ms, successful_runs);
  res_ecdsa.server_crypto_ms   = calculate_stats(server_c_ms, successful_runs);
  res_ecdsa.non_crypto_ms      = calculate_stats(non_crypto_ms, successful_runs);
  res_ecdsa.avg_wire_bytes     = (successful_runs > 0) ? (total_wire / successful_runs) : 0;
  res_ecdsa.success_rate       = ((float)successful_runs / ECDSA_RUNS) * 100.0f;

  Serial.printf("  [RESULT] ECDSA Latency: Mean %5.2f ms | Median %5.2f ms | Crypto: %5.2f ms | %4u B\n",
                res_ecdsa.total_handshake_ms.mean, res_ecdsa.total_handshake_ms.median,
                res_ecdsa.client_crypto_ms.mean, res_ecdsa.avg_wire_bytes);
}

// ----------------------------------------------------
// [Test 3] RSA-3072 Mutual Authentication Network Benchmark
// ----------------------------------------------------
void test_rsa_network() {
  Serial.println("\n[3/3] Benchmarking RSA-3072 Real Mutual Authentication over Wi-Fi...");

  // Send command: 0x03 (RSA), runs
  uint8_t cmd[2] = {0x03, RSA_RUNS};
  client.write(cmd, 2);
  client.flush();

  // Export and exchange DER public keys
  uint8_t rsa_pub[512];
  int der_len = mbedtls_pk_write_pubkey_der(&rsa_key, rsa_pub, sizeof(rsa_pub));
  if (der_len <= 0) {
    Serial.println("  Failed to export RSA public key!");
    return;
  }
  uint8_t* der_start = rsa_pub + sizeof(rsa_pub) - der_len;
  send_msg(der_start, der_len);

  uint8_t s_rsa_buf[512];
  int s_rsa_len = recv_msg(s_rsa_buf, sizeof(s_rsa_buf));
  if (s_rsa_len <= 0) {
    Serial.println("  Failed to receive server RSA public key!");
    return;
  }
  mbedtls_pk_init(&server_rsa_key);
  mbedtls_pk_parse_public_key(&server_rsa_key, s_rsa_buf, s_rsa_len);

  float total_h_ms[RSA_RUNS];
  float client_c_ms[RSA_RUNS];
  float server_c_ms[RSA_RUNS];
  float non_crypto_ms[RSA_RUNS];
  int successful_runs = 0;
  uint32_t wire_start = session_wire_bytes;

  for (int i = 0; i < RSA_RUNS; i++) {
    int64_t t_start_us = esp_timer_get_time();

    // MSG 1: Generate 32B Client Nonce & Send 50-byte Client Hello
    uint8_t c_nonce[32];
    esp_fill_random(c_nonce, 32);
    uint8_t msg1[50];
    build_msg1_client_hello(0x03, c_nonce, msg1);
    send_msg(msg1, 50);

    // MSG 2: Receive 416-byte Server Proof (32B Server Nonce + 384B RSA Sig)
    uint8_t msg2[450];
    int msg2_len = recv_msg(msg2, sizeof(msg2));
    if (msg2_len != 416) continue;

    // Verify Server Signature over Server Transcript
    int64_t c_vstart_us = esp_timer_get_time();
    const uint8_t* server_nonce = msg2;
    const uint8_t* server_sig = msg2 + 32;

    uint8_t s_digest[32];
    build_server_transcript(msg1, 50, server_nonce, 32, s_digest);
    int ok = mbedtls_pk_verify(&server_rsa_key, MBEDTLS_MD_SHA256, s_digest, 32, server_sig, 384);
    int64_t c_vend_us = esp_timer_get_time();
    int64_t c_verify_us = c_vend_us - c_vstart_us;

    if (ok != 0) {
      Serial.printf("  Run %d failed: Invalid server RSA signature\n", i + 1);
      uint8_t zero_sig[64] = {0};
      send_msg(zero_sig, 64);
      uint8_t fail_ack[8];
      recv_msg(fail_ack, sizeof(fail_ack));
      continue;
    }

    // MSG 3: Sign Client Transcript (binds MSG1 || MSG2) and Send 384-byte RSA Sig
    int64_t c_sstart_us = esp_timer_get_time();
    uint8_t c_digest[32];
    build_client_transcript(msg1, 50, msg2, 416, c_digest);

    uint8_t c_sig[384];
    size_t sig_len = 0;
    mbedtls_pk_sign(&rsa_key, MBEDTLS_MD_SHA256, c_digest, 32, c_sig, sizeof(c_sig), &sig_len, mbedtls_ctr_drbg_random, &random_gen);
    int64_t c_send_us = esp_timer_get_time();
    int64_t c_sign_us = c_send_us - c_sstart_us;

    send_msg(c_sig, 384);

    // MSG 4: Receive 8-byte Verdict ACK
    uint8_t ack[8];
    if (recv_msg(ack, sizeof(ack)) != 8) continue;

    int64_t t_end_us = esp_timer_get_time();

    uint32_t status = ((uint32_t)ack[0] << 24) | ((uint32_t)ack[1] << 16) | ((uint32_t)ack[2] << 8) | ack[3];
    uint32_t s_crypto_us = ((uint32_t)ack[4] << 24) | ((uint32_t)ack[5] << 16) | ((uint32_t)ack[6] << 8) | ack[7];

    if (status != 1) {
      Serial.printf("  Run %d failed: Server rejected authentication\n", i + 1);
      continue;
    }

    float total_ms = (float)(t_end_us - t_start_us) / 1000.0f;
    float client_crypto = (float)(c_verify_us + c_sign_us) / 1000.0f;
    float server_crypto = (float)s_crypto_us / 1000.0f;
    float transit_ms = total_ms - client_crypto - server_crypto;
    if (transit_ms < 0.0f) transit_ms = 0.0f;

    total_h_ms[successful_runs] = total_ms;
    client_c_ms[successful_runs] = client_crypto;
    server_c_ms[successful_runs] = server_crypto;
    non_crypto_ms[successful_runs] = transit_ms;
    successful_runs++;

    if ((i + 1) % 5 == 0 || (i + 1) == RSA_RUNS) {
      Serial.printf("  - Completed %2d/%d | Total: %5.2f ms (Client Crypto: %5.2f ms, Srv: %4.2f ms, Net: %5.2f ms)\n",
                    i + 1, RSA_RUNS, total_ms, client_crypto, server_crypto, transit_ms);
    }
    vTaskDelay(10); // Yield between heavy RSA prime modular math
  }

  uint32_t total_wire = session_wire_bytes - wire_start;
  res_rsa.name = "RSA-3072";
  res_rsa.total_runs = RSA_RUNS;
  res_rsa.successful_runs = successful_runs;
  res_rsa.total_handshake_ms = calculate_stats(total_h_ms, successful_runs);
  res_rsa.client_crypto_ms   = calculate_stats(client_c_ms, successful_runs);
  res_rsa.server_crypto_ms   = calculate_stats(server_c_ms, successful_runs);
  res_rsa.non_crypto_ms      = calculate_stats(non_crypto_ms, successful_runs);
  res_rsa.avg_wire_bytes     = (successful_runs > 0) ? (total_wire / successful_runs) : 0;
  res_rsa.success_rate       = ((float)successful_runs / RSA_RUNS) * 100.0f;

  Serial.printf("  [RESULT] RSA-3072 Latency: Mean %5.2f ms | Median %5.2f ms | Crypto: %5.2f ms | %4u B\n",
                res_rsa.total_handshake_ms.mean, res_rsa.total_handshake_ms.median,
                res_rsa.client_crypto_ms.mean, res_rsa.avg_wire_bytes);
}

// ----------------------------------------------------
// Setup and Main Loop
// ----------------------------------------------------
void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println("\n========================================================================================================");
  Serial.println("              ESP32 Mutual Authentication Network Benchmark (Phase B: Over Wi-Fi)                       ");
  Serial.printf("Host: %s:%d | Initial Free Heap: %u bytes\n", LAPTOP_IP, PORT, ESP.getFreeHeap());
  Serial.println("========================================================================================================");

  // 1. Initialize Libsodium engine for Ed25519
  if (sodium_init() < 0) {
    Serial.println("[ERROR] Failed to initialize libsodium!");
    while (1) delay(1000);
  }

  // 2. Initialize mbedTLS random number generator
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&random_gen);
  mbedtls_ctr_drbg_seed(&random_gen, mbedtls_entropy_func, &entropy, (const unsigned char*)"net_bench", 9);

  // 3. Pre-generate keys (Provisioning step, not counted in per-handshake time)
  crypto_sign_keypair(ed_pk, ed_sk);

  mbedtls_ecdsa_init(&ec_key);
  mbedtls_ecdsa_genkey(&ec_key, MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random, &random_gen);

  mbedtls_pk_init(&rsa_key);
  mbedtls_pk_setup(&rsa_key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
  mbedtls_rsa_gen_key(mbedtls_pk_rsa(rsa_key), mbedtls_ctr_drbg_random, &random_gen, 3072, 65537);

  // 4. Connect to Wi-Fi
  Serial.print("\n[WIFI] Connecting to ");
  Serial.println(WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  // Disable Wi-Fi modem sleep to eliminate radio power-save jitter
  WiFi.setSleep(false);

  Serial.println("\n[WIFI] Connected!");
  Serial.print("       ESP32 IP: ");
  Serial.println(WiFi.localIP());

  // 5. Connect to Laptop Server
  Serial.printf("[TCP]  Connecting to Server %s:%d ...\n", LAPTOP_IP, PORT);
  if (!client.connect(LAPTOP_IP, PORT)) {
    Serial.println("[FAIL] Could not connect to server. Check IP and port!");
    return;
  }

  // Disable Nagle's algorithm to eliminate delayed-ACK packet buffering
  client.setNoDelay(true);

  Serial.println("[OK]   Connected to server! Starting benchmark suite...\n");

  // Run the 4 benchmark suites sequentially
  test_null_network();
  test_ed25519_network();
  test_ecdsa_network();
  test_rsa_network();

  // Notify server that all tests are done
  uint8_t finish_cmd[2] = {0xFF, 0x00};
  client.write(finish_cmd, 2);
  client.flush();
  client.stop();

  // Print Publication-Grade Summary Comparison Table
  Serial.println("\n==========================================================================================================");
  Serial.println("                                    BENCHMARK RESULTS SUMMARY (PHASE B)                                    ");
  Serial.println("==========================================================================================================");
  Serial.printf("%-6s | %-37s | %-11s | %-11s | %-11s | %-11s\n", "KPI ID", "Metric", "NULL Ctrl", "Ed25519", "ECDSA P-256", "RSA-3072");
  Serial.println("-------+---------------------------------------+-------------+-------------+-------------+------------");
  Serial.printf("%-6s | %-37s | %8.2f ms | %8.2f ms | %8.2f ms | %8.2f ms\n", "NET-1", "Total Handshake Latency (Mean)",
                res_null.total_handshake_ms.mean, res_ed25519.total_handshake_ms.mean, res_ecdsa.total_handshake_ms.mean, res_rsa.total_handshake_ms.mean);
  Serial.printf("%-6s | %-37s | %8.2f ms | %8.2f ms | %8.2f ms | %8.2f ms\n", "     ", "Total Handshake Latency (Median)",
                res_null.total_handshake_ms.median, res_ed25519.total_handshake_ms.median, res_ecdsa.total_handshake_ms.median, res_rsa.total_handshake_ms.median);
  Serial.printf("%-6s | %-37s | %8.2f ms | %8.2f ms | %8.2f ms | %8.2f ms\n", "     ", "Total Handshake Latency (StdDev σ)",
                res_null.total_handshake_ms.stddev, res_ed25519.total_handshake_ms.stddev, res_ecdsa.total_handshake_ms.stddev, res_rsa.total_handshake_ms.stddev);
  Serial.printf("%-6s | %-37s | %5.1f-%-4.1f ms| %5.1f-%-4.1f ms| %5.1f-%-4.1f ms| %5.1f-%-4.1f ms\n", "     ", "Total Handshake Range (Min - Max)",
                res_null.total_handshake_ms.min_val, res_null.total_handshake_ms.max_val,
                res_ed25519.total_handshake_ms.min_val, res_ed25519.total_handshake_ms.max_val,
                res_ecdsa.total_handshake_ms.min_val, res_ecdsa.total_handshake_ms.max_val,
                res_rsa.total_handshake_ms.min_val, res_rsa.total_handshake_ms.max_val);
  Serial.printf("%-6s | %-37s | %9u B | %9u B | %9u B | %9u B\n", "NET-2", "Handshake Wire Payload (Mean)",
                res_null.avg_wire_bytes, res_ed25519.avg_wire_bytes, res_ecdsa.avg_wire_bytes, res_rsa.avg_wire_bytes);
  Serial.printf("%-6s | %-37s | %8.2f ms | %8.2f ms | %8.2f ms | %8.2f ms\n", "NET-3", "Client Cryptographic Time (Mean)",
                res_null.client_crypto_ms.mean, res_ed25519.client_crypto_ms.mean, res_ecdsa.client_crypto_ms.mean, res_rsa.client_crypto_ms.mean);
  Serial.printf("%-6s | %-37s | %8.2f ms | %8.2f ms | %8.2f ms | %8.2f ms\n", "NET-4", "Server Cryptographic Time (Mean)",
                res_null.server_crypto_ms.mean, res_ed25519.server_crypto_ms.mean, res_ecdsa.server_crypto_ms.mean, res_rsa.server_crypto_ms.mean);
  Serial.printf("%-6s | %-37s | %8.2f ms | %8.2f ms | %8.2f ms | %8.2f ms\n", "NET-5", "Non-Crypto Overhead / Transit Latency",
                res_null.non_crypto_ms.mean, res_ed25519.non_crypto_ms.mean, res_ecdsa.non_crypto_ms.mean, res_rsa.non_crypto_ms.mean);
  Serial.printf("%-6s | %-37s | %8.2f ms | %8.2f ms | %8.2f ms | %8.2f ms\n", "     ", "Non-Crypto Overhead (Median)",
                res_null.non_crypto_ms.median, res_ed25519.non_crypto_ms.median, res_ecdsa.non_crypto_ms.median, res_rsa.non_crypto_ms.median);
  Serial.printf("%-6s | %-37s | %7.1f %% | %7.1f %% | %7.1f %% | %7.1f %%\n", "NET-6", "Handshake Success Rate",
                res_null.success_rate, res_ed25519.success_rate, res_ecdsa.success_rate, res_rsa.success_rate);
  Serial.println("==========================================================================================================\n");
}

void loop() {
  delay(10000);
}
