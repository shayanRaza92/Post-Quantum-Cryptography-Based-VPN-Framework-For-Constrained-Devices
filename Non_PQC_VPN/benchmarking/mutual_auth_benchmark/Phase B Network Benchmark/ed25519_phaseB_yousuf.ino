// ESP32 Phase B Network Benchmark — Ed25519 ONLY (Production-Aligned 4-Message Handshake)
// Rigorous Network Methodology:
// - Option A 4-Message Handshake:
//     MSG 1 (Client Hello, 50B) -> [Ver (1B) | AlgID (1B) | DeviceID (16B) | ClientNonce (32B)]
//     MSG 2 (Server Proof, 96B) <- [ServerNonce (32B) | ServerSig over Server Transcript]
//     MSG 3 (Client Proof, 64B) -> [ClientSig over Client Transcript (binds MSG1 || MSG2)]
//     MSG 4 (Server Verdict & Timing ACK, 8B) <- [Status (4B) | Server Crypto Time in us (4B)]
// - TLS 1.3-style Running Transcript Hashing:
//     Server Transcript: SHA-256("VPN-v1|SERVER|" || MSG1 || ServerNonce)
//     Client Transcript: SHA-256("VPN-v1|CLIENT|" || MSG1 || MSG2)
// - Single-Packet Buffer Writes (Zero Nagle / delayed-ACK packet splitting)
// - Hardware Microsecond Timing (esp_timer_get_time)

#include <WiFi.h>
#include <sodium.h>
#include <esp_timer.h>

const char *WIFI_SSID = "Tenda_401";
const char *WIFI_PASSWORD = "Tenda111";
const char *LAPTOP_IP = "192.168.0.200";
const uint16_t PORT = 9000;

#define ED25519_RUNS 20
#define DEVICE_ID    "esp32-01"

const char* SERVER_TRANSCRIPT_LABEL = "VPN-v1|SERVER|";
const char* CLIENT_TRANSCRIPT_LABEL = "VPN-v1|CLIENT|";

WiFiClient client;

uint8_t ed_pk[crypto_sign_PUBLICKEYBYTES];
uint8_t ed_sk[crypto_sign_SECRETKEYBYTES];
uint8_t server_ed_pk[crypto_sign_PUBLICKEYBYTES];

struct BenchmarkResult {
  const char *name;
  int runs;
  float avg_handshake_ms;
  float avg_client_crypto_ms;
  float avg_server_crypto_ms;
  float avg_non_crypto_ms;
  uint32_t avg_wire_bytes;
};

BenchmarkResult res_ed25519;
static uint32_t session_wire_bytes = 0;

bool read_exact(uint8_t *buf, size_t len, unsigned long timeout_ms = 8000) {
  size_t bytes_read = 0;
  int64_t start_us = esp_timer_get_time();
  int64_t timeout_us = (int64_t)timeout_ms * 1000;

  while (bytes_read < len && (esp_timer_get_time() - start_us < timeout_us)) {
    while (client.available() && bytes_read < len) {
      buf[bytes_read++] = client.read();
    }
    if (bytes_read < len) {
      delayMicroseconds(250);
    }
  }
  return bytes_read == len;
}

int recv_msg(uint8_t *buf, size_t max_len, unsigned long timeout_ms = 8000) {
  uint8_t header[2];
  if (!read_exact(header, 2, timeout_ms))
    return -1;
  uint16_t len = ((uint16_t)header[0] << 8) | header[1];
  if (len > max_len)
    return -1;
  if (!read_exact(buf, len, timeout_ms))
    return -1;
  session_wire_bytes += (2 + len);
  return (int)len;
}

void send_msg(const uint8_t *data, uint16_t len) {
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

void build_msg1_client_hello(uint8_t alg_id, const uint8_t* client_nonce, uint8_t* out_msg1) {
  out_msg1[0] = 0x01; // Version
  out_msg1[1] = alg_id; // AlgID: 0x01 = Ed25519
  memset(out_msg1 + 2, 0, 16);
  strncpy((char*)(out_msg1 + 2), DEVICE_ID, 15);
  memcpy(out_msg1 + 18, client_nonce, 32);
}

void build_server_transcript(const uint8_t* msg1, size_t msg1_len, const uint8_t* server_nonce, size_t nonce_len, uint8_t* out_digest) {
  crypto_hash_sha256_state state;
  crypto_hash_sha256_init(&state);
  crypto_hash_sha256_update(&state, (const unsigned char*)SERVER_TRANSCRIPT_LABEL, 14);
  crypto_hash_sha256_update(&state, msg1, msg1_len);
  crypto_hash_sha256_update(&state, server_nonce, nonce_len);
  crypto_hash_sha256_final(&state, out_digest);
}

void build_client_transcript(const uint8_t* msg1, size_t msg1_len, const uint8_t* msg2, size_t msg2_len, uint8_t* out_digest) {
  crypto_hash_sha256_state state;
  crypto_hash_sha256_init(&state);
  crypto_hash_sha256_update(&state, (const unsigned char*)CLIENT_TRANSCRIPT_LABEL, 14);
  crypto_hash_sha256_update(&state, msg1, msg1_len);
  crypto_hash_sha256_update(&state, msg2, msg2_len);
  crypto_hash_sha256_final(&state, out_digest);
}

void test_ed25519_network() {
  Serial.println("\nBenchmarking Ed25519 4-Message Handshake over Wi-Fi...");

  // Command 0x01 selects Ed25519; second byte is run count.
  uint8_t cmd[2] = {0x01, ED25519_RUNS};
  client.write(cmd, 2);
  client.flush();

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
  float client_crypto_ms[ED25519_RUNS] = {0};
  float server_crypto_ms[ED25519_RUNS] = {0};
  float non_crypto_ms[ED25519_RUNS] = {0};
  bool run_success[ED25519_RUNS] = {false};
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
    if (recv_msg(msg2, sizeof(msg2)) != 96) {
      Serial.printf("Run %d failed receiving MSG 2.\n", i + 1);
      continue;
    }

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
      Serial.printf("Run %d failed: invalid server signature.\n", i + 1);
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
    if (recv_msg(ack, sizeof(ack)) != 8) {
      Serial.printf("Run %d failed receiving MSG 4.\n", i + 1);
      continue;
    }

    int64_t t_end_us = esp_timer_get_time();

    uint32_t status = ((uint32_t)ack[0] << 24) | ((uint32_t)ack[1] << 16) | ((uint32_t)ack[2] << 8) | ack[3];
    uint32_t s_crypto_us = ((uint32_t)ack[4] << 24) | ((uint32_t)ack[5] << 16) | ((uint32_t)ack[6] << 8) | ack[7];

    if (status != 1) {
      Serial.printf("Run %d failed: server rejected verdict.\n", i + 1);
      continue;
    }

    float total_ms = (float)(t_end_us - t_start_us) / 1000.0f;
    float client_crypto = (float)(c_verify_us + c_sign_us) / 1000.0f;
    float server_crypto = (float)s_crypto_us / 1000.0f;
    float transit_ms = total_ms - client_crypto - server_crypto;
    if (transit_ms < 0.0f) transit_ms = 0.0f;

    total_handshake_ms[i] = total_ms;
    client_crypto_ms[i] = client_crypto;
    server_crypto_ms[i] = server_crypto;
    non_crypto_ms[i] = transit_ms;
    run_success[i] = true;

    Serial.printf("Handshake %2d/%d: %6.2f ms (Client Crypto: %.2f ms, Srv: %.2f ms, Net: %.2f ms) | OK\n",
                  i + 1, ED25519_RUNS, total_ms, client_crypto, server_crypto, transit_ms);
  }

  float sum_h = 0.0f, sum_cc = 0.0f, sum_sc = 0.0f, sum_nc = 0.0f;
  int successful_runs = 0;
  for (int i = 0; i < ED25519_RUNS; i++) {
    if (run_success[i]) {
      sum_h += total_handshake_ms[i];
      sum_cc += client_crypto_ms[i];
      sum_sc += server_crypto_ms[i];
      sum_nc += non_crypto_ms[i];
      successful_runs++;
    }
  }

  uint32_t total_wire = session_wire_bytes - wire_start;
  res_ed25519.name = "Ed25519";
  res_ed25519.runs = successful_runs;
  res_ed25519.avg_wire_bytes = (successful_runs > 0) ? (total_wire / successful_runs) : 0;

  if (successful_runs > 0) {
    res_ed25519.avg_handshake_ms = sum_h / successful_runs;
    res_ed25519.avg_client_crypto_ms = sum_cc / successful_runs;
    res_ed25519.avg_server_crypto_ms = sum_sc / successful_runs;
    res_ed25519.avg_non_crypto_ms = sum_nc / successful_runs;
  }

  Serial.println("\n========== Ed25519 Phase B Results ==========");
  Serial.printf("NET-1 Average Handshake Latency      : %7.2f ms\n", res_ed25519.avg_handshake_ms);
  Serial.printf("NET-2 Measured Handshake Wire Payload: %7u bytes\n", res_ed25519.avg_wire_bytes);
  Serial.printf("NET-3 Client Cryptographic Time      : %7.2f ms\n", res_ed25519.avg_client_crypto_ms);
  Serial.printf("NET-4 Server Cryptographic Time      : %7.2f ms\n", res_ed25519.avg_server_crypto_ms);
  Serial.printf("NET-5 Non-Crypto Overhead / Transit  : %7.2f ms\n", res_ed25519.avg_non_crypto_ms);
  Serial.printf("NET-6 Handshake Success Rate         : %7.1f %% (%d/%d)\n",
                100.0f * successful_runs / ED25519_RUNS, successful_runs, ED25519_RUNS);
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
  WiFi.setSleep(false);

  Serial.println("\n[WIFI] Connected!");
  Serial.print("       ESP32 IP: ");
  Serial.println(WiFi.localIP());

  Serial.printf("[TCP] Connecting to server %s:%u ...\n", LAPTOP_IP, PORT);
  if (!client.connect(LAPTOP_IP, PORT)) {
    Serial.println("[FAIL] Could not connect to server. Check IP and port!");
    return;
  }
  client.setNoDelay(true);

  Serial.println("[OK] Connected to server. Starting Ed25519 benchmark...\n");
  test_ed25519_network();

  uint8_t finish_cmd[2] = {0xFF, 0x00};
  client.write(finish_cmd, 2);
  client.flush();
  client.stop();

  Serial.println("\nEd25519 Phase B benchmark finished.");
}

void loop() { delay(1000); }
