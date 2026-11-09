#include "SystemBenchmark.h"
#include <algorithm>
#include <WiFi.h>
#include <sodium.h>
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/gcm.h"
#include "config.h"
#include "AuthManager.h"
#include "SecureTunnel.h"
#include "VpnLog.h"
#include "KnownAnswerTests.h"

// --- Objects and rekey helpers defined in esp32_client.ino ---
extern WiFiClient   networkClient;
extern AuthManager  auth;
extern SecureTunnel tunnel;
bool startRekey();
bool finishRekey(const uint8_t* payload, size_t len);
void cancelRekey();

// Algorithm ID 0x03 = ML-DSA-44 + ML-KEM-512 (PQC_VPN), 0x01 = Ed25519 + X25519 (Non_PQC_VPN)
static const char* VPN_NAME = (ALGORITHM_ID == 0x03) ? "PQC VPN (ML-DSA-44 + ML-KEM-512 + AES-256-GCM)"
                                                     : "Classical VPN (Ed25519 + X25519 + AES-256-GCM)";

// ============================================================================
// Statistics helper (mean / median / 95th percentile / std / min / max)
// ============================================================================
static const int MAX_SAMPLES = 800;   // B4b records one ACK latency per message (750 in 30 s)

struct Stats {
  float v[MAX_SAMPLES];
  int   n = 0;
  void  reset() { n = 0; }
  void  add(float x) { if (n < MAX_SAMPLES) v[n++] = x; }
  float mean() const { double s = 0; for (int i = 0; i < n; i++) s += v[i]; return n ? s / n : 0; }
  float stdev() const {
    if (n < 2) return 0;
    double m = mean(), s = 0;
    for (int i = 0; i < n; i++) s += (v[i] - m) * (v[i] - m);
    return sqrt(s / (n - 1));
  }
  float minv() const { float m = n ? v[0] : 0; for (int i = 1; i < n; i++) m = min(m, v[i]); return m; }
  float maxv() const { float m = n ? v[0] : 0; for (int i = 1; i < n; i++) m = max(m, v[i]); return m; }
  float percentile(float p) const {          // Linear interpolation between closest ranks
    if (n == 0) return 0;
    static float tmp[MAX_SAMPLES];
    memcpy(tmp, v, n * sizeof(float));
    std::sort(tmp, tmp + n);
    float rank = p / 100.0f * (n - 1);
    int lo = (int)rank;
    int hi = lo + 1 < n ? lo + 1 : lo;
    return tmp[lo] + (tmp[hi] - tmp[lo]) * (rank - lo);
  }
  float median() const { return percentile(50); }
};

static void reportStats(const char* id, const char* name, const Stats& s, const char* unit) {
  Serial.printf("  %-4s %-40s n=%-4d mean=%9.3f median=%9.3f p95=%9.3f std=%8.3f min=%9.3f max=%9.3f %s\n",
                id, name, s.n, s.mean(), s.median(), s.percentile(95), s.stdev(), s.minv(), s.maxv(), unit);
  Serial.printf("BENCH,%s,%s,%d,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%s\n", id, name, s.n, s.mean(), s.median(),
                s.percentile(95), s.stdev(), s.minv(), s.maxv(), unit);
}

static void reportValue(const char* id, const char* name, double value, const char* unit) {
  Serial.printf("  %-4s %-40s %12.3f %s\n", id, name, value, unit);
  Serial.printf("BENCH,%s,%s,1,%.4f,%.4f,%.4f,0,%.4f,%.4f,%s\n", id, name, value, value, value, value, value, unit);
}

static void section(const char* title) {
  Serial.println();
  Serial.println("------------------------------------------------------------------------------");
  Serial.println(title);
  Serial.println("------------------------------------------------------------------------------");
}

// ============================================================================
// CPU load from FreeRTOS run-time statistics: the time each core's idle task
// ran, compared with the elapsed time (both in microseconds from esp_timer).
// This counts ALL work on the chip: our crypto, the TCP/IP stack and Wi-Fi.
// ============================================================================
struct CpuWindow {
  uint32_t t0, idle0, idle1;
  void start() {
    t0    = (uint32_t)esp_timer_get_time();
    idle0 = ulTaskGetIdleRunTimeCounterForCore(0);
    idle1 = ulTaskGetIdleRunTimeCounterForCore(1);
  }
  // Busy percentage of one core (0 or 1) since start()
  float busyPct(int core) const {
    uint32_t elapsed = (uint32_t)esp_timer_get_time() - t0;
    uint32_t idle = ulTaskGetIdleRunTimeCounterForCore(core) - (core == 0 ? idle0 : idle1);
    if (elapsed == 0) return 0;
    float pct = 100.0f - 100.0f * idle / elapsed;
    return pct < 0 ? 0 : pct;
  }
};

// ============================================================================
// Tunnel helpers
// ============================================================================
static uint8_t rxBuf[SecureTunnel::MAX_PLAINTEXT];

// While true, waiting loops sleep for one scheduler tick instead of spinning, so the
// waiting itself does not count as CPU load (used during CPU measurements only;
// latency tests spin for microsecond-accurate timing).
static bool gYieldWhileWaiting = false;

static void waitALittle() {
  if (gYieldWhileWaiting) vTaskDelay(1);
  else delayMicroseconds(50);
}

// Receives at most one frame. Returns its TYPE (DATA / REKEY_RESP), 0 if none, -1 on failure.
// A REKEY_RESP is applied (new keys installed) before returning.
static int pumpOne() {
  int n = tunnel.poll(rxBuf, sizeof(rxBuf));
  if (n < 0) return -1;
  if (n == 0) return (!networkClient.connected() && !networkClient.available()) ? -1 : 0;
  uint8_t type = tunnel.lastType();
  if (type == SecureTunnel::MSG_REKEY_RESP && !finishRekey(rxBuf, n)) return -1;
  return type;
}

// Waits for a message of type `want`. Returns 1 when found, 0 on timeout, -1 on failure.
static int waitFor(uint8_t want, unsigned long timeoutMs) {
  unsigned long t0 = millis();
  while (millis() - t0 < timeoutMs) {
    int t = pumpOne();
    if (t < 0) return -1;
    if (t == want) return 1;
    if (t == 0) waitALittle();
  }
  return 0;
}

static bool rekeyDue() {
  return (tunnel.framesSent() >= REKEY_AFTER_MESSAGES && tunnel.keyAgeMs() >= REKEY_MIN_AGE_MS) ||
         tunnel.keyAgeMs() >= REKEY_AFTER_MS;
}

// Rekeys now if the normal client policy says so (long tests stay within the gateway policy).
// Must only be called when no DATA message is waiting for its ACK.
static bool rekeyIfDue(int* rekeys) {
  if (!rekeyDue()) return true;
  if (!startRekey() || waitFor(SecureTunnel::MSG_REKEY_RESP, REKEY_RESPONSE_TIMEOUT_MS) != 1) return false;
  if (rekeys) (*rekeys)++;
  return true;
}

// Sends one DATA message and waits for its encrypted ACK. Returns the round trip in ms, or -1.
static float vpnRoundTrip(const uint8_t* msg, size_t len) {
  unsigned long t0 = micros();
  if (!tunnel.send(msg, len)) return -1;
  if (waitFor(SecureTunnel::MSG_DATA, 5000) != 1) return -1;
  return (micros() - t0) / 1000.0f;
}

static bool openVpnSession() {
  networkClient.stop();
  cancelRekey();
  if (!networkClient.connect(GATEWAY_IP, GATEWAY_PORT)) return false;
  networkClient.setNoDelay(true);
  return auth.performMutualAuthentication() && tunnel.begin(auth.getSessionKey());
}

// ============================================================================
// B0: known-answer tests for every algorithm the VPN uses (KnownAnswerTests.cpp)
// ============================================================================
static bool benchKnownAnswer() {
  section("[B0] KNOWN-ANSWER TESTS: every algorithm the VPN uses, checked against official / reference vectors");
  return runKnownAnswerTests();
}

// ============================================================================
// B1: per-message AES-256-GCM cost on the ESP32 (hardware AES, no network)
// ============================================================================
static void benchLocalAes() {
  section("[B1] PER-MESSAGE AES-256-GCM COST ON THE ESP32 (200 runs per size, no network)");
  const size_t sizes[] = { 64, 256, 1023 };
  static uint8_t pt[1024], ct[1024], out[1024];
  uint8_t key[32], iv[12], aad[10], tag[16];
  randombytes_buf(key, sizeof(key));
  randombytes_buf(pt, sizeof(pt));
  memset(iv, 0, sizeof(iv));
  memset(aad, 0x5A, sizeof(aad));

  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);
  mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
  static Stats enc, dec;
  for (size_t size : sizes) {
    enc.reset();
    dec.reset();
    for (int i = 0; i < 200; i++) {
      iv[11] = (uint8_t)i;
      unsigned long t0 = micros();
      mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, size, iv, 12, aad, sizeof(aad), pt, ct, 16, tag);
      unsigned long t1 = micros();
      mbedtls_gcm_auth_decrypt(&ctx, size, iv, 12, aad, sizeof(aad), tag, 16, ct, out);
      unsigned long t2 = micros();
      enc.add((t1 - t0) / 1000.0f);
      dec.add((t2 - t1) / 1000.0f);
    }
    char name[48];
    snprintf(name, sizeof(name), "aes_gcm_encrypt_%uB", (unsigned)size);
    reportStats("B1", name, enc, "ms");
    snprintf(name, sizeof(name), "aes_gcm_decrypt_%uB", (unsigned)size);
    reportStats("B1", name, dec, "ms");
    snprintf(name, sizeof(name), "aes_gcm_encrypt_plus_decrypt_%uB_per_KB", (unsigned)size);
    reportValue("B1", name, (enc.mean() + dec.mean()) * 1024.0 / size, "ms/KB");
  }
  mbedtls_gcm_free(&ctx);
}

// ============================================================================
// B2: full handshake time over real Wi-Fi (TCP connect + MSG 1-4)
// ============================================================================
static void benchHandshake() {
  char title[140];
  snprintf(title, sizeof(title), "[B2] HANDSHAKE TIME OVER WI-FI (%d runs, %lu ms apart to respect the gateway rate limit)",
           BENCH_HANDSHAKES, BENCH_HANDSHAKE_GAP_MS);
  section(title);
  static Stats tcp, hs, total;
  tcp.reset(); hs.reset(); total.reset();
  int failures = 0;
  for (int i = 0; i < BENCH_HANDSHAKES; i++) {
    networkClient.stop();
    delay(BENCH_HANDSHAKE_GAP_MS);
    unsigned long t0 = micros();
    bool connected = networkClient.connect(GATEWAY_IP, GATEWAY_PORT);
    unsigned long t1 = micros();
    if (!connected) { failures++; continue; }
    networkClient.setNoDelay(true);
    bool ok = auth.performMutualAuthentication();
    unsigned long t2 = micros();
    if (!ok) { failures++; continue; }
    tcp.add((t1 - t0) / 1000.0f);
    hs.add((t2 - t1) / 1000.0f);
    total.add((t2 - t0) / 1000.0f);
    if ((i + 1) % 10 == 0) Serial.printf("  ... %d/%d handshakes done\n", i + 1, BENCH_HANDSHAKES);
  }
  networkClient.stop();
  reportStats("B2", "tcp_connect_time", tcp, "ms");
  reportStats("B2", "handshake_msg1_to_msg4", hs, "ms");
  reportStats("B2", "connect_plus_handshake_total", total, "ms");
  reportValue("B2", "handshake_failures", failures, "count");
  reportValue("B2", "handshake_bytes_on_wire",
              MSG1_CLIENT_HELLO_SIZE + MSG2_SERVER_PROOF_SIZE + MSG3_CLIENT_PROOF_SIZE + MSG4_AUTH_VERDICT_SIZE, "bytes");
}

// ============================================================================
// B3: added round-trip latency: encrypted VPN message vs. plain TCP echo.
// The two are measured ALTERNATELY (plain, VPN, plain, VPN, ...) so that changes
// in Wi-Fi conditions during the test affect both equally.
// ============================================================================
static void benchLatency() {
  char title[140];
  snprintf(title, sizeof(title), "[B3] ROUND-TRIP LATENCY: PLAIN TCP vs. ENCRYPTED VPN, alternating, %d pairs per size",
           BENCH_LATENCY_PAIRS);
  section(title);
  const size_t sizes[] = { 64, 1023 };
  static uint8_t msg[1024], back[1024];
  memset(msg, 'x', sizeof(msg));

  WiFiClient echo;
  bool haveEcho = echo.connect(GATEWAY_IP, BENCH_ECHO_PORT);
  if (haveEcho) echo.setNoDelay(true);
  else Serial.printf("  (No plain echo server on %s:%u -> baseline skipped. Run gateway_benchmark.py --serve)\n",
                     GATEWAY_IP, (unsigned)BENCH_ECHO_PORT);

  static Stats plain, vpn;
  for (size_t size : sizes) {
    plain.reset();
    vpn.reset();
    for (int i = 0; i < BENCH_LATENCY_PAIRS; i++) {
      if (haveEcho) {
        unsigned long t0 = micros();
        echo.write(msg, size);
        size_t got = 0;
        unsigned long start = millis();
        while (got < size && millis() - start < 3000) {
          int a = echo.available();
          if (a > 0) got += echo.read(back + got, size - got);
          else delayMicroseconds(50);
        }
        if (got == size) plain.add((micros() - t0) / 1000.0f);
      }
      if (!rekeyIfDue(nullptr)) break;
      float rtt = vpnRoundTrip(msg, size);
      if (rtt >= 0) vpn.add(rtt);
      delay(10);
    }
    char name[48];
    snprintf(name, sizeof(name), "rtt_plain_tcp_%uB", (unsigned)size);
    if (haveEcho) reportStats("B3", name, plain, "ms");
    snprintf(name, sizeof(name), "rtt_vpn_encrypted_%uB", (unsigned)size);
    reportStats("B3", name, vpn, "ms");
    if (haveEcho && plain.n && vpn.n) {
      snprintf(name, sizeof(name), "added_latency_median_%uB", (unsigned)size);
      reportValue("B3", name, vpn.median() - plain.median(), "ms");
      snprintf(name, sizeof(name), "added_latency_mean_%uB", (unsigned)size);
      reportValue("B3", name, vpn.mean() - plain.mean(), "ms");
    }
  }
  echo.stop();
}

// ============================================================================
// B4: throughput.
//  B4a  Maximum goodput: up to BENCH_PIPELINE_WINDOW messages in flight (the next one is
//       sent without waiting for the previous ACK). Only bytes the gateway acknowledged
//       count, and the remaining ACKs are drained before the clock stops.
//  B4b  Sustained fixed rate: one 512-byte message every BENCH_FIXED_RATE_INTERVAL_MS,
//       sent on schedule whether or not earlier ACKs arrived. Reports the delivered
//       rate and the ACK latency, which stays flat if the VPN keeps up. CPU load is
//       measured during this test as well (see B6).
// ============================================================================
static const int ACK_FIFO = 64;
// The gateway allows at most 2,000 messages per key and one rekey per 5 s. A fast sender pauses
// here (like any well-behaved client must) until the key is old enough to be replaced.
static const uint64_t PAUSE_AT_FRAMES = 1900;

static void benchThroughputMax() {
  char title[140];
  snprintf(title, sizeof(title), "[B4a] MAXIMUM GOODPUT (%lu s, 1,023-byte messages, up to %d in flight, gateway-ACKed bytes only)",
           BENCH_THROUGHPUT_MS / 1000, BENCH_PIPELINE_WINDOW);
  section(title);
  static uint8_t msg[1023];
  memset(msg, 'T', sizeof(msg));
  uint32_t acked = 0;
  int outstanding = 0, rekeys = 0;
  bool failed = false;
  unsigned long start = millis();

  while (!failed && millis() - start < BENCH_THROUGHPUT_MS) {
    if (rekeyDue()) {                       // Rekey only with nothing in flight
      while (!failed && outstanding > 0) {
        int t = pumpOne();
        if (t < 0) failed = true;
        else if (t == SecureTunnel::MSG_DATA) { outstanding--; acked++; }
      }
      if (failed || !rekeyIfDue(&rekeys)) { failed = true; break; }
    }
    while (outstanding < BENCH_PIPELINE_WINDOW && !rekeyDue() && tunnel.framesSent() < PAUSE_AT_FRAMES) {
      if (!tunnel.send(msg, sizeof(msg))) { failed = true; break; }
      outstanding++;
    }
    int t = pumpOne();
    if (t < 0) failed = true;
    else if (t == SecureTunnel::MSG_DATA) { outstanding--; acked++; }
  }
  unsigned long drainStart = millis();      // Count the messages still in flight
  while (!failed && outstanding > 0 && millis() - drainStart < 5000) {
    int t = pumpOne();
    if (t < 0) failed = true;
    else if (t == SecureTunnel::MSG_DATA) { outstanding--; acked++; }
  }
  float seconds = (millis() - start) / 1000.0f;
  reportValue("B4a", "messages_acked", acked, "count");
  reportValue("B4a", "max_goodput_application_data", acked * sizeof(msg) * 8 / seconds / 1000.0, "kbps");
  reportValue("B4a", "messages_per_second", acked / seconds, "msg/s");
  reportValue("B4a", "rekeys_during_test", rekeys, "count");
  reportValue("B4a", "failed", failed ? 1 : 0, "bool");
}

static void benchThroughputFixedRate(float* cpuCore0, float* cpuCore1) {
  const size_t size = 512;
  char title[160];
  snprintf(title, sizeof(title), "[B4b] SUSTAINED FIXED RATE (%lu s, 512 B every %lu ms = %.1f kbps offered, sent on schedule)",
           BENCH_THROUGHPUT_MS / 1000, BENCH_FIXED_RATE_INTERVAL_MS, size * 8.0 / BENCH_FIXED_RATE_INTERVAL_MS);
  section(title);
  static uint8_t msg[size];
  memset(msg, 'R', sizeof(msg));
  static unsigned long sentAt[ACK_FIFO];   // ACKs arrive in order: a FIFO matches them to their message
  static Stats ackLatency;
  ackLatency.reset();
  int head = 0, tail = 0, outstanding = 0, rekeys = 0;
  uint32_t sent = 0, acked = 0;
  bool failed = false;

  gYieldWhileWaiting = true;               // Waiting must not show up as CPU load
  CpuWindow cpu;
  cpu.start();
  unsigned long start = millis(), nextSend = start;
  while (!failed && millis() - start < BENCH_THROUGHPUT_MS) {
    if (millis() >= nextSend) {
      if (rekeyDue() && outstanding == 0) {
        if (!rekeyIfDue(&rekeys)) { failed = true; break; }
      }
      if (outstanding < ACK_FIFO && tunnel.send(msg, size)) {
        sentAt[head] = micros();
        head = (head + 1) % ACK_FIFO;
        outstanding++;
        sent++;
      } else if (outstanding >= ACK_FIFO) {
        failed = true;                      // 64 messages without an ACK: the link cannot keep up
      }
      nextSend += BENCH_FIXED_RATE_INTERVAL_MS;
    }
    int t = pumpOne();
    if (t < 0) failed = true;
    else if (t == SecureTunnel::MSG_DATA && outstanding > 0) {
      ackLatency.add((micros() - sentAt[tail]) / 1000.0f);
      tail = (tail + 1) % ACK_FIFO;
      outstanding--;
      acked++;
    } else if (t == 0) {
      vTaskDelay(1);
    }
  }
  // A failed stream is not a valid CPU measurement: mark it so B6 skips it
  *cpuCore0 = failed ? -1.0f : cpu.busyPct(0);
  *cpuCore1 = failed ? -1.0f : cpu.busyPct(1);
  gYieldWhileWaiting = false;
  float seconds = (millis() - start) / 1000.0f;
  reportValue("B4b", "offered_rate", size * 8.0 / BENCH_FIXED_RATE_INTERVAL_MS, "kbps");
  reportValue("B4b", "delivered_rate_gateway_acked", acked * size * 8 / seconds / 1000.0, "kbps");
  reportValue("B4b", "messages_sent", sent, "count");
  reportValue("B4b", "messages_acked", acked, "count");
  reportStats("B4b", "ack_latency_under_load", ackLatency, "ms");
  reportValue("B4b", "rekeys_during_test", rekeys, "count");
  reportValue("B4b", "failed", failed ? 1 : 0, "bool");
}

// ============================================================================
// B5: rekey time (fresh key exchange inside the tunnel)
// ============================================================================
static void benchRekey() {
  char title[120];
  snprintf(title, sizeof(title), "[B5] REKEY TIME (REKEY_REQ -> REKEY_RESP -> new keys installed), %d runs", BENCH_REKEY_RUNS);
  section(title);
  static const uint8_t ping[] = "BENCH_KEEPALIVE";
  static Stats rk;
  rk.reset();
  for (int i = 0; i < BENCH_REKEY_RUNS; i++) {
    // The gateway refuses rekeys less than 5 s apart: keep the tunnel busy until the key is old enough
    while (tunnel.keyAgeMs() < REKEY_MIN_AGE_MS) {
      if (vpnRoundTrip(ping, sizeof(ping) - 1) < 0) { Serial.println("  tunnel lost"); return; }
      delay(1000);
    }
    // One message right before the timed rekey keeps the Wi-Fi link awake: after ~1 s without
    // traffic, access points (phone hotspots in particular) sleep their radio and the next packet
    // waits up to one beacon interval (~100 ms), which would be measured as "rekey time".
    if (vpnRoundTrip(ping, sizeof(ping) - 1) < 0) { Serial.println("  tunnel lost"); return; }
    unsigned long t0 = micros();
    bool ok = startRekey() && waitFor(SecureTunnel::MSG_REKEY_RESP, REKEY_RESPONSE_TIMEOUT_MS) == 1;
    unsigned long t1 = micros();
    if (ok) rk.add((t1 - t0) / 1000.0f);
    if ((i + 1) % 5 == 0) Serial.printf("  ... %d/%d rekeys done\n", i + 1, BENCH_REKEY_RUNS);
  }
  reportStats("B5", "rekey_time", rk, "ms");
}

// ============================================================================
// B6: CPU load of the whole chip (FreeRTOS idle-task run time on both cores)
//   idle tunnel  : tunnel open, nothing sent      -> cost of Wi-Fi + TCP alone
//   normal use   : one encrypted ping every 1.5 s -> what the VPN costs day to day
//   sustained    : 512 B every 40 ms (B4b)        -> a heavy, steady sensor stream
// ============================================================================
// Returns false if the tunnel was lost: the window is then too short to mean anything
static bool measureCpu(const char* label, unsigned long durationMs, bool sendPings, float* c0, float* c1) {
  static const uint8_t ping[] = "[bench] STATUS_PING";
  gYieldWhileWaiting = true;
  bool ok = true;
  CpuWindow cpu;
  cpu.start();
  unsigned long start = millis(), lastPing = start;
  while (millis() - start < durationMs) {
    if (sendPings && millis() - lastPing >= 1500) {
      lastPing = millis();
      tunnel.send(ping, sizeof(ping) - 1);
    }
    if (pumpOne() < 0) { Serial.printf("  (%s: tunnel lost)\n", label); ok = false; break; }
    vTaskDelay(pdMS_TO_TICKS(5));
  }
  *c0 = cpu.busyPct(0);
  *c1 = cpu.busyPct(1);
  gYieldWhileWaiting = false;
  return ok;
}

static void reportCpu(const char* name, bool ok, float c0, float c1) {
  char metric[64];
  if (!ok) {
    Serial.printf("  B6   cpu_%s skipped: the tunnel was lost, so no valid measurement\n", name);
    return;
  }
  snprintf(metric, sizeof(metric), "cpu_%s_core0", name);   reportValue("B6", metric, c0, "%");
  snprintf(metric, sizeof(metric), "cpu_%s_core1", name);   reportValue("B6", metric, c1, "%");
  snprintf(metric, sizeof(metric), "cpu_%s_average", name); reportValue("B6", metric, (c0 + c1) / 2, "%");
}

static void benchCpuLoad(float sustainedCore0, float sustainedCore1) {
  section("[B6] CPU LOAD OF THE WHOLE ESP32 (FreeRTOS idle-task run time, core 0 = Wi-Fi/TCP, core 1 = VPN)");
  float i0 = 0, i1 = 0, n0 = 0, n1 = 0;
  bool idleOk = measureCpu("idle tunnel", 20000, false, &i0, &i1);   // < 30 s: the gateway closes idle tunnels at 30 s
  bool normalOk = idleOk && measureCpu("normal use", 20000, true, &n0, &n1);
  reportCpu("idle_tunnel", idleOk, i0, i1);
  reportCpu("normal_ping", normalOk, n0, n1);
  reportCpu("sustained_512B", sustainedCore0 >= 0 && sustainedCore1 >= 0, sustainedCore0, sustainedCore1);
}

// ============================================================================
// B7: memory and flash
// ============================================================================
static void benchMemory() {
  section("[B7] MEMORY AND FLASH");
  reportValue("B7", "heap_total", ESP.getHeapSize(), "bytes");
  reportValue("B7", "heap_peak_used", ESP.getHeapSize() - ESP.getMinFreeHeap(), "bytes");
  reportValue("B7", "heap_free_now", ESP.getFreeHeap(), "bytes");
  reportValue("B7", "task_stack_never_used", uxTaskGetStackHighWaterMark(NULL), "bytes");
  reportValue("B7", "flash_firmware_size", ESP.getSketchSize(), "bytes");
}

// ============================================================================
// Entry point
// ============================================================================
void runSystemBenchmark() {
  Serial.println("\n==============================================================================");
  Serial.printf ("SYSTEM BENCHMARK: %s\n", VPN_NAME);
  Serial.printf ("Gateway %s:%u | ESP32 @ %u MHz | handshake/tunnel output silenced while measuring\n",
                 GATEWAY_IP, (unsigned)GATEWAY_PORT, (unsigned)getCpuFrequencyMhz());
  Serial.println("==============================================================================");
  Serial.println("BENCH,id,metric,n,mean,median,p95,std,min,max,unit");

  VpnSerial.quiet = true;   // Printing at 115200 baud would distort every timing
  benchKnownAnswer();
  benchLocalAes();
  benchHandshake();

  section("Opening one VPN session for tests B3-B6 ...");
  // B2 used up the gateway's rate limit (5 connections per IP per 10 s): wait for the window to clear
  Serial.println("  Waiting 11 s for the gateway's per-IP rate-limit window to clear...");
  delay(11000);
  if (!openVpnSession()) {
    Serial.println("  Could not open a VPN session. Is the gateway running and this device registered?");
  } else {
    float s0 = 0, s1 = 0;
    benchLatency();
    benchThroughputMax();
    benchThroughputFixedRate(&s0, &s1);
    benchRekey();
    benchCpuLoad(s0, s1);
  }
  networkClient.stop();
  tunnel.end();
  benchMemory();
  VpnSerial.quiet = false;

  Serial.println("\n==============================================================================");
  Serial.println("BENCHMARK COMPLETE. Copy the BENCH,... lines into a .csv file to keep the results.");
  Serial.println("==============================================================================");
}
