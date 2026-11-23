// sig_bench_unified.ino - Steps 1 and 2 (experiments E1 and E2) of the drone authentication study.
//   Send S: Step 1, all algorithms on 64-byte messages (this file)
//   Send P: Step 2, message size and largest signable message (e2_payload.ino)
//
// Times Ed25519, ECDSA P-256, RSA-3072, ML-DSA-44, ML-DSA-65 and ML-DSA-87 on ONE ESP32,
// in ONE firmware, under the same conditions, so the numbers can be compared directly:
//   * CPU fixed at 240 MHz (checked), Wi-Fi and Bluetooth never started
//   * every measurement runs in a fresh FreeRTOS task on core 1 with the same stack size
//   * the same 1,000 messages (64 bytes, all different) are signed by every algorithm
//   * timing with the CPU cycle counter (RSA key generation: esp_timer, it can exceed 17 s)
//   * nothing is printed while a timed loop runs (the UART is flushed before each loop)
//   * a known-answer test against an independent reference must pass before timing
//
// Output: machine-readable lines (META, KAT, SIZE, RAW, SUM, STACK, HEAP, LEAK) between
// "### BEGIN SIG_BENCH" and "### END SIG_BENCH", then a readable summary table.
// Save it with tools/capture_serial.py, then run tools/analyze_sig_bench.py.
//
// Arduino IDE: Board "ESP32 Dev Module", CPU Frequency "240MHz (WiFi/BT)".
// Open the Serial Monitor at 115200 baud and send "S" to start (or let capture_serial.py do it).

#include <Arduino.h>
#include <esp_heap_caps.h>
#include <esp_timer.h>
#include <esp_system.h>
#include <esp_arduino_version.h>
#include <sodium.h>
#include "mbedtls/version.h"

#include "bench_config.h"
#include "algorithms.h"

static_assert(RSA_KEYGEN_RUNS <= BENCH_RUNS, "RSA_KEYGEN_RUNS must not exceed BENCH_RUNS");
static_assert(BENCH_RUNS <= 65535, "BENCH_RUNS too large");

// ---- Sample storage (static, so it never sits on a measured stack) ---------------------
static uint64_t s_keygen[BENCH_RUNS];
static uint64_t s_sign[BENCH_RUNS];
static uint64_t s_verify[BENCH_RUNS];
static uint16_t s_siglen[BENCH_RUNS];

static uint8_t g_msg[MSG_SIZE];
static uint8_t g_sig[MAX_SIG_BYTES];
static size_t g_siglen = 0;
static uint32_t g_stack_bytes = 0;               // stack size given to every measurement task
static uint32_t g_stack_baseline = 0;            // stack used by an empty measurement task
static volatile size_t g_probe_heap = 0;
static volatile int g_probe_rc = 0;

struct Stats {
  int n, fails;
  double min_us, median_us, mean_us, p95_us, p99_us, max_us, std_us;
};

struct AlgResult {
  bool done, kat;
  Stats keygen, sign, verify;
  uint32_t sig_min, sig_max;
  double sig_mean;
  size_t sk_bytes;
  uint32_t stack[3];
  size_t heap[3];
};
static AlgResult g_results[8];
static const char* const OP_NAMES[3] = {"keygen", "sign", "verify"};

// ---- Small helpers --------------------------------------------------------------------
static inline uint32_t cycles() {
  uint32_t c;
  __asm__ __volatile__("rsr %0, ccount" : "=a"(c));
  return c;
}

// The i-th test message. Identical for every algorithm: a 4-byte run number followed by
// 60 fixed pseudo-random bytes (xorshift32), so every run signs a different message.
static void make_message(uint32_t i, uint8_t* m) {
  uint32_t x = 0x9E3779B9u ^ (i * 0x85EBCA6Bu);
  for (int k = 0; k < MSG_SIZE; k++) {
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    m[k] = (uint8_t)x;
  }
  m[0] = (uint8_t)i; m[1] = (uint8_t)(i >> 8); m[2] = (uint8_t)(i >> 16); m[3] = (uint8_t)(i >> 24);
}

static int cmp_u64(const void* a, const void* b) {
  uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
  return (x > y) - (x < y);
}

// Sorts the samples in place, so the RAW lines must be printed before this is called.
static Stats compute_stats(uint64_t* samples, int n, int fails) {
  Stats s = {n, fails, 0, 0, 0, 0, 0, 0, 0};
  if (n <= 0) return s;
  uint64_t* s_sorted = samples;
  qsort(s_sorted, n, sizeof(uint64_t), cmp_u64);
  const double per_us = (double)CPU_MHZ;
  double sum = 0;
  for (int i = 0; i < n; i++) sum += s_sorted[i];
  s.mean_us = sum / n / per_us;
  double var = 0;
  for (int i = 0; i < n; i++) {
    double d = s_sorted[i] / per_us - s.mean_us;
    var += d * d;
  }
  s.std_us = n > 1 ? sqrt(var / (n - 1)) : 0;
  s.min_us = s_sorted[0] / per_us;
  s.max_us = s_sorted[n - 1] / per_us;
  s.median_us = (n % 2 ? s_sorted[n / 2] : (s_sorted[n / 2 - 1] + s_sorted[n / 2]) / 2.0) / per_us;
  int i95 = (int)ceil(0.95 * n) - 1, i99 = (int)ceil(0.99 * n) - 1;   // nearest-rank percentiles
  s.p95_us = s_sorted[i95 < 0 ? 0 : i95] / per_us;
  s.p99_us = s_sorted[i99 < 0 ? 0 : i99] / per_us;
  return s;
}

static void print_raw(const char* alg, const char* op, const uint64_t* samples, int n) {
  for (int i = 0; i < n; i += RAW_PER_LINE) {
    Serial.printf("RAW,%s,%s,%d,", alg, op, i);
    for (int k = i; k < n && k < i + RAW_PER_LINE; k++) Serial.printf(k == i ? "%llu" : " %llu", samples[k]);
    Serial.println();
  }
}

static void print_stats(const char* alg, const char* op, const Stats& s) {
  Serial.printf("SUM,%s,%s,n=%d,fail=%d,min_us=%.3f,median_us=%.3f,mean_us=%.3f,p95_us=%.3f,"
                "p99_us=%.3f,max_us=%.3f,std_us=%.3f\n",
                alg, op, s.n, s.fails, s.min_us, s.median_us, s.mean_us, s.p95_us, s.p99_us, s.max_us, s.std_us);
}

// ---- Running a function in a fresh measurement task -----------------------------------
// FreeRTOS fills a new task's stack with a known byte, so after the function returns the
// high-water mark tells how much stack it really used.
struct TaskJob {
  void (*fn)(void*);
  void* arg;
  SemaphoreHandle_t done;
  UBaseType_t free_min;
};

static void job_entry(void* p) {
  TaskJob* j = (TaskJob*)p;
  j->fn(j->arg);
  j->free_min = uxTaskGetStackHighWaterMark(NULL);
  xSemaphoreGive(j->done);
  vTaskDelete(NULL);
}

// Runs fn in a new task with stack_bytes of stack. quiet: no ERROR line if the task cannot be
// created (used by Step 2's largest-message search, where running out of memory is expected).
static bool run_in_task_stack(void (*fn)(void*), void* arg, uint32_t stack_bytes, uint32_t* stack_used,
                              bool quiet = false) {
  TaskJob j = {fn, arg, xSemaphoreCreateBinary(), 0};
  if (j.done == NULL) return false;
  if (xTaskCreatePinnedToCore(job_entry, "measure", stack_bytes, &j, BENCH_PRIORITY, NULL, BENCH_CORE) != pdPASS) {
    if (!quiet) Serial.printf("ERROR,task,could not create a task with %u bytes of stack\n", (unsigned)stack_bytes);
    vSemaphoreDelete(j.done);
    return false;
  }
  xSemaphoreTake(j.done, portMAX_DELAY);
  vSemaphoreDelete(j.done);
  delay(20);                                     // let the idle task free the finished task's stack
  if (stack_used) *stack_used = stack_bytes - (uint32_t)(j.free_min * sizeof(StackType_t));
  return true;
}

static bool run_in_task(void (*fn)(void*), void* arg, uint32_t* stack_used) {
  return run_in_task_stack(fn, arg, g_stack_bytes, stack_used);
}

// ---- The timed loops for one algorithm (runs inside a measurement task) ----------------
static void bench_one(void* p) {
  const SigAlgorithm* a = (const SigAlgorithm*)p;
  int idx = -1;
  for (int k = 0; k < ALGORITHM_COUNT; k++) if (ALGORITHMS[k] == a) idx = k;
  AlgResult& r = g_results[idx];

  // 1. Known-answer test: an algorithm that fails it is not timed
  r.kat = a->kat();
  Serial.printf("KAT,%s,%s\n", a->name, r.kat ? "PASS" : "FAIL");
  if (!r.kat) { Serial.flush(); return; }

  // 2. Key generation
  int n = a->keygen_runs, fails = 0;
  Serial.printf("PROGRESS,%s,timing %d key generations\n", a->name, n);
  Serial.flush();
  for (int w = 0; w < (a->slow_keygen ? 1 : WARMUP_RUNS); w++) a->keygen_once();
  for (int i = 0; i < n; i++) {
    vTaskDelay(1);
    int rc;
    if (a->slow_keygen) {
      int64_t t0 = esp_timer_get_time();
      rc = a->keygen_once();
      s_keygen[i] = (uint64_t)(esp_timer_get_time() - t0) * CPU_MHZ;   // stored as cycles too
    } else {
      uint32_t t0 = cycles();
      rc = a->keygen_once();
      s_keygen[i] = cycles() - t0;
    }
    if (rc != 0) fails++;
  }
  print_raw(a->name, "keygen", s_keygen, n);
  r.keygen = compute_stats(s_keygen, n, fails);
  print_stats(a->name, "keygen", r.keygen);

  // 3. Signing and verifying, with one key, on BENCH_RUNS different messages
  if (a->make_bench_key() != 0) {
    Serial.printf("ERROR,%s,could not make the benchmark key\n", a->name);
    return;
  }
  Serial.printf("PROGRESS,%s,timing %d signatures and verifications\n", a->name, BENCH_RUNS);
  Serial.flush();
  for (int w = 0; w < WARMUP_RUNS; w++) {         // warm-up messages are not in the timed set
    make_message(BENCH_RUNS + w, g_msg);
    a->sign(g_msg, MSG_SIZE, g_sig, &g_siglen);
    a->verify(g_msg, MSG_SIZE, g_sig, g_siglen);
  }
  int sfails = 0, vfails = 0;
  uint32_t smin = UINT32_MAX, smax = 0;
  double ssum = 0;
  for (int i = 0; i < BENCH_RUNS; i++) {
    make_message(i, g_msg);
    vTaskDelay(1);
    uint32_t t0 = cycles();
    int rc = a->sign(g_msg, MSG_SIZE, g_sig, &g_siglen);
    s_sign[i] = cycles() - t0;
    if (rc != 0) sfails++;
    s_siglen[i] = (uint16_t)g_siglen;
    t0 = cycles();
    rc = a->verify(g_msg, MSG_SIZE, g_sig, g_siglen);
    s_verify[i] = cycles() - t0;
    if (rc != 0) vfails++;
    if (g_siglen < smin) smin = g_siglen;
    if (g_siglen > smax) smax = g_siglen;
    ssum += g_siglen;
  }
  print_raw(a->name, "sign", s_sign, BENCH_RUNS);
  print_raw(a->name, "verify", s_verify, BENCH_RUNS);
  r.sign = compute_stats(s_sign, BENCH_RUNS, sfails);
  r.verify = compute_stats(s_verify, BENCH_RUNS, vfails);
  print_stats(a->name, "sign", r.sign);
  print_stats(a->name, "verify", r.verify);

  r.sig_min = smin;
  r.sig_max = smax;
  r.sig_mean = ssum / BENCH_RUNS;
  r.sk_bytes = a->sk_bytes();
  Serial.printf("SIZE,%s,pk=%u,sk=%u,sig_min=%u,sig_max=%u,sig_mean=%.2f\n", a->name,
                (unsigned)a->pk_bytes, (unsigned)r.sk_bytes, (unsigned)smin, (unsigned)smax, r.sig_mean);
  r.done = true;
  Serial.flush();
}

// ---- Stack and heap of one operation (each in its own fresh task) ----------------------
static const SigAlgorithm* g_probe_alg = nullptr;

static void probe_empty(void*) {}

// Check of the stack meter itself: this function writes a 16,384-byte local array, so the
// meter must report a little more than 16,384 bytes (the array plus one small call frame).
static const int CALIBRATION_BYTES = 16384;
static void probe_calibration(void*) {
  volatile uint8_t buf[CALIBRATION_BYTES];
  for (int i = 0; i < CALIBRATION_BYTES; i++) buf[i] = (uint8_t)(i * 7 + 1);
  (void)buf[CALIBRATION_BYTES / 2];
}
static void probe_keygen(void*) {
  heap_track_start();
  g_probe_rc = g_probe_alg->keygen_once();
  g_probe_heap = heap_track_stop();
}
static void probe_sign(void*) {
  make_message(0, g_msg);
  heap_track_start();
  g_probe_rc = g_probe_alg->sign(g_msg, MSG_SIZE, g_sig, &g_siglen);
  g_probe_heap = heap_track_stop();
}
static void probe_verify(void*) {                // checks the signature made by probe_sign
  heap_track_start();
  g_probe_rc = g_probe_alg->verify(g_msg, MSG_SIZE, g_sig, g_siglen);
  g_probe_heap = heap_track_stop();
}

static void measure_memory(int idx) {
  const SigAlgorithm* a = ALGORITHMS[idx];
  AlgResult& r = g_results[idx];
  void (*probes[3])(void*) = {probe_keygen, probe_sign, probe_verify};
  g_probe_alg = a;
  for (int op = 0; op < 3; op++) {
    uint32_t used = 0;
    g_probe_rc = 0;
    if (!run_in_task(probes[op], nullptr, &used)) return;
    r.stack[op] = used > g_stack_baseline ? used - g_stack_baseline : 0;
    r.heap[op] = g_probe_heap;
    Serial.printf("STACK,%s,%s,%u\n", a->name, OP_NAMES[op], (unsigned)r.stack[op]);
    Serial.printf("HEAP,%s,%s,%u%s\n", a->name, OP_NAMES[op], (unsigned)r.heap[op],
                  g_probe_rc == 0 ? "" : ",ERROR");
  }
}

// ---- Ed25519 is timed once more at the end: shows whether conditions stayed the same ----
static void repeat_check(void* p) {
  const SigAlgorithm* a = (const SigAlgorithm*)p;
  if (a->make_bench_key() != 0) return;
  const int n = REPEAT_RUNS < BENCH_RUNS ? REPEAT_RUNS : BENCH_RUNS;   // fits the sample array
  int fails = 0;
  for (int i = 0; i < n; i++) {
    make_message(i, g_msg);
    vTaskDelay(1);
    uint32_t t0 = cycles();
    if (a->sign(g_msg, MSG_SIZE, g_sig, &g_siglen) != 0) fails++;
    s_sign[i] = cycles() - t0;
  }
  Stats s = compute_stats(s_sign, n, fails);
  print_stats(a->name, "sign_repeat_end", s);
  a->free_bench_key();
}

// ---- Readable summary for the Serial Monitor -------------------------------------------
static void print_table() {
  Serial.println();
  Serial.println("===========================================================================================================");
  Serial.println(" Algorithm  | KAT  | keygen med | sign med / p95 / max (ms)  | verify med / p95 / max (ms) | pk B | sig B | stack sign B | heap sign B");
  Serial.println("-----------------------------------------------------------------------------------------------------------");
  for (int k = 0; k < ALGORITHM_COUNT; k++) {
    const AlgResult& r = g_results[k];
    if (!r.done) {
      Serial.printf(" %-10s | %s | not measured\n", ALGORITHMS[k]->name, r.kat ? "PASS" : "FAIL");
      continue;
    }
    Serial.printf(" %-10s | PASS | %8.2f ms | %7.2f / %7.2f / %7.2f | %7.2f / %7.2f / %7.2f  | %4u | %5u | %12u | %10u\n",
                  ALGORITHMS[k]->name, r.keygen.median_us / 1000, r.sign.median_us / 1000, r.sign.p95_us / 1000,
                  r.sign.max_us / 1000, r.verify.median_us / 1000, r.verify.p95_us / 1000, r.verify.max_us / 1000,
                  (unsigned)ALGORITHMS[k]->pk_bytes, (unsigned)r.sig_max, (unsigned)r.stack[1], (unsigned)r.heap[1]);
  }
  Serial.println("===========================================================================================================");
}

// ---- Start-up ---------------------------------------------------------------------------
static void print_meta_common() {
  Serial.println("META,firmware,sig_bench_unified v2 (Drone_Auth_Research steps 1 and 2)");
  Serial.printf("META,build,%s %s\n", __DATE__, __TIME__);
  Serial.printf("META,arduino_core,%s\n", ESP_ARDUINO_VERSION_STR);
  Serial.printf("META,esp_idf,%s\n", esp_get_idf_version());
  Serial.printf("META,mbedtls,%s\n", MBEDTLS_VERSION_STRING);
  Serial.printf("META,libsodium,%s\n", sodium_version_string());
  Serial.println("META,mldsa_native,v1.0.0-beta2 (portable C, MLD_CONFIG_REDUCE_RAM)");
  Serial.printf("META,chip,%s rev %d, %d cores\n", ESP.getChipModel(), ESP.getChipRevision(), ESP.getChipCores());
  Serial.printf("META,cpu_mhz,%u\n", (unsigned)getCpuFrequencyMhz());
  Serial.printf("META,flash,%u MB at %u MHz\n", (unsigned)(ESP.getFlashChipSize() >> 20),
                (unsigned)(ESP.getFlashChipSpeed() / 1000000));
  Serial.printf("META,sketch_bytes,%u\n", (unsigned)ESP.getSketchSize());
  Serial.printf("META,free_heap,%u\n", (unsigned)ESP.getFreeHeap());
  Serial.printf("META,largest_free_block,%u\n",
                (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
  Serial.println("META,radio,Wi-Fi and Bluetooth never started");
}

static void print_meta() {                       // Step 1
  print_meta_common();
  Serial.printf("META,runs,%d (RSA keygen %d, warm-up %d, repeat check %d)\n", BENCH_RUNS, RSA_KEYGEN_RUNS,
                WARMUP_RUNS, REPEAT_RUNS);
  Serial.printf("META,message_bytes,%d\n", MSG_SIZE);
  Serial.printf("META,core,%d (priority %d)\n", BENCH_CORE, BENCH_PRIORITY);
  Serial.printf("META,stack_bytes,%u (empty task uses %u, subtracted from STACK values)\n",
                (unsigned)g_stack_bytes, (unsigned)g_stack_baseline);
  Serial.println("META,timer,CPU cycle counter; RSA keygen esp_timer (us x 240). RAW values are CPU cycles");
}

void run_e2();                                   // Step 2, in e2_payload.ino

// Step 1: all algorithms on 64-byte messages
static void run_e1() {
  print_meta();
  uint32_t cal_used = 0;
  run_in_task(probe_calibration, nullptr, &cal_used);
  Serial.printf("STACK,_calibration,%d_byte_array,%u\n", CALIBRATION_BYTES,
                (unsigned)(cal_used > g_stack_baseline ? cal_used - g_stack_baseline : 0));

  int64_t t_start = esp_timer_get_time();
  for (int k = 0; k < ALGORITHM_COUNT; k++) {
    const SigAlgorithm* a = ALGORITHMS[k];
    memset(&g_results[k], 0, sizeof(AlgResult));
    Serial.printf("PROGRESS,%s,start (%s; %s)\n", a->name, a->library, a->security);
    size_t free_before = ESP.getFreeHeap();
    run_in_task(bench_one, (void*)a, nullptr);
    if (g_results[k].done) measure_memory(k);
    a->free_bench_key();
    Serial.printf("LEAK,%s,free_before=%u,free_after=%u\n", a->name, (unsigned)free_before,
                  (unsigned)ESP.getFreeHeap());
  }
  for (int k = 0; k < ALGORITHM_COUNT; k++) {
    if (strcmp(ALGORITHMS[k]->name, "Ed25519") == 0 && g_results[k].done) {
      run_in_task(repeat_check, (void*)ALGORITHMS[k], nullptr);
    }
  }
  Serial.printf("META,total_seconds,%.1f\n", (esp_timer_get_time() - t_start) / 1e6);
  Serial.println("### END SIG_BENCH");
  print_table();
}

void setup() {
  Serial.begin(115200);
  setCpuFrequencyMhz(CPU_MHZ);
  delay(500);
  int experiment = 0;
  while (experiment == 0) {                      // wait for the start command
    Serial.println("Ready. Send S for Step 1 (all algorithms, about 40 minutes) "
                   "or P for Step 2 (message sizes, about 20 minutes).");
    uint32_t t = millis();
    while (millis() - t < 3000 && experiment == 0) {
      if (Serial.available()) {
        char c = Serial.read();
        if (c == 'S' || c == 's') experiment = 1;
        if (c == 'P' || c == 'p') experiment = 2;
      }
      delay(10);
    }
  }
  while (Serial.available()) Serial.read();
  const char* marker = experiment == 1 ? "SIG_BENCH" : "PAYLOAD_BENCH";

  Serial.printf("### BEGIN %s\n", marker);
  if (getCpuFrequencyMhz() != CPU_MHZ) {
    Serial.printf("ERROR,cpu,clock is %u MHz, expected %d. Set CPU Frequency to 240 MHz.\n",
                  (unsigned)getCpuFrequencyMhz(), CPU_MHZ);
    Serial.printf("### END %s\n", marker);
    return;
  }
  if (!algorithms_init()) {
    Serial.println("ERROR,init,mbedTLS or libsodium set-up failed");
    Serial.printf("### END %s\n", marker);
    return;
  }

  // One stack size for every measurement task: as wanted, or what the heap allows
  size_t largest = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  g_stack_bytes = STACK_BYTES_WANTED;
  if (largest < g_stack_bytes + 8192) g_stack_bytes = ((largest - 8192) / 4096) * 4096;
  run_in_task(probe_empty, nullptr, &g_stack_baseline);

  if (experiment == 1) run_e1();
  else run_e2();
}

void loop() {
  delay(10000);
}
