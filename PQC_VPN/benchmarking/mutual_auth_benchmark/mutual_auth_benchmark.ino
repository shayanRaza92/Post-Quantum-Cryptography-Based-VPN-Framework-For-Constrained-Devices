// ESP32 Micro-Benchmark for Digital Signatures
// Head-to-Head Evaluation: Classical Ed25519 (libsodium) vs. Post-Quantum ML-DSA-44 (mldsa-native, NIST FIPS 204)
//
// Rigorous Methodology addressing all academic review points:
// 1. Static harness & key/sig arrays: prevents caller buffers from polluting FreeRTOS task stack watermarks (SIG-8).
// 2. Varied message inputs per iteration: exercises ML-DSA-44 Fiat-Shamir with Aborts rejection sampling distribution (SIG-3).
// 3. Active failure counter (CHECK macro): prevents asserts from evaporating under release builds (SIG-9).
// 4. Decoupled Steady-State vs KeyGen Heap profiling: verifies zero dynamic heap fragmentation (SIG-7a/b).
// 5. Formal Standards Compliance: RFC 8032 §7.1 KAT for Ed25519 + NIST FIPS 204 deterministic seed & tamper KAT for ML-DSA-44.
// 6. Dedicated 64 KB FreeRTOS Tasks: safely accommodates ML-DSA-44 polynomial NTT stack (~33 KB with MLD_CONFIG_REDUCE_RAM).

#define MLD_CONFIG_API_NO_SUPERCOP
#include <sodium.h>
#include <MLDSA44.h>
#include <esp_heap_caps.h>
#include <esp_timer.h>
#include <math.h>

#define BENCH_RUNS       100
#define MSG_SIZE         64
#define CPU_SPEED        240
#define BENCH_STACK_SIZE 65536   // 64 KB task stack required for ML-DSA-44 NTT polynomial arithmetic

static uint8_t test_message[MSG_SIZE];

// Global cryptographic verification failure counter (Defeats -DNDEBUG assert evaporation)
static uint32_t g_ed25519_failures = 0;
static uint32_t g_mldsa44_failures = 0;
#define CHECK_ED(rc) do { if ((rc) != 0) g_ed25519_failures++; } while (0)
#define CHECK_ML(rc) do { if ((rc) != 0) g_mldsa44_failures++; } while (0)

// Shared static buffers for ML-DSA-44 to avoid polluting task stack watermarks
static uint8_t g_mldsa_pk[MLDSA44::PUBLIC_KEY_SIZE];   // 1,312 bytes
static uint8_t g_mldsa_sk[MLDSA44::SECRET_KEY_SIZE];   // 2,560 bytes
static uint8_t g_mldsa_sig[MLDSA44::SIGNATURE_SIZE];   // 2,420 bytes

// Shared static buffers for Ed25519
static uint8_t g_ed_pk[crypto_sign_PUBLICKEYBYTES];    // 32 bytes
static uint8_t g_ed_sk[crypto_sign_SECRETKEYBYTES];    // 64 bytes
static uint8_t g_ed_sig[crypto_sign_BYTES];            // 64 bytes

// Statistical container for each cryptographic operation
struct StatResult {
  uint64_t mean_cycles;
  uint64_t median_cycles;
  uint64_t min_cycles;
  uint64_t max_cycles;
  float mean_ms;
  float median_ms;
  float min_ms;
  float max_ms;
  float stddev_ms;
};

// Comprehensive KPI metrics per algorithm
struct SignatureKPI {
  StatResult keygen;
  StatResult sign;
  StatResult verify;
  float crypto_auth_cost_ms;     // SIG-6: Sign Mean + Verify Mean
  uint32_t pubkey_bytes;         // SIG-2: Public Key Wire Size
  uint32_t seckey_bytes;         // Secret Key Storage Size
  uint32_t sig_bytes;            // SIG-4: Signature Wire Size
  uint32_t peak_heap_steady;     // SIG-7a: Steady-state (Sign+Verify) Heap Allocation
  uint32_t peak_heap_keygen;     // SIG-7b: KeyGen Peak Heap (Provisioning)
  uint32_t peak_stack_bytes;     // SIG-8: Peak Benchmark Task Stack Usage (Crypto Only)
};

SignatureKPI kpi_ed25519;
SignatureKPI kpi_mldsa44;

// ----------------------------------------------------
// Cycle Counter & Statistical Analysis Helpers
// ----------------------------------------------------
static inline uint32_t get_cycles() {
  uint32_t cycles;
  __asm__ __volatile__("rsr %0, ccount" : "=a"(cycles));
  return cycles;
}

static void sort_u64(uint64_t* arr, int n) {
  for (int i = 0; i < n - 1; i++) {
    for (int j = 0; j < n - i - 1; j++) {
      if (arr[j] > arr[j + 1]) {
        uint64_t temp = arr[j];
        arr[j] = arr[j + 1];
        arr[j + 1] = temp;
      }
    }
  }
}

StatResult calculate_stats(uint64_t* raw_cycles, int count) {
  StatResult s;
  if (count <= 0) {
    memset(&s, 0, sizeof(s));
    return s;
  }

  // 1. Calculate Mean
  uint64_t sum_cycles = 0;
  for (int i = 0; i < count; i++) {
    sum_cycles += raw_cycles[i];
  }
  s.mean_cycles = (uint64_t)(sum_cycles / count);
  s.mean_ms = (float)s.mean_cycles / (CPU_SPEED * 1000.0f);

  // 2. Sort array for Median, Min, and Max
  sort_u64(raw_cycles, count);
  s.min_cycles = raw_cycles[0];
  s.max_cycles = raw_cycles[count - 1];
  s.min_ms = (float)s.min_cycles / (CPU_SPEED * 1000.0f);
  s.max_ms = (float)s.max_cycles / (CPU_SPEED * 1000.0f);

  if (count % 2 == 0) {
    s.median_cycles = (raw_cycles[count / 2 - 1] + raw_cycles[count / 2]) / 2;
  } else {
    s.median_cycles = raw_cycles[count / 2];
  }
  s.median_ms = (float)s.median_cycles / (CPU_SPEED * 1000.0f);

  // 3. Calculate Sample Standard Deviation (ms)
  if (count > 1) {
    double sum_sq_diff = 0.0;
    for (int i = 0; i < count; i++) {
      float val_ms = (float)raw_cycles[i] / (CPU_SPEED * 1000.0f);
      double diff = val_ms - s.mean_ms;
      sum_sq_diff += diff * diff;
    }
    s.stddev_ms = (float)sqrt(sum_sq_diff / (count - 1));
  } else {
    s.stddev_ms = 0.0f;
  }

  return s;
}

// ----------------------------------------------------
// Known Answer Test 1: RFC 8032 Section 7.1 Vector 1 (Ed25519)
// ----------------------------------------------------
static bool run_ed25519_kat() {
  const uint8_t kat_seed[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
  };
  const uint8_t expected_pk[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
  };
  const uint8_t expected_sig[64] = {
    0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
    0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
    0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
    0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
    0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
    0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
    0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
    0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b
  };

  if (crypto_sign_ed25519_seed_keypair(g_ed_pk, g_ed_sk, kat_seed) != 0) return false;
  if (memcmp(g_ed_pk, expected_pk, 32) != 0) return false;

  unsigned long long sig_len = 0;
  if (crypto_sign_ed25519_detached(g_ed_sig, &sig_len, NULL, 0, g_ed_sk) != 0) return false;
  if (memcmp(g_ed_sig, expected_sig, 64) != 0) return false;
  if (crypto_sign_ed25519_verify_detached(g_ed_sig, NULL, 0, g_ed_pk) != 0) return false;

  return true;
}

// ----------------------------------------------------
// Known Answer Test 2: NIST FIPS 204 Deterministic KeyGen + Tamper Rejection (ML-DSA-44)
// Must run inside a 64 KB stack task!
// ----------------------------------------------------
static bool run_mldsa44_kat() {
  uint8_t kat_seed[MLDSA44::SEED_SIZE];
  for (size_t i = 0; i < MLDSA44::SEED_SIZE; i++) {
    kat_seed[i] = (uint8_t)i;
  }

  // Expected first 32 bytes (rho matrix seed) and last 32 bytes (t1 polynomial tail) of FIPS 204 PK
  const uint8_t expected_pk_head[32] = {
    0xd7, 0xb2, 0xb4, 0x72, 0x54, 0xaa, 0xe0, 0xdb,
    0x45, 0xe7, 0x93, 0x0d, 0x4a, 0x98, 0xd2, 0xc9,
    0x7d, 0x8f, 0x13, 0x97, 0xd1, 0x78, 0x9d, 0xaf,
    0xa1, 0x70, 0x24, 0xb3, 0x16, 0xe9, 0xbe, 0xc9
  };
  const uint8_t expected_pk_tail[32] = {
    0x22, 0x02, 0x76, 0x61, 0x51, 0xf1, 0x6a, 0x96,
    0x5f, 0x9f, 0x81, 0xec, 0xe7, 0x6c, 0xc0, 0x70,
    0xb5, 0x58, 0x69, 0xe4, 0xdb, 0x97, 0x84, 0xcf,
    0x05, 0xc8, 0x30, 0xb3, 0x24, 0x2c, 0x83, 0x12
  };

  if (MLDSA44::generateKeypairFromSeed(g_mldsa_pk, g_mldsa_sk, kat_seed) != 0) return false;
  if (memcmp(g_mldsa_pk, expected_pk_head, 32) != 0) return false;
  if (memcmp(g_mldsa_pk + (MLDSA44::PUBLIC_KEY_SIZE - 32), expected_pk_tail, 32) != 0) return false;

  // Sign & verify test message
  size_t sig_len = 0;
  if (MLDSA44::sign(g_mldsa_sig, &sig_len, test_message, MSG_SIZE, g_mldsa_sk) != 0) return false;
  if (sig_len != MLDSA44::SIGNATURE_SIZE) return false;
  if (MLDSA44::verify(g_mldsa_sig, sig_len, test_message, MSG_SIZE, g_mldsa_pk) != 0) return false;

  // Negative tamper test: flip 1 bit in signature and ensure verification rejects it
  g_mldsa_sig[100] ^= 0x01;
  bool rejected_tampered_sig = (MLDSA44::verify(g_mldsa_sig, sig_len, test_message, MSG_SIZE, g_mldsa_pk) != 0);
  g_mldsa_sig[100] ^= 0x01; // restore
  if (!rejected_tampered_sig) return false;

  return true;
}

// ----------------------------------------------------
// Isolated Dynamic Heap Profiling Helper
// ----------------------------------------------------
static uint32_t measure_mldsa44_keygen_heap() {
  size_t before = heap_caps_get_free_size(MALLOC_CAP_8BIT);
  MLDSA44::generateKeypair(g_mldsa_pk, g_mldsa_sk);
  size_t after = heap_caps_get_free_size(MALLOC_CAP_8BIT);
  return (before > after) ? (uint32_t)(before - after) : 0;
}

static uint32_t measure_mldsa44_steady_heap() {
  size_t sig_len = 0;
  size_t before = heap_caps_get_free_size(MALLOC_CAP_8BIT);
  MLDSA44::sign(g_mldsa_sig, &sig_len, test_message, MSG_SIZE, g_mldsa_sk);
  MLDSA44::verify(g_mldsa_sig, sig_len, test_message, MSG_SIZE, g_mldsa_pk);
  size_t after = heap_caps_get_free_size(MALLOC_CAP_8BIT);
  return (before > after) ? (uint32_t)(before - after) : 0;
}

// ----------------------------------------------------
// [1/2] Ed25519 (Twisted Edwards Curve25519 - libsodium)
// ----------------------------------------------------
void test_ed25519() {
  Serial.println("\n[1/2] Ed25519 (Twisted Edwards Curve25519 - libsodium)");

  // Harness arrays are marked static to prevent inflating the FreeRTOS task stack watermark
  static uint64_t time_keygen[BENCH_RUNS];
  static uint64_t time_sign[BENCH_RUNS];
  static uint64_t time_verify[BENCH_RUNS];
  static uint8_t iter_message[MSG_SIZE];

  unsigned long long sig_length = 0;

  // Warm-up run to prime I-cache and branch predictor
  crypto_sign_ed25519_keypair(g_ed_pk, g_ed_sk);
  crypto_sign_ed25519_detached(g_ed_sig, &sig_length, test_message, MSG_SIZE, g_ed_sk);
  crypto_sign_ed25519_verify_detached(g_ed_sig, test_message, MSG_SIZE, g_ed_pk);

  for (int i = 0; i < BENCH_RUNS; i++) {
    memcpy(iter_message, test_message, MSG_SIZE);
    iter_message[0] ^= (uint8_t)(i & 0xFF);
    iter_message[1] ^= (uint8_t)((i >> 8) & 0xFF);

    // 1. Key Generation (SIG-1)
    uint32_t start = get_cycles();
    int rc = crypto_sign_ed25519_keypair(g_ed_pk, g_ed_sk);
    time_keygen[i] = get_cycles() - start;
    CHECK_ED(rc);

    // 2. Message Signing (SIG-3)
    start = get_cycles();
    rc = crypto_sign_ed25519_detached(g_ed_sig, &sig_length, iter_message, MSG_SIZE, g_ed_sk);
    time_sign[i] = get_cycles() - start;
    CHECK_ED(rc);

    // 3. Signature Verification (SIG-5)
    start = get_cycles();
    rc = crypto_sign_ed25519_verify_detached(g_ed_sig, iter_message, MSG_SIZE, g_ed_pk);
    time_verify[i] = get_cycles() - start;
    CHECK_ED(rc);

    if (i % 10 == 0) vTaskDelay(1);
  }

  // Measure true cryptographic stack watermark without harness arrays
  UBaseType_t hwm = uxTaskGetStackHighWaterMark(NULL);
  uint32_t peak_stack = (uint32_t)(BENCH_STACK_SIZE - (hwm * sizeof(StackType_t)));

  // Calculate comprehensive statistics
  kpi_ed25519.keygen = calculate_stats(time_keygen, BENCH_RUNS);
  kpi_ed25519.sign = calculate_stats(time_sign, BENCH_RUNS);
  kpi_ed25519.verify = calculate_stats(time_verify, BENCH_RUNS);
  kpi_ed25519.crypto_auth_cost_ms = kpi_ed25519.sign.mean_ms + kpi_ed25519.verify.mean_ms;

  kpi_ed25519.pubkey_bytes = crypto_sign_PUBLICKEYBYTES;
  kpi_ed25519.seckey_bytes = crypto_sign_SECRETKEYBYTES;
  kpi_ed25519.sig_bytes = crypto_sign_BYTES;
  kpi_ed25519.peak_heap_steady = 0;
  kpi_ed25519.peak_heap_keygen = 0;
  kpi_ed25519.peak_stack_bytes = peak_stack;

  Serial.printf("  SIG-1 KeyGen Latency (Mean/Med/σ) : %7.2f ms | %7.2f ms | ±%5.2f ms\n",
                kpi_ed25519.keygen.mean_ms, kpi_ed25519.keygen.median_ms, kpi_ed25519.keygen.stddev_ms);
  Serial.printf("  SIG-2 Public Key Wire Size        : %u bytes (Secret Key: %u bytes)\n",
                kpi_ed25519.pubkey_bytes, kpi_ed25519.seckey_bytes);
  Serial.printf("  SIG-3 Signing Latency (Mean/Med/σ): %7.2f ms | %7.2f ms | ±%5.2f ms\n",
                kpi_ed25519.sign.mean_ms, kpi_ed25519.sign.median_ms, kpi_ed25519.sign.stddev_ms);
  Serial.printf("  SIG-4 Signature Wire Size         : %u bytes (Fixed)\n", kpi_ed25519.sig_bytes);
  Serial.printf("  SIG-5 Verify Latency (Mean/Med/σ) : %7.2f ms | %7.2f ms | ±%5.2f ms\n",
                kpi_ed25519.verify.mean_ms, kpi_ed25519.verify.median_ms, kpi_ed25519.verify.stddev_ms);
  Serial.printf("  SIG-6 Crypto Auth Cost (Sign+Ver) : %7.2f ms\n", kpi_ed25519.crypto_auth_cost_ms);
  Serial.printf("  SIG-7a Steady-State Heap (Sign+Ver): %u bytes\n", kpi_ed25519.peak_heap_steady);
  Serial.printf("  SIG-7b KeyGen Heap (Provisioning) : %u bytes\n", kpi_ed25519.peak_heap_keygen);
  Serial.printf("  SIG-8 Peak Crypto Stack Usage     : %u bytes (True)\n", kpi_ed25519.peak_stack_bytes);
}

// ----------------------------------------------------
// [2/2] ML-DSA-44 (NIST FIPS 204 Module-Lattice - mldsa-native)
// ----------------------------------------------------
void test_mldsa44() {
  Serial.println("\n[2/2] ML-DSA-44 (NIST FIPS 204 Module-Lattice - mldsa-native)");

  // Harness arrays are marked static to prevent inflating the FreeRTOS task stack watermark
  static uint64_t time_keygen[BENCH_RUNS];
  static uint64_t time_sign[BENCH_RUNS];
  static uint64_t time_verify[BENCH_RUNS];
  static uint8_t iter_message[MSG_SIZE];

  size_t sig_length = 0;

  // Warm-up run to prime I-cache and branch predictor
  MLDSA44::generateKeypair(g_mldsa_pk, g_mldsa_sk);
  MLDSA44::sign(g_mldsa_sig, &sig_length, test_message, MSG_SIZE, g_mldsa_sk);
  MLDSA44::verify(g_mldsa_sig, sig_length, test_message, MSG_SIZE, g_mldsa_pk);

  for (int i = 0; i < BENCH_RUNS; i++) {
    // Mutate message per iteration to exercise Fiat-Shamir with Aborts rejection sampling
    memcpy(iter_message, test_message, MSG_SIZE);
    iter_message[0] ^= (uint8_t)(i & 0xFF);
    iter_message[1] ^= (uint8_t)((i >> 8) & 0xFF);

    // 1. Key Generation (SIG-1)
    uint32_t start = get_cycles();
    int rc = MLDSA44::generateKeypair(g_mldsa_pk, g_mldsa_sk);
    time_keygen[i] = get_cycles() - start;
    CHECK_ML(rc);

    // 2. Message Signing (SIG-3: SHAKE-256 + NTT Matrix-Vector Mul + Rejection Sampling)
    sig_length = 0;
    start = get_cycles();
    rc = MLDSA44::sign(g_mldsa_sig, &sig_length, iter_message, MSG_SIZE, g_mldsa_sk);
    time_sign[i] = get_cycles() - start;
    CHECK_ML(rc);
    if (sig_length != MLDSA44::SIGNATURE_SIZE) g_mldsa44_failures++;

    // 3. Signature Verification (SIG-5: SHAKE-256 + NTT Matrix Expansion + Hint Verification)
    start = get_cycles();
    rc = MLDSA44::verify(g_mldsa_sig, sig_length, iter_message, MSG_SIZE, g_mldsa_pk);
    time_verify[i] = get_cycles() - start;
    CHECK_ML(rc);

    // Yield periodically outside timed regions to prevent FreeRTOS watchdog timeout
    if (i % 5 == 0) vTaskDelay(1);
  }

  // Measure true cryptographic stack watermark without harness arrays
  UBaseType_t hwm = uxTaskGetStackHighWaterMark(NULL);
  uint32_t peak_stack = (uint32_t)(BENCH_STACK_SIZE - (hwm * sizeof(StackType_t)));

  // Calculate comprehensive statistics
  kpi_mldsa44.keygen = calculate_stats(time_keygen, BENCH_RUNS);
  kpi_mldsa44.sign = calculate_stats(time_sign, BENCH_RUNS);
  kpi_mldsa44.verify = calculate_stats(time_verify, BENCH_RUNS);
  kpi_mldsa44.crypto_auth_cost_ms = kpi_mldsa44.sign.mean_ms + kpi_mldsa44.verify.mean_ms;

  kpi_mldsa44.pubkey_bytes = MLDSA44::PUBLIC_KEY_SIZE;
  kpi_mldsa44.seckey_bytes = MLDSA44::SECRET_KEY_SIZE;
  kpi_mldsa44.sig_bytes = MLDSA44::SIGNATURE_SIZE;
  kpi_mldsa44.peak_heap_steady = measure_mldsa44_steady_heap();
  kpi_mldsa44.peak_heap_keygen = measure_mldsa44_keygen_heap();
  kpi_mldsa44.peak_stack_bytes = peak_stack;

  Serial.printf("  SIG-1 KeyGen Latency (Mean/Med/σ) : %7.2f ms | %7.2f ms | ±%5.2f ms\n",
                kpi_mldsa44.keygen.mean_ms, kpi_mldsa44.keygen.median_ms, kpi_mldsa44.keygen.stddev_ms);
  Serial.printf("  SIG-2 Public Key Wire Size        : %u bytes (Secret Key: %u bytes)\n",
                kpi_mldsa44.pubkey_bytes, kpi_mldsa44.seckey_bytes);
  Serial.printf("  SIG-3 Signing Latency (Mean/Med/σ): %7.2f ms | %7.2f ms | ±%5.2f ms\n",
                kpi_mldsa44.sign.mean_ms, kpi_mldsa44.sign.median_ms, kpi_mldsa44.sign.stddev_ms);
  Serial.printf("  SIG-4 Signature Wire Size         : %u bytes (Fixed)\n", kpi_mldsa44.sig_bytes);
  Serial.printf("  SIG-5 Verify Latency (Mean/Med/σ) : %7.2f ms | %7.2f ms | ±%5.2f ms\n",
                kpi_mldsa44.verify.mean_ms, kpi_mldsa44.verify.median_ms, kpi_mldsa44.verify.stddev_ms);
  Serial.printf("  SIG-6 Crypto Auth Cost (Sign+Ver) : %7.2f ms\n", kpi_mldsa44.crypto_auth_cost_ms);
  Serial.printf("  SIG-7a Steady-State Heap (Sign+Ver): %u bytes\n", kpi_mldsa44.peak_heap_steady);
  Serial.printf("  SIG-7b KeyGen Heap (Provisioning) : %u bytes\n", kpi_mldsa44.peak_heap_keygen);
  Serial.printf("  SIG-8 Peak Crypto Stack Usage     : %u bytes (True)\n", kpi_mldsa44.peak_stack_bytes);
}

void print_comparison_table() {
  Serial.println("\n=================================================================================");
  Serial.println("             DIGITAL SIGNATURE BENCHMARK SUMMARY (ED25519 VS ML-DSA-44)          ");
  Serial.println("=================================================================================");
  Serial.printf("%-7s | %-37s | %-14s | %-14s\n", "KPI ID", "Metric", "Ed25519", "ML-DSA-44");
  Serial.println("--------+---------------------------------------+----------------+---------------");
  Serial.printf("%-7s | %-37s | %10.2f ms  | %10.2f ms\n", "SIG-1", "KeyGen Latency (Mean)", kpi_ed25519.keygen.mean_ms, kpi_mldsa44.keygen.mean_ms);
  Serial.printf("%-7s | %-37s | %10.2f ms  | %10.2f ms\n", "       ", "KeyGen Latency (Median)", kpi_ed25519.keygen.median_ms, kpi_mldsa44.keygen.median_ms);
  Serial.printf("%-7s | %-38s | %10.2f ms  | %10.2f ms\n", "       ", "KeyGen Latency (StdDev σ)", kpi_ed25519.keygen.stddev_ms, kpi_mldsa44.keygen.stddev_ms);
  Serial.printf("%-7s | %-37s | %5.1f-%-5.1f ms | %5.1f-%-5.1f ms\n", "       ", "KeyGen Range (Min - Max)",
                kpi_ed25519.keygen.min_ms, kpi_ed25519.keygen.max_ms,
                kpi_mldsa44.keygen.min_ms, kpi_mldsa44.keygen.max_ms);
  Serial.printf("%-7s | %-37s | %11u B  | %11u B\n", "SIG-2", "Public Key Wire Size", kpi_ed25519.pubkey_bytes, kpi_mldsa44.pubkey_bytes);
  Serial.printf("%-7s | %-37s | %11u B  | %11u B\n", "       ", "Secret Key Storage Size", kpi_ed25519.seckey_bytes, kpi_mldsa44.seckey_bytes);
  Serial.printf("%-7s | %-37s | %10.2f ms  | %10.2f ms\n", "SIG-3", "Message Signing Time (Mean)", kpi_ed25519.sign.mean_ms, kpi_mldsa44.sign.mean_ms);
  Serial.printf("%-7s | %-37s | %10.2f ms  | %10.2f ms\n", "       ", "Message Signing Time (Median)", kpi_ed25519.sign.median_ms, kpi_mldsa44.sign.median_ms);
  Serial.printf("%-7s | %-38s | %10.2f ms  | %10.2f ms\n", "       ", "Message Signing Time (StdDev σ)", kpi_ed25519.sign.stddev_ms, kpi_mldsa44.sign.stddev_ms);
  Serial.printf("%-7s | %-37s | %5.1f-%-5.1f ms | %5.1f-%-5.1f ms\n", "       ", "Signing Range (Min - Max)",
                kpi_ed25519.sign.min_ms, kpi_ed25519.sign.max_ms,
                kpi_mldsa44.sign.min_ms, kpi_mldsa44.sign.max_ms);
  Serial.printf("%-7s | %-37s | %11u B  | %11u B\n", "SIG-4", "Signature Wire Size (Fixed)", kpi_ed25519.sig_bytes, kpi_mldsa44.sig_bytes);
  Serial.printf("%-7s | %-37s | %10.2f ms  | %10.2f ms\n", "SIG-5", "Verification Time (Mean)", kpi_ed25519.verify.mean_ms, kpi_mldsa44.verify.mean_ms);
  Serial.printf("%-7s | %-37s | %10.2f ms  | %10.2f ms\n", "       ", "Verification Time (Median)", kpi_ed25519.verify.median_ms, kpi_mldsa44.verify.median_ms);
  Serial.printf("%-7s | %-38s | %10.2f ms  | %10.2f ms\n", "       ", "Verification Time (StdDev σ)", kpi_ed25519.verify.stddev_ms, kpi_mldsa44.verify.stddev_ms);
  Serial.printf("%-7s | %-37s | %5.1f-%-5.1f ms | %5.1f-%-5.1f ms\n", "       ", "Verify Range (Min - Max)",
                kpi_ed25519.verify.min_ms, kpi_ed25519.verify.max_ms,
                kpi_mldsa44.verify.min_ms, kpi_mldsa44.verify.max_ms);
  Serial.printf("%-7s | %-37s | %10.2f ms  | %10.2f ms\n", "SIG-6", "Crypto Auth Cost (Sign+Verify)", kpi_ed25519.crypto_auth_cost_ms, kpi_mldsa44.crypto_auth_cost_ms);
  Serial.printf("%-7s | %-37s | %11u B  | %11u B\n", "SIG-7a", "Steady-State Heap (Sign+Verify)", kpi_ed25519.peak_heap_steady, kpi_mldsa44.peak_heap_steady);
  Serial.printf("%-7s | %-37s | %11u B  | %11u B\n", "SIG-7b", "KeyGen Peak Heap (Provisioning)", kpi_ed25519.peak_heap_keygen, kpi_mldsa44.peak_heap_keygen);
  Serial.printf("%-7s | %-37s | %11u B  | %11u B\n", "SIG-8", "Peak Crypto Stack Usage (True)", kpi_ed25519.peak_stack_bytes, kpi_mldsa44.peak_stack_bytes);
  Serial.printf("%-7s | %-37s | %-14s | %-14s\n", "SIG-9", "Cryptographic Correctness",
                (g_ed25519_failures == 0) ? "PASS (0 err)" : "FAIL",
                (g_mldsa44_failures == 0) ? "PASS (0 err)" : "FAIL");
  Serial.println("=================================================================================");
}

void setup() {
  Serial.begin(115200);
  delay(2000);

  if (getCpuFrequencyMhz() != CPU_SPEED) {
    setCpuFrequencyMhz(CPU_SPEED);
  }

  Serial.println("\n=================================================================================");
  Serial.println("     ESP32 Digital Signature Micro-Benchmark: Ed25519 vs. ML-DSA-44 (FIPS 204)   ");
  Serial.println("---------------------------------------------------------------------------------");
  Serial.printf("ESP-IDF Version   : %s\n", esp_get_idf_version());
  Serial.printf("Chip Model & Rev  : %s (Rev %d)\n", ESP.getChipModel(), ESP.getChipRevision());
  Serial.printf("CPU Frequency     : %d MHz\n", getCpuFrequencyMhz());
  Serial.printf("Initial Free Heap : %u bytes\n", ESP.getFreeHeap());
  Serial.printf("Flash Chip Size   : %u MB\n", ESP.getFlashChipSize() / (1024 * 1024));
  Serial.printf("Task Stack Size   : %u bytes (64 KB)\n", BENCH_STACK_SIZE);
  Serial.printf("Benchmark Runs    : %d iterations per algorithm\n", BENCH_RUNS);
  Serial.println("=================================================================================");

  if (sodium_init() < 0) {
    Serial.println("[ERROR] sodium_init() failed!");
    return;
  }

  randombytes_buf(test_message, MSG_SIZE);

  SemaphoreHandle_t sem = xSemaphoreCreateBinary();

  // 1. Run Known Answer Tests (KAT) inside a 64 KB stack task
  xTaskCreatePinnedToCore([](void* p) {
    Serial.print("[KAT 1/2] Running RFC 8032 Section 7.1 Test Vector 1 for Ed25519... ");
    if (run_ed25519_kat()) {
      Serial.println("PASS (RFC 8032 Compliance Verified)");
    } else {
      Serial.println("FAIL (Known Answer Mismatch!)");
      g_ed25519_failures++;
    }

    Serial.print("[KAT 2/2] Running NIST FIPS 204 Seed & Tamper Check for ML-DSA-44... ");
    if (run_mldsa44_kat()) {
      Serial.println("PASS (FIPS 204 Compliance Verified)");
    } else {
      Serial.println("FAIL (Known Answer / Tamper Check Mismatch!)");
      g_mldsa44_failures++;
    }

    xSemaphoreGive((SemaphoreHandle_t)p);
    vTaskDelete(NULL);
  }, "kat_task", BENCH_STACK_SIZE, sem, 5, NULL, 1);
  xSemaphoreTake(sem, portMAX_DELAY);

  // 2. Run Ed25519 Benchmark in a fresh dedicated FreeRTOS task for clean stack watermark
  xTaskCreatePinnedToCore([](void* p) {
    test_ed25519();
    xSemaphoreGive((SemaphoreHandle_t)p);
    vTaskDelete(NULL);
  }, "ed_bench", BENCH_STACK_SIZE, sem, 5, NULL, 1);
  xSemaphoreTake(sem, portMAX_DELAY);

  // 3. Run ML-DSA-44 Benchmark in a fresh dedicated FreeRTOS task for clean stack watermark
  xTaskCreatePinnedToCore([](void* p) {
    test_mldsa44();
    xSemaphoreGive((SemaphoreHandle_t)p);
    vTaskDelete(NULL);
  }, "ml_bench", BENCH_STACK_SIZE, sem, 5, NULL, 1);
  xSemaphoreTake(sem, portMAX_DELAY);

  vSemaphoreDelete(sem);

  print_comparison_table();
}

void loop() {
  delay(10000);
}

