// ESP32 Micro-Benchmark for Digital Signatures (Phase A: Isolated)
// Evaluates Ed25519, ECDSA P-256, and RSA-3072
// Rigorous Methodology addressing all academic review points:
// 1. Static harness arrays: prevents benchmark arrays from polluting task stack watermarks (SIG-8).
// 2. Varied message inputs: exercises DER encoding for true 70–72 B length variation in ECDSA (SIG-4).
// 3. Active failure counter (CHECK macro): prevents asserts from evaporating under release builds.
// 4. Decoupled Steady-State vs KeyGen Heap profiling: separates runtime VPN heap from offline prime search (SIG-7a/b).
// 5. Formal Standards Compliance: RFC 8032 Section 7.1 Known Answer Test (KAT) for Ed25519.
// 6. Complete platform instrumentation: prints IDF version, chip model, revision, and clock frequency.

#include <sodium.h>

#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/error.h"
#include "mbedtls/platform.h"
#include <esp_heap_caps.h>
#include <esp_timer.h>
#include <math.h>

#define FAST_RUNS        100
#define SLOW_RSA_RUNS    10
#define FAST_RSA_RUNS    100
#define MSG_SIZE         64
#define CPU_SPEED        240
#define BENCH_STACK_SIZE 16384

uint8_t test_message[MSG_SIZE];

// Global cryptographic verification failure counter (Defeats -DNDEBUG assert evaporation)
static uint32_t g_crypto_failures = 0;
#define CHECK(rc) do { if ((rc) != 0) g_crypto_failures++; } while (0)

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
  uint32_t pubkey_bytes;         // SIG-2
  uint32_t sig_bytes;            // SIG-4: Mean or Fixed size
  uint32_t min_sig_bytes;        // SIG-4: Min size
  uint32_t max_sig_bytes;        // SIG-4: Max size
  float avg_sig_bytes;           // SIG-4: Average size
  uint32_t peak_heap_steady;     // SIG-7a: Steady-state (Sign+Verify) Heap Allocation
  uint32_t peak_heap_keygen;     // SIG-7b: KeyGen Peak Heap (Provisioning)
  uint32_t peak_stack_bytes;     // SIG-8: Peak Benchmark Task Stack Usage (Crypto Only, static harness)
};

SignatureKPI kpi_ed25519;
SignatureKPI kpi_p256;
SignatureKPI kpi_rsa;

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
// Memory Instrumentation Module (Used ONLY in isolated profiling passes)
// ----------------------------------------------------
static size_t g_mbedtls_current_heap = 0;
static size_t g_mbedtls_peak_heap = 0;

#define MEM_MAGIC 0x50514331 // 'PQC1'
struct MemHeader {
  uint32_t magic;
  uint32_t size; // Guarantees 8-byte alignment for BigNum limbs
};

static void* custom_mbedtls_calloc(size_t n, size_t size) {
  size_t total = n * size;
  MemHeader* h = (MemHeader*)malloc(total + sizeof(MemHeader));
  if (!h) return NULL;
  h->magic = MEM_MAGIC;
  h->size = (uint32_t)total;
  g_mbedtls_current_heap += total;
  if (g_mbedtls_current_heap > g_mbedtls_peak_heap) {
    g_mbedtls_peak_heap = g_mbedtls_current_heap;
  }
  void* payload = (void*)(h + 1);
  memset(payload, 0, total);
  return payload;
}

static void custom_mbedtls_free(void* ptr) {
  if (!ptr) return;
  MemHeader* h = ((MemHeader*)ptr) - 1;
  if (h->magic == MEM_MAGIC) {
    if (g_mbedtls_current_heap >= h->size) {
      g_mbedtls_current_heap -= h->size;
    }
    h->magic = 0; // Invalidate magic
    free(h);
  } else {
    // Gracefully handle uninstrumented pointers
    free(ptr);
  }
}

static void enable_mbedtls_memory_instrumentation() {
  g_mbedtls_current_heap = 0;
  g_mbedtls_peak_heap = 0;
  mbedtls_platform_set_calloc_free(custom_mbedtls_calloc, custom_mbedtls_free);
}

static void disable_mbedtls_memory_instrumentation() {
  // Restore standard platform allocators (ESP-IDF default calloc/free)
  mbedtls_platform_set_calloc_free(calloc, free);
  g_mbedtls_current_heap = 0;
  g_mbedtls_peak_heap = 0;
}

// ----------------------------------------------------
// Known Answer Test (KAT): RFC 8032 Section 7.1 Vector 1
// Proves formal cryptographic compliance rather than self-consistent bugs
// ----------------------------------------------------
static bool run_ed25519_kat() {
  // Test Vector 1 from RFC 8032 §7.1: Empty message with known 32-byte seed
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

  uint8_t pk[crypto_sign_PUBLICKEYBYTES];
  uint8_t sk[crypto_sign_SECRETKEYBYTES];
  if (crypto_sign_seed_keypair(pk, sk, kat_seed) != 0) return false;
  if (memcmp(pk, expected_pk, 32) != 0) return false;

  uint8_t sig[crypto_sign_BYTES];
  unsigned long long sig_len = 0;
  if (crypto_sign_detached(sig, &sig_len, NULL, 0, sk) != 0) return false;
  if (memcmp(sig, expected_sig, 64) != 0) return false;
  if (crypto_sign_verify_detached(sig, NULL, 0, pk) != 0) return false;

  return true;
}

// ----------------------------------------------------
// Isolated Heap Profiling: Decoupled KeyGen vs Steady-State
// ----------------------------------------------------

// Ed25519 heap profiling: libsodium uses pure stack buffers
static void profile_ed25519_memory(uint32_t* out_steady, uint32_t* out_keygen) {
  *out_steady = 0;
  *out_keygen = 0;
}

// ECDSA P-256 KeyGen peak heap
static uint32_t profile_ecdsa_keygen_memory() {
  enable_mbedtls_memory_instrumentation();
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context random_gen;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&random_gen);
  mbedtls_ctr_drbg_seed(&random_gen, mbedtls_entropy_func, &entropy, (const unsigned char *)"ecdsa_kg", 8);

  mbedtls_ecdsa_context ctx;
  mbedtls_ecdsa_init(&ctx);
  mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random, &random_gen);
  uint32_t peak = (uint32_t)g_mbedtls_peak_heap;

  mbedtls_ecdsa_free(&ctx);
  mbedtls_ctr_drbg_free(&random_gen);
  mbedtls_entropy_free(&entropy);
  disable_mbedtls_memory_instrumentation();
  return peak;
}

// ECDSA P-256 Steady-State (Sign + Verify with pre-loaded key in memory)
static uint32_t profile_ecdsa_steady_memory() {
  enable_mbedtls_memory_instrumentation();
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context random_gen;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&random_gen);
  mbedtls_ctr_drbg_seed(&random_gen, mbedtls_entropy_func, &entropy, (const unsigned char *)"ecdsa_st", 8);

  mbedtls_ecdsa_context ctx;
  mbedtls_ecdsa_init(&ctx);
  mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random, &random_gen);

  // Key is now pre-loaded in memory. Reset peak tracker to current baseline so we record peak during Sign + Verify
  g_mbedtls_peak_heap = g_mbedtls_current_heap;

  uint8_t hash[32];
  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), test_message, MSG_SIZE, hash);

  uint8_t sig[MBEDTLS_ECDSA_MAX_LEN];
  size_t sig_len = 0;
  mbedtls_ecdsa_write_signature(&ctx, MBEDTLS_MD_SHA256, hash, 32, sig, sizeof(sig), &sig_len, mbedtls_ctr_drbg_random, &random_gen);
  mbedtls_ecdsa_read_signature(&ctx, hash, 32, sig, sig_len);

  uint32_t peak = (uint32_t)g_mbedtls_peak_heap;

  mbedtls_ecdsa_free(&ctx);
  mbedtls_ctr_drbg_free(&random_gen);
  mbedtls_entropy_free(&entropy);
  disable_mbedtls_memory_instrumentation();
  return peak;
}

// RSA-3072 KeyGen peak heap (Heavy prime search)
static uint32_t profile_rsa_keygen_memory() {
  enable_mbedtls_memory_instrumentation();
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context random_gen;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&random_gen);
  mbedtls_ctr_drbg_seed(&random_gen, mbedtls_entropy_func, &entropy, (const unsigned char *)"rsa_kg", 6);

  mbedtls_pk_context ctx;
  mbedtls_pk_init(&ctx);
  mbedtls_pk_setup(&ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
  mbedtls_rsa_gen_key(mbedtls_pk_rsa(ctx), mbedtls_ctr_drbg_random, &random_gen, 3072, 65537);
  uint32_t peak = (uint32_t)g_mbedtls_peak_heap;

  mbedtls_pk_free(&ctx);
  mbedtls_ctr_drbg_free(&random_gen);
  mbedtls_entropy_free(&entropy);
  disable_mbedtls_memory_instrumentation();
  return peak;
}

// RSA-3072 Steady-State (Sign + Verify with 3072-bit key pre-loaded in memory)
static uint32_t profile_rsa_steady_memory() {
  enable_mbedtls_memory_instrumentation();
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context random_gen;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&random_gen);
  mbedtls_ctr_drbg_seed(&random_gen, mbedtls_entropy_func, &entropy, (const unsigned char *)"rsa_st", 6);

  mbedtls_pk_context ctx;
  mbedtls_pk_init(&ctx);
  mbedtls_pk_setup(&ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
  mbedtls_rsa_gen_key(mbedtls_pk_rsa(ctx), mbedtls_ctr_drbg_random, &random_gen, 3072, 65537);

  // Key is now pre-loaded in memory. Reset peak tracker to current baseline so we record peak during Sign + Verify
  g_mbedtls_peak_heap = g_mbedtls_current_heap;

  uint8_t hash[32];
  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), test_message, MSG_SIZE, hash);

  uint8_t sig[384];
  size_t sig_len = 0;
  mbedtls_pk_sign(&ctx, MBEDTLS_MD_SHA256, hash, 32, sig, sizeof(sig), &sig_len, mbedtls_ctr_drbg_random, &random_gen);
  mbedtls_pk_verify(&ctx, MBEDTLS_MD_SHA256, hash, 32, sig, sig_len);

  uint32_t peak = (uint32_t)g_mbedtls_peak_heap;

  mbedtls_pk_free(&ctx);
  mbedtls_ctr_drbg_free(&random_gen);
  mbedtls_entropy_free(&entropy);
  disable_mbedtls_memory_instrumentation();
  return peak;
}

// ----------------------------------------------------
// [1/3] Ed25519 (Twisted Edwards Curve25519)
// ----------------------------------------------------
void test_ed25519() {
  Serial.println("\n[1/3] Ed25519 (Curve25519)");

  // Harness arrays are marked static to prevent inflating the FreeRTOS task stack watermark
  static uint64_t time_keygen[FAST_RUNS];
  static uint64_t time_sign[FAST_RUNS];
  static uint64_t time_verify[FAST_RUNS];

  uint8_t public_key[crypto_sign_PUBLICKEYBYTES];
  uint8_t private_key[crypto_sign_SECRETKEYBYTES];
  uint8_t signature[crypto_sign_BYTES];
  unsigned long long sig_length = 0;

  // Warm-up run to prime I-cache and branch predictor
  crypto_sign_keypair(public_key, private_key);
  crypto_sign_detached(signature, &sig_length, test_message, MSG_SIZE, private_key);
  crypto_sign_verify_detached(signature, test_message, MSG_SIZE, public_key);

  for (int i = 0; i < FAST_RUNS; i++) {
    // 1. Key Generation (SIG-1)
    uint32_t start = get_cycles();
    int rc = crypto_sign_keypair(public_key, private_key);
    time_keygen[i] = get_cycles() - start;
    CHECK(rc);

    // 2. Message Signing (SIG-3: PureEd25519 internal SHA-512 + Curve Math)
    start = get_cycles();
    rc = crypto_sign_detached(signature, &sig_length, test_message, MSG_SIZE, private_key);
    time_sign[i] = get_cycles() - start;
    CHECK(rc);

    // 3. Signature Verification (SIG-5)
    start = get_cycles();
    rc = crypto_sign_verify_detached(signature, test_message, MSG_SIZE, public_key);
    time_verify[i] = get_cycles() - start;
    CHECK(rc);
  }

  // Measure true cryptographic stack watermark without harness arrays
  UBaseType_t hwm = uxTaskGetStackHighWaterMark(NULL);
  uint32_t peak_stack = (uint32_t)(BENCH_STACK_SIZE - (hwm * sizeof(StackType_t)));

  // Calculate comprehensive statistics
  kpi_ed25519.keygen = calculate_stats(time_keygen, FAST_RUNS);
  kpi_ed25519.sign = calculate_stats(time_sign, FAST_RUNS);
  kpi_ed25519.verify = calculate_stats(time_verify, FAST_RUNS);
  kpi_ed25519.crypto_auth_cost_ms = kpi_ed25519.sign.mean_ms + kpi_ed25519.verify.mean_ms;

  kpi_ed25519.pubkey_bytes = crypto_sign_PUBLICKEYBYTES;
  kpi_ed25519.sig_bytes = crypto_sign_BYTES;
  kpi_ed25519.min_sig_bytes = crypto_sign_BYTES;
  kpi_ed25519.max_sig_bytes = crypto_sign_BYTES;
  kpi_ed25519.avg_sig_bytes = (float)crypto_sign_BYTES;
  kpi_ed25519.peak_stack_bytes = peak_stack;

  // Run isolated memory-profiling pass
  profile_ed25519_memory(&kpi_ed25519.peak_heap_steady, &kpi_ed25519.peak_heap_keygen);

  Serial.printf("  SIG-1 KeyGen Latency (Mean/Med/σ) : %7.2f ms | %7.2f ms | ±%5.2f ms\n",
                kpi_ed25519.keygen.mean_ms, kpi_ed25519.keygen.median_ms, kpi_ed25519.keygen.stddev_ms);
  Serial.printf("  SIG-2 Public Key Wire Size        : %u bytes\n", kpi_ed25519.pubkey_bytes);
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
// [2/3] ECDSA P-256 (NIST prime curve secp256r1)
// ----------------------------------------------------
void test_ecdsa_p256() {
  Serial.println("\n[2/3] ECDSA P-256 (secp256r1)");

  disable_mbedtls_memory_instrumentation();

  // Harness arrays marked static to prevent task stack contamination
  static uint64_t time_keygen[FAST_RUNS];
  static uint64_t time_sign[FAST_RUNS];
  static uint64_t time_verify[FAST_RUNS];
  static uint32_t sig_lengths[FAST_RUNS];

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context random_gen;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&random_gen);
  mbedtls_ctr_drbg_seed(&random_gen, mbedtls_entropy_func, &entropy, (const unsigned char *)"ecdsa", 5);

  uint8_t signature[MBEDTLS_ECDSA_MAX_LEN];
  size_t sig_length = 0;

  mbedtls_ecdsa_context main_key;
  mbedtls_ecdsa_init(&main_key);
  mbedtls_ecdsa_genkey(&main_key, MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random, &random_gen);

  // Warm-up run to prime I-cache and branch predictor
  {
    uint8_t warmup_hash[32];
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), test_message, MSG_SIZE, warmup_hash);
    mbedtls_ecdsa_write_signature(&main_key, MBEDTLS_MD_SHA256, warmup_hash, 32, signature, sizeof(signature), &sig_length, mbedtls_ctr_drbg_random, &random_gen);
    mbedtls_ecdsa_read_signature(&main_key, warmup_hash, 32, signature, sig_length);
  }

  for (int i = 0; i < FAST_RUNS; i++) {
    // 1. Key Generation (SIG-1)
    mbedtls_ecdsa_context temp_key;
    mbedtls_ecdsa_init(&temp_key);
    
    uint32_t start = get_cycles();
    int rc = mbedtls_ecdsa_genkey(&temp_key, MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random, &random_gen);
    time_keygen[i] = get_cycles() - start;
    CHECK(rc);
    mbedtls_ecdsa_free(&temp_key);

    // 2. Message Signing (SIG-3)
    // Note: Mutate message input to exercise RFC 6979 deterministic nonce generator and DER byte variability (70–72 B)
    uint8_t iter_message[MSG_SIZE];
    memcpy(iter_message, test_message, MSG_SIZE);
    iter_message[0] ^= (uint8_t)(i & 0xFF);
    iter_message[1] ^= (uint8_t)((i >> 8) & 0xFF);

    uint8_t message_hash[32];
    sig_length = 0;
    start = get_cycles();
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), iter_message, MSG_SIZE, message_hash);
    rc = mbedtls_ecdsa_write_signature(&main_key, MBEDTLS_MD_SHA256, message_hash, 32, signature, sizeof(signature), &sig_length, mbedtls_ctr_drbg_random, &random_gen);
    time_sign[i] = get_cycles() - start;
    CHECK(rc);
    sig_lengths[i] = (uint32_t)sig_length;

    // 3. Signature Verification (SIG-5)
    start = get_cycles();
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), iter_message, MSG_SIZE, message_hash);
    rc = mbedtls_ecdsa_read_signature(&main_key, message_hash, 32, signature, sig_length);
    time_verify[i] = get_cycles() - start;
    CHECK(rc);
  }

  // Measure true cryptographic stack watermark without harness arrays
  UBaseType_t hwm = uxTaskGetStackHighWaterMark(NULL);
  uint32_t peak_stack = (uint32_t)(BENCH_STACK_SIZE - (hwm * sizeof(StackType_t)));

  mbedtls_ecdsa_free(&main_key);
  mbedtls_ctr_drbg_free(&random_gen);
  mbedtls_entropy_free(&entropy);

  // Calculate comprehensive statistics
  kpi_p256.keygen = calculate_stats(time_keygen, FAST_RUNS);
  kpi_p256.sign = calculate_stats(time_sign, FAST_RUNS);
  kpi_p256.verify = calculate_stats(time_verify, FAST_RUNS);
  kpi_p256.crypto_auth_cost_ms = kpi_p256.sign.mean_ms + kpi_p256.verify.mean_ms;

  // Compute ECDSA signature length range and mean across all 100 runs (variable DER encoding)
  uint32_t min_sig = sig_lengths[0];
  uint32_t max_sig = sig_lengths[0];
  uint32_t sum_sig = 0;
  for (int i = 0; i < FAST_RUNS; i++) {
    if (sig_lengths[i] < min_sig) min_sig = sig_lengths[i];
    if (sig_lengths[i] > max_sig) max_sig = sig_lengths[i];
    sum_sig += sig_lengths[i];
  }
  kpi_p256.min_sig_bytes = min_sig;
  kpi_p256.max_sig_bytes = max_sig;
  kpi_p256.avg_sig_bytes = (float)sum_sig / (float)FAST_RUNS;
  kpi_p256.sig_bytes = (uint32_t)round(kpi_p256.avg_sig_bytes);

  kpi_p256.pubkey_bytes = 65;
  kpi_p256.peak_stack_bytes = peak_stack;

  // Run isolated memory-profiling passes (Steady-state vs KeyGen)
  kpi_p256.peak_heap_steady = profile_ecdsa_steady_memory();
  kpi_p256.peak_heap_keygen = profile_ecdsa_keygen_memory();

  Serial.printf("  SIG-1 KeyGen Latency (Mean/Med/σ) : %7.2f ms | %7.2f ms | ±%5.2f ms\n",
                kpi_p256.keygen.mean_ms, kpi_p256.keygen.median_ms, kpi_p256.keygen.stddev_ms);
  Serial.printf("  SIG-2 Public Key Wire Size        : %u bytes\n", kpi_p256.pubkey_bytes);
  Serial.printf("  SIG-3 Signing Latency (Mean/Med/σ): %7.2f ms | %7.2f ms | ±%5.2f ms\n",
                kpi_p256.sign.mean_ms, kpi_p256.sign.median_ms, kpi_p256.sign.stddev_ms);
  Serial.printf("  SIG-4 Signature Wire Size (Mean)  : %5.1f bytes (Min: %u B, Max: %u B, DER variable)\n",
                kpi_p256.avg_sig_bytes, kpi_p256.min_sig_bytes, kpi_p256.max_sig_bytes);
  Serial.printf("  SIG-5 Verify Latency (Mean/Med/σ) : %7.2f ms | %7.2f ms | ±%5.2f ms\n",
                kpi_p256.verify.mean_ms, kpi_p256.verify.median_ms, kpi_p256.verify.stddev_ms);
  Serial.printf("  SIG-6 Crypto Auth Cost (Sign+Ver) : %7.2f ms\n", kpi_p256.crypto_auth_cost_ms);
  Serial.printf("  SIG-7a Steady-State Heap (Sign+Ver): %u bytes\n", kpi_p256.peak_heap_steady);
  Serial.printf("  SIG-7b KeyGen Heap (Provisioning) : %u bytes\n", kpi_p256.peak_heap_keygen);
  Serial.printf("  SIG-8 Peak Crypto Stack Usage     : %u bytes (True)\n", kpi_p256.peak_stack_bytes);
}

// ----------------------------------------------------
// [3/3] Classical RSA-3072 (PKCS#1 v1.5)
// ----------------------------------------------------
void test_rsa_3072() {
  Serial.println("\n[3/3] Classical RSA-3072 (PKCS#1 v1.5)");

  disable_mbedtls_memory_instrumentation();

  // Harness arrays marked static to prevent task stack contamination
  static uint64_t time_keygen[SLOW_RSA_RUNS];
  static uint64_t time_sign[FAST_RSA_RUNS];
  static uint64_t time_verify[FAST_RSA_RUNS];

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context random_gen;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&random_gen);
  mbedtls_ctr_drbg_seed(&random_gen, mbedtls_entropy_func, &entropy, (const unsigned char *)"rsa", 3);

  uint8_t signature[384];
  size_t sig_length = 0;

  // Keypair for signing and verification benchmark
  mbedtls_pk_context main_key;
  mbedtls_pk_init(&main_key);
  mbedtls_pk_setup(&main_key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
  int rc_gen = mbedtls_rsa_gen_key(mbedtls_pk_rsa(main_key), mbedtls_ctr_drbg_random, &random_gen, 3072, 65537);
  CHECK(rc_gen);

  // Warm-up run
  {
    uint8_t warmup_hash[32];
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), test_message, MSG_SIZE, warmup_hash);
    mbedtls_pk_sign(&main_key, MBEDTLS_MD_SHA256, warmup_hash, 32, signature, sizeof(signature), &sig_length, mbedtls_ctr_drbg_random, &random_gen);
    mbedtls_pk_verify(&main_key, MBEDTLS_MD_SHA256, warmup_hash, 32, signature, sig_length);
  }

  // 1. Key Generation (SIG-1)
  // Note: 64-bit esp_timer is used to prevent 32-bit hardware ccount overflow on heavy RSA prime search (>17.89s)
  for (int i = 0; i < SLOW_RSA_RUNS; i++) {
    mbedtls_pk_context temp_key;
    mbedtls_pk_init(&temp_key);
    mbedtls_pk_setup(&temp_key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));

    int64_t start_us = esp_timer_get_time();
    int rc = mbedtls_rsa_gen_key(mbedtls_pk_rsa(temp_key), mbedtls_ctr_drbg_random, &random_gen, 3072, 65537);
    int64_t elapsed_us = esp_timer_get_time() - start_us;
    time_keygen[i] = (uint64_t)elapsed_us * (uint64_t)CPU_SPEED;
    CHECK(rc);

    mbedtls_pk_free(&temp_key);
    vTaskDelay(1); // Prevent watchdog timeout during heavy prime generation
  }

  // 2. Message Signing (SIG-3: SHA-256 Hash + RSA-3072 Modulo Exponentiation)
  for (int i = 0; i < FAST_RSA_RUNS; i++) {
    uint8_t message_hash[32];
    sig_length = 0;
    uint32_t start = get_cycles();
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), test_message, MSG_SIZE, message_hash);
    int rc = mbedtls_pk_sign(&main_key, MBEDTLS_MD_SHA256, message_hash, 32, signature, sizeof(signature), &sig_length, mbedtls_ctr_drbg_random, &random_gen);
    time_sign[i] = get_cycles() - start;
    CHECK(rc);

    if (i % 10 == 0) vTaskDelay(1);
  }

  // 3. Signature Verification (SIG-5: SHA-256 Hash + RSA Public Exponentiation)
  for (int i = 0; i < FAST_RSA_RUNS; i++) {
    uint8_t message_hash[32];
    uint32_t start = get_cycles();
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), test_message, MSG_SIZE, message_hash);
    int rc = mbedtls_pk_verify(&main_key, MBEDTLS_MD_SHA256, message_hash, 32, signature, sig_length);
    time_verify[i] = get_cycles() - start;
    CHECK(rc);
  }

  // Measure true cryptographic stack watermark without harness arrays
  UBaseType_t hwm = uxTaskGetStackHighWaterMark(NULL);
  uint32_t peak_stack = (uint32_t)(BENCH_STACK_SIZE - (hwm * sizeof(StackType_t)));

  mbedtls_pk_free(&main_key);
  mbedtls_ctr_drbg_free(&random_gen);
  mbedtls_entropy_free(&entropy);

  // Calculate comprehensive statistics
  kpi_rsa.keygen = calculate_stats(time_keygen, SLOW_RSA_RUNS);
  kpi_rsa.sign = calculate_stats(time_sign, FAST_RSA_RUNS);
  kpi_rsa.verify = calculate_stats(time_verify, FAST_RSA_RUNS);
  kpi_rsa.crypto_auth_cost_ms = kpi_rsa.sign.mean_ms + kpi_rsa.verify.mean_ms;

  kpi_rsa.pubkey_bytes = 384;
  kpi_rsa.sig_bytes = 384;
  kpi_rsa.min_sig_bytes = 384;
  kpi_rsa.max_sig_bytes = 384;
  kpi_rsa.avg_sig_bytes = 384.0f;
  kpi_rsa.peak_stack_bytes = peak_stack;

  // Run isolated memory-profiling passes (Steady-state vs KeyGen)
  kpi_rsa.peak_heap_steady = profile_rsa_steady_memory();
  kpi_rsa.peak_heap_keygen = profile_rsa_keygen_memory();

  Serial.printf("  SIG-1 KeyGen Latency (Mean/Med/σ) : %7.2f ms | %7.2f ms | ±%5.2f ms\n",
                kpi_rsa.keygen.mean_ms, kpi_rsa.keygen.median_ms, kpi_rsa.keygen.stddev_ms);
  Serial.printf("  SIG-2 Public Key Wire Size        : %u bytes\n", kpi_rsa.pubkey_bytes);
  Serial.printf("  SIG-3 Signing Latency (Mean/Med/σ): %7.2f ms | %7.2f ms | ±%5.2f ms\n",
                kpi_rsa.sign.mean_ms, kpi_rsa.sign.median_ms, kpi_rsa.sign.stddev_ms);
  Serial.printf("  SIG-4 Signature Wire Size         : %u bytes (Fixed)\n", kpi_rsa.sig_bytes);
  Serial.printf("  SIG-5 Verify Latency (Mean/Med/σ) : %7.2f ms | %7.2f ms | ±%5.2f ms\n",
                kpi_rsa.verify.mean_ms, kpi_rsa.verify.median_ms, kpi_rsa.verify.stddev_ms);
  Serial.printf("  SIG-6 Crypto Auth Cost (Sign+Ver) : %7.2f ms\n", kpi_rsa.crypto_auth_cost_ms);
  Serial.printf("  SIG-7a Steady-State Heap (Sign+Ver): %u bytes\n", kpi_rsa.peak_heap_steady);
  Serial.printf("  SIG-7b KeyGen Heap (Provisioning) : %u bytes\n", kpi_rsa.peak_heap_keygen);
  Serial.printf("  SIG-8 Peak Crypto Stack Usage     : %u bytes (True)\n", kpi_rsa.peak_stack_bytes);
}

void print_comparison_table() {
  Serial.println("\n==========================================================================================");
  Serial.println("                              BENCHMARK RESULTS SUMMARY (PHASE A)                         ");
  Serial.println("==========================================================================================");
  Serial.printf("%-7s | %-37s | %-12s | %-12s | %-12s\n", "KPI ID", "Metric", "Ed25519", "ECDSA P-256", "RSA-3072");
  Serial.println("--------+---------------------------------------+--------------+--------------+-------------");
  Serial.printf("%-7s | %-37s | %8.2f ms | %8.2f ms | %8.2f ms\n", "SIG-1", "KeyGen Latency (Mean)", kpi_ed25519.keygen.mean_ms, kpi_p256.keygen.mean_ms, kpi_rsa.keygen.mean_ms);
  Serial.printf("%-7s | %-37s | %8.2f ms | %8.2f ms | %8.2f ms\n", "       ", "KeyGen Latency (Median)", kpi_ed25519.keygen.median_ms, kpi_p256.keygen.median_ms, kpi_rsa.keygen.median_ms);
  Serial.printf("%-7s | %-37s | %8.2f ms | %8.2f ms | %8.2f ms\n", "       ", "KeyGen Latency (StdDev σ)", kpi_ed25519.keygen.stddev_ms, kpi_p256.keygen.stddev_ms, kpi_rsa.keygen.stddev_ms);
  Serial.printf("%-7s | %-37s | %5.1f-%-4.1f ms| %5.1f-%-4.1f ms| %5.1f-%-4.1f s*\n", "       ", "KeyGen Range (Min - Max)",
                kpi_ed25519.keygen.min_ms, kpi_ed25519.keygen.max_ms,
                kpi_p256.keygen.min_ms, kpi_p256.keygen.max_ms,
                kpi_rsa.keygen.min_ms / 1000.0f, kpi_rsa.keygen.max_ms / 1000.0f);
  Serial.printf("%-7s | %-37s | %9u B | %9u B | %9u B\n", "SIG-2", "Public Key Wire Size", kpi_ed25519.pubkey_bytes, kpi_p256.pubkey_bytes, kpi_rsa.pubkey_bytes);
  Serial.printf("%-7s | %-37s | %8.2f ms | %8.2f ms | %8.2f ms\n", "SIG-3", "Message Signing Time (Mean)", kpi_ed25519.sign.mean_ms, kpi_p256.sign.mean_ms, kpi_rsa.sign.mean_ms);
  Serial.printf("%-7s | %-37s | %8.2f ms | %8.2f ms | %8.2f ms\n", "       ", "Message Signing Time (Median)", kpi_ed25519.sign.median_ms, kpi_p256.sign.median_ms, kpi_rsa.sign.median_ms);
  Serial.printf("%-7s | %-37s | %8.2f ms | %8.2f ms | %8.2f ms\n", "       ", "Message Signing Time (StdDev σ)", kpi_ed25519.sign.stddev_ms, kpi_p256.sign.stddev_ms, kpi_rsa.sign.stddev_ms);
  Serial.printf("%-7s | %-37s | %9u B | %9.1f B | %9u B\n", "SIG-4", "Signature Wire Size (Mean/Fixed)", kpi_ed25519.sig_bytes, kpi_p256.avg_sig_bytes, kpi_rsa.sig_bytes);
  Serial.printf("%-7s | %-37s | %6u-%u B | %6u-%u B | %6u-%u B\n", "       ", "Signature Wire Range (Min - Max)", kpi_ed25519.min_sig_bytes, kpi_ed25519.max_sig_bytes, kpi_p256.min_sig_bytes, kpi_p256.max_sig_bytes, kpi_rsa.min_sig_bytes, kpi_rsa.max_sig_bytes);
  Serial.printf("%-7s | %-37s | %8.2f ms | %8.2f ms | %8.2f ms\n", "SIG-5", "Verification Time (Mean)", kpi_ed25519.verify.mean_ms, kpi_p256.verify.mean_ms, kpi_rsa.verify.mean_ms);
  Serial.printf("%-7s | %-37s | %8.2f ms | %8.2f ms | %8.2f ms\n", "       ", "Verification Time (Median)", kpi_ed25519.verify.median_ms, kpi_p256.verify.median_ms, kpi_rsa.verify.median_ms);
  Serial.printf("%-7s | %-37s | %8.2f ms | %8.2f ms | %8.2f ms\n", "       ", "Verification Time (StdDev σ)", kpi_ed25519.verify.stddev_ms, kpi_p256.verify.stddev_ms, kpi_rsa.verify.stddev_ms);
  Serial.printf("%-7s | %-37s | %8.2f ms | %8.2f ms | %8.2f ms\n", "SIG-6", "Crypto Auth Cost (Sign+Verify)", kpi_ed25519.crypto_auth_cost_ms, kpi_p256.crypto_auth_cost_ms, kpi_rsa.crypto_auth_cost_ms);
  Serial.printf("%-7s | %-37s | %9u B | %9u B | %9u B\n", "SIG-7a", "Steady-State Heap (Sign+Verify)", kpi_ed25519.peak_heap_steady, kpi_p256.peak_heap_steady, kpi_rsa.peak_heap_steady);
  Serial.printf("%-7s | %-37s | %9u B | %9u B | %9u B\n", "SIG-7b", "KeyGen Peak Heap (Provisioning)", kpi_ed25519.peak_heap_keygen, kpi_p256.peak_heap_keygen, kpi_rsa.peak_heap_keygen);
  Serial.printf("%-7s | %-37s | %9u B | %9u B | %9u B\n", "SIG-8", "Peak Crypto Stack Usage (True)", kpi_ed25519.peak_stack_bytes, kpi_p256.peak_stack_bytes, kpi_rsa.peak_stack_bytes);
  Serial.printf("%-7s | %-37s | %10s   | %10s   | %10s  \n", "SIG-9", "Cryptographic Correctness",
                (g_crypto_failures == 0) ? "PASS (0 err)" : "FAIL",
                (g_crypto_failures == 0) ? "PASS (0 err)" : "FAIL",
                (g_crypto_failures == 0) ? "PASS (0 err)" : "FAIL");
  Serial.println("==========================================================================================");
  Serial.println("* Note: RSA-3072 KeyGen is an offline provisioning cost (heavy-tailed prime search).");
  Serial.println("  In an IoT VPN, keypair generation occurs once during factory provisioning, not per connection.\n");
}

void setup() {
  Serial.begin(115200);
  delay(2000);

  // Guarantee CPU frequency matches CPU_SPEED constant for accurate cycles -> ms conversion
  if (getCpuFrequencyMhz() != CPU_SPEED) {
    setCpuFrequencyMhz(CPU_SPEED);
  }

  Serial.println("\n==========================================================================================");
  Serial.println("             ESP32 Digital Signature Micro-Benchmark (Phase A: Isolated)                  ");
  Serial.println("------------------------------------------------------------------------------------------");
  Serial.printf("ESP-IDF Version   : %s\n", esp_get_idf_version());
  Serial.printf("Chip Model & Rev  : %s (Rev %d)\n", ESP.getChipModel(), ESP.getChipRevision());
  Serial.printf("CPU Frequency     : %d MHz\n", getCpuFrequencyMhz());
  Serial.printf("Initial Free Heap : %u bytes\n", ESP.getFreeHeap());
  Serial.printf("Flash Chip Size   : %u MB\n", ESP.getFlashChipSize() / (1024 * 1024));
  Serial.printf("Fast Runs: %d | RSA KeyGen Runs: %d\n", FAST_RUNS, SLOW_RSA_RUNS);
  Serial.println("==========================================================================================");

  if (sodium_init() < 0) {
    Serial.println("[ERROR] sodium_init() failed!");
    return;
  }

  // 1. Run RFC 8032 Known Answer Test (KAT) for Ed25519
  Serial.print("[KAT] Running RFC 8032 Section 7.1 Test Vector 1 for Ed25519... ");
  if (run_ed25519_kat()) {
    Serial.println("PASS (Formal RFC Compliance Verified)");
  } else {
    Serial.println("FAIL (Known Answer Mismatch!)");
    g_crypto_failures++;
  }

  randombytes_buf(test_message, MSG_SIZE);

  // Run each benchmark in a clean, dedicated FreeRTOS task to measure true stack watermark
  SemaphoreHandle_t sem = xSemaphoreCreateBinary();

  xTaskCreatePinnedToCore([](void* p) {
    test_ed25519();
    xSemaphoreGive((SemaphoreHandle_t)p);
    vTaskDelete(NULL);
  }, "ed_bench", BENCH_STACK_SIZE, sem, 5, NULL, 1);
  xSemaphoreTake(sem, portMAX_DELAY);

  xTaskCreatePinnedToCore([](void* p) {
    test_ecdsa_p256();
    xSemaphoreGive((SemaphoreHandle_t)p);
    vTaskDelete(NULL);
  }, "ec_bench", BENCH_STACK_SIZE, sem, 5, NULL, 1);
  xSemaphoreTake(sem, portMAX_DELAY);

  xTaskCreatePinnedToCore([](void* p) {
    test_rsa_3072();
    xSemaphoreGive((SemaphoreHandle_t)p);
    vTaskDelete(NULL);
  }, "rsa_bench", BENCH_STACK_SIZE, sem, 5, NULL, 1);
  xSemaphoreTake(sem, portMAX_DELAY);

  vSemaphoreDelete(sem);

  print_comparison_table();
}

void loop() {
  delay(10000);
}
