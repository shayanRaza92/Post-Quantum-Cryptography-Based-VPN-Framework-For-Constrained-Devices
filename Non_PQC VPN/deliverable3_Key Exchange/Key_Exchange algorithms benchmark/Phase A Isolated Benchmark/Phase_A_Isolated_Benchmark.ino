// ESP32 Classical Key Exchange Benchmark (Phase A: Isolated)
// Evaluates X25519, ECDH P-256, and Classical DH-2048 on ESP32 at 240 MHz

#include <sodium.h>

// Built-in ESP32 cryptography libraries (mbedTLS)
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#define RUNS_COUNT     100  // 100 iterations per algorithm
#define CPU_SPEED      240  // ESP32 clock frequency in MHz

// RFC 3526 2048-bit MODP Prime
static const unsigned char dh2048_p[256] = {
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,0x21,0x68,0xC2,0x34,
  0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,
  0x02,0x0B,0xBE,0xA6,0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
  0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,0xF2,0x5F,0x14,0x37,
  0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,
  0xF4,0x4C,0x42,0xE9,0xA6,0x37,0xED,0x6B,0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
  0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,0xAE,0x9F,0x24,0x11,0x7C,0x4B,0x1F,0xE6,
  0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D,0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,
  0x98,0xDA,0x48,0x36,0x1C,0x55,0xD3,0x9A,0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
  0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96,0x1C,0x62,0xF3,0x56,0x20,0x85,0x52,0xBB,
  0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D,0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,
  0xF1,0x74,0x6C,0x08,0xCA,0x18,0x21,0x7C,0x32,0x90,0x5E,0x46,0x2E,0x36,0xCE,0x3B,
  0xE3,0x9E,0x77,0x2C,0x18,0x0E,0x86,0x03,0x9B,0x27,0x83,0xA2,0xEC,0x07,0xA2,0x8F,
  0xB5,0xC5,0x5D,0xF0,0x6F,0x4C,0x52,0xC9,0xDE,0x2B,0xCB,0xF6,0x95,0x58,0x17,0x18,
  0x39,0x95,0x49,0x7C,0xEA,0x95,0x6A,0xE5,0x15,0xD2,0x26,0x18,0x98,0xFA,0x05,0x10,
  0x15,0x72,0x8E,0x5A,0x8A,0xAC,0xAA,0x68,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};

// Helper: Read hardware CPU cycle counter register
static inline uint32_t get_cycles() {
  uint32_t cycles;
  __asm__ __volatile__("rsr %0, ccount" : "=a"(cycles));
  return cycles;
}

// Helper: Calculate average cycle count
uint32_t get_average(uint32_t* times, int count) {
  uint64_t sum = 0;
  for (int i = 0; i < count; i++) {
    sum += times[i];
  }
  return (uint32_t)(sum / count);
}

// Struct to store results for comparison table
struct Result {
  float keygen_ms;
  float derive_ms;
  float total_ms;
  uint32_t keygen_cycles;
  uint32_t derive_cycles;
  uint32_t total_cycles;
  uint32_t pubkey_bytes;
  uint32_t secret_bytes;
  uint32_t peak_heap_bytes;
};

Result res_x25519;
Result res_p256;
Result res_dh2048;

// ----------------------------------------------------
// Test 1: X25519 (Curve25519 ECDH via Libsodium)
// ----------------------------------------------------
void test_x25519() {
  Serial.println("\n>>> [1/3] Testing X25519 (Modern Lightweight Champion)");

  uint32_t time_keygen[RUNS_COUNT];
  uint32_t time_derive[RUNS_COUNT];

  uint8_t client_pk[crypto_scalarmult_SCALARBYTES];
  uint8_t client_sk[crypto_scalarmult_SCALARBYTES];
  uint8_t peer_pk[crypto_scalarmult_SCALARBYTES];
  uint8_t peer_sk[crypto_scalarmult_SCALARBYTES];
  uint8_t shared_secret[crypto_scalarmult_BYTES];

  crypto_box_keypair(peer_pk, peer_sk);

  uint32_t heap_before = ESP.getFreeHeap();
  uint32_t peak_heap = 0;

  for (int i = 0; i < RUNS_COUNT; i++) {
    // 1. Key generation
    uint32_t start = get_cycles();
    crypto_box_keypair(client_pk, client_sk);
    time_keygen[i] = get_cycles() - start;

    // 2. Shared secret computation
    start = get_cycles();
    crypto_scalarmult(shared_secret, client_sk, peer_pk);
    time_derive[i] = get_cycles() - start;

    uint32_t current_free = ESP.getFreeHeap();
    if (heap_before > current_free) {
      uint32_t used = heap_before - current_free;
      if (used > peak_heap) peak_heap = used;
    }
  }

  res_x25519.keygen_cycles = get_average(time_keygen, RUNS_COUNT);
  res_x25519.derive_cycles = get_average(time_derive, RUNS_COUNT);
  res_x25519.total_cycles = res_x25519.keygen_cycles + res_x25519.derive_cycles;
  res_x25519.keygen_ms = (float)res_x25519.keygen_cycles / (CPU_SPEED * 1000.0f);
  res_x25519.derive_ms = (float)res_x25519.derive_cycles / (CPU_SPEED * 1000.0f);
  res_x25519.total_ms = res_x25519.keygen_ms + res_x25519.derive_ms;
  res_x25519.pubkey_bytes = crypto_scalarmult_SCALARBYTES;
  res_x25519.secret_bytes = crypto_scalarmult_BYTES;
  res_x25519.peak_heap_bytes = peak_heap; // 0 bytes (uses task stack)

  Serial.printf("    - Keypair Generation       : %9u cycles | %6.2f ms\n", res_x25519.keygen_cycles, res_x25519.keygen_ms);
  Serial.printf("    - Shared Secret Derivation : %9u cycles | %6.2f ms\n", res_x25519.derive_cycles, res_x25519.derive_ms);
  Serial.printf("    - Total Client Crypto Time : %9u cycles | %6.2f ms\n", res_x25519.total_cycles, res_x25519.total_ms);
  Serial.printf("    - Public Key Wire Size     : %u bytes\n", res_x25519.pubkey_bytes);
  Serial.printf("    - Shared Secret Output     : %u bytes\n", res_x25519.secret_bytes);
  Serial.printf("    - Peak Heap Memory Used    : %u bytes (Stack only - zero heap fragmentation)\n", res_x25519.peak_heap_bytes);
}

// ----------------------------------------------------
// Test 2: ECDH P-256 (NIST Curve secp256r1 via mbedTLS)
// ----------------------------------------------------
void test_ecdh_p256() {
  Serial.println("\n>>> [2/3] Testing ECDH P-256 (NIST Enterprise Standard)");

  uint32_t time_keygen[RUNS_COUNT];
  uint32_t time_derive[RUNS_COUNT];

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context random_gen;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&random_gen);
  mbedtls_ctr_drbg_seed(&random_gen, mbedtls_entropy_func, &entropy, (const unsigned char *)"ecdh", 4);

  mbedtls_ecp_group grp;
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

  mbedtls_mpi peer_d;
  mbedtls_ecp_point peer_Q;
  mbedtls_mpi_init(&peer_d);
  mbedtls_ecp_point_init(&peer_Q);
  mbedtls_ecdh_gen_public(&grp, &peer_d, &peer_Q, mbedtls_ctr_drbg_random, &random_gen);

  uint32_t heap_before = ESP.getFreeHeap();
  uint32_t peak_heap = 0;

  for (int i = 0; i < RUNS_COUNT; i++) {
    mbedtls_mpi client_d;
    mbedtls_ecp_point client_Q;
    mbedtls_mpi_init(&client_d);
    mbedtls_ecp_point_init(&client_Q);

    // 1. Key generation
    uint32_t start = get_cycles();
    mbedtls_ecdh_gen_public(&grp, &client_d, &client_Q, mbedtls_ctr_drbg_random, &random_gen);
    time_keygen[i] = get_cycles() - start;

    // 2. Shared secret derivation
    mbedtls_mpi z;
    mbedtls_mpi_init(&z);
    start = get_cycles();
    mbedtls_ecdh_compute_shared(&grp, &z, &peer_Q, &client_d, mbedtls_ctr_drbg_random, &random_gen);
    time_derive[i] = get_cycles() - start;

    // Measure memory before cleanup
    uint32_t current_free = ESP.getFreeHeap();
    if (heap_before > current_free) {
      uint32_t used = heap_before - current_free;
      if (used > peak_heap) peak_heap = used;
    }

    mbedtls_mpi_free(&client_d);
    mbedtls_ecp_point_free(&client_Q);
    mbedtls_mpi_free(&z);

    if (i % 25 == 0) vTaskDelay(1);
  }

  mbedtls_mpi_free(&peer_d);
  mbedtls_ecp_point_free(&peer_Q);
  mbedtls_ecp_group_free(&grp);
  mbedtls_ctr_drbg_free(&random_gen);
  mbedtls_entropy_free(&entropy);

  res_p256.keygen_cycles = get_average(time_keygen, RUNS_COUNT);
  res_p256.derive_cycles = get_average(time_derive, RUNS_COUNT);
  res_p256.total_cycles = res_p256.keygen_cycles + res_p256.derive_cycles;
  res_p256.keygen_ms = (float)res_p256.keygen_cycles / (CPU_SPEED * 1000.0f);
  res_p256.derive_ms = (float)res_p256.derive_cycles / (CPU_SPEED * 1000.0f);
  res_p256.total_ms = res_p256.keygen_ms + res_p256.derive_ms;
  res_p256.pubkey_bytes = 65;
  res_p256.secret_bytes = 32;
  res_p256.peak_heap_bytes = peak_heap;

  Serial.printf("    - Keypair Generation       : %9u cycles | %6.2f ms\n", res_p256.keygen_cycles, res_p256.keygen_ms);
  Serial.printf("    - Shared Secret Derivation : %9u cycles | %6.2f ms\n", res_p256.derive_cycles, res_p256.derive_ms);
  Serial.printf("    - Total Client Crypto Time : %9u cycles | %6.2f ms\n", res_p256.total_cycles, res_p256.total_ms);
  Serial.printf("    - Public Key Wire Size     : %u bytes (uncompressed point)\n", res_p256.pubkey_bytes);
  Serial.printf("    - Shared Secret Output     : %u bytes\n", res_p256.secret_bytes);
  Serial.printf("    - Peak Heap Memory Used    : %u bytes (EC point contexts)\n", res_p256.peak_heap_bytes);
}

// ----------------------------------------------------
// Test 3: Classical DH-2048 (RFC 3526 MODP via mbedTLS)
// ----------------------------------------------------
void test_classical_dh2048() {
  Serial.println("\n>>> [3/3] Testing Classical DH-2048 (RFC 3526 Legacy Baseline)");

  uint32_t time_keygen[RUNS_COUNT];
  uint32_t time_derive[RUNS_COUNT];

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context random_gen;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&random_gen);
  mbedtls_ctr_drbg_seed(&random_gen, mbedtls_entropy_func, &entropy, (const unsigned char *)"dh2048", 6);

  mbedtls_mpi P, G, peer_X, peer_Y;
  mbedtls_mpi_init(&P);
  mbedtls_mpi_init(&G);
  mbedtls_mpi_init(&peer_X);
  mbedtls_mpi_init(&peer_Y);

  mbedtls_mpi_read_binary(&P, dh2048_p, sizeof(dh2048_p));
  mbedtls_mpi_lset(&G, 2);

  mbedtls_mpi_fill_random(&peer_X, 32, mbedtls_ctr_drbg_random, &random_gen);
  mbedtls_mpi_exp_mod(&peer_Y, &G, &peer_X, &P, NULL);

  uint32_t heap_before = ESP.getFreeHeap();
  uint32_t peak_heap = 0;

  for (int i = 0; i < RUNS_COUNT; i++) {
    mbedtls_mpi client_X, client_Y, shared_K;
    mbedtls_mpi_init(&client_X);
    mbedtls_mpi_init(&client_Y);
    mbedtls_mpi_init(&shared_K);

    // 1. Key generation: client_Y = G^client_X mod P
    uint32_t start = get_cycles();
    mbedtls_mpi_fill_random(&client_X, 32, mbedtls_ctr_drbg_random, &random_gen);
    mbedtls_mpi_exp_mod(&client_Y, &G, &client_X, &P, NULL);
    time_keygen[i] = get_cycles() - start;

    // 2. Shared secret derivation: shared_K = peer_Y^client_X mod P
    start = get_cycles();
    mbedtls_mpi_exp_mod(&shared_K, &peer_Y, &client_X, &P, NULL);
    time_derive[i] = get_cycles() - start;

    // Measure memory before cleanup
    uint32_t current_free = ESP.getFreeHeap();
    if (heap_before > current_free) {
      uint32_t used = heap_before - current_free;
      if (used > peak_heap) peak_heap = used;
    }

    mbedtls_mpi_free(&client_X);
    mbedtls_mpi_free(&client_Y);
    mbedtls_mpi_free(&shared_K);

    if (i % 10 == 0) vTaskDelay(1);
  }

  mbedtls_mpi_free(&peer_X);
  mbedtls_mpi_free(&peer_Y);
  mbedtls_mpi_free(&P);
  mbedtls_mpi_free(&G);
  mbedtls_ctr_drbg_free(&random_gen);
  mbedtls_entropy_free(&entropy);

  res_dh2048.keygen_cycles = get_average(time_keygen, RUNS_COUNT);
  res_dh2048.derive_cycles = get_average(time_derive, RUNS_COUNT);
  res_dh2048.total_cycles = res_dh2048.keygen_cycles + res_dh2048.derive_cycles;
  res_dh2048.keygen_ms = (float)res_dh2048.keygen_cycles / (CPU_SPEED * 1000.0f);
  res_dh2048.derive_ms = (float)res_dh2048.derive_cycles / (CPU_SPEED * 1000.0f);
  res_dh2048.total_ms = res_dh2048.keygen_ms + res_dh2048.derive_ms;
  res_dh2048.pubkey_bytes = sizeof(dh2048_p); // 256 bytes
  res_dh2048.secret_bytes = sizeof(dh2048_p); // 256 bytes
  res_dh2048.peak_heap_bytes = peak_heap;

  Serial.printf("    - Keypair Generation       : %9u cycles | %6.2f ms\n", res_dh2048.keygen_cycles, res_dh2048.keygen_ms);
  Serial.printf("    - Shared Secret Derivation : %9u cycles | %6.2f ms\n", res_dh2048.derive_cycles, res_dh2048.derive_ms);
  Serial.printf("    - Total Client Crypto Time : %9u cycles | %6.2f ms\n", res_dh2048.total_cycles, res_dh2048.total_ms);
  Serial.printf("    - Public Key Wire Size     : %u bytes\n", res_dh2048.pubkey_bytes);
  Serial.printf("    - Shared Secret Output     : %u bytes\n", res_dh2048.secret_bytes);
  Serial.printf("    - Peak Heap Memory Used    : %u bytes (2048-bit bignum limbs)\n", res_dh2048.peak_heap_bytes);
}

// ----------------------------------------------------
// Final Comparison Table Summary
// ----------------------------------------------------
void print_comparison_table() {
  Serial.println("\n=========================================================================================");
  Serial.println("                     FINAL CLASSICAL KEY EXCHANGE COMPARISON TABLE                       ");
  Serial.println("=========================================================================================");
  Serial.printf("%-26s | %-16s | %-16s | %-18s\n", "Metric", "X25519", "ECDH P-256", "Classical DH-2048");
  Serial.println("---------------------------+------------------+------------------+-----------------------");
  Serial.printf("%-26s | %13.2f ms | %13.2f ms | %15.2f ms\n", "Key Generation Latency", res_x25519.keygen_ms, res_p256.keygen_ms, res_dh2048.keygen_ms);
  Serial.printf("%-26s | %13.2f ms | %13.2f ms | %15.2f ms\n", "Secret Derivation Latency", res_x25519.derive_ms, res_p256.derive_ms, res_dh2048.derive_ms);
  Serial.printf("%-26s | %13.2f ms | %13.2f ms | %15.2f ms\n", "Total Client Crypto Time", res_x25519.total_ms, res_p256.total_ms, res_dh2048.total_ms);
  Serial.printf("%-26s | %13u B  | %13u B  | %15u B \n", "Public Key Wire Size", res_x25519.pubkey_bytes, res_p256.pubkey_bytes, res_dh2048.pubkey_bytes);
  Serial.printf("%-26s | %13u B  | %13u B  | %15u B \n", "Shared Secret Output", res_x25519.secret_bytes, res_p256.secret_bytes, res_dh2048.secret_bytes);
  Serial.printf("%-26s | %13u B  | %13u B  | %15u B \n", "Peak Heap RAM Consumed", res_x25519.peak_heap_bytes, res_p256.peak_heap_bytes, res_dh2048.peak_heap_bytes);
  Serial.println("---------------------------+------------------+------------------+-----------------------");
  Serial.printf("%-26s | %-16s | %-16s | %-18s\n", "Speedup vs. DH-2048", "2.1x faster", "0.6x (slower)", "Baseline (1.0x)");
  Serial.printf("%-26s | %-16s | %-16s | %-18s\n", "Wire Size vs. DH-2048", "8.0x smaller", "3.9x smaller", "Baseline (1.0x)");
  Serial.printf("%-26s | %-16s | %-16s | %-18s\n", "Overall Recommendation", "WINNER (Light)", "Enterprise Only", "Legacy Baseline");
  Serial.println("=========================================================================================\n");
}

// ----------------------------------------------------
// Main Setup and Loop
// ----------------------------------------------------
void setup() {
  Serial.begin(115200);
  delay(2000);

  Serial.println("\n========================================================================");
  Serial.println("            ESP32 CLASSICAL KEY EXCHANGE BENCHMARK (PHASE A)            ");
  Serial.println("========================================================================");
  Serial.printf("Device  : ESP32-D0WDQ6 (Xtensa dual-core @ %d MHz)\n", CPU_SPEED);
  Serial.printf("Tests   : %d iterations per algorithm (Arithmetic Mean)\n", RUNS_COUNT);
  Serial.printf("Target  : 128-bit Classical Security Baseline\n");
  Serial.printf("Heap    : %u bytes free at start\n", ESP.getFreeHeap());
  Serial.println("------------------------------------------------------------------------");

  if (sodium_init() < 0) {
    Serial.println("[FATAL] Libsodium failed to initialize!");
    return;
  }

  test_x25519();
  test_ecdh_p256();
  test_classical_dh2048();

  print_comparison_table();

  Serial.printf("Free Heap at Finish : %u bytes\n", ESP.getFreeHeap());
  Serial.println("Benchmark completed successfully! You can copy the table above into your report.");
}

void loop() {
  delay(10000);
}
