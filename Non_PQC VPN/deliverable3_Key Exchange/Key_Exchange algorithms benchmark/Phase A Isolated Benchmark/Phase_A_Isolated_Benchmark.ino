// ==============================================================================
// ESP32 Classical Key Exchange Micro-Benchmark (Phase A: Isolated)
//
// Evaluates traditional/classical key exchange algorithms on the ESP32
// microcontroller at an equivalent 128-bit classical security baseline.
//
// Algorithms Tested:
//   1. X25519 (Curve25519 ECDH via Libsodium) - Modern lightweight baseline
//   2. ECDH P-256 (NIST secp256r1 via Mbed TLS) - Enterprise standard
//   3. Classical DH-2048 (RFC 3526 MODP via Mbed TLS DHM) - Legacy baseline
//
// Timing: Cycle-accurate measurement using ESP32 hardware register 'ccount' (240 MHz).
// Memory: Dynamic heap profiling via ESP.getFreeHeap().
// ==============================================================================

#include <sodium.h>

// Built-in ESP32 cryptography libraries (Mbed TLS)
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/dhm.h"
#include "mbedtls/bignum.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

// Configuration parameters
#define RUNS_COUNT     100   // 100 iterations per algorithm (matches Basil's thesis)
#define CPU_SPEED      240   // ESP32 clock frequency in MHz (240,000,000 cycles/sec)

// Helper: Read hardware CPU cycle counter register
static inline uint32_t get_cycles() {
  uint32_t cycles;
  __asm__ __volatile__("rsr %0, ccount" : "=a"(cycles));
  return cycles;
}

// Helper: Calculate average cycle count from array
uint32_t get_average(uint32_t* arr, int count) {
  uint64_t sum = 0;
  for (int i = 0; i < count; i++) {
    sum += arr[i];
  }
  return (uint32_t)(sum / count);
}

// Helper: Print a single metric result line
void print_metric(const char* label, uint32_t avg_cycles, int runs) {
  float time_ms = (float)avg_cycles / (CPU_SPEED * 1000.0f);
  Serial.printf("  %-28s: %9u cycles | %6.2f ms (Avg over %d runs)\n", label, avg_cycles, time_ms, runs);
}

// Structure to store final summary numbers
struct BenchmarkResult {
  const char* name;
  uint32_t keygen_cycles;
  float keygen_ms;
  uint32_t derive_cycles;
  float derive_ms;
  uint32_t total_cycles;
  float total_ms;
  size_t pubkey_bytes;
  size_t secret_bytes;
  int32_t heap_delta;
};

BenchmarkResult res_x25519;
BenchmarkResult res_p256;
BenchmarkResult res_dh2048;

// ==============================================================================
// Test 1: X25519 (Curve25519 ECDH via Libsodium)
// ==============================================================================
void test_x25519() {
  Serial.println("\n------------------------------------------------------------");
  Serial.println("[1/3] Testing X25519 (Curve25519 - Modern Lightweight Champion)");
  Serial.println("------------------------------------------------------------");

  uint32_t time_keygen[RUNS_COUNT];
  uint32_t time_derive[RUNS_COUNT];

  uint8_t client_pk[crypto_scalarmult_SCALARBYTES];
  uint8_t client_sk[crypto_scalarmult_SCALARBYTES];
  uint8_t peer_pk[crypto_scalarmult_SCALARBYTES];
  uint8_t peer_sk[crypto_scalarmult_SCALARBYTES];
  uint8_t shared_secret[crypto_scalarmult_BYTES];

  // Pre-generate a peer keypair simulating incoming peer public key
  crypto_box_keypair(peer_pk, peer_sk);

  uint32_t heap_before = ESP.getFreeHeap();

  for (int i = 0; i < RUNS_COUNT; i++) {
    // 1. Key generation (client generates fresh ephemeral keypair)
    uint32_t start = get_cycles();
    crypto_box_keypair(client_pk, client_sk);
    time_keygen[i] = get_cycles() - start;

    // 2. Shared secret computation (scalar multiplication: client_sk * peer_pk)
    start = get_cycles();
    int ret = crypto_scalarmult(shared_secret, client_sk, peer_pk);
    time_derive[i] = get_cycles() - start;

    if (ret != 0 && i == 0) {
      Serial.println("  [ERROR] crypto_scalarmult failed!");
    }
  }

  uint32_t heap_after = ESP.getFreeHeap();

  res_x25519.name = "X25519 (Curve25519)";
  res_x25519.keygen_cycles = get_average(time_keygen, RUNS_COUNT);
  res_x25519.keygen_ms = (float)res_x25519.keygen_cycles / (CPU_SPEED * 1000.0f);
  res_x25519.derive_cycles = get_average(time_derive, RUNS_COUNT);
  res_x25519.derive_ms = (float)res_x25519.derive_cycles / (CPU_SPEED * 1000.0f);
  res_x25519.total_cycles = res_x25519.keygen_cycles + res_x25519.derive_cycles;
  res_x25519.total_ms = res_x25519.keygen_ms + res_x25519.derive_ms;
  res_x25519.pubkey_bytes = crypto_scalarmult_SCALARBYTES; // 32 bytes
  res_x25519.secret_bytes = crypto_scalarmult_BYTES;       // 32 bytes
  res_x25519.heap_delta = (int32_t)(heap_before - heap_after);

  Serial.printf("  Free Heap Before Test       : %u bytes\n", heap_before);
  Serial.printf("  Free Heap After Test        : %u bytes\n", heap_after);
  Serial.printf("  Dynamic Heap Delta          : %d bytes\n\n", res_x25519.heap_delta);

  print_metric("Keypair Generation", res_x25519.keygen_cycles, RUNS_COUNT);
  print_metric("Shared Secret Derivation", res_x25519.derive_cycles, RUNS_COUNT);
  print_metric("Total Client Crypto Time", res_x25519.total_cycles, RUNS_COUNT);

  Serial.println("");
  Serial.printf("  Public Key Wire Size        : %d bytes\n", res_x25519.pubkey_bytes);
  Serial.printf("  Shared Secret Size          : %d bytes\n", res_x25519.secret_bytes);
}

// ==============================================================================
// Test 2: ECDH P-256 (NIST Curve secp256r1 via Mbed TLS)
// ==============================================================================
void test_ecdh_p256() {
  Serial.println("\n------------------------------------------------------------");
  Serial.println("[2/3] Testing ECDH P-256 (NIST Curve - Enterprise Standard)");
  Serial.println("------------------------------------------------------------");

  uint32_t time_keygen[RUNS_COUNT];
  uint32_t time_derive[RUNS_COUNT];

  // Setup cryptographically secure random number generator (CTR_DRBG)
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context drbg;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&drbg);
  mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)"ecdh_p256", 9);

  // Pre-generate peer's public key simulating server's ephemeral key
  mbedtls_ecdh_context peer_ctx;
  mbedtls_ecdh_init(&peer_ctx);
  mbedtls_ecdh_setup(&peer_ctx, MBEDTLS_ECP_DP_SECP256R1);
  uint8_t peer_pk[65];
  size_t peer_pk_len = 0;
  mbedtls_ecdh_make_public(&peer_ctx, &peer_pk_len, peer_pk, sizeof(peer_pk), mbedtls_ctr_drbg_random, &drbg);

  uint32_t heap_before = ESP.getFreeHeap();
  size_t recorded_pubkey_len = 0;
  size_t recorded_secret_len = 0;

  for (int i = 0; i < RUNS_COUNT; i++) {
    mbedtls_ecdh_context client_ctx;
    mbedtls_ecdh_init(&client_ctx);
    mbedtls_ecdh_setup(&client_ctx, MBEDTLS_ECP_DP_SECP256R1);

    uint8_t client_pk[65];
    size_t client_pk_len = 0;

    // 1. Key generation
    uint32_t start = get_cycles();
    mbedtls_ecdh_make_public(&client_ctx, &client_pk_len, client_pk, sizeof(client_pk), mbedtls_ctr_drbg_random, &drbg);
    time_keygen[i] = get_cycles() - start;

    if (i == 0) recorded_pubkey_len = client_pk_len;

    // Read peer's public key
    mbedtls_ecdh_read_public(&client_ctx, peer_pk, peer_pk_len);

    // 2. Shared secret derivation
    uint8_t secret[32];
    size_t secret_len = 0;
    start = get_cycles();
    mbedtls_ecdh_calc_secret(&client_ctx, &secret_len, secret, sizeof(secret), mbedtls_ctr_drbg_random, &drbg);
    time_derive[i] = get_cycles() - start;

    if (i == 0) recorded_secret_len = secret_len;

    mbedtls_ecdh_free(&client_ctx);

    // Feed FreeRTOS watchdog periodically
    if (i % 25 == 0) vTaskDelay(1);
  }

  uint32_t heap_after = ESP.getFreeHeap();

  // Cleanup helper contexts
  mbedtls_ecdh_free(&peer_ctx);
  mbedtls_ctr_drbg_free(&drbg);
  mbedtls_entropy_free(&entropy);

  res_p256.name = "ECDH P-256 (secp256r1)";
  res_p256.keygen_cycles = get_average(time_keygen, RUNS_COUNT);
  res_p256.keygen_ms = (float)res_p256.keygen_cycles / (CPU_SPEED * 1000.0f);
  res_p256.derive_cycles = get_average(time_derive, RUNS_COUNT);
  res_p256.derive_ms = (float)res_p256.derive_cycles / (CPU_SPEED * 1000.0f);
  res_p256.total_cycles = res_p256.keygen_cycles + res_p256.derive_cycles;
  res_p256.total_ms = res_p256.keygen_ms + res_p256.derive_ms;
  res_p256.pubkey_bytes = recorded_pubkey_len;
  res_p256.secret_bytes = recorded_secret_len;
  res_p256.heap_delta = (int32_t)(heap_before - heap_after);

  Serial.printf("  Free Heap Before Test       : %u bytes\n", heap_before);
  Serial.printf("  Free Heap After Test        : %u bytes\n", heap_after);
  Serial.printf("  Dynamic Heap Delta          : %d bytes\n\n", res_p256.heap_delta);

  print_metric("Keypair Generation", res_p256.keygen_cycles, RUNS_COUNT);
  print_metric("Shared Secret Derivation", res_p256.derive_cycles, RUNS_COUNT);
  print_metric("Total Client Crypto Time", res_p256.total_cycles, RUNS_COUNT);

  Serial.println("");
  Serial.printf("  Public Key Wire Size        : %d bytes (uncompressed point)\n", res_p256.pubkey_bytes);
  Serial.printf("  Shared Secret Size          : %d bytes\n", res_p256.secret_bytes);
}

// ==============================================================================
// Test 3: Classical DH-2048 (RFC 3526 MODP Group via Mbed TLS DHM)
// ==============================================================================
void test_classical_dh2048() {
  Serial.println("\n------------------------------------------------------------");
  Serial.println("[3/3] Testing Classical DH-2048 (RFC 3526 MODP - Legacy Baseline)");
  Serial.println("------------------------------------------------------------");

  uint32_t time_keygen[RUNS_COUNT];
  uint32_t time_derive[RUNS_COUNT];

  // Setup DRBG
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context drbg;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&drbg);
  mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)"dhm_2048", 8);

  // RFC 3526 2048-bit MODP Prime and Generator (g = 2)
  const unsigned char p_bin[] = MBEDTLS_DHM_RFC3526_MODP_2048_P_BIN;
  const unsigned char g_bin[] = MBEDTLS_DHM_RFC3526_MODP_2048_G_BIN;

  mbedtls_mpi P, G;
  mbedtls_mpi_init(&P);
  mbedtls_mpi_init(&G);
  mbedtls_mpi_read_binary(&P, p_bin, sizeof(p_bin));
  mbedtls_mpi_read_binary(&G, g_bin, sizeof(g_bin));

  // Pre-generate peer's public key
  mbedtls_dhm_context peer_ctx;
  mbedtls_dhm_init(&peer_ctx);
  mbedtls_dhm_set_group(&peer_ctx, &P, &G);
  uint8_t peer_pub[sizeof(p_bin)];
  mbedtls_dhm_make_public(&peer_ctx, sizeof(p_bin), peer_pub, sizeof(peer_pub), mbedtls_ctr_drbg_random, &drbg);

  uint32_t heap_before = ESP.getFreeHeap();
  size_t recorded_secret_len = 0;

  Serial.println("  Running 100 iterations of DH-2048 (modular exponentiation)...");

  for (int i = 0; i < RUNS_COUNT; i++) {
    mbedtls_dhm_context client_ctx;
    mbedtls_dhm_init(&client_ctx);
    mbedtls_dhm_set_group(&client_ctx, &P, &G);

    uint8_t client_pub[sizeof(p_bin)];

    // 1. Key generation (compute g^x mod P)
    uint32_t start = get_cycles();
    mbedtls_dhm_make_public(&client_ctx, sizeof(p_bin), client_pub, sizeof(client_pub), mbedtls_ctr_drbg_random, &drbg);
    time_keygen[i] = get_cycles() - start;

    // Read peer's public value
    mbedtls_dhm_read_public(&client_ctx, peer_pub, sizeof(peer_pub));

    // 2. Shared secret derivation (compute Y^x mod P)
    uint8_t secret[sizeof(p_bin)];
    size_t secret_len = 0;
    start = get_cycles();
    mbedtls_dhm_calc_secret(&client_ctx, secret, sizeof(secret), &secret_len, mbedtls_ctr_drbg_random, &drbg);
    time_derive[i] = get_cycles() - start;

    if (i == 0) recorded_secret_len = secret_len;

    mbedtls_dhm_free(&client_ctx);

    // Regularly feed FreeRTOS watchdog to prevent reset on heavy modular math
    if (i % 10 == 0) {
      vTaskDelay(1);
    }
  }

  uint32_t heap_after = ESP.getFreeHeap();

  // Cleanup helper contexts
  mbedtls_dhm_free(&peer_ctx);
  mbedtls_mpi_free(&P);
  mbedtls_mpi_free(&G);
  mbedtls_ctr_drbg_free(&drbg);
  mbedtls_entropy_free(&entropy);

  res_dh2048.name = "Classical DH-2048";
  res_dh2048.keygen_cycles = get_average(time_keygen, RUNS_COUNT);
  res_dh2048.keygen_ms = (float)res_dh2048.keygen_cycles / (CPU_SPEED * 1000.0f);
  res_dh2048.derive_cycles = get_average(time_derive, RUNS_COUNT);
  res_dh2048.derive_ms = (float)res_dh2048.derive_cycles / (CPU_SPEED * 1000.0f);
  res_dh2048.total_cycles = res_dh2048.keygen_cycles + res_dh2048.derive_cycles;
  res_dh2048.total_ms = res_dh2048.keygen_ms + res_dh2048.derive_ms;
  res_dh2048.pubkey_bytes = sizeof(p_bin);   // 256 bytes
  res_dh2048.secret_bytes = recorded_secret_len;
  res_dh2048.heap_delta = (int32_t)(heap_before - heap_after);

  Serial.printf("  Free Heap Before Test       : %u bytes\n", heap_before);
  Serial.printf("  Free Heap After Test        : %u bytes\n", heap_after);
  Serial.printf("  Dynamic Heap Delta          : %d bytes\n\n", res_dh2048.heap_delta);

  print_metric("Keypair Generation", res_dh2048.keygen_cycles, RUNS_COUNT);
  print_metric("Shared Secret Derivation", res_dh2048.derive_cycles, RUNS_COUNT);
  print_metric("Total Client Crypto Time", res_dh2048.total_cycles, RUNS_COUNT);

  Serial.println("");
  Serial.printf("  Public Key Wire Size        : %d bytes\n", res_dh2048.pubkey_bytes);
  Serial.printf("  Shared Secret Size          : %d bytes\n", res_dh2048.secret_bytes);
}

// ==============================================================================
// Final Comparison Table Summary
// ==============================================================================
void print_comparison_table() {
  Serial.println("\n=============================================================================================");
  Serial.println("                     FINAL CLASSICAL KEY EXCHANGE COMPARISON TABLE                          ");
  Serial.println("=============================================================================================");
  Serial.printf("%-26s | %-16s | %-16s | %-18s\n", "Metric", "X25519", "ECDH P-256", "Classical DH-2048");
  Serial.println("---------------------------------------------------------------------------------------------");
  Serial.printf("%-26s | %13.2f ms | %13.2f ms | %15.2f ms\n", "Key Generation Time", res_x25519.keygen_ms, res_p256.keygen_ms, res_dh2048.keygen_ms);
  Serial.printf("%-26s | %13.2f ms | %13.2f ms | %15.2f ms\n", "Secret Derivation Time", res_x25519.derive_ms, res_p256.derive_ms, res_dh2048.derive_ms);
  Serial.printf("%-26s | %13.2f ms | %13.2f ms | %15.2f ms\n", "Total Client Crypto Time", res_x25519.total_ms, res_p256.total_ms, res_dh2048.total_ms);
  Serial.printf("%-26s | %13u B  | %13u B  | %15u B \n", "Public Key Wire Size", (unsigned int)res_x25519.pubkey_bytes, (unsigned int)res_p256.pubkey_bytes, (unsigned int)res_dh2048.pubkey_bytes);
  Serial.printf("%-26s | %13u B  | %13u B  | %15u B \n", "Shared Secret Size", (unsigned int)res_x25519.secret_bytes, (unsigned int)res_p256.secret_bytes, (unsigned int)res_dh2048.secret_bytes);
  Serial.printf("%-26s | %13d B  | %13d B  | %15d B \n", "Heap Memory Consumed", res_x25519.heap_delta, res_p256.heap_delta, res_dh2048.heap_delta);
  Serial.println("=============================================================================================");
  Serial.println("\nKEY FINDINGS FOR YOUR THESIS:");
  Serial.printf("  1. X25519 Speedup vs. DH-2048   : %.1fx faster total crypto time\n", res_dh2048.total_ms / res_x25519.total_ms);
  Serial.printf("  2. X25519 Speedup vs. ECDH P-256: %.1fx faster total crypto time\n", res_p256.total_ms / res_x25519.total_ms);
  Serial.printf("  3. Wire Size Advantage          : X25519 (32B) is %.1fx smaller than DH-2048 (256B)\n", (float)res_dh2048.pubkey_bytes / (float)res_x25519.pubkey_bytes);
  Serial.println("=============================================================================================\n");
}

// ==============================================================================
// Main Setup and Loop
// ==============================================================================
void setup() {
  Serial.begin(115200);
  delay(2000); // Wait for Serial Monitor connection

  Serial.println("\n============================================================");
  Serial.println("  ESP32 Classical Key Exchange Benchmark (Phase A: Isolated)");
  Serial.println("============================================================");
  Serial.printf("Iterations per test : %d runs\n", RUNS_COUNT);
  Serial.printf("Target Frequency    : %d MHz\n", CPU_SPEED);
  Serial.printf("Free Heap at Start  : %u bytes\n", ESP.getFreeHeap());

  // Initialize Libsodium
  if (sodium_init() < 0) {
    Serial.println("[FATAL] Libsodium failed to initialize!");
    return;
  }

  // Execute isolated benchmarks sequentially
  test_x25519();
  test_ecdh_p256();
  test_classical_dh2048();

  // Print master summary table
  print_comparison_table();

  Serial.printf("Free Heap at Finish : %u bytes\n", ESP.getFreeHeap());
  Serial.println("Benchmark completed successfully! You can copy the table above into your report.");
}

void loop() {
  // Tests run once on startup. Idle loop.
  delay(10000);
}
