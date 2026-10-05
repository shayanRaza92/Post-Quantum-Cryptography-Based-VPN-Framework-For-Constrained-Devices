// ESP32 Benchmark for Key Exchange
// Tests X25519, ECDH P-256, and Classical DH-2048

#include <sodium.h>

// Built-in ESP32 cryptography libraries (mbedTLS)
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/dhm.h"
#include "mbedtls/bignum.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

// Setup how many times to run each test
#define RUNS_COUNT     100  // Runs 100 times for all algorithms
#define CPU_SPEED      240  // ESP32 runs at 240 MHz

// Helper: Get exact CPU cycles
static inline uint32_t get_cycles() {
  uint32_t cycles;
  __asm__ __volatile__("rsr %0, ccount" : "=a"(cycles));
  return cycles;
}

// Helper: Calculate average time
uint32_t get_average(uint32_t* times, int count) {
  uint64_t sum = 0;
  for (int i = 0; i < count; i++) {
    sum += times[i];
  }
  return (uint32_t)(sum / count);
}

// Helper: Print nicely
void print_result(const char* name, uint32_t average_cycles, int runs) {
  float time_in_ms = (float)average_cycles / (CPU_SPEED * 1000.0f);
  Serial.printf("  %s: %u cycles | %.2f ms (Average over %d runs)\n", name, average_cycles, time_in_ms, runs);
}

// ----------------------------------------------------
// Test 1: X25519
// ----------------------------------------------------
void test_x25519() {
  Serial.println("\n[1/3] Testing X25519 (Fast and Modern)");

  uint32_t time_keygen[RUNS_COUNT];
  uint32_t time_derive[RUNS_COUNT];

  uint8_t client_pk[crypto_scalarmult_SCALARBYTES];
  uint8_t client_sk[crypto_scalarmult_SCALARBYTES];
  uint8_t peer_pk[crypto_scalarmult_SCALARBYTES];
  uint8_t peer_sk[crypto_scalarmult_SCALARBYTES];
  uint8_t shared_secret[crypto_scalarmult_BYTES];

  // Make a peer key to use for shared secret calculation
  crypto_box_keypair(peer_pk, peer_sk);

  uint32_t memory_start = ESP.getFreeHeap();

  for (int i = 0; i < RUNS_COUNT; i++) {
    // 1. Create keys
    uint32_t start = get_cycles();
    crypto_box_keypair(client_pk, client_sk);
    time_keygen[i] = get_cycles() - start;

    // 2. Compute shared secret
    start = get_cycles();
    int ok = crypto_scalarmult(shared_secret, client_sk, peer_pk);
    time_derive[i] = get_cycles() - start;

    if (ok != 0) Serial.println("  Oops! Key exchange failed.");
  }

  uint32_t memory_end = ESP.getFreeHeap();

  Serial.printf("  Memory Before Test: %u bytes\n", memory_start);
  Serial.printf("  Memory After Test : %u bytes\n", memory_end);
  Serial.printf("  Memory Difference : %d bytes\n", (int)(memory_start - memory_end));
  Serial.println("");

  print_result("Creating Keys           ", get_average(time_keygen, RUNS_COUNT), RUNS_COUNT);
  print_result("Deriving Shared Secret  ", get_average(time_derive, RUNS_COUNT), RUNS_COUNT);
  
  uint32_t total_cycles = get_average(time_keygen, RUNS_COUNT) + get_average(time_derive, RUNS_COUNT);
  print_result("Total Client Crypto Time", total_cycles, RUNS_COUNT);

  Serial.println("");
  Serial.printf("  Public Key Size       : %d bytes\n", crypto_scalarmult_SCALARBYTES);
  Serial.printf("  Shared Secret Size    : %d bytes\n", crypto_scalarmult_BYTES);
}

// ----------------------------------------------------
// Test 2: ECDH P-256
// ----------------------------------------------------
void test_ecdh_p256() {
  Serial.println("\n[2/3] Testing ECDH P-256 (Standard and Secure)");

  uint32_t time_keygen[RUNS_COUNT];
  uint32_t time_derive[RUNS_COUNT];

  // Setup random number generator
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context random_gen;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&random_gen);
  mbedtls_ctr_drbg_seed(&random_gen, mbedtls_entropy_func, &entropy, (const unsigned char *)"ecdh", 4);

  // Make a peer key to use for shared secret calculation
  mbedtls_ecdh_context peer_key;
  mbedtls_ecdh_init(&peer_key);
  mbedtls_ecdh_setup(&peer_key, MBEDTLS_ECP_DP_SECP256R1);
  uint8_t peer_pk[65];
  size_t peer_pk_len = 0;
  mbedtls_ecdh_make_public(&peer_key, &peer_pk_len, peer_pk, sizeof(peer_pk), mbedtls_ctr_drbg_random, &random_gen);

  uint32_t memory_start = ESP.getFreeHeap();
  size_t pubkey_len = 0;
  size_t secret_len = 0;

  for (int i = 0; i < RUNS_COUNT; i++) {
    mbedtls_ecdh_context client_key;
    mbedtls_ecdh_init(&client_key);
    mbedtls_ecdh_setup(&client_key, MBEDTLS_ECP_DP_SECP256R1);

    uint8_t client_pk[65];

    // 1. Create keys
    uint32_t start = get_cycles();
    mbedtls_ecdh_make_public(&client_key, &pubkey_len, client_pk, sizeof(client_pk), mbedtls_ctr_drbg_random, &random_gen);
    time_keygen[i] = get_cycles() - start;

    // 2. Compute shared secret
    mbedtls_ecdh_read_public(&client_key, peer_pk, peer_pk_len);
    uint8_t secret[32];
    start = get_cycles();
    mbedtls_ecdh_calc_secret(&client_key, &secret_len, secret, sizeof(secret), mbedtls_ctr_drbg_random, &random_gen);
    time_derive[i] = get_cycles() - start;

    mbedtls_ecdh_free(&client_key);

    if (i % 25 == 0) vTaskDelay(1);
  }

  uint32_t memory_end = ESP.getFreeHeap();

  Serial.printf("  Memory Before Test: %u bytes\n", memory_start);
  Serial.printf("  Memory After Test : %u bytes\n", memory_end);
  Serial.printf("  Memory Difference : %d bytes\n", (int)(memory_start - memory_end));
  Serial.println("");

  print_result("Creating Keys           ", get_average(time_keygen, RUNS_COUNT), RUNS_COUNT);
  print_result("Deriving Shared Secret  ", get_average(time_derive, RUNS_COUNT), RUNS_COUNT);

  uint32_t total_cycles = get_average(time_keygen, RUNS_COUNT) + get_average(time_derive, RUNS_COUNT);
  print_result("Total Client Crypto Time", total_cycles, RUNS_COUNT);

  Serial.println("");
  Serial.printf("  Public Key Size       : %d bytes (uncompressed)\n", (int)pubkey_len);
  Serial.printf("  Shared Secret Size    : %d bytes\n", (int)secret_len);

  // Clean up
  mbedtls_ecdh_free(&peer_key);
  mbedtls_ctr_drbg_free(&random_gen);
  mbedtls_entropy_free(&entropy);
}

// ----------------------------------------------------
// Test 3: Classical DH-2048
// ----------------------------------------------------
void test_classical_dh2048() {
  Serial.println("\n[3/3] Testing Classical DH-2048 (Heavy and Classic)");

  uint32_t time_keygen[RUNS_COUNT];
  uint32_t time_derive[RUNS_COUNT];

  // Setup random number generator
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context random_gen;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&random_gen);
  mbedtls_ctr_drbg_seed(&random_gen, mbedtls_entropy_func, &entropy, (const unsigned char *)"dh2048", 6);

  // Load standard 2048-bit prime and generator (g = 2)
  const unsigned char p_bin[] = MBEDTLS_DHM_RFC3526_MODP_2048_P_BIN;
  const unsigned char g_bin[] = MBEDTLS_DHM_RFC3526_MODP_2048_G_BIN;

  mbedtls_mpi P, G;
  mbedtls_mpi_init(&P);
  mbedtls_mpi_init(&G);
  mbedtls_mpi_read_binary(&P, p_bin, sizeof(p_bin));
  mbedtls_mpi_read_binary(&G, g_bin, sizeof(g_bin));

  // Make a peer key to use for shared secret calculation
  mbedtls_dhm_context peer_key;
  mbedtls_dhm_init(&peer_key);
  mbedtls_dhm_set_group(&peer_key, &P, &G);
  uint8_t peer_pub[sizeof(p_bin)];
  mbedtls_dhm_make_public(&peer_key, sizeof(p_bin), peer_pub, sizeof(peer_pub), mbedtls_ctr_drbg_random, &random_gen);

  uint32_t memory_start = ESP.getFreeHeap();
  size_t secret_len = 0;

  for (int i = 0; i < RUNS_COUNT; i++) {
    mbedtls_dhm_context client_key;
    mbedtls_dhm_init(&client_key);
    mbedtls_dhm_set_group(&client_key, &P, &G);

    uint8_t client_pub[sizeof(p_bin)];

    // 1. Create keys
    uint32_t start = get_cycles();
    mbedtls_dhm_make_public(&client_key, sizeof(p_bin), client_pub, sizeof(client_pub), mbedtls_ctr_drbg_random, &random_gen);
    time_keygen[i] = get_cycles() - start;

    // 2. Compute shared secret
    mbedtls_dhm_read_public(&client_key, peer_pub, sizeof(peer_pub));
    uint8_t secret[sizeof(p_bin)];
    start = get_cycles();
    mbedtls_dhm_calc_secret(&client_key, secret, sizeof(secret), &secret_len, mbedtls_ctr_drbg_random, &random_gen);
    time_derive[i] = get_cycles() - start;

    mbedtls_dhm_free(&client_key);

    if (i % 10 == 0) vTaskDelay(1);
  }

  uint32_t memory_end = ESP.getFreeHeap();

  Serial.printf("  Memory Before Test: %u bytes\n", memory_start);
  Serial.printf("  Memory After Test : %u bytes\n", memory_end);
  Serial.printf("  Memory Difference : %d bytes\n", (int)(memory_start - memory_end));
  Serial.println("");

  print_result("Creating Keys           ", get_average(time_keygen, RUNS_COUNT), RUNS_COUNT);
  print_result("Deriving Shared Secret  ", get_average(time_derive, RUNS_COUNT), RUNS_COUNT);

  uint32_t total_cycles = get_average(time_keygen, RUNS_COUNT) + get_average(time_derive, RUNS_COUNT);
  print_result("Total Client Crypto Time", total_cycles, RUNS_COUNT);

  Serial.println("");
  Serial.printf("  Public Key Size       : %d bytes\n", (int)sizeof(p_bin));
  Serial.printf("  Shared Secret Size    : %d bytes\n", (int)secret_len);

  // Clean up
  mbedtls_dhm_free(&peer_key);
  mbedtls_mpi_free(&P);
  mbedtls_mpi_free(&G);
  mbedtls_ctr_drbg_free(&random_gen);
  mbedtls_entropy_free(&entropy);
}

// ----------------------------------------------------
// Main Setup
// ----------------------------------------------------
void setup() {
  Serial.begin(115200);
  delay(2000); // Give time for monitor to open

  Serial.println("\nStarting Key Exchange Benchmark");
  Serial.printf("Runs per test: %d runs\n", RUNS_COUNT);
  Serial.printf("Free Heap at Start: %u bytes\n", ESP.getFreeHeap());

  // Setup Libsodium
  if (sodium_init() < 0) {
    Serial.println("Uh oh, couldn't start Libsodium!");
    return;
  }

  // Run the tests one by one
  test_x25519();
  test_ecdh_p256();
  test_classical_dh2048();

  Serial.println("\nBenchmark Finished!");
  Serial.printf("Free Heap at End: %u bytes\n", ESP.getFreeHeap());
  Serial.println("You can now copy these results for your thesis.");
}

void loop() {
  // Nothing to do here, tests only run once at start.
  delay(10000);
}
