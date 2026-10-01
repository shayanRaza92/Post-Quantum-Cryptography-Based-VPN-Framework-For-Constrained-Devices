// ESP32 Benchmark for Digital Signatures
// Tests Ed25519, ECDSA P-256, and RSA-3072

#include <sodium.h>

// Built-in ESP32 cryptography libraries (mbedTLS)
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/error.h"

// Setup how many times to run each test
#define FAST_RUNS      100  // Runs 100 times for fast algorithms
#define SLOW_RSA_RUNS  10   // Runs 10 times for slow RSA key generation
#define FAST_RSA_RUNS  100  // Runs 100 times for RSA sign/verify
#define MSG_SIZE       64   // Dummy message size for testing
#define CPU_SPEED      240  // ESP32 runs at 240 MHz

uint8_t test_message[MSG_SIZE];

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
// Test 1: Ed25519 
// ----------------------------------------------------
void test_ed25519() {
  Serial.println("\n[1/3] Testing Ed25519 (Fast and Modern)");

  uint32_t time_keygen[FAST_RUNS];
  uint32_t time_sign[FAST_RUNS];
  uint32_t time_verify[FAST_RUNS];

  uint8_t public_key[crypto_sign_PUBLICKEYBYTES];
  uint8_t private_key[crypto_sign_SECRETKEYBYTES];
  uint8_t signature[crypto_sign_BYTES];
  unsigned long long sig_length = 0;

  uint32_t memory_start = ESP.getFreeHeap();

  for (int i = 0; i < FAST_RUNS; i++) {
    // 1. Create keys
    uint32_t start = get_cycles();
    crypto_sign_keypair(public_key, private_key);
    time_keygen[i] = get_cycles() - start;

    // 2. Sign the message
    start = get_cycles();
    crypto_sign_detached(signature, &sig_length, test_message, MSG_SIZE, private_key);
    time_sign[i] = get_cycles() - start;

    // 3. Verify the signature
    start = get_cycles();
    int ok = crypto_sign_verify_detached(signature, test_message, MSG_SIZE, public_key);
    time_verify[i] = get_cycles() - start;

    if (ok != 0) Serial.println("  Oops! Verification failed.");
  }

  uint32_t memory_end = ESP.getFreeHeap();

  Serial.printf("  Memory Before Test: %u bytes\n", memory_start);
  Serial.printf("  Memory After Test : %u bytes\n", memory_end);
  Serial.printf("  Memory Difference : %d bytes\n", (int)(memory_start - memory_end));
  Serial.println("");

  print_result("Creating Keys      ", get_average(time_keygen, FAST_RUNS), FAST_RUNS);
  print_result("Signing Message    ", get_average(time_sign, FAST_RUNS), FAST_RUNS);
  print_result("Verifying Signature", get_average(time_verify, FAST_RUNS), FAST_RUNS);
  
  Serial.println("");
  Serial.printf("  Public Key Size   : %d bytes\n", crypto_sign_PUBLICKEYBYTES);
  Serial.printf("  Signature Size    : %d bytes\n", crypto_sign_BYTES);
}

// ----------------------------------------------------
// Test 2: ECDSA P-256
// ----------------------------------------------------
void test_ecdsa_p256() {
  Serial.println("\n[2/3] Testing ECDSA P-256 (Standard and Secure)");

  uint32_t time_keygen[FAST_RUNS];
  uint32_t time_sign[FAST_RUNS];
  uint32_t time_verify[FAST_RUNS];

  // Setup random number generator
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context random_gen;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&random_gen);
  mbedtls_ctr_drbg_seed(&random_gen, mbedtls_entropy_func, &entropy, (const unsigned char *)"ecdsa", 5);

  // Hash our test message
  uint8_t message_hash[32];
  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), test_message, MSG_SIZE, message_hash);

  uint32_t memory_start = ESP.getFreeHeap();

  uint8_t signature[MBEDTLS_ECDSA_MAX_LEN];
  size_t sig_length = 0;

  // Make a main key pair to use for sign/verify
  mbedtls_ecdsa_context main_key;
  mbedtls_ecdsa_init(&main_key);
  mbedtls_ecdsa_genkey(&main_key, MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random, &random_gen);

  for (int i = 0; i < FAST_RUNS; i++) {
    // 1. Create keys
    mbedtls_ecdsa_context temp_key;
    mbedtls_ecdsa_init(&temp_key);
    
    uint32_t start = get_cycles();
    mbedtls_ecdsa_genkey(&temp_key, MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random, &random_gen);
    time_keygen[i] = get_cycles() - start;
    
    mbedtls_ecdsa_free(&temp_key);

    // 2. Sign the message
    sig_length = 0;
    start = get_cycles();
    mbedtls_ecdsa_write_signature(&main_key, MBEDTLS_MD_SHA256, message_hash, 32, signature, sizeof(signature), &sig_length, mbedtls_ctr_drbg_random, &random_gen);
    time_sign[i] = get_cycles() - start;

    // 3. Verify the signature
    start = get_cycles();
    mbedtls_ecdsa_read_signature(&main_key, message_hash, 32, signature, sig_length);
    time_verify[i] = get_cycles() - start;
  }

  uint32_t memory_end = ESP.getFreeHeap();

  Serial.printf("  Memory Before Test: %u bytes\n", memory_start);
  Serial.printf("  Memory After Test : %u bytes\n", memory_end);
  Serial.printf("  Memory Difference : %d bytes\n", (int)(memory_start - memory_end));
  Serial.println("");

  print_result("Creating Keys      ", get_average(time_keygen, FAST_RUNS), FAST_RUNS);
  print_result("Signing Message    ", get_average(time_sign, FAST_RUNS), FAST_RUNS);
  print_result("Verifying Signature", get_average(time_verify, FAST_RUNS), FAST_RUNS);
  
  Serial.println("");
  Serial.printf("  Public Key Size   : 65 bytes (uncompressed)\n");
  Serial.printf("  Signature Size    : %d bytes (DER, last sig)\n", (int)sig_length);

  // Clean up
  mbedtls_ecdsa_free(&main_key);
  mbedtls_ctr_drbg_free(&random_gen);
  mbedtls_entropy_free(&entropy);
}

// ----------------------------------------------------
// Test 3: RSA-3072
// ----------------------------------------------------
void test_rsa_3072() {
  Serial.println("\n[3/3] Testing RSA-3072 (Heavy and Classic)");

  uint32_t time_keygen[SLOW_RSA_RUNS];
  uint32_t time_sign[FAST_RSA_RUNS];
  uint32_t time_verify[FAST_RSA_RUNS];

  // Setup random number generator
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context random_gen;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&random_gen);
  mbedtls_ctr_drbg_seed(&random_gen, mbedtls_entropy_func, &entropy, (const unsigned char *)"rsa", 3);

  // Hash our test message
  uint8_t message_hash[32];
  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), test_message, MSG_SIZE, message_hash);

  uint8_t signature[384];
  size_t sig_length = 0;

  uint32_t memory_start = ESP.getFreeHeap();

  Serial.printf("  Running RSA-3072 keygen (%d iterations, this takes time)...\n", SLOW_RSA_RUNS);

  for (int i = 0; i < SLOW_RSA_RUNS; i++) {
    mbedtls_pk_context temp_key;
    mbedtls_pk_init(&temp_key);
    mbedtls_pk_setup(&temp_key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));

    Serial.printf("    - Keygen iteration %d/%d ... ", i + 1, SLOW_RSA_RUNS);

    uint32_t start = get_cycles();
    int ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(temp_key), mbedtls_ctr_drbg_random, &random_gen, 3072, 65537);
    time_keygen[i] = get_cycles() - start;

    if (ret != 0) {
      Serial.println("FAILED!");
    } else {
      float time_ms = (float)time_keygen[i] / (CPU_SPEED * 1000.0f);
      Serial.printf("OK (%.0f ms)\n", time_ms);
    }

    mbedtls_pk_free(&temp_key);
    
    // Give ESP32 a tiny break so it doesn't crash
    vTaskDelay(1);
  }

  Serial.println("  Generating persistent RSA-3072 key for sign/verify ...");
  
  // Make a main key pair to use for sign/verify
  mbedtls_pk_context main_key;
  mbedtls_pk_init(&main_key);
  mbedtls_pk_setup(&main_key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
  mbedtls_rsa_gen_key(mbedtls_pk_rsa(main_key), mbedtls_ctr_drbg_random, &random_gen, 3072, 65537);

  for (int i = 0; i < FAST_RSA_RUNS; i++) {
    sig_length = 0;
    
    // 2. Sign the message
    uint32_t start = get_cycles();
    mbedtls_pk_sign(&main_key, MBEDTLS_MD_SHA256, message_hash, 32, signature, sizeof(signature), &sig_length, mbedtls_ctr_drbg_random, &random_gen);
    time_sign[i] = get_cycles() - start;

    // Give ESP32 a tiny break occasionally 
    if (i % 10 == 0) vTaskDelay(1);
  }

  for (int i = 0; i < FAST_RSA_RUNS; i++) {
    // 3. Verify the signature
    uint32_t start = get_cycles();
    mbedtls_pk_verify(&main_key, MBEDTLS_MD_SHA256, message_hash, 32, signature, sig_length);
    time_verify[i] = get_cycles() - start;
  }

  uint32_t memory_end = ESP.getFreeHeap();

  Serial.printf("  Memory Before Test: %u bytes\n", memory_start);
  Serial.printf("  Memory After Test : %u bytes\n", memory_end);
  Serial.printf("  Memory Difference : %d bytes\n", (int)(memory_start - memory_end));
  Serial.println("");

  print_result("Creating Keys      ", get_average(time_keygen, SLOW_RSA_RUNS), SLOW_RSA_RUNS);
  print_result("Signing Message    ", get_average(time_sign, FAST_RSA_RUNS), FAST_RSA_RUNS);
  print_result("Verifying Signature", get_average(time_verify, FAST_RSA_RUNS), FAST_RSA_RUNS);
  
  Serial.println("");
  Serial.printf("  Public Key Size   : 384 bytes\n");
  Serial.printf("  Signature Size    : %d bytes\n", (int)sig_length);

  // Clean up
  mbedtls_pk_free(&main_key);
  mbedtls_ctr_drbg_free(&random_gen);
  mbedtls_entropy_free(&entropy);
}

// ----------------------------------------------------
// Main Setup
// ----------------------------------------------------
void setup() {
  Serial.begin(115200);
  delay(2000); // Give time for monitor to open

  Serial.println("\nStarting Digital Signatures Benchmark");
  Serial.printf("Fast tests: %d runs | Slow tests: %d runs\n", FAST_RUNS, SLOW_RSA_RUNS);
  Serial.printf("Free Heap at Start: %u bytes\n", ESP.getFreeHeap());
  
  // Setup Libsodium
  if (sodium_init() < 0) {
    Serial.println("Uh oh, couldn't start Libsodium!");
    return;
  }

  // Create some fake data for testing
  randombytes_buf(test_message, MSG_SIZE);

  // Run the tests one by one
  test_ed25519();
  test_ecdsa_p256();
  test_rsa_3072();

  Serial.println("\nBenchmark Finished!");
  Serial.printf("Free Heap at End: %u bytes\n", ESP.getFreeHeap());
  Serial.println("You can now copy these results for your thesis.");
}

void loop() {
  // Nothing to do here, tests only run once at start.
  delay(10000);
}
