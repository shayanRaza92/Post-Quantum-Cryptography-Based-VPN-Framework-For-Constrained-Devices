// ESP32 Micro-Benchmark for Digital Signatures (Phase A: Isolated)
// Evaluates Ed25519, ECDSA P-256, and RSA-3072

#include <sodium.h>

#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/error.h"

#define FAST_RUNS      100
#define SLOW_RSA_RUNS  10
#define FAST_RSA_RUNS  100
#define MSG_SIZE       64
#define CPU_SPEED      240

uint8_t test_message[MSG_SIZE];

struct SignatureKPI {
  uint32_t keygen_cycles;
  uint32_t sign_cycles;
  uint32_t verify_cycles;
  uint32_t total_cycles;
  float keygen_ms;
  float sign_ms;
  float verify_ms;
  float total_ms;
  uint32_t pubkey_bytes;
  uint32_t sig_bytes;
  uint32_t peak_heap_bytes;
};

SignatureKPI kpi_ed25519;
SignatureKPI kpi_p256;
SignatureKPI kpi_rsa;

static inline uint32_t get_cycles() {
  uint32_t cycles;
  __asm__ __volatile__("rsr %0, ccount" : "=a"(cycles));
  return cycles;
}

uint32_t get_average(uint32_t* times, int count) {
  uint64_t sum = 0;
  for (int i = 0; i < count; i++) {
    sum += times[i];
  }
  return (uint32_t)(sum / count);
}

// ----------------------------------------------------
// [1/3] Ed25519 (Twisted Edwards Curve25519)
// ----------------------------------------------------
void test_ed25519() {
  Serial.println("\n[1/3] Ed25519 (Curve25519)");

  uint32_t time_keygen[FAST_RUNS];
  uint32_t time_sign[FAST_RUNS];
  uint32_t time_verify[FAST_RUNS];

  uint8_t public_key[crypto_sign_PUBLICKEYBYTES];
  uint8_t private_key[crypto_sign_SECRETKEYBYTES];
  uint8_t signature[crypto_sign_BYTES];
  unsigned long long sig_length = 0;

  uint32_t heap_before = ESP.getFreeHeap();
  uint32_t peak_heap = 0;

  for (int i = 0; i < FAST_RUNS; i++) {
    // 1. Key Generation (SIG-1)
    uint32_t start = get_cycles();
    crypto_sign_keypair(public_key, private_key);
    time_keygen[i] = get_cycles() - start;

    // Peak Heap Profiling (SIG-7)
    uint32_t used = heap_before - ESP.getFreeHeap();
    if (used > peak_heap) peak_heap = used;

    // 2. Message Signing (SIG-3)
    start = get_cycles();
    crypto_sign_detached(signature, &sig_length, test_message, MSG_SIZE, private_key);
    time_sign[i] = get_cycles() - start;

    // 3. Signature Verification (SIG-5)
    start = get_cycles();
    crypto_sign_verify_detached(signature, test_message, MSG_SIZE, public_key);
    time_verify[i] = get_cycles() - start;
  }

  kpi_ed25519.keygen_cycles = get_average(time_keygen, FAST_RUNS);
  kpi_ed25519.sign_cycles = get_average(time_sign, FAST_RUNS);
  kpi_ed25519.verify_cycles = get_average(time_verify, FAST_RUNS);
  kpi_ed25519.total_cycles = kpi_ed25519.keygen_cycles + kpi_ed25519.sign_cycles;

  kpi_ed25519.keygen_ms = (float)kpi_ed25519.keygen_cycles / (CPU_SPEED * 1000.0f);
  kpi_ed25519.sign_ms = (float)kpi_ed25519.sign_cycles / (CPU_SPEED * 1000.0f);
  kpi_ed25519.verify_ms = (float)kpi_ed25519.verify_cycles / (CPU_SPEED * 1000.0f);
  kpi_ed25519.total_ms = kpi_ed25519.keygen_ms + kpi_ed25519.sign_ms;

  kpi_ed25519.pubkey_bytes = crypto_sign_PUBLICKEYBYTES;
  kpi_ed25519.sig_bytes = crypto_sign_BYTES;
  kpi_ed25519.peak_heap_bytes = peak_heap;

  Serial.printf("  SIG-1 Key Generation Latency   : %9u cycles | %7.2f ms\n", kpi_ed25519.keygen_cycles, kpi_ed25519.keygen_ms);
  Serial.printf("  SIG-2 Public Key Wire Size     : %u bytes\n", kpi_ed25519.pubkey_bytes);
  Serial.printf("  SIG-3 Message Signing Latency  : %9u cycles | %7.2f ms\n", kpi_ed25519.sign_cycles, kpi_ed25519.sign_ms);
  Serial.printf("  SIG-4 Signature Wire Size      : %u bytes\n", kpi_ed25519.sig_bytes);
  Serial.printf("  SIG-5 Verification Latency     : %9u cycles | %7.2f ms\n", kpi_ed25519.verify_cycles, kpi_ed25519.verify_ms);
  Serial.printf("  SIG-6 Total Client Sign Time   : %9u cycles | %7.2f ms\n", kpi_ed25519.total_cycles, kpi_ed25519.total_ms);
  Serial.printf("  SIG-7 Peak Dynamic Heap Memory : %u bytes\n", kpi_ed25519.peak_heap_bytes);
}

// ----------------------------------------------------
// [2/3] ECDSA P-256 (NIST prime curve secp256r1)
// ----------------------------------------------------
void test_ecdsa_p256() {
  Serial.println("\n[2/3] ECDSA P-256 (secp256r1)");

  uint32_t time_keygen[FAST_RUNS];
  uint32_t time_sign[FAST_RUNS];
  uint32_t time_verify[FAST_RUNS];

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context random_gen;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&random_gen);
  mbedtls_ctr_drbg_seed(&random_gen, mbedtls_entropy_func, &entropy, (const unsigned char *)"ecdsa", 5);

  uint8_t message_hash[32];
  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), test_message, MSG_SIZE, message_hash);

  uint8_t signature[MBEDTLS_ECDSA_MAX_LEN];
  size_t sig_length = 0;

  mbedtls_ecdsa_context main_key;
  mbedtls_ecdsa_init(&main_key);
  mbedtls_ecdsa_genkey(&main_key, MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random, &random_gen);

  uint32_t heap_before = ESP.getFreeHeap();
  uint32_t peak_heap = 0;

  for (int i = 0; i < FAST_RUNS; i++) {
    // 1. Key Generation (SIG-1)
    mbedtls_ecdsa_context temp_key;
    mbedtls_ecdsa_init(&temp_key);
    
    uint32_t start = get_cycles();
    mbedtls_ecdsa_genkey(&temp_key, MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random, &random_gen);
    time_keygen[i] = get_cycles() - start;

    // Peak Heap Profiling (SIG-7)
    uint32_t used = heap_before - ESP.getFreeHeap();
    if (used > peak_heap) peak_heap = used;
    mbedtls_ecdsa_free(&temp_key);

    // 2. Message Signing (SIG-3)
    sig_length = 0;
    start = get_cycles();
    mbedtls_ecdsa_write_signature(&main_key, MBEDTLS_MD_SHA256, message_hash, 32, signature, sizeof(signature), &sig_length, mbedtls_ctr_drbg_random, &random_gen);
    time_sign[i] = get_cycles() - start;

    // 3. Signature Verification (SIG-5)
    start = get_cycles();
    mbedtls_ecdsa_read_signature(&main_key, message_hash, 32, signature, sig_length);
    time_verify[i] = get_cycles() - start;
  }

  mbedtls_ecdsa_free(&main_key);
  mbedtls_ctr_drbg_free(&random_gen);
  mbedtls_entropy_free(&entropy);

  kpi_p256.keygen_cycles = get_average(time_keygen, FAST_RUNS);
  kpi_p256.sign_cycles = get_average(time_sign, FAST_RUNS);
  kpi_p256.verify_cycles = get_average(time_verify, FAST_RUNS);
  kpi_p256.total_cycles = kpi_p256.keygen_cycles + kpi_p256.sign_cycles;

  kpi_p256.keygen_ms = (float)kpi_p256.keygen_cycles / (CPU_SPEED * 1000.0f);
  kpi_p256.sign_ms = (float)kpi_p256.sign_cycles / (CPU_SPEED * 1000.0f);
  kpi_p256.verify_ms = (float)kpi_p256.verify_cycles / (CPU_SPEED * 1000.0f);
  kpi_p256.total_ms = kpi_p256.keygen_ms + kpi_p256.sign_ms;

  kpi_p256.pubkey_bytes = 65;
  kpi_p256.sig_bytes = (uint32_t)sig_length;
  kpi_p256.peak_heap_bytes = peak_heap;

  Serial.printf("  SIG-1 Key Generation Latency   : %9u cycles | %7.2f ms\n", kpi_p256.keygen_cycles, kpi_p256.keygen_ms);
  Serial.printf("  SIG-2 Public Key Wire Size     : %u bytes\n", kpi_p256.pubkey_bytes);
  Serial.printf("  SIG-3 Message Signing Latency  : %9u cycles | %7.2f ms\n", kpi_p256.sign_cycles, kpi_p256.sign_ms);
  Serial.printf("  SIG-4 Signature Wire Size      : %u bytes\n", kpi_p256.sig_bytes);
  Serial.printf("  SIG-5 Verification Latency     : %9u cycles | %7.2f ms\n", kpi_p256.verify_cycles, kpi_p256.verify_ms);
  Serial.printf("  SIG-6 Total Client Sign Time   : %9u cycles | %7.2f ms\n", kpi_p256.total_cycles, kpi_p256.total_ms);
  Serial.printf("  SIG-7 Peak Dynamic Heap Memory : %u bytes\n", kpi_p256.peak_heap_bytes);
}

// ----------------------------------------------------
// [3/3] Classical RSA-3072 (PKCS#1 v1.5)
// ----------------------------------------------------
void test_rsa_3072() {
  Serial.println("\n[3/3] Classical RSA-3072 (PKCS#1 v1.5)");

  uint32_t time_keygen[SLOW_RSA_RUNS];
  uint32_t time_sign[FAST_RSA_RUNS];
  uint32_t time_verify[FAST_RSA_RUNS];

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context random_gen;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&random_gen);
  mbedtls_ctr_drbg_seed(&random_gen, mbedtls_entropy_func, &entropy, (const unsigned char *)"rsa", 3);

  uint8_t message_hash[32];
  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), test_message, MSG_SIZE, message_hash);

  uint8_t signature[384];
  size_t sig_length = 0;

  uint32_t heap_before = ESP.getFreeHeap();
  uint32_t peak_heap = 0;

  for (int i = 0; i < SLOW_RSA_RUNS; i++) {
    mbedtls_pk_context temp_key;
    mbedtls_pk_init(&temp_key);
    mbedtls_pk_setup(&temp_key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));

    uint32_t start = get_cycles();
    mbedtls_rsa_gen_key(mbedtls_pk_rsa(temp_key), mbedtls_ctr_drbg_random, &random_gen, 3072, 65537);
    time_keygen[i] = get_cycles() - start;

    // Peak Heap Profiling (SIG-7)
    uint32_t used = heap_before - ESP.getFreeHeap();
    if (used > peak_heap) peak_heap = used;

    mbedtls_pk_free(&temp_key);
    vTaskDelay(1);
  }

  mbedtls_pk_context main_key;
  mbedtls_pk_init(&main_key);
  mbedtls_pk_setup(&main_key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
  mbedtls_rsa_gen_key(mbedtls_pk_rsa(main_key), mbedtls_ctr_drbg_random, &random_gen, 3072, 65537);

  for (int i = 0; i < FAST_RSA_RUNS; i++) {
    sig_length = 0;
    uint32_t start = get_cycles();
    mbedtls_pk_sign(&main_key, MBEDTLS_MD_SHA256, message_hash, 32, signature, sizeof(signature), &sig_length, mbedtls_ctr_drbg_random, &random_gen);
    time_sign[i] = get_cycles() - start;

    if (i % 10 == 0) vTaskDelay(1);
  }

  for (int i = 0; i < FAST_RSA_RUNS; i++) {
    uint32_t start = get_cycles();
    mbedtls_pk_verify(&main_key, MBEDTLS_MD_SHA256, message_hash, 32, signature, sig_length);
    time_verify[i] = get_cycles() - start;
  }

  mbedtls_pk_free(&main_key);
  mbedtls_ctr_drbg_free(&random_gen);
  mbedtls_entropy_free(&entropy);

  kpi_rsa.keygen_cycles = get_average(time_keygen, SLOW_RSA_RUNS);
  kpi_rsa.sign_cycles = get_average(time_sign, FAST_RSA_RUNS);
  kpi_rsa.verify_cycles = get_average(time_verify, FAST_RSA_RUNS);
  kpi_rsa.total_cycles = kpi_rsa.keygen_cycles + kpi_rsa.sign_cycles;

  kpi_rsa.keygen_ms = (float)kpi_rsa.keygen_cycles / (CPU_SPEED * 1000.0f);
  kpi_rsa.sign_ms = (float)kpi_rsa.sign_cycles / (CPU_SPEED * 1000.0f);
  kpi_rsa.verify_ms = (float)kpi_rsa.verify_cycles / (CPU_SPEED * 1000.0f);
  kpi_rsa.total_ms = kpi_rsa.keygen_ms + kpi_rsa.sign_ms;

  kpi_rsa.pubkey_bytes = 384;
  kpi_rsa.sig_bytes = 384;
  kpi_rsa.peak_heap_bytes = peak_heap;

  Serial.printf("  SIG-1 Key Generation Latency   : %9u cycles | %7.2f ms\n", kpi_rsa.keygen_cycles, kpi_rsa.keygen_ms);
  Serial.printf("  SIG-2 Public Key Wire Size     : %u bytes\n", kpi_rsa.pubkey_bytes);
  Serial.printf("  SIG-3 Message Signing Latency  : %9u cycles | %7.2f ms\n", kpi_rsa.sign_cycles, kpi_rsa.sign_ms);
  Serial.printf("  SIG-4 Signature Wire Size      : %u bytes\n", kpi_rsa.sig_bytes);
  Serial.printf("  SIG-5 Verification Latency     : %9u cycles | %7.2f ms\n", kpi_rsa.verify_cycles, kpi_rsa.verify_ms);
  Serial.printf("  SIG-6 Total Client Sign Time   : %9u cycles | %7.2f ms\n", kpi_rsa.total_cycles, kpi_rsa.total_ms);
  Serial.printf("  SIG-7 Peak Dynamic Heap Memory : %u bytes\n", kpi_rsa.peak_heap_bytes);
}

void print_comparison_table() {
  Serial.println("\n========================================================================");
  Serial.println("                     BENCHMARK RESULTS SUMMARY                          ");
  Serial.println("========================================================================");
  Serial.printf("%-6s | %-28s | %-10s | %-10s | %-10s\n", "KPI ID", "Metric", "Ed25519", "ECDSA P-256", "RSA-3072");
  Serial.println("-------+------------------------------+------------+------------+-----------");
  Serial.printf("%-6s | %-28s | %7.2f ms | %7.2f ms | %7.2f ms\n", "SIG-1", "Key Generation Time", kpi_ed25519.keygen_ms, kpi_p256.keygen_ms, kpi_rsa.keygen_ms);
  Serial.printf("%-6s | %-28s | %8u B | %8u B | %8u B\n", "SIG-2", "Public Key Wire Size", kpi_ed25519.pubkey_bytes, kpi_p256.pubkey_bytes, kpi_rsa.pubkey_bytes);
  Serial.printf("%-6s | %-28s | %7.2f ms | %7.2f ms | %7.2f ms\n", "SIG-3", "Message Signing Time", kpi_ed25519.sign_ms, kpi_p256.sign_ms, kpi_rsa.sign_ms);
  Serial.printf("%-6s | %-28s | %8u B | %8u B | %8u B\n", "SIG-4", "Signature Wire Size", kpi_ed25519.sig_bytes, kpi_p256.sig_bytes, kpi_rsa.sig_bytes);
  Serial.printf("%-6s | %-28s | %7.2f ms | %7.2f ms | %7.2f ms\n", "SIG-5", "Verification Time", kpi_ed25519.verify_ms, kpi_p256.verify_ms, kpi_rsa.verify_ms);
  Serial.printf("%-6s | %-28s | %7.2f ms | %7.2f ms | %7.2f ms\n", "SIG-6", "Total Client Sign Time", kpi_ed25519.total_ms, kpi_p256.total_ms, kpi_rsa.total_ms);
  Serial.printf("%-6s | %-28s | %8u B | %8u B | %8u B\n", "SIG-7", "Peak Dynamic Heap RAM", kpi_ed25519.peak_heap_bytes, kpi_p256.peak_heap_bytes, kpi_rsa.peak_heap_bytes);
  Serial.println("========================================================================\n");
}

void setup() {
  Serial.begin(115200);
  delay(2000);

  Serial.println("\n========================================================================");
  Serial.println("ESP32 Digital Signature Micro-Benchmark (Phase A: Isolated)");
  Serial.printf("Fast Runs: %d | RSA KeyGen Runs: %d | CPU: %d MHz | Heap: %u bytes\n", FAST_RUNS, SLOW_RSA_RUNS, CPU_SPEED, ESP.getFreeHeap());
  Serial.println("========================================================================");

  if (sodium_init() < 0) {
    Serial.println("Error: sodium_init() failed");
    return;
  }

  randombytes_buf(test_message, MSG_SIZE);

  test_ed25519();
  test_ecdsa_p256();
  test_rsa_3072();

  print_comparison_table();
}

void loop() {
  delay(10000);
}
