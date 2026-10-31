// Combined ESP32 <-> Gateway (Laptop) Key Exchange Benchmark
// Evaluates X25519, ECDH P-256, and DH-3072 (RFC 7919 ffdhe3072) at ~128-bit security.
//
// Unified Single-Phase Methodology:
// 1. Pure Key Exchange Only (No Signatures / Transcript Binding):
//      MSG 1 (ESP32 -> Laptop): [AlgID (1B) | pk_C (32B / 65B / 384B)]
//      MSG 2 (Laptop -> ESP32): [pk_S (32B / 65B / 384B) | SrvKeyGen_us (4B) | SrvDerive_us (4B) | ConfirmTag (16B)]
// 2. Hardware Cycle Counter (ccount @ 240 MHz) times ESP32 KeyGen and ESP32 Derive.
//    Derivation timing includes parsing and validating the Laptop's public key share.
// 3. Laptop times its own KeyGen and Derive in microseconds and returns them in MSG 2,
//    allowing the ESP32 to report ESP32 Crypto, Gateway Crypto, Combined Crypto, and
//    End-to-End Wi-Fi KEX Latency in a single unified table.
// 4. Proper Key Separation for Verification (Outside Timed Region):
//    Both sides derive K_confirm = HMAC-SHA256("VPN-v1-KEX-SALT", SS) and verify
//    ConfirmTag = HMAC-SHA256(K_confirm, "VPN-v1|KEX-CONFIRM|" || pk_C || pk_S)[0:16].
//    The raw shared secret SS (or a direct hash of SS) is never sent over the wire.
// 5. Dedicated On-Chip Memory Pass measures Peak Heap (instrumented mbedTLS allocator)
//    and Peak Crypto Stack Usage (isolated FreeRTOS tasks) before Wi-Fi starts.

#include <WiFi.h>
#include <sodium.h>

#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/dhm.h"
#include "mbedtls/bignum.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"
#include "mbedtls/md.h"
#include <esp_heap_caps.h>
#include <esp_timer.h>
#include <math.h>

// --- Wi-Fi & Laptop Gateway Configuration ---
const char* WIFI_SSID     = "Redmi 13C";
const char* WIFI_PASSWORD = "92144444";
const char* LAPTOP_IP     = "10.180.139.216"; // IP printed by python3 benchmark_gateway_kex.py
const uint16_t PORT       = 9000;

// --- Benchmark Iteration Counts ---
#define FAST_RUNS        50    // X25519 and ECDH P-256 live exchanges
#define DH_RUNS          20    // DH-3072 live exchanges
#define CPU_SPEED        240
#define BENCH_STACK_SIZE 16384

// Algorithm IDs
#define ALG_X25519       0x01
#define ALG_ECDH_P256    0x02
#define ALG_DH3072       0x03
#define ALG_DONE         0xFF

// RFC 7919 ffdhe3072 prime p (generator g = 2). Safe prime: p = 2q + 1.
static const uint8_t FFDHE3072_P[384] = {
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xAD,0xF8,0x54,0x58,0xA2,0xBB,0x4A,0x9A,
  0xAF,0xDC,0x56,0x20,0x27,0x3D,0x3C,0xF1,0xD8,0xB9,0xC5,0x83,0xCE,0x2D,0x36,0x95,
  0xA9,0xE1,0x36,0x41,0x14,0x64,0x33,0xFB,0xCC,0x93,0x9D,0xCE,0x24,0x9B,0x3E,0xF9,
  0x7D,0x2F,0xE3,0x63,0x63,0x0C,0x75,0xD8,0xF6,0x81,0xB2,0x02,0xAE,0xC4,0x61,0x7A,
  0xD3,0xDF,0x1E,0xD5,0xD5,0xFD,0x65,0x61,0x24,0x33,0xF5,0x1F,0x5F,0x06,0x6E,0xD0,
  0x85,0x63,0x65,0x55,0x3D,0xED,0x1A,0xF3,0xB5,0x57,0x13,0x5E,0x7F,0x57,0xC9,0x35,
  0x98,0x4F,0x0C,0x70,0xE0,0xE6,0x8B,0x77,0xE2,0xA6,0x89,0xDA,0xF3,0xEF,0xE8,0x72,
  0x1D,0xF1,0x58,0xA1,0x36,0xAD,0xE7,0x35,0x30,0xAC,0xCA,0x4F,0x48,0x3A,0x79,0x7A,
  0xBC,0x0A,0xB1,0x82,0xB3,0x24,0xFB,0x61,0xD1,0x08,0xA9,0x4B,0xB2,0xC8,0xE3,0xFB,
  0xB9,0x6A,0xDA,0xB7,0x60,0xD7,0xF4,0x68,0x1D,0x4F,0x42,0xA3,0xDE,0x39,0x4D,0xF4,
  0xAE,0x56,0xED,0xE7,0x63,0x72,0xBB,0x19,0x0B,0x07,0xA7,0xC8,0xEE,0x0A,0x6D,0x70,
  0x9E,0x02,0xFC,0xE1,0xCD,0xF7,0xE2,0xEC,0xC0,0x34,0x04,0xCD,0x28,0x34,0x2F,0x61,
  0x91,0x72,0xFE,0x9C,0xE9,0x85,0x83,0xFF,0x8E,0x4F,0x12,0x32,0xEE,0xF2,0x81,0x83,
  0xC3,0xFE,0x3B,0x1B,0x4C,0x6F,0xAD,0x73,0x3B,0xB5,0xFC,0xBC,0x2E,0xC2,0x20,0x05,
  0xC5,0x8E,0xF1,0x83,0x7D,0x16,0x83,0xB2,0xC6,0xF3,0x4A,0x26,0xC1,0xB2,0xEF,0xFA,
  0x88,0x6B,0x42,0x38,0x61,0x1F,0xCF,0xDC,0xDE,0x35,0x5B,0x3B,0x65,0x19,0x03,0x5B,
  0xBC,0x34,0xF4,0xDE,0xF9,0x9C,0x02,0x38,0x61,0xB4,0x6F,0xC9,0xD6,0xE6,0xC9,0x07,
  0x7A,0xD9,0x1D,0x26,0x91,0xF7,0xF7,0xEE,0x59,0x8C,0xB0,0xFA,0xC1,0x86,0xD9,0x1C,
  0xAE,0xFE,0x13,0x09,0x85,0x13,0x92,0x70,0xB4,0x13,0x0C,0x93,0xBC,0x43,0x79,0x44,
  0xF4,0xFD,0x44,0x52,0xE2,0xD7,0x4D,0xD3,0x64,0xF2,0xE2,0x1E,0x71,0xF5,0x4B,0xFF,
  0x5C,0xAE,0x82,0xAB,0x9C,0x9D,0xF6,0x9E,0xE8,0x6D,0x2B,0xC5,0x22,0x36,0x3A,0x0D,
  0xAB,0xC5,0x21,0x97,0x9B,0x0D,0xEA,0xDA,0x1D,0xBF,0x9A,0x42,0xD5,0xC4,0x48,0x4E,
  0x0A,0xBC,0xD0,0x6B,0xFA,0x53,0xDD,0xEF,0x3C,0x1B,0x20,0xEE,0x3F,0xD5,0x9D,0x7C,
  0x25,0xE4,0x1D,0x2B,0x66,0xC6,0x2E,0x37,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};

WiFiClient client;

struct StatResult {
  uint64_t mean_cycles, median_cycles, min_cycles, max_cycles;
  float mean_ms, median_ms, min_ms, max_ms, stddev_ms;
};

struct KexKPI {
  StatResult keygen;            // KEX-1: ESP32 KeyGen
  uint32_t   share_bytes;       // KEX-2: Public key share on the wire
  StatResult derive;            // KEX-3: ESP32 Secret Derivation
  uint32_t   secret_bytes;      // KEX-4: Raw shared secret length
  float      esp_crypto_ms;     // KEX-5: ESP32 KeyGen + ESP32 Derive
  float      srv_keygen_ms;     // KEX-6: Gateway (Laptop) KeyGen mean
  float      srv_derive_ms;     // KEX-7: Gateway (Laptop) Derive mean
  float      srv_crypto_ms;     // KEX-8: Gateway KeyGen + Derive
  float      combined_crypto_ms;// KEX-9: ESP32 Crypto + Gateway Crypto
  float      e2e_network_ms;    // KEX-10: End-to-End Wi-Fi KEX Handshake Time
  uint32_t   peak_heap;         // KEX-11: Peak dynamic heap on ESP32
  uint32_t   peak_stack;        // KEX-12: Peak crypto stack usage on ESP32
  uint32_t   failures;          // KEX-13: Key confirmation / crypto failures
};

KexKPI kpi_x25519;
KexKPI kpi_p256;
KexKPI kpi_dh3072;

struct DhGroup {
  mbedtls_mpi P;
  mbedtls_mpi G;
  mbedtls_mpi Q;
  mbedtls_mpi Pm2;
  mbedtls_mpi RR;
};

struct DhKey {
  mbedtls_mpi x;
};

// ----------------------------------------------------
// Cycle Counter & Statistical Helpers
// ----------------------------------------------------
static inline uint32_t get_cycles() {
  uint32_t cycles;
  __asm__ __volatile__("rsr %0, ccount" : "=a"(cycles));
  return cycles;
}

static void sort_u64(uint64_t* arr, int n) {
  for (int i = 0; i < n - 1; i++)
    for (int j = 0; j < n - i - 1; j++)
      if (arr[j] > arr[j + 1]) { uint64_t t = arr[j]; arr[j] = arr[j + 1]; arr[j + 1] = t; }
}

StatResult calculate_stats(uint64_t* raw, int count) {
  StatResult s;
  memset(&s, 0, sizeof(s));
  if (count <= 0) return s;

  uint64_t sum = 0;
  for (int i = 0; i < count; i++) sum += raw[i];
  s.mean_cycles = sum / count;
  s.mean_ms = (float)s.mean_cycles / (CPU_SPEED * 1000.0f);

  if (count > 1) {
    double acc = 0.0;
    for (int i = 0; i < count; i++) {
      double d = (double)raw[i] / (CPU_SPEED * 1000.0) - s.mean_ms;
      acc += d * d;
    }
    s.stddev_ms = (float)sqrt(acc / (count - 1));
  }

  sort_u64(raw, count);
  s.min_cycles = raw[0];
  s.max_cycles = raw[count - 1];
  s.median_cycles = (count % 2 == 0) ? (raw[count / 2 - 1] + raw[count / 2]) / 2 : raw[count / 2];
  s.min_ms    = (float)s.min_cycles    / (CPU_SPEED * 1000.0f);
  s.max_ms    = (float)s.max_cycles    / (CPU_SPEED * 1000.0f);
  s.median_ms = (float)s.median_cycles / (CPU_SPEED * 1000.0f);
  return s;
}

static uint32_t measure_stack_used() {
  UBaseType_t hwm = uxTaskGetStackHighWaterMark(NULL);
  return (uint32_t)(BENCH_STACK_SIZE - (hwm * sizeof(StackType_t)));
}

// ----------------------------------------------------
// mbedTLS Heap Instrumentation (Memory Pass Only)
// ----------------------------------------------------
static size_t g_heap_current = 0;
static size_t g_heap_peak = 0;
#define MEM_MAGIC 0x4B455831
struct MemHeader { uint32_t magic; uint32_t size; };

static void* counting_calloc(size_t n, size_t size) {
  size_t total = n * size;
  MemHeader* h = (MemHeader*)malloc(total + sizeof(MemHeader));
  if (!h) return NULL;
  h->magic = MEM_MAGIC;
  h->size = (uint32_t)total;
  g_heap_current += total;
  if (g_heap_current > g_heap_peak) g_heap_peak = g_heap_current;
  void* payload = (void*)(h + 1);
  memset(payload, 0, total);
  return payload;
}

static void counting_free(void* ptr) {
  if (!ptr) return;
  MemHeader* h = ((MemHeader*)ptr) - 1;
  if (h->magic == MEM_MAGIC) {
    if (g_heap_current >= h->size) g_heap_current -= h->size;
    h->magic = 0;
    free(h);
  } else {
    free(ptr);
  }
}

static void heap_tracking_on()  { g_heap_current = 0; g_heap_peak = 0; mbedtls_platform_set_calloc_free(counting_calloc, counting_free); }
static void heap_tracking_off() { mbedtls_platform_set_calloc_free(calloc, free); g_heap_current = 0; g_heap_peak = 0; }

// ----------------------------------------------------
// HKDF Key Separation & Confirmation Tag (Untimed)
// Matches Python compute_kex_confirm_tag() byte-for-byte
// ----------------------------------------------------
static void compute_kex_confirm_tag(const uint8_t* ss, size_t ss_len,
                                    const uint8_t* cli_pk, const uint8_t* srv_pk,
                                    size_t pk_len, uint8_t out_tag16[16]) {
  const char* salt  = "VPN-v1-KEX-SALT";
  const char* label = "VPN-v1|KEX-CONFIRM|";
  const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  // 1. K_confirm = HMAC-SHA256("VPN-v1-KEX-SALT", shared_secret)
  uint8_t k_confirm[32];
  mbedtls_md_hmac(md_info, (const unsigned char*)salt, strlen(salt), ss, ss_len, k_confirm);

  // 2. Tag = HMAC-SHA256(K_confirm, "VPN-v1|KEX-CONFIRM|" || cli_pk || srv_pk)[0..15]
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, md_info, 1);
  mbedtls_md_hmac_starts(&ctx, k_confirm, 32);
  mbedtls_md_hmac_update(&ctx, (const unsigned char*)label, strlen(label));
  mbedtls_md_hmac_update(&ctx, cli_pk, pk_len);
  mbedtls_md_hmac_update(&ctx, srv_pk, pk_len);
  uint8_t full_tag[32];
  mbedtls_md_hmac_finish(&ctx, full_tag);
  mbedtls_md_free(&ctx);

  memcpy(out_tag16, full_tag, 16);
  sodium_memzero(k_confirm, sizeof(k_confirm));
}

// ----------------------------------------------------
// Network Framing Helpers (Single-Write Zero-Nagle)
// ----------------------------------------------------
bool read_exact(uint8_t* buf, size_t len, unsigned long timeout_ms = 15000) {
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
  return (bytes_read == len);
}

int recv_msg(uint8_t* buf, size_t max_len, unsigned long timeout_ms = 15000) {
  uint8_t header[2];
  if (!read_exact(header, 2, timeout_ms)) return -1;
  uint16_t len = ((uint16_t)header[0] << 8) | header[1];
  if (len > max_len) return -1;
  if (!read_exact(buf, len, timeout_ms)) return -1;
  return (int)len;
}

void send_msg(const uint8_t* data, uint16_t len) {
  static uint8_t packet[2 + 512];
  packet[0] = (len >> 8) & 0xFF;
  packet[1] = len & 0xFF;
  if (len > 0 && data != NULL) {
    memcpy(packet + 2, data, len);
  }
  client.write(packet, 2 + len);
  client.flush();
}

static uint32_t read_u32_be(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

// ----------------------------------------------------
// RFC 7748 Section 6.1 Known Answer Test (X25519)
// ----------------------------------------------------
static bool run_x25519_kat() {
  const uint8_t a[32]  = {0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
                          0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a};
  const uint8_t A[32]  = {0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54,0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a,
                          0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4,0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a};
  const uint8_t b[32]  = {0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
                          0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,0x1c,0x2f,0x8b,0x27,0xff,0x88,0xe0,0xeb};
  const uint8_t B[32]  = {0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4,0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37,
                          0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d,0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f};
  const uint8_t K[32]  = {0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1,0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25,
                          0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33,0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42};
  uint8_t out[32];
  if (crypto_scalarmult_base(out, a) != 0 || memcmp(out, A, 32) != 0) return false;
  if (crypto_scalarmult_base(out, b) != 0 || memcmp(out, B, 32) != 0) return false;
  if (crypto_scalarmult(out, a, B) != 0 || memcmp(out, K, 32) != 0) return false;
  if (crypto_scalarmult(out, b, A) != 0 || memcmp(out, K, 32) != 0) return false;
  return true;
}

// ----------------------------------------------------
// Cryptographic Primitives (ECDH P-256 & DH-3072)
// ----------------------------------------------------
static int p256_keygen(mbedtls_ecp_group* grp, mbedtls_mpi* d, uint8_t* share_out,
                       mbedtls_ctr_drbg_context* rng) {
  mbedtls_ecp_point Q;
  mbedtls_ecp_point_init(&Q);
  size_t olen = 0;
  int rc = mbedtls_ecdh_gen_public(grp, d, &Q, mbedtls_ctr_drbg_random, rng);
  if (rc == 0) rc = mbedtls_ecp_point_write_binary(grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, share_out, 65);
  if (rc == 0 && olen != 65) rc = -1;
  mbedtls_ecp_point_free(&Q);
  return rc;
}

static int p256_derive(mbedtls_ecp_group* grp, const mbedtls_mpi* d, const uint8_t* peer_share,
                       uint8_t* secret_out, mbedtls_ctr_drbg_context* rng) {
  mbedtls_ecp_point Qp;
  mbedtls_mpi z;
  mbedtls_ecp_point_init(&Qp);
  mbedtls_mpi_init(&z);
  int rc = mbedtls_ecp_point_read_binary(grp, &Qp, peer_share, 65);
  if (rc == 0) rc = mbedtls_ecp_check_pubkey(grp, &Qp);
  if (rc == 0) rc = mbedtls_ecdh_compute_shared(grp, &z, &Qp, d, mbedtls_ctr_drbg_random, rng);
  if (rc == 0) rc = mbedtls_mpi_write_binary(&z, secret_out, 32);
  mbedtls_mpi_free(&z);
  mbedtls_ecp_point_free(&Qp);
  return rc;
}

static int dh_group_init(DhGroup* g) {
  mbedtls_mpi_init(&g->P); mbedtls_mpi_init(&g->G); mbedtls_mpi_init(&g->Q);
  mbedtls_mpi_init(&g->Pm2); mbedtls_mpi_init(&g->RR);
  int rc = mbedtls_mpi_read_binary(&g->P, FFDHE3072_P, sizeof(FFDHE3072_P));
  if (rc == 0) rc = mbedtls_mpi_lset(&g->G, 2);
  if (rc == 0) rc = mbedtls_mpi_sub_int(&g->Q, &g->P, 1);
  if (rc == 0) rc = mbedtls_mpi_shift_r(&g->Q, 1);
  if (rc == 0) rc = mbedtls_mpi_sub_int(&g->Pm2, &g->P, 2);
  return rc;
}

static void dh_group_free(DhGroup* g) {
  mbedtls_mpi_free(&g->P); mbedtls_mpi_free(&g->G); mbedtls_mpi_free(&g->Q);
  mbedtls_mpi_free(&g->Pm2); mbedtls_mpi_free(&g->RR);
}

static int dh_keygen(DhGroup* g, DhKey* k, uint8_t* share_out, mbedtls_ctr_drbg_context* rng) {
  mbedtls_mpi X;
  mbedtls_mpi_init(&X);
  int rc = mbedtls_mpi_random(&k->x, 2, &g->Q, mbedtls_ctr_drbg_random, rng);
  if (rc == 0) rc = mbedtls_mpi_exp_mod(&X, &g->G, &k->x, &g->P, &g->RR);
  if (rc == 0) rc = mbedtls_mpi_write_binary(&X, share_out, 384);
  mbedtls_mpi_free(&X);
  return rc;
}

static int dh_derive(DhGroup* g, const DhKey* k, const uint8_t* peer_share, uint8_t* secret_out) {
  mbedtls_mpi Y, K;
  mbedtls_mpi_init(&Y);
  mbedtls_mpi_init(&K);
  int rc = mbedtls_mpi_read_binary(&Y, peer_share, 384);
  if (rc == 0 && (mbedtls_mpi_cmp_int(&Y, 2) < 0 || mbedtls_mpi_cmp_mpi(&Y, &g->Pm2) > 0)) rc = -1;
  if (rc == 0) rc = mbedtls_mpi_exp_mod(&K, &Y, &k->x, &g->P, &g->RR);
  if (rc == 0) rc = mbedtls_mpi_write_binary(&K, secret_out, 384);
  mbedtls_mpi_free(&K);
  mbedtls_mpi_free(&Y);
  return rc;
}

// ----------------------------------------------------
// Stage 1: On-Chip Memory Profiling (Heap & Stack)
// Executed in dedicated FreeRTOS tasks before Wi-Fi
// ----------------------------------------------------
static void memory_pass_x25519() {
  uint8_t sk1[32], pk1[32], sk2[32], pk2[32], ss[32];
  randombytes_buf(sk1, 32); crypto_scalarmult_base(pk1, sk1);
  randombytes_buf(sk2, 32); crypto_scalarmult_base(pk2, sk2);
  crypto_scalarmult(ss, sk1, pk2);
  kpi_x25519.peak_heap  = 0; // libsodium X25519 uses zero dynamic heap
  kpi_x25519.peak_stack = measure_stack_used();
}

static void memory_pass_p256() {
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context rng;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&rng);
  mbedtls_ctr_drbg_seed(&rng, mbedtls_entropy_func, &entropy, (const unsigned char*)"mem_p256", 8);

  heap_tracking_on();
  mbedtls_ecp_group grp;
  mbedtls_mpi d1, d2;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d1);
  mbedtls_mpi_init(&d2);
  mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  g_heap_peak = g_heap_current;

  uint8_t share1[65], share2[65], ss[32];
  p256_keygen(&grp, &d1, share1, &rng);
  p256_keygen(&grp, &d2, share2, &rng);
  p256_derive(&grp, &d1, share2, ss, &rng);
  kpi_p256.peak_heap  = (uint32_t)g_heap_peak;
  kpi_p256.peak_stack = measure_stack_used();

  mbedtls_mpi_free(&d1);
  mbedtls_mpi_free(&d2);
  mbedtls_ecp_group_free(&grp);
  heap_tracking_off();
  mbedtls_ctr_drbg_free(&rng);
  mbedtls_entropy_free(&entropy);
}

static void memory_pass_dh3072() {
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context rng;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&rng);
  mbedtls_ctr_drbg_seed(&rng, mbedtls_entropy_func, &entropy, (const unsigned char*)"mem_dh", 6);

  heap_tracking_on();
  DhGroup grp;
  DhKey k1;
  dh_group_init(&grp);
  mbedtls_mpi_init(&k1.x);
  g_heap_peak = g_heap_current;

  static uint8_t share[384], ss[384];
  dh_keygen(&grp, &k1, share, &rng);
  dh_derive(&grp, &k1, share, ss);
  kpi_dh3072.peak_heap  = (uint32_t)g_heap_peak;
  kpi_dh3072.peak_stack = measure_stack_used();

  mbedtls_mpi_free(&k1.x);
  dh_group_free(&grp);
  heap_tracking_off();
  mbedtls_ctr_drbg_free(&rng);
  mbedtls_entropy_free(&entropy);
}

// ----------------------------------------------------
// Stage 2: Live ESP32 <-> Laptop Key Exchange Suites
// ----------------------------------------------------
static void print_suite_kpis(const char* title, const KexKPI& k) {
  Serial.printf("  [%s Summary]\n", title);
  Serial.printf("  ESP32 KeyGen (Mean/Med/σ) : %7.2f ms | %7.2f ms | ±%5.2f ms\n", k.keygen.mean_ms, k.keygen.median_ms, k.keygen.stddev_ms);
  Serial.printf("  ESP32 Derive (Mean/Med/σ) : %7.2f ms | %7.2f ms | ±%5.2f ms\n", k.derive.mean_ms, k.derive.median_ms, k.derive.stddev_ms);
  Serial.printf("  ESP32 Total Crypto Cost   : %7.2f ms\n", k.esp_crypto_ms);
  Serial.printf("  Laptop KeyGen + Derive    : %7.3f ms (%5.3f ms + %5.3f ms)\n", k.srv_crypto_ms, k.srv_keygen_ms, k.srv_derive_ms);
  Serial.printf("  Combined Crypto (Both)    : %7.2f ms\n", k.combined_crypto_ms);
  Serial.printf("  End-to-End Wi-Fi KEX Time : %7.2f ms\n", k.e2e_network_ms);
  Serial.printf("  Key Share Wire Size       : %u B | Heap: %u B | Stack: %u B | Status: %s\n",
                k.share_bytes, k.peak_heap, k.peak_stack, k.failures == 0 ? "PASS" : "FAIL");
}

void benchmark_live_x25519() {
  Serial.println("\n[1/3] Live ESP32 <-> Laptop Key Exchange: X25519 (Curve25519)");
  uint8_t cmd[2] = {ALG_X25519, FAST_RUNS};
  client.write(cmd, 2);
  client.flush();

  static uint64_t t_keygen[FAST_RUNS];
  static uint64_t t_derive[FAST_RUNS];
  double srv_kg_sum_us = 0, srv_der_sum_us = 0, e2e_sum_ms = 0;
  uint32_t failures = 0;

  uint8_t cli_sk[32], cli_pk[32], srv_pk[32], cli_ss[32];
  uint8_t msg1[1 + 32];
  uint8_t msg2[32 + 8 + 16];

  for (int i = 0; i < FAST_RUNS; i++) {
    int64_t t_e2e_start = esp_timer_get_time();

    // 1. ESP32 KeyGen (Timed)
    uint32_t c0 = get_cycles();
    randombytes_buf(cli_sk, 32);
    int rc = crypto_scalarmult_base(cli_pk, cli_sk);
    t_keygen[i] = get_cycles() - c0;
    if (rc != 0) failures++;

    // 2. Send MSG 1: [AlgID (1B) | cli_pk (32B)]
    msg1[0] = ALG_X25519;
    memcpy(msg1 + 1, cli_pk, 32);
    send_msg(msg1, sizeof(msg1));

    // 3. Receive MSG 2: [srv_pk (32B) | SrvKeyGen_us (4B) | SrvDerive_us (4B) | ConfirmTag (16B)]
    if (recv_msg(msg2, sizeof(msg2)) != (int)sizeof(msg2)) {
      failures++;
      break;
    }
    memcpy(srv_pk, msg2, 32);
    uint32_t srv_kg_us  = read_u32_be(msg2 + 32);
    uint32_t srv_der_us = read_u32_be(msg2 + 36);
    const uint8_t* rx_tag = msg2 + 40;

    // 4. ESP32 Derive (Timed)
    c0 = get_cycles();
    rc = crypto_scalarmult(cli_ss, cli_sk, srv_pk);
    t_derive[i] = get_cycles() - c0;
    if (rc != 0) failures++;

    int64_t t_e2e_end = esp_timer_get_time();

    // 5. Key Confirmation Check (Untimed — uses HKDF-derived K_confirm)
    uint8_t expected_tag[16];
    compute_kex_confirm_tag(cli_ss, 32, cli_pk, srv_pk, 32, expected_tag);
    if (memcmp(expected_tag, rx_tag, 16) != 0) failures++;

    srv_kg_sum_us  += srv_kg_us;
    srv_der_sum_us += srv_der_us;
    e2e_sum_ms     += (double)(t_e2e_end - t_e2e_start) / 1000.0;
  }

  kpi_x25519.keygen             = calculate_stats(t_keygen, FAST_RUNS);
  kpi_x25519.derive             = calculate_stats(t_derive, FAST_RUNS);
  kpi_x25519.share_bytes        = 32;
  kpi_x25519.secret_bytes       = 32;
  kpi_x25519.esp_crypto_ms      = kpi_x25519.keygen.mean_ms + kpi_x25519.derive.mean_ms;
  kpi_x25519.srv_keygen_ms      = (float)(srv_kg_sum_us / FAST_RUNS / 1000.0);
  kpi_x25519.srv_derive_ms      = (float)(srv_der_sum_us / FAST_RUNS / 1000.0);
  kpi_x25519.srv_crypto_ms      = kpi_x25519.srv_keygen_ms + kpi_x25519.srv_derive_ms;
  kpi_x25519.combined_crypto_ms = kpi_x25519.esp_crypto_ms + kpi_x25519.srv_crypto_ms;
  kpi_x25519.e2e_network_ms     = (float)(e2e_sum_ms / FAST_RUNS);
  kpi_x25519.failures           = failures;

  sodium_memzero(cli_sk, sizeof(cli_sk));
  print_suite_kpis("X25519", kpi_x25519);
}

void benchmark_live_p256() {
  Serial.println("\n[2/3] Live ESP32 <-> Laptop Key Exchange: ECDH P-256 (secp256r1)");
  uint8_t cmd[2] = {ALG_ECDH_P256, FAST_RUNS};
  client.write(cmd, 2);
  client.flush();

  static uint64_t t_keygen[FAST_RUNS];
  static uint64_t t_derive[FAST_RUNS];
  double srv_kg_sum_us = 0, srv_der_sum_us = 0, e2e_sum_ms = 0;
  uint32_t failures = 0;

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context rng;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&rng);
  mbedtls_ctr_drbg_seed(&rng, mbedtls_entropy_func, &entropy, (const unsigned char*)"kex_p256", 8);

  mbedtls_ecp_group grp;
  mbedtls_mpi cli_d;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&cli_d);
  mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);

  uint8_t cli_pk[65], srv_pk[65], cli_ss[32];
  uint8_t msg1[1 + 65];
  uint8_t msg2[65 + 8 + 16];

  for (int i = 0; i < FAST_RUNS; i++) {
    int64_t t_e2e_start = esp_timer_get_time();

    // 1. ESP32 KeyGen (Timed)
    uint32_t c0 = get_cycles();
    int rc = p256_keygen(&grp, &cli_d, cli_pk, &rng);
    t_keygen[i] = get_cycles() - c0;
    if (rc != 0) failures++;

    // 2. Send MSG 1: [AlgID (1B) | cli_pk (65B)]
    msg1[0] = ALG_ECDH_P256;
    memcpy(msg1 + 1, cli_pk, 65);
    send_msg(msg1, sizeof(msg1));

    // 3. Receive MSG 2: [srv_pk (65B) | SrvKeyGen_us (4B) | SrvDerive_us (4B) | ConfirmTag (16B)]
    if (recv_msg(msg2, sizeof(msg2)) != (int)sizeof(msg2)) {
      failures++;
      break;
    }
    memcpy(srv_pk, msg2, 65);
    uint32_t srv_kg_us  = read_u32_be(msg2 + 65);
    uint32_t srv_der_us = read_u32_be(msg2 + 69);
    const uint8_t* rx_tag = msg2 + 73;

    // 4. ESP32 Derive (Timed)
    c0 = get_cycles();
    rc = p256_derive(&grp, &cli_d, srv_pk, cli_ss, &rng);
    t_derive[i] = get_cycles() - c0;
    if (rc != 0) failures++;

    int64_t t_e2e_end = esp_timer_get_time();

    // 5. Key Confirmation Check (Untimed)
    uint8_t expected_tag[16];
    compute_kex_confirm_tag(cli_ss, 32, cli_pk, srv_pk, 65, expected_tag);
    if (memcmp(expected_tag, rx_tag, 16) != 0) failures++;

    srv_kg_sum_us  += srv_kg_us;
    srv_der_sum_us += srv_der_us;
    e2e_sum_ms     += (double)(t_e2e_end - t_e2e_start) / 1000.0;
    if (i % 10 == 9) vTaskDelay(1);
  }

  kpi_p256.keygen             = calculate_stats(t_keygen, FAST_RUNS);
  kpi_p256.derive             = calculate_stats(t_derive, FAST_RUNS);
  kpi_p256.share_bytes        = 65;
  kpi_p256.secret_bytes       = 32;
  kpi_p256.esp_crypto_ms      = kpi_p256.keygen.mean_ms + kpi_p256.derive.mean_ms;
  kpi_p256.srv_keygen_ms      = (float)(srv_kg_sum_us / FAST_RUNS / 1000.0);
  kpi_p256.srv_derive_ms      = (float)(srv_der_sum_us / FAST_RUNS / 1000.0);
  kpi_p256.srv_crypto_ms      = kpi_p256.srv_keygen_ms + kpi_p256.srv_derive_ms;
  kpi_p256.combined_crypto_ms = kpi_p256.esp_crypto_ms + kpi_p256.srv_crypto_ms;
  kpi_p256.e2e_network_ms     = (float)(e2e_sum_ms / FAST_RUNS);
  kpi_p256.failures           = failures;

  mbedtls_mpi_free(&cli_d);
  mbedtls_ecp_group_free(&grp);
  mbedtls_ctr_drbg_free(&rng);
  mbedtls_entropy_free(&entropy);
  print_suite_kpis("ECDH P-256", kpi_p256);
}

void benchmark_live_dh3072() {
  Serial.println("\n[3/3] Live ESP32 <-> Laptop Key Exchange: DH-3072 (RFC 7919 ffdhe3072)");
  uint8_t cmd[2] = {ALG_DH3072, DH_RUNS};
  client.write(cmd, 2);
  client.flush();

  static uint64_t t_keygen[DH_RUNS];
  static uint64_t t_derive[DH_RUNS];
  double srv_kg_sum_us = 0, srv_der_sum_us = 0, e2e_sum_ms = 0;
  uint32_t failures = 0;

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context rng;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&rng);
  mbedtls_ctr_drbg_seed(&rng, mbedtls_entropy_func, &entropy, (const unsigned char*)"kex_dh", 6);

  DhGroup grp;
  DhKey cli;
  dh_group_init(&grp);
  mbedtls_mpi_init(&cli.x);

  static uint8_t cli_pk[384], srv_pk[384], cli_ss[384];
  static uint8_t msg1[1 + 384];
  static uint8_t msg2[384 + 8 + 16];

  // Warm-up to populate Montgomery constant RR
  dh_keygen(&grp, &cli, cli_pk, &rng);

  for (int i = 0; i < DH_RUNS; i++) {
    int64_t t_e2e_start = esp_timer_get_time();

    // 1. ESP32 KeyGen (Timed)
    uint32_t c0 = get_cycles();
    int rc = dh_keygen(&grp, &cli, cli_pk, &rng);
    t_keygen[i] = get_cycles() - c0;
    if (rc != 0) failures++;

    // 2. Send MSG 1: [AlgID (1B) | cli_pk (384B)]
    msg1[0] = ALG_DH3072;
    memcpy(msg1 + 1, cli_pk, 384);
    send_msg(msg1, sizeof(msg1));

    // 3. Receive MSG 2: [srv_pk (384B) | SrvKeyGen_us (4B) | SrvDerive_us (4B) | ConfirmTag (16B)]
    if (recv_msg(msg2, sizeof(msg2)) != (int)sizeof(msg2)) {
      failures++;
      break;
    }
    memcpy(srv_pk, msg2, 384);
    uint32_t srv_kg_us  = read_u32_be(msg2 + 384);
    uint32_t srv_der_us = read_u32_be(msg2 + 388);
    const uint8_t* rx_tag = msg2 + 392;

    // 4. ESP32 Derive (Timed)
    c0 = get_cycles();
    rc = dh_derive(&grp, &cli, srv_pk, cli_ss);
    t_derive[i] = get_cycles() - c0;
    if (rc != 0) failures++;

    int64_t t_e2e_end = esp_timer_get_time();

    // 5. Key Confirmation Check (Untimed)
    uint8_t expected_tag[16];
    compute_kex_confirm_tag(cli_ss, 384, cli_pk, srv_pk, 384, expected_tag);
    if (memcmp(expected_tag, rx_tag, 16) != 0) failures++;

    srv_kg_sum_us  += srv_kg_us;
    srv_der_sum_us += srv_der_us;
    e2e_sum_ms     += (double)(t_e2e_end - t_e2e_start) / 1000.0;
    vTaskDelay(1);
  }

  kpi_dh3072.keygen             = calculate_stats(t_keygen, DH_RUNS);
  kpi_dh3072.derive             = calculate_stats(t_derive, DH_RUNS);
  kpi_dh3072.share_bytes        = 384;
  kpi_dh3072.secret_bytes       = 384;
  kpi_dh3072.esp_crypto_ms      = kpi_dh3072.keygen.mean_ms + kpi_dh3072.derive.mean_ms;
  kpi_dh3072.srv_keygen_ms      = (float)(srv_kg_sum_us / DH_RUNS / 1000.0);
  kpi_dh3072.srv_derive_ms      = (float)(srv_der_sum_us / DH_RUNS / 1000.0);
  kpi_dh3072.srv_crypto_ms      = kpi_dh3072.srv_keygen_ms + kpi_dh3072.srv_derive_ms;
  kpi_dh3072.combined_crypto_ms = kpi_dh3072.esp_crypto_ms + kpi_dh3072.srv_crypto_ms;
  kpi_dh3072.e2e_network_ms     = (float)(e2e_sum_ms / DH_RUNS);
  kpi_dh3072.failures           = failures;

  mbedtls_mpi_free(&cli.x);
  dh_group_free(&grp);
  mbedtls_ctr_drbg_free(&rng);
  mbedtls_entropy_free(&entropy);
  print_suite_kpis("DH-3072", kpi_dh3072);
}

// ----------------------------------------------------
// Unified Summary Table
// ----------------------------------------------------
static const char* pass_str(uint32_t f) { return f == 0 ? "PASS (0 err)" : "FAIL"; }

void print_comparison_table() {
  const KexKPI& a = kpi_x25519;
  const KexKPI& b = kpi_p256;
  const KexKPI& c = kpi_dh3072;
  Serial.println("\n==========================================================================================");
  Serial.println("            COMBINED ESP32 <-> LAPTOP KEY EXCHANGE BENCHMARK SUMMARY                      ");
  Serial.println("==========================================================================================");
  Serial.printf("%-7s | %-37s | %-12s | %-12s | %-12s\n", "KPI ID", "Metric", "X25519", "ECDH P-256", "DH-3072");
  Serial.println("--------+---------------------------------------+--------------+--------------+-------------");
  Serial.printf("%-7s | %-37s | %9.2f ms | %9.2f ms | %9.2f ms\n", "KEX-1", "ESP32 Ephemeral KeyGen (Mean)", a.keygen.mean_ms, b.keygen.mean_ms, c.keygen.mean_ms);
  Serial.printf("%-7s | %-37s | %9.2f ms | %9.2f ms | %9.2f ms\n", "",      "ESP32 Ephemeral KeyGen (Median)", a.keygen.median_ms, b.keygen.median_ms, c.keygen.median_ms);
  Serial.printf("%-7s | %-38s | %9.2f ms | %9.2f ms | %9.2f ms\n", "",      "ESP32 Ephemeral KeyGen (StdDev σ)", a.keygen.stddev_ms, b.keygen.stddev_ms, c.keygen.stddev_ms);
  Serial.printf("%-7s | %-37s | %10u B | %10u B | %10u B\n",      "KEX-2", "Public Key Share Wire Size", a.share_bytes, b.share_bytes, c.share_bytes);
  Serial.printf("%-7s | %-37s | %9.2f ms | %9.2f ms | %9.2f ms\n", "KEX-3", "ESP32 Secret Derivation (Mean)", a.derive.mean_ms, b.derive.mean_ms, c.derive.mean_ms);
  Serial.printf("%-7s | %-37s | %9.2f ms | %9.2f ms | %9.2f ms\n", "",      "ESP32 Secret Derivation (Median)", a.derive.median_ms, b.derive.median_ms, c.derive.median_ms);
  Serial.printf("%-7s | %-38s | %9.2f ms | %9.2f ms | %9.2f ms\n", "",      "ESP32 Secret Derivation (StdDev σ)", a.derive.stddev_ms, b.derive.stddev_ms, c.derive.stddev_ms);
  Serial.printf("%-7s | %-37s | %9.2f ms | %9.2f ms | %9.2f ms\n", "KEX-4", "ESP32 Total Crypto (KeyGen+Derive)", a.esp_crypto_ms, b.esp_crypto_ms, c.esp_crypto_ms);
  Serial.printf("%-7s | %-37s | %9.3f ms | %9.3f ms | %9.3f ms\n", "KEX-5", "Laptop Gateway Crypto (KeyGen+Derive)", a.srv_crypto_ms, b.srv_crypto_ms, c.srv_crypto_ms);
  Serial.printf("%-7s | %-37s | %9.2f ms | %9.2f ms | %9.2f ms\n", "KEX-6", "Combined Crypto (ESP32 + Laptop)", a.combined_crypto_ms, b.combined_crypto_ms, c.combined_crypto_ms);
  Serial.printf("%-7s | %-37s | %9.2f ms | %9.2f ms | %9.2f ms\n", "KEX-7", "End-to-End Network KEX Latency", a.e2e_network_ms, b.e2e_network_ms, c.e2e_network_ms);
  Serial.printf("%-7s | %-37s | %10u B | %10u B | %10u B\n",      "KEX-8", "ESP32 Peak Dynamic Heap RAM", a.peak_heap, b.peak_heap, c.peak_heap);
  Serial.printf("%-7s | %-37s | %10u B | %10u B | %10u B\n",      "KEX-9", "ESP32 Peak Crypto Stack Usage", a.peak_stack, b.peak_stack, c.peak_stack);
  Serial.printf("%-7s | %-37s | %12s | %12s | %12s\n",            "KEX-10","HKDF Key Confirmation (Every Run)", pass_str(a.failures), pass_str(b.failures), pass_str(c.failures));
  Serial.println("==========================================================================================");
}

void setup() {
  Serial.begin(115200);
  delay(2000);

  if (getCpuFrequencyMhz() != CPU_SPEED) setCpuFrequencyMhz(CPU_SPEED);

  Serial.println("\n==========================================================================================");
  Serial.println("          Combined ESP32 <-> Laptop Key Exchange Benchmark (X25519 / P-256 / DH-3072)     ");
  Serial.println("------------------------------------------------------------------------------------------");
  Serial.printf("ESP-IDF Version   : %s\n", esp_get_idf_version());
  Serial.printf("Chip Model & Rev  : %s (Rev %d) @ %d MHz\n", ESP.getChipModel(), ESP.getChipRevision(), getCpuFrequencyMhz());
  Serial.printf("Initial Free Heap : %u bytes\n", ESP.getFreeHeap());
  Serial.println("==========================================================================================");

  if (sodium_init() < 0) {
    Serial.println("[ERROR] sodium_init() failed!");
    return;
  }

  Serial.print("[KAT] RFC 7748 Section 6.1 X25519 test vectors... ");
  Serial.println(run_x25519_kat() ? "PASS" : "FAIL");

  // Stage 1: On-Chip Memory & Stack Profiling (Isolated FreeRTOS tasks)
  Serial.println("\n[Stage 1] Profiling On-Chip Heap & Stack Usage...");
  SemaphoreHandle_t sem = xSemaphoreCreateBinary();

  xTaskCreatePinnedToCore([](void* p) { memory_pass_x25519(); xSemaphoreGive((SemaphoreHandle_t)p); vTaskDelete(NULL); },
                          "mem_x25519", BENCH_STACK_SIZE, sem, 5, NULL, 1);
  xSemaphoreTake(sem, portMAX_DELAY);

  xTaskCreatePinnedToCore([](void* p) { memory_pass_p256();   xSemaphoreGive((SemaphoreHandle_t)p); vTaskDelete(NULL); },
                          "mem_p256", BENCH_STACK_SIZE, sem, 5, NULL, 1);
  xSemaphoreTake(sem, portMAX_DELAY);

  xTaskCreatePinnedToCore([](void* p) { memory_pass_dh3072(); xSemaphoreGive((SemaphoreHandle_t)p); vTaskDelete(NULL); },
                          "mem_dh3072", BENCH_STACK_SIZE, sem, 5, NULL, 1);
  xSemaphoreTake(sem, portMAX_DELAY);
  vSemaphoreDelete(sem);

  // Stage 2: Connect to Wi-Fi & Laptop Gateway Server
  Serial.printf("\n[Stage 2] Connecting to Wi-Fi '%s'...", WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false); // Disable modem sleep for consistent timing
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(300);
    Serial.print(".");
  }
  Serial.printf(" Connected! ESP32 IP: %s\n", WiFi.localIP().toString().c_str());

  Serial.printf("Connecting to Laptop Gateway at %s:%u...", LAPTOP_IP, PORT);
  if (!client.connect(LAPTOP_IP, PORT)) {
    Serial.println("\n[ERROR] Connection failed! Start 'python3 benchmark_gateway_kex.py' on your laptop first.");
    return;
  }
  client.setNoDelay(true);
  Serial.println(" Connected!");

  // Execute Live Combined Key Exchange Suites
  benchmark_live_x25519();
  benchmark_live_p256();
  benchmark_live_dh3072();

  // Signal completion to Laptop server
  uint8_t done_cmd[2] = {ALG_DONE, 0};
  client.write(done_cmd, 2);
  client.flush();
  client.stop();

  print_comparison_table();
}

void loop() {
  delay(10000);
}
