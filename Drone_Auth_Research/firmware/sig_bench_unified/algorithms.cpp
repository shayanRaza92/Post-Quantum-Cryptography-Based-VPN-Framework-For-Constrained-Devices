// algorithms.cpp - the six signature algorithms behind one interface (see algorithms.h).
//
// Rules that keep the comparison fair:
//  * "sign" and "verify" always start from the message: for ECDSA and RSA the SHA-256 of
//    the message is part of the timed operation (Ed25519 and ML-DSA hash internally).
//  * Every algorithm uses the library the VPN uses on the ESP32: libsodium (Ed25519),
//    mbedTLS (ECDSA P-256, RSA-3072, both with SHA-256) and mldsa-native (ML-DSA).
//  * Keys are kept in static memory, so stack measurements show only the algorithm.
//  * Every algorithm must pass a known-answer test against an independent reference
//    before it is timed (vectors in classical_vectors.h and test_vectors.h).

#include <Arduino.h>
#include <string.h>
#include <esp_heap_caps.h>
#include <sodium.h>

#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha256.h"
#include "mbedtls/platform.h"

#include "bench_config.h"
#include "algorithms.h"
#include "classical_vectors.h"
#include "test_vectors.h"
#include <MLDSA_Levels.h>

// In a FOOTPRINT_BUILD (tools/flash_footprint.sh) the test-only code is left out: the
// known-answer tests, their test vectors and the RSA key DER writer. What remains is what a
// drone firmware using the algorithm would contain.
#if ENABLE_LINK_TEST
#define PK_EXPORT(f) f
#else
#define PK_EXPORT(f) nullptr
#endif

#if FOOTPRINT_BUILD
static bool kat_not_built() { return true; }
#define KAT_FN(f) kat_not_built
#else
#define KAT_FN(f) f
#endif

// ----------------------------------------------------------------------------------------
// Shared helpers
// ----------------------------------------------------------------------------------------
static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_drbg;

static uint8_t kat_sig[MAX_SIG_BYTES];          // signature buffer for the known-answer tests
static uint8_t tmp_pk[MAX_PK_BYTES];             // throw-away keys from timed key generation
static uint8_t tmp_sk[MAX_SK_BYTES];

void sha256(const uint8_t* in, size_t len, uint8_t out[32]) {
  mbedtls_sha256(in, len, out, 0);
}

[[maybe_unused]] static bool hex_to_bytes(const char* hex, uint8_t* out, size_t n) {
  if (strlen(hex) != 2 * n) return false;
  for (size_t i = 0; i < n; i++) {
    unsigned v;
    if (sscanf(hex + 2 * i, "%2x", &v) != 1) return false;
    out[i] = (uint8_t)v;
  }
  return true;
}

// ---- mbedTLS heap tracking --------------------------------------------------------------
// Installed once at start-up for ALL mbedTLS allocations (so no pointer is ever freed by
// the wrong allocator). It only counts while tracking is switched on. Allocation is done
// from internal RAM, as mbedTLS itself does here (CONFIG_MBEDTLS_INTERNAL_MEM_ALLOC=y).
struct MemHeader {
  uint32_t magic;
  uint32_t size;                                 // 8-byte header keeps payload 8-byte aligned
};
static const uint32_t MEM_MAGIC = 0x44524E31;    // "DRN1"
static volatile bool g_track = false;
static size_t g_heap_now = 0, g_heap_peak = 0;

static void* tracked_calloc(size_t n, size_t size) {
  if (size != 0 && n > SIZE_MAX / size) return NULL;
  size_t total = n * size;
  MemHeader* h = (MemHeader*)heap_caps_calloc(1, total + sizeof(MemHeader),
                                              MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  if (!h) return NULL;
  h->magic = MEM_MAGIC;
  h->size = (uint32_t)total;
  if (g_track) {
    g_heap_now += total;
    if (g_heap_now > g_heap_peak) g_heap_peak = g_heap_now;
  }
  return h + 1;
}

static void tracked_free(void* p) {
  if (!p) return;
  MemHeader* h = ((MemHeader*)p) - 1;
  if (h->magic != MEM_MAGIC) {                   // never expected; do not corrupt the heap
    Serial.println("WARN,heap,foreign pointer passed to mbedTLS free");
    return;
  }
  if (g_track && g_heap_now >= h->size) g_heap_now -= h->size;
  h->magic = 0;
  heap_caps_free(h);
}

void heap_track_start() {
  g_heap_now = 0;
  g_heap_peak = 0;
  g_track = true;
}

size_t heap_track_stop() {
  g_track = false;
  return g_heap_peak;
}

bool algorithms_init() {
  // Must run before any other mbedTLS call
  if (mbedtls_platform_set_calloc_free(tracked_calloc, tracked_free) != 0) return false;
  mbedtls_entropy_init(&g_entropy);
  mbedtls_ctr_drbg_init(&g_drbg);
  static const char pers[] = "drone-auth-sig-bench";
  if (mbedtls_ctr_drbg_seed(&g_drbg, mbedtls_entropy_func, &g_entropy,
                            (const unsigned char*)pers, sizeof(pers) - 1) != 0) return false;
  return sodium_init() >= 0;
}

// ========================================================================================
// Ed25519 (libsodium)
// ========================================================================================
#if ENABLE_ED25519
static uint8_t ed_pk[32], ed_sk[64];

[[maybe_unused]] static bool ed_kat() {
  uint8_t pk[32], sk[64];
  unsigned long long len = 0;
  const uint8_t empty = 0;
  if (crypto_sign_ed25519_seed_keypair(pk, sk, KAT_ED25519_SEED) != 0) return false;
  if (memcmp(pk, KAT_ED25519_PK, 32) != 0) return false;
  if (crypto_sign_ed25519_detached(kat_sig, &len, &empty, 0, sk) != 0 || len != 64) return false;
  if (memcmp(kat_sig, KAT_ED25519_SIG, 64) != 0) return false;
  if (crypto_sign_ed25519_verify_detached(kat_sig, &empty, 0, pk) != 0) return false;
  kat_sig[10] ^= 0x01;                            // one changed bit must be rejected
  return crypto_sign_ed25519_verify_detached(kat_sig, &empty, 0, pk) != 0;
}
static int ed_keygen_once() { return crypto_sign_ed25519_keypair(tmp_pk, tmp_sk); }
static int ed_make_key() { return crypto_sign_ed25519_keypair(ed_pk, ed_sk); }
static void ed_free_key() { sodium_memzero(ed_sk, sizeof ed_sk); }
static int ed_sign(const uint8_t* m, size_t len, uint8_t* sig, size_t* siglen) {
  unsigned long long l = 0;
  int rc = crypto_sign_ed25519_detached(sig, &l, m, len, ed_sk);
  *siglen = (size_t)l;
  return rc;
}
static int ed_verify(const uint8_t* m, size_t len, const uint8_t* sig, size_t siglen) {
  if (siglen != 64) return -1;
  return crypto_sign_ed25519_verify_detached(sig, m, len, ed_pk);
}
static size_t ed_sk_bytes() { return 64; }       // libsodium format: 32-byte seed + public key
#if ENABLE_LINK_TEST
static size_t ed_export_pk(uint8_t* out, size_t max) {
  if (max < 32) return 0;
  memcpy(out, ed_pk, 32);
  return 32;
}
#endif

static const SigAlgorithm ALG_ED25519 = {
  "Ed25519", "libsodium (ESP-IDF, SHA-512 via mbedTLS)", "~128-bit classical", false, BENCH_RUNS,
  KAT_FN(ed_kat), ed_keygen_once, ed_make_key, ed_free_key, ed_sign, ed_verify, 32, ed_sk_bytes,
  PK_EXPORT(ed_export_pk) };
#endif

// ========================================================================================
// ECDSA P-256 with SHA-256 (mbedTLS, deterministic nonces per RFC 6979)
// ========================================================================================
#if ENABLE_ECDSA_P256
static mbedtls_ecdsa_context ec_key;

[[maybe_unused]] static bool ec_kat() {
  bool ok = false;
  uint8_t x[32], ux[32], uy[32], q[65], h[32];
  size_t qlen = 0, slen = 0;
  mbedtls_ecp_keypair kp;
  mbedtls_ecp_keypair_init(&kp);
  if (!hex_to_bytes(KAT_ECDSA_X_HEX, x, 32) || !hex_to_bytes(KAT_ECDSA_UX_HEX, ux, 32) ||
      !hex_to_bytes(KAT_ECDSA_UY_HEX, uy, 32)) goto done;
  if (mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &kp, x, 32) != 0) goto done;
  if (mbedtls_ecp_keypair_calc_public(&kp, mbedtls_ctr_drbg_random, &g_drbg) != 0) goto done;
  if (mbedtls_ecp_write_public_key(&kp, MBEDTLS_ECP_PF_UNCOMPRESSED, &qlen, q, sizeof q) != 0) goto done;
  if (qlen != 65 || q[0] != 0x04 || memcmp(q + 1, ux, 32) != 0 || memcmp(q + 33, uy, 32) != 0) goto done;
  sha256((const uint8_t*)KAT_ECDSA_MSG, strlen(KAT_ECDSA_MSG), h);
  if (mbedtls_ecdsa_write_signature(&kp, MBEDTLS_MD_SHA256, h, 32, kat_sig, sizeof kat_sig, &slen,
                                    mbedtls_ctr_drbg_random, &g_drbg) != 0) goto done;
  if (slen != sizeof(KAT_ECDSA_SIG_DER) || memcmp(kat_sig, KAT_ECDSA_SIG_DER, slen) != 0) goto done;
  if (mbedtls_ecdsa_read_signature(&kp, h, 32, kat_sig, slen) != 0) goto done;
  kat_sig[slen - 5] ^= 0x01;
  ok = mbedtls_ecdsa_read_signature(&kp, h, 32, kat_sig, slen) != 0;
done:
  mbedtls_ecp_keypair_free(&kp);
  return ok;
}
static int ec_keygen_once() {
  mbedtls_ecdsa_context k;
  mbedtls_ecdsa_init(&k);
  int rc = mbedtls_ecdsa_genkey(&k, MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random, &g_drbg);
  mbedtls_ecdsa_free(&k);
  return rc;
}
static int ec_make_key() {
  mbedtls_ecdsa_init(&ec_key);
  return mbedtls_ecdsa_genkey(&ec_key, MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random, &g_drbg);
}
static void ec_free_key() { mbedtls_ecdsa_free(&ec_key); }
static int ec_sign(const uint8_t* m, size_t len, uint8_t* sig, size_t* siglen) {
  uint8_t h[32];
  sha256(m, len, h);
  return mbedtls_ecdsa_write_signature(&ec_key, MBEDTLS_MD_SHA256, h, 32, sig, MAX_SIG_BYTES, siglen,
                                       mbedtls_ctr_drbg_random, &g_drbg);
}
static int ec_verify(const uint8_t* m, size_t len, const uint8_t* sig, size_t siglen) {
  uint8_t h[32];
  sha256(m, len, h);
  return mbedtls_ecdsa_read_signature(&ec_key, h, 32, sig, siglen);
}
static size_t ec_sk_bytes() { return 32; }       // the private scalar
#if ENABLE_LINK_TEST
static size_t ec_export_pk(uint8_t* out, size_t max) {   // uncompressed point, 65 bytes
  size_t olen = 0;
  if (mbedtls_ecp_write_public_key(&ec_key, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, out, max) != 0) return 0;
  return olen;
}
#endif

static const SigAlgorithm ALG_ECDSA_P256 = {
  "ECDSA-P256", "mbedTLS 3.6 (hardware MPI + SHA)", "~128-bit classical", false, BENCH_RUNS,
  KAT_FN(ec_kat), ec_keygen_once, ec_make_key, ec_free_key, ec_sign, ec_verify, 65, ec_sk_bytes,
  PK_EXPORT(ec_export_pk) };
#endif

// ========================================================================================
// RSA-3072, PKCS#1 v1.5 with SHA-256, e = 65537 (mbedTLS)
// ========================================================================================
#if ENABLE_RSA3072
static mbedtls_pk_context rsa_key;
static bool rsa_key_ready = false;

[[maybe_unused]] static bool rsa_kat() {
  bool ok = false;
  uint8_t h[32], d[32];
  size_t slen = 0;
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);
  if (mbedtls_pk_parse_key(&pk, (const unsigned char*)KAT_RSA_KEY_PEM, sizeof(KAT_RSA_KEY_PEM), NULL, 0,
                           mbedtls_ctr_drbg_random, &g_drbg) != 0) goto done;
  sha256((const uint8_t*)KAT_RSA_MSG, strlen(KAT_RSA_MSG), h);
  if (mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, h, 32, kat_sig, sizeof kat_sig, &slen,
                      mbedtls_ctr_drbg_random, &g_drbg) != 0 || slen != 384) goto done;
  sha256(kat_sig, slen, d);
  if (memcmp(d, KAT_RSA_SIG_SHA256, 32) != 0) goto done;
  if (mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, h, 32, kat_sig, slen) != 0) goto done;
  kat_sig[100] ^= 0x01;
  ok = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, h, 32, kat_sig, slen) != 0;
done:
  mbedtls_pk_free(&pk);
  return ok;
}
static int rsa_keygen_once() {
  mbedtls_pk_context k;
  mbedtls_pk_init(&k);
  int rc = mbedtls_pk_setup(&k, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
  if (rc == 0) rc = mbedtls_rsa_gen_key(mbedtls_pk_rsa(k), mbedtls_ctr_drbg_random, &g_drbg, 3072, 65537);
  mbedtls_pk_free(&k);
  return rc;
}
static int rsa_make_key() {
  mbedtls_pk_init(&rsa_key);
  int rc = mbedtls_pk_setup(&rsa_key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
  if (rc == 0) rc = mbedtls_rsa_gen_key(mbedtls_pk_rsa(rsa_key), mbedtls_ctr_drbg_random, &g_drbg, 3072, 65537);
  rsa_key_ready = (rc == 0);
  return rc;
}
static void rsa_free_key() {
  mbedtls_pk_free(&rsa_key);
  rsa_key_ready = false;
}
static int rsa_sign(const uint8_t* m, size_t len, uint8_t* sig, size_t* siglen) {
  uint8_t h[32];
  sha256(m, len, h);
  return mbedtls_pk_sign(&rsa_key, MBEDTLS_MD_SHA256, h, 32, sig, MAX_SIG_BYTES, siglen,
                         mbedtls_ctr_drbg_random, &g_drbg);
}
static int rsa_verify(const uint8_t* m, size_t len, const uint8_t* sig, size_t siglen) {
  uint8_t h[32];
  sha256(m, len, h);
  return mbedtls_pk_verify(&rsa_key, MBEDTLS_MD_SHA256, h, 32, sig, siglen);
}
static size_t rsa_sk_bytes() {                   // PKCS#1 DER of the private key
#if FOOTPRINT_BUILD
  return 0;
#else
  static uint8_t der[2400];
  if (!rsa_key_ready) return 0;
  int n = mbedtls_pk_write_key_der(&rsa_key, der, sizeof der);
  return n > 0 ? (size_t)n : 0;
#endif
}

#if ENABLE_LINK_TEST
static size_t rsa_export_pk(uint8_t* out, size_t max) {  // the modulus N
  if (max < 384 || !rsa_key_ready) return 0;
  if (mbedtls_rsa_export_raw(mbedtls_pk_rsa(rsa_key), out, 384, NULL, 0, NULL, 0, NULL, 0, NULL, 0) != 0) return 0;
  return 384;
}
#endif

// Public key on the wire: the 384-byte modulus (e = 65537 is fixed and not sent)
static const SigAlgorithm ALG_RSA3072 = {
  "RSA-3072", "mbedTLS 3.6 (hardware MPI + SHA)", "~128-bit classical", true, RSA_KEYGEN_RUNS,
  KAT_FN(rsa_kat), rsa_keygen_once, rsa_make_key, rsa_free_key, rsa_sign, rsa_verify, 384, rsa_sk_bytes,
  PK_EXPORT(rsa_export_pk) };
#endif

// ========================================================================================
// ML-DSA-44 / 65 / 87 (mldsa-native v1.0.0-beta2, portable C, MLD_CONFIG_REDUCE_RAM)
// Pure ML-DSA, empty context, hedged signing with the hardware random generator.
// ========================================================================================
static uint8_t ml_pk[MAX_PK_BYTES], ml_sk[MAX_SK_BYTES];

#define MLDSA_ADAPTER(L, CAT)                                                                    \
  [[maybe_unused]] static bool ml##L##_kat() {                                                                    \
    uint8_t seed[32], msg[32], zero[32], d[32];                                                  \
    const uint8_t pre[2] = {0, 0}; /* FIPS 204 M' prefix for an empty context */                 \
    size_t slen = 0;                                                                             \
    for (int i = 0; i < 32; i++) { seed[i] = i; msg[i] = 0x60 + i; zero[i] = 0; }                \
    if (DRONE_MLDSA##L##_keypair_internal(tmp_pk, tmp_sk, seed) != 0) return false;             \
    sha256(tmp_pk, DRONE_MLDSA##L##_PK_BYTES, d);                                                \
    if (memcmp(d, KAT_MLDSA##L##_PK_SHA256, 32) != 0) return false;                              \
    if (DRONE_MLDSA##L##_signature_internal(kat_sig, &slen, msg, 32, pre, 2, zero, tmp_sk, 0))   \
      return false;                                                                              \
    if (slen != KAT_MLDSA##L##_SIG_LEN) return false;                                            \
    sha256(kat_sig, slen, d);                                                                    \
    if (memcmp(d, KAT_MLDSA##L##_SIG_SHA256, 32) != 0) return false;                             \
    if (DRONE_MLDSA##L##_verify(kat_sig, slen, msg, 32, NULL, 0, tmp_pk) != 0) return false;     \
    kat_sig[7] ^= 0x01;                                                                          \
    if (DRONE_MLDSA##L##_verify(kat_sig, slen, msg, 32, NULL, 0, tmp_pk) == 0) return false;     \
    if (DRONE_MLDSA##L##_signature(kat_sig, &slen, msg, 32, NULL, 0, tmp_sk) != 0) return false; \
    return DRONE_MLDSA##L##_verify(kat_sig, slen, msg, 32, NULL, 0, tmp_pk) == 0;                \
  }                                                                                              \
  static int ml##L##_keygen_once() { return DRONE_MLDSA##L##_keypair(tmp_pk, tmp_sk); }          \
  static int ml##L##_make_key() { return DRONE_MLDSA##L##_keypair(ml_pk, ml_sk); }               \
  static void ml##L##_free_key() { memset(ml_sk, 0, sizeof ml_sk); }                             \
  static int ml##L##_sign(const uint8_t* m, size_t len, uint8_t* sig, size_t* siglen) {          \
    return DRONE_MLDSA##L##_signature(sig, siglen, m, len, NULL, 0, ml_sk);                      \
  }                                                                                              \
  static int ml##L##_verify(const uint8_t* m, size_t len, const uint8_t* sig, size_t siglen) {   \
    return DRONE_MLDSA##L##_verify(sig, siglen, m, len, NULL, 0, ml_pk);                         \
  }                                                                                              \
  static size_t ml##L##_sk_bytes() { return DRONE_MLDSA##L##_SK_BYTES; }                         \
  [[maybe_unused]] static size_t ml##L##_export_pk(uint8_t* out, size_t max) {                   \
    if (max < DRONE_MLDSA##L##_PK_BYTES) return 0;                                               \
    memcpy(out, ml_pk, DRONE_MLDSA##L##_PK_BYTES);                                               \
    return DRONE_MLDSA##L##_PK_BYTES;                                                            \
  }                                                                                              \
  static const SigAlgorithm ALG_MLDSA##L = {                                                     \
    "ML-DSA-" #L, "mldsa-native v1.0.0-beta2 (portable C, software SHAKE)", CAT, false,          \
    BENCH_RUNS, KAT_FN(ml##L##_kat), ml##L##_keygen_once, ml##L##_make_key, ml##L##_free_key,            \
    ml##L##_sign, ml##L##_verify, DRONE_MLDSA##L##_PK_BYTES, ml##L##_sk_bytes,                    \
    PK_EXPORT(ml##L##_export_pk) };

#if ENABLE_MLDSA44
MLDSA_ADAPTER(44, "NIST category 2")
#endif
#if ENABLE_MLDSA65
MLDSA_ADAPTER(65, "NIST category 3")
#endif
#if ENABLE_MLDSA87
MLDSA_ADAPTER(87, "NIST category 5")
#endif

// ----------------------------------------------------------------------------------------
// The list of algorithms (the trailing nullptr allows a build with none, for flash tests)
// ----------------------------------------------------------------------------------------
const SigAlgorithm* const ALGORITHMS[] = {
#if ENABLE_ED25519
  &ALG_ED25519,
#endif
#if ENABLE_ECDSA_P256
  &ALG_ECDSA_P256,
#endif
#if ENABLE_RSA3072
  &ALG_RSA3072,
#endif
#if ENABLE_MLDSA44
  &ALG_MLDSA44,
#endif
#if ENABLE_MLDSA65
  &ALG_MLDSA65,
#endif
#if ENABLE_MLDSA87
  &ALG_MLDSA87,
#endif
  nullptr
};
const int ALGORITHM_COUNT = (int)(sizeof(ALGORITHMS) / sizeof(ALGORITHMS[0])) - 1;
