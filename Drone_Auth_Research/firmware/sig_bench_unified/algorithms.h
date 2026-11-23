// algorithms.h - every signature algorithm behind the same small interface, so the
// benchmark harness times all of them in exactly the same way.
#pragma once
#include <stddef.h>
#include <stdint.h>

// Biggest sizes over all algorithms (ML-DSA-87), for the shared buffers
#define MAX_PK_BYTES  2592
#define MAX_SK_BYTES  4896
#define MAX_SIG_BYTES 4627

struct SigAlgorithm {
  const char* name;            // short name used in the output, e.g. "MLDSA65"
  const char* library;         // which library does the work
  const char* security;        // security level, e.g. "~128-bit classical" or "NIST category 3"
  bool slow_keygen;            // true: key generation is timed with esp_timer (can exceed 17 s)
  int keygen_runs;             // how many key generations are timed

  bool (*kat)();               // known-answer test; true = pass
  int (*keygen_once)();        // one complete, throw-away key generation (timed)
  int (*make_bench_key)();     // the key used for all sign/verify runs
  void (*free_bench_key)();
  int (*sign)(const uint8_t* msg, size_t len, uint8_t* sig, size_t* siglen);
  int (*verify)(const uint8_t* msg, size_t len, const uint8_t* sig, size_t siglen);

  size_t pk_bytes;             // public key as sent over the network (raw encoding)
  size_t (*sk_bytes)();        // secret key as stored (RSA: PKCS#1 DER, measured)
};

// Set up shared state (random generator for mbedTLS, libsodium). Returns false on error.
bool algorithms_init();

// The algorithms that are built in, in the order they are measured.
extern const SigAlgorithm* const ALGORITHMS[];
extern const int ALGORITHM_COUNT;

// mbedTLS heap tracking (counts every allocation mbedTLS makes while active)
void heap_track_start();
size_t heap_track_stop();      // returns the peak number of bytes allocated

// SHA-256 helper (mbedTLS) used by the known-answer tests
void sha256(const uint8_t* in, size_t len, uint8_t out[32]);
