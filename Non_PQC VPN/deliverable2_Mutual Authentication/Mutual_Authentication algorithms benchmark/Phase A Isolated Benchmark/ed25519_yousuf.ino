// ESP32 Ed25519 Micro-Benchmark (Phase A: Isolated)

#include <sodium.h>

#define FAST_RUNS 100
#define MSG_SIZE 64
#define CPU_SPEED 240

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

static inline uint32_t get_cycles() {
  uint32_t cycles;
  __asm__ __volatile__("rsr %0, ccount" : "=a"(cycles));
  return cycles;
}

uint32_t get_average(uint32_t *times, int count) {
  uint64_t sum = 0;
  for (int i = 0; i < count; i++) {
    sum += times[i];
  }
  return (uint32_t)(sum / count);
}

void test_ed25519() {
  Serial.println("\nEd25519 (Curve25519) benchmark");

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
    // 1. Key generation
    uint32_t start = get_cycles();
    int keygen_result = crypto_sign_keypair(public_key, private_key);
    time_keygen[i] = get_cycles() - start;

    if (keygen_result != 0) {
      Serial.println("Error: Ed25519 key generation failed.");
      return;
    }

    // Approximate heap-use measurement
    uint32_t used = heap_before - ESP.getFreeHeap();
    if (used > peak_heap) {
      peak_heap = used;
    }

    // 2. Message signing
    start = get_cycles();
    int sign_result = crypto_sign_detached(signature, &sig_length, test_message,
                                           MSG_SIZE, private_key);
    time_sign[i] = get_cycles() - start;

    if (sign_result != 0) {
      Serial.println("Error: Ed25519 signing failed.");
      return;
    }

    // 3. Signature verification
    start = get_cycles();
    int verify_result = crypto_sign_verify_detached(signature, test_message,
                                                    MSG_SIZE, public_key);
    time_verify[i] = get_cycles() - start;

    if (verify_result != 0) {
      Serial.println("Error: Ed25519 signature verification failed.");
      return;
    }
  }

  kpi_ed25519.keygen_cycles = get_average(time_keygen, FAST_RUNS);
  kpi_ed25519.sign_cycles = get_average(time_sign, FAST_RUNS);
  kpi_ed25519.verify_cycles = get_average(time_verify, FAST_RUNS);
  kpi_ed25519.total_cycles =
      kpi_ed25519.keygen_cycles + kpi_ed25519.sign_cycles;

  // Convert cycles to milliseconds, assuming CPU_SPEED MHz.
  kpi_ed25519.keygen_ms =
      (float)kpi_ed25519.keygen_cycles / (CPU_SPEED * 1000.0f);
  kpi_ed25519.sign_ms = (float)kpi_ed25519.sign_cycles / (CPU_SPEED * 1000.0f);
  kpi_ed25519.verify_ms =
      (float)kpi_ed25519.verify_cycles / (CPU_SPEED * 1000.0f);
  kpi_ed25519.total_ms = kpi_ed25519.keygen_ms + kpi_ed25519.sign_ms;

  kpi_ed25519.pubkey_bytes = crypto_sign_PUBLICKEYBYTES;
  kpi_ed25519.sig_bytes = crypto_sign_BYTES;
  kpi_ed25519.peak_heap_bytes = peak_heap;

  Serial.printf("  SIG-1 Key Generation Latency   : %9u cycles | %7.2f ms\n",
                kpi_ed25519.keygen_cycles, kpi_ed25519.keygen_ms);
  Serial.printf("  SIG-2 Public Key Wire Size     : %u bytes\n",
                kpi_ed25519.pubkey_bytes);
  Serial.printf("  SIG-3 Message Signing Latency  : %9u cycles | %7.2f ms\n",
                kpi_ed25519.sign_cycles, kpi_ed25519.sign_ms);
  Serial.printf("  SIG-4 Signature Wire Size      : %u bytes\n",
                kpi_ed25519.sig_bytes);
  Serial.printf("  SIG-5 Verification Latency     : %9u cycles | %7.2f ms\n",
                kpi_ed25519.verify_cycles, kpi_ed25519.verify_ms);
  Serial.printf("  SIG-6 Total Client Sign Time   : %9u cycles | %7.2f ms\n",
                kpi_ed25519.total_cycles, kpi_ed25519.total_ms);
  Serial.printf("  SIG-7 Approx. Heap Change      : %u bytes\n",
                kpi_ed25519.peak_heap_bytes);
  Serial.println("\nEd25519 benchmark completed.");
}

void setup() {
  Serial.begin(115200);
  delay(2000);

  Serial.println("\n==============================================");
  Serial.println("ESP32 Ed25519 Micro-Benchmark (Phase A)");
  Serial.printf("Runs: %d | Assumed CPU: %d MHz | Free heap: %u bytes\n",
                FAST_RUNS, CPU_SPEED, ESP.getFreeHeap());
  Serial.println("==============================================");

  if (sodium_init() < 0) {
    Serial.println("Error: sodium_init() failed.");
    return;
  }

  randombytes_buf(test_message, MSG_SIZE);
  test_ed25519();
}

void loop() { delay(10000); }
