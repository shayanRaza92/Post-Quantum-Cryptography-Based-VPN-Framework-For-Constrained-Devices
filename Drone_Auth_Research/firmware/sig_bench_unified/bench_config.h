// bench_config.h - settings for the unified signature benchmark (Step 1 / experiment E1).
#pragma once

// ---- How many times each operation is timed -----------------------------------------
// 1000 timed runs per operation gives stable p95/p99 values. A full run takes about
// 40-50 minutes. For a quick test of the setup, set BENCH_RUNS to 20 and RSA_KEYGEN_RUNS to 2.
#define BENCH_RUNS       1000  // key generation, signing and verifying (all algorithms)
#define RSA_KEYGEN_RUNS  30    // RSA-3072 key generation takes 4-30 s per key
#define WARMUP_RUNS      5      // untimed runs before each timed loop (caches, branch history)
#define REPEAT_RUNS      100    // Ed25519 is timed again at the very end to check run stability

// ---- Fixed test conditions --------------------------------------------------------------
#define MSG_SIZE         64     // bytes signed per run; every run signs a different message
#define CPU_MHZ          240    // the firmware sets and checks this clock
#define BENCH_CORE       1      // all measurements run on core 1
#define BENCH_PRIORITY   5      // above the Arduino loop task (priority 1)
#define STACK_BYTES_WANTED (96 * 1024) // task stack for every measurement task (ML-DSA-87 needs a lot)
#define RAW_PER_LINE     20     // raw samples printed per output line

// ---- Step 2 (send P): message size ------------------------------------------------------
#define E2_RUNS          100    // signatures and verifications timed per message size
#define E2_SIZES         {64, 256, 1024, 4096, 16384, 65536}   // message sizes in bytes
#define E2_STACK_MARGIN  8192   // extra stack on top of what an algorithm was measured to need
#define E2_SEARCH_STEP   64     // the largest-message search stops when it is this close (bytes)

// ---- Step 3 (send W): real Wi-Fi link to the laptop ground station --------------------
// 0 = Wi-Fi is not even built into the firmware (Steps 1 and 2 stay exactly as measured).
// 1 = Step 3 can run. Also set the Wi-Fi name and password in link_config.h.
#ifndef ENABLE_LINK_TEST
#define ENABLE_LINK_TEST 0
#endif

// ---- Step 5 (send T): signed MPU6050 telemetry ----------------------------------------
#define E5_SECONDS          10      // length of every run
#define E5_RATES            {10, 50, 100}   // sensor sample rates tested (samples per second)
#define E5_BATCH            10      // samples signed together in mode "sig10"
#define E5_INLINE_RATE      50      // rate for the simple-loop ("inline") runs
#define E5_BUFFER_MS        500     // unsigned samples kept at most (task); the oldest are dropped
#define E5_SAMPLER_PRIORITY 10      // sensor task: above the signing task (BENCH_PRIORITY)
#define E5_SIGN_STACK       (40 * 1024)     // stack of the task that signs (ML-DSA-87 needs ~23 KB)
#define E5_I2C_SDA          21      // MPU6050 SDA (ESP32duino: the pin marked SDA, next to AREF)
#define E5_I2C_SCL          22      // MPU6050 SCL (ESP32duino: the pin marked SCL)
#define E5_I2C_HZ           400000
#define E5_STR_(x) #x
#define E5_STR(x) E5_STR_(x)

// ---- Only for tools/flash_footprint.sh: leave out the test-only code -----------------
#ifndef FOOTPRINT_BUILD
#define FOOTPRINT_BUILD 0
#endif

// ---- Which algorithms are built in (1 = yes) --------------------------------------------
// Turning some off is only used to measure the flash cost of each algorithm on its own
// (tools/flash_footprint.sh). For the benchmark, leave all of them on.
#ifndef ENABLE_ED25519
#define ENABLE_ED25519 1
#endif
#ifndef ENABLE_ECDSA_P256
#define ENABLE_ECDSA_P256 1
#endif
#ifndef ENABLE_RSA3072
#define ENABLE_RSA3072 1
#endif
#ifndef ENABLE_MLDSA44
#define ENABLE_MLDSA44 1
#endif
#ifndef ENABLE_MLDSA65
#define ENABLE_MLDSA65 1
#endif
#ifndef ENABLE_MLDSA87
#define ENABLE_MLDSA87 1
#endif
