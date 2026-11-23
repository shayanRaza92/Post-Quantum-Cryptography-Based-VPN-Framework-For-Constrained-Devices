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
