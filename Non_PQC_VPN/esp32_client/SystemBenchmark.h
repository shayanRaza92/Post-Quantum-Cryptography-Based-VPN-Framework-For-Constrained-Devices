#ifndef SYSTEM_BENCHMARK_H
#define SYSTEM_BENCHMARK_H

// ============================================================================
// End-to-end system benchmark of the whole VPN on the ESP32 (identical file in
// Non_PQC_VPN and PQC_VPN, so both VPNs are measured the same way).
// Enabled with BENCHMARK_MODE 1 in config.h; see benchmarking/system_benchmark/README.md.
//
// Measures: AES-256-GCM known-answer test, handshake time, per-message AES-GCM
// cost, added round-trip latency (VPN vs. plain TCP), sustained throughput,
// rekey time, CPU load at the normal ping rate, peak RAM, stack and flash.
// Results are printed as a table and as "BENCH,..." CSV lines for copying.
// ============================================================================
void runSystemBenchmark();

#endif // SYSTEM_BENCHMARK_H
