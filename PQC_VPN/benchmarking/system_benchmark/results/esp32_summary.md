# ESP32 benchmark: 3 classical runs, 3 post-quantum runs

Each cell: mean over the runs +- 95% confidence interval (Student t). For KPIs that are a
median or p95, each run contributes its own median / p95. 1 KB = 1,024 bytes.

| KPI | Unit | Classical: per run | Classical: mean +- 95% CI | Post-quantum: per run | Post-quantum: mean +- 95% CI |
|---|---|---|---|---|---|
| B1 AES-256-GCM enc+dec, 64 B message | ms/KB | 2.37, 2.37, 2.37 | 2.37 +- 0.00 | 2.71, 2.71, 2.71 | 2.71 +- 0.01 |
| B1 AES-256-GCM enc+dec, 1,023 B message | ms/KB | 1.21, 1.21, 1.21 | 1.21 +- 0.00 | 1.23, 1.23, 1.23 | 1.23 +- 0.00 |
| B2 Handshake (MSG 1-4), median | ms | 85.5, 84.1, 87.4 | 85.7 +- 4.17 | 184.0, 187.2, 191.7 | 187.6 +- 9.62 |
| B2 Handshake (MSG 1-4), p95 | ms | 129.9, 157.8, 147.2 | 144.9 +- 35.0 | 341.2, 309.3, 317.1 | 322.5 +- 41.3 |
| B2 TCP connect, median | ms | 15.3, 13.7, 21.2 | 16.7 +- 9.88 | 14.9, 12.9, 13.8 | 13.9 +- 2.46 |
| B2 Failed handshakes (of 100) |  | 0, 0, 0 | 0 +- 0 | 0, 0, 0 | 0 +- 0 |
| B2 Handshake bytes on the wire | B | 346, 346, 346 | 346 +- 0 | 6,562, 6,562, 6,562 | 6,562 +- 0 |
| B3 Added round-trip delay, 64 B (median VPN - median plain) | ms | 0.36, -0.10, 0.52 | 0.26 +- 0.80 | 0.77, 0.99, 0.76 | 0.84 +- 0.32 |
| B3 Added round-trip delay, 1,023 B (median VPN - median plain) | ms | 1.68, -1.60, 2.00 | 0.69 +- 4.95 | 0.74, 1.51, 1.58 | 1.28 +- 1.15 |
| B4a Maximum goodput (application data) | kbps | 1,784, 1,301, 1,638 | 1,575 +- 615.3 | 1,689, 1,758, 1,443 | 1,630 +- 411.4 |
| B4b Delivered at 102.4 kbps offered | kbps | 102.4, 102.4, 102.4 | 102.4 +- 0.00 | 102.4, 102.4, 102.4 | 102.4 +- 0.00 |
| B4b Reply time during the 102.4 kbps stream, median | ms | 9.37, 10.6, 10.4 | 10.1 +- 1.59 | 9.59, 8.62, 9.58 | 9.27 +- 1.39 |
| B4b Reply time during the 102.4 kbps stream, p95 | ms | 32.0, 41.7, 30.4 | 34.7 +- 15.2 | 18.0, 16.2, 16.3 | 16.8 +- 2.42 |
| B5 Rekey, median | ms | 39.4, 36.1, 37.1 | 37.5 +- 4.16 | 22.2, 23.0, 22.4 | 22.5 +- 1.12 |
| B5 Rekey, p95 | ms | 46.7, 48.7, 114.0 | 69.8 +- 95.1 | 28.3, 24.9, 25.8 | 26.3 +- 4.39 |
| B6 CPU, tunnel open and quiet | % | 0.95, 0.97, 0.95 | 0.96 +- 0.02 | 0.95, 0.96, 0.95 | 0.96 +- 0.02 |
| B6 CPU, one ping every 1.5 s | % | 1.13, 1.14, 1.15 | 1.14 +- 0.03 | 1.14, 1.14, 1.18 | 1.15 +- 0.06 |
| B6 CPU, 102.4 kbps stream | % | 8.96, 8.93, 8.87 | 8.92 +- 0.11 | 9.41, 9.35, 9.41 | 9.39 +- 0.08 |
| B7 Peak heap used | KB | 123.4, 130.6, 126.2 | 126.7 +- 9.03 | 190.5, 188.9, 189.5 | 189.7 +- 1.99 |
| B7 Heap still free after the run | KB | 178.6, 178.7, 178.5 | 178.6 +- 0.26 | 86.7, 86.9, 86.9 | 86.9 +- 0.28 |
| B7 Task stack never used | KB | 3.28, 3.28, 3.28 | 3.28 +- 0.00 | 48.2, 48.2, 48.2 | 48.2 +- 0.00 |
| B7 Program size (benchmark build) | KB | 1,021, 1,021, 1,021 | 1,021 +- 0.00 | 1,033, 1,033, 1,033 | 1,033 +- 0.00 |

Runs used:
* classical: ../../../Non_PQC_VPN/benchmarking/system_benchmark/results/esp32_results_run1.csv
* classical: ../../../Non_PQC_VPN/benchmarking/system_benchmark/results/esp32_results_run2.csv
* classical: ../../../Non_PQC_VPN/benchmarking/system_benchmark/results/esp32_results_run3.csv
* post-quantum: results/esp32_results_run1.csv
* post-quantum: results/esp32_results_run2.csv
* post-quantum: results/esp32_results_run3.csv
