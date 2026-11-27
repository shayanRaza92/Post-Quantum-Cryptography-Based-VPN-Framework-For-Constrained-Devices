# LAPTOP benchmark: 3 classical runs, 3 post-quantum runs

Each cell: mean over the runs +- 95% confidence interval (Student t). For KPIs that are a
median or p95, each run contributes its own median / p95. 1 KB = 1,024 bytes.

| KPI | Unit | Classical: per run | Classical: mean +- 95% CI | Post-quantum: per run | Post-quantum: mean +- 95% CI |
|---|---|---|---|---|---|
| L2 Gateway encrypt, 1,023 B, median | us | 7.30, 7.10, 7.10 | 7.17 +- 0.29 | 7.10, 7.20, 7.00 | 7.10 +- 0.25 |
| L2 Gateway decrypt, 1,023 B, median | us | 7.70, 7.50, 7.60 | 7.60 +- 0.25 | 7.70, 7.60, 7.40 | 7.57 +- 0.38 |
| L3 Full handshake on the laptop, median | ms | 1.28, 1.17, 1.16 | 1.20 +- 0.16 | 2.25, 2.32, 2.35 | 2.31 +- 0.12 |
| L3 Full handshake on the laptop, p95 | ms | 1.50, 1.26, 1.32 | 1.36 +- 0.31 | 3.43, 3.46, 3.78 | 3.55 +- 0.48 |
| L4 Rekey on the laptop, median | ms | 0.24, 0.43, 0.21 | 0.29 +- 0.29 | 0.32, 0.15, 0.16 | 0.21 +- 0.24 |
| L5 10 devices at once: accepted |  | 10, 10, 10 | 10 +- 0 | 10, 8, 10 | 9.3 +- 2.9 |
| L5 40 devices at once: accepted |  | 40, 40, 40 | 40 +- 0 | 33, 34, 33 | 33.3 +- 1.4 |
| L6 1 device: messages per second | msg/s | 15,577, 24,491, 26,735 | 22,268 +- 14,662 | 26,307, 26,185, 23,537 | 25,343 +- 3,888 |
| L6 10 devices: messages per second | msg/s | 11,999, 11,939, 11,757 | 11,898 +- 312.9 | 12,361, 12,204, 11,952 | 12,172 +- 512.8 |
| L6 40 devices: messages per second | msg/s | 11,633, 11,605, 11,645 | 11,628 +- 50.6 | 12,110, 11,509, 9,676 | 11,098 +- 3,151 |
| L6 40 devices: reply time, median | ms | 3.25, 3.22, 3.23 | 3.23 +- 0.03 | 3.11, 3.28, 3.75 | 3.38 +- 0.82 |
| L6 40 devices: sessions dropped |  | 0, 0, 0 | 0 +- 0 | 0, 0, 0 | 0 +- 0 |

Runs used:
* classical: ../../../Non_PQC_VPN/benchmarking/system_benchmark/results/laptop_gateway_results_run1.csv
* classical: ../../../Non_PQC_VPN/benchmarking/system_benchmark/results/laptop_gateway_results_run2.csv
* classical: ../../../Non_PQC_VPN/benchmarking/system_benchmark/results/laptop_gateway_results_run3.csv
* post-quantum: results/laptop_gateway_results_run1.csv
* post-quantum: results/laptop_gateway_results_run2.csv
* post-quantum: results/laptop_gateway_results_run3.csv
