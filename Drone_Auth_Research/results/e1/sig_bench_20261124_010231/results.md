# Step 1 (E1): signature algorithms on the ESP32

Log: `sig_bench_20261124_010231.log`. Board: ESP32-D0WD rev 100, 2 cores, 240 MHz. ESP-IDF v5.5.5, mbedTLS 3.6.6, libsodium 1.0.21, mldsa-native v1.0.0-beta2. Runs: 1000 (RSA keygen 30, warm-up 5, repeat check 100). Message: 64 bytes. Git commit: `78016cca5f0d` (with uncommitted changes).


## Keygen time (ms)

| Algorithm | n | Median [95% CI] | Mean | p95 | p99 | Max | Std | CV % |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Ed25519 | 1000 | 8.020 [8.020, 8.020] | 8.021 | 8.026 | 8.029 | 8.030 | 0.003 | 0.0 |
| ECDSA-P256 | 1000 | 145.981 [145.968, 145.989] | 145.986 | 146.220 | 146.307 | 146.388 | 0.141 | 0.1 |
| RSA-3072 | 30 | 12,929.419 [10,949.449, 15,698.606] | 14,814.211 | 28,277.255 | 46,896.898 | 46,896.898 | 9,013.990 | 60.8 |
| ML-DSA-44 | 1000 | 13.055 [13.055, 13.055] | 13.018 | 13.057 | 13.057 | 13.058 | 0.113 | 0.9 |
| ML-DSA-65 | 1000 | 22.534 [22.533, 22.534] | 22.534 | 22.538 | 22.540 | 22.544 | 0.003 | 0.0 |
| ML-DSA-87 | 1000 | 39.008 [39.008, 39.008] | 38.942 | 39.009 | 39.009 | 39.011 | 0.154 | 0.4 |

## Sign time (ms)

| Algorithm | n | Median [95% CI] | Mean | p95 | p99 | Max | Std | CV % |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Ed25519 | 1000 | 9.426 [9.426, 9.427] | 9.426 | 9.435 | 9.436 | 9.443 | 0.005 | 0.1 |
| ECDSA-P256 | 1000 | 158.176 [158.156, 158.193] | 158.193 | 158.561 | 158.686 | 158.883 | 0.216 | 0.1 |
| RSA-3072 | 1000 | 373.437 [373.349, 373.527] | 373.452 | 375.632 | 376.504 | 377.765 | 1.364 | 0.4 |
| ML-DSA-44 | 1000 | 54.738 [53.584, 57.643] | 74.610 | 198.381 | 289.507 | 486.003 | 61.004 | 81.8 |
| ML-DSA-65 | 1000 | 103.610 [87.547, 109.253] | 145.637 | 419.663 | 681.148 | 1,110.777 | 137.148 | 94.2 |
| ML-DSA-87 | 1000 | 137.956 [133.038, 141.418] | 185.409 | 525.293 | 769.463 | 1,170.079 | 161.905 | 87.3 |

## Verify time (ms)

| Algorithm | n | Median [95% CI] | Mean | p95 | p99 | Max | Std | CV % |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Ed25519 | 1000 | 19.793 [19.782, 19.805] | 19.789 | 20.054 | 20.140 | 20.225 | 0.165 | 0.8 |
| ECDSA-P256 | 1000 | 313.071 [313.059, 313.090] | 313.069 | 313.396 | 313.507 | 313.628 | 0.195 | 0.1 |
| RSA-3072 | 1000 | 1.812 [1.811, 1.814] | 1.813 | 1.839 | 1.848 | 1.866 | 0.015 | 0.8 |
| ML-DSA-44 | 1000 | 13.435 [13.435, 13.435] | 13.434 | 13.436 | 13.436 | 13.437 | 0.002 | 0.0 |
| ML-DSA-65 | 1000 | 22.477 [22.475, 22.477] | 22.476 | 22.479 | 22.479 | 22.479 | 0.002 | 0.0 |
| ML-DSA-87 | 1000 | 38.757 [38.757, 38.757] | 38.756 | 38.758 | 38.759 | 38.759 | 0.002 | 0.0 |

## Sign + verify (one authentication, medians, ms)

| Algorithm | Sign | Verify | Sum |
|---|---:|---:|---:|
| Ed25519 | 9.426 | 19.793 | 29.219 |
| ECDSA-P256 | 158.176 | 313.071 | 471.247 |
| RSA-3072 | 373.437 | 1.812 | 375.249 |
| ML-DSA-44 | 54.738 | 13.435 | 68.173 |
| ML-DSA-65 | 103.610 | 22.477 | 126.087 |
| ML-DSA-87 | 137.956 | 38.757 | 176.713 |

## Sizes (bytes)

| Algorithm | Public key | Secret key | Signature |
|---|---:|---:|---:|
| Ed25519 | 32 | 64 | 64 |
| ECDSA-P256 | 65 | 32 | 69-72 (mean 71.0) |
| RSA-3072 | 384 | 1,767 | 384 |
| ML-DSA-44 | 1,312 | 2,560 | 2420 |
| ML-DSA-65 | 1,952 | 4,032 | 3309 |
| ML-DSA-87 | 2,592 | 4,896 | 4627 |

## Memory (bytes)

| Algorithm | Stack keygen | Stack sign | Stack verify | Heap keygen | Heap sign | Heap verify |
|---|---:|---:|---:|---:|---:|---:|
| Ed25519 | 1,072 | 1,504 | 3,344 | 0 | 0 | 0 |
| ECDSA-P256 | 1,488 | 2,032 | 1,568 | 2,680 | 2,952 | 3,108 |
| RSA-3072 | 1,732 | 1,120 | 692 | 4,576 | 7,932 | 1,920 |
| ML-DSA-44 | 13,408 | 14,960 | 11,280 | 0 | 0 | 0 |
| ML-DSA-65 | 16,480 | 19,168 | 12,368 | 0 | 0 | 0 |
| ML-DSA-87 | 20,576 | 23,264 | 14,672 | 0 | 0 | 0 |

## ML-DSA levels compared with ML-DSA-44 (ratio of medians)

| Level | Keygen | Sign | Verify | Signature size | Public key size |
|---|---:|---:|---:|---:|---:|
| ML-DSA-44 | 1.00x | 1.00x | 1.00x | 1.00x | 1.00x |
| ML-DSA-65 | 1.73x | 1.89x | 1.67x | 1.37x | 1.49x |
| ML-DSA-87 | 2.99x | 2.52x | 2.88x | 1.91x | 1.98x |

## Checks

| Algorithm | Known-answer test | Failed operations | Heap change after run (B) |
|---|---|---:|---:|
| Ed25519 | PASS | 0 | -44 |
| ECDSA-P256 | PASS | 0 | -156 |
| RSA-3072 | PASS | 0 | 0 |
| ML-DSA-44 | PASS | 0 | -44 |
| ML-DSA-65 | PASS | 0 | -44 |
| ML-DSA-87 | PASS | 0 | -44 |

Stack meter check: a function using a 16384-byte array was measured as 16,196 bytes.

Heap change after run: a few dozen bytes once per algorithm is set-up memory of the system (it does not grow with the number of runs), not a leak.

Stability: Ed25519 sign median 9.426 ms at the start, 9.437 ms at the end (+0.11%).

Device summary vs recomputed medians: all match.
