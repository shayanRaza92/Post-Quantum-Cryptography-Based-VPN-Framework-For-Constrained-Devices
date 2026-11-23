# Step 2 (E2): message size and the largest message

Log: `payload_bench_20261124_020247.log`. Board: ESP32-D0WD rev 100, 2 cores, 240 MHz. Runs per size: 100. Sizes: 64 256 1024 4096 16384 65536 bytes. Git commit: `4f11a4a352ec`.


## Sign time by message size (median ms; p95 in brackets)

| Algorithm | 64 B | 256 B | 1,024 B | 4,096 B | 16,384 B | 65,536 B |
|---|---:|---:|---:|---:|---:|---:|
| Ed25519 | 9.50 (9.5) | 9.54 (9.5) | 9.64 (9.6) | 10.05 (10.1) | 11.68 (11.7) | 18.23 (18.2) |
| ECDSA-P256 | 162.16 (162.5) | 162.17 (162.5) | 162.22 (162.6) | 162.55 (162.8) | 163.68 (164.0) | 168.19 (168.4) |
| RSA-3072 | 374.33 (376.3) | 374.26 (376.7) | 374.28 (377.0) | 374.69 (376.5) | 375.62 (378.3) | 380.39 (383.0) |
| ML-DSA-44 | 53.79 (201.0) | 56.04 (249.5) | 53.85 (186.2) | 69.08 (181.5) | 77.79 (216.8) | 100.57 (224.1) |
| ML-DSA-65 | 84.76 (305.1) | 90.36 (369.3) | 107.72 (364.2) | 101.12 (380.2) | 122.21 (344.9) | 133.38 (365.5) |
| ML-DSA-87 | 119.33 (408.3) | 138.33 (495.7) | 140.06 (529.5) | 140.70 (446.9) | 149.71 (482.3) | 186.38 (502.0) |

## Verify time by message size (median ms; p95 in brackets)

| Algorithm | 64 B | 256 B | 1,024 B | 4,096 B | 16,384 B | 65,536 B |
|---|---:|---:|---:|---:|---:|---:|
| Ed25519 | 19.79 (20.0) | 19.78 (20.0) | 19.87 (20.1) | 20.07 (20.3) | 20.86 (21.1) | 24.20 (24.4) |
| ECDSA-P256 | 320.84 (321.1) | 320.86 (321.2) | 320.97 (321.3) | 321.25 (321.6) | 322.36 (322.6) | 326.88 (327.2) |
| RSA-3072 | 1.81 (1.8) | 1.83 (1.8) | 1.90 (1.9) | 2.18 (2.2) | 3.30 (3.3) | 7.81 (7.8) |
| ML-DSA-44 | 13.43 (13.4) | 13.61 (13.6) | 14.16 (14.2) | 16.19 (16.2) | 24.46 (24.5) | 57.73 (57.7) |
| ML-DSA-65 | 22.48 (22.5) | 22.65 (22.7) | 23.20 (23.2) | 25.23 (25.2) | 33.51 (33.5) | 66.77 (66.8) |
| ML-DSA-87 | 38.52 (38.5) | 38.72 (38.7) | 39.25 (39.3) | 41.29 (41.3) | 49.56 (49.6) | 82.83 (82.8) |

## Cost of a longer message (straight-line fit on the medians)

| Algorithm | Sign: fixed part (ms) | Sign: per KB (ms) | Verify: fixed part (ms) | Verify: per KB (ms) | Fit R² (sign / verify) |
|---|---:|---:|---:|---:|---:|
| Ed25519 | 9.50 | 0.1364 | 19.78 | 0.0690 | 1.000 / 1.000 |
| ECDSA-P256 | 162.15 | 0.0945 | 320.86 | 0.0941 | 1.000 / 1.000 |
| RSA-3072 | 374.23 | 0.0957 | 1.80 | 0.0939 | 0.999 / 1.000 |
| ML-DSA-44 | 58.69 | 0.6917 | 13.42 | 0.6921 | 0.888 / 1.000 |
| ML-DSA-65 | 97.86 | 0.6141 | 22.46 | 0.6921 | 0.687 / 1.000 |
| ML-DSA-87 | 133.88 | 0.8346 | 38.52 | 0.6923 | 0.887 / 1.000 |

## Largest message the ESP32 could sign (measured)

| Algorithm | Largest message (B) | Next size failed because | Stack given (B) | Free heap at start (B) | Largest free block (B) | Sign time at largest (ms) |
|---|---:|---|---:|---:|---:|---:|
| Ed25519 | 110,536 | message buffer did not fit | 12,288 | 274,192 | 110,580 | 24.2 |
| ECDSA-P256 | 110,536 | message buffer did not fit | 11,264 | 273,752 | 110,580 | 172.2 |
| RSA-3072 | 110,536 | message buffer did not fit | 10,240 | 269,252 | 110,580 | 385.3 |
| ML-DSA-44 | 110,536 | message buffer did not fit | 23,552 | 274,084 | 110,580 | 147.6 |
| ML-DSA-65 | 110,536 | message buffer did not fit | 28,672 | 274,084 | 110,580 | 443.8 |
| ML-DSA-87 | 110,536 | message buffer did not fit | 32,768 | 274,084 | 110,580 | 210.4 |

## Largest message that can be signed within a time budget (bytes; 0 = not even a tiny message)

| Algorithm | 20 ms (median) | 20 ms (p95) | 50 ms (median) | 50 ms (p95) | 100 ms (median) | 100 ms (p95) |
|---|---:|---:|---:|---:|---:|---:|
| Ed25519 | 79,464 | 79,400 | 110,536 | 110,536 | 110,536 | 110,536 |
| ECDSA-P256 | 0 | 0 | 0 | 0 | 0 | 0 |
| RSA-3072 | 0 | 0 | 0 | 0 | 0 | 0 |
| ML-DSA-44 | 0 | 0 | 0 | 0 | 67,028 | 0 |
| ML-DSA-65 | 0 | 0 | 0 | 0 | 0 | 0 |
| ML-DSA-87 | 0 | 0 | 0 | 0 | 0 | 0 |

Median: the typical signature fits. p95: 95% of signatures fit. Model: time for a 64-byte message (Step 1, 1,000 runs: sig_bench_20261124_010231) + per-KB cost (ML-DSA: from verifying, the same hashing work). Capped at the largest message that fits in RAM.

## Data that fits next to the signature in ONE frame (calculated, bytes)

| Algorithm | Signature | MAVLink 2 message (255 B) | ESP-NOW v1 (250 B) | ESP-NOW v2 (1470 B) | TCP segment (ESP32) (1436 B) | Frames for the signature alone (MAVLink 2) |
|---|---:|---:|---:|---:|---:|---:|
| Ed25519 | 64 | 191 | 186 | 1,406 | 1,372 | 1 |
| ECDSA-P256 | 72 | 183 | 178 | 1,398 | 1,364 | 1 |
| RSA-3072 | 384 | 0 | 0 | 1,086 | 1,052 | 2 |
| ML-DSA-44 | 2,420 | 0 | 0 | 0 | 0 | 10 |
| ML-DSA-65 | 3,309 | 0 | 0 | 0 | 0 | 13 |
| ML-DSA-87 | 4,627 | 0 | 0 | 0 | 0 | 19 |

0 = the signature alone does not fit in one frame, so the message must be split. Frame counts are a minimum (no extra headers for splitting are counted).

## Stack given to each algorithm in Step 2

| Algorithm | Measured need (B) | Given (need + margin) (B) |
|---|---:|---:|
| Ed25519 | 3,684 | 12,288 |
| ECDSA-P256 | 2,264 | 11,264 |
| RSA-3072 | 1,604 | 10,240 |
| ML-DSA-44 | 15,348 | 23,552 |
| ML-DSA-65 | 19,556 | 28,672 |
| ML-DSA-87 | 23,652 | 32,768 |

Known-answer tests: Ed25519 PASS, ECDSA-P256 PASS, RSA-3072 PASS, ML-DSA-44 PASS, ML-DSA-65 PASS, ML-DSA-87 PASS. Failed operations: 0.
