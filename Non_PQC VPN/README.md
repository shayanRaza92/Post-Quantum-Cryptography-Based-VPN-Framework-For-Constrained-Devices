# Non-PQC VPN: Classical Cryptography Baseline

This directory contains the classical, non-quantum-resistant VPN implementation and benchmarking milestone for the ESP32 embedded client and laptop gateway.

## Deliverables Overview

### Deliverable 1: TCP Transport Layer
* Directory: `delivarable1_tcp_transport/`
* Establishes a reliable TCP client-server socket connection over local Wi-Fi between the ESP32 and the laptop gateway on port 9000.

### Deliverable 2: Mutual Authentication
* Directory: `deliverable2_Mutual Authentication/`
* Implements asymmetric mutual authentication using 64-byte Ed25519 digital signatures.
* Sub-components:
  * `step2_mutual_auth/`: End-to-end 3-way challenge-response handshake implementation.
  * `Mutual_Authentication algorithms benchmark/`: Benchmarks and selection data evaluating Ed25519, ECDSA P-256, and RSA-3072.
    * `Phase A Isolated Benchmark/`: Standalone Arduino benchmark sketch (`Phase_A_Isolated_Benchmark.ino`) and compiled reference documentation (`benchmark_report.pdf`).
