# Post-Quantum VPN Framework For Constrained Devices

A lightweight VPN framework connecting an ESP32 microcontroller to a laptop gateway.

---

## Repository Layout

* **`Non_PQC_VPN/`**: Classical cryptography baseline implementation (Ed25519 mutual authentication, allowlisting, TCP transport) and micro-benchmarks.
  * `esp32_client/`: ESP32 Arduino C++ firmware.
  * `laptop_server/`: Python gateway server.
  * `benchmarking/`: Performance tests for mutual authentication and key exchange algorithms.
  * `sequence_diagram.png`: Sequence diagram of the authentication handshake.

---

## Detailed Guide

For setup steps, code explanation, and the handshake sequence diagram, see:
* **[Non_PQC_VPN Documentation](Non_PQC_VPN/README.md)**
