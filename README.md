# Post-Quantum VPN Framework For Constrained Devices

A lightweight VPN framework for ESP32 microcontrollers. Each project uses the same 4-message mutual-authentication handshake with an ephemeral key exchange, HKDF-SHA256 key derivation and HMAC key confirmation. A classical baseline (Ed25519 + X25519) is compared with a fully post-quantum version (ML-DSA-44, NIST FIPS 204 + ML-KEM-512, NIST FIPS 203, with an AES-256-GCM tunnel).

---

## Repository Layout

```
FYP/
├── Non_PQC_VPN/                  Classical baseline: laptop gateway + ESP32 clients (AES-256-GCM tunnel)
│   ├── esp32_client/             ESP32 firmware (Arduino IDE)
│   ├── laptop_server/            Python gateway
│   ├── benchmarking/             Signature + key-exchange benchmarks (graphs, screenshots, report)
│   ├── screenshots/              Photos of the three-ESP32 demo
│   └── sequence_diagram.png      Handshake + AES-256-GCM tunnel diagram
├── Non_PQC_VPN_ESP32_Gateway/    Classical VPN with NO laptop: one ESP32 is the gateway
│   ├── esp32_gateway/            Gateway firmware (creates its own Wi-Fi network)
│   ├── esp32_client/             Client firmware set up for the ESP32 gateway
│   └── sequence_diagram.png      Wi-Fi join + handshake + AES-256-GCM tunnel diagram
├── Non_PQC_VPN_DHT22/            DHT22 temperature readings over the classical VPN (AES-256-GCM tunnel)
│   ├── esp32_dht22_client/       ESP32 firmware with the DHT22 sensor
│   ├── laptop_server/            Python gateway that decrypts and logs readings
│   ├── screenshots/              Test-run screenshots
│   └── sequence_diagram.png      Handshake + encrypted telemetry diagram
└── PQC_VPN/                      Fully post-quantum VPN: ML-DSA-44 + ML-KEM-512 + AES-256-GCM tunnel
    ├── esp32_client/             ESP32 firmware (needs the two libraries below)
    ├── laptop_server/            Python gateway (+ build_native_libs.sh, requirements.txt)
    ├── arduino_libraries/        MLDSA44 + MLKEM512 Arduino libraries (mldsa-native / mlkem-native)
    ├── benchmarking/             Ed25519 vs. ML-DSA-44 benchmark
    └── sequence_diagram.png      ML-DSA-44 + ML-KEM-512 handshake + AES-256-GCM tunnel diagram
```

Each project folder is **self-contained**. The Arduino IDE only compiles files inside a sketch's own folder, so every ESP32 sketch keeps its own copy of the shared client code (`AuthManager`, `DeviceIdentity`). If you change the handshake in one project, update the copies in the others too.

---

## Documentation

* **[Non_PQC_VPN](Non_PQC_VPN/README.md)**: classical protocol, handshake walkthrough, setup, performance summary
* **[Non_PQC_VPN_ESP32_Gateway](Non_PQC_VPN_ESP32_Gateway/README.md)**: ESP32-to-ESP32 setup, gateway Serial commands, multi-device behaviour
* **[Non_PQC_VPN_DHT22](Non_PQC_VPN_DHT22/README.md)**: sensor wiring, encrypted record layer, telemetry log
* **[PQC_VPN](PQC_VPN/README.md)**: ML-DSA-44 + ML-KEM-512 handshake, AES-256-GCM tunnel, building the native libraries, multi-device behaviour
* Benchmarks: [signatures](Non_PQC_VPN/benchmarking/mutual_auth_benchmark/README.md) · [key exchange](Non_PQC_VPN/benchmarking/key_exchange_benchmark/README.md) · [Ed25519 vs. ML-DSA-44](PQC_VPN/benchmarking/mutual_auth_benchmark/README.md)
