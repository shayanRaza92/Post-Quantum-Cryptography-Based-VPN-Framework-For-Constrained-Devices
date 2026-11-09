# Post-Quantum VPN for Small IoT Devices (ESP32)

This is our final year project. We built a small VPN for ESP32 boards, in two versions:

* a **classical** version, using the algorithms most VPNs use today (Ed25519 and X25519), and
* a **post-quantum** version, using the new NIST algorithms that are designed to resist quantum computers (ML-DSA-44 and ML-KEM-512).

Both versions work the same way. The ESP32 and the gateway first prove to each other who they are and agree on a secret key, in four messages we call the **handshake**. After that, every message is encrypted with AES-256-GCM, and the keys are replaced regularly while connected. We then measure both versions in the same way to see what post-quantum security costs on a small device.

---

## What is in this repository

```
FYP/
├── Non_PQC_VPN/                  Classical VPN: ESP32 boards + a laptop as the gateway
│   ├── esp32_client/             ESP32 code (Arduino IDE)
│   ├── laptop_server/            Gateway code (Python)
│   ├── benchmarking/             Speed tests of the algorithms, and of the whole VPN
│   ├── screenshots/              Photos of the VPN running on three ESP32s
│   └── sequence_diagram.png      Picture of every step
├── Non_PQC_VPN_ESP32_Gateway/    Classical VPN with NO laptop: one ESP32 is the gateway
│   ├── esp32_gateway/            Gateway code (makes its own Wi-Fi network)
│   ├── esp32_client/             ESP32 client code for this gateway
│   └── sequence_diagram.png      Picture of every step
├── Non_PQC_VPN_DHT22/            Classical VPN sending DHT22 temperature readings
│   ├── esp32_dht22_client/       ESP32 code with the DHT22 sensor
│   ├── laptop_server/            Gateway code that decrypts and saves the readings
│   ├── screenshots/              Screenshots from a test run
│   └── sequence_diagram.png      Picture of every step
└── PQC_VPN/                      Post-quantum VPN: ML-DSA-44 + ML-KEM-512
    ├── esp32_client/             ESP32 code (needs the two libraries below)
    ├── laptop_server/            Gateway code (Python)
    ├── arduino_libraries/        The ML-DSA-44 and ML-KEM-512 libraries
    ├── benchmarking/             Ed25519 vs. ML-DSA-44, and the whole-VPN comparison
    └── sequence_diagram.png      Picture of every step
```

Each folder works on its own. The Arduino IDE only builds the files that are inside a sketch's own folder, so every ESP32 project has its own copy of the shared code (`AuthManager`, `DeviceIdentity`, `SecureTunnel`). If you change the handshake in one project, change the other copies too.

---

## Where to read more

* **[Non_PQC_VPN](Non_PQC_VPN/README.md)**: how the classical VPN works, step by step, and how to run it
* **[Non_PQC_VPN_ESP32_Gateway](Non_PQC_VPN_ESP32_Gateway/README.md)**: running the VPN with an ESP32 as the gateway, and the commands you can type on it
* **[Non_PQC_VPN_DHT22](Non_PQC_VPN_DHT22/README.md)**: wiring the sensor, and how the readings are encrypted and saved
* **[PQC_VPN](PQC_VPN/README.md)**: how the post-quantum VPN works, and how to build and run it
* **[Whole-VPN benchmark: classical vs. post-quantum](PQC_VPN/benchmarking/system_benchmark/README.md)**: the main comparison
* **[Benchmark report (PDF)](PQC_VPN/benchmarking/system_benchmark/benchmark_report.pdf)**: all the results, graphs and what each measurement means, in one document
* Algorithm benchmarks: [signatures](Non_PQC_VPN/benchmarking/mutual_auth_benchmark/README.md) · [key exchange](Non_PQC_VPN/benchmarking/key_exchange_benchmark/README.md) · [Ed25519 vs. ML-DSA-44](PQC_VPN/benchmarking/mutual_auth_benchmark/README.md)
