# Post-Quantum IoT VPN (ESP32 to Laptop Gateway)

The post-quantum version of the classical VPN in [`../Non_PQC_VPN/`](../Non_PQC_VPN/README.md). The handshake has the same 4 messages, transcripts, X25519 key exchange, HKDF-SHA256 and HMAC key confirmation. The one change: **Ed25519 is replaced by ML-DSA-44** (NIST FIPS 204), a lattice-based signature that resists quantum computers.

| | Classical (`Non_PQC_VPN`) | Post-Quantum (`PQC_VPN`) |
|---|---|---|
| Algorithm ID | `0x01` | `0x02` |
| Signature | Ed25519 (64 B) | ML-DSA-44 (2,420 B) |
| Public key | 32 B | 1,312 B |
| MSG 2 / MSG 3 | 128 B / 96 B | 2,484 B / 2,452 B |
| Key exchange | X25519 | X25519 (same) |

---

## Directory Overview

* **`esp32_client/`**: ESP32 firmware for the Arduino IDE (`esp32_client.ino`, `AuthManager`, `DeviceIdentity`, `config.h`). The handshake runs in a dedicated **64 KB FreeRTOS task** on Core 1, because ML-DSA-44 needs about 34 KB of stack.
* **`laptop_server/`**: Python gateway (`server.py`, `tunnel_session.py`, `crypto_engine.py`, `config.py`, `authorized_devices.json`).
  * `libmldsa44.so`: the ML-DSA-44 C library, loaded by `crypto_engine.py` through `ctypes`. It is **not in git**; build it with the script below.
  * `build_libmldsa44.sh` + `linux_randombytes.c`: build `libmldsa44.so` from the same C source the ESP32 uses.
* **`benchmarking/mutual_auth_benchmark/`**: Ed25519 vs. ML-DSA-44 benchmark on the ESP32 ([README](benchmarking/mutual_auth_benchmark/README.md)).

---

## Requirements

**Laptop gateway**
* Python 3 with `cryptography` (`pip install cryptography`)
* `gcc`, to build `libmldsa44.so`

**ESP32 client (Arduino IDE)**
* Board package **esp32 by Espressif Systems**. It includes libsodium, used for X25519, SHA-256 and HMAC.
* Library **`mldsa`** v0.2.0 (ML-DSA-44 for ESP32), from <https://github.com/NeuraiProject/mldsa-esp32>. It is not in the Library Manager: download the repository as a ZIP, then use **Sketch → Include Library → Add .ZIP Library**. It installs into `~/Arduino/libraries/mldsa/`.

---

## Setup and Run

### 1. Build `libmldsa44.so` (once per laptop)
```bash
cd laptop_server
./build_libmldsa44.sh                      # uses ~/Arduino/libraries/mldsa/src
# or: ./build_libmldsa44.sh /path/to/mldsa-esp32/src
```
The gateway then runs exactly the same ML-DSA-44 code as the ESP32. The only difference is that on the laptop, random bytes come from `/dev/urandom` instead of the ESP32's hardware RNG.

### 2. Start the gateway
```bash
cd laptop_server
python3 server.py
```
It prints the laptop's IP and listens on port **9000**.

### 3. Flash the ESP32 client
1. In `esp32_client/config.h`, set `WIFI_SSID`, `WIFI_PASSWORD`, `GATEWAY_IP` (the IP printed by `server.py`) and a unique `DEVICE_ID`.
2. Open `esp32_client/esp32_client.ino`, select **ESP32 Dev Module**, and click **Upload**.
3. Open the Serial Monitor at **115200 baud**. On first boot the client prints its 1,312-byte ML-DSA-44 public key. Add it under its `DEVICE_ID` in `laptop_server/authorized_devices.json`.
