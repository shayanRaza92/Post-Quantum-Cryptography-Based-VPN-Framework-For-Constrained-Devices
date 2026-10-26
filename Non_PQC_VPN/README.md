# Classical IoT VPN (ESP32 to Gateway)

A lightweight mutual authentication and secure communication tunnel between an ESP32 microcontroller and a Python gateway server using Ed25519 digital signatures and SHA-256 session transcript binding.

---

## Directory Overview

* **`esp32_client/`**: ESP32 C++ firmware for Arduino IDE (`esp32_client.ino`, `AuthManager`, `DeviceIdentity`, `config.h`).
* **`laptop_server/`**: Python gateway server (`server.py`, `tunnel_session.py`, `crypto_engine.py`, `authorized_devices.json`).
* **`sequence_diagram.png`**: Protocol flow diagram showing the mutual authentication exchange.
* **`benchmarking/`**: Standalone microcontroller benchmarks and analysis reports for classical cryptography.

---

## Protocol Handshake Flow

![Handshake Sequence Diagram](sequence_diagram.png)

1. **TCP Connection**: The ESP32 connects to the gateway over Wi-Fi on TCP port 9000.
2. **Message 1 (Client Hello, 50 B)**:
   * The ESP32 transmits `[1B Version] [1B AlgID] [16B DeviceID] [32B ClientNonce]`.
   * Version (`0x01`) and AlgID (`0x01`) enforce protocol standards and downgrade protection.
   * The gateway validates `DeviceID` against `authorized_devices.json` and drops unauthorized devices.
3. **Message 2 (Server Proof, 96 B — Server Authenticates First)**:
   * The gateway generates a 32-byte random challenge nonce (`ServerNonce`).
   * The gateway constructs the Server Transcript (running hash over MSG 1):  
     `SHA-256("VPN-v1|SERVER|" (14 B) || MSG1 (50 B) || ServerNonce (32 B))` -> 96 B input
   * The gateway signs this digest with its Ed25519 private key and returns `[32B ServerNonce] [64B ServerSignature]`.
   * The ESP32 verifies the signature against its pinned public key (`TRUSTED_GATEWAY_PUBLIC_KEY`). If verification fails, the ESP32 stops immediately.
4. **Message 3 (Client Proof, 64 B — Client Binds Full Handshake History)**:
   * The ESP32 constructs the Client Transcript binding the complete wire exchange (MSG 1 + MSG 2):  
     `SHA-256("VPN-v1|CLIENT|" (14 B) || MSG1 (50 B) || MSG2 (96 B))` -> 160 B input
   * The ESP32 signs this digest with its device private key and transmits its 64-byte signature.
   * The gateway verifies the signature using the device's registered public key.
5. **Message 4 (Server Verdict, 8 B)**:
   * The gateway sends `AUTH_OK\n` to confirm mutual authentication succeeded.
   * The ESP32 verifies `AUTH_OK` and transitions to the active tunnel.
6. **Active Data Tunnel**: The client and server exchange newline-delimited telemetry and status pings, protected by an idle session timeout.

---

## Quickstart Guide

### 1. Start the Server (Laptop)

```bash
cd laptop_server
python3 server.py
```
The server will print its local IP address, public key, and listen for incoming connections on port 9000.

### 2. Configure and Flash the Client (ESP32)

1. Open `esp32_client/config.h` and verify your network settings:
   ```cpp
   const char* const WIFI_SSID     = "Your_WiFi_SSID";
   const char* const WIFI_PASSWORD = "Your_WiFi_Password";
   const char* const GATEWAY_IP    = "10.202.171.216"; // IP address printed by server.py
   const uint16_t    GATEWAY_PORT  = 9000;
   ```
2. Open `esp32_client/esp32_client.ino` in Arduino IDE.
3. Select your ESP32 board and COM port, then click **Upload**.
4. Open the Serial Monitor at **115200 baud** to monitor the connection and authentication.

---

## Performance Summary (ESP32 @ 240 MHz)

Cryptographic operations benchmarked directly on the ESP32 (Xtensa LX6 @ 240 MHz):

| Metric | Ed25519 (Selected) | ECDSA P-256 | RSA-3072 |
| :--- | :---: | :---: | :---: |
| **Sign Latency** | **9.42 ms** | 158.58 ms | 375.81 ms |
| **Verify Latency** | 19.80 ms | 313.88 ms | **1.71 ms** |
| **Total Handshake Crypto** | **29.22 ms** | 472.46 ms | 377.52 ms |
| **Signature Wire Size** | **64 bytes** | 71 bytes | 384 bytes |
| **Peak Heap Overhead** | **108 bytes** | 300 bytes | 2,068 bytes |
