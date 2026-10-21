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
2. **Device Authorization**: The ESP32 sends its 16-byte Device ID (`esp32-01`). The server validates the ID against `authorized_devices.json` and drops unauthorized devices.
3. **Mutual Challenge-Response**:
   * The server sends a fresh 32-byte random challenge nonce.
   * The ESP32 samples 32 bytes of physical entropy from its hardware TRNG (`esp_fill_random`).
   * Both sides construct a session transcript:
     `SHA-256("VPN-AUTH-v1|" + Role + "|" + DeviceID + "|" + ServerNonce + "|" + ClientNonce)`
   * **Client Authentication**: The ESP32 signs the transcript (`Role = "CLIENT"`) with its Ed25519 private key and sends the 64-byte signature with its nonce. The server verifies the signature using the pre-registered public key.
   * **Server Authentication**: The gateway signs the transcript (`Role = "SERVER"`) and sends its 64-byte signature back. The ESP32 verifies it using the pinned gateway public key.
4. **Cryptographic Confirmation**: The ESP32 sends a 32-byte confirmation tag (`SHA-256("VPN-AUTH-v1|CONFIRM|...")`). The server verifies this digest before transitioning the session to the active tunnel state.
5. **Active Tunnel**: The client and server begin bidirectional data exchange and periodic status pings.

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
