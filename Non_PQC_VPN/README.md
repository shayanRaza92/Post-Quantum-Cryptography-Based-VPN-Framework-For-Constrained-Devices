# Non-PQC VPN Baseline

This folder has the classical (non-quantum) VPN implementation between an ESP32 and a laptop gateway, along with our benchmark results.

---

## Folder Structure

* `esp32_client/`: Arduino C++ code for the ESP32 board (`DeviceIdentity`, `AuthManager`, `config.h`, and `esp32_client.ino`).
* `laptop_server/`: Python gateway server (`server.py`, `tunnel_session.py`, `crypto_engine.py`, `config.py`, and `authorized_devices.json`).
* `benchmarking/`: All raw test data, plots, and PDF reports for mutual authentication and key exchange algorithms.
* `sequence_diagram.png`: Visual handshake diagram showing how the ESP32 and gateway authenticate each other.

---

## How It Works

![Handshake Sequence Diagram](sequence_diagram.png)

1. **TCP Connection**: The ESP32 connects to the laptop server over local Wi-Fi on port 9000.
2. **Device Allowlist Check**: The ESP32 sends its device ID (`esp32-01`). The server checks `authorized_devices.json`. If the device is not registered, the server drops the connection immediately.
3. **Mutual Authentication (Ed25519)**:
   - The server sends a random 32-byte challenge nonce to the ESP32.
   - The ESP32 signs this nonce with its private key (stored in NVS flash) and generates its own random challenge nonce, sending both back (96 bytes total).
   - The server verifies the ESP32 signature using the pre-registered public key from the allowlist. Then, the server signs the ESP32 challenge with its own private key and sends it back (64 bytes).
   - The ESP32 verifies the server's signature using the hardcoded server public key in `config.h`.
4. **Handshake Confirmation**: Once the ESP32 verifies the server, it sends `AUTH_OK`. Only then does the server mark the tunnel as established.
5. **Data Tunnel**: Both sides now safely exchange encrypted tunnel packets and periodic heartbeat pings.

---

## Benchmark Highlights

We tested these algorithms on real ESP32 hardware (Xtensa dual-core @ 240 MHz):

* **Mutual Authentication (`benchmarking/mutual_auth_benchmark/`)**:
  * **Ed25519**: ~22 ms signing time, 64-byte signature. Best speed and smallest memory usage on ESP32. (Selected algorithm)
  * **ECDSA P-256**: ~48 ms signing time, 70–72 byte DER signature.
  * **RSA-3072**: ~1850 ms signing time, 384-byte signature. Far too heavy and slow for microcontrollers.

* **Key Exchange (`benchmarking/key_exchange_benchmark/`)**:
  * **X25519**: Fast Curve25519 scalar multiplication with compact 32-byte keys. (Selected algorithm)
  * **ECDH P-256**: Standard NIST curve, 64-byte keys.
  * **DH-2048**: Classic Diffie-Hellman, 256-byte keys. Much slower on embedded hardware.

---

## How to Run

### 1. Start the Laptop Server

```bash
cd laptop_server
python3 server.py
```
The server will detect your local IP address and start listening on port 9000.

### 2. Flash the ESP32

1. Open `esp32_client/config.h` and put your Wi-Fi name, password, and the laptop's IP address:
   ```cpp
   #define WIFI_SSID     "Your_WiFi_Name"
   #define WIFI_PASSWORD "Your_WiFi_Password"
   #define VPN_SERVER_IP "192.168.1.X"   // Put your laptop IP here
   #define VPN_SERVER_PORT 9000
   ```
2. Open `esp32_client/esp32_client.ino` in Arduino IDE, select your ESP32 board, and upload.
3. Open the Serial Monitor at **115200 baud** to see the handshake complete.
