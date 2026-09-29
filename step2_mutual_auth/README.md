# Step 2: Mutual Authentication (Ed25519 Digital Signatures)

This step builds on the TCP socket connection from Step 1 by adding **Asymmetric Mutual Authentication using Ed25519 Digital Signatures** before any regular messages can be exchanged.

---

## Why Ed25519?

* **Asymmetric Public-Key Security:** No shared static password is used. The ESP32 and Laptop Gateway each possess their own private key and public key.
* **Compact & High Performance:** Public keys are **32 bytes**, and digital signatures are **64 bytes**.
* **Precursor to Post-Quantum Migration:** In classical cryptography, Ed25519 is broken by Shor's quantum algorithm. In Milestone 2, this exact authentication handshake will be upgraded to **ML-DSA (CRYSTALS-Dilithium)**.

---

## How the Handshake Works

```text
       ESP32 (Client)                                          Laptop (Server)
         |                                                           |
         | <--- 1. [MSG1] Laptop Challenge (32 bytes) ---------------|
         |                                                           |
         | --- 2. [MSG2] ESP32 Signature (64 bytes) ---------------> |
         |     + ESP32 Challenge (32 bytes)                          |
         |                                                           |
         | <--- 3. [MSG3] Laptop Signature (64 bytes) ---------------|
         |                                                           |
  [VERIFY OK]                                                 [VERIFY OK]
=============================================================================
                  MUTUAL AUTHENTICATION COMPLETE
=============================================================================
```

1. **Server sends 32-byte Challenge** (`os.urandom(32)`).
2. **ESP32 signs the Challenge** using its Ed25519 private key, generates its own 32-byte challenge, and sends both back (96 bytes).
3. **Server verifies the ESP32 Signature** using the registered ESP32 Public Key.
4. **Server signs the ESP32 Challenge** using its private key and sends back the 64-byte signature.
5. **ESP32 verifies the Server Signature** using the registered Server Public Key.
6. Once both signatures pass verification, the connection is approved and data transfer begins.

---

## Libraries Used & Purpose

### On ESP32 (`esp32_client.ino`):
* **`WiFi.h`**: Built into the ESP32 Arduino core. Handles connecting to Wi-Fi and provides `WiFiClient` for TCP socket communication.
* **`<sodium.h>`**: Libsodium cryptographic engine pre-compiled inside the ESP32 Arduino Core (`crypto_sign_ed25519`). Computes and verifies 64-byte Ed25519 digital signatures with high performance.

### On Laptop Server (`server.py`):
* **`socket`**: Standard Python networking library for the TCP server.
* **`cryptography.hazmat.primitives.asymmetric.ed25519`**: Modern Python cryptography library for signing and verifying Ed25519 signatures.

---

## File Structure

```text
step2_mutual_auth/
├── laptop_server/
│   └── server.py           # Python server with Ed25519 challenge-response
├── esp32_client/
│   └── esp32_client.ino    # ESP32 sketch using built-in Libsodium for Ed25519
└── README.md
```

---

## How to Run and Test

### 1. Start the Laptop Server
Open a terminal and run:
```bash
python3 /home/shayan/Downloads/VPN1/FYP/step2_mutual_auth/laptop_server/server.py
```

### 2. Upload to ESP32
1. Open [`esp32_client.ino`](file:///home/shayan/Downloads/VPN1/FYP/step2_mutual_auth/esp32_client/esp32_client.ino) in the Arduino IDE.
2. Update your `WIFI_SSID`, `WIFI_PASSWORD`, and `LAPTOP_IP`.
3. Click **Upload** and open the **Serial Monitor** at **115200 baud**.

---

## Expected Output

### On the ESP32 Serial Monitor:
```text
============================================================
         PQC VPN - ESP32 CLIENT (Ed25519 AUTH)
============================================================

[CRYPTO]
     ESP32 PubKey   : 7edd147c31ad36a424d378610ef89dd38c0922a8a9bb1402bcd20b975f8a0e31

[NETWORK]
[OK] Wi-Fi connected
     ESP32 IP       : 10.27.228.175
     Server IP      : 10.27.228.216
     Server Port    : 9000

[TCP TRANSPORT]
Connecting to server 10.27.228.216:9000...
[OK] TCP connection established

[MUTUAL AUTHENTICATION]
[MSG1] Server Challenge
       Length         : 32 bytes
       Nonce (Hex)    : ...
       Status         : RECEIVED

[MSG2] ESP32 Authentication Proof
       Algorithm      : Ed25519 Digital Signature
       Signature (Hex): ... (64 bytes / 128 hex chars)
       Client Nonce   : ...
       Status         : SENT

[MSG3] Server Authentication Proof
       Algorithm      : Ed25519 Digital Signature
       Signature (Hex): ... (64 bytes / 128 hex chars)
       Status         : RECEIVED

[VERIFY] Server Digital Signature
         Result       : SUCCESS (Valid Ed25519 Signature)

============================================================
        MUTUAL AUTHENTICATION SUCCESSFUL (Ed25519)
============================================================

[DATA TUNNEL]
[TX] PING #1
[RX] ACK: PING #1
```

### On the Laptop Terminal:
```text
============================================================
         PQC VPN - LAPTOP GATEWAY (Ed25519 AUTH)
============================================================

[NETWORK]
[OK] Server listening
     Server IP      : 10.27.228.216
     Server Port    : 9000
     Server PubKey  : 191a242ddd267e20588d076b12f44c834fddc7c53d8678922eb17759b17673ba

[TCP TRANSPORT]
Waiting for ESP32 connection...
[OK] ESP32 connected from 10.27.228.175:xxxxx

[MUTUAL AUTHENTICATION]
[MSG1] Server Challenge
       Length         : 32 bytes
       Nonce (Hex)    : ...
       Status         : SENT

[MSG2] ESP32 Authentication Proof
       Algorithm      : Ed25519 Digital Signature
       Signature (Hex): ...
       Client Nonce   : ...
       Status         : RECEIVED

[VERIFY] ESP32 Digital Signature
         Result       : SUCCESS (Valid Ed25519 Signature)

[MSG3] Server Authentication Proof
       Algorithm      : Ed25519 Digital Signature
       Signature (Hex): ...
       Status         : SENT

============================================================
        MUTUAL AUTHENTICATION SUCCESSFUL (Ed25519)
============================================================

[DATA TUNNEL]
[RX] PING #1
[TX] ACK: PING #1
```
