# Deliverable 2: Mutual Authentication (Ed25519 Signatures)

Asymmetric mutual authentication using Ed25519 digital signatures established over the TCP transport layer before allowing payload data transfer.

## Cryptographic Mechanism

* **Asymmetric Public-Key Authentication:** The ESP32 client and laptop gateway maintain individual private-public key pairs. No static shared password is used on the wire.
* **Payload Footprint:** Public keys are 32 bytes and signatures are 64 bytes, minimizing transmission overhead.
* **Handshake Protocol:** 3-way nonce challenge-response exchange ensuring freshness and mutual verification.

## Handshake Flow Diagram

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

1. Server transmits 32-byte challenge nonce (`os.urandom(32)`).
2. ESP32 signs the challenge with its Ed25519 private key, generates a fresh 32-byte client challenge, and sends both back (96 bytes).
3. Server validates the ESP32 signature using the registered ESP32 public key.
4. Server signs the client challenge with its private key and returns the 64-byte signature.
5. ESP32 validates the server signature using the registered server public key.
6. Once both checks succeed, the encrypted data tunnel begins exchanging packets.

## Libraries and Dependencies

### ESP32 Client (`esp32_client.ino`)
* `WiFi.h`: ESP32 network stack handling Wi-Fi connection and `WiFiClient` TCP sockets.
* `sodium.h`: Libsodium cryptographic engine providing `crypto_sign_ed25519` detached signature generation and verification.

### Laptop Gateway (`server.py`)
* `socket`: Standard Python socket library for TCP server management.
* `cryptography.hazmat.primitives.asymmetric.ed25519`: Python cryptography library for Ed25519 signing and verification.

## Directory Structure

```text
step2_mutual_auth/
├── generate_keys.py        # Utility script to generate fresh Ed25519 identity keypairs
├── laptop_server/
│   └── server.py           # Python server with Ed25519 challenge-response logic
├── esp32_client/
│   └── esp32_client.ino    # ESP32 sketch using Libsodium Ed25519 routines
└── README.md
```

## Running the Components

### Step 1: Start the Gateway Server
```bash
python3 laptop_server/server.py
```

### Step 2: Upload Sketch to ESP32
1. Open `esp32_client/esp32_client.ino` in the Arduino IDE.
2. Confirm `WIFI_SSID`, `WIFI_PASSWORD`, and `LAPTOP_IP`.
3. Upload to the ESP32 and monitor execution via the Serial Monitor at 115200 baud.

## Verification Output

### ESP32 Serial Monitor
```text
============================================================
         PQC VPN: ESP32 CLIENT (Ed25519 AUTH)
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
       Status         : RECEIVED

[MSG2] ESP32 Authentication Proof
       Algorithm      : Ed25519 Digital Signature
       Signature Size : 64 bytes
       Status         : SENT

[MSG3] Server Authentication Proof
       Algorithm      : Ed25519 Digital Signature
       Signature Size : 64 bytes
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

### Laptop Gateway Terminal
```text
============================================================
         PQC VPN: LAPTOP GATEWAY (Ed25519 AUTH)
============================================================

[NETWORK]
[OK] Server listening on 10.27.228.216:9000
     Server PubKey  : 191a242ddd267e20588d076b12f44c834fddc7c53d8678922eb17759b17673ba

[TCP TRANSPORT]
Waiting for ESP32 connection...
[OK] ESP32 connected from 10.27.228.175:51432

[MUTUAL AUTHENTICATION]
[MSG1] Server Challenge sent (32 bytes)
[MSG2] ESP32 Signature received and verified: SUCCESS
[MSG3] Server Signature sent (64 bytes)

============================================================
        MUTUAL AUTHENTICATION SUCCESSFUL (Ed25519)
============================================================

[DATA TUNNEL]
[RX] PING #1
[TX] ACK: PING #1
```
