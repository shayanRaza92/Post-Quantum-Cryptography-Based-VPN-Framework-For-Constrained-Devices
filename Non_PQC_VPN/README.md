# Classical VPN (ESP32 to Laptop)

This is our normal (not post-quantum) VPN. ESP32 boards connect to a Python program on a laptop, which we call the **gateway**. Before any data is sent, the ESP32 and the gateway prove to each other who they are. Then they agree on a secret key, and every message after that is encrypted.

The algorithms used:
* **Ed25519**: signatures, so each side can prove who it is
* **X25519**: key exchange, so both sides get the same secret key without ever sending it
* **HKDF-SHA256 and HMAC-SHA256**: turn that secret into the actual keys and double-check both sides have the same ones
* **AES-256-GCM**: encrypts every message after the handshake

---

## What is in this folder

* `esp32_client/`: the code for the ESP32 (Arduino IDE).
  * `esp32_client.ino`: Wi-Fi, connecting to the gateway, sending pings.
  * `AuthManager`: the handshake.
  * `DeviceIdentity`: the ESP32's own key, saved in flash.
  * `SecureTunnel`: encryption of messages.
  * `config.h`: Wi-Fi name, password, gateway IP and other settings.
* `laptop_server/`: the gateway (Python).
  * `server.py`: starts the gateway and accepts connections.
  * `tunnel_session.py`: talks to one ESP32 (each ESP32 gets its own thread).
  * `crypto_engine.py`: the crypto for the handshake.
  * `secure_tunnel.py`: encryption of messages.
  * `session_registry.py`: keeps one connection per device.
  * `console.py`: keeps the printouts of different ESP32s from mixing.
  * `authorized_devices.json`: the list of ESP32s that are allowed in.
* `sequence_diagram.png`: a picture of every step, from connecting to disconnecting.
* `screenshots/`: photos of the VPN running on three ESP32s.
* `benchmarking/`: speed tests.
  * `mutual_auth_benchmark/`: compares Ed25519, ECDSA P-256 and RSA-3072 on the ESP32.
  * `key_exchange_benchmark/`: compares X25519, ECDH P-256 and DH-3072.
  * `system_benchmark/`: tests the whole VPN from start to end, in the same way as the post-quantum VPN, so the two can be compared ([README](benchmarking/system_benchmark/README.md)).

Other projects built on this one:
* [`../Non_PQC_VPN_ESP32_Gateway/`](../Non_PQC_VPN_ESP32_Gateway/README.md): the same VPN, but an ESP32 is the gateway instead of a laptop.
* [`../Non_PQC_VPN_DHT22/`](../Non_PQC_VPN_DHT22/README.md): sends temperature readings from a DHT22 sensor through the VPN.

---

## How it works

![Sequence diagram](sequence_diagram.png)

The ESP32 connects to the gateway on TCP port 9000. Then four messages are exchanged. We call this the **handshake**.

**Message 1, Client Hello (82 bytes): ESP32 to gateway**
* Contains: version, algorithm ID, device name (like `esp32-01`), a 32-byte random number, and a fresh X25519 public key.
* The X25519 key is new for every connection. So even if a key leaks one day, old sessions stay safe (this is called *forward secrecy*).
* The gateway checks the device name against `authorized_devices.json`. Unknown devices are dropped right away.

**Message 2, Server Proof (128 bytes): gateway to ESP32**
* The gateway makes its own random number and its own fresh X25519 key.
* It takes a SHA-256 hash of message 1 plus its own random number and key, then **signs** that hash with its Ed25519 key.
* The ESP32 checks the signature with the gateway's public key, which is saved in `config.h`. If the check fails, the ESP32 stops. This protects against fake gateways.
* Both sides now combine the two X25519 keys and get the same 32-byte secret. From it, using HKDF, they make two keys: `K_confirm` (used to check the handshake) and `K_session` (used for the data).

**Message 3, Client Proof (96 bytes): ESP32 to gateway**
* The ESP32 hashes messages 1 and 2 together and signs the hash with its own Ed25519 key. This proves it really is the device it claimed to be.
* It also adds an HMAC tag made with `K_confirm`. This proves it got the same secret as the gateway.
* The gateway checks both. If either is wrong, it sends `AUTH_NO` and closes the connection.

**Message 4, Verdict (40 bytes): gateway to ESP32**
* The gateway sends `AUTH_OK` and its own HMAC tag. The ESP32 checks the tag.
* Now both sides have proved who they are and share the same `K_session`. The key itself was never sent over Wi-Fi.

**After the handshake: encrypted messages**
* From `K_session`, each side makes two AES-256 keys: one for ESP32 → gateway and one for gateway → ESP32.
* Every message is encrypted with AES-256-GCM. The format is `[2 bytes length][8 bytes message number][encrypted data][16 bytes tag]`.
* The tag proves the message was not changed on the way.
* The message number must go up by exactly 1 each time, so an old message that is sent again (a *replay*) is caught.
* If any message is wrong (changed, replayed, too big, or not encrypted), only that ESP32's connection is closed. Other ESP32s are not affected.
* Example: the ping `"[esp32-01] STATUS_PING #1"` (25 bytes) travels as a 52-byte encrypted message. The text never appears on the Wi-Fi.
* On the ESP32, AES runs on the chip's built-in AES hardware.

**Changing the keys while connected (rekeying)**
* After **1,000 messages or 5 minutes** with the same keys, the ESP32 asks for new keys. You can change this with `REKEY_AFTER_MESSAGES` and `REKEY_AFTER_MS` in `config.h`. For a demo, set it to 10 messages.
* The ESP32 sends a fresh X25519 key inside the encrypted connection. The gateway answers with its own fresh X25519 key. Both make a new `K_session` from the new secret mixed with the old key. The old keys are deleted and the message number starts again from 0.
* Because this happens inside the encrypted connection, nobody else can start a rekey. If a key ever leaks, it only exposes the messages from its own period.
* The gateway disconnects a device that does not rekey (more than 2,000 messages or 10 minutes with one key), that asks for new keys within 5 seconds of the last time, or that sends a bad rekey message. Only that device is disconnected.

**Many ESP32s at the same time**
* Every ESP32 gets its own thread on the gateway, so one bad or rejected device never closes the others.
* If the same device connects again, the old connection is closed and the new one is kept.
* If you remove a device from `authorized_devices.json` while it is connected, it is disconnected within 5 seconds.
* The gateway also limits how many connections it accepts at once, so it cannot easily be flooded.

---

## How to run it

### 1. Start the gateway (laptop)
```bash
cd laptop_server
python3 server.py
```
It prints the laptop's IP address and waits for ESP32s on port 9000.

### 2. Set up and flash the ESP32
1. Open `esp32_client/config.h` and set your Wi-Fi and the laptop's IP:
   ```cpp
   const char* const WIFI_SSID     = "Your_WiFi_Name";
   const char* const WIFI_PASSWORD = "Your_WiFi_Password";
   const char* const GATEWAY_IP    = "192.168.1.10";   // the IP printed by server.py
   const char* const DEVICE_ID     = "esp32-01";       // a different name for each board
   ```
2. Open `esp32_client/esp32_client.ino` in the Arduino IDE.
3. Select your ESP32 board and port, then click **Upload**.
4. Open the Serial Monitor at **115200 baud** to watch the handshake and the encrypted messages.

### 3. Add a new ESP32 to the allowed list
The first time an ESP32 starts, it creates its own key and prints its **Device Public Key** on the Serial Monitor. Copy it into `laptop_server/authorized_devices.json` under its device name. The gateway picks up the change without a restart.

---

## Speed on the ESP32 (240 MHz)

From the algorithm benchmarks in `benchmarking/`:
* **Ed25519 sign + verify:** 29.35 ms. Uses no extra heap memory. The signature is 64 bytes.
* **X25519 key exchange:** 25.57 ms on the ESP32 (8.48 ms to make the key + 17.09 ms to compute the secret), 0.79 ms on the laptop. Over Wi-Fi, the whole exchange takes about 39 ms. The key is 32 bytes.

For the whole VPN (handshake, encrypted messages, CPU, memory), see the [system benchmark](benchmarking/system_benchmark/README.md).
