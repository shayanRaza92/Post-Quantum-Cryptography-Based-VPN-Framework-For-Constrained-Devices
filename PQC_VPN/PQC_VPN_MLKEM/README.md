# Fully Post-Quantum IoT VPN (ESP32 to Gateway): ML-DSA-44 + ML-KEM-512

This is the same 4-message handshake as [`PQC_VPN/`](..), with one change: the ephemeral **X25519** key exchange is replaced by **NIST FIPS 203 ML-KEM-512**. Authentication is unchanged (**ML-DSA-44**, FIPS 204). The rest of the stack is also unchanged: HKDF-SHA256 key derivation, bidirectional HMAC-SHA256 key confirmation, the device allowlist and the pinned gateway key. Both the key exchange and the signatures are now post-quantum.

| | `PQC_VPN/` | `PQC_VPN_MLKEM/` (this folder) |
| :--- | :--- | :--- |
| Algorithm ID | `0x02` | `0x03` |
| Authentication | ML-DSA-44 | ML-DSA-44 (same keys, same allowlist) |
| Key exchange | Ephemeral X25519 (quantum-vulnerable) | Ephemeral ML-KEM-512 (FIPS 203) |
| KEM / KEX library | libsodium / `cryptography` | [`mlkem-native`](https://github.com/pq-code-package/mlkem-native) v2.0.0 (ESP32 and laptop) |
| MSG 1 / MSG 2 / MSG 3 / MSG 4 | 82 / 2,484 / 2,452 / 40 B | **850 / 3,220** / 2,452 / 40 B |
| Total handshake bytes | 5,058 B | 6,562 B (+1,504 B) |

---

## Directory Overview

* **`esp32_client/`**: ESP32 Arduino firmware (`esp32_client.ino`, `AuthManager`, `DeviceIdentity`, `config.h`).
* **`laptop_server/`**: Python gateway (`server.py`, `tunnel_session.py`, `crypto_engine.py`, `config.py`, `authorized_devices.json`, `build_native_libs.sh`).
* **`arduino_libraries/MLKEM512/`**: Arduino library with a `MLKEM512::` wrapper around the vendored portable C sources of mlkem-native v2.0.0.
* **`arduino_libraries/MLDSA44/`**: Arduino library with the `MLDSA44::` wrapper around mldsa-native v1.0.0-beta2 (`MLD_CONFIG_REDUCE_RAM`). It derives the same keys from the same seeds as the original MLDSA44 build, so existing device keys and the pinned gateway key still work.

---

## Protocol Handshake Flow (ML-DSA-44 Mutual Authentication + Ephemeral ML-KEM-512)

1. **TCP Connection**: The ESP32 connects to the gateway over Wi-Fi on TCP port 9000.
2. **Message 1 (Client Hello, 850 B)** `[1B Ver] [1B AlgID=0x03] [16B DeviceID] [32B N_cli] [800B ek_cli_eph]`
   * The ESP32 generates a fresh **ephemeral ML-KEM-512 keypair** `(dk_cli_eph 1,632 B, ek_cli_eph 800 B)` with the hardware TRNG. A new keypair per handshake gives **forward secrecy**.
   * The gateway checks Version/AlgID (downgrade protection) and checks `DeviceID` against `authorized_devices.json`.
3. **Message 2 (Server Proof, 3,220 B)** `[32B N_srv] [768B ct] [2,420B ML-DSA-44 sig]`. The server authenticates first.
   * The gateway runs `(K, ct) = ML-KEM-512.Encaps(ek_cli_eph)`. This includes the FIPS 203 encapsulation-key modulus check, and a malformed `ek` aborts the handshake.
   * Server Transcript: `SHA-256("VPN-v1|SERVER|" || MSG1 (850 B) || N_srv || ct)` over 1,664 B of input. The gateway signs the digest with its ML-DSA-44 key.
   * The ESP32 verifies the signature against the pinned `TRUSTED_GATEWAY_PUBLIC_KEY` **before** decapsulating. Because `ek` and `ct` are both in the signed transcript, a man-in-the-middle cannot substitute either one.
   * The ESP32 runs `K = ML-KEM-512.Decaps(dk_cli_eph, ct)` and then wipes `dk_cli_eph`. Decapsulation uses implicit rejection: a bad `ct` produces a pseudorandom `K`, which the key-confirmation tags in MSG 3/4 then catch.
   * Both sides run HKDF-SHA256 (RFC 5869): `salt = SHA-256(N_cli || N_srv)`, `IKM = K`, which gives `K_confirm` and `K_session`.
4. **Message 3 (Client Proof, 2,452 B)** `[2,420B ML-DSA-44 sig] [32B tag]`
   * Client Transcript: `SHA-256("VPN-v1|CLIENT|" || MSG1 || MSG2)` over 4,084 B of input. The ESP32 signs it with its device key and adds `HMAC-SHA256(K_confirm, "VPN-v1|CLIENT-CONFIRM|" || H_cli)`.
5. **Message 4 (Server Verdict, 40 B)** `["AUTH_OK\n"] [32B HMAC(K_confirm, "VPN-v1|SERVER-CONFIRM|" || H_cli)]`
6. **AES-256-GCM Data Tunnel** keyed from `K_session` (`esp32_client/SecureTunnel.*`, `laptop_server/secure_tunnel.py`):
   * A separate key for each direction (HKDF-Expand): `K_c2s = HMAC-SHA256(K_session, "VPN-v1|TUNNEL|C2S" || 0x01)` and `K_s2c = HMAC-SHA256(K_session, "VPN-v1|TUNNEL|S2C" || 0x01)`.
   * Frame `[2B LEN][8B SEQ][ciphertext][16B tag]`. The nonce is `DIR (4B) || SEQ (8B)` and the AAD is `LEN || SEQ`, so the header is authenticated too.
   * `SEQ` starts at 0 and must increase by exactly 1. Any tampered, replayed, reordered or plaintext frame fails authentication and the session is dropped.
   * On the ESP32, mbedtls uses the hardware AES accelerator. On the laptop, the `cryptography` package (`AESGCM`) is used.

### ML-KEM-512 object sizes (FIPS 203)

| Object | Size | Layout |
| :--- | :---: | :--- |
| Encapsulation key `ek` | 800 B | `ByteEncode12(t_hat)` 768 B, then `rho` 32 B |
| Decapsulation key `dk` | 1,632 B | `dk_pke` 768 B, `ek` 800 B, `H(ek)` 32 B, `z` 32 B |
| Ciphertext `ct` | 768 B | `c1 = Compress_10(u)` 640 B, then `c2 = Compress_4(v)` 128 B |
| Shared secret `K` | 32 B | |

---

## Quickstart Guide

### 1. Build the native libraries and start the server (laptop)

The server loads mlkem-native and mldsa-native through `ctypes`. AES-256-GCM for the tunnel comes from the `cryptography` package, which is installed into a local `.venv`.

```bash
cd PQC_VPN/PQC_VPN_MLKEM/laptop_server
./build_native_libs.sh      # builds libmlkem512.so (mlkem-native v2.0.0) + libmldsa44.so (mldsa-native v1.0.0-beta2)
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt   # one-time: cryptography (AES-GCM)
.venv/bin/python server.py
```

To keep using the `libmldsa44.so` you already built for `PQC_VPN/`, copy it into this folder and run `SKIP_MLDSA=1 ./build_native_libs.sh`.

The gateway seed (`SERVER_PRIVATE_SEED_HEX`) and `authorized_devices.json` are the same as in `PQC_VPN/`, so the pinned key in `config.h` and your registered ESP32 key work as they are.

### 2. Install the Arduino libraries and flash the ESP32

1. Copy **both** libraries into your Arduino libraries folder:
   ```bash
   mkdir -p ~/Documents/Arduino/libraries
   cp -R PQC_VPN/PQC_VPN_MLKEM/arduino_libraries/MLDSA44 PQC_VPN/PQC_VPN_MLKEM/arduino_libraries/MLKEM512 ~/Documents/Arduino/libraries/
   ```
   Restart Arduino IDE afterwards so it picks them up.
2. Check `esp32_client/config.h` (Wi-Fi SSID/password, `GATEWAY_IP`, `GATEWAY_PORT`).
3. Open `esp32_client/esp32_client.ino`, select **ESP32 Dev Module** at 240 MHz, upload, and open the Serial Monitor at **115200 baud**.

The device keeps the ML-DSA-44 identity seed it already has in NVS (`vpn_pqc_id`), so no re-registration is needed.

Command-line build:

```bash
arduino-cli compile --fqbn esp32:esp32:esp32 \
  --libraries PQC_VPN/PQC_VPN_MLKEM/arduino_libraries PQC_VPN/PQC_VPN_MLKEM/esp32_client
```

---

## Implementation Notes

* **Randomness on the ESP32**: `arduino_libraries/MLKEM512/src/mlkem_native_config.h` is the upstream config with two changes, both marked `[ESP32 VPN]`. It sets `MLK_CONFIG_PARAMETER_SET=512`, and it routes randomness through `MLK_CONFIG_CUSTOM_RANDOMBYTES` to `esp_fill_random()`. The custom hook is needed because the ESP32 core's libsodium already exports a global `randombytes()`; defining a second one would fail to link.
* **Randomness on the laptop**: `libmlkem512.so` is built with `MLK_CONFIG_NO_RANDOMIZED_API`. The server draws the 32-byte encapsulation seed `m` from `os.urandom` and calls `enc_derand`, which is equivalent to `ML-KEM.Encaps` with the OS CSPRNG.
* **Memory**: ML-KEM state lives in the global `AuthManager` (`.bss`, about 6.5 KB including the cached MSG 1/MSG 2). Key generation and decapsulation run inside the existing 64 KB FreeRTOS task, where ML-DSA-44 signing is still the peak stack user. The library does no heap allocation.
* **Vendored source**: only the portable C files of mlkem-native v2.0.0 are included (no AArch64/x86-64 assembly backends), under its original license (`LICENSE.mlkem-native`).

## Verification Performed

* **Cross-implementation check**: mlkem-native `keypair_derand` / `enc_derand` / `dec`, including implicit rejection on a tampered `ct`, matches the independent `kyber-py` FIPS 203 implementation byte for byte over 25 random seeds.
* **End-to-end against the real `VpnSession`**, using a Python client that mirrors `AuthManager.cpp` byte for byte (with kyber-py on the client side):
  * A valid device completes the handshake, and client and server derive the same `K_session`.
  * A wrong device ML-DSA key gets `AUTH_NO`.
  * A ciphertext tampered in MSG 2 makes the client reject the server signature.
  * A malformed `ek` makes the server abort.
  * An unregistered device ID is dropped.
* **Firmware**: compiles with `arduino-cli` for `esp32:esp32:esp32` (core 3.3.12) with no warnings under `--warnings all`. It uses 78% of flash and 61 KB of globals.
* **Real hardware** (ESP32-D0WD rev 1.0 ↔ MacBook over a phone hotspot): the full handshake completed. ML-DSA-44 signatures and both HMAC key-confirmation tags passed, both sides derived the same `K_session`, and the tunnel exchanged 50+ `STATUS_PING`/`SERVER_ACK` messages. The AES-256-GCM tunnel has also run on the hardware: ESP32 frames decrypted on the laptop with `GCM tag VALID`, encrypted replies went back, and sequence numbers advanced by one per frame in each direction. Host tests also confirm that tampered, replayed and plaintext frames are rejected.
