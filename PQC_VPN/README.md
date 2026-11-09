# Fully Post-Quantum IoT VPN (ESP32 to Gateway): ML-DSA-44 + ML-KEM-512 + AES-256-GCM

The post-quantum version of the classical VPN in [`../Non_PQC_VPN/`](../Non_PQC_VPN/README.md). It keeps the same 4-message handshake, transcripts, HKDF-SHA256 key derivation, HMAC-SHA256 key confirmation, device allowlist and pinned gateway key. Three things change:

| | Classical (`Non_PQC_VPN`) | Post-Quantum (`PQC_VPN`, this folder) |
| :--- | :--- | :--- |
| Algorithm ID | `0x01` | `0x03` |
| Authentication (signatures) | Ed25519 | **ML-DSA-44** (NIST FIPS 204) |
| Key exchange | Ephemeral X25519 | **Ephemeral ML-KEM-512** (NIST FIPS 203) |
| Data tunnel | Plaintext lines | **AES-256-GCM**, one key per direction, replay-protected |
| MSG 1 / MSG 2 / MSG 3 / MSG 4 | 82 / 128 / 96 / 40 B | 850 / 3,220 / 2,452 / 40 B |
| Total handshake bytes | 346 B | 6,562 B |

Both the signatures and the key exchange are post-quantum, so traffic recorded today cannot be decrypted later by a quantum computer ("harvest now, decrypt later").

> **History.** An earlier version in this folder used ML-DSA-44 with a *classical* X25519 key exchange (Algorithm ID `0x02`; MSG 1/2 = 82 / 2,484 B) and a plaintext tunnel. It was replaced by this version and removed. It is still in the git history (commit `3952522`) if the report needs the intermediate step.

---

## Directory Overview

* **`esp32_client/`**: ESP32 Arduino firmware.
  * `esp32_client.ino`: Wi-Fi, reconnect with backoff, and the tunnel loop, run in a dedicated **64 KB FreeRTOS task** because ML-DSA-44 signing needs about 34 KB of stack.
  * `AuthManager.*`: the 4-message handshake (ML-DSA-44 + ML-KEM-512).
  * `DeviceIdentity.*`: the ML-DSA-44 device key, stored in NVS flash.
  * `SecureTunnel.*`: the AES-256-GCM tunnel, using the ESP32 hardware AES through mbedTLS.
  * `config.h`: Wi-Fi, gateway IP, device ID, and the pinned gateway public key.
* **`laptop_server/`**: Python gateway.
  * `server.py`: accept loop with DoS limits. One connection's failure never stops the server.
  * `tunnel_session.py`: one thread per ESP32, running the handshake and then the encrypted tunnel.
  * `crypto_engine.py`: ML-DSA-44 / ML-KEM-512 through `ctypes`, plus HKDF, HMAC and transcripts.
  * `secure_tunnel.py`: AES-256-GCM record layer, matching `SecureTunnel.*`.
  * `session_registry.py`: one live tunnel per device ID.
  * `console.py`: thread-safe output, so each device's log prints as one block.
  * `authorized_devices.json`: the allowlist of device IDs and their 1,312-byte ML-DSA-44 public keys.
  * `build_native_libs.sh` + `host_shim/`: build `libmlkem512.so` and `libmldsa44.so` **offline** from `arduino_libraries/`.
  * `requirements.txt`: `cryptography`, for AES-GCM.
* **`arduino_libraries/`**: the two Arduino libraries used by both the ESP32 and the laptop.
  * `MLKEM512/`: `MLKEM512::` wrapper around the portable C sources of [mlkem-native](https://github.com/pq-code-package/mlkem-native) v2.0.0.
  * `MLDSA44/`: `MLDSA44::` wrapper around mldsa-native v1.0.0-beta2 (`MLD_CONFIG_REDUCE_RAM`).
* **`benchmarking/mutual_auth_benchmark/`**: Ed25519 vs. ML-DSA-44 benchmark on the ESP32 ([README](benchmarking/mutual_auth_benchmark/README.md)).

---

## Protocol Handshake Flow (ML-DSA-44 Mutual Authentication + Ephemeral ML-KEM-512)

1. **TCP Connection**: The ESP32 connects to the gateway over Wi-Fi on TCP port 9000.
2. **Message 1 (Client Hello, 850 B)** `[1B Ver] [1B AlgID=0x03] [16B DeviceID] [32B N_cli] [800B ek_cli_eph]`
   * The ESP32 generates a fresh **ephemeral ML-KEM-512 keypair** `(dk_cli_eph 1,632 B, ek_cli_eph 800 B)` with the hardware TRNG. A new keypair per handshake gives **forward secrecy**.
   * The gateway checks Version/AlgID (downgrade protection) and checks `DeviceID` against `authorized_devices.json`. Unknown devices are dropped here.
3. **Message 2 (Server Proof, 3,220 B)** `[32B N_srv] [768B ct] [2,420B ML-DSA-44 sig]`. The server authenticates first.
   * The gateway runs `(K, ct) = ML-KEM-512.Encaps(ek_cli_eph)`. This includes the FIPS 203 encapsulation-key modulus check, and a malformed `ek` aborts the handshake.
   * Server Transcript: `SHA-256("VPN-v1|SERVER|" || MSG1 (850 B) || N_srv || ct)` over 1,664 B of input. The gateway signs the digest with its ML-DSA-44 key.
   * The ESP32 verifies the signature against the pinned `TRUSTED_GATEWAY_PUBLIC_KEY` **before** decapsulating. Because `ek` and `ct` are both in the signed transcript, a man-in-the-middle cannot substitute either one.
   * The ESP32 runs `K = ML-KEM-512.Decaps(dk_cli_eph, ct)` and then wipes `dk_cli_eph`. Decapsulation uses implicit rejection: a bad `ct` produces a pseudorandom `K`, which the key-confirmation tags in MSG 3/4 then catch.
   * Both sides run HKDF-SHA256 (RFC 5869): `salt = SHA-256(N_cli || N_srv)`, `IKM = K`, which gives `K_confirm` and `K_session`.
4. **Message 3 (Client Proof, 2,452 B)** `[2,420B ML-DSA-44 sig] [32B tag]`
   * Client Transcript: `SHA-256("VPN-v1|CLIENT|" || MSG1 || MSG2)` over 4,084 B of input. The ESP32 signs it with its device key and adds `HMAC-SHA256(K_confirm, "VPN-v1|CLIENT-CONFIRM|" || H_cli)`.
5. **Message 4 (Server Verdict, 40 B)** `["AUTH_OK\n"] [32B HMAC(K_confirm, "VPN-v1|SERVER-CONFIRM|" || H_cli)]`, or `"AUTH_NO\n"` (8 B) if the client proof fails.
6. **AES-256-GCM Data Tunnel** keyed from `K_session`:
   * A separate key for each direction (HKDF-Expand): `K_c2s = HMAC-SHA256(K_session, "VPN-v1|TUNNEL|C2S" || 0x01)` and `K_s2c = HMAC-SHA256(K_session, "VPN-v1|TUNNEL|S2C" || 0x01)`.
   * Frame `[2B LEN][8B SEQ][ciphertext][16B tag]`. The nonce is `DIR (4B) || SEQ (8B)` and the AAD is `LEN || SEQ`, so the header is authenticated too. The maximum plaintext is 1,024 B per frame.
   * `SEQ` starts at 0 and must increase by exactly 1. Any tampered, replayed, reordered or oversized frame closes **that** session.

### ML-KEM-512 object sizes (FIPS 203)

| Object | Size | Layout |
| :--- | :---: | :--- |
| Encapsulation key `ek` | 800 B | `ByteEncode12(t_hat)` 768 B, then `rho` 32 B |
| Decapsulation key `dk` | 1,632 B | `dk_pke` 768 B, `ek` 800 B, `H(ek)` 32 B, `z` 32 B |
| Ciphertext `ct` | 768 B | `c1 = Compress_10(u)` 640 B, then `c2 = Compress_4(v)` 128 B |
| Shared secret `K` | 32 B | |

---

## Multiple ESP32s

Every ESP32 runs in its **own gateway thread**, so a problem with one device affects only that device:

| Situation | What happens |
|---|---|
| Device ID not in the allowlist | Only that connection is closed. The ESP32 notices at once and retries after 3 s, 6 s, 12 s, 24 s, 30 s |
| Wrong ML-DSA key / bad HMAC tag | That device gets `AUTH_NO`; the others keep working |
| Garbage, wrong version, or malformed ML-KEM key | That connection is closed |
| Device silent or too slow | Its handshake times out after 15 s |
| Same device connects again | The new tunnel replaces the old one |
| Device removed from `authorized_devices.json` while connected | Only that device is disconnected (checked every 5 s) |
| `authorized_devices.json` saved half-way or with a typo | The last valid allowlist is kept; nobody is disconnected |
| Tampered / replayed / oversized tunnel frame | Only that session is closed |
| Too many connections | 8 handshakes at once, 2 per IP, 5 new connections per IP per 10 s; extra connections are refused |
| An error while starting one connection | That connection is refused; the server and the other tunnels keep running |

---

## Setup and Run

### Requirements
* **Laptop:** Python 3, a C compiler (`gcc`/`clang`), and the `cryptography` package (from `requirements.txt`).
* **ESP32:** Arduino IDE 2.x with the **esp32 by Espressif Systems** board package. It includes libsodium (SHA-256/HMAC) and mbedTLS (AES-GCM). You also need the two libraries in `arduino_libraries/`.

### 1. Build the native libraries and start the gateway (laptop)
```bash
cd PQC_VPN/laptop_server
./build_native_libs.sh      # offline: builds libmlkem512.so + libmldsa44.so from ../arduino_libraries
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt   # one-time
.venv/bin/python server.py
```
The `.so` files are build output and are not committed to git; rebuild them on each laptop. The gateway prints its IP and listens on port **9000**.

### 2. Install the Arduino libraries and flash the ESP32
1. Copy **both** libraries into your Arduino libraries folder (`~/Arduino/libraries` on Linux, `~/Documents/Arduino/libraries` on Windows/macOS):
   ```bash
   cp -R PQC_VPN/arduino_libraries/MLDSA44 PQC_VPN/arduino_libraries/MLKEM512 ~/Arduino/libraries/
   ```
   Restart the Arduino IDE afterwards.
2. In `esp32_client/config.h`, set `WIFI_SSID`, `WIFI_PASSWORD`, `GATEWAY_IP` (printed by `server.py`) and a unique `DEVICE_ID` per board.
3. Open `esp32_client/esp32_client.ino`, select **ESP32 Dev Module** (240 MHz), upload, and open the Serial Monitor at **115200 baud**.

Command-line build (no library install needed):
```bash
arduino-cli compile --fqbn esp32:esp32:esp32 --libraries PQC_VPN/arduino_libraries PQC_VPN/esp32_client
```

### 3. Register each ESP32
On first boot each board creates its ML-DSA-44 key and keeps it in NVS flash (`vpn_pqc_id`). It prints the 1,312-byte **Device Public Key** on the Serial Monitor. Add it under the board's `DEVICE_ID` in `laptop_server/authorized_devices.json`. The gateway picks up the change without a restart.

> The committed `authorized_devices.json` holds the `esp32-01` key of the board used for the hardware test. A different board with the same ID will be rejected until you replace that key with its own.

---

## Implementation Notes

* **Randomness on the ESP32**: the bundled `*_native_config.h` files are the upstream configs with the changes marked `[ESP32 VPN]`: parameter sets 512 / 44, `MLD_CONFIG_REDUCE_RAM`, and randomness routed through the `MLK_/MLD_CONFIG_CUSTOM_RANDOMBYTES` hooks to `esp_fill_random()`. A custom hook is needed because the ESP32 core's libsodium already exports a global `randombytes()`.
* **Randomness on the laptop**: `build_native_libs.sh` compiles the *same* sources with the *same* configs. `host_shim/` supplies `esp_fill_random()` from the OS CSPRNG (`getentropy`). The server also draws the 32-byte ML-KEM encapsulation seed from `os.urandom` and calls `enc_derand`.
* **Memory**: ML-KEM state lives in the global `AuthManager` (`.bss`, about 6.5 KB including the cached MSG 1/MSG 2). Key generation and decapsulation run inside the 64 KB FreeRTOS task, where ML-DSA-44 signing is still the peak stack user. The libraries do no heap allocation.
* **Vendored source**: only the portable C files of mlkem-native v2.0.0 are included (no assembly backends), under its original license (`LICENSE.mlkem-native`).

## Verification Performed

* **Cross-implementation check**: mlkem-native `keypair_derand` / `enc_derand` / `dec`, including implicit rejection on a tampered `ct`, matches the independent `kyber-py` FIPS 203 implementation byte for byte over 25 random seeds.
* **Same keys as before**: the offline-built `libmldsa44.so` derives the same ML-DSA-44 gateway key from `SERVER_PRIVATE_SEED_HEX` as the earlier library, so the pinned key in `config.h` is unchanged.
* **Multi-device tests against the real gateway** (Python clients that mirror `AuthManager.cpp`, with different source IPs), 20/20 passed:
  * 3 devices complete the handshake at once and exchange encrypted pings.
  * Unregistered ID, wrong key, bad HMAC tag, garbage and malformed `ek` are rejected, and the other tunnels keep working.
  * Silent connections don't block a real device.
  * Tampered, replayed and oversized tunnel frames close only that session.
  * Same-ID re-login replaces the old tunnel.
  * A broken allowlist file keeps every tunnel up; a revoked device is disconnected and the others stay up.
  * The server survives a failure while starting a connection.
  * Log blocks never interleave.
* **Firmware**: compiles with `arduino-cli` for `esp32:esp32:esp32` (core 3.3.12) with no warnings under `--warnings all`. It uses 79% of flash.
* **Real hardware** (ESP32-D0WD rev 1.0 ↔ laptop over a phone hotspot), run before the multi-device changes: the full handshake completed. ML-DSA-44 signatures and both HMAC key-confirmation tags passed, both sides derived the same `K_session`, and the AES-256-GCM tunnel exchanged 50+ encrypted `STATUS_PING`/`SERVER_ACK` messages with sequence numbers advancing by one per frame in each direction.
