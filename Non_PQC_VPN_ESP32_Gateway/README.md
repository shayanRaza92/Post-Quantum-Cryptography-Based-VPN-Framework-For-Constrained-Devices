# Classical VPN: ESP32 Gateway (no laptop)

The same classical VPN as [`Non_PQC_VPN/`](../Non_PQC_VPN/README.md), but here **one ESP32 is the gateway** and does the laptop's job. The other ESP32s are clients.

```
   [ESP32 client: esp32-01] ─┐
   [ESP32 client: esp32-02] ─┼── Wi-Fi "ESP32-VPN-GW" ──>  [ESP32 GATEWAY]  192.168.4.1 : 9000
   [ESP32 client: esp32-03] ─┘
```

* The gateway creates its **own Wi-Fi network** (SoftAP). You need no router, phone hotspot or laptop.
* The **handshake is unchanged**: the same 4 messages (Ed25519 mutual authentication, X25519 ephemeral key exchange, HKDF-SHA256, HMAC key confirmation). The client firmware only has a different Wi-Fi network and gateway IP.
* The gateway uses **the same identity seed** as the laptop gateway, so its public key (`191A242D…B17673BA`) is the one already pinned in every client.

---

## Folder Layout

| Path | What it is |
|---|---|
| `esp32_gateway/` | Gateway firmware (C++ version of `Non_PQC_VPN/laptop_server/`) |
| `esp32_gateway/gateway_config.h` | Wi-Fi access point, allowlist, identity seed, limits |
| `esp32_gateway/VpnGateway.*` | Accept loop, DoS limits, Serial commands (like `server.py`) |
| `esp32_gateway/GatewaySession.*` | Handshake and tunnel for one client, in its own FreeRTOS task (like `tunnel_session.py`) |
| `esp32_gateway/GatewayTunnel.*` | Gateway side of the AES-256-GCM tunnel (like `secure_tunnel.py`) |
| `esp32_gateway/GatewayCrypto.*` | Ed25519, X25519, HKDF, HMAC, transcripts (like `crypto_engine.py`) |
| `esp32_gateway/Allowlist.*` | Authorized devices with runtime revoke/allow (like `authorized_devices.json`) |
| `esp32_gateway/SessionRegistry.*` | One live tunnel per device ID (like `session_registry.py`) |
| `esp32_gateway/Log.*` | Thread-safe Serial output: each handshake prints as one block (like `console.py`) |
| `esp32_client/` | Client firmware: a copy of `Non_PQC_VPN/esp32_client/` (including `SecureTunnel`, AES-256-GCM) set up for the ESP32 gateway |
| `sequence_diagram.png` | Full protocol flow: Wi-Fi join, handshake, tunnel keys, encrypted frames, in-tunnel rekeying, teardown |

![Protocol Sequence Diagram](sequence_diagram.png)

---

## Setup (Arduino IDE)

**Requirements:** Arduino IDE 2.x and the **esp32 by Espressif Systems** board package (Boards Manager). libsodium comes with the ESP32 board package, so no extra library is needed. You need at least 2 ESP32 boards: 1 gateway and 1 or more clients.

### 1. Flash the gateway
1. Open `esp32_gateway/esp32_gateway.ino`.
2. Optional: change `AP_SSID` / `AP_PASSWORD` in `gateway_config.h`. The password needs 8 or more characters.
3. Select **Tools → Board → esp32 → ESP32 Dev Module** and the board's port, then click **Upload**.
4. Open the Serial Monitor at **115200 baud** with line ending **"Newline"**. You should see:
   ```
   Wi-Fi SSID        : ESP32-VPN-GW
   Gateway IP        : 192.168.4.1
   Gateway Public Key: 191A242DDD267E20588D076B12F44C834FDDC7C53D8678922EB17759B17673BA
   ```

### 2. Flash each client
1. Open `esp32_client/esp32_client.ino`.
2. In `config.h`, set a **different `DEVICE_ID` for each board** (`esp32-01`, `esp32-02`, `esp32-03`). Leave `WIFI_SSID`, `WIFI_PASSWORD` and `GATEWAY_IP` (`192.168.4.1`) as they are unless you changed them on the gateway.
3. Upload. On its first boot the client prints its **Device Public Key**.

### 3. Register a new client
Each board makes its own key the first time it boots and keeps it in flash. Boards that were already registered with the laptop gateway keep their keys, and those keys are already in `gateway_config.h`. For a new board:
1. Copy the `Device Public Key` from the client's Serial Monitor.
2. Add `{ "esp32-04", { 0x.., ... } }` to `AUTHORIZED_DEVICES` in `gateway_config.h`.
3. Re-flash the gateway.

---

## Gateway Serial Commands

Type these into the gateway's Serial Monitor:

| Command | Effect |
|---|---|
| `help` | List the commands |
| `status` | Free memory, number of Wi-Fi clients, active tunnels |
| `list` | Allowlist with each device ALLOWED / REVOKED |
| `sessions` | Devices that have a live tunnel |
| `revoke esp32-02` | Block the device **and disconnect it now**. Saved in flash, so it survives a reboot |
| `allow esp32-02` | Allow a revoked device again |
| `kick esp32-02` | Disconnect the device once (it reconnects by itself) |

---

## Multi-Device Behaviour

Every client runs in its **own FreeRTOS task**, so a problem with one client affects only that client:

| Situation | What happens |
|---|---|
| Device ID not in the allowlist, or revoked | Only that connection is closed. The client notices at once and retries after 3 s, 6 s, 12 s, 24 s, 30 s |
| Wrong key / bad signature / bad HMAC tag | That client gets `AUTH_NO`; the others keep working |
| Garbage or wrong protocol version | That connection is closed |
| Client silent or too slow | Its handshake times out after 10 s |
| Same device connects again | The new tunnel replaces the old one |
| `revoke <id>` while connected | Only that device is disconnected |
| Tampered, replayed, reordered or oversized encrypted frame | Only that session is closed |
| Client skips rekeying (over 200 messages or 10 min per key), rekeys too often, or sends a bad rekey | Only that session is closed |
| No data for 30 s | That tunnel is closed (clients ping every 1.5 s) |
| Too many connections | Limits: 6 sessions in total, 4 handshakes at once, 2 per IP. Extra connections are refused |
| Gateway out of memory for a new client | Only the new client is refused |
| Gateway reboots | Clients wait for its Wi-Fi to come back, then reconnect by themselves |

---

## Security Notes
* `GATEWAY_PRIVATE_SEED` is in the source code so that the clients' pinned key stays the same as with the laptop gateway. Anyone who reads it can pretend to be the gateway. For a real deployment, generate a new seed, keep it out of the repository, and update `TRUSTED_GATEWAY_PUBLIC_KEY` in the clients.
* The tunnel is **encrypted with AES-256-GCM**, the same design as `Non_PQC_VPN/` and `PQC_VPN/`: one key per direction derived from `K_session`, a 64-bit sequence number in every frame, and the 16-byte GCM tag checked before anything is used. Both ESP32s use the hardware AES engine through mbedTLS.
* **In-tunnel rekeying** works exactly as in [`Non_PQC_VPN/`](../Non_PQC_VPN/README.md): every 100 messages or 5 minutes the client runs a fresh X25519 exchange inside the tunnel (`REKEY_REQ` / `REKEY_RESP`), both sides switch to new keys, and the old keys are wiped. The gateway's limits are `REKEY_MAX_MESSAGES`, `REKEY_MAX_MS` and `REKEY_MIN_INTERVAL_MS` in `gateway_config.h`.
