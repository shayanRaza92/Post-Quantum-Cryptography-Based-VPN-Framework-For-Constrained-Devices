# Phase B: Integrated Network Benchmark (Mutual Authentication Handshake)

Network benchmarking implementation and rigorous evaluation methodology measuring real-world mutual authentication handshakes between the ESP32 embedded client and laptop server over local Wi-Fi and TCP sockets.

While Phase A evaluated raw cryptographic primitives in isolated micro-benchmarks (zero I/O), Phase B profiles end-to-end handshake latency, transmission overhead, and packet exchange under real embedded Wi-Fi network conditions.

---

## Methodological Improvements & Corrections

Based on comprehensive architectural alignment with the production VPN system, Phase B has been updated from first principles:

1. **Protocol Alignment (Production 4-Message Handshake & Running Transcript):**
   - Eliminates legacy 6-stage surrogate challenges and dummy CONFIRM tags.
   - Enforces the production 4-message exchange:
     - `MSG 1`: Client Hello (50B) -> `[Version (1B) | AlgID (1B) | DeviceID (16B) | ClientNonce (32B)]`
     - `MSG 2`: Server Proof -> `[ServerNonce (32B) | ServerSig over Server Transcript]`
     - `MSG 3`: Client Proof -> `[ClientSig over Client Transcript]`
     - `MSG 4`: Server Verdict & Timing ACK (8B) -> `[Status (4B) | Server Crypto Time in us (4B)]`
   - **Running Transcript Hashing (TLS 1.3 style):**
     - Server Transcript: $\text{SHA-256}(\texttt{"VPN-v1|SERVER|"} \parallel \text{MSG 1} \parallel \text{ServerNonce})$
     - Client Transcript: $\text{SHA-256}(\texttt{"VPN-v1|CLIENT|"} \parallel \text{MSG 1} \parallel \text{MSG 2})$
     - Binds the exact wire bytes of the entire handshake sequence, preventing MITM modification or desynchronization.

2. **Elimination of TCP Delayed-ACK & Radio Artifacts:**
   - **Unified Single-Packet Framing:** Message headers (2B length) and payloads are bundled into a single write buffer (`uint8_t packet[2 + len]`), preventing TCP segment fragmentation and avoiding Nagle delayed-ACK timeouts (~40–200 ms).
   - **Socket Tuning:** `TCP_NODELAY` is enabled on both client and server sockets.
   - **Wi-Fi Power-Save Disabled:** `WiFi.setSleep(false)` prevents modem sleep clock jitter.
   - **Microsecond Polling Yields:** Polling waits use `delayMicroseconds(250)` instead of millisecond blocking.

3. **Empirical NULL-Crypto Control Baseline:**
   - Evaluates a control handshake (`Suite 0`) with identical wire frames (50B, 96B, 64B, 8B) and round trips but zero cryptographic computation.
   - Measures the empirical physical transport floor over Wi-Fi without relying on mathematical subtractions alone.

4. **Measured Server Cryptographic Latency:**
   - The laptop server precisely timestamps its internal signature verification and generation steps.
   - Server crypto duration (in microseconds) is returned to the ESP32 in the 8-byte MSG 4 ACK packet, enabling exact decomposition:
     $$T_{\text{overhead}} = T_{\text{total}} - T_{\text{client\_crypto}} - T_{\text{server\_crypto}}$$

5. **Dynamic Metric Tracking & Statistical Rigor:**
   - Replaces hard-coded bytes and 100% success constants with live byte counters and verified handshake success counters.
   - Explicit failure verdicts (Status = 0) prevent TCP stream stalls or cascade failures.
   - Every metric reports **Mean**, **Median**, **Standard Deviation ($\sigma$)**, **Min**, and **Max**.

---

## Test Suites Evaluated

| Suite | Description | Key Curve / Standard | Implementation Library | Wire Signature Format | Iterations ($N$) |
| :--- | :--- | :--- | :--- | :---: | :---: |
| **0. NULL Control** | Physical Wi-Fi transport baseline | None (zero compute) | Baseline raw sockets | None (dummy frames) | 50 |
| **1. Ed25519** | Modern Edwards curve | Twisted Edwards Curve25519 | libsodium (ESP32) / cryptography (Server) | 64 bytes (raw) | 50 |
| **2. ECDSA P-256** | NIST prime curve | NIST secp256r1 | ESP32 mbedTLS / cryptography (Server) | 70–72 bytes (DER) | 50 |
| **3. RSA-3072** | Classical modular exponentiation | PKCS#1 v1.5 with SHA-256 | ESP32 mbedTLS / cryptography (Server) | 384 bytes (raw) | 20 |

---

## Handshake Protocol Architecture

Each handshake iteration executes the 4-message mutual authentication sequence:

```
    ESP32 Client (Embedded)                              Laptop Server (Gateway)
       |                                                            |
       |  ---- [MSG 1] Client Hello (50B) ------------------------> | (Checks allowlist & AlgID)
       |       [Ver(1) | Alg(1) | DevID(16) | N_cli(32)]            |
       |                                                            | (Signs Server Transcript)
       |  <--- [MSG 2] Server Proof (96B) ------------------------- |
       |       [N_srv(32) | sigma_srv(64)]                          |
       |                                                            |
 (Verifies server sig)                                              |
 (Signs Client Transcript)                                          |
       |  ---- [MSG 3] Client Proof (64B) ------------------------> | (Verifies client sig)
       |       [sigma_cli(64)]                                      |
       |                                                            |
       |  <--- [MSG 4] Server Verdict ACK (8B) -------------------- | (Sends status & crypto time)
       |       [Status(4) | ServerCryptoTime_us(4)]                 |
       |                                                            |
```

---

## Standardized Metrics Reported

1. **`NET-1` Total Handshake Latency:** End-to-end wall-clock duration from initial Client Hello transmission to Verdict ACK reception (Mean, Median, $\sigma$, Min, Max).
2. **`NET-2` Handshake Wire Payload:** Total wire bytes transferred across the 4 messages per handshake (including 2-byte length-prefix framing).
3. **`NET-3` Client Cryptographic Time:** On-chip ESP32 compute time (verification of server signature + generation of client signature).
4. **`NET-4` Server Cryptographic Time:** Server-side compute time (generation of server signature + verification of client signature).
5. **`NET-5` Non-Crypto Overhead / Transit Latency:** Physical radio round-trip time, TCP stack buffering, and packet serialization overhead:
   $$T_{\text{overhead}} = T_{\text{total}} - T_{\text{client\_crypto}} - T_{\text{server\_crypto}}$$
6. **`NET-6` Handshake Success Rate:** Percentage of handshakes where all cryptographic proofs verified successfully.

---

## Instructions to Run the Benchmark

### 1. Start Server on Laptop
Ensure Python 3.9+ with `cryptography` installed:
```bash
python3 benchmark_server.py
```
Note the printed local IP address (e.g., `10.202.171.216`).

### 2. Configure and Flash ESP32
1. Open `Phase_B_Network_Benchmark.ino` in Arduino IDE or compile via CLI.
2. Verify Wi-Fi credentials (`WIFI_SSID`, `WIFI_PASSWORD`) and set `LAPTOP_IP` to your server's IP address.
3. Upload to the ESP32.
4. Open the Serial Monitor at `115200` baud to observe live iteration logs and the final summary table.

---

## Files in this Directory

* **`Phase_B_Network_Benchmark.ino`**: ESP32 firmware running all 4 benchmark suites with single-segment packet framing and unified 64-bit timing.
* **`ed25519_phaseB_yousuf.ino`**: Standalone Ed25519 benchmark sketch aligned with the 4-message protocol.
* **`benchmark_server.py`**: Python TCP gateway server executing transcript verification, server timing instrumentation, and statistical reporting.
* **`README.md`**: Technical specification, protocol layout, and benchmark guidelines.
