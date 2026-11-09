# Ed25519 vs. ML-DSA-44 on the ESP32

This test compares the signature algorithm of our classical VPN (**Ed25519**) with the post-quantum one (**ML-DSA-44**, NIST FIPS 204) on the ESP32 at 240 MHz. In the handshake, the ESP32 signs once (to prove who it is) and verifies once (to check the gateway), so these are the two most important numbers.

---

## Algorithms

| Algorithm | Based on | Safe against quantum computers? | Library |
| :--- | :--- | :--- | :--- |
| **Ed25519** | Curve25519 (RFC 8032) | No | libsodium |
| **ML-DSA-44** | Lattices (NIST FIPS 204) | Yes (NIST security category 2) | mldsa-native, with its low-memory setting (`MLD_CONFIG_REDUCE_RAM`) |

---

## Test setup

* **Board:** ESP32-D0WDQ6, two cores, 240 MHz
* **Stack:** each test runs in its own task with a 64 KB stack, on core 1
* **How time is measured:** the ESP32's cycle counter. Time in ms = cycles / 240,000.
* **Number of runs:** 100 per algorithm. The message changes every run, because ML-DSA-44 signing time depends on the message (see below).

---

## What we measured

| ID | What | How |
| :--- | :--- | :--- |
| SIG-1 | Time to make a key pair | Cycle counter, 100 runs (mean, median, spread, min-max) |
| SIG-2 | Key sizes | Public key size (32 B vs. 1,312 B) and secret key size (64 B vs. 2,560 B) |
| SIG-3 | Time to sign | Cycle counter, 100 different messages |
| SIG-4 | Signature size | Bytes sent over the network (64 B vs. 2,420 B) |
| SIG-5 | Time to verify | Cycle counter, 100 runs |
| SIG-6 | Cost per handshake | Sign + verify (SIG-3 mean + SIG-5 mean) |
| SIG-7a | Heap memory while signing and verifying | Highest heap use |
| SIG-7b | Heap memory while making keys | Highest heap use |
| SIG-8 | Stack memory | Highest stack use (the test's own buffers are kept off the stack so they do not count) |
| SIG-9 | Correct results | Ed25519: official RFC 8032 test vector. ML-DSA-44: a key made from a fixed seed must match the expected bytes, and a signature with one changed bit must be rejected |

The expected ML-DSA-44 bytes used in SIG-9 have been checked against dilithium-py, a separate implementation of FIPS 204. They match.

---

## Results (ESP32 at 240 MHz, 100 runs)

| ID | What | Ed25519 | ML-DSA-44 | Comparison |
| :--- | :--- | :---: | :---: | :---: |
| SIG-1 | Make key pair (mean) | 13.36 ms | **12.69 ms** | ML-DSA-44 is 1.05 times faster |
| | Make key pair (median) | 13.36 ms | **12.67 ms** | |
| | Make key pair (spread / min-max) | 0.02 ms (13.3-13.4 ms) | 0.14 ms (12.4-13.0 ms) | |
| SIG-2 | Public key size | **32 B** | 1,312 B | 41 times larger |
| | Secret key size | **64 B** | 2,560 B | 40 times larger (or keep only the 32 B seed) |
| SIG-3 | Sign (mean) | **15.91 ms** | 56.76 ms | 3.6 times slower |
| | Sign (median) | **15.91 ms** | 47.36 ms | 3.0 times slower |
| | Sign (spread / min-max) | 0.01 ms (15.9-15.9 ms) | 41.52 ms (18.8-236.9 ms) | ML-DSA-44 varies a lot (see below) |
| SIG-4 | Signature size | **64 B** | 2,420 B | 38 times larger (needs 2 TCP packets) |
| SIG-5 | Verify (mean) | 20.73 ms | **13.39 ms** | **ML-DSA-44 is 1.55 times faster** |
| | Verify (median) | 20.74 ms | **13.39 ms** | |
| | Verify (spread / min-max) | 0.20 ms (20.3-21.1 ms) | **0.00 ms (13.4-13.4 ms)** | ML-DSA-44 always takes the same time |
| SIG-6 | Sign + verify per handshake | **36.64 ms** | 70.15 ms | 1.9 times more |
| SIG-7a | Heap while signing and verifying | **0 B** | **0 B** | Neither uses heap |
| SIG-7b | Heap while making keys | **0 B** | **0 B** | Neither uses heap |
| SIG-8 | Stack used | **3,908 B** (about 3.8 KB) | 34,800 B (about 34 KB) | Fits in a 64 KB task stack |
| SIG-9 | Correct results | **PASS** | **PASS** | |

---

## What the results mean

1. **ML-DSA-44 verifies faster than Ed25519** (13.39 ms vs. 20.73 ms). The ESP32 has to verify the gateway's signature in every handshake, so this helps. ML-DSA-44 verification always takes exactly the same time.
2. **ML-DSA-44 also makes keys a little faster** (12.69 ms vs. 13.36 ms). This only happens once, when a device starts for the first time.
3. **ML-DSA-44 signing time jumps around.** It is between 18.8 ms and 236.9 ms, with a median of 47.36 ms. This is how ML-DSA works: it makes a candidate signature, and if that candidate could leak something about the secret key, it throws it away and tries again. Some messages need one try, others need several. Ed25519 always takes 15.91 ms.
4. **In total, one post-quantum handshake costs the ESP32 70.15 ms of signing and verifying**, about 1.9 times Ed25519. That is still much faster than the older classical options: ECDSA P-256 needs 470.09 ms and RSA-3072 needs 388.27 ms (see `Non_PQC_VPN/benchmarking/mutual_auth_benchmark/`).
5. **The real costs are size and stack.** The ML-DSA-44 public key and signature are about 40 times bigger than Ed25519's. Signing needs about 34 KB of stack, which is why the post-quantum ESP32 code runs in its own task with a 64 KB stack. Neither algorithm uses any heap memory.

---

## Output from the ESP32

![Summary table on the Serial Monitor](screenshots/terminal_summary_table.png)

---

## Graphs

### Time to make a key pair (SIG-1)
![Key generation time](graphs/fig_keygen_mean.png)

### Key sizes (SIG-2)
![Key sizes](graphs/fig_public_key_wire_size.png)

### Time to sign (SIG-3)
![Signing time](graphs/fig_signing_latency.png)

### Signature size (SIG-4)
![Signature size](graphs/fig_signature_wire_size.png)

### Time to verify (SIG-5)
![Verification time](graphs/fig_verify_latency.png)

### Sign + verify per handshake (SIG-6)
![Sign and verify time](graphs/fig_crypto_auth_cost.png)

### Heap memory (SIG-7a and SIG-7b)
![Heap use](graphs/fig_heap_steady_state.png)

### Stack memory (SIG-8)
![Stack use](graphs/fig_stack_usage.png)

---

## How to run it

1. Open `mutual_auth_benchmark.ino` in the Arduino IDE.
2. Choose **Tools > Board > ESP32 Dev Module** and set the CPU frequency to **240 MHz**.
3. Upload, then open the **Serial Monitor** at **115200 baud**.
