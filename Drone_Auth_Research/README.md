# Drone Authentication Study: Signature Algorithms on the ESP32

This folder holds the experiments for our research on **authentication for drones**. We compare four signature algorithms that a drone could use to prove who it is:

* **RSA-3072**, **ECDSA P-256** and **Ed25519**: classical, used today, about 128-bit security
* **ML-DSA-44**: post-quantum (NIST FIPS 204), at a similar security level

and we compare the three **ML-DSA** levels with each other: **ML-DSA-44, ML-DSA-65 and ML-DSA-87**.

The existing VPN projects in this repository are not changed. Everything new is in this folder.

We work step by step and collect results first. The paper comes later.

| Step | What | Status |
|---|---|---|
| 1 | All six algorithms timed on one ESP32 under the same conditions: speed, sizes, memory, flash | **Ready to run** |
| 2 | How the time grows with message size, and the largest message the ESP32 can sign | Planned |
| 3 | The authentication messages on the network, captured with Wireshark | Planned |
| 4 | Sequence diagrams for the drone scenario | Planned |
| 5 | MPU6050 sensor: signed drone telemetry | Planned |

---

## What is in this folder

```
Drone_Auth_Research/
├── arduino_libraries/MLDSA_Levels/   ML-DSA-44, -65 and -87 in one firmware (unmodified mldsa-native source)
├── firmware/sig_bench_unified/       Step 1 firmware: times all six algorithms
├── tools/
│   ├── capture_serial.py             saves the ESP32 output to a log file and starts the run
│   ├── analyze_sig_bench.py          turns the log into tables (CSV + Markdown)
│   ├── flash_footprint.sh            flash size of each algorithm (needs no board)
│   ├── mldsa_vectors/                checks our ML-DSA build against dilithium-py
│   └── classical_vectors/            checks the classical test values with OpenSSL
└── results/                          everything measured
```

---

## Step 1: the six algorithms on one ESP32

### What is measured

| Measurement | How |
|---|---|
| Time to make a key, sign and verify | 1,000 times each (RSA key generation: 30 times, because one takes 4-30 seconds) |
| Median, p95, p99, maximum, spread | From every single measurement. The maximum matters for a drone, because it has fixed deadlines |
| Public key, secret key and signature size | In bytes |
| Peak stack and heap | For each operation, measured separately |
| Flash (program size) | How much each algorithm adds to the firmware |
| Correct results | Before timing, each algorithm must pass a known-answer test against an independent implementation |

### How we keep it fair

* **One firmware, one board, the same conditions** for all six algorithms. (Our two older benchmarks gave different Ed25519 times, 9.6 ms and 15.9 ms, because they were separate programs. This step replaces both.)
* The CPU is set to **240 MHz** and checked. Wi-Fi and Bluetooth are never started.
* Every measurement runs in a **fresh task on core 1** with the same stack size.
* **The same 1,000 messages** (64 bytes each, all different) are signed by every algorithm.
* "Sign" and "verify" always start **from the message**. For ECDSA and RSA, the SHA-256 hash of the message is included in the time; Ed25519 and ML-DSA hash inside the algorithm anyway.
* Nothing is printed while a timed loop runs.
* At the end, Ed25519 is timed again, to show that the conditions did not change during the run.

**One difference to report in the paper:** RSA and ECDSA use the ESP32's hardware for big-number maths and SHA-256, and Ed25519 uses the SHA hardware for its SHA-512. ML-DSA runs completely in software. This is how the ESP32 libraries work by default, and it favours the classical algorithms.

### Correctness checks (known-answer tests)

| Algorithm | Checked against |
|---|---|
| Ed25519 | RFC 8032, section 7.1, test 1 |
| ECDSA P-256 | RFC 6979, appendix A.2.5: the exact deterministic signature |
| RSA-3072 | A signature made by OpenSSL with a fixed test key |
| ML-DSA-44 / 65 / 87 | dilithium-py 1.5.1: our build gives byte-for-byte the same keys and signatures |

The ML-DSA check also runs on the laptop: `tools/mldsa_vectors/gen_mldsa_vectors.py` builds the same ML-DSA code for the laptop and compares it with dilithium-py. All three levels are identical.

### How to run it

**1. Install the ML-DSA library (once).** Copy the folder `arduino_libraries/MLDSA_Levels` into your Arduino libraries folder, `~/Arduino/libraries/`. Restart the Arduino IDE.

**2. Upload the firmware.**
1. Open `firmware/sig_bench_unified/sig_bench_unified.ino`.
2. Choose **Tools > Board > ESP32 Dev Module** and **Tools > CPU Frequency > 240MHz (WiFi/BT)**.
3. Click **Upload**.

**3. Do a quick test first (about 5 minutes).** In `bench_config.h`, set `BENCH_RUNS` to `20` and `RSA_KEYGEN_RUNS` to `2`, upload, and run step 4. If every known-answer test says PASS and nothing says ERROR, set them back to `1000` and `30` and upload again.

**4. Run and save the output (about 40-50 minutes).** Close the Arduino Serial Monitor (only one program can use the port), then:
```bash
cd Drone_Auth_Research
python3 tools/capture_serial.py --port /dev/ttyUSB0
```
It starts the benchmark and saves everything to `results/e1/raw/`. Keep the board powered and the laptop awake until it says "Done".

(You can also open the Serial Monitor and type `S` to start, but the output has more than 2,000 lines, so saving it with the script is easier.)

**5. Make the tables.**
```bash
python3 tools/analyze_sig_bench.py results/e1/raw/sig_bench_<date>_<time>.log
```
The tables are in `results/e1/sig_bench_<date>_<time>/results.md`. The CSV files next to it hold the same numbers.

### Flash size (already measured, no board needed)

Made with `bash tools/flash_footprint.sh`. Each line is the firmware with only that algorithm, minus the firmware with none. Test-only code (known-answer tests, test keys) is left out.

| Algorithm | Flash added |
|---|---:|
| Ed25519 | 22,620 B |
| ECDSA P-256 | 24,580 B |
| RSA-3072 | 39,088 B |
| ML-DSA-44 | 14,084 B |
| ML-DSA-65 | 13,808 B |
| ML-DSA-87 | 14,052 B |

The three ML-DSA levels need almost the same flash, because they run the same code with different parameters.

### Software versions

Arduino core for ESP32 3.3.12 (ESP-IDF 5.5.5), mbedTLS 3.6.6, libsodium (from ESP-IDF), mldsa-native v1.0.0-beta2 (portable C, `MLD_CONFIG_REDUCE_RAM`). The firmware prints the exact versions at the start of every log.
