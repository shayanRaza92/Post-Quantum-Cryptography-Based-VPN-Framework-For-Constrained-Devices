# Drone Authentication Study: Signature Algorithms on the ESP32

This folder holds the experiments for our research on **authentication for drones**. We compare four signature algorithms that a drone could use to prove who it is:

* **RSA-3072**, **ECDSA P-256** and **Ed25519**: classical, used today, about 128-bit security
* **ML-DSA-44**: post-quantum (NIST FIPS 204), at a similar security level

and we compare the three **ML-DSA** levels with each other: **ML-DSA-44, ML-DSA-65 and ML-DSA-87**.

The existing VPN projects in this repository are not changed. Everything new is in this folder.

We work step by step and collect results first. The paper comes later.

| Step | What | Status |
|---|---|---|
| 1 | All six algorithms timed on one ESP32 under the same conditions: speed, sizes, memory, flash | **Done** (results in `results/e1/`) |
| 2 | How the time grows with message size, and the largest message the ESP32 can sign | **Done** (results in `results/e2/`) |
| 3 | The authentication messages on a real Wi-Fi link, captured with Wireshark | **Done** (results in `results/e3/`) |
| 4 | Sequence diagrams for the drone scenario | **Done** (results in `results/e4/`) |
| 5 | MPU6050 sensor: signed drone telemetry (simulated sensor data if no sensor is connected) | **Done** (results in `results/e5/`) |

---

## What is in this folder

```
Drone_Auth_Research/
├── arduino_libraries/MLDSA_Levels/   ML-DSA-44, -65 and -87 in one firmware (unmodified mldsa-native source)
├── firmware/sig_bench_unified/       the firmware for Steps 1, 2, 3 and 5
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

---

## Step 2: message size and the largest message

The same firmware does Step 2 when you send **P** instead of **S**. Nothing has to be changed in the code.

| Part | What | How |
|---|---|---|
| A | Time vs message size | Each algorithm signs and verifies the same messages of 64 B, 256 B, 1 KB, 4 KB, 16 KB and 64 KB, 100 times per size |
| B | Largest message the ESP32 can sign | A search for the biggest message that can still be kept in RAM, signed and verified. Each algorithm gets only the stack it was measured to need (+ 8 KB), and the message is placed in RAM inside that task, as in a real drone firmware. The limit that stopped it is reported |
| C | Calculated from A and B | The largest message that can be signed within 20, 50 or 100 ms, and how much data still fits next to the signature in one MAVLink 2 message (255 B), ESP-NOW frame (250 B / 1,470 B) or ESP32 TCP segment (1,436 B) |

**How to run it (about 20 minutes).** Upload the firmware (the same `sig_bench_unified.ino`), close the Serial Monitor, then:
```bash
python3 tools/capture_serial.py --port /dev/ttyUSB0 --experiment e2
python3 tools/analyze_payload.py results/e2/raw/payload_bench_<date>_<time>.log
```
The tables are in `results/e2/payload_bench_<date>_<time>/results.md` and the figure in its `figures/` folder.

---

## Step 3: authentication on a real Wi-Fi link (Wireshark)

The ESP32 plays the drone, the laptop the ground station. The ground station sends a random challenge; the drone signs `[challenge, drone id, clock, data]` and sends it back; the ground station checks the signature. This is done for every algorithm, for growing amounts of data, in two link styles:

* **udp**: the whole signed message as one UDP datagram. If it is bigger than one Wi-Fi packet (1,500 bytes), the network splits it into several packets.
* **mav**: the message cut into MAVLink-sized frames of at most 255 bytes, like a drone radio link.

Wireshark (`dumpcap`) records every packet. From the capture we measure, for each algorithm: packets per signed message, bytes on the wire, the time from challenge to verified signature, losses, and **the largest data that still fits in one packet with the signature**.

**How to run it (about 15 minutes):**
1. In `bench_config.h` set `ENABLE_LINK_TEST` to `1`. In `link_config.h` set your Wi-Fi name and password (the laptop must be on the same Wi-Fi). Upload, and close the Serial Monitor.
2. Terminal 1: `python3 tools/capture_serial.py --port /dev/ttyUSB0 --experiment e3` (starts the drone with `W` and saves its messages). Wait until it shows `META,drone_ip`.
3. Terminal 2: `python3 tools/gcs_link_test.py --iface wlo1` (the ground station; it starts the Wireshark capture itself).
4. When both are done: `python3 tools/analyze_link.py results/e3/raw/link_<date>_<time>`

To look at the packets in Wireshark with readable names: `wireshark -X lua_script:tools/wireshark/drone_auth.lua results/e3/raw/link_<date>_<time>/capture.pcapng`

Afterwards set `ENABLE_LINK_TEST` back to `0` and the Wi-Fi password back to the placeholder before committing.

---

## Step 4: sequence diagrams

Three diagrams that show who sends what, in which order, with the numbers measured in Steps 1–3 written on them:

* **fig8**: one authentication (challenge, sign, send, verify, result) with the time and size of each part.
* **fig9**: the same authentication as real packets, Ed25519 (1 frame) against ML-DSA-44 (10 frames), with times from the Step 3 Wireshark recording.
* **fig10**: where signatures are used in a whole drone mission (registration, before take-off, signed commands, signed sensor data).

To draw them again: `python3 tools/draw_sequence_diagrams.py` (writes PDF and PNG to `results/e4/figures/`). The explanation is in `results/e4/report/step4_progress_report.pdf`.

---

## Step 5: signed sensor telemetry (MPU6050)

A drone sends its sensor readings (accelerometer and gyroscope) many times per second. Step 5 measures what signing them costs on the ESP32:

* **sig1**: every sample is signed on its own.
* **sig10**: 10 samples are collected, then signed together (fewer signatures, but older data).
* **mavsign**: MAVLink 2's own message signing, which drones use today: a 13-byte signature on every packet, made with a key shared by the drone and the ground station ([mavlink.io](https://mavlink.io/en/guide/message_signing.html)). It is fast, but the shared key has to be set up safely first; the public-key authentication of Step 3 can do that once.

Each mode runs at 10, 50 and 100 samples per second, 10 seconds each. A high-priority sensor task takes the samples on a timer, and a separate task signs them. The firmware also runs one "simple loop" test (read the sensor, then sign, in one loop) to show what happens when signing is slower than the sample period. Measured: how many samples get signed, how old the data is when its signature is ready, and whether the samples are still taken on time.

**The sensor:** if an MPU6050 answers on I2C (SDA = GPIO 21, SCL = GPIO 22; on an ESP32duino these are the pins marked SDA and SCL next to AREF), it is read for real. If not, the firmware uses **simulated** samples: the same 14 bytes in the same layout as a real MPU6050. Signing only depends on how many bytes there are, not what they say. The log says which one was used (`META,sensor`), and also lists what it found on the I2C bus, which helps when checking the wiring.

**How to run it (about 12 minutes):**
1. Upload the firmware as usual (`ENABLE_LINK_TEST` stays `0`; no Wi-Fi is needed). Close the Serial Monitor.
2. `python3 tools/capture_serial.py --port /dev/ttyUSB0 --experiment e5`
3. `python3 tools/analyze_telemetry.py results/e5/raw/telemetry_bench_<date>_<time>.log`

Results go to `results/e5/<log name>/`: tables (`runs.csv`, `capacity.csv`, `radio.csv`, `results.md`) and figures fig11–fig14.

### Software versions

Arduino core for ESP32 3.3.12 (ESP-IDF 5.5.5), mbedTLS 3.6.6, libsodium (from ESP-IDF), mldsa-native v1.0.0-beta2 (portable C, `MLD_CONFIG_REDUCE_RAM`). The firmware prints the exact versions at the start of every log.
