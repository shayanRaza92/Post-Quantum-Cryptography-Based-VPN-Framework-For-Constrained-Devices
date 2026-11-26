# Test 6: Quantum Threat Demo (Shor's algorithm, simulated with Qiskit)

**Type: offline demonstration, toy size.** Nothing here touches the gateway, an ESP32 or the network.
It only simulates a quantum computer on the laptop.

**Goal:** show, in a way you can run, that

1. **Shor's algorithm breaks classical public-key cryptography** (RSA and the elliptic curves used by
   our classical VPN: X25519 and Ed25519), and that this lets an attacker **decrypt traffic recorded
   today** ("harvest now, decrypt later");
2. **Shor's algorithm does not break ML-KEM / ML-DSA**, the post-quantum algorithms of our PQC VPN,
   because their hard problem (Learning With Errors) has no hidden period for Shor to find.

> **Why only toy sizes?** A normal computer simulates a quantum computer by storing 2^n numbers for
> n qubits (16 bytes each). Memory doubles with every qubit. 19 qubits need 8 MB; this laptop (16 GB)
> can reach about 29 qubits. Real X25519 needs about 2,330 qubits and RSA-2048 about 4,099: that cannot
> be simulated at all. So the demos use **the same math with tiny numbers**. They show *how* the attack
> works, not that today's real keys are broken.

## What each script does

| Script | What it shows |
|---|---|
| `scripts/run_shor_factoring.py` | Shor's circuit factors 15, 21 and 35 (the problem behind RSA) |
| `scripts/run_harvest_now_decrypt_later.py` | A toy-size session of **our classical VPN** is recorded; later Shor recovers the ESP32's one-time private key from MSG 1 and **every recorded message is decrypted** |
| `scripts/run_pqc_vs_shor.py` | The same Shor circuit on a *group* problem (secret found) and on an *LWE* problem like ML-KEM / ML-DSA (secret not found: output is noise) |
| `scripts/run_memory_table.py` | How much memory the simulation needs, measured on this laptop and calculated for real targets |
| `scripts/qshor.py` | Shared code: circuits, the toy elliptic curve, the simulator call |

The harvest-now-decrypt-later demo imports the **real** message formats, key derivation (HKDF),
key-confirmation tags, SA binding and AES-256-GCM tunnel from `Non_PQC_VPN/laptop_server/`
(read-only). Only the key exchange is shrunk: the same elliptic-curve Diffie-Hellman as X25519, but on
a curve over p = 13 with 19 points instead of Curve25519.

## How to run

```
cd PEN_Testing/06_Quantum_Threat_Demo
python3 -m venv --system-site-packages .venv
.venv/bin/pip install -r requirements.txt          # Qiskit + Qiskit Aer (one time)
.venv/bin/python scripts/run_shor_factoring.py
.venv/bin/python scripts/run_harvest_now_decrypt_later.py
.venv/bin/python scripts/run_pqc_vs_shor.py
.venv/bin/python scripts/run_memory_table.py
```

Each script prints its result and saves a text file and a figure in `results/`.

## Results (run on this laptop, 26 Nov 2026, Qiskit 2.6.2 + Aer 0.18.4)

**Demo 1: Shor factors numbers (RSA's problem)** (`results/shor_factoring.txt`, `fig_shor_factoring.png`)

| N | Qubits | Memory for the quantum state | Period found | Factors | Shots that gave the factors |
|---|---:|---:|---:|---|---:|
| 15 | 12 | 64 KB | 4 | 3 x 5 | 76.9% |
| 21 | 15 | 512 KB | 6 | 3 x 7 | 81.7% |
| 35 | 18 | 4 MB | 12 | 5 x 7 | 65.4% |

**Demo 2: harvest now, decrypt later on our classical VPN (toy size)** (`results/harvest_now_decrypt_later.txt`, `fig_shor_ecdlp.png`)

* The attacker records MSG 1-4 (82 / 128 / 96 / 40 bytes, the real format) and 3 encrypted frames.
* Shor (19 qubits, 8 MB) recovers the ESP32's one-time private key from MSG 1: **88% of the runs gave
  the right key** (the exact calculation predicted 89%).
* With it, the attacker recomputes the shared secret, K_session and the SA, and **decrypts all three
  recorded messages** (GPS position, mission, battery). Signatures, HKDF, SA binding and AES-256-GCM
  do not help, because they all depend on the shared secret that Shor recovers.

**Demo 3: the same Shor circuit on a group problem vs. an LWE problem** (`results/pqc_vs_shor.txt`, `fig_pqc_vs_shor.png`)

| Problem (secret s, q = 13) | Like | Shor finds s |
|---|---|---:|
| f = a + s*b (exact algebra) | X25519, Ed25519, RSA | **86.2%** of shots |
| f = a + s*b + small error e | ML-KEM, ML-DSA | **28.4%** of shots (guessing: 7.7%) |

The small errors blur the exact pattern Shor needs, and the success rate falls sharply. In this tiny toy
(ONE secret number) some signal still survives; real ML-KEM-512 hides 512 numbers mod 3329, and no known
quantum algorithm (Shor or any other) can undo the errors efficiently. Without a quantum computer, the
same holds: without errors, linear algebra finds the secret instantly; with errors it gives a wrong
answer, and brute force grows 13x for every extra number (ML-KEM-512: about 10^1803 secrets, about
10^902 even with Grover's quantum search).

**Demo 4: memory** (`results/memory_table.txt`, `fig_memory.png`)

| Qubits | Memory for the quantum state | Measured peak on this laptop |
|---:|---:|---:|
| 16 | 1 MB | 129 MB (mostly Python + Qiskit itself, ~103 MB) |
| 20 | 16 MB | 143 MB |
| 24 | 256 MB | 386 MB |
| 26 | 1 GB | 1,152 MB |
| 29 | 8 GB | (largest that fits in 16 GB) |
| 2,330 (real X25519 / Ed25519) | 10^703 bytes | impossible |
| 4,099 (real RSA-2048) | 10^1,235 bytes | impossible |

Our demos use 12 to 19 qubits: **at most 8 MB** for the quantum state (about 0.1-0.2 GB for the whole
Python process), and each runs in a few seconds.

## Honest limits

* **Toy sizes only.** Real 255-bit curves and RSA-2048 cannot be simulated; they need a large,
  error-corrected quantum computer, which does not exist yet.
* **The multiplication / point-addition steps are exact "permutation" gates** (one gate per step). A real
  quantum computer would build them from many small gates; the result is the same, only the circuit is
  bigger.
* **Demo 3 loads the state after the oracle directly** into the simulator (the oracle is not built from
  gates), then applies the real quantum Fourier transforms. It is an **illustration** of why Shor does
  not apply to LWE, not a proof that lattice problems are hard. That confidence comes from many years of
  cryptanalysis and NIST's evaluation.
* Nobody can promise that a future quantum algorithm will never break lattices. Today, **no known quantum
  algorithm does**, and NIST standardised ML-KEM and ML-DSA for that reason.

## Sources

* P. W. Shor, "Polynomial-Time Algorithms for Prime Factorization and Discrete Logarithms on a Quantum
  Computer", *SIAM Journal on Computing* 26(5), 1997, pp. 1484-1509. https://arxiv.org/abs/quant-ph/9508027
* S. Beauregard, "Circuit for Shor's algorithm using 2n+3 qubits", *Quantum Information and Computation*
  3(2), 2003 (RSA-2048: 2 x 2048 + 3 = 4,099 qubits). https://arxiv.org/abs/quant-ph/0205095
* M. Roetteler, M. Naehrig, K. Svore, K. Lauter, "Quantum resource estimates for computing elliptic curve
  discrete logarithms", ASIACRYPT 2017, Abstract: at most 9n + 2 ceil(log2 n) + 10 qubits (n = 256:
  2,330). https://arxiv.org/abs/1706.06752
* NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA), 2024, Abstract: believed secure even against adversaries
  with a quantum computer. https://csrc.nist.gov/pubs/fips/203/final , https://csrc.nist.gov/pubs/fips/204/final
* NIST IR 8547 (ipd), Nov 2024, p. 8 lines 333-335 ("harvest now, decrypt later").
  https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf
