# PEN_Testing — Penetration-Testing Framework for the PQC VPN

This folder is a **self-contained, authorised-lab penetration-testing framework** for the
post-quantum VPN implemented in [`../PQC_VPN/`](../PQC_VPN/). It is part of our Final Year
Project (FYP) security evaluation.

> **Status: PREPARATION PHASE.** Nothing in this folder has been executed. No packets have
> been sent to the gateway, no handshakes have been attempted, no fuzzing has been done, and
> no ESP32 flash has been extracted. Every script defaults to **dry-run / preparation mode**
> and refuses to touch a live target until it is explicitly pointed at an authorised lab
> address and run with an explicit `--run` flag.

## What is being tested

The target is the PQC VPN in `../PQC_VPN/`:

* **ESP32 client firmware** (`PQC_VPN/esp32_client/`, Arduino/C++).
* **Python laptop gateway** (`PQC_VPN/laptop_server/`).
* **ML-KEM-512** (FIPS 203) for post-quantum key exchange.
* **ML-DSA-44** (FIPS 204) for mutual authentication.
* **HKDF-SHA256** for session-key derivation.
* **AES-256-GCM** for the encrypted tunnel, with **in-tunnel rekeying**.

The classical VPNs (`../Non_PQC_VPN/`, `../Non_PQC_VPN_DHT22/`, `../Non_PQC_VPN_ESP32_Gateway/`)
are **out of scope** and must not be modified.

## The five test categories

| # | Folder | What it checks | Security property |
|---|--------|----------------|-------------------|
| 1 | [`01_Server_Key_Security/`](01_Server_Key_Security/) | Gateway private seed, Wi-Fi creds, git-history secrets, key loading | Key confidentiality / secure configuration |
| 2 | [`02_ESP32_Hardware_Security/`](02_ESP32_Hardware_Security/) | NVS key storage, flash encryption, Secure Boot, UART/JTAG, firmware extraction | Device identity protection |
| 3 | [`03_Handshake_Protocol_Security/`](03_Handshake_Protocol_Security/) | 4-message handshake: MITM, replay, downgrade, key substitution, transcript integrity | Mutual authentication + key-exchange integrity |
| 4 | [`04_AES_GCM_Tunnel_Security/`](04_AES_GCM_Tunnel_Security/) | Ciphertext/tag tampering, nonce uniqueness, replay, reorder, cross-direction, rekeying | Confidentiality + integrity + replay protection |
| 5 | [`05_Gateway_DoS_Resilience/`](05_Gateway_DoS_Resilience/) | Concurrent-handshake caps, per-IP limits, rate limiting, slowloris, cleanup | Availability / resource exhaustion |

Each category folder has its own `README.md` that fully explains the test (purpose,
vulnerability, mechanism, affected source files, tools, execution, expected secure behaviour,
what counts as a vulnerability, and evidence to collect).

## Layout

```
PEN_Testing/
├── README.md                 # this file
├── TESTING_METHODOLOGY.md     # overall methodology, rules of engagement, ethics
├── TEST_RESULTS_TEMPLATE.md   # fill-in template for recording findings
├── requirements.txt           # Python dependencies for future execution
├── config.example.json        # copy to config.json and set YOUR authorised lab target
├── common/                    # shared helpers used by several tests (no duplication)
│   ├── target_config.py       # loads config.json, enforces the lab-only safety gate
│   └── pqc_paths.py           # locates the PQC_VPN source so tests import the REAL code
├── 01_Server_Key_Security/
├── 02_ESP32_Hardware_Security/
├── 03_Handshake_Protocol_Security/
├── 04_AES_GCM_Tunnel_Security/
└── 05_Gateway_DoS_Resilience/
```

Every category folder contains `scripts/` (runnable entry points), `reports/` (where
evidence/output is written — empty until a test is run), and, for the protocol/tunnel/DoS
tests, `modules/` (reusable logic so scripts don't duplicate each other).

## Before you run anything (future phase)

1. `pip install -r requirements.txt` (do this in a venv — see methodology doc; **do not**
   change the VPN's own environment).
2. `cp config.example.json config.json` and set `target.host`/`target.port` to **your own
   lab gateway**, and set `authorised: true` to confirm you own/control the target.
3. Build the PQC native libs if a test needs the real crypto
   (`../PQC_VPN/laptop_server/build_native_libs.sh`).
4. Read the category `README.md`, then run its script with `--dry-run` first. Only add
   `--run` once the dry-run output is understood.

See [`TESTING_METHODOLOGY.md`](TESTING_METHODOLOGY.md) for the full rules of engagement.
