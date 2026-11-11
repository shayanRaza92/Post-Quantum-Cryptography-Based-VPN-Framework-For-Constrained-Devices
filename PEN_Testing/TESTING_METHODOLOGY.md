# Testing Methodology & Rules of Engagement

This document describes how the PQC VPN penetration test is organised, the ethical and safety
rules that govern it, and how each phase maps to a recognised security property. It is written
so it can go directly into the FYP report and be explained to the supervisor.

## 1. Objective

Evaluate whether the post-quantum VPN in `../PQC_VPN/` meets the security goals it was designed
for, by attempting (in an authorised lab) to break each of the following properties:

1. **Confidentiality of long-term keys** (gateway seed, device seed).
2. **Mutual authentication** of ESP32 and gateway (ML-DSA-44).
3. **Key-exchange integrity and forward secrecy** (ephemeral ML-KEM-512 + HKDF).
4. **Data confidentiality, integrity and replay protection** (AES-256-GCM tunnel + rekeying).
5. **Availability** of the gateway under resource pressure.

## 2. Methodology (phased, non-destructive first)

We follow a standard, low-risk-to-high-risk progression modelled on the OWASP Testing Guide,
the PTES (Penetration Testing Execution Standard) phases, and NIST SP 800-115:

| Phase | Activity | Risk | This framework |
|-------|----------|------|----------------|
| A | **Information gathering / code review** | None | Reading `PQC_VPN/` source, mapping message formats and limits |
| B | **Static analysis** | None | Secret scanning (Test 1), config inspection (Test 2) |
| C | **Offline cryptographic analysis** | None | Protocol/tunnel logic checked against the *real* imported modules, no network |
| D | **Active lab testing** | Controlled | MITM, replay, fuzzing, rekey abuse, bounded DoS — only against our own lab target |
| E | **Hardware testing** | Physical | ESP32 flash/JTAG inspection on our own board |

The current deliverable covers **Phases A–C as scaffolding**: the code review is done, the
scripts and modules are written to match the real implementation, but **no active test (Phase
D/E) has been executed.**

## 3. Rules of engagement (mandatory)

* **Authorised targets only.** Every active script loads `config.json` and refuses to run
  unless `authorised: true` and a target host/port are explicitly set. The target must be a
  gateway and ESP32 that we own and operate on an isolated lab network.
* **Isolated network.** Active testing is done on a private lab LAN / dedicated AP, never on a
  shared or production network.
* **Dry-run by default.** Every active script starts in `--dry-run` mode and only describes
  what it would do. Live action requires an explicit `--run` flag.
* **No unrestricted flooding.** DoS scripts (Test 5) have conservative hard-coded caps, a
  required `--max-requests`, and refuse to exceed a small ceiling. They exist to *probe the
  documented limits*, not to take the service down.
* **No destructive hardware operations** in this phase. Test 2 inspects configuration and
  documents commands; it does not erase, re-flash, or glitch the device.
* **Do not modify the target.** The framework never edits files under `PQC_VPN/` or the
  classical VPN folders, and never changes keys, configs, or the Python environment of the VPN.
* **Containment.** All output/evidence is written under each test's `reports/` folder.

## 4. Environment isolation

The VPN gateway uses its own `cryptography` install. To avoid touching it, create a **separate**
virtual environment for the pen-test framework:

```bash
cd PEN_Testing
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Tests that need the real ML-KEM / ML-DSA code import it from `../PQC_VPN/laptop_server/` via
`common/pqc_paths.py` (read-only import), and expect the native `.so` libraries to have been
built there already. We never rebuild or move them.

## 5. Mapping to security properties (for the report)

| Test | STRIDE category | CIA property | Primary claim under test |
|------|-----------------|--------------|--------------------------|
| 1 Server key | Information disclosure | Confidentiality | Gateway private key is not recoverable from the repo/config |
| 2 ESP32 hardware | Tampering / Info disclosure | Confidentiality/Integrity | Device signing key is not extractable from flash |
| 3 Handshake | Spoofing / Tampering | Authentication/Integrity | Only genuine, un-tampered handshakes succeed |
| 4 Tunnel | Tampering / Repudiation | Confidentiality/Integrity | No data is readable, forgeable, replayable, or reorderable |
| 5 DoS | Denial of service | Availability | Documented limits bound an attacker's resource impact |

## 6. Evidence & metrics

For each test we collect: the exact command run, the target, timestamps, raw output/pcap, a
pass/fail verdict against the "expected secure behaviour" in that test's README, and any
deviation. The [`TEST_RESULTS_TEMPLATE.md`](TEST_RESULTS_TEMPLATE.md) standardises this.

## 7. Scope boundaries

In scope: everything under `../PQC_VPN/`. Out of scope: the classical VPN folders, the Wi-Fi
infrastructure itself, the host OS beyond the gateway process, and any third party.
