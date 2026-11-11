# Test 3 — Handshake Authentication & Protocol Security

## 1. Purpose
Verify that the four-message PQC handshake provides genuine mutual authentication and that no
tampering, replay, downgrade, or key substitution lets an attacker establish or hijack a session.

## 2. Vulnerability under investigation
A handshake is secure only if **every** byte that matters is authenticated and bound to the
session. We probe for the classic failure modes: accepting a tampered server/client proof,
accepting a replayed proof from an old session, negotiating a weaker algorithm, or accepting a
substituted public key / KEM ciphertext.

## 3. How the test works
Each attack is one script that drives a real (or, in dry-run, a described) handshake against a
**lab** gateway, changing exactly one thing:

* **MITM tamper** (`run_mitm_tamper.py`) — flip bytes in MSG 2 (server nonce, KEM ciphertext, or
  ML-DSA signature) and check the client/gateway rejects it; and flip bytes in a forwarded MSG 1
  to confirm the signed transcript catches it.
* **Replay** (`run_replay_attack.py`) — capture a valid MSG 3 (client proof) and replay it in a
  fresh session; it must fail because each session uses fresh nonces bound into the transcript.
* **Downgrade** (`run_downgrade_attack.py`) — send MSG 1 with a different version byte or
  `Algorithm ID` (e.g. `0x01` classical); the gateway must refuse.
* **Key substitution** (`run_key_substitution.py`) — present a device ID from the allowlist but
  sign MSG 3 with a different ML-DSA key, and separately substitute the KEM ciphertext; both must
  be rejected (`AUTH_NO`).

All four import the shared `modules/` so the honest parts of the handshake are built identically
from the real PQC_VPN code and only the attacked field differs.

## 4. Part of the PQC VPN involved
* [`tunnel_session.py`](../../PQC_VPN/laptop_server/tunnel_session.py) — `_receive_client_hello`
  (version/alg/device-ID checks), `_send_server_proof`, `_verify_client_proof`, `_send_verdict`.
* [`crypto_engine.py`](../../PQC_VPN/laptop_server/crypto_engine.py) — `encapsulate`,
  `derive_session_keys`, `build_server_transcript`, `build_client_transcript`,
  `verify_client_transcript`, `compute_confirmation_tag`.
* [`config.py`](../../PQC_VPN/laptop_server/config.py) — message sizes, `PROTOCOL_VERSION=0x01`,
  `ALGORITHM_ID=0x03`, transcript labels.
* ESP32 side: [`AuthManager.cpp`](../../PQC_VPN/esp32_client/AuthManager.cpp) verifies the server
  signature **before** decapsulating.

## 5. Files & modules in this test
* `modules/protocol_constants.py` — message sizes/offsets, cross-checked against `config.py`.
* `modules/handshake_client.py` — builds a real MSG 1 (real ML-KEM keygen), socket helper,
  MSG 2 / verdict parsing. Shared by every script.
* `scripts/run_mitm_tamper.py`, `run_replay_attack.py`, `run_downgrade_attack.py`,
  `run_key_substitution.py` — one attack each.

## 6. Tools & dependencies
* Python 3 + `cryptography` (from `requirements.txt`).
* The built native libs in `PQC_VPN/laptop_server/` (`libmlkem512.so`, `libmldsa44.so`).
* Optional: Wireshark/tshark to capture the exchange as evidence.

## 7. How it will be executed (future phase)
```bash
cd PEN_Testing/03_Handshake_Protocol_Security
python modules/protocol_constants.py            # verify constants match source
python scripts/run_downgrade_attack.py --dry-run
python scripts/run_downgrade_attack.py --run    # needs config.json authorised + lab target
```
Every script is dry-run by default and refuses a live target unless `config.json` has
`authorised: true` and `--run` is passed.

## 8. Expected secure behaviour
* Any single-byte change to MSG 2 → the ESP32 rejects the server signature and aborts.
* Any change to the forwarded MSG 1 → MSG 3 verification fails on the gateway.
* A replayed MSG 3 in a new session → `AUTH_NO`.
* A wrong version/algorithm byte → connection dropped before any crypto.
* A device ID signed with the wrong key, or a substituted KEM ciphertext → `AUTH_NO` / key
  confirmation failure.

## 9. What constitutes a vulnerability
Any of the above being **accepted**: a tampered or replayed proof that yields `AUTH_OK`, a
successful downgrade, or a session established with a substituted key.

## 10. Evidence & metrics to collect
* For each scenario: the field changed, bytes sent, and the gateway/client response
  (`AUTH_OK`/`AUTH_NO`/disconnect).
* A pcap of each run.
* A table of scenario → expected → observed → verdict for the report.
