# Test 4 — AES-256-GCM Secure Tunnel & Rekeying Security

## 1. Purpose
Verify that, after the handshake, the AES-256-GCM tunnel keeps data confidential and
tamper-proof, rejects replayed/reordered/cross-direction frames, and that rekeying correctly
retires old keys.

## 2. Vulnerability under investigation
An authenticated-encryption channel fails if any of these hold: a modified ciphertext or tag is
accepted, a GCM nonce repeats (catastrophic for GCM), a frame can be replayed or reordered, a
frame from one direction is accepted in the other, or old keys still work after a rekey.

## 3. How the test works — OFFLINE
This test imports the **real** `secure_tunnel.SecureTunnel` from `PQC_VPN/laptop_server` and
drives a matched client/server tunnel pair with a fixed test key. Each script performs one
manipulation and checks the real code's reaction (it raises `TunnelError` on any violation).
**No network, no gateway, no ESP32** — it is a pure cryptographic analysis, so it is safe and
reproducible. Scripts are still dry-run by default; `--run` executes the offline analysis.

* `run_ciphertext_tamper.py` — flip a byte in the ciphertext, then in the 16-byte GCM tag; both
  must raise `TunnelError` ("AES-GCM authentication FAILED").
* `run_replay_reorder.py` — replay a frame (reuse a seq), skip a seq, and reorder two frames;
  each must raise `TunnelError` ("replay/reorder detected").
* `run_nonce_uniqueness.py` — seal many frames and confirm every nonce `DIR(4B)||SEQ(8B)` is
  unique within a key, that the two directions use different `DIR` values (1 vs 2), and that a
  rekey resets `SEQ` to 0 under a NEW key (so no nonce/key pair repeats).
* `run_cross_direction.py` — feed a C2S frame into the C2S decryptor (wrong side) and confirm it
  fails, proving per-direction keys prevent reflection/injection.
* `run_rekey_security.py` — rekey the tunnel, then confirm a frame sealed under the old key no
  longer decrypts, and that `REKEY_REQ` epoch must equal `epoch+1`.

## 4. Part of the PQC VPN involved
* [`secure_tunnel.py`](../../PQC_VPN/laptop_server/secure_tunnel.py) — `SecureTunnel.seal`,
  `.feed`, `_nonce` (`struct.pack(">IQ", direction, seq)`), `rekey`,
  `derive_rekeyed_session_key`; `DIR_C2S=1`, `DIR_S2C=2`, `MAX_PAYLOAD=1023`, `TAG_SIZE=16`.
* [`esp32_client/SecureTunnel.cpp`](../../PQC_VPN/esp32_client/SecureTunnel.cpp) — the mirrored
  ESP32 implementation (`mbedtls_gcm_crypt_and_tag` / `mbedtls_gcm_auth_decrypt`); the offline
  results predict its behaviour, confirmable later with a live capture.
* [`tunnel_session.py`](../../PQC_VPN/laptop_server/tunnel_session.py) — `_check_rekey_request`
  (epoch must be `tunnel.epoch+1`), rekey policy (`REKEY_MAX_MESSAGES=2000`,
  `REKEY_MAX_SECONDS=600`, `REKEY_MIN_INTERVAL=5`).

## 5. Files & modules in this test
* `modules/tunnel_harness.py` — wraps the real `SecureTunnel`, builds a client/server pair, and
  provides `flip_frame_byte()`. Shared by all scripts (no duplication).
* `scripts/run_ciphertext_tamper.py`, `run_replay_reorder.py`, `run_nonce_uniqueness.py`,
  `run_cross_direction.py`, `run_rekey_security.py`.

## 6. Tools & dependencies
* Python 3 + `cryptography` (provides `AESGCM`, as the gateway uses).
* No native libs needed (the tunnel is pure Python crypto); no target needed.

## 7. How it will be executed (future phase)
```bash
cd PEN_Testing/04_AES_GCM_Tunnel_Security
python scripts/run_ciphertext_tamper.py --dry-run
python scripts/run_ciphertext_tamper.py --run    # offline analysis, no network
```

## 8. Expected secure behaviour
* Tampered ciphertext/tag → `TunnelError` (frame rejected, session would be dropped).
* Replayed/skipped/reordered seq → `TunnelError`.
* Every `(key, nonce)` pair is unique; directions use distinct `DIR`; rekey resets seq under a
  new key.
* A cross-direction frame → authentication failure.
* After rekey, old-key frames no longer decrypt; wrong epoch rejected.

## 9. What constitutes a vulnerability
Any manipulation above that is **accepted** (decrypts and yields a frame), any repeated
`(key, nonce)` pair, or an old key still decrypting after a rekey.

## 10. Evidence & metrics to collect
* For each script: manipulation applied, exception raised (or not), and the decrypted output if
  it wrongly succeeded.
* The nonce-uniqueness script's dump of `(DIR, SEQ)` pairs across a rekey boundary.
* A scenario → expected → observed → verdict table for the report.
