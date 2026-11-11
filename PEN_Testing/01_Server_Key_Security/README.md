# Test 1 — Server Private-Key Exposure & Configuration Security

## 1. Purpose
Determine whether the gateway's long-term private cryptographic material or other sensitive
configuration can be recovered by anyone who obtains the repository or the gateway host.

## 2. Vulnerability under investigation
The gateway's ML-DSA-44 identity keypair is derived deterministically from a 32-byte seed. If
that seed, or Wi-Fi credentials, are hard-coded in source or committed to git history, an
attacker who reads the repo can **reconstruct the gateway's private signing key** and run a
rogue gateway that every ESP32 will trust — defeating authentication entirely.

## 3. How the test works
Static, non-network analysis in three parts:
1. **Known-secret check** — confirm whether `SERVER_PRIVATE_SEED_HEX` is a real, usable seed by
   reading it from `config.py` (string inspection only; we do *not* derive or print the private
   key) and flag it as a committed secret.
2. **Secret scanning** — run `gitleaks` / `trufflehog` across the working tree and the full git
   history to catch this seed, Wi-Fi passwords, or any other secret in past commits.
3. **Configuration review** — inspect how the seed is loaded (env var vs. hard-coded), whether
   `config.h` contains real Wi-Fi credentials, and whether `.gitignore` actually protects the
   sensitive build artefacts.

## 4. Part of the PQC VPN involved
* [`../../PQC_VPN/laptop_server/config.py`](../../PQC_VPN/laptop_server/config.py) —
  `SERVER_PRIVATE_SEED_HEX` (line ~62), `HOST`, `PORT`.
* [`../../PQC_VPN/laptop_server/crypto_engine.py`](../../PQC_VPN/laptop_server/crypto_engine.py) —
  `GatewayCrypto.__init__` turns the seed into the keypair via
  `PQCP_MLDSA_NATIVE_MLDSA44_keypair_internal`.
* [`../../PQC_VPN/esp32_client/config.h`](../../PQC_VPN/esp32_client/config.h) — `WIFI_SSID`,
  `WIFI_PASSWORD`, `GATEWAY_IP`.
* [`../../.gitignore`](../../.gitignore) — confirms `*.so` is ignored (so the private key is
  never shipped as a compiled artefact, but the *seed* still is).

## 5. Files & modules in this test
* `scripts/scan_secrets.py` — orchestrates gitleaks/trufflehog over the repo + history, writes
  JSON output to `reports/`. Dry-run prints the exact commands without executing them.
* `scripts/inspect_server_config.py` — pure-Python static review of the seed, Wi-Fi creds, key
  loading path and `.gitignore`; prints a findings table. Read-only; never prints the private key.
* `gitleaks.toml` — custom gitleaks rules tuned for this project (ML-DSA seed hex, Wi-Fi creds).

## 6. Tools & dependencies
* [`gitleaks`](https://github.com/gitleaks/gitleaks) (external binary)
* [`trufflehog`](https://github.com/trufflesecurity/trufflehog) (external binary)
* Python 3 (standard library only for `inspect_server_config.py`)

## 7. How it will be executed (future phase)
```bash
cd PEN_Testing/01_Server_Key_Security
python scripts/inspect_server_config.py            # static review, always safe
python scripts/scan_secrets.py --dry-run           # shows the gitleaks/trufflehog commands
python scripts/scan_secrets.py --run               # actually runs the scanners, writes reports/
```
No network and no target needed — this test only reads local files and git history.

## 8. Expected secure behaviour
* The gateway seed is loaded from an environment variable or an untracked file, **not** from a
  value committed to git.
* No real Wi-Fi password is present in any committed file (only placeholders).
* `gitleaks`/`trufflehog` report **no** secrets in the working tree or history.

## 9. What constitutes a vulnerability
* `SERVER_PRIVATE_SEED_HEX` (or any private seed) present as a literal in a tracked file. **This
  is expected to FAIL on the current code** — the seed is currently hard-coded in `config.py`;
  documenting it with evidence is a core deliverable of this test.
* Any real Wi-Fi credential committed in `config.h` or its history.
* A secret found anywhere in git history even if later removed from `HEAD`.

## 10. Evidence & metrics to collect
* gitleaks/trufflehog JSON reports (commit hash, file, line, rule) saved in `reports/`.
* The specific file+line of the hard-coded seed.
* A remediation note: move the seed to `$VPN_SERVER_SEED` / untracked file, rotate the key,
  and rewrite history if a real secret was ever committed.
