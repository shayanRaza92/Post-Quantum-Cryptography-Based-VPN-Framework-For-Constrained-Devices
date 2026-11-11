#!/usr/bin/env python3
"""
Test 3 — KEY-SUBSTITUTION attack on the handshake.

Two sub-scenarios, both expected to be rejected:

  A. Impersonation with wrong signing key: claim an allowlisted device ID (e.g. esp32-01) but
     sign MSG 3 with an ML-DSA-44 key that is NOT the one registered for that ID. The gateway
     looks up the registered public key and verify_client_transcript() must fail -> AUTH_NO.

  B. KEM-ciphertext substitution: a MITM swaps the gateway's MSG 2 ciphertext for one it chose.
     The client then derives a different shared secret, so the HMAC key-confirmation tags
     (K_confirm) will not match and the handshake must abort.

Target code: crypto_engine.verify_client_transcript (checks against the REGISTERED key);
derive_session_keys + compute_confirmation_tag bind the shared secret into K_confirm.

This script enumerates and documents the substitution vectors and, for scenario A, needs a
signing-capable client (real ESP32 with a non-registered key, or a signing helper) to produce
MSG 3. It does not forge ML-DSA signatures itself.

Dry-run by default; --run needs an authorised lab target.
"""
from __future__ import annotations

import _bootstrap  # noqa: F401
import argparse
import sys

import target_config as tc
import protocol_constants as P


def describe() -> None:
    print("\nScenario A — wrong signing key for an allowlisted device ID:")
    print("  * MSG 1 device ID = an allowlisted ID (e.g. esp32-01).")
    print("  * MSG 3 signed with a DIFFERENT ML-DSA-44 key.")
    print("  * Expected: gateway verifies against the registered key -> AUTH_NO.")
    print("\nScenario B — KEM ciphertext substitution (MITM on MSG 2):")
    print(f"  * Replace bytes [{P.OFF_KEM_CT.start}:{P.OFF_KEM_CT.stop}] of MSG 2 with a chosen ct.")
    print("  * Client derives a different K -> K_confirm mismatch -> handshake aborts.")
    print("\nBoth require a signing-capable client / MITM position; this harness supplies the")
    print("vectors and offsets, and records results. It does NOT forge ML-DSA signatures.")


def run_live(cfg: dict) -> int:
    tc.require_live_authorisation(cfg, run_flag=True)
    print("\n[live] Drive scenario A with a client holding a non-registered key; drive scenario B")
    print("       from the MITM position (bettercap/ettercap). Capture each gateway/client verdict")
    print("       into reports/. A result of AUTH_OK in either scenario is a vulnerability.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Handshake key-substitution attack (lab only).")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    cfg = tc.load_target()
    tc.banner("Test 3 — key substitution", run_flag=args.run, cfg=cfg)
    P.assert_matches_source()

    if not args.run:
        describe()
        print("\nDRY-RUN complete. No packets sent.")
        return 0
    try:
        return run_live(cfg)
    except tc.AuthorisationError as exc:
        print(f"[BLOCKED] {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
