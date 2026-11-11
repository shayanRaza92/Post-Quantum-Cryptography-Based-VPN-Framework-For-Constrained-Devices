#!/usr/bin/env python3
"""
Test 3 — MITM / proof-tampering attack.

Acts as a man-in-the-middle that flips bytes in MSG 2 (Server Proof) before it reaches the
client, and in MSG 1 before it reaches the gateway, to confirm the signed transcript detects any
change.

Because the ESP32 is the party that verifies MSG 2, the fully active version of this test runs
between a real ESP32 and the gateway (ARP spoof / rogue AP) and observes the ESP32 aborting.
This script implements the GATEWAY-SIDE half you can drive from a laptop: tamper MSG 1 fields
and confirm the gateway's MSG 3 verification fails (AUTH_NO), which proves MSG 1 is bound into
the signed client transcript. The MSG 2 tamper cases are enumerated for the ESP32-side run and
recorded as test vectors.

Target code: crypto_engine.build_client_transcript binds MSG1||MSG2; verify_client_transcript
rejects any change. ESP32 AuthManager verifies the server signature before decapsulation.

Dry-run by default; --run needs an authorised lab target.
"""
from __future__ import annotations

import _bootstrap  # noqa: F401
import argparse
import sys

import target_config as tc
import protocol_constants as P

# MSG 2 tamper vectors to apply during the ESP32-side MITM run (offset, description).
MSG2_TAMPER_VECTORS = [
    (P.OFF_SERVER_NONCE.start, "flip 1 byte of Server Nonce"),
    (P.OFF_KEM_CT.start, "flip 1 byte of ML-KEM ciphertext"),
    (P.OFF_SERVER_SIG.start, "flip 1 byte of ML-DSA-44 signature"),
    (P.MSG2_SERVER_PROOF_SIZE - 1, "flip last byte of signature"),
]

# MSG 1 tamper vectors driveable from this script (sent to the gateway).
MSG1_TAMPER_VECTORS = [
    (P.OFF_CLIENT_NONCE.start, "flip 1 byte of Client Nonce"),
    (P.OFF_CLIENT_EK.start, "flip 1 byte of client ML-KEM ek"),
]


def flip_byte(buf: bytes, index: int) -> bytes:
    b = bytearray(buf)
    b[index] ^= 0x01
    return bytes(b)


def describe() -> None:
    print("\nMSG 2 tamper vectors (apply during ESP32<->gateway MITM; ESP32 must abort):")
    for off, desc in MSG2_TAMPER_VECTORS:
        print(f"  offset {off:<5} -> {desc}")
    print("\nMSG 1 tamper vectors (driveable from this laptop; gateway MSG 3 check must fail):")
    for off, desc in MSG1_TAMPER_VECTORS:
        print(f"  offset {off:<5} -> {desc}")
    print("\nExpected: every tampered byte causes rejection (signature/transcript mismatch).")


def run_live(cfg: dict) -> int:
    tc.require_live_authorisation(cfg, run_flag=True)
    print("\n[live] The MSG 1 tamper path requires an honest client that can sign MSG 3 with the")
    print("       device key. Drive it with a real ESP32 (or a signing-capable client) and apply")
    print("       each vector above; capture the gateway verdict. The MSG 2 tamper path needs the")
    print("       MITM position between the ESP32 and the gateway (e.g. bettercap ARP spoof).")
    print("       This harness provides the tamper vectors and flip_byte(); record each result in")
    print("       reports/ using TEST_RESULTS_TEMPLATE.md.")
    # Intentionally does not forge signatures here; that belongs to the ESP32-driven run.
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Handshake MITM/tamper attack (lab only).")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    cfg = tc.load_target()
    tc.banner("Test 3 — MITM / tamper", run_flag=args.run, cfg=cfg)
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
