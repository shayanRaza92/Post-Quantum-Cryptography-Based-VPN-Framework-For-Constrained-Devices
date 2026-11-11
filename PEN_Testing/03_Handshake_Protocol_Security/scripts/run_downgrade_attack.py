#!/usr/bin/env python3
"""
Test 3 — DOWNGRADE attack on the handshake.

Sends MSG 1 with a non-expected Version byte and/or Algorithm ID (e.g. 0x01 = the classical
suite) to check that the gateway refuses anything other than Version 0x01 / Algorithm 0x03
BEFORE doing any cryptographic work.

Target code: tunnel_session.py::_receive_client_hello rejects mismatched ver/alg
(`version != PROTOCOL_VERSION or alg_id != ALGORITHM_ID`).

Expected secure behaviour: gateway drops the connection with no MSG 2.
Vulnerability if: the gateway proceeds / sends MSG 2 for a downgraded suite.

Dry-run by default; --run needs an authorised lab target in config.json.
"""
from __future__ import annotations

import _bootstrap  # noqa: F401  (sets up import paths)
import argparse
import sys

import target_config as tc
import handshake_client as hc
import protocol_constants as P

# Variations to try: (version, alg_id, label)
VARIANTS = [
    (0x01, 0x01, "classical suite (Ed25519/X25519) alg=0x01"),
    (0x02, 0x03, "unknown protocol version 0x02"),
    (0x01, 0x00, "null algorithm id 0x00"),
    (0x01, 0xFF, "out-of-range algorithm id 0xFF"),
]


def describe() -> None:
    print("\nDowngrade variants that WOULD be sent as MSG 1 (one connection each):")
    for ver, alg, label in VARIANTS:
        print(f"  Ver=0x{ver:02X} Alg=0x{alg:02X}  -> {label}")
    print("\nExpected: every variant is dropped before MSG 2. Baseline Ver=0x01/Alg=0x03 "
          "would be accepted.")


def run_live(cfg: dict) -> int:
    host, port = tc.require_live_authorisation(cfg, run_flag=True)
    if not hc.native_mlkem_available():
        print("[ABORT] libmlkem512.so not built in PQC_VPN/laptop_server. Run build_native_libs.sh.")
        return 2
    device_id = cfg.get("lab", {}).get("device_id", "esp32-01")
    ek, _dk = hc.generate_ephemeral_kem_keypair()

    results = []
    for ver, alg, label in VARIANTS:
        msg1 = hc.build_client_hello(device_id, ek, version=ver, alg_id=alg)
        try:
            with hc.GatewayConnection(host, port) as conn:
                conn.send(msg1)
                resp = conn.recv_exact(P.MSG2_SERVER_PROOF_SIZE)
            accepted = resp is not None and len(resp) == P.MSG2_SERVER_PROOF_SIZE
        except OSError as exc:
            accepted, resp = False, None
            print(f"  [net] {label}: connection error {exc}")
        verdict = "VULNERABLE (accepted!)" if accepted else "ok (rejected)"
        results.append((label, verdict))
        print(f"  Ver=0x{ver:02X} Alg=0x{alg:02X} {label:<40} -> {verdict}")

    bad = [r for r in results if "VULNERABLE" in r[1]]
    print(f"\nSummary: {len(bad)} downgrade variant(s) wrongly accepted.")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Handshake downgrade attack (lab only).")
    ap.add_argument("--run", action="store_true", help="execute against the authorised lab target")
    ap.add_argument("--dry-run", action="store_true", help="describe only (default)")
    args = ap.parse_args()

    cfg = tc.load_target()
    tc.banner("Test 3 — downgrade attack", run_flag=args.run, cfg=cfg)
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
