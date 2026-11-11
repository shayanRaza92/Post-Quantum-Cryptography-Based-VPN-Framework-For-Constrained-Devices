#!/usr/bin/env python3
"""
Test 3 — REPLAY attack on the handshake.

Replays a previously captured MSG 3 (Client Proof) inside a brand-new session to confirm it is
rejected. The client proof signs the Client Transcript = label || MSG1 || MSG2, and MSG1/MSG2
each contain fresh 32-byte nonces (client + server). A new session has different nonces, so a
replayed MSG 3 signs the wrong transcript and must fail with AUTH_NO.

Target code: crypto_engine.build_client_transcript / verify_client_transcript;
server nonce generated fresh per session in tunnel_session._send_server_proof.

Workflow:
  1. Provide a captured MSG 3 (hex file via --captured-msg3) from an earlier honest handshake.
  2. The script opens a NEW session, sends a fresh MSG 1, receives the new MSG 2, then sends the
     OLD MSG 3. Expected: AUTH_NO (or key-confirmation failure / disconnect).

Dry-run by default; --run needs an authorised lab target and a captured MSG 3.
"""
from __future__ import annotations

import _bootstrap  # noqa: F401
import argparse
import sys
from pathlib import Path

import target_config as tc
import handshake_client as hc
import protocol_constants as P


def describe(captured: str | None) -> None:
    print("\nReplay plan:")
    print("  1. New TCP session to the gateway.")
    print("  2. Send a freshly built MSG 1 (new client nonce + new ephemeral ek).")
    print("  3. Receive the gateway's new MSG 2 (new server nonce).")
    print(f"  4. Send the CAPTURED MSG 3 from file: {captured or '<none provided>'}")
    print("  Expected: gateway returns AUTH_NO because the replayed proof signs an old transcript.")
    if not captured:
        print("\n  (Provide --captured-msg3 <hexfile> of a real MSG 3 for the live run.)")


def run_live(cfg: dict, captured_path: str | None) -> int:
    host, port = tc.require_live_authorisation(cfg, run_flag=True)
    if not captured_path:
        print("[ABORT] --run requires --captured-msg3 <hexfile>.")
        return 2
    data = Path(captured_path).read_text().strip()
    old_msg3 = bytes.fromhex(data)
    if len(old_msg3) != P.MSG3_CLIENT_PROOF_SIZE:
        print(f"[ABORT] captured MSG 3 is {len(old_msg3)}B, expected {P.MSG3_CLIENT_PROOF_SIZE}.")
        return 2
    if not hc.native_mlkem_available():
        print("[ABORT] libmlkem512.so not built. Run build_native_libs.sh.")
        return 2

    device_id = cfg.get("lab", {}).get("device_id", "esp32-01")
    ek, _dk = hc.generate_ephemeral_kem_keypair()
    msg1 = hc.build_client_hello(device_id, ek)

    with hc.GatewayConnection(host, port) as conn:
        conn.send(msg1)
        msg2 = conn.recv_exact(P.MSG2_SERVER_PROOF_SIZE)
        if msg2 is None:
            print("[info] gateway closed before MSG 2 (device may be unauthorised). Inconclusive.")
            return 2
        conn.send(old_msg3)
        verdict = conn.recv_exact(P.MSG4_AUTH_VERDICT_SIZE) or conn.recv_exact(len(P.AUTH_FAIL_TOKEN))

    accepted = bool(verdict and verdict[:8] == P.AUTH_OK_TOKEN)
    print(f"  Verdict: {'AUTH_OK — VULNERABLE (replay accepted!)' if accepted else 'rejected — ok'}")
    return 1 if accepted else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Handshake replay attack (lab only).")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--captured-msg3", help="hex file containing a captured 2452-byte MSG 3")
    args = ap.parse_args()

    cfg = tc.load_target()
    tc.banner("Test 3 — replay attack", run_flag=args.run, cfg=cfg)
    P.assert_matches_source()

    if not args.run:
        describe(args.captured_msg3)
        print("\nDRY-RUN complete. No packets sent.")
        return 0
    try:
        return run_live(cfg, args.captured_msg3)
    except tc.AuthorisationError as exc:
        print(f"[BLOCKED] {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
