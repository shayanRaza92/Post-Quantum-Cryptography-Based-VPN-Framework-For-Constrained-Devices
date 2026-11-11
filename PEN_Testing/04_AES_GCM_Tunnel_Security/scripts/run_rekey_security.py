#!/usr/bin/env python3
"""
Test 4 — rekeying security (OFFLINE).

Checks two properties of the in-tunnel rekey:
  1. Old-key rejection: a frame sealed under the pre-rekey key must NOT decrypt after both sides
     rekey to a new epoch (keys change, seq resets).
  2. Epoch binding (documented against tunnel_session._check_rekey_request): REKEY_REQ epoch must
     equal tunnel.epoch+1; and derive_rekeyed_session_key mixes the OLD K_session as HKDF salt,
     so a fresh shared secret alone cannot reproduce the new key without the old one.

Dry-run by default; --run performs the offline analysis.
"""
from __future__ import annotations

import _bootstrap  # noqa: F401
import argparse
import sys

import target_config as tc
import tunnel_harness as th


def analyse() -> int:
    server, client = th.make_tunnel_pair()
    problems = []

    # Seal a frame under epoch 0, but do NOT deliver it yet.
    stale = server.seal(b"old epoch data", th.MSG_DATA)

    # Both sides rekey to epoch 1 with the same fresh shared secret.
    ss_new = b"\x19" * 32
    server.rekey(ss_new, epoch=1)
    client.rekey(ss_new, epoch=1)

    # The client (now on epoch 1) tries to decrypt the epoch-0 frame.
    try:
        list(client.feed(stale))
        print("  epoch-0 frame after rekey -> ACCEPTED  ** VULNERABLE (old key still works) **")
        problems.append("old key accepted")
    except th.TunnelError as e:
        print(f"  epoch-0 frame after rekey -> rejected ({e})")

    # Confirm a fresh epoch-1 frame round-trips.
    fresh = server.seal(b"new epoch data", th.MSG_DATA)
    got = list(client.feed(fresh))
    print(f"  epoch-1 frame round-trip  -> {'ok' if got else 'FAILED (unexpected)'}")
    if not got:
        problems.append("rekeyed channel broken")

    # Document epoch-binding rule from the source.
    print("  note: gateway requires REKEY_REQ epoch == tunnel.epoch+1 and rekey age >= 5s")
    print("        (tunnel_session._check_rekey_request); old K_session is the HKDF salt.")
    return 1 if problems else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Rekey security (offline).")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    tc.banner("Test 4 — rekey security (OFFLINE)", run_flag=args.run, cfg={})
    if not args.run:
        print("\nWould seal a frame under epoch 0, rekey both sides to epoch 1, and confirm the")
        print("old frame no longer decrypts while new frames do. No network. Re-run with --run.")
        return 0
    return analyse()


if __name__ == "__main__":
    sys.exit(main())
