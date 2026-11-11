#!/usr/bin/env python3
"""
Test 4 — ciphertext / GCM-tag tamper detection (OFFLINE, against the real SecureTunnel).

Seals a frame with the real SecureTunnel, flips one byte in (a) the ciphertext and (b) the
16-byte GCM tag, and confirms SecureTunnel.feed() raises TunnelError both times.

Dry-run by default; --run performs the offline analysis (no network).
"""
from __future__ import annotations

import _bootstrap  # noqa: F401
import argparse
import sys

import target_config as tc
import tunnel_harness as th


def analyse() -> int:
    server, client = th.make_tunnel_pair()
    frame = server.seal(b"hello tunnel", th.MSG_DATA)  # S2C frame for the client to receive

    cases = {
        "flip ciphertext byte": th.HEADER_SIZE,            # first ciphertext byte
        "flip GCM tag byte": len(frame) - 1,               # last byte = tag
    }
    failures = []
    for label, idx in cases.items():
        tampered = th.flip_frame_byte(frame, idx)
        fresh = th.make_tunnel_pair()[1]  # fresh client so rx_seq==0 matches the frame
        try:
            list(fresh.feed(tampered))
            print(f"  {label:<24} -> ACCEPTED  ** VULNERABLE **")
            failures.append(label)
        except th.TunnelError as e:
            print(f"  {label:<24} -> rejected ({e})")
    # Sanity: the untampered frame must decrypt cleanly.
    ok = list(client.feed(frame))
    print(f"  untampered control       -> {'decrypted ok' if ok else 'FAILED to decrypt (unexpected)'}")
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="AES-GCM tamper detection (offline).")
    ap.add_argument("--run", action="store_true", help="run the offline analysis")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    tc.banner("Test 4 — ciphertext/tag tamper (OFFLINE)", run_flag=args.run, cfg={})
    if not args.run:
        print("\nWould seal one frame, flip a ciphertext byte and a tag byte, and confirm both are")
        print("rejected by the real SecureTunnel. No network involved. Re-run with --run.")
        return 0
    return analyse()


if __name__ == "__main__":
    sys.exit(main())
