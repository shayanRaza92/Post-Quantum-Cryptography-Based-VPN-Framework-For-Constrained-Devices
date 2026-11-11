#!/usr/bin/env python3
"""
Test 4 — replay / reorder / skipped-sequence detection (OFFLINE).

The real SecureTunnel enforces that each received frame's SEQ equals the expected rx_seq and
increments by exactly 1. This checks three violations are all rejected with TunnelError:
  * replay    : deliver frame #0 twice
  * reorder   : deliver frame #1 before frame #0
  * skip      : deliver frame #0 then frame #2 (gap)

Dry-run by default; --run performs the offline analysis.
"""
from __future__ import annotations

import _bootstrap  # noqa: F401
import argparse
import sys

import target_config as tc
import tunnel_harness as th


def seal_three():
    server, _client = th.make_tunnel_pair()
    frames = [server.seal(f"msg {i}".encode(), th.MSG_DATA) for i in range(3)]
    return frames


def analyse() -> int:
    frames = seal_three()
    failures = []

    # replay: feed frame0, then frame0 again
    rx = th.make_tunnel_pair()[1]
    list(rx.feed(frames[0]))
    try:
        list(rx.feed(frames[0]))
        print("  replay frame#0           -> ACCEPTED  ** VULNERABLE **"); failures.append("replay")
    except th.TunnelError as e:
        print(f"  replay frame#0           -> rejected ({e})")

    # reorder: feed frame1 first
    rx = th.make_tunnel_pair()[1]
    try:
        list(rx.feed(frames[1]))
        print("  reorder (frame#1 first)  -> ACCEPTED  ** VULNERABLE **"); failures.append("reorder")
    except th.TunnelError as e:
        print(f"  reorder (frame#1 first)  -> rejected ({e})")

    # skip: feed frame0 then frame2
    rx = th.make_tunnel_pair()[1]
    list(rx.feed(frames[0]))
    try:
        list(rx.feed(frames[2]))
        print("  skip (frame#0 then #2)   -> ACCEPTED  ** VULNERABLE **"); failures.append("skip")
    except th.TunnelError as e:
        print(f"  skip (frame#0 then #2)   -> rejected ({e})")

    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Replay/reorder detection (offline).")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    tc.banner("Test 4 — replay/reorder (OFFLINE)", run_flag=args.run, cfg={})
    if not args.run:
        print("\nWould seal 3 frames and attempt replay, reorder and skip; each must be rejected.")
        print("No network. Re-run with --run.")
        return 0
    return analyse()


if __name__ == "__main__":
    sys.exit(main())
