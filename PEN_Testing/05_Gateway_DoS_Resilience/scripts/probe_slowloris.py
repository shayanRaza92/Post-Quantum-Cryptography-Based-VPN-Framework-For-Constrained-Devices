#!/usr/bin/env python3
"""
Test 5 — slow-handshake (slowloris-style) probe (BOUNDED, lab only).

Opens a few connections (clamped) and sends only a PARTIAL MSG 1, one byte at a time with gaps,
never completing it, to confirm the gateway's handshake deadline (HANDSHAKE_TIMEOUT = 15 s)
drops stalled handshakes and releases their slots instead of holding them forever.

It opens at most `--connections` sockets (clamped), sends a handful of bytes each, waits long
enough to observe the timeout, then closes. No loop, no reconnection storm.

Measures: how long until the gateway drops each stalled connection (should be ≈ 15 s).

Dry-run by default; --run needs config.json authorised + a lab target.
"""
from __future__ import annotations

import _bootstrap  # noqa: F401
import argparse
import sys
import time

import target_config as tc
import dos_common as dc

PARTIAL_BYTES = 4  # send only the first few bytes of the 850-byte MSG 1, then stall


def run_live(cfg: dict, connections: int, wait: float) -> int:
    host, port = tc.require_live_authorisation(cfg, run_flag=True)
    _, n = dc.resolve_limits(cfg, None, connections)
    print(f"[{dc.timestamp()}] opening {n} stalled handshakes to {host}:{port}")

    socks = []
    for i in range(n):
        s = dc.open_connection(host, port)
        if s is None:
            print(f"  conn {i+1}: refused")
            continue
        try:
            # Send a tiny partial MSG 1 then stop (never reach 850 bytes).
            s.sendall(bytes([0x01, 0x03]) + b"\x00" * (PARTIAL_BYTES - 2))
        except OSError:
            pass
        socks.append(s)
        print(f"  conn {i+1}: opened, sent {PARTIAL_BYTES} partial bytes, now stalling")

    start = time.monotonic()
    dropped = 0
    deadline = start + min(wait, 25.0)
    while time.monotonic() < deadline and dropped < len(socks):
        time.sleep(1.0)
        for s in socks:
            try:
                s.settimeout(0.2)
                if s.recv(1) == b"":  # peer closed => gateway dropped the stalled handshake
                    dropped += 1
            except OSError:
                pass
        print(f"  [{dc.timestamp()}] observed {dropped}/{len(socks)} dropped "
              f"({time.monotonic()-start:.1f}s elapsed; expect ~15s)")
    dc.close_all(socks)
    print("Confirm the gateway stayed up and a legitimate handshake still succeeds (slot freed).")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Slow-handshake probe (bounded, lab only).")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--connections", type=int, default=2, help="stalled sockets (clamped)")
    ap.add_argument("--wait", type=float, default=20.0, help="seconds to watch for drop (max 25)")
    args = ap.parse_args()

    cfg = tc.load_target()
    tc.banner("Test 5 — slowloris handshake probe", run_flag=args.run, cfg=cfg)

    if not args.run:
        _, conc = dc.resolve_limits(cfg, None, args.connections)
        print(f"\nWould open {conc} connections (clamped), send {PARTIAL_BYTES} partial MSG 1 bytes")
        print("each, and watch them get dropped at ~15s (HANDSHAKE_TIMEOUT). Bounded, no loop.")
        print("Re-run with --run on an authorised lab target.")
        return 0
    try:
        return run_live(cfg, args.connections, args.wait)
    except tc.AuthorisationError as exc:
        print(f"[BLOCKED] {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
