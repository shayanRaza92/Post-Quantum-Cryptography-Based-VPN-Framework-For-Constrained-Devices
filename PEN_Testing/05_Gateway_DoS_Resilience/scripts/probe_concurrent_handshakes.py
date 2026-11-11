#!/usr/bin/env python3
"""
Test 5 — concurrent-handshake cap probe (BOUNDED, lab only).

Opens up to the clamped ceiling of simultaneous connections from this host and holds them
briefly WITHOUT completing the handshake, to observe:
  * the global cap  MAX_CONCURRENT_HANDSHAKES = 8
  * the per-IP cap  MAX_HANDSHAKES_PER_IP     = 2  (all our connections share one source IP)

It does not send a valid handshake and does not loop; it opens N sockets, records how many the
gateway keeps vs. drops, holds for a few seconds, then closes everything. This probes the limit;
it does not try to cause an outage.

Dry-run by default; --run needs config.json authorised + a lab target. Counts are clamped by
modules/dos_common (config ceiling AND an absolute max).
"""
from __future__ import annotations

import _bootstrap  # noqa: F401
import argparse
import sys
import time

import target_config as tc
import dos_common as dc


def run_live(cfg: dict, requested: int, hold: float) -> int:
    host, port = tc.require_live_authorisation(cfg, run_flag=True)
    n, _ = dc.resolve_limits(cfg, requested, None)
    print(f"[{dc.timestamp()}] opening {n} connections to {host}:{port} (clamped). Holding {hold}s.")

    socks = []
    opened = 0
    for i in range(n):
        s = dc.open_connection(host, port)
        if s is not None:
            socks.append(s)
            opened += 1
        time.sleep(0.05)  # gentle pacing, not a burst
    print(f"[{dc.timestamp()}] sockets opened: {opened}/{n}. "
          f"(gateway per-IP handshake cap is 2; extras should be dropped quickly)")

    time.sleep(hold)
    dc.close_all(socks)
    print(f"[{dc.timestamp()}] closed all. Record accepted-vs-dropped from the gateway log.")
    print("Then confirm a legitimate handshake still succeeds (no slot leak).")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Concurrent-handshake cap probe (bounded, lab only).")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--requests", type=int, default=None, help="desired sockets (clamped to ceiling)")
    ap.add_argument("--hold", type=float, default=3.0, help="seconds to hold sockets (max ~10)")
    args = ap.parse_args()
    args.hold = min(args.hold, 10.0)

    cfg = tc.load_target()
    tc.banner("Test 5 — concurrent-handshake probe", run_flag=args.run, cfg=cfg)

    if not args.run:
        req, conc = dc.resolve_limits(cfg, args.requests, None)
        print(f"\nWould open {req} connections (clamped; absolute max {dc.ABSOLUTE_MAX_REQUESTS}),")
        print(f"hold {args.hold}s, then close. Observes global cap 8 / per-IP cap 2. No handshake")
        print("is completed, no loop, no flood. Re-run with --run on an authorised lab target.")
        return 0
    try:
        return run_live(cfg, args.requests, args.hold)
    except tc.AuthorisationError as exc:
        print(f"[BLOCKED] {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
